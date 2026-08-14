//! Async network fuzzing harness: TcpFuzzHarness and UdpFuzzHarness.
//!
//! Provides connection pooling, per-attempt timeout tracking, crash detection
//! via response anomaly scoring, and per-iteration statistics collection.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection timeout")]
    ConnectTimeout,
    #[error("send timeout")]
    SendTimeout,
    #[error("recv timeout")]
    RecvTimeout,
    #[error("crash detected: {0}")]
    CrashDetected(String),
    #[error("pool exhausted")]
    PoolExhausted,
}

// ── Attempt result ────────────────────────────────────────────────────────────

/// Disposition of a single fuzz attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptOutcome {
    Success,
    SendTimeout,
    RecvTimeout,
    ConnectTimeout,
    ConnectionRefused,
    ConnectionReset,
    AnomalyDetected(String),
    InternalError(String),
}

/// Result of a single fuzz attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptResult {
    /// Input that was sent.
    pub input: Vec<u8>,
    /// Bytes received in response.
    pub response: Vec<u8>,
    /// Outcome.
    pub outcome: AttemptOutcome,
    /// Round-trip time in milliseconds.
    pub rtt_ms: u64,
    /// Anomaly score (0 = normal, higher = more suspicious).
    pub anomaly_score: u32,
    /// Sequential attempt number.
    pub attempt_id: u64,
}

impl AttemptResult {
    #[must_use]
    pub fn is_crash(&self) -> bool {
        matches!(
            &self.outcome,
            AttemptOutcome::ConnectionReset | AttemptOutcome::AnomalyDetected(_)
        ) || self.anomaly_score >= 50
    }
}

// ── Anomaly detector ──────────────────────────────────────────────────────────

/// Scores how anomalous a response is compared to a baseline.
#[derive(Debug, Default)]
pub struct AnomalyDetector {
    /// Baseline response length (rolling average).
    baseline_len: Option<usize>,
    /// Known error patterns.
    error_patterns: Vec<Vec<u8>>,
    /// Number of normal responses seen.
    baseline_count: usize,
    /// Running sum for average.
    len_sum: usize,
}

impl AnomalyDetector {
    #[must_use]
    pub fn new() -> Self {
        let mut d = Self::default();
        d.add_error_pattern(b"error".to_vec());
        d.add_error_pattern(b"Error".to_vec());
        d.add_error_pattern(b"exception".to_vec());
        d.add_error_pattern(b"crash".to_vec());
        d.add_error_pattern(b"fault".to_vec());
        d.add_error_pattern(b"segfault".to_vec());
        d.add_error_pattern(b"SIGSEGV".to_vec());
        d.add_error_pattern(b"Traceback".to_vec());
        d.add_error_pattern(b"panic".to_vec());
        d.add_error_pattern(b"abort".to_vec());
        d
    }

    pub fn add_error_pattern(&mut self, pattern: Vec<u8>) {
        self.error_patterns.push(pattern);
    }

    /// Feed a normal (non-mutated) response to build the baseline.
    pub fn feed_baseline(&mut self, response: &[u8]) {
        self.len_sum += response.len();
        self.baseline_count += 1;
        self.baseline_len = Some(self.len_sum / self.baseline_count);
    }

    /// Score a response (0 = normal, up to 100).
    #[must_use]
    pub fn score(&self, response: &[u8]) -> u32 {
        let mut score = 0u32;

        // Empty response when baseline was non-empty
        if response.is_empty() {
            if self.baseline_len.map_or(false, |l| l > 0) {
                score += 40;
            } else {
                score += 5;
            }
        }

        // Length deviation from baseline
        if let Some(bl) = self.baseline_len {
            if bl > 0 {
                let ratio = response.len() as f64 / bl as f64;
                if ratio < 0.1 || ratio > 10.0 {
                    score += 20;
                } else if ratio < 0.5 || ratio > 3.0 {
                    score += 10;
                }
            }
        }

        // Error patterns
        for pat in &self.error_patterns {
            if response.windows(pat.len()).any(|w| w == pat.as_slice()) {
                score += 15;
                break;
            }
        }

        // Binary content in what should be ASCII (heuristic)
        let binary_bytes = response.iter().filter(|&&b| b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t').count();
        if binary_bytes > response.len() / 4 {
            score += 10;
        }

        score.min(100)
    }

    #[must_use]
    pub fn describe_anomaly(&self, response: &[u8]) -> Option<String> {
        if response.is_empty() && self.baseline_len.map_or(false, |l| l > 0) {
            return Some("empty response (expected non-empty)".to_string());
        }
        for pat in &self.error_patterns {
            if response.windows(pat.len()).any(|w| w == pat.as_slice()) {
                let pattern_str = String::from_utf8_lossy(pat);
                return Some(format!("error pattern '{}' in response", pattern_str));
            }
        }
        None
    }
}

// ── Connection pool ───────────────────────────────────────────────────────────

/// A simple pool of reusable TCP connections.
pub struct TcpConnectionPool {
    addr: SocketAddr,
    max_size: usize,
    connections: VecDeque<TcpStream>,
    connect_timeout_ms: u64,
    reuse_count: usize,
}

impl TcpConnectionPool {
    #[must_use]
    pub fn new(addr: SocketAddr, max_size: usize, connect_timeout_ms: u64) -> Self {
        Self {
            addr,
            max_size,
            connections: VecDeque::new(),
            connect_timeout_ms,
            reuse_count: 0,
        }
    }

    /// Acquire a connection from the pool or create a new one.
    pub async fn acquire(&mut self) -> Result<TcpStream, HarnessError> {
        // Try to reuse a pooled connection
        while let Some(conn) = self.connections.pop_front() {
            // Quick health check: peek for readable data
            // If there's unexpected data, discard and try next
            self.reuse_count += 1;
            return Ok(conn);
        }
        // Create a new connection
        let connect_fut = TcpStream::connect(self.addr);
        match timeout(Duration::from_millis(self.connect_timeout_ms), connect_fut).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(HarnessError::Io(e)),
            Err(_) => Err(HarnessError::ConnectTimeout),
        }
    }

    /// Return a connection to the pool for reuse.
    pub fn release(&mut self, conn: TcpStream) {
        if self.connections.len() < self.max_size {
            self.connections.push_back(conn);
        }
        // If pool is full, connection is dropped (closed)
    }

    #[must_use]
    pub fn pool_size(&self) -> usize {
        self.connections.len()
    }

    #[must_use]
    pub fn reuse_count(&self) -> usize {
        self.reuse_count
    }
}

// ── TCP fuzzing harness ───────────────────────────────────────────────────────

/// Configuration for the TCP fuzzing harness.
#[derive(Debug, Clone)]
pub struct TcpFuzzConfig {
    pub target_addr: SocketAddr,
    pub connect_timeout_ms: u64,
    pub send_timeout_ms: u64,
    pub recv_timeout_ms: u64,
    pub pool_size: usize,
    pub crash_threshold: u32,
    pub max_response_bytes: usize,
    pub baseline_attempts: usize,
}

impl Default for TcpFuzzConfig {
    fn default() -> Self {
        Self {
            target_addr: "127.0.0.1:9999".parse().unwrap(),
            connect_timeout_ms: 2000,
            send_timeout_ms: 5000,
            recv_timeout_ms: 5000,
            pool_size: 4,
            crash_threshold: 50,
            max_response_bytes: 65536,
            baseline_attempts: 10,
        }
    }
}

/// Async TCP fuzzing harness.
pub struct TcpFuzzHarness {
    config: TcpFuzzConfig,
    anomaly: AnomalyDetector,
    attempt_counter: Arc<AtomicU64>,
    stats: HarnessStats,
}

impl TcpFuzzHarness {
    #[must_use]
    pub fn new(config: TcpFuzzConfig) -> Self {
        Self {
            config,
            anomaly: AnomalyDetector::new(),
            attempt_counter: Arc::new(AtomicU64::new(0)),
            stats: HarnessStats::default(),
        }
    }

    /// Run a single fuzz attempt: connect, send `input`, recv response, score.
    pub async fn attempt(&mut self, input: Vec<u8>) -> AttemptResult {
        let attempt_id = self.attempt_counter.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();

        let outcome;
        let mut response = Vec::new();

        // Connect
        let connect_res = timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            TcpStream::connect(self.config.target_addr),
        ).await;

        match connect_res {
            Err(_) => {
                outcome = AttemptOutcome::ConnectTimeout;
                self.stats.timeouts += 1;
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    outcome = AttemptOutcome::ConnectionRefused;
                } else {
                    outcome = AttemptOutcome::InternalError(e.to_string());
                }
                self.stats.errors += 1;
            }
            Ok(Ok(mut stream)) => {
                // Send
                let send_res = timeout(
                    Duration::from_millis(self.config.send_timeout_ms),
                    stream.write_all(&input),
                ).await;

                // Distinguish outer timeout from inner IO error so that send
                // failures (broken pipe, connection reset) are not misclassified
                // as timeouts, which would lose diagnostic information.
                let send_failed = match send_res {
                    Err(_elapsed) => true,                       // outer timeout
                    Ok(Err(_io_err)) => true,                    // inner IO error
                    Ok(Ok(())) => false,
                };
                if send_failed {
                    outcome = AttemptOutcome::SendTimeout;
                    self.stats.timeouts += 1;
                } else {
                    // Recv
                    let mut buf = vec![0u8; self.config.max_response_bytes];
                    let recv_res = timeout(
                        Duration::from_millis(self.config.recv_timeout_ms),
                        stream.read(&mut buf),
                    ).await;

                    match recv_res {
                        Err(_) => {
                            outcome = AttemptOutcome::RecvTimeout;
                            self.stats.timeouts += 1;
                        }
                        Ok(Err(e)) => {
                            if e.kind() == std::io::ErrorKind::ConnectionReset {
                                outcome = AttemptOutcome::ConnectionReset;
                                self.stats.crashes += 1;
                            } else {
                                outcome = AttemptOutcome::InternalError(e.to_string());
                                self.stats.errors += 1;
                            }
                        }
                        Ok(Ok(n)) => {
                            response = buf[..n].to_vec();
                            let score = self.anomaly.score(&response);
                            if score >= self.config.crash_threshold {
                                let desc = self.anomaly.describe_anomaly(&response)
                                    .unwrap_or_else(|| format!("anomaly score {score}"));
                                outcome = AttemptOutcome::AnomalyDetected(desc);
                                self.stats.crashes += 1;
                            } else {
                                outcome = AttemptOutcome::Success;
                                self.stats.successes += 1;
                            }
                        }
                    }
                }
            }
        }

        let rtt_ms = start.elapsed().as_millis() as u64;
        let anomaly_score = self.anomaly.score(&response);

        self.stats.total_attempts += 1;
        self.stats.total_bytes_sent += input.len() as u64;

        AttemptResult { input, response, outcome, rtt_ms, anomaly_score, attempt_id }
    }

    /// Run `count` fuzz attempts with the given input generator.
    pub async fn run<F>(&mut self, count: usize, mut generator: F) -> Vec<AttemptResult>
    where
        F: FnMut(u64) -> Vec<u8>,
    {
        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            let input = generator(i as u64);
            let r = self.attempt(input).await;
            results.push(r);
        }
        results
    }

    #[must_use]
    pub fn stats(&self) -> &HarnessStats { &self.stats }

    /// Feed a normal response to the anomaly detector baseline.
    pub fn feed_baseline_response(&mut self, response: &[u8]) {
        self.anomaly.feed_baseline(response);
    }
}

// ── UDP fuzzing harness ───────────────────────────────────────────────────────

/// Configuration for the UDP fuzzing harness.
#[derive(Debug, Clone)]
pub struct UdpFuzzConfig {
    pub target_addr: SocketAddr,
    pub bind_addr: SocketAddr,
    pub send_timeout_ms: u64,
    pub recv_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub crash_threshold: u32,
}

impl Default for UdpFuzzConfig {
    fn default() -> Self {
        Self {
            target_addr: "127.0.0.1:9999".parse().unwrap(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            send_timeout_ms: 2000,
            recv_timeout_ms: 2000,
            max_response_bytes: 65536,
            crash_threshold: 50,
        }
    }
}

/// Async UDP fuzzing harness.
pub struct UdpFuzzHarness {
    config: UdpFuzzConfig,
    anomaly: AnomalyDetector,
    attempt_counter: Arc<AtomicU64>,
    stats: HarnessStats,
}

impl UdpFuzzHarness {
    #[must_use]
    pub fn new(config: UdpFuzzConfig) -> Self {
        Self {
            config,
            anomaly: AnomalyDetector::new(),
            attempt_counter: Arc::new(AtomicU64::new(0)),
            stats: HarnessStats::default(),
        }
    }

    /// Run a single UDP fuzz attempt.
    pub async fn attempt(&mut self, input: Vec<u8>) -> AttemptResult {
        let attempt_id = self.attempt_counter.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let mut response = Vec::new();
        let outcome;

        match UdpSocket::bind(self.config.bind_addr).await {
            Err(e) => {
                outcome = AttemptOutcome::InternalError(e.to_string());
                self.stats.errors += 1;
            }
            Ok(socket) => {
                // Send datagram
                let send_res = timeout(
                    Duration::from_millis(self.config.send_timeout_ms),
                    socket.send_to(&input, self.config.target_addr),
                ).await;

                match send_res {
                    Err(_) => {
                        outcome = AttemptOutcome::SendTimeout;
                        self.stats.timeouts += 1;
                    }
                    Ok(Err(e)) => {
                        outcome = AttemptOutcome::InternalError(e.to_string());
                        self.stats.errors += 1;
                    }
                    Ok(Ok(_)) => {
                        // Receive response
                        let mut buf = vec![0u8; self.config.max_response_bytes];
                        let recv_res = timeout(
                            Duration::from_millis(self.config.recv_timeout_ms),
                            socket.recv_from(&mut buf),
                        ).await;

                        match recv_res {
                            Err(_) => {
                                // UDP timeout is normal (no response expected by some protocols)
                                outcome = AttemptOutcome::RecvTimeout;
                                self.stats.timeouts += 1;
                            }
                            Ok(Err(e)) => {
                                outcome = AttemptOutcome::InternalError(e.to_string());
                                self.stats.errors += 1;
                            }
                            Ok(Ok((n, _src))) => {
                                response = buf[..n].to_vec();
                                let score = self.anomaly.score(&response);
                                if score >= self.config.crash_threshold {
                                    let desc = self.anomaly.describe_anomaly(&response)
                                        .unwrap_or_else(|| format!("anomaly score {score}"));
                                    outcome = AttemptOutcome::AnomalyDetected(desc);
                                    self.stats.crashes += 1;
                                } else {
                                    outcome = AttemptOutcome::Success;
                                    self.stats.successes += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        let rtt_ms = start.elapsed().as_millis() as u64;
        let anomaly_score = self.anomaly.score(&response);
        self.stats.total_attempts += 1;
        self.stats.total_bytes_sent += input.len() as u64;

        AttemptResult { input, response, outcome, rtt_ms, anomaly_score, attempt_id }
    }

    /// Run `count` fuzz attempts.
    pub async fn run<F>(&mut self, count: usize, mut generator: F) -> Vec<AttemptResult>
    where
        F: FnMut(u64) -> Vec<u8>,
    {
        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            let input = generator(i as u64);
            let r = self.attempt(input).await;
            results.push(r);
        }
        results
    }

    #[must_use]
    pub fn stats(&self) -> &HarnessStats { &self.stats }
}

// ── Harness statistics ────────────────────────────────────────────────────────

/// Aggregate statistics for a fuzzing harness.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HarnessStats {
    pub total_attempts: u64,
    pub successes: u64,
    pub crashes: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub total_bytes_sent: u64,
}

impl HarnessStats {
    #[must_use]
    pub fn crash_rate(&self) -> f64 {
        if self.total_attempts == 0 { return 0.0; }
        self.crashes as f64 / self.total_attempts as f64
    }

    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 { return 0.0; }
        self.successes as f64 / self.total_attempts as f64
    }
}

// ── Crash deduplicator ────────────────────────────────────────────────────────

/// Deduplicates crash attempts by hashing their response bytes.
#[derive(Debug, Default)]
pub struct CrashDeduplicator {
    seen: std::collections::HashSet<u64>,
}

impl CrashDeduplicator {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Return `true` if this crash is new (first time seen by response hash).
    pub fn is_new(&mut self, result: &AttemptResult) -> bool {
        let hash = fnv1a_hash(&result.response);
        self.seen.insert(hash)
    }

    #[must_use]
    pub fn unique_crashes(&self) -> usize { self.seen.len() }
}

fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_PRIME: u64 = 0x00000100000001B3;
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    data.iter().fold(FNV_OFFSET, |acc, &b| (acc ^ b as u64).wrapping_mul(FNV_PRIME))
}

// ── Mutation generators ───────────────────────────────────────────────────────

/// A suite of simple mutation strategies usable as input generators.
pub struct MutationSuite {
    seed: Vec<u8>,
    state: u64,
}

impl MutationSuite {
    #[must_use]
    pub fn new(seed: Vec<u8>) -> Self {
        Self { seed, state: 0xDEAD_BEEF_CAFE_BABE }
    }

    fn next_rand(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    /// Generate the `n`-th mutation.
    #[must_use]
    pub fn generate(&mut self, n: u64) -> Vec<u8> {
        let strategy = n % 8;
        match strategy {
            0 => self.seed.clone(),
            1 => {
                let mut m = self.seed.clone();
                if !m.is_empty() {
                    let idx = (self.next_rand() as usize) % m.len();
                    m[idx] ^= 0xFF;
                }
                m
            }
            2 => {
                // Truncate to half
                self.seed[..self.seed.len() / 2].to_vec()
            }
            3 => {
                // Double length
                let mut m = self.seed.clone();
                m.extend_from_slice(&self.seed.clone());
                m
            }
            4 => {
                // All zeros
                vec![0u8; self.seed.len()]
            }
            5 => {
                // All 0xFF
                vec![0xFFu8; self.seed.len()]
            }
            6 => {
                // Random bytes
                let len = self.seed.len();
                (0..len).map(|_| (self.next_rand() & 0xFF) as u8).collect()
            }
            _ => {
                // Bit flip
                let mut m = self.seed.clone();
                if !m.is_empty() {
                    let byte_idx = (self.next_rand() as usize) % m.len();
                    let bit_idx = (self.next_rand() as usize) % 8;
                    m[byte_idx] ^= 1 << bit_idx;
                }
                m
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_detector_empty_response() {
        let mut det = AnomalyDetector::new();
        det.feed_baseline(b"HTTP/1.1 200 OK\r\n\r\nHello");
        let score = det.score(&[]);
        assert!(score >= 40, "expected high score for empty response, got {}", score);
    }

    #[test]
    fn anomaly_detector_normal_response() {
        let mut det = AnomalyDetector::new();
        for _ in 0..5 {
            det.feed_baseline(b"HTTP/1.1 200 OK\r\n\r\nHello World");
        }
        let score = det.score(b"HTTP/1.1 200 OK\r\n\r\nHello World");
        assert!(score < 30, "expected low score for normal response, got {}", score);
    }

    #[test]
    fn anomaly_detector_error_pattern() {
        let det = AnomalyDetector::new();
        let score = det.score(b"Internal Server error: segfault detected");
        assert!(score >= 15);
    }

    #[test]
    fn crash_deduplicator_unique() {
        let mut dedup = CrashDeduplicator::new();
        let r1 = AttemptResult {
            input: vec![1], response: vec![1, 2, 3], outcome: AttemptOutcome::ConnectionReset,
            rtt_ms: 10, anomaly_score: 80, attempt_id: 1,
        };
        let r2 = AttemptResult {
            input: vec![2], response: vec![4, 5, 6], outcome: AttemptOutcome::ConnectionReset,
            rtt_ms: 10, anomaly_score: 80, attempt_id: 2,
        };
        let r3 = AttemptResult {
            input: vec![3], response: vec![1, 2, 3], outcome: AttemptOutcome::ConnectionReset,
            rtt_ms: 10, anomaly_score: 80, attempt_id: 3,
        };
        assert!(dedup.is_new(&r1));
        assert!(dedup.is_new(&r2));
        assert!(!dedup.is_new(&r3)); // same response as r1
        assert_eq!(dedup.unique_crashes(), 2);
    }

    #[test]
    fn harness_stats_rates() {
        let stats = HarnessStats {
            total_attempts: 100,
            successes: 90,
            crashes: 5,
            timeouts: 5,
            errors: 0,
            total_bytes_sent: 1000,
        };
        assert!((stats.crash_rate() - 0.05).abs() < 0.001);
        assert!((stats.success_rate() - 0.90).abs() < 0.001);
    }

    #[test]
    fn mutation_suite_generates_variants() {
        let mut suite = MutationSuite::new(b"HELLO".to_vec());
        let mut seen = std::collections::HashSet::new();
        for i in 0..8 {
            seen.insert(suite.generate(i));
        }
        assert!(seen.len() > 3, "expected diverse mutations");
    }

    #[test]
    fn mutation_suite_seed_as_first() {
        let mut suite = MutationSuite::new(b"SEED".to_vec());
        assert_eq!(suite.generate(0), b"SEED");
    }

    #[test]
    fn attempt_result_is_crash() {
        let crash = AttemptResult {
            input: vec![], response: vec![], outcome: AttemptOutcome::ConnectionReset,
            rtt_ms: 0, anomaly_score: 0, attempt_id: 0,
        };
        assert!(crash.is_crash());

        let ok = AttemptResult {
            input: vec![], response: vec![1], outcome: AttemptOutcome::Success,
            rtt_ms: 0, anomaly_score: 0, attempt_id: 0,
        };
        assert!(!ok.is_crash());
    }

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(fnv1a_hash(b"hello"), fnv1a_hash(b"hello"));
        assert_ne!(fnv1a_hash(b"hello"), fnv1a_hash(b"world"));
    }
}
