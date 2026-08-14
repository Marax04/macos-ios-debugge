//! Replay engine — send fuzzed packet sequences over TCP/UDP and capture
//! responses, enabling deterministic crash reproduction.
//!
//! The primary types are:
//! * [`ReplayEngine`] — high-level engine that manages a list of
//!   [`ReplaySession`]s and executes them.
//! * [`ReplaySession`] — a single replay run: a target address, an ordered
//!   list of [`PacketSpec`]s, and recorded [`PacketResult`]s.
//! * [`PacketResult`] — the outcome of sending one packet.
//! * [`replay_sequence`] — free function to replay a raw byte slice list.

use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the replay engine.
#[derive(Debug)]
pub enum ReplayError {
    /// Could not establish a connection to the target.
    Connect(String),
    /// A send operation failed.
    Send(String),
    /// A receive operation failed.
    Recv(String),
    /// An I/O error from the standard library.
    Io(std::io::Error),
    /// The session index is out of range.
    InvalidSession(usize),
    /// The protocol is unsupported.
    UnsupportedProtocol(String),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(s) => write!(f, "connect error: {s}"),
            Self::Send(s) => write!(f, "send error: {s}"),
            Self::Recv(s) => write!(f, "recv error: {s}"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::InvalidSession(i) => write!(f, "invalid session index: {i}"),
            Self::UnsupportedProtocol(p) => write!(f, "unsupported protocol: {p}"),
        }
    }
}

impl std::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<std::io::Error> for ReplayError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── TransportProtocol ─────────────────────────────────────────────────────────

/// The transport layer protocol used for replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// Transmission Control Protocol (stream, reliable).
    Tcp,
    /// User Datagram Protocol (datagram, unreliable).
    Udp,
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

// ── PacketSpec ────────────────────────────────────────────────────────────────

/// Specification of a single packet to send during replay.
#[derive(Debug, Clone)]
pub struct PacketSpec {
    /// Raw bytes to send.
    pub payload: Vec<u8>,
    /// Delay before sending (milliseconds).
    pub delay_ms: u64,
    /// If `true`, attempt to read a response after sending.
    pub expect_response: bool,
    /// Maximum bytes to read in the response.
    pub max_response_bytes: usize,
    /// Response read timeout in milliseconds.
    pub response_timeout_ms: u64,
    /// Optional human-readable label for this packet.
    pub label: Option<String>,
}

impl PacketSpec {
    /// Create a minimal packet spec with no delay and no expected response.
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            delay_ms: 0,
            expect_response: false,
            max_response_bytes: 4096,
            response_timeout_ms: 500,
            label: None,
        }
    }

    /// Request a response after sending.
    #[must_use]
    pub const fn with_response(mut self) -> Self {
        self.expect_response = true;
        self
    }

    /// Set the inter-packet delay.
    #[must_use]
    pub const fn with_delay_ms(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the maximum response size.
    #[must_use]
    pub const fn with_max_response(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        self
    }
}

// ── PacketResult ──────────────────────────────────────────────────────────────

/// The outcome of replaying a single [`PacketSpec`].
#[derive(Debug, Clone)]
pub struct PacketResult {
    /// Zero-based index of this packet in the session.
    pub index: usize,
    /// The payload that was sent.
    pub sent: Vec<u8>,
    /// Whether the send succeeded.
    pub send_ok: bool,
    /// Error message if the send failed.
    pub send_error: Option<String>,
    /// Response bytes received (empty if none expected or timed out).
    pub response: Vec<u8>,
    /// Whether the response read timed out.
    pub response_timeout: bool,
    /// Round-trip time from send to response read completion (microseconds).
    pub rtt_us: u64,
    /// Label from the corresponding [`PacketSpec`].
    pub label: Option<String>,
}

impl PacketResult {
    /// Returns `true` if the packet was sent successfully.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.send_ok
    }

    /// Returns `true` if a non-empty response was captured.
    #[must_use]
    pub fn has_response(&self) -> bool {
        !self.response.is_empty()
    }

    /// Returns the response as a lossy UTF-8 string for logging.
    #[must_use]
    pub fn response_str(&self) -> String {
        String::from_utf8_lossy(&self.response).into_owned()
    }
}

impl fmt::Display for PacketResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = self.label.as_deref().unwrap_or("<unlabelled>");
        if self.send_ok {
            write!(
                f,
                "[{}] #{} sent {} bytes, response {} bytes, rtt {}µs",
                label,
                self.index,
                self.sent.len(),
                self.response.len(),
                self.rtt_us
            )
        } else {
            write!(
                f,
                "[{}] #{} FAILED: {}",
                label,
                self.index,
                self.send_error.as_deref().unwrap_or("unknown")
            )
        }
    }
}

// ── SessionStatus ─────────────────────────────────────────────────────────────

/// Summary status of a completed [`ReplaySession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// All packets were sent successfully.
    Success,
    /// At least one packet failed to send.
    Failure,
    /// The session has not been executed yet.
    Pending,
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::Failure => write!(f, "Failure"),
            Self::Pending => write!(f, "Pending"),
        }
    }
}

// ── ReplaySession ─────────────────────────────────────────────────────────────

/// A single replay run targeting one address.
#[derive(Debug)]
pub struct ReplaySession {
    /// Human-readable name for this session.
    pub name: String,
    /// Target host:port string.
    pub target: String,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Packets to send in order.
    pub packets: Vec<PacketSpec>,
    /// Results recorded during execution (populated by [`ReplayEngine::run`]).
    pub results: Vec<PacketResult>,
    /// Overall status.
    pub status: SessionStatus,
    /// Wall-clock time the session started.
    pub started_at: Option<Instant>,
    /// Total elapsed time of the session in milliseconds.
    pub elapsed_ms: u64,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, String>,
}

impl ReplaySession {
    /// Create a new pending TCP session.
    #[must_use]
    pub fn tcp(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target: target.into(),
            protocol: TransportProtocol::Tcp,
            packets: Vec::new(),
            results: Vec::new(),
            status: SessionStatus::Pending,
            started_at: None,
            elapsed_ms: 0,
            metadata: HashMap::new(),
        }
    }

    /// Create a new pending UDP session.
    #[must_use]
    pub fn udp(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target: target.into(),
            protocol: TransportProtocol::Udp,
            packets: Vec::new(),
            results: Vec::new(),
            status: SessionStatus::Pending,
            started_at: None,
            elapsed_ms: 0,
            metadata: HashMap::new(),
        }
    }

    /// Append a packet specification.
    pub fn add_packet(&mut self, spec: PacketSpec) {
        self.packets.push(spec);
    }

    /// Number of packets that succeeded (populated after execution).
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.send_ok).count()
    }

    /// Number of packets that failed (populated after execution).
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.send_ok).count()
    }

    /// Collect all non-empty responses.
    #[must_use]
    pub fn all_responses(&self) -> Vec<&[u8]> {
        self.results
            .iter()
            .filter(|r| !r.response.is_empty())
            .map(|r| r.response.as_slice())
            .collect()
    }

    /// Mean round-trip time in microseconds across all successful sends.
    #[must_use]
    pub fn mean_rtt_us(&self) -> u64 {
        let ok: Vec<u64> = self
            .results
            .iter()
            .filter(|r| r.send_ok)
            .map(|r| r.rtt_us)
            .collect();
        if ok.is_empty() {
            return 0;
        }
        ok.iter().sum::<u64>() / ok.len() as u64
    }

    /// Run this session over TCP, populating `results` and `status`.
    ///
    /// # Errors
    /// [`ReplayError::Connect`] when the TCP handshake fails.
    pub fn run_tcp(&mut self) -> Result<(), ReplayError> {
        self.started_at = Some(Instant::now());
        let addr: SocketAddr = self
            .target
            .parse()
            .map_err(|e| ReplayError::Connect(format!("parse '{}': {e}", self.target)))?;
        let mut stream = TcpStream::connect(addr)
            .map_err(|e| ReplayError::Connect(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(ReplayError::Io)?;

        let mut all_ok = true;
        for (idx, spec) in self.packets.iter().enumerate() {
            if spec.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(spec.delay_ms));
            }
            let t0 = Instant::now();
            let send_res = stream.write_all(&spec.payload);
            let (send_ok, send_error) = match send_res {
                Ok(()) => (true, None),
                Err(e) => {
                    all_ok = false;
                    (false, Some(e.to_string()))
                }
            };

            let mut response = Vec::new();
            let mut response_timeout = false;
            if send_ok && spec.expect_response {
                let timeout = Duration::from_millis(spec.response_timeout_ms.max(1));
                stream.set_read_timeout(Some(timeout)).ok();
                let mut buf = vec![0u8; spec.max_response_bytes.min(65536)];
                match stream.read(&mut buf) {
                    Ok(n) => response.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        response_timeout = true;
                    }
                    Err(_) => {}
                }
            }
            let rtt_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
            self.results.push(PacketResult {
                index: idx,
                sent: spec.payload.clone(),
                send_ok,
                send_error,
                response,
                response_timeout,
                rtt_us,
                label: spec.label.clone(),
            });
        }

        self.elapsed_ms = self
            .started_at
            .map(|t| u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.status = if all_ok {
            SessionStatus::Success
        } else {
            SessionStatus::Failure
        };
        Ok(())
    }

    /// Run this session over UDP.
    ///
    /// # Errors
    /// [`ReplayError::Connect`] when the socket cannot be bound.
    pub fn run_udp(&mut self) -> Result<(), ReplayError> {
        self.started_at = Some(Instant::now());
        let target: SocketAddr = self
            .target
            .parse()
            .map_err(|e| ReplayError::Connect(format!("parse '{}': {e}", self.target)))?;
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| ReplayError::Connect(e.to_string()))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(ReplayError::Io)?;

        let mut all_ok = true;
        for (idx, spec) in self.packets.iter().enumerate() {
            if spec.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(spec.delay_ms));
            }
            let t0 = Instant::now();
            let send_res = socket.send_to(&spec.payload, target);
            let (send_ok, send_error) = match send_res {
                Ok(_) => (true, None),
                Err(e) => {
                    all_ok = false;
                    (false, Some(e.to_string()))
                }
            };

            let mut response = Vec::new();
            let mut response_timeout = false;
            if send_ok && spec.expect_response {
                let timeout = Duration::from_millis(spec.response_timeout_ms.max(1));
                socket.set_read_timeout(Some(timeout)).ok();
                let mut buf = vec![0u8; spec.max_response_bytes.min(65536)];
                match socket.recv_from(&mut buf) {
                    Ok((n, _)) => response.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        response_timeout = true;
                    }
                    Err(_) => {}
                }
            }
            let rtt_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX);
            self.results.push(PacketResult {
                index: idx,
                sent: spec.payload.clone(),
                send_ok,
                send_error,
                response,
                response_timeout,
                rtt_us,
                label: spec.label.clone(),
            });
        }

        self.elapsed_ms = self
            .started_at
            .map(|t| u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.status = if all_ok {
            SessionStatus::Success
        } else {
            SessionStatus::Failure
        };
        Ok(())
    }
}

// ── ReplayEngine ──────────────────────────────────────────────────────────────

/// Manages and executes multiple [`ReplaySession`]s.
#[derive(Default)]
pub struct ReplayEngine {
    /// Registered sessions.
    pub sessions: Vec<ReplaySession>,
    /// Global inter-session delay in milliseconds.
    pub inter_session_delay_ms: u64,
    /// If `true`, stop on the first session failure.
    pub stop_on_failure: bool,
}

impl ReplayEngine {
    /// Create a new engine with no sessions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the delay between sessions.
    #[must_use]
    pub const fn with_inter_session_delay(mut self, ms: u64) -> Self {
        self.inter_session_delay_ms = ms;
        self
    }

    /// Stop after the first failed session.
    #[must_use]
    pub const fn stop_on_failure(mut self) -> Self {
        self.stop_on_failure = true;
        self
    }

    /// Register a session.
    pub fn add_session(&mut self, session: ReplaySession) {
        self.sessions.push(session);
    }

    /// Number of registered sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Run all sessions in order.  Returns the number of sessions that
    /// completed successfully.
    ///
    /// # Errors
    /// Returns [`ReplayError`] only when a fundamental setup failure prevents
    /// any session from running.  Per-packet send errors are recorded in
    /// [`PacketResult`] and do not propagate here unless `stop_on_failure` is
    /// set and a connect-level error occurs.
    pub fn run_all(&mut self) -> Result<usize, ReplayError> {
        let mut success_count = 0usize;
        for session in &mut self.sessions {
            if self.inter_session_delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.inter_session_delay_ms));
            }
            let result = match session.protocol {
                TransportProtocol::Tcp => session.run_tcp(),
                TransportProtocol::Udp => session.run_udp(),
            };
            match result {
                Ok(()) => {
                    if session.status == SessionStatus::Success {
                        success_count += 1;
                    } else if self.stop_on_failure {
                        break;
                    }
                }
                Err(e) => {
                    session.status = SessionStatus::Failure;
                    if self.stop_on_failure {
                        return Err(e);
                    }
                }
            }
        }
        Ok(success_count)
    }

    /// Run only the session at `index`.
    ///
    /// # Errors
    /// [`ReplayError::InvalidSession`] if `index >= session_count`.
    pub fn run_one(&mut self, index: usize) -> Result<(), ReplayError> {
        let session = self
            .sessions
            .get_mut(index)
            .ok_or(ReplayError::InvalidSession(index))?;
        match session.protocol {
            TransportProtocol::Tcp => session.run_tcp(),
            TransportProtocol::Udp => session.run_udp(),
        }
    }

    /// Aggregate statistics across all sessions.
    #[must_use]
    pub fn aggregate_stats(&self) -> ReplayStats {
        let total_sessions = self.sessions.len();
        let successful_sessions = self
            .sessions
            .iter()
            .filter(|s| s.status == SessionStatus::Success)
            .count();
        let total_packets: usize = self.sessions.iter().map(|s| s.packets.len()).collect::<Vec<_>>().iter().sum();
        let sent_ok: usize = self
            .sessions
            .iter()
            .flat_map(|s| s.results.iter())
            .filter(|r| r.send_ok)
            .count();
        let send_failures: usize = self
            .sessions
            .iter()
            .flat_map(|s| s.results.iter())
            .filter(|r| !r.send_ok)
            .count();
        let total_response_bytes: usize = self
            .sessions
            .iter()
            .flat_map(|s| s.results.iter())
            .map(|r| r.response.len())
            .sum();
        ReplayStats {
            total_sessions,
            successful_sessions,
            total_packets,
            sent_ok,
            send_failures,
            total_response_bytes,
        }
    }
}

/// Aggregate replay statistics.
#[derive(Debug, Clone)]
pub struct ReplayStats {
    /// Total number of sessions.
    pub total_sessions: usize,
    /// Sessions where all sends succeeded.
    pub successful_sessions: usize,
    /// Total number of packet specs across all sessions.
    pub total_packets: usize,
    /// Total successful sends.
    pub sent_ok: usize,
    /// Total failed sends.
    pub send_failures: usize,
    /// Total bytes received across all responses.
    pub total_response_bytes: usize,
}

impl fmt::Display for ReplayStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sessions={}/{} packets={} ok={} fail={} response_bytes={}",
            self.successful_sessions,
            self.total_sessions,
            self.total_packets,
            self.sent_ok,
            self.send_failures,
            self.total_response_bytes
        )
    }
}

// ── replay_sequence free function ─────────────────────────────────────────────

/// Replay a raw sequence of byte slices over TCP to `target`.
///
/// This is a convenience wrapper for quick reproduction of a crash sequence
/// captured from a fuzzing run.  Returns a list of [`PacketResult`]s.
///
/// # Errors
/// [`ReplayError::Connect`] when the TCP connection cannot be established.
pub fn replay_sequence(
    target: &str,
    payloads: &[Vec<u8>],
    expect_responses: bool,
) -> Result<Vec<PacketResult>, ReplayError> {
    let mut session = ReplaySession::tcp("quick-replay", target);
    for (i, payload) in payloads.iter().enumerate() {
        let spec = PacketSpec::new(payload.clone())
            .with_label(format!("pkt-{i}"))
            .with_response()
            .with_delay_ms(0);
        let spec = if expect_responses {
            spec
        } else {
            PacketSpec {
                expect_response: false,
                ..spec
            }
        };
        session.add_packet(spec);
    }
    session.run_tcp()?;
    Ok(session.results)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PacketSpec ────────────────────────────────────────────────────────────

    #[test]
    fn packet_spec_defaults() {
        let s = PacketSpec::new(b"hello".to_vec());
        assert_eq!(s.payload, b"hello");
        assert!(!s.expect_response);
        assert_eq!(s.delay_ms, 0);
        assert!(s.label.is_none());
    }

    #[test]
    fn packet_spec_builder_chain() {
        let s = PacketSpec::new(b"ping".to_vec())
            .with_response()
            .with_delay_ms(10)
            .with_label("test-pkt")
            .with_max_response(512);
        assert!(s.expect_response);
        assert_eq!(s.delay_ms, 10);
        assert_eq!(s.label.as_deref(), Some("test-pkt"));
        assert_eq!(s.max_response_bytes, 512);
    }

    // ── PacketResult ──────────────────────────────────────────────────────────

    #[test]
    fn packet_result_ok() {
        let r = PacketResult {
            index: 0,
            sent: b"data".to_vec(),
            send_ok: true,
            send_error: None,
            response: b"ok".to_vec(),
            response_timeout: false,
            rtt_us: 100,
            label: Some("t".to_string()),
        };
        assert!(r.is_ok());
        assert!(r.has_response());
        assert_eq!(r.response_str(), "ok");
    }

    #[test]
    fn packet_result_failure() {
        let r = PacketResult {
            index: 1,
            sent: b"bad".to_vec(),
            send_ok: false,
            send_error: Some("refused".to_string()),
            response: Vec::new(),
            response_timeout: false,
            rtt_us: 0,
            label: None,
        };
        assert!(!r.is_ok());
        assert!(!r.has_response());
    }

    #[test]
    fn packet_result_display() {
        let r = PacketResult {
            index: 0,
            sent: b"hello".to_vec(),
            send_ok: true,
            send_error: None,
            response: b"world".to_vec(),
            response_timeout: false,
            rtt_us: 42,
            label: Some("greet".to_string()),
        };
        let s = r.to_string();
        assert!(s.contains("greet"));
        assert!(s.contains("5 bytes")); // sent 5 bytes
    }

    // ── ReplaySession (no-network) ────────────────────────────────────────────

    #[test]
    fn session_tcp_new() {
        let s = ReplaySession::tcp("s1", "127.0.0.1:9999");
        assert_eq!(s.protocol, TransportProtocol::Tcp);
        assert_eq!(s.status, SessionStatus::Pending);
        assert!(s.results.is_empty());
    }

    #[test]
    fn session_udp_new() {
        let s = ReplaySession::udp("s2", "127.0.0.1:9999");
        assert_eq!(s.protocol, TransportProtocol::Udp);
    }

    #[test]
    fn session_add_packets() {
        let mut s = ReplaySession::tcp("s3", "127.0.0.1:9999");
        s.add_packet(PacketSpec::new(b"a".to_vec()));
        s.add_packet(PacketSpec::new(b"b".to_vec()));
        assert_eq!(s.packets.len(), 2);
    }

    #[test]
    fn session_success_failure_count_with_manual_results() {
        let mut s = ReplaySession::tcp("s4", "127.0.0.1:9999");
        s.results.push(PacketResult {
            index: 0,
            sent: b"x".to_vec(),
            send_ok: true,
            send_error: None,
            response: Vec::new(),
            response_timeout: false,
            rtt_us: 0,
            label: None,
        });
        s.results.push(PacketResult {
            index: 1,
            sent: b"y".to_vec(),
            send_ok: false,
            send_error: Some("err".to_string()),
            response: Vec::new(),
            response_timeout: false,
            rtt_us: 0,
            label: None,
        });
        assert_eq!(s.success_count(), 1);
        assert_eq!(s.failure_count(), 1);
    }

    #[test]
    fn session_mean_rtt_no_results() {
        let s = ReplaySession::tcp("empty", "127.0.0.1:9999");
        assert_eq!(s.mean_rtt_us(), 0);
    }

    #[test]
    fn session_mean_rtt_computed() {
        let mut s = ReplaySession::tcp("rtt", "127.0.0.1:9999");
        for rtt in [100u64, 200, 300] {
            s.results.push(PacketResult {
                index: 0,
                sent: vec![],
                send_ok: true,
                send_error: None,
                response: vec![],
                response_timeout: false,
                rtt_us: rtt,
                label: None,
            });
        }
        assert_eq!(s.mean_rtt_us(), 200);
    }

    // ── ReplayEngine (no-network) ─────────────────────────────────────────────

    #[test]
    fn engine_add_session() {
        let mut e = ReplayEngine::new();
        e.add_session(ReplaySession::tcp("s", "127.0.0.1:1"));
        assert_eq!(e.session_count(), 1);
    }

    #[test]
    fn engine_invalid_session_index() {
        let mut e = ReplayEngine::new();
        let err = e.run_one(99).unwrap_err();
        assert!(matches!(err, ReplayError::InvalidSession(99)));
    }

    #[test]
    fn engine_aggregate_stats_empty() {
        let e = ReplayEngine::new();
        let stats = e.aggregate_stats();
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.total_packets, 0);
    }

    #[test]
    fn replay_stats_display() {
        let stats = ReplayStats {
            total_sessions: 3,
            successful_sessions: 2,
            total_packets: 10,
            sent_ok: 9,
            send_failures: 1,
            total_response_bytes: 512,
        };
        let s = stats.to_string();
        assert!(s.contains("2/3"));
        assert!(s.contains("10"));
    }

    // ── TransportProtocol ─────────────────────────────────────────────────────

    #[test]
    fn transport_protocol_display() {
        assert_eq!(TransportProtocol::Tcp.to_string(), "TCP");
        assert_eq!(TransportProtocol::Udp.to_string(), "UDP");
    }

    // ── SessionStatus ─────────────────────────────────────────────────────────

    #[test]
    fn session_status_display() {
        assert_eq!(SessionStatus::Success.to_string(), "Success");
        assert_eq!(SessionStatus::Pending.to_string(), "Pending");
        assert_eq!(SessionStatus::Failure.to_string(), "Failure");
    }

    // ── ReplayError ───────────────────────────────────────────────────────────

    #[test]
    fn replay_error_display() {
        let e = ReplayError::Connect("refused".to_string());
        assert!(e.to_string().contains("refused"));
        let e2 = ReplayError::InvalidSession(5);
        assert!(e2.to_string().contains('5'));
    }
}
