//! `network_behavior_simulator` — emulate network activity triggered by shellcode.
//!
//! Rather than hitting the real network, [`NetworkBehaviorSimulator`] intercepts
//! common socket-family API calls from the execution log and synthesises
//! [`SimulatedConnection`] records that describe what the shellcode *would* have
//! done.  All captured outbound data is accumulated in [`CapturedTraffic`].

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

// ── SocketFamily / SocketType ─────────────────────────────────────────────────

/// IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketFamily {
    Ipv4,
    Ipv6,
    Unix,
    Unknown(u32),
}

impl fmt::Display for SocketFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => f.write_str("AF_INET"),
            Self::Ipv6 => f.write_str("AF_INET6"),
            Self::Unix => f.write_str("AF_UNIX"),
            Self::Unknown(n) => write!(f, "AF_UNKNOWN({n})"),
        }
    }
}

impl SocketFamily {
    pub fn from_raw(v: u32) -> Self {
        match v {
            2 => Self::Ipv4,
            10 => Self::Ipv6,
            1 => Self::Unix,
            n => Self::Unknown(n),
        }
    }
}

/// Socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketType {
    Stream,
    Dgram,
    Raw,
    Unknown(u32),
}

impl fmt::Display for SocketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream => f.write_str("SOCK_STREAM"),
            Self::Dgram => f.write_str("SOCK_DGRAM"),
            Self::Raw => f.write_str("SOCK_RAW"),
            Self::Unknown(n) => write!(f, "SOCK_UNKNOWN({n})"),
        }
    }
}

impl SocketType {
    pub fn from_raw(v: u32) -> Self {
        match v {
            1 => Self::Stream,
            2 => Self::Dgram,
            3 => Self::Raw,
            n => Self::Unknown(n),
        }
    }
}

// ── ConnectionState ───────────────────────────────────────────────────────────

/// Lifecycle state of a simulated connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    Created,
    Connecting,
    Connected,
    DataTransferred,
    Closed,
    Failed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::DataTransferred => "data_transferred",
            Self::Closed => "closed",
            Self::Failed => "failed",
        };
        f.write_str(s)
    }
}

// ── SimulatedConnection ───────────────────────────────────────────────────────

/// A simulated socket connection derived from shellcode API call analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedConnection {
    /// Unique handle (mirrors the fake socket file-descriptor the emulator returned).
    pub handle: u64,
    /// Socket family.
    pub family: SocketFamily,
    /// Socket type.
    pub sock_type: SocketType,
    /// Remote IP address (may be synthetic).
    pub remote_ip: IpAddr,
    /// Remote port.
    pub remote_port: u16,
    /// Connection state at end of trace.
    pub state: ConnectionState,
    /// Bytes sent (raw buffer captured from `send`/`sendto` args).
    pub sent: Vec<u8>,
    /// Bytes received (simulated response injected by the simulator).
    pub received: Vec<u8>,
    /// Ordered API calls that affected this connection (name, call-site VA).
    pub api_events: Vec<(String, u64)>,
}

impl SimulatedConnection {
    fn new(handle: u64, family: SocketFamily, sock_type: SocketType) -> Self {
        Self {
            handle,
            family,
            sock_type,
            remote_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
            state: ConnectionState::Created,
            sent: Vec::new(),
            received: Vec::new(),
            api_events: Vec::new(),
        }
    }

    /// Total bytes transferred (sent + received).
    pub fn total_bytes(&self) -> usize {
        self.sent.len() + self.received.len()
    }

    /// Return `true` when the connection reached at least `Connected` state.
    pub fn was_connected(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connected | ConnectionState::DataTransferred | ConnectionState::Closed
        )
    }
}

impl fmt::Display for SimulatedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conn[0x{:x}] {} {}:{} state={} sent={} recv={}",
            self.handle,
            self.sock_type,
            self.remote_ip,
            self.remote_port,
            self.state,
            self.sent.len(),
            self.received.len(),
        )
    }
}

// ── CapturedTraffic ───────────────────────────────────────────────────────────

/// All network activity captured during a shellcode simulation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapturedTraffic {
    /// All simulated connections, keyed by handle.
    pub connections: HashMap<u64, SimulatedConnection>,
    /// Unique remote IPs contacted.
    pub remote_ips: Vec<IpAddr>,
    /// Unique remote ports contacted.
    pub remote_ports: Vec<u16>,
    /// All outbound payloads (concatenated bytes per connection).
    pub outbound_payloads: Vec<Vec<u8>>,
    /// DNS-like hostname strings extracted from `send` data.
    pub dns_queries: Vec<String>,
    /// HTTP request lines detected in outbound data.
    pub http_requests: Vec<String>,
    /// Total bytes sent across all connections.
    pub total_sent: usize,
    /// Total bytes received (simulated).
    pub total_received: usize,
}

impl CapturedTraffic {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` when any connection was successfully established.
    pub fn has_connections(&self) -> bool {
        self.connections.values().any(|c| c.was_connected())
    }

    /// Return the first remote IP encountered, if any.
    pub fn primary_remote(&self) -> Option<IpAddr> {
        self.remote_ips.first().copied()
    }

    /// Collect printable strings (>= 6 bytes) from all outbound payloads.
    pub fn outbound_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for payload in &self.outbound_payloads {
            let mut cur = Vec::<u8>::new();
            for &b in payload {
                if (0x20..=0x7e).contains(&b) {
                    cur.push(b);
                } else {
                    if cur.len() >= 6 {
                        if let Ok(s) = std::str::from_utf8(&cur) {
                            out.push(s.to_owned());
                        }
                    }
                    cur.clear();
                }
            }
            if cur.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    out.push(s.to_owned());
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

// ── NetworkBehaviorSimulator ──────────────────────────────────────────────────

/// Simulates the network-level behaviour implied by shellcode API calls.
///
/// Feed it an execution log (list of API call names and their arguments from
/// the emulator), and it builds a [`CapturedTraffic`] model of what would have
/// happened on the wire.
#[derive(Debug, Clone, Default)]
pub struct NetworkBehaviorSimulator {
    /// Synthetic response to inject when `recv`/`recvfrom` is called.
    pub recv_response: Vec<u8>,
    /// Maximum bytes to extract from a `send` argument (to avoid noise).
    pub max_send_bytes: usize,
}

impl NetworkBehaviorSimulator {
    pub fn new() -> Self {
        Self {
            recv_response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            max_send_bytes: 4096,
        }
    }

    /// Set the synthetic HTTP-ish response injected on every `recv`.
    pub fn with_recv_response(mut self, resp: Vec<u8>) -> Self {
        self.recv_response = resp;
        self
    }

    /// Simulate network behaviour from a flat list of `(api_name, address, args)` tuples.
    ///
    /// `args` is a slice of up to 6 register values passed to the API call.
    pub fn simulate(&self, calls: &[(String, u64, Vec<u64>)]) -> CapturedTraffic {
        let mut traffic = CapturedTraffic::new();
        // socket_handle → SimulatedConnection
        let mut connections: HashMap<u64, SimulatedConnection> = HashMap::new();
        // next handle counter
        let mut next_handle = 0x1000u64;

        for (api, addr, args) in calls {
            let api_lc = api.to_ascii_lowercase();
            match api_lc.as_str() {
                "socket" | "wsasocketa" | "wsasocketw" => {
                    let family = args.first().map(|&v| SocketFamily::from_raw(v as u32)).unwrap_or(SocketFamily::Ipv4);
                    let sock_type = args.get(1).map(|&v| SocketType::from_raw(v as u32)).unwrap_or(SocketType::Stream);
                    let handle = next_handle;
                    next_handle += 1;
                    let mut conn = SimulatedConnection::new(handle, family, sock_type);
                    conn.api_events.push((api.clone(), *addr));
                    connections.insert(handle, conn);
                }
                "connect" | "wsaconnect" => {
                    let handle = args.first().copied().unwrap_or(0);
                    let ip = extract_ip_from_sockaddr(args.get(1).copied().unwrap_or(0));
                    let port = extract_port_from_sockaddr(args.get(1).copied().unwrap_or(0));
                    if let Some(conn) = connections.get_mut(&handle) {
                        conn.remote_ip = ip;
                        conn.remote_port = port;
                        conn.state = ConnectionState::Connected;
                        conn.api_events.push((api.clone(), *addr));
                        if !traffic.remote_ips.contains(&ip) { traffic.remote_ips.push(ip); }
                        if !traffic.remote_ports.contains(&port) { traffic.remote_ports.push(port); }
                    }
                }
                "send" | "wsasend" => {
                    let handle = args.first().copied().unwrap_or(0);
                    // args[2] = length hint
                    let len = args.get(2).copied().unwrap_or(32) as usize;
                    let len = len.min(self.max_send_bytes);
                    // We synthesise the payload since we can't read real memory here.
                    let payload = synthesise_send_payload(len, *addr);
                    if let Some(conn) = connections.get_mut(&handle) {
                        // Cap per-connection sent bytes at 16 MiB to prevent
                        // memory exhaustion when shellcode calls send in a loop.
                        const MAX_SENT_PER_CONN: usize = 16 * 1024 * 1024;
                        let space = MAX_SENT_PER_CONN.saturating_sub(conn.sent.len());
                        let to_append = payload.len().min(space);
                        conn.sent.extend_from_slice(&payload[..to_append]);
                        conn.state = ConnectionState::DataTransferred;
                        conn.api_events.push((api.clone(), *addr));
                        traffic.total_sent += to_append;
                        traffic.outbound_payloads.push(payload[..to_append].to_vec());
                        // Detect HTTP
                        if let Ok(s) = std::str::from_utf8(&payload) {
                            if s.starts_with("GET ") || s.starts_with("POST ") || s.starts_with("HEAD ") {
                                if let Some(line) = s.lines().next() {
                                    traffic.http_requests.push(line.to_owned());
                                }
                            }
                        }
                    }
                }
                "sendto" => {
                    let handle = args.first().copied().unwrap_or(0);
                    let len = args.get(2).copied().unwrap_or(32) as usize;
                    let payload = synthesise_send_payload(len.min(self.max_send_bytes), *addr);
                    if let Some(conn) = connections.get_mut(&handle) {
                        conn.sent.extend_from_slice(&payload);
                        conn.api_events.push((api.clone(), *addr));
                        traffic.total_sent += payload.len();
                        traffic.outbound_payloads.push(payload);
                    }
                }
                "recv" | "recvfrom" | "wsarecv" => {
                    let handle = args.first().copied().unwrap_or(0);
                    let resp = self.recv_response.clone();
                    if let Some(conn) = connections.get_mut(&handle) {
                        // Cap per-connection received bytes at 1 MiB to prevent
                        // memory exhaustion when shellcode calls recv in a tight
                        // loop — each call would otherwise append `recv_response`
                        // (up to ~40 bytes by default, but configurable) without
                        // any upper bound, constituting a dos-memory-exhaustion.
                        const MAX_RECV_PER_CONN: usize = 1024 * 1024;
                        let space = MAX_RECV_PER_CONN.saturating_sub(conn.received.len());
                        let to_append = resp.len().min(space);
                        conn.received.extend_from_slice(&resp[..to_append]);
                        traffic.total_received += to_append;
                        conn.api_events.push((api.clone(), *addr));
                    }
                }
                "closesocket" | "close" | "shutdown" => {
                    let handle = args.first().copied().unwrap_or(0);
                    if let Some(conn) = connections.get_mut(&handle) {
                        conn.state = ConnectionState::Closed;
                        conn.api_events.push((api.clone(), *addr));
                    }
                }
                "gethostbyname" | "getaddrinfo" | "dnsquery_a" => {
                    // Synthesise a DNS query entry.
                    let query = format!("dns_query@0x{addr:x}");
                    if !traffic.dns_queries.contains(&query) {
                        traffic.dns_queries.push(query);
                    }
                }
                "internetopena" | "internetopenw" => {
                    // WinINet — treat as a pseudo-connection.
                    let handle = next_handle;
                    next_handle += 1;
                    let mut conn = SimulatedConnection::new(handle, SocketFamily::Ipv4, SocketType::Stream);
                    conn.api_events.push((api.clone(), *addr));
                    connections.insert(handle, conn);
                }
                "internetconnecta" | "internetconnectw" => {
                    // args[1] = hostname ptr (we can't dereference, synthesise from addr)
                    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
                    let port = args.get(2).copied().unwrap_or(80) as u16;
                    // Attach to last WinINet connection.
                    if let Some(conn) = connections.values_mut().last() {
                        conn.remote_ip = ip;
                        conn.remote_port = port;
                        conn.state = ConnectionState::Connected;
                        conn.api_events.push((api.clone(), *addr));
                        if !traffic.remote_ips.contains(&ip) { traffic.remote_ips.push(ip); }
                        if !traffic.remote_ports.contains(&port) { traffic.remote_ports.push(port); }
                    }
                }
                _ => {} // Non-network API — ignore.
            }
        }

        traffic.connections = connections;
        traffic
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Synthesise a plausible send payload when the real memory buffer is unavailable.
/// Uses a simple deterministic pattern seeded by `len` and `pc`.
fn synthesise_send_payload(len: usize, pc: u64) -> Vec<u8> {
    (0..len).map(|i| ((i as u64 + pc) & 0xFF) as u8).collect()
}

/// Extract an IP address from a raw sockaddr pointer value.
/// Since we cannot dereference the emulated address, we synthesise a plausible IP.
fn extract_ip_from_sockaddr(ptr: u64) -> IpAddr {
    // Use the pointer value bytes as synthetic octets — non-zero, non-broadcast.
    let bytes = ptr.to_le_bytes();
    let a = if bytes[0] == 0 { 10 } else { bytes[0] };
    let b = if bytes[1] == 0 { 0 } else { bytes[1] };
    let c = if bytes[2] == 0 { 0 } else { bytes[2] };
    let d = if bytes[3] == 0 { 1 } else { bytes[3] };
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Extract a port from a raw sockaddr pointer value.
fn extract_port_from_sockaddr(ptr: u64) -> u16 {
    let bytes = ptr.to_le_bytes();
    // htons of bytes[4..6] — synthetic.
    let raw = u16::from_le_bytes([bytes[4], bytes[5]]);
    if raw == 0 { 80 } else { raw }
}

// ── NetworkReport ─────────────────────────────────────────────────────────────

/// Summary report generated from a [`CapturedTraffic`] instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    pub connection_count: usize,
    pub connected_count: usize,
    pub unique_ips: Vec<String>,
    pub unique_ports: Vec<u16>,
    pub total_sent_bytes: usize,
    pub total_recv_bytes: usize,
    pub dns_query_count: usize,
    pub http_request_count: usize,
    pub outbound_string_count: usize,
}

impl NetworkReport {
    pub fn from_traffic(traffic: &CapturedTraffic) -> Self {
        Self {
            connection_count: traffic.connections.len(),
            connected_count: traffic.connections.values().filter(|c| c.was_connected()).count(),
            unique_ips: traffic.remote_ips.iter().map(|ip| ip.to_string()).collect(),
            unique_ports: traffic.remote_ports.clone(),
            total_sent_bytes: traffic.total_sent,
            total_recv_bytes: traffic.total_received,
            dns_query_count: traffic.dns_queries.len(),
            http_request_count: traffic.http_requests.len(),
            outbound_string_count: traffic.outbound_strings().len(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str, addr: u64, args: &[u64]) -> (String, u64, Vec<u64>) {
        (name.to_owned(), addr, args.to_vec())
    }

    #[test]
    fn simulate_empty_no_connections() {
        let sim = NetworkBehaviorSimulator::new();
        let t = sim.simulate(&[]);
        assert!(t.connections.is_empty());
        assert!(!t.has_connections());
    }

    #[test]
    fn simulate_socket_creates_connection() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [call("socket", 0x1000, &[2, 1, 0])];
        let t = sim.simulate(&calls);
        assert_eq!(t.connections.len(), 1);
    }

    #[test]
    fn simulate_connect_sets_state() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [
            call("socket", 0x1000, &[2, 1, 0]),
            call("connect", 0x1010, &[0x1000, 0xC0A80001_0050_0000u64, 16]),
        ];
        let t = sim.simulate(&calls);
        let conn = t.connections.values().next().unwrap();
        assert!(conn.was_connected());
    }

    #[test]
    fn simulate_send_records_bytes() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [
            call("socket", 0x1000, &[2, 1, 0]),
            call("connect", 0x1010, &[0x1000, 0, 16]),
            call("send", 0x1020, &[0x1000, 0x2000, 32, 0]),
        ];
        let t = sim.simulate(&calls);
        let conn = t.connections.values().next().unwrap();
        assert!(!conn.sent.is_empty());
        assert!(t.total_sent > 0);
    }

    #[test]
    fn simulate_recv_injects_response() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [
            call("socket", 0x1000, &[2, 1, 0]),
            call("connect", 0x1010, &[0x1000, 0, 16]),
            call("recv", 0x1030, &[0x1000, 0x3000, 256, 0]),
        ];
        let t = sim.simulate(&calls);
        let conn = t.connections.values().next().unwrap();
        assert!(!conn.received.is_empty());
        assert!(t.total_received > 0);
    }

    #[test]
    fn simulate_closesocket_sets_closed() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [
            call("socket", 0x1000, &[2, 1, 0]),
            call("connect", 0x1010, &[0x1000, 0, 16]),
            call("closesocket", 0x1050, &[0x1000]),
        ];
        let t = sim.simulate(&calls);
        let conn = t.connections.values().next().unwrap();
        assert_eq!(conn.state, ConnectionState::Closed);
    }

    #[test]
    fn simulate_dns_query_recorded() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [call("gethostbyname", 0x2000, &[0xDEAD])];
        let t = sim.simulate(&calls);
        assert!(!t.dns_queries.is_empty());
    }

    #[test]
    fn simulated_connection_total_bytes() {
        let mut conn = SimulatedConnection::new(1, SocketFamily::Ipv4, SocketType::Stream);
        conn.sent = vec![0u8; 100];
        conn.received = vec![0u8; 200];
        assert_eq!(conn.total_bytes(), 300);
    }

    #[test]
    fn simulated_connection_display() {
        let conn = SimulatedConnection::new(0x42, SocketFamily::Ipv4, SocketType::Stream);
        let s = conn.to_string();
        assert!(s.contains("0x42"));
    }

    #[test]
    fn captured_traffic_outbound_strings() {
        let mut t = CapturedTraffic::new();
        t.outbound_payloads.push(b"GET /payload HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec());
        let strings = t.outbound_strings();
        assert!(strings.iter().any(|s| s.contains("HTTP")));
    }

    #[test]
    fn network_report_from_traffic() {
        let sim = NetworkBehaviorSimulator::new();
        let calls = [
            call("socket", 0x1000, &[2, 1, 0]),
            call("connect", 0x1010, &[0x1000, 0x0A000001_0050u64, 16]),
            call("send", 0x1020, &[0x1000, 0x2000, 64, 0]),
        ];
        let t = sim.simulate(&calls);
        let r = NetworkReport::from_traffic(&t);
        assert_eq!(r.connection_count, 1);
        assert!(r.total_sent_bytes > 0);
    }

    #[test]
    fn socket_family_display() {
        assert_eq!(SocketFamily::Ipv4.to_string(), "AF_INET");
        assert_eq!(SocketFamily::Unknown(99).to_string(), "AF_UNKNOWN(99)");
    }

    #[test]
    fn socket_type_display() {
        assert_eq!(SocketType::Stream.to_string(), "SOCK_STREAM");
    }

    #[test]
    fn connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
    }

    #[test]
    fn socket_family_from_raw() {
        assert_eq!(SocketFamily::from_raw(2), SocketFamily::Ipv4);
        assert_eq!(SocketFamily::from_raw(10), SocketFamily::Ipv6);
    }
}
