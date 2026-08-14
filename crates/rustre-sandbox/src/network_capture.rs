//! Network capture for sandboxed processes.
//!
//! Captures DNS queries, HTTP requests, TCP/UDP connections, and reconstructs
//! higher-level network flows for behavioural analysis.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ── Transport protocol ─────────────────────────────────────────────────────────

/// Layer-4 transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── DNS ────────────────────────────────────────────────────────────────────────

/// Type of DNS record queried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    Aaaa,
    Mx,
    Txt,
    Cname,
    Ns,
    Ptr,
    Any,
    Other(String),
}

impl std::fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Cname => write!(f, "CNAME"),
            Self::Ns => write!(f, "NS"),
            Self::Ptr => write!(f, "PTR"),
            Self::Any => write!(f, "ANY"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// A single DNS query captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Queried hostname.
    pub name: String,
    /// Query type.
    pub query_type: DnsQueryType,
    /// Resolved IP addresses (empty if query failed or not yet resolved).
    pub resolved_ips: Vec<String>,
    /// Whether the query was answered (vs. NXDOMAIN / timeout).
    pub answered: bool,
    /// PID that issued the query.
    pub pid: u32,
    /// Timestamp in ms since capture start.
    pub timestamp_ms: u64,
    /// Whether this domain looks like a DGA-generated name.
    pub dga_suspect: bool,
}

impl DnsQuery {
    /// Create a new DNS query event.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        query_type: DnsQueryType,
        pid: u32,
        timestamp_ms: u64,
    ) -> Self {
        let name = name.into();
        let dga_suspect = Self::score_dga(&name) > 0.7;
        Self {
            name,
            query_type,
            resolved_ips: Vec::new(),
            answered: false,
            pid,
            timestamp_ms,
            dga_suspect,
        }
    }

    /// Losslessly-truncated cast from `usize` to `f32` for heuristic ratios.
    fn usize_to_f32(n: usize) -> f32 {
        f32::from(u16::try_from(n).unwrap_or(u16::MAX))
    }

    /// Simple DGA heuristic: entropy / consonant-cluster ratio.
    fn score_dga(name: &str) -> f32 {
        let label = name.split('.').next().unwrap_or(name);
        if label.len() < 8 {
            return 0.0;
        }
        let vowels = "aeiou";
        let consonant_runs = label
            .chars()
            .fold((0u32, 0u32, false), |(run_count, max_run, in_run), c| {
                if c.is_ascii_alphabetic() && !vowels.contains(c) {
                    if in_run {
                        (run_count, max_run.max(1), true)
                    } else {
                        (run_count + 1, max_run.max(1), true)
                    }
                } else {
                    (run_count, max_run, false)
                }
            });
        let digit_ratio = Self::usize_to_f32(label.chars().filter(char::is_ascii_digit).count())
            / Self::usize_to_f32(label.len());
        // Rough heuristic: high digit ratio + many consonant clusters → suspicious
        let runs_f32 = f32::from(u16::try_from(consonant_runs.0).unwrap_or(u16::MAX));
        (runs_f32 / Self::usize_to_f32(label.len())).mul_add(0.5, digit_ratio * 0.5)
    }

    /// Builder: add resolved IP addresses.
    #[must_use]
    pub fn with_resolved(mut self, ips: Vec<String>) -> Self {
        self.resolved_ips = ips;
        self.answered = !self.resolved_ips.is_empty();
        self
    }

    /// Returns `true` if at least one resolved IP is external (non-RFC1918).
    #[must_use]
    pub fn resolves_to_external(&self) -> bool {
        self.resolved_ips.iter().any(|ip| {
            IpAddr::from_str(ip).is_ok_and(|addr| match addr {
                IpAddr::V4(v4) => {
                    !v4.is_private() && !v4.is_loopback() && !v4.is_link_local()
                }
                IpAddr::V6(v6) => !v6.is_loopback(),
            })
        })
    }
}

// ── HTTP ───────────────────────────────────────────────────────────────────────

/// HTTP method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Other(String),
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Patch => write!(f, "PATCH"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl HttpMethod {
    /// Parse from a string (case-insensitive).
    #[must_use]
    pub fn from_str_ci(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            other => Self::Other(other.to_string()),
        }
    }
}

/// An HTTP/HTTPS request reconstructed from network traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// Full URL (scheme + host + path + query).
    pub url: String,
    /// HTTP method.
    pub method: HttpMethod,
    /// Whether TLS (HTTPS) was used.
    pub is_https: bool,
    /// HTTP version string (e.g. `"1.1"`, `"2"`).
    pub http_version: String,
    /// Request headers as key-value pairs.
    pub headers: Vec<(String, String)>,
    /// Request body size in bytes.
    pub body_size: usize,
    /// HTTP response status code (`None` if not captured).
    pub response_status: Option<u16>,
    /// Response body size in bytes.
    pub response_body_size: usize,
    /// Content type from the response.
    pub response_content_type: Option<String>,
    /// PID that made the request.
    pub pid: u32,
    /// Timestamp in ms since capture start.
    pub timestamp_ms: u64,
    /// Whether this looks like a C2 beacon.
    pub c2_suspect: bool,
}

impl HttpRequest {
    /// Create a new HTTP request event.
    #[must_use]
    pub fn new(
        url: impl Into<String>,
        method: HttpMethod,
        pid: u32,
        timestamp_ms: u64,
    ) -> Self {
        let url = url.into();
        let is_https = url.starts_with("https://");
        Self {
            url,
            method,
            is_https,
            http_version: "1.1".to_string(),
            headers: Vec::new(),
            body_size: 0,
            response_status: None,
            response_body_size: 0,
            response_content_type: None,
            pid,
            timestamp_ms,
            c2_suspect: false,
        }
    }

    /// Builder: add a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    /// Builder: set response status.
    #[must_use]
    pub const fn with_status(mut self, code: u16) -> Self {
        self.response_status = Some(code);
        self
    }

    /// Builder: mark as C2 suspect.
    #[must_use]
    pub const fn mark_c2(mut self) -> Self {
        self.c2_suspect = true;
        self
    }

    /// Returns the host portion of the URL.
    #[must_use]
    pub fn host(&self) -> &str {
        let url = self.url.as_str();
        let after_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        after_scheme
            .split('/')
            .next()
            .unwrap_or(after_scheme)
            .split(':')
            .next()
            .unwrap_or(after_scheme)
    }

    /// Returns the `User-Agent` header value if present.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
    }
}

// ── TCP Flow ──────────────────────────────────────────────────────────────────

/// Direction of a connection from the sandboxed process's perspective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionDirection {
    /// Process initiated the connection (outbound).
    Outbound,
    /// Connection was accepted (inbound).
    Inbound,
}

/// State of a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    Connecting,
    Established,
    Closing,
    Closed,
    Reset,
    TimedOut,
}

/// A single TCP or UDP flow captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlow {
    /// Protocol (Tcp or Udp).
    pub protocol: TransportProtocol,
    /// Local endpoint (IP:port).
    pub local_addr: String,
    /// Remote endpoint (IP:port).
    pub remote_addr: String,
    /// Remote port number.
    pub remote_port: u16,
    /// Direction relative to the sandboxed process.
    pub direction: ConnectionDirection,
    /// Current connection state.
    pub state: TcpState,
    /// Total bytes sent by the sandboxed process.
    pub bytes_sent: u64,
    /// Total bytes received by the sandboxed process.
    pub bytes_received: u64,
    /// PID owning the connection.
    pub pid: u32,
    /// Timestamp when the flow started (ms since capture start).
    pub start_ms: u64,
    /// Timestamp when the flow ended (`None` if still open).
    pub end_ms: Option<u64>,
    /// Whether this connection was classified as suspicious.
    pub suspicious: bool,
    /// Optional higher-layer protocol label (e.g. `"HTTP"`, `"TLS"`).
    pub app_proto: Option<String>,
}

impl TcpFlow {
    /// Create a new TCP flow event.
    #[must_use]
    pub fn new(
        protocol: TransportProtocol,
        local_addr: impl Into<String>,
        remote_addr: impl Into<String>,
        remote_port: u16,
        direction: ConnectionDirection,
        pid: u32,
        start_ms: u64,
    ) -> Self {
        Self {
            protocol,
            local_addr: local_addr.into(),
            remote_addr: remote_addr.into(),
            remote_port,
            direction,
            state: TcpState::Connecting,
            bytes_sent: 0,
            bytes_received: 0,
            pid,
            start_ms,
            end_ms: None,
            suspicious: false,
            app_proto: None,
        }
    }

    /// Builder: mark as established.
    #[must_use]
    pub const fn established(mut self) -> Self {
        self.state = TcpState::Established;
        self
    }

    /// Builder: mark as closed with an end timestamp.
    #[must_use]
    pub const fn closed(mut self, end_ms: u64) -> Self {
        self.state = TcpState::Closed;
        self.end_ms = Some(end_ms);
        self
    }

    /// Builder: set byte counters.
    #[must_use]
    pub const fn with_bytes(mut self, sent: u64, received: u64) -> Self {
        self.bytes_sent = sent;
        self.bytes_received = received;
        self
    }

    /// Builder: label with an application-layer protocol.
    #[must_use]
    pub fn with_app_proto(mut self, proto: impl Into<String>) -> Self {
        self.app_proto = Some(proto.into());
        self
    }

    /// Returns `true` if the remote IP is in a private RFC1918 range.
    #[must_use]
    pub fn is_private(&self) -> bool {
        let ip = self.remote_addr.split(':').next().unwrap_or("");
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.")
            || ip.starts_with("127.")
            || ip == "::1"
    }

    /// Returns `true` if the remote port matches common C2 or high-risk ports.
    #[must_use]
    pub const fn is_high_risk_port(&self) -> bool {
        matches!(
            self.remote_port,
            443 | 80 | 4444 | 8080 | 8443 | 6666 | 1337 | 31337 | 9001 | 9002
        )
    }

    /// Flow duration in milliseconds (`None` if not yet closed).
    #[must_use]
    pub fn duration_ms(&self) -> Option<u64> {
        self.end_ms.map(|e| e.saturating_sub(self.start_ms))
    }
}

// ── NetworkCapture ────────────────────────────────────────────────────────────

/// Summary statistics for a `NetworkCapture`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    pub dns_queries: usize,
    pub dga_suspects: usize,
    pub http_requests: usize,
    pub https_requests: usize,
    pub c2_suspects: usize,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub external_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub unique_remote_hosts: usize,
}

/// Aggregates all network activity captured during sandbox execution.
pub struct NetworkCapture {
    dns_queries: Vec<DnsQuery>,
    http_requests: Vec<HttpRequest>,
    tcp_flows: Vec<TcpFlow>,
}

impl NetworkCapture {
    /// Create an empty capture.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dns_queries: Vec::new(),
            http_requests: Vec::new(),
            tcp_flows: Vec::new(),
        }
    }

    /// Record a DNS query.
    pub fn add_dns(&mut self, query: DnsQuery) {
        self.dns_queries.push(query);
    }

    /// Record an HTTP request.
    pub fn add_http(&mut self, req: HttpRequest) {
        self.http_requests.push(req);
    }

    /// Record a TCP/UDP flow.
    pub fn add_flow(&mut self, flow: TcpFlow) {
        self.tcp_flows.push(flow);
    }

    /// All DNS queries.
    #[must_use]
    pub fn dns_queries(&self) -> &[DnsQuery] {
        &self.dns_queries
    }

    /// All HTTP requests.
    #[must_use]
    pub fn http_requests(&self) -> &[HttpRequest] {
        &self.http_requests
    }

    /// All TCP/UDP flows.
    #[must_use]
    pub fn tcp_flows(&self) -> &[TcpFlow] {
        &self.tcp_flows
    }

    /// Compute network statistics.
    #[must_use]
    pub fn stats(&self) -> NetworkStats {
        let dns_queries = self.dns_queries.len();
        let dga_suspects = self.dns_queries.iter().filter(|q| q.dga_suspect).count();
        let plain_http_count = self
            .http_requests
            .iter()
            .filter(|r| !r.is_https)
            .count();
        let https_requests = self
            .http_requests
            .iter()
            .filter(|r| r.is_https)
            .count();
        let c2_suspects = self.http_requests.iter().filter(|r| r.c2_suspect).count();

        let tcp_flows = self
            .tcp_flows
            .iter()
            .filter(|f| f.protocol == TransportProtocol::Tcp)
            .count();
        let udp_flows = self
            .tcp_flows
            .iter()
            .filter(|f| f.protocol == TransportProtocol::Udp)
            .count();
        let external_connections = self.tcp_flows.iter().filter(|f| !f.is_private()).count();

        let total_bytes_sent = self.tcp_flows.iter().map(|f| f.bytes_sent).sum();
        let total_bytes_received = self.tcp_flows.iter().map(|f| f.bytes_received).sum();

        let mut hosts: Vec<String> = self
            .tcp_flows
            .iter()
            .map(|f| f.remote_addr.split(':').next().unwrap_or("").to_string())
            .collect();
        hosts.extend(
            self.dns_queries
                .iter()
                .flat_map(|q| q.resolved_ips.iter().cloned()),
        );
        hosts.sort_unstable();
        hosts.dedup();
        let unique_remote_hosts = hosts.len();

        NetworkStats {
            dns_queries,
            dga_suspects,
            http_requests: plain_http_count,
            https_requests,
            c2_suspects,
            tcp_flows,
            udp_flows,
            external_connections,
            total_bytes_sent,
            total_bytes_received,
            unique_remote_hosts,
        }
    }

    /// Return all DGA-suspect DNS queries.
    #[must_use]
    pub fn dga_queries(&self) -> Vec<&DnsQuery> {
        self.dns_queries.iter().filter(|q| q.dga_suspect).collect()
    }

    /// Return all C2-suspect HTTP requests.
    #[must_use]
    pub fn c2_requests(&self) -> Vec<&HttpRequest> {
        self.http_requests.iter().filter(|r| r.c2_suspect).collect()
    }

    /// Return flows to external hosts on high-risk ports.
    #[must_use]
    pub fn high_risk_flows(&self) -> Vec<&TcpFlow> {
        self.tcp_flows
            .iter()
            .filter(|f| !f.is_private() && f.is_high_risk_port())
            .collect()
    }

    /// Unique remote hosts contacted (IP or hostname).
    #[must_use]
    pub fn unique_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .tcp_flows
            .iter()
            .map(|f| {
                f.remote_addr
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        hosts.extend(self.dns_queries.iter().map(|q| q.name.clone()));
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }

    /// Group HTTP requests by host.
    #[must_use]
    pub fn requests_by_host(&self) -> HashMap<String, Vec<&HttpRequest>> {
        let mut map: HashMap<String, Vec<&HttpRequest>> = HashMap::new();
        for req in &self.http_requests {
            map.entry(req.host().to_string()).or_default().push(req);
        }
        map
    }

    /// Classify network behaviour based on captured data.
    #[must_use]
    pub fn classify(&self) -> NetworkClassification {
        let stats = self.stats();
        let mut flags = Vec::new();

        if stats.dga_suspects > 5 {
            flags.push("possible-dga");
        }
        if stats.c2_suspects > 0 {
            flags.push("c2-beacon");
        }
        if stats.external_connections > 10 {
            flags.push("high-external-traffic");
        }
        if self.http_requests.iter().any(|r| {
            r.user_agent().is_some_and(|ua| {
                ua.is_empty() || ua.len() < 10
            })
        }) {
            flags.push("suspicious-useragent");
        }
        if stats.https_requests > 0 && stats.dns_queries == 0 {
            flags.push("no-dns-direct-ip");
        }

        NetworkClassification {
            flags: flags.iter().map(std::string::ToString::to_string).collect(),
            risk_score: Self::compute_risk(&stats),
        }
    }

    fn compute_risk(stats: &NetworkStats) -> u8 {
        let mut score = 0u32;
        if stats.c2_suspects > 0 {
            score += 30;
        }
        if stats.dga_suspects > 3 {
            score += 20;
        }
        if stats.external_connections > 5 {
            score += 15;
        }
        if stats.dns_queries > 50 {
            score += 10;
        }
        score.min(100) as u8
    }
}

impl Default for NetworkCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NetworkCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.stats();
        write!(
            f,
            "NetworkCapture {{ dns: {}, http: {}, flows: {} }}",
            s.dns_queries,
            s.http_requests + s.https_requests,
            s.tcp_flows + s.udp_flows
        )
    }
}

/// Classification result for network behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkClassification {
    /// Human-readable behaviour flags (e.g. `"c2-beacon"`, `"possible-dga"`).
    pub flags: Vec<String>,
    /// Overall risk score (0–100).
    pub risk_score: u8,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_answered() {
        let mut q = DnsQuery::new("evil.com", DnsQueryType::A, 100, 0);
        q = q.with_resolved(vec!["185.10.1.2".to_string()]);
        assert!(q.answered);
    }

    #[test]
    fn test_dns_resolves_external() {
        let q = DnsQuery::new("example.com", DnsQueryType::A, 100, 0)
            .with_resolved(vec!["93.184.216.34".to_string()]);
        assert!(q.resolves_to_external());
    }

    #[test]
    fn test_dns_private_not_external() {
        let q = DnsQuery::new("internal.corp", DnsQueryType::A, 100, 0)
            .with_resolved(vec!["192.168.1.1".to_string()]);
        assert!(!q.resolves_to_external());
    }

    #[test]
    fn test_http_host_extraction() {
        let req = HttpRequest::new("https://evil.com/gate.php", HttpMethod::Post, 100, 0);
        assert_eq!(req.host(), "evil.com");
    }

    #[test]
    fn test_http_user_agent() {
        let req = HttpRequest::new("http://x.com/", HttpMethod::Get, 100, 0)
            .with_header("User-Agent", "Mozilla/5.0");
        assert_eq!(req.user_agent(), Some("Mozilla/5.0"));
    }

    #[test]
    fn test_tcp_flow_private() {
        let flow = TcpFlow::new(
            TransportProtocol::Tcp,
            "192.168.1.100:50000",
            "192.168.1.1:445",
            445,
            ConnectionDirection::Outbound,
            100,
            0,
        );
        assert!(flow.is_private());
    }

    #[test]
    fn test_tcp_flow_external_high_risk() {
        let flow = TcpFlow::new(
            TransportProtocol::Tcp,
            "192.168.1.100:49000",
            "185.10.1.2:4444",
            4444,
            ConnectionDirection::Outbound,
            100,
            0,
        );
        assert!(!flow.is_private());
        assert!(flow.is_high_risk_port());
    }

    #[test]
    fn test_network_capture_stats() {
        let mut cap = NetworkCapture::new();
        cap.add_dns(DnsQuery::new("c2.evil.com", DnsQueryType::A, 100, 0));
        cap.add_http(
            HttpRequest::new("https://c2.evil.com/beacon", HttpMethod::Post, 100, 5).mark_c2(),
        );
        cap.add_flow(
            TcpFlow::new(
                TransportProtocol::Tcp,
                "10.0.0.1:1234",
                "185.10.1.2:443",
                443,
                ConnectionDirection::Outbound,
                100,
                0,
            )
            .established(),
        );
        let stats = cap.stats();
        assert_eq!(stats.dns_queries, 1);
        assert_eq!(stats.c2_suspects, 1);
        assert_eq!(stats.https_requests, 1);
        assert_eq!(stats.tcp_flows, 1);
        assert_eq!(stats.external_connections, 1);
    }

    #[test]
    fn test_classification_c2() {
        let mut cap = NetworkCapture::new();
        cap.add_http(
            HttpRequest::new("https://evil.com/gate", HttpMethod::Post, 100, 0).mark_c2(),
        );
        let cls = cap.classify();
        assert!(cls.flags.contains(&"c2-beacon".to_string()));
        assert!(cls.risk_score > 0);
    }

    #[test]
    fn test_requests_by_host() {
        let mut cap = NetworkCapture::new();
        cap.add_http(HttpRequest::new("http://host-a.com/a", HttpMethod::Get, 1, 0));
        cap.add_http(HttpRequest::new("http://host-a.com/b", HttpMethod::Get, 1, 1));
        cap.add_http(HttpRequest::new("http://host-b.com/c", HttpMethod::Get, 1, 2));
        let by_host = cap.requests_by_host();
        assert_eq!(by_host.get("host-a.com").map(Vec::len), Some(2));
        assert_eq!(by_host.get("host-b.com").map(Vec::len), Some(1));
    }

    #[test]
    fn test_unique_hosts() {
        let mut cap = NetworkCapture::new();
        cap.add_flow(TcpFlow::new(
            TransportProtocol::Tcp,
            "10.0.0.1:9000",
            "5.5.5.5:80",
            80,
            ConnectionDirection::Outbound,
            1,
            0,
        ));
        cap.add_flow(TcpFlow::new(
            TransportProtocol::Tcp,
            "10.0.0.1:9001",
            "5.5.5.5:443",
            443,
            ConnectionDirection::Outbound,
            1,
            1,
        ));
        let hosts = cap.unique_hosts();
        assert!(hosts.contains(&"5.5.5.5".to_string()));
        // Both flows to same IP → deduplicated
        assert_eq!(hosts.iter().filter(|h| *h == "5.5.5.5").count(), 1);
    }
}
