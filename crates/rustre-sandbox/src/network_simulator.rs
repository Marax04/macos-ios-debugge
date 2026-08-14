// network_simulator.rs — Sandbox network simulator for RustRE

use std::collections::HashMap;

// ─── Protocol ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
    Http,
    Https,
}

impl Protocol {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    #[must_use] 
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::Tcp | Self::Udp => 0,
            Self::Dns => 53,
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

// ─── SimResponse ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimResponse {
    pub response: Vec<u8>,
    pub delay_ms: u64,
}

impl SimResponse {
    #[must_use] 
    pub const fn new(response: Vec<u8>, delay_ms: u64) -> Self {
        Self { response, delay_ms }
    }

    #[must_use] 
    pub fn text(s: &str, delay_ms: u64) -> Self {
        Self::new(s.as_bytes().to_vec(), delay_ms)
    }
}

// ─── SimulatedHost ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SimulatedHost {
    pub ip: String,
    pub port: u16,
    pub protocol: Protocol,
    pub responses: Vec<SimResponse>,
    response_index: usize,
}

impl SimulatedHost {
    #[must_use] 
    pub fn new(ip: &str, port: u16, protocol: Protocol) -> Self {
        Self {
            ip: ip.to_string(),
            port,
            protocol,
            responses: Vec::new(),
            response_index: 0,
        }
    }

    pub fn add_response(&mut self, resp: SimResponse) {
        self.responses.push(resp);
    }

    /// Return next canned response (cycling).
    pub fn next_response(&mut self) -> Option<&SimResponse> {
        if self.responses.is_empty() { return None; }
        let resp = &self.responses[self.response_index];
        self.response_index = (self.response_index + 1) % self.responses.len();
        Some(resp)
    }

    #[must_use] 
    pub fn key(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

// ─── DnsQuery / DnsResponse ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub query_name: String,
    pub query_type: u16, // 1 = A, 28 = AAAA, 15 = MX, 16 = TXT
}

impl DnsQuery {
    #[must_use] 
    pub fn a_record(name: &str) -> Self {
        Self { query_name: name.to_string(), query_type: 1 }
    }

    #[must_use] 
    pub fn aaaa_record(name: &str) -> Self {
        Self { query_name: name.to_string(), query_type: 28 }
    }
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub name: String,
    pub addresses: Vec<String>,
    pub ttl: u32,
}

impl DnsResponse {
    #[must_use] 
    pub fn new(name: &str, addresses: Vec<String>, ttl: u32) -> Self {
        Self { name: name.to_string(), addresses, ttl }
    }

    #[must_use] 
    pub fn nxdomain(name: &str) -> Self {
        Self::new(name, vec![], 0)
    }

    #[must_use] 
    pub const fn is_nxdomain(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Serialize to a simple DNS wire-like response for testing.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Transaction ID
        out.extend_from_slice(&[0x00, 0x01]);
        // Flags: response
        out.extend_from_slice(&[0x81, 0x80]);
        // Questions: 1
        out.extend_from_slice(&[0x00, 0x01]);
        // Answers
        let answers = u16::try_from(self.addresses.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&answers.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Simplified: append IPs as dotted-decimal strings
        for addr in &self.addresses {
            let parts: Vec<u8> = addr.split('.').filter_map(|p| p.parse().ok()).collect();
            if parts.len() == 4 {
                out.extend_from_slice(&[0xC0, 0x0C]); // name pointer
                out.extend_from_slice(&[0x00, 0x01]); // type A
                out.extend_from_slice(&[0x00, 0x01]); // class IN
                out.extend_from_slice(&self.ttl.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x04]); // rdlength
                out.extend_from_slice(&parts);
            }
        }
        out
    }
}

// ─── SimulatedDns ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SimulatedDns {
    pub records: HashMap<String, Vec<String>>,
    /// Default IP returned for unknown domains (sinkhole).
    pub sinkhole_ip: Option<String>,
    pub query_log: Vec<DnsQuery>,
}

impl SimulatedDns {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn add_record(&mut self, name: &str, addresses: &[&str]) {
        self.records.insert(
            name.to_ascii_lowercase(),
            addresses.iter().map(std::string::ToString::to_string).collect(),
        );
    }

    pub fn set_sinkhole(&mut self, ip: &str) {
        self.sinkhole_ip = Some(ip.to_string());
    }

    pub fn intercept_dns(&mut self, query: &DnsQuery) -> DnsResponse {
        self.query_log.push(query.clone());
        let key = query.query_name.to_ascii_lowercase();
        if let Some(addrs) = self.records.get(&key) {
            DnsResponse::new(&query.query_name, addrs.clone(), 300)
        } else if let Some(ref sink) = self.sinkhole_ip.clone() {
            DnsResponse::new(&query.query_name, vec![sink.clone()], 60)
        } else {
            DnsResponse::nxdomain(&query.query_name)
        }
    }

    #[must_use] 
    pub const fn query_count(&self) -> usize {
        self.query_log.len()
    }

    #[must_use] 
    pub fn unique_queried_domains(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.query_log.iter().filter_map(|q| {
            let key = q.query_name.to_ascii_lowercase();
            if seen.insert(key.clone()) { Some(key) } else { None }
        }).collect()
    }
}

// ─── HttpRoute ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpRoute {
    pub method: String,
    pub path_pattern: String,
    pub response_code: u16,
    pub response_body: Vec<u8>,
    pub response_headers: Vec<(String, String)>,
}

impl HttpRoute {
    #[must_use] 
    pub fn new(method: &str, path_pattern: &str, code: u16, body: &[u8]) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            path_pattern: path_pattern.to_string(),
            response_code: code,
            response_body: body.to_vec(),
            response_headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Server".to_string(), "RustRE-SimServer/1.0".to_string()),
            ],
        }
    }

    #[must_use] 
    pub fn matches(&self, method: &str, path: &str) -> bool {
        self.method == method.to_ascii_uppercase()
            && (self.path_pattern == path || self.path_pattern == "*")
    }

    #[must_use] 
    pub fn build_response(&self) -> Vec<u8> {
        let status_text = status_text(self.response_code);
        let mut headers_str = String::new();
        for (k, v) in &self.response_headers {
            use std::fmt::Write as _;
            let _ = write!(headers_str, "{k}: {v}\r\n");
        }
        let mut resp = format!(
            "HTTP/1.1 {} {}\r\n{}\r\n",
            self.response_code, status_text, headers_str
        ).into_bytes();
        resp.extend_from_slice(&self.response_body);
        resp
    }
}

const fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

// ─── SimulatedHttp ────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SimulatedHttp {
    pub vhosts: HashMap<String, Vec<HttpRoute>>,
    pub request_log: Vec<(String, String, String)>, // (host, method, path)
}

impl SimulatedHttp {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn add_route(&mut self, vhost: &str, route: HttpRoute) {
        self.vhosts.entry(vhost.to_string()).or_default().push(route);
    }

    pub fn intercept_http(&mut self, host: &str, method: &str, path: &str) -> (u16, Vec<u8>) {
        self.request_log.push((host.to_string(), method.to_string(), path.to_string()));
        let routes = self.vhosts.get(host).or_else(|| self.vhosts.get("*"));
        if let Some(routes) = routes {
            for route in routes {
                if route.matches(method, path) {
                    return (route.response_code, route.build_response());
                }
            }
        }
        // Default 200 sinkhole response
        let body = b"<html><body>Sinkhole</body></html>";
        let route = HttpRoute::new(method, path, 200, body);
        (200, route.build_response())
    }

    #[must_use] 
    pub const fn request_count(&self) -> usize {
        self.request_log.len()
    }
}

// ─── CapturedPacket ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub data: Vec<u8>,
    pub timestamp_ns: u64,
}

impl CapturedPacket {
    #[must_use] 
    pub fn new(src: &str, dst: &str, src_port: u16, dst_port: u16, protocol: Protocol, data: Vec<u8>, ts: u64) -> Self {
        Self {
            src: src.to_string(),
            dst: dst.to_string(),
            src_port,
            dst_port,
            protocol,
            data,
            timestamp_ns: ts,
        }
    }

    #[must_use] 
    pub const fn size(&self) -> usize { self.data.len() }

    #[must_use] 
    pub fn flow_key(&self) -> String {
        format!("{}:{} -> {}:{}", self.src, self.src_port, self.dst, self.dst_port)
    }
}

// ─── NetworkCapture ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct NetworkCapture {
    pub packets: Vec<CapturedPacket>,
    clock_ns: u64,
}

impl NetworkCapture {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn capture(&mut self, src: &str, dst: &str, src_port: u16, dst_port: u16, protocol: Protocol, data: Vec<u8>) {
        self.clock_ns += 500_000; // 0.5ms per packet
        let pkt = CapturedPacket::new(src, dst, src_port, dst_port, protocol, data, self.clock_ns);
        self.packets.push(pkt);
    }

    #[must_use] 
    pub fn total_bytes(&self) -> usize {
        self.packets.iter().map(CapturedPacket::size).sum()
    }

    #[must_use] 
    pub fn packets_by_protocol(&self, proto: &Protocol) -> Vec<&CapturedPacket> {
        self.packets.iter().filter(|p| &p.protocol == proto).collect()
    }

    #[must_use] 
    pub fn unique_destinations(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.packets.iter().filter_map(|p| {
            if seen.insert(p.dst.clone()) { Some(p.dst.clone()) } else { None }
        }).collect()
    }

    #[must_use] 
    pub fn flows(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.packets.iter().filter_map(|p| {
            let k = p.flow_key();
            if seen.insert(k.clone()) { Some(k) } else { None }
        }).collect()
    }
}

// ─── NetworkSimulator ────────────────────────────────────────────────────────

pub struct NetworkSimulator {
    pub hosts: HashMap<String, SimulatedHost>,
    pub dns: SimulatedDns,
    pub http: SimulatedHttp,
    pub capture: NetworkCapture,
    pub blocked_ips: Vec<String>,
}

impl NetworkSimulator {
    #[must_use] 
    pub fn new() -> Self {
        let mut sim = Self {
            hosts: HashMap::new(),
            dns: SimulatedDns::new(),
            http: SimulatedHttp::new(),
            capture: NetworkCapture::new(),
            blocked_ips: Vec::new(),
        };
        // Default: sinkhole all DNS to 10.0.0.1
        sim.dns.set_sinkhole("10.0.0.1");
        // Default HTTP route
        sim.http.add_route("*", HttpRoute::new("GET", "*", 200, b"<html>OK</html>"));
        sim.http.add_route("*", HttpRoute::new("POST", "*", 200, b"OK"));
        sim
    }

    pub fn add_host(&mut self, host: SimulatedHost) {
        self.hosts.insert(host.key(), host);
    }

    pub fn block_ip(&mut self, ip: &str) {
        self.blocked_ips.push(ip.to_string());
    }

    #[must_use] 
    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.iter().any(|b| b == ip)
    }

    /// Simulate a TCP connect to (ip, port).
    pub fn connect(&mut self, src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> bool {
        if self.is_blocked(dst_ip) {
            return false;
        }
        self.capture.capture(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp, vec![]);
        true
    }

    /// Simulate a DNS query.
    pub fn resolve(&mut self, query: &DnsQuery) -> DnsResponse {
        let resp = self.dns.intercept_dns(query);
        // Capture DNS packet
        self.capture.capture("10.0.0.2", "10.0.0.53", 54321, 53, Protocol::Dns,
            query.query_name.as_bytes().to_vec());
        resp
    }

    /// Simulate an HTTP request.
    pub fn http_request(&mut self, src_ip: &str, host: &str, method: &str, path: &str) -> (u16, Vec<u8>) {
        let (code, body) = self.http.intercept_http(host, method, path);
        self.capture.capture(src_ip, "10.0.0.1", 12345, 80, Protocol::Http,
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes());
        (code, body)
    }

    #[must_use] 
    pub const fn packet_count(&self) -> usize {
        self.capture.packets.len()
    }

    #[must_use] 
    pub const fn dns_query_count(&self) -> usize {
        self.dns.query_count()
    }

    #[must_use] 
    pub const fn http_request_count(&self) -> usize {
        self.http.request_count()
    }
}

impl Default for NetworkSimulator {
    fn default() -> Self { Self::new() }
}

/// Sub-sequence membership test for byte slices.
///
/// Returns `true` when `needle` appears as a contiguous sub-sequence.
/// Public so external packet-inspection helpers can reuse the same
/// primitive the simulator uses internally.
pub trait ByteSliceContains {
    /// `true` if `needle` is contained as a contiguous slice of `self`.
    fn contains_slice(&self, needle: &[u8]) -> bool;
}

impl ByteSliceContains for Vec<u8> {
    fn contains_slice(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > self.len() {
            return false;
        }
        self.windows(needle.len()).any(|w| w == needle)
    }
}

impl ByteSliceContains for [u8] {
    fn contains_slice(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > self.len() {
            return false;
        }
        self.windows(needle.len()).any(|w| w == needle)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sim() -> NetworkSimulator { NetworkSimulator::new() }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Http.as_str(), "http");
        assert_eq!(Protocol::Dns.as_str(), "dns");
    }

    #[test]
    fn test_protocol_default_port() {
        assert_eq!(Protocol::Http.default_port(), 80);
        assert_eq!(Protocol::Dns.default_port(), 53);
    }

    #[test]
    fn test_dns_resolve_known() {
        let mut dns = SimulatedDns::new();
        dns.add_record("example.com", &["93.184.216.34"]);
        let resp = dns.intercept_dns(&DnsQuery::a_record("example.com"));
        assert_eq!(resp.addresses, vec!["93.184.216.34"]);
        assert!(!resp.is_nxdomain());
    }

    #[test]
    fn test_dns_resolve_unknown_sinkhole() {
        let mut dns = SimulatedDns::new();
        dns.set_sinkhole("10.0.0.1");
        let resp = dns.intercept_dns(&DnsQuery::a_record("evil.example"));
        assert_eq!(resp.addresses, vec!["10.0.0.1"]);
    }

    #[test]
    fn test_dns_resolve_nxdomain() {
        let mut dns = SimulatedDns::new();
        let resp = dns.intercept_dns(&DnsQuery::a_record("nxdomain.test"));
        assert!(resp.is_nxdomain());
    }

    #[test]
    fn test_dns_query_log() {
        let mut dns = SimulatedDns::new();
        dns.intercept_dns(&DnsQuery::a_record("a.com"));
        dns.intercept_dns(&DnsQuery::a_record("b.com"));
        assert_eq!(dns.query_count(), 2);
    }

    #[test]
    fn test_dns_unique_domains() {
        let mut dns = SimulatedDns::new();
        dns.intercept_dns(&DnsQuery::a_record("a.com"));
        dns.intercept_dns(&DnsQuery::a_record("a.com"));
        dns.intercept_dns(&DnsQuery::a_record("b.com"));
        assert_eq!(dns.unique_queried_domains().len(), 2);
    }

    #[test]
    fn test_http_route_matches() {
        let route = HttpRoute::new("GET", "/index.html", 200, b"OK");
        assert!(route.matches("GET", "/index.html"));
        assert!(!route.matches("POST", "/index.html"));
    }

    #[test]
    fn test_http_intercept_known_route() {
        let mut http = SimulatedHttp::new();
        http.add_route("mysite.com", HttpRoute::new("GET", "/robots.txt", 200, b"User-agent: *\nDisallow:"));
        let (code, body) = http.intercept_http("mysite.com", "GET", "/robots.txt");
        assert_eq!(code, 200);
        assert!(body.contains_slice(b"User-agent"));
    }

    #[test]
    fn test_http_intercept_default_sinkhole() {
        let mut http = SimulatedHttp::new();
        http.add_route("*", HttpRoute::new("GET", "*", 200, b"sinkhole"));
        let (code, _body) = http.intercept_http("unknown.com", "GET", "/");
        assert_eq!(code, 200);
    }

    #[test]
    fn test_network_capture_packet_count() {
        let mut cap = NetworkCapture::new();
        cap.capture("1.1.1.1", "2.2.2.2", 1234, 80, Protocol::Tcp, vec![]);
        cap.capture("1.1.1.1", "3.3.3.3", 1235, 80, Protocol::Http, vec![]);
        assert_eq!(cap.packets.len(), 2);
    }

    #[test]
    fn test_network_capture_unique_destinations() {
        let mut cap = NetworkCapture::new();
        cap.capture("1.1.1.1", "2.2.2.2", 1234, 80, Protocol::Tcp, vec![]);
        cap.capture("1.1.1.1", "2.2.2.2", 1235, 80, Protocol::Tcp, vec![]);
        cap.capture("1.1.1.1", "3.3.3.3", 1236, 80, Protocol::Tcp, vec![]);
        assert_eq!(cap.unique_destinations().len(), 2);
    }

    #[test]
    fn test_simulator_connect_blocked() {
        let mut sim = make_sim();
        sim.block_ip("8.8.8.8");
        let ok = sim.connect("10.0.0.2", "8.8.8.8", 12345, 53);
        assert!(!ok);
    }

    #[test]
    fn test_simulator_connect_allowed() {
        let mut sim = make_sim();
        let ok = sim.connect("10.0.0.2", "1.1.1.1", 12345, 80);
        assert!(ok);
        assert_eq!(sim.packet_count(), 1);
    }

    #[test]
    fn test_simulator_resolve_captures_packet() {
        let mut sim = make_sim();
        sim.resolve(&DnsQuery::a_record("test.com"));
        assert_eq!(sim.dns_query_count(), 1);
        assert!(sim.packet_count() > 0);
    }

    #[test]
    fn test_simulator_http_request() {
        let mut sim = make_sim();
        let (code, _) = sim.http_request("10.0.0.2", "example.com", "GET", "/");
        assert_eq!(code, 200);
        assert_eq!(sim.http_request_count(), 1);
    }

    #[test]
    fn test_dns_response_to_bytes_nonempty() {
        let r = DnsResponse::new("test.com", vec!["1.2.3.4".to_string()], 300);
        let bytes = r.to_bytes();
        assert!(!bytes.is_empty());
    }
}
