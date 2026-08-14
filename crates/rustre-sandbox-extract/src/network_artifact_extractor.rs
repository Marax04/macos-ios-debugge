//! Network artifact extractor: captures C2 traffic, DNS lookups, HTTP sessions,
//! and raw TCP/UDP flows observed during sandbox execution.
//!
//! Use [`classify_ip`] to parse and tag IP literals as IPv4/IPv6 and
//! private/global.  The main entry point is [`NetworkArtifactExtractor`].

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Parse a textual IP address and tag it as IPv4 / IPv6 plus a private/global
/// hint.  Used by the network normalizer to keep RFC1918 / link-local traffic
/// out of the C2-suspect bucket.
#[must_use]
pub fn classify_ip(s: &str) -> Option<IpClass> {
    let parsed: IpAddr = s.parse().ok()?;
    let is_private = match parsed {
        IpAddr::V4(v4) => {
            let v4: Ipv4Addr = v4;
            v4.is_private() || v4.is_loopback() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            let v6: Ipv6Addr = v6;
            v6.is_loopback() || v6.is_unspecified()
        }
    };
    Some(IpClass {
        addr: parsed,
        is_v6: matches!(parsed, IpAddr::V6(_)),
        is_private,
    })
}

/// Classification of a parsed IP literal.
#[derive(Debug, Clone, Copy)]
pub struct IpClass {
    pub addr: IpAddr,
    pub is_v6: bool,
    pub is_private: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkArtifact
// ─────────────────────────────────────────────────────────────────────────────

/// The type of a network observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEventKind {
    DnsQuery { hostname: String, resolved: Vec<String> },
    TcpConnect { dst_ip: String, dst_port: u16 },
    TcpAccept  { src_ip: String, src_port: u16 },
    UdpSend    { dst_ip: String, dst_port: u16, size: usize },
    UdpRecv    { src_ip: String, src_port: u16, size: usize },
    HttpRequest  { method: String, url: String, host: String },
    HttpResponse { status: u16, content_type: String, size: usize },
    TlsHandshake { sni: String, version: String },
    IcmpSend   { dst_ip: String, icmp_type: u8 },
    RawConnect { dst_ip: String, dst_port: u16, proto: u8 },
}

impl fmt::Display for NetworkEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsQuery { hostname, resolved } =>
                write!(f, "DNS {hostname} -> [{}]", resolved.join(", ")),
            Self::TcpConnect { dst_ip, dst_port } =>
                write!(f, "TCP connect {dst_ip}:{dst_port}"),
            Self::TcpAccept { src_ip, src_port } =>
                write!(f, "TCP accept from {src_ip}:{src_port}"),
            Self::UdpSend { dst_ip, dst_port, size } =>
                write!(f, "UDP send {dst_ip}:{dst_port} {size}B"),
            Self::UdpRecv { src_ip, src_port, size } =>
                write!(f, "UDP recv {src_ip}:{src_port} {size}B"),
            Self::HttpRequest { method, url, .. } =>
                write!(f, "HTTP {method} {url}"),
            Self::HttpResponse { status, content_type, size } =>
                write!(f, "HTTP {status} {content_type} {size}B"),
            Self::TlsHandshake { sni, version } =>
                write!(f, "TLS {version} SNI={sni}"),
            Self::IcmpSend { dst_ip, icmp_type } =>
                write!(f, "ICMP type={icmp_type} -> {dst_ip}"),
            Self::RawConnect { dst_ip, dst_port, proto } =>
                write!(f, "RAW proto={proto} {dst_ip}:{dst_port}"),
        }
    }
}

/// A single network event recorded during sandbox execution.
#[derive(Debug, Clone)]
pub struct NetworkArtifact {
    pub kind: NetworkEventKind,
    pub pid: u32,
    pub timestamp: u64,
    /// Raw bytes of the payload (first 4 KB max).
    pub payload: Vec<u8>,
    /// Tags set during analysis.
    pub tags: Vec<String>,
}

impl NetworkArtifact {
    #[must_use]
    pub fn new(kind: NetworkEventKind, pid: u32) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self { kind, pid, timestamp: ts, payload: Vec::new(), tags: Vec::new() }
    }

    #[must_use]
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload.into_iter().take(4096).collect();
        self
    }

    pub fn add_tag(&mut self, t: impl Into<String>) {
        let s = t.into();
        if !self.tags.contains(&s) { self.tags.push(s); }
    }
}

impl fmt::Display for NetworkArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[PID {}] {}", self.pid, self.kind)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C2Pattern detection
// ─────────────────────────────────────────────────────────────────────────────

/// A C2 communication pattern rule.
#[derive(Debug, Clone)]
pub struct C2Pattern {
    pub name: String,
    /// Family or malware this pattern matches.
    pub family: String,
    /// Port numbers associated with this C2 pattern.
    pub ports: Vec<u16>,
    /// Beacon interval hint (seconds).
    pub beacon_interval_hint: Option<u64>,
    /// URI path fragments typical for this C2.
    pub uri_fragments: Vec<String>,
    /// User-agent strings typical for this C2.
    pub user_agents: Vec<String>,
    /// Known C2 IP or hostname fragments.
    pub host_patterns: Vec<String>,
}

impl C2Pattern {
    #[must_use]
    pub fn new(name: impl Into<String>, family: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            family: family.into(),
            ports: Vec::new(),
            beacon_interval_hint: None,
            uri_fragments: Vec::new(),
            user_agents: Vec::new(),
            host_patterns: Vec::new(),
        }
    }

    /// Check if a URL matches any URI fragment.
    #[must_use]
    pub fn matches_url(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        self.uri_fragments.iter().any(|f| lower.contains(f.as_str()))
    }

    /// Check if a user-agent matches.
    #[must_use]
    pub fn matches_ua(&self, ua: &str) -> bool {
        let lower = ua.to_ascii_lowercase();
        self.user_agents.iter().any(|u| lower.contains(u.as_str()))
    }

    /// Check if host matches.
    #[must_use]
    pub fn matches_host(&self, host: &str) -> bool {
        let lower = host.to_ascii_lowercase();
        self.host_patterns.iter().any(|h| lower.contains(h.as_str()))
    }

    /// Returns true if the port is associated with this pattern.
    #[must_use]
    pub fn matches_port(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }
}

impl fmt::Display for C2Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C2Pattern({} / {})", self.name, self.family)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkSession
// ─────────────────────────────────────────────────────────────────────────────

/// A reconstructed TCP/HTTP session (multiple events aggregated).
#[derive(Debug, Clone)]
pub struct NetworkSession {
    pub session_id: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: SessionProto,
    pub start_ts: u64,
    pub end_ts: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub http_requests: Vec<HttpRecord>,
    pub tls_sni: Option<String>,
    pub payload_samples: Vec<Vec<u8>>,
    pub matched_c2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionProto { Tcp, Udp, Tls, Http, Https, Unknown }

impl fmt::Display for SessionProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tls => write!(f, "TLS"),
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpRecord {
    pub method: String,
    pub url: String,
    pub host: String,
    pub user_agent: String,
    pub response_status: Option<u16>,
    pub response_size: usize,
    pub response_content_type: String,
}

impl fmt::Display for NetworkSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Session[{}] {} {}:{} sent={} recv={}",
            self.session_id, self.proto, self.dst_ip, self.dst_port,
            self.bytes_sent, self.bytes_recv)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PayloadExtract
// ─────────────────────────────────────────────────────────────────────────────

/// A binary payload extracted from network traffic.
#[derive(Debug, Clone)]
pub struct PayloadExtract {
    pub session_id: u64,
    pub direction: PayloadDirection,
    pub data: Vec<u8>,
    pub offset: u64,
    /// Detected payload type (e.g. `"PE"`, `"shellcode"`, `"config"`).
    pub payload_type: String,
    /// Confidence score 0–100.
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadDirection { Sent, Received }

impl fmt::Display for PayloadDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Sent => write!(f, "→"), Self::Received => write!(f, "←") }
    }
}

impl PayloadExtract {
    #[must_use]
    pub fn detect_type(data: &[u8]) -> (&'static str, u8) {
        if data.starts_with(b"MZ") { return ("PE", 95); }
        if data.starts_with(b"\x7fELF") { return ("ELF", 95); }
        if data.starts_with(b"PK\x03\x04") { return ("ZIP", 90); }
        if data.starts_with(b"%PDF") { return ("PDF", 90); }
        // Check for shellcode heuristics: starts with NOP sled or common prologues
        if data.len() >= 4 {
            let first = &data[..4];
            if first == [0x90,0x90,0x90,0x90] || first[..2] == [0x55,0x8b] {
                return ("shellcode", 60);
            }
        }
        // JSON/XML config
        if data.starts_with(b"{") || data.starts_with(b"[") { return ("json", 70); }
        if data.starts_with(b"<?xml") { return ("xml", 70); }
        ("binary", 30)
    }

    #[must_use]
    pub fn new(session_id: u64, dir: PayloadDirection, data: Vec<u8>, offset: u64) -> Self {
        let (t, c) = Self::detect_type(&data);
        Self {
            session_id,
            direction: dir,
            data,
            offset,
            payload_type: t.to_string(),
            confidence: c,
        }
    }
}

impl fmt::Display for PayloadExtract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Payload[{}] {} {} {}B (confidence {}%)",
            self.session_id, self.direction, self.payload_type, self.data.len(), self.confidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkReport
// ─────────────────────────────────────────────────────────────────────────────

/// Complete network activity report.
#[derive(Debug, Clone)]
pub struct NetworkReport {
    pub events: Vec<NetworkArtifact>,
    pub sessions: Vec<NetworkSession>,
    pub payloads: Vec<PayloadExtract>,
    pub dns_lookups: Vec<(String, Vec<String>)>,
    pub http_requests: Vec<HttpRecord>,
    pub unique_ips: Vec<String>,
    pub unique_domains: Vec<String>,
    pub c2_matches: Vec<(String, String)>,
    pub indicators: Vec<String>,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
}

impl NetworkReport {
    #[must_use]
    pub const fn is_suspicious(&self) -> bool { !self.c2_matches.is_empty() || !self.indicators.is_empty() }
}

impl fmt::Display for NetworkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "NetworkReport: {} events, {} sessions, {} payloads",
            self.events.len(), self.sessions.len(), self.payloads.len())?;
        writeln!(f, "  DNS: {} unique domains, IPs: {}",
            self.unique_domains.len(), self.unique_ips.len())?;
        writeln!(f, "  Sent: {} B, Recv: {} B", self.total_bytes_sent, self.total_bytes_recv)?;
        for (p, family) in &self.c2_matches {
            writeln!(f, "  [C2] {p} matched pattern {family}")?;
        }
        for ind in &self.indicators {
            writeln!(f, "  [!] {ind}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkArtifactExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Collects network events and produces structured sessions and payloads.
#[derive(Debug, Default)]
pub struct NetworkArtifactExtractor {
    events: Vec<NetworkArtifact>,
    c2_patterns: Vec<C2Pattern>,
    session_counter: u64,
}

impl NetworkArtifactExtractor {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add a C2 detection pattern.
    pub fn add_c2_pattern(&mut self, p: C2Pattern) {
        self.c2_patterns.push(p);
    }

    /// Add commonly seen malware C2 patterns.
    pub fn add_default_patterns(&mut self) {
        let mut cobalt = C2Pattern::new("CobaltStrike", "cobalt_strike");
        cobalt.ports = vec![80, 443, 8080, 8443, 4444];
        cobalt.uri_fragments = vec!["/s/", "/submit.php", "/ptj", "/____cB", "/__utm.gif", "/pixel.gif", "/ca", "/updates/"].into_iter().map(String::from).collect();
        cobalt.user_agents = vec!["mozilla/5.0 (compatible; msie 9.0"].into_iter().map(String::from).collect();
        self.c2_patterns.push(cobalt);

        let mut metasploit = C2Pattern::new("Metasploit", "metasploit");
        metasploit.ports = vec![4444, 4445, 8080, 8443];
        metasploit.uri_fragments = vec!["/multi/handler", "/payload/", "/_ns_blv"].into_iter().map(String::from).collect();
        self.c2_patterns.push(metasploit);

        let mut emotet = C2Pattern::new("Emotet", "emotet");
        emotet.ports = vec![80, 443, 7080, 8080, 8090];
        emotet.uri_fragments = vec!["/wp-content/", "/wp-admin/", "/images/", "/static/"].into_iter().map(String::from).collect();
        self.c2_patterns.push(emotet);

        let mut qbot = C2Pattern::new("Qbot", "qakbot");
        qbot.ports = vec![443, 2222, 443, 995, 993];
        qbot.uri_fragments = vec!["/t4/", "/f.php", "/i.php"].into_iter().map(String::from).collect();
        self.c2_patterns.push(qbot);
    }

    /// Record a network event.
    pub fn record(&mut self, event: NetworkArtifact) {
        self.events.push(event);
    }

    pub fn record_dns(&mut self, hostname: String, resolved: Vec<String>, pid: u32) {
        self.record(NetworkArtifact::new(NetworkEventKind::DnsQuery { hostname, resolved }, pid));
    }

    pub fn record_tcp_connect(&mut self, dst_ip: String, dst_port: u16, pid: u32) {
        self.record(NetworkArtifact::new(NetworkEventKind::TcpConnect { dst_ip, dst_port }, pid));
    }

    pub fn record_http(&mut self, method: String, url: String, host: String, pid: u32) {
        self.record(NetworkArtifact::new(NetworkEventKind::HttpRequest { method, url, host }, pid));
    }

    const fn next_session_id(&mut self) -> u64 {
        self.session_counter += 1;
        self.session_counter
    }

    fn check_c2(&self, event: &NetworkArtifact) -> Option<String> {
        for pat in &self.c2_patterns {
            let matched = match &event.kind {
                NetworkEventKind::TcpConnect { dst_port, dst_ip } =>
                    pat.matches_port(*dst_port) || pat.matches_host(dst_ip),
                NetworkEventKind::HttpRequest { url, host, .. } =>
                    pat.matches_url(url) || pat.matches_host(host),
                NetworkEventKind::DnsQuery { hostname, .. } =>
                    pat.matches_host(hostname),
                _ => false,
            };
            if matched { return Some(pat.name.clone()); }
        }
        None
    }

    /// Build the final network report.
    pub fn build_report(&mut self) -> NetworkReport {
        let mut sessions: Vec<NetworkSession> = Vec::new();
        let mut payloads: Vec<PayloadExtract> = Vec::new();
        let mut dns_lookups: Vec<(String, Vec<String>)> = Vec::new();
        let mut http_requests: Vec<HttpRecord> = Vec::new();
        let mut unique_ips_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut unique_domains_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut c2_matches: Vec<(String, String)> = Vec::new();
        let mut indicators: Vec<String> = Vec::new();
        let mut total_sent = 0u64;
        let mut total_recv = 0u64;

        // Group TCP connects into sessions; collect DNS and HTTP inline
        let mut open_sessions: HashMap<String, u64> = HashMap::new();

        let events = self.events.clone();
        for event in &events {
            // C2 check
            if let Some(c2) = self.check_c2(event) {
                let key = format!("{}", event.kind);
                if !c2_matches.iter().any(|(k, _)| k == &key) {
                    c2_matches.push((key, c2));
                }
            }

            match &event.kind {
                NetworkEventKind::DnsQuery { hostname, resolved } => {
                    unique_domains_set.insert(hostname.clone());
                    for ip in resolved { unique_ips_set.insert(ip.clone()); }
                    dns_lookups.push((hostname.clone(), resolved.clone()));
                }
                NetworkEventKind::TcpConnect { dst_ip, dst_port } => {
                    unique_ips_set.insert(dst_ip.clone());
                    let session_key = format!("{dst_ip}:{dst_port}");
                    open_sessions.entry(session_key).or_insert_with(|| {
                        let sid = self.next_session_id();
                        sessions.push(NetworkSession {
                            session_id: sid,
                            src_ip: String::new(),
                            dst_ip: dst_ip.clone(),
                            dst_port: *dst_port,
                            proto: SessionProto::Tcp,
                            start_ts: event.timestamp,
                            end_ts: event.timestamp,
                            bytes_sent: 0,
                            bytes_recv: 0,
                            http_requests: Vec::new(),
                            tls_sni: None,
                            payload_samples: Vec::new(),
                            matched_c2: None,
                        });
                        sid
                    });
                }
                NetworkEventKind::UdpSend { dst_ip, size, .. } => {
                    unique_ips_set.insert(dst_ip.clone());
                    total_sent += u64::try_from(*size).unwrap_or(u64::MAX);
                }
                NetworkEventKind::UdpRecv { src_ip, size, .. } => {
                    unique_ips_set.insert(src_ip.clone());
                    total_recv += u64::try_from(*size).unwrap_or(u64::MAX);
                }
                NetworkEventKind::HttpRequest { method, url, host } => {
                    unique_domains_set.insert(host.clone());
                    http_requests.push(HttpRecord {
                        method: method.clone(),
                        url: url.clone(),
                        host: host.clone(),
                        user_agent: String::new(),
                        response_status: None,
                        response_size: 0,
                        response_content_type: String::new(),
                    });
                }
                NetworkEventKind::TlsHandshake { sni, .. } => {
                    unique_domains_set.insert(sni.clone());
                }
                _ => {}
            }

            if !event.payload.is_empty() {
                let pe = PayloadExtract::new(0, PayloadDirection::Received, event.payload.clone(), 0);
                if pe.confidence >= 60 { payloads.push(pe); }
            }
        }

        // Populate indicators
        if !c2_matches.is_empty() {
            let n = c2_matches.len();
            indicators.push(format!("{n} potential C2 pattern match(es)"));
        }
        if !payloads.is_empty() {
            let pe_count = payloads.iter().filter(|p| p.payload_type == "PE").count();
            if pe_count > 0 {
                indicators.push(format!("{pe_count} PE payload(s) transferred"));
            }
        }
        let plain_http = http_requests.iter()
            .filter(|r| !r.url.starts_with("https"))
            .count();
        if plain_http > 0 {
            indicators.push(format!("{plain_http} unencrypted HTTP request(s)"));
        }

        let mut unique_ips: Vec<String> = unique_ips_set.into_iter().collect();
        unique_ips.sort();
        let mut unique_domains: Vec<String> = unique_domains_set.into_iter().collect();
        unique_domains.sort();

        NetworkReport {
            events: self.events.clone(),
            sessions,
            payloads,
            dns_lookups,
            http_requests,
            unique_ips,
            unique_domains,
            c2_matches,
            indicators,
            total_bytes_sent: total_sent,
            total_bytes_recv: total_recv,
        }
    }
}
