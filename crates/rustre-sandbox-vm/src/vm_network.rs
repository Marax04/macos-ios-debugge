use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use anyhow::{Result, bail};
use tokio::sync::mpsc;

// ── Fake network stack for sandbox ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPacket {
    pub id: u64,
    pub direction: PacketDirection,
    pub protocol: Protocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
    pub timestamp_ns: u64,
    pub flags: PacketFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PacketDirection { Inbound, Outbound }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol { Tcp, Udp, Icmp, Http, Https, Dns, Ftp, Smtp, Unknown }

/// TCP-style packet flags encoded as a bitmask.
///
/// | Bit | Flag |
/// |-----|------|
/// | 0   | SYN  |
/// | 1   | ACK  |
/// | 2   | FIN  |
/// | 3   | RST  |
/// | 4   | PSH  |
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PacketFlags {
    /// Raw bitmask of TCP flags (SYN=bit0, ACK=bit1, FIN=bit2, RST=bit3, PSH=bit4).
    pub bits: u8,
}

impl PacketFlags {
    #[must_use] pub const fn syn(&self) -> bool { self.bits & 0x01 != 0 }
    #[must_use] pub const fn ack(&self) -> bool { self.bits & 0x02 != 0 }
    #[must_use] pub const fn fin(&self) -> bool { self.bits & 0x04 != 0 }
    #[must_use] pub const fn rst(&self) -> bool { self.bits & 0x08 != 0 }
    #[must_use] pub const fn psh(&self) -> bool { self.bits & 0x10 != 0 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub flow_id: u64,
    pub protocol: Protocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub packets_out: u64,
    pub packets_in: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub state: FlowState,
    pub application_layer: Option<ApplicationLayerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowState {
    Syn, SynAck, Established, FinWait, TimeWait, Closed, Reset, Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApplicationLayerInfo {
    Http(HttpInfo),
    Dns(DnsInfo),
    Smtp(SmtpInfo),
    Ftp(FtpInfo),
    Tls(TlsInfo),
    Unknown { banner: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub method: String,
    pub host: String,
    pub path: String,
    pub version: String,
    pub request_headers: Vec<(String, String)>,
    pub response_code: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub user_agent: Option<String>,
    pub cookies: Vec<String>,
    pub body_preview: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub query_type: DnsQueryType,
    pub domain: String,
    pub answers: Vec<DnsAnswer>,
    pub recursive: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DnsQueryType { A, Aaaa, Cname, Mx, Txt, Ns, Ptr, Soa, Srv, Any, Unknown(u16) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: DnsQueryType,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpInfo {
    pub from: Option<String>,
    pub to: Vec<String>,
    pub subject: Option<String>,
    pub has_attachments: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpInfo {
    pub commands: Vec<String>,
    pub data_port: Option<u16>,
    pub username: Option<String>,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub sni: Option<String>,
    pub cipher_suite: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub certificate_cn: Option<String>,
    pub certificate_san: Vec<String>,
}

// ── Fake DNS resolver ─────────────────────────────────────────────────────────

pub struct FakeDnsResolver {
    records: HashMap<String, Vec<IpAddr>>,
    fallback_ip: Ipv4Addr,
    query_log: Arc<Mutex<Vec<DnsQuery>>>,
    sinkhole_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub domain: String,
    pub qtype: String,
    pub resolved_to: Vec<String>,
    pub sinkholed: bool,
    pub timestamp_ns: u64,
}

impl FakeDnsResolver {
    #[must_use]
    pub fn new(fallback_ip: Ipv4Addr) -> Self {
        let mut records = HashMap::new();
        // Pre-seed some common domains
        records.insert("example.com".to_string(), vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        records.insert("google.com".to_string(), vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
        records.insert("microsoft.com".to_string(), vec![IpAddr::V4(Ipv4Addr::new(20, 112, 52, 29))]);
        Self {
            records,
            fallback_ip,
            query_log: Arc::new(Mutex::new(Vec::new())),
            sinkhole_domains: Vec::new(),
        }
    }

    pub fn add_record(&mut self, domain: impl Into<String>, ips: Vec<IpAddr>) {
        self.records.insert(domain.into(), ips);
    }

    pub fn sinkhole(&mut self, domain: impl Into<String>) {
        self.sinkhole_domains.push(domain.into());
    }

    pub fn resolve(&self, domain: &str) -> Vec<IpAddr> {
        let is_sinkhole = self.sinkhole_domains.iter()
            .any(|s| domain.ends_with(s.as_str()) || domain == s.as_str());

        let resolved = if is_sinkhole {
            vec![IpAddr::V4(self.fallback_ip)]
        } else if let Some(ips) = self.records.get(domain) {
            ips.clone()
        } else {
            // Return fake IP derived from domain hash for determinism
            let hash = simple_hash(domain.as_bytes());
            let a = ((hash >> 24) & 0x7F) as u8 + 1;
            let b = ((hash >> 16) & 0xFF) as u8;
            let c = ((hash >> 8) & 0xFF) as u8;
            let d = (hash & 0xFF) as u8;
            vec![IpAddr::V4(Ipv4Addr::new(a, b, c, d))]
        };

        let ts = nanos_to_u64();

        if let Ok(mut log) = self.query_log.lock() {
            log.push(DnsQuery {
                domain: domain.to_string(),
                qtype: "A".to_string(),
                resolved_to: resolved.iter().map(ToString::to_string).collect(),
                sinkholed: is_sinkhole,
                timestamp_ns: ts,
            });
        }
        resolved
    }

    #[must_use]
    pub fn get_query_log(&self) -> Vec<DnsQuery> {
        match self.query_log.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    #[must_use]
    pub fn get_all_queried_domains(&self) -> Vec<String> {
        let guard = match self.query_log.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.iter()
            .map(|q| q.domain.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
}

// ── Fake HTTP server (honeypot) ───────────────────────────────────────────────

pub struct FakeHttpServer {
    responses: HashMap<String, HttpResponse>,
    default_response: HttpResponse,
    request_log: Arc<Mutex<Vec<RecordedRequest>>>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Server".to_string(), "Apache/2.4.41".to_string()),
            ],
            body: body.into(),
        }
    }
    #[must_use]
    pub fn not_found() -> Self {
        Self {
            status: 404,
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            body: b"<html><body>Not Found</body></html>".to_vec(),
        }
    }
    #[must_use]
    pub fn c2_beacon_response() -> Self {
        // Fake C2 beacon response to capture what the malware sends
        Self {
            status: 200,
            headers: vec![
                ("Content-Type".to_string(), "application/octet-stream".to_string()),
                ("X-Control".to_string(), "sleep:60".to_string()),
            ],
            body: b"\x00\x00\x00\x00".to_vec(), // "no command" response
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub src_addr: SocketAddr,
    pub timestamp_ns: u64,
    pub user_agent: Option<String>,
    pub cookie: Option<String>,
    pub content_type: Option<String>,
    pub suspicious_patterns: Vec<String>,
}

impl FakeHttpServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            default_response: HttpResponse::c2_beacon_response(),
            request_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_route(&mut self, path: impl Into<String>, response: HttpResponse) {
        self.responses.insert(path.into(), response);
    }

    #[must_use]
    pub fn handle_request(&self, req: &RecordedRequest) -> &HttpResponse {
        self.responses.get(&req.path).unwrap_or(&self.default_response)
    }

    pub fn record_request(&self, req: RecordedRequest) {
        if let Ok(mut log) = self.request_log.lock() {
            log.push(req);
        }
    }

    #[must_use]
    pub fn get_request_log(&self) -> Vec<RecordedRequest> {
        match self.request_log.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    #[must_use]
    pub fn parse_raw_http(&self, data: &[u8], src: SocketAddr) -> Option<RecordedRequest> {
        let text = std::str::from_utf8(data).ok()?;
        let mut lines = text.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();

        let mut headers = Vec::new();
        let mut host = String::new();
        let mut user_agent = None;
        let mut cookie = None;
        let mut content_type = None;
        let mut content_length = 0usize;

        for line in lines.by_ref() {
            if line.is_empty() { break; }
            if let Some((key, val)) = line.split_once(':') {
                let k = key.trim().to_string();
                let v = val.trim().to_string();
                if k.to_lowercase() == "host" { host.clone_from(&v); }
                if k.to_lowercase() == "user-agent" { user_agent = Some(v.clone()); }
                if k.to_lowercase() == "cookie" { cookie = Some(v.clone()); }
                if k.to_lowercase() == "content-type" { content_type = Some(v.clone()); }
                if k.to_lowercase() == "content-length" {
                    content_length = v.parse().unwrap_or(0);
                }
                headers.push((k, v));
            }
        }

        let body: Vec<u8> = if content_length > 0 && content_length <= data.len() {
            data[data.len() - content_length..].to_vec()
        } else { Vec::new() };

        let suspicious = detect_suspicious_http_patterns(&method, &path, &headers, &body);

        Some(RecordedRequest {
            method,
            path,
            host,
            headers,
            body,
            src_addr: src,
            timestamp_ns: nanos_to_u64(),
            user_agent,
            cookie,
            content_type,
            suspicious_patterns: suspicious,
        })
    }
}

impl Default for FakeHttpServer {
    fn default() -> Self { Self::new() }
}

fn detect_suspicious_http_patterns(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<String> {
    let mut patterns = Vec::new();
    let path_low = path.to_lowercase();
    let body_text = String::from_utf8_lossy(body);

    if path_low.contains("gate.php") || path_low.contains("gate.asp") {
        patterns.push("c2_gate_path".to_string());
    }
    if path_low.contains("upload") && method == "POST" {
        patterns.push("file_upload".to_string());
    }
    if body_text.contains("COMPUTERNAME=") || body_text.contains("USERNAME=") {
        patterns.push("system_info_exfil".to_string());
    }
    // Look for base64 in body
    if body.len() > 64 && body.iter().all(|&b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')) {
        patterns.push("possible_base64_payload".to_string());
    }
    // UA looks like malware
    for (k, v) in headers {
        if k.to_lowercase() == "user-agent" && (v.is_empty() || v == "Mozilla") {
            patterns.push("suspicious_user_agent".to_string());
        }
    }
    patterns
}

// ── Network analyzer ─────────────────────────────────────────────────────────

pub struct NetworkAnalyzer {
    packets: Vec<NetworkPacket>,
    flows: HashMap<u64, NetworkFlow>,
    flow_counter: u64,
    c2_indicators: Vec<C2Indicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Indicator {
    pub indicator_type: C2IndicatorType,
    pub description: String,
    pub flow_id: Option<u64>,
    pub confidence: f32,
    pub ioc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2IndicatorType {
    BeaconInterval,
    DomainGenerationAlgorithm,
    KnownC2Domain,
    UnusualPort,
    LargeDataExfil,
    Base64InUrl,
    PhpGate,
    EncryptedChannel,
    JitterPattern,
}

impl NetworkAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            flows: HashMap::new(),
            flow_counter: 0,
            c2_indicators: Vec::new(),
        }
    }

    pub fn add_packet(&mut self, pkt: NetworkPacket) {
        let fid = self.get_or_create_flow(&pkt);
        if let Some(flow) = self.flows.get_mut(&fid) {
            match pkt.direction {
                PacketDirection::Outbound => {
                    flow.packets_out += 1;
                    flow.bytes_out += pkt.payload.len() as u64;
                }
                PacketDirection::Inbound => {
                    flow.packets_in += 1;
                    flow.bytes_in += pkt.payload.len() as u64;
                }
            }
            flow.last_seen_ns = pkt.timestamp_ns;
        }
        self.packets.push(pkt);
    }

    fn get_or_create_flow(&mut self, pkt: &NetworkPacket) -> u64 {
        // Simple flow key: sorted endpoints
        let (a, b) = if pkt.src < pkt.dst { (pkt.src, pkt.dst) } else { (pkt.dst, pkt.src) };
        let key = format!("{a}-{b}");
        let key_hash = simple_hash(key.as_bytes());

        if !self.flows.contains_key(&key_hash) {
            self.flow_counter += 1;
            let state = if pkt.flags.syn() && !pkt.flags.ack() {
                FlowState::Syn
            } else { FlowState::Unknown };
            self.flows.insert(key_hash, NetworkFlow {
                flow_id: self.flow_counter,
                protocol: pkt.protocol.clone(),
                src: pkt.src,
                dst: pkt.dst,
                packets_out: 0,
                packets_in: 0,
                bytes_out: 0,
                bytes_in: 0,
                first_seen_ns: pkt.timestamp_ns,
                last_seen_ns: pkt.timestamp_ns,
                state,
                application_layer: None,
            });
        }
        key_hash
    }

    pub fn analyze_c2_patterns(&mut self) {
        self.c2_indicators.clear();

        // Check for beacon interval patterns
        let outbound_times: Vec<u64> = self.packets.iter()
            .filter(|p| p.direction == PacketDirection::Outbound)
            .map(|p| p.timestamp_ns)
            .collect();

        if outbound_times.len() >= 3 {
            let intervals: Vec<u64> = outbound_times.windows(2)
                .map(|w| w[1].saturating_sub(w[0]))
                .collect();
            let n = intervals.len() as u64;
            // Use f64 throughout to avoid integer overflow on sum and variance.
            let mean_f = intervals.iter().map(|&i| u64_to_f64(i)).sum::<f64>() / u64_to_f64(n);
            let mean = f64_to_u64(mean_f);
            let variance_f: f64 = intervals.iter()
                .map(|&i| { let d = u64_to_f64(i) - mean_f; d * d })
                .sum::<f64>() / u64_to_f64(n);
            let std_dev = variance_f.sqrt();
            let cv = if mean > 0 { std_dev / u64_to_f64(mean) } else { 0.0 };
            if cv < 0.15 && outbound_times.len() >= 5 {
                self.c2_indicators.push(C2Indicator {
                    indicator_type: C2IndicatorType::BeaconInterval,
                    description: format!("Regular beacon interval detected: {}ms \u{b1}{:.0}ms (CV={:.2})",
                        mean / 1_000_000, std_dev / 1_000_000.0, cv),
                    flow_id: None,
                    confidence: f64_to_f32(1.0 - cv),
                    ioc: format!("interval={}ms", mean / 1_000_000),
                });
            }
        }

        // Check unusual ports
        for flow in self.flows.values() {
            let dst_port = flow.dst.port();
            if !matches!(dst_port, 80 | 443 | 53 | 22 | 25 | 587 | 8080 | 8443) {
                self.c2_indicators.push(C2Indicator {
                    indicator_type: C2IndicatorType::UnusualPort,
                    description: format!("Connection to unusual port {dst_port}"),
                    flow_id: Some(flow.flow_id),
                    confidence: 0.5,
                    ioc: format!("dst_port={dst_port}"),
                });
            }
        }

        // Large data exfiltration
        for flow in self.flows.values() {
            if flow.bytes_out > 1_000_000 {
                self.c2_indicators.push(C2Indicator {
                    indicator_type: C2IndicatorType::LargeDataExfil,
                    description: format!("Large outbound data: {} bytes to {}",
                        flow.bytes_out, flow.dst),
                    flow_id: Some(flow.flow_id),
                    confidence: 0.7,
                    ioc: format!("exfil={}bytes,dst={}", flow.bytes_out, flow.dst),
                });
            }
        }
    }

    #[must_use]
    pub fn get_summary(&self) -> NetworkSummary {
        let unique_ips: std::collections::HashSet<_> = self.flows.values()
            .map(|f| f.dst.ip()).collect();
        let unique_ports: std::collections::HashSet<_> = self.flows.values()
            .map(|f| f.dst.port()).collect();

        NetworkSummary {
            total_packets: self.packets.len(),
            total_flows: self.flows.len(),
            unique_remote_ips: unique_ips.len(),
            unique_remote_ports: unique_ports.len(),
            bytes_out: self.flows.values().map(|f| f.bytes_out).sum(),
            bytes_in: self.flows.values().map(|f| f.bytes_in).sum(),
            c2_indicators: self.c2_indicators.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub total_packets: usize,
    pub total_flows: usize,
    pub unique_remote_ips: usize,
    pub unique_remote_ports: usize,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub c2_indicators: Vec<C2Indicator>,
}

impl Default for NetworkAnalyzer {
    fn default() -> Self { Self::new() }
}

/// Saturating cast: `u64` → `f64` (precision loss accepted for statistics).
#[inline]
const fn u64_to_f64(v: u64) -> f64 { v as f64 }

/// Saturating cast: `f64` → `f32` (truncation accepted for score fields).
#[inline]
const fn f64_to_f32(v: f64) -> f32 { v as f32 }

/// Saturating cast: `usize` → `f32` (precision loss accepted for ratios).
#[inline]
const fn usize_to_f32(v: usize) -> f32 { v as f32 }

/// Saturating cast: `u32` → `f32` (precision loss accepted for frequencies).
#[inline]
const fn u32_to_f32(v: u32) -> f32 { v as f32 }

/// Saturating cast: `f64` → `u64` (non-negative values only, truncates).
#[inline]
fn f64_to_u64(v: f64) -> u64 { if v < 0.0 { 0 } else { v as u64 } }

fn simple_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Clamp current nanosecond timestamp to `u64` range.
fn nanos_to_u64() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u128::from(u64::MAX)),
    )
    .unwrap_or(u64::MAX)
}

// ── Async dispatch channel ───────────────────────────────────────────────────

/// A bounded async channel for emitting [`NetworkPacket`]s out of the
/// in-process fake stack.
///
/// The receiver half can be used by a real driver (Frida, Qiling, etc.) to
/// forward simulated traffic to the outside world.
pub struct PacketDispatch {
    sender: mpsc::Sender<NetworkPacket>,
}

impl PacketDispatch {
    /// Build a new dispatch with capacity `cap`. Returns the dispatch and
    /// the matching receiver half.
    #[must_use]
    pub fn channel(cap: usize) -> (Self, mpsc::Receiver<NetworkPacket>) {
        let (tx, rx) = mpsc::channel(cap.max(1));
        (Self { sender: tx }, rx)
    }

    /// Validate `pkt` and forward it onto the channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is empty (the fake stack never emits
    /// zero-byte frames) or if the receiver was dropped.
    pub async fn dispatch(&self, pkt: NetworkPacket) -> Result<()> {
        if pkt.payload.is_empty() {
            bail!("refusing to dispatch zero-byte NetworkPacket id={}", pkt.id);
        }
        self.sender
            .send(pkt)
            .await
            .map_err(|e| anyhow::anyhow!("PacketDispatch receiver closed: {e}"))
    }
}

// ── DGA detector ─────────────────────────────────────────────────────────────

pub struct DgaDetector {
    known_benign_tlds: Vec<String>,
    dga_threshold: f32,
}

impl DgaDetector {
    pub fn new() -> Self {
        Self {
            known_benign_tlds: ["com", "net", "org", "gov", "edu", "io", "co"].iter()
                .map(ToString::to_string).collect(),
            dga_threshold: 0.7,
        }
    }

    /// Vocabulary of TLDs treated as benign (`com`, `net`, …). Public so
    /// callers can audit / extend the heuristic.
    #[must_use]
    pub fn benign_tlds(&self) -> &[String] {
        &self.known_benign_tlds
    }

    /// Add a TLD to the benign list. Lower-cased, deduplicated.
    pub fn add_benign_tld(&mut self, tld: &str) {
        let t = tld.trim_start_matches('.').to_ascii_lowercase();
        if !self.known_benign_tlds.iter().any(|x| x == &t) {
            self.known_benign_tlds.push(t);
        }
    }

    #[must_use]
    pub fn classify(&self, domain: &str) -> DgaClassification {
        let parts: Vec<&str> = domain.rsplitn(3, '.').collect();
        let host = parts.last().copied().unwrap_or(domain);
        let tld = parts.first().copied().unwrap_or("").to_ascii_lowercase();
        let entropy = char_entropy(host);
        let consonant_ratio = consonant_ratio(host);
        let digit_ratio = usize_to_f32(host.chars().filter(char::is_ascii_digit).count())
            / usize_to_f32(host.len().max(1));
        let len = host.len();

        // Score 0-1 where 1 = likely DGA
        let mut score = 0.0f32;
        if entropy > 3.8 { score += 0.3; }
        if consonant_ratio > 0.75 { score += 0.2; }
        if digit_ratio > 0.3 { score += 0.2; }
        if len > 12 { score += 0.1; }
        if len > 20 { score += 0.2; }
        if !host.chars().any(is_vowel) { score += 0.2; }
        // Benign TLD heuristic: trim by a fixed bonus when the domain ends
        // in something we explicitly trust. Doesn't zero the score (a DGA
        // can still register a `.com`) but lowers false-positive rate.
        if self.known_benign_tlds.iter().any(|t| t == &tld) {
            score = (score - 0.15).max(0.0);
        }

        DgaClassification {
            domain: domain.to_string(),
            is_dga: score >= self.dga_threshold,
            score,
            entropy,
            consonant_ratio,
            digit_ratio,
            host_length: len,
        }
    }
}

impl Default for DgaDetector {
    fn default() -> Self { Self::new() }
}

fn char_entropy(s: &str) -> f32 {
    let mut freq = [0u32; 26];
    let mut total = 0u32;
    for c in s.chars().filter(char::is_ascii_alphabetic) {
        freq[(c.to_ascii_lowercase() as u8 - b'a') as usize] += 1;
        total += 1;
    }
    if total == 0 { return 0.0; }
    freq.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = u32_to_f32(c) / u32_to_f32(total); -p * p.log2() })
        .sum()
}

fn consonant_ratio(s: &str) -> f32 {
    let alpha: usize = s.chars().filter(char::is_ascii_alphabetic).count();
    let consonants: usize = s.chars().filter(|c| c.is_ascii_alphabetic() && !is_vowel(*c)).count();
    if alpha == 0 { 0.0 } else { usize_to_f32(consonants) / usize_to_f32(alpha) }
}

const fn is_vowel(c: char) -> bool {
    matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaClassification {
    pub domain: String,
    pub is_dga: bool,
    pub score: f32,
    pub entropy: f32,
    pub consonant_ratio: f32,
    pub digit_ratio: f32,
    pub host_length: usize,
}
