//! `network_simulation` — Simulated network services for sandbox analysis.
//!
//! Provides fake DNS, HTTP/HTTPS, SMTP servers and ARP spoofing to intercept
//! and record all network activity from a sandboxed process without allowing
//! real outbound connectivity.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("bind failed on {addr}: {msg}")]
    BindFailed { addr: SocketAddr, msg: String },
    #[error("server already running: {0}")]
    AlreadyRunning(String),
    #[error("server not running: {0}")]
    NotRunning(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("tls config error: {0}")]
    TlsConfig(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl From<std::io::Error> for SimError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ─── Shared Types ─────────────────────────────────────────────────────────────

/// Timestamp as milliseconds since Unix epoch.
pub type Timestamp = u64;

fn now_ms() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX)
}

/// A captured network interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedInteraction {
    pub id: u64,
    pub timestamp_ms: Timestamp,
    pub protocol: NetworkProtocol,
    pub client_addr: String,
    pub server_addr: String,
    pub request_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Dns,
    Http,
    Https,
    Smtp,
    Arp,
    Unknown,
}

impl std::fmt::Display for NetworkProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns => write!(f, "DNS"),
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Smtp => write!(f, "SMTP"),
            Self::Arp => write!(f, "ARP"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Interaction Store ────────────────────────────────────────────────────────

/// Shared in-memory store for every interaction captured by the fake servers.
///
/// Public so the constructors that take an `Arc<Mutex<InteractionStore>>` are
/// usable from downstream crates that drive the sandbox.
#[derive(Debug, Default)]
pub struct InteractionStore {
    next_id: u64,
    interactions: Vec<CapturedInteraction>,
}

impl InteractionStore {
    /// Record one interaction and return its assigned id.
    pub fn push(&mut self, mut interaction: CapturedInteraction) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        interaction.id = id;
        self.interactions.push(interaction);
        id
    }

    /// All captured interactions in insertion order.
    #[must_use]
    pub fn get_all(&self) -> Vec<CapturedInteraction> {
        self.interactions.clone()
    }

    /// Only the interactions matching `proto`.
    #[must_use]
    pub fn get_by_protocol(&self, proto: NetworkProtocol) -> Vec<CapturedInteraction> {
        self.interactions.iter().filter(|i| i.protocol == proto).cloned().collect()
    }

    /// Total number of captured interactions.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.interactions.len()
    }
}

// ─── DNS Record ───────────────────────────────────────────────────────────────

/// A DNS record returned by the fake DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
}

/// Configuration for the fake DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerConfig {
    /// IP to bind on (e.g., 127.0.0.1 or a sandbox-internal IP).
    pub bind_addr: String,
    /// Port (default: 53).
    pub port: u16,
    /// Default IP returned for any A query not in `overrides`.
    pub default_a_response: Ipv4Addr,
    /// Per-domain overrides.
    pub overrides: HashMap<String, String>,
    /// Whether to log all queries.
    pub log_queries: bool,
    /// Simulated latency in milliseconds.
    pub latency_ms: u64,
}

impl Default for DnsServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.53".to_owned(),
            port: 53,
            default_a_response: Ipv4Addr::new(10, 0, 0, 1),
            overrides: HashMap::new(),
            log_queries: true,
            latency_ms: 5,
        }
    }
}

/// Captured DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp_ms: Timestamp,
    pub client: String,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: DnsRecordType,
    pub response_ip: String,
}

/// Fake DNS server — responds to all queries with a controlled IP.
#[derive(Debug)]
pub struct FakeDnsServer {
    config: DnsServerConfig,
    queries: Arc<Mutex<Vec<DnsQuery>>>,
    store: Arc<Mutex<InteractionStore>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl FakeDnsServer {
    /// Returns `true` if the server's run-flag has been toggled on by
    /// [`Self::set_running`]. Lets callers gate on lifecycle from outside.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Mark the server as running (or stopped). Cooperative flag — the
    /// async listen loop is expected to honour this in its select branch.
    pub fn set_running(&self, on: bool) {
        self.running.store(on, std::sync::atomic::Ordering::Release);
    }

    pub fn new(config: DnsServerConfig, store: Arc<Mutex<InteractionStore>>) -> Self {
        Self {
            config,
            queries: Arc::new(Mutex::new(Vec::new())),
            store,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Parse a minimal DNS query packet and extract the queried name.
    fn parse_query_name(data: &[u8]) -> Option<(u16, String)> {
        if data.len() < 12 {
            return None;
        }
        let txid = u16::from_be_bytes([data[0], data[1]]);
        // flags at [2..4], qdcount at [4..6]
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount == 0 {
            return None;
        }
        // Parse QNAME starting at offset 12
        let mut offset = 12usize;
        let mut labels = Vec::new();
        loop {
            if offset >= data.len() {
                return None;
            }
            let len = data[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            // Compression pointer
            if len & 0xC0 == 0xC0 {
                return None; // skip compression for fake server
            }
            offset += 1;
            if offset + len > data.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
            offset += len;
        }
        // After the terminating zero label, a well-formed DNS query carries
        // QTYPE (2 bytes) and QCLASS (2 bytes). Validate the packet is long
        // enough so we don't claim success on a truncated trailer.
        if offset + 4 > data.len() {
            return None;
        }
        Some((txid, labels.join(".")))
    }

    /// Build a minimal DNS A response.
    fn build_a_response(txid: u16, name: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        // Header
        buf.extend_from_slice(&txid.to_be_bytes());
        buf.extend_from_slice(&[0x81, 0x80]); // QR=1 AA=0 RD=1 RA=1
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        buf.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // Question (copy encoded name)
        for label in name.split('.') {
            // DNS labels are at most 63 bytes; silently truncate longer labels
            // rather than casting a large usize to u8 (which would wrap).
            let label_bytes = label.as_bytes();
            let label_len = u8::try_from(label_bytes.len().min(63)).unwrap_or(63);
            buf.push(label_len);
            buf.extend_from_slice(&label_bytes[..label_len as usize]);
        }
        buf.push(0x00);              // end of name
        buf.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        // Answer — pointer to question name (0xC00C)
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        buf.extend_from_slice(&ip.octets());
        buf
    }

    /// Simulate processing a received DNS packet.
    #[must_use] 
    pub fn process_packet(&self, data: &[u8], client: &str) -> Option<Vec<u8>> {
        let (txid, name) = Self::parse_query_name(data)?;
        // Look up override or use default
        let response_ip = self.config.overrides.get(&name).map_or(
            self.config.default_a_response,
            |ip_str| ip_str.parse::<Ipv4Addr>().unwrap_or(self.config.default_a_response),
        );

        let query = DnsQuery {
            timestamp_ms: now_ms(),
            client: client.to_owned(),
            transaction_id: txid,
            query_name: name.clone(),
            query_type: DnsRecordType::A,
            response_ip: response_ip.to_string(),
        };
        self.queries.lock().push(query);

        let response = Self::build_a_response(txid, &name, response_ip);
        let interaction = CapturedInteraction {
            id: 0,
            timestamp_ms: now_ms(),
            protocol: NetworkProtocol::Dns,
            client_addr: client.to_owned(),
            server_addr: format!("{}:{}", self.config.bind_addr, self.config.port),
            request_bytes: data.to_vec(),
            response_bytes: response.clone(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("query_name".to_owned(), name);
                m.insert("response_ip".to_owned(), response_ip.to_string());
                m
            },
        };
        self.store.lock().push(interaction);
        Some(response)
    }

    #[must_use] 
    pub fn get_queries(&self) -> Vec<DnsQuery> {
        self.queries.lock().clone()
    }

    #[must_use] 
    pub fn unique_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = {
            let qs = self.queries.lock();
            qs.iter().map(|q| q.query_name.clone()).collect()
        };
        domains.sort();
        domains.dedup();
        domains
    }

    #[must_use] 
    pub fn query_count(&self) -> usize {
        self.queries.lock().len()
    }
}

// ─── HTTP Response Template ───────────────────────────────────────────────────

/// Custom HTTP response returned by the fake HTTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseTemplate {
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Default for HttpResponseTemplate {
    fn default() -> Self {
        Self {
            status_code: 200,
            status_text: "OK".to_owned(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Content-Type".to_owned(), "text/plain".to_owned());
                h.insert("Server".to_owned(), "FakeSrv/1.0".to_owned());
                h
            },
            body: b"OK".to_vec(),
        }
    }
}

impl HttpResponseTemplate {
    #[must_use] 
    pub fn redirect(location: &str) -> Self {
        Self {
            status_code: 302,
            status_text: "Found".to_owned(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Location".to_owned(), location.to_owned());
                h
            },
            body: Vec::new(),
        }
    }

    #[must_use] 
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status_code, self.status_text
        )
        .into_bytes();
        let body_len = self.body.len();
        for (k, v) in &self.headers {
            buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        buf.extend_from_slice(
            format!("Content-Length: {body_len}\r\n\r\n").as_bytes(),
        );
        buf.extend_from_slice(&self.body);
        buf
    }
}

/// A parsed HTTP request captured by the fake server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedHttpRequest {
    pub timestamp_ms: Timestamp,
    pub client_addr: String,
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub tls: bool,
}

impl CapturedHttpRequest {
    /// Minimal HTTP/1.x request parser.
    #[must_use] 
    pub fn parse(data: &[u8], client: &str, tls: bool) -> Option<Self> {
        let raw = std::str::from_utf8(data).ok()?;
        let mut lines = raw.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next()?.to_owned();
        let path = parts.next()?.to_owned();
        let version = parts.next().unwrap_or("HTTP/1.1").to_owned();

        let mut headers = HashMap::new();
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(": ") {
                headers.insert(k.to_ascii_lowercase(), v.to_owned());
            }
        }
        // Find body separator
        let body_start = data
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(data.len(), |p| p + 4);
        let body = data[body_start..].to_vec();

        Some(Self {
            timestamp_ms: now_ms(),
            client_addr: client.to_owned(),
            method,
            path,
            http_version: version,
            headers,
            body,
            tls,
        })
    }
}

/// Configuration for the fake HTTP/HTTPS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpServerConfig {
    pub bind_addr: String,
    pub http_port: u16,
    pub https_port: u16,
    /// Default response for unmatched paths.
    pub default_response: HttpResponseTemplate,
    /// Path-specific response overrides.
    pub path_overrides: HashMap<String, HttpResponseTemplate>,
    /// If true, record all request bodies.
    pub record_bodies: bool,
    /// Maximum body bytes to store (prevents memory exhaustion).
    pub max_body_bytes: usize,
    /// Simulated latency in milliseconds.
    pub latency_ms: u64,
    /// TLS certificate PEM (self-signed acceptable).
    pub tls_cert_pem: Option<String>,
    /// TLS private key PEM.
    pub tls_key_pem: Option<String>,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_owned(),
            http_port: 8080,
            https_port: 8443,
            default_response: HttpResponseTemplate::default(),
            path_overrides: HashMap::new(),
            record_bodies: true,
            max_body_bytes: 1_048_576, // 1 MiB
            latency_ms: 10,
            tls_cert_pem: None,
            tls_key_pem: None,
        }
    }
}

/// Fake HTTP/HTTPS server.
pub struct FakeHttpServer {
    config: HttpServerConfig,
    requests: Arc<Mutex<Vec<CapturedHttpRequest>>>,
    store: Arc<Mutex<InteractionStore>>,
}

impl std::fmt::Debug for FakeHttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeHttpServer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl FakeHttpServer {
    pub fn new(config: HttpServerConfig, store: Arc<Mutex<InteractionStore>>) -> Self {
        Self {
            config,
            requests: Arc::new(Mutex::new(Vec::new())),
            store,
        }
    }

    /// Process a raw HTTP(S) request buffer. Returns the serialized response.
    #[must_use] 
    pub fn process_request(&self, data: &[u8], client: &str, tls: bool) -> Vec<u8> {
        let req = CapturedHttpRequest::parse(data, client, tls);
        let (path, method) = req.as_ref().map_or_else(|| ("/".to_owned(), "GET".to_owned()), |r| (r.path.clone(), r.method.clone()));

        // Store request
        if let Some(r) = &req {
            self.requests.lock().push(r.clone());
        }

        // Determine response
        let template = self.config.path_overrides.get(&path)
            .unwrap_or(&self.config.default_response);
        let response_bytes = template.serialize();

        let interaction = CapturedInteraction {
            id: 0,
            timestamp_ms: now_ms(),
            protocol: if tls { NetworkProtocol::Https } else { NetworkProtocol::Http },
            client_addr: client.to_owned(),
            server_addr: format!(
                "{}:{}",
                self.config.bind_addr,
                if tls { self.config.https_port } else { self.config.http_port }
            ),
            request_bytes: if self.config.record_bodies {
                data[..data.len().min(self.config.max_body_bytes)].to_vec()
            } else {
                Vec::new()
            },
            response_bytes: response_bytes.clone(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("method".to_owned(), method);
                m.insert("path".to_owned(), path);
                m.insert("tls".to_owned(), tls.to_string());
                m
            },
        };
        self.store.lock().push(interaction);
        response_bytes
    }

    #[must_use] 
    pub fn get_requests(&self) -> Vec<CapturedHttpRequest> {
        self.requests.lock().clone()
    }

    #[must_use] 
    pub fn unique_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = {
            let reqs = self.requests.lock();
            reqs.iter().map(|r| r.path.clone()).collect()
        };
        paths.sort();
        paths.dedup();
        paths
    }

    #[must_use] 
    pub fn c2_beacon_candidates(&self) -> Vec<String> {
        // Paths accessed more than 3 times are beacon candidates
        let reqs = self.requests.lock();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in reqs.iter() {
            *counts.entry(r.path.clone()).or_default() += 1;
        }
        drop(reqs);
        counts.into_iter()
            .filter(|(_, c)| *c > 3)
            .map(|(p, _)| p)
            .collect()
    }

    #[must_use] 
    pub fn request_count(&self) -> usize {
        self.requests.lock().len()
    }
}

// ─── SMTP Server ──────────────────────────────────────────────────────────────

/// A captured SMTP email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedEmail {
    pub timestamp_ms: Timestamp,
    pub client_addr: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<EmailAttachment>,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// Configuration for the fake SMTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpServerConfig {
    pub bind_addr: String,
    pub port: u16,
    pub hostname: String,
    pub max_message_size: usize,
    pub latency_ms: u64,
}

impl Default for SmtpServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_owned(),
            port: 25,
            hostname: "sandbox.local".to_owned(),
            max_message_size: 10 * 1024 * 1024,
            latency_ms: 20,
        }
    }
}

/// Fake SMTP server — captures exfiltration emails.
#[derive(Debug)]
pub struct FakeSmtpServer {
    config: SmtpServerConfig,
    emails: Arc<Mutex<Vec<CapturedEmail>>>,
    store: Arc<Mutex<InteractionStore>>,
}

impl FakeSmtpServer {
    pub fn new(config: SmtpServerConfig, store: Arc<Mutex<InteractionStore>>) -> Self {
        Self {
            config,
            emails: Arc::new(Mutex::new(Vec::new())),
            store,
        }
    }

    /// Build SMTP greeting banner.
    #[must_use] 
    pub fn greeting(&self) -> String {
        format!("220 {} ESMTP FakeMTA\r\n", self.config.hostname)
    }

    /// Process an SMTP command line. Returns (response, done).
    pub fn process_command(&self, cmd: &str, state: &mut SmtpSessionState) -> (String, bool) {
        let upper = cmd.trim().to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            state.phase = SmtpPhase::Greeted;
            (format!("250-{}\r\n250 OK\r\n", self.config.hostname), false)
        } else if upper.starts_with("MAIL FROM:") {
            // Use the uppercased prefix length to skip the ASCII prefix safely,
            // then recover the original characters from the trimmed original string.
            let trimmed = cmd.trim();
            let from = trimmed.get(10..)
                .unwrap_or("")
                .trim()
                .trim_matches('<')
                .trim_matches('>')
                .to_owned();
            state.from = from;
            state.phase = SmtpPhase::Mail;
            ("250 OK\r\n".to_owned(), false)
        } else if upper.starts_with("RCPT TO:") {
            let trimmed = cmd.trim();
            let to = trimmed.get(8..)
                .unwrap_or("")
                .trim()
                .trim_matches('<')
                .trim_matches('>')
                .to_owned();
            state.to.push(to);
            state.phase = SmtpPhase::Rcpt;
            ("250 OK\r\n".to_owned(), false)
        } else if upper == "DATA" {
            state.phase = SmtpPhase::Data;
            ("354 Start input; end with <CRLF>.<CRLF>\r\n".to_owned(), false)
        } else if upper == "QUIT" {
            ("221 Bye\r\n".to_owned(), true)
        } else if upper == "RSET" {
            *state = SmtpSessionState::default();
            ("250 OK\r\n".to_owned(), false)
        } else {
            ("500 Unknown command\r\n".to_owned(), false)
        }
    }

    /// Called when DATA phase ends (after ".\r\n"). Stores the captured email.
    pub fn finalize_email(&self, data: Vec<u8>, state: &SmtpSessionState, client: &str) {
        let raw_str = String::from_utf8_lossy(&data).to_string();
        // Extract subject from headers
        let subject = raw_str.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("subject:")).map_or_else(|| "(no subject)".to_owned(), |l| l[8..].trim().to_owned());

        // Parse attachments (minimal MIME, look for Content-Disposition: attachment)
        let attachments = Self::parse_attachments(&data);

        let email = CapturedEmail {
            timestamp_ms: now_ms(),
            client_addr: client.to_owned(),
            from: state.from.clone(),
            to: state.to.clone(),
            subject: subject.clone(),
            body: raw_str,
            attachments,
            raw_data: data.clone(),
        };
        self.emails.lock().push(email);

        let interaction = CapturedInteraction {
            id: 0,
            timestamp_ms: now_ms(),
            protocol: NetworkProtocol::Smtp,
            client_addr: client.to_owned(),
            server_addr: format!("{}:{}", self.config.bind_addr, self.config.port),
            request_bytes: data,
            response_bytes: b"250 OK\r\n".to_vec(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("from".to_owned(), state.from.clone());
                m.insert("to".to_owned(), state.to.join(", "));
                m.insert("subject".to_owned(), subject);
                m
            },
        };
        self.store.lock().push(interaction);
    }

    fn parse_attachments(data: &[u8]) -> Vec<EmailAttachment> {
        let raw = String::from_utf8_lossy(data);
        let mut attachments = Vec::new();
        let mut in_attachment = false;
        let mut current_filename = String::new();
        let mut current_ct = String::new();
        let mut current_data = Vec::new();

        for line in raw.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("content-disposition: attachment") {
                in_attachment = true;
            } else if in_attachment && lower.starts_with("content-type:") {
                line[13..].trim().clone_into(&mut current_ct);
            } else if in_attachment && lower.contains("filename=") {
                if let Some(pos) = line.find("filename=") {
                    line[pos + 9..]
                        .trim_matches('"')
                        .trim_matches('\'')
                        .clone_into(&mut current_filename);
                }
            } else if in_attachment && line.trim().is_empty() && !current_filename.is_empty() {
                // Data follows
            } else if in_attachment && line.starts_with("--") {
                if !current_data.is_empty() {
                    attachments.push(EmailAttachment {
                        filename: current_filename.clone(),
                        content_type: current_ct.clone(),
                        data: current_data.clone(),
                    });
                    current_data.clear();
                    current_filename.clear();
                    in_attachment = false;
                }
            } else if in_attachment {
                current_data.extend_from_slice(line.as_bytes());
            }
        }
        attachments
    }

    #[must_use] 
    pub fn get_emails(&self) -> Vec<CapturedEmail> {
        self.emails.lock().clone()
    }

    #[must_use] 
    pub fn email_count(&self) -> usize {
        self.emails.lock().len()
    }
}

/// State for an active SMTP session.
#[derive(Debug, Default, Clone)]
pub struct SmtpSessionState {
    pub phase: SmtpPhase,
    pub from: String,
    pub to: Vec<String>,
    pub data_buffer: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum SmtpPhase {
    #[default]
    Connected,
    Greeted,
    Mail,
    Rcpt,
    Data,
    Done,
}

// ─── ARP Spoofer ──────────────────────────────────────────────────────────────

/// An ARP table entry as captured by the spoofer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub timestamp_ms: Timestamp,
    pub ip: String,
    pub mac: [u8; 6],
    pub spoofed: bool,
}

/// ARP spoofer — intercepts LAN traffic by poisoning ARP caches.
#[derive(Debug)]
pub struct ArpSpoofer {
    target_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    attacker_mac: [u8; 6],
    arp_table: Arc<RwLock<HashMap<Ipv4Addr, [u8; 6]>>>,
    intercepted: Arc<Mutex<Vec<ArpEntry>>>,
    store: Arc<Mutex<InteractionStore>>,
}

impl ArpSpoofer {
    pub fn new(
        target_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        attacker_mac: [u8; 6],
        store: Arc<Mutex<InteractionStore>>,
    ) -> Self {
        Self {
            target_ip,
            gateway_ip,
            attacker_mac,
            arp_table: Arc::new(RwLock::new(HashMap::new())),
            intercepted: Arc::new(Mutex::new(Vec::new())),
            store,
        }
    }

    /// Gateway address this spoofer is masquerading as.
    #[must_use]
    pub const fn gateway_ip(&self) -> Ipv4Addr {
        self.gateway_ip
    }

    /// Target host whose ARP cache we are poisoning.
    #[must_use]
    pub const fn target_ip(&self) -> Ipv4Addr {
        self.target_ip
    }

    /// Build an ARP reply packet (opcode=2) announcing we own `sender_ip`.
    #[must_use] 
    pub fn build_arp_reply(
        &self,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        target_mac: [u8; 6],
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(42);
        // Ethernet header (14 bytes)
        frame.extend_from_slice(&target_mac);       // dst MAC
        frame.extend_from_slice(&self.attacker_mac); // src MAC
        frame.extend_from_slice(&[0x08, 0x06]);     // EtherType ARP
        // ARP payload (28 bytes)
        frame.extend_from_slice(&[0x00, 0x01]); // HTYPE=Ethernet
        frame.extend_from_slice(&[0x08, 0x00]); // PTYPE=IPv4
        frame.push(6);                          // HLEN
        frame.push(4);                          // PLEN
        frame.extend_from_slice(&[0x00, 0x02]); // OPER=Reply
        frame.extend_from_slice(&self.attacker_mac); // SHA (our MAC)
        frame.extend_from_slice(&sender_ip.octets()); // SPA
        frame.extend_from_slice(&target_mac);   // THA
        frame.extend_from_slice(&target_ip.octets()); // TPA
        frame
    }

    /// Process a received ARP packet to update the local ARP table.
    pub fn process_arp_packet(&self, data: &[u8]) {
        if data.len() < 42 {
            return;
        }
        // Skip Ethernet header (14 bytes), parse ARP
        let arp = &data[14..];
        if arp.len() < 28 {
            return;
        }
        let opcode = u16::from_be_bytes([arp[6], arp[7]]);
        if opcode != 1 && opcode != 2 {
            return;
        }
        let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
        let sender_mac = [arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]];

        let spoofed = sender_mac == self.attacker_mac;
        let entry = ArpEntry {
            timestamp_ms: now_ms(),
            ip: sender_ip.to_string(),
            mac: sender_mac,
            spoofed,
        };
        self.intercepted.lock().push(entry);
        self.arp_table.write().insert(sender_ip, sender_mac);

        let interaction = CapturedInteraction {
            id: 0,
            timestamp_ms: now_ms(),
            protocol: NetworkProtocol::Arp,
            client_addr: sender_ip.to_string(),
            server_addr: self.target_ip.to_string(),
            request_bytes: data.to_vec(),
            response_bytes: Vec::new(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("opcode".to_owned(), opcode.to_string());
                m.insert("spoofed".to_owned(), spoofed.to_string());
                m
            },
        };
        self.store.lock().push(interaction);
    }

    /// Get the current ARP table snapshot.
    #[must_use] 
    pub fn arp_table(&self) -> HashMap<String, String> {
        self.arp_table.read().iter()
            .map(|(ip, mac)| {
                let mac_str = mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
                (ip.to_string(), mac_str)
            })
            .collect()
    }

    #[must_use] 
    pub fn intercepted_count(&self) -> usize {
        self.intercepted.lock().len()
    }
}

// ─── Network Simulation Orchestrator ─────────────────────────────────────────

/// All fake servers bundled together for sandbox use.
pub struct NetworkSimulation {
    pub dns: FakeDnsServer,
    pub http: FakeHttpServer,
    pub smtp: FakeSmtpServer,
    pub arp: Option<ArpSpoofer>,
    store: Arc<Mutex<InteractionStore>>,
}

impl std::fmt::Debug for NetworkSimulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkSimulation")
            .field("dns_queries", &self.dns.query_count())
            .field("http_requests", &self.http.request_count())
            .field("smtp_emails", &self.smtp.email_count())
            .finish_non_exhaustive()
    }
}

impl NetworkSimulation {
    #[must_use] 
    pub fn new(
        dns_cfg: DnsServerConfig,
        http_cfg: HttpServerConfig,
        smtp_cfg: SmtpServerConfig,
    ) -> Self {
        let store = Arc::new(Mutex::new(InteractionStore::default()));
        Self {
            dns: FakeDnsServer::new(dns_cfg, Arc::clone(&store)),
            http: FakeHttpServer::new(http_cfg, Arc::clone(&store)),
            smtp: FakeSmtpServer::new(smtp_cfg, Arc::clone(&store)),
            arp: None,
            store,
        }
    }

    #[must_use] 
    pub fn with_arp(
        mut self,
        target_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        attacker_mac: [u8; 6],
    ) -> Self {
        self.arp = Some(ArpSpoofer::new(
            target_ip,
            gateway_ip,
            attacker_mac,
            Arc::clone(&self.store),
        ));
        self
    }

    #[must_use] 
    pub fn all_interactions(&self) -> Vec<CapturedInteraction> {
        self.store.lock().get_all()
    }

    #[must_use] 
    pub fn interaction_count(&self) -> usize {
        self.store.lock().count()
    }

    #[must_use] 
    pub fn summary(&self) -> NetworkSimulationSummary {
        NetworkSimulationSummary {
            dns_queries: self.dns.query_count(),
            unique_domains: self.dns.unique_domains(),
            http_requests: self.http.request_count(),
            unique_paths: self.http.unique_paths(),
            smtp_emails: self.smtp.email_count(),
            arp_entries: self.arp.as_ref().map_or(0, ArpSpoofer::intercepted_count),
            total_interactions: self.interaction_count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSimulationSummary {
    pub dns_queries: usize,
    pub unique_domains: Vec<String>,
    pub http_requests: usize,
    pub unique_paths: Vec<String>,
    pub smtp_emails: usize,
    pub arp_entries: usize,
    pub total_interactions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_response_roundtrip() {
        let store = Arc::new(Mutex::new(InteractionStore::default()));
        let cfg = DnsServerConfig::default();
        let srv = FakeDnsServer::new(cfg, store);

        // Build a minimal A query for "evil.com"
        let mut pkt = vec![0xAB, 0xCD]; // txid
        pkt.extend_from_slice(&[0x01, 0x00]); // flags RD=1
        pkt.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // counts
        // QNAME: 4evil3com0
        pkt.extend_from_slice(&[4, b'e', b'v', b'i', b'l', 3, b'c', b'o', b'm', 0]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A QCLASS=IN

        let resp = srv.process_packet(&pkt, "127.0.0.2");
        assert!(resp.is_some());
        assert_eq!(srv.query_count(), 1);
    }

    #[test]
    fn test_http_request_parse() {
        let store = Arc::new(Mutex::new(InteractionStore::default()));
        let cfg = HttpServerConfig::default();
        let srv = FakeHttpServer::new(cfg, store);

        let req = b"GET /beacon HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        let resp = srv.process_request(req, "192.168.1.50:12345", false);
        assert!(!resp.is_empty());
        assert_eq!(srv.request_count(), 1);
    }

    #[test]
    fn test_arp_spoofing() {
        let store = Arc::new(Mutex::new(InteractionStore::default()));
        let spoofer = ArpSpoofer::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            store,
        );
        let reply = spoofer.build_arp_reply(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        );
        assert_eq!(reply.len(), 42);
        assert_eq!(&reply[12..14], &[0x08, 0x06]); // ARP ethertype
    }

    #[test]
    fn test_smtp_session() {
        let store = Arc::new(Mutex::new(InteractionStore::default()));
        let cfg = SmtpServerConfig::default();
        let srv = FakeSmtpServer::new(cfg, store);
        let mut state = SmtpSessionState::default();

        let (r1, _) = srv.process_command("EHLO attacker.com", &mut state);
        assert!(r1.contains("250"));
        let (r2, _) = srv.process_command("MAIL FROM:<attacker@evil.com>", &mut state);
        assert!(r2.contains("250"));
        let (r3, _) = srv.process_command("RCPT TO:<victim@target.com>", &mut state);
        assert!(r3.contains("250"));
        let (r4, _) = srv.process_command("DATA", &mut state);
        assert!(r4.contains("354"));
        srv.finalize_email(b"Subject: test\r\n\r\nbody".to_vec(), &state, "192.168.1.200");
        assert_eq!(srv.email_count(), 1);
    }
}
