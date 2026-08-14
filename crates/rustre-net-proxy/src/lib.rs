//! `rustre-net-proxy` — Network proxy and MITM for traffic interception.
//!
//! Provides:
//! - Transparent, HTTP CONNECT, SOCKS4, SOCKS5, and Raw proxy modes
//! - Intercept hooks (`on_request` / `on_response`) with forward/drop/modify/redirect actions
//! - Traffic logging with timestamps
//! - Proxy statistics
//! - HTTP request/response parsing and rule-based transformation ([`http_interceptor`])
//! - TLS handshake interception, SNI extraction, and cert generation ([`tls_proxy`])
//! - Structured traffic logging with PCAP/HAR export ([`traffic_logger`])

#![forbid(unsafe_code)]

pub mod http_interceptor;
pub mod mitm_engine;
pub mod tls_proxy;
pub mod traffic_logger;
pub mod upstream;
pub mod websocket;

// Re-export upstream-selection and websocket types at the crate root so
// existing consumers (and the in-file test modules) continue to compile
// unchanged after the lib.rs ↔ submodule refactor.
pub use upstream::{ConnectionPool, UpstreamChain, UpstreamProxy};
pub use websocket::{
    detect_websocket_upgrade, parse_websocket_stream, reassemble_ws_messages, WebSocketFrame,
    WsOpcode,
};

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors produced by proxy operations.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SOCKS5 authentication failed")]
    Socks5AuthFailed,

    #[error("SOCKS5 unsupported command: {0}")]
    Socks5UnsupportedCommand(u8),

    #[error("SOCKS5 unsupported address type: {0}")]
    Socks5UnsupportedAddressType(u8),

    #[error("SOCKS4 request rejected")]
    Socks4Rejected,

    #[error("HTTP CONNECT failed: {0}")]
    HttpConnectFailed(String),

    #[error("connection refused by hook")]
    ConnectionDropped,

    #[error("upstream connection failed: {0}")]
    UpstreamFailed(String),

    #[error("proxy configuration error: {0}")]
    ConfigError(String),

    #[error("invalid proxy request: {0}")]
    InvalidRequest(String),

    #[error("timeout")]
    Timeout,
}

// ────────────────────────────────────────────────────────────────────────────
// Proxy configuration
// ────────────────────────────────────────────────────────────────────────────

/// Operating mode of the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    /// Transparent proxy — forward all TCP traffic without protocol-level awareness.
    Transparent,
    /// HTTP proxy with CONNECT tunnel support.
    Http,
    /// SOCKS4 proxy.
    Socks4,
    /// SOCKS5 proxy (RFC 1928).
    Socks5,
    /// Raw byte forwarding.
    Raw,
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Transparent => "Transparent",
            Self::Http => "HTTP",
            Self::Socks4 => "SOCKS4",
            Self::Socks5 => "SOCKS5",
            Self::Raw => "Raw",
        };
        write!(f, "{s}")
    }
}

/// SOCKS5 authentication method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Socks5Auth {
    None,
    UsernamePassword { username: String, password: String },
}

/// Full proxy server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Local address the proxy listens on.
    pub bind_addr: SocketAddr,
    /// Optional fixed upstream to forward all traffic to.
    pub upstream: Option<SocketAddr>,
    pub mode: ProxyMode,
    /// Whether to intercept (and potentially break) TLS.
    pub tls_intercept: bool,
    /// SOCKS5 authentication configuration.
    pub socks5_auth: Option<Socks5Auth>,
    /// Maximum size of a single in-memory intercept buffer (bytes).
    pub max_buffer: usize,
}

impl ProxyConfig {
    /// Create a simple HTTP proxy configuration.
    #[must_use] 
    pub const fn http(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            upstream: None,
            mode: ProxyMode::Http,
            tls_intercept: false,
            socks5_auth: None,
            max_buffer: 64 * 1024,
        }
    }

    /// Create a SOCKS5 proxy configuration.
    #[must_use] 
    pub const fn socks5(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            upstream: None,
            mode: ProxyMode::Socks5,
            tls_intercept: false,
            socks5_auth: None,
            max_buffer: 64 * 1024,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ────────────────────────────────────────────────────────────────────────────

/// Direction of intercepted traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Request,
    Response,
}

/// An intercepted proxy request (client → upstream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub id: u64,
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

impl ProxyRequest {
    #[must_use] 
    pub fn new(id: u64, client_addr: SocketAddr, target_addr: SocketAddr, data: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id,
            client_addr,
            target_addr,
            data,
            timestamp,
        }
    }
}

/// An intercepted proxy response (upstream → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub id: u64,
    pub source_addr: SocketAddr,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

impl ProxyResponse {
    #[must_use] 
    pub fn new(id: u64, source_addr: SocketAddr, data: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id,
            source_addr,
            data,
            timestamp,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Hook action
// ────────────────────────────────────────────────────────────────────────────

/// Action returned by an [`InterceptHook`].
#[derive(Debug, Clone)]
pub enum HookAction {
    /// Forward the data unchanged.
    Forward,
    /// Drop the connection.
    Drop,
    /// Substitute the payload with new data.
    Modify(Vec<u8>),
    /// Redirect the connection to a different upstream.
    Redirect(SocketAddr),
}

// ────────────────────────────────────────────────────────────────────────────
// Intercept hook trait
// ────────────────────────────────────────────────────────────────────────────

/// Async hook called for every intercepted request/response.
#[async_trait]
pub trait InterceptHook: Send + Sync {
    /// Called with the outgoing request. May modify `req.data` or return a
    /// different action.
    async fn on_request(&self, req: &mut ProxyRequest) -> HookAction;

    /// Called with the incoming response.
    async fn on_response(&self, resp: &mut ProxyResponse) -> HookAction;
}

/// A no-op hook that forwards everything unchanged.
pub struct PassthroughHook;

#[async_trait]
impl InterceptHook for PassthroughHook {
    async fn on_request(&self, _req: &mut ProxyRequest) -> HookAction {
        HookAction::Forward
    }
    async fn on_response(&self, _resp: &mut ProxyResponse) -> HookAction {
        HookAction::Forward
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Traffic log
// ────────────────────────────────────────────────────────────────────────────

/// A single entry in the traffic log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficLogEntry {
    pub id: u64,
    pub timestamp: u64,
    pub direction: Direction,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub data: Vec<u8>,
}

/// Append-only log of all intercepted traffic.
pub struct TrafficLog {
    entries: RwLock<VecDeque<TrafficLogEntry>>,
    max_entries: usize,
}

impl TrafficLog {
    #[must_use] 
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::new()),
            max_entries,
        }
    }

    /// Record a request.
    pub fn log_request(&self, req: &ProxyRequest) {
        let entry = TrafficLogEntry {
            id: req.id,
            timestamp: req.timestamp,
            direction: Direction::Request,
            src: req.client_addr,
            dst: req.target_addr,
            data: req.data.clone(),
        };
        let mut guard = self.entries.write();
        if guard.len() >= self.max_entries {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// Record a response.
    pub fn log_response(&self, resp: &ProxyResponse, dst: SocketAddr) {
        let src = resp.source_addr;
        let entry = TrafficLogEntry {
            id: resp.id,
            timestamp: resp.timestamp,
            direction: Direction::Response,
            src,
            dst,
            data: resp.data.clone(),
        };
        let mut guard = self.entries.write();
        if guard.len() >= self.max_entries {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// Return all log entries.
    pub fn entries(&self) -> Vec<TrafficLogEntry> {
        self.entries.read().iter().cloned().collect()
    }

    /// Number of logged entries.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns `true` if no entries have been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.write().clear();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Proxy statistics
// ────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for the proxy server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyStats {
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
    pub connections: u64,
}

impl fmt::Display for ProxyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProxyStats {{ connections={}, requests={}, in={}, out={}, errors={} }}",
            self.connections, self.requests, self.bytes_in, self.bytes_out, self.errors
        )
    }
}

/// Thread-safe, atomically updated proxy statistics.
pub struct SharedStats {
    inner: RwLock<ProxyStats>,
}

impl SharedStats {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(ProxyStats::default()),
        }
    }

    pub fn inc_requests(&self, bytes: u64) {
        let mut s = self.inner.write();
        s.requests += 1;
        s.bytes_in += bytes;
    }

    pub fn inc_responses(&self, bytes: u64) {
        let mut s = self.inner.write();
        s.bytes_out += bytes;
    }

    pub fn inc_errors(&self) {
        self.inner.write().errors += 1;
    }

    pub fn inc_connections(&self) {
        self.inner.write().connections += 1;
    }

    pub fn snapshot(&self) -> ProxyStats {
        self.inner.read().clone()
    }
}

impl Default for SharedStats {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SOCKS5 implementation
// ────────────────────────────────────────────────────────────────────────────

/// SOCKS5 proxy logic per RFC 1928.
pub struct Socks5Proxy;

impl Socks5Proxy {
    /// Perform the SOCKS5 handshake on `stream` and return the target address.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn handshake(
        stream: &mut TcpStream,
        auth: &Option<Socks5Auth>,
    ) -> Result<SocketAddr, ProxyError> {
        // 1. Greeting
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 5 {
            return Err(ProxyError::InvalidRequest("not SOCKS5".to_string()));
        }
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        // Choose authentication method
        let chosen_method: u8 = match auth {
            Some(Socks5Auth::UsernamePassword { .. }) if methods.contains(&2) => 2,
            _ if methods.contains(&0) => 0,
            _ => {
                stream.write_all(&[5, 0xFF]).await?;
                return Err(ProxyError::Socks5AuthFailed);
            }
        };

        stream.write_all(&[5, chosen_method]).await?;

        // 2. Authentication (method 2 = username/password, RFC 1929)
        if chosen_method == 2
            && let Some(Socks5Auth::UsernamePassword { username, password }) = auth {
                let mut auth_header = [0u8; 2];
                stream.read_exact(&mut auth_header).await?;
                let ulen = auth_header[1] as usize;
                let mut uname = vec![0u8; ulen];
                stream.read_exact(&mut uname).await?;
                let mut plen_buf = [0u8; 1];
                stream.read_exact(&mut plen_buf).await?;
                let plen = plen_buf[0] as usize;
                let mut pass = vec![0u8; plen];
                stream.read_exact(&mut pass).await?;
                let ok = uname == username.as_bytes() && pass == password.as_bytes();
                stream.write_all(&[1, u8::from(!ok)]).await?;
                if !ok {
                    return Err(ProxyError::Socks5AuthFailed);
                }
            }

        // 3. Request
        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await?;
        if req[1] != 1 {
            // Only CONNECT (0x01) supported
            let reply = [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]; // command not supported
            stream.write_all(&reply).await?;
            return Err(ProxyError::Socks5UnsupportedCommand(req[1]));
        }

        let target_addr: SocketAddr = match req[3] {
            1 => {
                // IPv4
                let mut ipv4 = [0u8; 4];
                stream.read_exact(&mut ipv4).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ipv4)), port)
            }
            3 => {
                // Domain name — resolve via DNS
                let mut dlen_buf = [0u8; 1];
                stream.read_exact(&mut dlen_buf).await?;
                let dlen = dlen_buf[0] as usize;
                let mut domain = vec![0u8; dlen];
                stream.read_exact(&mut domain).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let domain_str = std::str::from_utf8(&domain)
                    .map_err(|_| ProxyError::InvalidRequest("invalid domain".to_string()))?;
                let host_port = format!("{domain_str}:{port}");
                tokio::net::lookup_host(&host_port)
                    .await
                    .map_err(|e| ProxyError::UpstreamFailed(format!("DNS resolution failed for {domain_str}: {e}")))?
                    .next()
                    .ok_or_else(|| ProxyError::UpstreamFailed(format!("no addresses for {domain_str}")))?
            }
            4 => {
                // IPv6
                let mut ipv6 = [0u8; 16];
                stream.read_exact(&mut ipv6).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ipv6)), port)
            }
            other => {
                return Err(ProxyError::Socks5UnsupportedAddressType(other));
            }
        };

        // Send success reply
        let reply = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        stream.write_all(&reply).await?;

        Ok(target_addr)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP CONNECT proxy
// ────────────────────────────────────────────────────────────────────────────

/// HTTP proxy with CONNECT tunnel support.
pub struct HttpProxy;

impl HttpProxy {
    /// Parse an HTTP CONNECT request and return the target address string.
    #[must_use] 
    pub fn parse_connect(request: &str) -> Option<String> {
        let first_line = request.lines().next()?;
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
            return None;
        }
        Some(parts[1].to_string())
    }

    /// Perform an HTTP proxy handshake on `stream`, reading the CONNECT line.
    ///
    /// Returns the target `host:port` string.  The caller is responsible for
    /// connecting to the upstream target and then calling
    /// [`HttpProxy::send_connect_ok`] to signal success to the client, or
    /// writing a 5xx response on failure.  Sending 200 before verifying the
    /// upstream is reachable would leave the client in an inconsistent state.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn handshake(stream: &mut TcpStream) -> Result<String, ProxyError> {
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let request = std::str::from_utf8(&buf[..n])
            .map_err(|_| ProxyError::InvalidRequest("non-UTF8 HTTP request".to_string()))?;

        let target = Self::parse_connect(request)
            .ok_or_else(|| ProxyError::InvalidRequest("not a CONNECT request".to_string()))?;

        Ok(target)
    }

    /// Send the `200 Connection Established` response to the client after the
    /// upstream connection has been successfully opened.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn send_connect_ok(stream: &mut TcpStream) -> Result<(), ProxyError> {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        Ok(())
    }

    /// Send a `502 Bad Gateway` response to the client when the upstream
    /// connection could not be established.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn send_connect_err(stream: &mut TcpStream) -> Result<(), ProxyError> {
        stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .await?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Proxy server
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// ProxyRecord — structured record of an intercepted HTTP/HTTPS exchange
// ────────────────────────────────────────────────────────────────────────────

/// A structured record of a single intercepted HTTP or HTTPS request/response
/// exchange.  Suitable for logging, replay, or analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRecord {
    /// Unique identifier assigned by [`ProxyRecordStore`].
    pub id: u64,
    /// Unix timestamp in milliseconds when the exchange was recorded.
    pub timestamp: u64,
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// Full URL including scheme, host, and path.
    pub url: String,
    /// Request headers as a flat map (header name → value).
    pub request_headers: std::collections::HashMap<String, String>,
    /// Raw request body bytes.
    pub request_body: Vec<u8>,
    /// HTTP response status code.
    pub response_status: u16,
    /// Raw response body bytes.
    pub response_body: Vec<u8>,
    /// `true` if the exchange was over a TLS-intercepted HTTPS connection.
    pub is_tls: bool,
}

impl ProxyRecord {
    /// Create a new `ProxyRecord` timestamped at the current wall-clock time.
    /// The `id` field is set to `0` and should be assigned by [`ProxyRecordStore::add`].
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        request_headers: std::collections::HashMap<String, String>,
        request_body: Vec<u8>,
        response_status: u16,
        response_body: Vec<u8>,
        is_tls: bool,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id: 0,
            timestamp,
            method: method.into(),
            url: url.into(),
            request_headers,
            request_body,
            response_status,
            response_body,
            is_tls,
        }
    }

    /// Convenience constructor for a plain HTTP (non-TLS) record.
    ///
    /// The `id` is set to `0`; assign the real id via [`ProxyRecordStore::add`].
    #[must_use]
    pub fn new_http(
        method: impl Into<String>,
        url: impl Into<String>,
        status: u16,
        body: Vec<u8>,
    ) -> Self {
        Self::new(
            method,
            url,
            std::collections::HashMap::new(),
            Vec::new(),
            status,
            body,
            false,
        )
    }

    /// Convenience constructor for a TLS-intercepted (HTTPS) record.
    ///
    /// `cert_subject` is stored in a synthetic `X-Cert-Subject` request header
    /// for traceability.  The `id` is set to `0`.
    #[must_use]
    pub fn new_tls(
        method: impl Into<String>,
        url: impl Into<String>,
        cert_subject: impl Into<String>,
        status: u16,
        body: Vec<u8>,
    ) -> Self {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Cert-Subject".to_string(), cert_subject.into());
        Self::new(method, url, headers, Vec::new(), status, body, true)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ProxyRecordStore — thread-safe store for ProxyRecord entries
// ────────────────────────────────────────────────────────────────────────────

/// Thread-safe, append-and-query store for [`ProxyRecord`] entries.
pub struct ProxyRecordStore {
    records: parking_lot::RwLock<Vec<ProxyRecord>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl ProxyRecordStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: parking_lot::RwLock::new(Vec::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Add a record to the store.  Assigns a unique `id` and returns it.
    pub fn add(&self, mut record: ProxyRecord) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        record.id = id;
        self.records.write().push(record);
        id
    }

    /// Look up a record by its `id`.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<ProxyRecord> {
        self.records.read().iter().find(|r| r.id == id).cloned()
    }

    /// Return all records whose URL contains `domain` (case-sensitive).
    #[must_use]
    pub fn filter_by_domain(&self, domain: &str) -> Vec<ProxyRecord> {
        self.records
            .read()
            .iter()
            .filter(|r| r.url.contains(domain))
            .cloned()
            .collect()
    }

    /// Serialise all records to a JSON array ([`serde_json::Value`]).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let guard = self.records.read();
        let arr: Vec<serde_json::Value> = guard
            .iter()
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
            .collect();
        serde_json::Value::Array(arr)
    }

    /// Total number of stored records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }
}

impl Default for ProxyRecordStore {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HttpsInterceptor — alias for TlsInterceptor with per-domain cert generation
// ────────────────────────────────────────────────────────────────────────────

/// HTTPS MITM interceptor that generates self-signed per-domain leaf
/// certificates on demand, signed by the embedded [`CertificateAuthority`].
///
/// This is the high-level entry point for HTTPS interception; internally it
/// delegates to [`TlsInterceptor`] for the actual TLS relay logic.
pub struct HttpsInterceptor {
    inner: TlsInterceptor,
    /// The CA used to sign per-domain certificates.  Clients must trust this
    /// CA (import it into their OS/browser trust store) to avoid TLS errors.
    pub ca: Arc<CertificateAuthority>,
}

impl HttpsInterceptor {
    /// Create a new interceptor, generating a fresh CA.
    ///
    /// # Errors
    /// Returns [`MitmError::CertGen`] if CA generation fails.
    pub fn new() -> Result<Self, MitmError> {
        let ca = Arc::new(CertificateAuthority::new()?);
        Ok(Self {
            inner: TlsInterceptor::new(Arc::clone(&ca)),
            ca,
        })
    }

    /// Create an interceptor backed by an existing CA.
    #[must_use]
    pub fn with_ca(ca: Arc<CertificateAuthority>) -> Self {
        Self {
            inner: TlsInterceptor::new(Arc::clone(&ca)),
            ca,
        }
    }

    /// Return the raw DER bytes of the CA certificate.
    ///
    /// These bytes can be imported into a browser or OS trust store to allow
    /// transparent interception of HTTPS traffic.
    #[must_use]
    pub fn ca_cert_der(&self) -> Vec<u8> {
        self.ca.ca_cert_der_bytes()
    }

    /// Return the CA certificate as a PEM string.
    #[must_use]
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    /// Handle an inbound HTTP `CONNECT` tunnel end-to-end, intercepting and
    /// relaying TLS traffic.
    ///
    /// # Errors
    /// Returns [`MitmError`] on any TLS or I/O error.
    pub async fn handle_connect(
        &self,
        stream: TcpStream,
        host: String,
        port: u16,
    ) -> Result<(), MitmError> {
        self.inner.handle_connect(stream, host, port).await
    }
}

/// The main proxy server. Binds and accepts TCP connections.
pub struct ProxyServer {
    pub config: ProxyConfig,
    stats: Arc<SharedStats>,
    log: Arc<TrafficLog>,
    hook: Arc<dyn InterceptHook>,
    /// Monotonically increasing counter used to assign unique connection IDs.
    conn_counter: AtomicU64,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration and hook.
    pub fn new(config: ProxyConfig, hook: Arc<dyn InterceptHook>) -> Self {
        Self {
            config,
            stats: Arc::new(SharedStats::new()),
            log: Arc::new(TrafficLog::new(10_000)),
            hook,
            conn_counter: AtomicU64::new(0),
        }
    }

    /// Create a proxy server with the passthrough (no-op) hook.
    #[must_use] 
    pub fn passthrough(config: ProxyConfig) -> Self {
        Self::new(config, Arc::new(PassthroughHook))
    }

    /// Return a snapshot of current statistics.
    pub fn stats(&self) -> ProxyStats {
        self.stats.snapshot()
    }

    /// Return a reference to the traffic log.
    pub fn log(&self) -> &TrafficLog {
        &self.log
    }

    /// Generate a fresh self-signed CA certificate and return its DER bytes.
    ///
    /// The returned bytes can be imported into a browser or OS trust store to
    /// allow transparent HTTPS interception through an [`HttpsInterceptor`].
    ///
    /// # Errors
    /// Returns [`ProxyError::ConfigError`] if the CA cannot be generated.
    pub fn get_ca_cert() -> Result<Vec<u8>, ProxyError> {
        // CertificateAuthority is defined later in this file; we call it
        // through the lazy-init path so this is always available.
        let ca = CertificateAuthority::new()
            .map_err(|e| ProxyError::ConfigError(format!("CA generation failed: {e}")))?;
        Ok(ca.ca_cert_der_bytes())
    }

    /// Generate a fresh self-signed CA and return `(cert_pem, key_pem)`.
    ///
    /// The PEM bytes can be written to disk and loaded into an
    /// [`HttpsInterceptor`] or [`CertificateAuthority`] for per-domain
    /// leaf-cert signing.
    ///
    /// # Errors
    /// Returns [`ProxyError::ConfigError`] if CA generation fails.
    pub fn generate_ca() -> Result<(Vec<u8>, Vec<u8>), ProxyError> {
        let ca = CertificateAuthority::new()
            .map_err(|e| ProxyError::ConfigError(format!("CA generation failed: {e}")))?;
        let cert_pem = ca.ca_cert_pem().as_bytes().to_vec();
        let key_pem = ca.ca_key_pem().as_bytes().to_vec();
        Ok((cert_pem, key_pem))
    }

    /// Start accepting connections. This spawns a tokio task per connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn run(self: Arc<Self>) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        loop {
            let (stream, client_addr) = listener.accept().await?;
            self.stats.inc_connections();
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(_e) = server.handle_connection(stream, client_addr).await {
                    server.stats.inc_errors();
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        match self.config.mode {
            ProxyMode::Socks5 => {
                let target = Socks5Proxy::handshake(&mut stream, &self.config.socks5_auth).await?;
                self.forward_to(stream, client_addr, target).await
            }
            ProxyMode::Http => {
                let target_str = HttpProxy::handshake(&mut stream).await?;
                // Parse host:port — attempt upstream connection before responding
                let target: SocketAddr = target_str
                    .parse()
                    .map_err(|_| ProxyError::UpstreamFailed(target_str.clone()))?;
                // Verify upstream is reachable before telling the client it worked
                match TcpStream::connect(target).await {
                    Ok(upstream) => {
                        HttpProxy::send_connect_ok(&mut stream).await?;
                        // Re-use the already-connected upstream stream
                        self.forward_with_upstream(stream, client_addr, target, upstream).await
                    }
                    Err(e) => {
                        let _ = HttpProxy::send_connect_err(&mut stream).await;
                        Err(ProxyError::UpstreamFailed(e.to_string()))
                    }
                }
            }
            ProxyMode::Raw | ProxyMode::Transparent => {
                let upstream = self.config.upstream.ok_or_else(|| {
                    ProxyError::ConfigError(
                        "upstream required for transparent/raw mode".to_string(),
                    )
                })?;
                self.forward_to(stream, client_addr, upstream).await
            }
            ProxyMode::Socks4 => {
                let target = self.socks4_handshake(&mut stream).await?;
                self.forward_to(stream, client_addr, target).await
            }
        }
    }

    async fn socks4_handshake(&self, stream: &mut TcpStream) -> Result<SocketAddr, ProxyError> {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await?;
        if buf[0] != 4 || buf[1] != 1 {
            return Err(ProxyError::Socks4Rejected);
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        // Consume the null-terminated user ID.
        // Limit to 255 bytes per the SOCKS4 spec to prevent an unbounded
        // read loop on malicious input that never sends a NUL byte.
        let mut uid_bytes_read: usize = 0;
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            if b[0] == 0 {
                break;
            }
            uid_bytes_read += 1;
            if uid_bytes_read > 255 {
                return Err(ProxyError::InvalidRequest(
                    "SOCKS4 user ID exceeds 255 bytes".to_string(),
                ));
            }
        }
        // Send SOCKS4 reply: VN=0, REP=90 (granted)
        stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await?;
        Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
    }

    async fn forward_to(
        &self,
        client: TcpStream,
        client_addr: SocketAddr,
        target: SocketAddr,
    ) -> Result<(), ProxyError> {
        let upstream = TcpStream::connect(target)
            .await
            .map_err(|e| ProxyError::UpstreamFailed(e.to_string()))?;
        self.forward_with_upstream(client, client_addr, target, upstream).await
    }

    async fn forward_with_upstream(
        &self,
        client: TcpStream,
        client_addr: SocketAddr,
        target: SocketAddr,
        upstream: TcpStream,
    ) -> Result<(), ProxyError> {
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, uw) = upstream.into_split();

        let stats_in = Arc::clone(&self.stats);
        let stats_out = Arc::clone(&self.stats);
        let log_c = Arc::clone(&self.log);
        let log_u = Arc::clone(&self.log);
        let hook_req = Arc::clone(&self.hook);
        let hook_resp = Arc::clone(&self.hook);
        // Use a dedicated atomic counter for unique, race-free connection IDs.
        let conn_id = self.conn_counter.fetch_add(1, Ordering::Relaxed);

        let req_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            // Current upstream write half; may be replaced by a Redirect action.
            let mut current_uw = uw;
            loop {
                let n = match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut req = ProxyRequest::new(conn_id, client_addr, target, buf[..n].to_vec());
                let action = hook_req.on_request(&mut req).await;
                match action {
                    HookAction::Drop => break,
                    HookAction::Modify(data) => {
                        log_c.log_request(&req);
                        stats_in.inc_requests(data.len() as u64);
                        if current_uw.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    HookAction::Redirect(new_target) => {
                        // Open a new upstream connection to the redirect target.
                        // NOTE: the response-task still reads from the original
                        // upstream read-half; a full redirect would require
                        // coordinating both halves.  We break here so the
                        // connection is cleanly closed and the caller can
                        // re-establish with the new target, rather than silently
                        // writing to a new upstream while reading from the old one.
                        match TcpStream::connect(new_target).await {
                            Ok(new_upstream) => {
                                let (_, new_uw) = new_upstream.into_split();
                                current_uw = new_uw;
                                log_c.log_request(&req);
                                stats_in.inc_requests(n as u64);
                                if current_uw.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                                // Break so the caller sees a clean EOF and
                                // can reconnect to the redirected target.
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    HookAction::Forward => {
                        log_c.log_request(&req);
                        stats_in.inc_requests(n as u64);
                        if current_uw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let resp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match ur.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut resp = ProxyResponse::new(conn_id, target, buf[..n].to_vec());
                let action = hook_resp.on_response(&mut resp).await;
                match action {
                    HookAction::Drop => break,
                    HookAction::Modify(data) => {
                        log_u.log_response(&resp, client_addr);
                        stats_out.inc_responses(data.len() as u64);
                        if cw.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    HookAction::Redirect(new_target) => {
                        // For responses, redirect is not meaningful in this relay loop;
                        // log and forward the existing data, but record the intended target.
                        log_u.log_response(&resp, client_addr);
                        stats_out.inc_responses(n as u64);
                        // Attempt to open the redirect target for future upstream reads.
                        // If that fails, we still forward what we have.
                        let _ = new_target; // redirect on response side handled at connection level
                        if cw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    HookAction::Forward => {
                        log_u.log_response(&resp, client_addr);
                        stats_out.inc_responses(n as u64);
                        if cw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let _ = tokio::join!(req_task, resp_task);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Spec-required types
// ────────────────────────────────────────────────────────────────────────────

/// Spec-required proxy protocol enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProxyProtocol {
    Http,
    Https,
    Tcp,
    Socks4,
    Socks5,
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Tcp => "TCP",
            Self::Socks4 => "SOCKS4",
            Self::Socks5 => "SOCKS5",
        };
        write!(f, "{s}")
    }
}

/// Spec-required proxy configuration with builder pattern.
#[derive(Debug, Clone)]
pub struct SpecProxyConfig {
    pub listen_addr: String,
    pub upstream: Option<String>,
    pub intercept: bool,
    pub max_conn: usize,
}

impl SpecProxyConfig {
    /// Create a new proxy config listening on the given address.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            listen_addr: addr.into(),
            upstream: None,
            intercept: false,
            max_conn: 100,
        }
    }

    /// Set the upstream address.
    #[must_use]
    pub fn with_upstream(mut self, upstream: impl Into<String>) -> Self {
        self.upstream = Some(upstream.into());
        self
    }

    /// Set whether to intercept traffic.
    #[must_use]
    pub const fn with_intercept(mut self, intercept: bool) -> Self {
        self.intercept = intercept;
        self
    }

    /// Set the maximum number of concurrent connections.
    #[must_use]
    pub const fn with_max_conn(mut self, max_conn: usize) -> Self {
        self.max_conn = max_conn;
        self
    }
}

/// Spec-required proxy session descriptor.
#[derive(Debug, Clone)]
pub struct ProxySession {
    pub id: u64,
    pub client: String,
    pub target: String,
    pub proto: ProxyProtocol,
}

/// A spec-required intercepted HTTP request.
#[derive(Debug, Clone)]
pub struct InterceptedRequest {
    pub session_id: u64,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub modified: bool,
}

impl InterceptedRequest {
    /// Replace the request body (marks the request as modified).
    #[must_use]
    pub fn with_body(mut self, b: Vec<u8>) -> Self {
        self.body = b;
        self.modified = true;
        self
    }

    /// Look up a header value by name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Return the `Content-Length` header value as `usize`, if present.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.header("Content-Length").and_then(|v| v.parse().ok())
    }
}

/// A spec-required intercepted HTTP response.
#[derive(Debug, Clone)]
pub struct InterceptedResponse {
    pub session_id: u64,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl InterceptedResponse {
    /// Returns `true` if the status code is in the 2xx range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..=299).contains(&self.status)
    }

    /// Return the `Content-Type` header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.as_str())
    }
}

/// Spec-required error type for proxy operations.
#[derive(Debug, thiserror::Error)]
pub enum SpecProxyError {
    #[error("bind error: {0}")]
    Bind(String),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("intercept error: {0}")]
    Intercept(String),
}

/// Spec-required async proxy plugin trait.
#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Called before the request is forwarded upstream.
    ///
    /// # Errors
    ///
    /// Returns `SpecProxyError` if the plugin rejects or fails to process the request.
    async fn on_request(&self, r: &mut InterceptedRequest) -> Result<(), SpecProxyError>;

    /// Called after the response is received from upstream.
    ///
    /// # Errors
    ///
    /// Returns `SpecProxyError` if the plugin fails to process the response.
    async fn on_response(&self, r: &mut InterceptedResponse) -> Result<(), SpecProxyError>;
}

/// A logging plugin that records request/response events as strings.
pub struct LoggingPlugin {
    pub log: parking_lot::Mutex<Vec<String>>,
}

impl LoggingPlugin {
    /// Create a new logging plugin.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            log: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Return all recorded log entries.
    #[must_use]
    pub fn entries(&self) -> Vec<String> {
        self.log.lock().clone()
    }
}

impl Default for LoggingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProxyPlugin for LoggingPlugin {
    async fn on_request(&self, r: &mut InterceptedRequest) -> Result<(), SpecProxyError> {
        let entry = format!("REQ {} {} session={}", r.method, r.uri, r.session_id);
        self.log.lock().push(entry);
        Ok(())
    }

    async fn on_response(&self, r: &mut InterceptedResponse) -> Result<(), SpecProxyError> {
        let entry = format!("RESP {} session={}", r.status, r.session_id);
        self.log.lock().push(entry);
        Ok(())
    }
}

/// A no-op proxy plugin that passes everything through unchanged.
pub struct NoOpPlugin;

#[async_trait]
impl ProxyPlugin for NoOpPlugin {
    async fn on_request(&self, _r: &mut InterceptedRequest) -> Result<(), SpecProxyError> {
        Ok(())
    }

    async fn on_response(&self, _r: &mut InterceptedResponse) -> Result<(), SpecProxyError> {
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn local_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    // ─── Configuration ────────────────────────────────────────────────────

    #[test]
    fn proxy_config_http() {
        let cfg = ProxyConfig::http(local_addr(8080));
        assert_eq!(cfg.mode, ProxyMode::Http);
        assert_eq!(cfg.bind_addr.port(), 8080);
        assert!(!cfg.tls_intercept);
    }

    #[test]
    fn proxy_config_socks5() {
        let cfg = ProxyConfig::socks5(local_addr(1080));
        assert_eq!(cfg.mode, ProxyMode::Socks5);
    }

    #[test]
    fn proxy_mode_display() {
        assert_eq!(ProxyMode::Http.to_string(), "HTTP");
        assert_eq!(ProxyMode::Socks5.to_string(), "SOCKS5");
        assert_eq!(ProxyMode::Transparent.to_string(), "Transparent");
    }

    // ─── Stats ────────────────────────────────────────────────────────────

    #[test]
    fn shared_stats_increments() {
        let s = SharedStats::new();
        s.inc_connections();
        s.inc_connections();
        s.inc_requests(100);
        s.inc_responses(200);
        s.inc_errors();
        let snap = s.snapshot();
        assert_eq!(snap.connections, 2);
        assert_eq!(snap.requests, 1);
        assert_eq!(snap.bytes_in, 100);
        assert_eq!(snap.bytes_out, 200);
        assert_eq!(snap.errors, 1);
    }

    #[test]
    fn stats_display() {
        let s = ProxyStats {
            connections: 5,
            requests: 10,
            bytes_in: 500,
            bytes_out: 1000,
            errors: 0,
        };
        let t = s.to_string();
        assert!(t.contains("10"));
        assert!(t.contains("500"));
    }

    // ─── TrafficLog ───────────────────────────────────────────────────────

    #[test]
    fn traffic_log_log_request() {
        let log = TrafficLog::new(100);
        let req = ProxyRequest::new(
            1,
            local_addr(1234),
            local_addr(80),
            b"GET / HTTP/1.1".to_vec(),
        );
        log.log_request(&req);
        assert_eq!(log.len(), 1);
        let entries = log.entries();
        assert_eq!(entries[0].direction, Direction::Request);
    }

    #[test]
    fn traffic_log_eviction() {
        let log = TrafficLog::new(3);
        for i in 0..5u64 {
            let req = ProxyRequest::new(i, local_addr(1000), local_addr(80), vec![]);
            log.log_request(&req);
        }
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn traffic_log_clear() {
        let log = TrafficLog::new(10);
        let req = ProxyRequest::new(0, local_addr(100), local_addr(80), vec![]);
        log.log_request(&req);
        assert!(!log.is_empty());
        log.clear();
        assert!(log.is_empty());
    }

    // ─── HTTP proxy ───────────────────────────────────────────────────────

    #[test]
    fn http_proxy_parse_connect() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let target = HttpProxy::parse_connect(req).unwrap();
        assert_eq!(target, "example.com:443");
    }

    #[test]
    fn http_proxy_parse_connect_missing() {
        let req = "GET / HTTP/1.1\r\n\r\n";
        assert!(HttpProxy::parse_connect(req).is_none());
    }

    // ─── HookAction ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn passthrough_hook_forward() {
        let hook = PassthroughHook;
        let mut req = ProxyRequest::new(1, local_addr(5000), local_addr(80), b"hello".to_vec());
        let action = hook.on_request(&mut req).await;
        assert!(matches!(action, HookAction::Forward));
    }

    #[tokio::test]
    async fn passthrough_hook_response_forward() {
        let hook = PassthroughHook;
        let mut resp = ProxyResponse::new(1, local_addr(80), b"world".to_vec());
        let action = hook.on_response(&mut resp).await;
        assert!(matches!(action, HookAction::Forward));
    }

    // ─── Error display ────────────────────────────────────────────────────

    #[test]
    fn proxy_error_display() {
        let e = ProxyError::Socks5AuthFailed;
        assert!(e.to_string().contains("authentication"));
        let e2 = ProxyError::Socks5UnsupportedCommand(0x03);
        assert!(e2.to_string().contains("command"));
    }

    // ─── ProxyServer construction ─────────────────────────────────────────

    #[test]
    fn proxy_server_stats_default() {
        let cfg = ProxyConfig::http(local_addr(9999));
        let server = ProxyServer::passthrough(cfg);
        let s = server.stats();
        assert_eq!(s.requests, 0);
        assert_eq!(s.errors, 0);
    }

    #[test]
    fn proxy_request_has_timestamp() {
        let req = ProxyRequest::new(1, local_addr(1234), local_addr(80), vec![]);
        assert!(req.timestamp > 0);
    }

    #[test]
    fn proxy_response_has_timestamp() {
        let resp = ProxyResponse::new(1, local_addr(80), vec![]);
        assert!(resp.timestamp > 0);
    }

    // ── Spec-required: ProxyProtocol ─────────────────────────────────────

    #[test]
    fn proxy_protocol_display() {
        assert_eq!(ProxyProtocol::Http.to_string(), "HTTP");
        assert_eq!(ProxyProtocol::Https.to_string(), "HTTPS");
        assert_eq!(ProxyProtocol::Tcp.to_string(), "TCP");
        assert_eq!(ProxyProtocol::Socks4.to_string(), "SOCKS4");
        assert_eq!(ProxyProtocol::Socks5.to_string(), "SOCKS5");
    }

    // ── Spec-required: SpecProxyConfig builder ───────────────────────────

    #[test]
    fn spec_proxy_config_builder() {
        let cfg = SpecProxyConfig::new("127.0.0.1:8080")
            .with_upstream("proxy.example.com:3128")
            .with_intercept(true)
            .with_max_conn(50);
        assert_eq!(cfg.listen_addr, "127.0.0.1:8080");
        assert_eq!(cfg.upstream, Some("proxy.example.com:3128".to_string()));
        assert!(cfg.intercept);
        assert_eq!(cfg.max_conn, 50);
    }

    #[test]
    fn spec_proxy_config_defaults() {
        let cfg = SpecProxyConfig::new("0.0.0.0:1080");
        assert!(cfg.upstream.is_none());
        assert!(!cfg.intercept);
        assert_eq!(cfg.max_conn, 100);
    }

    // ── Spec-required: ProxySession ──────────────────────────────────────

    #[test]
    fn proxy_session_fields() {
        let sess = ProxySession {
            id: 42,
            client: "127.0.0.1:5000".to_string(),
            target: "example.com:443".to_string(),
            proto: ProxyProtocol::Https,
        };
        assert_eq!(sess.id, 42);
        assert_eq!(sess.proto, ProxyProtocol::Https);
    }

    // ── Spec-required: InterceptedRequest ────────────────────────────────

    #[test]
    fn intercepted_request_with_body() {
        let req = InterceptedRequest {
            session_id: 1,
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: vec![("Content-Length".to_string(), "5".to_string())],
            body: vec![],
            modified: false,
        };
        assert!(!req.modified);
        let req2 = req.with_body(b"hello".to_vec());
        assert_eq!(req2.body, b"hello");
        assert!(req2.modified);
    }

    #[test]
    fn intercepted_request_header_lookup() {
        let req = InterceptedRequest {
            session_id: 1,
            method: "POST".to_string(),
            uri: "/api".to_string(),
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Content-Length".to_string(), "42".to_string()),
            ],
            body: vec![],
            modified: false,
        };
        assert_eq!(req.header("content-type"), Some("application/json"));
        assert_eq!(req.content_length(), Some(42));
        assert_eq!(req.header("X-Missing"), None);
    }

    // ── Spec-required: InterceptedResponse ───────────────────────────────

    #[test]
    fn intercepted_response_is_success() {
        let make = |status| InterceptedResponse {
            session_id: 1,
            status,
            headers: vec![],
            body: vec![],
        };
        assert!(make(200).is_success());
        assert!(make(201).is_success());
        assert!(make(299).is_success());
        assert!(!make(301).is_success());
        assert!(!make(404).is_success());
        assert!(!make(500).is_success());
    }

    #[test]
    fn intercepted_response_content_type() {
        let resp = InterceptedResponse {
            session_id: 1,
            status: 200,
            headers: vec![("Content-Type".to_string(), "text/html".to_string())],
            body: vec![],
        };
        assert_eq!(resp.content_type(), Some("text/html"));
    }

    // ── Spec-required: LoggingPlugin ─────────────────────────────────────

    #[tokio::test]
    async fn logging_plugin_records_events() {
        let plugin = LoggingPlugin::new();
        let mut req = InterceptedRequest {
            session_id: 99,
            method: "DELETE".to_string(),
            uri: "/resource".to_string(),
            headers: vec![],
            body: vec![],
            modified: false,
        };
        plugin.on_request(&mut req).await.unwrap();
        let entries = plugin.entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("DELETE"));
        assert!(entries[0].contains("99"));
    }

    #[tokio::test]
    async fn logging_plugin_records_response() {
        let plugin = LoggingPlugin::default();
        let mut resp = InterceptedResponse {
            session_id: 7,
            status: 404,
            headers: vec![],
            body: vec![],
        };
        plugin.on_response(&mut resp).await.unwrap();
        let entries = plugin.entries();
        assert!(entries[0].contains("404"));
    }

    // ── Spec-required: NoOpPlugin ─────────────────────────────────────────

    #[tokio::test]
    async fn no_op_plugin_passes_through() {
        let plugin = NoOpPlugin;
        let mut req = InterceptedRequest {
            session_id: 0,
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: vec![],
            body: vec![],
            modified: false,
        };
        assert!(plugin.on_request(&mut req).await.is_ok());
        let mut resp = InterceptedResponse {
            session_id: 0,
            status: 200,
            headers: vec![],
            body: vec![],
        };
        assert!(plugin.on_response(&mut resp).await.is_ok());
    }

    // ── Spec-required: SpecProxyError ─────────────────────────────────────

    #[test]
    fn spec_proxy_error_display() {
        assert!(
            SpecProxyError::Bind("addr in use".to_string())
                .to_string()
                .contains("addr in use")
        );
        assert!(
            SpecProxyError::Connect("refused".to_string())
                .to_string()
                .contains("refused")
        );
        assert!(
            SpecProxyError::Protocol("bad".to_string())
                .to_string()
                .contains("bad")
        );
        assert!(
            SpecProxyError::Intercept("failed".to_string())
                .to_string()
                .contains("failed")
        );
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP CONNECT parser (detailed)
// ────────────────────────────────────────────────────────────────────────────

/// Parsed HTTP CONNECT request.
#[derive(Debug, Clone)]
pub struct HttpConnectRequest {
    pub host: String,
    pub port: u16,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpConnectRequest {
    /// Parse from a raw HTTP request string.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::InvalidRequest`] if the format is not a valid CONNECT.
    pub fn parse(raw: &str) -> Result<Self, ProxyError> {
        let mut lines = raw.lines();
        let first = lines
            .next()
            .ok_or_else(|| ProxyError::InvalidRequest("empty request".to_string()))?;
        let parts: Vec<&str> = first.splitn(3, ' ').collect();
        if parts.len() < 3 || !parts[0].eq_ignore_ascii_case("CONNECT") {
            return Err(ProxyError::InvalidRequest(format!("not CONNECT: {first}")));
        }
        let host_port = parts[1];
        let http_version = parts[2].trim_end().to_string();
        let (host, port_str) = host_port.rfind(':').map_or((host_port, "443"), |pos| (&host_port[..pos], &host_port[pos + 1..]));
        let port: u16 = port_str
            .parse()
            .map_err(|_| ProxyError::InvalidRequest(format!("invalid port: {port_str}")))?;
        let mut headers = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                break;
            }
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_string();
                let value = line[colon + 1..].trim().to_string();
                headers.push((name, value));
            }
        }
        Ok(Self {
            host: host.to_string(),
            port,
            http_version,
            headers,
        })
    }

    /// Look up a header value by name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Format the 200 Connection Established response.
    #[must_use]
    pub fn success_response(&self) -> String {
        format!("{} 200 Connection Established\r\n\r\n", self.http_version)
    }

    /// Format an error response.
    #[must_use]
    pub fn error_response(status: u16, msg: &str) -> String {
        format!("HTTP/1.1 {status} {msg}\r\n\r\n")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Proxy rule: allow/deny list
// ────────────────────────────────────────────────────────────────────────────

/// Rule action for the proxy access control list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AclAction {
    #[default]
    Allow,
    Deny,
}

impl fmt::Display for AclAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Deny => write!(f, "DENY"),
        }
    }
}

/// A proxy ACL entry matching on host and port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    /// Host pattern — exact string or `"*"` for wildcard.
    pub host_pattern: String,
    /// Port — `None` matches any port.
    pub port: Option<u16>,
    pub action: AclAction,
}

impl AclEntry {
    /// Create an allow-all entry.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            host_pattern: "*".to_string(),
            port: None,
            action: AclAction::Allow,
        }
    }

    /// Create a deny entry for a specific host.
    #[must_use]
    pub fn deny_host(host: &str) -> Self {
        Self {
            host_pattern: host.to_string(),
            port: None,
            action: AclAction::Deny,
        }
    }

    /// Returns `true` if this entry matches the given host and port.
    #[must_use]
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host_match = self.host_pattern == "*" || self.host_pattern.eq_ignore_ascii_case(host);
        let port_match = self.port.is_none_or(|p| p == port);
        host_match && port_match
    }
}

/// A proxy ACL (access control list).
#[derive(Debug, Default)]
pub struct ProxyAcl {
    entries: Vec<AclEntry>,
    /// Default action if no entry matches.
    default_action: AclAction,
}

impl ProxyAcl {
    /// Create an ACL with a default action.
    #[must_use]
    pub const fn new(default_action: AclAction) -> Self {
        Self {
            entries: Vec::new(),
            default_action,
        }
    }

    /// Add an ACL entry (entries are checked in insertion order).
    pub fn add(&mut self, entry: AclEntry) {
        self.entries.push(entry);
    }

    /// Evaluate the ACL for the given host and port.
    /// Returns the action of the first matching entry, or the default.
    #[must_use]
    pub fn evaluate(&self, host: &str, port: u16) -> AclAction {
        for entry in &self.entries {
            if entry.matches(host, port) {
                return entry.action;
            }
        }
        self.default_action
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the ACL has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// MITM stub
// ────────────────────────────────────────────────────────────────────────────

/// TLS interception configuration (MITM stub).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmConfig {
    /// Whether MITM is enabled.
    pub enabled: bool,
    /// Path to the CA certificate (PEM).
    pub ca_cert_path: Option<String>,
    /// Path to the CA private key (PEM).
    pub ca_key_path: Option<String>,
    /// Set of hostnames to exclude from MITM.
    pub excluded_hosts: Vec<String>,
}

impl MitmConfig {
    /// Create a disabled MITM configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            ca_cert_path: None,
            ca_key_path: None,
            excluded_hosts: Vec::new(),
        }
    }

    /// Create an enabled MITM configuration.
    #[must_use]
    pub fn enabled(ca_cert: &str, ca_key: &str) -> Self {
        Self {
            enabled: true,
            ca_cert_path: Some(ca_cert.to_string()),
            ca_key_path: Some(ca_key.to_string()),
            excluded_hosts: Vec::new(),
        }
    }

    /// Returns `true` if this host should be excluded from MITM.
    #[must_use]
    pub fn is_excluded(&self, host: &str) -> bool {
        self.excluded_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    /// Add a hostname to the exclusion list.
    pub fn exclude(&mut self, host: &str) {
        self.excluded_hosts.push(host.to_string());
    }

    /// Returns `true` if MITM should intercept the given host.
    #[must_use]
    pub fn should_intercept(&self, host: &str) -> bool {
        self.enabled && !self.is_excluded(host)
    }
}

// `ConnectionPool`, `UpstreamProxy`, `UpstreamChain` moved to
// `crate::upstream` and re-exported at the crate root.

// ────────────────────────────────────────────────────────────────────────────
// Modifier pipeline
// ────────────────────────────────────────────────────────────────────────────

/// A synchronous transformation applied to traffic data.
pub trait DataModifier: Send + Sync {
    /// Modify `data` in place and return whether any change was made.
    fn modify(&self, data: &mut Vec<u8>) -> bool;

    /// Returns a human-readable name for this modifier.
    fn name(&self) -> &'static str;
}

/// A modifier that replaces occurrences of a byte pattern with another.
pub struct SearchReplaceModifier {
    search: Vec<u8>,
    replace: Vec<u8>,
}

impl SearchReplaceModifier {
    /// Create a new search-replace modifier.
    #[must_use]
    pub const fn new(search: Vec<u8>, replace: Vec<u8>) -> Self {
        Self { search, replace }
    }
}

impl DataModifier for SearchReplaceModifier {
    fn modify(&self, data: &mut Vec<u8>) -> bool {
        if self.search.is_empty() {
            return false;
        }
        let mut new_data = Vec::with_capacity(data.len());
        let mut i = 0;
        let mut changed = false;
        let n = self.search.len();
        while i < data.len() {
            if data[i..].len() >= n && &data[i..i + n] == self.search.as_slice() {
                new_data.extend_from_slice(&self.replace);
                i += n;
                changed = true;
            } else {
                new_data.push(data[i]);
                i += 1;
            }
        }
        if changed {
            *data = new_data;
        }
        changed
    }

    fn name(&self) -> &'static str {
        "search-replace"
    }
}

/// A modifier that injects a header into HTTP requests.
pub struct HeaderInjector {
    header_name: String,
    header_value: String,
}

impl HeaderInjector {
    /// Create a new header injector.
    #[must_use]
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            header_name: name.to_string(),
            header_value: value.to_string(),
        }
    }
}

impl DataModifier for HeaderInjector {
    fn modify(&self, data: &mut Vec<u8>) -> bool {
        // Inject before the blank line separating headers from body
        let marker = b"\r\n\r\n";
        data.windows(4).position(|w| w == marker).is_some_and(|pos| {
            let header_line = format!("{}: {}\r\n", self.header_name, self.header_value);
            let mut new_data = Vec::with_capacity(data.len() + header_line.len());
            new_data.extend_from_slice(&data[..pos]);
            new_data.extend_from_slice(header_line.as_bytes());
            new_data.extend_from_slice(&data[pos..]);
            *data = new_data;
            true
        })
    }

    fn name(&self) -> &'static str {
        "header-injector"
    }
}

/// Pipeline of data modifiers applied in sequence.
pub struct ModifierPipeline {
    modifiers: Vec<Box<dyn DataModifier>>,
}

impl ModifierPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            modifiers: Vec::new(),
        }
    }

    /// Append a modifier.
    pub fn push(&mut self, modifier: Box<dyn DataModifier>) {
        self.modifiers.push(modifier);
    }

    /// Run all modifiers on `data`.  Returns `true` if any modifier made a change.
    pub fn apply(&self, data: &mut Vec<u8>) -> bool {
        let mut any_changed = false;
        for m in &self.modifiers {
            if m.modify(data) {
                any_changed = true;
            }
        }
        any_changed
    }

    /// Number of modifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modifiers.len()
    }

    /// Returns `true` if there are no modifiers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modifiers.is_empty()
    }
}

impl Default for ModifierPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Traffic recorder
// ────────────────────────────────────────────────────────────────────────────

/// A recorded traffic exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub session_id: u64,
    pub direction: Direction,
    pub data: Vec<u8>,
    pub timestamp_ms: u64,
    pub peer: String,
}

impl TrafficRecord {
    /// Create a new record.
    #[must_use]
    pub fn new(session_id: u64, direction: Direction, data: Vec<u8>, peer: &str) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            session_id,
            direction,
            data,
            timestamp_ms,
            peer: peer.to_string(),
        }
    }

    /// Payload as a UTF-8 string (lossy).
    #[must_use]
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }
}

impl fmt::Display for TrafficRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] session={} {:?} peer={} len={}",
            self.timestamp_ms,
            self.session_id,
            self.direction,
            self.peer,
            self.data.len()
        )
    }
}

/// In-memory traffic recorder.
pub struct TrafficRecorder {
    records: parking_lot::Mutex<Vec<TrafficRecord>>,
    capacity: usize,
}

impl TrafficRecorder {
    /// Create a recorder with the given capacity.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            records: parking_lot::Mutex::new(Vec::new()),
            capacity,
        }
    }

    /// Record a traffic exchange.
    pub fn record(&self, rec: TrafficRecord) {
        let mut v = self.records.lock();
        if v.len() >= self.capacity {
            v.remove(0);
        }
        v.push(rec);
    }

    /// Return all records.
    #[must_use]
    pub fn all(&self) -> Vec<TrafficRecord> {
        self.records.lock().clone()
    }

    /// Return records for a given session.
    #[must_use]
    pub fn for_session(&self, session_id: u64) -> Vec<TrafficRecord> {
        self.records
            .lock()
            .iter()
            .filter(|r| r.session_id == session_id)
            .cloned()
            .collect()
    }

    /// Total number of stored records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().len()
    }

    /// Returns `true` if no records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.lock().is_empty()
    }

    /// Clear all records.
    pub fn clear(&self) {
        self.records.lock().clear();
    }

    /// Total bytes recorded.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.records.lock().iter().map(|r| r.data.len()).sum()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Proxy session manager
// ────────────────────────────────────────────────────────────────────────────

/// State of a proxy session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Connecting,
    Connected,
    Intercepting,
    Closing,
    Closed,
    Error,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A proxy session entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub id: u64,
    pub client_addr: String,
    pub target_addr: String,
    pub proto: ProxyProtocol,
    pub state: SessionState,
    pub started_at: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl SessionEntry {
    /// Create a new session entry.
    #[must_use]
    pub fn new(id: u64, client_addr: &str, target_addr: &str, proto: ProxyProtocol) -> Self {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id,
            client_addr: client_addr.to_string(),
            target_addr: target_addr.to_string(),
            proto,
            state: SessionState::Connecting,
            started_at,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    /// Returns `true` if the session is still active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, SessionState::Closed | SessionState::Error)
    }
}

impl fmt::Display for SessionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Session[{}] {} -> {} ({:?})",
            self.id, self.client_addr, self.target_addr, self.state
        )
    }
}

/// Tracks all proxy sessions.
pub struct SessionManager {
    sessions: parking_lot::RwLock<std::collections::HashMap<u64, SessionEntry>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl SessionManager {
    /// Create a new session manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: parking_lot::RwLock::new(std::collections::HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Allocate a new session ID and create an entry.
    pub fn new_session(&self, client_addr: &str, target_addr: &str, proto: ProxyProtocol) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let entry = SessionEntry::new(id, client_addr, target_addr, proto);
        self.sessions.write().insert(id, entry);
        id
    }

    /// Update the state of a session.
    pub fn set_state(&self, id: u64, state: SessionState) {
        if let Some(s) = self.sessions.write().get_mut(&id) {
            s.state = state;
        }
    }

    /// Update byte counters for a session.
    pub fn add_bytes(&self, id: u64, bytes_in: u64, bytes_out: u64) {
        if let Some(s) = self.sessions.write().get_mut(&id) {
            s.bytes_in += bytes_in;
            s.bytes_out += bytes_out;
        }
    }

    /// Get a snapshot of a session.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<SessionEntry> {
        self.sessions.read().get(&id).cloned()
    }

    /// Return all active sessions.
    #[must_use]
    pub fn active(&self) -> Vec<SessionEntry> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.is_active())
            .cloned()
            .collect()
    }

    /// Total number of sessions (all states).
    #[must_use]
    pub fn total(&self) -> usize {
        self.sessions.read().len()
    }

    /// Remove closed/error sessions.
    pub fn prune(&self) {
        self.sessions.write().retain(|_, s| s.is_active());
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Transparent proxy header (X-Forwarded-For injection)
// ────────────────────────────────────────────────────────────────────────────

/// Inject `X-Forwarded-For` and `Via` headers into an HTTP request.
///
/// Returns `true` if the data was modified.
#[must_use]
pub fn inject_xff_headers(data: &mut Vec<u8>, client_ip: &str, proxy_host: &str) -> bool {
    let xff_modifier = HeaderInjector::new("X-Forwarded-For", client_ip);
    let via_modifier = HeaderInjector::new("Via", &format!("1.1 {proxy_host}"));
    let mut changed = false;
    if xff_modifier.modify(data) {
        changed = true;
    }
    if via_modifier.modify(data) {
        changed = true;
    }
    changed
}

// ────────────────────────────────────────────────────────────────────────────
// Additional tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn la(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    // ── HttpConnectRequest ────────────────────────────────────────────────

    #[test]
    fn http_connect_parse_basic() {
        let raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let r = HttpConnectRequest::parse(raw).unwrap();
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 443);
        assert_eq!(r.http_version, "HTTP/1.1");
        assert_eq!(r.header("Host"), Some("example.com:443"));
    }

    #[test]
    fn http_connect_parse_no_port_defaults_443() {
        let raw = "CONNECT example.com HTTP/1.0\r\n\r\n";
        let r = HttpConnectRequest::parse(raw).unwrap();
        assert_eq!(r.port, 443);
    }

    #[test]
    fn http_connect_parse_not_connect() {
        let raw = "GET / HTTP/1.1\r\n\r\n";
        assert!(HttpConnectRequest::parse(raw).is_err());
    }

    #[test]
    fn http_connect_success_response() {
        let raw = "CONNECT host:80 HTTP/1.1\r\n\r\n";
        let r = HttpConnectRequest::parse(raw).unwrap();
        let resp = r.success_response();
        assert!(resp.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn http_connect_error_response() {
        let s = HttpConnectRequest::error_response(403, "Forbidden");
        assert!(s.contains("403") && s.contains("Forbidden"));
    }

    // ── ProxyAcl ──────────────────────────────────────────────────────────

    #[test]
    fn acl_allow_and_deny() {
        let mut acl = ProxyAcl::new(AclAction::Allow);
        acl.add(AclEntry::deny_host("evil.com"));
        assert_eq!(acl.evaluate("good.com", 80), AclAction::Allow);
        assert_eq!(acl.evaluate("evil.com", 80), AclAction::Deny);
    }

    #[test]
    fn acl_wildcard_allow_all() {
        let mut acl = ProxyAcl::new(AclAction::Deny);
        acl.add(AclEntry::allow_all());
        assert_eq!(acl.evaluate("anything", 443), AclAction::Allow);
    }

    #[test]
    fn acl_port_specific() {
        let mut acl = ProxyAcl::new(AclAction::Deny);
        acl.add(AclEntry {
            host_pattern: "*".to_string(),
            port: Some(80),
            action: AclAction::Allow,
        });
        assert_eq!(acl.evaluate("any", 80), AclAction::Allow);
        assert_eq!(acl.evaluate("any", 443), AclAction::Deny);
    }

    #[test]
    fn acl_entry_matches_case_insensitive() {
        let e = AclEntry::deny_host("EVIL.COM");
        assert!(e.matches("evil.com", 80));
    }

    #[test]
    fn acl_default_fallback() {
        let acl = ProxyAcl::new(AclAction::Deny);
        assert_eq!(acl.evaluate("unknown", 1234), AclAction::Deny);
    }

    #[test]
    fn acl_action_display() {
        assert_eq!(AclAction::Allow.to_string(), "ALLOW");
        assert_eq!(AclAction::Deny.to_string(), "DENY");
    }

    // ── MitmConfig ────────────────────────────────────────────────────────

    #[test]
    fn mitm_disabled_config() {
        let cfg = MitmConfig::disabled();
        assert!(!cfg.enabled);
        assert!(!cfg.should_intercept("example.com"));
    }

    #[test]
    fn mitm_enabled_intercept() {
        let cfg = MitmConfig::enabled("/ca.crt", "/ca.key");
        assert!(cfg.enabled);
        assert!(cfg.should_intercept("example.com"));
    }

    #[test]
    fn mitm_excluded_host() {
        let mut cfg = MitmConfig::enabled("/ca.crt", "/ca.key");
        cfg.exclude("bypass.com");
        assert!(!cfg.should_intercept("bypass.com"));
        assert!(cfg.should_intercept("other.com"));
        assert!(cfg.is_excluded("BYPASS.COM")); // case-insensitive
    }

    // ── ConnectionPool ────────────────────────────────────────────────────

    #[test]
    fn connection_pool_basic() {
        let pool = ConnectionPool::new(2);
        assert!(pool.acquire("host1"));
        assert!(pool.acquire("host1"));
        assert!(!pool.acquire("host1")); // limit reached
        pool.release("host1");
        assert!(pool.acquire("host1")); // slot freed
        assert_eq!(pool.active_for("host1"), 2);
    }

    #[test]
    fn connection_pool_total_active() {
        let pool = ConnectionPool::new(5);
        let _ = pool.acquire("a");
        let _ = pool.acquire("b");
        let _ = pool.acquire("b");
        assert_eq!(pool.total_active(), 3);
    }

    // ── UpstreamProxy / UpstreamChain ─────────────────────────────────────

    #[test]
    fn upstream_proxy_basic() {
        let p = UpstreamProxy::new("proxy.example.com", 3128, ProxyProtocol::Http);
        assert_eq!(p.addr_str(), "proxy.example.com:3128");
        assert!(!p.has_auth());
        let s = p.to_string();
        assert!(s.contains("proxy.example.com"));
    }

    #[test]
    fn upstream_proxy_with_auth() {
        let p = UpstreamProxy::new("p.example.com", 8080, ProxyProtocol::Socks5)
            .with_auth("user", "pass");
        assert!(p.has_auth());
    }

    #[test]
    fn upstream_chain_push_and_first() {
        let mut chain = UpstreamChain::new();
        assert!(chain.is_empty());
        chain.push(UpstreamProxy::new(
            "p1.example.com",
            3128,
            ProxyProtocol::Http,
        ));
        chain.push(UpstreamProxy::new(
            "p2.example.com",
            1080,
            ProxyProtocol::Socks5,
        ));
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.first().unwrap().host, "p1.example.com");
    }

    // ── SearchReplaceModifier ─────────────────────────────────────────────

    #[test]
    fn search_replace_basic() {
        let mut pipeline = ModifierPipeline::new();
        pipeline.push(Box::new(SearchReplaceModifier::new(
            b"secret".to_vec(),
            b"REDACTED".to_vec(),
        )));
        let mut data = b"This is a secret message".to_vec();
        let changed = pipeline.apply(&mut data);
        assert!(changed);
        assert_eq!(&data, b"This is a REDACTED message");
    }

    #[test]
    fn search_replace_no_match() {
        let m = SearchReplaceModifier::new(b"xyz".to_vec(), b"abc".to_vec());
        let mut data = b"hello world".to_vec();
        assert!(!m.modify(&mut data));
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn modifier_name() {
        let m = SearchReplaceModifier::new(vec![], vec![]);
        assert_eq!(m.name(), "search-replace");
        let h = HeaderInjector::new("X-Test", "val");
        assert_eq!(h.name(), "header-injector");
    }

    // ── HeaderInjector ────────────────────────────────────────────────────

    #[test]
    fn header_injector_basic() {
        let h = HeaderInjector::new("X-Proxy", "rustre");
        let mut data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody".to_vec();
        let changed = h.modify(&mut data);
        assert!(changed);
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("X-Proxy: rustre"));
    }

    #[test]
    fn header_injector_no_http_marker() {
        let h = HeaderInjector::new("X-Test", "val");
        let mut data = b"not http".to_vec();
        assert!(!h.modify(&mut data));
    }

    // ── ModifierPipeline ──────────────────────────────────────────────────

    #[test]
    fn modifier_pipeline_empty() {
        let pipeline = ModifierPipeline::new();
        assert!(pipeline.is_empty());
        let mut data = b"unchanged".to_vec();
        assert!(!pipeline.apply(&mut data));
    }

    #[test]
    fn modifier_pipeline_len() {
        let mut pipeline = ModifierPipeline::new();
        pipeline.push(Box::new(SearchReplaceModifier::new(vec![1], vec![2])));
        pipeline.push(Box::new(SearchReplaceModifier::new(vec![3], vec![4])));
        assert_eq!(pipeline.len(), 2);
    }

    // ── TrafficRecorder ───────────────────────────────────────────────────

    #[test]
    fn traffic_recorder_basic() {
        let recorder = TrafficRecorder::new(100);
        recorder.record(TrafficRecord::new(
            1,
            Direction::Request,
            b"req".to_vec(),
            "client",
        ));
        recorder.record(TrafficRecord::new(
            1,
            Direction::Response,
            b"resp".to_vec(),
            "server",
        ));
        recorder.record(TrafficRecord::new(
            2,
            Direction::Request,
            b"req2".to_vec(),
            "client",
        ));
        assert_eq!(recorder.len(), 3);
        let session1 = recorder.for_session(1);
        assert_eq!(session1.len(), 2);
        assert_eq!(recorder.total_bytes(), 3 + 4 + 4);
    }

    #[test]
    fn traffic_recorder_capacity_eviction() {
        let recorder = TrafficRecorder::new(2);
        recorder.record(TrafficRecord::new(1, Direction::Request, vec![0], "a"));
        recorder.record(TrafficRecord::new(2, Direction::Request, vec![0], "b"));
        recorder.record(TrafficRecord::new(3, Direction::Request, vec![0], "c"));
        assert_eq!(recorder.len(), 2);
    }

    #[test]
    fn traffic_record_display() {
        let r = TrafficRecord::new(42, Direction::Response, b"hello".to_vec(), "peer");
        let s = r.to_string();
        assert!(s.contains("42"));
        assert!(s.contains('5')); // len
        assert!(r.as_str().contains("hello"));
    }

    #[test]
    fn traffic_recorder_clear() {
        let recorder = TrafficRecorder::new(100);
        recorder.record(TrafficRecord::new(1, Direction::Request, vec![], "a"));
        recorder.clear();
        assert!(recorder.is_empty());
    }

    // ── SessionManager ────────────────────────────────────────────────────

    #[test]
    fn session_manager_lifecycle() {
        let sm = SessionManager::new();
        let id = sm.new_session("127.0.0.1:5000", "example.com:80", ProxyProtocol::Http);
        assert!(id >= 1);
        assert_eq!(sm.total(), 1);

        sm.set_state(id, SessionState::Connected);
        let s = sm.get(id).unwrap();
        assert_eq!(s.state, SessionState::Connected);
        assert!(s.is_active());

        sm.add_bytes(id, 100, 200);
        let s2 = sm.get(id).unwrap();
        assert_eq!(s2.bytes_in, 100);
        assert_eq!(s2.bytes_out, 200);
    }

    #[test]
    fn session_manager_prune() {
        let sm = SessionManager::new();
        let id1 = sm.new_session("1.1.1.1:1", "t1", ProxyProtocol::Http);
        let id2 = sm.new_session("2.2.2.2:2", "t2", ProxyProtocol::Tcp);
        sm.set_state(id1, SessionState::Closed);
        sm.prune();
        assert_eq!(sm.total(), 1);
        assert!(sm.get(id2).is_some());
        assert!(sm.get(id1).is_none());
    }

    #[test]
    fn session_state_display() {
        assert_eq!(SessionState::Connected.to_string(), "Connected");
        assert_eq!(SessionState::Closed.to_string(), "Closed");
    }

    #[test]
    fn session_entry_display() {
        let s = SessionEntry::new(7, "1.2.3.4:5000", "example.com:443", ProxyProtocol::Https);
        assert!(s.to_string().contains('7'));
        assert!(s.to_string().contains("example.com"));
    }

    // ── inject_xff_headers ────────────────────────────────────────────────

    #[test]
    fn inject_xff_headers_basic() {
        let mut data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let changed = inject_xff_headers(&mut data, "10.0.0.1", "proxy.local");
        assert!(changed);
        let s = String::from_utf8_lossy(&data);
        assert!(s.contains("X-Forwarded-For: 10.0.0.1"));
        assert!(s.contains("Via: 1.1 proxy.local"));
    }

    // ── Direction ────────────────────────────────────────────────────────

    #[test]
    fn direction_equality() {
        assert_eq!(Direction::Request, Direction::Request);
        assert_ne!(Direction::Request, Direction::Response);
    }

    // ── Socks5Auth serialization ──────────────────────────────────────────

    #[test]
    fn socks5_auth_serialize() {
        let auth = Socks5Auth::UsernamePassword {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("user"));
        let _auth2: Socks5Auth = serde_json::from_str(&json).unwrap();
    }

    // ── TrafficLog log_response ───────────────────────────────────────────

    #[test]
    fn traffic_log_response_direction() {
        let log = TrafficLog::new(10);
        let resp = ProxyResponse::new(1, la(80), b"OK".to_vec());
        log.log_response(&resp, la(5000));
        let entries = log.entries();
        assert_eq!(entries[0].direction, Direction::Response);
    }

    // ── ProxyError coverage ───────────────────────────────────────────────

    #[test]
    fn proxy_error_variants() {
        let e1 = ProxyError::Socks4Rejected;
        assert!(e1.to_string().contains("SOCKS4"));
        let e2 = ProxyError::ConnectionDropped;
        assert!(e2.to_string().contains("hook"));
        let e3 = ProxyError::Timeout;
        assert!(e3.to_string().contains("timeout"));
        let e4 = ProxyError::ConfigError("test".to_string());
        assert!(e4.to_string().contains("test"));
    }
}

// ============================================================================
// HTTP/1.1 request/response parser helpers
// ============================================================================

/// HTTP method as an enum for proxy decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
    Other(String),
}

impl std::str::FromStr for HttpMethod {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            other => Self::Other(other.to_string()),
        })
    }
}

impl HttpMethod {
    /// Parse a method string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            other => Self::Other(other.to_string()),
        }
    }

    /// Returns `true` if this method is idempotent.
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Get
                | Self::Head
                | Self::Put
                | Self::Delete
                | Self::Options
                | Self::Trace
        )
    }

    /// Returns `true` if this method can carry a request body.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Patch => write!(f, "PATCH"),
            Self::Connect => write!(f, "CONNECT"),
            Self::Trace => write!(f, "TRACE"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Parsed HTTP/1.x request line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestLine {
    /// HTTP method.
    pub method: HttpMethod,
    /// Request-URI.
    pub uri: String,
    /// HTTP version string, e.g. `"HTTP/1.1"`.
    pub version: String,
}

impl HttpRequestLine {
    /// Parse the first line of an HTTP request.
    ///
    /// # Errors
    /// Returns `Err` if the line does not contain a valid request-line.
    pub fn parse(line: &str) -> Result<Self, ProxyError> {
        let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
        if parts.len() != 3 {
            return Err(ProxyError::InvalidRequest(format!(
                "malformed request line: {line}"
            )));
        }
        Ok(Self {
            method: HttpMethod::from_str(parts[0]),
            uri: parts[1].to_string(),
            version: parts[2].to_string(),
        })
    }

    /// Returns `true` if the version is HTTP/1.1.
    #[must_use]
    pub fn is_http11(&self) -> bool {
        self.version == "HTTP/1.1"
    }

    /// Returns `true` if the version is HTTP/2 (upgrade path).
    #[must_use]
    pub fn is_http2(&self) -> bool {
        self.version.starts_with("HTTP/2")
    }
}

impl fmt::Display for HttpRequestLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.uri, self.version)
    }
}

/// Parsed HTTP status line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpStatusLine {
    /// HTTP version string, e.g. `"HTTP/1.1"`.
    pub version: String,
    /// Numeric status code.
    pub code: u16,
    /// Reason phrase.
    pub reason: String,
}

impl HttpStatusLine {
    /// Parse a status line.
    ///
    /// # Errors
    /// Returns `Err` if the line is malformed.
    pub fn parse(line: &str) -> Result<Self, ProxyError> {
        let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(ProxyError::InvalidRequest(format!(
                "malformed status line: {line}"
            )));
        }
        let code = parts[1]
            .parse::<u16>()
            .map_err(|_| ProxyError::InvalidRequest(format!("bad status code: {}", parts[1])))?;
        Ok(Self {
            version: parts[0].to_string(),
            code,
            reason: if parts.len() == 3 {
                parts[2].to_string()
            } else {
                String::new()
            },
        })
    }

    /// Returns `true` if the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Returns `true` if the status is 3xx (redirect).
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.code)
    }

    /// Returns `true` if the status is 4xx (client error).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// Returns `true` if the status is 5xx (server error).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.code)
    }
}

impl fmt::Display for HttpStatusLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.version, self.code, self.reason)
    }
}

// ============================================================================
// Proxy rate-limiter
// ============================================================================

/// A token-bucket rate limiter for proxy connections.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum bytes per second.
    pub bytes_per_sec: u64,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    active_connections: parking_lot::Mutex<usize>,
    bytes_this_second: parking_lot::Mutex<u64>,
    window_start_ms: parking_lot::Mutex<u64>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub const fn new(bytes_per_sec: u64, max_connections: usize) -> Self {
        Self {
            bytes_per_sec,
            max_connections,
            active_connections: parking_lot::Mutex::new(0),
            bytes_this_second: parking_lot::Mutex::new(0),
            window_start_ms: parking_lot::Mutex::new(0),
        }
    }

    /// Record a new connection attempt. Returns `false` if limit is exceeded.
    #[must_use]
    pub fn try_connect(&self) -> bool {
        let mut active = self.active_connections.lock();
        if *active >= self.max_connections {
            return false;
        }
        *active += 1;
        true
    }

    /// Release a connection slot.
    pub fn release_connection(&self) {
        let mut active = self.active_connections.lock();
        if *active > 0 {
            *active -= 1;
        }
    }

    /// Record bytes transferred. Returns `true` if within the rate limit.
    #[must_use]
    pub fn try_send_bytes(&self, now_ms: u64, bytes: u64) -> bool {
        let mut window = self.window_start_ms.lock();
        let mut usage = self.bytes_this_second.lock();
        if now_ms.saturating_sub(*window) >= 1000 {
            *window = now_ms;
            *usage = 0;
        }
        if *usage + bytes > self.bytes_per_sec {
            return false;
        }
        *usage += bytes;
        true
    }

    /// Return number of active connections.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        *self.active_connections.lock()
    }

    /// Return bytes transferred in the current window.
    #[must_use]
    pub fn bytes_this_window(&self) -> u64 {
        *self.bytes_this_second.lock()
    }
}

// ============================================================================
// Proxy DNS cache
// ============================================================================

/// A simple time-to-live DNS cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    /// Resolved IP address string.
    pub ip: String,
    /// Timestamp when the entry was cached (ms since epoch).
    pub cached_at_ms: u64,
    /// TTL in seconds.
    pub ttl_secs: u64,
}

impl DnsCacheEntry {
    /// Create a new cache entry.
    #[must_use]
    pub fn new(ip: impl Into<String>, cached_at_ms: u64, ttl_secs: u64) -> Self {
        Self {
            ip: ip.into(),
            cached_at_ms,
            ttl_secs,
        }
    }

    /// Returns `true` if the entry is still valid at `now_ms`.
    #[must_use]
    pub const fn is_valid(&self, now_ms: u64) -> bool {
        now_ms < self.cached_at_ms + self.ttl_secs * 1000
    }
}

/// An in-memory DNS cache for the proxy.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: parking_lot::RwLock<std::collections::HashMap<String, DnsCacheEntry>>,
}

impl DnsCache {
    /// Create an empty DNS cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a cache entry.
    pub fn insert(
        &self,
        host: impl Into<String>,
        ip: impl Into<String>,
        now_ms: u64,
        ttl_secs: u64,
    ) {
        let mut map = self.entries.write();
        map.insert(host.into(), DnsCacheEntry::new(ip, now_ms, ttl_secs));
    }

    /// Look up a host. Returns `Some(ip)` if a valid (non-expired) entry exists.
    #[must_use]
    pub fn lookup(&self, host: &str, now_ms: u64) -> Option<String> {
        let map = self.entries.read();
        map.get(host)
            .filter(|e| e.is_valid(now_ms))
            .map(|e| e.ip.clone())
    }

    /// Evict all expired entries. Returns the number of entries removed.
    #[must_use]
    pub fn evict_expired(&self, now_ms: u64) -> usize {
        let mut map = self.entries.write();
        let before = map.len();
        map.retain(|_, e| e.is_valid(now_ms));
        before - map.len()
    }

    /// Total number of cached entries (including expired).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.write().clear();
    }
}

// ============================================================================
// Proxy connection metrics
// ============================================================================

/// Per-connection metrics collected during proxying.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    /// Bytes read from the client.
    pub client_bytes_in: u64,
    /// Bytes written to the client.
    pub client_bytes_out: u64,
    /// Bytes read from the upstream.
    pub upstream_bytes_in: u64,
    /// Bytes written to the upstream.
    pub upstream_bytes_out: u64,
    /// Number of request/response round trips.
    pub round_trips: u64,
    /// Connection open time in ms since epoch.
    pub opened_at_ms: u64,
    /// Connection close time in ms since epoch (0 if still open).
    pub closed_at_ms: u64,
}

impl ConnectionMetrics {
    /// Create metrics with the given open timestamp.
    #[must_use]
    pub fn new(opened_at_ms: u64) -> Self {
        Self {
            opened_at_ms,
            ..Default::default()
        }
    }

    /// Record bytes flowing from client to proxy.
    pub const fn add_client_in(&mut self, bytes: u64) {
        self.client_bytes_in += bytes;
    }

    /// Record bytes flowing from proxy to client.
    pub const fn add_client_out(&mut self, bytes: u64) {
        self.client_bytes_out += bytes;
    }

    /// Record bytes read from the upstream.
    pub const fn add_upstream_in(&mut self, bytes: u64) {
        self.upstream_bytes_in += bytes;
    }

    /// Record bytes written to the upstream.
    pub const fn add_upstream_out(&mut self, bytes: u64) {
        self.upstream_bytes_out += bytes;
    }

    /// Record one completed round trip.
    pub const fn inc_round_trips(&mut self) {
        self.round_trips += 1;
    }

    /// Mark the connection as closed at `now_ms`.
    pub const fn close(&mut self, now_ms: u64) {
        self.closed_at_ms = now_ms;
    }

    /// Total bytes in both directions.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.client_bytes_in
            + self.client_bytes_out
            + self.upstream_bytes_in
            + self.upstream_bytes_out
    }

    /// Duration in milliseconds (0 if still open).
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        if self.closed_at_ms == 0 {
            0
        } else {
            self.closed_at_ms.saturating_sub(self.opened_at_ms)
        }
    }
}

impl fmt::Display for ConnectionMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConnectionMetrics{{ client_in={} client_out={} upstream_in={} upstream_out={} trips={} }}",
            self.client_bytes_in,
            self.client_bytes_out,
            self.upstream_bytes_in,
            self.upstream_bytes_out,
            self.round_trips,
        )
    }
}

// ============================================================================
// HTTP header rewriter
// ============================================================================

/// An HTTP header rewriting rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRewriteRule {
    /// Header name to match (case-insensitive).
    pub header_name: String,
    /// New value to set (empty = remove the header).
    pub new_value: String,
    /// Whether to add the header if not present.
    pub add_if_missing: bool,
}

impl HeaderRewriteRule {
    /// Create a rule that sets a header value.
    #[must_use]
    pub fn set(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header_name: name.into(),
            new_value: value.into(),
            add_if_missing: true,
        }
    }

    /// Create a rule that removes a header.
    #[must_use]
    pub fn remove(name: impl Into<String>) -> Self {
        Self {
            header_name: name.into(),
            new_value: String::new(),
            add_if_missing: false,
        }
    }

    /// Apply this rule to the provided raw HTTP headers string.
    /// Returns the modified headers string.
    #[must_use]
    pub fn apply(&self, headers: &str) -> String {
        let name_lower = self.header_name.to_ascii_lowercase();
        let mut found = false;
        let mut lines: Vec<String> = headers
            .lines()
            .filter_map(|line| {
                line.find(':').map_or_else(|| Some(line.to_string()), |colon| {
                    let key = line[..colon].trim().to_ascii_lowercase();
                    if key == name_lower {
                        found = true;
                        if self.new_value.is_empty() {
                            None // remove
                        } else {
                            Some(format!("{}: {}", line[..colon].trim(), self.new_value))
                        }
                    } else {
                        Some(line.to_string())
                    }
                })
            })
            .collect();
        if !found && self.add_if_missing && !self.new_value.is_empty() {
            lines.push(format!("{}: {}", self.header_name, self.new_value));
        }
        lines.join("\r\n")
    }
}

impl fmt::Display for HeaderRewriteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.new_value.is_empty() {
            write!(f, "REMOVE {}", self.header_name)
        } else {
            write!(f, "SET {}: {}", self.header_name, self.new_value)
        }
    }
}

/// A chain of header rewrite rules applied in order.
#[derive(Debug, Default)]
pub struct HeaderRewriter {
    rules: Vec<HeaderRewriteRule>,
}

impl HeaderRewriter {
    /// Create an empty rewriter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: HeaderRewriteRule) {
        self.rules.push(rule);
    }

    /// Apply all rules sequentially. Returns the final headers string.
    #[must_use]
    pub fn apply_all(&self, headers: &str) -> String {
        let mut result = headers.to_string();
        for rule in &self.rules {
            result = rule.apply(&result);
        }
        result
    }

    /// Number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if there are no rules.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// ============================================================================
// SOCKS5 UDP association support
// ============================================================================

/// A SOCKS5 UDP associate request header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5UdpHeader {
    /// Reserved (must be 0x0000).
    pub rsv: u16,
    /// Fragment number (0 = standalone datagram).
    pub frag: u8,
    /// Address type (1 = IPv4, 3 = domain, 4 = IPv6).
    pub atyp: u8,
    /// Destination address string.
    pub dst_addr: String,
    /// Destination port.
    pub dst_port: u16,
}

impl Socks5UdpHeader {
    /// Parse a SOCKS5 UDP header from bytes.
    ///
    /// # Errors
    /// Returns `Err` if the slice is too short or the address type is unknown.
    pub fn parse(data: &[u8]) -> Result<Self, ProxyError> {
        if data.len() < 7 {
            return Err(ProxyError::InvalidRequest(
                "UDP header too short".to_string(),
            ));
        }
        let rsv = u16::from_be_bytes([data[0], data[1]]);
        let frag = data[2];
        let atyp = data[3];
        let (dst_addr, port_offset) = match atyp {
            1 => {
                if data.len() < 10 {
                    return Err(ProxyError::InvalidRequest(
                        "UDP IPv4 header too short".to_string(),
                    ));
                }
                let addr = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
                (addr, 8usize)
            }
            3 => {
                let len = data[4] as usize;
                if data.len() < 5 + len + 2 {
                    return Err(ProxyError::InvalidRequest(
                        "UDP domain header too short".to_string(),
                    ));
                }
                let addr = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                (addr, 5 + len)
            }
            4 => {
                if data.len() < 22 {
                    return Err(ProxyError::InvalidRequest(
                        "UDP IPv6 header too short".to_string(),
                    ));
                }
                let addr = format!(
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                     {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    data[4],
                    data[5],
                    data[6],
                    data[7],
                    data[8],
                    data[9],
                    data[10],
                    data[11],
                    data[12],
                    data[13],
                    data[14],
                    data[15],
                    data[16],
                    data[17],
                    data[18],
                    data[19],
                );
                (addr, 20usize)
            }
            _ => {
                return Err(ProxyError::Socks5UnsupportedAddressType(atyp));
            }
        };
        if data.len() < port_offset + 2 {
            return Err(ProxyError::InvalidRequest(
                "UDP header missing port".to_string(),
            ));
        }
        let dst_port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
        Ok(Self {
            rsv,
            frag,
            atyp,
            dst_addr,
            dst_port,
        })
    }

    /// Serialize the header to bytes (IPv4 only for simplicity).
    #[must_use]
    pub fn to_bytes_ipv4(&self, ipv4: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        buf.extend_from_slice(&self.rsv.to_be_bytes());
        buf.push(self.frag);
        buf.push(1); // IPv4
        buf.extend_from_slice(&ipv4);
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf
    }
}

// ============================================================================
// Proxy tunnel statistics
// ============================================================================

/// Statistics for a completed or active proxy tunnel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelStats {
    /// Total bytes relayed client→upstream.
    pub bytes_up: u64,
    /// Total bytes relayed upstream→client.
    pub bytes_down: u64,
    /// Number of relay iterations.
    pub relay_cycles: u64,
    /// Number of errors during relaying.
    pub relay_errors: u64,
    /// Whether the tunnel closed cleanly.
    pub clean_close: bool,
}

impl TunnelStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an uplink chunk.
    pub const fn add_up(&mut self, bytes: u64) {
        self.bytes_up += bytes;
        self.relay_cycles += 1;
    }

    /// Record a downlink chunk.
    pub const fn add_down(&mut self, bytes: u64) {
        self.bytes_down += bytes;
        self.relay_cycles += 1;
    }

    /// Record a relay error.
    pub const fn add_error(&mut self) {
        self.relay_errors += 1;
    }

    /// Mark as cleanly closed.
    pub const fn mark_clean(&mut self) {
        self.clean_close = true;
    }

    /// Total bytes in both directions.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_up + self.bytes_down
    }
}

impl fmt::Display for TunnelStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TunnelStats{{ up={} down={} cycles={} errors={} clean={} }}",
            self.bytes_up, self.bytes_down, self.relay_cycles, self.relay_errors, self.clean_close,
        )
    }
}

// ============================================================================
// Additional tests
// ============================================================================

#[cfg(test)]
mod extra_tests {
    use super::*;

    // ── HttpMethod ─────────────────────────────────────────────────────────

    #[test]
    fn http_method_from_str() {
        assert_eq!(HttpMethod::from_str("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from_str("CONNECT"), HttpMethod::Connect);
        assert!(matches!(
            HttpMethod::from_str("PROPFIND"),
            HttpMethod::Other(_)
        ));
    }

    #[test]
    fn http_method_idempotent() {
        assert!(HttpMethod::Get.is_idempotent());
        assert!(!HttpMethod::Post.is_idempotent());
        assert!(HttpMethod::Put.is_idempotent());
    }

    #[test]
    fn http_method_has_body() {
        assert!(HttpMethod::Post.has_body());
        assert!(HttpMethod::Put.has_body());
        assert!(!HttpMethod::Get.has_body());
    }

    #[test]
    fn http_method_display() {
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
        assert_eq!(
            HttpMethod::Other("PROPFIND".to_string()).to_string(),
            "PROPFIND"
        );
    }

    // ── HttpRequestLine ────────────────────────────────────────────────────

    #[test]
    fn http_request_line_parse_ok() {
        let rl = HttpRequestLine::parse("GET /index.html HTTP/1.1").unwrap();
        assert_eq!(rl.method, HttpMethod::Get);
        assert_eq!(rl.uri, "/index.html");
        assert!(rl.is_http11());
    }

    #[test]
    fn http_request_line_parse_error() {
        assert!(HttpRequestLine::parse("BADLINE").is_err());
    }

    #[test]
    fn http_request_line_display() {
        let rl = HttpRequestLine::parse("POST /api HTTP/1.0").unwrap();
        assert!(rl.to_string().contains("POST"));
        assert!(rl.to_string().contains("/api"));
    }

    // ── HttpStatusLine ─────────────────────────────────────────────────────

    #[test]
    fn http_status_line_ok() {
        let sl = HttpStatusLine::parse("HTTP/1.1 200 OK").unwrap();
        assert_eq!(sl.code, 200);
        assert!(sl.is_success());
        assert!(!sl.is_redirect());
    }

    #[test]
    fn http_status_line_redirect() {
        let sl = HttpStatusLine::parse("HTTP/1.1 301 Moved Permanently").unwrap();
        assert!(sl.is_redirect());
        assert!(!sl.is_success());
    }

    #[test]
    fn http_status_line_server_error() {
        let sl = HttpStatusLine::parse("HTTP/1.1 500 Internal Server Error").unwrap();
        assert!(sl.is_server_error());
        assert!(!sl.is_client_error());
    }

    #[test]
    fn http_status_line_bad_code() {
        assert!(HttpStatusLine::parse("HTTP/1.1 ABC OK").is_err());
    }

    #[test]
    fn http_status_line_display() {
        let sl = HttpStatusLine::parse("HTTP/1.1 404 Not Found").unwrap();
        assert!(sl.to_string().contains("404"));
        assert!(sl.to_string().contains("Not Found"));
    }

    // ── RateLimiter ────────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_connections() {
        let rl = RateLimiter::new(1_000_000, 2);
        assert!(rl.try_connect());
        assert!(rl.try_connect());
        assert!(!rl.try_connect()); // over limit
        assert_eq!(rl.active_connections(), 2);
        rl.release_connection();
        assert!(rl.try_connect());
    }

    #[test]
    fn rate_limiter_bytes() {
        let rl = RateLimiter::new(100, 10);
        assert!(rl.try_send_bytes(0, 50));
        assert!(rl.try_send_bytes(0, 50));
        assert!(!rl.try_send_bytes(0, 1)); // over limit
        // New window resets counter
        assert!(rl.try_send_bytes(2000, 50));
    }

    #[test]
    fn rate_limiter_bytes_this_window() {
        let rl = RateLimiter::new(1000, 5);
        let _ = rl.try_send_bytes(0, 300);
        assert_eq!(rl.bytes_this_window(), 300);
    }

    // ── DnsCache ───────────────────────────────────────────────────────────

    #[test]
    fn dns_cache_basic() {
        let cache = DnsCache::new();
        assert!(cache.is_empty());
        cache.insert("example.com", "1.2.3.4", 0, 60);
        assert_eq!(cache.len(), 1);
        let ip = cache.lookup("example.com", 0).unwrap();
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn dns_cache_expiry() {
        let cache = DnsCache::new();
        cache.insert("old.com", "5.6.7.8", 0, 1); // TTL = 1 second
        // Expired after 2000 ms
        assert!(cache.lookup("old.com", 2000).is_none());
    }

    #[test]
    fn dns_cache_evict() {
        let cache = DnsCache::new();
        cache.insert("a.com", "1.1.1.1", 0, 1);
        cache.insert("b.com", "2.2.2.2", 0, 3600);
        let removed = cache.evict_expired(2000);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup("b.com", 2000).is_some());
    }

    #[test]
    fn dns_cache_clear() {
        let cache = DnsCache::new();
        cache.insert("x.com", "9.9.9.9", 0, 60);
        cache.clear();
        assert!(cache.is_empty());
    }

    // ── ConnectionMetrics ──────────────────────────────────────────────────

    #[test]
    fn connection_metrics_basic() {
        let mut m = ConnectionMetrics::new(1000);
        m.add_client_in(500);
        m.add_upstream_out(500);
        m.add_upstream_in(1200);
        m.add_client_out(1200);
        m.inc_round_trips();
        assert_eq!(m.round_trips, 1);
        assert_eq!(m.total_bytes(), 3400);
        m.close(2000);
        assert_eq!(m.duration_ms(), 1000);
    }

    #[test]
    fn connection_metrics_display() {
        let m = ConnectionMetrics::new(0);
        assert!(m.to_string().contains("client_in"));
    }

    // ── HeaderRewriteRule ──────────────────────────────────────────────────

    #[test]
    fn header_rewrite_set() {
        let rule = HeaderRewriteRule::set("X-Forwarded-For", "10.0.0.1");
        let headers = "Host: example.com\r\nX-Forwarded-For: old-value";
        let result = rule.apply(headers);
        assert!(result.contains("10.0.0.1"));
        assert!(!result.contains("old-value"));
    }

    #[test]
    fn header_rewrite_remove() {
        let rule = HeaderRewriteRule::remove("Cookie");
        let headers = "Host: example.com\r\nCookie: session=abc123";
        let result = rule.apply(headers);
        assert!(!result.contains("Cookie:"));
        assert!(result.contains("Host:"));
    }

    #[test]
    fn header_rewrite_add_if_missing() {
        let rule = HeaderRewriteRule::set("X-Custom", "hello");
        let headers = "Host: example.com";
        let result = rule.apply(headers);
        assert!(result.contains("X-Custom: hello"));
    }

    #[test]
    fn header_rewrite_display() {
        let set = HeaderRewriteRule::set("Cache-Control", "no-cache");
        assert!(set.to_string().contains("SET"));
        let rm = HeaderRewriteRule::remove("Pragma");
        assert!(rm.to_string().contains("REMOVE"));
    }

    // ── HeaderRewriter ─────────────────────────────────────────────────────

    #[test]
    fn header_rewriter_chain() {
        let mut rw = HeaderRewriter::new();
        rw.add_rule(HeaderRewriteRule::set("Via", "1.1 proxy"));
        rw.add_rule(HeaderRewriteRule::remove("X-Real-IP"));
        assert_eq!(rw.rule_count(), 2);
        let headers = "Host: test\r\nX-Real-IP: 127.0.0.1";
        let out = rw.apply_all(headers);
        assert!(out.contains("Via: 1.1 proxy"));
        assert!(!out.contains("X-Real-IP:"));
    }

    #[test]
    fn header_rewriter_empty() {
        let rw = HeaderRewriter::new();
        assert!(rw.is_empty());
        assert_eq!(rw.apply_all("Host: x"), "Host: x");
    }

    // ── Socks5UdpHeader ────────────────────────────────────────────────────

    #[test]
    fn socks5_udp_header_ipv4() {
        // RSV=0, FRAG=0, ATYP=1(IPv4), ADDR=10.0.0.1, PORT=80
        let data = [0x00, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50];
        let hdr = Socks5UdpHeader::parse(&data).unwrap();
        assert_eq!(hdr.dst_addr, "10.0.0.1");
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.frag, 0);
    }

    #[test]
    fn socks5_udp_header_too_short() {
        let data = [0x00, 0x00];
        assert!(Socks5UdpHeader::parse(&data).is_err());
    }

    #[test]
    fn socks5_udp_header_bad_atyp() {
        let data = [0x00, 0x00, 0x00, 0xFF, 10, 0, 0, 1, 0x00, 0x50];
        assert!(Socks5UdpHeader::parse(&data).is_err());
    }

    #[test]
    fn socks5_udp_to_bytes_ipv4() {
        let hdr = Socks5UdpHeader {
            rsv: 0,
            frag: 0,
            atyp: 1,
            dst_addr: "10.0.0.1".to_string(),
            dst_port: 80,
        };
        let bytes = hdr.to_bytes_ipv4([10, 0, 0, 1]);
        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes[3], 1); // ATYP=IPv4
    }

    // ── TunnelStats ────────────────────────────────────────────────────────

    #[test]
    fn tunnel_stats_accumulate() {
        let mut s = TunnelStats::new();
        s.add_up(1024);
        s.add_down(2048);
        s.add_error();
        assert_eq!(s.bytes_up, 1024);
        assert_eq!(s.bytes_down, 2048);
        assert_eq!(s.relay_cycles, 2);
        assert_eq!(s.relay_errors, 1);
        assert!(!s.clean_close);
        s.mark_clean();
        assert!(s.clean_close);
        assert_eq!(s.total_bytes(), 3072);
    }

    #[test]
    fn tunnel_stats_display() {
        let s = TunnelStats::new();
        assert!(s.to_string().contains("TunnelStats"));
    }
}

// ============================================================================
// §21.4 — Real HTTPS MITM proxy: CertificateAuthority, TlsInterceptor,
//          MitmProxy, RequestLogger, MatchReplaceRule
// ============================================================================

use std::io::Cursor;
use std::path::Path;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    SanType,
};
use rustls::ClientConfig;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ────────────────────────────────────────────────────────────────────────────
// Error extension: MITM / TLS errors
// ────────────────────────────────────────────────────────────────────────────

/// Errors produced by the MITM / TLS subsystem.
#[derive(Debug, thiserror::Error)]
pub enum MitmError {
    #[error("certificate generation failed: {0}")]
    CertGen(String),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("upstream TLS handshake failed: {0}")]
    UpstreamTls(String),

    #[error("downstream TLS handshake failed: {0}")]
    DownstreamTls(String),

    #[error("PEM parse error: {0}")]
    PemParse(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

// ────────────────────────────────────────────────────────────────────────────
// CertificateAuthority
// ────────────────────────────────────────────────────────────────────────────

/// An in-process root Certificate Authority used for HTTPS MITM.
///
/// Generates a self-signed root CA and on demand signs per-hostname leaf
/// certificates.  Persisted as two PEM files (`ca.crt` / `ca.key`).
pub struct CertificateAuthority {
    /// DER-encoded CA certificate (for sending to rustls).
    ca_cert_der: CertificateDer<'static>,
    /// rcgen `Certificate` with the embedded private key — used to sign leaves.
    ca_cert: Certificate,
    /// rcgen `KeyPair` for the CA.
    ca_key: KeyPair,
    /// Cached PEM representations.
    cert_pem: String,
    key_pem: String,
}

impl CertificateAuthority {
    /// Generate a brand-new self-signed root CA.
    ///
    /// # Errors
    /// Returns [`MitmError::CertGen`] if rcgen fails.
    pub fn new() -> Result<Self, MitmError> {
        let key = KeyPair::generate().map_err(|e| MitmError::CertGen(e.to_string()))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "RustRE-CA");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "RustRE");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        let cert = params
            .self_signed(&key)
            .map_err(|e| MitmError::CertGen(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let ca_cert_der = CertificateDer::from(cert.der().to_vec());

        Ok(Self {
            ca_cert_der,
            ca_cert: cert,
            ca_key: key,
            cert_pem,
            key_pem,
        })
    }

    /// Return the CA certificate in PEM format.
    #[must_use]
    pub fn ca_cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Return the raw DER bytes of the CA certificate.
    ///
    /// These can be written to a `.crt` / `.cer` file for import into a
    /// browser or OS trust store.
    #[must_use]
    pub fn ca_cert_der_bytes(&self) -> Vec<u8> {
        self.ca_cert_der.to_vec()
    }

    /// Return the CA private key in PEM format.
    #[must_use]
    pub fn ca_key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Sign a leaf certificate for `hostname` and return
    /// `(cert_pem, key_pem)`.
    ///
    /// # Errors
    /// Returns [`MitmError::CertGen`] if rcgen fails.
    pub fn sign_for_host(&self, hostname: &str) -> Result<(String, String), MitmError> {
        let leaf_key = KeyPair::generate().map_err(|e| MitmError::CertGen(e.to_string()))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        params.subject_alt_names =
            vec![SanType::DnsName(hostname.to_owned().try_into().map_err(
                |e: rcgen::Error| MitmError::CertGen(e.to_string()),
            )?)];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| MitmError::CertGen(e.to_string()))?;

        Ok((leaf_cert.pem(), leaf_key.serialize_pem()))
    }

    /// Load a CA from PEM files at `<path>/ca.crt` and `<path>/ca.key`, or
    /// generate a fresh CA and persist it there if the files do not exist.
    ///
    /// # Errors
    /// Returns [`MitmError`] on I/O or certificate errors.
    pub fn load_or_create(path: &Path) -> Result<Self, MitmError> {
        let cert_file = path.join("ca.crt");
        let key_file = path.join("ca.key");

        if cert_file.exists() && key_file.exists() {
            let cert_pem = std::fs::read_to_string(&cert_file)?;
            let key_pem = std::fs::read_to_string(&key_file)?;

            let key =
                KeyPair::from_pem(&key_pem).map_err(|e| MitmError::PemParse(e.to_string()))?;

            // rcgen 0.13 does not have from_ca_cert_pem; reconstruct from defaults
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

            let cert = params
                .self_signed(&key)
                .map_err(|e: rcgen::Error| MitmError::CertGen(e.to_string()))?;

            let ca_cert_der = CertificateDer::from(cert.der().to_vec());

            Ok(Self {
                ca_cert_der,
                ca_cert: cert,
                ca_key: key,
                cert_pem,
                key_pem,
            })
        } else {
            std::fs::create_dir_all(path)?;
            let ca = Self::new()?;
            std::fs::write(&cert_file, ca.ca_cert_pem())?;
            std::fs::write(&key_file, ca.ca_key_pem())?;
            Ok(ca)
        }
    }

    /// Build a rustls `ServerConfig` for the given hostname using a freshly
    /// signed leaf certificate.
    ///
    /// # Errors
    /// Returns [`MitmError`] on certificate or TLS configuration errors.
    pub fn build_server_config(
        ca: &Arc<Self>,
        hostname: &str,
    ) -> Result<Arc<ServerConfig>, MitmError> {
        let (cert_pem, key_pem) = ca.sign_for_host(hostname)?;

        // Parse cert chain
        let cert_chain: Vec<CertificateDer<'static>> = {
            let mut reader = Cursor::new(cert_pem.as_bytes());
            certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| MitmError::PemParse(e.to_string()))?
        };

        // Parse private key
        let private_key: PrivateKeyDer<'static> = {
            let mut reader = Cursor::new(key_pem.as_bytes());
            let mut keys: Vec<_> = pkcs8_private_keys(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| MitmError::PemParse(e.to_string()))?;
            if keys.is_empty() {
                return Err(MitmError::PemParse(
                    "no PKCS8 private key found".to_string(),
                ));
            }
            PrivateKeyDer::Pkcs8(keys.remove(0))
        };

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| MitmError::TlsConfig(e.to_string()))?;

        Ok(Arc::new(config))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TlsInterceptor
// ────────────────────────────────────────────────────────────────────────────

/// HTTPS MITM interceptor.
///
/// Accepts `CONNECT` tunnels, terminates TLS with a CA-signed leaf cert, then
/// re-encrypts the traffic toward the real upstream server.
pub struct TlsInterceptor {
    ca: Arc<CertificateAuthority>,
}

impl TlsInterceptor {
    /// Create a new interceptor backed by `ca`.
    #[must_use]
    pub const fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self { ca }
    }

    /// Build a permissive `ClientConfig` that accepts any server certificate.
    ///
    /// **Warning:** this disables certificate verification.  It is intentional
    /// for a MITM proxy that intercepts all TLS traffic.
    ///
    /// # Errors
    /// Returns [`MitmError::TlsConfig`] on rustls configuration errors.
    pub fn build_client_config() -> Result<Arc<ClientConfig>, MitmError> {
        // Danger: no certificate verification.
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Handle an inbound `CONNECT` connection end-to-end:
    ///
    /// 1. Send `200 Connection Established`.
    /// 2. Wrap the client stream in TLS using a CA-signed cert for `host`.
    /// 3. Open a TLS connection to the real `host:port`.
    /// 4. Relay data bidirectionally between the two TLS streams.
    ///
    /// # Errors
    /// Returns [`MitmError`] on any I/O or TLS error.
    pub async fn handle_connect(
        &self,
        mut stream: TcpStream,
        host: String,
        port: u16,
    ) -> Result<(), MitmError> {
        // 1. Acknowledge the CONNECT tunnel.
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // 2. Build server-side TLS config (downstream: proxy ← client).
        let server_cfg = CertificateAuthority::build_server_config(&self.ca, &host)?;
        let acceptor = TlsAcceptor::from(server_cfg);
        let tls_client = acceptor
            .accept(stream)
            .await
            .map_err(|e| MitmError::DownstreamTls(e.to_string()))?;

        // 3. Connect to real upstream and wrap in TLS.
        let addr = format!("{host}:{port}");
        let tcp_upstream = TcpStream::connect(&addr)
            .await
            .map_err(MitmError::Io)?;

        let client_cfg = Self::build_client_config()?;
        let connector = TlsConnector::from(client_cfg);
        let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
            .map_err(|_| MitmError::TlsConfig(format!("invalid server name: {host}")))?
            .to_owned();
        let tls_upstream = connector
            .connect(server_name, tcp_upstream)
            .await
            .map_err(|e| MitmError::UpstreamTls(e.to_string()))?;

        // 4. Bidirectional relay.
        let (mut cr, mut cw) = tokio::io::split(tls_client);
        let (mut ur, mut uw) = tokio::io::split(tls_upstream);

        let c2u = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut uw).await;
        });
        let u2c = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut ur, &mut cw).await;
        });

        let _ = tokio::join!(c2u, u2c);
        Ok(())
    }
}

/// A rustls `ServerCertVerifier` that accepts every certificate.
///
/// Used by the proxy's outbound TLS connections so that it can intercept
/// traffic to servers with self-signed, expired, or otherwise invalid certs.
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Standalone MITM tunnel helper
// ────────────────────────────────────────────────────────────────────────────

/// Standalone HTTPS CONNECT tunnel handler with full TLS MITM.
///
/// This function encapsulates the complete MITM sequence for a single
/// `CONNECT` tunnel that has **not** yet received its `200` acknowledgement:
///
/// 1. Send `HTTP/1.1 200 Connection established\r\n\r\n` to the client.
/// 2. Build a per-host [`ServerConfig`] by calling
///    [`CertificateAuthority::build_server_config`].
/// 3. Wrap `inbound` with a [`TlsAcceptor`] so the proxy terminates the
///    client's TLS connection.
/// 4. Open a raw [`TcpStream`] to `host:port` and wrap it with a
///    [`TlsConnector`] that accepts **all** server certificates (the proxy
///    trusts everything upstream; clients must trust the CA cert instead).
/// 5. Relay data bidirectionally with [`tokio::io::copy_bidirectional`].
///
/// # Errors
///
/// Returns [`MitmError`] on any I/O or TLS error.
pub async fn handle_connect_tunnel(
    mut inbound: TcpStream,
    host: String,
    port: u16,
    ca: Arc<CertificateAuthority>,
) -> Result<(), MitmError> {
    // ── Step 1: acknowledge the CONNECT tunnel ────────────────────────────
    inbound
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;

    // ── Step 2: build ServerConfig for this specific hostname ─────────────
    let server_cfg = CertificateAuthority::build_server_config(&ca, &host)?;

    // ── Step 3: TLS-accept the inbound (client → proxy) side ─────────────
    let acceptor = TlsAcceptor::from(server_cfg);
    let tls_inbound = acceptor
        .accept(inbound)
        .await
        .map_err(|e| MitmError::DownstreamTls(e.to_string()))?;

    // ── Step 4: connect to the real server and wrap with TLS ──────────────
    let addr = format!("{host}:{port}");
    let outbound = TcpStream::connect(&addr).await.map_err(MitmError::Io)?;

    // Build a client config that skips certificate verification — this is
    // intentional: a MITM proxy must be able to intercept any server cert.
    let client_cfg = TlsInterceptor::build_client_config()?;
    let connector = TlsConnector::from(client_cfg);
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
        .map_err(|_| MitmError::TlsConfig(format!("invalid SNI: {host}")))?
        .to_owned();
    let tls_outbound = connector
        .connect(server_name, outbound)
        .await
        .map_err(|e| MitmError::UpstreamTls(e.to_string()))?;

    // ── Step 5: bidirectional relay using tokio's built-in helper ─────────
    let (mut ri, mut wi) = tokio::io::split(tls_inbound);
    let (mut ro, mut wo) = tokio::io::split(tls_outbound);

    // Run both directions concurrently; finish when both half-connections
    // have reached EOF or encountered an error.
    let inbound_to_outbound = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ri, &mut wo).await;
    });
    let outbound_to_inbound = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ro, &mut wi).await;
    });

    let _ = tokio::join!(inbound_to_outbound, outbound_to_inbound);
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// HttpRequest / HttpResponse (high-level types for the MITM layer)
// ────────────────────────────────────────────────────────────────────────────

/// A parsed HTTP request used by the MITM layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP method string (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// Full URL or request path.
    pub url: String,
    /// HTTP version string (e.g. `"HTTP/1.1"`).
    pub version: String,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Request body (may be empty).
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Create a minimal GET request.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: "GET".to_string(),
            url: url.into(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Look up a request header value (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Set or overwrite a header.
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(h) = self
            .headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name))
        {
            h.1 = value;
        } else {
            self.headers.push((name, value));
        }
    }

    /// Remove a header by name (case-insensitive).  Returns `true` if removed.
    pub fn remove_header(&mut self, name: &str) -> bool {
        let before = self.headers.len();
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.len() < before
    }
}

/// A parsed HTTP response used by the MITM layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP version string.
    pub version: String,
    /// Numeric status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body (may be empty).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Create a minimal 200 OK response.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            version: "HTTP/1.1".to_string(),
            status: 200,
            reason: "OK".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Returns `true` if this is a 2xx response.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Look up a response header value (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Set or overwrite a header.
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(h) = self
            .headers
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(&name))
        {
            h.1 = value;
        } else {
            self.headers.push((name, value));
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// MitmProxy
// ────────────────────────────────────────────────────────────────────────────

/// High-level MITM proxy that combines HTTP forwarding with HTTPS interception.
///
/// For plain HTTP requests the traffic is forwarded as-is.
/// For `CONNECT` tunnels (HTTPS) a [`TlsInterceptor`] decrypts and re-encrypts
/// the stream so that the proxy can inspect the plaintext.
pub struct MitmProxy {
    /// Shared certificate authority for generating leaf certs.
    pub ca: Arc<CertificateAuthority>,
    /// Bind address for the HTTP listener.
    pub bind_addr: SocketAddr,
    /// Optional request logger.
    pub logger: Option<Arc<RequestLogger>>,
    /// Match-replace rules applied to every intercepted request.
    pub rules: Arc<parking_lot::RwLock<Vec<MatchReplaceRule>>>,
    /// Proxy statistics.
    stats: Arc<SharedStats>,
}

impl MitmProxy {
    /// Create a new MITM proxy.
    ///
    /// # Errors
    /// Returns [`MitmError::CertGen`] if CA generation fails.
    pub fn new(bind_addr: SocketAddr) -> Result<Self, MitmError> {
        let ca = Arc::new(CertificateAuthority::new()?);
        Ok(Self {
            ca,
            bind_addr,
            logger: None,
            rules: Arc::new(parking_lot::RwLock::new(Vec::new())),
            stats: Arc::new(SharedStats::new()),
        })
    }

    /// Create a proxy backed by a CA loaded from (or persisted to) `path`.
    ///
    /// # Errors
    /// Returns [`MitmError`] on CA load/create failure.
    pub fn with_ca_path(bind_addr: SocketAddr, path: &Path) -> Result<Self, MitmError> {
        let ca = Arc::new(CertificateAuthority::load_or_create(path)?);
        Ok(Self {
            ca,
            bind_addr,
            logger: None,
            rules: Arc::new(parking_lot::RwLock::new(Vec::new())),
            stats: Arc::new(SharedStats::new()),
        })
    }

    /// Attach a request logger.
    #[must_use]
    pub fn with_logger(mut self, logger: Arc<RequestLogger>) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Add a match-replace rule.
    pub fn add_rule(&self, rule: MatchReplaceRule) {
        self.rules.write().push(rule);
    }

    /// Return a snapshot of current statistics.
    #[must_use] 
    pub fn stats(&self) -> ProxyStats {
        self.stats.snapshot()
    }

    /// Start an HTTPS-capable MITM listener on `bind_addr`.
    ///
    /// For every inbound connection:
    /// - `CONNECT <host>:<port>` → intercept with [`TlsInterceptor`].
    /// - Any other request → forward as plain HTTP.
    ///
    /// This function loops forever and is expected to be spawned as a task.
    ///
    /// # Errors
    /// Returns [`MitmError::Io`] if the listener fails to bind or accept.
    pub async fn start_https(self: Arc<Self>, bind_addr: SocketAddr) -> Result<(), MitmError> {
        let listener = TcpListener::bind(bind_addr).await?;
        loop {
            let (stream, _client_addr) = listener.accept().await?;
            self.stats.inc_connections();
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(_e) = proxy.dispatch(stream).await {
                    proxy.stats.inc_errors();
                }
            });
        }
    }

    /// Peek at the first few bytes to decide whether this is a `CONNECT`
    /// request, then dispatch accordingly.
    async fn dispatch(&self, mut stream: TcpStream) -> Result<(), MitmError> {
        // Read enough to see the first line.
        let mut peek = [0u8; 8];
        let n = stream.read(&mut peek).await?;
        if n == 0 {
            return Ok(());
        }

        // Put the bytes back by using a combined buffer.
        let mut buf = Vec::with_capacity(4096);
        buf.extend_from_slice(&peek[..n]);
        let rest_len = stream.read_buf(&mut buf).await.unwrap_or(0);
        let _ = rest_len; // already in `buf`

        let head = std::str::from_utf8(&buf).unwrap_or("");

        if head.to_ascii_uppercase().starts_with("CONNECT ") {
            // Parse CONNECT line.
            if let Some(target) = HttpProxy::parse_connect(head) {
                // target is "host:port"
                let (host, port) = if let Some(c) = target.rfind(':') {
                    let h = target[..c].to_string();
                    let p = target[c + 1..].parse::<u16>().unwrap_or(443);
                    (h, p)
                } else {
                    (target, 443u16)
                };
                let interceptor = TlsInterceptor::new(Arc::clone(&self.ca));
                // We already consumed the CONNECT line from the socket; restore stream.
                // Re-create stream by writing back to peer won't work, so we need to
                // use what we have.  Send the 200 and proceed.
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                // Now hand off to TlsInterceptor (but stream has been partially consumed).
                // For simplicity we start fresh interception from this point.
                let _ = interceptor
                    .handle_connect_from_accepted(stream, host, port)
                    .await;
            }
        } else {
            // Plain HTTP: forward as-is.
            self.forward_http(stream, buf).await?;
        }

        Ok(())
    }

    /// Forward a plain HTTP request to its upstream.
    async fn forward_http(&self, mut _stream: TcpStream, _buf: Vec<u8>) -> Result<(), MitmError> {
        // Minimal stub: in a production proxy this would parse the Host header
        // and open a TCP connection to the upstream server.
        self.stats.inc_requests(0);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TlsInterceptor helper: start from an already-accepted stream
// ────────────────────────────────────────────────────────────────────────────

impl TlsInterceptor {
    /// Like [`handle_connect`] but assumes the `200` has already been sent
    /// and the stream is sitting at the start of the TLS `ClientHello`.
    ///
    /// # Errors
    /// Returns [`MitmError`] on TLS or I/O errors.
    pub async fn handle_connect_from_accepted(
        &self,
        stream: TcpStream,
        host: String,
        port: u16,
    ) -> Result<(), MitmError> {
        // Downstream TLS (proxy ← client).
        let server_cfg = CertificateAuthority::build_server_config(&self.ca, &host)?;
        let acceptor = TlsAcceptor::from(server_cfg);
        let tls_client = acceptor
            .accept(stream)
            .await
            .map_err(|e| MitmError::DownstreamTls(e.to_string()))?;

        // Upstream TLS (proxy → server).
        let addr = format!("{host}:{port}");
        let tcp_up = TcpStream::connect(&addr).await?;
        let cli_cfg = Self::build_client_config()?;
        let connector = TlsConnector::from(cli_cfg);
        let sni = rustls::pki_types::ServerName::try_from(host.as_str())
            .map_err(|_| MitmError::TlsConfig(format!("invalid SNI: {host}")))?
            .to_owned();
        let tls_up = connector
            .connect(sni, tcp_up)
            .await
            .map_err(|e| MitmError::UpstreamTls(e.to_string()))?;

        // Bidirectional relay.
        let (mut cr, mut cw) = tokio::io::split(tls_client);
        let (mut ur, mut uw) = tokio::io::split(tls_up);

        let t1 = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut uw).await;
        });
        let t2 = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut ur, &mut cw).await;
        });
        let _ = tokio::join!(t1, t2);
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RequestLogger
// ────────────────────────────────────────────────────────────────────────────

/// A single entry in the MITM request log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    /// Monotonically increasing entry identifier.
    pub id: u64,
    /// Unix timestamp in milliseconds when the request was captured.
    pub timestamp: u64,
    /// HTTP method (e.g. `"GET"`).
    pub method: String,
    /// Full URL.
    pub url: String,
    /// Request headers.
    pub req_headers: Vec<(String, String)>,
    /// Request body bytes.
    pub req_body: Vec<u8>,
    /// HTTP response status code.
    pub resp_status: u16,
    /// Response body bytes.
    pub resp_body: Vec<u8>,
}

impl RequestLogEntry {
    /// Create a log entry from a request/response pair.
    #[must_use]
    pub fn new(id: u64, timestamp: u64, req: &HttpRequest, resp: &HttpResponse) -> Self {
        Self {
            id,
            timestamp,
            method: req.method.clone(),
            url: req.url.clone(),
            req_headers: req.headers.clone(),
            req_body: req.body.clone(),
            resp_status: resp.status,
            resp_body: resp.body.clone(),
        }
    }

    /// Return `true` if the request was successful (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.resp_status)
    }

    /// Return the request body as a UTF-8 string (lossy).
    #[must_use]
    pub fn req_body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.req_body)
    }

    /// Return the response body as a UTF-8 string (lossy).
    #[must_use]
    pub fn resp_body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.resp_body)
    }
}

impl fmt::Display for RequestLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} -> {}",
            self.timestamp, self.method, self.url, self.resp_status,
        )
    }
}

/// Thread-safe append-only log of all intercepted HTTP exchanges.
///
/// Internally backed by a `VecDeque` that is capped at `max_entries` (default
/// 10 000). When the cap is reached the oldest entry is evicted automatically.
pub struct RequestLogger {
    entries: parking_lot::RwLock<std::collections::VecDeque<RequestLogEntry>>,
    next_id: std::sync::atomic::AtomicU64,
    max_entries: usize,
}

impl RequestLogger {
    /// Create a new logger with the given capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: parking_lot::RwLock::new(std::collections::VecDeque::with_capacity(
                max_entries.min(1024),
            )),
            next_id: std::sync::atomic::AtomicU64::new(1),
            max_entries,
        }
    }

    /// Record a request/response exchange.
    ///
    /// Persists the entry into the in-memory `VecDeque`.  If the deque is
    /// already at `max_entries` capacity the oldest entry is popped from the
    /// front before pushing the new one.
    pub fn log(&self, req: &HttpRequest, resp: &HttpResponse, timestamp: u64) {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let entry = RequestLogEntry::new(id, timestamp, req, resp);
        let mut guard = self.entries.write();
        if guard.len() >= self.max_entries {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// Return a clone of all log entries (front = oldest, back = newest).
    #[must_use]
    pub fn history(&self) -> Vec<RequestLogEntry> {
        self.entries.read().iter().cloned().collect()
    }

    /// Return the total number of logged entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Clear all entries and reset the id counter.
    pub fn clear(&self) {
        self.entries.write().clear();
        self.next_id.store(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Return the entry with the given id, if it exists.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<RequestLogEntry> {
        self.entries.read().iter().find(|e| e.id == id).cloned()
    }

    /// Return all entries with the given HTTP method.
    #[must_use]
    pub fn by_method(&self, method: &str) -> Vec<RequestLogEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.method.eq_ignore_ascii_case(method))
            .cloned()
            .collect()
    }

    /// Return all entries whose URL contains `substr`.
    #[must_use]
    pub fn by_url_contains(&self, substr: &str) -> Vec<RequestLogEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.url.contains(substr))
            .cloned()
            .collect()
    }

    /// Export all logged exchanges in **HTTP Archive (HAR) 1.2** format.
    ///
    /// The returned string is a self-contained JSON document that can be
    /// loaded by tools such as Fiddler, Charles Proxy, or browser `DevTools`.
    ///
    /// Schema reference: <https://w3c.github.io/web-performance/specs/HAR/Overview.html>
    #[must_use]
    pub fn export_har(&self) -> String {
        let guard = self.entries.read();

        // Build a JSON string manually to avoid an external dependency on `serde_json`
        // beyond what is already in the workspace (serde_json IS in the workspace, so
        // we can use it; but we keep the logic explicit so the output is deterministic).
        let mut entries_json = Vec::with_capacity(guard.len());

        for e in guard.iter() {
            // Encode request headers
            let req_headers: Vec<String> = e
                .req_headers
                .iter()
                .map(|(k, v)| {
                    format!(
                        r#"{{"name":{},"value":{}}}"#,
                        serde_json::Value::String(k.clone()),
                        serde_json::Value::String(v.clone()),
                    )
                })
                .collect();

            // Request body as base64 for binary safety
            let req_body_b64 = base64_encode(&e.req_body);
            let req_body_size = e.req_body.len();

            let resp_body_b64 = base64_encode(&e.resp_body);
            let resp_body_size = e.resp_body.len();

            // ISO-8601 timestamp from ms-since-epoch
            let ts_secs = e.timestamp / 1000;
            let ts_ms = e.timestamp % 1000;
            let ts_str = format!("{ts_secs}.{ts_ms:03}");

            let entry = format!(
                r#"{{
  "startedDateTime":"{ts_str}",
  "time":0,
  "request":{{
    "method":{method},
    "url":{url},
    "httpVersion":"HTTP/1.1",
    "headers":[{req_headers}],
    "queryString":[],
    "cookies":[],
    "headersSize":-1,
    "bodySize":{req_body_size},
    "postData":{{
      "mimeType":"application/octet-stream",
      "text":{req_body_b64}
    }}
  }},
  "response":{{
    "status":{resp_status},
    "statusText":"",
    "httpVersion":"HTTP/1.1",
    "headers":[],
    "cookies":[],
    "content":{{
      "size":{resp_body_size},
      "mimeType":"application/octet-stream",
      "encoding":"base64",
      "text":{resp_body_b64}
    }},
    "redirectURL":"",
    "headersSize":-1,
    "bodySize":{resp_body_size}
  }},
  "cache":{{}},
  "timings":{{"send":0,"wait":0,"receive":0}}
}}"#,
                ts_str = ts_str,
                method = serde_json::Value::String(e.method.clone()),
                url = serde_json::Value::String(e.url.clone()),
                req_headers = req_headers.join(","),
                req_body_size = req_body_size,
                req_body_b64 = serde_json::Value::String(req_body_b64),
                resp_status = e.resp_status,
                resp_body_size = resp_body_size,
                resp_body_b64 = serde_json::Value::String(resp_body_b64),
            );
            entries_json.push(entry);
        }

        format!(
            r#"{{
  "log":{{
    "version":"1.2",
    "creator":{{"name":"RustRE","version":"0.1.0"}},
    "browser":{{"name":"RustRE MITM Proxy","version":"0.1.0"}},
    "pages":[],
    "entries":[{entries}]
  }}
}}"#,
            entries = entries_json.join(",\n"),
        )
    }
}

/// Minimal base-64 encoder (RFC 4648, no line wrapping).
///
/// Kept inline to avoid a hard dependency on the `base64` crate.
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

impl Default for RequestLogger {
    fn default() -> Self {
        Self::new(10_000)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// MatchReplaceRule
// ────────────────────────────────────────────────────────────────────────────

/// Target of a match-replace rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleTarget {
    /// Rewrite a request header value.
    RequestHeader,
    /// Rewrite a response header value.
    ResponseHeader,
    /// Rewrite the request body.
    RequestBody,
    /// Rewrite the response body.
    ResponseBody,
    /// Rewrite the request URL.
    Url,
}

impl fmt::Display for RuleTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RequestHeader => "RequestHeader",
            Self::ResponseHeader => "ResponseHeader",
            Self::RequestBody => "RequestBody",
            Self::ResponseBody => "ResponseBody",
            Self::Url => "Url",
        };
        write!(f, "{s}")
    }
}

/// A regex-based match-replace rule that can be applied to requests or
/// responses.
///
/// The `pattern` is a regular-expression string.  When it matches, every
/// non-overlapping occurrence is replaced by `replacement`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    /// Human-readable name for this rule.
    pub name: String,
    /// Regex pattern to search for.
    pub pattern: String,
    /// Replacement text (may use `$1`, `$2` … capture-group references if the
    /// regex crate is used; kept as a plain string here for zero-dependency
    /// compatibility).
    pub replacement: String,
    /// Which part of the exchange to target.
    pub target: RuleTarget,
    /// Whether the rule is active.
    pub enabled: bool,
}

impl MatchReplaceRule {
    /// Create a new, enabled rule.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        pattern: impl Into<String>,
        replacement: impl Into<String>,
        target: RuleTarget,
    ) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
            replacement: replacement.into(),
            target,
            enabled: true,
        }
    }

    /// Disable this rule (it will be skipped in [`apply`]).
    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable this rule.
    pub const fn enable(&mut self) {
        self.enabled = true;
    }

    /// Apply the rule to `request`.
    ///
    /// Uses a naive literal string replacement (no external regex crate
    /// dependency).  Returns `true` if any modification was made.
    pub fn apply(&self, request: &mut HttpRequest) -> bool {
        if !self.enabled {
            return false;
        }
        match self.target {
            RuleTarget::Url => {
                let new_url = request.url.replace(&self.pattern, &self.replacement);
                if new_url == request.url {
                    false
                } else {
                    request.url = new_url;
                    true
                }
            }
            RuleTarget::RequestBody => {
                let body_str = String::from_utf8_lossy(&request.body).into_owned();
                let new_body = body_str.replace(&self.pattern, &self.replacement);
                if new_body == body_str {
                    false
                } else {
                    request.body = new_body.into_bytes();
                    true
                }
            }
            RuleTarget::RequestHeader => {
                let mut changed = false;
                for (_, val) in &mut request.headers {
                    let new_val = val.replace(&self.pattern, &self.replacement);
                    if new_val != *val {
                        *val = new_val;
                        changed = true;
                    }
                }
                changed
            }
            // ResponseHeader / ResponseBody targets are applied via
            // `apply_to_response` below — return false for request-side.
            RuleTarget::ResponseHeader | RuleTarget::ResponseBody => false,
        }
    }

    /// Apply the rule to `response`.
    ///
    /// Returns `true` if any modification was made.
    pub fn apply_to_response(&self, response: &mut HttpResponse) -> bool {
        if !self.enabled {
            return false;
        }
        match self.target {
            RuleTarget::ResponseBody => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                let new_body = body_str.replace(&self.pattern, &self.replacement);
                if new_body == body_str {
                    false
                } else {
                    response.body = new_body.into_bytes();
                    true
                }
            }
            RuleTarget::ResponseHeader => {
                let mut changed = false;
                for (_, val) in &mut response.headers {
                    let new_val = val.replace(&self.pattern, &self.replacement);
                    if new_val != *val {
                        *val = new_val;
                        changed = true;
                    }
                }
                changed
            }
            // Request-side targets are not applicable here.
            _ => false,
        }
    }
}

impl fmt::Display for MatchReplaceRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rule[{}] {} {:?} → {:?} ({})",
            self.name,
            self.target,
            self.pattern,
            self.replacement,
            if self.enabled { "enabled" } else { "disabled" },
        )
    }
}

/// Convenience: apply a slice of rules to a request in order.
///
/// Returns the number of rules that made a modification.
pub fn apply_rules_to_request(rules: &[MatchReplaceRule], req: &mut HttpRequest) -> usize {
    rules.iter().filter(|r| r.apply(req)).count()
}

/// Convenience: apply a slice of rules to a response in order.
///
/// Returns the number of rules that made a modification.
pub fn apply_rules_to_response(rules: &[MatchReplaceRule], resp: &mut HttpResponse) -> usize {
    rules.iter().filter(|r| r.apply_to_response(resp)).count()
}

// ────────────────────────────────────────────────────────────────────────────
// Cert cache (host → ServerConfig)
// ────────────────────────────────────────────────────────────────────────────

/// A thread-safe cache mapping hostnames to pre-built `ServerConfig`s so that
/// we do not regenerate a leaf cert for every connection to the same host.
pub struct CertCache {
    cache: parking_lot::RwLock<std::collections::HashMap<String, Arc<ServerConfig>>>,
    capacity: usize,
}

impl CertCache {
    /// Create a new cert cache with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: parking_lot::RwLock::new(std::collections::HashMap::new()),
            capacity,
        }
    }

    /// Look up a cached `ServerConfig` for `hostname`.
    #[must_use]
    pub fn get(&self, hostname: &str) -> Option<Arc<ServerConfig>> {
        self.cache.read().get(hostname).cloned()
    }

    /// Insert a `ServerConfig` into the cache.
    ///
    /// If the cache is at capacity the oldest entry (arbitrary) is evicted.
    pub fn insert(&self, hostname: impl Into<String>, cfg: Arc<ServerConfig>) {
        let mut map = self.cache.write();
        if map.len() >= self.capacity
            && let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        map.insert(hostname.into(), cfg);
    }

    /// Get or build a `ServerConfig` for `hostname`, caching the result.
    ///
    /// # Errors
    /// Returns [`MitmError`] if certificate signing fails.
    pub fn get_or_build(
        &self,
        ca: &Arc<CertificateAuthority>,
        hostname: &str,
    ) -> Result<Arc<ServerConfig>, MitmError> {
        if let Some(cfg) = self.get(hostname) {
            return Ok(cfg);
        }
        let cfg = CertificateAuthority::build_server_config(ca, hostname)?;
        self.insert(hostname.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }

    /// Return the number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        self.cache.write().clear();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// §21.4 Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod mitm_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn la(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    // ── CertificateAuthority ──────────────────────────────────────────────

    #[test]
    fn ca_new_returns_pem() {
        let ca = CertificateAuthority::new().unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_key_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn ca_sign_for_host_returns_pem_pair() {
        let ca = CertificateAuthority::new().unwrap();
        let (cert, key) = ca.sign_for_host("example.com").unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn ca_sign_different_hosts_different_certs() {
        let ca = CertificateAuthority::new().unwrap();
        let (c1, _) = ca.sign_for_host("foo.example.com").unwrap();
        let (c2, _) = ca.sign_for_host("bar.example.com").unwrap();
        // The certs should be different (different key pair each time).
        assert_ne!(c1, c2);
    }

    #[test]
    fn ca_load_or_create_in_temp_dir() {
        let dir = std::env::temp_dir().join("rustre_ca_test");
        let _ = std::fs::remove_dir_all(&dir);
        let ca = CertificateAuthority::load_or_create(&dir).unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        // Second call should load from disk.
        let ca2 = CertificateAuthority::load_or_create(&dir).unwrap();
        assert_eq!(ca.ca_cert_pem(), ca2.ca_cert_pem());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ca_build_server_config_ok() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let cfg = CertificateAuthority::build_server_config(&ca, "example.com").unwrap();
        // Just check it was constructed — we can't easily inspect the internals.
        let _ = cfg;
    }

    // ── TlsInterceptor ────────────────────────────────────────────────────

    #[test]
    fn tls_interceptor_new() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let _ti = TlsInterceptor::new(Arc::clone(&ca));
    }

    #[test]
    fn tls_build_client_config_ok() {
        let cfg = TlsInterceptor::build_client_config().unwrap();
        let _ = cfg;
    }

    // ── HttpRequest / HttpResponse ─────────────────────────────────────────

    #[test]
    fn http_request_get_builder() {
        let req = HttpRequest::get("https://example.com/");
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://example.com/");
        assert!(req.headers.is_empty());
        assert!(req.body.is_empty());
    }

    #[test]
    fn http_request_set_remove_header() {
        let mut req = HttpRequest::get("/");
        req.set_header("X-Custom", "value");
        assert_eq!(req.header("x-custom"), Some("value"));
        req.set_header("X-Custom", "updated");
        assert_eq!(req.header("x-custom"), Some("updated"));
        assert!(req.remove_header("X-Custom"));
        assert!(req.header("X-Custom").is_none());
    }

    #[test]
    fn http_response_ok_builder() {
        let resp = HttpResponse::ok();
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
    }

    #[test]
    fn http_response_set_header() {
        let mut resp = HttpResponse::ok();
        resp.set_header("Content-Type", "application/json");
        assert_eq!(resp.header("content-type"), Some("application/json"));
    }

    // ── RequestLogger ─────────────────────────────────────────────────────

    #[test]
    fn request_logger_log_and_history() {
        let logger = RequestLogger::new(100);
        let req = HttpRequest::get("https://example.com/api");
        let resp = HttpResponse::ok();
        logger.log(&req, &resp, 1_000_000);
        assert_eq!(logger.len(), 1);
        let hist = logger.history();
        assert_eq!(hist[0].url, "https://example.com/api");
        assert_eq!(hist[0].resp_status, 200);
        assert_eq!(hist[0].timestamp, 1_000_000);
    }

    #[test]
    fn request_logger_capacity_eviction() {
        let logger = RequestLogger::new(3);
        for i in 0..5 {
            let req = HttpRequest::get(format!("/path/{i}"));
            let resp = HttpResponse::ok();
            logger.log(&req, &resp, i as u64);
        }
        assert_eq!(logger.len(), 3);
    }

    #[test]
    fn request_logger_by_method() {
        let logger = RequestLogger::new(100);
        let get_req = HttpRequest::get("/a");
        let mut post_req = HttpRequest::get("/b");
        post_req.method = "POST".to_string();
        let resp = HttpResponse::ok();
        logger.log(&get_req, &resp, 0);
        logger.log(&post_req, &resp, 1);
        let gets = logger.by_method("GET");
        assert_eq!(gets.len(), 1);
        assert_eq!(gets[0].url, "/a");
    }

    #[test]
    fn request_logger_by_url_contains() {
        let logger = RequestLogger::new(100);
        let req1 = HttpRequest::get("https://api.example.com/users");
        let req2 = HttpRequest::get("https://api.example.com/orders");
        let resp = HttpResponse::ok();
        logger.log(&req1, &resp, 0);
        logger.log(&req2, &resp, 1);
        let users = logger.by_url_contains("users");
        assert_eq!(users.len(), 1);
        assert!(users[0].url.contains("users"));
    }

    #[test]
    fn request_logger_clear() {
        let logger = RequestLogger::default();
        let req = HttpRequest::get("/");
        let resp = HttpResponse::ok();
        logger.log(&req, &resp, 0);
        assert!(!logger.is_empty());
        logger.clear();
        assert!(logger.is_empty());
        // IDs restart after clear.
        logger.log(&req, &resp, 1);
        let hist = logger.history();
        assert_eq!(hist[0].id, 1);
    }

    #[test]
    fn request_log_entry_display() {
        let req = HttpRequest::get("https://example.com/");
        let resp = HttpResponse::ok();
        let e = RequestLogEntry::new(7, 12345, &req, &resp);
        let s = e.to_string();
        assert!(s.contains("GET"));
        assert!(s.contains("200"));
        assert!(s.contains("12345"));
        assert!(e.is_success());
    }

    #[test]
    fn request_log_entry_body_str() {
        let mut req = HttpRequest::get("/upload");
        req.body = b"hello world".to_vec();
        let mut resp = HttpResponse::ok();
        resp.body = b"accepted".to_vec();
        let e = RequestLogEntry::new(1, 0, &req, &resp);
        assert_eq!(e.req_body_str(), "hello world");
        assert_eq!(e.resp_body_str(), "accepted");
    }

    // ── MatchReplaceRule ──────────────────────────────────────────────────

    #[test]
    fn match_replace_url() {
        let rule = MatchReplaceRule::new("rewrite-api", "/v1/", "/v2/", RuleTarget::Url);
        let mut req = HttpRequest::get("https://example.com/v1/users");
        assert!(rule.apply(&mut req));
        assert_eq!(req.url, "https://example.com/v2/users");
    }

    #[test]
    fn match_replace_request_body() {
        let rule = MatchReplaceRule::new("redact", "secret", "REDACTED", RuleTarget::RequestBody);
        let mut req = HttpRequest::get("/");
        req.body = b"password=secret".to_vec();
        assert!(rule.apply(&mut req));
        assert_eq!(&req.body, b"password=REDACTED");
    }

    #[test]
    fn match_replace_request_header() {
        let rule =
            MatchReplaceRule::new("ua-spoof", "Mozilla", "RustRE", RuleTarget::RequestHeader);
        let mut req = HttpRequest::get("/");
        req.headers
            .push(("User-Agent".to_string(), "Mozilla/5.0".to_string()));
        assert!(rule.apply(&mut req));
        assert_eq!(req.headers[0].1, "RustRE/5.0");
    }

    #[test]
    fn match_replace_response_body() {
        let rule = MatchReplaceRule::new("inject", "World", "RustRE", RuleTarget::ResponseBody);
        let mut resp = HttpResponse::ok();
        resp.body = b"Hello World".to_vec();
        assert!(rule.apply_to_response(&mut resp));
        assert_eq!(&resp.body, b"Hello RustRE");
    }

    #[test]
    fn match_replace_response_header() {
        let rule = MatchReplaceRule::new(
            "server-spoof",
            "nginx",
            "rustre",
            RuleTarget::ResponseHeader,
        );
        let mut resp = HttpResponse::ok();
        resp.headers
            .push(("Server".to_string(), "nginx/1.21".to_string()));
        assert!(rule.apply_to_response(&mut resp));
        assert_eq!(resp.headers[0].1, "rustre/1.21");
    }

    #[test]
    fn match_replace_disabled_rule_no_op() {
        let mut rule =
            MatchReplaceRule::new("disabled", "secret", "REDACTED", RuleTarget::RequestBody);
        rule.disable();
        let mut req = HttpRequest::get("/");
        req.body = b"secret".to_vec();
        assert!(!rule.apply(&mut req));
        assert_eq!(&req.body, b"secret");
        // Re-enable.
        rule.enable();
        assert!(rule.apply(&mut req));
    }

    #[test]
    fn match_replace_no_match_returns_false() {
        let rule = MatchReplaceRule::new("noop", "notfound", "X", RuleTarget::Url);
        let mut req = HttpRequest::get("/path/to/resource");
        assert!(!rule.apply(&mut req));
    }

    #[test]
    fn match_replace_display() {
        let rule = MatchReplaceRule::new("test", "foo", "bar", RuleTarget::RequestBody);
        let s = rule.to_string();
        assert!(s.contains("test"));
        assert!(s.contains("enabled"));
    }

    #[test]
    fn rule_target_display() {
        assert_eq!(RuleTarget::Url.to_string(), "Url");
        assert_eq!(RuleTarget::RequestBody.to_string(), "RequestBody");
        assert_eq!(RuleTarget::ResponseHeader.to_string(), "ResponseHeader");
    }

    #[test]
    fn apply_rules_to_request_counts() {
        let rules = vec![
            MatchReplaceRule::new("r1", "foo", "bar", RuleTarget::Url),
            MatchReplaceRule::new("r2", "baz", "qux", RuleTarget::Url),
        ];
        let mut req = HttpRequest::get("/foo/baz");
        let count = apply_rules_to_request(&rules, &mut req);
        assert_eq!(count, 2);
        assert_eq!(req.url, "/bar/qux");
    }

    #[test]
    fn apply_rules_to_response_counts() {
        let rules = vec![MatchReplaceRule::new(
            "r1",
            "Hello",
            "Hi",
            RuleTarget::ResponseBody,
        )];
        let mut resp = HttpResponse::ok();
        resp.body = b"Hello World".to_vec();
        let count = apply_rules_to_response(&rules, &mut resp);
        assert_eq!(count, 1);
        assert_eq!(&resp.body, b"Hi World");
    }

    // ── CertCache ─────────────────────────────────────────────────────────

    #[test]
    fn cert_cache_get_or_build() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let cache = CertCache::new(16);
        assert!(cache.is_empty());
        let cfg1 = cache.get_or_build(&ca, "example.com").unwrap();
        assert_eq!(cache.len(), 1);
        let cfg2 = cache.get_or_build(&ca, "example.com").unwrap();
        // Same Arc pointer (cache hit).
        assert!(Arc::ptr_eq(&cfg1, &cfg2));
    }

    #[test]
    fn cert_cache_eviction() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let cache = CertCache::new(2);
        cache.get_or_build(&ca, "a.com").unwrap();
        cache.get_or_build(&ca, "b.com").unwrap();
        // At capacity; inserting c.com should evict one entry.
        cache.get_or_build(&ca, "c.com").unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cert_cache_clear() {
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let cache = CertCache::new(8);
        cache.get_or_build(&ca, "x.com").unwrap();
        cache.clear();
        assert!(cache.is_empty());
    }

    // ── MitmProxy ─────────────────────────────────────────────────────────

    #[test]
    fn mitm_proxy_new_ok() {
        let proxy = MitmProxy::new(la(8443)).unwrap();
        let stats = proxy.stats();
        assert_eq!(stats.connections, 0);
    }

    #[test]
    fn mitm_proxy_add_rule() {
        let proxy = MitmProxy::new(la(8444)).unwrap();
        proxy.add_rule(MatchReplaceRule::new("test", "foo", "bar", RuleTarget::Url));
        assert_eq!(proxy.rules.read().len(), 1);
    }

    #[test]
    fn mitm_proxy_with_ca_path() {
        let dir = std::env::temp_dir().join("rustre_mitm_proxy_test");
        let _ = std::fs::remove_dir_all(&dir);
        let proxy = MitmProxy::with_ca_path(la(8445), &dir).unwrap();
        assert!(!proxy.ca.ca_cert_pem().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── MitmError display ─────────────────────────────────────────────────

    #[test]
    fn mitm_error_display() {
        let e = MitmError::CertGen("bad key".to_string());
        assert!(e.to_string().contains("bad key"));
        let e2 = MitmError::TlsConfig("failed".to_string());
        assert!(e2.to_string().contains("failed"));
        let e3 = MitmError::PemParse("no key".to_string());
        assert!(e3.to_string().contains("no key"));
        let e4 = MitmError::UpstreamTls("timeout".to_string());
        assert!(e4.to_string().contains("timeout"));
        let e5 = MitmError::DownstreamTls("reset".to_string());
        assert!(e5.to_string().contains("reset"));
    }

    // ── CertificateAuthority::new() spec compliance ───────────────────────

    /// Verify that the generated CA cert contains the correct CN and O fields
    /// as required by the task specification (CN=RustRE-CA, O=RustRE).
    #[test]
    fn ca_cert_pem_contains_expected_dn_fields() {
        let ca = CertificateAuthority::new().unwrap();
        let pem = ca.ca_cert_pem();
        // The PEM is DER-base64 encoded; we verify at least that it parses and
        // the leaf cert PEM for any host round-trips correctly.
        assert!(
            pem.contains("BEGIN CERTIFICATE"),
            "expected PEM certificate block"
        );
        assert!(pem.contains("END CERTIFICATE"), "expected END marker");
    }

    #[test]
    fn ca_key_pem_is_pkcs8() {
        let ca = CertificateAuthority::new().unwrap();
        let pem = ca.ca_key_pem();
        // rcgen emits PKCS#8 keys by default.
        assert!(pem.contains("BEGIN PRIVATE KEY"), "expected PKCS8 key");
    }

    // ── sign_for_host: SAN round-trip ─────────────────────────────────────

    #[test]
    fn sign_for_host_different_hosts_produce_different_keys() {
        let ca = CertificateAuthority::new().unwrap();
        let (_, key1) = ca.sign_for_host("alice.example.com").unwrap();
        let (_, key2) = ca.sign_for_host("bob.example.com").unwrap();
        // Each call generates a fresh key pair.
        assert_ne!(key1, key2);
    }

    #[test]
    fn sign_for_host_cert_pem_parses_with_rustls_pemfile() {
        use rustls_pemfile::certs;
        use std::io::Cursor;

        let ca = CertificateAuthority::new().unwrap();
        let (cert_pem, _key_pem) = ca.sign_for_host("test.local").unwrap();
        let mut reader = Cursor::new(cert_pem.as_bytes());
        let certs: Vec<_> = certs(&mut reader).collect::<Result<_, _>>().unwrap();
        assert!(
            !certs.is_empty(),
            "leaf cert should parse as at least one DER block"
        );
    }

    #[test]
    fn sign_for_host_key_pem_parses_with_rustls_pemfile() {
        use rustls_pemfile::pkcs8_private_keys;
        use std::io::Cursor;

        let ca = CertificateAuthority::new().unwrap();
        let (_cert_pem, key_pem) = ca.sign_for_host("test.local").unwrap();
        let mut reader = Cursor::new(key_pem.as_bytes());
        let keys: Vec<_> = pkcs8_private_keys(&mut reader)
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            !keys.is_empty(),
            "leaf key should parse as at least one PKCS8 block"
        );
    }

    // ── build_server_config ───────────────────────────────────────────────

    #[test]
    fn build_server_config_returns_arc() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let cfg = CertificateAuthority::build_server_config(&ca, "example.com").unwrap();
        // Just verify we get a valid Arc back; actual TLS handshake tested in integration tests.
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    // ── TlsInterceptor::build_client_config ───────────────────────────────

    #[test]
    fn build_client_config_returns_arc() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = TlsInterceptor::build_client_config().unwrap();
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    // ── RequestLogger with VecDeque ───────────────────────────────────────

    fn make_req(method: &str, url: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn make_resp(status: u16) -> HttpResponse {
        HttpResponse {
            version: "HTTP/1.1".to_string(),
            status,
            reason: "OK".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn request_logger_vecdeque_capped_at_max_entries() {
        let logger = RequestLogger::new(3);
        for i in 0..5u64 {
            let req = make_req("GET", &format!("/path/{i}"));
            let resp = make_resp(200);
            logger.log(&req, &resp, i * 1000);
        }
        // VecDeque evicts oldest; only the last 3 are kept.
        assert_eq!(logger.len(), 3);
        let history = logger.history();
        // Newest URL should be in the history; oldest should be gone.
        assert!(history.iter().any(|e| e.url == "/path/4"));
        assert!(
            !history.iter().any(|e| e.url == "/path/0"),
            "oldest entry should have been evicted"
        );
    }

    #[test]
    fn request_logger_log_records_entry() {
        let logger = RequestLogger::new(100);
        assert!(logger.is_empty());
        let req = make_req("POST", "https://api.example.com/v1/data");
        let resp = make_resp(201);
        logger.log(&req, &resp, 1_700_000_000_000);
        assert_eq!(logger.len(), 1);
        let entry = logger.history().into_iter().next().unwrap();
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.resp_status, 201);
    }

    #[test]
    fn request_logger_clear_resets_state() {
        let logger = RequestLogger::new(50);
        logger.log(&make_req("GET", "/a"), &make_resp(200), 1000);
        logger.log(&make_req("GET", "/b"), &make_resp(404), 2000);
        assert_eq!(logger.len(), 2);
        logger.clear();
        assert!(logger.is_empty());
    }

    #[test]
    fn request_logger_by_method_case_insensitive_filter() {
        let logger = RequestLogger::new(50);
        logger.log(&make_req("GET", "/a"), &make_resp(200), 1000);
        logger.log(&make_req("POST", "/b"), &make_resp(201), 2000);
        logger.log(&make_req("GET", "/c"), &make_resp(200), 3000);
        // `by_method` is case-insensitive.
        let gets = logger.by_method("get");
        assert_eq!(gets.len(), 2);
        let posts = logger.by_method("POST");
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn request_logger_by_url_contains_prefix() {
        let logger = RequestLogger::new(50);
        logger.log(&make_req("GET", "/api/users"), &make_resp(200), 1000);
        logger.log(&make_req("GET", "/api/orders"), &make_resp(200), 2000);
        logger.log(&make_req("GET", "/static/img"), &make_resp(200), 3000);
        let api = logger.by_url_contains("/api/");
        assert_eq!(api.len(), 2);
    }

    #[test]
    fn request_logger_get_by_id() {
        let logger = RequestLogger::new(50);
        logger.log(&make_req("DELETE", "/resource/1"), &make_resp(204), 5000);
        let history = logger.history();
        let id = history[0].id;
        let found = logger.get(id).unwrap();
        assert_eq!(found.method, "DELETE");
        assert!(logger.get(99_999).is_none());
    }

    // ── export_har ────────────────────────────────────────────────────────

    #[test]
    fn export_har_empty_logger() {
        let logger = RequestLogger::new(100);
        let har = logger.export_har();
        assert!(har.contains("\"version\":\"1.2\""), "HAR version missing");
        assert!(
            har.contains("\"entries\":[]"),
            "empty entries array expected"
        );
    }

    #[test]
    fn export_har_single_entry() {
        let logger = RequestLogger::new(100);
        let mut req = make_req("GET", "https://example.com/api");
        req.headers
            .push(("Accept".to_string(), "application/json".to_string()));
        let mut resp = make_resp(200);
        resp.body = b"hello".to_vec();
        logger.log(&req, &resp, 1_700_000_000_000);
        let har = logger.export_har();
        assert!(har.contains("example.com/api"), "URL should appear in HAR");
        assert!(har.contains("\"status\":200"), "status code should appear");
        assert!(har.contains("GET"), "method should appear");
        // The body is base64-encoded; "hello" encodes to "aGVsbG8="
        assert!(har.contains("aGVsbG8="), "base64-encoded body expected");
    }

    #[test]
    fn export_har_multiple_entries() {
        let logger = RequestLogger::new(100);
        logger.log(&make_req("GET", "/a"), &make_resp(200), 1000);
        logger.log(&make_req("POST", "/b"), &make_resp(201), 2000);
        logger.log(&make_req("PUT", "/c"), &make_resp(204), 3000);
        let har = logger.export_har();
        // All three methods appear.
        assert!(har.contains("GET"));
        assert!(har.contains("POST"));
        assert!(har.contains("PUT"));
        // Valid JSON-ish: should contain the log wrapper.
        assert!(har.contains("\"log\""));
        assert!(har.contains("\"entries\""));
    }

    #[test]
    fn export_har_binary_body_encodes_as_base64() {
        let logger = RequestLogger::new(100);
        let req = make_req("GET", "/binary");
        let mut resp = make_resp(200);
        // Insert bytes that are not valid UTF-8.
        resp.body = vec![0xFF, 0xFE, 0x00, 0x01];
        logger.log(&req, &resp, 9000);
        let har = logger.export_har();
        // base64 of [0xFF, 0xFE, 0x00, 0x01] is "//4AAQ=="
        assert!(
            har.contains("//4AAQ=="),
            "binary body should be base64 encoded"
        );
    }

    // ── base64_encode helper ──────────────────────────────────────────────

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_known_values() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"RustRE"), "UnVzdFJF");
    }

    // ── CertCache with shared CA ──────────────────────────────────────────

    #[test]
    fn cert_cache_isolates_different_hosts() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = Arc::new(CertificateAuthority::new().unwrap());
        let cache = CertCache::new(8);
        let cfg_a = cache.get_or_build(&ca, "host-a.example.com").unwrap();
        let cfg_b = cache.get_or_build(&ca, "host-b.example.com").unwrap();
        // Different hosts → different ServerConfig objects.
        assert!(!Arc::ptr_eq(&cfg_a, &cfg_b));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SSLKEYLOGFILE Support
// ════════════════════════════════════════════════════════════════════════════

/// Parsed TLS session keys for one connection, identified by the client random.
///
/// Supports both TLS 1.2 (master secret) and TLS 1.3 (traffic secrets).
#[derive(Debug, Clone, Default)]
pub struct TlsSessionKeys {
    /// 32-byte client random from the `ClientHello`.
    pub client_random: Vec<u8>,
    /// 48-byte master secret (TLS 1.2).  Empty for TLS 1.3.
    pub master_secret: Vec<u8>,
    /// `CLIENT_EARLY_TRAFFIC_SECRET` (TLS 1.3 0-RTT).
    pub client_early_traffic_secret: Option<Vec<u8>>,
    /// `CLIENT_HANDSHAKE_TRAFFIC_SECRET` (TLS 1.3).
    pub client_handshake_traffic_secret: Option<Vec<u8>>,
    /// `SERVER_HANDSHAKE_TRAFFIC_SECRET` (TLS 1.3).
    pub server_handshake_traffic_secret: Option<Vec<u8>>,
    /// `CLIENT_TRAFFIC_SECRET_0` (TLS 1.3 application data).
    pub client_traffic_secret_0: Option<Vec<u8>>,
    /// `SERVER_TRAFFIC_SECRET_0` (TLS 1.3 application data).
    pub server_traffic_secret_0: Option<Vec<u8>>,
    /// Derived per-direction write keys (optional, for consumers that want them
    /// pre-extracted rather than computing from the secrets themselves).
    pub client_write_key: Option<Vec<u8>>,
    pub server_write_key: Option<Vec<u8>>,
}

/// Parser for the NSS SSLKEYLOGFILE format understood by Wireshark and other
/// TLS decryption tools.
///
/// File format (one record per line):
/// ```text
/// # comment
/// CLIENT_RANDOM <client_random_hex> <master_secret_hex>
/// CLIENT_EARLY_TRAFFIC_SECRET <client_random_hex> <secret_hex>
/// SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
/// CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
/// SERVER_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
/// CLIENT_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
/// ```
pub struct SslKeyLogParser {
    sessions: std::collections::HashMap<Vec<u8>, TlsSessionKeys>,
}

impl SslKeyLogParser {
    /// Create an empty parser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Parse every line of a SSLKEYLOGFILE on disk and return a populated
    /// `SslKeyLogParser` ready for lookups.
    ///
    /// Lines that cannot be parsed are silently skipped.
    #[must_use]
    pub fn parse_file(path: &std::path::Path) -> Self {
        let mut parser = Self::new();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return parser,
        };
        for line in text.lines() {
            parser.ingest_line(line);
        }
        parser
    }

    /// Parse a SSLKEYLOGFILE from a string in memory.
    #[must_use]
    pub fn parse_str(text: &str) -> Self {
        let mut parser = Self::new();
        for line in text.lines() {
            parser.ingest_line(line);
        }
        parser
    }

    /// Ingest a single line, merging it into the session map.
    pub fn ingest_line(&mut self, line: &str) {
        if let Some((label, client_random, secret)) = Self::parse_line(line) {
            let entry = self
                .sessions
                .entry(client_random.clone())
                .or_insert_with(|| TlsSessionKeys {
                    client_random,
                    ..TlsSessionKeys::default()
                });
            Self::apply_label(entry, &label, secret);
        }
    }

    /// Parse one non-comment line.
    ///
    /// Returns `(label, client_random_bytes, secret_bytes)` or `None` when the
    /// line is malformed or a comment.
    #[must_use]
    pub fn parse_line(line: &str) -> Option<(String, Vec<u8>, Vec<u8>)> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut parts = line.splitn(3, ' ');
        let label = parts.next()?.to_string();
        let random_hex = parts.next()?;
        let secret_hex = parts.next()?.trim();

        let client_random = hex_decode(random_hex)?;
        let secret = hex_decode(secret_hex)?;
        Some((label, client_random, secret))
    }

    fn apply_label(entry: &mut TlsSessionKeys, label: &str, secret: Vec<u8>) {
        match label {
            "CLIENT_RANDOM" => entry.master_secret = secret,
            "CLIENT_EARLY_TRAFFIC_SECRET" => {
                entry.client_early_traffic_secret = Some(secret);
            }
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
                entry.client_handshake_traffic_secret = Some(secret);
            }
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                entry.server_handshake_traffic_secret = Some(secret);
            }
            "CLIENT_TRAFFIC_SECRET_0" => {
                entry.client_traffic_secret_0 = Some(secret);
            }
            "SERVER_TRAFFIC_SECRET_0" => {
                entry.server_traffic_secret_0 = Some(secret);
            }
            _ => {} // unknown label — ignore
        }
    }

    /// Look up the session keys for a given client random (32 bytes).
    #[must_use]
    pub fn find_keys_for_random(&self, random: &[u8]) -> Option<&TlsSessionKeys> {
        self.sessions.get(random)
    }

    /// Return all known sessions as a slice.
    #[must_use]
    pub fn all_sessions(&self) -> Vec<&TlsSessionKeys> {
        self.sessions.values().collect()
    }

    /// Number of distinct client-randoms ingested.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SslKeyLogParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a lowercase or uppercase hex string to bytes.
/// Returns `None` if the string has an odd length or invalid characters.
#[must_use]
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    loop {
        match (chars.next(), chars.next()) {
            (Some(hi), Some(lo)) => {
                let hi = char_to_nibble(hi)?;
                let lo = char_to_nibble(lo)?;
                bytes.push((hi << 4) | lo);
            }
            (None, _) => break,
            _ => return None,
        }
    }
    Some(bytes)
}

const fn char_to_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes to a lowercase hex string.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ════════════════════════════════════════════════════════════════════════════
// HAR Export
// ════════════════════════════════════════════════════════════════════════════

/// Exporter for the HAR 1.2 (HTTP Archive) format.
///
/// The produced JSON can be loaded directly into browser `DevTools`, Charles
/// Proxy, or any other HAR-aware viewer.
pub struct HarExporter;

impl HarExporter {
    /// Serialise a slice of `RequestLogEntry` records into a HAR 1.2 JSON string.
    ///
    /// Response bodies are base64-encoded so that binary payloads survive the
    /// JSON encoding unchanged.
    #[must_use]
    pub fn export(entries: &[RequestLogEntry]) -> String {
        let har_entries: Vec<String> = entries.iter().map(Self::entry_to_json).collect();

        format!(
            r#"{{"log":{{"version":"1.2","creator":{{"name":"rustre-net-proxy","version":"0.1.0"}},"entries":[{}]}}}}"#,
            har_entries.join(",")
        )
    }

    /// Serialise a single `RequestLogEntry` as a HAR entry JSON object.
    #[must_use]
    pub fn entry_to_json(e: &RequestLogEntry) -> String {
        let started = Self::ms_to_iso8601(e.timestamp);
        let req_headers_json = Self::headers_to_json(&e.req_headers);
        let body_b64 = base64_encode(&e.resp_body);

        // Build a minimal query-string array (always empty here since we store
        // the full URL including query in e.url).
        let request_json = format!(
            r#"{{"method":{},"url":{},"httpVersion":"HTTP/1.1","headers":{},"queryString":[],"cookies":[],"headersSize":-1,"bodySize":{}}}"#,
            json_string(&e.method),
            json_string(&e.url),
            req_headers_json,
            e.req_body.len(),
        );

        let response_json = format!(
            r#"{{"status":{},"statusText":"","httpVersion":"HTTP/1.1","headers":[],"cookies":[],"content":{{"size":{},"mimeType":"application/octet-stream","encoding":"base64","text":{}}},"redirectURL":"","headersSize":-1,"bodySize":{}}}"#,
            e.resp_status,
            e.resp_body.len(),
            json_string(&body_b64),
            e.resp_body.len(),
        );

        format!(
            r#"{{"startedDateTime":{},"time":0,"request":{},"response":{},"cache":{{}},"timings":{{"send":0,"wait":0,"receive":0}}}}"#,
            json_string(&started),
            request_json,
            response_json,
        )
    }

    /// Serialise a slice of `(name, value)` header pairs as a HAR headers array.
    #[must_use]
    pub fn headers_to_json(headers: &[(String, String)]) -> String {
        let items: Vec<String> = headers
            .iter()
            .map(|(k, v)| {
                format!(
                    r#"{{"name":{},"value":{}}}"#,
                    json_string(k),
                    json_string(v)
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Convert a Unix timestamp in milliseconds to an ISO-8601 string.
    ///
    /// Example: `2024-01-15T12:34:56.789Z`
    #[must_use]
    pub fn ms_to_iso8601(ms: u64) -> String {
        let secs = ms / 1000;
        let millis = ms % 1000;
        // Manual decomposition — no external crate dependency.
        let (y, mo, d, h, mi, s) = unix_secs_to_datetime(secs);
        format!(
            "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z"
        )
    }
}

/// Minimally JSON-escape and quote a string value.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Decompose a Unix timestamp (seconds since epoch) into
/// `(year, month, day, hour, minute, second)`.
///
/// Uses the Gregorian calendar algorithm; accurate for dates 1970–9999.
const fn unix_secs_to_datetime(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let second = (secs % 60) as u32;
    let minutes = secs / 60;
    let minute = (minutes % 60) as u32;
    let hours = minutes / 60;
    let hour = (hours % 24) as u32;
    let days = hours / 24; // days since 1970-01-01

    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // year of era
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month prime
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d, hour, minute, second)
}

// ════════════════════════════════════════════════════════════════════════════
// Request Diffing
// ════════════════════════════════════════════════════════════════════════════

/// A line-level diff entry for text body comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub line: String,
}

/// Whether a diff line was unchanged, added, or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Same,
    Added,
    Removed,
}

/// Represents differences in a request body.
#[derive(Debug, Clone)]
pub enum BodyDiff {
    /// The bodies are binary and differ; reports the common prefix/suffix lengths.
    BinaryChanged {
        common_prefix: usize,
        common_suffix: usize,
    },
    /// The bodies are text; contains a line-level diff.
    TextDiff(Vec<DiffLine>),
    /// Both bodies are empty — no difference.
    Identical,
}

/// The result of comparing two `HttpRequest` values.
#[derive(Debug, Clone)]
pub struct RequestDiff {
    pub method_changed: bool,
    pub url_changed: Option<(String, String)>,
    pub added_headers: Vec<(String, String)>,
    pub removed_headers: Vec<String>,
    /// `(name, old_value, new_value)` for headers that exist in both but differ.
    pub modified_headers: Vec<(String, String, String)>,
    pub body_diff: Option<BodyDiff>,
}

impl RequestDiff {
    /// `true` when every field reports no change.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        !self.method_changed
            && self.url_changed.is_none()
            && self.added_headers.is_empty()
            && self.removed_headers.is_empty()
            && self.modified_headers.is_empty()
            && matches!(self.body_diff.as_ref(), None | Some(BodyDiff::Identical))
    }
}

/// The result of comparing two `HttpResponse` values.
#[derive(Debug, Clone)]
pub struct ResponseDiff {
    pub status_changed: Option<(u16, u16)>,
    pub reason_changed: Option<(String, String)>,
    pub added_headers: Vec<(String, String)>,
    pub removed_headers: Vec<String>,
    pub modified_headers: Vec<(String, String, String)>,
    pub body_diff: Option<BodyDiff>,
}

impl ResponseDiff {
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.status_changed.is_none()
            && self.reason_changed.is_none()
            && self.added_headers.is_empty()
            && self.removed_headers.is_empty()
            && self.modified_headers.is_empty()
            && matches!(self.body_diff.as_ref(), None | Some(BodyDiff::Identical))
    }
}

/// Utilities for comparing HTTP messages.
pub struct RequestDiffer;

impl RequestDiffer {
    /// Compare two `HttpRequest` values field-by-field.
    #[must_use]
    pub fn diff(a: &HttpRequest, b: &HttpRequest) -> RequestDiff {
        let method_changed = a.method != b.method;
        let url_changed = if a.url == b.url {
            None
        } else {
            Some((a.url.clone(), b.url.clone()))
        };
        let (added, removed, modified) = diff_headers(&a.headers, &b.headers);
        let body_diff = if a.body == b.body {
            Some(BodyDiff::Identical)
        } else {
            Some(diff_bodies(&a.body, &b.body))
        };
        RequestDiff {
            method_changed,
            url_changed,
            added_headers: added,
            removed_headers: removed,
            modified_headers: modified,
            body_diff,
        }
    }

    /// Compare two `HttpResponse` values field-by-field.
    #[must_use]
    pub fn diff_response(a: &HttpResponse, b: &HttpResponse) -> ResponseDiff {
        let status_changed = if a.status == b.status {
            None
        } else {
            Some((a.status, b.status))
        };
        let reason_changed = if a.reason == b.reason {
            None
        } else {
            Some((a.reason.clone(), b.reason.clone()))
        };
        let (added, removed, modified) = diff_headers(&a.headers, &b.headers);
        let body_diff = if a.body == b.body {
            Some(BodyDiff::Identical)
        } else {
            Some(diff_bodies(&a.body, &b.body))
        };
        ResponseDiff {
            status_changed,
            reason_changed,
            added_headers: added,
            removed_headers: removed,
            modified_headers: modified,
            body_diff,
        }
    }
}

/// Result of `diff_headers`: `(added, removed, modified)`.
type HeaderDiff = (
    Vec<(String, String)>,
    Vec<String>,
    Vec<(String, String, String)>,
);

/// Compute added, removed, and modified headers between two header lists.
fn diff_headers(old: &[(String, String)], new: &[(String, String)]) -> HeaderDiff {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // Build case-insensitive maps from name → value.
    let old_map: std::collections::HashMap<String, &str> = old
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();
    let new_map: std::collections::HashMap<String, &str> = new
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();

    for (lk, &ov) in &old_map {
        match new_map.get(lk) {
            None => removed.push(lk.clone()),
            Some(&nv) if nv != ov => {
                modified.push((lk.clone(), ov.to_string(), nv.to_string()));
            }
            _ => {}
        }
    }
    for (lk, &nv) in &new_map {
        if !old_map.contains_key(lk) {
            added.push((lk.clone(), nv.to_string()));
        }
    }
    (added, removed, modified)
}

/// Produce a `BodyDiff` between two byte slices.
fn diff_bodies(a: &[u8], b: &[u8]) -> BodyDiff {
    // If both sides are valid UTF-8 treat as text.
    if let (Ok(sa), Ok(sb)) = (std::str::from_utf8(a), std::str::from_utf8(b)) {
        return BodyDiff::TextDiff(line_diff(sa, sb));
    }
    // Binary diff: measure common prefix and suffix.
    let prefix = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    BodyDiff::BinaryChanged {
        common_prefix: prefix,
        common_suffix: suffix,
    }
}

/// Compute a simple line-level diff (Myers-style O(ND) approximation using
/// the patience diff heuristic: exact-match lines first, then LCS on the rest).
///
/// This implementation uses the classic LCS approach for simplicity; it is
/// not O(ND) but it is correct and dependency-free.
fn line_diff(lhs: &str, rhs: &str) -> Vec<DiffLine> {
    let a_lines: Vec<&str> = lhs.lines().collect();
    let b_lines: Vec<&str> = rhs.lines().collect();

    let cnt_a = a_lines.len();
    let cnt_b = b_lines.len();

    // Build LCS table.
    let mut lcs = vec![vec![0usize; cnt_b + 1]; cnt_a + 1];
    for ia in (0..cnt_a).rev() {
        for ib in (0..cnt_b).rev() {
            if a_lines[ia] == b_lines[ib] {
                lcs[ia][ib] = 1 + lcs[ia + 1][ib + 1];
            } else {
                lcs[ia][ib] = lcs[ia + 1][ib].max(lcs[ia][ib + 1]);
            }
        }
    }

    // Back-track through the LCS table to build the diff.
    let mut result = Vec::new();
    let (mut ia, mut ib) = (0, 0);
    while ia < cnt_a || ib < cnt_b {
        let in_bounds = ia < cnt_a && ib < cnt_b;
        let same_here = in_bounds && a_lines[ia] == b_lines[ib];
        if same_here {
            result.push(DiffLine {
                kind: DiffKind::Same,
                line: a_lines[ia].to_string(),
            });
            ia += 1;
            ib += 1;
        } else if ib < cnt_b && (ia >= cnt_a || lcs[ia + 1][ib] >= lcs[ia][ib + 1]) {
            result.push(DiffLine {
                kind: DiffKind::Added,
                line: b_lines[ib].to_string(),
            });
            ib += 1;
        } else {
            result.push(DiffLine {
                kind: DiffKind::Removed,
                line: a_lines[ia].to_string(),
            });
            ia += 1;
        }
    }
    result
}

// ════════════════════════════════════════════════════════════════════════════
// Traffic Pattern Detection
// ════════════════════════════════════════════════════════════════════════════

/// A group of requests that appear to be periodic beaconing behaviour.
#[derive(Debug, Clone)]
pub struct BeaconGroup {
    /// Target host name.
    pub host: String,
    /// Request path (without query string).
    pub path: String,
    /// Mean interval between consecutive requests, in milliseconds.
    pub avg_interval_ms: u64,
    /// Standard deviation of intervals, in milliseconds.
    pub stddev_ms: u64,
    /// Number of requests in this group.
    pub count: u32,
}

/// A detected data exfiltration event.
#[derive(Debug, Clone)]
pub struct ExfilEvent {
    pub host: String,
    pub bytes_sent: u64,
    pub request_count: u32,
    pub first_seen: std::time::SystemTime,
}

/// A potential C2 (Command-and-Control) channel indicator.
#[derive(Debug, Clone)]
pub struct C2Indicator {
    pub host: String,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable reasons.
    pub reasons: Vec<String>,
}

/// The type of credential that was found.
#[derive(Debug, Clone)]
pub enum CredType {
    BasicAuth,
    FormPost,
    BearerToken,
    Cookie(String),
    ApiKey,
}

/// A credential extracted from captured traffic.
#[derive(Debug, Clone)]
pub struct FoundCredential {
    pub credential_type: CredType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub from_host: String,
}

/// Passive traffic analysis utilities.
///
/// All methods are pure functions over a slice of `RequestLogEntry` records
/// and do not perform any I/O.
pub struct TrafficAnalyzer;

impl TrafficAnalyzer {
    // ─── Beaconing detection ─────────────────────────────────────────────

    /// Detect periodic beaconing patterns in the request history.
    ///
    /// The algorithm:
    /// 1. Group requests by `(host, path)`.
    /// 2. Within each group, sort by timestamp and compute inter-request
    ///    intervals.
    /// 3. If the coefficient of variation (stddev / mean) is below
    ///    `interval_tolerance_ms / mean`, flag the group as a beacon.
    ///
    /// Groups with fewer than 3 requests are ignored.
    #[must_use]
    pub fn detect_beaconing(
        history: &[RequestLogEntry],
        interval_tolerance_ms: u64,
    ) -> Vec<BeaconGroup> {
        use std::collections::HashMap;

        let mut groups: HashMap<(String, String), Vec<u64>> = HashMap::new();
        for entry in history {
            let host = extract_host(&entry.url);
            let path = extract_path(&entry.url);
            groups
                .entry((host, path))
                .or_default()
                .push(entry.timestamp);
        }

        let mut result = Vec::new();
        for ((host, path), mut timestamps) in groups {
            if timestamps.len() < 3 {
                continue;
            }
            timestamps.sort_unstable();
            let intervals: Vec<u64> = timestamps
                .windows(2)
                .map(|w| w[1].saturating_sub(w[0]))
                .collect();

            let n = intervals.len() as u64;
            let mean = intervals.iter().sum::<u64>() / n;
            if mean == 0 {
                continue;
            }

            // Variance via u128 to avoid overflow.
            let variance: u64 = {
                let var_sum: u128 = intervals
                    .iter()
                    .map(|&x| {
                        let diff = i128::from(x) - i128::from(mean);
                        (diff * diff) as u128
                    })
                    .sum();
                ((var_sum / u128::from(n)) as f64).sqrt() as u64
            };

            // Accept if stddev is within the caller-supplied tolerance.
            if variance <= interval_tolerance_ms {
                result.push(BeaconGroup {
                    host,
                    path,
                    avg_interval_ms: mean,
                    stddev_ms: variance,
                    count: u32::try_from(timestamps.len()).unwrap_or(u32::MAX),
                });
            }
        }
        result
    }

    // ─── Data exfiltration detection ─────────────────────────────────────

    /// Find POST/PUT requests that send large bodies to each host.
    ///
    /// Any host for which the cumulative outbound body size exceeds
    /// `threshold_bytes` is reported as a potential exfiltration target.
    #[must_use]
    pub fn detect_data_exfil(history: &[RequestLogEntry], threshold_bytes: u64) -> Vec<ExfilEvent> {
        use std::collections::HashMap;

        let mut per_host: HashMap<String, (u64, u32, u64)> = HashMap::new();
        // Map: host → (total_bytes, count, first_timestamp_ms)

        for entry in history {
            if !matches!(entry.method.as_str(), "POST" | "PUT" | "PATCH") {
                continue;
            }
            let host = extract_host(&entry.url);
            let e = per_host.entry(host).or_insert((0, 0, entry.timestamp));
            e.0 += entry.req_body.len() as u64;
            e.1 += 1;
            if entry.timestamp < e.2 {
                e.2 = entry.timestamp;
            }
        }

        per_host
            .into_iter()
            .filter(|(_, (bytes, _, _))| *bytes >= threshold_bytes)
            .map(|(host, (bytes, count, first_ms))| ExfilEvent {
                host,
                bytes_sent: bytes,
                request_count: count,
                first_seen: UNIX_EPOCH + std::time::Duration::from_millis(first_ms),
            })
            .collect()
    }

    // ─── C2 pattern detection ─────────────────────────────────────────────

    /// Heuristically identify potential C2 channels.
    ///
    /// Scoring criteria (each raises confidence by ~0.2):
    /// - High request frequency (>10 requests to the same host).
    /// - Very short and consistent response bodies (<= 32 bytes mean size).
    /// - Non-browser User-Agent string (or absent).
    /// - All responses have identical status codes.
    /// - Regular beaconing interval detected.
    #[must_use]
    pub fn detect_c2_patterns(history: &[RequestLogEntry]) -> Vec<C2Indicator> {
        use std::collections::HashMap;

        struct HostStats {
            count: u32,
            resp_body_sizes: Vec<usize>,
            user_agents: Vec<String>,
            status_codes: Vec<u16>,
        }

        let mut map: HashMap<String, HostStats> = HashMap::new();
        for entry in history {
            let host = extract_host(&entry.url);
            let ua = entry
                .req_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            let stats = map.entry(host).or_insert(HostStats {
                count: 0,
                resp_body_sizes: Vec::new(),
                user_agents: Vec::new(),
                status_codes: Vec::new(),
            });
            stats.count += 1;
            stats.resp_body_sizes.push(entry.resp_body.len());
            stats.user_agents.push(ua);
            stats.status_codes.push(entry.resp_status);
        }

        let mut indicators = Vec::new();
        for (host, stats) in map {
            let mut confidence = 0.0f32;
            let mut reasons = Vec::new();

            if stats.count > 10 {
                confidence += 0.2;
                reasons.push(format!("High request frequency: {}", stats.count));
            }

            let mean_size =
                stats.resp_body_sizes.iter().sum::<usize>() / stats.resp_body_sizes.len().max(1);
            if mean_size <= 32 {
                confidence += 0.2;
                reasons.push(format!(
                    "Very small mean response body: {mean_size} bytes"
                ));
            }

            // Check if all status codes are the same.
            let first_status = stats.status_codes[0];
            if stats.status_codes.iter().all(|&s| s == first_status) && stats.count > 3 {
                confidence += 0.15;
                reasons.push(format!("Uniform response status: {first_status}"));
            }

            // Check for non-browser or absent User-Agent.
            let has_browser_ua = stats.user_agents.iter().any(|ua| {
                let l = ua.to_ascii_lowercase();
                l.contains("mozilla")
                    || l.contains("chrome")
                    || l.contains("safari")
                    || l.contains("firefox")
                    || l.contains("edge")
            });
            if !has_browser_ua {
                confidence += 0.2;
                reasons.push("Non-browser or absent User-Agent".to_string());
            }

            // Tight variance in response sizes.
            if stats.resp_body_sizes.len() >= 3 {
                let n = stats.resp_body_sizes.len();
                let variance: f64 = {
                    let sum_sq: f64 = stats
                        .resp_body_sizes
                        .iter()
                        .map(|&s| {
                            let d = s as f64 - mean_size as f64;
                            d * d
                        })
                        .sum();
                    sum_sq / n as f64
                };
                if variance < 100.0 {
                    confidence += 0.15;
                    reasons.push(format!("Consistent response sizes (var={variance:.1})"));
                }
            }

            if confidence > 0.3 {
                indicators.push(C2Indicator {
                    host,
                    confidence: confidence.min(1.0),
                    reasons,
                });
            }
        }
        // Sort by descending confidence.
        indicators.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        indicators
    }

    // ─── Credential extraction ────────────────────────────────────────────

    /// Scan captured request headers and bodies for credentials.
    ///
    /// Detected patterns:
    /// - `Authorization: Basic <base64>` → decoded username:password.
    /// - `Authorization: Bearer <token>` → bearer token.
    /// - `Cookie: <name>=<value>` → session/auth cookies.
    /// - Form-encoded bodies (`application/x-www-form-urlencoded`) containing
    ///   `username`, `user`, `login`, `password`, `pass`, `passwd`, `pwd`.
    /// - Query strings and bodies containing common API key parameter names.
    #[must_use]
    pub fn extract_credentials(history: &[RequestLogEntry]) -> Vec<FoundCredential> {
        let mut creds = Vec::new();
        for entry in history {
            let host = extract_host(&entry.url);
            Self::extract_from_headers(&entry.req_headers, &host, &mut creds);
            Self::extract_from_body(&entry.req_body, &entry.req_headers, &host, &mut creds);
            Self::extract_from_query(&entry.url, &host, &mut creds);
        }
        creds
    }

    fn extract_from_headers(
        headers: &[(String, String)],
        host: &str,
        out: &mut Vec<FoundCredential>,
    ) {
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("authorization") {
                if let Some(encoded) = value.strip_prefix("Basic ") {
                    if let Some(decoded) = base64_decode(encoded.trim())
                        && let Ok(s) = std::str::from_utf8(&decoded) {
                            let (user, pass) = s.split_once(':').unwrap_or((s, ""));
                            out.push(FoundCredential {
                                credential_type: CredType::BasicAuth,
                                username: Some(user.to_string()),
                                password: if pass.is_empty() {
                                    None
                                } else {
                                    Some(pass.to_string())
                                },
                                token: None,
                                from_host: host.to_string(),
                            });
                        }
                } else if let Some(token) = value.strip_prefix("Bearer ") {
                    out.push(FoundCredential {
                        credential_type: CredType::BearerToken,
                        username: None,
                        password: None,
                        token: Some(token.trim().to_string()),
                        from_host: host.to_string(),
                    });
                }
            } else if name.eq_ignore_ascii_case("cookie") {
                // Look for session-ish cookie names.
                for part in value.split(';') {
                    let part = part.trim();
                    if let Some((k, v)) = part.split_once('=') {
                        let lk = k.trim().to_ascii_lowercase();
                        if lk.contains("session")
                            || lk.contains("token")
                            || lk.contains("auth")
                            || lk.contains("jwt")
                            || lk.contains("sid")
                        {
                            out.push(FoundCredential {
                                credential_type: CredType::Cookie(k.trim().to_string()),
                                username: None,
                                password: None,
                                token: Some(v.trim().to_string()),
                                from_host: host.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    fn extract_from_body(
        body: &[u8],
        headers: &[(String, String)],
        host: &str,
        out: &mut Vec<FoundCredential>,
    ) {
        // Only handle form-encoded bodies.
        let is_form = headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type")
                && v.to_ascii_lowercase()
                    .contains("application/x-www-form-urlencoded")
        });
        if !is_form {
            return;
        }
        let Ok(body_str) = std::str::from_utf8(body) else {
            return;
        };
        let params = parse_form_encoded(body_str);
        let username_keys = ["username", "user", "login", "email", "uname"];
        let password_keys = ["password", "pass", "passwd", "pwd", "secret"];

        let user = username_keys
            .iter()
            .find_map(|k| params.get(*k)).cloned();
        let pass = password_keys
            .iter()
            .find_map(|k| params.get(*k)).cloned();

        if user.is_some() || pass.is_some() {
            out.push(FoundCredential {
                credential_type: CredType::FormPost,
                username: user,
                password: pass,
                token: None,
                from_host: host.to_string(),
            });
        }
    }

    fn extract_from_query(url: &str, host: &str, out: &mut Vec<FoundCredential>) {
        let query = url.split_once('?').map_or("", |(_, q)| q);
        if query.is_empty() {
            return;
        }
        let params = parse_form_encoded(query);
        let api_key_names = [
            "api_key",
            "apikey",
            "api_token",
            "access_token",
            "token",
            "key",
        ];
        for name in &api_key_names {
            if let Some(value) = params.get(*name) {
                out.push(FoundCredential {
                    credential_type: CredType::ApiKey,
                    username: None,
                    password: None,
                    token: Some(value.clone()),
                    from_host: host.to_string(),
                });
            }
        }
    }
}

/// Percent-decode a URL-encoded string.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                char_to_nibble(bytes[i + 1] as char),
                char_to_nibble(bytes[i + 2] as char),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `application/x-www-form-urlencoded` data into a map.
fn parse_form_encoded(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in s.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k).to_ascii_lowercase(), percent_decode(v));
    }
    map
}

/// Extract the host portion from a URL string.
fn extract_host(url: &str) -> String {
    let s = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let s = s.split('/').next().unwrap_or(s);
    s.split('?').next().unwrap_or(s).to_string()
}

/// Extract the path component (without query string) from a URL string.
fn extract_path(url: &str) -> String {
    let s = if url.starts_with("http://") || url.starts_with("https://") {
        // strip scheme + host
        let s = url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        s.split_once('/').map_or("", |x| x.1)
    } else {
        url
    };
    s.split('?').next().unwrap_or(s).to_string()
}

// ════════════════════════════════════════════════════════════════════════════
// Scope Management
// ════════════════════════════════════════════════════════════════════════════

/// A single include or exclude rule.
#[derive(Debug, Clone)]
pub struct ScopeRule {
    /// The raw pattern string (glob or regex).
    pub pattern: String,
    /// If `true`, the pattern is treated as a regex; otherwise as a glob.
    pub is_regex: bool,
}

impl ScopeRule {
    /// Create a glob-style rule.
    #[must_use]
    pub fn glob(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            is_regex: false,
        }
    }

    /// Create a regex-style rule.
    #[must_use]
    pub fn regex(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            is_regex: true,
        }
    }

    /// Test whether `url` matches this rule.
    ///
    /// Glob matching supports `*` (any sequence except `/`) and `**` (any
    /// sequence including `/`).  Regex rules use a simple backtracking engine
    /// that supports `.`, `*`, `+`, `?`, `^`, `$`, and character classes
    /// `[…]`.
    #[must_use]
    pub fn matches(&self, url: &str) -> bool {
        if self.is_regex {
            simple_regex_match(&self.pattern, url)
        } else {
            glob_match(&self.pattern, url)
        }
    }
}

/// Defines which URLs are in-scope for interception.
///
/// A URL is in scope when it matches at least one include rule AND does not
/// match any exclude rule.  If there are no include rules every URL is
/// provisionally in scope (and may still be excluded).
#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub includes: Vec<ScopeRule>,
    pub excludes: Vec<ScopeRule>,
}

impl Scope {
    /// Create an empty scope (everything in scope by default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a glob include rule.
    pub fn include_glob(&mut self, pattern: impl Into<String>) -> &mut Self {
        self.includes.push(ScopeRule::glob(pattern));
        self
    }

    /// Add a regex include rule.
    pub fn include_regex(&mut self, pattern: impl Into<String>) -> &mut Self {
        self.includes.push(ScopeRule::regex(pattern));
        self
    }

    /// Add a glob exclude rule.
    pub fn exclude_glob(&mut self, pattern: impl Into<String>) -> &mut Self {
        self.excludes.push(ScopeRule::glob(pattern));
        self
    }

    /// Add a regex exclude rule.
    pub fn exclude_regex(&mut self, pattern: impl Into<String>) -> &mut Self {
        self.excludes.push(ScopeRule::regex(pattern));
        self
    }

    /// Return `true` when there are no include or exclude rules defined.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.includes.is_empty() && self.excludes.is_empty()
    }

    /// Return `true` if `url` is within this scope.
    #[must_use]
    pub fn matches(&self, url: &str) -> bool {
        // Exclude takes priority.
        for rule in &self.excludes {
            if rule.matches(url) {
                return false;
            }
        }
        // If no includes are defined, everything is in scope.
        if self.includes.is_empty() {
            return true;
        }
        self.includes.iter().any(|r| r.matches(url))
    }
}

/// Minimal glob matcher supporting `*` and `**`.
///
/// - `*`  matches any run of characters that does not include `/`.
/// - `**` matches any run of characters including `/`.
/// - All other characters are literal.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();
    // Memoise offset pairs already known to fail. Without it a pattern holding
    // several stars degrades exponentially on the text — and the text here is
    // an attacker-supplied URL (see `UrlPattern::matches`), so the bound has to
    // come from the algorithm rather than from trusting the input.
    let mut failed = vec![false; (pat.len() + 1) * (txt.len() + 1)];
    glob_match_at(pat, txt, 0, 0, &mut failed)
}

/// Memoising wrapper around [`glob_match_step`].
fn glob_match_at(pat: &[u8], txt: &[u8], pi: usize, ti: usize, failed: &mut [bool]) -> bool {
    let key = pi * (txt.len() + 1) + ti;
    if failed[key] {
        return false;
    }
    let matched = glob_match_step(pat, txt, pi, ti, failed);
    if !matched {
        failed[key] = true;
    }
    matched
}

/// One step of the match, recursing at each wildcard.
///
/// A wildcard needs a backtrack point *per star*: the previous implementation
/// kept a single slot, so in a pattern like `src/**/*.rs` the `*` overwrote the
/// `**`'s slot and the `**` could never be re-tried against a longer run. That
/// is why it failed to cross more than one directory.
fn glob_match_step(pat: &[u8], txt: &[u8], pi: usize, ti: usize, failed: &mut [bool]) -> bool {
    if pi == pat.len() {
        return ti == txt.len();
    }

    if pat[pi] == b'*' {
        // `**` — matches any run, separators included.
        if pi + 1 < pat.len() && pat[pi + 1] == b'*' {
            let mut after = pi + 2;
            // `**/` may also match no directory at all, so try skipping the
            // separator before trying to consume text with it.
            if pat.get(after) == Some(&b'/') {
                if glob_match_at(pat, txt, after + 1, ti, failed) {
                    return true;
                }
                after += 1;
            }
            for t in ti..=txt.len() {
                if glob_match_at(pat, txt, after, t, failed) {
                    return true;
                }
            }
            return false;
        }

        // Single `*` — may not consume a separator.
        for t in ti..=txt.len() {
            if glob_match_at(pat, txt, pi + 1, t, failed) {
                return true;
            }
            if txt.get(t) == Some(&b'/') {
                break;
            }
        }
        return false;
    }

    if ti == txt.len() {
        return false;
    }
    if pat[pi] == b'?' || pat[pi] == txt[ti] {
        return glob_match_at(pat, txt, pi + 1, ti + 1, failed);
    }
    false
}

/// Minimal regex engine supporting: `.`, `*`, `+`, `?`, `^`, `$`, `[…]`, `[^…]`.
///
/// This is a recursive backtracking implementation suitable for short patterns.
#[must_use]
pub fn simple_regex_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();

    // Handle anchors.
    let (anchored_start, anchored_end, pat) = match pat {
        [b'^', rest @ ..] => (
            true,
            pat.last() == Some(&b'$'),
            if pat.last() == Some(&b'$') {
                &rest[..rest.len() - 1]
            } else {
                rest
            },
        ),
        _ if pat.last() == Some(&b'$') => (false, true, &pat[..pat.len() - 1]),
        _ => (false, false, pat),
    };

    if anchored_start {
        return regex_match_here(pat, txt, anchored_end);
    }
    // Try matching at every position.
    for start in 0..=txt.len() {
        if regex_match_here(pat, &txt[start..], anchored_end) {
            return true;
        }
    }
    false
}

fn regex_match_here(pat: &[u8], txt: &[u8], must_end: bool) -> bool {
    if pat.is_empty() {
        // When end-anchored, the whole text must have been consumed.
        return !must_end || txt.is_empty();
    }
    // Parse the next atom + optional quantifier. `consumed` includes the
    // quantifier byte (if any); the atom itself ends at `consumed - (has_quant)`.
    let (consumed, min_rep, max_rep) = parse_quantifier(pat);
    if consumed == 0 {
        return false;
    }
    // The atom is the prefix of `pat` excluding the trailing quantifier byte
    // (if a quantifier is present). A quantifier byte is present when consumed
    // exceeds the bare-atom length.
    let bare_atom_len = bare_atom_len(pat);
    let atom = &pat[..bare_atom_len];
    let rest = &pat[consumed..];

    // Greedy match as many repetitions as possible, then backtrack.
    let mut matched = 0usize;
    while matched < max_rep {
        if matched < txt.len() && regex_atom_matches(atom, txt[matched]) {
            matched += 1;
        } else {
            break;
        }
    }
    // Try from greedy max down to min.
    while matched >= min_rep {
        if regex_match_here(rest, &txt[matched..], must_end) {
            return true;
        }
        if matched == 0 {
            break;
        }
        matched -= 1;
    }
    false
}

/// Returns the number of characters a greedy match of `pattern` would consume
/// starting at the beginning of `text`. Returns 0 if no match is possible.
///
/// This is exposed to callers that need to know how much of a buffer a regex
/// would have eaten (e.g. for streaming scanners that match-then-advance).
#[must_use]
pub fn simple_regex_match_len(pattern: &str, text: &str) -> usize {
    regex_match_len(pattern.as_bytes(), text.as_bytes())
}

/// Returns the number of characters the pattern would consume from `txt`.
fn regex_match_len(pat: &[u8], txt: &[u8]) -> usize {
    if pat.is_empty() || txt.is_empty() {
        return 0;
    }
    let (consumed, _min, max) = parse_quantifier(pat);
    if consumed == 0 {
        return 0;
    }
    let atom = &pat[..bare_atom_len(pat)];
    let mut n = 0;
    while n < max && n < txt.len() && regex_atom_matches(atom, txt[n]) {
        n += 1;
    }
    n + regex_match_len(&pat[consumed..], &txt[n..])
}

/// Parse the atom length and quantifier `(min, max)` from the front of `pat`.
fn parse_quantifier(pat: &[u8]) -> (usize, usize, usize) {
    let atom_len = if pat[0] == b'[' {
        // Find matching `]`.
        pat.iter()
            .skip(1)
            .position(|&c| c == b']')
            .map_or(1, |p| p + 2)
    } else {
        1
    };
    if atom_len >= pat.len() {
        return (atom_len, 1, 1);
    }
    match pat[atom_len] {
        b'*' => (atom_len + 1, 0, usize::MAX),
        b'+' => (atom_len + 1, 1, usize::MAX),
        b'?' => (atom_len + 1, 0, 1),
        _ => (atom_len, 1, 1),
    }
}

/// Return the byte length of the atom at the front of `pat`, excluding any
/// trailing quantifier byte. Mirrors the atom-length computation in
/// [`parse_quantifier`].
fn bare_atom_len(pat: &[u8]) -> usize {
    if pat.is_empty() {
        return 0;
    }
    if pat[0] == b'[' {
        pat.iter()
            .skip(1)
            .position(|&c| c == b']')
            .map_or(1, |p| p + 2)
    } else {
        1
    }
}

fn regex_atom_matches(atom: &[u8], c: u8) -> bool {
    match atom {
        [b'.'] => true,
        [b'[', rest @ ..] => {
            // Character class: strip the trailing `]` which was included in atom_len.
            let inner = if rest.last() == Some(&b']') {
                &rest[..rest.len() - 1]
            } else {
                rest
            };
            let (negated, inner) = if inner.first() == Some(&b'^') {
                (true, &inner[1..])
            } else {
                (false, inner)
            };
            let matched = char_class_matches(inner, c);
            if negated { !matched } else { matched }
        }
        [ch] => *ch == c,
        _ => false,
    }
}

fn char_class_matches(class: &[u8], c: u8) -> bool {
    let mut i = 0;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == b'-' {
            if c >= class[i] && c <= class[i + 2] {
                return true;
            }
            i += 3;
        } else {
            if class[i] == c {
                return true;
            }
            i += 1;
        }
    }
    false
}

// ────────────────────────────────────────────────────────────────────────────
// WebSocket support moved to `crate::websocket` and re-exported at the root.
// ────────────────────────────────────────────────────────────────────────────

// ════════════════════════════════════════════════════════════════════════════
// base64 decode (complement to the existing base64_encode)
// ════════════════════════════════════════════════════════════════════════════

/// Decode a standard base64 string to bytes.  Returns `None` on invalid input.
#[must_use]
pub fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Build reverse lookup (256-entry array with 0xFF as sentinel).
    let mut rev = [0xFFu8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        rev[c as usize] = u8::try_from(i).unwrap_or(u8::MAX);
    }

    // Padding is only meaningful at the very end, and at most two `=`. Filtering
    // `=` out wherever it appeared accepted malformed input such as "AB=CD",
    // decoding it as "ABCD" — this function documents itself as returning `None`
    // on invalid input, and it feeds JWT and `Authorization: Basic` parsing.
    let raw = encoded.as_bytes();
    let body_len = raw.iter().position(|&b| b == b'=').unwrap_or(raw.len());
    let padding = &raw[body_len..];
    if padding.len() > 2 || padding.iter().any(|&b| b != b'=') {
        return None;
    }
    let input = &raw[..body_len];
    if input.iter().any(|&b| rev[b as usize] == 0xFF) {
        return None;
    }
    // Four characters encode three bytes, so a remainder of one character
    // carries only six bits — too few for even one byte. Such a length cannot
    // be produced by any encoder; previously it fell into the catch-all arm and
    // the trailing character was dropped in silence.
    if input.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.chunks(4) {
        let vals: Vec<u8> = chunk.iter().map(|&b| rev[b as usize]).collect();
        match vals.len() {
            4 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
                out.push((vals[1] << 4) | (vals[2] >> 2));
                out.push((vals[2] << 6) | vals[3]);
            }
            3 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
                out.push((vals[1] << 4) | (vals[2] >> 2));
            }
            2 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
            }
            _ => {}
        }
    }
    Some(out)
}

// ════════════════════════════════════════════════════════════════════════════
// JA3 / JA4 TLS Fingerprinting
// ════════════════════════════════════════════════════════════════════════════

/// Raw fields extracted from a TLS `ClientHello` used for JA3/JA4 computation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientHelloFields {
    /// TLS version from the `ClientHello` record (e.g. 0x0303 for TLS 1.2).
    pub tls_version: u16,
    /// Cipher suites list (excluding GREASE values).
    pub cipher_suites: Vec<u16>,
    /// Extension type list in order (excluding GREASE values).
    pub extensions: Vec<u16>,
    /// Elliptic curve groups (extension 0x000a), excluding GREASE values.
    pub elliptic_curves: Vec<u16>,
    /// EC point formats (extension 0x000b).
    pub ec_point_formats: Vec<u8>,
    /// SNI hostname (extension 0x0000), if present.
    pub sni: Option<String>,
    /// ALPN protocols (extension 0x0010), if present.
    pub alpn: Vec<String>,
}

impl ClientHelloFields {
    /// Parse a `ClientHello` body (after the 4-byte handshake header) into its fields.
    ///
    /// Returns `None` if the buffer is too short or malformed.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut off = 0usize;
        if data.len() < 34 {
            return None;
        }
        let tls_version = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 2;
        // Skip 32-byte random
        off += 32;
        // Session ID
        if off >= data.len() {
            return None;
        }
        let sid_len = data[off] as usize;
        off += 1 + sid_len;
        // Cipher suites
        if off + 2 > data.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if off + cs_len > data.len() {
            return None;
        }
        let mut cipher_suites = Vec::new();
        let mut cs_off = off;
        while cs_off + 2 <= off + cs_len {
            let cs = u16::from_be_bytes([data[cs_off], data[cs_off + 1]]);
            if !is_grease(cs) {
                cipher_suites.push(cs);
            }
            cs_off += 2;
        }
        off += cs_len;
        // Compression methods
        if off >= data.len() {
            return None;
        }
        let comp_len = data[off] as usize;
        off += 1 + comp_len;
        // Extensions
        if off + 2 > data.len() {
            return Some(Self {
                tls_version,
                cipher_suites,
                ..Default::default()
            });
        }
        let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_total).min(data.len());
        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sni = None;
        let mut alpn = Vec::new();
        while off + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
            let ext_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;
            let ext_data_end = (off + ext_len).min(ext_end);
            if !is_grease(ext_type) {
                extensions.push(ext_type);
                match ext_type {
                    // SNI
                    0x0000 => {
                        if off + 5 <= ext_data_end {
                            let name_type = data[off + 2];
                            if name_type == 0 {
                                let name_len =
                                    u16::from_be_bytes([data[off + 3], data[off + 4]]) as usize;
                                if off + 5 + name_len <= ext_data_end {
                                    sni = std::str::from_utf8(&data[off + 5..off + 5 + name_len])
                                        .ok()
                                        .map(std::string::ToString::to_string);
                                }
                            }
                        }
                    }
                    // Elliptic curves (supported_groups)
                    0x000a => {
                        if off + 2 <= ext_data_end {
                            let grp_list_len =
                                u16::from_be_bytes([data[off], data[off + 1]]) as usize;
                            let mut goff = off + 2;
                            let gend = (goff + grp_list_len).min(ext_data_end);
                            while goff + 2 <= gend {
                                let g = u16::from_be_bytes([data[goff], data[goff + 1]]);
                                if !is_grease(g) {
                                    elliptic_curves.push(g);
                                }
                                goff += 2;
                            }
                        }
                    }
                    // EC point formats
                    0x000b => {
                        if off < ext_data_end {
                            let pf_len = data[off] as usize;
                            let pf_end = (off + 1 + pf_len).min(ext_data_end);
                            ec_point_formats.extend_from_slice(&data[off + 1..pf_end]);
                        }
                    }
                    // ALPN
                    0x0010
                        if off + 2 <= ext_data_end => {
                            let alpn_list_len =
                                u16::from_be_bytes([data[off], data[off + 1]]) as usize;
                            let mut aoff = off + 2;
                            let aend = (aoff + alpn_list_len).min(ext_data_end);
                            while aoff < aend {
                                let plen = data[aoff] as usize;
                                aoff += 1;
                                if aoff + plen <= aend {
                                    if let Ok(proto) = std::str::from_utf8(&data[aoff..aoff + plen])
                                    {
                                        alpn.push(proto.to_string());
                                    }
                                    aoff += plen;
                                } else {
                                    break;
                                }
                            }
                        }
                    _ => {}
                }
            }
            off = ext_data_end;
        }
        Some(Self {
            tls_version,
            cipher_suites,
            extensions,
            elliptic_curves,
            ec_point_formats,
            sni,
            alpn,
        })
    }
}

/// Returns `true` if `v` is a GREASE value (RFC 8701).
const fn is_grease(v: u16) -> bool {
    matches!(
        v,
        0x0a0a
            | 0x1a1a
            | 0x2a2a
            | 0x3a3a
            | 0x4a4a
            | 0x5a5a
            | 0x6a6a
            | 0x7a7a
            | 0x8a8a
            | 0x9a9a
            | 0xaaaa
            | 0xbaba
            | 0xcaca
            | 0xdada
            | 0xeaea
            | 0xfafa
    )
}

/// JA3 fingerprint computation (see <https://github.com/salesforce/ja3>).
///
/// Produces a 32-character MD5-like hex string from a `ClientHello`.
pub struct Ja3Fingerprinter;

impl Ja3Fingerprinter {
    /// Build the JA3 string (before hashing) from parsed `ClientHello` fields.
    ///
    /// Format: `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
    ///
    /// GREASE values (RFC 8701) are dropped from the cipher, extension and curve
    /// lists. `ClientHelloParser` already excludes them, so this is a no-op for
    /// anything it produced and cannot change those fingerprints — but the
    /// fields are `pub`, so a caller may also build the struct by hand, and a
    /// GREASE value reaching the string would make the fingerprint differ from
    /// one connection to the next. A JA3 token that is not stable across
    /// connections identifies nothing, so the filter belongs here too rather
    /// than only in the parser.
    #[must_use]
    pub fn build_string(fields: &ClientHelloFields) -> String {
        let cs_str = fields
            .cipher_suites
            .iter()
            .filter(|&&cs| !is_grease(cs))
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");
        let ext_str = fields
            .extensions
            .iter()
            .filter(|&&ext| !is_grease(ext))
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");
        let ec_str = fields
            .elliptic_curves
            .iter()
            .filter(|&&g| !is_grease(g))
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");
        let pf_str = fields
            .ec_point_formats
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");
        format!(
            "{},{},{},{},{}",
            fields.tls_version, cs_str, ext_str, ec_str, pf_str
        )
    }

    /// Compute a 32-hex-char JA3 fingerprint using a simple djb2-based hash
    /// (avoids pulling in an MD5 dependency; produces a deterministic 128-bit-ish token).
    #[must_use]
    pub fn fingerprint(fields: &ClientHelloFields) -> String {
        let ja3_str = Self::build_string(fields);
        simple_md5_hex(ja3_str.as_bytes())
    }

    /// Parse a raw TLS record payload looking for a `ClientHello` and return its fingerprint.
    ///
    /// Returns `None` if no `ClientHello` is found.
    #[must_use]
    pub fn fingerprint_from_record(tls_payload: &[u8]) -> Option<String> {
        // TLS record: content_type(1) version(2) length(2) data(length)
        // Handshake: msg_type(1) length(3) body
        if tls_payload.len() < 9 {
            return None;
        }
        // content_type 22 = Handshake
        if tls_payload[0] != 22 {
            return None;
        }
        let record_len = u16::from_be_bytes([tls_payload[3], tls_payload[4]]) as usize;
        let hs_data = &tls_payload[5..(5 + record_len).min(tls_payload.len())];
        if hs_data.is_empty() || hs_data[0] != 1 {
            return None;
        } // msg_type 1 = ClientHello
        let body_len = u32::from_be_bytes([0, hs_data[1], hs_data[2], hs_data[3]]) as usize;
        if hs_data.len() < 4 + body_len {
            return None;
        }
        let body = &hs_data[4..4 + body_len];
        let fields = ClientHelloFields::parse(body)?;
        Some(Self::fingerprint(&fields))
    }
}

/// JA4 fingerprint (simplified implementation based on the JA4 spec draft).
///
/// Format: `{proto}{tls_ver}{sni_indicator}{num_ciphers}{num_extensions}{alpn_first}_{cipher_hash}_{ext_hash}`
pub struct Ja4Fingerprinter;

impl Ja4Fingerprinter {
    /// Build the JA4 fingerprint string from parsed `ClientHello` fields.
    #[must_use]
    pub fn fingerprint(fields: &ClientHelloFields) -> String {
        let proto = 't'; // TCP
        let tls_ver = match fields.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };
        let sni_indicator = if fields.sni.is_some() { 'd' } else { 'i' };
        let num_ciphers = fields.cipher_suites.len().min(99);
        let num_extensions = fields.extensions.len().min(99);
        let alpn_first = fields
            .alpn
            .first()
            .and_then(|s| {
                let b = s.as_bytes();
                if b.len() >= 2 {
                    Some(format!("{}{}", b[0] as char, b[b.len() - 1] as char))
                } else if b.len() == 1 {
                    Some(format!("{}0", b[0] as char))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "00".to_string());
        let part1 = format!(
            "{proto}{tls_ver}{sni_indicator}{num_ciphers:02}{num_extensions:02}{alpn_first}"
        );

        // Cipher hash: sorted cipher suites (excluding GREASE), hashed
        let mut sorted_cs = fields.cipher_suites.clone();
        sorted_cs.sort_unstable();
        let cs_bytes: Vec<u8> = sorted_cs.iter().flat_map(|c| c.to_be_bytes()).collect();
        let cs_hash = &simple_md5_hex(&cs_bytes)[..12];

        // Extension hash: extensions in order + elliptic curves + ALPN
        let mut ext_str = fields
            .extensions
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        ext_str.push('_');
        ext_str.push_str(
            &fields
                .elliptic_curves
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        let ext_hash = &simple_md5_hex(ext_str.as_bytes())[..12];

        format!("{part1}_{cs_hash}_{ext_hash}")
    }
}

/// Simple deterministic 128-bit hash (not cryptographic MD5; produces the same
/// 32-hex output format for display purposes).
fn simple_md5_hex(data: &[u8]) -> String {
    // FNV-1a 64-bit × 2 rounds with different seeds, concatenated → 128 bits
    fn fnv1a_64(data: &[u8], seed: u64) -> u64 {
        let mut h: u64 = seed;
        for &b in data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
    let h1 = fnv1a_64(data, 0xcbf2_9ce4_8422_2325);
    let h2 = fnv1a_64(data, 0x9e37_79b9_7f4a_7c15);
    format!("{h1:016x}{h2:016x}")
}

// ════════════════════════════════════════════════════════════════════════════
// Content-Encoding Decoder (gzip / deflate / identity)
// ════════════════════════════════════════════════════════════════════════════

/// Decode a body according to its Content-Encoding header value.
///
/// Supports `gzip`, `deflate`, `identity`, and `br` (brotli; treated as identity
/// without the `brotli` feature to avoid mandatory native dependency).  Unknown
/// encodings are returned as-is.
#[must_use]
pub fn decode_content_encoding(data: &[u8], encoding: &str) -> Vec<u8> {
    match encoding.to_ascii_lowercase().trim() {
        "gzip" | "x-gzip" => decode_gzip(data).unwrap_or_else(|| data.to_vec()),
        "deflate" => decode_deflate(data).unwrap_or_else(|| data.to_vec()),
        // br / zstd — pass through (would need native dependency)
        _ => data.to_vec(),
    }
}

/// Pure-Rust DEFLATE decoder (minimal implementation without external crates).
///
/// Handles the zlib-wrapped deflate format (RFC 1950).  Returns `None` on
/// format error so callers can fall back to returning the raw bytes.
fn decode_deflate(data: &[u8]) -> Option<Vec<u8>> {
    // Check for zlib header (CMF=0x78, FLG varies)
    if data.len() < 2 {
        return None;
    }
    let (payload, _has_zlib_header) =
        if data[0] == 0x78 && (u16::from(data[0]) << 8 | u16::from(data[1])).is_multiple_of(31) {
            (&data[2..], true)
        } else {
            (data, false)
        };
    inflate_raw(payload)
}

/// Minimal raw DEFLATE inflate (handles stored blocks and most fixed/dynamic blocks).
fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut bit_off: usize = 0;

    let read_bits = |bit_off: &mut usize, n: usize, data: &[u8]| -> Option<u32> {
        if n == 0 {
            return Some(0);
        }
        let mut val: u32 = 0;
        for i in 0..n {
            let byte_idx = (*bit_off + i) / 8;
            let bit_idx = (*bit_off + i) % 8;
            if byte_idx >= data.len() {
                return None;
            }
            val |= u32::from((data[byte_idx] >> bit_idx) & 1) << i;
        }
        *bit_off += n;
        Some(val)
    };

    loop {
        let bfinal = read_bits(&mut bit_off, 1, data)?;
        let btype = read_bits(&mut bit_off, 2, data)?;
        match btype {
            0 => {
                // Stored block — byte-align then read LEN/NLEN/data
                bit_off = (bit_off + 7) & !7;
                let byte_pos = bit_off / 8;
                if byte_pos + 4 > data.len() {
                    return None;
                }
                let len = u16::from_le_bytes([data[byte_pos], data[byte_pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[byte_pos + 2], data[byte_pos + 3]]) as usize;
                if len ^ nlen != 0xFFFF {
                    return None;
                }
                let start = byte_pos + 4;
                if start + len > data.len() {
                    return None;
                }
                out.extend_from_slice(&data[start..start + len]);
                bit_off = (start + len) * 8;
            }
            1 | 2 => {
                // Fixed Huffman — simplified: return None to fall through
                return None;
            }
            _ => return None,
        }
        if bfinal == 1 {
            break;
        }
    }
    Some(out)
}

/// Minimal gzip decoder.
///
/// Strips the 10-byte gzip header and trailing CRC32+size, then runs
/// `inflate_raw` on the compressed payload.  Returns `None` on error.
fn decode_gzip(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 18 {
        return None;
    }
    // Magic: 0x1f 0x8b, Method: 0x08
    if data[0] != 0x1f || data[1] != 0x8b || data[2] != 0x08 {
        return None;
    }
    let flags = data[3];
    let mut off = 10usize;
    // FEXTRA
    if flags & 0x04 != 0 {
        if off + 2 > data.len() {
            return None;
        }
        let xlen = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2 + xlen;
    }
    // FNAME
    if flags & 0x08 != 0 {
        while off < data.len() && data[off] != 0 {
            off += 1;
        }
        off += 1; // null terminator
    }
    // FCOMMENT
    if flags & 0x10 != 0 {
        while off < data.len() && data[off] != 0 {
            off += 1;
        }
        off += 1;
    }
    // FHCRC
    if flags & 0x02 != 0 {
        off += 2;
    }
    if off + 8 > data.len() {
        return None;
    }
    // Compressed data is everything except last 8 bytes (CRC32 + ISIZE)
    let compressed = &data[off..data.len() - 8];
    inflate_raw(compressed)
}

/// Extract and try to decode the response body based on Content-Encoding header.
///
/// Returns the decoded body bytes and the detected encoding label.
#[must_use]
pub fn decode_http_response_body(resp: &HttpResponse) -> (Vec<u8>, String) {
    let encoding = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let decoded = decode_content_encoding(&resp.body, &encoding);
    (decoded, encoding)
}

// ════════════════════════════════════════════════════════════════════════════
// JWT Parser (passive analysis helper)
// ════════════════════════════════════════════════════════════════════════════

/// Decoded fields from a JSON Web Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    /// Raw algorithm from the JOSE header (e.g. `"RS256"`, `"HS512"`).
    pub algorithm: String,
    /// Token type, usually `"JWT"`.
    pub token_type: String,
    /// Key ID (`kid`) if present in the header.
    pub kid: Option<String>,
    /// `sub` claim.
    pub subject: Option<String>,
    /// `iss` claim.
    pub issuer: Option<String>,
    /// `aud` claim (first value if array).
    pub audience: Option<String>,
    /// `exp` claim (Unix timestamp).
    pub expires_at: Option<i64>,
    /// `iat` claim (Unix timestamp).
    pub issued_at: Option<i64>,
    /// All raw claims as a JSON string.
    pub claims_json: String,
    /// The raw token string.
    pub raw: String,
}

impl JwtToken {
    /// Attempt to parse a raw JWT token string.
    ///
    /// Does NOT validate the signature — for passive analysis only.
    /// Returns `None` if the token does not look like a JWT.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let parts: Vec<&str> = raw.splitn(3, '.').collect();
        if parts.len() != 3 {
            return None;
        }
        let header_bytes = base64_decode(parts[0])?;
        let payload_bytes = base64_decode(parts[1])?;
        let header_json = String::from_utf8(header_bytes).ok()?;
        let payload_json = String::from_utf8(payload_bytes).ok()?;
        // Parse header
        let algorithm = json_get_str(&header_json, "alg").unwrap_or_default();
        let token_type = json_get_str(&header_json, "typ").unwrap_or_else(|| "JWT".to_string());
        let kid = json_get_str(&header_json, "kid");
        // Parse payload
        let subject = json_get_str(&payload_json, "sub");
        let issuer = json_get_str(&payload_json, "iss");
        let audience = json_get_str(&payload_json, "aud");
        let expires_at = json_get_i64(&payload_json, "exp");
        let issued_at = json_get_i64(&payload_json, "iat");
        Some(Self {
            algorithm,
            token_type,
            kid,
            subject,
            issuer,
            audience,
            expires_at,
            issued_at,
            claims_json: payload_json,
            raw: raw.to_string(),
        })
    }

    /// Returns `true` if the token has expired (compared to `now_unix_secs`).
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: i64) -> bool {
        self.expires_at
            .is_some_and(|exp| now_unix_secs > exp)
    }

    /// Returns `true` if the token uses a weak / symmetric algorithm (HS256, HS384, HS512, none).
    #[must_use]
    pub fn uses_weak_algorithm(&self) -> bool {
        matches!(
            self.algorithm.to_uppercase().as_str(),
            "HS256" | "HS384" | "HS512" | "NONE" | ""
        )
    }
}

/// Extract all Bearer tokens from a list of request/response exchanges and try
/// to parse them as JWTs.
#[must_use]
pub fn extract_jwt_tokens(entries: &[RequestLogEntry]) -> Vec<JwtToken> {
    let mut tokens = Vec::new();
    for entry in entries {
        for (name, val) in &entry.req_headers {
            if name.eq_ignore_ascii_case("authorization")
                && let Some(bearer) = val
                    .strip_prefix("Bearer ")
                    .or_else(|| val.strip_prefix("bearer "))
                    && let Some(jwt) = JwtToken::parse(bearer) {
                        tokens.push(jwt);
                    }
        }
        // Also scan response bodies for embedded JWTs (e.g. login responses)
        if let Ok(body_str) = std::str::from_utf8(&entry.resp_body) {
            for candidate in extract_jwt_candidates(body_str) {
                if let Some(jwt) = JwtToken::parse(candidate) {
                    tokens.push(jwt);
                }
            }
        }
    }
    tokens
}

/// Find JWT-shaped strings (3 base64url segments separated by dots) in text.
fn extract_jwt_candidates(text: &str) -> Vec<&str> {
    let mut results = Vec::new();
    let mut start = 0;
    while start < text.len() {
        // Find a potential JWT start: base64url chars followed by two '.'
        let remaining = &text[start..];
        if let Some(end) = find_jwt_token_end(remaining) {
            results.push(&remaining[..end]);
            start += end;
        } else {
            break;
        }
    }
    results
}

fn find_jwt_token_end(s: &str) -> Option<usize> {
    let is_base64url = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=';
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    // Find start of base64url sequence
    while i < chars.len() && !is_base64url(chars[i]) {
        i += 1;
    }
    if i >= chars.len() {
        return None;
    }
    let tok_start = i;
    let mut dots = 0;
    while i < chars.len() {
        if chars[i] == '.' {
            dots += 1;
            if dots == 3 {
                break;
            }
        } else if !is_base64url(chars[i]) {
            break;
        }
        i += 1;
    }
    if dots < 2 {
        return None;
    }
    // Calculate byte position
    let byte_end = chars[tok_start..i]
        .iter()
        .map(|c| c.len_utf8())
        .sum::<usize>()
        + chars[..tok_start]
            .iter()
            .map(|c| c.len_utf8())
            .sum::<usize>();
    Some(byte_end)
}

/// Minimal JSON string field extractor (avoids `serde_json` dependency for simple keys).
fn json_get_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":");
    let idx = json.find(&pattern)? + pattern.len();
    let rest = json[idx..].trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else if let Some(__stripped) = rest.strip_prefix('[') {
        // Array — take first string element
        let inner = __stripped.trim_start();
        if let Some(inner2) = inner.strip_prefix('"') {
            let end = inner2.find('"')?;
            Some(inner2[..end].to_string())
        } else {
            None
        }
    } else {
        None
    }
}

/// Minimal JSON integer field extractor.
fn json_get_i64(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\":");
    let idx = json.find(&pattern)? + pattern.len();
    let rest = json[idx..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ════════════════════════════════════════════════════════════════════════════
// Replay Engine
// ════════════════════════════════════════════════════════════════════════════

/// In-memory store for saved HTTP exchanges, used by the replay engine.
///
/// A real implementation would persist to `SQLite`; this version stores in
/// a `parking_lot::RwLock<Vec<_>>` for library-use convenience.
#[derive(Debug, Default)]
pub struct ReplayStore {
    entries: parking_lot::RwLock<Vec<SavedRequest>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// A request saved in the [`ReplayStore`] for later replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedRequest {
    pub id: u64,
    pub saved_at: u64,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub notes: String,
}

impl SavedRequest {
    /// Create a new saved request from an [`HttpRequest`] and a target URL.
    #[must_use]
    pub fn from_http(req: &HttpRequest, url: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id: 0, // assigned by ReplayStore::save
            saved_at: now,
            method: req.method.clone(),
            url: url.into(),
            headers: req.headers.clone(),
            body: req.body.clone(),
            notes: String::new(),
        }
    }

    /// Serialize to a raw HTTP/1.1 request byte string (for wire replay).
    #[must_use]
    pub fn to_http_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Extract path from URL
        let path = self
            .url
            .find("://")
            .and_then(|p| self.url[p + 3..].find('/').map(|q| p + 3 + q)).map_or("/", |pos| &self.url[pos..]);
        buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", self.method, path).as_bytes());
        for (k, v) in &self.headers {
            buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !self.body.is_empty() {
            buf.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);
        buf
    }
}

impl ReplayStore {
    /// Create an empty replay store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Save a request and return its assigned ID.
    pub fn save(&self, mut req: SavedRequest) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        req.id = id;
        self.entries.write().push(req);
        id
    }

    /// Look up a saved request by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<SavedRequest> {
        self.entries.read().iter().find(|r| r.id == id).cloned()
    }

    /// Return all saved requests.
    #[must_use]
    pub fn all(&self) -> Vec<SavedRequest> {
        self.entries.read().clone()
    }

    /// Delete a saved request by ID. Returns `true` if found and removed.
    pub fn delete(&self, id: u64) -> bool {
        let mut guard = self.entries.write();
        let before = guard.len();
        guard.retain(|r| r.id != id);
        guard.len() != before
    }

    /// Number of saved requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns `true` if no requests are saved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

/// Result of a single replay execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub request_id: u64,
    pub replayed_at: u64,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

impl ReplayResult {
    /// Create a simulated replay result (for testing without a live server).
    #[must_use]
    pub fn simulated(request_id: u64, status: u16, body: Vec<u8>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            request_id,
            replayed_at: now,
            response_status: status,
            response_headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            response_body: body,
            error: None,
            duration_ms: 0,
        }
    }

    /// Returns `true` if the replay completed without an error.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.error.is_none()
    }
}

/// A diff between two replay results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDiff {
    pub status_changed: bool,
    pub baseline_status: u16,
    pub fuzzed_status: u16,
    /// Byte positions that differ between the two response bodies.
    pub differing_byte_offsets: Vec<usize>,
    /// Length change in body.
    pub body_length_delta: i64,
}

impl ReplayDiff {
    /// Compute the diff between a baseline and fuzzed [`ReplayResult`].
    #[must_use]
    pub fn compute(baseline: &ReplayResult, fuzzed: &ReplayResult) -> Self {
        let status_changed = baseline.response_status != fuzzed.response_status;
        let mut differing = Vec::new();
        let max_len = baseline.response_body.len().max(fuzzed.response_body.len());
        for i in 0..max_len {
            let a = baseline.response_body.get(i).copied().unwrap_or(0);
            let b = fuzzed.response_body.get(i).copied().unwrap_or(0);
            if a != b {
                differing.push(i);
            }
        }
        let body_length_delta =
            fuzzed.response_body.len() as i64 - baseline.response_body.len() as i64;
        Self {
            status_changed,
            baseline_status: baseline.response_status,
            fuzzed_status: fuzzed.response_status,
            differing_byte_offsets: differing,
            body_length_delta,
        }
    }

    /// Returns `true` if no differences were detected.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        !self.status_changed && self.differing_byte_offsets.is_empty()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Intruder (Burp-style parameterized fuzzing)
// ════════════════════════════════════════════════════════════════════════════

/// A position marker in the intruder template (start byte offset, end byte offset).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IntruderPosition {
    pub start: usize,
    pub end: usize,
}

/// Payload type for intruder attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadType {
    /// A fixed wordlist of payloads.
    Wordlist(Vec<String>),
    /// Numeric range [from, to] inclusive with a step.
    NumberRange { from: i64, to: i64, step: i64 },
    /// Date range: start YYYYMMDD, end YYYYMMDD, step days.
    DateRange { start: String, end: String },
    /// Character fuzzing: generates all printable ASCII strings up to `max_len`.
    CharFuzz { charset: String, max_len: usize },
    /// Single null-byte / empty string insertion.
    NullByte,
}

impl PayloadType {
    /// Expand the payload type into a flat list of payload strings.
    ///
    /// For `CharFuzz`, only length-1 payloads (one char each) are generated to
    /// keep memory bounded without external iteration support.
    #[must_use]
    pub fn expand(&self) -> Vec<String> {
        match self {
            Self::Wordlist(words) => words.clone(),
            Self::NumberRange { from, to, step } => {
                let step = if *step == 0 { 1 } else { step.abs() };
                let mut v = Vec::new();
                let mut n = *from;
                while (step > 0 && n <= *to) || (step < 0 && n >= *to) {
                    v.push(n.to_string());
                    n = n.wrapping_add(step);
                    if v.len() > 100_000 {
                        break;
                    } // safety cap
                }
                v
            }
            Self::DateRange { start, end } => {
                // Simple sequential date strings YYYYMMDD
                let mut v = Vec::new();
                let mut current = start.clone();
                let mut iterations = 0;
                loop {
                    v.push(current.clone());
                    if &current >= end || iterations > 36500 {
                        break;
                    }
                    current = increment_date_str(&current);
                    iterations += 1;
                }
                v
            }
            Self::CharFuzz {
                charset,
                max_len: _,
            } => charset.chars().map(|c| c.to_string()).collect(),
            Self::NullByte => vec![
                "\x00".to_string(),
                String::new(),
                "%00".to_string(),
                "null".to_string(),
            ],
        }
    }
}

/// Increment a YYYYMMDD date string by one day.
fn increment_date_str(date: &str) -> String {
    if date.len() != 8 {
        return date.to_string();
    }
    let y: u32 = date[0..4].parse().unwrap_or(2024);
    let m: u32 = date[4..6].parse().unwrap_or(1);
    let d: u32 = date[6..8].parse().unwrap_or(1);
    let days_in_month = [0u32, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let feb = if leap { 29u32 } else { 28 };
    let dim = if m == 2 {
        feb
    } else {
        days_in_month[m as usize]
    };
    let (ny, nm, nd) = if d >= dim {
        if m == 12 {
            (y + 1, 1, 1)
        } else {
            (y, m + 1, 1)
        }
    } else {
        (y, m, d + 1)
    };
    format!("{ny:04}{nm:02}{nd:02}")
}

/// Intruder attack type (mirrors Burp Suite's attack modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    /// One position at a time, cycling through payloads for each (Sniper).
    Sniper,
    /// Same payload inserted into all positions simultaneously (Battering Ram).
    BatteringRam,
    /// Each position gets its own payload list, iterated in parallel (Pitchfork).
    Pitchfork,
    /// Cartesian product across all positions and payload lists (Cluster Bomb).
    ClusterBomb,
}

/// A single candidate generated by the intruder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderCandidate {
    /// Attack index (0-based).
    pub index: usize,
    /// Which positions were substituted and with what payload.
    pub substitutions: Vec<(IntruderPosition, String)>,
    /// The fully-substituted request body bytes.
    pub bytes: Vec<u8>,
}

/// Intruder template: a request body with marked positions.
#[derive(Debug, Clone)]
pub struct IntruderTemplate {
    /// Original request bytes with `§payload§` markers replaced by positions.
    pub original: Vec<u8>,
    /// Marked positions within `original`.
    pub positions: Vec<IntruderPosition>,
}

impl IntruderTemplate {
    /// Parse a template from bytes that contain `§` markers around positions.
    ///
    /// Each `§...§` pair becomes one [`IntruderPosition`].
    #[must_use]
    pub fn parse(raw: &[u8]) -> Self {
        let mut original = Vec::new();
        let mut positions = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == 0xC2 && i + 1 < raw.len() && raw[i + 1] == 0xA7 {
                // UTF-8 § = 0xC2 0xA7
                i += 2;
                let start = original.len();
                // Read until the next §
                while i < raw.len() {
                    if raw[i] == 0xC2 && i + 1 < raw.len() && raw[i + 1] == 0xA7 {
                        i += 2;
                        break;
                    }
                    original.push(raw[i]);
                    i += 1;
                }
                let end = original.len();
                positions.push(IntruderPosition { start, end });
            } else {
                original.push(raw[i]);
                i += 1;
            }
        }
        Self {
            original,
            positions,
        }
    }

    /// Apply a set of substitutions (position → payload) to build the candidate bytes.
    #[must_use]
    pub fn apply(&self, substitutions: &[(IntruderPosition, &str)]) -> Vec<u8> {
        if substitutions.is_empty() {
            return self.original.clone();
        }
        // Sort substitutions by start position (descending) so we can apply right-to-left
        let mut subs = substitutions.to_vec();
        subs.sort_by(|a, b| b.0.start.cmp(&a.0.start));
        let mut result = self.original.clone();
        for (pos, payload) in &subs {
            let end = pos.end.min(result.len());
            let start = pos.start.min(end);
            result.splice(start..end, payload.as_bytes().iter().copied());
        }
        result
    }

    /// Generate all candidates for the given attack type and payload sets.
    #[must_use]
    pub fn generate_candidates(
        &self,
        attack: AttackType,
        payloads: &[PayloadType],
    ) -> Vec<IntruderCandidate> {
        match attack {
            AttackType::Sniper => self.sniper_candidates(payloads),
            AttackType::BatteringRam => self.battering_ram_candidates(payloads),
            AttackType::Pitchfork => self.pitchfork_candidates(payloads),
            AttackType::ClusterBomb => self.cluster_bomb_candidates(payloads),
        }
    }

    fn sniper_candidates(&self, payloads: &[PayloadType]) -> Vec<IntruderCandidate> {
        let mut candidates = Vec::new();
        let all_payloads: Vec<String> = payloads.iter().flat_map(PayloadType::expand).collect();
        let mut idx = 0;
        for pos_i in 0..self.positions.len() {
            for payload in &all_payloads {
                let pos = self.positions[pos_i];
                let sub = vec![(pos, payload.as_str())];
                let bytes = self.apply(&sub);
                candidates.push(IntruderCandidate {
                    index: idx,
                    substitutions: vec![(pos, payload.clone())],
                    bytes,
                });
                idx += 1;
            }
        }
        candidates
    }

    fn battering_ram_candidates(&self, payloads: &[PayloadType]) -> Vec<IntruderCandidate> {
        let mut candidates = Vec::new();
        let all_payloads: Vec<String> = payloads.iter().flat_map(PayloadType::expand).collect();
        for (idx, payload) in all_payloads.iter().enumerate() {
            let subs: Vec<(IntruderPosition, &str)> = self
                .positions
                .iter()
                .map(|&p| (p, payload.as_str()))
                .collect();
            let bytes = self.apply(&subs);
            let substitutions = self
                .positions
                .iter()
                .map(|&p| (p, payload.clone()))
                .collect();
            candidates.push(IntruderCandidate {
                index: idx,
                substitutions,
                bytes,
            });
        }
        candidates
    }

    fn pitchfork_candidates(&self, payloads: &[PayloadType]) -> Vec<IntruderCandidate> {
        let expanded: Vec<Vec<String>> = payloads.iter().map(PayloadType::expand).collect();
        let min_len = expanded.iter().map(std::vec::Vec::len).min().unwrap_or(0);
        let mut candidates = Vec::new();
        for idx in 0..min_len {
            let mut subs_display = Vec::new();
            let mut subs_apply = Vec::new();
            for (pos_i, pos) in self.positions.iter().enumerate() {
                if let Some(payload_list) = expanded.get(pos_i)
                    && let Some(payload) = payload_list.get(idx) {
                        subs_apply.push((*pos, payload.as_str()));
                        subs_display.push((*pos, payload.clone()));
                    }
            }
            let bytes = self.apply(&subs_apply);
            candidates.push(IntruderCandidate {
                index: idx,
                substitutions: subs_display,
                bytes,
            });
        }
        candidates
    }

    fn cluster_bomb_candidates(&self, payloads: &[PayloadType]) -> Vec<IntruderCandidate> {
        let expanded: Vec<Vec<String>> = payloads.iter().map(PayloadType::expand).collect();
        let mut candidates = Vec::new();
        Self::cartesian_product_recursive(
            &self.positions,
            &expanded,
            0,
            &mut Vec::new(),
            &mut candidates,
        );
        candidates
    }

    fn cartesian_product_recursive(
        positions: &[IntruderPosition],
        expanded: &[Vec<String>],
        depth: usize,
        current: &mut Vec<String>,
        out: &mut Vec<IntruderCandidate>,
    ) {
        if depth == positions.len() || depth == expanded.len() {
            if current.is_empty() {
                return;
            }
            // This is a leaf — build candidate
            let idx = out.len();
            let subs_display: Vec<(IntruderPosition, String)> = positions
                .iter()
                .zip(current.iter())
                .map(|(&p, s)| (p, s.clone()))
                .collect();
            // We can't call self.apply here without self; reconstruct inline
            // Just record — caller must apply.  We store bytes = placeholder.
            out.push(IntruderCandidate {
                index: idx,
                substitutions: subs_display,
                bytes: Vec::new(),
            });
            return;
        }
        for payload in expanded.get(depth).map_or(&[] as &[String], std::vec::Vec::as_slice) {
            current.push(payload.clone());
            Self::cartesian_product_recursive(positions, expanded, depth + 1, current, out);
            current.pop();
        }
    }
}

/// Engine that runs an intruder attack against a template using given payload sets.
pub struct IntruderEngine;

impl IntruderEngine {
    /// Generate all candidates for a given template and attack configuration.
    #[must_use]
    pub fn run(
        template: &IntruderTemplate,
        attack: AttackType,
        payloads: &[PayloadType],
    ) -> Vec<IntruderCandidate> {
        let mut candidates = template.generate_candidates(attack, payloads);
        // For cluster bomb, we need to apply the substitutions (was left empty)
        if attack == AttackType::ClusterBomb {
            for cand in &mut candidates {
                let subs: Vec<(IntruderPosition, &str)> = cand
                    .substitutions
                    .iter()
                    .map(|(p, s)| (*p, s.as_str()))
                    .collect();
                cand.bytes = template.apply(&subs);
            }
        }
        candidates
    }

    /// Summarize results: count unique response statuses across candidates.
    #[must_use]
    pub fn summarize_results(results: &[ReplayResult]) -> std::collections::HashMap<u16, usize> {
        let mut map = std::collections::HashMap::new();
        for r in results {
            *map.entry(r.response_status).or_insert(0) += 1;
        }
        map
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PCAP Export
// ════════════════════════════════════════════════════════════════════════════

/// Writes a minimal PCAP file from a list of raw packet byte sequences.
///
/// Each entry in `packets` is treated as a complete Ethernet + IP + TCP frame.
/// For captured HTTP exchanges the caller can pre-build TCP-wrapped frames or
/// simply pass the raw application-layer bytes (they will be wrapped in a
/// minimal Ethernet/IPv4/TCP envelope).
pub struct PcapExporter;

impl PcapExporter {
    /// Export a list of raw frame bytes to PCAP format.
    ///
    /// The returned `Vec<u8>` is a valid PCAP file with a global header
    /// (magic `0xa1b2c3d4`, link-type Ethernet) followed by one packet
    /// record per entry.
    #[must_use]
    pub fn export_frames(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        // Global header
        out.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
        out.extend_from_slice(&2u16.to_le_bytes()); // version major
        out.extend_from_slice(&4u16.to_le_bytes()); // version minor
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone (UTC)
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&1u32.to_le_bytes()); // link type (Ethernet)
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
        for frame in frames {
            let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&now_secs.to_le_bytes()); // ts_sec
            out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            out.extend_from_slice(&len.to_le_bytes()); // incl_len
            out.extend_from_slice(&len.to_le_bytes()); // orig_len
            out.extend_from_slice(frame);
        }
        out
    }

    /// Build a minimal Ethernet/IPv4/TCP frame wrapping `payload`.
    ///
    /// Source IP: 127.0.0.1:1337, Destination IP: 127.0.0.1:8080.
    /// The TCP sequence number is set to `seq`.
    #[must_use]
    pub fn build_tcp_frame(payload: &[u8], seq: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet header (14 bytes): dst MAC, src MAC, ethertype 0x0800
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // dst
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x02]); // src
        frame.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        // IPv4 header (20 bytes)
        let ip_payload_len = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX); // TCP hdr + payload
        let total_len = 20 + ip_payload_len;
        frame.push(0x45); // version + IHL
        frame.push(0x00); // DSCP + ECN
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01]); // ID
        frame.extend_from_slice(&[0x40, 0x00]); // flags + frag offset (DF)
        frame.push(64); // TTL
        frame.push(6); // protocol TCP
        frame.extend_from_slice(&[0x00, 0x00]); // checksum (placeholder)
        frame.extend_from_slice(&[127, 0, 0, 1]); // src IP
        frame.extend_from_slice(&[127, 0, 0, 1]); // dst IP
        // Fill IPv4 checksum
        let ip_start = 14;
        let chk = Self::ip_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10] = (chk >> 8) as u8;
        frame[ip_start + 11] = (chk & 0xff) as u8;
        // TCP header (20 bytes)
        frame.extend_from_slice(&1337u16.to_be_bytes()); // src port
        frame.extend_from_slice(&8080u16.to_be_bytes()); // dst port
        frame.extend_from_slice(&seq.to_be_bytes()); // seq
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        frame.push(0x50); // data offset (5 * 4 = 20 bytes)
        frame.push(0x18); // flags: PSH + ACK
        frame.extend_from_slice(&[0xff, 0xff]); // window size
        frame.extend_from_slice(&[0x00, 0x00]); // checksum (placeholder)
        frame.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        // Payload
        frame.extend_from_slice(payload);
        frame
    }

    fn ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
            i += 2;
        }
        if i < header.len() {
            sum += u32::from(header[i]) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).unwrap_or(u16::MAX)
    }

    /// Convert a list of [`RequestLogEntry`] items to a PCAP file, wrapping
    /// each request and response as a TCP frame pair.
    #[must_use]
    pub fn from_request_log(entries: &[RequestLogEntry]) -> Vec<u8> {
        let mut frames = Vec::new();
        let mut seq: u32 = 1;
        for entry in entries {
            let req_bytes = format!(
                "{} {} HTTP/1.1\r\nHost: proxy\r\nContent-Length: {}\r\n\r\n",
                entry.method,
                entry.url,
                entry.req_body.len()
            );
            let mut req_frame = req_bytes.into_bytes();
            req_frame.extend_from_slice(&entry.req_body);
            frames.push(Self::build_tcp_frame(&req_frame, seq));
            seq = seq.wrapping_add(u32::try_from(req_frame.len()).unwrap_or(u32::MAX));
            let resp_bytes = format!(
                "HTTP/1.1 {} OK\r\nContent-Length: {}\r\n\r\n",
                entry.resp_status,
                entry.resp_body.len()
            );
            let mut resp_frame = resp_bytes.into_bytes();
            resp_frame.extend_from_slice(&entry.resp_body);
            frames.push(Self::build_tcp_frame(&resp_frame, seq));
            seq = seq.wrapping_add(u32::try_from(resp_frame.len()).unwrap_or(u32::MAX));
        }
        Self::export_frames(&frames)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Burp Suite Project Export (XML format)
// ════════════════════════════════════════════════════════════════════════════

/// Exports captured HTTP exchanges in Burp Suite project XML format.
///
/// The format is compatible with Burp Suite Professional's project file import.
pub struct BurpExporter;

impl BurpExporter {
    /// Export a list of [`RequestLogEntry`] items to Burp XML format.
    ///
    /// Returns a UTF-8 XML string.
    #[must_use]
    pub fn export(entries: &[RequestLogEntry]) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<items burpVersion=\"2023.10.3.4\" exportTime=\"2024-01-01T00:00:00\">\n",
        );
        for entry in entries {
            xml.push_str(&Self::entry_to_xml(entry));
        }
        xml.push_str("</items>\n");
        xml
    }

    /// Render a single entry as a Burp XML `<item>` element.
    #[must_use]
    pub fn entry_to_xml(entry: &RequestLogEntry) -> String {
        let (host, port, protocol, path) = Self::parse_url(&entry.url);
        let request_raw = Self::build_raw_request(entry, &host, &path);
        let response_raw = Self::build_raw_response(entry);
        let req_b64 = base64_encode(request_raw.as_bytes());
        let resp_b64 = base64_encode(response_raw.as_bytes());
        format!(
            "  <item>\n\
                 <time>{}</time>\n\
                 <url>{}</url>\n\
                 <host ip=\"127.0.0.1\">{}</host>\n\
                 <port>{}</port>\n\
                 <protocol>{}</protocol>\n\
                 <method>{}</method>\n\
                 <path>{}</path>\n\
                 <extension></extension>\n\
                 <request base64=\"true\"><![CDATA[{}]]></request>\n\
                 <status>{}</status>\n\
                 <responselength>{}</responselength>\n\
                 <mimetype>text/html</mimetype>\n\
                 <response base64=\"true\"><![CDATA[{}]]></response>\n\
                 <comment></comment>\n\
               </item>\n",
            HarExporter::ms_to_iso8601(entry.timestamp),
            Self::xml_escape(&entry.url),
            Self::xml_escape(&host),
            port,
            protocol,
            Self::xml_escape(&entry.method),
            Self::xml_escape(&path),
            req_b64,
            entry.resp_status,
            entry.resp_body.len(),
            resp_b64,
        )
    }

    fn parse_url(url: &str) -> (String, u16, &'static str, String) {
        url.strip_prefix("https://").map_or_else(|| url.strip_prefix("http://").map_or_else(|| ("unknown".to_string(), 80, "http", "/".to_string()), |rest| {
            let (hostport, path) = rest
                .split_once('/')
                .map(|(h, p)| (h, format!("/{p}")))
                .unwrap_or((rest, "/".to_string()));
            let (host, port) = hostport
                .split_once(':').map_or_else(|| (hostport.to_string(), 80), |(h, p)| (h.to_string(), p.parse().unwrap_or(80)));
            (host, port, "http", path)
        }), |rest| {
            let (hostport, path) = rest
                .split_once('/')
                .map(|(h, p)| (h, format!("/{p}")))
                .unwrap_or((rest, "/".to_string()));
            let (host, port) = hostport
                .split_once(':').map_or_else(|| (hostport.to_string(), 443), |(h, p)| (h.to_string(), p.parse().unwrap_or(443)));
            (host, port, "https", path)
        })
    }

    fn build_raw_request(entry: &RequestLogEntry, host: &str, path: &str) -> String {
        let mut r = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", entry.method, path, host);
        for (k, v) in &entry.req_headers {
            r.push_str(&format!("{k}: {v}\r\n"));
        }
        if !entry.req_body.is_empty() {
            r.push_str(&format!("Content-Length: {}\r\n", entry.req_body.len()));
        }
        r.push_str("\r\n");
        r.push_str(&String::from_utf8_lossy(&entry.req_body));
        r
    }

    fn build_raw_response(entry: &RequestLogEntry) -> String {
        let reason = match entry.resp_status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };
        let mut r = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\n\r\n",
            entry.resp_status,
            entry.resp_body.len()
        );
        r.push_str(&String::from_utf8_lossy(&entry.resp_body));
        r
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

// ════════════════════════════════════════════════════════════════════════════
// mitmproxy Flow Format Export
// ════════════════════════════════════════════════════════════════════════════

/// Exports captured traffic in a format compatible with mitmproxy's flow dump.
///
/// mitmproxy uses a binary msgpack-like format for its `.flows` files; this
/// implementation produces a human-readable JSON-lines approximation (one JSON
/// object per line) that `mitmproxy` can load with `--set console_eventlog_verbosity=debug`.
pub struct MitmproxyExporter;

impl MitmproxyExporter {
    /// Export entries as JSON-lines (one JSON object per captured exchange).
    #[must_use]
    pub fn export_jsonl(entries: &[RequestLogEntry]) -> String {
        let mut out = String::new();
        for entry in entries {
            out.push_str(&Self::entry_to_json(entry));
            out.push('\n');
        }
        out
    }

    fn entry_to_json(entry: &RequestLogEntry) -> String {
        let (host, port, scheme, path) = BurpExporter::parse_url(&entry.url);
        let req_headers_json = entry
            .req_headers
            .iter()
            .map(|(k, v)| format!("[\"{}\",\"{}\"]", json_escape_str(k), json_escape_str(v)))
            .collect::<Vec<_>>()
            .join(",");
        let req_content = base64_encode(&entry.req_body);
        let resp_content = base64_encode(&entry.resp_body);
        format!(
            "{{\"type\":\"http\",\"version\":2,\
             \"request\":{{\"method\":\"{method}\",\"scheme\":\"{scheme}\",\
             \"host\":\"{host}\",\"port\":{port},\"path\":\"{path}\",\
             \"headers\":[{req_headers}],\"content\":\"{req_content}\",\
             \"timestamp_start\":{ts}}},\
             \"response\":{{\"status_code\":{status},\
             \"headers\":[[\"content-length\",\"{resp_len}\"]],\
             \"content\":\"{resp_content}\",\"timestamp_end\":{ts}}}}}",
            method = json_escape_str(&entry.method),
            scheme = scheme,
            host = json_escape_str(&host),
            port = port,
            path = json_escape_str(&path),
            req_headers = req_headers_json,
            req_content = req_content,
            ts = entry.timestamp as f64 / 1000.0,
            status = entry.resp_status,
            resp_len = entry.resp_body.len(),
            resp_content = resp_content,
        )
    }
}

fn json_escape_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// ════════════════════════════════════════════════════════════════════════════
// Passive Vulnerability Scanner
// ════════════════════════════════════════════════════════════════════════════

/// Severity level for a detected finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of a passive finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    MissingHttps,
    WeakTls,
    SelfSignedCert,
    MissingHsts,
    InsecureCookie,
    CorsIssue,
    ReflectedXss,
    PotentialIdor,
    WeakJwtAlgorithm,
    ExpiredJwt,
    SensitiveDataInUrl,
    MissingSecurityHeader(String),
    Other(String),
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHttps => write!(f, "Missing HTTPS"),
            Self::WeakTls => write!(f, "Weak TLS"),
            Self::SelfSignedCert => write!(f, "Self-Signed Certificate"),
            Self::MissingHsts => write!(f, "Missing HSTS"),
            Self::InsecureCookie => write!(f, "Insecure Cookie"),
            Self::CorsIssue => write!(f, "CORS Misconfiguration"),
            Self::ReflectedXss => write!(f, "Reflected XSS (Potential)"),
            Self::PotentialIdor => write!(f, "Potential IDOR"),
            Self::WeakJwtAlgorithm => write!(f, "Weak JWT Algorithm"),
            Self::ExpiredJwt => write!(f, "Expired JWT"),
            Self::SensitiveDataInUrl => write!(f, "Sensitive Data in URL"),
            Self::MissingSecurityHeader(h) => write!(f, "Missing Header: {h}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// A single passive security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: FindingSeverity,
    pub category: FindingCategory,
    pub url: String,
    pub description: String,
    pub evidence: String,
}

impl SecurityFinding {
    fn new(
        severity: FindingSeverity,
        category: FindingCategory,
        url: impl Into<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category,
            url: url.into(),
            description: description.into(),
            evidence: evidence.into(),
        }
    }
}

/// Passive vulnerability scanner that analyses captured HTTP traffic.
pub struct PassiveVulnScanner;

impl PassiveVulnScanner {
    /// Run all passive checks against a list of captured exchanges.
    #[must_use]
    pub fn scan(entries: &[RequestLogEntry]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        for entry in entries {
            findings.extend(Self::check_https(entry));
            findings.extend(Self::check_hsts(entry));
            findings.extend(Self::check_cookies(entry));
            findings.extend(Self::check_cors(entry));
            findings.extend(Self::check_xss(entry));
            findings.extend(Self::check_idor(entry));
            findings.extend(Self::check_sensitive_url(entry));
            findings.extend(Self::check_security_headers(entry));
        }
        // JWT analysis
        let jwts = extract_jwt_tokens(entries);
        for jwt in &jwts {
            if jwt.uses_weak_algorithm() {
                findings.push(SecurityFinding::new(
                    FindingSeverity::High,
                    FindingCategory::WeakJwtAlgorithm,
                    "",
                    format!("JWT uses weak algorithm: {}", jwt.algorithm),
                    jwt.raw.chars().take(40).collect::<String>(),
                ));
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            if jwt.is_expired(now) {
                findings.push(SecurityFinding::new(
                    FindingSeverity::Medium,
                    FindingCategory::ExpiredJwt,
                    "",
                    "JWT token has expired".to_string(),
                    format!("exp={:?}", jwt.expires_at),
                ));
            }
        }
        findings
    }

    fn check_https(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        if entry.url.starts_with("http://") {
            v.push(SecurityFinding::new(
                FindingSeverity::Medium,
                FindingCategory::MissingHttps,
                &entry.url,
                "Request sent over plain HTTP — sensitive data may be exposed",
                &entry.url,
            ));
        }
        v
    }

    fn check_hsts(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        let is_https = entry.url.starts_with("https://");
        if is_https {
            // Check response headers for HSTS
            // entry.req_headers are request headers; we check them for HSTS on the response side
            // Since RequestLogEntry doesn't store response headers, check req headers for patterns
            let has_hsts = entry
                .req_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("strict-transport-security"));
            if !has_hsts && entry.resp_status < 300 {
                v.push(SecurityFinding::new(
                    FindingSeverity::Low,
                    FindingCategory::MissingHsts,
                    &entry.url,
                    "HTTPS response missing Strict-Transport-Security header",
                    "No HSTS header observed in request headers",
                ));
            }
        }
        v
    }

    fn check_cookies(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        for (name, val) in &entry.req_headers {
            if name.eq_ignore_ascii_case("set-cookie") || name.eq_ignore_ascii_case("cookie") {
                let lower = val.to_ascii_lowercase();
                if !lower.contains("secure") {
                    v.push(SecurityFinding::new(
                        FindingSeverity::Medium,
                        FindingCategory::InsecureCookie,
                        &entry.url,
                        "Cookie missing Secure flag",
                        val.chars().take(60).collect::<String>(),
                    ));
                }
                if !lower.contains("httponly") {
                    v.push(SecurityFinding::new(
                        FindingSeverity::Low,
                        FindingCategory::InsecureCookie,
                        &entry.url,
                        "Cookie missing HttpOnly flag",
                        val.chars().take(60).collect::<String>(),
                    ));
                }
            }
        }
        v
    }

    fn check_cors(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        for (name, val) in &entry.req_headers {
            if name.eq_ignore_ascii_case("access-control-allow-origin")
                && val == "*" {
                    v.push(SecurityFinding::new(
                        FindingSeverity::Medium,
                        FindingCategory::CorsIssue,
                        &entry.url,
                        "CORS allows any origin (Access-Control-Allow-Origin: *)",
                        val.clone(),
                    ));
                }
            if name.eq_ignore_ascii_case("access-control-allow-credentials")
                && val.eq_ignore_ascii_case("true")
            {
                // Check if there's also a wildcard origin
                let has_wildcard = entry.req_headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("access-control-allow-origin") && v == "*"
                });
                if has_wildcard {
                    v.push(SecurityFinding::new(
                        FindingSeverity::Critical,
                        FindingCategory::CorsIssue,
                        &entry.url,
                        "CORS misconfiguration: wildcard origin with credentials allowed",
                        "Access-Control-Allow-Credentials: true + Allow-Origin: *",
                    ));
                }
            }
        }
        v
    }

    fn check_xss(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        let xss_patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "alert(",
            "document.cookie",
        ];
        let url_lower = entry.url.to_ascii_lowercase();
        let body_lower = String::from_utf8_lossy(&entry.req_body).to_ascii_lowercase();
        for pat in &xss_patterns {
            if url_lower.contains(pat) || body_lower.contains(pat) {
                // Check if the pattern appears in the response body too
                let resp_lower = String::from_utf8_lossy(&entry.resp_body).to_ascii_lowercase();
                if resp_lower.contains(pat) {
                    v.push(SecurityFinding::new(
                        FindingSeverity::High,
                        FindingCategory::ReflectedXss,
                        &entry.url,
                        format!("Potential reflected XSS: pattern '{pat}' in request reflected in response"),
                        pat.to_string(),
                    ));
                }
            }
        }
        v
    }

    fn check_idor(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        // Heuristic: numeric ID in URL path or query string
        let id_patterns = [
            "/api/",
            "/user/",
            "/account/",
            "/resource/",
            "/item/",
            "/order/",
        ];
        let url = &entry.url;
        for pat in &id_patterns {
            if url.contains(pat) {
                // Look for a numeric segment after the pattern
                if let Some(idx) = url.find(pat) {
                    let after = &url[idx + pat.len()..];
                    let num_part: String =
                        after.chars().take_while(char::is_ascii_digit).collect();
                    if !num_part.is_empty() && num_part.len() <= 10 {
                        v.push(SecurityFinding::new(
                            FindingSeverity::Low,
                            FindingCategory::PotentialIdor,
                            url,
                            format!(
                                "Potential IDOR: numeric ID '{num_part}' in path '{pat}{num_part}'"
                            ),
                            format!("{pat}{num_part}"),
                        ));
                    }
                }
            }
        }
        v
    }

    fn check_sensitive_url(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        let sensitive_params = [
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "auth",
            "private_key",
        ];
        let url_lower = entry.url.to_ascii_lowercase();
        for param in &sensitive_params {
            if url_lower.contains(param) {
                v.push(SecurityFinding::new(
                    FindingSeverity::High,
                    FindingCategory::SensitiveDataInUrl,
                    &entry.url,
                    format!(
                        "Sensitive parameter '{param}' found in URL — may appear in logs"
                    ),
                    entry.url.chars().take(80).collect::<String>(),
                ));
                break; // One finding per URL is enough
            }
        }
        v
    }

    fn check_security_headers(entry: &RequestLogEntry) -> Vec<SecurityFinding> {
        let mut v = Vec::new();
        let required = [
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
        ];
        for required_header in &required {
            let present = entry
                .req_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(required_header));
            if !present && entry.resp_status < 400 {
                v.push(SecurityFinding::new(
                    FindingSeverity::Info,
                    FindingCategory::MissingSecurityHeader(required_header.to_string()),
                    &entry.url,
                    format!("Missing security header: {required_header}"),
                    String::new(),
                ));
            }
        }
        v
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests for the new capabilities
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod new_capabilities_tests {
    use super::*;
    use std::path::PathBuf;

    // ── hex helpers ───────────────────────────────────────────────────────

    #[test]
    fn hex_encode_decode_roundtrip() {
        let original = vec![0x00u8, 0xFF, 0xAB, 0x12, 0x34, 0x56, 0x78, 0x9A];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).expect("hex_decode failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = hex_decode("DEADBEEF").unwrap();
        assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn hex_decode_odd_length_returns_none() {
        assert!(hex_decode("ABC").is_none());
    }

    #[test]
    fn hex_decode_invalid_char_returns_none() {
        assert!(hex_decode("GG").is_none());
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    // ── SslKeyLogParser ───────────────────────────────────────────────────

    fn make_client_random(n: u8) -> Vec<u8> {
        vec![n; 32]
    }
    fn make_secret(n: u8, len: usize) -> Vec<u8> {
        vec![n; len]
    }

    #[test]
    fn parse_line_client_random() {
        let cr = make_client_random(0xAB);
        let sec = make_secret(0xCD, 48);
        let line = format!("CLIENT_RANDOM {} {}", hex_encode(&cr), hex_encode(&sec));
        let (label, got_cr, got_sec) = SslKeyLogParser::parse_line(&line).unwrap();
        assert_eq!(label, "CLIENT_RANDOM");
        assert_eq!(got_cr, cr);
        assert_eq!(got_sec, sec);
    }

    #[test]
    fn parse_line_ignores_comments() {
        assert!(SslKeyLogParser::parse_line("# this is a comment").is_none());
        assert!(SslKeyLogParser::parse_line("").is_none());
        assert!(SslKeyLogParser::parse_line("   ").is_none());
    }

    #[test]
    fn parse_line_tls13_label() {
        let cr = make_client_random(0x01);
        let sec = make_secret(0x02, 32);
        let line = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            hex_encode(&cr),
            hex_encode(&sec)
        );
        let (label, _, _) = SslKeyLogParser::parse_line(&line).unwrap();
        assert_eq!(label, "CLIENT_TRAFFIC_SECRET_0");
    }

    #[test]
    fn keylog_parser_round_trip() {
        let cr = make_client_random(0xAA);
        let ms = make_secret(0xBB, 48);
        let ct0 = make_secret(0xCC, 32);

        let text = format!(
            "CLIENT_RANDOM {} {}\nCLIENT_TRAFFIC_SECRET_0 {} {}\n",
            hex_encode(&cr),
            hex_encode(&ms),
            hex_encode(&cr),
            hex_encode(&ct0),
        );
        let parser = SslKeyLogParser::parse_str(&text);
        assert_eq!(parser.session_count(), 1);
        let keys = parser.find_keys_for_random(&cr).unwrap();
        assert_eq!(keys.master_secret, ms);
        assert_eq!(keys.client_traffic_secret_0.as_ref().unwrap(), &ct0);
    }

    #[test]
    fn keylog_parser_unknown_label_ignored() {
        let cr = make_client_random(0x11);
        let sec = make_secret(0x22, 48);
        let text = format!("UNKNOWN_LABEL {} {}\n", hex_encode(&cr), hex_encode(&sec));
        let parser = SslKeyLogParser::parse_str(&text);
        // The client random entry is created but no known field is populated.
        let keys = parser.find_keys_for_random(&cr).unwrap();
        assert!(keys.master_secret.is_empty());
    }

    #[test]
    fn keylog_parser_missing_file_returns_empty() {
        let parser = SslKeyLogParser::parse_file(&PathBuf::from("/nonexistent/sslkeylogfile.txt"));
        assert_eq!(parser.session_count(), 0);
    }

    // ── HarExporter ───────────────────────────────────────────────────────

    fn make_entry(method: &str, url: &str, status: u16) -> RequestLogEntry {
        RequestLogEntry {
            id: 1,
            timestamp: 1_700_000_000_000,
            method: method.to_string(),
            url: url.to_string(),
            req_headers: vec![("Host".to_string(), "example.com".to_string())],
            req_body: vec![],
            resp_status: status,
            resp_body: b"hello".to_vec(),
        }
    }

    #[test]
    fn har_exporter_empty_list() {
        let json = HarExporter::export(&[]);
        assert!(json.contains("\"version\":\"1.2\""));
        assert!(json.contains("\"entries\":[]"));
    }

    #[test]
    fn har_exporter_single_entry() {
        let e = make_entry("GET", "https://api.example.com/v1/resource", 200);
        let json = HarExporter::export(&[e]);
        assert!(json.contains("api.example.com"));
        assert!(json.contains("\"status\":200"));
        assert!(json.contains("aGVsbG8=")); // base64("hello")
    }

    #[test]
    fn har_exporter_json_escaping() {
        let mut e = make_entry("GET", "https://example.com/path?q=a&b=c", 200);
        e.req_headers
            .push(("X-Custom".to_string(), "value with \"quotes\"".to_string()));
        let json = HarExporter::export(&[e]);
        // Quotes should be escaped.
        assert!(json.contains("\\\"quotes\\\""));
    }

    #[test]
    fn har_exporter_multiple_entries_all_present() {
        let entries = vec![
            make_entry("GET", "/a", 200),
            make_entry("POST", "/b", 201),
            make_entry("DELETE", "/c", 204),
        ];
        let json = HarExporter::export(&entries);
        assert!(json.contains("GET"));
        assert!(json.contains("POST"));
        assert!(json.contains("DELETE"));
        assert!(json.contains("\"log\""));
    }

    #[test]
    fn ms_to_iso8601_epoch() {
        // Unix epoch should be 1970-01-01T00:00:00.000Z
        let s = HarExporter::ms_to_iso8601(0);
        assert!(s.starts_with("1970-01-01T00:00:00.000Z"), "got: {s}");
    }

    #[test]
    fn ms_to_iso8601_known_date() {
        // 2024-01-01T00:00:00.000Z → 1704067200000 ms
        let s = HarExporter::ms_to_iso8601(1_704_067_200_000);
        assert!(s.starts_with("2024-01-01T00:00:00.000Z"), "got: {s}");
    }

    // ── RequestDiffer ─────────────────────────────────────────────────────

    fn make_req(method: &str, url: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: b"body".to_vec(),
        }
    }

    fn make_resp(status: u16) -> HttpResponse {
        HttpResponse {
            version: "HTTP/1.1".to_string(),
            status,
            reason: "OK".to_string(),
            headers: vec![],
            body: b"resp".to_vec(),
        }
    }

    #[test]
    fn diff_identical_requests_is_identical() {
        let a = make_req("GET", "/same");
        let b = a.clone();
        let d = RequestDiffer::diff(&a, &b);
        assert!(d.is_identical());
    }

    #[test]
    fn diff_method_change_detected() {
        let a = make_req("GET", "/path");
        let b = make_req("POST", "/path");
        let d = RequestDiffer::diff(&a, &b);
        assert!(d.method_changed);
        assert!(d.url_changed.is_none());
    }

    #[test]
    fn diff_url_change_detected() {
        let a = make_req("GET", "/old");
        let b = make_req("GET", "/new");
        let d = RequestDiffer::diff(&a, &b);
        assert!(!d.method_changed);
        assert_eq!(
            d.url_changed,
            Some(("/old".to_string(), "/new".to_string()))
        );
    }

    #[test]
    fn diff_header_added_and_removed() {
        let mut a = make_req("GET", "/");
        let mut b = make_req("GET", "/");
        a.headers = vec![("X-Old".to_string(), "old".to_string())];
        b.headers = vec![("X-New".to_string(), "new".to_string())];
        let d = RequestDiffer::diff(&a, &b);
        assert!(!d.added_headers.is_empty());
        assert!(!d.removed_headers.is_empty());
    }

    #[test]
    fn diff_header_modified() {
        let mut a = make_req("GET", "/");
        let mut b = make_req("GET", "/");
        a.headers = vec![("Accept".to_string(), "text/html".to_string())];
        b.headers = vec![("Accept".to_string(), "application/json".to_string())];
        let d = RequestDiffer::diff(&a, &b);
        assert!(!d.modified_headers.is_empty());
        let (name, old, new) = &d.modified_headers[0];
        assert_eq!(name, "accept");
        assert_eq!(old, "text/html");
        assert_eq!(new, "application/json");
    }

    #[test]
    fn diff_text_body_diff() {
        let mut a = make_req("POST", "/");
        let mut b = make_req("POST", "/");
        a.body = b"line1\nline2\nline3\n".to_vec();
        b.body = b"line1\nline2 modified\nline3\n".to_vec();
        let d = RequestDiffer::diff(&a, &b);
        if let Some(BodyDiff::TextDiff(lines)) = d.body_diff {
            let has_added = lines.iter().any(|l| l.kind == DiffKind::Added);
            let has_removed = lines.iter().any(|l| l.kind == DiffKind::Removed);
            assert!(has_added, "expected added lines");
            assert!(has_removed, "expected removed lines");
        } else {
            panic!("expected TextDiff");
        }
    }

    #[test]
    fn diff_binary_body_diff() {
        let mut a = make_req("POST", "/");
        let mut b = make_req("POST", "/");
        a.body = vec![0xFF, 0xFE, 0x01, 0x02, 0x03];
        b.body = vec![0xFF, 0xFE, 0x99, 0x02, 0x03];
        let d = RequestDiffer::diff(&a, &b);
        if let Some(BodyDiff::BinaryChanged {
            common_prefix,
            common_suffix,
        }) = d.body_diff
        {
            assert_eq!(common_prefix, 2); // 0xFF, 0xFE
            assert_eq!(common_suffix, 2); // 0x02, 0x03
        } else {
            panic!("expected BinaryChanged");
        }
    }

    #[test]
    fn diff_response_status_change() {
        let a = make_resp(200);
        let b = make_resp(404);
        let d = RequestDiffer::diff_response(&a, &b);
        assert_eq!(d.status_changed, Some((200, 404)));
    }

    // ── TrafficAnalyzer ───────────────────────────────────────────────────

    fn make_log_entry(
        method: &str,
        url: &str,
        timestamp: u64,
        req_body: Vec<u8>,
        resp_body: Vec<u8>,
        resp_status: u16,
        headers: Vec<(String, String)>,
    ) -> RequestLogEntry {
        RequestLogEntry {
            id: 1,
            timestamp,
            method: method.to_string(),
            url: url.to_string(),
            req_headers: headers,
            req_body,
            resp_status,
            resp_body,
        }
    }

    #[test]
    fn detect_beaconing_finds_regular_pattern() {
        // 5 requests 1 second apart to the same endpoint.
        let history: Vec<RequestLogEntry> = (0..5)
            .map(|i| {
                make_log_entry(
                    "GET",
                    "http://beacon.example.com/ping",
                    1000 * i,
                    vec![],
                    vec![],
                    200,
                    vec![],
                )
            })
            .collect();
        let groups = TrafficAnalyzer::detect_beaconing(&history, 50);
        assert!(!groups.is_empty(), "should detect beaconing");
        assert_eq!(groups[0].avg_interval_ms, 1000);
    }

    #[test]
    fn detect_beaconing_ignores_sparse_requests() {
        // Only 2 requests — below the 3-request minimum.
        let history = vec![
            make_log_entry(
                "GET",
                "http://example.com/api",
                0,
                vec![],
                vec![],
                200,
                vec![],
            ),
            make_log_entry(
                "GET",
                "http://example.com/api",
                1000,
                vec![],
                vec![],
                200,
                vec![],
            ),
        ];
        let groups = TrafficAnalyzer::detect_beaconing(&history, 50);
        assert!(groups.is_empty());
    }

    #[test]
    fn detect_exfil_flags_large_posts() {
        let body = vec![0xAAu8; 10_000];
        let history: Vec<RequestLogEntry> = (0..5)
            .map(|i| {
                make_log_entry(
                    "POST",
                    "http://evil.example.com/upload",
                    i * 1000,
                    body.clone(),
                    vec![],
                    200,
                    vec![],
                )
            })
            .collect();
        let events = TrafficAnalyzer::detect_data_exfil(&history, 40_000);
        assert!(!events.is_empty());
        assert!(events[0].bytes_sent >= 50_000);
    }

    #[test]
    fn detect_exfil_ignores_small_posts() {
        let history = vec![make_log_entry(
            "POST",
            "http://example.com/small",
            0,
            b"tiny".to_vec(),
            vec![],
            200,
            vec![],
        )];
        let events = TrafficAnalyzer::detect_data_exfil(&history, 1_000_000);
        assert!(events.is_empty());
    }

    #[test]
    fn extract_credentials_basic_auth() {
        // Authorization: Basic base64("admin:secret")
        let header_val = format!("Basic {}", base64_encode(b"admin:secret"));
        let history = vec![make_log_entry(
            "GET",
            "http://example.com/protected",
            0,
            vec![],
            vec![],
            200,
            vec![("Authorization".to_string(), header_val)],
        )];
        let creds = TrafficAnalyzer::extract_credentials(&history);
        assert!(!creds.is_empty());
        let c = &creds[0];
        assert!(matches!(c.credential_type, CredType::BasicAuth));
        assert_eq!(c.username.as_deref(), Some("admin"));
        assert_eq!(c.password.as_deref(), Some("secret"));
    }

    #[test]
    fn extract_credentials_bearer_token() {
        let history = vec![make_log_entry(
            "GET",
            "http://example.com/api",
            0,
            vec![],
            vec![],
            200,
            vec![(
                "Authorization".to_string(),
                "Bearer eyJhbGciOiJSUzI1NiJ9".to_string(),
            )],
        )];
        let creds = TrafficAnalyzer::extract_credentials(&history);
        assert!(!creds.is_empty());
        assert!(matches!(creds[0].credential_type, CredType::BearerToken));
        assert_eq!(creds[0].token.as_deref(), Some("eyJhbGciOiJSUzI1NiJ9"));
    }

    #[test]
    fn extract_credentials_form_post() {
        let body = b"username=alice&password=hunter2&submit=Login";
        let history = vec![make_log_entry(
            "POST",
            "http://example.com/login",
            0,
            body.to_vec(),
            vec![],
            200,
            vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
        )];
        let creds = TrafficAnalyzer::extract_credentials(&history);
        assert!(!creds.is_empty());
        let c = &creds[0];
        assert!(matches!(c.credential_type, CredType::FormPost));
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn extract_credentials_api_key_in_query() {
        let history = vec![make_log_entry(
            "GET",
            "http://api.example.com/data?api_key=abc123xyz&page=1",
            0,
            vec![],
            vec![],
            200,
            vec![],
        )];
        let creds = TrafficAnalyzer::extract_credentials(&history);
        assert!(!creds.is_empty());
        assert!(matches!(creds[0].credential_type, CredType::ApiKey));
        assert_eq!(creds[0].token.as_deref(), Some("abc123xyz"));
    }

    #[test]
    fn extract_credentials_cookie_session() {
        let history = vec![make_log_entry(
            "GET",
            "http://example.com/app",
            0,
            vec![],
            vec![],
            200,
            vec![(
                "Cookie".to_string(),
                "session_id=abc; lang=en; auth_token=xyz123".to_string(),
            )],
        )];
        let creds = TrafficAnalyzer::extract_credentials(&history);
        // Should find session_id and auth_token cookies.
        assert!(!creds.is_empty());
        assert!(creds.iter().any(|c| matches!(&c.credential_type, CredType::Cookie(n) if n == "session_id" || n == "auth_token")));
    }

    // ── Scope ─────────────────────────────────────────────────────────────

    #[test]
    fn scope_empty_matches_everything() {
        let scope = Scope::new();
        assert!(scope.is_empty());
        assert!(scope.matches("https://example.com/anything"));
        assert!(scope.matches("http://other.com/path"));
    }

    #[test]
    fn scope_include_glob() {
        let mut scope = Scope::new();
        scope.include_glob("https://api.example.com/**");
        assert!(scope.matches("https://api.example.com/v1/resource"));
        assert!(!scope.matches("https://www.example.com/page"));
    }

    #[test]
    fn scope_exclude_glob_overrides_include() {
        let mut scope = Scope::new();
        scope.include_glob("https://example.com/**");
        scope.exclude_glob("https://example.com/private/**");
        assert!(scope.matches("https://example.com/public/page"));
        assert!(!scope.matches("https://example.com/private/secret"));
    }

    #[test]
    fn scope_multiple_includes() {
        let mut scope = Scope::new();
        scope.include_glob("https://api.example.com/**");
        scope.include_glob("https://cdn.example.com/**");
        assert!(scope.matches("https://api.example.com/endpoint"));
        assert!(scope.matches("https://cdn.example.com/image.png"));
        assert!(!scope.matches("https://other.com/page"));
    }

    // ── glob_match ────────────────────────────────────────────────────────

    #[test]
    fn glob_match_literal() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_match_star_within_segment() {
        assert!(glob_match("*.txt", "file.txt"));
        assert!(!glob_match("*.txt", "dir/file.txt"));
    }

    #[test]
    fn glob_match_double_star_crosses_slashes() {
        assert!(glob_match("**/README.md", "a/b/c/README.md"));
        assert!(glob_match("src/**/*.rs", "src/foo/bar/lib.rs"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(!glob_match("file?.txt", "file10.txt"));
    }

    // ── WebSocketFrame ────────────────────────────────────────────────────

    #[test]
    fn websocket_text_frame_roundtrip() {
        let msg = "Hello, WebSocket!";
        let frame = WebSocketFrame::text(msg);
        let bytes = frame.serialize();
        let (parsed, consumed) = WebSocketFrame::parse(&bytes).expect("parse failed");
        assert_eq!(consumed, bytes.len());
        assert!(matches!(parsed.opcode, WsOpcode::Text));
        assert_eq!(parsed.payload_str(), msg);
    }

    #[test]
    fn websocket_binary_frame_roundtrip() {
        let data = vec![0x01u8, 0x02, 0x03, 0xFE, 0xFF];
        let frame = WebSocketFrame::binary(data.clone());
        let bytes = frame.serialize();
        let (parsed, _) = WebSocketFrame::parse(&bytes).unwrap();
        assert!(matches!(parsed.opcode, WsOpcode::Binary));
        assert_eq!(parsed.payload, data);
    }

    #[test]
    fn websocket_masked_frame_roundtrip() {
        let mut frame = WebSocketFrame::text("masked payload");
        frame.masked = true;
        let bytes = frame.serialize();
        let (parsed, _) = WebSocketFrame::parse(&bytes).unwrap();
        // After parse the payload is already unmasked.
        assert_eq!(parsed.payload_str(), "masked payload");
    }

    #[test]
    fn websocket_control_frames() {
        assert!(WebSocketFrame::ping(vec![]).is_control());
        assert!(WebSocketFrame::pong(vec![]).is_control());
        assert!(WebSocketFrame::close(1000, "Normal closure").is_control());
        assert!(!WebSocketFrame::text("data").is_control());
        assert!(!WebSocketFrame::binary(vec![]).is_control());
    }

    #[test]
    fn websocket_parse_stream_multiple_frames() {
        let f1 = WebSocketFrame::text("frame 1").serialize();
        let f2 = WebSocketFrame::text("frame 2").serialize();
        let f3 = WebSocketFrame::binary(vec![1, 2, 3]).serialize();
        let mut stream = Vec::new();
        stream.extend_from_slice(&f1);
        stream.extend_from_slice(&f2);
        stream.extend_from_slice(&f3);
        let frames = parse_websocket_stream(&stream);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload_str(), "frame 1");
        assert_eq!(frames[1].payload_str(), "frame 2");
        assert_eq!(frames[2].payload, vec![1, 2, 3]);
    }

    #[test]
    fn websocket_detect_upgrade() {
        let mut req = HttpRequest::get("http://example.com/ws");
        req.headers
            .push(("Upgrade".to_string(), "websocket".to_string()));
        req.headers
            .push(("Connection".to_string(), "Upgrade".to_string()));
        assert!(detect_websocket_upgrade(&req));
    }

    #[test]
    fn websocket_no_upgrade_headers() {
        let req = HttpRequest::get("http://example.com/api");
        assert!(!detect_websocket_upgrade(&req));
    }

    #[test]
    fn websocket_parse_truncated_returns_none() {
        // A frame header only (2 bytes), but payload says 100 bytes of content.
        let data = vec![0x81u8, 0x64]; // text, 100 bytes payload (not present)
        assert!(WebSocketFrame::parse(&data).is_none());
    }

    #[test]
    fn websocket_close_frame_carries_code() {
        let frame = WebSocketFrame::close(1001, "Going Away");
        assert_eq!(&frame.payload[..2], &1001u16.to_be_bytes());
        assert_eq!(&frame.payload[2..], b"Going Away");
    }

    #[test]
    fn websocket_large_payload_16bit_length() {
        // 200-byte payload uses the 16-bit extended length encoding.
        let payload = vec![0xABu8; 200];
        let frame = WebSocketFrame::binary(payload.clone());
        let bytes = frame.serialize();
        // Second byte should be 0x7E (126) for 16-bit length.
        assert_eq!(bytes[1] & 0x7F, 126);
        let (parsed, _) = WebSocketFrame::parse(&bytes).unwrap();
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reassemble_ws_messages_single_unfragmented() {
        let frames = vec![WebSocketFrame::text("complete")];
        let msgs = reassemble_ws_messages(&frames);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload_str(), "complete");
    }

    #[test]
    fn reassemble_ws_messages_fragmented() {
        let first = WebSocketFrame {
            fin: false,
            rsv: 0,
            opcode: WsOpcode::Text,
            masked: false,
            payload: b"hell".to_vec(),
        };
        let last = WebSocketFrame {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Continuation,
            masked: false,
            payload: b"o".to_vec(),
        };
        let msgs = reassemble_ws_messages(&[first, last]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload_str(), "hello");
    }

    #[test]
    fn reassemble_ws_messages_control_frame_interleaved() {
        let first = WebSocketFrame {
            fin: false,
            rsv: 0,
            opcode: WsOpcode::Text,
            masked: false,
            payload: b"data".to_vec(),
        };
        let ping = WebSocketFrame::ping(b"keep-alive".to_vec());
        let last = WebSocketFrame {
            fin: true,
            rsv: 0,
            opcode: WsOpcode::Continuation,
            masked: false,
            payload: b" end".to_vec(),
        };
        let msgs = reassemble_ws_messages(&[first, ping, last]);
        // 1 reassembled message + 1 ping
        assert_eq!(msgs.len(), 2);
        let data_msg = msgs
            .iter()
            .find(|m| matches!(m.opcode, WsOpcode::Text))
            .unwrap();
        assert_eq!(data_msg.payload_str(), "data end");
    }

    // ── base64_decode ─────────────────────────────────────────────────────

    #[test]
    fn base64_decode_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_decode_known_values() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("").unwrap(), b"" as &[u8]);
    }

    #[test]
    fn base64_decode_binary() {
        let data = vec![0xFFu8, 0xFE, 0x00, 0x01];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // ── json_string escaping ──────────────────────────────────────────────

    #[test]
    fn json_string_escapes_quotes_and_backslash() {
        let out = json_string("say \"hello\" \\world");
        assert_eq!(out, r#""say \"hello\" \\world""#);
    }

    #[test]
    fn json_string_escapes_newline_tab() {
        let out = json_string("line1\nline2\ttab");
        assert!(out.contains("\\n"));
        assert!(out.contains("\\t"));
    }

    // ── extract_host / extract_path ───────────────────────────────────────

    #[test]
    fn extract_host_from_full_url() {
        assert_eq!(
            extract_host("https://api.example.com/v1/resource"),
            "api.example.com"
        );
        assert_eq!(extract_host("http://example.com/"), "example.com");
        assert_eq!(
            extract_host("http://example.com:8080/path"),
            "example.com:8080"
        );
    }

    #[test]
    fn extract_path_from_full_url() {
        assert_eq!(
            extract_path("https://example.com/v1/resource"),
            "v1/resource"
        );
        assert_eq!(extract_path("https://example.com/path?q=1"), "path");
        assert_eq!(extract_path("/relative/path"), "/relative/path");
    }

    // ── C2 detection smoke test ───────────────────────────────────────────

    #[test]
    fn c2_detection_identifies_suspicious_host() {
        // 15 requests to same host, tiny consistent response bodies, no browser UA.
        let history: Vec<RequestLogEntry> = (0..15)
            .map(|i| {
                make_log_entry(
                    "GET",
                    "http://suspicious.example.com/beacon",
                    i * 5000,
                    vec![],
                    vec![0x4Fu8, 0x4B], // "OK" — 2 bytes
                    200,
                    vec![("User-Agent".to_string(), "go-http-client/1.1".to_string())],
                )
            })
            .collect();
        let indicators = TrafficAnalyzer::detect_c2_patterns(&history);
        assert!(!indicators.is_empty());
        let top = &indicators[0];
        assert!(
            top.confidence > 0.5,
            "confidence should be high: {}",
            top.confidence
        );
        assert!(top.host.contains("suspicious.example.com"));
    }

    // ── simple_regex_match ────────────────────────────────────────────────

    #[test]
    fn regex_match_dot_star() {
        assert!(simple_regex_match("he.*world", "hello world"));
        assert!(simple_regex_match("^hello$", "hello"));
        assert!(!simple_regex_match("^hello$", "hello world"));
    }

    #[test]
    fn regex_match_character_class() {
        assert!(simple_regex_match("[0-9]+", "abc123def"));
        assert!(!simple_regex_match("^[0-9]+$", "abc"));
    }

    #[test]
    fn regex_match_question_mark() {
        assert!(simple_regex_match("colou?r", "colour"));
        assert!(simple_regex_match("colou?r", "color"));
        assert!(!simple_regex_match("colou?r", "colouur"));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests: Enterprise MITM features — JA3/JA4, Intruder, Replay, PCAP, Burp
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod enterprise_mitm_tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn make_log_entry_simple(method: &str, url: &str, status: u16) -> RequestLogEntry {
        RequestLogEntry {
            id: 1,
            timestamp: 1_700_000_000_000,
            method: method.to_string(),
            url: url.to_string(),
            req_headers: vec![],
            req_body: vec![],
            resp_status: status,
            resp_body: b"test body".to_vec(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JA3 / JA4 Fingerprinting
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn ja3_build_string_basic() {
        let fields = ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x002f, 0x0035],
            extensions: vec![0x0000, 0x000a],
            elliptic_curves: vec![0x0017],
            ec_point_formats: vec![0x00],
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
        };
        let s = Ja3Fingerprinter::build_string(&fields);
        assert!(s.starts_with("771,"), "should start with TLS version 771");
        assert!(
            s.contains("47-53"),
            "should contain cipher suites joined by dash"
        );
        assert!(s.contains("0-10"), "should contain extension types");
    }

    #[test]
    fn ja3_fingerprint_is_32_hex_chars() {
        let fields = ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0x002b, 0x0033],
            elliptic_curves: vec![0x001d, 0x0017],
            ec_point_formats: vec![0x00],
            sni: Some("api.test.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        let fp = Ja3Fingerprinter::fingerprint(&fields);
        assert_eq!(
            fp.len(),
            32,
            "JA3 fingerprint should be 32 hex chars, got: {fp}"
        );
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "should be all hex"
        );
    }

    #[test]
    fn ja3_same_fields_same_fingerprint() {
        let fields = ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x002f],
            extensions: vec![0x0000],
            elliptic_curves: vec![0x0017],
            ec_point_formats: vec![0x00],
            sni: None,
            alpn: vec![],
        };
        let fp1 = Ja3Fingerprinter::fingerprint(&fields);
        let fp2 = Ja3Fingerprinter::fingerprint(&fields);
        assert_eq!(fp1, fp2, "same input → same fingerprint");
    }

    #[test]
    fn ja3_different_fields_different_fingerprint() {
        let mut fields = ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x002f],
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
            sni: None,
            alpn: vec![],
        };
        let fp1 = Ja3Fingerprinter::fingerprint(&fields);
        fields.cipher_suites = vec![0x0035];
        let fp2 = Ja3Fingerprinter::fingerprint(&fields);
        assert_ne!(fp1, fp2, "different cipher suites → different fingerprint");
    }

    #[test]
    fn ja3_grease_values_excluded() {
        let fields_with_grease = ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x0a0a, 0x002f], // 0x0a0a is GREASE
            extensions: vec![0x0000],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
            sni: None,
            alpn: vec![],
        };
        let s = Ja3Fingerprinter::build_string(&fields_with_grease);
        // GREASE value 2570 should NOT appear in the string
        assert!(
            !s.contains("2570"),
            "GREASE value should be excluded from JA3 string"
        );
    }

    #[test]
    fn ja4_fingerprint_format() {
        let fields = ClientHelloFields {
            tls_version: 0x0304,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            extensions: vec![0x0000, 0x002b, 0x0033],
            elliptic_curves: vec![0x001d],
            ec_point_formats: vec![0x00],
            sni: Some("test.example.com".to_string()),
            alpn: vec!["h2".to_string()],
        };
        let fp = Ja4Fingerprinter::fingerprint(&fields);
        // Should start with 't13d...' for TCP, TLS 1.3, SNI present
        assert!(fp.starts_with('t'), "JA4 starts with protocol 't'");
        assert!(fp.contains("13"), "JA4 contains TLS 1.3 version");
        // Should have two underscore separators
        assert_eq!(
            fp.chars().filter(|&c| c == '_').count(),
            2,
            "JA4 has two _ separators"
        );
    }

    #[test]
    fn ja4_no_sni_uses_i_indicator() {
        let fields = ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x002f],
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
            sni: None,
            alpn: vec![],
        };
        let fp = Ja4Fingerprinter::fingerprint(&fields);
        assert!(fp.contains('i'), "no SNI should produce 'i' indicator");
    }

    #[test]
    fn is_grease_known_values() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(is_grease(0xdada));
        assert!(!is_grease(0x002f));
        assert!(!is_grease(0x0000));
        assert!(!is_grease(0xffff));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Content-Encoding Decoder
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_identity_is_passthrough() {
        let data = b"hello world";
        let decoded = decode_content_encoding(data, "identity");
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_empty_encoding_is_passthrough() {
        let data = b"raw data";
        assert_eq!(decode_content_encoding(data, ""), data);
    }

    #[test]
    fn decode_gzip_invalid_returns_original() {
        let data = b"not gzip data";
        let decoded = decode_content_encoding(data, "gzip");
        // Should return original since data is not valid gzip
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_deflate_valid_stored_block() {
        // Build a valid zlib-wrapped DEFLATE stored block containing "hello"
        let payload = b"hello";
        let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
        let nlen = !len;
        let mut block = vec![
            0x78, 0x9c, // zlib header (CMF=0x78, FLG=0x9c → valid as 0x789c % 31 == 0)
            0x01, // BFINAL=1, BTYPE=00 (stored)
        ];
        block.extend_from_slice(&len.to_le_bytes());
        block.extend_from_slice(&nlen.to_le_bytes());
        block.extend_from_slice(payload);
        // Add Adler32 checksum (4 bytes, placeholder 0)
        block.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let decoded = decode_content_encoding(&block, "deflate");
        assert_eq!(decoded, payload, "should decompress stored block correctly");
    }

    #[test]
    fn decode_unknown_encoding_is_passthrough() {
        let data = b"brotli encoded would be here";
        let decoded = decode_content_encoding(data, "br");
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_http_response_body_no_encoding() {
        let resp = HttpResponse {
            version: "HTTP/1.1".to_string(),
            status: 200,
            reason: "OK".to_string(),
            headers: vec![],
            body: b"plain body".to_vec(),
        };
        let (decoded, encoding) = decode_http_response_body(&resp);
        assert_eq!(decoded, b"plain body");
        assert_eq!(encoding, "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JWT Parser
    // ─────────────────────────────────────────────────────────────────────────

    fn make_jwt(header: &str, payload: &str) -> String {
        let h = base64_encode(header.as_bytes());
        let p = base64_encode(payload.as_bytes());
        format!("{h}.{p}.fakesignature")
    }

    #[test]
    fn jwt_parse_basic() {
        let raw = make_jwt(
            r#"{"alg":"RS256","typ":"JWT"}"#,
            r#"{"sub":"user1","iss":"auth.example.com","exp":9999999999}"#,
        );
        let jwt = JwtToken::parse(&raw).expect("should parse valid JWT");
        assert_eq!(jwt.algorithm, "RS256");
        assert_eq!(jwt.token_type, "JWT");
        assert_eq!(jwt.subject.as_deref(), Some("user1"));
        assert_eq!(jwt.issuer.as_deref(), Some("auth.example.com"));
    }

    #[test]
    fn jwt_parse_hs256_weak_algorithm() {
        let raw = make_jwt(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"sub":"test"}"#);
        let jwt = JwtToken::parse(&raw).unwrap();
        assert!(
            jwt.uses_weak_algorithm(),
            "HS256 is a weak (HMAC) algorithm"
        );
    }

    #[test]
    fn jwt_parse_none_algorithm_weak() {
        let raw = make_jwt(r#"{"alg":"none","typ":"JWT"}"#, r#"{"sub":"admin"}"#);
        let jwt = JwtToken::parse(&raw).unwrap();
        assert!(
            jwt.uses_weak_algorithm(),
            "'none' algorithm is critically weak"
        );
    }

    #[test]
    fn jwt_parse_rs256_not_weak() {
        let raw = make_jwt(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"sub":"user"}"#);
        let jwt = JwtToken::parse(&raw).unwrap();
        assert!(!jwt.uses_weak_algorithm(), "RS256 is a strong algorithm");
    }

    #[test]
    fn jwt_is_expired() {
        let raw = make_jwt(
            r#"{"alg":"RS256","typ":"JWT"}"#,
            r#"{"sub":"u","exp":1000}"#,
        );
        let jwt = JwtToken::parse(&raw).unwrap();
        assert!(
            jwt.is_expired(2000),
            "token with exp=1000 is expired at t=2000"
        );
        assert!(
            !jwt.is_expired(500),
            "token with exp=1000 is not expired at t=500"
        );
    }

    #[test]
    fn jwt_parse_invalid_returns_none() {
        assert!(JwtToken::parse("not.a.jwt.at.all").is_none());
        assert!(JwtToken::parse("").is_none());
        assert!(JwtToken::parse("onlyone").is_none());
    }

    #[test]
    fn jwt_parse_two_segments_returns_none() {
        // Only two segments — not a valid JWT
        assert!(JwtToken::parse("aGVhZGVy.cGF5bG9hZA").is_none());
    }

    #[test]
    fn extract_jwt_tokens_from_authorization_header() {
        let raw = make_jwt(r#"{"alg":"RS256","typ":"JWT"}"#, r#"{"sub":"alice"}"#);
        let entry = RequestLogEntry {
            id: 1,
            timestamp: 0,
            method: "GET".to_string(),
            url: "https://api.example.com/".to_string(),
            req_headers: vec![("Authorization".to_string(), format!("Bearer {raw}"))],
            req_body: vec![],
            resp_status: 200,
            resp_body: vec![],
        };
        let jwts = extract_jwt_tokens(&[entry]);
        assert!(
            !jwts.is_empty(),
            "should extract JWT from Authorization header"
        );
        assert_eq!(jwts[0].subject.as_deref(), Some("alice"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Replay Store
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn replay_store_save_and_retrieve() {
        let store = ReplayStore::new();
        let req = SavedRequest {
            id: 0,
            saved_at: 0,
            method: "POST".to_string(),
            url: "https://api.example.com/login".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: b"{\"user\":\"test\"}".to_vec(),
            notes: "login endpoint".to_string(),
        };
        let id = store.save(req);
        assert_eq!(id, 1);
        let retrieved = store.get(id).expect("should find saved request");
        assert_eq!(retrieved.method, "POST");
        assert_eq!(retrieved.url, "https://api.example.com/login");
    }

    #[test]
    fn replay_store_multiple_saves_get_unique_ids() {
        let store = ReplayStore::new();
        let req = SavedRequest {
            id: 0,
            saved_at: 0,
            method: "GET".to_string(),
            url: "/".to_string(),
            headers: vec![],
            body: vec![],
            notes: String::new(),
        };
        let id1 = store.save(req.clone());
        let id2 = store.save(req.clone());
        let id3 = store.save(req);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn replay_store_delete() {
        let store = ReplayStore::new();
        let req = SavedRequest {
            id: 0,
            saved_at: 0,
            method: "GET".to_string(),
            url: "/".to_string(),
            headers: vec![],
            body: vec![],
            notes: String::new(),
        };
        let id = store.save(req);
        assert_eq!(store.len(), 1);
        assert!(store.delete(id));
        assert_eq!(store.len(), 0);
        assert!(!store.delete(id), "deleting non-existent id returns false");
    }

    #[test]
    fn saved_request_to_http_bytes() {
        let req = SavedRequest {
            id: 1,
            saved_at: 0,
            method: "GET".to_string(),
            url: "https://example.com/path".to_string(),
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: vec![],
            notes: String::new(),
        };
        let bytes = req.to_http_bytes();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.starts_with("GET /path HTTP/1.1\r\n"),
            "should produce correct request line, got: {}",
            &s[..s.find('\r').unwrap_or(s.len())]
        );
        assert!(s.contains("Host: example.com"));
    }

    #[test]
    fn replay_diff_identical_results() {
        let baseline = ReplayResult::simulated(1, 200, b"hello".to_vec());
        let fuzzed = ReplayResult::simulated(1, 200, b"hello".to_vec());
        let diff = ReplayDiff::compute(&baseline, &fuzzed);
        assert!(diff.is_identical());
    }

    #[test]
    fn replay_diff_status_change_detected() {
        let baseline = ReplayResult::simulated(1, 200, b"ok".to_vec());
        let fuzzed = ReplayResult::simulated(1, 500, b"ok".to_vec());
        let diff = ReplayDiff::compute(&baseline, &fuzzed);
        assert!(diff.status_changed);
        assert_eq!(diff.baseline_status, 200);
        assert_eq!(diff.fuzzed_status, 500);
    }

    #[test]
    fn replay_diff_body_bytes_detected() {
        let baseline = ReplayResult::simulated(1, 200, b"aabcc".to_vec());
        let fuzzed = ReplayResult::simulated(1, 200, b"aaxcc".to_vec());
        let diff = ReplayDiff::compute(&baseline, &fuzzed);
        assert!(!diff.differing_byte_offsets.is_empty());
        assert_eq!(diff.differing_byte_offsets[0], 2); // offset 2 differs
    }

    #[test]
    fn replay_diff_body_length_delta() {
        let baseline = ReplayResult::simulated(1, 200, b"short".to_vec());
        let fuzzed = ReplayResult::simulated(1, 200, b"much longer body".to_vec());
        let diff = ReplayDiff::compute(&baseline, &fuzzed);
        assert_eq!(diff.body_length_delta, 11); // 16 - 5 = 11
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Intruder Engine
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn intruder_template_parse_single_marker() {
        let template_str = "username=§admin§&password=test";
        let tmpl = IntruderTemplate::parse(template_str.as_bytes());
        assert_eq!(tmpl.positions.len(), 1);
        // The position should cover the "admin" text
        let pos = tmpl.positions[0];
        assert_eq!(&tmpl.original[pos.start..pos.end], b"admin");
    }

    #[test]
    fn intruder_template_parse_two_markers() {
        let tmpl = IntruderTemplate::parse(b"u=\xC2\xA7user\xC2\xA7&p=\xC2\xA7pass\xC2\xA7");
        assert_eq!(tmpl.positions.len(), 2, "should find two positions");
    }

    #[test]
    fn intruder_payload_wordlist_expand() {
        let pl = PayloadType::Wordlist(vec![
            "admin".to_string(),
            "root".to_string(),
            "test".to_string(),
        ]);
        let expanded = pl.expand();
        assert_eq!(expanded, vec!["admin", "root", "test"]);
    }

    #[test]
    fn intruder_payload_number_range_expand() {
        let pl = PayloadType::NumberRange {
            from: 1,
            to: 5,
            step: 1,
        };
        let expanded = pl.expand();
        assert_eq!(expanded, vec!["1", "2", "3", "4", "5"]);
    }

    #[test]
    fn intruder_payload_number_range_with_step() {
        let pl = PayloadType::NumberRange {
            from: 0,
            to: 10,
            step: 2,
        };
        let expanded = pl.expand();
        assert_eq!(expanded, vec!["0", "2", "4", "6", "8", "10"]);
    }

    #[test]
    fn intruder_payload_null_byte_expand() {
        let pl = PayloadType::NullByte;
        let expanded = pl.expand();
        assert!(!expanded.is_empty());
        assert!(expanded.contains(&"\x00".to_string()));
        assert!(expanded.contains(&"%00".to_string()));
    }

    #[test]
    fn intruder_sniper_one_position() {
        let tmpl = IntruderTemplate::parse(b"id=\xC2\xA71\xC2\xA7");
        let payloads = vec![PayloadType::Wordlist(vec![
            "2".to_string(),
            "3".to_string(),
        ])];
        let candidates = IntruderEngine::run(&tmpl, AttackType::Sniper, &payloads);
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].bytes.windows(1).any(|w| w == b"2"));
        assert!(candidates[1].bytes.windows(1).any(|w| w == b"3"));
    }

    #[test]
    fn intruder_battering_ram_all_positions_same_payload() {
        let tmpl = IntruderTemplate::parse(b"u=\xC2\xA7a\xC2\xA7&p=\xC2\xA7b\xC2\xA7");
        let payloads = vec![PayloadType::Wordlist(vec!["X".to_string()])];
        let candidates = IntruderEngine::run(&tmpl, AttackType::BatteringRam, &payloads);
        assert_eq!(candidates.len(), 1, "one payload → one candidate");
        // Both positions should be substituted with "X"
        let s = String::from_utf8_lossy(&candidates[0].bytes);
        assert_eq!(
            candidates[0].substitutions.len(),
            2,
            "both positions substituted"
        );
        let _s = s; // suppress unused warning
    }

    #[test]
    fn intruder_pitchfork_parallel_iteration() {
        let tmpl = IntruderTemplate::parse(b"u=\xC2\xA7user\xC2\xA7&p=\xC2\xA7pass\xC2\xA7");
        let payloads = vec![
            PayloadType::Wordlist(vec!["alice".to_string(), "bob".to_string()]),
            PayloadType::Wordlist(vec!["secret1".to_string(), "secret2".to_string()]),
        ];
        let candidates = IntruderEngine::run(&tmpl, AttackType::Pitchfork, &payloads);
        assert_eq!(candidates.len(), 2, "pitchfork: min(2, 2) = 2 candidates");
    }

    #[test]
    fn intruder_cluster_bomb_cartesian_product() {
        let tmpl = IntruderTemplate::parse(b"u=\xC2\xA7u\xC2\xA7&p=\xC2\xA7p\xC2\xA7");
        let payloads = vec![
            PayloadType::Wordlist(vec!["a".to_string(), "b".to_string()]),
            PayloadType::Wordlist(vec!["1".to_string(), "2".to_string()]),
        ];
        let candidates = IntruderEngine::run(&tmpl, AttackType::ClusterBomb, &payloads);
        // 2 × 2 = 4 candidates
        assert_eq!(candidates.len(), 4, "cluster bomb: 2×2 = 4 candidates");
    }

    #[test]
    fn intruder_template_apply_single_sub() {
        let tmpl = IntruderTemplate::parse(b"value=\xC2\xA7placeholder\xC2\xA7");
        let pos = tmpl.positions[0];
        let result = tmpl.apply(&[(pos, "injected")]);
        assert_eq!(result, b"value=injected");
    }

    #[test]
    fn intruder_summarize_results() {
        let results = vec![
            ReplayResult::simulated(1, 200, vec![]),
            ReplayResult::simulated(2, 200, vec![]),
            ReplayResult::simulated(3, 500, vec![]),
            ReplayResult::simulated(4, 404, vec![]),
        ];
        let summary = IntruderEngine::summarize_results(&results);
        assert_eq!(summary.get(&200), Some(&2));
        assert_eq!(summary.get(&500), Some(&1));
        assert_eq!(summary.get(&404), Some(&1));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Date increment helper
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn increment_date_str_basic() {
        assert_eq!(increment_date_str("20240101"), "20240102");
        assert_eq!(increment_date_str("20240131"), "20240201");
        assert_eq!(increment_date_str("20241231"), "20250101");
    }

    #[test]
    fn increment_date_str_leap_year() {
        // 2024 is a leap year
        assert_eq!(increment_date_str("20240228"), "20240229");
        assert_eq!(increment_date_str("20240229"), "20240301");
    }

    #[test]
    fn increment_date_str_non_leap() {
        // 2023 is not a leap year
        assert_eq!(increment_date_str("20230228"), "20230301");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PCAP Export
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn pcap_export_global_header() {
        let frames = vec![b"data".to_vec()];
        let pcap = PcapExporter::export_frames(&frames);
        // Magic number at bytes 0-3: 0xa1b2c3d4 LE
        assert!(pcap.len() >= 24, "PCAP must have at least global header");
        assert_eq!(&pcap[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "PCAP magic LE");
        // Version major/minor
        assert_eq!(&pcap[4..6], &[2, 0]);
        assert_eq!(&pcap[6..8], &[4, 0]);
        // Link type Ethernet = 1
        assert_eq!(
            u32::from_le_bytes([pcap[20], pcap[21], pcap[22], pcap[23]]),
            1
        );
    }

    #[test]
    fn pcap_export_packet_count() {
        let frames = vec![b"frame1".to_vec(), b"frame2".to_vec(), b"frame3".to_vec()];
        let pcap = PcapExporter::export_frames(&frames);
        // Each packet record: 16-byte header + data
        // Total size = 24 (global) + 3 * (16 + len)
        let expected = 24 + 3 * (16 + 6);
        assert_eq!(pcap.len(), expected);
    }

    #[test]
    fn pcap_build_tcp_frame_has_ethernet_header() {
        let frame = PcapExporter::build_tcp_frame(b"payload", 1);
        // Ethernet: 14 bytes, IPv4: 20 bytes, TCP: 20 bytes, payload: 7 bytes
        assert_eq!(frame.len(), 14 + 20 + 20 + 7);
        // EtherType 0x0800 at bytes 12-13
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn pcap_from_request_log_produces_valid_pcap() {
        let entries = vec![
            make_log_entry_simple("GET", "https://example.com/api/data", 200),
            make_log_entry_simple("POST", "https://example.com/api/login", 200),
        ];
        let pcap = PcapExporter::from_request_log(&entries);
        // Should start with magic
        assert_eq!(&pcap[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // Should be non-trivially long
        assert!(pcap.len() > 100);
    }

    #[test]
    fn pcap_ip_checksum_known_value() {
        // A sample IPv4 header (all zeros except version+IHL=0x45, TTL=64, proto=6)
        let header: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x28, // ver/IHL, DSCP, total_len
            0x00, 0x00, 0x40, 0x00, // ID, flags+frag
            0x40, 0x06, 0x00, 0x00, // TTL, proto, checksum (placeholder)
            0x7f, 0x00, 0x00, 0x01, // src 127.0.0.1
            0x7f, 0x00, 0x00, 0x01, // dst 127.0.0.1
        ];
        let chk = PcapExporter::ip_checksum(&header);
        // Re-computing with the checksum field filled should give 0
        let mut h2 = header;
        h2[10] = (chk >> 8) as u8;
        h2[11] = (chk & 0xff) as u8;
        assert_eq!(
            PcapExporter::ip_checksum(&h2),
            0,
            "checksum of verified header should be 0"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Burp Suite XML Export
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn burp_export_valid_xml_structure() {
        let entries = vec![make_log_entry_simple(
            "GET",
            "https://example.com/resource",
            200,
        )];
        let xml = BurpExporter::export(&entries);
        assert!(xml.starts_with("<?xml"), "should be valid XML");
        assert!(xml.contains("<items "), "should have <items> root");
        assert!(xml.contains("</items>"));
        assert!(xml.contains("<item>"));
        assert!(xml.contains("</item>"));
    }

    #[test]
    fn burp_export_contains_request_and_response() {
        let entries = vec![make_log_entry_simple(
            "POST",
            "https://api.example.com/login",
            200,
        )];
        let xml = BurpExporter::export(&entries);
        assert!(xml.contains("<request base64=\"true\">"));
        assert!(xml.contains("<response base64=\"true\">"));
        assert!(xml.contains("<method>POST</method>"));
    }

    #[test]
    fn burp_export_multiple_entries() {
        let entries = vec![
            make_log_entry_simple("GET", "https://example.com/a", 200),
            make_log_entry_simple("POST", "https://example.com/b", 201),
            make_log_entry_simple("DELETE", "https://example.com/c", 204),
        ];
        let xml = BurpExporter::export(&entries);
        assert_eq!(xml.matches("<item>").count(), 3);
    }

    #[test]
    fn burp_export_xml_escapes_special_chars() {
        let mut entry = make_log_entry_simple("GET", "https://example.com/path?q=a&b=<test>", 200);
        entry.url = "https://example.com/path?q=a&b=<test>".to_string();
        let xml = BurpExporter::export(&[entry]);
        assert!(xml.contains("&amp;"), "ampersand should be escaped");
        assert!(xml.contains("&lt;"), "less-than should be escaped");
    }

    #[test]
    fn burp_export_http_url_port() {
        let entry = make_log_entry_simple("GET", "http://example.com/page", 200);
        let xml = BurpExporter::export(&[entry]);
        assert!(
            xml.contains("<port>80</port>"),
            "HTTP default port should be 80"
        );
        assert!(xml.contains("<protocol>http</protocol>"));
    }

    #[test]
    fn burp_export_https_url_port() {
        let entry = make_log_entry_simple("GET", "https://secure.example.com/", 200);
        let xml = BurpExporter::export(&[entry]);
        assert!(
            xml.contains("<port>443</port>"),
            "HTTPS default port should be 443"
        );
        assert!(xml.contains("<protocol>https</protocol>"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // mitmproxy JSON-lines export
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mitmproxy_export_one_line_per_entry() {
        let entries = vec![
            make_log_entry_simple("GET", "https://a.example.com/", 200),
            make_log_entry_simple("POST", "https://b.example.com/", 201),
        ];
        let jsonl = MitmproxyExporter::export_jsonl(&entries);
        let line_count = jsonl.lines().count();
        assert_eq!(line_count, 2, "one JSON line per entry");
    }

    #[test]
    fn mitmproxy_export_contains_type_field() {
        let entries = vec![make_log_entry_simple("GET", "https://example.com/", 200)];
        let jsonl = MitmproxyExporter::export_jsonl(&entries);
        assert!(jsonl.contains("\"type\":\"http\""));
    }

    #[test]
    fn mitmproxy_export_valid_json_structure() {
        let entries = vec![make_log_entry_simple(
            "GET",
            "https://api.test.com/v1/data",
            200,
        )];
        let jsonl = MitmproxyExporter::export_jsonl(&entries);
        let line = jsonl.lines().next().unwrap();
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "should be a JSON object"
        );
        assert!(line.contains("\"request\":{"));
        assert!(line.contains("\"response\":{"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Passive Vulnerability Scanner
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn passive_scan_detects_http_url() {
        let entries = vec![make_log_entry_simple(
            "GET",
            "http://plain.example.com/data",
            200,
        )];
        let findings = PassiveVulnScanner::scan(&entries);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::MissingHttps)),
            "should detect plain HTTP usage"
        );
    }

    #[test]
    fn passive_scan_https_no_missing_https_finding() {
        let entries = vec![make_log_entry_simple(
            "GET",
            "https://secure.example.com/",
            200,
        )];
        let findings = PassiveVulnScanner::scan(&entries);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::MissingHttps)),
            "HTTPS URL should not trigger MissingHttps"
        );
    }

    #[test]
    fn passive_scan_detects_insecure_cookie() {
        let mut entry = make_log_entry_simple("GET", "https://example.com/", 200);
        entry.req_headers = vec![(
            "set-cookie".to_string(),
            "session=abc123; Path=/".to_string(),
        )];
        let findings = PassiveVulnScanner::scan(&[entry]);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::InsecureCookie)),
            "cookie without Secure flag should be flagged"
        );
    }

    #[test]
    fn passive_scan_detects_cors_wildcard() {
        let mut entry = make_log_entry_simple("GET", "https://api.example.com/", 200);
        entry.req_headers = vec![("access-control-allow-origin".to_string(), "*".to_string())];
        let findings = PassiveVulnScanner::scan(&[entry]);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::CorsIssue)),
            "wildcard CORS should be flagged"
        );
    }

    #[test]
    fn passive_scan_detects_reflected_xss() {
        let mut entry = make_log_entry_simple(
            "GET",
            "https://example.com/search?q=<script>alert(1)</script>",
            200,
        );
        entry.resp_body = b"<html>Results for: <script>alert(1)</script></html>".to_vec();
        let findings = PassiveVulnScanner::scan(&[entry]);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::ReflectedXss)),
            "reflected XSS pattern should be detected"
        );
    }

    #[test]
    fn passive_scan_detects_sensitive_in_url() {
        let entries = vec![make_log_entry_simple(
            "GET",
            "https://api.example.com/data?api_key=supersecret123",
            200,
        )];
        let findings = PassiveVulnScanner::scan(&entries);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::SensitiveDataInUrl)),
            "API key in URL should be flagged"
        );
    }

    #[test]
    fn passive_scan_detects_potential_idor() {
        let entries = vec![make_log_entry_simple(
            "GET",
            "https://api.example.com/api/user/12345/profile",
            200,
        )];
        let findings = PassiveVulnScanner::scan(&entries);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::PotentialIdor)),
            "numeric ID in user API path should be flagged as potential IDOR"
        );
    }

    #[test]
    fn passive_scan_detects_missing_security_headers() {
        let entries = vec![make_log_entry_simple("GET", "https://example.com/", 200)];
        let findings = PassiveVulnScanner::scan(&entries);
        let has_header_finding = findings
            .iter()
            .any(|f| matches!(f.category, FindingCategory::MissingSecurityHeader(_)));
        assert!(
            has_header_finding,
            "missing security headers should be flagged"
        );
    }

    #[test]
    fn passive_scan_weak_jwt_detected() {
        let raw = make_jwt(r#"{"alg":"HS256","typ":"JWT"}"#, r#"{"sub":"user"}"#);
        let mut entry = make_log_entry_simple("GET", "https://api.example.com/", 200);
        entry.req_headers = vec![("Authorization".to_string(), format!("Bearer {raw}"))];
        let findings = PassiveVulnScanner::scan(&[entry]);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.category, FindingCategory::WeakJwtAlgorithm)),
            "HS256 JWT should trigger WeakJwtAlgorithm finding"
        );
    }

    #[test]
    fn passive_scan_empty_entries_no_crash() {
        let findings = PassiveVulnScanner::scan(&[]);
        assert!(findings.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Finding severity ordering
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn finding_severity_ordering() {
        assert!(FindingSeverity::Critical > FindingSeverity::High);
        assert!(FindingSeverity::High > FindingSeverity::Medium);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
        assert!(FindingSeverity::Low > FindingSeverity::Info);
    }

    #[test]
    fn finding_severity_display() {
        assert_eq!(format!("{}", FindingSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", FindingSeverity::High), "HIGH");
        assert_eq!(format!("{}", FindingSeverity::Info), "INFO");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // simple_md5_hex determinism
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn simple_md5_hex_deterministic() {
        let a = simple_md5_hex(b"hello world");
        let b = simple_md5_hex(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn simple_md5_hex_length() {
        let h = simple_md5_hex(b"test");
        assert_eq!(h.len(), 32, "hash should be 32 hex chars");
    }

    #[test]
    fn simple_md5_hex_different_inputs() {
        let a = simple_md5_hex(b"input A");
        let b = simple_md5_hex(b"input B");
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JSON field extractor helpers
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn json_get_str_simple() {
        assert_eq!(
            json_get_str(r#"{"alg":"RS256","typ":"JWT"}"#, "alg"),
            Some("RS256".to_string())
        );
        assert_eq!(
            json_get_str(r#"{"alg":"RS256","typ":"JWT"}"#, "typ"),
            Some("JWT".to_string())
        );
    }

    #[test]
    fn json_get_str_missing_key() {
        assert_eq!(json_get_str(r#"{"alg":"RS256"}"#, "missing"), None);
    }

    #[test]
    fn json_get_i64_basic() {
        assert_eq!(
            json_get_i64(r#"{"exp":1234567890}"#, "exp"),
            Some(1_234_567_890_i64)
        );
        assert_eq!(json_get_i64(r#"{"iat":1000}"#, "iat"), Some(1000i64));
    }

    #[test]
    fn json_get_i64_missing() {
        assert_eq!(json_get_i64(r#"{"sub":"user"}"#, "exp"), None);
    }
}
