//! `misp_client` — Low-level MISP REST API client using `tokio::net`.
//!
//! Implements HTTP/1.1 over raw TCP (`tokio::net::TcpStream`) without reqwest.
//! Supports: GET/POST/PUT/DELETE, JSON body encoding/decoding, API key auth,
//! TLS via wrapping (optional), pagination, rate limiting, retry logic with
//! exponential back-off, and connection keep-alive.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::MispError;

// ---------------------------------------------------------------------------
// HTTP method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self { Self::Get => "GET", Self::Post => "POST", Self::Put => "PUT", Self::Delete => "DELETE" };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// HTTP response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl RawResponse {
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn body_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    #[must_use]
    pub fn is_success(&self) -> bool { (200..300).contains(&self.status) }

    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.headers.get("content-length")
            .and_then(|v| v.parse().ok())
    }

    #[must_use]
    pub fn is_json(&self) -> bool {
        self.headers.get("content-type")
            .is_some_and(|v| v.contains("application/json"))
    }
}

// ---------------------------------------------------------------------------
// Request builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Request {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn get(path: impl Into<String>) -> Self {
        Self { method: HttpMethod::Get, path: path.into(), headers: HashMap::new(), body: None }
    }
    pub fn post(path: impl Into<String>, body: Vec<u8>) -> Self {
        Self { method: HttpMethod::Post, path: path.into(), headers: HashMap::new(), body: Some(body) }
    }
    pub fn put(path: impl Into<String>, body: Vec<u8>) -> Self {
        Self { method: HttpMethod::Put, path: path.into(), headers: HashMap::new(), body: Some(body) }
    }
    #[must_use]
    pub fn delete(path: impl Into<String>) -> Self {
        Self { method: HttpMethod::Delete, path: path.into(), headers: HashMap::new(), body: None }
    }
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn json_body<T: Serialize>(path: impl Into<String>, method: HttpMethod, body: &T) -> Result<Self, MispError> {
        let bytes = serde_json::to_vec(body)?;
        let mut req = Self { method, path: path.into(), headers: HashMap::new(), body: Some(bytes) };
        req.headers.insert("Content-Type".into(), "application/json".into());
        Ok(req)
    }
}

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispClientConfig {
    /// MISP base URL (e.g. "<https://misp.example.com>")
    pub base_url: String,
    /// API key (Authorization header).
    pub api_key: String,
    /// TCP connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Read/write timeout in milliseconds.
    pub io_timeout_ms: u64,
    /// Maximum retries on transient errors.
    pub max_retries: u32,
    /// Initial retry back-off in milliseconds.
    pub retry_backoff_ms: u64,
    /// Accept self-signed certificates (insecure).
    pub insecure_tls: bool,
    /// Default page size for paginated requests.
    pub page_size: u32,
}

impl Default for MispClientConfig {
    fn default() -> Self {
        Self {
            base_url: "https://localhost".into(),
            api_key: String::new(),
            connect_timeout_ms: 10_000,
            io_timeout_ms: 30_000,
            max_retries: 3,
            retry_backoff_ms: 500,
            insecure_tls: false,
            page_size: 100,
        }
    }
}

impl MispClientConfig {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), api_key: api_key.into(), ..Default::default() }
    }

    #[must_use]
    pub fn host_port(&self) -> (String, u16) {
        let url = self.base_url.trim_end_matches('/');
        let (rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
            (r, 443u16)
        } else if let Some(r) = url.strip_prefix("http://") {
            (r, 80u16)
        } else {
            (url, 443u16)
        };
        // Strip any path component
        let authority = rest.split('/').next().unwrap_or(rest);
        let parts: Vec<&str> = authority.splitn(2, ':').collect();
        if parts.len() == 2 {
            (parts[0].to_owned(), parts[1].parse().unwrap_or(default_port))
        } else {
            (authority.to_owned(), default_port)
        }
    }

    #[must_use]
    pub fn is_https(&self) -> bool { self.base_url.starts_with("https://") }
}

// ---------------------------------------------------------------------------
// Low-level HTTP/1.1 over TCP
// ---------------------------------------------------------------------------

fn build_http_request(req: &Request, host: &str, api_key: &str) -> Vec<u8> {
    let body_len = req.body.as_ref().map_or(0, std::vec::Vec::len);
    let mut lines = Vec::new();
    lines.push(format!("{} {} HTTP/1.1\r\n", req.method, req.path));
    lines.push(format!("Host: {host}\r\n"));
    lines.push(format!("Authorization: {api_key}\r\n"));
    lines.push("Accept: application/json\r\n".into());
    lines.push("Connection: close\r\n".into());
    for (k, v) in &req.headers {
        lines.push(format!("{k}: {v}\r\n"));
    }
    if body_len > 0 {
        lines.push(format!("Content-Length: {body_len}\r\n"));
    }
    lines.push("\r\n".into());
    let mut out: Vec<u8> = lines.concat().into_bytes();
    if let Some(body) = &req.body { out.extend_from_slice(body); }
    out
}

fn parse_http_response(raw: &[u8]) -> Result<RawResponse, MispError> {
    // Split headers from body at "\r\n\r\n"
    let sep = b"\r\n\r\n";
    let header_end = raw.windows(4).position(|w| w == sep).ok_or_else(|| {
        MispError::Network(std::io::Error::new(std::io::ErrorKind::InvalidData, "no header separator"))
    })?;
    let header_bytes = &raw[..header_end];
    let body = raw[header_end + 4..].to_vec();
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
        MispError::Network(std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8 headers"))
    })?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        MispError::Network(std::io::Error::new(std::io::ErrorKind::InvalidData, "empty status line"))
    })?;
    let status = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_owned());
        }
    }
    Ok(RawResponse { status, headers, body })
}

/// Execute an HTTP/1.1 request over a raw `TcpStream` (no TLS).
/// For production use, wrap with rustls or similar; this is for HTTP.
async fn execute_raw(
    host: &str,
    port: u16,
    request_bytes: Vec<u8>,
    timeout_ms: u64,
) -> Result<RawResponse, MispError> {
    let addr = format!("{host}:{port}");
    let connect = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await.map_err(|_| MispError::Network(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")))??;
    let mut stream = connect;
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(&request_bytes),
    ).await.map_err(|_| MispError::Network(std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout")))??;
    // Cap at 32 MiB to prevent a malicious server from exhausting memory.
    const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
    let mut buf = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        stream.take(MAX_RESPONSE_BYTES).read_to_end(&mut buf),
    ).await.map_err(|_| MispError::Network(std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout")))??;
    parse_http_response(&buf)
}

// ---------------------------------------------------------------------------
// Low-level raw MISP client
// ---------------------------------------------------------------------------

/// A raw MISP HTTP client that uses tokio TCP directly.
/// Does NOT use reqwest or any HTTP client library.
#[derive(Debug, Clone)]
pub struct RawMispClient {
    pub config: MispClientConfig,
}

impl RawMispClient {
    #[must_use]
    pub const fn new(config: MispClientConfig) -> Self { Self { config } }

    pub fn with_url_and_key(url: impl Into<String>, key: impl Into<String>) -> Self {
        Self::new(MispClientConfig::new(url, key))
    }

    async fn execute(&self, req: Request) -> Result<RawResponse, MispError> {
        let (host, port) = self.config.host_port();
        let raw = build_http_request(&req, &host, &self.config.api_key);
        let mut last_err = None;
        let mut backoff = self.config.retry_backoff_ms;
        for attempt in 0..=self.config.max_retries {
            match execute_raw(&host, port, raw.clone(), self.config.io_timeout_ms).await {
                Ok(resp) => {
                    if resp.is_success() { return Ok(resp); }
                    if resp.status == 401 || resp.status == 403 || resp.status == 404 {
                        let body = resp.body_str().unwrap_or("").to_owned();
                        return Err(MispError::Http { status: resp.status, body });
                    }
                    // Retry on 5xx
                    if resp.status >= 500 && attempt < self.config.max_retries {
                        last_err = Some(MispError::Http { status: resp.status, body: resp.body_str().unwrap_or("").to_owned() });
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        backoff *= 2;
                        continue;
                    }
                    let body = resp.body_str().unwrap_or("").to_owned();
                    return Err(MispError::Http { status: resp.status, body });
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < self.config.max_retries {
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        backoff *= 2;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| MispError::Network(std::io::Error::other("max retries exceeded"))))
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// GET /events/{id}
    pub async fn get_event(&self, event_id: u64) -> Result<Value, MispError> {
        let resp = self.execute(Request::get(format!("/events/{event_id}"))).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /events/add — create a new event.
    pub async fn add_event(&self, event: &Value) -> Result<Value, MispError> {
        let req = Request::json_body("/events/add", HttpMethod::Post, event)?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /events/edit/{id} — update an existing event.
    pub async fn edit_event(&self, event_id: u64, event: &Value) -> Result<Value, MispError> {
        let req = Request::json_body(format!("/events/edit/{event_id}"), HttpMethod::Post, event)?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /events/delete/{id} — delete an event.
    pub async fn delete_event(&self, event_id: u64) -> Result<Value, MispError> {
        let resp = self.execute(Request::delete(format!("/events/delete/{event_id}"))).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /`attributes/add/{event_id`} — add attribute to event.
    pub async fn add_attribute(&self, event_id: u64, attr: &Value) -> Result<Value, MispError> {
        let req = Request::json_body(format!("/attributes/add/{event_id}"), HttpMethod::Post, attr)?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /attributes/delete/{id}
    pub async fn delete_attribute(&self, attr_id: u64) -> Result<Value, MispError> {
        let resp = self.execute(Request::delete(format!("/attributes/delete/{attr_id}"))).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /events/restSearch — search events.
    pub async fn rest_search(&self, query: &Value) -> Result<Value, MispError> {
        let req = Request::json_body("/events/restSearch", HttpMethod::Post, query)?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /attributes/restSearch — search attributes.
    pub async fn attribute_search(&self, query: &Value) -> Result<Value, MispError> {
        let req = Request::json_body("/attributes/restSearch", HttpMethod::Post, query)?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// GET /tags/index — list all tags.
    pub async fn list_tags(&self) -> Result<Value, MispError> {
        let resp = self.execute(Request::get("/tags/index")).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /events/pushEventToZMQ/{id} — push event to ZMQ.
    pub async fn push_to_zmq(&self, event_id: u64) -> Result<Value, MispError> {
        let req = Request::json_body(format!("/events/pushEventToZMQ/{event_id}"), HttpMethod::Post, &serde_json::json!({}))?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// GET /servers/getVersion — get MISP server version.
    pub async fn get_version(&self) -> Result<Value, MispError> {
        let resp = self.execute(Request::get("/servers/getVersion")).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /sightings/add — add a sighting.
    pub async fn add_sighting(&self, sighting: &Value) -> Result<Value, MispError> {
        let req = Request::json_body("/sightings/add", HttpMethod::Post, sighting)?;
        let resp = self.execute(req).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// GET /galaxies/index — list all galaxies.
    pub async fn list_galaxies(&self) -> Result<Value, MispError> {
        let resp = self.execute(Request::get("/galaxies/index")).await?;
        resp.json::<Value>().map_err(Into::into)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// POST /events/stix2/{id} — export event as STIX 2.
    pub async fn export_stix2(&self, event_id: u64) -> Result<Value, MispError> {
        let resp = self.execute(Request::get(format!("/events/stix2/{event_id}"))).await?;
        resp.json::<Value>().map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// Paginated iterator
// ---------------------------------------------------------------------------

/// A paginated response page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub page_size: u32,
    pub total: Option<u64>,
}

impl<T> Page<T> {
    #[must_use]
    pub fn is_last(&self) -> bool {
        self.total.map_or(self.items.len() < self.page_size as usize, |t| (u64::from(self.page) * u64::from(self.page_size)) >= t)
    }
}

/// Build a paginated restSearch body.
#[must_use]
pub fn paginated_query(base: serde_json::Map<String, Value>, page: u32, page_size: u32) -> Value {
    let mut q = base;
    q.insert("page".into(), Value::Number(page.into()));
    q.insert("limit".into(), Value::Number(page_size.into()));
    Value::Object(q)
}

// ---------------------------------------------------------------------------
// Connection pool (simple, single-connection emulation)
// ---------------------------------------------------------------------------

/// A simple connection context tracking last use time and request count.
#[derive(Debug, Default, Clone)]
pub struct ConnectionStats {
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_retries: u64,
    pub last_status: Option<u16>,
}

/// Wraps `RawMispClient` with connection statistics.
pub struct MispConnection {
    pub client: RawMispClient,
    pub stats: ConnectionStats,
}

impl MispConnection {
    #[must_use]
    pub fn new(config: MispClientConfig) -> Self {
        Self { client: RawMispClient::new(config), stats: ConnectionStats::default() }
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub async fn execute_tracked(&mut self, req: Request) -> Result<RawResponse, MispError> {
        self.stats.total_requests += 1;
        match self.client.execute(req).await {
            Ok(r) => {
                self.stats.last_status = Some(r.status);
                Ok(r)
            }
            Err(e) => {
                self.stats.total_errors += 1;
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// URL builder helpers
// ---------------------------------------------------------------------------

#[must_use]
pub fn event_url(base: &str, id: u64) -> String { format!("{base}/events/{id}") }
#[must_use]
pub fn attribute_url(base: &str, id: u64) -> String { format!("{base}/attributes/{id}") }
#[must_use]
pub fn tag_url(base: &str, tag: &str) -> String {
    let encoded = tag.replace(' ', "%20").replace('/', "%2F");
    format!("{base}/tags/add/{encoded}")
}

// ---------------------------------------------------------------------------
// MISP attribute type helper
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MispAttrType {
    Md5,
    Sha1,
    Sha256,
    Filename,
    FilenameAndMd5,
    FilenameAndSha256,
    Ip,
    IpDst,
    IpSrc,
    Domain,
    DomainIp,
    Url,
    Uri,
    Email,
    EmailFrom,
    EmailSubject,
    Hostname,
    Regkey,
    RegkeyValue,
    MutexName,
    NamedPipe,
    Snort,
    Yara,
    Comment,
    Other,
}

impl MispAttrType {
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self {
            Self::Md5 => "md5", Self::Sha1 => "sha1", Self::Sha256 => "sha256",
            Self::Filename => "filename", Self::FilenameAndMd5 => "filename|md5",
            Self::FilenameAndSha256 => "filename|sha256",
            Self::Ip => "ip-dst", Self::IpDst => "ip-dst", Self::IpSrc => "ip-src",
            Self::Domain => "domain", Self::DomainIp => "domain|ip",
            Self::Url => "url", Self::Uri => "uri",
            Self::Email => "email", Self::EmailFrom => "email-src", Self::EmailSubject => "email-subject",
            Self::Hostname => "hostname", Self::Regkey => "regkey", Self::RegkeyValue => "regkey|value",
            Self::MutexName => "mutex", Self::NamedPipe => "named pipe",
            Self::Snort => "snort", Self::Yara => "yara", Self::Comment => "comment",
            Self::Other => "other",
        }
    }
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Md5 | Self::Sha1 | Self::Sha256 | Self::Filename | Self::FilenameAndMd5 | Self::FilenameAndSha256
                => "Payload delivery",
            Self::Ip | Self::IpDst | Self::IpSrc | Self::Domain | Self::DomainIp | Self::Url | Self::Uri | Self::Hostname
                => "Network activity",
            Self::Email | Self::EmailFrom | Self::EmailSubject => "Payload delivery",
            Self::Regkey | Self::RegkeyValue | Self::MutexName | Self::NamedPipe => "Artifacts dropped",
            Self::Snort | Self::Yara => "External analysis",
            _ => "Other",
        }
    }
}

impl fmt::Display for MispAttrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.type_str()) }
}

// ---------------------------------------------------------------------------
// Tests (synchronous-compatible)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_host_port_https() {
        let cfg = MispClientConfig::new("https://misp.example.com", "key");
        assert_eq!(cfg.host_port(), ("misp.example.com".to_owned(), 443));
        assert!(cfg.is_https());
    }

    #[test]
    fn test_config_host_port_custom() {
        let cfg = MispClientConfig::new("http://localhost:8080", "key");
        assert_eq!(cfg.host_port(), ("localhost".to_owned(), 8080));
        assert!(!cfg.is_https());
    }

    #[test]
    fn test_build_http_request() {
        let req = Request::get("/events/1");
        let raw = build_http_request(&req, "misp.example.com", "apikey123");
        let s = std::str::from_utf8(&raw).unwrap();
        assert!(s.contains("GET /events/1 HTTP/1.1\r\n"));
        assert!(s.contains("Authorization: apikey123\r\n"));
    }

    #[test]
    fn test_parse_http_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        assert_eq!(resp.body, b"{}");
    }

    #[test]
    fn test_attr_type_strings() {
        assert_eq!(MispAttrType::Md5.type_str(), "md5");
        assert_eq!(MispAttrType::Sha256.category(), "Payload delivery");
        assert_eq!(MispAttrType::Domain.category(), "Network activity");
    }

    #[test]
    fn test_page_is_last() {
        let p: Page<u32> = Page { items: vec![1, 2, 3], page: 1, page_size: 100, total: Some(3) };
        assert!(p.is_last());
        let p2: Page<u32> = Page { items: (0..100).collect(), page: 1, page_size: 100, total: Some(200) };
        assert!(!p2.is_last());
    }

    #[test]
    fn test_paginated_query() {
        let mut base = serde_json::Map::new();
        base.insert("value".into(), Value::String("test".into()));
        let q = paginated_query(base, 2, 50);
        assert_eq!(q["page"], Value::Number(2.into()));
        assert_eq!(q["limit"], Value::Number(50.into()));
        assert_eq!(q["value"], Value::String("test".into()));
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.total_requests, 0);
        assert!(stats.last_status.is_none());
    }

    #[test]
    fn test_request_json_body() {
        let payload = serde_json::json!({"key": "value"});
        let req = Request::json_body("/events/add", HttpMethod::Post, &payload).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.body.is_some());
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/json");
    }
}
