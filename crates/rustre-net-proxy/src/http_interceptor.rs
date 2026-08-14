//! HTTP interceptor — parse, inspect, and transform HTTP/1.x traffic.
//!
//! Provides:
//! - [`HttpRequest`] / [`HttpResponse`] parsers
//! - [`HttpInterceptor`] for request/response transformation pipelines
//! - [`InterceptRule`] with match predicates and transform actions
//! - SSL-stripping detection heuristics
//! - Credential harvesting pattern detection

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ProxyError;

// ────────────────────────────────────────────────────────────────────────────
// HTTP version
// ────────────────────────────────────────────────────────────────────────────

/// HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http20,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http10 => write!(f, "HTTP/1.0"),
            Self::Http11 => write!(f, "HTTP/1.1"),
            Self::Http20 => write!(f, "HTTP/2.0"),
        }
    }
}

impl HttpVersion {
    /// Parse an HTTP version string like `"HTTP/1.1"`.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "HTTP/1.0" => Some(Self::Http10),
            "HTTP/1.1" => Some(Self::Http11),
            "HTTP/2.0" | "HTTP/2" => Some(Self::Http20),
            _ => None,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP method
// ────────────────────────────────────────────────────────────────────────────

/// HTTP request method.
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

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
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
}

// ────────────────────────────────────────────────────────────────────────────
// Header map
// ────────────────────────────────────────────────────────────────────────────

/// Case-insensitive HTTP header map preserving insertion order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeaderMap {
    entries: Vec<(String, String)>,
}

impl HeaderMap {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or replace a header (case-insensitive key match).
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        let lower = name.to_ascii_lowercase();
        // Replace existing
        for (k, v) in &mut self.entries {
            if k.to_ascii_lowercase() == lower {
                *v = value;
                return;
            }
        }
        self.entries.push((name, value));
    }

    /// Append a header without replacing existing ones.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    /// Get the first value for a header name (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get all values for a header name.
    #[must_use] 
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Remove all headers with the given name.
    pub fn remove(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        self.entries
            .retain(|(k, _)| k.to_ascii_lowercase() != lower);
    }

    /// Iterate over all (name, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of header entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize back to wire format.
    #[must_use]
    pub fn to_wire(&self) -> String {
        self.entries.iter().fold(String::new(), |mut acc, (k, v)| {
            use std::fmt::Write;
            let _ = write!(acc, "{k}: {v}\r\n");
            acc
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP request
// ────────────────────────────────────────────────────────────────────────────

/// A parsed HTTP/1.x request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Build a minimal GET request.
    #[must_use]
    pub fn get(uri: impl Into<String>) -> Self {
        let mut req = Self {
            method: HttpMethod::Get,
            uri: uri.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Vec::new(),
        };
        req.headers.insert("Connection", "keep-alive");
        req
    }

    /// Parse a raw HTTP/1.x request from bytes.
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidRequest`] if the request line or headers
    /// are malformed.
    pub fn parse(data: &[u8]) -> Result<Self, ProxyError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| ProxyError::InvalidRequest("non-UTF-8 request".into()))?;

        let (head, body_str) = text.split_once("\r\n\r\n").unwrap_or((text, ""));

        let mut lines = head.splitn(2, "\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| ProxyError::InvalidRequest("empty request".into()))?;

        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(ProxyError::InvalidRequest(format!(
                "bad request line: {request_line}"
            )));
        }

        let method = HttpMethod::from(parts[0]);
        let uri = parts[1].to_string();
        let version = HttpVersion::parse(parts[2]).ok_or_else(|| {
            ProxyError::InvalidRequest(format!("unknown HTTP version: {}", parts[2]))
        })?;

        let mut headers = HeaderMap::new();
        if let Some(header_block) = lines.next() {
            for line in header_block.split("\r\n") {
                if line.is_empty() {
                    continue;
                }
                if let Some((k, v)) = line.split_once(": ") {
                    headers.append(k.trim(), v.trim());
                }
            }
        }

        Ok(Self {
            method,
            uri,
            version,
            headers,
            body: body_str.as_bytes().to_vec(),
        })
    }

    /// Serialize back to wire-format bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "{} {} {}\r\n{}\r\n",
            self.method,
            self.uri,
            self.version,
            self.headers.to_wire()
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    /// Host extracted from the `Host` header or the URI.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host")
    }

    /// Content-Type header value.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// Returns `true` if this looks like a form POST.
    #[must_use]
    pub fn is_form_post(&self) -> bool {
        self.method == HttpMethod::Post
            && self
                .content_type()
                .is_some_and(|ct| ct.contains("application/x-www-form-urlencoded"))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP response
// ────────────────────────────────────────────────────────────────────────────

/// A parsed HTTP/1.x response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: u16,
    pub reason: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse a raw HTTP/1.x response from bytes.
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidRequest`] on malformed status line.
    pub fn parse(data: &[u8]) -> Result<Self, ProxyError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| ProxyError::InvalidRequest("non-UTF-8 response".into()))?;

        let (head, body_str) = text.split_once("\r\n\r\n").unwrap_or((text, ""));

        let mut lines = head.splitn(2, "\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| ProxyError::InvalidRequest("empty response".into()))?;

        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(ProxyError::InvalidRequest(format!(
                "bad status line: {status_line}"
            )));
        }

        let version = HttpVersion::parse(parts[0]).ok_or_else(|| {
            ProxyError::InvalidRequest(format!("unknown HTTP version: {}", parts[0]))
        })?;
        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| ProxyError::InvalidRequest(format!("bad status code: {}", parts[1])))?;
        let reason = parts.get(2).unwrap_or(&"").to_string();

        let mut headers = HeaderMap::new();
        if let Some(header_block) = lines.next() {
            for line in header_block.split("\r\n") {
                if line.is_empty() {
                    continue;
                }
                if let Some((k, v)) = line.split_once(": ") {
                    headers.append(k.trim(), v.trim());
                }
            }
        }

        Ok(Self {
            version,
            status_code,
            reason,
            headers,
            body: body_str.as_bytes().to_vec(),
        })
    }

    /// Serialize back to wire-format bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "{} {} {}\r\n{}\r\n",
            self.version,
            self.status_code,
            self.reason,
            self.headers.to_wire()
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    /// Returns `true` if this is a redirect response.
    #[must_use]
    pub const fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }

    /// Location header for redirects.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.headers.get("location")
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SSL-stripping detection
// ────────────────────────────────────────────────────────────────────────────

/// Result of an SSL-stripping heuristic check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslStripAnalysis {
    /// The original URL that contained `https://` references.
    pub original_url: String,
    /// Whether the response Location or body references were downgraded.
    pub downgrade_detected: bool,
    /// HSTS header found.
    pub hsts_present: bool,
    /// Secure cookie flags stripped.
    pub secure_cookies_stripped: bool,
}

/// Detect SSL-stripping patterns in an HTTP response.
///
/// Looks for:
/// - `https://` URLs in the `Location` header downgraded to `http://`
/// - Absence of `Strict-Transport-Security`
/// - `Set-Cookie` headers missing the `Secure` flag
#[must_use]
pub fn detect_ssl_strip(request_url: &str, response: &HttpResponse) -> SslStripAnalysis {
    let hsts_present = response.headers.get("strict-transport-security").is_some();

    // Check if Location downgrades https -> http
    let downgrade_detected = response
        .location()
        .is_some_and(|loc| loc.starts_with("http://") && request_url.contains("https://"));

    // Check for Secure flag stripping in Set-Cookie
    let secure_cookies_stripped = response
        .headers
        .get_all("set-cookie")
        .iter()
        .any(|v| !v.to_ascii_lowercase().contains("secure"));

    SslStripAnalysis {
        original_url: request_url.to_string(),
        downgrade_detected,
        hsts_present,
        secure_cookies_stripped,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Credential harvesting
// ────────────────────────────────────────────────────────────────────────────

/// A detected credential pair from HTTP traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestedCredential {
    pub kind: CredentialKind,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub source_url: String,
}

/// The type of credential detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialKind {
    BasicAuth,
    FormPost,
    BearerToken,
    ApiKey,
    Cookie,
}

/// Known field names that commonly carry credentials.
static CREDENTIAL_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
];

static USERNAME_FIELDS: &[&str] = &[
    "username", "user", "login", "email", "uname", "uid", "account",
];

/// Attempt to harvest credentials from an HTTP request.
///
/// Checks:
/// - `Authorization` header (Basic and Bearer)
/// - Form-encoded body fields
/// - Cookie header for session tokens
#[must_use] 
pub fn harvest_credentials(req: &HttpRequest) -> Vec<HarvestedCredential> {
    let mut found = Vec::new();

    // Basic / Bearer auth header
    if let Some(auth) = req.headers.get("authorization") {
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            // Decode base64
            if let Ok(decoded) = decode_base64(encoded) && let Ok(text) = std::str::from_utf8(&decoded) {
                let (user, pass) = text
                    .split_once(':')
                    .map(|(u, p)| (Some(u.to_string()), Some(p.to_string())))
                    .unwrap_or((Some(text.to_string()), None));
                found.push(HarvestedCredential {
                    kind: CredentialKind::BasicAuth,
                    username: user,
                    password: pass,
                    token: None,
                    source_url: req.uri.clone(),
                });
            }
        } else if let Some(token) = auth.strip_prefix("Bearer ") {
            found.push(HarvestedCredential {
                kind: CredentialKind::BearerToken,
                username: None,
                password: None,
                token: Some(token.to_string()),
                source_url: req.uri.clone(),
            });
        }
    }

    // Form POST body
    if req.is_form_post() && let Ok(body_str) = std::str::from_utf8(&req.body) {
        let params = parse_query_string(body_str);
        let username = USERNAME_FIELDS.iter().find_map(|f| params.get(*f)).cloned();
        let password = CREDENTIAL_FIELDS
            .iter()
            .find_map(|f| params.get(*f))
            .cloned();
        if username.is_some() || password.is_some() {
            found.push(HarvestedCredential {
                kind: CredentialKind::FormPost,
                username,
                password,
                token: None,
                source_url: req.uri.clone(),
            });
        }
    }

    // API key in query string
    if let Some(qs) = req.uri.split_once('?').map(|(_, q)| q) {
        let params = parse_query_string(qs);
        for key_field in &["api_key", "apikey", "key", "token", "access_token"] {
            if let Some(val) = params.get(*key_field) {
                found.push(HarvestedCredential {
                    kind: CredentialKind::ApiKey,
                    username: None,
                    password: None,
                    token: Some(val.clone()),
                    source_url: req.uri.clone(),
                });
            }
        }
    }

    found
}

/// Maximum number of bytes allowed in a base64-encoded Basic-auth credential.
/// RFC 7617 §2 says username and password are limited to 255 octets each;
/// base64(511 bytes) ≈ 682 characters.  We allow generous headroom (4 KiB)
/// to handle non-standard implementations without permitting `DoS` allocations.
const MAX_BASE64_INPUT_LEN: usize = 4096;

/// Minimal base64 decode (standard alphabet, no padding check).
fn decode_base64(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() > MAX_BASE64_INPUT_LEN {
        return Err(());
    }
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 1);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let pos = u32::try_from(CHARS.iter().position(|&c| c == byte).ok_or(())?).unwrap_or(u32::MAX);
        buf = (buf << 6) | pos;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(buf >> bits).unwrap_or(u8::MAX));
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Parse `key=value&key2=value2` query strings.
fn parse_query_string(qs: &str) -> HashMap<String, String> {
    qs.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (url_decode(k), url_decode(v)))
        .collect()
}

/// Minimal percent-decoding.
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'+' {
            out.push(' ');
        } else if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let hex = format!("{}{}", hi as char, lo as char);
            if let Ok(n) = u8::from_str_radix(&hex, 16) {
                out.push(n as char);
            } else {
                out.push('%');
                out.push(hi as char);
                out.push(lo as char);
            }
        } else {
            out.push(b as char);
        }
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Intercept rule
// ────────────────────────────────────────────────────────────────────────────

/// Predicate controlling which requests/responses an [`InterceptRule`] matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchPredicate {
    /// Match any traffic.
    Any,
    /// URI contains the given substring.
    UriContains(String),
    /// URI matches the given prefix.
    UriPrefix(String),
    /// Method equals the given string.
    Method(String),
    /// Header (name, `value_contains`).
    HeaderContains { name: String, value: String },
    /// Body contains the given byte sequence (UTF-8).
    BodyContains(String),
    /// Status code equals.
    StatusCode(u16),
    /// Logical AND of two predicates.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two predicates.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
}

/// Maximum nesting depth allowed when evaluating recursive [`MatchPredicate`]s.
/// A deserialized predicate with deeper nesting is treated as non-matching to
/// prevent stack overflow from adversarially crafted rules.
const MAX_PREDICATE_DEPTH: u32 = 64;

impl MatchPredicate {
    /// Evaluate this predicate against a request.
    #[must_use]
    pub fn matches_request(&self, req: &HttpRequest) -> bool {
        self.matches_request_depth(req, 0)
    }

    fn matches_request_depth(&self, req: &HttpRequest, depth: u32) -> bool {
        if depth > MAX_PREDICATE_DEPTH {
            return false;
        }
        match self {
            Self::Any => true,
            Self::UriContains(s) => req.uri.contains(s.as_str()),
            Self::UriPrefix(s) => req.uri.starts_with(s.as_str()),
            Self::Method(m) => req.method.to_string().eq_ignore_ascii_case(m),
            Self::HeaderContains { name, value } => req
                .headers
                .get(name)
                .is_some_and(|v| v.contains(value.as_str())),
            Self::BodyContains(s) => {
                !s.is_empty() && req.body.windows(s.len()).any(|w| w == s.as_bytes())
            }
            Self::StatusCode(_) => false, // not applicable to requests
            Self::And(a, b) => {
                a.matches_request_depth(req, depth + 1)
                    && b.matches_request_depth(req, depth + 1)
            }
            Self::Or(a, b) => {
                a.matches_request_depth(req, depth + 1)
                    || b.matches_request_depth(req, depth + 1)
            }
            Self::Not(p) => !p.matches_request_depth(req, depth + 1),
        }
    }

    /// Evaluate this predicate against a response.
    #[must_use]
    pub fn matches_response(&self, resp: &HttpResponse) -> bool {
        self.matches_response_depth(resp, 0)
    }

    fn matches_response_depth(&self, resp: &HttpResponse, depth: u32) -> bool {
        if depth > MAX_PREDICATE_DEPTH {
            return false;
        }
        match self {
            Self::Any => true,
            Self::UriContains(_) | Self::UriPrefix(_) | Self::Method(_) => false,
            Self::HeaderContains { name, value } => resp
                .headers
                .get(name)
                .is_some_and(|v| v.contains(value.as_str())),
            Self::BodyContains(s) => {
                !s.is_empty() && resp.body.windows(s.len()).any(|w| w == s.as_bytes())
            }
            Self::StatusCode(code) => resp.status_code == *code,
            Self::And(a, b) => {
                a.matches_response_depth(resp, depth + 1)
                    && b.matches_response_depth(resp, depth + 1)
            }
            Self::Or(a, b) => {
                a.matches_response_depth(resp, depth + 1)
                    || b.matches_response_depth(resp, depth + 1)
            }
            Self::Not(p) => !p.matches_response_depth(resp, depth + 1),
        }
    }
}

/// Transform to apply when an [`InterceptRule`] matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformAction {
    /// Pass through unchanged.
    PassThrough,
    /// Drop the request/response entirely.
    Drop,
    /// Inject or overwrite a request header.
    InjectRequestHeader { name: String, value: String },
    /// Remove a request header.
    RemoveRequestHeader(String),
    /// Inject or overwrite a response header.
    InjectResponseHeader { name: String, value: String },
    /// Remove a response header.
    RemoveResponseHeader(String),
    /// Replace a substring in the body.
    ReplaceBody { find: String, replace: String },
    /// Replace the entire body with fixed bytes.
    SetBody(Vec<u8>),
    /// Redirect the response to a new URL (301).
    Redirect(String),
}

/// A complete rule: if the predicate matches, apply the list of actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    pub name: String,
    pub enabled: bool,
    pub predicate: MatchPredicate,
    pub actions: Vec<TransformAction>,
}

impl InterceptRule {
    /// Construct a new enabled rule.
    pub fn new(
        name: impl Into<String>,
        predicate: MatchPredicate,
        actions: Vec<TransformAction>,
    ) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            predicate,
            actions,
        }
    }

    /// Apply all actions to a request. Returns `false` if a `Drop` action was
    /// encountered.
    #[must_use]
    pub fn apply_to_request(&self, req: &mut HttpRequest) -> bool {
        if !self.enabled || !self.predicate.matches_request(req) {
            return true;
        }
        for action in &self.actions {
            match action {
                TransformAction::Drop => return false,
                TransformAction::InjectRequestHeader { name, value } => {
                    req.headers.insert(name.clone(), value.clone());
                }
                TransformAction::RemoveRequestHeader(name) => {
                    req.headers.remove(name);
                }
                TransformAction::ReplaceBody { find, replace } => {
                    if let Ok(body_str) = std::str::from_utf8(&req.body) {
                        let new_body = body_str.replace(find.as_str(), replace.as_str());
                        req.body = new_body.into_bytes();
                    }
                }
                TransformAction::SetBody(bytes) => {
                    req.body.clone_from(bytes);
                }
                _ => {} // response-only actions are no-ops here
            }
        }
        true
    }

    /// Apply all actions to a response. Returns `false` if a `Drop` action was
    /// encountered.
    #[must_use]
    pub fn apply_to_response(&self, resp: &mut HttpResponse) -> bool {
        if !self.enabled || !self.predicate.matches_response(resp) {
            return true;
        }
        for action in &self.actions {
            match action {
                TransformAction::Drop => return false,
                TransformAction::InjectResponseHeader { name, value } => {
                    resp.headers.insert(name.clone(), value.clone());
                }
                TransformAction::RemoveResponseHeader(name) => {
                    resp.headers.remove(name);
                }
                TransformAction::ReplaceBody { find, replace } => {
                    if let Ok(body_str) = std::str::from_utf8(&resp.body) {
                        let new_body = body_str.replace(find.as_str(), replace.as_str());
                        resp.body = new_body.into_bytes();
                    }
                }
                TransformAction::SetBody(bytes) => {
                    resp.body.clone_from(bytes);
                }
                TransformAction::Redirect(url) => {
                    resp.status_code = 301;
                    resp.reason = "Moved Permanently".to_string();
                    resp.headers.insert("Location", url.clone());
                    resp.body = Vec::new();
                }
                _ => {}
            }
        }
        true
    }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP interceptor
// ────────────────────────────────────────────────────────────────────────────

/// Stateful HTTP interceptor that applies a chain of [`InterceptRule`]s.
#[derive(Debug, Default)]
pub struct HttpInterceptor {
    rules: Vec<InterceptRule>,
    harvest_credentials: bool,
    detect_ssl_stripping: bool,
    harvested: Vec<HarvestedCredential>,
    ssl_strip_events: Vec<SslStripAnalysis>,
}

impl HttpInterceptor {
    /// Create a new interceptor with no rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable credential harvesting.
    #[must_use] 
    pub const fn with_credential_harvesting(mut self) -> Self {
        self.harvest_credentials = true;
        self
    }

    /// Enable SSL-strip detection.
    #[must_use] 
    pub const fn with_ssl_strip_detection(mut self) -> Self {
        self.detect_ssl_stripping = true;
        self
    }

    /// Add a rule to the chain.
    pub fn add_rule(&mut self, rule: InterceptRule) {
        self.rules.push(rule);
    }

    /// Process a request through the rule chain.
    ///
    /// Returns `false` if the request should be dropped.
    pub fn process_request(&mut self, req: &mut HttpRequest) -> bool {
        if self.harvest_credentials {
            let creds = harvest_credentials(req);
            self.harvested.extend(creds);
        }
        for rule in &self.rules {
            if !rule.apply_to_request(req) {
                return false;
            }
        }
        true
    }

    /// Process a response through the rule chain.
    ///
    /// Returns `false` if the response should be dropped.
    pub fn process_response(&mut self, request_url: &str, resp: &mut HttpResponse) -> bool {
        if self.detect_ssl_stripping {
            let analysis = detect_ssl_strip(request_url, resp);
            self.ssl_strip_events.push(analysis);
        }
        for rule in &self.rules {
            if !rule.apply_to_response(resp) {
                return false;
            }
        }
        true
    }

    /// Return all harvested credentials so far.
    #[must_use]
    pub fn harvested_credentials(&self) -> &[HarvestedCredential] {
        &self.harvested
    }

    /// Return all SSL-strip analysis events.
    #[must_use]
    pub fn ssl_strip_events(&self) -> &[SslStripAnalysis] {
        &self.ssl_strip_events
    }

    /// Clear rule chain.
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Number of active rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Body rewriter helpers
// ────────────────────────────────────────────────────────────────────────────

/// Replace all occurrences of `find` in `body` with `replace` (byte-level).
#[must_use]
pub fn rewrite_body(body: &[u8], find: &[u8], replace: &[u8]) -> Vec<u8> {
    if find.is_empty() {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(find) {
            out.extend_from_slice(replace);
            i += find.len();
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_get_bytes() -> Vec<u8> {
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n".to_vec()
    }

    fn simple_post_bytes() -> Vec<u8> {
        b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nusername=admin&password=secret".to_vec()
    }

    fn simple_response_bytes() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello".to_vec()
    }

    // ── HttpMethod ────────────────────────────────────────────────────────────

    #[test]
    fn test_http_method_from_str() {
        assert_eq!(HttpMethod::from("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from("post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from("PATCH"), HttpMethod::Patch);
        assert_eq!(HttpMethod::from("CONNECT"), HttpMethod::Connect);
        assert_eq!(
            HttpMethod::from("PROPFIND"),
            HttpMethod::Other("PROPFIND".to_string())
        );
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
        assert_eq!(HttpMethod::Other("BREW".to_string()).to_string(), "BREW");
    }

    // ── HttpVersion ───────────────────────────────────────────────────────────

    #[test]
    fn test_http_version_parse() {
        assert_eq!(HttpVersion::parse("HTTP/1.0"), Some(HttpVersion::Http10));
        assert_eq!(HttpVersion::parse("HTTP/1.1"), Some(HttpVersion::Http11));
        assert_eq!(HttpVersion::parse("HTTP/2"), Some(HttpVersion::Http20));
        assert_eq!(HttpVersion::parse("FTP/1.0"), None);
    }

    #[test]
    fn test_http_version_display() {
        assert_eq!(HttpVersion::Http11.to_string(), "HTTP/1.1");
    }

    // ── HeaderMap ─────────────────────────────────────────────────────────────

    #[test]
    fn test_header_map_insert_get() {
        let mut m = HeaderMap::new();
        m.insert("Content-Type", "text/html");
        assert_eq!(m.get("content-type"), Some("text/html"));
        assert_eq!(m.get("Content-Type"), Some("text/html"));
    }

    #[test]
    fn test_header_map_replace() {
        let mut m = HeaderMap::new();
        m.insert("X-Custom", "first");
        m.insert("x-custom", "second");
        assert_eq!(m.get("X-Custom"), Some("second"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn test_header_map_remove() {
        let mut m = HeaderMap::new();
        m.insert("Accept", "application/json");
        m.remove("accept");
        assert!(m.get("Accept").is_none());
        assert!(m.is_empty());
    }

    #[test]
    fn test_header_map_append_multiple() {
        let mut m = HeaderMap::new();
        m.append("Set-Cookie", "a=1");
        m.append("Set-Cookie", "b=2");
        assert_eq!(m.get_all("set-cookie").len(), 2);
    }

    #[test]
    fn test_header_map_to_wire() {
        let mut m = HeaderMap::new();
        m.insert("Host", "example.com");
        let wire = m.to_wire();
        assert!(wire.contains("Host: example.com\r\n"));
    }

    // ── HttpRequest parsing ───────────────────────────────────────────────────

    #[test]
    fn test_parse_get_request() {
        let req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.version, HttpVersion::Http11);
        assert_eq!(req.headers.get("host"), Some("example.com"));
    }

    #[test]
    fn test_parse_post_request() {
        let req = HttpRequest::parse(&simple_post_bytes()).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.is_form_post());
        assert!(!req.body.is_empty());
    }

    #[test]
    fn test_request_roundtrip() {
        let original = simple_get_bytes();
        let req = HttpRequest::parse(&original).unwrap();
        let serialized = req.to_bytes();
        // Re-parse the serialized form
        let req2 = HttpRequest::parse(&serialized).unwrap();
        assert_eq!(req.method, req2.method);
        assert_eq!(req.uri, req2.uri);
    }

    #[test]
    fn test_parse_request_bad_line() {
        let bad = b"BADREQUEST\r\n\r\n";
        assert!(HttpRequest::parse(bad).is_err());
    }

    // ── HttpResponse parsing ──────────────────────────────────────────────────

    #[test]
    fn test_parse_response() {
        let resp = HttpResponse::parse(&simple_response_bytes()).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.headers.get("content-type"), Some("text/html"));
    }

    #[test]
    fn test_response_is_redirect() {
        let resp = HttpResponse::parse(
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com\r\n\r\n",
        )
        .unwrap();
        assert!(resp.is_redirect());
        assert_eq!(resp.location(), Some("https://example.com"));
    }

    #[test]
    fn test_response_roundtrip() {
        let original = simple_response_bytes();
        let resp = HttpResponse::parse(&original).unwrap();
        let serialized = resp.to_bytes();
        let resp2 = HttpResponse::parse(&serialized).unwrap();
        assert_eq!(resp.status_code, resp2.status_code);
    }

    // ── SSL-strip detection ────────────────────────────────────────────────────

    #[test]
    fn test_ssl_strip_no_hsts() {
        let resp = HttpResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
        let analysis = detect_ssl_strip("https://example.com/", &resp);
        assert!(!analysis.hsts_present);
    }

    #[test]
    fn test_ssl_strip_hsts_present() {
        let resp = HttpResponse::parse(
            b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Length: 0\r\n\r\n"
        ).unwrap();
        let analysis = detect_ssl_strip("https://example.com/", &resp);
        assert!(analysis.hsts_present);
    }

    #[test]
    fn test_ssl_strip_location_downgrade() {
        let resp = HttpResponse::parse(
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://example.com/\r\n\r\n",
        )
        .unwrap();
        let analysis = detect_ssl_strip("https://example.com/", &resp);
        assert!(analysis.downgrade_detected);
    }

    #[test]
    fn test_ssl_strip_secure_cookie() {
        let resp =
            HttpResponse::parse(b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; HttpOnly\r\n\r\n")
                .unwrap();
        let analysis = detect_ssl_strip("https://example.com/", &resp);
        assert!(analysis.secure_cookies_stripped);
    }

    // ── Credential harvesting ──────────────────────────────────────────────────

    #[test]
    fn test_harvest_form_post_credentials() {
        let req = HttpRequest::parse(&simple_post_bytes()).unwrap();
        let creds = harvest_credentials(&req);
        assert!(!creds.is_empty());
        let form_cred = creds
            .iter()
            .find(|c| matches!(c.kind, CredentialKind::FormPost));
        assert!(form_cred.is_some());
        let c = form_cred.unwrap();
        assert_eq!(c.username.as_deref(), Some("admin"));
        assert_eq!(c.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_harvest_basic_auth() {
        // "user:pass" base64 = "dXNlcjpwYXNz"
        let raw =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        let creds = harvest_credentials(&req);
        let basic = creds
            .iter()
            .find(|c| matches!(c.kind, CredentialKind::BasicAuth));
        assert!(basic.is_some());
        let c = basic.unwrap();
        assert_eq!(c.username.as_deref(), Some("user"));
        assert_eq!(c.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_harvest_bearer_token() {
        let raw =
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer mytoken123\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        let creds = harvest_credentials(&req);
        let bearer = creds
            .iter()
            .find(|c| matches!(c.kind, CredentialKind::BearerToken));
        assert!(bearer.is_some());
        assert_eq!(bearer.unwrap().token.as_deref(), Some("mytoken123"));
    }

    #[test]
    fn test_harvest_api_key_in_query() {
        let raw = b"GET /data?api_key=supersecretkey HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        let creds = harvest_credentials(&req);
        let api = creds
            .iter()
            .find(|c| matches!(c.kind, CredentialKind::ApiKey));
        assert!(api.is_some());
        assert_eq!(api.unwrap().token.as_deref(), Some("supersecretkey"));
    }

    // ── MatchPredicate ────────────────────────────────────────────────────────

    #[test]
    fn test_predicate_uri_contains() {
        let req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        assert!(MatchPredicate::UriContains("index".to_string()).matches_request(&req));
        assert!(!MatchPredicate::UriContains("login".to_string()).matches_request(&req));
    }

    #[test]
    fn test_predicate_method() {
        let req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        assert!(MatchPredicate::Method("GET".to_string()).matches_request(&req));
        assert!(!MatchPredicate::Method("POST".to_string()).matches_request(&req));
    }

    #[test]
    fn test_predicate_and_or_not() {
        let req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        let and = MatchPredicate::And(
            Box::new(MatchPredicate::Any),
            Box::new(MatchPredicate::Method("GET".to_string())),
        );
        assert!(and.matches_request(&req));

        let not = MatchPredicate::Not(Box::new(MatchPredicate::Method("POST".to_string())));
        assert!(not.matches_request(&req));
    }

    #[test]
    fn test_predicate_status_code_on_response() {
        let resp = HttpResponse::parse(&simple_response_bytes()).unwrap();
        assert!(MatchPredicate::StatusCode(200).matches_response(&resp));
        assert!(!MatchPredicate::StatusCode(404).matches_response(&resp));
    }

    // ── InterceptRule ─────────────────────────────────────────────────────────

    #[test]
    fn test_rule_inject_request_header() {
        let mut req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        let rule = InterceptRule::new(
            "inject-x-forwarded",
            MatchPredicate::Any,
            vec![TransformAction::InjectRequestHeader {
                name: "X-Forwarded-For".to_string(),
                value: "127.0.0.1".to_string(),
            }],
        );
        assert!(rule.apply_to_request(&mut req));
        assert_eq!(req.headers.get("X-Forwarded-For"), Some("127.0.0.1"));
    }

    #[test]
    fn test_rule_remove_request_header() {
        let mut req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        let rule = InterceptRule::new(
            "strip-connection",
            MatchPredicate::Any,
            vec![TransformAction::RemoveRequestHeader(
                "Connection".to_string(),
            )],
        );
        assert!(rule.apply_to_request(&mut req));
        assert!(req.headers.get("Connection").is_none());
    }

    #[test]
    fn test_rule_drop_request() {
        let mut req = HttpRequest::parse(&simple_get_bytes()).unwrap();
        let rule = InterceptRule::new("drop-all", MatchPredicate::Any, vec![TransformAction::Drop]);
        assert!(!rule.apply_to_request(&mut req));
    }

    #[test]
    fn test_rule_replace_body() {
        let mut resp = HttpResponse::parse(&simple_response_bytes()).unwrap();
        let rule = InterceptRule::new(
            "replace-body",
            MatchPredicate::Any,
            vec![TransformAction::ReplaceBody {
                find: "hello".to_string(),
                replace: "world".to_string(),
            }],
        );
        assert!(rule.apply_to_response(&mut resp));
        assert_eq!(&resp.body, b"world");
    }

    #[test]
    fn test_rule_redirect_response() {
        let mut resp = HttpResponse::parse(&simple_response_bytes()).unwrap();
        let rule = InterceptRule::new(
            "redirect",
            MatchPredicate::StatusCode(200),
            vec![TransformAction::Redirect(
                "https://new.example.com/".to_string(),
            )],
        );
        assert!(rule.apply_to_response(&mut resp));
        assert_eq!(resp.status_code, 301);
        assert_eq!(resp.location(), Some("https://new.example.com/"));
    }

    // ── HttpInterceptor ───────────────────────────────────────────────────────

    #[test]
    fn test_interceptor_harvest_on_process() {
        let mut interceptor = HttpInterceptor::new().with_credential_harvesting();
        let mut req = HttpRequest::parse(&simple_post_bytes()).unwrap();
        let result = interceptor.process_request(&mut req);
        assert!(result);
        assert!(!interceptor.harvested_credentials().is_empty());
    }

    #[test]
    fn test_interceptor_ssl_strip_on_process() {
        let mut interceptor = HttpInterceptor::new().with_ssl_strip_detection();
        let mut resp =
            HttpResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
        interceptor.process_response("https://example.com/", &mut resp);
        assert_eq!(interceptor.ssl_strip_events().len(), 1);
    }

    #[test]
    fn test_interceptor_multiple_rules() {
        let mut interceptor = HttpInterceptor::new();
        interceptor.add_rule(InterceptRule::new(
            "inject",
            MatchPredicate::Any,
            vec![TransformAction::InjectRequestHeader {
                name: "X-Intercepted".to_string(),
                value: "true".to_string(),
            }],
        ));
        let mut req = HttpRequest::get("/");
        let result = interceptor.process_request(&mut req);
        assert!(result);
        assert_eq!(req.headers.get("X-Intercepted"), Some("true"));
    }

    // ── rewrite_body ──────────────────────────────────────────────────────────

    #[test]
    fn test_rewrite_body_simple() {
        let result = rewrite_body(b"hello world", b"world", b"rust");
        assert_eq!(result, b"hello rust");
    }

    #[test]
    fn test_rewrite_body_no_match() {
        let result = rewrite_body(b"hello world", b"xyz", b"abc");
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_rewrite_body_empty_find() {
        let result = rewrite_body(b"data", b"", b"X");
        assert_eq!(result, b"data");
    }

    // ── url_decode ─────────────────────────────────────────────────────────────

    #[test]
    fn test_url_decode_basic() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("foo%20bar"), "foo bar");
        assert_eq!(url_decode("a%3Db"), "a=b");
    }

    // ── parse_query_string ────────────────────────────────────────────────────

    #[test]
    fn test_parse_query_string() {
        let params = parse_query_string("a=1&b=hello+world&c=foo%20bar");
        assert_eq!(params.get("a").map(std::string::String::as_str), Some("1"));
        assert_eq!(params.get("b").map(std::string::String::as_str), Some("hello world"));
        assert_eq!(params.get("c").map(std::string::String::as_str), Some("foo bar"));
    }

    // ── base64 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_base64_user_pass() {
        // "user:pass" -> "dXNlcjpwYXNz"
        let decoded = decode_base64("dXNlcjpwYXNz").unwrap();
        assert_eq!(decoded, b"user:pass");
    }

    #[test]
    fn test_decode_base64_empty() {
        let decoded = decode_base64("").unwrap();
        assert!(decoded.is_empty());
    }
}
