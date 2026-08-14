//! REST API server for `rustre-daemon`.
//!
//! Provides a synchronous, hyper-free REST layer built on the existing
//! `IpcServer` infrastructure.  Full async REST routing (hyper-based) is handled
//! by `HttpServer` in `lib.rs`; this module adds typed endpoint descriptors,
//! an `AuthMiddleware`, a `RateLimiter`, and convenience request/response types
//! for the documented API surface.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── HTTP primitives ───────────────────────────────────────────────────────────

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Get => "GET",
                Self::Post => "POST",
                Self::Put => "PUT",
                Self::Delete => "DELETE",
                Self::Patch => "PATCH",
                Self::Head => "HEAD",
                Self::Options => "OPTIONS",
            }
        )
    }
}

// ── RestRequest / RestResponse ────────────────────────────────────────────────

/// An incoming REST request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestRequest {
    pub method: Method,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl RestRequest {
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            query: HashMap::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    #[must_use]
    pub fn with_query(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.query.insert(k.into(), v.into());
        self
    }

    /// Parse the body as JSON.
    #[must_use] 
    pub fn json_body<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        serde_json::from_slice(&self.body).ok()
    }

    /// Get a header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Return the bearer token from the Authorization header.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        self.header("Authorization")?.strip_prefix("Bearer ")
    }
}

/// An outgoing REST response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl RestResponse {
    /// 200 OK with empty body.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// JSON response with the given status.
    #[must_use]
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_default();
        let mut r = Self {
            status,
            headers: HashMap::new(),
            body,
        };
        r.headers
            .insert("Content-Type".into(), "application/json".into());
        r
    }

    /// 200 JSON response.
    #[must_use]
    pub fn ok_json(value: &serde_json::Value) -> Self {
        Self::json(200, value)
    }

    /// 400 Bad Request JSON.
    #[must_use]
    pub fn bad_request(msg: &str) -> Self {
        Self::json(400, &serde_json::json!({"error": msg}))
    }

    /// 401 Unauthorized.
    #[must_use]
    pub fn unauthorized() -> Self {
        Self::json(401, &serde_json::json!({"error": "unauthorized"}))
    }

    /// 403 Forbidden.
    #[must_use]
    pub fn forbidden() -> Self {
        Self::json(403, &serde_json::json!({"error": "forbidden"}))
    }

    /// 404 Not Found.
    #[must_use]
    pub fn not_found(path: &str) -> Self {
        Self::json(
            404,
            &serde_json::json!({"error": format!("not found: {path}")}),
        )
    }

    /// 429 Too Many Requests.
    #[must_use]
    pub fn too_many_requests() -> Self {
        Self::json(429, &serde_json::json!({"error": "rate limit exceeded"}))
    }

    /// 500 Internal Server Error.
    #[must_use]
    pub fn internal_error(msg: &str) -> Self {
        Self::json(500, &serde_json::json!({"error": msg}))
    }

    /// Add a response header.
    #[must_use]
    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }

    /// Return `true` if the status code is 2xx.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Parse the body as JSON.
    #[must_use] 
    pub fn json_body<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        serde_json::from_slice(&self.body).ok()
    }
}

// ── AuthMiddleware ─────────────────────────────────────────────────────────────

/// Authentication middleware for the REST API.
#[derive(Debug, Clone)]
pub struct AuthMiddleware {
    /// Accepted bearer tokens.
    tokens: Vec<String>,
    /// Paths that are exempt from authentication.
    pub public_paths: Vec<String>,
    /// Whether authentication is enabled.
    pub enabled: bool,
}

impl AuthMiddleware {
    /// Create a middleware with the given set of accepted tokens.
    #[must_use]
    pub fn new(tokens: Vec<String>) -> Self {
        Self {
            tokens,
            public_paths: vec!["/health".into(), "/version".into()],
            enabled: true,
        }
    }

    /// Disabled middleware (all requests pass).
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            tokens: Vec::new(),
            public_paths: Vec::new(),
            enabled: false,
        }
    }

    /// Check whether `req` is authenticated.
    #[must_use]
    pub fn authenticate(&self, req: &RestRequest) -> bool {
        if !self.enabled {
            return true;
        }
        if self.public_paths.iter().any(|p| req.path.starts_with(p)) {
            return true;
        }
        let Some(token) = req.bearer_token() else {
            return false;
        };
        self.tokens.iter().any(|t| t == token)
    }

    /// Add a token.
    pub fn add_token(&mut self, token: impl Into<String>) {
        self.tokens.push(token.into());
    }

    /// Add a public path prefix.
    pub fn add_public_path(&mut self, path: impl Into<String>) {
        self.public_paths.push(path.into());
    }

    /// Number of configured tokens.
    #[must_use]
    pub const fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

/// Token-bucket rate limiter per client identifier.
#[derive(Debug)]
pub struct RateLimiter {
    /// Requests per minute per client.
    pub rpm: u32,
    /// Per-client buckets: (count, `window_start`).
    buckets: HashMap<String, (u32, Instant)>,
    /// Window duration.
    window: Duration,
}

impl RateLimiter {
    /// Create a rate limiter allowing `rpm` requests per minute per client.
    #[must_use]
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm,
            buckets: HashMap::new(),
            window: Duration::from_secs(60),
        }
    }

    /// Unlimited rate limiter.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(u32::MAX)
    }

    /// Check and record a request for `client_id`.
    /// Returns `true` if the request is within the rate limit.
    pub fn check(&mut self, client_id: &str) -> bool {
        let now = Instant::now();
        let entry = self
            .buckets
            .entry(client_id.to_string())
            .or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (1, now);
            return true;
        }
        if entry.0 >= self.rpm {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// Reset a specific client's counter.
    pub fn reset(&mut self, client_id: &str) {
        self.buckets.remove(client_id);
    }

    /// Return the current request count for a client (for testing).
    #[must_use]
    pub fn count_for(&self, client_id: &str) -> u32 {
        self.buckets.get(client_id).map_or(0, |(c, _)| *c)
    }
}

// ── RestEndpoint ──────────────────────────────────────────────────────────────

/// A registered REST endpoint descriptor.
#[derive(Debug, Clone)]
pub struct RestEndpoint {
    /// HTTP method.
    pub method: Method,
    /// Path pattern (e.g. `/analyze`). Prefix matching only in this implementation.
    pub path: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this endpoint requires authentication.
    pub requires_auth: bool,
}

impl RestEndpoint {
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            description: description.into(),
            requires_auth: true,
        }
    }

    #[must_use]
    pub const fn public(mut self) -> Self {
        self.requires_auth = false;
        self
    }

    /// Check if this endpoint matches the given method and path.
    #[must_use]
    pub fn matches(&self, method: Method, path: &str) -> bool {
        self.method == method && (path == self.path || path.starts_with(&format!("{}/", self.path)))
    }
}

// ── RestApi ───────────────────────────────────────────────────────────────────

/// Synchronous REST API router with built-in auth and rate limiting.
pub struct RestApi {
    pub endpoints: Vec<RestEndpoint>,
    pub auth: AuthMiddleware,
    pub rate_limiter: RateLimiter,
    handler_log: Vec<String>,
}

impl RestApi {
    /// Create with default endpoints pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut api = Self {
            endpoints: Vec::new(),
            auth: AuthMiddleware::disabled(),
            rate_limiter: RateLimiter::unlimited(),
            handler_log: Vec::new(),
        };
        api.register_builtin_endpoints();
        api
    }

    /// Create with authentication enabled.
    #[must_use]
    pub fn with_auth(mut self, tokens: Vec<String>) -> Self {
        self.auth = AuthMiddleware::new(tokens);
        self
    }

    /// Create with rate limiting.
    #[must_use]
    pub fn with_rate_limit(mut self, rpm: u32) -> Self {
        self.rate_limiter = RateLimiter::new(rpm);
        self
    }

    /// Register a custom endpoint.
    pub fn register(&mut self, endpoint: RestEndpoint) {
        self.endpoints.push(endpoint);
    }

    fn register_builtin_endpoints(&mut self) {
        self.endpoints
            .push(RestEndpoint::new(Method::Post, "/analyze", "Analyze a binary file").public());
        self.endpoints.push(RestEndpoint::new(
            Method::Get,
            "/functions",
            "List all functions",
        ));
        self.endpoints.push(RestEndpoint::new(
            Method::Post,
            "/decompile",
            "Decompile a function",
        ));
        self.endpoints.push(RestEndpoint::new(
            Method::Get,
            "/xrefs",
            "Get cross-references",
        ));
        self.endpoints
            .push(RestEndpoint::new(Method::Get, "/symbols", "List symbols"));
        self.endpoints.push(RestEndpoint::new(
            Method::Post,
            "/comments",
            "Set or get comments",
        ));
        self.endpoints
            .push(RestEndpoint::new(Method::Post, "/yara", "Run YARA scan"));
        self.endpoints.push(RestEndpoint::new(
            Method::Post,
            "/diff",
            "Diff two binaries",
        ));
        self.endpoints.push(RestEndpoint::new(
            Method::Get,
            "/debug",
            "Debug session info",
        ));
        self.endpoints.push(RestEndpoint::new(
            Method::Post,
            "/script",
            "Execute a script",
        ));
        self.endpoints.push(RestEndpoint::new(
            Method::Get,
            "/triage",
            "Auto-triage binary",
        ));
        self.endpoints
            .push(RestEndpoint::new(Method::Get, "/health", "Health check").public());
        self.endpoints
            .push(RestEndpoint::new(Method::Get, "/version", "API version").public());
    }

    /// Dispatch a request and return a response.
    ///
    /// Applies authentication and rate limiting before calling the appropriate
    /// handler.
    pub fn dispatch(&mut self, req: &RestRequest, client_id: &str) -> RestResponse {
        // Rate limit check
        if !self.rate_limiter.check(client_id) {
            return RestResponse::too_many_requests();
        }
        // Auth check
        if !self.auth.authenticate(req) {
            return RestResponse::unauthorized();
        }
        // Route matching
        let matched = self
            .endpoints
            .iter()
            .find(|e| e.matches(req.method, &req.path))
            .cloned();
        match matched {
            None => RestResponse::not_found(&req.path),
            Some(endpoint) => {
                self.handler_log
                    .push(format!("{} {}", req.method, req.path));
                self.handle(&endpoint, req)
            }
        }
    }

    fn handle(&self, endpoint: &RestEndpoint, req: &RestRequest) -> RestResponse {
        match (endpoint.method, endpoint.path.as_str()) {
            (Method::Get, "/health") => RestResponse::ok_json(&serde_json::json!({"status": "ok"})),
            (Method::Get, "/version") => {
                RestResponse::ok_json(&serde_json::json!({"version": "0.1.0"}))
            }
            (Method::Post, "/analyze") => self.handle_analyze(req),
            (Method::Get, "/functions") => self.handle_functions(req),
            (Method::Post, "/decompile") => self.handle_decompile(req),
            (Method::Get, "/xrefs") => self.handle_xrefs(req),
            (Method::Get, "/symbols") => self.handle_symbols(req),
            (Method::Post, "/comments") => self.handle_comments(req),
            (Method::Post, "/yara") => self.handle_yara(req),
            (Method::Post, "/diff") => self.handle_diff(req),
            (Method::Get, "/debug") => self.handle_debug(req),
            (Method::Post, "/script") => self.handle_script(req),
            (Method::Get, "/triage") => self.handle_triage(req),
            _ => RestResponse::not_found(&req.path),
        }
    }

    // ── Built-in handlers ──────────────────────────────────────────────────

    fn handle_analyze(&self, req: &RestRequest) -> RestResponse {
        let path = req
            .query
            .get("path")
            .map_or("<none>", String::as_str);
        RestResponse::ok_json(&serde_json::json!({
            "status": "queued",
            "path": path,
            "job_id": "job-0001",
        }))
    }

    fn handle_functions(&self, req: &RestRequest) -> RestResponse {
        let offset = req
            .query
            .get("offset")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        RestResponse::ok_json(&serde_json::json!({
            "functions": [],
            "offset": offset,
            "total": 0,
        }))
    }

    fn handle_decompile(&self, req: &RestRequest) -> RestResponse {
        let addr = req
            .json_body::<serde_json::Value>()
            .and_then(|v| v.get("address").and_then(serde_json::Value::as_u64))
            .unwrap_or(0);
        RestResponse::ok_json(&serde_json::json!({
            "address": addr,
            "pseudo_c": format!("void func_{addr:x}() {{ /* decompiled */ }}"),
        }))
    }

    fn handle_xrefs(&self, req: &RestRequest) -> RestResponse {
        let addr = req
            .query
            .get("address")
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        RestResponse::ok_json(
            &serde_json::json!({ "address": addr, "xrefs_to": [], "xrefs_from": [] }),
        )
    }

    fn handle_symbols(&self, req: &RestRequest) -> RestResponse {
        let filter = req.query.get("filter").map_or("", String::as_str);
        RestResponse::ok_json(&serde_json::json!({ "symbols": [], "filter": filter }))
    }

    fn handle_comments(&self, req: &RestRequest) -> RestResponse {
        if req.method == Method::Post {
            let body = req.json_body::<serde_json::Value>();
            let addr = body
                .as_ref()
                .and_then(|v| v.get("address"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let comment = body
                .as_ref()
                .and_then(|v| v.get("comment"))
                .and_then(|c| c.as_str())
                .unwrap_or("");
            RestResponse::ok_json(
                &serde_json::json!({ "address": addr, "comment": comment, "set": true }),
            )
        } else {
            RestResponse::ok_json(&serde_json::json!({ "comments": [] }))
        }
    }

    fn handle_yara(&self, req: &RestRequest) -> RestResponse {
        let rule_count = req
            .json_body::<serde_json::Value>()
            .as_ref()
            .and_then(|v| v.get("rules"))
            .and_then(|r| r.as_array())
            .map_or(0, std::vec::Vec::len);
        RestResponse::ok_json(&serde_json::json!({ "matches": [], "rules_checked": rule_count }))
    }

    fn handle_diff(&self, _req: &RestRequest) -> RestResponse {
        RestResponse::ok_json(
            &serde_json::json!({ "diff": { "identical": 0, "changed": 0, "added": 0, "removed": 0 } }),
        )
    }

    fn handle_debug(&self, _req: &RestRequest) -> RestResponse {
        RestResponse::ok_json(&serde_json::json!({ "sessions": [], "active": 0 }))
    }

    fn handle_script(&self, req: &RestRequest) -> RestResponse {
        let lang = req
            .json_body::<serde_json::Value>()
            .and_then(|v| {
                v.get("language")
                    .and_then(|l| l.as_str())
                    .map(std::string::ToString::to_string)
            })
            .unwrap_or_else(|| "python".into());
        RestResponse::ok_json(
            &serde_json::json!({ "language": lang, "output": "", "exit_code": 0 }),
        )
    }

    fn handle_triage(&self, req: &RestRequest) -> RestResponse {
        let path = req
            .query
            .get("path")
            .map_or("<none>", String::as_str);
        RestResponse::ok_json(&serde_json::json!({
            "path": path,
            "verdict": "benign",
            "confidence": 0.5,
            "indicators": [],
        }))
    }

    /// Number of requests logged.
    #[must_use]
    pub const fn request_count(&self) -> usize {
        self.handler_log.len()
    }

    /// Path of the last request handled.
    #[must_use]
    pub fn last_path(&self) -> Option<&str> {
        self.handler_log
            .last()
            .map(|s| s.split_once(' ').map_or("", |x| x.1))
    }
}

impl Default for RestApi {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn api() -> RestApi {
        RestApi::new()
    }
    fn get(path: &str) -> RestRequest {
        RestRequest::new(Method::Get, path)
    }
    fn post(path: &str) -> RestRequest {
        RestRequest::new(Method::Post, path)
    }

    // ── RestRequest ──────────────────────────────────────────────────────────

    #[test]
    fn test_request_bearer_token() {
        let req = get("/api").with_header("Authorization", "Bearer secret-token");
        assert_eq!(req.bearer_token(), Some("secret-token"));
    }

    #[test]
    fn test_request_no_auth_header() {
        let req = get("/api");
        assert_eq!(req.bearer_token(), None);
    }

    #[test]
    fn test_request_json_body() {
        let body = serde_json::to_vec(&serde_json::json!({"key": 42})).unwrap();
        let req = post("/api").with_body(body);
        let parsed: serde_json::Value = req.json_body().unwrap();
        assert_eq!(parsed["key"], 42);
    }

    #[test]
    fn test_request_query_param() {
        let req = get("/api").with_query("address", "0x1000");
        assert_eq!(req.query.get("address").map(std::string::String::as_str), Some("0x1000"));
    }

    // ── RestResponse ─────────────────────────────────────────────────────────

    #[test]
    fn test_response_ok() {
        let r = RestResponse::ok();
        assert_eq!(r.status, 200);
        assert!(r.is_success());
    }

    #[test]
    fn test_response_json() {
        let r = RestResponse::ok_json(&serde_json::json!({"a": 1}));
        assert!(r.is_success());
        assert_eq!(
            r.headers.get("Content-Type").map(std::string::String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn test_response_not_found() {
        let r = RestResponse::not_found("/unknown");
        assert_eq!(r.status, 404);
        assert!(!r.is_success());
    }

    #[test]
    fn test_response_unauthorized() {
        let r = RestResponse::unauthorized();
        assert_eq!(r.status, 401);
    }

    #[test]
    fn test_response_bad_request() {
        let r = RestResponse::bad_request("missing field");
        assert_eq!(r.status, 400);
    }

    #[test]
    fn test_response_too_many_requests() {
        let r = RestResponse::too_many_requests();
        assert_eq!(r.status, 429);
    }

    #[test]
    fn test_response_internal_error() {
        let r = RestResponse::internal_error("crash");
        assert_eq!(r.status, 500);
    }

    #[test]
    fn test_response_with_header() {
        let r = RestResponse::ok().with_header("X-Custom", "value");
        assert_eq!(r.headers.get("X-Custom").map(std::string::String::as_str), Some("value"));
    }

    // ── AuthMiddleware ────────────────────────────────────────────────────────

    #[test]
    fn test_auth_disabled_allows_all() {
        let auth = AuthMiddleware::disabled();
        assert!(auth.authenticate(&get("/private")));
    }

    #[test]
    fn test_auth_public_path_no_token_needed() {
        let auth = AuthMiddleware::new(vec!["secret".into()]);
        assert!(auth.authenticate(&get("/health")));
    }

    #[test]
    fn test_auth_correct_token_passes() {
        let auth = AuthMiddleware::new(vec!["my-token".into()]);
        let req = get("/analyze").with_header("Authorization", "Bearer my-token");
        assert!(auth.authenticate(&req));
    }

    #[test]
    fn test_auth_wrong_token_fails() {
        let auth = AuthMiddleware::new(vec!["correct".into()]);
        let req = get("/analyze").with_header("Authorization", "Bearer wrong");
        assert!(!auth.authenticate(&req));
    }

    #[test]
    fn test_auth_no_token_fails() {
        let auth = AuthMiddleware::new(vec!["secret".into()]);
        assert!(!auth.authenticate(&get("/analyze")));
    }

    #[test]
    fn test_auth_add_token() {
        let mut auth = AuthMiddleware::new(vec![]);
        assert_eq!(auth.token_count(), 0);
        auth.add_token("new-token");
        assert_eq!(auth.token_count(), 1);
    }

    // ── RateLimiter ──────────────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_unlimited_always_passes() {
        let mut rl = RateLimiter::unlimited();
        for _ in 0..1000 {
            assert!(rl.check("client"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_after_limit() {
        let mut rl = RateLimiter::new(3);
        assert!(rl.check("c"));
        assert!(rl.check("c"));
        assert!(rl.check("c"));
        assert!(!rl.check("c"));
    }

    #[test]
    fn test_rate_limiter_separate_clients() {
        let mut rl = RateLimiter::new(1);
        assert!(rl.check("alice"));
        assert!(!rl.check("alice"));
        assert!(rl.check("bob")); // different client
    }

    #[test]
    fn test_rate_limiter_reset() {
        let mut rl = RateLimiter::new(1);
        rl.check("c");
        assert!(!rl.check("c"));
        rl.reset("c");
        assert!(rl.check("c"));
    }

    #[test]
    fn test_rate_limiter_count_for() {
        let mut rl = RateLimiter::new(10);
        rl.check("x");
        rl.check("x");
        assert_eq!(rl.count_for("x"), 2);
    }

    // ── RestEndpoint ─────────────────────────────────────────────────────────

    #[test]
    fn test_endpoint_exact_match() {
        let ep = RestEndpoint::new(Method::Get, "/functions", "desc");
        assert!(ep.matches(Method::Get, "/functions"));
    }

    #[test]
    fn test_endpoint_prefix_match() {
        let ep = RestEndpoint::new(Method::Get, "/functions", "desc");
        assert!(ep.matches(Method::Get, "/functions/0x1000"));
    }

    #[test]
    fn test_endpoint_wrong_method_no_match() {
        let ep = RestEndpoint::new(Method::Get, "/functions", "desc");
        assert!(!ep.matches(Method::Post, "/functions"));
    }

    // ── RestApi routing ───────────────────────────────────────────────────────

    #[test]
    fn test_api_health_endpoint() {
        let mut api = api();
        let resp = api.dispatch(&get("/health"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_version_endpoint() {
        let mut api = api();
        let resp = api.dispatch(&get("/version"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_unknown_path_404() {
        let mut api = api();
        let resp = api.dispatch(&get("/nonexistent"), "client");
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_api_analyze_post() {
        let mut api = api();
        let resp = api.dispatch(&post("/analyze").with_query("path", "/bin/ls"), "client");
        assert!(resp.is_success());
        let body: serde_json::Value = resp.json_body().unwrap();
        assert_eq!(body["status"], "queued");
    }

    #[test]
    fn test_api_functions_get() {
        let mut api = api();
        let resp = api.dispatch(&get("/functions"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_decompile_post() {
        let body = serde_json::to_vec(&serde_json::json!({"address": 4096})).unwrap();
        let mut api = api();
        let resp = api.dispatch(&post("/decompile").with_body(body), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_xrefs_get() {
        let mut api = api();
        let resp = api.dispatch(&get("/xrefs").with_query("address", "0x1000"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_symbols_get() {
        let mut api = api();
        let resp = api.dispatch(&get("/symbols"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_comments_post() {
        let body =
            serde_json::to_vec(&serde_json::json!({"address": 0x1000, "comment": "test"})).unwrap();
        let mut api = api();
        let resp = api.dispatch(&post("/comments").with_body(body), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_yara_post() {
        let body = serde_json::to_vec(&serde_json::json!({"rules": ["rule1", "rule2"]})).unwrap();
        let mut api = api();
        let resp = api.dispatch(&post("/yara").with_body(body), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_diff_post() {
        let mut api = api();
        let resp = api.dispatch(&post("/diff"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_debug_get() {
        let mut api = api();
        let resp = api.dispatch(&get("/debug"), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_script_post() {
        let body =
            serde_json::to_vec(&serde_json::json!({"language": "python", "code": "print(1)"}))
                .unwrap();
        let mut api = api();
        let resp = api.dispatch(&post("/script").with_body(body), "client");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_triage_get() {
        let mut api = api();
        let resp = api.dispatch(
            &get("/triage").with_query("path", "/tmp/sample.exe"),
            "client",
        );
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_request_count() {
        let mut api = api();
        api.dispatch(&get("/health"), "c");
        api.dispatch(&get("/version"), "c");
        assert_eq!(api.request_count(), 2);
    }

    #[test]
    fn test_api_with_auth_blocks_unauthenticated() {
        let mut api = RestApi::new().with_auth(vec!["mytoken".into()]);
        let resp = api.dispatch(&get("/functions"), "c"); // no token
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn test_api_with_auth_allows_authenticated() {
        let mut api = RestApi::new().with_auth(vec!["mytoken".into()]);
        let req = get("/functions").with_header("Authorization", "Bearer mytoken");
        let resp = api.dispatch(&req, "c");
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_rate_limit_blocks() {
        let mut api = RestApi::new().with_rate_limit(2);
        api.dispatch(&get("/health"), "c");
        api.dispatch(&get("/health"), "c");
        let resp = api.dispatch(&get("/health"), "c");
        assert_eq!(resp.status, 429);
    }

    #[test]
    fn test_api_endpoint_count() {
        let api = api();
        assert!(api.endpoints.len() >= 11);
    }

    #[test]
    fn test_api_last_path() {
        let mut api = api();
        api.dispatch(&get("/health"), "c");
        api.dispatch(&get("/version"), "c");
        assert_eq!(api.last_path(), Some("/version"));
    }
}
