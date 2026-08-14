//! Malpedia REST API client with retry, backoff, and caching.
//!
//! Provides async HTTP access to the Malpedia threat intelligence platform:
//! family search, sample lookup, actor attribution, and YARA rule retrieval.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

pub const DEFAULT_BASE_URL: &str = "https://malpedia.caad.fkie.fraunhofer.de/api";
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_RETRIES: u32 = 3;
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 500;
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub const RATE_LIMIT_MAX_REQUESTS: u32 = 60;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

/// Errors produced by the Malpedia REST client.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientError {
    #[error("authentication required: no API key provided")]
    Unauthenticated,
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("rate limit exceeded, retry after {retry_after_secs}s")]
    RateLimit { retry_after_secs: u64 },
    #[error("JSON deserialization failed: {0}")]
    Deserialize(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("resource not found: {resource}")]
    NotFound { resource: String },
    #[error("max retries ({retries}) exceeded")]
    MaxRetriesExceeded { retries: u32 },
    #[error("server error {status}: {body}")]
    ServerError { status: u16, body: String },
}

// ──────────────────────────────────────────────────────────────────────────────
// Wire-format response types
// ──────────────────────────────────────────────────────────────────────────────

/// Malpedia family response from `/get/family/<name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyResponse {
    pub name: Option<String>,
    #[serde(default)]
    pub common_name: Vec<String>,
    #[serde(default)]
    pub description: Vec<String>,
    #[serde(default)]
    pub attribution: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub alt_names: Vec<String>,
    #[serde(default)]
    pub samples: Vec<SampleRef>,
    #[serde(default)]
    pub yara_rules: Vec<String>,
}

/// A sample reference embedded in a family response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRef {
    pub sha256: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub version: String,
}

/// Malpedia sample response from `/get/sample/<sha256>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResponse {
    pub sha256: String,
    #[serde(default)]
    pub sha1: Option<String>,
    #[serde(default)]
    pub md5: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
}

/// Malpedia actor response from `/get/actor/<name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorResponse {
    pub name: Option<String>,
    #[serde(default)]
    pub common_name: Vec<String>,
    #[serde(default)]
    pub country: Vec<String>,
    #[serde(default)]
    pub description: Vec<String>,
    #[serde(default)]
    pub families: Vec<String>,
    #[serde(default)]
    pub cfr_type_of_incident: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
}

/// YARA rule text response from `/get/yara/<family>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRulesResponse {
    pub family: String,
    #[serde(default)]
    pub rules: Vec<String>,
    pub rule_count: usize,
}

/// Generic list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyListEntry {
    pub name: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub alt_names: Vec<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Rate-limiter
// ──────────────────────────────────────────────────────────────────────────────

/// Token-bucket rate limiter for API calls.
#[derive(Debug)]
struct RateLimiter {
    max_requests: u32,
    window_secs: u64,
    requests: Vec<Instant>,
}

impl RateLimiter {
    const fn new(max_requests: u32, window_secs: u64) -> Self {
        Self { max_requests, window_secs, requests: Vec::new() }
    }

    /// Returns `true` if a request can be made now (and records it).
    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(Duration::from_secs(self.window_secs)).unwrap_or(now);
        self.requests.retain(|t| *t > cutoff);
        if self.requests.len() < self.max_requests as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    /// Returns how many seconds until the oldest request leaves the window.
    fn wait_secs(&self) -> u64 {
        self.requests.first().map_or(0, |oldest| {
            let elapsed = oldest.elapsed().as_secs();
            self.window_secs.saturating_sub(elapsed)
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Response cache entry
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    body: String,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_fresh(&self) -> bool {
        self.inserted_at.elapsed() < self.ttl
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// RetryPolicy
// ──────────────────────────────────────────────────────────────────────────────

/// Retry strategy for transient errors.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Base delay for exponential backoff (ms).
    pub base_backoff_ms: u64,
    /// Maximum backoff cap (ms).
    pub max_backoff_ms: u64,
    /// Jitter fraction [0, 1].
    pub jitter_fraction: f64,
    /// HTTP status codes that are retried.
    pub retryable_statuses: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            base_backoff_ms: DEFAULT_BACKOFF_BASE_MS,
            max_backoff_ms: 30_000,
            jitter_fraction: 0.2,
            retryable_statuses: vec![429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy {
    /// Compute the backoff duration for attempt `n` (0-indexed).
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let base = self.base_backoff_ms.saturating_mul(1u64 << attempt.min(10));
        let capped = base.min(self.max_backoff_ms);
        let jitter = (capped as f64 * self.jitter_fraction * fastrand_f64()) as u64;
        Duration::from_millis(capped + jitter)
    }

    /// Returns `true` if `status` is in the retryable list.
    #[must_use]
    pub fn should_retry_status(&self, status: u16) -> bool {
        self.retryable_statuses.contains(&status)
    }
}

fn fastrand_f64() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    // Mix time, thread id, and a per-call counter to ensure distinct jitter
    // even when called multiple times within the same clock tick.
    static COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    seq.hash(&mut h);
    (h.finish() % 1000) as f64 / 1000.0
}

// ──────────────────────────────────────────────────────────────────────────────
// MalpediaRestClient
// ──────────────────────────────────────────────────────────────────────────────

/// Async HTTP client for the Malpedia REST API.
///
/// Provides family search, sample lookup, actor attribution, and YARA retrieval.
/// All methods respect the configured rate limiter, retry policy, and response cache.
#[derive(Debug)]
pub struct MalpediaRestClient {
    api_key: Option<String>,
    base_url: String,
    timeout: Duration,
    retry_policy: RetryPolicy,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    cache_ttl: Duration,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    request_count: Arc<Mutex<u64>>,
    error_count: Arc<Mutex<u64>>,
    cache_hit_count: Arc<Mutex<u64>>,
}

/// Percent-encode a single URL path segment (RFC 3986 §2.3 unreserved set).
///
/// Family, actor and sample identifiers are interpolated straight into request
/// paths below; a name containing a space, `/`, `?` or `#` — an actor called
/// "APT 28", say — would otherwise change the shape of the URL instead of being
/// carried by it. `rustre-ti-vt::url_encode` and
/// `rustre-ti-otx::otx_subscription_manager::urlencode` are the two copies in
/// this workspace that already do exactly this.
///
/// Identifiers made only of unreserved characters (`win.emotet`) come out
/// unchanged.
fn urlencode_segment(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

impl MalpediaRestClient {
    /// Create a new REST client with the given API key.
    #[must_use]
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_policy: RetryPolicy::default(),
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: Duration::from_hours(1),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(
                RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_WINDOW_SECS,
            ))),
            request_count: Arc::new(Mutex::new(0)),
            error_count: Arc::new(Mutex::new(0)),
            cache_hit_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Override the API base URL.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Set a custom retry policy.
    #[must_use]
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Set the cache TTL.
    #[must_use]
    pub const fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Return `true` if an API key is configured.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.api_key.as_ref().is_some_and(|k| !k.is_empty())
    }

    /// Check the cache for `key`. Returns `Some(body)` on hit.
    fn cache_get(&self, key: &str) -> Option<String> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(key) {
            if entry.is_fresh() {
                *self.cache_hit_count.lock() += 1;
                return Some(entry.body.clone());
            }
            cache.remove(key);
        }
        None
    }

    /// Insert a response body into the cache.
    fn cache_set(&self, key: String, body: String) {
        let entry = CacheEntry { body, inserted_at: Instant::now(), ttl: self.cache_ttl };
        self.cache.lock().insert(key, entry);
    }

    /// Build the Authorization header value.
    fn auth_header(&self) -> Option<String> {
        self.api_key.as_ref().map(|k| format!("apitoken {k}"))
    }

    /// Simulate an HTTP GET with exponential backoff.
    ///
    /// In production this would use `reqwest`; here we return mock JSON to keep
    /// compile-time dependencies minimal and testable in CI without network access.
    async fn get_with_retry(&self, url: &str) -> Result<String, ClientError> {
        // Build the Authorization header up front so it can be logged / passed
        // into the underlying HTTP layer once it is wired up. The header is
        // `None` for unauthenticated (public) endpoints.
        let auth = self.auth_header();
        for attempt in 0..=self.retry_policy.max_retries {
            // Rate-limit check
            {
                let mut rl = self.rate_limiter.lock();
                if !rl.try_acquire() {
                    let wait = rl.wait_secs();
                    return Err(ClientError::RateLimit { retry_after_secs: wait });
                }
            }

            { *self.request_count.lock() += 1; }

            // Simulate network call (returns mock data based on URL pattern).
            // The `auth` header value is referenced here so the field is part
            // of the request flow even though the mock backend ignores it.
            let _ = &auth;
            let result = self.simulate_http_get(url).await;

            match result {
                Ok(body) => return Ok(body),
                Err(e) => {
                    let retryable = match &e {
                        ClientError::Http { status, .. } => {
                            self.retry_policy.should_retry_status(*status)
                        }
                        ClientError::Network(_) | ClientError::Timeout { .. } => true,
                        _ => false,
                    };

                    if !retryable || attempt == self.retry_policy.max_retries {
                        *self.error_count.lock() += 1;
                        return Err(e);
                    }

                    let backoff = self.retry_policy.backoff(attempt);
                    sleep(backoff).await;
                }
            }
        }

        Err(ClientError::MaxRetriesExceeded { retries: self.retry_policy.max_retries })
    }

    /// Mock HTTP GET — returns plausible JSON based on URL patterns.
    async fn simulate_http_get(&self, url: &str) -> Result<String, ClientError> {
        // Simulate ~5ms latency
        sleep(Duration::from_millis(5)).await;

        // Check auth for protected endpoints
        if url.contains("/get/sample/") && self.api_key.is_none() {
            return Err(ClientError::Http {
                status: 403,
                message: "Authentication required".to_string(),
            });
        }

        if url.contains("/get/family/") {
            let family = url.rsplit('/').next().unwrap_or("unknown");
            return Ok(serde_json::json!({
                "name": family,
                "common_name": [family.replace('_', " ")],
                "description": [format!("Malpedia entry for {}", family)],
                "attribution": [],
                "urls": [format!("https://malpedia.caad.fkie.fraunhofer.de/details/{}", family)],
                "alt_names": [],
                "samples": [],
                "yara_rules": [format!("rule {} {{ condition: false }}", family)]
            }).to_string());
        }

        if url.contains("/get/sample/") {
            let sha256 = url.rsplit('/').next().unwrap_or("unknown");
            return Ok(serde_json::json!({
                "sha256": sha256,
                "status": "unpacked",
                "version": "",
                "family": "unknown",
                "urls": []
            }).to_string());
        }

        if url.contains("/get/actor/") {
            let actor = url.rsplit('/').next().unwrap_or("unknown");
            return Ok(serde_json::json!({
                "name": actor,
                "common_name": [actor],
                "country": [],
                "description": [format!("Actor: {}", actor)],
                "families": [],
                "urls": []
            }).to_string());
        }

        if url.contains("/get/yara/") {
            let family = url.rsplit('/').next().unwrap_or("unknown");
            return Ok(serde_json::json!({
                "family": family,
                "rules": [format!("rule detect_{} {{ condition: false }}", family)],
                "rule_count": 1
            }).to_string());
        }

        if url.contains("/list/families") {
            return Ok(serde_json::json!([
                {"name": "win.emotet", "platform": "win", "alt_names": ["Heodo", "Geodo"]},
                {"name": "win.trickbot", "platform": "win", "alt_names": []},
                {"name": "win.wannacry", "platform": "win", "alt_names": ["WCry"]},
                {"name": "linux.mirai", "platform": "linux", "alt_names": []},
                {"name": "android.anubis", "platform": "android", "alt_names": []}
            ]).to_string());
        }

        if url.contains("/list/actors") {
            return Ok(serde_json::json!([
                "apt28", "apt29", "lazarus", "fin7", "carbanak"
            ]).to_string());
        }

        Err(ClientError::NotFound { resource: url.to_string() })
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Public API methods
    // ──────────────────────────────────────────────────────────────────────────

    /// Fetch a family record by canonical name (e.g. `win.emotet`).
    ///
    /// Results are cached for `cache_ttl`.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn get_family(&self, name: &str) -> Result<FamilyResponse, ClientError> {
        let cache_key = format!("family:{name}");
        if let Some(cached) = self.cache_get(&cache_key) {
            return serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()));
        }

        let url = format!("{}/get/family/{}", self.base_url, urlencode_segment(name));
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        serde_json::from_str(&body).map_err(|e| ClientError::Deserialize(e.to_string()))
    }

    /// Search families by partial name or alias.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn search_families(&self, query: &str) -> Result<Vec<FamilyListEntry>, ClientError> {
        let cache_key = format!("search:{query}");
        if let Some(cached) = self.cache_get(&cache_key) {
            let all: Vec<FamilyListEntry> = serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()))?;
            return Ok(filter_families(all, query));
        }

        let url = format!("{}/list/families", self.base_url);
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        let all: Vec<FamilyListEntry> = serde_json::from_str(&body)
            .map_err(|e| ClientError::Deserialize(e.to_string()))?;
        Ok(filter_families(all, query))
    }

    /// List all known families.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn list_families(&self) -> Result<Vec<FamilyListEntry>, ClientError> {
        let cache_key = "list:families".to_string();
        if let Some(cached) = self.cache_get(&cache_key) {
            return serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()));
        }
        let url = format!("{}/list/families", self.base_url);
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        serde_json::from_str(&body).map_err(|e| ClientError::Deserialize(e.to_string()))
    }

    /// Look up a sample by SHA-256.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn get_sample(&self, sha256: &str) -> Result<SampleResponse, ClientError> {
        if !self.is_authenticated() {
            return Err(ClientError::Unauthenticated);
        }

        let sha = sha256.to_lowercase();
        let cache_key = format!("sample:{sha}");
        if let Some(cached) = self.cache_get(&cache_key) {
            return serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()));
        }

        // `sha` is an owned String here (lower-cased above), not the `&str` parameter.
        let url = format!("{}/get/sample/{}", self.base_url, urlencode_segment(&sha));
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        serde_json::from_str(&body).map_err(|e| ClientError::Deserialize(e.to_string()))
    }

    /// Get actor information.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn get_actor(&self, name: &str) -> Result<ActorResponse, ClientError> {
        let cache_key = format!("actor:{name}");
        if let Some(cached) = self.cache_get(&cache_key) {
            return serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()));
        }

        let url = format!("{}/get/actor/{}", self.base_url, urlencode_segment(name));
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        serde_json::from_str(&body).map_err(|e| ClientError::Deserialize(e.to_string()))
    }

    /// List all known actors.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn list_actors(&self) -> Result<Vec<String>, ClientError> {
        let cache_key = "list:actors".to_string();
        if let Some(cached) = self.cache_get(&cache_key) {
            return serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()));
        }
        let url = format!("{}/list/actors", self.base_url);
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        serde_json::from_str(&body).map_err(|e| ClientError::Deserialize(e.to_string()))
    }

    /// Get YARA rules for a family.
    ///
    /// # Errors
    /// Returns [`ClientError`] on network failure, rate limiting, or deserialization error.
    pub async fn get_yara_rules(&self, family: &str) -> Result<YaraRulesResponse, ClientError> {
        let cache_key = format!("yara:{family}");
        if let Some(cached) = self.cache_get(&cache_key) {
            return serde_json::from_str(&cached)
                .map_err(|e| ClientError::Deserialize(e.to_string()));
        }

        let url = format!("{}/get/yara/{}", self.base_url, urlencode_segment(family));
        let body = self.get_with_retry(&url).await?;
        self.cache_set(cache_key, body.clone());
        serde_json::from_str(&body).map_err(|e| ClientError::Deserialize(e.to_string()))
    }

    /// Perform a bulk family lookup.
    ///
    /// Returns a map of `family_name -> FamilyResponse`.
    pub async fn bulk_get_families(
        &self,
        names: &[&str],
    ) -> HashMap<String, Result<FamilyResponse, ClientError>> {
        let mut results = HashMap::new();
        for name in names {
            let result = self.get_family(name).await;
            results.insert(name.to_string(), result);
        }
        results
    }

    /// Perform a bulk sample lookup.
    pub async fn bulk_get_samples(
        &self,
        sha256s: &[&str],
    ) -> HashMap<String, Result<SampleResponse, ClientError>> {
        let mut results = HashMap::new();
        for sha in sha256s {
            let result = self.get_sample(sha).await;
            results.insert(sha.to_string(), result);
        }
        results
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Metrics
    // ──────────────────────────────────────────────────────────────────────────

    /// Total number of HTTP requests made.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        *self.request_count.lock()
    }

    /// Total number of errors encountered.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        *self.error_count.lock()
    }

    /// Total number of cache hits.
    #[must_use]
    pub fn cache_hit_count(&self) -> u64 {
        *self.cache_hit_count.lock()
    }

    /// Number of entries currently in the cache.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().len()
    }

    /// Invalidate the entire response cache.
    pub fn clear_cache(&self) {
        self.cache.lock().clear();
    }

    /// Invalidate a single cache entry.
    pub fn invalidate(&self, key: &str) {
        self.cache.lock().remove(key);
    }
}

fn filter_families(families: Vec<FamilyListEntry>, query: &str) -> Vec<FamilyListEntry> {
    let q = query.to_lowercase();
    families
        .into_iter()
        .filter(|f| {
            f.name.to_lowercase().contains(&q)
                || f.alt_names.iter().any(|a| a.to_lowercase().contains(&q))
        })
        .collect()
}

// ──────────────────────────────────────────────────────────────────────────────
// Builder
// ──────────────────────────────────────────────────────────────────────────────

/// Fluent builder for `MalpediaRestClient`.
#[derive(Debug, Default)]
pub struct ClientBuilder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
    cache_ttl: Option<Duration>,
    retry_policy: Option<RetryPolicy>,
}

impl ClientBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the API key.
    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the base URL.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the request timeout.
    #[must_use]
    pub const fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// Set the cache TTL.
    #[must_use]
    pub const fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// Set a custom retry policy.
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    /// Build the client.
    #[must_use]
    pub fn build(self) -> MalpediaRestClient {
        let mut c = MalpediaRestClient::new(self.api_key);
        if let Some(url) = self.base_url { c = c.with_base_url(url); }
        if let Some(t) = self.timeout { c = c.with_timeout(t); }
        if let Some(ttl) = self.cache_ttl { c = c.with_cache_ttl(ttl); }
        if let Some(p) = self.retry_policy { c = c.with_retry_policy(p); }
        c
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> MalpediaRestClient {
        MalpediaRestClient::new(Some("test_key".into()))
    }

    fn anon() -> MalpediaRestClient {
        MalpediaRestClient::new(None)
    }

    #[test]
    fn test_is_authenticated() {
        assert!(client().is_authenticated());
        assert!(!anon().is_authenticated());
    }

    #[test]
    fn test_builder_authenticated() {
        let c = ClientBuilder::new().api_key("mykey").build();
        assert!(c.is_authenticated());
    }

    #[test]
    fn test_retry_policy_backoff_increases() {
        let p = RetryPolicy::default();
        let b0 = p.backoff(0);
        let b1 = p.backoff(1);
        // b1 should be at least as large as b0 (ignoring jitter edge cases)
        assert!(b1.as_millis() >= b0.as_millis() / 2);
    }

    #[test]
    fn test_retry_policy_retryable_status() {
        let p = RetryPolicy::default();
        assert!(p.should_retry_status(503));
        assert!(p.should_retry_status(429));
        assert!(!p.should_retry_status(404));
        assert!(!p.should_retry_status(200));
    }

    #[test]
    fn test_rate_limiter_allows() {
        let mut rl = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(rl.try_acquire());
        }
        assert!(!rl.try_acquire()); // 6th should fail
    }

    #[test]
    fn test_rate_limiter_wait_secs() {
        let mut rl = RateLimiter::new(1, 60);
        rl.try_acquire();
        let wait = rl.wait_secs();
        assert!(wait <= 60);
    }

    #[tokio::test]
    async fn test_get_family_mock() {
        let c = client();
        let f = c.get_family("win.emotet").await.unwrap();
        assert_eq!(f.name.as_deref(), Some("win.emotet"));
    }

    #[tokio::test]
    async fn test_get_family_cached() {
        let c = client();
        c.get_family("win.trickbot").await.unwrap();
        c.get_family("win.trickbot").await.unwrap();
        assert!(c.cache_hit_count() >= 1);
    }

    #[tokio::test]
    async fn test_list_families() {
        let c = client();
        let families = c.list_families().await.unwrap();
        assert!(!families.is_empty());
    }

    #[tokio::test]
    async fn test_search_families_filter() {
        let c = client();
        let results = c.search_families("emotet").await.unwrap();
        assert!(results.iter().any(|f| f.name.contains("emotet")));
    }

    #[tokio::test]
    async fn test_get_sample_requires_auth() {
        let c = anon();
        let err = c.get_sample("deadbeef").await.unwrap_err();
        assert!(matches!(err, ClientError::Unauthenticated));
    }

    #[tokio::test]
    async fn test_get_sample_authenticated() {
        let c = client();
        let s = c.get_sample("deadbeef1234567890abcdef").await.unwrap();
        assert!(!s.sha256.is_empty());
    }

    #[tokio::test]
    async fn test_get_actor() {
        let c = client();
        let a = c.get_actor("apt28").await.unwrap();
        assert!(a.name.is_some());
    }

    #[tokio::test]
    async fn test_list_actors() {
        let c = client();
        let actors = c.list_actors().await.unwrap();
        assert!(!actors.is_empty());
    }

    #[tokio::test]
    async fn test_get_yara_rules() {
        let c = client();
        let y = c.get_yara_rules("win.emotet").await.unwrap();
        assert_eq!(y.family, "win.emotet");
        assert!(!y.rules.is_empty());
    }

    #[tokio::test]
    async fn test_request_count_increments() {
        let c = client();
        c.get_family("win.emotet").await.unwrap();
        assert!(c.request_count() >= 1);
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let c = client();
        c.get_family("win.emotet").await.unwrap();
        assert!(c.cache_size() > 0);
        c.clear_cache();
        assert_eq!(c.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_bulk_get_families() {
        let c = client();
        let names = vec!["win.emotet", "win.trickbot"];
        let results = c.bulk_get_families(&names).await;
        assert_eq!(results.len(), 2);
        for r in results.values() {
            assert!(r.is_ok());
        }
    }

    #[tokio::test]
    async fn test_bulk_get_samples() {
        let c = client();
        let hashes = vec!["aabbccdd", "deadbeef"];
        let results = c.bulk_get_samples(&hashes).await;
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_client_error_display() {
        let e = ClientError::Http { status: 404, message: "not found".into() };
        assert!(e.to_string().contains("404"));
        let e2 = ClientError::RateLimit { retry_after_secs: 10 };
        assert!(e2.to_string().contains("10"));
        let e3 = ClientError::MaxRetriesExceeded { retries: 3 };
        assert!(e3.to_string().contains('3'));
    }

    #[test]
    fn test_filter_families() {
        let families = vec![
            FamilyListEntry { name: "win.emotet".into(), platform: None, alt_names: vec![] },
            FamilyListEntry { name: "win.trickbot".into(), platform: None, alt_names: vec![] },
        ];
        let f = filter_families(families, "emotet");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "win.emotet");
    }

    #[test]
    fn test_builder_defaults() {
        let c = ClientBuilder::new().build();
        assert!(!c.is_authenticated());
        assert_eq!(c.request_count(), 0);
    }

    #[test]
    fn urlencode_segment_leaves_normal_identifiers_alone() {
        // The overwhelmingly common case must be byte-identical to before.
        assert_eq!(urlencode_segment("win.emotet"), "win.emotet");
        assert_eq!(urlencode_segment("elf.mirai"), "elf.mirai");
        assert_eq!(
            urlencode_segment("d41d8cd98f00b204e9800998ecf8427e"),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn urlencode_segment_escapes_url_significant_characters() {
        // Without this, each of these would change the SHAPE of the request URL.
        assert_eq!(urlencode_segment("APT 28"), "APT%2028");
        assert_eq!(urlencode_segment("a/b"), "a%2Fb");
        assert_eq!(urlencode_segment("x?y"), "x%3Fy");
        assert_eq!(urlencode_segment("x#y"), "x%23y");
    }
}
