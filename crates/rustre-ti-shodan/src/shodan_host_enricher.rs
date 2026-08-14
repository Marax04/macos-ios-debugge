//! Shodan host enrichment client.
//!
//! Async HTTP client over the Shodan REST API. Provides:
//! * host lookup (`/shodan/host/{ip}`)
//! * search (`/shodan/host/search`)
//! * streaming banner subscription (`https://stream.shodan.io/shodan/banners`)
//! * alert management (`/shodan/alert`)
//!
//! Includes auth via env var / config, retry with exponential backoff,
//! and graceful handling of 401/404/429.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::{ShodanConfig, ShodanError};

const USER_AGENT: &str = concat!("rustre-ti-shodan/", env!("CARGO_PKG_VERSION"));

// ─── Retry policy ─────────────────────────────────────────────────────────────

/// Retry / backoff parameters for Shodan HTTP calls.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the first).
    pub max_attempts: u32,
    /// Initial backoff before the second attempt.
    pub initial_backoff: Duration,
    /// Cap on per-attempt backoff.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_backoff: Duration::from_millis(400),
            max_backoff: Duration::from_secs(20),
        }
    }
}

// ─── Models ──────────────────────────────────────────────────────────────────

/// A single banner returned by Shodan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanBanner {
    /// Source IP address (string form).
    #[serde(default, alias = "ip_str")]
    pub ip: Option<String>,
    /// Port number.
    #[serde(default)]
    pub port: u16,
    /// Transport protocol (`tcp`/`udp`).
    #[serde(default)]
    pub transport: Option<String>,
    /// Service product/vendor identifier.
    #[serde(default)]
    pub product: Option<String>,
    /// Detected version, if any.
    #[serde(default)]
    pub version: Option<String>,
    /// CPE identifiers reported by Shodan.
    #[serde(default)]
    pub cpe: Vec<String>,
    /// CPE 2.3 identifiers, if present.
    #[serde(default, rename = "cpe23")]
    pub cpe23: Vec<String>,
    /// Banner hostnames.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Banner raw data, included only if `include_raw_banners` is enabled.
    #[serde(default)]
    pub data: Option<String>,
    /// Timestamp (Shodan-formatted, UTC).
    #[serde(default)]
    pub timestamp: Option<String>,
    /// ASN string (`ASxxxx`).
    #[serde(default)]
    pub asn: Option<String>,
    /// ISP / organisation.
    #[serde(default)]
    pub org: Option<String>,
    /// Vulnerabilities mentioned in the banner, keyed by CVE.
    #[serde(default)]
    pub vulns: Option<serde_json::Value>,
}

/// Host info returned by `/shodan/host/{ip}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHost {
    #[serde(alias = "ip_str")]
    pub ip: String,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub country_name: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub asn: Option<String>,
    #[serde(default)]
    pub isp: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub vulns: Vec<String>,
    /// Per-port banners.
    #[serde(default)]
    pub data: Vec<ShodanBanner>,
    #[serde(default)]
    pub last_update: Option<String>,
}

/// One page of search results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanSearchPage {
    /// Total number of matches across all pages.
    #[serde(default)]
    pub total: u64,
    /// Banners in this page.
    #[serde(default, rename = "matches")]
    pub banners: Vec<ShodanBanner>,
}

/// Shodan network alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanAlert {
    /// Alert id (Shodan-assigned).
    #[serde(default)]
    pub id: Option<String>,
    /// Human-friendly name.
    pub name: String,
    /// Targeted filters (typically `{"ip": ["1.2.3.4/24"]}`).
    pub filters: serde_json::Value,
    /// Optional notifier ids attached to the alert.
    #[serde(default)]
    pub triggers: Option<serde_json::Value>,
    /// Creation timestamp.
    #[serde(default)]
    pub created: Option<String>,
    /// Expiration in seconds, if scheduled.
    #[serde(default)]
    pub expires: Option<u64>,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// Async Shodan client.
#[derive(Clone, Debug)]
pub struct ShodanClient {
    config: ShodanConfig,
    http: Client,
    retry: RetryPolicy,
}

impl ShodanClient {
    /// Build a client from the given config.
    ///
    /// # Errors
    /// Returns [`ShodanError::Http`] if the TLS client cannot be built.
    pub fn new(config: ShodanConfig) -> Result<Self, ShodanError> {
        if config.api_key.trim().is_empty() {
            return Err(ShodanError::Auth("empty api key".to_owned()));
        }
        let http = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(config.timeout_secs))
            .use_rustls_tls()
            .build()
            .map_err(|e| ShodanError::Http(e.to_string()))?;
        Ok(Self {
            config,
            http,
            retry: RetryPolicy::default(),
        })
    }

    /// Construct a client reading the API key from `SHODAN_API_KEY`.
    ///
    /// # Errors
    /// Returns [`ShodanError::Auth`] if the variable is missing or empty.
    pub fn from_env() -> Result<Self, ShodanError> {
        let key = std::env::var("SHODAN_API_KEY")
            .map_err(|_| ShodanError::Auth("SHODAN_API_KEY not set".to_owned()))?;
        Self::from_api_key(key)
    }

    /// Construct from a raw API-key string, validating it is non-empty.
    ///
    /// # Errors
    /// Returns `ShodanError::Auth` when the key is empty or whitespace-only.
    pub fn from_api_key(key: String) -> Result<Self, ShodanError> {
        if key.trim().is_empty() {
            return Err(ShodanError::Auth("SHODAN_API_KEY is empty".to_owned()));
        }
        Self::new(ShodanConfig::new(key))
    }

    /// Override the retry policy.
    #[must_use]
    pub const fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Reference to the active config.
    #[must_use]
    pub const fn config(&self) -> &ShodanConfig {
        &self.config
    }

    // ── Host lookup ──────────────────────────────────────────────────────────

    /// Lookup host information for `ip`.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn host(&self, ip: IpAddr) -> Result<ShodanHost, ShodanError> {
        let url = self.config.host_url(&ip.to_string());
        let body = self.get_text(&url).await?;
        serde_json::from_str(&body).map_err(|e| ShodanError::Json(e.to_string()))
    }

    /// Lookup host information for a raw IP string (validates first).
    ///
    /// # Errors
    /// [`ShodanError::InvalidIp`] if `ip` is not parseable, plus the errors
    /// of [`ShodanClient::host`].
    pub async fn host_str(&self, ip: &str) -> Result<ShodanHost, ShodanError> {
        let parsed: IpAddr = ip
            .parse()
            .map_err(|e: std::net::AddrParseError| ShodanError::InvalidIp(e.to_string()))?;
        self.host(parsed).await
    }

    // ── Search ───────────────────────────────────────────────────────────────

    /// Run one page of `/shodan/host/search` with the given Shodan query.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn search(&self, query: &str, page: u32) -> Result<ShodanSearchPage, ShodanError> {
        let url = format!(
            "{}/shodan/host/search?key={}&query={}&page={}",
            self.config.base_url,
            urlencode(&self.config.api_key),
            urlencode(query),
            page.max(1),
        );
        let body = self.get_text(&url).await?;
        serde_json::from_str(&body).map_err(|e| ShodanError::Json(e.to_string()))
    }

    /// Iterate every search page until exhausted, returning all banners.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn search_all(
        &self,
        query: &str,
        max_pages: u32,
    ) -> Result<Vec<ShodanBanner>, ShodanError> {
        let mut out = Vec::new();
        for page in 1..=max_pages.max(1) {
            let p = self.search(query, page).await?;
            let got = p.banners.len();
            out.extend(p.banners);
            if got == 0 {
                break;
            }
        }
        Ok(out)
    }

    // ── Stream ───────────────────────────────────────────────────────────────

    /// Subscribe to the live banner stream and forward each parsed banner to
    /// the returned receiver. The background task exits when the API closes
    /// the stream, when a parse/HTTP error occurs, or when the receiver is
    /// dropped.
    ///
    /// # Errors
    /// HTTP errors from the initial stream connection.
    pub async fn stream_banners(&self) -> Result<mpsc::Receiver<ShodanBanner>, ShodanError> {
        // Guard against a runaway server sending data without newlines: if the
        // in-progress line buffer exceeds 4 MiB we drop it and log a warning
        // to avoid unbounded memory growth (resource-leak / OOM protection).
        const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
        // 90-second idle timeout: if the stream delivers no chunk for this
        // long the server is likely stalled and the task should exit rather
        // than holding the connection and memory indefinitely.
        const CHUNK_TIMEOUT: Duration = Duration::from_secs(90);

        let url = format!(
            "https://stream.shodan.io/shodan/banners?key={}",
            urlencode(&self.config.api_key),
        );
        let res = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;

        let status = res.status();
        if !status.is_success() {
            return Err(map_status_error(status));
        }

        let (tx, rx) = mpsc::channel::<ShodanBanner>(64);
        let mut stream_res = res;

        tokio::spawn(async move {
            let mut leftover: Vec<u8> = Vec::new();
            loop {
                let chunk_result = tokio::time::timeout(CHUNK_TIMEOUT, stream_res.chunk()).await;
                let chunk_result = match chunk_result {
                    Ok(r) => r,
                    Err(_elapsed) => {
                        warn!("shodan stream: chunk timeout, closing stream");
                        return;
                    }
                };
                match chunk_result {
                    Ok(Some(bytes)) => {
                        leftover.extend_from_slice(&bytes);
                        // Shodan stream is newline-delimited JSON.
                        while let Some(pos) = leftover.iter().position(|b| *b == b'\n') {
                            let line: Vec<u8> = leftover.drain(..=pos).collect();
                            let trimmed = trim_ascii(&line);
                            if trimmed.is_empty() {
                                continue;
                            }
                            match serde_json::from_slice::<ShodanBanner>(trimmed) {
                                Ok(banner) => {
                                    if tx.send(banner).await.is_err() {
                                        return; // receiver dropped
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "shodan stream: bad json frame");
                                }
                            }
                        }
                        // Safety valve: discard oversized partial lines so we
                        // do not accumulate unbounded data between newlines.
                        if leftover.len() > MAX_LINE_BYTES {
                            warn!(
                                bytes = leftover.len(),
                                "shodan stream: oversized line buffer, discarding"
                            );
                            leftover.clear();
                        }
                    }
                    Ok(None) => return,
                    Err(e) => {
                        warn!(error = %e, "shodan stream chunk error");
                        return;
                    }
                }
            }
        });
        Ok(rx)
    }

    // ── Alerts ───────────────────────────────────────────────────────────────

    /// List existing alerts on the account.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn list_alerts(&self) -> Result<Vec<ShodanAlert>, ShodanError> {
        let url = format!(
            "{}/shodan/alert/info?key={}",
            self.config.base_url,
            urlencode(&self.config.api_key),
        );
        let body = self.get_text(&url).await?;
        serde_json::from_str(&body).map_err(|e| ShodanError::Json(e.to_string()))
    }

    /// Create a new alert.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn create_alert(
        &self,
        name: &str,
        filters: &serde_json::Value,
        expires_secs: Option<u64>,
    ) -> Result<ShodanAlert, ShodanError> {
        let url = format!(
            "{}/shodan/alert?key={}",
            self.config.base_url,
            urlencode(&self.config.api_key),
        );
        let mut body = serde_json::json!({
            "name": name,
            "filters": filters,
        });
        if let Some(e) = expires_secs {
            body["expires"] = serde_json::json!(e);
        }
        let res = self.post_json(&url, &body).await?;
        serde_json::from_str(&res).map_err(|e| ShodanError::Json(e.to_string()))
    }

    /// Delete an alert by id.
    ///
    /// # Errors
    /// Network / HTTP errors.
    pub async fn delete_alert(&self, alert_id: &str) -> Result<(), ShodanError> {
        let url = format!(
            "{}/shodan/alert/{}?key={}",
            self.config.base_url,
            urlencode(alert_id),
            urlencode(&self.config.api_key),
        );
        let res = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;
        let status = res.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(map_status_error(status))
        }
    }

    // ── HTTP helpers with retry/backoff ──────────────────────────────────────

    async fn get_text(&self, url: &str) -> Result<String, ShodanError> {
        let mut attempt: u32 = 0;
        let mut backoff = self.retry.initial_backoff;
        loop {
            attempt = attempt.saturating_add(1);
            debug!(%url, attempt, "Shodan GET");
            let res = self.http.get(url).send().await;
            match classify(res).await {
                Outcome::Ok(text) => return Ok(text),
                Outcome::Retry(reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, "Shodan retrying");
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(self.retry.max_backoff);
                }
                Outcome::Retry(reason) => return Err(ShodanError::Http(reason)),
                Outcome::Fatal(err) => return Err(err),
            }
        }
    }

    async fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<String, ShodanError> {
        let mut attempt: u32 = 0;
        let mut backoff = self.retry.initial_backoff;
        loop {
            attempt = attempt.saturating_add(1);
            debug!(%url, attempt, "Shodan POST");
            let res = self.http.post(url).json(body).send().await;
            match classify(res).await {
                Outcome::Ok(text) => return Ok(text),
                Outcome::Retry(reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, "Shodan retrying");
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(self.retry.max_backoff);
                }
                Outcome::Retry(reason) => return Err(ShodanError::Http(reason)),
                Outcome::Fatal(err) => return Err(err),
            }
        }
    }
}

enum Outcome {
    Ok(String),
    Retry(String),
    Fatal(ShodanError),
}

async fn classify(res: Result<Response, reqwest::Error>) -> Outcome {
    match res {
        Ok(r) => {
            let status = r.status();
            if status.is_success() {
                // Guard against enormous responses that could exhaust memory.
                // 32 MiB is well above any legitimate Shodan host/search page.
                const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
                if let Some(len) = r.content_length()
                    && len > MAX_RESPONSE_BYTES
                {
                    return Outcome::Fatal(ShodanError::Http(format!(
                        "response too large: {len} bytes"
                    )));
                }
                return match r.text().await {
                    Ok(t) => {
                        if t.len() as u64 > MAX_RESPONSE_BYTES {
                            Outcome::Fatal(ShodanError::Http(format!(
                                "response body too large: {} bytes",
                                t.len()
                            )))
                        } else {
                            Outcome::Ok(t)
                        }
                    }
                    Err(e) => Outcome::Fatal(ShodanError::Http(e.to_string())),
                };
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Outcome::Retry(format!("rate-limited {status}"));
            }
            if status.is_server_error() {
                return Outcome::Retry(format!("server {status}"));
            }
            Outcome::Fatal(map_status_error(status))
        }
        Err(e) if e.is_timeout() || e.is_connect() => Outcome::Retry(format!("transport: {e}")),
        Err(e) => Outcome::Fatal(ShodanError::Http(e.to_string())),
    }
}

fn map_status_error(status: StatusCode) -> ShodanError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            ShodanError::Auth(format!("status {status}"))
        }
        StatusCode::NOT_FOUND => ShodanError::NotFound(format!("status {status}")),
        StatusCode::TOO_MANY_REQUESTS => ShodanError::RateLimited,
        StatusCode::PAYMENT_REQUIRED => ShodanError::PlanLimit(format!("status {status}")),
        s => ShodanError::Http(format!("status {s}")),
    }
}

/// Public-within-crate alias so `ShodanConfig` URL helpers can reuse the
/// same encoding logic without duplicating it.
pub(crate) fn urlencode_pub(s: &str) -> String {
    urlencode(s)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_basic() {
        assert_eq!(urlencode("abc"), "abc");
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn trim_ascii_works() {
        assert_eq!(trim_ascii(b"  hi\n"), b"hi");
        assert_eq!(trim_ascii(b""), b"");
    }

    #[test]
    fn from_env_empty_key_is_auth_error() {
        // Exercise the Auth-error path via the public helper that does not
        // need to touch the process environment (which would require `unsafe`
        // `set_var` in Rust 2024).
        let err = ShodanClient::from_api_key(String::new()).unwrap_err();
        assert!(matches!(err, ShodanError::Auth(_)));
        let err = ShodanClient::from_api_key("   ".to_owned()).unwrap_err();
        assert!(matches!(err, ShodanError::Auth(_)));
    }
}
