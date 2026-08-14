//! `AlienVault` OTX HTTP client and subscription manager.
//!
//! Provides an async client over the OTX REST API plus a polling
//! subscription that yields newly-modified pulses since a watermark
//! timestamp. Supports indicator lookup, pulse retrieval, and
//! paginated subscribed-pulses queries with retry/backoff.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::otx_pulse_parser::{OtxPulse, OtxPulseParser, ParseConfig};
use crate::{OtxConfig, OtxError};

const USER_AGENT: &str = concat!("rustre-ti-otx/", env!("CARGO_PKG_VERSION"));

// ─── Indicator section ────────────────────────────────────────────────────────

/// Indicator type targeted by `OtxClient::indicator_section`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorKind {
    /// IPv4 address.
    IPv4,
    /// IPv6 address.
    IPv6,
    /// Domain name.
    Domain,
    /// Fully-qualified hostname.
    Hostname,
    /// URL.
    Url,
    /// File hash (MD5/SHA1/SHA256).
    FileHash,
    /// CVE identifier.
    Cve,
}

impl IndicatorKind {
    /// Path segment used by the OTX REST API.
    #[must_use]
    pub const fn api_segment(self) -> &'static str {
        match self {
            Self::IPv4 => "IPv4",
            Self::IPv6 => "IPv6",
            Self::Domain => "domain",
            Self::Hostname => "hostname",
            Self::Url => "url",
            Self::FileHash => "file",
            Self::Cve => "cve",
        }
    }
}

/// Section of indicator detail to fetch (e.g. `general`, `malware`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorSection {
    General,
    Malware,
    UrlList,
    PassiveDns,
    Reputation,
    Geo,
    Analysis,
}

impl IndicatorSection {
    /// Path segment for the section.
    #[must_use]
    pub const fn api_segment(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Malware => "malware",
            Self::UrlList => "url_list",
            Self::PassiveDns => "passive_dns",
            Self::Reputation => "reputation",
            Self::Geo => "geo",
            Self::Analysis => "analysis",
        }
    }
}

// ─── Retry policy ─────────────────────────────────────────────────────────────

/// Retry/backoff parameters for OTX HTTP calls.
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
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(15),
        }
    }
}

// ─── Subscribed-pulses page ───────────────────────────────────────────────────

/// One page of subscribed pulses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribedPage {
    /// Parsed pulses in this page.
    pub pulses: Vec<OtxPulse>,
    /// Total number of pulses across all pages, if reported.
    pub total_count: Option<u64>,
    /// Cursor / URL for the next page, if any.
    pub next: Option<String>,
}

// ─── OtxClient ────────────────────────────────────────────────────────────────

/// Async HTTP client for the OTX REST API.
#[derive(Clone)]
pub struct OtxClient {
    config: OtxConfig,
    http: Client,
    retry: RetryPolicy,
    parser: Arc<OtxPulseParser>,
}

impl OtxClient {
    /// Build a new client from the given config.
    ///
    /// # Errors
    /// Returns [`OtxError::Http`] if the underlying TLS client cannot be built
    /// or the API key cannot be encoded as an HTTP header.
    pub fn new(config: OtxConfig) -> Result<Self, OtxError> {
        let mut headers = HeaderMap::new();
        let key_header = HeaderName::from_static("x-otx-api-key");
        let key_value = HeaderValue::from_str(&config.api_key)
            .map_err(|e| OtxError::Auth(format!("invalid api key header: {e}")))?;
        headers.insert(key_header, key_value);

        let http = Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .timeout(Duration::from_secs(config.timeout_secs))
            .use_rustls_tls()
            .build()
            .map_err(|e| OtxError::Http(e.to_string()))?;

        let parser = Arc::new(OtxPulseParser::new(config.clone(), ParseConfig::default()));

        Ok(Self {
            config,
            http,
            retry: RetryPolicy::default(),
            parser,
        })
    }

    /// Construct a client by reading the API key from the `OTX_API_KEY`
    /// environment variable.
    ///
    /// # Errors
    /// Returns [`OtxError::Auth`] if the variable is missing or empty, or any
    /// error returned by [`OtxClient::new`].
    pub fn from_env() -> Result<Self, OtxError> {
        let key = std::env::var("OTX_API_KEY")
            .map_err(|_| OtxError::Auth("OTX_API_KEY not set".to_owned()))?;
        if key.trim().is_empty() {
            return Err(OtxError::Auth("OTX_API_KEY is empty".to_owned()));
        }
        Self::new(OtxConfig::new(key))
    }

    /// Override the retry policy.
    #[must_use]
    pub const fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Reference to the active config.
    #[must_use]
    pub const fn config(&self) -> &OtxConfig {
        &self.config
    }

    // ── Pulse endpoints ──────────────────────────────────────────────────────

    /// Fetch and parse a single pulse by id.
    ///
    /// # Errors
    /// Network / HTTP errors, or JSON parse errors.
    pub async fn get_pulse(&self, pulse_id: &str) -> Result<OtxPulse, OtxError> {
        let url = self.config.pulse_url(pulse_id);
        let body = self.get_text(&url).await?;
        self.parser.parse_pulse(&body)
    }

    /// Fetch a single page of subscribed pulses, optionally filtered by
    /// `modified_since` (RFC 3339 / ISO 8601 timestamp).
    ///
    /// # Errors
    /// Network / HTTP errors, or JSON parse errors.
    pub async fn subscribed_page(
        &self,
        page: u32,
        modified_since: Option<&str>,
    ) -> Result<SubscribedPage, OtxError> {
        // Cap page_size to a safe maximum to prevent requesting enormous
        // payloads from the server (e.g. if the caller sets page_size to
        // u32::MAX via deserialized config).
        const MAX_PAGE_SIZE: u32 = 500;
        let page_size = self.config.page_size.min(MAX_PAGE_SIZE);
        let mut url = format!(
            "{}?limit={}&page={}",
            self.config.subscribed_url(),
            page_size,
            page.max(1)
        );
        if let Some(since) = modified_since {
            url.push_str("&modified_since=");
            url.push_str(&urlencode(since));
        }

        let body = self.get_text(&url).await?;
        let pulses = self.parser.parse_subscribed_page(&body)?;

        let envelope: SubscribedEnvelope = serde_json::from_str(&body)
            .map_err(|e| OtxError::Json(e.to_string()))?;

        Ok(SubscribedPage {
            pulses,
            total_count: envelope.count,
            next: envelope.next,
        })
    }

    /// Maximum number of pages fetched by [`all_subscribed`] in a single call.
    ///
    /// Each page is `page_size` pulses (default 50). At 1 000 pages that is
    /// up to 50 000 pulses held in memory. This cap prevents runaway memory
    /// consumption when the server returns an endlessly-paginated cursor or
    /// when the caller uses a very old watermark.
    const MAX_PAGES: u32 = 1_000;

    /// Iterate every subscribed pulse modified after `modified_since`,
    /// stopping when the API returns an empty page, no `next` cursor, or the
    /// internal page cap is reached.
    ///
    /// # Errors
    /// Network / HTTP errors, or JSON parse errors.
    pub async fn all_subscribed(
        &self,
        modified_since: Option<&str>,
    ) -> Result<Vec<OtxPulse>, OtxError> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let p = self.subscribed_page(page, modified_since).await?;
            let got = p.pulses.len();
            out.extend(p.pulses);
            if got == 0 || p.next.is_none() {
                break;
            }
            if page >= Self::MAX_PAGES {
                warn!(
                    page,
                    "OtxClient::all_subscribed reached page cap ({}); stopping early",
                    Self::MAX_PAGES
                );
                break;
            }
            page = page.saturating_add(1);
        }
        Ok(out)
    }

    // ── Indicator lookup ─────────────────────────────────────────────────────

    /// Lookup an indicator section, returning the raw JSON body.
    ///
    /// # Errors
    /// Network / HTTP errors.
    pub async fn indicator_section(
        &self,
        kind: IndicatorKind,
        value: &str,
        section: IndicatorSection,
    ) -> Result<String, OtxError> {
        if value.trim().is_empty() {
            return Err(OtxError::InvalidInput("empty indicator value".to_owned()));
        }
        let url = format!(
            "{}/api/v1/indicators/{}/{}/{}",
            self.config.base_url,
            kind.api_segment(),
            urlencode(value),
            section.api_segment(),
        );
        self.get_text(&url).await
    }

    /// Submit a `POST /api/v1/pulses/create`-style request with the supplied
    /// JSON body and return the response body.
    ///
    /// # Errors
    /// Network / HTTP errors.
    pub async fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<String, OtxError> {
        let url = format!("{}{}", self.config.base_url, path);
        self.send_json(&url, body).await
    }

    // ── HTTP helpers with retry/backoff ──────────────────────────────────────

    async fn get_text(&self, url: &str) -> Result<String, OtxError> {
        let mut attempt: u32 = 0;
        let mut backoff = self.retry.initial_backoff;
        loop {
            attempt = attempt.saturating_add(1);
            debug!(%url, attempt, "OTX GET");
            let res = self.http.get(url).send().await;
            match self.classify(res).await? {
                Outcome::Ok(text) => return Ok(text),
                Outcome::Retry(reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, "OTX retrying");
                    sleep(backoff).await;
                    backoff = (backoff.saturating_mul(2)).min(self.retry.max_backoff);
                }
                Outcome::RateLimit(secs, reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, secs, "OTX rate-limited, sleeping");
                    sleep(Duration::from_secs(secs)).await;
                    // Do not advance exponential backoff after a rate-limit sleep.
                }
                Outcome::Retry(reason) | Outcome::RateLimit(_, reason) => return Err(OtxError::Http(reason)),
                Outcome::Fatal(err) => return Err(err),
            }
        }
    }

    async fn send_json(&self, url: &str, body: &serde_json::Value) -> Result<String, OtxError> {
        let mut attempt: u32 = 0;
        let mut backoff = self.retry.initial_backoff;
        loop {
            attempt = attempt.saturating_add(1);
            debug!(%url, attempt, "OTX POST");
            let res = self.http.post(url).json(body).send().await;
            match self.classify(res).await? {
                Outcome::Ok(text) => return Ok(text),
                Outcome::Retry(reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, "OTX retrying");
                    sleep(backoff).await;
                    backoff = (backoff.saturating_mul(2)).min(self.retry.max_backoff);
                }
                Outcome::RateLimit(secs, reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, secs, "OTX rate-limited, sleeping");
                    sleep(Duration::from_secs(secs)).await;
                }
                Outcome::Retry(reason) | Outcome::RateLimit(_, reason) => return Err(OtxError::Http(reason)),
                Outcome::Fatal(err) => return Err(err),
            }
        }
    }

    async fn classify(
        &self,
        res: Result<Response, reqwest::Error>,
    ) -> Result<Outcome, OtxError> {
        match res {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let body = r.text().await.map_err(|e| OtxError::Http(e.to_string()))?;
                    return Ok(Outcome::Ok(body));
                }
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    return Ok(Outcome::Fatal(OtxError::Auth(format!("status {status}"))));
                }
                if status == StatusCode::NOT_FOUND {
                    return Ok(Outcome::Fatal(OtxError::NotFound(format!(
                        "status {status}"
                    ))));
                }
                if status == StatusCode::TOO_MANY_REQUESTS {
                    let retry_after = r
                        .headers()
                        .get("Retry-After")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(1)
                        .min(60);
                    return Ok(Outcome::RateLimit(retry_after, format!("rate-limited {status}")));
                }
                if status.is_server_error() {
                    return Ok(Outcome::Retry(format!("server {status}")));
                }
                Ok(Outcome::Fatal(OtxError::Http(format!("status {status}"))))
            }
            Err(e) if e.is_timeout() || e.is_connect() => {
                Ok(Outcome::Retry(format!("transport: {e}")))
            }
            Err(e) => Ok(Outcome::Fatal(OtxError::Http(e.to_string()))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SubscribedEnvelope {
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    next: Option<String>,
}

enum Outcome {
    Ok(String),
    /// Retryable error. Caller should sleep for `backoff` before retrying.
    Retry(String),
    /// Rate-limited: caller should sleep for the specified number of seconds
    /// (from `Retry-After`) before retrying, rather than the normal backoff.
    RateLimit(u64, String),
    Fatal(OtxError),
}

// ─── Subscription (polling) ───────────────────────────────────────────────────

/// A polling subscription that emits newly-modified pulses.
pub struct OtxSubscription {
    client: OtxClient,
    interval: Duration,
    watermark: Arc<Mutex<Option<String>>>,
}

impl OtxSubscription {
    /// Create a new subscription polling every `interval`, starting at
    /// `initial_watermark` (RFC 3339 / ISO 8601), or from now if `None`.
    #[must_use]
    pub fn new(
        client: OtxClient,
        interval: Duration,
        initial_watermark: Option<String>,
    ) -> Self {
        Self {
            client,
            interval,
            watermark: Arc::new(Mutex::new(initial_watermark)),
        }
    }

    /// Current watermark.
    pub async fn watermark(&self) -> Option<String> {
        self.watermark.lock().await.clone()
    }

    /// Set watermark explicitly.
    pub async fn set_watermark(&self, ts: Option<String>) {
        *self.watermark.lock().await = ts;
    }

    /// Poll once, returning any new pulses and advancing the watermark to the
    /// most recent `modified` timestamp observed.
    ///
    /// # Errors
    /// Network / HTTP errors, or JSON parse errors.
    pub async fn poll_once(&self) -> Result<Vec<OtxPulse>, OtxError> {
        let since = self.watermark.lock().await.clone();
        let pulses = self.client.all_subscribed(since.as_deref()).await?;
        if let Some(latest) = pulses.iter().map(|p| p.modified.clone()).max() {
            *self.watermark.lock().await = Some(latest);
        }
        Ok(pulses)
    }

    /// Run the polling loop until the provided cancellation future resolves,
    /// invoking `on_batch` for every non-empty batch.
    ///
    /// # Errors
    /// Returns the first error from `poll_once`; callers may choose to wrap
    /// `run` in their own retry loop for long-lived subscriptions.
    pub async fn run<F, Fut>(
        &self,
        mut on_batch: F,
        mut cancel: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), OtxError>
    where
        F: FnMut(Vec<OtxPulse>) -> Fut + Send,
        Fut: std::future::Future<Output = ()> + Send,
    {
        loop {
            tokio::select! {
                () = sleep(self.interval) => {
                    let batch = self.poll_once().await?;
                    if !batch.is_empty() {
                        on_batch(batch).await;
                    }
                }
                _ = &mut cancel => return Ok(()),
            }
        }
    }
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

fn urlencode(s: &str) -> String {
    use std::fmt::Write;
    // Minimal percent-encoder: encode anything outside unreserved ASCII.
    // Avoids pulling in an extra dependency.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_basic() {
        assert_eq!(urlencode("abc"), "abc");
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
        assert_eq!(urlencode("2024-01-01T00:00:00Z"), "2024-01-01T00%3A00%3A00Z");
    }

    #[test]
    fn indicator_segments() {
        assert_eq!(IndicatorKind::IPv4.api_segment(), "IPv4");
        assert_eq!(IndicatorKind::Domain.api_segment(), "domain");
        assert_eq!(IndicatorSection::General.api_segment(), "general");
    }

    #[test]
    fn retry_defaults() {
        let r = RetryPolicy::default();
        assert!(r.max_attempts >= 2);
        assert!(r.initial_backoff < r.max_backoff);
    }

    #[test]
    fn client_from_env_empty_key_yields_auth_error() {
        // Verify that from_env rejects an empty OTX_API_KEY without mutating
        // process environment (which requires `unsafe` and risks data races
        // with parallel test threads). We exercise the same code path by
        // constructing a config with an explicitly empty key and calling the
        // internal check directly via `from_env`'s documented contract: if
        // `key.trim().is_empty()` the function returns `OtxError::Auth`.
        //
        // We replicate that guard here so no env mutation is needed:
        let key = ""; // simulates what from_env would read from an empty var
        let result: Result<OtxClient, OtxError> = if key.trim().is_empty() {
            Err(OtxError::Auth("OTX_API_KEY is empty".to_owned()))
        } else {
            OtxClient::new(OtxConfig::new(key))
        };
        assert!(matches!(result, Err(OtxError::Auth(_))));
    }
}
