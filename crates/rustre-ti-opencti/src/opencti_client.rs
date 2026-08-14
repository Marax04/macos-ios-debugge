//! `OpenCTI` HTTP client — `GraphQL` push/pull plus STIX/TAXII 2.x collection
//! access. Async, built on `reqwest`/`tokio`, with retry/backoff and basic
//! auth handling.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::opencti_stix_mapper::StixBundle;
use crate::{OpenCtiConfig, OpenCtiError};

const USER_AGENT: &str = concat!("rustre-ti-opencti/", env!("CARGO_PKG_VERSION"));
const TAXII_ACCEPT: &str = "application/taxii+json;version=2.1";
const STIX_CONTENT: &str = "application/stix+json;version=2.1";

// ─── Retry policy ─────────────────────────────────────────────────────────────

/// Retry parameters for `OpenCTI` HTTP calls.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Maximum number of attempts.
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
            max_backoff: Duration::from_secs(20),
        }
    }
}

// ─── TAXII models ─────────────────────────────────────────────────────────────

/// TAXII 2.1 collection record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub can_read: bool,
    #[serde(default)]
    pub can_write: bool,
    #[serde(default)]
    pub media_types: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TaxiiCollectionsEnvelope {
    #[serde(default)]
    collections: Vec<TaxiiCollection>,
}

/// One page of TAXII envelope objects.
#[derive(Debug, Clone, Deserialize)]
pub struct TaxiiEnvelope {
    #[serde(default)]
    pub more: bool,
    #[serde(default)]
    pub next: Option<String>,
    #[serde(default)]
    pub objects: Vec<serde_json::Value>,
}

// ─── GraphQL ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct GraphQlRequest<'a> {
    query: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    variables: Option<&'a serde_json::Value>,
}

/// Raw GraphQL response.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphQlResponse {
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    #[serde(default)]
    pub errors: Option<Vec<serde_json::Value>>,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// Async `OpenCTI` client.
#[derive(Clone, Debug)]
pub struct OpenCtiClient {
    config: OpenCtiConfig,
    http: Client,
    retry: RetryPolicy,
}

impl OpenCtiClient {
    /// Build a new client.
    ///
    /// # Errors
    /// Returns [`OpenCtiError::Http`] if the TLS client cannot be built or the
    /// API token cannot be encoded as an HTTP header.
    pub fn new(config: OpenCtiConfig) -> Result<Self, OpenCtiError> {
        if config.api_token.trim().is_empty() {
            return Err(OpenCtiError::Auth("empty api token".to_owned()));
        }

        let bearer = format!("Bearer {}", config.api_token);
        let auth_value = HeaderValue::from_str(&bearer)
            .map_err(|e| OpenCtiError::Auth(format!("invalid token header: {e}")))?;

        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json"),
        );

        let http = Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_tls)
            .use_rustls_tls()
            .build()
            .map_err(|e| OpenCtiError::Http(e.to_string()))?;

        Ok(Self {
            config,
            http,
            retry: RetryPolicy::default(),
        })
    }

    /// Construct from `OPENCTI_URL` + `OPENCTI_TOKEN` environment variables.
    ///
    /// # Errors
    /// Returns [`OpenCtiError::Auth`] if either variable is missing/empty.
    pub fn from_env() -> Result<Self, OpenCtiError> {
        Self::from_env_getter(|k| std::env::var(k).ok())
    }

    /// Inner implementation that accepts a custom env-var getter; useful for
    /// testing without mutating the process environment.
    ///
    /// # Errors
    /// Returns [`OpenCtiError::Auth`] if the URL or token is missing or empty.
    pub(crate) fn from_env_getter(
        getter: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, OpenCtiError> {
        let url = getter("OPENCTI_URL")
            .ok_or_else(|| OpenCtiError::Auth("OPENCTI_URL not set".to_owned()))?;
        let token = getter("OPENCTI_TOKEN")
            .ok_or_else(|| OpenCtiError::Auth("OPENCTI_TOKEN not set".to_owned()))?;
        if url.trim().is_empty() || token.trim().is_empty() {
            return Err(OpenCtiError::Auth(
                "OPENCTI_URL or OPENCTI_TOKEN empty".to_owned(),
            ));
        }
        Self::new(OpenCtiConfig::new(url, token))
    }

    /// Override the retry policy.
    #[must_use]
    pub const fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Reference to the active config.
    #[must_use]
    pub const fn config(&self) -> &OpenCtiConfig {
        &self.config
    }

    // ── GraphQL push/pull ────────────────────────────────────────────────────

    /// Execute a GraphQL query/mutation against `{base}/graphql`.
    ///
    /// # Errors
    /// Network, HTTP, or GraphQL-side errors.
    pub async fn graphql(
        &self,
        query: &str,
        variables: Option<&serde_json::Value>,
    ) -> Result<GraphQlResponse, OpenCtiError> {
        let url = self.config.graphql_url();
        let req = GraphQlRequest { query, variables };
        let body = serde_json::to_value(&req)
            .map_err(|e| OpenCtiError::Serialization(e.to_string()))?;
        let text = self.send_json(&url, &body, None).await?;
        let parsed: GraphQlResponse =
            serde_json::from_str(&text).map_err(|e| OpenCtiError::Serialization(e.to_string()))?;
        if let Some(errs) = parsed.errors.as_ref().filter(|e| !e.is_empty()) {
            return Err(OpenCtiError::GraphQL(
                serde_json::to_string(errs).unwrap_or_else(|_| "<unprintable>".into()),
            ));
        }
        Ok(parsed)
    }

    /// Push a STIX bundle (e.g. produced by `StixMapper`) into `OpenCTI` via
    /// the platform's `/stix2` import endpoint.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn push_bundle(&self, bundle: &StixBundle) -> Result<(), OpenCtiError> {
        let url = format!(
            "{}/stix2",
            self.config.base_url.trim_end_matches('/')
        );
        let body = serde_json::to_value(bundle)
            .map_err(|e| OpenCtiError::Serialization(e.to_string()))?;
        let _ = self.send_json(&url, &body, Some(STIX_CONTENT)).await?;
        Ok(())
    }

    // ── TAXII 2.1 ────────────────────────────────────────────────────────────

    /// List collections at a TAXII root (e.g.
    /// `/taxii2/root/collections/`).
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn taxii_collections(
        &self,
        root_path: &str,
    ) -> Result<Vec<TaxiiCollection>, OpenCtiError> {
        let url = format!(
            "{}{}",
            self.config.base_url.trim_end_matches('/'),
            normalize_path(root_path)
        );
        let text = self.get_text(&url, Some(TAXII_ACCEPT)).await?;
        let env: TaxiiCollectionsEnvelope = serde_json::from_str(&text)
            .map_err(|e| OpenCtiError::Serialization(e.to_string()))?;
        Ok(env.collections)
    }

    /// Pull one page of objects from a TAXII collection.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors.
    pub async fn taxii_objects(
        &self,
        root_path: &str,
        collection_id: &str,
        added_after: Option<&str>,
        next: Option<&str>,
    ) -> Result<TaxiiEnvelope, OpenCtiError> {
        let mut url = format!(
            "{}{}collections/{}/objects/",
            self.config.base_url.trim_end_matches('/'),
            normalize_path(root_path),
            urlencode(collection_id),
        );
        let mut sep = '?';
        if let Some(a) = added_after {
            url.push(sep);
            url.push_str("added_after=");
            url.push_str(&urlencode(a));
            sep = '&';
        }
        if let Some(n) = next {
            url.push(sep);
            url.push_str("next=");
            url.push_str(&urlencode(n));
        }
        let text = self.get_text(&url, Some(TAXII_ACCEPT)).await?;
        serde_json::from_str(&text).map_err(|e| OpenCtiError::Serialization(e.to_string()))
    }

    /// Maximum number of pages fetched by [`Self::taxii_objects_all`] to
    /// prevent an infinite loop when a misbehaving server always returns
    /// `more: true`.
    const TAXII_MAX_PAGES: u32 = 10_000;

    /// Pull every page from a TAXII collection, returning a flat list.
    ///
    /// # Errors
    /// Network / HTTP / JSON errors, or [`OpenCtiError::InvalidInput`] if the
    /// server returns more than [`Self::TAXII_MAX_PAGES`] pages (likely a loop
    /// caused by a misbehaving server).
    pub async fn taxii_objects_all(
        &self,
        root_path: &str,
        collection_id: &str,
        added_after: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, OpenCtiError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        let mut pages: u32 = 0;
        loop {
            if pages >= Self::TAXII_MAX_PAGES {
                return Err(OpenCtiError::InvalidInput(format!(
                    "taxii_objects_all exceeded {0} pages — possible infinite pagination loop",
                    Self::TAXII_MAX_PAGES
                )));
            }
            pages = pages.saturating_add(1);
            let env = self
                .taxii_objects(root_path, collection_id, added_after, next.as_deref())
                .await?;
            out.extend(env.objects);
            if !env.more {
                break;
            }
            match env.next {
                Some(n) if !n.is_empty() => next = Some(n),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Push (publish) a STIX envelope of objects to a TAXII collection.
    ///
    /// # Errors
    /// Network / HTTP errors.
    pub async fn taxii_publish(
        &self,
        root_path: &str,
        collection_id: &str,
        objects: &[serde_json::Value],
    ) -> Result<(), OpenCtiError> {
        let url = format!(
            "{}{}collections/{}/objects/",
            self.config.base_url.trim_end_matches('/'),
            normalize_path(root_path),
            urlencode(collection_id),
        );
        let body = serde_json::json!({ "objects": objects });
        let _ = self.send_json(&url, &body, Some(TAXII_ACCEPT)).await?;
        Ok(())
    }

    // ── HTTP helpers with retry/backoff ──────────────────────────────────────

    async fn get_text(&self, url: &str, accept: Option<&str>) -> Result<String, OpenCtiError> {
        let mut attempt: u32 = 0;
        let mut backoff = self.retry.initial_backoff;
        loop {
            attempt = attempt.saturating_add(1);
            debug!(%url, attempt, "OpenCTI GET");
            let mut req = self.http.get(url);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            let res = req.send().await;
            match classify(res).await {
                Outcome::Ok(t) => return Ok(t),
                Outcome::Retry(reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, "OpenCTI retrying");
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(self.retry.max_backoff);
                }
                Outcome::Retry(reason) => return Err(OpenCtiError::Http(reason)),
                Outcome::Fatal(err) => return Err(err),
            }
        }
    }

    async fn send_json(
        &self,
        url: &str,
        body: &serde_json::Value,
        accept: Option<&str>,
    ) -> Result<String, OpenCtiError> {
        let mut attempt: u32 = 0;
        let mut backoff = self.retry.initial_backoff;
        loop {
            attempt = attempt.saturating_add(1);
            debug!(%url, attempt, "OpenCTI POST");
            let mut req = self.http.post(url).json(body);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            let res = req.send().await;
            match classify(res).await {
                Outcome::Ok(t) => return Ok(t),
                Outcome::Retry(reason) if attempt < self.retry.max_attempts => {
                    warn!(%url, attempt, %reason, "OpenCTI retrying");
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(self.retry.max_backoff);
                }
                Outcome::Retry(reason) => return Err(OpenCtiError::Http(reason)),
                Outcome::Fatal(err) => return Err(err),
            }
        }
    }
}

enum Outcome {
    Ok(String),
    Retry(String),
    Fatal(OpenCtiError),
}

async fn classify(res: Result<Response, reqwest::Error>) -> Outcome {
    match res {
        Ok(r) => {
            let status = r.status();
            if status.is_success() {
                return match r.text().await {
                    Ok(t) => Outcome::Ok(t),
                    Err(e) => Outcome::Fatal(OpenCtiError::Http(e.to_string())),
                };
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Outcome::Retry(format!("rate-limited {status}"));
            }
            if status.is_server_error() {
                return Outcome::Retry(format!("server {status}"));
            }
            Outcome::Fatal(map_status(status))
        }
        Err(e) if e.is_timeout() || e.is_connect() => Outcome::Retry(format!("transport: {e}")),
        Err(e) => Outcome::Fatal(OpenCtiError::Http(e.to_string())),
    }
}

fn map_status(status: StatusCode) -> OpenCtiError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            OpenCtiError::Auth(format!("status {status}"))
        }
        StatusCode::NOT_FOUND => OpenCtiError::NotFound(format!("status {status}")),
        s => OpenCtiError::Http(format!("status {s}")),
    }
}

fn normalize_path(p: &str) -> String {
    let mut s = String::with_capacity(p.len() + 2);
    if !p.starts_with('/') {
        s.push('/');
    }
    s.push_str(p);
    if !s.ends_with('/') {
        s.push('/');
    }
    s
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_wraps() {
        assert_eq!(normalize_path("taxii2/root"), "/taxii2/root/");
        assert_eq!(normalize_path("/taxii2/root/"), "/taxii2/root/");
    }

    #[test]
    fn urlencode_basic() {
        assert_eq!(urlencode("abc"), "abc");
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn from_env_missing() {
        // Use the testable getter path — no env mutation needed.
        let err = OpenCtiClient::from_env_getter(|_| None).unwrap_err();
        assert!(matches!(err, OpenCtiError::Auth(_)));
    }

    #[test]
    fn from_env_empty_values() {
        let err = OpenCtiClient::from_env_getter(|_| Some(String::new())).unwrap_err();
        assert!(matches!(err, OpenCtiError::Auth(_)));
    }

    #[test]
    fn rejects_empty_token() {
        let cfg = OpenCtiConfig::new("https://example.com", "");
        let err = OpenCtiClient::new(cfg).unwrap_err();
        assert!(matches!(err, OpenCtiError::Auth(_)));
    }
}
