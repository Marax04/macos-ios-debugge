//! High-level threat intelligence abstractions: [`IntelProvider`] trait,
//! [`IntelReport`] struct, concrete provider wrappers, and the
//! [`IocExtractor`] static helper methods.
//!
//! This module complements the lower-level [`crate::provider::TiProvider`]
//! machinery with a simpler, uniform interface suitable for quick enrichment
//! pipelines.  Both the `VirusTotal` and `MalwareBazaar` backends are exposed as
//! [`IntelProvider`] implementations, and [`query_all_providers`] fans out
//! queries concurrently using `futures::future::join_all`.
//!
//! # Example
//!
//! ```rust,no_run
//! # use rustre_threatintel::intel::{
//! #     IntelProvider, VirusTotalIntelClient, MalwareBazaarIntelClient,
//! #     query_all_providers, IocExtractor,
//! # };
//! # #[tokio::main] async fn main() {
//! let vt  = VirusTotalIntelClient::new("MY_VT_KEY");
//! let mbz = MalwareBazaarIntelClient::new();
//! let providers: Vec<Box<dyn IntelProvider>> = vec![Box::new(vt), Box::new(mbz)];
//! let reports = query_all_providers(
//!     "44d88612fea8a8f36de82e1278abb02f",
//!     &providers.iter().map(|p| p.as_ref()).collect::<Vec<_>>(),
//! ).await;
//! for r in reports {
//!     println!("{}: malicious={}", r.source, r.malicious);
//! }
//! # }
//! ```

use std::collections::HashSet;

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::TiError;

// ─────────────────────────────────────────────────────────────────────────────
// IntelReport
// ─────────────────────────────────────────────────────────────────────────────

/// A normalised intelligence report produced by an [`IntelProvider`].
///
/// All providers map their raw responses into this common shape so callers can
/// aggregate results without knowing which backend produced each entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntelReport {
    /// Human-readable name of the provider that created this report.
    pub source: String,

    /// SHA-256 hash of the artefact (if returned by the provider).
    pub sha256: Option<String>,

    /// `true` when the provider classifies the sample as malicious.
    pub malicious: bool,

    /// Number of detection engines / data sources that flagged the sample.
    pub detections: u32,

    /// Total number of engines / data sources consulted.
    pub total_engines: u32,

    /// Malware family name (e.g. `"Emotet"`, `"QakBot"`), if identified.
    pub family: Option<String>,

    /// Classification tags (e.g. `"ransomware"`, `"banker"`, `"trojan"`).
    pub tags: Vec<String>,

    /// Unix epoch timestamp of the earliest known observation.
    pub first_seen: Option<u64>,

    /// Provider confidence in the verdict, in the range `[0.0, 1.0]`.
    ///
    /// This is derived from the detection ratio: `detections / total_engines`
    /// when engine counts are available, or from a provider-specific heuristic
    /// otherwise.
    pub confidence: f32,
}

impl IntelReport {
    /// Create a minimal report with just a source and verdict.
    #[must_use]
    pub fn new(source: impl Into<String>, malicious: bool) -> Self {
        Self {
            source: source.into(),
            sha256: None,
            malicious,
            detections: 0,
            total_engines: 0,
            family: None,
            tags: Vec::new(),
            first_seen: None,
            confidence: 0.0,
        }
    }

    /// Compute the detection ratio as a value in `[0.0, 1.0]`.
    #[must_use]
    pub fn detection_ratio(&self) -> f32 {
        if self.total_engines == 0 {
            self.confidence
        } else {
            crate::casts::f64_to_f32(f64::from(self.detections) / f64::from(self.total_engines))
        }
    }

    /// Return `true` when the detection ratio exceeds the given threshold.
    #[must_use]
    pub fn exceeds_threshold(&self, threshold: f32) -> bool {
        self.detection_ratio() >= threshold
    }
}

impl std::fmt::Display for IntelReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] malicious={} detections={}/{} confidence={:.2} family={}",
            self.source,
            self.malicious,
            self.detections,
            self.total_engines,
            self.confidence,
            self.family.as_deref().unwrap_or("unknown"),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IntelProvider trait
// ─────────────────────────────────────────────────────────────────────────────

/// Async trait for threat intelligence backends.
///
/// Implementors provide hash and IP lookups returning a normalised
/// [`IntelReport`] (or `None` when the indicator is not in the provider's
/// database).
///
/// # Implementing `IntelProvider`
///
/// ```rust,no_run
/// # use async_trait::async_trait;
/// # use rustre_threatintel::intel::{IntelProvider, IntelReport};
/// # use rustre_threatintel::error::TiError;
/// struct MockProvider;
///
/// #[async_trait]
/// impl IntelProvider for MockProvider {
///     fn name(&self) -> &str { "mock" }
///
///     async fn query_hash(&self, hash: &str) -> Result<Option<IntelReport>, TiError> {
///         if hash == "deadbeef" {
///             Ok(Some(IntelReport::new("mock", true)))
///         } else {
///             Ok(None)
///         }
///     }
///
///     async fn query_ip(&self, _ip: &str) -> Result<Option<IntelReport>, TiError> {
///         Ok(None)
///     }
/// }
/// ```
#[async_trait]
pub trait IntelProvider: Send + Sync {
    /// Short identifier for this provider (e.g. `"virustotal"`, `"malwarebazaar"`).
    fn name(&self) -> &str;

    /// Query the provider for a file hash (MD5, SHA-1 or SHA-256).
    ///
    /// Returns `Ok(None)` when the hash is absent from the provider's database.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP, rate-limit, or parse failures.
    async fn query_hash(&self, hash: &str) -> Result<Option<IntelReport>, TiError>;

    /// Query the provider for an IP address.
    ///
    /// Returns `Ok(None)` when the IP is not in the provider's database.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP, rate-limit, or parse failures.
    async fn query_ip(&self, ip: &str) -> Result<Option<IntelReport>, TiError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// VirusTotalIntelClient
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight [`IntelProvider`] wrapper around the `VirusTotal` API v3.
///
/// Uses only the `/files/{hash}` and `/ip_addresses/{ip}` endpoints.  For
/// the full `VirusTotal` feature set (URL reports, domain reports, bulk lookups,
/// YARA hits, …) use [`crate::virustotal::VirusTotalClient`] directly.
pub struct VirusTotalIntelClient {
    api_key: String,
    http: reqwest::Client,
    base_url: String,
}

impl VirusTotalIntelClient {
    const VT_BASE: &'static str = "https://www.virustotal.com/api/v3";

    /// Create a new client authenticated with the given API key.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            http: reqwest::Client::new(),
            base_url: Self::VT_BASE.to_owned(),
        }
    }

    /// Override the base URL (useful for unit tests against a mock server).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Parse a `VirusTotal` `/files/{hash}` or `/ip_addresses/{ip}` response into
    /// an [`IntelReport`].
    fn parse_response(
        &self,
        body: &serde_json::Value,
        _ioc_key: &str,
    ) -> Result<IntelReport, TiError> {
        // Clamp to u32 with a sane maximum so overflow never produces wildly wrong values.
        const MAX_ENGINE_COUNT: u64 = 100_000;
        let data = body
            .get("data")
            .ok_or_else(|| TiError::Parse("missing `data` key".into()))?;

        let attrs = data
            .get("attributes")
            .ok_or_else(|| TiError::Parse("missing `attributes` key".into()))?;

        let stats = attrs.get("last_analysis_stats");

        let malicious: u64 = stats.and_then(|s| s.get("malicious")).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let suspicious: u64 = stats.and_then(|s| s.get("suspicious")).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let harmless: u64 = stats.and_then(|s| s.get("harmless")).and_then(serde_json::Value::as_u64).unwrap_or(0);
        let undetected: u64 = stats.and_then(|s| s.get("undetected")).and_then(serde_json::Value::as_u64).unwrap_or(0);

        // Saturating, not wrapping: the addends come straight from the remote
        // JSON and are unbounded, so a plain `+` wraps to a SMALL value that
        // then passes `.min(MAX_ENGINE_COUNT)` untouched — turning a maximally
        // malicious report into a clean one. Saturating first is what makes the
        // clamp below mean what its comment says.
        let detections_u64 = malicious.saturating_add(suspicious);
        let total_engines_u64 = malicious
            .saturating_add(suspicious)
            .saturating_add(harmless)
            .saturating_add(undetected);

        let confidence = if total_engines_u64 > 0 {
            crate::casts::f64_to_f32(crate::casts::u64_to_f64(detections_u64) / crate::casts::u64_to_f64(total_engines_u64))
        } else {
            0.0
        };

        let detections = u32::try_from(detections_u64.min(MAX_ENGINE_COUNT)).unwrap_or(u32::MAX);
        let total_engines = u32::try_from(total_engines_u64.min(MAX_ENGINE_COUNT)).unwrap_or(u32::MAX);

        let sha256 = attrs
            .get("sha256")
            .and_then(|v| v.as_str())
            .map(std::borrow::ToOwned::to_owned);

        let tags: Vec<String> = attrs
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str())
                    .map(std::borrow::ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        let first_seen = attrs.get("first_submission_date").and_then(serde_json::Value::as_u64);

        let is_malicious = detections > 0 && confidence > 0.05;

        Ok(IntelReport {
            source: self.name().to_owned(),
            sha256,
            malicious: is_malicious,
            detections,
            total_engines,
            family: None,
            tags,
            first_seen,
            confidence,
        })
    }
}

#[async_trait]
impl IntelProvider for VirusTotalIntelClient {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    /// Query `VirusTotal` for a file hash (MD5, SHA-1 or SHA-256).
    ///
    /// Returns `Ok(None)` for 404 responses (unknown hash).
    async fn query_hash(&self, hash: &str) -> Result<Option<IntelReport>, TiError> {
        let url = format!("{}/files/{}", self.base_url, hash);
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| TiError::Http(e.to_string()))?;

        match resp.status().as_u16() {
            404 => return Ok(None),
            429 => return Err(TiError::RateLimit("virustotal".into())),
            401 | 403 => return Err(TiError::InvalidApiKey("virustotal".into())),
            s if s >= 400 => {
                return Err(TiError::Http(format!("VirusTotal HTTP {s}")));
            }
            _ => {}
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;

        self.parse_response(&body, hash).map(Some)
    }

    /// Query `VirusTotal` for an IP address report.
    ///
    /// Returns `Ok(None)` for 404 responses (unknown IP).
    async fn query_ip(&self, ip: &str) -> Result<Option<IntelReport>, TiError> {
        let url = format!("{}/ip_addresses/{}", self.base_url, ip);
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| TiError::Http(e.to_string()))?;

        match resp.status().as_u16() {
            404 => return Ok(None),
            429 => return Err(TiError::RateLimit("virustotal".into())),
            401 | 403 => return Err(TiError::InvalidApiKey("virustotal".into())),
            s if s >= 400 => {
                return Err(TiError::Http(format!("VirusTotal HTTP {s}")));
            }
            _ => {}
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;

        self.parse_response(&body, ip).map(Some)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MalwareBazaarIntelClient
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight [`IntelProvider`] wrapper around the `MalwareBazaar` API.
///
/// `MalwareBazaar` does not require an API key.  This client only supports hash
/// lookups (`query_hash`); `query_ip` always returns `Ok(None)` because the
/// `MalwareBazaar` API does not expose an IP lookup endpoint.
pub struct MalwareBazaarIntelClient {
    http: reqwest::Client,
    api_url: String,
}

impl MalwareBazaarIntelClient {
    const MB_URL: &'static str = "https://mb-api.abuse.ch/api/v1/";

    /// Create a new client using the default `MalwareBazaar` endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            api_url: Self::MB_URL.to_owned(),
        }
    }

    /// Override the API endpoint (useful for unit tests against a mock server).
    #[must_use]
    pub fn with_api_url(mut self, url: impl Into<String>) -> Self {
        self.api_url = url.into();
        self
    }
}

impl Default for MalwareBazaarIntelClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IntelProvider for MalwareBazaarIntelClient {
    fn name(&self) -> &'static str {
        "malwarebazaar"
    }

    /// Query `MalwareBazaar` for a file hash.
    ///
    /// Returns `Ok(None)` when the hash is absent from the database.
    ///
    /// Parses the response JSON and extracts:
    /// - `data[0].signature` as the malware family name
    /// - `data[0].tags` as classification tags
    /// - `data[0].first_seen` (ISO-8601 string, converted to epoch via simple heuristic)
    async fn query_hash(&self, hash: &str) -> Result<Option<IntelReport>, TiError> {
        let params = [("query", "get_info"), ("hash", hash)];
        let resp = self
            .http
            .post(&self.api_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| TiError::Http(e.to_string()))?;

        if resp.status() == 429 {
            return Err(TiError::RateLimit("malwarebazaar".into()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!(
                "MalwareBazaar HTTP {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;

        let query_status = body
            .get("query_status")
            .and_then(|v| v.as_str())
            .unwrap_or("error");

        if query_status != "ok" {
            return Ok(None);
        }

        let data = match body.get("data").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => &arr[0],
            _ => return Ok(None),
        };

        let family = data
            .get("signature")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(std::borrow::ToOwned::to_owned);

        let tags: Vec<String> = data
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str())
                    .map(std::borrow::ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        let sha256 = data
            .get("sha256_hash")
            .and_then(|v| v.as_str())
            .map(std::borrow::ToOwned::to_owned);

        // MalwareBazaar returns first_seen as "YYYY-MM-DD HH:MM:SS"; we do a
        // rough epoch conversion (good enough for display/sorting purposes).
        let first_seen = data
            .get("first_seen")
            .and_then(|v| v.as_str())
            .and_then(parse_mbz_datetime);

        // MalwareBazaar reports a known malware signature → classify as malicious.
        let malicious = family.is_some() || !tags.is_empty();

        // Confidence heuristic: high when signature is known, moderate otherwise.
        let confidence = if family.is_some() {
            0.85
        } else if !tags.is_empty() {
            0.50
        } else {
            0.10
        };

        Ok(Some(IntelReport {
            source: self.name().to_owned(),
            sha256,
            malicious,
            detections: u32::from(malicious),
            total_engines: 1,
            family,
            tags,
            first_seen,
            confidence,
        }))
    }

    /// `MalwareBazaar` does not expose an IP lookup endpoint; always returns
    /// `Ok(None)`.
    async fn query_ip(&self, _ip: &str) -> Result<Option<IntelReport>, TiError> {
        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// query_all_providers
// ─────────────────────────────────────────────────────────────────────────────

/// Query every provider concurrently for a file hash and collect successful
/// reports.
///
/// Providers that return `Ok(None)` (hash unknown) or an `Err` (network
/// failure, rate limit, …) are silently skipped.  Use this function when you
/// want a best-effort enrichment from all available backends without failing
/// the entire pipeline on a single provider error.
///
/// # Concurrency
///
/// All provider queries are submitted simultaneously using
/// `futures::future::join_all`, so the total latency is bounded by the
/// slowest single provider rather than the sum of all providers.
///
/// # Example
///
/// ```rust,no_run
/// # use rustre_threatintel::intel::{
/// #     query_all_providers, VirusTotalIntelClient, MalwareBazaarIntelClient, IntelProvider,
/// # };
/// # #[tokio::main] async fn main() {
/// let providers: Vec<Box<dyn IntelProvider>> = vec![
///     Box::new(VirusTotalIntelClient::new("KEY")),
///     Box::new(MalwareBazaarIntelClient::new()),
/// ];
/// let refs: Vec<&dyn IntelProvider> = providers.iter().map(|p| p.as_ref()).collect();
/// let reports = query_all_providers("44d88612fea8a8f36de82e1278abb02f", &refs).await;
/// println!("Got {} reports", reports.len());
/// # }
/// ```
pub async fn query_all_providers(hash: &str, providers: &[&dyn IntelProvider]) -> Vec<IntelReport> {
    // Build a future for each provider's hash query.
    let futures: Vec<_> = providers.iter().map(|p| p.query_hash(hash)).collect();

    // Run all queries concurrently and collect non-None, non-error results.
    futures::future::join_all(futures)
        .await
        .into_iter()
        .filter_map(|result| match result {
            Ok(Some(report)) => Some(report),
            Ok(None) | Err(_) => None,
        })
        .collect()
}

/// Query every provider concurrently for an IP address and collect successful
/// reports.
///
/// Providers that return `Ok(None)` or `Err` are silently skipped.
pub async fn query_ip_all_providers(
    ip: &str,
    providers: &[&dyn IntelProvider],
) -> Vec<IntelReport> {
    let futures: Vec<_> = providers.iter().map(|p| p.query_ip(ip)).collect();

    futures::future::join_all(futures)
        .await
        .into_iter()
        .filter_map(|result| match result {
            Ok(Some(report)) => Some(report),
            Ok(None) | Err(_) => None,
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// IocExtractor — static / free-function helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Static `IoC` extraction helpers.
///
/// These free functions complement the full [`crate::ioc_extractor::IocExtractor`]
/// struct API with simple, self-contained methods that compile their regexes
/// lazily.  They are intended for one-shot extractions where constructing and
/// holding a long-lived `IocExtractor` instance is inconvenient.
///
/// # `IoC` Defanging
///
/// Threat reports often "defang" `IoCs` to prevent accidental clicking.  The
/// [`IocExtractor::defang`] and [`IocExtractor::refang`] helpers convert
/// between live and defanged representations.
pub struct IocExtractor;

impl IocExtractor {
    // ── IPv4 ────────────────────────────────────────────────────────────────

    /// Extract routable IPv4 addresses from `text`.
    ///
    /// Private / link-local / loopback ranges are filtered out:
    ///
    /// | Range          | Description               |
    /// |----------------|---------------------------|
    /// | `0.0.0.0/8`    | "This" network            |
    /// | `127.x.x.x`    | Loopback                  |
    /// | `10.x.x.x`     | Private class A           |
    /// | `192.168.x.x`  | Private class C           |
    /// | `172.16–31.x.x`| Private class B           |
    ///
    /// ```rust
    /// use rustre_threatintel::intel::IocExtractor;
    ///
    /// let ips = IocExtractor::extract_ipv4("C2 server at 185.220.101.1; internal 10.0.0.1");
    /// assert_eq!(ips, vec!["185.220.101.1"]);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the internal regex fails to compile (this is a bug and should
    /// never happen in practice).
    #[must_use]
    pub fn extract_ipv4(text: &str) -> Vec<String> {
        // Lazily compiled regex — avoids re-compiling on every call while still
        // being a free function (no constructor required).
        use std::sync::OnceLock;
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(
                r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b",
            )
            .expect("ipv4 regex")
        });

        let mut seen = HashSet::new();
        let mut out = Vec::new();

        for caps in re.captures_iter(text) {
            let ip = caps[1].to_owned();
            if is_private_ipv4(&ip) {
                continue;
            }
            if seen.insert(ip.clone()) {
                out.push(ip);
            }
        }
        out
    }

    // ── Domain names ────────────────────────────────────────────────────────

    /// Extract fully-qualified domain names with recognised TLDs from `text`.
    ///
    /// Common TLDs are matched: `com`, `net`, `org`, `io`, `ru`, `cn`, `de`,
    /// `uk`, `fr`, `br`, `info`, `biz`, `co`, `me`, `xyz`, `top`, `site`,
    /// `online`, `store`, `shop`, `club`, `pro`, `app`, `dev`, `tech`, `ai`,
    /// `cloud`, `gov`, `edu`, `mil`, `int`.
    ///
    /// Results are lowercased and deduplicated.
    ///
    /// ```rust
    /// use rustre_threatintel::intel::IocExtractor;
    ///
    /// let domains = IocExtractor::extract_domains("beacon to evil.example.com and cdn.ok.io");
    /// assert!(domains.iter().any(|d| d == "evil.example.com"));
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the internal regex fails to compile (this is a bug and should
    /// never happen in practice).
    #[must_use]
    pub fn extract_domains(text: &str) -> Vec<String> {
        use std::sync::OnceLock;
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(
                r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|fr|br|info|biz|co|me|xyz|top|site|online|store|shop|club|pro|app|dev|tech|ai|cloud|gov|edu|mil|int)\b"
            ).expect("domain regex")
        });

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for m in re.find_iter(text) {
            let d = m.as_str().to_lowercase();
            if seen.insert(d.clone()) {
                out.push(d);
            }
        }
        out
    }

    // ── File hashes ─────────────────────────────────────────────────────────

    /// Extract SHA-256 hashes (64 lowercase hex characters) from `text`.
    ///
    /// Strings that are exactly 128 hex characters (SHA-512) are excluded to
    /// avoid partial SHA-512 matches being classified as SHA-256.
    ///
    /// ```rust
    /// use rustre_threatintel::intel::IocExtractor;
    ///
    /// let hashes = IocExtractor::extract_sha256(
    ///     "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// assert_eq!(hashes.len(), 1);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the internal regex fails to compile (this is a bug and should
    /// never happen in practice).
    #[must_use]
    pub fn extract_sha256(text: &str) -> Vec<String> {
        use std::sync::OnceLock;
        static RE_256: OnceLock<Regex> = OnceLock::new();
        static RE_512: OnceLock<Regex> = OnceLock::new();

        let re256 =
            RE_256.get_or_init(|| Regex::new(r"(?i)\b[0-9a-fA-F]{64}\b").expect("sha256 regex"));
        let re512 =
            RE_512.get_or_init(|| Regex::new(r"(?i)\b[0-9a-fA-F]{128}\b").expect("sha512 regex"));

        // Collect SHA-512s first so we can filter them out.
        let sha512: HashSet<String> = re512
            .find_iter(text)
            .map(|m| m.as_str().to_lowercase())
            .collect();

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for m in re256.find_iter(text) {
            let h = m.as_str().to_lowercase();
            if sha512.contains(&h) {
                continue;
            }
            if seen.insert(h.clone()) {
                out.push(h);
            }
        }
        out
    }

    /// Extract MD5 hashes (32 lowercase hex characters) from `text`.
    ///
    /// Strings that are 40, 64, or 128 hex characters (SHA-1, SHA-256,
    /// SHA-512) are excluded to avoid false positives.
    ///
    /// ```rust
    /// use rustre_threatintel::intel::IocExtractor;
    ///
    /// let hashes = IocExtractor::extract_md5("md5: d41d8cd98f00b204e9800998ecf8427e");
    /// assert_eq!(hashes.len(), 1);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the internal regex fails to compile (this is a bug and should
    /// never happen in practice).
    #[must_use]
    pub fn extract_md5(text: &str) -> Vec<String> {
        use std::sync::OnceLock;
        static RE_MD5: OnceLock<Regex> = OnceLock::new();
        static RE_LONGER: OnceLock<Regex> = OnceLock::new();

        let re_md5 =
            RE_MD5.get_or_init(|| Regex::new(r"(?i)\b[0-9a-fA-F]{32}\b").expect("md5 regex"));
        // Anything longer that starts with a 32-char run is not an MD5.
        let re_longer = RE_LONGER
            .get_or_init(|| Regex::new(r"(?i)\b[0-9a-fA-F]{40,}\b").expect("longer-hash regex"));

        let longer: HashSet<String> = re_longer
            .find_iter(text)
            .map(|m| {
                // Grab the first 32 chars as a potential overlap check.
                m.as_str().to_lowercase()
            })
            .collect();

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for m in re_md5.find_iter(text) {
            let h = m.as_str().to_lowercase();
            // Reject if any longer hash *contains* this 32-char string.
            if longer.iter().any(|l| l.starts_with(h.as_str())) {
                continue;
            }
            if seen.insert(h.clone()) {
                out.push(h);
            }
        }
        out
    }

    // ── Defang / refang ─────────────────────────────────────────────────────

    /// Defang an `IoC` string so it cannot be accidentally followed as a link or
    /// resolved by a DNS client.
    ///
    /// The following substitutions are applied (in order):
    ///
    /// | Original | Defanged |
    /// |----------|---------|
    /// | `.`      | `[.]`   |
    /// | `://`    | `[://]` |
    ///
    /// Note: `://` is replaced *before* `.` so that `http://` becomes
    /// `http[://]` rather than `http[://]` with extra dots.
    ///
    /// ```rust
    /// use rustre_threatintel::intel::IocExtractor;
    ///
    /// assert_eq!(IocExtractor::defang("http://evil.example.com"), "http[://]evil[.]example[.]com");
    /// assert_eq!(IocExtractor::defang("8.8.8.8"), "8[.]8[.]8[.]8");
    /// ```
    #[must_use]
    pub fn defang(ioc: &str) -> String {
        ioc.replace("://", "[://]").replace('.', "[.]")
    }

    /// Refang a previously defanged `IoC` string, restoring it to its original
    /// form.
    ///
    /// This is the inverse of [`IocExtractor::defang`]:
    ///
    /// | Defanged | Refanged |
    /// |---------|---------|
    /// | `[://]` | `://`   |
    /// | `[.]`   | `.`     |
    ///
    /// ```rust
    /// use rustre_threatintel::intel::IocExtractor;
    ///
    /// assert_eq!(
    ///     IocExtractor::refang("http[://]evil[.]example[.]com"),
    ///     "http://evil.example.com"
    /// );
    /// assert_eq!(IocExtractor::refang("8[.]8[.]8[.]8"), "8.8.8.8");
    /// ```
    #[must_use]
    pub fn refang(ioc: &str) -> String {
        ioc.replace("[://]", "://").replace("[.]", ".")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return `true` when `ip` is in a private, link-local, or loopback range.
///
/// Filtered ranges:
/// - `0.0.0.0/8`      — "this" network
/// - `10.x.x.x`       — private class A (RFC 1918)
/// - `127.x.x.x`      — loopback (RFC 5735)
/// - `169.254.x.x`    — link-local (RFC 3927)
/// - `172.16–31.x.x`  — private class B (RFC 1918)
/// - `192.168.x.x`    — private class C (RFC 1918)
fn is_private_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse::<u8>().ok()).collect();
    if octets.len() != 4 {
        return false;
    }
    match octets[0] {
        0 | 10 | 127 => true,
        169 if octets[1] == 254 => true,
        172 if (16..=31).contains(&octets[1]) => true,
        192 if octets[1] == 168 => true,
        _ => false,
    }
}

/// Parse a `MalwareBazaar` datetime string of the form `"YYYY-MM-DD HH:MM:SS"`
/// into a Unix epoch timestamp.
///
/// Returns `None` if the string does not match the expected format.
fn parse_mbz_datetime(s: &str) -> Option<u64> {
    // Expected format: "2023-04-15 13:22:01"
    let parts: Vec<&str> = s.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<u32> = parts[0]
        .split('-')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    let time_parts: Vec<u32> = parts[1]
        .split(':')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();

    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }

    let year = u64::from(date_parts[0]);
    let month = u64::from(date_parts[1]);
    let day = u64::from(date_parts[2]);
    let hour = u64::from(time_parts[0]);
    let min = u64::from(time_parts[1]);
    let sec = u64::from(time_parts[2]);

    // Days since Unix epoch (1970-01-01) via a simplified Gregorian formula.
    let days = days_since_epoch(year, month, day)?;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Compute the number of days elapsed since 1970-01-01 for the given date.
fn days_since_epoch(year: u64, month: u64, day: u64) -> Option<u64> {
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Shift to a March-based year for easier leap-year handling.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };

    let era = y / 400;
    let yoe = y % 400; // year-of-era [0, 399]
    let doy = (153 * m + 2) / 5 + day - 1; // day-of-year [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day-of-era [0, 146096]
    let days_from_0000 = era * 146_097 + doe;

    // Days from 0000-03-01 to 1970-01-01 = 719468
    Some(days_from_0000.saturating_sub(719_468))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IntelReport ──────────────────────────────────────────────────────────

    #[test]
    fn test_report_new_defaults() {
        let r = IntelReport::new("test", false);
        assert_eq!(r.source, "test");
        assert!(!r.malicious);
        assert_eq!(r.detections, 0);
        assert_eq!(r.total_engines, 0);
        assert!(r.family.is_none());
        assert!(r.tags.is_empty());
        assert!(r.first_seen.is_none());
        assert!((r.confidence - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_report_detection_ratio_no_engines() {
        let mut r = IntelReport::new("test", false);
        r.confidence = 0.75;
        // Falls back to confidence when total_engines == 0
        assert!((r.detection_ratio() - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_report_detection_ratio_with_engines() {
        let r = IntelReport {
            source: "vt".into(),
            sha256: None,
            malicious: true,
            detections: 30,
            total_engines: 60,
            family: None,
            tags: vec![],
            first_seen: None,
            confidence: 0.5,
        };
        assert!((r.detection_ratio() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_report_exceeds_threshold_true() {
        let r = IntelReport {
            source: "vt".into(),
            sha256: None,
            malicious: true,
            detections: 40,
            total_engines: 70,
            family: None,
            tags: vec![],
            first_seen: None,
            confidence: 0.57,
        };
        assert!(r.exceeds_threshold(0.5));
        assert!(!r.exceeds_threshold(0.9));
    }

    #[test]
    fn test_report_display() {
        let r = IntelReport::new("mock", true);
        let s = r.to_string();
        assert!(s.contains("mock"));
        assert!(s.contains("true"));
    }

    #[test]
    fn test_report_serialization_round_trip() {
        let r = IntelReport {
            source: "virustotal".into(),
            sha256: Some("abc123".into()),
            malicious: true,
            detections: 5,
            total_engines: 70,
            family: Some("Emotet".into()),
            tags: vec!["banker".into()],
            first_seen: Some(1_700_000_000),
            confidence: 0.07,
        };
        let json = serde_json::to_string(&r).unwrap();
        let decoded: IntelReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    // ── IocExtractor::extract_ipv4 ───────────────────────────────────────────

    #[test]
    fn test_extract_ipv4_public() {
        let ips = IocExtractor::extract_ipv4("C2 server 185.220.101.45");
        assert_eq!(ips, vec!["185.220.101.45"]);
    }

    #[test]
    fn test_extract_ipv4_filters_private() {
        let ips = IocExtractor::extract_ipv4("10.0.0.1 and 192.168.1.100 and 172.20.0.1");
        assert!(ips.is_empty(), "private IPs should be filtered: {ips:?}");
    }

    #[test]
    fn test_extract_ipv4_filters_loopback() {
        let ips = IocExtractor::extract_ipv4("127.0.0.1 is loopback");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_extract_ipv4_filters_zero_network() {
        let ips = IocExtractor::extract_ipv4("0.0.0.1 is reserved");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_extract_ipv4_dedup() {
        let ips = IocExtractor::extract_ipv4("8.8.8.8 beacon and 8.8.8.8 again");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "8.8.8.8");
    }

    #[test]
    fn test_extract_ipv4_multiple_public() {
        let ips = IocExtractor::extract_ipv4("1.1.1.1 and 8.8.4.4 are DNS servers");
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.1.1.1".to_owned()));
        assert!(ips.contains(&"8.8.4.4".to_owned()));
    }

    // ── IocExtractor::extract_domains ────────────────────────────────────────

    #[test]
    fn test_extract_domains_basic() {
        let domains = IocExtractor::extract_domains("contacted evil.example.com");
        assert!(domains.iter().any(|d| d == "evil.example.com"));
    }

    #[test]
    fn test_extract_domains_lowercased() {
        let domains = IocExtractor::extract_domains("EVIL.EXAMPLE.COM");
        assert!(domains.iter().any(|d| d == "evil.example.com"));
    }

    #[test]
    fn test_extract_domains_dedup() {
        let domains = IocExtractor::extract_domains("evil.com and evil.com twice");
        assert_eq!(
            domains.iter().filter(|d| d.as_str() == "evil.com").count(),
            1
        );
    }

    #[test]
    fn test_extract_domains_filters_invalid_tld() {
        // ".xyz123" is not a recognised TLD in our list
        let domains = IocExtractor::extract_domains("host.xyz123 is not valid");
        assert!(!domains.iter().any(|d| d.contains("xyz123")));
    }

    // ── IocExtractor::extract_sha256 ─────────────────────────────────────────

    #[test]
    fn test_extract_sha256_canonical() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hashes = IocExtractor::extract_sha256(&format!("hash: {hash}"));
        assert_eq!(hashes, vec![hash]);
    }

    #[test]
    fn test_extract_sha256_normalised_to_lowercase() {
        let hash_upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let hashes = IocExtractor::extract_sha256(hash_upper);
        assert!(!hashes.is_empty());
        assert!(
            hashes[0]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn test_extract_sha256_excludes_sha512() {
        // A 128-char hex string should NOT appear in sha256 results
        let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                      47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let hashes = IocExtractor::extract_sha256(sha512);
        // If any 64-char prefix was returned it would be wrong
        for h in &hashes {
            assert_ne!(h.len(), 64, "sha512 prefix should not appear as sha256");
        }
    }

    #[test]
    fn test_extract_sha256_dedup() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let text = format!("{hash} and again {hash}");
        let hashes = IocExtractor::extract_sha256(&text);
        assert_eq!(hashes.len(), 1);
    }

    // ── IocExtractor::extract_md5 ────────────────────────────────────────────

    #[test]
    fn test_extract_md5_canonical() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let hashes = IocExtractor::extract_md5(&format!("md5: {md5}"));
        assert_eq!(hashes, vec![md5]);
    }

    #[test]
    fn test_extract_md5_does_not_return_sha1_prefix() {
        // 40-char string should NOT produce an MD5 result
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let hashes = IocExtractor::extract_md5(sha1);
        assert!(hashes.is_empty(), "SHA-1 should not match MD5: {hashes:?}");
    }

    #[test]
    fn test_extract_md5_dedup() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let text = format!("{md5} {md5}");
        let hashes = IocExtractor::extract_md5(&text);
        assert_eq!(hashes.len(), 1);
    }

    // ── IocExtractor::defang ─────────────────────────────────────────────────

    #[test]
    fn test_defang_url() {
        assert_eq!(
            IocExtractor::defang("http://evil.example.com/path"),
            "http[://]evil[.]example[.]com/path"
        );
    }

    #[test]
    fn test_defang_ip() {
        assert_eq!(IocExtractor::defang("1.2.3.4"), "1[.]2[.]3[.]4");
    }

    #[test]
    fn test_defang_domain() {
        assert_eq!(IocExtractor::defang("malware.io"), "malware[.]io");
    }

    #[test]
    fn test_defang_https() {
        assert_eq!(
            IocExtractor::defang("https://bad.example.org"),
            "https[://]bad[.]example[.]org"
        );
    }

    #[test]
    fn test_defang_idempotent_round_trip() {
        let original = "http://evil.example.com";
        let defanged = IocExtractor::defang(original);
        let refanged = IocExtractor::refang(&defanged);
        assert_eq!(refanged, original);
    }

    // ── IocExtractor::refang ─────────────────────────────────────────────────

    #[test]
    fn test_refang_url() {
        assert_eq!(
            IocExtractor::refang("http[://]evil[.]example[.]com"),
            "http://evil.example.com"
        );
    }

    #[test]
    fn test_refang_ip() {
        assert_eq!(IocExtractor::refang("8[.]8[.]8[.]8"), "8.8.8.8");
    }

    #[test]
    fn test_refang_no_change_when_already_live() {
        // Refanging a live URL should leave it unchanged (no substitutions match)
        assert_eq!(
            IocExtractor::refang("http://clean.example.com"),
            "http://clean.example.com"
        );
    }

    // ── is_private_ipv4 ──────────────────────────────────────────────────────

    #[test]
    fn test_is_private_10() {
        assert!(is_private_ipv4("10.255.255.255"));
        assert!(!is_private_ipv4("11.0.0.1"));
    }

    #[test]
    fn test_is_private_172_16_to_31() {
        assert!(is_private_ipv4("172.16.0.1"));
        assert!(is_private_ipv4("172.31.255.255"));
        assert!(!is_private_ipv4("172.15.0.1"));
        assert!(!is_private_ipv4("172.32.0.1"));
    }

    #[test]
    fn test_is_private_192_168() {
        assert!(is_private_ipv4("192.168.100.200"));
        assert!(!is_private_ipv4("192.169.0.1"));
    }

    #[test]
    fn test_is_private_loopback() {
        assert!(is_private_ipv4("127.0.0.1"));
        assert!(is_private_ipv4("127.255.0.1"));
        assert!(!is_private_ipv4("128.0.0.1"));
    }

    #[test]
    fn test_is_private_zero_network() {
        assert!(is_private_ipv4("0.0.0.0"));
        assert!(is_private_ipv4("0.255.255.255"));
        assert!(!is_private_ipv4("1.0.0.0"));
    }

    // ── parse_mbz_datetime ───────────────────────────────────────────────────

    #[test]
    fn test_parse_mbz_datetime_epoch() {
        // 1970-01-01 00:00:00 == 0
        let ts = parse_mbz_datetime("1970-01-01 00:00:00");
        assert_eq!(ts, Some(0));
    }

    #[test]
    fn test_parse_mbz_datetime_known() {
        // 2024-01-01 00:00:00 == 1704067200
        let ts = parse_mbz_datetime("2024-01-01 00:00:00");
        assert_eq!(ts, Some(1_704_067_200));
    }

    #[test]
    fn test_parse_mbz_datetime_invalid() {
        assert_eq!(parse_mbz_datetime("not-a-date"), None);
        assert_eq!(parse_mbz_datetime("2024/01/01 00:00:00"), None);
    }

    // ── days_since_epoch ─────────────────────────────────────────────────────

    #[test]
    fn test_days_since_epoch_epoch() {
        assert_eq!(days_since_epoch(1970, 1, 1), Some(0));
    }

    #[test]
    fn test_days_since_epoch_known_date() {
        // 2024-01-01 is 19723 days after epoch
        let d = days_since_epoch(2024, 1, 1);
        assert_eq!(d, Some(19723));
    }

    #[test]
    fn test_days_since_epoch_pre_epoch_returns_none() {
        // 1969-12-31 would underflow; function returns None or 0 (saturating)
        // We only require it doesn't panic.
        let _ = days_since_epoch(1969, 12, 31);
    }

    // ── query_all_providers (with a mock) ─────────────────────────────────────

    struct MockProvider {
        name: &'static str,
        result: Option<IntelReport>,
    }

    #[async_trait]
    impl IntelProvider for MockProvider {
        fn name(&self) -> &str {
            self.name
        }

        async fn query_hash(&self, _hash: &str) -> Result<Option<IntelReport>, TiError> {
            Ok(self.result.clone())
        }

        async fn query_ip(&self, _ip: &str) -> Result<Option<IntelReport>, TiError> {
            Ok(None)
        }
    }

    struct ErrorProvider;

    #[async_trait]
    impl IntelProvider for ErrorProvider {
        fn name(&self) -> &'static str {
            "error"
        }

        async fn query_hash(&self, _hash: &str) -> Result<Option<IntelReport>, TiError> {
            Err(TiError::RateLimit("error".into()))
        }

        async fn query_ip(&self, _ip: &str) -> Result<Option<IntelReport>, TiError> {
            Err(TiError::RateLimit("error".into()))
        }
    }

    #[tokio::test]
    async fn test_query_all_providers_collects_reports() {
        let p1 = MockProvider {
            name: "p1",
            result: Some(IntelReport::new("p1", true)),
        };
        let p2 = MockProvider {
            name: "p2",
            result: Some(IntelReport::new("p2", false)),
        };
        let providers: Vec<&dyn IntelProvider> = vec![&p1, &p2];
        let reports = query_all_providers("abc", &providers).await;
        assert_eq!(reports.len(), 2);
    }

    #[tokio::test]
    async fn test_query_all_providers_skips_none() {
        let p1 = MockProvider {
            name: "p1",
            result: None,
        };
        let p2 = MockProvider {
            name: "p2",
            result: Some(IntelReport::new("p2", false)),
        };
        let providers: Vec<&dyn IntelProvider> = vec![&p1, &p2];
        let reports = query_all_providers("abc", &providers).await;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].source, "p2");
    }

    #[tokio::test]
    async fn test_query_all_providers_skips_errors() {
        let err = ErrorProvider;
        let ok = MockProvider {
            name: "ok",
            result: Some(IntelReport::new("ok", false)),
        };
        let providers: Vec<&dyn IntelProvider> = vec![&err, &ok];
        let reports = query_all_providers("abc", &providers).await;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].source, "ok");
    }

    #[tokio::test]
    async fn test_query_all_providers_empty_providers() {
        let providers: Vec<&dyn IntelProvider> = vec![];
        let reports = query_all_providers("abc", &providers).await;
        assert!(reports.is_empty());
    }

    #[tokio::test]
    async fn test_query_ip_all_providers() {
        let p1 = MockProvider {
            name: "p1",
            result: Some(IntelReport::new("p1", true)),
        };
        // query_ip always returns None for MockProvider
        let providers: Vec<&dyn IntelProvider> = vec![&p1];
        let reports = query_ip_all_providers("1.2.3.4", &providers).await;
        assert!(reports.is_empty());
    }
}

/// The engine counts in a `VirusTotal` response are unbounded `u64` values read
/// straight from the remote JSON, and `MAX_ENGINE_COUNT` exists so that
/// "overflow never produces wildly wrong values".
///
/// A clamp applied *after* the addition cannot deliver that: a wrapping `+`
/// yields a SMALL number, which then passes `.min(MAX_ENGINE_COUNT)` untouched.
/// The property below is the one that makes the clamp meaningful — the
/// detection count must never come out lower than what the inputs imply.
#[cfg(test)]
mod engine_count_arithmetic {
    use super::VirusTotalIntelClient;

    fn response(malicious: u64, suspicious: u64, harmless: u64, undetected: u64) -> serde_json::Value {
        serde_json::json!({
            "data": { "attributes": { "last_analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            }}}
        })
    }

    /// Cases on BOTH sides of the overflow boundary: ordinary responses, and
    /// ones whose sums exceed `u64::MAX`.
    fn corpus() -> Vec<(&'static str, u64, u64, u64, u64)> {
        vec![
            ("all zero", 0, 0, 0, 0),
            ("typical clean", 0, 0, 60, 10),
            ("typical malicious", 45, 3, 10, 12),
            ("at the clamp", 100_000, 0, 0, 0),
            ("past the clamp", 100_001, 5, 0, 0),
            ("detections overflow", u64::MAX, 1, 0, 0),
            ("total overflows on the last addend", 1, 1, 1, u64::MAX),
            ("everything saturated", u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        ]
    }

    #[test]
    fn a_malicious_verdict_never_wraps_into_a_clean_one() {
        let client = VirusTotalIntelClient::new("test-key");
        let cases = corpus();
        assert!(cases.len() >= 8, "anti-vacuity: expected the full corpus");

        let mut overflowing = 0usize;
        let mut ordinary = 0usize;
        let mut divergences = Vec::new();

        for (label, malicious, suspicious, harmless, undetected) in &cases {
            let body = response(*malicious, *suspicious, *harmless, *undetected);
            let report = client
                .parse_response(&body, "sample")
                .expect("premise: the fixture is a well-formed VirusTotal response");

            let saturates = malicious.checked_add(*suspicious).is_none()
                || malicious
                    .checked_add(*suspicious)
                    .and_then(|s| s.checked_add(*harmless))
                    .and_then(|s| s.checked_add(*undetected))
                    .is_none();
            if saturates {
                overflowing += 1;
            } else {
                ordinary += 1;
            }

            // Any single malicious engine must be visible in the count. Under a
            // wrapping `+` this is exactly what fails: u64::MAX + 1 == 0.
            if (*malicious > 0 || *suspicious > 0) && report.detections == 0 {
                divergences.push(format!(
                    "case `{label}`: malicious={malicious} suspicious={suspicious} \
                     reported as {} detections",
                    report.detections
                ));
            }
            if report.detections > report.total_engines {
                divergences.push(format!(
                    "case `{label}`: {} detections out of {} engines",
                    report.detections, report.total_engines
                ));
            }
            if !report.confidence.is_finite() || !(0.0..=1.0).contains(&report.confidence) {
                divergences.push(format!(
                    "case `{label}`: confidence {} is outside [0,1]",
                    report.confidence
                ));
            }
        }

        // Both sides of the boundary must actually be exercised.
        assert!(overflowing >= 3, "anti-vacuity: expected overflowing cases, got {overflowing}");
        assert!(ordinary >= 3, "anti-vacuity: expected ordinary cases, got {ordinary}");
        assert!(divergences.is_empty(), "{}", divergences.join("\n"));
    }
}
