//! `VirusTotal` API v3 client for the `RustRE` Suite.
//!
//! Provides asynchronous access to `VirusTotal`'s file, URL, domain and IP
//! report endpoints.  All requests are authenticated with an API key passed
//! in the `x-apikey` header.
//!
//! # Rate limiting
//! Free API keys are limited to 4 requests per minute and 500 per day.
//! The [`VirusTotalClient`] exposes `rate_limit_per_minute()` so the
//! [`crate::provider::TiProvider`] machinery can throttle calls automatically.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::TiError,
    ioc::{IoC, IoCType, Severity},
    provider::{TiProvider, TiResult, Verdict},
};

// ─────────────────────────────────────────────────────────────────────────────
// Raw API response types
// ─────────────────────────────────────────────────────────────────────────────

/// Result returned by one antivirus engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtEngineResult {
    /// Engine category (e.g. `"malicious"`, `"clean"`, `"undetected"`).
    pub category: String,
    /// Human-readable engine name.
    pub engine_name: String,
    /// Engine definition version string.
    pub engine_version: Option<String>,
    /// Engine update date (YYYYMMDD).
    pub engine_update: Option<String>,
    /// Detection name reported by the engine, if any.
    pub result: Option<String>,
    /// Method used for the detection (e.g. `"blacklist"`, `"heuristic"`).
    pub method: Option<String>,
}

/// File attributes from the `VirusTotal` `/files/{hash}` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtFileAttributes {
    /// MD5 hash of the file.
    pub md5: Option<String>,
    /// SHA-1 hash of the file.
    pub sha1: Option<String>,
    /// SHA-256 hash of the file.
    pub sha256: Option<String>,
    /// File size in bytes.
    pub size: Option<u64>,
    /// MIME type (e.g. `"application/x-dosexec"`).
    #[serde(rename = "type_description")]
    pub type_description: Option<String>,
    /// Number of engines that flagged the file as malicious.
    pub last_analysis_stats: Option<VtAnalysisStats>,
    /// Per-engine results.
    pub last_analysis_results: Option<HashMap<String, VtEngineResult>>,
    /// Timestamp of the last analysis (Unix epoch).
    pub last_analysis_date: Option<u64>,
    /// Timestamp when the file was first submitted (Unix epoch).
    pub first_submission_date: Option<u64>,
    /// Meaningful names observed in submissions.
    pub names: Option<Vec<String>>,
    /// Tags assigned by `VirusTotal` (e.g. `"peexe"`, `"64bits"`).
    pub tags: Option<Vec<String>>,
    /// Crowdsourced YARA rule hits.
    pub crowdsourced_yara_results: Option<Vec<VtYaraHit>>,
    /// Sigma rule hits.
    pub sigma_analysis_stats: Option<VtSigmaStats>,
}

/// Summary counts from `last_analysis_stats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtAnalysisStats {
    pub harmless: u32,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub timeout: u32,
}

impl VtAnalysisStats {
    /// Total number of engines that ran.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.harmless
            .saturating_add(self.malicious)
            .saturating_add(self.suspicious)
            .saturating_add(self.undetected)
            .saturating_add(self.timeout)
    }

    /// Detection ratio as a value in `[0.0, 1.0]`.
    #[must_use]
    pub fn detection_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            f64::from(self.malicious + self.suspicious) / f64::from(total)
        }
    }
}

/// A crowdsourced YARA rule hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtYaraHit {
    /// Name of the YARA rule.
    pub rule_name: String,
    /// Author or source of the rule.
    pub source: Option<String>,
    /// Rule description.
    pub description: Option<String>,
}

/// Sigma analysis summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtSigmaStats {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

/// Top-level wrapper for a `/files/{hash}` response data object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtFileReport {
    /// `VirusTotal` object type (always `"file"`).
    #[serde(rename = "type")]
    pub object_type: Option<String>,
    /// The file's SHA-256 (used as the `VirusTotal` ID).
    pub id: Option<String>,
    /// File attributes.
    pub attributes: VtFileAttributes,
}

impl VtFileReport {
    /// Returns `true` when more than 5 % of engines detected the file.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.attributes
            .last_analysis_stats
            .as_ref()
            .is_some_and(|s| s.detection_ratio() > 0.05)
    }

    /// Returns the number of detecting engines (malicious + suspicious).
    #[must_use]
    pub fn positive_count(&self) -> u32 {
        self.attributes
            .last_analysis_stats
            .as_ref()
            .map_or(0, |s| s.malicious + s.suspicious)
    }

    /// Returns the total number of engines.
    #[must_use]
    pub fn engine_count(&self) -> u32 {
        self.attributes
            .last_analysis_stats
            .as_ref()
            .map_or(0, VtAnalysisStats::total)
    }

    /// Collect the most common detection names across all engines.
    #[must_use]
    pub fn detection_names(&self) -> Vec<String> {
        let Some(results) = &self.attributes.last_analysis_results else {
            return Vec::new();
        };
        let mut names: Vec<String> = results.values().filter_map(|e| e.result.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Return the last-analysis date as an ISO-8601 string, if available.
    #[must_use]
    pub fn last_analysis_date_str(&self) -> Option<String> {
        self.attributes.last_analysis_date.map(epoch_to_iso8601)
    }

    /// Return the first-submission date as an ISO-8601 string, if available.
    #[must_use]
    pub fn first_submission_date_str(&self) -> Option<String> {
        self.attributes.first_submission_date.map(epoch_to_iso8601)
    }

    /// Derive a [`Severity`] from the detection ratio.
    #[must_use]
    pub fn severity(&self) -> Severity {
        let ratio = self
            .attributes
            .last_analysis_stats
            .as_ref()
            .map_or(0.0, VtAnalysisStats::detection_ratio);
        if ratio >= 0.5 {
            Severity::Critical
        } else if ratio >= 0.2 {
            Severity::High
        } else if ratio >= 0.05 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

/// URL report attributes from `/urls/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtUrlAttributes {
    pub url: Option<String>,
    pub final_url: Option<String>,
    pub last_analysis_stats: Option<VtAnalysisStats>,
    pub last_analysis_results: Option<HashMap<String, VtEngineResult>>,
    pub last_http_response_code: Option<u16>,
    pub tags: Option<Vec<String>>,
}

/// Domain / IP report attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtNetworkAttributes {
    /// Registrar.
    pub registrar: Option<String>,
    /// Creation date (RFC3339).
    pub creation_date: Option<String>,
    /// Last WHOIS update date (RFC3339).
    pub last_update_date: Option<String>,
    pub last_analysis_stats: Option<VtAnalysisStats>,
    pub last_analysis_results: Option<HashMap<String, VtEngineResult>>,
    /// Categories assigned to the domain/IP.
    pub categories: Option<HashMap<String, String>>,
    /// Associated IP addresses (for domains).
    pub last_dns_records: Option<Vec<VtDnsRecord>>,
}

/// A single DNS record returned by `VirusTotal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtDnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// VirusTotalClient
// ─────────────────────────────────────────────────────────────────────────────

/// Async HTTP client for the `VirusTotal` API v3.
///
/// ```rust,no_run
/// # use rustre_threatintel::virustotal::VirusTotalClient;
/// # #[tokio::main] async fn main() {
/// let client = VirusTotalClient::new("YOUR_API_KEY");
/// let report = client.file_report("44d88612fea8a8f36de82e1278abb02f").await;
/// # }
/// ```
pub struct VirusTotalClient {
    api_key: String,
    http: reqwest::Client,
    base_url: String,
}

impl VirusTotalClient {
    const DEFAULT_BASE: &'static str = "https://www.virustotal.com/api/v3";

    /// Create a new client with the given API key.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            http: reqwest::Client::new(),
            base_url: Self::DEFAULT_BASE.to_owned(),
        }
    }

    /// Override the base URL (useful for testing against a mock server).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Build the `x-apikey` header value.
    fn auth_header(&self) -> String {
        self.api_key.clone()
    }

    /// Fetch a file report by hash (MD5, SHA-1 or SHA-256).
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP errors or JSON deserialization failures.
    pub async fn file_report(&self, hash: &str) -> Result<VtFileReport, TiError> {
        let url = format!("{}/files/{}", self.base_url, hash);
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", self.auth_header())
            .send()
            .await
            .map_err(|e| TiError::Http(e.to_string()))?;

        if resp.status() == 404 {
            return Err(TiError::NotFound(hash.to_owned()));
        }
        if resp.status() == 429 {
            return Err(TiError::RateLimit("virustotal".to_owned()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;

        let data = body
            .get("data")
            .ok_or_else(|| TiError::Parse("missing `data` key".into()))?;
        serde_json::from_value(data.clone()).map_err(|e| TiError::Parse(e.to_string()))
    }

    /// Fetch a URL report.  The URL must be base64url-encoded without padding.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP errors or JSON deserialization failures.
    pub async fn url_report(&self, url_id: &str) -> Result<VtUrlAttributes, TiError> {
        let endpoint = format!("{}/urls/{}", self.base_url, url_id);
        let resp = self
            .http
            .get(&endpoint)
            .header("x-apikey", self.auth_header())
            .send()
            .await
            .map_err(|e| TiError::Http(e.to_string()))?;

        if resp.status() == 404 {
            return Err(TiError::NotFound(url_id.to_owned()));
        }
        if resp.status() == 429 {
            return Err(TiError::RateLimit("virustotal".to_owned()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let data = body
            .get("data")
            .ok_or_else(|| TiError::Parse("missing `data` key".into()))?;
        let attrs = data
            .get("attributes")
            .ok_or_else(|| TiError::Parse("missing `attributes`".into()))?;
        serde_json::from_value(attrs.clone()).map_err(|e| TiError::Parse(e.to_string()))
    }

    /// Fetch a domain report.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP errors or JSON deserialization failures.
    pub async fn domain_report(&self, domain: &str) -> Result<VtNetworkAttributes, TiError> {
        let url = format!("{}/domains/{}", self.base_url, domain);
        self.fetch_network_attrs(&url).await
    }

    /// Fetch an IP address report.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP errors or JSON deserialization failures.
    pub async fn ip_report(&self, ip: &str) -> Result<VtNetworkAttributes, TiError> {
        let url = format!("{}/ip_addresses/{}", self.base_url, ip);
        self.fetch_network_attrs(&url).await
    }

    async fn fetch_network_attrs(&self, url: &str) -> Result<VtNetworkAttributes, TiError> {
        let resp = self
            .http
            .get(url)
            .header("x-apikey", self.auth_header())
            .send()
            .await
            .map_err(|e| TiError::Http(e.to_string()))?;

        if resp.status() == 404 {
            return Err(TiError::NotFound(url.to_owned()));
        }
        if resp.status() == 429 {
            return Err(TiError::RateLimit("virustotal".to_owned()));
        }
        if !resp.status().is_success() {
            return Err(TiError::Http(format!("HTTP {}", resp.status())));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TiError::Parse(e.to_string()))?;
        let data = body
            .get("data")
            .ok_or_else(|| TiError::Parse("missing `data` key".into()))?;
        let attrs = data
            .get("attributes")
            .ok_or_else(|| TiError::Parse("missing `attributes`".into()))?;
        serde_json::from_value(attrs.clone()).map_err(|e| TiError::Parse(e.to_string()))
    }

    /// Submit a file hash for bulk lookup and return raw JSON results.
    ///
    /// # Errors
    /// Returns [`TiError`] on HTTP errors or JSON deserialization failures.
    pub async fn bulk_file_reports(&self, hashes: &[&str]) -> Result<Vec<VtFileReport>, TiError> {
        let mut reports = Vec::with_capacity(hashes.len());
        for hash in hashes {
            match self.file_report(hash).await {
                Ok(r) => reports.push(r),
                Err(TiError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(reports)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TiProvider implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl TiProvider for VirusTotalClient {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    fn supported_ioc_types(&self) -> Vec<IoCType> {
        vec![
            IoCType::Md5,
            IoCType::Sha1,
            IoCType::Sha256,
            IoCType::Sha512,
            IoCType::Domain,
            IoCType::Ip,
            IoCType::Url,
        ]
    }

    fn rate_limit_per_minute(&self) -> u32 {
        4
    }

    async fn lookup(&self, ioc: &IoC) -> Result<TiResult, TiError> {
        let mut result = TiResult::new(ioc.clone());

        match ioc.ioc_type {
            IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 | IoCType::Sha512 => {
                let report = self.file_report(&ioc.value).await?;
                let positive = report.positive_count();
                let total = report.engine_count();
                let malicious = report.is_malicious();
                let confidence = crate::casts::f64_to_u8_sat((f64::from(positive) / f64::from(total.max(1))) * 100.0);
                let tags = report.detection_names();
                let first_seen = report.attributes.first_submission_date;
                let last_seen = report.attributes.last_analysis_date;
                result.verdicts.push(Verdict {
                    malicious,
                    confidence,
                    tags,
                    engine_count: total,
                    positive_count: positive,
                    first_seen,
                    last_seen,
                    description: None,
                    provider: "virustotal".to_owned(),
                });
            }
            IoCType::Domain => {
                let attrs = self.domain_report(&ioc.value).await?;
                let positive = attrs
                    .last_analysis_stats
                    .as_ref()
                    .map_or(0, |s| s.malicious + s.suspicious);
                let total = attrs
                    .last_analysis_stats
                    .as_ref()
                    .map_or(0, VtAnalysisStats::total);
                result.verdicts.push(Verdict {
                    malicious: positive > 0,
                    confidence: crate::casts::f64_to_u8_sat((f64::from(positive) / f64::from(total.max(1))) * 100.0),
                    tags: Vec::new(),
                    engine_count: total,
                    positive_count: positive,
                    first_seen: None,
                    last_seen: None,
                    description: None,
                    provider: "virustotal".to_owned(),
                });
            }
            IoCType::Ip => {
                let attrs = self.ip_report(&ioc.value).await?;
                let positive = attrs
                    .last_analysis_stats
                    .as_ref()
                    .map_or(0, |s| s.malicious + s.suspicious);
                let total = attrs
                    .last_analysis_stats
                    .as_ref()
                    .map_or(0, VtAnalysisStats::total);
                result.verdicts.push(Verdict {
                    malicious: positive > 0,
                    confidence: crate::casts::f64_to_u8_sat((f64::from(positive) / f64::from(total.max(1))) * 100.0),
                    tags: Vec::new(),
                    engine_count: total,
                    positive_count: positive,
                    first_seen: None,
                    last_seen: None,
                    description: None,
                    provider: "virustotal".to_owned(),
                });
            }
            _ => {
                // Unsupported IoC type for VirusTotal: return empty result
            }
        }

        Ok(result)
    }

    async fn bulk_lookup(&self, iocs: &[IoC]) -> Result<Vec<TiResult>, TiError> {
        let mut results = Vec::with_capacity(iocs.len());
        for ioc in iocs {
            results.push(self.lookup(ioc).await?);
        }
        Ok(results)
    }
}

/// Convert a Unix epoch timestamp to an ISO-8601 date string.
///
/// This is a `no_std`-friendly replacement for `chrono::DateTime` that avoids
/// pulling in the full chrono crate.
#[must_use] 
pub fn epoch_to_iso8601(epoch: u64) -> String {
    // Simple formatting without chrono dependency: YYYY-MM-DDThh:mm:ssZ
    let secs = epoch;
    // Days since epoch
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let rem2 = rem % 3600;
    let minutes = rem2 / 60;
    let seconds = rem2 % 60;

    // Gregorian calendar calculation
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

const fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Shift to 1 Mar 0000 era for simpler leap-year calculation
    days += 719_468;
    let era = days / 146_097;
    let doe = days % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`VirusTotalClient`] to allow optional configuration.
#[derive(Default)]
pub struct VirusTotalClientBuilder {
    api_key: String,
    base_url: Option<String>,
}

impl VirusTotalClientBuilder {
    /// Start building a new client.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: None,
        }
    }

    /// Override the API base URL.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Consume the builder and produce a [`VirusTotalClient`].
    #[must_use]
    pub fn build(self) -> VirusTotalClient {
        let mut c = VirusTotalClient::new(self.api_key);
        if let Some(u) = self.base_url {
            c = c.with_base_url(u);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_stats_total_and_ratio() {
        let stats = VtAnalysisStats {
            harmless: 60,
            malicious: 20,
            suspicious: 5,
            undetected: 15,
            timeout: 0,
        };
        assert_eq!(stats.total(), 100);
        assert!((stats.detection_ratio() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_analysis_stats_zero_total() {
        let stats = VtAnalysisStats {
            harmless: 0,
            malicious: 0,
            suspicious: 0,
            undetected: 0,
            timeout: 0,
        };
        assert!((stats.detection_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_file_report_severity() {
        let mk_report = |malicious: u32, total: u32| VtFileReport {
            object_type: None,
            id: None,
            attributes: VtFileAttributes {
                md5: None,
                sha1: None,
                sha256: None,
                size: None,
                type_description: None,
                last_analysis_stats: Some(VtAnalysisStats {
                    harmless: total - malicious,
                    malicious,
                    suspicious: 0,
                    undetected: 0,
                    timeout: 0,
                }),
                last_analysis_results: None,
                last_analysis_date: None,
                first_submission_date: None,
                names: None,
                tags: None,
                crowdsourced_yara_results: None,
                sigma_analysis_stats: None,
            },
        };
        assert_eq!(mk_report(0, 70).severity(), Severity::Low);
        assert_eq!(mk_report(4, 70).severity(), Severity::Medium);
        assert_eq!(mk_report(15, 70).severity(), Severity::High);
        assert_eq!(mk_report(50, 70).severity(), Severity::Critical);
    }

    #[test]
    fn test_detection_names_dedup() {
        let mut results = HashMap::new();
        results.insert(
            "EngineA".to_owned(),
            VtEngineResult {
                category: "malicious".to_owned(),
                engine_name: "EngineA".to_owned(),
                engine_version: None,
                engine_update: None,
                result: Some("Trojan.Generic".to_owned()),
                method: None,
            },
        );
        results.insert(
            "EngineB".to_owned(),
            VtEngineResult {
                category: "malicious".to_owned(),
                engine_name: "EngineB".to_owned(),
                engine_version: None,
                engine_update: None,
                result: Some("Trojan.Generic".to_owned()),
                method: None,
            },
        );
        let report = VtFileReport {
            object_type: None,
            id: None,
            attributes: VtFileAttributes {
                md5: None,
                sha1: None,
                sha256: None,
                size: None,
                type_description: None,
                last_analysis_stats: None,
                last_analysis_results: Some(results),
                last_analysis_date: None,
                first_submission_date: None,
                names: None,
                tags: None,
                crowdsourced_yara_results: None,
                sigma_analysis_stats: None,
            },
        };
        let names = report.detection_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "Trojan.Generic");
    }

    #[test]
    fn test_builder() {
        let client = VirusTotalClientBuilder::new("testkey")
            .base_url("http://localhost:9999")
            .build();
        assert_eq!(client.api_key, "testkey");
        assert_eq!(client.base_url, "http://localhost:9999");
    }

    #[test]
    fn test_epoch_to_iso8601() {
        // 2024-01-01T00:00:00Z = 1704067200
        let s = epoch_to_iso8601(1_704_067_200);
        assert_eq!(s, "2024-01-01T00:00:00Z");
    }
}
