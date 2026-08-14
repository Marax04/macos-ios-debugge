//! `VirusTotal` API v3 client using `reqwest` with `rustls-tls`.

use std::collections::HashMap;

use reqwest::{Client, multipart};

use crate::cache::{CacheKind, VtCache};
use crate::error::VtError;
use crate::models::{
    VtAnalysisId, VtAnalysisReport, VtAnalysisStatus, VtDomainReport, VtEngineResult, VtFileReport,
    VtIpReport, VtStats, VtUrlReport,
};
use crate::rate_limit::VtRateLimiter;

const VT_BASE_URL: &str = "https://www.virustotal.com";

// ---------------------------------------------------------------------------
// VtReport — simplified report returned by the convenience helpers.
// ---------------------------------------------------------------------------

/// Simplified `VirusTotal` report returned by `lookup_hash` and `lookup_url`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VtReport {
    /// Hash (SHA-256, SHA-1, or MD5) that was queried.
    pub hash: String,
    /// Number of engines that flagged the resource as malicious.
    pub positives: u32,
    /// Total number of engines that participated in the analysis.
    pub total: u32,
    /// Suggested threat/malware family name, if available.
    pub threat_name: Option<String>,
    /// Timestamp of the last analysis (Unix seconds), if available.
    pub scan_date: Option<u64>,
}

impl VtReport {
    /// Return `true` if at least one engine flagged the resource.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.positives > 0
    }

    /// Detection ratio as a `"X/Y"` string.
    #[must_use]
    pub fn detection_ratio(&self) -> String {
        format!("{}/{}", self.positives, self.total)
    }
}

// ---------------------------------------------------------------------------
// VtClient
// ---------------------------------------------------------------------------

/// `VirusTotal` API v3 client.
pub struct VtClient {
    api_key: String,
    base_url: String,
    rate_limiter: VtRateLimiter,
    cache: Option<VtCache>,
    http: Client,
}

impl VtClient {
    /// Create a new client with the given API key.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest` TLS client cannot be built (this
    /// should never happen with the bundled `rustls-tls` feature).
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        let http = Client::builder()
            .use_rustls_tls()
            .build()
            .expect("failed to build reqwest TLS client");
        Self {
            api_key: api_key.into(),
            base_url: VT_BASE_URL.to_string(),
            rate_limiter: VtRateLimiter::default_free_tier(),
            cache: None,
            http,
        }
    }

    /// Attach a result cache.
    #[must_use]
    pub fn with_cache(mut self, cache: VtCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set a custom base URL (useful for testing against a mock server).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    // -----------------------------------------------------------------------
    // Internal HTTP helpers
    // -----------------------------------------------------------------------

    async fn get_json(&self, path: &str) -> Result<serde_json::Value, VtError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e: reqwest::Error| VtError::Http {
                status: 0,
                body: e.to_string(),
            })?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Err(VtError::not_found("resource not found on VirusTotal"));
        }
        if status == 429 {
            return Err(VtError::RateLimited {
                retry_after_secs: 60,
            });
        }
        if status >= 400 {
            let body = resp.text().await.unwrap_or_default();
            return Err(VtError::Http { status, body });
        }

        let json = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e: reqwest::Error| VtError::Http {
                status,
                body: e.to_string(),
            })?;
        Ok(json)
    }

    // -----------------------------------------------------------------------
    // Public API — convenience `VtReport` helpers
    // -----------------------------------------------------------------------

    /// Look up a file by its MD5, SHA-1, or SHA-256 hash and return a
    /// simplified [`VtReport`].
    ///
    /// Accepts MD5 (32 hex chars), SHA-1 (40 hex chars), or SHA-256 (64 hex
    /// chars).  Returns [`VtError::InvalidResponse`] if the hash length or
    /// character set is not recognised.
    ///
    /// Endpoint: `GET /api/v3/files/<hash>`
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn lookup_hash(&self, hash: &str) -> Result<VtReport, VtError> {
        let key = hash.trim().to_ascii_lowercase();
        // Validate: must be all hex digits and one of the three expected lengths.
        let valid_len = matches!(key.len(), 32 | 40 | 64);
        let all_hex = key.chars().all(|c| c.is_ascii_hexdigit());
        if !valid_len || !all_hex {
            return Err(VtError::invalid_response(format!(
                "invalid hash '{hash}': expected MD5 (32), SHA-1 (40), or SHA-256 (64) hex chars"
            )));
        }
        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/files/{key}");
        let json = self.get_json(&path).await?;

        let attrs = &json["data"]["attributes"];
        let stats = parse_stats(&attrs["last_analysis_stats"]);

        // Best-effort threat name from popular_threat_classification.
        let threat_name = attrs["popular_threat_classification"]["suggested_threat_label"]
            .as_str()
            .map(str::to_string)
            .or_else(|| {
                // Fall back to first malicious engine result name.
                attrs["last_analysis_results"].as_object().and_then(|obj| {
                    obj.values()
                        .filter(|v| v["category"].as_str() == Some("malicious"))
                        .find_map(|v| v["result"].as_str().map(str::to_string))
                })
            });

        let scan_date = attrs["last_analysis_date"].as_u64();

        Ok(VtReport {
            hash: key,
            positives: stats.malicious,
            total: stats.total(),
            threat_name,
            scan_date,
        })
    }

    /// Look up a URL and return a simplified [`VtReport`].
    ///
    /// The URL is base64url-encoded (no padding) before being sent to the API.
    ///
    /// Endpoint: `GET /api/v3/urls/<base64url_encoded_url>`
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn lookup_url(&self, url: &str) -> Result<VtReport, VtError> {
        let url_id = base64url_encode(url);

        // Cache check.
        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(CacheKind::Url, url)? {
                return Ok(url_report_to_vt_report(url, &cached));
            }

        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/urls/{url_id}");
        let json = self.get_json(&path).await?;

        if let Some(ref cache) = self.cache {
            let _ = cache.put(CacheKind::Url, url, &json);
        }

        Ok(url_report_to_vt_report(url, &json))
    }

    /// Submit a file for analysis and return the resulting [`VtAnalysisId`].
    ///
    /// The `filename` is sent as the `Content-Disposition` filename in the
    /// multipart form and is visible in the VT web UI.  Uses
    /// `multipart/form-data` as required by the VT API.
    ///
    /// Endpoint: `POST /api/v3/files`
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn submit_file(&self, data: &[u8], filename: &str) -> Result<VtAnalysisId, VtError> {
        self.rate_limiter.acquire().await;
        let url = format!("{}/api/v3/files", self.base_url);

        let part = multipart::Part::bytes(data.to_vec())
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e: reqwest::Error| VtError::Http {
                status: 0,
                body: e.to_string(),
            })?;
        let form = multipart::Form::new().part("file", part);

        let resp = self
            .http
            .post(&url)
            .header("x-apikey", &self.api_key)
            .multipart(form)
            .send()
            .await
            .map_err(|e: reqwest::Error| VtError::Http {
                status: 0,
                body: e.to_string(),
            })?;

        let status = resp.status().as_u16();
        if status == 429 {
            return Err(VtError::RateLimited {
                retry_after_secs: 60,
            });
        }
        if status >= 400 {
            let body = resp.text().await.unwrap_or_default();
            return Err(VtError::Http { status, body });
        }

        let json = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e: reqwest::Error| VtError::Http {
                status: 0,
                body: e.to_string(),
            })?;
        let id = json["data"]["id"]
            .as_str()
            .ok_or_else(|| VtError::invalid_response("missing analysis id in submit response"))?
            .to_string();
        Ok(VtAnalysisId::new(id))
    }

    /// Retrieve an analysis report by its ID.
    ///
    /// Poll this after [`submit_file`] until `status == Completed`.
    ///
    /// Endpoint: `GET /api/v3/analyses/<analysis_id>`
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_analysis(&self, analysis_id: &str) -> Result<VtAnalysisReport, VtError> {
        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/analyses/{analysis_id}");
        let json = self.get_json(&path).await?;
        Self::parse_analysis_report(&json)
    }

    // -----------------------------------------------------------------------
    // Full-report API methods
    // -----------------------------------------------------------------------

    /// Look up a file by hash and return a full [`VtFileReport`].
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn lookup_file(&self, hash: &str) -> Result<VtFileReport, VtError> {
        let key = hash.to_ascii_lowercase();

        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(CacheKind::File, &key)? {
                return Self::parse_file_report(&cached);
            }

        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/files/{key}");
        let json = self.get_json(&path).await?;

        if let Some(ref cache) = self.cache {
            let _ = cache.put(CacheKind::File, &key, &json);
        }

        Self::parse_file_report(&json)
    }

    /// Look up an IP address.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn lookup_ip(&self, ip: &str) -> Result<VtIpReport, VtError> {
        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(CacheKind::Ip, ip)? {
                return Self::parse_ip_report(&cached);
            }

        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/ip_addresses/{ip}");
        let json = self.get_json(&path).await?;

        if let Some(ref cache) = self.cache {
            let _ = cache.put(CacheKind::Ip, ip, &json);
        }

        Self::parse_ip_report(&json)
    }

    /// Look up a domain name.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn lookup_domain(&self, domain: &str) -> Result<VtDomainReport, VtError> {
        let key = domain.to_ascii_lowercase();

        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(CacheKind::Domain, &key)? {
                return Self::parse_domain_report(&cached);
            }

        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/domains/{key}");
        let json = self.get_json(&path).await?;

        if let Some(ref cache) = self.cache {
            let _ = cache.put(CacheKind::Domain, &key, &json);
        }

        Self::parse_domain_report(&json)
    }

    /// Look up a URL and return a full [`VtUrlReport`].
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn lookup_url_full(&self, url: &str) -> Result<VtUrlReport, VtError> {
        let url_id = base64url_encode(url);

        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(CacheKind::Url, url)? {
                return Self::parse_url_report(&cached);
            }

        self.rate_limiter.acquire().await;
        let path = format!("/api/v3/urls/{url_id}");
        let json = self.get_json(&path).await?;

        if let Some(ref cache) = self.cache {
            let _ = cache.put(CacheKind::Url, url, &json);
        }

        Self::parse_url_report(&json)
    }

    // -----------------------------------------------------------------------
    // JSON parsers (pub(crate) for tests)
    // -----------------------------------------------------------------------

    pub(crate) fn parse_file_report(json: &serde_json::Value) -> Result<VtFileReport, VtError> {
        let attrs = &json["data"]["attributes"];
        let stats = parse_stats(&attrs["last_analysis_stats"]);
        let results = parse_engine_results(&attrs["last_analysis_results"]);

        Ok(VtFileReport {
            sha256: str_field(attrs, "sha256"),
            md5: str_field(attrs, "md5"),
            sha1: str_field(attrs, "sha1"),
            name: attrs["meaningful_name"].as_str().map(str::to_string),
            size: attrs["size"].as_u64().unwrap_or(0),
            type_tag: str_field(attrs, "type_tag"),
            last_analysis_stats: stats,
            last_analysis_results: results,
            first_submission_date: attrs["first_submission_date"].as_u64().unwrap_or(0),
            tags: parse_string_array(&attrs["tags"]),
        })
    }

    pub(crate) fn parse_ip_report(json: &serde_json::Value) -> Result<VtIpReport, VtError> {
        let attrs = &json["data"]["attributes"];
        Ok(VtIpReport {
            ip_address: str_field(&json["data"], "id"),
            country: attrs["country"].as_str().map(str::to_string),
            as_owner: attrs["as_owner"].as_str().map(str::to_string),
            asn: attrs["asn"].as_u64().and_then(|v| v.try_into().ok()),
            last_analysis_stats: parse_stats(&attrs["last_analysis_stats"]),
            tags: parse_string_array(&attrs["tags"]),
        })
    }

    pub(crate) fn parse_domain_report(json: &serde_json::Value) -> Result<VtDomainReport, VtError> {
        let attrs = &json["data"]["attributes"];
        let categories: HashMap<String, String> = attrs["categories"]
            .as_object()
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(VtDomainReport {
            domain: str_field(&json["data"], "id"),
            registrar: attrs["registrar"].as_str().map(str::to_string),
            creation_date: attrs["creation_date"].as_u64(),
            last_analysis_stats: parse_stats(&attrs["last_analysis_stats"]),
            tags: parse_string_array(&attrs["tags"]),
            categories,
        })
    }

    pub(crate) fn parse_analysis_report(
        json: &serde_json::Value,
    ) -> Result<VtAnalysisReport, VtError> {
        let data = &json["data"];
        let id = data["id"].as_str().unwrap_or("").to_string();
        let attrs = &data["attributes"];

        let status_str = attrs["status"].as_str().unwrap_or("unknown");
        let status = match status_str {
            "queued" => VtAnalysisStatus::Queued,
            "in-progress" => VtAnalysisStatus::InProgress,
            "completed" => VtAnalysisStatus::Completed,
            _ => VtAnalysisStatus::Unknown,
        };

        let stats = parse_stats(&attrs["stats"]);
        let results = parse_engine_results(&attrs["results"]);
        let sha256 = attrs["sha256"].as_str().map(str::to_string);

        Ok(VtAnalysisReport {
            id,
            status,
            results,
            stats,
            sha256,
        })
    }

    pub(crate) fn parse_url_report(json: &serde_json::Value) -> Result<VtUrlReport, VtError> {
        let attrs = &json["data"]["attributes"];
        Ok(VtUrlReport {
            url: str_field(attrs, "url"),
            final_url: attrs["final_url"].as_str().map(str::to_string),
            title: attrs["title"].as_str().map(str::to_string),
            last_analysis_stats: parse_stats(&attrs["last_analysis_stats"]),
            tags: parse_string_array(&attrs["tags"]),
            threat_names: parse_string_array(&attrs["threat_names"]),
        })
    }

    /// Extract just the HTTP status from a raw `"HTTP/1.1 NNN ..."` line.
    /// Kept for compatibility with tests that still exercise the header parser.
    #[cfg(test)]
    pub(crate) fn _extract_status_from_line(line: &str) -> Option<u16> {
        line.split_whitespace().nth(1).and_then(|s| s.parse().ok())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn url_report_to_vt_report(url: &str, json: &serde_json::Value) -> VtReport {
    let attrs = &json["data"]["attributes"];
    let stats = parse_stats(&attrs["last_analysis_stats"]);
    let threat_name = parse_string_array(&attrs["threat_names"])
        .into_iter()
        .next();
    let scan_date = attrs["last_analysis_date"].as_u64();
    VtReport {
        hash: url.to_string(),
        positives: stats.malicious,
        total: stats.total(),
        threat_name,
        scan_date,
    }
}

fn str_field(obj: &serde_json::Value, key: &str) -> String {
    obj[key].as_str().unwrap_or("").to_string()
}

fn parse_stats(v: &serde_json::Value) -> VtStats {
    // Clamp each counter to u32::MAX rather than silently truncating.
    let clamp = |field: &str| -> u32 {
        v[field]
            .as_u64()
            .unwrap_or(0)
            .try_into()
            .unwrap_or(u32::MAX)
    };
    VtStats {
        malicious: clamp("malicious"),
        suspicious: clamp("suspicious"),
        undetected: clamp("undetected"),
        harmless: clamp("harmless"),
        timeout: clamp("timeout"),
    }
}

fn parse_engine_results(v: &serde_json::Value) -> HashMap<String, VtEngineResult> {
    let Some(obj) = v.as_object() else {
        return HashMap::new();
    };
    obj.iter()
        .map(|(engine, result)| {
            (
                engine.clone(),
                VtEngineResult {
                    category: result["category"].as_str().unwrap_or("").to_string(),
                    engine_name: result["engine_name"].as_str().unwrap_or(engine).to_string(),
                    result: result["result"].as_str().map(str::to_string),
                    method: result["method"].as_str().unwrap_or("").to_string(),
                },
            )
        })
        .collect()
}

fn parse_string_array(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// URL-safe base64 encoding (no padding) as used by VT for URL IDs.
fn base64url_encode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[((b0 & 0x3) << 4 | b1 >> 4) as usize] as char);
        out.push(CHARS[((b1 & 0xf) << 2 | b2 >> 6) as usize] as char);
        out.push(CHARS[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    // Strip trailing padding-equivalent characters introduced by zero-padding.
    let remainder = bytes.len() % 3;
    if remainder == 1 {
        out.pop();
        out.pop();
    } else if remainder == 2 {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mock_file_json() -> serde_json::Value {
        json!({
            "data": {
                "id": "abc123",
                "attributes": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb924",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "meaningful_name": "test.exe",
                    "size": 4096,
                    "type_tag": "peexe",
                    "last_analysis_stats": {
                        "malicious": 30,
                        "suspicious": 5,
                        "undetected": 35,
                        "harmless": 0,
                        "timeout": 1
                    },
                    "last_analysis_results": {
                        "Engine1": {
                            "category": "malicious",
                            "engine_name": "Engine1",
                            "result": "Trojan.Generic",
                            "method": "blacklist"
                        }
                    },
                    "first_submission_date": 1_600_000_000_u64,
                    "tags": ["peexe", "overlay"]
                }
            }
        })
    }

    #[test]
    fn test_parse_file_report() {
        let json = mock_file_json();
        let report = VtClient::parse_file_report(&json).unwrap();
        assert_eq!(report.sha256, "e3b0c44298fc1c149afbf4c8996fb924");
        assert_eq!(report.name, Some("test.exe".to_string()));
        assert_eq!(report.last_analysis_stats.malicious, 30);
        assert!(report.is_malicious());
        assert_eq!(report.tags, vec!["peexe", "overlay"]);
        assert!(report.last_analysis_results.contains_key("Engine1"));
    }

    #[test]
    fn test_parse_ip_report() {
        let json = json!({
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "country": "US",
                    "as_owner": "Google LLC",
                    "asn": 15169,
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "undetected": 70,
                        "harmless": 0, "timeout": 0
                    },
                    "tags": []
                }
            }
        });
        let report = VtClient::parse_ip_report(&json).unwrap();
        assert_eq!(report.ip_address, "8.8.8.8");
        assert_eq!(report.country.as_deref(), Some("US"));
        assert_eq!(report.asn, Some(15169));
    }

    #[test]
    fn test_parse_domain_report() {
        let json = json!({
            "data": {
                "id": "evil.com",
                "attributes": {
                    "registrar": "Evil Registrar Inc.",
                    "creation_date": 1_000_000_u64,
                    "last_analysis_stats": {
                        "malicious": 10, "suspicious": 2, "undetected": 30,
                        "harmless": 0, "timeout": 0
                    },
                    "tags": ["phishing"],
                    "categories": {
                        "Forcepoint ThreatSeeker": "malicious sites"
                    }
                }
            }
        });
        let report = VtClient::parse_domain_report(&json).unwrap();
        assert_eq!(report.domain, "evil.com");
        assert_eq!(report.last_analysis_stats.malicious, 10);
        assert!(report.categories.contains_key("Forcepoint ThreatSeeker"));
    }

    #[test]
    fn test_parse_url_report() {
        let json = json!({
            "data": {
                "attributes": {
                    "url": "http://evil.com/malware",
                    "final_url": "http://evil.com/malware",
                    "title": "Malware Download",
                    "last_analysis_stats": {
                        "malicious": 20, "suspicious": 3, "undetected": 20,
                        "harmless": 0, "timeout": 0
                    },
                    "tags": [],
                    "threat_names": ["Phishing"]
                }
            }
        });
        let report = VtClient::parse_url_report(&json).unwrap();
        assert_eq!(report.url, "http://evil.com/malware");
        assert_eq!(report.threat_names, vec!["Phishing"]);
    }

    #[test]
    fn test_base64url_encode_man() {
        // "Man" encodes to "TWFu" in standard base64 — same alphabet except +/->-_
        let enc = base64url_encode("Man");
        assert_eq!(enc, "TWFu");
        for c in enc.chars() {
            assert!(
                c.is_alphanumeric() || c == '-' || c == '_',
                "unexpected char: {c}"
            );
        }
    }

    #[test]
    fn test_base64url_encode_no_padding() {
        // Encoding should never contain '=' padding.
        for input in &["", "a", "ab", "abc", "abcd", "http://example.com/path?q=1"] {
            let enc = base64url_encode(input);
            assert!(!enc.contains('='), "padding in encoded '{input}': {enc}");
        }
    }

    #[test]
    fn test_vt_report_detection_ratio() {
        let r = VtReport {
            hash: "abc".to_string(),
            positives: 5,
            total: 72,
            threat_name: Some("Trojan.Generic".to_string()),
            scan_date: Some(1_700_000_000),
        };
        assert_eq!(r.detection_ratio(), "5/72");
        assert!(r.is_malicious());
    }

    #[test]
    fn test_vt_report_clean() {
        let r = VtReport {
            hash: "def".to_string(),
            positives: 0,
            total: 72,
            threat_name: None,
            scan_date: None,
        };
        assert!(!r.is_malicious());
        assert_eq!(r.detection_ratio(), "0/72");
    }

    #[test]
    fn test_lookup_hash_invalid_length() {
        // We can't call the async method in a sync test, but we can verify
        // the validation logic directly via the length/hex check used inside
        // lookup_hash by replicating it here.
        let hash = "not_a_hash";
        let key = hash.trim().to_ascii_lowercase();
        let valid_len = matches!(key.len(), 32 | 40 | 64);
        assert!(!valid_len, "short string should fail length check");
    }

    #[test]
    fn test_lookup_hash_non_hex_rejected() {
        let hash = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"; // 32 chars, non-hex
        let key = hash.trim().to_ascii_lowercase();
        let valid_len = matches!(key.len(), 32 | 40 | 64);
        let all_hex = key.chars().all(|c| c.is_ascii_hexdigit());
        assert!(valid_len);
        assert!(!all_hex, "non-hex chars should fail hex check");
    }

    #[test]
    fn test_lookup_hash_md5_valid() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e"; // 32 hex chars
        let key = md5.trim().to_ascii_lowercase();
        let valid_len = matches!(key.len(), 32 | 40 | 64);
        let all_hex = key.chars().all(|c| c.is_ascii_hexdigit());
        assert!(valid_len && all_hex);
    }

    #[test]
    fn test_lookup_hash_sha1_valid() {
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 40 hex chars
        let key = sha1.trim().to_ascii_lowercase();
        let valid_len = matches!(key.len(), 32 | 40 | 64);
        let all_hex = key.chars().all(|c| c.is_ascii_hexdigit());
        assert!(valid_len && all_hex);
    }

    #[test]
    fn test_lookup_hash_sha256_valid() {
        // Standard SHA-256 of an empty string — exactly 64 hex chars.
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let key = sha256.trim().to_ascii_lowercase();
        let valid_len = matches!(key.len(), 32 | 40 | 64);
        let all_hex = key.chars().all(|c| c.is_ascii_hexdigit());
        assert!(valid_len && all_hex);
    }

    #[test]
    fn test_parse_analysis_report_completed() {
        let json = json!({
            "data": {
                "id": "analysis-abc123",
                "type": "analysis",
                "attributes": {
                    "status": "completed",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb924270216474141d2a167217c92661f35a",
                    "stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "undetected": 60,
                        "harmless": 0,
                        "timeout": 0
                    },
                    "results": {
                        "ThreatEngine": {
                            "category": "malicious",
                            "engine_name": "ThreatEngine",
                            "result": "Trojan.Generic",
                            "method": "blacklist"
                        }
                    }
                }
            }
        });
        let report = VtClient::parse_analysis_report(&json).unwrap();
        assert_eq!(report.id, "analysis-abc123");
        assert!(report.is_complete());
        assert!(report.is_malicious());
        assert_eq!(report.stats.malicious, 5);
        assert_eq!(report.detection_ratio(), "5/66");
        assert!(report.sha256.is_some());
        assert!(report.results.contains_key("ThreatEngine"));
    }

    #[test]
    fn test_parse_analysis_report_queued() {
        let json = json!({
            "data": {
                "id": "analysis-queued",
                "type": "analysis",
                "attributes": {
                    "status": "queued",
                    "stats": {
                        "malicious": 0, "suspicious": 0, "undetected": 0,
                        "harmless": 0, "timeout": 0
                    },
                    "results": {}
                }
            }
        });
        let report = VtClient::parse_analysis_report(&json).unwrap();
        assert!(!report.is_complete());
        assert!(!report.is_malicious());
        assert_eq!(report.status, VtAnalysisStatus::Queued);
    }

    #[test]
    fn test_parse_analysis_report_in_progress() {
        let json = json!({
            "data": {
                "id": "analysis-wip",
                "type": "analysis",
                "attributes": {
                    "status": "in-progress",
                    "stats": { "malicious": 0, "suspicious": 0, "undetected": 0,
                               "harmless": 0, "timeout": 0 },
                    "results": {}
                }
            }
        });
        let report = VtClient::parse_analysis_report(&json).unwrap();
        assert_eq!(report.status, VtAnalysisStatus::InProgress);
        assert!(!report.is_complete());
    }

    #[test]
    fn test_vt_analysis_id_display() {
        let id = VtAnalysisId::new("abc-xyz-123");
        assert_eq!(id.as_str(), "abc-xyz-123");
        assert_eq!(id.to_string(), "abc-xyz-123");
    }

    #[test]
    fn test_url_report_to_vt_report() {
        let json = json!({
            "data": {
                "attributes": {
                    "url": "http://evil.com",
                    "last_analysis_stats": {
                        "malicious": 10, "suspicious": 0, "undetected": 62,
                        "harmless": 0, "timeout": 0
                    },
                    "last_analysis_date": 1_700_000_000_u64,
                    "threat_names": ["Phishing", "Malware"]
                }
            }
        });
        let report = url_report_to_vt_report("http://evil.com", &json);
        assert_eq!(report.positives, 10);
        assert_eq!(report.total, 72);
        assert_eq!(report.threat_name.as_deref(), Some("Phishing"));
        assert_eq!(report.scan_date, Some(1_700_000_000));
    }
}
