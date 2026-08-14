//! `rustre-ti-shodan` — Shodan threat intelligence integration.
//!
//! Provides host enrichment, banner analysis, and exposure scoring using
//! the Shodan REST API.

pub mod shodan_host_enricher;
pub mod shodan_banner_analyzer;
pub mod shodan_exposure_scorer;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by Shodan operations.
#[derive(Debug, Error)]
pub enum ShodanError {
    #[error("http error: {0}")]
    Http(String),
    #[error("json error: {0}")]
    Json(String),
    #[error("rate limited")]
    RateLimited,
    #[error("auth error: {0}")]
    Auth(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid ip: {0}")]
    InvalidIp(String),
    #[error("api plan limit: {0}")]
    PlanLimit(String),
}

/// Shodan API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanConfig {
    /// Shodan API key.
    pub api_key: String,
    /// Base URL (default: `https://api.shodan.io`).
    pub base_url: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Whether to include raw banners in results.
    pub include_raw_banners: bool,
}

impl ShodanConfig {
    /// Create a config with the given API key and default settings.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://api.shodan.io".to_string(),
            timeout_secs: 30,
            include_raw_banners: false,
        }
    }

    /// Host info endpoint URL for an IP.
    ///
    /// The API key is percent-encoded so that keys containing special
    /// characters are not silently mis-transmitted.
    #[must_use]
    pub fn host_url(&self, ip: &str) -> String {
        // ip is already validated as IpAddr by callers, so only the key needs
        // encoding.
        format!(
            "{}/shodan/host/{ip}?key={}",
            self.base_url,
            crate::shodan_host_enricher::urlencode_pub(&self.api_key),
        )
    }

    /// Search endpoint URL.
    ///
    /// Both the API key and the query string are percent-encoded.
    #[must_use]
    pub fn search_url(&self, query: &str) -> String {
        format!(
            "{}/shodan/host/search?key={}&query={}",
            self.base_url,
            crate::shodan_host_enricher::urlencode_pub(&self.api_key),
            crate::shodan_host_enricher::urlencode_pub(query),
        )
    }
}

/// Common network port categories for exposure analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortCategory {
    /// Standard web ports (80, 443, 8080, 8443).
    Web,
    /// Database ports (1433, 3306, 5432, 27017, 6379, etc.).
    Database,
    /// Remote access ports (22, 23, 3389, 5900).
    RemoteAccess,
    /// File sharing ports (21, 445, 139).
    FileSharing,
    /// Industrial control ports (102, 502, 44818).
    Ics,
    /// Mail ports (25, 110, 143, 465, 587, 993, 995).
    Mail,
    /// DNS port (53).
    Dns,
    /// Other / unclassified.
    Other(u16),
}

impl PortCategory {
    /// Classify a port number.
    #[must_use]
    pub const fn from_port(port: u16) -> Self {
        match port {
            80 | 443 | 8080 | 8443 | 8000 | 8888 => Self::Web,
            1433 | 3306 | 5432 | 27017 | 6379 | 9200 | 9042 | 5984 => Self::Database,
            22 | 23 | 3389 | 5900 | 5901 => Self::RemoteAccess,
            21 | 445 | 139 => Self::FileSharing,
            102 | 502 | 44818 | 20000 | 47808 => Self::Ics,
            25 | 110 | 143 | 465 | 587 | 993 | 995 => Self::Mail,
            53 => Self::Dns,
            p => Self::Other(p),
        }
    }

    /// Risk weight for this category (higher = more dangerous exposed).
    #[must_use]
    pub const fn risk_weight(&self) -> u32 {
        match self {
            Self::RemoteAccess => 30,
            Self::Database => 25,
            Self::Ics => 35,
            Self::FileSharing => 20,
            Self::Mail => 10,
            Self::Web => 5,
            Self::Dns => 8,
            Self::Other(_) => 3,
        }
    }
}
