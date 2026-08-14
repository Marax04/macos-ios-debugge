//! `rustre-ti-opencti` — `OpenCTI` threat intelligence integration.
//!
//! Provides STIX object mapping, CTI report importing, and alert creation
//! against an `OpenCTI` platform instance via its `GraphQL` API.

pub mod opencti_client;
pub mod opencti_stix_mapper;
pub mod opencti_report_importer;
pub mod opencti_alert_creator;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by `OpenCTI` operations.
#[derive(Debug, Error)]
pub enum OpenCtiError {
    #[error("http error: {0}")]
    Http(String),
    #[error("graphql error: {0}")]
    GraphQL(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("auth error: {0}")]
    Auth(String),
}

/// `OpenCTI` platform configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCtiConfig {
    /// Base URL of the `OpenCTI` instance (e.g. `https://opencti.example.com`).
    pub base_url: String,
    /// API token for authentication.
    pub api_token: String,
    /// Optional organisation name for created objects.
    pub org_name: Option<String>,
    /// Timeout in seconds for HTTP requests.
    pub timeout_secs: u64,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
}

impl OpenCtiConfig {
    /// Create a new config pointing at the given URL with the given token.
    #[must_use]
    pub fn new(base_url: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_token: api_token.into(),
            org_name: None,
            timeout_secs: 30,
            verify_tls: true,
        }
    }

    /// Set the organisation name.
    #[must_use]
    pub fn with_org(mut self, org: impl Into<String>) -> Self {
        self.org_name = Some(org.into());
        self
    }

    /// GraphQL endpoint URL.
    #[must_use]
    pub fn graphql_url(&self) -> String {
        format!("{}/graphql", self.base_url.trim_end_matches('/'))
    }
}

/// Confidence level (0–100) for a CTI object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Confidence(pub u8);

impl Confidence {
    /// High confidence (≥ 75).
    pub const HIGH: Self = Self(85);
    /// Medium confidence (≈ 50).
    pub const MEDIUM: Self = Self(50);
    /// Low confidence (≤ 25).
    pub const LOW: Self = Self(25);

    /// Clamp to 0–100.
    #[must_use]
    pub fn new(v: u8) -> Self {
        Self(v.min(100))
    }

    /// Return the numeric value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Returns `true` if confidence is ≥ 75.
    #[must_use]
    pub const fn is_high(self) -> bool {
        self.0 >= 75
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
