//! `rustre-ti-otx` — `AlienVault` OTX (Open Threat Exchange) integration.
//!
//! Provides pulse parsing, IOC extraction, and subscription management
//! against the OTX `DirectConnect` and REST APIs.

pub mod otx_pulse_parser;
pub mod otx_ioc_extractor;
pub mod otx_subscription_manager;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by OTX operations.
#[derive(Debug, Error)]
pub enum OtxError {
    #[error("http error: {0}")]
    Http(String),
    #[error("json error: {0}")]
    Json(String),
    #[error("rate limited: retry after {0} seconds")]
    RateLimited(u64),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// OTX API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxConfig {
    /// OTX `DirectConnect` API key.
    pub api_key: String,
    /// Base URL (default: `https://otx.alienvault.com`).
    pub base_url: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum number of pulses to retrieve per page.
    pub page_size: u32,
}

impl OtxConfig {
    /// Create a config with the given API key and default settings.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://otx.alienvault.com".to_string(),
            timeout_secs: 30,
            page_size: 50,
        }
    }

    /// Pulse endpoint URL.
    #[must_use]
    pub fn pulse_url(&self, pulse_id: &str) -> String {
        format!("{}/api/v1/pulses/{pulse_id}", self.base_url)
    }

    /// Subscribed pulses URL.
    #[must_use]
    pub fn subscribed_url(&self) -> String {
        format!("{}/api/v1/pulses/subscribed", self.base_url)
    }
}

/// Threat level reported in an OTX pulse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl ThreatLevel {
    /// Parse from the integer 1–4 returned by the OTX API.
    #[must_use]
    pub const fn from_int(v: u8) -> Self {
        match v {
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            4 => Self::Critical,
            _ => Self::Unknown,
        }
    }

    /// Numeric severity (1–4, 0 for unknown).
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}
