//! Error types for rustre-ti-vt.

use thiserror::Error;

/// All errors that can occur in the `VirusTotal` integration.
#[derive(Debug, Error)]
pub enum VtError {
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("rate limit exceeded — retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl VtError {
    /// Construct a `NotFound` error.
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::NotFound(what.into())
    }

    /// Construct an `InvalidResponse` error.
    pub fn invalid_response(msg: impl Into<String>) -> Self {
        Self::InvalidResponse(msg.into())
    }
}

impl From<VtError> for rustre_threatintel::TiError {
    fn from(e: VtError) -> Self {
        match e {
            VtError::NotFound(s) => Self::NotFound(s),
            VtError::Database(e) => Self::Database(e),
            VtError::Json(e) => Self::Serde(e),
            VtError::RateLimited { .. } => Self::RateLimit("virustotal".to_string()),
            VtError::Http { status, body } => {
                Self::Http(format!("HTTP {status}: {body}"))
            }
            VtError::Network(e) => Self::Other(e.to_string()),
            VtError::InvalidResponse(s) => Self::Parse(s),
        }
    }
}
