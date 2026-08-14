//! Error types for the threat-intelligence crate.

use thiserror::Error;

/// All errors that can be produced by `rustre-threatintel`.
#[derive(Debug, Error)]
pub enum TiError {
    /// The requested `IoC` could not be found.
    #[error("IoC not found: {0}")]
    NotFound(String),

    /// An underlying `SQLite` database error.
    ///
    /// # Errors
    ///
    /// Propagated from `rusqlite` operations.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// An underlying `MySQL` database error (stored as a message string).
    #[error("mysql error: {0}")]
    Mysql(String),

    /// An HTTP-level error from a remote TI provider.
    #[error("http error: {0}")]
    Http(String),

    /// The configured rate limit for a provider was exceeded.
    #[error("rate limit exceeded for provider {0}")]
    RateLimit(String),

    /// The API key supplied for the named provider is invalid or revoked.
    #[error("invalid API key for {0}")]
    InvalidApiKey(String),

    /// A parse error while interpreting provider data.
    #[error("parse error: {0}")]
    Parse(String),

    /// A JSON serialisation / deserialisation error.
    ///
    /// # Errors
    ///
    /// Propagated from `serde_json` operations.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Any other error not covered by a specific variant.
    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for TiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
    }
}

#[cfg(feature = "mysql-backend")]
impl From<mysql::Error> for TiError {
    fn from(e: mysql::Error) -> Self {
        Self::Mysql(e.to_string())
    }
}
