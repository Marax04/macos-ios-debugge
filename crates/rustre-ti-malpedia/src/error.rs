//! Error types for rustre-ti-malpedia.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MalpediaError {
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("mysql error: {0}")]
    Mysql(#[from] mysql::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl MalpediaError {
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::NotFound(what.into())
    }
}

impl From<MalpediaError> for rustre_threatintel::TiError {
    fn from(e: MalpediaError) -> Self {
        match e {
            MalpediaError::NotFound(s) => Self::NotFound(s),
            MalpediaError::Database(e) => Self::Database(e),
            MalpediaError::Json(e) => Self::Serde(e),
            MalpediaError::Mysql(e) => Self::Mysql(e.to_string()),
            MalpediaError::Http { status, body } => Self::Http(format!("HTTP {status}: {body}")),
            MalpediaError::Network(e) => Self::Other(e.to_string()),
            MalpediaError::InvalidInput(s) => Self::Parse(s),
        }
    }
}
