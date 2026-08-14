//! Error types for rustre-ti-misp.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MispError {
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("mysql error: {0}")]
    Mysql(#[from] mysql::Error),

    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("auth error: invalid API key")]
    AuthError,

    #[error("env var missing: {0}")]
    EnvVar(String),
}

impl MispError {
    pub fn not_found(what: impl Into<String>) -> Self {
        Self::NotFound(what.into())
    }

    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }
}

impl From<MispError> for rustre_threatintel::TiError {
    fn from(e: MispError) -> Self {
        match e {
            MispError::NotFound(s) => Self::NotFound(s),
            MispError::Database(e) => Self::Database(e),
            MispError::Json(e) => Self::Serde(e),
            MispError::Mysql(e) => Self::Mysql(e.to_string()),
            MispError::AuthError => Self::InvalidApiKey("misp".to_string()),
            MispError::Http { status, body } => Self::Http(format!("HTTP {status}: {body}")),
            MispError::Network(e) => Self::Other(e.to_string()),
            MispError::Reqwest(e) => Self::Http(e.to_string()),
            MispError::InvalidInput(s) => Self::Parse(s),
            MispError::EnvVar(s) => Self::Other(format!("missing env var: {s}")),
        }
    }
}
