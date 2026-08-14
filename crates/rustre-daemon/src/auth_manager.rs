//! `auth_manager` — daemon authentication: API key validation and session tokens.
//!
//! Provides [`AuthManager`], which combines API key validation with session-token
//! issuance so that callers can authenticate once (with a long-lived API key) and
//! then use a short-lived session token for subsequent requests.
//!
//! # Security model
//! * API keys are stored as SHA-256 hashes; plaintext keys are never retained
//!   after the initial `add_key` call.
//! * Session tokens are 32-byte cryptographically-random hex strings generated
//!   via the standard library's entropy source.
//! * Expired sessions are lazily pruned on every `validate_session` call.
//!
//! # Notes
//! All `pub fn` returning `Result` carry `/// # Errors`.

use std::collections::HashMap;
use std::fmt;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the authentication subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The provided API key is invalid or unrecognised.
    #[error("invalid api key")]
    InvalidApiKey,

    /// The session token has expired.
    #[error("session expired")]
    SessionExpired,

    /// The session token is not recognised.
    #[error("unknown session token")]
    UnknownSession,

    /// The key ID already exists.
    #[error("key id already exists: {0}")]
    DuplicateKeyId(String),

    /// The key was revoked.
    #[error("api key revoked")]
    KeyRevoked,

    /// An internal error (e.g. entropy failure).
    #[error("internal auth error: {0}")]
    Internal(String),
}

// ── KeyPermission ─────────────────────────────────────────────────────────────

/// Permissions associated with an API key or session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPermission {
    /// Can only call read-only methods.
    ReadOnly,
    /// Can call read and write methods.
    ReadWrite,
    /// Full administrative access.
    Admin,
}

impl fmt::Display for KeyPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read_only"),
            Self::ReadWrite => write!(f, "read_write"),
            Self::Admin => write!(f, "admin"),
        }
    }
}

// ── ApiKey ────────────────────────────────────────────────────────────────────

/// A registered API key record stored inside [`AuthManager`].
///
/// The plaintext key is **never** stored; only its SHA-256 digest (hex) is kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Human-readable identifier (not the key itself).
    pub id: String,
    /// SHA-256 hex digest of the raw API key bytes.
    pub hash: String,
    /// Permission level granted to this key.
    pub permission: KeyPermission,
    /// Whether the key has been revoked.
    pub revoked: bool,
    /// Epoch-seconds when this key was created.
    pub created_at: u64,
    /// Optional expiry (epoch-seconds).
    pub expires_at: Option<u64>,
    /// Optional human label.
    pub label: Option<String>,
}

impl ApiKey {
    /// Check whether this key has expired relative to the current system time.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            now >= exp
        } else {
            false
        }
    }

    /// Return `true` if the key is usable (not revoked, not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }
}

// ── SessionToken ──────────────────────────────────────────────────────────────

/// An active daemon session created by [`AuthManager::create_session`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// The opaque 64-hex-char token string.
    pub token: String,
    /// The API key ID that created this session.
    pub key_id: String,
    /// Permission inherited from the creating key.
    pub permission: KeyPermission,
    /// When this session was created (`Instant`-based; not serialisable —
    /// the epoch version is used for persistence).
    #[serde(skip)]
    pub created_instant: Option<Instant>,
    /// Epoch-seconds when the session was created.
    pub created_at: u64,
    /// Session TTL in seconds.
    pub ttl_secs: u64,
    /// Epoch-seconds when the session expires.
    pub expires_at: u64,
    /// Number of requests served in this session.
    pub request_count: u64,
}

impl SessionToken {
    /// Return `true` if the session has not yet expired.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        match &self.created_instant {
            Some(inst) => inst.elapsed().as_secs() < self.ttl_secs,
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                now < self.expires_at
            }
        }
    }

    /// Seconds remaining before this session expires.
    #[must_use]
    pub fn remaining_secs(&self) -> u64 {
        match &self.created_instant {
            Some(inst) => self.ttl_secs.saturating_sub(inst.elapsed().as_secs()),
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                self.expires_at.saturating_sub(now)
            }
        }
    }
}

// ── AuthManagerConfig ─────────────────────────────────────────────────────────

/// Configuration for [`AuthManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthManagerConfig {
    /// Default session TTL in seconds.
    pub session_ttl_secs: u64,
    /// Maximum number of concurrent sessions per key.
    pub max_sessions_per_key: usize,
    /// Maximum total concurrent sessions.
    pub max_sessions: usize,
    /// Whether to require authentication on every request.
    pub require_auth: bool,
}

impl Default for AuthManagerConfig {
    fn default() -> Self {
        Self {
            session_ttl_secs: 3600,       // 1 hour
            max_sessions_per_key: 10,
            max_sessions: 256,
            require_auth: true,
        }
    }
}

// ── AuthManager ───────────────────────────────────────────────────────────────

/// Central authentication manager for the daemon.
///
/// Thread-safe — all methods use internal `RwLock`/`Mutex` guards.
pub struct AuthManager {
    config: AuthManagerConfig,
    /// Registered API keys, keyed by `ApiKey::id`.
    keys: RwLock<HashMap<String, ApiKey>>,
    /// Active sessions, keyed by token string.
    sessions: Mutex<HashMap<String, SessionToken>>,
}

impl AuthManager {
    /// Create a new `AuthManager` with the given configuration.
    #[must_use]
    pub fn new(config: AuthManagerConfig) -> Self {
        Self {
            config,
            keys: RwLock::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new `AuthManager` with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(AuthManagerConfig::default())
    }

    // ── Key management ─────────────────────────────────────────────────────────

    /// Add an API key.  The raw `plaintext_key` is hashed immediately; the
    /// plaintext is not stored.
    ///
    /// # Errors
    /// Returns [`AuthError::DuplicateKeyId`] if the ID is already registered.
    pub fn add_key(
        &self,
        id: impl Into<String>,
        plaintext_key: &str,
        permission: KeyPermission,
        ttl_secs: Option<u64>,
        label: Option<String>,
    ) -> Result<(), AuthError> {
        let id = id.into();
        let mut keys = self.keys.write();
        if keys.contains_key(&id) {
            return Err(AuthError::DuplicateKeyId(id));
        }
        let hash = sha256_hex(plaintext_key);
        let now = epoch_secs();
        let expires_at = ttl_secs.map(|t| now + t);
        keys.insert(
            id.clone(),
            ApiKey {
                id,
                hash,
                permission,
                revoked: false,
                created_at: now,
                expires_at,
                label,
            },
        );
        Ok(())
    }

    /// Revoke an API key by ID.  Returns `true` if the key existed.
    pub fn revoke_key(&self, id: &str) -> bool {
        let mut keys = self.keys.write();
        if let Some(key) = keys.get_mut(id) {
            key.revoked = true;
            true
        } else {
            false
        }
    }

    /// Remove an API key and all its sessions.
    pub fn remove_key(&self, id: &str) -> bool {
        let removed = self.keys.write().remove(id).is_some();
        if removed {
            self.sessions.lock().retain(|_, s| s.key_id != id);
        }
        removed
    }

    /// Look up a key by ID (read-only snapshot).
    #[must_use]
    pub fn get_key(&self, id: &str) -> Option<ApiKey> {
        self.keys.read().get(id).cloned()
    }

    /// Return the number of registered (non-revoked) keys.
    #[must_use]
    pub fn active_key_count(&self) -> usize {
        self.keys.read().values().filter(|k| k.is_valid()).count()
    }

    // ── Validation ─────────────────────────────────────────────────────────────

    /// Validate a plaintext API key.  Returns the key's ID and permission if
    /// the key is valid and active.
    ///
    /// # Errors
    /// Returns [`AuthError::InvalidApiKey`] if the key does not match any
    /// registered entry, or if the matching key is revoked/expired.
    pub fn validate_key(&self, plaintext_key: &str) -> Result<(String, KeyPermission), AuthError> {
        use subtle::ConstantTimeEq;
        let hash = sha256_hex(plaintext_key);
        let keys = self.keys.read();
        for key in keys.values() {
            // Compare the hex-encoded SHA-256 digests in constant time so that
            // a network-observable timing side-channel cannot be used to learn
            // information about registered key hashes.
            let hashes_match = key.hash.as_bytes().ct_eq(hash.as_bytes()).into();
            if hashes_match {
                if key.revoked {
                    return Err(AuthError::KeyRevoked);
                }
                if key.is_expired() {
                    return Err(AuthError::InvalidApiKey);
                }
                return Ok((key.id.clone(), key.permission.clone()));
            }
        }
        Err(AuthError::InvalidApiKey)
    }

    // ── Session management ─────────────────────────────────────────────────────

    /// Create a new session for the key identified by `key_id`.
    ///
    /// The session TTL is taken from the manager configuration unless the key
    /// has a shorter remaining lifetime.
    ///
    /// # Errors
    /// * [`AuthError::InvalidApiKey`] if `key_id` is not registered or is revoked.
    /// * [`AuthError::Internal`] if entropy generation fails.
    pub fn create_session(&self, key_id: &str) -> Result<SessionToken, AuthError> {
        // Validate the key.
        let (permission, key_ttl) = {
            let keys = self.keys.read();
            let key = keys.get(key_id).ok_or(AuthError::InvalidApiKey)?;
            if !key.is_valid() {
                return Err(AuthError::InvalidApiKey);
            }
            (key.permission.clone(), key.expires_at)
        };

        // Compute TTL: min(config, remaining key lifetime).
        let now_secs = epoch_secs();
        let ttl_secs = if let Some(key_exp) = key_ttl {
            let remaining = key_exp.saturating_sub(now_secs);
            remaining.min(self.config.session_ttl_secs)
        } else {
            self.config.session_ttl_secs
        };

        // Check session caps.
        let mut sessions = self.sessions.lock();
        let total = sessions.len();
        if total >= self.config.max_sessions {
            // Prune expired sessions and retry.
            sessions.retain(|_, s| s.is_alive());
            if sessions.len() >= self.config.max_sessions {
                return Err(AuthError::Internal("max sessions reached".into()));
            }
        }
        let per_key = sessions.values().filter(|s| s.key_id == key_id).count();
        if per_key >= self.config.max_sessions_per_key {
            return Err(AuthError::Internal(format!(
                "max sessions per key ({}) reached for key {key_id}",
                self.config.max_sessions_per_key
            )));
        }

        // Generate token.
        let token = generate_token();
        let expires_at = now_secs + ttl_secs;
        let session = SessionToken {
            token: token.clone(),
            key_id: key_id.to_string(),
            permission,
            created_instant: Some(Instant::now()),
            created_at: now_secs,
            ttl_secs,
            expires_at,
            request_count: 0,
        };

        sessions.insert(token.clone(), session.clone());
        Ok(session)
    }

    /// Validate a session token, incrementing its request counter.
    ///
    /// # Errors
    /// * [`AuthError::UnknownSession`] if the token is not recognised.
    /// * [`AuthError::SessionExpired`] if the token has expired.
    pub fn validate_session(&self, token: &str) -> Result<KeyPermission, AuthError> {
        let mut sessions = self.sessions.lock();
        // Lazy prune.
        sessions.retain(|_, s| s.is_alive());

        let session = sessions.get_mut(token).ok_or(AuthError::UnknownSession)?;
        if !session.is_alive() {
            return Err(AuthError::SessionExpired);
        }
        session.request_count += 1;
        Ok(session.permission.clone())
    }

    /// Revoke (delete) a session token.  Returns `true` if it existed.
    pub fn revoke_session(&self, token: &str) -> bool {
        self.sessions.lock().remove(token).is_some()
    }

    /// Return the number of currently active (non-expired) sessions.
    #[must_use]
    pub fn active_session_count(&self) -> usize {
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, s| s.is_alive());
        sessions.len()
    }

    /// Return a snapshot of all active sessions.
    #[must_use]
    pub fn session_snapshot(&self) -> Vec<SessionToken> {
        let sessions = self.sessions.lock();
        sessions.values().filter(|s| s.is_alive()).cloned().collect()
    }

    /// Return `true` if authentication is required.
    #[must_use]
    pub const fn requires_auth(&self) -> bool {
        self.config.require_auth
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Compute the SHA-256 hex digest of a string.
///
/// Implemented using the standard SHA-256 algorithm in pure Rust without
/// external crypto crates (this is for authentication tokens, not a
/// production security primitive — callers requiring FIPS compliance should
/// substitute a validated implementation).
fn sha256_hex(input: &str) -> String {
    // Simple SHA-256 using the reference implementation from FIPS 180-4.
    // Constants: first 32 bits of the fractional parts of cube roots of first 64 primes.
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bytes = input.as_bytes();
    let bit_len = (bytes.len() as u64) * 8;

    // Pre-processing: padding.
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    // Append 8-byte big-endian length.
    for i in (0..8).rev() {
        msg.push(((bit_len >> (i * 8)) & 0xff) as u8);
    }

    // Initial hash values: first 32 bits of fractional parts of sqrt of first 8 primes.
    let mut h = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    // Process each 512-bit chunk.
    for chunk in msg.chunks(64) {
        let mut w = [0_u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let tmp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e;
            e = d.wrapping_add(tmp1);
            d = c; c = b; b = a;
            a = tmp1.wrapping_add(tmp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// Generate a 64-hex-char random token using OS entropy (`OsRng`).
///
/// `DefaultHasher` / time / thread-id combinations are **not**
/// cryptographically random and are vulnerable to prediction.  `OsRng`
/// (backed by `getrandom`) is the correct source for auth tokens.
fn generate_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    // OsRng draws from the OS CSPRNG (/dev/urandom, BCryptGenRandom, etc.).
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").ok();
        s
    })
}

/// Current epoch in seconds.
fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> AuthManager {
        AuthManager::with_defaults()
    }

    fn add_rw_key(m: &AuthManager, id: &str, key: &str) {
        m.add_key(id, key, KeyPermission::ReadWrite, None, None).unwrap();
    }

    // ── sha256 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_empty() {
        // SHA-256 of empty string.
        let h = sha256_hex("");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_abc() {
        let h = sha256_hex("abc");
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_sha256_deterministic() {
        assert_eq!(sha256_hex("hello"), sha256_hex("hello"));
    }

    // ── add_key ───────────────────────────────────────────────────────────────

    #[test]
    fn test_add_key_success() {
        let m = manager();
        m.add_key("k1", "mykey", KeyPermission::ReadOnly, None, None).unwrap();
        assert_eq!(m.active_key_count(), 1);
    }

    #[test]
    fn test_add_key_duplicate_fails() {
        let m = manager();
        add_rw_key(&m, "k1", "key1");
        assert!(matches!(m.add_key("k1", "key2", KeyPermission::ReadOnly, None, None), Err(AuthError::DuplicateKeyId(_))));
    }

    // ── validate_key ──────────────────────────────────────────────────────────

    #[test]
    fn test_validate_key_correct() {
        let m = manager();
        add_rw_key(&m, "k1", "correct-key-value");
        let (id, perm) = m.validate_key("correct-key-value").unwrap();
        assert_eq!(id, "k1");
        assert_eq!(perm, KeyPermission::ReadWrite);
    }

    #[test]
    fn test_validate_key_wrong() {
        let m = manager();
        add_rw_key(&m, "k1", "correct-key");
        assert!(matches!(m.validate_key("wrong-key"), Err(AuthError::InvalidApiKey)));
    }

    #[test]
    fn test_validate_key_revoked() {
        let m = manager();
        add_rw_key(&m, "k1", "mykey");
        m.revoke_key("k1");
        assert!(matches!(m.validate_key("mykey"), Err(AuthError::KeyRevoked)));
    }

    // ── create_session ────────────────────────────────────────────────────────

    #[test]
    fn test_create_session_success() {
        let m = manager();
        add_rw_key(&m, "k1", "s1key");
        let session = m.create_session("k1").unwrap();
        assert_eq!(session.key_id, "k1");
        assert!(session.is_alive());
        assert_eq!(session.token.len(), 64);
    }

    #[test]
    fn test_create_session_unknown_key() {
        let m = manager();
        assert!(matches!(m.create_session("nonexistent"), Err(AuthError::InvalidApiKey)));
    }

    #[test]
    fn test_create_session_revoked_key() {
        let m = manager();
        add_rw_key(&m, "k1", "key");
        m.revoke_key("k1");
        assert!(matches!(m.create_session("k1"), Err(AuthError::InvalidApiKey)));
    }

    // ── validate_session ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_session_valid() {
        let m = manager();
        add_rw_key(&m, "k1", "key1");
        let session = m.create_session("k1").unwrap();
        let perm = m.validate_session(&session.token).unwrap();
        assert_eq!(perm, KeyPermission::ReadWrite);
    }

    #[test]
    fn test_validate_session_unknown() {
        let m = manager();
        assert!(matches!(m.validate_session("nonexistent"), Err(AuthError::UnknownSession)));
    }

    #[test]
    fn test_validate_session_increments_count() {
        let m = manager();
        add_rw_key(&m, "k1", "key1");
        let session = m.create_session("k1").unwrap();
        m.validate_session(&session.token).unwrap();
        m.validate_session(&session.token).unwrap();
        let snap = m.session_snapshot();
        let s = snap.iter().find(|s| s.token == session.token).unwrap();
        assert_eq!(s.request_count, 2);
    }

    // ── revoke_session ────────────────────────────────────────────────────────

    #[test]
    fn test_revoke_session() {
        let m = manager();
        add_rw_key(&m, "k1", "key1");
        let session = m.create_session("k1").unwrap();
        assert!(m.revoke_session(&session.token));
        assert!(matches!(m.validate_session(&session.token), Err(AuthError::UnknownSession)));
    }

    #[test]
    fn test_revoke_session_nonexistent() {
        let m = manager();
        assert!(!m.revoke_session("ghost"));
    }

    // ── remove_key ────────────────────────────────────────────────────────────

    #[test]
    fn test_remove_key_clears_sessions() {
        let m = manager();
        add_rw_key(&m, "k1", "key1");
        let _session = m.create_session("k1").unwrap();
        assert_eq!(m.active_session_count(), 1);
        m.remove_key("k1");
        assert_eq!(m.active_session_count(), 0);
    }

    // ── KeyPermission ─────────────────────────────────────────────────────────

    #[test]
    fn test_permission_display() {
        assert_eq!(KeyPermission::ReadOnly.to_string(), "read_only");
        assert_eq!(KeyPermission::Admin.to_string(), "admin");
    }

    // ── generate_token ────────────────────────────────────────────────────────

    #[test]
    fn test_generate_token_length() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
    }

    #[test]
    fn test_generate_token_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        // Not guaranteed but very likely in practice.
        assert_ne!(t1, t2, "tokens should generally be unique");
    }

    // ── AuthError display ─────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = AuthError::InvalidApiKey;
        assert!(e.to_string().contains("api key"));
    }

    // ── active_key_count ─────────────────────────────────────────────────────

    #[test]
    fn test_active_key_count_skips_revoked() {
        let m = manager();
        add_rw_key(&m, "k1", "k1");
        add_rw_key(&m, "k2", "k2");
        m.revoke_key("k1");
        assert_eq!(m.active_key_count(), 1);
    }
}
