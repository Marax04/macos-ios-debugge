//! `upstream` — Upstream proxy selection and connection-pool accounting.
//!
//! Provides:
//! - [`ConnectionPool`] — per-host limit accounting (no real socket pooling;
//!   the proxy itself owns the [`tokio::net::TcpStream`]s).
//! - [`UpstreamProxy`] — single upstream entry with optional basic-auth.
//! - [`UpstreamChain`] — an ordered chain of upstream proxies; traffic is
//!   forwarded through them in order (proxy-of-proxies).

use std::collections::HashMap;
use std::fmt;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::ProxyProtocol;

// ── ConnectionPool ────────────────────────────────────────────────────────────

/// A stub upstream connection pool.
#[derive(Debug, Default)]
pub struct ConnectionPool {
    active: Mutex<HashMap<String, usize>>,
    max_per_host: usize,
}

impl ConnectionPool {
    /// Create a pool with the given per-host maximum.
    #[must_use]
    pub fn new(max_per_host: usize) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            max_per_host,
        }
    }

    /// Attempt to allocate a connection slot for `host`.  Returns `false`
    /// if the per-host limit is exhausted.
    #[must_use]
    pub fn acquire(&self, host: &str) -> bool {
        let mut map = self.active.lock();
        let count = map.entry(host.to_string()).or_insert(0);
        if *count >= self.max_per_host {
            false
        } else {
            *count += 1;
            true
        }
    }

    /// Release a connection slot for `host`.
    pub fn release(&self, host: &str) {
        let mut map = self.active.lock();
        if let Some(c) = map.get_mut(host) {
            *c = c.saturating_sub(1);
        }
    }

    /// Return the number of active connections for `host`.
    #[must_use]
    pub fn active_for(&self, host: &str) -> usize {
        *self.active.lock().get(host).unwrap_or(&0)
    }

    /// Total active connections across all hosts.
    #[must_use]
    pub fn total_active(&self) -> usize {
        self.active.lock().values().sum()
    }
}

// ── UpstreamProxy ─────────────────────────────────────────────────────────────

/// An upstream proxy chain entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamProxy {
    pub host: String,
    pub port: u16,
    pub proto: ProxyProtocol,
    pub auth: Option<(String, String)>,
}

impl UpstreamProxy {
    /// Create a new upstream proxy entry.
    #[must_use]
    pub fn new(host: &str, port: u16, proto: ProxyProtocol) -> Self {
        Self {
            host: host.to_string(),
            port,
            proto,
            auth: None,
        }
    }

    /// Create with basic authentication.
    #[must_use]
    pub fn with_auth(mut self, username: &str, password: &str) -> Self {
        self.auth = Some((username.to_string(), password.to_string()));
        self
    }

    /// Return the `host:port` string.
    #[must_use]
    pub fn addr_str(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Returns `true` if authentication is configured.
    #[must_use]
    pub const fn has_auth(&self) -> bool {
        self.auth.is_some()
    }
}

impl fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.proto, self.host, self.port)
    }
}

// ── UpstreamChain ─────────────────────────────────────────────────────────────

/// A chain of upstream proxies.  Traffic is forwarded through them in order.
#[derive(Debug, Default, Clone)]
pub struct UpstreamChain {
    pub proxies: Vec<UpstreamProxy>,
}

impl UpstreamChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a proxy to the end of the chain.
    pub fn push(&mut self, proxy: UpstreamProxy) {
        self.proxies.push(proxy);
    }

    /// Returns `true` if the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Return the first proxy in the chain (the one to connect to first).
    #[must_use]
    pub fn first(&self) -> Option<&UpstreamProxy> {
        self.proxies.first()
    }

    /// Number of proxies in the chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.proxies.len()
    }
}
