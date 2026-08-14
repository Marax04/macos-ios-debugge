//! `federation_registry` — Registry of federated MCP servers.
//!
//! Handles automatic discovery (config file, environment, mDNS/DNS-SD), multiplexed
//! connections, health checking, capability negotiation, version-compatibility checks,
//! and reconnection with exponential back-off.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::{ExternalServerConfig, HealthStatus, ServerTransport};

// ─────────────────────────────────────────────────────────────────────────────
// Version / ProtocolVersion
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic version of the MCP protocol spoken by a server.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ProtocolVersion {
    /// Parse from `"major.minor.patch"`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some(Self { major, minor, patch })
    }

    /// Returns `true` when `other` is backward-compatible with `self`.
    ///
    /// Compatibility rule: same major version, other minor >= self minor.
    #[must_use]
    pub const fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major && other.minor >= self.minor
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self { major: 1, minor: 0, patch: 0 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability set
// ─────────────────────────────────────────────────────────────────────────────

/// A negotiated capability set for a server connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub tools: Vec<String>,
    pub resources: Vec<String>,
    pub prompts: Vec<String>,
    pub supports_streaming: bool,
    pub supports_progress: bool,
    pub supports_cancellation: bool,
    pub experimental: HashMap<String, serde_json::Value>,
}

impl CapabilitySet {
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t == name)
    }

    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Merge another capability set into this one (union).
    pub fn merge(&mut self, other: &CapabilitySet) {
        for t in &other.tools {
            if !self.tools.contains(t) {
                self.tools.push(t.clone());
            }
        }
        for r in &other.resources {
            if !self.resources.contains(r) {
                self.resources.push(r.clone());
            }
        }
        self.supports_streaming |= other.supports_streaming;
        self.supports_progress |= other.supports_progress;
        self.supports_cancellation |= other.supports_cancellation;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Connection state of a registered server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Failed { reason: String },
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Reconnecting { attempt } => write!(f, "reconnecting(attempt={attempt})"),
            Self::Failed { reason } => write!(f, "failed({reason})"),
        }
    }
}

/// A single entry in the federation registry.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Unique ID assigned at registration time.
    pub id: Uuid,
    /// Server configuration (name, transport, tags, …).
    pub config: ExternalServerConfig,
    /// Current connection state.
    pub state: ConnectionState,
    /// Negotiated protocol version (set after successful handshake).
    pub protocol_version: Option<ProtocolVersion>,
    /// Capabilities reported by the server after initialization.
    pub capabilities: CapabilitySet,
    /// Health status from the last health check.
    pub health: HealthStatus,
    /// Timestamp of last successful health check.
    pub last_healthy_at: Option<Instant>,
    /// Consecutive health-check failures.
    pub consecutive_failures: u32,
    /// Next reconnect attempt time (used for back-off).
    pub next_reconnect_at: Option<Instant>,
    /// Back-off exponent (doubles each failure, capped at 5 min).
    pub backoff_exp: u32,
    /// Source that discovered this server.
    pub discovery_source: DiscoverySource,
}

impl RegistryEntry {
    /// Create a new entry from config with sane defaults.
    #[must_use]
    pub fn new(config: ExternalServerConfig, source: DiscoverySource) -> Self {
        Self {
            id: Uuid::new_v4(),
            config,
            state: ConnectionState::Disconnected,
            protocol_version: None,
            capabilities: CapabilitySet::default(),
            health: HealthStatus::Unknown,
            last_healthy_at: None,
            consecutive_failures: 0,
            next_reconnect_at: None,
            backoff_exp: 0,
            discovery_source: source,
        }
    }

    /// Compute the next back-off duration (exponential, capped at 5 min).
    #[must_use]
    pub fn backoff_duration(&self) -> Duration {
        let base_secs = 1u64 << self.backoff_exp.min(8); // 1s, 2s, 4s … 256s
        Duration::from_secs(base_secs.min(300))
    }

    /// Advance backoff exponent and schedule next reconnect.
    pub fn schedule_reconnect(&mut self) {
        let delay = self.backoff_duration();
        self.next_reconnect_at = Some(Instant::now() + delay);
        self.backoff_exp = (self.backoff_exp + 1).min(8);
        self.consecutive_failures += 1;
    }

    /// Reset back-off on a successful connection.
    pub fn reset_backoff(&mut self) {
        self.backoff_exp = 0;
        self.consecutive_failures = 0;
        self.next_reconnect_at = None;
        self.last_healthy_at = Some(Instant::now());
        self.health = HealthStatus::Healthy;
        self.state = ConnectionState::Connected;
    }

    /// Returns `true` when a reconnect is due (or no reconnect is scheduled).
    #[must_use]
    pub fn reconnect_due(&self) -> bool {
        self.next_reconnect_at
            .map(|t| Instant::now() >= t)
            .unwrap_or(true)
    }

    /// Returns `true` when the server is considered available.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self.state, ConnectionState::Connected)
            && matches!(self.health, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiscoverySource
// ─────────────────────────────────────────────────────────────────────────────

/// Where a server entry was discovered from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// Loaded from `~/.config/rustre/mcp-servers.json` or a custom config file.
    ConfigFile { path: String },
    /// Provided via `RUSTRE_MCP_SERVERS` environment variable.
    Environment,
    /// Discovered via mDNS/DNS-SD advertisement.
    Mdns { service_type: String },
    /// Manually registered at runtime via the API.
    Manual,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigFile { path } => write!(f, "config:{path}"),
            Self::Environment => write!(f, "env:RUSTRE_MCP_SERVERS"),
            Self::Mdns { service_type } => write!(f, "mdns:{service_type}"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiscoveryConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Settings controlling the auto-discovery mechanisms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Path to the JSON config file (`~/.config/rustre/mcp-servers.json` by default).
    pub config_file: Option<String>,
    /// Whether to scan `RUSTRE_MCP_SERVERS` environment variable.
    pub scan_env: bool,
    /// Whether to run mDNS/DNS-SD discovery.
    pub enable_mdns: bool,
    /// mDNS service type to look for.
    pub mdns_service_type: String,
    /// How often to repeat discovery.
    pub discovery_interval: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            config_file: default_config_path(),
            scan_env: true,
            enable_mdns: false,
            mdns_service_type: "_mcp._tcp.local.".to_string(),
            discovery_interval: Duration::from_secs(60),
        }
    }
}

fn default_config_path() -> Option<String> {
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.config/rustre/mcp-servers.json"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|a| format!("{a}\\rustre\\mcp-servers.json"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JsonConfigFile — the on-disk format
// ─────────────────────────────────────────────────────────────────────────────

/// On-disk format for `~/.config/rustre/mcp-servers.json`.
#[derive(Debug, Default, Deserialize)]
pub struct JsonConfigFile {
    pub servers: Vec<JsonServerEntry>,
}

#[derive(Debug, Deserialize)]
pub struct JsonServerEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type")]
    pub transport_type: String,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "bool_true")]
    pub enabled: bool,
}

fn bool_true() -> bool { true }

impl JsonServerEntry {
    /// Convert to [`ExternalServerConfig`] (returns `None` on bad config).
    #[must_use]
    pub fn to_server_config(&self) -> Option<ExternalServerConfig> {
        let transport = match self.transport_type.as_str() {
            "stdio" => ServerTransport::Stdio {
                command: self.command.clone()?,
                args: self.args.clone().unwrap_or_default(),
                env: HashMap::new(),
            },
            "sse_http" | "http" => ServerTransport::SseHttp {
                url: self.url.clone()?,
                headers: HashMap::new(),
                timeout_secs: 30,
            },
            "websocket" | "ws" => ServerTransport::WebSocket {
                url: self.url.clone()?,
                headers: HashMap::new(),
            },
            _ => return None,
        };
        Some(ExternalServerConfig {
            name: self.name.clone(),
            description: self.description.clone(),
            transport,
            tags: self.tags.clone(),
            enabled: self.enabled,
            health_check_interval_secs: 60,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry of all federated MCP servers.
///
/// Thread-safe: all mutations go through `Arc<FederationRegistry>`.
pub struct FederationRegistry {
    /// All registered servers, keyed by server name.
    entries: DashMap<String, RegistryEntry>,
    /// Discovery configuration.
    discovery_cfg: RwLock<DiscoveryConfig>,
    /// Required protocol version range.
    min_protocol: ProtocolVersion,
    /// Aggregated capability view across all connected servers.
    merged_caps: Mutex<CapabilitySet>,
    /// How many health-check failures before marking Unhealthy.
    unhealthy_threshold: u32,
}

impl FederationRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            discovery_cfg: RwLock::new(DiscoveryConfig::default()),
            min_protocol: ProtocolVersion { major: 1, minor: 0, patch: 0 },
            merged_caps: Mutex::new(CapabilitySet::default()),
            unhealthy_threshold: 3,
        })
    }

    /// Register a server from config.
    pub fn register(&self, config: ExternalServerConfig, source: DiscoverySource) -> Uuid {
        let entry = RegistryEntry::new(config.clone(), source);
        let id = entry.id;
        self.entries.insert(config.name.clone(), entry);
        id
    }

    /// Deregister a server by name.
    pub fn deregister(&self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    /// Look up a server entry by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<RegistryEntry> {
        self.entries.get(name).map(|e| e.clone())
    }

    /// List names of all registered servers.
    #[must_use]
    pub fn server_names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.key().clone()).collect()
    }

    /// List names of all available (connected + healthy) servers.
    #[must_use]
    pub fn available_servers(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| e.value().is_available())
            .map(|e| e.key().clone())
            .collect()
    }

    /// Update connection state for a server.
    pub fn set_state(&self, name: &str, state: ConnectionState) {
        if let Some(mut e) = self.entries.get_mut(name) {
            e.state = state;
        }
    }

    /// Record a health check result.
    pub fn record_health(&self, name: &str, ok: bool) {
        if let Some(mut e) = self.entries.get_mut(name) {
            if ok {
                e.reset_backoff();
            } else {
                e.consecutive_failures += 1;
                e.health = if e.consecutive_failures >= self.unhealthy_threshold {
                    HealthStatus::Unhealthy
                } else {
                    HealthStatus::Degraded
                };
                e.schedule_reconnect();
            }
        }
    }

    /// Store negotiated capabilities for a server.
    pub async fn store_capabilities(&self, name: &str, caps: CapabilitySet) {
        if let Some(mut e) = self.entries.get_mut(name) {
            e.capabilities = caps.clone();
        }
        // Rebuild merged capability set
        let mut merged = self.merged_caps.lock().await;
        merged.tools.clear();
        merged.resources.clear();
        for entry in self.entries.iter() {
            if entry.value().is_available() {
                merged.merge(&entry.value().capabilities);
            }
        }
    }

    /// Get the merged capabilities of all available servers.
    pub async fn merged_capabilities(&self) -> CapabilitySet {
        self.merged_caps.lock().await.clone()
    }

    /// Store the negotiated protocol version for a server.
    pub fn store_protocol_version(&self, name: &str, version: ProtocolVersion) {
        if let Some(mut e) = self.entries.get_mut(name) {
            e.protocol_version = Some(version);
        }
    }

    /// Verify a server's protocol version against the registry minimum.
    ///
    /// Returns `Ok(())` when compatible, `Err(reason)` otherwise.
    pub fn check_version_compat(&self, name: &str) -> Result<(), String> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| format!("server '{name}' not registered"))?;
        match &entry.protocol_version {
            None => Err(format!("server '{name}' has no negotiated protocol version")),
            Some(v) => {
                if self.min_protocol.is_compatible(v) {
                    Ok(())
                } else {
                    Err(format!(
                        "server '{name}' protocol {v} incompatible with minimum {}",
                        self.min_protocol
                    ))
                }
            }
        }
    }

    /// Run discovery from all configured sources.
    ///
    /// Returns a list of newly discovered server configs.
    pub async fn discover(&self) -> Vec<ExternalServerConfig> {
        let cfg = self.discovery_cfg.read().await.clone();
        let mut discovered = Vec::new();

        // 1. Config file
        if let Some(ref path) = cfg.config_file {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                if let Ok(parsed) = serde_json::from_str::<JsonConfigFile>(&content) {
                    for entry in parsed.servers {
                        if let Some(sc) = entry.to_server_config() {
                            if !self.entries.contains_key(&sc.name) {
                                discovered.push(sc);
                            }
                        }
                    }
                }
            }
        }

        // 2. Environment variable RUSTRE_MCP_SERVERS
        if cfg.scan_env {
            if let Ok(val) = std::env::var("RUSTRE_MCP_SERVERS") {
                // Expect a JSON array of server configs or comma-separated URLs
                if let Ok(parsed) = serde_json::from_str::<Vec<JsonServerEntry>>(&val) {
                    for entry in parsed {
                        if let Some(sc) = entry.to_server_config() {
                            if !self.entries.contains_key(&sc.name) {
                                discovered.push(sc);
                            }
                        }
                    }
                } else {
                    // Fallback: comma-separated "name=url" pairs
                    for pair in val.split(',') {
                        let pair = pair.trim();
                        if let Some((name, url)) = pair.split_once('=') {
                            let sc = ExternalServerConfig::new_http(name.trim(), url.trim());
                            if !self.entries.contains_key(&sc.name) {
                                discovered.push(sc);
                            }
                        }
                    }
                }
            }
        }

        // 3. mDNS (stub — real implementation would use `mdns-sd` crate)
        if cfg.enable_mdns {
            // In a real implementation:
            // let mdns = ServiceDaemon::new()?;
            // let receiver = mdns.browse(&cfg.mdns_service_type)?;
            // collect advertisements for 500ms …
            // For now we just log intent.
            tracing_stub("mdns discovery would run here");
        }

        discovered
    }

    /// Register all newly discovered servers.
    pub async fn run_discovery(&self) {
        let found = self.discover().await;
        for sc in found {
            self.register(sc, DiscoverySource::ConfigFile { path: "auto".to_string() });
        }
    }

    /// Return entries that are due for a reconnect attempt.
    #[must_use]
    pub fn servers_due_reconnect(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| {
                let v = e.value();
                !matches!(v.state, ConnectionState::Connected)
                    && v.config.enabled
                    && v.reconnect_due()
            })
            .map(|e| e.key().clone())
            .collect()
    }

    /// Total number of registered servers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no servers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Registry health summary.
    #[must_use]
    pub fn health_summary(&self) -> RegistryHealthSummary {
        let total = self.entries.len();
        let connected = self.entries.iter().filter(|e| e.value().is_available()).count();
        let degraded = self.entries.iter().filter(|e| {
            matches!(e.value().health, HealthStatus::Degraded)
        }).count();
        let failed = self.entries.iter().filter(|e| {
            matches!(e.value().state, ConnectionState::Failed { .. })
        }).count();
        RegistryHealthSummary { total, connected, degraded, failed }
    }
}

/// Stub for tracing — keeps this module dependency-free of the full tracing setup.
fn tracing_stub(_msg: &str) {
    // In production, replace with: tracing::debug!("{}", msg);
}

impl Default for FederationRegistry {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            discovery_cfg: RwLock::new(DiscoveryConfig::default()),
            min_protocol: ProtocolVersion::default(),
            merged_caps: Mutex::new(CapabilitySet::default()),
            unhealthy_threshold: 3,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryHealthSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of the registry's overall health.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryHealthSummary {
    pub total: usize,
    pub connected: usize,
    pub degraded: usize,
    pub failed: usize,
}

impl RegistryHealthSummary {
    #[must_use]
    pub fn availability_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.connected as f64 / self.total as f64 * 100.0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HealthChecker
// ─────────────────────────────────────────────────────────────────────────────

/// Drives periodic health-check probes for all registered servers.
pub struct HealthChecker {
    registry: Arc<FederationRegistry>,
    interval: Duration,
}

impl HealthChecker {
    #[must_use]
    pub fn new(registry: Arc<FederationRegistry>, interval: Duration) -> Self {
        Self { registry, interval }
    }

    /// Run health checks for all registered servers (single pass).
    pub async fn run_once(&self) {
        let names = self.registry.server_names();
        for name in names {
            let ok = self.probe(&name).await;
            self.registry.record_health(&name, ok);
        }
    }

    /// Probe a single server.  Returns `true` on success.
    async fn probe(&self, name: &str) -> bool {
        let entry = match self.registry.get(name) {
            Some(e) => e,
            None => return false,
        };
        if !entry.config.enabled {
            return true; // don't penalise disabled servers
        }
        match &entry.config.transport {
            ServerTransport::SseHttp { url, timeout_secs, .. } => {
                let url = url.clone();
                let timeout = Duration::from_secs(*timeout_secs);
                self.http_probe(&url, timeout).await
            }
            ServerTransport::WebSocket { url, .. } => {
                // Treat as HTTP probe with a HEAD request for now
                let url = url.replace("ws://", "http://").replace("wss://", "https://");
                self.http_probe(&url, Duration::from_secs(5)).await
            }
            ServerTransport::Stdio { .. } | ServerTransport::UnixSocket { .. } => {
                // Local transports: assume available if state is Connected
                matches!(entry.state, ConnectionState::Connected)
            }
        }
    }

    async fn http_probe(&self, url: &str, timeout: Duration) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(timeout)
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        let ping_url = format!("{url}/health");
        // Try /health first, fall back to root
        if let Ok(r) = client.get(&ping_url).send().await {
            return r.status().is_success() || r.status().as_u16() < 500;
        }
        if let Ok(r) = client.get(url).send().await {
            return r.status().is_success() || r.status().as_u16() < 500;
        }
        false
    }

    /// Run health checks forever at the configured interval.
    pub async fn run_loop(self: Arc<Self>) {
        loop {
            self.run_once().await;
            tokio::time::sleep(self.interval).await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReconnectManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages exponential back-off reconnects for failed servers.
pub struct ReconnectManager {
    registry: Arc<FederationRegistry>,
    max_attempts: u32,
}

impl ReconnectManager {
    #[must_use]
    pub fn new(registry: Arc<FederationRegistry>, max_attempts: u32) -> Self {
        Self { registry, max_attempts }
    }

    /// Attempt to reconnect all servers that are due a reconnect.
    ///
    /// Calls the provided `connect_fn` per server.  The function should
    /// return `Ok(CapabilitySet)` on success or an error string on failure.
    pub async fn run_once<F, Fut>(&self, connect_fn: F)
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<CapabilitySet, String>>,
    {
        let due = self.registry.servers_due_reconnect();
        for name in due {
            let entry = match self.registry.get(&name) {
                Some(e) => e,
                None => continue,
            };
            if entry.consecutive_failures >= self.max_attempts {
                self.registry.set_state(
                    &name,
                    ConnectionState::Failed {
                        reason: format!(
                            "exceeded max reconnect attempts ({})",
                            self.max_attempts
                        ),
                    },
                );
                continue;
            }
            self.registry.set_state(
                &name,
                ConnectionState::Reconnecting {
                    attempt: entry.consecutive_failures + 1,
                },
            );
            match connect_fn(name.clone()).await {
                Ok(caps) => {
                    self.registry.set_state(&name, ConnectionState::Connected);
                    self.registry.record_health(&name, true);
                    self.registry.store_capabilities(&name, caps).await;
                }
                Err(reason) => {
                    self.registry.set_state(
                        &name,
                        ConnectionState::Failed { reason },
                    );
                    self.registry.record_health(&name, false);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(name: &str) -> ExternalServerConfig {
        ExternalServerConfig::new_stdio(name, "echo")
    }

    #[test]
    fn test_protocol_version_parse() {
        let v = ProtocolVersion::parse("2.3.1").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 3);
        assert_eq!(v.patch, 1);
    }

    #[test]
    fn test_protocol_version_compat() {
        let base = ProtocolVersion { major: 1, minor: 0, patch: 0 };
        let newer = ProtocolVersion { major: 1, minor: 1, patch: 0 };
        let older = ProtocolVersion { major: 1, minor: 0, patch: 0 };
        let diff_major = ProtocolVersion { major: 2, minor: 0, patch: 0 };
        assert!(base.is_compatible(&newer));
        assert!(base.is_compatible(&older));
        assert!(!base.is_compatible(&diff_major));
    }

    #[test]
    fn test_registry_register_and_get() {
        let reg = FederationRegistry::new();
        let id = reg.register(make_config("ghidra"), DiscoverySource::Manual);
        let entry = reg.get("ghidra").unwrap();
        assert_eq!(entry.id, id);
        assert_eq!(entry.config.name, "ghidra");
    }

    #[test]
    fn test_registry_deregister() {
        let reg = FederationRegistry::new();
        reg.register(make_config("srv"), DiscoverySource::Manual);
        assert!(reg.deregister("srv"));
        assert!(reg.get("srv").is_none());
    }

    #[test]
    fn test_registry_record_health_success() {
        let reg = FederationRegistry::new();
        reg.register(make_config("srv"), DiscoverySource::Manual);
        reg.set_state("srv", ConnectionState::Connected);
        reg.record_health("srv", true);
        let e = reg.get("srv").unwrap();
        assert_eq!(e.health, HealthStatus::Healthy);
        assert_eq!(e.consecutive_failures, 0);
    }

    #[test]
    fn test_registry_record_health_failure_backoff() {
        let reg = FederationRegistry::new();
        reg.register(make_config("srv"), DiscoverySource::Manual);
        reg.record_health("srv", false);
        reg.record_health("srv", false);
        let e = reg.get("srv").unwrap();
        assert_eq!(e.consecutive_failures, 2);
        assert_eq!(e.health, HealthStatus::Degraded);
    }

    #[test]
    fn test_registry_unhealthy_after_threshold() {
        let reg = FederationRegistry::new();
        reg.register(make_config("srv"), DiscoverySource::Manual);
        for _ in 0..4 {
            reg.record_health("srv", false);
        }
        let e = reg.get("srv").unwrap();
        assert_eq!(e.health, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_entry_backoff_duration() {
        let mut e = RegistryEntry::new(make_config("s"), DiscoverySource::Manual);
        assert_eq!(e.backoff_duration(), Duration::from_secs(1));
        e.backoff_exp = 3;
        assert_eq!(e.backoff_duration(), Duration::from_secs(8));
        e.backoff_exp = 9; // capped
        assert_eq!(e.backoff_duration(), Duration::from_secs(300));
    }

    #[test]
    fn test_capability_set_merge() {
        let mut a = CapabilitySet {
            tools: vec!["decompile".into()],
            ..Default::default()
        };
        let b = CapabilitySet {
            tools: vec!["disasm".into(), "decompile".into()],
            supports_streaming: true,
            ..Default::default()
        };
        a.merge(&b);
        assert_eq!(a.tools.len(), 2);
        assert!(a.supports_streaming);
    }

    #[test]
    fn test_health_summary() {
        let reg = FederationRegistry::new();
        reg.register(make_config("a"), DiscoverySource::Manual);
        reg.register(make_config("b"), DiscoverySource::Manual);
        let s = reg.health_summary();
        assert_eq!(s.total, 2);
        assert_eq!(s.connected, 0);
    }

    #[test]
    fn test_servers_due_reconnect() {
        let reg = FederationRegistry::new();
        reg.register(make_config("srv"), DiscoverySource::Manual);
        // Initial state: disconnected, no next_reconnect_at → due immediately
        let due = reg.servers_due_reconnect();
        assert!(due.contains(&"srv".to_string()));
    }

    #[test]
    fn test_discovery_source_display() {
        assert!(
            DiscoverySource::ConfigFile { path: "/etc/x".into() }
                .to_string()
                .contains("config")
        );
        assert_eq!(DiscoverySource::Manual.to_string(), "manual");
    }

    #[test]
    fn test_json_server_entry_stdio() {
        let entry = JsonServerEntry {
            name: "frida".into(),
            description: "".into(),
            transport_type: "stdio".into(),
            command: Some("frida-mcp".into()),
            args: None,
            url: None,
            tags: vec![],
            enabled: true,
        };
        let sc = entry.to_server_config().unwrap();
        assert_eq!(sc.name, "frida");
        assert!(matches!(sc.transport, ServerTransport::Stdio { .. }));
    }

    #[test]
    fn test_json_server_entry_http() {
        let entry = JsonServerEntry {
            name: "ghidra".into(),
            description: "".into(),
            transport_type: "http".into(),
            command: None,
            args: None,
            url: Some("http://localhost:18080".into()),
            tags: vec![],
            enabled: true,
        };
        let sc = entry.to_server_config().unwrap();
        assert!(matches!(sc.transport, ServerTransport::SseHttp { .. }));
    }
}
