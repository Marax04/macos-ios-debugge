//! `server_discovery` — Discovery of MCP servers from multiple sources.
//!
//! Sources: `~/.config/rustre/mcp-servers.json`, `RUSTRE_MCP_SERVERS` env var,
//! optional mDNS/DNS-SD, and manual registration.  Also handles stdio, TCP,
//! and WebSocket transports.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{ExternalServerConfig, ServerTransport};

// ─────────────────────────────────────────────────────────────────────────────
// TransportDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-specified transport for connecting to an MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportDescriptor {
    /// Launch a subprocess and speak JSON-RPC over stdin/stdout.
    Stdio {
        command: String,
        args: Vec<String>,
        env: HashMap<String, String>,
        working_dir: Option<String>,
    },
    /// Connect via HTTP/SSE.
    SseHttp {
        url: String,
        headers: HashMap<String, String>,
        timeout_secs: u64,
    },
    /// Connect via WebSocket.
    WebSocket {
        url: String,
        headers: HashMap<String, String>,
        timeout_secs: u64,
    },
    /// Connect via raw TCP socket and use JSON-RPC over the byte stream.
    Tcp {
        host: String,
        port: u16,
        timeout_secs: u64,
    },
    /// Connect via Unix domain socket (non-Windows only).
    UnixSocket {
        path: String,
    },
    /// Named pipe (Windows only).
    NamedPipe {
        name: String,
    },
}

impl TransportDescriptor {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Stdio { .. } => "stdio",
            Self::SseHttp { .. } => "sse_http",
            Self::WebSocket { .. } => "websocket",
            Self::Tcp { .. } => "tcp",
            Self::UnixSocket { .. } => "unix_socket",
            Self::NamedPipe { .. } => "named_pipe",
        }
    }

    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Stdio { .. } | Self::UnixSocket { .. } | Self::NamedPipe { .. })
    }

    /// Convert to a URL-like string for logging.
    #[must_use]
    pub fn to_address(&self) -> String {
        match self {
            Self::Stdio { command, args, .. } => {
                if args.is_empty() {
                    command.clone()
                } else {
                    format!("{command} {}", args.join(" "))
                }
            }
            Self::SseHttp { url, .. } | Self::WebSocket { url, .. } => url.clone(),
            Self::Tcp { host, port, .. } => format!("{host}:{port}"),
            Self::UnixSocket { path } => format!("unix://{path}"),
            Self::NamedPipe { name } => format!("pipe://{name}"),
        }
    }
}

impl From<&ServerTransport> for TransportDescriptor {
    fn from(t: &ServerTransport) -> Self {
        match t {
            ServerTransport::Stdio { command, args, env } => Self::Stdio {
                command: command.clone(),
                args: args.clone(),
                env: env.clone(),
                working_dir: None,
            },
            ServerTransport::SseHttp { url, headers, timeout_secs } => Self::SseHttp {
                url: url.clone(),
                headers: headers.clone(),
                timeout_secs: *timeout_secs,
            },
            ServerTransport::WebSocket { url, headers } => Self::WebSocket {
                url: url.clone(),
                headers: headers.clone(),
                timeout_secs: 30,
            },
            ServerTransport::UnixSocket { path } => Self::UnixSocket { path: path.clone() },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiscoveredServer
// ─────────────────────────────────────────────────────────────────────────────

/// A server discovered from any source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredServer {
    pub name: String,
    pub description: String,
    pub transport: TransportDescriptor,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub source: DiscoverySourceKind,
    pub priority: u32,
}

impl DiscoveredServer {
    #[must_use]
    pub fn from_config(cfg: &ExternalServerConfig, source: DiscoverySourceKind) -> Self {
        Self {
            name: cfg.name.clone(),
            description: cfg.description.clone(),
            transport: TransportDescriptor::from(&cfg.transport),
            tags: cfg.tags.clone(),
            enabled: cfg.enabled,
            source,
            priority: 100,
        }
    }

    /// Convert back to [`ExternalServerConfig`].
    #[must_use]
    pub fn to_server_config(&self) -> ExternalServerConfig {
        let transport = match &self.transport {
            TransportDescriptor::Stdio { command, args, env, .. } => ServerTransport::Stdio {
                command: command.clone(),
                args: args.clone(),
                env: env.clone(),
            },
            TransportDescriptor::SseHttp { url, headers, timeout_secs } => ServerTransport::SseHttp {
                url: url.clone(),
                headers: headers.clone(),
                timeout_secs: *timeout_secs,
            },
            TransportDescriptor::WebSocket { url, headers, .. } => ServerTransport::WebSocket {
                url: url.clone(),
                headers: headers.clone(),
            },
            TransportDescriptor::UnixSocket { path } => ServerTransport::UnixSocket { path: path.clone() },
            TransportDescriptor::Tcp { host, port, .. } => ServerTransport::SseHttp {
                url: format!("http://{host}:{port}"),
                headers: HashMap::new(),
                timeout_secs: 30,
            },
            TransportDescriptor::NamedPipe { name } => ServerTransport::Stdio {
                command: format!("\\\\.\\pipe\\{name}"),
                args: Vec::new(),
                env: HashMap::new(),
            },
        };
        ExternalServerConfig {
            name: self.name.clone(),
            description: self.description.clone(),
            transport,
            tags: self.tags.clone(),
            enabled: self.enabled,
            health_check_interval_secs: 60,
        }
    }
}

/// Source of discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoverySourceKind {
    ConfigFile,
    Environment,
    Mdns,
    Manual,
    DnsSd,
}

impl std::fmt::Display for DiscoverySourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigFile => write!(f, "config_file"),
            Self::Environment => write!(f, "environment"),
            Self::Mdns => write!(f, "mdns"),
            Self::Manual => write!(f, "manual"),
            Self::DnsSd => write!(f, "dns_sd"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigFileFormat — on-disk JSON format
// ─────────────────────────────────────────────────────────────────────────────

/// Root of `~/.config/rustre/mcp-servers.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct McpServersConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub servers: Vec<ServerConfigEntry>,
}

/// Individual server entry in the config file.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfigEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "transport")]
    pub transport_kind: String,
    // stdio
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub working_dir: Option<String>,
    // http/ws
    pub url: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    // tcp
    pub host: Option<String>,
    pub port: Option<u16>,
    // unix
    pub socket_path: Option<String>,
    // named pipe (windows)
    pub pipe_name: Option<String>,
    // metadata
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_timeout() -> u64 { 30 }
fn bool_true() -> bool { true }
fn default_priority() -> u32 { 100 }

impl ServerConfigEntry {
    /// Parse transport descriptor.
    #[must_use]
    pub fn to_transport(&self) -> Option<TransportDescriptor> {
        match self.transport_kind.as_str() {
            "stdio" => Some(TransportDescriptor::Stdio {
                command: self.command.clone()?,
                args: self.args.clone(),
                env: self.env.clone(),
                working_dir: self.working_dir.clone(),
            }),
            "sse_http" | "http" | "sse" => Some(TransportDescriptor::SseHttp {
                url: self.url.clone()?,
                headers: self.headers.clone(),
                timeout_secs: self.timeout_secs,
            }),
            "websocket" | "ws" => Some(TransportDescriptor::WebSocket {
                url: self.url.clone()?,
                headers: self.headers.clone(),
                timeout_secs: self.timeout_secs,
            }),
            "tcp" => Some(TransportDescriptor::Tcp {
                host: self.host.clone().unwrap_or_else(|| "127.0.0.1".into()),
                port: self.port?,
                timeout_secs: self.timeout_secs,
            }),
            "unix" | "unix_socket" => Some(TransportDescriptor::UnixSocket {
                path: self.socket_path.clone()?,
            }),
            "named_pipe" | "pipe" => Some(TransportDescriptor::NamedPipe {
                name: self.pipe_name.clone()?,
            }),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_discovered(&self) -> Option<DiscoveredServer> {
        let transport = self.to_transport()?;
        Some(DiscoveredServer {
            name: self.name.clone(),
            description: self.description.clone(),
            transport,
            tags: self.tags.clone(),
            enabled: self.enabled,
            source: DiscoverySourceKind::ConfigFile,
            priority: self.priority,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerDiscovery
// ─────────────────────────────────────────────────────────────────────────────

/// Discovery configuration.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Path to the config file.
    pub config_file: Option<PathBuf>,
    /// Whether to scan `RUSTRE_MCP_SERVERS`.
    pub scan_env: bool,
    /// Whether to run mDNS discovery.
    pub mdns: bool,
    /// mDNS service type.
    pub mdns_service_type: String,
    /// How long to listen for mDNS advertisements.
    pub mdns_listen_ms: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            config_file: default_config_file_path(),
            scan_env: true,
            mdns: false,
            mdns_service_type: "_mcp._tcp.local.".into(),
            mdns_listen_ms: 500,
        }
    }
}

fn default_config_file_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("APPDATA").ok().map(|a| PathBuf::from(a).join("rustre").join("mcp-servers.json"))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config").join("rustre").join("mcp-servers.json"))
    }
}

/// Main discovery orchestrator.
pub struct ServerDiscovery {
    config: DiscoveryConfig,
    manually_added: Vec<DiscoveredServer>,
}

impl ServerDiscovery {
    #[must_use]
    pub fn new(config: DiscoveryConfig) -> Self {
        Self { config, manually_added: Vec::new() }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DiscoveryConfig::default())
    }

    /// Manually register a server.
    pub fn add_manual(&mut self, server: DiscoveredServer) {
        self.manually_added.push(server);
    }

    /// Run all configured discovery mechanisms and return deduplicated servers.
    pub async fn discover_all(&self) -> Vec<DiscoveredServer> {
        let mut found: HashMap<String, DiscoveredServer> = HashMap::new();

        // 1. Config file
        for srv in self.discover_from_file().await {
            found.entry(srv.name.clone()).or_insert(srv);
        }

        // 2. Environment variable
        if self.config.scan_env {
            for srv in self.discover_from_env() {
                found.entry(srv.name.clone()).or_insert(srv);
            }
        }

        // 3. mDNS (stub)
        if self.config.mdns {
            for srv in self.discover_mdns().await {
                found.entry(srv.name.clone()).or_insert(srv);
            }
        }

        // 4. Manually added (highest priority — overrides)
        for srv in &self.manually_added {
            found.insert(srv.name.clone(), srv.clone());
        }

        let mut result: Vec<DiscoveredServer> = found.into_values().collect();
        result.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.name.cmp(&b.name)));
        result
    }

    /// Discover from the JSON config file.
    pub async fn discover_from_file(&self) -> Vec<DiscoveredServer> {
        let path = match &self.config.config_file {
            Some(p) => p.clone(),
            None => return Vec::new(),
        };
        Self::load_config_file(&path).await
    }

    /// Load and parse a config file.
    pub async fn load_config_file(path: &Path) -> Vec<DiscoveredServer> {
        let content = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let config: McpServersConfig = match serde_json::from_str(&content) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        config.servers.iter().filter_map(|e| e.to_discovered()).collect()
    }

    /// Discover from `RUSTRE_MCP_SERVERS` environment variable.
    #[must_use]
    pub fn discover_from_env(&self) -> Vec<DiscoveredServer> {
        let val = match std::env::var("RUSTRE_MCP_SERVERS") {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        // Sanity-check the env-var size before deserializing to prevent
        // adversarial inputs from causing huge allocations.
        const MAX_ENV_BYTES: usize = 1024 * 1024; // 1 MiB
        if val.len() > MAX_ENV_BYTES {
            return Vec::new();
        }
        // Try JSON array first
        if let Ok(entries) = serde_json::from_str::<Vec<ServerConfigEntry>>(&val) {
            return entries.iter().filter_map(|e| {
                let mut d = e.to_discovered()?;
                d.source = DiscoverySourceKind::Environment;
                Some(d)
            }).collect();
        }
        // Fall back to `name=url[,name=url,…]`
        val.split(',')
            .filter_map(|pair| {
                let (name, url) = pair.trim().split_once('=')?;
                Some(DiscoveredServer {
                    name: name.trim().to_string(),
                    description: String::new(),
                    transport: TransportDescriptor::SseHttp {
                        url: url.trim().to_string(),
                        headers: HashMap::new(),
                        timeout_secs: 30,
                    },
                    tags: Vec::new(),
                    enabled: true,
                    source: DiscoverySourceKind::Environment,
                    priority: 50,
                })
            })
            .collect()
    }

    /// mDNS discovery stub.
    async fn discover_mdns(&self) -> Vec<DiscoveredServer> {
        // Real implementation would use the `mdns-sd` crate.
        // We simulate a brief listen window.
        tokio::time::sleep(Duration::from_millis(self.config.mdns_listen_ms)).await;
        Vec::new()
    }

    /// Watch a config file for changes and re-run discovery when it changes.
    /// Returns a `tokio::sync::watch::Receiver` that yields new server lists.
    pub fn watch_config_file(
        config_path: PathBuf,
        poll_interval: Duration,
    ) -> tokio::sync::watch::Receiver<Vec<DiscoveredServer>> {
        let (tx, rx) = tokio::sync::watch::channel(Vec::new());
        tokio::spawn(async move {
            let mut last_mtime: u64 = 0;
            loop {
                tokio::time::sleep(poll_interval).await;
                let mtime = std::fs::metadata(&config_path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if mtime != last_mtime {
                    last_mtime = mtime;
                    let servers = Self::load_config_file(&config_path).await;
                    let _ = tx.send(servers);
                }
            }
        });
        rx
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WellKnownServers — built-in defaults for common RE tools
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-configured descriptors for well-known RE MCP servers.
pub struct WellKnownServers;

impl WellKnownServers {
    /// Ghidra MCP server (SSE HTTP on localhost:18080).
    #[must_use]
    pub fn ghidra() -> DiscoveredServer {
        DiscoveredServer {
            name: "ghidra".into(),
            description: "Ghidra decompiler MCP server".into(),
            transport: TransportDescriptor::SseHttp {
                url: "http://localhost:18080".into(),
                headers: HashMap::new(),
                timeout_secs: 30,
            },
            tags: vec!["decompiler".into(), "static".into()],
            enabled: true,
            source: DiscoverySourceKind::Manual,
            priority: 100,
        }
    }

    /// IDA Pro MCP bridge (stdio).
    #[must_use]
    pub fn ida_pro(path: impl Into<String>) -> DiscoveredServer {
        DiscoveredServer {
            name: "ida-pro".into(),
            description: "IDA Pro MCP bridge".into(),
            transport: TransportDescriptor::Stdio {
                command: path.into(),
                args: vec!["--mcp".into()],
                env: HashMap::new(),
                working_dir: None,
            },
            tags: vec!["decompiler".into(), "static".into()],
            enabled: true,
            source: DiscoverySourceKind::Manual,
            priority: 110,
        }
    }

    /// Frida dynamic instrumentation MCP server (stdio).
    #[must_use]
    pub fn frida() -> DiscoveredServer {
        DiscoveredServer {
            name: "frida".into(),
            description: "Frida dynamic instrumentation MCP server".into(),
            transport: TransportDescriptor::Stdio {
                command: "frida-mcp".into(),
                args: Vec::new(),
                env: HashMap::new(),
                working_dir: None,
            },
            tags: vec!["dynamic".into(), "instrumentation".into()],
            enabled: true,
            source: DiscoverySourceKind::Manual,
            priority: 90,
        }
    }

    /// x64dbg MCP bridge (TCP on localhost:9090).
    #[must_use]
    pub fn x64dbg() -> DiscoveredServer {
        DiscoveredServer {
            name: "x64dbg".into(),
            description: "x64dbg debugger MCP bridge".into(),
            transport: TransportDescriptor::Tcp {
                host: "127.0.0.1".into(),
                port: 9090,
                timeout_secs: 10,
            },
            tags: vec!["debugger".into(), "dynamic".into()],
            enabled: true,
            source: DiscoverySourceKind::Manual,
            priority: 80,
        }
    }

    /// YARA MCP scanner (stdio).
    #[must_use]
    pub fn yara() -> DiscoveredServer {
        DiscoveredServer {
            name: "yara".into(),
            description: "YARA rule scanning MCP server".into(),
            transport: TransportDescriptor::Stdio {
                command: "yara-mcp-server".into(),
                args: Vec::new(),
                env: HashMap::new(),
                working_dir: None,
            },
            tags: vec!["scanner".into(), "detection".into()],
            enabled: true,
            source: DiscoverySourceKind::Manual,
            priority: 70,
        }
    }

    /// All well-known servers.
    #[must_use]
    pub fn all() -> Vec<DiscoveredServer> {
        vec![
            Self::ghidra(),
            Self::frida(),
            Self::yara(),
            Self::x64dbg(),
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_descriptor_kind() {
        let t = TransportDescriptor::Stdio {
            command: "cmd".into(), args: vec![], env: HashMap::new(), working_dir: None,
        };
        assert_eq!(t.kind(), "stdio");
        assert!(t.is_local());
    }

    #[test]
    fn test_transport_http_not_local() {
        let t = TransportDescriptor::SseHttp {
            url: "http://x".into(), headers: HashMap::new(), timeout_secs: 30,
        };
        assert!(!t.is_local());
        assert_eq!(t.to_address(), "http://x");
    }

    #[test]
    fn test_server_config_entry_stdio() {
        let entry = ServerConfigEntry {
            name: "frida".into(),
            description: "".into(),
            transport_kind: "stdio".into(),
            command: Some("frida-mcp".into()),
            args: vec![],
            env: HashMap::new(),
            working_dir: None,
            url: None,
            headers: HashMap::new(),
            timeout_secs: 30,
            host: None,
            port: None,
            socket_path: None,
            pipe_name: None,
            tags: vec![],
            enabled: true,
            priority: 100,
        };
        let d = entry.to_discovered().unwrap();
        assert_eq!(d.name, "frida");
        assert!(matches!(d.transport, TransportDescriptor::Stdio { .. }));
    }

    #[test]
    fn test_server_config_entry_tcp() {
        let entry = ServerConfigEntry {
            name: "x64dbg".into(),
            description: "".into(),
            transport_kind: "tcp".into(),
            command: None,
            args: vec![],
            env: HashMap::new(),
            working_dir: None,
            url: None,
            headers: HashMap::new(),
            timeout_secs: 10,
            host: Some("127.0.0.1".into()),
            port: Some(9090),
            socket_path: None,
            pipe_name: None,
            tags: vec![],
            enabled: true,
            priority: 80,
        };
        let d = entry.to_discovered().unwrap();
        assert!(matches!(d.transport, TransportDescriptor::Tcp { port: 9090, .. }));
    }

    #[test]
    fn test_discovered_server_to_config() {
        let srv = WellKnownServers::ghidra();
        let cfg = srv.to_server_config();
        assert_eq!(cfg.name, "ghidra");
        assert!(matches!(cfg.transport, ServerTransport::SseHttp { .. }));
    }

    #[test]
    fn test_env_discovery_key_value() {
        unsafe {
            std::env::set_var("RUSTRE_MCP_SERVERS", "my-server=http://localhost:5000");
        }
        let disc = ServerDiscovery::with_defaults();
        let found = disc.discover_from_env();
        unsafe {
            std::env::remove_var("RUSTRE_MCP_SERVERS");
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "my-server");
    }

    #[test]
    fn test_well_known_servers_all() {
        let servers = WellKnownServers::all();
        assert!(!servers.is_empty());
        let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"ghidra"));
        assert!(names.contains(&"frida"));
    }

    #[test]
    fn test_discovery_source_display() {
        assert_eq!(DiscoverySourceKind::ConfigFile.to_string(), "config_file");
        assert_eq!(DiscoverySourceKind::Mdns.to_string(), "mdns");
    }

    #[test]
    fn test_discovered_server_from_config() {
        let cfg = ExternalServerConfig::new_stdio("test-srv", "my-cmd");
        let ds = DiscoveredServer::from_config(&cfg, DiscoverySourceKind::Manual);
        assert_eq!(ds.name, "test-srv");
        assert_eq!(ds.source, DiscoverySourceKind::Manual);
    }

    #[tokio::test]
    async fn test_discover_all_empty() {
        let mut cfg = DiscoveryConfig::default();
        cfg.config_file = None;
        cfg.scan_env = false;
        cfg.mdns = false;
        let disc = ServerDiscovery::new(cfg);
        let found = disc.discover_all().await;
        assert!(found.is_empty());
    }
}
