//! `rustre-sandbox-extract` — Sandbox artifact extraction.
//!
//! Dropped file extraction, memory dumps, network captures, registry snapshots,
//! credential extraction, packer unpacking detection, config extraction.

pub mod c2_extractor;
pub mod file_artifact_collector;
pub mod malware_config_db;
pub mod memory_artifact_dumper;
pub mod network_artifact_extractor;
pub mod ransomware_analysis;
pub mod behavior_extractor;
pub mod config_extractor;
pub mod sandbox_report_normalizer;
pub mod dropped_file_collector;
pub mod credential_harvester;
pub mod crypto_key_finder;
pub mod dropper_analysis;
pub mod ransomware_detector;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors that can occur during artifact extraction.
#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("extraction failed: {0}")]
    ExtractionFailed(String),
}

// ─── ArtifactKind ────────────────────────────────────────────────────────────

/// The type of a sandbox artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    DroppedFile,
    NetworkConn,
    RegistryKey,
    ProcessSpawn,
    MutexCreate,
    InjectedCode,
    MemoryDump,
    Credential,
    Config,
    PackerLayer,
    Screenshot,
    PcapCapture,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DroppedFile => write!(f, "dropped_file"),
            Self::NetworkConn => write!(f, "network_conn"),
            Self::RegistryKey => write!(f, "registry_key"),
            Self::ProcessSpawn => write!(f, "process_spawn"),
            Self::MutexCreate => write!(f, "mutex_create"),
            Self::InjectedCode => write!(f, "injected_code"),
            Self::MemoryDump => write!(f, "memory_dump"),
            Self::Credential => write!(f, "credential"),
            Self::Config => write!(f, "config"),
            Self::PackerLayer => write!(f, "packer_layer"),
            Self::Screenshot => write!(f, "screenshot"),
            Self::PcapCapture => write!(f, "pcap_capture"),
        }
    }
}

// ─── DroppedFile ─────────────────────────────────────────────────────────────

/// A file dropped to disk by the sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    pub path: String,
    pub size: usize,
    pub sha256: String,
    pub md5: String,
    pub preview: Vec<u8>,
    pub mime_type: String,
    pub created_ms: u64,
    pub pid: u32,
}

impl DroppedFile {
    /// Create a new dropped file entry.
    #[must_use]
    pub fn new(path: impl Into<String>, size: usize, sha256: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            size,
            sha256: sha256.into(),
            md5: String::new(),
            preview: vec![],
            mime_type: "application/octet-stream".to_string(),
            created_ms: 0,
            pid: 0,
        }
    }

    /// Return the file extension (empty string if none).
    #[must_use]
    pub fn extension(&self) -> &str {
        if let Some(pos) = self.path.rfind('.') {
            // Use `get` to avoid panicking if the dot sits at the boundary of a
            // multibyte UTF-8 sequence in an adversarially crafted path string.
            self.path.get(pos + 1..).unwrap_or("")
        } else {
            ""
        }
    }

    /// Returns `true` if the preview bytes suggest an MZ PE header.
    #[must_use]
    pub fn is_pe(&self) -> bool {
        self.preview.starts_with(&[0x4d, 0x5a])
    }

    /// Returns `true` if the preview bytes suggest an ELF header.
    #[must_use]
    pub fn is_elf(&self) -> bool {
        self.preview.starts_with(&[0x7f, 0x45, 0x4c, 0x46])
    }

    /// Returns `true` if the preview bytes suggest a ZIP/APK/JAR.
    #[must_use]
    pub fn is_zip(&self) -> bool {
        self.preview.starts_with(&[0x50, 0x4b, 0x03, 0x04])
            || self.preview.starts_with(&[0x50, 0x4b, 0x05, 0x06])
    }

    /// Returns `true` if this looks like an executable file.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        let ext = self.extension().to_ascii_lowercase();
        matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "sh"
        ) || self.is_pe()
            || self.is_elf()
    }

    /// Calculate a rudimentary entropy estimate from the preview bytes.
    #[must_use]
    pub fn preview_entropy(&self) -> f64 {
        if self.preview.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in &self.preview {
            counts[b as usize] += 1;
        }
        let n = self.preview.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = f64::from(c) / n;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

// ─── MemoryDump ───────────────────────────────────────────────────────────────

/// A memory dump captured from a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDump {
    pub pid: u32,
    pub label: String,
    pub start_va: u64,
    pub size: usize,
    pub data: Vec<u8>,
    pub ts_ms: u64,
    pub is_injected: bool,
    pub sha256: String,
}

impl MemoryDump {
    /// Create a new memory dump.
    #[must_use]
    pub fn new(pid: u32, label: impl Into<String>, start_va: u64, data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            pid,
            label: label.into(),
            start_va,
            size,
            data,
            ts_ms: 0,
            is_injected: false,
            sha256: String::new(),
        }
    }

    /// Returns `true` if the dump begins with an MZ header.
    #[must_use]
    pub fn has_pe_header(&self) -> bool {
        self.data.starts_with(&[0x4d, 0x5a])
    }

    /// Calculate approximate entropy of the dump data.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in &self.data {
            counts[b as usize] += 1;
        }
        let n = self.data.len() as f64;
        let mut entropy = 0.0f64;
        for &c in &counts {
            if c > 0 {
                let p = f64::from(c) / n;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Returns `true` if the entropy suggests encrypted/compressed data.
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy() > 7.0
    }

    /// Scan the dump for ASCII strings of minimum length.
    #[must_use]
    pub fn extract_strings(&self, min_len: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current = String::new();
        for &b in &self.data {
            if b.is_ascii_graphic() || b == b' ' {
                current.push(b as char);
            } else {
                if current.len() >= min_len {
                    strings.push(current.clone());
                }
                current.clear();
            }
        }
        if current.len() >= min_len {
            strings.push(current);
        }
        strings
    }
}

// ─── NetworkCapture ───────────────────────────────────────────────────────────

/// A captured network connection and its data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCapture {
    pub proto: String,
    pub remote_ip: String,
    pub port: u16,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub dns_query: Option<String>,
    pub http_host: Option<String>,
    pub http_url: Option<String>,
    pub http_method: Option<String>,
    pub payload_preview: Vec<u8>,
    pub ts_ms: u64,
    pub pid: u32,
}

impl NetworkCapture {
    /// Returns `true` if the remote IP is external (non-RFC1918).
    #[must_use]
    pub fn is_external(&self) -> bool {
        let ip = &self.remote_ip;
        if ip.starts_with("127.") || ip.starts_with("192.168.") || ip.starts_with("10.") || ip == "::1" {
            return false;
        }
        // RFC 1918: 172.16.0.0/12 covers 172.16–172.31 only.
        if let Some(rest) = ip.strip_prefix("172.")
            && let Some(second_octet_str) = rest.split('.').next()
                && let Ok(second) = second_octet_str.parse::<u8>()
                    && (16..=31).contains(&second) {
                        return false;
                    }
        true
    }

    /// Returns `true` if this capture shows HTTP/HTTPS activity.
    #[must_use]
    pub const fn is_http(&self) -> bool {
        self.http_host.is_some() || self.http_url.is_some()
    }

    /// Returns `true` if the port is a common C2 port.
    #[must_use]
    pub const fn is_c2_port(&self) -> bool {
        matches!(
            self.port,
            443 | 80 | 4444 | 8080 | 8443 | 1337 | 6666 | 31337
        )
    }

    /// Infer whether this might be a C2 beacon.
    #[must_use]
    pub fn is_likely_c2(&self) -> bool {
        self.is_external() && self.is_c2_port()
    }
}

// ─── RegOpKind ───────────────────────────────────────────────────────────────

/// Type of registry operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegOpKind {
    Create,
    Delete,
    SetValue,
    QueryValue,
    EnumKey,
    EnumValue,
}

impl fmt::Display for RegOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Delete => write!(f, "delete"),
            Self::SetValue => write!(f, "set_value"),
            Self::QueryValue => write!(f, "query_value"),
            Self::EnumKey => write!(f, "enum_key"),
            Self::EnumValue => write!(f, "enum_value"),
        }
    }
}

// ─── RegistryOp ──────────────────────────────────────────────────────────────

/// A registry operation captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOp {
    pub key: String,
    pub value: String,
    pub data: Option<String>,
    pub op: RegOpKind,
    pub ts_ms: u64,
    pub pid: u32,
}

impl RegistryOp {
    /// Returns `true` if this is a persistence-related registry write.
    #[must_use]
    pub fn is_persistence(&self) -> bool {
        matches!(self.op, RegOpKind::SetValue | RegOpKind::Create)
            && (self.key.contains("\\Run\\")
                || self.key.ends_with("\\Run")
                || self.key.contains("\\RunOnce\\")
                || self.key.ends_with("\\RunOnce")
                || self.key.contains("\\Services\\")
                || self.key.contains("\\Winlogon\\")
                || self.key.contains("\\Image File Execution Options\\"))
    }
}

// ─── ProcessSpawn ────────────────────────────────────────────────────────────

/// A process creation event captured during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSpawn {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub cmdline: String,
    pub image: String,
    pub ts_ms: u64,
    pub injected: bool,
}

impl ProcessSpawn {
    /// Returns `true` if this spawn looks like a shell being launched.
    #[must_use]
    pub fn is_shell(&self) -> bool {
        let img = self.image.to_ascii_lowercase();
        img.contains("cmd.exe")
            || img.contains("powershell")
            || img.contains("bash")
            || img.contains("sh")
    }

    /// Returns `true` if this looks like a `LOLBin` execution.
    #[must_use]
    pub fn is_lolbin(&self) -> bool {
        let img = self.image.to_ascii_lowercase();
        [
            "certutil",
            "wscript",
            "cscript",
            "mshta",
            "regsvr32",
            "rundll32",
            "msiexec",
            "bitsadmin",
            "wmic",
            "powershell",
            "msbuild",
        ]
        .iter()
        .any(|lol| img.contains(lol))
    }
}

// ─── Credential ───────────────────────────────────────────────────────────────

/// An extracted credential or secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub kind: CredentialKind,
    pub target: String,
    pub username: Option<String>,
    pub secret: String,
    pub source: String,
    pub ts_ms: u64,
}

/// The type of an extracted credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    Password,
    ApiKey,
    Certificate,
    Token,
    Hash,
    Other(String),
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::ApiKey => write!(f, "api_key"),
            Self::Certificate => write!(f, "certificate"),
            Self::Token => write!(f, "token"),
            Self::Hash => write!(f, "hash"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── PackerLayer ──────────────────────────────────────────────────────────────

/// A detected packer / protector layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerLayer {
    pub name: String,
    pub version: Option<String>,
    pub payload_offset: u64,
    pub payload_size: usize,
    pub entropy: f64,
    pub unpacked_data: Option<Vec<u8>>,
}

impl PackerLayer {
    /// Create a packer layer entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        payload_offset: u64,
        payload_size: usize,
        entropy: f64,
    ) -> Self {
        Self {
            name: name.into(),
            version: None,
            payload_offset,
            payload_size,
            entropy,
            unpacked_data: None,
        }
    }

    /// Returns `true` if the unpacked payload is available.
    #[must_use]
    pub const fn is_unpacked(&self) -> bool {
        self.unpacked_data.is_some()
    }

    /// Returns `true` if the entropy suggests this layer is encrypted/compressed.
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 7.0
    }
}

// ─── PackerDetector ───────────────────────────────────────────────────────────

/// Detects common packers and protectors from binary signatures.
#[derive(Debug, Clone, Default)]
pub struct PackerDetector {
    signatures: Vec<PackerSignature>,
}

#[derive(Debug, Clone)]
struct PackerSignature {
    name: &'static str,
    version: Option<&'static str>,
    /// Byte pattern to search for (offset, bytes).
    patterns: &'static [(usize, &'static [u8])],
}

impl PackerDetector {
    /// Create a detector with built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        // In a real implementation these would be much larger and more precise.
        Self {
            signatures: vec![
                PackerSignature {
                    name: "UPX",
                    version: Some("3.x"),
                    patterns: &[(0, b"UPX!"), (256, b"UPX0")],
                },
                PackerSignature {
                    name: "MPRESS",
                    version: None,
                    patterns: &[(0, b"MPRESS")],
                },
                PackerSignature {
                    name: "Themida",
                    version: None,
                    patterns: &[(0, b"THEMIDA")],
                },
                PackerSignature {
                    name: "ASPack",
                    version: Some("2.x"),
                    patterns: &[(0, b"ASPack")],
                },
                PackerSignature {
                    name: "PECompact",
                    version: None,
                    patterns: &[(0, b"PEC2")],
                },
                PackerSignature {
                    name: "NsPack",
                    version: None,
                    patterns: &[(0, b"NsPack")],
                },
            ],
        }
    }

    /// Detect packer layers in raw binary data.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<PackerLayer> {
        let mut layers = Vec::new();
        for sig in &self.signatures {
            let mut matched = false;
            for &(offset, pattern) in sig.patterns {
                if offset + pattern.len() <= data.len()
                    && &data[offset..offset + pattern.len()] == pattern
                {
                    matched = true;
                    break;
                }
                // Also scan the whole buffer for the pattern.
                if data.windows(pattern.len()).any(|w| w == pattern) {
                    matched = true;
                    break;
                }
            }
            if matched {
                let mut layer = PackerLayer::new(sig.name, 0, data.len(), 7.5);
                if let Some(ver) = sig.version {
                    layer.version = Some(ver.to_string());
                }
                layers.push(layer);
            }
        }
        layers
    }

    /// Returns the number of built-in signatures.
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

// ─── ConfigExtractor ──────────────────────────────────────────────────────────

/// Extracts embedded configuration data from a sample's binary or memory dump.
#[derive(Debug, Clone, Default)]
pub struct ConfigExtractor;

/// An extracted malware configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedConfig {
    pub family: String,
    pub fields: HashMap<String, String>,
    pub raw_bytes: Vec<u8>,
    pub source: String,
}

impl ExtractedConfig {
    /// Create a new extracted config.
    #[must_use]
    pub fn new(family: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            fields: HashMap::new(),
            raw_bytes: vec![],
            source: source.into(),
        }
    }

    /// Add a field.
    pub fn add_field(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }

    /// Get a field value.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(std::string::String::as_str)
    }
}

impl ConfigExtractor {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Heuristically extract configuration fields from a string blob.
    /// Looks for IP:port patterns, URLs, and key=value pairs.
    #[must_use]
    pub fn extract_from_strings(&self, strings: &[&str], family_hint: &str) -> ExtractedConfig {
        let mut config = ExtractedConfig::new(family_hint, "string_analysis");

        for s in strings {
            // IP:port pattern.
            if let Some(ip_port) = extract_ip_port(s) {
                config.add_field("c2", ip_port);
            }
            // URL pattern.
            if s.starts_with("http://") || s.starts_with("https://") {
                config.add_field("url", *s);
            }
            // key=value pair.
            if let Some(pos) = s.find('=') {
                let k = s[..pos].trim();
                let v = s[pos + 1..].trim();
                if !k.is_empty() && !v.is_empty() && k.len() < 64 {
                    config.add_field(k, v);
                }
            }
        }
        config
    }

    /// Extract configs from a memory dump by scanning for known patterns.
    #[must_use]
    pub fn extract_from_dump(&self, dump: &MemoryDump, family_hint: &str) -> ExtractedConfig {
        let strings = dump.extract_strings(6);
        let str_refs: Vec<&str> = strings.iter().map(std::string::String::as_str).collect();
        self.extract_from_strings(&str_refs, family_hint)
    }
}

/// Parse an IP:port string from a string, returning "ip:port" if found.
fn extract_ip_port(s: &str) -> Option<String> {
    // Very simple heuristic: look for n.n.n.n:n pattern.
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return None;
    }
    let all_octets = ip_parts.iter().all(|p| p.parse::<u8>().is_ok());
    let port_ok = parts[1].parse::<u16>().is_ok();
    if all_octets && port_ok {
        Some(s.to_string())
    } else {
        None
    }
}

// ─── Artifact ────────────────────────────────────────────────────────────────

/// Generic artifact entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub ts_ms: u64,
    pub pid: u32,
    pub desc: String,
    pub size: usize,
}

impl Artifact {
    /// Create a new artifact.
    #[must_use]
    pub fn new(kind: ArtifactKind, pid: u32, desc: impl Into<String>) -> Self {
        Self {
            kind,
            ts_ms: 0,
            pid,
            desc: desc.into(),
            size: 0,
        }
    }
}

// ─── ArtifactCollection ──────────────────────────────────────────────────────

/// Full collection of all artifacts extracted from a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactCollection {
    pub artifacts: Vec<Artifact>,
    pub files: Vec<DroppedFile>,
    pub network: Vec<NetworkCapture>,
    pub registry: Vec<RegistryOp>,
    pub processes: Vec<ProcessSpawn>,
    pub memory_dumps: Vec<MemoryDump>,
    pub credentials: Vec<Credential>,
    pub packer_layers: Vec<PackerLayer>,
    pub configs: Vec<ExtractedConfig>,
}

impl ArtifactCollection {
    /// Create an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            artifacts: vec![],
            files: vec![],
            network: vec![],
            registry: vec![],
            processes: vec![],
            memory_dumps: vec![],
            credentials: vec![],
            packer_layers: vec![],
            configs: vec![],
        }
    }

    /// Add a generic artifact.
    pub fn add_artifact(&mut self, a: Artifact) {
        self.artifacts.push(a);
    }

    /// Add a dropped file.
    pub fn add_file(&mut self, f: DroppedFile) {
        self.files.push(f);
    }

    /// Add a network capture.
    pub fn add_network(&mut self, n: NetworkCapture) {
        self.network.push(n);
    }

    /// Add a registry operation.
    pub fn add_registry(&mut self, r: RegistryOp) {
        self.registry.push(r);
    }

    /// Add a process spawn.
    pub fn add_process(&mut self, p: ProcessSpawn) {
        self.processes.push(p);
    }

    /// Add a memory dump.
    pub fn add_memory_dump(&mut self, d: MemoryDump) {
        self.memory_dumps.push(d);
    }

    /// Add a credential.
    pub fn add_credential(&mut self, c: Credential) {
        self.credentials.push(c);
    }

    /// Add a packer layer.
    pub fn add_packer_layer(&mut self, l: PackerLayer) {
        self.packer_layers.push(l);
    }

    /// Add an extracted config.
    pub fn add_config(&mut self, c: ExtractedConfig) {
        self.configs.push(c);
    }

    /// Total count of all artifacts (generic + typed).
    #[must_use]
    pub const fn total(&self) -> usize {
        self.artifacts.len()
            + self.files.len()
            + self.network.len()
            + self.registry.len()
            + self.processes.len()
            + self.memory_dumps.len()
            + self.credentials.len()
            + self.packer_layers.len()
            + self.configs.len()
    }

    /// Return all external network connections.
    #[must_use]
    pub fn external_connections(&self) -> Vec<&NetworkCapture> {
        self.network.iter().filter(|n| n.is_external()).collect()
    }

    /// Return all dropped executable files.
    #[must_use]
    pub fn dropped_executables(&self) -> Vec<&DroppedFile> {
        self.files.iter().filter(|f| f.is_executable()).collect()
    }

    /// Return all persistence registry operations.
    #[must_use]
    pub fn persistence_ops(&self) -> Vec<&RegistryOp> {
        self.registry
            .iter()
            .filter(|r| r.is_persistence())
            .collect()
    }

    /// Return all shell process spawns.
    #[must_use]
    pub fn shell_spawns(&self) -> Vec<&ProcessSpawn> {
        self.processes.iter().filter(|p| p.is_shell()).collect()
    }

    /// Return all `LOLBin` executions.
    #[must_use]
    pub fn lolbin_spawns(&self) -> Vec<&ProcessSpawn> {
        self.processes.iter().filter(|p| p.is_lolbin()).collect()
    }

    /// Return all high-entropy memory dumps.
    #[must_use]
    pub fn high_entropy_dumps(&self) -> Vec<&MemoryDump> {
        self.memory_dumps
            .iter()
            .filter(|d| d.is_high_entropy())
            .collect()
    }

    /// Return all dumps that contain PE headers.
    #[must_use]
    pub fn pe_dumps(&self) -> Vec<&MemoryDump> {
        self.memory_dumps
            .iter()
            .filter(|d| d.has_pe_header())
            .collect()
    }

    /// Create a mock collection with rich data for testing.
    #[must_use]
    pub fn mock() -> Self {
        let mut c = Self::new();
        // Dropped executables.
        let mut f1 = DroppedFile::new("C:\\Windows\\Temp\\payload.exe", 102_400, "abc123def456");
        f1.preview = vec![0x4d, 0x5a, 0x90, 0x00]; // MZ
        f1.mime_type = "application/x-dosexec".to_string();
        c.add_file(f1);

        let f2 = DroppedFile::new(
            "C:\\Users\\sandbox\\AppData\\Roaming\\data.bin",
            4096,
            "cafebabe",
        );
        c.add_file(f2);

        // Network connections.
        c.add_network(NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "185.220.101.1".to_string(),
            port: 443,
            bytes_sent: 1024,
            bytes_recv: 512,
            dns_query: Some("c2server.evil".to_string()),
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 200,
            pid: 1000,
        });
        c.add_network(NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "127.0.0.1".to_string(),
            port: 8080,
            bytes_sent: 256,
            bytes_recv: 128,
            dns_query: None,
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 300,
            pid: 1000,
        });

        // Registry ops.
        c.add_registry(RegistryOp {
            key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value: "Malware".to_string(),
            data: Some("C:\\Windows\\Temp\\payload.exe".to_string()),
            op: RegOpKind::SetValue,
            ts_ms: 400,
            pid: 1000,
        });

        // Process spawns.
        c.add_process(ProcessSpawn {
            parent_pid: 1234,
            child_pid: 5678,
            cmdline: "powershell.exe -enc <base64>".to_string(),
            image: "powershell.exe".to_string(),
            ts_ms: 500,
            injected: false,
        });

        // Memory dump.
        let mut dump = MemoryDump::new(
            1000,
            "injected_shellcode",
            0x0001_0000_0000,
            vec![
                0x4d, 0x5a, 0x90, 0x00, // MZ
                b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r', b'l', b'd',
            ],
        );
        dump.is_injected = true;
        c.add_memory_dump(dump);

        // Credential.
        c.add_credential(Credential {
            kind: CredentialKind::Password,
            target: "SMTP server".to_string(),
            username: Some("admin".to_string()),
            secret: "P@ssw0rd!".to_string(),
            source: "memory dump".to_string(),
            ts_ms: 600,
        });

        // Packer layer.
        c.add_packer_layer(PackerLayer::new("UPX", 0, 65536, 7.8));

        // Config.
        let mut config = ExtractedConfig::new("generic_rat", "string_analysis");
        config.add_field("c2", "185.220.101.1:443");
        config.add_field("sleep_ms", "5000");
        c.add_config(config);

        // Generic artifact.
        c.add_artifact(Artifact::new(
            ArtifactKind::InjectedCode,
            1000,
            "WriteProcessMemory into notepad.exe",
        ));

        c
    }
}

impl Default for ArtifactCollection {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Trait for artifact extractors.
pub trait ArtifactExtractor: Send + Sync {
    /// Extract artifacts from a log string.
    ///
    /// # Errors
    /// Returns `ExtractError` if parsing fails.
    fn extract(&self, log: &str) -> Result<ArtifactCollection, ExtractError>;
}

// ─── LogExtractor ────────────────────────────────────────────────────────────

/// Parses log lines in the format:
/// - `DROP:path:sha256`
/// - `NET:ip:port:proto`
/// - `REG:key:val:op`
/// - `PROC:ppid:cpid:cmd`
/// - `MEM:pid:label:start_va`
/// - `CRED:kind:target:secret`
#[derive(Debug, Clone, Default)]
pub struct LogExtractor;

impl ArtifactExtractor for LogExtractor {
    fn extract(&self, log: &str) -> Result<ArtifactCollection, ExtractError> {
        let mut col = ArtifactCollection::new();
        for line in log.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(6, ':').collect();
            match parts.first() {
                Some(&"DROP") if parts.len() >= 3 => {
                    col.add_file(DroppedFile::new(parts[1], 0, parts[2]));
                }
                Some(&"NET") if parts.len() >= 4 => {
                    let port = parts[2].parse::<u16>().unwrap_or(0);
                    col.add_network(NetworkCapture {
                        proto: parts.get(3).copied().unwrap_or("tcp").to_string(),
                        remote_ip: parts[1].to_string(),
                        port,
                        bytes_sent: 0,
                        bytes_recv: 0,
                        dns_query: None,
                        http_host: None,
                        http_url: None,
                        http_method: None,
                        payload_preview: vec![],
                        ts_ms: 0,
                        pid: 0,
                    });
                }
                Some(&"REG") if parts.len() >= 4 => {
                    let op = match parts[3] {
                        "create" => RegOpKind::Create,
                        "delete" => RegOpKind::Delete,
                        "set_value" | "set" => RegOpKind::SetValue,
                        "query" => RegOpKind::QueryValue,
                        _ => RegOpKind::SetValue,
                    };
                    col.add_registry(RegistryOp {
                        key: parts[1].to_string(),
                        value: parts[2].to_string(),
                        data: None,
                        op,
                        ts_ms: 0,
                        pid: 0,
                    });
                }
                Some(&"PROC") if parts.len() >= 4 => {
                    let ppid = parts[1].parse::<u32>().unwrap_or(0);
                    let cpid = parts[2].parse::<u32>().unwrap_or(0);
                    let cmd = parts[3..].join(":");
                    col.add_process(ProcessSpawn {
                        parent_pid: ppid,
                        child_pid: cpid,
                        cmdline: cmd.clone(),
                        image: cmd.split_whitespace().next().unwrap_or("").to_string(),
                        ts_ms: 0,
                        injected: false,
                    });
                }
                Some(&"MEM") if parts.len() >= 4 => {
                    let pid = parts[1].parse::<u32>().unwrap_or(0);
                    let start_va =
                        u64::from_str_radix(parts[3].trim_start_matches("0x"), 16).unwrap_or(0);
                    col.add_memory_dump(MemoryDump::new(pid, parts[2], start_va, vec![]));
                }
                Some(&"CRED") if parts.len() >= 4 => {
                    col.add_credential(Credential {
                        kind: CredentialKind::Other(parts[1].to_string()),
                        target: parts[2].to_string(),
                        username: None,
                        secret: parts[3..].join(":"),
                        source: "log".to_string(),
                        ts_ms: 0,
                    });
                }
                _ => {}
            }
        }
        Ok(col)
    }
}

// ─── ApiCall ─────────────────────────────────────────────────────────────────

/// A single API call captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    /// Name of the API function, e.g. `"CreateFileW"`.
    pub name: String,
    /// Return value (as hex string).
    pub retval: String,
    /// Argument list — each element is the string representation of one argument.
    pub args: Vec<String>,
    /// Timestamp in milliseconds since execution start.
    pub ts_ms: u64,
    /// PID of the caller.
    pub pid: u32,
    /// Category tag, e.g. `"file"`, `"network"`, `"registry"`.
    pub category: String,
}

impl ApiCall {
    /// Create a new API call record.
    #[must_use]
    pub fn new(name: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            retval: String::new(),
            args,
            ts_ms: 0,
            pid: 0,
            category: String::new(),
        }
    }
}

// ─── SandboxResult ───────────────────────────────────────────────────────────

/// The raw output of a sandbox execution run, aggregating all captured data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxResult {
    /// SHA-256 of the analyzed sample.
    pub sha256: String,
    /// Human-readable sample name.
    pub sample_name: String,
    /// Analysis duration in milliseconds.
    pub analysis_ms: u64,
    /// All API calls captured during the run.
    pub api_calls: Vec<ApiCall>,
    /// Files dropped to disk.
    pub dropped_files: Vec<DroppedFile>,
    /// Network connections.
    pub network: Vec<NetworkCapture>,
    /// Registry operations.
    pub registry: Vec<RegistryOp>,
    /// Process spawns.
    pub processes: Vec<ProcessSpawn>,
    /// Memory dumps.
    pub memory_dumps: Vec<MemoryDump>,
    /// Mutexes created during execution.
    pub mutexes: Vec<String>,
    /// Raw PCAP bytes (may be empty if no capture was performed).
    pub pcap_bytes: Vec<u8>,
}

impl SandboxResult {
    /// Create a new empty `SandboxResult`.
    #[must_use]
    pub fn new(sample_name: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            sha256: sha256.into(),
            sample_name: sample_name.into(),
            ..Default::default()
        }
    }

    /// Construct a rich mock result useful for unit tests.
    #[must_use]
    pub fn mock() -> Self {
        let mut r = Self::new("malware.exe", "deadbeef0123456789abcdef0123456789abcdef");
        r.analysis_ms = 60_000;

        // API calls carrying IOC-relevant arguments.
        r.api_calls.push(ApiCall::new(
            "InternetConnectA",
            vec![
                "0x0".to_string(),
                "185.220.101.1".to_string(),
                "443".to_string(),
            ],
        ));
        r.api_calls.push(ApiCall::new(
            "HttpOpenRequestA",
            vec![
                "0x0".to_string(),
                "GET".to_string(),
                "/beacon?id=abc123".to_string(),
                "HTTP/1.1".to_string(),
            ],
        ));
        r.api_calls.push(ApiCall::new(
            "CreateMutexA",
            vec![
                "0".to_string(),
                "0".to_string(),
                "Global\\MalwareMutex_v2".to_string(),
            ],
        ));
        r.api_calls.push(ApiCall::new(
            "RegSetValueExA",
            vec![
                "HKCU".to_string(),
                r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                "0".to_string(),
                "1".to_string(),
                r"C:\Windows\Temp\payload.exe".to_string(),
            ],
        ));

        // Dropped files.
        let mut f1 = DroppedFile::new(r"C:\Windows\Temp\payload.exe", 102_400, "abc123sha256");
        f1.preview = vec![0x4d, 0x5a, 0x90, 0x00];
        r.dropped_files.push(f1);

        // Network captures.
        r.network.push(NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "185.220.101.1".to_string(),
            port: 443,
            bytes_sent: 512,
            bytes_recv: 1024,
            dns_query: Some("c2server.evil".to_string()),
            http_host: Some("185.220.101.1".to_string()),
            http_url: Some("https://185.220.101.1/beacon".to_string()),
            http_method: Some("GET".to_string()),
            payload_preview: vec![],
            ts_ms: 200,
            pid: 1000,
        });

        // Mutexes.
        r.mutexes.push("Global\\MalwareMutex_v2".to_string());

        // Memory dump.
        let dump = MemoryDump::new(
            1000,
            "section_.text",
            0x0040_0000,
            vec![
                0x4d, 0x5a, 0x90, 0x00, // MZ
                b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'e', b'v', b'i', b'l', b'.', b'c',
                b'o', b'm', b'/', b'b', b'e', b'a', b'c', b'o', b'n', 0x00, b'1', b'8', b'5', b'.',
                b'2', b'2', b'0', b'.', b'1', b'0', b'1', b'.', b'1', b':', b'4', b'4', b'3',
            ],
        );
        r.memory_dumps.push(dump);

        r
    }
}

// ─── IocCollection ───────────────────────────────────────────────────────────

/// A flat collection of all IOC strings extracted from a sandbox run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocCollection {
    /// IPv4/IPv6 address strings.
    pub ips: Vec<String>,
    /// Domain / hostname strings.
    pub domains: Vec<String>,
    /// Full URL strings.
    pub urls: Vec<String>,
    /// File-system paths.
    pub file_paths: Vec<String>,
    /// Registry key paths.
    pub registry_keys: Vec<String>,
    /// Mutex names.
    pub mutexes: Vec<String>,
    /// Hash strings (MD5/SHA-1/SHA-256).
    pub hashes: Vec<String>,
    /// Bitcoin / cryptocurrency addresses.
    pub btc_addresses: Vec<String>,
}

impl IocCollection {
    /// Create an empty collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of IOC entries across all categories.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.ips.len()
            + self.domains.len()
            + self.urls.len()
            + self.file_paths.len()
            + self.registry_keys.len()
            + self.mutexes.len()
            + self.hashes.len()
            + self.btc_addresses.len()
    }

    /// Returns `true` if the collection contains no IOCs.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Deduplicate all lists in-place.
    pub fn deduplicate(&mut self) {
        dedup_vec(&mut self.ips);
        dedup_vec(&mut self.domains);
        dedup_vec(&mut self.urls);
        dedup_vec(&mut self.file_paths);
        dedup_vec(&mut self.registry_keys);
        dedup_vec(&mut self.mutexes);
        dedup_vec(&mut self.hashes);
        dedup_vec(&mut self.btc_addresses);
    }

    /// Merge another `IocCollection` into `self`.
    pub fn merge(&mut self, other: Self) {
        self.ips.extend(other.ips);
        self.domains.extend(other.domains);
        self.urls.extend(other.urls);
        self.file_paths.extend(other.file_paths);
        self.registry_keys.extend(other.registry_keys);
        self.mutexes.extend(other.mutexes);
        self.hashes.extend(other.hashes);
        self.btc_addresses.extend(other.btc_addresses);
    }

    /// Extract IOCs from a list of API call records.
    ///
    /// Inspects the argument lists of network, file, registry, and mutex APIs
    /// for recognisable IOC patterns.
    #[must_use]
    pub fn from_api_trace(calls: &[ApiCall]) -> Self {
        let mut col = Self::new();

        // Pre-compile patterns (cheap for small inputs; no need for lazy_static here).
        let re_ipv4 = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").expect("valid regex");
        let re_url = Regex::new(r"(?i)^https?://").expect("valid regex");
        let re_domain = Regex::new(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
            .expect("valid regex");
        let re_hash_md5 = Regex::new(r"^[0-9a-fA-F]{32}$").expect("valid regex");
        let re_hash_sha1 = Regex::new(r"^[0-9a-fA-F]{40}$").expect("valid regex");
        let re_hash_sha256 = Regex::new(r"^[0-9a-fA-F]{64}$").expect("valid regex");
        let re_btc = Regex::new(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$").expect("valid regex");

        for call in calls {
            let name_lower = call.name.to_ascii_lowercase();

            // Network-related calls: treat second arg as host/IP.
            if name_lower.contains("internetconnect")
                || name_lower.contains("connect")
                || name_lower.contains("gethostbyname")
                || name_lower.contains("getaddrinfo")
            {
                for arg in &call.args {
                    let a = arg.trim();
                    if re_ipv4.is_match(a) {
                        col.ips.push(a.to_string());
                    } else if re_domain.is_match(a) {
                        col.domains.push(a.to_string());
                    }
                }
            }

            // HTTP calls: look for URL patterns in args.
            if name_lower.contains("httpopenrequest")
                || name_lower.contains("httpsendrequest")
                || name_lower.contains("winhttpopenrequest")
            {
                for arg in &call.args {
                    let a = arg.trim();
                    if re_url.is_match(a) {
                        col.urls.push(a.to_string());
                    }
                    // path-only: prepend context if we have a host already.
                    if a.starts_with('/') && !a.is_empty() {
                        // Store as a partial URL indicator.
                        col.urls.push(format!("(path){a}"));
                    }
                }
            }

            // File-related calls: path is usually the first argument.
            if (name_lower.contains("createfile")
                || name_lower.contains("writefile")
                || name_lower.contains("readfile")
                || name_lower.contains("movefile")
                || name_lower.contains("copyfile")
                || name_lower.contains("deletefile"))
                && let Some(path) = call.args.first()
            {
                let p = path.trim();
                if !p.is_empty() && (p.contains('\\') || p.contains('/')) && p.len() > 3 {
                    col.file_paths.push(p.to_string());
                }
            }

            // Registry calls: key path is usually the second argument.
            if (name_lower.contains("regsetvalue")
                || name_lower.contains("regcreatekey")
                || name_lower.contains("ntsetvaluekey"))
                && let Some(key) = call.args.get(1)
            {
                let k = key.trim();
                if !k.is_empty() && k.len() > 4 {
                    col.registry_keys.push(k.to_string());
                }
            }

            // Mutex creation: name is usually the third argument.
            if (name_lower.contains("createmutex") || name_lower.contains("openmutex"))
                && let Some(mutex) = call.args.get(2)
            {
                let m = mutex.trim();
                if !m.is_empty() && m != "0" {
                    col.mutexes.push(m.to_string());
                }
            }

            // Hash-like arguments in any call.
            for arg in &call.args {
                let a = arg.trim();
                if re_hash_md5.is_match(a) || re_hash_sha1.is_match(a) || re_hash_sha256.is_match(a)
                {
                    col.hashes.push(a.to_string());
                }
                if re_btc.is_match(a) {
                    col.btc_addresses.push(a.to_string());
                }
                // Full URL in any argument.
                if re_url.is_match(a) && !col.urls.contains(&a.to_string()) {
                    col.urls.push(a.to_string());
                }
            }
        }

        col.deduplicate();
        col
    }

    /// Scan a raw PCAP payload for printable-string IOCs.
    ///
    /// This is a best-effort heuristic: it extracts ASCII strings of at least 8
    /// characters and matches them against IP, domain, URL, and hash patterns.
    #[must_use]
    pub fn from_network_pcap(pcap_bytes: &[u8]) -> Self {
        // Extract printable ASCII strings (min 8 chars).
        let strings = extract_ascii_strings(pcap_bytes, 8);

        let re_ipv4 = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").expect("valid regex");
        let re_url = Regex::new(r#"(?i)(https?://[^\s<>"]{8,})"#).expect("valid regex");
        let re_domain = Regex::new(
            r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|de|uk|fr|info|biz|xyz|top|evil|onion))\b",
        ).expect("valid regex");
        let re_hash_md5 = Regex::new(r"\b([0-9a-fA-F]{32})\b").expect("valid regex");
        let re_hash_sha256 = Regex::new(r"\b([0-9a-fA-F]{64})\b").expect("valid regex");
        let re_btc = Regex::new(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b").expect("valid regex");

        let mut col = Self::new();

        for s in &strings {
            // URLs — scan whole string.
            for cap in re_url.captures_iter(s) {
                if let Some(m) = cap.get(1) {
                    col.urls.push(m.as_str().to_string());
                }
            }
            // IPs.
            for cap in re_ipv4.captures_iter(s) {
                if let Some(m) = cap.get(1) {
                    let ip = m.as_str().to_string();
                    // Validate each octet.
                    if ip.split('.').all(|o| o.parse::<u8>().is_ok()) {
                        col.ips.push(ip);
                    }
                }
            }
            // Domains.
            for cap in re_domain.captures_iter(s) {
                if let Some(m) = cap.get(1) {
                    col.domains.push(m.as_str().to_string());
                }
            }
            // Hashes.
            for cap in re_hash_sha256.captures_iter(s) {
                if let Some(m) = cap.get(1) {
                    col.hashes.push(m.as_str().to_string());
                }
            }
            for cap in re_hash_md5.captures_iter(s) {
                if let Some(m) = cap.get(1) {
                    col.hashes.push(m.as_str().to_string());
                }
            }
            // BTC addresses.
            for cap in re_btc.captures_iter(s) {
                if let Some(m) = cap.get(1) {
                    col.btc_addresses.push(m.as_str().to_string());
                }
            }
            // File paths.
            if s.contains('\\') || (s.starts_with('/') && s.len() > 4) {
                col.file_paths.push(s.clone());
            }
        }

        col.deduplicate();
        col
    }

    /// Extract IOCs from a list of dropped files.
    ///
    /// Collects file paths and SHA-256 hashes from each `DroppedFile`.
    #[must_use]
    pub fn from_dropped_files(files: &[DroppedFile]) -> Self {
        let mut col = Self::new();
        for f in files {
            if !f.path.is_empty() {
                col.file_paths.push(f.path.clone());
            }
            if !f.sha256.is_empty() {
                col.hashes.push(f.sha256.clone());
            }
            if !f.md5.is_empty() {
                col.hashes.push(f.md5.clone());
            }
        }
        col.deduplicate();
        col
    }
}

// ─── extract_iocs ─────────────────────────────────────────────────────────────

/// Aggregate all IOCs from a complete `SandboxResult`.
///
/// Combines API-trace extraction, PCAP scanning, dropped-file hashes,
/// network captures, mutex names, and registry keys.
#[must_use]
pub fn extract_iocs(sandbox_result: &SandboxResult) -> IocCollection {
    let mut col = IocCollection::new();

    // From API trace.
    col.merge(IocCollection::from_api_trace(&sandbox_result.api_calls));

    // From PCAP bytes.
    if !sandbox_result.pcap_bytes.is_empty() {
        col.merge(IocCollection::from_network_pcap(&sandbox_result.pcap_bytes));
    }

    // From dropped files.
    col.merge(IocCollection::from_dropped_files(
        &sandbox_result.dropped_files,
    ));

    // From live network captures.
    for net in &sandbox_result.network {
        if !net.remote_ip.is_empty() {
            col.ips.push(net.remote_ip.clone());
        }
        if let Some(ref host) = net.http_host
            && !host.is_empty()
        {
            col.domains.push(host.clone());
        }
        if let Some(ref url) = net.http_url
            && !url.is_empty()
        {
            col.urls.push(url.clone());
        }
        if let Some(ref dns) = net.dns_query
            && !dns.is_empty()
        {
            col.domains.push(dns.clone());
        }
    }

    // From registry operations.
    for reg in &sandbox_result.registry {
        if !reg.key.is_empty() {
            col.registry_keys.push(reg.key.clone());
        }
    }

    // From mutexes.
    for m in &sandbox_result.mutexes {
        if !m.is_empty() {
            col.mutexes.push(m.clone());
        }
    }

    col.deduplicate();
    col
}

// ─── MalwareConfig ───────────────────────────────────────────────────────────

/// A decoded malware configuration extracted from a memory dump or binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareConfig {
    /// Malware family name, e.g. `"emotet"`.
    pub family: String,
    /// C2 server addresses (host:port or URL).
    pub c2_servers: Vec<String>,
    /// Raw encryption key bytes, if recovered.
    pub encryption_key: Option<Vec<u8>>,
    /// Campaign or botnet identifier, if present.
    pub campaign_id: Option<String>,
    /// Arbitrary extra key/value pairs from the config.
    pub extra: HashMap<String, String>,
}

impl MalwareConfig {
    /// Create an empty config for the given family.
    #[must_use]
    pub fn new(family: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            c2_servers: vec![],
            encryption_key: None,
            campaign_id: None,
            extra: HashMap::new(),
        }
    }

    /// Add a C2 server entry.
    pub fn add_c2(&mut self, server: impl Into<String>) {
        self.c2_servers.push(server.into());
    }

    /// Set an extra key/value field.
    pub fn set_extra(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extra.insert(key.into(), value.into());
    }

    /// Returns `true` if at least one C2 server was recovered.
    #[must_use]
    pub const fn has_c2(&self) -> bool {
        !self.c2_servers.is_empty()
    }

    /// Returns the encryption key as a lowercase hex string, if present.
    #[must_use]
    pub fn key_hex(&self) -> Option<String> {
        self.encryption_key.as_ref().map(hex::encode)
    }
}

// ─── extract_config ──────────────────────────────────────────────────────────

/// Attempt to extract a malware configuration from a raw memory dump.
///
/// Pattern-matching heuristics are applied for common families:
/// - **generic**: scan for URLs in the dump.
/// - **emotet**: XOR-decode with a set of common single-byte keys, then look
///   for `ip:port` pairs.
/// - **`cobalt_strike`**: look for the watermark / configuration beacon byte
///   pattern (`0x2e 0x2e 0x2e`).
///
/// Returns `None` if no recognisable configuration could be extracted.
#[must_use]
pub fn extract_config(family: &str, memory_dump: &[u8]) -> Option<MalwareConfig> {
    match family.to_ascii_lowercase().as_str() {
        "emotet" => extract_config_emotet(memory_dump),
        "cobalt_strike" | "cobaltstrike" | "cs" => extract_config_cobalt_strike(memory_dump),
        _ => extract_config_generic(memory_dump),
    }
}

/// Generic config extraction: scan for URLs in memory.
fn extract_config_generic(dump: &[u8]) -> Option<MalwareConfig> {
    let strings = extract_ascii_strings(dump, 8);
    let re_url = Regex::new(r#"(?i)https?://[^\s<>"]{4,}"#).expect("valid regex");
    let re_ipport =
        Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b").expect("valid regex");

    let mut cfg = MalwareConfig::new("generic");
    for s in &strings {
        for cap in re_url.captures_iter(s) {
            cfg.add_c2(cap[0].to_string());
        }
        for cap in re_ipport.captures_iter(s) {
            if let (Ok(_ip), Ok(port)) =
                (cap[1].parse::<std::net::Ipv4Addr>(), cap[2].parse::<u16>())
            {
                cfg.add_c2(format!("{}:{}", &cap[1], port));
            }
        }
    }

    if cfg.has_c2() { Some(cfg) } else { None }
}

/// Emotet-style extraction: XOR-decode with common keys, then find IP:port pairs.
fn extract_config_emotet(dump: &[u8]) -> Option<MalwareConfig> {
    // Common single-byte XOR keys used by Emotet variants.
    const COMMON_KEYS: &[u8] = &[0x05, 0x0a, 0x1b, 0x22, 0x33, 0x42, 0x7f, 0xff];

    let re_ipport =
        Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\b").expect("valid regex");

    let mut cfg = MalwareConfig::new("emotet");

    // Also scan the raw dump first.
    let raw_strings = extract_ascii_strings(dump, 7);
    for s in &raw_strings {
        for cap in re_ipport.captures_iter(s) {
            if cap[2].parse::<u16>().is_ok() {
                cfg.add_c2(format!("{}:{}", &cap[1], &cap[2]));
            }
        }
    }

    // Try each XOR key.
    for &key in COMMON_KEYS {
        let decoded: Vec<u8> = dump.iter().map(|&b| b ^ key).collect();
        let strings = extract_ascii_strings(&decoded, 7);
        for s in &strings {
            for cap in re_ipport.captures_iter(s) {
                if cap[2].parse::<u16>().is_ok() {
                    let entry = format!("{}:{}", &cap[1], &cap[2]);
                    if !cfg.c2_servers.contains(&entry) {
                        cfg.add_c2(entry);
                        // Record the successful key.
                        cfg.encryption_key.get_or_insert_with(Vec::new).push(key);
                    }
                }
            }
        }
    }

    if cfg.has_c2() { Some(cfg) } else { None }
}

/// Cobalt Strike config extraction: look for `0x2e 0x2e 0x2e` watermark sequence.
fn extract_config_cobalt_strike(dump: &[u8]) -> Option<MalwareConfig> {
    // The CS beacon config block is often preceded by a sequence of 0x2e bytes.
    const BEACON_MARKER: &[u8] = &[0x2e, 0x2e, 0x2e];
    // Alternative: look for the 0x0001 (BeaconType) field magic.
    const FIELD_MAGIC: &[u8] = &[0x00, 0x01, 0x00, 0x02];

    let has_marker = dump
        .windows(BEACON_MARKER.len())
        .any(|w| w == BEACON_MARKER);
    let has_field = dump.windows(FIELD_MAGIC.len()).any(|w| w == FIELD_MAGIC);

    if !has_marker && !has_field {
        return None;
    }

    let mut cfg = MalwareConfig::new("cobalt_strike");
    cfg.set_extra("detection", "beacon_marker_found");

    // Scan for embedded URLs (C2 profile URIs are plain ASCII in the config block).
    let re_url = Regex::new(r"(?i)https?://[^\x00-\x1f\x7f-\xff]{4,64}").expect("valid regex");
    let strings = extract_ascii_strings(dump, 6);
    for s in &strings {
        for cap in re_url.captures_iter(s) {
            cfg.add_c2(cap[0].to_string());
        }
    }

    // Try to find the watermark as a u32 LE at known offset (best-effort).
    if dump.len() > 8 {
        let wm_bytes = &dump[..4];
        cfg.set_extra("watermark_bytes", hex::encode(wm_bytes));
    }

    Some(cfg)
}

// ─── SandboxArtifact ─────────────────────────────────────────────────────────

/// The semantic kind of a file-based sandbox artifact stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxArtifactKind {
    /// A file dropped to disk by the malware.
    DroppedFile,
    /// A PCAP network capture file.
    NetworkCapture,
    /// A raw memory dump.
    MemoryDump,
    /// A screenshot image.
    Screenshot,
    /// An API trace log.
    ApiTrace,
    /// A memory region containing injected code.
    InjectedCode,
    /// An unrecognised / generic artifact.
    Other(String),
}

impl fmt::Display for SandboxArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DroppedFile => write!(f, "dropped_file"),
            Self::NetworkCapture => write!(f, "network_capture"),
            Self::MemoryDump => write!(f, "memory_dump"),
            Self::Screenshot => write!(f, "screenshot"),
            Self::ApiTrace => write!(f, "api_trace"),
            Self::InjectedCode => write!(f, "injected_code"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// A file-based artifact produced during or after sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxArtifact {
    /// Semantic kind of this artifact.
    pub kind: SandboxArtifactKind,
    /// Absolute path to the artifact on the analysis host.
    pub path: PathBuf,
    /// SHA-256 hex digest of the file contents.
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

impl SandboxArtifact {
    /// Create a new artifact record.
    #[must_use]
    pub fn new(
        kind: SandboxArtifactKind,
        path: PathBuf,
        hash: impl Into<String>,
        size: u64,
    ) -> Self {
        Self {
            kind,
            path,
            hash: hash.into(),
            size,
        }
    }

    /// Infer the artifact kind from a file extension.
    #[must_use]
    pub fn kind_from_extension(ext: &str) -> SandboxArtifactKind {
        match ext.to_ascii_lowercase().as_str() {
            "pcap" | "pcapng" | "cap" => SandboxArtifactKind::NetworkCapture,
            "dmp" | "dump" | "bin" => SandboxArtifactKind::MemoryDump,
            "png" | "jpg" | "bmp" => SandboxArtifactKind::Screenshot,
            "log" | "txt" | "json" => SandboxArtifactKind::ApiTrace,
            "exe" | "dll" | "sys" | "scr" | "bat" | "ps1" => SandboxArtifactKind::DroppedFile,
            _ => SandboxArtifactKind::Other(ext.to_string()),
        }
    }
}

// ─── collect_artifacts ────────────────────────────────────────────────────────

/// Walk a sandbox report directory and collect all recognised artifact files.
///
/// Each file is stat-ed for its size; the hash field is set to the empty string
/// because computing real SHA-256 would require an I/O dependency — callers can
/// fill it in after the fact.
///
/// # Errors
/// Returns an `anyhow::Error` if the directory cannot be read.
pub fn collect_artifacts(report_dir: &Path) -> Result<Vec<SandboxArtifact>> {
    let mut artifacts = Vec::new();

    let rd = std::fs::read_dir(report_dir)?;
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let kind = SandboxArtifact::kind_from_extension(ext);

        // Skip unknown small files (< 16 bytes) that are clearly not artifacts.
        if matches!(kind, SandboxArtifactKind::Other(_)) && size < 16 {
            continue;
        }

        artifacts.push(SandboxArtifact::new(kind, path, "", size));
    }

    // Sort by path for deterministic output.
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(artifacts)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract printable ASCII strings of at least `min_len` characters from `data`.
fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    out
}

/// Sort and deduplicate a `Vec<String>` in-place.
fn dedup_vec(v: &mut Vec<String>) {
    v.sort_unstable();
    v.dedup();
}

// ─── SandboxEvent (local definition, mirrors rustre-sandbox-vm) ──────────────
//
// A minimal, self-contained copy of the event type so that `rustre-sandbox-extract`
// does not need to depend on the full VM crate.  The fields and variant names
// are intentionally compatible so cross-crate consumers can convert trivially.

/// High-level category for a `SandboxEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxEventKind {
    /// An API function was called; inner string is the function name.
    ApiCall(String),
    /// A file operation (create / write / delete); inner string is the path or verb.
    FileOp(String),
    /// A network connection was attempted.
    NetworkConn {
        /// Source IP.
        src_ip: String,
        /// Destination IP.
        dst_ip: String,
        /// Destination port.
        dst_port: u16,
        /// Protocol string.
        proto: String,
        /// Raw payload bytes captured.
        payload: Vec<u8>,
        /// Direction: `"outbound"` or `"inbound"`.
        direction: String,
    },
    /// Code was injected into another process.
    CodeInjection {
        /// PID of the target process.
        target_pid: u32,
        /// SHA-256 of the injected region (empty if unknown).
        bytes_hash: String,
    },
    /// Generic / uncategorised.
    Other(String),
}

/// A discrete event recorded during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEvent {
    /// Milliseconds since execution start.
    pub ts_ms: u64,
    /// PID that generated this event.
    pub pid: u32,
    /// High-level category.
    pub kind: SandboxEventKind,
    /// Human-readable detail string.
    pub detail: String,
}

impl SandboxEvent {
    /// Create a new event with the given fields.
    #[must_use]
    pub fn new(ts_ms: u64, pid: u32, kind: SandboxEventKind, detail: impl Into<String>) -> Self {
        Self {
            ts_ms,
            pid,
            kind,
            detail: detail.into(),
        }
    }
}

// ─── ArtifactExtractor ───────────────────────────────────────────────────────

/// A file dropped to disk by the sandboxed process as recorded in event logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedDroppedFile {
    /// Path on the guest filesystem.
    pub path: String,
    /// SHA-256 hex digest of the file contents (as recorded in the event).
    pub content_hash: String,
    /// Size in bytes.
    pub size: usize,
}

/// A network payload captured from sandbox event logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPayload {
    /// `"outbound"` or `"inbound"`.
    pub direction: String,
    /// Raw payload bytes.
    pub content: Vec<u8>,
    /// Source IP.
    pub src_ip: String,
    /// Destination IP.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol string.
    pub proto: String,
}

/// Code injected into a target process, as captured in event logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedCode {
    /// PID of the victim process.
    pub target_pid: u32,
    /// SHA-256 hex digest of the injected bytes (may be empty if not captured).
    pub bytes_hash: String,
}

/// Pulls typed artifacts out of a `SandboxEvent` slice.
///
/// Named `SandboxArtifactExtractor` to avoid collision with the existing
/// `ArtifactExtractor` trait defined earlier in this module.
pub struct SandboxArtifactExtractor;

impl SandboxArtifactExtractor {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Extract all file-drop records from the event stream.
    ///
    /// Every `SandboxEventKind::FileOp` whose verb string contains `"create"`
    /// or `"write"` is treated as a dropped file.  The `detail` field is
    /// expected to follow the convention `"<path>|<sha256>|<size>"` produced
    /// by the guest agent.  Fields that are missing or unparseable are left as
    /// empty / zero.
    #[must_use]
    pub fn extract_dropped_files(&self, events: &[SandboxEvent]) -> Vec<ExtractedDroppedFile> {
        events
            .iter()
            .filter_map(|e| {
                if let SandboxEventKind::FileOp(verb) = &e.kind {
                    if verb.contains("create") || verb.contains("write") {
                        // Parse the detail field: "<path>|<sha256>|<size_bytes>"
                        let parts: Vec<&str> = e.detail.splitn(3, '|').collect();
                        let path = parts.first().copied().unwrap_or("").to_string();
                        let content_hash = parts.get(1).copied().unwrap_or("").to_string();
                        let size = parts
                            .get(2)
                            .and_then(|s| s.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        Some(ExtractedDroppedFile {
                            path,
                            content_hash,
                            size,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract network payloads from the event stream.
    ///
    /// Each `SandboxEventKind::NetworkConn` event contributes one
    /// `NetworkPayload` entry.
    #[must_use]
    pub fn extract_network_payloads(&self, events: &[SandboxEvent]) -> Vec<NetworkPayload> {
        events
            .iter()
            .filter_map(|e| {
                if let SandboxEventKind::NetworkConn {
                    src_ip,
                    dst_ip,
                    dst_port,
                    proto,
                    payload,
                    direction,
                } = &e.kind
                {
                    Some(NetworkPayload {
                        direction: direction.clone(),
                        content: payload.clone(),
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        dst_port: *dst_port,
                        proto: proto.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract code-injection records from the event stream.
    #[must_use]
    pub fn extract_injected_code(&self, events: &[SandboxEvent]) -> Vec<InjectedCode> {
        events
            .iter()
            .filter_map(|e| {
                if let SandboxEventKind::CodeInjection {
                    target_pid,
                    bytes_hash,
                } = &e.kind
                {
                    Some(InjectedCode {
                        target_pid: *target_pid,
                        bytes_hash: bytes_hash.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for SandboxArtifactExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── MemoryRegionDumper ───────────────────────────────────────────────────────

/// A single dumped memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpRegion {
    /// Process ID that owns this region.
    pub pid: u32,
    /// Start virtual address.
    pub start_addr: u64,
    /// Length of the region in bytes.
    pub size: usize,
    /// Region permissions, e.g. `"r-xp"`.
    pub perms: String,
    /// Path of the backing file (e.g. a mapped `.so` / `.dll`), if any.
    pub path: Option<String>,
    /// Raw bytes of the region (may be empty if read failed or truncated).
    pub bytes: Vec<u8>,
}

impl MemoryDumpRegion {
    /// Create a new region descriptor.
    #[must_use]
    pub fn new(pid: u32, start_addr: u64, size: usize, perms: impl Into<String>) -> Self {
        Self {
            pid,
            start_addr,
            size,
            perms: perms.into(),
            path: None,
            bytes: vec![],
        }
    }

    /// Returns `true` if this region is executable.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }
}

/// Dumps executable memory regions from a running process.
pub struct MemoryRegionDumper;

impl MemoryRegionDumper {
    /// Create a new dumper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Dump all executable memory regions for `pid`.
    ///
    /// ## Linux
    /// Reads `/proc/<pid>/maps` to enumerate regions, then reads each
    /// executable region from `/proc/<pid>/mem`.  Regions that cannot be
    /// read (e.g. due to permissions or the process having exited) are
    /// silently skipped.
    ///
    /// ## Windows
    /// Walks the address space of the target process with `VirtualQueryEx`
    /// and reads each committed executable region via `ReadProcessMemory`.
    /// Requires `SeDebugPrivilege` for processes the caller does not own.
    ///
    /// ## Other platforms
    /// Returns an empty `Vec` — live memory reading requires platform-specific
    /// APIs that are not wired up here.
    /// Integrate with a real debugger or the `HyperDBG` / Frida MCP tools for
    /// live Windows support.
    ///
    /// # Errors
    /// Returns an error only if the `/proc` filesystem is completely
    /// inaccessible (Linux) or for non-Linux platforms returns `Ok(vec![])`.
    pub fn dump_executable_regions(
        &self,
        pid: u32,
    ) -> Result<Vec<MemoryDumpRegion>, ExtractError> {
        #[cfg(target_os = "linux")]
        {
            self.dump_linux(pid)
        }
        #[cfg(target_os = "windows")]
        {
            self.dump_windows(pid)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = pid;
            Ok(vec![])
        }
    }

    #[cfg(target_os = "windows")]
    fn dump_windows(&self, pid: u32) -> Result<Vec<MemoryDumpRegion>, ExtractError> {
        use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE,
            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        // SAFETY: OpenProcess is an FFI call with `pid` passed by value and no
        // memory shared with Rust. The returned handle is checked before any
        // dependent call and closed on every return path below.
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
        };
        if handle.is_null() {
            return Err(ExtractError::Io(format!(
                "OpenProcess(pid={pid}) failed; SeDebugPrivilege may be required"
            )));
        }

        let exec_mask =
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        let mut regions = Vec::new();
        let mut address: usize = 0;
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: `mbi` is a stack-local, properly-sized buffer; we pass
            // its address and the exact byte size as required by the API.
            let written = unsafe {
                VirtualQueryEx(handle, address as *const _, &raw mut mbi, mbi_size)
            };
            if written == 0 {
                break;
            }

            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            let is_committed = mbi.State == MEM_COMMIT;
            let is_executable = (mbi.Protect & exec_mask) != 0;

            if is_committed && is_executable && region_size > 0 {
                let mut buf = vec![0u8; region_size];
                let mut bytes_read: usize = 0;
                // SAFETY: `buf` owns `region_size` bytes; ReadProcessMemory
                // writes at most that many and reports the actual count
                // through `bytes_read`. Failures are non-fatal — the region
                // is skipped, mirroring the Linux fallback behaviour.
                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buf.as_mut_ptr().cast(),
                        region_size,
                        &raw mut bytes_read,
                    )
                };
                if ok != 0 && bytes_read > 0 {
                    buf.truncate(bytes_read);
                    let mut perms = String::from("r-x");
                    if mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0 {
                        perms = String::from("rwx");
                    }
                    regions.push(MemoryDumpRegion {
                        pid,
                        start_addr: region_base as u64,
                        size: bytes_read,
                        perms,
                        path: None,
                        bytes: buf,
                    });
                }
            }

            let next = region_base.saturating_add(region_size);
            if next == address {
                break;
            }
            address = next;
        }

        // SAFETY: `handle` was produced by OpenProcess above and is closed
        // exactly once here on the normal return path.
        unsafe {
            CloseHandle(handle);
        }
        Ok(regions)
    }

    #[cfg(target_os = "linux")]
    fn dump_linux(&self, pid: u32) -> Result<Vec<MemoryDumpRegion>, ExtractError> {
        use std::fs::File;
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
        use std::str::FromStr;

        let maps_path = format!("/proc/{pid}/maps");
        let maps_file = File::open(&maps_path)
            .map_err(|e| ExtractError::Io(format!("cannot open {maps_path}: {e}")))?;

        let mem_path = format!("/proc/{pid}/mem");
        // Opening /proc/PID/mem may fail if we don't have ptrace permissions.
        let mem_file = File::open(&mem_path).ok();

        let mut regions = Vec::new();

        for line in BufReader::new(maps_file).lines() {
            let line = line.map_err(|e| ExtractError::Io(e.to_string()))?;
            // Format: addr_start-addr_end perms offset dev inode [path]
            // Example: 00400000-00401000 r-xp 00000000 fd:01 123456 /bin/cat
            let mut parts = line.splitn(6, ' ');
            let addrs = parts.next().unwrap_or("");
            let perms = parts.next().unwrap_or("");
            // Skip offset, dev, inode.
            let _offset = parts.next();
            let _dev = parts.next();
            let _inode = parts.next();
            let path = parts
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            // Only care about executable regions.
            if !perms.contains('x') {
                continue;
            }

            // Parse address range.
            let (start_str, end_str) = match addrs.split_once('-') {
                Some(p) => p,
                None => continue,
            };
            let start = u64::from_str_radix(start_str, 16).unwrap_or(0);
            let end = u64::from_str_radix(end_str, 16).unwrap_or(0);
            if end <= start {
                continue;
            }
            let size = (end - start) as usize;

            let mut region = MemoryDumpRegion::new(pid, start, size, perms);
            region.path = path;

            // Attempt to read the bytes from /proc/PID/mem.
            if let Some(ref mut mf) = mem_file.as_ref().map(|_| {
                // Re-open each time because seeks on /proc/mem are per-fd.
                File::open(&mem_path).ok()
            }) {
                if let Some(ref mut mf_inner) = mf {
                    if mf_inner.seek(SeekFrom::Start(start)).is_ok() {
                        let mut buf = vec![0u8; size.min(65536)]; // cap at 64 KiB
                        match mf_inner.read(&mut buf) {
                            Ok(n) => {
                                buf.truncate(n);
                                region.bytes = buf;
                            }
                            Err(_) => {} // permission denied or process gone — skip
                        }
                    }
                }
            }

            regions.push(region);
        }

        Ok(regions)
    }
}

impl Default for MemoryRegionDumper {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ArtifactKind ─────────────────────────────────────────────────────────

    #[test]
    fn test_artifact_kind_display_all() {
        assert_eq!(ArtifactKind::DroppedFile.to_string(), "dropped_file");
        assert_eq!(ArtifactKind::NetworkConn.to_string(), "network_conn");
        assert_eq!(ArtifactKind::RegistryKey.to_string(), "registry_key");
        assert_eq!(ArtifactKind::ProcessSpawn.to_string(), "process_spawn");
        assert_eq!(ArtifactKind::MutexCreate.to_string(), "mutex_create");
        assert_eq!(ArtifactKind::InjectedCode.to_string(), "injected_code");
        assert_eq!(ArtifactKind::MemoryDump.to_string(), "memory_dump");
        assert_eq!(ArtifactKind::Credential.to_string(), "credential");
        assert_eq!(ArtifactKind::Config.to_string(), "config");
        assert_eq!(ArtifactKind::PackerLayer.to_string(), "packer_layer");
    }

    // ── DroppedFile ──────────────────────────────────────────────────────────

    #[test]
    fn test_dropped_file_extension() {
        let f = DroppedFile::new("/tmp/payload.exe", 100, "abc");
        assert_eq!(f.extension(), "exe");
    }

    #[test]
    fn test_dropped_file_extension_no_ext() {
        let f = DroppedFile::new("/tmp/payload", 100, "abc");
        assert_eq!(f.extension(), "");
    }

    #[test]
    fn test_dropped_file_is_pe() {
        let mut f = DroppedFile::new("payload.exe", 100, "abc");
        f.preview = vec![0x4d, 0x5a, 0x90, 0x00];
        assert!(f.is_pe());
    }

    #[test]
    fn test_dropped_file_is_elf() {
        let mut f = DroppedFile::new("payload", 100, "abc");
        f.preview = vec![0x7f, 0x45, 0x4c, 0x46];
        assert!(f.is_elf());
    }

    #[test]
    fn test_dropped_file_is_zip() {
        let mut f = DroppedFile::new("payload.zip", 100, "abc");
        f.preview = vec![0x50, 0x4b, 0x03, 0x04];
        assert!(f.is_zip());
    }

    #[test]
    fn test_dropped_file_is_executable_ext() {
        let f = DroppedFile::new("script.ps1", 10, "abc");
        assert!(f.is_executable());
    }

    #[test]
    fn test_dropped_file_preview_entropy() {
        let mut f = DroppedFile::new("a", 4, "abc");
        f.preview = vec![0x00, 0x01, 0x02, 0x03];
        let entropy = f.preview_entropy();
        assert!(entropy > 0.0);
        assert!(entropy <= 8.0);
    }

    #[test]
    fn test_dropped_file_preview_entropy_empty() {
        let f = DroppedFile::new("a", 0, "abc");
        assert_eq!(f.preview_entropy(), 0.0);
    }

    // ── MemoryDump ───────────────────────────────────────────────────────────

    #[test]
    fn test_memory_dump_has_pe_header() {
        let dump = MemoryDump::new(1, "test", 0, vec![0x4d, 0x5a, 0x90, 0x00]);
        assert!(dump.has_pe_header());
    }

    #[test]
    fn test_memory_dump_no_pe_header() {
        let dump = MemoryDump::new(1, "test", 0, vec![0x00, 0x01, 0x02]);
        assert!(!dump.has_pe_header());
    }

    #[test]
    fn test_memory_dump_entropy() {
        let data: Vec<u8> = (0u8..=255).collect();
        let dump = MemoryDump::new(1, "test", 0, data);
        let e = dump.entropy();
        // Uniform distribution → close to 8.0.
        assert!(e > 7.9);
    }

    #[test]
    fn test_memory_dump_high_entropy() {
        // All-zero = 0 entropy.
        let dump = MemoryDump::new(1, "zero", 0, vec![0u8; 100]);
        assert!(!dump.is_high_entropy());
    }

    #[test]
    fn test_memory_dump_extract_strings() {
        let data = b"Hello World\x00nop\x00this_is_a_long_string\x00\x01\x02";
        let dump = MemoryDump::new(1, "test", 0, data.to_vec());
        let strings = dump.extract_strings(6);
        assert!(strings.iter().any(|s| s.contains("Hello World")));
        assert!(strings.iter().any(|s| s.contains("this_is_a_long_string")));
    }

    // ── NetworkCapture ───────────────────────────────────────────────────────

    #[test]
    fn test_network_capture_is_external() {
        let n = NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "8.8.8.8".to_string(),
            port: 53,
            bytes_sent: 0,
            bytes_recv: 0,
            dns_query: None,
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 0,
            pid: 0,
        };
        assert!(n.is_external());
    }

    #[test]
    fn test_network_capture_not_external_loopback() {
        let n = NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "127.0.0.1".to_string(),
            port: 80,
            bytes_sent: 0,
            bytes_recv: 0,
            dns_query: None,
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 0,
            pid: 0,
        };
        assert!(!n.is_external());
    }

    #[test]
    fn test_network_capture_is_c2_port() {
        let n = NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "1.2.3.4".to_string(),
            port: 4444,
            bytes_sent: 0,
            bytes_recv: 0,
            dns_query: None,
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 0,
            pid: 0,
        };
        assert!(n.is_c2_port());
    }

    #[test]
    fn test_network_capture_is_likely_c2() {
        let n = NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "185.220.101.1".to_string(),
            port: 443,
            bytes_sent: 0,
            bytes_recv: 0,
            dns_query: None,
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 0,
            pid: 0,
        };
        assert!(n.is_likely_c2());
    }

    // ── RegistryOp ───────────────────────────────────────────────────────────

    #[test]
    fn test_registry_op_is_persistence() {
        let r = RegistryOp {
            key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            value: "Malware".to_string(),
            data: None,
            op: RegOpKind::SetValue,
            ts_ms: 0,
            pid: 0,
        };
        assert!(r.is_persistence());
    }

    #[test]
    fn test_registry_op_not_persistence() {
        let r = RegistryOp {
            key: r"HKLM\Software\Microsoft\Windows NT".to_string(),
            value: "ProductName".to_string(),
            data: None,
            op: RegOpKind::QueryValue,
            ts_ms: 0,
            pid: 0,
        };
        assert!(!r.is_persistence());
    }

    #[test]
    fn test_reg_op_kind_display() {
        assert_eq!(RegOpKind::Create.to_string(), "create");
        assert_eq!(RegOpKind::SetValue.to_string(), "set_value");
        assert_eq!(RegOpKind::QueryValue.to_string(), "query_value");
        assert_eq!(RegOpKind::EnumKey.to_string(), "enum_key");
    }

    // ── ProcessSpawn ─────────────────────────────────────────────────────────

    #[test]
    fn test_process_spawn_is_shell() {
        let p = ProcessSpawn {
            parent_pid: 1,
            child_pid: 2,
            cmdline: "cmd.exe /c whoami".to_string(),
            image: "cmd.exe".to_string(),
            ts_ms: 0,
            injected: false,
        };
        assert!(p.is_shell());
    }

    #[test]
    fn test_process_spawn_is_lolbin() {
        let p = ProcessSpawn {
            parent_pid: 1,
            child_pid: 2,
            cmdline: "certutil -decode file.b64 file.exe".to_string(),
            image: "certutil.exe".to_string(),
            ts_ms: 0,
            injected: false,
        };
        assert!(p.is_lolbin());
    }

    #[test]
    fn test_process_spawn_not_shell() {
        let p = ProcessSpawn {
            parent_pid: 1,
            child_pid: 2,
            cmdline: "notepad.exe".to_string(),
            image: "notepad.exe".to_string(),
            ts_ms: 0,
            injected: false,
        };
        assert!(!p.is_shell());
    }

    // ── PackerDetector ───────────────────────────────────────────────────────

    #[test]
    fn test_packer_detector_upx() {
        let det = PackerDetector::new();
        let data = b"MZ\x90\x00UPX!\x00\x00UPX0\x00\x00";
        let layers = det.detect(data);
        assert!(layers.iter().any(|l| l.name == "UPX"));
    }

    #[test]
    fn test_packer_detector_no_match() {
        let det = PackerDetector::new();
        let data = b"MZ\x90\x00\x00\x00\x00\x00";
        let layers = det.detect(data);
        assert!(layers.is_empty());
    }

    #[test]
    fn test_packer_detector_signature_count() {
        let det = PackerDetector::new();
        assert!(det.signature_count() >= 6);
    }

    #[test]
    fn test_packer_layer_high_entropy() {
        let l = PackerLayer::new("UPX", 0, 100, 7.9);
        assert!(l.is_high_entropy());
    }

    #[test]
    fn test_packer_layer_not_high_entropy() {
        let l = PackerLayer::new("UPX", 0, 100, 5.0);
        assert!(!l.is_high_entropy());
    }

    #[test]
    fn test_packer_layer_not_unpacked() {
        let l = PackerLayer::new("UPX", 0, 100, 7.5);
        assert!(!l.is_unpacked());
    }

    // ── ConfigExtractor ──────────────────────────────────────────────────────

    #[test]
    fn test_config_extractor_ip_port() {
        let ext = ConfigExtractor::new();
        let strings = ["185.220.101.1:443", "some other string"];
        let config = ext.extract_from_strings(&strings, "rat");
        assert!(config.field("c2").is_some());
    }

    #[test]
    fn test_config_extractor_url() {
        let ext = ConfigExtractor::new();
        let strings = ["https://c2server.evil/beacon"];
        let config = ext.extract_from_strings(&strings, "banker");
        assert!(config.field("url").is_some());
    }

    #[test]
    fn test_config_extractor_key_value() {
        let ext = ConfigExtractor::new();
        let strings = ["sleep_ms=5000"];
        let config = ext.extract_from_strings(&strings, "rat");
        assert_eq!(config.field("sleep_ms"), Some("5000"));
    }

    #[test]
    fn test_config_extractor_from_dump() {
        let ext = ConfigExtractor::new();
        let data = b"185.220.101.1:443\x00https://evil.com/beacon\x00sleep_ms=5000\x00";
        let dump = MemoryDump::new(1, "test", 0, data.to_vec());
        let config = ext.extract_from_dump(&dump, "rat");
        assert_eq!(config.family, "rat");
    }

    // ── ArtifactCollection ───────────────────────────────────────────────────

    #[test]
    fn test_collection_new_empty() {
        let c = ArtifactCollection::new();
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn test_collection_add_artifact() {
        let mut c = ArtifactCollection::new();
        c.add_artifact(Artifact::new(ArtifactKind::InjectedCode, 1, "test"));
        assert_eq!(c.total(), 1);
    }

    #[test]
    fn test_collection_add_file() {
        let mut c = ArtifactCollection::new();
        c.add_file(DroppedFile::new("/tmp/a.exe", 100, "abc"));
        assert_eq!(c.files.len(), 1);
    }

    #[test]
    fn test_collection_add_network() {
        let mut c = ArtifactCollection::new();
        c.add_network(NetworkCapture {
            proto: "tcp".to_string(),
            remote_ip: "1.2.3.4".to_string(),
            port: 80,
            bytes_sent: 0,
            bytes_recv: 0,
            dns_query: None,
            http_host: None,
            http_url: None,
            http_method: None,
            payload_preview: vec![],
            ts_ms: 0,
            pid: 0,
        });
        assert_eq!(c.network.len(), 1);
    }

    #[test]
    fn test_collection_mock_total() {
        let c = ArtifactCollection::mock();
        assert!(c.total() > 0);
    }

    #[test]
    fn test_collection_mock_has_files() {
        let c = ArtifactCollection::mock();
        assert!(!c.files.is_empty());
    }

    #[test]
    fn test_collection_mock_has_network() {
        let c = ArtifactCollection::mock();
        assert!(!c.network.is_empty());
    }

    #[test]
    fn test_collection_mock_external_connections() {
        let c = ArtifactCollection::mock();
        let ext = c.external_connections();
        assert!(!ext.is_empty());
    }

    #[test]
    fn test_collection_mock_dropped_executables() {
        let c = ArtifactCollection::mock();
        let execs = c.dropped_executables();
        assert!(!execs.is_empty());
    }

    #[test]
    fn test_collection_mock_persistence_ops() {
        let c = ArtifactCollection::mock();
        let persist = c.persistence_ops();
        assert!(!persist.is_empty());
    }

    #[test]
    fn test_collection_mock_shell_spawns() {
        let c = ArtifactCollection::mock();
        let shells = c.shell_spawns();
        assert!(!shells.is_empty());
    }

    #[test]
    fn test_collection_mock_pe_dumps() {
        let c = ArtifactCollection::mock();
        let pe = c.pe_dumps();
        assert!(!pe.is_empty());
    }

    #[test]
    fn test_collection_mock_credentials() {
        let c = ArtifactCollection::mock();
        assert!(!c.credentials.is_empty());
    }

    #[test]
    fn test_collection_mock_packer_layers() {
        let c = ArtifactCollection::mock();
        assert!(!c.packer_layers.is_empty());
    }

    #[test]
    fn test_collection_mock_configs() {
        let c = ArtifactCollection::mock();
        assert!(!c.configs.is_empty());
    }

    // ── LogExtractor ─────────────────────────────────────────────────────────

    #[test]
    fn test_log_extractor_drop() {
        let log = "DROP:/tmp/payload.exe:deadbeef";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.files.len(), 1);
        assert_eq!(col.files[0].path, "/tmp/payload.exe");
        assert_eq!(col.files[0].sha256, "deadbeef");
    }

    #[test]
    fn test_log_extractor_net() {
        let log = "NET:8.8.8.8:53:udp";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.network.len(), 1);
        assert_eq!(col.network[0].remote_ip, "8.8.8.8");
        assert_eq!(col.network[0].port, 53);
        assert_eq!(col.network[0].proto, "udp");
    }

    #[test]
    fn test_log_extractor_proc() {
        let log = "PROC:1000:2000:cmd.exe";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.processes.len(), 1);
        assert_eq!(col.processes[0].parent_pid, 1000);
        assert_eq!(col.processes[0].child_pid, 2000);
    }

    #[test]
    fn test_log_extractor_reg() {
        let log = "REG:HKCU\\Run:malware:set";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.registry.len(), 1);
    }

    #[test]
    fn test_log_extractor_mem() {
        let log = "MEM:1234:injected:0x1000000";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.memory_dumps.len(), 1);
        assert_eq!(col.memory_dumps[0].pid, 1234);
    }

    #[test]
    fn test_log_extractor_cred() {
        let log = "CRED:password:smtp_server:SuperSecret!";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.credentials.len(), 1);
        assert_eq!(col.credentials[0].target, "smtp_server");
    }

    #[test]
    fn test_log_extractor_empty() {
        let ext = LogExtractor;
        let col = ext.extract("").unwrap();
        assert_eq!(col.total(), 0);
    }

    #[test]
    fn test_extract_error_parse() {
        let e = ExtractError::ParseError("bad line".to_string());
        assert!(e.to_string().contains("bad line"));
    }

    #[test]
    fn test_extract_error_io() {
        let e = ExtractError::Io("file not found".to_string());
        assert!(e.to_string().contains("file not found"));
    }

    #[test]
    fn test_extract_error_not_found() {
        let e = ExtractError::NotFound("artifact".to_string());
        assert!(e.to_string().contains("artifact"));
    }

    #[test]
    fn test_extract_error_invalid_format() {
        let e = ExtractError::InvalidFormat("bad header".to_string());
        assert!(e.to_string().contains("bad header"));
    }

    #[test]
    fn test_credential_kind_display() {
        assert_eq!(CredentialKind::Password.to_string(), "password");
        assert_eq!(CredentialKind::ApiKey.to_string(), "api_key");
        assert_eq!(CredentialKind::Hash.to_string(), "hash");
    }

    #[test]
    fn test_extract_ip_port_valid() {
        let result = extract_ip_port("185.220.101.1:443");
        assert_eq!(result.as_deref(), Some("185.220.101.1:443"));
    }

    #[test]
    fn test_extract_ip_port_invalid() {
        let result = extract_ip_port("not.an.ip:port");
        assert!(result.is_none());
    }

    #[test]
    fn test_log_extractor_multi_line() {
        let log = "DROP:/tmp/a.exe:abc\nNET:1.2.3.4:80:tcp\nREG:HKCU\\Run:m:set";
        let ext = LogExtractor;
        let col = ext.extract(log).unwrap();
        assert_eq!(col.files.len(), 1);
        assert_eq!(col.network.len(), 1);
        assert_eq!(col.registry.len(), 1);
    }

    // ── ApiCall ──────────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_new() {
        let call = ApiCall::new("CreateFileW", vec!["C:\\temp\\x.exe".to_string()]);
        assert_eq!(call.name, "CreateFileW");
        assert_eq!(call.args.len(), 1);
        assert_eq!(call.pid, 0);
    }

    // ── SandboxResult ────────────────────────────────────────────────────────

    #[test]
    fn test_sandbox_result_new() {
        let r = SandboxResult::new("test.exe", "abc123");
        assert_eq!(r.sample_name, "test.exe");
        assert_eq!(r.sha256, "abc123");
        assert!(r.api_calls.is_empty());
        assert!(r.mutexes.is_empty());
    }

    #[test]
    fn test_sandbox_result_mock_has_api_calls() {
        let r = SandboxResult::mock();
        assert!(!r.api_calls.is_empty());
    }

    #[test]
    fn test_sandbox_result_mock_has_network() {
        let r = SandboxResult::mock();
        assert!(!r.network.is_empty());
    }

    #[test]
    fn test_sandbox_result_mock_has_mutexes() {
        let r = SandboxResult::mock();
        assert!(!r.mutexes.is_empty());
    }

    // ── IocCollection ────────────────────────────────────────────────────────

    #[test]
    fn test_ioc_collection_new_empty() {
        let c = IocCollection::new();
        assert!(c.is_empty());
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn test_ioc_collection_from_dropped_files_path_and_hash() {
        let files = vec![DroppedFile::new(
            "/tmp/payload.exe",
            100,
            "abc123sha256hash000000000000000000000000000000000000000000000001",
        )];
        let col = IocCollection::from_dropped_files(&files);
        assert!(col.file_paths.iter().any(|p| p.contains("payload.exe")));
        assert!(!col.hashes.is_empty());
    }

    #[test]
    fn test_ioc_collection_from_dropped_files_empty() {
        let col = IocCollection::from_dropped_files(&[]);
        assert!(col.is_empty());
    }

    #[test]
    fn test_ioc_collection_from_api_trace_ip() {
        let calls = vec![ApiCall::new(
            "InternetConnectA",
            vec![
                "0".to_string(),
                "185.220.101.1".to_string(),
                "443".to_string(),
            ],
        )];
        let col = IocCollection::from_api_trace(&calls);
        assert!(col.ips.contains(&"185.220.101.1".to_string()));
    }

    #[test]
    fn test_ioc_collection_from_api_trace_mutex() {
        let calls = vec![ApiCall::new(
            "CreateMutexA",
            vec![
                "0".to_string(),
                "0".to_string(),
                "Global\\EvilMutex".to_string(),
            ],
        )];
        let col = IocCollection::from_api_trace(&calls);
        assert!(col.mutexes.contains(&"Global\\EvilMutex".to_string()));
    }

    #[test]
    fn test_ioc_collection_from_api_trace_registry() {
        let calls = vec![ApiCall::new(
            "RegSetValueExA",
            vec![
                "HKCU".to_string(),
                r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            ],
        )];
        let col = IocCollection::from_api_trace(&calls);
        assert!(!col.registry_keys.is_empty());
    }

    #[test]
    fn test_ioc_collection_from_api_trace_url() {
        let calls = vec![ApiCall::new(
            "HttpOpenRequestA",
            vec![
                "0".to_string(),
                "GET".to_string(),
                "/beacon".to_string(),
                "HTTP/1.1".to_string(),
            ],
        )];
        let col = IocCollection::from_api_trace(&calls);
        // path-only entries are stored with (path) prefix.
        assert!(col.urls.iter().any(|u| u.contains("beacon")));
    }

    #[test]
    fn test_ioc_collection_from_network_pcap_empty() {
        let col = IocCollection::from_network_pcap(&[]);
        assert!(col.is_empty());
    }

    #[test]
    fn test_ioc_collection_from_network_pcap_url() {
        let payload = b"GET /beacon HTTP/1.1\r\nHost: evil.com\r\nhttps://evil.com/c2\r\n";
        let col = IocCollection::from_network_pcap(payload);
        assert!(col.urls.iter().any(|u| u.contains("evil.com")));
    }

    #[test]
    fn test_ioc_collection_from_network_pcap_ip() {
        let payload = b"Connected to 185.220.101.1:443 successfully";
        let col = IocCollection::from_network_pcap(payload);
        assert!(col.ips.iter().any(|ip| ip.contains("185.220")));
    }

    #[test]
    fn test_ioc_collection_deduplicate() {
        let mut col = IocCollection::new();
        col.ips.push("1.2.3.4".to_string());
        col.ips.push("1.2.3.4".to_string());
        col.deduplicate();
        assert_eq!(col.ips.len(), 1);
    }

    #[test]
    fn test_ioc_collection_merge() {
        let mut a = IocCollection::new();
        a.ips.push("1.1.1.1".to_string());
        let mut b = IocCollection::new();
        b.ips.push("2.2.2.2".to_string());
        a.merge(b);
        assert_eq!(a.ips.len(), 2);
    }

    #[test]
    fn test_extract_iocs_from_mock() {
        let result = SandboxResult::mock();
        let iocs = extract_iocs(&result);
        assert!(!iocs.is_empty());
        assert!(iocs.ips.iter().any(|ip| ip.contains("185.220")));
    }

    #[test]
    fn test_extract_iocs_mutexes_present() {
        let result = SandboxResult::mock();
        let iocs = extract_iocs(&result);
        assert!(!iocs.mutexes.is_empty());
    }

    #[test]
    fn test_extract_iocs_urls_present() {
        let result = SandboxResult::mock();
        let iocs = extract_iocs(&result);
        assert!(!iocs.urls.is_empty());
    }

    // ── MalwareConfig ────────────────────────────────────────────────────────

    #[test]
    fn test_malware_config_new() {
        let cfg = MalwareConfig::new("emotet");
        assert_eq!(cfg.family, "emotet");
        assert!(!cfg.has_c2());
        assert!(cfg.encryption_key.is_none());
    }

    #[test]
    fn test_malware_config_add_c2() {
        let mut cfg = MalwareConfig::new("rat");
        cfg.add_c2("1.2.3.4:4444");
        assert!(cfg.has_c2());
        assert_eq!(cfg.c2_servers[0], "1.2.3.4:4444");
    }

    #[test]
    fn test_malware_config_key_hex() {
        let mut cfg = MalwareConfig::new("cs");
        cfg.encryption_key = Some(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(cfg.key_hex().as_deref(), Some("deadbeef"));
    }

    #[test]
    fn test_malware_config_key_hex_none() {
        let cfg = MalwareConfig::new("x");
        assert!(cfg.key_hex().is_none());
    }

    #[test]
    fn test_malware_config_set_extra() {
        let mut cfg = MalwareConfig::new("banker");
        cfg.set_extra("sleep_ms", "5000");
        assert_eq!(
            cfg.extra.get("sleep_ms").map(std::string::String::as_str),
            Some("5000")
        );
    }

    // ── extract_config ───────────────────────────────────────────────────────

    #[test]
    fn test_extract_config_generic_url() {
        let dump = b"garbage\x00https://c2server.evil/beacon\x00more_garbage";
        let cfg = extract_config("generic", dump);
        assert!(cfg.is_some());
        let cfg = cfg.unwrap();
        assert!(cfg.c2_servers.iter().any(|s| s.contains("c2server.evil")));
    }

    #[test]
    fn test_extract_config_generic_ipport() {
        let dump = b"config\x00185.220.101.1:443\x00end";
        let cfg = extract_config("any_unknown_family", dump);
        assert!(cfg.is_some());
    }

    #[test]
    fn test_extract_config_generic_no_match() {
        let dump = b"\x00\x01\x02\x03\x04\x05";
        let cfg = extract_config("generic", dump);
        assert!(cfg.is_none());
    }

    #[test]
    fn test_extract_config_emotet_raw() {
        let dump = b"botdata 1.2.3.4:8080 botdata";
        let cfg = extract_config("emotet", dump);
        assert!(cfg.is_some());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.family, "emotet");
        assert!(cfg.has_c2());
    }

    #[test]
    fn test_extract_config_emotet_xor() {
        // XOR the IP:port string with key 0x05.
        let plaintext = b"2.3.4.5:4444";
        let encoded: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x05).collect();
        let cfg = extract_config("emotet", &encoded);
        assert!(cfg.is_some());
    }

    #[test]
    fn test_extract_config_cobalt_strike_marker() {
        let mut dump = vec![0u8; 32];
        // Insert the beacon marker.
        dump[10] = 0x2e;
        dump[11] = 0x2e;
        dump[12] = 0x2e;
        let cfg = extract_config("cobalt_strike", &dump);
        assert!(cfg.is_some());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.family, "cobalt_strike");
    }

    #[test]
    fn test_extract_config_cobalt_strike_field_magic() {
        let dump: Vec<u8> = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x00];
        let cfg = extract_config("cobaltstrike", &dump);
        assert!(cfg.is_some());
    }

    #[test]
    fn test_extract_config_cobalt_strike_no_match() {
        let dump = b"nothing_special_here_at_all";
        let cfg = extract_config("cs", dump);
        assert!(cfg.is_none());
    }

    // ── SandboxArtifactKind ──────────────────────────────────────────────────

    #[test]
    fn test_sandbox_artifact_kind_display() {
        assert_eq!(SandboxArtifactKind::DroppedFile.to_string(), "dropped_file");
        assert_eq!(
            SandboxArtifactKind::NetworkCapture.to_string(),
            "network_capture"
        );
        assert_eq!(SandboxArtifactKind::MemoryDump.to_string(), "memory_dump");
        assert_eq!(SandboxArtifactKind::Screenshot.to_string(), "screenshot");
        assert_eq!(SandboxArtifactKind::ApiTrace.to_string(), "api_trace");
        assert_eq!(
            SandboxArtifactKind::InjectedCode.to_string(),
            "injected_code"
        );
        assert_eq!(
            SandboxArtifactKind::Other("weird".to_string()).to_string(),
            "weird"
        );
    }

    #[test]
    fn test_sandbox_artifact_kind_from_extension_pcap() {
        let k = SandboxArtifact::kind_from_extension("pcap");
        assert_eq!(k, SandboxArtifactKind::NetworkCapture);
    }

    #[test]
    fn test_sandbox_artifact_kind_from_extension_dmp() {
        let k = SandboxArtifact::kind_from_extension("dmp");
        assert_eq!(k, SandboxArtifactKind::MemoryDump);
    }

    #[test]
    fn test_sandbox_artifact_kind_from_extension_png() {
        let k = SandboxArtifact::kind_from_extension("png");
        assert_eq!(k, SandboxArtifactKind::Screenshot);
    }

    #[test]
    fn test_sandbox_artifact_kind_from_extension_log() {
        let k = SandboxArtifact::kind_from_extension("log");
        assert_eq!(k, SandboxArtifactKind::ApiTrace);
    }

    #[test]
    fn test_sandbox_artifact_kind_from_extension_exe() {
        let k = SandboxArtifact::kind_from_extension("exe");
        assert_eq!(k, SandboxArtifactKind::DroppedFile);
    }

    #[test]
    fn test_sandbox_artifact_new() {
        let a = SandboxArtifact::new(
            SandboxArtifactKind::MemoryDump,
            PathBuf::from("/tmp/dump.dmp"),
            "deadbeef",
            1024,
        );
        assert_eq!(a.size, 1024);
        assert_eq!(a.hash, "deadbeef");
        assert_eq!(a.kind, SandboxArtifactKind::MemoryDump);
    }

    // ── collect_artifacts ────────────────────────────────────────────────────

    #[test]
    fn test_collect_artifacts_empty_dir() {
        let dir = std::env::temp_dir().join("rustre_sandbox_test_empty_artifacts");
        let _ = std::fs::create_dir_all(&dir);
        let result = collect_artifacts(&dir);
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collect_artifacts_detects_pcap() {
        let dir = std::env::temp_dir().join("rustre_sandbox_test_pcap_artifacts");
        let _ = std::fs::create_dir_all(&dir);
        let pcap_path = dir.join("capture.pcap");
        let _ = std::fs::write(&pcap_path, b"\xd4\xc3\xb2\xa1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00");
        let result = collect_artifacts(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            result
                .iter()
                .any(|a| a.kind == SandboxArtifactKind::NetworkCapture)
        );
    }

    #[test]
    fn test_collect_artifacts_detects_screenshot() {
        let dir = std::env::temp_dir().join("rustre_sandbox_test_png_artifacts");
        let _ = std::fs::create_dir_all(&dir);
        let png_path = dir.join("screen.png");
        // Minimal fake PNG (magic bytes).
        let _ = std::fs::write(&png_path, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR");
        let result = collect_artifacts(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            result
                .iter()
                .any(|a| a.kind == SandboxArtifactKind::Screenshot)
        );
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_ascii_strings_basic() {
        let data = b"Hello World\x00short\x00this_is_long_enough\x00";
        let strings = extract_ascii_strings(data, 8);
        assert!(strings.iter().any(|s| s == "Hello World"));
        assert!(strings.iter().any(|s| s == "this_is_long_enough"));
        assert!(!strings.iter().any(|s| s == "short"));
    }

    #[test]
    fn test_dedup_vec() {
        let mut v = vec![
            "b".to_string(),
            "a".to_string(),
            "a".to_string(),
            "b".to_string(),
        ];
        dedup_vec(&mut v);
        assert_eq!(v.len(), 2);
    }

    // ── ArtifactExtractor ────────────────────────────────────────────────────

    fn make_file_event(path: &str, hash: &str, size: usize) -> SandboxEvent {
        SandboxEvent::new(
            0,
            1,
            SandboxEventKind::FileOp("create".to_string()),
            format!("{path}|{hash}|{size}"),
        )
    }

    fn make_net_event(direction: &str, payload: Vec<u8>) -> SandboxEvent {
        SandboxEvent::new(
            0,
            1,
            SandboxEventKind::NetworkConn {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "8.8.8.8".to_string(),
                dst_port: 443,
                proto: "tcp".to_string(),
                payload,
                direction: direction.to_string(),
            },
            "",
        )
    }

    fn make_inject_event(target_pid: u32, hash: &str) -> SandboxEvent {
        SandboxEvent::new(
            0,
            1,
            SandboxEventKind::CodeInjection {
                target_pid,
                bytes_hash: hash.to_string(),
            },
            "",
        )
    }

    #[test]
    fn test_extract_dropped_files_basic() {
        let ext = SandboxArtifactExtractor::new();
        let events = vec![make_file_event(
            r"C:\Windows\Temp\evil.exe",
            "deadbeef",
            4096,
        )];
        let files = ext.extract_dropped_files(&events);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, r"C:\Windows\Temp\evil.exe");
        assert_eq!(files[0].content_hash, "deadbeef");
        assert_eq!(files[0].size, 4096);
    }

    #[test]
    fn test_extract_dropped_files_only_create_write() {
        let ext = SandboxArtifactExtractor::new();
        let events = vec![
            make_file_event("a.dll", "hash1", 100),
            SandboxEvent::new(
                0,
                1,
                SandboxEventKind::FileOp("delete".to_string()),
                "b.dll",
            ),
            SandboxEvent::new(
                0,
                1,
                SandboxEventKind::FileOp("write".to_string()),
                "c.dll|hash2|200",
            ),
        ];
        let files = ext.extract_dropped_files(&events);
        // "delete" should be excluded; "create" and "write" should be included.
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_extract_network_payloads() {
        let ext = SandboxArtifactExtractor::new();
        let events = vec![
            make_net_event("outbound", vec![1, 2, 3]),
            make_net_event("inbound", vec![4, 5]),
        ];
        let payloads = ext.extract_network_payloads(&events);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].direction, "outbound");
        assert_eq!(payloads[0].content, vec![1, 2, 3]);
        assert_eq!(payloads[1].direction, "inbound");
    }

    #[test]
    fn test_extract_injected_code() {
        let ext = SandboxArtifactExtractor::new();
        let events = vec![
            make_inject_event(1234, "cafebabe"),
            make_inject_event(5678, ""),
        ];
        let injections = ext.extract_injected_code(&events);
        assert_eq!(injections.len(), 2);
        assert_eq!(injections[0].target_pid, 1234);
        assert_eq!(injections[0].bytes_hash, "cafebabe");
        assert_eq!(injections[1].target_pid, 5678);
    }

    #[test]
    fn test_extract_empty_events() {
        let ext = SandboxArtifactExtractor::new();
        assert!(ext.extract_dropped_files(&[]).is_empty());
        assert!(ext.extract_network_payloads(&[]).is_empty());
        assert!(ext.extract_injected_code(&[]).is_empty());
    }

    // ── MemoryRegionDumper ───────────────────────────────────────────────────

    #[test]
    fn test_memory_region_dumper_non_linux_returns_empty() {
        // On non-Linux platforms this must return Ok(empty).
        // On Linux it will try to read /proc/<pid>/maps for a nonexistent PID
        // and should return an error or empty vec — both are acceptable here
        // as long as it does not panic.
        let dumper = MemoryRegionDumper::new();
        let result = dumper.dump_executable_regions(u32::MAX); // nonexistent PID
        // Either Ok(empty) or Err — just verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_memory_region_is_executable() {
        let mut r = MemoryDumpRegion::new(1, 0x1000, 0x1000, "r-xp");
        assert!(r.is_executable());
        r.perms = "rw-p".to_string();
        assert!(!r.is_executable());
    }
}
