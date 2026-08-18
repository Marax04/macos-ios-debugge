//! Firmware analysis report: embedded OS detection, kernel version, filesystem
//! tree, hardcoded credentials, network endpoints, crypto keys, vulnerable
//! components.

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FirmwareReportError {
    #[error("analysis error: {0}")]
    Analysis(String),
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("io error: {0}")]
    Io(String),
}

// ─── EmbeddedOs ──────────────────────────────────────────────────────────────

/// Classification of the operating system embedded in a firmware image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmbeddedOs {
    /// Full Linux distribution.
    Linux,
    /// `FreeRTOS` real-time OS.
    FreeRtos,
    /// `VxWorks` real-time OS.
    VxWorks,
    /// `ThreadX` real-time OS.
    ThreadX,
    /// RTEMS real-time OS.
    Rtems,
    /// QNX Neutrino real-time OS.
    QnxNeutrino,
    /// Zephyr OS.
    Zephyr,
    /// `NuttX` OS.
    NuttX,
    /// Bare-metal (no OS detected).
    BareMetal,
    /// uClinux (MMU-less Linux).
    UClinux,
    /// `OpenWrt` distribution.
    OpenWrt,
    /// Unknown / unrecognised OS.
    Unknown(String),
}

impl fmt::Display for EmbeddedOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Linux => "Linux",
            Self::FreeRtos => "FreeRTOS",
            Self::VxWorks => "VxWorks",
            Self::ThreadX => "ThreadX",
            Self::Rtems => "RTEMS",
            Self::QnxNeutrino => "QNX Neutrino",
            Self::Zephyr => "Zephyr",
            Self::NuttX => "NuttX",
            Self::BareMetal => "Bare Metal",
            Self::UClinux => "uClinux",
            Self::OpenWrt => "OpenWrt",
            Self::Unknown(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

impl EmbeddedOs {
    /// Detect the OS from firmware bytes using string signatures.
    #[must_use]
    pub fn detect(data: &[u8]) -> Self {
        let sigs: &[(&[u8], EmbeddedOs)] = &[
            (b"OpenWrt", Self::OpenWrt),
            (b"uClinux", Self::UClinux),
            (b"Linux version", Self::Linux),
            (b"FreeRTOS", Self::FreeRtos),
            (b"VxWorks", Self::VxWorks),
            (b"ThreadX", Self::ThreadX),
            (b"RTEMS", Self::Rtems),
            (b"QNX", Self::QnxNeutrino),
            (b"Zephyr", Self::Zephyr),
            (b"NuttX", Self::NuttX),
        ];
        for (sig, os) in sigs {
            if data.windows(sig.len()).any(|w| w == *sig) {
                return os.clone();
            }
        }
        Self::BareMetal
    }

    /// Returns `true` if this is a Linux-derived OS.
    #[must_use]
    pub const fn is_linux_based(&self) -> bool {
        matches!(self, Self::Linux | Self::UClinux | Self::OpenWrt)
    }

    /// Returns `true` if this is a real-time OS.
    #[must_use]
    pub const fn is_rtos(&self) -> bool {
        matches!(
            self,
            Self::FreeRtos
                | Self::VxWorks
                | Self::ThreadX
                | Self::Rtems
                | Self::QnxNeutrino
                | Self::Zephyr
                | Self::NuttX
        )
    }
}

// ─── KernelVersion ───────────────────────────────────────────────────────────

/// Detected Linux kernel version.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelVersion {
    /// Full version string (e.g. `"Linux version 4.14.77 (gcc version 7.3.0)"`).
    pub full_string: String,
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
    /// Patch level.
    pub patch: u32,
    /// Whether this is a Long-Term Support (LTS) release.
    pub is_lts: bool,
    /// End-of-life status based on known LTS schedules.
    pub is_eol: bool,
}

impl KernelVersion {
    /// Try to extract a kernel version string from firmware bytes.
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<Self> {
        let needle = b"Linux version ";
        let pos = data.windows(needle.len()).position(|w| w == needle)?;
        let start = pos + needle.len();
        let slice = &data[start..];
        let end = slice
            .iter()
            .take(128)
            .position(|&b| b == b' ' || b == 0)
            .unwrap_or(64);
        let ver_str = String::from_utf8_lossy(&slice[..end]).into_owned();

        let full = String::from_utf8_lossy(&data[pos..pos + (end + 14).min(256)]).into_owned();

        let parts: Vec<&str> = ver_str.split('.').collect();
        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch_str = parts.get(2).copied().unwrap_or("0");
        let patch = patch_str
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0);

        let is_lts = matches!(
            (major, minor),
            (4, 4) | (4, 9) | (4, 14) | (4, 19) | (5, 4) | (5, 10) | (5, 15) | (6, 1) | (6, 6)
        );
        let is_eol = major < 4 || (major == 4 && minor < 4);

        Some(KernelVersion {
            full_string: full,
            major,
            minor,
            patch,
            is_lts,
            is_eol,
        })
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}{}",
            self.major,
            self.minor,
            self.patch,
            if self.is_lts { " LTS" } else { "" }
        )
    }
}

// ─── FileSystemTree ──────────────────────────────────────────────────────────

/// A node in the extracted filesystem tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsNode {
    /// Absolute path within the firmware filesystem.
    pub path: String,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// File permissions (Unix mode bits).
    pub permissions: u16,
    /// Whether the node is a symlink.
    pub is_symlink: bool,
    /// Symlink target, if applicable.
    pub symlink_target: Option<String>,
}

impl FsNode {
    /// Returns `true` if this is a potentially sensitive configuration file.
    #[must_use]
    pub fn is_config_file(&self) -> bool {
        !self.is_dir
            && (std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("conf"))
                || std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("cfg"))
                || std::path::Path::new(&self.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("ini"))
                || self.path.contains("/etc/")
                || self.path.ends_with("passwd")
                || self.path.ends_with("shadow"))
    }

    /// Returns `true` if the file is world-writable.
    #[must_use]
    pub const fn is_world_writable(&self) -> bool {
        self.permissions & 0o002 != 0
    }

    /// Returns `true` if this is a setuid executable.
    #[must_use]
    pub const fn is_setuid(&self) -> bool {
        self.permissions & 0o4000 != 0
    }
}

/// The complete filesystem tree extracted from a firmware image.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileSystemTree {
    pub nodes: Vec<FsNode>,
    pub total_files: usize,
    pub total_dirs: usize,
    pub total_size: u64,
}

impl FileSystemTree {
    /// Find nodes matching a path prefix.
    #[must_use]
    pub fn find_prefix(&self, prefix: &str) -> Vec<&FsNode> {
        self.nodes
            .iter()
            .filter(|n| n.path.starts_with(prefix))
            .collect()
    }

    /// Return all setuid executables.
    #[must_use]
    pub fn setuid_files(&self) -> Vec<&FsNode> {
        self.nodes.iter().filter(|n| n.is_setuid()).collect()
    }

    /// Return all world-writable files.
    #[must_use]
    pub fn world_writable(&self) -> Vec<&FsNode> {
        self.nodes
            .iter()
            .filter(|n| n.is_world_writable())
            .collect()
    }
}

// ─── HardcodedCredential ─────────────────────────────────────────────────────

/// A hardcoded credential found in the firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardcodedCredential {
    /// Category (e.g. `"password"`, `"api_key"`, `"private_key"`).
    pub category: String,
    /// The matched pattern or value (redacted if sensitive).
    pub value: String,
    /// File path where this was found.
    pub source_path: String,
    /// Byte offset in the firmware image.
    pub offset: usize,
    /// Confidence level (0.0–1.0).
    pub confidence: f64,
}

impl HardcodedCredential {
    /// Returns `true` if this is a high-confidence finding.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

// ─── NetworkEndpoint ─────────────────────────────────────────────────────────

/// A network endpoint (IP address or hostname) found in the firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    /// Endpoint address (IPv4, IPv6, or hostname).
    pub address: String,
    /// Optional port number.
    pub port: Option<u16>,
    /// Protocol hint (e.g. `"http"`, `"mqtt"`, `"telnet"`).
    pub protocol: Option<String>,
    /// Context string (surrounding bytes for review).
    pub context: String,
    /// Offset in firmware image.
    pub offset: usize,
}

impl NetworkEndpoint {
    /// Returns `true` if this is a private IP address.
    #[must_use]
    pub fn is_private_ip(&self) -> bool {
        self.address.starts_with("192.168.")
            || self.address.starts_with("10.")
            || self.address.starts_with("172.16.")
            || self.address == "127.0.0.1"
    }

    /// Returns `true` when the protocol indicates an unencrypted service.
    #[must_use]
    pub fn is_unencrypted(&self) -> bool {
        matches!(
            self.protocol.as_deref(),
            Some("http") | Some("telnet") | Some("ftp") | Some("mqtt")
        )
    }
}

// ─── CryptoKey ───────────────────────────────────────────────────────────────

/// A cryptographic key or certificate found in the firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKey {
    /// Type of key (e.g. `"RSA private key"`, `"X.509 certificate"`, `"AES key"`).
    pub key_type: String,
    /// PEM header used to detect the key.
    pub pem_header: String,
    /// Byte offset in the firmware.
    pub offset: usize,
    /// Length of the PEM-encoded block.
    pub length: usize,
    /// Whether this is a private key (high risk).
    pub is_private: bool,
}

impl CryptoKey {
    /// Scan `data` for PEM-encoded keys.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<Self> {
        let pem_types: &[(&[u8], &str, bool)] = &[
            (b"-----BEGIN RSA PRIVATE KEY-----", "RSA private key", true),
            (b"-----BEGIN PRIVATE KEY-----", "PKCS#8 private key", true),
            (b"-----BEGIN EC PRIVATE KEY-----", "EC private key", true),
            (b"-----BEGIN DSA PRIVATE KEY-----", "DSA private key", true),
            (b"-----BEGIN CERTIFICATE-----", "X.509 certificate", false),
            (b"-----BEGIN PUBLIC KEY-----", "public key", false),
            (b"-----BEGIN PGP PRIVATE KEY-----", "PGP private key", true),
        ];
        let mut keys = Vec::new();
        for (header, key_type, is_private) in pem_types {
            let mut start = 0;
            while let Some(pos) = data[start..]
                .windows(header.len())
                .position(|w| w == *header)
                .map(|p| start + p)
            {
                let end_marker = b"-----END";
                let block_end = data[pos + header.len()..]
                    .windows(end_marker.len())
                    .position(|w| w == end_marker)
                    .map(|e| pos + header.len() + e + 50)
                    .unwrap_or(pos + header.len() + 1024);
                let length = block_end.min(data.len()) - pos;
                keys.push(CryptoKey {
                    key_type: (*key_type).to_string(),
                    pem_header: String::from_utf8_lossy(header).to_string(),
                    offset: pos,
                    length,
                    is_private: *is_private,
                });
                start = pos + header.len();
            }
        }
        keys
    }

    /// Returns `true` if this is a high-risk private key.
    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        self.is_private
    }
}

// ─── VulnerableComponent ─────────────────────────────────────────────────────

/// A known-vulnerable component detected in the firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableComponent {
    /// Component name (e.g. `"OpenSSL"`, `"BusyBox"`).
    pub name: String,
    /// Detected version string.
    pub version: String,
    /// CVE identifiers associated with this version.
    pub cves: Vec<String>,
    /// Severity of the worst CVE (e.g. `"critical"`, `"high"`, `"medium"`).
    pub max_severity: String,
    /// Source of the version string.
    pub source: String,
}

impl VulnerableComponent {
    /// Returns `true` if any CVE has critical severity.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.max_severity == "critical"
    }
}

// ─── FirmwareReport ──────────────────────────────────────────────────────────

/// Full analysis report for a firmware image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareReport {
    /// Detected embedded operating system.
    pub embedded_os: EmbeddedOs,
    /// Kernel version, if Linux-based.
    pub kernel_version: Option<KernelVersion>,
    /// Extracted filesystem tree (may be partial).
    pub filesystem: FileSystemTree,
    /// Hardcoded credentials found.
    pub credentials: Vec<HardcodedCredential>,
    /// Network endpoints found.
    pub endpoints: Vec<NetworkEndpoint>,
    /// Cryptographic keys/certificates found.
    pub crypto_keys: Vec<CryptoKey>,
    /// Known-vulnerable components.
    pub vulnerable_components: Vec<VulnerableComponent>,
    /// Overall risk score (0–100).
    pub risk_score: f64,
    /// Summary of key findings.
    pub findings_summary: Vec<String>,
    /// Firmware image size in bytes.
    pub image_size: u64,
    /// SHA-256 of the firmware image (hex string).
    pub sha256: String,
}

impl FirmwareReport {
    /// Build a mock report for testing.
    #[must_use]
    pub fn mock() -> Self {
        let os = EmbeddedOs::Linux;
        let kernel = KernelVersion {
            full_string: "Linux version 4.14.77 (buildroot@localhost)".into(),
            major: 4,
            minor: 14,
            patch: 77,
            is_lts: true,
            is_eol: false,
        };
        let nodes = vec![
            FsNode {
                path: "/etc/passwd".into(),
                size: 512,
                is_dir: false,
                permissions: 0o644,
                is_symlink: false,
                symlink_target: None,
            },
            FsNode {
                path: "/bin/busybox".into(),
                size: 1_048_576,
                is_dir: false,
                permissions: 0o4755,
                is_symlink: false,
                symlink_target: None,
            },
            FsNode {
                path: "/tmp".into(),
                size: 0,
                is_dir: true,
                permissions: 0o1777,
                is_symlink: false,
                symlink_target: None,
            },
        ];
        let fs = FileSystemTree {
            total_files: 2,
            total_dirs: 1,
            total_size: 1_049_088,
            nodes,
        };
        let creds = vec![HardcodedCredential {
            category: "password".into(),
            value: "admin:admin".into(),
            source_path: "/etc/passwd".into(),
            offset: 0x1000,
            confidence: 0.95,
        }];
        let endpoints = vec![
            NetworkEndpoint {
                address: "192.168.1.1".into(),
                port: Some(80),
                protocol: Some("http".into()),
                context: "Gateway IP".into(),
                offset: 0x2000,
            },
            NetworkEndpoint {
                address: "update.vendor.com".into(),
                port: Some(443),
                protocol: Some("https".into()),
                context: "OTA update server".into(),
                offset: 0x3000,
            },
        ];
        let crypto_keys = vec![CryptoKey {
            key_type: "RSA private key".into(),
            pem_header: "-----BEGIN RSA PRIVATE KEY-----".into(),
            offset: 0x4000,
            length: 1700,
            is_private: true,
        }];
        let vulns = vec![
            VulnerableComponent {
                name: "BusyBox".into(),
                version: "1.29.3".into(),
                cves: vec!["CVE-2019-5747".into(), "CVE-2021-28831".into()],
                max_severity: "high".into(),
                source: "/bin/busybox".into(),
            },
            VulnerableComponent {
                name: "OpenSSL".into(),
                version: "1.0.2k".into(),
                cves: vec!["CVE-2020-1971".into()],
                max_severity: "critical".into(),
                source: "/usr/lib/libssl.so.1.0.2".into(),
            },
        ];
        let findings = vec![
            "Hardcoded admin credentials found".into(),
            "Private RSA key embedded in firmware".into(),
            "Unencrypted HTTP endpoint found".into(),
            "Critical OpenSSL vulnerability detected".into(),
        ];
        Self {
            embedded_os: os,
            kernel_version: Some(kernel),
            filesystem: fs,
            credentials: creds,
            endpoints,
            crypto_keys,
            vulnerable_components: vulns,
            risk_score: 82.5,
            findings_summary: findings,
            image_size: 8_388_608,
            sha256: "deadbeef".repeat(8),
        }
    }

    /// Compute a risk score from the collected findings.
    #[must_use]
    pub fn compute_risk_score(
        creds: &[HardcodedCredential],
        endpoints: &[NetworkEndpoint],
        keys: &[CryptoKey],
        vulns: &[VulnerableComponent],
    ) -> f64 {
        let mut score = 0.0_f64;
        score += creds
            .iter()
            .map(|c| c.confidence * 20.0)
            .sum::<f64>()
            .min(30.0);
        score += endpoints.iter().filter(|e| e.is_unencrypted()).count() as f64 * 5.0;
        score += keys.iter().filter(|k| k.is_private).count() as f64 * 15.0;
        score += vulns
            .iter()
            .map(|v| match v.max_severity.as_str() {
                "critical" => 20.0,
                "high" => 10.0,
                "medium" => 5.0,
                _ => 1.0,
            })
            .sum::<f64>();
        score.min(100.0)
    }

    /// Return all private cryptographic keys.
    #[must_use]
    pub fn private_keys(&self) -> Vec<&CryptoKey> {
        self.crypto_keys.iter().filter(|k| k.is_private).collect()
    }

    /// Return all critical vulnerabilities.
    #[must_use]
    pub fn critical_vulnerabilities(&self) -> Vec<&VulnerableComponent> {
        self.vulnerable_components
            .iter()
            .filter(|v| v.is_critical())
            .collect()
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Firmware: os={} kernel={} risk={:.1} creds={} keys={} vulns={}",
            self.embedded_os,
            self.kernel_version
                .as_ref()
                .map(|k| k.to_string())
                .unwrap_or_else(|| "N/A".into()),
            self.risk_score,
            self.credentials.len(),
            self.crypto_keys.len(),
            self.vulnerable_components.len(),
        )
    }
}

impl fmt::Display for FirmwareReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EmbeddedOs ────────────────────────────────────────────────────────────

    #[test]
    fn test_embedded_os_detect_linux() {
        let data = b"Linux version 5.4.0";
        assert_eq!(EmbeddedOs::detect(data), EmbeddedOs::Linux);
    }

    #[test]
    fn test_embedded_os_detect_freertos() {
        let data = b"FreeRTOS kernel v10.4.0";
        assert_eq!(EmbeddedOs::detect(data), EmbeddedOs::FreeRtos);
    }

    #[test]
    fn test_embedded_os_detect_bare_metal() {
        let data = b"\x00\x01\x02\x03";
        assert_eq!(EmbeddedOs::detect(data), EmbeddedOs::BareMetal);
    }

    #[test]
    fn test_embedded_os_is_linux_based() {
        assert!(EmbeddedOs::Linux.is_linux_based());
        assert!(EmbeddedOs::OpenWrt.is_linux_based());
        assert!(!EmbeddedOs::FreeRtos.is_linux_based());
    }

    #[test]
    fn test_embedded_os_is_rtos() {
        assert!(EmbeddedOs::FreeRtos.is_rtos());
        assert!(EmbeddedOs::VxWorks.is_rtos());
        assert!(!EmbeddedOs::Linux.is_rtos());
    }

    #[test]
    fn test_embedded_os_display() {
        assert_eq!(EmbeddedOs::Linux.to_string(), "Linux");
        assert_eq!(EmbeddedOs::BareMetal.to_string(), "Bare Metal");
    }

    // ── KernelVersion ─────────────────────────────────────────────────────────

    #[test]
    fn test_kernel_version_detect() {
        let data = b"Linux version 4.14.77 (gcc)";
        let kv = KernelVersion::detect(data).unwrap();
        assert_eq!(kv.major, 4);
        assert_eq!(kv.minor, 14);
        assert_eq!(kv.patch, 77);
    }

    #[test]
    fn test_kernel_version_is_lts() {
        let data = b"Linux version 5.10.0 gcc";
        let kv = KernelVersion::detect(data).unwrap();
        assert!(kv.is_lts);
    }

    #[test]
    fn test_kernel_version_is_eol() {
        let data = b"Linux version 3.10.1 gcc";
        let kv = KernelVersion::detect(data).unwrap();
        assert!(kv.is_eol);
    }

    #[test]
    fn test_kernel_version_none_when_absent() {
        let data = b"VxWorks 6.9.0";
        assert!(KernelVersion::detect(data).is_none());
    }

    #[test]
    fn test_kernel_version_display() {
        let kv = KernelVersion {
            major: 5,
            minor: 15,
            patch: 32,
            is_lts: true,
            is_eol: false,
            full_string: String::new(),
        };
        assert_eq!(kv.to_string(), "5.15.32 LTS");
    }

    // ── FsNode ────────────────────────────────────────────────────────────────

    #[test]
    fn test_fs_node_is_config_file() {
        let n = FsNode {
            path: "/etc/passwd".into(),
            size: 0,
            is_dir: false,
            permissions: 0o644,
            is_symlink: false,
            symlink_target: None,
        };
        assert!(n.is_config_file());
    }

    #[test]
    fn test_fs_node_is_setuid() {
        let n = FsNode {
            path: "/bin/su".into(),
            size: 0,
            is_dir: false,
            permissions: 0o4755,
            is_symlink: false,
            symlink_target: None,
        };
        assert!(n.is_setuid());
    }

    #[test]
    fn test_fs_node_is_world_writable() {
        let n = FsNode {
            path: "/tmp/foo".into(),
            size: 0,
            is_dir: false,
            permissions: 0o777,
            is_symlink: false,
            symlink_target: None,
        };
        assert!(n.is_world_writable());
    }

    // ── FileSystemTree ────────────────────────────────────────────────────────

    #[test]
    fn test_fs_tree_setuid_files() {
        let r = FirmwareReport::mock();
        let su = r.filesystem.setuid_files();
        assert!(!su.is_empty());
    }

    #[test]
    fn test_fs_tree_find_prefix() {
        let r = FirmwareReport::mock();
        let etc = r.filesystem.find_prefix("/etc");
        assert!(!etc.is_empty());
    }

    // ── HardcodedCredential ───────────────────────────────────────────────────

    #[test]
    fn test_credential_is_high_confidence() {
        let c = HardcodedCredential {
            category: "password".into(),
            value: "root:root".into(),
            source_path: "/etc/passwd".into(),
            offset: 0,
            confidence: 0.9,
        };
        assert!(c.is_high_confidence());
    }

    #[test]
    fn test_credential_low_confidence() {
        let c = HardcodedCredential {
            category: "password".into(),
            value: "maybe".into(),
            source_path: "".into(),
            offset: 0,
            confidence: 0.5,
        };
        assert!(!c.is_high_confidence());
    }

    // ── NetworkEndpoint ───────────────────────────────────────────────────────

    #[test]
    fn test_endpoint_is_private_ip() {
        let e = NetworkEndpoint {
            address: "192.168.1.1".into(),
            port: None,
            protocol: None,
            context: String::new(),
            offset: 0,
        };
        assert!(e.is_private_ip());
    }

    #[test]
    fn test_endpoint_is_unencrypted_http() {
        let e = NetworkEndpoint {
            address: "1.2.3.4".into(),
            port: Some(80),
            protocol: Some("http".into()),
            context: String::new(),
            offset: 0,
        };
        assert!(e.is_unencrypted());
    }

    #[test]
    fn test_endpoint_is_not_unencrypted_https() {
        let e = NetworkEndpoint {
            address: "1.2.3.4".into(),
            port: Some(443),
            protocol: Some("https".into()),
            context: String::new(),
            offset: 0,
        };
        assert!(!e.is_unencrypted());
    }

    // ── CryptoKey ─────────────────────────────────────────────────────────────

    #[test]
    fn test_crypto_key_scan_finds_private_key() {
        let data =
            b"Some data -----BEGIN RSA PRIVATE KEY-----\nABCDEFG\n-----END RSA PRIVATE KEY-----\n";
        let keys = CryptoKey::scan(data);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].is_private);
        assert!(keys[0].is_high_risk());
    }

    #[test]
    fn test_crypto_key_scan_empty() {
        let keys = CryptoKey::scan(b"no keys here");
        assert!(keys.is_empty());
    }

    #[test]
    fn test_crypto_key_certificate_not_private() {
        let data = b"-----BEGIN CERTIFICATE-----\nXXXX\n-----END CERTIFICATE-----\n";
        let keys = CryptoKey::scan(data);
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].is_private);
    }

    // ── VulnerableComponent ───────────────────────────────────────────────────

    #[test]
    fn test_vuln_component_is_critical() {
        let v = VulnerableComponent {
            name: "OpenSSL".into(),
            version: "1.0.2k".into(),
            cves: vec![],
            max_severity: "critical".into(),
            source: String::new(),
        };
        assert!(v.is_critical());
    }

    #[test]
    fn test_vuln_component_not_critical() {
        let v = VulnerableComponent {
            name: "curl".into(),
            version: "7.68.0".into(),
            cves: vec![],
            max_severity: "high".into(),
            source: String::new(),
        };
        assert!(!v.is_critical());
    }

    // ── FirmwareReport ────────────────────────────────────────────────────────

    #[test]
    fn test_firmware_report_mock_os() {
        let r = FirmwareReport::mock();
        assert_eq!(r.embedded_os, EmbeddedOs::Linux);
    }

    #[test]
    fn test_firmware_report_mock_kernel() {
        let r = FirmwareReport::mock();
        let k = r.kernel_version.as_ref().unwrap();
        assert_eq!(k.major, 4);
        assert_eq!(k.minor, 14);
    }

    #[test]
    fn test_firmware_report_mock_risk_score() {
        let r = FirmwareReport::mock();
        assert!(r.risk_score > 0.0 && r.risk_score <= 100.0);
    }

    #[test]
    fn test_firmware_report_private_keys() {
        let r = FirmwareReport::mock();
        assert!(!r.private_keys().is_empty());
    }

    #[test]
    fn test_firmware_report_critical_vulns() {
        let r = FirmwareReport::mock();
        assert!(!r.critical_vulnerabilities().is_empty());
    }

    #[test]
    fn test_firmware_report_summary() {
        let r = FirmwareReport::mock();
        let s = r.summary();
        assert!(s.contains("Linux"));
    }

    #[test]
    fn test_firmware_report_display() {
        let r = FirmwareReport::mock();
        let s = format!("{r}");
        assert!(!s.is_empty());
    }

    #[test]
    fn test_firmware_report_compute_risk_score() {
        let creds = vec![HardcodedCredential {
            category: String::new(),
            value: String::new(),
            source_path: String::new(),
            offset: 0,
            confidence: 0.9,
        }];
        let score = FirmwareReport::compute_risk_score(&creds, &[], &[], &[]);
        assert!(score > 0.0);
    }

    #[test]
    fn test_firmware_report_serialization() {
        let r = FirmwareReport::mock();
        let json = serde_json::to_string(&r).unwrap();
        let back: FirmwareReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image_size, r.image_size);
    }
    #[test]
    fn test_embedded_os_detect_vxworks() {
        assert_eq!(EmbeddedOs::detect(b"VxWorks 6.9"), EmbeddedOs::VxWorks);
    }
    #[test]
    fn test_embedded_os_detect_zephyr() {
        assert_eq!(EmbeddedOs::detect(b"Zephyr kernel"), EmbeddedOs::Zephyr);
    }
    #[test]
    fn test_embedded_os_uclinux() {
        assert!(EmbeddedOs::UClinux.is_linux_based());
    }
    #[test]
    fn test_kernel_version_lts_4_14() {
        let d = b"Linux version 4.14.0 gcc";
        let kv = KernelVersion::detect(d).unwrap();
        assert!(kv.is_lts);
    }
    #[test]
    fn test_kernel_version_lts_6_1() {
        let d = b"Linux version 6.1.0 gcc";
        let kv = KernelVersion::detect(d).unwrap();
        assert!(kv.is_lts);
    }
    #[test]
    fn test_fs_node_is_not_config_file() {
        let n = FsNode {
            path: "/bin/sh".into(),
            size: 0,
            is_dir: false,
            permissions: 0o755,
            is_symlink: false,
            symlink_target: None,
        };
        assert!(!n.is_config_file());
    }
    #[test]
    fn test_crypto_key_private_high_risk() {
        let k = CryptoKey {
            key_type: "RSA private key".into(),
            pem_header: String::new(),
            offset: 0,
            length: 0,
            is_private: true,
        };
        assert!(k.is_high_risk());
    }
    #[test]
    fn test_network_endpoint_display() {
        let e = NetworkEndpoint {
            address: "192.168.1.1".into(),
            port: None,
            protocol: None,
            context: String::new(),
            offset: 0,
        };
        assert_eq!(e.address, "192.168.1.1");
    }
    #[test]
    fn test_vuln_component_cve_list() {
        let r = FirmwareReport::mock();
        assert!(!r.vulnerable_components[0].cves.is_empty());
    }
    #[test]
    fn test_firmware_report_findings_nonempty() {
        let r = FirmwareReport::mock();
        assert!(!r.findings_summary.is_empty());
    }
}
