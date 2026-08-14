//! `firmware_security` — Security analysis for firmware images.
//!
//! Detects common firmware security issues:
//! - `FirmwareSecurity`: top-level facade.
//! - `HardcodedCredentials`: finds hardcoded passwords, API keys, tokens.
//! - `WeakCrypto`: identifies weak or broken cryptographic usage.
//! - `DebugInterface`: detects JTAG/SWD/debug port exposure.
//! - `UartConsole`: identifies UART/serial console strings.
//! - `TelnetService`: detects Telnet service indicators.

pub use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Risk level
// ─────────────────────────────────────────────────────────────────────────────

/// Security risk level of a firmware finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FwRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for FwRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareFinding
// ─────────────────────────────────────────────────────────────────────────────

/// A single security finding in firmware.
#[derive(Debug, Clone)]
pub struct FirmwareFinding {
    /// Category label.
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Risk level.
    pub risk: FwRisk,
    /// Byte offset in the firmware image.
    pub offset: Option<u64>,
    /// Matched evidence string (e.g. the credential value).
    pub evidence: Option<String>,
}

impl FirmwareFinding {
    /// Create a new finding.
    #[must_use]
    pub fn new(category: impl Into<String>, description: impl Into<String>, risk: FwRisk) -> Self {
        Self {
            category: category.into(),
            description: description.into(),
            risk,
            offset: None,
            evidence: None,
        }
    }

    /// Attach a byte offset.
    #[must_use]
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Attach evidence text.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

impl fmt::Display for FirmwareFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.risk, self.category, self.description)?;
        if let Some(off) = self.offset {
            write!(f, " @ {off:#x}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HardcodedCredentials
// ─────────────────────────────────────────────────────────────────────────────

/// A matched credential entry.
#[derive(Debug, Clone)]
pub struct CredentialMatch {
    /// Kind of credential (e.g. `"password"`, `"api_key"`).
    pub kind: String,
    /// The matched value (truncated for safety).
    pub value: String,
    /// Offset in the firmware.
    pub offset: u64,
}

/// Scans firmware for hardcoded credentials.
#[derive(Debug, Default)]
pub struct HardcodedCredentials {
    pub matches: Vec<CredentialMatch>,
    findings: Vec<FirmwareFinding>,
}

impl HardcodedCredentials {
    /// Create a new scanner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for credential patterns.
    pub fn scan(&mut self, data: &[u8]) {
        let patterns: &[(&[u8], &str, FwRisk)] = &[
            (b"password=", "password", FwRisk::Critical),
            (b"passwd=", "password", FwRisk::Critical),
            (b"admin:admin", "credential", FwRisk::Critical),
            (b"root:root", "credential", FwRisk::Critical),
            (b"default:default", "credential", FwRisk::Critical),
            (b"api_key=", "api_key", FwRisk::High),
            (b"token=", "token", FwRisk::High),
            (b"secret=", "secret", FwRisk::High),
            (b"private_key", "crypto_key", FwRisk::Critical),
            (b"BEGIN RSA PRIVATE KEY", "rsa_key", FwRisk::Critical),
            (b"AKID", "aws_key", FwRisk::Critical),
        ];
        for (pattern, kind, risk) in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if let Some(p) = data[pos..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs = pos + p;
                    // Extract up to 32 bytes of value.
                    let val_start = abs + pattern.len();
                    let val_end = (val_start + 32).min(data.len());
                    let raw_val = &data[val_start..val_end];
                    let value = String::from_utf8_lossy(raw_val)
                        .trim_matches(|c: char| !c.is_ascii_graphic())
                        .chars()
                        .take(32)
                        .collect::<String>();

                    self.matches.push(CredentialMatch {
                        kind: kind.to_string(),
                        value: value.clone(),
                        offset: abs as u64,
                    });
                    self.findings.push(
                        FirmwareFinding::new(
                            "hardcoded_credentials",
                            format!("hardcoded {} found", kind),
                            *risk,
                        )
                        .with_offset(abs as u64)
                        .with_evidence(value),
                    );
                    pos = abs + pattern.len();
                } else {
                    break;
                }
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[FirmwareFinding] {
        &self.findings
    }

    /// Return `true` if any credential was found.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Return all matches of a given kind.
    #[must_use]
    pub fn matches_of_kind(&self, kind: &str) -> Vec<&CredentialMatch> {
        self.matches.iter().filter(|m| m.kind == kind).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WeakCrypto
// ─────────────────────────────────────────────────────────────────────────────

/// A detected weak cryptographic indicator.
#[derive(Debug, Clone)]
pub struct WeakCryptoMatch {
    /// Name of the weak algorithm.
    pub algorithm: String,
    /// Context description.
    pub context: String,
    /// Offset in the firmware.
    pub offset: u64,
}

/// Detects weak or deprecated cryptographic usage in firmware.
#[derive(Debug, Default)]
pub struct WeakCrypto {
    pub matches: Vec<WeakCryptoMatch>,
    findings: Vec<FirmwareFinding>,
}

impl WeakCrypto {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for weak cryptographic patterns.
    pub fn scan(&mut self, data: &[u8]) {
        let patterns: &[(&[u8], &str, &str, FwRisk)] = &[
            (
                b"MD5",
                "MD5",
                "deprecated hash (collision-prone)",
                FwRisk::Medium,
            ),
            (
                b"SHA1",
                "SHA-1",
                "deprecated hash (near-collision-prone)",
                FwRisk::Low,
            ),
            (b"RC4", "RC4", "broken stream cipher", FwRisk::High),
            (
                b"DES",
                "DES",
                "56-bit key (easily brute-forced)",
                FwRisk::High,
            ),
            (b"3DES", "3DES", "deprecated block cipher", FwRisk::Medium),
            (b"MD2", "MD2", "completely broken hash", FwRisk::Critical),
            (
                b"RSA512",
                "RSA-512",
                "512-bit RSA (factored in days)",
                FwRisk::Critical,
            ),
            (
                b"crc32(",
                "CRC32",
                "CRC used as integrity check (not crypto)",
                FwRisk::Low,
            ),
            (
                b"xor_encrypt",
                "XOR_encrypt",
                "XOR used as encryption",
                FwRisk::High,
            ),
            (
                b"ECB",
                "ECB mode",
                "electronic codebook (no IV, patterns)",
                FwRisk::High,
            ),
        ];
        for (pattern, algo, context, risk) in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if let Some(p) = data[pos..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs = pos + p;
                    self.matches.push(WeakCryptoMatch {
                        algorithm: algo.to_string(),
                        context: context.to_string(),
                        offset: abs as u64,
                    });
                    self.findings.push(
                        FirmwareFinding::new("weak_crypto", format!("{algo}: {context}"), *risk)
                            .with_offset(abs as u64),
                    );
                    pos = abs + pattern.len();
                } else {
                    break;
                }
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[FirmwareFinding] {
        &self.findings
    }

    /// Return the set of distinct weak algorithms found.
    #[must_use]
    pub fn algorithm_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.matches.iter().map(|m| m.algorithm.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugInterface
// ─────────────────────────────────────────────────────────────────────────────

/// Type of debug interface detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DebugInterfaceType {
    Jtag,
    Swd,
    Uart,
    Usb,
    BdmCopProcessor,
    Other(String),
}

impl fmt::Display for DebugInterfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jtag => write!(f, "JTAG"),
            Self::Swd => write!(f, "SWD"),
            Self::Uart => write!(f, "UART"),
            Self::Usb => write!(f, "USB"),
            Self::BdmCopProcessor => write!(f, "BDM/COP"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Detects debug interface exposure in firmware.
#[derive(Debug, Default)]
pub struct DebugInterface {
    pub detected: Vec<(DebugInterfaceType, u64)>,
    findings: Vec<FirmwareFinding>,
}

impl DebugInterface {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for debug interface indicators.
    pub fn scan(&mut self, data: &[u8]) {
        let patterns: &[(&[u8], DebugInterfaceType, FwRisk)] = &[
            (b"JTAG", DebugInterfaceType::Jtag, FwRisk::Critical),
            (b"jtag", DebugInterfaceType::Jtag, FwRisk::Critical),
            (b"SWD", DebugInterfaceType::Swd, FwRisk::Critical),
            (
                b"debug_enabled",
                DebugInterfaceType::Other("debug_flag".into()),
                FwRisk::High,
            ),
            (
                b"DEBUG_ENABLE",
                DebugInterfaceType::Other("debug_flag".into()),
                FwRisk::High,
            ),
            (b"UART_DEBUG", DebugInterfaceType::Uart, FwRisk::High),
            (
                b"bdm",
                DebugInterfaceType::BdmCopProcessor,
                FwRisk::Critical,
            ),
        ];
        for (pattern, iface_type, risk) in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if let Some(p) = data[pos..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs = pos + p;
                    self.detected.push((iface_type.clone(), abs as u64));
                    self.findings.push(
                        FirmwareFinding::new(
                            "debug_interface",
                            format!("debug interface exposed: {}", iface_type),
                            *risk,
                        )
                        .with_offset(abs as u64),
                    );
                    pos = abs + pattern.len();
                } else {
                    break;
                }
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[FirmwareFinding] {
        &self.findings
    }

    /// Return `true` if a specific interface type was found.
    #[must_use]
    pub fn has_interface(&self, iface: &DebugInterfaceType) -> bool {
        self.detected.iter().any(|(t, _)| t == iface)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UartConsole
// ─────────────────────────────────────────────────────────────────────────────

/// A UART console string found in firmware.
#[derive(Debug, Clone)]
pub struct UartString {
    /// The string content.
    pub content: String,
    /// Offset in the firmware.
    pub offset: u64,
    /// Whether this looks like a shell prompt.
    pub is_prompt: bool,
}

/// Detects UART console strings and shell-prompt indicators.
#[derive(Debug, Default)]
pub struct UartConsole {
    pub strings: Vec<UartString>,
    findings: Vec<FirmwareFinding>,
}

impl UartConsole {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for UART console indicators.
    pub fn scan(&mut self, data: &[u8]) {
        let patterns: &[(&[u8], bool, FwRisk)] = &[
            (b"login:", true, FwRisk::High),
            (b"Password:", true, FwRisk::High),
            (b"# ", true, FwRisk::Medium),
            (b"$ ", true, FwRisk::Medium),
            (b"BusyBox", false, FwRisk::Medium),
            (b"ash shell", false, FwRisk::Medium),
            (b"uart_init", false, FwRisk::Low),
            (b"UART init", false, FwRisk::Low),
            (b"Press Enter", false, FwRisk::Low),
            (b"u-boot>", true, FwRisk::High),
        ];
        for (pattern, is_prompt, risk) in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if let Some(p) = data[pos..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs = pos + p;
                    let end = (abs + 64).min(data.len());
                    let content = String::from_utf8_lossy(&data[abs..end])
                        .chars()
                        .take(64)
                        .collect::<String>();
                    self.strings.push(UartString {
                        content: content.clone(),
                        offset: abs as u64,
                        is_prompt: *is_prompt,
                    });
                    if *risk >= FwRisk::Medium {
                        self.findings.push(
                            FirmwareFinding::new(
                                "uart_console",
                                format!(
                                    "UART console indicator: '{}'",
                                    String::from_utf8_lossy(pattern)
                                ),
                                *risk,
                            )
                            .with_offset(abs as u64)
                            .with_evidence(content),
                        );
                    }
                    pos = abs + pattern.len();
                } else {
                    break;
                }
            }
        }
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[FirmwareFinding] {
        &self.findings
    }

    /// Return `true` if a shell prompt was found.
    #[must_use]
    pub fn has_shell_prompt(&self) -> bool {
        self.strings.iter().any(|s| s.is_prompt)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TelnetService
// ─────────────────────────────────────────────────────────────────────────────

/// Detects Telnet service indicators in firmware.
#[derive(Debug, Default)]
pub struct TelnetService {
    findings: Vec<FirmwareFinding>,
    /// Detected Telnet-related strings.
    pub hits: Vec<String>,
}

impl TelnetService {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for Telnet indicators.
    pub fn scan(&mut self, data: &[u8]) {
        let patterns: &[(&[u8], FwRisk)] = &[
            (b"telnetd", FwRisk::Critical),
            (b"telnet", FwRisk::High),
            (b"port=23\x00", FwRisk::Critical),
            (b":23\x00", FwRisk::High),
            (b"Telnet", FwRisk::High),
            (b"TELNET", FwRisk::High),
            (b"nvram get telnet", FwRisk::Critical),
        ];
        for (pattern, risk) in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if let Some(p) = data[pos..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs = pos + p;
                    let hit = String::from_utf8_lossy(pattern).into_owned();
                    self.hits.push(hit.clone());
                    self.findings.push(
                        FirmwareFinding::new(
                            "telnet_service",
                            format!("Telnet service indicator: '{hit}'"),
                            *risk,
                        )
                        .with_offset(abs as u64)
                        .with_evidence(hit),
                    );
                    pos = abs + pattern.len();
                } else {
                    break;
                }
            }
        }
        // Deduplicate hits.
        self.hits.sort();
        self.hits.dedup();
    }

    /// Return all findings.
    #[must_use]
    pub fn findings(&self) -> &[FirmwareFinding] {
        &self.findings
    }

    /// Return `true` if Telnet daemon was detected.
    #[must_use]
    pub fn has_telnetd(&self) -> bool {
        self.hits
            .iter()
            .any(|h| h.contains("telnetd") || h.contains("Telnet"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareSecurity — top-level facade
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level firmware security analysis facade.
#[derive(Debug, Default)]
pub struct FirmwareSecurity {
    pub credentials: HardcodedCredentials,
    pub weak_crypto: WeakCrypto,
    pub debug_interfaces: DebugInterface,
    pub uart: UartConsole,
    pub telnet: TelnetService,
    /// Summary statistics populated by `analyse()`.
    pub stats: SecurityStats,
}

/// Summary statistics from a firmware security analysis.
#[derive(Debug, Default, Clone)]
pub struct SecurityStats {
    pub credential_count: usize,
    pub weak_crypto_count: usize,
    pub debug_interface_count: usize,
    pub uart_string_count: usize,
    pub telnet_indicator_count: usize,
    pub total_findings: usize,
}

impl FirmwareSecurity {
    /// Create a new analyser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all analysis passes on raw firmware `data`.
    pub fn analyse(&mut self, data: &[u8]) {
        self.credentials.scan(data);
        self.weak_crypto.scan(data);
        self.debug_interfaces.scan(data);
        self.uart.scan(data);
        self.telnet.scan(data);

        self.stats.credential_count = self.credentials.matches.len();
        self.stats.weak_crypto_count = self.weak_crypto.matches.len();
        self.stats.debug_interface_count = self.debug_interfaces.detected.len();
        self.stats.uart_string_count = self.uart.strings.len();
        self.stats.telnet_indicator_count = self.telnet.hits.len();
        self.stats.total_findings = self.all_findings().len();
    }

    /// Return all findings from all analysers, sorted by risk (highest first).
    #[must_use]
    pub fn all_findings(&self) -> Vec<&FirmwareFinding> {
        let mut all: Vec<&FirmwareFinding> = Vec::new();
        all.extend(self.credentials.findings());
        all.extend(self.weak_crypto.findings());
        all.extend(self.debug_interfaces.findings());
        all.extend(self.uart.findings());
        all.extend(self.telnet.findings());
        all.sort_by(|a, b| b.risk.cmp(&a.risk));
        all
    }

    /// Return the maximum risk level across all findings.
    #[must_use]
    pub fn max_risk(&self) -> Option<FwRisk> {
        self.all_findings().first().map(|f| f.risk)
    }

    /// Return `true` if any finding is at or above `risk`.
    #[must_use]
    pub fn has_risk(&self, risk: FwRisk) -> bool {
        self.all_findings().iter().any(|f| f.risk >= risk)
    }

    /// Return total number of findings.
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.all_findings().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringExtractor — pull ASCII strings from firmware for further analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A printable ASCII string found in firmware.
#[derive(Debug, Clone)]
pub struct FirmwareString {
    /// The string content.
    pub content: String,
    /// Offset in the firmware image.
    pub offset: u64,
}

/// Extracts printable ASCII strings from raw firmware bytes.
#[derive(Debug, Default)]
pub struct FirmwareStringExtractor {
    /// Minimum string length to extract.
    pub min_length: usize,
}

impl FirmwareStringExtractor {
    /// Create an extractor with a minimum length of 4.
    #[must_use]
    pub fn new() -> Self {
        Self { min_length: 4 }
    }

    /// Set the minimum string length.
    #[must_use]
    pub fn with_min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    /// Extract all printable strings from `data`.
    #[must_use]
    pub fn extract(&self, data: &[u8]) -> Vec<FirmwareString> {
        let mut results = Vec::new();
        let mut start = 0usize;
        let mut run = 0usize;

        for (i, &b) in data.iter().enumerate() {
            if (0x20..0x7F).contains(&b) {
                if run == 0 {
                    start = i;
                }
                run += 1;
            } else {
                if run >= self.min_length {
                    // Bytes in 0x20..0x7F are valid ASCII, hence valid UTF-8.
                    let content = std::str::from_utf8(&data[start..start + run])
                        .expect("ASCII printable bytes are valid UTF-8")
                        .to_owned();
                    results.push(FirmwareString {
                        content,
                        offset: start as u64,
                    });
                }
                run = 0;
            }
        }
        // Handle trailing string.
        if run >= self.min_length {
            let content = String::from_utf8_lossy(&data[start..start + run]).into_owned();
            results.push(FirmwareString {
                content,
                offset: start as u64,
            });
        }
        results
    }

    /// Extract strings and filter to those containing `substr`.
    #[must_use]
    pub fn find_containing(&self, data: &[u8], substr: &str) -> Vec<FirmwareString> {
        self.extract(data)
            .into_iter()
            .filter(|s| s.content.contains(substr))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareRiskSummary — overall risk score for a firmware image
// ─────────────────────────────────────────────────────────────────────────────

/// Computes an overall risk score for a firmware image.
pub struct FirmwareRiskSummary;

impl FirmwareRiskSummary {
    /// Compute a normalised risk score in `[0.0, 1.0]` from a `FirmwareSecurity` run.
    ///
    /// Weights:
    /// - Critical findings: 1.0 each (capped at 5)
    /// - High: 0.5 (capped at 5)
    /// - Medium: 0.2 (capped at 5)
    /// - Low: 0.05 (capped at 5)
    #[must_use]
    pub fn score(security: &FirmwareSecurity) -> f64 {
        let findings = security.all_findings();
        let critical = findings
            .iter()
            .filter(|f| f.risk == FwRisk::Critical)
            .count()
            .min(5) as f64;
        let high = findings
            .iter()
            .filter(|f| f.risk == FwRisk::High)
            .count()
            .min(5) as f64;
        let medium = findings
            .iter()
            .filter(|f| f.risk == FwRisk::Medium)
            .count()
            .min(5) as f64;
        let low = findings
            .iter()
            .filter(|f| f.risk == FwRisk::Low)
            .count()
            .min(5) as f64;

        let raw = critical * 1.0 + high * 0.5 + medium * 0.2 + low * 0.05;
        // Maximum raw score when all caps hit: 5 + 2.5 + 1.0 + 0.25 = 8.75
        (raw / 8.75).min(1.0)
    }

    /// Classify the score as a risk label.
    #[must_use]
    pub fn label(score: f64) -> &'static str {
        if score >= 0.75 {
            "CRITICAL"
        } else if score >= 0.5 {
            "HIGH"
        } else if score >= 0.25 {
            "MEDIUM"
        } else if score > 0.0 {
            "LOW"
        } else {
            "CLEAN"
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkServiceScanner — finds network service strings beyond Telnet
// ─────────────────────────────────────────────────────────────────────────────

/// A detected network service in firmware.
#[derive(Debug, Clone)]
pub struct NetworkService {
    pub name: String,
    pub port_hint: Option<u16>,
    pub offset: u64,
    pub risk: FwRisk,
}

/// Scans for network service indicators other than Telnet.
#[derive(Debug, Default)]
pub struct NetworkServiceScanner {
    pub services: Vec<NetworkService>,
}

impl NetworkServiceScanner {
    /// Create a new scanner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `data` for network service indicators.
    pub fn scan(&mut self, data: &[u8]) {
        let patterns: &[(&[u8], &str, Option<u16>, FwRisk)] = &[
            (b"ftpd", "FTP", Some(21), FwRisk::High),
            (b"httpd", "HTTP", Some(80), FwRisk::Medium),
            (b"sshd", "SSH", Some(22), FwRisk::Low),
            (b"dropbear", "SSH", Some(22), FwRisk::Low),
            (b"mosquitto", "MQTT", Some(1883), FwRisk::Medium),
            (b"upnpd", "UPnP", Some(1900), FwRisk::High),
            (b"miniupnpd", "UPnP", Some(1900), FwRisk::High),
            (b"snmpd", "SNMP", Some(161), FwRisk::High),
        ];
        for (pattern, name, port, risk) in patterns {
            let mut pos = 0;
            while pos + pattern.len() <= data.len() {
                if let Some(p) = data[pos..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs = pos + p;
                    self.services.push(NetworkService {
                        name: name.to_string(),
                        port_hint: *port,
                        offset: abs as u64,
                        risk: *risk,
                    });
                    pos = abs + pattern.len();
                } else {
                    break;
                }
            }
        }
    }

    /// Return service names found.
    #[must_use]
    pub fn service_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.services.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FwRisk ────────────────────────────────────────────────────────────────

    #[test]
    fn test_risk_ordering() {
        assert!(FwRisk::Critical > FwRisk::High);
        assert!(FwRisk::High > FwRisk::Medium);
        assert!(FwRisk::Medium > FwRisk::Low);
        assert!(FwRisk::Low > FwRisk::Info);
    }

    #[test]
    fn test_risk_display() {
        assert_eq!(FwRisk::Critical.to_string(), "CRITICAL");
        assert_eq!(FwRisk::Info.to_string(), "INFO");
    }

    // ── FirmwareFinding ───────────────────────────────────────────────────────

    #[test]
    fn test_finding_new() {
        let f = FirmwareFinding::new("cat", "desc", FwRisk::High);
        assert_eq!(f.category, "cat");
        assert_eq!(f.risk, FwRisk::High);
    }

    #[test]
    fn test_finding_with_offset() {
        let f = FirmwareFinding::new("c", "d", FwRisk::Low).with_offset(0x1234);
        assert_eq!(f.offset, Some(0x1234));
    }

    #[test]
    fn test_finding_display() {
        let f = FirmwareFinding::new("cat", "desc", FwRisk::High).with_offset(0x100);
        let s = f.to_string();
        assert!(s.contains("HIGH"));
        assert!(s.contains("0x100"));
    }

    // ── HardcodedCredentials ──────────────────────────────────────────────────

    #[test]
    fn test_creds_scan_password() {
        let mut hc = HardcodedCredentials::new();
        let data = b"password=supersecret\x00";
        hc.scan(data);
        assert!(hc.has_credentials());
        assert!(!hc.matches_of_kind("password").is_empty());
    }

    #[test]
    fn test_creds_scan_admin_admin() {
        let mut hc = HardcodedCredentials::new();
        let data = b"admin:admin\x00";
        hc.scan(data);
        assert!(hc.has_credentials());
    }

    #[test]
    fn test_creds_scan_no_creds() {
        let mut hc = HardcodedCredentials::new();
        let data = b"clean firmware no credentials here";
        hc.scan(data);
        assert!(!hc.has_credentials());
    }

    #[test]
    fn test_creds_scan_rsa_key() {
        let mut hc = HardcodedCredentials::new();
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        hc.scan(data);
        assert!(hc.has_credentials());
    }

    #[test]
    fn test_creds_api_key() {
        let mut hc = HardcodedCredentials::new();
        let data = b"api_key=abcdef1234567890\x00";
        hc.scan(data);
        assert!(!hc.matches_of_kind("api_key").is_empty());
    }

    // ── WeakCrypto ────────────────────────────────────────────────────────────

    #[test]
    fn test_weak_crypto_md5() {
        let mut wc = WeakCrypto::new();
        let data = b"MD5 hash of something";
        wc.scan(data);
        assert!(wc.algorithm_names().contains(&"MD5"));
    }

    #[test]
    fn test_weak_crypto_des() {
        let mut wc = WeakCrypto::new();
        let data = b"using DES encryption";
        wc.scan(data);
        assert!(wc.algorithm_names().contains(&"DES"));
    }

    #[test]
    fn test_weak_crypto_none() {
        let mut wc = WeakCrypto::new();
        let data = b"using AES-256-GCM properly";
        wc.scan(data);
        assert!(wc.matches.is_empty());
    }

    #[test]
    fn test_weak_crypto_rc4_risk() {
        let mut wc = WeakCrypto::new();
        let data = b"RC4 stream cipher";
        wc.scan(data);
        assert!(wc.findings().iter().any(|f| f.risk >= FwRisk::High));
    }

    // ── DebugInterface ────────────────────────────────────────────────────────

    #[test]
    fn test_debug_jtag() {
        let mut di = DebugInterface::new();
        let data = b"JTAG interface enabled";
        di.scan(data);
        assert!(di.has_interface(&DebugInterfaceType::Jtag));
    }

    #[test]
    fn test_debug_swd() {
        let mut di = DebugInterface::new();
        let data = b"SWD debug port";
        di.scan(data);
        assert!(di.has_interface(&DebugInterfaceType::Swd));
    }

    #[test]
    fn test_debug_no_interface() {
        let mut di = DebugInterface::new();
        let data = b"normal firmware code";
        di.scan(data);
        assert!(di.detected.is_empty());
    }

    #[test]
    fn test_debug_interface_type_display() {
        assert_eq!(DebugInterfaceType::Jtag.to_string(), "JTAG");
        assert_eq!(DebugInterfaceType::Swd.to_string(), "SWD");
    }

    // ── UartConsole ───────────────────────────────────────────────────────────

    #[test]
    fn test_uart_login_prompt() {
        let mut uc = UartConsole::new();
        let data = b"login: ";
        uc.scan(data);
        assert!(uc.has_shell_prompt());
    }

    #[test]
    fn test_uart_busybox() {
        let mut uc = UartConsole::new();
        let data = b"BusyBox v1.30.1";
        uc.scan(data);
        assert!(!uc.strings.is_empty());
    }

    #[test]
    fn test_uart_no_strings() {
        let mut uc = UartConsole::new();
        let data = [0x00u8; 64];
        uc.scan(&data);
        assert!(uc.strings.is_empty());
    }

    #[test]
    fn test_uart_u_boot() {
        let mut uc = UartConsole::new();
        let data = b"u-boot> help";
        uc.scan(data);
        assert!(uc.has_shell_prompt());
    }

    // ── TelnetService ─────────────────────────────────────────────────────────

    #[test]
    fn test_telnet_telnetd() {
        let mut ts = TelnetService::new();
        let data = b"telnetd -l /bin/sh";
        ts.scan(data);
        assert!(ts.has_telnetd());
    }

    #[test]
    fn test_telnet_keyword() {
        let mut ts = TelnetService::new();
        let data = b"Telnet service on port 23";
        ts.scan(data);
        assert!(!ts.hits.is_empty());
    }

    #[test]
    fn test_telnet_none() {
        let mut ts = TelnetService::new();
        let data = b"SSH service only";
        ts.scan(data);
        assert!(ts.hits.is_empty());
    }

    #[test]
    fn test_telnet_critical_risk() {
        let mut ts = TelnetService::new();
        let data = b"telnetd -p 23";
        ts.scan(data);
        assert!(ts.findings().iter().any(|f| f.risk >= FwRisk::Critical));
    }

    // ── FirmwareSecurity (facade) ─────────────────────────────────────────────

    #[test]
    fn test_firmware_security_empty() {
        let fs = FirmwareSecurity::new();
        assert_eq!(fs.finding_count(), 0);
        assert!(fs.max_risk().is_none());
    }

    #[test]
    fn test_firmware_security_analyse() {
        let mut fs = FirmwareSecurity::new();
        let data =
            b"password=admin123\x00telnetd -l /bin/sh\x00JTAG enabled\x00MD5 hash\x00login: ";
        fs.analyse(data);
        assert!(fs.finding_count() > 0);
    }

    #[test]
    fn test_firmware_security_max_risk() {
        let mut fs = FirmwareSecurity::new();
        let data = b"password=admin\x00JTAG debug port\x00";
        fs.analyse(data);
        assert_eq!(fs.max_risk(), Some(FwRisk::Critical));
    }

    #[test]
    fn test_firmware_security_sorted() {
        let mut fs = FirmwareSecurity::new();
        let data = b"MD5 hash\x00password=test\x00";
        fs.analyse(data);
        let findings = fs.all_findings();
        for w in findings.windows(2) {
            assert!(w[0].risk >= w[1].risk);
        }
    }

    #[test]
    fn test_firmware_security_has_risk() {
        let mut fs = FirmwareSecurity::new();
        let data = b"telnetd running\x00";
        fs.analyse(data);
        assert!(fs.has_risk(FwRisk::High));
    }

    #[test]
    fn test_creds_root_root() {
        let mut hc = HardcodedCredentials::new();
        let data = b"root:root\x00";
        hc.scan(data);
        assert!(hc.has_credentials());
    }

    #[test]
    fn test_weak_crypto_ecb_mode() {
        let mut wc = WeakCrypto::new();
        let data = b"using AES-ECB mode for encryption";
        wc.scan(data);
        assert!(wc.algorithm_names().contains(&"ECB mode"));
    }

    #[test]
    fn test_uart_password_prompt() {
        let mut uc = UartConsole::new();
        let data = b"Password: ";
        uc.scan(data);
        assert!(uc.has_shell_prompt());
    }

    #[test]
    fn test_debug_jtag_lowercase() {
        let mut di = DebugInterface::new();
        let data = b"jtag pins exposed";
        di.scan(data);
        assert!(di.has_interface(&DebugInterfaceType::Jtag));
    }

    #[test]
    fn test_telnet_port_23() {
        let mut ts = TelnetService::new();
        let data = b"service listening on :23\x00";
        ts.scan(data);
        assert!(!ts.hits.is_empty());
    }

    #[test]
    fn test_firmware_stats_populated() {
        let mut fs = FirmwareSecurity::new();
        let data = b"password=secret\x00telnetd\x00JTAG\x00MD5\x00login: ";
        fs.analyse(data);
        assert!(fs.stats.total_findings > 0);
    }

    #[test]
    fn test_firmware_finding_display_no_offset() {
        let f = FirmwareFinding::new("test", "description", FwRisk::Low);
        let s = f.to_string();
        assert!(s.contains("LOW"));
        assert!(!s.contains('@'));
    }

    #[test]
    fn test_weak_crypto_md2_critical() {
        let mut wc = WeakCrypto::new();
        let data = b"using MD2 for checksums";
        wc.scan(data);
        assert!(wc.findings().iter().any(|f| f.risk == FwRisk::Critical));
    }
}
