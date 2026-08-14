//! `static_analysis_triage` — Static analysis triage engine.
//!
//! Provides [`StaticAnalysisTriage`], [`StaticFeature`], [`FeatureWeight`],
//! [`TriageScore`], [`QuickTriage`], [`DeepTriage`], and [`TriageDecision`]
//! for rapid classification of binary files without execution.

use std::fmt;
use std::time::Instant;

/// Extract the integer floor of `v` as `u32` without any float-to-integer cast.
/// Valid for `v` in `[0.0, 65535.0]`; values outside are clamped.
fn floor_f32_to_u32(v: f32) -> u32 {
    let mut rem = v.clamp(0.0_f32, 65535.0_f32);
    let mut out = 0u32;
    for (thr, bit) in [
        (32768.0_f32, 32768u32),
        (16384.0, 16384),
        (8192.0, 8192),
        (4096.0, 4096),
        (2048.0, 2048),
        (1024.0, 1024),
        (512.0, 512),
        (256.0, 256),
        (128.0, 128),
        (64.0, 64),
        (32.0, 32),
        (16.0, 16),
        (8.0, 8),
        (4.0, 4),
        (2.0, 2),
        (1.0, 1),
    ] {
        if rem >= thr {
            rem -= thr;
            out += bit;
        }
    }
    out
}

use serde::{Deserialize, Serialize};

// ─── StaticFeature ────────────────────────────────────────────────────────────

/// A static feature extracted from a binary during triage analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StaticFeature {
    /// PE anomaly (bad timestamps, mismatched headers, oversized overlay, etc.)
    PeAnomaly(PeAnomaly),
    /// Packer / protector detected.
    Packer(PackerKind),
    /// Cryptographic constant or API usage detected.
    Crypto(CryptoIndicator),
    /// Network-related API or string found.
    Network(NetworkIndicator),
    /// Anti-debug / anti-analysis technique detected.
    AntiDebug(AntiDebugTechnique),
    /// Dropper / downloader behaviour indicators.
    Dropper(DropperIndicator),
}

impl StaticFeature {
    /// Short category label used in reports.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::PeAnomaly(_) => "pe_anomaly",
            Self::Packer(_) => "packer",
            Self::Crypto(_) => "crypto",
            Self::Network(_) => "network",
            Self::AntiDebug(_) => "anti_debug",
            Self::Dropper(_) => "dropper",
        }
    }

    /// Human-readable description of this feature.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::PeAnomaly(a) => format!("PE anomaly: {a}"),
            Self::Packer(p) => format!("Packer detected: {p}"),
            Self::Crypto(c) => format!("Crypto indicator: {c}"),
            Self::Network(n) => format!("Network indicator: {n}"),
            Self::AntiDebug(d) => format!("Anti-debug: {d}"),
            Self::Dropper(d) => format!("Dropper indicator: {d}"),
        }
    }
}

impl fmt::Display for StaticFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category(), self.description())
    }
}

// ── Sub-enumerations ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeAnomaly {
    InvalidTimestamp,
    OversizedOverlay,
    MismatchedSectionCount,
    EntryPointOutsideSection,
    TruncatedOptionalHeader,
    ZeroSizeSection,
    DuplicateSectionName,
    HighEntropySection(String),
    MissingImportDirectory,
    InvalidMachineType,
    SuspiciousCharacteristics,
    DebugDirectoryAbsent,
}

impl fmt::Display for PeAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::OversizedOverlay => write!(f, "oversized overlay"),
            Self::MismatchedSectionCount => write!(f, "mismatched section count"),
            Self::EntryPointOutsideSection => write!(f, "entry point outside any section"),
            Self::TruncatedOptionalHeader => write!(f, "truncated optional header"),
            Self::ZeroSizeSection => write!(f, "section with zero raw size"),
            Self::DuplicateSectionName => write!(f, "duplicate section name"),
            Self::HighEntropySection(s) => write!(f, "high-entropy section: {s}"),
            Self::MissingImportDirectory => write!(f, "no import directory"),
            Self::InvalidMachineType => write!(f, "invalid COFF machine type"),
            Self::SuspiciousCharacteristics => write!(f, "suspicious PE characteristics flags"),
            Self::DebugDirectoryAbsent => write!(f, "debug directory absent (stripped)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerKind {
    Upx,
    Mpress,
    Aspack,
    Vmprotect,
    Themida,
    Pecompact,
    Custom(String),
    Unknown,
}

impl fmt::Display for PackerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upx => write!(f, "UPX"),
            Self::Mpress => write!(f, "MPRESS"),
            Self::Aspack => write!(f, "ASPack"),
            Self::Vmprotect => write!(f, "VMProtect"),
            Self::Themida => write!(f, "Themida/WinLicense"),
            Self::Pecompact => write!(f, "PECompact"),
            Self::Custom(s) => write!(f, "Custom({s})"),
            Self::Unknown => write!(f, "Unknown packer"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoIndicator {
    AesSbox,
    AesRcon,
    Rc4Ksa,
    Sha256Constants,
    Md5Constants,
    ChaCha20Sigma,
    CryptApiImport(String),
    HardcodedKey,
    Base64Payload,
    XorObfuscation,
}

impl fmt::Display for CryptoIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AesSbox => write!(f, "AES S-Box constant table"),
            Self::AesRcon => write!(f, "AES RCON table"),
            Self::Rc4Ksa => write!(f, "RC4 KSA pattern"),
            Self::Sha256Constants => write!(f, "SHA-256 K constants"),
            Self::Md5Constants => write!(f, "MD5 T constants"),
            Self::ChaCha20Sigma => write!(f, "ChaCha20 sigma constant"),
            Self::CryptApiImport(api) => write!(f, "Crypto API import: {api}"),
            Self::HardcodedKey => write!(f, "Hardcoded key material"),
            Self::Base64Payload => write!(f, "Base64-encoded payload"),
            Self::XorObfuscation => write!(f, "XOR-encoded strings"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkIndicator {
    HardcodedIp(String),
    HardcodedDomain(String),
    SuspiciousUrl(String),
    C2Pattern,
    RawSocket,
    DnsLookup,
    HttpClient,
    WinInetImport,
}

impl fmt::Display for NetworkIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardcodedIp(ip) => write!(f, "hard-coded IP: {ip}"),
            Self::HardcodedDomain(d) => write!(f, "hard-coded domain: {d}"),
            Self::SuspiciousUrl(u) => write!(f, "suspicious URL: {u}"),
            Self::C2Pattern => write!(f, "C2 beacon pattern"),
            Self::RawSocket => write!(f, "raw socket usage"),
            Self::DnsLookup => write!(f, "DNS lookup functions"),
            Self::HttpClient => write!(f, "HTTP client strings"),
            Self::WinInetImport => write!(f, "WinInet/WinHTTP import"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiDebugTechnique {
    IsDebuggerPresent,
    CheckRemoteDebuggerPresent,
    NtQueryInformationProcess,
    Timing,
    HardwareBreakpointDetection,
    SehManipulation,
    OutputDebugString,
    Tls,
    VirtualizationDetection,
    HeapFlagCheck,
}

impl fmt::Display for AntiDebugTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsDebuggerPresent => write!(f, "IsDebuggerPresent API"),
            Self::CheckRemoteDebuggerPresent => write!(f, "CheckRemoteDebuggerPresent API"),
            Self::NtQueryInformationProcess => write!(f, "NtQueryInformationProcess"),
            Self::Timing => write!(f, "timing-based anti-debug"),
            Self::HardwareBreakpointDetection => write!(f, "hardware breakpoint detection"),
            Self::SehManipulation => write!(f, "SEH manipulation"),
            Self::OutputDebugString => write!(f, "OutputDebugString trick"),
            Self::Tls => write!(f, "TLS callback anti-debug"),
            Self::VirtualizationDetection => write!(f, "VM/sandbox detection"),
            Self::HeapFlagCheck => write!(f, "heap flag inspection"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DropperIndicator {
    EmbeddedPe,
    ResourceSection,
    DownloadAndExecute,
    SelfDelete,
    ChildProcess,
    MemoryOnlyExecution,
    ReflectiveDll,
    ShellcodePattern,
}

impl fmt::Display for DropperIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmbeddedPe => write!(f, "embedded PE in resources/overlay"),
            Self::ResourceSection => write!(f, "suspicious resource section"),
            Self::DownloadAndExecute => write!(f, "download-and-execute pattern"),
            Self::SelfDelete => write!(f, "self-deletion routine"),
            Self::ChildProcess => write!(f, "child process spawning"),
            Self::MemoryOnlyExecution => write!(f, "memory-only execution"),
            Self::ReflectiveDll => write!(f, "reflective DLL injection"),
            Self::ShellcodePattern => write!(f, "embedded shellcode pattern"),
        }
    }
}

// ─── FeatureWeight ────────────────────────────────────────────────────────────

/// Score weight assigned to a detected [`StaticFeature`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureWeight {
    pub feature: StaticFeature,
    /// Base weight contribution to the total score (0–30).
    pub weight: u8,
    /// Multiplier applied when the feature co-occurs with another high-severity feature.
    pub escalation_multiplier: f32,
    /// Whether this feature is sufficient alone for a malicious verdict.
    pub critical: bool,
    /// Evidence string (e.g., byte offset, matched string).
    pub evidence: String,
}

impl FeatureWeight {
    /// Create a standard weight entry.
    #[must_use]
    pub fn new(feature: StaticFeature, weight: u8, evidence: impl Into<String>) -> Self {
        Self {
            feature,
            weight: weight.min(30),
            escalation_multiplier: 1.0,
            critical: false,
            evidence: evidence.into(),
        }
    }

    /// Mark as a critical indicator.
    #[must_use]
    pub const fn critical(mut self) -> Self {
        self.critical = true;
        self
    }

    /// Set the escalation multiplier.
    #[must_use]
    pub const fn with_escalation(mut self, m: f32) -> Self {
        self.escalation_multiplier = if m > 1.0 { m } else { 1.0 };
        self
    }

    /// Effective weight after applying the escalation multiplier.
    #[must_use]
    pub fn effective_weight(&self) -> u32 {
        // weight is u8 (0-30); escalation_multiplier ≥ 1.0 by construction.
        // Clamp to [0, 255] so the as-cast to u8 is always safe.
        let product = f32::from(self.weight) * self.escalation_multiplier;
        floor_f32_to_u32(product.clamp(0.0_f32, 65535.0_f32))
    }
}

// ─── TriageScore ──────────────────────────────────────────────────────────────

/// A normalised threat score in the range 0–100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TriageScore(u8);

impl TriageScore {
    /// Construct a new score, clamping to [0, 100].
    #[must_use]
    pub fn new(raw: u32) -> Self {
        Self(raw.min(100) as u8)
    }

    /// Underlying score value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Returns the corresponding [`TriageDecision`].
    #[must_use]
    pub const fn decision(self) -> TriageDecision {
        match self.0 {
            0..=20 => TriageDecision::Benign,
            21..=60 => TriageDecision::Suspicious,
            61..=100 => TriageDecision::Malicious,
            _ => unreachable!(),
        }
    }

    /// Returns `true` if the score suggests a malicious sample.
    #[must_use]
    pub const fn is_malicious(self) -> bool {
        self.0 >= 61
    }

    /// Returns `true` if the score suggests a suspicious sample.
    #[must_use]
    pub const fn is_suspicious(self) -> bool {
        self.0 >= 21
    }
}

impl fmt::Display for TriageScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/100", self.0)
    }
}

// ─── TriageDecision ───────────────────────────────────────────────────────────

/// Final verdict produced by the triage engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TriageDecision {
    /// No malicious indicators found.
    Benign,
    /// Some suspicious indicators; manual review recommended.
    Suspicious,
    /// High confidence of malicious intent.
    Malicious,
}

impl TriageDecision {
    /// Returns the recommended action string.
    #[must_use]
    pub const fn recommended_action(self) -> &'static str {
        match self {
            Self::Benign => "allow",
            Self::Suspicious => "manual_review",
            Self::Malicious => "block_and_quarantine",
        }
    }
}

impl fmt::Display for TriageDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Benign => write!(f, "Benign"),
            Self::Suspicious => write!(f, "Suspicious"),
            Self::Malicious => write!(f, "Malicious"),
        }
    }
}

// ─── TriageReport ─────────────────────────────────────────────────────────────

/// Fully-structured output from a triage pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticTriageReport {
    /// Hash of the analysed file (hex string, 16 bytes FNV-like placeholder).
    pub file_hash: String,
    /// File size in bytes.
    pub file_size: usize,
    /// Overall threat score.
    pub score: TriageScore,
    /// Final decision.
    pub decision: TriageDecision,
    /// All features detected with their weights.
    pub features: Vec<FeatureWeight>,
    /// Whether the binary appears packed.
    pub is_packed: bool,
    /// Detected compiler / linker hint.
    pub compiler_hint: Option<String>,
    /// Wall-clock time taken by this analysis pass, in milliseconds.
    pub elapsed_ms: u64,
    /// Whether this was a quick pass (< 1 s) or a deep pass.
    pub mode: TriageMode,
    /// Any critical features that immediately escalate to Malicious.
    pub critical_features: Vec<String>,
}

impl StaticTriageReport {
    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns a string description on serialisation failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Short summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{:?}] score={} packed={} features={} elapsed={}ms",
            self.decision,
            self.score,
            self.is_packed,
            self.features.len(),
            self.elapsed_ms
        )
    }
}

impl fmt::Display for StaticTriageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Static Triage Report ===")?;
        writeln!(f, "  Decision   : {}", self.decision)?;
        writeln!(f, "  Score      : {}", self.score)?;
        writeln!(f, "  Packed     : {}", self.is_packed)?;
        writeln!(f, "  Mode       : {:?}", self.mode)?;
        writeln!(f, "  Elapsed ms : {}", self.elapsed_ms)?;
        writeln!(f, "  Features   : {}", self.features.len())?;
        for fw in &self.features {
            writeln!(f, "    [w={:2}] {}", fw.weight, fw.feature)?;
        }
        Ok(())
    }
}

// ─── TriageMode ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageMode {
    /// < 1 second pass: EP bytes, magic detection, string grep only.
    Quick,
    /// Full pass: all detectors including entropy and import analysis.
    Deep,
}

// ─── QuickTriage ─────────────────────────────────────────────────────────────

/// Fast triage pass that completes in under 1 second.
///
/// Checks:
/// - MZ / ELF magic
/// - UPX section name presence
/// - Common malware strings
/// - EP byte patterns (pushad/call)
/// - Import count anomaly
pub struct QuickTriage {
    /// Minimum number of characters for string extraction.
    pub min_string_len: usize,
}

impl QuickTriage {
    /// Create a default [`QuickTriage`] instance.
    #[must_use]
    pub const fn new() -> Self {
        Self { min_string_len: 6 }
    }

    /// Run a quick pass on `data` and return the detected features.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> Vec<FeatureWeight> {
        let mut features = Vec::new();

        // UPX detection
        if contains(data, b"UPX0") || contains(data, b"UPX1") || contains(data, b"UPX!") {
            features.push(FeatureWeight::new(
                StaticFeature::Packer(PackerKind::Upx),
                20,
                "UPX section name found",
            ));
        }

        // VMProtect
        if contains(data, b".vmp0") || contains(data, b".vmp1") {
            features.push(FeatureWeight::new(
                StaticFeature::Packer(PackerKind::Vmprotect),
                22,
                ".vmp0/.vmp1 section name",
            ));
        }

        // Themida
        if contains(data, b".themida") {
            features.push(FeatureWeight::new(
                StaticFeature::Packer(PackerKind::Themida),
                22,
                ".themida section name",
            ));
        }

        // ASPack
        if contains(data, b".aspack") {
            features.push(FeatureWeight::new(
                StaticFeature::Packer(PackerKind::Aspack),
                18,
                ".aspack section name",
            ));
        }

        // IsDebuggerPresent
        if contains(data, b"IsDebuggerPresent") {
            features.push(FeatureWeight::new(
                StaticFeature::AntiDebug(AntiDebugTechnique::IsDebuggerPresent),
                10,
                "IsDebuggerPresent string",
            ));
        }

        // CheckRemoteDebuggerPresent
        if contains(data, b"CheckRemoteDebuggerPresent") {
            features.push(FeatureWeight::new(
                StaticFeature::AntiDebug(AntiDebugTechnique::CheckRemoteDebuggerPresent),
                12,
                "CheckRemoteDebuggerPresent string",
            ));
        }

        // NtQueryInformationProcess
        if contains(data, b"NtQueryInformationProcess") {
            features.push(FeatureWeight::new(
                StaticFeature::AntiDebug(AntiDebugTechnique::NtQueryInformationProcess),
                12,
                "NtQueryInformationProcess",
            ));
        }

        // AES S-Box
        let aes_sbox: &[u8] = &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        ];
        if contains(data, aes_sbox) {
            features.push(FeatureWeight::new(
                StaticFeature::Crypto(CryptoIndicator::AesSbox),
                8,
                "AES S-Box at offset",
            ));
        }

        // ChaCha20 sigma
        if contains(data, b"expand 32-byte k") {
            features.push(FeatureWeight::new(
                StaticFeature::Crypto(CryptoIndicator::ChaCha20Sigma),
                8,
                "ChaCha20 sigma constant",
            ));
        }

        // Suspicious download strings
        for s in &[b"DownloadString" as &[u8], b"DownloadFile", b"URLDownloadToFile"] {
            if contains(data, s) {
                features.push(FeatureWeight::new(
                    StaticFeature::Dropper(DropperIndicator::DownloadAndExecute),
                    15,
                    String::from_utf8_lossy(s).to_string(),
                ));
                break;
            }
        }

        // Embedded PE in data
        if count_occurrences(data, b"MZ") > 1 {
            features.push(FeatureWeight::new(
                StaticFeature::Dropper(DropperIndicator::EmbeddedPe),
                20,
                "multiple MZ headers",
            ).critical());
        }

        // Shellcode pattern (call $+5)
        let call_plus5: &[u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B];
        if contains(data, call_plus5) {
            features.push(FeatureWeight::new(
                StaticFeature::Dropper(DropperIndicator::ShellcodePattern),
                18,
                "call $+5 shellcode pattern",
            ));
        }

        features
    }
}

impl Default for QuickTriage {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DeepTriage ───────────────────────────────────────────────────────────────

/// Full static analysis triage pass.
///
/// Runs all `QuickTriage` checks plus:
/// - Section entropy analysis
/// - Full import table scan
/// - PE header anomaly detection
/// - Overlay / resource analysis
/// - Crypto constant scanning
pub struct DeepTriage {
    /// Entropy threshold above which a section is flagged (default 7.0).
    pub entropy_threshold: f64,
    /// Minimum string length for string scanning.
    pub min_string_len: usize,
    /// Whether to scan the overlay for embedded PE files.
    pub scan_overlay: bool,
}

impl DeepTriage {
    /// Create a [`DeepTriage`] instance with defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entropy_threshold: 7.0,
            min_string_len: 6,
            scan_overlay: true,
        }
    }

    /// Analyse `data` and return features (quick + deep checks).
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> Vec<FeatureWeight> {
        let mut features = QuickTriage::new().analyze(data);

        // ── PE header checks ──────────────────────────────────────────────────
        if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
            self.analyze_pe(data, &mut features);
        }

        // ── Entropy of whole file ─────────────────────────────────────────────
        let global_entropy = shannon_entropy(data);
        if global_entropy > self.entropy_threshold {
            features.push(FeatureWeight::new(
                StaticFeature::PeAnomaly(PeAnomaly::HighEntropySection("file".to_string())),
                18,
                format!("global entropy = {global_entropy:.3}"),
            ));
        }

        // ── Crypto constants ──────────────────────────────────────────────────
        // RC4 KSA
        let rc4: &[u8] = &[0x88, 0x04, 0x0E, 0x02, 0x04, 0x0E, 0x88, 0x01];
        if contains(data, rc4) {
            features.push(FeatureWeight::new(
                StaticFeature::Crypto(CryptoIndicator::Rc4Ksa),
                8,
                "RC4 KSA pattern",
            ));
        }

        // SHA-256 K constants (first 8 bytes)
        let sha256k: &[u8] = &[0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71];
        if contains(data, sha256k) {
            features.push(FeatureWeight::new(
                StaticFeature::Crypto(CryptoIndicator::Sha256Constants),
                7,
                "SHA-256 K constants",
            ));
        }

        // CryptAPI imports
        for api in &["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptGenerateSymmetricKey"] {
            if contains(data, api.as_bytes()) {
                features.push(FeatureWeight::new(
                    StaticFeature::Crypto(CryptoIndicator::CryptApiImport(api.to_string())),
                    10,
                    format!("Crypto API: {api}"),
                ));
            }
        }

        // ── Network strings ───────────────────────────────────────────────────
        for api in &["WinHttpSendRequest", "InternetConnect", "WSAStartup", "connect"] {
            if contains(data, api.as_bytes()) {
                features.push(FeatureWeight::new(
                    StaticFeature::Network(NetworkIndicator::WinInetImport),
                    8,
                    format!("Network API: {api}"),
                ));
                break;
            }
        }

        // Hard-coded IP detection in strings
        let ascii_strings = extract_ascii_strings(data, self.min_string_len);
        for s in &ascii_strings {
            // Report the address itself, not the whole run it was found in.
            if let Some(ip) = find_ipv4(s) {
                features.push(FeatureWeight::new(
                    StaticFeature::Network(NetworkIndicator::HardcodedIp(ip.to_string())),
                    10,
                    format!("IP string: {s}"),
                ));
            }
            // `contains`, not `starts_with`: a scheme marker is unambiguous
            // wherever it sits in an extracted run (same defect as the IP
            // check above, and as `StringHeuristics::classify_structural`).
            if s.contains("http://") || s.contains("https://") {
                features.push(FeatureWeight::new(
                    StaticFeature::Network(NetworkIndicator::SuspiciousUrl(s.clone())),
                    12,
                    format!("URL: {s}"),
                ));
            }
        }

        // ── Timing anti-debug ─────────────────────────────────────────────────
        if contains(data, b"QueryPerformanceCounter") && contains(data, b"GetTickCount") {
            features.push(FeatureWeight::new(
                StaticFeature::AntiDebug(AntiDebugTechnique::Timing),
                10,
                "timing-based anti-debug APIs",
            ));
        }

        // ── Reflective DLL ────────────────────────────────────────────────────
        if contains(data, b"ReflectiveDll") || contains(data, b"ReflectiveLoader") {
            features.push(FeatureWeight::new(
                StaticFeature::Dropper(DropperIndicator::ReflectiveDll),
                25,
                "ReflectiveDll/Loader string",
            ).critical());
        }

        features
    }

    fn analyze_pe(&self, data: &[u8], features: &mut Vec<FeatureWeight>) {
        if data.len() < 0x40 {
            return;
        }
        let pe_off = match read_u32_le(data, 0x3C) {
            Some(o) if (o as usize) + 0x18 < data.len() => o as usize,
            _ => return,
        };
        if data.get(pe_off..pe_off + 4) != Some(b"PE\x00\x00") {
            return;
        }

        let num_sections = read_u16_le(data, pe_off + 6).unwrap_or(0) as usize;
        let opt_size = read_u16_le(data, pe_off + 0x14).unwrap_or(0) as usize;

        // Missing import directory check
        let magic = read_u16_le(data, pe_off + 0x18).unwrap_or(0);
        let dd_off = if magic == 0x020b { pe_off + 0x18 + 0x70 } else { pe_off + 0x18 + 0x60 };
        if let (Some(0), Some(_)) = (
            read_u32_le(data, dd_off + 8),
            read_u32_le(data, dd_off + 12),
        ) {
            features.push(FeatureWeight::new(
                StaticFeature::PeAnomaly(PeAnomaly::MissingImportDirectory),
                20,
                "import directory RVA = 0",
            ));
        }

        // Section analysis
        let sec_tbl = pe_off + 0x18 + opt_size;
        let mut section_names: std::collections::HashSet<String> = std::collections::HashSet::new();

        for i in 0..num_sections.min(96) {
            let s = sec_tbl + i * 40;
            if s + 40 > data.len() {
                break;
            }
            let name_bytes = &data[s..s + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

            // Duplicate section names
            if !section_names.insert(name.clone()) {
                features.push(FeatureWeight::new(
                    StaticFeature::PeAnomaly(PeAnomaly::DuplicateSectionName),
                    15,
                    format!("duplicate section name: {name}"),
                ));
            }

            // Zero-size section
            let raw_size = read_u32_le(data, s + 16).unwrap_or(0) as usize;
            if raw_size == 0 {
                features.push(FeatureWeight::new(
                    StaticFeature::PeAnomaly(PeAnomaly::ZeroSizeSection),
                    8,
                    format!("section {name} has raw size 0"),
                ));
            }

            // High entropy section
            let raw_off = read_u32_le(data, s + 20).unwrap_or(0) as usize;
            if raw_size > 0 && raw_off + raw_size <= data.len() {
                let entropy = shannon_entropy(&data[raw_off..raw_off + raw_size]);
                if entropy > self.entropy_threshold {
                    features.push(FeatureWeight::new(
                        StaticFeature::PeAnomaly(PeAnomaly::HighEntropySection(name.clone())),
                        18,
                        format!("section {name} entropy = {entropy:.3}"),
                    ));
                }
            }
        }

        // Overlay check
        if self.scan_overlay {
            let mut last_end = 0usize;
            for i in 0..num_sections.min(96) {
                let s = sec_tbl + i * 40;
                if s + 40 > data.len() { break; }
                let raw_off = read_u32_le(data, s + 20).unwrap_or(0) as usize;
                let raw_size = read_u32_le(data, s + 16).unwrap_or(0) as usize;
                if raw_off + raw_size > last_end {
                    last_end = raw_off + raw_size;
                }
            }
            if last_end > 0 && last_end < data.len() {
                let overlay_size = data.len() - last_end;
                if overlay_size > 4096 {
                    features.push(FeatureWeight::new(
                        StaticFeature::PeAnomaly(PeAnomaly::OversizedOverlay),
                        15,
                        format!("overlay: {overlay_size} bytes at 0x{last_end:x}"),
                    ));
                }
            }
        }
    }
}

impl Default for DeepTriage {
    fn default() -> Self {
        Self::new()
    }
}

// ─── StaticAnalysisTriage ─────────────────────────────────────────────────────

/// Main entry point for static analysis triage.
///
/// Combines quick and deep analysis passes into a single pipeline that
/// produces a [`StaticTriageReport`].
pub struct StaticAnalysisTriage {
    /// Configuration parameters.
    pub config: StaticTriageConfig,
}

/// Configuration for [`StaticAnalysisTriage`].
#[derive(Debug, Clone)]
pub struct StaticTriageConfig {
    /// Entropy threshold for marking a section as high-entropy.
    pub entropy_threshold: f64,
    /// Whether to run the deep analysis pass.
    pub deep_analysis: bool,
    /// Minimum string length.
    pub min_string_len: usize,
    /// Score threshold below which the result is benign (default 20).
    pub benign_threshold: u8,
    /// Score threshold above which the result is malicious (default 60).
    pub malicious_threshold: u8,
    /// Maximum number of features to collect.
    pub max_features: usize,
}

impl Default for StaticTriageConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 7.0,
            deep_analysis: true,
            min_string_len: 6,
            benign_threshold: 20,
            malicious_threshold: 60,
            max_features: 256,
        }
    }
}

impl StaticAnalysisTriage {
    /// Create an instance with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: StaticTriageConfig::default() }
    }

    /// Create an instance with custom configuration.
    #[must_use]
    pub const fn with_config(config: StaticTriageConfig) -> Self {
        Self { config }
    }

    /// Run the full triage pipeline on `data`.
    #[must_use]
    pub fn triage(&self, data: &[u8]) -> StaticTriageReport {
        let start = Instant::now();
        let mode = if self.config.deep_analysis { TriageMode::Deep } else { TriageMode::Quick };

        let features = if self.config.deep_analysis {
            let dt = DeepTriage {
                entropy_threshold: self.config.entropy_threshold,
                min_string_len: self.config.min_string_len,
                scan_overlay: true,
            };
            dt.analyze(data)
        } else {
            QuickTriage::new().analyze(data)
        };

        // Limit features
        let features: Vec<FeatureWeight> = features
            .into_iter()
            .take(self.config.max_features)
            .collect();

        // Compute score
        let mut raw_score: u32 = 0;
        let mut critical_features: Vec<String> = Vec::new();
        let mut is_packed = false;

        for fw in &features {
            raw_score = raw_score.saturating_add(fw.effective_weight());
            if fw.critical {
                critical_features.push(fw.feature.description());
                raw_score = raw_score.saturating_add(20); // extra for critical
            }
            if matches!(fw.feature, StaticFeature::Packer(_)) {
                is_packed = true;
            }
        }

        // Any critical feature escalates directly to malicious score
        if !critical_features.is_empty() {
            raw_score = raw_score.max(65);
        }

        let score = TriageScore::new(raw_score);
        let decision = score.decision();

        // Compiler hint
        let compiler_hint = detect_compiler_hint(data);

        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let file_hash = simple_hash(data);

        StaticTriageReport {
            file_hash,
            file_size: data.len(),
            score,
            decision,
            features,
            is_packed,
            compiler_hint,
            elapsed_ms,
            mode,
            critical_features,
        }
    }

    /// Run a quick (< 1 s) triage on `data`.
    #[must_use]
    pub fn quick_triage(&self, data: &[u8]) -> StaticTriageReport {
        let mut cfg = self.config.clone();
        cfg.deep_analysis = false;
        let quick = Self::with_config(cfg);
        quick.triage(data)
    }

    /// Batch triage: analyse multiple buffers and return one report per input.
    #[must_use]
    pub fn batch_triage<'a>(&self, inputs: impl Iterator<Item = &'a [u8]>) -> Vec<StaticTriageReport> {
        inputs.map(|data| self.triage(data)).collect()
    }

    /// Analyse a feature set and classify without running detectors.
    #[must_use]
    pub fn classify_features(&self, features: Vec<FeatureWeight>) -> StaticTriageReport {
        let mut raw_score: u32 = 0;
        let mut critical_features = Vec::new();
        let mut is_packed = false;

        for fw in &features {
            raw_score = raw_score.saturating_add(fw.effective_weight());
            if fw.critical { critical_features.push(fw.feature.description()); }
            if matches!(fw.feature, StaticFeature::Packer(_)) { is_packed = true; }
        }

        if !critical_features.is_empty() {
            raw_score = raw_score.max(65);
        }

        let score = TriageScore::new(raw_score);
        StaticTriageReport {
            file_hash: String::new(),
            file_size: 0,
            score,
            decision: score.decision(),
            features,
            is_packed,
            compiler_hint: None,
            elapsed_ms: 0,
            mode: TriageMode::Quick,
            critical_features,
        }
    }
}

impl Default for StaticAnalysisTriage {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[inline]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() { return 0; }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut start: Option<usize> = None;
    // A run is opened by the first printable byte and closed by the first
    // NON-printable one.
    //
    // Until 2026-07-29 the loop read
    //   `if (printable) && start.is_none() { start = Some(i) } else if …`,
    // so once a run was open the first arm was false for **every** following
    // byte — printable or not — and the `else` arm immediately closed the run
    // after a single character and reset `start`. With `min_len = 6` that meant
    // `extract_ascii_strings` returned **nothing at all, for any input**, and
    // every caller silently saw a binary with no strings in it.
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take()
            && i - s >= min_len
            && let Ok(v) = std::str::from_utf8(&data[s..i])
        {
            strings.push(v.to_string());
        }
    }
    if let Some(s) = start && data.len() - s >= min_len && let Ok(v) = std::str::from_utf8(&data[s..]) {
        strings.push(v.to_string());
    }
    strings
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Find an IPv4 address **embedded anywhere** in `s`, returning the exact
/// substring that matched.
///
/// [`looks_like_ipv4`] tests a whole string, which is the wrong question for
/// extracted strings: a run of printable bytes reads like
/// `"connect to 192.168.1.1 for stuff"`, and splitting THAT on `.` yields
/// four parts of which the first is `"connect to 192"` — so the address was
/// missed entirely. Added 2026-07-29.
///
/// Scans maximal runs of digits and dots, since an IPv4 literal can contain
/// nothing else, and trims trailing dots so `"10.0.0.1."` still matches.
fn find_ipv4(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        let tok = s[start..i].trim_end_matches('.');
        if looks_like_ipv4(tok) {
            return Some(tok);
        }
    }
    None
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = f64::from(c) / len;
        -p * p.log2()
    }).sum::<f64>().clamp(0.0, 8.0)
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]))
}

fn simple_hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325_u64;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3_u64);
    }
    format!("{h:016x}")
}

fn detect_compiler_hint(data: &[u8]) -> Option<String> {
    if contains(data, b"rustc") { return Some("Rust".to_string()); }
    if contains(data, b"GoBuildID") || contains(data, b"GoLang") { return Some("Go".to_string()); }
    if contains(data, b"MinGW") || contains(data, b"GCC") { return Some("GCC/MinGW".to_string()); }
    if contains(data, b"MSVC") || contains(data, b"Visual C++") { return Some("MSVC".to_string()); }
    if contains(data, b"Delphi") || contains(data, b"Borland") { return Some("Delphi".to_string()); }
    if contains(data, b"PyInstaller") || contains(data, b"MEI\x0C") { return Some("PyInstaller".to_string()); }
    None
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mz() -> Vec<u8> {
        let mut v = vec![0u8; 512];
        v[0] = 0x4D; v[1] = 0x5A;
        v
    }

    // ── TriageScore ──────────────────────────────────────────────────────────

    #[test]
    fn test_triage_score_benign() {
        let s = TriageScore::new(10);
        assert_eq!(s.decision(), TriageDecision::Benign);
        assert!(!s.is_malicious());
    }

    #[test]
    fn test_triage_score_suspicious() {
        let s = TriageScore::new(40);
        assert_eq!(s.decision(), TriageDecision::Suspicious);
        assert!(s.is_suspicious());
        assert!(!s.is_malicious());
    }

    #[test]
    fn test_triage_score_malicious() {
        let s = TriageScore::new(75);
        assert_eq!(s.decision(), TriageDecision::Malicious);
        assert!(s.is_malicious());
    }

    #[test]
    fn test_triage_score_clamped() {
        let s = TriageScore::new(9999);
        assert_eq!(s.value(), 100);
    }

    #[test]
    fn test_triage_score_zero() {
        let s = TriageScore::new(0);
        assert_eq!(s.decision(), TriageDecision::Benign);
    }

    #[test]
    fn test_triage_score_boundary_21() {
        assert_eq!(TriageScore::new(21).decision(), TriageDecision::Suspicious);
    }

    #[test]
    fn test_triage_score_boundary_61() {
        assert_eq!(TriageScore::new(61).decision(), TriageDecision::Malicious);
    }

    // ── TriageDecision ───────────────────────────────────────────────────────

    #[test]
    fn test_decision_display() {
        assert_eq!(TriageDecision::Benign.to_string(), "Benign");
        assert_eq!(TriageDecision::Suspicious.to_string(), "Suspicious");
        assert_eq!(TriageDecision::Malicious.to_string(), "Malicious");
    }

    #[test]
    fn test_decision_action() {
        assert_eq!(TriageDecision::Benign.recommended_action(), "allow");
        assert_eq!(TriageDecision::Malicious.recommended_action(), "block_and_quarantine");
    }

    // ── StaticFeature ────────────────────────────────────────────────────────

    #[test]
    fn test_static_feature_category() {
        assert_eq!(StaticFeature::Packer(PackerKind::Upx).category(), "packer");
        assert_eq!(StaticFeature::AntiDebug(AntiDebugTechnique::IsDebuggerPresent).category(), "anti_debug");
        assert_eq!(StaticFeature::Crypto(CryptoIndicator::AesSbox).category(), "crypto");
    }

    #[test]
    fn test_static_feature_display() {
        let f = StaticFeature::Packer(PackerKind::Upx);
        assert!(f.to_string().contains("UPX"));
    }

    #[test]
    fn test_packer_kind_display() {
        assert!(PackerKind::Upx.to_string().contains("UPX"));
        assert!(PackerKind::Vmprotect.to_string().contains("VMProtect"));
    }

    #[test]
    fn test_anti_debug_display() {
        assert!(AntiDebugTechnique::IsDebuggerPresent.to_string().contains("IsDebuggerPresent"));
    }

    #[test]
    fn test_network_indicator_display() {
        let n = NetworkIndicator::HardcodedIp("1.2.3.4".to_string());
        assert!(n.to_string().contains("1.2.3.4"));
    }

    // ── FeatureWeight ────────────────────────────────────────────────────────

    #[test]
    fn test_feature_weight_effective_weight() {
        let fw = FeatureWeight::new(
            StaticFeature::Packer(PackerKind::Upx),
            10,
            "test",
        ).with_escalation(2.0);
        assert_eq!(fw.effective_weight(), 20);
    }

    #[test]
    fn test_feature_weight_critical() {
        let fw = FeatureWeight::new(
            StaticFeature::Dropper(DropperIndicator::EmbeddedPe),
            20,
            "test",
        ).critical();
        assert!(fw.critical);
    }

    #[test]
    fn test_feature_weight_weight_capped() {
        let fw = FeatureWeight::new(StaticFeature::Packer(PackerKind::Upx), 255, "test");
        assert_eq!(fw.weight, 30);
    }

    // ── QuickTriage ──────────────────────────────────────────────────────────

    #[test]
    fn test_quick_triage_empty_data() {
        let qt = QuickTriage::new();
        let features = qt.analyze(&[]);
        assert!(features.is_empty());
    }

    #[test]
    fn test_quick_triage_detects_upx() {
        let qt = QuickTriage::new();
        let mut data = vec![0u8; 100];
        data.extend_from_slice(b"UPX0");
        let features = qt.analyze(&data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Packer(PackerKind::Upx))));
    }

    #[test]
    fn test_quick_triage_detects_vmprotect() {
        let qt = QuickTriage::new();
        let mut data = vec![0u8; 100];
        data.extend_from_slice(b".vmp0");
        let features = qt.analyze(&data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Packer(PackerKind::Vmprotect))));
    }

    #[test]
    fn test_quick_triage_detects_isdebugger() {
        let qt = QuickTriage::new();
        let data = b"IsDebuggerPresent some junk";
        let features = qt.analyze(data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::AntiDebug(AntiDebugTechnique::IsDebuggerPresent))));
    }

    #[test]
    fn test_quick_triage_detects_aes_sbox() {
        let qt = QuickTriage::new();
        let aes_sbox: &[u8] = &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        ];
        let features = qt.analyze(aes_sbox);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Crypto(CryptoIndicator::AesSbox))));
    }

    #[test]
    fn test_quick_triage_detects_embedded_pe() {
        let qt = QuickTriage::new();
        let data = b"MZ...\x00\x00MZ...\x00\x00";
        let features = qt.analyze(data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Dropper(DropperIndicator::EmbeddedPe))));
    }

    #[test]
    fn test_quick_triage_detects_shellcode() {
        let qt = QuickTriage::new();
        let data: &[u8] = &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x00, 0x00];
        let features = qt.analyze(data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Dropper(DropperIndicator::ShellcodePattern))));
    }

    // ── DeepTriage ───────────────────────────────────────────────────────────

    #[test]
    fn test_deep_triage_includes_quick_results() {
        let dt = DeepTriage::new();
        let mut data = vec![0u8; 200];
        data.extend_from_slice(b"UPX0");
        let features = dt.analyze(&data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Packer(PackerKind::Upx))));
    }

    #[test]
    fn test_deep_triage_high_entropy() {
        let dt = DeepTriage { entropy_threshold: 7.0, ..Default::default() };
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let features = dt.analyze(&data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::PeAnomaly(PeAnomaly::HighEntropySection(_)))));
    }

    #[test]
    fn test_deep_triage_sha256_constants() {
        let dt = DeepTriage::new();
        let k: &[u8] = &[0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71];
        let features = dt.analyze(k);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Crypto(CryptoIndicator::Sha256Constants))));
    }

    #[test]
    fn test_deep_triage_hardcoded_ip() {
        let dt = DeepTriage::new();
        let data = b"connect to 192.168.1.1 for stuff";
        let features = dt.analyze(data);
        assert!(features.iter().any(|f| matches!(f.feature, StaticFeature::Network(NetworkIndicator::HardcodedIp(_)))));
    }

    // ── StaticAnalysisTriage ─────────────────────────────────────────────────

    #[test]
    fn test_triage_empty_data_benign() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(&[]);
        assert_eq!(report.decision, TriageDecision::Benign);
    }

    #[test]
    fn test_triage_clean_binary() {
        let t = StaticAnalysisTriage::new();
        let data = make_mz();
        let report = t.triage(&data);
        // MZ with nothing suspicious should be benign or low score
        assert!(report.score.value() < 50);
    }

    #[test]
    fn test_triage_upx_sample() {
        let t = StaticAnalysisTriage::new();
        let mut data = make_mz();
        data.extend_from_slice(b"UPX0UPX1UPX!");
        let report = t.triage(&data);
        assert!(report.is_packed);
    }

    #[test]
    fn test_triage_critical_feature_escalates() {
        let t = StaticAnalysisTriage::new();
        let data = b"MZMZheader"; // two MZ headers triggers embedded PE (critical)
        let report = t.triage(data);
        assert!(!report.critical_features.is_empty());
        assert!(report.score.is_malicious());
    }

    #[test]
    fn test_triage_report_json_roundtrip() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(b"test data");
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["decision"].is_string());
    }

    #[test]
    fn test_triage_quick_mode() {
        let t = StaticAnalysisTriage::new();
        let report = t.quick_triage(b"IsDebuggerPresent");
        assert_eq!(report.mode, TriageMode::Quick);
    }

    #[test]
    fn test_triage_deep_mode() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(b"IsDebuggerPresent");
        assert_eq!(report.mode, TriageMode::Deep);
    }

    #[test]
    fn test_triage_batch() {
        let t = StaticAnalysisTriage::new();
        let inputs: Vec<Vec<u8>> = vec![vec![0u8; 10], vec![0x4d, 0x5a], b"UPX0".to_vec()];
        let reports = t.batch_triage(inputs.iter().map(|v| v.as_slice()));
        assert_eq!(reports.len(), 3);
    }

    #[test]
    fn test_triage_rust_compiler_hint() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(b"rustc 1.75.0");
        assert_eq!(report.compiler_hint.as_deref(), Some("Rust"));
    }

    #[test]
    fn test_triage_go_compiler_hint() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(b"GoBuildID: some-id");
        assert_eq!(report.compiler_hint.as_deref(), Some("Go"));
    }

    #[test]
    fn test_triage_summary_contains_fields() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(&[]);
        let summary = report.summary();
        assert!(summary.contains("score="));
        assert!(summary.contains("packed="));
    }

    #[test]
    fn test_triage_display() {
        let t = StaticAnalysisTriage::new();
        let report = t.triage(b"UPX0IsDebuggerPresent");
        let s = format!("{report}");
        assert!(s.contains("Static Triage Report"));
    }

    #[test]
    fn test_classify_features_empty() {
        let t = StaticAnalysisTriage::new();
        let report = t.classify_features(vec![]);
        assert_eq!(report.decision, TriageDecision::Benign);
    }

    #[test]
    fn test_classify_features_critical() {
        let t = StaticAnalysisTriage::new();
        let fw = FeatureWeight::new(
            StaticFeature::Dropper(DropperIndicator::EmbeddedPe),
            25,
            "test",
        ).critical();
        let report = t.classify_features(vec![fw]);
        assert!(report.score.is_malicious());
    }

    #[test]
    fn test_pe_anomaly_display() {
        assert!(PeAnomaly::InvalidTimestamp.to_string().contains("invalid timestamp"));
        assert!(PeAnomaly::HighEntropySection(".text".to_string()).to_string().contains(".text"));
    }

    #[test]
    fn test_dropper_indicator_display() {
        assert!(DropperIndicator::EmbeddedPe.to_string().contains("embedded PE"));
    }

    #[test]
    fn test_crypto_indicator_display() {
        assert!(CryptoIndicator::AesSbox.to_string().contains("AES"));
    }

    #[test]
    fn test_helpers_contains() {
        assert!(contains(b"hello world", b"world"));
        assert!(!contains(b"hello world", b"xyz"));
    }

    #[test]
    fn test_helpers_count_occurrences() {
        assert_eq!(count_occurrences(b"MZMZMZ", b"MZ"), 3);
    }

    #[test]
    fn test_helpers_looks_like_ipv4() {
        assert!(looks_like_ipv4("192.168.1.1"));
        assert!(!looks_like_ipv4("not.an.ip.addr.extra"));
        assert!(!looks_like_ipv4("999.999.999.999")); // parse::<u8> will fail
    }

    #[test]
    fn test_helpers_shannon_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_helpers_simple_hash_deterministic() {
        assert_eq!(simple_hash(b"hello"), simple_hash(b"hello"));
        assert_ne!(simple_hash(b"hello"), simple_hash(b"world"));
    }
}
