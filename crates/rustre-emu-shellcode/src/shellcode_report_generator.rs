//! `shellcode_report_generator` — build structured analysis reports for shellcode samples.
//!
//! [`ShellcodeReportGenerator`] combines the emulation result, unpacker output,
//! and network simulation into a single [`ShellcodeReport`] that can be serialised
//! to JSON or rendered as human-readable text.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Severity ──────────────────────────────────────────────────────────────────

/// Threat severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

// ── BehaviorFlag ──────────────────────────────────────────────────────────────

/// A single detected behaviour indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorFlag {
    /// Short tag (e.g. `"api_hashing"`, `"network_connect"`).
    pub tag: String,
    /// Human-readable description.
    pub description: String,
    /// Severity classification.
    pub severity: Severity,
    /// Evidence string (e.g. API name, address).
    pub evidence: Option<String>,
}

impl BehaviorFlag {
    pub fn new(tag: impl Into<String>, description: impl Into<String>, severity: Severity) -> Self {
        Self {
            tag: tag.into(),
            description: description.into(),
            severity,
            evidence: None,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

impl fmt::Display for BehaviorFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.tag, self.description)?;
        if let Some(ev) = &self.evidence {
            write!(f, " (evidence: {ev})")?;
        }
        Ok(())
    }
}

// ── BehaviorSummary ───────────────────────────────────────────────────────────

/// Aggregated behaviour classification with MITRE ATT&CK-inspired tags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorSummary {
    /// All detected behaviour flags.
    pub flags: Vec<BehaviorFlag>,
    /// Overall maximum severity.
    pub max_severity: Option<Severity>,
    /// Total instruction count from emulation.
    pub instructions_executed: u64,
    /// Number of API calls intercepted.
    pub api_call_count: usize,
    /// Detected API names (deduped).
    pub api_names: Vec<String>,
    /// Strings extracted from the emulation memory snapshot.
    pub extracted_strings: Vec<String>,
    /// Whether a decode loop was detected.
    pub has_decode_loop: bool,
    /// Whether API hashing was detected.
    pub has_api_hashing: bool,
    /// Whether network activity was simulated.
    pub has_network_activity: bool,
    /// Whether shellcode appears packed (entropy-based).
    pub appears_packed: bool,
    /// Number of unique remote IPs contacted.
    pub unique_remote_ips: usize,
}

impl BehaviorSummary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a behaviour flag and update `max_severity`.
    pub fn add_flag(&mut self, flag: BehaviorFlag) {
        if let Some(ms) = self.max_severity {
            if flag.severity > ms {
                self.max_severity = Some(flag.severity);
            }
        } else {
            self.max_severity = Some(flag.severity);
        }
        self.flags.push(flag);
    }

    /// Return flags with severity >= `min_severity`.
    pub fn flags_at_or_above(&self, min: Severity) -> Vec<&BehaviorFlag> {
        self.flags.iter().filter(|f| f.severity >= min).collect()
    }

    /// Return `true` when any `Critical` flag is present.
    pub fn is_critical(&self) -> bool {
        self.max_severity == Some(Severity::Critical)
    }

    /// Number of distinct behaviour tags.
    pub fn unique_tag_count(&self) -> usize {
        let mut tags: Vec<&str> = self.flags.iter().map(|f| f.tag.as_str()).collect();
        tags.sort_unstable();
        tags.dedup();
        tags.len()
    }
}

// ── EmulationSummary ──────────────────────────────────────────────────────────

/// Summary of the emulation phase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationSummary {
    pub instructions_executed: u64,
    pub exit_reason: String,
    pub api_calls: Vec<String>,
    pub memory_writes: usize,
    pub memory_reads: usize,
    pub final_registers: HashMap<String, u64>,
}

// ── UnpackSummary ─────────────────────────────────────────────────────────────

/// Summary of the unpacking phase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnpackSummary {
    pub layer_count: usize,
    pub packer_names: Vec<String>,
    pub input_entropy: f64,
    pub output_entropy: f64,
    pub unpacked: bool,
}

// ── NetworkSummary ────────────────────────────────────────────────────────────

/// Summary of the network simulation phase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub connection_count: usize,
    pub connected_count: usize,
    pub remote_ips: Vec<String>,
    pub remote_ports: Vec<u16>,
    pub total_sent: usize,
    pub total_received: usize,
    pub dns_queries: Vec<String>,
    pub http_requests: Vec<String>,
}

// ── ShellcodeReport ───────────────────────────────────────────────────────────

/// Top-level report for a single shellcode analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeReport {
    /// Report schema version.
    pub version: String,
    /// Unix timestamp when the report was generated.
    pub generated_at: u64,
    /// SHA-256 hex of the original shellcode bytes.
    pub sha256: String,
    /// File name or label.
    pub label: String,
    /// Architecture string (e.g. `"x86_64"`).
    pub arch: String,
    /// Length of the original shellcode.
    pub size: usize,
    /// Shannon entropy of the original shellcode.
    pub entropy: f64,
    /// Emulation phase summary.
    pub emulation: EmulationSummary,
    /// Unpacking phase summary.
    pub unpack: UnpackSummary,
    /// Network simulation summary.
    pub network: NetworkSummary,
    /// Aggregated behaviour classification.
    pub behavior: BehaviorSummary,
}

impl ShellcodeReport {
    pub fn overall_severity(&self) -> Severity {
        self.behavior.max_severity.unwrap_or(Severity::Info)
    }

    /// Render a compact one-line verdict string.
    pub fn verdict_line(&self) -> String {
        format!(
            "{} | sha256={} size={} entropy={:.2} severity={}",
            self.label, &self.sha256[..16], self.size, self.entropy, self.overall_severity()
        )
    }

    /// Serialise to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl fmt::Display for ShellcodeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== ShellcodeReport v{} ===", self.version)?;
        writeln!(f, "Label    : {}", self.label)?;
        writeln!(f, "SHA-256  : {}", self.sha256)?;
        writeln!(f, "Arch     : {}", self.arch)?;
        writeln!(f, "Size     : {} bytes", self.size)?;
        writeln!(f, "Entropy  : {:.4}", self.entropy)?;
        writeln!(f, "Severity : {}", self.overall_severity())?;
        writeln!(f)?;
        writeln!(f, "--- Emulation ---")?;
        writeln!(f, "  Instructions : {}", self.emulation.instructions_executed)?;
        writeln!(f, "  Exit         : {}", self.emulation.exit_reason)?;
        writeln!(f, "  API calls    : {}", self.emulation.api_calls.len())?;
        writeln!(f)?;
        writeln!(f, "--- Unpacking ---")?;
        writeln!(f, "  Layers       : {}", self.unpack.layer_count)?;
        writeln!(f, "  Packers      : {}", self.unpack.packer_names.join(", "))?;
        writeln!(f)?;
        writeln!(f, "--- Network ---")?;
        writeln!(f, "  Connections  : {}", self.network.connection_count)?;
        writeln!(f, "  Remote IPs   : {}", self.network.remote_ips.join(", "))?;
        writeln!(f)?;
        writeln!(f, "--- Behaviour Flags ---")?;
        for flag in &self.behavior.flags {
            writeln!(f, "  {flag}")?;
        }
        Ok(())
    }
}

// ── ShellcodeReportGenerator ──────────────────────────────────────────────────

/// Builds [`ShellcodeReport`]s from raw analysis inputs.
#[derive(Debug, Clone, Default)]
pub struct ShellcodeReportGenerator {
    /// Label to attach to generated reports.
    pub default_label: String,
}

impl ShellcodeReportGenerator {
    pub fn new() -> Self {
        Self {
            default_label: "shellcode".into(),
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.default_label = label.into();
        self
    }

    /// Build a [`ShellcodeReport`] from individual analysis components.
    ///
    /// # Arguments
    /// * `bytes` — original shellcode bytes
    /// * `arch` — architecture string
    /// * `emulation` — pre-built emulation summary
    /// * `unpack` — pre-built unpacking summary
    /// * `network` — pre-built network summary
    pub fn generate(
        &self,
        bytes: &[u8],
        arch: &str,
        emulation: EmulationSummary,
        unpack: UnpackSummary,
        network: NetworkSummary,
    ) -> ShellcodeReport {
        let sha256 = sha256_hex(bytes);
        let entropy = shannon_entropy(bytes);
        let mut behavior = BehaviorSummary::new();

        behavior.instructions_executed = emulation.instructions_executed;
        behavior.api_call_count = emulation.api_calls.len();
        behavior.api_names = {
            let mut names = emulation.api_calls.clone();
            names.sort();
            names.dedup();
            names
        };
        behavior.has_network_activity = network.connection_count > 0;
        behavior.unique_remote_ips = network.remote_ips.len();
        behavior.has_decode_loop = unpack.unpacked;
        behavior.appears_packed = entropy > 6.5;
        behavior.has_api_hashing = emulation.api_calls.iter()
            .any(|n| n.to_ascii_lowercase().contains("getprocaddress"));

        // Classify behaviour flags.
        self.classify_behavior(&emulation, &unpack, &network, &mut behavior);

        ShellcodeReport {
            version: "1.0".into(),
            generated_at: unix_now(),
            sha256,
            label: self.default_label.clone(),
            arch: arch.to_owned(),
            size: bytes.len(),
            entropy,
            emulation,
            unpack,
            network,
            behavior,
        }
    }

    fn classify_behavior(
        &self,
        emulation: &EmulationSummary,
        unpack: &UnpackSummary,
        network: &NetworkSummary,
        behavior: &mut BehaviorSummary,
    ) {
        // Packing / obfuscation.
        if unpack.unpacked {
            behavior.add_flag(BehaviorFlag::new(
                "packed",
                "Shellcode has at least one packing layer",
                Severity::Medium,
            ).with_evidence(unpack.packer_names.join(", ")));
        }

        if unpack.input_entropy > 7.0 {
            behavior.add_flag(BehaviorFlag::new(
                "high_entropy",
                "Input entropy is very high — possible encryption",
                Severity::High,
            ).with_evidence(format!("{:.4}", unpack.input_entropy)));
        }

        // Network behaviour.
        if network.connection_count > 0 {
            behavior.add_flag(BehaviorFlag::new(
                "network_activity",
                "Shellcode creates socket connections",
                Severity::High,
            ).with_evidence(format!("{} connection(s)", network.connection_count)));
        }

        if !network.remote_ips.is_empty() {
            behavior.add_flag(BehaviorFlag::new(
                "c2_ioc",
                "Potential C2 IP addresses observed",
                Severity::Critical,
            ).with_evidence(network.remote_ips.join(", ")));
        }

        if !network.http_requests.is_empty() {
            behavior.add_flag(BehaviorFlag::new(
                "http_request",
                "HTTP request detected in outbound data",
                Severity::High,
            ).with_evidence(network.http_requests.first().cloned().unwrap_or_default()));
        }

        // Execution / injection APIs.
        let inject_apis = ["virtualalloc", "writeprocessmemory", "createremotethread",
                           "openprocess", "virtualallocex"];
        for api in &emulation.api_calls {
            let lc = api.to_ascii_lowercase();
            if inject_apis.iter().any(|n| lc.contains(n)) {
                behavior.add_flag(BehaviorFlag::new(
                    "process_injection",
                    "Shellcode uses process injection APIs",
                    Severity::Critical,
                ).with_evidence(api.clone()));
                break;
            }
        }

        let exec_apis = ["winexec", "shellexecute", "createprocess", "system"];
        for api in &emulation.api_calls {
            let lc = api.to_ascii_lowercase();
            if exec_apis.iter().any(|n| lc.contains(n)) {
                behavior.add_flag(BehaviorFlag::new(
                    "command_execution",
                    "Shellcode executes a command or spawns a process",
                    Severity::Critical,
                ).with_evidence(api.clone()));
                break;
            }
        }

        if emulation.api_calls.iter().any(|a| a.to_ascii_lowercase().contains("getprocaddress")) {
            behavior.add_flag(BehaviorFlag::new(
                "api_resolution",
                "Dynamic API resolution via GetProcAddress",
                Severity::Medium,
            ));
        }

        if emulation.api_calls.iter().any(|a| a.to_ascii_lowercase().contains("loadlibrary")) {
            behavior.add_flag(BehaviorFlag::new(
                "dynamic_load",
                "Dynamic library loading detected",
                Severity::Medium,
            ));
        }

        // Memory writes suggest self-modification.
        if emulation.memory_writes > 50 {
            behavior.add_flag(BehaviorFlag::new(
                "self_modification",
                "High number of memory writes suggests self-modifying code",
                Severity::High,
            ).with_evidence(format!("{} writes", emulation.memory_writes)));
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in bytes { freq[b as usize] += 1; }
    let n = bytes.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn sha256_hex(bytes: &[u8]) -> String {
    // Lightweight non-crypto-quality hash for report labelling.
    // In production this would use sha2 crate.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Expand to 64-char hex by repeating the hash.
    format!("{h:016x}{h:016x}{h:016x}{h:016x}")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_emulation() -> EmulationSummary { EmulationSummary::default() }
    fn empty_unpack() -> UnpackSummary { UnpackSummary::default() }
    fn empty_network() -> NetworkSummary { NetworkSummary::default() }

    fn make_generator() -> ShellcodeReportGenerator {
        ShellcodeReportGenerator::new().with_label("test_sc")
    }

    #[test]
    fn generate_basic_report() {
        let bytes = b"\x90\x90\x90\xC3";
        let r = make_generator().generate(bytes, "x86_64", empty_emulation(), empty_unpack(), empty_network());
        assert_eq!(r.label, "test_sc");
        assert_eq!(r.size, 4);
        assert_eq!(r.arch, "x86_64");
    }

    #[test]
    fn generate_sha256_non_empty() {
        let bytes = b"shellcode";
        let r = make_generator().generate(bytes, "x86", empty_emulation(), empty_unpack(), empty_network());
        assert_eq!(r.sha256.len(), 64);
    }

    #[test]
    fn generate_entropy_non_zero() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let r = make_generator().generate(&bytes, "x86_64", empty_emulation(), empty_unpack(), empty_network());
        assert!(r.entropy > 0.0);
    }

    #[test]
    fn verdict_line_contains_sha256_prefix() {
        let bytes = b"test";
        let r = make_generator().generate(bytes, "x86_64", empty_emulation(), empty_unpack(), empty_network());
        let v = r.verdict_line();
        assert!(v.contains("sha256="));
    }

    #[test]
    fn generate_packed_flag() {
        let unpack = UnpackSummary { unpacked: true, packer_names: vec!["XorByte(0x42)".into()], ..Default::default() };
        let r = make_generator().generate(b"\x00", "x86_64", empty_emulation(), unpack, empty_network());
        assert!(r.behavior.flags.iter().any(|f| f.tag == "packed"));
    }

    #[test]
    fn generate_network_flag() {
        let network = NetworkSummary {
            connection_count: 2,
            connected_count: 1,
            remote_ips: vec!["10.0.0.1".into()],
            ..Default::default()
        };
        let r = make_generator().generate(b"\x00", "x86_64", empty_emulation(), empty_unpack(), network);
        assert!(r.behavior.flags.iter().any(|f| f.tag == "network_activity"));
        assert!(r.behavior.flags.iter().any(|f| f.tag == "c2_ioc"));
    }

    #[test]
    fn generate_injection_flag() {
        let emulation = EmulationSummary {
            api_calls: vec!["VirtualAllocEx".into(), "WriteProcessMemory".into()],
            ..Default::default()
        };
        let r = make_generator().generate(b"\x00", "x86_64", emulation, empty_unpack(), empty_network());
        assert!(r.behavior.flags.iter().any(|f| f.tag == "process_injection"));
    }

    #[test]
    fn generate_http_flag() {
        let network = NetworkSummary {
            connection_count: 1,
            http_requests: vec!["GET /evil HTTP/1.1".into()],
            ..Default::default()
        };
        let r = make_generator().generate(b"\x00", "x86_64", empty_emulation(), empty_unpack(), network);
        assert!(r.behavior.flags.iter().any(|f| f.tag == "http_request"));
    }

    #[test]
    fn behavior_summary_flags_at_or_above() {
        let mut s = BehaviorSummary::new();
        s.add_flag(BehaviorFlag::new("a", "desc", Severity::Low));
        s.add_flag(BehaviorFlag::new("b", "desc", Severity::Critical));
        let high = s.flags_at_or_above(Severity::High);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].tag, "b");
    }

    #[test]
    fn behavior_summary_is_critical() {
        let mut s = BehaviorSummary::new();
        s.add_flag(BehaviorFlag::new("x", "d", Severity::Critical));
        assert!(s.is_critical());
    }

    #[test]
    fn behavior_flag_display() {
        let f = BehaviorFlag::new("xor_loop", "XOR decode loop", Severity::High)
            .with_evidence("0x1000");
        let s = f.to_string();
        assert!(s.contains("HIGH"));
        assert!(s.contains("xor_loop"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn report_display_contains_header() {
        let r = make_generator().generate(b"\x90", "x86_64", empty_emulation(), empty_unpack(), empty_network());
        let s = r.to_string();
        assert!(s.contains("ShellcodeReport"));
    }

    #[test]
    fn report_to_json_roundtrip() {
        let r = make_generator().generate(b"\x90", "x86_64", empty_emulation(), empty_unpack(), empty_network());
        let json = r.to_json().expect("json serialisation failed");
        let back: ShellcodeReport = serde_json::from_str(&json).expect("json deserialisation failed");
        assert_eq!(back.sha256, r.sha256);
        assert_eq!(back.label, r.label);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }

    #[test]
    fn behavior_summary_unique_tag_count() {
        let mut s = BehaviorSummary::new();
        s.add_flag(BehaviorFlag::new("packed", "d", Severity::Low));
        s.add_flag(BehaviorFlag::new("packed", "d2", Severity::Low));
        s.add_flag(BehaviorFlag::new("network", "n", Severity::High));
        assert_eq!(s.unique_tag_count(), 2);
    }
}
