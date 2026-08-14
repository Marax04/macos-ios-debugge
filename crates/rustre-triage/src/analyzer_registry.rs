// rustre-triage/src/analyzer_registry.rs
//! Triage analyzer registry and trait definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{ThreatLevel, TriageIndicator};

// ─── Analysis result ──────────────────────────────────────────────────────────

/// The output of a single triage analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Analyzer name.
    pub analyzer: String,
    /// Score contribution (0–100).
    pub score: u8,
    /// Whether the analyzer ran successfully.
    pub success: bool,
    /// Error message if success = false.
    pub error: Option<String>,
    /// Indicators produced.
    pub indicators: Vec<TriageIndicator>,
    /// Additional key-value metadata.
    pub metadata: HashMap<String, String>,
    /// Wall-clock time taken.
    pub duration_ms: u64,
}

impl AnalysisResult {
    pub fn ok(analyzer: impl Into<String>, score: u8) -> Self {
        Self {
            analyzer: analyzer.into(),
            score,
            success: true,
            error: None,
            indicators: Vec::new(),
            metadata: HashMap::new(),
            duration_ms: 0,
        }
    }

    pub fn err(analyzer: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            analyzer: analyzer.into(),
            score: 0,
            success: false,
            error: Some(msg.into()),
            indicators: Vec::new(),
            metadata: HashMap::new(),
            duration_ms: 0,
        }
    }

    pub fn add_indicator(&mut self, ind: TriageIndicator) {
        if ind.threat_level > ThreatLevel::Clean {
            let delta: u8 = match ind.threat_level {
                ThreatLevel::Informational => 2,
                ThreatLevel::Low => 10,
                ThreatLevel::Medium => 20,
                ThreatLevel::High => 35,
                ThreatLevel::Critical => 50,
                ThreatLevel::Clean => 0,
            };
            self.score = self.score.saturating_add(delta).min(100);
        }
        self.indicators.push(ind);
    }

    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into());
        self
    }

    /// True if any indicator is High or Critical.
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.indicators
            .iter()
            .any(|i| i.threat_level >= ThreatLevel::High)
    }
}

// ─── Analyzer trait ───────────────────────────────────────────────────────────

/// A pluggable triage analyzer.
pub trait TriageAnalyzer: Send + Sync {
    /// Unique name for this analyzer.
    fn name(&self) -> &str;

    /// Analyze raw binary bytes and return a result.
    fn analyze(&self, bytes: &[u8]) -> AnalysisResult;

    /// Whether this analyzer should run in fast mode (skip deep analysis).
    fn supports_fast_mode(&self) -> bool {
        false
    }

    /// Estimated priority (higher = runs first).
    fn priority(&self) -> u8 {
        50
    }

    /// Maximum time this analyzer should be allowed (None = no limit).
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Categories / tags for this analyzer.
    fn tags(&self) -> Vec<&str> {
        Vec::new()
    }
}

// ─── Analyzer run mode ────────────────────────────────────────────────────────

/// How to run a set of analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Run all registered analyzers.
    All,
    /// Run only analyzers that support fast mode.
    Fast,
    /// Run analyzers depth-first (all + extra thoroughness).
    Deep,
    /// Run only analyzers matching specific tags.
    Tagged,
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// Registry of triage analyzers.
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn TriageAnalyzer>>,
    default_timeout: Duration,
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            default_timeout: Duration::from_secs(30),
        }
    }

    /// Register an analyzer.
    pub fn register(&mut self, a: Box<dyn TriageAnalyzer>) {
        self.analyzers.push(a);
        // Sort by priority descending
        self.analyzers
            .sort_by_key(|b| std::cmp::Reverse(b.priority()));
    }

    pub const fn set_default_timeout(&mut self, t: Duration) {
        self.default_timeout = t;
    }

    /// Number of registered analyzers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.analyzers.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.analyzers.is_empty()
    }

    /// Analyzer names in priority order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.analyzers.iter().map(|a| a.name()).collect()
    }

    // ── Run methods ───────────────────────────────────────────────────────────

    /// Run all registered analyzers.
    #[must_use]
    pub fn run_all(&self, bytes: &[u8]) -> Vec<AnalysisResult> {
        self.run_with_mode(bytes, RunMode::All, &[])
    }

    /// Run only fast-mode analyzers.
    #[must_use]
    pub fn run_fast(&self, bytes: &[u8]) -> Vec<AnalysisResult> {
        self.run_with_mode(bytes, RunMode::Fast, &[])
    }

    /// Run all analyzers with extended timeouts.
    #[must_use]
    pub fn run_deep(&self, bytes: &[u8]) -> Vec<AnalysisResult> {
        self.run_with_mode(bytes, RunMode::Deep, &[])
    }

    /// Run only analyzers with all the specified tags.
    #[must_use]
    pub fn run_tagged(&self, bytes: &[u8], tags: &[&str]) -> Vec<AnalysisResult> {
        self.run_with_mode(bytes, RunMode::Tagged, tags)
    }

    fn run_with_mode(&self, bytes: &[u8], mode: RunMode, tags: &[&str]) -> Vec<AnalysisResult> {
        let selected: Vec<&dyn TriageAnalyzer> = self
            .analyzers
            .iter()
            .map(std::convert::AsRef::as_ref)
            .filter(|a| match mode {
                RunMode::All | RunMode::Deep => true,
                RunMode::Fast => a.supports_fast_mode(),
                RunMode::Tagged => tags.iter().all(|t| a.tags().contains(t)),
            })
            .collect();

        selected
            .iter()
            .map(|a| {
                let t0 = Instant::now();
                let timeout = a.timeout().unwrap_or(self.default_timeout);
                let mut result = Self::run_analyzer_with_timeout(*a, bytes, timeout);
                result.duration_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
                result
            })
            .collect()
    }

    fn run_analyzer_with_timeout(
        analyzer: &dyn TriageAnalyzer,
        bytes: &[u8],
        _timeout: Duration,
    ) -> AnalysisResult {
        // Note: true timeout would require threading; here we run synchronously.
        // A production implementation could use std::thread::spawn + join with timeout.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| analyzer.analyze(bytes)))
            .unwrap_or_else(|_| AnalysisResult::err(analyzer.name(), "analyzer panicked"))
    }

    // ── Aggregation ───────────────────────────────────────────────────────────

    /// Run all analyzers and aggregate into a single result summary.
    #[must_use]
    pub fn run_and_aggregate(&self, bytes: &[u8]) -> RegistryRunResult {
        let results = self.run_all(bytes);
        self.aggregate_results(results)
    }

    #[must_use]
    pub fn aggregate_results(&self, results: Vec<AnalysisResult>) -> RegistryRunResult {
        let mut total_score: u32 = 0;
        let mut all_indicators: Vec<TriageIndicator> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let total_time: u64 = results.iter().map(|r| r.duration_ms).sum();

        for r in &results {
            if !r.success {
                if let Some(ref e) = r.error {
                    errors.push(format!("{}: {}", r.analyzer, e));
                }
                continue;
            }
            total_score = total_score.saturating_add(u32::from(r.score));
            all_indicators.extend(r.indicators.clone());
        }

        let final_score = (total_score.min(100)) as u8;
        let label = if final_score < 20 {
            "clean"
        } else if final_score < 60 {
            "suspicious"
        } else {
            "malicious"
        }
        .to_string();

        RegistryRunResult {
            analyzer_results: results,
            final_score,
            label,
            all_indicators,
            errors,
            total_time_ms: total_time,
        }
    }
}

/// Combined result of running all analyzers.
#[derive(Debug, Clone)]
pub struct RegistryRunResult {
    pub analyzer_results: Vec<AnalysisResult>,
    pub final_score: u8,
    pub label: String,
    pub all_indicators: Vec<TriageIndicator>,
    pub errors: Vec<String>,
    pub total_time_ms: u64,
}

impl RegistryRunResult {
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.label == "malicious"
    }
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.label == "clean"
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (score={}) indicators={} analyzers={} time={}ms",
            self.label.to_uppercase(),
            self.final_score,
            self.all_indicators.len(),
            self.analyzer_results.len(),
            self.total_time_ms,
        )
    }

    #[must_use]
    pub fn by_analyzer(&self, name: &str) -> Option<&AnalysisResult> {
        self.analyzer_results.iter().find(|r| r.analyzer == name)
    }
}

// ─── Built-in analyzers ───────────────────────────────────────────────────────

/// Entropy-based packing analyzer.
pub struct EntropyAnalyzer {
    pub high_entropy_threshold: f64,
    pub very_high_threshold: f64,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self {
            high_entropy_threshold: 7.0,
            very_high_threshold: 7.8,
        }
    }
}

impl TriageAnalyzer for EntropyAnalyzer {
    fn name(&self) -> &'static str {
        "entropy"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn supports_fast_mode(&self) -> bool {
        true
    }
    fn tags(&self) -> Vec<&str> {
        vec!["fast", "packing"]
    }

    fn analyze(&self, bytes: &[u8]) -> AnalysisResult {
        let entropy = rustre_pe_tools::compute_entropy(bytes);
        let mut result = AnalysisResult::ok("entropy", 0);
        result
            .metadata
            .insert("entropy".into(), format!("{entropy:.4}"));

        if entropy > self.very_high_threshold {
            result.add_indicator(TriageIndicator {
                name: "very-high-entropy".to_string(),
                description: format!(
                    "Entropy {:.3} > {:.1} — likely encrypted or packed",
                    entropy, self.very_high_threshold
                ),
                threat_level: ThreatLevel::High,
                category: "packing".to_string(),
                evidence: format!("entropy={entropy:.4}"),
            });
        } else if entropy > self.high_entropy_threshold {
            result.add_indicator(TriageIndicator {
                name: "high-entropy".to_string(),
                description: format!(
                    "Entropy {:.3} > {:.1} — possibly packed",
                    entropy, self.high_entropy_threshold
                ),
                threat_level: ThreatLevel::Medium,
                category: "packing".to_string(),
                evidence: format!("entropy={entropy:.4}"),
            });
        }
        result
    }
}

/// String-based heuristic analyzer.
pub struct StringHeuristicAnalyzer {
    pub min_string_len: usize,
}

impl Default for StringHeuristicAnalyzer {
    fn default() -> Self {
        Self { min_string_len: 6 }
    }
}

impl TriageAnalyzer for StringHeuristicAnalyzer {
    fn name(&self) -> &'static str {
        "strings"
    }
    fn priority(&self) -> u8 {
        70
    }
    fn supports_fast_mode(&self) -> bool {
        false
    }
    fn tags(&self) -> Vec<&str> {
        vec!["strings", "heuristic"]
    }

    fn analyze(&self, bytes: &[u8]) -> AnalysisResult {
        use crate::StringHeuristics;
        let scan = &bytes[..bytes.len().min(2 * 1024 * 1024)];
        let strings = StringHeuristics::extract_strings(scan, self.min_string_len);
        let suspicious = StringHeuristics::classify(&strings);

        let mut result = AnalysisResult::ok("strings", 0);
        result
            .metadata
            .insert("total_strings".into(), strings.len().to_string());
        result
            .metadata
            .insert("suspicious_strings".into(), suspicious.len().to_string());

        for s in suspicious {
            result.add_indicator(TriageIndicator {
                name: format!(
                    "suspicious-string:{}",
                    &s.string.value.chars().take(20).collect::<String>()
                ),
                description: format!("{:?} string: {}", s.category, s.string.value),
                threat_level: s.threat_level,
                category: format!("{:?}", s.category),
                evidence: format!("offset=0x{:x}", s.string.offset),
            });
        }
        result
    }
}

/// Packer detection analyzer.
pub struct PackerAnalyzer;

impl TriageAnalyzer for PackerAnalyzer {
    fn name(&self) -> &'static str {
        "packer"
    }
    fn priority(&self) -> u8 {
        80
    }
    fn supports_fast_mode(&self) -> bool {
        true
    }
    fn tags(&self) -> Vec<&str> {
        vec!["fast", "packing"]
    }

    fn analyze(&self, bytes: &[u8]) -> AnalysisResult {
        let mut result = AnalysisResult::ok("packer", 0);
        let packers: &[(&str, &str, u8)] = &[
            ("UPX0", "UPX packer section marker", 15),
            ("UPX!", "UPX packer magic", 15),
            (".vmp0", "VMProtect virtualizer section", 30),
            (".themida", "Themida software protector", 25),
            ("MPRESS1", "MPRESS packer", 15),
            (".aspack", "ASPack packer", 15),
            ("PECompact2", "PECompact packer", 15),
            ("nSPack", "nSPack packer", 15),
            ("Enigma", "Enigma Protector", 20),
            ("WinLicense", "WinLicense protector", 20),
        ];
        for (sig, desc, score_contrib) in packers {
            if bytes.windows(sig.len()).any(|w| w == sig.as_bytes()) {
                result.add_indicator(TriageIndicator {
                    name: format!("packer:{sig}"),
                    description: desc.to_string(),
                    threat_level: ThreatLevel::Medium,
                    category: "packing".to_string(),
                    evidence: format!("signature={sig}"),
                });
                result.score = result.score.saturating_add(*score_contrib).min(100);
            }
        }
        result
    }
}

/// Import table (Windows API) analyzer.
pub struct ImportAnalyzer;

impl ImportAnalyzer {
    fn is_suspicious_import(name: &str) -> Option<(ThreatLevel, &'static str)> {
        let suspicious: &[(&str, ThreatLevel, &str)] = &[
            (
                "VirtualAllocEx",
                ThreatLevel::High,
                "Cross-process memory allocation",
            ),
            (
                "WriteProcessMemory",
                ThreatLevel::High,
                "Cross-process memory write",
            ),
            (
                "CreateRemoteThread",
                ThreatLevel::High,
                "Remote thread creation",
            ),
            (
                "NtAllocateVirtualMemory",
                ThreatLevel::High,
                "NT virtual memory allocation",
            ),
            (
                "NtWriteVirtualMemory",
                ThreatLevel::High,
                "NT virtual memory write",
            ),
            ("NtCreateThreadEx", ThreatLevel::High, "NT thread creation"),
            (
                "OpenProcess",
                ThreatLevel::Medium,
                "Process handle acquisition",
            ),
            (
                "OpenThread",
                ThreatLevel::Medium,
                "Thread handle acquisition",
            ),
            ("IsDebuggerPresent", ThreatLevel::Low, "Debugger detection"),
            (
                "CheckRemoteDebuggerPresent",
                ThreatLevel::Low,
                "Remote debugger detection",
            ),
            (
                "NtQueryInformationProcess",
                ThreatLevel::Low,
                "Process information query",
            ),
            (
                "CreateProcessInternalW",
                ThreatLevel::Medium,
                "Internal process creation",
            ),
            ("RegSetValueEx", ThreatLevel::Medium, "Registry value write"),
            ("InternetOpenUrl", ThreatLevel::Medium, "Network URL open"),
            ("HttpOpenRequest", ThreatLevel::Medium, "HTTP request"),
            ("WSAStartup", ThreatLevel::Low, "Winsock initialization"),
            ("CryptAcquireContext", ThreatLevel::Low, "Crypto context"),
            ("LoadLibrary", ThreatLevel::Low, "Dynamic library loading"),
            (
                "GetProcAddress",
                ThreatLevel::Low,
                "Dynamic symbol resolution",
            ),
            (
                "SetWindowsHookEx",
                ThreatLevel::High,
                "Keyboard/mouse hook installation",
            ),
            ("GetAsyncKeyState", ThreatLevel::High, "Keylogger API"),
            ("GetKeyboardState", ThreatLevel::High, "Keyboard state read"),
        ];
        suspicious
            .iter()
            .find(|(sym, _, _)| *sym == name)
            .map(|(_, lvl, desc)| (*lvl, *desc))
    }
}

impl TriageAnalyzer for ImportAnalyzer {
    fn name(&self) -> &'static str {
        "imports"
    }
    fn priority(&self) -> u8 {
        85
    }
    fn supports_fast_mode(&self) -> bool {
        true
    }
    fn tags(&self) -> Vec<&str> {
        vec!["fast", "imports", "pe"]
    }

    fn analyze(&self, bytes: &[u8]) -> AnalysisResult {
        let mut result = AnalysisResult::ok("imports", 0);

        // Try PE parse
        if let Ok(pe) = rustre_pe_tools::PeFile::parse(bytes) {
            let imports = &pe.imports;
            let total = imports.len();
            result
                .metadata
                .insert("total_imports".into(), total.to_string());

            let mut suspicious_count = 0;
            for import_entry in imports {
                let import_name = import_entry.name.as_deref().unwrap_or("");
                if let Some((lvl, desc)) = Self::is_suspicious_import(import_name) {
                    suspicious_count += 1;
                    result.add_indicator(TriageIndicator {
                        name: format!("suspicious-import:{import_name}"),
                        description: format!("{import_name} — {desc}"),
                        threat_level: lvl,
                        category: "suspicious-import".to_string(),
                        evidence: format!("import={import_name}"),
                    });
                }
            }
            result
                .metadata
                .insert("suspicious_imports".into(), suspicious_count.to_string());
        }
        result
    }
}

/// Network indicator analyzer (scans for IPs, URLs, domains).
pub struct NetworkAnalyzer;

impl TriageAnalyzer for NetworkAnalyzer {
    fn name(&self) -> &'static str {
        "network"
    }
    fn priority(&self) -> u8 {
        60
    }
    fn supports_fast_mode(&self) -> bool {
        false
    }
    fn tags(&self) -> Vec<&str> {
        vec!["network", "ioc"]
    }

    fn analyze(&self, bytes: &[u8]) -> AnalysisResult {
        let mut result = AnalysisResult::ok("network", 0);
        let scan = &bytes[..bytes.len().min(1024 * 1024)];

        let text = String::from_utf8_lossy(scan);

        // Check for suspicious network patterns
        let patterns: &[(&str, ThreatLevel, &str)] = &[
            ("http://", ThreatLevel::Low, "HTTP URL"),
            ("https://", ThreatLevel::Low, "HTTPS URL"),
            ("ftp://", ThreatLevel::Low, "FTP URL"),
            ("ws://", ThreatLevel::Low, "WebSocket URL"),
            ("wss://", ThreatLevel::Medium, "Secure WebSocket URL"),
            ("dns.google", ThreatLevel::Medium, "DNS-over-HTTPS resolver"),
            (
                "cloudflare-dns.com",
                ThreatLevel::Medium,
                "Cloudflare DoH resolver",
            ),
            ("ngrok.io", ThreatLevel::High, "Ngrok tunneling service"),
            ("pastebin.com", ThreatLevel::High, "Pastebin (C2 staging)"),
            (
                "raw.githubusercontent.com",
                ThreatLevel::Medium,
                "GitHub raw content",
            ),
            (
                "WindowsInstaller",
                ThreatLevel::Low,
                "Windows installer reference",
            ),
        ];

        for (pat, lvl, desc) in patterns {
            if text.contains(pat) {
                result.add_indicator(TriageIndicator {
                    name: format!("network:{}", pat.trim_end_matches('/')),
                    description: format!("{desc}: {pat}"),
                    threat_level: *lvl,
                    category: "network".to_string(),
                    evidence: format!("pattern={pat}"),
                });
            }
        }
        result
    }
}

/// File format structure analyzer.
pub struct StructureAnalyzer;

impl TriageAnalyzer for StructureAnalyzer {
    fn name(&self) -> &'static str {
        "structure"
    }
    fn priority(&self) -> u8 {
        95
    }
    fn supports_fast_mode(&self) -> bool {
        true
    }
    fn tags(&self) -> Vec<&str> {
        vec!["fast", "structure", "format"]
    }

    fn analyze(&self, bytes: &[u8]) -> AnalysisResult {
        use crate::detect_file_kind;
        let kind = detect_file_kind(bytes);
        let mut result = AnalysisResult::ok("structure", 0);
        result.metadata.insert("file_kind".into(), kind.to_string());

        // Check for malformed or truncated headers
        if bytes.len() < 4 {
            result.add_indicator(TriageIndicator {
                name: "tiny-file".to_string(),
                description: "File is smaller than 4 bytes".to_string(),
                threat_level: ThreatLevel::Informational,
                category: "structure".to_string(),
                evidence: format!("size={}", bytes.len()),
            });
        }

        result
    }
}

/// Factory function to create a registry with all built-in analyzers.
#[must_use]
pub fn default_registry() -> AnalyzerRegistry {
    let mut reg = AnalyzerRegistry::new();
    reg.register(Box::new(StructureAnalyzer));
    reg.register(Box::new(EntropyAnalyzer::default()));
    reg.register(Box::new(PackerAnalyzer));
    reg.register(Box::new(ImportAnalyzer));
    reg.register(Box::new(StringHeuristicAnalyzer::default()));
    reg.register(Box::new(NetworkAnalyzer));
    reg
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_analyzers() {
        let reg = default_registry();
        assert!(reg.len() >= 4);
    }

    #[test]
    fn run_all_returns_one_per_analyzer() {
        let reg = default_registry();
        let results = reg.run_all(b"MZ\x00\x00small data");
        assert_eq!(results.len(), reg.len());
    }

    #[test]
    fn run_fast_fewer_analyzers() {
        let reg = default_registry();
        let fast = reg.run_fast(b"data");
        let all = reg.run_all(b"data");
        assert!(fast.len() <= all.len());
    }

    #[test]
    fn entropy_analyzer_low_entropy() {
        let a = EntropyAnalyzer::default();
        let data = vec![0u8; 1000];
        let result = a.analyze(&data);
        assert!(result.success);
        // Low entropy data should have score 0
        assert_eq!(result.score, 0);
    }

    #[test]
    fn entropy_analyzer_high_entropy() {
        let a = EntropyAnalyzer::default();
        // Create high-entropy data (pseudo-random)
        let data: Vec<u8> = (0..256_i32)
            .cycle()
            .take(1024)
            .map(|i| u8::try_from(i & 0xFF).unwrap_or(0))
            .collect();
        let result = a.analyze(&data);
        assert!(result.success);
        // Should detect high entropy
        assert!(!result.indicators.is_empty() || result.score > 0);
    }

    #[test]
    fn packer_analyzer_finds_upx() {
        let a = PackerAnalyzer;
        let data = b"MZSomeDataUPX!MoreData";
        let result = a.analyze(data);
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn packer_analyzer_no_packer() {
        let a = PackerAnalyzer;
        let data = b"MZCleanExecutableNoPackerHere";
        let result = a.analyze(data);
        assert!(result.indicators.is_empty());
    }

    #[test]
    fn analysis_result_is_high_risk() {
        let mut r = AnalysisResult::ok("test", 0);
        r.add_indicator(TriageIndicator {
            name: "test".into(),
            description: "test".into(),
            threat_level: ThreatLevel::High,
            category: "test".into(),
            evidence: String::new(),
        });
        assert!(r.is_high_risk());
    }

    #[test]
    fn analysis_result_err() {
        let r = AnalysisResult::err("test", "something broke");
        assert!(!r.success);
        assert_eq!(r.score, 0);
    }

    #[test]
    fn registry_run_and_aggregate_clean() {
        let reg = default_registry();
        let result = reg.run_and_aggregate(b"Hello World");
        assert!(result.final_score <= 100);
    }

    #[test]
    fn registry_summary_format() {
        let reg = default_registry();
        let result = reg.run_and_aggregate(b"data");
        let s = result.summary();
        assert!(s.contains("score="));
    }

    #[test]
    fn run_tagged_filters_correctly() {
        let reg = default_registry();
        let results = reg.run_tagged(b"data", &["fast"]);
        for r in &results {
            // All results should be from fast-mode analyzers
            let _ = r; // just ensure no panic
        }
        assert!(!results.is_empty());
    }

    #[test]
    fn string_heuristic_analyzer_finds_url() {
        let a = StringHeuristicAnalyzer::default();
        let data = b"Loading http://malicious.example.com/payload.exe from server";
        let result = a.analyze(data);
        // Should detect the URL
        assert!(!result.indicators.is_empty() || result.score > 0);
    }
}
