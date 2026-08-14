//! Complete binary analysis result aggregation.
//!
//! `BinaryAnalysisReport` aggregates all pass results into a single structure
//! covering security risks, crypto usage, network behaviour, individual findings,
//! and an overall `AnalysisScore`.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisFinding
// ─────────────────────────────────────────────────────────────────────────────

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// Category of a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    Security,
    Crypto,
    Network,
    StringAnalysis,
    TypeRecovery,
    BehaviourPattern,
    Custom(String),
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Security => write!(f, "security"),
            Self::Crypto => write!(f, "crypto"),
            Self::Network => write!(f, "network"),
            Self::StringAnalysis => write!(f, "string_analysis"),
            Self::TypeRecovery => write!(f, "type_recovery"),
            Self::BehaviourPattern => write!(f, "behaviour_pattern"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

/// A single analysis finding.
#[derive(Debug, Clone)]
pub struct AnalysisFinding {
    /// Short unique code (e.g., "SEC-001").
    pub code: String,
    pub severity: Severity,
    pub category: FindingCategory,
    /// Human-readable description.
    pub description: String,
    /// Virtual address of the offending code, if applicable.
    pub address: Option<u64>,
    /// Related function name or symbol.
    pub function: Option<String>,
    /// Evidence / context strings.
    pub evidence: Vec<String>,
}

impl AnalysisFinding {
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        severity: Severity,
        category: FindingCategory,
        description: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            category,
            description: description.into(),
            address: None,
            function: None,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub const fn at(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn in_func(mut self, name: impl Into<String>) -> Self {
        self.function = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }

    /// Whether this finding is at or above `min_severity`.
    #[must_use]
    pub fn is_at_least(&self, min_severity: Severity) -> bool {
        self.severity >= min_severity
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityRisk
// ─────────────────────────────────────────────────────────────────────────────

/// Category of a security risk.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RiskKind {
    BufferOverflow,
    FormatString,
    IntegerOverflow,
    UseAfterFree,
    NullDeref,
    InsecureCrypto,
    HardcodedSecret,
    CommandInjection,
    Custom(String),
}

impl fmt::Display for RiskKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BufferOverflow => "buffer_overflow",
            Self::FormatString => "format_string",
            Self::IntegerOverflow => "integer_overflow",
            Self::UseAfterFree => "use_after_free",
            Self::NullDeref => "null_deref",
            Self::InsecureCrypto => "insecure_crypto",
            Self::HardcodedSecret => "hardcoded_secret",
            Self::CommandInjection => "command_injection",
            Self::Custom(s) => s,
        };
        f.write_str(s)
    }
}

/// A security risk found in the binary.
#[derive(Debug, Clone)]
pub struct SecurityRisk {
    pub kind: RiskKind,
    pub severity: Severity,
    pub address: u64,
    pub description: String,
    pub cwe: Option<u32>,
    pub cvss: Option<f32>,
}

impl SecurityRisk {
    #[must_use]
    pub fn new(
        kind: RiskKind,
        severity: Severity,
        address: u64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            severity,
            address,
            description: description.into(),
            cwe: None,
            cvss: None,
        }
    }

    #[must_use]
    pub const fn with_cwe(mut self, cwe: u32) -> Self {
        self.cwe = Some(cwe);
        self
    }

    #[must_use]
    pub const fn with_cvss(mut self, cvss: f32) -> Self {
        self.cvss = Some(cvss);
        self
    }

    /// Whether this risk has a CVSS score above `threshold`.
    #[must_use]
    pub fn is_high_cvss(&self, threshold: f32) -> bool {
        self.cvss.is_some_and(|s| s >= threshold)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CryptoUsage
// ─────────────────────────────────────────────────────────────────────────────

/// A detected cryptographic algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    Aes,
    Des,
    TripleDes,
    Rc4,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Rsa,
    Ecc,
    ChaCha20,
    Xor,
    Custom(String),
}

impl fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Aes => "AES",
            Self::Des => "DES",
            Self::TripleDes => "3DES",
            Self::Rc4 => "RC4",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Rsa => "RSA",
            Self::Ecc => "ECC",
            Self::ChaCha20 => "ChaCha20",
            Self::Xor => "XOR",
            Self::Custom(s) => s,
        };
        f.write_str(s)
    }
}

/// Evidence of cryptographic algorithm use.
#[derive(Debug, Clone)]
pub struct CryptoUsage {
    pub algorithm: CryptoAlgorithm,
    pub address: u64,
    pub key_size_bits: Option<u32>,
    pub is_insecure: bool,
    pub evidence: Vec<String>,
}

impl CryptoUsage {
    #[must_use]
    pub const fn new(algorithm: CryptoAlgorithm, address: u64) -> Self {
        let is_insecure = matches!(
            algorithm,
            CryptoAlgorithm::Des
                | CryptoAlgorithm::Md5
                | CryptoAlgorithm::Sha1
                | CryptoAlgorithm::Rc4
                | CryptoAlgorithm::Xor
        );
        Self {
            algorithm,
            address,
            key_size_bits: None,
            is_insecure,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_key_size(mut self, bits: u32) -> Self {
        self.key_size_bits = Some(bits);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkBehavior
// ─────────────────────────────────────────────────────────────────────────────

/// Observed network-related behaviour.
#[derive(Debug, Clone)]
pub struct NetworkBehavior {
    /// Protocol or API name (e.g. "TCP", "HTTP", "DNS").
    pub protocol: String,
    /// Hardcoded hostname or IP, if present.
    pub endpoint: Option<String>,
    /// Port, if determinable.
    pub port: Option<u16>,
    /// Whether TLS/SSL is used.
    pub is_encrypted: bool,
    /// Function addresses involved in network activity.
    pub related_funcs: Vec<u64>,
}

impl NetworkBehavior {
    #[must_use]
    pub fn new(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            endpoint: None,
            port: None,
            is_encrypted: false,
            related_funcs: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_endpoint(mut self, ep: impl Into<String>) -> Self {
        self.endpoint = Some(ep.into());
        self
    }

    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    #[must_use]
    pub const fn encrypted(mut self) -> Self {
        self.is_encrypted = true;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisScore
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate quality/risk score for a binary analysis.
#[derive(Debug, Clone, Default)]
pub struct AnalysisScore {
    /// Overall risk score 0–100 (higher = riskier).
    pub risk_score: u32,
    /// Security-specific score 0–100.
    pub security_score: u32,
    /// Completeness of the analysis 0–100.
    pub completeness: u32,
    /// Confidence in the results 0–100.
    pub confidence: u32,
    /// Per-category scores.
    pub category_scores: HashMap<String, u32>,
}

impl AnalysisScore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute score from counts of high/medium/low severity findings.
    #[must_use]
    pub fn from_findings(findings: &[AnalysisFinding]) -> Self {
        let critical = u32::try_from(findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()).unwrap_or(u32::MAX);
        let high = u32::try_from(findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count()).unwrap_or(u32::MAX);
        let medium = u32::try_from(findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count()).unwrap_or(u32::MAX);
        let risk = (critical * 20 + high * 10 + medium * 5).min(100);
        let completeness = if findings.is_empty() { 0 } else { 70 };
        Self {
            risk_score: risk,
            security_score: risk,
            completeness,
            confidence: 75,
            category_scores: HashMap::new(),
        }
    }

    /// Set a per-category score.
    pub fn set_category_score(&mut self, category: impl Into<String>, score: u32) {
        self.category_scores.insert(category.into(), score);
    }

    /// Whether the overall risk exceeds `threshold`.
    #[must_use]
    pub const fn is_high_risk(&self, threshold: u32) -> bool {
        self.risk_score >= threshold
    }

    /// Overall letter grade (A–F).
    #[must_use]
    pub const fn grade(&self) -> char {
        match self.risk_score {
            0..=10 => 'A',
            11..=30 => 'B',
            31..=50 => 'C',
            51..=70 => 'D',
            _ => 'F',
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryAnalysisReport
// ─────────────────────────────────────────────────────────────────────────────

/// The complete output of a full binary analysis run.
#[derive(Debug, Clone)]
pub struct BinaryAnalysisReport {
    /// URI / path of the analysed binary.
    pub binary_uri: String,
    /// MD5/SHA-256 hash of the binary (hex string).
    pub hash: Option<String>,
    /// Detected architecture string.
    pub arch: Option<String>,
    /// Detected OS/ABI.
    pub os: Option<String>,
    /// All analysis findings.
    pub findings: Vec<AnalysisFinding>,
    /// Detected security risks.
    pub security_risks: Vec<SecurityRisk>,
    /// Detected cryptographic usages.
    pub crypto_usages: Vec<CryptoUsage>,
    /// Detected network behaviours.
    pub network_behaviors: Vec<NetworkBehavior>,
    /// Aggregate score.
    pub score: AnalysisScore,
    /// Per-pass metadata (pass name → duration ms).
    pub pass_durations: HashMap<String, u64>,
    /// Warnings emitted during analysis.
    pub warnings: Vec<String>,
    /// Whether the analysis completed without errors.
    pub success: bool,
}

impl BinaryAnalysisReport {
    /// Create an empty report for the given binary URI.
    #[must_use]
    pub fn new(binary_uri: impl Into<String>) -> Self {
        Self {
            binary_uri: binary_uri.into(),
            hash: None,
            arch: None,
            os: None,
            findings: Vec::new(),
            security_risks: Vec::new(),
            crypto_usages: Vec::new(),
            network_behaviors: Vec::new(),
            score: AnalysisScore::new(),
            pass_durations: HashMap::new(),
            warnings: Vec::new(),
            success: true,
        }
    }

    /// Add a finding.
    pub fn add_finding(&mut self, f: AnalysisFinding) {
        self.findings.push(f);
    }

    /// Add a security risk.
    pub fn add_risk(&mut self, r: SecurityRisk) {
        self.security_risks.push(r);
    }

    /// Add a crypto usage.
    pub fn add_crypto(&mut self, c: CryptoUsage) {
        self.crypto_usages.push(c);
    }

    /// Add a network behaviour.
    pub fn add_network(&mut self, n: NetworkBehavior) {
        self.network_behaviors.push(n);
    }

    /// Record pass duration.
    pub fn record_pass(&mut self, name: impl Into<String>, duration_ms: u64) {
        self.pass_durations.insert(name.into(), duration_ms);
    }

    /// Recompute the score from the current findings.
    pub fn recompute_score(&mut self) {
        self.score = AnalysisScore::from_findings(&self.findings);
    }

    /// All findings with severity >= `min`.
    #[must_use]
    pub fn findings_at_least(&self, min: Severity) -> Vec<&AnalysisFinding> {
        self.findings
            .iter()
            .filter(|f| f.is_at_least(min))
            .collect()
    }

    /// All findings in a given `category`.
    #[must_use]
    pub fn findings_by_category(&self, category: &FindingCategory) -> Vec<&AnalysisFinding> {
        self.findings
            .iter()
            .filter(|f| &f.category == category)
            .collect()
    }

    /// Whether the report contains any critical findings.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// All insecure crypto usages.
    #[must_use]
    pub fn insecure_crypto(&self) -> Vec<&CryptoUsage> {
        self.crypto_usages
            .iter()
            .filter(|c| c.is_insecure)
            .collect()
    }

    /// All unencrypted network behaviours.
    #[must_use]
    pub fn unencrypted_network(&self) -> Vec<&NetworkBehavior> {
        self.network_behaviors
            .iter()
            .filter(|n| !n.is_encrypted)
            .collect()
    }

    /// Total pass duration across all passes.
    #[must_use]
    pub fn total_duration_ms(&self) -> u64 {
        self.pass_durations.values().sum()
    }

    /// Summary one-liner.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: {} findings, {} risks, {} crypto, {} network | score={} grade={}",
            self.binary_uri,
            self.findings.len(),
            self.security_risks.len(),
            self.crypto_usages.len(),
            self.network_behaviors.len(),
            self.score.risk_score,
            self.score.grade(),
        )
    }

    /// Number of distinct functions mentioned across all findings.
    #[must_use]
    pub fn affected_function_count(&self) -> usize {
        let mut funcs: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for f in &self.findings {
            if let Some(func) = f.function.as_deref() {
                funcs.insert(func);
            }
        }
        funcs.len()
    }

    /// Export a JSON-like string for tooling integration.
    #[must_use]
    pub fn to_json_summary(&self) -> String {
        format!(
            r#"{{"uri":"{}","findings":{},"risks":{},"score":{},"grade":"{}","success":{}}}"#,
            self.binary_uri,
            self.findings.len(),
            self.security_risks.len(),
            self.score.risk_score,
            self.score.grade(),
            self.success,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn info_finding(code: &str) -> AnalysisFinding {
        AnalysisFinding::new(code, Severity::Info, FindingCategory::Security, "test")
    }

    fn critical_finding(code: &str) -> AnalysisFinding {
        AnalysisFinding::new(
            code,
            Severity::Critical,
            FindingCategory::Security,
            "critical",
        )
    }

    // 1. BinaryAnalysisReport::new
    #[test]
    fn test_report_new() {
        let r = BinaryAnalysisReport::new("test.bin");
        assert_eq!(r.binary_uri, "test.bin");
        assert!(r.findings.is_empty());
        assert!(r.success);
    }

    // 2. add_finding
    #[test]
    fn test_add_finding() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_finding(info_finding("I-001"));
        assert_eq!(r.findings.len(), 1);
    }

    // 3. add_risk
    #[test]
    fn test_add_risk() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_risk(SecurityRisk::new(
            RiskKind::BufferOverflow,
            Severity::High,
            0x1000,
            "bof",
        ));
        assert_eq!(r.security_risks.len(), 1);
    }

    // 4. add_crypto
    #[test]
    fn test_add_crypto() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_crypto(CryptoUsage::new(CryptoAlgorithm::Aes, 0x2000));
        assert_eq!(r.crypto_usages.len(), 1);
    }

    // 5. add_network
    #[test]
    fn test_add_network() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_network(NetworkBehavior::new("TCP"));
        assert_eq!(r.network_behaviors.len(), 1);
    }

    // 6. recompute_score
    #[test]
    fn test_recompute_score() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_finding(critical_finding("C-001"));
        r.recompute_score();
        assert!(r.score.risk_score > 0);
    }

    // 7. findings_at_least filters
    #[test]
    fn test_findings_at_least() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_finding(info_finding("I-001"));
        r.add_finding(critical_finding("C-001"));
        let high = r.findings_at_least(Severity::High);
        assert_eq!(high.len(), 1);
    }

    // 8. has_critical
    #[test]
    fn test_has_critical() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        assert!(!r.has_critical());
        r.add_finding(critical_finding("C-001"));
        assert!(r.has_critical());
    }

    // 9. insecure_crypto
    #[test]
    fn test_insecure_crypto() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_crypto(CryptoUsage::new(CryptoAlgorithm::Md5, 0x1000));
        r.add_crypto(CryptoUsage::new(CryptoAlgorithm::Aes, 0x2000));
        assert_eq!(r.insecure_crypto().len(), 1);
    }

    // 10. unencrypted_network
    #[test]
    fn test_unencrypted_network() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_network(NetworkBehavior::new("HTTP").with_port(80));
        r.add_network(NetworkBehavior::new("HTTPS").with_port(443).encrypted());
        assert_eq!(r.unencrypted_network().len(), 1);
    }

    // 11. total_duration_ms
    #[test]
    fn test_total_duration() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.record_pass("pass_a", 100);
        r.record_pass("pass_b", 200);
        assert_eq!(r.total_duration_ms(), 300);
    }

    // 12. summary contains binary uri
    #[test]
    fn test_summary() {
        let r = BinaryAnalysisReport::new("malware.exe");
        let s = r.summary();
        assert!(s.contains("malware.exe"));
    }

    // 13. to_json_summary is valid-ish JSON
    #[test]
    fn test_json_summary() {
        let r = BinaryAnalysisReport::new("test.bin");
        let j = r.to_json_summary();
        assert!(j.starts_with('{'));
        assert!(j.ends_with('}'));
    }

    // 14. affected_function_count
    #[test]
    fn test_affected_function_count() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_finding(info_finding("I-001").in_func("main"));
        r.add_finding(info_finding("I-002").in_func("main"));
        r.add_finding(info_finding("I-003").in_func("init"));
        assert_eq!(r.affected_function_count(), 2);
    }

    // 15. AnalysisFinding::at
    #[test]
    fn test_finding_at() {
        let f = info_finding("I-001").at(0x4000);
        assert_eq!(f.address, Some(0x4000));
    }

    // 16. AnalysisFinding::in_func
    #[test]
    fn test_finding_in_func() {
        let f = info_finding("I-001").in_func("printf");
        assert_eq!(f.function.as_deref(), Some("printf"));
    }

    // 17. AnalysisFinding is_at_least
    #[test]
    fn test_finding_is_at_least() {
        let f = AnalysisFinding::new("H-001", Severity::High, FindingCategory::Security, "high");
        assert!(f.is_at_least(Severity::Medium));
        assert!(!f.is_at_least(Severity::Critical));
    }

    // 18. Severity ordering
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    // 19. Severity Display
    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    // 20. SecurityRisk with_cwe
    #[test]
    fn test_risk_with_cwe() {
        let r = SecurityRisk::new(RiskKind::BufferOverflow, Severity::High, 0, "bof").with_cwe(120);
        assert_eq!(r.cwe, Some(120));
    }

    // 21. SecurityRisk with_cvss
    #[test]
    fn test_risk_with_cvss() {
        let r = SecurityRisk::new(RiskKind::FormatString, Severity::High, 0, "fmt").with_cvss(8.5);
        assert!(r.is_high_cvss(7.0));
        assert!(!r.is_high_cvss(9.0));
    }

    // 22. CryptoAlgorithm Display
    #[test]
    fn test_crypto_algo_display() {
        assert_eq!(CryptoAlgorithm::Aes.to_string(), "AES");
        assert_eq!(CryptoAlgorithm::Sha256.to_string(), "SHA-256");
        assert_eq!(CryptoAlgorithm::Rc4.to_string(), "RC4");
    }

    // 23. CryptoUsage insecure detection
    #[test]
    fn test_crypto_insecure() {
        assert!(CryptoUsage::new(CryptoAlgorithm::Md5, 0).is_insecure);
        assert!(CryptoUsage::new(CryptoAlgorithm::Rc4, 0).is_insecure);
        assert!(!CryptoUsage::new(CryptoAlgorithm::Aes, 0).is_insecure);
    }

    // 24. CryptoUsage with_key_size
    #[test]
    fn test_crypto_key_size() {
        let c = CryptoUsage::new(CryptoAlgorithm::Aes, 0x1000).with_key_size(256);
        assert_eq!(c.key_size_bits, Some(256));
    }

    // 25. NetworkBehavior builder
    #[test]
    fn test_network_builder() {
        let n = NetworkBehavior::new("HTTP")
            .with_endpoint("evil.example.com")
            .with_port(8080)
            .encrypted();
        assert_eq!(n.endpoint.as_deref(), Some("evil.example.com"));
        assert_eq!(n.port, Some(8080));
        assert!(n.is_encrypted);
    }

    // 26. AnalysisScore grade A
    #[test]
    fn test_score_grade_a() {
        let s = AnalysisScore {
            risk_score: 5,
            ..Default::default()
        };
        assert_eq!(s.grade(), 'A');
    }

    // 27. AnalysisScore grade F
    #[test]
    fn test_score_grade_f() {
        let s = AnalysisScore {
            risk_score: 90,
            ..Default::default()
        };
        assert_eq!(s.grade(), 'F');
    }

    // 28. AnalysisScore is_high_risk
    #[test]
    fn test_score_high_risk() {
        let s = AnalysisScore {
            risk_score: 60,
            ..Default::default()
        };
        assert!(s.is_high_risk(50));
        assert!(!s.is_high_risk(70));
    }

    // 29. AnalysisScore::from_findings zero findings
    #[test]
    fn test_score_from_empty() {
        let s = AnalysisScore::from_findings(&[]);
        assert_eq!(s.risk_score, 0);
        assert_eq!(s.completeness, 0);
    }

    // 30. AnalysisScore::from_findings critical findings
    #[test]
    fn test_score_from_critical() {
        let findings = vec![critical_finding("C-001"), critical_finding("C-002")];
        let s = AnalysisScore::from_findings(&findings);
        assert!(s.risk_score >= 40);
    }

    // 31. AnalysisScore set_category_score
    #[test]
    fn test_score_category() {
        let mut s = AnalysisScore::new();
        s.set_category_score("crypto", 80);
        assert_eq!(s.category_scores["crypto"], 80);
    }

    // 32. findings_by_category
    #[test]
    fn test_findings_by_category() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.add_finding(AnalysisFinding::new(
            "C-001",
            Severity::Info,
            FindingCategory::Crypto,
            "c",
        ));
        r.add_finding(info_finding("S-001"));
        let crypto = r.findings_by_category(&FindingCategory::Crypto);
        assert_eq!(crypto.len(), 1);
    }

    // 33. RiskKind Display
    #[test]
    fn test_risk_kind_display() {
        assert_eq!(RiskKind::BufferOverflow.to_string(), "buffer_overflow");
        assert_eq!(RiskKind::FormatString.to_string(), "format_string");
    }

    // 34. FindingCategory Display
    #[test]
    fn test_finding_category_display() {
        assert_eq!(FindingCategory::Security.to_string(), "security");
        assert_eq!(FindingCategory::Custom("x".into()).to_string(), "custom:x");
    }

    // 35. AnalysisFinding evidence
    #[test]
    fn test_finding_evidence() {
        let f = info_finding("I-001").with_evidence("found at 0x1000");
        assert_eq!(f.evidence.len(), 1);
    }

    // 36. Report with arch and os
    #[test]
    fn test_report_arch_os() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.arch = Some("x86_64".into());
        r.os = Some("Linux".into());
        assert_eq!(r.arch.as_deref(), Some("x86_64"));
    }

    // 37. Report with hash
    #[test]
    fn test_report_hash() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.hash = Some("deadbeef".into());
        assert_eq!(r.hash.as_deref(), Some("deadbeef"));
    }

    // 38. Record pass duration
    #[test]
    fn test_record_pass_duration() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.record_pass("cfg_analysis", 42);
        assert_eq!(r.pass_durations["cfg_analysis"], 42);
    }

    // 39. Report warnings
    #[test]
    fn test_report_warnings() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        r.warnings.push("unknown jump table".into());
        assert_eq!(r.warnings.len(), 1);
    }

    // 40. AnalysisScore default is zero
    #[test]
    fn test_score_default() {
        let s = AnalysisScore::default();
        assert_eq!(s.risk_score, 0);
        assert!(s.category_scores.is_empty());
    }

    // 41. summary grade is A for clean binary
    #[test]
    fn test_summary_grade_a() {
        let r = BinaryAnalysisReport::new("clean.bin");
        let s = r.summary();
        assert!(s.contains("grade=A"));
    }

    // 42. Report success flag
    #[test]
    fn test_report_success_flag() {
        let mut r = BinaryAnalysisReport::new("test.bin");
        assert!(r.success);
        r.success = false;
        assert!(!r.success);
        assert!(r.to_json_summary().contains("false"));
    }
}
