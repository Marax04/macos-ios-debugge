//! Sandbox analysis report generation.
//!
//! Aggregates all events from a sandbox run, classifies the behaviour
//! (ransomware / spyware / dropper / etc.) and emits a structured report.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::network_capture::NetworkCapture;
use crate::process_monitor::ProcessMonitor;
use crate::{BehaviorFlag, SandboxResult};

// ── BehaviorClassification ─────────────────────────────────────────────────────

/// Top-level malware family classification derived from observed behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MalwareFamily {
    Ransomware,
    Spyware,
    Dropper,
    Downloader,
    Trojan,
    Worm,
    Rootkit,
    Keylogger,
    BankingTrojan,
    Backdoor,
    Adware,
    Benign,
    Unknown,
}

impl std::fmt::Display for MalwareFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ransomware => "Ransomware",
            Self::Spyware => "Spyware",
            Self::Dropper => "Dropper",
            Self::Downloader => "Downloader",
            Self::Trojan => "Trojan",
            Self::Worm => "Worm",
            Self::Rootkit => "Rootkit",
            Self::Keylogger => "Keylogger",
            Self::BankingTrojan => "BankingTrojan",
            Self::Backdoor => "Backdoor",
            Self::Adware => "Adware",
            Self::Benign => "Benign",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

/// A single classification with a confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorClassification {
    /// Primary malware family guess.
    pub family: MalwareFamily,
    /// Confidence 0.0–1.0.
    pub confidence: f32,
    /// Supporting evidence strings.
    pub evidence: Vec<String>,
}

impl BehaviorClassification {
    const fn new(family: MalwareFamily, confidence: f32) -> Self {
        Self {
            family,
            confidence,
            evidence: Vec::new(),
        }
    }

    fn with_evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
}

// ── ThreatScore ────────────────────────────────────────────────────────────────

/// Detailed threat-score breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    /// Overall score 0–100.
    pub total: u32,
    /// Breakdown by category.
    pub components: HashMap<String, u32>,
}

impl ThreatScore {
    fn zero() -> Self {
        Self {
            total: 0,
            components: HashMap::new(),
        }
    }

    fn add(&mut self, category: impl Into<String>, points: u32) {
        let cat = category.into();
        let entry = self.components.entry(cat).or_insert(0);
        *entry += points;
        self.total = (self.total + points).min(100);
    }
}

// ── SandboxReport ─────────────────────────────────────────────────────────────

/// IOC bundle embedded in the report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportIocs {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub dropped_files: Vec<String>,
    pub registry_persistence: Vec<String>,
    pub mutexes: Vec<String>,
    pub c2_endpoints: Vec<String>,
}

/// Executive summary section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// One-paragraph summary.
    pub text: String,
    /// Whether the sample is considered malicious.
    pub verdict: Verdict,
    /// Threat score 0–100.
    pub score: u32,
    /// Primary classification.
    pub classification: String,
}

/// High-level verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Malicious,
    Suspicious,
    PotentiallyUnwanted,
    Benign,
    Unknown,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Malicious => "Malicious",
            Self::Suspicious => "Suspicious",
            Self::PotentiallyUnwanted => "PotentiallyUnwanted",
            Self::Benign => "Benign",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

/// A complete sandbox analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    /// Unique report identifier.
    pub report_id: String,
    /// Sample identifier (hash or path).
    pub sample_id: String,
    /// Analysis duration in milliseconds.
    pub duration_ms: u64,
    /// Executive summary.
    pub summary: ExecutiveSummary,
    /// Threat score breakdown.
    pub threat_score: ThreatScore,
    /// Behaviour classifications (ordered by confidence descending).
    pub classifications: Vec<BehaviorClassification>,
    /// Indicator-of-compromise collection.
    pub iocs: ReportIocs,
    /// Detailed behaviour flags.
    pub behavior_flags: Vec<String>,
    /// Raw log lines from the sandbox.
    pub log: Vec<String>,
    /// Per-section sub-reports.
    pub sections: HashMap<String, String>,
}

impl SandboxReport {
    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a string description of any serialization error.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Render a human-readable text report.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "=== Sandbox Analysis Report ===\n\
             Report ID  : {}\n\
             Sample     : {}\n\
             Duration   : {} ms\n\
             Verdict    : {}\n\
             Score      : {}/100\n\
             Class      : {}\n\n",
            self.report_id,
            self.sample_id,
            self.duration_ms,
            self.summary.verdict,
            self.summary.score,
            self.summary.classification
        );

        out.push_str("--- Summary ---\n");
        out.push_str(&self.summary.text);
        out.push_str("\n\n");

        out.push_str("--- Threat Score Breakdown ---\n");
        let mut components: Vec<(&String, &u32)> = self.threat_score.components.iter().collect();
        components.sort_by_key(|(k, _)| k.as_str());
        for (cat, pts) in &components {
            let _ = writeln!(out, "  {cat:<30} +{pts}");
        }
        out.push('\n');

        out.push_str("--- Classifications ---\n");
        for cls in &self.classifications {
            let _ = writeln!(
                out,
                "  {:<20} {:.1}%  {:?}",
                cls.family.to_string(),
                cls.confidence * 100.0,
                cls.evidence
            );
        }
        out.push('\n');

        out.push_str("--- Behaviour Flags ---\n");
        for flag in &self.behavior_flags {
            let _ = writeln!(out, "  - {flag}");
        }
        out.push('\n');

        if !self.iocs.ips.is_empty() || !self.iocs.domains.is_empty() {
            out.push_str("--- IOCs ---\n");
            for ip in &self.iocs.ips {
                let _ = writeln!(out, "  IP        : {ip}");
            }
            for d in &self.iocs.domains {
                let _ = writeln!(out, "  Domain    : {d}");
            }
            for u in &self.iocs.urls {
                let _ = writeln!(out, "  URL       : {u}");
            }
            for f in &self.iocs.dropped_files {
                let _ = writeln!(out, "  Dropped   : {f}");
            }
            for r in &self.iocs.registry_persistence {
                let _ = writeln!(out, "  Registry  : {r}");
            }
            out.push('\n');
        }

        out
    }
}

// ── ReportBuilder ─────────────────────────────────────────────────────────────

/// Counter used for deterministic report IDs in tests.
static REPORT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_report_id() -> String {
    let n = REPORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("report-{n:08x}")
}

/// Builder that compiles a `SandboxReport` from all available data sources.
pub struct ReportBuilder {
    sample_id: String,
    sandbox_result: Option<SandboxResult>,
    monitor: Option<ProcessMonitor>,
    network: Option<NetworkCapture>,
    extra_log: Vec<String>,
}

impl ReportBuilder {
    /// Create a new builder for the given sample.
    #[must_use]
    pub fn new(sample_id: impl Into<String>) -> Self {
        Self {
            sample_id: sample_id.into(),
            sandbox_result: None,
            monitor: None,
            network: None,
            extra_log: Vec::new(),
        }
    }

    /// Attach the core sandbox result.
    #[must_use]
    pub fn with_result(mut self, result: SandboxResult) -> Self {
        self.sandbox_result = Some(result);
        self
    }

    /// Attach a process monitor snapshot.
    #[must_use]
    pub fn with_monitor(mut self, monitor: ProcessMonitor) -> Self {
        self.monitor = Some(monitor);
        self
    }

    /// Attach a network capture snapshot.
    #[must_use]
    pub fn with_network(mut self, network: NetworkCapture) -> Self {
        self.network = Some(network);
        self
    }

    /// Add an extra log line.
    pub fn add_log(&mut self, msg: impl Into<String>) {
        self.extra_log.push(msg.into());
    }

    fn collect_from_sandbox_result(
        r: &SandboxResult,
        iocs: &mut ReportIocs,
        behavior_flags: &mut Vec<String>,
        log: &mut Vec<String>,
        duration_ms: &mut u64,
    ) -> BehaviorFlag {
        *duration_ms = r.duration_ms;
        log.extend(r.log.clone());
        if let Some(ref rec) = r.behavior_record {
            for net in &rec.network {
                if net.is_external() { iocs.ips.push(net.remote_addr.clone()); }
                if let Some(ref dns) = net.dns_query { iocs.domains.push(dns.clone()); }
            }
            for file in &rec.files {
                if file.is_dropper_op() { iocs.dropped_files.push(file.path.clone()); }
            }
            for reg in &rec.registry {
                if reg.is_persistence_op() { iocs.registry_persistence.push(reg.key.clone()); }
            }
        }
        for d in &r.behaviors.describe() { behavior_flags.push(d.to_string()); }
        r.behaviors
    }

    fn collect_from_monitor(
        mon: &crate::process_monitor::ProcessMonitor,
        iocs: &mut ReportIocs,
        threat_score: &mut ThreatScore,
        duration_ms: &mut u64,
    ) {
        let stats = mon.stats();
        if stats.suspicious_syscalls > 0 {
            let n = u32::try_from(stats.suspicious_syscalls).unwrap_or(u32::MAX);
            threat_score.add("injection", (n.saturating_mul(5)).min(25));
        }
        if stats.dropper_indicators > 0 {
            let n = u32::try_from(stats.dropper_indicators).unwrap_or(u32::MAX);
            threat_score.add("dropper", (n.saturating_mul(8)).min(20));
            iocs.dropped_files.extend(mon.dropper_indicators().iter().map(|f| f.path.clone()));
        }
        if stats.persistence_writes > 0 {
            let n = u32::try_from(stats.persistence_writes).unwrap_or(u32::MAX);
            threat_score.add("persistence", (n.saturating_mul(10)).min(20));
            iocs.registry_persistence.extend(mon.persistence_writes().iter().map(|r| r.key.clone()));
        }
        *duration_ms = (*duration_ms).max(stats.duration_ms);
    }

    fn collect_from_network(
        net: &crate::network_capture::NetworkCapture,
        iocs: &mut ReportIocs,
        threat_score: &mut ThreatScore,
    ) {
        let ns = net.stats();
        if ns.c2_suspects > 0 {
            let n = u32::try_from(ns.c2_suspects).unwrap_or(u32::MAX);
            threat_score.add("c2", (n.saturating_mul(15)).min(30));
            iocs.c2_endpoints.extend(net.c2_requests().iter().map(|r| r.url.clone()));
        }
        if ns.dga_suspects > 0 {
            let n = u32::try_from(ns.dga_suspects).unwrap_or(u32::MAX);
            threat_score.add("dga", (n.saturating_mul(5)).min(20));
        }
        if ns.external_connections > 3 { threat_score.add("network", 10); }
        iocs.ips.extend(net.unique_hosts());
    }

    /// Build the complete report.
    #[must_use]
    pub fn build(self) -> SandboxReport {
        let mut threat_score = ThreatScore::zero();
        let mut iocs = ReportIocs::default();
        let mut behavior_flags: Vec<String> = Vec::new();
        let mut log = self.extra_log;
        let mut duration_ms = 0u64;

        let flags = self.sandbox_result.as_ref().map_or_else(BehaviorFlag::empty, |r| {
            Self::collect_from_sandbox_result(r, &mut iocs, &mut behavior_flags, &mut log, &mut duration_ms)
        });

        if let Some(ref mon) = self.monitor {
            Self::collect_from_monitor(mon, &mut iocs, &mut threat_score, &mut duration_ms);
        }
        if let Some(ref net) = self.network {
            Self::collect_from_network(net, &mut iocs, &mut threat_score);
        }

        // ── Score from behavior flags ──────────────────────────────────────────
        if flags.contains(BehaviorFlag::INJECTION)    { threat_score.add("injection",    25); }
        if flags.contains(BehaviorFlag::ANTIANALYSIS) { threat_score.add("anti-analysis",15); }
        if flags.contains(BehaviorFlag::RANSOMWARE)   { threat_score.add("ransomware",   30); }
        if flags.contains(BehaviorFlag::ROOTKIT)      { threat_score.add("rootkit",      30); }
        if flags.contains(BehaviorFlag::KEYLOGGER)    { threat_score.add("keylogger",    20); }

        // Deduplicate IOCs
        iocs.ips.sort_unstable();         iocs.ips.dedup();
        iocs.domains.sort_unstable();     iocs.domains.dedup();
        iocs.dropped_files.sort_unstable(); iocs.dropped_files.dedup();
        iocs.registry_persistence.sort_unstable(); iocs.registry_persistence.dedup();

        let classifications = classify(flags, threat_score.total, &iocs);
        let primary_family = classifications.first().map_or(MalwareFamily::Unknown, |c| c.family.clone());
        let verdict = match threat_score.total {
            0..=9   => Verdict::Benign,
            10..=29 => Verdict::PotentiallyUnwanted,
            30..=59 => Verdict::Suspicious,
            _       => Verdict::Malicious,
        };
        let summary_text = build_summary_text(flags, threat_score.total, &primary_family, &verdict, &iocs);
        let summary = ExecutiveSummary {
            text: summary_text,
            verdict,
            score: threat_score.total,
            classification: primary_family.to_string(),
        };

        let mut sections = HashMap::new();
        sections.insert("behavior_flags".to_string(), behavior_flags.join(", "));
        if let Some(ref net) = self.network {
            let ns = net.stats();
            sections.insert(
                "network_summary".to_string(),
                format!("dns={} http={} https={} flows_tcp={} external={}",
                    ns.dns_queries, ns.http_requests, ns.https_requests, ns.tcp_flows, ns.external_connections),
            );
        }

        SandboxReport {
            report_id: next_report_id(),
            sample_id: self.sample_id,
            duration_ms,
            summary,
            threat_score,
            classifications,
            iocs,
            behavior_flags,
            log,
            sections,
        }
    }
}

fn classify(
    flags: BehaviorFlag,
    score: u32,
    iocs: &ReportIocs,
) -> Vec<BehaviorClassification> {
    let mut out = Vec::new();

    if flags.contains(BehaviorFlag::RANSOMWARE) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Ransomware, 0.95)
                .with_evidence("RANSOMWARE flag set")
                .with_evidence("crypto + file writes observed"),
        );
    }
    if flags.contains(BehaviorFlag::KEYLOGGER) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Keylogger, 0.90)
                .with_evidence("KEYLOGGER flag set"),
        );
    }
    if flags.contains(BehaviorFlag::ROOTKIT) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Rootkit, 0.92)
                .with_evidence("ROOTKIT flag set"),
        );
    }
    if flags.contains(BehaviorFlag::DROPPER) {
        let conf = if iocs.dropped_files.len() > 2 {
            0.88
        } else {
            0.70
        };
        out.push(
            BehaviorClassification::new(MalwareFamily::Dropper, conf)
                .with_evidence(format!("{} dropped files", iocs.dropped_files.len())),
        );
    }
    if flags.contains(BehaviorFlag::DOWNLOADER) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Downloader, 0.75)
                .with_evidence("DOWNLOADER + NETWORK flags"),
        );
    }
    if flags.contains(BehaviorFlag::INJECTION) && flags.contains(BehaviorFlag::C2) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Backdoor, 0.85)
                .with_evidence("injection + C2 communication"),
        );
    }
    if flags.contains(BehaviorFlag::WORM) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Worm, 0.80)
                .with_evidence("WORM flag set"),
        );
    }
    if flags.contains(BehaviorFlag::SCREENSHOT) && flags.contains(BehaviorFlag::NETWORK) {
        out.push(
            BehaviorClassification::new(MalwareFamily::Spyware, 0.78)
                .with_evidence("screenshot capture + network exfiltration"),
        );
    }

    // Fallback
    if out.is_empty() {
        if score > 0 {
            out.push(BehaviorClassification::new(MalwareFamily::Trojan, 0.40));
        } else {
            out.push(BehaviorClassification::new(MalwareFamily::Benign, 0.80));
        }
    }

    out.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    out
}

fn build_summary_text(
    flags: BehaviorFlag,
    score: u32,
    family: &MalwareFamily,
    verdict: &Verdict,
    iocs: &ReportIocs,
) -> String {
    let flag_names = flags.describe();
    let flag_str = if flag_names.is_empty() {
        "no notable behaviours".to_string()
    } else {
        flag_names.join(", ")
    };
    format!(
        "The sample was classified as {verdict} with a threat score of {score}/100. \
         Primary classification: {family}. \
         Observed behaviours: {flag_str}. \
         IOCs collected: {} IPs, {} domains, {} dropped files, {} persistence keys.",
        iocs.ips.len(),
        iocs.domains.len(),
        iocs.dropped_files.len(),
        iocs.registry_persistence.len()
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_builder_minimal() {
        let report = ReportBuilder::new("sample.exe").build();
        assert!(!report.report_id.is_empty());
        assert_eq!(report.sample_id, "sample.exe");
    }

    #[test]
    fn test_report_with_result() {
        let result = SandboxResult::mock();
        let report = ReportBuilder::new("malware.exe")
            .with_result(result)
            .build();
        assert!(report.threat_score.total > 0);
        assert!(!report.classifications.is_empty());
    }

    #[test]
    fn test_report_verdict_malicious() {
        let result = SandboxResult::mock();
        let report = ReportBuilder::new("x.exe").with_result(result).build();
        assert!(
            report.summary.verdict == Verdict::Malicious
                || report.summary.verdict == Verdict::Suspicious,
            "expected malicious/suspicious, got {:?}",
            report.summary.verdict
        );
    }

    #[test]
    fn test_report_benign_zero_score() {
        let report = ReportBuilder::new("clean.exe").build();
        assert_eq!(report.summary.verdict, Verdict::Benign);
        assert_eq!(report.threat_score.total, 0);
    }

    #[test]
    fn test_report_json_serializable() {
        let report = ReportBuilder::new("test.bin").build();
        let json = report.to_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("report_id"));
    }

    #[test]
    fn test_report_text_contains_verdict() {
        let result = SandboxResult::mock();
        let report = ReportBuilder::new("x.exe").with_result(result).build();
        let text = report.to_text();
        assert!(text.contains("Verdict") || text.contains("Score"));
    }

    #[test]
    fn test_classifications_sorted_by_confidence() {
        let result = SandboxResult::mock();
        let report = ReportBuilder::new("x.exe").with_result(result).build();
        let confs: Vec<f32> = report.classifications.iter().map(|c| c.confidence).collect();
        for w in confs.windows(2) {
            assert!(w[0] >= w[1]);
        }
    }

    #[test]
    fn test_ioc_deduplication() {
        let result = SandboxResult::mock();
        let mut builder = ReportBuilder::new("x.exe").with_result(result);
        builder.add_log("extra log");
        let report = builder.build();
        let mut ips = report.iocs.ips.clone();
        ips.sort_unstable();
        ips.dedup();
        assert_eq!(ips.len(), report.iocs.ips.len());
    }

    #[test]
    fn test_malware_family_display() {
        assert_eq!(MalwareFamily::Ransomware.to_string(), "Ransomware");
        assert_eq!(MalwareFamily::Benign.to_string(), "Benign");
    }

    #[test]
    fn test_threat_score_capped_at_100() {
        let mut ts = ThreatScore::zero();
        for _ in 0..20 {
            ts.add("test", 10);
        }
        assert_eq!(ts.total, 100);
    }
}
