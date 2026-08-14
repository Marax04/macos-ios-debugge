//! Normalize sandbox reports from multiple vendors to a common format.
//!
//! Supports Cuckoo, `AnyRun`, Triage.io, Joe Sandbox, Hybrid-Analysis,
//! and `VirusTotal` Behavior reports.

use std::collections::HashMap;

/// Tally how many times each `FileOp` appears across `events`. Useful when
/// downstream code needs to score a report by activity mix (e.g. mostly
/// `Write` + `Delete` strongly suggests a ransomware payload).
#[must_use]
pub fn file_op_histogram(events: &[NormalizedFileEvent]) -> HashMap<FileOp, usize> {
    let mut hist: HashMap<FileOp, usize> = HashMap::new();
    for ev in events {
        *hist.entry(ev.operation.clone()).or_insert(0) += 1;
    }
    hist
}

/// Tally how many times each `RegOp` appears across `events`.
#[must_use]
pub fn reg_op_histogram(events: &[NormalizedRegistryEvent]) -> HashMap<RegOp, usize> {
    let mut hist: HashMap<RegOp, usize> = HashMap::new();
    for ev in events {
        *hist.entry(ev.operation.clone()).or_insert(0) += 1;
    }
    hist
}
use serde_json::Value;

// ─── ReportSource ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportSource {
    Cuckoo,
    AnyRun,
    TriageIo,
    JoeSandbox,
    HybridAnalysis,
    VirustotalBehavior,
}

impl std::fmt::Display for ReportSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Cuckoo => "Cuckoo",
            Self::AnyRun => "AnyRun",
            Self::TriageIo => "Triage.io",
            Self::JoeSandbox => "Joe Sandbox",
            Self::HybridAnalysis => "Hybrid Analysis",
            Self::VirustotalBehavior => "VirusTotal Behavior",
        };
        write!(f, "{s}")
    }
}

// ─── Verdict ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
}

impl Verdict {
    #[must_use] 
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Unknown => 1,
            Self::Suspicious => 2,
            Self::Malicious => 3,
        }
    }

    #[must_use] 
    pub fn from_score(score: f64) -> Self {
        if score >= 7.0 { Self::Malicious }
        else if score >= 4.0 { Self::Suspicious }
        else if score > 0.0 { Self::Suspicious }
        else { Self::Clean }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Clean => "Clean",
            Self::Suspicious => "Suspicious",
            Self::Malicious => "Malicious",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── NormalizedProcess ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NormalizedProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: String,
    pub injected: bool,
    pub hollowed: bool,
}

// ─── NormalizedNetworkEvent ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NormalizedNetworkEvent {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub data_size: u64,
    pub dns_query: Option<String>,
}

// ─── FileOp / NormalizedFileEvent ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileOp {
    Create,
    Write,
    Read,
    Delete,
    Move,
    Copy,
    Chmod,
    Unknown,
}

impl FileOp {
    /// Parse a free-form sandbox report verb (e.g. `"CreateFile"`, `"write"`,
    /// `"renamefile"`) into the canonical `FileOp` taxonomy. Sandbox vendors
    /// emit wildly varying spellings; this is the single place we normalize.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "create" | "createfile" | "created" => Self::Create,
            "write" | "writefile" | "written" => Self::Write,
            "read" | "readfile" => Self::Read,
            "delete" | "deletefile" | "deleted" => Self::Delete,
            "move" | "movefile" | "rename" | "renamefile" => Self::Move,
            "copy" | "copyfile" => Self::Copy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedFileEvent {
    pub path: String,
    pub operation: FileOp,
    pub size: u64,
    pub sha256: Option<String>,
}

// ─── RegOp / NormalizedRegistryEvent ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegOp {
    Create,
    Set,
    Delete,
    Query,
    Unknown,
}

impl RegOp {
    /// Parse a free-form registry verb (`"RegSetValue"`, `"created"`, ...) into
    /// the canonical `RegOp` taxonomy. Public so external normalizers can
    /// reuse the same vendor-agnostic mapping.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "create" | "regcreatekey" | "created" => Self::Create,
            "set" | "regsetvalue" | "written" => Self::Set,
            "delete" | "regdeletekey" | "regdeletevalue" => Self::Delete,
            "query" | "regqueryvalue" | "regquerykey" => Self::Query,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedRegistryEvent {
    pub key: String,
    pub value: String,
    pub data: String,
    pub operation: RegOp,
}

// ─── NormalizedSignature ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NormalizedSignature {
    pub name: String,
    /// Severity 0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical.
    pub severity: u8,
    pub description: String,
    pub mitre_attack: Vec<String>,
}

// ─── NormalizedReport ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct NormalizedReport {
    pub sha256: String,
    pub filename: String,
    pub file_type: String,
    pub analysis_duration_s: u32,
    pub verdict: Verdict,
    pub processes: Vec<NormalizedProcess>,
    pub network: Vec<NormalizedNetworkEvent>,
    pub files: Vec<NormalizedFileEvent>,
    pub registry: Vec<NormalizedRegistryEvent>,
    pub signatures: Vec<NormalizedSignature>,
    pub source: ReportSource,
    pub raw_score: Option<f64>,
    pub tags: Vec<String>,
}

impl NormalizedReport {
    const fn empty(source: ReportSource) -> Self {
        Self {
            sha256: String::new(),
            filename: String::new(),
            file_type: String::new(),
            analysis_duration_s: 0,
            verdict: Verdict::Unknown,
            processes: Vec::new(),
            network: Vec::new(),
            files: Vec::new(),
            registry: Vec::new(),
            signatures: Vec::new(),
            source,
            raw_score: None,
            tags: Vec::new(),
        }
    }

    /// Summary line for quick display.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} sha256={} verdict={} procs={} net={} files={} sigs={}",
            self.source,
            self.filename,
            if self.sha256.is_empty() { "?" } else { &self.sha256[..8.min(self.sha256.len())] },
            self.verdict,
            self.processes.len(),
            self.network.len(),
            self.files.len(),
            self.signatures.len(),
        )
    }

    /// Check if any signature name matches a keyword.
    #[must_use] 
    pub fn has_signature_containing(&self, keyword: &str) -> bool {
        let kw = keyword.to_lowercase();
        self.signatures.iter().any(|s| s.name.to_lowercase().contains(&kw) || s.description.to_lowercase().contains(&kw))
    }

    /// Unique destination IPs from network events.
    #[must_use] 
    pub fn unique_dst_ips(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.network.iter().filter_map(|e| {
            if !e.dst_ip.is_empty() && seen.insert(e.dst_ip.as_str()) { Some(e.dst_ip.as_str()) } else { None }
        }).collect()
    }

    /// All DNS queries (non-empty `dns_query` fields).
    #[must_use] 
    pub fn dns_queries(&self) -> Vec<&str> {
        self.network.iter().filter_map(|e| e.dns_query.as_deref()).collect()
    }
}

// ─── SandboxReportNormalizer ──────────────────────────────────────────────────

pub struct SandboxReportNormalizer;

impl SandboxReportNormalizer {
    #[must_use] 
    pub const fn new() -> Self { Self }

    /// Auto-detect format and normalise.
    pub fn normalize(&self, json_str: &str) -> Result<NormalizedReport, String> {
        let v: Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
        let source = self.detect_source(json_str, &v);
        let report = match source {
            ReportSource::Cuckoo => self.normalize_cuckoo(&v),
            ReportSource::AnyRun => self.normalize_anyrun(&v),
            ReportSource::TriageIo => self.normalize_triage(&v),
            ReportSource::JoeSandbox => self.normalize_joe(&v),
            ReportSource::HybridAnalysis => self.normalize_hybrid(&v),
            ReportSource::VirustotalBehavior => self.normalize_vt_behavior(&v),
        };
        Ok(report)
    }

    fn detect_source(&self, raw: &str, _v: &Value) -> ReportSource {
        if raw.contains("\"behavior\"") && raw.contains("\"signatures\"") && raw.contains("\"info\"") {
            return ReportSource::Cuckoo;
        }
        if raw.contains("\"generalInfo\"") {
            return ReportSource::AnyRun;
        }
        if raw.contains("\"task_name\"") && raw.contains("\"sample\"") {
            return ReportSource::TriageIo;
        }
        if raw.contains("\"generalOverview\"") {
            return ReportSource::JoeSandbox;
        }
        if raw.contains("\"hybrid_analysis\"") || raw.contains("\"threat_score\"") {
            return ReportSource::HybridAnalysis;
        }
        if raw.contains("\"behavior_summary\"") || raw.contains("\"network_infrastructure\"") {
            return ReportSource::VirustotalBehavior;
        }
        ReportSource::Cuckoo // default fallback
    }

    // ── Cuckoo ──────────────────────────────────────────────────────────────

    pub fn normalize_cuckoo(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::Cuckoo);

        // Basic file info
        if let Some(info) = v.get("info") {
            r.analysis_duration_s = info.get("duration").and_then(Value::as_u64).unwrap_or(0) as u32;
        }
        if let Some(target) = v.get("target")
            && let Some(file) = target.get("file") {
                r.filename = file.get("name").and_then(Value::as_str).unwrap_or("").to_owned();
                r.sha256 = file.get("sha256").and_then(Value::as_str).unwrap_or("").to_owned();
                r.file_type = file.get("type").and_then(Value::as_str).unwrap_or("").to_owned();
            }

        // Score / verdict
        if let Some(score) = v.get("info").and_then(|i| i.get("score")).and_then(Value::as_f64) {
            r.raw_score = Some(score);
            r.verdict = Verdict::from_score(score);
        }

        // Processes
        if let Some(behavior) = v.get("behavior")
            && let Some(procs) = behavior.get("processes").and_then(Value::as_array) {
                for p in procs {
                    let proc = NormalizedProcess {
                        pid: p.get("process_id").and_then(Value::as_u64).unwrap_or(0) as u32,
                        ppid: p.get("parent_id").and_then(Value::as_u64).unwrap_or(0) as u32,
                        name: p.get("process_name").and_then(Value::as_str).unwrap_or("").to_owned(),
                        command_line: p.get("command_line").and_then(Value::as_str).unwrap_or("").to_owned(),
                        injected: false,
                        hollowed: false,
                    };
                    r.processes.push(proc);
                }
            }

        // Network
        if let Some(net) = v.get("network") {
            // DNS
            if let Some(dns) = net.get("dns").and_then(Value::as_array) {
                for d in dns {
                    let req = d.get("request").and_then(Value::as_str).unwrap_or("");
                    r.network.push(NormalizedNetworkEvent {
                        src_ip: String::new(),
                        dst_ip: d.get("answers").and_then(Value::as_array)
                            .and_then(|a| a.first())
                            .and_then(|a| a.get("data"))
                            .and_then(Value::as_str)
                            .unwrap_or("").to_owned(),
                        dst_port: 53,
                        protocol: "DNS".into(),
                        data_size: 0,
                        dns_query: if req.is_empty() { None } else { Some(req.to_owned()) },
                    });
                }
            }
            // TCP
            if let Some(tcp) = net.get("tcp").and_then(Value::as_array) {
                for conn in tcp {
                    r.network.push(NormalizedNetworkEvent {
                        src_ip: conn.get("src").and_then(Value::as_str).unwrap_or("").to_owned(),
                        dst_ip: conn.get("dst").and_then(Value::as_str).unwrap_or("").to_owned(),
                        dst_port: conn.get("dport").and_then(Value::as_u64).unwrap_or(0) as u16,
                        protocol: "TCP".into(),
                        data_size: conn.get("dlen").and_then(Value::as_u64).unwrap_or(0),
                        dns_query: None,
                    });
                }
            }
            // HTTP
            if let Some(http) = net.get("http").and_then(Value::as_array) {
                for req in http {
                    let uri = req.get("uri").and_then(Value::as_str).unwrap_or("");
                    r.network.push(NormalizedNetworkEvent {
                        src_ip: String::new(),
                        dst_ip: req.get("dst").and_then(Value::as_str).unwrap_or("").to_owned(),
                        dst_port: req.get("dport").and_then(Value::as_u64).unwrap_or(80) as u16,
                        protocol: "HTTP".into(),
                        data_size: 0,
                        dns_query: None,
                    });
                    r.tags.push(format!("url:{uri}"));
                }
            }
        }

        // Dropped files
        if let Some(dropped) = v.get("dropped").and_then(Value::as_array) {
            for f in dropped {
                r.files.push(NormalizedFileEvent {
                    path: f.get("path").and_then(Value::as_str).unwrap_or("").to_owned(),
                    operation: FileOp::Create,
                    size: f.get("size").and_then(Value::as_u64).unwrap_or(0),
                    sha256: f.get("sha256").and_then(Value::as_str).map(std::borrow::ToOwned::to_owned),
                });
            }
        }

        // Registry
        if let Some(behavior) = v.get("behavior")
            && let Some(summary) = behavior.get("summary")
                && let Some(keys) = summary.get("regkey_written").and_then(Value::as_array) {
                    for k in keys {
                        let key = k.as_str().unwrap_or("");
                        let (base, val) = split_reg_key(key);
                        r.registry.push(NormalizedRegistryEvent {
                            key: base.to_owned(),
                            value: val.to_owned(),
                            data: String::new(),
                            operation: RegOp::Set,
                        });
                    }
                }

        // Signatures
        if let Some(sigs) = v.get("signatures").and_then(Value::as_array) {
            for sig in sigs {
                let name = sig.get("name").and_then(Value::as_str).unwrap_or("").to_owned();
                let desc = sig.get("description").and_then(Value::as_str).unwrap_or("").to_owned();
                let severity = sig.get("severity").and_then(Value::as_u64).unwrap_or(1) as u8;
                r.signatures.push(NormalizedSignature { name, severity, description: desc, mitre_attack: Vec::new() });
            }
        }

        r
    }

    // ── AnyRun ──────────────────────────────────────────────────────────────

    pub fn normalize_anyrun(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::AnyRun);

        if let Some(gi) = v.get("generalInfo") {
            r.filename = gi.get("exifInfo").and_then(|e| e.get("fileName")).and_then(Value::as_str).unwrap_or("").to_owned();
        }
        if let Some(analysis) = v.get("analysis") {
            let verdict_str = analysis.get("verdict").and_then(Value::as_str).unwrap_or("").to_lowercase();
            r.verdict = match verdict_str.as_str() {
                "malicious" => Verdict::Malicious,
                "suspicious" => Verdict::Suspicious,
                "no threats detected" | "clean" => Verdict::Clean,
                _ => Verdict::Unknown,
            };
        }
        if let Some(dns) = v.get("dnsRequests").and_then(Value::as_array) {
            for d in dns {
                r.network.push(NormalizedNetworkEvent {
                    src_ip: String::new(),
                    dst_ip: d.get("ip").and_then(Value::as_str).unwrap_or("").to_owned(),
                    dst_port: 53,
                    protocol: "DNS".into(),
                    data_size: 0,
                    dns_query: d.get("domain").and_then(Value::as_str).map(std::borrow::ToOwned::to_owned),
                });
            }
        }
        if let Some(connections) = v.get("connections").and_then(Value::as_array) {
            for c in connections {
                r.network.push(NormalizedNetworkEvent {
                    src_ip: String::new(),
                    dst_ip: c.get("ip").and_then(Value::as_str).unwrap_or("").to_owned(),
                    dst_port: c.get("port").and_then(Value::as_u64).unwrap_or(0) as u16,
                    protocol: c.get("protocol").and_then(Value::as_str).unwrap_or("TCP").to_owned(),
                    data_size: 0,
                    dns_query: None,
                });
            }
        }
        r
    }

    // ── Triage.io ────────────────────────────────────────────────────────────

    pub fn normalize_triage(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::TriageIo);
        if let Some(sample) = v.get("sample") {
            r.filename = sample.get("target").and_then(Value::as_str).unwrap_or("").to_owned();
            r.sha256 = sample.get("sha256").and_then(Value::as_str).unwrap_or("").to_owned();
        }
        if let Some(analysis) = v.get("analysis") {
            let score = analysis.get("score").and_then(Value::as_f64).unwrap_or(0.0);
            r.raw_score = Some(score);
            r.verdict = Verdict::from_score(score);
        }
        if let Some(iocs) = v.get("iocs") {
            for key in &["domains", "ips", "urls"] {
                if let Some(arr) = iocs.get(key).and_then(Value::as_array) {
                    for item in arr {
                        let val = item.as_str().unwrap_or("");
                        if !val.is_empty() {
                            let proto = match *key { "domains" => "DNS", "ips" => "TCP", _ => "HTTP" };
                            r.network.push(NormalizedNetworkEvent {
                                src_ip: String::new(),
                                dst_ip: if *key == "ips" { val.to_owned() } else { String::new() },
                                dst_port: 0,
                                protocol: proto.into(),
                                data_size: 0,
                                dns_query: if *key == "domains" { Some(val.to_owned()) } else { None },
                            });
                        }
                    }
                }
            }
        }
        r
    }

    // ── Joe Sandbox ──────────────────────────────────────────────────────────

    pub fn normalize_joe(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::JoeSandbox);
        if let Some(general) = v.get("generalOverview") {
            r.filename = general.get("fileName").and_then(Value::as_str).unwrap_or("").to_owned();
            r.sha256 = general.get("sha256").and_then(Value::as_str).unwrap_or("").to_owned();
            let det = general.get("detection").and_then(Value::as_str).unwrap_or("").to_lowercase();
            r.verdict = match det.as_str() {
                "malicious" => Verdict::Malicious,
                "suspicious" => Verdict::Suspicious,
                "clean" => Verdict::Clean,
                _ => Verdict::Unknown,
            };
        }
        if let Some(nb) = v.get("networkBehavior")
            && let Some(dns) = nb.get("dnsLookups").and_then(Value::as_array) {
                for d in dns {
                    r.network.push(NormalizedNetworkEvent {
                        src_ip: String::new(),
                        dst_ip: d.get("ip").and_then(Value::as_str).unwrap_or("").to_owned(),
                        dst_port: 53,
                        protocol: "DNS".into(),
                        data_size: 0,
                        dns_query: d.get("hostname").and_then(Value::as_str).map(std::borrow::ToOwned::to_owned),
                    });
                }
            }
        r
    }

    // ── Hybrid Analysis ──────────────────────────────────────────────────────

    pub fn normalize_hybrid(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::HybridAnalysis);
        r.sha256 = v.get("sha256").and_then(Value::as_str).unwrap_or("").to_owned();
        r.filename = v.get("submit_name").and_then(Value::as_str).unwrap_or("").to_owned();
        let threat_score = v.get("threat_score").and_then(Value::as_f64).unwrap_or(0.0);
        r.raw_score = Some(threat_score);
        r.verdict = Verdict::from_score(threat_score / 10.0);

        if let Some(domains) = v.get("domains").and_then(Value::as_array) {
            for d in domains {
                let domain = d.as_str().unwrap_or("");
                if !domain.is_empty() {
                    r.network.push(NormalizedNetworkEvent {
                        src_ip: String::new(),
                        dst_ip: String::new(),
                        dst_port: 53,
                        protocol: "DNS".into(),
                        data_size: 0,
                        dns_query: Some(domain.to_owned()),
                    });
                }
            }
        }
        r
    }

    // ── VT Behavior ──────────────────────────────────────────────────────────

    pub fn normalize_vt_behavior(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::VirustotalBehavior);
        if let Some(sha) = v.get("sha256").and_then(Value::as_str) {
            r.sha256 = sha.to_owned();
        }
        if let Some(net) = v.get("network_infrastructure") {
            for dns_key in &["dns_lookups", "domains"] {
                if let Some(arr) = net.get(dns_key).and_then(Value::as_array) {
                    for d in arr {
                        let hostname = d.get("hostname").or_else(|| d.get("domain"))
                            .and_then(Value::as_str).unwrap_or("");
                        if !hostname.is_empty() {
                            r.network.push(NormalizedNetworkEvent {
                                src_ip: String::new(),
                                dst_ip: String::new(),
                                dst_port: 53,
                                protocol: "DNS".into(),
                                data_size: 0,
                                dns_query: Some(hostname.to_owned()),
                            });
                        }
                    }
                }
            }
        }
        if let Some(sigs) = v.get("behavior_summary").and_then(Value::as_array) {
            for sig in sigs {
                let name = sig.as_str().unwrap_or("").to_owned();
                if !name.is_empty() {
                    r.signatures.push(NormalizedSignature { name, severity: 2, description: String::new(), mitre_attack: Vec::new() });
                }
            }
        }
        r.verdict = if r.signatures.is_empty() { Verdict::Unknown } else { Verdict::Suspicious };
        r
    }

    /// Normalise a generic JSON blob using common field names.
    pub fn normalize_generic(&self, v: &Value) -> NormalizedReport {
        let mut r = NormalizedReport::empty(ReportSource::Cuckoo);
        // Try common hash fields
        for key in &["sha256", "SHA256", "file_sha256"] {
            if let Some(s) = v.get(key).and_then(Value::as_str) { r.sha256 = s.to_owned(); break; }
        }
        for key in &["filename", "file_name", "name", "sample"] {
            if let Some(s) = v.get(key).and_then(Value::as_str) { r.filename = s.to_owned(); break; }
        }
        r
    }
}

impl Default for SandboxReportNormalizer {
    fn default() -> Self { Self::new() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Split `HKCU\Software\Run\AppName` into `("HKCU\Software\Run", "AppName")`.
fn split_reg_key(key: &str) -> (&str, &str) {
    match key.rfind('\\') {
        Some(pos) => (&key[..pos], &key[pos + 1..]),
        None => (key, ""),
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cuckoo() -> String {
        r#"{
          "info": {"id": 1, "score": 8.5, "duration": 120},
          "target": {"file": {"name": "mal.exe", "sha256": "aaaa", "type": "PE32"}},
          "behavior": {
            "processes": [{"process_name": "mal.exe", "process_id": 1000, "parent_id": 4, "command_line": "mal.exe /s"}],
            "summary": {"regkey_written": ["HKCU\\Software\\Run\\malware"]}
          },
          "network": {
            "dns": [{"request": "evil.com", "answers": [{"data": "1.2.3.4"}]}],
            "tcp": [{"src": "10.0.0.2", "dst": "1.2.3.4", "dport": 443, "dlen": 512}],
            "http": [{"uri": "http://evil.com/payload", "dst": "1.2.3.4", "dport": 80}]
          },
          "dropped": [{"path": "C:\\Temp\\d.exe", "sha256": "bbbbb", "size": 1024}],
          "signatures": [{"name": "process_injection", "description": "Injects code", "severity": 3}]
        }"#.to_owned()
    }

    #[test]
    fn test_normalize_cuckoo_sha256() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        assert_eq!(r.sha256, "aaaa");
    }

    #[test]
    fn test_normalize_cuckoo_verdict_malicious() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        assert_eq!(r.verdict, Verdict::Malicious);
    }

    #[test]
    fn test_normalize_cuckoo_process() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        assert_eq!(r.processes.len(), 1);
        assert_eq!(r.processes[0].name, "mal.exe");
    }

    #[test]
    fn test_normalize_cuckoo_dns() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        let dns: Vec<_> = r.dns_queries();
        assert!(dns.iter().any(|&d| d == "evil.com"));
    }

    #[test]
    fn test_normalize_cuckoo_network_tcp() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        let tcp: Vec<_> = r.network.iter().filter(|e| e.protocol == "TCP").collect();
        assert!(!tcp.is_empty());
        assert_eq!(tcp[0].dst_port, 443);
    }

    #[test]
    fn test_normalize_cuckoo_dropped_file() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].operation, FileOp::Create);
    }

    #[test]
    fn test_normalize_cuckoo_registry() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        assert!(!r.registry.is_empty());
        assert_eq!(r.registry[0].operation, RegOp::Set);
    }

    #[test]
    fn test_normalize_cuckoo_signatures() {
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(&make_cuckoo()).unwrap();
        assert!(r.has_signature_containing("injection"));
    }

    #[test]
    fn test_verdict_from_score() {
        assert_eq!(Verdict::from_score(9.0), Verdict::Malicious);
        assert_eq!(Verdict::from_score(5.0), Verdict::Suspicious);
        assert_eq!(Verdict::from_score(0.0), Verdict::Clean);
    }

    #[test]
    fn test_verdict_severity_ordering() {
        assert!(Verdict::Malicious.severity() > Verdict::Suspicious.severity());
        assert!(Verdict::Suspicious.severity() > Verdict::Clean.severity());
    }

    #[test]
    fn test_file_op_from_str() {
        assert_eq!(FileOp::from_str("CreateFile"), FileOp::Create);
        assert_eq!(FileOp::from_str("ReadFile"), FileOp::Read);
        assert_eq!(FileOp::from_str("foobar"), FileOp::Unknown);
    }

    #[test]
    fn test_reg_op_from_str() {
        assert_eq!(RegOp::from_str("RegSetValue"), RegOp::Set);
        assert_eq!(RegOp::from_str("RegDeleteKey"), RegOp::Delete);
    }

    #[test]
    fn test_normalize_anyrun_verdict() {
        let json = r#"{"generalInfo": {}, "analysis": {"verdict": "Malicious"}, "dnsRequests": [], "connections": []}"#;
        let norm = SandboxReportNormalizer::new();
        let r = norm.normalize(json).unwrap();
        assert_eq!(r.verdict, Verdict::Malicious);
    }

    #[test]
    fn test_split_reg_key_with_backslash() {
        let (k, v) = split_reg_key("HKCU\\Software\\Run\\malware");
        assert_eq!(k, "HKCU\\Software\\Run");
        assert_eq!(v, "malware");
    }

    #[test]
    fn test_normalize_invalid_json_returns_err() {
        let norm = SandboxReportNormalizer::new();
        assert!(norm.normalize("{not valid}").is_err());
    }

    #[test]
    fn test_unique_dst_ips() {
        let mut r = NormalizedReport::empty(ReportSource::Cuckoo);
        r.network.push(NormalizedNetworkEvent { src_ip: "".into(), dst_ip: "1.2.3.4".into(), dst_port: 80, protocol: "TCP".into(), data_size: 0, dns_query: None });
        r.network.push(NormalizedNetworkEvent { src_ip: "".into(), dst_ip: "1.2.3.4".into(), dst_port: 443, protocol: "TCP".into(), data_size: 0, dns_query: None });
        r.network.push(NormalizedNetworkEvent { src_ip: "".into(), dst_ip: "5.6.7.8".into(), dst_port: 22, protocol: "TCP".into(), data_size: 0, dns_query: None });
        let ips = r.unique_dst_ips();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_summary_contains_verdict() {
        let mut r = NormalizedReport::empty(ReportSource::Cuckoo);
        r.verdict = Verdict::Malicious;
        r.filename = "mal.exe".into();
        let s = r.summary();
        assert!(s.contains("Malicious"));
        assert!(s.contains("mal.exe"));
    }
}
