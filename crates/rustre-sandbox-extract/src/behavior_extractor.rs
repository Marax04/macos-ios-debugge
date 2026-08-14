//! Behavioral artifact extractor from sandbox logs.
//!
//! Parses Cuckoo, `AnyRun`, Triage, `Joe Sandbox`, and generic JSON reports and
//! normalises the output into typed [`BehaviorArtifact`] and [`Ioc`] values.

use std::collections::HashMap;
use serde_json::Value;

// ─── SandboxLogFormat ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxLogFormat {
    Cuckoo,
    AnyRun,
    Triage,
    JoeSandbox,
    GenericJson,
}

// ─── ArtifactType ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactType {
    DroppedFile,
    NetworkConnection,
    RegistryModification,
    ProcessCreation,
    MutexCreation,
    ServiceInstallation,
    ScheduledTaskCreation,
    DllInjection,
    MemoryAllocation,
    ApiCall,
    DnsQuery,
    HttpRequest,
    C2Communication,
    FileHash,
    UrlVisited,
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DroppedFile => "DroppedFile",
            Self::NetworkConnection => "NetworkConnection",
            Self::RegistryModification => "RegistryModification",
            Self::ProcessCreation => "ProcessCreation",
            Self::MutexCreation => "MutexCreation",
            Self::ServiceInstallation => "ServiceInstallation",
            Self::ScheduledTaskCreation => "ScheduledTaskCreation",
            Self::DllInjection => "DllInjection",
            Self::MemoryAllocation => "MemoryAllocation",
            Self::ApiCall => "ApiCall",
            Self::DnsQuery => "DnsQuery",
            Self::HttpRequest => "HttpRequest",
            Self::C2Communication => "C2Communication",
            Self::FileHash => "FileHash",
            Self::UrlVisited => "UrlVisited",
        };
        write!(f, "{s}")
    }
}

// ─── BehaviorArtifact ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorArtifact {
    pub artifact_type: ArtifactType,
    pub value: String,
    pub confidence: f64,
    pub source_pid: u32,
    pub timestamp_ms: u64,
    /// Additional key-value metadata from the original report.
    pub metadata: HashMap<String, String>,
}

impl BehaviorArtifact {
    pub fn new(artifact_type: ArtifactType, value: impl Into<String>, confidence: f64) -> Self {
        Self {
            artifact_type,
            value: value.into(),
            confidence,
            source_pid: 0,
            timestamp_ms: 0,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn with_pid(mut self, pid: u32) -> Self { self.source_pid = pid; self }
    #[must_use]
    pub const fn with_ts(mut self, ts: u64) -> Self { self.timestamp_ms = ts; self }
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into()); self
    }
}

// ─── Ioc ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IocKind {
    Ip, Domain, Url, Md5, Sha1, Sha256, FilePath, RegistryKey, Mutex,
}

#[derive(Debug, Clone)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub source: String,
}

// ─── ExtractionReport ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ExtractionReport {
    pub artifacts: Vec<BehaviorArtifact>,
    pub iocs: Vec<Ioc>,
    pub risk_score: f64,
    pub format: SandboxLogFormat,
    pub parse_errors: Vec<String>,
}

impl ExtractionReport {
    const fn new(format: SandboxLogFormat) -> Self {
        Self {
            artifacts: Vec::new(),
            iocs: Vec::new(),
            risk_score: 0.0,
            format,
            parse_errors: Vec::new(),
        }
    }

    fn compute_risk_score(&mut self) {
        let mut score = 0.0f64;
        for a in &self.artifacts {
            score += match a.artifact_type {
                ArtifactType::C2Communication => 3.0,
                ArtifactType::DllInjection => 2.5,
                ArtifactType::ServiceInstallation | ArtifactType::ScheduledTaskCreation => 2.0,
                ArtifactType::MemoryAllocation => 1.5,
                ArtifactType::ProcessCreation | ArtifactType::RegistryModification => 1.0,
                ArtifactType::NetworkConnection | ArtifactType::HttpRequest => 0.8,
                ArtifactType::DroppedFile => 0.7,
                ArtifactType::DnsQuery => 0.5,
                _ => 0.2,
            } * a.confidence;
        }
        self.risk_score = score.min(100.0);
    }
}

// ─── BehaviorExtractor ───────────────────────────────────────────────────────

pub struct BehaviorExtractor {
    format: SandboxLogFormat,
}

impl BehaviorExtractor {
    #[must_use]
    pub const fn new(format: SandboxLogFormat) -> Self { Self { format } }

    #[must_use]
    pub fn detect_format(json_str: &str) -> SandboxLogFormat {
        if json_str.contains("\"info\"") && json_str.contains("\"signatures\"") && json_str.contains("\"behavior\"") {
            return SandboxLogFormat::Cuckoo;
        }
        if json_str.contains("\"generalInfo\"") && json_str.contains("\"mitreTechniques\"") {
            return SandboxLogFormat::AnyRun;
        }
        if json_str.contains("\"sample\"") && json_str.contains("\"task_name\"") {
            return SandboxLogFormat::Triage;
        }
        if json_str.contains("\"generalOverview\"") && json_str.contains("\"networkBehavior\"") {
            return SandboxLogFormat::JoeSandbox;
        }
        SandboxLogFormat::GenericJson
    }

    /// Parse any supported format. Auto-detects if needed.
    #[must_use]
    pub fn extract(&self, json_str: &str) -> ExtractionReport {
        let fmt = if self.format == SandboxLogFormat::GenericJson {
            Self::detect_format(json_str)
        } else {
            self.format.clone()
        };
        let mut report = match fmt {
            SandboxLogFormat::Cuckoo => self.parse_cuckoo_report(json_str),
            SandboxLogFormat::AnyRun => self.parse_anyrun_report(json_str),
            SandboxLogFormat::Triage => self.parse_triage_report(json_str),
            SandboxLogFormat::JoeSandbox => self.parse_joe_report(json_str),
            SandboxLogFormat::GenericJson => self.parse_generic_json(json_str),
        };
        report.compute_risk_score();
        report
    }

    // ── Cuckoo ──────────────────────────────────────────────────────────────

    pub fn parse_cuckoo_report(&self, json_str: &str) -> ExtractionReport {
        let mut report = ExtractionReport::new(SandboxLogFormat::Cuckoo);
        let v: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => { report.parse_errors.push(format!("JSON parse: {e}")); return report; }
        };

        // Network artifacts
        if let Some(network) = v.get("network") {
            // DNS
            if let Some(dns) = network.get("dns").and_then(Value::as_array) {
                for entry in dns {
                    let request = entry.get("request").and_then(Value::as_str).unwrap_or("");
                    if !request.is_empty() {
                        let a = BehaviorArtifact::new(ArtifactType::DnsQuery, request, 0.95);
                        report.iocs.push(Ioc { kind: IocKind::Domain, value: request.to_owned(), source: "cuckoo/dns".into() });
                        report.artifacts.push(a);
                    }
                }
            }
            // HTTP
            if let Some(http) = network.get("http").and_then(Value::as_array) {
                for entry in http {
                    let uri = entry.get("uri").and_then(Value::as_str).unwrap_or("");
                    if !uri.is_empty() {
                        report.artifacts.push(BehaviorArtifact::new(ArtifactType::HttpRequest, uri, 0.95));
                        report.iocs.push(Ioc { kind: IocKind::Url, value: uri.to_owned(), source: "cuckoo/http".into() });
                    }
                }
            }
            // TCP connections
            if let Some(tcp) = network.get("tcp").and_then(Value::as_array) {
                for conn in tcp {
                    let dst = conn.get("dst").and_then(Value::as_str).unwrap_or("");
                    let dport = conn.get("dport").and_then(Value::as_u64).unwrap_or(0);
                    if !dst.is_empty() {
                        let val = format!("{dst}:{dport}");
                        let art = BehaviorArtifact::new(ArtifactType::NetworkConnection, &val, 0.90);
                        report.iocs.push(Ioc { kind: IocKind::Ip, value: dst.to_owned(), source: "cuckoo/tcp".into() });
                        report.artifacts.push(art);
                    }
                }
            }
        }

        // Dropped files
        if let Some(dropped) = v.get("dropped").and_then(Value::as_array) {
            for f in dropped {
                let path = f.get("path").and_then(Value::as_str).unwrap_or("");
                let sha256 = f.get("sha256").and_then(Value::as_str).unwrap_or("");
                if !path.is_empty() {
                    let mut art = BehaviorArtifact::new(ArtifactType::DroppedFile, path, 0.92);
                    if !sha256.is_empty() {
                        art = art.with_meta("sha256", sha256);
                        report.iocs.push(Ioc { kind: IocKind::Sha256, value: sha256.to_owned(), source: "cuckoo/dropped".into() });
                    }
                    report.artifacts.push(art);
                }
            }
        }

        // Behavior: processes
        if let Some(processes) = v.get("behavior")
            .and_then(|b| b.get("processes"))
            .and_then(Value::as_array)
        {
            for proc in processes {
                let name = proc.get("process_name").and_then(Value::as_str).unwrap_or("");
                let pid = u32::try_from(proc.get("process_id").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(u32::MAX);
                if !name.is_empty() {
                    report.artifacts.push(BehaviorArtifact::new(ArtifactType::ProcessCreation, name, 0.88).with_pid(pid));
                }
                // Registry calls
                if let Some(calls) = proc.get("calls").and_then(Value::as_array) {
                    for call in calls {
                        let api = call.get("api").and_then(Value::as_str).unwrap_or("");
                        if api.to_lowercase().contains("regsetvalue") || api.to_lowercase().contains("regcreatekey") {
                            let key = call.get("arguments").and_then(|a| a.get("regkey")).and_then(Value::as_str).unwrap_or("");
                            if !key.is_empty() {
                                report.artifacts.push(BehaviorArtifact::new(ArtifactType::RegistryModification, key, 0.85).with_pid(pid));
                                report.iocs.push(Ioc { kind: IocKind::RegistryKey, value: key.to_owned(), source: "cuckoo/behavior".into() });
                            }
                        }
                        if api.to_lowercase().contains("createmutex") {
                            let mutex = call.get("arguments").and_then(|a| a.get("mutant_name")).and_then(Value::as_str).unwrap_or("");
                            if !mutex.is_empty() {
                                report.artifacts.push(BehaviorArtifact::new(ArtifactType::MutexCreation, mutex, 0.88).with_pid(pid));
                                report.iocs.push(Ioc { kind: IocKind::Mutex, value: mutex.to_owned(), source: "cuckoo/behavior".into() });
                            }
                        }
                    }
                }
            }
        }

        // Signatures
        if let Some(sigs) = v.get("signatures").and_then(Value::as_array) {
            for sig in sigs {
                let name = sig.get("name").and_then(Value::as_str).unwrap_or("");
                if name.to_lowercase().contains("inject") || name.to_lowercase().contains("hollowing") {
                    report.artifacts.push(BehaviorArtifact::new(ArtifactType::DllInjection, name, 0.80));
                }
            }
        }

        report
    }

    // ── AnyRun ──────────────────────────────────────────────────────────────

    pub fn parse_anyrun_report(&self, json_str: &str) -> ExtractionReport {
        let mut report = ExtractionReport::new(SandboxLogFormat::AnyRun);
        let v: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => { report.parse_errors.push(e.to_string()); return report; }
        };

        // Network connections
        if let Some(net) = v.get("network").and_then(Value::as_array) {
            for entry in net {
                let ip = entry.get("ip").and_then(Value::as_str).unwrap_or("");
                let port = entry.get("port").and_then(Value::as_u64).unwrap_or(0);
                if !ip.is_empty() {
                    let val = format!("{ip}:{port}");
                    report.artifacts.push(BehaviorArtifact::new(ArtifactType::NetworkConnection, &val, 0.88));
                    report.iocs.push(Ioc { kind: IocKind::Ip, value: ip.to_owned(), source: "anyrun/network".into() });
                }
            }
        }

        // DNS
        if let Some(dns) = v.get("dnsRequests").and_then(Value::as_array) {
            for d in dns {
                let domain = d.get("domain").and_then(Value::as_str).unwrap_or("");
                if !domain.is_empty() {
                    report.artifacts.push(BehaviorArtifact::new(ArtifactType::DnsQuery, domain, 0.90));
                    report.iocs.push(Ioc { kind: IocKind::Domain, value: domain.to_owned(), source: "anyrun/dns".into() });
                }
            }
        }

        report
    }

    // ── Triage ──────────────────────────────────────────────────────────────

    pub fn parse_triage_report(&self, json_str: &str) -> ExtractionReport {
        let mut report = ExtractionReport::new(SandboxLogFormat::Triage);
        let v: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => { report.parse_errors.push(e.to_string()); return report; }
        };
        if let Some(iocs) = v.get("iocs") {
            for kind_key in &["domains", "ips", "urls"] {
                if let Some(arr) = iocs.get(kind_key).and_then(Value::as_array) {
                    for item in arr {
                        let val = item.as_str().unwrap_or("");
                        if !val.is_empty() {
                            let kind = match *kind_key {
                                "domains" => IocKind::Domain,
                                "ips" => IocKind::Ip,
                                _ => IocKind::Url,
                            };
                            report.iocs.push(Ioc { kind, value: val.to_owned(), source: "triage/iocs".into() });
                            let art_type = if *kind_key == "domains" { ArtifactType::DnsQuery } else { ArtifactType::NetworkConnection };
                            report.artifacts.push(BehaviorArtifact::new(art_type, val, 0.88));
                        }
                    }
                }
            }
        }
        report
    }

    // ── Joe Sandbox ─────────────────────────────────────────────────────────

    pub fn parse_joe_report(&self, json_str: &str) -> ExtractionReport {
        let mut report = ExtractionReport::new(SandboxLogFormat::JoeSandbox);
        let v: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => { report.parse_errors.push(e.to_string()); return report; }
        };
        if let Some(dns) = v.get("networkBehavior")
            .and_then(|nb| nb.get("dnsLookups"))
            .and_then(Value::as_array)
        {
            for d in dns {
                let name = d.get("hostname").and_then(Value::as_str).unwrap_or("");
                if !name.is_empty() {
                    report.artifacts.push(BehaviorArtifact::new(ArtifactType::DnsQuery, name, 0.90));
                    report.iocs.push(Ioc { kind: IocKind::Domain, value: name.to_owned(), source: "joe/dns".into() });
                }
            }
        }
        report
    }

    // ── Generic JSON ────────────────────────────────────────────────────────

    #[must_use] 
    pub fn parse_generic_json(&self, json_str: &str) -> ExtractionReport {
        let mut report = ExtractionReport::new(SandboxLogFormat::GenericJson);
        let v: Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => { report.parse_errors.push(e.to_string()); return report; }
        };
        self.walk_json_for_iocs(&v, &mut report);
        report
    }

    fn walk_json_for_iocs(&self, v: &Value, report: &mut ExtractionReport) {
        match v {
            Value::Object(map) => {
                for (key, val) in map {
                    let key_lower = key.to_lowercase();
                    if let Some(s) = val.as_str() {
                        if key_lower.contains("url") || key_lower.contains("uri") {
                            if s.starts_with("http") || s.starts_with("ftp") {
                                report.artifacts.push(BehaviorArtifact::new(ArtifactType::UrlVisited, s, 0.80));
                                report.iocs.push(Ioc { kind: IocKind::Url, value: s.to_owned(), source: "generic/url".into() });
                            }
                        } else if key_lower.contains("domain") || key_lower.contains("hostname") {
                            if !s.is_empty() && !s.contains(' ') {
                                report.artifacts.push(BehaviorArtifact::new(ArtifactType::DnsQuery, s, 0.72));
                                report.iocs.push(Ioc { kind: IocKind::Domain, value: s.to_owned(), source: "generic/domain".into() });
                            }
                        } else if key_lower == "sha256" && s.len() == 64 {
                            report.iocs.push(Ioc { kind: IocKind::Sha256, value: s.to_owned(), source: "generic/hash".into() });
                        } else if key_lower == "md5" && s.len() == 32 {
                            report.iocs.push(Ioc { kind: IocKind::Md5, value: s.to_owned(), source: "generic/hash".into() });
                        } else if key_lower.contains("path") && (s.contains('\\') || s.starts_with('/')) {
                            report.artifacts.push(BehaviorArtifact::new(ArtifactType::DroppedFile, s, 0.70));
                            report.iocs.push(Ioc { kind: IocKind::FilePath, value: s.to_owned(), source: "generic/path".into() });
                        }
                    } else {
                        self.walk_json_for_iocs(val, report);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr { self.walk_json_for_iocs(item, report); }
            }
            _ => {}
        }
    }

    // ── Targeted extractors ─────────────────────────────────────────────────

    /// Extract network IOCs from already-parsed artifacts.
    #[must_use]
    pub fn extract_network_iocs(artifacts: &[BehaviorArtifact]) -> Vec<Ioc> {
        let mut iocs = Vec::new();
        for a in artifacts {
            match a.artifact_type {
                ArtifactType::NetworkConnection => {
                    // value may be "1.2.3.4:4444"
                    let ip = a.value.split(':').next().unwrap_or(&a.value);
                    iocs.push(Ioc { kind: IocKind::Ip, value: ip.to_owned(), source: "network_conn".into() });
                }
                ArtifactType::DnsQuery => {
                    iocs.push(Ioc { kind: IocKind::Domain, value: a.value.clone(), source: "dns".into() });
                }
                ArtifactType::HttpRequest | ArtifactType::UrlVisited => {
                    iocs.push(Ioc { kind: IocKind::Url, value: a.value.clone(), source: "http".into() });
                }
                _ => {}
            }
        }
        iocs
    }

    /// Extract file-related IOCs (dropped paths + hashes).
    #[must_use]
    pub fn extract_file_iocs(artifacts: &[BehaviorArtifact]) -> Vec<Ioc> {
        let mut iocs = Vec::new();
        for a in artifacts {
            if a.artifact_type == ArtifactType::DroppedFile {
                iocs.push(Ioc { kind: IocKind::FilePath, value: a.value.clone(), source: "dropped".into() });
                if let Some(sha256) = a.metadata.get("sha256") {
                    iocs.push(Ioc { kind: IocKind::Sha256, value: sha256.clone(), source: "dropped_hash".into() });
                }
                if let Some(md5) = a.metadata.get("md5") {
                    iocs.push(Ioc { kind: IocKind::Md5, value: md5.clone(), source: "dropped_hash".into() });
                }
            }
        }
        iocs
    }

    /// Extract persistence-related artifacts (registry, services, scheduled tasks).
    #[must_use]
    pub fn extract_persistence(artifacts: &[BehaviorArtifact]) -> Vec<&BehaviorArtifact> {
        artifacts.iter().filter(|a| matches!(
            a.artifact_type,
            ArtifactType::RegistryModification |
            ArtifactType::ServiceInstallation  |
            ArtifactType::ScheduledTaskCreation
        )).collect()
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cuckoo_json() -> &'static str {
        r#"{
          "info": {"id": 1},
          "network": {
            "dns": [{"request": "evil.com", "answers": []}],
            "http": [{"uri": "http://evil.com/payload.exe", "method": "GET"}],
            "tcp": [{"src": "10.0.0.1", "dst": "1.2.3.4", "dport": 4444}]
          },
          "dropped": [{"path": "C:\\Windows\\Temp\\drop.exe", "sha256": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"}],
          "behavior": {"processes": [{"process_name": "malware.exe", "process_id": 1234, "calls": []}]},
          "signatures": [{"name": "process_injection"}]
        }"#
    }

    #[test]
    fn test_detect_format_cuckoo() {
        assert_eq!(BehaviorExtractor::detect_format(make_cuckoo_json()), SandboxLogFormat::Cuckoo);
    }

    #[test]
    fn test_detect_format_generic() {
        let json = r#"{"some": "data"}"#;
        assert_eq!(BehaviorExtractor::detect_format(json), SandboxLogFormat::GenericJson);
    }

    #[test]
    fn test_cuckoo_dns_extracted() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        let dns: Vec<_> = report.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::DnsQuery).collect();
        assert!(!dns.is_empty());
        assert!(dns[0].value.contains("evil.com"));
    }

    #[test]
    fn test_cuckoo_http_extracted() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        let http: Vec<_> = report.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::HttpRequest).collect();
        assert!(!http.is_empty());
    }

    #[test]
    fn test_cuckoo_network_connection() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        let net: Vec<_> = report.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::NetworkConnection).collect();
        assert!(!net.is_empty());
    }

    #[test]
    fn test_cuckoo_dropped_file() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        let dropped: Vec<_> = report.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::DroppedFile).collect();
        assert!(!dropped.is_empty());
        assert!(dropped[0].value.contains("drop.exe"));
    }

    #[test]
    fn test_cuckoo_process_creation() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        let proc: Vec<_> = report.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::ProcessCreation).collect();
        assert!(!proc.is_empty());
    }

    #[test]
    fn test_cuckoo_iocs_populated() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        assert!(!report.iocs.is_empty());
    }

    #[test]
    fn test_risk_score_positive() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract(make_cuckoo_json());
        assert!(report.risk_score > 0.0);
    }

    #[test]
    fn test_generic_json_url_extraction() {
        let json = r#"{"url": "http://malicious.site/cmd", "sha256": "abc"}"#;
        let extractor = BehaviorExtractor::new(SandboxLogFormat::GenericJson);
        let report = extractor.extract(json);
        assert!(report.artifacts.iter().any(|a| a.artifact_type == ArtifactType::UrlVisited));
    }

    #[test]
    fn test_generic_json_domain_extraction() {
        let json = r#"{"hostname": "badguy.example.com"}"#;
        let extractor = BehaviorExtractor::new(SandboxLogFormat::GenericJson);
        let report = extractor.extract(json);
        assert!(report.iocs.iter().any(|i| i.kind == IocKind::Domain));
    }

    #[test]
    fn test_extract_network_iocs_from_artifacts() {
        let artifacts = vec![
            BehaviorArtifact::new(ArtifactType::NetworkConnection, "1.2.3.4:4444", 0.9),
            BehaviorArtifact::new(ArtifactType::DnsQuery, "evil.com", 0.9),
        ];
        let iocs = BehaviorExtractor::extract_network_iocs(&artifacts);
        assert_eq!(iocs.len(), 2);
        assert!(iocs.iter().any(|i| i.kind == IocKind::Ip));
        assert!(iocs.iter().any(|i| i.kind == IocKind::Domain));
    }

    #[test]
    fn test_extract_file_iocs_with_hash() {
        let mut a = BehaviorArtifact::new(ArtifactType::DroppedFile, "C:\\tmp\\x.exe", 0.9);
        a.metadata.insert("sha256".into(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into());
        let iocs = BehaviorExtractor::extract_file_iocs(&[a]);
        assert!(iocs.iter().any(|i| i.kind == IocKind::FilePath));
        assert!(iocs.iter().any(|i| i.kind == IocKind::Sha256));
    }

    #[test]
    fn test_extract_persistence_filters_correctly() {
        let artifacts = vec![
            BehaviorArtifact::new(ArtifactType::RegistryModification, "HKCU\\Run", 0.9),
            BehaviorArtifact::new(ArtifactType::DnsQuery, "evil.com", 0.9),
            BehaviorArtifact::new(ArtifactType::ServiceInstallation, "MySvc", 0.9),
        ];
        let persist = BehaviorExtractor::extract_persistence(&artifacts);
        assert_eq!(persist.len(), 2);
    }

    #[test]
    fn test_invalid_json_returns_parse_error() {
        let extractor = BehaviorExtractor::new(SandboxLogFormat::Cuckoo);
        let report = extractor.extract("{not valid json}");
        assert!(!report.parse_errors.is_empty());
    }

    #[test]
    fn test_artifact_type_display() {
        assert_eq!(ArtifactType::DroppedFile.to_string(), "DroppedFile");
        assert_eq!(ArtifactType::C2Communication.to_string(), "C2Communication");
    }
}
