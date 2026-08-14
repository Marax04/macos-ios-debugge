/// JSON report serializer: structured report in cuckoo/any.run format;
/// MITRE ATT&CK mapping.
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    AttackMapping, AttackTactic, AttackTechnique, Behavior, Indicator, IocCollection,
    IocKind, IocSet, SandboxReport, Severity, Verdict,
};

// ─── ReportFormat enum ────────────────────────────────────────────────────────

/// Output format variants for the JSON reporter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonReportFormat {
    /// Cuckoo Sandbox v2/v3 compatible format.
    Cuckoo,
    /// `any.run`-style report format.
    AnyRun,
    /// Generic `RustRE` native format.
    Native,
    /// Minimal IOC-only export.
    IocOnly,
    /// STIX-lite JSON (simplified, not full STIX 2.1).
    StixLite,
}

impl fmt::Display for JsonReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cuckoo => write!(f, "cuckoo"),
            Self::AnyRun => write!(f, "any_run"),
            Self::Native => write!(f, "native"),
            Self::IocOnly => write!(f, "ioc_only"),
            Self::StixLite => write!(f, "stix_lite"),
        }
    }
}

// ─── MitreTechnique ───────────────────────────────────────────────────────────

/// MITRE ATT&CK technique in serializable form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub sub_id: Option<String>,
    pub full_id: String,
    pub name: String,
    pub tactic: String,
    pub url: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

impl MitreTechnique {
    #[must_use]
    pub fn from_attack_technique(t: &AttackTechnique) -> Self {
        let full = t.full_id().to_owned();
        let url_id = full.replace('.', "/");
        Self {
            id: t.id.clone(),
            sub_id: t.sub_id.clone(),
            full_id: full,
            name: t.name.clone(),
            tactic: t.tactic.to_string(),
            url: format!("https://attack.mitre.org/techniques/{url_id}"),
            confidence: t.confidence,
            evidence: t.evidence.clone(),
        }
    }

    /// Convert to a JSON value.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "sub_id": self.sub_id,
            "full_id": self.full_id,
            "name": self.name,
            "tactic": self.tactic,
            "url": self.url,
            "confidence": self.confidence,
            "evidence": self.evidence,
        })
    }
}

// ─── CuckooReport ─────────────────────────────────────────────────────────────

/// Cuckoo-style report structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooReport {
    pub info: CuckooInfo,
    pub target: CuckooTarget,
    pub signatures: Vec<CuckooSignature>,
    pub behavior: CuckooBehavior,
    pub network: CuckooNetwork,
    pub mist: Value,
    pub dropped: Vec<CuckooDroppedFile>,
    pub static_analysis: Value,
    pub malfamily: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooInfo {
    pub id: u64,
    pub version: String,
    pub started: String,
    pub ended: String,
    pub duration: u64,
    pub category: String,
    pub platform: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooTarget {
    pub category: String,
    pub file: CuckooFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub file_type: String,
    pub yara: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooSignature {
    pub name: String,
    pub description: String,
    pub severity: u8,
    pub categories: Vec<String>,
    pub families: Vec<String>,
    pub markcount: u32,
    pub marks: Vec<Value>,
    pub confidence: u8,
    pub ttps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooBehavior {
    pub processes: Vec<CuckooProcess>,
    pub summary: CuckooBehaviorSummary,
    pub apistats: HashMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooProcess {
    pub process_id: u32,
    pub parent_id: u32,
    pub process_name: String,
    pub calls: Vec<CuckooApiCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooApiCall {
    pub api: String,
    pub category: String,
    pub timestamp: u64,
    pub return_value: Value,
    pub arguments: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooBehaviorSummary {
    pub files: Vec<String>,
    pub keys: Vec<String>,
    pub mutexes: Vec<String>,
    pub resolved_apis: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooNetwork {
    pub hosts: Vec<String>,
    pub domains: Vec<CuckooDomain>,
    pub tcp: Vec<CuckooConnection>,
    pub udp: Vec<CuckooConnection>,
    pub http: Vec<CuckooHttpRequest>,
    pub dns: Vec<CuckooDnsQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooDomain {
    pub ip: String,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooConnection {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooHttpRequest {
    pub count: u32,
    pub body: String,
    pub uri: String,
    pub user_agent: String,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub data: String,
    pub path: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooDnsQuery {
    pub request: String,
    pub r#type: String,
    pub answers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooDroppedFile {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub file_type: String,
    pub yara: Vec<String>,
}

// ─── AnyRunReport ─────────────────────────────────────────────────────────────

/// any.run-style report wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunReport {
    pub version: String,
    pub analysis: AnyRunAnalysis,
    pub verdicts: AnyRunVerdicts,
    pub network: AnyRunNetwork,
    pub threats: Vec<AnyRunThreat>,
    pub mitre: Vec<MitreTechnique>,
    pub iocs: AnyRunIocs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunAnalysis {
    pub id: String,
    pub date: String,
    pub uuid: String,
    pub score: f64,
    pub duration_ms: u64,
    pub sandbox_type: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunVerdicts {
    pub score: u32,
    pub status: String,
    pub tags: Vec<String>,
    pub family: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunNetwork {
    pub c2_servers: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunThreat {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunIocs {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub hashes: Vec<String>,
    pub files: Vec<String>,
    pub registry: Vec<String>,
    pub mutexes: Vec<String>,
}

// ─── JsonReporter ─────────────────────────────────────────────────────────────

/// JSON report serializer with multiple output format support.
pub struct JsonReporter {
    format: JsonReportFormat,
    pretty: bool,
    extra_iocs: Option<IocCollection>,
    analysis_id: Option<String>,
    platform: String,
    sandbox_type: String,
}

impl JsonReporter {
    #[must_use]
    pub fn new(format: JsonReportFormat) -> Self {
        Self {
            format,
            pretty: true,
            extra_iocs: None,
            analysis_id: None,
            platform: "windows10".to_string(),
            sandbox_type: "rustre-sandbox".to_string(),
        }
    }

    #[must_use]
    pub fn cuckoo() -> Self { Self::new(JsonReportFormat::Cuckoo) }

    #[must_use]
    pub fn any_run() -> Self { Self::new(JsonReportFormat::AnyRun) }

    #[must_use]
    pub fn native() -> Self { Self::new(JsonReportFormat::Native) }

    #[must_use]
    pub const fn pretty(mut self, v: bool) -> Self { self.pretty = v; self }

    #[must_use]
    pub fn with_ioc_collection(mut self, iocs: IocCollection) -> Self {
        self.extra_iocs = Some(iocs);
        self
    }

    #[must_use]
    pub fn with_analysis_id(mut self, id: impl Into<String>) -> Self {
        self.analysis_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn platform(mut self, p: impl Into<String>) -> Self {
        self.platform = p.into();
        self
    }

    /// Serialize the report to JSON according to the configured format.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on serialization failure.
    pub fn serialize(&self, report: &SandboxReport) -> Result<String, serde_json::Error> {
        let value = match self.format {
            JsonReportFormat::Cuckoo => self.to_cuckoo_value(report),
            JsonReportFormat::AnyRun => self.to_any_run_value(report),
            JsonReportFormat::Native => self.to_native_value(report),
            JsonReportFormat::IocOnly => self.to_ioc_only_value(report),
            JsonReportFormat::StixLite => Self::to_stix_lite_value(report),
        };
        if self.pretty {
            serde_json::to_string_pretty(&value)
        } else {
            serde_json::to_string(&value)
        }
    }

    fn to_native_value(&self, report: &SandboxReport) -> Value {
        let techniques: Vec<Value> = report.attack.techniques.iter()
            .map(|t| MitreTechnique::from_attack_technique(t).to_json())
            .collect();

        let indicators: Vec<Value> = report.indicators.iter().map(|i| json!({
            "name": i.name,
            "description": i.desc,
            "severity": i.severity.to_string(),
            "category": i.category.to_string(),
            "ioc": i.ioc,
            "technique_ids": i.technique_ids,
        })).collect();

        let behaviors: Vec<Value> = report.behaviors.iter().map(|b| json!({
            "name": b.name,
            "description": b.desc,
            "severity": b.severity.to_string(),
            "category": b.category,
            "apis": b.apis,
            "pid": b.pid,
            "first_seen_ms": b.first_seen_ms,
        })).collect();

        let iocs = Self::serialize_ioc_set(&report.iocs);

        let mut root = json!({
            "schema_version": "rustre-sandbox/1.0",
            "analysis_id": self.analysis_id.as_deref().unwrap_or("unknown"),
            "sample": report.sample,
            "sha256": report.sha256,
            "verdict": report.verdict.to_string(),
            "score": report.score,
            "family": report.family,
            "analysis_duration_ms": report.analysis_ms,
            "tags": report.tags,
            "indicators": indicators,
            "behaviors": behaviors,
            "attack_techniques": techniques,
            "iocs": iocs,
            "sections": report.sections.iter().map(|s| json!({
                "title": s.title,
                "content": s.content,
                "order": s.order,
            })).collect::<Vec<_>>(),
        });

        if let Some(extra) = &self.extra_iocs {
            root["extra_iocs"] = json!({
                "ips": extra.ips,
                "domains": extra.domains,
                "urls": extra.urls,
                "file_paths": extra.file_paths,
                "hashes": extra.hashes,
                "registry_keys": extra.registry_keys,
                "mutexes": extra.mutexes,
                "btc_addresses": extra.btc_addresses,
            });
        }

        root
    }

    fn to_cuckoo_value(&self, report: &SandboxReport) -> Value {
        let signatures: Vec<Value> = report.indicators.iter().map(|ind| {
            let sev = match ind.severity {
                Severity::Info => 1u8,
                Severity::Low => 2,
                Severity::Medium => 3,
                Severity::High => 4,
                Severity::Critical => 5,
            };
            json!({
                "name": ind.name.to_lowercase().replace(' ', "_"),
                "description": ind.desc,
                "severity": sev,
                "categories": [ind.category.to_string()],
                "families": [report.family],
                "markcount": 1,
                "marks": [],
                "confidence": 80,
                "ttps": ind.technique_ids,
            })
        }).collect();

        let mut api_stats: HashMap<String, u32> = HashMap::new();
        for b in &report.behaviors {
            for api in &b.apis {
                *api_stats.entry(api.clone()).or_insert(0) += 1;
            }
        }

        let network_hosts: Vec<String> = report.iocs.by_kind(&IocKind::Ip)
            .iter().map(|i| i.value.clone()).collect();
        let domains: Vec<Value> = report.iocs.by_kind(&IocKind::Domain)
            .iter().map(|i| json!({"ip": "", "domain": i.value})).collect();

        json!({
            "info": {
                "id": 1,
                "version": "2.0.7",
                "started": "2024-01-01T00:00:00",
                "ended": "2024-01-01T00:00:30",
                "duration": report.analysis_ms / 1000,
                "category": "file",
                "platform": self.platform,
                "score": f64::from(report.score) / 10.0,
            },
            "target": {
                "category": "file",
                "file": {
                    "name": report.sample,
                    "size": 0,
                    "sha256": report.sha256,
                    "md5": "",
                    "file_type": "PE32 executable",
                    "yara": [],
                }
            },
            "signatures": signatures,
            "behavior": {
                "processes": [],
                "summary": {
                    "files": report.iocs.by_kind(&IocKind::FilePath)
                        .iter().map(|i| i.value.clone()).collect::<Vec<_>>(),
                    "keys": report.iocs.by_kind(&IocKind::RegistryKey)
                        .iter().map(|i| i.value.clone()).collect::<Vec<_>>(),
                    "mutexes": report.iocs.by_kind(&IocKind::Mutex)
                        .iter().map(|i| i.value.clone()).collect::<Vec<_>>(),
                    "resolved_apis": report.behaviors.iter()
                        .flat_map(|b| b.apis.iter().cloned())
                        .collect::<Vec<_>>(),
                },
                "apistats": api_stats,
            },
            "network": {
                "hosts": network_hosts,
                "domains": domains,
                "tcp": [],
                "udp": [],
                "http": [],
                "dns": [],
            },
            "dropped": [],
            "static": {},
            "malfamily": report.family,
            "mist": {},
        })
    }

    fn to_any_run_value(&self, report: &SandboxReport) -> Value {
        let mitre: Vec<Value> = report.attack.techniques.iter()
            .map(|t| MitreTechnique::from_attack_technique(t).to_json())
            .collect();

        let threats: Vec<Value> = report.indicators.iter().map(|ind| json!({
            "name": ind.name,
            "category": ind.category.to_string(),
            "severity": ind.severity.to_string(),
            "description": ind.desc,
        })).collect();

        let ips: Vec<&str> = report.iocs.by_kind(&IocKind::Ip)
            .iter().map(|i| i.value.as_str()).collect();
        let domains: Vec<&str> = report.iocs.by_kind(&IocKind::Domain)
            .iter().map(|i| i.value.as_str()).collect();
        let urls: Vec<&str> = report.iocs.by_kind(&IocKind::Url)
            .iter().map(|i| i.value.as_str()).collect();
        let hashes: Vec<&str> = report.iocs.by_kind(&IocKind::FileHash)
            .iter().map(|i| i.value.as_str()).collect();

        let verdict_str = match report.verdict {
            Verdict::Clean => "no-threats",
            Verdict::Low => "low",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
            Verdict::Unknown => "unknown",
        };

        json!({
            "version": "any.run/2.0",
            "analysis": {
                "id": self.analysis_id.as_deref().unwrap_or("0"),
                "date": "2024-01-01T00:00:00Z",
                "uuid": self.analysis_id.as_deref().unwrap_or("00000000-0000-0000-0000-000000000000"),
                "score": report.score,
                "duration_ms": report.analysis_ms,
                "sandbox_type": self.sandbox_type,
                "os": self.platform,
            },
            "verdicts": {
                "score": report.score,
                "status": verdict_str,
                "tags": report.tags,
                "family": report.family,
            },
            "network": {
                "c2_servers": ips,
                "domains": domains,
                "urls": urls,
            },
            "threats": threats,
            "mitre": mitre,
            "iocs": {
                "ips": ips,
                "domains": domains,
                "urls": urls,
                "hashes": hashes,
                "files": report.iocs.by_kind(&IocKind::FilePath)
                    .iter().map(|i| i.value.as_str()).collect::<Vec<_>>(),
                "registry": report.iocs.by_kind(&IocKind::RegistryKey)
                    .iter().map(|i| i.value.as_str()).collect::<Vec<_>>(),
                "mutexes": report.iocs.by_kind(&IocKind::Mutex)
                    .iter().map(|i| i.value.as_str()).collect::<Vec<_>>(),
            }
        })
    }

    fn to_ioc_only_value(&self, report: &SandboxReport) -> Value {
        let mut all_ips: Vec<String> = report.iocs.by_kind(&IocKind::Ip)
            .iter().map(|i| i.value.clone()).collect();
        let mut all_domains: Vec<String> = report.iocs.by_kind(&IocKind::Domain)
            .iter().map(|i| i.value.clone()).collect();
        let mut all_hashes: Vec<String> = report.iocs.by_kind(&IocKind::FileHash)
            .iter().map(|i| i.value.clone()).collect();
        let mut all_paths: Vec<String> = report.iocs.by_kind(&IocKind::FilePath)
            .iter().map(|i| i.value.clone()).collect();
        let mut all_urls: Vec<String> = report.iocs.by_kind(&IocKind::Url)
            .iter().map(|i| i.value.clone()).collect();
        let mut all_reg: Vec<String> = report.iocs.by_kind(&IocKind::RegistryKey)
            .iter().map(|i| i.value.clone()).collect();
        let mut all_mutex: Vec<String> = report.iocs.by_kind(&IocKind::Mutex)
            .iter().map(|i| i.value.clone()).collect();

        if let Some(extra) = &self.extra_iocs {
            all_ips.extend(extra.ips.iter().cloned());
            all_domains.extend(extra.domains.iter().cloned());
            all_hashes.extend(extra.hashes.iter().cloned());
            all_paths.extend(extra.file_paths.iter().cloned());
            all_urls.extend(extra.urls.iter().cloned());
            all_reg.extend(extra.registry_keys.iter().cloned());
            all_mutex.extend(extra.mutexes.iter().cloned());
        }

        // Deduplicate all vectors.
        for v in [&mut all_ips, &mut all_domains, &mut all_hashes,
                  &mut all_paths, &mut all_urls, &mut all_reg, &mut all_mutex] {
            v.sort();
            v.dedup();
        }

        json!({
            "sample": report.sample,
            "sha256": report.sha256,
            "verdict": report.verdict.to_string(),
            "iocs": {
                "ip_addresses": all_ips,
                "domains": all_domains,
                "urls": all_urls,
                "file_hashes": all_hashes,
                "file_paths": all_paths,
                "registry_keys": all_reg,
                "mutexes": all_mutex,
            }
        })
    }

    fn to_stix_lite_value(report: &SandboxReport) -> Value {
        let bundle_id = format!("bundle--{}", report.sha256.get(..8).unwrap_or("00000000"));
        let indicator_id = format!("indicator--{}", &report.sha256);

        let attack_patterns: Vec<Value> = report.attack.techniques.iter().map(|t| {
            let full = t.full_id();
            json!({
                "type": "attack-pattern",
                "id": format!("attack-pattern--{}", full.to_lowercase().replace('.', "-")),
                "name": t.name,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": full,
                    "url": format!("https://attack.mitre.org/techniques/{}", full.replace('.', "/")),
                }],
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": t.tactic.to_string(),
                }],
            })
        }).collect();

        let observed_data: Vec<Value> = {
            let mut obs = Vec::new();
            for ioc in &report.iocs.iocs {
                let obj_type = match ioc.kind {
                    IocKind::Ip => "ipv4-addr",
                    IocKind::Domain => "domain-name",
                    IocKind::Url => "url",
                    IocKind::FileHash | IocKind::FilePath => "file",
                    IocKind::RegistryKey => "windows-registry-key",
                    IocKind::Mutex => "mutex",
                    IocKind::Email => "email-addr",
                    IocKind::Other(_) => "x-custom-observable",
                };
                obs.push(json!({
                    "type": "observed-data",
                    "id": format!("observed-data--{}", &report.sha256),
                    "first_observed": "2024-01-01T00:00:00Z",
                    "last_observed": "2024-01-01T00:00:00Z",
                    "number_observed": 1,
                    "object_refs": [{
                        "type": obj_type,
                        "value": ioc.value,
                    }],
                }));
            }
            obs
        };

        let malware_obj = json!({
            "type": "malware",
            "id": format!("malware--{}", &report.sha256),
            "name": if report.family.is_empty() { "unknown" } else { report.family.as_str() },
            "malware_types": [report.family],
            "is_family": false,
            "labels": report.tags,
        });

        json!({
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": {
                "indicator": {
                    "type": "indicator",
                    "id": indicator_id,
                    "name": report.sample,
                    "pattern": format!("[file:hashes.SHA256 = '{}']", report.sha256),
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "labels": ["malicious-activity"],
                },
                "malware": malware_obj,
                "attack_patterns": attack_patterns,
                "observed_data": observed_data,
            }
        })
    }

    fn serialize_ioc_set(ioc_set: &IocSet) -> Value {
        let mut grouped: HashMap<String, Vec<Value>> = HashMap::new();
        for ioc in &ioc_set.iocs {
            grouped.entry(ioc.kind.to_string()).or_default().push(json!({
                "value": ioc.value,
                "confidence": ioc.confidence,
                "context": ioc.context,
            }));
        }
        serde_json::to_value(grouped).unwrap_or_else(|_| json!({}))
    }

    /// Serialize the MITRE ATT&CK mapping from a report to JSON.
    #[must_use]
    pub fn serialize_attack_mapping(mapping: &AttackMapping) -> Value {
        let by_tactic: HashMap<String, Vec<Value>> = {
            let mut m: HashMap<String, Vec<Value>> = HashMap::new();
            for t in &mapping.techniques {
                m.entry(t.tactic.to_string())
                    .or_default()
                    .push(MitreTechnique::from_attack_technique(t).to_json());
            }
            m
        };

        json!({
            "total_techniques": mapping.techniques.len(),
            "tactics_covered": mapping.tactics_present(),
            "techniques": mapping.techniques.iter()
                .map(|t| MitreTechnique::from_attack_technique(t).to_json())
                .collect::<Vec<_>>(),
            "by_tactic": by_tactic,
        })
    }

    /// Convenience: serialize just IOCs to JSON (flat format).
    #[must_use]
    pub fn serialize_iocs_flat(
        ioc_set: &IocSet,
        extra: Option<&IocCollection>,
    ) -> Value {
        let mut ips: Vec<String> = ioc_set.by_kind(&IocKind::Ip).iter()
            .map(|i| i.value.clone()).collect();
        let mut domains: Vec<String> = ioc_set.by_kind(&IocKind::Domain).iter()
            .map(|i| i.value.clone()).collect();
        let mut urls: Vec<String> = ioc_set.by_kind(&IocKind::Url).iter()
            .map(|i| i.value.clone()).collect();
        let mut hashes: Vec<String> = ioc_set.by_kind(&IocKind::FileHash).iter()
            .map(|i| i.value.clone()).collect();

        if let Some(e) = extra {
            ips.extend(e.ips.iter().cloned());
            domains.extend(e.domains.iter().cloned());
            urls.extend(e.urls.iter().cloned());
            hashes.extend(e.hashes.iter().cloned());
        }

        ips.sort(); ips.dedup();
        domains.sort(); domains.dedup();
        urls.sort(); urls.dedup();
        hashes.sort(); hashes.dedup();

        json!({
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
        })
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new(JsonReportFormat::Native)
    }
}

// ─── MitreAttackMapper ────────────────────────────────────────────────────────

/// Maps observed behaviors to MITRE ATT&CK techniques and serializes them.
pub struct MitreAttackMapper {
    /// Custom technique overrides (id → evidence notes).
    overrides: HashMap<String, Vec<String>>,
}

impl MitreAttackMapper {
    #[must_use]
    pub fn new() -> Self {
        Self { overrides: HashMap::new() }
    }

    /// Add additional evidence for a technique.
    pub fn add_evidence(&mut self, technique_id: impl Into<String>, evidence: impl Into<String>) {
        self.overrides.entry(technique_id.into()).or_default().push(evidence.into());
    }

    /// Generate a full MITRE ATT&CK JSON report section from a `SandboxReport`.
    #[must_use]
    pub fn generate_attack_report(&self, report: &SandboxReport) -> Value {
        let mut techniques_by_tactic: HashMap<String, Vec<Value>> = HashMap::new();

        for t in &report.attack.techniques {
            let tactic = t.tactic.to_string();
            let mut evidence = t.evidence.clone();
            if let Some(extra) = self.overrides.get(t.full_id()) {
                evidence.extend(extra.iter().cloned());
            }

            let entry = json!({
                "technique_id": t.full_id(),
                "technique_name": t.name,
                "sub_technique": t.sub_id.as_deref().unwrap_or(""),
                "confidence": t.confidence,
                "evidence": evidence,
                "reference": format!("https://attack.mitre.org/techniques/{}", t.full_id().replace('.', "/")),
            });

            techniques_by_tactic.entry(tactic).or_default().push(entry);
        }

        // Navigator layer format (simplified).
        let navigator_techniques: Vec<Value> = report.attack.techniques.iter().map(|t| {
            json!({
                "techniqueID": t.full_id(),
                "tactic": t.tactic.to_string().replace('_', "-"),
                "color": match t.confidence {
                    90..=100 => "#ff6666",
                    70..=89 => "#ff9999",
                    _ => "#ffcccc",
                },
                "comment": t.evidence.first().cloned().unwrap_or_default(),
                "enabled": true,
                "score": t.confidence,
            })
        }).collect();

        json!({
            "schema_version": "rustre-attack/1.0",
            "sample": report.sample,
            "total_techniques": report.attack.techniques.len(),
            "tactics_covered": report.attack.tactics_present(),
            "by_tactic": techniques_by_tactic,
            "navigator_layer": {
                "name": format!("{} — ATT&CK", report.sample),
                "versions": {"layer": "4.4", "navigator": "4.8"},
                "domain": "enterprise-attack",
                "techniques": navigator_techniques,
            }
        })
    }
}

impl Default for MitreAttackMapper {
    fn default() -> Self { Self::new() }
}

// ─── Public helpers wiring crate-level types into the JSON serialization API ──

/// Serialize a [`Behavior`] to a JSON value (native shape).
#[must_use]
pub fn behavior_to_json(b: &Behavior) -> Value {
    json!({
        "name": b.name,
        "desc": b.desc,
        "severity": format!("{:?}", b.severity),
        "category": b.category,
        "pid": b.pid,
        "first_seen_ms": b.first_seen_ms,
        "apis": b.apis,
    })
}

/// Serialize an [`Indicator`] to a JSON value (native shape).
#[must_use]
pub fn indicator_to_json(i: &Indicator) -> Value {
    json!({
        "name": i.name,
        "desc": i.desc,
        "severity": format!("{:?}", i.severity),
        "ioc": i.ioc,
        "technique_ids": i.technique_ids,
        "category": format!("{}", i.category),
    })
}

/// Serialize an [`AttackTactic`] as a stable lowercase string.
#[must_use]
pub fn tactic_to_string(t: &AttackTactic) -> String {
    t.to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxReport;

    #[test]
    fn test_native_format() {
        let report = SandboxReport::mock();
        let json = JsonReporter::native().serialize(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["sample"].as_str().unwrap(), "malware.exe");
        assert!(v["attack_techniques"].is_array());
    }

    #[test]
    fn test_cuckoo_format() {
        let report = SandboxReport::mock();
        let json = JsonReporter::cuckoo().serialize(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["info"]["category"].as_str().unwrap(), "file");
        assert!(v["signatures"].is_array());
    }

    #[test]
    fn test_any_run_format() {
        let report = SandboxReport::mock();
        let json = JsonReporter::any_run().serialize(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["verdicts"]["score"].as_u64().is_some());
        assert!(v["mitre"].is_array());
    }

    #[test]
    fn test_ioc_only_format() {
        let report = SandboxReport::mock();
        let json = JsonReporter::new(JsonReportFormat::IocOnly).serialize(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["iocs"]["ip_addresses"].is_array());
    }

    #[test]
    fn test_stix_lite_format() {
        let report = SandboxReport::mock();
        let json = JsonReporter::new(JsonReportFormat::StixLite).serialize(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "bundle");
    }

    #[test]
    fn test_with_extra_iocs() {
        let report = SandboxReport::mock();
        let extra = IocCollection::mock();
        let json = JsonReporter::native()
            .with_ioc_collection(extra)
            .serialize(&report)
            .unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["extra_iocs"]["ips"].is_array());
    }

    #[test]
    fn test_attack_mapper() {
        let report = SandboxReport::mock();
        let mut mapper = MitreAttackMapper::new();
        mapper.add_evidence("T1055.001", "confirmed via memory scan");
        let v = mapper.generate_attack_report(&report);
        assert!(v["navigator_layer"]["techniques"].is_array());
    }

    #[test]
    fn test_serialize_iocs_flat() {
        let ioc_set = crate::IocSet::mock();
        let v = JsonReporter::serialize_iocs_flat(&ioc_set, None);
        assert!(v["ips"].is_array());
    }

    #[test]
    fn test_mitre_technique_url() {
        use crate::{AttackTactic};
        let t = AttackTechnique {
            id: "T1055".to_string(),
            sub_id: Some("T1055.001".to_string()),
            name: "DLL Injection".to_string(),
            tactic: AttackTactic::DefenseEvasion,
            evidence: vec!["test".to_string()],
            confidence: 90,
        };
        let mt = MitreTechnique::from_attack_technique(&t);
        assert!(mt.url.contains("T1055/001"));
    }
}
