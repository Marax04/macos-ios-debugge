//! `rustre-ti-correlate`
//!
//! `IoC` correlation engine for the `RustRE` Suite.
//! Finds relationships between Indicators of Compromise, malware families, and
//! threat actors within a collected dataset of [`ThreatReport`]s and standalone
//! [`IoC`]s.

pub mod actor_attribution;
pub mod attribution;
pub mod behavioral_clustering;
pub mod campaign_analysis;
pub mod campaign_correlation;
pub mod clustering;
pub mod graph_correlator;
pub mod temporal_analysis;
pub mod ttp_analysis;
pub mod sample_correlator;
pub mod campaign_detector;
pub mod ioc_graph;
pub mod ioc_correlator;
pub mod actor_tracker;
pub mod temporal_correlator;
pub mod campaign_tracker;
pub mod attribution_engine;

pub use ttp_analysis::{
    MitreTactic, MitreTtpMapping, TtpAnalysis, TtpCluster, TtpGraph, TtpReport, TtpTimeline,
};

pub use actor_attribution::{
    ActorAttributor, AttributionEvidence, AttributionResult, EvidenceKind,
};
pub use behavioral_clustering::{
    BehavioralClusterer, BehavioralFeature, BehavioralProfile, Cluster,
};
pub use campaign_correlation::{
    CampaignCorrelationEngine, CampaignLink, CampaignLinkKind, CampaignOverlap, OverlapCategory,
};
pub use rustre_threatintel::Ttp;

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use rustre_threatintel::{IoC, IoCType, ThreatReport};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CorrelationKind
// ---------------------------------------------------------------------------

/// The type of relationship identified between two `IoCs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationKind {
    /// Both `IoCs` appear in reports attributed to the same threat actor.
    SharedThreatActor,
    /// Both `IoCs` appear in reports attributed to the same malware family.
    SharedMalwareFamily,
    /// The hash values share a common prefix, suggesting a related sample set.
    SimilarHash,
    /// Both `IoCs` are network indicators sharing the same /24 or registrar.
    NetworkInfrastructure,
    /// Both domain `IoCs` share the same WHOIS registrar.
    SameRegistrar,
    /// Both `IoCs` share the same TLS/X.509 certificate fingerprint.
    SameCertificate,
    /// Both `IoCs` were observed within a narrow time window.
    TemporalProximity,
}

impl fmt::Display for CorrelationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SharedThreatActor => "Shared Threat Actor",
            Self::SharedMalwareFamily => "Shared Malware Family",
            Self::SimilarHash => "Similar Hash",
            Self::NetworkInfrastructure => "Network Infrastructure",
            Self::SameRegistrar => "Same Registrar",
            Self::SameCertificate => "Same Certificate",
            Self::TemporalProximity => "Temporal Proximity",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

/// A directed correlation between two `IoCs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    /// First `IoC` in the pair.
    pub ioc_a: IoC,
    /// Second `IoC` in the pair.
    pub ioc_b: IoC,
    /// The kind of relationship that was detected.
    pub kind: CorrelationKind,
    /// Analyst confidence in this correlation, [0, 100].
    pub confidence: u8,
    /// Human-readable evidence summary.
    pub evidence: String,
}

impl Correlation {
    /// Return `true` if this correlation meets or exceeds the given confidence threshold.
    #[must_use]
    pub const fn meets_threshold(&self, min_confidence: u8) -> bool {
        self.confidence >= min_confidence
    }
}

impl fmt::Display for Correlation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} <-> {} [{}] confidence={}",
            self.ioc_a.value, self.ioc_b.value, self.kind, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// CorrelationEngine
// ---------------------------------------------------------------------------

/// Engine that correlates `IoCs` and threat intelligence reports.
pub struct CorrelationEngine {
    iocs: Vec<IoC>,
    reports: Vec<ThreatReport>,
}

impl CorrelationEngine {
    /// Create an empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            iocs: Vec::new(),
            reports: Vec::new(),
        }
    }

    /// Add a standalone `IoC` to the dataset.
    pub fn add_ioc(&mut self, ioc: IoC) {
        self.iocs.push(ioc);
    }

    /// Add a threat report to the dataset.
    ///
    /// `IoCs` embedded in the report are also indexed for correlation.
    pub fn add_report(&mut self, report: ThreatReport) {
        self.reports.push(report);
    }

    /// Compute correlations across all `IoCs` in the dataset.
    ///
    /// Returns every correlation that could be detected.
    #[must_use]
    pub fn correlate_all(&self) -> Vec<Correlation> {
        let all_iocs = self.all_iocs();
        let mut correlations = Vec::new();
        for i in 0..all_iocs.len() {
            for j in (i + 1)..all_iocs.len() {
                if let Some(c) = self.correlate_pair(&all_iocs[i], &all_iocs[j]) {
                    correlations.push(c);
                }
            }
        }
        // Also check shared families / actors via reports.
        correlations.extend(self.report_correlations());
        correlations
    }

    /// Return all correlations that involve the given `IoC`.
    #[must_use]
    pub fn find_related(&self, ioc: &IoC) -> Vec<Correlation> {
        self.correlate_all()
            .into_iter()
            .filter(|c| c.ioc_a.value == ioc.value || c.ioc_b.value == ioc.value)
            .collect()
    }

    /// Group all `IoCs` by the malware families they appear in across all reports.
    ///
    /// `IoCs` not referenced by any report are placed under the `"uncategorised"`
    /// key.
    #[must_use]
    pub fn cluster_by_family(&self) -> HashMap<String, Vec<IoC>> {
        let mut clusters: HashMap<String, Vec<IoC>> = HashMap::new();
        for report in &self.reports {
            let families = if report.malware_families.is_empty() {
                vec!["uncategorised".to_string()]
            } else {
                report.malware_families.clone()
            };
            for family in &families {
                let entry = clusters.entry(family.clone()).or_default();
                for ioc in &report.iocs {
                    if !entry.iter().any(|e: &IoC| e.value == ioc.value) {
                        entry.push(ioc.clone());
                    }
                }
            }
        }
        // Standalone IoCs with no report go to uncategorised.
        let entry = clusters.entry("uncategorised".to_string()).or_default();
        for ioc in &self.iocs {
            if !entry.iter().any(|e: &IoC| e.value == ioc.value) {
                entry.push(ioc.clone());
            }
        }
        clusters
    }

    /// Return only correlations whose confidence meets the given threshold.
    #[must_use]
    pub fn high_confidence_correlations(&self, min_confidence: u8) -> Vec<Correlation> {
        self.correlate_all()
            .into_iter()
            .filter(|c| c.meets_threshold(min_confidence))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Collect every `IoC` from the engine — both standalone and from reports.
    fn all_iocs(&self) -> Vec<IoC> {
        let mut result = self.iocs.clone();
        for report in &self.reports {
            for ioc in &report.iocs {
                if !result.iter().any(|e| e.value == ioc.value) {
                    result.push(ioc.clone());
                }
            }
        }
        result
    }

    /// Try to find a correlation between two `IoCs` based on their intrinsic
    /// properties (hash similarity, network neighbourhood, temporal proximity,
    /// etc.).  Each pair is checked against all applicable strategies; the
    /// first match is returned.
    fn correlate_pair(&self, a: &IoC, b: &IoC) -> Option<Correlation> {
        // Same value → no correlation (deduplication, not a finding).
        if a.value == b.value {
            return None;
        }

        let mut candidates: Vec<Correlation> = Vec::new();

        // Both are hashes — check prefix similarity.
        if a.is_hash() && b.is_hash() {
            if let Some(c) = Self::hash_correlation(a, b) {
                candidates.push(c);
            }
        }

        // Both are network indicators.
        if a.is_network() && b.is_network() {
            if let Some(c) = Self::network_correlation(a, b) {
                candidates.push(c);
            }
        }

        // Temporal proximity when both carry timestamps (any IoC type).
        if a.first_seen > 0 && b.first_seen > 0 {
            if let Some(c) = Self::temporal_correlation(a, b) {
                candidates.push(c);
            }
        }

        // Return the correlation with the highest confidence so callers always
        // receive the strongest signal; temporal proximity is not suppressed for
        // pairs that also match a structural rule.
        candidates.into_iter().max_by_key(|c| c.confidence)
    }

    /// Detect similar hashes (shared 8-char prefix → possible variant samples).
    fn hash_correlation(a: &IoC, b: &IoC) -> Option<Correlation> {
        const MIN_PREFIX: usize = 8;
        if a.value.len() >= MIN_PREFIX
            && b.value.len() >= MIN_PREFIX
            && a.value.is_char_boundary(MIN_PREFIX)
            && b.value.is_char_boundary(MIN_PREFIX)
            && a.value[..MIN_PREFIX].eq_ignore_ascii_case(&b.value[..MIN_PREFIX])
        {
            Some(Correlation {
                ioc_a: a.clone(),
                ioc_b: b.clone(),
                kind: CorrelationKind::SimilarHash,
                confidence: 60,
                evidence: format!(
                    "Hashes share first {} characters: {}",
                    MIN_PREFIX,
                    a.value[..MIN_PREFIX].to_ascii_lowercase()
                ),
            })
        } else {
            None
        }
    }

    /// Detect network `IoCs` sharing the same /24 subnet or domain suffix.
    fn network_correlation(a: &IoC, b: &IoC) -> Option<Correlation> {
        // Same /24 for IPs.
        if a.ioc_type == IoCType::Ip && b.ioc_type == IoCType::Ip {
            let prefix_a = ip_prefix_24(&a.value);
            let prefix_b = ip_prefix_24(&b.value);
            if let (Some(pa), Some(pb)) = (prefix_a, prefix_b)
                && pa == pb {
                    return Some(Correlation {
                        ioc_a: a.clone(),
                        ioc_b: b.clone(),
                        kind: CorrelationKind::NetworkInfrastructure,
                        confidence: 70,
                        evidence: format!("Both IPs share /24 prefix: {pa}"),
                    });
                }
        }

        // Shared parent domain (same eTLD+1).
        if matches!(a.ioc_type, IoCType::Domain | IoCType::Url)
            && matches!(b.ioc_type, IoCType::Domain | IoCType::Url)
        {
            let pa = parent_domain(&a.value);
            let pb = parent_domain(&b.value);
            if !pa.is_empty() && pa == pb && pa != a.value && pa != b.value {
                return Some(Correlation {
                    ioc_a: a.clone(),
                    ioc_b: b.clone(),
                    kind: CorrelationKind::NetworkInfrastructure,
                    confidence: 65,
                    evidence: format!("Both domains share parent: {pa}"),
                });
            }
        }
        None
    }

    /// Detect `IoCs` observed within a 24-hour window.
    fn temporal_correlation(a: &IoC, b: &IoC) -> Option<Correlation> {
        const WINDOW_SECS: u64 = 86_400;
        let diff = a.first_seen.abs_diff(b.first_seen);
        if diff <= WINDOW_SECS {
            Some(Correlation {
                ioc_a: a.clone(),
                ioc_b: b.clone(),
                kind: CorrelationKind::TemporalProximity,
                confidence: 40,
                evidence: format!(
                    "Both IoCs were first seen within {diff} seconds of each other"
                ),
            })
        } else {
            None
        }
    }

    /// Find `IoC` pairs that share threat actor or malware family via reports.
    fn report_correlations(&self) -> Vec<Correlation> {
        let mut correlations = Vec::new();

        // Build actor → IoC list.
        let mut actor_to_iocs: HashMap<String, Vec<IoC>> = HashMap::new();
        for report in &self.reports {
            for actor in &report.threat_actors {
                let entry = actor_to_iocs.entry(actor.clone()).or_default();
                for ioc in &report.iocs {
                    if !entry.iter().any(|e: &IoC| e.value == ioc.value) {
                        entry.push(ioc.clone());
                    }
                }
            }
        }
        for (actor, iocs) in &actor_to_iocs {
            for i in 0..iocs.len() {
                for j in (i + 1)..iocs.len() {
                    correlations.push(Correlation {
                        ioc_a: iocs[i].clone(),
                        ioc_b: iocs[j].clone(),
                        kind: CorrelationKind::SharedThreatActor,
                        confidence: 75,
                        evidence: format!(
                            "Both IoCs appear in reports attributed to actor: {actor}"
                        ),
                    });
                }
            }
        }

        // Build family → IoC list.
        let mut family_to_iocs: HashMap<String, Vec<IoC>> = HashMap::new();
        for report in &self.reports {
            for family in &report.malware_families {
                let entry = family_to_iocs.entry(family.clone()).or_default();
                for ioc in &report.iocs {
                    if !entry.iter().any(|e: &IoC| e.value == ioc.value) {
                        entry.push(ioc.clone());
                    }
                }
            }
        }
        for (family, iocs) in &family_to_iocs {
            for i in 0..iocs.len() {
                for j in (i + 1)..iocs.len() {
                    correlations.push(Correlation {
                        ioc_a: iocs[i].clone(),
                        ioc_b: iocs[j].clone(),
                        kind: CorrelationKind::SharedMalwareFamily,
                        confidence: 80,
                        evidence: format!("Both IoCs appear in reports for family: {family}"),
                    });
                }
            }
        }

        correlations
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CorrelationEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CorrelationEngine")
            .field("ioc_count", &self.iocs.len())
            .field("report_count", &self.reports.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

/// Extract the /24 prefix from a dotted-decimal IPv4 address.
fn ip_prefix_24(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// Return the last two labels of a domain (eTLD+1 approximation).
fn parent_domain(s: &str) -> String {
    // Minimal multi-label TLD handling (e.g. co.uk, com.au). Not a full PSL,
    // but avoids the common false positive of returning "co.uk" as eTLD+1.
    const MULTI_LABEL_TLDS: &[&str] = &[
        "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "ne.jp", "or.jp",
        "co.kr", "com.au", "net.au", "org.au", "gov.au", "com.br", "com.cn",
        "com.mx", "co.in", "co.nz", "co.za",
    ];
    // Strip URL scheme / path if present.
    let host = s
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(s);
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 3 {
        let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
        if MULTI_LABEL_TLDS.contains(&last_two.as_str()) {
            return format!("{}.{}", labels[labels.len() - 3], last_two);
        }
    }
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

// ---------------------------------------------------------------------------
// MitreAttackDb — static data tables
// ---------------------------------------------------------------------------

/// (api_name, tactic, technique) triples for `map_api_to_technique`.
const API_TECHNIQUE_MAP: &[(&str, &str, &str)] = &[
    ("CreateRemoteThread",      "Defense Evasion",    "T1055 Process Injection"),
    ("WriteProcessMemory",      "Defense Evasion",    "T1055 Process Injection"),
    ("VirtualAllocEx",          "Defense Evasion",    "T1055 Process Injection"),
    ("VirtualProtect",          "Defense Evasion",    "T1055 Process Injection"),
    ("NtUnmapViewOfSection",    "Defense Evasion",    "T1055.012 Process Hollowing"),
    ("RegSetValueEx",           "Persistence",        "T1547.001 Registry Run Keys"),
    ("RegOpenKeyEx",            "Persistence",        "T1547.001 Registry Run Keys"),
    ("RegCreateKeyEx",          "Persistence",        "T1547.001 Registry Run Keys"),
    ("CreateService",           "Persistence",        "T1543.003 Windows Service"),
    ("StartService",            "Persistence",        "T1543.003 Windows Service"),
    ("ChangeServiceConfig",     "Persistence",        "T1543.003 Windows Service"),
    ("URLDownloadToFile",       "Command and Control","T1105 Ingress Tool Transfer"),
    ("InternetReadFile",        "Command and Control","T1105 Ingress Tool Transfer"),
    ("WinHttpSendRequest",      "Command and Control","T1071.001 Web Protocols"),
    ("HttpSendRequest",         "Command and Control","T1071.001 Web Protocols"),
    ("InternetOpenUrl",         "Command and Control","T1071.001 Web Protocols"),
    ("socket",                  "Command and Control","T1095 Non-Application Layer Protocol"),
    ("connect",                 "Command and Control","T1095 Non-Application Layer Protocol"),
    ("send",                    "Command and Control","T1095 Non-Application Layer Protocol"),
    ("CryptEncrypt",            "Impact",             "T1486 Data Encrypted for Impact"),
    ("FindFirstFile",           "Impact",             "T1486 Data Encrypted for Impact"),
    ("MoveFile",                "Impact",             "T1486 Data Encrypted for Impact"),
    ("CryptGenKey",             "Impact",             "T1486 Data Encrypted for Impact"),
    ("EnumProcesses",           "Discovery",          "T1057 Process Discovery"),
    ("Process32First",          "Discovery",          "T1057 Process Discovery"),
    ("Process32Next",           "Discovery",          "T1057 Process Discovery"),
    ("GetSystemInfo",           "Discovery",          "T1082 System Information Discovery"),
    ("NtQuerySystemInformation","Discovery",          "T1082 System Information Discovery"),
    ("RtlGetVersion",           "Discovery",          "T1082 System Information Discovery"),
    ("IsDebuggerPresent",       "Defense Evasion",    "T1622 Debugger Evasion"),
    ("CheckRemoteDebuggerPresent","Defense Evasion",  "T1622 Debugger Evasion"),
    ("NtQueryInformationProcess","Defense Evasion",   "T1622 Debugger Evasion"),
    ("WNetAddConnection",       "Lateral Movement",   "T1021 Remote Services"),
    ("WNetAddConnection2",      "Lateral Movement",   "T1021 Remote Services"),
    ("OpenProcess",             "Credential Access",  "T1003 OS Credential Dumping"),
    ("ReadProcessMemory",       "Credential Access",  "T1003 OS Credential Dumping"),
    ("SamQueryInformationUser", "Credential Access",  "T1003.002 SAM Database"),
    ("SamOpenDomain",           "Credential Access",  "T1003.002 SAM Database"),
    ("GetClipboardData",        "Collection",         "T1115 Clipboard Data"),
    ("OpenClipboard",           "Collection",         "T1115 Clipboard Data"),
    ("keybd_event",             "Collection",         "T1056.001 Keylogging"),
    ("SetWindowsHookEx",        "Collection",         "T1056.001 Keylogging"),
    ("GetAsyncKeyState",        "Collection",         "T1056.001 Keylogging"),
    ("DeleteFile",              "Defense Evasion",    "T1070.004 File Deletion"),
    ("DeleteFileA",             "Defense Evasion",    "T1070.004 File Deletion"),
    ("DeleteFileW",             "Defense Evasion",    "T1070.004 File Deletion"),
    ("ShellExecute",            "Execution",          "T1059 Command and Scripting Interpreter"),
    ("WinExec",                 "Execution",          "T1059 Command and Scripting Interpreter"),
    ("CreateProcess",           "Execution",          "T1059 Command and Scripting Interpreter"),
    ("LoadLibrary",             "Defense Evasion",    "T1574 Hijack Execution Flow"),
    ("LoadLibraryEx",           "Defense Evasion",    "T1574 Hijack Execution Flow"),
    ("GetProcAddress",          "Defense Evasion",    "T1027 Obfuscated Files"),
    ("LdrGetProcedureAddress",  "Defense Evasion",    "T1027 Obfuscated Files"),
    ("CreateMutex",             "Defense Evasion",    "T1480 Execution Guardrails"),
    ("CreateMutexEx",           "Defense Evasion",    "T1480 Execution Guardrails"),
    ("FindNextFile",            "Discovery",          "T1083 File and Directory Discovery"),
    ("BitBlt",                  "Collection",         "T1113 Screen Capture"),
    ("GetDC",                   "Collection",         "T1113 Screen Capture"),
    ("FtpPutFile",              "Exfiltration",       "T1048 Exfiltration Over Alternative Protocol"),
    ("SetFileTime",             "Defense Evasion",    "T1070.006 Timestomp"),
    ("SetDllDirectory",         "Defense Evasion",    "T1574.002 DLL Side-Loading"),
    ("ImpersonateLoggedOnUser", "Privilege Escalation","T1134.001 Token Impersonation"),
    ("DuplicateToken",          "Privilege Escalation","T1134 Access Token Manipulation"),
    ("AdjustTokenPrivileges",   "Privilege Escalation","T1134 Access Token Manipulation"),
];

const RANSOMWARE_APIS: &[&str] = &[
    "CryptEncrypt","CryptGenKey","CryptAcquireContext","FindFirstFile","FindNextFile",
    "MoveFile","MoveFileEx","DeleteFile","SetEndOfFile","CreateFile","WriteFile","ReadFile",
    "RegSetValueEx","ExitProcess","MessageBox","CryptImportKey","CryptExportKey",
    "CryptDestroyKey","CreateMutex","GetSystemDriveW",
];
const KEYLOGGER_APIS: &[&str] = &[
    "SetWindowsHookEx","GetAsyncKeyState","keybd_event","GetKeyState","GetKeyboardState",
    "RegisterHotKey","UnhookWindowsHookEx","CallNextHookEx","GetForegroundWindow",
    "GetWindowText","OpenClipboard","GetClipboardData","WriteFile","CreateFile","GetClassNameA",
];
const RAT_APIS: &[&str] = &[
    "WinHttpOpen","WinHttpSendRequest","HttpSendRequest","InternetOpen","InternetConnect",
    "InternetOpenUrl","socket","connect","send","recv","WSAStartup","CreateProcess",
    "ShellExecute","GetDesktopWindow","BitBlt","GetDC","CreateRemoteThread","WriteProcessMemory",
    "VirtualAllocEx","SetWindowsHookEx","URLDownloadToFile","GetClipboardData",
    "EnumProcesses","OpenProcess",
];
const DROPPER_APIS: &[&str] = &[
    "URLDownloadToFile","InternetOpenUrl","InternetReadFile","WinHttpSendRequest",
    "CreateFile","WriteFile","WinExec","ShellExecute","CreateProcess","LoadLibrary",
    "GetTempPath","GetTempFileName","CopyFile","MoveFile","SetFileAttributes","CreateMutex",
    "RegSetValueEx","GetModuleFileName","GetCurrentDirectory","FindResource",
];
const INJECTOR_APIS: &[&str] = &[
    "OpenProcess","VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "NtUnmapViewOfSection","NtWriteVirtualMemory","SetThreadContext","ResumeThread",
    "SuspendThread","CreateProcess","VirtualProtect","LoadLibrary","GetProcAddress",
    "ZwCreateSection","MapViewOfSection","NtCreateSection","RtlCreateUserThread","QueueUserAPC",
];
const WORM_APIS: &[&str] = &[
    "WNetEnumResource","WNetOpenEnum","WNetAddConnection","WNetAddConnection2",
    "NetShareEnum","NetShareAdd","CopyFile","CreateFile","WriteFile","FindFirstFile",
    "FindNextFile","socket","connect","send","recv","InternetConnect","URLDownloadToFile",
    "CreateProcess","RegSetValueEx","GetSystemInfo",
];
const INFOSTEALER_APIS: &[&str] = &[
    "RegOpenKeyEx","RegQueryValueEx","CryptUnprotectData","SamQueryInformationUser",
    "SamOpenDomain","LsaOpenPolicy","ReadProcessMemory","OpenProcess","GetClipboardData",
    "OpenClipboard","FindFirstFile","FindNextFile","GetEnvironmentVariable","sqlite3_open",
    "InternetOpen","WinHttpSendRequest","send","CryptDecrypt","GetUserNameA","GetComputerNameA",
];
/// (family_name, api_list) pairs for malware classification.
const MALWARE_FAMILIES: &[(&str, &[&str])] = &[
    ("Ransomware",  RANSOMWARE_APIS),
    ("Keylogger",   KEYLOGGER_APIS),
    ("RAT",         RAT_APIS),
    ("Dropper",     DROPPER_APIS),
    ("Injector",    INJECTOR_APIS),
    ("Worm",        WORM_APIS),
    ("InfoStealer", INFOSTEALER_APIS),
];

// ---------------------------------------------------------------------------
// MitreAttackDb
// ---------------------------------------------------------------------------

/// Static database of Windows API names mapped to MITRE ATT&CK tactics and
/// technique identifiers.
///
/// The mapping covers the 30+ most commonly abused APIs seen in malware
/// triage, including process injection, persistence, C2, credential access,
/// discovery, and defence evasion techniques.
pub struct MitreAttackDb;

impl MitreAttackDb {
    /// Return every (tactic, technique) pair that the given API name is
    /// associated with.  Returns an empty `Vec` when the API is not in the
    /// database.
    ///
    /// Both `tactic` and `technique` are human-readable strings, e.g.:
    /// `("Defense Evasion", "T1055 Process Injection")`.
    #[must_use]
    pub fn map_api_to_technique(api_name: &str) -> Vec<(String, String)> {
        API_TECHNIQUE_MAP
            .iter()
            .filter(|(api, _, _)| api.eq_ignore_ascii_case(api_name))
            .map(|(_, tactic, technique)| ((*tactic).to_string(), (*technique).to_string()))
            .collect()
    }

    /// Query all techniques associated with a slice of API names, deduplicating
    /// results.  Returns a sorted, unique list of `(tactic, technique)` pairs.
    #[must_use]
    pub fn map_apis_to_techniques(api_names: &[&str]) -> Vec<(String, String)> {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for api in api_names {
            for pair in Self::map_api_to_technique(api) {
                seen.insert(pair);
            }
        }
        let mut result: Vec<_> = seen.into_iter().collect();
        result.sort();
        result
    }
}

// ---------------------------------------------------------------------------
// CorrelationNode
// ---------------------------------------------------------------------------

/// A typed node in the [`CorrelationGraph`].
///
/// Each variant wraps the string identifier for that node kind so the graph
/// can hold heterogeneous entities — hashes, IPs, domains, families, actors,
/// campaigns, and ATT&CK techniques — in a single structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorrelationNode {
    /// A file hash (MD5 / SHA-1 / SHA-256 / imphash …).
    Hash(String),
    /// An IP address (v4 or v6).
    Ip(String),
    /// A domain name.
    Domain(String),
    /// A malware family label.
    Family(String),
    /// A threat actor or APT group name.
    ThreatActor(String),
    /// A named campaign.
    Campaign(String),
    /// A MITRE ATT&CK technique identifier, e.g. `"T1055 Process Injection"`.
    Technique(String),
}

impl CorrelationNode {
    /// Return the raw string key regardless of variant.
    #[must_use]
    pub const fn key(&self) -> &str {
        match self {
            Self::Hash(s)
            | Self::Ip(s)
            | Self::Domain(s)
            | Self::Family(s)
            | Self::ThreatActor(s)
            | Self::Campaign(s)
            | Self::Technique(s) => s.as_str(),
        }
    }

    /// Return a short tag string describing the variant ("hash", "ip", …).
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Hash(_) => "hash",
            Self::Ip(_) => "ip",
            Self::Domain(_) => "domain",
            Self::Family(_) => "family",
            Self::ThreatActor(_) => "actor",
            Self::Campaign(_) => "campaign",
            Self::Technique(_) => "technique",
        }
    }
}

impl fmt::Display for CorrelationNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind_label(), self.key())
    }
}

// ---------------------------------------------------------------------------
// CorrelationGraph
// ---------------------------------------------------------------------------

/// A directed graph where nodes are [`CorrelationNode`]s and edges carry a
/// free-form relation label (e.g. `"uses"`, `"attributed_to"`, `"drops"`).
///
/// Backed by [`petgraph::Graph`] for efficient traversal.  Node indices are
/// maintained in an internal look-up table keyed by `(kind_label, key)` so
/// that duplicate insertions are elided.
pub struct CorrelationGraph {
    graph: petgraph::Graph<CorrelationNode, String>,
    /// (`kind_label`, key) → `NodeIndex`
    index: HashMap<(String, String), petgraph::graph::NodeIndex>,
}

impl CorrelationGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: petgraph::Graph::new(),
            index: HashMap::new(),
        }
    }

    /// Add a directed edge between `from` and `to` with the given `relation`
    /// label.  Nodes that do not yet exist are inserted automatically.
    pub fn add_correlation(
        &mut self,
        from: CorrelationNode,
        to: CorrelationNode,
        relation: String,
    ) {
        let from_idx = self.get_or_insert(from);
        let to_idx = self.get_or_insert(to);
        self.graph.add_edge(from_idx, to_idx, relation);
    }

    /// Return the string keys of all nodes reachable from any node whose key
    /// matches `node_key` (case-insensitive substring search), via a
    /// breadth-first traversal.
    ///
    /// The starting node itself is excluded from the result.
    #[must_use]
    pub fn find_related(&self, node_key: &str) -> Vec<String> {
        use petgraph::visit::Bfs;

        // Collect all source nodes that match the key.
        let needle = node_key.to_ascii_lowercase();
        let start_indices: Vec<petgraph::graph::NodeIndex> = self
            .index
            .iter()
            .filter(|((_, k), _)| k.to_ascii_lowercase().contains(&needle))
            .map(|(_, idx)| *idx)
            .collect();

        let mut visited: std::collections::HashSet<petgraph::graph::NodeIndex> =
            start_indices.iter().copied().collect();
        let mut result: Vec<String> = Vec::new();

        for start in start_indices {
            let mut bfs = Bfs::new(&self.graph, start);
            while let Some(nx) = bfs.next(&self.graph) {
                if visited.insert(nx) {
                    result.push(self.graph[nx].key().to_string());
                }
            }
        }

        result.sort();
        result.dedup();
        result
    }

    /// Serialise the graph to a Graphviz DOT string.
    ///
    /// Node shapes are chosen by variant: hashes → box, IPs → ellipse,
    /// domains → diamond, families/actors/campaigns → hexagon, techniques →
    /// note.
    ///
    /// # Panics
    ///
    /// Panics if an edge index is invalid (should not happen in practice).
    #[must_use]
    pub fn export_dot(&self) -> String {
        let mut dot = String::from(
            "digraph correlation {\n    rankdir=LR;\n    node [fontname=\"Helvetica\"];\n",
        );

        // Node definitions with labels and shapes.
        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let shape = match node {
                CorrelationNode::Hash(_) => "box",
                CorrelationNode::Ip(_) => "ellipse",
                CorrelationNode::Domain(_) => "diamond",
                CorrelationNode::Family(_)
                | CorrelationNode::ThreatActor(_)
                | CorrelationNode::Campaign(_) => "hexagon",
                CorrelationNode::Technique(_) => "note",
            };
            let label = escape_dot(node.key());
            use std::fmt::Write as _;
            let _ = write!(
                dot,
                "    n{} [label=\"{}\", shape={}, style=filled, fillcolor=\"{}\"];\n",
                idx.index(),
                label,
                shape,
                node_color(node),
            );
        }

        // Edge definitions.
        for edge in self.graph.edge_indices() {
            let (src, dst) = self.graph.edge_endpoints(edge).expect("valid edge");
            let label = escape_dot(
                self.graph
                    .edge_weight(edge)
                    .map_or("", String::as_str),
            );
            let _ = write!(
                dot,
                "    n{} -> n{} [label=\"{}\"];\n",
                src.index(),
                dst.index(),
                label,
            );
        }

        dot.push('}');
        dot
    }

    /// Return the number of nodes in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Return the number of edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn get_or_insert(&mut self, node: CorrelationNode) -> petgraph::graph::NodeIndex {
        let key = (node.kind_label().to_string(), node.key().to_string());
        if let Some(&idx) = self.index.get(&key) {
            return idx;
        }
        let idx = self.graph.add_node(node);
        self.index.insert(key, idx);
        idx
    }
}

impl Default for CorrelationGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CorrelationGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CorrelationGraph")
            .field("nodes", &self.graph.node_count())
            .field("edges", &self.graph.edge_count())
            .finish_non_exhaustive()
    }
}

/// Escape a string for use as a DOT label (double-quotes and backslashes).
fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Choose a fill colour for a DOT node based on its variant.
const fn node_color(node: &CorrelationNode) -> &'static str {
    match node {
        CorrelationNode::Hash(_) => "#d0e8ff",
        CorrelationNode::Ip(_) => "#ffd0d0",
        CorrelationNode::Domain(_) => "#d0ffd0",
        CorrelationNode::Family(_) => "#ffe8b0",
        CorrelationNode::ThreatActor(_) => "#f0b0f0",
        CorrelationNode::Campaign(_) => "#b0f0f0",
        CorrelationNode::Technique(_) => "#ffe0b0",
    }
}

// ---------------------------------------------------------------------------
// FamilyClassifier
// ---------------------------------------------------------------------------

/// Heuristic classifier that estimates the most likely malware family category
/// from a list of API call names observed during static or dynamic analysis.
///
/// Each family is scored by how many of its characteristic APIs appear in the
/// input list.  The family with the highest score (above a minimum threshold)
/// is returned; when no family reaches the threshold, `"Unknown"` is returned.
pub struct FamilyClassifier;

impl FamilyClassifier {
    /// Classify a set of API call strings into one of the known family
    /// categories: `"Ransomware"`, `"Keylogger"`, `"RAT"`, `"Dropper"`,
    /// `"Injector"`, `"Worm"`, `"InfoStealer"`, or `"Unknown"`.
    ///
    /// Matching is case-insensitive.
    #[must_use]
    pub fn classify(api_calls: &[String]) -> String {
        let call_set: std::collections::HashSet<String> =
            api_calls.iter().map(|s| s.to_ascii_lowercase()).collect();
        let has = |api: &str| -> bool { call_set.contains(&api.to_ascii_lowercase()) };
        let min_score = 3usize;
        let mut best_family = "Unknown";
        let mut best_score = 0usize;
        for &(family, indicators) in MALWARE_FAMILIES {
            let score = indicators.iter().filter(|&&api| has(api)).count();
            if score > best_score {
                best_score = score;
                best_family = family;
            }
        }
        if best_score >= min_score {
            best_family.to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Compute a per-family score breakdown for diagnostic purposes.
    ///
    /// Returns a `Vec` of `(family_name, score)` pairs sorted by score
    /// descending.
    #[must_use]
    pub fn score_breakdown(api_calls: &[String]) -> Vec<(String, usize)> {
        let call_set: std::collections::HashSet<String> =
            api_calls.iter().map(|s| s.to_ascii_lowercase()).collect();
        let has = |api: &str| -> bool { call_set.contains(&api.to_ascii_lowercase()) };
        let mut scores: Vec<(String, usize)> = MALWARE_FAMILIES
            .iter()
            .map(|&(name, indicators)| {
                let score = indicators.iter().filter(|&&api| has(api)).count();
                (name.to_string(), score)
            })
            .collect();
        scores.sort_by(|a, b| b.1.cmp(&a.1));
        scores
    }
}

// ---------------------------------------------------------------------------
// deduplicate_iocs
// ---------------------------------------------------------------------------

/// Remove exact duplicates from a list of `IoCs`, normalising values so that:
/// - domain and URL values are lower-cased
/// - hash values (MD5 / SHA-1 / SHA-256 / SHA-512) are upper-cased
///
/// Two `IoCs` are considered duplicates when they have the same `ioc_type` and
/// the same *normalised* value.  The first occurrence wins.
#[must_use]
pub fn deduplicate_iocs(iocs: Vec<IoC>) -> Vec<IoC> {
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut result: Vec<IoC> = Vec::with_capacity(iocs.len());
    for mut ioc in iocs {
        // Normalise in-place.
        ioc.value = normalise_ioc_value(&ioc.ioc_type, &ioc.value);
        let key = (ioc.ioc_type.as_str().to_string(), ioc.value.clone());
        if seen.insert(key) {
            result.push(ioc);
        }
    }
    result
}

/// Apply canonical form to an `IoC` value depending on its type.
fn normalise_ioc_value(ioc_type: &IoCType, value: &str) -> String {
    match ioc_type {
        IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 | IoCType::Sha512 => {
            value.to_ascii_uppercase()
        }
        IoCType::Domain | IoCType::Url | IoCType::Email => value.to_ascii_lowercase(),
        _ => value.to_string(),
    }
}

// ---------------------------------------------------------------------------
// CorrelationResult  (cross-source)
// ---------------------------------------------------------------------------

/// Result returned by [`correlate_across_sources`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// `IoCs` that appear in more than one source, together with the list of
    /// source indices in which they were found.
    pub multi_source_iocs: Vec<(IoC, Vec<usize>)>,
    /// Total number of unique `IoCs` examined.
    pub total_unique: usize,
    /// Number of sources examined.
    pub source_count: usize,
}

impl CorrelationResult {
    /// Return only `IoCs` that appear in at least `min_sources` sources.
    #[must_use]
    pub fn filter_by_min_sources(&self, min_sources: usize) -> Vec<&IoC> {
        self.multi_source_iocs
            .iter()
            .filter(|(_, srcs)| srcs.len() >= min_sources)
            .map(|(ioc, _)| ioc)
            .collect()
    }

    /// Return the maximum number of sources any single `IoC` was found in.
    #[must_use]
    pub fn max_source_count(&self) -> usize {
        self.multi_source_iocs
            .iter()
            .map(|(_, s)| s.len())
            .max()
            .unwrap_or(0)
    }
}

/// Find `IoCs` that appear in multiple sources (slices).
///
/// Normalises all values before comparison so that casing differences are not
/// treated as distinct indicators.
///
/// Returns a [`CorrelationResult`] where each entry in `multi_source_iocs`
/// lists the *source indices* that contained that `IoC`.  `IoCs` present in only
/// one source are excluded from the list but counted in `total_unique`.
#[must_use]
pub fn correlate_across_sources(sources: &[&[IoC]]) -> CorrelationResult {
    let source_count = sources.len();
    // Map (ioc_type_str, normalised_value) → (representative IoC, set of source indices).
    let mut map: HashMap<(String, String), (IoC, Vec<usize>)> = HashMap::new();

    for (src_idx, slice) in sources.iter().enumerate() {
        for ioc in *slice {
            let norm = normalise_ioc_value(&ioc.ioc_type, &ioc.value);
            let key = (ioc.ioc_type.as_str().to_string(), norm.clone());
            let entry = map.entry(key).or_insert_with(|| {
                let mut representative = ioc.clone();
                representative.value = norm;
                (representative, Vec::new())
            });
            // Record this source if not already seen.
            if !entry.1.contains(&src_idx) {
                entry.1.push(src_idx);
            }
        }
    }

    let total_unique = map.len();
    let mut multi_source_iocs: Vec<(IoC, Vec<usize>)> = map
        .into_values()
        .filter(|(_, sources)| sources.len() > 1)
        .collect();
    // Stable ordering by number of sources (descending), then value.
    multi_source_iocs.sort_by(|a, b| {
        b.1.len()
            .cmp(&a.1.len())
            .then_with(|| a.0.value.cmp(&b.0.value))
    });

    CorrelationResult {
        multi_source_iocs,
        total_unique,
        source_count,
    }
}

// ---------------------------------------------------------------------------
// CampaignCluster  (campaign clustering by infrastructure)
// ---------------------------------------------------------------------------

/// A cluster of `IoCs` (and associated TTPs) that share overlapping
/// infrastructure such as IP /24 prefixes, domain parents, or ASN-level
/// groupings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCluster {
    /// Cluster identifier (sequential index).
    pub id: usize,
    /// `IoC` members of this cluster.
    pub iocs: Vec<IoC>,
    /// TTPs associated with this cluster.
    pub ttps: Vec<Ttp>,
    /// Shared infrastructure markers that caused these `IoCs` to be grouped
    /// (e.g. `/24` prefixes or parent domains).
    pub shared_infrastructure: Vec<String>,
    /// Estimated campaign label derived from shared malware family tags.
    pub inferred_campaign: Option<String>,
}

impl CampaignCluster {
    /// Number of `IoCs` in this cluster.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.iocs.len()
    }
}

/// Group `IoCs` by overlapping infrastructure (shared /24 IP prefix, shared
/// parent domain) and associate the supplied TTPs with the cluster whose `IoCs`
/// share the most infrastructure with them.
///
/// Two `IoCs` are placed in the same cluster when they share at least one
/// infrastructure marker (IP /24 prefix or eTLD+1 domain).
///
/// Returns the clusters sorted by descending size.
#[must_use]
pub fn cluster_by_campaign(iocs: &[IoC], ttps: &[Ttp]) -> Vec<CampaignCluster> {
    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]);
        }
        parent[x]
    }

    fn union(parent: &mut Vec<usize>, x: usize, y: usize) {
        let rx = find(parent, x);
        let ry = find(parent, y);
        if rx != ry {
            parent[rx] = ry;
        }
    }

    // Build a (marker → ioc indices) map first.
    let mut marker_to_indices: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, ioc) in iocs.iter().enumerate() {
        for marker in infrastructure_markers(ioc) {
            marker_to_indices.entry(marker).or_default().push(idx);
        }
    }

    // Union-Find to merge IoCs that share at least one marker.
    let n = iocs.len();
    let mut parent: Vec<usize> = (0..n).collect();

    for indices in marker_to_indices.values() {
        for window in indices.windows(2) {
            union(&mut parent, window[0], window[1]);
        }
    }

    // Group by root.
    let mut root_to_cluster: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        root_to_cluster.entry(r).or_default().push(i);
    }

    // Build CampaignCluster list.
    let mut clusters: Vec<CampaignCluster> = root_to_cluster
        .into_iter()
        .enumerate()
        .map(|(cluster_id, (_, member_indices))| {
            let cluster_iocs: Vec<IoC> = member_indices.iter().map(|&i| iocs[i].clone()).collect();

            // Collect shared markers.
            let cluster_set: std::collections::HashSet<usize> =
                member_indices.iter().copied().collect();
            let mut shared: Vec<String> = Vec::new();
            for (marker, mi) in &marker_to_indices {
                // A marker is "shared" if >1 of its IoC indices belong to this cluster.
                let overlap = mi.iter().filter(|&&i| cluster_set.contains(&i)).count();
                if overlap > 1 && !shared.contains(marker) {
                    shared.push(marker.clone());
                }
            }
            shared.sort();

            // Infer campaign from malware family tags in the cluster IoCs.
            let inferred = infer_campaign_label(&cluster_iocs);

            CampaignCluster {
                id: cluster_id,
                iocs: cluster_iocs,
                ttps: Vec::new(),
                shared_infrastructure: shared,
                inferred_campaign: inferred,
            }
        })
        .collect();

    // TTP assignment heuristic: all TTPs from the input ThreatReports are
    // attributed to the largest cluster by IoC count.  This is a size-based
    // approximation — the union-find process does not track which IoC belongs
    // to which report, so per-cluster TTP filtering is not available here.
    // Callers that need accurate TTP-to-cluster attribution should iterate
    // ThreatReports individually and match IoCs to clusters by identity.
    if let Some(largest) = clusters.iter_mut().max_by_key(|c| c.iocs.len()) {
        largest.ttps = ttps.to_vec();
    }

    clusters.sort_by(|a, b| b.iocs.len().cmp(&a.iocs.len()));
    clusters
}

/// Extract infrastructure markers from an `IoC` (IP /24, eTLD+1 domain).
fn infrastructure_markers(ioc: &IoC) -> Vec<String> {
    let mut markers = Vec::new();
    if ioc.ioc_type == IoCType::Ip
        && let Some(prefix) = ip_prefix_24(&ioc.value) {
            markers.push(format!("ip24:{prefix}"));
        }
    if matches!(ioc.ioc_type, IoCType::Domain | IoCType::Url) {
        let pd = parent_domain(&ioc.value);
        if !pd.is_empty() {
            markers.push(format!("dom:{pd}"));
        }
    }
    markers
}

/// Infer a campaign label from the most common malware family tag in a set
/// of `IoCs`.
fn infer_campaign_label(iocs: &[IoC]) -> Option<String> {
    let mut family_counts: HashMap<String, usize> = HashMap::new();
    for ioc in iocs {
        for tag in &ioc.tags {
            *family_counts.entry(tag.clone()).or_insert(0) += 1;
        }
    }
    family_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(f, _)| f)
}

// ---------------------------------------------------------------------------
// ThreatEvent / TimelineEntry  (timeline analysis)
// ---------------------------------------------------------------------------

/// A timestamped threat event (wraps an `IoC` with an explicit timestamp and
/// optional label).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// The `IoC` associated with this event.
    pub ioc: IoC,
    /// Unix timestamp (seconds) of the event.
    pub timestamp: u64,
    /// Optional human-readable label (e.g. "`first_seen`", "`last_seen`", "report").
    pub label: Option<String>,
}

impl ThreatEvent {
    /// Construct a new event from an `IoC` and a timestamp.
    #[must_use]
    pub const fn new(ioc: IoC, timestamp: u64) -> Self {
        Self {
            ioc,
            timestamp,
            label: None,
        }
    }

    /// Construct a new event with a label.
    #[must_use]
    pub fn with_label(ioc: IoC, timestamp: u64, label: impl Into<String>) -> Self {
        Self {
            ioc,
            timestamp,
            label: Some(label.into()),
        }
    }
}

/// A bucket of [`ThreatEvent`]s that fall within a single time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Start of the window (inclusive), Unix seconds.
    pub window_start: u64,
    /// End of the window (exclusive), Unix seconds.
    pub window_end: u64,
    /// Events falling within this window.
    pub events: Vec<ThreatEvent>,
}

impl TimelineEntry {
    /// Number of events in this window.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.events.len()
    }

    /// Return the types of `IoCs` represented in this window (deduplicated).
    #[must_use]
    pub fn ioc_types(&self) -> Vec<&IoCType> {
        let mut seen: Vec<&IoCType> = Vec::new();
        for ev in &self.events {
            if !seen.contains(&&ev.ioc.ioc_type) {
                seen.push(&ev.ioc.ioc_type);
            }
        }
        seen
    }
}

/// Sort and bucket a slice of [`ThreatEvent`]s into fixed-width time windows.
///
/// `window_secs` controls the bucket size (default-friendly value: 86 400 for
/// daily buckets).  Events with timestamp 0 are placed into the first bucket.
///
/// Returns the buckets sorted by `window_start` ascending, with empty windows
/// omitted.
#[must_use]
pub fn timeline(events: &[ThreatEvent], window_secs: u64) -> Vec<TimelineEntry> {
    if events.is_empty() {
        return Vec::new();
    }
    let ws = window_secs.max(1);

    // Bucket each event.
    let mut buckets: HashMap<u64, Vec<ThreatEvent>> = HashMap::new();
    for ev in events {
        let bucket_key = (ev.timestamp / ws) * ws;
        buckets.entry(bucket_key).or_default().push(ev.clone());
    }

    let mut entries: Vec<TimelineEntry> = buckets
        .into_iter()
        .map(|(start, mut evts)| {
            evts.sort_by_key(|e| e.timestamp);
            TimelineEntry {
                window_start: start,
                window_end: start + ws,
                events: evts,
            }
        })
        .collect();

    entries.sort_by_key(|e| e.window_start);
    entries
}

// ---------------------------------------------------------------------------
// CorrelationContext / score_ioc
// ---------------------------------------------------------------------------

/// Context used by [`score_ioc`] to compute a composite threat score.
#[derive(Debug, Clone)]
pub struct CorrelationContext {
    /// Current Unix timestamp (seconds) — used to compute `IoC` age decay.
    pub now: u64,
    /// Number of distinct sources that reported this `IoC` (affects score).
    pub source_count: usize,
    /// Known malware family names that this `IoC` has been co-observed with.
    pub known_malware_families: Vec<String>,
    /// Half-life in days for the age-decay factor (default 90 days).
    ///
    /// An `IoC` last seen `half_life_days` ago retains 0.5 of the base score.
    pub half_life_days: f32,
}

impl CorrelationContext {
    /// Create a basic context with minimal fields.
    #[must_use]
    pub const fn new(now: u64, source_count: usize) -> Self {
        Self {
            now,
            source_count,
            known_malware_families: Vec::new(),
            half_life_days: 90.0,
        }
    }
}

impl Default for CorrelationContext {
    fn default() -> Self {
        Self::new(0, 1)
    }
}

/// Compute a composite threat score for a single [`IoC`] in [0.0, 1.0].
///
/// The score is derived from three independent factors:
///
/// | Factor | Weight | Description |
/// |--------|--------|-------------|
/// | **Age** | 0.30 | Exponential decay from `last_seen`; recent = higher score. |
/// | **Source count** | 0.30 | Logarithmic boost; more sources → higher confidence. |
/// | **Malware co-occurrence** | 0.40 | Flat bonus per known family tag match. |
///
/// A score close to 1.0 represents a high-confidence, recently-active,
/// multi-source `IoC` strongly linked to known malware families.
#[must_use]
pub fn score_ioc(ioc: &IoC, context: &CorrelationContext) -> f32 {
    const W_AGE: f32 = 0.30;
    const W_SRC: f32 = 0.30;
    const W_FAM: f32 = 0.40;

    // ---- Age factor -------------------------------------------------------
    // Use last_seen when available, fall back to first_seen, then 0.
    let last_ts = if ioc.last_seen > 0 {
        ioc.last_seen
    } else {
        ioc.first_seen
    };

    let age_factor = if context.now == 0 || last_ts == 0 {
        // No temporal data — neutral score.
        0.5_f32
    } else {
        let age_days = (context.now.saturating_sub(last_ts) as f64 / 86_400.0) as f32;
        let half_life = context.half_life_days.max(1.0);
        // Exponential decay: f(age) = 2^(−age / half_life)
        (-(age_days / half_life) * std::f32::consts::LN_2).exp()
    };

    // ---- Source count factor ----------------------------------------------
    // log2(1 + src_count) / log2(1 + 10) normalised to [0, 1] where 10
    // sources → ~1.0.
    let src = f32::from(u16::try_from(context.source_count.max(1)).unwrap_or(u16::MAX));
    let source_factor = (src.ln_1p() / 10.0_f32.ln_1p()).min(1.0);

    // ---- Malware co-occurrence factor -------------------------------------
    let family_hits = if context.known_malware_families.is_empty() {
        0.0_f32
    } else {
        let hits = f32::from(u16::try_from(
            ioc.tags
                .iter()
                .filter(|tag| {
                    context
                        .known_malware_families
                        .iter()
                        .any(|f| f.eq_ignore_ascii_case(tag))
                })
                .count(),
        ).unwrap_or(u16::MAX));
        let denom = f32::from(u16::try_from(context.known_malware_families.len().max(1)).unwrap_or(u16::MAX));
        (hits / denom).min(1.0)
    };

    // ---- Weighted sum -----------------------------------------------------
    let score = W_FAM.mul_add(family_hits, W_AGE.mul_add(age_factor, W_SRC * source_factor));
    score.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Tests (25+)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoCType, ThreatReport};

    fn sha256_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Sha256, val.to_string(), "test".to_string())
    }

    fn ip_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Ip, val.to_string(), "test".to_string())
    }

    fn domain_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Domain, val.to_string(), "test".to_string())
    }

    fn timed_ioc(val: &str, first_seen: u64) -> IoC {
        let mut ioc = sha256_ioc(val);
        ioc.first_seen = first_seen;
        ioc
    }

    fn report_with_iocs(iocs: Vec<IoC>) -> ThreatReport {
        let mut r = ThreatReport::new("Test Report".to_string(), "analyst".to_string());
        for ioc in iocs {
            r.add_ioc(ioc);
        }
        r
    }

    // ---- CorrelationEngine basics ----

    #[test]
    fn test_engine_new_empty() {
        let e = CorrelationEngine::new();
        assert!(e.iocs.is_empty());
        assert!(e.reports.is_empty());
    }

    #[test]
    fn test_engine_default() {
        let e = CorrelationEngine::default();
        assert!(e.correlate_all().is_empty());
    }

    #[test]
    fn test_engine_debug_format() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("1.2.3.4"));
        let s = format!("{e:?}");
        assert!(s.contains("CorrelationEngine"));
        assert!(s.contains("ioc_count"));
    }

    #[test]
    fn test_add_ioc_and_report() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("1.2.3.4"));
        e.add_report(report_with_iocs(vec![sha256_ioc("abc")]));
        assert_eq!(e.iocs.len(), 1);
        assert_eq!(e.reports.len(), 1);
    }

    // ---- Hash correlation ----

    #[test]
    fn test_hash_correlation_similar_prefix() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(sha256_ioc("deadbeef1234567890abcdef"));
        e.add_ioc(sha256_ioc("deadbeef9876543210fedcba"));
        let corrs = e.correlate_all();
        assert!(corrs.iter().any(|c| c.kind == CorrelationKind::SimilarHash));
    }

    #[test]
    fn test_hash_correlation_different_prefix() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(sha256_ioc("aaaa0000deadbeef"));
        e.add_ioc(sha256_ioc("bbbb1111cafebabe"));
        let corrs = e.correlate_all();
        assert!(!corrs.iter().any(|c| c.kind == CorrelationKind::SimilarHash));
    }

    #[test]
    fn test_hash_correlation_confidence() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(sha256_ioc("abcdef001122334455"));
        e.add_ioc(sha256_ioc("abcdef009988776655"));
        let corrs = e.correlate_all();
        let hash_corrs: Vec<_> = corrs
            .iter()
            .filter(|c| c.kind == CorrelationKind::SimilarHash)
            .collect();
        assert!(!hash_corrs.is_empty());
        assert!(hash_corrs[0].confidence > 0);
    }

    // ---- Network correlation ----

    #[test]
    fn test_ip_same_subnet() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("192.168.1.10"));
        e.add_ioc(ip_ioc("192.168.1.20"));
        let corrs = e.correlate_all();
        assert!(
            corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::NetworkInfrastructure)
        );
    }

    #[test]
    fn test_ip_different_subnet() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("10.0.0.1"));
        e.add_ioc(ip_ioc("192.168.1.1"));
        let corrs = e.correlate_all();
        assert!(
            !corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::NetworkInfrastructure)
        );
    }

    #[test]
    fn test_domain_shared_parent() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(domain_ioc("c2.evil.example.com"));
        e.add_ioc(domain_ioc("drop.evil.example.com"));
        let corrs = e.correlate_all();
        assert!(
            corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::NetworkInfrastructure)
        );
    }

    #[test]
    fn test_domain_different_parent() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(domain_ioc("a.foo.com"));
        e.add_ioc(domain_ioc("a.bar.com"));
        let corrs = e.correlate_all();
        assert!(
            !corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::NetworkInfrastructure)
        );
    }

    // ---- Temporal correlation ----

    #[test]
    fn test_temporal_within_window() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(timed_ioc("hash1", 1_000_000));
        e.add_ioc(timed_ioc("hash2", 1_000_000 + 3600)); // 1 hour apart
        let corrs = e.correlate_all();
        assert!(
            corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::TemporalProximity)
        );
    }

    #[test]
    fn test_temporal_outside_window() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(timed_ioc("hash1", 1_000_000));
        e.add_ioc(timed_ioc("hash2", 1_000_000 + 200_000)); // >24h
        let corrs = e.correlate_all();
        assert!(
            !corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::TemporalProximity)
        );
    }

    // ---- Report-based correlations ----

    #[test]
    fn test_shared_threat_actor_correlation() {
        let mut e = CorrelationEngine::new();
        let mut r = report_with_iocs(vec![sha256_ioc("hash_a"), sha256_ioc("hash_b")]);
        r.threat_actors.push("APT29".to_string());
        e.add_report(r);
        let corrs = e.correlate_all();
        assert!(
            corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::SharedThreatActor)
        );
    }

    #[test]
    fn test_shared_malware_family_correlation() {
        let mut e = CorrelationEngine::new();
        let mut r = report_with_iocs(vec![ip_ioc("1.1.1.1"), ip_ioc("2.2.2.2")]);
        r.malware_families.push("Emotet".to_string());
        e.add_report(r);
        let corrs = e.correlate_all();
        assert!(
            corrs
                .iter()
                .any(|c| c.kind == CorrelationKind::SharedMalwareFamily)
        );
    }

    #[test]
    fn test_shared_family_confidence() {
        let mut e = CorrelationEngine::new();
        let mut r = report_with_iocs(vec![sha256_ioc("a"), sha256_ioc("b")]);
        r.malware_families.push("WannaCry".to_string());
        e.add_report(r);
        let corrs = e.correlate_all();
        let fam_corrs: Vec<_> = corrs
            .iter()
            .filter(|c| c.kind == CorrelationKind::SharedMalwareFamily)
            .collect();
        assert!(!fam_corrs.is_empty());
        assert!(fam_corrs[0].confidence >= 75);
    }

    // ---- find_related ----

    #[test]
    fn test_find_related() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("10.0.0.1"));
        e.add_ioc(ip_ioc("10.0.0.2"));
        e.add_ioc(ip_ioc("192.168.1.1"));
        let related = e.find_related(&ip_ioc("10.0.0.1"));
        // 10.0.0.1 and 10.0.0.2 share /24
        assert!(
            related
                .iter()
                .any(|c| c.ioc_b.value == "10.0.0.2" || c.ioc_a.value == "10.0.0.2")
        );
    }

    // ---- cluster_by_family ----

    #[test]
    fn test_cluster_by_family() {
        let mut e = CorrelationEngine::new();
        let mut r = report_with_iocs(vec![sha256_ioc("hash1"), sha256_ioc("hash2")]);
        r.malware_families.push("Emotet".to_string());
        e.add_report(r);
        let clusters = e.cluster_by_family();
        assert!(clusters.contains_key("Emotet"));
        assert_eq!(clusters["Emotet"].len(), 2);
    }

    #[test]
    fn test_cluster_uncategorised_standalone() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("5.5.5.5"));
        let clusters = e.cluster_by_family();
        let uncat = clusters.get("uncategorised").cloned().unwrap_or_default();
        assert!(uncat.iter().any(|i| i.value == "5.5.5.5"));
    }

    // ---- high_confidence_correlations ----

    #[test]
    fn test_high_confidence_filter() {
        let mut e = CorrelationEngine::new();
        let mut r = report_with_iocs(vec![sha256_ioc("a"), sha256_ioc("b")]);
        r.malware_families.push("Emotet".to_string());
        e.add_report(r);
        let high = e.high_confidence_correlations(75);
        assert!(!high.is_empty());
        for c in &high {
            assert!(c.confidence >= 75);
        }
    }

    #[test]
    fn test_high_confidence_filter_none() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("1.2.3.4"));
        e.add_ioc(ip_ioc("1.2.3.5"));
        // NetworkInfrastructure confidence is 70 — threshold of 100 returns nothing.
        let high = e.high_confidence_correlations(100);
        assert!(high.is_empty());
    }

    // ---- Correlation display / serde ----

    #[test]
    fn test_correlation_display() {
        let c = Correlation {
            ioc_a: ip_ioc("1.1.1.1"),
            ioc_b: ip_ioc("1.1.1.2"),
            kind: CorrelationKind::NetworkInfrastructure,
            confidence: 70,
            evidence: "Test".to_string(),
        };
        let s = c.to_string();
        assert!(s.contains("1.1.1.1"));
        assert!(s.contains("Network Infrastructure"));
    }

    #[test]
    fn test_correlation_meets_threshold() {
        let c = Correlation {
            ioc_a: sha256_ioc("a"),
            ioc_b: sha256_ioc("b"),
            kind: CorrelationKind::SimilarHash,
            confidence: 60,
            evidence: String::new(),
        };
        assert!(c.meets_threshold(60));
        assert!(c.meets_threshold(50));
        assert!(!c.meets_threshold(61));
    }

    #[test]
    fn test_correlation_kind_display() {
        let kinds = [
            CorrelationKind::SharedThreatActor,
            CorrelationKind::SharedMalwareFamily,
            CorrelationKind::SimilarHash,
            CorrelationKind::NetworkInfrastructure,
            CorrelationKind::SameRegistrar,
            CorrelationKind::SameCertificate,
            CorrelationKind::TemporalProximity,
        ];
        for k in &kinds {
            assert!(!k.to_string().is_empty());
        }
    }

    #[test]
    fn test_correlation_serde() {
        let c = Correlation {
            ioc_a: ip_ioc("10.0.0.1"),
            ioc_b: ip_ioc("10.0.0.2"),
            kind: CorrelationKind::NetworkInfrastructure,
            confidence: 70,
            evidence: "Same /24".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let decoded: Correlation = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ioc_a.value, "10.0.0.1");
        assert_eq!(decoded.kind, CorrelationKind::NetworkInfrastructure);
    }

    // ---- ip_prefix_24 / parent_domain helpers ----

    #[test]
    fn test_ip_prefix_24_valid() {
        assert_eq!(ip_prefix_24("192.168.1.100"), Some("192.168.1".to_string()));
    }

    #[test]
    fn test_ip_prefix_24_invalid() {
        assert_eq!(ip_prefix_24("not-an-ip"), None);
    }

    #[test]
    fn test_parent_domain_basic() {
        assert_eq!(parent_domain("c2.evil.com"), "evil.com");
    }

    #[test]
    fn test_parent_domain_url() {
        assert_eq!(parent_domain("https://sub.evil.com/path"), "evil.com");
    }

    #[test]
    fn test_no_self_correlation() {
        let mut e = CorrelationEngine::new();
        e.add_ioc(ip_ioc("1.2.3.4"));
        e.add_ioc(ip_ioc("1.2.3.4")); // duplicate
        // Dedup: same value should produce no correlation.
        let corrs = e.correlate_all();
        assert!(corrs.iter().all(|c| c.ioc_a.value != c.ioc_b.value));
    }

    // ---- MitreAttackDb ----

    #[test]
    fn test_mitre_create_remote_thread() {
        let hits = MitreAttackDb::map_api_to_technique("CreateRemoteThread");
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|(t, _)| t == "Defense Evasion"));
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1055")));
    }

    #[test]
    fn test_mitre_reg_set_value_ex() {
        let hits = MitreAttackDb::map_api_to_technique("RegSetValueEx");
        assert!(hits.iter().any(|(t, _)| t == "Persistence"));
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1547.001")));
    }

    #[test]
    fn test_mitre_url_download() {
        let hits = MitreAttackDb::map_api_to_technique("URLDownloadToFile");
        assert!(hits.iter().any(|(t, _)| t == "Command and Control"));
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1105")));
    }

    #[test]
    fn test_mitre_crypt_encrypt() {
        let hits = MitreAttackDb::map_api_to_technique("CryptEncrypt");
        assert!(hits.iter().any(|(t, _)| t == "Impact"));
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1486")));
    }

    #[test]
    fn test_mitre_is_debugger_present() {
        let hits = MitreAttackDb::map_api_to_technique("IsDebuggerPresent");
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1622")));
    }

    #[test]
    fn test_mitre_unknown_api() {
        let hits = MitreAttackDb::map_api_to_technique("SomeRandomUnknownApi");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_mitre_case_insensitive() {
        let lower = MitreAttackDb::map_api_to_technique("createremotethread");
        let mixed = MitreAttackDb::map_api_to_technique("CreateRemoteThread");
        assert_eq!(lower, mixed);
    }

    #[test]
    fn test_mitre_map_apis_dedup() {
        let apis = [
            "CreateRemoteThread",
            "CreateRemoteThread",
            "WriteProcessMemory",
        ];
        let hits = MitreAttackDb::map_apis_to_techniques(&apis);
        // Deduplication: T1055 should appear only once even though two APIs map to it.
        let count = hits
            .iter()
            .filter(|(_, t)| t.contains("T1055 Process"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_mitre_set_windows_hook_ex() {
        let hits = MitreAttackDb::map_api_to_technique("SetWindowsHookEx");
        assert!(hits.iter().any(|(t, _)| t == "Collection"));
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1056.001")));
    }

    #[test]
    fn test_mitre_create_service() {
        let hits = MitreAttackDb::map_api_to_technique("CreateService");
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1543.003")));
    }

    #[test]
    fn test_mitre_delete_file() {
        let hits = MitreAttackDb::map_api_to_technique("DeleteFile");
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1070.004")));
    }

    #[test]
    fn test_mitre_sam_query() {
        let hits = MitreAttackDb::map_api_to_technique("SamQueryInformationUser");
        assert!(hits.iter().any(|(t, _)| t == "Credential Access"));
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1003.002")));
    }

    #[test]
    fn test_mitre_create_mutex() {
        let hits = MitreAttackDb::map_api_to_technique("CreateMutex");
        assert!(hits.iter().any(|(_, tech)| tech.contains("T1480")));
    }

    // ---- CorrelationNode ----

    #[test]
    fn test_node_key() {
        assert_eq!(CorrelationNode::Hash("abc".to_string()).key(), "abc");
        assert_eq!(CorrelationNode::Ip("1.2.3.4".to_string()).key(), "1.2.3.4");
        assert_eq!(
            CorrelationNode::Technique("T1055".to_string()).key(),
            "T1055"
        );
    }

    #[test]
    fn test_node_kind_label() {
        assert_eq!(CorrelationNode::Hash("x".to_string()).kind_label(), "hash");
        assert_eq!(CorrelationNode::Ip("x".to_string()).kind_label(), "ip");
        assert_eq!(
            CorrelationNode::Domain("x".to_string()).kind_label(),
            "domain"
        );
        assert_eq!(
            CorrelationNode::Family("x".to_string()).kind_label(),
            "family"
        );
        assert_eq!(
            CorrelationNode::ThreatActor("x".to_string()).kind_label(),
            "actor"
        );
        assert_eq!(
            CorrelationNode::Campaign("x".to_string()).kind_label(),
            "campaign"
        );
        assert_eq!(
            CorrelationNode::Technique("x".to_string()).kind_label(),
            "technique"
        );
    }

    #[test]
    fn test_node_display() {
        let n = CorrelationNode::Family("Emotet".to_string());
        assert!(n.to_string().contains("family"));
        assert!(n.to_string().contains("Emotet"));
    }

    // ---- CorrelationGraph ----

    #[test]
    fn test_graph_add_and_count() {
        let mut g = CorrelationGraph::new();
        g.add_correlation(
            CorrelationNode::Hash("deadbeef".to_string()),
            CorrelationNode::Family("Emotet".to_string()),
            "member_of".to_string(),
        );
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_graph_dedup_nodes() {
        let mut g = CorrelationGraph::new();
        // Insert the same hash twice as source and target for different relations.
        g.add_correlation(
            CorrelationNode::Hash("aabbcc".to_string()),
            CorrelationNode::Ip("1.2.3.4".to_string()),
            "connects_to".to_string(),
        );
        g.add_correlation(
            CorrelationNode::Hash("aabbcc".to_string()),
            CorrelationNode::Domain("evil.com".to_string()),
            "resolves".to_string(),
        );
        // Only 3 unique nodes: hash, ip, domain.
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_graph_find_related_bfs() {
        let mut g = CorrelationGraph::new();
        g.add_correlation(
            CorrelationNode::ThreatActor("APT28".to_string()),
            CorrelationNode::Campaign("Operation X".to_string()),
            "conducted".to_string(),
        );
        g.add_correlation(
            CorrelationNode::Campaign("Operation X".to_string()),
            CorrelationNode::Family("XAgent".to_string()),
            "uses".to_string(),
        );
        let related = g.find_related("APT28");
        assert!(related.iter().any(|s| s.contains("Operation X")));
        assert!(related.iter().any(|s| s.contains("XAgent")));
    }

    #[test]
    fn test_graph_find_related_no_match() {
        let g = CorrelationGraph::new();
        let related = g.find_related("nonexistent");
        assert!(related.is_empty());
    }

    #[test]
    fn test_graph_export_dot_contains_nodes() {
        let mut g = CorrelationGraph::new();
        g.add_correlation(
            CorrelationNode::Hash("cafebabe".to_string()),
            CorrelationNode::Technique("T1055 Process Injection".to_string()),
            "uses".to_string(),
        );
        let dot = g.export_dot();
        assert!(dot.starts_with("digraph"));
        assert!(dot.contains("cafebabe"));
        assert!(dot.contains("T1055"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_graph_export_dot_escaping() {
        let mut g = CorrelationGraph::new();
        g.add_correlation(
            CorrelationNode::Domain("sub.\"evil\".com".to_string()),
            CorrelationNode::Ip("10.0.0.1".to_string()),
            "resolves_to".to_string(),
        );
        let dot = g.export_dot();
        // Double-quote in label must be escaped.
        assert!(dot.contains("\\\"evil\\\"") || dot.contains(r#"\""#));
    }

    #[test]
    fn test_graph_default() {
        let g = CorrelationGraph::default();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_graph_debug_format() {
        let g = CorrelationGraph::new();
        let s = format!("{g:?}");
        assert!(s.contains("CorrelationGraph"));
    }

    // ---- FamilyClassifier ----

    fn apis(list: &[&str]) -> Vec<String> {
        list.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn test_classify_ransomware() {
        let calls = apis(&[
            "CryptEncrypt",
            "CryptGenKey",
            "CryptAcquireContext",
            "FindFirstFile",
            "FindNextFile",
            "MoveFile",
            "DeleteFile",
            "WriteFile",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "Ransomware");
    }

    #[test]
    fn test_classify_keylogger() {
        let calls = apis(&[
            "SetWindowsHookEx",
            "GetAsyncKeyState",
            "keybd_event",
            "GetKeyState",
            "CallNextHookEx",
            "OpenClipboard",
            "GetClipboardData",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "Keylogger");
    }

    #[test]
    fn test_classify_injector() {
        let calls = apis(&[
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "SetThreadContext",
            "ResumeThread",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "Injector");
    }

    #[test]
    fn test_classify_dropper() {
        let calls = apis(&[
            "URLDownloadToFile",
            "CreateFile",
            "WriteFile",
            "WinExec",
            "CreateProcess",
            "LoadLibrary",
            "GetTempPath",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "Dropper");
    }

    #[test]
    fn test_classify_rat() {
        let calls = apis(&[
            "WinHttpOpen",
            "WinHttpSendRequest",
            "socket",
            "connect",
            "send",
            "recv",
            "CreateProcess",
            "ShellExecute",
            "BitBlt",
            "GetDC",
            "EnumProcesses",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "RAT");
    }

    #[test]
    fn test_classify_worm() {
        let calls = apis(&[
            "WNetEnumResource",
            "WNetOpenEnum",
            "WNetAddConnection",
            "CopyFile",
            "FindFirstFile",
            "FindNextFile",
            "socket",
            "connect",
            "send",
            "URLDownloadToFile",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "Worm");
    }

    #[test]
    fn test_classify_infostealer() {
        let calls = apis(&[
            "RegOpenKeyEx",
            "RegQueryValueEx",
            "CryptUnprotectData",
            "SamQueryInformationUser",
            "LsaOpenPolicy",
            "ReadProcessMemory",
            "GetClipboardData",
            "WinHttpSendRequest",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "InfoStealer");
    }

    #[test]
    fn test_classify_unknown() {
        let calls = apis(&["CreateFile", "CloseHandle"]);
        assert_eq!(FamilyClassifier::classify(&calls), "Unknown");
    }

    #[test]
    fn test_classify_empty() {
        assert_eq!(FamilyClassifier::classify(&[]), "Unknown");
    }

    #[test]
    fn test_classify_case_insensitive() {
        let calls = apis(&[
            "cryptencrypt",
            "cryptgenkey",
            "cryptacquirecontext",
            "findfirstfile",
            "findnextfile",
            "movefile",
            "deletefile",
        ]);
        assert_eq!(FamilyClassifier::classify(&calls), "Ransomware");
    }

    #[test]
    fn test_score_breakdown_order() {
        let calls = apis(&[
            "CryptEncrypt",
            "CryptGenKey",
            "FindFirstFile",
            "FindNextFile",
            "MoveFile",
            "DeleteFile",
            "WriteFile",
        ]);
        let scores = FamilyClassifier::score_breakdown(&calls);
        assert!(!scores.is_empty());
        // First entry must be the highest score.
        assert!(scores[0].1 >= scores[1].1);
        // Ransomware should lead.
        assert_eq!(scores[0].0, "Ransomware");
    }

    #[test]
    fn test_score_breakdown_all_families_present() {
        let calls = apis(&["CreateFile"]);
        let scores = FamilyClassifier::score_breakdown(&calls);
        let families: Vec<&str> = scores.iter().map(|(f, _)| f.as_str()).collect();
        assert!(families.contains(&"Ransomware"));
        assert!(families.contains(&"Keylogger"));
        assert!(families.contains(&"RAT"));
        assert!(families.contains(&"Dropper"));
        assert!(families.contains(&"Injector"));
        assert!(families.contains(&"Worm"));
        assert!(families.contains(&"InfoStealer"));
    }

    // ---- deduplicate_iocs ----

    #[test]
    fn test_dedup_removes_exact_duplicate() {
        let a = ip_ioc("1.2.3.4");
        let b = ip_ioc("1.2.3.4");
        let result = deduplicate_iocs(vec![a, b]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "1.2.3.4");
    }

    #[test]
    fn test_dedup_normalises_hash_uppercase() {
        let a = sha256_ioc("deadbeef1234abcd");
        let result = deduplicate_iocs(vec![a]);
        assert_eq!(result[0].value, "DEADBEEF1234ABCD");
    }

    #[test]
    fn test_dedup_normalises_domain_lowercase() {
        let a = domain_ioc("Evil.COM");
        let result = deduplicate_iocs(vec![a]);
        assert_eq!(result[0].value, "evil.com");
    }

    #[test]
    fn test_dedup_hash_case_variants_collapse() {
        let a = sha256_ioc("AABBCCDD");
        let b = sha256_ioc("aabbccdd");
        let result = deduplicate_iocs(vec![a, b]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_keeps_distinct() {
        let a = ip_ioc("1.2.3.4");
        let b = ip_ioc("5.6.7.8");
        let result = deduplicate_iocs(vec![a, b]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_empty() {
        let result = deduplicate_iocs(vec![]);
        assert!(result.is_empty());
    }

    // ---- correlate_across_sources ----

    #[test]
    fn test_cross_source_finds_shared() {
        let src0 = vec![ip_ioc("1.2.3.4"), ip_ioc("9.9.9.9")];
        let src1 = vec![ip_ioc("1.2.3.4"), ip_ioc("8.8.8.8")];
        let result = correlate_across_sources(&[&src0, &src1]);
        assert_eq!(result.source_count, 2);
        assert_eq!(result.multi_source_iocs.len(), 1);
        assert_eq!(result.multi_source_iocs[0].0.value, "1.2.3.4");
        assert_eq!(result.multi_source_iocs[0].1.len(), 2);
    }

    #[test]
    fn test_cross_source_no_overlap() {
        let src0 = vec![ip_ioc("1.1.1.1")];
        let src1 = vec![ip_ioc("2.2.2.2")];
        let result = correlate_across_sources(&[&src0, &src1]);
        assert!(result.multi_source_iocs.is_empty());
        assert_eq!(result.total_unique, 2);
    }

    #[test]
    fn test_cross_source_filter_by_min_sources() {
        let src0 = vec![ip_ioc("1.2.3.4")];
        let src1 = vec![ip_ioc("1.2.3.4")];
        let src2 = vec![ip_ioc("1.2.3.4")];
        let result = correlate_across_sources(&[&src0, &src1, &src2]);
        assert_eq!(result.filter_by_min_sources(3).len(), 1);
        assert_eq!(result.filter_by_min_sources(4).len(), 0);
    }

    #[test]
    fn test_cross_source_max_source_count() {
        let src0 = vec![ip_ioc("10.0.0.1")];
        let src1 = vec![ip_ioc("10.0.0.1")];
        let result = correlate_across_sources(&[&src0, &src1]);
        assert_eq!(result.max_source_count(), 2);
    }

    #[test]
    fn test_cross_source_empty() {
        let result = correlate_across_sources(&[]);
        assert_eq!(result.total_unique, 0);
        assert!(result.multi_source_iocs.is_empty());
    }

    // ---- cluster_by_campaign ----

    #[test]
    fn test_cluster_by_campaign_same_subnet() {
        let iocs = vec![
            ip_ioc("192.168.1.10"),
            ip_ioc("192.168.1.20"),
            ip_ioc("10.0.0.1"),
        ];
        let clusters = cluster_by_campaign(&iocs, &[]);
        // First two share /24; third is alone.
        let first = &clusters[0];
        assert!(first.size() >= 2);
    }

    #[test]
    fn test_cluster_by_campaign_shared_domain() {
        let iocs = vec![
            domain_ioc("c2.evil.com"),
            domain_ioc("drop.evil.com"),
            domain_ioc("legit.example.com"),
        ];
        let clusters = cluster_by_campaign(&iocs, &[]);
        assert!(!clusters.is_empty());
        let largest = &clusters[0];
        assert!(largest.size() >= 2);
    }

    #[test]
    fn test_cluster_by_campaign_empty() {
        let clusters = cluster_by_campaign(&[], &[]);
        assert!(clusters.is_empty());
    }

    #[test]
    fn test_cluster_by_campaign_ttps_assigned() {
        use rustre_threatintel::Ttp;
        let iocs = vec![ip_ioc("1.1.1.1"), ip_ioc("1.1.1.2")];
        let ttps = vec![Ttp::new("T1055", "Process Injection", "Defense Evasion")];
        let clusters = cluster_by_campaign(&iocs, &ttps);
        let any_with_ttp = clusters.iter().any(|c| !c.ttps.is_empty());
        assert!(any_with_ttp);
    }

    // ---- timeline ----

    #[test]
    fn test_timeline_basic_bucketing() {
        let ioc1 = timed_ioc("h1", 0);
        let ioc2 = timed_ioc("h2", 3600); // same day bucket
        let ioc3 = timed_ioc("h3", 100_000); // different bucket
        let events = vec![
            ThreatEvent::new(ioc1, 0),
            ThreatEvent::new(ioc2, 3600),
            ThreatEvent::new(ioc3, 100_000),
        ];
        let entries = timeline(&events, 86_400);
        assert_eq!(entries.len(), 2); // two day-buckets
        assert_eq!(entries[0].count(), 2);
        assert_eq!(entries[1].count(), 1);
    }

    #[test]
    fn test_timeline_empty() {
        let entries = timeline(&[], 86_400);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_timeline_sorted_ascending() {
        let events = vec![
            ThreatEvent::new(timed_ioc("h1", 200_000), 200_000),
            ThreatEvent::new(timed_ioc("h2", 100), 100),
        ];
        let entries = timeline(&events, 86_400);
        assert!(entries[0].window_start <= entries[1].window_start);
    }

    #[test]
    fn test_timeline_entry_ioc_types() {
        let ev = ThreatEvent::new(ip_ioc("1.2.3.4"), 1000);
        let entries = timeline(&[ev], 86_400);
        assert!(!entries[0].ioc_types().is_empty());
    }

    #[test]
    fn test_timeline_with_label() {
        let ev = ThreatEvent::with_label(ip_ioc("1.2.3.4"), 0, "first_seen");
        assert_eq!(ev.label.as_deref(), Some("first_seen"));
    }

    // ---- score_ioc ----

    #[test]
    fn test_score_ioc_recent_multi_source() {
        let now = 1_700_000_000u64;
        let mut ioc = ip_ioc("1.2.3.4");
        ioc.last_seen = now - 3600; // 1 hour ago
        ioc.tags.push("Emotet".to_string());
        let ctx = CorrelationContext {
            now,
            source_count: 5,
            known_malware_families: vec!["Emotet".to_string()],
            half_life_days: 90.0,
        };
        let score = score_ioc(&ioc, &ctx);
        assert!(score > 0.5, "Expected high score, got {score}");
        assert!(score <= 1.0);
    }

    #[test]
    fn test_score_ioc_old_single_source() {
        let now = 1_700_000_000u64;
        let mut ioc = ip_ioc("9.9.9.9");
        ioc.last_seen = now - 365 * 86_400; // 1 year ago
        let ctx = CorrelationContext::new(now, 1);
        let score = score_ioc(&ioc, &ctx);
        assert!(score < 0.5, "Expected low score for old IoC, got {score}");
    }

    #[test]
    fn test_score_ioc_no_temporal_data() {
        let ctx = CorrelationContext::default();
        let score = score_ioc(&ip_ioc("1.2.3.4"), &ctx);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn test_score_ioc_many_sources_boosts_score() {
        let ctx_one = CorrelationContext::new(0, 1);
        let ctx_ten = CorrelationContext::new(0, 10);
        let ioc = ip_ioc("1.2.3.4");
        assert!(score_ioc(&ioc, &ctx_ten) > score_ioc(&ioc, &ctx_one));
    }

    #[test]
    fn test_score_ioc_family_match_boosts() {
        let mut ioc = ip_ioc("1.2.3.4");
        ioc.tags.push("WannaCry".to_string());
        let ctx_no_fam = CorrelationContext {
            now: 0,
            source_count: 1,
            known_malware_families: vec![],
            half_life_days: 90.0,
        };
        let ctx_with_fam = CorrelationContext {
            now: 0,
            source_count: 1,
            known_malware_families: vec!["WannaCry".to_string()],
            half_life_days: 90.0,
        };
        assert!(score_ioc(&ioc, &ctx_with_fam) > score_ioc(&ioc, &ctx_no_fam));
    }

    #[test]
    fn test_score_ioc_clamp() {
        let mut ioc = ip_ioc("1.2.3.4");
        let now = 1_000u64;
        ioc.last_seen = now;
        ioc.tags = vec!["Emotet".to_string(), "Cobalt".to_string()];
        let ctx = CorrelationContext {
            now,
            source_count: 100,
            known_malware_families: vec!["Emotet".to_string(), "Cobalt".to_string()],
            half_life_days: 90.0,
        };
        let score = score_ioc(&ioc, &ctx);
        assert!((0.0..=1.0).contains(&score));
    }
}
