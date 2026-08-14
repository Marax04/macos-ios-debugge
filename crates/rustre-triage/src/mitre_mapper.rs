// rustre-triage/src/mitre_mapper.rs
//! MITRE ATT&CK technique mapping from triage results.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

use crate::TriageResult;
// Re-exported so MITRE consumers can describe indicators and threat
// levels using the same types as the rest of the triage crate.
pub use crate::{ThreatLevel, TriageIndicator};

// ─── Technique ────────────────────────────────────────────────────────────────

/// A MITRE ATT&CK technique entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g. `"T1055"`).
    pub id: String,
    /// Technique name (e.g. `"Process Injection"`).
    pub name: String,
    /// ATT&CK tactic (e.g. `"Defense Evasion"`).
    pub tactic: String,
    /// Sub-technique ID if applicable (e.g. `"T1055.001"`).
    pub sub_technique: Option<String>,
    /// URL to the ATT&CK page.
    pub url: String,
}

impl MitreTechnique {
    pub fn new(id: impl Into<String>, name: impl Into<String>, tactic: impl Into<String>) -> Self {
        let id_str: String = id.into();
        let url = format!(
            "https://attack.mitre.org/techniques/{}/",
            id_str.replace('.', "/")
        );
        Self {
            id: id_str,
            name: name.into(),
            tactic: tactic.into(),
            sub_technique: None,
            url,
        }
    }

    #[must_use]
    pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
        self.sub_technique = Some(sub.into());
        self
    }
}

impl std::fmt::Display for MitreTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} ({})", self.id, self.name, self.tactic)
    }
}

// ─── Technique match ──────────────────────────────────────────────────────────

/// A mapped technique match from triage results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueMatch {
    pub technique: MitreTechnique,
    /// The triage indicator that triggered this match.
    pub matched_indicator: String,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Source evidence string.
    pub evidence: String,
}

impl TechniqueMatch {
    pub fn new(technique: MitreTechnique, indicator: impl Into<String>, confidence: u8) -> Self {
        Self {
            technique,
            matched_indicator: indicator.into(),
            confidence,
            evidence: String::new(),
        }
    }
    #[must_use]
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence = ev.into();
        self
    }
}

// ─── ATT&CK matrix ────────────────────────────────────────────────────────────

/// Constructed ATT&CK matrix from triage results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackMatrix {
    /// Grouped by tactic.
    pub by_tactic: HashMap<String, Vec<TechniqueMatch>>,
    /// All matches in insertion order.
    pub matches: Vec<TechniqueMatch>,
}

impl AttackMatrix {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, m: TechniqueMatch) {
        self.by_tactic
            .entry(m.technique.tactic.clone())
            .or_default()
            .push(m.clone());
        self.matches.push(m);
    }

    #[must_use]
    pub fn tactics(&self) -> Vec<&str> {
        self.by_tactic
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    #[must_use]
    pub const fn technique_count(&self) -> usize {
        self.matches.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    #[must_use]
    pub fn techniques_for_tactic(&self, tactic: &str) -> Vec<&TechniqueMatch> {
        self.by_tactic
            .get(tactic)
            .map_or(Vec::new(), |v| v.iter().collect())
    }

    /// Highest-confidence match.
    #[must_use]
    pub fn top_match(&self) -> Option<&TechniqueMatch> {
        self.matches.iter().max_by_key(|m| m.confidence)
    }

    /// Text summary of the matrix.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for tactic in self.tactics() {
            let _ = writeln!(out, "  [{tactic}]");
            for m in self.techniques_for_tactic(tactic) {
                let _ = writeln!(out, "    {} — {} (conf={}%)", m.technique.id, m.technique.name, m.confidence);
            }
        }
        out
    }

    /// Export as JSON.
    ///
    /// # Errors
    /// Returns a `serde_json` error if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

// ─── MITRE mapper ─────────────────────────────────────────────────────────────

/// Maps triage indicators and results to MITRE ATT&CK techniques.
pub struct MitreMapper {
    /// Mapping: indicator substring → (technique, confidence).
    rules: Vec<MappingRule>,
}

struct MappingRule {
    /// Keyword to search for in indicator names/descriptions (lowercase).
    keyword: String,
    technique: MitreTechnique,
    confidence: u8,
}

impl Default for MitreMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MitreMapper {
    /// Create a mapper pre-loaded with 50+ technique mappings.
    #[must_use]
    pub fn new() -> Self {
        let mut mapper = Self { rules: Vec::new() };
        mapper.load_default_mappings();
        mapper
    }

    fn add(&mut self, keyword: impl Into<String>, tech: MitreTechnique, confidence: u8) {
        self.rules.push(MappingRule {
            keyword: keyword.into().to_lowercase(),
            technique: tech,
            confidence,
        });
    }

    /// Build an ATT&CK matrix from a triage result.
    #[must_use]
    pub fn build_attack_matrix(&self, result: &TriageResult) -> AttackMatrix {
        let mut matrix = AttackMatrix::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for indicator in &result.indicators {
            let combined = format!(
                "{} {} {}",
                indicator.name, indicator.description, indicator.evidence
            )
            .to_lowercase();

            for rule in &self.rules {
                if combined.contains(&rule.keyword) {
                    let key = format!("{}:{}", rule.technique.id, indicator.name);
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);

                    let m = TechniqueMatch {
                        technique: rule.technique.clone(),
                        matched_indicator: indicator.name.clone(),
                        confidence: rule.confidence,
                        evidence: indicator.evidence.clone(),
                    };
                    matrix.add(m);
                }
            }
        }
        matrix
    }

    /// Build a matrix from a list of indicator strings.
    #[must_use]
    pub fn build_from_strings(&self, indicators: &[&str]) -> AttackMatrix {
        let mut matrix = AttackMatrix::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for &indicator in indicators {
            let lower = indicator.to_lowercase();
            for rule in &self.rules {
                if lower.contains(&rule.keyword) {
                    let key = format!("{}:{}", rule.technique.id, indicator);
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);
                    matrix.add(TechniqueMatch::new(
                        rule.technique.clone(),
                        indicator,
                        rule.confidence,
                    ));
                }
            }
        }
        matrix
    }

    /// Look up a technique by ID.
    #[must_use]
    pub fn lookup_technique(&self, id: &str) -> Option<&MitreTechnique> {
        self.rules
            .iter()
            .find(|r| r.technique.id == id)
            .map(|r| &r.technique)
    }

    /// All technique IDs in the mapper.
    #[must_use]
    pub fn technique_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.rules.iter().map(|r| r.technique.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    // ── Default mappings ──────────────────────────────────────────────────────

    fn load_default_mappings(&mut self) {
        self.load_access_exec_rules();
        self.load_persist_privesc_rules();
        self.load_defense_evasion_a_rules();
        self.load_defense_evasion_b_rules();
        self.load_cred_discovery_rules();
        self.load_lateral_collection_rules();
        self.load_c2_rules();
        self.load_exfil_impact_rules();
        self.load_resource_inject_rules();
    }

    fn load_access_exec_rules(&mut self) {
        // ── Initial Access ────────────────────────────────────────────────────
        self.add(
            "phishing",
            MitreTechnique::new("T1566", "Phishing", "Initial Access"),
            75,
        );
        self.add(
            "exploit",
            MitreTechnique::new(
                "T1190",
                "Exploit Public-Facing Application",
                "Initial Access",
            ),
            80,
        );
        self.add(
            "drive-by",
            MitreTechnique::new("T1189", "Drive-by Compromise", "Initial Access"),
            70,
        );

        // ── Execution ─────────────────────────────────────────────────────────
        self.add(
            "powershell",
            MitreTechnique::new("T1059.001", "PowerShell", "Execution"),
            90,
        );
        self.add(
            "wscript",
            MitreTechnique::new("T1059.005", "Visual Basic", "Execution"),
            80,
        );
        self.add(
            "wmi",
            MitreTechnique::new("T1047", "Windows Management Instrumentation", "Execution"),
            85,
        );
        self.add(
            "cmd",
            MitreTechnique::new("T1059.003", "Windows Command Shell", "Execution"),
            70,
        );
        self.add(
            "shellcode",
            MitreTechnique::new("T1059.005", "Shellcode Execution", "Execution"),
            90,
        );
        self.add(
            "mshta",
            MitreTechnique::new("T1218.005", "Mshta", "Defense Evasion"),
            85,
        );
        self.add(
            "rundll32",
            MitreTechnique::new("T1218.011", "Rundll32", "Defense Evasion"),
            80,
        );
        self.add(
            "regsvr32",
            MitreTechnique::new("T1218.010", "Regsvr32", "Defense Evasion"),
            80,
        );

    }

    fn load_persist_privesc_rules(&mut self) {
        // ── Persistence ───────────────────────────────────────────────────────
        self.add(
            "currentversion\\run",
            MitreTechnique::new(
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "Persistence",
            ),
            90,
        );
        self.add(
            "scheduled-task",
            MitreTechnique::new("T1053.005", "Scheduled Task", "Persistence"),
            85,
        );
        self.add(
            "schtasks",
            MitreTechnique::new("T1053.005", "Scheduled Task", "Persistence"),
            85,
        );
        self.add(
            "service-create",
            MitreTechnique::new("T1543.003", "Windows Service", "Persistence"),
            80,
        );
        self.add(
            "wmi-event",
            MitreTechnique::new("T1546.003", "WMI Event Subscription", "Persistence"),
            85,
        );
        self.add(
            "com hijack",
            MitreTechnique::new("T1546.015", "COM Hijacking", "Persistence"),
            80,
        );
        self.add(
            "init_array",
            MitreTechnique::new("T1546", "Event Triggered Execution", "Persistence"),
            60,
        );

        // ── Privilege Escalation ──────────────────────────────────────────────
        self.add(
            "token impersonat",
            MitreTechnique::new("T1134", "Access Token Manipulation", "Privilege Escalation"),
            85,
        );
        self.add(
            "privilege::debug",
            MitreTechnique::new(
                "T1134.001",
                "Token Impersonation/Theft",
                "Privilege Escalation",
            ),
            90,
        );
        self.add(
            "uac bypass",
            MitreTechnique::new(
                "T1548.002",
                "Bypass User Account Control",
                "Privilege Escalation",
            ),
            85,
        );
        self.add(
            "fodhelper",
            MitreTechnique::new(
                "T1548.002",
                "Bypass User Account Control (fodhelper)",
                "Privilege Escalation",
            ),
            90,
        );
        self.add(
            "juicypotato",
            MitreTechnique::new(
                "T1134.001",
                "JuicyPotato Token Impersonation",
                "Privilege Escalation",
            ),
            90,
        );

    }

    fn load_defense_evasion_a_rules(&mut self) {
        // ── Defense Evasion ───────────────────────────────────────────────────
        self.add(
            "antidebug",
            MitreTechnique::new("T1622", "Debugger Evasion", "Defense Evasion"),
            80,
        );
        self.add(
            "isdebuggerpresent",
            MitreTechnique::new(
                "T1622",
                "Debugger Evasion (IsDebuggerPresent)",
                "Defense Evasion",
            ),
            75,
        );
        self.add(
            "antivm",
            MitreTechnique::new("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion"),
            80,
        );
        self.add(
            "vmware",
            MitreTechnique::new("T1497.001", "System Checks (VMware)", "Defense Evasion"),
            75,
        );
        self.add(
            "virtualbox",
            MitreTechnique::new("T1497.001", "System Checks (VirtualBox)", "Defense Evasion"),
            75,
        );
        self.add(
            "packer",
            MitreTechnique::new("T1027.002", "Software Packing", "Defense Evasion"),
            70,
        );
        self.add(
            "upx",
            MitreTechnique::new("T1027.002", "Software Packing (UPX)", "Defense Evasion"),
            65,
        );
        self.add(
            "vmprotect",
            MitreTechnique::new(
                "T1027.009",
                "Embedded Payloads (VMProtect)",
                "Defense Evasion",
            ),
            75,
        );
        self.add(
            "base64",
            MitreTechnique::new(
                "T1027",
                "Obfuscated Files or Information",
                "Defense Evasion",
            ),
            70,
        );
        self.add(
            "encode",
            MitreTechnique::new(
                "T1027",
                "Obfuscated Files or Information",
                "Defense Evasion",
            ),
            65,
        );
    }

    fn load_defense_evasion_b_rules(&mut self) {
        self.add(
            "obfusc",
            MitreTechnique::new(
                "T1027",
                "Obfuscated Files or Information",
                "Defense Evasion",
            ),
            70,
        );
        self.add(
            "amsi bypass",
            MitreTechnique::new(
                "T1562.001",
                "Disable or Modify Tools (AMSI)",
                "Defense Evasion",
            ),
            90,
        );
        self.add(
            "dll side",
            MitreTechnique::new("T1574.002", "DLL Side-Loading", "Defense Evasion"),
            85,
        );
        self.add(
            "reflective",
            MitreTechnique::new("T1620", "Reflective Code Loading", "Defense Evasion"),
            85,
        );
        self.add(
            "process hollow",
            MitreTechnique::new("T1055.012", "Process Hollowing", "Defense Evasion"),
            90,
        );
        self.add(
            "indirect syscall",
            MitreTechnique::new("T1106", "Native API (syscall)", "Defense Evasion"),
            80,
        );
        self.add(
            "direct syscall",
            MitreTechnique::new("T1106", "Native API (direct syscall)", "Defense Evasion"),
            80,
        );
        self.add(
            "ppid spoof",
            MitreTechnique::new("T1134.004", "Parent PID Spoofing", "Defense Evasion"),
            85,
        );
        self.add(
            "stack spoof",
            MitreTechnique::new(
                "T1027.007",
                "Dynamic API Resolution (stack spoof)",
                "Defense Evasion",
            ),
            80,
        );
        self.add(
            "sign",
            MitreTechnique::new("T1553.002", "Code Signing", "Defense Evasion"),
            50,
        );

    }

    fn load_cred_discovery_rules(&mut self) {
        // ── Credential Access ─────────────────────────────────────────────────
        self.add(
            "sekurlsa",
            MitreTechnique::new("T1003.001", "LSASS Memory", "Credential Access"),
            95,
        );
        self.add(
            "lsass",
            MitreTechnique::new("T1003.001", "LSASS Memory", "Credential Access"),
            90,
        );
        self.add(
            "mimikatz",
            MitreTechnique::new("T1003", "OS Credential Dumping", "Credential Access"),
            95,
        );
        self.add(
            "kerberoast",
            MitreTechnique::new("T1558.003", "Kerberoasting", "Credential Access"),
            90,
        );
        self.add(
            "ntlm",
            MitreTechnique::new(
                "T1557.001",
                "LLMNR/NBT-NS Poisoning (NTLM)",
                "Credential Access",
            ),
            75,
        );
        self.add(
            "credential",
            MitreTechnique::new(
                "T1555",
                "Credentials from Password Stores",
                "Credential Access",
            ),
            70,
        );

        // ── Discovery ─────────────────────────────────────────────────────────
        self.add(
            "process enum",
            MitreTechnique::new("T1057", "Process Discovery", "Discovery"),
            70,
        );
        self.add(
            "registry",
            MitreTechnique::new("T1012", "Query Registry", "Discovery"),
            60,
        );
        self.add(
            "sharphound",
            MitreTechnique::new("T1087", "Account Discovery (SharpHound)", "Discovery"),
            85,
        );
        self.add(
            "bloodhound",
            MitreTechnique::new("T1087", "Account Discovery (BloodHound)", "Discovery"),
            85,
        );
        self.add(
            "network scan",
            MitreTechnique::new("T1046", "Network Service Discovery", "Discovery"),
            75,
        );

    }

    fn load_lateral_collection_rules(&mut self) {
        // ── Lateral Movement ──────────────────────────────────────────────────
        self.add(
            "psexec",
            MitreTechnique::new(
                "T1569.002",
                "Service Execution (PsExec)",
                "Lateral Movement",
            ),
            85,
        );
        self.add(
            "winrm",
            MitreTechnique::new("T1021.006", "Windows Remote Management", "Lateral Movement"),
            80,
        );
        self.add(
            "smb",
            MitreTechnique::new("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
            75,
        );
        self.add(
            "wmic",
            MitreTechnique::new("T1047", "WMI Lateral Movement", "Lateral Movement"),
            80,
        );

        // ── Collection ────────────────────────────────────────────────────────
        self.add(
            "keylog",
            MitreTechnique::new("T1056.001", "Keylogging", "Collection"),
            90,
        );
        self.add(
            "getkeyboardstate",
            MitreTechnique::new("T1056.001", "Keylogging (GetKeyboardState)", "Collection"),
            90,
        );
        self.add(
            "setwindowshookex",
            MitreTechnique::new("T1056.001", "Keylogging (SetWindowsHookEx)", "Collection"),
            90,
        );
        self.add(
            "screenshot",
            MitreTechnique::new("T1113", "Screen Capture", "Collection"),
            80,
        );
        self.add(
            "wallet",
            MitreTechnique::new("T1552", "Unsecured Credentials (wallets)", "Collection"),
            75,
        );

    }

    fn load_c2_rules(&mut self) {
        // ── Command and Control ───────────────────────────────────────────────
        self.add(
            "c2",
            MitreTechnique::new("T1071", "Application Layer Protocol", "Command and Control"),
            70,
        );
        self.add(
            "http c2",
            MitreTechnique::new(
                "T1071.001",
                "Web Protocols (HTTP C2)",
                "Command and Control",
            ),
            85,
        );
        self.add(
            "beacon",
            MitreTechnique::new("T1071.001", "Web Protocols (Beacon)", "Command and Control"),
            85,
        );
        self.add(
            "dns tunnel",
            MitreTechnique::new("T1071.004", "DNS (Tunneling)", "Command and Control"),
            85,
        );
        self.add(
            "cobalt strike",
            MitreTechnique::new("T1071.001", "Cobalt Strike C2", "Command and Control"),
            95,
        );
        self.add(
            "meterpreter",
            MitreTechnique::new(
                "T1219",
                "Remote Access Software (Meterpreter)",
                "Command and Control",
            ),
            95,
        );
        self.add(
            "sliver",
            MitreTechnique::new(
                "T1219",
                "Remote Access Software (Sliver)",
                "Command and Control",
            ),
            90,
        );
        self.add(
            "ngrok",
            MitreTechnique::new(
                "T1090.003",
                "Multi-hop Proxy (Ngrok)",
                "Command and Control",
            ),
            75,
        );
        self.add(
            "tunnel",
            MitreTechnique::new("T1572", "Protocol Tunneling", "Command and Control"),
            70,
        );
        self.add(
            "named pipe",
            MitreTechnique::new("T1559.001", "Component Object Model", "Command and Control"),
            70,
        );

    }

    fn load_exfil_impact_rules(&mut self) {
        // ── Exfiltration ──────────────────────────────────────────────────────
        self.add(
            "exfil",
            MitreTechnique::new("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
            80,
        );
        self.add(
            "pastebin",
            MitreTechnique::new(
                "T1567.002",
                "Exfiltration to Code Repository",
                "Exfiltration",
            ),
            80,
        );
        self.add(
            "stealer",
            MitreTechnique::new("T1005", "Data from Local System", "Exfiltration"),
            85,
        );
        self.add(
            "firefox",
            MitreTechnique::new("T1555.003", "Credentials from Web Browsers", "Collection"),
            80,
        );
        self.add(
            "login data",
            MitreTechnique::new(
                "T1555.003",
                "Credentials from Web Browsers (Login Data)",
                "Collection",
            ),
            85,
        );

        // ── Impact ────────────────────────────────────────────────────────────
        self.add(
            "ransom",
            MitreTechnique::new("T1486", "Data Encrypted for Impact", "Impact"),
            95,
        );
        self.add(
            "wannacry",
            MitreTechnique::new("T1486", "Data Encrypted for Impact (WannaCry)", "Impact"),
            95,
        );
        self.add(
            "lockbit",
            MitreTechnique::new("T1486", "Data Encrypted for Impact (LockBit)", "Impact"),
            95,
        );
        self.add(
            "vssadmin delete",
            MitreTechnique::new("T1490", "Inhibit System Recovery", "Impact"),
            95,
        );
        self.add(
            "wiper",
            MitreTechnique::new("T1485", "Data Destruction", "Impact"),
            95,
        );
        self.add(
            "mbr",
            MitreTechnique::new("T1561.002", "Disk Structure Wipe (MBR)", "Impact"),
            90,
        );
        self.add(
            "ddos",
            MitreTechnique::new("T1498", "Network Denial of Service", "Impact"),
            85,
        );

    }

    fn load_resource_inject_rules(&mut self) {
        // ── Resource Development ──────────────────────────────────────────────
        self.add(
            "stager",
            MitreTechnique::new("T1608.002", "Upload Tool (Stager)", "Resource Development"),
            80,
        );
        self.add(
            "dropper",
            MitreTechnique::new(
                "T1608.001",
                "Upload Malware (Dropper)",
                "Resource Development",
            ),
            80,
        );

        // ── Injection sub-techniques ──────────────────────────────────────────
        self.add(
            "virtualallocex",
            MitreTechnique::new("T1055", "Process Injection", "Defense Evasion"),
            90,
        );
        self.add(
            "writeprocessmemory",
            MitreTechnique::new(
                "T1055",
                "Process Injection (WriteProcessMemory)",
                "Defense Evasion",
            ),
            90,
        );
        self.add(
            "createremotethread",
            MitreTechnique::new("T1055.003", "Thread Execution Hijacking", "Defense Evasion"),
            90,
        );
        self.add(
            "atombomb",
            MitreTechnique::new("T1055.015", "ListPlanting (AtomBombing)", "Defense Evasion"),
            85,
        );
        self.add(
            "dll hollow",
            MitreTechnique::new(
                "T1055.001",
                "Dynamic-link Library Injection",
                "Defense Evasion",
            ),
            90,
        );
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_has_50_plus_techniques() {
        let mapper = MitreMapper::new();
        let ids = mapper.technique_ids();
        assert!(
            ids.len() >= 30,
            "Expected 30+ unique technique IDs, got {}",
            ids.len()
        );
        assert!(
            mapper.rule_count() >= 50,
            "Expected 50+ rules, got {}",
            mapper.rule_count()
        );
    }

    #[test]
    fn build_from_strings_powershell() {
        let mapper = MitreMapper::new();
        let matrix = mapper.build_from_strings(&["powershell encoded command detected"]);
        assert!(!matrix.is_empty());
        assert!(matrix.tactics().contains(&"Execution"));
    }

    #[test]
    fn build_from_strings_ransomware() {
        let mapper = MitreMapper::new();
        let matrix = mapper.build_from_strings(&["ransom note found", "vssadmin delete shadows"]);
        assert!(!matrix.is_empty());
        assert!(matrix.tactics().contains(&"Impact"));
    }

    #[test]
    fn build_from_strings_mimikatz() {
        let mapper = MitreMapper::new();
        let matrix = mapper.build_from_strings(&["sekurlsa module loaded"]);
        assert!(!matrix.is_empty());
        let cred_matches = matrix.techniques_for_tactic("Credential Access");
        assert!(!cred_matches.is_empty());
    }

    #[test]
    fn build_attack_matrix_from_triage_result() {
        use crate::FileKind;
        use crate::TriageResult;

        let mapper = MitreMapper::new();
        let data = b"MZ";
        let mut result = TriageResult::new(FileKind::Pe32, data);
        result.add_indicator(TriageIndicator {
            name: "process-injection".to_string(),
            description: "VirtualAllocEx WriteProcessMemory detected".to_string(),
            threat_level: ThreatLevel::High,
            category: "injection".to_string(),
            evidence: "api=VirtualAllocEx".to_string(),
        });

        let matrix = mapper.build_attack_matrix(&result);
        assert!(!matrix.is_empty());
    }

    #[test]
    fn lookup_technique_by_id() {
        let mapper = MitreMapper::new();
        // Some technique must be findable by ID
        let ids = mapper.technique_ids();
        assert!(!ids.is_empty());
        let first = ids[0];
        assert!(mapper.lookup_technique(first).is_some());
    }

    #[test]
    fn attack_matrix_top_match() {
        let mapper = MitreMapper::new();
        let matrix = mapper.build_from_strings(&["mimikatz sekurlsa", "powershell"]);
        if !matrix.is_empty() {
            let top = matrix.top_match().unwrap();
            assert!(top.confidence > 0);
        }
    }

    #[test]
    fn attack_matrix_summary_format() {
        let mapper = MitreMapper::new();
        let matrix = mapper.build_from_strings(&["ransomware encrypt"]);
        let s = matrix.summary();
        // May be empty if no match, but should not panic
        let _ = s;
    }

    #[test]
    fn attack_matrix_to_json() {
        let mapper = MitreMapper::new();
        let matrix = mapper.build_from_strings(&["cobalt strike"]);
        let json = matrix.to_json().unwrap();
        assert!(json.contains("matches") || json.contains("by_tactic"));
    }

    #[test]
    fn technique_display() {
        let t = MitreTechnique::new("T1055", "Process Injection", "Defense Evasion");
        let s = t.to_string();
        assert!(s.contains("T1055"));
        assert!(s.contains("Process Injection"));
    }

    #[test]
    fn multiple_indicators_mapped() {
        let mapper = MitreMapper::new();
        let indicators = vec![
            "powershell encoded command",
            "virtualallocex cross-process",
            "ransom note encrypted files",
            "mimikatz credential dump",
            "isdebuggerpresent anti-debug",
        ];
        let matrix = mapper.build_from_strings(&indicators);
        assert!(matrix.technique_count() >= 4);
    }
}
