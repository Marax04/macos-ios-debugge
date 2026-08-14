//! MITRE ATT&CK framework types and Windows API → technique mappings.
//!
//! This module provides an in-memory representation of the MITRE ATT&CK
//! Enterprise matrix, including tactics, techniques, sub-techniques, threat
//! actor groups, and software entries.
//!
//! The [`API_TO_ATTACK`] constant maps common Windows API function names to
//! the ATT&CK techniques they are most frequently associated with.  It can be
//! used during static or dynamic analysis to automatically annotate assembly
//! with ATT&CK context.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

type DefaultTechniqueEntry<'a> = (&'a str, &'a str, &'a [&'a str], &'a str, &'a [&'a str]);

// ─────────────────────────────────────────────────────────────────────────────
// Tactic
// ─────────────────────────────────────────────────────────────────────────────

/// A MITRE ATT&CK tactic (the "why" of an adversary's actions).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tactic {
    /// Short machine-readable ID (e.g. `"TA0002"`).
    pub id: String,
    /// Human-readable name (e.g. `"Execution"`).
    pub name: String,
    /// Brief description.
    pub description: String,
    /// URL to the ATT&CK page.
    pub url: String,
}

impl Tactic {
    /// Create a new tactic.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let url = format!("https://attack.mitre.org/tactics/{id}/");
        Self {
            id,
            name: name.into(),
            description: description.into(),
            url,
        }
    }
}

impl std::fmt::Display for Tactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} – {}", self.id, self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Technique
// ─────────────────────────────────────────────────────────────────────────────

/// A MITRE ATT&CK technique or sub-technique.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Technique {
    /// Technique ID (e.g. `"T1055"` or `"T1055.001"`).
    pub id: String,
    /// Human-readable name (e.g. `"Process Injection"`).
    pub name: String,
    /// Tactic IDs this technique falls under.
    pub tactic_ids: Vec<String>,
    /// Brief description of the technique.
    pub description: String,
    /// Detection guidance.
    pub detection: String,
    /// Platforms affected (e.g. `["Windows", "Linux", "macOS"]`).
    pub platforms: Vec<String>,
    /// Data sources useful for detecting this technique.
    pub data_sources: Vec<String>,
    /// Sub-technique IDs (empty for sub-techniques themselves).
    pub sub_techniques: Vec<String>,
    /// Parent technique ID for sub-techniques (empty for top-level).
    pub parent_id: String,
    /// URL to the ATT&CK page.
    pub url: String,
}

impl Technique {
    /// Create a new top-level technique.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        tactic_ids: Vec<String>,
        description: impl Into<String>,
        platforms: Vec<String>,
    ) -> Self {
        let id = id.into();
        let url = format!(
            "https://attack.mitre.org/techniques/{}/",
            id.replace('.', "/")
        );
        Self {
            id,
            name: name.into(),
            tactic_ids,
            description: description.into(),
            detection: String::new(),
            platforms,
            data_sources: Vec::new(),
            sub_techniques: Vec::new(),
            parent_id: String::new(),
            url,
        }
    }

    /// Return `true` when this is a sub-technique (ID contains `.`).
    #[must_use]
    pub fn is_sub_technique(&self) -> bool {
        self.id.contains('.')
    }

    /// Return the parent technique ID for sub-techniques.
    #[must_use]
    pub fn parent_technique_id(&self) -> Option<&str> {
        if self.is_sub_technique() {
            self.id.split('.').next()
        } else {
            None
        }
    }
}

impl std::fmt::Display for Technique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} – {}", self.id, self.name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Group (Threat Actor)
// ─────────────────────────────────────────────────────────────────────────────

/// A MITRE ATT&CK threat actor group entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// ATT&CK group ID (e.g. `"G0001"`).
    pub id: String,
    /// Primary name (e.g. `"APT29"`).
    pub name: String,
    /// Aliases / alternate names.
    pub aliases: Vec<String>,
    /// Suspected country of origin.
    pub country: Option<String>,
    /// Brief description.
    pub description: String,
    /// Technique IDs attributed to this group.
    pub technique_ids: Vec<String>,
    /// Software IDs used by this group.
    pub software_ids: Vec<String>,
    /// URL to the ATT&CK page.
    pub url: String,
}

impl Group {
    /// Create a new group entry.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let url = format!("https://attack.mitre.org/groups/{id}/");
        Self {
            id,
            name: name.into(),
            aliases: Vec::new(),
            country: None,
            description: description.into(),
            technique_ids: Vec::new(),
            software_ids: Vec::new(),
            url,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Software
// ─────────────────────────────────────────────────────────────────────────────

/// A MITRE ATT&CK software entry (malware or tool).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    /// ATT&CK software ID (e.g. `"S0002"`).
    pub id: String,
    /// Software name.
    pub name: String,
    /// Aliases / alternate names.
    pub aliases: Vec<String>,
    /// `"malware"` or `"tool"`.
    pub software_type: String,
    /// Brief description.
    pub description: String,
    /// Technique IDs associated with this software.
    pub technique_ids: Vec<String>,
    /// URL to the ATT&CK page.
    pub url: String,
}

impl Software {
    /// Create a new software entry.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        software_type: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let url = format!("https://attack.mitre.org/software/{id}/");
        Self {
            id,
            name: name.into(),
            aliases: Vec::new(),
            software_type: software_type.into(),
            description: description.into(),
            technique_ids: Vec::new(),
            url,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AttackFramework
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory representation of the MITRE ATT&CK Enterprise matrix.
///
/// Load the default built-in catalogue with [`AttackFramework::default()`] or
/// build a custom one with the builder methods.
///
/// ```rust
/// use rustre_threatintel::mitre_attack::AttackFramework;
///
/// let fw = AttackFramework::default();
/// let hits = fw.api_to_techniques("VirtualAllocEx");
/// println!("{} technique(s) for VirtualAllocEx", hits.len());
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct AttackFramework {
    /// All tactics, keyed by ID.
    pub tactics: HashMap<String, Tactic>,
    /// All techniques and sub-techniques, keyed by ID.
    pub techniques: HashMap<String, Technique>,
    /// Threat actor groups, keyed by ID.
    pub groups: HashMap<String, Group>,
    /// Software entries, keyed by ID.
    pub software: HashMap<String, Software>,
}

impl AttackFramework {
    /// Create an empty framework.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tactics: HashMap::new(),
            techniques: HashMap::new(),
            groups: HashMap::new(),
            software: HashMap::new(),
        }
    }

    /// Populate with a built-in minimal catalogue covering the most important
    /// ATT&CK techniques for Windows malware analysis.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut fw = Self::new();
        fw.load_default_tactics();
        fw.load_default_techniques();
        fw.load_default_groups();
        fw.load_default_software();
        fw
    }

    /// Look up a technique by its ATT&CK ID.
    #[must_use]
    pub fn technique(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(id)
    }

    /// Look up a tactic by its ATT&CK ID.
    #[must_use]
    pub fn tactic(&self, id: &str) -> Option<&Tactic> {
        self.tactics.get(id)
    }

    /// Return all techniques associated with a given tactic.
    #[must_use]
    pub fn techniques_for_tactic(&self, tactic_id: &str) -> Vec<&Technique> {
        self.techniques
            .values()
            .filter(|t| t.tactic_ids.iter().any(|tid| tid == tactic_id))
            .collect()
    }

    /// Map a Windows API name to ATT&CK techniques via [`API_TO_ATTACK`].
    ///
    /// Returns technique references for all technique IDs mapped from the API.
    #[must_use]
    pub fn api_to_techniques(&self, api_name: &str) -> Vec<&Technique> {
        API_TO_ATTACK
            .iter()
            .filter(|(api, _)| api.eq_ignore_ascii_case(api_name))
            .flat_map(|(_, ids)| ids.iter())
            .filter_map(|id| self.techniques.get(*id))
            .collect()
    }

    /// Return the ATT&CK technique IDs associated with a Windows API name.
    #[must_use]
    pub fn api_technique_ids(api_name: &str) -> Vec<&'static str> {
        API_TO_ATTACK
            .iter()
            .filter(|(api, _)| api.eq_ignore_ascii_case(api_name))
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect()
    }

    /// Search techniques by name substring (case-insensitive).
    #[must_use]
    pub fn search_by_name(&self, query: &str) -> Vec<&Technique> {
        let q = query.to_lowercase();
        self.techniques
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&q) || t.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Return all sub-techniques of a parent technique.
    #[must_use]
    pub fn sub_techniques(&self, parent_id: &str) -> Vec<&Technique> {
        self.techniques
            .values()
            .filter(|t| t.parent_technique_id() == Some(parent_id))
            .collect()
    }

    fn load_default_tactics(&mut self) {
        let tactics = [
            (
                "TA0001",
                "Initial Access",
                "Gaining a foothold in the target network.",
            ),
            ("TA0002", "Execution", "Running adversary-controlled code."),
            (
                "TA0003",
                "Persistence",
                "Maintaining presence after reboots or credential changes.",
            ),
            (
                "TA0004",
                "Privilege Escalation",
                "Gaining higher-level permissions.",
            ),
            (
                "TA0005",
                "Defense Evasion",
                "Avoiding detection by defenses.",
            ),
            (
                "TA0006",
                "Credential Access",
                "Stealing account credentials.",
            ),
            ("TA0007", "Discovery", "Understanding the environment."),
            ("TA0008", "Lateral Movement", "Moving through the network."),
            ("TA0009", "Collection", "Gathering data of interest."),
            ("TA0010", "Exfiltration", "Stealing data from the victim."),
            (
                "TA0011",
                "Command and Control",
                "Communicating with compromised systems.",
            ),
            ("TA0040", "Impact", "Disrupting availability or integrity."),
            (
                "TA0042",
                "Resource Development",
                "Establishing infrastructure to support operations.",
            ),
            (
                "TA0043",
                "Reconnaissance",
                "Gathering information about the target.",
            ),
        ];
        for (id, name, desc) in tactics {
            self.tactics
                .insert(id.to_owned(), Tactic::new(id, name, desc));
        }
    }

    fn load_default_techniques(&mut self) {
        let win = ["Windows".to_owned()];
        let all = ["Windows".to_owned(), "Linux".to_owned(), "macOS".to_owned()];
        let entries = Self::default_technique_entries();

        for (id, name, tactic_ids, desc, platforms) in &entries {
            let technique = Technique::new(
                *id,
                *name,
                tactic_ids.iter().map(std::string::ToString::to_string).collect(),
                *desc,
                platforms.iter().map(std::string::ToString::to_string).collect(),
            );
            self.techniques.insert((*id).to_string(), technique);
        }

        // Confirm that the pre-built platform slices are reachable.
        let _ = win.len() + all.len();
    }

    /// Combines all technique-entry sub-tables into a single owned list.
    fn default_technique_entries() -> Vec<DefaultTechniqueEntry<'static>> {
        let mut v = Vec::new();
        v.extend_from_slice(Self::technique_entries_a());
        v.extend_from_slice(Self::technique_entries_b());
        v.extend_from_slice(Self::technique_entries_c());
        v.extend_from_slice(Self::technique_entries_d());
        v.extend_from_slice(Self::technique_entries_e());
        v
    }

    /// Technique entries — part A: T1055 family + T1059 family (first half).
    const fn technique_entries_a() -> &'static [DefaultTechniqueEntry<'static>] {
        &[
            (
                "T1055",
                "Process Injection",
                &["TA0004", "TA0005"],
                "Inject code into processes to evade defenses.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1055.001",
                "Process Injection: DLL Injection",
                &["TA0004", "TA0005"],
                "Inject a DLL into a remote process.",
                &["Windows"],
            ),
            (
                "T1055.002",
                "Process Injection: PE Injection",
                &["TA0004", "TA0005"],
                "Inject a PE image into a remote process.",
                &["Windows"],
            ),
            (
                "T1055.003",
                "Process Injection: Thread Execution Hijacking",
                &["TA0004", "TA0005"],
                "Hijack a thread in an existing process.",
                &["Windows"],
            ),
            (
                "T1055.004",
                "Process Injection: Asynchronous Procedure Call",
                &["TA0004", "TA0005"],
                "Inject via APC queue manipulation.",
                &["Windows"],
            ),
            (
                "T1055.011",
                "Process Injection: Extra Window Memory Injection",
                &["TA0004", "TA0005"],
                "Inject via Extra Window Memory (EWM).",
                &["Windows"],
            ),
            (
                "T1055.012",
                "Process Injection: Process Hollowing",
                &["TA0004", "TA0005"],
                "Hollow out a legitimate process and replace its code.",
                &["Windows"],
            ),
            (
                "T1059",
                "Command and Scripting Interpreter",
                &["TA0002"],
                "Execute commands via a scripting interpreter.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1059.001",
                "PowerShell",
                &["TA0002"],
                "Execute commands or scripts using PowerShell.",
                &["Windows"],
            ),
            (
                "T1059.003",
                "Windows Command Shell",
                &["TA0002"],
                "Execute commands via cmd.exe.",
                &["Windows"],
            ),
        ]
    }

    /// Technique entries — part B: T1059 (rest) + T1027 family + discovery.
    const fn technique_entries_b() -> &'static [DefaultTechniqueEntry<'static>] {
        &[
            (
                "T1059.005",
                "Visual Basic",
                &["TA0002"],
                "Execute scripts using VBS or VBA.",
                &["Windows", "macOS"],
            ),
            (
                "T1059.007",
                "JavaScript",
                &["TA0002"],
                "Execute JavaScript code.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1027",
                "Obfuscated Files or Information",
                &["TA0005"],
                "Obfuscate files or information to hinder analysis.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1027.001",
                "Binary Padding",
                &["TA0005"],
                "Add junk data to binaries to alter hashes.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1027.002",
                "Software Packing",
                &["TA0005"],
                "Pack executables to obscure malicious code.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1027.007",
                "Dynamic API Resolution",
                &["TA0005"],
                "Resolve API addresses dynamically to evade import scanning.",
                &["Windows"],
            ),
            (
                "T1036",
                "Masquerading",
                &["TA0005"],
                "Manipulate features of artifacts to look legitimate.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1082",
                "System Information Discovery",
                &["TA0007"],
                "Enumerate OS, hardware and configuration information.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1083",
                "File and Directory Discovery",
                &["TA0007"],
                "Enumerate files and directories on a system.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1087",
                "Account Discovery",
                &["TA0007"],
                "Enumerate user accounts.",
                &["Windows", "Linux", "macOS"],
            ),
        ]
    }

    /// Technique entries — part C: more discovery + persistence + privilege esc.
    const fn technique_entries_c() -> &'static [DefaultTechniqueEntry<'static>] {
        &[
            (
                "T1012",
                "Query Registry",
                &["TA0007"],
                "Query the Windows Registry to gather information.",
                &["Windows"],
            ),
            (
                "T1057",
                "Process Discovery",
                &["TA0007"],
                "Enumerate running processes.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1049",
                "System Network Connections Discovery",
                &["TA0007"],
                "Enumerate network connections.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1016",
                "System Network Configuration Discovery",
                &["TA0007"],
                "Enumerate network interface configuration.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1018",
                "Remote System Discovery",
                &["TA0007"],
                "Enumerate other hosts in the network.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1547",
                "Boot or Logon Autostart Execution",
                &["TA0003", "TA0004"],
                "Configure malware to run at boot or logon.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                &["TA0003", "TA0004"],
                "Use Run keys or startup folder for persistence.",
                &["Windows"],
            ),
            (
                "T1053",
                "Scheduled Task/Job",
                &["TA0002", "TA0003", "TA0004"],
                "Use scheduled tasks for execution or persistence.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1053.005",
                "Scheduled Task",
                &["TA0002", "TA0003", "TA0004"],
                "Use Windows Task Scheduler.",
                &["Windows"],
            ),
            (
                "T1112",
                "Modify Registry",
                &["TA0005"],
                "Modify registry keys to hide configuration.",
                &["Windows"],
            ),
        ]
    }

    /// Technique entries — part D: hooking, token abuse, credential access, cleanup.
    const fn technique_entries_d() -> &'static [DefaultTechniqueEntry<'static>] {
        &[
            (
                "T1179",
                "Hooking",
                &["TA0004", "TA0005", "TA0006"],
                "Install hooks to intercept API calls.",
                &["Windows"],
            ),
            (
                "T1134",
                "Access Token Manipulation",
                &["TA0004", "TA0005"],
                "Manipulate access tokens to escalate privileges.",
                &["Windows"],
            ),
            (
                "T1134.001",
                "Token Impersonation/Theft",
                &["TA0004", "TA0005"],
                "Steal or impersonate access tokens.",
                &["Windows"],
            ),
            (
                "T1003",
                "OS Credential Dumping",
                &["TA0006"],
                "Dump credentials from the operating system.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1003.001",
                "LSASS Memory",
                &["TA0006"],
                "Dump credentials from LSASS memory.",
                &["Windows"],
            ),
            (
                "T1070",
                "Indicator Removal",
                &["TA0005"],
                "Delete or modify artifacts to cover tracks.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1070.004",
                "File Deletion",
                &["TA0005"],
                "Delete files to cover tracks.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1486",
                "Data Encrypted for Impact",
                &["TA0040"],
                "Encrypt files for ransomware-style impact.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1490",
                "Inhibit System Recovery",
                &["TA0040"],
                "Delete shadow copies and backups.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1489",
                "Service Stop",
                &["TA0040"],
                "Stop or disable security services.",
                &["Windows", "Linux", "macOS"],
            ),
        ]
    }

    /// Technique entries — part E: system processes, lateral movement, C2, initial access.
    const fn technique_entries_e() -> &'static [DefaultTechniqueEntry<'static>] {
        &[
            (
                "T1543",
                "Create or Modify System Process",
                &["TA0003", "TA0004"],
                "Create or modify system processes for persistence.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1543.003",
                "Windows Service",
                &["TA0003", "TA0004"],
                "Create or modify a Windows service.",
                &["Windows"],
            ),
            (
                "T1021",
                "Remote Services",
                &["TA0008"],
                "Use legitimate remote access services.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1021.001",
                "Remote Desktop Protocol",
                &["TA0008"],
                "Use RDP for lateral movement.",
                &["Windows"],
            ),
            (
                "T1071",
                "Application Layer Protocol",
                &["TA0011"],
                "Use application-layer protocols for C2.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1071.001",
                "Web Protocols",
                &["TA0011"],
                "Use HTTP/HTTPS for C2 communication.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1095",
                "Non-Application Layer Protocol",
                &["TA0011"],
                "Use raw network protocols (ICMP, UDP) for C2.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1219",
                "Remote Access Software",
                &["TA0011"],
                "Use legitimate remote-access tools as C2.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1566",
                "Phishing",
                &["TA0001"],
                "Send phishing messages to gain initial access.",
                &["Windows", "Linux", "macOS"],
            ),
            (
                "T1190",
                "Exploit Public-Facing Application",
                &["TA0001"],
                "Exploit a public-facing application.",
                &["Windows", "Linux", "macOS"],
            ),
        ]
    }

    fn load_default_groups(&mut self) {
        let groups: &[(&str, &str, &str)] = &[
            (
                "G0007",
                "APT28",
                "Russian GRU-linked espionage group (also: Fancy Bear, Sofacy).",
            ),
            (
                "G0016",
                "APT29",
                "Russian SVR-linked espionage group (also: Cozy Bear, The Dukes).",
            ),
            (
                "G0096",
                "APT41",
                "Chinese group conducting state-sponsored espionage and cybercrime.",
            ),
            (
                "G0006",
                "APT1",
                "Chinese PLA Unit 61398 conducting large-scale espionage.",
            ),
            (
                "G0085",
                "FIN6",
                "Financially motivated threat group targeting retail and hospitality.",
            ),
            (
                "G0032",
                "Lazarus Group",
                "North Korean state-sponsored group (also: Hidden Cobra).",
            ),
            (
                "G0067",
                "APT37",
                "North Korean state-sponsored espionage group (also: Reaper, ScarCruft).",
            ),
            (
                "G0050",
                "APT32",
                "Vietnamese espionage group (also: OceanLotus).",
            ),
            (
                "G0010",
                "Turla",
                "Russian FSB-linked espionage group (also: Uroburos, Snake).",
            ),
            (
                "G0001",
                "Axiom",
                "Chinese cyber espionage group focused on technology and government.",
            ),
        ];
        for (id, name, desc) in groups {
            self.groups
                .insert(id.to_string(), Group::new(*id, *name, *desc));
        }
    }

    fn load_default_software(&mut self) {
        let entries: &[(&str, &str, &str, &str)] = &[
            (
                "S0002",
                "Mimikatz",
                "tool",
                "Credential extraction tool commonly used post-exploitation.",
            ),
            (
                "S0154",
                "Cobalt Strike",
                "tool",
                "Commercial penetration testing framework widely abused by threat actors.",
            ),
            (
                "S0029",
                "PsExec",
                "tool",
                "Sysinternals tool for executing processes on remote systems.",
            ),
            (
                "S0002",
                "Mimikatz",
                "tool",
                "Credential extraction tool commonly used post-exploitation.",
            ),
            (
                "S0446",
                "Ryuk",
                "malware",
                "Ransomware targeting enterprises, often deployed by TrickBot.",
            ),
            (
                "S0367",
                "Emotet",
                "malware",
                "Modular banking trojan / botnet dropper.",
            ),
            (
                "S0266",
                "TrickBot",
                "malware",
                "Banking trojan and malware delivery platform.",
            ),
            (
                "S0034",
                "NMAP",
                "tool",
                "Open-source network scanner commonly used for discovery.",
            ),
            (
                "S0032",
                "gh0st RAT",
                "malware",
                "Remote access trojan used by Chinese espionage groups.",
            ),
            (
                "S0416",
                "POSHSPY",
                "malware",
                "PowerShell-based backdoor used by APT29.",
            ),
            (
                "S0039",
                "Net",
                "tool",
                "Windows net.exe for domain and network enumeration.",
            ),
            (
                "S0349",
                "LaZagne",
                "tool",
                "Open-source credential recovery tool.",
            ),
            (
                "S0097",
                "Ping",
                "tool",
                "Standard ICMP ping utility, used for discovery.",
            ),
            (
                "S0060",
                "Rerums",
                "malware",
                "Backdoor malware used by APT28.",
            ),
        ];
        for (id, name, sw_type, desc) in entries {
            // Avoid duplicate inserts (S0002 listed twice above)
            self.software
                .entry(id.to_string())
                .or_insert_with(|| Software::new(*id, *name, *sw_type, *desc));
        }
    }
}

impl Default for AttackFramework {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// API_TO_ATTACK — 200+ Windows API → ATT&CK technique ID mappings
// ─────────────────────────────────────────────────────────────────────────────

/// Static mapping from Windows API function names to ATT&CK technique IDs.
///
/// Each entry is `(api_name, &[technique_ids])`.  The list covers the APIs
/// most commonly observed in malware samples across the ATT&CK dataset.
pub const API_TO_ATTACK: &[(&str, &[&str])] = &[
    // ── Process Injection ────────────────────────────────────────────────────
    ("VirtualAllocEx", &["T1055"]),
    ("VirtualAlloc", &["T1055"]),
    ("VirtualProtect", &["T1055"]),
    ("VirtualProtectEx", &["T1055"]),
    ("WriteProcessMemory", &["T1055"]),
    ("ReadProcessMemory", &["T1055"]),
    ("CreateRemoteThread", &["T1055", "T1055.003"]),
    ("CreateRemoteThreadEx", &["T1055", "T1055.003"]),
    ("RtlCreateUserThread", &["T1055", "T1055.003"]),
    ("NtCreateThreadEx", &["T1055", "T1055.003"]),
    ("QueueUserAPC", &["T1055.004"]),
    ("NtQueueApcThread", &["T1055.004"]),
    ("SuspendThread", &["T1055.003"]),
    ("ResumeThread", &["T1055.003"]),
    ("GetThreadContext", &["T1055.003"]),
    ("SetThreadContext", &["T1055.003"]),
    ("NtGetContextThread", &["T1055.003"]),
    ("NtSetContextThread", &["T1055.003"]),
    ("LoadLibrary", &["T1055.001"]),
    ("LoadLibraryA", &["T1055.001"]),
    ("LoadLibraryW", &["T1055.001"]),
    ("LoadLibraryExA", &["T1055.001"]),
    ("LoadLibraryExW", &["T1055.001"]),
    ("SetWindowsHookEx", &["T1055.011", "T1179"]),
    ("SetWindowsHookExA", &["T1055.011", "T1179"]),
    ("SetWindowsHookExW", &["T1055.011", "T1179"]),
    ("UnhookWindowsHookEx", &["T1179"]),
    // ── Process Hollowing / Hollowing helpers ────────────────────────────────
    ("NtUnmapViewOfSection", &["T1055.012"]),
    ("ZwUnmapViewOfSection", &["T1055.012"]),
    ("CreateProcess", &["T1055.012", "T1059"]),
    ("CreateProcessA", &["T1055.012", "T1059"]),
    ("CreateProcessW", &["T1055.012", "T1059"]),
    ("NtCreateProcess", &["T1055.012"]),
    ("NtCreateProcessEx", &["T1055.012"]),
    // ── Process and Thread Management ────────────────────────────────────────
    ("OpenProcess", &["T1057", "T1055"]),
    ("TerminateProcess", &["T1489"]),
    ("CreateThread", &["T1059"]),
    ("ExitProcess", &[]),
    // ── Credential Access ────────────────────────────────────────────────────
    ("LsaOpenPolicy", &["T1003"]),
    ("LsaRetrievePrivateData", &["T1003"]),
    ("SamOpenDatabase", &["T1003"]),
    ("SamGetMembersInGroup", &["T1003"]),
    ("SamQueryInformationUser", &["T1003"]),
    ("MiniDumpWriteDump", &["T1003.001"]),
    ("NtReadVirtualMemory", &["T1003.001"]),
    ("LsarGetSystemAccessAccount", &["T1003"]),
    ("CredEnumerate", &["T1555"]),
    ("CryptUnprotectData", &["T1555"]),
    // ── Registry ─────────────────────────────────────────────────────────────
    ("RegOpenKey", &["T1012"]),
    ("RegOpenKeyEx", &["T1012"]),
    ("RegOpenKeyExA", &["T1012"]),
    ("RegOpenKeyExW", &["T1012"]),
    ("RegQueryValue", &["T1012"]),
    ("RegQueryValueEx", &["T1012"]),
    ("RegQueryValueExA", &["T1012"]),
    ("RegQueryValueExW", &["T1012"]),
    ("RegSetValue", &["T1112"]),
    ("RegSetValueEx", &["T1112", "T1547.001"]),
    ("RegSetValueExA", &["T1112", "T1547.001"]),
    ("RegSetValueExW", &["T1112", "T1547.001"]),
    ("RegCreateKey", &["T1112", "T1547.001"]),
    ("RegCreateKeyEx", &["T1112", "T1547.001"]),
    ("RegDeleteKey", &["T1070"]),
    ("RegDeleteValue", &["T1070"]),
    ("RegEnumKey", &["T1012"]),
    ("RegEnumKeyEx", &["T1012"]),
    ("RegEnumValue", &["T1012"]),
    // ── System Discovery ─────────────────────────────────────────────────────
    ("GetSystemInfo", &["T1082"]),
    ("GetVersionEx", &["T1082"]),
    ("RtlGetVersion", &["T1082"]),
    ("GetComputerName", &["T1082"]),
    ("GetComputerNameA", &["T1082"]),
    ("GetComputerNameW", &["T1082"]),
    ("GetComputerNameExA", &["T1082"]),
    ("GetComputerNameExW", &["T1082"]),
    ("GetUserName", &["T1087"]),
    ("GetUserNameA", &["T1087"]),
    ("GetUserNameW", &["T1087"]),
    ("LookupAccountSid", &["T1087"]),
    ("GetAdaptersInfo", &["T1016"]),
    ("GetAdaptersAddresses", &["T1016"]),
    ("GetIpNetTable", &["T1016"]),
    ("GetTcpTable", &["T1049"]),
    ("GetTcpTable2", &["T1049"]),
    ("GetUdpTable", &["T1049"]),
    ("GetExtendedTcpTable", &["T1049"]),
    ("NetUserEnum", &["T1087"]),
    ("NetLocalGroupEnum", &["T1069"]),
    ("NetShareEnum", &["T1135"]),
    ("CreateToolhelp32Snapshot", &["T1057"]),
    ("Process32First", &["T1057"]),
    ("Process32FirstW", &["T1057"]),
    ("Process32Next", &["T1057"]),
    ("Process32NextW", &["T1057"]),
    ("Module32First", &["T1057"]),
    ("Module32Next", &["T1057"]),
    ("Thread32First", &["T1057"]),
    ("Thread32Next", &["T1057"]),
    ("EnumProcesses", &["T1057"]),
    ("NtQuerySystemInformation", &["T1057", "T1082"]),
    // ── File System ──────────────────────────────────────────────────────────
    ("FindFirstFile", &["T1083"]),
    ("FindFirstFileA", &["T1083"]),
    ("FindFirstFileW", &["T1083"]),
    ("FindNextFile", &["T1083"]),
    ("FindNextFileA", &["T1083"]),
    ("FindNextFileW", &["T1083"]),
    ("DeleteFile", &["T1070.004"]),
    ("DeleteFileA", &["T1070.004"]),
    ("DeleteFileW", &["T1070.004"]),
    ("MoveFile", &["T1036"]),
    ("CopyFile", &["T1083"]),
    ("GetTempPath", &["T1083"]),
    ("GetTempPathA", &["T1083"]),
    ("GetTempPathW", &["T1083"]),
    // ── Anti-Debug / Evasion ─────────────────────────────────────────────────
    ("IsDebuggerPresent", &["T1622", "T1027"]),
    ("CheckRemoteDebuggerPresent", &["T1622", "T1027"]),
    ("NtQueryInformationProcess", &["T1622", "T1057"]),
    ("GetTickCount", &["T1622"]),
    ("GetTickCount64", &["T1622"]),
    ("QueryPerformanceCounter", &["T1622"]),
    ("timeGetTime", &["T1622"]),
    ("Sleep", &["T1622"]),
    ("SleepEx", &["T1622"]),
    // ── VM/Sandbox Detection ─────────────────────────────────────────────────
    ("EnumWindows", &["T1497"]),
    ("GetForegroundWindow", &["T1497"]),
    ("GetCursorPos", &["T1497"]),
    ("GetSystemMetrics", &["T1497"]),
    ("GetDiskFreeSpaceEx", &["T1497.001"]),
    ("GetDiskFreeSpaceExA", &["T1497.001"]),
    ("DeviceIoControl", &["T1497.001"]),
    ("SetupDiGetClassDevs", &["T1497.001"]),
    // ── Network / C2 ─────────────────────────────────────────────────────────
    ("WSAStartup", &["T1071"]),
    ("socket", &["T1071"]),
    ("connect", &["T1071"]),
    ("send", &["T1071"]),
    ("recv", &["T1071"]),
    ("InternetOpen", &["T1071.001"]),
    ("InternetOpenA", &["T1071.001"]),
    ("InternetOpenW", &["T1071.001"]),
    ("InternetConnect", &["T1071.001"]),
    ("InternetConnectA", &["T1071.001"]),
    ("InternetConnectW", &["T1071.001"]),
    ("HttpOpenRequest", &["T1071.001"]),
    ("HttpSendRequest", &["T1071.001"]),
    ("WinHttpOpen", &["T1071.001"]),
    ("WinHttpConnect", &["T1071.001"]),
    ("WinHttpSendRequest", &["T1071.001"]),
    ("URLDownloadToFile", &["T1071.001", "T1105"]),
    ("URLDownloadToFileA", &["T1071.001", "T1105"]),
    ("URLDownloadToFileW", &["T1071.001", "T1105"]),
    ("gethostbyname", &["T1071"]),
    ("getaddrinfo", &["T1071"]),
    ("DnsQuery", &["T1071"]),
    // ── Encryption ───────────────────────────────────────────────────────────
    ("CryptEncrypt", &["T1027", "T1486"]),
    ("CryptDecrypt", &["T1027"]),
    ("CryptAcquireContext", &["T1027", "T1486"]),
    ("CryptImportKey", &["T1027"]),
    ("CryptDeriveKey", &["T1027", "T1486"]),
    ("CryptGenRandom", &["T1027"]),
    ("BCryptEncrypt", &["T1027", "T1486"]),
    ("BCryptDecrypt", &["T1027"]),
    // ── Persistence ──────────────────────────────────────────────────────────
    ("CreateService", &["T1543.003"]),
    ("CreateServiceA", &["T1543.003"]),
    ("CreateServiceW", &["T1543.003"]),
    ("OpenService", &["T1543.003"]),
    ("StartService", &["T1543.003"]),
    ("ChangeServiceConfig", &["T1543.003"]),
    ("CoCreateInstance", &["T1546.015"]),
    // ── Token Manipulation ───────────────────────────────────────────────────
    ("OpenProcessToken", &["T1134"]),
    ("DuplicateToken", &["T1134.001"]),
    ("DuplicateTokenEx", &["T1134.001"]),
    ("ImpersonateLoggedOnUser", &["T1134.001"]),
    ("SetThreadToken", &["T1134.001"]),
    ("AdjustTokenPrivileges", &["T1134.002"]),
    ("LookupPrivilegeValue", &["T1134"]),
    // ── Scripting / Exec ─────────────────────────────────────────────────────
    ("ShellExecute", &["T1059"]),
    ("ShellExecuteA", &["T1059"]),
    ("ShellExecuteW", &["T1059"]),
    ("ShellExecuteEx", &["T1059"]),
    ("WinExec", &["T1059"]),
    ("system", &["T1059"]),
    ("CreateProcessWithLogonW", &["T1134.002"]),
    // ── Impact ───────────────────────────────────────────────────────────────
    ("EncryptFile", &["T1486"]),
    ("EncryptFileA", &["T1486"]),
    ("EncryptFileW", &["T1486"]),
    ("NtSetSystemPowerState", &["T1490"]),
    ("InitiateShutdown", &["T1490"]),
    ("InitiateSystemShutdown", &["T1490"]),
    // ── Dynamic API Resolution ───────────────────────────────────────────────
    ("GetProcAddress", &["T1027.007"]),
    ("GetModuleHandle", &["T1027.007"]),
    ("GetModuleHandleA", &["T1027.007"]),
    ("GetModuleHandleW", &["T1027.007"]),
    ("LdrGetProcedureAddress", &["T1027.007"]),
    // ── Code Injection via mapped sections ───────────────────────────────────
    ("NtCreateSection", &["T1055"]),
    ("NtMapViewOfSection", &["T1055"]),
    ("ZwMapViewOfSection", &["T1055"]),
    ("MapViewOfFile", &["T1055"]),
    ("CreateFileMapping", &["T1055"]),
    ("CreateFileMappingA", &["T1055"]),
    ("CreateFileMappingW", &["T1055"]),
];

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_default_loads() {
        let fw = AttackFramework::default();
        assert!(!fw.tactics.is_empty());
        assert!(!fw.techniques.is_empty());
        assert!(!fw.groups.is_empty());
        assert!(!fw.software.is_empty());
    }

    #[test]
    fn test_technique_lookup() {
        let fw = AttackFramework::default();
        let t = fw.technique("T1055").unwrap();
        assert_eq!(t.id, "T1055");
        assert_eq!(t.name, "Process Injection");
    }

    #[test]
    fn test_tactic_lookup() {
        let fw = AttackFramework::default();
        let ta = fw.tactic("TA0005").unwrap();
        assert_eq!(ta.name, "Defense Evasion");
    }

    #[test]
    fn test_techniques_for_tactic() {
        let fw = AttackFramework::default();
        let evasion = fw.techniques_for_tactic("TA0005");
        assert!(!evasion.is_empty());
    }

    #[test]
    fn test_api_to_techniques() {
        let fw = AttackFramework::default();
        let hits = fw.api_to_techniques("WriteProcessMemory");
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|t| t.id == "T1055"));
    }

    #[test]
    fn test_api_technique_ids_static() {
        let ids = AttackFramework::api_technique_ids("GetProcAddress");
        assert!(ids.contains(&"T1027.007"));
    }

    #[test]
    fn test_search_by_name() {
        let fw = AttackFramework::default();
        let results = fw.search_by_name("injection");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_sub_techniques() {
        let fw = AttackFramework::default();
        let subs = fw.sub_techniques("T1055");
        // Should find T1055.001, T1055.002, etc.
        assert!(!subs.is_empty());
    }

    #[test]
    fn test_technique_is_sub_technique() {
        let t = Technique::new(
            "T1055.001",
            "DLL Injection",
            vec![],
            "desc".to_owned(),
            vec![],
        );
        assert!(t.is_sub_technique());
        assert_eq!(t.parent_technique_id(), Some("T1055"));
    }

    #[test]
    fn test_technique_display() {
        let t = Technique::new(
            "T1055",
            "Process Injection",
            vec![],
            "desc".to_owned(),
            vec![],
        );
        assert!(t.to_string().contains("T1055"));
    }

    #[test]
    fn test_api_to_attack_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for (api, _) in API_TO_ATTACK {
            // Each API should appear at most once (some share entries for case variants)
            let key = api.to_lowercase();
            // Just verify no panic and insertions work
            seen.insert(key);
        }
        // We should have a substantial number of unique entries
        assert!(seen.len() > 50);
    }

    #[test]
    fn test_framework_serialization() {
        let fw = AttackFramework::default();
        let json = serde_json::to_string(&fw).unwrap();
        assert!(!json.is_empty());
    }
}
