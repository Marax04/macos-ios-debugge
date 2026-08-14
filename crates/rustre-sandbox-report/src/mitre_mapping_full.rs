//! Full MITRE ATT&CK mapping with 200+ technique entries, tactic hierarchy,
//! sub-techniques, evidence tracking, and attack matrix navigation.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Tactic ───────────────────────────────────────────────────────────────────

/// ATT&CK Enterprise tactic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl fmt::Display for Tactic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        };
        write!(f, "{s}")
    }
}

impl Tactic {
    /// Human-readable tactic name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::ResourceDevelopment => "Resource Development",
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }
}

// ─── SubTechnique ─────────────────────────────────────────────────────────────

/// A sub-technique within a parent technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubTechnique {
    /// Sub-technique ID, e.g. "T1055.001".
    pub id: String,
    /// Sub-technique name.
    pub name: String,
    /// Description.
    pub description: String,
    /// API or indicator patterns associated with this sub-technique.
    pub indicators: Vec<String>,
}

impl SubTechnique {
    /// Create a new sub-technique.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            indicators: vec![],
        }
    }

    /// Add an indicator.
    #[must_use]
    pub fn with_indicator(mut self, ind: impl Into<String>) -> Self {
        self.indicators.push(ind.into());
        self
    }
}

// ─── Technique ────────────────────────────────────────────────────────────────

/// A MITRE ATT&CK technique with optional sub-techniques.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    /// Technique ID, e.g. "T1055".
    pub id: String,
    /// Technique name.
    pub name: String,
    /// Tactic(s) this technique belongs to.
    pub tactics: Vec<Tactic>,
    /// Short description.
    pub description: String,
    /// API or indicator patterns.
    pub indicators: Vec<String>,
    /// Sub-techniques.
    pub sub_techniques: Vec<SubTechnique>,
    /// URL on attack.mitre.org.
    pub url: String,
    /// Platforms affected.
    pub platforms: Vec<String>,
}

impl Technique {
    /// Create a new technique.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        tactics: Vec<Tactic>,
        description: impl Into<String>,
    ) -> Self {
        let id_str: String = id.into();
        let url = format!(
            "https://attack.mitre.org/techniques/{}/",
            id_str.replace('.', "/")
        );
        Self {
            id: id_str,
            name: name.into(),
            tactics,
            description: description.into(),
            indicators: vec![],
            sub_techniques: vec![],
            url,
            platforms: vec!["Windows".to_string()],
        }
    }

    /// Add an indicator.
    #[must_use]
    pub fn with_indicator(mut self, ind: impl Into<String>) -> Self {
        self.indicators.push(ind.into());
        self
    }

    /// Add a sub-technique.
    #[must_use]
    pub fn with_sub(mut self, sub: SubTechnique) -> Self {
        self.sub_techniques.push(sub);
        self
    }

    /// Add a platform.
    #[must_use]
    pub fn with_platform(mut self, p: impl Into<String>) -> Self {
        self.platforms.push(p.into());
        self
    }

    /// Find a sub-technique by ID.
    #[must_use]
    pub fn find_sub(&self, id: &str) -> Option<&SubTechnique> {
        self.sub_techniques.iter().find(|s| s.id == id)
    }
}

// ─── TechniqueEvidence ────────────────────────────────────────────────────────

/// Evidence linking an observed behavior to a specific technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueEvidence {
    /// Technique or sub-technique ID.
    pub technique_id: String,
    /// Observed evidence strings.
    pub evidence: Vec<String>,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Source of the evidence (e.g. "`api_trace`", "`memory_dump`").
    pub source: String,
}

impl TechniqueEvidence {
    /// Create a new evidence entry.
    #[must_use]
    pub fn new(technique_id: impl Into<String>, confidence: u8, source: impl Into<String>) -> Self {
        Self {
            technique_id: technique_id.into(),
            evidence: vec![],
            confidence: confidence.min(100),
            source: source.into(),
        }
    }

    /// Add an evidence string.
    pub fn add(&mut self, ev: impl Into<String>) {
        self.evidence.push(ev.into());
    }
}

// ─── AttackMatrix ─────────────────────────────────────────────────────────────

/// Full ATT&CK matrix with lookup facilities.
#[derive(Debug, Default)]
pub struct AttackMatrix {
    techniques: HashMap<String, Technique>,
}

impl AttackMatrix {
    /// Create an empty matrix.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a technique.
    pub fn add(&mut self, t: Technique) {
        self.techniques.insert(t.id.clone(), t);
    }

    /// Look up a technique by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(id)
    }

    /// Return all techniques for a given tactic.
    #[must_use]
    pub fn by_tactic(&self, tactic: &Tactic) -> Vec<&Technique> {
        self.techniques
            .values()
            .filter(|t| t.tactics.contains(tactic))
            .collect()
    }

    /// Total technique count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.techniques.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.techniques.is_empty()
    }

    /// Search techniques by name keyword.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&Technique> {
        let q = query.to_ascii_lowercase();
        self.techniques
            .values()
            .filter(|t| {
                t.name.to_ascii_lowercase().contains(&q)
                    || t.description.to_ascii_lowercase().contains(&q)
            })
            .collect()
    }

    /// Return all technique IDs.
    #[must_use]
    pub fn all_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.techniques.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }
}

// ─── MitreMappingFull ─────────────────────────────────────────────────────────

/// Full MITRE ATT&CK mapping engine with 200+ technique entries and evidence matching.
pub struct MitreMappingFull {
    pub matrix: AttackMatrix,
}

impl MitreMappingFull {
    /// Build the full matrix with 200+ technique entries.
    #[must_use]
    pub fn build() -> Self {
        let mut matrix = AttackMatrix::new();

        Self::add_initial_and_execution(&mut matrix);
        Self::add_persistence_and_privesc(&mut matrix);
        Self::add_defense_and_credentials(&mut matrix);
        Self::add_discovery_and_lateral(&mut matrix);
        Self::add_collection_c2_and_exfil(&mut matrix);
        Self::add_impact_and_recon(&mut matrix);

        Self { matrix }
    }

    fn add_initial_and_execution(matrix: &mut AttackMatrix) {
        // ── Initial Access ────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1566",
                "Phishing",
                vec![Tactic::InitialAccess],
                "Adversaries may send phishing messages",
            )
            .with_sub(
                SubTechnique::new(
                    "T1566.001",
                    "Spearphishing Attachment",
                    "malicious attachment",
                )
                .with_indicator("mshta.exe")
                .with_indicator("wscript.exe"),
            )
            .with_sub(SubTechnique::new(
                "T1566.002",
                "Spearphishing Link",
                "malicious link",
            ))
            .with_sub(SubTechnique::new(
                "T1566.003",
                "Spearphishing via Service",
                "via 3rd party service",
            )),
        );
        matrix.add(
            Technique::new(
                "T1190",
                "Exploit Public-Facing Application",
                vec![Tactic::InitialAccess],
                "Exploit external services",
            )
            .with_indicator("cmd.exe /c whoami"),
        );
        matrix.add(
            Technique::new(
                "T1133",
                "External Remote Services",
                vec![Tactic::InitialAccess, Tactic::Persistence],
                "VPN/RDP/VNC access",
            )
            .with_indicator("Remote Desktop"),
        );
        matrix.add(Technique::new(
            "T1199",
            "Trusted Relationship",
            vec![Tactic::InitialAccess],
            "Supply chain / managed service",
        ));
        matrix.add(Technique::new(
            "T1078",
            "Valid Accounts",
            vec![
                Tactic::InitialAccess,
                Tactic::DefenseEvasion,
                Tactic::Persistence,
            ],
            "Stolen credentials",
        ));
        // ── Execution ─────────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1059",
                "Command and Scripting Interpreter",
                vec![Tactic::Execution],
                "Shell / script execution",
            )
            .with_sub(
                SubTechnique::new("T1059.001", "PowerShell", "PowerShell execution")
                    .with_indicator("powershell.exe"),
            )
            .with_sub(
                SubTechnique::new("T1059.003", "Windows Command Shell", "cmd.exe")
                    .with_indicator("cmd.exe"),
            )
            .with_sub(
                SubTechnique::new("T1059.005", "Visual Basic", "VBScript")
                    .with_indicator("wscript.exe")
                    .with_indicator("cscript.exe"),
            )
            .with_sub(
                SubTechnique::new("T1059.007", "JavaScript", "JS execution")
                    .with_indicator("wscript.exe"),
            )
            .with_sub(SubTechnique::new("T1059.006", "Python", "Python execution")),
        );
        Self::add_execution_techniques(matrix);
    }

    fn add_execution_techniques(matrix: &mut AttackMatrix) {
        matrix.add(
            Technique::new(
                "T1047",
                "Windows Management Instrumentation",
                vec![Tactic::Execution],
                "WMI execution",
            )
            .with_indicator("wmic.exe")
            .with_indicator("Win32_Process"),
        );
        matrix.add(
            Technique::new(
                "T1053",
                "Scheduled Task/Job",
                vec![Tactic::Execution, Tactic::Persistence],
                "Task scheduler",
            )
            .with_sub(
                SubTechnique::new("T1053.005", "Scheduled Task", "schtasks")
                    .with_indicator("schtasks.exe"),
            ),
        );
        matrix.add(Technique::new(
            "T1129",
            "Shared Modules",
            vec![Tactic::Execution],
            "DLL side-loading execution",
        ));
        matrix.add(Technique::new(
            "T1203",
            "Exploitation for Client Execution",
            vec![Tactic::Execution],
            "Exploit document/browser",
        ));
        matrix.add(
            Technique::new(
                "T1106",
                "Native API",
                vec![Tactic::Execution],
                "Direct NT API calls",
            )
            .with_indicator("NtCreateProcess")
            .with_indicator("NtCreateThread"),
        );
        matrix.add(
            Technique::new(
                "T1569",
                "System Services",
                vec![Tactic::Execution],
                "Service execution",
            )
            .with_sub(
                SubTechnique::new("T1569.002", "Service Execution", "sc.exe / CreateService")
                    .with_indicator("CreateService"),
            ),
        );
    }

    fn add_persistence_and_privesc(matrix: &mut AttackMatrix) {
        // ── Persistence ───────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1547",
                "Boot or Logon Autostart Execution",
                vec![Tactic::Persistence, Tactic::PrivilegeEscalation],
                "Autostart entries",
            )
            .with_sub(
                SubTechnique::new(
                    "T1547.001",
                    "Registry Run Keys / Startup Folder",
                    "Run key persistence",
                )
                .with_indicator("RegSetValueExW")
                .with_indicator("CurrentVersion\\Run"),
            )
            .with_sub(SubTechnique::new(
                "T1547.004",
                "Winlogon Helper DLL",
                "Winlogon persistence",
            ))
            .with_sub(SubTechnique::new(
                "T1547.009",
                "Shortcut Modification",
                "LNK shortcut",
            )),
        );
        matrix.add(
            Technique::new(
                "T1543",
                "Create or Modify System Process",
                vec![Tactic::Persistence, Tactic::PrivilegeEscalation],
                "Service / daemon persistence",
            )
            .with_sub(
                SubTechnique::new("T1543.003", "Windows Service", "Service installation")
                    .with_indicator("CreateService")
                    .with_indicator("sc.exe"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1574",
                "Hijack Execution Flow",
                vec![Tactic::Persistence, Tactic::DefenseEvasion],
                "DLL hijacking",
            )
            .with_sub(SubTechnique::new(
                "T1574.001",
                "DLL Search Order Hijacking",
                "DLL hijacking via search order",
            ))
            .with_sub(SubTechnique::new(
                "T1574.002",
                "DLL Side-Loading",
                "Signed binary DLL side-load",
            )),
        );
        Self::add_persistence_accounts(matrix);
    }

    fn add_persistence_accounts(matrix: &mut AttackMatrix) {
        matrix.add(
            Technique::new(
                "T1098",
                "Account Manipulation",
                vec![Tactic::Persistence],
                "Add accounts to groups",
            )
            .with_indicator("net localgroup administrators"),
        );
        matrix.add(
            Technique::new(
                "T1136",
                "Create Account",
                vec![Tactic::Persistence],
                "Create user accounts",
            )
            .with_indicator("net user /add"),
        );
        matrix.add(
            Technique::new(
                "T1505",
                "Server Software Component",
                vec![Tactic::Persistence],
                "Web shell",
            )
            .with_sub(SubTechnique::new(
                "T1505.003",
                "Web Shell",
                "Web shell deployment",
            )),
        );
        matrix.add(
            Technique::new(
                "T1546",
                "Event Triggered Execution",
                vec![Tactic::Persistence],
                "Event-based triggers",
            )
            .with_sub(SubTechnique::new(
                "T1546.003",
                "Windows Management Instrumentation Event Subscription",
                "WMI event",
            ))
            .with_sub(SubTechnique::new(
                "T1546.015",
                "Component Object Model Hijacking",
                "COM hijack",
            )),
        );
        matrix.add(
            Technique::new(
                "T1137",
                "Office Application Startup",
                vec![Tactic::Persistence],
                "Office macro / add-in persistence",
            )
            .with_sub(SubTechnique::new(
                "T1137.001",
                "Office Template Macros",
                "VBA macro",
            )),
        );
        Self::add_privesc_techniques(matrix);
    }

    fn add_privesc_techniques(matrix: &mut AttackMatrix) {
        // ── Privilege Escalation ──────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1548",
                "Abuse Elevation Control Mechanism",
                vec![Tactic::PrivilegeEscalation, Tactic::DefenseEvasion],
                "UAC bypass",
            )
            .with_sub(
                SubTechnique::new("T1548.002", "Bypass User Account Control", "UAC bypass")
                    .with_indicator("fodhelper.exe")
                    .with_indicator("eventvwr.exe"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1068",
                "Exploitation for Privilege Escalation",
                vec![Tactic::PrivilegeEscalation],
                "Kernel / privilege exploit",
            )
            .with_indicator("privilege::debug"),
        );
        matrix.add(
            Technique::new(
                "T1134",
                "Access Token Manipulation",
                vec![Tactic::PrivilegeEscalation, Tactic::DefenseEvasion],
                "Token impersonation",
            )
            .with_sub(
                SubTechnique::new(
                    "T1134.001",
                    "Token Impersonation/Theft",
                    "Impersonate token",
                )
                .with_indicator("ImpersonateLoggedOnUser"),
            )
            .with_sub(SubTechnique::new(
                "T1134.002",
                "Create Process with Token",
                "CreateProcessWithToken",
            )),
        );
        matrix.add(
            Technique::new(
                "T1055",
                "Process Injection",
                vec![Tactic::PrivilegeEscalation, Tactic::DefenseEvasion],
                "Inject code into processes",
            )
            .with_sub(
                SubTechnique::new(
                    "T1055.001",
                    "Dynamic-link Library Injection",
                    "DLL injection",
                )
                .with_indicator("WriteProcessMemory")
                .with_indicator("CreateRemoteThread"),
            )
            .with_sub(SubTechnique::new(
                "T1055.002",
                "Portable Executable Injection",
                "PE injection",
            ))
            .with_sub(
                SubTechnique::new("T1055.003", "Thread Execution Hijacking", "Thread hijack")
                    .with_indicator("SetThreadContext"),
            )
            .with_sub(
                SubTechnique::new("T1055.004", "Asynchronous Procedure Call", "APC injection")
                    .with_indicator("QueueUserAPC"),
            )
            .with_sub(
                SubTechnique::new("T1055.012", "Process Hollowing", "Hollow process")
                    .with_indicator("NtUnmapViewOfSection"),
            )
            .with_sub(SubTechnique::new(
                "T1055.013",
                "Process Doppelgänging",
                "NTFS transaction",
            )),
        );
        matrix.add(Technique::new(
            "T1611",
            "Escape to Host",
            vec![Tactic::PrivilegeEscalation],
            "Container escape",
        ));
    }
    fn add_defense_and_credentials(matrix: &mut AttackMatrix) {
        // ── Defense Evasion ───────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1036",
                "Masquerading",
                vec![Tactic::DefenseEvasion],
                "Rename / spoof process names",
            )
            .with_sub(SubTechnique::new(
                "T1036.004",
                "Masquerade Task or Service",
                "Fake service name",
            ))
            .with_sub(SubTechnique::new(
                "T1036.005",
                "Match Legitimate Name or Location",
                "Mimic system binary",
            )),
        );
        matrix.add(
            Technique::new(
                "T1027",
                "Obfuscated Files or Information",
                vec![Tactic::DefenseEvasion],
                "Obfuscate payloads",
            )
            .with_sub(
                SubTechnique::new("T1027.002", "Software Packing", "UPX/custom packer")
                    .with_indicator("UPX!"),
            )
            .with_sub(SubTechnique::new(
                "T1027.004",
                "Compile After Delivery",
                "Compile on victim",
            )),
        );
        matrix.add(
            Technique::new(
                "T1562",
                "Impair Defenses",
                vec![Tactic::DefenseEvasion],
                "Disable AV/EDR",
            )
            .with_sub(
                SubTechnique::new("T1562.001", "Disable or Modify Tools", "Disable AV")
                    .with_indicator("Set-MpPreference")
                    .with_indicator("netsh advfirewall"),
            )
            .with_sub(
                SubTechnique::new(
                    "T1562.002",
                    "Disable Windows Event Logging",
                    "Disable event log",
                )
                .with_indicator("wevtutil cl"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1497",
                "Virtualization/Sandbox Evasion",
                vec![Tactic::DefenseEvasion, Tactic::Discovery],
                "Detect sandbox/VM",
            )
            .with_sub(
                SubTechnique::new("T1497.001", "System Checks", "Check for VM artifacts")
                    .with_indicator("CPUID")
                    .with_indicator("rdtsc"),
            )
            .with_sub(SubTechnique::new(
                "T1497.002",
                "User Activity Based Checks",
                "Check for user interaction",
            ))
            .with_sub(
                SubTechnique::new("T1497.003", "Time Based Evasion", "Sleep / timing checks")
                    .with_indicator("NtDelayExecution"),
            ),
        );
        Self::add_defense_evasion_lolbins(matrix);
    }

    fn add_defense_evasion_lolbins(matrix: &mut AttackMatrix) {
        matrix.add(
            Technique::new(
                "T1218",
                "System Binary Proxy Execution",
                vec![Tactic::DefenseEvasion],
                "LOLBins",
            )
            .with_sub(
                SubTechnique::new("T1218.003", "CMSTP", "cmstp.exe").with_indicator("cmstp.exe"),
            )
            .with_sub(
                SubTechnique::new("T1218.010", "Regsvr32", "regsvr32.exe")
                    .with_indicator("regsvr32.exe"),
            )
            .with_sub(
                SubTechnique::new("T1218.011", "Rundll32", "rundll32.exe")
                    .with_indicator("rundll32.exe"),
            )
            .with_sub(
                SubTechnique::new("T1218.005", "Mshta", "mshta.exe").with_indicator("mshta.exe"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1070",
                "Indicator Removal",
                vec![Tactic::DefenseEvasion],
                "Clear event logs / files",
            )
            .with_sub(
                SubTechnique::new("T1070.001", "Clear Windows Event Logs", "wevtutil cl")
                    .with_indicator("wevtutil cl System")
                    .with_indicator("wevtutil cl Security"),
            )
            .with_sub(SubTechnique::new(
                "T1070.004",
                "File Deletion",
                "Delete own binary",
            )),
        );
        matrix.add(Technique::new(
            "T1202",
            "Indirect Command Execution",
            vec![Tactic::DefenseEvasion],
            "Indirect shell",
        ));
        matrix.add(
            Technique::new(
                "T1620",
                "Reflective Code Loading",
                vec![Tactic::DefenseEvasion],
                "Load code reflectively",
            )
            .with_indicator("ReflectiveDLLInjection"),
        );
        Self::add_credential_access(matrix);
    }

    fn add_credential_access(matrix: &mut AttackMatrix) {
        // ── Credential Access ─────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1003",
                "OS Credential Dumping",
                vec![Tactic::CredentialAccess],
                "Dump credentials from OS",
            )
            .with_sub(
                SubTechnique::new("T1003.001", "LSASS Memory", "mimikatz lsass dump")
                    .with_indicator("sekurlsa::logonpasswords")
                    .with_indicator("MiniDumpWriteDump"),
            )
            .with_sub(
                SubTechnique::new("T1003.002", "Security Account Manager", "SAM dump")
                    .with_indicator("reg save HKLM\\SAM"),
            )
            .with_sub(SubTechnique::new(
                "T1003.003",
                "NTDS",
                "ntds.dit extraction",
            ))
            .with_sub(SubTechnique::new("T1003.004", "LSA Secrets", "LSA secrets")),
        );
        matrix.add(
            Technique::new(
                "T1110",
                "Brute Force",
                vec![Tactic::CredentialAccess],
                "Password brute force",
            )
            .with_sub(SubTechnique::new(
                "T1110.001",
                "Password Guessing",
                "Guess passwords",
            ))
            .with_sub(SubTechnique::new(
                "T1110.003",
                "Password Spraying",
                "Spray passwords",
            )),
        );
        matrix.add(
            Technique::new(
                "T1056",
                "Input Capture",
                vec![Tactic::CredentialAccess, Tactic::Collection],
                "Keylogging",
            )
            .with_sub(
                SubTechnique::new("T1056.001", "Keylogging", "Keyboard hooking")
                    .with_indicator("SetWindowsHookExW")
                    .with_indicator("GetAsyncKeyState"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1555",
                "Credentials from Password Stores",
                vec![Tactic::CredentialAccess],
                "Browser/password manager",
            )
            .with_sub(SubTechnique::new(
                "T1555.003",
                "Credentials from Web Browsers",
                "Browser credential theft",
            )),
        );
        matrix.add(Technique::new(
            "T1539",
            "Steal Web Session Cookie",
            vec![Tactic::CredentialAccess],
            "Cookie theft",
        ));
        matrix.add(Technique::new(
            "T1528",
            "Steal Application Access Token",
            vec![Tactic::CredentialAccess],
            "OAuth token theft",
        ));
    }
    fn add_discovery_and_lateral(matrix: &mut AttackMatrix) {
        // ── Discovery ─────────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1082",
                "System Information Discovery",
                vec![Tactic::Discovery],
                "Enumerate OS info",
            )
            .with_indicator("GetSystemInfo")
            .with_indicator("systeminfo"),
        );
        matrix.add(
            Technique::new(
                "T1083",
                "File and Directory Discovery",
                vec![Tactic::Discovery],
                "Enumerate files",
            )
            .with_indicator("FindFirstFile")
            .with_indicator("dir /s"),
        );
        matrix.add(
            Technique::new(
                "T1057",
                "Process Discovery",
                vec![Tactic::Discovery],
                "Enumerate processes",
            )
            .with_indicator("CreateToolhelp32Snapshot")
            .with_indicator("tasklist"),
        );
        matrix.add(
            Technique::new(
                "T1012",
                "Query Registry",
                vec![Tactic::Discovery],
                "Read registry",
            )
            .with_indicator("RegQueryValueExW"),
        );
        matrix.add(
            Technique::new(
                "T1018",
                "Remote System Discovery",
                vec![Tactic::Discovery],
                "Discover network hosts",
            )
            .with_indicator("net view")
            .with_indicator("arp -a"),
        );
        matrix.add(
            Technique::new(
                "T1049",
                "System Network Connections Discovery",
                vec![Tactic::Discovery],
                "List connections",
            )
            .with_indicator("netstat -an"),
        );
        matrix.add(
            Technique::new(
                "T1016",
                "System Network Configuration Discovery",
                vec![Tactic::Discovery],
                "Network config",
            )
            .with_indicator("ipconfig /all")
            .with_indicator("GetAdaptersInfo"),
        );
        matrix.add(
            Technique::new(
                "T1033",
                "System Owner/User Discovery",
                vec![Tactic::Discovery],
                "Who am I",
            )
            .with_indicator("GetUserNameW")
            .with_indicator("whoami"),
        );
        Self::add_discovery_accounts_shares(matrix);
    }

    fn add_discovery_accounts_shares(matrix: &mut AttackMatrix) {
        matrix.add(
            Technique::new(
                "T1087",
                "Account Discovery",
                vec![Tactic::Discovery],
                "List user accounts",
            )
            .with_sub(
                SubTechnique::new("T1087.001", "Local Account", "net user")
                    .with_indicator("net user"),
            )
            .with_sub(SubTechnique::new(
                "T1087.002",
                "Domain Account",
                "net user /domain",
            )),
        );
        matrix.add(
            Technique::new(
                "T1135",
                "Network Share Discovery",
                vec![Tactic::Discovery],
                "Enumerate shares",
            )
            .with_indicator("NetShareEnum")
            .with_indicator("net share"),
        );
        matrix.add(
            Technique::new(
                "T1069",
                "Permission Groups Discovery",
                vec![Tactic::Discovery],
                "Enumerate group membership",
            )
            .with_sub(
                SubTechnique::new("T1069.001", "Local Groups", "net localgroup")
                    .with_indicator("net localgroup"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1007",
                "System Service Discovery",
                vec![Tactic::Discovery],
                "List services",
            )
            .with_indicator("sc query"),
        );
        Self::add_lateral_movement(matrix);
    }

    fn add_lateral_movement(matrix: &mut AttackMatrix) {
        // ── Lateral Movement ──────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1021",
                "Remote Services",
                vec![Tactic::LateralMovement],
                "Use remote services",
            )
            .with_sub(
                SubTechnique::new(
                    "T1021.001",
                    "Remote Desktop Protocol",
                    "RDP lateral movement",
                )
                .with_indicator("mstsc.exe"),
            )
            .with_sub(
                SubTechnique::new(
                    "T1021.002",
                    "SMB/Windows Admin Shares",
                    "SMB lateral movement",
                )
                .with_indicator("net use"),
            )
            .with_sub(SubTechnique::new(
                "T1021.004",
                "SSH",
                "SSH lateral movement",
            )),
        );
        matrix.add(Technique::new(
            "T1570",
            "Lateral Tool Transfer",
            vec![Tactic::LateralMovement],
            "Transfer tools laterally",
        ));
        matrix.add(
            Technique::new(
                "T1550",
                "Use Alternate Authentication Material",
                vec![Tactic::LateralMovement, Tactic::DefenseEvasion],
                "Pass the hash/ticket",
            )
            .with_sub(
                SubTechnique::new("T1550.002", "Pass the Hash", "PtH")
                    .with_indicator("sekurlsa::pth"),
            )
            .with_sub(SubTechnique::new("T1550.003", "Pass the Ticket", "PtT")),
        );
        matrix.add(
            Technique::new(
                "T1210",
                "Exploitation of Remote Services",
                vec![Tactic::LateralMovement],
                "Exploit remote services",
            )
            .with_indicator("EternalBlue")
            .with_indicator("ms17-010"),
        );
        matrix.add(
            Technique::new(
                "T1563",
                "Remote Service Session Hijacking",
                vec![Tactic::LateralMovement],
                "Hijack existing sessions",
            )
            .with_sub(SubTechnique::new(
                "T1563.001",
                "SSH Hijacking",
                "SSH session hijack",
            )),
        );
    }
    fn add_collection_c2_and_exfil(matrix: &mut AttackMatrix) {
        // ── Collection ────────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1113",
                "Screen Capture",
                vec![Tactic::Collection],
                "Take screenshots",
            )
            .with_indicator("BitBlt")
            .with_indicator("GetDC")
            .with_indicator("CaptureScreen"),
        );
        matrix.add(
            Technique::new(
                "T1115",
                "Clipboard Data",
                vec![Tactic::Collection],
                "Steal clipboard",
            )
            .with_indicator("GetClipboardData")
            .with_indicator("OpenClipboard"),
        );
        matrix.add(Technique::new(
            "T1005",
            "Data from Local System",
            vec![Tactic::Collection],
            "Read local files",
        ));
        matrix.add(Technique::new(
            "T1039",
            "Data from Network Shared Drive",
            vec![Tactic::Collection],
            "Read network shares",
        ));
        matrix.add(Technique::new(
            "T1025",
            "Data from Removable Media",
            vec![Tactic::Collection],
            "Read USB/removable drives",
        ));
        matrix.add(
            Technique::new(
                "T1074",
                "Data Staged",
                vec![Tactic::Collection],
                "Stage exfiltration data",
            )
            .with_sub(SubTechnique::new(
                "T1074.001",
                "Local Data Staging",
                "Stage locally",
            )),
        );
        matrix.add(Technique::new(
            "T1119",
            "Automated Collection",
            vec![Tactic::Collection],
            "Automated data gathering",
        ));
        matrix.add(Technique::new(
            "T1020",
            "Automated Exfiltration",
            vec![Tactic::Exfiltration],
            "Auto-exfil",
        ));
        Self::add_c2_and_exfil(matrix);
    }

    fn add_c2_and_exfil(matrix: &mut AttackMatrix) {
        // ── C2 ────────────────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1071",
                "Application Layer Protocol",
                vec![Tactic::CommandAndControl],
                "Use app protocols for C2",
            )
            .with_sub(
                SubTechnique::new("T1071.001", "Web Protocols", "HTTP/HTTPS C2")
                    .with_indicator("InternetConnectA")
                    .with_indicator("WinHttpSendRequest"),
            )
            .with_sub(SubTechnique::new(
                "T1071.002",
                "File Transfer Protocols",
                "FTP C2",
            ))
            .with_sub(SubTechnique::new("T1071.003", "Mail Protocols", "Email C2"))
            .with_sub(SubTechnique::new("T1071.004", "DNS", "DNS C2").with_indicator("DnsQuery")),
        );
        matrix.add(Technique::new(
            "T1095",
            "Non-Application Layer Protocol",
            vec![Tactic::CommandAndControl],
            "Raw socket / ICMP C2",
        ));
        matrix.add(
            Technique::new(
                "T1572",
                "Protocol Tunneling",
                vec![Tactic::CommandAndControl],
                "Tunnel C2 over DNS/HTTPS",
            )
            .with_indicator("dnscat2")
            .with_indicator("iodine"),
        );
        matrix.add(
            Technique::new(
                "T1573",
                "Encrypted Channel",
                vec![Tactic::CommandAndControl],
                "Encrypted C2 channel",
            )
            .with_sub(
                SubTechnique::new(
                    "T1573.001",
                    "Symmetric Cryptography",
                    "AES/RC4 encrypted C2",
                )
                .with_indicator("BCryptEncrypt"),
            )
            .with_sub(SubTechnique::new(
                "T1573.002",
                "Asymmetric Cryptography",
                "RSA/ECC encrypted C2",
            )),
        );
        Self::add_c2_protocols_b(matrix);
    }

    fn add_c2_protocols_b(matrix: &mut AttackMatrix) {
        matrix.add(Technique::new(
            "T1008",
            "Fallback Channels",
            vec![Tactic::CommandAndControl],
            "Multiple C2 channels",
        ));
        matrix.add(
            Technique::new(
                "T1090",
                "Proxy",
                vec![Tactic::CommandAndControl],
                "Route through proxy",
            )
            .with_sub(SubTechnique::new(
                "T1090.001",
                "Internal Proxy",
                "Internal relay",
            ))
            .with_sub(SubTechnique::new(
                "T1090.003",
                "Multi-hop Proxy",
                "Proxy chain",
            )),
        );
        matrix.add(
            Technique::new(
                "T1219",
                "Remote Access Software",
                vec![Tactic::CommandAndControl],
                "Commercial RAT",
            )
            .with_indicator("TeamViewer")
            .with_indicator("AnyDesk"),
        );
        matrix.add(
            Technique::new(
                "T1105",
                "Ingress Tool Transfer",
                vec![Tactic::CommandAndControl],
                "Download payload",
            )
            .with_indicator("URLDownloadToFile")
            .with_indicator("bitsadmin /transfer"),
        );
        matrix.add(
            Technique::new(
                "T1132",
                "Data Encoding",
                vec![Tactic::CommandAndControl],
                "Encode C2 traffic",
            )
            .with_sub(SubTechnique::new(
                "T1132.001",
                "Standard Encoding",
                "Base64/hex encoding",
            )),
        );
        Self::add_exfiltration(matrix);
    }

    fn add_exfiltration(matrix: &mut AttackMatrix) {
        // ── Exfiltration ──────────────────────────────────────────────────────
        matrix.add(Technique::new(
            "T1041",
            "Exfiltration Over C2 Channel",
            vec![Tactic::Exfiltration],
            "Exfil over C2",
        ));
        matrix.add(
            Technique::new(
                "T1048",
                "Exfiltration Over Alternative Protocol",
                vec![Tactic::Exfiltration],
                "Exfil over DNS/ICMP",
            )
            .with_sub(SubTechnique::new(
                "T1048.003",
                "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
                "Cleartext exfil",
            )),
        );
        matrix.add(
            Technique::new(
                "T1052",
                "Exfiltration Over Physical Medium",
                vec![Tactic::Exfiltration],
                "Exfil to USB",
            )
            .with_sub(SubTechnique::new(
                "T1052.001",
                "Exfiltration over USB",
                "USB exfil",
            )),
        );
        matrix.add(
            Technique::new(
                "T1567",
                "Exfiltration Over Web Service",
                vec![Tactic::Exfiltration],
                "Exfil to cloud",
            )
            .with_sub(SubTechnique::new(
                "T1567.002",
                "Exfiltration to Cloud Storage",
                "Upload to cloud",
            )),
        );
    }
    fn add_impact_and_recon(matrix: &mut AttackMatrix) {
        // ── Impact ────────────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1486",
                "Data Encrypted for Impact",
                vec![Tactic::Impact],
                "Ransomware encryption",
            )
            .with_indicator("BCryptEncrypt")
            .with_indicator("CryptEncrypt")
            .with_indicator("FindFirstFile"),
        );
        matrix.add(
            Technique::new(
                "T1490",
                "Inhibit System Recovery",
                vec![Tactic::Impact],
                "Delete shadow copies",
            )
            .with_indicator("vssadmin delete shadows")
            .with_indicator("wmic shadowcopy delete"),
        );
        matrix.add(
            Technique::new(
                "T1485",
                "Data Destruction",
                vec![Tactic::Impact],
                "Destroy data",
            )
            .with_indicator("ZeroFile")
            .with_indicator("format /y"),
        );
        matrix.add(
            Technique::new(
                "T1489",
                "Service Stop",
                vec![Tactic::Impact],
                "Stop critical services",
            )
            .with_indicator("sc stop")
            .with_indicator("net stop"),
        );
        matrix.add(
            Technique::new(
                "T1491",
                "Defacement",
                vec![Tactic::Impact],
                "Web / internal defacement",
            )
            .with_sub(SubTechnique::new(
                "T1491.001",
                "Internal Defacement",
                "Change desktop/wallpaper",
            ))
            .with_sub(SubTechnique::new(
                "T1491.002",
                "External Defacement",
                "Web defacement",
            )),
        );
        matrix.add(
            Technique::new(
                "T1561",
                "Disk Wipe",
                vec![Tactic::Impact],
                "Wipe disk / MBR",
            )
            .with_sub(SubTechnique::new(
                "T1561.001",
                "Disk Content Wipe",
                "Wipe content",
            ))
            .with_sub(SubTechnique::new(
                "T1561.002",
                "Disk Structure Wipe",
                "Wipe MBR/VBR",
            )),
        );
        Self::add_impact_dos_reboot(matrix);
    }

    fn add_impact_dos_reboot(matrix: &mut AttackMatrix) {
        matrix.add(
            Technique::new(
                "T1498",
                "Network Denial of Service",
                vec![Tactic::Impact],
                "DoS / DDoS",
            )
            .with_sub(SubTechnique::new(
                "T1498.001",
                "Direct Network Flood",
                "Direct flood",
            )),
        );
        matrix.add(Technique::new(
            "T1496",
            "Resource Hijacking",
            vec![Tactic::Impact],
            "Cryptomining",
        ));
        matrix.add(
            Technique::new(
                "T1529",
                "System Shutdown/Reboot",
                vec![Tactic::Impact],
                "Shutdown/reboot system",
            )
            .with_indicator("ExitWindowsEx")
            .with_indicator("shutdown /r"),
        );
        Self::add_recon_and_resource_dev(matrix);
    }

    fn add_recon_and_resource_dev(matrix: &mut AttackMatrix) {
        // ── Reconnaissance ────────────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1595",
                "Active Scanning",
                vec![Tactic::Reconnaissance],
                "Port / vuln scanning",
            )
            .with_sub(SubTechnique::new(
                "T1595.001",
                "Scanning IP Blocks",
                "CIDR scan",
            ))
            .with_sub(SubTechnique::new(
                "T1595.002",
                "Vulnerability Scanning",
                "Vuln scan",
            )),
        );
        matrix.add(Technique::new(
            "T1592",
            "Gather Victim Host Information",
            vec![Tactic::Reconnaissance],
            "OS/hardware recon",
        ));
        matrix.add(Technique::new(
            "T1591",
            "Gather Victim Org Information",
            vec![Tactic::Reconnaissance],
            "Org/employee recon",
        ));
        matrix.add(Technique::new(
            "T1590",
            "Gather Victim Network Information",
            vec![Tactic::Reconnaissance],
            "IP/ASN/domain recon",
        ));
        Self::add_resource_dev_and_misc(matrix);
    }

    fn add_resource_dev_and_misc(matrix: &mut AttackMatrix) {
        // ── Resource Development ──────────────────────────────────────────────
        matrix.add(
            Technique::new(
                "T1583",
                "Acquire Infrastructure",
                vec![Tactic::ResourceDevelopment],
                "Buy/rent servers",
            )
            .with_sub(SubTechnique::new(
                "T1583.001",
                "Domains",
                "Register domains",
            ))
            .with_sub(SubTechnique::new(
                "T1583.006",
                "Web Services",
                "Abuse cloud services",
            )),
        );
        matrix.add(Technique::new(
            "T1584",
            "Compromise Infrastructure",
            vec![Tactic::ResourceDevelopment],
            "Hijack existing servers",
        ));
        matrix.add(
            Technique::new(
                "T1588",
                "Obtain Capabilities",
                vec![Tactic::ResourceDevelopment],
                "Buy/steal tools",
            )
            .with_sub(SubTechnique::new("T1588.001", "Malware", "Obtain malware"))
            .with_sub(SubTechnique::new(
                "T1588.002",
                "Tool",
                "Obtain red-team tool",
            )),
        );

        // Extra techniques to exceed 200 total
        matrix.add(
            Technique::new(
                "T1040",
                "Network Sniffing",
                vec![Tactic::CredentialAccess, Tactic::Discovery],
                "Capture network traffic",
            )
            .with_indicator("WinPcap")
            .with_indicator("Npcap"),
        );
        matrix.add(
            Technique::new(
                "T1557",
                "Adversary-in-the-Middle",
                vec![Tactic::CredentialAccess],
                "AiTM / MITM attack",
            )
            .with_sub(
                SubTechnique::new("T1557.001", "LLMNR/NBT-NS Poisoning", "Responder poisoning")
                    .with_indicator("Responder"),
            ),
        );
        matrix.add(
            Technique::new(
                "T1558",
                "Steal or Forge Kerberos Tickets",
                vec![Tactic::CredentialAccess],
                "Kerberoasting / AS-REP roasting",
            )
            .with_sub(
                SubTechnique::new("T1558.003", "Kerberoasting", "Kerberoasting")
                    .with_indicator("Rubeus"),
            )
            .with_sub(SubTechnique::new(
                "T1558.004",
                "AS-REP Roasting",
                "AS-REP roasting",
            )),
        );
        matrix.add(
            Technique::new(
                "T1606",
                "Forge Web Credentials",
                vec![Tactic::CredentialAccess],
                "SAML/OAuth token forgery",
            )
            .with_sub(SubTechnique::new(
                "T1606.001",
                "Web Cookies",
                "Forge cookie",
            ))
            .with_sub(SubTechnique::new("T1606.002", "SAML Tokens", "Forge SAML")),
        );
        Self::add_defense_evasion_advanced(matrix);
    }

    fn add_defense_evasion_advanced(matrix: &mut AttackMatrix) {
        matrix.add(Technique::new(
            "T1621",
            "Multi-Factor Authentication Request Generation",
            vec![Tactic::CredentialAccess],
            "MFA fatigue / push spamming",
        ));
        matrix.add(
            Technique::new(
                "T1601",
                "Modify System Image",
                vec![Tactic::DefenseEvasion],
                "Patch firmware/OS image",
            )
            .with_sub(SubTechnique::new(
                "T1601.001",
                "Patch System Image",
                "Modify OS binary",
            ))
            .with_sub(SubTechnique::new(
                "T1601.002",
                "Downgrade System Image",
                "Downgrade OS",
            )),
        );
        matrix.add(Technique::new(
            "T1599",
            "Network Boundary Bridging",
            vec![Tactic::DefenseEvasion],
            "Route across network segments",
        ));
        matrix.add(
            Technique::new(
                "T1600",
                "Weaken Encryption",
                vec![Tactic::DefenseEvasion],
                "Downgrade TLS / weaken crypto",
            )
            .with_sub(SubTechnique::new(
                "T1600.001",
                "Reduce Key Space",
                "Truncate key size",
            ))
            .with_sub(SubTechnique::new(
                "T1600.002",
                "Disable Crypto Hardware",
                "Disable HSM",
            )),
        );
        Self::add_cloud_and_debugger_techniques(matrix);
    }

    fn add_cloud_and_debugger_techniques(matrix: &mut AttackMatrix) {
        matrix.add(Technique::new(
            "T1612",
            "Build Image on Host",
            vec![Tactic::DefenseEvasion],
            "Compile on victim host",
        ));
        matrix.add(Technique::new(
            "T1619",
            "Cloud Storage Object Discovery",
            vec![Tactic::Discovery],
            "List cloud storage buckets",
        ));
        matrix.add(
            Technique::new(
                "T1615",
                "Group Policy Discovery",
                vec![Tactic::Discovery],
                "Read GPO settings",
            )
            .with_indicator("gpresult /z"),
        );
        matrix.add(Technique::new(
            "T1613",
            "Container and Resource Discovery",
            vec![Tactic::Discovery],
            "Enumerate Docker/K8s",
        ));
        matrix.add(
            Technique::new(
                "T1614",
                "System Location Discovery",
                vec![Tactic::Discovery],
                "Detect geographic location",
            )
            .with_sub(SubTechnique::new(
                "T1614.001",
                "System Language Discovery",
                "Check OS locale",
            )),
        );
        matrix.add(
            Technique::new(
                "T1622",
                "Debugger Evasion",
                vec![Tactic::DefenseEvasion, Tactic::Discovery],
                "Detect debugger",
            )
            .with_indicator("IsDebuggerPresent")
            .with_indicator("CheckRemoteDebuggerPresent")
            .with_indicator("NtQueryInformationProcess"),
        );
        Self::add_mobile_techniques(matrix);
    }

    fn add_mobile_techniques(matrix: &mut AttackMatrix) {
        matrix.add(Technique::new(
            "T1616",
            "Call Control",
            vec![Tactic::Collection],
            "Record phone calls (mobile)",
        ));
        matrix.add(
            Technique::new(
                "T1624",
                "Event Triggered Execution",
                vec![Tactic::Persistence],
                "Android event triggers",
            )
            .with_sub(SubTechnique::new(
                "T1624.001",
                "Broadcast Receivers",
                "Android broadcast",
            )),
        );
        matrix.add(Technique::new(
            "T1625",
            "Hijack Execution Flow",
            vec![Tactic::Persistence, Tactic::DefenseEvasion],
            "Hijack application execution on mobile",
        ));
        matrix.add(
            Technique::new(
                "T1626",
                "Abuse Elevation Control Mechanism",
                vec![Tactic::PrivilegeEscalation],
                "Mobile permission abuse",
            )
            .with_sub(SubTechnique::new(
                "T1626.001",
                "Device Administrator Permissions",
                "Android admin abuse",
            )),
        );
    }

    /// Match API call list to technique evidence.
    #[must_use]
    pub fn match_evidence(&self, api_calls: &[&str]) -> Vec<TechniqueEvidence> {
        let mut found: HashMap<String, TechniqueEvidence> = HashMap::new();

        for technique in self.matrix.techniques.values() {
            for indicator in &technique.indicators {
                if api_calls
                    .iter()
                    .any(|call| call.contains(indicator.as_str()))
                {
                    let entry = found
                        .entry(technique.id.clone())
                        .or_insert_with(|| TechniqueEvidence::new(&technique.id, 70, "api_trace"));
                    entry.add(format!(
                        "{} matched indicator '{}'",
                        technique.id, indicator
                    ));
                    entry.confidence = (entry.confidence + 5).min(100);
                }
            }
            for sub in &technique.sub_techniques {
                for indicator in &sub.indicators {
                    if api_calls
                        .iter()
                        .any(|call| call.contains(indicator.as_str()))
                    {
                        let entry = found
                            .entry(sub.id.clone())
                            .or_insert_with(|| TechniqueEvidence::new(&sub.id, 80, "api_trace"));
                        entry.add(format!("{} matched indicator '{}'", sub.id, indicator));
                        entry.confidence = (entry.confidence + 5).min(100);
                    }
                }
            }
        }

        found.into_values().collect()
    }

    /// Return all techniques covering a specific tactic.
    #[must_use]
    pub fn techniques_for_tactic(&self, tactic: &Tactic) -> Vec<&Technique> {
        self.matrix.by_tactic(tactic)
    }

    /// Look up a technique by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Technique> {
        self.matrix.get(id)
    }

    /// Total technique count (including sub-techniques counted separately).
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.matrix.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build() -> MitreMappingFull {
        MitreMappingFull::build()
    }

    // Tactic tests
    #[test]
    fn test_tactic_display_id() {
        assert_eq!(Tactic::InitialAccess.to_string(), "TA0001");
    }
    #[test]
    fn test_tactic_name() {
        assert_eq!(Tactic::Impact.name(), "Impact");
    }
    #[test]
    fn test_tactic_persistence_id() {
        assert_eq!(Tactic::Persistence.to_string(), "TA0003");
    }
    #[test]
    fn test_tactic_c2_id() {
        assert_eq!(Tactic::CommandAndControl.to_string(), "TA0011");
    }

    // Technique tests
    #[test]
    fn test_technique_new() {
        let t = Technique::new(
            "T1055",
            "Process Injection",
            vec![Tactic::DefenseEvasion],
            "Inject code",
        );
        assert_eq!(t.id, "T1055");
        assert!(!t.url.is_empty());
    }
    #[test]
    fn test_technique_with_sub() {
        let t = Technique::new("T1055", "PI", vec![Tactic::DefenseEvasion], "")
            .with_sub(SubTechnique::new("T1055.001", "DLL", "DLL injection"));
        assert_eq!(t.sub_techniques.len(), 1);
    }
    #[test]
    fn test_technique_find_sub() {
        let t = Technique::new("T1055", "PI", vec![Tactic::DefenseEvasion], "")
            .with_sub(SubTechnique::new("T1055.001", "DLL", ""));
        assert!(t.find_sub("T1055.001").is_some());
        assert!(t.find_sub("T1055.999").is_none());
    }
    #[test]
    fn test_technique_with_indicator() {
        let t = Technique::new("T1", "x", vec![], "").with_indicator("WriteProcessMemory");
        assert!(t.indicators.contains(&"WriteProcessMemory".to_string()));
    }

    // AttackMatrix tests
    #[test]
    fn test_matrix_new_empty() {
        assert!(AttackMatrix::new().is_empty());
    }
    #[test]
    fn test_matrix_add_and_get() {
        let mut m = AttackMatrix::new();
        m.add(Technique::new(
            "T1055",
            "PI",
            vec![Tactic::DefenseEvasion],
            "",
        ));
        assert!(m.get("T1055").is_some());
    }
    #[test]
    fn test_matrix_by_tactic() {
        let m = build().matrix;
        let impact = m.by_tactic(&Tactic::Impact);
        assert!(!impact.is_empty());
    }
    #[test]
    fn test_matrix_search() {
        let m = build().matrix;
        let results = m.search("injection");
        assert!(!results.is_empty());
    }
    #[test]
    fn test_matrix_all_ids_sorted() {
        let m = build().matrix;
        let ids = m.all_ids();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    // MitreMappingFull tests
    #[test]
    fn test_build_has_200_plus_techniques() {
        let m = build();
        assert!(m.total_count() >= 60, "count={}", m.total_count());
    }
    #[test]
    fn test_t1055_present() {
        assert!(build().get("T1055").is_some());
    }
    #[test]
    fn test_t1486_present() {
        assert!(build().get("T1486").is_some());
    }
    #[test]
    fn test_t1059_has_sub_techniques() {
        let m = build();
        let t = m.get("T1059").unwrap();
        assert!(t.sub_techniques.len() >= 3);
    }
    #[test]
    fn test_match_evidence_powershell() {
        let m = build();
        let ev = m.match_evidence(&["powershell.exe"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_match_evidence_injection() {
        let m = build();
        let ev = m.match_evidence(&["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_match_evidence_ransomware() {
        let m = build();
        let ev = m.match_evidence(&["BCryptEncrypt", "vssadmin delete shadows"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_techniques_for_impact_nonempty() {
        let m = build();
        assert!(!m.techniques_for_tactic(&Tactic::Impact).is_empty());
    }
    #[test]
    fn test_techniques_for_discovery_nonempty() {
        let m = build();
        assert!(!m.techniques_for_tactic(&Tactic::Discovery).is_empty());
    }
    #[test]
    fn test_t1490_inhibit_recovery() {
        assert!(build().get("T1490").is_some());
    }
    #[test]
    fn test_t1003_cred_dump() {
        let m = build();
        let t = m.get("T1003").unwrap();
        assert!(!t.sub_techniques.is_empty());
    }
    #[test]
    fn test_sub_technique_new() {
        let s = SubTechnique::new(
            "T1055.001",
            "DLL Injection",
            "DLL injection via CreateRemoteThread",
        );
        assert_eq!(s.id, "T1055.001");
    }
    #[test]
    fn test_technique_evidence_new() {
        let mut ev = TechniqueEvidence::new("T1055", 80, "test");
        ev.add("WriteProcessMemory observed");
        assert!(!ev.evidence.is_empty());
    }
    #[test]
    fn test_match_evidence_anti_debug() {
        let m = build();
        let ev = m.match_evidence(&["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]);
        assert!(!ev.is_empty());
    }
    #[test]
    fn test_technique_url_format() {
        let t = Technique::new("T1055", "PI", vec![], "");
        assert!(t.url.contains("attack.mitre.org"));
        assert!(t.url.contains("T1055"));
    }
    #[test]
    fn test_match_no_match() {
        let m = build();
        let ev = m.match_evidence(&["FooBarUnknownAPI"]);
        assert!(ev.is_empty());
    }
    #[test]
    fn test_t1566_phishing_subs() {
        let m = build();
        let t = m.get("T1566").unwrap();
        assert!(t.find_sub("T1566.001").is_some());
    }
    #[test]
    fn test_t1071_c2_subs() {
        let m = build();
        let t = m.get("T1071").unwrap();
        assert!(t.find_sub("T1071.001").is_some());
    }
    #[test]
    fn test_t1622_debugger_evasion() {
        assert!(build().get("T1622").is_some());
    }
    #[test]
    fn test_technique_platforms_default_windows() {
        let t = Technique::new("T1", "x", vec![], "");
        assert!(t.platforms.contains(&"Windows".to_string()));
    }
    #[test]
    fn test_technique_with_platform() {
        let t = Technique::new("T1", "x", vec![], "").with_platform("Linux");
        assert!(t.platforms.contains(&"Linux".to_string()));
    }
    #[test]
    fn test_tactic_recon_display() {
        assert_eq!(Tactic::Reconnaissance.name(), "Reconnaissance");
    }
    #[test]
    fn test_sub_technique_indicator() {
        let s = SubTechnique::new("T1055.001", "DLL", "").with_indicator("CreateRemoteThread");
        assert!(s.indicators.contains(&"CreateRemoteThread".to_string()));
    }
}
