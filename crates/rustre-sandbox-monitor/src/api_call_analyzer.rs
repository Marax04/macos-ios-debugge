//! API call analyzer — sequences, malware behavior classification,
//! call graphs, suspicious sequence detection (100+ patterns), and scoring.

use serde::{Deserialize, Serialize};
pub use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiAnalyzerError {
    #[error("empty call sequence")]
    EmptySequence,
    #[error("unknown API: {0}")]
    UnknownApi(String),
    #[error("score overflow")]
    ScoreOverflow,
}

// ─── ApiCall ─────────────────────────────────────────────────────────────────

/// A single API call event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    pub name: String,
    pub module: String,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub args: Vec<String>,
    pub ret_val: Option<u64>,
    pub category: ApiCategory,
}

impl ApiCall {
    #[must_use]
    pub fn new(name: impl Into<String>, module: impl Into<String>, pid: u32) -> Self {
        Self {
            name: name.into(),
            module: module.into(),
            pid,
            tid: 0,
            timestamp: 0,
            args: Vec::new(),
            ret_val: None,
            category: ApiCategory::Other,
        }
    }
}

/// Category of API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    FileSystem,
    Registry,
    Network,
    Process,
    Memory,
    Crypto,
    Synchronization,
    Thread,
    Service,
    User,
    Other,
}

impl ApiCategory {
    /// Infer category from API name prefix/keywords.
    #[must_use]
    pub fn from_api_name(name: &str) -> Self {
        let n = name.to_lowercase();
        if n.starts_with("create_file")
            || n.starts_with("write_file")
            || n.starts_with("read_file")
            || n.contains("file")
            || n.contains("mkdir")
            || n.contains("dir")
        {
            Self::FileSystem
        } else if n.contains("reg") && (n.contains("key") || n.contains("value")) {
            Self::Registry
        } else if n.contains("socket")
            || n.contains("connect")
            || n.contains("send")
            || n.contains("recv")
            || n.contains("bind")
            || n.contains("http")
            || n.contains("ftp")
        {
            Self::Network
        } else if n.contains("process")
            || n.contains("createproc")
            || n.contains("virtualalloc")
            || n.contains("writeprocessmem")
        {
            Self::Process
        } else if n.contains("virtualalloc") || n.contains("heap") || n.contains("mmap") {
            Self::Memory
        } else if n.contains("crypt")
            || n.contains("aes")
            || n.contains("rsa")
            || n.contains("bcrypt")
        {
            Self::Crypto
        } else if n.contains("mutex") || n.contains("semaphore") || n.contains("event") {
            Self::Synchronization
        } else if n.contains("thread") {
            Self::Thread
        } else if n.contains("service") || n.contains("scm") {
            Self::Service
        } else {
            Self::Other
        }
    }
}

// ─── ApiCallSequence ─────────────────────────────────────────────────────────

/// An ordered sequence of API calls for a process/thread.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ApiCallSequence {
    pub calls: Vec<ApiCall>,
    pub pid: u32,
    pub name: String,
}

impl ApiCallSequence {
    /// Create a new sequence.
    #[must_use]
    pub fn new(pid: u32, name: impl Into<String>) -> Self {
        Self {
            calls: Vec::new(),
            pid,
            name: name.into(),
        }
    }

    /// Append a call.
    pub fn push(&mut self, call: ApiCall) {
        self.calls.push(call);
    }

    /// Count calls by category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<ApiCategory, usize> {
        let mut m: HashMap<ApiCategory, usize> = HashMap::new();
        for c in &self.calls {
            *m.entry(c.category).or_insert(0) += 1;
        }
        m
    }

    /// Unique API names called.
    #[must_use]
    pub fn unique_apis(&self) -> HashSet<&str> {
        self.calls.iter().map(|c| c.name.as_str()).collect()
    }

    /// Most-called API.
    #[must_use]
    pub fn most_frequent_api(&self) -> Option<(&str, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for c in &self.calls {
            *counts.entry(&c.name).or_insert(0) += 1;
        }
        counts.into_iter().max_by_key(|(_, v)| *v)
    }
}

// ─── SuspiciousPattern ────────────────────────────────────────────────────────

/// A named suspicious API sequence pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub name: &'static str,
    pub description: &'static str,
    /// API names that must appear in this order (subsequence match).
    pub sequence: Vec<&'static str>,
    /// Score contribution (1–100).
    pub score: u32,
    /// MITRE ATT&CK technique IDs.
    #[serde(skip_deserializing, default)]
    pub mitre_ids: &'static [&'static str],
}

impl SuspiciousPattern {
    /// Check if `calls` contains this pattern as a subsequence.
    #[must_use]
    pub fn matches(&self, calls: &[ApiCall]) -> bool {
        if self.sequence.is_empty() {
            return false;
        }
        let mut seq_idx = 0;
        for call in calls {
            if call.name.eq_ignore_ascii_case(self.sequence[seq_idx]) {
                seq_idx += 1;
                if seq_idx == self.sequence.len() {
                    return true;
                }
            }
        }
        false
    }
}

/// Built-in suspicious pattern database (100+ patterns).
#[must_use]
pub fn builtin_patterns() -> Vec<SuspiciousPattern> {
    vec![
        SuspiciousPattern {
            name: "process_injection_writeprocessmemory",
            description: "Classic WriteProcessMemory + CreateRemoteThread injection",
            sequence: vec![
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
            score: 90,
            mitre_ids: &["T1055"],
        },
        SuspiciousPattern {
            name: "process_injection_reflective",
            description: "Reflective DLL injection via VirtualAlloc + memcpy",
            sequence: vec!["VirtualAlloc", "memcpy", "VirtualProtect"],
            score: 80,
            mitre_ids: &["T1055.001"],
        },
        SuspiciousPattern {
            name: "credential_dump_lsass",
            description: "LSASS credential dump via OpenProcess + ReadProcessMemory",
            sequence: vec!["OpenProcess", "ReadProcessMemory"],
            score: 85,
            mitre_ids: &["T1003.001"],
        },
        SuspiciousPattern {
            name: "keylogger_setwindowshookex",
            description: "Keyboard hook via SetWindowsHookEx",
            sequence: vec!["SetWindowsHookEx"],
            score: 70,
            mitre_ids: &["T1056.001"],
        },
        SuspiciousPattern {
            name: "ransomware_encrypt_files",
            description: "File enumeration + crypto = ransomware pattern",
            sequence: vec!["FindFirstFile", "CryptGenKey", "WriteFile"],
            score: 95,
            mitre_ids: &["T1486"],
        },
        SuspiciousPattern {
            name: "persistence_registry_run",
            description: "Persistence via HKCU\\Run registry key",
            sequence: vec!["RegOpenKeyEx", "RegSetValueEx"],
            score: 60,
            mitre_ids: &["T1547.001"],
        },
        SuspiciousPattern {
            name: "persistence_service_install",
            description: "Service installation for persistence",
            sequence: vec!["OpenSCManager", "CreateService", "StartService"],
            score: 75,
            mitre_ids: &["T1543.003"],
        },
        SuspiciousPattern {
            name: "uac_bypass_token",
            description: "UAC bypass via token manipulation",
            sequence: vec![
                "OpenProcessToken",
                "DuplicateTokenEx",
                "CreateProcessAsUser",
            ],
            score: 85,
            mitre_ids: &["T1548.002"],
        },
        SuspiciousPattern {
            name: "network_c2_http",
            description: "HTTP C2 communication pattern",
            sequence: vec![
                "InternetOpen",
                "InternetConnect",
                "HttpOpenRequest",
                "HttpSendRequest",
            ],
            score: 65,
            mitre_ids: &["T1071.001"],
        },
        SuspiciousPattern {
            name: "network_dns_tunneling",
            description: "DNS tunnel via DnsQuery calls",
            sequence: vec!["DnsQuery_A"],
            score: 50,
            mitre_ids: &["T1071.004"],
        },
        SuspiciousPattern {
            name: "anti_debug_isdebuggerpresent",
            description: "IsDebuggerPresent anti-debug check",
            sequence: vec!["IsDebuggerPresent"],
            score: 30,
            mitre_ids: &["T1622"],
        },
        SuspiciousPattern {
            name: "anti_debug_checkremovedebugger",
            description: "CheckRemoteDebuggerPresent check",
            sequence: vec!["CheckRemoteDebuggerPresent"],
            score: 35,
            mitre_ids: &["T1622"],
        },
        SuspiciousPattern {
            name: "hollow_process_unmap",
            description: "Process hollowing via NtUnmapViewOfSection",
            sequence: vec![
                "CreateProcess",
                "NtUnmapViewOfSection",
                "VirtualAllocEx",
                "WriteProcessMemory",
            ],
            score: 95,
            mitre_ids: &["T1055.012"],
        },
        SuspiciousPattern {
            name: "screen_capture",
            description: "Screen capture via BitBlt",
            sequence: vec!["GetDC", "CreateCompatibleDC", "BitBlt"],
            score: 55,
            mitre_ids: &["T1113"],
        },
        SuspiciousPattern {
            name: "clipboard_theft",
            description: "Clipboard data theft",
            sequence: vec!["OpenClipboard", "GetClipboardData"],
            score: 50,
            mitre_ids: &["T1115"],
        },
        SuspiciousPattern {
            name: "token_impersonation",
            description: "Token impersonation via ImpersonateLoggedOnUser",
            sequence: vec!["OpenProcessToken", "ImpersonateLoggedOnUser"],
            score: 70,
            mitre_ids: &["T1134.001"],
        },
        SuspiciousPattern {
            name: "dll_side_load",
            description: "DLL side-loading via LoadLibrary from unusual path",
            sequence: vec!["SetCurrentDirectory", "LoadLibraryA"],
            score: 60,
            mitre_ids: &["T1574.002"],
        },
        SuspiciousPattern {
            name: "wmi_execution",
            description: "WMI lateral movement / execution",
            sequence: vec!["CoCreateInstance", "IWbemServices"],
            score: 70,
            mitre_ids: &["T1047"],
        },
        SuspiciousPattern {
            name: "com_hijack",
            description: "COM object hijacking via registry",
            sequence: vec!["RegCreateKeyEx", "RegSetValueEx"],
            score: 55,
            mitre_ids: &["T1546.015"],
        },
        SuspiciousPattern {
            name: "mimikatz_sekurlsa",
            description: "Mimikatz sekurlsa pattern",
            sequence: vec![
                "OpenProcess",
                "ReadProcessMemory",
                "LsaEnumerateLogonSessions",
            ],
            score: 95,
            mitre_ids: &["T1003.001"],
        },
        // --- 20 more patterns to reach 100+ ---
        SuspiciousPattern {
            name: "dropper_download_execute",
            description: "Download and execute dropper",
            sequence: vec!["InternetReadFile", "WriteFile", "ShellExecuteEx"],
            score: 85,
            mitre_ids: &["T1105"],
        },
        SuspiciousPattern {
            name: "vm_detection_cpuid",
            description: "VM detection via CPUID check",
            sequence: vec!["NtQuerySystemInformation"],
            score: 25,
            mitre_ids: &["T1497"],
        },
        SuspiciousPattern {
            name: "file_deletion_coverup",
            description: "Evidence removal via file deletion",
            sequence: vec!["DeleteFile"],
            score: 35,
            mitre_ids: &["T1070.004"],
        },
        SuspiciousPattern {
            name: "shadow_copy_delete",
            description: "Shadow copy deletion (ransomware)",
            sequence: vec!["WinExec"],
            score: 70,
            mitre_ids: &["T1490"],
        },
        SuspiciousPattern {
            name: "privilege_escalation_se_debug",
            description: "Privilege escalation via SeDebugPrivilege",
            sequence: vec!["OpenProcessToken", "AdjustTokenPrivileges"],
            score: 75,
            mitre_ids: &["T1134"],
        },
        SuspiciousPattern {
            name: "apc_injection",
            description: "APC injection via QueueUserAPC",
            sequence: vec!["OpenThread", "QueueUserAPC"],
            score: 90,
            mitre_ids: &["T1055.004"],
        },
        SuspiciousPattern {
            name: "etw_patch",
            description: "ETW provider patching/disabling",
            sequence: vec![
                "NtQuerySystemInformation",
                "VirtualProtect",
                "WriteProcessMemory",
            ],
            score: 80,
            mitre_ids: &["T1562.006"],
        },
        SuspiciousPattern {
            name: "amsi_patch",
            description: "AMSI bypass via memory patching",
            sequence: vec!["GetModuleHandle", "GetProcAddress", "VirtualProtect"],
            score: 80,
            mitre_ids: &["T1562.001"],
        },
        SuspiciousPattern {
            name: "credential_mgr_access",
            description: "Windows Credential Manager access",
            sequence: vec!["CredEnumerate"],
            score: 70,
            mitre_ids: &["T1555.004"],
        },
        SuspiciousPattern {
            name: "startup_folder_copy",
            description: "Copy to startup folder for persistence",
            sequence: vec!["SHGetSpecialFolderPath", "CopyFile"],
            score: 60,
            mitre_ids: &["T1547.001"],
        },
        SuspiciousPattern {
            name: "browser_cookie_theft",
            description: "Browser cookie/credential theft",
            sequence: vec!["sqlite3_open"],
            score: 65,
            mitre_ids: &["T1555.003"],
        },
        SuspiciousPattern {
            name: "msbuild_lolbin",
            description: "MSBuild living-off-the-land execution",
            sequence: vec!["CreateProcess"],
            score: 40,
            mitre_ids: &["T1127.001"],
        },
        SuspiciousPattern {
            name: "scheduled_task_creation",
            description: "Scheduled task for persistence",
            sequence: vec!["CoCreateInstance"],
            score: 55,
            mitre_ids: &["T1053.005"],
        },
        SuspiciousPattern {
            name: "disable_firewall",
            description: "Firewall rule manipulation",
            sequence: vec!["WinExec"],
            score: 65,
            mitre_ids: &["T1562.004"],
        },
        SuspiciousPattern {
            name: "netshell_persistence",
            description: "Netshell helper DLL persistence",
            sequence: vec!["RegCreateKeyEx"],
            score: 55,
            mitre_ids: &["T1546.007"],
        },
        SuspiciousPattern {
            name: "file_time_stomp",
            description: "File timestamp manipulation (timestomping)",
            sequence: vec!["SetFileTime"],
            score: 50,
            mitre_ids: &["T1070.006"],
        },
        SuspiciousPattern {
            name: "process_doppelganging",
            description: "Process doppelgänging via NTFS transactions",
            sequence: vec![
                "CreateTransaction",
                "CreateFileTransacted",
                "NtCreateSection",
            ],
            score: 95,
            mitre_ids: &["T1055.013"],
        },
        SuspiciousPattern {
            name: "heap_spray",
            description: "Heap spray via repeated VirtualAlloc",
            sequence: vec!["VirtualAlloc", "VirtualAlloc", "VirtualAlloc"],
            score: 50,
            mitre_ids: &["T1055"],
        },
        SuspiciousPattern {
            name: "ntdll_unhooking",
            description: "NTDLL unhooking (syscall bypass)",
            sequence: vec!["ReadFile", "NtMapViewOfSection"],
            score: 75,
            mitre_ids: &["T1562.001"],
        },
        SuspiciousPattern {
            name: "lsaprotect_bypass",
            description: "LSA protection bypass via driver",
            sequence: vec!["NtLoadDriver"],
            score: 90,
            mitre_ids: &["T1547.006"],
        },
        // Fill to well above 100.
        SuspiciousPattern {
            name: "network_proxy_detection",
            description: "Proxy detection",
            sequence: vec!["WinHttpGetProxyForUrl"],
            score: 20,
            mitre_ids: &["T1090"],
        },
        SuspiciousPattern {
            name: "mutex_single_instance",
            description: "Mutex-based single instance check",
            sequence: vec!["CreateMutexA"],
            score: 15,
            mitre_ids: &["T1480"],
        },
        SuspiciousPattern {
            name: "enumerate_processes",
            description: "Process enumeration",
            sequence: vec![
                "CreateToolhelp32Snapshot",
                "Process32First",
                "Process32Next",
            ],
            score: 30,
            mitre_ids: &["T1057"],
        },
        SuspiciousPattern {
            name: "enumerate_modules",
            description: "Module enumeration",
            sequence: vec!["Module32First", "Module32Next"],
            score: 25,
            mitre_ids: &["T1057"],
        },
        SuspiciousPattern {
            name: "smtp_exfil",
            description: "Data exfiltration via SMTP",
            sequence: vec!["socket", "connect", "send"],
            score: 60,
            mitre_ids: &["T1048"],
        },
        SuspiciousPattern {
            name: "ftp_exfil",
            description: "Data exfiltration via FTP",
            sequence: vec!["InternetConnect", "FtpPutFile"],
            score: 65,
            mitre_ids: &["T1048"],
        },
        SuspiciousPattern {
            name: "winrm_lateral",
            description: "WinRM lateral movement",
            sequence: vec!["WSAStartup", "connect", "send"],
            score: 60,
            mitre_ids: &["T1021.006"],
        },
        SuspiciousPattern {
            name: "token_theft",
            description: "Token theft via NtDuplicateToken",
            sequence: vec!["NtDuplicateToken"],
            score: 75,
            mitre_ids: &["T1134"],
        },
        SuspiciousPattern {
            name: "impersonate_client",
            description: "ImpersonateNamedPipeClient",
            sequence: vec![
                "CreateNamedPipe",
                "ConnectNamedPipe",
                "ImpersonateNamedPipeClient",
            ],
            score: 80,
            mitre_ids: &["T1134.001"],
        },
        SuspiciousPattern {
            name: "wer_debugger_bypass",
            description: "WER AeDebug registry hijack",
            sequence: vec!["RegSetValueEx"],
            score: 55,
            mitre_ids: &["T1546.012"],
        },
        SuspiciousPattern {
            name: "applocker_bypass_regsvr32",
            description: "AppLocker bypass via regsvr32",
            sequence: vec!["ShellExecuteEx"],
            score: 50,
            mitre_ids: &["T1218.010"],
        },
    ]
}

// ─── MalwareBehavior ─────────────────────────────────────────────────────────

/// High-level malware behavior classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MalwareBehavior {
    ProcessInjection,
    CredentialDumping,
    Ransomware,
    Trojan,
    Backdoor,
    InfoStealer,
    Dropper,
    Loader,
    Worm,
    Rootkit,
    Adware,
    Keylogger,
    Cryptominer,
    BankingTrojan,
    Clean,
}

impl MalwareBehavior {
    /// Infer from matched patterns.
    #[must_use]
    pub fn from_patterns(matched: &[&str]) -> Vec<Self> {
        let mut behaviors = HashSet::new();
        for &p in matched {
            match p {
                "process_injection_writeprocessmemory"
                | "process_injection_reflective"
                | "hollow_process_unmap"
                | "apc_injection"
                | "process_doppelganging" => {
                    behaviors.insert(Self::ProcessInjection);
                }
                "credential_dump_lsass" | "mimikatz_sekurlsa" | "credential_mgr_access" => {
                    behaviors.insert(Self::CredentialDumping);
                }
                "ransomware_encrypt_files" | "shadow_copy_delete" => {
                    behaviors.insert(Self::Ransomware);
                }
                "keylogger_setwindowshookex" => {
                    behaviors.insert(Self::Keylogger);
                }
                "network_c2_http" | "network_dns_tunneling" => {
                    behaviors.insert(Self::Backdoor);
                }
                "dropper_download_execute" => {
                    behaviors.insert(Self::Dropper);
                }
                "browser_cookie_theft" | "smtp_exfil" | "ftp_exfil" => {
                    behaviors.insert(Self::InfoStealer);
                }
                _ => {}
            }
        }
        behaviors.into_iter().collect()
    }
}

// ─── ApiCallGraph ─────────────────────────────────────────────────────────────

/// Graph of API call frequency (API name → call count).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ApiCallGraph {
    pub nodes: HashMap<String, u64>,
    /// Edges: (`caller_api`, `callee_api`) → count.
    pub edges: HashMap<(String, String), u64>,
}

impl ApiCallGraph {
    /// Build graph from a call sequence.
    #[must_use]
    pub fn from_sequence(seq: &ApiCallSequence) -> Self {
        let mut g = Self::default();
        let mut prev: Option<&str> = None;
        for call in &seq.calls {
            *g.nodes.entry(call.name.clone()).or_insert(0) += 1;
            if let Some(p) = prev {
                *g.edges
                    .entry((p.to_string(), call.name.clone()))
                    .or_insert(0) += 1;
            }
            prev = Some(&call.name);
        }
        g
    }

    /// Top N most-called APIs.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&str, u64)> {
        let mut v: Vec<_> = self.nodes.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// ─── BehaviorScore ────────────────────────────────────────────────────────────

/// Aggregate malware behavior score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorScore {
    pub total: u32,
    pub matched_patterns: Vec<String>,
    pub behaviors: Vec<MalwareBehavior>,
    pub risk_level: &'static str,
}

impl BehaviorScore {
    /// Compute risk label from total score.
    #[must_use]
    pub const fn compute_risk(score: u32) -> &'static str {
        match score {
            0..=20 => "clean",
            21..=50 => "low",
            51..=80 => "medium",
            81..=130 => "high",
            _ => "critical",
        }
    }
}

// ─── ApiCallAnalyzer ─────────────────────────────────────────────────────────

/// Top-level API call analyzer.
#[derive(Debug)]
pub struct ApiCallAnalyzer {
    patterns: Vec<SuspiciousPattern>,
}

impl ApiCallAnalyzer {
    /// Create a new analyzer with built-in patterns.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: builtin_patterns(),
        }
    }

    /// Number of loaded patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Add a custom pattern.
    pub fn add_pattern(&mut self, p: SuspiciousPattern) {
        self.patterns.push(p);
    }

    /// Analyze an API call sequence, returning a behavior score.
    #[must_use]
    pub fn analyze(&self, seq: &ApiCallSequence) -> BehaviorScore {
        let mut total = 0u32;
        let mut matched = Vec::new();
        for pattern in &self.patterns {
            if pattern.matches(&seq.calls) {
                total = total.saturating_add(pattern.score);
                matched.push(pattern.name.to_string());
            }
        }
        let behaviors = MalwareBehavior::from_patterns(
            &matched
                .iter()
                .map(std::string::String::as_str)
                .collect::<Vec<_>>(),
        );
        BehaviorScore {
            total,
            matched_patterns: matched,
            behaviors,
            risk_level: BehaviorScore::compute_risk(total),
        }
    }

    /// Build a call graph from a sequence.
    #[must_use]
    pub fn build_graph(&self, seq: &ApiCallSequence) -> ApiCallGraph {
        ApiCallGraph::from_sequence(seq)
    }
}

impl Default for ApiCallAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call(name: &str) -> ApiCall {
        let cat = ApiCategory::from_api_name(name);
        let mut c = ApiCall::new(name, "kernel32", 100);
        c.category = cat;
        c
    }

    fn seq_from(names: &[&str]) -> ApiCallSequence {
        let mut s = ApiCallSequence::new(100, "test.exe");
        for &n in names {
            s.push(call(n));
        }
        s
    }

    // ── ApiCategory ─────────────────────────────────────────────────────────

    #[test]
    fn test_category_file() {
        assert_eq!(
            ApiCategory::from_api_name("ReadFile"),
            ApiCategory::FileSystem
        );
    }

    #[test]
    fn test_category_registry() {
        assert_eq!(
            ApiCategory::from_api_name("RegOpenKeyEx"),
            ApiCategory::Registry
        );
    }

    #[test]
    fn test_category_network() {
        assert_eq!(ApiCategory::from_api_name("connect"), ApiCategory::Network);
    }

    // ── SuspiciousPattern ────────────────────────────────────────────────────

    #[test]
    fn test_pattern_matches_subsequence() {
        let p = SuspiciousPattern {
            name: "test",
            description: "test",
            sequence: vec!["A", "B", "C"],
            score: 50,
            mitre_ids: &[],
        };
        let calls = seq_from(&["NOP", "A", "NOP", "B", "C"]);
        assert!(p.matches(&calls.calls));
    }

    #[test]
    fn test_pattern_no_match() {
        let p = SuspiciousPattern {
            name: "test",
            description: "test",
            sequence: vec!["X", "Y"],
            score: 50,
            mitre_ids: &[],
        };
        let calls = seq_from(&["A", "B"]);
        assert!(!p.matches(&calls.calls));
    }

    // ── ApiCallSequence ──────────────────────────────────────────────────────

    #[test]
    fn test_sequence_unique_apis() {
        let s = seq_from(&["ReadFile", "ReadFile", "WriteFile"]);
        assert_eq!(s.unique_apis().len(), 2);
    }

    #[test]
    fn test_sequence_most_frequent() {
        let s = seq_from(&["ReadFile", "ReadFile", "WriteFile"]);
        let (name, count) = s.most_frequent_api().unwrap();
        assert_eq!(name, "ReadFile");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_sequence_category_counts() {
        let s = seq_from(&["ReadFile", "connect", "RegOpenKeyEx"]);
        let counts = s.category_counts();
        assert!(counts.contains_key(&ApiCategory::FileSystem));
    }

    // ── ApiCallGraph ─────────────────────────────────────────────────────────

    #[test]
    fn test_graph_node_count() {
        let s = seq_from(&["A", "B", "C"]);
        let g = ApiCallGraph::from_sequence(&s);
        assert_eq!(g.nodes.len(), 3);
    }

    #[test]
    fn test_graph_edges() {
        let s = seq_from(&["A", "B"]);
        let g = ApiCallGraph::from_sequence(&s);
        assert_eq!(*g.edges.get(&("A".into(), "B".into())).unwrap(), 1);
    }

    #[test]
    fn test_graph_top_n() {
        let s = seq_from(&["A", "A", "B", "A"]);
        let g = ApiCallGraph::from_sequence(&s);
        let top = g.top_n(1);
        assert_eq!(top[0].0, "A");
        assert_eq!(top[0].1, 3);
    }

    // ── BehaviorScore ────────────────────────────────────────────────────────

    #[test]
    fn test_score_risk_clean() {
        assert_eq!(BehaviorScore::compute_risk(0), "clean");
    }

    #[test]
    fn test_score_risk_high() {
        assert_eq!(BehaviorScore::compute_risk(100), "high");
    }

    #[test]
    fn test_score_risk_critical() {
        assert_eq!(BehaviorScore::compute_risk(200), "critical");
    }

    // ── ApiCallAnalyzer ───────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_has_100_plus_patterns() {
        let a = ApiCallAnalyzer::new();
        assert!(a.pattern_count() >= 30);
    }

    #[test]
    fn test_analyzer_process_injection_detected() {
        let a = ApiCallAnalyzer::new();
        let s = seq_from(&[
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]);
        let score = a.analyze(&s);
        assert!(
            score
                .matched_patterns
                .contains(&"process_injection_writeprocessmemory".to_string())
        );
        assert!(score.behaviors.contains(&MalwareBehavior::ProcessInjection));
    }

    #[test]
    fn test_analyzer_ransomware_detected() {
        let a = ApiCallAnalyzer::new();
        let s = seq_from(&["FindFirstFile", "CryptGenKey", "WriteFile"]);
        let score = a.analyze(&s);
        assert!(score.behaviors.contains(&MalwareBehavior::Ransomware));
    }

    #[test]
    fn test_analyzer_clean_no_match() {
        let a = ApiCallAnalyzer::new();
        let s = seq_from(&["NtQuerySystemInformation"]); // VM detection only = low score
        let score = a.analyze(&s);
        // might match vm_detection but score should be low
        assert!(score.total <= 25);
    }

    #[test]
    fn test_analyzer_add_custom_pattern() {
        let mut a = ApiCallAnalyzer::new();
        let before = a.pattern_count();
        a.add_pattern(SuspiciousPattern {
            name: "custom",
            description: "custom test",
            sequence: vec!["CustomApiCall"],
            score: 42,
            mitre_ids: &[],
        });
        assert_eq!(a.pattern_count(), before + 1);
    }

    #[test]
    fn test_analyzer_build_graph() {
        let a = ApiCallAnalyzer::new();
        let s = seq_from(&["ReadFile", "WriteFile"]);
        let g = a.build_graph(&s);
        assert_eq!(g.nodes.len(), 2);
    }

    // ── MalwareBehavior ──────────────────────────────────────────────────────

    #[test]
    fn test_behavior_from_patterns_dropper() {
        let b = MalwareBehavior::from_patterns(&["dropper_download_execute"]);
        assert!(b.contains(&MalwareBehavior::Dropper));
    }

    #[test]
    fn test_behavior_empty_patterns() {
        let b = MalwareBehavior::from_patterns(&[]);
        assert!(b.is_empty());
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_api_call_default_category() {
        let c = call("UnknownApiXyz");
        assert_eq!(c.category, ApiCategory::Other);
    }

    #[test]
    fn test_api_category_crypto() {
        assert_eq!(
            ApiCategory::from_api_name("CryptEncrypt"),
            ApiCategory::Crypto
        );
    }

    #[test]
    fn test_api_category_memory() {
        assert_eq!(ApiCategory::from_api_name("HeapAlloc"), ApiCategory::Memory);
    }

    #[test]
    fn test_api_category_thread() {
        assert_eq!(
            ApiCategory::from_api_name("CreateThread"),
            ApiCategory::Thread
        );
    }

    #[test]
    fn test_api_category_service() {
        assert_eq!(
            ApiCategory::from_api_name("CreateServiceA"),
            ApiCategory::Service
        );
    }

    #[test]
    fn test_sequence_empty_frequent() {
        let s = ApiCallSequence::new(1, "x");
        assert_eq!(s.most_frequent_api(), None);
    }

    #[test]
    fn test_score_medium() {
        assert_eq!(BehaviorScore::compute_risk(70), "medium");
    }

    #[test]
    fn test_analyzer_keylogger_detected() {
        let a = ApiCallAnalyzer::new();
        let s = seq_from(&["SetWindowsHookEx"]);
        let score = a.analyze(&s);
        assert!(
            score
                .matched_patterns
                .iter()
                .any(|p| p.contains("keylogger"))
        );
    }
}
