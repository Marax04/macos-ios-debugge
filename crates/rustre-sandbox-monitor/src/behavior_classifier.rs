//! Sandbox behavior classifier.
//!
//! `BehaviorClassifier` matches sequences of API-call events against 30+
//! built-in `BehaviorSignature`s and produces a `BehaviorReport`.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ─── BehaviorCategory ─────────────────────────────────────────────────────────

/// High-level category of a detected behavior.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorCategory {
    /// File system access / modification.
    FileSystem,
    /// Network communication.
    Network,
    /// Windows registry manipulation.
    Registry,
    /// Process / thread operations.
    Process,
    /// Persistence mechanisms.
    Persistence,
    /// Code / process injection.
    Injection,
    /// Anti-analysis / sandbox evasion.
    Evasion,
    /// Cryptographic operations.
    Crypto,
    /// Command-and-control communication.
    C2,
    /// Data exfiltration.
    Exfiltration,
}

impl fmt::Display for BehaviorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FileSystem => "filesystem",
            Self::Network => "network",
            Self::Registry => "registry",
            Self::Process => "process",
            Self::Persistence => "persistence",
            Self::Injection => "injection",
            Self::Evasion => "evasion",
            Self::Crypto => "crypto",
            Self::C2 => "c2",
            Self::Exfiltration => "exfiltration",
        };
        write!(f, "{s}")
    }
}

// ─── BehaviorSignature ────────────────────────────────────────────────────────

/// A behavior signature: a set of API names that, when all appear in a sequence,
/// indicate a specific behavior.
#[derive(Debug, Clone)]
pub struct BehaviorSignature {
    /// Short identifier for this signature.
    pub id: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Category this signature belongs to.
    pub category: BehaviorCategory,
    /// API names that must all be present (as a subsequence or as a set).
    pub api_sequence: &'static [&'static str],
    /// Match mode.
    pub mode: MatchMode,
    /// Base severity score (0–100).
    pub severity: u8,
}

/// How the `api_sequence` is matched against observed events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// All APIs must be present (in any order).
    AllPresent,
    /// All APIs must appear as a subsequence (in order, not necessarily contiguous).
    OrderedSubsequence,
    /// Any one API in the list suffices.
    AnyPresent,
}

impl BehaviorSignature {
    /// Returns `true` if this signature matches the given API call set / sequence.
    #[must_use]
    pub fn matches(&self, calls: &[String]) -> bool {
        match self.mode {
            MatchMode::AllPresent => {
                let call_set: HashSet<&str> = calls.iter().map(String::as_str).collect();
                self.api_sequence.iter().all(|&api| call_set.contains(api))
            }
            MatchMode::OrderedSubsequence => {
                let mut idx = 0usize;
                for call in calls {
                    if idx < self.api_sequence.len() && call == self.api_sequence[idx] {
                        idx += 1;
                    }
                }
                idx == self.api_sequence.len()
            }
            MatchMode::AnyPresent => {
                let call_set: HashSet<&str> = calls.iter().map(String::as_str).collect();
                self.api_sequence.iter().any(|&api| call_set.contains(api))
            }
        }
    }
}

// ─── Built-in signatures ──────────────────────────────────────────────────────

/// The built-in signature database (30+ entries).
pub static BUILT_IN_SIGNATURES: &[BehaviorSignature] = &[
    // ── Injection ────────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "process_injection",
        description: "Classic process injection via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
        category: BehaviorCategory::Injection,
        api_sequence: &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        mode: MatchMode::OrderedSubsequence,
        severity: 95,
    },
    BehaviorSignature {
        id: "dll_injection_loadlibrary",
        description: "DLL injection via WriteProcessMemory + LoadLibrary",
        category: BehaviorCategory::Injection,
        api_sequence: &[
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ],
        mode: MatchMode::AllPresent,
        severity: 90,
    },
    BehaviorSignature {
        id: "apc_injection",
        description: "APC injection via QueueUserAPC",
        category: BehaviorCategory::Injection,
        api_sequence: &["OpenThread", "QueueUserAPC"],
        mode: MatchMode::AllPresent,
        severity: 85,
    },
    BehaviorSignature {
        id: "nt_map_injection",
        description: "Section-based injection via NtMapViewOfSection",
        category: BehaviorCategory::Injection,
        api_sequence: &["NtCreateSection", "NtMapViewOfSection", "NtCreateThread"],
        mode: MatchMode::AllPresent,
        severity: 90,
    },
    // ── Persistence ──────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "run_key_persistence",
        description: "Writes to HKCU or HKLM Run key for auto-start persistence",
        category: BehaviorCategory::Persistence,
        api_sequence: &["RegOpenKeyExW", "RegSetValueExW"],
        mode: MatchMode::AllPresent,
        severity: 75,
    },
    BehaviorSignature {
        id: "scheduled_task_creation",
        description: "Scheduled task creation via COM or schtasks",
        category: BehaviorCategory::Persistence,
        api_sequence: &["CoCreateInstance", "ITaskScheduler"],
        mode: MatchMode::AnyPresent,
        severity: 70,
    },
    BehaviorSignature {
        id: "service_installation",
        description: "Windows service registration for persistence",
        category: BehaviorCategory::Persistence,
        api_sequence: &["CreateServiceW", "StartServiceW"],
        mode: MatchMode::AllPresent,
        severity: 80,
    },
    BehaviorSignature {
        id: "startup_folder_drop",
        description: "File dropped to startup folder",
        category: BehaviorCategory::Persistence,
        api_sequence: &["SHGetFolderPathW", "CreateFileW", "WriteFile"],
        mode: MatchMode::AllPresent,
        severity: 70,
    },
    // ── Evasion ───────────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "debugger_detection",
        description: "Attempts to detect attached debugger",
        category: BehaviorCategory::Evasion,
        api_sequence: &[
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringW",
        ],
        mode: MatchMode::AnyPresent,
        severity: 60,
    },
    BehaviorSignature {
        id: "timing_check",
        description: "Timing-based sandbox evasion (RDTSC / GetTickCount)",
        category: BehaviorCategory::Evasion,
        api_sequence: &["GetTickCount", "QueryPerformanceCounter"],
        mode: MatchMode::AllPresent,
        severity: 40,
    },
    BehaviorSignature {
        id: "vm_detection",
        description: "Virtual machine / sandbox detection via CPUID or registry",
        category: BehaviorCategory::Evasion,
        api_sequence: &["RegOpenKeyExA", "NtQuerySystemInformation"],
        mode: MatchMode::AllPresent,
        severity: 55,
    },
    BehaviorSignature {
        id: "sleep_evasion",
        description: "Long sleep to evade sandbox time limits",
        category: BehaviorCategory::Evasion,
        api_sequence: &["Sleep"],
        mode: MatchMode::AnyPresent,
        severity: 30,
    },
    BehaviorSignature {
        id: "thread_hide_from_debugger",
        description: "Hides thread from debugger via NtSetInformationThread",
        category: BehaviorCategory::Evasion,
        api_sequence: &["NtSetInformationThread"],
        mode: MatchMode::AnyPresent,
        severity: 70,
    },
    // ── Crypto ────────────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "ransomware_encryption",
        description: "Bulk file encryption pattern (ransomware indicator)",
        category: BehaviorCategory::Crypto,
        api_sequence: &["CryptEncrypt", "BCryptEncrypt"],
        mode: MatchMode::AnyPresent,
        severity: 85,
    },
    BehaviorSignature {
        id: "key_generation",
        description: "Cryptographic key generation",
        category: BehaviorCategory::Crypto,
        api_sequence: &["BCryptGenerateSymmetricKey", "CryptGenKey"],
        mode: MatchMode::AnyPresent,
        severity: 50,
    },
    BehaviorSignature {
        id: "cert_store_access",
        description: "Certificate store access (credential theft indicator)",
        category: BehaviorCategory::Crypto,
        api_sequence: &["CertOpenSystemStoreW", "CertEnumCertificatesInStore"],
        mode: MatchMode::AllPresent,
        severity: 65,
    },
    // ── Network / C2 ──────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "http_c2",
        description: "HTTP-based C2 communication",
        category: BehaviorCategory::C2,
        api_sequence: &["WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest"],
        mode: MatchMode::AllPresent,
        severity: 75,
    },
    BehaviorSignature {
        id: "raw_socket_c2",
        description: "Raw socket-based C2 communication",
        category: BehaviorCategory::C2,
        api_sequence: &["WSASocket", "connect", "send", "recv"],
        mode: MatchMode::AllPresent,
        severity: 70,
    },
    BehaviorSignature {
        id: "dns_query",
        description: "DNS query (may indicate DGA or C2 domain lookup)",
        category: BehaviorCategory::Network,
        api_sequence: &["DnsQuery_W", "GetAddrInfoW"],
        mode: MatchMode::AnyPresent,
        severity: 30,
    },
    BehaviorSignature {
        id: "smtp_exfil",
        description: "Email-based exfiltration via SMTP",
        category: BehaviorCategory::Exfiltration,
        api_sequence: &["InternetConnect", "FtpPutFileW"],
        mode: MatchMode::AnyPresent,
        severity: 80,
    },
    // ── File System ───────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "mass_file_rename",
        description: "Mass file renaming (ransomware file extension change)",
        category: BehaviorCategory::FileSystem,
        api_sequence: &["FindFirstFileW", "FindNextFileW", "MoveFileExW"],
        mode: MatchMode::AllPresent,
        severity: 80,
    },
    BehaviorSignature {
        id: "shadow_copy_deletion",
        description: "Shadow copy deletion (ransomware anti-recovery)",
        category: BehaviorCategory::FileSystem,
        api_sequence: &["WinExec", "ShellExecuteW"],
        mode: MatchMode::AnyPresent,
        severity: 90,
    },
    BehaviorSignature {
        id: "executable_drop",
        description: "Executable file written to disk",
        category: BehaviorCategory::FileSystem,
        api_sequence: &["CreateFileW", "WriteFile"],
        mode: MatchMode::AllPresent,
        severity: 55,
    },
    BehaviorSignature {
        id: "temp_directory_write",
        description: "File written to TEMP directory",
        category: BehaviorCategory::FileSystem,
        api_sequence: &["GetTempPathW", "CreateFileW", "WriteFile"],
        mode: MatchMode::AllPresent,
        severity: 40,
    },
    // ── Process ───────────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "process_hollowing",
        description: "Process hollowing / RunPE pattern",
        category: BehaviorCategory::Process,
        api_sequence: &[
            "CreateProcessW",
            "NtUnmapViewOfSection",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "SetThreadContext",
            "ResumeThread",
        ],
        mode: MatchMode::AllPresent,
        severity: 95,
    },
    BehaviorSignature {
        id: "child_process_spawn",
        description: "Spawns a child process (cmd.exe / powershell)",
        category: BehaviorCategory::Process,
        api_sequence: &["CreateProcessW", "CreateProcessA"],
        mode: MatchMode::AnyPresent,
        severity: 35,
    },
    BehaviorSignature {
        id: "wmi_execution",
        description: "WMI-based process execution",
        category: BehaviorCategory::Process,
        api_sequence: &["CoCreateInstance", "IWbemServices"],
        mode: MatchMode::AnyPresent,
        severity: 65,
    },
    // ── Exfiltration ──────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "credential_access",
        description: "Credential dumping via LSASS or SAM",
        category: BehaviorCategory::Exfiltration,
        api_sequence: &["MiniDumpWriteDump", "OpenProcess", "ReadProcessMemory"],
        mode: MatchMode::AllPresent,
        severity: 95,
    },
    BehaviorSignature {
        id: "clipboard_access",
        description: "Clipboard data access (possible info-stealer)",
        category: BehaviorCategory::Exfiltration,
        api_sequence: &["OpenClipboard", "GetClipboardData"],
        mode: MatchMode::AllPresent,
        severity: 60,
    },
    BehaviorSignature {
        id: "keylogger",
        description: "Keylogger via SetWindowsHookEx",
        category: BehaviorCategory::Exfiltration,
        api_sequence: &["SetWindowsHookExW", "GetAsyncKeyState"],
        mode: MatchMode::AnyPresent,
        severity: 85,
    },
    BehaviorSignature {
        id: "screenshot_capture",
        description: "Screen capture (spyware indicator)",
        category: BehaviorCategory::Exfiltration,
        api_sequence: &["GetDC", "BitBlt", "CreateCompatibleDC"],
        mode: MatchMode::AllPresent,
        severity: 70,
    },
    // ── Registry ──────────────────────────────────────────────────────────────
    BehaviorSignature {
        id: "registry_run_set",
        description: "HKLM/HKCU Run key value set",
        category: BehaviorCategory::Registry,
        api_sequence: &["RegSetValueExW"],
        mode: MatchMode::AnyPresent,
        severity: 45,
    },
];

// ─── BehaviorEvent ────────────────────────────────────────────────────────────

/// A single sandbox event (intercepted API call).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    /// API / syscall name.
    pub api: String,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Timestamp in milliseconds.
    pub ts_ms: u64,
    /// Argument strings (for context).
    pub args: Vec<String>,
    /// Return value.
    pub ret: Option<i64>,
}

impl BehaviorEvent {
    /// Create a new event.
    #[must_use]
    pub fn new(api: impl Into<String>, pid: u32) -> Self {
        Self {
            api: api.into(),
            pid,
            tid: 0,
            ts_ms: 0,
            args: vec![],
            ret: None,
        }
    }

    #[must_use]
    pub const fn with_ts(mut self, ts: u64) -> Self {
        self.ts_ms = ts;
        self
    }
    #[must_use]
    pub fn with_arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
}

// ─── BehaviorMatch ────────────────────────────────────────────────────────────

/// A matched behavior signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorMatch {
    /// Signature identifier.
    pub sig_id: String,
    /// Description of the behavior.
    pub description: String,
    /// Category of the behavior.
    pub category: BehaviorCategory,
    /// Severity score (0–100).
    pub severity: u8,
    /// The API calls in the event trace that triggered the match.
    pub matched_apis: Vec<String>,
}

// ─── BehaviorReport ───────────────────────────────────────────────────────────

/// Aggregated classification report for a set of events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    /// Process IDs observed in this report.
    pub pids: Vec<u32>,
    /// All matched signatures.
    pub matches: Vec<BehaviorMatch>,
    /// Overall risk score (0–100), aggregated from match severities.
    pub risk_score: u8,
    /// Top-level behavior categories observed.
    pub categories: Vec<BehaviorCategory>,
    /// Total events analyzed.
    pub event_count: usize,
    /// Unique API names observed.
    pub unique_apis: Vec<String>,
}

impl BehaviorReport {
    /// True if any match has the given category.
    #[must_use]
    pub fn has_category(&self, cat: &BehaviorCategory) -> bool {
        self.categories.contains(cat)
    }

    /// Number of matched signatures.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// True if the risk score exceeds `threshold`.
    #[must_use]
    pub const fn is_high_risk(&self, threshold: u8) -> bool {
        self.risk_score >= threshold
    }

    /// Find all matches in the given category.
    #[must_use]
    pub fn matches_for_category(&self, cat: &BehaviorCategory) -> Vec<&BehaviorMatch> {
        self.matches.iter().filter(|m| &m.category == cat).collect()
    }

    /// The highest-severity match, if any.
    #[must_use]
    pub fn top_match(&self) -> Option<&BehaviorMatch> {
        self.matches.iter().max_by_key(|m| m.severity)
    }
}

impl fmt::Display for BehaviorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BehaviorReport {{ risk={}, matches={}, events={}, categories=[{}] }}",
            self.risk_score,
            self.match_count(),
            self.event_count,
            self.categories
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

// ─── BehaviorClassifier ───────────────────────────────────────────────────────

/// Sandbox behavior classifier.
///
/// Matches a list of `BehaviorEvent`s against the built-in signature database
/// and any additional user-provided signatures.
pub struct BehaviorClassifier {
    signatures: Vec<BehaviorSignature>,
}

impl BehaviorClassifier {
    /// Create a classifier loaded with the 30+ built-in signatures.
    #[must_use]
    pub const fn new() -> Self {
        // We need to store owned signatures but the statics are &'static, so just
        // reference them by creating a vec of refs via a wrapper type.
        // Actually we store them directly as we own them.
        Self {
            signatures: Vec::new(),
        }
    }

    /// Create a classifier with built-in signatures pre-loaded.
    #[must_use]
    pub const fn with_builtins() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Number of loaded signatures.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        BUILT_IN_SIGNATURES.len() + self.signatures.len()
    }

    /// Classify a list of events and produce a `BehaviorReport`.
    ///
    /// Events from all PIDs are merged into a single API call sequence.
    #[must_use]
    pub fn classify_events(&self, events: &[BehaviorEvent]) -> BehaviorReport {
        let calls: Vec<String> = events.iter().map(|e| e.api.clone()).collect();
        let unique_apis: Vec<String> = {
            let mut s: HashSet<&str> = HashSet::new();
            for c in &calls {
                s.insert(c);
            }
            let mut v: Vec<String> = s.iter().map(|&x| x.to_string()).collect();
            v.sort();
            v
        };

        let pids: Vec<u32> = {
            let mut s: HashSet<u32> = HashSet::new();
            for e in events {
                s.insert(e.pid);
            }
            let mut v: Vec<u32> = s.into_iter().collect();
            v.sort_unstable();
            v
        };

        let mut matches = Vec::new();

        // Check built-ins
        for sig in BUILT_IN_SIGNATURES {
            if sig.matches(&calls) {
                let matched_apis: Vec<String> = sig
                    .api_sequence
                    .iter()
                    .filter(|&&api| calls.iter().any(|c| c == api))
                    .map(|&api| api.to_string())
                    .collect();
                matches.push(BehaviorMatch {
                    sig_id: sig.id.to_string(),
                    description: sig.description.to_string(),
                    category: sig.category.clone(),
                    severity: sig.severity,
                    matched_apis,
                });
            }
        }

        // Check user-provided signatures
        for sig in &self.signatures {
            if sig.matches(&calls) {
                let matched_apis: Vec<String> = sig
                    .api_sequence
                    .iter()
                    .filter(|&&api| calls.iter().any(|c| c == api))
                    .map(|&api| api.to_string())
                    .collect();
                matches.push(BehaviorMatch {
                    sig_id: sig.id.to_string(),
                    description: sig.description.to_string(),
                    category: sig.category.clone(),
                    severity: sig.severity,
                    matched_apis,
                });
            }
        }

        // Deduplicate categories
        let mut cat_set: HashSet<String> = HashSet::new();
        let mut categories = Vec::new();
        for m in &matches {
            let k = m.category.to_string();
            if cat_set.insert(k) {
                categories.push(m.category.clone());
            }
        }

        // Compute overall risk score: max of all severities
        let risk_score: u8 = matches.iter().map(|m| m.severity).max().unwrap_or(0);

        BehaviorReport {
            pids,
            matches,
            risk_score,
            categories,
            event_count: events.len(),
            unique_apis,
        }
    }

    /// Classify events per-PID and return a map of pid → report.
    #[must_use]
    pub fn classify_per_pid(&self, events: &[BehaviorEvent]) -> HashMap<u32, BehaviorReport> {
        let mut by_pid: HashMap<u32, Vec<&BehaviorEvent>> = HashMap::new();
        for e in events {
            by_pid.entry(e.pid).or_default().push(e);
        }
        by_pid
            .into_iter()
            .map(|(pid, evs)| {
                let owned: Vec<BehaviorEvent> = evs.into_iter().cloned().collect();
                (pid, self.classify_events(&owned))
            })
            .collect()
    }

    /// Add a custom signature to the classifier.
    pub fn add_signature(&mut self, sig: BehaviorSignature) {
        self.signatures.push(sig);
    }

    /// Look up a built-in signature by ID.
    #[must_use]
    pub fn find_signature(id: &str) -> Option<&'static BehaviorSignature> {
        BUILT_IN_SIGNATURES.iter().find(|s| s.id == id)
    }
}

impl Default for BehaviorClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper trait ─────────────────────────────────────────────────────────────

/// Extension methods for `BehaviorReport`.
pub trait BehaviorReportExt {
    fn is_empty_or_benign(&self) -> bool;
}

impl BehaviorReportExt for BehaviorReport {
    fn is_empty_or_benign(&self) -> bool {
        self.match_count() == 0
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn events(apis: &[&str]) -> Vec<BehaviorEvent> {
        apis.iter()
            .enumerate()
            .map(|(i, &api)| BehaviorEvent::new(api, 1234).with_ts(i as u64 * 10))
            .collect()
    }

    #[test]
    fn test_builtin_count() {
        let c = BehaviorClassifier::with_builtins();
        assert!(c.signature_count() >= 30);
    }

    #[test]
    fn test_process_injection_detection() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
        let r = c.classify_events(&evs);
        assert!(
            r.has_category(&BehaviorCategory::Injection),
            "Expected Injection in {:?}",
            r.categories
        );
        assert!(r.is_high_risk(80));
    }

    #[test]
    fn test_debugger_detection() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["IsDebuggerPresent"]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::Evasion));
    }

    #[test]
    fn test_ransomware_pattern() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&[
            "CryptEncrypt",
            "FindFirstFileW",
            "FindNextFileW",
            "MoveFileExW",
        ]);
        let r = c.classify_events(&evs);
        assert!(
            r.has_category(&BehaviorCategory::Crypto)
                || r.has_category(&BehaviorCategory::FileSystem)
        );
    }

    #[test]
    fn test_persistence_pattern() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["RegOpenKeyExW", "RegSetValueExW"]);
        let r = c.classify_events(&evs);
        assert!(
            r.has_category(&BehaviorCategory::Persistence)
                || r.has_category(&BehaviorCategory::Registry)
        );
    }

    #[test]
    fn test_keylogger_detection() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["SetWindowsHookExW", "GetMessage"]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::Exfiltration));
    }

    #[test]
    fn test_empty_events() {
        let c = BehaviorClassifier::with_builtins();
        let r = c.classify_events(&[]);
        assert_eq!(r.match_count(), 0);
        assert_eq!(r.risk_score, 0);
        assert!(r.is_empty_or_benign());
    }

    #[test]
    fn test_credential_dump_pattern() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["OpenProcess", "ReadProcessMemory", "MiniDumpWriteDump"]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::Exfiltration));
        assert!(r.risk_score >= 90);
    }

    #[test]
    fn test_http_c2_pattern() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest"]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::C2));
    }

    #[test]
    fn test_process_hollowing() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&[
            "CreateProcessW",
            "NtUnmapViewOfSection",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "SetThreadContext",
            "ResumeThread",
        ]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::Process));
        assert!(r.risk_score >= 90);
    }

    #[test]
    fn test_screenshot_capture() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["GetDC", "CreateCompatibleDC", "BitBlt"]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::Exfiltration));
    }

    #[test]
    fn test_match_count_and_top_match() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "IsDebuggerPresent",
            "CryptEncrypt",
        ]);
        let r = c.classify_events(&evs);
        assert!(r.match_count() >= 3);
        let top = r.top_match().unwrap();
        assert!(top.severity >= 85);
    }

    #[test]
    fn test_per_pid_classification() {
        let c = BehaviorClassifier::with_builtins();
        let mut evs = events(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
        for _e in &mut evs { /* pid already 1234 */ }
        let mut evs2 = events(&["IsDebuggerPresent"]);
        for e in &mut evs2 {
            e.pid = 5678;
        }
        evs.extend(evs2);
        let map = c.classify_per_pid(&evs);
        assert!(map.contains_key(&1234));
        assert!(map.contains_key(&5678));
    }

    #[test]
    fn test_custom_signature() {
        let mut c = BehaviorClassifier::new();
        c.add_signature(BehaviorSignature {
            id: "custom_test",
            description: "Custom test signature",
            category: BehaviorCategory::Network,
            api_sequence: &["MyCustomApi"],
            mode: MatchMode::AnyPresent,
            severity: 50,
        });
        let evs = events(&["MyCustomApi", "SomeOtherApi"]);
        let r = c.classify_events(&evs);
        assert!(r.matches.iter().any(|m| m.sig_id == "custom_test"));
    }

    #[test]
    fn test_find_signature() {
        let sig = BehaviorClassifier::find_signature("process_injection");
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().severity, 95);
    }

    #[test]
    fn test_ordered_subsequence_not_matched_wrong_order() {
        let c = BehaviorClassifier::with_builtins();
        // Reverse the injection order — should NOT match ordered subsequence
        let evs = events(&["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"]);
        let r = c.classify_events(&evs);
        let injection_match = r.matches.iter().find(|m| m.sig_id == "process_injection");
        assert!(
            injection_match.is_none(),
            "Reversed order should not match ordered subsequence"
        );
    }

    #[test]
    fn test_report_display() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["IsDebuggerPresent"]);
        let r = c.classify_events(&evs);
        let s = format!("{r}");
        assert!(s.contains("risk="));
        assert!(s.contains("matches="));
    }

    #[test]
    fn test_behavior_category_display() {
        assert_eq!(BehaviorCategory::Injection.to_string(), "injection");
        assert_eq!(BehaviorCategory::C2.to_string(), "c2");
        assert_eq!(BehaviorCategory::Exfiltration.to_string(), "exfiltration");
    }

    #[test]
    fn test_service_installation() {
        let c = BehaviorClassifier::with_builtins();
        let evs = events(&["CreateServiceW", "StartServiceW"]);
        let r = c.classify_events(&evs);
        assert!(r.has_category(&BehaviorCategory::Persistence));
    }
}
