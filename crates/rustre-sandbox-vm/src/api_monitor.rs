//! Windows API monitoring layer for the sandbox VM.
//!
//! Tracks all Windows API calls made by a sandboxed process, builds an API call
//! graph, detects API call chains indicative of malware behavior (process injection,
//! persistence, C2 comms), simulates IAT hooking, and provides IAT analysis.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// ─── ApiCategory ─────────────────────────────────────────────────────────────

/// High-level category of a Windows API function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    /// Memory allocation and manipulation: `VirtualAlloc`, `HeapAlloc`, etc.
    Memory,
    /// Process and thread creation: `CreateProcess`, `CreateThread`, etc.
    Process,
    /// File system: `CreateFile`, `ReadFile`, `WriteFile`, `DeleteFile`, etc.
    FileSystem,
    /// Registry operations: `RegOpenKey`, `RegSetValue`, etc.
    Registry,
    /// Network: `WSASocket`, `connect`, `send`, `recv`, `WinHttpOpen`, etc.
    Network,
    /// Cryptography: `CryptEncrypt`, `BCryptHashData`, etc.
    Crypto,
    /// Code injection: `WriteProcessMemory`, `CreateRemoteThread`, etc.
    Injection,
    /// Anti-analysis: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, etc.
    AntiAnalysis,
    /// Persistence: `RegCreateKey` (Run keys), `CreateService`, `schtasks`, etc.
    Persistence,
    /// GUI and user interaction: `MessageBox`, `keybd_event`, etc.
    UserInterface,
    /// COM and OLE: `CoCreateInstance`, `IDispatch::Invoke`, etc.
    Com,
    /// Token and privilege manipulation: `OpenProcessToken`, `AdjustTokenPrivileges`.
    Token,
    /// Service control: `OpenSCManager`, `CreateService`, `StartService`.
    ServiceControl,
    /// Unknown / unclassified.
    Unknown,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Memory => "memory",
            Self::Process => "process",
            Self::FileSystem => "filesystem",
            Self::Registry => "registry",
            Self::Network => "network",
            Self::Crypto => "crypto",
            Self::Injection => "injection",
            Self::AntiAnalysis => "anti_analysis",
            Self::Persistence => "persistence",
            Self::UserInterface => "user_interface",
            Self::Com => "com",
            Self::Token => "token",
            Self::ServiceControl => "service_control",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ─── ApiModule ────────────────────────────────────────────────────────────────

/// The DLL module that exports a given Windows API function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiModule(pub String);

impl ApiModule {
    /// Canonical module names for common DLLs.
    pub const NTDLL: &'static str = "ntdll.dll";
    pub const KERNEL32: &'static str = "kernel32.dll";
    pub const KERNELBASE: &'static str = "kernelbase.dll";
    pub const USER32: &'static str = "user32.dll";
    pub const ADVAPI32: &'static str = "advapi32.dll";
    pub const WININET: &'static str = "wininet.dll";
    pub const WINHTTP: &'static str = "winhttp.dll";
    pub const WS2_32: &'static str = "ws2_32.dll";
    pub const SHELL32: &'static str = "shell32.dll";
    pub const OLE32: &'static str = "ole32.dll";
    pub const CRYPT32: &'static str = "crypt32.dll";
    pub const BCRYPT: &'static str = "bcrypt.dll";
    pub const SECUR32: &'static str = "secur32.dll";
}

impl fmt::Display for ApiModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── ApiCall ─────────────────────────────────────────────────────────────────

/// Execution context for a single API call (process/thread/timing).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ApiCallContext {
    /// Monotonic call index.
    pub index: u64,
    /// Milliseconds since sandbox start.
    pub ts_ms: u64,
    /// PID of the calling process.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
}

impl ApiCallContext {
    /// Construct a context record.
    #[must_use]
    pub const fn new(index: u64, ts_ms: u64, pid: u32, tid: u32) -> Self {
        Self { index, ts_ms, pid, tid }
    }
}

/// A single Windows API call captured by the monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    /// Monotonic call index.
    pub index: u64,
    /// Milliseconds since sandbox start.
    pub ts_ms: u64,
    /// PID of the calling process.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Module (DLL) from which the API is exported.
    pub module: String,
    /// Name of the API function.
    pub function: String,
    /// High-level category.
    pub category: ApiCategory,
    /// Simplified parameter descriptions.
    pub params: Vec<ApiParam>,
    /// Return value (HRESULT / BOOL / HANDLE, etc.) as a hex string.
    pub return_value: Option<String>,
    /// Whether this call was hooked/intercepted.
    pub hooked: bool,
    /// Optional annotation from the behavior analyzer.
    pub annotation: Option<String>,
    /// Call stack depth (approximate).
    pub call_depth: u32,
}

impl ApiCall {
    /// Create a new API call record.
    #[must_use]
    pub fn new(
        ctx: ApiCallContext,
        module: impl Into<String>,
        function: impl Into<String>,
        category: ApiCategory,
        params: Vec<ApiParam>,
    ) -> Self {
        Self {
            index: ctx.index,
            ts_ms: ctx.ts_ms,
            pid: ctx.pid,
            tid: ctx.tid,
            module: module.into(),
            function: function.into(),
            category,
            params,
            return_value: None,
            hooked: false,
            annotation: None,
            call_depth: 0,
        }
    }

    /// Set the return value.
    #[must_use]
    pub fn with_return(mut self, rv: impl Into<String>) -> Self {
        self.return_value = Some(rv.into());
        self
    }

    /// Annotate the call.
    pub fn annotate(&mut self, note: impl Into<String>) {
        self.annotation = Some(note.into());
    }

    /// Full qualified name: `module!function`.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}!{}", self.module, self.function)
    }
}

// ─── ApiParam ─────────────────────────────────────────────────────────────────

/// A simplified API parameter record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiParam {
    /// Parameter name.
    pub name: String,
    /// String representation of the value.
    pub value: String,
    /// Type hint for the parameter.
    pub type_hint: String,
}

impl ApiParam {
    /// Create a new parameter.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        type_hint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            type_hint: type_hint.into(),
        }
    }

    /// Create a HANDLE parameter.
    #[must_use]
    pub fn handle(name: impl Into<String>, value: u64) -> Self {
        Self::new(name, format!("0x{value:016X}"), "HANDLE")
    }

    /// Create a string parameter.
    #[must_use]
    pub fn string(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, value, "LPCWSTR")
    }

    /// Create a DWORD parameter.
    #[must_use]
    pub fn dword(name: impl Into<String>, value: u32) -> Self {
        Self::new(name, value.to_string(), "DWORD")
    }

    /// Create a pointer parameter.
    #[must_use]
    pub fn ptr(name: impl Into<String>, value: u64) -> Self {
        Self::new(name, format!("0x{value:016X}"), "LPVOID")
    }
}

// ─── ApiChain ─────────────────────────────────────────────────────────────────

/// A named sequence of API calls that together constitute a behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiChain {
    /// Descriptive name for the chain (e.g. "`process_injection_chain`").
    pub name: String,
    /// Ordered list of call indices that form the chain.
    pub call_indices: Vec<u64>,
    /// The inferred malware behavior.
    pub behavior: MalwareBehaviorPattern,
    /// Confidence score [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable description.
    pub description: String,
}

impl ApiChain {
    /// Create a new chain.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        call_indices: Vec<u64>,
        behavior: MalwareBehaviorPattern,
        confidence: f32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            call_indices,
            behavior,
            confidence,
            description: description.into(),
        }
    }

    /// Number of calls in this chain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.call_indices.len()
    }

    /// Returns true if the chain is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.call_indices.is_empty()
    }
}

// ─── MalwareBehaviorPattern ──────────────────────────────────────────────────

/// High-level malware behavior inferred from an API chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MalwareBehaviorPattern {
    /// Classic `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`.
    ClassicRemoteInjection,
    /// Process hollowing: `CreateProcess` + `NtUnmapViewOfSection` + `WriteProcessMemory`.
    ProcessHollowing,
    /// DLL injection via `LoadLibrary` path write.
    DllInjection,
    /// APC injection via `QueueUserAPC`.
    ApcInjection,
    /// Registry persistence (Run key or `RunOnce`).
    RegistryPersistence,
    /// Service-based persistence.
    ServicePersistence,
    /// Scheduled task persistence.
    ScheduledTaskPersistence,
    /// C2 communication via raw sockets.
    C2RawSocket,
    /// C2 communication via HTTP/HTTPS.
    C2Http,
    /// Credential dumping (LSASS read).
    CredentialDumping,
    /// Ransomware encryption loop.
    RansomwareEncryption,
    /// Shadow copy deletion.
    ShadowCopyDeletion,
    /// Keylogging via `SetWindowsHookEx`.
    Keylogging,
    /// Anti-debug technique.
    AntiDebug,
    /// Anti-sandbox timing check.
    AntiSandbox,
    /// Token impersonation / privilege escalation.
    TokenImpersonation,
    /// UAC bypass.
    UacBypass,
    /// Generic suspicious behavior.
    SuspiciousBehavior(String),
}

impl fmt::Display for MalwareBehaviorPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassicRemoteInjection => write!(f, "classic_remote_injection"),
            Self::ProcessHollowing => write!(f, "process_hollowing"),
            Self::DllInjection => write!(f, "dll_injection"),
            Self::ApcInjection => write!(f, "apc_injection"),
            Self::RegistryPersistence => write!(f, "registry_persistence"),
            Self::ServicePersistence => write!(f, "service_persistence"),
            Self::ScheduledTaskPersistence => write!(f, "scheduled_task_persistence"),
            Self::C2RawSocket => write!(f, "c2_raw_socket"),
            Self::C2Http => write!(f, "c2_http"),
            Self::CredentialDumping => write!(f, "credential_dumping"),
            Self::RansomwareEncryption => write!(f, "ransomware_encryption"),
            Self::ShadowCopyDeletion => write!(f, "shadow_copy_deletion"),
            Self::Keylogging => write!(f, "keylogging"),
            Self::AntiDebug => write!(f, "anti_debug"),
            Self::AntiSandbox => write!(f, "anti_sandbox"),
            Self::TokenImpersonation => write!(f, "token_impersonation"),
            Self::UacBypass => write!(f, "uac_bypass"),
            Self::SuspiciousBehavior(s) => write!(f, "suspicious:{s}"),
        }
    }
}

// ─── InjectionPattern ─────────────────────────────────────────────────────────

/// Specific injection technique detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionPattern {
    /// Technique name.
    pub technique: String,
    /// Target PID (if known).
    pub target_pid: Option<u32>,
    /// Payload size in bytes (if known).
    pub payload_size: Option<usize>,
    /// The API chain that revealed this pattern.
    pub chain_name: String,
    /// Confidence.
    pub confidence: f32,
}

impl InjectionPattern {
    /// Create a new injection pattern record.
    #[must_use]
    pub fn new(technique: impl Into<String>, chain_name: impl Into<String>, confidence: f32) -> Self {
        Self {
            technique: technique.into(),
            target_pid: None,
            payload_size: None,
            chain_name: chain_name.into(),
            confidence,
        }
    }
}

// ─── IatEntry ─────────────────────────────────────────────────────────────────

/// A single entry in the Import Address Table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatEntry {
    /// Module name that owns this entry.
    pub module: String,
    /// Function name.
    pub function: String,
    /// Virtual address of the entry in the IAT.
    pub iat_address: u64,
    /// Resolved function address.
    pub resolved_address: u64,
    /// Whether this entry has been hooked (resolved != expected).
    pub hooked: bool,
    /// If hooked, the address that the hook redirects to.
    pub hook_target: Option<u64>,
}

impl IatEntry {
    /// Returns true if the IAT entry points to an unexpected location.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.hooked
    }
}

// ─── ApiCallGraph ─────────────────────────────────────────────────────────────

/// A directed graph of API call relationships.
///
/// Nodes are API function names; directed edges represent a caller→callee
/// relationship with a call count weight.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiCallGraph {
    /// Adjacency list: caller → (callee, weight).
    edges: HashMap<String, Vec<(String, u64)>>,
    /// Total number of unique nodes.
    node_count: usize,
}

impl ApiCallGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or increment an edge between two function names.
    pub fn add_edge(&mut self, caller: impl Into<String>, callee: impl Into<String>) {
        let caller = caller.into();
        let callee = callee.into();
        let edges = self.edges.entry(caller).or_default();
        if let Some(existing) = edges.iter_mut().find(|(edge_name, _)| *edge_name == callee) {
            existing.1 += 1;
        } else {
            edges.push((callee, 1));
            self.node_count += 1;
        }
    }

    /// Get all callee edges for a given caller.
    #[must_use]
    pub fn callees(&self, caller: &str) -> &[(String, u64)] {
        self.edges.get(caller).map_or(&[], Vec::as_slice)
    }

    /// Return all nodes (unique function names) in the graph.
    #[must_use]
    pub fn nodes(&self) -> Vec<String> {
        let mut nodes: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (caller, callees) in &self.edges {
            nodes.insert(caller.clone());
            for (callee, _) in callees {
                nodes.insert(callee.clone());
            }
        }
        nodes.into_iter().collect()
    }

    /// Return the top-N most called functions (by edge weight sum).
    #[must_use]
    pub fn top_called(&self, n: usize) -> Vec<(String, u64)> {
        let mut totals: HashMap<String, u64> = HashMap::new();
        for callees in self.edges.values() {
            for (callee, count) in callees {
                *totals.entry(callee.clone()).or_insert(0) += count;
            }
        }
        let mut sorted: Vec<(String, u64)> = totals.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Number of unique caller nodes.
    #[must_use]
    pub fn caller_count(&self) -> usize {
        self.edges.len()
    }

    /// Total edge count (including weights).
    #[must_use]
    pub fn total_edges(&self) -> u64 {
        self.edges.values().flat_map(|v| v.iter().map(|(_, w)| *w)).sum()
    }
}

// ─── ApiFunctionDb ────────────────────────────────────────────────────────────

/// Database mapping function names to their categories.
pub struct ApiFunctionDb {
    db: HashMap<String, (String, ApiCategory)>,
}

impl ApiFunctionDb {
    /// Build a database of well-known Windows API functions.
    #[must_use]
    pub fn windows() -> Self {
        let mut db: HashMap<String, (String, ApiCategory)> = HashMap::new();
        let entries: &[(&str, &str, ApiCategory)] = &[
            // Memory
            ("VirtualAlloc", ApiModule::KERNEL32, ApiCategory::Memory),
            ("VirtualAllocEx", ApiModule::KERNEL32, ApiCategory::Memory),
            ("VirtualFree", ApiModule::KERNEL32, ApiCategory::Memory),
            ("VirtualProtect", ApiModule::KERNEL32, ApiCategory::Memory),
            ("VirtualProtectEx", ApiModule::KERNEL32, ApiCategory::Injection),
            ("HeapAlloc", ApiModule::KERNEL32, ApiCategory::Memory),
            ("HeapCreate", ApiModule::KERNEL32, ApiCategory::Memory),
            ("MapViewOfFile", ApiModule::KERNEL32, ApiCategory::Memory),
            ("NtAllocateVirtualMemory", ApiModule::NTDLL, ApiCategory::Memory),
            ("NtProtectVirtualMemory", ApiModule::NTDLL, ApiCategory::Memory),
            // Process
            ("CreateProcessA", ApiModule::KERNEL32, ApiCategory::Process),
            ("CreateProcessW", ApiModule::KERNEL32, ApiCategory::Process),
            ("OpenProcess", ApiModule::KERNEL32, ApiCategory::Process),
            ("TerminateProcess", ApiModule::KERNEL32, ApiCategory::Process),
            ("CreateThread", ApiModule::KERNEL32, ApiCategory::Process),
            ("CreateRemoteThread", ApiModule::KERNEL32, ApiCategory::Injection),
            ("CreateRemoteThreadEx", ApiModule::KERNEL32, ApiCategory::Injection),
            ("NtCreateThreadEx", ApiModule::NTDLL, ApiCategory::Injection),
            ("ResumeThread", ApiModule::KERNEL32, ApiCategory::Process),
            ("SuspendThread", ApiModule::KERNEL32, ApiCategory::Process),
            ("QueueUserAPC", ApiModule::KERNEL32, ApiCategory::Injection),
            // Injection
            ("WriteProcessMemory", ApiModule::KERNEL32, ApiCategory::Injection),
            ("ReadProcessMemory", ApiModule::KERNEL32, ApiCategory::Injection),
            ("NtWriteVirtualMemory", ApiModule::NTDLL, ApiCategory::Injection),
            ("NtReadVirtualMemory", ApiModule::NTDLL, ApiCategory::Injection),
            ("NtUnmapViewOfSection", ApiModule::NTDLL, ApiCategory::Injection),
            ("SetThreadContext", ApiModule::KERNEL32, ApiCategory::Injection),
            ("GetThreadContext", ApiModule::KERNEL32, ApiCategory::Injection),
            ("LoadLibraryA", ApiModule::KERNEL32, ApiCategory::Injection),
            ("LoadLibraryW", ApiModule::KERNEL32, ApiCategory::Injection),
            ("LoadLibraryExW", ApiModule::KERNEL32, ApiCategory::Injection),
            // File system
            ("CreateFileA", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("CreateFileW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("ReadFile", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("WriteFile", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("DeleteFileA", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("DeleteFileW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("MoveFileW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("FindFirstFileW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("FindNextFileW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("GetTempPathW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            ("GetSystemDirectoryW", ApiModule::KERNEL32, ApiCategory::FileSystem),
            // Registry
            ("RegOpenKeyExA", ApiModule::ADVAPI32, ApiCategory::Registry),
            ("RegOpenKeyExW", ApiModule::ADVAPI32, ApiCategory::Registry),
            ("RegSetValueExA", ApiModule::ADVAPI32, ApiCategory::Registry),
            ("RegSetValueExW", ApiModule::ADVAPI32, ApiCategory::Persistence),
            ("RegCreateKeyExW", ApiModule::ADVAPI32, ApiCategory::Persistence),
            ("RegDeleteValueW", ApiModule::ADVAPI32, ApiCategory::Registry),
            ("RegQueryValueExW", ApiModule::ADVAPI32, ApiCategory::Registry),
            // Network
            ("WSAStartup", ApiModule::WS2_32, ApiCategory::Network),
            ("socket", ApiModule::WS2_32, ApiCategory::Network),
            ("connect", ApiModule::WS2_32, ApiCategory::Network),
            ("send", ApiModule::WS2_32, ApiCategory::Network),
            ("recv", ApiModule::WS2_32, ApiCategory::Network),
            ("closesocket", ApiModule::WS2_32, ApiCategory::Network),
            ("gethostbyname", ApiModule::WS2_32, ApiCategory::Network),
            ("getaddrinfo", ApiModule::WS2_32, ApiCategory::Network),
            ("WinHttpOpen", ApiModule::WINHTTP, ApiCategory::Network),
            ("WinHttpConnect", ApiModule::WINHTTP, ApiCategory::Network),
            ("WinHttpOpenRequest", ApiModule::WINHTTP, ApiCategory::Network),
            ("WinHttpSendRequest", ApiModule::WINHTTP, ApiCategory::Network),
            ("InternetOpenA", ApiModule::WININET, ApiCategory::Network),
            ("InternetConnectA", ApiModule::WININET, ApiCategory::Network),
            ("HttpOpenRequestA", ApiModule::WININET, ApiCategory::Network),
            ("HttpSendRequestA", ApiModule::WININET, ApiCategory::Network),
            // Anti-debug
            ("IsDebuggerPresent", ApiModule::KERNEL32, ApiCategory::AntiAnalysis),
            ("CheckRemoteDebuggerPresent", ApiModule::KERNEL32, ApiCategory::AntiAnalysis),
            ("NtQueryInformationProcess", ApiModule::NTDLL, ApiCategory::AntiAnalysis),
            ("GetTickCount", ApiModule::KERNEL32, ApiCategory::AntiAnalysis),
            ("GetTickCount64", ApiModule::KERNEL32, ApiCategory::AntiAnalysis),
            ("QueryPerformanceCounter", ApiModule::KERNEL32, ApiCategory::AntiAnalysis),
            // Crypto
            ("CryptEncrypt", ApiModule::ADVAPI32, ApiCategory::Crypto),
            ("CryptDecrypt", ApiModule::ADVAPI32, ApiCategory::Crypto),
            ("CryptGenKey", ApiModule::ADVAPI32, ApiCategory::Crypto),
            ("BCryptEncrypt", ApiModule::BCRYPT, ApiCategory::Crypto),
            ("BCryptHashData", ApiModule::BCRYPT, ApiCategory::Crypto),
            ("CryptAcquireContextW", ApiModule::ADVAPI32, ApiCategory::Crypto),
            // Service control
            ("OpenSCManagerA", ApiModule::ADVAPI32, ApiCategory::ServiceControl),
            ("OpenSCManagerW", ApiModule::ADVAPI32, ApiCategory::ServiceControl),
            ("CreateServiceA", ApiModule::ADVAPI32, ApiCategory::Persistence),
            ("CreateServiceW", ApiModule::ADVAPI32, ApiCategory::Persistence),
            ("StartServiceA", ApiModule::ADVAPI32, ApiCategory::ServiceControl),
            // Token
            ("OpenProcessToken", ApiModule::ADVAPI32, ApiCategory::Token),
            ("AdjustTokenPrivileges", ApiModule::ADVAPI32, ApiCategory::Token),
            ("DuplicateTokenEx", ApiModule::ADVAPI32, ApiCategory::Token),
            ("ImpersonateLoggedOnUser", ApiModule::ADVAPI32, ApiCategory::Token),
            // UI / Keylogging
            ("SetWindowsHookExA", ApiModule::USER32, ApiCategory::UserInterface),
            ("SetWindowsHookExW", ApiModule::USER32, ApiCategory::UserInterface),
            ("GetAsyncKeyState", ApiModule::USER32, ApiCategory::UserInterface),
            ("GetForegroundWindow", ApiModule::USER32, ApiCategory::UserInterface),
            // Shadow copy / ransomware
            ("ShellExecuteA", ApiModule::SHELL32, ApiCategory::Process),
            ("ShellExecuteW", ApiModule::SHELL32, ApiCategory::Process),
        ];
        for (name, module, cat) in entries {
            db.insert(name.to_string(), (module.to_string(), cat.clone()));
        }
        Self { db }
    }

    /// Look up a function name, returning (module, category).
    #[must_use]
    pub fn lookup(&self, function: &str) -> (String, ApiCategory) {
        self.db
            .get(function)
            .cloned()
            .unwrap_or_else(|| ("unknown.dll".to_string(), ApiCategory::Unknown))
    }
}

// ─── BehaviorAnalyzer ─────────────────────────────────────────────────────────

/// Analyzes sequences of API calls to detect malware behavior chains.
pub struct BehaviorAnalyzer {
    window: Vec<ApiCall>,
    window_size: usize,
}

impl BehaviorAnalyzer {
    /// Create a new analyzer with a 512-call window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: Vec::with_capacity(512),
            window_size: 512,
        }
    }

    /// Push a new call and return any detected chains.
    #[must_use]
    pub fn process(&mut self, call: &ApiCall) -> Vec<ApiChain> {
        self.window.push(call.clone());
        if self.window.len() > self.window_size {
            self.window.remove(0);
        }
        let mut chains = Vec::new();
        chains.extend(self.detect_classic_injection());
        chains.extend(self.detect_registry_persistence());
        chains.extend(self.detect_anti_debug());
        chains.extend(self.detect_c2_http());
        chains.extend(self.detect_keylogging());
        chains.extend(self.detect_process_hollowing());
        chains.extend(self.detect_token_impersonation());
        chains
    }

    /// Return `(window_slot, call_index)` for every call in the current
    /// window whose function name appears in `names`. Used by the chain
    /// detectors to attach precise indices to reported findings.
    #[must_use] 
    pub fn function_indices(&self, names: &[&str]) -> Vec<(usize, u64)> {
        self.window
            .iter()
            .enumerate()
            .filter(|(_, c)| names.iter().any(|n| *n == c.function))
            .map(|(i, c)| (i, c.index))
            .collect()
    }

    fn detect_classic_injection(&self) -> Vec<ApiChain> {
        let has_open = self.window.iter().any(|c| c.function == "OpenProcess");
        let has_write = self.window.iter().any(|c| c.function == "WriteProcessMemory");
        let has_alloc = self.window.iter().any(|c| c.function == "VirtualAllocEx");
        let has_thread = self.window.iter().any(|c| {
            c.function == "CreateRemoteThread" || c.function == "NtCreateThreadEx"
        });
        if has_open && has_write && has_alloc && has_thread {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| {
                    matches!(
                        c.function.as_str(),
                        "OpenProcess" | "WriteProcessMemory" | "VirtualAllocEx"
                            | "CreateRemoteThread" | "NtCreateThreadEx"
                    )
                })
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "classic_remote_injection",
                indices,
                MalwareBehaviorPattern::ClassicRemoteInjection,
                0.92,
                "OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
            )];
        }
        vec![]
    }

    fn detect_registry_persistence(&self) -> Vec<ApiChain> {
        let has_set = self.window.iter().any(|c| {
            c.function == "RegSetValueExW" || c.function == "RegSetValueExA"
        });
        let has_create = self.window.iter().any(|c| c.function == "RegCreateKeyExW");
        if has_create && has_set {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| {
                    matches!(
                        c.function.as_str(),
                        "RegCreateKeyExW" | "RegSetValueExW" | "RegSetValueExA"
                    )
                })
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "registry_persistence",
                indices,
                MalwareBehaviorPattern::RegistryPersistence,
                0.85,
                "RegCreateKeyExW + RegSetValueExW — possible Run key persistence",
            )];
        }
        vec![]
    }

    fn detect_anti_debug(&self) -> Vec<ApiChain> {
        let count = self.window.iter().filter(|c| c.category == ApiCategory::AntiAnalysis).count();
        if count >= 2 {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| c.category == ApiCategory::AntiAnalysis)
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "anti_debug_chain",
                indices,
                MalwareBehaviorPattern::AntiDebug,
                0.80,
                format!("{count} anti-debug API calls detected"),
            )];
        }
        vec![]
    }

    fn detect_c2_http(&self) -> Vec<ApiChain> {
        let has_open = self.window.iter().any(|c| {
            c.function == "WinHttpOpen" || c.function == "InternetOpenA"
        });
        let has_send = self.window.iter().any(|c| {
            c.function == "WinHttpSendRequest" || c.function == "HttpSendRequestA"
        });
        if has_open && has_send {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| {
                    matches!(
                        c.function.as_str(),
                        "WinHttpOpen" | "WinHttpConnect" | "WinHttpOpenRequest"
                            | "WinHttpSendRequest" | "InternetOpenA" | "HttpSendRequestA"
                    )
                })
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "c2_http_chain",
                indices,
                MalwareBehaviorPattern::C2Http,
                0.78,
                "HTTP API chain suggesting C2 communication",
            )];
        }
        vec![]
    }

    fn detect_keylogging(&self) -> Vec<ApiChain> {
        let hook = self.window.iter().any(|c| {
            c.function == "SetWindowsHookExA" || c.function == "SetWindowsHookExW"
        });
        let getkey = self.window.iter().any(|c| c.function == "GetAsyncKeyState");
        if hook || getkey {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| {
                    matches!(
                        c.function.as_str(),
                        "SetWindowsHookExA" | "SetWindowsHookExW" | "GetAsyncKeyState"
                    )
                })
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "keylogging_chain",
                indices,
                MalwareBehaviorPattern::Keylogging,
                0.88,
                "Keyboard hook or GetAsyncKeyState — possible keylogger",
            )];
        }
        vec![]
    }

    fn detect_process_hollowing(&self) -> Vec<ApiChain> {
        let has_create = self.window.iter().any(|c| c.function.starts_with("CreateProcess"));
        let has_unmap = self.window.iter().any(|c| c.function == "NtUnmapViewOfSection");
        let has_write = self.window.iter().any(|c| c.function == "WriteProcessMemory");
        if has_create && has_unmap && has_write {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| {
                    c.function.starts_with("CreateProcess")
                        || c.function == "NtUnmapViewOfSection"
                        || c.function == "WriteProcessMemory"
                        || c.function == "ResumeThread"
                })
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "process_hollowing",
                indices,
                MalwareBehaviorPattern::ProcessHollowing,
                0.90,
                "CreateProcess + NtUnmapViewOfSection + WriteProcessMemory — process hollowing",
            )];
        }
        vec![]
    }

    fn detect_token_impersonation(&self) -> Vec<ApiChain> {
        let has_open = self.window.iter().any(|c| c.function == "OpenProcessToken");
        let has_impersonate = self.window.iter().any(|c| {
            c.function == "ImpersonateLoggedOnUser" || c.function == "DuplicateTokenEx"
        });
        if has_open && has_impersonate {
            let indices: Vec<u64> = self
                .window
                .iter()
                .filter(|c| {
                    matches!(
                        c.function.as_str(),
                        "OpenProcessToken" | "AdjustTokenPrivileges"
                            | "DuplicateTokenEx" | "ImpersonateLoggedOnUser"
                    )
                })
                .map(|c| c.index)
                .collect();
            return vec![ApiChain::new(
                "token_impersonation",
                indices,
                MalwareBehaviorPattern::TokenImpersonation,
                0.87,
                "Token manipulation sequence detected",
            )];
        }
        vec![]
    }
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ApiMonitor ───────────────────────────────────────────────────────────────

/// The main Windows API monitoring subsystem.
pub struct ApiMonitor {
    /// Function database for category lookup.
    db: ApiFunctionDb,
    /// All recorded API calls.
    call_log: Mutex<Vec<ApiCall>>,
    /// Detected behavior chains.
    chains: Mutex<Vec<ApiChain>>,
    /// IAT entries.
    iat: Mutex<Vec<IatEntry>>,
    /// Behavioral analyzer (stateful).
    analyzer: Mutex<BehaviorAnalyzer>,
    /// API call graph.
    graph: Mutex<ApiCallGraph>,
    /// Monotonic call counter.
    counter: AtomicU64,
}

impl ApiMonitor {
    /// Create a new API monitor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: ApiFunctionDb::windows(),
            call_log: Mutex::new(Vec::new()),
            chains: Mutex::new(Vec::new()),
            iat: Mutex::new(Vec::new()),
            analyzer: Mutex::new(BehaviorAnalyzer::new()),
            graph: Mutex::new(ApiCallGraph::new()),
            counter: AtomicU64::new(0),
        }
    }

    /// Record an API call by function name.
    ///
    /// Automatically looks up the module and category.
    pub fn record(
        &self,
        ts_ms: u64,
        pid: u32,
        tid: u32,
        function: impl Into<String>,
        params: Vec<ApiParam>,
    ) -> u64 {
        let function = function.into();
        let (module, category) = self.db.lookup(&function);
        let index = self.counter.fetch_add(1, Ordering::Relaxed);
        let ctx = ApiCallContext::new(index, ts_ms, pid, tid);
        let call = ApiCall::new(ctx, module, function.clone(), category, params);

        // Update graph: record a self-edge to track call counts.
        self.graph.lock().add_edge(&function, &function);

        // Run behavioral analysis.
        let new_chains = self.analyzer.lock().process(&call);
        if !new_chains.is_empty() {
            self.chains.lock().extend(new_chains);
        }

        self.call_log.lock().push(call);
        index
    }

    /// Register an IAT entry.
    pub fn register_iat_entry(&self, entry: IatEntry) {
        self.iat.lock().push(entry);
    }

    /// Scan the IAT for hooked entries.
    #[must_use]
    pub fn hooked_iat_entries(&self) -> Vec<IatEntry> {
        self.iat.lock().iter().filter(|e| e.hooked).cloned().collect()
    }

    /// Return a snapshot of all calls.
    #[must_use]
    pub fn calls(&self) -> Vec<ApiCall> {
        self.call_log.lock().clone()
    }

    /// Return all detected behavior chains.
    #[must_use]
    pub fn chains(&self) -> Vec<ApiChain> {
        self.chains.lock().clone()
    }

    /// Return a clone of the current API call graph.
    #[must_use]
    pub fn graph(&self) -> ApiCallGraph {
        self.graph.lock().clone()
    }

    /// Count calls per category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<String, u64> {
        let mut m: HashMap<String, u64> = HashMap::new();
        for c in self.call_log.lock().iter() {
            *m.entry(c.category.to_string()).or_insert(0) += 1;
        }
        m
    }

    /// Total calls recorded.
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Reset all logs.
    pub fn reset(&self) {
        self.call_log.lock().clear();
        self.chains.lock().clear();
        self.iat.lock().clear();
        *self.analyzer.lock() = BehaviorAnalyzer::new();
        *self.graph.lock() = ApiCallGraph::new();
        self.counter.store(0, Ordering::Relaxed);
    }
}

impl Default for ApiMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared API monitor.
pub type SharedApiMonitor = Arc<ApiMonitor>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_count() {
        let monitor = ApiMonitor::new();
        monitor.record(0, 1, 1, "CreateFileW", vec![]);
        monitor.record(1, 1, 1, "WriteFile", vec![]);
        assert_eq!(monitor.total_calls(), 2);
    }

    #[test]
    fn test_category_lookup() {
        let db = ApiFunctionDb::windows();
        let (module, cat) = db.lookup("IsDebuggerPresent");
        assert_eq!(cat, ApiCategory::AntiAnalysis);
        assert!(module.contains("kernel32"));
    }

    #[test]
    fn test_injection_chain_detection() {
        let monitor = ApiMonitor::new();
        for func in &["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] {
            monitor.record(0, 1, 1, *func, vec![]);
        }
        let chains = monitor.chains();
        assert!(chains.iter().any(|c| c.behavior == MalwareBehaviorPattern::ClassicRemoteInjection));
    }

    #[test]
    fn test_api_call_graph_edges() {
        let mut graph = ApiCallGraph::new();
        graph.add_edge("A", "B");
        graph.add_edge("A", "B");
        graph.add_edge("A", "C");
        assert_eq!(graph.callees("A").len(), 2);
    }
}
