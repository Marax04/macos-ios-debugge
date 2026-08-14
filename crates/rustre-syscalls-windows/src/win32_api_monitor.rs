//! Win32 API call recorder and categorizer.
//!
//! **Layer**: analytics / categorization on top of a trace stream.
//!
//! This module focuses on *what* was called and assigns it an [`ApiCategory`]
//! (`Memory`, `FileIo`, `Crypto`, …) using a static database plus heuristics.
//! It is not concerned with hook strategy or blocking.
//!
//! Related modules and how they differ:
//! - [`crate::api_monitor`] — policy layer: *rule-based* IAT/EAT/inline hook
//!   management with block/allow decisions.  Uses raw `u64` arg values and is
//!   arch-aware via [`crate::WinArch`].
//! - [`crate::api_monitor_hooks`] — low-level trampoline registry: manages
//!   actual hook entries keyed by virtual address, with typed [`ArgValue`]
//!   descriptors and calling-convention metadata.
//! - This module — sits between the two: it receives already-decoded calls and
//!   enriches them with category/suspicion tags for offline analysis.

use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

// ─── ApiCategory ─────────────────────────────────────────────────────────────

/// Broad functional category of a Win32 API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ApiCategory {
    /// Memory allocation, deallocation, and virtual memory.
    Memory,
    /// File I/O: `CreateFile`, `ReadFile`, `WriteFile`, etc.
    FileIo,
    /// Registry: `RegOpenKey`, `RegQueryValue`, etc.
    Registry,
    /// Process and thread management.
    ProcessThread,
    /// Network: `socket`, `connect`, `send`, `recv`, `WinHTTP`, `WinInet`.
    Network,
    /// Synchronisation: `CreateEvent`, `WaitForSingleObject`, etc.
    Synchronisation,
    /// Crypto: `CryptEncrypt`, `CryptDecrypt`, `BCrypt*`.
    Crypto,
    /// String and locale operations.
    StringLocale,
    /// UI / Window management (mostly irrelevant for RE, but tracked).
    Ui,
    /// Security: `OpenProcessToken`, `AdjustTokenPrivileges`, etc.
    Security,
    /// COM / OLE operations.
    Com,
    /// Service control (`SCM`, `CreateService`, etc.).
    ServiceControl,
    /// Dynamic code loading: `LoadLibrary`, `GetProcAddress`, etc.
    DynLoad,
    /// Debug: `IsDebuggerPresent`, `OutputDebugString`, etc.
    Debug,
    /// Anti-analysis / anti-debug primitives.
    AntiAnalysis,
    /// Miscellaneous / uncategorised.
    Misc,
}

impl ApiCategory {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::FileIo => "file_io",
            Self::Registry => "registry",
            Self::ProcessThread => "process_thread",
            Self::Network => "network",
            Self::Synchronisation => "synchronisation",
            Self::Crypto => "crypto",
            Self::StringLocale => "string_locale",
            Self::Ui => "ui",
            Self::Security => "security",
            Self::Com => "com",
            Self::ServiceControl => "service_control",
            Self::DynLoad => "dyn_load",
            Self::Debug => "debug",
            Self::AntiAnalysis => "anti_analysis",
            Self::Misc => "misc",
        }
    }

    /// Return `true` when this category is suspicious from a security analysis perspective.
    #[must_use]
    pub const fn is_suspicious(self) -> bool {
        matches!(
            self,
            Self::AntiAnalysis | Self::DynLoad | Self::Crypto | Self::Network | Self::Security
        )
    }
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── Win32Call ────────────────────────────────────────────────────────────────

/// A single captured Win32 API call.
#[derive(Debug, Clone)]
pub struct Win32Call {
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Calling instruction address.
    pub caller_addr: u64,
    /// DLL name (e.g. `kernel32.dll`).
    pub dll: String,
    /// Function name (e.g. `CreateFileW`).
    pub function: String,
    /// Category of the call.
    pub category: ApiCategory,
    /// Arguments as hex strings (up to 6).
    pub args: Vec<u64>,
    /// Return value.
    pub return_value: Option<u64>,
    /// Wall-clock timestamp relative to the monitor start.
    pub timestamp_us: u64,
    /// Whether this call was flagged as suspicious.
    pub suspicious: bool,
    /// Optional analyst note.
    pub note: Option<String>,
}

impl Win32Call {
    /// Return the fully qualified name `dll!function`.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        format!("{}!{}", self.dll, self.function)
    }

    /// Return a brief one-line description.
    #[must_use]
    pub fn summary(&self) -> String {
        let ret = self.return_value.map_or_else(String::new, |v| format!(" -> {v:#x}"));
        let args: Vec<String> = self.args.iter().map(|a| format!("{a:#x}")).collect();
        format!(
            "[{:>6}] {:#010x} {}({}){}",
            self.seq,
            self.caller_addr,
            self.qualified_name(),
            args.join(", "),
            ret
        )
    }
}

impl fmt::Display for Win32Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── ApiFilter ────────────────────────────────────────────────────────────────

/// Configurable filter for which calls to record.
#[derive(Debug, Clone, Default)]
pub struct ApiFilter {
    /// Only record calls in these categories. Empty = record all.
    pub include_categories: Vec<ApiCategory>,
    /// Exclude calls from these categories.
    pub exclude_categories: Vec<ApiCategory>,
    /// Only record calls to these DLLs (case-insensitive prefix match). Empty = all.
    pub include_dlls: Vec<String>,
    /// Exclude calls to these DLLs.
    pub exclude_dlls: Vec<String>,
    /// Only record calls from addresses in this range (both 0 = no restriction).
    pub caller_range: (u64, u64),
    /// Only record calls whose function name contains this substring.
    pub function_name_contains: Option<String>,
}

impl ApiFilter {
    /// Create a filter that passes everything.
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Create a filter that records only the given categories.
    #[must_use]
    pub fn for_categories(cats: Vec<ApiCategory>) -> Self {
        Self {
            include_categories: cats,
            ..Self::default()
        }
    }

    /// Return `true` when the call should be recorded.
    #[must_use]
    pub fn matches(&self, call: &Win32Call) -> bool {
        // Category exclusion
        if self.exclude_categories.contains(&call.category) {
            return false;
        }
        // Category inclusion (empty = all)
        if !self.include_categories.is_empty()
            && !self.include_categories.contains(&call.category)
        {
            return false;
        }
        // DLL exclusion
        let dll_lc = call.dll.to_ascii_lowercase();
        if self
            .exclude_dlls
            .iter()
            .any(|d| dll_lc.contains(&d.to_ascii_lowercase()))
        {
            return false;
        }
        // DLL inclusion
        if !self.include_dlls.is_empty()
            && !self
                .include_dlls
                .iter()
                .any(|d| dll_lc.contains(&d.to_ascii_lowercase()))
        {
            return false;
        }
        // Caller range
        let (lo, hi) = self.caller_range;
        if (lo != 0 || hi != 0) && (call.caller_addr < lo || call.caller_addr > hi) {
            return false;
        }
        // Function name substring
        if self.function_name_contains.as_ref().is_some_and(|sub| {
            !call.function.to_ascii_lowercase().contains(&sub.to_ascii_lowercase())
        }) {
            return false;
        }
        true
    }
}

// ─── ApiDatabase ─────────────────────────────────────────────────────────────

/// Static database mapping `dll!function` to [`ApiCategory`].
struct ApiDatabase {
    entries: HashMap<String, ApiCategory>,
}

impl ApiDatabase {
    fn new() -> Self {
        let mut db = Self {
            entries: HashMap::new(),
        };
        db.populate();
        db
    }

    fn insert(&mut self, dll: &str, func: &str, cat: ApiCategory) {
        let key = format!("{}!{}", dll.to_ascii_lowercase(), func.to_ascii_lowercase());
        self.entries.insert(key, cat);
    }

    fn categorize(&self, dll: &str, func: &str) -> ApiCategory {
        let key = format!(
            "{}!{}",
            dll.to_ascii_lowercase(),
            func.to_ascii_lowercase()
        );
        if let Some(&cat) = self.entries.get(&key) {
            return cat;
        }
        // Heuristic by function name prefix
        Self::heuristic_category(func)
    }

    fn heuristic_category(func: &str) -> ApiCategory {
        let f = func.to_ascii_lowercase();
        if f.starts_with("virtual")
            || f.starts_with("heap")
            || f.starts_with("localalloc")
            || f.starts_with("localfree")
            || f.starts_with("globalalloc")
            || f.starts_with("globalfree")
        {
            return ApiCategory::Memory;
        }
        if f.starts_with("createfile")
            || f.starts_with("readfile")
            || f.starts_with("writefile")
            || f.starts_with("deletefile")
            || f.starts_with("setfile")
            || f.starts_with("getfile")
            || f.starts_with("findfile")
            || f.starts_with("closefile")
        {
            return ApiCategory::FileIo;
        }
        if f.starts_with("reg") {
            return ApiCategory::Registry;
        }
        if f.starts_with("createprocess")
            || f.starts_with("createthread")
            || f.starts_with("openprocess")
            || f.starts_with("openthread")
            || f.starts_with("terminateprocess")
            || f.starts_with("exitprocess")
        {
            return ApiCategory::ProcessThread;
        }
        if f.starts_with("socket")
            || f.starts_with("connect")
            || f.starts_with("send")
            || f.starts_with("recv")
            || f.starts_with("bind")
            || f.starts_with("listen")
            || f.starts_with("accept")
            || f.starts_with("winhttp")
            || f.starts_with("wininet")
            || f.starts_with("internetopen")
            || f.starts_with("internetconnect")
            || f.starts_with("httpopen")
        {
            return ApiCategory::Network;
        }
        if f.starts_with("crypt") || f.starts_with("bcrypt") || f.starts_with("ncrypt") {
            return ApiCategory::Crypto;
        }
        if f.starts_with("loadlibrary")
            || f.starts_with("getprocaddress")
            || f.starts_with("freelibrary")
        {
            return ApiCategory::DynLoad;
        }
        if f.starts_with("isdebuggerpresent")
            || f.starts_with("checkremotedebugger")
            || f.starts_with("outputdebugstring")
        {
            return ApiCategory::Debug;
        }
        if f.starts_with("ntquerysystem")
            || f.starts_with("ntsetinformationthread")
            || f.starts_with("ntqueryvirtual")
        {
            return ApiCategory::AntiAnalysis;
        }
        if f.starts_with("createevent")
            || f.starts_with("createmutext")
            || f.starts_with("waitforsingleobject")
            || f.starts_with("waitformultipleobjects")
            || f.starts_with("releasesemaphore")
            || f.starts_with("setevent")
        {
            return ApiCategory::Synchronisation;
        }
        if f.starts_with("openprocesstoken")
            || f.starts_with("lookupprivilegename")
            || f.starts_with("adjusttokenprivileges")
        {
            return ApiCategory::Security;
        }
        ApiCategory::Misc
    }

    fn populate(&mut self) {
        // Memory
        for func in &[
            "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
            "VirtualProtect", "VirtualProtectEx", "VirtualQuery", "VirtualQueryEx",
            "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy",
            "LocalAlloc", "LocalFree", "GlobalAlloc", "GlobalFree",
        ] {
            self.insert("kernel32.dll", func, ApiCategory::Memory);
        }
        // File I/O
        for func in &[
            "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW", "CopyFileA", "CopyFileW",
            "GetFileSize", "SetFilePointer", "SetFilePointerEx", "FlushFileBuffers",
            "GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW",
        ] {
            self.insert("kernel32.dll", func, ApiCategory::FileIo);
        }
        // Dynamic load
        for func in &[
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
            "GetProcAddress", "FreeLibrary",
        ] {
            self.insert("kernel32.dll", func, ApiCategory::DynLoad);
        }
        // Process / thread
        for func in &[
            "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
            "ExitProcess", "GetCurrentProcess", "GetCurrentProcessId",
            "CreateThread", "CreateRemoteThread", "OpenThread", "TerminateThread",
            "SuspendThread", "ResumeThread", "GetThreadContext", "SetThreadContext",
        ] {
            self.insert("kernel32.dll", func, ApiCategory::ProcessThread);
        }
        // Crypto
        for func in &[
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
            "CryptGenKey", "CryptDestroyKey", "CryptImportKey", "CryptExportKey",
            "CryptHashData", "CryptDeriveKey",
        ] {
            self.insert("advapi32.dll", func, ApiCategory::Crypto);
        }
        for func in &[
            "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
            "BCryptImportKey", "BCryptExportKey", "BCryptHash", "BCryptCreateHash",
        ] {
            self.insert("bcrypt.dll", func, ApiCategory::Crypto);
        }
        // Registry
        for func in &[
            "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
            "RegQueryValueA", "RegQueryValueW", "RegQueryValueExA", "RegQueryValueExW",
            "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
            "RegCreateKeyA", "RegCreateKeyW", "RegDeleteKeyA", "RegDeleteKeyW",
            "RegCloseKey", "RegEnumKeyA", "RegEnumKeyW",
        ] {
            self.insert("advapi32.dll", func, ApiCategory::Registry);
        }
        // Security
        for func in &[
            "OpenProcessToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
            "AdjustTokenPrivileges", "GetTokenInformation", "SetTokenInformation",
            "ImpersonateLoggedOnUser", "RevertToSelf",
        ] {
            self.insert("advapi32.dll", func, ApiCategory::Security);
        }
        // Debug
        for func in &[
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "OutputDebugStringA", "OutputDebugStringW",
        ] {
            self.insert("kernel32.dll", func, ApiCategory::Debug);
        }
        // Sync
        for func in &[
            "CreateEventA", "CreateEventW", "OpenEventA", "OpenEventW",
            "SetEvent", "ResetEvent", "WaitForSingleObject", "WaitForMultipleObjects",
            "CreateMutexA", "CreateMutexW", "ReleaseMutex",
            "CreateSemaphoreA", "CreateSemaphoreW", "ReleaseSemaphore",
            "Sleep", "SleepEx",
        ] {
            self.insert("kernel32.dll", func, ApiCategory::Synchronisation);
        }
    }
}

// ─── Win32ApiMonitor ──────────────────────────────────────────────────────────

/// Monitors Win32 API calls made by the emulated process.
///
/// Records calls, categorises them, computes per-category statistics, and
/// supports filtering for targeted analysis.
pub struct Win32ApiMonitor {
    log: Vec<Win32Call>,
    seq: u64,
    db: ApiDatabase,
    start_time: Instant,
    pub filter: ApiFilter,
    /// Whether to mark calls in suspicious categories automatically.
    pub auto_flag_suspicious: bool,
    /// Per-category call counts.
    category_counts: HashMap<ApiCategory, u64>,
    /// Per-function call counts.
    function_counts: HashMap<String, u64>,
}

impl Win32ApiMonitor {
    /// Create a new monitor with no recorded calls.
    #[must_use]
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            seq: 1,
            db: ApiDatabase::new(),
            start_time: Instant::now(),
            filter: ApiFilter::allow_all(),
            auto_flag_suspicious: true,
            category_counts: HashMap::new(),
            function_counts: HashMap::new(),
        }
    }

    /// Categorise a call to `dll!function` using the static database.
    #[must_use]
    pub fn categorize_call(&self, dll: &str, function: &str) -> ApiCategory {
        self.db.categorize(dll, function)
    }

    /// Record an API call. Returns the sequence number if recorded, or `None` if filtered.
    pub fn record(
        &mut self,
        caller_addr: u64,
        dll: &str,
        function: &str,
        args: Vec<u64>,
        return_value: Option<u64>,
    ) -> Option<u64> {
        let category = self.db.categorize(dll, function);
        let suspicious = self.auto_flag_suspicious && category.is_suspicious();
        let timestamp_us = self
            .start_time
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);

        let call = Win32Call {
            seq: self.seq,
            caller_addr,
            dll: dll.to_string(),
            function: function.to_string(),
            category,
            args,
            return_value,
            timestamp_us,
            suspicious,
            note: None,
        };

        if !self.filter.matches(&call) {
            return None;
        }

        let seq = self.seq;
        self.seq += 1;
        *self.category_counts.entry(category).or_insert(0) += 1;
        *self
            .function_counts
            .entry(call.qualified_name())
            .or_insert(0) += 1;
        self.log.push(call);
        Some(seq)
    }

    /// Return all recorded calls.
    #[must_use]
    pub fn calls(&self) -> &[Win32Call] {
        &self.log
    }

    /// Return calls matching the given category.
    #[must_use]
    pub fn calls_in_category(&self, cat: ApiCategory) -> Vec<&Win32Call> {
        self.log.iter().filter(|c| c.category == cat).collect()
    }

    /// Return calls that were flagged as suspicious.
    #[must_use]
    pub fn suspicious_calls(&self) -> Vec<&Win32Call> {
        self.log.iter().filter(|c| c.suspicious).collect()
    }

    /// Return calls from the given DLL (case-insensitive).
    #[must_use]
    pub fn calls_from_dll(&self, dll: &str) -> Vec<&Win32Call> {
        let dll_lc = dll.to_ascii_lowercase();
        self.log
            .iter()
            .filter(|c| c.dll.to_ascii_lowercase() == dll_lc)
            .collect()
    }

    /// Return calls to the named function (exact, case-sensitive).
    #[must_use]
    pub fn calls_to_function(&self, function: &str) -> Vec<&Win32Call> {
        self.log.iter().filter(|c| c.function == function).collect()
    }

    /// Return per-category counts.
    #[must_use]
    pub const fn category_counts(&self) -> &HashMap<ApiCategory, u64> {
        &self.category_counts
    }

    /// Return per-function counts.
    #[must_use]
    pub const fn function_counts(&self) -> &HashMap<String, u64> {
        &self.function_counts
    }

    /// Return the total number of recorded calls.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.log.len()
    }

    /// Clear all recorded calls and reset counters.
    pub fn clear(&mut self) {
        self.log.clear();
        self.seq = 1;
        self.category_counts.clear();
        self.function_counts.clear();
    }

    /// Return the top N most-called functions.
    #[must_use]
    pub fn top_functions(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .function_counts
            .iter()
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Add a note to a specific call by sequence number.
    pub fn annotate(&mut self, seq: u64, note: impl Into<String>) -> bool {
        if let Some(call) = self.log.iter_mut().find(|c| c.seq == seq) {
            call.note = Some(note.into());
            true
        } else {
            false
        }
    }
}

impl Default for Win32ApiMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Win32ApiMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Win32ApiMonitor")
            .field("call_count", &self.log.len())
            .field("auto_flag_suspicious", &self.auto_flag_suspicious)
            .finish_non_exhaustive()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> Win32ApiMonitor {
        Win32ApiMonitor::new()
    }

    #[test]
    fn categorize_virtual_alloc() {
        let m = monitor();
        assert_eq!(
            m.categorize_call("kernel32.dll", "VirtualAlloc"),
            ApiCategory::Memory
        );
    }

    #[test]
    fn categorize_create_file() {
        let m = monitor();
        assert_eq!(
            m.categorize_call("kernel32.dll", "CreateFileW"),
            ApiCategory::FileIo
        );
    }

    #[test]
    fn categorize_load_library() {
        let m = monitor();
        assert_eq!(
            m.categorize_call("kernel32.dll", "LoadLibraryA"),
            ApiCategory::DynLoad
        );
    }

    #[test]
    fn categorize_crypto() {
        let m = monitor();
        assert_eq!(
            m.categorize_call("advapi32.dll", "CryptEncrypt"),
            ApiCategory::Crypto
        );
        assert_eq!(
            m.categorize_call("bcrypt.dll", "BCryptEncrypt"),
            ApiCategory::Crypto
        );
    }

    #[test]
    fn record_call_increments_count() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![0x1000, 0x100], Some(0x2000));
        assert_eq!(m.call_count(), 1);
    }

    #[test]
    fn record_returns_sequence_number() {
        let mut m = monitor();
        let seq = m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        assert_eq!(seq, Some(1));
    }

    #[test]
    fn calls_in_category() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        m.record(0x2000, "kernel32.dll", "CreateFileW", vec![], None);
        let mem_calls = m.calls_in_category(ApiCategory::Memory);
        assert_eq!(mem_calls.len(), 1);
        assert_eq!(mem_calls[0].function, "VirtualAlloc");
    }

    #[test]
    fn suspicious_calls() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "LoadLibraryA", vec![], Some(0x7fff_0000));
        let sus = m.suspicious_calls();
        assert_eq!(sus.len(), 1);
    }

    #[test]
    fn calls_from_dll() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        m.record(0x2000, "advapi32.dll", "CryptEncrypt", vec![], None);
        let k32 = m.calls_from_dll("kernel32.dll");
        assert_eq!(k32.len(), 1);
    }

    #[test]
    fn calls_to_function() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "Sleep", vec![100], None);
        m.record(0x2000, "kernel32.dll", "Sleep", vec![200], None);
        let sleeps = m.calls_to_function("Sleep");
        assert_eq!(sleeps.len(), 2);
    }

    #[test]
    fn top_functions() {
        let mut m = monitor();
        for _ in 0..5 {
            m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        }
        for _ in 0..3 {
            m.record(0x2000, "kernel32.dll", "Sleep", vec![], None);
        }
        let top = m.top_functions(1);
        assert_eq!(top.len(), 1);
        assert!(top[0].0.contains("VirtualAlloc"));
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn filter_by_category() {
        let mut m = monitor();
        m.filter = ApiFilter::for_categories(vec![ApiCategory::Memory]);
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        m.record(0x2000, "kernel32.dll", "CreateFileW", vec![], None);
        assert_eq!(m.call_count(), 1);
        assert_eq!(m.calls()[0].function, "VirtualAlloc");
    }

    #[test]
    fn clear_resets_state() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        m.clear();
        assert_eq!(m.call_count(), 0);
        assert!(m.category_counts().is_empty());
    }

    #[test]
    fn annotate_call() {
        let mut m = monitor();
        let seq = m
            .record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None)
            .unwrap();
        assert!(m.annotate(seq, "suspicious heap spray"));
        let call = m.calls().iter().find(|c| c.seq == seq).unwrap();
        assert_eq!(call.note.as_deref(), Some("suspicious heap spray"));
    }

    #[test]
    fn win32_call_summary_contains_function_name() {
        let call = Win32Call {
            seq: 1,
            caller_addr: 0x1000,
            dll: "kernel32.dll".into(),
            function: "VirtualAlloc".into(),
            category: ApiCategory::Memory,
            args: vec![0x1000, 0x100],
            return_value: Some(0x2000),
            timestamp_us: 0,
            suspicious: false,
            note: None,
        };
        let s = call.summary();
        assert!(s.contains("VirtualAlloc"));
        assert!(s.contains("0x2000"));
    }

    #[test]
    fn api_category_is_suspicious() {
        assert!(ApiCategory::Crypto.is_suspicious());
        assert!(ApiCategory::DynLoad.is_suspicious());
        assert!(!ApiCategory::Memory.is_suspicious());
        assert!(!ApiCategory::Misc.is_suspicious());
    }

    #[test]
    fn api_filter_function_name_contains() {
        let mut m = monitor();
        m.filter.function_name_contains = Some("Alloc".into());
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        m.record(0x2000, "kernel32.dll", "VirtualFree", vec![], None);
        assert_eq!(m.call_count(), 1);
    }

    #[test]
    fn category_counts_tracked() {
        let mut m = monitor();
        m.record(0x1000, "kernel32.dll", "VirtualAlloc", vec![], None);
        m.record(0x2000, "kernel32.dll", "HeapAlloc", vec![], None);
        let counts = m.category_counts();
        assert_eq!(*counts.get(&ApiCategory::Memory).unwrap_or(&0), 2);
    }
}
