//! API call tracking during TTD replay.
//!
//! Provides [`ApiCallRecord`], [`ApiCallTracker`], [`ApiCallFilter`],
//! and [`ApiCallSummary`] for extracting and analysing Windows API calls
//! from a time-travel debug trace.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ApiTrackerError {
    #[error("function {0} not found in module {1}")]
    FunctionNotFound(String, String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ── ApiCategory ───────────────────────────────────────────────────────────────

/// High-level category of a Win32 API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    Crypto,
    Network,
    Process,
    Thread,
    File,
    Registry,
    Memory,
    Sync,
    AntiDebug,
    Persistence,
    Injection,
    Other,
}

impl ApiCategory {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Crypto => "crypto",
            Self::Network => "network",
            Self::Process => "process",
            Self::Thread => "thread",
            Self::File => "file",
            Self::Registry => "registry",
            Self::Memory => "memory",
            Self::Sync => "sync",
            Self::AntiDebug => "anti-debug",
            Self::Persistence => "persistence",
            Self::Injection => "injection",
            Self::Other => "other",
        }
    }
}

// ── API database ──────────────────────────────────────────────────────────────

/// An entry in the interesting-API database.
#[derive(Debug, Clone)]
pub struct ApiEntry {
    pub module: &'static str,
    pub function: &'static str,
    pub category: ApiCategory,
    pub description: &'static str,
    pub arg_count: u8,
}

/// Pre-built list of interesting Windows APIs for the tracker.
pub static INTERESTING_APIS: &[ApiEntry] = &[
    // ── Crypto ──────────────────────────────────────────────────────────────
    ApiEntry { module: "advapi32", function: "CryptEncrypt",        category: ApiCategory::Crypto,    description: "Encrypt data using a session key",                        arg_count: 6 },
    ApiEntry { module: "advapi32", function: "CryptDecrypt",        category: ApiCategory::Crypto,    description: "Decrypt data using a session key",                        arg_count: 6 },
    ApiEntry { module: "advapi32", function: "CryptHashData",       category: ApiCategory::Crypto,    description: "Hash data into a CryptoAPI hash object",                  arg_count: 4 },
    ApiEntry { module: "advapi32", function: "CryptDeriveKey",      category: ApiCategory::Crypto,    description: "Derive session key from password hash",                   arg_count: 5 },
    ApiEntry { module: "bcrypt",   function: "BCryptEncrypt",       category: ApiCategory::Crypto,    description: "CNG encrypt (modern)",                                    arg_count: 8 },
    ApiEntry { module: "bcrypt",   function: "BCryptDecrypt",       category: ApiCategory::Crypto,    description: "CNG decrypt (modern)",                                    arg_count: 8 },
    ApiEntry { module: "bcrypt",   function: "BCryptGenRandom",     category: ApiCategory::Crypto,    description: "Generate random bytes (CNG)",                             arg_count: 4 },
    // ── Network ─────────────────────────────────────────────────────────────
    ApiEntry { module: "ws2_32",   function: "connect",             category: ApiCategory::Network,   description: "Connect socket to remote address",                        arg_count: 3 },
    ApiEntry { module: "ws2_32",   function: "send",                category: ApiCategory::Network,   description: "Send data on a socket",                                   arg_count: 4 },
    ApiEntry { module: "ws2_32",   function: "recv",                category: ApiCategory::Network,   description: "Receive data from a socket",                              arg_count: 4 },
    ApiEntry { module: "winhttp",  function: "WinHttpSendRequest",  category: ApiCategory::Network,   description: "Send HTTP request",                                       arg_count: 7 },
    ApiEntry { module: "winhttp",  function: "WinHttpReadData",     category: ApiCategory::Network,   description: "Read HTTP response data",                                 arg_count: 4 },
    ApiEntry { module: "wininet",  function: "InternetOpenUrl",     category: ApiCategory::Network,   description: "Open URL for reading",                                    arg_count: 5 },
    ApiEntry { module: "wininet",  function: "InternetReadFile",    category: ApiCategory::Network,   description: "Read internet file data",                                 arg_count: 4 },
    ApiEntry { module: "dnsapi",   function: "DnsQuery_A",          category: ApiCategory::Network,   description: "DNS query (ANSI)",                                        arg_count: 5 },
    // ── Process ─────────────────────────────────────────────────────────────
    ApiEntry { module: "kernel32", function: "CreateProcessA",      category: ApiCategory::Process,   description: "Create new process (ANSI)",                               arg_count: 10 },
    ApiEntry { module: "kernel32", function: "CreateProcessW",      category: ApiCategory::Process,   description: "Create new process (Unicode)",                            arg_count: 10 },
    ApiEntry { module: "kernel32", function: "OpenProcess",         category: ApiCategory::Process,   description: "Open handle to existing process",                         arg_count: 3 },
    ApiEntry { module: "kernel32", function: "TerminateProcess",    category: ApiCategory::Process,   description: "Terminate a process",                                     arg_count: 2 },
    ApiEntry { module: "ntdll",    function: "NtCreateProcess",     category: ApiCategory::Process,   description: "Native API: create process",                              arg_count: 8 },
    ApiEntry { module: "ntdll",    function: "NtTerminateProcess",  category: ApiCategory::Process,   description: "Native API: terminate process",                           arg_count: 2 },
    // ── Injection ───────────────────────────────────────────────────────────
    ApiEntry { module: "kernel32", function: "VirtualAllocEx",      category: ApiCategory::Injection, description: "Allocate memory in remote process",                       arg_count: 5 },
    ApiEntry { module: "kernel32", function: "WriteProcessMemory",  category: ApiCategory::Injection, description: "Write to remote process memory",                          arg_count: 5 },
    ApiEntry { module: "kernel32", function: "CreateRemoteThread",  category: ApiCategory::Injection, description: "Create thread in remote process",                         arg_count: 7 },
    ApiEntry { module: "ntdll",    function: "NtWriteVirtualMemory",category: ApiCategory::Injection, description: "Native API: write to virtual memory",                     arg_count: 5 },
    ApiEntry { module: "ntdll",    function: "NtCreateThreadEx",    category: ApiCategory::Injection, description: "Native API: create remote thread",                        arg_count: 11 },
    // ── File ────────────────────────────────────────────────────────────────
    ApiEntry { module: "kernel32", function: "CreateFileA",         category: ApiCategory::File,      description: "Create / open file (ANSI)",                               arg_count: 7 },
    ApiEntry { module: "kernel32", function: "CreateFileW",         category: ApiCategory::File,      description: "Create / open file (Unicode)",                            arg_count: 7 },
    ApiEntry { module: "kernel32", function: "ReadFile",            category: ApiCategory::File,      description: "Read from file",                                          arg_count: 5 },
    ApiEntry { module: "kernel32", function: "WriteFile",           category: ApiCategory::File,      description: "Write to file",                                           arg_count: 5 },
    ApiEntry { module: "kernel32", function: "DeleteFileA",         category: ApiCategory::File,      description: "Delete file (ANSI)",                                      arg_count: 1 },
    ApiEntry { module: "kernel32", function: "MoveFileExW",         category: ApiCategory::File,      description: "Move / rename file (Unicode, with flags)",                arg_count: 3 },
    // ── Registry ────────────────────────────────────────────────────────────
    ApiEntry { module: "advapi32", function: "RegOpenKeyExA",       category: ApiCategory::Registry,  description: "Open registry key (ANSI)",                                arg_count: 5 },
    ApiEntry { module: "advapi32", function: "RegSetValueExA",      category: ApiCategory::Registry,  description: "Set registry value (ANSI)",                               arg_count: 6 },
    ApiEntry { module: "advapi32", function: "RegSetValueExW",      category: ApiCategory::Registry,  description: "Set registry value (Unicode)",                            arg_count: 6 },
    ApiEntry { module: "advapi32", function: "RegDeleteValueA",     category: ApiCategory::Registry,  description: "Delete registry value (ANSI)",                            arg_count: 2 },
    ApiEntry { module: "ntdll",    function: "NtSetValueKey",       category: ApiCategory::Registry,  description: "Native API: set registry key value",                      arg_count: 6 },
    // ── Memory ──────────────────────────────────────────────────────────────
    ApiEntry { module: "kernel32", function: "VirtualAlloc",        category: ApiCategory::Memory,    description: "Allocate virtual memory in current process",              arg_count: 4 },
    ApiEntry { module: "kernel32", function: "VirtualProtect",      category: ApiCategory::Memory,    description: "Change page protection flags",                            arg_count: 4 },
    ApiEntry { module: "ntdll",    function: "NtAllocateVirtualMemory", category: ApiCategory::Memory, description: "Native API: allocate virtual memory",                   arg_count: 6 },
    // ── Anti-debug ──────────────────────────────────────────────────────────
    ApiEntry { module: "kernel32", function: "IsDebuggerPresent",   category: ApiCategory::AntiDebug, description: "Check if process is being debugged",                      arg_count: 0 },
    ApiEntry { module: "kernel32", function: "CheckRemoteDebuggerPresent", category: ApiCategory::AntiDebug, description: "Check if remote debugger is attached",            arg_count: 2 },
    ApiEntry { module: "ntdll",    function: "NtQueryInformationProcess", category: ApiCategory::AntiDebug, description: "Query process info (used for debug detection)",    arg_count: 5 },
    ApiEntry { module: "kernel32", function: "GetTickCount",        category: ApiCategory::AntiDebug, description: "Timing check used for sandbox evasion",                  arg_count: 0 },
    // ── Persistence ─────────────────────────────────────────────────────────
    ApiEntry { module: "advapi32", function: "CreateServiceA",      category: ApiCategory::Persistence, description: "Create a service for persistence",                    arg_count: 13 },
    ApiEntry { module: "kernel32", function: "SetFileAttributesA",  category: ApiCategory::Persistence, description: "Set file attributes (e.g., hidden)",                  arg_count: 2 },
    ApiEntry { module: "schtasks", function: "SchRpcRegisterTask",  category: ApiCategory::Persistence, description: "Register scheduled task via RPC",                    arg_count: 6 },
];

/// Look up an API by function name.
#[must_use] 
pub fn lookup_api(function_name: &str) -> Option<&'static ApiEntry> {
    let lower = function_name.to_ascii_lowercase();
    INTERESTING_APIS.iter().find(|e| e.function.to_ascii_lowercase() == lower)
}

// ── ApiCallRecord ─────────────────────────────────────────────────────────────

/// A single recorded API call during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    /// Replay tick when the call was intercepted.
    pub tick: u64,
    /// Module name (e.g., `"kernel32"`).
    pub module: String,
    /// Function name (e.g., `"CreateFileW"`).
    pub function: String,
    /// Arguments (raw register values; number depends on calling convention).
    pub args: Vec<u64>,
    /// Return value (from replayer state after the call returns).
    pub return_val: Option<u64>,
    /// Category of the API call.
    pub category: ApiCategory,
    /// `true` if this call is in the interesting-API database.
    pub is_interesting: bool,
}

impl ApiCallRecord {
    /// Create a new record.
    pub fn new(
        tick: u64,
        module: impl Into<String>,
        function: impl Into<String>,
        args: Vec<u64>,
    ) -> Self {
        let func = function.into();
        let is_interesting = lookup_api(&func).is_some();
        let category = lookup_api(&func).map_or(ApiCategory::Other, |e| e.category);
        Self {
            tick,
            module: module.into(),
            function: func,
            args,
            return_val: None,
            category,
            is_interesting,
        }
    }

    /// Attach a return value.
    #[must_use] 
    pub const fn with_return(mut self, rv: u64) -> Self {
        self.return_val = Some(rv);
        self
    }

    /// Format as a human-readable call string.
    #[must_use] 
    pub fn display(&self) -> String {
        let args_str = self.args.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>().join(", ");
        let ret_str = self.return_val.map(|r| format!(" = {r:#x}")).unwrap_or_default();
        format!("[tick={}] {}.{}({args_str}){ret_str}", self.tick, self.module, self.function)
    }
}

// ── ApiCallFilter ─────────────────────────────────────────────────────────────

/// Composable filter for API call records.
#[derive(Debug, Clone, Default)]
pub struct ApiCallFilter {
    pub category: Option<ApiCategory>,
    pub module: Option<String>,
    pub function_contains: Option<String>,
    pub tick_range: Option<(u64, u64)>,
    pub interesting_only: bool,
}

impl ApiCallFilter {
    /// Create a filter that accepts everything.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to a specific category.
    #[must_use] 
    pub const fn with_category(mut self, cat: ApiCategory) -> Self {
        self.category = Some(cat);
        self
    }

    /// Restrict to a specific module (case-insensitive).
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Restrict to functions whose names contain `substring` (case-insensitive).
    pub fn with_function_contains(mut self, substring: impl Into<String>) -> Self {
        self.function_contains = Some(substring.into());
        self
    }

    /// Restrict to a tick range.
    #[must_use] 
    pub const fn with_tick_range(mut self, start: u64, end: u64) -> Self {
        self.tick_range = Some((start, end));
        self
    }

    /// Only include calls that are in the interesting-API database.
    #[must_use] 
    pub const fn interesting_only(mut self) -> Self {
        self.interesting_only = true;
        self
    }

    /// Return `true` if `record` passes the filter.
    #[must_use] 
    pub fn matches(&self, record: &ApiCallRecord) -> bool {
        if let Some(cat) = self.category
            && record.category != cat { return false; }
        if let Some(ref module) = self.module
            && !record.module.to_ascii_lowercase().contains(&module.to_ascii_lowercase()) {
                return false;
            }
        if let Some(ref substr) = self.function_contains
            && !record.function.to_ascii_lowercase().contains(&substr.to_ascii_lowercase()) {
                return false;
            }
        if let Some((start, end)) = self.tick_range
            && (record.tick < start || record.tick > end) { return false; }
        if self.interesting_only && !record.is_interesting {
            return false;
        }
        true
    }

    /// Apply this filter to a slice of records.
    #[must_use] 
    pub fn apply<'a>(&self, records: &'a [ApiCallRecord]) -> Vec<&'a ApiCallRecord> {
        records.iter().filter(|r| self.matches(r)).collect()
    }
}

// ── ApiCallSummary ────────────────────────────────────────────────────────────

/// Aggregated summary of API calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallSummary {
    /// Total number of calls recorded.
    pub total_calls: usize,
    /// Number of unique function names called.
    pub unique_functions: usize,
    /// Most frequently called functions: (`function_name`, count).
    pub most_called: Vec<(String, usize)>,
    /// Count per category.
    pub category_counts: HashMap<String, usize>,
    /// Interesting-only count.
    pub interesting_count: usize,
}

impl ApiCallSummary {
    /// Build a summary from a slice of records.
    #[must_use] 
    pub fn from_records(records: &[ApiCallRecord]) -> Self {
        let total_calls = records.len();
        let mut func_counts: HashMap<&str, usize> = HashMap::new();
        let mut cat_counts: HashMap<String, usize> = HashMap::new();
        let mut interesting_count = 0;

        for r in records {
            *func_counts.entry(r.function.as_str()).or_insert(0) += 1;
            *cat_counts.entry(r.category.as_str().to_owned()).or_insert(0) += 1;
            if r.is_interesting { interesting_count += 1; }
        }

        let unique_functions = func_counts.len();
        let mut most_called: Vec<(String, usize)> = func_counts
            .into_iter()
            .map(|(f, c)| (f.to_owned(), c))
            .collect();
        most_called.sort_by_key(|b| std::cmp::Reverse(b.1));
        most_called.truncate(20);

        Self { total_calls, unique_functions, most_called, category_counts: cat_counts, interesting_count }
    }

    /// Return the top N most called functions.
    #[must_use] 
    pub fn top_n(&self, n: usize) -> &[(String, usize)] {
        &self.most_called[..self.most_called.len().min(n)]
    }
}

// ── ApiCallTracker ────────────────────────────────────────────────────────────

/// Accumulates and queries API call records during replay.
pub struct ApiCallTracker {
    records: Vec<ApiCallRecord>,
}

impl ApiCallTracker {
    /// Create a new tracker.
    #[must_use] 
    pub const fn new() -> Self {
        Self { records: Vec::new() }
    }

    /// Record an API call.
    pub fn record(&mut self, call: ApiCallRecord) {
        self.records.push(call);
    }

    /// Return a reference to all records.
    #[must_use] 
    pub fn records(&self) -> &[ApiCallRecord] {
        &self.records
    }

    /// Return the total number of calls.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// True if no calls have been recorded.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Apply a filter and return matching records.
    #[must_use] 
    pub fn filter<'a>(&'a self, filter: &ApiCallFilter) -> Vec<&'a ApiCallRecord> {
        filter.apply(&self.records)
    }

    /// Build a summary of all recorded calls.
    #[must_use] 
    pub fn summary(&self) -> ApiCallSummary {
        ApiCallSummary::from_records(&self.records)
    }

    /// Return all records for a specific function name (case-insensitive).
    #[must_use] 
    pub fn calls_to(&self, function: &str) -> Vec<&ApiCallRecord> {
        let lower = function.to_ascii_lowercase();
        self.records.iter().filter(|r| r.function.to_ascii_lowercase() == lower).collect()
    }

    /// Return all injection-related calls.
    #[must_use] 
    pub fn injection_calls(&self) -> Vec<&ApiCallRecord> {
        self.filter(&ApiCallFilter::new().with_category(ApiCategory::Injection))
    }

    /// Return all crypto-related calls.
    #[must_use] 
    pub fn crypto_calls(&self) -> Vec<&ApiCallRecord> {
        self.filter(&ApiCallFilter::new().with_category(ApiCategory::Crypto))
    }

    /// Return all network-related calls.
    #[must_use] 
    pub fn network_calls(&self) -> Vec<&ApiCallRecord> {
        self.filter(&ApiCallFilter::new().with_category(ApiCategory::Network))
    }

    /// Resolve a function name given module and function.
    #[must_use] 
    pub fn resolve_name(&self, module: &str, function: &str) -> Option<&'static ApiEntry> {
        let lower_m = module.to_ascii_lowercase();
        let lower_f = function.to_ascii_lowercase();
        INTERESTING_APIS.iter().find(|e| {
            e.module == lower_m && e.function.to_ascii_lowercase() == lower_f
        })
    }

    /// Export all records as JSON.
    pub fn to_json(&self) -> Result<String, ApiTrackerError> {
        serde_json::to_string_pretty(&self.records)
            .map_err(|e| ApiTrackerError::Serialization(e.to_string()))
    }
}

impl Default for ApiCallTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> ApiCallTracker {
        let mut t = ApiCallTracker::new();
        t.record(ApiCallRecord::new(100, "kernel32", "CreateFileW", vec![0x1000, 0, 0]));
        t.record(ApiCallRecord::new(200, "kernel32", "VirtualAllocEx", vec![0xFFFF, 0, 0x1000, 0x40]));
        t.record(ApiCallRecord::new(300, "kernel32", "WriteProcessMemory", vec![0xFFFF, 0x2000, 0, 0x100]));
        t.record(ApiCallRecord::new(400, "advapi32", "CryptEncrypt", vec![0xABCD, 0, 0, 0, 0, 0]));
        t
    }

    #[test]
    fn test_tracker_len() {
        let t = make_tracker();
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn test_tracker_empty() {
        let t = ApiCallTracker::new();
        assert!(t.is_empty());
    }

    #[test]
    fn test_injection_calls() {
        let t = make_tracker();
        let inj = t.injection_calls();
        assert!(!inj.is_empty());
        for c in &inj {
            assert_eq!(c.category, ApiCategory::Injection);
        }
    }

    #[test]
    fn test_crypto_calls() {
        let t = make_tracker();
        let crypto = t.crypto_calls();
        assert_eq!(crypto.len(), 1);
        assert_eq!(crypto[0].function, "CryptEncrypt");
    }

    #[test]
    fn test_calls_to_specific_function() {
        let t = make_tracker();
        let calls = t.calls_to("CreateFileW");
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn test_api_call_record_display() {
        let r = ApiCallRecord::new(42, "kernel32", "CreateFileW", vec![0x1000]).with_return(0xABCD);
        let s = r.display();
        assert!(s.contains("CreateFileW"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_api_call_is_interesting() {
        let r = ApiCallRecord::new(0, "kernel32", "VirtualAllocEx", vec![]);
        assert!(r.is_interesting);
    }

    #[test]
    fn test_api_call_not_interesting() {
        let r = ApiCallRecord::new(0, "user32", "MessageBoxA", vec![]);
        assert!(!r.is_interesting);
    }

    #[test]
    fn test_filter_by_category() {
        let t = make_tracker();
        let filter = ApiCallFilter::new().with_category(ApiCategory::File);
        let results = t.filter(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_by_module() {
        let t = make_tracker();
        let filter = ApiCallFilter::new().with_module("advapi32");
        let results = t.filter(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_function_contains() {
        let t = make_tracker();
        let filter = ApiCallFilter::new().with_function_contains("Process");
        let results = t.filter(&filter);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_filter_tick_range() {
        let t = make_tracker();
        let filter = ApiCallFilter::new().with_tick_range(150, 350);
        let results = t.filter(&filter);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_filter_interesting_only() {
        let mut tracker = ApiCallTracker::new();
        tracker.record(ApiCallRecord::new(0, "user32", "MessageBoxA", vec![]));
        tracker.record(ApiCallRecord::new(1, "kernel32", "CreateFileW", vec![]));
        let filter = ApiCallFilter::new().interesting_only();
        let results = tracker.filter(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_summary_total_calls() {
        let t = make_tracker();
        let s = t.summary();
        assert_eq!(s.total_calls, 4);
    }

    #[test]
    fn test_summary_unique_functions() {
        let t = make_tracker();
        let s = t.summary();
        assert_eq!(s.unique_functions, 4);
    }

    #[test]
    fn test_summary_most_called() {
        let mut tracker = ApiCallTracker::new();
        for _ in 0..5 {
            tracker.record(ApiCallRecord::new(0, "kernel32", "CreateFileW", vec![]));
        }
        tracker.record(ApiCallRecord::new(0, "kernel32", "ReadFile", vec![]));
        let s = tracker.summary();
        assert_eq!(s.most_called[0].0, "CreateFileW");
        assert_eq!(s.most_called[0].1, 5);
    }

    #[test]
    fn test_lookup_api_found() {
        let entry = lookup_api("IsDebuggerPresent").unwrap();
        assert_eq!(entry.category, ApiCategory::AntiDebug);
    }

    #[test]
    fn test_lookup_api_not_found() {
        assert!(lookup_api("NotARealApi").is_none());
    }

    #[test]
    fn test_api_category_as_str() {
        assert_eq!(ApiCategory::Crypto.as_str(), "crypto");
        assert_eq!(ApiCategory::Injection.as_str(), "injection");
        assert_eq!(ApiCategory::AntiDebug.as_str(), "anti-debug");
    }

    #[test]
    fn test_tracker_resolve_name() {
        let t = ApiCallTracker::new();
        let e = t.resolve_name("kernel32", "IsDebuggerPresent");
        assert!(e.is_some());
        assert_eq!(e.unwrap().category, ApiCategory::AntiDebug);
    }

    #[test]
    fn test_tracker_json_export() {
        let t = make_tracker();
        let json = t.to_json().unwrap();
        assert!(json.contains("CreateFileW"));
    }

    #[test]
    fn test_summary_interesting_count() {
        let t = make_tracker();
        let s = t.summary();
        assert!(s.interesting_count > 0);
    }

    #[test]
    fn test_summary_top_n() {
        let t = make_tracker();
        let s = t.summary();
        let top2 = s.top_n(2);
        assert!(top2.len() <= 2);
    }
}
