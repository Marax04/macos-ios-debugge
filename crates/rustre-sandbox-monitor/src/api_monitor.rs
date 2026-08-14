// api_monitor.rs — Windows API call monitoring
// Records and analyzes API calls made by a monitored process.

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// API category classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApiCategory {
    FileSystem,
    Registry,
    Network,
    Process,
    Thread,
    Memory,
    Crypto,
    Service,
    Synchronization,
    DllLoading,
    Other,
}

impl ApiCategory {
    #[must_use] 
    pub fn from_api_name(name: &str) -> Self {
        let lc = name.to_lowercase();
        if lc.contains("file") || lc.contains("read") || lc.contains("write") || lc.contains("create") {
            Self::FileSystem
        } else if lc.contains("reg") {
            Self::Registry
        } else if lc.contains("socket") || lc.contains("connect") || lc.contains("send")
            || lc.contains("recv") || lc.contains("bind") || lc.contains("listen")
        {
            Self::Network
        } else if lc.contains("process") || lc.contains("openprocess") {
            Self::Process
        } else if lc.contains("thread") || lc.contains("createthread") {
            Self::Thread
        } else if lc.contains("virtual") || lc.contains("alloc") || lc.contains("heap") {
            Self::Memory
        } else if lc.contains("crypt") || lc.contains("bcrypt") || lc.contains("ncrypt") {
            Self::Crypto
        } else if lc.contains("service") || lc.contains("scm") {
            Self::Service
        } else if lc.contains("event") || lc.contains("mutex") || lc.contains("semaphore") {
            Self::Synchronization
        } else if lc.contains("loadlibrary") || lc.contains("getprocaddress") {
            Self::DllLoading
        } else {
            Self::Other
        }
    }
}

// ---------------------------------------------------------------------------
// API argument representation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiArg {
    Int(i64),
    Uint(u64),
    Ptr(u64),
    Str(String),
    WStr(String),
    Bool(bool),
    Bytes(Vec<u8>),
    Null,
}

impl ApiArg {
    #[must_use] 
    pub const fn as_int(&self) -> Option<i64> {
        match self { Self::Int(i) => Some(*i), Self::Uint(u) => Some(*u as i64), _ => None }
    }

    #[must_use] 
    pub fn as_str(&self) -> Option<&str> {
        match self { Self::Str(s) | Self::WStr(s) => Some(s), _ => None }
    }

    #[must_use] 
    pub const fn as_ptr(&self) -> Option<u64> {
        match self { Self::Ptr(p) => Some(*p), Self::Null => Some(0), _ => None }
    }
}

impl std::fmt::Display for ApiArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(i)   => write!(f, "{i}"),
            Self::Uint(u)  => write!(f, "0x{u:X}"),
            Self::Ptr(p)   => write!(f, "0x{p:016X}"),
            Self::Str(s)   => write!(f, "\"{}\"", s.escape_default()),
            Self::WStr(s)  => write!(f, "L\"{}\"", s.escape_default()),
            Self::Bool(b)  => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            Self::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            Self::Null     => write!(f, "NULL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Return value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnValue {
    Int(i64),
    Uint(u64),
    Ptr(u64),
    Bool(bool),
    Handle(u64),
    Status(u32),
    Null,
    Void,
}

impl ReturnValue {
    #[must_use] 
    pub const fn is_success(&self) -> bool {
        match self {
            Self::Bool(b)   => *b,
            Self::Int(i)    => *i != 0,
            Self::Ptr(p)    => *p != 0,
            Self::Handle(h) => *h != 0,
            Self::Status(s) => (*s & 0x8000_0000) == 0,
            Self::Null      => false,
            Self::Void      => true,
            Self::Uint(u)   => *u != 0,
        }
    }
}

impl std::fmt::Display for ReturnValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(i)    => write!(f, "{i}"),
            Self::Uint(u)   => write!(f, "0x{u:X}"),
            Self::Ptr(p)    => write!(f, "0x{p:016X}"),
            Self::Bool(b)   => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            Self::Handle(h) => write!(f, "HANDLE(0x{h:X})"),
            Self::Status(s) => write!(f, "0x{s:08X}"),
            Self::Null      => write!(f, "NULL"),
            Self::Void      => write!(f, "<void>"),
        }
    }
}

// ---------------------------------------------------------------------------
// API call record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApiCallRecord {
    pub id: u64,
    pub api_name: String,
    pub module_name: String,
    pub category: ApiCategory,
    pub args: Vec<ApiArg>,
    pub return_value: ReturnValue,
    pub thread_id: u32,
    pub process_id: u32,
    pub timestamp_ns: u64,
    pub duration_ns: u64,
    pub call_depth: u32,
    pub caller_address: u64,
}

impl ApiCallRecord {
    pub fn new(
        id: u64,
        api_name: impl Into<String>,
        module_name: impl Into<String>,
        args: Vec<ApiArg>,
        return_value: ReturnValue,
        thread_id: u32,
        process_id: u32,
        timestamp_ns: u64,
        duration_ns: u64,
        caller_address: u64,
    ) -> Self {
        let api = api_name.into();
        let cat = ApiCategory::from_api_name(&api);
        Self {
            id,
            api_name: api,
            module_name: module_name.into(),
            category: cat,
            args,
            return_value,
            thread_id,
            process_id,
            timestamp_ns,
            duration_ns,
            call_depth: 0,
            caller_address,
        }
    }
}

// ---------------------------------------------------------------------------
// Format an API call for display
// ---------------------------------------------------------------------------

#[must_use] 
pub fn format_api_call(record: &ApiCallRecord) -> String {
    let args: Vec<String> = record.args.iter().map(std::string::ToString::to_string).collect();
    format!(
        "[{:6}] {}!{}({}) = {} [{} ns, TID:{}, PID:{}]",
        record.id,
        record.module_name,
        record.api_name,
        args.join(", "),
        record.return_value,
        record.duration_ns,
        record.thread_id,
        record.process_id,
    )
}

// ---------------------------------------------------------------------------
// Hook configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HookConfig {
    pub api_name: String,
    pub module_name: String,
    pub capture_args: bool,
    pub capture_return: bool,
    pub max_arg_string_len: usize,
    pub break_on_call: bool,
    pub enabled: bool,
}

impl HookConfig {
    pub fn new(api_name: impl Into<String>, module_name: impl Into<String>) -> Self {
        Self {
            api_name: api_name.into(),
            module_name: module_name.into(),
            capture_args: true,
            capture_return: true,
            max_arg_string_len: 256,
            break_on_call: false,
            enabled: true,
        }
    }

    #[must_use] 
    pub const fn disable(mut self) -> Self { self.enabled = false; self }
    #[must_use] 
    pub const fn break_on_call(mut self) -> Self { self.break_on_call = true; self }
    #[must_use] 
    pub const fn no_args(mut self) -> Self { self.capture_args = false; self }
}

// ---------------------------------------------------------------------------
// ApiHook: in-memory representation of a placed hook
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApiHook {
    pub config: HookConfig,
    /// Simulated original function bytes (for restoration)
    pub original_bytes: Vec<u8>,
    /// The hook trampoline address (simulated)
    pub trampoline_addr: u64,
    pub installed: bool,
    pub hit_count: u64,
}

impl ApiHook {
    #[must_use] 
    pub const fn new(config: HookConfig) -> Self {
        Self {
            config,
            original_bytes: Vec::new(),
            trampoline_addr: 0,
            installed: false,
            hit_count: 0,
        }
    }

    pub const fn record_hit(&mut self) {
        self.hit_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Filter for API calls
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct ApiFilter {
    pub categories: Vec<ApiCategory>,
    pub name_prefix: Option<String>,
    pub module: Option<String>,
    pub success_only: bool,
    pub failure_only: bool,
    pub min_duration_ns: Option<u64>,
    pub thread_id: Option<u32>,
}

impl ApiFilter {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    #[must_use] 
    pub fn category(mut self, cat: ApiCategory) -> Self {
        self.categories.push(cat);
        self
    }

    pub fn name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.name_prefix = Some(prefix.into());
        self
    }

    #[must_use] 
    pub const fn success_only(mut self) -> Self {
        self.success_only = true;
        self
    }

    #[must_use] 
    pub const fn failure_only(mut self) -> Self {
        self.failure_only = true;
        self
    }

    #[must_use] 
    pub fn matches(&self, record: &ApiCallRecord) -> bool {
        if !self.categories.is_empty() && !self.categories.contains(&record.category) {
            return false;
        }
        if let Some(ref pfx) = self.name_prefix
            && !record.api_name.starts_with(pfx.as_str()) {
                return false;
            }
        if let Some(ref m) = self.module
            && record.module_name.to_lowercase() != m.to_lowercase() {
                return false;
            }
        if self.success_only && !record.return_value.is_success() {
            return false;
        }
        if self.failure_only && record.return_value.is_success() {
            return false;
        }
        if let Some(min_dur) = self.min_duration_ns
            && record.duration_ns < min_dur {
                return false;
            }
        if let Some(tid) = self.thread_id
            && record.thread_id != tid {
                return false;
            }
        true
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct ApiStats {
    pub total_calls: u64,
    pub calls_by_category: HashMap<String, u64>,
    pub calls_by_api: HashMap<String, u64>,
    pub failed_calls: u64,
    pub total_duration_ns: u64,
    pub max_duration_ns: u64,
    pub slowest_api: Option<String>,
}

impl ApiStats {
    pub fn update(&mut self, record: &ApiCallRecord) {
        self.total_calls += 1;
        *self.calls_by_category
            .entry(format!("{:?}", record.category))
            .or_insert(0) += 1;
        *self.calls_by_api.entry(record.api_name.clone()).or_insert(0) += 1;
        if !record.return_value.is_success() {
            self.failed_calls += 1;
        }
        self.total_duration_ns += record.duration_ns;
        if record.duration_ns > self.max_duration_ns {
            self.max_duration_ns = record.duration_ns;
            self.slowest_api = Some(record.api_name.clone());
        }
    }

    #[must_use] 
    pub const fn avg_duration_ns(&self) -> u64 {
        if self.total_calls == 0 { 0 } else { self.total_duration_ns / self.total_calls }
    }

    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        if self.total_calls == 0 { return 1.0; }
        (self.total_calls - self.failed_calls) as f64 / self.total_calls as f64
    }

    #[must_use] 
    pub fn top_apis(&self, n: usize) -> Vec<(&str, u64)> {
        let mut pairs: Vec<(&str, u64)> = self.calls_by_api.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

// ---------------------------------------------------------------------------
// ApiMonitor
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiMonitor {
    pub hooks: HashMap<String, ApiHook>,
    pub log: Vec<ApiCallRecord>,
    pub stats: ApiStats,
    pub next_id: u64,
    pub max_log_size: usize,
    pub start_time: Option<Instant>,
}

impl ApiMonitor {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            log: Vec::new(),
            stats: ApiStats::default(),
            next_id: 1,
            max_log_size: 100_000,
            start_time: None,
        }
    }

    #[must_use] 
    pub const fn with_max_log(mut self, n: usize) -> Self {
        self.max_log_size = n;
        self
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    #[must_use] 
    pub fn elapsed(&self) -> Duration {
        self.start_time.map(|t| t.elapsed()).unwrap_or_default()
    }

    /// Install a hook configuration.
    pub fn install_hook(&mut self, config: HookConfig) -> bool {
        if !config.enabled { return false; }
        let key = format!("{}!{}", config.module_name.to_lowercase(), config.api_name.to_lowercase());
        let hook = ApiHook::new(config);
        self.hooks.insert(key, hook);
        true
    }

    /// Simulate recording an API call.
    pub fn record_call(&mut self, mut record: ApiCallRecord) {
        record.id = self.next_id;
        self.next_id += 1;

        // Update hook hit count if present
        let key = format!("{}!{}", record.module_name.to_lowercase(), record.api_name.to_lowercase());
        if let Some(hook) = self.hooks.get_mut(&key) {
            hook.record_hit();
        }

        self.stats.update(&record);

        if self.log.len() < self.max_log_size {
            self.log.push(record);
        }
    }

    /// Filter log records.
    #[must_use] 
    pub fn filter_log(&self, filter: &ApiFilter) -> Vec<&ApiCallRecord> {
        self.log.iter().filter(|r| filter.matches(r)).collect()
    }

    /// Return log formatted as text lines.
    #[must_use] 
    pub fn format_log(&self, filter: Option<&ApiFilter>) -> Vec<String> {
        let records: Vec<&ApiCallRecord> = match filter {
            Some(f) => self.filter_log(f),
            None    => self.log.iter().collect(),
        };
        records.iter().map(|r| format_api_call(r)).collect()
    }

    /// Extract all string arguments from the log (for IOC extraction).
    #[must_use] 
    pub fn extract_strings(&self) -> Vec<(u64, String, String)> {
        let mut result = Vec::new();
        for record in &self.log {
            for arg in &record.args {
                if let Some(s) = arg.as_str()
                    && !s.is_empty() {
                        result.push((record.id, record.api_name.clone(), s.to_string()));
                    }
            }
        }
        result
    }

    /// Find suspicious call patterns.
    #[must_use] 
    pub fn detect_suspicious_patterns(&self) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();

        // Check for VirtualAllocEx + WriteProcessMemory (process injection)
        let has_valloc = self.log.iter().any(|r| r.api_name.eq_ignore_ascii_case("VirtualAllocEx"));
        let has_wpm = self.log.iter().any(|r| r.api_name.eq_ignore_ascii_case("WriteProcessMemory"));
        if has_valloc && has_wpm {
            patterns.push(SuspiciousPattern {
                name: "ProcessInjection".to_string(),
                description: "VirtualAllocEx + WriteProcessMemory — classic process injection".to_string(),
                severity: PatternSeverity::High,
                related_apis: vec!["VirtualAllocEx".to_string(), "WriteProcessMemory".to_string()],
            });
        }

        // Check for CreateRemoteThread (DLL injection)
        let has_crt = self.log.iter().any(|r| r.api_name.eq_ignore_ascii_case("CreateRemoteThread"));
        if has_crt {
            patterns.push(SuspiciousPattern {
                name: "RemoteThreadCreation".to_string(),
                description: "CreateRemoteThread observed — potential code injection".to_string(),
                severity: PatternSeverity::High,
                related_apis: vec!["CreateRemoteThread".to_string()],
            });
        }

        // Check for CryptEncrypt (ransomware-like behavior)
        let crypt_count = self.log.iter().filter(|r| r.api_name.eq_ignore_ascii_case("CryptEncrypt")).count();
        if crypt_count > 50 {
            patterns.push(SuspiciousPattern {
                name: "MassCryptEncrypt".to_string(),
                description: format!("CryptEncrypt called {crypt_count} times — possible ransomware"),
                severity: PatternSeverity::Critical,
                related_apis: vec!["CryptEncrypt".to_string()],
            });
        }

        // Check for network activity after file operations (data exfiltration)
        let file_writes = self.log.iter().filter(|r| r.category == ApiCategory::FileSystem).count();
        let net_sends = self.log.iter().filter(|r| r.category == ApiCategory::Network).count();
        if file_writes > 0 && net_sends > 10 {
            patterns.push(SuspiciousPattern {
                name: "PossibleExfiltration".to_string(),
                description: format!(
                    "{file_writes} file ops followed by {net_sends} network ops — possible data exfiltration"
                ),
                severity: PatternSeverity::Medium,
                related_apis: vec!["WriteFile".to_string(), "send".to_string()],
            });
        }

        patterns
    }
}

impl Default for ApiMonitor {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Suspicious pattern
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub name: String,
    pub description: String,
    pub severity: PatternSeverity,
    pub related_apis: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for PatternSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Bulk hook installer for common malware-relevant APIs
// ---------------------------------------------------------------------------

pub fn install_default_hooks(monitor: &mut ApiMonitor) {
    let hooks = [
        ("kernel32", "CreateFileW"),
        ("kernel32", "WriteFile"),
        ("kernel32", "ReadFile"),
        ("kernel32", "DeleteFileW"),
        ("kernel32", "CreateProcessW"),
        ("kernel32", "OpenProcess"),
        ("kernel32", "VirtualAllocEx"),
        ("kernel32", "WriteProcessMemory"),
        ("kernel32", "CreateRemoteThread"),
        ("kernel32", "LoadLibraryW"),
        ("kernel32", "GetProcAddress"),
        ("advapi32", "RegOpenKeyExW"),
        ("advapi32", "RegSetValueExW"),
        ("advapi32", "RegDeleteValueW"),
        ("advapi32", "CryptEncrypt"),
        ("advapi32", "CryptDecrypt"),
        ("ws2_32",   "connect"),
        ("ws2_32",   "send"),
        ("ws2_32",   "recv"),
        ("ws2_32",   "WSAConnect"),
        ("wininet",  "InternetOpenW"),
        ("wininet",  "HttpSendRequestW"),
        ("ntdll",    "NtWriteVirtualMemory"),
        ("ntdll",    "NtCreateThreadEx"),
    ];
    for (module, api) in &hooks {
        monitor.install_hook(HookConfig::new(*api, *module));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(api: &str, module: &str, success: bool) -> ApiCallRecord {
        ApiCallRecord::new(
            0,
            api,
            module,
            vec![ApiArg::Str("test.txt".to_string()), ApiArg::Uint(0x4000_0000)],
            if success { ReturnValue::Handle(0x100) } else { ReturnValue::Handle(0) },
            1234,
            5678,
            1_000_000,
            500,
            0xDEAD_BEEF,
        )
    }

    #[test]
    fn test_api_category_from_name() {
        assert_eq!(ApiCategory::from_api_name("CreateFileW"), ApiCategory::FileSystem);
        assert_eq!(ApiCategory::from_api_name("RegOpenKeyExW"), ApiCategory::Registry);
        assert_eq!(ApiCategory::from_api_name("connect"), ApiCategory::Network);
        assert_eq!(ApiCategory::from_api_name("LoadLibraryW"), ApiCategory::DllLoading);
    }

    #[test]
    fn test_api_arg_display() {
        assert_eq!(ApiArg::Int(-1).to_string(), "-1");
        assert_eq!(ApiArg::Null.to_string(), "NULL");
        assert_eq!(ApiArg::Bool(true).to_string(), "TRUE");
    }

    #[test]
    fn test_return_value_success() {
        assert!(ReturnValue::Handle(0x100).is_success());
        assert!(!ReturnValue::Handle(0).is_success());
        assert!(ReturnValue::Bool(true).is_success());
        assert!(!ReturnValue::Status(0x8000_0000).is_success());
    }

    #[test]
    fn test_format_api_call() {
        let r = make_record("CreateFileW", "kernel32", true);
        let s = format_api_call(&r);
        assert!(s.contains("CreateFileW"));
        assert!(s.contains("kernel32"));
    }

    #[test]
    fn test_hook_install_and_record() {
        let mut monitor = ApiMonitor::new();
        monitor.install_hook(HookConfig::new("CreateFileW", "kernel32"));
        assert!(monitor.hooks.contains_key("kernel32!createfilew"));

        let record = make_record("CreateFileW", "kernel32", true);
        monitor.record_call(record);
        assert_eq!(monitor.log.len(), 1);
        assert_eq!(monitor.stats.total_calls, 1);
    }

    #[test]
    fn test_api_filter_category() {
        let mut monitor = ApiMonitor::new();
        monitor.record_call(make_record("CreateFileW", "kernel32", true));
        monitor.record_call(make_record("connect", "ws2_32", false));

        let filter = ApiFilter::new().category(ApiCategory::FileSystem);
        let results = monitor.filter_log(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].api_name, "CreateFileW");
    }

    #[test]
    fn test_api_filter_success_only() {
        let mut monitor = ApiMonitor::new();
        monitor.record_call(make_record("CreateFileW", "kernel32", true));
        monitor.record_call(make_record("CreateFileW", "kernel32", false));

        let filter = ApiFilter::new().success_only();
        let results = monitor.filter_log(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_extract_strings() {
        let mut monitor = ApiMonitor::new();
        monitor.record_call(make_record("CreateFileW", "kernel32", true));
        let strs = monitor.extract_strings();
        assert!(!strs.is_empty());
        assert!(strs.iter().any(|(_, _, s)| s == "test.txt"));
    }

    #[test]
    fn test_detect_injection_pattern() {
        let mut monitor = ApiMonitor::new();
        let mut r1 = make_record("VirtualAllocEx", "kernel32", true);
        r1.args = vec![ApiArg::Ptr(0x1234), ApiArg::Uint(0x1000)];
        let mut r2 = make_record("WriteProcessMemory", "kernel32", true);
        r2.args = vec![ApiArg::Ptr(0x1234)];
        monitor.record_call(r1);
        monitor.record_call(r2);

        let patterns = monitor.detect_suspicious_patterns();
        assert!(patterns.iter().any(|p| p.name == "ProcessInjection"));
    }

    #[test]
    fn test_stats_top_apis() {
        let mut monitor = ApiMonitor::new();
        for _ in 0..5 {
            monitor.record_call(make_record("CreateFileW", "kernel32", true));
        }
        monitor.record_call(make_record("connect", "ws2_32", true));
        let top = monitor.stats.top_apis(1);
        assert_eq!(top[0].0, "CreateFileW");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn test_install_default_hooks() {
        let mut monitor = ApiMonitor::new();
        install_default_hooks(&mut monitor);
        assert!(monitor.hooks.len() >= 20);
        assert!(monitor.hooks.contains_key("kernel32!createfilew"));
        assert!(monitor.hooks.contains_key("ntdll!ntwritevirtualmemory"));
    }

    #[test]
    fn test_stats_success_rate() {
        let mut stats = ApiStats::default();
        let r1 = make_record("CreateFileW", "kernel32", true);
        let r2 = make_record("CreateFileW", "kernel32", false);
        stats.update(&r1);
        stats.update(&r2);
        assert!((stats.success_rate() - 0.5).abs() < f64::EPSILON);
    }
}
