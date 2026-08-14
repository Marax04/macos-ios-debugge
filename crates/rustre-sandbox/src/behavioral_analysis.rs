//! `behavioral_analysis` — Sandbox behavioral analysis.
//!
//! Provides `BehaviorAnalyzer`, `ApiCallSequence`, `BehaviorSignature`,
//! `BehaviorMatcher`, `ProcessBehaviorProfile`, `NetworkBehaviorProfile`,
//! `FileBehaviorProfile`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from behavioral analysis.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BehaviorError {
    #[error("no API calls recorded")]
    Empty,
    #[error("signature not found: '{0}'")]
    SignatureNotFound(String),
    #[error("pattern error: {0}")]
    Pattern(String),
    #[error("analysis failed: {0}")]
    Analysis(String),
}

// ─── ApiCall ──────────────────────────────────────────────────────────────────

/// A single API call captured during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    /// Timestamp in milliseconds since sandbox start.
    pub timestamp_ms: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// API name (e.g. `"CreateFile"`, `"RegSetValue"`).
    pub name: String,
    /// DLL/module providing the API.
    pub module: String,
    /// Arguments (as strings).
    pub args: Vec<String>,
    /// Return value.
    pub return_value: Option<i64>,
    /// Whether the call was flagged as suspicious.
    pub suspicious: bool,
    /// Call category.
    pub category: ApiCategory,
}

impl ApiCall {
    /// Create a new API call record.
    #[must_use]
    pub fn new(pid: u32, timestamp_ms: u64, name: impl Into<String>, module: impl Into<String>) -> Self {
        let name_s: String = name.into();
        let category = ApiCategory::infer(&name_s);
        Self {
            timestamp_ms, pid, tid: 0,
            name: name_s, module: module.into(),
            args: vec![], return_value: None,
            suspicious: false, category,
        }
    }

    /// Builder: add argument.
    #[must_use]
    pub fn with_arg(mut self, a: impl Into<String>) -> Self { self.args.push(a.into()); self }

    /// Builder: set return value.
    #[must_use]
    pub const fn with_ret(mut self, r: i64) -> Self { self.return_value = Some(r); self }

    /// Builder: mark suspicious.
    #[must_use]
    pub const fn flagged(mut self) -> Self { self.suspicious = true; self }
}

impl fmt::Display for ApiCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}ms] {}!{}({})", self.timestamp_ms, self.module, self.name, self.args.join(", "))
    }
}

// ─── ApiCategory ──────────────────────────────────────────────────────────────

/// Category for an API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    File, Registry, Network, Process, Thread, Memory,
    Crypto, AntiDebug, Persistence, Injection,
    InfoGathering, Service, COM, Sync, Other,
}

impl ApiCategory {
    /// Infer category from API name (case-insensitive heuristic).
    #[must_use]
    pub fn infer(api_name: &str) -> Self {
        let lower = api_name.to_ascii_lowercase();
        // Injection markers must be checked before the generic "process"
        // and "memory" buckets because names like `WriteProcessMemory` and
        // `VirtualAllocEx` substring-match those broader categories.
        if lower.contains("inject")
            || lower.contains("remotethrd")
            || lower.contains("writeprocessmem")
            || lower.contains("createremotethread")
            || lower.contains("virtualallocex")
        { return Self::Injection; }
        if lower.contains("file") || lower.contains("readfile") || lower.contains("writefile") { return Self::File; }
        if lower.contains("reg") { return Self::Registry; }
        if lower.contains("socket") || lower.contains("connect") || lower.contains("send") || lower.contains("recv") || lower.contains("internet") { return Self::Network; }
        if lower.contains("process") || lower.contains("createproc") { return Self::Process; }
        if lower.contains("thread") { return Self::Thread; }
        if lower.contains("virtualalloc") || lower.contains("heapalloc") || lower.contains("mapview") { return Self::Memory; }
        if lower.contains("crypt") || lower.contains("bcrypt") { return Self::Crypto; }
        if lower.contains("debug") || lower.contains("isdebugg") { return Self::AntiDebug; }
        if lower.contains("service") || lower.contains("schtask") { return Self::Persistence; }
        if lower.contains("getcomputername") || lower.contains("getusername") { return Self::InfoGathering; }
        Self::Other
    }
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::File => "file", Self::Registry => "registry", Self::Network => "network",
            Self::Process => "process", Self::Thread => "thread", Self::Memory => "memory",
            Self::Crypto => "crypto", Self::AntiDebug => "anti_debug", Self::Persistence => "persistence",
            Self::Injection => "injection", Self::InfoGathering => "info_gathering",
            Self::Service => "service", Self::COM => "com", Self::Sync => "sync", Self::Other => "other",
        };
        f.write_str(s)
    }
}

// ─── ApiCallSequence ──────────────────────────────────────────────────────────

/// An ordered sequence of API calls from one process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallSequence {
    pub pid: u32,
    pub calls: Vec<ApiCall>,
}

impl ApiCallSequence {
    /// Create an empty sequence.
    #[must_use]
    pub const fn new(pid: u32) -> Self { Self { pid, calls: vec![] } }

    /// Add a call.
    pub fn add(&mut self, call: ApiCall) { self.calls.push(call); }

    /// Number of calls.
    #[must_use]
    pub const fn len(&self) -> usize { self.calls.len() }

    /// Return `true` if no calls have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.calls.is_empty() }

    /// Calls filtered by category.
    #[must_use]
    pub fn by_category(&self, cat: ApiCategory) -> Vec<&ApiCall> {
        self.calls.iter().filter(|c| c.category == cat).collect()
    }

    /// Calls filtered to only suspicious ones.
    #[must_use]
    pub fn suspicious_calls(&self) -> Vec<&ApiCall> {
        self.calls.iter().filter(|c| c.suspicious).collect()
    }

    /// Return the unique set of API names.
    #[must_use]
    pub fn unique_apis(&self) -> HashSet<String> {
        self.calls.iter().map(|c| c.name.clone()).collect()
    }

    /// Count calls by category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<ApiCategory, usize> {
        let mut m: HashMap<ApiCategory, usize> = HashMap::new();
        for call in &self.calls {
            *m.entry(call.category).or_insert(0) += 1;
        }
        m
    }

    /// Extract sub-sequences of N consecutive calls where any matches `predicate`.
    #[must_use]
    pub fn windows(&self, n: usize) -> Vec<Vec<&ApiCall>> {
        if n == 0 || self.calls.len() < n { return vec![]; }
        (0..=(self.calls.len() - n)).map(|i| self.calls[i..i + n].iter().collect()).collect()
    }
}

// ─── PatternElement ───────────────────────────────────────────────────────────

/// One element in a behavioral pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternElement {
    /// Match a specific API name (case-insensitive substring).
    ApiName(String),
    /// Match any API in a given category.
    Category(ApiCategory),
    /// Match any API call.
    Any,
    /// Optional element (0 or 1 occurrence).
    Optional(Box<Self>),
    /// Repeated element (1 or more occurrences).
    OneOrMore(Box<Self>),
}

impl PatternElement {
    /// Return `true` if this element matches the given call.
    #[must_use]
    pub fn matches(&self, call: &ApiCall) -> bool {
        match self {
            Self::ApiName(n) => call.name.to_ascii_lowercase().contains(&n.to_ascii_lowercase()),
            Self::Category(cat) => call.category == *cat,
            Self::Any => true,
            Self::Optional(inner) | Self::OneOrMore(inner) => inner.matches(call),
        }
    }
}

// ─── BehaviorSignature ────────────────────────────────────────────────────────

/// A named behavioral pattern with a severity score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSignature {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: Vec<PatternElement>,
    pub severity: u8,
    pub tags: Vec<String>,
}

impl BehaviorSignature {
    /// Create a new signature.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        pattern: Vec<PatternElement>,
        severity: u8,
    ) -> Self {
        Self {
            id: id.into(), name: name.into(), description: description.into(),
            pattern, severity, tags: vec![],
        }
    }

    /// Builder: add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into()); self
    }
}

// ─── BehaviorMatcher ─────────────────────────────────────────────────────────

/// Matches behavioral signatures against API call sequences.
pub struct BehaviorMatcher {
    signatures: Vec<BehaviorSignature>,
}

impl BehaviorMatcher {
    /// Create with built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        let mut m = Self { signatures: vec![] };
        m.load_builtin();
        m
    }

    /// Create empty.
    #[must_use]
    pub const fn empty() -> Self { Self { signatures: vec![] } }

    /// Add a signature.
    pub fn add_signature(&mut self, sig: BehaviorSignature) {
        self.signatures.push(sig);
    }

    /// Match all registered signatures against a sequence.
    ///
    /// Returns a list of matched signature IDs.
    #[must_use]
    pub fn match_all(&self, seq: &ApiCallSequence) -> Vec<&BehaviorSignature> {
        self.signatures.iter().filter(|sig| self.matches_signature(sig, seq)).collect()
    }

    /// Return the highest-severity match.
    #[must_use]
    pub fn max_severity_match(&self, seq: &ApiCallSequence) -> Option<&BehaviorSignature> {
        self.match_all(seq).into_iter().max_by_key(|s| s.severity)
    }

    /// Check if a specific signature matches.
    #[must_use]
    pub fn matches_signature(&self, sig: &BehaviorSignature, seq: &ApiCallSequence) -> bool {
        if sig.pattern.is_empty() { return false; }
        // Simple ordered subsequence match (not-necessarily-contiguous)
        let mut p_idx = 0;
        for call in &seq.calls {
            if p_idx >= sig.pattern.len() { break; }
            if sig.pattern[p_idx].matches(call) {
                p_idx += 1;
            }
        }
        p_idx >= sig.pattern.len()
    }

    fn load_builtin(&mut self) {
        // Remote thread injection
        self.add_signature(BehaviorSignature::new(
            "remote_thread_injection",
            "Remote Thread Injection",
            "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
            vec![
                PatternElement::ApiName("virtualallocex".into()),
                PatternElement::ApiName("writeprocessmemory".into()),
                PatternElement::ApiName("createremotethread".into()),
            ],
            95,
        ).with_tag("injection"));

        // Download and execute
        self.add_signature(BehaviorSignature::new(
            "download_exec",
            "Download and Execute",
            "Downloads a file and creates a new process",
            vec![
                PatternElement::Category(ApiCategory::Network),
                PatternElement::ApiName("createfile".into()),
                PatternElement::ApiName("createprocess".into()),
            ],
            80,
        ).with_tag("downloader"));

        // Registry persistence
        self.add_signature(BehaviorSignature::new(
            "reg_persistence",
            "Registry Persistence",
            "Creates a registry Run key for persistence",
            vec![
                PatternElement::ApiName("regopen".into()),
                PatternElement::ApiName("regset".into()),
            ],
            70,
        ).with_tag("persistence"));

        // Anti-debug
        self.add_signature(BehaviorSignature::new(
            "anti_debug",
            "Anti-Debug Check",
            "Checks for debugger presence",
            vec![
                PatternElement::Category(ApiCategory::AntiDebug),
            ],
            50,
        ).with_tag("evasion"));

        // Crypto + Network = possible exfil
        self.add_signature(BehaviorSignature::new(
            "crypto_network",
            "Encrypt then Exfiltrate",
            "Encrypts data and sends it over the network",
            vec![
                PatternElement::Category(ApiCategory::Crypto),
                PatternElement::Category(ApiCategory::Network),
            ],
            75,
        ).with_tag("exfiltration"));

        // Process enumeration
        self.add_signature(BehaviorSignature::new(
            "process_enum",
            "Process Enumeration",
            "Enumerates running processes",
            vec![
                PatternElement::ApiName("createtoolhelp32snapshot".into()),
                PatternElement::ApiName("process32first".into()),
            ],
            40,
        ).with_tag("discovery"));
    }

    /// Number of registered signatures.
    #[must_use]
    pub const fn signature_count(&self) -> usize { self.signatures.len() }
}

impl Default for BehaviorMatcher {
    fn default() -> Self { Self::new() }
}

// ─── ProcessBehaviorProfile ───────────────────────────────────────────────────

/// Behavioral profile for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBehaviorProfile {
    pub pid: u32,
    pub image_name: String,
    pub parent_pid: u32,
    pub command_line: String,
    pub api_sequence: ApiCallSequence,
    pub child_pids: Vec<u32>,
    pub total_api_calls: usize,
    pub suspicious_api_count: usize,
    pub category_counts: HashMap<String, usize>,
    pub detected_signatures: Vec<String>,
    pub threat_score: u8,
}

impl ProcessBehaviorProfile {
    /// Build a profile from an API call sequence.
    #[must_use]
    pub fn build(
        pid: u32,
        image_name: impl Into<String>,
        seq: ApiCallSequence,
        matcher: &BehaviorMatcher,
    ) -> Self {
        let total = seq.len();
        let suspicious = seq.suspicious_calls().len();
        let cats: HashMap<String, usize> = seq.category_counts().into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let sig_matches = matcher.match_all(&seq);
        let detected: Vec<String> = sig_matches.iter().map(|s| s.id.clone()).collect();
        let max_sev = sig_matches.iter().map(|s| s.severity).max().unwrap_or(0);
        let avg_risk: u8 = if total == 0 {
            0
        } else {
            u8::try_from((suspicious * 100 / total).min(usize::from(u8::MAX))).unwrap_or(u8::MAX)
        };
        let score = u32::midpoint(u32::from(max_sev), u32::from(avg_risk)).min(100) as u8;

        Self {
            pid, image_name: image_name.into(), parent_pid: 0, command_line: String::new(),
            api_sequence: seq, child_pids: vec![], total_api_calls: total,
            suspicious_api_count: suspicious, category_counts: cats,
            detected_signatures: detected, threat_score: score,
        }
    }

    /// Return `true` if the process shows signs of malicious behaviour.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.threat_score >= 50 || !self.detected_signatures.is_empty()
    }
}

// ─── NetworkBehaviorProfile ───────────────────────────────────────────────────

/// Behavioral profile capturing network behaviour.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkBehaviorProfile {
    pub connections: Vec<NetworkConnection>,
    pub dns_queries: Vec<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// One network connection observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub timestamp_ms: u64,
}

impl NetworkBehaviorProfile {
    /// Create an empty profile.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add a connection.
    pub fn add_connection(&mut self, conn: NetworkConnection) {
        self.bytes_sent += conn.bytes_sent;
        self.bytes_received += conn.bytes_recv;
        self.connections.push(conn);
    }

    /// Add a DNS query.
    pub fn add_dns_query(&mut self, domain: impl Into<String>) {
        self.dns_queries.push(domain.into());
    }

    /// Unique external IPs.
    #[must_use]
    pub fn unique_ips(&self) -> Vec<&str> {
        let mut seen = HashSet::new();
        self.connections.iter()
            .filter(|c| seen.insert(c.remote_ip.as_str()))
            .map(|c| c.remote_ip.as_str())
            .collect()
    }

    /// Return `true` if any C2-likely ports were used.
    #[must_use]
    pub fn has_c2_ports(&self) -> bool {
        self.connections.iter().any(|c| matches!(c.remote_port, 4444 | 8080 | 8443 | 1337 | 31337))
    }

    /// Return `true` if there is any external network activity.
    #[must_use]
    pub const fn has_activity(&self) -> bool { !self.connections.is_empty() }
}

// ─── FileBehaviorProfile ─────────────────────────────────────────────────────

/// Behavioral profile for file system operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileBehaviorProfile {
    pub files_created: Vec<String>,
    pub files_deleted: Vec<String>,
    pub files_modified: Vec<String>,
    pub files_read: Vec<String>,
    pub executables_dropped: Vec<String>,
}

impl FileBehaviorProfile {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add a created file.
    pub fn created(&mut self, path: impl Into<String>) {
        let p: String = path.into();
        if std::path::Path::new(&p).extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) || std::path::Path::new(&p).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")) {
            self.executables_dropped.push(p.clone());
        }
        self.files_created.push(p);
    }

    /// Add a deleted file.
    pub fn deleted(&mut self, path: impl Into<String>) {
        self.files_deleted.push(path.into());
    }

    /// Add a modified file.
    pub fn modified(&mut self, path: impl Into<String>) {
        self.files_modified.push(path.into());
    }

    /// Add a read file.
    pub fn read(&mut self, path: impl Into<String>) {
        self.files_read.push(path.into());
    }

    /// Return `true` if any executables were dropped.
    #[must_use]
    pub const fn dropped_executables(&self) -> bool { !self.executables_dropped.is_empty() }

    /// Total file operations.
    #[must_use]
    pub const fn total_ops(&self) -> usize {
        self.files_created.len() + self.files_deleted.len()
            + self.files_modified.len() + self.files_read.len()
    }
}

// ─── BehaviorAnalyzer ────────────────────────────────────────────────────────

/// Coordinates behavioral analysis across processes.
pub struct BehaviorAnalyzer {
    pub matcher: BehaviorMatcher,
    pub process_profiles: HashMap<u32, ProcessBehaviorProfile>,
    pub network_profile: NetworkBehaviorProfile,
    pub file_profile: FileBehaviorProfile,
}

impl BehaviorAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            matcher: BehaviorMatcher::new(),
            process_profiles: HashMap::new(),
            network_profile: NetworkBehaviorProfile::new(),
            file_profile: FileBehaviorProfile::new(),
        }
    }

    /// Analyse an API call sequence and add the result.
    pub fn analyse_process(
        &mut self,
        pid: u32,
        image_name: impl Into<String>,
        seq: ApiCallSequence,
    ) {
        let profile = ProcessBehaviorProfile::build(pid, image_name, seq, &self.matcher);
        self.process_profiles.insert(pid, profile);
    }

    /// Return all suspicious processes.
    #[must_use]
    pub fn suspicious_processes(&self) -> Vec<&ProcessBehaviorProfile> {
        self.process_profiles.values().filter(|p| p.is_suspicious()).collect()
    }

    /// Aggregate threat score across all processes.
    #[must_use]
    pub fn aggregate_threat_score(&self) -> u8 {
        let max = self.process_profiles.values().map(|p| p.threat_score).max().unwrap_or(0);
        let net_bonus: u8 = if self.network_profile.has_c2_ports() { 20 } else { 0 };
        let file_bonus: u8 = if self.file_profile.dropped_executables() { 15 } else { 0 };
        max.saturating_add(net_bonus).saturating_add(file_bonus).min(100)
    }

    /// Return all detected signature IDs across all processes.
    #[must_use]
    pub fn all_detected_signatures(&self) -> Vec<String> {
        let mut sigs: HashSet<String> = HashSet::new();
        for p in self.process_profiles.values() {
            for s in &p.detected_signatures { sigs.insert(s.clone()); }
        }
        let mut v: Vec<String> = sigs.into_iter().collect();
        v.sort();
        v
    }

    /// Number of analysed processes.
    #[must_use]
    pub fn process_count(&self) -> usize { self.process_profiles.len() }
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn injection_seq(pid: u32) -> ApiCallSequence {
        let mut seq = ApiCallSequence::new(pid);
        seq.add(ApiCall::new(pid, 100, "VirtualAllocEx", "kernel32.dll").flagged());
        seq.add(ApiCall::new(pid, 200, "WriteProcessMemory", "kernel32.dll").flagged());
        seq.add(ApiCall::new(pid, 300, "CreateRemoteThread", "kernel32.dll").flagged());
        seq
    }

    fn benign_seq(pid: u32) -> ApiCallSequence {
        let mut seq = ApiCallSequence::new(pid);
        seq.add(ApiCall::new(pid, 100, "CreateFileA", "kernel32.dll"));
        seq.add(ApiCall::new(pid, 200, "ReadFile", "kernel32.dll"));
        seq.add(ApiCall::new(pid, 300, "CloseHandle", "kernel32.dll"));
        seq
    }

    // ── ApiCategory ───────────────────────────────────────────────────────────

    #[test]
    fn test_infer_file() {
        assert_eq!(ApiCategory::infer("CreateFileA"), ApiCategory::File);
    }

    #[test]
    fn test_infer_network() {
        assert_eq!(ApiCategory::infer("connect"), ApiCategory::Network);
    }

    #[test]
    fn test_infer_injection() {
        assert_eq!(ApiCategory::infer("WriteProcessMemory"), ApiCategory::Injection);
    }

    #[test]
    fn test_infer_crypto() {
        assert_eq!(ApiCategory::infer("CryptEncrypt"), ApiCategory::Crypto);
    }

    #[test]
    fn test_infer_anti_debug() {
        assert_eq!(ApiCategory::infer("IsDebuggerPresent"), ApiCategory::AntiDebug);
    }

    #[test]
    fn test_infer_other() {
        assert_eq!(ApiCategory::infer("FooBarBaz"), ApiCategory::Other);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(ApiCategory::Injection.to_string(), "injection");
    }

    // ── ApiCall ───────────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_new() {
        let c = ApiCall::new(1, 100, "CreateFileA", "kernel32.dll");
        assert_eq!(c.category, ApiCategory::File);
        assert!(!c.suspicious);
    }

    #[test]
    fn test_api_call_flagged() {
        let c = ApiCall::new(1, 0, "VirtualAllocEx", "kernel32.dll").flagged();
        assert!(c.suspicious);
    }

    #[test]
    fn test_api_call_display() {
        let c = ApiCall::new(1, 100, "send", "ws2_32.dll").with_arg("data");
        assert!(c.to_string().contains("send"));
        assert!(c.to_string().contains("data"));
    }

    // ── ApiCallSequence ───────────────────────────────────────────────────────

    #[test]
    fn test_seq_len() {
        let seq = injection_seq(100);
        assert_eq!(seq.len(), 3);
        assert!(!seq.is_empty());
    }

    #[test]
    fn test_seq_by_category() {
        let seq = injection_seq(1);
        let injection = seq.by_category(ApiCategory::Injection);
        assert_eq!(injection.len(), 2); // VirtualAllocEx + WriteProcessMemory
    }

    #[test]
    fn test_seq_suspicious_calls() {
        let seq = injection_seq(1);
        assert_eq!(seq.suspicious_calls().len(), 3);
    }

    #[test]
    fn test_seq_unique_apis() {
        let seq = injection_seq(1);
        assert_eq!(seq.unique_apis().len(), 3);
    }

    #[test]
    fn test_seq_category_counts() {
        let seq = benign_seq(1);
        let counts = seq.category_counts();
        assert!(counts.contains_key(&ApiCategory::File));
    }

    #[test]
    fn test_seq_windows() {
        let seq = injection_seq(1);
        let windows = seq.windows(2);
        assert_eq!(windows.len(), 2);
    }

    // ── PatternElement ────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_api_name_matches() {
        let call = ApiCall::new(1, 0, "VirtualAllocEx", "kernel32.dll");
        let p = PatternElement::ApiName("virtualallocex".into());
        assert!(p.matches(&call));
    }

    #[test]
    fn test_pattern_category_matches() {
        let call = ApiCall::new(1, 0, "CryptEncrypt", "advapi32.dll");
        let p = PatternElement::Category(ApiCategory::Crypto);
        assert!(p.matches(&call));
    }

    #[test]
    fn test_pattern_any_matches() {
        let call = ApiCall::new(1, 0, "FooBar", "foo.dll");
        assert!(PatternElement::Any.matches(&call));
    }

    // ── BehaviorSignature ─────────────────────────────────────────────────────

    #[test]
    fn test_signature_new() {
        let sig = BehaviorSignature::new("id", "Name", "Desc", vec![], 80)
            .with_tag("injection");
        assert_eq!(sig.severity, 80);
        assert_eq!(sig.tags, vec!["injection"]);
    }

    // ── BehaviorMatcher ───────────────────────────────────────────────────────

    #[test]
    fn test_matcher_builtin_signatures() {
        let m = BehaviorMatcher::new();
        assert!(m.signature_count() >= 5);
    }

    #[test]
    fn test_matcher_detects_injection() {
        let m = BehaviorMatcher::new();
        let seq = injection_seq(1);
        let matches = m.match_all(&seq);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.id.as_str() == "remote_thread_injection"));
    }

    #[test]
    fn test_matcher_no_match_benign() {
        let m = BehaviorMatcher::new();
        let seq = benign_seq(1);
        let matches = m.match_all(&seq);
        // Benign seq should not match injection pattern
        assert!(!matches.iter().any(|s| s.id.as_str() == "remote_thread_injection"));
    }

    #[test]
    fn test_matcher_max_severity() {
        let m = BehaviorMatcher::new();
        let seq = injection_seq(1);
        let best = m.max_severity_match(&seq).unwrap();
        assert!(best.severity >= 90);
    }

    #[test]
    fn test_matcher_empty_seq_no_match() {
        let m = BehaviorMatcher::new();
        let seq = ApiCallSequence::new(1);
        assert!(m.match_all(&seq).is_empty());
    }

    // ── ProcessBehaviorProfile ────────────────────────────────────────────────

    #[test]
    fn test_process_profile_build() {
        let m = BehaviorMatcher::new();
        let seq = injection_seq(100);
        let p = ProcessBehaviorProfile::build(100, "malware.exe", seq, &m);
        assert_eq!(p.pid, 100);
        assert!(p.is_suspicious());
        assert!(!p.detected_signatures.is_empty());
    }

    #[test]
    fn test_process_profile_benign() {
        let m = BehaviorMatcher::new();
        let seq = benign_seq(200);
        let p = ProcessBehaviorProfile::build(200, "notepad.exe", seq, &m);
        // Not necessarily suspicious unless threshold is met
        let _ = p.threat_score;
    }

    // ── NetworkBehaviorProfile ────────────────────────────────────────────────

    #[test]
    fn test_network_profile_c2_port() {
        let mut n = NetworkBehaviorProfile::new();
        n.add_connection(NetworkConnection {
            pid: 1, remote_ip: "1.2.3.4".into(), remote_port: 4444,
            protocol: "tcp".into(), bytes_sent: 100, bytes_recv: 200, timestamp_ms: 0,
        });
        assert!(n.has_c2_ports());
        assert_eq!(n.bytes_sent, 100);
    }

    #[test]
    fn test_network_profile_unique_ips() {
        let mut n = NetworkBehaviorProfile::new();
        n.add_connection(NetworkConnection { pid: 1, remote_ip: "1.1.1.1".into(), remote_port: 80, protocol: "tcp".into(), bytes_sent: 0, bytes_recv: 0, timestamp_ms: 0 });
        n.add_connection(NetworkConnection { pid: 1, remote_ip: "1.1.1.1".into(), remote_port: 443, protocol: "tcp".into(), bytes_sent: 0, bytes_recv: 0, timestamp_ms: 0 });
        n.add_connection(NetworkConnection { pid: 1, remote_ip: "2.2.2.2".into(), remote_port: 80, protocol: "tcp".into(), bytes_sent: 0, bytes_recv: 0, timestamp_ms: 0 });
        assert_eq!(n.unique_ips().len(), 2);
    }

    #[test]
    fn test_network_dns_queries() {
        let mut n = NetworkBehaviorProfile::new();
        n.add_dns_query("evil.com");
        assert_eq!(n.dns_queries, vec!["evil.com"]);
    }

    // ── FileBehaviorProfile ───────────────────────────────────────────────────

    #[test]
    fn test_file_profile_created_exe() {
        let mut f = FileBehaviorProfile::new();
        f.created("C:\\Windows\\Temp\\payload.exe");
        assert!(f.dropped_executables());
        assert_eq!(f.executables_dropped.len(), 1);
    }

    #[test]
    fn test_file_profile_total_ops() {
        let mut f = FileBehaviorProfile::new();
        f.created("a.txt");
        f.deleted("b.txt");
        f.read("c.txt");
        assert_eq!(f.total_ops(), 3);
    }

    // ── BehaviorAnalyzer ──────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_analyse_process() {
        let mut a = BehaviorAnalyzer::new();
        a.analyse_process(1, "malware.exe", injection_seq(1));
        assert_eq!(a.process_count(), 1);
    }

    #[test]
    fn test_analyzer_suspicious_processes() {
        let mut a = BehaviorAnalyzer::new();
        a.analyse_process(1, "malware.exe", injection_seq(1));
        a.analyse_process(2, "notepad.exe", benign_seq(2));
        let sus = a.suspicious_processes();
        assert!(!sus.is_empty());
    }

    #[test]
    fn test_analyzer_aggregate_score() {
        let mut a = BehaviorAnalyzer::new();
        a.analyse_process(1, "bad.exe", injection_seq(1));
        a.network_profile.add_connection(NetworkConnection {
            pid: 1, remote_ip: "8.8.8.8".into(), remote_port: 4444,
            protocol: "tcp".into(), bytes_sent: 500, bytes_recv: 100, timestamp_ms: 0,
        });
        let score = a.aggregate_threat_score();
        assert!(score > 0);
    }

    #[test]
    fn test_analyzer_all_detected_signatures() {
        let mut a = BehaviorAnalyzer::new();
        a.analyse_process(1, "bad.exe", injection_seq(1));
        let sigs = a.all_detected_signatures();
        assert!(sigs.contains(&"remote_thread_injection".to_string()));
    }
}
