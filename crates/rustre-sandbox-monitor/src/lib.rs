//! `rustre-sandbox-monitor` — Real-time sandbox monitoring.
//!
//! Hooking layer, API call interception, event streaming, anomaly detection,
//! live behavioral analysis, ML-based classification of behavior sequences,
//! and a TCP server for receiving guest-agent API call events (§23.3).

pub mod anti_evasion_hooks;
pub mod api_call_analyzer;
pub mod behavior_classifier;
pub mod dll_injector;
pub mod ebpf_monitor;
pub mod process_tree_analyzer;
pub mod process_monitor;
pub mod file_monitor;
pub mod registry_monitor;
pub mod api_monitor;
pub mod registry_watcher;
pub mod file_tracker;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by monitor operations.
#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("hook failed: {0}")]
    HookFailed(String),
    #[error("record error: {0}")]
    RecordError(String),
    #[error("event stream closed")]
    StreamClosed,
    #[error("classification error: {0}")]
    ClassificationError(String),
    #[error("anomaly detection error: {0}")]
    AnomalyError(String),
    #[error("not initialized: {0}")]
    NotInitialized(String),
}

// ─── ApiCategory ─────────────────────────────────────────────────────────────

/// High-level category for an intercepted API call.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    FileSystem,
    Network,
    Registry,
    Process,
    Memory,
    Crypto,
    System,
    Synchronization,
    Token,
    Gui,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Network => write!(f, "network"),
            Self::Registry => write!(f, "registry"),
            Self::Process => write!(f, "process"),
            Self::Memory => write!(f, "memory"),
            Self::Crypto => write!(f, "crypto"),
            Self::System => write!(f, "system"),
            Self::Synchronization => write!(f, "synchronization"),
            Self::Token => write!(f, "token"),
            Self::Gui => write!(f, "gui"),
        }
    }
}

// ─── ApiCall ─────────────────────────────────────────────────────────────────

/// A single intercepted API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    pub name: String,
    pub category: ApiCategory,
    pub pid: u32,
    pub tid: u32,
    pub ts_ms: u64,
    pub args: Vec<String>,
    pub ret: Option<i64>,
    pub suspicious: bool,
    pub call_stack: Vec<String>,
}

impl ApiCall {
    /// Create a new `ApiCall` with default values.
    #[must_use]
    pub fn new(name: impl Into<String>, cat: ApiCategory, pid: u32) -> Self {
        Self {
            name: name.into(),
            category: cat,
            pid,
            tid: 0,
            ts_ms: 0,
            args: vec![],
            ret: None,
            suspicious: false,
            call_stack: vec![],
        }
    }

    /// Builder method — add an argument.
    #[must_use]
    pub fn with_arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Builder method — set return value.
    #[must_use]
    pub const fn with_ret(mut self, r: i64) -> Self {
        self.ret = Some(r);
        self
    }

    /// Builder method — set timestamp.
    #[must_use]
    pub const fn with_ts(mut self, ts: u64) -> Self {
        self.ts_ms = ts;
        self
    }

    /// Builder method — add a stack frame.
    #[must_use]
    pub fn with_frame(mut self, frame: impl Into<String>) -> Self {
        self.call_stack.push(frame.into());
        self
    }

    /// Returns `true` if any argument contains the given substring.
    #[must_use]
    pub fn arg_contains(&self, s: &str) -> bool {
        self.args.iter().any(|a| a.contains(s))
    }
}

// ─── ApiHook ─────────────────────────────────────────────────────────────────

/// Defines how a particular API should be hooked and what patterns are suspicious.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHook {
    pub api: String,
    pub category: ApiCategory,
    pub suspicious_patterns: Vec<String>,
    /// If `true`, every call to this API is always flagged (no pattern needed).
    pub always_suspicious: bool,
    /// Weight for anomaly scoring (0–100).
    pub anomaly_weight: u8,
}

impl ApiHook {
    /// Create a hook that fires on pattern match.
    #[must_use]
    pub fn new(api: impl Into<String>, cat: ApiCategory) -> Self {
        Self {
            api: api.into(),
            category: cat,
            suspicious_patterns: vec![],
            always_suspicious: false,
            anomaly_weight: 50,
        }
    }

    /// Always flag calls to this API.
    #[must_use]
    pub const fn always(mut self) -> Self {
        self.always_suspicious = true;
        self
    }

    /// Add a suspicious argument pattern.
    #[must_use]
    pub fn with_pattern(mut self, p: impl Into<String>) -> Self {
        self.suspicious_patterns.push(p.into());
        self
    }

    /// Set anomaly weight.
    #[must_use]
    pub const fn with_weight(mut self, w: u8) -> Self {
        self.anomaly_weight = w;
        self
    }

    /// Returns `true` if the given call matches this hook.
    #[must_use]
    pub fn is_suspicious(&self, call: &ApiCall) -> bool {
        if call.name != self.api {
            return false;
        }
        if self.always_suspicious {
            return true;
        }
        if self.suspicious_patterns.is_empty() {
            return false;
        }
        for pattern in &self.suspicious_patterns {
            for arg in &call.args {
                if arg.contains(pattern.as_str()) {
                    return true;
                }
            }
        }
        false
    }
}

// ─── MonitorConfig ────────────────────────────────────────────────────────────

/// Configuration controlling which event categories the monitor captures.
///
/// Each field corresponds to a category of Windows API calls that the monitor
/// intercepts via DetourHook-style function patching.  Disabling a category
/// reduces overhead but means the corresponding `MonitorEventKind` variants
/// will not be emitted during that session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Capture network connection and send/recv events
    /// (hooks: `WSAConnect`, `connect`, `WinHttpSendRequest`, …).
    pub trace_network: bool,
    /// Capture file open/read/write events
    /// (hooks: `NtCreateFile`, `CreateFileW`, `WriteFile`, …).
    pub trace_file_io: bool,
    /// Capture registry read/write/delete events
    /// (hooks: `RegSetValueExW`, `RegOpenKeyExW`, `RegDeleteKeyW`, …).
    pub trace_registry: bool,
    /// Capture process and thread creation events
    /// (hooks: `CreateProcessW`, `NtCreateThread`, `CreateRemoteThread`, …).
    pub trace_process_creation: bool,
}

impl MonitorConfig {
    /// Create a config with all categories enabled (default for full analysis).
    #[must_use]
    pub const fn all_enabled() -> Self {
        Self {
            trace_network: true,
            trace_file_io: true,
            trace_registry: true,
            trace_process_creation: true,
        }
    }

    /// Create a config with all categories disabled.
    #[must_use]
    pub const fn all_disabled() -> Self {
        Self {
            trace_network: false,
            trace_file_io: false,
            trace_registry: false,
            trace_process_creation: false,
        }
    }
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self::all_enabled()
    }
}

// ─── MonitorEvent ─────────────────────────────────────────────────────────────

/// An event emitted by the monitor (for streaming consumers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub kind: MonitorEventKind,
    pub pid: u32,
}

/// The payload of a monitor event.
///
/// Variants are emitted according to the active [`MonitorConfig`].  File I/O
/// variants require `trace_file_io`, network variants require `trace_network`,
/// registry variants require `trace_registry`, and process variants require
/// `trace_process_creation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitorEventKind {
    /// A raw Windows API call was intercepted.
    ApiCallEvent(ApiCall),
    /// A process has started (first observed by the guest agent).
    ProcessStart { pid: u32, image: String },
    /// A process has exited.
    ProcessExit { pid: u32, exit_code: i32 },
    /// A file was opened for reading or writing.
    /// Requires [`MonitorConfig::trace_file_io`].
    FileOpen { path: String },
    /// Data was written to a file.
    /// Requires [`MonitorConfig::trace_file_io`].
    FileWrite { path: String, size: u64 },
    /// An outbound network connection was established.
    /// Requires [`MonitorConfig::trace_network`].
    NetworkConnect { host: String, port: u16 },
    /// A new child process was spawned.
    /// Requires [`MonitorConfig::trace_process_creation`].
    ProcessCreate { name: String, cmdline: String },
    /// A registry value was created or modified.
    /// Requires [`MonitorConfig::trace_registry`].
    RegistrySet { key: String, value: String },
    /// An anomaly was detected by the scoring engine.
    Anomaly { score: f64, reason: String },
}

impl fmt::Display for MonitorEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiCallEvent(c) => write!(f, "api_call:{}", c.name),
            Self::ProcessStart { pid, image } => write!(f, "process_start:{pid}:{image}"),
            Self::ProcessExit { pid, exit_code } => write!(f, "process_exit:{pid}:{exit_code}"),
            Self::FileOpen { path } => write!(f, "file_open:{path}"),
            Self::FileWrite { path, size } => write!(f, "file_write:{path}:{size}"),
            Self::NetworkConnect { host, port } => write!(f, "net_connect:{host}:{port}"),
            Self::ProcessCreate { name, cmdline } => write!(f, "process_create:{name}:{cmdline}"),
            Self::RegistrySet { key, value } => write!(f, "reg_set:{key}:{value}"),
            Self::Anomaly { score, reason } => write!(f, "anomaly:{score:.2}:{reason}"),
        }
    }
}

// ─── EventStream ─────────────────────────────────────────────────────────────

/// A bounded ring buffer of monitor events.
pub struct EventStream {
    buf: Mutex<VecDeque<MonitorEvent>>,
    capacity: usize,
    seq: AtomicU64,
    dropped: AtomicU64,
}

impl EventStream {
    /// Create a new stream with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            seq: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Push a new event onto the stream. If full, drops the oldest event.
    pub fn push(&self, pid: u32, ts_ms: u64, kind: MonitorEventKind) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ev = MonitorEvent {
            seq,
            ts_ms,
            kind,
            pid,
        };
        let mut buf = self.buf.lock();
        if buf.len() >= self.capacity {
            buf.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        buf.push_back(ev);
    }

    /// Drain all events, returning them in order.
    #[must_use]
    pub fn drain(&self) -> Vec<MonitorEvent> {
        self.buf.lock().drain(..).collect()
    }

    /// Peek at all current events without consuming them.
    #[must_use]
    pub fn peek(&self) -> Vec<MonitorEvent> {
        self.buf.lock().iter().cloned().collect()
    }

    /// Current number of events in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.lock().len()
    }

    /// Returns `true` if the stream has no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.lock().is_empty()
    }

    /// Number of events dropped due to buffer overflow.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Total events ever pushed (including dropped).
    #[must_use]
    pub fn total_pushed(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}

// ─── BehaviorSequence ─────────────────────────────────────────────────────────

/// A temporal sequence of API call names for ML classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSequence {
    pub pid: u32,
    pub calls: Vec<String>,
    pub window_ms: u64,
    pub start_ms: u64,
}

impl BehaviorSequence {
    /// Create an empty sequence for a process.
    #[must_use]
    pub const fn new(pid: u32, start_ms: u64, window_ms: u64) -> Self {
        Self {
            pid,
            calls: vec![],
            window_ms,
            start_ms,
        }
    }

    /// Append a call name.
    pub fn push(&mut self, name: impl Into<String>) {
        self.calls.push(name.into());
    }

    /// Number of calls in this sequence.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.calls.len()
    }

    /// Returns `true` if the sequence is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// Count occurrences of a call name.
    #[must_use]
    pub fn count(&self, name: &str) -> usize {
        self.calls.iter().filter(|c| c.as_str() == name).count()
    }

    /// Returns `true` if this sequence contains all of the given subsequence
    /// in order (not necessarily contiguous).
    #[must_use]
    pub fn contains_subsequence(&self, sub: &[&str]) -> bool {
        let mut sub_iter = sub.iter();
        let Some(mut target) = sub_iter.next() else {
            return true;
        };
        for call in &self.calls {
            if call == *target {
                match sub_iter.next() {
                    Some(next) => target = next,
                    None => return true,
                }
            }
        }
        false
    }

    /// Compute a simple n-gram frequency map.
    #[must_use]
    pub fn ngrams(&self, n: usize) -> HashMap<Vec<String>, usize> {
        let mut freq: HashMap<Vec<String>, usize> = HashMap::new();
        if self.calls.len() < n {
            return freq;
        }
        for window in self.calls.windows(n) {
            *freq.entry(window.to_vec()).or_insert(0) += 1;
        }
        freq
    }
}

// ─── ClassificationResult ─────────────────────────────────────────────────────

/// Result of ML-based classification of a behavior sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub label: String,
    pub confidence: f64,
    pub features: HashMap<String, f64>,
    pub top_indicators: Vec<String>,
}

impl ClassificationResult {
    /// Returns `true` if the classification confidence exceeds the threshold.
    #[must_use]
    pub fn is_confident(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }

    /// Returns `true` if the label is a malicious class.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        matches!(
            self.label.as_str(),
            "trojan" | "ransomware" | "spyware" | "injector" | "rootkit" | "worm" | "malicious"
        )
    }
}

// ─── FeatureExtractor ─────────────────────────────────────────────────────────

/// Extracts numerical features from a behavior sequence for classification.
#[derive(Debug, Clone, Default)]
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Extract a feature vector from a sequence.
    #[must_use]
    pub fn extract(&self, seq: &BehaviorSequence) -> HashMap<String, f64> {
        let mut feats = HashMap::new();
        let n = seq.len() as f64;
        if n == 0.0 {
            return feats;
        }

        // Raw counts for key API categories.
        let injection_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtMapViewOfSection",
        ];
        let crypto_apis = ["CryptEncrypt", "BCryptEncrypt", "AES", "RSA"];
        let net_apis = [
            "InternetConnect",
            "HttpSendRequest",
            "WinHttpSendRequest",
            "WSAConnect",
        ];
        let evasion_apis = [
            "IsDebuggerPresent",
            "NtQueryInformationProcess",
            "CheckRemoteDebuggerPresent",
            "CPUID",
        ];
        let persistence_apis = [
            "RegSetValue",
            "NtSetValueKey",
            "CreateService",
            "SHSetValue",
        ];
        let keylog_apis = ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"];
        let screen_apis = ["BitBlt", "GetDC", "CreateDC", "PrintWindow"];

        let inj_count: f64 = injection_apis.iter().map(|a| seq.count(a) as f64).sum();
        let crypt_count: f64 = crypto_apis.iter().map(|a| seq.count(a) as f64).sum();
        let net_count: f64 = net_apis.iter().map(|a| seq.count(a) as f64).sum();
        let evasion_count: f64 = evasion_apis.iter().map(|a| seq.count(a) as f64).sum();
        let persist_count: f64 = persistence_apis.iter().map(|a| seq.count(a) as f64).sum();
        let keylog_count: f64 = keylog_apis.iter().map(|a| seq.count(a) as f64).sum();
        let screen_count: f64 = screen_apis.iter().map(|a| seq.count(a) as f64).sum();

        feats.insert("f_injection".to_string(), inj_count / n);
        feats.insert("f_crypto".to_string(), crypt_count / n);
        feats.insert("f_network".to_string(), net_count / n);
        feats.insert("f_evasion".to_string(), evasion_count / n);
        feats.insert("f_persistence".to_string(), persist_count / n);
        feats.insert("f_keylogging".to_string(), keylog_count / n);
        feats.insert("f_screenshot".to_string(), screen_count / n);
        feats.insert("f_total_calls".to_string(), n);
        feats.insert("f_unique_calls".to_string(), {
            let mut uniq: Vec<_> = seq.calls.clone();
            uniq.sort();
            uniq.dedup();
            uniq.len() as f64
        });
        feats
    }
}

// ─── RuleBasedClassifier ──────────────────────────────────────────────────────

/// A rule-based behavior classifier that uses feature thresholds.
#[derive(Debug, Clone)]
pub struct RuleBasedClassifier {
    /// Minimum feature value to trigger each rule.
    rules: Vec<ClassificationRule>,
}

#[derive(Debug, Clone)]
struct ClassificationRule {
    label: &'static str,
    feature: &'static str,
    threshold: f64,
    confidence: f64,
}

impl RuleBasedClassifier {
    /// Create a classifier with a default set of rules.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: vec![
                ClassificationRule {
                    label: "injector",
                    feature: "f_injection",
                    threshold: 0.01,
                    confidence: 0.85,
                },
                ClassificationRule {
                    label: "ransomware",
                    feature: "f_crypto",
                    threshold: 0.05,
                    confidence: 0.80,
                },
                ClassificationRule {
                    label: "spyware",
                    feature: "f_keylogging",
                    threshold: 0.01,
                    confidence: 0.90,
                },
                ClassificationRule {
                    label: "screenlogger",
                    feature: "f_screenshot",
                    threshold: 0.01,
                    confidence: 0.75,
                },
                ClassificationRule {
                    label: "evasive",
                    feature: "f_evasion",
                    threshold: 0.02,
                    confidence: 0.80,
                },
                ClassificationRule {
                    label: "downloader",
                    feature: "f_network",
                    threshold: 0.03,
                    confidence: 0.70,
                },
                ClassificationRule {
                    label: "apt",
                    feature: "f_persistence",
                    threshold: 0.02,
                    confidence: 0.75,
                },
            ],
        }
    }

    /// Classify features and return the best-match result.
    #[must_use]
    pub fn classify(&self, features: &HashMap<String, f64>) -> ClassificationResult {
        let mut best_label = "benign";
        let mut best_confidence = 0.3f64;
        let mut top_indicators = vec![];

        for rule in &self.rules {
            if let Some(&val) = features.get(rule.feature)
                && val >= rule.threshold
                && rule.confidence > best_confidence
            {
                best_confidence = rule.confidence;
                best_label = rule.label;
                top_indicators.push(format!("{}={:.4}", rule.feature, val));
            }
        }

        ClassificationResult {
            label: best_label.to_string(),
            confidence: best_confidence,
            features: features.clone(),
            top_indicators,
        }
    }
}

impl Default for RuleBasedClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AnomalyScore ─────────────────────────────────────────────────────────────

/// Anomaly score for a process at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub pid: u32,
    pub ts_ms: u64,
    pub score: f64,
    pub reasons: Vec<String>,
}

impl AnomalyScore {
    /// Returns `true` if the score exceeds the threshold.
    #[must_use]
    pub fn is_anomalous(&self, threshold: f64) -> bool {
        self.score >= threshold
    }
}

// ─── AnomalyDetector ──────────────────────────────────────────────────────────

/// Detects anomalies by scoring processes based on suspicious API call patterns.
#[derive(Debug)]
pub struct AnomalyDetector {
    /// Per-API anomaly weights.
    weights: HashMap<String, f64>,
    /// Threshold above which a process is considered anomalous.
    threshold: f64,
    /// Per-process running scores.
    scores: RwLock<HashMap<u32, f64>>,
}

impl AnomalyDetector {
    /// Create a new detector with default weights.
    #[must_use]
    pub fn new(threshold: f64) -> Self {
        let mut weights = HashMap::new();
        weights.insert("VirtualAllocEx".to_string(), 20.0);
        weights.insert("WriteProcessMemory".to_string(), 25.0);
        weights.insert("CreateRemoteThread".to_string(), 25.0);
        weights.insert("NtMapViewOfSection".to_string(), 15.0);
        weights.insert("IsDebuggerPresent".to_string(), 10.0);
        weights.insert("CryptEncrypt".to_string(), 12.0);
        weights.insert("BCryptEncrypt".to_string(), 12.0);
        weights.insert("SetWindowsHookEx".to_string(), 18.0);
        weights.insert("BitBlt".to_string(), 8.0);
        weights.insert("RegSetValue".to_string(), 7.0);
        weights.insert("CreateService".to_string(), 15.0);
        weights.insert("WinHttpSendRequest".to_string(), 10.0);
        weights.insert("InternetConnect".to_string(), 8.0);
        weights.insert("NtSetInformationThread".to_string(), 20.0);
        Self {
            weights,
            threshold,
            scores: RwLock::new(HashMap::new()),
        }
    }

    /// Update the anomaly score for the process that made this call.
    pub fn observe(&self, call: &ApiCall) {
        if let Some(&weight) = self.weights.get(&call.name) {
            let mut scores = self.scores.write();
            let entry = scores.entry(call.pid).or_insert(0.0);
            *entry += weight;
        }
    }

    /// Retrieve the current score for a process.
    #[must_use]
    pub fn score_for(&self, pid: u32) -> f64 {
        self.scores.read().get(&pid).copied().unwrap_or(0.0)
    }

    /// Check if a process exceeds the anomaly threshold.
    #[must_use]
    pub fn is_anomalous(&self, pid: u32) -> bool {
        self.score_for(pid) >= self.threshold
    }

    /// Snapshot all anomalous processes.
    #[must_use]
    pub fn anomalous_processes(&self) -> Vec<AnomalyScore> {
        self.scores
            .read()
            .iter()
            .filter(|&(_, &s)| s >= self.threshold)
            .map(|(&pid, &score)| AnomalyScore {
                pid,
                ts_ms: 0,
                score,
                reasons: vec![format!("cumulative_score={score:.1}")],
            })
            .collect()
    }

    /// Reset the score for a process.
    pub fn reset(&self, pid: u32) {
        self.scores.write().remove(&pid);
    }
}

// ─── ApiMonitor ──────────────────────────────────────────────────────────────

/// Full API monitoring system: hooks + event stream + anomaly detection.
pub struct ApiMonitor {
    pub hooks: Vec<ApiHook>,
    pub calls: Mutex<Vec<ApiCall>>,
    pub stream: Arc<EventStream>,
    pub anomaly: Arc<AnomalyDetector>,
    call_counter: AtomicU64,
}

impl ApiMonitor {
    /// Create an empty monitor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hooks: vec![],
            calls: Mutex::new(vec![]),
            stream: Arc::new(EventStream::new(4096)),
            anomaly: Arc::new(AnomalyDetector::new(50.0)),
            call_counter: AtomicU64::new(0),
        }
    }

    /// Add a hook.
    pub fn add_hook(&mut self, h: ApiHook) {
        self.hooks.push(h);
    }

    /// Record an API call.
    /// - Marks it suspicious if any hook matches.
    /// - Updates anomaly scores.
    /// - Emits an event to the stream.
    pub fn record(&self, mut c: ApiCall) {
        for hook in &self.hooks {
            if hook.is_suspicious(&c) {
                c.suspicious = true;
                break;
            }
        }
        self.anomaly.observe(&c);
        let pid = c.pid;
        let ts = c.ts_ms;
        self.stream
            .push(pid, ts, MonitorEventKind::ApiCallEvent(c.clone()));
        self.call_counter.fetch_add(1, Ordering::Relaxed);
        self.calls.lock().push(c);
    }

    /// Record a process start event.
    pub fn record_process_start(&self, pid: u32, image: impl Into<String>, ts_ms: u64) {
        self.stream.push(
            pid,
            ts_ms,
            MonitorEventKind::ProcessStart {
                pid,
                image: image.into(),
            },
        );
    }

    /// Record a process exit event.
    pub fn record_process_exit(&self, pid: u32, exit_code: i32, ts_ms: u64) {
        self.stream
            .push(pid, ts_ms, MonitorEventKind::ProcessExit { pid, exit_code });
    }

    /// Record a network connection event.
    pub fn record_network(&self, pid: u32, remote: impl Into<String>, port: u16, ts_ms: u64) {
        self.stream.push(
            pid,
            ts_ms,
            MonitorEventKind::NetworkConnect {
                host: remote.into(),
                port,
            },
        );
    }

    /// Record a file open event (intercepted via `NtCreateFile` / `CreateFileW`).
    pub fn record_file_open(&self, pid: u32, path: impl Into<String>, ts_ms: u64) {
        self.stream
            .push(pid, ts_ms, MonitorEventKind::FileOpen { path: path.into() });
    }

    /// Record a file write event (intercepted via `NtWriteFile` / `WriteFile`).
    pub fn record_file_write(&self, pid: u32, path: impl Into<String>, size: u64, ts_ms: u64) {
        self.stream.push(
            pid,
            ts_ms,
            MonitorEventKind::FileWrite {
                path: path.into(),
                size,
            },
        );
    }

    /// Record a process creation event (intercepted via `CreateProcessW`).
    pub fn record_process_create(
        &self,
        pid: u32,
        name: impl Into<String>,
        cmdline: impl Into<String>,
        ts_ms: u64,
    ) {
        self.stream.push(
            pid,
            ts_ms,
            MonitorEventKind::ProcessCreate {
                name: name.into(),
                cmdline: cmdline.into(),
            },
        );
    }

    /// Record a registry value set event (intercepted via `RegSetValueExW`).
    pub fn record_registry_set(
        &self,
        pid: u32,
        key: impl Into<String>,
        value: impl Into<String>,
        ts_ms: u64,
    ) {
        self.stream.push(
            pid,
            ts_ms,
            MonitorEventKind::RegistrySet {
                key: key.into(),
                value: value.into(),
            },
        );
    }

    /// Return all suspicious calls.
    #[must_use]
    pub fn suspicious(&self) -> Vec<ApiCall> {
        self.calls
            .lock()
            .iter()
            .filter(|c| c.suspicious)
            .cloned()
            .collect()
    }

    /// Return all calls in the given category.
    #[must_use]
    pub fn by_category(&self, cat: &ApiCategory) -> Vec<ApiCall> {
        self.calls
            .lock()
            .iter()
            .filter(|c| &c.category == cat)
            .cloned()
            .collect()
    }

    /// Return all calls by a given process.
    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Vec<ApiCall> {
        self.calls
            .lock()
            .iter()
            .filter(|c| c.pid == pid)
            .cloned()
            .collect()
    }

    /// Return the total number of recorded calls.
    #[must_use]
    pub fn total(&self) -> usize {
        self.calls.lock().len()
    }

    /// Return call frequency map (name → count).
    #[must_use]
    pub fn call_frequency(&self) -> HashMap<String, usize> {
        let mut freq: HashMap<String, usize> = HashMap::new();
        for call in self.calls.lock().iter() {
            *freq.entry(call.name.clone()).or_insert(0) += 1;
        }
        freq
    }

    /// Build a behavior sequence for a specific process.
    #[must_use]
    pub fn behavior_sequence_for(&self, pid: u32) -> BehaviorSequence {
        let calls = self.calls.lock();
        let mut seq = BehaviorSequence::new(pid, 0, u64::MAX);
        for call in calls.iter().filter(|c| c.pid == pid) {
            seq.push(&call.name);
        }
        seq
    }

    /// Classify behavior for a specific process using the rule-based classifier.
    #[must_use]
    pub fn classify_pid(&self, pid: u32) -> ClassificationResult {
        let seq = self.behavior_sequence_for(pid);
        let extractor = FeatureExtractor::new();
        let features = extractor.extract(&seq);
        let classifier = RuleBasedClassifier::new();
        classifier.classify(&features)
    }

    /// Return all anomalous processes.
    #[must_use]
    pub fn anomalous_processes(&self) -> Vec<AnomalyScore> {
        self.anomaly.anomalous_processes()
    }

    /// Create a monitor pre-loaded with hooks for 16 common suspicious APIs.
    #[must_use]
    pub fn default_hooks() -> Self {
        let mut monitor = Self::new();
        let hooks: &[(&str, ApiCategory, &[&str], bool)] = &[
            (
                "CreateFile",
                ApiCategory::FileSystem,
                &["\\pipe\\", "\\device\\"],
                false,
            ),
            (
                "WriteFile",
                ApiCategory::FileSystem,
                &[".exe", ".dll", ".bat", ".ps1"],
                false,
            ),
            (
                "RegSetValue",
                ApiCategory::Registry,
                &["\\Run\\", "\\Services\\"],
                false,
            ),
            ("VirtualAllocEx", ApiCategory::Memory, &[], true),
            ("WriteProcessMemory", ApiCategory::Memory, &[], true),
            ("CreateRemoteThread", ApiCategory::Process, &[], true),
            ("NtMapViewOfSection", ApiCategory::Memory, &[], true),
            ("InternetConnect", ApiCategory::Network, &[], true),
            ("HttpSendRequest", ApiCategory::Network, &[], true),
            ("WinHttpSendRequest", ApiCategory::Network, &[], true),
            (
                "CreateProcess",
                ApiCategory::Process,
                &["cmd", "powershell", "wscript"],
                false,
            ),
            ("CryptEncrypt", ApiCategory::Crypto, &[], true),
            ("BCryptEncrypt", ApiCategory::Crypto, &[], true),
            ("SetWindowsHookEx", ApiCategory::Gui, &[], true),
            ("WinExec", ApiCategory::System, &[], true),
            (
                "ShellExecute",
                ApiCategory::System,
                &["cmd", "powershell"],
                false,
            ),
        ];
        for (api, cat, patterns, always) in hooks {
            let mut hook = ApiHook::new(*api, cat.clone());
            if *always {
                hook = hook.always();
            }
            for p in *patterns {
                hook = hook.with_pattern(*p);
            }
            monitor.add_hook(hook);
        }
        monitor
    }
}

impl Default for ApiMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Monitor ─────────────────────────────────────────────────────────────────

/// Top-level monitor that integrates the API monitor, classifier, and event loop.
pub struct Monitor {
    pub api_monitor: ApiMonitor,
    pub classifier: RuleBasedClassifier,
    pub extractor: FeatureExtractor,
    pub running: Arc<RwLock<bool>>,
    pub events_processed: AtomicU64,
    /// Runtime configuration that controls which event categories are captured.
    pub config: MonitorConfig,
}

impl Monitor {
    /// Create a new monitor with default hooks and all tracing categories enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            api_monitor: ApiMonitor::default_hooks(),
            classifier: RuleBasedClassifier::new(),
            extractor: FeatureExtractor::new(),
            running: Arc::new(RwLock::new(false)),
            events_processed: AtomicU64::new(0),
            config: MonitorConfig::default(),
        }
    }

    /// Create a monitor with a specific [`MonitorConfig`].
    #[must_use]
    pub fn with_config(config: MonitorConfig) -> Self {
        let mut m = Self::new();
        m.config = config;
        m
    }

    /// Start monitoring.
    pub fn start(&self) {
        *self.running.write() = true;
    }

    /// Stop monitoring.
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Returns `true` if the monitor is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Record an API call and update internal state.
    pub fn observe_call(&self, call: ApiCall) {
        self.api_monitor.record(call);
        self.events_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Classify all observed behavior for a PID.
    #[must_use]
    pub fn classify(&self, pid: u32) -> ClassificationResult {
        self.api_monitor.classify_pid(pid)
    }

    /// Return a summary of all suspicious activity.
    #[must_use]
    pub fn suspicious_summary(&self) -> MonitorSummary {
        let suspicious = self.api_monitor.suspicious();
        let anomalous = self.api_monitor.anomalous_processes();
        let freq = self.api_monitor.call_frequency();
        MonitorSummary {
            total_calls: self.api_monitor.total(),
            suspicious_calls: suspicious.len(),
            anomalous_pids: anomalous.len(),
            top_apis: top_n_by_freq(&freq, 5),
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of monitor observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSummary {
    pub total_calls: usize,
    pub suspicious_calls: usize,
    pub anomalous_pids: usize,
    pub top_apis: Vec<(String, usize)>,
}

/// Return the top-N entries from a frequency map.
fn top_n_by_freq(freq: &HashMap<String, usize>, n: usize) -> Vec<(String, usize)> {
    let mut pairs: Vec<_> = freq.iter().map(|(k, &v)| (k.clone(), v)).collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1));
    pairs.truncate(n);
    pairs
}

// ─── §23.3 Guest-Agent API Monitoring Infrastructure ─────────────────────────

// ── ArgType / ApiCategory (signature database) ───────────────────────────────

/// The type of a single argument or return value in a Windows API signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgType {
    Handle,
    Ptr,
    Dword,
    QWord,
    String,
    Bool,
    Void,
    SizeT,
    LpVoid,
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handle => write!(f, "HANDLE"),
            Self::Ptr => write!(f, "PVOID"),
            Self::Dword => write!(f, "DWORD"),
            Self::QWord => write!(f, "QWORD"),
            Self::String => write!(f, "LPCSTR"),
            Self::Bool => write!(f, "BOOL"),
            Self::Void => write!(f, "VOID"),
            Self::SizeT => write!(f, "SIZE_T"),
            Self::LpVoid => write!(f, "LPVOID"),
        }
    }
}

/// Signature category — mirrors `ApiCategory` but is `'static` friendly for
/// embedding in the `MONITORED_APIS` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigCategory {
    FileSystem,
    Registry,
    Network,
    Process,
    Memory,
    Crypto,
    Debug,
    Ui,
}

impl fmt::Display for SigCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "filesystem"),
            Self::Registry => write!(f, "registry"),
            Self::Network => write!(f, "network"),
            Self::Process => write!(f, "process"),
            Self::Memory => write!(f, "memory"),
            Self::Crypto => write!(f, "crypto"),
            Self::Debug => write!(f, "debug"),
            Self::Ui => write!(f, "ui"),
        }
    }
}

// ── ApiSignature ──────────────────────────────────────────────────────────────

/// A static Windows API signature used by the guest-agent monitoring database.
#[derive(Debug, Clone, Copy)]
pub struct ApiSignature {
    pub dll: &'static str,
    pub name: &'static str,
    pub arg_count: u8,
    pub arg_types: &'static [ArgType],
    pub ret_type: ArgType,
    pub category: SigCategory,
}

/// 50-entry monitored Windows API signature database.
pub static MONITORED_APIS: &[ApiSignature] = &[
    // ── FileSystem (ntdll / kernel32) ─────────────────────────────────────
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtCreateFile",
        arg_count: 11,
        arg_types: &[
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtReadFile",
        arg_count: 9,
        arg_types: &[
            ArgType::Handle,
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtWriteFile",
        arg_count: 9,
        arg_types: &[
            ArgType::Handle,
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtClose",
        arg_count: 1,
        arg_types: &[ArgType::Handle],
        ret_type: ArgType::Dword,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "CreateFileW",
        arg_count: 7,
        arg_types: &[
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Handle,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "ReadFile",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "WriteFile",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "DeleteFileW",
        arg_count: 1,
        arg_types: &[ArgType::String],
        ret_type: ArgType::Bool,
        category: SigCategory::FileSystem,
    },
    // ── Registry (advapi32) ───────────────────────────────────────────────
    ApiSignature {
        dll: "advapi32.dll",
        name: "RegOpenKeyExW",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Registry,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "RegQueryValueExW",
        arg_count: 6,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Registry,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "RegSetValueExW",
        arg_count: 6,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Registry,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "RegDeleteKeyW",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::String],
        ret_type: ArgType::Dword,
        category: SigCategory::Registry,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "RegCreateKeyExW",
        arg_count: 9,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::Dword,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Registry,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "RegDeleteValueW",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::String],
        ret_type: ArgType::Dword,
        category: SigCategory::Registry,
    },
    // ── Network (ws2_32 / winhttp) ────────────────────────────────────────
    ApiSignature {
        dll: "ws2_32.dll",
        name: "WSAConnect",
        arg_count: 7,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "ws2_32.dll",
        name: "send",
        arg_count: 4,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "ws2_32.dll",
        name: "recv",
        arg_count: 4,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "ws2_32.dll",
        name: "connect",
        arg_count: 3,
        arg_types: &[ArgType::Handle, ArgType::Ptr, ArgType::Dword],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "ws2_32.dll",
        name: "bind",
        arg_count: 3,
        arg_types: &[ArgType::Handle, ArgType::Ptr, ArgType::Dword],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "winhttp.dll",
        name: "WinHttpConnect",
        arg_count: 4,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "winhttp.dll",
        name: "WinHttpSendRequest",
        arg_count: 7,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Network,
    },
    // ── Process (kernel32 / ntdll) ────────────────────────────────────────
    ApiSignature {
        dll: "kernel32.dll",
        name: "CreateProcessW",
        arg_count: 10,
        arg_types: &[
            ArgType::String,
            ArgType::String,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Bool,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::String,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "OpenProcess",
        arg_count: 3,
        arg_types: &[ArgType::Dword, ArgType::Bool, ArgType::Dword],
        ret_type: ArgType::Handle,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "TerminateProcess",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Dword],
        ret_type: ArgType::Bool,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "CreateThread",
        arg_count: 6,
        arg_types: &[
            ArgType::Ptr,
            ArgType::SizeT,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "CreateRemoteThread",
        arg_count: 7,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::SizeT,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "OpenThread",
        arg_count: 3,
        arg_types: &[ArgType::Dword, ArgType::Bool, ArgType::Dword],
        ret_type: ArgType::Handle,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "WriteProcessMemory",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::LpVoid,
            ArgType::LpVoid,
            ArgType::SizeT,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Process,
    },
    // ── Memory (kernel32 / ntdll) ─────────────────────────────────────────
    ApiSignature {
        dll: "kernel32.dll",
        name: "VirtualAlloc",
        arg_count: 4,
        arg_types: &[
            ArgType::LpVoid,
            ArgType::SizeT,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::LpVoid,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "VirtualAllocEx",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::LpVoid,
            ArgType::SizeT,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::LpVoid,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "VirtualFree",
        arg_count: 3,
        arg_types: &[ArgType::LpVoid, ArgType::SizeT, ArgType::Dword],
        ret_type: ArgType::Bool,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "VirtualProtect",
        arg_count: 4,
        arg_types: &[
            ArgType::LpVoid,
            ArgType::SizeT,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "HeapAlloc",
        arg_count: 3,
        arg_types: &[ArgType::Handle, ArgType::Dword, ArgType::SizeT],
        ret_type: ArgType::LpVoid,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "HeapFree",
        arg_count: 3,
        arg_types: &[ArgType::Handle, ArgType::Dword, ArgType::LpVoid],
        ret_type: ArgType::Bool,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtAllocateVirtualMemory",
        arg_count: 6,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::QWord,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Memory,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtMapViewOfSection",
        arg_count: 10,
        arg_types: &[
            ArgType::Handle,
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::QWord,
            ArgType::SizeT,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Memory,
    },
    // ── Crypto (advapi32 / bcrypt) ────────────────────────────────────────
    ApiSignature {
        dll: "advapi32.dll",
        name: "CryptEncrypt",
        arg_count: 7,
        arg_types: &[
            ArgType::Handle,
            ArgType::Handle,
            ArgType::Bool,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Ptr,
            ArgType::Dword,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "CryptDecrypt",
        arg_count: 6,
        arg_types: &[
            ArgType::Handle,
            ArgType::Handle,
            ArgType::Bool,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "bcrypt.dll",
        name: "BCryptEncrypt",
        arg_count: 8,
        arg_types: &[
            ArgType::Handle,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "bcrypt.dll",
        name: "BCryptDecrypt",
        arg_count: 8,
        arg_types: &[
            ArgType::Handle,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "bcrypt.dll",
        name: "BCryptGenerateSymmetricKey",
        arg_count: 6,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "bcrypt.dll",
        name: "BCryptOpenAlgorithmProvider",
        arg_count: 3,
        arg_types: &[ArgType::Ptr, ArgType::String, ArgType::String],
        ret_type: ArgType::Dword,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "CryptGenRandom",
        arg_count: 3,
        arg_types: &[ArgType::Handle, ArgType::Dword, ArgType::LpVoid],
        ret_type: ArgType::Bool,
        category: SigCategory::Crypto,
    },
    // ── Anti-Debug (kernel32 / ntdll) ─────────────────────────────────────
    ApiSignature {
        dll: "kernel32.dll",
        name: "IsDebuggerPresent",
        arg_count: 0,
        arg_types: &[],
        ret_type: ArgType::Bool,
        category: SigCategory::Debug,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "CheckRemoteDebuggerPresent",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Ptr],
        ret_type: ArgType::Bool,
        category: SigCategory::Debug,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtQueryInformationProcess",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::Dword,
            ArgType::LpVoid,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Debug,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "OutputDebugStringW",
        arg_count: 1,
        arg_types: &[ArgType::String],
        ret_type: ArgType::Void,
        category: SigCategory::Debug,
    },
    // ── UI (user32) ───────────────────────────────────────────────────────
    ApiSignature {
        dll: "user32.dll",
        name: "MessageBoxW",
        arg_count: 4,
        arg_types: &[
            ArgType::Handle,
            ArgType::String,
            ArgType::String,
            ArgType::Dword,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Ui,
    },
    ApiSignature {
        dll: "user32.dll",
        name: "CreateWindowExW",
        arg_count: 12,
        arg_types: &[
            ArgType::Dword,
            ArgType::String,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Handle,
            ArgType::Handle,
            ArgType::Handle,
            ArgType::LpVoid,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::Ui,
    },
    ApiSignature {
        dll: "user32.dll",
        name: "ShowWindow",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Dword],
        ret_type: ArgType::Bool,
        category: SigCategory::Ui,
    },
    ApiSignature {
        dll: "user32.dll",
        name: "SetWindowsHookExW",
        arg_count: 4,
        arg_types: &[
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Handle,
            ArgType::Dword,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::Ui,
    },
    // ── Thread (ntdll) ───────────────────────────────────────────────────────
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtCreateThread",
        arg_count: 8,
        arg_types: &[
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Bool,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtSuspendThread",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Ptr],
        ret_type: ArgType::Dword,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "ntdll.dll",
        name: "NtResumeThread",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Ptr],
        ret_type: ArgType::Dword,
        category: SigCategory::Process,
    },
    // ── WinHTTP ──────────────────────────────────────────────────────────────
    ApiSignature {
        dll: "winhttp.dll",
        name: "WinHttpOpen",
        arg_count: 5,
        arg_types: &[
            ArgType::String,
            ArgType::Dword,
            ArgType::String,
            ArgType::String,
            ArgType::Dword,
        ],
        ret_type: ArgType::Handle,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "winhttp.dll",
        name: "WinHttpReceiveResponse",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::LpVoid],
        ret_type: ArgType::Bool,
        category: SigCategory::Network,
    },
    // ── Crypt32 / advapi32 ───────────────────────────────────────────────────
    ApiSignature {
        dll: "advapi32.dll",
        name: "CryptAcquireContextA",
        arg_count: 5,
        arg_types: &[
            ArgType::Ptr,
            ArgType::String,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Crypto,
    },
    ApiSignature {
        dll: "advapi32.dll",
        name: "CryptAcquireContextW",
        arg_count: 5,
        arg_types: &[
            ArgType::Ptr,
            ArgType::String,
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
        ],
        ret_type: ArgType::Bool,
        category: SigCategory::Crypto,
    },
    // ── SAM / Network user enum ──────────────────────────────────────────────
    ApiSignature {
        dll: "samsrv.dll",
        name: "SamOpenDomain",
        arg_count: 3,
        arg_types: &[ArgType::Handle, ArgType::Dword, ArgType::Ptr],
        ret_type: ArgType::Dword,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "samsrv.dll",
        name: "SamEnumerateUsersInDomain",
        arg_count: 6,
        arg_types: &[
            ArgType::Handle,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Process,
    },
    ApiSignature {
        dll: "netapi32.dll",
        name: "NetUserEnum",
        arg_count: 7,
        arg_types: &[
            ArgType::String,
            ArgType::Dword,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    ApiSignature {
        dll: "netapi32.dll",
        name: "NetLocalGroupEnum",
        arg_count: 6,
        arg_types: &[
            ArgType::String,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Network,
    },
    // ── File enumeration (kernel32) ──────────────────────────────────────────
    ApiSignature {
        dll: "kernel32.dll",
        name: "FindFirstFileA",
        arg_count: 2,
        arg_types: &[ArgType::String, ArgType::Ptr],
        ret_type: ArgType::Handle,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "FindFirstFileW",
        arg_count: 2,
        arg_types: &[ArgType::String, ArgType::Ptr],
        ret_type: ArgType::Handle,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "FindNextFileA",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Ptr],
        ret_type: ArgType::Bool,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "kernel32.dll",
        name: "FindNextFileW",
        arg_count: 2,
        arg_types: &[ArgType::Handle, ArgType::Ptr],
        ret_type: ArgType::Bool,
        category: SigCategory::FileSystem,
    },
    // ── Shell paths (shell32) ─────────────────────────────────────────────────
    ApiSignature {
        dll: "shell32.dll",
        name: "SHGetFolderPathA",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::Dword,
            ArgType::Handle,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::FileSystem,
    },
    ApiSignature {
        dll: "shell32.dll",
        name: "SHGetFolderPathW",
        arg_count: 5,
        arg_types: &[
            ArgType::Handle,
            ArgType::Dword,
            ArgType::Handle,
            ArgType::Dword,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::FileSystem,
    },
    // ── COM (ole32) ───────────────────────────────────────────────────────────
    ApiSignature {
        dll: "ole32.dll",
        name: "CoCreateInstance",
        arg_count: 5,
        arg_types: &[
            ArgType::Ptr,
            ArgType::Ptr,
            ArgType::Dword,
            ArgType::Ptr,
            ArgType::Ptr,
        ],
        ret_type: ArgType::Dword,
        category: SigCategory::Process,
    },
];

// ── ArgValue ──────────────────────────────────────────────────────────────────

/// A resolved argument or return value captured from a live API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArgValue {
    Handle(u64),
    Ptr(u64),
    Dword(u32),
    QWord(u64),
    Str(String),
    Bool(bool),
    Void,
    SizeT(usize),
    LpVoid(u64),
    Unknown(String),
}

impl fmt::Display for ArgValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handle(h) => write!(f, "HANDLE(0x{h:016x})"),
            Self::Ptr(p) => write!(f, "PTR(0x{p:016x})"),
            Self::Dword(d) => write!(f, "DWORD(0x{d:08x})"),
            Self::QWord(q) => write!(f, "QWORD(0x{q:016x})"),
            Self::Str(s) => write!(f, "{s:?}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Void => write!(f, "void"),
            Self::SizeT(s) => write!(f, "SIZE_T({s})"),
            Self::LpVoid(p) => write!(f, "LPVOID(0x{p:016x})"),
            Self::Unknown(u) => write!(f, "?({u})"),
        }
    }
}

// ── EnhancedApiCall ───────────────────────────────────────────────────────────

/// An enhanced API call record carrying resolved argument values, category, and
/// suspicion flag — suitable for guest-agent reporting (§23.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedApiCall {
    pub timestamp: u64,
    pub pid: u32,
    pub thread_id: u32,
    pub dll: String,
    pub function: String,
    pub args: Vec<ArgValue>,
    pub return_value: Option<ArgValue>,
    pub category: SigCategory,
    pub is_suspicious: bool,
}

impl EnhancedApiCall {
    /// Build from raw parts without inspecting signature database.
    #[must_use]
    pub fn new(
        timestamp: u64,
        pid: u32,
        thread_id: u32,
        dll: impl Into<String>,
        function: impl Into<String>,
        category: SigCategory,
    ) -> Self {
        Self {
            timestamp,
            pid,
            thread_id,
            dll: dll.into(),
            function: function.into(),
            args: vec![],
            return_value: None,
            category,
            is_suspicious: false,
        }
    }

    /// Append an argument value.
    #[must_use]
    pub fn with_arg(mut self, v: ArgValue) -> Self {
        self.args.push(v);
        self
    }

    /// Set the return value.
    #[must_use]
    pub fn with_return(mut self, v: ArgValue) -> Self {
        self.return_value = Some(v);
        self
    }

    /// Look up this call in `MONITORED_APIS` and tag category / suspicion.
    pub fn enrich_from_db(&mut self) {
        for sig in MONITORED_APIS {
            if sig.name == self.function.as_str() {
                self.category = sig.category;
                // Calls in Debug category are always suspicious.
                if matches!(sig.category, SigCategory::Debug) {
                    self.is_suspicious = true;
                }
                break;
            }
        }
    }
}

// ── SuspiciousPattern ─────────────────────────────────────────────────────────

/// A suspicious behavioral pattern identified by the analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuspiciousPattern {
    /// Classic process injection tri-pattern.
    ProcessInjection,
    /// Registry run-key persistence write.
    RunKeyPersistence,
    /// Periodic beaconing (regular send intervals).
    NetworkBeacon,
    /// Anti-debugging API detected.
    AntiDebug(String),
    /// Shellcode-like executable memory allocation.
    ExecutableMemory,
    /// Encryption of large buffers (possible ransomware).
    BulkEncryption,
    /// Remote thread creation in a foreign process.
    RemoteThreadCreation,
    /// Suspicious process name passed to `CreateProcess`.
    SuspiciousChildProcess(String),
}

impl fmt::Display for SuspiciousPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessInjection => write!(f, "process_injection"),
            Self::RunKeyPersistence => write!(f, "run_key_persistence"),
            Self::NetworkBeacon => write!(f, "network_beacon"),
            Self::AntiDebug(api) => write!(f, "anti_debug:{api}"),
            Self::ExecutableMemory => write!(f, "executable_memory"),
            Self::BulkEncryption => write!(f, "bulk_encryption"),
            Self::RemoteThreadCreation => write!(f, "remote_thread_creation"),
            Self::SuspiciousChildProcess(n) => write!(f, "suspicious_child:{n}"),
        }
    }
}

// ── ApiCallAnalyzer ───────────────────────────────────────────────────────────

/// Analyzes sequences of `EnhancedApiCall` records for malicious patterns and
/// maps them to MITRE ATT&CK techniques.
#[derive(Debug, Default)]
pub struct ApiCallAnalyzer;

impl ApiCallAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify a single call and return all matching patterns.
    #[must_use]
    pub fn classify_call(call: &EnhancedApiCall) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();

        // Anti-debug APIs
        let anti_debug = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringW",
        ];
        if anti_debug.contains(&call.function.as_str()) {
            patterns.push(SuspiciousPattern::AntiDebug(call.function.clone()));
        }

        // Remote thread creation
        if call.function == "CreateRemoteThread" {
            patterns.push(SuspiciousPattern::RemoteThreadCreation);
        }

        // Executable memory (VirtualAlloc/Ex with PAGE_EXECUTE_* flags)
        if matches!(call.function.as_str(), "VirtualAlloc" | "VirtualAllocEx") {
            // Arg index 3 (VirtualAlloc) or 4 (VirtualAllocEx) is the protection flag.
            // PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20.
            let exec_flags: &[u32] = &[0x10, 0x20, 0x40, 0x80];
            let prot_arg_idx = if call.function == "VirtualAllocEx" {
                4
            } else {
                3
            };
            if let Some(ArgValue::Dword(flags)) = call.args.get(prot_arg_idx)
                && exec_flags.contains(flags)
            {
                patterns.push(SuspiciousPattern::ExecutableMemory);
            }
        }

        // Suspicious child processes
        if call.function == "CreateProcessW" {
            let suspicious_names = [
                "cmd.exe",
                "powershell.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "regsvr32.exe",
            ];
            for arg in &call.args {
                if let ArgValue::Str(s) = arg {
                    let lower = s.to_lowercase();
                    for name in suspicious_names {
                        if lower.contains(name) {
                            patterns
                                .push(SuspiciousPattern::SuspiciousChildProcess(name.to_string()));
                        }
                    }
                }
            }
        }

        // Bulk encryption
        if matches!(call.function.as_str(), "CryptEncrypt" | "BCryptEncrypt") {
            // Arg 6 (CryptEncrypt) / arg 2 (BCryptEncrypt) is the buffer length.
            let len_idx = if call.function == "CryptEncrypt" {
                6
            } else {
                2
            };
            if let Some(ArgValue::Dword(len)) = call.args.get(len_idx)
                && *len > 65536
            {
                patterns.push(SuspiciousPattern::BulkEncryption);
            }
        }

        patterns
    }

    /// Detect classic process injection:
    /// `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`, in order.
    #[must_use]
    pub fn detect_injection(calls: &[EnhancedApiCall]) -> bool {
        let mut saw_alloc = false;
        let mut saw_write = false;
        let mut saw_thread = false;
        for call in calls {
            match call.function.as_str() {
                "VirtualAllocEx" => {
                    saw_alloc = true;
                }
                "WriteProcessMemory" => {
                    if saw_alloc {
                        saw_write = true;
                    }
                }
                "CreateRemoteThread" => {
                    if saw_write {
                        saw_thread = true;
                    }
                }
                _ => {}
            }
        }
        saw_thread
    }

    /// Detect persistence via common Run-key registry writes.
    #[must_use]
    pub fn detect_persistence(calls: &[EnhancedApiCall]) -> Vec<String> {
        let run_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SYSTEM\CurrentControlSet\Services",
        ];
        let mut found = Vec::new();
        for call in calls {
            if call.function == "RegSetValueExW" {
                for arg in &call.args {
                    if let ArgValue::Str(s) = arg {
                        for key in run_keys {
                            if s.to_uppercase().contains(&key.to_uppercase()) {
                                found.push(s.clone());
                            }
                        }
                    }
                }
            }
        }
        found.sort();
        found.dedup();
        found
    }

    /// Detect periodic network beaconing: at least 5 `send` calls with
    /// inter-call intervals in the range [5 000, 300 000] ms (5 s – 5 min)
    /// and a coefficient of variation below 0.25 (regular intervals).
    #[must_use]
    pub fn detect_network_beacon(calls: &[EnhancedApiCall]) -> bool {
        let send_ts: Vec<u64> = calls
            .iter()
            .filter(|c| c.function == "send" || c.function == "WinHttpSendRequest")
            .map(|c| c.timestamp)
            .collect();
        if send_ts.len() < 5 {
            return false;
        }
        let intervals: Vec<u64> = send_ts
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]))
            .collect();
        let all_in_range = intervals.iter().all(|&i| (5_000..=300_000).contains(&i));
        if !all_in_range {
            return false;
        }
        // Use f64 accumulation to avoid u64 overflow with large or numerous intervals.
        let n = intervals.len() as f64;
        let mean = intervals.iter().map(|&i| i as f64).sum::<f64>() / n;
        if mean < 1.0 {
            return false;
        }
        let variance = intervals
            .iter()
            .map(|&i| (i as f64 - mean).powi(2))
            .sum::<f64>()
            / n;
        let cv = variance.sqrt() / mean;
        cv < 0.25
    }

    /// Detect anti-debugging API calls and return the list of API names used.
    #[must_use]
    pub fn detect_anti_debug(calls: &[EnhancedApiCall]) -> Vec<String> {
        let anti_debug = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringW",
            "NtSetInformationThread",
        ];
        let mut found: Vec<String> = calls
            .iter()
            .filter(|c| anti_debug.contains(&c.function.as_str()))
            .map(|c| c.function.clone())
            .collect();
        found.sort();
        found.dedup();
        found
    }

    /// Build a MITRE ATT&CK TTP map from a call trace.
    ///
    /// Returns a map of `technique_id → [api_names]`.
    #[must_use]
    pub fn generate_ttp_map(calls: &[EnhancedApiCall]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();

        let add = |map: &mut HashMap<String, Vec<String>>, ttp: &str, api: &str| {
            map.entry(ttp.to_string())
                .or_default()
                .push(api.to_string());
        };

        for call in calls {
            match call.function.as_str() {
                // T1055 — Process Injection
                "VirtualAllocEx" | "WriteProcessMemory" | "CreateRemoteThread"
                | "NtMapViewOfSection" => add(&mut map, "T1055", &call.function),

                // T1547.001 — Boot or Logon Autostart: Registry Run Keys
                "RegSetValueExW" | "RegCreateKeyExW" => {
                    add(&mut map, "T1547.001", &call.function);
                }

                // T1071 — Application Layer Protocol (network C2)
                "send" | "recv" | "WinHttpSendRequest" | "WSAConnect" | "connect" => {
                    add(&mut map, "T1071", &call.function);
                }

                // T1486 — Data Encrypted for Impact (ransomware)
                "CryptEncrypt" | "BCryptEncrypt" | "BCryptGenerateSymmetricKey" => {
                    add(&mut map, "T1486", &call.function);
                }

                // T1497 — Virtualization/Sandbox Evasion
                "IsDebuggerPresent"
                | "CheckRemoteDebuggerPresent"
                | "NtQueryInformationProcess" => {
                    add(&mut map, "T1497", &call.function);
                }

                // T1059 — Command and Scripting Interpreter
                "CreateProcessW" => {
                    let spawns_shell = call.args.iter().any(|a| {
                        if let ArgValue::Str(s) = a {
                            let l = s.to_lowercase();
                            l.contains("cmd") || l.contains("powershell") || l.contains("wscript")
                        } else {
                            false
                        }
                    });
                    if spawns_shell {
                        add(&mut map, "T1059", &call.function);
                    }
                }

                // T1056.001 — Input Capture: Keylogging
                "SetWindowsHookExW" => add(&mut map, "T1056.001", &call.function),

                // T1564 — Hide Artifacts
                "NtSetInformationThread" => add(&mut map, "T1564", &call.function),

                _ => {}
            }
        }

        // Deduplicate per-technique lists.
        for v in map.values_mut() {
            v.sort();
            v.dedup();
        }
        map
    }
}

// ── BehaviorReport ────────────────────────────────────────────────────────────

/// Comprehensive behavioral report synthesized from a full API call trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    /// Subset of calls flagged as suspicious.
    pub suspicious_calls: Vec<EnhancedApiCall>,
    /// Human-readable names of detected malicious techniques.
    pub detected_techniques: Vec<String>,
    /// MITRE ATT&CK technique ID → list of API names.
    pub ttp_mapping: HashMap<String, Vec<String>>,
    /// Overall risk score 0.0 (benign) – 10.0 (critical).
    pub risk_score: f32,
}

impl BehaviorReport {
    /// Build a `BehaviorReport` from a complete API call trace.
    #[must_use]
    pub fn from_api_trace(calls: &[EnhancedApiCall]) -> Self {
        let mut techniques = Vec::new();
        let mut risk: f32 = 0.0;

        // Process injection
        if ApiCallAnalyzer::detect_injection(calls) {
            techniques.push("Process Injection (T1055)".to_string());
            risk += 3.0;
        }

        // Persistence
        let persist_keys = ApiCallAnalyzer::detect_persistence(calls);
        if !persist_keys.is_empty() {
            techniques.push(format!(
                "Registry Persistence (T1547.001) — {} key(s)",
                persist_keys.len()
            ));
            risk += 2.0;
        }

        // Network beaconing
        if ApiCallAnalyzer::detect_network_beacon(calls) {
            techniques.push("Network Beaconing (T1071)".to_string());
            risk += 1.5;
        }

        // Anti-debug
        let anti_debug_apis = ApiCallAnalyzer::detect_anti_debug(calls);
        if !anti_debug_apis.is_empty() {
            techniques.push(format!(
                "Anti-Debug (T1497) — {}",
                anti_debug_apis.join(", ")
            ));
            risk += 1.0;
        }

        // Per-call suspicious patterns
        let suspicious_calls: Vec<EnhancedApiCall> = calls
            .iter()
            .filter(|c| c.is_suspicious || !ApiCallAnalyzer::classify_call(c).is_empty())
            .cloned()
            .collect();

        // Accumulate pattern scores
        for call in &suspicious_calls {
            for pat in ApiCallAnalyzer::classify_call(call) {
                match pat {
                    SuspiciousPattern::ExecutableMemory => risk += 0.5,
                    SuspiciousPattern::BulkEncryption => risk += 1.5,
                    SuspiciousPattern::RemoteThreadCreation => risk += 1.0,
                    SuspiciousPattern::SuspiciousChildProcess(_) => risk += 0.8,
                    _ => {}
                }
            }
        }

        let ttp_mapping = ApiCallAnalyzer::generate_ttp_map(calls);

        Self {
            suspicious_calls,
            detected_techniques: techniques,
            ttp_mapping,
            risk_score: risk.min(10.0),
        }
    }

    /// Returns `true` if the risk score exceeds the given threshold.
    #[must_use]
    pub fn is_high_risk(&self, threshold: f32) -> bool {
        self.risk_score >= threshold
    }
}

// ── MonitorServer ─────────────────────────────────────────────────────────────

/// Async TCP server that accepts JSON-encoded `EnhancedApiCall` events from
/// guest agents and feeds them into the shared `ApiMonitor` (§23.3).
pub struct MonitorServer {
    monitor: Arc<Mutex<ApiMonitor>>,
    enhanced: Arc<Mutex<Vec<EnhancedApiCall>>>,
}

impl MonitorServer {
    /// Create a new server wrapping an existing `ApiMonitor`.
    #[must_use]
    pub fn new(monitor: Arc<Mutex<ApiMonitor>>) -> Self {
        Self {
            monitor,
            enhanced: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a server with a fresh default `ApiMonitor`.
    #[must_use]
    pub fn with_default_monitor() -> Self {
        Self::new(Arc::new(Mutex::new(ApiMonitor::default_hooks())))
    }

    /// Return a snapshot of all `EnhancedApiCall` records received so far.
    #[must_use]
    pub fn enhanced_calls(&self) -> Vec<EnhancedApiCall> {
        self.enhanced.lock().clone()
    }

    /// Generate a `BehaviorReport` from all received calls.
    #[must_use]
    pub fn behavior_report(&self) -> BehaviorReport {
        let calls = self.enhanced.lock().clone();
        BehaviorReport::from_api_trace(&calls)
    }

    /// Start listening for incoming guest-agent connections on `addr`.
    ///
    /// Each connection sends newline-delimited JSON `EnhancedApiCall` records.
    /// The function runs until the listener is closed or an OS error occurs.
    pub async fn start_tcp_listener(
        addr: SocketAddr,
        monitor: Arc<Mutex<ApiMonitor>>,
        enhanced: Arc<Mutex<Vec<EnhancedApiCall>>>,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let mon_clone = Arc::clone(&monitor);
                    let enh_clone = Arc::clone(&enhanced);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, mon_clone, enh_clone).await {
                            eprintln!("[monitor-server] client {peer} error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[monitor-server] accept error: {e}");
                    // Only break on fatal errors; retry on transient OS errors.
                    match e.kind() {
                        std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::Interrupted => {
                            // Transient – keep accepting.
                            continue;
                        }
                        _ => {
                            // Treat unknown errors as potentially transient too,
                            // unless the listener itself was closed (raw OS errors
                            // like EMFILE/ENFILE fall here – log and continue).
                            let raw = e.raw_os_error();
                            // EMFILE=24, ENFILE=23 on Linux; on Windows WSAEMFILE=10024
                            const EMFILE: i32 = 24;
                            const ENFILE: i32 = 23;
                            const WSAEMFILE: i32 = 10024;
                            if matches!(raw, Some(EMFILE | ENFILE | WSAEMFILE)) {
                                continue;
                            }
                            // Fatal: listener closed or unrecoverable.
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Drive a single connected guest-agent stream to completion.
    ///
    /// Reads newline-delimited JSON, deserializes each line into an
    /// `EnhancedApiCall`, and forwards it to both the `ApiMonitor` (as a
    /// legacy `ApiCall`) and the enhanced call store.
    pub async fn handle_client(
        stream: TcpStream,
        monitor: Arc<Mutex<ApiMonitor>>,
        enhanced: Arc<Mutex<Vec<EnhancedApiCall>>>,
    ) -> Result<()> {
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();
        // Cap per-line size to 1 MiB to prevent a guest agent from allocating
        // unbounded memory before the JSON deserializer even runs.
        const MAX_LINE_BYTES: usize = 1024 * 1024;
        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_LINE_BYTES {
                eprintln!("[monitor-server] line too long ({} bytes), skipping", line.len());
                continue;
            }
            match serde_json::from_str::<EnhancedApiCall>(&line) {
                Ok(mut enhanced_call) => {
                    // Enrich from the signature database.
                    enhanced_call.enrich_from_db();

                    // Mirror into the legacy ApiCall path so existing hooks
                    // and anomaly detection continue to work.
                    let legacy = ApiCall {
                        name: enhanced_call.function.clone(),
                        category: sig_category_to_api_category(enhanced_call.category),
                        pid: enhanced_call.pid,
                        tid: enhanced_call.thread_id,
                        ts_ms: enhanced_call.timestamp,
                        args: enhanced_call
                            .args
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect(),
                        ret: None,
                        suspicious: enhanced_call.is_suspicious,
                        call_stack: vec![],
                    };
                    monitor.lock().record(legacy);
                    enhanced.lock().push(enhanced_call);
                }
                Err(e) => {
                    eprintln!("[monitor-server] JSON parse error: {e} — line: {line}");
                }
            }
        }
        Ok(())
    }

    /// Launch the TCP listener as a background task and return a handle to the
    /// server so callers can still access `enhanced_calls()` / `behavior_report()`.
    #[must_use]
    pub fn spawn(self: Arc<Self>, addr: SocketAddr) -> tokio::task::JoinHandle<Result<()>> {
        let monitor = Arc::clone(&self.monitor);
        let enhanced = Arc::clone(&self.enhanced);
        tokio::spawn(async move { Self::start_tcp_listener(addr, monitor, enhanced).await })
    }
}

/// Convert a `SigCategory` to the legacy `ApiCategory` used by `ApiMonitor`.
#[must_use]
const fn sig_category_to_api_category(cat: SigCategory) -> ApiCategory {
    match cat {
        SigCategory::FileSystem => ApiCategory::FileSystem,
        SigCategory::Registry => ApiCategory::Registry,
        SigCategory::Network => ApiCategory::Network,
        SigCategory::Process => ApiCategory::Process,
        SigCategory::Memory => ApiCategory::Memory,
        SigCategory::Crypto => ApiCategory::Crypto,
        SigCategory::Debug => ApiCategory::System,
        SigCategory::Ui => ApiCategory::Gui,
    }
}

// ─── BehaviorPhase ────────────────────────────────────────────────────────────

/// High-level execution phase inferred from API call timing and category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorPhase {
    Initialization,
    AntiAnalysis,
    Persistence,
    C2Setup,
    DataCollection,
    Execution,
    Cleanup,
}

impl fmt::Display for BehaviorPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialization => write!(f, "initialization"),
            Self::AntiAnalysis => write!(f, "anti_analysis"),
            Self::Persistence => write!(f, "persistence"),
            Self::C2Setup => write!(f, "c2_setup"),
            Self::DataCollection => write!(f, "data_collection"),
            Self::Execution => write!(f, "execution"),
            Self::Cleanup => write!(f, "cleanup"),
        }
    }
}

// ─── TimelineEntry ────────────────────────────────────────────────────────────

/// A single entry in the behavioral timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Millisecond timestamp of the API call.
    pub timestamp: u64,
    /// Inferred execution phase for this call.
    pub phase: BehaviorPhase,
    /// Human-readable description of what occurred.
    pub description: String,
    /// Name of the API that triggered this entry.
    pub api: String,
}

impl TimelineEntry {
    /// Create a new timeline entry.
    #[must_use]
    pub fn new(
        timestamp: u64,
        phase: BehaviorPhase,
        description: impl Into<String>,
        api: impl Into<String>,
    ) -> Self {
        Self {
            timestamp,
            phase,
            description: description.into(),
            api: api.into(),
        }
    }
}

// ─── BehaviorTimeline ─────────────────────────────────────────────────────────

/// Constructs and analyzes a temporal behavioral timeline from an API call trace.
#[derive(Debug, Default)]
pub struct BehaviorTimeline;

impl BehaviorTimeline {
    /// Create a new timeline builder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Classify a single API call into the most appropriate `BehaviorPhase`.
    #[must_use]
    pub fn classify_phase(api: &str) -> BehaviorPhase {
        // Anti-analysis checks.
        const ANTI_ANALYSIS: &[&str] = &[
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringW",
            "NtSetInformationThread",
            "NtYieldExecution",
            "GetTickCount",
            "timeGetTime",
            "QueryPerformanceCounter",
        ];
        // Persistence mechanisms.
        const PERSISTENCE: &[&str] = &[
            "RegSetValueExW",
            "RegCreateKeyExW",
            "CreateService",
            "NtSetValueKey",
            "SHGetFolderPathA",
            "SHGetFolderPathW",
            "WriteFile",
        ];
        // C2 / network setup.
        const C2SETUP: &[&str] = &[
            "WSAConnect",
            "connect",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "InternetConnect",
            "send",
            "recv",
            "DnsQuery",
            "getaddrinfo",
        ];
        // Data collection.
        const DATA_COLLECTION: &[&str] = &[
            "SetWindowsHookExW",
            "GetAsyncKeyState",
            "OpenClipboard",
            "GetClipboardData",
            "BitBlt",
            "PrintWindow",
            "ReadProcessMemory",
            "SamOpenDomain",
            "SamEnumerateUsersInDomain",
            "NetUserEnum",
            "NetLocalGroupEnum",
            "FindFirstFileA",
            "FindFirstFileW",
            "FindNextFileA",
            "FindNextFileW",
            "RegQueryValueExW",
        ];
        // Execution / injection.
        const EXECUTION: &[&str] = &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThread",
            "NtMapViewOfSection",
            "NtAllocateVirtualMemory",
            "CreateProcessW",
            "WinExec",
            "ShellExecuteW",
            "CoCreateInstance",
        ];
        // Crypto / encryption.
        const CRYPTO: &[&str] = &[
            "CryptEncrypt",
            "BCryptEncrypt",
            "CryptGenRandom",
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "BCryptOpenAlgorithmProvider",
            "BCryptGenerateSymmetricKey",
        ];
        // Cleanup.
        const CLEANUP: &[&str] = &[
            "DeleteFileW",
            "NtClose",
            "VirtualFree",
            "HeapFree",
            "RegDeleteKeyW",
            "RegDeleteValueW",
        ];

        if ANTI_ANALYSIS.contains(&api) {
            BehaviorPhase::AntiAnalysis
        } else if PERSISTENCE.contains(&api) {
            BehaviorPhase::Persistence
        } else if C2SETUP.contains(&api) {
            BehaviorPhase::C2Setup
        } else if DATA_COLLECTION.contains(&api) {
            BehaviorPhase::DataCollection
        } else if EXECUTION.contains(&api) {
            BehaviorPhase::Execution
        } else if CRYPTO.contains(&api) {
            BehaviorPhase::DataCollection // Encryption as part of data staging.
        } else if CLEANUP.contains(&api) {
            BehaviorPhase::Cleanup
        } else {
            BehaviorPhase::Initialization
        }
    }

    /// Build a `Vec<TimelineEntry>` from a slice of `ApiCall`s.
    ///
    /// Calls are processed in timestamp order. Each call is mapped to the most
    /// appropriate `BehaviorPhase` and a human-readable description is generated.
    #[must_use]
    pub fn build(calls: &[ApiCall]) -> Vec<TimelineEntry> {
        let mut sorted: Vec<&ApiCall> = calls.iter().collect();
        sorted.sort_by_key(|c| c.ts_ms);

        sorted
            .iter()
            .map(|call| {
                let phase = Self::classify_phase(&call.name);
                let description = Self::describe_call(call, &phase);
                TimelineEntry::new(call.ts_ms, phase, description, call.name.clone())
            })
            .collect()
    }

    /// Generate a human-readable description for a call given its phase.
    #[must_use]
    fn describe_call(call: &ApiCall, phase: &BehaviorPhase) -> String {
        let arg_summary = if call.args.is_empty() {
            String::new()
        } else {
            format!(" ({})", call.args.first().unwrap_or(&String::new()))
        };
        format!(
            "[{phase}] pid={} called {}{}",
            call.pid, call.name, arg_summary
        )
    }

    /// Detect contiguous phase ranges from a timeline.
    ///
    /// Returns a list of `(phase, start_ts, end_ts)` tuples representing each
    /// phase span (start is the first call in that phase, end is the last).
    /// Contiguous calls within the same phase are merged into a single span.
    #[must_use]
    pub fn detect_phases(timeline: &[TimelineEntry]) -> Vec<(BehaviorPhase, u64, u64)> {
        if timeline.is_empty() {
            return vec![];
        }

        let mut spans: Vec<(BehaviorPhase, u64, u64)> = Vec::new();
        let mut current_phase = timeline[0].phase.clone();
        let mut start = timeline[0].timestamp;
        let mut end = timeline[0].timestamp;

        for entry in timeline.iter().skip(1) {
            if entry.phase == current_phase {
                end = entry.timestamp;
            } else {
                spans.push((current_phase.clone(), start, end));
                current_phase = entry.phase.clone();
                start = entry.timestamp;
                end = entry.timestamp;
            }
        }
        spans.push((current_phase, start, end));

        // Merge non-contiguous occurrences of the same phase by folding.
        // (Keep separate spans — callers can merge if needed.)
        spans
    }

    /// Return all unique phases present in the timeline (in order of first appearance).
    #[must_use]
    pub fn unique_phases(timeline: &[TimelineEntry]) -> Vec<BehaviorPhase> {
        let mut seen = Vec::new();
        for entry in timeline {
            if !seen.contains(&entry.phase) {
                seen.push(entry.phase.clone());
            }
        }
        seen
    }

    /// Count calls per phase.
    #[must_use]
    pub fn phase_counts(timeline: &[TimelineEntry]) -> HashMap<BehaviorPhase, usize> {
        let mut map: HashMap<BehaviorPhase, usize> = HashMap::new();
        for entry in timeline {
            *map.entry(entry.phase.clone()).or_insert(0) += 1;
        }
        map
    }
}

// ─── HttpSummary ─────────────────────────────────────────────────────────────

/// Summary of a single captured HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSummary {
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Requested URL.
    pub url: String,
    /// HTTP status code of the response, if captured.
    pub status_code: Option<u16>,
    /// Number of bytes in the request body.
    pub request_bytes: u64,
    /// Number of bytes in the response body.
    pub response_bytes: u64,
    /// Millisecond timestamp of the request.
    pub ts_ms: u64,
}

impl HttpSummary {
    /// Returns `true` if this request looks like a C2 check-in (POST to a
    /// non-standard path with a small body).
    #[must_use]
    pub fn is_likely_c2(&self) -> bool {
        self.method == "POST"
            && self.request_bytes < 4096
            && (self.url.contains("/update")
                || self.url.contains("/gate")
                || self.url.contains("/check")
                || self.url.contains("/beacon"))
    }
}

// ─── NetworkBehaviorReport ────────────────────────────────────────────────────

/// Comprehensive report of observed network behavior, produced by
/// `NetworkBehaviorAnalyzer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBehaviorReport {
    /// Unique remote IP addresses observed.
    pub unique_ips: Vec<String>,
    /// Unique domain names queried.
    pub unique_domains: Vec<String>,
    /// Summarized HTTP request records.
    pub http_requests: Vec<HttpSummary>,
    /// DNS queries made by the sample.
    pub dns_queries: Vec<String>,
    /// Whether periodic C2 beaconing was detected.
    pub has_c2_beacon: bool,
    /// Estimated beaconing interval in milliseconds, if detected.
    pub beacon_interval_ms: Option<u64>,
    /// Estimated bytes exfiltrated (outbound to external hosts).
    pub data_exfiltrated_bytes: u64,
    /// Number of TLS connections observed.
    pub tls_connections: u32,
}

impl NetworkBehaviorReport {
    /// Create an empty report.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            unique_ips: vec![],
            unique_domains: vec![],
            http_requests: vec![],
            dns_queries: vec![],
            has_c2_beacon: false,
            beacon_interval_ms: None,
            data_exfiltrated_bytes: 0,
            tls_connections: 0,
        }
    }

    /// Returns `true` if the sample showed signs of data exfiltration (> 1 MB).
    #[must_use]
    pub const fn is_exfiltrating(&self) -> bool {
        self.data_exfiltrated_bytes > 1_048_576
    }

    /// Returns `true` if any of the HTTP requests look like C2 check-ins.
    #[must_use]
    pub fn has_c2_http(&self) -> bool {
        self.http_requests.iter().any(HttpSummary::is_likely_c2)
    }

    /// Overall threat indicator — true if beacon OR exfiltration OR C2 HTTP.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.has_c2_beacon || self.is_exfiltrating() || self.has_c2_http()
    }
}

// ─── NetworkBehaviorAnalyzer ──────────────────────────────────────────────────

/// Analyzes raw PCAP data (or a stream of connection records) to produce a
/// `NetworkBehaviorReport`.
///
/// For sandbox use the "PCAP" is treated as an opaque byte buffer.  A
/// lightweight internal parser extracts connection records and beacon patterns
/// without requiring an external pcap library.
#[derive(Debug, Default)]
pub struct NetworkBehaviorAnalyzer;

impl NetworkBehaviorAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyze raw PCAP bytes and return a behavioral report.
    ///
    /// This implementation parses the PCAP global header, then iterates over
    /// packet records extracting basic IP/TCP/UDP fields.  HTTP heuristics are
    /// applied to TCP port-80 payloads.  TLS is detected by checking for the
    /// TLS record type byte (0x16) on port 443.
    #[must_use]
    pub fn analyze(pcap: &[u8]) -> NetworkBehaviorReport {
        let mut report = NetworkBehaviorReport::empty();

        // A valid PCAP file starts with the magic number 0xA1B2C3D4 (LE) or 0xD4C3B2A1.
        // If the input is too short or lacks the magic, we return an empty report.
        if pcap.len() < 24 {
            return report;
        }
        let magic = u32::from_le_bytes([pcap[0], pcap[1], pcap[2], pcap[3]]);
        if magic != 0xA1B2_C3D4 && magic != 0xD4C3_B2A1 {
            return report;
        }

        // Connection timestamps for beacon detection.
        let mut connection_timestamps: Vec<u64> = Vec::new();
        let mut offset = 24usize; // Skip global header.

        while offset + 16 <= pcap.len() {
            // Packet record header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4).
            let ts_sec = u64::from(u32::from_le_bytes([
                pcap[offset],
                pcap[offset + 1],
                pcap[offset + 2],
                pcap[offset + 3],
            ]));
            let ts_subsec = u64::from(u32::from_le_bytes([
                pcap[offset + 4],
                pcap[offset + 5],
                pcap[offset + 6],
                pcap[offset + 7],
            ]));
            let incl_len_raw = u32::from_le_bytes([
                pcap[offset + 8],
                pcap[offset + 9],
                pcap[offset + 10],
                pcap[offset + 11],
            ]);
            // Guard against adversarially large incl_len values (PCAP max is 65535 bytes).
            if incl_len_raw > 65535 {
                break;
            }
            let incl_len = incl_len_raw as usize;
            offset += 16;

            if offset + incl_len > pcap.len() {
                break;
            }
            let pkt = &pcap[offset..offset + incl_len];
            offset += incl_len;

            let ts_ms = ts_sec * 1000 + ts_subsec / 1000;

            // Expect Ethernet II (14 bytes) then IPv4 (version/IHL at byte 14).
            if pkt.len() < 34 {
                continue;
            }
            // EtherType must be 0x0800 (IPv4).
            let ether_type = u16::from_be_bytes([pkt[12], pkt[13]]);
            if ether_type != 0x0800 {
                continue;
            }

            let ip_version = (pkt[14] >> 4) & 0xF;
            if ip_version != 4 {
                continue;
            }
            let ihl = ((pkt[14] & 0x0F) * 4) as usize;
            if pkt.len() < 14 + ihl {
                continue;
            }

            let proto = pkt[14 + 9]; // IP protocol field.
            let src_ip = format!(
                "{}.{}.{}.{}",
                pkt[14 + 12],
                pkt[14 + 13],
                pkt[14 + 14],
                pkt[14 + 15]
            );
            let dst_ip = format!(
                "{}.{}.{}.{}",
                pkt[14 + 16],
                pkt[14 + 17],
                pkt[14 + 18],
                pkt[14 + 19]
            );

            // Only track external destinations (non-RFC1918).
            let is_external = !dst_ip.starts_with("192.168.")
                && !dst_ip.starts_with("10.")
                && !dst_ip.starts_with("127.")
                && !dst_ip.starts_with("172.");

            if is_external && !report.unique_ips.contains(&dst_ip) {
                report.unique_ips.push(dst_ip.clone());
            }

            let tcp_udp_start = 14 + ihl;

            match proto {
                6 => {
                    // TCP
                    if pkt.len() < tcp_udp_start + 4 {
                        continue;
                    }
                    let dst_port =
                        u16::from_be_bytes([pkt[tcp_udp_start + 2], pkt[tcp_udp_start + 3]]);
                    let src_port = u16::from_be_bytes([pkt[tcp_udp_start], pkt[tcp_udp_start + 1]]);
                    // TCP data offset: high nibble of byte 12, units of 4 bytes. Minimum valid = 5 (20 bytes).
                    let tcp_doff_nibble = pkt.get(tcp_udp_start + 12).copied().unwrap_or(0x50) >> 4;
                    let tcp_doff_nibble = tcp_doff_nibble.max(5); // enforce minimum TCP header size
                    let tcp_data_offset = (tcp_doff_nibble as usize) * 4;
                    let payload_start = tcp_udp_start.saturating_add(tcp_data_offset);
                    // Validate payload_start is within the packet bounds before any indexing.
                    if payload_start > pkt.len() {
                        continue;
                    }

                    if is_external {
                        connection_timestamps.push(ts_ms);
                        let payload_bytes = (incl_len as u64).saturating_sub(payload_start as u64);
                        report.data_exfiltrated_bytes = report.data_exfiltrated_bytes.saturating_add(payload_bytes);
                    }

                    // TLS detection (port 443 or TLS record type 0x16).
                    if dst_port == 443
                        || src_port == 443
                        || pkt.get(payload_start).copied() == Some(0x16)
                    {
                        report.tls_connections = report.tls_connections.saturating_add(1);
                    }

                    // HTTP heuristic on port 80.
                    if (dst_port == 80 || src_port == 80) && payload_start < pkt.len() {
                        let payload = &pkt[payload_start..];
                        if let Some(summary) =
                            Self::parse_http_payload(payload, &dst_ip, ts_ms, incl_len as u64)
                        {
                            report.http_requests.push(summary);
                        }
                    }
                }
                17 => {
                    // UDP — check for DNS (port 53).
                    if pkt.len() < tcp_udp_start + 4 {
                        continue;
                    }
                    let dst_port =
                        u16::from_be_bytes([pkt[tcp_udp_start + 2], pkt[tcp_udp_start + 3]]);
                    if dst_port == 53 {
                        let dns_start = tcp_udp_start + 8;
                        if let Some(qname) = Self::extract_dns_qname(&pkt[dns_start..]) {
                            if !report.unique_domains.contains(&qname) {
                                report.unique_domains.push(qname.clone());
                            }
                            if !report.dns_queries.contains(&qname) {
                                report.dns_queries.push(qname);
                            }
                        }
                    }
                }
                _ => {}
            }

            let _ = src_ip; // used for completeness; external check uses dst_ip.
        }

        // Beacon detection.
        if let Some(interval) = Self::detect_beacon_pattern(&connection_timestamps) {
            report.has_c2_beacon = true;
            report.beacon_interval_ms = Some(interval);
        }

        report
    }

    /// Attempt to detect a periodic beacon pattern in a set of connection
    /// timestamps.  Returns the estimated interval in milliseconds if a
    /// regular pattern is found (CV < 0.25, at least 5 intervals in range).
    #[must_use]
    pub fn detect_beacon_pattern(timestamps: &[u64]) -> Option<u64> {
        if timestamps.len() < 6 {
            return None;
        }
        let mut ts: Vec<u64> = timestamps.to_vec();
        ts.sort_unstable();
        let intervals: Vec<u64> = ts.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();

        // All intervals must be in a plausible beacon range: 1 s – 10 min.
        let in_range = intervals.iter().all(|&i| (1_000..=600_000).contains(&i));
        if !in_range {
            return None;
        }

        // Use f64 accumulation to avoid u64 overflow with large or numerous intervals.
        let n = intervals.len() as f64;
        let mean = intervals.iter().map(|&i| i as f64).sum::<f64>() / n;
        if mean < 1.0 {
            return None;
        }
        let variance = intervals
            .iter()
            .map(|&i| (i as f64 - mean).powi(2))
            .sum::<f64>()
            / n;
        let cv = variance.sqrt() / mean;

        if cv < 0.25 {
            Some(mean.round() as u64)
        } else {
            None
        }
    }

    /// Lightweight HTTP payload parser.  Returns an `HttpSummary` if the
    /// payload begins with a recognisable HTTP request or response line.
    #[must_use]
    fn parse_http_payload(
        payload: &[u8],
        dst_ip: &str,
        ts_ms: u64,
        total_bytes: u64,
    ) -> Option<HttpSummary> {
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?;

        // Request: "METHOD /path HTTP/1.x"
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() == 3 && parts[2].starts_with("HTTP/") {
            let method = parts[0].to_string();
            let path = parts[1];
            // Reconstruct URL using dst IP (host header parsing omitted for brevity).
            let url = format!("http://{dst_ip}{path}");
            return Some(HttpSummary {
                method,
                url,
                status_code: None,
                request_bytes: total_bytes,
                response_bytes: 0,
                ts_ms,
            });
        }

        // Response: "HTTP/1.x 200 OK"
        if parts.len() >= 2 && parts[0].starts_with("HTTP/") {
            let status: u16 = parts[1].parse().ok()?;
            return Some(HttpSummary {
                method: "RESPONSE".to_string(),
                url: format!("http://{dst_ip}/"),
                status_code: Some(status),
                request_bytes: 0,
                response_bytes: total_bytes,
                ts_ms,
            });
        }

        None
    }

    /// Extract the DNS QNAME from a raw DNS message (starting at the Question
    /// section, i.e., after the 12-byte DNS header).
    #[must_use]
    fn extract_dns_qname(data: &[u8]) -> Option<String> {
        // Skip 12-byte DNS header.
        if data.len() < 13 {
            return None;
        }
        let mut labels = Vec::new();
        let mut i = 12usize; // Start of Question section.
        // DNS labels are limited to 127 per name in practice; cap to prevent DoS via
        // a malformed packet with thousands of tiny labels.
        const MAX_LABELS: usize = 128;
        loop {
            if i >= data.len() {
                return None;
            }
            let byte = data[i];
            // DNS pointer compression: top 2 bits set (0xC0) means this is a pointer, not a label.
            // We don't follow pointers (they reference earlier data we don't have context for);
            // treat them as end-of-name to avoid reading arbitrary offsets.
            if byte & 0xC0 == 0xC0 {
                break;
            }
            let len = byte as usize;
            if len == 0 {
                break;
            }
            i += 1;
            if i + len > data.len() {
                return None;
            }
            let label = std::str::from_utf8(&data[i..i + len]).ok()?;
            labels.push(label.to_string());
            i += len;
            if labels.len() > MAX_LABELS {
                return None;
            }
        }
        if labels.is_empty() {
            return None;
        }
        Some(labels.join("."))
    }

    /// Build a `NetworkBehaviorReport` directly from `ApiCall` records
    /// (no PCAP required).  This is used when the PCAP is unavailable but
    /// the API trace contains network events.
    #[must_use]
    pub fn from_api_calls(calls: &[ApiCall]) -> NetworkBehaviorReport {
        let mut report = NetworkBehaviorReport::empty();

        let mut send_timestamps: Vec<u64> = Vec::new();

        for call in calls {
            match call.name.as_str() {
                "WinHttpConnect" | "connect" | "WSAConnect" | "InternetConnect" => {
                    if let Some(ip_arg) = call.args.first() {
                        let ip = ip_arg.clone();
                        let is_external = !ip.starts_with("192.168.")
                            && !ip.starts_with("10.")
                            && !ip.starts_with("127.");
                        if is_external && !report.unique_ips.contains(&ip) {
                            report.unique_ips.push(ip);
                        }
                    }
                    send_timestamps.push(call.ts_ms);
                }
                "WinHttpSendRequest" | "send" => {
                    send_timestamps.push(call.ts_ms);
                    // Estimate exfiltration from argument carrying buffer size.
                    // Cap each individual value at 64 MiB and use saturating add
                    // to prevent overflow from adversarially large size fields.
                    if let Some(size_arg) = call.args.get(2)
                        && let Ok(n) = size_arg.parse::<u64>()
                    {
                        let n_capped = n.min(64 * 1024 * 1024);
                        report.data_exfiltrated_bytes = report.data_exfiltrated_bytes.saturating_add(n_capped);
                    }
                }
                "DnsQuery" | "getaddrinfo" | "gethostbyname" => {
                    if let Some(domain) = call.args.first() {
                        if !report.dns_queries.contains(domain) {
                            report.dns_queries.push(domain.clone());
                        }
                        if !report.unique_domains.contains(domain) {
                            report.unique_domains.push(domain.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        // Count TLS connections (WinHttpConnect on port 443 or HTTPS calls).
        report.tls_connections = calls
            .iter()
            .filter(|c| {
                c.name == "WinHttpConnect"
                    && c.args.get(1).map(std::string::String::as_str) == Some("443")
            })
            .count() as u32;

        if let Some(interval) = Self::detect_beacon_pattern(&send_timestamps) {
            report.has_c2_beacon = true;
            report.beacon_interval_ms = Some(interval);
        }

        report
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ApiCategory ──────────────────────────────────────────────────────────

    #[test]
    fn test_api_category_display_filesystem() {
        assert_eq!(ApiCategory::FileSystem.to_string(), "filesystem");
    }

    #[test]
    fn test_api_category_display_network() {
        assert_eq!(ApiCategory::Network.to_string(), "network");
    }

    #[test]
    fn test_api_category_display_registry() {
        assert_eq!(ApiCategory::Registry.to_string(), "registry");
    }

    #[test]
    fn test_api_category_display_process() {
        assert_eq!(ApiCategory::Process.to_string(), "process");
    }

    #[test]
    fn test_api_category_display_memory() {
        assert_eq!(ApiCategory::Memory.to_string(), "memory");
    }

    #[test]
    fn test_api_category_display_crypto() {
        assert_eq!(ApiCategory::Crypto.to_string(), "crypto");
    }

    #[test]
    fn test_api_category_display_system() {
        assert_eq!(ApiCategory::System.to_string(), "system");
    }

    #[test]
    fn test_api_category_all_display_non_empty() {
        let cats = [
            ApiCategory::FileSystem,
            ApiCategory::Network,
            ApiCategory::Registry,
            ApiCategory::Process,
            ApiCategory::Memory,
            ApiCategory::Crypto,
            ApiCategory::System,
            ApiCategory::Synchronization,
            ApiCategory::Token,
            ApiCategory::Gui,
        ];
        for cat in &cats {
            assert!(!cat.to_string().is_empty());
        }
    }

    // ── ApiCall ──────────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_new() {
        let c = ApiCall::new("CreateFile", ApiCategory::FileSystem, 1234);
        assert_eq!(c.name, "CreateFile");
        assert_eq!(c.pid, 1234);
        assert!(!c.suspicious);
    }

    #[test]
    fn test_api_call_with_arg() {
        let c = ApiCall::new("CreateFile", ApiCategory::FileSystem, 0).with_arg("C:\\evil.exe");
        assert_eq!(c.args.len(), 1);
        assert_eq!(c.args[0], "C:\\evil.exe");
    }

    #[test]
    fn test_api_call_with_ret() {
        let c = ApiCall::new("CreateFile", ApiCategory::FileSystem, 0).with_ret(42);
        assert_eq!(c.ret, Some(42));
    }

    #[test]
    fn test_api_call_with_ts() {
        let c = ApiCall::new("Foo", ApiCategory::System, 0).with_ts(9999);
        assert_eq!(c.ts_ms, 9999);
    }

    #[test]
    fn test_api_call_with_frame() {
        let c = ApiCall::new("Foo", ApiCategory::System, 0).with_frame("main+0x10");
        assert_eq!(c.call_stack.len(), 1);
    }

    #[test]
    fn test_api_call_arg_contains() {
        let c = ApiCall::new("F", ApiCategory::FileSystem, 0).with_arg("C:\\Windows\\evil.exe");
        assert!(c.arg_contains(".exe"));
        assert!(!c.arg_contains(".dll"));
    }

    // ── ApiHook ──────────────────────────────────────────────────────────────

    #[test]
    fn test_api_hook_is_suspicious_wrong_api() {
        let hook = ApiHook::new("CreateFile", ApiCategory::FileSystem).with_pattern(".exe");
        let call = ApiCall::new("ReadFile", ApiCategory::FileSystem, 0);
        assert!(!hook.is_suspicious(&call));
    }

    #[test]
    fn test_api_hook_is_suspicious_pattern_match() {
        let hook = ApiHook::new("CreateFile", ApiCategory::FileSystem).with_pattern(".exe");
        let call = ApiCall::new("CreateFile", ApiCategory::FileSystem, 0)
            .with_arg("C:\\Windows\\payload.exe");
        assert!(hook.is_suspicious(&call));
    }

    #[test]
    fn test_api_hook_no_patterns_is_not_suspicious() {
        // `ApiHook::new` documents "a hook that fires on pattern match", and the
        // `.always()` twin below exists precisely to flag every call without a
        // pattern. A bare hook with no patterns therefore must NOT fire — the
        // old expectation would have made `.always()` meaningless.
        let hook = ApiHook::new("VirtualAllocEx", ApiCategory::Memory);
        let call = ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 0);
        assert!(!hook.is_suspicious(&call));
    }

    #[test]
    fn test_api_hook_always_flag() {
        let hook = ApiHook::new("VirtualAllocEx", ApiCategory::Memory).always();
        let call = ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 0);
        assert!(hook.is_suspicious(&call));
    }

    #[test]
    fn test_api_hook_pattern_no_match() {
        let hook = ApiHook::new("CreateFile", ApiCategory::FileSystem).with_pattern(".exe");
        let call = ApiCall::new("CreateFile", ApiCategory::FileSystem, 0)
            .with_arg("C:\\Windows\\legit.txt");
        assert!(!hook.is_suspicious(&call));
    }

    // ── EventStream ──────────────────────────────────────────────────────────

    #[test]
    fn test_event_stream_push_and_len() {
        let s = EventStream::new(10);
        s.push(
            1,
            0,
            MonitorEventKind::ProcessStart {
                pid: 1,
                image: "foo.exe".to_string(),
            },
        );
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_event_stream_drain() {
        let s = EventStream::new(10);
        s.push(
            1,
            0,
            MonitorEventKind::ProcessStart {
                pid: 1,
                image: "a.exe".to_string(),
            },
        );
        s.push(
            1,
            0,
            MonitorEventKind::ProcessExit {
                pid: 1,
                exit_code: 0,
            },
        );
        let events = s.drain();
        assert_eq!(events.len(), 2);
        assert!(s.is_empty());
    }

    #[test]
    fn test_event_stream_overflow_drops_oldest() {
        let s = EventStream::new(3);
        for i in 0u64..5 {
            s.push(
                1,
                i,
                MonitorEventKind::ProcessExit {
                    pid: 1,
                    exit_code: 0,
                },
            );
        }
        assert_eq!(s.len(), 3);
        assert_eq!(s.dropped_count(), 2);
    }

    #[test]
    fn test_event_stream_total_pushed() {
        let s = EventStream::new(100);
        for _ in 0..10 {
            s.push(
                1,
                0,
                MonitorEventKind::ProcessExit {
                    pid: 1,
                    exit_code: 0,
                },
            );
        }
        assert_eq!(s.total_pushed(), 10);
    }

    #[test]
    fn test_event_stream_peek_no_consume() {
        let s = EventStream::new(10);
        s.push(
            1,
            0,
            MonitorEventKind::ProcessExit {
                pid: 1,
                exit_code: 0,
            },
        );
        let _ = s.peek();
        assert_eq!(s.len(), 1);
    }

    // ── BehaviorSequence ─────────────────────────────────────────────────────

    #[test]
    fn test_behavior_sequence_push_and_len() {
        let mut seq = BehaviorSequence::new(1, 0, 1000);
        seq.push("VirtualAllocEx");
        seq.push("WriteProcessMemory");
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn test_behavior_sequence_count() {
        let mut seq = BehaviorSequence::new(1, 0, 1000);
        seq.push("CreateFile");
        seq.push("CreateFile");
        seq.push("ReadFile");
        assert_eq!(seq.count("CreateFile"), 2);
        assert_eq!(seq.count("ReadFile"), 1);
    }

    #[test]
    fn test_behavior_sequence_contains_subsequence() {
        let mut seq = BehaviorSequence::new(1, 0, 1000);
        seq.push("VirtualAllocEx");
        seq.push("WriteProcessMemory");
        seq.push("CreateRemoteThread");
        assert!(seq.contains_subsequence(&["VirtualAllocEx", "CreateRemoteThread"]));
        assert!(!seq.contains_subsequence(&["CreateRemoteThread", "VirtualAllocEx"]));
    }

    #[test]
    fn test_behavior_sequence_ngrams() {
        let mut seq = BehaviorSequence::new(1, 0, 1000);
        seq.push("A");
        seq.push("B");
        seq.push("A");
        seq.push("B");
        let ng = seq.ngrams(2);
        assert!(ng.contains_key(&vec!["A".to_string(), "B".to_string()]));
        assert_eq!(*ng.get(&vec!["A".to_string(), "B".to_string()]).unwrap(), 2);
    }

    #[test]
    fn test_behavior_sequence_is_empty() {
        let seq = BehaviorSequence::new(1, 0, 1000);
        assert!(seq.is_empty());
    }

    // ── FeatureExtractor ─────────────────────────────────────────────────────

    #[test]
    fn test_feature_extractor_empty() {
        let e = FeatureExtractor::new();
        let seq = BehaviorSequence::new(1, 0, 1000);
        let feats = e.extract(&seq);
        assert!(feats.is_empty());
    }

    #[test]
    fn test_feature_extractor_injection_feature() {
        let e = FeatureExtractor::new();
        let mut seq = BehaviorSequence::new(1, 0, 1000);
        seq.push("VirtualAllocEx");
        seq.push("WriteProcessMemory");
        seq.push("NopCall");
        let feats = e.extract(&seq);
        let inj = feats.get("f_injection").copied().unwrap_or(0.0);
        assert!(inj > 0.0);
    }

    #[test]
    fn test_feature_extractor_unique_calls() {
        let e = FeatureExtractor::new();
        let mut seq = BehaviorSequence::new(1, 0, 1000);
        seq.push("A");
        seq.push("A");
        seq.push("B");
        let feats = e.extract(&seq);
        assert_eq!(
            feats.get("f_unique_calls").copied().unwrap_or(0.0) as usize,
            2
        );
    }

    // ── RuleBasedClassifier ──────────────────────────────────────────────────

    #[test]
    fn test_classifier_benign_empty() {
        let c = RuleBasedClassifier::new();
        let feats: HashMap<String, f64> = HashMap::new();
        let result = c.classify(&feats);
        assert_eq!(result.label, "benign");
    }

    #[test]
    fn test_classifier_injector() {
        let c = RuleBasedClassifier::new();
        let mut feats = HashMap::new();
        feats.insert("f_injection".to_string(), 0.05);
        let result = c.classify(&feats);
        assert_eq!(result.label, "injector");
    }

    #[test]
    fn test_classifier_keylogger() {
        let c = RuleBasedClassifier::new();
        let mut feats = HashMap::new();
        feats.insert("f_keylogging".to_string(), 0.02);
        let result = c.classify(&feats);
        assert_eq!(result.label, "spyware");
    }

    #[test]
    fn test_classification_result_is_malicious() {
        let r = ClassificationResult {
            label: "trojan".to_string(),
            confidence: 0.85,
            features: HashMap::new(),
            top_indicators: vec![],
        };
        assert!(r.is_malicious());
    }

    #[test]
    fn test_classification_result_not_malicious() {
        let r = ClassificationResult {
            label: "benign".to_string(),
            confidence: 0.30,
            features: HashMap::new(),
            top_indicators: vec![],
        };
        assert!(!r.is_malicious());
    }

    #[test]
    fn test_classification_result_is_confident() {
        let r = ClassificationResult {
            label: "injector".to_string(),
            confidence: 0.85,
            features: HashMap::new(),
            top_indicators: vec![],
        };
        assert!(r.is_confident(0.80));
        assert!(!r.is_confident(0.90));
    }

    // ── AnomalyDetector ──────────────────────────────────────────────────────

    #[test]
    fn test_anomaly_detector_no_score() {
        let det = AnomalyDetector::new(50.0);
        assert_eq!(det.score_for(999), 0.0);
    }

    #[test]
    fn test_anomaly_detector_observe_increments() {
        let det = AnomalyDetector::new(50.0);
        let call = ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1234);
        det.observe(&call);
        assert!(det.score_for(1234) > 0.0);
    }

    #[test]
    fn test_anomaly_detector_threshold() {
        let det = AnomalyDetector::new(30.0);
        let call = ApiCall::new("WriteProcessMemory", ApiCategory::Memory, 42);
        det.observe(&call);
        let call2 = ApiCall::new("CreateRemoteThread", ApiCategory::Process, 42);
        det.observe(&call2);
        assert!(det.is_anomalous(42));
    }

    #[test]
    fn test_anomaly_detector_reset() {
        let det = AnomalyDetector::new(5.0);
        let call = ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 7);
        det.observe(&call);
        det.reset(7);
        assert_eq!(det.score_for(7), 0.0);
    }

    #[test]
    fn test_anomaly_detector_anomalous_processes() {
        let det = AnomalyDetector::new(10.0);
        let call = ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 99);
        det.observe(&call);
        let procs = det.anomalous_processes();
        assert!(!procs.is_empty());
    }

    // ── ApiMonitor ───────────────────────────────────────────────────────────

    #[test]
    fn test_monitor_new_empty() {
        let m = ApiMonitor::new();
        assert_eq!(m.total(), 0);
    }

    #[test]
    fn test_monitor_record() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("CreateFile", ApiCategory::FileSystem, 1));
        assert_eq!(m.total(), 1);
    }

    #[test]
    fn test_monitor_suspicious_empty() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("CreateFile", ApiCategory::FileSystem, 1));
        assert!(m.suspicious().is_empty());
    }

    #[test]
    fn test_monitor_suspicious_with_hook() {
        let mut m = ApiMonitor::new();
        m.add_hook(ApiHook::new("VirtualAllocEx", ApiCategory::Memory).always());
        m.record(ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1));
        assert_eq!(m.suspicious().len(), 1);
    }

    #[test]
    fn test_monitor_by_category() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("CreateFile", ApiCategory::FileSystem, 1));
        m.record(ApiCall::new("RegSetValue", ApiCategory::Registry, 1));
        let fs = m.by_category(&ApiCategory::FileSystem);
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn test_monitor_by_pid() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("A", ApiCategory::System, 10));
        m.record(ApiCall::new("B", ApiCategory::System, 20));
        assert_eq!(m.by_pid(10).len(), 1);
        assert_eq!(m.by_pid(20).len(), 1);
    }

    #[test]
    fn test_monitor_default_hooks_count() {
        let m = ApiMonitor::default_hooks();
        assert_eq!(m.hooks.len(), 16);
    }

    #[test]
    fn test_monitor_default_hooks_virtual_alloc_suspicious() {
        let m = ApiMonitor::default_hooks();
        m.record(ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1));
        assert!(!m.suspicious().is_empty());
    }

    #[test]
    fn test_monitor_default_hooks_create_process_powershell() {
        let m = ApiMonitor::default_hooks();
        m.record(
            ApiCall::new("CreateProcess", ApiCategory::Process, 1)
                .with_arg("powershell.exe -exec bypass"),
        );
        assert!(!m.suspicious().is_empty());
    }

    #[test]
    fn test_monitor_call_frequency() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("A", ApiCategory::System, 1));
        m.record(ApiCall::new("A", ApiCategory::System, 1));
        m.record(ApiCall::new("B", ApiCategory::System, 1));
        let freq = m.call_frequency();
        assert_eq!(*freq.get("A").unwrap(), 2);
        assert_eq!(*freq.get("B").unwrap(), 1);
    }

    #[test]
    fn test_monitor_behavior_sequence() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 5));
        m.record(ApiCall::new("WriteProcessMemory", ApiCategory::Memory, 5));
        let seq = m.behavior_sequence_for(5);
        assert_eq!(seq.len(), 2);
    }

    #[test]
    fn test_monitor_classify_pid() {
        let m = ApiMonitor::default_hooks();
        m.record(ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 100));
        m.record(ApiCall::new("WriteProcessMemory", ApiCategory::Memory, 100));
        m.record(ApiCall::new(
            "CreateRemoteThread",
            ApiCategory::Process,
            100,
        ));
        let result = m.classify_pid(100);
        assert_eq!(result.label, "injector");
    }

    // ── Monitor ──────────────────────────────────────────────────────────────

    #[test]
    fn test_full_monitor_start_stop() {
        let m = Monitor::new();
        m.start();
        assert!(m.is_running());
        m.stop();
        assert!(!m.is_running());
    }

    #[test]
    fn test_full_monitor_observe_and_classify() {
        let m = Monitor::new();
        m.observe_call(ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 55));
        m.observe_call(ApiCall::new("WriteProcessMemory", ApiCategory::Memory, 55));
        m.observe_call(ApiCall::new("CreateRemoteThread", ApiCategory::Process, 55));
        let result = m.classify(55);
        assert_eq!(result.label, "injector");
    }

    #[test]
    fn test_full_monitor_summary() {
        let m = Monitor::new();
        m.observe_call(ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1));
        let summary = m.suspicious_summary();
        assert!(summary.total_calls > 0);
        assert!(summary.suspicious_calls > 0);
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    #[test]
    fn test_monitor_error_hook_failed() {
        let e = MonitorError::HookFailed("injection failed".to_string());
        assert!(e.to_string().contains("injection failed"));
    }

    #[test]
    fn test_monitor_error_record() {
        let e = MonitorError::RecordError("buffer full".to_string());
        assert!(e.to_string().contains("buffer full"));
    }

    #[test]
    fn test_monitor_error_stream_closed() {
        let e = MonitorError::StreamClosed;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_monitor_error_classification() {
        let e = MonitorError::ClassificationError("model not loaded".to_string());
        assert!(e.to_string().contains("model not loaded"));
    }

    #[test]
    fn test_monitor_total_counts_all() {
        let m = ApiMonitor::new();
        m.record(ApiCall::new("A", ApiCategory::FileSystem, 1));
        m.record(ApiCall::new("B", ApiCategory::Network, 1));
        m.record(ApiCall::new("C", ApiCategory::Registry, 1));
        assert_eq!(m.total(), 3);
    }

    #[test]
    fn test_api_call_default_suspicious_false() {
        let c = ApiCall::new("CreateFile", ApiCategory::FileSystem, 0);
        assert!(!c.suspicious);
    }

    #[test]
    fn test_monitor_event_kind_display_api_call() {
        let c = ApiCall::new("Foo", ApiCategory::System, 0);
        let k = MonitorEventKind::ApiCallEvent(c);
        assert!(k.to_string().contains("Foo"));
    }

    #[test]
    fn test_monitor_event_kind_display_anomaly() {
        let k = MonitorEventKind::Anomaly {
            score: 99.5,
            reason: "high_injection".to_string(),
        };
        assert!(k.to_string().contains("anomaly"));
    }

    // ── MONITORED_APIS expansion ─────────────────────────────────────────────

    #[test]
    fn test_monitored_apis_count_at_least_65() {
        // Original 50 + 20 newly added = 70+
        assert!(MONITORED_APIS.len() >= 65);
    }

    #[test]
    fn test_monitored_apis_has_nt_create_thread() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "NtCreateThread"));
    }

    #[test]
    fn test_monitored_apis_has_nt_suspend_thread() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "NtSuspendThread"));
    }

    #[test]
    fn test_monitored_apis_has_nt_resume_thread() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "NtResumeThread"));
    }

    #[test]
    fn test_monitored_apis_has_winhttp_open() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "WinHttpOpen"));
    }

    #[test]
    fn test_monitored_apis_has_winhttp_receive_response() {
        assert!(
            MONITORED_APIS
                .iter()
                .any(|s| s.name == "WinHttpReceiveResponse")
        );
    }

    #[test]
    fn test_monitored_apis_has_crypt_acquire_context() {
        assert!(
            MONITORED_APIS
                .iter()
                .any(|s| s.name == "CryptAcquireContextA")
        );
        assert!(
            MONITORED_APIS
                .iter()
                .any(|s| s.name == "CryptAcquireContextW")
        );
    }

    #[test]
    fn test_monitored_apis_has_sam_apis() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "SamOpenDomain"));
        assert!(
            MONITORED_APIS
                .iter()
                .any(|s| s.name == "SamEnumerateUsersInDomain")
        );
    }

    #[test]
    fn test_monitored_apis_has_net_user_enum() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "NetUserEnum"));
        assert!(MONITORED_APIS.iter().any(|s| s.name == "NetLocalGroupEnum"));
    }

    #[test]
    fn test_monitored_apis_has_find_file() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "FindFirstFileA"));
        assert!(MONITORED_APIS.iter().any(|s| s.name == "FindNextFileW"));
    }

    #[test]
    fn test_monitored_apis_has_sh_get_folder_path() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "SHGetFolderPathA"));
        assert!(MONITORED_APIS.iter().any(|s| s.name == "SHGetFolderPathW"));
    }

    #[test]
    fn test_monitored_apis_has_co_create_instance() {
        assert!(MONITORED_APIS.iter().any(|s| s.name == "CoCreateInstance"));
    }

    // ── BehaviorTimeline ─────────────────────────────────────────────────────

    #[test]
    fn test_behavior_timeline_classify_anti_analysis() {
        assert_eq!(
            BehaviorTimeline::classify_phase("IsDebuggerPresent"),
            BehaviorPhase::AntiAnalysis
        );
    }

    #[test]
    fn test_behavior_timeline_classify_persistence() {
        assert_eq!(
            BehaviorTimeline::classify_phase("RegSetValueExW"),
            BehaviorPhase::Persistence
        );
    }

    #[test]
    fn test_behavior_timeline_classify_c2_setup() {
        assert_eq!(
            BehaviorTimeline::classify_phase("WinHttpSendRequest"),
            BehaviorPhase::C2Setup
        );
    }

    #[test]
    fn test_behavior_timeline_classify_data_collection() {
        assert_eq!(
            BehaviorTimeline::classify_phase("SetWindowsHookExW"),
            BehaviorPhase::DataCollection
        );
    }

    #[test]
    fn test_behavior_timeline_classify_execution() {
        assert_eq!(
            BehaviorTimeline::classify_phase("CreateRemoteThread"),
            BehaviorPhase::Execution
        );
    }

    #[test]
    fn test_behavior_timeline_classify_cleanup() {
        assert_eq!(
            BehaviorTimeline::classify_phase("DeleteFileW"),
            BehaviorPhase::Cleanup
        );
    }

    #[test]
    fn test_behavior_timeline_classify_unknown_is_init() {
        assert_eq!(
            BehaviorTimeline::classify_phase("UnknownApiXyz"),
            BehaviorPhase::Initialization
        );
    }

    #[test]
    fn test_behavior_timeline_build_ordering() {
        let calls = vec![
            ApiCall::new("IsDebuggerPresent", ApiCategory::System, 1).with_ts(200),
            ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1).with_ts(50),
            ApiCall::new("RegSetValueExW", ApiCategory::Registry, 1).with_ts(300),
        ];
        let tl = BehaviorTimeline::build(&calls);
        assert_eq!(tl.len(), 3);
        // Should be sorted by timestamp.
        assert_eq!(tl[0].timestamp, 50);
        assert_eq!(tl[1].timestamp, 200);
        assert_eq!(tl[2].timestamp, 300);
    }

    #[test]
    fn test_behavior_timeline_detect_phases_single() {
        let calls = vec![
            ApiCall::new("IsDebuggerPresent", ApiCategory::System, 1).with_ts(100),
            ApiCall::new("CheckRemoteDebuggerPresent", ApiCategory::System, 1).with_ts(200),
        ];
        let tl = BehaviorTimeline::build(&calls);
        let phases = BehaviorTimeline::detect_phases(&tl);
        // Both calls are anti-analysis → merged into 1 span.
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0].0, BehaviorPhase::AntiAnalysis);
        assert_eq!(phases[0].1, 100);
        assert_eq!(phases[0].2, 200);
    }

    #[test]
    fn test_behavior_timeline_detect_phases_multiple() {
        let calls = vec![
            ApiCall::new("IsDebuggerPresent", ApiCategory::System, 1).with_ts(10),
            ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1).with_ts(20),
            ApiCall::new("RegSetValueExW", ApiCategory::Registry, 1).with_ts(30),
        ];
        let tl = BehaviorTimeline::build(&calls);
        let phases = BehaviorTimeline::detect_phases(&tl);
        // Three distinct phases.
        assert_eq!(phases.len(), 3);
    }

    #[test]
    fn test_behavior_timeline_empty() {
        let tl = BehaviorTimeline::build(&[]);
        assert!(tl.is_empty());
        let phases = BehaviorTimeline::detect_phases(&tl);
        assert!(phases.is_empty());
    }

    #[test]
    fn test_behavior_timeline_phase_counts() {
        let calls = vec![
            ApiCall::new("IsDebuggerPresent", ApiCategory::System, 1).with_ts(10),
            ApiCall::new("CheckRemoteDebuggerPresent", ApiCategory::System, 1).with_ts(20),
            ApiCall::new("VirtualAllocEx", ApiCategory::Memory, 1).with_ts(30),
        ];
        let tl = BehaviorTimeline::build(&calls);
        let counts = BehaviorTimeline::phase_counts(&tl);
        assert_eq!(*counts.get(&BehaviorPhase::AntiAnalysis).unwrap_or(&0), 2);
        assert_eq!(*counts.get(&BehaviorPhase::Execution).unwrap_or(&0), 1);
    }

    #[test]
    fn test_behavior_phase_display() {
        assert_eq!(BehaviorPhase::Initialization.to_string(), "initialization");
        assert_eq!(BehaviorPhase::AntiAnalysis.to_string(), "anti_analysis");
        assert_eq!(BehaviorPhase::C2Setup.to_string(), "c2_setup");
    }

    // ── NetworkBehaviorAnalyzer ──────────────────────────────────────────────

    #[test]
    fn test_network_analyzer_empty_pcap() {
        let report = NetworkBehaviorAnalyzer::analyze(&[]);
        assert!(report.unique_ips.is_empty());
        assert!(!report.has_c2_beacon);
    }

    #[test]
    fn test_network_analyzer_invalid_magic() {
        // Non-PCAP data should return an empty report.
        let junk = vec![0xFFu8; 100];
        let report = NetworkBehaviorAnalyzer::analyze(&junk);
        assert!(report.unique_ips.is_empty());
    }

    #[test]
    fn test_detect_beacon_pattern_too_few() {
        let ts = vec![0u64, 1000, 2000, 3000, 4000]; // 5 points → 4 intervals, need 5
        let result = NetworkBehaviorAnalyzer::detect_beacon_pattern(&ts);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_beacon_pattern_regular() {
        // 7 timestamps with ~10 s intervals (small random jitter within 25%).
        let ts: Vec<u64> = (0..7).map(|i| i * 10_000).collect();
        let result = NetworkBehaviorAnalyzer::detect_beacon_pattern(&ts);
        assert!(result.is_some());
        let interval = result.unwrap();
        assert!((9_500..=10_500).contains(&interval));
    }

    #[test]
    fn test_detect_beacon_pattern_irregular() {
        // Highly variable intervals → no beacon.
        let ts = vec![0u64, 1000, 10_000, 11_000, 50_000, 51_000, 200_000];
        let result = NetworkBehaviorAnalyzer::detect_beacon_pattern(&ts);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_beacon_out_of_range_interval() {
        // Intervals shorter than 1 s → not a valid beacon.
        let ts: Vec<u64> = (0..7).map(|i| i * 500).collect();
        let result = NetworkBehaviorAnalyzer::detect_beacon_pattern(&ts);
        assert!(result.is_none());
    }

    #[test]
    fn test_network_report_is_exfiltrating() {
        let mut r = NetworkBehaviorReport::empty();
        r.data_exfiltrated_bytes = 2 * 1024 * 1024;
        assert!(r.is_exfiltrating());
    }

    #[test]
    fn test_network_report_not_exfiltrating() {
        let r = NetworkBehaviorReport::empty();
        assert!(!r.is_exfiltrating());
    }

    #[test]
    fn test_network_report_is_suspicious_beacon() {
        let mut r = NetworkBehaviorReport::empty();
        r.has_c2_beacon = true;
        assert!(r.is_suspicious());
    }

    #[test]
    fn test_http_summary_is_likely_c2_true() {
        let s = HttpSummary {
            method: "POST".to_string(),
            url: "http://1.2.3.4/gate.php".to_string(),
            status_code: Some(200),
            request_bytes: 512,
            response_bytes: 128,
            ts_ms: 1000,
        };
        assert!(s.is_likely_c2());
    }

    #[test]
    fn test_http_summary_is_likely_c2_get() {
        let s = HttpSummary {
            method: "GET".to_string(),
            url: "http://example.com/page".to_string(),
            status_code: None,
            request_bytes: 100,
            response_bytes: 0,
            ts_ms: 0,
        };
        assert!(!s.is_likely_c2());
    }

    #[test]
    fn test_from_api_calls_extracts_domains() {
        let calls = vec![
            ApiCall::new("getaddrinfo", ApiCategory::Network, 1)
                .with_arg("evil.c2domain.net")
                .with_ts(100),
            ApiCall::new("getaddrinfo", ApiCategory::Network, 1)
                .with_arg("evil.c2domain.net") // duplicate
                .with_ts(200),
        ];
        let report = NetworkBehaviorAnalyzer::from_api_calls(&calls);
        assert_eq!(report.unique_domains.len(), 1);
        assert_eq!(report.dns_queries.len(), 1);
    }

    #[test]
    fn test_from_api_calls_beacon_detection() {
        // 7 WinHttpSendRequest calls at 30 s intervals.
        let calls: Vec<ApiCall> = (0..7)
            .map(|i| {
                ApiCall::new("WinHttpSendRequest", ApiCategory::Network, 1).with_ts(i * 30_000)
            })
            .collect();
        let report = NetworkBehaviorAnalyzer::from_api_calls(&calls);
        assert!(report.has_c2_beacon);
        assert!(report.beacon_interval_ms.is_some());
    }

    #[test]
    fn test_from_api_calls_no_beacon_few_calls() {
        let calls = vec![
            ApiCall::new("send", ApiCategory::Network, 1).with_ts(0),
            ApiCall::new("send", ApiCategory::Network, 1).with_ts(10_000),
        ];
        let report = NetworkBehaviorAnalyzer::from_api_calls(&calls);
        assert!(!report.has_c2_beacon);
    }
}


