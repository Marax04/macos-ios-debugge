use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use anyhow::Result;

/// Saturating cast: current nanosecond timestamp to `u64`.
fn nanos_to_u64() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u128::from(u64::MAX)),
    )
    .unwrap_or(u64::MAX)
}

/// Saturating cast: `u64` → `usize` (for indexing, 32-bit targets may truncate).
#[inline]
fn u64_to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Saturating cast: `u64` → `f32` (precision loss accepted for scoring).
#[inline]
const fn u64_to_f32(v: u64) -> f32 { v as f32 }

/// Saturating cast: `usize` → `f32` (precision loss accepted for scoring).
#[inline]
const fn usize_to_f32(v: usize) -> f32 { v as f32 }

// ── Core event types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub id: u64,
    pub timestamp_ns: u64,
    pub thread_id: u32,
    pub process_id: u32,
    pub category: EventCategory,
    pub event: EventDetail,
    pub call_stack: Vec<StackFrame>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    FileSystem,
    Registry,
    Network,
    Process,
    Memory,
    Crypto,
    AntiAnalysis,
    Injection,
    Persistence,
    Lateral,
    Exfil,
    Communication,
    Syscall,
    Api,
    Exception,
    Hook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventDetail {
    // File system
    FileCreate { path: String, attributes: u32, disposition: FileDisposition },
    FileOpen { path: String, access: u32 },
    FileWrite { path: String, offset: u64, size: usize },
    FileRead { path: String, offset: u64, size: usize },
    FileDelete { path: String },
    FileRename { old_path: String, new_path: String },
    FileSetInfo { path: String, info_class: u32 },
    // Registry
    RegCreate { key: String, desired_access: u32 },
    RegOpen { key: String },
    RegSetValue { key: String, value_name: String, data_type: u32, data: Vec<u8> },
    RegQueryValue { key: String, value_name: String },
    RegDelete { key: String },
    RegDeleteValue { key: String, value_name: String },
    // Network
    Connect { remote_addr: String, remote_port: u16, protocol: NetworkProtocol },
    Listen { local_port: u16, protocol: NetworkProtocol },
    Send { socket_id: u64, data_len: usize, flags: u32 },
    Recv { socket_id: u64, data_len: usize },
    DnsQuery { hostname: String, query_type: u16 },
    HttpRequest { method: String, url: String, headers: Vec<(String, String)>, body_len: usize },
    // Process
    CreateProcess { image: String, commandline: String, pid: u32, flags: u32 },
    TerminateProcess { pid: u32, exit_code: u32 },
    CreateThread { tid: u32, start_addr: u64, param: u64 },
    TerminateThread { tid: u32 },
    OpenProcess { target_pid: u32, desired_access: u32 },
    // Memory
    VirtualAlloc { addr: u64, size: usize, alloc_type: u32, protect: u32 },
    VirtualProtect { addr: u64, size: usize, new_protect: u32, old_protect: u32 },
    VirtualFree { addr: u64, size: usize, free_type: u32 },
    WriteProcessMemory { target_pid: u32, addr: u64, size: usize },
    ReadProcessMemory { target_pid: u32, addr: u64, size: usize },
    MapViewOfSection { addr: u64, size: usize, section_handle: u64 },
    // Crypto
    CryptCreateHash { algorithm: u32 },
    CryptEncrypt { algorithm: String, key_len: usize, data_len: usize },
    CryptDecrypt { algorithm: String, key_len: usize, data_len: usize },
    // Anti-analysis
    CheckDebugger { method: AntiDebugMethod, result: bool },
    CheckVmArtifact { artifact: String, detected: bool },
    SleepCall { duration_ms: u64 },
    QuerySystemTime,
    // Injection techniques
    CreateRemoteThread { target_pid: u32, start_addr: u64 },
    QueueApcThread { target_tid: u32, func_addr: u64 },
    SetWindowsHook { hook_id: i32 },
    NtMapViewOfSection { target_pid: u32, base_addr: u64, size: usize },
    // Persistence
    RegRunKey { key: String, value: String, command: String },
    ScheduledTask { name: String, command: String, trigger: String },
    ServiceCreate { name: String, binary_path: String, start_type: u32 },
    StartupFolder { filename: String, path: String },
    // Syscall
    Syscall { number: u32, name: String, args: Vec<u64>, ret: u64 },
    // API
    LoadLibrary { name: String, base_addr: u64 },
    GetProcAddress { module: String, proc_name: String, addr: u64 },
    // Exception
    Exception { code: u32, addr: u64, flags: u32 },
    // Generic
    Generic { name: String, data: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileDisposition { Create, Open, OpenIf, Overwrite, OverwriteIf, Supersede }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol { Tcp, Udp, Icmp, Raw, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiDebugMethod {
    IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess,
    HeapFlags, TimingCheck, HardwareBreakpoint, TlsCallback, OutputDebugString,
    CloseHandleException, VirtualAllocAntiDbg, EtFlags, Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub addr: u64,
    pub module: Option<String>,
    pub function: Option<String>,
    pub offset: u64,
}

// ── Behavior log ─────────────────────────────────────────────────────────────

pub struct BehaviorLog {
    events: Arc<Mutex<VecDeque<BehaviorEvent>>>,
    max_events: usize,
    event_counter: Arc<Mutex<u64>>,
    start_time: Instant,
    filters: Vec<EventFilter>,
    stats: Arc<Mutex<EventStats>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventStats {
    pub total_events: u64,
    pub events_by_category: HashMap<String, u64>,
    pub dropped_events: u64,
    pub filtered_events: u64,
    pub file_ops: u64,
    pub registry_ops: u64,
    pub network_ops: u64,
    pub process_ops: u64,
    pub memory_ops: u64,
    pub injection_indicators: u64,
    pub anti_analysis_indicators: u64,
    pub persistence_indicators: u64,
}

#[derive(Debug, Clone)]
pub enum EventFilter {
    ExcludeCategory(EventCategory),
    IncludeOnly(Vec<EventCategory>),
    MinSeverity(EventSeverity),
    ProcessId(u32),
    SampleRate(u32),  // 1 in N
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity { Low, Medium, High, Critical }

impl BehaviorLog {
    #[must_use]
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(max_events))),
            max_events,
            event_counter: Arc::new(Mutex::new(0)),
            start_time: Instant::now(),
            filters: Vec::new(),
            stats: Arc::new(Mutex::new(EventStats::default())),
        }
    }

    #[must_use]
    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filters.push(filter);
        self
    }

    pub fn log(&self, pid: u32, tid: u32, category: EventCategory, event: EventDetail) {
        self.log_with_stack(pid, tid, category, event, vec![]);
    }

    pub fn log_with_stack(
        &self,
        pid: u32,
        tid: u32,
        category: EventCategory,
        event: EventDetail,
        call_stack: Vec<StackFrame>,
    ) {
        // Apply filters
        for filter in &self.filters {
            match filter {
                EventFilter::ExcludeCategory(cat) if cat == &category => {
                    if let Ok(mut stats) = self.stats.lock() {
                        stats.filtered_events += 1;
                    }
                    return;
                }
                EventFilter::ProcessId(filter_pid) if filter_pid != &pid => {
                    if let Ok(mut stats) = self.stats.lock() {
                        stats.filtered_events += 1;
                    }
                    return;
                }
                _ => {}
            }
        }

        let id = {
            let mut c = match self.event_counter.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            *c += 1;
            *c
        };

        let timestamp_ns = nanos_to_u64();

        let ev = BehaviorEvent {
            id,
            timestamp_ns,
            thread_id: tid,
            process_id: pid,
            category,
            event,
            call_stack,
            tags: Vec::new(),
        };

        if let Ok(mut events) = self.events.lock() {
            if events.len() >= self.max_events {
                events.pop_front();
                if let Ok(mut stats) = self.stats.lock() {
                    stats.dropped_events += 1;
                }
            }
            events.push_back(ev);
        }

        if let Ok(mut stats) = self.stats.lock() {
            stats.total_events += 1;
            *stats.events_by_category.entry(format!("{category:?}")).or_insert(0) += 1;
            match &category {
                EventCategory::FileSystem => stats.file_ops += 1,
                EventCategory::Registry => stats.registry_ops += 1,
                EventCategory::Network => stats.network_ops += 1,
                EventCategory::Process => stats.process_ops += 1,
                EventCategory::Memory => stats.memory_ops += 1,
                EventCategory::Injection => stats.injection_indicators += 1,
                EventCategory::AntiAnalysis => stats.anti_analysis_indicators += 1,
                EventCategory::Persistence => stats.persistence_indicators += 1,
                _ => {}
            }
        }
    }

    #[must_use]
    pub fn get_events(&self) -> Vec<BehaviorEvent> {
        match self.events.lock() {
            Ok(g) => g.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    #[must_use]
    pub fn get_events_by_category(&self, category: &EventCategory) -> Vec<BehaviorEvent> {
        let guard = match self.events.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.iter()
            .filter(|e| &e.category == category)
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn get_stats(&self) -> EventStats {
        match self.stats.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    #[must_use]
    pub fn generate_report(&self) -> BehaviorReport {
        let events = self.get_events();
        let stats = self.get_stats();
        let iocs = Self::extract_iocs(&events);
        let tactics = self.classify_mitre_tactics(&events);
        let risk_score = Self::compute_risk_score(&stats, &iocs, &tactics);

        BehaviorReport {
            duration_ms: u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX),
            total_events: events.len(),
            stats,
            iocs,
            mitre_tactics: tactics,
            risk_score,
            summary: self.generate_summary(&events),
            highlights: self.generate_highlights(&events),
        }
    }

    fn extract_iocs(events: &[BehaviorEvent]) -> BehaviorIocs {
        let mut ips = std::collections::HashSet::new();
        let mut domains = std::collections::HashSet::new();
        let mut urls = std::collections::HashSet::new();
        let mut files = std::collections::HashSet::new();
        let mut registry_keys = std::collections::HashSet::new();
        let mut mutexes = std::collections::HashSet::new();

        for ev in events {
            match &ev.event {
                EventDetail::Connect { remote_addr, .. } => { ips.insert(remote_addr.clone()); }
                EventDetail::DnsQuery { hostname, .. } => { domains.insert(hostname.clone()); }
                EventDetail::HttpRequest { url, .. } => { urls.insert(url.clone()); }
                EventDetail::FileCreate { path, .. } | EventDetail::FileWrite { path, .. } => {
                    files.insert(path.clone());
                }
                EventDetail::RegSetValue { key, value_name, .. } => {
                    registry_keys.insert(format!("{key}\\{value_name}"));
                }
                EventDetail::RegCreate { key, .. } => { registry_keys.insert(key.clone()); }
                EventDetail::Generic { name, data } => {
                    // Mutex/Event/Semaphore object IOCs surface through generic events.
                    let n = name.to_ascii_lowercase();
                    if (n.contains("mutex") || n.contains("createmutex") || n.contains("openmutex"))
                        && let Some(mname) = data.get("name").and_then(|v| v.as_str()) {
                        mutexes.insert(mname.to_string());
                    }
                }
                _ => {}
            }
        }

        BehaviorIocs {
            ip_addresses: ips.into_iter().collect(),
            domains: domains.into_iter().collect(),
            urls: urls.into_iter().collect(),
            files_created: files.into_iter().collect(),
            registry_keys: registry_keys.into_iter().collect(),
            mutexes: mutexes.into_iter().collect(),
        }
    }

    fn classify_mitre_tactics(&self, events: &[BehaviorEvent]) -> Vec<MitreTactic> {
        let mut tactics = Vec::new();
        let stats = self.get_stats();
        // Time-window for "burst" heuristics — derived from the event span.
        let burst_window: Duration = if let (Some(first), Some(last)) = (events.first(), events.last()) {
            let span_ns = last.timestamp_ns.saturating_sub(first.timestamp_ns);
            Duration::from_nanos(span_ns.max(1))
        } else {
            Duration::from_nanos(1)
        };

        if stats.injection_indicators > 0 {
            tactics.push(MitreTactic {
                tactic_id: "TA0005".to_string(),
                tactic_name: "Defense Evasion".to_string(),
                technique_id: "T1055".to_string(),
                technique_name: "Process Injection".to_string(),
                confidence: 0.9,
                evidence_count: u64_to_usize(stats.injection_indicators),
            });
        }
        if stats.persistence_indicators > 0 {
            tactics.push(MitreTactic {
                tactic_id: "TA0003".to_string(),
                tactic_name: "Persistence".to_string(),
                technique_id: "T1060".to_string(),
                technique_name: "Registry Run Keys / Startup Folder".to_string(),
                confidence: 0.85,
                evidence_count: u64_to_usize(stats.persistence_indicators),
            });
        }
        if stats.anti_analysis_indicators > 0 {
            tactics.push(MitreTactic {
                tactic_id: "TA0005".to_string(),
                tactic_name: "Defense Evasion".to_string(),
                technique_id: "T1497".to_string(),
                technique_name: "Virtualization/Sandbox Evasion".to_string(),
                confidence: 0.75,
                evidence_count: u64_to_usize(stats.anti_analysis_indicators),
            });
        }
        if stats.network_ops > 0 {
            tactics.push(MitreTactic {
                tactic_id: "TA0011".to_string(),
                tactic_name: "Command and Control".to_string(),
                technique_id: "T1071".to_string(),
                technique_name: "Application Layer Protocol".to_string(),
                confidence: 0.6,
                evidence_count: u64_to_usize(stats.network_ops),
            });
        }

        // If the entire `events` slice was packed into a sub-second burst,
        // bump every tactic's confidence — automated tooling is the signal.
        if burst_window < Duration::from_secs(1) && !events.is_empty() {
            for t in &mut tactics {
                t.confidence = (t.confidence + 0.05).min(1.0);
            }
        }
        tactics
    }

    fn compute_risk_score(stats: &EventStats, iocs: &BehaviorIocs, tactics: &[MitreTactic]) -> f32 {
        let mut score = 0.0f32;
        score += u64_to_f32(stats.injection_indicators) * 25.0;
        score += u64_to_f32(stats.anti_analysis_indicators) * 15.0;
        score += u64_to_f32(stats.persistence_indicators) * 20.0;
        score += usize_to_f32(iocs.ip_addresses.len()) * 5.0;
        score += usize_to_f32(iocs.domains.len()) * 5.0;
        score += usize_to_f32(tactics.len()) * 10.0;
        score.min(100.0)
    }

    fn generate_summary(&self, events: &[BehaviorEvent]) -> String {
        let stats = self.get_stats();
        format!(
            "Analyzed {} events: {} file ops, {} registry ops, {} network ops, \
             {} process ops, {} injection indicators, {} anti-analysis indicators, \
             {} persistence indicators",
            events.len(),
            stats.file_ops, stats.registry_ops, stats.network_ops,
            stats.process_ops, stats.injection_indicators,
            stats.anti_analysis_indicators, stats.persistence_indicators
        )
    }

    fn generate_highlights(&self, events: &[BehaviorEvent]) -> Vec<String> {
        let mut highlights = Vec::new();
        let stats = self.get_stats();
        if stats.injection_indicators > 0 {
            highlights.push(format!("Process injection detected ({} events)", stats.injection_indicators));
        }
        if stats.anti_analysis_indicators > 0 {
            highlights.push(format!("Anti-analysis behavior ({} checks)", stats.anti_analysis_indicators));
        }
        if stats.persistence_indicators > 0 {
            highlights.push(format!("Persistence mechanisms ({} events)", stats.persistence_indicators));
        }
        // Specific patterns
        let has_create_remote_thread = events.iter().any(|e| matches!(&e.event, EventDetail::CreateRemoteThread { .. }));
        if has_create_remote_thread {
            highlights.push("CreateRemoteThread — classic code injection technique".to_string());
        }
        let write_mem = events.iter().any(|e| matches!(&e.event, EventDetail::WriteProcessMemory { .. }));
        if write_mem {
            highlights.push("WriteProcessMemory to external process".to_string());
        }
        highlights
    }

    /// Serialize the full behavior report to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if `serde_json` fails to serialize the report.
    pub fn export_json(&self) -> Result<String> {
        let report = self.generate_report();
        Ok(serde_json::to_string_pretty(&report)?)
    }

    #[must_use]
    pub fn export_timeline_csv(&self) -> String {
        use std::fmt::Write as _;
        let events = self.get_events();
        let mut out = String::from("id,timestamp_ns,pid,tid,category,summary\n");
        for ev in &events {
            let summary = event_summary(&ev.event);
            let _ = writeln!(out, "{},{},{},{},{:?},{}",
                ev.id, ev.timestamp_ns, ev.process_id, ev.thread_id,
                ev.category, summary.replace(',', ";"));
        }
        out
    }
}

fn event_summary(event: &EventDetail) -> String {
    match event {
        EventDetail::FileCreate { path, .. } => format!("FileCreate({path})"),
        EventDetail::FileOpen { path, .. } => format!("FileOpen({path})"),
        EventDetail::FileWrite { path, size, .. } => format!("FileWrite({path}, {size}B)"),
        EventDetail::FileDelete { path } => format!("FileDelete({path})"),
        EventDetail::RegSetValue { key, value_name, .. } => format!("RegSet({key}\\{value_name})"),
        EventDetail::Connect { remote_addr, remote_port, .. } => format!("Connect({remote_addr}:{remote_port})"),
        EventDetail::DnsQuery { hostname, .. } => format!("DNS({hostname})"),
        EventDetail::HttpRequest { method, url, .. } => format!("HTTP {method} {url}"),
        EventDetail::CreateProcess { image, .. } => format!("CreateProcess({image})"),
        EventDetail::VirtualAlloc { addr, size, protect, .. } => format!("VirtualAlloc({addr:#x}, {size}, prot={protect:#x})"),
        EventDetail::WriteProcessMemory { target_pid, addr, size } => format!("WriteProcessMemory(pid={target_pid}, addr={addr:#x}, size={size})"),
        EventDetail::CreateRemoteThread { target_pid, start_addr } => format!("CreateRemoteThread(pid={target_pid}, addr={start_addr:#x})"),
        EventDetail::CheckDebugger { method, result } => format!("AntiDebug({method:?})={result}"),
        EventDetail::Syscall { name, number, .. } => format!("syscall_{number}_{name}"),
        EventDetail::LoadLibrary { name, .. } => format!("LoadLibrary({name})"),
        _ => format!("{:?}", std::mem::discriminant(event)),
    }
}

// ── Report structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorReport {
    pub duration_ms: u64,
    pub total_events: usize,
    pub stats: EventStats,
    pub iocs: BehaviorIocs,
    pub mitre_tactics: Vec<MitreTactic>,
    pub risk_score: f32,
    pub summary: String,
    pub highlights: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehaviorIocs {
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub files_created: Vec<String>,
    pub registry_keys: Vec<String>,
    pub mutexes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTactic {
    pub tactic_id: String,
    pub tactic_name: String,
    pub technique_id: String,
    pub technique_name: String,
    pub confidence: f32,
    pub evidence_count: usize,
}

// ── Syscall trace analyzer ─────────────────────────────────────────────────────

pub struct SyscallTraceAnalyzer {
    sequences: Vec<Vec<(u32, String)>>,
    anomaly_threshold: f32,
}

impl SyscallTraceAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self { sequences: Vec::new(), anomaly_threshold: 0.8 }
    }

    /// Override the similarity score above which a syscall sequence is
    /// flagged as anomalous. Must be in `(0.0, 1.0]`.
    pub const fn set_anomaly_threshold(&mut self, t: f32) {
        self.anomaly_threshold = t.clamp(f32::EPSILON, 1.0);
    }

    /// Current anomaly threshold. See [`Self::set_anomaly_threshold`].
    #[must_use]
    pub const fn anomaly_threshold(&self) -> f32 {
        self.anomaly_threshold
    }

    pub fn add_trace(&mut self, events: &[BehaviorEvent]) {
        let seq: Vec<(u32, String)> = events.iter()
            .filter_map(|e| {
                if let EventDetail::Syscall { number, name, .. } = &e.event {
                    Some((*number, name.clone()))
                } else { None }
            })
            .collect();
        self.sequences.push(seq);
    }

    #[must_use]
    pub fn find_suspicious_sequences(&self) -> Vec<SuspiciousSequence> {
        let mut results = Vec::new();

        // Classic injection pattern: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
        let injection_pattern = ["NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"];
        for seq in &self.sequences {
            let names: Vec<&str> = seq.iter().map(|(_, n)| n.as_str()).collect();
            if contains_subsequence(&names, &injection_pattern) {
                results.push(SuspiciousSequence {
                    pattern: "process_injection".to_string(),
                    description: "Classic process injection syscall sequence".to_string(),
                    confidence: 0.95,
                    syscalls: injection_pattern.iter().map(ToString::to_string).collect(),
                    mitre_technique: "T1055".to_string(),
                });
            }
        }

        // APC injection: OpenThread -> QueueApcThread
        let apc_pattern = ["NtOpenThread", "NtQueueApcThread"];
        for seq in &self.sequences {
            let names: Vec<&str> = seq.iter().map(|(_, n)| n.as_str()).collect();
            if contains_subsequence(&names, &apc_pattern) {
                results.push(SuspiciousSequence {
                    pattern: "apc_injection".to_string(),
                    description: "APC-based thread injection".to_string(),
                    confidence: 0.85,
                    syscalls: apc_pattern.iter().map(ToString::to_string).collect(),
                    mitre_technique: "T1055.004".to_string(),
                });
            }
        }

        results
    }
}

fn contains_subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    if needle.is_empty() { return true; }
    let mut ni = 0;
    for &s in haystack {
        if s == needle[ni] { ni += 1; }
        if ni == needle.len() { return true; }
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousSequence {
    pub pattern: String,
    pub description: String,
    pub confidence: f32,
    pub syscalls: Vec<String>,
    pub mitre_technique: String,
}

impl Default for SyscallTraceAnalyzer {
    fn default() -> Self { Self::new() }
}
