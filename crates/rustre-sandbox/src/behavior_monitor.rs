// behavior_monitor.rs — Behavior monitor for sandbox analysis in RustRE

use std::collections::HashMap;

// ─── EventType ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventType {
    FileCreate,
    FileRead,
    FileWrite,
    FileDelete,
    RegistryCreate,
    RegistryWrite,
    RegistryDelete,
    NetworkConnect,
    NetworkSend,
    ProcessCreate,
    DllLoad,
    Mutex,
    Exception,
}

impl EventType {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FileCreate => "file_create",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::FileDelete => "file_delete",
            Self::RegistryCreate => "reg_create",
            Self::RegistryWrite => "reg_write",
            Self::RegistryDelete => "reg_delete",
            Self::NetworkConnect => "net_connect",
            Self::NetworkSend => "net_send",
            Self::ProcessCreate => "proc_create",
            Self::DllLoad => "dll_load",
            Self::Mutex => "mutex",
            Self::Exception => "exception",
        }
    }

    #[must_use] 
    pub const fn is_network(&self) -> bool {
        matches!(self, Self::NetworkConnect | Self::NetworkSend)
    }

    #[must_use] 
    pub const fn is_file(&self) -> bool {
        matches!(self, Self::FileCreate | Self::FileRead | Self::FileWrite | Self::FileDelete)
    }

    #[must_use] 
    pub const fn is_registry(&self) -> bool {
        matches!(self, Self::RegistryCreate | Self::RegistryWrite | Self::RegistryDelete)
    }
}

// ─── EventDetails ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EventDetails {
    FileDetails { path: String, size: u64 },
    RegDetails { key: String, value: String },
    NetworkDetails { remote: String, port: u16 },
    ProcessDetails { name: String, cmdline: String },
    ModuleDetails { name: String, base: u64 },
    GenericDetails { info: String },
}

impl EventDetails {
    #[must_use] 
    pub fn summary(&self) -> String {
        match self {
            Self::FileDetails { path, size } => format!("file={path} size={size}"),
            Self::RegDetails { key, value } => format!("key={key} val={value}"),
            Self::NetworkDetails { remote, port } => format!("{remote}:{port}"),
            Self::ProcessDetails { name, cmdline } => format!("{name}  {cmdline}"),
            Self::ModuleDetails { name, base } => format!("{name} @ 0x{base:X}"),
            Self::GenericDetails { info } => info.clone(),
        }
    }
}

// ─── MonitorEvent ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MonitorEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub event_type: EventType,
    pub details: EventDetails,
}

impl MonitorEvent {
    #[must_use] 
    pub const fn new(timestamp_ns: u64, pid: u32, tid: u32, event_type: EventType, details: EventDetails) -> Self {
        Self { timestamp_ns, pid, tid, event_type, details }
    }

    #[must_use] 
    pub fn is_suspicious(&self) -> bool {
        match &self.details {
            EventDetails::FileDetails { path, .. } => {
                let pl = path.to_ascii_lowercase();
                pl.contains("system32") || pl.contains("autorun") || pl.contains("startup")
            }
            EventDetails::RegDetails { key, .. } => {
                let kl = key.to_ascii_lowercase();
                kl.contains("run") || kl.contains("runonce") || kl.contains("services")
            }
            EventDetails::NetworkDetails { remote, .. } => {
                !is_private_ip(remote)
            }
            _ => false,
        }
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.1")
        || ip == "127.0.0.1" || ip == "::1"
}

// ─── BehaviorPattern ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub name: String,
    pub severity: u8,
    pub description: String,
    pub matching_events: usize,
}

impl BehaviorPattern {
    #[must_use] 
    pub fn new(name: &str, severity: u8, description: &str, matching_events: usize) -> Self {
        Self {
            name: name.to_string(),
            severity,
            description: description.to_string(),
            matching_events,
        }
    }
}

// ─── BehaviorTimeline ────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct BehaviorTimeline {
    pub events: Vec<MonitorEvent>,
}

impl BehaviorTimeline {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn add_event(&mut self, event: MonitorEvent) {
        self.events.push(event);
        // Keep sorted by timestamp
        let n = self.events.len();
        if n >= 2 && self.events[n-1].timestamp_ns < self.events[n-2].timestamp_ns {
            self.events.sort_by_key(|e| e.timestamp_ns);
        }
    }

    #[must_use] 
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    #[must_use] 
    pub fn events_for_pid(&self, pid: u32) -> Vec<&MonitorEvent> {
        self.events.iter().filter(|e| e.pid == pid).collect()
    }

    #[must_use] 
    pub fn events_in_window(&self, start_ns: u64, end_ns: u64) -> Vec<&MonitorEvent> {
        self.events.iter().filter(|e| e.timestamp_ns >= start_ns && e.timestamp_ns <= end_ns).collect()
    }

    /// Group events by type.
    #[must_use] 
    pub fn categorize_events(&self) -> HashMap<String, Vec<&MonitorEvent>> {
        let mut map: HashMap<String, Vec<&MonitorEvent>> = HashMap::new();
        for event in &self.events {
            map.entry(event.event_type.as_str().to_string()).or_default().push(event);
        }
        map
    }

    /// Detect known malicious patterns in the timeline.
    #[must_use] 
    pub fn detect_malicious_patterns(&self) -> Vec<BehaviorPattern> {
        let mut patterns = Vec::new();

        // Pattern: Persistence via registry run keys
        let reg_run_writes: Vec<&MonitorEvent> = self.events.iter().filter(|e| {
            e.event_type == EventType::RegistryWrite
                && matches!(&e.details, EventDetails::RegDetails { key, .. } if
                    key.to_ascii_lowercase().contains("run"))
        }).collect();
        if !reg_run_writes.is_empty() {
            patterns.push(BehaviorPattern::new(
                "RegistryPersistence",
                80,
                "Writes to registry Run/RunOnce keys for persistence",
                reg_run_writes.len(),
            ));
        }

        // Pattern: Network beacon (multiple outbound connections to non-private IPs)
        let external_connects: Vec<&MonitorEvent> = self.events.iter().filter(|e| {
            e.event_type == EventType::NetworkConnect
                && matches!(&e.details, EventDetails::NetworkDetails { remote, .. } if !is_private_ip(remote))
        }).collect();
        if external_connects.len() >= 3 {
            patterns.push(BehaviorPattern::new(
                "NetworkBeacon",
                70,
                "Multiple connections to external IP addresses",
                external_connects.len(),
            ));
        }

        // Pattern: Process injection (WriteFile to System32 + ProcessCreate)
        let sys32_writes = self.events.iter().filter(|e| {
            e.event_type == EventType::FileWrite
                && matches!(&e.details, EventDetails::FileDetails { path, .. } if
                    path.to_ascii_lowercase().contains("system32"))
        }).count();
        let proc_creates = self.events.iter().filter(|e| e.event_type == EventType::ProcessCreate).count();
        if sys32_writes > 0 && proc_creates > 1 {
            patterns.push(BehaviorPattern::new(
                "CodeInjection",
                90,
                "Writes to System32 + spawns child processes",
                sys32_writes + proc_creates,
            ));
        }

        // Pattern: Self-deletion (deletes own executable)
        let file_deletes = self.events.iter().filter(|e| e.event_type == EventType::FileDelete).count();
        if file_deletes > 0 {
            patterns.push(BehaviorPattern::new(
                "SelfDeletion",
                60,
                "Deletes files (possibly self-deletion for cleanup)",
                file_deletes,
            ));
        }

        // Pattern: Mutex creation (anti-analysis / single instance)
        let mutex_count = self.events.iter().filter(|e| e.event_type == EventType::Mutex).count();
        if mutex_count > 0 {
            patterns.push(BehaviorPattern::new(
                "MutexCreation",
                30,
                "Creates mutex (single-instance enforcement or marker)",
                mutex_count,
            ));
        }

        // Pattern: DLL side-loading (DLL loaded from user-writable path)
        let suspicious_dlls: Vec<&MonitorEvent> = self.events.iter().filter(|e| {
            e.event_type == EventType::DllLoad
                && matches!(&e.details, EventDetails::ModuleDetails { name, .. } if
                    name.to_ascii_lowercase().contains("temp") || name.contains("AppData"))
        }).collect();
        if !suspicious_dlls.is_empty() {
            patterns.push(BehaviorPattern::new(
                "DllSideloading",
                75,
                "Loads DLL from user-writable directory (Temp/AppData)",
                suspicious_dlls.len(),
            ));
        }

        // Pattern: Exception storm (may indicate anti-debug or exploit)
        let exceptions = self.events.iter().filter(|e| e.event_type == EventType::Exception).count();
        if exceptions >= 5 {
            patterns.push(BehaviorPattern::new(
                "ExceptionStorm",
                65,
                "Large number of exceptions (possible exploit or anti-debug)",
                exceptions,
            ));
        }

        // Pattern: Autorun file creation
        let autorun_creates: Vec<&MonitorEvent> = self.events.iter().filter(|e| {
            e.event_type == EventType::FileCreate
                && matches!(&e.details, EventDetails::FileDetails { path, .. } if
                    path.to_ascii_lowercase().contains("autorun"))
        }).collect();
        if !autorun_creates.is_empty() {
            patterns.push(BehaviorPattern::new(
                "AutorunPersistence",
                85,
                "Creates autorun.inf file for USB persistence",
                autorun_creates.len(),
            ));
        }

        patterns
    }

    /// Compute overall threat score from detected patterns.
    #[must_use] 
    pub fn threat_score(&self) -> u8 {
        let patterns = self.detect_malicious_patterns();
        if patterns.is_empty() { return 0; }
        let max = patterns.iter().map(|p| p.severity).max().unwrap_or(0);
        let count_bonus = u8::try_from(patterns.len().min(20)).unwrap_or(20);
        max.saturating_add(count_bonus).min(100)
    }

    #[must_use] 
    pub fn suspicious_event_count(&self) -> usize {
        self.events.iter().filter(|e| e.is_suspicious()).count()
    }
}

// ─── BehaviorMonitor ─────────────────────────────────────────────────────────

pub struct BehaviorMonitor {
    pub timeline: BehaviorTimeline,
    clock_ns: u64,
}

impl BehaviorMonitor {
    #[must_use] 
    pub fn new() -> Self {
        Self { timeline: BehaviorTimeline::new(), clock_ns: 0 }
    }

    const fn next_timestamp(&mut self) -> u64 {
        self.clock_ns += 1_000_000; // 1ms per event for simulation
        self.clock_ns
    }

    pub fn record_file_event(&mut self, event_type: EventType, pid: u32, path: &str, size: u64) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, event_type,
            EventDetails::FileDetails { path: path.to_string(), size },
        ));
    }

    pub fn record_registry_event(&mut self, event_type: EventType, pid: u32, key: &str, value: &str) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, event_type,
            EventDetails::RegDetails { key: key.to_string(), value: value.to_string() },
        ));
    }

    pub fn record_network_event(&mut self, event_type: EventType, pid: u32, remote: &str, port: u16) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, event_type,
            EventDetails::NetworkDetails { remote: remote.to_string(), port },
        ));
    }

    pub fn record_process_event(&mut self, pid: u32, name: &str, cmdline: &str) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, EventType::ProcessCreate,
            EventDetails::ProcessDetails { name: name.to_string(), cmdline: cmdline.to_string() },
        ));
    }

    pub fn record_dll_load(&mut self, pid: u32, name: &str, base: u64) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, EventType::DllLoad,
            EventDetails::ModuleDetails { name: name.to_string(), base },
        ));
    }

    pub fn record_mutex(&mut self, pid: u32, name: &str) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, EventType::Mutex,
            EventDetails::GenericDetails { info: name.to_string() },
        ));
    }

    pub fn record_exception(&mut self, pid: u32, addr: u64) {
        let ts = self.next_timestamp();
        self.timeline.add_event(MonitorEvent::new(
            ts, pid, pid, EventType::Exception,
            EventDetails::GenericDetails { info: format!("exception at 0x{addr:X}") },
        ));
    }

    #[must_use] 
    pub fn detect_patterns(&self) -> Vec<BehaviorPattern> {
        self.timeline.detect_malicious_patterns()
    }
}

impl Default for BehaviorMonitor {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_monitor() -> BehaviorMonitor { BehaviorMonitor::new() }

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(EventType::FileCreate.as_str(), "file_create");
        assert_eq!(EventType::NetworkConnect.as_str(), "net_connect");
    }

    #[test]
    fn test_event_type_is_network() {
        assert!(EventType::NetworkConnect.is_network());
        assert!(!EventType::FileCreate.is_network());
    }

    #[test]
    fn test_record_file_event() {
        let mut m = make_monitor();
        m.record_file_event(EventType::FileCreate, 1234, "C:\\Windows\\test.exe", 1024);
        assert_eq!(m.timeline.event_count(), 1);
    }

    #[test]
    fn test_categorize_events() {
        let mut m = make_monitor();
        m.record_file_event(EventType::FileCreate, 1, "foo.txt", 0);
        m.record_file_event(EventType::FileWrite, 1, "bar.txt", 0);
        m.record_network_event(EventType::NetworkConnect, 1, "8.8.8.8", 80);
        let cats = m.timeline.categorize_events();
        assert!(cats.contains_key("file_create"));
        assert!(cats.contains_key("file_write"));
        assert!(cats.contains_key("net_connect"));
    }

    #[test]
    fn test_detect_registry_persistence() {
        let mut m = make_monitor();
        m.record_registry_event(EventType::RegistryWrite, 1,
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "C:\\malware.exe");
        let patterns = m.detect_patterns();
        assert!(patterns.iter().any(|p| p.name == "RegistryPersistence"));
    }

    #[test]
    fn test_detect_network_beacon() {
        let mut m = make_monitor();
        for _ in 0..3 {
            m.record_network_event(EventType::NetworkConnect, 1, "185.220.101.1", 443);
        }
        let patterns = m.detect_patterns();
        assert!(patterns.iter().any(|p| p.name == "NetworkBeacon"));
    }

    #[test]
    fn test_no_beacon_private_ips() {
        let mut m = make_monitor();
        for _ in 0..5 {
            m.record_network_event(EventType::NetworkConnect, 1, "192.168.1.1", 80);
        }
        let patterns = m.detect_patterns();
        assert!(!patterns.iter().any(|p| p.name == "NetworkBeacon"));
    }

    #[test]
    fn test_detect_self_deletion() {
        let mut m = make_monitor();
        m.record_file_event(EventType::FileDelete, 1, "C:\\malware.exe", 0);
        let patterns = m.detect_patterns();
        assert!(patterns.iter().any(|p| p.name == "SelfDeletion"));
    }

    #[test]
    fn test_detect_mutex() {
        let mut m = make_monitor();
        m.record_mutex(1, "Global\\MalwareMutex");
        let patterns = m.detect_patterns();
        assert!(patterns.iter().any(|p| p.name == "MutexCreation"));
    }

    #[test]
    fn test_threat_score_zero_no_events() {
        let m = make_monitor();
        assert_eq!(m.timeline.threat_score(), 0);
    }

    #[test]
    fn test_threat_score_high_with_persistence() {
        let mut m = make_monitor();
        m.record_registry_event(EventType::RegistryWrite, 1,
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "evil.exe");
        let score = m.timeline.threat_score();
        assert!(score > 0);
    }

    #[test]
    fn test_events_for_pid() {
        let mut m = make_monitor();
        m.record_file_event(EventType::FileCreate, 100, "a.txt", 0);
        m.record_file_event(EventType::FileCreate, 200, "b.txt", 0);
        let evts = m.timeline.events_for_pid(100);
        assert_eq!(evts.len(), 1);
    }

    #[test]
    fn test_event_is_suspicious_system32() {
        let e = MonitorEvent::new(0, 1, 1, EventType::FileWrite,
            EventDetails::FileDetails { path: "C:\\Windows\\System32\\evil.dll".to_string(), size: 0 });
        assert!(e.is_suspicious());
    }

    #[test]
    fn test_event_details_summary() {
        let d = EventDetails::NetworkDetails { remote: "1.2.3.4".to_string(), port: 443 };
        assert!(d.summary().contains("443"));
    }

    #[test]
    fn test_exception_storm_pattern() {
        let mut m = make_monitor();
        for i in 0..6 {
            m.record_exception(1, 0x0040_1000 + i * 4);
        }
        let patterns = m.detect_patterns();
        assert!(patterns.iter().any(|p| p.name == "ExceptionStorm"));
    }

    #[test]
    fn test_dll_sideload_pattern() {
        let mut m = make_monitor();
        m.record_dll_load(1, "C:\\Users\\user\\AppData\\Temp\\evil.dll", 0x7000_0000);
        let patterns = m.detect_patterns();
        assert!(patterns.iter().any(|p| p.name == "DllSideloading"));
    }
}
