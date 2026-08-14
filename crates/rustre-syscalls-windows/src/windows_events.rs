//! Windows event monitoring model (ETW consumer stubs).
//!
//! Provides data structures and logic for consuming Windows Event Tracing (ETW)
//! events, filtering security audit events, and managing event providers and
//! sessions.  All provider interaction is modelled as a pure-Rust abstraction;
//! actual kernel calls are intended to be supplied by a platform layer.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use crate::WinVersion;

// ─── EventLevel ───────────────────────────────────────────────────────────────

/// ETW event level (mirrors the Windows ETW level constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventLevel {
    /// Always logged.
    LogAlways = 0,
    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5,
}

impl std::fmt::Display for EventLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::LogAlways => "log-always",
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Information => "information",
            Self::Verbose => "verbose",
        };
        write!(f, "{s}")
    }
}

// ─── EventProviderGuid ────────────────────────────────────────────────────────

/// A 128-bit GUID identifying an ETW provider, stored as four 32-bit words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventProviderGuid {
    pub data: [u32; 4],
}

impl EventProviderGuid {
    /// Construct from four 32-bit words.
    #[must_use]
    pub const fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self { data: [a, b, c, d] }
    }

    /// The Microsoft-Windows-Security-Auditing provider GUID.
    #[must_use]
    pub const fn security_auditing() -> Self {
        // {54849625-5478-4994-A5BA-3E3B0328C30D}
        Self::new(0x5484_9625, 0x5478_4994, 0xa5ba_3e3b, 0x0328_c30d)
    }

    /// The Microsoft-Windows-Kernel-Process provider GUID.
    #[must_use]
    pub const fn kernel_process() -> Self {
        // {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
        Self::new(0x22fb_2cd6, 0x0e7b_422b, 0xa0c7_2fad, 0x1fd0_e716)
    }
}

impl std::fmt::Display for EventProviderGuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:04X}-{:04X}{:08X}}}",
            self.data[0],
            self.data[1] >> 16,
            self.data[1] & 0xFFFF,
            self.data[2] >> 16,
            self.data[2] & 0xFFFF,
            self.data[3]
        )
    }
}

// ─── EventProvider ────────────────────────────────────────────────────────────

/// Models an ETW event provider registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventProvider {
    /// Provider GUID.
    pub guid: EventProviderGuid,
    /// Human-readable provider name.
    pub name: String,
    /// Minimum level to collect.
    pub level: EventLevel,
    /// Keywords bitmask (0 = all keywords).
    pub keywords: u64,
    /// Whether this provider is currently enabled.
    pub enabled: bool,
}

impl EventProvider {
    /// Build a new provider, enabled by default.
    #[must_use]
    pub fn new(
        guid: EventProviderGuid,
        name: impl Into<String>,
        level: EventLevel,
        keywords: u64,
    ) -> Self {
        Self {
            guid,
            name: name.into(),
            level,
            keywords,
            enabled: true,
        }
    }

    /// Convenience: create the Security Auditing provider.
    #[must_use]
    pub fn security_auditing() -> Self {
        Self::new(
            EventProviderGuid::security_auditing(),
            "Microsoft-Windows-Security-Auditing",
            EventLevel::Information,
            0xFFFF_FFFF_FFFF_FFFF,
        )
    }

    /// Convenience: create the Kernel Process provider.
    #[must_use]
    pub fn kernel_process() -> Self {
        Self::new(
            EventProviderGuid::kernel_process(),
            "Microsoft-Windows-Kernel-Process",
            EventLevel::Information,
            0x10,
        )
    }
}

// ─── EventRecord ──────────────────────────────────────────────────────────────

/// A single ETW event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    /// Monotonic sequence number within the session.
    pub seq: u64,
    /// Provider GUID.
    pub provider: EventProviderGuid,
    /// Event ID (opcode).
    pub event_id: u16,
    /// Event level.
    pub level: EventLevel,
    /// Keyword bitmask of this event.
    pub keywords: u64,
    /// Thread ID.
    pub tid: u32,
    /// Process ID.
    pub pid: u32,
    /// Timestamp (100-nanosecond intervals since 1601-01-01, i.e. FILETIME).
    pub timestamp_ft: u64,
    /// Raw event payload.
    pub payload: Vec<u8>,
    /// Decoded properties (name → string value).
    pub properties: HashMap<String, String>,
}

/// Per-record process/thread/time metadata, bundled to keep [`EventRecord::new`] argument-light.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventOrigin {
    /// Thread ID.
    pub tid: u32,
    /// Process ID.
    pub pid: u32,
    /// Timestamp (100-nanosecond intervals since 1601-01-01, i.e. FILETIME).
    pub timestamp_ft: u64,
}

impl EventRecord {
    #[must_use]
    pub fn new(
        seq: u64,
        provider: EventProviderGuid,
        event_id: u16,
        level: EventLevel,
        keywords: u64,
        origin: EventOrigin,
    ) -> Self {
        Self {
            seq,
            provider,
            event_id,
            level,
            keywords,
            tid: origin.tid,
            pid: origin.pid,
            timestamp_ft: origin.timestamp_ft,
            payload: Vec::new(),
            properties: HashMap::new(),
        }
    }

    /// Set a decoded property.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Get a decoded property.
    #[must_use]
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(String::as_str)
    }
}

// ─── SecurityAuditFilter ──────────────────────────────────────────────────────

/// Filters security audit events by event ID and/or target PID.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityAuditFilter {
    /// If non-empty, only these event IDs pass.
    allowed_event_ids: Vec<u16>,
    /// If non-empty, only events from these PIDs pass.
    allowed_pids: Vec<u32>,
    /// If `true`, only events with `level <= Information` pass.
    only_info_or_below: bool,
}

impl SecurityAuditFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an allowed event ID.
    pub fn allow_event_id(&mut self, id: u16) {
        if !self.allowed_event_ids.contains(&id) {
            self.allowed_event_ids.push(id);
        }
    }

    /// Add an allowed PID.
    pub fn allow_pid(&mut self, pid: u32) {
        if !self.allowed_pids.contains(&pid) {
            self.allowed_pids.push(pid);
        }
    }

    /// Whether a given record passes the filter.
    #[must_use]
    pub fn passes(&self, rec: &EventRecord) -> bool {
        if !self.allowed_event_ids.is_empty() && !self.allowed_event_ids.contains(&rec.event_id) {
            return false;
        }
        if !self.allowed_pids.is_empty() && !self.allowed_pids.contains(&rec.pid) {
            return false;
        }
        if self.only_info_or_below && rec.level > EventLevel::Information {
            return false;
        }
        true
    }
}

// ─── WindowsEventMonitor ──────────────────────────────────────────────────────

/// Core monitor that manages ETW providers and accumulates event records.
#[derive(Debug, Default)]
pub struct WindowsEventMonitor {
    providers: Vec<EventProvider>,
    records: Vec<EventRecord>,
    next_seq: u64,
    filter: Option<SecurityAuditFilter>,
}

impl WindowsEventMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an event provider.
    pub fn add_provider(&mut self, provider: EventProvider) {
        self.providers.push(provider);
    }

    /// Remove provider by GUID.
    pub fn remove_provider(&mut self, guid: &EventProviderGuid) {
        self.providers.retain(|p| &p.guid != guid);
    }

    /// Enable or disable a provider by GUID.
    pub fn set_provider_enabled(&mut self, guid: &EventProviderGuid, enabled: bool) {
        for p in &mut self.providers {
            if &p.guid == guid {
                p.enabled = enabled;
            }
        }
    }

    /// Set the security audit filter.
    pub fn set_filter(&mut self, filter: SecurityAuditFilter) {
        self.filter = Some(filter);
    }

    /// Ingest an event record.  Returns `true` if the record was accepted
    /// (the provider is enabled and the filter passes).
    pub fn ingest(&mut self, mut rec: EventRecord) -> bool {
        // Check provider enabled
        let provider_enabled = self
            .providers
            .iter()
            .any(|p| p.enabled && p.guid == rec.provider && rec.level <= p.level);
        if !provider_enabled {
            return false;
        }
        // Apply optional filter
        if let Some(filter) = &self.filter
            && !filter.passes(&rec)
        {
            return false;
        }
        rec.seq = self.next_seq;
        self.next_seq += 1;
        self.records.push(rec);
        true
    }

    /// All accepted records.
    #[must_use]
    pub fn records(&self) -> &[EventRecord] {
        &self.records
    }

    /// Records for a specific event ID.
    #[must_use]
    pub fn by_event_id(&self, id: u16) -> Vec<&EventRecord> {
        self.records.iter().filter(|r| r.event_id == id).collect()
    }

    /// Records for a specific PID.
    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Vec<&EventRecord> {
        self.records.iter().filter(|r| r.pid == pid).collect()
    }

    /// Number of registered providers.
    #[must_use]
    pub const fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Number of accumulated records.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Clear all accumulated records.
    pub fn clear_records(&mut self) {
        self.records.clear();
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn security_rec(event_id: u16, pid: u32, level: EventLevel) -> EventRecord {
        EventRecord::new(
            0,
            EventProviderGuid::security_auditing(),
            event_id,
            level,
            0,
            EventOrigin {
                tid: 1,
                pid,
                timestamp_ft: 0,
            },
        )
    }

    // --- EventLevel ---

    #[test]
    fn event_level_display() {
        assert_eq!(EventLevel::Information.to_string(), "information");
        assert_eq!(EventLevel::Error.to_string(), "error");
    }

    #[test]
    fn event_level_ordering() {
        assert!(EventLevel::Critical < EventLevel::Verbose);
        assert!(EventLevel::Error <= EventLevel::Error);
    }

    // --- EventProviderGuid ---

    #[test]
    fn guid_display_non_empty() {
        let g = EventProviderGuid::security_auditing();
        let s = g.to_string();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
    }

    #[test]
    fn guid_equality() {
        assert_eq!(
            EventProviderGuid::security_auditing(),
            EventProviderGuid::security_auditing()
        );
        assert_ne!(
            EventProviderGuid::security_auditing(),
            EventProviderGuid::kernel_process()
        );
    }

    // --- EventProvider ---

    #[test]
    fn provider_security_auditing_enabled() {
        let p = EventProvider::security_auditing();
        assert!(p.enabled);
        assert_eq!(p.guid, EventProviderGuid::security_auditing());
    }

    #[test]
    fn provider_kernel_process() {
        let p = EventProvider::kernel_process();
        assert_eq!(p.keywords, 0x10);
    }

    // --- EventRecord ---

    #[test]
    fn event_record_properties() {
        let mut r = security_rec(4624, 1000, EventLevel::Information);
        r.set_property("SubjectUserName", "SYSTEM");
        assert_eq!(r.get_property("SubjectUserName"), Some("SYSTEM"));
        assert!(r.get_property("Missing").is_none());
    }

    // --- SecurityAuditFilter ---

    #[test]
    fn filter_passes_all_empty() {
        let f = SecurityAuditFilter::new();
        let r = security_rec(4624, 100, EventLevel::Information);
        assert!(f.passes(&r));
    }

    #[test]
    fn filter_event_id_allow() {
        let mut f = SecurityAuditFilter::new();
        f.allow_event_id(4624);
        let good = security_rec(4624, 1, EventLevel::Information);
        let bad = security_rec(4625, 1, EventLevel::Information);
        assert!(f.passes(&good));
        assert!(!f.passes(&bad));
    }

    #[test]
    fn filter_pid_allow() {
        let mut f = SecurityAuditFilter::new();
        f.allow_pid(42);
        let good = security_rec(1, 42, EventLevel::Information);
        let bad = security_rec(1, 99, EventLevel::Information);
        assert!(f.passes(&good));
        assert!(!f.passes(&bad));
    }

    #[test]
    fn filter_only_info_or_below() {
        let mut f = SecurityAuditFilter::new();
        f.only_info_or_below = true;
        let info = security_rec(1, 1, EventLevel::Information);
        let verbose = security_rec(1, 1, EventLevel::Verbose);
        assert!(f.passes(&info));
        assert!(!f.passes(&verbose));
    }

    #[test]
    fn filter_no_duplicate_pids() {
        let mut f = SecurityAuditFilter::new();
        f.allow_pid(1);
        f.allow_pid(1);
        assert_eq!(f.allowed_pids.len(), 1);
    }

    // --- WindowsEventMonitor ---

    #[test]
    fn monitor_add_provider() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        assert_eq!(m.provider_count(), 1);
    }

    #[test]
    fn monitor_ingest_accepted() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        let r = security_rec(4624, 1, EventLevel::Information);
        assert!(m.ingest(r));
        assert_eq!(m.record_count(), 1);
    }

    #[test]
    fn monitor_ingest_rejected_disabled_provider() {
        let mut m = WindowsEventMonitor::new();
        let p = EventProvider::security_auditing();
        let guid = p.guid;
        m.add_provider(p);
        m.set_provider_enabled(&guid, false);
        let r = security_rec(4624, 1, EventLevel::Information);
        assert!(!m.ingest(r));
    }

    #[test]
    fn monitor_ingest_rejected_level_too_verbose() {
        let mut m = WindowsEventMonitor::new();
        // Provider configured at Information level — Verbose events should be rejected
        m.add_provider(EventProvider::security_auditing());
        let r = security_rec(4624, 1, EventLevel::Verbose);
        assert!(!m.ingest(r));
    }

    #[test]
    fn monitor_remove_provider() {
        let mut m = WindowsEventMonitor::new();
        let p = EventProvider::security_auditing();
        let guid = p.guid;
        m.add_provider(p);
        m.remove_provider(&guid);
        assert_eq!(m.provider_count(), 0);
    }

    #[test]
    fn monitor_by_event_id() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        m.ingest(security_rec(4624, 1, EventLevel::Information));
        m.ingest(security_rec(4625, 2, EventLevel::Information));
        assert_eq!(m.by_event_id(4624).len(), 1);
    }

    #[test]
    fn monitor_by_pid() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        m.ingest(security_rec(4624, 100, EventLevel::Information));
        m.ingest(security_rec(4624, 200, EventLevel::Information));
        assert_eq!(m.by_pid(100).len(), 1);
    }

    #[test]
    fn monitor_clear_records() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        m.ingest(security_rec(1, 1, EventLevel::Information));
        m.clear_records();
        assert_eq!(m.record_count(), 0);
    }

    #[test]
    fn monitor_filter_applied() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        let mut f = SecurityAuditFilter::new();
        f.allow_event_id(4624);
        m.set_filter(f);
        assert!(!m.ingest(security_rec(4625, 1, EventLevel::Information)));
        assert!(m.ingest(security_rec(4624, 1, EventLevel::Information)));
    }

    #[test]
    fn monitor_seq_assigned_sequentially() {
        let mut m = WindowsEventMonitor::new();
        m.add_provider(EventProvider::security_auditing());
        m.ingest(security_rec(1, 1, EventLevel::Information));
        m.ingest(security_rec(1, 1, EventLevel::Information));
        assert_eq!(m.records()[0].seq, 0);
        assert_eq!(m.records()[1].seq, 1);
    }
}
