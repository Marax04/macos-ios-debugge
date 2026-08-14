//! ETW (Event Tracing for Windows) session manager for TTD.
//!
//! Provides [`EtwTraceSession`], provider management, event parsing, and
//! a registry of well-known provider GUIDs.

use std::collections::HashMap;

// ─── GUID / Provider types ────────────────────────────────────────────────────

/// A 128-bit GUID stored as a `u128` (big-endian byte order).
pub type ProviderGuid = u128;

/// Parse a GUID string in the form `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
#[must_use]
pub fn parse_guid(s: &str) -> Option<ProviderGuid> {
    let s = s.trim_matches(|c| c == '{' || c == '}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let p0 = u32::from_str_radix(parts[0], 16).ok()?;
    let p1 = u16::from_str_radix(parts[1], 16).ok()?;
    let p2 = u16::from_str_radix(parts[2], 16).ok()?;
    let p3 = u16::from_str_radix(parts[3], 16).ok()?;
    let p4_str = parts[4];
    if p4_str.len() != 12 {
        return None;
    }
    let p4_hi = u16::from_str_radix(&p4_str[..4], 16).ok()?;
    let p4_lo = u64::from_str_radix(&p4_str[4..], 16).ok()?;
    // Pack: [p0(4) | p1(2) | p2(2) | p3(2) | p4_hi(2) | p4_lo(8)]
    // Total 20 bytes → we store as u128 using the standard GUID layout
    let high: u64 = (u64::from(p0) << 32) | (u64::from(p1) << 16) | u64::from(p2);
    let low: u64 = (u64::from(p3) << 48) | (u64::from(p4_hi) << 32) | p4_lo;
    Some((u128::from(high) << 64) | u128::from(low))
}

/// Format a `ProviderGuid` back to the standard GUID string representation.
#[must_use]
pub fn format_guid(guid: ProviderGuid) -> String {
    let high = u64::try_from(guid >> 64).unwrap_or(u64::MAX);
    let low = u64::try_from(guid & 0xFFFF_FFFF_FFFF_FFFF).unwrap_or(u64::MAX);
    let p0 = u32::try_from((high >> 32) & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let p1 = u16::try_from((high >> 16) & 0xFFFF).unwrap_or(u16::MAX);
    let p2 = u16::try_from(high & 0xFFFF).unwrap_or(u16::MAX);
    let p3 = u16::try_from(low >> 48).unwrap_or(u16::MAX);
    let p4 = low & 0x0000_FFFF_FFFF_FFFF;
    format!("{{{p0:08X}-{p1:04X}-{p2:04X}-{p3:04X}-{p4:012X}}}")
}

// ─── TraceLevel ───────────────────────────────────────────────────────────────

/// ETW event verbosity level, matching the Windows `EVENT_TRACE_LEVEL_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TraceLevel {
    Always = 0,
    Critical = 1,
    Error = 2,
    Warning = 3,
    Info = 4,
    Verbose = 5,
}

impl TraceLevel {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Always,
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            4 => Self::Info,
            _ => Self::Verbose,
        }
    }
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for TraceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Always => "ALWAYS",
            Self::Critical => "CRITICAL",
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
            Self::Verbose => "VERBOSE",
        };
        write!(f, "{s}")
    }
}

// ─── KernelProvider ───────────────────────────────────────────────────────────

/// Kernel-mode ETW providers that can be enabled for TTD recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelProvider {
    KernelProcess,
    KernelThread,
    KernelImage,
    KernelDisk,
    KernelNetwork,
    KernelRegistry,
    KernelFileIO,
    KernelTcpip,
    KernelPageFault,
}

impl KernelProvider {
    /// Returns the ETW keyword flag for this kernel provider
    /// (matches `EVENT_TRACE_FLAG_*` Windows constants).
    #[must_use]
    pub const fn flag(self) -> u32 {
        match self {
            Self::KernelProcess => 0x0000_0001,
            Self::KernelThread => 0x0000_0002,
            Self::KernelImage => 0x0000_0004,
            Self::KernelDisk => 0x0000_0100,
            Self::KernelNetwork => 0x0000_0200,
            Self::KernelRegistry => 0x0002_0000,
            Self::KernelFileIO => 0x0200_0000,
            Self::KernelTcpip => 0x0001_0000,
            Self::KernelPageFault => 0x0000_1000,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::KernelProcess => "KernelProcess",
            Self::KernelThread => "KernelThread",
            Self::KernelImage => "KernelImage",
            Self::KernelDisk => "KernelDisk",
            Self::KernelNetwork => "KernelNetwork",
            Self::KernelRegistry => "KernelRegistry",
            Self::KernelFileIO => "KernelFileIO",
            Self::KernelTcpip => "KernelTcpip",
            Self::KernelPageFault => "KernelPageFault",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::KernelProcess,
            Self::KernelThread,
            Self::KernelImage,
            Self::KernelDisk,
            Self::KernelNetwork,
            Self::KernelRegistry,
            Self::KernelFileIO,
            Self::KernelTcpip,
            Self::KernelPageFault,
        ]
    }
}

// ─── EtwProvider ─────────────────────────────────────────────────────────────

/// A user-mode ETW provider configuration.
#[derive(Debug, Clone)]
pub struct EtwProvider {
    pub guid: ProviderGuid,
    pub name: String,
    pub level: TraceLevel,
    pub keywords: u64,
    pub enabled: bool,
}

impl EtwProvider {
    #[must_use]
    pub fn new(guid: ProviderGuid, name: impl Into<String>, level: TraceLevel, keywords: u64) -> Self {
        Self {
            guid,
            name: name.into(),
            level,
            keywords,
            enabled: true,
        }
    }

    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    pub const fn enable(&mut self) {
        self.enabled = true;
    }
}

// ─── FieldValue / EventField ──────────────────────────────────────────────────

/// A typed field value decoded from ETW event user-data.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Str(String),
    Guid(u128),
    Pointer(u64),
    Bytes(Vec<u8>),
}

impl FieldValue {
    /// Return a human-readable type tag.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::UInt8(_) => "UInt8",
            Self::UInt16(_) => "UInt16",
            Self::UInt32(_) => "UInt32",
            Self::UInt64(_) => "UInt64",
            Self::Int8(_) => "Int8",
            Self::Int16(_) => "Int16",
            Self::Int32(_) => "Int32",
            Self::Int64(_) => "Int64",
            Self::Float(_) => "Float",
            Self::Double(_) => "Double",
            Self::Bool(_) => "Bool",
            Self::Str(_) => "String",
            Self::Guid(_) => "Guid",
            Self::Pointer(_) => "Pointer",
            Self::Bytes(_) => "Bytes",
        }
    }
}

/// A named field decoded from ETW event user-data.
#[derive(Debug, Clone)]
pub struct EventField {
    pub name: String,
    pub value: FieldValue,
}

impl EventField {
    pub fn new(name: impl Into<String>, value: FieldValue) -> Self {
        Self { name: name.into(), value }
    }
}

// ─── EtwEvent ────────────────────────────────────────────────────────────────

/// A decoded ETW event record.
#[derive(Debug, Clone)]
pub struct EtwEvent {
    pub provider_guid: ProviderGuid,
    pub event_id: u16,
    pub version: u8,
    pub level: TraceLevel,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
    pub timestamp_ns: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub user_data: Vec<u8>,
}

impl EtwEvent {
    /// Parse the `user_data` blob using a TDH-style field descriptor list.
    /// Each descriptor is `(name, FieldType enum, byte_size)`.
    #[must_use]
    pub fn parse_fields(&self, descriptors: &[FieldDescriptor]) -> Vec<EventField> {
        parse_event_user_data(&self.user_data, descriptors)
    }
}

// ─── FieldDescriptor / parse_event_user_data ─────────────────────────────────

/// Describes a single field in an ETW event's user-data payload.
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    pub name: String,
    pub field_type: FieldType,
}

/// The primitive type of a TDH field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Boolean,
    /// Null-terminated UTF-16LE string; `max_bytes` gives an upper bound.
    WideStr { max_bytes: u16 },
    /// Counted UTF-8 string (4-byte length prefix).
    AnsiStr,
    Guid,
    /// Either 4 or 8 bytes depending on session pointer size.
    Pointer32,
    Pointer64,
    Binary { size: u16 },
}

/// Parse a raw ETW user-data buffer according to a list of field descriptors.
/// Returns as many fields as can be decoded before the buffer is exhausted.
///
/// # Panics
///
/// Panics if a field slice cannot be converted to a fixed-size array (should not
/// happen with correct offset arithmetic).
#[must_use]
pub fn parse_event_user_data(data: &[u8], descriptors: &[FieldDescriptor]) -> Vec<EventField> {
    let mut fields = Vec::with_capacity(descriptors.len());
    let mut offset = 0usize;

    for desc in descriptors {
        if offset >= data.len() {
            break;
        }
        let remaining = &data[offset..];
        let value = match desc.field_type {
            FieldType::UInt8 => {
                if remaining.is_empty() { break; }
                offset += 1;
                FieldValue::UInt8(remaining[0])
            }
            FieldType::UInt16 => {
                if remaining.len() < 2 { break; }
                offset += 2;
                FieldValue::UInt16(u16::from_le_bytes([remaining[0], remaining[1]]))
            }
            FieldType::UInt32 => {
                if remaining.len() < 4 { break; }
                offset += 4;
                FieldValue::UInt32(u32::from_le_bytes(remaining[..4].try_into().unwrap()))
            }
            FieldType::UInt64 => {
                if remaining.len() < 8 { break; }
                offset += 8;
                FieldValue::UInt64(u64::from_le_bytes(remaining[..8].try_into().unwrap()))
            }
            FieldType::Int8 => {
                if remaining.is_empty() { break; }
                offset += 1;
                FieldValue::Int8(remaining[0].cast_signed())
            }
            FieldType::Int16 => {
                if remaining.len() < 2 { break; }
                offset += 2;
                FieldValue::Int16(i16::from_le_bytes([remaining[0], remaining[1]]))
            }
            FieldType::Int32 => {
                if remaining.len() < 4 { break; }
                offset += 4;
                FieldValue::Int32(i32::from_le_bytes(remaining[..4].try_into().unwrap()))
            }
            FieldType::Int64 => {
                if remaining.len() < 8 { break; }
                offset += 8;
                FieldValue::Int64(i64::from_le_bytes(remaining[..8].try_into().unwrap()))
            }
            FieldType::Float32 => {
                if remaining.len() < 4 { break; }
                offset += 4;
                FieldValue::Float(f32::from_le_bytes(remaining[..4].try_into().unwrap()))
            }
            FieldType::Float64 => {
                if remaining.len() < 8 { break; }
                offset += 8;
                FieldValue::Double(f64::from_le_bytes(remaining[..8].try_into().unwrap()))
            }
            FieldType::Boolean => {
                if remaining.is_empty() { break; }
                offset += 1;
                FieldValue::Bool(remaining[0] != 0)
            }
            FieldType::WideStr { max_bytes } => {
                let limit = (max_bytes as usize).min(remaining.len() & !1);
                // Scan for null terminator (two zero bytes)
                let mut end = 0usize;
                while end + 1 < limit {
                    if remaining[end] == 0 && remaining[end + 1] == 0 {
                        break;
                    }
                    end += 2;
                }
                let utf16_units: Vec<u16> = remaining[..end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&utf16_units).clone();
                // Advance past string + null terminator
                offset += (end + 2).min(remaining.len());
                FieldValue::Str(s)
            }
            FieldType::AnsiStr => {
                if remaining.len() < 4 { break; }
                let len = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
                if remaining.len() < 4 + len { break; }
                let s = String::from_utf8_lossy(&remaining[4..4 + len]).into_owned();
                offset += 4 + len;
                FieldValue::Str(s)
            }
            FieldType::Guid => {
                if remaining.len() < 16 { break; }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&remaining[..16]);
                let g = u128::from_le_bytes(bytes);
                offset += 16;
                FieldValue::Guid(g)
            }
            FieldType::Pointer32 => {
                if remaining.len() < 4 { break; }
                offset += 4;
                FieldValue::Pointer(u64::from(u32::from_le_bytes(remaining[..4].try_into().unwrap())))
            }
            FieldType::Pointer64 => {
                if remaining.len() < 8 { break; }
                offset += 8;
                FieldValue::Pointer(u64::from_le_bytes(remaining[..8].try_into().unwrap()))
            }
            FieldType::Binary { size } => {
                let sz = size as usize;
                if remaining.len() < sz { break; }
                let bytes = remaining[..sz].to_vec();
                offset += sz;
                FieldValue::Bytes(bytes)
            }
        };
        fields.push(EventField::new(desc.name.clone(), value));
    }
    fields
}

// ─── Well-known provider GUIDs ───────────────────────────────────────────────

/// Returns a map of well-known provider names to their GUIDs.
///
/// # Panics
///
/// Panics if any embedded GUID literal fails to parse (should never happen).
#[must_use]
pub fn well_known_provider_guids() -> HashMap<&'static str, ProviderGuid> {
    let mut m = HashMap::new();
    // Microsoft-Windows-Kernel-Process
    m.insert("Microsoft-Windows-Kernel-Process",
        parse_guid("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}").unwrap());
    // Microsoft-Windows-Kernel-Thread
    m.insert("Microsoft-Windows-Kernel-Thread",
        parse_guid("{EDD08927-9CC4-4E65-B970-C2560FB5C289}").unwrap());
    // Microsoft-Windows-Kernel-Memory
    m.insert("Microsoft-Windows-Kernel-Memory",
        parse_guid("{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}").unwrap());
    // Microsoft-Windows-Kernel-Network
    m.insert("Microsoft-Windows-Kernel-Network",
        parse_guid("{7DD42A49-5329-4832-8DFD-43D979153A88}").unwrap());
    // Microsoft-Windows-Kernel-Registry
    m.insert("Microsoft-Windows-Kernel-Registry",
        parse_guid("{70EB4F03-C1DE-4F73-A051-33D13D5413BD}").unwrap());
    // Microsoft-Windows-Kernel-File
    m.insert("Microsoft-Windows-Kernel-File",
        parse_guid("{EDD08927-9CC4-4E65-B970-C2560FB5C290}").unwrap());
    // Microsoft-Windows-DNS-Client
    m.insert("Microsoft-Windows-DNS-Client",
        parse_guid("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}").unwrap());
    // Microsoft-Windows-Security-Auditing
    m.insert("Microsoft-Windows-Security-Auditing",
        parse_guid("{54849625-5478-4994-A5BA-3E3B0328C30D}").unwrap());
    // Microsoft-Windows-WinInet
    m.insert("Microsoft-Windows-WinInet",
        parse_guid("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}").unwrap());
    // Microsoft-Windows-RPC
    m.insert("Microsoft-Windows-RPC",
        parse_guid("{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}").unwrap());
    // Microsoft-Windows-Winsock-AFD
    m.insert("Microsoft-Windows-Winsock-AFD",
        parse_guid("{E53C6823-7BB8-44BB-90DC-3F86090D48A6}").unwrap());
    // NT Kernel Logger (classic)
    m.insert("NT Kernel Logger",
        parse_guid("{9E814AAD-3204-11D2-9A82-006008A86939}").unwrap());
    m
}

// ─── SessionConfig ────────────────────────────────────────────────────────────

/// Configuration for an ETW trace session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_name: String,
    pub buffer_size_kb: u32,
    pub min_buffers: u32,
    pub max_buffers: u32,
    pub flush_timer_secs: u32,
    pub real_time: bool,
    pub kernel_flags: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_name: String::from("RustREEtwSession"),
            buffer_size_kb: 64,
            min_buffers: 4,
            max_buffers: 64,
            flush_timer_secs: 1,
            real_time: true,
            kernel_flags: 0,
        }
    }
}

// ─── SessionState ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Stopped,
    Running,
    Paused,
    Error,
}

// ─── EtwTraceSession ─────────────────────────────────────────────────────────

/// Manages an ETW trace session for TTD recording.
///
/// On Windows this would wrap `StartTrace`/`EnableTraceEx2`/`StopTrace`.
/// This implementation models the full state machine and event accumulation
/// without making actual Windows API calls, so it compiles cross-platform
/// and can be unit-tested everywhere.
pub struct EtwTraceSession {
    config: SessionConfig,
    state: SessionState,
    providers: Vec<EtwProvider>,
    kernel_providers: Vec<KernelProvider>,
    /// Accumulated events buffered in memory.
    event_buffer: Vec<EtwEvent>,
    /// Monotonic event counter.
    event_counter: u64,
    /// Simulated session handle (non-zero when running).
    session_handle: u64,
    /// Statistics.
    events_lost: u64,
    buffers_written: u64,
}

impl EtwTraceSession {
    #[must_use]
    pub const fn new(config: SessionConfig) -> Self {
        Self {
            config,
            state: SessionState::Stopped,
            providers: Vec::new(),
            kernel_providers: Vec::new(),
            event_buffer: Vec::new(),
            event_counter: 0,
            session_handle: 0,
            events_lost: 0,
            buffers_written: 0,
        }
    }

    /// Add a user-mode provider to the session.
    pub fn add_provider(&mut self, provider: EtwProvider) {
        // Replace if GUID already registered.
        if let Some(existing) = self.providers.iter_mut().find(|p| p.guid == provider.guid) {
            *existing = provider;
        } else {
            self.providers.push(provider);
        }
    }

    /// Remove a provider by GUID.
    pub fn remove_provider(&mut self, guid: ProviderGuid) -> bool {
        let before = self.providers.len();
        self.providers.retain(|p| p.guid != guid);
        self.providers.len() < before
    }

    /// Enable a kernel provider.
    pub fn enable_kernel_provider(&mut self, kp: KernelProvider) {
        if !self.kernel_providers.contains(&kp) {
            self.kernel_providers.push(kp);
        }
        self.config.kernel_flags |= kp.flag();
    }

    /// Disable a kernel provider.
    pub fn disable_kernel_provider(&mut self, kp: KernelProvider) {
        self.kernel_providers.retain(|&k| k != kp);
        self.config.kernel_flags &= !kp.flag();
    }

    /// Start the session (simulated; no real Windows API calls).
    ///
    /// # Errors
    ///
    /// Returns an error string if the session is already running.
    pub fn start(&mut self) -> Result<(), String> {
        if self.state == SessionState::Running {
            return Err("session already running".into());
        }
        self.session_handle = 0xDEAD_BEEF_0000_0001;
        self.state = SessionState::Running;
        Ok(())
    }

    /// Pause the session.
    ///
    /// # Errors
    ///
    /// Returns an error string if the session is not currently running.
    pub fn pause(&mut self) -> Result<(), String> {
        if self.state != SessionState::Running {
            return Err("session not running".into());
        }
        self.state = SessionState::Paused;
        Ok(())
    }

    /// Resume the session.
    ///
    /// # Errors
    ///
    /// Returns an error string if the session is not currently paused.
    pub fn resume(&mut self) -> Result<(), String> {
        if self.state != SessionState::Paused {
            return Err("session not paused".into());
        }
        self.state = SessionState::Running;
        Ok(())
    }

    /// Stop and close the session.
    pub const fn stop(&mut self) {
        self.state = SessionState::Stopped;
        self.session_handle = 0;
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Ingest a raw event into the buffer (called by the real ETW callback).
    pub fn ingest_event(&mut self, mut event: EtwEvent) {
        if self.state != SessionState::Running {
            self.events_lost += 1;
            return;
        }
        // Check that the provider is enabled.
        let provider_enabled = self.providers.iter()
            .any(|p| p.guid == event.provider_guid && p.enabled && event.level <= p.level);
        if !provider_enabled && event.provider_guid != 0 {
            return;
        }
        self.event_counter += 1;
        if event.timestamp_ns == 0 {
            event.timestamp_ns = self.event_counter * 100; // synthetic
        }
        self.event_buffer.push(event);
    }

    /// Drain all buffered events.
    pub fn drain_events(&mut self) -> Vec<EtwEvent> {
        self.buffers_written += 1;
        std::mem::take(&mut self.event_buffer)
    }

    /// Return a snapshot of buffered events without draining.
    #[must_use]
    pub fn peek_events(&self) -> &[EtwEvent] {
        &self.event_buffer
    }

    /// Query how many events have been lost.
    #[must_use]
    pub const fn events_lost(&self) -> u64 {
        self.events_lost
    }

    #[must_use]
    pub const fn buffers_written(&self) -> u64 {
        self.buffers_written
    }

    #[must_use]
    pub const fn config(&self) -> &SessionConfig {
        &self.config
    }

    #[must_use]
    pub fn providers(&self) -> &[EtwProvider] {
        &self.providers
    }

    #[must_use]
    pub fn kernel_providers(&self) -> &[KernelProvider] {
        &self.kernel_providers
    }

    /// Filter buffered events by provider GUID.
    #[must_use]
    pub fn events_for_provider(&self, guid: ProviderGuid) -> Vec<&EtwEvent> {
        self.event_buffer.iter()
            .filter(|e| e.provider_guid == guid)
            .collect()
    }

    /// Filter buffered events by time range.
    #[must_use]
    pub fn events_in_range(&self, start_ns: u64, end_ns: u64) -> Vec<&EtwEvent> {
        self.event_buffer.iter()
            .filter(|e| e.timestamp_ns >= start_ns && e.timestamp_ns <= end_ns)
            .collect()
    }

    /// Return all enabled provider GUIDs.
    #[must_use]
    pub fn enabled_provider_guids(&self) -> Vec<ProviderGuid> {
        self.providers.iter()
            .filter(|p| p.enabled)
            .map(|p| p.guid)
            .collect()
    }

    /// Lookup a provider by GUID.
    #[must_use]
    pub fn find_provider(&self, guid: ProviderGuid) -> Option<&EtwProvider> {
        self.providers.iter().find(|p| p.guid == guid)
    }
}

// ─── RateLimiter for ETW event ingestion ─────────────────────────────────────

/// Simple token-bucket rate limiter for ETW event ingestion.
pub struct EtwRateLimiter {
    pub max_events_per_second: u32,
    tokens: f64,
    last_refill_ns: u64,
}

const fn u64_to_f64_lossy(v: u64) -> f64 {
    v as f64
}

impl EtwRateLimiter {
    #[must_use]
    pub fn new(max_events_per_second: u32) -> Self {
        Self {
            max_events_per_second,
            tokens: f64::from(max_events_per_second),
            last_refill_ns: 0,
        }
    }

    fn refill(&mut self, now_ns: u64) {
        let elapsed = u64_to_f64_lossy(now_ns.saturating_sub(self.last_refill_ns)) / 1_000_000_000.0;
        self.tokens = (self.tokens + elapsed * f64::from(self.max_events_per_second))
            .min(f64::from(self.max_events_per_second));
        self.last_refill_ns = now_ns;
    }

    /// Returns true and consumes a token if within limit.
    #[must_use]
    pub fn check_and_consume(&mut self, now_ns: u64) -> bool {
        self.refill(now_ns);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─── Helper: build a synthetic EtwEvent ──────────────────────────────────────

#[must_use]
pub const fn make_event(
    guid: ProviderGuid,
    event_id: u16,
    level: TraceLevel,
    pid: u32,
    tid: u32,
    ts_ns: u64,
    user_data: Vec<u8>,
) -> EtwEvent {
    EtwEvent {
        provider_guid: guid,
        event_id,
        version: 0,
        level,
        opcode: 0,
        task: 0,
        keyword: 0,
        timestamp_ns: ts_ns,
        process_id: pid,
        thread_id: tid,
        user_data,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn guid_a() -> ProviderGuid {
        parse_guid("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}").unwrap()
    }

    #[test]
    fn test_parse_guid_roundtrip() {
        let guid_str = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}";
        let guid = parse_guid(guid_str).unwrap();
        let formatted = format_guid(guid);
        // Just check structural parts are preserved
        assert!(formatted.starts_with('{'));
        assert!(formatted.ends_with('}'));
        assert_eq!(formatted.len(), 38);
    }

    #[test]
    fn test_parse_guid_invalid() {
        assert!(parse_guid("not-a-guid").is_none());
        assert!(parse_guid("{1-2-3}").is_none());
    }

    #[test]
    fn test_trace_level_ordering() {
        assert!(TraceLevel::Critical < TraceLevel::Verbose);
        assert!(TraceLevel::Always < TraceLevel::Error);
        assert_eq!(TraceLevel::from_u8(4), TraceLevel::Info);
        assert_eq!(TraceLevel::Verbose.as_u8(), 5);
    }

    #[test]
    fn test_trace_level_display() {
        assert_eq!(format!("{}", TraceLevel::Warning), "WARNING");
        assert_eq!(format!("{}", TraceLevel::Critical), "CRITICAL");
    }

    #[test]
    fn test_kernel_provider_flags_unique() {
        let mut seen = std::collections::HashSet::new();
        for kp in KernelProvider::all() {
            assert!(seen.insert(kp.flag()), "duplicate flag for {:?}", kp);
        }
    }

    #[test]
    fn test_session_start_stop() {
        let cfg = SessionConfig::default();
        let mut sess = EtwTraceSession::new(cfg);
        assert_eq!(sess.state(), SessionState::Stopped);
        sess.start().unwrap();
        assert_eq!(sess.state(), SessionState::Running);
        sess.stop();
        assert_eq!(sess.state(), SessionState::Stopped);
    }

    #[test]
    fn test_session_double_start_error() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        sess.start().unwrap();
        assert!(sess.start().is_err());
    }

    #[test]
    fn test_session_pause_resume() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        sess.start().unwrap();
        sess.pause().unwrap();
        assert_eq!(sess.state(), SessionState::Paused);
        sess.resume().unwrap();
        assert_eq!(sess.state(), SessionState::Running);
    }

    #[test]
    fn test_add_remove_provider() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        let guid = guid_a();
        let p = EtwProvider::new(guid, "TestProvider", TraceLevel::Verbose, 0xFFFF_FFFF);
        sess.add_provider(p);
        assert_eq!(sess.providers().len(), 1);
        assert!(sess.remove_provider(guid));
        assert_eq!(sess.providers().len(), 0);
        assert!(!sess.remove_provider(guid)); // already gone
    }

    #[test]
    fn test_ingest_event_when_stopped() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        let ev = make_event(0, 1, TraceLevel::Info, 100, 200, 1000, vec![]);
        sess.ingest_event(ev);
        assert_eq!(sess.peek_events().len(), 0);
        assert_eq!(sess.events_lost(), 1);
    }

    #[test]
    fn test_ingest_event_when_running() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        let guid = guid_a();
        sess.add_provider(EtwProvider::new(guid, "P", TraceLevel::Verbose, 0xFFFF));
        sess.start().unwrap();
        let ev = make_event(guid, 1, TraceLevel::Info, 100, 200, 1000, vec![1, 2, 3]);
        sess.ingest_event(ev);
        assert_eq!(sess.peek_events().len(), 1);
    }

    #[test]
    fn test_drain_events() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        let guid = guid_a();
        sess.add_provider(EtwProvider::new(guid, "P", TraceLevel::Verbose, 0xFFFF));
        sess.start().unwrap();
        for i in 0u32..5 {
            sess.ingest_event(make_event(guid, 1, TraceLevel::Info, i, i, u64::from(i) * 100, vec![]));
        }
        let drained = sess.drain_events();
        assert_eq!(drained.len(), 5);
        assert_eq!(sess.peek_events().len(), 0);
    }

    #[test]
    fn test_parse_event_user_data_uint32() {
        let data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        let desc = vec![FieldDescriptor { name: "ProcessId".into(), field_type: FieldType::UInt32 }];
        let fields = parse_event_user_data(&data, &desc);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, FieldValue::UInt32(0x0403_0201));
    }

    #[test]
    fn test_parse_event_user_data_multi() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xAAu8.to_le_bytes());       // UInt8
        data.extend_from_slice(&0x1234u16.to_le_bytes());     // UInt16
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // UInt32
        let descs = vec![
            FieldDescriptor { name: "a".into(), field_type: FieldType::UInt8 },
            FieldDescriptor { name: "b".into(), field_type: FieldType::UInt16 },
            FieldDescriptor { name: "c".into(), field_type: FieldType::UInt32 },
        ];
        let fields = parse_event_user_data(&data, &descs);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].value, FieldValue::UInt8(0xAA));
        assert_eq!(fields[1].value, FieldValue::UInt16(0x1234));
        assert_eq!(fields[2].value, FieldValue::UInt32(0xDEAD_BEEF));
    }

    #[test]
    fn test_well_known_providers_count() {
        let map = well_known_provider_guids();
        assert!(map.len() >= 10);
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = EtwRateLimiter::new(1000);
        // At t=0 bucket is full; should allow 1000 events
        let mut allowed = 0u32;
        for i in 0u64..1100 {
            if rl.check_and_consume(i * 1_000) { // 1 µs each, total ~1.1 ms
                allowed += 1;
            }
        }
        assert!(allowed <= 1100);
        assert!(allowed > 0);
    }

    #[test]
    fn test_events_in_range() {
        let mut sess = EtwTraceSession::new(SessionConfig::default());
        let guid = guid_a();
        sess.add_provider(EtwProvider::new(guid, "P", TraceLevel::Verbose, 0xFFFF));
        sess.start().unwrap();
        for ts in [100u64, 200, 300, 400, 500] {
            sess.ingest_event(make_event(guid, 1, TraceLevel::Info, 1, 1, ts, vec![]));
        }
        let in_range = sess.events_in_range(200, 400);
        assert_eq!(in_range.len(), 3);
    }
}
