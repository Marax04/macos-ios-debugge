//! `recording_policy` — Configure what a TTD recorder should capture.
//!
//! Provides:
//! * [`RecordingPolicy`]   — top-level policy container driving recorder decisions
//! * [`RecordingFilter`]   — predicate rules for including/excluding events
//! * [`TriggerCondition`]  — condition that starts or stops recording
//! * [`RecordingStart`]    — what causes recording to begin
//! * [`RecordingStop`]     — what causes recording to end
//! * [`PolicyConfig`]      — serialisable configuration snapshot

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
pub use std::time::Duration;

use serde::{Deserialize, Serialize};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PolicyError {
    InvalidFilter(String),
    ConflictingRules(String),
    InvalidDuration(String),
    Custom(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFilter(s) => write!(f, "invalid filter: {s}"),
            Self::ConflictingRules(s) => write!(f, "conflicting rules: {s}"),
            Self::InvalidDuration(s) => write!(f, "invalid duration: {s}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for PolicyError {}

// ─── RecordingFilter ─────────────────────────────────────────────────────────

/// Category of trace events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    MemoryRead,
    MemoryWrite,
    Call,
    Return,
    Syscall,
    Exception,
    ThreadCreate,
    ThreadExit,
    Breakpoint,
    All,
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryRead => write!(f, "MemoryRead"),
            Self::MemoryWrite => write!(f, "MemoryWrite"),
            Self::Call => write!(f, "Call"),
            Self::Return => write!(f, "Return"),
            Self::Syscall => write!(f, "Syscall"),
            Self::Exception => write!(f, "Exception"),
            Self::ThreadCreate => write!(f, "ThreadCreate"),
            Self::ThreadExit => write!(f, "ThreadExit"),
            Self::Breakpoint => write!(f, "Breakpoint"),
            Self::All => write!(f, "All"),
        }
    }
}

/// Address range filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    #[must_use]
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}..{:#x}", self.start, self.end)
    }
}

/// Thread filter kind.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ThreadFilter {
    #[default]
    All,
    Include(HashSet<u32>),
    Exclude(HashSet<u32>),
}

impl ThreadFilter {
    #[must_use]
    pub fn allows(&self, tid: u32) -> bool {
        match self {
            Self::All => true,
            Self::Include(set) => set.contains(&tid),
            Self::Exclude(set) => !set.contains(&tid),
        }
    }
}

/// Module filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleFilter {
    pub included_modules: Vec<String>,
    pub excluded_modules: Vec<String>,
}

impl ModuleFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn include(mut self, name: impl Into<String>) -> Self {
        self.included_modules.push(name.into());
        self
    }

    pub fn exclude(mut self, name: impl Into<String>) -> Self {
        self.excluded_modules.push(name.into());
        self
    }

    #[must_use]
    pub fn allows(&self, module: &str) -> bool {
        if !self.included_modules.is_empty() {
            return self
                .included_modules
                .iter()
                .any(|m| module.to_lowercase().contains(&m.to_lowercase()));
        }
        !self
            .excluded_modules
            .iter()
            .any(|m| module.to_lowercase().contains(&m.to_lowercase()))
    }
}

/// Composable recording filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingFilter {
    pub name: String,
    pub enabled: bool,
    pub included_categories: HashSet<EventCategory>,
    pub excluded_categories: HashSet<EventCategory>,
    pub address_ranges: Vec<AddressRange>,
    pub thread_filter: ThreadFilter,
    pub module_filter: ModuleFilter,
    pub min_data_size: Option<usize>,
    pub max_data_size: Option<usize>,
}

impl RecordingFilter {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            included_categories: HashSet::new(),
            excluded_categories: HashSet::new(),
            address_ranges: Vec::new(),
            thread_filter: ThreadFilter::All,
            module_filter: ModuleFilter::new(),
            min_data_size: None,
            max_data_size: None,
        }
    }

    #[must_use]
    pub fn include_category(mut self, cat: EventCategory) -> Self {
        self.included_categories.insert(cat);
        self
    }

    #[must_use]
    pub fn exclude_category(mut self, cat: EventCategory) -> Self {
        self.excluded_categories.insert(cat);
        self
    }

    #[must_use]
    pub fn add_address_range(mut self, start: u64, end: u64) -> Self {
        self.address_ranges.push(AddressRange::new(start, end));
        self
    }

    #[must_use]
    pub fn with_thread_filter(mut self, tf: ThreadFilter) -> Self {
        self.thread_filter = tf;
        self
    }

    #[must_use]
    pub fn with_module_filter(mut self, mf: ModuleFilter) -> Self {
        self.module_filter = mf;
        self
    }

    #[must_use]
    pub const fn with_min_data_size(mut self, size: usize) -> Self {
        self.min_data_size = Some(size);
        self
    }

    #[must_use]
    pub const fn with_max_data_size(mut self, size: usize) -> Self {
        self.max_data_size = Some(size);
        self
    }

    #[must_use]
    pub const fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Check whether a given event passes this filter.
    #[must_use]
    pub fn passes(
        &self,
        category: EventCategory,
        address: Option<u64>,
        thread_id: u32,
        data_size: Option<usize>,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        // Category exclusion takes priority
        if self.excluded_categories.contains(&category)
            || self.excluded_categories.contains(&EventCategory::All)
        {
            return false;
        }

        // Category inclusion (if non-empty, must be in the set)
        if !self.included_categories.is_empty()
            && !self.included_categories.contains(&category)
            && !self.included_categories.contains(&EventCategory::All)
        {
            return false;
        }

        // Thread filter
        if !self.thread_filter.allows(thread_id) {
            return false;
        }

        // Address range filter
        if !self.address_ranges.is_empty()
            && let Some(addr) = address
            && !self.address_ranges.iter().any(|r| r.contains(addr))
        {
            return false;
        }

        // Data size filter
        if let (Some(sz), Some(min)) = (data_size, self.min_data_size)
            && sz < min
        {
            return false;
        }
        if let (Some(sz), Some(max)) = (data_size, self.max_data_size)
            && sz > max
        {
            return false;
        }

        true
    }
}

impl Default for RecordingFilter {
    fn default() -> Self {
        Self::new("default")
    }
}

impl fmt::Display for RecordingFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecordingFilter({}, enabled={})",
            self.name, self.enabled
        )
    }
}

// ─── TriggerCondition ────────────────────────────────────────────────────────

/// A condition that can trigger start/stop of recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerCondition {
    /// Always trigger immediately.
    Immediate,
    /// Trigger when execution reaches this address.
    AddressHit { address: u64 },
    /// Trigger on a specific exception code.
    ExceptionCode { code: u32 },
    /// Trigger after N events have been recorded.
    EventCount { n: u64 },
    /// Trigger after a wall-clock timeout.
    Timeout { millis: u64 },
    /// Trigger when a memory address equals a value.
    MemoryEquals { address: u64, expected: Vec<u8> },
    /// Trigger when a specific API (by name) is called.
    ApiCall { function_name: String },
    /// Trigger when a syscall number is invoked.
    SyscallNumber { nr: u32 },
    /// Trigger on any exception.
    AnyException,
    /// Never trigger (disabled).
    Never,
}

impl TriggerCondition {
    /// Check whether this condition is satisfied given the provided context.
    #[must_use]
    pub fn is_satisfied(
        &self,
        event_count: u64,
        elapsed_ms: u64,
        last_address: Option<u64>,
        last_exception: Option<u32>,
        last_syscall: Option<u32>,
        last_api: Option<&str>,
    ) -> bool {
        match self {
            Self::Immediate => true,
            Self::Never => false,
            Self::AddressHit { address } => last_address == Some(*address),
            Self::ExceptionCode { code } => last_exception == Some(*code),
            Self::EventCount { n } => event_count >= *n,
            Self::Timeout { millis } => elapsed_ms >= *millis,
            Self::MemoryEquals { .. } => false, // requires memory read, checked externally
            Self::ApiCall { function_name } => last_api.is_some_and(|a| a == function_name),
            Self::SyscallNumber { nr } => last_syscall == Some(*nr),
            Self::AnyException => last_exception.is_some(),
        }
    }

    #[must_use]
    pub const fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate)
    }

    #[must_use]
    pub const fn is_never(&self) -> bool {
        matches!(self, Self::Never)
    }
}

impl fmt::Display for TriggerCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate => write!(f, "Immediate"),
            Self::Never => write!(f, "Never"),
            Self::AddressHit { address } => write!(f, "AddressHit({address:#x})"),
            Self::ExceptionCode { code } => write!(f, "ExceptionCode({code:#x})"),
            Self::EventCount { n } => write!(f, "EventCount({n})"),
            Self::Timeout { millis } => write!(f, "Timeout({millis}ms)"),
            Self::MemoryEquals { address, .. } => write!(f, "MemoryEquals({address:#x})"),
            Self::ApiCall { function_name } => write!(f, "ApiCall({function_name})"),
            Self::SyscallNumber { nr } => write!(f, "SyscallNumber({nr})"),
            Self::AnyException => write!(f, "AnyException"),
        }
    }
}

// ─── RecordingStart ──────────────────────────────────────────────────────────

/// Configuration for when recording should begin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingStart {
    pub condition: TriggerCondition,
    pub description: String,
    pub delay_after_ms: Option<u64>,
}

impl RecordingStart {
    #[must_use]
    pub fn new(condition: TriggerCondition) -> Self {
        let desc = format!("{condition}");
        Self {
            condition,
            description: desc,
            delay_after_ms: None,
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    #[must_use]
    pub const fn with_delay_ms(mut self, ms: u64) -> Self {
        self.delay_after_ms = Some(ms);
        self
    }

    #[must_use]
    pub const fn is_immediate(&self) -> bool {
        self.condition.is_immediate()
    }
}

impl fmt::Display for RecordingStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordingStart {{ condition={} }}", self.condition)
    }
}

// ─── RecordingStop ───────────────────────────────────────────────────────────

/// Configuration for when recording should end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingStop {
    pub condition: TriggerCondition,
    pub description: String,
    pub max_trace_size_bytes: Option<u64>,
    pub max_events: Option<u64>,
}

impl RecordingStop {
    #[must_use]
    pub fn new(condition: TriggerCondition) -> Self {
        let desc = format!("{condition}");
        Self {
            condition,
            description: desc,
            max_trace_size_bytes: None,
            max_events: None,
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    #[must_use]
    pub const fn with_max_size_bytes(mut self, sz: u64) -> Self {
        self.max_trace_size_bytes = Some(sz);
        self
    }

    #[must_use]
    pub const fn with_max_events(mut self, n: u64) -> Self {
        self.max_events = Some(n);
        self
    }

    /// Return true if the stop condition is satisfied by the current state.
    #[must_use]
    pub fn should_stop(
        &self,
        event_count: u64,
        trace_size_bytes: u64,
        elapsed_ms: u64,
        last_address: Option<u64>,
        last_exception: Option<u32>,
        last_syscall: Option<u32>,
        last_api: Option<&str>,
    ) -> bool {
        if let Some(max) = self.max_events
            && event_count >= max
        {
            return true;
        }
        if let Some(max) = self.max_trace_size_bytes
            && trace_size_bytes >= max
        {
            return true;
        }
        self.condition.is_satisfied(
            event_count,
            elapsed_ms,
            last_address,
            last_exception,
            last_syscall,
            last_api,
        )
    }
}

impl fmt::Display for RecordingStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordingStop {{ condition={} }}", self.condition)
    }
}

// ─── PolicyConfig ────────────────────────────────────────────────────────────

/// Serialisable configuration snapshot for a recording policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub name: String,
    pub version: u32,
    pub compression_enabled: bool,
    pub encryption_enabled: bool,
    pub output_path: Option<PathBuf>,
    pub max_memory_mb: Option<u64>,
    pub snapshot_interval: Option<u64>,
    pub metadata: HashMap<String, String>,
}

impl PolicyConfig {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: 1,
            compression_enabled: false,
            encryption_enabled: false,
            output_path: None,
            max_memory_mb: None,
            snapshot_interval: None,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn with_compression(mut self) -> Self {
        self.compression_enabled = true;
        self
    }

    #[must_use]
    pub const fn with_encryption(mut self) -> Self {
        self.encryption_enabled = true;
        self
    }

    #[must_use]
    pub fn with_output_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    #[must_use]
    pub const fn with_max_memory_mb(mut self, mb: u64) -> Self {
        self.max_memory_mb = Some(mb);
        self
    }

    #[must_use]
    pub const fn with_snapshot_interval(mut self, interval: u64) -> Self {
        self.snapshot_interval = Some(interval);
        self
    }

    #[must_use]
    pub fn add_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// # Errors
    ///
    /// Returns `Err` if the config is invalid (empty name, zero `max_memory_mb`).
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.name.is_empty() {
            return Err(PolicyError::InvalidFilter(
                "Policy name cannot be empty".into(),
            ));
        }
        if let Some(mb) = self.max_memory_mb
            && mb == 0
        {
            return Err(PolicyError::InvalidDuration(
                "max_memory_mb cannot be 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self::new("default")
    }
}

impl fmt::Display for PolicyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PolicyConfig({}, v{}, compress={}, encrypt={})",
            self.name, self.version, self.compression_enabled, self.encryption_enabled
        )
    }
}

// ─── RecordingPolicy ─────────────────────────────────────────────────────────

/// Current recording state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordingState {
    Idle,
    WaitingForStart,
    Recording,
    Paused,
    Stopped,
}

impl fmt::Display for RecordingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::WaitingForStart => write!(f, "WaitingForStart"),
            Self::Recording => write!(f, "Recording"),
            Self::Paused => write!(f, "Paused"),
            Self::Stopped => write!(f, "Stopped"),
        }
    }
}

/// Full recording policy — drives all recorder decisions.
pub struct RecordingPolicy {
    pub config: PolicyConfig,
    pub start: RecordingStart,
    pub stop: RecordingStop,
    pub filters: Vec<RecordingFilter>,
    pub state: RecordingState,
    pub events_recorded: u64,
    pub trace_size_bytes: u64,
    pub elapsed_ms: u64,
}

impl RecordingPolicy {
    #[must_use]
    pub const fn new(config: PolicyConfig, start: RecordingStart, stop: RecordingStop) -> Self {
        let is_immediate = start.is_immediate();
        Self {
            config,
            start,
            stop,
            filters: Vec::new(),
            state: if is_immediate {
                RecordingState::Recording
            } else {
                RecordingState::WaitingForStart
            },
            events_recorded: 0,
            trace_size_bytes: 0,
            elapsed_ms: 0,
        }
    }

    /// Create a policy that records everything immediately.
    #[must_use]
    pub fn record_all() -> Self {
        Self::new(
            PolicyConfig::new("record_all"),
            RecordingStart::new(TriggerCondition::Immediate),
            RecordingStop::new(TriggerCondition::Never),
        )
    }

    /// Create a policy that records until N events then stops.
    #[must_use]
    pub fn record_n_events(n: u64) -> Self {
        Self::new(
            PolicyConfig::new("record_n"),
            RecordingStart::new(TriggerCondition::Immediate),
            RecordingStop::new(TriggerCondition::EventCount { n }).with_max_events(n),
        )
    }

    /// Add a filter.
    pub fn add_filter(&mut self, filter: RecordingFilter) {
        self.filters.push(filter);
    }

    /// Remove a filter by name.
    #[must_use]
    pub fn remove_filter(&mut self, name: &str) -> bool {
        if let Some(pos) = self.filters.iter().position(|f| f.name == name) {
            self.filters.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check whether a given event should be recorded.
    #[must_use]
    pub fn should_record(
        &self,
        category: EventCategory,
        address: Option<u64>,
        thread_id: u32,
        data_size: Option<usize>,
    ) -> bool {
        if self.state != RecordingState::Recording {
            return false;
        }
        if self.filters.is_empty() {
            return true;
        }
        // Any enabled filter that passes allows the event
        self.filters
            .iter()
            .any(|f| f.passes(category, address, thread_id, data_size))
    }

    /// Notify the policy that an event has occurred; may transition state.
    pub fn notify_event(
        &mut self,
        category: EventCategory,
        address: Option<u64>,
        data_size: Option<usize>,
        exception: Option<u32>,
        syscall: Option<u32>,
        api: Option<&str>,
    ) {
        let tid = 0u32;
        match self.state {
            RecordingState::WaitingForStart => {
                if self.start.condition.is_satisfied(
                    self.events_recorded,
                    self.elapsed_ms,
                    address,
                    exception,
                    syscall,
                    api,
                ) {
                    self.state = RecordingState::Recording;
                }
            }
            RecordingState::Recording => {
                if self.should_record(category, address, tid, data_size) {
                    self.events_recorded += 1;
                    if let Some(sz) = data_size {
                        self.trace_size_bytes += u64::try_from(sz).unwrap_or(u64::MAX);
                    }
                }
                if self.stop.should_stop(
                    self.events_recorded,
                    self.trace_size_bytes,
                    self.elapsed_ms,
                    address,
                    exception,
                    syscall,
                    api,
                ) {
                    self.state = RecordingState::Stopped;
                }
            }
            _ => {}
        }
    }

    /// Advance the elapsed time counter.
    pub fn tick_ms(&mut self, ms: u64) {
        self.elapsed_ms += ms;
        if self.state == RecordingState::Recording
            && self.stop.should_stop(
                self.events_recorded,
                self.trace_size_bytes,
                self.elapsed_ms,
                None,
                None,
                None,
                None,
            )
        {
            self.state = RecordingState::Stopped;
        }
    }

    pub fn pause(&mut self) {
        if self.state == RecordingState::Recording {
            self.state = RecordingState::Paused;
        }
    }

    pub fn resume(&mut self) {
        if self.state == RecordingState::Paused {
            self.state = RecordingState::Recording;
        }
    }

    pub const fn force_stop(&mut self) {
        self.state = RecordingState::Stopped;
    }

    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.state == RecordingState::Recording
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.state == RecordingState::Stopped
    }
}

impl fmt::Display for RecordingPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecordingPolicy {{ state={}, events={}, size={}B }}",
            self.state, self.events_recorded, self.trace_size_bytes
        )
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RecordingFilter ──────────────────────────────────────────────────────

    #[test]
    fn test_filter_passes_default() {
        let f = RecordingFilter::default();
        assert!(f.passes(EventCategory::Call, Some(0x1000), 1, None));
    }

    #[test]
    fn test_filter_excluded_category() {
        let f = RecordingFilter::new("f").exclude_category(EventCategory::MemoryRead);
        assert!(!f.passes(EventCategory::MemoryRead, None, 1, None));
        assert!(f.passes(EventCategory::Call, None, 1, None));
    }

    #[test]
    fn test_filter_included_category() {
        let f = RecordingFilter::new("f").include_category(EventCategory::Call);
        assert!(f.passes(EventCategory::Call, None, 1, None));
        assert!(!f.passes(EventCategory::MemoryRead, None, 1, None));
    }

    #[test]
    fn test_filter_address_range() {
        let f = RecordingFilter::new("f").add_address_range(0x1000, 0x2000);
        assert!(f.passes(EventCategory::Call, Some(0x1500), 1, None));
        assert!(!f.passes(EventCategory::Call, Some(0x3000), 1, None));
    }

    #[test]
    fn test_filter_thread_include() {
        let mut set = HashSet::new();
        set.insert(1u32);
        let f = RecordingFilter::new("f").with_thread_filter(ThreadFilter::Include(set));
        assert!(f.passes(EventCategory::Call, None, 1, None));
        assert!(!f.passes(EventCategory::Call, None, 2, None));
    }

    #[test]
    fn test_filter_thread_exclude() {
        let mut set = HashSet::new();
        set.insert(2u32);
        let f = RecordingFilter::new("f").with_thread_filter(ThreadFilter::Exclude(set));
        assert!(f.passes(EventCategory::Call, None, 1, None));
        assert!(!f.passes(EventCategory::Call, None, 2, None));
    }

    #[test]
    fn test_filter_data_size_min() {
        let f = RecordingFilter::new("f").with_min_data_size(4);
        assert!(!f.passes(EventCategory::MemoryWrite, None, 1, Some(2)));
        assert!(f.passes(EventCategory::MemoryWrite, None, 1, Some(8)));
    }

    #[test]
    fn test_filter_data_size_max() {
        let f = RecordingFilter::new("f").with_max_data_size(4);
        assert!(f.passes(EventCategory::MemoryWrite, None, 1, Some(2)));
        assert!(!f.passes(EventCategory::MemoryWrite, None, 1, Some(8)));
    }

    #[test]
    fn test_filter_disabled() {
        let f = RecordingFilter::new("f").disable();
        assert!(!f.passes(EventCategory::Call, None, 1, None));
    }

    // ── AddressRange ─────────────────────────────────────────────────────────

    #[test]
    fn test_address_range_contains() {
        let r = AddressRange::new(0x1000, 0x2000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn test_address_range_size() {
        let r = AddressRange::new(0x1000, 0x2000);
        assert_eq!(r.size(), 0x1000);
    }

    // ── TriggerCondition ─────────────────────────────────────────────────────

    #[test]
    fn test_trigger_immediate() {
        let t = TriggerCondition::Immediate;
        assert!(t.is_satisfied(0, 0, None, None, None, None));
    }

    #[test]
    fn test_trigger_never() {
        let t = TriggerCondition::Never;
        assert!(!t.is_satisfied(
            9999,
            9999,
            Some(0x1000),
            Some(0x0C00_0005),
            Some(1),
            Some("x")
        ));
    }

    #[test]
    fn test_trigger_address_hit() {
        let t = TriggerCondition::AddressHit { address: 0x1234 };
        assert!(t.is_satisfied(0, 0, Some(0x1234), None, None, None));
        assert!(!t.is_satisfied(0, 0, Some(0x5678), None, None, None));
    }

    #[test]
    fn test_trigger_exception_code() {
        let t = TriggerCondition::ExceptionCode { code: 0xC000_0005 };
        assert!(t.is_satisfied(0, 0, None, Some(0xC000_0005), None, None));
        assert!(!t.is_satisfied(0, 0, None, Some(0xC000_001D), None, None));
    }

    #[test]
    fn test_trigger_event_count() {
        let t = TriggerCondition::EventCount { n: 100 };
        assert!(t.is_satisfied(100, 0, None, None, None, None));
        assert!(!t.is_satisfied(50, 0, None, None, None, None));
    }

    #[test]
    fn test_trigger_timeout() {
        let t = TriggerCondition::Timeout { millis: 5000 };
        assert!(t.is_satisfied(0, 6000, None, None, None, None));
        assert!(!t.is_satisfied(0, 4000, None, None, None, None));
    }

    #[test]
    fn test_trigger_api_call() {
        let t = TriggerCondition::ApiCall {
            function_name: "CreateFile".into(),
        };
        assert!(t.is_satisfied(0, 0, None, None, None, Some("CreateFile")));
        assert!(!t.is_satisfied(0, 0, None, None, None, Some("ReadFile")));
    }

    // ── RecordingStart / RecordingStop ───────────────────────────────────────

    #[test]
    fn test_recording_start_is_immediate() {
        let s = RecordingStart::new(TriggerCondition::Immediate);
        assert!(s.is_immediate());
    }

    #[test]
    fn test_recording_stop_max_events() {
        let stop = RecordingStop::new(TriggerCondition::Never).with_max_events(10);
        assert!(!stop.should_stop(9, 0, 0, None, None, None, None));
        assert!(stop.should_stop(10, 0, 0, None, None, None, None));
    }

    #[test]
    fn test_recording_stop_max_size() {
        let stop = RecordingStop::new(TriggerCondition::Never).with_max_size_bytes(1024);
        assert!(!stop.should_stop(0, 512, 0, None, None, None, None));
        assert!(stop.should_stop(0, 1024, 0, None, None, None, None));
    }

    // ── PolicyConfig ─────────────────────────────────────────────────────────

    #[test]
    fn test_policy_config_validate_ok() {
        let c = PolicyConfig::new("test");
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_policy_config_validate_empty_name() {
        let c = PolicyConfig::new("");
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_policy_config_validate_zero_memory() {
        let c = PolicyConfig::new("test").with_max_memory_mb(0);
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_policy_config_builder() {
        let c = PolicyConfig::new("p")
            .with_compression()
            .with_encryption()
            .with_max_memory_mb(512)
            .with_snapshot_interval(1000)
            .add_metadata("key", "value");
        assert!(c.compression_enabled);
        assert!(c.encryption_enabled);
        assert_eq!(c.max_memory_mb, Some(512));
        assert_eq!(c.metadata.get("key"), Some(&"value".to_string()));
    }

    // ── RecordingPolicy ──────────────────────────────────────────────────────

    #[test]
    fn test_policy_record_all() {
        let mut p = RecordingPolicy::record_all();
        assert!(p.is_recording());
        p.notify_event(EventCategory::Call, Some(0x1000), None, None, None, None);
        assert_eq!(p.events_recorded, 1);
    }

    #[test]
    fn test_policy_record_n_stops() {
        let mut p = RecordingPolicy::record_n_events(3);
        for _ in 0..3 {
            p.notify_event(EventCategory::Call, None, None, None, None, None);
        }
        assert!(p.is_stopped());
    }

    #[test]
    fn test_policy_waiting_for_start() {
        let mut p = RecordingPolicy::new(
            PolicyConfig::new("test"),
            RecordingStart::new(TriggerCondition::AddressHit { address: 0x1234 }),
            RecordingStop::new(TriggerCondition::Never),
        );
        assert_eq!(p.state, RecordingState::WaitingForStart);
        p.notify_event(EventCategory::Call, Some(0x5678), None, None, None, None);
        assert_eq!(p.state, RecordingState::WaitingForStart);
        p.notify_event(EventCategory::Call, Some(0x1234), None, None, None, None);
        assert_eq!(p.state, RecordingState::Recording);
    }

    #[test]
    fn test_policy_pause_resume() {
        let mut p = RecordingPolicy::record_all();
        p.pause();
        assert_eq!(p.state, RecordingState::Paused);
        p.resume();
        assert_eq!(p.state, RecordingState::Recording);
    }

    #[test]
    fn test_policy_force_stop() {
        let mut p = RecordingPolicy::record_all();
        p.force_stop();
        assert!(p.is_stopped());
    }

    #[test]
    fn test_policy_filter_excluded_events_not_counted() {
        let mut p = RecordingPolicy::record_all();
        p.add_filter(RecordingFilter::new("no_reads").exclude_category(EventCategory::MemoryRead));
        p.notify_event(EventCategory::MemoryRead, None, None, None, None, None);
        assert_eq!(p.events_recorded, 0);
    }

    #[test]
    fn test_policy_tick_ms_triggers_stop() {
        let stop = RecordingStop::new(TriggerCondition::Timeout { millis: 1000 });
        let mut p = RecordingPolicy::new(
            PolicyConfig::new("test"),
            RecordingStart::new(TriggerCondition::Immediate),
            stop,
        );
        p.tick_ms(500);
        assert!(p.is_recording());
        p.tick_ms(600);
        assert!(p.is_stopped());
    }

    #[test]
    fn test_policy_add_remove_filter() {
        let mut p = RecordingPolicy::record_all();
        p.add_filter(RecordingFilter::new("f1"));
        assert_eq!(p.filters.len(), 1);
        assert!(p.remove_filter("f1"));
        assert_eq!(p.filters.len(), 0);
        assert!(!p.remove_filter("f1"));
    }

    #[test]
    fn test_module_filter_allows() {
        let mf = ModuleFilter::new().include("kernel32");
        assert!(mf.allows("kernel32.dll"));
        assert!(!mf.allows("ntdll.dll"));
    }

    #[test]
    fn test_module_filter_excludes() {
        let mf = ModuleFilter::new().exclude("ntdll");
        assert!(!mf.allows("ntdll.dll"));
        assert!(mf.allows("kernel32.dll"));
    }

    #[test]
    fn test_recording_state_display() {
        assert_eq!(format!("{}", RecordingState::Recording), "Recording");
        assert_eq!(format!("{}", RecordingState::Idle), "Idle");
        assert_eq!(format!("{}", RecordingState::Stopped), "Stopped");
    }

    #[test]
    fn test_event_category_display() {
        assert_eq!(format!("{}", EventCategory::Call), "Call");
        assert_eq!(format!("{}", EventCategory::MemoryWrite), "MemoryWrite");
    }

    #[test]
    fn test_policy_display() {
        let p = RecordingPolicy::record_all();
        let s = format!("{p}");
        assert!(s.contains("Recording"));
    }

    #[test]
    fn test_recording_filter_display() {
        let f = RecordingFilter::new("my_filter");
        let s = format!("{f}");
        assert!(s.contains("my_filter"));
    }

    #[test]
    fn test_recording_start_display() {
        let s = RecordingStart::new(TriggerCondition::Immediate);
        let disp = format!("{s}");
        assert!(disp.contains("RecordingStart"));
    }

    #[test]
    fn test_recording_stop_display() {
        let s = RecordingStop::new(TriggerCondition::Never);
        let disp = format!("{s}");
        assert!(disp.contains("RecordingStop"));
    }

    #[test]
    fn test_trigger_syscall_number() {
        let t = TriggerCondition::SyscallNumber { nr: 60 };
        assert!(t.is_satisfied(0, 0, None, None, Some(60), None));
        assert!(!t.is_satisfied(0, 0, None, None, Some(1), None));
    }

    #[test]
    fn test_trigger_any_exception() {
        let t = TriggerCondition::AnyException;
        assert!(t.is_satisfied(0, 0, None, Some(0xC000_0005), None, None));
        assert!(!t.is_satisfied(0, 0, None, None, None, None));
    }

    #[test]
    fn test_trigger_display() {
        assert_eq!(format!("{}", TriggerCondition::Immediate), "Immediate");
        assert_eq!(format!("{}", TriggerCondition::Never), "Never");
        let t = TriggerCondition::AddressHit { address: 0x1234 };
        assert!(format!("{t}").contains("0x1234"));
    }

    #[test]
    fn test_address_range_display() {
        let r = AddressRange::new(0x1000, 0x2000);
        let s = format!("{r}");
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_policy_config_display() {
        let c = PolicyConfig::new("test").with_compression();
        let s = format!("{c}");
        assert!(s.contains("test"));
        assert!(s.contains("compress=true"));
    }

    #[test]
    fn test_policy_resume_while_not_paused_noop() {
        let mut p = RecordingPolicy::record_all();
        p.resume(); // should not panic or change state
        assert!(p.is_recording());
    }

    #[test]
    fn test_policy_pause_while_stopped_noop() {
        let mut p = RecordingPolicy::record_all();
        p.force_stop();
        p.pause(); // should be a no-op
        assert!(p.is_stopped());
    }

    #[test]
    fn test_filter_all_categories_excluded() {
        let f = RecordingFilter::new("f").exclude_category(EventCategory::All);
        assert!(!f.passes(EventCategory::Call, None, 1, None));
    }

    #[test]
    fn test_policy_record_n_count_increments() {
        let mut p = RecordingPolicy::record_n_events(100);
        p.notify_event(EventCategory::Call, Some(0x1000), Some(8), None, None, None);
        assert_eq!(p.events_recorded, 1);
        assert_eq!(p.trace_size_bytes, 8);
    }
}
