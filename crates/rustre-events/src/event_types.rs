//! `event_types.rs` — Rich analysis event types for the `RustRE` event bus.
//!
//! Defines all analysis event variants as distinct payload structs, grouped
//! under [`AnalysisEvent`] and [`EventPayload`], along with priority and
//! filter helpers.

use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// EventPriority
// ---------------------------------------------------------------------------

/// Scheduling priority attached to every dispatched event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Default)]
pub enum EventPriority {
    /// Low-importance background events (progress updates, verbose tracing).
    Low = 0,
    /// Normal-importance events (typical analysis results).
    #[default]
    Normal = 1,
    /// High-importance events (alerts, errors, security findings).
    High = 2,
    /// Critical events that should never be dropped (crashes, fatal errors).
    Critical = 3,
}


impl fmt::Display for EventPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Normal => write!(f, "NORMAL"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Individual payload structs
// ---------------------------------------------------------------------------

/// Payload for [`AnalysisEvent::FileOpened`].
#[derive(Debug, Clone)]
pub struct FileOpenedPayload {
    /// Unique view identifier.
    pub view_id: u64,
    /// File path or URI.
    pub path: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Detected architecture (e.g. `"x86_64"`).
    pub arch: String,
    /// Detected operating system (e.g. `"Windows"`).
    pub os: String,
    /// Detected file format (e.g. `"PE"`, `"ELF"`).
    pub format: String,
    /// SHA-256 hash of the file, hex-encoded.
    pub sha256: String,
    /// When the file was opened.
    pub timestamp: SystemTime,
}

/// Payload for [`AnalysisEvent::FileAnalyzed`].
#[derive(Debug, Clone)]
pub struct FileAnalyzedPayload {
    pub view_id: u64,
    /// Name of the analysis pass that completed.
    pub pass_name: String,
    /// Duration of this pass in milliseconds.
    pub duration_ms: u64,
    /// How many functions were found during the pass.
    pub functions_found: usize,
    /// How many data references were found.
    pub data_refs_found: usize,
    /// Warnings emitted during the pass.
    pub warnings: Vec<String>,
}

/// Payload for [`AnalysisEvent::FunctionFound`].
#[derive(Debug, Clone)]
pub struct FunctionFoundPayload {
    pub view_id: u64,
    /// Start address of the function.
    pub address: u64,
    /// Detected or inferred name.
    pub name: String,
    /// Size of the function in bytes, if known.
    pub size: Option<u64>,
    /// Whether the name was obtained from a symbol table.
    pub from_symbol: bool,
    /// Number of basic blocks discovered.
    pub basic_block_count: usize,
    /// Estimated calling convention.
    pub calling_convention: Option<String>,
    /// Tags applied during discovery.
    pub tags: Vec<String>,
}

/// Payload for [`AnalysisEvent::StringFound`].
#[derive(Debug, Clone)]
pub struct StringFoundPayload {
    pub view_id: u64,
    /// Address where the string resides.
    pub address: u64,
    /// Decoded string value.
    pub value: String,
    /// Byte length in memory.
    pub byte_length: usize,
    /// Encoding name (e.g. `"ASCII"`, `"UTF-16 LE"`).
    pub encoding: String,
    /// Whether the string appears to be obfuscated.
    pub possibly_obfuscated: bool,
    /// Shannon entropy of the raw bytes.
    pub entropy: f64,
}

/// Payload for [`AnalysisEvent::SymbolResolved`].
#[derive(Debug, Clone)]
pub struct SymbolResolvedPayload {
    pub view_id: u64,
    pub address: u64,
    pub name: String,
    /// Symbol kind: `"function"`, `"data"`, `"import"`, `"export"`, etc.
    pub kind: String,
    /// Source that provided the symbol: `"pdb"`, `"elf_symtab"`, `"manual"`, etc.
    pub source: String,
    /// Demangled name, if available.
    pub demangled: Option<String>,
    /// Namespace or module the symbol belongs to.
    pub namespace: Option<String>,
}

/// Payload for [`AnalysisEvent::CrossRefAdded`].
// #[derive name = "CrossRefAddedPayload"]
#[derive(Debug, Clone)]
pub struct CrossRefAddedPayload {
    pub view_id: u64,
    /// Source address of the reference.
    pub from_addr: u64,
    /// Target address of the reference.
    pub to_addr: u64,
    /// Reference type: `"call"`, `"data"`, `"branch"`, `"pointer"`.
    pub ref_type: String,
    /// Whether this is a direct or indirect reference.
    pub indirect: bool,
}

/// Payload for [`AnalysisEvent::PatternMatched`].
#[derive(Debug, Clone)]
pub struct PatternMatchedPayload {
    pub view_id: u64,
    /// Address where the pattern was found.
    pub address: u64,
    /// Name of the pattern (e.g. `"memcpy_stub"`, `"cryptographic_constant"`).
    pub pattern_name: String,
    /// Confidence in [0.0, 1.0].
    pub confidence: f64,
    /// Raw bytes that matched.
    pub matched_bytes: Vec<u8>,
    /// Additional metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

/// Payload for [`AnalysisEvent::AlertTriggered`].
#[derive(Debug, Clone)]
pub struct AlertTriggeredPayload {
    pub view_id: u64,
    /// Alert title.
    pub title: String,
    /// Full description.
    pub description: String,
    /// Severity: `"info"`, `"warning"`, `"error"`, `"critical"`.
    pub severity: String,
    /// Address related to the alert, if any.
    pub address: Option<u64>,
    /// Alert category, e.g. `"security"`, `"correctness"`, `"performance"`.
    pub category: String,
    /// Suggested remediation steps.
    pub remediation: Option<String>,
}

/// Payload for [`AnalysisEvent::PluginStarted`].
#[derive(Debug, Clone)]
pub struct PluginStartedPayload {
    /// Plugin identifier.
    pub plugin_id: String,
    /// Human-readable plugin name.
    pub plugin_name: String,
    /// Plugin version string.
    pub version: String,
    /// Capabilities advertised by the plugin.
    pub capabilities: Vec<String>,
    /// When the plugin was started.
    pub started_at: SystemTime,
}

/// Payload for [`AnalysisEvent::ProgressUpdate`].
#[derive(Debug, Clone)]
pub struct ProgressUpdatePayload {
    pub view_id: u64,
    /// Name of the task being tracked.
    pub task_name: String,
    /// Completion percentage in [0, 100].
    pub percent: u8,
    /// Items completed so far.
    pub items_done: u64,
    /// Total items to process (0 = unknown).
    pub items_total: u64,
    /// Estimated seconds remaining (None = unknown).
    pub eta_secs: Option<u64>,
    /// Human-readable status message.
    pub message: String,
}

/// Payload for [`AnalysisEvent::AnalysisComplete`].
#[derive(Debug, Clone)]
pub struct AnalysisCompletePayload {
    pub view_id: u64,
    /// Name of the completed analysis pipeline.
    pub pipeline_name: String,
    /// Total elapsed time in milliseconds.
    pub total_ms: u64,
    /// Number of passes that ran.
    pub passes_run: usize,
    /// Number of passes that failed.
    pub passes_failed: usize,
    /// Aggregate statistics.
    pub stats: AnalysisStats,
}

/// Aggregate statistics included in [`AnalysisCompletePayload`].
#[derive(Debug, Clone, Default)]
pub struct AnalysisStats {
    pub functions_found: usize,
    pub strings_found: usize,
    pub symbols_resolved: usize,
    pub cross_refs_added: usize,
    pub patterns_matched: usize,
    pub alerts_triggered: usize,
    pub bytes_analyzed: u64,
}

/// Payload for [`AnalysisEvent::ErrorOccurred`].
#[derive(Debug, Clone)]
pub struct ErrorOccurredPayload {
    /// View this error is associated with, if any.
    pub view_id: Option<u64>,
    /// Error code (e.g. `"IO_ERROR"`, `"PARSE_FAILED"`).
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Stack trace or backtrace, if available.
    pub backtrace: Option<String>,
    /// Whether the error is recoverable.
    pub recoverable: bool,
    /// Component that raised the error.
    pub component: String,
    /// Timestamp of the error.
    pub timestamp: SystemTime,
}

// ---------------------------------------------------------------------------
// AnalysisEvent — top-level enum
// ---------------------------------------------------------------------------

/// Every distinct analysis event that can be fired on the platform.
///
/// Each variant carries a dedicated payload struct for maximum type safety
/// and extensibility.
#[derive(Debug, Clone)]
pub enum AnalysisEvent {
    /// A new file has been opened for analysis.
    FileOpened(FileOpenedPayload),
    /// An analysis pass has completed on a file.
    FileAnalyzed(FileAnalyzedPayload),
    /// A function has been discovered.
    FunctionFound(FunctionFoundPayload),
    /// A string has been found in the binary.
    StringFound(StringFoundPayload),
    /// A symbol has been resolved to an address.
    SymbolResolved(SymbolResolvedPayload),
    /// A cross-reference has been added to the database.
    CrossRefAdded(CrossRefAddedPayload),
    /// A code or data pattern has been matched.
    PatternMatched(PatternMatchedPayload),
    /// An alert has been triggered by an analysis pass.
    AlertTriggered(AlertTriggeredPayload),
    /// A plugin has started.
    PluginStarted(PluginStartedPayload),
    /// An analysis task has made progress.
    ProgressUpdate(ProgressUpdatePayload),
    /// An entire analysis pipeline has completed.
    AnalysisComplete(AnalysisCompletePayload),
    /// An error has occurred.
    ErrorOccurred(ErrorOccurredPayload),
}

impl AnalysisEvent {
    /// Return the view ID associated with this event, or `None` for global events.
    #[must_use]
    pub const fn view_id(&self) -> Option<u64> {
        match self {
            Self::FileOpened(p) => Some(p.view_id),
            Self::FileAnalyzed(p) => Some(p.view_id),
            Self::FunctionFound(p) => Some(p.view_id),
            Self::StringFound(p) => Some(p.view_id),
            Self::SymbolResolved(p) => Some(p.view_id),
            Self::CrossRefAdded(p) => Some(p.view_id),
            Self::PatternMatched(p) => Some(p.view_id),
            Self::AlertTriggered(p) => Some(p.view_id),
            Self::PluginStarted(_) => None,
            Self::ProgressUpdate(p) => Some(p.view_id),
            Self::AnalysisComplete(p) => Some(p.view_id),
            Self::ErrorOccurred(p) => p.view_id,
        }
    }

    /// Return the static variant name for logging and metrics.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::FileOpened(_) => "FileOpened",
            Self::FileAnalyzed(_) => "FileAnalyzed",
            Self::FunctionFound(_) => "FunctionFound",
            Self::StringFound(_) => "StringFound",
            Self::SymbolResolved(_) => "SymbolResolved",
            Self::CrossRefAdded(_) => "CrossRefAdded",
            Self::PatternMatched(_) => "PatternMatched",
            Self::AlertTriggered(_) => "AlertTriggered",
            Self::PluginStarted(_) => "PluginStarted",
            Self::ProgressUpdate(_) => "ProgressUpdate",
            Self::AnalysisComplete(_) => "AnalysisComplete",
            Self::ErrorOccurred(_) => "ErrorOccurred",
        }
    }

    /// Default priority for each event variant.
    #[must_use]
    pub fn default_priority(&self) -> EventPriority {
        match self {
            Self::AlertTriggered(p) if p.severity == "critical" => EventPriority::Critical,
            Self::ErrorOccurred(p) if !p.recoverable => EventPriority::Critical,
            Self::AlertTriggered(_) | Self::ErrorOccurred(_) => EventPriority::High,
            Self::ProgressUpdate(_) => EventPriority::Low,
            _ => EventPriority::Normal,
        }
    }

    /// Return `true` if this is an error or alert event.
    #[must_use]
    pub const fn is_error_or_alert(&self) -> bool {
        matches!(self, Self::AlertTriggered(_) | Self::ErrorOccurred(_))
    }

    /// Return `true` if this event carries discovery information.
    #[must_use]
    pub const fn is_discovery_event(&self) -> bool {
        matches!(
            self,
            Self::FunctionFound(_)
                | Self::StringFound(_)
                | Self::SymbolResolved(_)
                | Self::CrossRefAdded(_)
                | Self::PatternMatched(_)
        )
    }
}

impl fmt::Display for AnalysisEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.view_id() {
            Some(vid) => write!(f, "[view={}] {}", vid, self.variant_name()),
            None => write!(f, "{}", self.variant_name()),
        }
    }
}

// ---------------------------------------------------------------------------
// EventPayload — type-erased wrapper
// ---------------------------------------------------------------------------

/// A type-erased payload plus the event's priority and timestamp.
///
/// Useful for storing heterogeneous events in a single container without
/// heap-allocating each payload individually.
#[derive(Debug, Clone)]
pub struct EventPayload {
    /// The concrete event.
    pub event: AnalysisEvent,
    /// Priority assigned at dispatch time.
    pub priority: EventPriority,
    /// Wall-clock time at which the event was created.
    pub timestamp: SystemTime,
    /// Monotonically increasing sequence number (assigned by the dispatcher).
    pub sequence: u64,
}

impl EventPayload {
    /// Create a payload with a specific priority.
    #[must_use]
    pub fn new(event: AnalysisEvent, priority: EventPriority, sequence: u64) -> Self {
        Self {
            priority,
            timestamp: SystemTime::now(),
            sequence,
            event,
        }
    }

    /// Create a payload using the event's default priority.
    #[must_use]
    pub fn with_default_priority(event: AnalysisEvent, sequence: u64) -> Self {
        let priority = event.default_priority();
        Self::new(event, priority, sequence)
    }

    /// Return the view ID from the inner event.
    #[must_use]
    pub const fn view_id(&self) -> Option<u64> {
        self.event.view_id()
    }

    /// Return the variant name from the inner event.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        self.event.variant_name()
    }

    /// Return elapsed milliseconds since the event was created.
    #[must_use]
    pub fn age_ms(&self) -> u64 {
        self.timestamp
            .elapsed()
            .map_or(0, |d| u64::try_from(d.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX))
    }
}

impl fmt::Display for EventPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[seq={} pri={}] {}",
            self.sequence, self.priority, self.event
        )
    }
}

// ---------------------------------------------------------------------------
// EventFilter — composable predicate over EventPayload
// ---------------------------------------------------------------------------

/// A composable predicate used to filter [`EventPayload`] values.
pub struct AnalysisEventFilter {
    inner: Box<dyn Fn(&EventPayload) -> bool + Send + Sync>,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Debug for AnalysisEventFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnalysisEventFilter({})", self.description)
    }
}

impl AnalysisEventFilter {
    /// Create a filter from an arbitrary predicate.
    pub fn new(
        description: impl Into<String>,
        f: impl Fn(&EventPayload) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Box::new(f),
            description: description.into(),
        }
    }

    /// Accept only events for a specific view.
    #[must_use]
    pub fn for_view(view_id: u64) -> Self {
        Self::new(
            format!("view={view_id}"),
            move |p| p.view_id() == Some(view_id),
        )
    }

    /// Accept only events with priority >= `min`.
    #[must_use]
    pub fn min_priority(min: EventPriority) -> Self {
        Self::new(
            format!("priority>={min}"),
            move |p| p.priority >= min,
        )
    }

    /// Accept only events whose variant name matches.
    #[must_use]
    pub fn by_variant(name: &'static str) -> Self {
        Self::new(
            format!("variant={name}"),
            move |p| p.variant_name() == name,
        )
    }

    /// Accept only discovery events.
    #[must_use]
    pub fn discovery_only() -> Self {
        Self::new("discovery", |p| p.event.is_discovery_event())
    }

    /// Accept only error or alert events.
    #[must_use]
    pub fn errors_and_alerts() -> Self {
        Self::new("errors+alerts", |p| p.event.is_error_or_alert())
    }

    /// Logical AND of two filters.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        let desc = format!("({}) AND ({})", self.description, other.description);
        Self::new(desc, move |p| (self.inner)(p) && (other.inner)(p))
    }

    /// Logical OR of two filters.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        let desc = format!("({}) OR ({})", self.description, other.description);
        Self::new(desc, move |p| (self.inner)(p) || (other.inner)(p))
    }

    /// Logical NOT of this filter.
    #[must_use]
    pub fn negate(self) -> Self {
        let desc = format!("NOT ({})", self.description);
        Self::new(desc, move |p| !(self.inner)(p))
    }

    /// Test a payload against this filter.
    #[must_use]
    pub fn matches(&self, payload: &EventPayload) -> bool {
        (self.inner)(payload)
    }
}

// ---------------------------------------------------------------------------
// EventBatch — group of events for efficient batched delivery
// ---------------------------------------------------------------------------

/// A batch of [`EventPayload`] values assembled for bulk delivery.
#[derive(Debug, Clone, Default)]
pub struct EventBatch {
    /// The collected payloads, in order of arrival.
    pub events: Vec<EventPayload>,
    /// The highest priority present in this batch.
    pub max_priority: Option<EventPriority>,
    /// Sequence number of the first event in the batch.
    pub first_seq: u64,
    /// Sequence number of the last event in the batch.
    pub last_seq: u64,
}

impl EventBatch {
    /// Create an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a payload to the batch.
    pub fn push(&mut self, payload: EventPayload) {
        if self.events.is_empty() {
            self.first_seq = payload.sequence;
        }
        self.last_seq = payload.sequence;
        let p = payload.priority;
        match self.max_priority {
            None => self.max_priority = Some(p),
            Some(cur) if p > cur => self.max_priority = Some(p),
            _ => {}
        }
        self.events.push(payload);
    }

    /// Number of events in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if the batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Drain all events from the batch, returning them.
    pub fn drain(&mut self) -> Vec<EventPayload> {
        self.max_priority = None;
        self.first_seq = 0;
        self.last_seq = 0;
        std::mem::take(&mut self.events)
    }

    /// Return only events that pass the given filter.
    #[must_use]
    pub fn filtered(&self, filter: &AnalysisEventFilter) -> Vec<&EventPayload> {
        self.events.iter().filter(|p| filter.matches(p)).collect()
    }

    /// Group events by variant name.
    #[must_use]
    pub fn group_by_variant(&self) -> HashMap<&'static str, Vec<&EventPayload>> {
        let mut map: HashMap<&'static str, Vec<&EventPayload>> = HashMap::new();
        for p in &self.events {
            map.entry(p.variant_name()).or_default().push(p);
        }
        map
    }

    /// Count events by view ID.
    #[must_use]
    pub fn count_by_view(&self) -> HashMap<u64, usize> {
        let mut map: HashMap<u64, usize> = HashMap::new();
        for p in &self.events {
            if let Some(vid) = p.view_id() {
                *map.entry(vid).or_insert(0) += 1;
            }
        }
        map
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Build a [`FileOpenedPayload`] with minimal required fields.
#[must_use]
pub fn make_file_opened(view_id: u64, path: impl Into<String>, arch: impl Into<String>) -> FileOpenedPayload {
    FileOpenedPayload {
        view_id,
        path: path.into(),
        file_size: 0,
        arch: arch.into(),
        os: String::new(),
        format: String::new(),
        sha256: String::new(),
        timestamp: SystemTime::now(),
    }
}

/// Build a [`FunctionFoundPayload`] with minimal required fields.
#[must_use]
pub fn make_function_found(view_id: u64, address: u64, name: impl Into<String>) -> FunctionFoundPayload {
    FunctionFoundPayload {
        view_id,
        address,
        name: name.into(),
        size: None,
        from_symbol: false,
        basic_block_count: 0,
        calling_convention: None,
        tags: Vec::new(),
    }
}

/// Build an [`ErrorOccurredPayload`] with minimal required fields.
#[must_use]
pub fn make_error(
    view_id: Option<u64>,
    code: impl Into<String>,
    message: impl Into<String>,
    component: impl Into<String>,
) -> ErrorOccurredPayload {
    ErrorOccurredPayload {
        view_id,
        code: code.into(),
        message: message.into(),
        backtrace: None,
        recoverable: true,
        component: component.into(),
        timestamp: SystemTime::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_payload(seq: u64, view_id: Option<u64>) -> EventPayload {
        let inner = if let Some(vid) = view_id {
            AnalysisEvent::FunctionFound(make_function_found(vid, 0x1000, "test_fn"))
        } else {
            AnalysisEvent::PluginStarted(PluginStartedPayload {
                plugin_id: "p1".into(),
                plugin_name: "Plugin One".into(),
                version: "1.0.0".into(),
                capabilities: vec!["decompile".into()],
                started_at: SystemTime::now(),
            })
        };
        EventPayload::with_default_priority(inner, seq)
    }

    #[test]
    fn event_variant_names_are_correct() {
        let e = AnalysisEvent::FileOpened(make_file_opened(1, "/bin/ls", "x86_64"));
        assert_eq!(e.variant_name(), "FileOpened");

        let e2 = AnalysisEvent::ErrorOccurred(make_error(None, "E01", "oops", "loader"));
        assert_eq!(e2.variant_name(), "ErrorOccurred");
    }

    #[test]
    fn event_view_id_extraction() {
        let e = AnalysisEvent::FunctionFound(make_function_found(42, 0x100, "main"));
        assert_eq!(e.view_id(), Some(42));

        let e2 = AnalysisEvent::PluginStarted(PluginStartedPayload {
            plugin_id: "x".into(),
            plugin_name: "x".into(),
            version: "1".into(),
            capabilities: vec![],
            started_at: SystemTime::now(),
        });
        assert_eq!(e2.view_id(), None);
    }

    #[test]
    fn event_priority_ordering() {
        assert!(EventPriority::Critical > EventPriority::High);
        assert!(EventPriority::High > EventPriority::Normal);
        assert!(EventPriority::Normal > EventPriority::Low);
    }

    #[test]
    fn event_default_priority_critical_for_unrecoverable_error() {
        let err = make_error(None, "FATAL", "fatal error", "core");
        let mut err_unrecoverable = err;
        err_unrecoverable.recoverable = false;
        let e = AnalysisEvent::ErrorOccurred(err_unrecoverable);
        assert_eq!(e.default_priority(), EventPriority::Critical);
    }

    #[test]
    fn event_default_priority_low_for_progress() {
        let e = AnalysisEvent::ProgressUpdate(ProgressUpdatePayload {
            view_id: 1,
            task_name: "cfg".into(),
            percent: 50,
            items_done: 50,
            items_total: 100,
            eta_secs: None,
            message: "half done".into(),
        });
        assert_eq!(e.default_priority(), EventPriority::Low);
    }

    #[test]
    fn event_payload_with_default_priority() {
        let p = dummy_payload(1, Some(5));
        assert_eq!(p.sequence, 1);
        assert_eq!(p.view_id(), Some(5));
        assert_eq!(p.variant_name(), "FunctionFound");
    }

    #[test]
    fn event_payload_age_is_small() {
        let p = dummy_payload(0, None);
        assert!(p.age_ms() < 1000);
    }

    #[test]
    fn filter_for_view_accepts_matching() {
        let p = dummy_payload(1, Some(7));
        let f = AnalysisEventFilter::for_view(7);
        assert!(f.matches(&p));
    }

    #[test]
    fn filter_for_view_rejects_non_matching() {
        let p = dummy_payload(1, Some(9));
        let f = AnalysisEventFilter::for_view(7);
        assert!(!f.matches(&p));
    }

    #[test]
    fn filter_min_priority() {
        let mut p = dummy_payload(1, None);
        p.priority = EventPriority::Low;
        let f = AnalysisEventFilter::min_priority(EventPriority::High);
        assert!(!f.matches(&p));
        p.priority = EventPriority::High;
        assert!(f.matches(&p));
    }

    #[test]
    fn filter_and_composition() {
        let p = dummy_payload(1, Some(3));
        let f = AnalysisEventFilter::for_view(3).and(AnalysisEventFilter::discovery_only());
        assert!(f.matches(&p)); // FunctionFound is a discovery event for view 3
    }

    #[test]
    fn filter_not() {
        let p = dummy_payload(1, Some(3));
        let f = AnalysisEventFilter::for_view(3).negate();
        assert!(!f.matches(&p));
    }

    #[test]
    fn batch_push_and_drain() {
        let mut batch = EventBatch::new();
        batch.push(dummy_payload(1, Some(1)));
        batch.push(dummy_payload(2, Some(1)));
        assert_eq!(batch.len(), 2);
        let drained = batch.drain();
        assert_eq!(drained.len(), 2);
        assert!(batch.is_empty());
    }

    #[test]
    fn batch_max_priority_tracked() {
        let mut batch = EventBatch::new();
        let mut p1 = dummy_payload(1, Some(1));
        p1.priority = EventPriority::Low;
        let mut p2 = dummy_payload(2, Some(1));
        p2.priority = EventPriority::High;
        batch.push(p1);
        batch.push(p2);
        assert_eq!(batch.max_priority, Some(EventPriority::High));
    }

    #[test]
    fn batch_group_by_variant() {
        let mut batch = EventBatch::new();
        batch.push(dummy_payload(1, Some(1)));
        batch.push(dummy_payload(2, Some(2)));
        let groups = batch.group_by_variant();
        assert!(groups.contains_key("FunctionFound"));
        assert_eq!(groups["FunctionFound"].len(), 2);
    }

    #[test]
    fn batch_count_by_view() {
        let mut batch = EventBatch::new();
        batch.push(dummy_payload(1, Some(1)));
        batch.push(dummy_payload(2, Some(1)));
        batch.push(dummy_payload(3, Some(2)));
        let counts = batch.count_by_view();
        assert_eq!(counts[&1], 2);
        assert_eq!(counts[&2], 1);
    }

    #[test]
    fn analysis_stats_default_is_zeroed() {
        let s = AnalysisStats::default();
        assert_eq!(s.functions_found, 0);
        assert_eq!(s.bytes_analyzed, 0);
    }

    #[test]
    fn is_discovery_event_true_for_function_found() {
        let e = AnalysisEvent::FunctionFound(make_function_found(1, 0, "f"));
        assert!(e.is_discovery_event());
    }

    #[test]
    fn is_discovery_event_false_for_progress() {
        let e = AnalysisEvent::ProgressUpdate(ProgressUpdatePayload {
            view_id: 1,
            task_name: "x".into(),
            percent: 0,
            items_done: 0,
            items_total: 0,
            eta_secs: None,
            message: String::new(),
        });
        assert!(!e.is_discovery_event());
    }
}
