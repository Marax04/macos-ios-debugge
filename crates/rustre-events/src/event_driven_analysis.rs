//! `event_driven_analysis` — Drive analysis from event streams.
//!
//! Provides:
//! * [`EventDrivenAnalysis`] — top-level driver that wires events to handlers
//! * [`AnalysisEvent`]       — typed event that can trigger analysis actions
//! * [`EventTrigger`]        — predicate that matches incoming events
//! * [`EventHandler`]        — callback-style handler invoked on trigger match
//! * [`AnalysisPipeline`]    — ordered sequence of (trigger, handler) pairs
//! * [`EventLog`]            — append-only log of all processed events

use std::collections::{HashMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

pub use std::sync::Arc;

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AnalysisError {
    HandlerNotFound(String),
    TriggerError(String),
    PipelineEmpty,
    Custom(String),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandlerNotFound(s) => write!(f, "handler not found: {s}"),
            Self::TriggerError(s) => write!(f, "trigger error: {s}"),
            Self::PipelineEmpty => write!(f, "pipeline has no stages"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

// ─── AnalysisEventKind ───────────────────────────────────────────────────────

/// Kind of analysis event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalysisEventKind {
    FunctionEntered,
    FunctionExited,
    MemoryRead,
    MemoryWrite,
    ExceptionRaised,
    SyscallInvoked,
    ModuleLoaded,
    ModuleUnloaded,
    ThreadStarted,
    ThreadStopped,
    BreakpointHit,
    TaintPropagated,
    VulnerabilityFound,
    TraceStart,
    TraceEnd,
    Custom(String),
}

impl fmt::Display for AnalysisEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FunctionEntered => write!(f, "FunctionEntered"),
            Self::FunctionExited => write!(f, "FunctionExited"),
            Self::MemoryRead => write!(f, "MemoryRead"),
            Self::MemoryWrite => write!(f, "MemoryWrite"),
            Self::ExceptionRaised => write!(f, "ExceptionRaised"),
            Self::SyscallInvoked => write!(f, "SyscallInvoked"),
            Self::ModuleLoaded => write!(f, "ModuleLoaded"),
            Self::ModuleUnloaded => write!(f, "ModuleUnloaded"),
            Self::ThreadStarted => write!(f, "ThreadStarted"),
            Self::ThreadStopped => write!(f, "ThreadStopped"),
            Self::BreakpointHit => write!(f, "BreakpointHit"),
            Self::TaintPropagated => write!(f, "TaintPropagated"),
            Self::VulnerabilityFound => write!(f, "VulnerabilityFound"),
            Self::TraceStart => write!(f, "TraceStart"),
            Self::TraceEnd => write!(f, "TraceEnd"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ─── AnalysisEvent ───────────────────────────────────────────────────────────

/// A typed event with payload and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEvent {
    pub id: u64,
    pub kind: AnalysisEventKind,
    pub address: Option<u64>,
    pub thread_id: Option<u32>,
    pub module: Option<String>,
    pub payload: HashMap<String, String>,
    pub timestamp_ns: u64,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    Debug,
    Info,
    Warning,
    Critical,
}

impl fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Critical => write!(f, "CRIT"),
        }
    }
}

impl AnalysisEvent {
    #[must_use] 
    pub fn new(id: u64, kind: AnalysisEventKind) -> Self {
        Self {
            id,
            kind,
            address: None,
            thread_id: None,
            module: None,
            payload: HashMap::new(),
            timestamp_ns: 0,
            severity: EventSeverity::Info,
        }
    }

    #[must_use] 
    pub const fn at(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use] 
    pub const fn on_thread(mut self, tid: u32) -> Self {
        self.thread_id = Some(tid);
        self
    }

    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    #[must_use]
    pub fn with_payload(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.payload.insert(key.into(), value.into());
        self
    }

    #[must_use] 
    pub const fn with_severity(mut self, sev: EventSeverity) -> Self {
        self.severity = sev;
        self
    }

    #[must_use] 
    pub const fn with_timestamp(mut self, ns: u64) -> Self {
        self.timestamp_ns = ns;
        self
    }

    pub fn get_payload(&self, key: &str) -> Option<&str> {
        self.payload.get(key).map(String::as_str)
    }
}

impl fmt::Display for AnalysisEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Event#{} [{}] {}", self.id, self.severity, self.kind)
    }
}

// ─── EventTrigger ────────────────────────────────────────────────────────────

/// A predicate that matches incoming analysis events.
#[derive(Debug, Clone)]
pub enum EventTrigger {
    /// Match any event.
    Any,
    /// Match a specific kind.
    Kind(AnalysisEventKind),
    /// Match events at a specific address.
    AtAddress(u64),
    /// Match events on a specific thread.
    OnThread(u32),
    /// Match events with severity at or above a threshold.
    MinSeverity(EventSeverity),
    /// Match events from a specific module.
    FromModule(String),
    /// Match events with a specific payload key.
    HasPayload(String),
    /// Match events with a specific payload key=value.
    PayloadEquals(String, String),
    /// Conjunction of two triggers.
    And(Box<Self>, Box<Self>),
    /// Disjunction of two triggers.
    Or(Box<Self>, Box<Self>),
    /// Negation of a trigger.
    Not(Box<Self>),
}

impl EventTrigger {
    pub fn matches(&self, event: &AnalysisEvent) -> bool {
        match self {
            Self::Any => true,
            Self::Kind(k) => &event.kind == k,
            Self::AtAddress(addr) => event.address == Some(*addr),
            Self::OnThread(tid) => event.thread_id == Some(*tid),
            Self::MinSeverity(sev) => event.severity >= *sev,
            Self::FromModule(m) => event.module.as_deref() == Some(m.as_str()),
            Self::HasPayload(key) => event.payload.contains_key(key.as_str()),
            Self::PayloadEquals(key, val) => {
                event.payload.get(key.as_str()).map(String::as_str) == Some(val.as_str())
            }
            Self::And(a, b) => a.matches(event) && b.matches(event),
            Self::Or(a, b) => a.matches(event) || b.matches(event),
            Self::Not(inner) => !inner.matches(event),
        }
    }

    #[must_use] 
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    #[must_use] 
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

    #[must_use] 
    pub fn negate(self) -> Self {
        Self::Not(Box::new(self))
    }
}

// ─── HandlerResult ───────────────────────────────────────────────────────────

/// What a handler returns after processing an event.
#[derive(Debug, Clone)]
pub enum HandlerResult {
    Continue,
    StopPipeline,
    EmitEvent(AnalysisEvent),
    RecordFinding(AnalysisFinding),
}

/// A finding produced by an analysis handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisFinding {
    pub title: String,
    pub description: String,
    pub severity: EventSeverity,
    pub address: Option<u64>,
    pub evidence: Vec<String>,
}

impl AnalysisFinding {
    pub fn new(title: impl Into<String>, severity: EventSeverity) -> Self {
        Self {
            title: title.into(),
            description: String::new(),
            severity,
            address: None,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    #[must_use]
    pub const fn at(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn add_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }
}

impl fmt::Display for AnalysisFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Finding [{}]: {}", self.severity, self.title)
    }
}

// ─── EventHandler ────────────────────────────────────────────────────────────

/// A named handler that processes matching events.
pub struct EventHandler {
    pub name: String,
    pub invoke_count: u64,
    handler_fn: Box<dyn Fn(&AnalysisEvent) -> HandlerResult + Send + Sync>,
}

impl EventHandler {
    pub fn new(
        name: impl Into<String>,
        f: impl Fn(&AnalysisEvent) -> HandlerResult + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            invoke_count: 0,
            handler_fn: Box::new(f),
        }
    }

    pub fn invoke(&mut self, event: &AnalysisEvent) -> HandlerResult {
        self.invoke_count += 1;
        (self.handler_fn)(event)
    }
}

impl fmt::Debug for EventHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventHandler({})", self.name)
    }
}

impl fmt::Display for EventHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventHandler({}, invoked={})",
            self.name, self.invoke_count
        )
    }
}

// ─── EventLog ────────────────────────────────────────────────────────────────

/// Append-only log of processed events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EventLog {
    pub events: Vec<AnalysisEvent>,
    pub max_size: Option<usize>,
}

impl EventLog {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_max_size(mut self, n: usize) -> Self {
        self.max_size = Some(n);
        self
    }

    pub fn append(&mut self, event: AnalysisEvent) {
        if let Some(max) = self.max_size
            && self.events.len() >= max {
                self.events.remove(0);
            }
        self.events.push(event);
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[must_use] 
    pub fn events_of_kind(&self, kind: &AnalysisEventKind) -> Vec<&AnalysisEvent> {
        self.events.iter().filter(|e| &e.kind == kind).collect()
    }

    #[must_use] 
    pub fn events_at_address(&self, addr: u64) -> Vec<&AnalysisEvent> {
        self.events
            .iter()
            .filter(|e| e.address == Some(addr))
            .collect()
    }

    #[must_use] 
    pub fn events_on_thread(&self, tid: u32) -> Vec<&AnalysisEvent> {
        self.events
            .iter()
            .filter(|e| e.thread_id == Some(tid))
            .collect()
    }

    #[must_use] 
    pub fn critical_events(&self) -> Vec<&AnalysisEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == EventSeverity::Critical)
            .collect()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }

    #[must_use] 
    pub fn last(&self) -> Option<&AnalysisEvent> {
        self.events.last()
    }
}

impl fmt::Display for EventLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventLog {{ count={} }}", self.events.len())
    }
}

// ─── PipelineStage ───────────────────────────────────────────────────────────

/// A single stage in the analysis pipeline (trigger + handler).
pub struct PipelineStage {
    pub id: usize,
    pub trigger: EventTrigger,
    pub handler: EventHandler,
    pub matches_count: u64,
}

impl PipelineStage {
    #[must_use] 
    pub const fn new(id: usize, trigger: EventTrigger, handler: EventHandler) -> Self {
        Self {
            id,
            trigger,
            handler,
            matches_count: 0,
        }
    }

    pub fn process(&mut self, event: &AnalysisEvent) -> Option<HandlerResult> {
        if self.trigger.matches(event) {
            self.matches_count += 1;
            Some(self.handler.invoke(event))
        } else {
            None
        }
    }
}

impl fmt::Debug for PipelineStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PipelineStage(id={})", self.id)
    }
}

// ─── AnalysisPipeline ────────────────────────────────────────────────────────

/// Ordered sequence of (trigger, handler) pipeline stages.
pub struct AnalysisPipeline {
    pub stages: Vec<PipelineStage>,
    pub findings: Vec<AnalysisFinding>,
    pub stop_on_critical: bool,
    next_stage_id: usize,
}

impl AnalysisPipeline {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            stages: Vec::new(),
            findings: Vec::new(),
            stop_on_critical: false,
            next_stage_id: 0,
        }
    }

    #[must_use] 
    pub const fn with_stop_on_critical(mut self) -> Self {
        self.stop_on_critical = true;
        self
    }

    pub fn add_stage(&mut self, trigger: EventTrigger, handler: EventHandler) -> usize {
        let id = self.next_stage_id;
        self.next_stage_id += 1;
        self.stages.push(PipelineStage::new(id, trigger, handler));
        id
    }

    #[must_use] 
    pub const fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Process one event through all pipeline stages.
    pub fn process(&mut self, event: &AnalysisEvent) -> Vec<AnalysisEvent> {
        let mut emitted = Vec::new();
        for stage in &mut self.stages {
            if let Some(result) = stage.process(event) {
                match result {
                    HandlerResult::Continue => {}
                    HandlerResult::StopPipeline => break,
                    HandlerResult::EmitEvent(ev) => emitted.push(ev),
                    HandlerResult::RecordFinding(f) => {
                        let is_critical = f.severity == EventSeverity::Critical;
                        self.findings.push(f);
                        if is_critical && self.stop_on_critical {
                            break;
                        }
                    }
                }
            }
        }
        emitted
    }

    #[must_use] 
    pub fn critical_findings(&self) -> Vec<&AnalysisFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == EventSeverity::Critical)
            .collect()
    }

    #[must_use] 
    pub const fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl Default for AnalysisPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ─── EventDrivenAnalysis ─────────────────────────────────────────────────────

/// Statistics for the event-driven analysis session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub events_processed: u64,
    pub events_matched: u64,
    pub findings_generated: u64,
    pub emitted_events: u64,
}

/// The top-level event-driven analysis driver.
pub struct EventDrivenAnalysis {
    pub pipeline: AnalysisPipeline,
    pub log: EventLog,
    pub stats: AnalysisStats,
    event_queue: VecDeque<AnalysisEvent>,
    next_event_id: u64,
}

impl EventDrivenAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            pipeline: AnalysisPipeline::new(),
            log: EventLog::new(),
            stats: AnalysisStats::default(),
            event_queue: VecDeque::new(),
            next_event_id: 0,
        }
    }

    #[must_use] 
    pub fn with_log_max_size(mut self, n: usize) -> Self {
        self.log = EventLog::new().with_max_size(n);
        self
    }

    /// Create a new event and push it to the queue.
    pub fn enqueue_event(&mut self, kind: AnalysisEventKind) -> u64 {
        let id = self.next_event_id;
        self.next_event_id += 1;
        let event = AnalysisEvent::new(id, kind);
        self.event_queue.push_back(event);
        id
    }

    /// Push a pre-built event into the queue.
    pub fn push_event(&mut self, mut event: AnalysisEvent) {
        event.id = self.next_event_id;
        self.next_event_id += 1;
        self.event_queue.push_back(event);
    }

    /// Add a pipeline stage.
    pub fn add_stage(&mut self, trigger: EventTrigger, handler: EventHandler) -> usize {
        self.pipeline.add_stage(trigger, handler)
    }

    /// Drain the event queue, processing all pending events.
    ///
    /// # Errors
    /// Returns `AnalysisError` if any stage handler fails.
    pub fn flush(&mut self) -> Result<(), AnalysisError> {
        if self.pipeline.stage_count() == 0 {
            return Err(AnalysisError::PipelineEmpty);
        }

        while let Some(event) = self.event_queue.pop_front() {
            self.log.append(event.clone());
            self.stats.events_processed += 1;

            let emitted = self.pipeline.process(&event);
            self.stats.emitted_events += emitted.len() as u64;

            // Re-enqueue emitted events (front, so they are processed first)
            for ev in emitted.into_iter().rev() {
                self.event_queue.push_front(ev);
            }
        }

        self.stats.findings_generated = self.pipeline.findings_count() as u64;
        Ok(())
    }

    /// Process a single event immediately (bypassing the queue).
    pub fn process_now(&mut self, event: &AnalysisEvent) -> Vec<HandlerResult> {
        self.log.append(event.clone());
        self.stats.events_processed += 1;
        let emitted = self.pipeline.process(event);
        self.stats.emitted_events += emitted.len() as u64;
        emitted.into_iter().map(HandlerResult::EmitEvent).collect()
    }

    #[must_use] 
    pub fn findings(&self) -> &[AnalysisFinding] {
        &self.pipeline.findings
    }

    #[must_use] 
    pub fn critical_findings(&self) -> Vec<&AnalysisFinding> {
        self.pipeline.critical_findings()
    }
}

impl Default for EventDrivenAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: u64, kind: AnalysisEventKind) -> AnalysisEvent {
        AnalysisEvent::new(id, kind)
    }

    fn counter_handler(name: &str) -> EventHandler {
        let count = std::sync::Arc::new(std::sync::Mutex::new(0u64));
        EventHandler::new(name, move |_ev| {
            *count.lock().unwrap() += 1;
            HandlerResult::Continue
        })
    }

    // ── AnalysisEvent ────────────────────────────────────────────────────────

    #[test]
    fn test_event_creation() {
        let ev = AnalysisEvent::new(1, AnalysisEventKind::FunctionEntered);
        assert_eq!(ev.id, 1);
        assert_eq!(ev.kind, AnalysisEventKind::FunctionEntered);
    }

    #[test]
    fn test_event_at() {
        let ev = AnalysisEvent::new(0, AnalysisEventKind::BreakpointHit).at(0x1000);
        assert_eq!(ev.address, Some(0x1000));
    }

    #[test]
    fn test_event_on_thread() {
        let ev = AnalysisEvent::new(0, AnalysisEventKind::ThreadStarted).on_thread(3);
        assert_eq!(ev.thread_id, Some(3));
    }

    #[test]
    fn test_event_payload() {
        let ev = AnalysisEvent::new(0, AnalysisEventKind::VulnerabilityFound)
            .with_payload("type", "buffer_overflow");
        assert_eq!(ev.get_payload("type"), Some("buffer_overflow"));
        assert_eq!(ev.get_payload("missing"), None);
    }

    #[test]
    fn test_event_severity() {
        let ev = AnalysisEvent::new(0, AnalysisEventKind::ExceptionRaised)
            .with_severity(EventSeverity::Critical);
        assert_eq!(ev.severity, EventSeverity::Critical);
    }

    // ── EventTrigger ─────────────────────────────────────────────────────────

    #[test]
    fn test_trigger_any() {
        let ev = make_event(0, AnalysisEventKind::TraceStart);
        assert!(EventTrigger::Any.matches(&ev));
    }

    #[test]
    fn test_trigger_kind_match() {
        let ev = make_event(0, AnalysisEventKind::MemoryWrite);
        assert!(EventTrigger::Kind(AnalysisEventKind::MemoryWrite).matches(&ev));
    }

    #[test]
    fn test_trigger_kind_no_match() {
        let ev = make_event(0, AnalysisEventKind::MemoryRead);
        assert!(!EventTrigger::Kind(AnalysisEventKind::MemoryWrite).matches(&ev));
    }

    #[test]
    fn test_trigger_at_address() {
        let ev = make_event(0, AnalysisEventKind::BreakpointHit).at(0x5000);
        assert!(EventTrigger::AtAddress(0x5000).matches(&ev));
        assert!(!EventTrigger::AtAddress(0x9999).matches(&ev));
    }

    #[test]
    fn test_trigger_on_thread() {
        let ev = make_event(0, AnalysisEventKind::ThreadStarted).on_thread(2);
        assert!(EventTrigger::OnThread(2).matches(&ev));
        assert!(!EventTrigger::OnThread(3).matches(&ev));
    }

    #[test]
    fn test_trigger_min_severity() {
        let ev = make_event(0, AnalysisEventKind::VulnerabilityFound)
            .with_severity(EventSeverity::Warning);
        assert!(EventTrigger::MinSeverity(EventSeverity::Info).matches(&ev));
        assert!(!EventTrigger::MinSeverity(EventSeverity::Critical).matches(&ev));
    }

    #[test]
    fn test_trigger_from_module() {
        let ev = make_event(0, AnalysisEventKind::ModuleLoaded).with_module("ntdll.dll");
        assert!(EventTrigger::FromModule("ntdll.dll".into()).matches(&ev));
        assert!(!EventTrigger::FromModule("kernel32.dll".into()).matches(&ev));
    }

    #[test]
    fn test_trigger_and() {
        let ev = make_event(0, AnalysisEventKind::MemoryWrite)
            .on_thread(1)
            .at(0x1000);
        let t = EventTrigger::Kind(AnalysisEventKind::MemoryWrite).and(EventTrigger::OnThread(1));
        assert!(t.matches(&ev));
    }

    #[test]
    fn test_trigger_or() {
        let ev = make_event(0, AnalysisEventKind::MemoryRead);
        let t = EventTrigger::Kind(AnalysisEventKind::MemoryWrite)
            .or(EventTrigger::Kind(AnalysisEventKind::MemoryRead));
        assert!(t.matches(&ev));
    }

    #[test]
    fn test_trigger_not() {
        let ev = make_event(0, AnalysisEventKind::MemoryRead);
        let t = EventTrigger::Not(Box::new(EventTrigger::Kind(AnalysisEventKind::MemoryWrite)));
        assert!(t.matches(&ev));
    }

    #[test]
    fn test_trigger_payload_equals() {
        let ev = make_event(0, AnalysisEventKind::Custom("x".into())).with_payload("key", "value");
        assert!(EventTrigger::PayloadEquals("key".into(), "value".into()).matches(&ev));
        assert!(!EventTrigger::PayloadEquals("key".into(), "other".into()).matches(&ev));
    }

    // ── EventLog ─────────────────────────────────────────────────────────────

    #[test]
    fn test_log_append() {
        let mut log = EventLog::new();
        log.append(make_event(0, AnalysisEventKind::TraceStart));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_log_max_size() {
        let mut log = EventLog::new().with_max_size(2);
        for i in 0..5 {
            log.append(make_event(i, AnalysisEventKind::TraceStart));
        }
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn test_log_events_of_kind() {
        let mut log = EventLog::new();
        log.append(make_event(0, AnalysisEventKind::MemoryRead));
        log.append(make_event(1, AnalysisEventKind::MemoryWrite));
        log.append(make_event(2, AnalysisEventKind::MemoryRead));
        assert_eq!(log.events_of_kind(&AnalysisEventKind::MemoryRead).len(), 2);
    }

    #[test]
    fn test_log_critical_events() {
        let mut log = EventLog::new();
        log.append(
            make_event(0, AnalysisEventKind::ExceptionRaised)
                .with_severity(EventSeverity::Critical),
        );
        log.append(make_event(1, AnalysisEventKind::TraceStart));
        assert_eq!(log.critical_events().len(), 1);
    }

    #[test]
    fn test_log_clear() {
        let mut log = EventLog::new();
        log.append(make_event(0, AnalysisEventKind::TraceStart));
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_log_last() {
        let mut log = EventLog::new();
        log.append(make_event(0, AnalysisEventKind::TraceStart));
        log.append(make_event(1, AnalysisEventKind::TraceEnd));
        assert_eq!(log.last().unwrap().id, 1);
    }

    // ── AnalysisPipeline ─────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_add_stage() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.add_stage(EventTrigger::Any, counter_handler("h"));
        assert_eq!(pipeline.stage_count(), 1);
    }

    #[test]
    fn test_pipeline_process_matches() {
        let mut pipeline = AnalysisPipeline::new();
        let invoked = std::sync::Arc::new(std::sync::Mutex::new(false));
        let inv_clone = invoked.clone();
        pipeline.add_stage(
            EventTrigger::Kind(AnalysisEventKind::MemoryWrite),
            EventHandler::new("h", move |_| {
                *inv_clone.lock().unwrap() = true;
                HandlerResult::Continue
            }),
        );
        pipeline.process(&make_event(0, AnalysisEventKind::MemoryWrite));
        assert!(*invoked.lock().unwrap());
    }

    #[test]
    fn test_pipeline_no_match() {
        let mut pipeline = AnalysisPipeline::new();
        let invoked = std::sync::Arc::new(std::sync::Mutex::new(false));
        let inv_clone = invoked.clone();
        pipeline.add_stage(
            EventTrigger::Kind(AnalysisEventKind::MemoryWrite),
            EventHandler::new("h", move |_| {
                *inv_clone.lock().unwrap() = true;
                HandlerResult::Continue
            }),
        );
        pipeline.process(&make_event(0, AnalysisEventKind::MemoryRead));
        assert!(!*invoked.lock().unwrap());
    }

    #[test]
    fn test_pipeline_finding() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.add_stage(
            EventTrigger::Any,
            EventHandler::new("h", |_| {
                HandlerResult::RecordFinding(AnalysisFinding::new("bug", EventSeverity::Critical))
            }),
        );
        pipeline.process(&make_event(0, AnalysisEventKind::ExceptionRaised));
        assert_eq!(pipeline.findings_count(), 1);
    }

    #[test]
    fn test_pipeline_stop_pipeline() {
        let mut pipeline = AnalysisPipeline::new();
        let count = std::sync::Arc::new(std::sync::Mutex::new(0u32));
        let c2 = count.clone();
        let c3 = count.clone();
        pipeline.add_stage(
            EventTrigger::Any,
            EventHandler::new("stop", move |_| {
                *c2.lock().unwrap() += 1;
                HandlerResult::StopPipeline
            }),
        );
        pipeline.add_stage(
            EventTrigger::Any,
            EventHandler::new("never", move |_| {
                *c3.lock().unwrap() += 10;
                HandlerResult::Continue
            }),
        );
        pipeline.process(&make_event(0, AnalysisEventKind::TraceStart));
        assert_eq!(*count.lock().unwrap(), 1); // second stage not reached
    }

    // ── EventDrivenAnalysis ──────────────────────────────────────────────────

    #[test]
    fn test_eda_flush_empty_pipeline_error() {
        let mut eda = EventDrivenAnalysis::new();
        eda.enqueue_event(AnalysisEventKind::TraceStart);
        assert!(matches!(eda.flush(), Err(AnalysisError::PipelineEmpty)));
    }

    #[test]
    fn test_eda_flush_processes_events() {
        let mut eda = EventDrivenAnalysis::new();
        eda.add_stage(EventTrigger::Any, counter_handler("h"));
        eda.enqueue_event(AnalysisEventKind::TraceStart);
        eda.enqueue_event(AnalysisEventKind::TraceEnd);
        eda.flush().unwrap();
        assert_eq!(eda.stats.events_processed, 2);
    }

    #[test]
    fn test_eda_log_filled_on_flush() {
        let mut eda = EventDrivenAnalysis::new();
        eda.add_stage(EventTrigger::Any, counter_handler("h"));
        eda.enqueue_event(AnalysisEventKind::TraceStart);
        eda.flush().unwrap();
        assert_eq!(eda.log.len(), 1);
    }

    #[test]
    fn test_eda_process_now() {
        let mut eda = EventDrivenAnalysis::new();
        eda.add_stage(EventTrigger::Any, counter_handler("h"));
        eda.process_now(&make_event(0, AnalysisEventKind::TraceStart));
        assert_eq!(eda.stats.events_processed, 1);
    }

    #[test]
    fn test_eda_findings_after_flush() {
        let mut eda = EventDrivenAnalysis::new();
        eda.add_stage(
            EventTrigger::Kind(AnalysisEventKind::ExceptionRaised),
            EventHandler::new("vuln", |ev| {
                HandlerResult::RecordFinding(
                    AnalysisFinding::new("exception", EventSeverity::Critical)
                        .at(ev.address.unwrap_or(0)),
                )
            }),
        );
        eda.push_event(AnalysisEvent::new(0, AnalysisEventKind::ExceptionRaised).at(0xDEAD));
        eda.flush().unwrap();
        assert!(!eda.critical_findings().is_empty());
    }

    #[test]
    fn test_eda_event_id_auto_assigned() {
        let mut eda = EventDrivenAnalysis::new();
        let id1 = eda.enqueue_event(AnalysisEventKind::TraceStart);
        let id2 = eda.enqueue_event(AnalysisEventKind::TraceEnd);
        assert!(id2 > id1);
    }

    #[test]
    fn test_analysis_finding_creation() {
        let f = AnalysisFinding::new("overflow", EventSeverity::Critical)
            .with_description("buffer overflow")
            .at(0x1234)
            .add_evidence("rsp = 0x0");
        assert_eq!(f.address, Some(0x1234));
        assert!(!f.evidence.is_empty());
    }

    #[test]
    fn test_event_severity_ordering() {
        assert!(EventSeverity::Critical > EventSeverity::Warning);
        assert!(EventSeverity::Warning > EventSeverity::Info);
        assert!(EventSeverity::Info > EventSeverity::Debug);
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(format!("{}", AnalysisEventKind::MemoryWrite), "MemoryWrite");
        assert_eq!(format!("{}", AnalysisEventKind::TraceStart), "TraceStart");
    }

    #[test]
    fn test_event_severity_display() {
        assert_eq!(format!("{}", EventSeverity::Critical), "CRIT");
        assert_eq!(format!("{}", EventSeverity::Debug), "DEBUG");
    }

    #[test]
    fn test_event_display() {
        let ev = AnalysisEvent::new(7, AnalysisEventKind::BreakpointHit)
            .with_severity(EventSeverity::Warning);
        let s = format!("{ev}");
        assert!(s.contains('7'));
        assert!(s.contains("WARN"));
    }

    #[test]
    fn test_log_events_at_address() {
        let mut log = EventLog::new();
        log.append(make_event(0, AnalysisEventKind::BreakpointHit).at(0x1234));
        log.append(make_event(1, AnalysisEventKind::BreakpointHit).at(0x5678));
        assert_eq!(log.events_at_address(0x1234).len(), 1);
    }

    #[test]
    fn test_log_events_on_thread() {
        let mut log = EventLog::new();
        log.append(make_event(0, AnalysisEventKind::ThreadStarted).on_thread(3));
        log.append(make_event(1, AnalysisEventKind::ThreadStarted).on_thread(4));
        assert_eq!(log.events_on_thread(3).len(), 1);
        assert_eq!(log.events_on_thread(4).len(), 1);
        assert_eq!(log.events_on_thread(9).len(), 0);
    }

    #[test]
    fn test_pipeline_emit_event() {
        let mut pipeline = AnalysisPipeline::new();
        pipeline.add_stage(
            EventTrigger::Any,
            EventHandler::new("emitter", |_ev| {
                HandlerResult::EmitEvent(AnalysisEvent::new(
                    999,
                    AnalysisEventKind::Custom("derived".into()),
                ))
            }),
        );
        let emitted = pipeline.process(&make_event(0, AnalysisEventKind::TraceStart));
        assert_eq!(emitted.len(), 1);
    }

    #[test]
    fn test_pipeline_stage_count_after_add() {
        let mut pipeline = AnalysisPipeline::new();
        assert_eq!(pipeline.stage_count(), 0);
        pipeline.add_stage(EventTrigger::Any, counter_handler("h1"));
        pipeline.add_stage(EventTrigger::Any, counter_handler("h2"));
        assert_eq!(pipeline.stage_count(), 2);
    }

    #[test]
    fn test_eda_with_log_max_size() {
        let mut eda = EventDrivenAnalysis::new().with_log_max_size(2);
        eda.add_stage(EventTrigger::Any, counter_handler("h"));
        for kind in [
            AnalysisEventKind::TraceStart,
            AnalysisEventKind::MemoryRead,
            AnalysisEventKind::MemoryWrite,
        ] {
            eda.enqueue_event(kind);
        }
        eda.flush().unwrap();
        assert!(eda.log.len() <= 2);
    }

    #[test]
    fn test_trigger_has_payload() {
        let ev =
            make_event(0, AnalysisEventKind::Custom("x".into())).with_payload("vuln_type", "rop");
        assert!(EventTrigger::HasPayload("vuln_type".into()).matches(&ev));
        assert!(!EventTrigger::HasPayload("other_key".into()).matches(&ev));
    }

    #[test]
    fn test_pipeline_critical_findings_empty_by_default() {
        let pipeline = AnalysisPipeline::new();
        assert!(pipeline.critical_findings().is_empty());
    }

    #[test]
    fn test_eda_stats_findings_count() {
        let mut eda = EventDrivenAnalysis::new();
        eda.add_stage(
            EventTrigger::Any,
            EventHandler::new("h", |_| {
                HandlerResult::RecordFinding(AnalysisFinding::new("f", EventSeverity::Info))
            }),
        );
        eda.enqueue_event(AnalysisEventKind::TraceStart);
        eda.flush().unwrap();
        assert_eq!(eda.stats.findings_generated, 1);
    }
}
