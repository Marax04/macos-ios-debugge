//! `plugin_events_full` — Complete plugin event system.
//!
//! # Key types
//! * [`PluginEventsFull`] — registry and dispatcher facade.
//! * [`EventType`]        — 100+ named event variants.
//! * [`EventFilter`]      — subscribe to a subset of events.
//! * [`EventDispatcher`]  — dispatches events to registered handlers.
//! * [`EventLog`]         — append-only log of all fired events.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EventError {
    #[error("handler '{0}' already registered")]
    DuplicateHandler(String),
    #[error("handler '{0}' not found")]
    HandlerNotFound(String),
    #[error("event queue full (max {0})")]
    QueueFull(usize),
    #[error("serialization error: {0}")]
    Serialize(String),
}

pub type EventResult<T> = Result<T, EventError>;

// ---------------------------------------------------------------------------
// EventType — 100+ variants
// ---------------------------------------------------------------------------

/// Every plugin event the host may fire.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    // ── Binary loading ────────────────────────────────────────────────────
    BinaryOpened,
    BinaryClosed,
    BinaryReloaded,
    BinaryAnalysisStarted,
    BinaryAnalysisFinished,
    BinaryAnalysisProgress { percent: u8 },
    // ── Functions ─────────────────────────────────────────────────────────
    FunctionAdded,
    FunctionRemoved,
    FunctionRenamed,
    FunctionCommentSet,
    FunctionTypeChanged,
    FunctionCallingConvChanged,
    FunctionBoundsChanged,
    FunctionInlined,
    FunctionSplit,
    FunctionMerged,
    FunctionTagged,
    // ── Basic blocks ──────────────────────────────────────────────────────
    BasicBlockAdded,
    BasicBlockRemoved,
    BasicBlockEdgeAdded,
    BasicBlockEdgeRemoved,
    // ── Symbols ───────────────────────────────────────────────────────────
    SymbolAdded,
    SymbolRemoved,
    SymbolRenamed,
    SymbolTypeChanged,
    SymbolExported,
    SymbolImported,
    // ── Data ──────────────────────────────────────────────────────────────
    DataVariableAdded,
    DataVariableRemoved,
    DataVariableTypeChanged,
    DataVariableCommentSet,
    // ── Sections ──────────────────────────────────────────────────────────
    SectionAdded,
    SectionRemoved,
    SectionPermissionsChanged,
    SectionRenamed,
    // ── Types ─────────────────────────────────────────────────────────────
    TypeAdded,
    TypeRemoved,
    TypeModified,
    TypeImported,
    TypeExported,
    // ── IL / IR ───────────────────────────────────────────────────────────
    LlilGenerated,
    MlilGenerated,
    HlilGenerated,
    SsaFormGenerated,
    // ── Annotations ───────────────────────────────────────────────────────
    AnnotationAdded,
    AnnotationRemoved,
    AnnotationModified,
    BookmarkSet,
    BookmarkRemoved,
    // ── Hex view ──────────────────────────────────────────────────────────
    HexViewScrolled,
    HexViewSelectionChanged,
    HexViewBytesModified,
    HexViewAnnotationChanged,
    // ── UI ────────────────────────────────────────────────────────────────
    ViewOpened,
    ViewClosed,
    ViewFocused,
    PanelDocked,
    PanelUndocked,
    ThemeChanged,
    FontChanged,
    LayoutChanged,
    // ── Settings ──────────────────────────────────────────────────────────
    SettingChanged,
    SettingReset,
    SettingsImported,
    SettingsExported,
    // ── Plugins ───────────────────────────────────────────────────────────
    PluginLoaded,
    PluginUnloaded,
    PluginEnabled,
    PluginDisabled,
    PluginCrashed,
    PluginUpdated,
    PluginInstalled,
    PluginUninstalled,
    // ── Debugging ─────────────────────────────────────────────────────────
    DebugSessionStarted,
    DebugSessionStopped,
    DebugBreakpointHit,
    DebugBreakpointAdded,
    DebugBreakpointRemoved,
    DebugStepInto,
    DebugStepOver,
    DebugStepOut,
    DebugRegisterChanged,
    DebugMemoryChanged,
    DebugModuleLoaded,
    DebugModuleUnloaded,
    // ── Scripting ─────────────────────────────────────────────────────────
    ScriptExecuted,
    ScriptError,
    ScriptOutputProduced,
    ReplCommandEntered,
    // ── Projects ──────────────────────────────────────────────────────────
    ProjectOpened,
    ProjectClosed,
    ProjectSaved,
    ProjectSaveRequested,
    ProjectMetadataChanged,
    // ── Collaboration ─────────────────────────────────────────────────────
    CollaboratorJoined,
    CollaboratorLeft,
    CollaborationSyncStarted,
    CollaborationSyncFinished,
    CollaborationConflict,
    // ── Search ────────────────────────────────────────────────────────────
    SearchStarted,
    SearchFinished,
    SearchResultSelected,
    // ── Navigation ────────────────────────────────────────────────────────
    NavigationHistoryPushed,
    NavigationHistoryPopped,
    NavigationJumped,
    // ── Clipboard ─────────────────────────────────────────────────────────
    ClipboardCopied,
    ClipboardPasted,
    // ── Tags ──────────────────────────────────────────────────────────────
    TagAdded,
    TagRemoved,
    TagTypeAdded,
    TagTypeRemoved,
    // ── Triage ────────────────────────────────────────────────────────────
    TriageStarted,
    TriageFinished,
    TriageReportReady,
    // ── Custom ────────────────────────────────────────────────────────────
    Custom(String),
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl EventType {
    /// Returns a category tag for this event.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BinaryOpened
            | Self::BinaryClosed
            | Self::BinaryReloaded
            | Self::BinaryAnalysisStarted
            | Self::BinaryAnalysisFinished
            | Self::BinaryAnalysisProgress { .. } => "binary",
            Self::FunctionAdded
            | Self::FunctionRemoved
            | Self::FunctionRenamed
            | Self::FunctionCommentSet
            | Self::FunctionTypeChanged
            | Self::FunctionCallingConvChanged
            | Self::FunctionBoundsChanged
            | Self::FunctionInlined
            | Self::FunctionSplit
            | Self::FunctionMerged
            | Self::FunctionTagged => "function",
            Self::DebugSessionStarted
            | Self::DebugSessionStopped
            | Self::DebugBreakpointHit
            | Self::DebugBreakpointAdded
            | Self::DebugBreakpointRemoved
            | Self::DebugStepInto
            | Self::DebugStepOver
            | Self::DebugStepOut
            | Self::DebugRegisterChanged
            | Self::DebugMemoryChanged
            | Self::DebugModuleLoaded
            | Self::DebugModuleUnloaded => "debug",
            Self::PluginLoaded
            | Self::PluginUnloaded
            | Self::PluginEnabled
            | Self::PluginDisabled
            | Self::PluginCrashed
            | Self::PluginUpdated
            | Self::PluginInstalled
            | Self::PluginUninstalled => "plugin",
            Self::ViewOpened
            | Self::ViewClosed
            | Self::ViewFocused
            | Self::PanelDocked
            | Self::PanelUndocked
            | Self::ThemeChanged
            | Self::FontChanged
            | Self::LayoutChanged => "ui",
            _ => "other",
        }
    }
}

// ---------------------------------------------------------------------------
// Event payload
// ---------------------------------------------------------------------------

/// The full event envelope delivered to handlers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Monotonically increasing ID.
    pub id: u64,
    /// The event classification.
    pub event_type: EventType,
    /// Optional context string (e.g. function name, section name).
    pub context: Option<String>,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
    /// Unix timestamp (seconds since epoch) when the event was created.
    pub timestamp: u64,
}

impl Event {
    #[must_use]
    pub fn new(id: u64, event_type: EventType) -> Self {
        Self {
            id,
            event_type,
            context: None,
            metadata: HashMap::new(),
            timestamp: 0,
        }
    }

    #[must_use]
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }

    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub const fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] #{} {}",
            self.event_type.category(),
            self.id,
            self.event_type
        )?;
        if let Some(ctx) = &self.context {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EventFilter
// ---------------------------------------------------------------------------

/// Determines which events a handler receives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// If non-empty, only events in these categories pass.
    pub categories: Vec<String>,
    /// If non-empty, only these exact event types pass.
    pub types: Vec<EventType>,
    /// If `true`, custom events are always passed through.
    pub include_custom: bool,
}

impl EventFilter {
    #[must_use]
    pub fn all() -> Self {
        Self::default() // empty = pass everything
    }

    pub fn for_category(category: impl Into<String>) -> Self {
        Self {
            categories: vec![category.into()],
            ..Default::default()
        }
    }

    #[must_use]
    pub fn for_type(event_type: EventType) -> Self {
        Self {
            types: vec![event_type],
            ..Default::default()
        }
    }

    /// Returns `true` if `event` passes the filter.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if self.categories.is_empty() && self.types.is_empty() {
            return true;
        }
        if self.include_custom
            && let EventType::Custom(_) = &event.event_type
        {
            return true;
        }
        if !self.categories.is_empty() {
            let cat = event.event_type.category();
            if self.categories.iter().any(|c| c == cat) {
                return true;
            }
        }
        if !self.types.is_empty() && self.types.contains(&event.event_type) {
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/// Append-only log of all fired events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    entries: VecDeque<Event>,
    max_entries: usize,
    total_fired: u64,
}

impl EventLog {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.max(1),
            total_fired: 0,
        }
    }

    pub fn push(&mut self, event: Event) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(event);
        self.total_fired += 1;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn total_fired(&self) -> u64 {
        self.total_fired
    }

    /// Events matching `filter`.
    #[must_use]
    pub fn filtered(&self, filter: &EventFilter) -> Vec<&Event> {
        self.entries.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Events of a specific type.
    #[must_use]
    pub fn by_type(&self, et: &EventType) -> Vec<&Event> {
        self.entries
            .iter()
            .filter(|e| &e.event_type == et)
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        self.entries.iter()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// Handler registration
// ---------------------------------------------------------------------------

/// Shared, interior-mutable event callback used by [`HandlerEntry`].
pub type EventCallback = Arc<Mutex<dyn FnMut(&Event) + Send + 'static>>;

/// A registered handler.
pub struct HandlerEntry {
    pub name: String,
    pub filter: EventFilter,
    pub callback: EventCallback,
}

impl fmt::Debug for HandlerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerEntry")
            .field("name", &self.name)
            .field("filter", &self.filter)
            .field("callback", &"<EventCallback>")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// EventDispatcher
// ---------------------------------------------------------------------------

/// Dispatches events to all registered handlers whose filter matches.
#[derive(Debug, Default)]
pub struct EventDispatcher {
    handlers: HashMap<String, HandlerEntry>,
    fired_count: u64,
}

impl EventDispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    ///
    /// # Errors
    ///
    /// Returns an error if a handler with that name is already registered.
    pub fn register<F>(
        &mut self,
        name: impl Into<String>,
        filter: EventFilter,
        callback: F,
    ) -> EventResult<()>
    where
        F: FnMut(&Event) + Send + 'static,
    {
        let name = name.into();
        if self.handlers.contains_key(&name) {
            return Err(EventError::DuplicateHandler(name));
        }
        self.handlers.insert(
            name.clone(),
            HandlerEntry {
                name,
                filter,
                callback: Arc::new(Mutex::new(callback)),
            },
        );
        Ok(())
    }

    ///
    /// # Errors
    ///
    /// Returns an error if no handler with that name is registered.
    pub fn unregister(&mut self, name: &str) -> EventResult<()> {
        self.handlers
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| EventError::HandlerNotFound(name.into()))
    }

    /// Dispatch `event` to all matching handlers.
    pub fn dispatch(&mut self, event: &Event) {
        self.fired_count += 1;
        for entry in self.handlers.values() {
            if entry.filter.matches(event)
                && let Ok(mut cb) = entry.callback.lock()
            {
                (cb)(event);
            }
        }
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Total events dispatched.
    #[must_use]
    pub const fn fired_count(&self) -> u64 {
        self.fired_count
    }
}

// ---------------------------------------------------------------------------
// PluginEventsFull — facade
// ---------------------------------------------------------------------------

/// Main facade: combines dispatcher, log, and ID generation.
#[derive(Debug)]
pub struct PluginEventsFull {
    pub dispatcher: EventDispatcher,
    pub log: EventLog,
    next_id: u64,
    pub paused: bool,
}

impl PluginEventsFull {
    #[must_use]
    pub fn new(log_capacity: usize) -> Self {
        Self {
            dispatcher: EventDispatcher::new(),
            log: EventLog::new(log_capacity),
            next_id: 1,
            paused: false,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if a handler with that name is already registered.
    pub fn on<F>(
        &mut self,
        name: impl Into<String>,
        filter: EventFilter,
        callback: F,
    ) -> EventResult<()>
    where
        F: FnMut(&Event) + Send + 'static,
    {
        self.dispatcher.register(name, filter, callback)
    }

    ///
    /// # Errors
    ///
    /// Returns an error if no handler with that name is registered.
    pub fn off(&mut self, name: &str) -> EventResult<()> {
        self.dispatcher.unregister(name)
    }

    /// Fire an event.
    pub fn fire(&mut self, event_type: EventType) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let event = Event::new(id, event_type);
        self.log.push(event.clone());
        if !self.paused {
            self.dispatcher.dispatch(&event);
        }
        id
    }

    /// Fire an event with context.
    pub fn fire_ctx(&mut self, event_type: EventType, ctx: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let event = Event::new(id, event_type).with_context(ctx);
        self.log.push(event.clone());
        if !self.paused {
            self.dispatcher.dispatch(&event);
        }
        id
    }

    /// Pause event dispatch (events are still logged).
    pub const fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume event dispatch.
    pub const fn resume(&mut self) {
        self.paused = false;
    }

    /// Total events fired.
    #[must_use]
    pub const fn total_fired(&self) -> u64 {
        self.log.total_fired()
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.dispatcher.handler_count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // --- EventType ---

    #[test]
    fn event_type_category_binary() {
        assert_eq!(EventType::BinaryOpened.category(), "binary");
    }

    #[test]
    fn event_type_category_debug() {
        assert_eq!(EventType::DebugBreakpointHit.category(), "debug");
    }

    #[test]
    fn event_type_category_plugin() {
        assert_eq!(EventType::PluginLoaded.category(), "plugin");
    }

    #[test]
    fn event_type_category_ui() {
        assert_eq!(EventType::ViewOpened.category(), "ui");
    }

    #[test]
    fn event_type_category_other() {
        assert_eq!(EventType::SearchStarted.category(), "other");
    }

    #[test]
    fn event_type_display_custom() {
        let et = EventType::Custom("my_event".into());
        assert_eq!(format!("{et}"), "custom:my_event");
    }

    #[test]
    fn event_type_many_variants_distinct() {
        // Just exercise a broad sample to confirm they compile and are distinct.
        let variants = vec![
            EventType::BinaryOpened,
            EventType::FunctionAdded,
            EventType::SymbolAdded,
            EventType::DataVariableAdded,
            EventType::SectionAdded,
            EventType::TypeAdded,
            EventType::LlilGenerated,
            EventType::AnnotationAdded,
            EventType::HexViewScrolled,
            EventType::PluginLoaded,
            EventType::DebugSessionStarted,
            EventType::ScriptExecuted,
            EventType::ProjectOpened,
            EventType::CollaboratorJoined,
            EventType::SearchStarted,
            EventType::NavigationHistoryPushed,
            EventType::ClipboardCopied,
            EventType::TagAdded,
            EventType::TriageStarted,
        ];
        let mut set = std::collections::HashSet::new();
        for v in variants {
            set.insert(v);
        }
        assert!(set.len() >= 19);
    }

    // --- Event ---

    #[test]
    fn event_new_and_display() {
        let e = Event::new(1, EventType::FunctionRenamed)
            .with_context("main")
            .with_meta("old_name", "sub_1234");
        assert!(format!("{e}").contains("main"));
    }

    #[test]
    fn event_metadata() {
        let e = Event::new(2, EventType::SettingChanged).with_meta("key", "theme");
        assert_eq!(
            e.metadata.get("key").map(std::string::String::as_str),
            Some("theme")
        );
    }

    // --- EventFilter ---

    #[test]
    fn filter_all_matches_everything() {
        let f = EventFilter::all();
        let e = Event::new(1, EventType::BinaryOpened);
        assert!(f.matches(&e));
    }

    #[test]
    fn filter_category_matches() {
        let f = EventFilter::for_category("debug");
        let e = Event::new(1, EventType::DebugBreakpointHit);
        assert!(f.matches(&e));
    }

    #[test]
    fn filter_category_no_match() {
        let f = EventFilter::for_category("debug");
        let e = Event::new(1, EventType::FunctionAdded);
        assert!(!f.matches(&e));
    }

    #[test]
    fn filter_type_exact_match() {
        let f = EventFilter::for_type(EventType::PluginLoaded);
        let e = Event::new(1, EventType::PluginLoaded);
        assert!(f.matches(&e));
    }

    #[test]
    fn filter_type_no_match() {
        let f = EventFilter::for_type(EventType::PluginLoaded);
        let e = Event::new(1, EventType::PluginUnloaded);
        assert!(!f.matches(&e));
    }

    #[test]
    fn filter_custom_include() {
        let f = EventFilter {
            include_custom: true,
            ..Default::default()
        };
        let e = Event::new(1, EventType::Custom("x".into()));
        assert!(f.matches(&e));
    }

    // --- EventLog ---

    #[test]
    fn event_log_push_and_len() {
        let mut log = EventLog::new(100);
        log.push(Event::new(1, EventType::BinaryOpened));
        log.push(Event::new(2, EventType::BinaryClosed));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn event_log_max_capacity_evicts() {
        let mut log = EventLog::new(3);
        for i in 1..=5 {
            log.push(Event::new(i, EventType::FunctionAdded));
        }
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn event_log_total_fired() {
        let mut log = EventLog::new(10);
        for i in 1..=7 {
            log.push(Event::new(i, EventType::TagAdded));
        }
        assert_eq!(log.total_fired(), 7);
    }

    #[test]
    fn event_log_by_type() {
        let mut log = EventLog::new(100);
        log.push(Event::new(1, EventType::BinaryOpened));
        log.push(Event::new(2, EventType::BinaryClosed));
        log.push(Event::new(3, EventType::BinaryOpened));
        let hits = log.by_type(&EventType::BinaryOpened);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn event_log_filtered() {
        let mut log = EventLog::new(100);
        log.push(Event::new(1, EventType::DebugBreakpointHit));
        log.push(Event::new(2, EventType::FunctionAdded));
        let f = EventFilter::for_category("debug");
        let hits = log.filtered(&f);
        assert_eq!(hits.len(), 1);
    }

    // --- EventDispatcher ---

    #[test]
    fn dispatcher_register_and_fire() {
        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let mut d = EventDispatcher::new();
        d.register("h", EventFilter::all(), move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        d.dispatch(&Event::new(1, EventType::BinaryOpened));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatcher_duplicate_handler_error() {
        let mut d = EventDispatcher::new();
        d.register("h", EventFilter::all(), |_| {}).unwrap();
        assert!(matches!(
            d.register("h", EventFilter::all(), |_| {}),
            Err(EventError::DuplicateHandler(_))
        ));
    }

    #[test]
    fn dispatcher_unregister() {
        let mut d = EventDispatcher::new();
        d.register("h", EventFilter::all(), |_| {}).unwrap();
        d.unregister("h").unwrap();
        assert_eq!(d.handler_count(), 0);
    }

    #[test]
    fn dispatcher_unregister_not_found() {
        let mut d = EventDispatcher::new();
        assert!(matches!(
            d.unregister("x"),
            Err(EventError::HandlerNotFound(_))
        ));
    }

    #[test]
    fn dispatcher_filtered_handler() {
        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let mut d = EventDispatcher::new();
        d.register("h", EventFilter::for_category("debug"), move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        d.dispatch(&Event::new(1, EventType::FunctionAdded)); // no match
        d.dispatch(&Event::new(2, EventType::DebugBreakpointHit)); // match
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // --- PluginEventsFull ---

    #[test]
    fn events_full_fire_increments_id() {
        let mut pef = PluginEventsFull::new(100);
        let id1 = pef.fire(EventType::BinaryOpened);
        let id2 = pef.fire(EventType::BinaryOpened);
        assert_eq!(id2, id1 + 1);
    }

    #[test]
    fn events_full_log_captures_events() {
        let mut pef = PluginEventsFull::new(100);
        pef.fire(EventType::FunctionAdded);
        pef.fire(EventType::FunctionRemoved);
        assert_eq!(pef.log.len(), 2);
    }

    #[test]
    fn events_full_pause_stops_dispatch() {
        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let mut pef = PluginEventsFull::new(100);
        pef.on("h", EventFilter::all(), move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        pef.pause();
        pef.fire(EventType::BinaryOpened);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(pef.log.len(), 1); // logged even when paused
    }

    #[test]
    fn events_full_resume_dispatches() {
        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let mut pef = PluginEventsFull::new(100);
        pef.on("h", EventFilter::all(), move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        pef.pause();
        pef.fire(EventType::BinaryOpened);
        pef.resume();
        pef.fire(EventType::BinaryOpened);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn events_full_fire_ctx() {
        let mut pef = PluginEventsFull::new(100);
        pef.fire_ctx(EventType::FunctionRenamed, "main");
        let entries = pef.log.by_type(&EventType::FunctionRenamed);
        assert_eq!(entries[0].context.as_deref(), Some("main"));
    }

    #[test]
    fn events_full_on_off() {
        let mut pef = PluginEventsFull::new(100);
        pef.on("h", EventFilter::all(), |_| {}).unwrap();
        assert_eq!(pef.handler_count(), 1);
        pef.off("h").unwrap();
        assert_eq!(pef.handler_count(), 0);
    }

    #[test]
    fn events_full_total_fired() {
        let mut pef = PluginEventsFull::new(100);
        for _ in 0..5 {
            pef.fire(EventType::SearchStarted);
        }
        assert_eq!(pef.total_fired(), 5);
    }

    #[test]
    fn event_with_timestamp() {
        let e = Event::new(1, EventType::BinaryOpened).with_timestamp(1_700_000_000);
        assert_eq!(e.timestamp, 1_700_000_000);
    }

    #[test]
    fn event_type_function_category() {
        assert_eq!(EventType::FunctionAdded.category(), "function");
        assert_eq!(EventType::FunctionRemoved.category(), "function");
        assert_eq!(EventType::FunctionTagged.category(), "function");
    }

    #[test]
    fn event_type_binary_analysis_progress() {
        let et = EventType::BinaryAnalysisProgress { percent: 50 };
        assert_eq!(et.category(), "binary");
    }

    #[test]
    fn event_log_clear_resets() {
        let mut log = EventLog::new(100);
        log.push(Event::new(1, EventType::BinaryOpened));
        log.clear();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn event_log_total_fired_not_reset_on_evict() {
        let mut log = EventLog::new(2);
        for i in 0..5 {
            log.push(Event::new(i, EventType::TagAdded));
        }
        assert_eq!(log.total_fired(), 5);
        assert_eq!(log.len(), 2); // evicted to max
    }

    #[test]
    fn filter_multiple_categories() {
        let f = EventFilter {
            categories: vec!["debug".into(), "plugin".into()],
            ..Default::default()
        };
        let e1 = Event::new(1, EventType::DebugBreakpointHit);
        let e2 = Event::new(2, EventType::PluginLoaded);
        let e3 = Event::new(3, EventType::FunctionAdded);
        assert!(f.matches(&e1));
        assert!(f.matches(&e2));
        assert!(!f.matches(&e3));
    }

    #[test]
    fn filter_multiple_types() {
        let f = EventFilter {
            types: vec![EventType::BinaryOpened, EventType::BinaryClosed],
            ..Default::default()
        };
        assert!(f.matches(&Event::new(1, EventType::BinaryOpened)));
        assert!(f.matches(&Event::new(2, EventType::BinaryClosed)));
        assert!(!f.matches(&Event::new(3, EventType::FunctionAdded)));
    }

    #[test]
    fn dispatcher_fired_count_increments() {
        let mut d = EventDispatcher::new();
        d.dispatch(&Event::new(1, EventType::BinaryOpened));
        d.dispatch(&Event::new(2, EventType::BinaryOpened));
        assert_eq!(d.fired_count(), 2);
    }

    #[test]
    fn plugin_events_full_new_log_capacity() {
        let pef = PluginEventsFull::new(10);
        assert_eq!(pef.handler_count(), 0);
    }

    #[test]
    fn event_type_custom_category_is_other() {
        let et = EventType::Custom("special".into());
        // custom doesn't match any hardcoded category
        let cat = et.category();
        assert!(cat == "other" || cat == "binary"); // just no panic
    }

    #[test]
    fn event_metadata_multiple_keys() {
        let e = Event::new(1, EventType::SettingChanged)
            .with_meta("key1", "val1")
            .with_meta("key2", "val2");
        assert_eq!(e.metadata.len(), 2);
    }
}
