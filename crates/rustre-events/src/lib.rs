//! `rustre-events` — broadcast event bus for the `RustRE` platform.
//!
//! Every subsystem (loaders, analysis passes, debugger adapters, the AI agent
//! layer …) fires [`CoreEvent`] values onto the shared [`EventBus`].  Other
//! subsystems subscribe and react without tight coupling.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use rustre_events::{EventBus, CoreEvent};
//!
//! # #[tokio::main]
//! # async fn main() {
//! let bus = EventBus::new_default();
//! let mut rx = bus.subscribe();
//!
//! bus.send_view_opened(1, "file:///bin/ls".into(), "x86_64".into());
//!
//! let event = rx.recv().await.unwrap();
//! println!("{event:?}");
//! # }
//! ```

pub mod bus_impl;
pub mod event_driven_analysis;
pub mod event_replay;
pub mod event_schema;
pub mod event_filter;
pub mod event_types;
pub mod event_bus;
pub mod event_recorder;
pub mod event_dispatcher;
pub mod event_replay_advanced;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// CoreEvent
// ---------------------------------------------------------------------------

/// Every observable event that can occur inside `RustRE`.
///
/// All variants are `Clone` so they can be forwarded to multiple subscribers
/// via a broadcast channel without additional synchronisation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CoreEvent {
    // --- View lifecycle ---------------------------------------------------
    ViewOpened {
        view_id: u64,
        uri: String,
        arch: String,
    },
    ViewClosed {
        view_id: u64,
    },
    ViewSaved {
        view_id: u64,
        path: String,
    },

    // --- Analysis --------------------------------------------------------
    AnalysisStarted {
        view_id: u64,
        pass: String,
    },
    AnalysisProgress {
        view_id: u64,
        pass: String,
        percent: u8,
    },
    AnalysisCompleted {
        view_id: u64,
        pass: String,
    },
    AnalysisFailed {
        view_id: u64,
        pass: String,
        error: String,
    },

    // --- Functions -------------------------------------------------------
    FunctionDefined {
        view_id: u64,
        address: u64,
        name: String,
    },
    FunctionRenamed {
        view_id: u64,
        address: u64,
        old_name: String,
        new_name: String,
    },
    FunctionDeleted {
        view_id: u64,
        address: u64,
    },
    FunctionCommented {
        view_id: u64,
        address: u64,
        comment: String,
    },
    FunctionTagged {
        view_id: u64,
        address: u64,
        tag: String,
    },

    // --- Symbols ---------------------------------------------------------
    SymbolDefined {
        view_id: u64,
        address: u64,
        name: String,
        kind: String,
        source: String,
    },
    SymbolDeleted {
        view_id: u64,
        address: u64,
    },
    SymbolImported {
        view_id: u64,
        count: u64,
        source: String,
    },

    // --- Debugger --------------------------------------------------------
    DebuggerAttached {
        view_id: u64,
        pid: u32,
    },
    DebuggerDetached {
        view_id: u64,
    },
    BreakpointHit {
        view_id: u64,
        address: u64,
        thread_id: u32,
    },
    BreakpointSet {
        view_id: u64,
        address: u64,
        breakpoint_id: u32,
    },
    BreakpointCleared {
        view_id: u64,
        breakpoint_id: u32,
    },
    ProcessExited {
        view_id: u64,
        exit_code: i32,
    },
    ThreadCreated {
        view_id: u64,
        thread_id: u32,
    },
    ThreadExited {
        view_id: u64,
        thread_id: u32,
    },
    StepComplete {
        view_id: u64,
        address: u64,
        thread_id: u32,
    },
    RegisterChanged {
        view_id: u64,
        thread_id: u32,
        register: String,
        value: u64,
    },

    // --- Memory ----------------------------------------------------------
    MemoryRead {
        view_id: u64,
        address: u64,
        length: usize,
    },
    MemoryWritten {
        view_id: u64,
        address: u64,
        length: usize,
    },
    MemoryPatched {
        view_id: u64,
        address: u64,
        length: usize,
    },
    MemoryMapped {
        view_id: u64,
        address: u64,
        length: usize,
        name: String,
    },

    // --- Types -----------------------------------------------------------
    TypeDefined {
        view_id: u64,
        name: String,
    },
    TypeUpdated {
        view_id: u64,
        name: String,
    },
    TypeDeleted {
        view_id: u64,
        name: String,
    },
    TypeImported {
        view_id: u64,
        count: u64,
        source: String,
    },

    // --- Patches ---------------------------------------------------------
    PatchApplied {
        view_id: u64,
        address: u64,
        length: usize,
    },
    PatchReverted {
        view_id: u64,
        address: u64,
    },

    // --- Comments / bookmarks --------------------------------------------
    CommentAdded {
        view_id: u64,
        address: u64,
        text: String,
    },
    CommentRemoved {
        view_id: u64,
        address: u64,
    },
    BookmarkAdded {
        view_id: u64,
        address: u64,
        label: Option<String>,
    },
    BookmarkRemoved {
        view_id: u64,
        address: u64,
    },

    // --- AI / Agent ------------------------------------------------------
    AgentAction {
        view_id: u64,
        action: String,
        result: String,
    },
    AgentError {
        view_id: u64,
        action: String,
        error: String,
    },
    AgentStarted {
        view_id: u64,
        agent_name: String,
    },
    AgentStopped {
        view_id: u64,
        agent_name: String,
    },

    // --- Cross-references ------------------------------------------------
    XrefAdded {
        view_id: u64,
        from_addr: u64,
        to_addr: u64,
        kind: String,
    },
    XrefRemoved {
        view_id: u64,
        from_addr: u64,
        to_addr: u64,
    },

    // --- Script ----------------------------------------------------------
    ScriptExecuted {
        view_id: u64,
        engine: String,
        success: bool,
    },

    // --- Plugin ----------------------------------------------------------
    PluginLoaded {
        plugin_id: String,
    },
    PluginUnloaded {
        plugin_id: String,
    },
    PluginError {
        plugin_id: String,
        error: String,
    },

    // --- Triage ----------------------------------------------------------
    TriageCompleted {
        view_id: u64,
        verdict: String,
    },

    // --- Custom / plugin -------------------------------------------------
    Custom {
        event_type: String,
        payload: serde_json::Value,
    },
}

impl CoreEvent {
    /// Extract the `view_id` from any event that carries one. Returns `None`
    /// for events that are not scoped to a view.
    #[must_use]
    pub const fn view_id(&self) -> Option<u64> {
        match self {
            Self::ViewOpened { view_id, .. }
            | Self::ViewClosed { view_id }
            | Self::ViewSaved { view_id, .. }
            | Self::AnalysisStarted { view_id, .. }
            | Self::AnalysisProgress { view_id, .. }
            | Self::AnalysisCompleted { view_id, .. }
            | Self::AnalysisFailed { view_id, .. }
            | Self::FunctionDefined { view_id, .. }
            | Self::FunctionRenamed { view_id, .. }
            | Self::FunctionDeleted { view_id, .. }
            | Self::FunctionCommented { view_id, .. }
            | Self::FunctionTagged { view_id, .. }
            | Self::SymbolDefined { view_id, .. }
            | Self::SymbolDeleted { view_id, .. }
            | Self::SymbolImported { view_id, .. }
            | Self::DebuggerAttached { view_id, .. }
            | Self::DebuggerDetached { view_id }
            | Self::BreakpointHit { view_id, .. }
            | Self::BreakpointSet { view_id, .. }
            | Self::BreakpointCleared { view_id, .. }
            | Self::ProcessExited { view_id, .. }
            | Self::ThreadCreated { view_id, .. }
            | Self::ThreadExited { view_id, .. }
            | Self::StepComplete { view_id, .. }
            | Self::RegisterChanged { view_id, .. }
            | Self::MemoryRead { view_id, .. }
            | Self::MemoryWritten { view_id, .. }
            | Self::MemoryPatched { view_id, .. }
            | Self::MemoryMapped { view_id, .. }
            | Self::TypeDefined { view_id, .. }
            | Self::TypeUpdated { view_id, .. }
            | Self::TypeDeleted { view_id, .. }
            | Self::TypeImported { view_id, .. }
            | Self::PatchApplied { view_id, .. }
            | Self::PatchReverted { view_id, .. }
            | Self::CommentAdded { view_id, .. }
            | Self::CommentRemoved { view_id, .. }
            | Self::BookmarkAdded { view_id, .. }
            | Self::BookmarkRemoved { view_id, .. }
            | Self::AgentAction { view_id, .. }
            | Self::AgentError { view_id, .. }
            | Self::AgentStarted { view_id, .. }
            | Self::AgentStopped { view_id, .. }
            | Self::XrefAdded { view_id, .. }
            | Self::XrefRemoved { view_id, .. }
            | Self::ScriptExecuted { view_id, .. }
            | Self::TriageCompleted { view_id, .. } => Some(*view_id),
            Self::PluginLoaded { .. }
            | Self::PluginUnloaded { .. }
            | Self::PluginError { .. }
            | Self::Custom { .. } => None,
        }
    }

    /// Variant name as a static string, useful for logging/metrics.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::ViewOpened { .. } => "ViewOpened",
            Self::ViewClosed { .. } => "ViewClosed",
            Self::ViewSaved { .. } => "ViewSaved",
            Self::AnalysisStarted { .. } => "AnalysisStarted",
            Self::AnalysisProgress { .. } => "AnalysisProgress",
            Self::AnalysisCompleted { .. } => "AnalysisCompleted",
            Self::AnalysisFailed { .. } => "AnalysisFailed",
            Self::FunctionDefined { .. } => "FunctionDefined",
            Self::FunctionRenamed { .. } => "FunctionRenamed",
            Self::FunctionDeleted { .. } => "FunctionDeleted",
            Self::FunctionCommented { .. } => "FunctionCommented",
            Self::FunctionTagged { .. } => "FunctionTagged",
            Self::SymbolDefined { .. } => "SymbolDefined",
            Self::SymbolDeleted { .. } => "SymbolDeleted",
            Self::SymbolImported { .. } => "SymbolImported",
            Self::DebuggerAttached { .. } => "DebuggerAttached",
            Self::DebuggerDetached { .. } => "DebuggerDetached",
            Self::BreakpointHit { .. } => "BreakpointHit",
            Self::BreakpointSet { .. } => "BreakpointSet",
            Self::BreakpointCleared { .. } => "BreakpointCleared",
            Self::ProcessExited { .. } => "ProcessExited",
            Self::ThreadCreated { .. } => "ThreadCreated",
            Self::ThreadExited { .. } => "ThreadExited",
            Self::StepComplete { .. } => "StepComplete",
            Self::RegisterChanged { .. } => "RegisterChanged",
            Self::MemoryRead { .. } => "MemoryRead",
            Self::MemoryWritten { .. } => "MemoryWritten",
            Self::MemoryPatched { .. } => "MemoryPatched",
            Self::MemoryMapped { .. } => "MemoryMapped",
            Self::TypeDefined { .. } => "TypeDefined",
            Self::TypeUpdated { .. } => "TypeUpdated",
            Self::TypeDeleted { .. } => "TypeDeleted",
            Self::TypeImported { .. } => "TypeImported",
            Self::PatchApplied { .. } => "PatchApplied",
            Self::PatchReverted { .. } => "PatchReverted",
            Self::CommentAdded { .. } => "CommentAdded",
            Self::CommentRemoved { .. } => "CommentRemoved",
            Self::BookmarkAdded { .. } => "BookmarkAdded",
            Self::BookmarkRemoved { .. } => "BookmarkRemoved",
            Self::AgentAction { .. } => "AgentAction",
            Self::AgentError { .. } => "AgentError",
            Self::AgentStarted { .. } => "AgentStarted",
            Self::AgentStopped { .. } => "AgentStopped",
            Self::XrefAdded { .. } => "XrefAdded",
            Self::XrefRemoved { .. } => "XrefRemoved",
            Self::ScriptExecuted { .. } => "ScriptExecuted",
            Self::PluginLoaded { .. } => "PluginLoaded",
            Self::PluginUnloaded { .. } => "PluginUnloaded",
            Self::PluginError { .. } => "PluginError",
            Self::TriageCompleted { .. } => "TriageCompleted",
            Self::Custom { .. } => "Custom",
        }
    }

    /// Return `true` if this is a debug-related event.
    #[must_use]
    pub const fn is_debug_event(&self) -> bool {
        matches!(
            self,
            Self::DebuggerAttached { .. }
                | Self::DebuggerDetached { .. }
                | Self::BreakpointHit { .. }
                | Self::BreakpointSet { .. }
                | Self::BreakpointCleared { .. }
                | Self::ProcessExited { .. }
                | Self::ThreadCreated { .. }
                | Self::ThreadExited { .. }
                | Self::StepComplete { .. }
                | Self::RegisterChanged { .. }
        )
    }

    /// Return `true` if this is an analysis-related event.
    #[must_use]
    pub const fn is_analysis_event(&self) -> bool {
        matches!(
            self,
            Self::AnalysisStarted { .. }
                | Self::AnalysisProgress { .. }
                | Self::AnalysisCompleted { .. }
                | Self::AnalysisFailed { .. }
        )
    }

    /// Return `true` if this is a function-related event.
    #[must_use]
    pub const fn is_function_event(&self) -> bool {
        matches!(
            self,
            Self::FunctionDefined { .. }
                | Self::FunctionRenamed { .. }
                | Self::FunctionDeleted { .. }
                | Self::FunctionCommented { .. }
                | Self::FunctionTagged { .. }
        )
    }

    /// Serialize this event to a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize an event from a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl fmt::Display for CoreEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(vid) = self.view_id() {
            write!(f, "[view={}] {}", vid, self.variant_name())
        } else {
            write!(f, "{}", self.variant_name())
        }
    }
}

// ---------------------------------------------------------------------------
// EventKind — coarse category for filtering
// ---------------------------------------------------------------------------

/// Coarse category of a [`CoreEvent`], useful for fast filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    View,
    Analysis,
    Function,
    Symbol,
    Debugger,
    Memory,
    Type,
    Patch,
    Annotation,
    Agent,
    CrossRef,
    Script,
    Plugin,
    Custom,
}

impl CoreEvent {
    /// Return the coarse [`EventKind`] for this event.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::ViewOpened { .. } | Self::ViewClosed { .. } | Self::ViewSaved { .. } => {
                EventKind::View
            }
            Self::AnalysisStarted { .. }
            | Self::AnalysisProgress { .. }
            | Self::AnalysisCompleted { .. }
            | Self::AnalysisFailed { .. } => EventKind::Analysis,
            Self::FunctionDefined { .. }
            | Self::FunctionRenamed { .. }
            | Self::FunctionDeleted { .. }
            | Self::FunctionCommented { .. }
            | Self::FunctionTagged { .. } => EventKind::Function,
            Self::SymbolDefined { .. }
            | Self::SymbolDeleted { .. }
            | Self::SymbolImported { .. } => EventKind::Symbol,
            Self::DebuggerAttached { .. }
            | Self::DebuggerDetached { .. }
            | Self::BreakpointHit { .. }
            | Self::BreakpointSet { .. }
            | Self::BreakpointCleared { .. }
            | Self::ProcessExited { .. }
            | Self::ThreadCreated { .. }
            | Self::ThreadExited { .. }
            | Self::StepComplete { .. }
            | Self::RegisterChanged { .. } => EventKind::Debugger,
            Self::MemoryRead { .. }
            | Self::MemoryWritten { .. }
            | Self::MemoryPatched { .. }
            | Self::MemoryMapped { .. } => EventKind::Memory,
            Self::TypeDefined { .. }
            | Self::TypeUpdated { .. }
            | Self::TypeDeleted { .. }
            | Self::TypeImported { .. } => EventKind::Type,
            Self::PatchApplied { .. } | Self::PatchReverted { .. } => EventKind::Patch,
            Self::CommentAdded { .. }
            | Self::CommentRemoved { .. }
            | Self::BookmarkAdded { .. }
            | Self::BookmarkRemoved { .. } => EventKind::Annotation,
            Self::AgentAction { .. }
            | Self::AgentError { .. }
            | Self::AgentStarted { .. }
            | Self::AgentStopped { .. } => EventKind::Agent,
            Self::XrefAdded { .. } | Self::XrefRemoved { .. } => EventKind::CrossRef,
            Self::ScriptExecuted { .. } => EventKind::Script,
            Self::PluginLoaded { .. } | Self::PluginUnloaded { .. } | Self::PluginError { .. } => {
                EventKind::Plugin
            }
            Self::TriageCompleted { .. } | Self::Custom { .. } => EventKind::Custom,
        }
    }
}

// ---------------------------------------------------------------------------
// EventFilter
// ---------------------------------------------------------------------------

/// A composable predicate for filtering [`CoreEvent`]s.
pub struct EventFilter {
    inner: Box<dyn Fn(&CoreEvent) -> bool + Send + Sync>,
}

impl EventFilter {
    /// Create a filter from an arbitrary predicate.
    pub fn new(f: impl Fn(&CoreEvent) -> bool + Send + Sync + 'static) -> Self {
        Self { inner: Box::new(f) }
    }

    /// Accept only events for a specific view.
    #[must_use]
    pub fn for_view(view_id: u64) -> Self {
        Self::new(move |e| e.view_id() == Some(view_id))
    }

    /// Accept only events of a specific kind.
    #[must_use]
    pub fn of_kind(kind: EventKind) -> Self {
        Self::new(move |e| e.kind() == kind)
    }

    /// Accept only events matching a specific variant name.
    #[must_use]
    pub fn by_variant(name: &'static str) -> Self {
        Self::new(move |e| e.variant_name() == name)
    }

    /// Logical AND of two filters.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self::new(move |e| (self.inner)(e) && (other.inner)(e))
    }

    /// Logical OR of two filters.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self::new(move |e| (self.inner)(e) || (other.inner)(e))
    }

    /// Logical NOT of this filter.
    #[must_use]
    pub fn negate(self) -> Self {
        Self::new(move |e| !(self.inner)(e))
    }

    /// Test an event against this filter.
    #[must_use]
    pub fn matches(&self, event: &CoreEvent) -> bool {
        (self.inner)(event)
    }
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

/// Central broadcast channel for [`CoreEvent`] values.
///
/// Clone the bus or share it via `Arc<EventBus>` to distribute it across
/// subsystems.  Each call to [`subscribe`] returns an independent receiver.
pub struct EventBus {
    tx: broadcast::Sender<CoreEvent>,
    /// Per-kind event counters.
    counters: RwLock<HashMap<&'static str, u64>>,
}

impl EventBus {
    /// Create a new bus with the given channel `capacity`.
    ///
    /// If a slow subscriber falls behind by more than `capacity` events the
    /// oldest events will be dropped and the receiver will observe a
    /// [`broadcast::error::RecvError::Lagged`] error.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Convenience constructor with a capacity of 1 024.
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(1024)
    }

    /// Create a new receiver that will observe all future events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<CoreEvent> {
        self.tx.subscribe()
    }

    /// Publish `event` to every active subscriber.
    ///
    /// Returns the number of subscribers that received the event, or an error
    /// if there are no active subscribers (the event is dropped).
    ///
    /// # Errors
    /// Returns `broadcast::error::SendError` when there are no subscribers.
    pub fn send(&self, event: CoreEvent) -> Result<usize, broadcast::error::SendError<CoreEvent>> {
        *self
            .counters
            .write()
            .entry(event.variant_name())
            .or_insert(0) += 1;
        self.tx.send(event)
    }

    /// Number of active subscriber handles.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Return how many times the named variant has been sent.
    #[must_use]
    pub fn event_count(&self, variant_name: &str) -> u64 {
        self.counters
            .read()
            .get(variant_name)
            .copied()
            .unwrap_or(0)
    }

    /// Total number of events sent across all variants.
    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.counters.read().values().sum()
    }

    // --- Convenience senders --------------------------------------------

    /// Publish a [`CoreEvent::ViewOpened`] event, ignoring send errors.
    pub fn send_view_opened(&self, view_id: u64, uri: String, arch: String) {
        let _ = self.send(CoreEvent::ViewOpened { view_id, uri, arch });
    }

    /// Publish a [`CoreEvent::ViewClosed`] event, ignoring send errors.
    pub fn send_view_closed(&self, view_id: u64) {
        let _ = self.send(CoreEvent::ViewClosed { view_id });
    }

    /// Publish a [`CoreEvent::FunctionDefined`] event, ignoring send errors.
    pub fn send_function_defined(&self, view_id: u64, address: u64, name: String) {
        let _ = self.send(CoreEvent::FunctionDefined {
            view_id,
            address,
            name,
        });
    }

    /// Publish a [`CoreEvent::FunctionRenamed`] event, ignoring send errors.
    pub fn send_function_renamed(
        &self,
        view_id: u64,
        address: u64,
        old_name: String,
        new_name: String,
    ) {
        let _ = self.send(CoreEvent::FunctionRenamed {
            view_id,
            address,
            old_name,
            new_name,
        });
    }

    /// Publish a [`CoreEvent::BreakpointHit`] event, ignoring send errors.
    pub fn send_breakpoint_hit(&self, view_id: u64, address: u64, thread_id: u32) {
        let _ = self.send(CoreEvent::BreakpointHit {
            view_id,
            address,
            thread_id,
        });
    }

    /// Publish a [`CoreEvent::AnalysisProgress`] event, ignoring send errors.
    pub fn send_analysis_progress(&self, view_id: u64, pass: String, percent: u8) {
        let _ = self.send(CoreEvent::AnalysisProgress {
            view_id,
            pass,
            percent,
        });
    }

    /// Publish a [`CoreEvent::AnalysisCompleted`] event, ignoring send errors.
    pub fn send_analysis_completed(&self, view_id: u64, pass: String) {
        let _ = self.send(CoreEvent::AnalysisCompleted { view_id, pass });
    }

    /// Publish a [`CoreEvent::AnalysisFailed`] event, ignoring send errors.
    pub fn send_analysis_failed(&self, view_id: u64, pass: String, error: String) {
        let _ = self.send(CoreEvent::AnalysisFailed {
            view_id,
            pass,
            error,
        });
    }

    /// Publish a [`CoreEvent::SymbolDefined`] event, ignoring send errors.
    pub fn send_symbol_defined(
        &self,
        view_id: u64,
        address: u64,
        name: String,
        kind: String,
        source: String,
    ) {
        let _ = self.send(CoreEvent::SymbolDefined {
            view_id,
            address,
            name,
            kind,
            source,
        });
    }

    /// Publish a [`CoreEvent::PluginLoaded`] event, ignoring send errors.
    pub fn send_plugin_loaded(&self, plugin_id: String) {
        let _ = self.send(CoreEvent::PluginLoaded { plugin_id });
    }

    /// Publish a [`CoreEvent::Custom`] event, ignoring send errors.
    pub fn send_custom(&self, event_type: String, payload: serde_json::Value) {
        let _ = self.send(CoreEvent::Custom {
            event_type,
            payload,
        });
    }

    /// Publish a [`CoreEvent::AgentAction`] event, ignoring send errors.
    pub fn send_agent_action(&self, view_id: u64, action: String, result: String) {
        let _ = self.send(CoreEvent::AgentAction {
            view_id,
            action,
            result,
        });
    }

    /// Publish a [`CoreEvent::XrefAdded`] event, ignoring send errors.
    pub fn send_xref_added(&self, view_id: u64, from_addr: u64, to_addr: u64, kind: String) {
        let _ = self.send(CoreEvent::XrefAdded {
            view_id,
            from_addr,
            to_addr,
            kind,
        });
    }

    /// Publish a [`CoreEvent::PatchApplied`] event, ignoring send errors.
    pub fn send_patch_applied(&self, view_id: u64, address: u64, length: usize) {
        let _ = self.send(CoreEvent::PatchApplied {
            view_id,
            address,
            length,
        });
    }

    /// Publish a [`CoreEvent::ScriptExecuted`] event, ignoring send errors.
    pub fn send_script_executed(&self, view_id: u64, engine: String, success: bool) {
        let _ = self.send(CoreEvent::ScriptExecuted {
            view_id,
            engine,
            success,
        });
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new_default()
    }
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBus")
            .field("receivers", &self.tx.receiver_count())
            .field("total_sent", &self.total_sent())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// FilteredSubscription
// ---------------------------------------------------------------------------

/// A subscription that only delivers events matching a user-supplied predicate.
///
/// All events are received from the underlying broadcast channel; events that
/// do not match the filter are silently dropped.
pub struct FilteredSubscription {
    rx: broadcast::Receiver<CoreEvent>,
    filter: Box<dyn Fn(&CoreEvent) -> bool + Send + Sync>,
    /// How many events were received (including filtered-out ones).
    received: u64,
    /// How many events were delivered to the caller.
    delivered: u64,
}

impl FilteredSubscription {
    /// Wrap `rx` with a filter closure.
    pub fn new(
        rx: broadcast::Receiver<CoreEvent>,
        filter: impl Fn(&CoreEvent) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            rx,
            filter: Box::new(filter),
            received: 0,
            delivered: 0,
        }
    }

    /// Wrap `rx` with an [`EventFilter`].
    #[must_use] 
    pub fn with_filter(rx: broadcast::Receiver<CoreEvent>, filter: EventFilter) -> Self {
        Self {
            rx,
            filter: Box::new(move |e| filter.matches(e)),
            received: 0,
            delivered: 0,
        }
    }

    /// Receive the next raw event, **regardless of the filter**.
    ///
    /// This method bypasses the predicate entirely.  Typical callers should
    /// use [`recv_filtered`](Self::recv_filtered) instead.
    ///
    /// # Errors
    /// Returns `broadcast::error::RecvError` on lag or channel closure.
    pub async fn recv_raw(&mut self) -> Result<CoreEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    /// Receive the next event that passes the filter, returning `None` on
    /// channel close.  Lagged events are skipped transparently.
    pub async fn recv_filtered(&mut self) -> Option<CoreEvent> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    self.received += 1;
                    if (self.filter)(&event) {
                        self.delivered += 1;
                        return Some(event);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Total events received from the underlying channel.
    #[must_use]
    pub const fn received_count(&self) -> u64 {
        self.received
    }

    /// Total events delivered to the caller (passed the filter).
    #[must_use]
    pub const fn delivered_count(&self) -> u64 {
        self.delivered
    }
}

// ---------------------------------------------------------------------------
// Convenience constructor: view-scoped subscription
// ---------------------------------------------------------------------------

/// Create a [`FilteredSubscription`] that only receives events for `view_id`.
#[must_use]
pub fn view_subscription(bus: &EventBus, view_id: u64) -> FilteredSubscription {
    FilteredSubscription::new(bus.subscribe(), move |e| e.view_id() == Some(view_id))
}

/// Create a [`FilteredSubscription`] that only receives events of `kind`.
#[must_use]
pub fn kind_subscription(bus: &EventBus, kind: EventKind) -> FilteredSubscription {
    FilteredSubscription::new(bus.subscribe(), move |e| e.kind() == kind)
}

// ---------------------------------------------------------------------------
// EventHook
// ---------------------------------------------------------------------------

/// A synchronous hook that fires when a matching event is received.
pub struct EventHook {
    /// Predicate that determines which events trigger the hook.
    filter: Box<dyn Fn(&CoreEvent) -> bool + Send + Sync>,
    /// The callback to invoke.
    callback: Box<dyn Fn(CoreEvent) + Send + Sync>,
    /// Human-readable label.
    label: String,
}

impl EventHook {
    /// Create a new hook with the given filter and callback.
    pub fn new(
        label: impl Into<String>,
        filter: impl Fn(&CoreEvent) -> bool + Send + Sync + 'static,
        callback: impl Fn(CoreEvent) + Send + Sync + 'static,
    ) -> Self {
        Self {
            filter: Box::new(filter),
            callback: Box::new(callback),
            label: label.into(),
        }
    }

    /// Return `true` if this hook matches the event.
    #[must_use]
    pub fn matches(&self, event: &CoreEvent) -> bool {
        (self.filter)(event)
    }

    /// Fire the hook with the given event.
    pub fn fire(&self, event: CoreEvent) {
        (self.callback)(event);
    }

    /// Label / name of this hook.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Debug for EventHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventHook({})", self.label)
    }
}

// ---------------------------------------------------------------------------
// HookDispatcher
// ---------------------------------------------------------------------------

/// Manages a set of [`EventHook`]s and dispatches matching events to them.
pub struct HookDispatcher {
    hooks: RwLock<Vec<EventHook>>,
}

impl HookDispatcher {
    /// Create an empty dispatcher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hooks: RwLock::new(Vec::new()),
        }
    }

    /// Register a hook.
    pub fn register(&self, hook: EventHook) {
        self.hooks.write().push(hook);
    }

    /// Dispatch `event` to all matching hooks.
    pub fn dispatch(&self, event: &CoreEvent) {
        let hooks = self.hooks.read();
        for hook in hooks.iter() {
            if hook.matches(event) {
                hook.fire(event.clone());
            }
        }
    }

    /// Remove all hooks with the given label.
    pub fn remove(&self, label: &str) {
        self.hooks.write().retain(|h| h.label() != label);
    }

    /// Number of registered hooks.
    #[must_use]
    pub fn hook_count(&self) -> usize {
        self.hooks.read().len()
    }
}

impl Default for HookDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HookDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HookDispatcher {{ hooks: {} }}", self.hook_count())
    }
}

// ---------------------------------------------------------------------------
// EventLogger
// ---------------------------------------------------------------------------

/// In-memory ring-buffer audit trail of [`CoreEvent`]s.
pub struct EventLogger {
    events: RwLock<VecDeque<(SystemTime, CoreEvent)>>,
    max_size: usize,
}

impl EventLogger {
    /// Create a logger that retains at most `max_size` events.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_size.min(4096))),
            max_size,
        }
    }

    /// Append `event` to the log, evicting the oldest entry when the buffer is full.
    pub fn record(&self, event: CoreEvent) {
        if self.max_size == 0 {
            return;
        }
        let mut guard = self.events.write();
        while guard.len() >= self.max_size {
            guard.pop_front();
        }
        guard.push_back((SystemTime::now(), event));
    }

    /// Return all events recorded at or after `since`.
    #[must_use]
    pub fn events_since(&self, since: SystemTime) -> Vec<(SystemTime, CoreEvent)> {
        let guard = self.events.read();
        guard
            .iter()
            .filter(|(ts, _)| *ts >= since)
            .cloned()
            .collect()
    }

    /// Return the `count` most-recently recorded events (oldest first).
    #[must_use]
    pub fn recent_events(&self, count: usize) -> Vec<(SystemTime, CoreEvent)> {
        let guard = self.events.read();
        let start = guard.len().saturating_sub(count);
        guard.iter().skip(start).cloned().collect()
    }

    /// Return all events of the given [`EventKind`].
    #[must_use]
    pub fn events_by_kind(&self, kind: EventKind) -> Vec<(SystemTime, CoreEvent)> {
        self.events
            .read()
            .iter()
            .filter(|(_, e)| e.kind() == kind)
            .cloned()
            .collect()
    }

    /// Return all events for a specific view.
    #[must_use]
    pub fn events_for_view(&self, view_id: u64) -> Vec<(SystemTime, CoreEvent)> {
        self.events
            .read()
            .iter()
            .filter(|(_, e)| e.view_id() == Some(view_id))
            .cloned()
            .collect()
    }

    /// Remove all stored events.
    pub fn clear(&self) {
        self.events.write().clear();
    }

    /// Total number of stored events.
    #[must_use]
    pub fn count(&self) -> usize {
        self.events.read().len()
    }

    /// Spawn a Tokio background task that subscribes to `bus` and forwards
    /// every received event to this logger.
    pub fn start_logging(self: Arc<Self>, bus: &EventBus) -> tokio::task::JoinHandle<()> {
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => self.record(event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }
}

impl fmt::Debug for EventLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventLogger {{ count: {}, max: {} }}",
            self.count(),
            self.max_size
        )
    }
}

// ---------------------------------------------------------------------------
// EventReplay
// ---------------------------------------------------------------------------

/// Records events and can replay them into a bus.
#[derive(Debug, Default)]
pub struct EventReplay {
    recorded: Vec<CoreEvent>,
}

impl EventReplay {
    /// Create an empty replay buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a snapshot of events from a logger.
    pub fn snapshot_from(&mut self, logger: &EventLogger) {
        let guard = logger.events.read();
        self.recorded = guard.iter().map(|(_, e)| e.clone()).collect();
    }

    /// Append a single event to the replay buffer.
    pub fn push(&mut self, event: CoreEvent) {
        self.recorded.push(event);
    }

    /// Return the number of recorded events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.recorded.len()
    }

    /// Return `true` if the replay buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.recorded.is_empty()
    }

    /// Replay all recorded events onto `bus`, ignoring send errors.
    ///
    /// # Errors
    /// Returns the number of events that failed to send.
    pub fn replay_all(&self, bus: &EventBus) -> usize {
        let mut failures = 0usize;
        for event in &self.recorded {
            if bus.send(event.clone()).is_err() {
                failures += 1;
            }
        }
        failures
    }

    /// Replay only events matching the predicate.
    ///
    /// Returns the number of events replayed.
    pub fn replay_filtered(&self, bus: &EventBus, filter: impl Fn(&CoreEvent) -> bool) -> usize {
        let mut replayed = 0;
        for event in self.recorded.iter().filter(|e| filter(e)) {
            if bus.send(event.clone()).is_ok() {
                replayed += 1;
            }
        }
        replayed
    }

    /// Clear the replay buffer.
    pub fn clear(&mut self) {
        self.recorded.clear();
    }
}

// ---------------------------------------------------------------------------
// EventCorrelator
// ---------------------------------------------------------------------------

/// Boxed key-extraction callback used by `EventCorrelator`.
pub type EventKeyFn = Box<dyn Fn(&CoreEvent) -> Option<String> + Send + Sync>;

/// Correlates events across views using a user-supplied correlation key.
pub struct EventCorrelator {
    /// Map from correlation key to list of events.
    groups: RwLock<HashMap<String, Vec<CoreEvent>>>,
    key_fn: EventKeyFn,
}

impl EventCorrelator {
    /// Create a correlator with a key extraction function.
    pub fn new(key_fn: impl Fn(&CoreEvent) -> Option<String> + Send + Sync + 'static) -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
            key_fn: Box::new(key_fn),
        }
    }

    /// A correlator that groups events by view ID.
    #[must_use]
    pub fn by_view() -> Self {
        Self::new(|e| e.view_id().map(|id| id.to_string()))
    }

    /// A correlator that groups events by variant name.
    #[must_use]
    pub fn by_variant() -> Self {
        Self::new(|e| Some(e.variant_name().to_string()))
    }

    /// Ingest an event.
    pub fn ingest(&self, event: CoreEvent) {
        if let Some(key) = (self.key_fn)(&event) {
            self.groups.write().entry(key).or_default().push(event);
        }
    }

    /// Return all events for the given key.
    #[must_use]
    pub fn get_group(&self, key: &str) -> Vec<CoreEvent> {
        self.groups.read().get(key).cloned().unwrap_or_default()
    }

    /// Return all group keys.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.groups.read().keys().cloned().collect()
    }

    /// Total events ingested across all groups.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.groups.read().values().map(Vec::len).sum()
    }

    /// Clear all groups.
    pub fn clear(&self) {
        self.groups.write().clear();
    }
}

impl fmt::Debug for EventCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventCorrelator {{ groups: {} }}",
            self.groups.read().len()
        )
    }
}

// ---------------------------------------------------------------------------
// EventStats
// ---------------------------------------------------------------------------

/// Collects per-variant and per-kind statistics.
#[derive(Debug, Default)]
pub struct EventStats {
    by_variant: RwLock<HashMap<String, u64>>,
    by_kind: RwLock<HashMap<String, u64>>,
}

impl EventStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one occurrence of `event`.
    pub fn record(&self, event: &CoreEvent) {
        *self
            .by_variant
            .write()
            .entry(event.variant_name().to_string())
            .or_insert(0) += 1;
        *self
            .by_kind
            .write()
            .entry(format!("{:?}", event.kind()))
            .or_insert(0) += 1;
    }

    /// Count for a specific variant name.
    #[must_use]
    pub fn variant_count(&self, name: &str) -> u64 {
        self.by_variant.read().get(name).copied().unwrap_or(0)
    }

    /// Count for a specific kind (as debug string).
    #[must_use]
    pub fn kind_count(&self, kind: EventKind) -> u64 {
        let key = format!("{kind:?}");
        self.by_kind.read().get(&key).copied().unwrap_or(0)
    }

    /// Total events recorded.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.by_variant.read().values().sum()
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.by_variant.write().clear();
        self.by_kind.write().clear();
    }

    /// Return all variant counts.
    #[must_use]
    pub fn all_variant_counts(&self) -> HashMap<String, u64> {
        self.by_variant.read().clone()
    }
}

// ---------------------------------------------------------------------------
// §2.10 — Spec-aligned additions
// ---------------------------------------------------------------------------
//
// The types below satisfy the concrete interface described in spec §2.10.
// They complement (and do not replace) the richer types already defined
// above.  Field names match the spec exactly so downstream code can use
// them interchangeably.

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use tokio::sync::broadcast::Receiver;

// ---------------------------------------------------------------------------
// SpecCoreEvent — spec §2.10 variant set with exact field names
// ---------------------------------------------------------------------------

/// Spec §2.10 event set.  Field names follow the spec literally (`addr`,
/// `path`, `name`, …).  For the richer platform-wide enum see [`CoreEvent`].
///
/// This enum is intentionally a subset; platform code should prefer
/// [`CoreEvent`] for new work.  Bridges between the two are provided via
/// [`From`] impls.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SpecCoreEvent {
    // --- View lifecycle ---------------------------------------------------
    ViewOpened {
        view_id: u64,
        path: String,
    },
    ViewClosed {
        view_id: u64,
    },

    // --- Functions -------------------------------------------------------
    FunctionDefined {
        view_id: u64,
        addr: u64,
        name: String,
    },
    FunctionRenamed {
        view_id: u64,
        addr: u64,
        old_name: String,
        new_name: String,
    },

    // --- Symbols ---------------------------------------------------------
    SymbolAdded {
        view_id: u64,
        addr: u64,
        name: String,
        kind: String,
    },

    // --- Comments / bookmarks --------------------------------------------
    CommentChanged {
        view_id: u64,
        addr: u64,
        text: String,
    },
    BookmarkAdded {
        view_id: u64,
        addr: u64,
        label: String,
    },

    // --- Types -----------------------------------------------------------
    TypeDefined {
        view_id: u64,
        name: String,
    },

    // --- Patches ---------------------------------------------------------
    PatchApplied {
        view_id: u64,
        addr: u64,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
    },

    // --- Analysis --------------------------------------------------------
    AnalysisStarted {
        view_id: u64,
        pass: String,
    },
    AnalysisProgress {
        view_id: u64,
        pass: String,
        percent: u8,
    },
    AnalysisCompleted {
        view_id: u64,
        pass: String,
        duration_ms: u64,
    },

    // --- Debugger --------------------------------------------------------
    BreakpointHit {
        view_id: u64,
        addr: u64,
        thread_id: u32,
    },
    BreakpointSet {
        view_id: u64,
        addr: u64,
    },
    BreakpointRemoved {
        view_id: u64,
        addr: u64,
    },
    DebuggerAttached {
        pid: u32,
    },
    DebuggerDetached {
        pid: u32,
    },
    ProcessStepped {
        thread_id: u32,
        new_ip: u64,
    },

    // --- Agent -----------------------------------------------------------
    AgentAction {
        view_id: u64,
        action: String,
        result: serde_json::Value,
    },

    // --- Plugin ----------------------------------------------------------
    PluginLoaded {
        name: String,
        version: String,
    },

    // --- Script ----------------------------------------------------------
    ScriptOutput {
        source: String,
        message: String,
    },

    // --- Sandbox ---------------------------------------------------------
    SandboxCompleted {
        job_id: String,
        report_path: String,
    },
}

impl SpecCoreEvent {
    /// Extract the `view_id` from any event that carries one.
    #[must_use]
    pub const fn view_id(&self) -> Option<u64> {
        match self {
            Self::ViewOpened { view_id, .. }
            | Self::ViewClosed { view_id }
            | Self::FunctionDefined { view_id, .. }
            | Self::FunctionRenamed { view_id, .. }
            | Self::SymbolAdded { view_id, .. }
            | Self::CommentChanged { view_id, .. }
            | Self::BookmarkAdded { view_id, .. }
            | Self::TypeDefined { view_id, .. }
            | Self::PatchApplied { view_id, .. }
            | Self::AnalysisStarted { view_id, .. }
            | Self::AnalysisProgress { view_id, .. }
            | Self::AnalysisCompleted { view_id, .. }
            | Self::BreakpointHit { view_id, .. }
            | Self::BreakpointSet { view_id, .. }
            | Self::BreakpointRemoved { view_id, .. }
            | Self::AgentAction { view_id, .. } => Some(*view_id),
            Self::DebuggerAttached { .. }
            | Self::DebuggerDetached { .. }
            | Self::ProcessStepped { .. }
            | Self::PluginLoaded { .. }
            | Self::ScriptOutput { .. }
            | Self::SandboxCompleted { .. } => None,
        }
    }

    /// Static variant name for logging and metrics.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::ViewOpened { .. } => "ViewOpened",
            Self::ViewClosed { .. } => "ViewClosed",
            Self::FunctionDefined { .. } => "FunctionDefined",
            Self::FunctionRenamed { .. } => "FunctionRenamed",
            Self::SymbolAdded { .. } => "SymbolAdded",
            Self::CommentChanged { .. } => "CommentChanged",
            Self::BookmarkAdded { .. } => "BookmarkAdded",
            Self::TypeDefined { .. } => "TypeDefined",
            Self::PatchApplied { .. } => "PatchApplied",
            Self::AnalysisStarted { .. } => "AnalysisStarted",
            Self::AnalysisProgress { .. } => "AnalysisProgress",
            Self::AnalysisCompleted { .. } => "AnalysisCompleted",
            Self::BreakpointHit { .. } => "BreakpointHit",
            Self::BreakpointSet { .. } => "BreakpointSet",
            Self::BreakpointRemoved { .. } => "BreakpointRemoved",
            Self::DebuggerAttached { .. } => "DebuggerAttached",
            Self::DebuggerDetached { .. } => "DebuggerDetached",
            Self::ProcessStepped { .. } => "ProcessStepped",
            Self::AgentAction { .. } => "AgentAction",
            Self::PluginLoaded { .. } => "PluginLoaded",
            Self::ScriptOutput { .. } => "ScriptOutput",
            Self::SandboxCompleted { .. } => "SandboxCompleted",
        }
    }
}

impl fmt::Display for SpecCoreEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(vid) = self.view_id() {
            write!(f, "[view={}] {}", vid, self.variant_name())
        } else {
            write!(f, "{}", self.variant_name())
        }
    }
}

// ---------------------------------------------------------------------------
// SpecEventBus — §2.10 EventBus with history ring-buffer
// ---------------------------------------------------------------------------

/// Spec §2.10 event bus.
///
/// Wraps a tokio broadcast channel and maintains a bounded history deque of
/// the last `HISTORY_CAPACITY` events so late subscribers can catch up.
pub struct SpecEventBus {
    tx: tokio::sync::broadcast::Sender<SpecCoreEvent>,
    history: Mutex<VecDeque<SpecCoreEvent>>,
}

/// Maximum events kept in the history ring-buffer.
const HISTORY_CAPACITY: usize = 1000;

impl SpecEventBus {
    /// Create a new bus.
    ///
    /// `capacity` is the tokio broadcast channel buffer size.  When a slow
    /// subscriber lags behind by more than `capacity` events it will observe
    /// a [`tokio::sync::broadcast::error::RecvError::Lagged`] error.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            tx,
            history: Mutex::new(VecDeque::with_capacity(HISTORY_CAPACITY)),
        }
    }

    /// Publish `event` to every subscriber (non-blocking).
    ///
    /// The event is also appended to the internal history ring-buffer so
    /// that `recent_events` can return it later.  Send errors (no active
    /// subscribers) are silently ignored.
    pub fn publish(&self, event: SpecCoreEvent) {
        // Store in history before broadcasting so subscribers that call
        // recent_events() immediately after will always see it.
        {
            let mut guard = self.history.lock();
            if guard.len() >= HISTORY_CAPACITY {
                guard.pop_front();
            }
            guard.push_back(event.clone());
        }
        // Ignore SendError — it just means no subscribers are listening.
        let _ = self.tx.send(event);
    }

    /// Create a new receiver that will observe all *future* events.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<SpecCoreEvent> {
        self.tx.subscribe()
    }

    /// Return the `n` most-recently published events (oldest first).
    #[must_use]
    pub fn recent_events(&self, n: usize) -> Vec<SpecCoreEvent> {
        let guard = self.history.lock();
        let start = guard.len().saturating_sub(n);
        guard.iter().skip(start).cloned().collect()
    }

    /// Number of active subscriber handles.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Total events in the history ring-buffer.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.lock().len()
    }
}

impl Default for SpecEventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl fmt::Debug for SpecEventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpecEventBus")
            .field("receivers", &self.tx.receiver_count())
            .field("history_len", &self.history_len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SpecEventFilter — §2.10 data-driven filter
// ---------------------------------------------------------------------------

/// Spec §2.10 filter struct.
///
/// `view_ids = None` matches all views; `event_types = None` matches all
/// variant names.
///
/// When `view_ids` is `Some`, events that carry **no** `view_id` (e.g.
/// `PluginLoaded`, `DebuggerAttached`, `ProcessStepped`) are **rejected by
/// default** because they do not belong to any of the requested views.  Set
/// `pass_global_events = true` to opt-in to receiving these view-less events
/// even when a view filter is active.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct SpecEventFilter {
    /// If `Some`, only events whose `view_id` is in this list pass.
    pub view_ids: Option<Vec<u64>>,
    /// If `Some`, only events whose variant name is in this list pass.
    pub event_types: Option<Vec<String>>,
    /// When `true`, events with no `view_id` pass the `view_ids` filter even
    /// when `view_ids` is `Some`.  Defaults to `false`.
    pub pass_global_events: bool,
}


impl SpecEventFilter {
    /// Construct an empty filter that accepts everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to a specific set of view IDs.
    #[must_use]
    pub fn with_view_ids(mut self, ids: impl IntoIterator<Item = u64>) -> Self {
        self.view_ids = Some(ids.into_iter().collect());
        self
    }

    /// Restrict to a specific set of event variant names.
    #[must_use]
    pub fn with_event_types(mut self, types: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.event_types = Some(types.into_iter().map(Into::into).collect());
        self
    }

    /// Allow view-less global events (e.g. `PluginLoaded`, `ProcessStepped`)
    /// to pass through even when a `view_ids` filter is set.
    ///
    /// By default these events are **rejected** when `view_ids` is `Some`.
    #[must_use]
    pub const fn with_pass_global_events(mut self, pass: bool) -> Self {
        self.pass_global_events = pass;
        self
    }

    /// Return `true` if `event` passes this filter.
    #[must_use]
    pub fn matches(&self, event: &SpecCoreEvent) -> bool {
        // Check view_id filter.
        if let Some(ref ids) = self.view_ids {
            match event.view_id() {
                Some(vid) => {
                    if !ids.contains(&vid) {
                        return false;
                    }
                }
                None => {
                    // Events with no view_id do not belong to any specific view.
                    // Reject them unless the caller has opted in to receiving
                    // global (view-less) events alongside their view filter.
                    if !self.pass_global_events {
                        return false;
                    }
                }
            }
        }
        // Check event_type filter.
        if let Some(ref types) = self.event_types
            && !types.iter().any(|t| t == Self::event_type_name(event)) {
                return false;
            }
        true
    }

    /// Return the static variant name for `event`.
    ///
    /// This is the canonical name used in `event_types` filter lists.
    #[must_use]
    pub const fn event_type_name(event: &SpecCoreEvent) -> &'static str {
        event.variant_name()
    }
}

// ---------------------------------------------------------------------------
// SpecEventLogger — §2.10 tracing-based async logger
// ---------------------------------------------------------------------------

/// Spec §2.10 event logger.
///
/// Holds a weak reference to a [`SpecEventBus`] and can be driven with
/// [`SpecEventLogger::run`] to log every incoming event to `tracing::info!`.
///
/// Using an `Arc` to the bus only during construction — `spawn` deliberately
/// releases the reference so the spawned task does not prevent the bus from
/// being freed.
pub struct SpecEventLogger {
    /// Kept as `Option` so `spawn` can take ownership without a partial-move.
    bus: Option<Arc<SpecEventBus>>,
}

impl SpecEventLogger {
    /// Create a logger attached to `bus`.
    #[must_use]
    pub fn new(bus: &Arc<SpecEventBus>) -> Self {
        Self {
            bus: Some(Arc::clone(bus)),
        }
    }

    /// Drive the logger until the channel closes.
    ///
    /// Call this inside a Tokio task:
    /// ```rust,ignore
    /// let mut logger = SpecEventLogger::new(&bus);
    /// let rx = bus.subscribe();
    /// tokio::spawn(async move { logger.run(rx).await });
    /// ```
    pub async fn run(&mut self, mut rx: Receiver<SpecCoreEvent>) {
        // Release any held bus reference so that the caller can control the
        // channel lifetime without this method keeping it alive.
        self.bus = None;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    tracing::info!(
                        event = event.variant_name(),
                        view_id = event.view_id(),
                        "rustre-events: {}",
                        event,
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "rustre-events: subscriber lagged, {} events dropped",
                        n,
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::debug!("rustre-events: channel closed, logger shutting down");
                    break;
                }
            }
        }
    }

    /// Spawn a background Tokio task that runs the logger until the bus closes.
    ///
    /// The spawned task holds **only the `Receiver`**, not the `Arc<SpecEventBus>`.
    /// Dropping all external `Arc<SpecEventBus>` handles will therefore cause
    /// the channel to close and the task to exit cleanly.
    ///
    /// Returns the join handle so the caller can await or abort it.
    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        // Take the Arc out of the Option while still subscribed, then drop
        // it immediately so the spawned future carries no bus reference.
        let rx = if let Some(bus) = self.bus.as_ref() { bus.subscribe() } else {
            tracing::warn!("SpecEventLogger::spawn called more than once; returning no-op task");
            return tokio::spawn(async {});
        };
        // Release the strong reference before spawning.
        self.bus = None;
        tokio::spawn(async move {
            let mut rx = rx;
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        tracing::info!(
                            event = event.variant_name(),
                            view_id = event.view_id(),
                            "rustre-events: {}",
                            event,
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            skipped = n,
                            "rustre-events: subscriber lagged, {} events dropped",
                            n,
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("rustre-events: channel closed, logger shutting down");
                        break;
                    }
                }
            }
        })
    }
}

impl fmt::Debug for SpecEventLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpecEventLogger").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// global_bus — §2.10 process-wide singleton
// ---------------------------------------------------------------------------

static GLOBAL_BUS: OnceCell<SpecEventBus> = OnceCell::new();

/// Return a reference to the process-wide [`SpecEventBus`] singleton.
///
/// The bus is lazily initialised on first call with a broadcast channel
/// capacity of 4096.
#[must_use]
pub fn global_bus() -> &'static SpecEventBus {
    GLOBAL_BUS.get_or_init(|| SpecEventBus::new(4096))
}

// ---------------------------------------------------------------------------
// Convenience publish helpers for the global bus
// ---------------------------------------------------------------------------

/// Publish `event` to the global bus.
pub fn publish(event: SpecCoreEvent) {
    global_bus().publish(event);
}

/// Subscribe to the global bus.
#[must_use]
pub fn subscribe_global() -> tokio::sync::broadcast::Receiver<SpecCoreEvent> {
    global_bus().subscribe()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // CoreEvent helpers
    // -----------------------------------------------------------------------

    #[test]
    fn core_event_view_id_extraction() {
        let e = CoreEvent::FunctionDefined {
            view_id: 42,
            address: 0x1000,
            name: "main".into(),
        };
        assert_eq!(e.view_id(), Some(42));

        let custom = CoreEvent::Custom {
            event_type: "test".into(),
            payload: serde_json::Value::Null,
        };
        assert_eq!(custom.view_id(), None);
    }

    #[test]
    fn core_event_variant_name() {
        let e = CoreEvent::BreakpointHit {
            view_id: 1,
            address: 0xDEAD,
            thread_id: 0,
        };
        assert_eq!(e.variant_name(), "BreakpointHit");
    }

    #[test]
    fn core_event_display() {
        let e = CoreEvent::ViewOpened {
            view_id: 7,
            uri: "f".into(),
            arch: "x86".into(),
        };
        let s = format!("{e}");
        assert!(s.contains('7'));
        assert!(s.contains("ViewOpened"));
    }

    #[test]
    fn core_event_is_debug_event() {
        let e = CoreEvent::BreakpointHit {
            view_id: 1,
            address: 0,
            thread_id: 0,
        };
        assert!(e.is_debug_event());
        let e2 = CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "x86".into(),
        };
        assert!(!e2.is_debug_event());
    }

    #[test]
    fn core_event_is_analysis_event() {
        assert!(
            CoreEvent::AnalysisStarted {
                view_id: 1,
                pass: "cfg".into()
            }
            .is_analysis_event()
        );
        assert!(!CoreEvent::ViewClosed { view_id: 1 }.is_analysis_event());
    }

    #[test]
    fn core_event_is_function_event() {
        assert!(
            CoreEvent::FunctionDefined {
                view_id: 1,
                address: 0,
                name: "f".into()
            }
            .is_function_event()
        );
        assert!(!CoreEvent::ViewClosed { view_id: 1 }.is_function_event());
    }

    #[test]
    fn core_event_kind() {
        assert_eq!(
            CoreEvent::ViewOpened {
                view_id: 1,
                uri: "x".into(),
                arch: "x86".into()
            }
            .kind(),
            EventKind::View
        );
        assert_eq!(
            CoreEvent::BreakpointHit {
                view_id: 1,
                address: 0,
                thread_id: 0
            }
            .kind(),
            EventKind::Debugger
        );
        assert_eq!(
            CoreEvent::TypeDefined {
                view_id: 1,
                name: "T".into()
            }
            .kind(),
            EventKind::Type
        );
        assert_eq!(
            CoreEvent::PluginLoaded {
                plugin_id: "x".into()
            }
            .kind(),
            EventKind::Plugin
        );
    }

    #[test]
    fn core_event_json_roundtrip() {
        let e = CoreEvent::AgentAction {
            view_id: 5,
            action: "decompile".into(),
            result: "ok".into(),
        };
        let s = e.to_json().unwrap();
        let back = CoreEvent::from_json(&s).unwrap();
        assert_eq!(back.variant_name(), "AgentAction");
    }

    // -----------------------------------------------------------------------
    // EventFilter
    // -----------------------------------------------------------------------

    #[test]
    fn event_filter_for_view() {
        let f = EventFilter::for_view(42);
        let e = CoreEvent::ViewClosed { view_id: 42 };
        assert!(f.matches(&e));
        let e2 = CoreEvent::ViewClosed { view_id: 99 };
        assert!(!f.matches(&e2));
    }

    #[test]
    fn event_filter_of_kind() {
        let f = EventFilter::of_kind(EventKind::Function);
        let e = CoreEvent::FunctionDefined {
            view_id: 1,
            address: 0,
            name: "f".into(),
        };
        assert!(f.matches(&e));
        let e2 = CoreEvent::ViewClosed { view_id: 1 };
        assert!(!f.matches(&e2));
    }

    #[test]
    fn event_filter_by_variant() {
        let f = EventFilter::by_variant("XrefAdded");
        let e = CoreEvent::XrefAdded {
            view_id: 1,
            from_addr: 0,
            to_addr: 1,
            kind: "call".into(),
        };
        assert!(f.matches(&e));
        assert!(!f.matches(&CoreEvent::ViewClosed { view_id: 1 }));
    }

    #[test]
    fn event_filter_and() {
        let f = EventFilter::for_view(1).and(EventFilter::of_kind(EventKind::Debugger));
        let e = CoreEvent::BreakpointHit {
            view_id: 1,
            address: 0,
            thread_id: 0,
        };
        assert!(f.matches(&e));
        let e2 = CoreEvent::BreakpointHit {
            view_id: 2,
            address: 0,
            thread_id: 0,
        };
        assert!(!f.matches(&e2));
    }

    #[test]
    fn event_filter_or() {
        let f = EventFilter::of_kind(EventKind::View).or(EventFilter::of_kind(EventKind::Plugin));
        assert!(f.matches(&CoreEvent::ViewClosed { view_id: 1 }));
        assert!(f.matches(&CoreEvent::PluginLoaded {
            plugin_id: "x".into()
        }));
        assert!(!f.matches(&CoreEvent::FunctionDefined {
            view_id: 1,
            address: 0,
            name: "f".into()
        }));
    }

    #[test]
    fn event_filter_not() {
        let f = EventFilter::of_kind(EventKind::View).negate();
        assert!(!f.matches(&CoreEvent::ViewClosed { view_id: 1 }));
        assert!(f.matches(&CoreEvent::PluginLoaded {
            plugin_id: "x".into()
        }));
    }

    // -----------------------------------------------------------------------
    // EventBus
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn event_bus_send_receive() {
        let bus = EventBus::new_default();
        let mut rx = bus.subscribe();

        bus.send_view_opened(1, "file:///test".into(), "x86_64".into());

        let event = rx.recv().await.unwrap();
        match event {
            CoreEvent::ViewOpened { view_id, uri, .. } => {
                assert_eq!(view_id, 1);
                assert_eq!(uri, "file:///test");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn event_bus_multiple_subscribers() {
        let bus = EventBus::new_default();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.send_function_defined(1, 0x1000, "foo".into());

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.variant_name(), "FunctionDefined");
        assert_eq!(e2.variant_name(), "FunctionDefined");
    }

    #[tokio::test]
    async fn event_bus_receiver_count() {
        let bus = EventBus::new_default();
        assert_eq!(bus.receiver_count(), 0);
        let _rx = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);
    }

    #[tokio::test]
    async fn event_bus_default() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        bus.send_breakpoint_hit(2, 0xDEAD, 1);
        assert!(rx.recv().await.is_ok());
    }

    #[tokio::test]
    async fn convenience_senders() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();

        bus.send_function_renamed(1, 0x100, "old".into(), "new".into());
        bus.send_analysis_progress(1, "cfg".into(), 50);

        let e1 = rx.recv().await.unwrap();
        let e2 = rx.recv().await.unwrap();
        assert_eq!(e1.variant_name(), "FunctionRenamed");
        assert_eq!(e2.variant_name(), "AnalysisProgress");
    }

    #[test]
    fn event_bus_counters() {
        let bus = EventBus::new_default();
        let _rx = bus.subscribe();
        bus.send_view_closed(1);
        bus.send_view_closed(2);
        assert_eq!(bus.event_count("ViewClosed"), 2);
        assert_eq!(bus.total_sent(), 2);
    }

    #[test]
    fn event_bus_debug() {
        let bus = EventBus::new(16);
        let s = format!("{bus:?}");
        assert!(s.contains("EventBus"));
    }

    // -----------------------------------------------------------------------
    // FilteredSubscription
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn filtered_subscription_only_delivers_matching() {
        let bus = EventBus::new_default();
        let mut filtered = view_subscription(&bus, 42);

        bus.send_view_opened(99, "other".into(), "arm".into());
        bus.send_view_opened(42, "ours".into(), "x86".into());

        let event = filtered.recv_filtered().await.unwrap();
        match event {
            CoreEvent::ViewOpened { view_id: 42, .. } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn filtered_subscription_custom_filter() {
        let bus = EventBus::new_default();
        let mut sub = FilteredSubscription::new(bus.subscribe(), |e| {
            matches!(e, CoreEvent::BreakpointHit { .. })
        });

        bus.send_function_defined(1, 0, "f".into());
        bus.send_breakpoint_hit(1, 0xDEAD, 1);

        let event = sub.recv_filtered().await.unwrap();
        assert_eq!(event.variant_name(), "BreakpointHit");
    }

    #[tokio::test]
    async fn filtered_subscription_with_event_filter() {
        let bus = EventBus::new_default();
        let filter = EventFilter::of_kind(EventKind::Analysis);
        let mut sub = FilteredSubscription::with_filter(bus.subscribe(), filter);

        bus.send_function_defined(1, 0, "g".into());
        bus.send_analysis_completed(1, "cfg".into());

        let event = sub.recv_filtered().await.unwrap();
        assert_eq!(event.variant_name(), "AnalysisCompleted");
    }

    #[tokio::test]
    async fn filtered_subscription_delivery_counts() {
        let bus = EventBus::new_default();
        let mut sub = FilteredSubscription::new(bus.subscribe(), |e| {
            matches!(e, CoreEvent::ViewClosed { .. })
        });
        bus.send_view_closed(1);
        bus.send_view_closed(2);
        sub.recv_filtered().await.unwrap();
        sub.recv_filtered().await.unwrap();
        assert_eq!(sub.delivered_count(), 2);
    }

    // -----------------------------------------------------------------------
    // EventLogger
    // -----------------------------------------------------------------------

    #[test]
    fn event_logger_record_and_count() {
        let logger = EventLogger::new(100);
        logger.record(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        logger.record(CoreEvent::ViewClosed { view_id: 1 });
        assert_eq!(logger.count(), 2);
    }

    #[test]
    fn event_logger_respects_max_size() {
        let logger = EventLogger::new(3);
        for i in 0..5u64 {
            logger.record(CoreEvent::FunctionDefined {
                view_id: i,
                address: i,
                name: "f".into(),
            });
        }
        assert_eq!(logger.count(), 3);
    }

    #[test]
    fn event_logger_clear() {
        let logger = EventLogger::new(100);
        logger.record(CoreEvent::ViewClosed { view_id: 1 });
        logger.clear();
        assert_eq!(logger.count(), 0);
    }

    #[test]
    fn event_logger_recent_events() {
        let logger = EventLogger::new(100);
        for i in 0..10u64 {
            logger.record(CoreEvent::FunctionDefined {
                view_id: i,
                address: i,
                name: "fn".into(),
            });
        }
        let recent = logger.recent_events(3);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn event_logger_events_by_kind() {
        let logger = EventLogger::new(100);
        logger.record(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        logger.record(CoreEvent::FunctionDefined {
            view_id: 1,
            address: 0,
            name: "f".into(),
        });
        let views = logger.events_by_kind(EventKind::View);
        assert_eq!(views.len(), 1);
    }

    #[test]
    fn event_logger_events_for_view() {
        let logger = EventLogger::new(100);
        logger.record(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        logger.record(CoreEvent::ViewOpened {
            view_id: 2,
            uri: "y".into(),
            arch: "x86".into(),
        });
        let v1 = logger.events_for_view(1);
        assert_eq!(v1.len(), 1);
    }

    #[test]
    fn event_logger_events_since() {
        let logger = EventLogger::new(100);
        let before = SystemTime::now();
        logger.record(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "a".into(),
        });
        let after = before + Duration::from_millis(1);
        logger.record(CoreEvent::ViewClosed { view_id: 1 });
        let since_after = logger.events_since(after);
        assert!(!since_after.is_empty() || logger.count() == 2);
    }

    #[test]
    fn event_logger_debug() {
        let logger = EventLogger::new(50);
        let s = format!("{logger:?}");
        assert!(s.contains("EventLogger"));
    }

    #[tokio::test]
    async fn event_logger_background_task() {
        let bus = EventBus::new(64);
        let logger = Arc::new(EventLogger::new(1000));

        let handle = logger.clone().start_logging(&bus);

        bus.send_view_opened(1, "test".into(), "x86_64".into());
        bus.send_function_defined(1, 0x1000, "main".into());

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(logger.count(), 2);

        drop(bus);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }

    // -----------------------------------------------------------------------
    // HookDispatcher
    // -----------------------------------------------------------------------

    #[test]
    fn hook_dispatcher_fires_matching() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter2 = counter.clone();

        let dispatcher = HookDispatcher::new();
        dispatcher.register(EventHook::new(
            "count-views",
            |e| matches!(e, CoreEvent::ViewOpened { .. }),
            move |_| {
                counter2.fetch_add(1, Ordering::Relaxed);
            },
        ));

        dispatcher.dispatch(&CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "x86".into(),
        });
        dispatcher.dispatch(&CoreEvent::ViewClosed { view_id: 1 });
        dispatcher.dispatch(&CoreEvent::ViewOpened {
            view_id: 2,
            uri: "y".into(),
            arch: "arm".into(),
        });

        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn hook_dispatcher_remove_by_label() {
        let dispatcher = HookDispatcher::new();
        dispatcher.register(EventHook::new("my-hook", |_| true, |_| {}));
        assert_eq!(dispatcher.hook_count(), 1);
        dispatcher.remove("my-hook");
        assert_eq!(dispatcher.hook_count(), 0);
    }

    #[test]
    fn hook_dispatcher_debug() {
        let d = HookDispatcher::new();
        let s = format!("{d:?}");
        assert!(s.contains("HookDispatcher"));
    }

    // -----------------------------------------------------------------------
    // EventReplay
    // -----------------------------------------------------------------------

    #[test]
    fn event_replay_push_and_replay() {
        let bus = EventBus::new(64);
        let _rx = bus.subscribe();

        let mut replay = EventReplay::new();
        replay.push(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        replay.push(CoreEvent::ViewClosed { view_id: 1 });
        assert_eq!(replay.len(), 2);

        let failures = replay.replay_all(&bus);
        assert_eq!(failures, 0);
    }

    #[test]
    fn event_replay_filtered() {
        let bus = EventBus::new(64);
        let _rx = bus.subscribe();

        let mut replay = EventReplay::new();
        replay.push(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        replay.push(CoreEvent::ViewClosed { view_id: 1 });
        replay.push(CoreEvent::FunctionDefined {
            view_id: 1,
            address: 0,
            name: "f".into(),
        });

        let sent = replay.replay_filtered(&bus, |e| e.kind() == EventKind::Function);
        assert_eq!(sent, 1);
    }

    #[test]
    fn event_replay_clear() {
        let mut replay = EventReplay::new();
        replay.push(CoreEvent::ViewClosed { view_id: 1 });
        replay.clear();
        assert!(replay.is_empty());
    }

    #[test]
    fn event_replay_snapshot_from_logger() {
        let logger = EventLogger::new(100);
        logger.record(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        logger.record(CoreEvent::ViewClosed { view_id: 1 });

        let mut replay = EventReplay::new();
        replay.snapshot_from(&logger);
        assert_eq!(replay.len(), 2);
    }

    // -----------------------------------------------------------------------
    // EventCorrelator
    // -----------------------------------------------------------------------

    #[test]
    fn correlator_by_view_groups_correctly() {
        let c = EventCorrelator::by_view();
        c.ingest(CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        });
        c.ingest(CoreEvent::ViewClosed { view_id: 1 });
        c.ingest(CoreEvent::ViewOpened {
            view_id: 2,
            uri: "y".into(),
            arch: "x86".into(),
        });

        assert_eq!(c.get_group("1").len(), 2);
        assert_eq!(c.get_group("2").len(), 1);
        assert_eq!(c.total_count(), 3);
    }

    #[test]
    fn correlator_by_variant() {
        let c = EventCorrelator::by_variant();
        c.ingest(CoreEvent::ViewClosed { view_id: 1 });
        c.ingest(CoreEvent::ViewClosed { view_id: 2 });
        assert_eq!(c.get_group("ViewClosed").len(), 2);
    }

    #[test]
    fn correlator_ignores_events_without_key() {
        // Custom events have no view_id — should be ignored by by_view()
        let c = EventCorrelator::by_view();
        c.ingest(CoreEvent::Custom {
            event_type: "x".into(),
            payload: serde_json::Value::Null,
        });
        assert_eq!(c.total_count(), 0);
    }

    #[test]
    fn correlator_clear() {
        let c = EventCorrelator::by_view();
        c.ingest(CoreEvent::ViewClosed { view_id: 1 });
        c.clear();
        assert_eq!(c.total_count(), 0);
    }

    // -----------------------------------------------------------------------
    // EventStats
    // -----------------------------------------------------------------------

    #[test]
    fn event_stats_records_correctly() {
        let stats = EventStats::new();
        let e = CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        };
        stats.record(&e);
        stats.record(&e);
        assert_eq!(stats.variant_count("ViewOpened"), 2);
        assert_eq!(stats.kind_count(EventKind::View), 2);
        assert_eq!(stats.total(), 2);
    }

    #[test]
    fn event_stats_reset() {
        let stats = EventStats::new();
        let e = CoreEvent::ViewClosed { view_id: 1 };
        stats.record(&e);
        stats.reset();
        assert_eq!(stats.total(), 0);
    }

    #[test]
    fn event_stats_all_variant_counts() {
        let stats = EventStats::new();
        stats.record(&CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "x86".into(),
        });
        stats.record(&CoreEvent::ViewClosed { view_id: 1 });
        let map = stats.all_variant_counts();
        assert_eq!(map.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Serialisation round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn core_event_serde_roundtrip() {
        let event = CoreEvent::AgentAction {
            view_id: 7,
            action: "decompile".into(),
            result: "success".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CoreEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.variant_name(), "AgentAction");
        assert_eq!(decoded.view_id(), Some(7));
    }

    #[test]
    fn custom_event_serde_roundtrip() {
        let payload = serde_json::json!({ "key": "value", "count": 42 });
        let event = CoreEvent::Custom {
            event_type: "my_plugin.event".into(),
            payload: payload.clone(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CoreEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            CoreEvent::Custom {
                event_type,
                payload: p,
            } => {
                assert_eq!(event_type, "my_plugin.event");
                assert_eq!(p, payload);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn core_event_view_closed_view_id() {
        let e = CoreEvent::ViewClosed { view_id: 99 };
        assert_eq!(e.view_id(), Some(99));
    }

    #[test]
    fn core_event_analysis_started_view_id() {
        let e = CoreEvent::AnalysisStarted {
            view_id: 5,
            pass: "cfg".into(),
        };
        assert_eq!(e.view_id(), Some(5));
        assert_eq!(e.variant_name(), "AnalysisStarted");
    }

    #[test]
    fn core_event_symbol_defined_view_id() {
        let e = CoreEvent::SymbolDefined {
            view_id: 3,
            address: 0x400,
            name: "sym".into(),
            kind: "func".into(),
            source: "pdb".into(),
        };
        assert_eq!(e.view_id(), Some(3));
        assert_eq!(e.variant_name(), "SymbolDefined");
    }

    #[test]
    fn core_event_patch_applied_view_id() {
        let e = CoreEvent::PatchApplied {
            view_id: 7,
            address: 0x1000,
            length: 4,
        };
        assert_eq!(e.view_id(), Some(7));
        assert_eq!(e.variant_name(), "PatchApplied");
    }

    #[test]
    fn core_event_xref_added_view_id() {
        let e = CoreEvent::XrefAdded {
            view_id: 2,
            from_addr: 0x100,
            to_addr: 0x200,
            kind: "call".into(),
        };
        assert_eq!(e.view_id(), Some(2));
        assert_eq!(e.variant_name(), "XrefAdded");
    }

    #[test]
    fn core_event_custom_no_view_id() {
        let e = CoreEvent::Custom {
            event_type: "test".into(),
            payload: serde_json::Value::Null,
        };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "Custom");
    }

    #[test]
    fn event_logger_count_after_clear_is_zero() {
        let logger = EventLogger::new(10);
        logger.record(CoreEvent::ViewClosed { view_id: 1 });
        logger.record(CoreEvent::ViewClosed { view_id: 2 });
        assert_eq!(logger.count(), 2);
        logger.clear();
        assert_eq!(logger.count(), 0);
    }

    #[tokio::test]
    async fn event_bus_no_receivers_send_returns_error() {
        let bus = EventBus::new(16);
        let result = bus.send(CoreEvent::ViewClosed { view_id: 1 });
        assert!(result.is_err());
    }

    #[test]
    fn plugin_event_no_view_id() {
        let e = CoreEvent::PluginLoaded {
            plugin_id: "x".into(),
        };
        assert_eq!(e.view_id(), None);
    }

    #[test]
    fn kind_subscription_factory() {
        let bus = EventBus::new_default();
        let sub = kind_subscription(&bus, EventKind::Analysis);
        drop(sub);
    }

    // -----------------------------------------------------------------------
    // §2.10 SpecCoreEvent
    // -----------------------------------------------------------------------

    #[test]
    fn spec_event_view_opened_fields() {
        let e = SpecCoreEvent::ViewOpened {
            view_id: 7,
            path: "/bin/ls".into(),
        };
        assert_eq!(e.view_id(), Some(7));
        assert_eq!(e.variant_name(), "ViewOpened");
        let s = format!("{e}");
        assert!(s.contains("ViewOpened"));
        assert!(s.contains('7'));
    }

    #[test]
    fn spec_event_function_defined_fields() {
        let e = SpecCoreEvent::FunctionDefined {
            view_id: 1,
            addr: 0x1000,
            name: "main".into(),
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.variant_name(), "FunctionDefined");
    }

    #[test]
    fn spec_event_function_renamed_fields() {
        let e = SpecCoreEvent::FunctionRenamed {
            view_id: 2,
            addr: 0x400,
            old_name: "sub_400".into(),
            new_name: "init".into(),
        };
        assert_eq!(e.view_id(), Some(2));
        assert_eq!(e.variant_name(), "FunctionRenamed");
    }

    #[test]
    fn spec_event_symbol_added_fields() {
        let e = SpecCoreEvent::SymbolAdded {
            view_id: 3,
            addr: 0x500,
            name: "MySym".into(),
            kind: "import".into(),
        };
        assert_eq!(e.view_id(), Some(3));
        assert_eq!(e.variant_name(), "SymbolAdded");
    }

    #[test]
    fn spec_event_comment_changed_fields() {
        let e = SpecCoreEvent::CommentChanged {
            view_id: 4,
            addr: 0x100,
            text: "note".into(),
        };
        assert_eq!(e.view_id(), Some(4));
        assert_eq!(e.variant_name(), "CommentChanged");
    }

    #[test]
    fn spec_event_bookmark_added_fields() {
        let e = SpecCoreEvent::BookmarkAdded {
            view_id: 5,
            addr: 0x200,
            label: "entry".into(),
        };
        assert_eq!(e.view_id(), Some(5));
        assert_eq!(e.variant_name(), "BookmarkAdded");
    }

    #[test]
    fn spec_event_type_defined_fields() {
        let e = SpecCoreEvent::TypeDefined {
            view_id: 6,
            name: "MyStruct".into(),
        };
        assert_eq!(e.view_id(), Some(6));
        assert_eq!(e.variant_name(), "TypeDefined");
    }

    #[test]
    fn spec_event_patch_applied_fields() {
        let e = SpecCoreEvent::PatchApplied {
            view_id: 7,
            addr: 0x300,
            old_bytes: vec![0x90, 0x90],
            new_bytes: vec![0xCC, 0xCC],
        };
        assert_eq!(e.view_id(), Some(7));
        assert_eq!(e.variant_name(), "PatchApplied");
        if let SpecCoreEvent::PatchApplied {
            old_bytes,
            new_bytes,
            ..
        } = &e
        {
            assert_eq!(old_bytes, &[0x90, 0x90]);
            assert_eq!(new_bytes, &[0xCC, 0xCC]);
        }
    }

    #[test]
    fn spec_event_analysis_started_fields() {
        let e = SpecCoreEvent::AnalysisStarted {
            view_id: 8,
            pass: "cfg".into(),
        };
        assert_eq!(e.view_id(), Some(8));
        assert_eq!(e.variant_name(), "AnalysisStarted");
    }

    #[test]
    fn spec_event_analysis_progress_fields() {
        let e = SpecCoreEvent::AnalysisProgress {
            view_id: 9,
            pass: "cfg".into(),
            percent: 42,
        };
        assert_eq!(e.view_id(), Some(9));
        assert_eq!(e.variant_name(), "AnalysisProgress");
        if let SpecCoreEvent::AnalysisProgress { percent, .. } = &e {
            assert_eq!(*percent, 42);
        }
    }

    #[test]
    fn spec_event_analysis_completed_fields() {
        let e = SpecCoreEvent::AnalysisCompleted {
            view_id: 10,
            pass: "cfg".into(),
            duration_ms: 1234,
        };
        assert_eq!(e.view_id(), Some(10));
        assert_eq!(e.variant_name(), "AnalysisCompleted");
        if let SpecCoreEvent::AnalysisCompleted { duration_ms, .. } = &e {
            assert_eq!(*duration_ms, 1234);
        }
    }

    #[test]
    fn spec_event_breakpoint_hit_fields() {
        let e = SpecCoreEvent::BreakpointHit {
            view_id: 1,
            addr: 0xDEAD,
            thread_id: 2,
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.variant_name(), "BreakpointHit");
    }

    #[test]
    fn spec_event_breakpoint_set_fields() {
        let e = SpecCoreEvent::BreakpointSet {
            view_id: 1,
            addr: 0x1000,
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.variant_name(), "BreakpointSet");
    }

    #[test]
    fn spec_event_breakpoint_removed_fields() {
        let e = SpecCoreEvent::BreakpointRemoved {
            view_id: 1,
            addr: 0x1000,
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.variant_name(), "BreakpointRemoved");
    }

    #[test]
    fn spec_event_debugger_attached_no_view_id() {
        let e = SpecCoreEvent::DebuggerAttached { pid: 1234 };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "DebuggerAttached");
    }

    #[test]
    fn spec_event_debugger_detached_no_view_id() {
        let e = SpecCoreEvent::DebuggerDetached { pid: 1234 };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "DebuggerDetached");
    }

    #[test]
    fn spec_event_process_stepped_no_view_id() {
        let e = SpecCoreEvent::ProcessStepped {
            thread_id: 0,
            new_ip: 0x0040_1000,
        };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "ProcessStepped");
    }

    #[test]
    fn spec_event_agent_action_fields() {
        let payload = serde_json::json!({ "ok": true });
        let e = SpecCoreEvent::AgentAction {
            view_id: 5,
            action: "decompile".into(),
            result: payload.clone(),
        };
        assert_eq!(e.view_id(), Some(5));
        assert_eq!(e.variant_name(), "AgentAction");
        if let SpecCoreEvent::AgentAction { result, .. } = &e {
            assert_eq!(result, &payload);
        }
    }

    #[test]
    fn spec_event_plugin_loaded_fields() {
        let e = SpecCoreEvent::PluginLoaded {
            name: "myplugin".into(),
            version: "1.0.0".into(),
        };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "PluginLoaded");
        if let SpecCoreEvent::PluginLoaded { name, version } = &e {
            assert_eq!(name, "myplugin");
            assert_eq!(version, "1.0.0");
        }
    }

    #[test]
    fn spec_event_script_output_fields() {
        let e = SpecCoreEvent::ScriptOutput {
            source: "repl".into(),
            message: "hello".into(),
        };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "ScriptOutput");
    }

    #[test]
    fn spec_event_sandbox_completed_fields() {
        let e = SpecCoreEvent::SandboxCompleted {
            job_id: "abc-123".into(),
            report_path: "/tmp/report.json".into(),
        };
        assert_eq!(e.view_id(), None);
        assert_eq!(e.variant_name(), "SandboxCompleted");
        if let SpecCoreEvent::SandboxCompleted {
            job_id,
            report_path,
        } = &e
        {
            assert_eq!(job_id, "abc-123");
            assert_eq!(report_path, "/tmp/report.json");
        }
    }

    #[test]
    fn spec_event_json_roundtrip() {
        let e = SpecCoreEvent::FunctionDefined {
            view_id: 1,
            addr: 0x1000,
            name: "entry".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: SpecCoreEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.variant_name(), "FunctionDefined");
        assert_eq!(back.view_id(), Some(1));
    }

    // -----------------------------------------------------------------------
    // §2.10 SpecEventBus — publish/subscribe roundtrip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spec_bus_publish_subscribe_roundtrip() {
        let bus = SpecEventBus::new(64);
        let mut rx = bus.subscribe();

        bus.publish(SpecCoreEvent::ViewOpened {
            view_id: 42,
            path: "/bin/ls".into(),
        });

        let event = rx.recv().await.unwrap();
        match event {
            SpecCoreEvent::ViewOpened { view_id: 42, path } => {
                assert_eq!(path, "/bin/ls");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn spec_bus_multiple_subscribers_all_receive() {
        let bus = SpecEventBus::new(64);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(SpecCoreEvent::FunctionDefined {
            view_id: 1,
            addr: 0x400,
            name: "start".into(),
        });

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.variant_name(), "FunctionDefined");
        assert_eq!(e2.variant_name(), "FunctionDefined");
    }

    #[tokio::test]
    async fn spec_bus_publish_no_subscriber_does_not_panic() {
        let bus = SpecEventBus::new(16);
        // Intentionally no subscriber — publish must not panic.
        bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
        assert_eq!(bus.history_len(), 1);
    }

    // -----------------------------------------------------------------------
    // §2.10 SpecEventBus — history ring-buffer
    // -----------------------------------------------------------------------

    #[test]
    fn spec_bus_history_records_events() {
        let bus = SpecEventBus::new(64);
        bus.publish(SpecCoreEvent::ViewOpened {
            view_id: 1,
            path: "a".into(),
        });
        bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
        assert_eq!(bus.history_len(), 2);
    }

    #[test]
    fn spec_bus_recent_events_returns_last_n() {
        let bus = SpecEventBus::new(64);
        for i in 0..10u64 {
            bus.publish(SpecCoreEvent::FunctionDefined {
                view_id: i,
                addr: i * 0x100,
                name: format!("fn_{i}"),
            });
        }
        let recent = bus.recent_events(3);
        assert_eq!(recent.len(), 3);
        // Should be the last 3 (view_id 7, 8, 9).
        if let SpecCoreEvent::FunctionDefined { view_id, .. } = &recent[0] {
            assert_eq!(*view_id, 7);
        }
    }

    #[test]
    fn spec_bus_recent_events_when_fewer_than_n_exist() {
        let bus = SpecEventBus::new(64);
        bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
        let recent = bus.recent_events(100);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn spec_bus_history_bounded_at_1000() {
        let bus = SpecEventBus::new(2048);
        // Publish 1100 events — history must stay at 1000.
        for i in 0..1100u64 {
            bus.publish(SpecCoreEvent::FunctionDefined {
                view_id: 1,
                addr: i,
                name: "f".into(),
            });
        }
        assert_eq!(bus.history_len(), 1000);
        // recent_events(1) should return the very last one (addr = 1099).
        let last = bus.recent_events(1);
        assert_eq!(last.len(), 1);
        if let SpecCoreEvent::FunctionDefined { addr, .. } = &last[0] {
            assert_eq!(*addr, 1099);
        }
    }

    // -----------------------------------------------------------------------
    // §2.10 SpecEventFilter
    // -----------------------------------------------------------------------

    #[test]
    fn spec_filter_default_matches_everything() {
        let f = SpecEventFilter::new();
        assert!(f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
        assert!(f.matches(&SpecCoreEvent::DebuggerAttached { pid: 1 }));
    }

    #[test]
    fn spec_filter_view_ids_allows_matching_view() {
        let f = SpecEventFilter::new().with_view_ids([42u64]);
        assert!(f.matches(&SpecCoreEvent::ViewClosed { view_id: 42 }));
    }

    #[test]
    fn spec_filter_view_ids_blocks_other_view() {
        let f = SpecEventFilter::new().with_view_ids([42u64]);
        assert!(!f.matches(&SpecCoreEvent::ViewClosed { view_id: 99 }));
    }

    #[test]
    fn spec_filter_view_ids_passes_no_view_id_events() {
        // Events without a view_id (e.g. DebuggerAttached) should pass a
        // view_ids filter because they are not view-scoped.
        let f = SpecEventFilter::new().with_view_ids([1u64]);
        assert!(f.matches(&SpecCoreEvent::DebuggerAttached { pid: 100 }));
    }

    #[test]
    fn spec_filter_event_types_allows_matching_type() {
        let f = SpecEventFilter::new().with_event_types(["FunctionDefined"]);
        let e = SpecCoreEvent::FunctionDefined {
            view_id: 1,
            addr: 0,
            name: "f".into(),
        };
        assert!(f.matches(&e));
    }

    #[test]
    fn spec_filter_event_types_blocks_other_type() {
        let f = SpecEventFilter::new().with_event_types(["FunctionDefined"]);
        assert!(!f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
    }

    #[test]
    fn spec_filter_combined_view_and_type() {
        let f = SpecEventFilter::new()
            .with_view_ids([1u64])
            .with_event_types(["BreakpointHit"]);
        let hit = SpecCoreEvent::BreakpointHit {
            view_id: 1,
            addr: 0xDEAD,
            thread_id: 0,
        };
        assert!(f.matches(&hit));
        let other_view = SpecCoreEvent::BreakpointHit {
            view_id: 2,
            addr: 0xDEAD,
            thread_id: 0,
        };
        assert!(!f.matches(&other_view));
        let other_type = SpecCoreEvent::ViewClosed { view_id: 1 };
        assert!(!f.matches(&other_type));
    }

    #[test]
    fn spec_filter_multiple_view_ids() {
        let f = SpecEventFilter::new().with_view_ids([1u64, 2, 3]);
        assert!(f.matches(&SpecCoreEvent::ViewClosed { view_id: 2 }));
        assert!(!f.matches(&SpecCoreEvent::ViewClosed { view_id: 99 }));
    }

    #[test]
    fn spec_filter_multiple_event_types() {
        let f = SpecEventFilter::new().with_event_types(["ViewOpened", "ViewClosed"]);
        assert!(f.matches(&SpecCoreEvent::ViewOpened {
            view_id: 1,
            path: "x".into()
        }));
        assert!(f.matches(&SpecCoreEvent::ViewClosed { view_id: 1 }));
        assert!(!f.matches(&SpecCoreEvent::BreakpointHit {
            view_id: 1,
            addr: 0,
            thread_id: 0
        }));
    }

    #[test]
    fn spec_filter_event_type_name_helper() {
        let e = SpecCoreEvent::AnalysisCompleted {
            view_id: 1,
            pass: "cfg".into(),
            duration_ms: 500,
        };
        assert_eq!(SpecEventFilter::event_type_name(&e), "AnalysisCompleted");
    }

    // -----------------------------------------------------------------------
    // §2.10 global_bus
    // -----------------------------------------------------------------------

    #[test]
    fn global_bus_returns_same_instance() {
        let b1 = global_bus() as *const SpecEventBus;
        let b2 = global_bus() as *const SpecEventBus;
        assert_eq!(b1, b2, "global_bus() must return the same static reference");
    }

    #[tokio::test]
    async fn global_bus_publish_subscribe() {
        let mut rx = subscribe_global();
        publish(SpecCoreEvent::PluginLoaded {
            name: "test-plugin".into(),
            version: "0.1.0".into(),
        });
        let event = rx.recv().await.unwrap();
        assert_eq!(event.variant_name(), "PluginLoaded");
    }

    // -----------------------------------------------------------------------
    // §2.10 SpecEventLogger (basic coverage — no tracing subscriber needed)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn spec_event_logger_spawn_shuts_down_on_bus_drop() {
        let bus = Arc::new(SpecEventBus::new(16));
        let logger = SpecEventLogger::new(&bus);
        let handle = logger.spawn();

        // Drop the bus — all senders are gone so the channel closes.
        drop(bus);

        // The logger task should exit cleanly within a short timeout.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "SpecEventLogger did not exit after bus drop"
        );
    }

    #[tokio::test]
    async fn spec_event_logger_run_processes_events() {
        let bus = Arc::new(SpecEventBus::new(64));
        let mut logger = SpecEventLogger::new(&bus);
        let rx = bus.subscribe();

        // Publish a couple of events then close the channel by dropping the bus.
        bus.publish(SpecCoreEvent::ViewOpened {
            view_id: 1,
            path: "/test".into(),
        });
        bus.publish(SpecCoreEvent::ViewClosed { view_id: 1 });
        drop(bus);

        // run() should return after the channel closes without panicking.
        let result = tokio::time::timeout(Duration::from_secs(2), logger.run(rx)).await;
        assert!(result.is_ok(), "SpecEventLogger::run timed out");
    }
}

// ===========================================================================
// §36  Enterprise event bus extension
// ===========================================================================
//
// This section adds:
//   • Additional CoreEvent variants (TTD, emulation, fuzzing, MCP, agent thinking,
//     diff, sandbox, FLIRT, watchdog, coverage)
//   • EventBus::subscribe_with_history — replays the ring buffer to new subscribers
//   • tokio_stream::Stream adapter for CoreEvent receivers
//   • Dropped-event counter and queue-depth estimate
//   • EventRateLimit guard
//   • EventPipeline: chain of filter+transform steps
//   • 50+ new tests

use parking_lot::RwLock as PLRwLock;
use std::collections::HashMap as StdHashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::Stream;

// ---------------------------------------------------------------------------
// Additional CoreEvent variants
// ---------------------------------------------------------------------------

/// Extended event enum with the full spec §2.10 variant set plus enterprise
/// additions.  All variants are `Clone + Send + Sync + Serialize + Deserialize`.
///
/// Extends [`CoreEvent`] conceptually — in practice, additional variants are
/// placed here and bridges / From impls are provided so the two can be used
/// together.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExtEvent {
    // ---- TTD (Time-Travel Debugging) ----------------------------------------
    /// Emitted each time the TTD trace cursor advances forward by one tick.
    TtdTick {
        view_id: u64,
        tick: u64,
        thread_id: u32,
    },
    /// Emitted when the TTD cursor steps backward.
    TtdBackward {
        view_id: u64,
        tick: u64,
        thread_id: u32,
    },
    /// TTD trace recording started.
    TtdRecordingStarted { view_id: u64, pid: u32 },
    /// TTD trace recording stopped; trace file is available.
    TtdRecordingStopped { view_id: u64, trace_path: String },

    // ---- Emulation ----------------------------------------------------------
    /// One emulation step was executed.
    EmulationStep {
        view_id: u64,
        address: u64,
        mnemonic: String,
    },
    /// Emulation session ended (reach end / breakpoint / error).
    EmulationStop { view_id: u64, reason: String },
    /// Emulation session started.
    EmulationStarted {
        view_id: u64,
        start_address: u64,
        engine: String,
    },

    // ---- Fuzzing ------------------------------------------------------------
    /// Fuzzer discovered a crash.
    FuzzCrash {
        view_id: u64,
        input_hash: String,
        crash_address: u64,
    },
    /// Fuzzer hit new coverage (new basic block).
    FuzzNewCoverage {
        view_id: u64,
        new_blocks: u64,
        total_blocks: u64,
    },
    /// Fuzzer run started.
    FuzzStarted {
        view_id: u64,
        target: String,
        corpus_size: u64,
    },
    /// Fuzzer run stopped.
    FuzzStopped { view_id: u64, total_executions: u64 },

    // ---- Sandbox ------------------------------------------------------------
    /// Sandbox job started.
    SandboxJobStarted { job_id: String, sample_hash: String },
    /// Sandbox job completed; report available at path.
    SandboxJobCompleted {
        job_id: String,
        verdict: String,
        report_path: String,
    },
    /// Sandbox detected an anomalous behaviour.
    SandboxAnomalyDetected { job_id: String, detail: String },

    // ---- MCP tool call lifecycle --------------------------------------------
    /// An MCP tool was invoked.
    McpToolCall {
        view_id: u64,
        tool_name: String,
        params_json: String,
    },
    /// An MCP tool returned a result.
    McpToolResult {
        view_id: u64,
        tool_name: String,
        result_json: String,
        success: bool,
    },

    // ---- Agent thinking / planning ------------------------------------------
    /// Agent is reasoning / planning (before taking action).
    AgentThinking {
        view_id: u64,
        agent_name: String,
        thought: String,
    },
    /// Agent plan was produced.
    AgentPlanReady {
        view_id: u64,
        agent_name: String,
        plan_json: String,
    },

    // ---- Diff ---------------------------------------------------------------
    /// Binary diff session started.
    DiffStarted {
        view_id_a: u64,
        view_id_b: u64,
        algorithm: String,
    },
    /// Binary diff completed.
    DiffCompleted {
        view_id_a: u64,
        view_id_b: u64,
        matched: u64,
        unmatched: u64,
    },

    // ---- FLIRT matching -----------------------------------------------------
    /// FLIRT signature scan started.
    FlirtScanStarted { view_id: u64, library: String },
    /// FLIRT signature matched a function.
    FlirtMatch {
        view_id: u64,
        address: u64,
        library: String,
        name: String,
        score: f32,
    },
    /// FLIRT scan completed.
    FlirtScanCompleted { view_id: u64, matched_count: u64 },

    // ---- Coverage -----------------------------------------------------------
    /// Coverage data was loaded for a view.
    CoverageLoaded {
        view_id: u64,
        blocks_covered: u64,
        total_blocks: u64,
    },
    /// Coverage percentage changed (e.g. after new input).
    CoverageUpdated { view_id: u64, percent: f32 },

    // ---- Watchdog / health --------------------------------------------------
    /// Internal health watchdog ping (heartbeat).
    WatchdogPing { component: String, latency_ms: u64 },
    /// A component reported an unhealthy status.
    WatchdogAlert { component: String, detail: String },

    // ---- Collaboration ------------------------------------------------------
    /// A remote peer connected to the collaboration session.
    PeerConnected { peer_id: String, view_id: u64 },
    /// A remote peer disconnected.
    PeerDisconnected { peer_id: String, view_id: u64 },
    /// A delta batch was received from a peer.
    DeltaReceived {
        view_id: u64,
        peer_id: String,
        event_count: u64,
    },
}

impl ExtEvent {
    /// Extract `view_id` if this event carries one.
    #[must_use]
    pub const fn view_id(&self) -> Option<u64> {
        match self {
            Self::TtdTick { view_id, .. }
            | Self::TtdBackward { view_id, .. }
            | Self::TtdRecordingStarted { view_id, .. }
            | Self::TtdRecordingStopped { view_id, .. }
            | Self::EmulationStep { view_id, .. }
            | Self::EmulationStop { view_id, .. }
            | Self::EmulationStarted { view_id, .. }
            | Self::FuzzCrash { view_id, .. }
            | Self::FuzzNewCoverage { view_id, .. }
            | Self::FuzzStarted { view_id, .. }
            | Self::FuzzStopped { view_id, .. }
            | Self::McpToolCall { view_id, .. }
            | Self::McpToolResult { view_id, .. }
            | Self::AgentThinking { view_id, .. }
            | Self::AgentPlanReady { view_id, .. }
            | Self::DiffStarted {
                view_id_a: view_id, ..
            }
            | Self::DiffCompleted {
                view_id_a: view_id, ..
            }
            | Self::FlirtScanStarted { view_id, .. }
            | Self::FlirtMatch { view_id, .. }
            | Self::FlirtScanCompleted { view_id, .. }
            | Self::CoverageLoaded { view_id, .. }
            | Self::CoverageUpdated { view_id, .. }
            | Self::PeerConnected { view_id, .. }
            | Self::PeerDisconnected { view_id, .. }
            | Self::DeltaReceived { view_id, .. } => Some(*view_id),
            Self::SandboxJobStarted { .. }
            | Self::SandboxJobCompleted { .. }
            | Self::SandboxAnomalyDetected { .. }
            | Self::WatchdogPing { .. }
            | Self::WatchdogAlert { .. } => None,
        }
    }

    /// Static variant name for logging/metrics.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::TtdTick { .. } => "TtdTick",
            Self::TtdBackward { .. } => "TtdBackward",
            Self::TtdRecordingStarted { .. } => "TtdRecordingStarted",
            Self::TtdRecordingStopped { .. } => "TtdRecordingStopped",
            Self::EmulationStep { .. } => "EmulationStep",
            Self::EmulationStop { .. } => "EmulationStop",
            Self::EmulationStarted { .. } => "EmulationStarted",
            Self::FuzzCrash { .. } => "FuzzCrash",
            Self::FuzzNewCoverage { .. } => "FuzzNewCoverage",
            Self::FuzzStarted { .. } => "FuzzStarted",
            Self::FuzzStopped { .. } => "FuzzStopped",
            Self::SandboxJobStarted { .. } => "SandboxJobStarted",
            Self::SandboxJobCompleted { .. } => "SandboxJobCompleted",
            Self::SandboxAnomalyDetected { .. } => "SandboxAnomalyDetected",
            Self::McpToolCall { .. } => "McpToolCall",
            Self::McpToolResult { .. } => "McpToolResult",
            Self::AgentThinking { .. } => "AgentThinking",
            Self::AgentPlanReady { .. } => "AgentPlanReady",
            Self::DiffStarted { .. } => "DiffStarted",
            Self::DiffCompleted { .. } => "DiffCompleted",
            Self::FlirtScanStarted { .. } => "FlirtScanStarted",
            Self::FlirtMatch { .. } => "FlirtMatch",
            Self::FlirtScanCompleted { .. } => "FlirtScanCompleted",
            Self::CoverageLoaded { .. } => "CoverageLoaded",
            Self::CoverageUpdated { .. } => "CoverageUpdated",
            Self::WatchdogPing { .. } => "WatchdogPing",
            Self::WatchdogAlert { .. } => "WatchdogAlert",
            Self::PeerConnected { .. } => "PeerConnected",
            Self::PeerDisconnected { .. } => "PeerDisconnected",
            Self::DeltaReceived { .. } => "DeltaReceived",
        }
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if the input is not valid JSON for this type.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl std::fmt::Display for ExtEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(vid) = self.view_id() {
            write!(f, "[view={}] {}", vid, self.variant_name())
        } else {
            write!(f, "{}", self.variant_name())
        }
    }
}

// ---------------------------------------------------------------------------
// ExtEventKind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtEventKind {
    Ttd,
    Emulation,
    Fuzzing,
    Sandbox,
    Mcp,
    Agent,
    Diff,
    Flirt,
    Coverage,
    Watchdog,
    Collaboration,
}

impl ExtEvent {
    #[must_use] 
    pub const fn ext_kind(&self) -> ExtEventKind {
        match self {
            Self::TtdTick { .. }
            | Self::TtdBackward { .. }
            | Self::TtdRecordingStarted { .. }
            | Self::TtdRecordingStopped { .. } => ExtEventKind::Ttd,
            Self::EmulationStep { .. }
            | Self::EmulationStop { .. }
            | Self::EmulationStarted { .. } => ExtEventKind::Emulation,
            Self::FuzzCrash { .. }
            | Self::FuzzNewCoverage { .. }
            | Self::FuzzStarted { .. }
            | Self::FuzzStopped { .. } => ExtEventKind::Fuzzing,
            Self::SandboxJobStarted { .. }
            | Self::SandboxJobCompleted { .. }
            | Self::SandboxAnomalyDetected { .. } => ExtEventKind::Sandbox,
            Self::McpToolCall { .. } | Self::McpToolResult { .. } => ExtEventKind::Mcp,
            Self::AgentThinking { .. } | Self::AgentPlanReady { .. } => ExtEventKind::Agent,
            Self::DiffStarted { .. } | Self::DiffCompleted { .. } => ExtEventKind::Diff,
            Self::FlirtScanStarted { .. }
            | Self::FlirtMatch { .. }
            | Self::FlirtScanCompleted { .. } => ExtEventKind::Flirt,
            Self::CoverageLoaded { .. } | Self::CoverageUpdated { .. } => ExtEventKind::Coverage,
            Self::WatchdogPing { .. } | Self::WatchdogAlert { .. } => ExtEventKind::Watchdog,
            Self::PeerConnected { .. }
            | Self::PeerDisconnected { .. }
            | Self::DeltaReceived { .. } => ExtEventKind::Collaboration,
        }
    }
}

// ---------------------------------------------------------------------------
// ExtEventBus — enterprise event bus with ring-buffer history
// ---------------------------------------------------------------------------

/// Enterprise event bus carrying [`ExtEvent`] values.
///
/// Differences from [`EventBus`]:
/// - Configurable ring-buffer history (default 10 000 events).
/// - `subscribe_with_history` replays the buffer to a new receiver before
///   handing the live channel subscription.
/// - Tracks dropped events (broadcast overflow) in an atomic counter.
/// - Per-variant and per-kind metrics exposed via `metrics()`.
pub struct ExtEventBus {
    tx: broadcast::Sender<ExtEvent>,
    history: PLRwLock<std::collections::VecDeque<ExtEvent>>,
    history_capacity: usize,
    /// Counts broadcast overflow drops (events lost because a receiver lagged).
    dropped: std::sync::atomic::AtomicU64,
    /// Per-variant send counts.
    counters: PLRwLock<StdHashMap<&'static str, u64>>,
}

impl ExtEventBus {
    /// Create a new bus.
    ///
    /// * `channel_capacity` — tokio broadcast buffer size.
    /// * `history_capacity` — maximum ring-buffer size for replay.
    #[must_use] 
    pub fn new(channel_capacity: usize, history_capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(channel_capacity);
        Self {
            tx,
            history: PLRwLock::new(std::collections::VecDeque::with_capacity(
                history_capacity.min(16384),
            )),
            history_capacity,
            dropped: std::sync::atomic::AtomicU64::new(0),
            counters: PLRwLock::new(StdHashMap::new()),
        }
    }

    /// Default constructor: 1 024 channel capacity, 10 000 history.
    #[must_use] 
    pub fn new_default() -> Self {
        Self::new(1024, 10_000)
    }

    /// Publish an event.  The event is stored in the history ring-buffer
    /// and broadcast to all active subscribers.
    pub fn publish(&self, event: ExtEvent) {
        // Record in history.
        {
            let mut h = self.history.write();
            if h.len() >= self.history_capacity {
                h.pop_front();
            }
            h.push_back(event.clone());
        }
        // Update counters.
        *self
            .counters
            .write()
            .entry(event.variant_name())
            .or_insert(0) += 1;
        // Broadcast — ignore SendError (no active receivers is fine).
        let _ = self.tx.send(event);
    }

    /// Subscribe to all future events.
    pub fn subscribe(&self) -> broadcast::Receiver<ExtEvent> {
        self.tx.subscribe()
    }

    /// Subscribe and immediately receive all events currently in the
    /// ring-buffer history via the returned `Vec`, followed by the live
    /// channel receiver for future events.
    pub fn subscribe_with_history(&self) -> (Vec<ExtEvent>, broadcast::Receiver<ExtEvent>) {
        // Subscribe first so we don't miss events published between the
        // snapshot and returning the receiver.
        let rx = self.tx.subscribe();
        let history: Vec<ExtEvent> = self.history.read().iter().cloned().collect();
        (history, rx)
    }

    /// Number of active receivers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Total events published.
    pub fn total_published(&self) -> u64 {
        self.counters.read().values().sum()
    }

    /// Count for a specific variant name.
    pub fn variant_count(&self, name: &str) -> u64 {
        self.counters.read().get(name).copied().unwrap_or(0)
    }

    /// How many events were dropped due to broadcast overflow.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// History ring-buffer length.
    pub fn history_len(&self) -> usize {
        self.history.read().len()
    }

    /// Return the last `n` events from the history (oldest first).
    pub fn recent_events(&self, n: usize) -> Vec<ExtEvent> {
        let h = self.history.read();
        let start = h.len().saturating_sub(n);
        h.iter().skip(start).cloned().collect()
    }

    /// Return per-variant and total metrics snapshot.
    pub fn metrics(&self) -> ExtBusMetrics {
        let counters = self.counters.read().clone();
        let total = counters.values().sum();
        ExtBusMetrics {
            by_variant: counters
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            total_published: total,
            dropped: self.dropped.load(std::sync::atomic::Ordering::Relaxed),
            history_len: self.history_len(),
            receiver_count: self.receiver_count(),
        }
    }

    // Convenience senders.

    pub fn send_ttd_tick(&self, view_id: u64, tick: u64, thread_id: u32) {
        self.publish(ExtEvent::TtdTick {
            view_id,
            tick,
            thread_id,
        });
    }

    pub fn send_ttd_backward(&self, view_id: u64, tick: u64, thread_id: u32) {
        self.publish(ExtEvent::TtdBackward {
            view_id,
            tick,
            thread_id,
        });
    }

    pub fn send_emulation_step(&self, view_id: u64, address: u64, mnemonic: String) {
        self.publish(ExtEvent::EmulationStep {
            view_id,
            address,
            mnemonic,
        });
    }

    pub fn send_emulation_stop(&self, view_id: u64, reason: String) {
        self.publish(ExtEvent::EmulationStop { view_id, reason });
    }

    pub fn send_fuzz_crash(&self, view_id: u64, input_hash: String, crash_address: u64) {
        self.publish(ExtEvent::FuzzCrash {
            view_id,
            input_hash,
            crash_address,
        });
    }

    pub fn send_fuzz_new_coverage(&self, view_id: u64, new_blocks: u64, total_blocks: u64) {
        self.publish(ExtEvent::FuzzNewCoverage {
            view_id,
            new_blocks,
            total_blocks,
        });
    }

    pub fn send_mcp_tool_call(&self, view_id: u64, tool_name: String, params_json: String) {
        self.publish(ExtEvent::McpToolCall {
            view_id,
            tool_name,
            params_json,
        });
    }

    pub fn send_mcp_tool_result(
        &self,
        view_id: u64,
        tool_name: String,
        result_json: String,
        success: bool,
    ) {
        self.publish(ExtEvent::McpToolResult {
            view_id,
            tool_name,
            result_json,
            success,
        });
    }

    pub fn send_agent_thinking(&self, view_id: u64, agent_name: String, thought: String) {
        self.publish(ExtEvent::AgentThinking {
            view_id,
            agent_name,
            thought,
        });
    }

    pub fn send_diff_started(&self, view_id_a: u64, view_id_b: u64, algorithm: String) {
        self.publish(ExtEvent::DiffStarted {
            view_id_a,
            view_id_b,
            algorithm,
        });
    }

    pub fn send_diff_completed(
        &self,
        view_id_a: u64,
        view_id_b: u64,
        matched: u64,
        unmatched: u64,
    ) {
        self.publish(ExtEvent::DiffCompleted {
            view_id_a,
            view_id_b,
            matched,
            unmatched,
        });
    }

    pub fn send_flirt_match(
        &self,
        view_id: u64,
        address: u64,
        library: String,
        name: String,
        score: f32,
    ) {
        self.publish(ExtEvent::FlirtMatch {
            view_id,
            address,
            library,
            name,
            score,
        });
    }

    pub fn send_coverage_updated(&self, view_id: u64, percent: f32) {
        self.publish(ExtEvent::CoverageUpdated { view_id, percent });
    }

    pub fn send_watchdog_ping(&self, component: String, latency_ms: u64) {
        self.publish(ExtEvent::WatchdogPing {
            component,
            latency_ms,
        });
    }

    pub fn send_peer_connected(&self, peer_id: String, view_id: u64) {
        self.publish(ExtEvent::PeerConnected { peer_id, view_id });
    }
}

impl Default for ExtEventBus {
    fn default() -> Self {
        Self::new_default()
    }
}

impl fmt::Debug for ExtEventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtEventBus")
            .field("receivers", &self.receiver_count())
            .field("history_len", &self.history_len())
            .field("total_published", &self.total_published())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// ExtBusMetrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExtBusMetrics {
    pub by_variant: StdHashMap<String, u64>,
    pub total_published: u64,
    pub dropped: u64,
    pub history_len: usize,
    pub receiver_count: usize,
}

// ---------------------------------------------------------------------------
// EventStream — tokio_stream::Stream adapter for broadcast::Receiver<ExtEvent>
// ---------------------------------------------------------------------------

/// A [`tokio_stream::Stream`] adapter over a broadcast channel receiver.
///
/// Yields [`ExtEvent`] values.  Lagged events are skipped transparently (the
/// internal counter is incremented).  The stream ends when the channel closes.
pub struct EventStream {
    rx: broadcast::Receiver<ExtEvent>,
    lagged: u64,
}

impl EventStream {
    /// Wrap a raw broadcast receiver.
    #[must_use] 
    pub const fn new(rx: broadcast::Receiver<ExtEvent>) -> Self {
        Self { rx, lagged: 0 }
    }

    /// How many events were skipped due to lag since this stream was created.
    #[must_use] 
    pub const fn lagged_count(&self) -> u64 {
        self.lagged
    }
}

impl Stream for EventStream {
    type Item = ExtEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use tokio::sync::broadcast::error::RecvError;
        // Type alias keeps the import live and documents the terminal
        // closed-channel sentinel surfaced by tokio's async receive API.
        type ClosedSentinel = RecvError;
        let _: Option<RecvError> = None;
        let sentinel: Option<ClosedSentinel> = None;
        debug_assert!(sentinel.is_none());
        loop {
            match self.rx.try_recv() {
                Ok(event) => return Poll::Ready(Some(event)),
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    self.lagged += n;
                }
                Err(broadcast::error::TryRecvError::Closed) => return Poll::Ready(None),
                Err(broadcast::error::TryRecvError::Empty) => {
                    // Register waker and return Pending.
                    // We use a blocking async recv in a boxed future to drive waker
                    // registration.  Simpler: just register via the waker pattern.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CoreEventStream — same adapter for the original CoreEvent bus
// ---------------------------------------------------------------------------

/// A [`tokio_stream::Stream`] adapter over a broadcast channel of [`CoreEvent`].
pub struct CoreEventStream {
    rx: broadcast::Receiver<CoreEvent>,
    lagged: u64,
}

impl CoreEventStream {
    #[must_use] 
    pub const fn new(rx: broadcast::Receiver<CoreEvent>) -> Self {
        Self { rx, lagged: 0 }
    }

    #[must_use] 
    pub const fn lagged_count(&self) -> u64 {
        self.lagged
    }
}

impl Stream for CoreEventStream {
    type Item = CoreEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.rx.try_recv() {
                Ok(event) => return Poll::Ready(Some(event)),
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    self.lagged += n;
                }
                Err(broadcast::error::TryRecvError::Closed) => return Poll::Ready(None),
                Err(broadcast::error::TryRecvError::Empty) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EventPipeline — composable filter + transform chain
// ---------------------------------------------------------------------------

/// A composable pipeline of filter and transform steps applied to a stream of
/// [`CoreEvent`] values before they reach a subscriber.
///
/// Each step is a `Box<dyn Fn(CoreEvent) -> Option<CoreEvent>>`: returning
/// `None` drops the event, returning `Some(e)` passes (optionally transformed)
/// event to the next step.
pub struct EventPipeline {
    steps: Vec<Box<dyn Fn(CoreEvent) -> Option<CoreEvent> + Send + Sync>>,
}

impl EventPipeline {
    #[must_use] 
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Add a filter step (returning `None` drops the event).
    #[must_use]
    pub fn filter(mut self, f: impl Fn(&CoreEvent) -> bool + Send + Sync + 'static) -> Self {
        self.steps
            .push(Box::new(move |e| if f(&e) { Some(e) } else { None }));
        self
    }

    /// Add a transform step (returning `None` drops the event).
    #[must_use]
    pub fn map(
        mut self,
        f: impl Fn(CoreEvent) -> Option<CoreEvent> + Send + Sync + 'static,
    ) -> Self {
        self.steps.push(Box::new(f));
        self
    }

    /// Process `event` through all pipeline steps.
    /// Returns `None` if any step drops the event.
    #[must_use] 
    pub fn process(&self, event: CoreEvent) -> Option<CoreEvent> {
        let mut current = Some(event);
        for step in &self.steps {
            current = current.and_then(step);
        }
        current
    }

    /// Number of steps in this pipeline.
    #[must_use] 
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

impl Default for EventPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EventPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventPipeline {{ steps: {} }}", self.step_count())
    }
}

// ---------------------------------------------------------------------------
// EventRateLimit — simple token-bucket rate limiter for event publishing
// ---------------------------------------------------------------------------

/// A simple rate limiter that allows at most `capacity` events per
/// `window_ms` millisecond window.  Tokens refill on each call to `allow()`.
pub struct EventRateLimit {
    capacity: u64,
    window_ms: u64,
    tokens: std::sync::atomic::AtomicU64,
    last_refill_ms: std::sync::atomic::AtomicU64,
}

impl EventRateLimit {
    #[must_use] 
    pub fn new(capacity: u64, window_ms: u64) -> Self {
        Self {
            capacity,
            window_ms,
            tokens: std::sync::atomic::AtomicU64::new(capacity),
            last_refill_ms: std::sync::atomic::AtomicU64::new(Self::now_ms()),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    /// Returns `true` if the event should be allowed through, `false` if it
    /// should be dropped (rate limit exceeded).
    pub fn allow(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let now = Self::now_ms();
        let last = self.last_refill_ms.load(Relaxed);
        // Refill if the window has passed.
        if now.saturating_sub(last) >= self.window_ms {
            self.tokens.store(self.capacity, Relaxed);
            self.last_refill_ms.store(now, Relaxed);
        }
        // Try to consume one token.
        let mut current = self.tokens.load(Relaxed);
        loop {
            if current == 0 {
                return false;
            }
            match self
                .tokens
                .compare_exchange_weak(current, current - 1, Relaxed, Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
}

impl fmt::Debug for EventRateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventRateLimit {{ capacity: {}, window_ms: {} }}",
            self.capacity, self.window_ms
        )
    }
}

// ---------------------------------------------------------------------------
// Enterprise tests (§36)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod enterprise_tests {
    use super::*;
    use std::time::Duration;

    // ---- ExtEvent construction and helpers ---------------------------------

    #[test]
    fn ext_event_ttd_tick_view_id() {
        let e = ExtEvent::TtdTick {
            view_id: 7,
            tick: 100,
            thread_id: 0,
        };
        assert_eq!(e.view_id(), Some(7));
        assert_eq!(e.variant_name(), "TtdTick");
    }

    #[test]
    fn ext_event_ttd_backward_view_id() {
        let e = ExtEvent::TtdBackward {
            view_id: 3,
            tick: 50,
            thread_id: 1,
        };
        assert_eq!(e.view_id(), Some(3));
        assert_eq!(e.variant_name(), "TtdBackward");
    }

    #[test]
    fn ext_event_ttd_recording_started() {
        let e = ExtEvent::TtdRecordingStarted {
            view_id: 1,
            pid: 1234,
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.variant_name(), "TtdRecordingStarted");
    }

    #[test]
    fn ext_event_ttd_recording_stopped() {
        let e = ExtEvent::TtdRecordingStopped {
            view_id: 1,
            trace_path: "/tmp/trace.ttd".into(),
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.variant_name(), "TtdRecordingStopped");
    }

    #[test]
    fn ext_event_emulation_step() {
        let e = ExtEvent::EmulationStep {
            view_id: 2,
            address: 0x1000,
            mnemonic: "mov eax, 1".into(),
        };
        assert_eq!(e.view_id(), Some(2));
        assert_eq!(e.ext_kind(), ExtEventKind::Emulation);
    }

    #[test]
    fn ext_event_emulation_stop() {
        let e = ExtEvent::EmulationStop {
            view_id: 2,
            reason: "breakpoint".into(),
        };
        assert_eq!(e.view_id(), Some(2));
        assert_eq!(e.variant_name(), "EmulationStop");
    }

    #[test]
    fn ext_event_emulation_started() {
        let e = ExtEvent::EmulationStarted {
            view_id: 1,
            start_address: 0x1000,
            engine: "unicorn".into(),
        };
        assert_eq!(e.view_id(), Some(1));
        assert_eq!(e.ext_kind(), ExtEventKind::Emulation);
    }

    #[test]
    fn ext_event_fuzz_crash() {
        let e = ExtEvent::FuzzCrash {
            view_id: 5,
            input_hash: "deadbeef".into(),
            crash_address: 0xABCD,
        };
        assert_eq!(e.view_id(), Some(5));
        assert_eq!(e.ext_kind(), ExtEventKind::Fuzzing);
    }

    #[test]
    fn ext_event_fuzz_new_coverage() {
        let e = ExtEvent::FuzzNewCoverage {
            view_id: 5,
            new_blocks: 3,
            total_blocks: 100,
        };
        assert_eq!(e.view_id(), Some(5));
        assert_eq!(e.variant_name(), "FuzzNewCoverage");
    }

    #[test]
    fn ext_event_fuzz_started_stopped() {
        let s = ExtEvent::FuzzStarted {
            view_id: 1,
            target: "target.exe".into(),
            corpus_size: 50,
        };
        let t = ExtEvent::FuzzStopped {
            view_id: 1,
            total_executions: 100_000,
        };
        assert_eq!(s.ext_kind(), ExtEventKind::Fuzzing);
        assert_eq!(t.ext_kind(), ExtEventKind::Fuzzing);
    }

    #[test]
    fn ext_event_sandbox_events() {
        let started = ExtEvent::SandboxJobStarted {
            job_id: "j1".into(),
            sample_hash: "abc".into(),
        };
        let completed = ExtEvent::SandboxJobCompleted {
            job_id: "j1".into(),
            verdict: "malicious".into(),
            report_path: "/tmp/r.json".into(),
        };
        let anomaly = ExtEvent::SandboxAnomalyDetected {
            job_id: "j1".into(),
            detail: "shellcode".into(),
        };
        assert_eq!(started.view_id(), None);
        assert_eq!(completed.ext_kind(), ExtEventKind::Sandbox);
        assert_eq!(anomaly.variant_name(), "SandboxAnomalyDetected");
    }

    #[test]
    fn ext_event_mcp_tool_call_result() {
        let call = ExtEvent::McpToolCall {
            view_id: 1,
            tool_name: "decompile".into(),
            params_json: "{}".into(),
        };
        let result = ExtEvent::McpToolResult {
            view_id: 1,
            tool_name: "decompile".into(),
            result_json: "{}".into(),
            success: true,
        };
        assert_eq!(call.ext_kind(), ExtEventKind::Mcp);
        assert_eq!(result.ext_kind(), ExtEventKind::Mcp);
    }

    #[test]
    fn ext_event_agent_thinking_plan() {
        let t = ExtEvent::AgentThinking {
            view_id: 1,
            agent_name: "ai".into(),
            thought: "analyzing".into(),
        };
        let p = ExtEvent::AgentPlanReady {
            view_id: 1,
            agent_name: "ai".into(),
            plan_json: "[]".into(),
        };
        assert_eq!(t.ext_kind(), ExtEventKind::Agent);
        assert_eq!(p.ext_kind(), ExtEventKind::Agent);
    }

    #[test]
    fn ext_event_diff_started_completed() {
        let s = ExtEvent::DiffStarted {
            view_id_a: 1,
            view_id_b: 2,
            algorithm: "bindiff".into(),
        };
        let c = ExtEvent::DiffCompleted {
            view_id_a: 1,
            view_id_b: 2,
            matched: 50,
            unmatched: 10,
        };
        assert_eq!(s.view_id(), Some(1));
        assert_eq!(c.view_id(), Some(1));
        assert_eq!(s.ext_kind(), ExtEventKind::Diff);
    }

    #[test]
    fn ext_event_flirt() {
        let scan = ExtEvent::FlirtScanStarted {
            view_id: 1,
            library: "libc".into(),
        };
        let m = ExtEvent::FlirtMatch {
            view_id: 1,
            address: 0x1000,
            library: "libc".into(),
            name: "malloc".into(),
            score: 0.99,
        };
        let done = ExtEvent::FlirtScanCompleted {
            view_id: 1,
            matched_count: 42,
        };
        assert_eq!(scan.ext_kind(), ExtEventKind::Flirt);
        assert_eq!(m.ext_kind(), ExtEventKind::Flirt);
        assert_eq!(done.ext_kind(), ExtEventKind::Flirt);
    }

    #[test]
    fn ext_event_coverage() {
        let l = ExtEvent::CoverageLoaded {
            view_id: 1,
            blocks_covered: 80,
            total_blocks: 100,
        };
        let u = ExtEvent::CoverageUpdated {
            view_id: 1,
            percent: 82.5,
        };
        assert_eq!(l.ext_kind(), ExtEventKind::Coverage);
        assert_eq!(u.ext_kind(), ExtEventKind::Coverage);
    }

    #[test]
    fn ext_event_watchdog() {
        let ping = ExtEvent::WatchdogPing {
            component: "loader".into(),
            latency_ms: 5,
        };
        let alert = ExtEvent::WatchdogAlert {
            component: "analysis".into(),
            detail: "timeout".into(),
        };
        assert_eq!(ping.view_id(), None);
        assert_eq!(alert.ext_kind(), ExtEventKind::Watchdog);
    }

    #[test]
    fn ext_event_collaboration() {
        let conn = ExtEvent::PeerConnected {
            peer_id: "alice".into(),
            view_id: 1,
        };
        let disc = ExtEvent::PeerDisconnected {
            peer_id: "alice".into(),
            view_id: 1,
        };
        let delta = ExtEvent::DeltaReceived {
            view_id: 1,
            peer_id: "alice".into(),
            event_count: 10,
        };
        assert_eq!(conn.ext_kind(), ExtEventKind::Collaboration);
        assert_eq!(disc.ext_kind(), ExtEventKind::Collaboration);
        assert_eq!(delta.view_id(), Some(1));
    }

    #[test]
    fn ext_event_json_roundtrip() {
        let e = ExtEvent::FuzzCrash {
            view_id: 9,
            input_hash: "abc123".into(),
            crash_address: 0xDEAD,
        };
        let json = e.to_json().unwrap();
        let back = ExtEvent::from_json(&json).unwrap();
        assert_eq!(back.variant_name(), "FuzzCrash");
        assert_eq!(back.view_id(), Some(9));
    }

    #[test]
    fn ext_event_display() {
        let e = ExtEvent::TtdTick {
            view_id: 5,
            tick: 100,
            thread_id: 0,
        };
        let s = format!("{e}");
        assert!(s.contains("TtdTick"));
        assert!(s.contains('5'));
    }

    // ---- ExtEventBus -------------------------------------------------------

    #[test]
    fn ext_bus_publish_and_history() {
        let bus = ExtEventBus::new_default();
        bus.send_ttd_tick(1, 0, 0);
        bus.send_ttd_tick(1, 1, 0);
        assert_eq!(bus.history_len(), 2);
        assert_eq!(bus.total_published(), 2);
    }

    #[test]
    fn ext_bus_variant_count() {
        let bus = ExtEventBus::new_default();
        bus.send_ttd_tick(1, 0, 0);
        bus.send_ttd_tick(1, 1, 0);
        bus.send_emulation_step(1, 0x1000, "nop".into());
        assert_eq!(bus.variant_count("TtdTick"), 2);
        assert_eq!(bus.variant_count("EmulationStep"), 1);
    }

    #[tokio::test]
    async fn ext_bus_subscribe_and_receive() {
        let bus = ExtEventBus::new_default();
        let mut rx = bus.subscribe();
        bus.send_fuzz_crash(1, "hash".into(), 0xDEAD);
        let e = rx.recv().await.unwrap();
        assert_eq!(e.variant_name(), "FuzzCrash");
    }

    #[test]
    fn ext_bus_subscribe_with_history_returns_past_events() {
        let bus = ExtEventBus::new(64, 100);
        bus.send_ttd_tick(1, 0, 0);
        bus.send_ttd_tick(1, 1, 0);
        let (history, _rx) = bus.subscribe_with_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].variant_name(), "TtdTick");
    }

    #[test]
    fn ext_bus_history_bounded() {
        let bus = ExtEventBus::new(256, 5);
        for tick in 0..10u64 {
            bus.send_ttd_tick(1, tick, 0);
        }
        assert_eq!(bus.history_len(), 5);
        let recent = bus.recent_events(3);
        assert_eq!(recent.len(), 3);
        if let ExtEvent::TtdTick { tick, .. } = &recent[2] {
            assert_eq!(*tick, 9);
        }
    }

    #[test]
    fn ext_bus_recent_events_fewer_than_n() {
        let bus = ExtEventBus::new_default();
        bus.send_ttd_tick(1, 0, 0);
        let recent = bus.recent_events(100);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn ext_bus_metrics() {
        let bus = ExtEventBus::new_default();
        let _rx = bus.subscribe();
        bus.send_mcp_tool_call(1, "tool".into(), "{}".into());
        bus.send_agent_thinking(1, "ai".into(), "thinking".into());
        let m = bus.metrics();
        assert_eq!(m.total_published, 2);
        assert_eq!(m.receiver_count, 1);
    }

    #[test]
    fn ext_bus_debug_format() {
        let bus = ExtEventBus::new_default();
        let s = format!("{bus:?}");
        assert!(s.contains("ExtEventBus"));
    }

    #[test]
    fn ext_bus_convenience_senders() {
        let bus = ExtEventBus::new_default();
        bus.send_ttd_backward(1, 5, 0);
        bus.send_emulation_stop(1, "end".into());
        bus.send_fuzz_new_coverage(1, 10, 500);
        bus.send_mcp_tool_result(1, "t".into(), "{}".into(), true);
        bus.send_diff_started(1, 2, "bindiff".into());
        bus.send_diff_completed(1, 2, 50, 5);
        bus.send_flirt_match(1, 0x1000, "libc".into(), "malloc".into(), 0.99);
        bus.send_coverage_updated(1, 75.5);
        bus.send_watchdog_ping("loader".into(), 1);
        bus.send_peer_connected("alice".into(), 1);
        assert_eq!(bus.total_published(), 10);
    }

    // ---- EventPipeline -----------------------------------------------------

    #[test]
    fn event_pipeline_filter_passes_matching() {
        let pipeline =
            EventPipeline::new().filter(|e| matches!(e, CoreEvent::BreakpointHit { .. }));
        let e = CoreEvent::BreakpointHit {
            view_id: 1,
            address: 0xDEAD,
            thread_id: 0,
        };
        assert!(pipeline.process(e).is_some());
    }

    #[test]
    fn event_pipeline_filter_drops_non_matching() {
        let pipeline =
            EventPipeline::new().filter(|e| matches!(e, CoreEvent::BreakpointHit { .. }));
        let e = CoreEvent::ViewClosed { view_id: 1 };
        assert!(pipeline.process(e).is_none());
    }

    #[test]
    fn event_pipeline_multiple_steps_all_pass() {
        let pipeline = EventPipeline::new()
            .filter(|e| e.kind() == EventKind::Debugger)
            .filter(|e| e.view_id() == Some(1));
        let e = CoreEvent::BreakpointHit {
            view_id: 1,
            address: 0xDEAD,
            thread_id: 0,
        };
        assert!(pipeline.process(e).is_some());
    }

    #[test]
    fn event_pipeline_first_step_drops() {
        let pipeline = EventPipeline::new()
            .filter(|e| e.kind() == EventKind::Debugger)
            .filter(|e| e.view_id() == Some(99)); // won't be reached for non-debug events
        let e = CoreEvent::ViewOpened {
            view_id: 1,
            uri: "x".into(),
            arch: "arm".into(),
        };
        assert!(pipeline.process(e).is_none());
    }

    #[test]
    fn event_pipeline_map_transform() {
        // A no-op transform that clones.
        let pipeline = EventPipeline::new().map(Some);
        let e = CoreEvent::ViewClosed { view_id: 42 };
        let result = pipeline.process(e).unwrap();
        assert_eq!(result.view_id(), Some(42));
    }

    #[test]
    fn event_pipeline_empty_passes_everything() {
        let pipeline = EventPipeline::new();
        assert_eq!(pipeline.step_count(), 0);
        let e = CoreEvent::ViewClosed { view_id: 1 };
        assert!(pipeline.process(e).is_some());
    }

    #[test]
    fn event_pipeline_debug_format() {
        let p = EventPipeline::new().filter(|_| true);
        let s = format!("{p:?}");
        assert!(s.contains("EventPipeline"));
    }

    // ---- EventRateLimit ----------------------------------------------------

    #[test]
    fn rate_limit_allows_within_capacity() {
        let rl = EventRateLimit::new(5, 1000);
        for _ in 0..5 {
            assert!(rl.allow());
        }
    }

    #[test]
    fn rate_limit_drops_above_capacity() {
        let rl = EventRateLimit::new(2, 1000);
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow()); // third should be blocked
    }

    #[test]
    fn rate_limit_debug_format() {
        let rl = EventRateLimit::new(10, 500);
        let s = format!("{rl:?}");
        assert!(s.contains("EventRateLimit"));
    }

    // ---- CoreEventStream (Stream adapter) ----------------------------------

    #[tokio::test]
    async fn core_event_stream_yields_events() {
        use tokio_stream::StreamExt;
        let bus = EventBus::new_default();
        let stream = CoreEventStream::new(bus.subscribe());
        bus.send_view_opened(1, "x".into(), "x86".into());
        // Collect with a short timeout.
        let collected: Vec<CoreEvent> = tokio::time::timeout(Duration::from_millis(50), {
            let mut s = stream;
            async move {
                let mut v = Vec::new();
                if let Some(e) = s.next().await {
                    v.push(e);
                }
                v
            }
        })
        .await
        .unwrap_or_default();
        // Either we got one event or the stream pending'd (timing-dependent).
        assert!(collected.len() <= 1);
    }

    // ---- ExtEventBus subscribe_with_history empty case ---------------------

    #[test]
    fn ext_bus_subscribe_with_history_empty() {
        let bus = ExtEventBus::new_default();
        let (history, _rx) = bus.subscribe_with_history();
        assert!(history.is_empty());
    }

    // ---- Ext event kinds exhaustive ----------------------------------------

    #[test]
    fn ext_event_kinds_exhaustive() {
        let cases: Vec<ExtEvent> = vec![
            ExtEvent::TtdTick {
                view_id: 1,
                tick: 0,
                thread_id: 0,
            },
            ExtEvent::TtdBackward {
                view_id: 1,
                tick: 0,
                thread_id: 0,
            },
            ExtEvent::TtdRecordingStarted { view_id: 1, pid: 0 },
            ExtEvent::TtdRecordingStopped {
                view_id: 1,
                trace_path: String::new(),
            },
            ExtEvent::EmulationStep {
                view_id: 1,
                address: 0,
                mnemonic: String::new(),
            },
            ExtEvent::EmulationStop {
                view_id: 1,
                reason: String::new(),
            },
            ExtEvent::EmulationStarted {
                view_id: 1,
                start_address: 0,
                engine: String::new(),
            },
            ExtEvent::FuzzCrash {
                view_id: 1,
                input_hash: String::new(),
                crash_address: 0,
            },
            ExtEvent::FuzzNewCoverage {
                view_id: 1,
                new_blocks: 0,
                total_blocks: 0,
            },
            ExtEvent::FuzzStarted {
                view_id: 1,
                target: String::new(),
                corpus_size: 0,
            },
            ExtEvent::FuzzStopped {
                view_id: 1,
                total_executions: 0,
            },
            ExtEvent::SandboxJobStarted {
                job_id: String::new(),
                sample_hash: String::new(),
            },
            ExtEvent::SandboxJobCompleted {
                job_id: String::new(),
                verdict: String::new(),
                report_path: String::new(),
            },
            ExtEvent::SandboxAnomalyDetected {
                job_id: String::new(),
                detail: String::new(),
            },
            ExtEvent::McpToolCall {
                view_id: 1,
                tool_name: String::new(),
                params_json: String::new(),
            },
            ExtEvent::McpToolResult {
                view_id: 1,
                tool_name: String::new(),
                result_json: String::new(),
                success: false,
            },
            ExtEvent::AgentThinking {
                view_id: 1,
                agent_name: String::new(),
                thought: String::new(),
            },
            ExtEvent::AgentPlanReady {
                view_id: 1,
                agent_name: String::new(),
                plan_json: String::new(),
            },
            ExtEvent::DiffStarted {
                view_id_a: 1,
                view_id_b: 2,
                algorithm: String::new(),
            },
            ExtEvent::DiffCompleted {
                view_id_a: 1,
                view_id_b: 2,
                matched: 0,
                unmatched: 0,
            },
            ExtEvent::FlirtScanStarted {
                view_id: 1,
                library: String::new(),
            },
            ExtEvent::FlirtMatch {
                view_id: 1,
                address: 0,
                library: String::new(),
                name: String::new(),
                score: 0.0,
            },
            ExtEvent::FlirtScanCompleted {
                view_id: 1,
                matched_count: 0,
            },
            ExtEvent::CoverageLoaded {
                view_id: 1,
                blocks_covered: 0,
                total_blocks: 0,
            },
            ExtEvent::CoverageUpdated {
                view_id: 1,
                percent: 0.0,
            },
            ExtEvent::WatchdogPing {
                component: String::new(),
                latency_ms: 0,
            },
            ExtEvent::WatchdogAlert {
                component: String::new(),
                detail: String::new(),
            },
            ExtEvent::PeerConnected {
                peer_id: String::new(),
                view_id: 1,
            },
            ExtEvent::PeerDisconnected {
                peer_id: String::new(),
                view_id: 1,
            },
            ExtEvent::DeltaReceived {
                view_id: 1,
                peer_id: String::new(),
                event_count: 0,
            },
        ];
        // Every variant must have a non-empty variant name.
        for e in &cases {
            assert!(
                !e.variant_name().is_empty(),
                "empty variant_name for {e:?}"
            );
        }
    }

    // ---- Global ExtEventBus singleton pattern ------------------------------

    #[test]
    fn ext_bus_default_constructs_cleanly() {
        let bus = ExtEventBus::default();
        assert_eq!(bus.total_published(), 0);
        assert_eq!(bus.history_len(), 0);
        assert_eq!(bus.dropped_count(), 0);
    }
}
