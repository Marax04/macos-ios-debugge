//! Async event bus for the RustRE platform.
//!
//! The [`EventBus`] is a central broadcast channel built on top of
//! [`tokio::sync::broadcast`].  Every subsystem that mutates shared analysis
//! state should publish a [`CoreEvent`]; UI layers and plugins subscribe to
//! receive them asynchronously.
//!
//! # Design
//!
//! - **Single writer, many readers**: multiple subscriber handles can be
//!   created via [`EventBus::subscribe`].
//! - **Non-blocking publish**: [`EventBus::publish`] never waits; lagging
//!   subscribers drop old events per the broadcast channel semantics.
//! - **Typed event payloads**: every variant of [`CoreEvent`] carries enough
//!   context to act on the notification without round-tripping through shared
//!   state.
//!
//! # Example
//!
//! ```
//! use rustre_core::events::{CoreEvent, EventBus};
//!
//! let bus = EventBus::new(512);
//! let mut rx = bus.subscribe();
//! bus.publish(CoreEvent::BinaryLoaded { path: "a.exe".into(), view_id: 1 });
//!
//! // Receiving is async, so it belongs inside an async fn or block:
//! async fn drain(mut rx: tokio::sync::broadcast::Receiver<CoreEvent>) {
//!     if let Ok(evt) = rx.recv().await {
//!         println!("got event: {evt:?}");
//!     }
//! }
//! ```
//!
//! The block was `rust,ignore` until 2026-07-29 and used `.await` at
//! statement level, which no Rust context accepts — that is why it had
//! never compiled.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::{Receiver, Sender};

// ─────────────────────────────────────────────────────────────────────────────
// CoreEvent
// ─────────────────────────────────────────────────────────────────────────────

/// Every event that the `RustRE` platform can emit.
///
/// Events are lightweight, `Clone`-able value types suitable for broadcasting
/// across async tasks.  They carry enough information to identify the affected
/// entity and act on the change without additional lookups in most cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CoreEvent {
    // ── Binary lifecycle ─────────────────────────────────────────────────────
    /// A binary file has been loaded into a new view.
    BinaryLoaded {
        /// Path or URI of the loaded file.
        path: String,
        /// Identifier of the newly created view.
        view_id: u64,
    },
    /// A binary view has been closed and all its resources freed.
    BinaryClosed {
        /// Identifier of the closed view.
        view_id: u64,
    },
    /// A binary view has been saved to disk.
    BinarySaved {
        view_id: u64,
        /// Path written to.
        path: String,
    },
    /// Initial analysis of a binary is complete.
    AnalysisFinished {
        view_id: u64,
        /// Elapsed time in milliseconds.
        elapsed_ms: u64,
    },

    // ── Functions ────────────────────────────────────────────────────────────
    /// A new function has been defined (manually or via auto-analysis).
    FunctionAdded {
        view_id: u64,
        /// Virtual address of the function.
        address: u64,
        /// Name assigned to the function, if any.
        name: Option<String>,
    },
    /// A function has been removed.
    FunctionRemoved { view_id: u64, address: u64 },
    /// A function has been renamed.
    FunctionRenamed {
        view_id: u64,
        address: u64,
        old_name: String,
        new_name: String,
    },
    /// A function's prototype (type signature) has been updated.
    FunctionPrototypeChanged {
        view_id: u64,
        address: u64,
        /// Serialised representation of the new prototype.
        prototype: String,
    },
    /// A function's basic-block graph has been updated.
    FunctionCfgChanged {
        view_id: u64,
        address: u64,
        /// Number of basic blocks in the updated CFG.
        block_count: usize,
    },

    // ── Symbols ──────────────────────────────────────────────────────────────
    /// A symbol has been added to the symbol table.
    SymbolAdded {
        view_id: u64,
        address: u64,
        name: String,
    },
    /// A symbol has been removed.
    SymbolRemoved {
        view_id: u64,
        address: u64,
        name: String,
    },
    /// A symbol has been renamed.
    SymbolRenamed {
        view_id: u64,
        address: u64,
        old_name: String,
        new_name: String,
    },

    // ── Types ────────────────────────────────────────────────────────────────
    /// A new type definition has been added to the type store.
    TypeDefined {
        view_id: u64,
        /// Numeric type ID.
        type_id: u32,
        /// Name of the type.
        name: String,
    },
    /// A type definition has been updated in place.
    TypeUpdated {
        view_id: u64,
        type_id: u32,
        name: String,
    },
    /// A type has been removed from the type store.
    TypeRemoved { view_id: u64, type_id: u32 },

    // ── Patches ──────────────────────────────────────────────────────────────
    /// A byte patch has been applied to the binary image.
    PatchApplied {
        view_id: u64,
        address: u64,
        /// Number of bytes patched.
        length: usize,
    },
    /// A byte patch has been reverted.
    PatchReverted {
        view_id: u64,
        address: u64,
        length: usize,
    },

    // ── Comments ─────────────────────────────────────────────────────────────
    /// A comment has been added.
    CommentAdded {
        view_id: u64,
        address: u64,
        /// Text of the comment (truncated to 256 chars for the event payload).
        text: String,
    },
    /// A comment has been removed.
    CommentRemoved { view_id: u64, address: u64 },

    // ── Bookmarks ────────────────────────────────────────────────────────────
    /// A bookmark has been added.
    BookmarkAdded {
        view_id: u64,
        address: u64,
        label: String,
    },
    /// A bookmark has been removed.
    BookmarkRemoved {
        view_id: u64,
        address: u64,
        label: String,
    },

    // ── Cross-references ─────────────────────────────────────────────────────
    /// A cross-reference has been added.
    XrefAdded {
        view_id: u64,
        from: u64,
        to: u64,
        /// Short kind tag (e.g. "call", "data-read").
        kind: String,
    },
    /// A cross-reference has been removed.
    XrefRemoved { view_id: u64, from: u64, to: u64 },

    // ── Memory ───────────────────────────────────────────────────────────────
    /// A memory region has been added.
    RegionAdded {
        view_id: u64,
        start: u64,
        end: u64,
        /// Rwx string (e.g. "r-x").
        permissions: String,
    },
    /// A memory region has been removed.
    RegionRemoved { view_id: u64, start: u64 },
    /// A memory snapshot has been taken.
    SnapshotTaken {
        view_id: u64,
        /// Numeric snapshot ID.
        snapshot_id: u64,
        /// Optional tag assigned to the snapshot.
        tag: Option<String>,
    },

    // ── Data variables ───────────────────────────────────────────────────────
    /// A data variable has been defined.
    DataVarDefined {
        view_id: u64,
        address: u64,
        type_id: u32,
    },
    /// A data variable has been undefined.
    DataVarRemoved { view_id: u64, address: u64 },

    // ── Navigation ───────────────────────────────────────────────────────────
    /// The user or a plugin has navigated to a new address.
    NavigatedTo {
        view_id: u64,
        address: u64,
        /// Short label describing the navigation source (e.g. "user", "script").
        source: String,
    },

    // ── Plugins ──────────────────────────────────────────────────────────────
    /// A plugin has been loaded.
    PluginLoaded {
        /// Plugin name.
        name: String,
        /// Plugin version string.
        version: String,
    },
    /// A plugin has been unloaded.
    PluginUnloaded { name: String },
    /// A plugin emitted a custom event payload.
    PluginEvent {
        /// Plugin that produced the event.
        plugin_name: String,
        /// Arbitrary event tag.
        event_type: String,
        /// JSON-serialised payload.
        payload: String,
    },

    // ── Analysis tasks ───────────────────────────────────────────────────────
    /// A long-running analysis task has started.
    TaskStarted {
        view_id: u64,
        /// Human-readable task name.
        task_name: String,
        /// Unique task token for correlation with later events.
        task_id: u64,
    },
    /// An analysis task has made progress.
    TaskProgress {
        task_id: u64,
        /// Progress value in [0.0, 1.0].
        progress: f32,
        /// Optional status message.
        message: Option<String>,
    },
    /// An analysis task has completed successfully.
    TaskCompleted { task_id: u64, elapsed_ms: u64 },
    /// An analysis task has failed.
    TaskFailed {
        task_id: u64,
        /// Error description.
        error: String,
    },
    /// An analysis task has been cancelled by the user.
    TaskCancelled { task_id: u64 },

    // ── Decompiler ───────────────────────────────────────────────────────────
    /// Decompiled output for a function is now available.
    DecompilationReady {
        view_id: u64,
        address: u64,
        /// Number of lines in the decompiled output.
        line_count: usize,
    },

    // ── Debugging integration ────────────────────────────────────────────────
    /// A debugger has attached to a process.
    DebuggerAttached {
        view_id: u64,
        /// OS process ID.
        pid: u32,
    },
    /// A debugger has detached.
    DebuggerDetached { view_id: u64, pid: u32 },
    /// A breakpoint has been hit.
    BreakpointHit {
        view_id: u64,
        address: u64,
        pid: u32,
        /// Thread ID that hit the breakpoint.
        tid: u32,
    },

    // ── Scripting ────────────────────────────────────────────────────────────
    /// A script has started executing.
    ScriptStarted {
        /// Script file path or inline label.
        script: String,
    },
    /// A script has finished executing.
    ScriptFinished {
        script: String,
        /// Exit code or error description.
        result: String,
    },
}

impl CoreEvent {
    /// Returns the category tag for this event (used for filtering).
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::BinaryLoaded { .. }
            | Self::BinaryClosed { .. }
            | Self::BinarySaved { .. }
            | Self::AnalysisFinished { .. } => "binary",

            Self::FunctionAdded { .. }
            | Self::FunctionRemoved { .. }
            | Self::FunctionRenamed { .. }
            | Self::FunctionPrototypeChanged { .. }
            | Self::FunctionCfgChanged { .. } => "function",

            Self::SymbolAdded { .. } | Self::SymbolRemoved { .. } | Self::SymbolRenamed { .. } => {
                "symbol"
            }

            Self::TypeDefined { .. } | Self::TypeUpdated { .. } | Self::TypeRemoved { .. } => {
                "type"
            }

            Self::PatchApplied { .. } | Self::PatchReverted { .. } => "patch",

            Self::CommentAdded { .. } | Self::CommentRemoved { .. } => "comment",

            Self::BookmarkAdded { .. } | Self::BookmarkRemoved { .. } => "bookmark",

            Self::XrefAdded { .. } | Self::XrefRemoved { .. } => "xref",

            Self::RegionAdded { .. } | Self::RegionRemoved { .. } | Self::SnapshotTaken { .. } => {
                "memory"
            }

            Self::DataVarDefined { .. } | Self::DataVarRemoved { .. } => "data",

            Self::NavigatedTo { .. } => "navigation",

            Self::PluginLoaded { .. } | Self::PluginUnloaded { .. } | Self::PluginEvent { .. } => {
                "plugin"
            }

            Self::TaskStarted { .. }
            | Self::TaskProgress { .. }
            | Self::TaskCompleted { .. }
            | Self::TaskFailed { .. }
            | Self::TaskCancelled { .. } => "task",

            Self::DecompilationReady { .. } => "decompiler",

            Self::DebuggerAttached { .. }
            | Self::DebuggerDetached { .. }
            | Self::BreakpointHit { .. } => "debugger",

            Self::ScriptStarted { .. } | Self::ScriptFinished { .. } => "script",
        }
    }

    /// Returns the view ID associated with this event, if any.
    #[must_use]
    pub const fn view_id(&self) -> Option<u64> {
        match self {
            Self::BinaryLoaded { view_id, .. }
            | Self::BinaryClosed { view_id }
            | Self::BinarySaved { view_id, .. }
            | Self::AnalysisFinished { view_id, .. }
            | Self::FunctionAdded { view_id, .. }
            | Self::FunctionRemoved { view_id, .. }
            | Self::FunctionRenamed { view_id, .. }
            | Self::FunctionPrototypeChanged { view_id, .. }
            | Self::FunctionCfgChanged { view_id, .. }
            | Self::SymbolAdded { view_id, .. }
            | Self::SymbolRemoved { view_id, .. }
            | Self::SymbolRenamed { view_id, .. }
            | Self::TypeDefined { view_id, .. }
            | Self::TypeUpdated { view_id, .. }
            | Self::TypeRemoved { view_id, .. }
            | Self::PatchApplied { view_id, .. }
            | Self::PatchReverted { view_id, .. }
            | Self::CommentAdded { view_id, .. }
            | Self::CommentRemoved { view_id, .. }
            | Self::BookmarkAdded { view_id, .. }
            | Self::BookmarkRemoved { view_id, .. }
            | Self::XrefAdded { view_id, .. }
            | Self::XrefRemoved { view_id, .. }
            | Self::RegionAdded { view_id, .. }
            | Self::RegionRemoved { view_id, .. }
            | Self::SnapshotTaken { view_id, .. }
            | Self::DataVarDefined { view_id, .. }
            | Self::DataVarRemoved { view_id, .. }
            | Self::NavigatedTo { view_id, .. }
            | Self::DecompilationReady { view_id, .. }
            | Self::DebuggerAttached { view_id, .. }
            | Self::DebuggerDetached { view_id, .. }
            | Self::BreakpointHit { view_id, .. }
            | Self::TaskStarted { view_id, .. } => Some(*view_id),

            _ => None,
        }
    }

    /// Returns `true` if this event is directly visible to the end user and
    /// warrants a status-bar or notification display.
    #[must_use]
    pub const fn is_user_visible(&self) -> bool {
        matches!(
            self,
            Self::BinaryLoaded { .. }
                | Self::BinaryClosed { .. }
                | Self::BinarySaved { .. }
                | Self::AnalysisFinished { .. }
                | Self::TaskCompleted { .. }
                | Self::TaskFailed { .. }
                | Self::BreakpointHit { .. }
                | Self::ScriptFinished { .. }
        )
    }
}

impl fmt::Display for CoreEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinaryLoaded { path, view_id } => {
                write!(f, "[binary] loaded {path} (view={view_id})")
            }
            Self::BinaryClosed { view_id } => write!(f, "[binary] closed view={view_id}"),
            Self::BinarySaved { view_id, path } => {
                write!(f, "[binary] saved view={view_id} → {path}")
            }
            Self::AnalysisFinished {
                view_id,
                elapsed_ms,
            } => {
                write!(f, "[binary] analysis done view={view_id} in {elapsed_ms}ms")
            }
            Self::FunctionAdded {
                view_id,
                address,
                name,
            } => {
                write!(
                    f,
                    "[function] added 0x{address:x} {} (view={view_id})",
                    name.as_deref().unwrap_or("<unnamed>")
                )
            }
            Self::FunctionRemoved { view_id, address } => {
                write!(f, "[function] removed 0x{address:x} (view={view_id})")
            }
            Self::FunctionRenamed {
                view_id,
                address,
                old_name,
                new_name,
            } => {
                write!(
                    f,
                    "[function] renamed 0x{address:x} {old_name} → {new_name} (view={view_id})"
                )
            }
            Self::SymbolAdded {
                view_id,
                address,
                name,
            } => {
                write!(f, "[symbol] added {name} @ 0x{address:x} (view={view_id})")
            }
            Self::SymbolRemoved {
                view_id,
                address,
                name,
            } => {
                write!(
                    f,
                    "[symbol] removed {name} @ 0x{address:x} (view={view_id})"
                )
            }
            Self::TypeDefined {
                view_id,
                type_id,
                name,
            } => {
                write!(f, "[type] defined {name} id={type_id} (view={view_id})")
            }
            Self::PatchApplied {
                view_id,
                address,
                length,
            } => {
                write!(f, "[patch] applied 0x{address:x}+{length} (view={view_id})")
            }
            Self::TaskStarted {
                view_id,
                task_name,
                task_id,
            } => {
                write!(
                    f,
                    "[task] started {task_name} id={task_id} (view={view_id})"
                )
            }
            Self::TaskCompleted {
                task_id,
                elapsed_ms,
            } => {
                write!(f, "[task] completed id={task_id} in {elapsed_ms}ms")
            }
            Self::TaskFailed { task_id, error } => {
                write!(f, "[task] failed id={task_id}: {error}")
            }
            Self::BreakpointHit {
                view_id,
                address,
                pid,
                tid,
            } => {
                write!(
                    f,
                    "[dbg] breakpoint hit 0x{address:x} pid={pid} tid={tid} (view={view_id})"
                )
            }
            other => write!(f, "[{}] {other:?}", other.category()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventFilter
// ─────────────────────────────────────────────────────────────────────────────

/// A composable filter that decides whether a [`CoreEvent`] is interesting to
/// a particular subscriber.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// If non-empty, only events whose category is in this list are accepted.
    categories: Vec<&'static str>,
    /// If non-empty, only events for these view IDs are accepted.
    view_ids: Vec<u64>,
}

impl EventFilter {
    /// Create a new, empty filter that accepts all events.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to specific category tags.
    #[must_use]
    pub fn with_category(mut self, category: &'static str) -> Self {
        self.categories.push(category);
        self
    }

    /// Restrict to a specific view ID.
    #[must_use]
    pub fn with_view_id(mut self, view_id: u64) -> Self {
        self.view_ids.push(view_id);
        self
    }

    /// Returns `true` if the event passes this filter.
    #[must_use]
    pub fn accepts(&self, event: &CoreEvent) -> bool {
        if !self.categories.is_empty() && !self.categories.contains(&event.category()) {
            return false;
        }
        if !self.view_ids.is_empty() {
            match event.view_id() {
                Some(vid) if self.view_ids.contains(&vid) => {}
                Some(_) => return false,
                None => {}
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventBus
// ─────────────────────────────────────────────────────────────────────────────

/// Shared broadcast channel for [`CoreEvent`] messages.
///
/// The bus is cheaply cloneable via its inner [`Arc`]; all clones share the
/// same underlying channel.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

struct EventBusInner {
    sender: Sender<CoreEvent>,
    /// Counter tracking how many events have been published since creation.
    published: AtomicU64,
    /// Channel capacity (number of events retained for lagging receivers).
    capacity: usize,
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBus")
            .field("capacity", &self.inner.capacity)
            .field("published", &self.inner.published.load(Ordering::Relaxed))
            .field("receivers", &self.inner.sender.receiver_count())
            .finish_non_exhaustive()
    }
}

impl EventBus {
    /// Create a new event bus with the given channel capacity.
    ///
    /// `capacity` is the number of events the channel buffers for lagging
    /// subscribers.  Values between 64 and 4096 are typical; choose higher if
    /// events are produced in bursts.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            inner: Arc::new(EventBusInner {
                sender,
                published: AtomicU64::new(0),
                capacity,
            }),
        }
    }

    /// Create a new subscriber handle.
    ///
    /// The returned [`Receiver`] will receive all events published *after* this
    /// call.  Events published before `subscribe()` is called are not delivered
    /// to the new subscriber.
    #[must_use]
    pub fn subscribe(&self) -> Receiver<CoreEvent> {
        self.inner.sender.subscribe()
    }

    /// Publish an event to all active subscribers.
    ///
    /// Returns the number of subscribers that received the event.  A return
    /// value of `0` simply means there are no active subscribers — it is not
    /// an error.
    #[must_use]
    pub fn publish(&self, event: CoreEvent) -> usize {
        self.inner.published.fetch_add(1, Ordering::Relaxed);
        self.inner.sender.send(event).unwrap_or_default()
    }

    /// Total number of events published through this bus since creation.
    #[must_use]
    pub fn published_count(&self) -> u64 {
        self.inner.published.load(Ordering::Relaxed)
    }

    /// Number of active subscriber handles.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.inner.sender.receiver_count()
    }

    /// Channel capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FilteredReceiver
// ─────────────────────────────────────────────────────────────────────────────

/// A wrapper around [`Receiver<CoreEvent>`] that discards events that do not
/// match an [`EventFilter`].
pub struct FilteredReceiver {
    inner: Receiver<CoreEvent>,
    filter: EventFilter,
}

impl FilteredReceiver {
    /// Create a filtered receiver from a raw broadcast receiver and a filter.
    #[must_use]
    pub const fn new(inner: Receiver<CoreEvent>, filter: EventFilter) -> Self {
        Self { inner, filter }
    }

    /// Receive the next event that matches the filter.
    ///
    /// Calls [`Receiver::recv`] in a loop, discarding non-matching events.
    /// Returns an error if the channel is closed or the receiver has lagged.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn recv(&mut self) -> Result<CoreEvent, broadcast::error::RecvError> {
        loop {
            let event = self.inner.recv().await?;
            if self.filter.accepts(&event) {
                return Ok(event);
            }
        }
    }

    /// Non-async try-receive.  Returns `None` if no matching event is
    /// immediately available.
    pub fn try_recv(&mut self) -> Option<CoreEvent> {
        loop {
            match self.inner.try_recv() {
                Ok(evt) => {
                    if self.filter.accepts(&evt) {
                        return Some(evt);
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventRecorder
// ─────────────────────────────────────────────────────────────────────────────

/// A helper that records all events received from an [`EventBus`] into an
/// in-memory log.  Useful for testing and audit trails.
#[derive(Debug, Default)]
pub struct EventRecorder {
    log: Vec<CoreEvent>,
}

impl EventRecorder {
    /// Create a new, empty recorder.
    #[must_use]
    pub const fn new() -> Self {
        Self { log: Vec::new() }
    }

    /// Push an event into the log.
    pub fn record(&mut self, event: CoreEvent) {
        self.log.push(event);
    }

    /// Drain all recorded events from a receiver into this log.
    ///
    /// Uses `try_recv` so it is non-blocking.
    pub fn drain_from(&mut self, rx: &mut Receiver<CoreEvent>) {
        while let Ok(evt) = rx.try_recv() {
            self.log.push(evt);
        }
    }

    /// Returns a slice of all recorded events.
    #[must_use]
    pub fn events(&self) -> &[CoreEvent] {
        &self.log
    }

    /// Returns all events in a specific category.
    #[must_use]
    pub fn events_in_category(&self, category: &str) -> Vec<&CoreEvent> {
        self.log
            .iter()
            .filter(|e| e.category() == category)
            .collect()
    }

    /// Returns all events for a specific view ID.
    #[must_use]
    pub fn events_for_view(&self, view_id: u64) -> Vec<&CoreEvent> {
        self.log
            .iter()
            .filter(|e| e.view_id() == Some(view_id))
            .collect()
    }

    /// Clear all recorded events.
    pub fn clear(&mut self) {
        self.log.clear();
    }

    /// Returns the total number of recorded events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.log.len()
    }

    /// Returns `true` if no events have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_category() {
        assert_eq!(
            CoreEvent::BinaryLoaded {
                path: "x".into(),
                view_id: 1
            }
            .category(),
            "binary"
        );
        assert_eq!(
            CoreEvent::FunctionAdded {
                view_id: 1,
                address: 0x1000,
                name: None
            }
            .category(),
            "function"
        );
        assert_eq!(
            CoreEvent::TypeDefined {
                view_id: 1,
                type_id: 5,
                name: "Foo".into()
            }
            .category(),
            "type"
        );
        assert_eq!(
            CoreEvent::TaskCompleted {
                task_id: 1,
                elapsed_ms: 100
            }
            .category(),
            "task"
        );
    }

    #[test]
    fn event_view_id() {
        let e = CoreEvent::BinaryLoaded {
            path: "a".into(),
            view_id: 42,
        };
        assert_eq!(e.view_id(), Some(42));

        let e2 = CoreEvent::PluginLoaded {
            name: "p".into(),
            version: "1.0".into(),
        };
        assert_eq!(e2.view_id(), None);
    }

    #[test]
    fn event_is_user_visible() {
        assert!(
            CoreEvent::BinaryLoaded {
                path: "x".into(),
                view_id: 1
            }
            .is_user_visible()
        );
        assert!(
            CoreEvent::TaskCompleted {
                task_id: 1,
                elapsed_ms: 0
            }
            .is_user_visible()
        );
        assert!(
            !CoreEvent::SymbolAdded {
                view_id: 1,
                address: 0,
                name: "foo".into()
            }
            .is_user_visible()
        );
    }

    #[test]
    fn event_display() {
        let e = CoreEvent::FunctionAdded {
            view_id: 1,
            address: 0x4000,
            name: Some("main".into()),
        };
        let s = e.to_string();
        assert!(s.contains("0x4000"));
        assert!(s.contains("main"));
    }

    #[tokio::test]
    async fn event_bus_publish_receive() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();

        let evt = CoreEvent::BinaryLoaded {
            path: "test.exe".into(),
            view_id: 1,
        };
        let n = bus.publish(evt.clone());
        assert_eq!(n, 1);

        let received = rx.recv().await.unwrap();
        assert_eq!(received, evt);
        assert_eq!(bus.published_count(), 1);
    }

    #[tokio::test]
    async fn event_bus_multiple_subscribers() {
        let bus = EventBus::new(64);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let delivered = bus.publish(CoreEvent::BinaryClosed { view_id: 5 });
        assert_eq!(
            delivered, 2,
            "two subscribers should have received the event"
        );

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1, e2);
    }

    #[tokio::test]
    async fn event_bus_no_subscribers() {
        let bus = EventBus::new(64);
        // No subscribers; publish should not panic.
        let n = bus.publish(CoreEvent::BinaryClosed { view_id: 1 });
        assert_eq!(n, 0);
        assert_eq!(bus.published_count(), 1);
    }

    #[test]
    fn event_filter_category() {
        let filter = EventFilter::new().with_category("function");
        let fn_evt = CoreEvent::FunctionAdded {
            view_id: 1,
            address: 0,
            name: None,
        };
        let sym_evt = CoreEvent::SymbolAdded {
            view_id: 1,
            address: 0,
            name: "x".into(),
        };
        assert!(filter.accepts(&fn_evt));
        assert!(!filter.accepts(&sym_evt));
    }

    #[test]
    fn event_filter_view_id() {
        let filter = EventFilter::new().with_view_id(7);
        let e1 = CoreEvent::FunctionAdded {
            view_id: 7,
            address: 0,
            name: None,
        };
        let e2 = CoreEvent::FunctionAdded {
            view_id: 99,
            address: 0,
            name: None,
        };
        assert!(filter.accepts(&e1));
        assert!(!filter.accepts(&e2));
    }

    #[test]
    fn event_filter_combined() {
        let filter = EventFilter::new().with_category("function").with_view_id(3);
        let matching = CoreEvent::FunctionAdded {
            view_id: 3,
            address: 0,
            name: None,
        };
        let wrong_view = CoreEvent::FunctionAdded {
            view_id: 9,
            address: 0,
            name: None,
        };
        let wrong_cat = CoreEvent::SymbolAdded {
            view_id: 3,
            address: 0,
            name: "s".into(),
        };
        assert!(filter.accepts(&matching));
        assert!(!filter.accepts(&wrong_view));
        assert!(!filter.accepts(&wrong_cat));
    }

    #[tokio::test]
    async fn filtered_receiver_discards() {
        let bus = EventBus::new(64);
        let rx = bus.subscribe();
        let filter = EventFilter::new().with_category("function");
        let mut frx = FilteredReceiver::new(rx, filter);

        // Publish a symbol event first (should be discarded) then a function event.
        let n_sym = bus.publish(CoreEvent::SymbolAdded {
            view_id: 1,
            address: 0,
            name: "x".into(),
        });
        let n_fn = bus.publish(CoreEvent::FunctionAdded {
            view_id: 1,
            address: 0x1000,
            name: None,
        });
        assert_eq!(n_sym, 1, "filtered receiver counts as one subscriber");
        assert_eq!(n_fn, 1, "filtered receiver counts as one subscriber");

        let evt = frx.recv().await.unwrap();
        assert_eq!(evt.category(), "function");
    }

    #[test]
    fn event_recorder_drain() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let mut recorder = EventRecorder::new();

        let n_loaded = bus.publish(CoreEvent::BinaryLoaded {
            path: "a".into(),
            view_id: 1,
        });
        let n_closed = bus.publish(CoreEvent::BinaryClosed { view_id: 1 });
        assert_eq!(n_loaded, 1);
        assert_eq!(n_closed, 1);

        recorder.drain_from(&mut rx);
        assert_eq!(recorder.len(), 2);

        let binary_evts = recorder.events_in_category("binary");
        assert_eq!(binary_evts.len(), 2);

        recorder.clear();
        assert!(recorder.is_empty());
    }

    #[test]
    fn event_bus_debug_format() {
        let bus = EventBus::new(128);
        let s = format!("{bus:?}");
        assert!(s.contains("capacity"));
    }
}
