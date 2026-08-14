//! Per-view plugin context, lifecycle management, and inter-plugin communication.
//!
//! This module provides:
//!
//! | Type | Role |
//! |------|------|
//! | [`ViewPlugin`] | Trait that per-view plugin implementations must satisfy |
//! | [`PluginContext`] | Holds the live state of every plugin attached to a view |
//! | [`PluginAction`] | A discrete analyst action (rename, comment, annotate, mark) |
//! | [`ActionHistory`] | Undo/redo stack for plugin actions |
//! | [`PluginInterop`] | Typed mailbox for plugin-to-plugin communication |

/// Re-export of [`crate::address::Address`] so plugins can refer to addresses
/// without importing the `address` module directly.
pub use crate::address::Address;
use crate::errors::{CoreError, Result};
use std::any::Any;
use std::collections::{HashMap, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// PluginId
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a plugin attached to a binary view.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginId(String);

impl PluginId {
    /// Create from any string-like value.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Return the string ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PluginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Plugin({})", self.0)
    }
}

impl From<&str> for PluginId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for PluginId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginLifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Current lifecycle state of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginLifecycle {
    /// Plugin has been registered but not yet started.
    Registered,
    /// Plugin is active and running.
    Active,
    /// Plugin has been paused.
    Paused,
    /// Plugin has been stopped and cannot be restarted without re-registration.
    Stopped,
    /// Plugin failed to initialise or crashed.
    Faulted,
}

impl std::fmt::Display for PluginLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registered => write!(f, "registered"),
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Stopped => write!(f, "stopped"),
            Self::Faulted => write!(f, "faulted"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ViewPlugin — the trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait that per-view plugin implementations must satisfy.
pub trait ViewPlugin: Send + Sync + std::fmt::Debug {
    /// Return the canonical plugin ID.
    fn id(&self) -> PluginId;

    /// Human-readable display name.
    fn display_name(&self) -> &'static str {
        "unnamed plugin"
    }

    /// Called when the plugin is activated for a view.
    /// The `ctx` is a mutable reference to the plugin's private state box.
    fn on_activate(&self, ctx: &mut PluginStateBox) {
        let _ = ctx;
    }

    /// Called when the plugin is deactivated.
    fn on_deactivate(&self, ctx: &mut PluginStateBox) {
        let _ = ctx;
    }

    /// Called when the plugin is paused.
    fn on_pause(&self, ctx: &mut PluginStateBox) {
        let _ = ctx;
    }

    /// Called when the plugin is resumed after a pause.
    fn on_resume(&self, ctx: &mut PluginStateBox) {
        let _ = ctx;
    }

    /// Handle an incoming inter-plugin message.  Returns `true` if handled.
    fn handle_message(&self, msg: &PluginMessage, ctx: &mut PluginStateBox) -> bool {
        let _ = (msg, ctx);
        false
    }
}

/// Type-erased plugin state box.
pub type PluginStateBox = Box<dyn Any + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// PluginAction
// ─────────────────────────────────────────────────────────────────────────────

/// A discrete, reversible action that a plugin performs on the binary view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginAction {
    /// Rename a symbol or function.
    Rename {
        /// Virtual address of the renamed item.
        address: u64,
        /// Name before the action.
        old_name: String,
        /// Name after the action.
        new_name: String,
    },

    /// Add or update a comment.
    Comment {
        /// Virtual address.
        address: u64,
        /// Comment text before the action (`None` = no prior comment).
        old_text: Option<String>,
        /// Comment text after the action (`None` = comment removed).
        new_text: Option<String>,
    },

    /// Annotate an address with arbitrary key-value metadata.
    Annotate {
        /// Virtual address.
        address: u64,
        /// Annotation key.
        key: String,
        /// Previous value (`None` = no prior annotation).
        old_value: Option<String>,
        /// New value (`None` = annotation removed).
        new_value: Option<String>,
    },

    /// Mark an address with a named marker (e.g. bookmark, colour annotation).
    Mark {
        /// Virtual address.
        address: u64,
        /// Marker kind (e.g. `"bookmark"`, `"highlight"`).
        kind: String,
        /// Marker value before the action.
        old_value: Option<String>,
        /// Marker value after the action.
        new_value: Option<String>,
    },
}

impl PluginAction {
    /// Produce the inverse action (for undo).
    #[must_use]
    pub fn inverse(&self) -> Self {
        match self {
            Self::Rename {
                address,
                old_name,
                new_name,
            } => Self::Rename {
                address: *address,
                old_name: new_name.clone(),
                new_name: old_name.clone(),
            },
            Self::Comment {
                address,
                old_text,
                new_text,
            } => Self::Comment {
                address: *address,
                old_text: new_text.clone(),
                new_text: old_text.clone(),
            },
            Self::Annotate {
                address,
                key,
                old_value,
                new_value,
            } => Self::Annotate {
                address: *address,
                key: key.clone(),
                old_value: new_value.clone(),
                new_value: old_value.clone(),
            },
            Self::Mark {
                address,
                kind,
                old_value,
                new_value,
            } => Self::Mark {
                address: *address,
                kind: kind.clone(),
                old_value: new_value.clone(),
                new_value: old_value.clone(),
            },
        }
    }

    /// Return the virtual address associated with this action.
    #[must_use]
    pub const fn address(&self) -> u64 {
        match self {
            Self::Rename { address, .. }
            | Self::Comment { address, .. }
            | Self::Annotate { address, .. }
            | Self::Mark { address, .. } => *address,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ActionHistory — undo/redo stack
// ─────────────────────────────────────────────────────────────────────────────

/// Undo/redo history of plugin actions.
///
/// Actions are stored in a `VecDeque`.  The `cursor` points to the next undo
/// position (i.e. `history[cursor - 1]` is the last committed action).
/// `redo` moves the cursor forward; `undo` moves it backward.
#[derive(Debug, Default)]
pub struct ActionHistory {
    history: Vec<PluginAction>,
    cursor: usize,
    max_size: usize,
}

impl ActionHistory {
    /// Create a history with a maximum capacity of `max_size` actions.
    ///
    /// Older entries are discarded when the capacity is exceeded.
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self {
            history: Vec::new(),
            cursor: 0,
            max_size,
        }
    }

    /// Push a new action onto the history.
    ///
    /// Any undone actions (future history) are discarded.
    pub fn push(&mut self, action: PluginAction) {
        // Discard anything ahead of the cursor (redo stack).
        self.history.truncate(self.cursor);
        self.history.push(action);
        self.cursor += 1;

        // Trim if over capacity.
        if self.history.len() > self.max_size && self.max_size > 0 {
            let excess = self.history.len() - self.max_size;
            self.history.drain(..excess);
            self.cursor = self.cursor.saturating_sub(excess);
        }
    }

    /// Undo the last action.  Returns the inverse action (for applying), or
    /// `None` if there is nothing to undo.
    pub fn undo(&mut self) -> Option<PluginAction> {
        if self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        Some(self.history[self.cursor].inverse())
    }

    /// Redo the previously undone action.  Returns the action to apply, or
    /// `None` if there is nothing to redo.
    pub fn redo(&mut self) -> Option<PluginAction> {
        if self.cursor >= self.history.len() {
            return None;
        }
        let action = self.history[self.cursor].clone();
        self.cursor += 1;
        Some(action)
    }

    /// Return `true` if there are actions available to undo.
    #[must_use]
    pub const fn can_undo(&self) -> bool {
        self.cursor > 0
    }

    /// Return `true` if there are actions available to redo.
    #[must_use]
    pub const fn can_redo(&self) -> bool {
        self.cursor < self.history.len()
    }

    /// Total number of stored actions (including undone ones).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.history.len()
    }

    /// Return `true` if no actions have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.history.clear();
        self.cursor = 0;
    }

    /// Peek at the last committed action without undoing it.
    #[must_use]
    pub fn peek_last(&self) -> Option<&PluginAction> {
        if self.cursor == 0 {
            None
        } else {
            self.history.get(self.cursor - 1)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginMessage — inter-plugin communication payload
// ─────────────────────────────────────────────────────────────────────────────

/// A message passed between plugins via `PluginInterop`.
#[derive(Debug, Clone)]
pub struct PluginMessage {
    /// Sender plugin ID.
    pub from: PluginId,
    /// Optional destination plugin ID (`None` = broadcast to all).
    pub to: Option<PluginId>,
    /// Message topic / type tag.
    pub topic: String,
    /// Opaque payload encoded as a UTF-8 string (typically JSON or msgpack hex).
    pub payload: String,
}

impl PluginMessage {
    /// Create a directed message.
    #[must_use]
    pub fn directed(
        from: PluginId,
        to: PluginId,
        topic: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            from,
            to: Some(to),
            topic: topic.into(),
            payload: payload.into(),
        }
    }

    /// Create a broadcast message (no specific recipient).
    #[must_use]
    pub fn broadcast(from: PluginId, topic: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            from,
            to: None,
            topic: topic.into(),
            payload: payload.into(),
        }
    }

    /// Return `true` if this is a broadcast message.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        self.to.is_none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginInterop — plugin-to-plugin mailbox
// ─────────────────────────────────────────────────────────────────────────────

/// Typed mailbox enabling plugins to send messages to other plugins.
///
/// Each plugin has a bounded inbox.  Messages that do not fit are dropped
/// (oldest-first).  Plugins poll their inbox on each execution cycle.
#[derive(Debug, Default)]
pub struct PluginInterop {
    /// `plugin_id → inbox`
    inboxes: HashMap<PluginId, VecDeque<PluginMessage>>,
    /// Maximum inbox depth per plugin.
    inbox_depth: usize,
}

impl PluginInterop {
    /// Create an interop bus with a per-plugin inbox depth of `depth`.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self {
            inboxes: HashMap::new(),
            inbox_depth: depth,
        }
    }

    /// Register a plugin inbox.  Does nothing if already registered.
    pub fn register_inbox(&mut self, id: &PluginId) {
        self.inboxes.entry(id.clone()).or_default();
    }

    /// Remove a plugin's inbox.
    pub fn unregister_inbox(&mut self, id: &PluginId) {
        self.inboxes.remove(id);
    }

    /// Send a message.  If the target's inbox is full, the oldest message is
    /// dropped.  Broadcasts are delivered to all registered inboxes.
    pub fn send(&mut self, msg: PluginMessage) {
        if let Some(to) = msg.to.clone() {
            if let Some(inbox) = self.inboxes.get_mut(&to) {
                if self.inbox_depth > 0 && inbox.len() >= self.inbox_depth {
                    inbox.pop_front();
                }
                inbox.push_back(msg);
            }
        } else {
            // Broadcast: clone to every inbox except the sender.
            let sender = msg.from.clone();
            let ids: Vec<PluginId> = self
                .inboxes
                .keys()
                .filter(|id| *id != &sender)
                .cloned()
                .collect();
            for id in ids {
                let m = msg.clone();
                if let Some(inbox) = self.inboxes.get_mut(&id) {
                    if self.inbox_depth > 0 && inbox.len() >= self.inbox_depth {
                        inbox.pop_front();
                    }
                    inbox.push_back(m);
                }
            }
        }
    }

    /// Drain all pending messages for `id`.
    pub fn drain(&mut self, id: &PluginId) -> Vec<PluginMessage> {
        self.inboxes
            .get_mut(id)
            .map(|inbox| inbox.drain(..).collect())
            .unwrap_or_default()
    }

    /// Peek at the next message for `id` without consuming it.
    #[must_use]
    pub fn peek(&self, id: &PluginId) -> Option<&PluginMessage> {
        self.inboxes.get(id)?.front()
    }

    /// Number of pending messages for `id`.
    #[must_use]
    pub fn pending(&self, id: &PluginId) -> usize {
        self.inboxes
            .get(id)
            .map_or(0, std::collections::VecDeque::len)
    }

    /// Total number of registered inboxes.
    #[must_use]
    pub fn inbox_count(&self) -> usize {
        self.inboxes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginContext — per-view plugin orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Record tracking a single plugin's live state within a view.
struct PluginRecord {
    /// The plugin implementation.
    plugin: Box<dyn ViewPlugin>,
    /// Private plugin state.
    state: PluginStateBox,
    /// Lifecycle state.
    lifecycle: PluginLifecycle,
}

/// Per-view orchestrator for all attached plugins.
///
/// Manages plugin lifecycle, routes inter-plugin messages, and maintains the
/// action history for undo/redo operations.
pub struct PluginContext {
    plugins: HashMap<PluginId, PluginRecord>,
    interop: PluginInterop,
    history: ActionHistory,
}

impl PluginContext {
    /// Create an empty context with the given undo-history capacity and inbox
    /// depth.
    #[must_use]
    pub fn new(history_capacity: usize, inbox_depth: usize) -> Self {
        Self {
            plugins: HashMap::new(),
            interop: PluginInterop::new(inbox_depth),
            history: ActionHistory::new(history_capacity),
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Register a plugin.  The plugin starts in `Registered` state.
    ///
    /// # Errors
    /// Returns `Err` if a plugin with the same ID is already registered.
    pub fn register(
        &mut self,
        plugin: Box<dyn ViewPlugin>,
        initial_state: PluginStateBox,
    ) -> Result<()> {
        let id = plugin.id();
        if self.plugins.contains_key(&id) {
            return Err(CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin already registered".into(),
            });
        }
        self.interop.register_inbox(&id);
        self.plugins.insert(
            id,
            PluginRecord {
                plugin,
                state: initial_state,
                lifecycle: PluginLifecycle::Registered,
            },
        );
        Ok(())
    }

    /// Activate a registered plugin.
    ///
    /// # Errors
    /// Returns `Err` if the plugin is not in `Registered` or `Paused` state.
    pub fn activate(&mut self, id: &PluginId) -> Result<()> {
        let rec = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin not found".into(),
            })?;
        match rec.lifecycle {
            PluginLifecycle::Registered | PluginLifecycle::Paused => {
                rec.plugin.on_activate(&mut rec.state);
                rec.lifecycle = PluginLifecycle::Active;
                Ok(())
            }
            state => Err(CoreError::PluginError {
                plugin: id.0.clone(),
                message: format!("cannot activate plugin in state '{state}'"),
            }),
        }
    }

    /// Deactivate (stop) a plugin.
    ///
    /// # Errors
    /// Returns `Err` if the plugin is not found.
    pub fn deactivate(&mut self, id: &PluginId) -> Result<()> {
        let rec = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin not found".into(),
            })?;
        rec.plugin.on_deactivate(&mut rec.state);
        rec.lifecycle = PluginLifecycle::Stopped;
        Ok(())
    }

    /// Pause an active plugin.
    ///
    /// # Errors
    /// Returns `Err` if the plugin is not in `Active` state.
    pub fn pause(&mut self, id: &PluginId) -> Result<()> {
        let rec = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin not found".into(),
            })?;
        if rec.lifecycle != PluginLifecycle::Active {
            return Err(CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin must be Active to pause".into(),
            });
        }
        rec.plugin.on_pause(&mut rec.state);
        rec.lifecycle = PluginLifecycle::Paused;
        Ok(())
    }

    /// Resume a paused plugin.
    ///
    /// # Errors
    /// Returns `Err` if the plugin is not in `Paused` state.
    pub fn resume(&mut self, id: &PluginId) -> Result<()> {
        let rec = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin not found".into(),
            })?;
        if rec.lifecycle != PluginLifecycle::Paused {
            return Err(CoreError::PluginError {
                plugin: id.0.clone(),
                message: "plugin must be Paused to resume".into(),
            });
        }
        rec.plugin.on_resume(&mut rec.state);
        rec.lifecycle = PluginLifecycle::Active;
        Ok(())
    }

    /// Remove a plugin entirely.  Returns `true` if it was present.
    pub fn unregister(&mut self, id: &PluginId) -> bool {
        if self.plugins.remove(id).is_some() {
            self.interop.unregister_inbox(id);
            true
        } else {
            false
        }
    }

    /// Return the lifecycle state of `id`.
    #[must_use]
    pub fn lifecycle(&self, id: &PluginId) -> Option<PluginLifecycle> {
        self.plugins.get(id).map(|r| r.lifecycle)
    }

    /// Return `true` if a plugin with `id` is registered.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.plugins.contains_key(id)
    }

    /// Number of registered plugins.
    #[must_use]
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Iterate over all registered plugin IDs.
    pub fn ids(&self) -> impl Iterator<Item = &PluginId> {
        self.plugins.keys()
    }

    // ── Action history ────────────────────────────────────────────────────────

    /// Record a plugin action onto the undo stack.
    pub fn record_action(&mut self, action: PluginAction) {
        self.history.push(action);
    }

    /// Undo the last action.  Returns the inverse action to apply, or `None`.
    pub fn undo(&mut self) -> Option<PluginAction> {
        self.history.undo()
    }

    /// Redo the last undone action.  Returns the action to apply, or `None`.
    pub fn redo(&mut self) -> Option<PluginAction> {
        self.history.redo()
    }

    /// Return `true` if there is an action to undo.
    #[must_use]
    pub const fn can_undo(&self) -> bool {
        self.history.can_undo()
    }

    /// Return `true` if there is an action to redo.
    #[must_use]
    pub const fn can_redo(&self) -> bool {
        self.history.can_redo()
    }

    // ── Inter-plugin messaging ────────────────────────────────────────────────

    /// Send a message.  Delivered via `PluginInterop`.
    pub fn send_message(&mut self, msg: PluginMessage) {
        self.interop.send(msg);
    }

    /// Drain the inbox of the given plugin, delivering messages to `handle_message`.
    pub fn dispatch_messages(&mut self, id: &PluginId) {
        let messages = self.interop.drain(id);
        if let Some(rec) = self.plugins.get_mut(id) {
            for msg in messages {
                rec.plugin.handle_message(&msg, &mut rec.state);
            }
        }
    }

    /// Return the number of pending messages for `id`.
    #[must_use]
    pub fn pending_messages(&self, id: &PluginId) -> usize {
        self.interop.pending(id)
    }

    // ── Typed state access ────────────────────────────────────────────────────

    /// Downcast the state of `id` to `&T`.
    ///
    /// Returns `None` if the plugin is not registered or the type does not
    /// match.
    #[must_use]
    pub fn get_state<T: 'static>(&self, id: &PluginId) -> Option<&T> {
        self.plugins.get(id)?.state.downcast_ref::<T>()
    }

    /// Downcast the state of `id` to `&mut T`.
    #[must_use]
    pub fn get_state_mut<T: 'static>(&mut self, id: &PluginId) -> Option<&mut T> {
        self.plugins.get_mut(id)?.state.downcast_mut::<T>()
    }
}

impl std::fmt::Debug for PluginContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginContext")
            .field("plugins", &self.plugins.len())
            .field("interop", &self.interop)
            .field("history", &self.history)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stub plugins ──────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct CounterPlugin {
        id: PluginId,
        activation_count: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    impl CounterPlugin {
        fn new(name: &str) -> (Self, std::sync::Arc<std::sync::atomic::AtomicU32>) {
            let count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            (
                Self {
                    id: PluginId::new(name),
                    activation_count: count.clone(),
                },
                count,
            )
        }
    }

    impl ViewPlugin for CounterPlugin {
        fn id(&self) -> PluginId {
            self.id.clone()
        }
        fn display_name(&self) -> &'static str {
            "Counter"
        }
        fn on_activate(&self, _: &mut PluginStateBox) {
            self.activation_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct EchoPlugin {
        id: PluginId,
    }

    impl EchoPlugin {
        fn new(name: &str) -> Self {
            Self {
                id: PluginId::new(name),
            }
        }
    }

    impl ViewPlugin for EchoPlugin {
        fn id(&self) -> PluginId {
            self.id.clone()
        }
        fn handle_message(&self, msg: &PluginMessage, ctx: &mut PluginStateBox) -> bool {
            if let Some(v) = ctx.downcast_mut::<Vec<String>>() {
                v.push(msg.payload.clone());
            }
            true
        }
    }

    // ── PluginId ──────────────────────────────────────────────────────────────

    #[test]
    fn plugin_id_equality() {
        let a = PluginId::new("foo");
        let b = PluginId::new("foo");
        let c = PluginId::new("bar");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn plugin_id_display() {
        assert_eq!(PluginId::new("x").to_string(), "Plugin(x)");
    }

    // ── PluginAction ──────────────────────────────────────────────────────────

    #[test]
    fn action_rename_inverse() {
        let action = PluginAction::Rename {
            address: 0x1000,
            old_name: "sub_1000".into(),
            new_name: "main".into(),
        };
        let inv = action.inverse();
        if let PluginAction::Rename {
            old_name, new_name, ..
        } = inv
        {
            assert_eq!(old_name, "main");
            assert_eq!(new_name, "sub_1000");
        } else {
            panic!("wrong inverse variant");
        }
    }

    #[test]
    fn action_comment_inverse() {
        let action = PluginAction::Comment {
            address: 0x200,
            old_text: None,
            new_text: Some("entry point".into()),
        };
        let inv = action.inverse();
        if let PluginAction::Comment {
            old_text, new_text, ..
        } = inv
        {
            assert_eq!(old_text, Some("entry point".into()));
            assert!(new_text.is_none());
        } else {
            panic!();
        }
    }

    #[test]
    fn action_annotate_inverse() {
        let action = PluginAction::Annotate {
            address: 0x300,
            key: "color".into(),
            old_value: None,
            new_value: Some("red".into()),
        };
        let inv = action.inverse();
        if let PluginAction::Annotate {
            old_value,
            new_value,
            ..
        } = inv
        {
            assert_eq!(old_value, Some("red".into()));
            assert!(new_value.is_none());
        } else {
            panic!();
        }
    }

    #[test]
    fn action_mark_inverse() {
        let action = PluginAction::Mark {
            address: 0x400,
            kind: "bookmark".into(),
            old_value: None,
            new_value: Some("entry".into()),
        };
        let inv = action.inverse();
        if let PluginAction::Mark {
            old_value,
            new_value,
            ..
        } = inv
        {
            assert_eq!(old_value, Some("entry".into()));
            assert!(new_value.is_none());
        } else {
            panic!();
        }
    }

    #[test]
    fn action_address() {
        let a = PluginAction::Rename {
            address: 0xDEAD,
            old_name: "x".into(),
            new_name: "y".into(),
        };
        assert_eq!(a.address(), 0xDEAD);
    }

    // ── ActionHistory ─────────────────────────────────────────────────────────

    #[test]
    fn history_push_and_undo() {
        let mut hist = ActionHistory::new(10);
        hist.push(PluginAction::Rename {
            address: 0x100,
            old_name: "a".into(),
            new_name: "b".into(),
        });
        assert!(hist.can_undo());
        let inv = hist.undo().unwrap();
        if let PluginAction::Rename { new_name, .. } = inv {
            assert_eq!(new_name, "a");
        }
        assert!(!hist.can_undo());
    }

    #[test]
    fn history_undo_redo() {
        let mut hist = ActionHistory::new(10);
        hist.push(PluginAction::Comment {
            address: 0x200,
            old_text: None,
            new_text: Some("c".into()),
        });
        hist.undo();
        assert!(hist.can_redo());
        let redo = hist.redo().unwrap();
        if let PluginAction::Comment { new_text, .. } = redo {
            assert_eq!(new_text, Some("c".into()));
        }
        assert!(!hist.can_redo());
    }

    #[test]
    fn history_redo_discarded_on_new_push() {
        let mut hist = ActionHistory::new(10);
        hist.push(PluginAction::Comment {
            address: 0,
            old_text: None,
            new_text: Some("a".into()),
        });
        hist.undo();
        hist.push(PluginAction::Comment {
            address: 0,
            old_text: None,
            new_text: Some("b".into()),
        });
        assert!(!hist.can_redo());
        assert!(hist.can_undo());
    }

    #[test]
    fn history_max_size_respected() {
        let mut hist = ActionHistory::new(3);
        for i in 0..5u64 {
            hist.push(PluginAction::Mark {
                address: i,
                kind: "x".into(),
                old_value: None,
                new_value: None,
            });
        }
        // Should have at most 3 entries.
        assert!(hist.len() <= 3);
    }

    #[test]
    fn history_undo_empty_returns_none() {
        let mut hist = ActionHistory::new(5);
        assert!(hist.undo().is_none());
    }

    #[test]
    fn history_redo_empty_returns_none() {
        let mut hist = ActionHistory::new(5);
        assert!(hist.redo().is_none());
    }

    #[test]
    fn history_clear() {
        let mut hist = ActionHistory::new(5);
        hist.push(PluginAction::Comment {
            address: 0,
            old_text: None,
            new_text: None,
        });
        hist.clear();
        assert!(hist.is_empty());
        assert!(!hist.can_undo());
    }

    #[test]
    fn history_peek_last() {
        let mut hist = ActionHistory::new(5);
        hist.push(PluginAction::Mark {
            address: 0xABC,
            kind: "bm".into(),
            old_value: None,
            new_value: Some("x".into()),
        });
        let last = hist.peek_last().unwrap();
        assert_eq!(last.address(), 0xABC);
    }

    // ── PluginInterop ─────────────────────────────────────────────────────────

    #[test]
    fn interop_direct_message_delivered() {
        let mut interop = PluginInterop::new(10);
        let a = PluginId::new("a");
        let b = PluginId::new("b");
        interop.register_inbox(&a);
        interop.register_inbox(&b);
        interop.send(PluginMessage::directed(
            a.clone(),
            b.clone(),
            "ping",
            "hello",
        ));
        assert_eq!(interop.pending(&b), 1);
        assert_eq!(interop.pending(&a), 0);
    }

    #[test]
    fn interop_broadcast_delivered_to_others() {
        let mut interop = PluginInterop::new(10);
        let a = PluginId::new("a");
        let b = PluginId::new("b");
        let c = PluginId::new("c");
        interop.register_inbox(&a);
        interop.register_inbox(&b);
        interop.register_inbox(&c);
        interop.send(PluginMessage::broadcast(a.clone(), "event", "data"));
        assert_eq!(interop.pending(&a), 0); // sender excluded
        assert_eq!(interop.pending(&b), 1);
        assert_eq!(interop.pending(&c), 1);
    }

    #[test]
    fn interop_inbox_capacity_drop_oldest() {
        let mut interop = PluginInterop::new(2);
        let a = PluginId::new("a");
        let b = PluginId::new("b");
        interop.register_inbox(&a);
        interop.register_inbox(&b);
        for i in 0..4u32 {
            interop.send(PluginMessage::directed(
                b.clone(),
                a.clone(),
                "t",
                i.to_string(),
            ));
        }
        // Only 2 messages should remain.
        assert_eq!(interop.pending(&a), 2);
        let msgs = interop.drain(&a);
        // Newest two: "2" and "3".
        assert_eq!(msgs[0].payload, "2");
        assert_eq!(msgs[1].payload, "3");
    }

    #[test]
    fn interop_drain_empties_inbox() {
        let mut interop = PluginInterop::new(10);
        let a = PluginId::new("a");
        let b = PluginId::new("b");
        interop.register_inbox(&a);
        interop.register_inbox(&b);
        interop.send(PluginMessage::directed(b.clone(), a.clone(), "t", "x"));
        let msgs = interop.drain(&a);
        assert_eq!(msgs.len(), 1);
        assert_eq!(interop.pending(&a), 0);
    }

    #[test]
    fn interop_unregister_removes_inbox() {
        let mut interop = PluginInterop::new(10);
        let a = PluginId::new("a");
        interop.register_inbox(&a);
        interop.unregister_inbox(&a);
        assert_eq!(interop.inbox_count(), 0);
    }

    // ── PluginContext ─────────────────────────────────────────────────────────

    #[test]
    fn context_register_and_activate() {
        let mut ctx = PluginContext::new(10, 10);
        let (plugin, count) = CounterPlugin::new("counter");
        ctx.register(Box::new(plugin), Box::new(0u32)).unwrap();
        assert_eq!(
            ctx.lifecycle(&PluginId::new("counter")),
            Some(PluginLifecycle::Registered)
        );
        ctx.activate(&PluginId::new("counter")).unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            ctx.lifecycle(&PluginId::new("counter")),
            Some(PluginLifecycle::Active)
        );
    }

    #[test]
    fn context_duplicate_register_errors() {
        let mut ctx = PluginContext::new(10, 10);
        let (p1, _) = CounterPlugin::new("dup");
        let (p2, _) = CounterPlugin::new("dup");
        ctx.register(Box::new(p1), Box::new(0u32)).unwrap();
        assert!(ctx.register(Box::new(p2), Box::new(0u32)).is_err());
    }

    #[test]
    fn context_pause_and_resume() {
        let mut ctx = PluginContext::new(10, 10);
        let (p, _) = CounterPlugin::new("p");
        let id = PluginId::new("p");
        ctx.register(Box::new(p), Box::new(0u32)).unwrap();
        ctx.activate(&id).unwrap();
        ctx.pause(&id).unwrap();
        assert_eq!(ctx.lifecycle(&id), Some(PluginLifecycle::Paused));
        ctx.resume(&id).unwrap();
        assert_eq!(ctx.lifecycle(&id), Some(PluginLifecycle::Active));
    }

    #[test]
    fn context_pause_not_active_errors() {
        let mut ctx = PluginContext::new(10, 10);
        let (p, _) = CounterPlugin::new("q");
        let id = PluginId::new("q");
        ctx.register(Box::new(p), Box::new(0u32)).unwrap();
        assert!(ctx.pause(&id).is_err()); // Not Active yet
    }

    #[test]
    fn context_deactivate() {
        let mut ctx = PluginContext::new(10, 10);
        let (p, _) = CounterPlugin::new("dc");
        let id = PluginId::new("dc");
        ctx.register(Box::new(p), Box::new(0u32)).unwrap();
        ctx.activate(&id).unwrap();
        ctx.deactivate(&id).unwrap();
        assert_eq!(ctx.lifecycle(&id), Some(PluginLifecycle::Stopped));
    }

    #[test]
    fn context_unregister() {
        let mut ctx = PluginContext::new(10, 10);
        let (p, _) = CounterPlugin::new("del");
        let id = PluginId::new("del");
        ctx.register(Box::new(p), Box::new(0u32)).unwrap();
        assert!(ctx.unregister(&id));
        assert!(!ctx.contains(&id));
    }

    #[test]
    fn context_action_history_undo_redo() {
        let mut ctx = PluginContext::new(10, 10);
        ctx.record_action(PluginAction::Rename {
            address: 0x1000,
            old_name: "sub_1000".into(),
            new_name: "init".into(),
        });
        assert!(ctx.can_undo());
        let inv = ctx.undo().unwrap();
        assert_eq!(inv.address(), 0x1000);
        assert!(ctx.can_redo());
        ctx.redo().unwrap();
        assert!(!ctx.can_redo());
    }

    #[test]
    fn context_messaging_via_dispatch() {
        let mut ctx = PluginContext::new(10, 10);
        let echo_id = PluginId::new("echo");
        let other_id = PluginId::new("other");
        ctx.register(
            Box::new(EchoPlugin::new("echo")),
            Box::new(Vec::<String>::new()),
        )
        .unwrap();
        ctx.register(
            Box::new(EchoPlugin::new("other")),
            Box::new(Vec::<String>::new()),
        )
        .unwrap();

        ctx.send_message(PluginMessage::directed(
            other_id,
            echo_id.clone(),
            "greet",
            "hello",
        ));
        assert_eq!(ctx.pending_messages(&echo_id), 1);
        ctx.dispatch_messages(&echo_id);
        assert_eq!(ctx.pending_messages(&echo_id), 0);

        // The echo plugin's state (Vec<String>) should now contain "hello".
        let state = ctx.get_state::<Vec<String>>(&echo_id).unwrap();
        assert_eq!(state[0], "hello");
    }

    #[test]
    fn context_typed_state_access() {
        let mut ctx = PluginContext::new(10, 10);
        let (p, _) = CounterPlugin::new("typed");
        let id = PluginId::new("typed");
        ctx.register(Box::new(p), Box::new(42u32)).unwrap();
        assert_eq!(ctx.get_state::<u32>(&id), Some(&42));
        *ctx.get_state_mut::<u32>(&id).unwrap() = 99;
        assert_eq!(ctx.get_state::<u32>(&id), Some(&99));
    }

    #[test]
    fn context_ids_iteration() {
        let mut ctx = PluginContext::new(10, 10);
        let (p1, _) = CounterPlugin::new("a");
        let (p2, _) = CounterPlugin::new("b");
        ctx.register(Box::new(p1), Box::new(0u32)).unwrap();
        ctx.register(Box::new(p2), Box::new(0u32)).unwrap();

        assert_eq!(ctx.ids().count(), 2);
    }

    // ── PluginMessage ─────────────────────────────────────────────────────────

    #[test]
    fn message_directed_is_not_broadcast() {
        let msg = PluginMessage::directed(PluginId::new("a"), PluginId::new("b"), "t", "p");
        assert!(!msg.is_broadcast());
    }

    #[test]
    fn message_broadcast_is_broadcast() {
        let msg = PluginMessage::broadcast(PluginId::new("a"), "t", "p");
        assert!(msg.is_broadcast());
    }

    // ── PluginLifecycle display ───────────────────────────────────────────────

    #[test]
    fn lifecycle_display() {
        assert_eq!(PluginLifecycle::Active.to_string(), "active");
        assert_eq!(PluginLifecycle::Faulted.to_string(), "faulted");
    }
}
