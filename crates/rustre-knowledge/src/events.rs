//! `events` — Event-sourcing log for the knowledge graph.
//!
//! Every mutation that touches an entity table produces a [`KnowledgeEvent`].
//! The full history can be replayed against an empty [`EntitySnapshot`] to
//! reconstruct the latest state, supporting audit, undo, and divergent
//! branches.

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entities::{
    Bookmark, Comment, EntityId, EntityKind, EntitySnapshot, Function, Patch, Symbol,
    Tag, Trace, TypeDef, Xref,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced when applying an event to a snapshot.
#[derive(Debug, Error)]
pub enum EventError {
    /// The target entity does not exist.
    #[error("entity {kind} {id} not found")]
    NotFound {
        /// Entity table.
        kind: EntityKind,
        /// Target id.
        id: EntityId,
    },
    /// The target entity already exists (on insert).
    #[error("entity {kind} {id} already exists")]
    AlreadyExists {
        /// Entity table.
        kind: EntityKind,
        /// Target id.
        id: EntityId,
    },
    /// The event payload is structurally invalid.
    #[error("invalid event payload: {0}")]
    InvalidPayload(String),
}

// ---------------------------------------------------------------------------
// EventPayload
// ---------------------------------------------------------------------------

/// The body of a [`KnowledgeEvent`]: which table is touched and how.
///
/// `Upsert*` events replace any previous value with the same id; `Remove*`
/// events delete by id and error if missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventPayload {
    /// Insert or replace a [`Symbol`].
    UpsertSymbol(Symbol),
    /// Remove a [`Symbol`] by id.
    RemoveSymbol(EntityId),
    /// Insert or replace a [`Function`].
    UpsertFunction(Function),
    /// Remove a [`Function`] by id.
    RemoveFunction(EntityId),
    /// Insert or replace a [`TypeDef`].
    UpsertType(TypeDef),
    /// Remove a [`TypeDef`] by id.
    RemoveType(EntityId),
    /// Insert or replace a [`Comment`].
    UpsertComment(Comment),
    /// Remove a [`Comment`] by id.
    RemoveComment(EntityId),
    /// Insert or replace an [`Xref`].
    UpsertXref(Xref),
    /// Remove an [`Xref`] by id.
    RemoveXref(EntityId),
    /// Insert or replace a [`Patch`].
    UpsertPatch(Patch),
    /// Remove a [`Patch`] by id.
    RemovePatch(EntityId),
    /// Insert or replace a [`Bookmark`].
    UpsertBookmark(Bookmark),
    /// Remove a [`Bookmark`] by id.
    RemoveBookmark(EntityId),
    /// Insert or replace a [`Trace`].
    UpsertTrace(Trace),
    /// Remove a [`Trace`] by id.
    RemoveTrace(EntityId),
    /// Insert or replace a [`Tag`].
    UpsertTag(Tag),
    /// Remove a [`Tag`] by id.
    RemoveTag(EntityId),
}

impl EventPayload {
    /// Entity table this payload targets.
    #[must_use]
    pub const fn kind(&self) -> EntityKind {
        match self {
            Self::UpsertSymbol(_) | Self::RemoveSymbol(_) => EntityKind::Symbol,
            Self::UpsertFunction(_) | Self::RemoveFunction(_) => EntityKind::Function,
            Self::UpsertType(_) | Self::RemoveType(_) => EntityKind::Type,
            Self::UpsertComment(_) | Self::RemoveComment(_) => EntityKind::Comment,
            Self::UpsertXref(_) | Self::RemoveXref(_) => EntityKind::Xref,
            Self::UpsertPatch(_) | Self::RemovePatch(_) => EntityKind::Patch,
            Self::UpsertBookmark(_) | Self::RemoveBookmark(_) => EntityKind::Bookmark,
            Self::UpsertTrace(_) | Self::RemoveTrace(_) => EntityKind::Trace,
            Self::UpsertTag(_) | Self::RemoveTag(_) => EntityKind::Tag,
        }
    }

    /// `true` if this payload is an upsert; `false` for removals.
    #[must_use]
    pub const fn is_upsert(&self) -> bool {
        matches!(
            self,
            Self::UpsertSymbol(_)
                | Self::UpsertFunction(_)
                | Self::UpsertType(_)
                | Self::UpsertComment(_)
                | Self::UpsertXref(_)
                | Self::UpsertPatch(_)
                | Self::UpsertBookmark(_)
                | Self::UpsertTrace(_)
                | Self::UpsertTag(_)
        )
    }
}

// ---------------------------------------------------------------------------
// KnowledgeEvent
// ---------------------------------------------------------------------------

/// A single, timestamped knowledge-graph mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeEvent {
    /// Monotonic sequence number (assigned by the store).
    pub seq: u64,
    /// Author identifier (e.g. user, agent, plugin).
    pub author: String,
    /// Optional transaction id grouping a batch of events.
    pub txn: Option<u64>,
    /// The payload.
    pub payload: EventPayload,
}

impl KnowledgeEvent {
    /// Construct a new event (the store is responsible for assigning `seq`).
    #[must_use]
    pub fn new(seq: u64, author: impl Into<String>, payload: EventPayload) -> Self {
        Self { seq, author: author.into(), txn: None, payload }
    }

    /// Builder: attach a transaction id.
    #[must_use]
    pub const fn with_txn(mut self, txn: u64) -> Self {
        self.txn = Some(txn);
        self
    }

    /// Apply this event to a snapshot, mutating it in place.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::NotFound`] if a remove targets a missing id.
    pub fn apply(&self, snap: &mut EntitySnapshot) -> Result<(), EventError> {
        apply_payload(&self.payload, snap)
    }
}

impl fmt::Display for KnowledgeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Event[{}] by {} on {} ({})",
            self.seq,
            self.author,
            self.payload.kind(),
            if self.payload.is_upsert() { "upsert" } else { "remove" }
        )
    }
}

// ---------------------------------------------------------------------------
// EventLog
// ---------------------------------------------------------------------------

/// An append-only sequence of events with a monotonic counter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventLog {
    next_seq: u64,
    events: Vec<KnowledgeEvent>,
}

impl EventLog {
    /// Create an empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self { next_seq: 0, events: Vec::new() }
    }

    /// Number of recorded events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// `true` if no events have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Read-only slice of the events.
    #[must_use]
    pub fn events(&self) -> &[KnowledgeEvent] {
        &self.events
    }

    /// Next sequence number that will be assigned.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append a payload as a new event, assigning the next sequence number,
    /// and return the resulting [`KnowledgeEvent`].
    pub fn record(
        &mut self,
        author: impl Into<String>,
        txn: Option<u64>,
        payload: EventPayload,
    ) -> KnowledgeEvent {
        let mut ev = KnowledgeEvent::new(self.next_seq, author, payload);
        ev.txn = txn;
        self.next_seq = self.next_seq.saturating_add(1);
        self.events.push(ev.clone());
        ev
    }

    /// Replay every event into a fresh [`EntitySnapshot`].
    ///
    /// # Errors
    ///
    /// Returns the first [`EventError`] produced by any event.
    pub fn replay(&self) -> Result<EntitySnapshot, EventError> {
        let mut snap = EntitySnapshot::new();
        for ev in &self.events {
            ev.apply(&mut snap)?;
        }
        Ok(snap)
    }

    /// Replay only events up to (and including) `seq_inclusive`.
    ///
    /// # Errors
    ///
    /// Returns the first [`EventError`] produced by any event.
    pub fn replay_up_to(&self, seq_inclusive: u64) -> Result<EntitySnapshot, EventError> {
        let mut snap = EntitySnapshot::new();
        for ev in self.events.iter().take_while(|e| e.seq <= seq_inclusive) {
            ev.apply(&mut snap)?;
        }
        Ok(snap)
    }
}

// ---------------------------------------------------------------------------
// Internal: payload application
// ---------------------------------------------------------------------------

fn apply_payload(p: &EventPayload, snap: &mut EntitySnapshot) -> Result<(), EventError> {
    match p {
        EventPayload::UpsertSymbol(s) => { snap.symbols.insert(s.id, s.clone()); }
        EventPayload::RemoveSymbol(id) => {
            snap.symbols.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Symbol, id: *id })?;
        }
        EventPayload::UpsertFunction(f) => { snap.functions.insert(f.id, f.clone()); }
        EventPayload::RemoveFunction(id) => {
            snap.functions.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Function, id: *id })?;
        }
        EventPayload::UpsertType(t) => { snap.types.insert(t.id, t.clone()); }
        EventPayload::RemoveType(id) => {
            snap.types.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Type, id: *id })?;
        }
        EventPayload::UpsertComment(c) => { snap.comments.insert(c.id, c.clone()); }
        EventPayload::RemoveComment(id) => {
            snap.comments.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Comment, id: *id })?;
        }
        EventPayload::UpsertXref(x) => { snap.xrefs.insert(x.id, x.clone()); }
        EventPayload::RemoveXref(id) => {
            snap.xrefs.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Xref, id: *id })?;
        }
        EventPayload::UpsertPatch(p2) => { snap.patches.insert(p2.id, p2.clone()); }
        EventPayload::RemovePatch(id) => {
            snap.patches.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Patch, id: *id })?;
        }
        EventPayload::UpsertBookmark(b) => { snap.bookmarks.insert(b.id, b.clone()); }
        EventPayload::RemoveBookmark(id) => {
            snap.bookmarks.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Bookmark, id: *id })?;
        }
        EventPayload::UpsertTrace(t) => { snap.traces.insert(t.id, t.clone()); }
        EventPayload::RemoveTrace(id) => {
            snap.traces.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Trace, id: *id })?;
        }
        EventPayload::UpsertTag(t) => { snap.tags.insert(t.id, t.clone()); }
        EventPayload::RemoveTag(id) => {
            snap.tags.remove(id).ok_or(EventError::NotFound { kind: EntityKind::Tag, id: *id })?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{Symbol, SymbolScope};

    #[test]
    fn record_assigns_seq() {
        let mut log = EventLog::new();
        let s = Symbol::new(0x10, "foo", SymbolScope::Global);
        let ev = log.record("user", None, EventPayload::UpsertSymbol(s));
        assert_eq!(ev.seq, 0);
        assert_eq!(log.next_seq(), 1);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn replay_reconstructs_state() {
        let mut log = EventLog::new();
        let s = Symbol::new(0x10, "foo", SymbolScope::Global);
        let id = s.id;
        log.record("u", None, EventPayload::UpsertSymbol(s));
        let snap = log.replay().unwrap();
        assert!(snap.symbols.contains_key(&id));
    }

    #[test]
    fn remove_missing_errors() {
        let mut log = EventLog::new();
        let bogus = EntityId::new();
        log.record("u", None, EventPayload::RemoveSymbol(bogus));
        let err = log.replay();
        assert!(matches!(err, Err(EventError::NotFound { .. })));
    }

    #[test]
    fn replay_up_to_truncates() {
        let mut log = EventLog::new();
        let s1 = Symbol::new(0x10, "a", SymbolScope::Global);
        let s2 = Symbol::new(0x20, "b", SymbolScope::Global);
        let id2 = s2.id;
        log.record("u", None, EventPayload::UpsertSymbol(s1));
        log.record("u", None, EventPayload::UpsertSymbol(s2));
        let snap = log.replay_up_to(0).unwrap();
        assert_eq!(snap.symbols.len(), 1);
        assert!(!snap.symbols.contains_key(&id2));
    }

    #[test]
    fn payload_kind_classification() {
        let s = Symbol::new(0x10, "foo", SymbolScope::Global);
        let p = EventPayload::UpsertSymbol(s);
        assert_eq!(p.kind(), EntityKind::Symbol);
        assert!(p.is_upsert());
    }
}
