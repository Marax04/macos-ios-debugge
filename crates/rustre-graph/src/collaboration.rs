// collaboration.rs — Delta sync, conflict resolution, undo/redo, audit trail
// Part of rustre-graph crate.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::fmt::Write;

// ── Basic timestamp helpers ──────────────────────────────────────────────────

/// Unix milliseconds timestamp
pub type Timestamp = u64;

#[must_use]
pub fn now_ms() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis().try_into().unwrap_or(u64::MAX)
}

// ── Event model (mirrors rustre-events CoreEvent but self-contained here) ────

/// The kind of graph mutation an event represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum EventPayload {
    /// A symbol was renamed.
    SymbolRenamed {
        address: u64,
        old_name: String,
        new_name: String,
    },
    /// A function was annotated.
    FunctionAnnotated {
        address: u64,
        field: String,
        old_value: String,
        new_value: String,
    },
    /// A type definition was added or updated.
    TypeDefined {
        type_id: u32,
        serialized_type: String, // JSON of TypeDef
    },
    /// A type definition was removed.
    TypeRemoved {
        type_id: u32,
    },
    /// A cross-reference edge was added.
    XrefAdded {
        from_addr: u64,
        to_addr: u64,
        kind: String,
    },
    /// A cross-reference edge was removed.
    XrefRemoved {
        from_addr: u64,
        to_addr: u64,
        kind: String,
    },
    /// A comment was set on an address.
    CommentSet {
        address: u64,
        old_comment: Option<String>,
        new_comment: Option<String>,
    },
    /// A tag was added to a function.
    TagAdded {
        address: u64,
        tag: String,
    },
    /// A tag was removed from a function.
    TagRemoved {
        address: u64,
        tag: String,
    },
    /// Compensating event created by undo.
    Compensating {
        original_event_id: EventId,
        inner: Box<Self>,
    },
    /// Generic no-op marker (used as a sentinel).
    NoOp,
}

/// Unique identifier for a collaboration event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifies the actor (user or tool) that produced an event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    /// Human-readable name or node identifier.
    pub name: String,
    /// Confidence in the correctness of this edit (0.0–1.0).
    pub confidence: f32,
    /// Opaque session/token identifier.
    pub session_id: String,
}

impl Actor {
    pub fn new(name: impl Into<String>, confidence: f32) -> Self {
        Self {
            name: name.into(),
            confidence: confidence.clamp(0.0, 1.0),
            session_id: Uuid::new_v4().to_string(),
        }
    }

    #[must_use]
    pub fn local() -> Self {
        Self::new("local", 1.0)
    }
}

/// A single collaboration event: the atomic unit of change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabEvent {
    pub id: EventId,
    pub timestamp_ms: Timestamp,
    pub actor: Actor,
    pub payload: EventPayload,
    /// Logical clock / sequence number within the actor's session.
    pub sequence: u64,
    /// Optional parent event this event causally follows.
    pub parent_id: Option<EventId>,
}

impl CollabEvent {
    #[must_use]
    pub fn new(actor: Actor, payload: EventPayload) -> Self {
        Self {
            id: EventId::new(),
            timestamp_ms: now_ms(),
            actor,
            payload,
            sequence: 0,
            parent_id: None,
        }
    }

    #[must_use]
    pub const fn with_sequence(mut self, seq: u64) -> Self {
        self.sequence = seq;
        self
    }

    #[must_use]
    pub fn with_parent(mut self, parent: EventId) -> Self {
        self.parent_id = Some(parent);
        self
    }

    /// The "conflict key" — two events with the same key may conflict.
    #[must_use]
    pub fn conflict_key(&self) -> Option<String> {
        match &self.payload {
            EventPayload::SymbolRenamed { address, .. } => {
                Some(format!("symbol_name:{address:#x}"))
            }
            EventPayload::FunctionAnnotated { address, field, .. } => {
                Some(format!("func_field:{address:#x}:{field}"))
            }
            EventPayload::TypeDefined { type_id, .. } => Some(format!("type:{type_id}")),
            EventPayload::CommentSet { address, .. } => {
                Some(format!("comment:{address:#x}"))
            }
            _ => None,
        }
    }
}

// ── DeltaExport / DeltaImport ────────────────────────────────────────────────

/// A bundle of events exported since a checkpoint timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaExport {
    pub checkpoint_ts: Timestamp,
    pub export_ts: Timestamp,
    pub actor_name: String,
    pub events: Vec<CollabEvent>,
}

impl DeltaExport {
    /// Serialize to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Deserialize from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_json_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Result of applying a delta import.
#[derive(Debug, Default)]
pub struct ImportResult {
    pub applied: usize,
    pub skipped_duplicate: usize,
    pub conflicts_resolved: usize,
    pub errors: Vec<String>,
}

// ── Conflict resolution ──────────────────────────────────────────────────────

/// Strategy used when two events target the same field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
#[derive(Default)]
pub enum ConflictStrategy {
    /// Keep the event with the higher timestamp.
    LastWriteWins,
    /// Keep the event with the higher `actor.confidence`.
    #[default]
    HighestConfidenceWins,
    /// Keep the local event, reject the remote one.
    LocalWins,
    /// Always apply the remote event.
    RemoteWins,
}

/// Resolves conflicts between two events targeting the same field/symbol.
pub struct ConflictResolver {
    pub strategy: ConflictStrategy,
}

impl ConflictResolver {
    #[must_use]
    pub const fn new(strategy: ConflictStrategy) -> Self {
        Self { strategy }
    }

    /// Returns the event that should be kept, and the one that should be discarded.
    #[must_use]
    pub fn resolve<'a>(
        &self,
        local: &'a CollabEvent,
        remote: &'a CollabEvent,
    ) -> ConflictOutcome<'a> {
        let winner = match self.strategy {
            ConflictStrategy::LastWriteWins => {
                if remote.timestamp_ms >= local.timestamp_ms {
                    Winner::Remote
                } else {
                    Winner::Local
                }
            }
            ConflictStrategy::HighestConfidenceWins => {
                if remote.actor.confidence > local.actor.confidence {
                    Winner::Remote
                } else if local.actor.confidence > remote.actor.confidence {
                    Winner::Local
                } else {
                    // Tie-break by timestamp
                    if remote.timestamp_ms >= local.timestamp_ms {
                        Winner::Remote
                    } else {
                        Winner::Local
                    }
                }
            }
            ConflictStrategy::LocalWins => Winner::Local,
            ConflictStrategy::RemoteWins => Winner::Remote,
        };

        ConflictOutcome {
            winner,
            local,
            remote,
        }
    }
}
 #[must_use]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Winner {
    Local,
    Remote,
}

pub struct ConflictOutcome<'a> {
    pub winner: Winner,
    pub local: &'a CollabEvent,
    pub remote: &'a CollabEvent,
}

impl<'a> ConflictOutcome<'a> {
    #[must_use]
    pub const fn winning_event(&self) -> &'a CollabEvent {
        match self.winner {
            Winner::Local => self.local,
            Winner::Remote => self.remote,
        }
    }

    #[must_use]
    pub const fn losing_event(&self) -> &'a CollabEvent {
        match self.winner {
            Winner::Local => self.remote,
            Winner::Remote => self.local,
        }
    }
}

// ── EventStore: the authoritative local log ──────────────────────────────────

/// In-memory append-only event store with indexed lookups.
///
/// Secondary indices use [`BTreeMap`] instead of `HashMap` to prevent
/// hash-collision denial-of-service: an attacker controlling event IDs,
/// actor names, or addresses could craft inputs that all hash to the same
/// bucket, degrading lookups from O(1) to O(n).  `BTreeMap` provides
/// deterministic O(log n) regardless of key distribution.
pub struct EventStore {
    events: RwLock<Vec<CollabEvent>>,
    /// `event_id` → index in `events`
    id_index: RwLock<BTreeMap<String, usize>>,
    /// `conflict_key` → index of last event for that key
    key_index: RwLock<BTreeMap<String, usize>>,
    /// `actor_name` → list of event indices
    actor_index: RwLock<BTreeMap<String, Vec<usize>>>,
    /// address → list of event indices
    addr_index: RwLock<BTreeMap<u64, Vec<usize>>>,
}

impl EventStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            id_index: RwLock::new(BTreeMap::new()),
            key_index: RwLock::new(BTreeMap::new()),
            actor_index: RwLock::new(BTreeMap::new()),
            addr_index: RwLock::new(BTreeMap::new()),
        }
    }

    /// Append an event.  Returns false if the event ID already exists (duplicate).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn append(&self, event: CollabEvent) -> bool {
        let id_str = event.id.0.clone();
        {
            let id_idx = self.id_index.read().unwrap();
            if id_idx.contains_key(&id_str) {
                return false; // duplicate
            }
        }

        let mut events = self.events.write().unwrap();
        let idx = events.len();

        // Update secondary indices before push (avoids borrowing issue).
        {
            let mut id_idx = self.id_index.write().unwrap();
            id_idx.insert(id_str, idx);
        }
        if let Some(key) = event.conflict_key() {
            let mut key_idx = self.key_index.write().unwrap();
            key_idx.insert(key, idx);
        }
        {
            let mut actor_idx = self.actor_index.write().unwrap();
            actor_idx
                .entry(event.actor.name.clone())
                .or_default()
                .push(idx);
        }
        for addr in Self::extract_addresses(&event) {
            let mut addr_idx = self.addr_index.write().unwrap();
            addr_idx.entry(addr).or_default().push(idx);
        }

        events.push(event);
        true
    }

    fn extract_addresses(event: &CollabEvent) -> Vec<u64> {
        match &event.payload {
            EventPayload::SymbolRenamed { address, .. }
            | EventPayload::FunctionAnnotated { address, .. }
            | EventPayload::CommentSet { address, .. }
            | EventPayload::TagAdded { address, .. }
            | EventPayload::TagRemoved { address, .. } => vec![*address],
            EventPayload::XrefAdded { from_addr, to_addr, .. }
            | EventPayload::XrefRemoved { from_addr, to_addr, .. } => vec![*from_addr, *to_addr],
            _ => vec![],
        }
    }

    /// Return all events with `timestamp_ms` > checkpoint.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn delta_since(&self, checkpoint: Timestamp) -> Vec<CollabEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|e| e.timestamp_ms > checkpoint)
            .cloned()
            .collect()
    }

    /// Return all events from a given actor.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn events_by_actor(&self, actor_name: &str) -> Vec<CollabEvent> {
        let actor_idx = self.actor_index.read().unwrap();
        let events = self.events.read().unwrap();
        actor_idx
            .get(actor_name)
            .map(|indices| indices.iter().map(|&i| events[i].clone()).collect())
            .unwrap_or_default()
    }

    /// Return all events that touch an address.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn events_by_address(&self, address: u64) -> Vec<CollabEvent> {
        let addr_idx = self.addr_index.read().unwrap();
        let events = self.events.read().unwrap();
        addr_idx
            .get(&address)
            .map(|indices| indices.iter().map(|&i| events[i].clone()).collect())
            .unwrap_or_default()
    }

    /// Return all events in a time range [start, end].
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn events_in_range(&self, start: Timestamp, end: Timestamp) -> Vec<CollabEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|e| e.timestamp_ms >= start && e.timestamp_ms <= end)
            .cloned()
            .collect()
    }

    /// Return all events within an address range (any extracted address falls in range).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn events_in_addr_range(&self, lo: u64, hi: u64) -> Vec<CollabEvent> {
        let mut result: Vec<CollabEvent> = {
            let addr_idx = self.addr_index.read().unwrap();
            let events = self.events.read().unwrap();
            let mut seen = std::collections::BTreeSet::new();
            let mut out = Vec::new();
            for (addr, indices) in addr_idx.iter() {
                if *addr >= lo && *addr <= hi {
                    for &i in indices {
                        if seen.insert(i) {
                            out.push(events[i].clone());
                        }
                    }
                }
            }
            out
        };
        result.sort_by_key(|e| e.timestamp_ms);
        result
    }

    /// Get a single event by id.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn get_by_id(&self, id: &EventId) -> Option<CollabEvent> {
        let id_idx = self.id_index.read().unwrap();
        let events = self.events.read().unwrap();
        id_idx.get(&id.0).map(|&i| events[i].clone())
    }

    /// Get the last event that touched a given conflict key.
    ///
    /// # Panics
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Panics if the internal lock is poisoned.
    pub fn last_event_for_key(&self, key: &str) -> Option<CollabEvent> {
        let key_idx = self.key_index.read().unwrap();
        let events = self.events.read().unwrap();
        key_idx.get(key).map(|&i| events[i].clone())
    }

    /// Total number of events.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn len(&self) -> usize {
        self.events.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Latest timestamp in the store, or 0 if empty.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn latest_timestamp(&self) -> Timestamp {
        let events = self.events.read().unwrap();
        events.iter().map(|e| e.timestamp_ms).max().unwrap_or(0)
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── DeltaExporter ────────────────────────────────────────────────────────────

pub struct DeltaExporter<'a> {
    store: &'a EventStore,
    local_actor: String,
}

impl<'a> DeltaExporter<'a> {
    pub fn new(store: &'a EventStore, local_actor: impl Into<String>) -> Self {
        DeltaExporter {
            store,
            local_actor: local_actor.into(),
        }
    }

    /// Export all events since `checkpoint_ts` as a `DeltaExport`.
    #[must_use]
    pub fn export_since(&self, checkpoint_ts: Timestamp) -> DeltaExport {
        let events = self.store.delta_since(checkpoint_ts);
        DeltaExport {
            checkpoint_ts,
            export_ts: now_ms(),
            actor_name: self.local_actor.clone(),
            events,
        }
    }

    /// Export a `DeltaExport` and serialize it to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn export_json(&self, checkpoint_ts: Timestamp) -> Result<Vec<u8>, serde_json::Error> {
        self.export_since(checkpoint_ts).to_json()
    }
}

// ── DeltaImporter ────────────────────────────────────────────────────────────

pub struct DeltaImporter<'a> {
    store: &'a EventStore,
    resolver: ConflictResolver,
}

impl<'a> DeltaImporter<'a> {
    pub const fn new(store: &'a EventStore, strategy: ConflictStrategy) -> Self {
        DeltaImporter {
            store,
            resolver: ConflictResolver::new(strategy),
        }
    }

    /// Apply a `DeltaExport` from a collaborator.
    /// Returns an `ImportResult` describing what happened.
    #[must_use]
    pub fn apply(&self, delta: DeltaExport) -> ImportResult {
        let mut result = ImportResult::default();

        for remote_event in delta.events {
            // 1. Check for duplicate by event ID.
            if self.store.get_by_id(&remote_event.id).is_some() {
                result.skipped_duplicate += 1;
                continue;
            }

            // 2. Check for conflict.
            if let Some(key) = remote_event.conflict_key()
                && let Some(local_event) = self.store.last_event_for_key(&key) {
                    let outcome = self.resolver.resolve(&local_event, &remote_event);
                    if outcome.winner == Winner::Local {
                        // Remote loses — skip.
                        result.conflicts_resolved += 1;
                        continue;
                    }
                    result.conflicts_resolved += 1;
                    // Remote wins — fall through to append.
                }

            // 3. Append.
            let appended = self.store.append(remote_event);
            if appended {
                result.applied += 1;
            } else {
                result.skipped_duplicate += 1;
            }
        }

        result
    }

    /// Apply from raw JSON bytes.
    ///
    /// Enforces a size cap before deserializing to prevent memory exhaustion
    /// from a maliciously crafted delta with millions of events.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn apply_json(&self, bytes: &[u8]) -> Result<ImportResult, serde_json::Error> {
        // 64 MiB is a generous upper bound for a collaboration delta payload.
        const MAX_DELTA_BYTES: usize = 64 * 1024 * 1024;
        // Also cap the number of events to prevent a crafted compact payload.
        const MAX_EVENTS_PER_DELTA: usize = 100_000;
        if bytes.len() > MAX_DELTA_BYTES {
            // Return a custom serde error without deserializing.
            return Err(serde::de::Error::custom(format!(
                "delta payload too large: {} bytes (limit {})",
                bytes.len(),
                MAX_DELTA_BYTES
            )));
        }
        let delta = DeltaExport::from_json(bytes)?;
        if delta.events.len() > MAX_EVENTS_PER_DELTA {
            return Err(serde::de::Error::custom(format!(
                "delta contains too many events: {} (limit {})",
                delta.events.len(),
                MAX_EVENTS_PER_DELTA
            )));
        }
        Ok(self.apply(delta))
    }
}

// ── SyncSession ──────────────────────────────────────────────────────────────

/// Credentials and state for a remote sync peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSession {
    pub session_id: String,
    pub remote_url: String,
    pub auth_token: String,
    pub last_sync_ts: Timestamp,
    pub pending_deltas: Vec<DeltaExport>,
    pub connected: bool,
}

impl SyncSession {
    pub fn new(remote_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            remote_url: remote_url.into(),
            auth_token: auth_token.into(),
            last_sync_ts: 0,
            pending_deltas: Vec::new(),
            connected: false,
        }
    }

    #[must_use]
    pub fn push_endpoint(&self) -> String {
        format!("{}/sync/push", self.remote_url)
    }

    #[must_use]
    pub fn pull_endpoint(&self) -> String {
        format!("{}/sync/pull?since={}", self.remote_url, self.last_sync_ts)
    }

    #[must_use]
    pub fn ws_endpoint(&self) -> String {
        format!(
            "{}/sync/ws?token={}",
            self.remote_url.replace("http", "ws"),
            self.auth_token
        )
    }
}

/// Result from a sync push/pull operation.
#[derive(Debug)]
pub struct SyncResult {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts_resolved: usize,
    pub error: Option<String>,
}

/// Performs HTTP-based sync with a remote peer.
/// In a real build this would use `reqwest` or `ureq`; here we provide the
/// full interface and a stub implementation that records intent.
pub struct HttpSyncer {
    store: Arc<EventStore>,
    local_actor: String,
    strategy: ConflictStrategy,
}

impl HttpSyncer {
    pub fn new(
        store: Arc<EventStore>,
        local_actor: impl Into<String>,
        strategy: ConflictStrategy,
    ) -> Self {
        Self {
            store,
            local_actor: local_actor.into(),
            strategy,
        }
    }

    /// Push local delta to remote.
    /// Returns the number of events pushed or an error message.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn sync_push(&self, session: &mut SyncSession) -> SyncResult {
        let exporter = DeltaExporter::new(&self.store, &self.local_actor);
        let delta = exporter.export_since(session.last_sync_ts);
        let pushed = delta.events.len();

        match delta.to_json() {
            Ok(body) => {
                // In production: reqwest::blocking::Client::new().post(&session.push_endpoint())
                //     .bearer_auth(&session.auth_token)
                //     .body(body)
                //     .send()
                // For now, queue in pending_deltas.
                let delta_copy = DeltaExport::from_json(&body).unwrap();
                session.pending_deltas.push(delta_copy);
                session.last_sync_ts = now_ms();
                SyncResult {
                    pushed,
                    pulled: 0,
                    conflicts_resolved: 0,
                    error: None,
                }
            }
            Err(e) => SyncResult {
                pushed: 0,
                pulled: 0,
                conflicts_resolved: 0,
                error: Some(e.to_string()),
            },
        }
    }

    /// Pull remote delta and apply locally.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn sync_pull(&self, session: &mut SyncSession) -> SyncResult {
        // In production:
        //   let resp = reqwest::blocking::Client::new()
        //       .get(&session.pull_endpoint())
        //       .bearer_auth(&session.auth_token)
        //       .send()?;
        //   let delta = DeltaExport::from_json(&resp.bytes()?)?;
        // For now, drain pending_deltas as if they came from remote.
        let importer = DeltaImporter::new(&self.store, self.strategy);
        let mut total_applied = 0;
        let mut total_conflicts = 0;

        let deltas = std::mem::take(&mut session.pending_deltas);
        for delta in deltas {
            let result = importer.apply(delta);
            total_applied += result.applied;
            total_conflicts += result.conflicts_resolved;
        }

        session.last_sync_ts = now_ms();

        SyncResult {
            pushed: 0,
            pulled: total_applied,
            conflicts_resolved: total_conflicts,
            error: None,
        }
    }

    /// Run a full bidirectional sync cycle (push then pull).
    pub fn sync_bidirectional(&self, session: &mut SyncSession) -> SyncResult {
        let push_result = self.sync_push(session);
        let pull_result = self.sync_pull(session);
        SyncResult {
            pushed: push_result.pushed,
            pulled: pull_result.pulled,
            conflicts_resolved: push_result.conflicts_resolved + pull_result.conflicts_resolved,
            error: push_result.error.or(pull_result.error),
        }
    }
}

// ── WebSocket real-time sync ─────────────────────────────────────────────────

/// State of a WebSocket sync connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Failed { reason: String },
}

/// Message framing for the WebSocket protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type", content = "payload")]
pub enum WsMessage {
    /// Client → server: identify.
    Hello { actor_name: String, token: String },
    /// Server → client: welcome acknowledgement.
    Welcome { server_version: String },
    /// Either direction: a batch of events.
    Events(Vec<CollabEvent>),
    /// Client → server: request events since timestamp.
    Catchup { since_ts: Timestamp },
    /// Server → client: response to Catchup.
    CatchupResponse { events: Vec<CollabEvent> },
    /// Keepalive ping.
    Ping { ts: Timestamp },
    /// Keepalive pong.
    Pong { ts: Timestamp },
    /// Disconnect signal.
    Goodbye { reason: String },
}

impl WsMessage {
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Manages an in-process WebSocket-style sync channel.
/// Real network I/O would use `tokio-tungstenite`; this struct defines the
/// full interface and internal logic.
pub struct WsSyncChannel {
    state: Mutex<WsState>,
    store: Arc<EventStore>,
    local_actor: Actor,
    strategy: ConflictStrategy,
    /// Messages waiting to be sent to remote (outgoing queue).
    outgoing: Mutex<VecDeque<WsMessage>>,
    /// Messages received from remote (incoming queue).
    incoming: Mutex<VecDeque<WsMessage>>,
}

impl WsSyncChannel {
    pub const fn new(store: Arc<EventStore>, local_actor: Actor, strategy: ConflictStrategy) -> Self {
        Self {
            state: Mutex::new(WsState::Disconnected),
            store,
            local_actor,
            strategy,
            outgoing: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
        }
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn state(&self) -> WsState {
        self.state.lock().unwrap().clone()
    }

    /// Returns the local actor associated with this channel (used as the
    /// authoring identity when relaying outgoing events).
    pub const fn local_actor(&self) -> &Actor {
        &self.local_actor
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn connect(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        match *state {
            WsState::Disconnected | WsState::Failed { .. } => {
                *state = WsState::Connecting;
                // In production: spawn tokio task, connect via tungstenite.
                *state = WsState::Connected;
                true
            }
            _ => false,
        }
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn disconnect(&self) {
        {
            let mut state = self.state.lock().unwrap();
            *state = WsState::Disconnected;
        }
        self.outgoing.lock().unwrap().push_back(WsMessage::Goodbye {
            reason: "client disconnect".into(),
        });
    }

    /// Enqueue a single event for real-time broadcast.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn push_event(&self, event: CollabEvent) {
        let msg = WsMessage::Events(vec![event]);
        self.outgoing.lock().unwrap().push_back(msg);
    }

    /// Enqueue multiple events.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn push_events(&self, events: Vec<CollabEvent>) {
        if !events.is_empty() {
            let msg = WsMessage::Events(events);
            self.outgoing.lock().unwrap().push_back(msg);
        }
    }

    /// Simulate receiving a message from the network and process it.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn receive_message(&self, raw: &str) -> Result<(), String> {
        // Enforce a per-message size cap before deserializing to prevent
        // memory exhaustion from a crafted oversized WS frame.
        const MAX_WS_MESSAGE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
        // Cap the number of events in a single WS batch to prevent a remote
        // peer from exhausting memory via a single crafted message.
        const MAX_WS_EVENTS: usize = 10_000;
        if raw.len() > MAX_WS_MESSAGE_BYTES {
            return Err(format!(
                "WebSocket message too large: {} bytes (limit {})",
                raw.len(),
                MAX_WS_MESSAGE_BYTES
            ));
        }
        let msg = WsMessage::from_json(raw).map_err(|e| e.to_string())?;
        match msg {
            WsMessage::Events(events) => {
                if events.len() > MAX_WS_EVENTS {
                    return Err(format!(
                        "WsMessage::Events batch too large: {} events (limit {})",
                        events.len(),
                        MAX_WS_EVENTS
                    ));
                }
                let importer = DeltaImporter::new(&self.store, self.strategy);
                let delta = DeltaExport {
                    checkpoint_ts: 0,
                    export_ts: now_ms(),
                    actor_name: "remote".into(),
                    events,
                };
                let _ = importer.apply(delta);
            }
            WsMessage::Ping { ts } => {
                self.outgoing
                    .lock()
                    .unwrap()
                    .push_back(WsMessage::Pong { ts });
            }
            WsMessage::CatchupResponse { events } => {
                if events.len() > MAX_WS_EVENTS {
                    return Err(format!(
                        "WsMessage::CatchupResponse batch too large: {} events (limit {})",
                        events.len(),
                        MAX_WS_EVENTS
                    ));
                }
                let importer = DeltaImporter::new(&self.store, self.strategy);
                let delta = DeltaExport {
                    checkpoint_ts: 0,
                    export_ts: now_ms(),
                    actor_name: "remote_catchup".into(),
                    events,
                };
                let _ = importer.apply(delta);
            }
            WsMessage::Welcome { .. } => {
                *self.state.lock().unwrap() = WsState::Connected;
            }
            WsMessage::Goodbye { reason } => {
                *self.state.lock().unwrap() = WsState::Failed { reason };
            }
            other => {
                self.incoming.lock().unwrap().push_back(other);
            }
        }
        Ok(())
    }

    /// Drain the outgoing queue, returning serialized messages.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn drain_outgoing(&self) -> Vec<String> {
        let mut out = self.outgoing.lock().unwrap();
        out.drain(..)
            .filter_map(|m| m.to_json().ok())
            .collect()
    }
}

// ── Undo/Redo ────────────────────────────────────────────────────────────────

/// Computes the compensating (inverse) event for a given event, if possible.
#[must_use]
pub fn compensate(event: &CollabEvent, actor: Actor) -> Option<CollabEvent> {
    let inverse_payload = match &event.payload {
        EventPayload::SymbolRenamed { address, old_name, new_name } => {
            Some(EventPayload::SymbolRenamed {
                address: *address,
                old_name: new_name.clone(),
                new_name: old_name.clone(),
            })
        }
        EventPayload::FunctionAnnotated { address, field, old_value, new_value } => {
            Some(EventPayload::FunctionAnnotated {
                address: *address,
                field: field.clone(),
                old_value: new_value.clone(),
                new_value: old_value.clone(),
            })
        }
        EventPayload::TypeDefined { type_id, .. } => Some(EventPayload::TypeRemoved {
            type_id: *type_id,
        }),
        EventPayload::TypeRemoved { type_id } => {
            // Cannot reconstruct the original type without the original data.
            // Emit a tag marker on a synthetic address derived from `type_id`
            // so the inverse still records *which* type was removed.
            Some(EventPayload::TagAdded {
                address: u64::from(*type_id),
                tag: format!("type-removed:{type_id}"),
            })
        }
        EventPayload::XrefAdded { from_addr, to_addr, kind } => {
            Some(EventPayload::XrefRemoved {
                from_addr: *from_addr,
                to_addr: *to_addr,
                kind: kind.clone(),
            })
        }
        EventPayload::XrefRemoved { from_addr, to_addr, kind } => {
            Some(EventPayload::XrefAdded {
                from_addr: *from_addr,
                to_addr: *to_addr,
                kind: kind.clone(),
            })
        }
        EventPayload::CommentSet { address, old_comment, new_comment } => {
            Some(EventPayload::CommentSet {
                address: *address,
                old_comment: new_comment.clone(),
                new_comment: old_comment.clone(),
            })
        }
        EventPayload::TagAdded { address, tag } => Some(EventPayload::TagRemoved {
            address: *address,
            tag: tag.clone(),
        }),
        EventPayload::TagRemoved { address, tag } => Some(EventPayload::TagAdded {
            address: *address,
            tag: tag.clone(),
        }),
        EventPayload::Compensating { original_event_id, inner } => {
            // Undo of undo = redo: wrap original inner back inside a fresh
            // Compensating envelope whose `original_event_id` chains back to
            // the previously compensated event, preserving the audit trail.
            Some(EventPayload::Compensating {
                original_event_id: original_event_id.clone(),
                inner: inner.clone(),
            })
        }
        EventPayload::NoOp => None,
    };

    inverse_payload.map(|payload| {
        CollabEvent::new(
            actor,
            EventPayload::Compensating {
                original_event_id: event.id.clone(),
                inner: Box::new(payload),
            },
        )
    })
}

/// Tracks undo/redo history and generates compensating events.
#[must_use]
pub struct UndoHistory {
    /// Stack of event IDs that can be undone.
    undo_stack: Mutex<Vec<EventId>>,
    /// Stack of event IDs that can be redone (populated after undo).
    redo_stack: Mutex<Vec<EventId>>,
    /// IDs of compensating events emitted by [`UndoHistory::undo`], in order.
    /// Useful for auditing and for distinguishing user actions from undo events.
    compensations: Mutex<Vec<EventId>>,
    store: Arc<EventStore>,
    local_actor: Actor,
    max_depth: usize,
}

impl UndoHistory {
    pub const fn new(store: Arc<EventStore>, local_actor: Actor, max_depth: usize) -> Self {
        Self {
            undo_stack: Mutex::new(Vec::new()),
            redo_stack: Mutex::new(Vec::new()),
            compensations: Mutex::new(Vec::new()),
            store,
            local_actor,
            max_depth,
        }
    }

    /// Record that an event was applied (clears redo stack).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn record(&self, event_id: EventId) {
        {
            let mut undo = self.undo_stack.lock().unwrap();
            if undo.len() >= self.max_depth {
                undo.remove(0);
            }
            undo.push(event_id);
        }
        // Clear redo on new action.
        self.redo_stack.lock().unwrap().clear();
    }

    /// Undo the last recorded event: create compensating event, push to redo stack.
    /// Returns the compensating event if created.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn undo(&self) -> Option<CollabEvent> {
        let event_id = self.undo_stack.lock().unwrap().pop()?;
        let original = self.store.get_by_id(&event_id)?;
        let comp = compensate(&original, self.local_actor.clone())?;
        let comp_id = comp.id.clone();
        self.store.append(comp.clone());
        self.compensations.lock().unwrap().push(comp_id);
        self.redo_stack.lock().unwrap().push(event_id);
        Some(comp)
    }

    /// Returns the list of compensating event IDs emitted by previous calls
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    /// to [`Self::undo`], in chronological order.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn compensation_log(&self) -> Vec<EventId> {
        self.compensations.lock().unwrap().clone()
    }
 /// # Panics
 ///
 /// Panics if the internal lock is poisoned.
    /// Redo the last undone event.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn redo(&self) -> Option<CollabEvent> {
        let event_id = self.redo_stack.lock().unwrap().pop()?;
        let original = self.store.get_by_id(&event_id)?;
        // Re-apply by creating a fresh copy with updated timestamp.
        let mut re_applied = original;
        re_applied.id = EventId::new();
        re_applied.timestamp_ms = now_ms();
        re_applied.actor = self.local_actor.clone();
        self.store.append(re_applied.clone());
        self.undo_stack.lock().unwrap().push(re_applied.id.clone());
        Some(re_applied)
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.lock().unwrap().is_empty()
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.lock().unwrap().is_empty()
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn undo_depth(&self) -> usize {
        self.undo_stack.lock().unwrap().len()
    }

    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn redo_depth(&self) -> usize {
        self.redo_stack.lock().unwrap().len()
    }
}

// ── Audit trail ──────────────────────────────────────────────────────────────

/// A single audit entry summarizing one event for display.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_id: String,
    pub timestamp_ms: Timestamp,
    pub actor_name: String,
    pub actor_confidence: f32,
    pub summary: String,
    pub address: Option<u64>,
}

impl AuditEntry {
    pub fn from_event(event: &CollabEvent) -> Self {
        let summary = Self::summarize(&event.payload);
        let address = Self::primary_address(&event.payload);
        Self {
            event_id: event.id.0.clone(),
            timestamp_ms: event.timestamp_ms,
            actor_name: event.actor.name.clone(),
            actor_confidence: event.actor.confidence,
            summary,
            address,
        }
    }

    fn summarize(payload: &EventPayload) -> String {
        match payload {
            EventPayload::SymbolRenamed { address, old_name, new_name } => {
                format!("Renamed symbol at {address:#x}: '{old_name}' → '{new_name}'")
            }
            EventPayload::FunctionAnnotated { address, field, new_value, .. } => {
                format!("Function at {address:#x}: {field} = '{new_value}'")
            }
            EventPayload::TypeDefined { type_id, .. } => {
                format!("Defined type #{type_id}")
            }
            EventPayload::TypeRemoved { type_id } => {
                format!("Removed type #{type_id}")
            }
            EventPayload::XrefAdded { from_addr, to_addr, kind } => {
                format!("Xref added {from_addr:#x} → {to_addr:#x} ({kind})")
            }
            EventPayload::XrefRemoved { from_addr, to_addr, kind } => {
                format!("Xref removed {from_addr:#x} → {to_addr:#x} ({kind})")
            }
            EventPayload::CommentSet { address, new_comment, .. } => {
                new_comment.as_ref().map_or_else(
                    || format!("Comment cleared at {address:#x}"),
                    |c| format!("Comment at {address:#x}: '{}'", c.chars().take(40).collect::<String>()),
                )
            }
            EventPayload::TagAdded { address, tag } => {
                format!("Tag '{tag}' added at {address:#x}")
            }
            EventPayload::TagRemoved { address, tag } => {
                format!("Tag '{tag}' removed from {address:#x}")
            }
            EventPayload::Compensating { original_event_id, inner } => {
                format!("Undo of event {}: {}", original_event_id.0, Self::summarize(inner))
            }
            EventPayload::NoOp => "No-op".into(),
        }
    }

    const fn primary_address(payload: &EventPayload) -> Option<u64> {
        match payload {
            EventPayload::SymbolRenamed { address, .. }
            | EventPayload::FunctionAnnotated { address, .. }
            | EventPayload::CommentSet { address, .. }
            | EventPayload::TagAdded { address, .. }
            | EventPayload::TagRemoved { address, .. } => Some(*address),
            EventPayload::XrefAdded { from_addr, .. }
            | EventPayload::XrefRemoved { from_addr, .. } => Some(*from_addr),
            _ => None,
        }
    }
}

/// Queries the event store to produce audit trails.
pub struct AuditTrail<'a> {
    store: &'a EventStore,
}

impl<'a> AuditTrail<'a> {
    pub const fn new(store: &'a EventStore) -> Self {
        AuditTrail { store }
    }

    /// Full history for a specific address, ordered by timestamp ascending.
    pub fn history_at_address(&self, address: u64) -> Vec<AuditEntry> {
        let mut events = self.store.events_by_address(address);
        events.sort_by_key(|e| e.timestamp_ms);
        events.iter().map(AuditEntry::from_event).collect()
    }

    /// All changes by a given actor.
    pub fn history_by_actor(&self, actor_name: &str) -> Vec<AuditEntry> {
        let mut events = self.store.events_by_actor(actor_name);
        events.sort_by_key(|e| e.timestamp_ms);
        events.iter().map(AuditEntry::from_event).collect()
    }

    /// All events in a time range.
    pub fn history_in_time_range(
        &self,
        start: Timestamp,
        end: Timestamp,
    ) -> Vec<AuditEntry> {
        let mut events = self.store.events_in_range(start, end);
        events.sort_by_key(|e| e.timestamp_ms);
        events.iter().map(AuditEntry::from_event).collect()
    }

    /// All events touching an address range.
    pub fn history_in_addr_range(&self, lo: u64, hi: u64) -> Vec<AuditEntry> {
        let mut events = self.store.events_in_addr_range(lo, hi);
        events.sort_by_key(|e| e.timestamp_ms);
        events.iter().map(AuditEntry::from_event).collect()
    }

    /// Render a human-readable audit report for an address.
    #[must_use]
    pub fn render_address_history(&self, address: u64) -> String {
        let entries = self.history_at_address(address);
        if entries.is_empty() {
            return format!("No history for address {address:#x}.\n");
        }
        let mut out = format!("History for {address:#x}:\n");
        for e in &entries {
            let ts_secs = e.timestamp_ms / 1000;
            writeln!(out, "  [{ts_secs}] {} (confidence={:.2}): {}",
                e.actor_name, e.actor_confidence, e.summary
            ).unwrap();
        }
        out
    }

    /// Render a human-readable report for a given actor.
    #[must_use]
    pub fn render_actor_history(&self, actor_name: &str) -> String {
        let entries = self.history_by_actor(actor_name);
        if entries.is_empty() {
            return format!("No history for actor '{actor_name}'.\n");
        }
        let mut out = format!("History for actor '{actor_name}':\n");
        for e in &entries {
            let ts_secs = e.timestamp_ms / 1000;
            writeln!(out, "  [{ts_secs}] {}", e.summary).unwrap();
        }
        out
    }
}

// ── CollaborationManager: top-level facade ───────────────────────────────────

/// Combines the event store, undo history, sync sessions, and WS channel into
/// a single, convenient API.
pub struct CollaborationManager {
    pub store: Arc<EventStore>,
    pub undo_history: UndoHistory,
    pub ws_channel: WsSyncChannel,
    pub http_syncer: HttpSyncer,
    local_actor: Actor,
    sequence_counter: Mutex<u64>,
}

impl CollaborationManager {
    #[must_use]
    pub fn new(local_actor: Actor, strategy: ConflictStrategy) -> Self {
        let store = Arc::new(EventStore::new());
        let undo = UndoHistory::new(Arc::clone(&store), local_actor.clone(), 500);
        let ws = WsSyncChannel::new(Arc::clone(&store), local_actor.clone(), strategy);
        let http = HttpSyncer::new(Arc::clone(&store), local_actor.name.clone(), strategy);
        Self {
            store,
            undo_history: undo,
            ws_channel: ws,
            http_syncer: http,
            local_actor,
            sequence_counter: Mutex::new(0),
        }
    }

    fn next_seq(&self) -> u64 {
        let mut seq = self.sequence_counter.lock().unwrap();
        *seq += 1;
        *seq
    }

    /// Apply a local mutation: append to store, record in undo history, broadcast via WS.
    pub fn apply_local(&self, payload: EventPayload) -> CollabEvent {
        let seq = self.next_seq();
        let event = CollabEvent::new(self.local_actor.clone(), payload)
            .with_sequence(seq);
        self.store.append(event.clone());
        self.undo_history.record(event.id.clone());
        self.ws_channel.push_event(event.clone());
        event
    }

    /// Undo the last local action and broadcast the compensating event.
    pub fn undo(&self) -> Option<CollabEvent> {
        let comp = self.undo_history.undo()?;
        self.ws_channel.push_event(comp.clone());
        Some(comp)
    }

    /// Redo the last undone action.
    pub fn redo(&self) -> Option<CollabEvent> {
        let re = self.undo_history.redo()?;
        self.ws_channel.push_event(re.clone());
        Some(re)
    }

    /// Export a delta since the given checkpoint.
    pub fn export_delta(&self, checkpoint_ts: Timestamp) -> DeltaExport {
        let exporter = DeltaExporter::new(&self.store, &self.local_actor.name);
        exporter.export_since(checkpoint_ts)
    }

    /// Import a delta from a collaborator.
    pub fn import_delta(&self, delta: DeltaExport, strategy: ConflictStrategy) -> ImportResult {
        let importer = DeltaImporter::new(&self.store, strategy);
        importer.apply(delta)
    }

    /// Audit trail façade.
    pub fn audit(&self) -> AuditTrail<'_> {
        AuditTrail::new(&self.store)
    }

    /// Push/pull sync with an HTTP peer.
    pub fn sync(&self, session: &mut SyncSession) -> SyncResult {
        self.http_syncer.sync_bidirectional(session)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_actor(name: &str, conf: f32) -> Actor {
        Actor::new(name, conf)
    }

    #[test]
    fn test_append_and_delta() {
        let store = EventStore::new();
        let actor = make_actor("alice", 0.9);

        let e1 = CollabEvent::new(actor.clone(), EventPayload::SymbolRenamed {
            address: 0x1000,
            old_name: "sub_1000".into(),
            new_name: "decrypt".into(),
        });
        let ts1 = e1.timestamp_ms;
        store.append(e1);

        let e2 = CollabEvent::new(actor, EventPayload::CommentSet {
            address: 0x2000,
            old_comment: None,
            new_comment: Some("entry point".into()),
        });
        store.append(e2);

        let delta = store.delta_since(ts1 - 1);
        assert_eq!(delta.len(), 2);

        let delta_after = store.delta_since(ts1);
        assert!(delta_after.len() <= 1);
    }

    #[test]
    fn test_conflict_resolution_confidence() {
        let resolver = ConflictResolver::new(ConflictStrategy::HighestConfidenceWins);
        let mut local = CollabEvent::new(make_actor("alice", 0.6), EventPayload::SymbolRenamed {
            address: 0x1000,
            old_name: "a".into(),
            new_name: "b".into(),
        });
        local.timestamp_ms = 100;

        let mut remote = CollabEvent::new(make_actor("bot", 0.95), EventPayload::SymbolRenamed {
            address: 0x1000,
            old_name: "a".into(),
            new_name: "decrypt_xor".into(),
        });
        remote.timestamp_ms = 50; // older but higher confidence

        let outcome = resolver.resolve(&local, &remote);
        assert_eq!(outcome.winner, Winner::Remote);
    }

    #[test]
    fn test_undo_redo() {
        let store = Arc::new(EventStore::new());
        let actor = make_actor("test", 1.0);
        let history = UndoHistory::new(Arc::clone(&store), actor.clone(), 100);

        let event = CollabEvent::new(actor, EventPayload::SymbolRenamed {
            address: 0x400,
            old_name: "sub_400".into(),
            new_name: "main".into(),
        });
        let eid = event.id.clone();
        store.append(event);
        history.record(eid);

        assert!(history.can_undo());
        let comp = history.undo().unwrap();
        assert!(!history.can_undo());
        assert!(history.can_redo());

        // Compensating event should rename back.
        match &comp.payload {
            EventPayload::Compensating { inner, .. } => {
                match inner.as_ref() {
                    EventPayload::SymbolRenamed { new_name, .. } => {
                        assert_eq!(new_name, "sub_400");
                    }
                    _ => panic!("wrong inner payload"),
                }
            }
            _ => panic!("expected Compensating"),
        }

        let _ = history.redo().unwrap();
        assert!(history.can_undo());
    }

    #[test]
    fn test_import_dedup() {
        let store = EventStore::new();
        let actor = make_actor("remote", 0.8);

        let event = CollabEvent::new(actor, EventPayload::CommentSet {
            address: 0x500,
            old_comment: None,
            new_comment: Some("hello".into()),
        });
        let delta = DeltaExport {
            checkpoint_ts: 0,
            export_ts: now_ms(),
            actor_name: "remote".into(),
            events: vec![event.clone(), event], // duplicate
        };

        let importer = DeltaImporter::new(&store, ConflictStrategy::default());
        let result = importer.apply(delta);
        assert_eq!(result.applied, 1);
        assert_eq!(result.skipped_duplicate, 1);
    }

    #[test]
    fn test_audit_trail() {
        let store = EventStore::new();
        let alice = make_actor("alice", 0.9);
        let bob = make_actor("bob", 0.7);

        store.append(CollabEvent::new(alice, EventPayload::SymbolRenamed {
            address: 0x1000,
            old_name: "unk".into(),
            new_name: "init".into(),
        }));
        store.append(CollabEvent::new(bob, EventPayload::CommentSet {
            address: 0x1000,
            old_comment: None,
            new_comment: Some("initializes globals".into()),
        }));

        let trail = AuditTrail::new(&store);
        let history = trail.history_at_address(0x1000);
        assert_eq!(history.len(), 2);

        let alice_hist = trail.history_by_actor("alice");
        assert_eq!(alice_hist.len(), 1);
    }

    #[test]
    fn test_ws_message_roundtrip() {
        let msg = WsMessage::Events(vec![
            CollabEvent::new(make_actor("x", 1.0), EventPayload::NoOp),
        ]);
        let json = msg.to_json().unwrap();
        let parsed = WsMessage::from_json(&json).unwrap();
        match parsed {
            WsMessage::Events(evs) => assert_eq!(evs.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_collab_manager_apply_undo() {
        let actor = make_actor("analyst", 0.95);
        let mgr = CollaborationManager::new(actor, ConflictStrategy::HighestConfidenceWins);

        let _ = mgr.apply_local(EventPayload::SymbolRenamed {
            address: 0xdead,
            old_name: "fn_dead".into(),
            new_name: "parse_header".into(),
        });

        assert_eq!(mgr.store.len(), 1);
        let _ = mgr.undo().unwrap();
        assert_eq!(mgr.store.len(), 2); // original + compensating
        let _ = mgr.redo().unwrap();
        assert_eq!(mgr.store.len(), 3);
    }
}
