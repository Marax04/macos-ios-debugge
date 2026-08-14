//! `store` — Transactional, event-sourced knowledge store.
//!
//! Wraps an [`EntitySnapshot`] together with an [`EventLog`]. Mutations go
//! through [`KnowledgeStore::begin`], which returns a [`Transaction`]; on
//! [`Transaction::commit`] the buffered events are appended to the log and
//! applied to the snapshot atomically. Dropping a transaction without
//! committing is a no-op (rollback).
//!
//! The persistence backend is intentionally pluggable: see [`JsonBackend`]
//! for a file-based snapshot+log implementation, and the [`PersistBackend`]
//! trait if you want to plug a heavier store (e.g. `rustre-db` once it
//! exposes its public API).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use thiserror::Error;

use crate::entities::{
    Bookmark, Comment, EntityId, EntitySnapshot, Function, Patch, Symbol, Tag, Trace,
    TypeDef, Xref,
};
use crate::events::{EventError, EventLog, EventPayload, KnowledgeEvent};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by the store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A persistence backend reported a failure.
    #[error("persistence error: {0}")]
    Persist(String),
    /// An event could not be applied during commit or replay.
    #[error(transparent)]
    Event(#[from] EventError),
    /// A serialisation error.
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

// ---------------------------------------------------------------------------
// PersistBackend
// ---------------------------------------------------------------------------

/// Pluggable persistence backend for a [`KnowledgeStore`].
///
/// Implementors are responsible for durably storing the latest snapshot and
/// event log. Both are passed by value during save so the implementation can
/// stream them out without holding a read lock on the store.
pub trait PersistBackend: Send + Sync {
    /// Persist a snapshot plus the full event log.
    ///
    /// # Errors
    ///
    /// Implementation-defined; wrapped in [`StoreError::Persist`].
    fn save(&self, snapshot: &EntitySnapshot, log: &EventLog) -> Result<(), StoreError>;

    /// Load a snapshot and event log, if one exists.
    ///
    /// Returns `Ok(None)` if nothing has been persisted yet.
    ///
    /// # Errors
    ///
    /// Implementation-defined; wrapped in [`StoreError::Persist`].
    fn load(&self) -> Result<Option<(EntitySnapshot, EventLog)>, StoreError>;
}

// ---------------------------------------------------------------------------
// NullBackend
// ---------------------------------------------------------------------------

/// In-memory only backend — `save`/`load` are no-ops.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullBackend;

impl PersistBackend for NullBackend {
    fn save(&self, _snapshot: &EntitySnapshot, _log: &EventLog) -> Result<(), StoreError> {
        Ok(())
    }
    fn load(&self) -> Result<Option<(EntitySnapshot, EventLog)>, StoreError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// JsonBackend
// ---------------------------------------------------------------------------

/// JSON file backend: stores `<dir>/snapshot.json` and `<dir>/events.json`.
#[derive(Debug, Clone)]
pub struct JsonBackend {
    dir: PathBuf,
}

impl JsonBackend {
    /// Create a new backend rooted at `dir` (the directory must exist or be
    /// creatable).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn snapshot_path(&self) -> PathBuf {
        self.dir.join("snapshot.json")
    }
    fn events_path(&self) -> PathBuf {
        self.dir.join("events.json")
    }
}

impl PersistBackend for JsonBackend {
    fn save(&self, snapshot: &EntitySnapshot, log: &EventLog) -> Result<(), StoreError> {
        fs::create_dir_all(&self.dir)?;
        let snap_bytes = serde_json::to_vec_pretty(snapshot)?;
        let log_bytes = serde_json::to_vec_pretty(log)?;
        fs::write(self.snapshot_path(), snap_bytes)?;
        fs::write(self.events_path(), log_bytes)?;
        Ok(())
    }

    fn load(&self) -> Result<Option<(EntitySnapshot, EventLog)>, StoreError> {
        let snap_bytes = match fs::read(self.snapshot_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e)),
        };
        let log_bytes = match fs::read(self.events_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Snapshot exists but log is missing — treat as corrupt/incomplete.
                return Err(StoreError::Persist(
                    "snapshot.json exists but events.json is missing; store may be corrupt".to_string(),
                ));
            }
            Err(e) => return Err(StoreError::Io(e)),
        };
        let snapshot: EntitySnapshot = serde_json::from_slice(&snap_bytes)?;
        let log: EventLog = serde_json::from_slice(&log_bytes)?;
        Ok(Some((snapshot, log)))
    }
}

// ---------------------------------------------------------------------------
// KnowledgeStore
// ---------------------------------------------------------------------------

/// Thread-safe transactional knowledge store.
pub struct KnowledgeStore {
    inner: RwLock<Inner>,
    next_txn: AtomicU64,
    backend: Box<dyn PersistBackend>,
}

struct Inner {
    snapshot: EntitySnapshot,
    log: EventLog,
}

impl KnowledgeStore {
    /// Create a new in-memory store with no persistence.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            inner: RwLock::new(Inner {
                snapshot: EntitySnapshot::new(),
                log: EventLog::new(),
            }),
            next_txn: AtomicU64::new(0),
            backend: Box::new(NullBackend),
        }
    }

    /// Create a store backed by a custom persistence implementation. The
    /// backend's `load` is invoked immediately; on success the snapshot and
    /// log are restored.
    ///
    /// # Errors
    ///
    /// Propagates any [`StoreError`] from `backend.load()`.
    pub fn with_backend(backend: Box<dyn PersistBackend>) -> Result<Self, StoreError> {
        let (snapshot, log) = backend.load()?.unwrap_or_default();
        let next_txn = log.events().iter().filter_map(|e| e.txn).max().map_or(0, |m| m.saturating_add(1));
        Ok(Self {
            inner: RwLock::new(Inner { snapshot, log }),
            next_txn: AtomicU64::new(next_txn),
            backend,
        })
    }

    /// Convenience constructor: open or create a JSON-backed store at `dir`.
    ///
    /// # Errors
    ///
    /// Propagates any [`StoreError`] from the underlying load.
    pub fn open_json(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::with_backend(Box::new(JsonBackend::new(dir.as_ref().to_path_buf())))
    }

    /// Begin a new transaction. The transaction buffers mutations; nothing is
    /// visible to other readers until [`Transaction::commit`] succeeds.
    pub fn begin(&self, author: impl Into<String>) -> Transaction<'_> {
        let txn_id = self.next_txn.fetch_add(1, Ordering::AcqRel);
        Transaction {
            store: self,
            author: author.into(),
            txn_id,
            staged: Vec::new(),
            committed: false,
        }
    }

    /// Run a closure inside a transaction; commits on `Ok`, drops (rolls
    /// back) on `Err`.
    ///
    /// # Errors
    ///
    /// Returns whatever the closure returns; on commit, propagates
    /// [`StoreError`] from the commit step.
    pub fn with_txn<F, R, E>(&self, author: impl Into<String>, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut Transaction<'_>) -> Result<R, E>,
        E: From<StoreError>,
    {
        let mut txn = self.begin(author);
        let r = f(&mut txn)?;
        txn.commit().map_err(E::from)?;
        Ok(r)
    }

    /// Borrow the current snapshot.
    pub fn snapshot(&self) -> EntitySnapshot {
        self.inner.read().snapshot.clone()
    }

    /// Number of events recorded so far.
    pub fn event_count(&self) -> usize {
        self.inner.read().log.len()
    }

    /// Clone the full event log.
    pub fn event_log(&self) -> EventLog {
        self.inner.read().log.clone()
    }

    /// Force a save through the configured backend.
    ///
    /// # Errors
    ///
    /// Propagates any [`StoreError`] from `backend.save()`.
    pub fn flush(&self) -> Result<(), StoreError> {
        let guard = self.inner.read();
        self.backend.save(&guard.snapshot, &guard.log)
    }

    /// Run a read-only query against a borrowed snapshot.
    pub fn query<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&EntitySnapshot) -> R,
    {
        f(&self.inner.read().snapshot)
    }
}

impl Default for KnowledgeStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl std::fmt::Debug for KnowledgeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.inner.read();
        f.debug_struct("KnowledgeStore")
            .field("entities", &guard.snapshot.total_entities())
            .field("events", &guard.log.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

/// A buffered mutation handle. Mutations are recorded into the store on
/// [`Transaction::commit`]; dropping without committing discards them.
pub struct Transaction<'s> {
    store: &'s KnowledgeStore,
    author: String,
    txn_id: u64,
    staged: Vec<EventPayload>,
    committed: bool,
}

impl Transaction<'_> {
    /// Transaction id (also stamped onto each emitted event).
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.txn_id
    }

    /// Number of staged payloads.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.staged.len()
    }

    /// Discard all staged payloads without affecting the store.
    pub fn rollback(mut self) {
        self.staged.clear();
        self.committed = true; // suppress drop-warning path
    }

    /// Stage a raw payload.
    pub fn stage(&mut self, payload: EventPayload) {
        self.staged.push(payload);
    }

    /// Stage an upsert for a [`Symbol`].
    pub fn upsert_symbol(&mut self, s: Symbol) {
        self.stage(EventPayload::UpsertSymbol(s));
    }
    /// Stage a removal for a [`Symbol`] id.
    pub fn remove_symbol(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveSymbol(id));
    }
    /// Stage an upsert for a [`Function`].
    pub fn upsert_function(&mut self, f: Function) {
        self.stage(EventPayload::UpsertFunction(f));
    }
    /// Stage a removal for a [`Function`] id.
    pub fn remove_function(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveFunction(id));
    }
    /// Stage an upsert for a [`TypeDef`].
    pub fn upsert_type(&mut self, t: TypeDef) {
        self.stage(EventPayload::UpsertType(t));
    }
    /// Stage a removal for a [`TypeDef`] id.
    pub fn remove_type(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveType(id));
    }
    /// Stage an upsert for a [`Comment`].
    pub fn upsert_comment(&mut self, c: Comment) {
        self.stage(EventPayload::UpsertComment(c));
    }
    /// Stage a removal for a [`Comment`] id.
    pub fn remove_comment(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveComment(id));
    }
    /// Stage an upsert for an [`Xref`].
    pub fn upsert_xref(&mut self, x: Xref) {
        self.stage(EventPayload::UpsertXref(x));
    }
    /// Stage a removal for an [`Xref`] id.
    pub fn remove_xref(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveXref(id));
    }
    /// Stage an upsert for a [`Patch`].
    pub fn upsert_patch(&mut self, p: Patch) {
        self.stage(EventPayload::UpsertPatch(p));
    }
    /// Stage a removal for a [`Patch`] id.
    pub fn remove_patch(&mut self, id: EntityId) {
        self.stage(EventPayload::RemovePatch(id));
    }
    /// Stage an upsert for a [`Bookmark`].
    pub fn upsert_bookmark(&mut self, b: Bookmark) {
        self.stage(EventPayload::UpsertBookmark(b));
    }
    /// Stage a removal for a [`Bookmark`] id.
    pub fn remove_bookmark(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveBookmark(id));
    }
    /// Stage an upsert for a [`Trace`].
    pub fn upsert_trace(&mut self, t: Trace) {
        self.stage(EventPayload::UpsertTrace(t));
    }
    /// Stage a removal for a [`Trace`] id.
    pub fn remove_trace(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveTrace(id));
    }
    /// Stage an upsert for a [`Tag`].
    pub fn upsert_tag(&mut self, t: Tag) {
        self.stage(EventPayload::UpsertTag(t));
    }
    /// Stage a removal for a [`Tag`] id.
    pub fn remove_tag(&mut self, id: EntityId) {
        self.stage(EventPayload::RemoveTag(id));
    }

    /// Commit all staged payloads atomically. The snapshot is mutated under a
    /// single write lock; if any event fails to apply, the store state is
    /// rolled back to what it was before this commit started.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Event`] on apply failure.
    pub fn commit(mut self) -> Result<Vec<KnowledgeEvent>, StoreError> {
        let payloads = std::mem::take(&mut self.staged);
        self.committed = true;
        if payloads.is_empty() {
            return Ok(Vec::new());
        }
        let mut guard = self.store.inner.write();
        let snapshot_backup = guard.snapshot.clone();
        let log_seq_backup = guard.log.next_seq();
        let log_len_backup = guard.log.len();

        let mut recorded = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let ev = guard.log.record(self.author.clone(), Some(self.txn_id), payload);
            if let Err(e) = ev.apply(&mut guard.snapshot) {
                // Roll back: restore snapshot and trim log, then release the lock.
                guard.snapshot = snapshot_backup;
                truncate_log(&mut guard.log, log_len_backup, log_seq_backup);
                drop(guard);
                return Err(StoreError::Event(e));
            }
            recorded.push(ev);
        }
        drop(guard);
        Ok(recorded)
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        // Dropping without commit is a rollback: simply discard staged data.
        self.staged.clear();
    }
}

fn truncate_log(log: &mut EventLog, prev_len: usize, prev_next_seq: u64) {
    // Rebuild a log truncated to `prev_len` events / `prev_next_seq` counter.
    let kept: Vec<KnowledgeEvent> = log.events().iter().take(prev_len).cloned().collect();
    let mut new_log = EventLog::new();
    for ev in kept {
        new_log.record(ev.author.clone(), ev.txn, ev.payload.clone());
    }
    // Force the counter to the recorded value (events were re-stamped above
    // with the same sequence numbers because we recorded them in order).
    debug_assert_eq!(new_log.next_seq(), prev_next_seq);
    *log = new_log;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{Symbol, SymbolScope};

    #[test]
    fn commit_persists_to_snapshot() {
        let store = KnowledgeStore::in_memory();
        let mut txn = store.begin("alice");
        let sym = Symbol::new(0x1000, "main", SymbolScope::Global);
        let id = sym.id;
        txn.upsert_symbol(sym);
        let events = txn.commit().unwrap();
        assert_eq!(events.len(), 1);
        assert!(store.snapshot().symbols.contains_key(&id));
        assert_eq!(store.event_count(), 1);
    }

    #[test]
    fn rollback_discards_staged() {
        let store = KnowledgeStore::in_memory();
        let mut txn = store.begin("alice");
        txn.upsert_symbol(Symbol::new(0x1000, "main", SymbolScope::Global));
        txn.rollback();
        assert!(store.snapshot().symbols.is_empty());
        assert_eq!(store.event_count(), 0);
    }

    #[test]
    fn drop_without_commit_rolls_back() {
        let store = KnowledgeStore::in_memory();
        {
            let mut txn = store.begin("alice");
            txn.upsert_symbol(Symbol::new(0x1000, "main", SymbolScope::Global));
        }
        assert!(store.snapshot().symbols.is_empty());
    }

    #[test]
    fn commit_failure_rolls_back_all() {
        let store = KnowledgeStore::in_memory();
        // Seed
        let mut t = store.begin("a");
        let sym = Symbol::new(0x10, "x", SymbolScope::Global);
        let id = sym.id;
        t.upsert_symbol(sym);
        t.commit().unwrap();
        assert_eq!(store.event_count(), 1);

        // Now stage one good + one bad (remove of unknown id) → commit fails.
        let mut t = store.begin("a");
        t.upsert_symbol(Symbol::new(0x20, "y", SymbolScope::Global));
        t.remove_symbol(EntityId::new());
        let err = t.commit();
        assert!(err.is_err());
        // Snapshot must equal the previously committed state.
        let snap = store.snapshot();
        assert_eq!(snap.symbols.len(), 1);
        assert!(snap.symbols.contains_key(&id));
        assert_eq!(store.event_count(), 1);
    }

    #[test]
    fn with_txn_helper_commits_on_ok() {
        let store = KnowledgeStore::in_memory();
        let out: Result<usize, StoreError> = store.with_txn("u", |t| {
            t.upsert_symbol(Symbol::new(1, "a", SymbolScope::Local));
            t.upsert_symbol(Symbol::new(2, "b", SymbolScope::Local));
            Ok(t.pending())
        });
        assert_eq!(out.unwrap(), 2);
        assert_eq!(store.snapshot().symbols.len(), 2);
    }

    #[test]
    fn json_backend_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("rustre-knowledge-test-{}", uuid::Uuid::new_v4()));
        let store = KnowledgeStore::open_json(&tmp).unwrap();
        let mut t = store.begin("u");
        t.upsert_symbol(Symbol::new(0x10, "foo", SymbolScope::Global));
        t.commit().unwrap();
        store.flush().unwrap();

        let store2 = KnowledgeStore::open_json(&tmp).unwrap();
        assert_eq!(store2.snapshot().symbols.len(), 1);
        assert_eq!(store2.event_count(), 1);
        let _ = fs::remove_dir_all(&tmp);
    }
}
