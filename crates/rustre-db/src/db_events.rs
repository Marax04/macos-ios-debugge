//! `db_events` — Append-only event-sourcing storage backed by the
//! `events` table created by [`crate::db_schema`].
//!
//! Each event has:
//!
//! - a monotonically increasing `offset` (assigned by `SQLite`),
//! - a `stream` name (groups related events, e.g. `"project:42"`),
//! - a `kind` discriminator (e.g. `"SymbolRenamed"`),
//! - an opaque `payload` (bytes — typically bincode- or JSON-serialized),
//! - optional opaque `metadata` bytes.
//!
//! Events are never updated or deleted by this module; consumers replay
//! them in `offset` order to rebuild projections.

use rusqlite::params;
use thiserror::Error;

use crate::db_connection::{Connection, DbError, Transaction};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the event store.
#[derive(Debug, Error)]
pub enum EventError {
    /// Low-level database error.
    #[error(transparent)]
    Db(#[from] DbError),
    /// Low-level `SQLite` error.
    #[error("sql error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// The required `events` table is missing — run base migrations first.
    #[error("events table missing — run base migrations first")]
    SchemaMissing,
}

// ---------------------------------------------------------------------------
// Event records
// ---------------------------------------------------------------------------

/// A new event to be appended.
#[derive(Debug, Clone)]
pub struct NewEvent {
    /// Stream this event belongs to.
    pub stream: String,
    /// Discriminator for the event type.
    pub kind: String,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
    /// Optional opaque metadata bytes.
    pub metadata: Option<Vec<u8>>,
}

impl NewEvent {
    /// Build a new event with no metadata.
    #[must_use]
    pub fn new(
        stream: impl Into<String>,
        kind: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            stream: stream.into(),
            kind: kind.into(),
            payload: payload.into(),
            metadata: None,
        }
    }

    /// Attach metadata to this event.
    #[must_use]
    pub fn with_metadata(mut self, metadata: impl Into<Vec<u8>>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }
}

/// A persisted event read back from the store.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    /// Monotonic offset assigned by `SQLite`.
    pub offset: i64,
    /// Stream this event belongs to.
    pub stream: String,
    /// Discriminator for the event type.
    pub kind: String,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
    /// Optional opaque metadata bytes.
    pub metadata: Option<Vec<u8>>,
    /// Unix timestamp (seconds) when the event was persisted.
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// EventStore
// ---------------------------------------------------------------------------

/// Append-only event store backed by the shared `events` table.
///
/// Cheap to construct (holds no state); pass it any borrowed
/// [`Connection`] or [`Transaction`].
#[derive(Debug, Default, Clone, Copy)]
pub struct EventStore;

impl EventStore {
    /// Construct a new event store handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Append a single event using the given connection. Returns the
    /// assigned `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] if the insert fails.
    pub fn append(&self, conn: &Connection, event: &NewEvent) -> Result<i64, EventError> {
        let raw = conn.raw();
        raw.execute(
            "INSERT INTO events (stream, kind, payload, metadata) VALUES (?1, ?2, ?3, ?4)",
            params![event.stream, event.kind, event.payload, event.metadata],
        )?;
        Ok(raw.last_insert_rowid())
    }

    /// Append a single event inside an existing transaction. Returns the
    /// assigned `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] if the insert fails.
    pub fn append_in_tx(
        &self,
        tx: &Transaction<'_>,
        event: &NewEvent,
    ) -> Result<i64, EventError> {
        let raw = tx.raw();
        raw.execute(
            "INSERT INTO events (stream, kind, payload, metadata) VALUES (?1, ?2, ?3, ?4)",
            params![event.stream, event.kind, event.payload, event.metadata],
        )?;
        Ok(raw.last_insert_rowid())
    }

    /// Append a batch of events atomically. Returns the offsets in order.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] on insert failure; on error the
    /// transaction is rolled back and no events are persisted.
    pub fn append_batch(
        &self,
        conn: &mut Connection,
        events: &[NewEvent],
    ) -> Result<Vec<i64>, EventError> {
        let tx = conn.transaction()?;
        let mut offsets = Vec::with_capacity(events.len());
        {
            let raw = tx.raw();
            let mut stmt = raw.prepare(
                "INSERT INTO events (stream, kind, payload, metadata) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for ev in events {
                stmt.execute(params![ev.stream, ev.kind, ev.payload, ev.metadata])?;
                offsets.push(raw.last_insert_rowid());
            }
        }
        tx.commit()?;
        Ok(offsets)
    }

    /// The maximum number of events that a single `read_stream` / `read_all`
    /// call will materialise into memory. Callers that need more must paginate
    /// using `after_offset`. This cap prevents a caller-supplied `limit` value
    /// from causing unbounded heap allocation.
    pub const MAX_READ_LIMIT: usize = 100_000;

    /// Read events from `stream` starting just after `after_offset`.
    /// If `after_offset` is `None`, starts at the beginning. `limit`
    /// caps the number of rows returned (capped at [`Self::MAX_READ_LIMIT`]).
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] if the query fails.
    pub fn read_stream(
        &self,
        conn: &Connection,
        stream: &str,
        after_offset: Option<i64>,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, EventError> {
        let after = after_offset.unwrap_or(-1);
        // Cap the limit to prevent a large caller-supplied value from
        // materialising an unbounded number of rows into memory.
        let limit = limit.min(Self::MAX_READ_LIMIT);
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let raw = conn.raw();
        let mut stmt = raw.prepare(
            "SELECT offset, stream, kind, payload, metadata, created_at \
             FROM events \
             WHERE stream = ?1 AND offset > ?2 \
             ORDER BY offset ASC \
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![stream, after, lim], Self::row_to_event)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Read all events across all streams after `after_offset`, ordered by
    /// offset, capped by `limit` (capped at [`Self::MAX_READ_LIMIT`]).
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] if the query fails.
    pub fn read_all(
        &self,
        conn: &Connection,
        after_offset: Option<i64>,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, EventError> {
        let after = after_offset.unwrap_or(-1);
        let limit = limit.min(Self::MAX_READ_LIMIT);
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let raw = conn.raw();
        let mut stmt = raw.prepare(
            "SELECT offset, stream, kind, payload, metadata, created_at \
             FROM events \
             WHERE offset > ?1 \
             ORDER BY offset ASC \
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![after, lim], Self::row_to_event)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Return the highest offset across all events, or `None` if empty.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] if the query fails.
    pub fn latest_offset(&self, conn: &Connection) -> Result<Option<i64>, EventError> {
        let raw = conn.raw();
        let row: Option<i64> = raw
            .query_row("SELECT MAX(offset) FROM events", [], |r| r.get(0))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(row)
    }

    /// Return the total number of events.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Sql`] if the query fails.
    pub fn count(&self, conn: &Connection) -> Result<u64, EventError> {
        let raw = conn.raw();
        let n: i64 = raw.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    // -----------------------------------------------------------------------

    fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvent> {
        Ok(StoredEvent {
            offset: row.get(0)?,
            stream: row.get(1)?,
            kind: row.get(2)?,
            payload: row.get(3)?,
            metadata: row.get(4)?,
            created_at: row.get(5)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_connection::Database;
    use crate::db_schema::apply_base_schema;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        {
            let mut c = db.acquire().unwrap();
            apply_base_schema(&mut c).unwrap();
        }
        db
    }

    #[test]
    fn append_then_read() {
        let db = fresh_db();
        let c = db.acquire().unwrap();
        let store = EventStore::new();
        let off1 = store
            .append(&c, &NewEvent::new("s1", "Created", b"a".to_vec()))
            .unwrap();
        let off2 = store
            .append(&c, &NewEvent::new("s1", "Updated", b"b".to_vec()))
            .unwrap();
        assert!(off2 > off1);
        let evs = store.read_stream(&c, "s1", None, 100).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].kind, "Created");
        assert_eq!(evs[1].payload, b"b");
    }

    #[test]
    fn read_after_offset() {
        let db = fresh_db();
        let c = db.acquire().unwrap();
        let store = EventStore::new();
        let off1 = store
            .append(&c, &NewEvent::new("s", "A", b"1".to_vec()))
            .unwrap();
        store.append(&c, &NewEvent::new("s", "B", b"2".to_vec())).unwrap();
        let evs = store.read_stream(&c, "s", Some(off1), 100).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "B");
    }

    #[test]
    fn batch_is_atomic_and_ordered() {
        let db = fresh_db();
        let mut c = db.acquire().unwrap();
        let store = EventStore::new();
        let offsets = store
            .append_batch(
                &mut c,
                &[
                    NewEvent::new("s", "A", b"1".to_vec()),
                    NewEvent::new("s", "B", b"2".to_vec()),
                    NewEvent::new("s", "C", b"3".to_vec()),
                ],
            )
            .unwrap();
        assert_eq!(offsets.len(), 3);
        assert!(offsets[0] < offsets[1] && offsets[1] < offsets[2]);
        assert_eq!(store.count(&c).unwrap(), 3);
    }

    #[test]
    fn latest_offset_tracks_appends() {
        let db = fresh_db();
        let c = db.acquire().unwrap();
        let store = EventStore::new();
        assert!(matches!(store.latest_offset(&c).unwrap(), Some(0) | None));
        let off = store
            .append(&c, &NewEvent::new("s", "X", b"x".to_vec()))
            .unwrap();
        assert_eq!(store.latest_offset(&c).unwrap(), Some(off));
    }

    #[test]
    fn metadata_round_trips() {
        let db = fresh_db();
        let c = db.acquire().unwrap();
        let store = EventStore::new();
        store
            .append(
                &c,
                &NewEvent::new("s", "K", b"p".to_vec()).with_metadata(b"meta".to_vec()),
            )
            .unwrap();
        let evs = store.read_stream(&c, "s", None, 10).unwrap();
        assert_eq!(evs[0].metadata.as_deref(), Some(&b"meta"[..]));
    }
}
