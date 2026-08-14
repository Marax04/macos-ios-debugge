//! `db_schema` — Base schema for the `RustRE` knowledge graph.
//!
//! The base schema models analytic state (symbols, functions, types,
//! comments, xrefs, struct definitions, patches, bookmarks, trace records)
//! as a generic graph of `nodes` and `edges`, plus an append-only `events`
//! log used by [`crate::db_events`] for event-sourcing.
//!
//! Migrations are returned as a `Vec<Migration>` and applied via
//! [`crate::db_migration_manager::run_migrations`] or
//! [`apply_base_schema`].

use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::Connection as SqliteConnection;

use crate::db_connection::{Connection, DbError};
use crate::db_migration_manager::{Migration, MigrationError, MigrationReport, run_migrations};

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

const M001_UP: &str = r"
CREATE TABLE IF NOT EXISTS nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    key          TEXT    NOT NULL,
    payload      BLOB,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    UNIQUE(kind, key)
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);

CREATE TABLE IF NOT EXISTS edges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    src_id       INTEGER NOT NULL,
    dst_id       INTEGER NOT NULL,
    payload      BLOB,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    FOREIGN KEY (src_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (dst_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_edges_kind     ON edges(kind);
CREATE INDEX IF NOT EXISTS idx_edges_src      ON edges(src_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst      ON edges(dst_id);
CREATE INDEX IF NOT EXISTS idx_edges_kind_src ON edges(kind, src_id);
";

const M001_DOWN: &str = r"
DROP TABLE IF EXISTS edges;
DROP TABLE IF EXISTS nodes;
";

const M002_UP: &str = r"
CREATE TABLE IF NOT EXISTS events (
    offset       INTEGER PRIMARY KEY AUTOINCREMENT,
    stream       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    payload      BLOB    NOT NULL,
    metadata     BLOB,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_stream      ON events(stream);
CREATE INDEX IF NOT EXISTS idx_events_kind        ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_stream_off  ON events(stream, offset);
";

const M002_DOWN: &str = r"
DROP TABLE IF EXISTS events;
";

const M003_UP: &str = r"
CREATE TABLE IF NOT EXISTS kv_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
";

const M003_DOWN: &str = r"
DROP TABLE IF EXISTS kv_meta;
";

/// Return the canonical base schema migrations.
#[must_use]
pub fn base_migrations() -> Vec<Migration> {
    vec![
        Migration::with_rollback(1u32, "create_graph_tables", M001_UP, M001_DOWN),
        Migration::with_rollback(2u32, "create_events_table", M002_UP, M002_DOWN),
        Migration::with_rollback(3u32, "create_kv_meta_table", M003_UP, M003_DOWN),
    ]
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

/// Errors produced by [`apply_base_schema`].
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// Failed to acquire a connection or run SQL.
    #[error(transparent)]
    Db(#[from] DbError),
    /// A migration failed.
    #[error(transparent)]
    Migration(#[from] MigrationError),
}

/// Apply the base `RustRE` knowledge-graph schema to the given connection,
/// using a private `Mutex`-wrapped clone of the raw handle.
///
/// # Errors
///
/// Returns [`SchemaError::Migration`] if any migration fails to apply.
pub fn apply_base_schema(conn: &mut Connection) -> Result<MigrationReport, SchemaError> {
    // The migration manager wants `Arc<Mutex<SqliteConnection>>`. We don't
    // want to give up ownership of the pool connection, so we briefly move
    // the inner handle through a scoped `Arc<Mutex<_>>`, then put it back.
    let raw = std::mem::replace(
        conn.raw_mut(),
        SqliteConnection::open_in_memory().map_err(DbError::Sql)?,
    );
    let arc: Arc<Mutex<SqliteConnection>> = Arc::new(Mutex::new(raw));
    let result = run_migrations(arc.clone(), base_migrations());
    // Recover the real connection regardless of outcome.
    let mutex = Arc::try_unwrap(arc)
        .map_err(|_| SchemaError::Db(DbError::InvalidConfig(
            "internal: outstanding migration reference".into(),
        )))?;
    let real = mutex.into_inner();
    // Drop the placeholder in-memory conn and restore the real one.
    let placeholder = std::mem::replace(conn.raw_mut(), real);
    drop(placeholder);
    Ok(result?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_connection::Database;

    #[test]
    fn applies_base_schema_cleanly() {
        let db = Database::open_in_memory().unwrap();
        let mut c = db.acquire().unwrap();
        let report = apply_base_schema(&mut c).unwrap();
        assert!(report.is_success());
        assert_eq!(report.newly_applied, 3);

        // Verify tables exist
        let count: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='table' AND name IN ('nodes','edges','events','kv_meta');",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn base_schema_is_idempotent() {
        let db = Database::open_in_memory().unwrap();
        let mut c = db.acquire().unwrap();
        apply_base_schema(&mut c).unwrap();
        let r2 = apply_base_schema(&mut c).unwrap();
        assert_eq!(r2.newly_applied, 0);
        assert_eq!(r2.already_applied, 3);
    }
}
