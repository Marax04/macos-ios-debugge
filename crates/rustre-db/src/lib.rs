//! `rustre-db`
//!
//! Database layer for `RustRE` — SQLite-backed storage for the persistent
//! knowledge graph (P4). Provides:
//!
//! - [`Database`] connection pool over `rusqlite`,
//! - RAII [`Connection`] and [`Transaction`] handles,
//! - Versioned schema migrations ([`DbMigrationManager`], [`run_migrations`]),
//! - A base knowledge-graph schema ([`apply_base_schema`], [`base_migrations`]),
//! - Append-only event-sourcing storage ([`EventStore`], [`NewEvent`],
//!   [`StoredEvent`]),
//! - Index management ([`DbIndexManager`], [`create_index`]),
//! - A composable [`DbQueryBuilder`].

pub mod db_connection;
pub mod db_events;
pub mod db_index_manager;
pub mod db_migration_manager;
pub mod db_query_builder;
pub mod db_schema;

pub use db_connection::{
    Connection, Database, DbConfig, DbError, DbLocation, Transaction,
};
pub use db_events::{EventError, EventStore, NewEvent, StoredEvent};
pub use db_index_manager::{DbIndexManager, IndexDef, IndexError, IndexKind, create_index};
pub use db_migration_manager::{
    DbMigrationManager, Migration, MigrationError, MigrationReport, MigrationStatus,
    MigrationVersion, run_migrations,
};
pub use db_query_builder::{DbQueryBuilder, QueryParams, QueryPart, build_select};
pub use db_schema::{SchemaError, apply_base_schema, base_migrations};
