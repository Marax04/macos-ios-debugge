//! SQLite-backed graph persistence for `RustRE`.
//!
//! Provides [`GraphPersistence`] as the primary entry point, with
//! [`NodeSerializer`], [`EdgeSerializer`], [`GraphTransaction`],
//! [`GraphBackup`], and [`GraphMigration`] as supporting types.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A shared, reference-counted database path — exposed for callers that want
/// to hand the same `PathBuf` to several `GraphPersistence` instances without
/// cloning the underlying string allocation.
pub type SharedDbPath = Arc<PathBuf>;

use parking_lot::Mutex;
use rusqlite::{Connection, Result as SqlResult, Transaction, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the graph persistence layer.
#[derive(Debug, Error)]
pub enum PersistError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("node {0} not found")]
    NodeNotFound(i64),

    #[error("edge {0} not found")]
    EdgeNotFound(i64),

    #[error("migration failed at version {version}: {message}")]
    MigrationFailed { version: u32, message: String },

    #[error("backup error: {0}")]
    Backup(String),

    #[error("schema version mismatch: expected {expected}, got {got}")]
    SchemaMismatch { expected: u32, got: u32 },

    #[error("transaction rolled back: {0}")]
    Rollback(String),

    #[error("graph is locked by another writer")]
    Locked,
}

pub type PersistResult<T> = std::result::Result<T, PersistError>;

// ── Schema version ────────────────────────────────────────────────────────────

const CURRENT_SCHEMA_VERSION: u32 = 3;

// ── Node and Edge types ───────────────────────────────────────────────────────

/// A logical node kind stored in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Function,
    BasicBlock,
    Variable,
    Type,
    Symbol,
    Module,
    Class,
    Custom(String),
}

impl NodeKind {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Function => "function",
            Self::BasicBlock => "basic_block",
            Self::Variable => "variable",
            Self::Type => "type",
            Self::Symbol => "symbol",
            Self::Module => "module",
            Self::Class => "class",
            Self::Custom(s) => s.as_str(),
        }
    }
    #[must_use]
    pub fn from_kind_str(s: &str) -> Self {
        match s {
            "function" => Self::Function,
            "basic_block" => Self::BasicBlock,
            "variable" => Self::Variable,
            "type" => Self::Type,
            "symbol" => Self::Symbol,
            "module" => Self::Module,
            "class" => Self::Class,
            other => Self::Custom(other.to_owned()),
        }
    }
}

/// A logical edge kind stored in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Call,
    DataFlow,
    Control,
    Type,
    Contains,
    Reference,
    Custom(String),
}

impl EdgeKind {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Call => "call",
            Self::DataFlow => "data_flow",
            Self::Control => "control",
            Self::Type => "type",
            Self::Contains => "contains",
            Self::Reference => "reference",
            Self::Custom(s) => s.as_str(),
        }
    }

    #[must_use]
    pub fn from_kind_str(s: &str) -> Self {
        match s {
            "call" => Self::Call,
            "data_flow" => Self::DataFlow,
            "control" => Self::Control,
            "type" => Self::Type,
            "contains" => Self::Contains,
            "reference" => Self::Reference,
            other => Self::Custom(other.to_owned()),
        }
    }
}

// ── Node ─────────────────────────────────────────────────────────────────────

/// A persisted graph node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedNode {
    pub id: i64,
    pub kind: NodeKind,
    pub label: String,
    pub address: Option<u64>,
    pub view_id: Option<i64>,
    pub properties: HashMap<String, serde_json::Value>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl PersistedNode {
    pub fn new(kind: NodeKind, label: impl Into<String>) -> Self {
        let now = now_unix();
        Self {
            id: 0,
            kind,
            label: label.into(),
            address: None,
            view_id: None,
            properties: HashMap::default(),
            created_at: now,
            updated_at: now,
        }
    }

    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub const fn with_view(mut self, view_id: i64) -> Self {
        self.view_id = Some(view_id);
        self
    }

    pub fn set_property(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.properties.insert(key.into(), value);
    }
}

// ── Edge ─────────────────────────────────────────────────────────────────────

/// A persisted graph edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedEdge {
    pub id: i64,
    pub from_node: i64,
    pub to_node: i64,
    pub kind: EdgeKind,
    pub weight: f64,
    pub properties: HashMap<String, serde_json::Value>,
    pub created_at: i64,
}

impl PersistedEdge {
    #[must_use]
    pub fn new(from_node: i64, to_node: i64, kind: EdgeKind) -> Self {
        Self {
            id: 0,
            from_node,
            to_node,
            kind,
            weight: 1.0,
            properties: HashMap::default(),
            created_at: now_unix(),
        }
    }

    #[must_use]
    pub const fn with_weight(mut self, w: f64) -> Self {
        self.weight = w;
        self
    }

    pub fn set_property(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.properties.insert(key.into(), value);
    }
}

// ── NodeSerializer ────────────────────────────────────────────────────────────

/// Handles serialization of [`PersistedNode`] to/from `SQLite` row data.
pub struct NodeSerializer;

impl NodeSerializer {
    /// Serialize the properties map to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn serialize_properties(
        props: &HashMap<String, serde_json::Value>,
    ) -> PersistResult<String> {
        serde_json::to_string(props).map_err(|e| PersistError::Serialization(e.to_string()))
    }

    /// Deserialize a JSON string back to a properties map.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn deserialize_properties(json: &str) -> PersistResult<HashMap<String, serde_json::Value>> {
        if json.is_empty() || json == "null" {
            return Ok(HashMap::default());
        }
        serde_json::from_str(json).map_err(|e| PersistError::Serialization(e.to_string()))
    }

    /// Serialize a full node to a JSON string (for backup/export).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn to_json(node: &PersistedNode) -> PersistResult<String> {
        serde_json::to_string(node).map_err(|e| PersistError::Serialization(e.to_string()))
    }

    /// Deserialize a node from a JSON string (for restore/import).
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_json(json: &str) -> PersistResult<PersistedNode> {
        serde_json::from_str(json).map_err(|e| PersistError::Serialization(e.to_string()))
    }
}

// ── EdgeSerializer ────────────────────────────────────────────────────────────

/// Handles serialization of [`PersistedEdge`] to/from `SQLite` row data.
pub struct EdgeSerializer;

impl EdgeSerializer {
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn serialize_properties(
        props: &HashMap<String, serde_json::Value>,
    ) -> PersistResult<String> {
        serde_json::to_string(props).map_err(|e| PersistError::Serialization(e.to_string()))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn deserialize_properties(json: &str) -> PersistResult<HashMap<String, serde_json::Value>> {
        if json.is_empty() || json == "null" {
            return Ok(HashMap::default());
        }
        serde_json::from_str(json).map_err(|e| PersistError::Serialization(e.to_string()))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn to_json(edge: &PersistedEdge) -> PersistResult<String> {
        serde_json::to_string(edge).map_err(|e| PersistError::Serialization(e.to_string()))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_json(json: &str) -> PersistResult<PersistedEdge> {
        serde_json::from_str(json).map_err(|e| PersistError::Serialization(e.to_string()))
    }
}

// ── GraphMigration ────────────────────────────────────────────────────────────

/// Manages incremental schema migrations.
pub struct GraphMigration;

impl GraphMigration {
    /// Return the current schema version stored in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn current_version(conn: &Connection) -> PersistResult<u32> {
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(PersistError::Sqlite)?;
        Ok(v)
    }

    /// Apply all pending migrations up to [`CURRENT_SCHEMA_VERSION`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn migrate(conn: &mut Connection) -> PersistResult<()> {
        let current = Self::current_version(conn)?;
        if current == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }
        if current > CURRENT_SCHEMA_VERSION {
            return Err(PersistError::SchemaMismatch {
                expected: CURRENT_SCHEMA_VERSION,
                got: current,
            });
        }
        let tx = conn.transaction().map_err(PersistError::Sqlite)?;
        for version in (current + 1)..=CURRENT_SCHEMA_VERSION {
            Self::apply_migration(&tx, version)?;
        }
        tx.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)
            .map_err(|e| PersistError::MigrationFailed {
                version: CURRENT_SCHEMA_VERSION,
                message: e.to_string(),
            })?;
        tx.commit().map_err(PersistError::Sqlite)?;
        Ok(())
    }

    fn apply_migration(tx: &Transaction, version: u32) -> PersistResult<()> {
        match version {
            1 => tx
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS nodes (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind        TEXT    NOT NULL,
                        label       TEXT    NOT NULL,
                        address     INTEGER,
                        view_id     INTEGER,
                        properties  TEXT    NOT NULL DEFAULT '{}',
                        created_at  INTEGER NOT NULL,
                        updated_at  INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS edges (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        from_node   INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                        to_node     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                        kind        TEXT    NOT NULL,
                        weight      REAL    NOT NULL DEFAULT 1.0,
                        properties  TEXT    NOT NULL DEFAULT '{}',
                        created_at  INTEGER NOT NULL
                    );",
                )
                .map_err(|e| PersistError::MigrationFailed {
                    version,
                    message: e.to_string(),
                }),
            2 => tx
                .execute_batch(
                    "CREATE INDEX IF NOT EXISTS idx_nodes_kind    ON nodes(kind);
                     CREATE INDEX IF NOT EXISTS idx_nodes_address ON nodes(address);
                     CREATE INDEX IF NOT EXISTS idx_nodes_view    ON nodes(view_id);
                     CREATE INDEX IF NOT EXISTS idx_edges_from    ON edges(from_node);
                     CREATE INDEX IF NOT EXISTS idx_edges_to      ON edges(to_node);
                     CREATE INDEX IF NOT EXISTS idx_edges_kind    ON edges(kind);",
                )
                .map_err(|e| PersistError::MigrationFailed {
                    version,
                    message: e.to_string(),
                }),
            3 => tx
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS graph_meta (
                        key   TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );",
                )
                .map_err(|e| PersistError::MigrationFailed {
                    version,
                    message: e.to_string(),
                }),
            v => Err(PersistError::MigrationFailed {
                version: v,
                message: "unknown migration version".into(),
            }),
        }
    }
}

// ── GraphTransaction ──────────────────────────────────────────────────────────

/// A guard that batches multiple read/write operations inside a single `SQLite`
/// transaction.  Commit with [`GraphTransaction::commit`]; dropping without
/// committing automatically rolls back.
pub struct GraphTransaction<'a> {
    tx: Transaction<'a>,
    ops: usize,
}

impl<'a> GraphTransaction<'a> {
    #[must_use]
    pub const fn new(tx: Transaction<'a>) -> Self {
        Self { tx, ops: 0 }
    }

    /// Insert a node and return the assigned id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn insert_node(&mut self, node: &PersistedNode) -> PersistResult<i64> {
        let props = NodeSerializer::serialize_properties(&node.properties)?;
        self.tx
            .execute(
                "INSERT INTO nodes (kind, label, address, view_id, properties, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node.kind.as_str(),
                    node.label,
                    node.address.map(u64::cast_signed),
                    node.view_id,
                    props,
                    node.created_at,
                    node.updated_at,
                ],
            )
            .map_err(PersistError::Sqlite)?;
        self.ops += 1;
        Ok(self.tx.last_insert_rowid())
    }

    /// Insert an edge and return the assigned id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn insert_edge(&mut self, edge: &PersistedEdge) -> PersistResult<i64> {
        let props = EdgeSerializer::serialize_properties(&edge.properties)?;
        self.tx
            .execute(
                "INSERT INTO edges (from_node, to_node, kind, weight, properties, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    edge.from_node,
                    edge.to_node,
                    edge.kind.as_str(),
                    edge.weight,
                    props,
                    edge.created_at,
                ],
            )
            .map_err(PersistError::Sqlite)?;
        self.ops += 1;
        Ok(self.tx.last_insert_rowid())
    }

    /// Update an existing node's label and properties.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn update_node(
        &mut self,
        id: i64,
        label: &str,
        properties: &HashMap<String, serde_json::Value>,
    ) -> PersistResult<()> {
        let props = NodeSerializer::serialize_properties(properties)?;
        let now = now_unix();
        let affected = self
            .tx
            .execute(
                "UPDATE nodes SET label = ?1, properties = ?2, updated_at = ?3 WHERE id = ?4",
                params![label, props, now, id],
            )
            .map_err(PersistError::Sqlite)?;
        if affected == 0 {
            return Err(PersistError::NodeNotFound(id));
        }
        self.ops += 1;
        Ok(())
    }

    /// Delete a node by id (cascades to edges).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_node(&mut self, id: i64) -> PersistResult<()> {
        let affected = self
            .tx
            .execute("DELETE FROM nodes WHERE id = ?1", params![id])
            .map_err(PersistError::Sqlite)?;
        if affected == 0 {
            return Err(PersistError::NodeNotFound(id));
        }
        self.ops += 1;
        Ok(())
    }

    /// Delete an edge by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_edge(&mut self, id: i64) -> PersistResult<()> {
        let affected = self
            .tx
            .execute("DELETE FROM edges WHERE id = ?1", params![id])
            .map_err(PersistError::Sqlite)?;
        if affected == 0 {
            return Err(PersistError::EdgeNotFound(id));
        }
        self.ops += 1;
        Ok(())
    }

    /// Number of staged operations.
    #[must_use]
    pub const fn ops(&self) -> usize {
        self.ops
    }

    /// Commit the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn commit(self) -> PersistResult<()> {
        self.tx.commit().map_err(PersistError::Sqlite)
    }

    /// Roll back the transaction explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn rollback(self) -> PersistResult<()> {
        self.tx.rollback().map_err(PersistError::Sqlite)
    }
}

// ── GraphBackup ───────────────────────────────────────────────────────────────

/// Backup and restore utilities for the graph database.
pub struct GraphBackup {
    pub dest_dir: PathBuf,
}

impl GraphBackup {
    pub fn new(dest_dir: impl Into<PathBuf>) -> Self {
        Self {
            dest_dir: dest_dir.into(),
        }
    }

    /// Create a timestamped backup by exporting all nodes and edges to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn backup(&self, conn: &Connection) -> PersistResult<PathBuf> {
        let ts = now_unix();
        let filename = format!("graph_backup_{ts}.json");
        let dest = self.dest_dir.join(&filename);

        let nodes = GraphPersistence::list_nodes_raw(conn)?;
        let edges = GraphPersistence::list_edges_raw(conn)?;

        let payload = serde_json::json!({
            "version": CURRENT_SCHEMA_VERSION,
            "timestamp": ts,
            "nodes": nodes,
            "edges": edges,
        });

        let json = serde_json::to_string_pretty(&payload)
            .map_err(|e| PersistError::Backup(e.to_string()))?;
        std::fs::write(&dest, json).map_err(|e| PersistError::Backup(e.to_string()))?;
        Ok(dest)
    }

    /// Restore a previously created backup into an empty (or new) database.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn restore(
        &self,
        conn: &mut Connection,
        backup_path: &Path,
    ) -> PersistResult<(usize, usize)> {
        // Enforce a file-size cap before reading into memory to prevent
        // zip-bomb-like / oversized-backup denial of service.
        const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
        // Cap the number of entries to prevent DoS via a crafted JSON file with
        // millions of items that would still fit within the file-size limit due
        // to very short entries.
        const MAX_NODES: usize = 5_000_000;
        const MAX_EDGES: usize = 20_000_000;
        let meta = std::fs::metadata(backup_path)
            .map_err(|e| PersistError::Backup(e.to_string()))?;
        if meta.len() > MAX_BACKUP_BYTES {
            return Err(PersistError::Backup(format!(
                "backup file too large: {} bytes (limit {} bytes)",
                meta.len(),
                MAX_BACKUP_BYTES
            )));
        }
        let json = std::fs::read_to_string(backup_path)
            .map_err(|e| PersistError::Backup(e.to_string()))?;
        let payload: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| PersistError::Serialization(e.to_string()))?;

        GraphMigration::migrate(conn)?;

        let tx = conn.transaction().map_err(PersistError::Sqlite)?;
        let mut node_count = 0usize;
        let mut edge_count = 0usize;

        if let Some(nodes) = payload["nodes"].as_array() {
            if nodes.len() > MAX_NODES {
                return Err(PersistError::Backup(format!(
                    "backup contains too many nodes: {} (limit {})",
                    nodes.len(),
                    MAX_NODES
                )));
            }
            for n in nodes {
                let node: PersistedNode = serde_json::from_value(n.clone())
                    .map_err(|e| PersistError::Serialization(e.to_string()))?;
                let props = NodeSerializer::serialize_properties(&node.properties)?;
                tx.execute(
                    "INSERT OR REPLACE INTO nodes (id, kind, label, address, view_id, properties, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        node.id, node.kind.as_str(), node.label,
                        node.address.map(u64::cast_signed), node.view_id,
                        props, node.created_at, node.updated_at,
                    ],
                ).map_err(PersistError::Sqlite)?;
                node_count += 1;
            }
        }

        if let Some(edges) = payload["edges"].as_array() {
            if edges.len() > MAX_EDGES {
                return Err(PersistError::Backup(format!(
                    "backup contains too many edges: {} (limit {})",
                    edges.len(),
                    MAX_EDGES
                )));
            }
            for e in edges {
                let edge: PersistedEdge = serde_json::from_value(e.clone())
                    .map_err(|e| PersistError::Serialization(e.to_string()))?;
                let props = EdgeSerializer::serialize_properties(&edge.properties)?;
                tx.execute(
                    "INSERT OR REPLACE INTO edges (id, from_node, to_node, kind, weight, properties, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        edge.id, edge.from_node, edge.to_node,
                        edge.kind.as_str(), edge.weight, props, edge.created_at,
                    ],
                ).map_err(PersistError::Sqlite)?;
                edge_count += 1;
            }
        }

        tx.commit().map_err(PersistError::Sqlite)?;
        Ok((node_count, edge_count))
    }

    /// List available backups in the destination directory.
    #[must_use]
    pub fn list_backups(&self) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(&self.dest_dir) else {
            return Vec::new();
        };
        let mut result: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("graph_backup_"))
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .collect();
        result.sort();
        result
    }
}

// ── GraphPersistence ──────────────────────────────────────────────────────────

/// Primary SQLite-backed graph storage manager.
///
/// All operations are protected by an internal `Mutex<Connection>` so this
/// type is `Send + Sync`.
pub struct GraphPersistence {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

impl GraphPersistence {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Open (or create) a graph database at the given path.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn open(path: impl Into<PathBuf>) -> PersistResult<Self> {
        let db_path = path.into();
        let mut conn = Connection::open(&db_path).map_err(PersistError::Sqlite)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(PersistError::Sqlite)?;
        GraphMigration::migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path,
        })
    }

    /// Open an in-memory graph database (useful for tests).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn open_in_memory() -> PersistResult<Self> {
        let mut conn = Connection::open_in_memory().map_err(PersistError::Sqlite)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(PersistError::Sqlite)?;
        GraphMigration::migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_path: PathBuf::from(":memory:"),
        })
    }

    // ── Path ─────────────────────────────────────────────────────────────────

    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    // ── Node CRUD ─────────────────────────────────────────────────────────────

    /// Insert a node and return its assigned database id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn insert_node(&self, node: &PersistedNode) -> PersistResult<i64> {
        let conn = self.conn.lock();
        let props = NodeSerializer::serialize_properties(&node.properties)?;
        conn.execute(
            "INSERT INTO nodes (kind, label, address, view_id, properties, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                node.kind.as_str(),
                node.label,
                node.address.map(u64::cast_signed),
                node.view_id,
                props,
                node.created_at,
                node.updated_at,
            ],
        )
        .map_err(PersistError::Sqlite)?;
        Ok(conn.last_insert_rowid())
    }

    /// Retrieve a node by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_node(&self, id: i64) -> PersistResult<PersistedNode> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, kind, label, address, view_id, properties, created_at, updated_at
             FROM nodes WHERE id = ?1",
            params![id],
            Self::row_to_node,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => PersistError::NodeNotFound(id),
            other => PersistError::Sqlite(other),
        })
    }

    /// Update an existing node.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn update_node(
        &self,
        id: i64,
        label: &str,
        properties: &HashMap<String, serde_json::Value>,
    ) -> PersistResult<()> {
        let props = NodeSerializer::serialize_properties(properties)?;
        let now = now_unix();
        let affected = self.conn.lock()
            .execute(
                "UPDATE nodes SET label = ?1, properties = ?2, updated_at = ?3 WHERE id = ?4",
                params![label, props, now, id],
            )
            .map_err(PersistError::Sqlite)?;
        if affected == 0 {
            return Err(PersistError::NodeNotFound(id));
        }
        Ok(())
    }

    /// Delete a node (cascades to edges).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_node(&self, id: i64) -> PersistResult<()> {
        let affected = self.conn.lock()
            .execute("DELETE FROM nodes WHERE id = ?1", params![id])
            .map_err(PersistError::Sqlite)?;
        if affected == 0 {
            return Err(PersistError::NodeNotFound(id));
        }
        Ok(())
    }

    /// List all nodes, optionally filtered by kind.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn list_nodes(&self, kind: Option<&NodeKind>) -> PersistResult<Vec<PersistedNode>> {
        if let Some(k) = kind {
            let conn = self.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, kind, label, address, view_id, properties, created_at, updated_at
                     FROM nodes WHERE kind = ?1 ORDER BY id",
                )
                .map_err(PersistError::Sqlite)?;
            let rows = stmt
                .query_map(params![k.as_str()], Self::row_to_node)
                .map_err(PersistError::Sqlite)?;
            rows.collect::<SqlResult<Vec<_>>>()
                .map_err(PersistError::Sqlite)
        } else {
            let conn = self.conn.lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, kind, label, address, view_id, properties, created_at, updated_at
                     FROM nodes ORDER BY id",
                )
                .map_err(PersistError::Sqlite)?;
            let rows = stmt
                .query_map([], Self::row_to_node)
                .map_err(PersistError::Sqlite)?;
            rows.collect::<SqlResult<Vec<_>>>()
                .map_err(PersistError::Sqlite)
        }
    }

    /// Find nodes by address.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn find_nodes_by_address(&self, address: u64) -> PersistResult<Vec<PersistedNode>> {
        let addr_i = address.cast_signed();
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, label, address, view_id, properties, created_at, updated_at
                 FROM nodes WHERE address = ?1 ORDER BY id",
            )
            .map_err(PersistError::Sqlite)?;
        let rows = stmt
            .query_map(params![addr_i], Self::row_to_node)
            .map_err(PersistError::Sqlite)?;
        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(PersistError::Sqlite)
    }

    // ── Edge CRUD ─────────────────────────────────────────────────────────────

    /// Insert an edge and return its assigned database id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn insert_edge(&self, edge: &PersistedEdge) -> PersistResult<i64> {
        let conn = self.conn.lock();
        let props = EdgeSerializer::serialize_properties(&edge.properties)?;
        conn.execute(
            "INSERT INTO edges (from_node, to_node, kind, weight, properties, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                edge.from_node,
                edge.to_node,
                edge.kind.as_str(),
                edge.weight,
                props,
                edge.created_at,
            ],
        )
        .map_err(PersistError::Sqlite)?;
        Ok(conn.last_insert_rowid())
    }

    /// Retrieve an edge by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_edge(&self, id: i64) -> PersistResult<PersistedEdge> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, from_node, to_node, kind, weight, properties, created_at
             FROM edges WHERE id = ?1",
            params![id],
            Self::row_to_edge,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => PersistError::EdgeNotFound(id),
            other => PersistError::Sqlite(other),
        })
    }

    /// Delete an edge by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_edge(&self, id: i64) -> PersistResult<()> {
        let affected = self.conn.lock()
            .execute("DELETE FROM edges WHERE id = ?1", params![id])
            .map_err(PersistError::Sqlite)?;
        if affected == 0 {
            return Err(PersistError::EdgeNotFound(id));
        }
        Ok(())
    }

    /// List edges from or to a given node.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn edges_for_node(&self, node_id: i64) -> PersistResult<Vec<PersistedEdge>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, from_node, to_node, kind, weight, properties, created_at
                 FROM edges WHERE from_node = ?1 OR to_node = ?1 ORDER BY id",
            )
            .map_err(PersistError::Sqlite)?;
        let rows = stmt
            .query_map(params![node_id], Self::row_to_edge)
            .map_err(PersistError::Sqlite)?;
        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(PersistError::Sqlite)
    }

    /// List edges of a specific kind.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn list_edges_by_kind(&self, kind: &EdgeKind) -> PersistResult<Vec<PersistedEdge>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, from_node, to_node, kind, weight, properties, created_at
                 FROM edges WHERE kind = ?1 ORDER BY id",
            )
            .map_err(PersistError::Sqlite)?;
        let rows = stmt
            .query_map(params![kind.as_str()], Self::row_to_edge)
            .map_err(PersistError::Sqlite)?;
        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(PersistError::Sqlite)
    }

    // ── Transaction helper ────────────────────────────────────────────────────

    /// Execute a closure inside a [`GraphTransaction`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn with_transaction<F, R>(&self, f: F) -> PersistResult<R>
    where
        F: FnOnce(&mut GraphTransaction) -> PersistResult<R>,
    {
        let mut conn = self.conn.lock();
        let tx_inner = conn.transaction().map_err(PersistError::Sqlite)?;
        let mut gtx = GraphTransaction::new(tx_inner);
        let result = f(&mut gtx)?;
        gtx.commit()?;
        Ok(result)
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// Set a metadata key/value pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn set_meta(&self, key: &str, value: &str) -> PersistResult<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO graph_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map_err(PersistError::Sqlite)?;
        Ok(())
    }

    /// Get a metadata value by key.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_meta(&self, key: &str) -> PersistResult<Option<String>> {
        match self.conn.lock().query_row(
            "SELECT value FROM graph_meta WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PersistError::Sqlite(e)),
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Return (`node_count`, `edge_count`).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn stats(&self) -> PersistResult<(u64, u64)> {
        let nodes: i64 = {
            let conn = self.conn.lock();
            conn.query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
                .map_err(PersistError::Sqlite)?
        };
        let edges: i64 = {
            let conn = self.conn.lock();
            conn.query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))
                .map_err(PersistError::Sqlite)?
        };
        Ok((nodes.cast_unsigned(), edges.cast_unsigned()))
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn row_to_node(row: &rusqlite::Row) -> SqlResult<PersistedNode> {
        let kind_str: String = row.get(1)?;
        let props_str: String = row.get(5)?;
        let addr_raw: Option<i64> = row.get(3)?;
        Ok(PersistedNode {
            id: row.get(0)?,
            kind: NodeKind::from_kind_str(&kind_str),
            label: row.get(2)?,
            address: addr_raw.map(i64::cast_unsigned),
            view_id: row.get(4)?,
            properties: serde_json::from_str(&props_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
            })?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }

    fn row_to_edge(row: &rusqlite::Row) -> SqlResult<PersistedEdge> {
        let kind_str: String = row.get(3)?;
        let props_str: String = row.get(5)?;
        Ok(PersistedEdge {
            id: row.get(0)?,
            from_node: row.get(1)?,
            to_node: row.get(2)?,
            kind: EdgeKind::from_kind_str(&kind_str),
            weight: row.get(4)?,
            properties: serde_json::from_str(&props_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?,
            created_at: row.get(6)?,
        })
    }

    fn list_nodes_raw(conn: &Connection) -> PersistResult<Vec<PersistedNode>> {
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, label, address, view_id, properties, created_at, updated_at
                 FROM nodes ORDER BY id",
            )
            .map_err(PersistError::Sqlite)?;
        let rows = stmt
            .query_map([], Self::row_to_node)
            .map_err(PersistError::Sqlite)?;
        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(PersistError::Sqlite)
    }

    fn list_edges_raw(conn: &Connection) -> PersistResult<Vec<PersistedEdge>> {
        let mut stmt = conn
            .prepare(
                "SELECT id, from_node, to_node, kind, weight, properties, created_at
                 FROM edges ORDER BY id",
            )
            .map_err(PersistError::Sqlite)?;
        let rows = stmt
            .query_map([], Self::row_to_edge)
            .map_err(PersistError::Sqlite)?;
        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(PersistError::Sqlite)
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs().cast_signed(),
        Err(e) => -(e.duration().as_secs().cast_signed()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gp() -> GraphPersistence {
        GraphPersistence::open_in_memory().unwrap()
    }

    // ── schema ────────────────────────────────────────────────────────────────

    #[test]
    fn test_schema_version_correct() {
        let gp = gp();
        let conn = gp.conn.lock();
        let v = GraphMigration::current_version(&conn).unwrap();
        assert_eq!(v, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn test_open_in_memory() {
        let gp = gp();
        assert_eq!(gp.db_path().to_string_lossy(), ":memory:");
    }

    // ── node serializer ───────────────────────────────────────────────────────

    #[test]
    fn test_node_serializer_empty_props() {
        let props = HashMap::default();
        let json = NodeSerializer::serialize_properties(&props).unwrap();
        let back = NodeSerializer::deserialize_properties(&json).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn test_node_serializer_with_props() {
        let mut props = HashMap::default();
        props.insert("key".into(), serde_json::json!("value"));
        let json = NodeSerializer::serialize_properties(&props).unwrap();
        let back = NodeSerializer::deserialize_properties(&json).unwrap();
        assert_eq!(back["key"], serde_json::json!("value"));
    }

    #[test]
    fn test_node_serializer_empty_string() {
        let back = NodeSerializer::deserialize_properties("").unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn test_node_round_trip_json() {
        let node = PersistedNode::new(NodeKind::Function, "test_func");
        let json = NodeSerializer::to_json(&node).unwrap();
        let back = NodeSerializer::from_json(&json).unwrap();
        assert_eq!(back.label, "test_func");
    }

    // ── edge serializer ───────────────────────────────────────────────────────

    #[test]
    fn test_edge_serializer_round_trip() {
        let mut edge = PersistedEdge::new(1, 2, EdgeKind::Call);
        edge.set_property("inline", serde_json::json!(true));
        let json = EdgeSerializer::to_json(&edge).unwrap();
        let back = EdgeSerializer::from_json(&json).unwrap();
        assert_eq!(back.from_node, 1);
        assert_eq!(back.to_node, 2);
        assert_eq!(back.properties["inline"], serde_json::json!(true));
    }

    // ── node CRUD ─────────────────────────────────────────────────────────────

    #[test]
    fn test_insert_and_get_node() {
        let gp = gp();
        let node = PersistedNode::new(NodeKind::Function, "main");
        let id = gp.insert_node(&node).unwrap();
        assert!(id > 0);
        let fetched = gp.get_node(id).unwrap();
        assert_eq!(fetched.label, "main");
        assert_eq!(fetched.kind, NodeKind::Function);
    }

    #[test]
    fn test_get_node_not_found() {
        let gp = gp();
        let res = gp.get_node(9999);
        assert!(matches!(res, Err(PersistError::NodeNotFound(9999))));
    }

    #[test]
    fn test_update_node() {
        let gp = gp();
        let node = PersistedNode::new(NodeKind::Function, "old_name");
        let id = gp.insert_node(&node).unwrap();
        let mut props = HashMap::default();
        props.insert("updated".into(), serde_json::json!(true));
        gp.update_node(id, "new_name", &props).unwrap();
        let fetched = gp.get_node(id).unwrap();
        assert_eq!(fetched.label, "new_name");
        assert_eq!(fetched.properties["updated"], serde_json::json!(true));
    }

    #[test]
    fn test_delete_node() {
        let gp = gp();
        let node = PersistedNode::new(NodeKind::Symbol, "sym");
        let id = gp.insert_node(&node).unwrap();
        gp.delete_node(id).unwrap();
        assert!(matches!(
            gp.get_node(id),
            Err(PersistError::NodeNotFound(_))
        ));
    }

    #[test]
    fn test_delete_node_not_found() {
        let gp = gp();
        let res = gp.delete_node(42);
        assert!(matches!(res, Err(PersistError::NodeNotFound(42))));
    }

    #[test]
    fn test_list_nodes_empty() {
        let gp = gp();
        let nodes = gp.list_nodes(None).unwrap();
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_list_nodes_by_kind() {
        let gp = gp();
        gp.insert_node(&PersistedNode::new(NodeKind::Function, "f1"))
            .unwrap();
        gp.insert_node(&PersistedNode::new(NodeKind::Function, "f2"))
            .unwrap();
        gp.insert_node(&PersistedNode::new(NodeKind::Symbol, "s1"))
            .unwrap();
        let fns = gp.list_nodes(Some(&NodeKind::Function)).unwrap();
        assert_eq!(fns.len(), 2);
        let syms = gp.list_nodes(Some(&NodeKind::Symbol)).unwrap();
        assert_eq!(syms.len(), 1);
    }

    #[test]
    fn test_find_nodes_by_address() {
        let gp = gp();
        let node = PersistedNode::new(NodeKind::Function, "addr_func").with_address(0x1000);
        gp.insert_node(&node).unwrap();
        let found = gp.find_nodes_by_address(0x1000).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, Some(0x1000));
    }

    #[test]
    fn test_node_address_not_found() {
        let gp = gp();
        let found = gp.find_nodes_by_address(0xdead_beef).unwrap();
        assert!(found.is_empty());
    }

    // ── edge CRUD ─────────────────────────────────────────────────────────────

    #[test]
    fn test_insert_and_get_edge() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        let edge = PersistedEdge::new(n1, n2, EdgeKind::Call);
        let eid = gp.insert_edge(&edge).unwrap();
        let fetched = gp.get_edge(eid).unwrap();
        assert_eq!(fetched.from_node, n1);
        assert_eq!(fetched.to_node, n2);
        assert_eq!(fetched.kind, EdgeKind::Call);
    }

    #[test]
    fn test_get_edge_not_found() {
        let gp = gp();
        assert!(matches!(
            gp.get_edge(777),
            Err(PersistError::EdgeNotFound(777))
        ));
    }

    #[test]
    fn test_delete_edge() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        let eid = gp
            .insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::DataFlow))
            .unwrap();
        gp.delete_edge(eid).unwrap();
        assert!(matches!(
            gp.get_edge(eid),
            Err(PersistError::EdgeNotFound(_))
        ));
    }

    #[test]
    fn test_edges_cascade_on_node_delete() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        let eid = gp
            .insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::Call))
            .unwrap();
        gp.delete_node(n1).unwrap();
        assert!(matches!(
            gp.get_edge(eid),
            Err(PersistError::EdgeNotFound(_))
        ));
    }

    #[test]
    fn test_edges_for_node() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        let n3 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "c"))
            .unwrap();
        gp.insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::Call))
            .unwrap();
        gp.insert_edge(&PersistedEdge::new(n3, n1, EdgeKind::Call))
            .unwrap();
        let edges = gp.edges_for_node(n1).unwrap();
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn test_list_edges_by_kind() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        gp.insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::Call))
            .unwrap();
        gp.insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::DataFlow))
            .unwrap();
        let calls = gp.list_edges_by_kind(&EdgeKind::Call).unwrap();
        assert_eq!(calls.len(), 1);
    }

    // ── transaction ───────────────────────────────────────────────────────────

    #[test]
    fn test_transaction_commit() {
        let gp = gp();
        let (id1, id2) = gp
            .with_transaction(|tx| {
                let n1 = tx.insert_node(&PersistedNode::new(NodeKind::Function, "tx1"))?;
                let n2 = tx.insert_node(&PersistedNode::new(NodeKind::Function, "tx2"))?;
                Ok((n1, n2))
            })
            .unwrap();
        assert!(gp.get_node(id1).is_ok());
        assert!(gp.get_node(id2).is_ok());
    }

    #[test]
    fn test_transaction_op_count() {
        let gp = gp();
        gp.with_transaction(|tx| {
            tx.insert_node(&PersistedNode::new(NodeKind::Function, "x"))?;
            tx.insert_node(&PersistedNode::new(NodeKind::Symbol, "y"))?;
            assert_eq!(tx.ops(), 2);
            Ok(())
        })
        .unwrap();
    }

    // ── metadata ──────────────────────────────────────────────────────────────

    #[test]
    fn test_metadata_set_get() {
        let gp = gp();
        gp.set_meta("project", "rustre").unwrap();
        let val = gp.get_meta("project").unwrap();
        assert_eq!(val, Some("rustre".to_owned()));
    }

    #[test]
    fn test_metadata_missing_key() {
        let gp = gp();
        let val = gp.get_meta("nonexistent").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn test_metadata_overwrite() {
        let gp = gp();
        gp.set_meta("k", "v1").unwrap();
        gp.set_meta("k", "v2").unwrap();
        assert_eq!(gp.get_meta("k").unwrap(), Some("v2".to_owned()));
    }

    // ── stats ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_empty() {
        let gp = gp();
        let (nodes, edges) = gp.stats().unwrap();
        assert_eq!(nodes, 0);
        assert_eq!(edges, 0);
    }

    #[test]
    fn test_stats_after_inserts() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        gp.insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::Call))
            .unwrap();
        let (nodes, edges) = gp.stats().unwrap();
        assert_eq!(nodes, 2);
        assert_eq!(edges, 1);
    }

    // ── node kind helpers ─────────────────────────────────────────────────────

    #[test]
    fn test_node_kind_round_trip() {
        for k in [
            NodeKind::Function,
            NodeKind::BasicBlock,
            NodeKind::Variable,
            NodeKind::Type,
            NodeKind::Symbol,
            NodeKind::Module,
            NodeKind::Class,
            NodeKind::Custom("foo".into()),
        ] {
            assert_eq!(NodeKind::from_kind_str(k.as_str()), k);
        }
    }

    #[test]
    fn test_edge_kind_round_trip() {
        for k in [
            EdgeKind::Call,
            EdgeKind::DataFlow,
            EdgeKind::Control,
            EdgeKind::Type,
            EdgeKind::Contains,
            EdgeKind::Reference,
            EdgeKind::Custom("bar".into()),
        ] {
            assert_eq!(EdgeKind::from_kind_str(k.as_str()), k);
        }
    }

    // ── builder helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_node_builder_with_address_and_view() {
        let node = PersistedNode::new(NodeKind::Function, "f")
            .with_address(0x4000)
            .with_view(7);
        assert_eq!(node.address, Some(0x4000));
        assert_eq!(node.view_id, Some(7));
    }

    #[test]
    fn test_edge_builder_with_weight() {
        let edge = PersistedEdge::new(1, 2, EdgeKind::DataFlow).with_weight(std::f64::consts::PI);
        assert!((edge.weight - std::f64::consts::PI).abs() < 1e-9);
    }

    // ── backup (in-memory dir) ────────────────────────────────────────────────

    #[test]
    fn test_backup_list_empty_dir() {
        let tmp = std::env::temp_dir().join("rustre_gp_test_backup_empty");
        let _ = std::fs::create_dir_all(&tmp);
        let backup = GraphBackup::new(&tmp);
        // Only graph_backup_ files count — any stray file is ignored.
        for path in backup.list_backups() {
            assert!(
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("graph_backup_")
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_backup_and_restore() {
        let tmp = std::env::temp_dir().join("rustre_gp_test_backup_restore");
        let _ = std::fs::create_dir_all(&tmp);

        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "backup_fn"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Symbol, "backup_sym"))
            .unwrap();
        gp.insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::Reference))
            .unwrap();

        let backup = GraphBackup::new(&tmp);
        let path = backup.backup(&gp.conn.lock()).unwrap();
        assert!(path.exists());

        // Restore into a fresh DB.
        let mut conn2 = rusqlite::Connection::open_in_memory().unwrap();
        conn2.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let (nc, ec) = backup.restore(&mut conn2, &path).unwrap();
        assert_eq!(nc, 2);
        assert_eq!(ec, 1);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── edge with properties ──────────────────────────────────────────────────

    #[test]
    fn test_edge_with_custom_properties() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        let mut edge = PersistedEdge::new(n1, n2, EdgeKind::Call);
        edge.set_property("call_site", serde_json::json!(0xdead_c0de_u64));
        let eid = gp.insert_edge(&edge).unwrap();
        let fetched = gp.get_edge(eid).unwrap();
        assert!(fetched.properties.contains_key("call_site"));
    }

    #[test]
    fn test_node_with_custom_properties() {
        let gp = gp();
        let mut node = PersistedNode::new(NodeKind::Function, "props_fn");
        node.set_property("size", serde_json::json!(128));
        node.set_property("is_entry", serde_json::json!(true));
        let id = gp.insert_node(&node).unwrap();
        let fetched = gp.get_node(id).unwrap();
        assert_eq!(fetched.properties["size"], serde_json::json!(128));
        assert_eq!(fetched.properties["is_entry"], serde_json::json!(true));
    }

    #[test]
    fn test_list_all_nodes_no_filter() {
        let gp = gp();
        gp.insert_node(&PersistedNode::new(NodeKind::Function, "f"))
            .unwrap();
        gp.insert_node(&PersistedNode::new(NodeKind::Symbol, "s"))
            .unwrap();
        let all = gp.list_nodes(None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_multiple_view_ids() {
        let gp = gp();
        gp.insert_node(&PersistedNode::new(NodeKind::Function, "f1").with_view(1))
            .unwrap();
        gp.insert_node(&PersistedNode::new(NodeKind::Function, "f2").with_view(2))
            .unwrap();
        let view1: Vec<_> = gp
            .list_nodes(None)
            .unwrap()
            .into_iter()
            .filter(|n| n.view_id == Some(1))
            .collect();
        assert_eq!(view1.len(), 1);
    }

    #[test]
    fn test_edge_default_weight() {
        let edge = PersistedEdge::new(1, 2, EdgeKind::Call);
        assert!((edge.weight - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_transaction_update_node() {
        let gp = gp();
        let id = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "orig"))
            .unwrap();
        gp.with_transaction(|tx| {
            let mut props = HashMap::default();
            props.insert("updated".to_string(), serde_json::json!(true));
            tx.update_node(id, "updated_name", &props)
        })
        .unwrap();
        let fetched = gp.get_node(id).unwrap();
        assert_eq!(fetched.label, "updated_name");
    }

    #[test]
    fn test_transaction_delete_edge() {
        let gp = gp();
        let n1 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "a"))
            .unwrap();
        let n2 = gp
            .insert_node(&PersistedNode::new(NodeKind::Function, "b"))
            .unwrap();
        let eid = gp
            .insert_edge(&PersistedEdge::new(n1, n2, EdgeKind::Call))
            .unwrap();
        gp.with_transaction(|tx| tx.delete_edge(eid)).unwrap();
        assert!(matches!(
            gp.get_edge(eid),
            Err(PersistError::EdgeNotFound(_))
        ));
    }

    #[test]
    fn test_now_unix_positive() {
        assert!(now_unix() > 0);
    }

    #[test]
    fn test_node_created_at_set() {
        let node = PersistedNode::new(NodeKind::Function, "f");
        assert!(node.created_at > 0);
    }

    #[test]
    fn test_edge_created_at_set() {
        let edge = PersistedEdge::new(1, 2, EdgeKind::Call);
        assert!(edge.created_at > 0);
    }
}
