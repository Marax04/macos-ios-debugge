//! `db_index_manager` — Database index management for `SQLite`.
//!
//! Provides [`DbIndexManager`], [`IndexDef`], [`IndexKind`], and
//! the primary entry point [`create_index`].

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by index management operations.
#[derive(Debug, Error)]
pub enum IndexError {
    /// A SQL execution error.
    #[error("sql error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// The index name is invalid.
    #[error("invalid index name: '{0}'")]
    InvalidName(String),
    /// The table referenced does not exist.
    #[error("table not found: '{0}'")]
    TableNotFound(String),
    /// An index with this name already exists.
    #[error("index already exists: '{0}'")]
    AlreadyExists(String),
    /// The index definition specifies no columns.
    #[error("index '{0}' has no columns")]
    NoColumns(String),
    /// A partial index filter expression is malformed.
    #[error("malformed partial index expression: '{0}'")]
    MalformedExpression(String),
    /// Any other error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// IndexKind
// ---------------------------------------------------------------------------

/// The kind of an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndexKind {
    /// Standard non-unique index.
    Standard,
    /// Unique index — enforces uniqueness constraint.
    Unique,
    /// Partial index — only indexes rows satisfying a WHERE condition.
    Partial,
    /// Covering index — includes extra columns not in the key for performance.
    Covering,
}

impl IndexKind {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Unique => "unique",
            Self::Partial => "partial",
            Self::Covering => "covering",
        }
    }

    /// Returns `true` if this kind is unique.
    #[must_use]
    pub const fn is_unique(self) -> bool {
        matches!(self, Self::Unique)
    }

    /// Returns `true` if this kind supports a WHERE filter expression.
    #[must_use]
    pub const fn supports_filter(self) -> bool {
        matches!(self, Self::Partial)
    }
}

impl fmt::Display for IndexKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// IndexDef
// ---------------------------------------------------------------------------

/// Definition of a database index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDef {
    /// Name of the index (must be unique in the database).
    pub name: String,
    /// Table the index is on.
    pub table: String,
    /// Columns included in the index key, in key order.
    pub columns: Vec<String>,
    /// Kind of index.
    pub kind: IndexKind,
    /// Optional WHERE expression for partial indexes.
    pub filter: Option<String>,
    /// Extra non-key columns for covering indexes (INCLUDE clause).
    /// Note: `SQLite` does not support INCLUDE; this is informational only.
    pub include_columns: Vec<String>,
}

impl IndexDef {
    /// Create a new standard index.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        table: impl Into<String>,
        columns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            table: table.into(),
            columns: columns.into_iter().map(Into::into).collect(),
            kind: IndexKind::Standard,
            filter: None,
            include_columns: Vec::new(),
        }
    }

    /// Create a unique index.
    #[must_use]
    pub fn unique(
        name: impl Into<String>,
        table: impl Into<String>,
        columns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self { kind: IndexKind::Unique, ..Self::new(name, table, columns) }
    }

    /// Create a partial index with a WHERE filter expression.
    #[must_use]
    pub fn partial(
        name: impl Into<String>,
        table: impl Into<String>,
        columns: impl IntoIterator<Item = impl Into<String>>,
        filter: impl Into<String>,
    ) -> Self {
        Self {
            kind: IndexKind::Partial,
            filter: Some(filter.into()),
            ..Self::new(name, table, columns)
        }
    }

    /// Set the index kind.
    #[must_use]
    pub const fn with_kind(mut self, kind: IndexKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the partial index filter expression.
    #[must_use]
    pub fn with_filter(mut self, expr: impl Into<String>) -> Self {
        self.filter = Some(expr.into());
        self
    }

    /// Generate the `CREATE INDEX` SQL for this definition.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::NoColumns`] if `columns` is empty, or
    /// [`IndexError::InvalidName`] if `name` is empty.
    pub fn to_sql(&self) -> Result<String, IndexError> {
        if self.name.is_empty() {
            return Err(IndexError::InvalidName(self.name.clone()));
        }
        if self.columns.is_empty() {
            return Err(IndexError::NoColumns(self.name.clone()));
        }
        let unique_kw = if self.kind.is_unique() { "UNIQUE " } else { "" };
        let col_list = self.columns.join(", ");
        let mut sql = format!(
            "CREATE {}INDEX IF NOT EXISTS {} ON {} ({})",
            unique_kw, self.name, self.table, col_list
        );
        if let Some(filter) = &self.filter {
            use std::fmt::Write as _;
            let _ = write!(sql, " WHERE {filter}");
        }
        Ok(sql)
    }

    /// Generate the `DROP INDEX` SQL.
    #[must_use]
    pub fn drop_sql(&self) -> String {
        format!("DROP INDEX IF EXISTS {}", self.name)
    }

    /// Column count.
    #[must_use]
    pub const fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Returns `true` if this is a composite (multi-column) index.
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        self.columns.len() > 1
    }
}

impl fmt::Display for IndexDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IndexDef[{}] on {}.({}) [{}]",
            self.name,
            self.table,
            self.columns.join(", "),
            self.kind
        )
    }
}

// ---------------------------------------------------------------------------
// IndexInfo
// ---------------------------------------------------------------------------

/// Runtime information about an existing database index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    /// Index name.
    pub name: String,
    /// Table the index is on.
    pub table: String,
    /// Whether the index is unique.
    pub unique: bool,
    /// Columns in the index.
    pub columns: Vec<String>,
    /// Whether the index was created manually (not auto-generated by `SQLite`).
    pub user_created: bool,
}

// ---------------------------------------------------------------------------
// DbIndexManager
// ---------------------------------------------------------------------------

/// Manages creation, introspection, and deletion of database indexes.
pub struct DbIndexManager {
    conn: Arc<Mutex<Connection>>,
    /// Definitions known to this manager (tracked locally).
    known: HashMap<String, IndexDef>,
}

impl DbIndexManager {
    /// Create a new index manager.
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn, known: HashMap::new() }
    }

    /// Register an index definition without creating it.
    pub fn register(&mut self, def: IndexDef) {
        self.known.insert(def.name.clone(), def);
    }

    /// Create an index in the database from an [`IndexDef`].
    ///
    /// # Errors
    ///
    /// Returns [`IndexError`] if the SQL generation or execution fails.
    pub fn create(&self, def: &IndexDef) -> Result<(), IndexError> {
        let sql = def.to_sql()?;
        self.conn.lock().execute_batch(&sql)?;
        Ok(())
    }

    /// Create an index only if no index with the same name already exists.
    ///
    /// Returns `true` if the index was newly created, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError`] if the SQL execution fails.
    pub fn create_if_missing(&self, def: &IndexDef) -> Result<bool, IndexError> {
        if self.index_exists(&def.name)? {
            return Ok(false);
        }
        self.create(def)?;
        Ok(true)
    }

    /// Drop an index by name.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Sql`] on database errors.
    pub fn drop(&self, name: &str) -> Result<(), IndexError> {
        let sql = format!("DROP INDEX IF EXISTS {name}");
        self.conn.lock().execute_batch(&sql)?;
        Ok(())
    }

    /// Rebuild (drop and re-create) an index.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError`] if either the drop or create fails.
    pub fn rebuild(&self, def: &IndexDef) -> Result<(), IndexError> {
        self.drop(&def.name)?;
        self.create(def)?;
        Ok(())
    }

    /// Check whether a named index exists in the database.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Sql`] on database errors.
    pub fn index_exists(&self, name: &str) -> Result<bool, IndexError> {
        let count: i64 = self.conn.lock().query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
            params![name],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// List all user-visible indexes in the database.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Sql`] on database errors.
    pub fn list_all(&self) -> Result<Vec<IndexInfo>, IndexError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
        )?;
        let infos: Result<Vec<IndexInfo>, rusqlite::Error> = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let table: String = row.get(1)?;
                Ok(IndexInfo {
                    name,
                    table,
                    unique: false, // SQLite doesn't expose this easily without PRAGMA
                    columns: Vec::new(),
                    user_created: true,
                })
            })?
            .collect();
        drop(stmt);
        drop(conn);
        Ok(infos?)
    }

    /// Get detailed info about an index using `PRAGMA index_info`.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Sql`] on database errors, or
    /// [`IndexError::InvalidName`] if `name` contains characters that could
    /// alter the PRAGMA statement.
    pub fn inspect(&self, name: &str) -> Result<Option<IndexInfo>, IndexError> {
        // Guard: PRAGMA does not support bound parameters, so we validate that
        // the name contains only safe identifier characters before interpolating.
        if name.contains(['\'', '"', ';', ')', '(', '\0', '\n', '\r']) {
            return Err(IndexError::InvalidName(name.to_string()));
        }
        if !self.index_exists(name)? {
            return Ok(None);
        }
        let conn = self.conn.lock();
        // Get table name via a parameterised query (safe).
        let table: String = conn.query_row(
            "SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?1",
            params![name],
            |row| row.get(0),
        )?;
        // Validate table name before interpolating into PRAGMA.
        if table.contains(['\'', '"', ';', ')', '(', '\0', '\n', '\r']) {
            return Err(IndexError::InvalidName(table));
        }
        let mut stmt = conn.prepare(&format!("PRAGMA index_info({name})"))?;
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(2))?
            .filter_map(std::result::Result::ok)
            .collect();
        drop(stmt);
        // Check uniqueness via index_list
        let mut uq_stmt = conn.prepare(&format!("PRAGMA index_list({table})"))?;
        let unique = uq_stmt
            .query_map([], |row| {
                let n: String = row.get(1)?;
                let u: i64 = row.get(2)?;
                Ok((n, u))
            })?
            .filter_map(std::result::Result::ok)
            .find(|(n, _)| n == name)
            .is_some_and(|(_, u)| u != 0);
        drop(uq_stmt);
        drop(conn);
        Ok(Some(IndexInfo {
            name: name.to_string(),
            table,
            unique,
            columns,
            user_created: true,
        }))
    }

    /// Create all registered index definitions at once.
    ///
    /// # Errors
    ///
    /// Returns the first [`IndexError`] encountered.
    pub fn create_all_registered(&self) -> Result<usize, IndexError> {
        let defs: Vec<IndexDef> = self.known.values().cloned().collect();
        let mut count = 0;
        for def in &defs {
            self.create(def)?;
            count += 1;
        }
        Ok(count)
    }

    /// Drop all registered index definitions.
    ///
    /// # Errors
    ///
    /// Returns the first [`IndexError`] encountered.
    pub fn drop_all_registered(&self) -> Result<usize, IndexError> {
        let names: Vec<String> = self.known.keys().cloned().collect();
        let mut count = 0;
        for name in &names {
            self.drop(name)?;
            count += 1;
        }
        Ok(count)
    }

    /// Number of registered index definitions.
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.known.len()
    }

    /// Analyse the given table to update `SQLite` query planner statistics.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::Sql`] on database errors, or
    /// [`IndexError::InvalidName`] if `table` contains characters that could
    /// alter the ANALYZE statement.
    pub fn analyse_table(&self, table: &str) -> Result<(), IndexError> {
        // ANALYZE does not support bound parameters; validate the table name
        // before interpolating it into the SQL statement.
        if table.is_empty() || table.contains(['\'', '"', ';', ')', '(', '\0', '\n', '\r', ' ']) {
            return Err(IndexError::InvalidName(table.to_string()));
        }
        self.conn.lock().execute_batch(&format!("ANALYZE {table}"))?;
        Ok(())
    }
}

impl fmt::Debug for DbIndexManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DbIndexManager(registered={})", self.known.len())
    }
}

// ---------------------------------------------------------------------------
// create_index — primary entry point
// ---------------------------------------------------------------------------

/// Create a single index on the given connection.
///
/// This is the primary one-shot entry point for simple index creation.
///
/// # Errors
///
/// Returns [`IndexError`] if the SQL generation or execution fails.
pub fn create_index(
    conn: Arc<Mutex<Connection>>,
    def: &IndexDef,
) -> Result<(), IndexError> {
    let manager = DbIndexManager::new(conn);
    manager.create(def)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn open_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE functions (id INTEGER PRIMARY KEY, name TEXT, address INTEGER, kind TEXT);
             CREATE TABLE symbols (id INTEGER PRIMARY KEY, sym TEXT, func_id INTEGER);"
        ).unwrap();
        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn test_index_kind_names() {
        assert_eq!(IndexKind::Standard.name(), "standard");
        assert_eq!(IndexKind::Unique.name(), "unique");
        assert_eq!(IndexKind::Partial.name(), "partial");
        assert_eq!(IndexKind::Covering.name(), "covering");
    }

    #[test]
    fn test_index_kind_unique() {
        assert!(IndexKind::Unique.is_unique());
        assert!(!IndexKind::Standard.is_unique());
    }

    #[test]
    fn test_index_def_to_sql_standard() {
        let def = IndexDef::new("idx_name", "functions", ["name"]);
        let sql = def.to_sql().unwrap();
        assert!(sql.contains("CREATE INDEX"));
        assert!(sql.contains("idx_name"));
        assert!(sql.contains("functions"));
        assert!(sql.contains("(name)"));
    }

    #[test]
    fn test_index_def_to_sql_unique() {
        let def = IndexDef::unique("idx_unique_name", "functions", ["name"]);
        let sql = def.to_sql().unwrap();
        assert!(sql.contains("UNIQUE INDEX"));
    }

    #[test]
    fn test_index_def_to_sql_partial() {
        let def = IndexDef::partial("idx_funcs", "functions", ["name"], "kind = 'function'");
        let sql = def.to_sql().unwrap();
        assert!(sql.contains("WHERE kind = 'function'"));
    }

    #[test]
    fn test_index_def_no_columns_error() {
        let def = IndexDef {
            name: "idx_bad".into(),
            table: "functions".into(),
            columns: vec![],
            kind: IndexKind::Standard,
            filter: None,
            include_columns: vec![],
        };
        let err = def.to_sql();
        assert!(matches!(err, Err(IndexError::NoColumns(_))));
    }

    #[test]
    fn test_index_def_composite() {
        let def = IndexDef::new("idx_comp", "functions", ["name", "address"]);
        assert!(def.is_composite());
        assert_eq!(def.column_count(), 2);
    }

    #[test]
    fn test_create_index_fn() {
        let db = open_db();
        let def = IndexDef::new("idx_fn_name", "functions", ["name"]);
        create_index(db.clone(), &def).unwrap();
        let manager = DbIndexManager::new(db);
        assert!(manager.index_exists("idx_fn_name").unwrap());
    }

    #[test]
    fn test_manager_create_and_drop() {
        let db = open_db();
        let manager = DbIndexManager::new(db);
        let def = IndexDef::new("idx_addr", "functions", ["address"]);
        manager.create(&def).unwrap();
        assert!(manager.index_exists("idx_addr").unwrap());
        manager.drop("idx_addr").unwrap();
        assert!(!manager.index_exists("idx_addr").unwrap());
    }

    #[test]
    fn test_manager_create_if_missing() {
        let db = open_db();
        let manager = DbIndexManager::new(db);
        let def = IndexDef::new("idx_kind", "functions", ["kind"]);
        let created_first = manager.create_if_missing(&def).unwrap();
        assert!(created_first);
        let created_second = manager.create_if_missing(&def).unwrap();
        assert!(!created_second);
    }

    #[test]
    fn test_manager_rebuild() {
        let db = open_db();
        let manager = DbIndexManager::new(db);
        let def = IndexDef::new("idx_rebuild", "functions", ["name"]);
        manager.create(&def).unwrap();
        manager.rebuild(&def).unwrap();
        assert!(manager.index_exists("idx_rebuild").unwrap());
    }

    #[test]
    fn test_manager_list_all() {
        let db = open_db();
        let manager = DbIndexManager::new(db);
        manager.create(&IndexDef::new("idx_a", "functions", ["name"])).unwrap();
        manager.create(&IndexDef::new("idx_b", "functions", ["address"])).unwrap();
        let list = manager.list_all().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_manager_inspect() {
        let db = open_db();
        let manager = DbIndexManager::new(db);
        let def = IndexDef::new("idx_inspect", "functions", ["name", "kind"]);
        manager.create(&def).unwrap();
        let info = manager.inspect("idx_inspect").unwrap().unwrap();
        assert_eq!(info.name, "idx_inspect");
        assert_eq!(info.table, "functions");
        assert_eq!(info.columns.len(), 2);
    }

    #[test]
    fn test_manager_register_and_create_all() {
        let db = open_db();
        let mut manager = DbIndexManager::new(db);
        manager.register(IndexDef::new("idx_r1", "functions", ["name"]));
        manager.register(IndexDef::new("idx_r2", "symbols", ["sym"]));
        assert_eq!(manager.registered_count(), 2);
        let created = manager.create_all_registered().unwrap();
        assert_eq!(created, 2);
    }

    #[test]
    fn test_manager_drop_all_registered() {
        let db = open_db();
        let mut manager = DbIndexManager::new(db);
        manager.register(IndexDef::new("idx_d1", "functions", ["name"]));
        manager.create_all_registered().unwrap();
        let dropped = manager.drop_all_registered().unwrap();
        assert_eq!(dropped, 1);
    }

    #[test]
    fn test_index_def_drop_sql() {
        let def = IndexDef::new("idx_drop_test", "functions", ["name"]);
        let sql = def.drop_sql();
        assert!(sql.contains("DROP INDEX IF EXISTS idx_drop_test"));
    }

    #[test]
    fn test_index_def_display() {
        let def = IndexDef::unique("idx_display", "functions", ["name", "address"]);
        let s = def.to_string();
        assert!(s.contains("idx_display"));
        assert!(s.contains("unique"));
    }
}
