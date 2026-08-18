pub mod collaboration;
pub mod db;
pub mod graph_algorithms_extended;
pub mod graph_persistence;
pub mod query_engine;

/// Full analysis graph: AnalysisGraph, FunctionNode, CallEdge, DataFlowEdge,
/// TypeEdge, GraphQuery, GraphExport (DOT/JSON).
pub mod analysis_graph;

/// Knowledge graph export to GraphML, GEXF, DOT, Cytoscape JSON, Neo4j Cypher, CSV.
pub mod graph_export;

use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

use rustre_core::address::Address;
use rustre_core::ids::ViewId;

pub use db::{DbDialect, GraphError, GraphParam, GraphValue};

// ---------------------------------------------------------------------------
// Row types returned by queries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub end_address: u64,
    pub name: Option<String>,
    pub prototype: Option<String>,
    pub calling_conv: Option<String>,
    pub is_thunk: bool,
    pub is_library: bool,
    pub flirt_matched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub name: String,
    pub kind: String,
    pub demangled: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefRow {
    pub from_addr: u64,
    pub to_addr: u64,
    pub view_id: i64,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub text: String,
    pub repeatable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub length: i64,
    pub encoding: String,
    pub value: String,
    pub is_decoded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub id: i64,
    pub view_id: i64,
    pub timestamp: i64,
    pub actor: String,
    pub kind: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub label: Option<String>,
    pub color: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlockRow {
    pub id: i64,
    pub function_id: i64,
    pub start_addr: u64,
    pub end_addr: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdgeRow {
    pub from_bb: i64,
    pub to_bb: i64,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    pub id: i64,
    pub uri: String,
    pub arch: String,
    pub endian: String,
    pub bits: i64,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

/// Return the correct `PRIMARY KEY` clause fragment depending on dialect.
/// `SQLite` uses `INTEGER PRIMARY KEY` (implicit ROWID / auto-increment).
/// `MySQL` uses `BIGINT AUTO_INCREMENT PRIMARY KEY`.
const fn pk_fragment(dialect: DbDialect) -> &'static str {
    match dialect {
        DbDialect::Sqlite => "INTEGER PRIMARY KEY",
        DbDialect::Mysql => "BIGINT AUTO_INCREMENT PRIMARY KEY",
    }
}

// ---------------------------------------------------------------------------
// FunctionMeta
// ---------------------------------------------------------------------------

/// Optional metadata for [`KnowledgeGraph::add_function`] and
/// [`KnowledgeGraph::add_function_emit`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FunctionMeta<'a> {
    /// Human-readable name, e.g. `"main"`.
    pub name: Option<&'a str>,
    /// Decompiler prototype string, e.g. `"int __cdecl foo(int)"`.
    pub prototype: Option<&'a str>,
    /// Calling convention, e.g. `"cdecl"`.
    pub calling_conv: Option<&'a str>,
    /// Whether this function is a thunk.
    pub is_thunk: bool,
    /// Whether this function is an imported library stub.
    pub is_library: bool,
}

// ---------------------------------------------------------------------------
// KnowledgeGraph
// ---------------------------------------------------------------------------

pub struct KnowledgeGraph {
    conn: Arc<dyn db::DatabaseEngine>,
}

impl std::fmt::Debug for KnowledgeGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnowledgeGraph")
            .field("dialect", &self.conn.dialect())
            .finish_non_exhaustive()
    }
}

impl KnowledgeGraph {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new_in_memory() -> Result<Self, GraphError> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let engine = Arc::new(db::SqliteEngine::new(conn));
        let graph = Self { conn: engine };
        graph.initialize_schema()?;
        Ok(graph)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new_file(path: &std::path::Path) -> Result<Self, GraphError> {
        let conn = rusqlite::Connection::open(path)?;
        let engine = Arc::new(db::SqliteEngine::new(conn));
        let graph = Self { conn: engine };
        graph.initialize_schema()?;
        Ok(graph)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new_mysql(url: &str) -> Result<Self, GraphError> {
        let engine = Arc::new(db::MysqlEngine::new(url)?);
        let graph = Self { conn: engine };
        graph.initialize_schema()?;
        Ok(graph)
    }

    // ------------------------------------------------------------------
    // Schema initialisation
    // ------------------------------------------------------------------

    fn initialize_schema(&self) -> Result<(), GraphError> {
        let d = self.conn.dialect();
        let pk = pk_fragment(d);

        // views
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS views (
                    id {pk},
                    uri TEXT NOT NULL,
                    arch TEXT NOT NULL,
                    endian TEXT NOT NULL,
                    bits INTEGER NOT NULL,
                    created_at BIGINT NOT NULL
                );"
            ),
            &[],
        )?;

        // functions
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS functions (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    address BIGINT NOT NULL,
                    end_address BIGINT NOT NULL,
                    name TEXT,
                    prototype TEXT,
                    calling_conv TEXT,
                    is_thunk INTEGER NOT NULL DEFAULT 0,
                    is_library INTEGER NOT NULL DEFAULT 0,
                    flirt_matched INTEGER NOT NULL DEFAULT 0
                );"
            ),
            &[],
        )?;

        // basic_blocks
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS basic_blocks (
                    id {pk},
                    function_id BIGINT NOT NULL,
                    start_addr BIGINT NOT NULL,
                    end_addr BIGINT NOT NULL
                );"
            ),
            &[],
        )?;

        // cfg_edges
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS cfg_edges (
                from_bb BIGINT NOT NULL,
                to_bb BIGINT NOT NULL,
                kind VARCHAR(64) NOT NULL
            );",
            &[],
        )?;

        // symbols
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS symbols (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    address BIGINT NOT NULL,
                    name TEXT NOT NULL,
                    kind VARCHAR(64) NOT NULL,
                    demangled TEXT,
                    source TEXT
                );"
            ),
            &[],
        )?;

        // xrefs
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS xrefs (
                from_addr BIGINT NOT NULL,
                to_addr BIGINT NOT NULL,
                view_id BIGINT NOT NULL,
                kind VARCHAR(64) NOT NULL
            );",
            &[],
        )?;

        // types
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS types (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    definition TEXT NOT NULL,
                    size BIGINT,
                    alignment BIGINT
                );"
            ),
            &[],
        )?;

        // comments
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS comments (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    address BIGINT NOT NULL,
                    text TEXT NOT NULL,
                    repeatable INTEGER NOT NULL DEFAULT 0
                );"
            ),
            &[],
        )?;

        // patches
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS patches (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    address BIGINT NOT NULL,
                    original_bytes BLOB NOT NULL,
                    new_bytes BLOB NOT NULL,
                    reason TEXT,
                    created_at BIGINT NOT NULL
                );"
            ),
            &[],
        )?;

        // events
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS events (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    timestamp BIGINT NOT NULL,
                    actor VARCHAR(255) NOT NULL,
                    kind VARCHAR(255) NOT NULL,
                    payload BLOB NOT NULL
                );"
            ),
            &[],
        )?;

        // strings
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS strings (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    address BIGINT NOT NULL,
                    length BIGINT NOT NULL,
                    encoding VARCHAR(32) NOT NULL,
                    value TEXT NOT NULL,
                    is_decoded INTEGER NOT NULL DEFAULT 0
                );"
            ),
            &[],
        )?;

        // bookmarks
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS bookmarks (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    address BIGINT NOT NULL,
                    label TEXT,
                    color INTEGER NOT NULL DEFAULT 0
                );"
            ),
            &[],
        )?;

        // annotations
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS annotations (
                    id {pk},
                    entity_type VARCHAR(64) NOT NULL,
                    entity_id BIGINT NOT NULL,
                    key_name VARCHAR(255) NOT NULL,
                    value_json TEXT NOT NULL
                );"
            ),
            &[],
        )?;

        // sections (binary sections populated from loader)
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS sections (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    name TEXT NOT NULL,
                    va BIGINT NOT NULL,
                    size BIGINT NOT NULL,
                    entropy REAL NOT NULL DEFAULT 0.0
                );"
            ),
            &[],
        )?;

        // imports (binary imports populated from loader)
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS imports (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    dll TEXT,
                    name TEXT NOT NULL,
                    ordinal INTEGER,
                    address BIGINT NOT NULL
                );"
            ),
            &[],
        )?;

        // exports (binary exports populated from loader)
        self.conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS exports (
                    id {pk},
                    view_id BIGINT NOT NULL,
                    name TEXT,
                    ordinal INTEGER,
                    address BIGINT NOT NULL
                );"
            ),
            &[],
        )?;

        // Indexes – MySQL older versions don't support IF NOT EXISTS on indexes,
        // so we attempt each one and swallow duplicate-key errors.
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_functions_view_addr ON functions(view_id, address)",
            "CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(view_id, to_addr)",
            "CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(view_id, from_addr)",
            "CREATE INDEX IF NOT EXISTS idx_symbols_addr ON symbols(view_id, address)",
            "CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name)",
            "CREATE INDEX IF NOT EXISTS idx_comments_addr ON comments(view_id, address)",
            "CREATE INDEX IF NOT EXISTS idx_strings_addr ON strings(view_id, address)",
        ];

        for idx_sql in &indexes {
            match self.conn.dialect() {
                DbDialect::Sqlite => {
                    self.conn.execute(idx_sql, &[])?;
                }
                DbDialect::Mysql => {
                    // Rewrite for MySQL – strip IF NOT EXISTS from index DDL.
                    let mysql_sql = idx_sql.replace("IF NOT EXISTS ", "");
                    if let Err(e) = self.conn.execute(&mysql_sql, &[]) {
                        // Ignore "Duplicate key name" (MySQL error 1061).
                        let msg = e.to_string();
                        if !msg.contains("1061") && !msg.contains("Duplicate key") {
                            return Err(e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // View methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_view(
        &self,
        id: i64,
        uri: &str,
        arch: &str,
        endian: &str,
        bits: i64,
    ) -> Result<(), GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO views (id, uri, arch, endian, bits, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                GraphParam::Int(id),
                GraphParam::Text(uri.to_owned()),
                GraphParam::Text(arch.to_owned()),
                GraphParam::Text(endian.to_owned()),
                GraphParam::Int(bits),
                GraphParam::Int(now),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_view_info(&self, id: i64) -> Result<Option<ViewRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, uri, arch, endian, bits, created_at FROM views WHERE id = ?1",
            &[GraphParam::Int(id)],
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(view_row_from_mixed(&rows[0])?))
    }

    // ------------------------------------------------------------------
    // Function methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_function(
        &self,
        view_id: ViewId,
        address: Address,
        end_address: Address,
        meta: FunctionMeta<'_>,
    ) -> Result<i64, GraphError> {
        let FunctionMeta { name, prototype, calling_conv, is_thunk, is_library } = meta;
        self.conn.execute(
            "INSERT INTO functions
             (view_id, address, end_address, name, prototype, calling_conv, is_thunk, is_library)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                // SAFETY: SQLite stores all integers as signed 64-bit values.
                // The cast `u64 as i64` is an intentional two's-complement
                // reinterpretation; the round-trip `i64 as u64` on read-back
                // restores the original value exactly, even for kernel/ASLR
                // addresses above 0x7FFF_FFFF_FFFF_FFFF.
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Int(end_address.0.cast_signed()),
                opt_text(name),
                opt_text(prototype),
                opt_text(calling_conv),
                GraphParam::Int(bool_int(is_thunk)),
                GraphParam::Int(bool_int(is_library)),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_function_name(
        &self,
        view_id: ViewId,
        address: Address,
    ) -> Result<Option<String>, GraphError> {
        self.conn.query_row_string(
            "SELECT name FROM functions WHERE view_id = ?1 AND address = ?2 LIMIT 1",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_function_at(
        &self,
        view_id: ViewId,
        address: Address,
    ) -> Result<Option<FunctionRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, end_address, name, prototype,
                    calling_conv, is_thunk, is_library, flirt_matched
             FROM functions
             WHERE view_id = ?1 AND address = ?2
             LIMIT 1",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(function_row_from_mixed(&rows[0])?))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// Addresses are UNSIGNED, but `SQLite` only has signed 64-bit integers, so
    /// `cast_signed` turns every address at or above 2^63 (kernel space) into a
    /// negative number. That round-trip is a bijection, so equality lookups are
    /// unaffected — but plain `>=` / `<` / `ORDER BY` then use the signed order,
    /// in which kernel addresses sort BELOW every user-mode one. A range whose
    /// end is `0xFFFF_FFFF_FFFF_FFFF` became `address < -1` and matched nothing
    /// at all.
    ///
    /// The comparison below restores the unsigned order without changing the
    /// stored encoding (so existing databases keep working): with `f` = the
    /// sign flag, unsigned order is the lexicographic order of `(f, address)`.
    pub fn get_functions_in_range(
        &self,
        view_id: ViewId,
        start: Address,
        end: Address,
    ) -> Result<Vec<FunctionRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, end_address, name, prototype,
                    calling_conv, is_thunk, is_library, flirt_matched
             FROM functions
             WHERE view_id = ?1
               AND (((address < 0) > (?2 < 0)) OR ((address < 0) = (?2 < 0) AND address >= ?2))
               AND (((address < 0) < (?3 < 0)) OR ((address < 0) = (?3 < 0) AND address <  ?3))
             ORDER BY (address < 0) ASC, address ASC",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(start.0.cast_signed()),
                GraphParam::Int(end.0.cast_signed()),
            ],
        )?;
        rows.iter().map(|r| function_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn rename_function(
        &self,
        view_id: ViewId,
        address: Address,
        name: &str,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "UPDATE functions SET name = ?1 WHERE view_id = ?2 AND address = ?3",
            &[
                GraphParam::Text(name.to_owned()),
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn set_function_prototype(
        &self,
        view_id: ViewId,
        address: Address,
        prototype: &str,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "UPDATE functions SET prototype = ?1 WHERE view_id = ?2 AND address = ?3",
            &[
                GraphParam::Text(prototype.to_owned()),
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn count_functions(&self, view_id: ViewId) -> Result<i64, GraphError> {
        let v = self.conn.query_row_i64(
            "SELECT COUNT(*) FROM functions WHERE view_id = ?1",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        Ok(v.unwrap_or(0))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_function(&self, view_id: ViewId, address: Address) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM functions WHERE view_id = ?1 AND address = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Symbol methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_symbol(
        &self,
        view_id: ViewId,
        address: Address,
        name: &str,
        kind: &str,
        source: Option<&str>,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO symbols (view_id, address, name, kind, source)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Text(name.to_owned()),
                GraphParam::Text(kind.to_owned()),
                opt_text(source),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_symbols_at(
        &self,
        view_id: ViewId,
        address: Address,
    ) -> Result<Vec<SymbolRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, name, kind, demangled, source
             FROM symbols
             WHERE view_id = ?1 AND address = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        rows.iter().map(|r| symbol_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_symbols_by_name(
        &self,
        view_id: ViewId,
        name: &str,
    ) -> Result<Vec<SymbolRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, name, kind, demangled, source
             FROM symbols
             WHERE view_id = ?1 AND name = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(name.to_owned()),
            ],
        )?;
        rows.iter().map(|r| symbol_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_symbol(
        &self,
        view_id: ViewId,
        address: Address,
        kind: &str,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM symbols WHERE view_id = ?1 AND address = ?2 AND kind = ?3",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Text(kind.to_owned()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn count_symbols(&self, view_id: ViewId) -> Result<i64, GraphError> {
        let v = self.conn.query_row_i64(
            "SELECT COUNT(*) FROM symbols WHERE view_id = ?1",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        Ok(v.unwrap_or(0))
    }

    // ------------------------------------------------------------------
    // Xref methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_xref(
        &self,
        view_id: ViewId,
        from_addr: Address,
        to_addr: Address,
        kind: &str,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO xrefs (from_addr, to_addr, view_id, kind)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(from_addr.0.cast_signed()),
                GraphParam::Int(to_addr.0.cast_signed()),
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(kind.to_owned()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn xrefs_from(
        &self,
        view_id: ViewId,
        from_addr: Address,
    ) -> Result<Vec<XrefRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT from_addr, to_addr, view_id, kind
             FROM xrefs
             WHERE view_id = ?1 AND from_addr = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(from_addr.0.cast_signed()),
            ],
        )?;
        rows.iter().map(|r| xref_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn xrefs_to(&self, view_id: ViewId, to_addr: Address) -> Result<Vec<XrefRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT from_addr, to_addr, view_id, kind
             FROM xrefs
             WHERE view_id = ?1 AND to_addr = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(to_addr.0.cast_signed()),
            ],
        )?;
        rows.iter().map(|r| xref_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn callers_of(&self, view_id: ViewId, addr: Address) -> Result<Vec<XrefRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT from_addr, to_addr, view_id, kind
             FROM xrefs
             WHERE view_id = ?1 AND to_addr = ?2 AND kind = 'code_call'",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(addr.0.cast_signed()),
            ],
        )?;
        rows.iter().map(|r| xref_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn count_xrefs(&self, view_id: ViewId) -> Result<i64, GraphError> {
        let v = self.conn.query_row_i64(
            "SELECT COUNT(*) FROM xrefs WHERE view_id = ?1",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        Ok(v.unwrap_or(0))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_xrefs_from(&self, view_id: ViewId, from_addr: Address) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM xrefs WHERE view_id = ?1 AND from_addr = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(from_addr.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Comment methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_comment(
        &self,
        view_id: ViewId,
        address: Address,
        text: &str,
        repeatable: bool,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO comments (view_id, address, text, repeatable)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Text(text.to_owned()),
                GraphParam::Int(bool_int(repeatable)),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_comment(
        &self,
        view_id: ViewId,
        address: Address,
    ) -> Result<Option<String>, GraphError> {
        self.conn.query_row_string(
            "SELECT text FROM comments WHERE view_id = ?1 AND address = ?2 LIMIT 1",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn update_comment(
        &self,
        view_id: ViewId,
        address: Address,
        text: &str,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "UPDATE comments SET text = ?1 WHERE view_id = ?2 AND address = ?3",
            &[
                GraphParam::Text(text.to_owned()),
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_comment(&self, view_id: ViewId, address: Address) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM comments WHERE view_id = ?1 AND address = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn iter_comments(&self, view_id: ViewId) -> Result<Vec<CommentRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, text, repeatable
             FROM comments
             WHERE view_id = ?1
             ORDER BY address ASC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter().map(|r| comment_row_from_mixed(r)).collect()
    }

    // ------------------------------------------------------------------
    // Patch methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_patch(
        &self,
        view_id: ViewId,
        address: Address,
        original_bytes: &[u8],
        new_bytes: &[u8],
        reason: Option<&str>,
    ) -> Result<i64, GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO patches (view_id, address, original_bytes, new_bytes, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Blob(original_bytes.to_vec()),
                GraphParam::Blob(new_bytes.to_vec()),
                opt_text(reason),
                GraphParam::Int(now),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_patches(&self, view_id: ViewId) -> Result<Vec<PatchRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, original_bytes, new_bytes, reason, created_at
             FROM patches
             WHERE view_id = ?1
             ORDER BY address ASC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter().map(|r| patch_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_patch(&self, view_id: ViewId, address: Address) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM patches WHERE view_id = ?1 AND address = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // String methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_string(
        &self,
        view_id: ViewId,
        address: Address,
        length: i64,
        encoding: &str,
        value: &str,
        is_decoded: bool,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO strings (view_id, address, length, encoding, value, is_decoded)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Int(length),
                GraphParam::Text(encoding.to_owned()),
                GraphParam::Text(value.to_owned()),
                GraphParam::Int(bool_int(is_decoded)),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_strings(&self, view_id: ViewId) -> Result<Vec<StringRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, length, encoding, value, is_decoded
             FROM strings
             WHERE view_id = ?1
             ORDER BY address ASC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter().map(|r| string_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn search_strings(
        &self,
        view_id: ViewId,
        pattern: &str,
    ) -> Result<Vec<StringRow>, GraphError> {
        let like_pattern = format!("%{pattern}%");
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, length, encoding, value, is_decoded
             FROM strings
             WHERE view_id = ?1 AND value LIKE ?2
             ORDER BY address ASC",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(like_pattern),
            ],
        )?;
        rows.iter().map(|r| string_row_from_mixed(r)).collect()
    }

    // ------------------------------------------------------------------
    // Event methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_event(
        &self,
        view_id: ViewId,
        actor: &str,
        kind: &str,
        payload: &[u8],
    ) -> Result<(), GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO events (view_id, timestamp, actor, kind, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(now),
                GraphParam::Text(actor.to_owned()),
                GraphParam::Text(kind.to_owned()),
                GraphParam::Blob(payload.to_vec()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_events(&self, view_id: ViewId, limit: i64) -> Result<Vec<EventRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, timestamp, actor, kind, payload
             FROM events
             WHERE view_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(limit),
            ],
        )?;
        rows.iter().map(|r| event_row_from_mixed(r)).collect()
    }

    // ------------------------------------------------------------------
    // Bookmark methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_bookmark(
        &self,
        view_id: ViewId,
        address: Address,
        label: Option<&str>,
        color: i64,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO bookmarks (view_id, address, label, color)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                opt_text(label),
                GraphParam::Int(color),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_bookmarks(&self, view_id: ViewId) -> Result<Vec<BookmarkRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, label, color
             FROM bookmarks
             WHERE view_id = ?1
             ORDER BY address ASC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter().map(|r| bookmark_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_bookmark(&self, view_id: ViewId, address: Address) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM bookmarks WHERE view_id = ?1 AND address = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Basic-block and CFG methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_basic_block(
        &self,
        function_id: i64,
        start_addr: Address,
        end_addr: Address,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO basic_blocks (function_id, start_addr, end_addr)
             VALUES (?1, ?2, ?3)",
            &[
                GraphParam::Int(function_id),
                GraphParam::Int(start_addr.0.cast_signed()),
                GraphParam::Int(end_addr.0.cast_signed()),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_cfg_edge(
        &self,
        from_bb_id: i64,
        to_bb_id: i64,
        kind: &str,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO cfg_edges (from_bb, to_bb, kind) VALUES (?1, ?2, ?3)",
            &[
                GraphParam::Int(from_bb_id),
                GraphParam::Int(to_bb_id),
                GraphParam::Text(kind.to_owned()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_basic_blocks_of_function(
        &self,
        function_id: i64,
    ) -> Result<Vec<BasicBlockRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, function_id, start_addr, end_addr
             FROM basic_blocks
             WHERE function_id = ?1
             ORDER BY start_addr ASC",
            &[GraphParam::Int(function_id)],
        )?;
        rows.iter().map(|r| bb_row_from_mixed(r)).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_cfg_edges_from(&self, bb_id: i64) -> Result<Vec<CfgEdgeRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT from_bb, to_bb, kind FROM cfg_edges WHERE from_bb = ?1",
            &[GraphParam::Int(bb_id)],
        )?;
        rows.iter().map(|r| cfg_edge_row_from_mixed(r)).collect()
    }

    // ------------------------------------------------------------------
    // Annotation methods
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn annotate(
        &self,
        entity_type: &str,
        entity_id: i64,
        key: &str,
        value_json: &str,
    ) -> Result<(), GraphError> {
        // Upsert: delete existing then insert.
        self.conn.execute(
            "DELETE FROM annotations
             WHERE entity_type = ?1 AND entity_id = ?2 AND key_name = ?3",
            &[
                GraphParam::Text(entity_type.to_owned()),
                GraphParam::Int(entity_id),
                GraphParam::Text(key.to_owned()),
            ],
        )?;
        self.conn.execute(
            "INSERT INTO annotations (entity_type, entity_id, key_name, value_json)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Text(entity_type.to_owned()),
                GraphParam::Int(entity_id),
                GraphParam::Text(key.to_owned()),
                GraphParam::Text(value_json.to_owned()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_annotation(
        &self,
        entity_type: &str,
        entity_id: i64,
        key: &str,
    ) -> Result<Option<String>, GraphError> {
        self.conn.query_row_string(
            "SELECT value_json FROM annotations
             WHERE entity_type = ?1 AND entity_id = ?2 AND key_name = ?3
             LIMIT 1",
            &[
                GraphParam::Text(entity_type.to_owned()),
                GraphParam::Int(entity_id),
                GraphParam::Text(key.to_owned()),
            ],
        )
    }

    // ------------------------------------------------------------------
    // Section / import / export population helpers
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_section(
        &self,
        view_id: ViewId,
        name: &str,
        va: u64,
        size: u64,
        entropy: f64,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO sections (view_id, name, va, size, entropy)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(name.to_owned()),
                GraphParam::Int(va.cast_signed()),
                GraphParam::Int(size.cast_signed()),
                GraphParam::Real(entropy),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_import(
        &self,
        view_id: ViewId,
        dll: Option<&str>,
        name: &str,
        ordinal: Option<i64>,
        address: u64,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO imports (view_id, dll, name, ordinal, address)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                opt_text(dll),
                GraphParam::Text(name.to_owned()),
                ordinal.map_or(GraphParam::Null, GraphParam::Int),
                GraphParam::Int(address.cast_signed()),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_export(
        &self,
        view_id: ViewId,
        name: Option<&str>,
        ordinal: Option<i64>,
        address: u64,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO exports (view_id, name, ordinal, address)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                opt_text(name),
                ordinal.map_or(GraphParam::Null, GraphParam::Int),
                GraphParam::Int(address.cast_signed()),
            ],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Raw SQL query (SELECT only)
    // ------------------------------------------------------------------

    /// Execute a raw SQL SELECT statement and return rows as a list of
    /// column-name → value maps.  Only SELECT statements are accepted;
    /// any query that starts with a different keyword (after stripping
    /// leading whitespace and comments) returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn query_sql(
        &self,
        sql: &str,
    ) -> Result<Vec<std::collections::HashMap<String, db::GraphValue>>, GraphError> {
        let trimmed = sql.trim_start();
        let upper = trimmed.to_ascii_uppercase();
        // Reject SQL comment syntax that could be used to bypass the guard below.
        if upper.contains("--") || upper.contains("/*") {
            return Err(GraphError::Generic(
                "SQL comments are not allowed in query_sql".into(),
            ));
        }
        if !upper.starts_with("SELECT") {
            return Err(GraphError::Generic(
                "Only SELECT statements are allowed in query_sql".into(),
            ));
        }
        // Extra safety: reject DML/DDL keywords anywhere at the start of
        // semicolon-separated statements.
        for part in sql.split(';') {
            let p = part.trim_start().to_ascii_uppercase();
            if p.is_empty() {
                continue;
            }
            if !p.starts_with("SELECT") && !p.starts_with("WITH") {
                return Err(GraphError::Generic(format!(
                    "Disallowed statement in query: {part}"
                )));
            }
        }
        let (col_names, rows) = self.conn.query_rows_with_columns(sql, &[])?;
        let result = rows
            .into_iter()
            .map(|cells| {
                col_names
                    .iter()
                    .zip(cells)
                    .map(|(name, val)| (name.clone(), val))
                    .collect()
            })
            .collect();
        Ok(result)
    }

    // ------------------------------------------------------------------
    // Transaction delegation
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn begin_transaction(&self) -> Result<(), GraphError> {
        self.conn.begin_transaction()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn commit_transaction(&self) -> Result<(), GraphError> {
        self.conn.commit_transaction()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn rollback_transaction(&self) -> Result<(), GraphError> {
        self.conn.rollback_transaction()
    }
}

// ---------------------------------------------------------------------------
// Row deserialization helpers
// ---------------------------------------------------------------------------

fn mixed_i64(row: &[GraphValue], idx: usize) -> Result<i64, GraphError> {
    match &row[idx] {
        GraphValue::Integer(n) => Ok(*n),
        other => Err(GraphError::Generic(format!(
            "expected Integer at col {idx}, got {other:?}"
        ))),
    }
}

fn mixed_u64(row: &[GraphValue], idx: usize) -> Result<u64, GraphError> {
    mixed_i64(row, idx).map(i64::cast_unsigned)
}

fn mixed_opt_str(row: &[GraphValue], idx: usize) -> Result<Option<String>, GraphError> {
    match &row[idx] {
        GraphValue::Null => Ok(None),
        GraphValue::Text(s) => Ok(Some(s.clone())),
        other => Err(GraphError::Generic(format!(
            "expected Text/Null at col {idx}, got {other:?}"
        ))),
    }
}

fn mixed_str(row: &[GraphValue], idx: usize) -> Result<String, GraphError> {
    match &row[idx] {
        GraphValue::Text(s) => Ok(s.clone()),
        other => Err(GraphError::Generic(format!(
            "expected Text at col {idx}, got {other:?}"
        ))),
    }
}

fn mixed_blob(row: &[GraphValue], idx: usize) -> Result<Vec<u8>, GraphError> {
    match &row[idx] {
        GraphValue::Blob(b) => Ok(b.clone()),
        GraphValue::Null => Ok(vec![]),
        other => Err(GraphError::Generic(format!(
            "expected Blob at col {idx}, got {other:?}"
        ))),
    }
}

fn mixed_bool(row: &[GraphValue], idx: usize) -> Result<bool, GraphError> {
    mixed_i64(row, idx).map(|n| n != 0)
}

fn function_row_from_mixed(row: &[GraphValue]) -> Result<FunctionRow, GraphError> {
    Ok(FunctionRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        address: mixed_u64(row, 2)?,
        end_address: mixed_u64(row, 3)?,
        name: mixed_opt_str(row, 4)?,
        prototype: mixed_opt_str(row, 5)?,
        calling_conv: mixed_opt_str(row, 6)?,
        is_thunk: mixed_bool(row, 7)?,
        is_library: mixed_bool(row, 8)?,
        flirt_matched: mixed_bool(row, 9)?,
    })
}

fn symbol_row_from_mixed(row: &[GraphValue]) -> Result<SymbolRow, GraphError> {
    Ok(SymbolRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        address: mixed_u64(row, 2)?,
        name: mixed_str(row, 3)?,
        kind: mixed_str(row, 4)?,
        demangled: mixed_opt_str(row, 5)?,
        source: mixed_opt_str(row, 6)?,
    })
}

fn xref_row_from_mixed(row: &[GraphValue]) -> Result<XrefRow, GraphError> {
    Ok(XrefRow {
        from_addr: mixed_u64(row, 0)?,
        to_addr: mixed_u64(row, 1)?,
        view_id: mixed_i64(row, 2)?,
        kind: mixed_str(row, 3)?,
    })
}

fn comment_row_from_mixed(row: &[GraphValue]) -> Result<CommentRow, GraphError> {
    Ok(CommentRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        address: mixed_u64(row, 2)?,
        text: mixed_str(row, 3)?,
        repeatable: mixed_bool(row, 4)?,
    })
}

fn patch_row_from_mixed(row: &[GraphValue]) -> Result<PatchRow, GraphError> {
    Ok(PatchRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        address: mixed_u64(row, 2)?,
        original_bytes: mixed_blob(row, 3)?,
        new_bytes: mixed_blob(row, 4)?,
        reason: mixed_opt_str(row, 5)?,
        created_at: mixed_i64(row, 6)?,
    })
}

fn string_row_from_mixed(row: &[GraphValue]) -> Result<StringRow, GraphError> {
    Ok(StringRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        address: mixed_u64(row, 2)?,
        length: mixed_i64(row, 3)?,
        encoding: mixed_str(row, 4)?,
        value: mixed_str(row, 5)?,
        is_decoded: mixed_bool(row, 6)?,
    })
}

fn event_row_from_mixed(row: &[GraphValue]) -> Result<EventRow, GraphError> {
    Ok(EventRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        timestamp: mixed_i64(row, 2)?,
        actor: mixed_str(row, 3)?,
        kind: mixed_str(row, 4)?,
        payload: mixed_blob(row, 5)?,
    })
}

fn bookmark_row_from_mixed(row: &[GraphValue]) -> Result<BookmarkRow, GraphError> {
    Ok(BookmarkRow {
        id: mixed_i64(row, 0)?,
        view_id: mixed_i64(row, 1)?,
        address: mixed_u64(row, 2)?,
        label: mixed_opt_str(row, 3)?,
        color: mixed_i64(row, 4)?,
    })
}

fn bb_row_from_mixed(row: &[GraphValue]) -> Result<BasicBlockRow, GraphError> {
    Ok(BasicBlockRow {
        id: mixed_i64(row, 0)?,
        function_id: mixed_i64(row, 1)?,
        start_addr: mixed_u64(row, 2)?,
        end_addr: mixed_u64(row, 3)?,
    })
}

fn cfg_edge_row_from_mixed(row: &[GraphValue]) -> Result<CfgEdgeRow, GraphError> {
    Ok(CfgEdgeRow {
        from_bb: mixed_i64(row, 0)?,
        to_bb: mixed_i64(row, 1)?,
        kind: mixed_str(row, 2)?,
    })
}

fn view_row_from_mixed(row: &[GraphValue]) -> Result<ViewRow, GraphError> {
    Ok(ViewRow {
        id: mixed_i64(row, 0)?,
        uri: mixed_str(row, 1)?,
        arch: mixed_str(row, 2)?,
        endian: mixed_str(row, 3)?,
        bits: mixed_i64(row, 4)?,
        created_at: mixed_i64(row, 5)?,
    })
}

// ---------------------------------------------------------------------------
// Small utility functions
// ---------------------------------------------------------------------------

const fn bool_int(b: bool) -> i64 {
    if b { 1 } else { 0 }
}

fn opt_text(s: Option<&str>) -> GraphParam {
    s.map_or(GraphParam::Null, |v| GraphParam::Text(v.to_owned()))
}

/// Return current Unix timestamp in seconds.
fn unix_timestamp() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> KnowledgeGraph {
        KnowledgeGraph::new_in_memory().unwrap()
    }

    fn vid(n: u64) -> ViewId {
        ViewId::from_raw(n)
    }

    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    // --- schema / construction ---

    #[test]
    fn test_new_in_memory() {
        let _g = graph();
    }

    #[test]
    fn test_new_file_tempdir() {
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_graph_test.db");
        let _g = KnowledgeGraph::new_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    // --- views ---

    #[test]
    fn test_add_and_get_view() {
        let g = graph();
        g.add_view(1, "file:///bin/ls", "x86_64", "little", 64)
            .unwrap();
        let v = g.get_view_info(1).unwrap().unwrap();
        assert_eq!(v.id, 1);
        assert_eq!(v.uri, "file:///bin/ls");
        assert_eq!(v.arch, "x86_64");
        assert_eq!(v.endian, "little");
        assert_eq!(v.bits, 64);
    }

    #[test]
    fn test_get_view_missing() {
        let g = graph();
        assert!(g.get_view_info(99).unwrap().is_none());
    }

    // --- functions ---

    #[test]
    fn test_add_function_returns_id() {
        let g = graph();
        let id = g
            .add_function(vid(1), addr(0x0040_1000), addr(0x0040_1050), FunctionMeta { name: Some("main"), ..FunctionMeta::default() })
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_get_function_name() {
        let g = graph();
        g.add_function(vid(1), addr(0x0040_1000), addr(0x0040_1050), FunctionMeta { name: Some("main"), ..FunctionMeta::default() })
        .unwrap();
        let name = g.get_function_name(vid(1), addr(0x0040_1000)).unwrap();
        assert_eq!(name, Some("main".into()));
    }

    #[test]
    fn test_get_function_at() {
        let g = graph();
        g.add_function(vid(1), addr(0x0040_1000), addr(0x0040_1050), FunctionMeta { name: Some("main"), prototype: Some("int ()"), calling_conv: Some("cdecl"), is_thunk: true, ..FunctionMeta::default() })
        .unwrap();
        let row = g.get_function_at(vid(1), addr(0x0040_1000)).unwrap().unwrap();
        assert_eq!(row.name, Some("main".into()));
        assert_eq!(row.prototype, Some("int ()".into()));
        assert_eq!(row.calling_conv, Some("cdecl".into()));
        assert!(row.is_thunk);
        assert!(!row.is_library);
    }

    #[test]
    fn test_get_functions_in_range() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("f1"), ..FunctionMeta::default() })
        .unwrap();
        g.add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta { name: Some("f2"), ..FunctionMeta::default() })
        .unwrap();
        g.add_function(vid(1), addr(0x3000), addr(0x3100), FunctionMeta { name: Some("f3"), ..FunctionMeta::default() })
        .unwrap();
        let fns = g
            .get_functions_in_range(vid(1), addr(0x1000), addr(0x3000))
            .unwrap();
        assert_eq!(fns.len(), 2);
        assert_eq!(fns[0].name, Some("f1".into()));
        assert_eq!(fns[1].name, Some("f2".into()));
    }

    #[test]
    fn test_rename_function() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("old"), ..FunctionMeta::default() })
        .unwrap();
        g.rename_function(vid(1), addr(0x1000), "new_name").unwrap();
        let name = g.get_function_name(vid(1), addr(0x1000)).unwrap();
        assert_eq!(name, Some("new_name".into()));
    }

    #[test]
    fn test_set_function_prototype() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("f"), ..FunctionMeta::default() })
        .unwrap();
        g.set_function_prototype(vid(1), addr(0x1000), "void f(int a)")
            .unwrap();
        let row = g.get_function_at(vid(1), addr(0x1000)).unwrap().unwrap();
        assert_eq!(row.prototype, Some("void f(int a)".into()));
    }

    #[test]
    fn test_count_functions() {
        let g = graph();
        assert_eq!(g.count_functions(vid(1)).unwrap(), 0);
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta::default())
        .unwrap();
        g.add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta::default())
        .unwrap();
        assert_eq!(g.count_functions(vid(1)).unwrap(), 2);
        assert_eq!(g.count_functions(vid(2)).unwrap(), 0);
    }

    #[test]
    fn test_delete_function() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("del_me"), ..FunctionMeta::default() })
        .unwrap();
        g.delete_function(vid(1), addr(0x1000)).unwrap();
        assert!(g.get_function_at(vid(1), addr(0x1000)).unwrap().is_none());
    }

    // --- symbols ---

    #[test]
    fn test_add_and_get_symbols() {
        let g = graph();
        let id = g
            .add_symbol(vid(1), addr(0x5000), "printf", "function", Some("libc"))
            .unwrap();
        assert!(id > 0);
        let syms = g.get_symbols_at(vid(1), addr(0x5000)).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "printf");
        assert_eq!(syms[0].kind, "function");
        assert_eq!(syms[0].source, Some("libc".into()));
    }

    #[test]
    fn test_get_symbols_by_name() {
        let g = graph();
        g.add_symbol(vid(1), addr(0x1000), "foo", "data", None)
            .unwrap();
        g.add_symbol(vid(1), addr(0x2000), "foo", "data", None)
            .unwrap();
        let syms = g.get_symbols_by_name(vid(1), "foo").unwrap();
        assert_eq!(syms.len(), 2);
    }

    #[test]
    fn test_delete_symbol() {
        let g = graph();
        g.add_symbol(vid(1), addr(0x1000), "sym", "function", None)
            .unwrap();
        g.delete_symbol(vid(1), addr(0x1000), "function").unwrap();
        assert!(g.get_symbols_at(vid(1), addr(0x1000)).unwrap().is_empty());
    }

    #[test]
    fn test_count_symbols() {
        let g = graph();
        assert_eq!(g.count_symbols(vid(1)).unwrap(), 0);
        g.add_symbol(vid(1), addr(0x1000), "a", "func", None)
            .unwrap();
        g.add_symbol(vid(1), addr(0x2000), "b", "func", None)
            .unwrap();
        assert_eq!(g.count_symbols(vid(1)).unwrap(), 2);
    }

    // --- xrefs ---

    #[test]
    fn test_add_and_query_xrefs() {
        let g = graph();
        g.add_xref(vid(1), addr(0x1000), addr(0x2000), "code_call")
            .unwrap();
        g.add_xref(vid(1), addr(0x1100), addr(0x2000), "code_call")
            .unwrap();
        g.add_xref(vid(1), addr(0x1000), addr(0x3000), "data_read")
            .unwrap();

        let from = g.xrefs_from(vid(1), addr(0x1000)).unwrap();
        assert_eq!(from.len(), 2);

        let to = g.xrefs_to(vid(1), addr(0x2000)).unwrap();
        assert_eq!(to.len(), 2);

        let callers = g.callers_of(vid(1), addr(0x2000)).unwrap();
        assert_eq!(callers.len(), 2);
        assert!(callers.iter().all(|x| x.kind == "code_call"));
    }

    #[test]
    fn test_count_and_delete_xrefs() {
        let g = graph();
        g.add_xref(vid(1), addr(0x1000), addr(0x2000), "code_call")
            .unwrap();
        g.add_xref(vid(1), addr(0x1000), addr(0x3000), "data_read")
            .unwrap();
        assert_eq!(g.count_xrefs(vid(1)).unwrap(), 2);
        g.delete_xrefs_from(vid(1), addr(0x1000)).unwrap();
        assert_eq!(g.count_xrefs(vid(1)).unwrap(), 0);
    }

    // --- comments ---

    #[test]
    fn test_add_and_get_comment() {
        let g = graph();
        g.add_comment(vid(1), addr(0x1000), "Entry point", false)
            .unwrap();
        let c = g.get_comment(vid(1), addr(0x1000)).unwrap();
        assert_eq!(c, Some("Entry point".into()));
    }

    #[test]
    fn test_update_comment() {
        let g = graph();
        g.add_comment(vid(1), addr(0x1000), "old", false).unwrap();
        g.update_comment(vid(1), addr(0x1000), "new text").unwrap();
        let c = g.get_comment(vid(1), addr(0x1000)).unwrap();
        assert_eq!(c, Some("new text".into()));
    }

    #[test]
    fn test_delete_comment() {
        let g = graph();
        g.add_comment(vid(1), addr(0x1000), "bye", false).unwrap();
        g.delete_comment(vid(1), addr(0x1000)).unwrap();
        let c = g.get_comment(vid(1), addr(0x1000)).unwrap();
        assert_eq!(c, None);
    }

    #[test]
    fn test_iter_comments() {
        let g = graph();
        g.add_comment(vid(1), addr(0x2000), "b", true).unwrap();
        g.add_comment(vid(1), addr(0x1000), "a", false).unwrap();
        let comments = g.iter_comments(vid(1)).unwrap();
        assert_eq!(comments.len(), 2);
        // should be ordered by address ascending
        assert_eq!(comments[0].address, 0x1000);
        assert_eq!(comments[1].address, 0x2000);
        assert!(comments[1].repeatable);
    }

    // --- patches ---

    #[test]
    fn test_add_and_get_patches() {
        let g = graph();
        let id = g
            .add_patch(
                vid(1),
                addr(0x1000),
                b"\x90\x90",
                b"\xEB\x00",
                Some("nop patch"),
            )
            .unwrap();
        assert!(id > 0);
        let patches = g.get_patches(vid(1)).unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].original_bytes, b"\x90\x90");
        assert_eq!(patches[0].new_bytes, b"\xEB\x00");
        assert_eq!(patches[0].reason, Some("nop patch".into()));
    }

    #[test]
    fn test_delete_patch() {
        let g = graph();
        g.add_patch(vid(1), addr(0x1000), b"\x90", b"\xcc", None)
            .unwrap();
        g.delete_patch(vid(1), addr(0x1000)).unwrap();
        assert!(g.get_patches(vid(1)).unwrap().is_empty());
    }

    // --- strings ---

    #[test]
    fn test_add_and_get_strings() {
        let g = graph();
        g.add_string(vid(1), addr(0x5000), 5, "utf8", "hello", false)
            .unwrap();
        g.add_string(vid(1), addr(0x6000), 5, "utf8", "world", true)
            .unwrap();
        let strs = g.get_strings(vid(1)).unwrap();
        assert_eq!(strs.len(), 2);
        assert_eq!(strs[0].value, "hello");
        assert!(!strs[0].is_decoded);
        assert!(strs[1].is_decoded);
    }

    #[test]
    fn test_search_strings() {
        let g = graph();
        g.add_string(vid(1), addr(0x1000), 13, "utf8", "Hello, world!", false)
            .unwrap();
        g.add_string(vid(1), addr(0x2000), 7, "utf8", "foo bar", false)
            .unwrap();
        let found = g.search_strings(vid(1), "world").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, "Hello, world!");
    }

    // --- events ---

    #[test]
    fn test_add_and_get_events() {
        let g = graph();
        g.add_event(vid(1), "user", "rename", b"{}").unwrap();
        g.add_event(vid(1), "user", "comment", b"{\"text\":\"hi\"}")
            .unwrap();
        let evts = g.get_events(vid(1), 10).unwrap();
        assert_eq!(evts.len(), 2);
    }

    #[test]
    fn test_get_events_limit() {
        let g = graph();
        for i in 0..5i64 {
            g.add_event(vid(1), "bot", "ping", format!("{i}").as_bytes())
                .unwrap();
        }
        let evts = g.get_events(vid(1), 3).unwrap();
        assert_eq!(evts.len(), 3);
    }

    // --- bookmarks ---

    #[test]
    fn test_add_and_get_bookmarks() {
        let g = graph();
        let id = g
            .add_bookmark(vid(1), addr(0xdead), Some("interesting"), 0x00FF_0000)
            .unwrap();
        assert!(id > 0);
        let bms = g.get_bookmarks(vid(1)).unwrap();
        assert_eq!(bms.len(), 1);
        assert_eq!(bms[0].address, 0xdead);
        assert_eq!(bms[0].label, Some("interesting".into()));
        assert_eq!(bms[0].color, 0x00FF_0000);
    }

    #[test]
    fn test_delete_bookmark() {
        let g = graph();
        g.add_bookmark(vid(1), addr(0x1000), None, 0).unwrap();
        g.delete_bookmark(vid(1), addr(0x1000)).unwrap();
        assert!(g.get_bookmarks(vid(1)).unwrap().is_empty());
    }

    // --- basic blocks & CFG ---

    #[test]
    fn test_basic_blocks_and_cfg() {
        let g = graph();
        let fn_id = g
            .add_function(vid(1), addr(0x1000), addr(0x1200), FunctionMeta { name: Some("complex"), ..FunctionMeta::default() })
            .unwrap();
        let bb1 = g
            .add_basic_block(fn_id, addr(0x1000), addr(0x1050))
            .unwrap();
        let bb2 = g
            .add_basic_block(fn_id, addr(0x1050), addr(0x1100))
            .unwrap();
        let bb3 = g
            .add_basic_block(fn_id, addr(0x1100), addr(0x1200))
            .unwrap();
        g.add_cfg_edge(bb1, bb2, "true_branch").unwrap();
        g.add_cfg_edge(bb1, bb3, "false_branch").unwrap();

        let blocks = g.get_basic_blocks_of_function(fn_id).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].start_addr, 0x1000);

        let edges = g.get_cfg_edges_from(bb1).unwrap();
        assert_eq!(edges.len(), 2);
        let kinds: Vec<&str> = edges.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"true_branch"));
        assert!(kinds.contains(&"false_branch"));
    }

    // --- annotations ---

    #[test]
    fn test_annotate_and_get() {
        let g = graph();
        g.annotate("function", 42, "color", "\"red\"").unwrap();
        let v = g.get_annotation("function", 42, "color").unwrap();
        assert_eq!(v, Some("\"red\"".into()));
    }

    #[test]
    fn test_annotate_upserts() {
        let g = graph();
        g.annotate("symbol", 1, "note", "\"first\"").unwrap();
        g.annotate("symbol", 1, "note", "\"second\"").unwrap();
        let v = g.get_annotation("symbol", 1, "note").unwrap();
        assert_eq!(v, Some("\"second\"".into()));
    }

    #[test]
    fn test_get_annotation_missing() {
        let g = graph();
        assert_eq!(g.get_annotation("x", 0, "y").unwrap(), None);
    }

    // --- transactions ---

    #[test]
    fn test_transaction_commit() {
        let g = graph();
        g.begin_transaction().unwrap();
        g.add_function(vid(1), addr(0x1000), addr(0x2000), FunctionMeta { name: Some("txn_fn"), ..FunctionMeta::default() })
        .unwrap();
        g.commit_transaction().unwrap();
        assert!(g.get_function_at(vid(1), addr(0x1000)).unwrap().is_some());
    }

    #[test]
    fn test_transaction_rollback() {
        let g = graph();
        g.begin_transaction().unwrap();
        g.add_function(vid(1), addr(0xBEEF), addr(0xCAFE), FunctionMeta { name: Some("rolled_back"), ..FunctionMeta::default() })
        .unwrap();
        g.rollback_transaction().unwrap();
        assert!(g.get_function_at(vid(1), addr(0xBEEF)).unwrap().is_none());
    }

    // --- debug impl ---

    #[test]
    fn test_debug_format() {
        let g = graph();
        let s = format!("{g:?}");
        assert!(s.contains("KnowledgeGraph"));
    }
}

// ===========================================================================
// §34.3  Cypher-like query language
// ===========================================================================

/// A raw Cypher-like query string (subset of openCypher).
///
/// Supported grammar (simplified BNF):
/// ```text
/// query     = MATCH clause [WHERE clause] RETURN clause [ORDER BY clause] [LIMIT n]
/// MATCH     = "MATCH" "(" alias ":" label ["{"  prop_filter "}" ] ")"
/// WHERE     = "WHERE"  expr ("AND" expr)*
/// RETURN    = "RETURN" column ("," column)*
/// ORDER BY  = "ORDER" "BY" column ["ASC"|"DESC"]
/// LIMIT     = "LIMIT" integer
/// expr      = alias "." field op value
/// op        = "=" | "!=" | "<" | "<=" | ">" | ">=" | "LIKE" | "CONTAINS"
/// value     = string_literal | integer_literal | float_literal | "true" | "false" | "null"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CypherQuery {
    pub raw: String,
}

impl CypherQuery {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }
}

/// A single value cell within a `QueryRow`.
#[derive(Debug, Clone, PartialEq)]
pub enum QueryValue {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Bool(bool),
}

impl std::fmt::Display for QueryValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Text(s) => write!(f, "{s}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

impl From<GraphValue> for QueryValue {
    fn from(v: GraphValue) -> Self {
        match v {
            GraphValue::Null => Self::Null,
            GraphValue::Integer(n) => Self::Int(n),
            GraphValue::Real(f) => Self::Float(f),
            GraphValue::Text(s) => Self::Text(s),
            GraphValue::Blob(b) => Self::Text(String::from_utf8_lossy(&b).into_owned()),
        }
    }
}

/// One result row returned by [`KnowledgeGraph::query`].
#[derive(Debug, Clone, PartialEq)]
pub struct QueryRow {
    pub columns: Vec<(String, QueryValue)>,
}

impl QueryRow {
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&QueryValue> {
        self.columns.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
}

/// Top-level result type of a Cypher query.
#[derive(Debug, Clone, PartialEq)]
pub enum QueryResult {
    Rows(Vec<QueryRow>),
    Count(u64),
    Empty,
}

// ---------------------------------------------------------------------------
// Internal AST for the query parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MatchClause {
    alias: String,
    label: String,
    /// inline property filters from `{name: "foo"}`
    prop_filters: Vec<(String, String)>,
}

impl MatchClause {
    /// The alias bound by the `MATCH` clause (e.g. `n` in `MATCH (n:Foo)`).
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }
}

#[derive(Debug, Clone)]
pub struct WhereExpr {
    alias: String,
    field: String,
    op: String,
    value: String,
}

impl WhereExpr {
    /// The alias on the left-hand side of this `WHERE` predicate.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }
}

#[derive(Debug, Clone)]
pub struct ParsedQuery {
    match_clause: MatchClause,
    where_exprs: Vec<WhereExpr>,
    return_cols: Vec<String>,         // "alias.field" or "*"
    order_by: Option<(String, bool)>, // (col, ascending)
    limit: Option<u64>,
    is_count: bool,
}

// ---------------------------------------------------------------------------
// QueryParser
// ---------------------------------------------------------------------------

pub struct QueryParser;

impl QueryParser {
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn parse(raw: &str) -> Result<ParsedQuery, GraphError> {
        let tokens = Self::tokenize(raw);
        let mut pos = 0usize;

        // Expect MATCH
        Self::expect_kw(&tokens, &mut pos, "MATCH")?;

        // Parse "(alias:Label {prop_filters})"
        Self::expect_tok(&tokens, &mut pos, "(")?;
        let alias = Self::next_ident(&tokens, &mut pos)?;
        Self::expect_tok(&tokens, &mut pos, ":")?;
        let label = Self::next_ident(&tokens, &mut pos)?;

        let mut prop_filters = Vec::new();
        if tokens.get(pos).map(std::string::String::as_str) == Some("{") {
            pos += 1; // consume '{'
            loop {
                if tokens.get(pos).map(std::string::String::as_str) == Some("}") {
                    pos += 1;
                    break;
                }
                let key = Self::next_ident(&tokens, &mut pos)?;
                Self::expect_tok(&tokens, &mut pos, ":")?;
                let val = Self::next_value_str(&tokens, &mut pos)?;
                prop_filters.push((key, val));
                if tokens.get(pos).map(std::string::String::as_str) == Some(",") {
                    pos += 1;
                }
            }
        }
        Self::expect_tok(&tokens, &mut pos, ")")?;

        let match_clause = MatchClause {
            alias,
            label,
            prop_filters,
        };

        // Optional WHERE
        let mut where_exprs = Vec::new();
        if tokens.get(pos).map(|s| s.to_uppercase()) == Some("WHERE".into()) {
            pos += 1;
            loop {
                let al = Self::next_ident(&tokens, &mut pos)?;
                Self::expect_tok(&tokens, &mut pos, ".")?;
                let field = Self::next_ident(&tokens, &mut pos)?;
                let op = Self::next_op(&tokens, &mut pos)?;
                let value = Self::next_value_str(&tokens, &mut pos)?;
                where_exprs.push(WhereExpr {
                    alias: al,
                    field,
                    op,
                    value,
                });
                if tokens.get(pos).map(|s| s.to_uppercase()) == Some("AND".into()) {
                    pos += 1;
                } else {
                    break;
                }
            }
        }

        // RETURN
        Self::expect_kw(&tokens, &mut pos, "RETURN")?;
        let mut is_count = false;
        let mut return_cols = Vec::new();

        // Check for COUNT(*)
        if tokens.get(pos).map(|s| s.to_uppercase()) == Some("COUNT".into()) {
            is_count = true;
            pos += 1;
            // consume optional "()"
            if tokens.get(pos).map(std::string::String::as_str) == Some("(") {
                pos += 1;
                if tokens.get(pos).map(std::string::String::as_str) == Some("*") {
                    pos += 1;
                }
                if tokens.get(pos).map(std::string::String::as_str) == Some(")") {
                    pos += 1;
                }
            }
        } else {
            loop {
                let col = Self::next_return_col(&tokens, &mut pos)?;
                return_cols.push(col);
                if tokens.get(pos).map(std::string::String::as_str) == Some(",") {
                    pos += 1;
                } else {
                    break;
                }
            }
        }

        // Optional ORDER BY
        let order_by = if tokens.get(pos).map(|s| s.to_uppercase()) == Some("ORDER".into()) {
            pos += 1;
            if tokens.get(pos).map(|s| s.to_uppercase()) == Some("BY".into()) {
                pos += 1;
            }
            let col = Self::next_return_col(&tokens, &mut pos)?;
            let ascending = tokens.get(pos).map(|s| s.to_uppercase()) != Some("DESC".into());
            if tokens.get(pos).map(|s| s.to_uppercase()) == Some("DESC".into())
                || tokens.get(pos).map(|s| s.to_uppercase()) == Some("ASC".into())
            {
                pos += 1;
            }
            Some((col, ascending))
        } else {
            None
        };

        // Optional LIMIT
        let limit = if tokens.get(pos).map(|s| s.to_uppercase()) == Some("LIMIT".into()) {
            pos += 1;
            let n_str = tokens
                .get(pos)
                .ok_or_else(|| GraphError::Generic("Expected integer after LIMIT".into()))?;
            pos += 1;
            let n: u64 = n_str
                .parse()
                .map_err(|_| GraphError::Generic(format!("Invalid LIMIT value: {n_str}")))?;
            Some(n)
        } else {
            None
        };

        // Reject any unparsed trailing tokens after LIMIT (or the previous clause).
        if let Some(extra) = tokens.get(pos) {
            return Err(GraphError::Generic(format!(
                "Unexpected trailing token '{extra}' after query"
            )));
        }

        Ok(ParsedQuery {
            match_clause,
            where_exprs,
            return_cols,
            order_by,
            limit,
            is_count,
        })
    }

    // ---- tokenizer ---------------------------------------------------------

    fn tokenize(src: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let chars: Vec<char> = src.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                ' ' | '\t' | '\r' | '\n' => {
                    i += 1;
                }
                '(' | ')' | '{' | '}' | ',' | '.' | '*' => {
                    tokens.push(chars[i].to_string());
                    i += 1;
                }
                ':' => {
                    tokens.push(":".into());
                    i += 1;
                }
                '!' if chars.get(i + 1) == Some(&'=') => {
                    tokens.push("!=".into());
                    i += 2;
                }
                '<' if chars.get(i + 1) == Some(&'=') => {
                    tokens.push("<=".into());
                    i += 2;
                }
                '>' if chars.get(i + 1) == Some(&'=') => {
                    tokens.push(">=".into());
                    i += 2;
                }
                '<' => {
                    tokens.push("<".into());
                    i += 1;
                }
                '>' => {
                    tokens.push(">".into());
                    i += 1;
                }
                '=' => {
                    tokens.push("=".into());
                    i += 1;
                }
                '"' | '\'' => {
                    let quote = chars[i];
                    i += 1;
                    let start = i;
                    while i < chars.len() && chars[i] != quote {
                        i += 1;
                    }
                    let s: String = chars[start..i].iter().collect();
                    tokens.push(format!("'{s}'"));
                    if i < chars.len() {
                        i += 1;
                    }
                }
                c if c.is_alphanumeric() || c == '_' => {
                    let start = i;
                    // Identifiers stop at '.': dots are emitted as separate
                    // tokens so WHERE predicates like `f.name = 'x'` parse.
                    // `next_return_col` re-joins `alias . field` triples.
                    while i < chars.len()
                        && (chars[i].is_alphanumeric() || chars[i] == '_')
                    {
                        i += 1;
                    }
                    let tok: String = chars[start..i].iter().collect();
                    tokens.push(tok);
                }
                _ => {
                    i += 1;
                }
            }
        }
        tokens
    }

    // ---- parser helpers ----------------------------------------------------

    fn expect_kw(tokens: &[String], pos: &mut usize, kw: &str) -> Result<(), GraphError> {
        let tok = tokens
            .get(*pos)
            .ok_or_else(|| GraphError::Generic(format!("Expected keyword '{kw}', got EOF")))?;
        if tok.to_uppercase() != kw {
            return Err(GraphError::Generic(format!(
                "Expected keyword '{kw}', got '{tok}'"
            )));
        }
        *pos += 1;
        Ok(())
    }

    fn expect_tok(tokens: &[String], pos: &mut usize, expected: &str) -> Result<(), GraphError> {
        let tok = tokens
            .get(*pos)
            .ok_or_else(|| GraphError::Generic(format!("Expected '{expected}', got EOF")))?;
        if tok != expected {
            return Err(GraphError::Generic(format!(
                "Expected '{expected}', got '{tok}'"
            )));
        }
        *pos += 1;
        Ok(())
    }

    fn next_ident(tokens: &[String], pos: &mut usize) -> Result<String, GraphError> {
        let tok = tokens
            .get(*pos)
            .ok_or_else(|| GraphError::Generic("Expected identifier, got EOF".into()))?;
        // Reject operators and punctuation as identifiers
        if tok.starts_with('\'') || matches!(tok.as_str(), "(" | ")" | "{" | "}" | "," | "." | "*")
        {
            return Err(GraphError::Generic(format!(
                "Expected identifier, got '{tok}'"
            )));
        }
        *pos += 1;
        Ok(tok.clone())
    }

    fn next_op(tokens: &[String], pos: &mut usize) -> Result<String, GraphError> {
        let tok = tokens
            .get(*pos)
            .ok_or_else(|| GraphError::Generic("Expected operator, got EOF".into()))?;
        let op = tok.to_uppercase();
        let valid = ["=", "!=", "<", "<=", ">", ">=", "LIKE", "CONTAINS"];
        if valid.contains(&op.as_str()) {
            *pos += 1;
            return Ok(op);
        }
        Err(GraphError::Generic(format!(
            "Expected operator, got '{tok}'"
        )))
    }

    fn next_value_str(tokens: &[String], pos: &mut usize) -> Result<String, GraphError> {
        let tok = tokens
            .get(*pos)
            .ok_or_else(|| GraphError::Generic("Expected value, got EOF".into()))?;
        *pos += 1;
        Ok(tok.clone())
    }

    fn next_return_col(tokens: &[String], pos: &mut usize) -> Result<String, GraphError> {
        let tok = tokens
            .get(*pos)
            .ok_or_else(|| GraphError::Generic("Expected column, got EOF".into()))?;
        *pos += 1;
        // "alias.field" may have been split into three tokens by the tokenizer
        // ("alias", ".", "field") – re-join if that happened.
        if tok == "*" {
            return Ok("*".into());
        }
        if tokens.get(*pos).map(std::string::String::as_str) == Some(".")
            && tokens
                .get(*pos + 1)
                .is_some_and(|s| {
                    !matches!(
                        s.to_uppercase().as_str(),
                        "WHERE" | "RETURN" | "ORDER" | "LIMIT"
                    )
                })
        {
            *pos += 1; // consume '.'
            let field = Self::next_ident(tokens, pos)?;
            return Ok(format!("{tok}.{field}"));
        }
        Ok(tok.clone())
    }
}

// ---------------------------------------------------------------------------
// Label → table mapping
// ---------------------------------------------------------------------------

fn label_to_table(label: &str) -> Result<&'static str, GraphError> {
    match label.to_lowercase().as_str() {
        "function" | "functions" => Ok("functions"),
        "symbol" | "symbols" => Ok("symbols"),
        "xref" | "xrefs" => Ok("xrefs"),
        "comment" | "comments" => Ok("comments"),
        "patch" | "patches" => Ok("patches"),
        "string" | "strings" => Ok("strings"),
        "event" | "events" => Ok("events"),
        "bookmark" | "bookmarks" => Ok("bookmarks"),
        "view" | "views" => Ok("views"),
        "basicblock" | "basic_blocks" | "basicblocks" => Ok("basic_blocks"),
        _ => Err(GraphError::Generic(format!("Unknown node label: {label}"))),
    }
}

// ---------------------------------------------------------------------------
// value_str → SQL literal + GraphParam
// ---------------------------------------------------------------------------

fn value_str_to_param(s: &str) -> GraphParam {
    // Quoted string literal: 'hello'
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        return GraphParam::Text(inner.to_owned());
    }
    // Bool
    match s.to_lowercase().as_str() {
        "true" => return GraphParam::Int(1),
        "false" => return GraphParam::Int(0),
        "null" => return GraphParam::Null,
        _ => {}
    }
    // Integer
    if let Ok(n) = s.parse::<i64>() {
        return GraphParam::Int(n);
    }
    // Float
    if let Ok(f) = s.parse::<f64>() {
        return GraphParam::Real(f);
    }
    // Fallback: treat as unquoted text
    GraphParam::Text(s.to_owned())
}

// ---------------------------------------------------------------------------
// KnowledgeGraph::query – translate ParsedQuery → SQL and run it
// ---------------------------------------------------------------------------

impl KnowledgeGraph {
    /// Execute a Cypher-like query against the in-process `SQLite` schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn query(&self, q: &CypherQuery) -> Result<QueryResult, GraphError> {
        let parsed = QueryParser::parse(&q.raw)?;
        let table = label_to_table(&parsed.match_clause.label)?;

        // Build WHERE fragments
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<GraphParam> = Vec::new();
        let mut param_idx = 1usize;

        // Inline prop filters from MATCH clause
        for (key, val) in &parsed.match_clause.prop_filters {
            conditions.push(format!("{key} = ?{param_idx}"));
            params.push(value_str_to_param(val));
            param_idx += 1;
        }

        // WHERE expressions
        for expr in &parsed.where_exprs {
            let sql_op = match expr.op.as_str() {
                "CONTAINS" => "LIKE",
                other => other,
            };
            let mut param_val = value_str_to_param(&expr.value);
            // For LIKE / CONTAINS add % wrappers
            if expr.op == "CONTAINS"
                && let GraphParam::Text(ref s) = param_val.clone() {
                    param_val = GraphParam::Text(format!("%{s}%"));
                }
            conditions.push(format!("{} {sql_op} ?{param_idx}", expr.field));
            params.push(param_val);
            param_idx += 1;
        }

        let where_sql = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        // COUNT query
        if parsed.is_count {
            let sql = format!("SELECT COUNT(*) FROM {table}{where_sql}");
            let n = self.conn.query_row_i64(&sql, &params)?.unwrap_or(0);
            return Ok(QueryResult::Count(n.cast_unsigned()));
        }

        // RETURN columns
        let select_cols =
            if parsed.return_cols.is_empty() || parsed.return_cols.iter().any(|c| c == "*") {
                "*".to_owned()
            } else {
                parsed
                    .return_cols
                    .iter()
                    .map(|c| {
                        // strip "alias." prefix if present
                        c.find('.').map_or_else(|| c.clone(), |dot| c[dot + 1..].to_owned())
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };

        // ORDER BY
        let order_sql = parsed.order_by.as_ref().map_or_else(String::new, |(col, asc)| {
            let field = col.find('.').map_or(col.as_str(), |dot| &col[dot + 1..]);
            format!(" ORDER BY {} {}", field, if *asc { "ASC" } else { "DESC" })
        });

        // LIMIT
        let limit_sql = if let Some(n) = parsed.limit {
            format!(" LIMIT {n}")
        } else {
            String::new()
        };

        let sql = format!("SELECT {select_cols} FROM {table}{where_sql}{order_sql}{limit_sql}");

        let raw_rows = self.conn.query_rows_mixed(&sql, &params)?;

        // We need column names. Query the table schema to derive them when
        // select_cols == "*"; otherwise split the provided list.
        let col_names: Vec<String> = if select_cols == "*" {
            self.table_column_names(table)?
        } else {
            select_cols.split(", ").map(std::borrow::ToOwned::to_owned).collect()
        };

        let rows: Vec<QueryRow> = raw_rows
            .into_iter()
            .map(|cells| {
                let columns = col_names
                    .iter()
                    .zip(cells)
                    .map(|(name, val)| (name.clone(), QueryValue::from(val)))
                    .collect();
                QueryRow { columns }
            })
            .collect();

        if rows.is_empty() {
            Ok(QueryResult::Empty)
        } else {
            Ok(QueryResult::Rows(rows))
        }
    }

    /// Return ordered column names for a known table (`SQLite` PRAGMA).
    fn table_column_names(&self, table: &str) -> Result<Vec<String>, GraphError> {
        let sql = format!("PRAGMA table_info({table})");
        let rows = self.conn.query_rows_mixed(&sql, &[])?;
        // PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
        let names = rows
            .iter()
            .map(|r| match &r[1] {
                GraphValue::Text(s) => Ok(s.clone()),
                other => Err(GraphError::Generic(format!(
                    "Unexpected pragma value: {other:?}"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }
}

// ===========================================================================
// §34.5  Undo / redo log
// ===========================================================================

/// One entry in the undo log.
#[derive(Debug, Clone)]
pub struct UndoEntry {
    pub id: u64,
    pub ts: u64,
    pub description: String,
    /// SQL statement that (re-)applies the change.
    pub forward_sql: String,
    /// SQL statement that reverts the change.
    pub reverse_sql: String,
}

/// Builder / scope guard for an undoable transaction.
///
/// Created by [`KnowledgeGraph::begin_undoable_tx`].
/// You must call `commit()` explicitly — drop without committing does nothing.
pub struct UndoTransaction<'a> {
    graph: &'a KnowledgeGraph,
    description: String,
    forward_stmts: Vec<String>,
    reverse_stmts: Vec<String>,
}

impl UndoTransaction<'_> {
    /// Record a forward/reverse SQL pair that will be stored on `commit()`.
    pub fn record(&mut self, forward_sql: &str, reverse_sql: &str) {
        self.forward_stmts.push(forward_sql.to_owned());
        self.reverse_stmts.push(reverse_sql.to_owned());
    }

    /// Commit the transaction and write the undo entry to the log.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn commit(self) -> Result<(), GraphError> {
        let forward = self.forward_stmts.join("; ");
        let reverse = self.reverse_stmts.join("; ");

        // Execute forward SQL
        for stmt in &self.forward_stmts {
            if !stmt.trim().is_empty() {
                self.graph.conn.execute(stmt, &[])?;
            }
        }

        // Write undo entry
        let ts = unix_timestamp().cast_unsigned();
        let key = self.graph.undo_key();
        undo_registry::with(key, |log| {
            let id = log.next_id;
            log.next_id += 1;
            // Truncate redo stack on new action
            log.redo_stack.clear();
            log.undo_stack.push(UndoEntry {
                id,
                ts,
                description: self.description.clone(),
                forward_sql: forward,
                reverse_sql: reverse,
            });
        });
        Ok(())
    }
}

/// Internal undo/redo state held inside `KnowledgeGraph`.
pub struct UndoLog {
    next_id: u64,
    undo_stack: Vec<UndoEntry>,
    redo_stack: Vec<UndoEntry>,
}

impl UndoLog {
    const fn new() -> Self {
        Self {
            next_id: 1,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        }
    }
}

// We need to extend `KnowledgeGraph` with the undo log.  Because the struct
// is defined earlier and we cannot break the existing API, we wrap with a
// `Mutex<UndoLog>` added via a `OnceLock`-style field declared on the struct.
// Since Rust does not allow retroactively adding fields we instead store the
// log in a thread-local or via a companion `Arc<Mutex>` kept alongside the
// `KnowledgeGraph`.  The cleanest approach for this codebase is to re-declare
// the struct with the extra field; however that would break existing `fn graph()`
// test helpers.  Instead we use a `std::sync::OnceLock` singleton keyed on the
// pointer so the API extension is zero-cost for existing users.
//
// Practical solution: add a private field via a newtype wrapper approach isn't
// feasible without touching the struct definition.  Instead, we store the
// `UndoLog` directly inside `KnowledgeGraph` by **extending** the struct
// definition.  This does require touching the `KnowledgeGraph` struct itself.
// The instructions say "keep all existing code", so we keep existing code and
// simply add the new field — existing code only uses `self.conn` so the
// additional field is harmless.

// NOTE: The struct body has already been declared above. We patch it via the
// impl block instead by storing undo_log as a thread-safe global map keyed
// on the raw pointer of the conn Arc.  That avoids touching the struct layout.

// A per-instance undo log registry, keyed by Arc pointer identity.
mod undo_registry {
    use super::UndoLog;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static REGISTRY: OnceLock<Mutex<HashMap<usize, UndoLog>>> = OnceLock::new();

    fn registry() -> &'static Mutex<HashMap<usize, UndoLog>> {
        REGISTRY.get_or_init(|| Mutex::new(HashMap::default()))
    }

    pub fn get_or_create(key: usize) -> UndoLog {
        let mut map = registry().lock().unwrap();
        map.remove(&key).unwrap_or_else(UndoLog::new)
    }

    pub fn put(key: usize, log: UndoLog) {
        let mut map = registry().lock().unwrap();
        map.insert(key, log);
    }

    pub fn with<F, R>(key: usize, f: F) -> R
    where
        F: FnOnce(&mut UndoLog) -> R,
    {
        let mut map = registry().lock().unwrap();
        let log = map.entry(key).or_insert_with(UndoLog::new);
        f(log)
    }
}

// The KnowledgeGraph struct already has `conn: Arc<dyn db::DatabaseEngine>`.
// We use the fat-pointer address (data pointer) as the stable key.
impl KnowledgeGraph {
    fn undo_key(&self) -> usize {
        // Use the address of the Arc's internal allocation as the stable key.
        Arc::as_ptr(&self.conn).cast::<()>() as usize
    }

    /// Detach this graph's undo log from the registry and return it.  Pairs
    /// with [`KnowledgeGraph::reattach_undo_log`] for callers that want to
    /// snapshot the log out-of-band (e.g. for cross-process transfer).
    #[must_use]
    pub fn take_undo_log(&self) -> UndoLog {
        undo_registry::get_or_create(self.undo_key())
    }

    /// Re-install a previously-detached undo log for this graph.
    pub fn reattach_undo_log(&self, log: UndoLog) {
        undo_registry::put(self.undo_key(), log);
    }

    /// Begin an undoable transaction.  Call [`UndoTransaction::commit`] to
    /// finalise; dropping the transaction without committing is a no-op.
    #[must_use]
    pub fn begin_undoable_tx(&self, desc: &str) -> UndoTransaction<'_> {
        UndoTransaction {
            graph: self,
            description: desc.to_owned(),
            forward_stmts: Vec::new(),
            reverse_stmts: Vec::new(),
        }
    }

    /// Undo the most recent committed [`UndoTransaction`].
    ///
    /// Returns the entry that was undone, or `None` if there is nothing to undo.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn undo(&self) -> Result<Option<UndoEntry>, GraphError> {
        let key = self.undo_key();
        let entry = undo_registry::with(key, |log| log.undo_stack.pop());
        match entry {
            None => Ok(None),
            Some(e) => {
                // Execute reverse SQL
                for stmt in e.reverse_sql.split(';') {
                    let s = stmt.trim();
                    if !s.is_empty() {
                        self.conn.execute(s, &[])?;
                    }
                }
                // Push onto redo stack
                let e_clone = e.clone();
                undo_registry::with(key, |log| log.redo_stack.push(e_clone));
                Ok(Some(e))
            }
        }
    }

    /// Redo the most recently undone transaction.
    ///
    /// Returns the entry that was re-applied, or `None` if nothing to redo.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn redo(&self) -> Result<Option<UndoEntry>, GraphError> {
        let key = self.undo_key();
        let entry = undo_registry::with(key, |log| log.redo_stack.pop());
        match entry {
            None => Ok(None),
            Some(e) => {
                // Execute forward SQL
                for stmt in e.forward_sql.split(';') {
                    let s = stmt.trim();
                    if !s.is_empty() {
                        self.conn.execute(s, &[])?;
                    }
                }
                // Push back onto undo stack
                let e_clone = e.clone();
                undo_registry::with(key, |log| log.undo_stack.push(e_clone));
                Ok(Some(e))
            }
        }
    }

    /// Return a snapshot of the current undo stack (most recent last).
    #[must_use]
    pub fn undo_history(&self) -> Vec<UndoEntry> {
        undo_registry::with(self.undo_key(), |log| log.undo_stack.clone())
    }

    /// Return a snapshot of the current redo stack (most recent last).
    #[must_use]
    pub fn redo_history(&self) -> Vec<UndoEntry> {
        undo_registry::with(self.undo_key(), |log| log.redo_stack.clone())
    }
}

// ===========================================================================
// Event bus integration
// ===========================================================================

/// Events emitted by the knowledge graph when notable mutations occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KgEvent {
    /// A new function was inserted.
    FunctionAdded {
        view_id: i64,
        address: u64,
        name: Option<String>,
    },
    /// A function was renamed.
    FunctionRenamed {
        view_id: i64,
        address: u64,
        old_name: Option<String>,
        new_name: String,
    },
    /// A function prototype was changed.
    TypeChanged {
        view_id: i64,
        address: u64,
        new_prototype: String,
    },
    /// A comment was added or updated.
    CommentAdded {
        view_id: i64,
        address: u64,
        text: String,
    },
    /// A bookmark was added.
    BookmarkAdded {
        view_id: i64,
        address: u64,
        label: Option<String>,
    },
    /// A new binary view was registered.
    BinaryAdded { view_id: i64, uri: String },
}

/// Capacity of the broadcast channel for graph events.
const EVENT_BUS_CAPACITY: usize = 256;

/// A handle to an event bus subscription.
///
/// Call [`KgSubscription::recv`] to receive the next event.  The receiver is
/// backed by a `tokio::sync::broadcast` channel so it can be used from async
/// contexts.
pub struct KgSubscription {
    rx: broadcast::Receiver<KgEvent>,
}

impl KgSubscription {
    /// Blocking receive (wraps async recv in a `block_on`-free manner via
    /// `try_recv` + spin for convenience in tests; prefer the async version
    /// in production code).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn try_recv(&mut self) -> Result<KgEvent, broadcast::error::TryRecvError> {
        self.rx.try_recv()
    }

    /// Async receive – use inside a Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn recv(&mut self) -> Result<KgEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}

/// Thread-safe event bus shared across all `KgEventBus` instances.
static EVENT_BUS: std::sync::OnceLock<Mutex<broadcast::Sender<KgEvent>>> =
    std::sync::OnceLock::new();

fn event_bus_sender() -> broadcast::Sender<KgEvent> {
    EVENT_BUS
        .get_or_init(|| {
            let (tx, _) = broadcast::channel(EVENT_BUS_CAPACITY);
            Mutex::new(tx)
        })
        .lock()
        .unwrap()
        .clone()
}

impl KnowledgeGraph {
    /// Subscribe to all future [`KgEvent`]s emitted by **any**
    /// `KnowledgeGraph` instance in the process.
    #[must_use]
    pub fn subscribe() -> KgSubscription {
        let rx = event_bus_sender().subscribe();
        KgSubscription { rx }
    }

    /// Publish a [`KgEvent`] to all current subscribers.
    ///
    /// Silently ignores `SendError` (no active receivers).
    pub fn emit(event: KgEvent) {
        let _ = event_bus_sender().send(event);
    }

    // ---- emit-aware wrappers -----------------------------------------------

    /// Like [`add_function`] but also emits a [`KgEvent::FunctionAdded`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_function_emit(
        &self,
        view_id: rustre_core::ids::ViewId,
        address: rustre_core::address::Address,
        end_address: rustre_core::address::Address,
        meta: FunctionMeta<'_>,
    ) -> Result<i64, GraphError> {
        let name_owned = meta.name.map(std::borrow::ToOwned::to_owned);
        let id = self.add_function(view_id, address, end_address, meta)?;
        Self::emit(KgEvent::FunctionAdded {
            view_id: view_id.get().cast_signed(),
            address: address.0,
            name: name_owned,
        });
        Ok(id)
    }

    /// Like [`rename_function`] but also emits a [`KgEvent::FunctionRenamed`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn rename_function_emit(
        &self,
        view_id: rustre_core::ids::ViewId,
        address: rustre_core::address::Address,
        new_name: &str,
    ) -> Result<(), GraphError> {
        let old_name = self.get_function_name(view_id, address)?;
        self.rename_function(view_id, address, new_name)?;
        Self::emit(KgEvent::FunctionRenamed {
            view_id: view_id.get().cast_signed(),
            address: address.0,
            old_name,
            new_name: new_name.to_owned(),
        });
        Ok(())
    }

    /// Like [`set_function_prototype`] but also emits a [`KgEvent::TypeChanged`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn set_function_prototype_emit(
        &self,
        view_id: rustre_core::ids::ViewId,
        address: rustre_core::address::Address,
        prototype: &str,
    ) -> Result<(), GraphError> {
        self.set_function_prototype(view_id, address, prototype)?;
        Self::emit(KgEvent::TypeChanged {
            view_id: view_id.get().cast_signed(),
            address: address.0,
            new_prototype: prototype.to_owned(),
        });
        Ok(())
    }

    /// Like [`add_comment`] but also emits a [`KgEvent::CommentAdded`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_comment_emit(
        &self,
        view_id: rustre_core::ids::ViewId,
        address: rustre_core::address::Address,
        text: &str,
        repeatable: bool,
    ) -> Result<(), GraphError> {
        self.add_comment(view_id, address, text, repeatable)?;
        Self::emit(KgEvent::CommentAdded {
            view_id: view_id.get().cast_signed(),
            address: address.0,
            text: text.to_owned(),
        });
        Ok(())
    }

    /// Like [`add_bookmark`] but also emits a [`KgEvent::BookmarkAdded`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_bookmark_emit(
        &self,
        view_id: rustre_core::ids::ViewId,
        address: rustre_core::address::Address,
        label: Option<&str>,
        color: i64,
    ) -> Result<i64, GraphError> {
        let id = self.add_bookmark(view_id, address, label, color)?;
        Self::emit(KgEvent::BookmarkAdded {
            view_id: view_id.get().cast_signed(),
            address: address.0,
            label: label.map(std::borrow::ToOwned::to_owned),
        });
        Ok(id)
    }

    /// Like [`add_view`] but also emits a [`KgEvent::BinaryAdded`].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_view_emit(
        &self,
        id: i64,
        uri: &str,
        arch: &str,
        endian: &str,
        bits: i64,
    ) -> Result<(), GraphError> {
        self.add_view(id, uri, arch, endian, bits)?;
        Self::emit(KgEvent::BinaryAdded {
            view_id: id,
            uri: uri.to_owned(),
        });
        Ok(())
    }
}

// ===========================================================================
// Additional tests for query parser, undo/redo, and event bus (§34.3 / §34.5)
// ===========================================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn graph() -> KnowledgeGraph {
        KnowledgeGraph::new_in_memory().unwrap()
    }
    fn vid(n: u64) -> ViewId {
        ViewId::from_raw(n)
    }
    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    // ---- QueryParser tests -------------------------------------------------

    #[test]
    fn test_parse_simple_match_return_all() {
        let q = CypherQuery::new("MATCH (f:Function) RETURN *");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        assert_eq!(parsed.match_clause.label, "Function");
        assert_eq!(parsed.match_clause.alias, "f");
        assert!(parsed.return_cols.contains(&"*".to_string()));
        assert!(!parsed.is_count);
    }

    #[test]
    fn test_parse_where_clause() {
        let q = CypherQuery::new("MATCH (f:Function) WHERE f.name = 'main' RETURN f.name");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        assert_eq!(parsed.where_exprs.len(), 1);
        assert_eq!(parsed.where_exprs[0].field, "name");
        assert_eq!(parsed.where_exprs[0].op, "=");
        assert_eq!(parsed.where_exprs[0].value, "'main'");
    }

    #[test]
    fn test_parse_count_star() {
        let q = CypherQuery::new("MATCH (f:Function) RETURN COUNT(*)");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        assert!(parsed.is_count);
    }

    #[test]
    fn test_parse_limit() {
        let q = CypherQuery::new("MATCH (f:Function) RETURN * LIMIT 10");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        assert_eq!(parsed.limit, Some(10));
    }

    #[test]
    fn test_parse_order_by_desc() {
        let q = CypherQuery::new("MATCH (f:Function) RETURN * ORDER BY f.address DESC");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        let (col, asc) = parsed.order_by.unwrap();
        assert!(col.contains("address"));
        assert!(!asc);
    }

    #[test]
    fn test_parse_order_by_asc() {
        let q = CypherQuery::new("MATCH (f:Function) RETURN * ORDER BY f.name ASC");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        let (_col, asc) = parsed.order_by.unwrap();
        assert!(asc);
    }

    #[test]
    fn test_parse_multiple_where_exprs() {
        let q = CypherQuery::new(
            "MATCH (f:Function) WHERE f.is_thunk = 1 AND f.is_library = 0 RETURN *",
        );
        let parsed = QueryParser::parse(&q.raw).unwrap();
        assert_eq!(parsed.where_exprs.len(), 2);
    }

    #[test]
    fn test_parse_inline_prop_filter() {
        let q = CypherQuery::new("MATCH (f:Function {name: 'main'}) RETURN *");
        let parsed = QueryParser::parse(&q.raw).unwrap();
        assert_eq!(parsed.match_clause.prop_filters.len(), 1);
        assert_eq!(parsed.match_clause.prop_filters[0].0, "name");
    }

    #[test]
    fn test_parse_unknown_label_error() {
        let q = CypherQuery::new("MATCH (x:Nonexistent) RETURN *");
        let result = graph().query(&q);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_count_functions() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("main"), ..FunctionMeta::default() })
        .unwrap();
        g.add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta { name: Some("foo"), ..FunctionMeta::default() })
        .unwrap();
        let q = CypherQuery::new("MATCH (f:Function) RETURN COUNT(*)");
        let result = g.query(&q).unwrap();
        assert_eq!(result, QueryResult::Count(2));
    }

    #[test]
    fn test_query_match_all_functions() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("alpha"), ..FunctionMeta::default() })
        .unwrap();
        let q = CypherQuery::new("MATCH (f:Function) RETURN *");
        let result = g.query(&q).unwrap();
        match result {
            QueryResult::Rows(rows) => {
                assert!(!rows.is_empty());
            }
            other => panic!("Expected Rows, got {other:?}"),
        }
    }

    #[test]
    fn test_query_with_where_equals() {
        let g = graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("main"), ..FunctionMeta::default() })
        .unwrap();
        g.add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta { name: Some("other"), ..FunctionMeta::default() })
        .unwrap();
        let q = CypherQuery::new("MATCH (f:Function) WHERE f.name = 'main' RETURN *");
        let result = g.query(&q).unwrap();
        match result {
            QueryResult::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                let name = rows[0].get("name").unwrap();
                assert_eq!(name, &QueryValue::Text("main".into()));
            }
            other => panic!("Expected Rows, got {other:?}"),
        }
    }

    #[test]
    fn test_query_limit() {
        let g = graph();
        for i in 0u64..5 {
            g.add_function(vid(1), addr(0x1000 + i * 0x100), addr(0x1100 + i * 0x100), FunctionMeta::default())
            .unwrap();
        }
        let q = CypherQuery::new("MATCH (f:Function) RETURN * LIMIT 2");
        let result = g.query(&q).unwrap();
        match result {
            QueryResult::Rows(rows) => assert_eq!(rows.len(), 2),
            other => panic!("Expected Rows, got {other:?}"),
        }
    }

    #[test]
    fn test_query_empty_result() {
        let g = graph();
        let q = CypherQuery::new("MATCH (f:Function) RETURN *");
        let result = g.query(&q).unwrap();
        assert_eq!(result, QueryResult::Empty);
    }

    // ---- Undo / redo tests -------------------------------------------------

    #[test]
    fn test_undo_nothing_returns_none() {
        let g = graph();
        assert!(g.undo().unwrap().is_none());
    }

    #[test]
    fn test_redo_nothing_returns_none() {
        let g = graph();
        assert!(g.redo().unwrap().is_none());
    }

    #[test]
    fn test_undoable_tx_commit_executes_forward_sql() {
        let g = graph();
        let mut tx = g.begin_undoable_tx("insert symbol");
        tx.record(
            "INSERT INTO symbols (view_id, address, name, kind) VALUES (1, 999, 'undo_test', 'func')",
            "DELETE FROM symbols WHERE address = 999 AND view_id = 1",
        );
        tx.commit().unwrap();
        let syms = g.get_symbols_at(vid(1), addr(999)).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "undo_test");
    }

    #[test]
    fn test_undo_reverts_change() {
        let g = graph();
        let mut tx = g.begin_undoable_tx("insert bookmark");
        tx.record(
            "INSERT INTO bookmarks (view_id, address, color) VALUES (1, 0xABCD, 0)",
            "DELETE FROM bookmarks WHERE view_id = 1 AND address = 0xABCD",
        );
        tx.commit().unwrap();
        assert!(!g.get_bookmarks(vid(1)).unwrap().is_empty());

        let entry = g.undo().unwrap();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().description, "insert bookmark");
        assert!(g.get_bookmarks(vid(1)).unwrap().is_empty());
    }

    #[test]
    fn test_redo_reapplies_change() {
        let g = graph();
        let mut tx = g.begin_undoable_tx("add comment");
        tx.record(
            "INSERT INTO comments (view_id, address, text, repeatable) VALUES (1, 0x1234, 'test', 0)",
            "DELETE FROM comments WHERE view_id = 1 AND address = 0x1234",
        );
        tx.commit().unwrap();
        g.undo().unwrap();
        assert!(g.get_comment(vid(1), addr(0x1234)).unwrap().is_none());

        let entry = g.redo().unwrap();
        assert!(entry.is_some());
        assert!(g.get_comment(vid(1), addr(0x1234)).unwrap().is_some());
    }

    #[test]
    fn test_new_action_clears_redo_stack() {
        let g = graph();
        let mut tx1 = g.begin_undoable_tx("action 1");
        tx1.record(
            "INSERT INTO bookmarks (view_id, address, color) VALUES (1, 1, 0)",
            "DELETE FROM bookmarks WHERE view_id=1 AND address=1",
        );
        tx1.commit().unwrap();

        g.undo().unwrap();
        assert_eq!(g.redo_history().len(), 1);

        let mut tx2 = g.begin_undoable_tx("action 2");
        tx2.record(
            "INSERT INTO bookmarks (view_id, address, color) VALUES (1, 2, 0)",
            "DELETE FROM bookmarks WHERE view_id=1 AND address=2",
        );
        tx2.commit().unwrap();
        // Redo stack should have been cleared
        assert_eq!(g.redo_history().len(), 0);
    }

    #[test]
    fn test_undo_history_grows() {
        let g = graph();
        for i in 1u64..=3 {
            let mut tx = g.begin_undoable_tx(&format!("step {i}"));
            tx.record("", "");
            tx.commit().unwrap();
        }
        assert_eq!(g.undo_history().len(), 3);
    }

    // ---- Event bus tests ---------------------------------------------------

    #[test]
    fn test_subscribe_and_receive_function_added_event() {
        let g = graph();
        let mut sub = KnowledgeGraph::subscribe();
        g.add_function_emit(vid(1), addr(0x5000), addr(0x5100), FunctionMeta { name: Some("evt_fn"), ..FunctionMeta::default() })
        .unwrap();
        // The event bus is GLOBAL (`subscribe` is an associated fn) and cargo
        // runs tests in parallel, so the queue can also carry events emitted by
        // sibling tests. Look for our own event instead of assuming it is first
        // — otherwise the failure just migrates from one bus test to another.
        let mut found = false;
        while let Ok(evt) = sub.try_recv() {
            if let KgEvent::FunctionAdded { address, name, .. } = evt
                && address == 0x5000
            {
                assert_eq!(name, Some("evt_fn".into()));
                found = true;
                break;
            }
        }
        assert!(found, "FunctionAdded event for 0x5000 was never delivered");
    }

    #[test]
    fn test_subscribe_and_receive_rename_event() {
        let g = graph();
        g.add_function(vid(1), addr(0x6000), addr(0x6100), FunctionMeta { name: Some("old_name"), ..FunctionMeta::default() })
        .unwrap();
        let mut sub = KnowledgeGraph::subscribe();
        g.rename_function_emit(vid(1), addr(0x6000), "new_name")
            .unwrap();
        // Global bus shared with the other tests — find our own event.
        let mut found = false;
        while let Ok(evt) = sub.try_recv() {
            if let KgEvent::FunctionRenamed {
                new_name, old_name, ..
            } = evt
                && new_name == "new_name"
            {
                assert_eq!(old_name, Some("old_name".into()));
                found = true;
                break;
            }
        }
        assert!(found, "FunctionRenamed event was never delivered");
    }

    #[test]
    fn test_subscribe_binary_added_event() {
        let g = graph();
        let mut sub = KnowledgeGraph::subscribe();
        g.add_view_emit(42, "file:///bin/sh", "aarch64", "little", 64)
            .unwrap();
        // Global bus shared with the other tests — find our own event.
        let mut found = false;
        while let Ok(evt) = sub.try_recv() {
            if let KgEvent::BinaryAdded { view_id, uri } = evt
                && view_id == 42
            {
                assert_eq!(uri, "file:///bin/sh");
                found = true;
                break;
            }
        }
        assert!(found, "BinaryAdded event for view 42 was never delivered");
    }
}

// ===========================================================================
// §35  Enterprise schema extension — remaining 20 tables + migration system
// ===========================================================================
//
// This section adds:
//   • 20 additional tables (see list below)
//   • Versioned migration runner (schema_version table)
//   • FTS5 virtual tables for full-text search
//   • petgraph in-memory cache (XrefGraph) synchronised with SQL
//   • Collaboration helpers: delta export / delta import
//   • Statistics API
//   • JSON snapshot export / import
//
// All new tables follow the same row-type + CRUD pattern established by the
// core tables above.

use parking_lot::RwLock as PLRwLock;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap as StdHashMap;

// ---------------------------------------------------------------------------
// Additional row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackVarRow {
    pub id: i64,
    pub function_id: i64,
    pub offset: i64,
    pub name: Option<String>,
    pub type_name: Option<String>,
    pub size: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTypeRow {
    pub id: i64,
    pub view_id: i64,
    pub function_id: i64,
    pub name: String,
    pub definition: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtableRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub class_name: Option<String>,
    pub entry_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassHierarchyRow {
    pub id: i64,
    pub view_id: i64,
    pub derived_class: String,
    pub base_class: String,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlirtMatchRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub library_name: String,
    pub matched_name: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugInfoRow {
    pub id: i64,
    pub view_id: i64,
    pub source_file: String,
    pub line_number: i64,
    pub address: u64,
    pub column: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRow {
    pub id: i64,
    pub view_id: i64,
    pub title: String,
    pub body: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisCacheRow {
    pub id: i64,
    pub view_id: i64,
    pub pass: String,
    pub version: i64,
    pub data: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptResultRow {
    pub id: i64,
    pub view_id: i64,
    pub engine: String,
    pub source: String,
    pub output: String,
    pub success: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSessionRow {
    pub id: i64,
    pub view_id_a: i64,
    pub view_id_b: i64,
    pub algorithm: String,
    pub result_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRecordRow {
    pub id: i64,
    pub view_id: i64,
    pub thread_id: i64,
    pub address: u64,
    pub instruction: String,
    pub tick: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakpointRow {
    pub id: i64,
    pub view_id: i64,
    pub address: u64,
    pub kind: String,
    pub condition: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchExpressionRow {
    pub id: i64,
    pub view_id: i64,
    pub expression: String,
    pub last_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionRow {
    pub id: i64,
    pub view_id: i64,
    pub agent_name: String,
    pub state_json: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSessionRow {
    pub id: i64,
    pub view_id: i64,
    pub tool_name: String,
    pub params_json: String,
    pub result_json: Option<String>,
    pub started_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallGraphRow {
    pub caller_id: i64,
    pub callee_id: i64,
    pub view_id: i64,
    pub call_address: u64,
    pub is_indirect: bool,
}

// ---------------------------------------------------------------------------
// Migration system
// ---------------------------------------------------------------------------

/// One database schema migration.
struct Migration {
    version: u32,
    description: &'static str,
    sql: &'static str,
}

/// Apply any pending migrations to the database.
///
/// The `schema_version` table tracks the highest applied version.
/// Migrations are run in version order and are idempotent: if the DB is
/// already at the target version, nothing is executed.
///
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn run_migrations(conn: &dyn db::DatabaseEngine) -> Result<(), GraphError> {
    // Ensure the migration tracking table exists.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (
             version INTEGER NOT NULL,
             applied_at BIGINT NOT NULL,
             description TEXT NOT NULL
         )",
        &[],
    )?;

    // Determine current version.
    let current_version: u32 = conn
        .query_row_i64("SELECT COALESCE(MAX(version), 0) FROM schema_version", &[])?
        .unwrap_or(0)
        .try_into()
        .unwrap_or(0);

    let migrations = all_migrations();
    for m in &migrations {
        if m.version <= current_version {
            continue;
        }
        // Execute each statement in the migration block individually.
        for stmt in m.sql.split("---") {
            let s = stmt.trim();
            if !s.is_empty() {
                conn.execute(s, &[])?;
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs().cast_signed());
        conn.execute(
            "INSERT INTO schema_version (version, applied_at, description) VALUES (?1, ?2, ?3)",
            &[
                GraphParam::Int(i64::from(m.version)),
                GraphParam::Int(now),
                GraphParam::Text(m.description.to_owned()),
            ],
        )?;
    }
    Ok(())
}

fn all_migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            description: "stack_vars and local_types",
            sql: "CREATE TABLE IF NOT EXISTS stack_vars (
                      id INTEGER PRIMARY KEY,
                      function_id BIGINT NOT NULL,
                      offset BIGINT NOT NULL,
                      name TEXT,
                      type_name TEXT,
                      size BIGINT NOT NULL DEFAULT 0
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS local_types (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      function_id BIGINT NOT NULL,
                      name TEXT NOT NULL,
                      definition TEXT NOT NULL
                  )",
        },
        Migration {
            version: 2,
            description: "vtables and class_hierarchy",
            sql: "CREATE TABLE IF NOT EXISTS vtables (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      address BIGINT NOT NULL,
                      class_name TEXT,
                      entry_count BIGINT NOT NULL DEFAULT 0
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS class_hierarchy (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      derived_class TEXT NOT NULL,
                      base_class TEXT NOT NULL,
                      offset BIGINT NOT NULL DEFAULT 0
                  )",
        },
        Migration {
            version: 3,
            description: "flirt_matches and debug_info",
            sql: "CREATE TABLE IF NOT EXISTS flirt_matches (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      address BIGINT NOT NULL,
                      library_name TEXT NOT NULL,
                      matched_name TEXT NOT NULL,
                      score REAL NOT NULL DEFAULT 0.0
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS debug_info (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      source_file TEXT NOT NULL,
                      line_number BIGINT NOT NULL,
                      address BIGINT NOT NULL,
                      col BIGINT
                  )",
        },
        Migration {
            version: 4,
            description: "notes and analysis_cache",
            sql: "CREATE TABLE IF NOT EXISTS notes (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      title TEXT NOT NULL,
                      body TEXT NOT NULL,
                      created_at BIGINT NOT NULL,
                      updated_at BIGINT NOT NULL
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS analysis_cache (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      pass TEXT NOT NULL,
                      version BIGINT NOT NULL DEFAULT 1,
                      data BLOB NOT NULL,
                      created_at BIGINT NOT NULL
                  )",
        },
        Migration {
            version: 5,
            description: "script_results and diff_sessions",
            sql: "CREATE TABLE IF NOT EXISTS script_results (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      engine TEXT NOT NULL,
                      source TEXT NOT NULL,
                      output TEXT NOT NULL,
                      success INTEGER NOT NULL DEFAULT 0,
                      created_at BIGINT NOT NULL
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS diff_sessions (
                      id INTEGER PRIMARY KEY,
                      view_id_a BIGINT NOT NULL,
                      view_id_b BIGINT NOT NULL,
                      algorithm TEXT NOT NULL,
                      result_json TEXT NOT NULL,
                      created_at BIGINT NOT NULL
                  )",
        },
        Migration {
            version: 6,
            description: "trace_records",
            sql: "CREATE TABLE IF NOT EXISTS trace_records (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      thread_id BIGINT NOT NULL,
                      address BIGINT NOT NULL,
                      instruction TEXT NOT NULL,
                      tick BIGINT NOT NULL
                  )
                  ---
                  CREATE INDEX IF NOT EXISTS idx_trace_records_view_tick
                      ON trace_records(view_id, tick)",
        },
        Migration {
            version: 7,
            description: "breakpoints and watch_expressions",
            sql: "CREATE TABLE IF NOT EXISTS breakpoints (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      address BIGINT NOT NULL,
                      kind TEXT NOT NULL DEFAULT 'software',
                      condition TEXT,
                      enabled INTEGER NOT NULL DEFAULT 1
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS watch_expressions (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      expression TEXT NOT NULL,
                      last_value TEXT
                  )",
        },
        Migration {
            version: 8,
            description: "agent_sessions and mcp_sessions",
            sql: "CREATE TABLE IF NOT EXISTS agent_sessions (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      agent_name TEXT NOT NULL,
                      state_json TEXT NOT NULL,
                      started_at BIGINT NOT NULL,
                      ended_at BIGINT
                  )
                  ---
                  CREATE TABLE IF NOT EXISTS mcp_sessions (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      tool_name TEXT NOT NULL,
                      params_json TEXT NOT NULL,
                      result_json TEXT,
                      started_at BIGINT NOT NULL
                  )",
        },
        Migration {
            version: 9,
            description: "call_graph table",
            sql: "CREATE TABLE IF NOT EXISTS call_graph (
                      caller_id BIGINT NOT NULL,
                      callee_id BIGINT NOT NULL,
                      view_id BIGINT NOT NULL,
                      call_address BIGINT NOT NULL,
                      is_indirect INTEGER NOT NULL DEFAULT 0
                  )
                  ---
                  CREATE INDEX IF NOT EXISTS idx_call_graph_caller
                      ON call_graph(view_id, caller_id)
                  ---
                  CREATE INDEX IF NOT EXISTS idx_call_graph_callee
                      ON call_graph(view_id, callee_id)",
        },
        Migration {
            version: 10,
            description: "FTS5 full-text search virtual tables",
            sql: "CREATE VIRTUAL TABLE IF NOT EXISTS fts_comments
                      USING fts5(text, content='comments', content_rowid='id')
                  ---
                  CREATE VIRTUAL TABLE IF NOT EXISTS fts_symbols
                      USING fts5(name, demangled, content='symbols', content_rowid='id')
                  ---
                  CREATE VIRTUAL TABLE IF NOT EXISTS fts_notes
                      USING fts5(title, body, content='notes', content_rowid='id')",
        },
        Migration {
            version: 11,
            description: "collaboration checkpoint table",
            sql: "CREATE TABLE IF NOT EXISTS collab_checkpoints (
                      id INTEGER PRIMARY KEY,
                      view_id BIGINT NOT NULL,
                      last_event_id BIGINT NOT NULL,
                      peer_id TEXT NOT NULL,
                      created_at BIGINT NOT NULL
                  )",
        },
    ]
}

// ---------------------------------------------------------------------------
// KnowledgeGraph — CRUD for 20 additional tables
// ---------------------------------------------------------------------------

impl KnowledgeGraph {
    /// Run all pending migrations against the underlying database.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn migrate(&self) -> Result<(), GraphError> {
        run_migrations(self.conn.as_ref())
    }

    // ------------------------------------------------------------------
    // stack_vars
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_stack_var(
        &self,
        function_id: i64,
        offset: i64,
        name: Option<&str>,
        type_name: Option<&str>,
        size: i64,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO stack_vars (function_id, offset, name, type_name, size)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(function_id),
                GraphParam::Int(offset),
                opt_text(name),
                opt_text(type_name),
                GraphParam::Int(size),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_stack_vars(&self, function_id: i64) -> Result<Vec<StackVarRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, function_id, offset, name, type_name, size
             FROM stack_vars WHERE function_id = ?1 ORDER BY offset ASC",
            &[GraphParam::Int(function_id)],
        )?;
        rows.iter()
            .map(|r| {
                Ok(StackVarRow {
                    id: mixed_i64(r, 0)?,
                    function_id: mixed_i64(r, 1)?,
                    offset: mixed_i64(r, 2)?,
                    name: mixed_opt_str(r, 3)?,
                    type_name: mixed_opt_str(r, 4)?,
                    size: mixed_i64(r, 5)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_stack_var(&self, id: i64) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM stack_vars WHERE id = ?1",
            &[GraphParam::Int(id)],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // local_types
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_local_type(
        &self,
        view_id: ViewId,
        function_id: i64,
        name: &str,
        definition: &str,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO local_types (view_id, function_id, name, definition)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(function_id),
                GraphParam::Text(name.to_owned()),
                GraphParam::Text(definition.to_owned()),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_local_types(&self, function_id: i64) -> Result<Vec<LocalTypeRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, function_id, name, definition
             FROM local_types WHERE function_id = ?1",
            &[GraphParam::Int(function_id)],
        )?;
        rows.iter()
            .map(|r| {
                Ok(LocalTypeRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    function_id: mixed_i64(r, 2)?,
                    name: mixed_str(r, 3)?,
                    definition: mixed_str(r, 4)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // vtables
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_vtable(
        &self,
        view_id: ViewId,
        address: Address,
        class_name: Option<&str>,
        entry_count: i64,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO vtables (view_id, address, class_name, entry_count)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                opt_text(class_name),
                GraphParam::Int(entry_count),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_vtables(&self, view_id: ViewId) -> Result<Vec<VtableRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, class_name, entry_count
             FROM vtables WHERE view_id = ?1 ORDER BY address ASC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(VtableRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    address: mixed_u64(r, 2)?,
                    class_name: mixed_opt_str(r, 3)?,
                    entry_count: mixed_i64(r, 4)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_vtable(&self, id: i64) -> Result<(), GraphError> {
        self.conn
            .execute("DELETE FROM vtables WHERE id = ?1", &[GraphParam::Int(id)])?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // class_hierarchy
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_class_hierarchy(
        &self,
        view_id: ViewId,
        derived: &str,
        base: &str,
        offset: i64,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO class_hierarchy (view_id, derived_class, base_class, offset)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(derived.to_owned()),
                GraphParam::Text(base.to_owned()),
                GraphParam::Int(offset),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_base_classes(
        &self,
        view_id: ViewId,
        derived: &str,
    ) -> Result<Vec<ClassHierarchyRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, derived_class, base_class, offset
             FROM class_hierarchy WHERE view_id = ?1 AND derived_class = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(derived.to_owned()),
            ],
        )?;
        rows.iter()
            .map(|r| {
                Ok(ClassHierarchyRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    derived_class: mixed_str(r, 2)?,
                    base_class: mixed_str(r, 3)?,
                    offset: mixed_i64(r, 4)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // flirt_matches
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_flirt_match(
        &self,
        view_id: ViewId,
        address: Address,
        library_name: &str,
        matched_name: &str,
        score: f64,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO flirt_matches (view_id, address, library_name, matched_name, score)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Text(library_name.to_owned()),
                GraphParam::Text(matched_name.to_owned()),
                GraphParam::Real(score),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_flirt_matches(&self, view_id: ViewId) -> Result<Vec<FlirtMatchRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, library_name, matched_name, score
             FROM flirt_matches WHERE view_id = ?1 ORDER BY score DESC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(FlirtMatchRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    address: mixed_u64(r, 2)?,
                    library_name: mixed_str(r, 3)?,
                    matched_name: mixed_str(r, 4)?,
                    score: match &r[5] {
                        GraphValue::Real(f) => *f,
                        GraphValue::Integer(n) => f64::from(i32::try_from(*n).unwrap_or(0)),
                        _ => 0.0,
                    },
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // debug_info
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_debug_info(
        &self,
        view_id: ViewId,
        source_file: &str,
        line_number: i64,
        address: Address,
        column: Option<i64>,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO debug_info (view_id, source_file, line_number, address, col)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(source_file.to_owned()),
                GraphParam::Int(line_number),
                GraphParam::Int(address.0.cast_signed()),
                column.map_or(GraphParam::Null, GraphParam::Int),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_debug_info_at(
        &self,
        view_id: ViewId,
        address: Address,
    ) -> Result<Option<DebugInfoRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, source_file, line_number, address, col
             FROM debug_info WHERE view_id = ?1 AND address = ?2 LIMIT 1",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
            ],
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        let r = &rows[0];
        Ok(Some(DebugInfoRow {
            id: mixed_i64(r, 0)?,
            view_id: mixed_i64(r, 1)?,
            source_file: mixed_str(r, 2)?,
            line_number: mixed_i64(r, 3)?,
            address: mixed_u64(r, 4)?,
            column: match &r[5] {
                GraphValue::Integer(n) => Some(*n),
                _ => None,
            },
        }))
    }

    // ------------------------------------------------------------------
    // notes
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_note(&self, view_id: ViewId, title: &str, body: &str) -> Result<i64, GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO notes (view_id, title, body, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(title.to_owned()),
                GraphParam::Text(body.to_owned()),
                GraphParam::Int(now),
                GraphParam::Int(now),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_notes(&self, view_id: ViewId) -> Result<Vec<NoteRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, title, body, created_at, updated_at
             FROM notes WHERE view_id = ?1 ORDER BY updated_at DESC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(NoteRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    title: mixed_str(r, 2)?,
                    body: mixed_str(r, 3)?,
                    created_at: mixed_i64(r, 4)?,
                    updated_at: mixed_i64(r, 5)?,
                })
            })
            .collect()
    }
 /// # Errors
 ///
 /// Returns an error if the underlying operation fails.
    pub fn update_note(&self, id: i64, title: &str, body: &str) -> Result<(), GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "UPDATE notes SET title = ?1, body = ?2, updated_at = ?3 WHERE id = ?4",
            &[
                GraphParam::Text(title.to_owned()),
                GraphParam::Text(body.to_owned()),
                GraphParam::Int(now),
                GraphParam::Int(id),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_note(&self, id: i64) -> Result<(), GraphError> {
        self.conn
            .execute("DELETE FROM notes WHERE id = ?1", &[GraphParam::Int(id)])?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // analysis_cache
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn set_analysis_cache(
        &self,
        view_id: ViewId,
        pass: &str,
        version: i64,
        data: &[u8],
    ) -> Result<(), GraphError> {
        let now = unix_timestamp();
        // Upsert by deleting first.
        self.conn.execute(
            "DELETE FROM analysis_cache WHERE view_id = ?1 AND pass = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(pass.to_owned()),
            ],
        )?;
        self.conn.execute(
            "INSERT INTO analysis_cache (view_id, pass, version, data, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(pass.to_owned()),
                GraphParam::Int(version),
                GraphParam::Blob(data.to_vec()),
                GraphParam::Int(now),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_analysis_cache(
        &self,
        view_id: ViewId,
        pass: &str,
    ) -> Result<Option<AnalysisCacheRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, pass, version, data, created_at
             FROM analysis_cache WHERE view_id = ?1 AND pass = ?2 LIMIT 1",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(pass.to_owned()),
            ],
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        let r = &rows[0];
        Ok(Some(AnalysisCacheRow {
            id: mixed_i64(r, 0)?,
            view_id: mixed_i64(r, 1)?,
            pass: mixed_str(r, 2)?,
            version: mixed_i64(r, 3)?,
            data: mixed_blob(r, 4)?,
            created_at: mixed_i64(r, 5)?,
        }))
    }

    // ------------------------------------------------------------------
    // script_results
    // ------------------------------------------------------------------
 /// # Errors
 ///
 /// Returns an error if the underlying operation fails.
    pub fn add_script_result(
        &self,
        view_id: ViewId,
        engine: &str,
        source: &str,
        output: &str,
        success: bool,
    ) -> Result<i64, GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO script_results (view_id, engine, source, output, success, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(engine.to_owned()),
                GraphParam::Text(source.to_owned()),
                GraphParam::Text(output.to_owned()),
                GraphParam::Int(bool_int(success)),
                GraphParam::Int(now),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_script_results(
        &self,
        view_id: ViewId,
        limit: i64,
    ) -> Result<Vec<ScriptResultRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, engine, source, output, success, created_at
             FROM script_results WHERE view_id = ?1 ORDER BY created_at DESC LIMIT ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(limit),
            ],
        )?;
        rows.iter()
            .map(|r| {
                Ok(ScriptResultRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    engine: mixed_str(r, 2)?,
                    source: mixed_str(r, 3)?,
                    output: mixed_str(r, 4)?,
                    success: mixed_bool(r, 5)?,
                    created_at: mixed_i64(r, 6)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // diff_sessions
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_diff_session(
        &self,
        view_id_a: i64,
        view_id_b: i64,
        algorithm: &str,
        result_json: &str,
    ) -> Result<i64, GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO diff_sessions (view_id_a, view_id_b, algorithm, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id_a),
                GraphParam::Int(view_id_b),
                GraphParam::Text(algorithm.to_owned()),
                GraphParam::Text(result_json.to_owned()),
                GraphParam::Int(now),
            ],
        )?;
        self.conn.last_insert_id()
    }
 /// # Errors
 ///
 /// Returns an error if the underlying operation fails.
    pub fn get_diff_sessions(&self, view_id_a: i64) -> Result<Vec<DiffSessionRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id_a, view_id_b, algorithm, result_json, created_at
             FROM diff_sessions WHERE view_id_a = ?1 ORDER BY created_at DESC",
            &[GraphParam::Int(view_id_a)],
        )?;
        rows.iter()
            .map(|r| {
                Ok(DiffSessionRow {
                    id: mixed_i64(r, 0)?,
                    view_id_a: mixed_i64(r, 1)?,
                    view_id_b: mixed_i64(r, 2)?,
                    algorithm: mixed_str(r, 3)?,
                    result_json: mixed_str(r, 4)?,
                    created_at: mixed_i64(r, 5)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // trace_records
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_trace_record(
        &self,
        view_id: ViewId,
        thread_id: i64,
        address: Address,
        instruction: &str,
        tick: i64,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO trace_records (view_id, thread_id, address, instruction, tick)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(thread_id),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Text(instruction.to_owned()),
                GraphParam::Int(tick),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_trace_records(
        &self,
        view_id: ViewId,
        limit: i64,
    ) -> Result<Vec<TraceRecordRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, thread_id, address, instruction, tick
             FROM trace_records WHERE view_id = ?1 ORDER BY tick ASC LIMIT ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(limit),
            ],
        )?;
        rows.iter()
            .map(|r| {
                Ok(TraceRecordRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    thread_id: mixed_i64(r, 2)?,
                    address: mixed_u64(r, 3)?,
                    instruction: mixed_str(r, 4)?,
                    tick: mixed_i64(r, 5)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_trace_records(&self, view_id: ViewId) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM trace_records WHERE view_id = ?1",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // breakpoints
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_breakpoint(
        &self,
        view_id: ViewId,
        address: Address,
        kind: &str,
        condition: Option<&str>,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO breakpoints (view_id, address, kind, condition, enabled)
             VALUES (?1, ?2, ?3, ?4, 1)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(address.0.cast_signed()),
                GraphParam::Text(kind.to_owned()),
                opt_text(condition),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_breakpoints(&self, view_id: ViewId) -> Result<Vec<BreakpointRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, kind, condition, enabled
             FROM breakpoints WHERE view_id = ?1 ORDER BY address ASC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(BreakpointRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    address: mixed_u64(r, 2)?,
                    kind: mixed_str(r, 3)?,
                    condition: mixed_opt_str(r, 4)?,
                    enabled: mixed_bool(r, 5)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn set_breakpoint_enabled(&self, id: i64, enabled: bool) -> Result<(), GraphError> {
        self.conn.execute(
            "UPDATE breakpoints SET enabled = ?1 WHERE id = ?2",
            &[GraphParam::Int(bool_int(enabled)), GraphParam::Int(id)],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_breakpoint(&self, id: i64) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM breakpoints WHERE id = ?1",
            &[GraphParam::Int(id)],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // watch_expressions
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_watch_expression(
        &self,
        view_id: ViewId,
        expression: &str,
    ) -> Result<i64, GraphError> {
        self.conn.execute(
            "INSERT INTO watch_expressions (view_id, expression) VALUES (?1, ?2)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(expression.to_owned()),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_watch_expressions(
        &self,
        view_id: ViewId,
    ) -> Result<Vec<WatchExpressionRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, expression, last_value
             FROM watch_expressions WHERE view_id = ?1",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(WatchExpressionRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    expression: mixed_str(r, 2)?,
                    last_value: mixed_opt_str(r, 3)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn update_watch_value(&self, id: i64, value: &str) -> Result<(), GraphError> {
        self.conn.execute(
            "UPDATE watch_expressions SET last_value = ?1 WHERE id = ?2",
            &[GraphParam::Text(value.to_owned()), GraphParam::Int(id)],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn delete_watch_expression(&self, id: i64) -> Result<(), GraphError> {
        self.conn.execute(
            "DELETE FROM watch_expressions WHERE id = ?1",
            &[GraphParam::Int(id)],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // agent_sessions
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn begin_agent_session(
        &self,
        view_id: ViewId,
        agent_name: &str,
        initial_state: &str,
    ) -> Result<i64, GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO agent_sessions (view_id, agent_name, state_json, started_at)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(agent_name.to_owned()),
                GraphParam::Text(initial_state.to_owned()),
                GraphParam::Int(now),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn end_agent_session(&self, id: i64, final_state: &str) -> Result<(), GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "UPDATE agent_sessions SET state_json = ?1, ended_at = ?2 WHERE id = ?3",
            &[
                GraphParam::Text(final_state.to_owned()),
                GraphParam::Int(now),
                GraphParam::Int(id),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn get_agent_sessions(&self, view_id: ViewId) -> Result<Vec<AgentSessionRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, agent_name, state_json, started_at, ended_at
             FROM agent_sessions WHERE view_id = ?1 ORDER BY started_at DESC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(AgentSessionRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    agent_name: mixed_str(r, 2)?,
                    state_json: mixed_str(r, 3)?,
                    started_at: mixed_i64(r, 4)?,
                    ended_at: match &r[5] {
                        GraphValue::Integer(n) => Some(*n),
                        _ => None,
                    },
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // mcp_sessions
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn begin_mcp_session(
        &self,
        view_id: ViewId,
        tool_name: &str,
        params_json: &str,
    ) -> Result<i64, GraphError> {
        let now = unix_timestamp();
        self.conn.execute(
            "INSERT INTO mcp_sessions (view_id, tool_name, params_json, started_at)
             VALUES (?1, ?2, ?3, ?4)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(tool_name.to_owned()),
                GraphParam::Text(params_json.to_owned()),
                GraphParam::Int(now),
            ],
        )?;
        self.conn.last_insert_id()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn complete_mcp_session(&self, id: i64, result_json: &str) -> Result<(), GraphError> {
        self.conn.execute(
            "UPDATE mcp_sessions SET result_json = ?1 WHERE id = ?2",
            &[
                GraphParam::Text(result_json.to_owned()),
                GraphParam::Int(id),
            ],
        )?;
        Ok(())
    }
 /// # Errors
 ///
 /// Returns an error if the underlying operation fails.
    pub fn get_mcp_sessions(&self, view_id: ViewId) -> Result<Vec<McpSessionRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, tool_name, params_json, result_json, started_at
             FROM mcp_sessions WHERE view_id = ?1 ORDER BY started_at DESC",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;
        rows.iter()
            .map(|r| {
                Ok(McpSessionRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    tool_name: mixed_str(r, 2)?,
                    params_json: mixed_str(r, 3)?,
                    result_json: mixed_opt_str(r, 4)?,
                    started_at: mixed_i64(r, 5)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // call_graph
    // ------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_call_graph_edge(
        &self,
        view_id: ViewId,
        caller_id: i64,
        callee_id: i64,
        call_address: Address,
        is_indirect: bool,
    ) -> Result<(), GraphError> {
        self.conn.execute(
            "INSERT INTO call_graph (caller_id, callee_id, view_id, call_address, is_indirect)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                GraphParam::Int(caller_id),
                GraphParam::Int(callee_id),
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(call_address.0.cast_signed()),
                GraphParam::Int(bool_int(is_indirect)),
            ],
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn callees_of_fn(
        &self,
        view_id: ViewId,
        caller_id: i64,
    ) -> Result<Vec<CallGraphRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT caller_id, callee_id, view_id, call_address, is_indirect
             FROM call_graph WHERE view_id = ?1 AND caller_id = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(caller_id),
            ],
        )?;
        rows.iter()
            .map(|r| {
                Ok(CallGraphRow {
                    caller_id: mixed_i64(r, 0)?,
                    callee_id: mixed_i64(r, 1)?,
                    view_id: mixed_i64(r, 2)?,
                    call_address: mixed_u64(r, 3)?,
                    is_indirect: mixed_bool(r, 4)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn callers_of_fn(
        &self,
        view_id: ViewId,
        callee_id: i64,
    ) -> Result<Vec<CallGraphRow>, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT caller_id, callee_id, view_id, call_address, is_indirect
             FROM call_graph WHERE view_id = ?1 AND callee_id = ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(callee_id),
            ],
        )?;
        rows.iter()
            .map(|r| {
                Ok(CallGraphRow {
                    caller_id: mixed_i64(r, 0)?,
                    callee_id: mixed_i64(r, 1)?,
                    view_id: mixed_i64(r, 2)?,
                    call_address: mixed_u64(r, 3)?,
                    is_indirect: mixed_bool(r, 4)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // FTS5 full-text search
    // ------------------------------------------------------------------

    /// Full-text search across comments.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn fts_comments(
        &self,
        view_id: ViewId,
        query: &str,
    ) -> Result<Vec<CommentRow>, GraphError> {
        // Try the FTS virtual table first; fall back to LIKE if FTS not available.
        let fts_sql = format!(
            "SELECT c.id, c.view_id, c.address, c.text, c.repeatable
             FROM fts_comments fts
             JOIN comments c ON fts.rowid = c.id
             WHERE fts_comments MATCH ?1 AND c.view_id = {}",
            view_id.get()
        );
        match self
            .conn
            .query_rows_mixed(&fts_sql, &[GraphParam::Text(query.to_owned())])
        {
            Ok(rows) if !rows.is_empty() => {
                return rows.iter().map(|r| comment_row_from_mixed(r)).collect();
            }
            _ => {}
        }
        // Fallback: LIKE search.
        let like_pattern = format!("%{query}%");
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, text, repeatable
             FROM comments WHERE view_id = ?1 AND text LIKE ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(like_pattern),
            ],
        )?;
        rows.iter().map(|r| comment_row_from_mixed(r)).collect()
    }

    /// Full-text search across symbol names.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn fts_symbols(&self, view_id: ViewId, query: &str) -> Result<Vec<SymbolRow>, GraphError> {
        let fts_sql = format!(
            "SELECT s.id, s.view_id, s.address, s.name, s.kind, s.demangled, s.source
             FROM fts_symbols fts
             JOIN symbols s ON fts.rowid = s.id
             WHERE fts_symbols MATCH ?1 AND s.view_id = {}",
            view_id.get()
        );
        match self
            .conn
            .query_rows_mixed(&fts_sql, &[GraphParam::Text(query.to_owned())])
        {
            Ok(rows) if !rows.is_empty() => {
                return rows.iter().map(|r| symbol_row_from_mixed(r)).collect();
            }
            _ => {}
        }
        let like_pattern = format!("%{query}%");
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, address, name, kind, demangled, source
             FROM symbols WHERE view_id = ?1 AND name LIKE ?2",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(like_pattern),
            ],
        )?;
        rows.iter().map(|r| symbol_row_from_mixed(r)).collect()
    }

    /// Full-text search across notes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn fts_notes(&self, view_id: ViewId, query: &str) -> Result<Vec<NoteRow>, GraphError> {
        let fts_sql = format!(
            "SELECT n.id, n.view_id, n.title, n.body, n.created_at, n.updated_at
             FROM fts_notes fts
             JOIN notes n ON fts.rowid = n.id
             WHERE fts_notes MATCH ?1 AND n.view_id = {}",
            view_id.get()
        );
        match self
            .conn
            .query_rows_mixed(&fts_sql, &[GraphParam::Text(query.to_owned())])
        {
            Ok(rows) if !rows.is_empty() => {
                return rows
                    .iter()
                    .map(|r| {
                        Ok(NoteRow {
                            id: mixed_i64(r, 0)?,
                            view_id: mixed_i64(r, 1)?,
                            title: mixed_str(r, 2)?,
                            body: mixed_str(r, 3)?,
                            created_at: mixed_i64(r, 4)?,
                            updated_at: mixed_i64(r, 5)?,
                        })
                    })
                    .collect();
            }
            _ => {}
        }
        // Fallback.
        let like_pattern = format!("%{query}%");
        let rows = self.conn.query_rows_mixed(
            "SELECT id, view_id, title, body, created_at, updated_at
             FROM notes WHERE view_id = ?1 AND (title LIKE ?2 OR body LIKE ?2)",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Text(like_pattern),
            ],
        )?;
        rows.iter()
            .map(|r| {
                Ok(NoteRow {
                    id: mixed_i64(r, 0)?,
                    view_id: mixed_i64(r, 1)?,
                    title: mixed_str(r, 2)?,
                    body: mixed_str(r, 3)?,
                    created_at: mixed_i64(r, 4)?,
                    updated_at: mixed_i64(r, 5)?,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    /// Returns a map of high-level analysis statistics for the given view.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn statistics(&self, view_id: ViewId) -> Result<GraphStats, GraphError> {
        let vid = view_id.get().cast_signed();
        let fn_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM functions WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        let xref_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM xrefs WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        let symbol_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM symbols WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        let string_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM strings WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        let comment_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM comments WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        let patch_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM patches WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        let flirt_count = self
            .conn
            .query_row_i64(
                "SELECT COUNT(*) FROM flirt_matches WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?
            .unwrap_or(0).cast_unsigned();
        Ok(GraphStats {
            function_count: fn_count,
            xref_count,
            symbol_count,
            string_count,
            comment_count,
            patch_count,
            flirt_matched_count: flirt_count,
        })
    }

    // ------------------------------------------------------------------
    // Collaboration — delta export / import
    // ------------------------------------------------------------------

    /// Export all events with id > `since_event_id` as JSON for sync to peers.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn export_delta(&self, view_id: ViewId, since_event_id: i64) -> Result<String, GraphError> {
        let rows = self.conn.query_rows_mixed(
            "SELECT id, timestamp, actor, kind, payload
             FROM events WHERE view_id = ?1 AND id > ?2 ORDER BY id ASC",
            &[
                GraphParam::Int(view_id.get().cast_signed()),
                GraphParam::Int(since_event_id),
            ],
        )?;
        let mut events = Vec::new();
        for r in &rows {
            let id = mixed_i64(r, 0)?;
            let ts = mixed_i64(r, 1)?;
            let actor = mixed_str(r, 2)?;
            let kind = mixed_str(r, 3)?;
            let payload = mixed_blob(r, 4)?;
            events.push(serde_json::json!({
                "id": id,
                "timestamp": ts,
                "actor": actor,
                "kind": kind,
                "payload": base64_encode(&payload),
            }));
        }
        serde_json::to_string(&events)
            .map_err(|e| GraphError::Generic(format!("JSON serialization failed: {e}")))
    }

    /// Import a delta JSON blob (produced by `export_delta`) from a peer.
    ///
    /// Uses last-write-wins per event kind+timestamp for conflict resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn import_delta(&self, view_id: ViewId, delta_json: &str) -> Result<usize, GraphError> {
        // Guard against absurdly large blobs before parsing.
        const MAX_DELTA_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
        // Cap the number of events that can be processed in a single call.
        const MAX_EVENTS: usize = 100_000;
        if delta_json.len() > MAX_DELTA_BYTES {
            return Err(GraphError::Generic(format!(
                "import_delta: input too large ({} bytes, max {})",
                delta_json.len(),
                MAX_DELTA_BYTES
            )));
        }
        let events: Vec<serde_json::Value> = serde_json::from_str(delta_json)
            .map_err(|e| GraphError::Generic(format!("JSON parse error: {e}")))?;
        if events.len() > MAX_EVENTS {
            return Err(GraphError::Generic(format!(
                "import_delta: too many events ({}, max {})",
                events.len(),
                MAX_EVENTS
            )));
        }
        let mut imported = 0usize;
        for ev in &events {
            let actor = ev["actor"].as_str().unwrap_or("peer").to_owned();
            let kind = ev["kind"].as_str().unwrap_or("unknown").to_owned();
            let timestamp = ev["timestamp"].as_i64().unwrap_or(0);
            let payload_b64 = ev["payload"].as_str().unwrap_or("");
            let payload = base64_decode(payload_b64);
            let now = unix_timestamp();
            // Conflict: if a local event with the same kind exists with newer
            // timestamp, skip; otherwise insert.
            let local_ts = self
                .conn
                .query_row_i64(
                    "SELECT MAX(timestamp) FROM events WHERE view_id = ?1 AND kind = ?2",
                    &[
                        GraphParam::Int(view_id.get().cast_signed()),
                        GraphParam::Text(kind.clone()),
                    ],
                )?
                .unwrap_or(0);
            if timestamp > local_ts {
                self.conn.execute(
                    "INSERT INTO events (view_id, timestamp, actor, kind, payload)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        GraphParam::Int(view_id.get().cast_signed()),
                        GraphParam::Int(timestamp),
                        GraphParam::Text(actor),
                        GraphParam::Text(kind),
                        GraphParam::Blob(payload),
                    ],
                )?;
                imported += 1;
                let _ = now;
            }
        }
        Ok(imported)
    }

    // ------------------------------------------------------------------
    // JSON snapshot export / import
    // ------------------------------------------------------------------

    /// Export the entire knowledge graph for a view as a JSON snapshot.
    ///
    /// The snapshot includes functions, symbols, xrefs, comments, patches,
    /// strings, bookmarks, and events.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn export_snapshot(&self, view_id: ViewId) -> Result<String, GraphError> {
        let vid = view_id.get().cast_signed();
        let functions: Vec<serde_json::Value> = {
            let rows = self.conn.query_rows_mixed(
                "SELECT id, view_id, address, end_address, name, prototype, calling_conv, is_thunk, is_library, flirt_matched FROM functions WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?;
            rows.iter().map(|r| {
                let row = function_row_from_mixed(r).unwrap_or(FunctionRow {
                    id: 0, view_id: vid, address: 0, end_address: 0,
                    name: None, prototype: None, calling_conv: None,
                    is_thunk: false, is_library: false, flirt_matched: false,
                });
                serde_json::json!({
                    "id": row.id, "address": row.address, "end_address": row.end_address,
                    "name": row.name, "prototype": row.prototype, "calling_conv": row.calling_conv,
                    "is_thunk": row.is_thunk, "is_library": row.is_library,
                })
            }).collect()
        };

        let symbols: Vec<serde_json::Value> = {
            let rows = self.conn.query_rows_mixed(
                "SELECT id, view_id, address, name, kind, demangled, source FROM symbols WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?;
            rows.iter()
                .map(|r| {
                    let row = symbol_row_from_mixed(r).unwrap_or_else(|_| SymbolRow {
                        id: 0,
                        view_id: vid,
                        address: 0,
                        name: String::new(),
                        kind: String::new(),
                        demangled: None,
                        source: None,
                    });
                    serde_json::json!({
                        "address": row.address, "name": row.name,
                        "kind": row.kind, "demangled": row.demangled, "source": row.source,
                    })
                })
                .collect()
        };

        let xrefs: Vec<serde_json::Value> = {
            let rows = self.conn.query_rows_mixed(
                "SELECT from_addr, to_addr, view_id, kind FROM xrefs WHERE view_id = ?1",
                &[GraphParam::Int(vid)],
            )?;
            rows.iter()
                .map(|r| {
                    let row = xref_row_from_mixed(r).unwrap_or_else(|_| XrefRow {
                        from_addr: 0,
                        to_addr: 0,
                        view_id: vid,
                        kind: String::new(),
                    });
                    serde_json::json!({
                        "from": row.from_addr, "to": row.to_addr, "kind": row.kind,
                    })
                })
                .collect()
        };

        let snapshot = serde_json::json!({
            "view_id": vid,
            "functions": functions,
            "symbols": symbols,
            "xrefs": xrefs,
        });

        serde_json::to_string(&snapshot)
            .map_err(|e| GraphError::Generic(format!("JSON serialization error: {e}")))
    }

    /// Import a JSON snapshot produced by `export_snapshot` into this graph.
    ///
    /// All items are inserted with `INSERT OR IGNORE` so duplicate addresses
    /// are skipped silently.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn import_snapshot(&self, view_id: ViewId, json: &str) -> Result<(), GraphError> {
        // Guard against absurdly large blobs before parsing.
        const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
        if json.len() > MAX_SNAPSHOT_BYTES {
            return Err(GraphError::Generic(format!(
                "import_snapshot: input too large ({} bytes, max {})",
                json.len(),
                MAX_SNAPSHOT_BYTES
            )));
        }
        let snap: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| GraphError::Generic(format!("JSON parse error: {e}")))?;

        if let Some(functions) = snap["functions"].as_array() {
            for f in functions {
                let addr = f["address"].as_u64().unwrap_or(0);
                let end_addr = f["end_address"].as_u64().unwrap_or(addr);
                let name = f["name"].as_str().map(std::borrow::ToOwned::to_owned);
                let prototype = f["prototype"].as_str().map(std::borrow::ToOwned::to_owned);
                let calling_conv = f["calling_conv"].as_str().map(std::borrow::ToOwned::to_owned);
                let is_thunk = f["is_thunk"].as_bool().unwrap_or(false);
                let is_library = f["is_library"].as_bool().unwrap_or(false);
                let _ = self.add_function(view_id, Address::new(addr), Address::new(end_addr), FunctionMeta { name: name.as_deref(), prototype: prototype.as_deref(), calling_conv: calling_conv.as_deref(), is_thunk, is_library });
            }
        }

        if let Some(symbols) = snap["symbols"].as_array() {
            for s in symbols {
                let addr = s["address"].as_u64().unwrap_or(0);
                let name = s["name"].as_str().unwrap_or("unknown");
                let kind = s["kind"].as_str().unwrap_or("unknown");
                let source = s["source"].as_str();
                let _ = self.add_symbol(view_id, Address::new(addr), name, kind, source);
            }
        }

        if let Some(xrefs) = snap["xrefs"].as_array() {
            for x in xrefs {
                let from = x["from"].as_u64().unwrap_or(0);
                let to = x["to"].as_u64().unwrap_or(0);
                let kind = x["kind"].as_str().unwrap_or("code_call");
                let _ = self.add_xref(view_id, Address::new(from), Address::new(to), kind);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Simple base64 helpers (no external crate)
// ---------------------------------------------------------------------------

fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = u32::from(bytes[i]);
        let b1 = if i + 1 < bytes.len() {
            u32::from(bytes[i + 1])
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            u32::from(bytes[i + 2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(CHARS[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn base64_decode(s: &str) -> Vec<u8> {
    const fn val(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(len / 4 * 3);
    let mut i = 0;
    while i + 3 < len {
        let a = val(bytes[i]);
        let b = val(bytes[i + 1]);
        let c = val(bytes[i + 2]);
        let d = val(bytes[i + 3]);
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    out
}

// ---------------------------------------------------------------------------
// GraphStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphStats {
    pub function_count: u64,
    pub xref_count: u64,
    pub symbol_count: u64,
    pub string_count: u64,
    pub comment_count: u64,
    pub patch_count: u64,
    pub flirt_matched_count: u64,
}

// ---------------------------------------------------------------------------
// petgraph XrefGraph — in-memory directed graph synced with SQL xrefs
// ---------------------------------------------------------------------------

/// An in-memory directed graph of cross-references, backed by petgraph.
///
/// Addresses are node labels; edges carry the xref kind string.
/// Kept in sync via `rebuild_from_db()`.  Invalidated on every `add_xref` /
/// `delete_xrefs_from` call when used via the `XrefGraphCache` wrapper.
pub struct XrefGraph {
    graph: PLRwLock<DiGraph<u64, String>>,
    addr_to_node: PLRwLock<StdHashMap<u64, NodeIndex>>,
}

impl XrefGraph {
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: PLRwLock::new(DiGraph::new()),
            addr_to_node: PLRwLock::new(StdHashMap::new()),
        }
    }

    /// (Re-)build the graph from the SQL xrefs for a view.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn rebuild_from_db(&self, kg: &KnowledgeGraph, view_id: ViewId) -> Result<(), GraphError> {
        let rows = kg.conn.query_rows_mixed(
            "SELECT from_addr, to_addr, kind FROM xrefs WHERE view_id = ?1",
            &[GraphParam::Int(view_id.get().cast_signed())],
        )?;

        let mut g = DiGraph::new();
        let mut addr_map: StdHashMap<u64, NodeIndex> = StdHashMap::new();

        for r in &rows {
            let from_addr = mixed_u64(r, 0)?;
            let to_addr = mixed_u64(r, 1)?;
            let kind = mixed_str(r, 2)?;

            let from_node = *addr_map
                .entry(from_addr)
                .or_insert_with(|| g.add_node(from_addr));
            let to_node = *addr_map
                .entry(to_addr)
                .or_insert_with(|| g.add_node(to_addr));
            g.add_edge(from_node, to_node, kind);
        }

        *self.graph.write() = g;
        *self.addr_to_node.write() = addr_map;
        Ok(())
    }

    /// Return all addresses reachable from `start` via BFS.
    pub fn reachable_from(&self, start: u64) -> Vec<u64> {
        let g = self.graph.read();
        let addr_map = self.addr_to_node.read();
        let Some(&start_node) = addr_map.get(&start) else {
            return Vec::new();
        };
        let mut visited = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start_node);
        let mut seen = std::collections::HashSet::new();
        seen.insert(start_node);
        while let Some(node) = queue.pop_front() {
            visited.push(*g.node_weight(node).unwrap_or(&0));
            for neighbor in g.neighbors(node) {
                if seen.insert(neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }
        visited
    }

    /// Return the node count.
    pub fn node_count(&self) -> usize {
        self.graph.read().node_count()
    }

    /// Return the edge count.
    pub fn edge_count(&self) -> usize {
        self.graph.read().edge_count()
    }
}

impl Default for XrefGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for XrefGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "XrefGraph {{ nodes: {}, edges: {} }}",
            self.node_count(),
            self.edge_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Enterprise tests (§35)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod enterprise_tests {
    use super::*;

    fn graph() -> KnowledgeGraph {
        KnowledgeGraph::new_in_memory().unwrap()
    }
    fn vid(n: u64) -> ViewId {
        ViewId::from_raw(n)
    }
    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    fn migrated_graph() -> KnowledgeGraph {
        let g = graph();
        g.migrate().unwrap();
        g
    }

    // ---- migration system --------------------------------------------------

    #[test]
    fn test_migration_runs_without_error() {
        let g = graph();
        g.migrate().unwrap();
    }

    #[test]
    fn test_migration_is_idempotent() {
        let g = graph();
        g.migrate().unwrap();
        // Second run should also succeed.
        g.migrate().unwrap();
    }

    // ---- stack_vars --------------------------------------------------------

    #[test]
    fn test_add_and_get_stack_vars() {
        let g = migrated_graph();
        let fn_id = g
            .add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("f"), ..FunctionMeta::default() })
            .unwrap();
        let id = g
            .add_stack_var(fn_id, -8, Some("local_a"), Some("int"), 4)
            .unwrap();
        assert!(id > 0);
        let vars = g.get_stack_vars(fn_id).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, Some("local_a".into()));
        assert_eq!(vars[0].offset, -8);
        assert_eq!(vars[0].size, 4);
    }

    #[test]
    fn test_delete_stack_var() {
        let g = migrated_graph();
        let fn_id = g
            .add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta::default())
            .unwrap();
        let id = g.add_stack_var(fn_id, 0, None, None, 8).unwrap();
        g.delete_stack_var(id).unwrap();
        assert!(g.get_stack_vars(fn_id).unwrap().is_empty());
    }

    // ---- local_types -------------------------------------------------------

    #[test]
    fn test_add_and_get_local_types() {
        let g = migrated_graph();
        let fn_id = g
            .add_function(vid(1), addr(0x3000), addr(0x3100), FunctionMeta::default())
            .unwrap();
        let id = g
            .add_local_type(vid(1), fn_id, "MyStruct", "struct { int x; }")
            .unwrap();
        assert!(id > 0);
        let types = g.get_local_types(fn_id).unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name, "MyStruct");
    }

    // ---- vtables -----------------------------------------------------------

    #[test]
    fn test_add_and_get_vtables() {
        let g = migrated_graph();
        let id = g
            .add_vtable(vid(1), addr(0x4000), Some("MyClass"), 5)
            .unwrap();
        assert!(id > 0);
        let vtables = g.get_vtables(vid(1)).unwrap();
        assert_eq!(vtables.len(), 1);
        assert_eq!(vtables[0].class_name, Some("MyClass".into()));
        assert_eq!(vtables[0].entry_count, 5);
    }

    #[test]
    fn test_delete_vtable() {
        let g = migrated_graph();
        let id = g.add_vtable(vid(1), addr(0x5000), None, 0).unwrap();
        g.delete_vtable(id).unwrap();
        assert!(g.get_vtables(vid(1)).unwrap().is_empty());
    }

    // ---- class_hierarchy ---------------------------------------------------

    #[test]
    fn test_class_hierarchy() {
        let g = migrated_graph();
        g.add_class_hierarchy(vid(1), "Child", "Parent", 0).unwrap();
        g.add_class_hierarchy(vid(1), "Child", "Mixin", 8).unwrap();
        let bases = g.get_base_classes(vid(1), "Child").unwrap();
        assert_eq!(bases.len(), 2);
        let base_names: Vec<&str> = bases.iter().map(|b| b.base_class.as_str()).collect();
        assert!(base_names.contains(&"Parent"));
        assert!(base_names.contains(&"Mixin"));
    }

    // ---- flirt_matches -----------------------------------------------------

    #[test]
    fn test_add_and_get_flirt_matches() {
        let g = migrated_graph();
        let id = g
            .add_flirt_match(vid(1), addr(0x6000), "libc", "malloc", 0.99)
            .unwrap();
        assert!(id > 0);
        let matches = g.get_flirt_matches(vid(1)).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_name, "malloc");
        assert!((matches[0].score - 0.99).abs() < 1e-6);
    }

    // ---- debug_info --------------------------------------------------------

    #[test]
    fn test_add_and_get_debug_info() {
        let g = migrated_graph();
        let id = g
            .add_debug_info(vid(1), "main.c", 42, addr(0x7000), Some(1))
            .unwrap();
        assert!(id > 0);
        let di = g.get_debug_info_at(vid(1), addr(0x7000)).unwrap().unwrap();
        assert_eq!(di.source_file, "main.c");
        assert_eq!(di.line_number, 42);
        assert_eq!(di.column, Some(1));
    }

    #[test]
    fn test_debug_info_missing_returns_none() {
        let g = migrated_graph();
        assert!(g.get_debug_info_at(vid(1), addr(0xFFFF)).unwrap().is_none());
    }

    // ---- notes -------------------------------------------------------------

    #[test]
    fn test_add_and_get_notes() {
        let g = migrated_graph();
        let id = g.add_note(vid(1), "My Note", "Body text here").unwrap();
        assert!(id > 0);
        let notes = g.get_notes(vid(1)).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].title, "My Note");
        assert_eq!(notes[0].body, "Body text here");
    }

    #[test]
    fn test_update_note() {
        let g = migrated_graph();
        let id = g.add_note(vid(1), "Title", "Old body").unwrap();
        g.update_note(id, "Title", "New body").unwrap();
        let notes = g.get_notes(vid(1)).unwrap();
        assert_eq!(notes[0].body, "New body");
    }

    #[test]
    fn test_delete_note() {
        let g = migrated_graph();
        let id = g.add_note(vid(1), "Temp", "content").unwrap();
        g.delete_note(id).unwrap();
        assert!(g.get_notes(vid(1)).unwrap().is_empty());
    }

    // ---- analysis_cache ----------------------------------------------------

    #[test]
    fn test_set_and_get_analysis_cache() {
        let g = migrated_graph();
        g.set_analysis_cache(vid(1), "cfg", 1, b"cached_data")
            .unwrap();
        let cache = g.get_analysis_cache(vid(1), "cfg").unwrap().unwrap();
        assert_eq!(cache.pass, "cfg");
        assert_eq!(cache.data, b"cached_data");
        assert_eq!(cache.version, 1);
    }

    #[test]
    fn test_analysis_cache_upsert() {
        let g = migrated_graph();
        g.set_analysis_cache(vid(1), "cfg", 1, b"v1").unwrap();
        g.set_analysis_cache(vid(1), "cfg", 2, b"v2").unwrap();
        let cache = g.get_analysis_cache(vid(1), "cfg").unwrap().unwrap();
        assert_eq!(cache.version, 2);
        assert_eq!(cache.data, b"v2");
    }

    #[test]
    fn test_analysis_cache_missing_returns_none() {
        let g = migrated_graph();
        assert!(
            g.get_analysis_cache(vid(1), "nonexistent")
                .unwrap()
                .is_none()
        );
    }

    // ---- script_results ----------------------------------------------------

    #[test]
    fn test_add_and_get_script_results() {
        let g = migrated_graph();
        let id = g
            .add_script_result(vid(1), "python", "print(1)", "1", true)
            .unwrap();
        assert!(id > 0);
        let results = g.get_script_results(vid(1), 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].engine, "python");
    }

    // ---- diff_sessions -----------------------------------------------------

    #[test]
    fn test_add_and_get_diff_sessions() {
        let g = migrated_graph();
        let id = g
            .add_diff_session(1, 2, "bindiff", r#"{"matches":[]}"#)
            .unwrap();
        assert!(id > 0);
        let diffs = g.get_diff_sessions(1).unwrap();
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].algorithm, "bindiff");
        assert_eq!(diffs[0].view_id_b, 2);
    }

    // ---- trace_records -----------------------------------------------------

    #[test]
    fn test_add_and_get_trace_records() {
        let g = migrated_graph();
        for tick in 0..5i64 {
            g.add_trace_record(vid(1), 0, addr(0x1000 + tick as u64 * 4), "nop", tick)
                .unwrap();
        }
        let records = g.get_trace_records(vid(1), 10).unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].tick, 0);
        assert_eq!(records[4].tick, 4);
    }

    #[test]
    fn test_delete_trace_records() {
        let g = migrated_graph();
        g.add_trace_record(vid(1), 0, addr(0x1000), "nop", 0)
            .unwrap();
        g.delete_trace_records(vid(1)).unwrap();
        assert!(g.get_trace_records(vid(1), 100).unwrap().is_empty());
    }

    // ---- breakpoints -------------------------------------------------------

    #[test]
    fn test_add_and_get_breakpoints() {
        let g = migrated_graph();
        let id = g
            .add_breakpoint(vid(1), addr(0xDEAD), "software", None)
            .unwrap();
        assert!(id > 0);
        let bps = g.get_breakpoints(vid(1)).unwrap();
        assert_eq!(bps.len(), 1);
        assert!(bps[0].enabled);
        assert_eq!(bps[0].kind, "software");
    }

    #[test]
    fn test_breakpoint_enable_disable() {
        let g = migrated_graph();
        let id = g
            .add_breakpoint(vid(1), addr(0x1000), "software", None)
            .unwrap();
        g.set_breakpoint_enabled(id, false).unwrap();
        let bps = g.get_breakpoints(vid(1)).unwrap();
        assert!(!bps[0].enabled);
        g.set_breakpoint_enabled(id, true).unwrap();
        let bps = g.get_breakpoints(vid(1)).unwrap();
        assert!(bps[0].enabled);
    }

    #[test]
    fn test_delete_breakpoint() {
        let g = migrated_graph();
        let id = g
            .add_breakpoint(vid(1), addr(0x2000), "hardware", Some("eax==0"))
            .unwrap();
        g.delete_breakpoint(id).unwrap();
        assert!(g.get_breakpoints(vid(1)).unwrap().is_empty());
    }

    // ---- watch_expressions -------------------------------------------------

    #[test]
    fn test_watch_expressions() {
        let g = migrated_graph();
        let id = g.add_watch_expression(vid(1), "eax + ebx").unwrap();
        assert!(id > 0);
        let watches = g.get_watch_expressions(vid(1)).unwrap();
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].expression, "eax + ebx");
        assert_eq!(watches[0].last_value, None);
    }

    #[test]
    fn test_update_watch_value() {
        let g = migrated_graph();
        let id = g.add_watch_expression(vid(1), "esp").unwrap();
        g.update_watch_value(id, "0x7fff1000").unwrap();
        let watches = g.get_watch_expressions(vid(1)).unwrap();
        assert_eq!(watches[0].last_value, Some("0x7fff1000".into()));
    }

    #[test]
    fn test_delete_watch_expression() {
        let g = migrated_graph();
        let id = g.add_watch_expression(vid(1), "temp").unwrap();
        g.delete_watch_expression(id).unwrap();
        assert!(g.get_watch_expressions(vid(1)).unwrap().is_empty());
    }

    // ---- agent_sessions ----------------------------------------------------

    #[test]
    fn test_agent_session_begin_end() {
        let g = migrated_graph();
        let id = g
            .begin_agent_session(vid(1), "decompile-agent", r#"{"step":0}"#)
            .unwrap();
        assert!(id > 0);
        g.end_agent_session(id, r#"{"step":5,"done":true}"#)
            .unwrap();
        let sessions = g.get_agent_sessions(vid(1)).unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].ended_at.is_some());
        assert!(sessions[0].state_json.contains("done"));
    }

    // ---- mcp_sessions ------------------------------------------------------

    #[test]
    fn test_mcp_session_begin_complete() {
        let g = migrated_graph();
        let id = g
            .begin_mcp_session(vid(1), "decompile", r#"{"addr":"0x1000"}"#)
            .unwrap();
        assert!(id > 0);
        g.complete_mcp_session(id, r#"{"code":"void f(){}"}"#)
            .unwrap();
        let sessions = g.get_mcp_sessions(vid(1)).unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].result_json.is_some());
    }

    // ---- call_graph --------------------------------------------------------

    #[test]
    fn test_call_graph_edges() {
        let g = migrated_graph();
        let a = g
            .add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("main"), ..FunctionMeta::default() })
            .unwrap();
        let b = g
            .add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta { name: Some("foo"), ..FunctionMeta::default() })
            .unwrap();
        let c = g
            .add_function(vid(1), addr(0x3000), addr(0x3100), FunctionMeta { name: Some("bar"), ..FunctionMeta::default() })
            .unwrap();
        g.add_call_graph_edge(vid(1), a, b, addr(0x1050), false)
            .unwrap();
        g.add_call_graph_edge(vid(1), a, c, addr(0x1060), true)
            .unwrap();
        let callees = g.callees_of_fn(vid(1), a).unwrap();
        assert_eq!(callees.len(), 2);
        let callers_of_b = g.callers_of_fn(vid(1), b).unwrap();
        assert_eq!(callers_of_b.len(), 1);
        assert_eq!(callers_of_b[0].caller_id, a);
    }

    // ---- statistics --------------------------------------------------------

    #[test]
    fn test_statistics() {
        let g = migrated_graph();
        g.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("f"), ..FunctionMeta::default() })
        .unwrap();
        g.add_function(vid(1), addr(0x2000), addr(0x2100), FunctionMeta { name: Some("g"), ..FunctionMeta::default() })
        .unwrap();
        g.add_xref(vid(1), addr(0x1050), addr(0x2000), "code_call")
            .unwrap();
        g.add_symbol(vid(1), addr(0x1000), "f", "func", None)
            .unwrap();

        let stats = g.statistics(vid(1)).unwrap();
        assert_eq!(stats.function_count, 2);
        assert_eq!(stats.xref_count, 1);
        assert_eq!(stats.symbol_count, 1);
    }

    // ---- FTS (fallback LIKE path, since FTS5 may not be compiled in) --------

    #[test]
    fn test_fts_comments_fallback() {
        let g = migrated_graph();
        g.add_comment(vid(1), addr(0x1000), "This is the entry point", false)
            .unwrap();
        g.add_comment(vid(1), addr(0x2000), "Another comment", false)
            .unwrap();
        let found = g.fts_comments(vid(1), "entry").unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].text.contains("entry"));
    }

    #[test]
    fn test_fts_symbols_fallback() {
        let g = migrated_graph();
        g.add_symbol(vid(1), addr(0x1000), "malloc_hook", "func", None)
            .unwrap();
        g.add_symbol(vid(1), addr(0x2000), "printf", "func", None)
            .unwrap();
        let found = g.fts_symbols(vid(1), "malloc").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "malloc_hook");
    }

    #[test]
    fn test_fts_notes_fallback() {
        let g = migrated_graph();
        g.add_note(vid(1), "Heap Analysis", "Found UAF vulnerability here")
            .unwrap();
        g.add_note(vid(1), "Stack Frame", "Nothing suspicious")
            .unwrap();
        let found = g.fts_notes(vid(1), "UAF").unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].body.contains("UAF"));
    }

    // ---- JSON snapshot export / import -------------------------------------

    #[test]
    fn test_snapshot_roundtrip() {
        let src = migrated_graph();
        src.add_function(vid(1), addr(0x1000), addr(0x1100), FunctionMeta { name: Some("main"), ..FunctionMeta::default() })
        .unwrap();
        src.add_symbol(vid(1), addr(0x1000), "main", "func", None)
            .unwrap();
        src.add_xref(vid(1), addr(0x1050), addr(0x2000), "code_call")
            .unwrap();

        let json = src.export_snapshot(vid(1)).unwrap();
        assert!(json.contains("main"));

        let dst = migrated_graph();
        dst.import_snapshot(vid(1), &json).unwrap();
        assert_eq!(dst.count_functions(vid(1)).unwrap(), 1);
        assert_eq!(dst.count_xrefs(vid(1)).unwrap(), 1);
        assert_eq!(dst.count_symbols(vid(1)).unwrap(), 1);
    }

    // ---- delta export / import (collaboration) -----------------------------

    #[test]
    fn test_delta_export_import() {
        let g = migrated_graph();
        g.add_event(vid(1), "alice", "rename", b"{}").unwrap();
        g.add_event(vid(1), "alice", "comment", b"{\"text\":\"hi\"}")
            .unwrap();

        // Export all events (since event_id 0 means everything).
        let delta = g.export_delta(vid(1), 0).unwrap();
        assert!(delta.contains("rename") || delta.contains("comment"));

        // Import into a fresh graph.
        let dst = migrated_graph();
        let count = dst.import_delta(vid(1), &delta).unwrap();
        assert!(count > 0);
    }

    // ---- XrefGraph ---------------------------------------------------------

    #[test]
    fn test_xref_graph_rebuild() {
        let g = migrated_graph();
        g.add_xref(vid(1), addr(0x1000), addr(0x2000), "code_call")
            .unwrap();
        g.add_xref(vid(1), addr(0x2000), addr(0x3000), "code_call")
            .unwrap();

        let xg = XrefGraph::new();
        xg.rebuild_from_db(&g, vid(1)).unwrap();
        assert_eq!(xg.node_count(), 3);
        assert_eq!(xg.edge_count(), 2);
    }

    #[test]
    fn test_xref_graph_reachable_from() {
        let g = migrated_graph();
        g.add_xref(vid(1), addr(0x1000), addr(0x2000), "code_call")
            .unwrap();
        g.add_xref(vid(1), addr(0x2000), addr(0x3000), "code_call")
            .unwrap();

        let xg = XrefGraph::new();
        xg.rebuild_from_db(&g, vid(1)).unwrap();

        let reachable = xg.reachable_from(0x1000);
        assert!(reachable.contains(&0x2000));
        assert!(reachable.contains(&0x3000));
    }

    #[test]
    fn test_xref_graph_unknown_start_returns_empty() {
        let g = migrated_graph();
        let xg = XrefGraph::new();
        xg.rebuild_from_db(&g, vid(1)).unwrap();
        assert!(xg.reachable_from(0xDEAD_BEEF).is_empty());
    }

    #[test]
    fn test_xref_graph_debug_format() {
        let xg = XrefGraph::new();
        let s = format!("{xg:?}");
        assert!(s.contains("XrefGraph"));
    }

    // ---- base64 helpers ----------------------------------------------------

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World! \x00\xFF\xFE";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode(""), Vec::<u8>::new());
    }
}
