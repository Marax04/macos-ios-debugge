//! rustre-project — project file management and persisted session state.
//!
//! Spec §34.6 and §36.1 plus the expanded spec for multi-view projects:
//!
//! - [`Project`] — a directory-backed project containing a `.rustre-project/`
//!   subdirectory with SQLite DB, JSON metadata, and well-known subdirectories.
//! - [`ProjectManager`] — manages multiple concurrently-open projects.
//! - [`ProjectSession`] — active runtime session (open views + scripts).
//! - [`ProjectFile`] (container) — ZIP-like `.rustre` container format (metadata).
//! - Version history: last 10 SQLite snapshots per binary view for undo.
//! - Auto-save: configurable interval, default 5 minutes.
//! - Collaboration delta: export/import changeset since last sync.
pub mod analysis_cache;
pub mod annotation_store;
pub mod collaboration;
pub mod export;
pub mod plugin_manager;
pub mod project_db_extended;
pub mod project_migrator;
pub mod project_serializer;
pub mod project_templates;
pub mod search;
pub mod session;
pub mod session_management;
pub mod workspace;
pub mod project_diff;

pub use session_management::{
    ActiveSession, MultiSession, SessionExport, SessionHistory, SessionManagement, SessionRestore,
    SessionState,
};
//
// Spec §34.6 and §36.1 plus the expanded spec for multi-view projects:
//
// - [`Project`] — a directory-backed project containing a `.rustre-project/`
//   subdirectory with SQLite DB, JSON metadata, and well-known subdirectories.
// - [`ProjectManager`] — manages multiple concurrently-open projects.
// - [`ProjectSession`] — active runtime session (open views + scripts).
// - [`ProjectFile`] (container) — ZIP-like `.rustre` container format (metadata).
// - Version history: last 10 SQLite snapshots per binary view for undo.
// - Auto-save: configurable interval, default 5 minutes.
// - Collaboration delta: export/import changeset since last sync.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use rusqlite::{Connection, Result as SqlResult, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const PROJECT_DIR_NAME: &str = ".rustre-project";
pub const CURRENT_SCHEMA_VERSION: u32 = 4;
const META_FILE: &str = "meta.json";
const DB_FILE: &str = "project.db";
/// Default auto-save interval.
pub const DEFAULT_AUTOSAVE_INTERVAL_SECS: u64 = 300; // 5 minutes
/// Maximum version history snapshots per view.
pub const MAX_VERSION_SNAPSHOTS: usize = 10;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("project directory not found at {0}")]
    NotFound(PathBuf),
    #[error("project already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("metadata file is corrupt or missing: {0}")]
    CorruptMetadata(#[source] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("binary not found: {0}")]
    BinaryNotFound(String),
    #[error("hash error: {0}")]
    HashError(String),
    #[error("migration failed at version {version}: {source}")]
    MigrationFailed {
        version: u32,
        #[source]
        source: rusqlite::Error,
    },
    #[error("project not found in manager: {0}")]
    ProjectNotManaged(String),
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("view not found: {0}")]
    ViewNotFound(String),
    #[error("script not found: {0}")]
    ScriptNotFound(String),
}

pub type Result<T> = std::result::Result<T, ProjectError>;

// ── ProjectMetadata ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub name: String,
    pub created_at: u64,
    pub last_modified: u64,
    /// ISO-8601 representation of `created_at` for human-readable display
    /// (e.g. in meta.json and event logs).
    #[serde(default)]
    pub created_at_iso: String,
    pub version: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub author: Option<String>,
}

impl ProjectMetadata {
    fn new(name: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            name: name.into(),
            created_at: now,
            last_modified: now,
            created_at_iso: unix_to_iso8601(now),
            version: "1.0.0".into(),
            description: None,
            tags: Vec::new(),
            author: None,
        }
    }
}

// ── BinaryEntry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryEntry {
    pub id: u64,
    pub sha256: String,
    pub path: String,
    pub format: String,
    pub arch: String,
    pub added_at: u64,
    pub size_bytes: Option<i64>,
    pub entry_point: Option<i64>,
    pub base_addr: Option<i64>,
}

// ── FunctionEntry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub id: u64,
    pub binary_id: u64,
    pub addr: u64,
    pub name: String,
    pub size_bytes: Option<i64>,
    pub is_thunk: bool,
    pub calling_conv: Option<String>,
    pub return_type: Option<String>,
    pub flags: i64,
    pub created_at: u64,
    pub updated_at: u64,
}

// ── EventEntry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub id: u64,
    pub binary_id: Option<u64>,
    pub kind: String,
    pub payload: Vec<u8>,
    pub occurred_at: u64,
}

// ── TriageResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub id: u64,
    pub binary_id: u64,
    pub scanner: String,
    pub verdict: String,
    pub score: f64,
    pub details: String,
    pub scanned_at: u64,
}

// ── KgBackend / ProjectConfig ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[derive(Default)]
pub enum KgBackend {
    Sqlite { path: String },
    #[default]
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub kg_backend: KgBackend,
    pub default_arch: Option<String>,
    #[serde(default)]
    pub plugins: Vec<String>,
    #[serde(default = "default_true")]
    pub wal_mode: bool,
    #[serde(default = "default_undo_limit")]
    pub undo_limit: u32,
    /// Auto-save interval in seconds. 0 = disabled.
    #[serde(default = "default_autosave")]
    pub autosave_interval_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_undo_limit() -> u32 {
    1000
}
fn default_autosave() -> u64 {
    DEFAULT_AUTOSAVE_INTERVAL_SECS
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            kg_backend: KgBackend::default(),
            default_arch: None,
            plugins: Vec::new(),
            wal_mode: true,
            undo_limit: 1000,
            autosave_interval_secs: DEFAULT_AUTOSAVE_INTERVAL_SECS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectFileMeta {
    metadata: ProjectMetadata,
    config: ProjectConfig,
}

// ── BinaryStats ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryStats {
    pub function_count: u64,
    pub xref_count: u64,
    pub symbol_count: u64,
    pub comment_count: u64,
    pub string_count: u64,
    pub bookmark_count: u64,
}

// ── Migrations ────────────────────────────────────────────────────────────────

pub struct Migration {
    pub version: u32,
    pub description: String,
    pub sql: String,
}

#[must_use] 
pub fn get_migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            description: "Create core analysis tables".into(),
            sql: r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE, path TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
    added_at INTEGER NOT NULL, size_bytes INTEGER, entry_point INTEGER, base_addr INTEGER, notes TEXT
);
CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, name TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER, is_thunk INTEGER NOT NULL DEFAULT 0,
    calling_conv TEXT, return_type TEXT, flags INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    UNIQUE(binary_id, addr)
);
CREATE TABLE IF NOT EXISTS basic_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, size_bytes INTEGER NOT NULL, flags INTEGER NOT NULL DEFAULT 0,
    UNIQUE(function_id, addr)
);
CREATE TABLE IF NOT EXISTS edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    src_addr INTEGER NOT NULL, dst_addr INTEGER NOT NULL,
    edge_type TEXT NOT NULL DEFAULT 'unconditional', flags INTEGER NOT NULL DEFAULT 0,
    UNIQUE(binary_id, src_addr, dst_addr, edge_type)
);
CREATE TABLE IF NOT EXISTS xrefs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    from_addr INTEGER NOT NULL, to_addr INTEGER NOT NULL,
    xref_type TEXT NOT NULL DEFAULT 'code', flags INTEGER NOT NULL DEFAULT 0,
    UNIQUE(binary_id, from_addr, to_addr, xref_type)
);
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, name TEXT NOT NULL,
    symbol_type TEXT NOT NULL DEFAULT 'unknown', source TEXT NOT NULL DEFAULT 'user',
    mangled TEXT, flags INTEGER NOT NULL DEFAULT 0,
    UNIQUE(binary_id, addr, name)
);
CREATE TABLE IF NOT EXISTS types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'struct',
    definition TEXT NOT NULL DEFAULT '', size_bytes INTEGER, flags INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(binary_id, name)
);
CREATE TABLE IF NOT EXISTS variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    name TEXT NOT NULL, var_type TEXT NOT NULL DEFAULT '', storage TEXT NOT NULL DEFAULT 'stack',
    offset INTEGER, flags INTEGER NOT NULL DEFAULT 0, UNIQUE(function_id, name)
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, body TEXT NOT NULL, comment_type TEXT NOT NULL DEFAULT 'line',
    author TEXT NOT NULL DEFAULT 'user', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    UNIQUE(binary_id, addr, comment_type)
);
CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, label TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '#ffff00',
    created_at INTEGER NOT NULL, UNIQUE(binary_id, addr)
);
CREATE TABLE IF NOT EXISTS strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, value TEXT NOT NULL, encoding TEXT NOT NULL DEFAULT 'utf8',
    length INTEGER NOT NULL, flags INTEGER NOT NULL DEFAULT 0, UNIQUE(binary_id, addr)
);
CREATE TABLE IF NOT EXISTS annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT 'note', body TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT 'user', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
    kind TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}', occurred_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS undo_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL, seq INTEGER NOT NULL, table_name TEXT NOT NULL,
    operation TEXT NOT NULL, row_id INTEGER NOT NULL,
    before_json TEXT, after_json TEXT, committed_at INTEGER NOT NULL,
    UNIQUE(session_id, seq)
);
CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, language TEXT NOT NULL DEFAULT 'python',
    body TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL UNIQUE, body TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr INTEGER NOT NULL, original_bytes BLOB NOT NULL, patched_bytes BLOB NOT NULL,
    description TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
    UNIQUE(binary_id, addr)
);
CREATE TABLE IF NOT EXISTS version_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    snapshot_data BLOB NOT NULL, created_at INTEGER NOT NULL, description TEXT
);
CREATE TABLE IF NOT EXISTS layout_state (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    layout_json TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_functions_binary ON functions(binary_id);
CREATE INDEX IF NOT EXISTS idx_functions_addr ON functions(addr);
CREATE INDEX IF NOT EXISTS idx_bb_function ON basic_blocks(function_id);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(binary_id, src_addr);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(binary_id, dst_addr);
CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(binary_id, from_addr);
CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(binary_id, to_addr);
CREATE INDEX IF NOT EXISTS idx_symbols_addr ON symbols(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(binary_id, name);
CREATE INDEX IF NOT EXISTS idx_comments_addr ON comments(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_strings_addr ON strings(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_undo_session ON undo_log(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_patches_binary ON patches(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_version_history ON version_history(binary_id, created_at);
"#.into(),
        },
        Migration {
            version: 2,
            description: "Add performance indices".into(),
            sql: r#"
CREATE INDEX IF NOT EXISTS idx_binaries_sha256 ON binaries(sha256);
CREATE INDEX IF NOT EXISTS idx_binaries_format ON binaries(format);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_types_kind ON types(binary_id, kind);
CREATE INDEX IF NOT EXISTS idx_variables_fn ON variables(function_id);
CREATE INDEX IF NOT EXISTS idx_annotations_addr ON annotations(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_bookmarks_addr ON bookmarks(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_events_binary ON events(binary_id);
CREATE INDEX IF NOT EXISTS idx_events_occurred ON events(occurred_at);
"#.into(),
        },
        Migration {
            version: 3,
            description: "FTS5 string search".into(),
            sql: r#"
CREATE VIRTUAL TABLE IF NOT EXISTS strings_fts
    USING fts5(value, content=strings, content_rowid=id);
CREATE TRIGGER IF NOT EXISTS strings_fts_ai AFTER INSERT ON strings BEGIN
    INSERT INTO strings_fts(rowid, value) VALUES (new.id, new.value);
END;
CREATE TRIGGER IF NOT EXISTS strings_fts_ad AFTER DELETE ON strings BEGIN
    INSERT INTO strings_fts(strings_fts, rowid, value) VALUES('delete', old.id, old.value);
END;
CREATE TRIGGER IF NOT EXISTS strings_fts_au AFTER UPDATE ON strings BEGIN
    INSERT INTO strings_fts(strings_fts, rowid, value) VALUES('delete', old.id, old.value);
    INSERT INTO strings_fts(rowid, value) VALUES (new.id, new.value);
END;
"#.into(),
        },
        Migration {
            version: 4,
            description: "Triage results table".into(),
            sql: r#"
CREATE TABLE IF NOT EXISTS triage_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT 'unknown',
    score REAL NOT NULL DEFAULT 0.0, details TEXT NOT NULL DEFAULT '',
    scanned_at INTEGER NOT NULL, UNIQUE(binary_id, scanner)
);
CREATE INDEX IF NOT EXISTS idx_triage_binary ON triage_results(binary_id);
CREATE INDEX IF NOT EXISTS idx_triage_scanner ON triage_results(scanner);
CREATE INDEX IF NOT EXISTS idx_triage_verdict ON triage_results(verdict);
"#.into(),
        },
    ]
}

pub fn run_pending_migrations(conn: &Connection) -> Result<u32> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);")?;
    let applied: std::collections::HashSet<u32> = {
        let mut stmt = conn.prepare("SELECT version FROM schema_migrations")?;
        stmt.query_map([], |row| row.get::<_, u32>(0))?
            .collect::<SqlResult<_>>()?
    };
    let mut count = 0u32;
    for m in get_migrations() {
        if applied.contains(&m.version) {
            continue;
        }
        conn.execute_batch(&m.sql)
            .map_err(|e| ProjectError::MigrationFailed {
                version: m.version,
                source: e,
            })?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
            params![m.version, unix_now()],
        )?;
        count += 1;
    }
    Ok(count)
}

pub fn run_migrations(conn: &Connection) -> Result<()> {
    run_pending_migrations(conn).map(|_| ())
}

// ── BinaryProject trait ───────────────────────────────────────────────────────

pub trait BinaryProject {
    fn add_binary(&mut self, path: &Path, sha256: &str) -> Result<u64>;
    fn get_binary(&self, id: u64) -> Result<Option<BinaryEntry>>;
    fn add_function(&mut self, binary_id: u64, addr: u64, name: &str) -> Result<u64>;
    fn get_function(&self, binary_id: u64, addr: u64) -> Result<Option<FunctionEntry>>;
    fn add_comment(&mut self, binary_id: u64, addr: u64, text: &str) -> Result<()>;
    fn add_xref(&mut self, binary_id: u64, from: u64, to: u64, kind: &str) -> Result<()>;
    fn add_event(&mut self, kind: &str, actor: &str, payload: &[u8]) -> Result<u64>;
}

// ── Project ───────────────────────────────────────────────────────────────────

/// A RustRE project — all persistent state inside `<root>/.rustre-project/`.
#[derive(Debug)]
pub struct Project {
    root_dir: PathBuf,
    metadata: ProjectMetadata,
    config: ProjectConfig,
    last_autosave: std::time::Instant,
    /// Cached database connection; shared across all method calls to avoid
    /// opening a new file descriptor on every operation.
    db_conn: Arc<Mutex<Connection>>,
}

impl Project {
    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn new(name: impl Into<String>, root_dir: impl AsRef<Path>) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let project_dir = root_dir.join(PROJECT_DIR_NAME);
        if project_dir.exists() {
            return Err(ProjectError::AlreadyExists(project_dir));
        }
        fs::create_dir_all(&project_dir)?;
        for sub in &[
            "recordings",
            "sandbox",
            "attachments",
            "workflows",
            "scripts",
            "reports",
            "views",
            "snapshots",
        ] {
            fs::create_dir_all(project_dir.join(sub))?;
        }
        let metadata = ProjectMetadata::new(name);
        let config = ProjectConfig::default();
        let db = Connection::open(project_dir.join(DB_FILE))?;
        // Apply WAL mode and foreign keys at connection setup (config defaults have wal_mode=true)
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        run_migrations(&db)?;
        let db_conn = Arc::new(Mutex::new(db));
        let p = Self {
            root_dir,
            metadata,
            config,
            last_autosave: std::time::Instant::now(),
            db_conn,
        };
        p.write_meta()?;
        Ok(p)
    }

    pub fn open(root_dir: impl AsRef<Path>) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let project_dir = root_dir.join(PROJECT_DIR_NAME);
        if !project_dir.exists() {
            return Err(ProjectError::NotFound(project_dir));
        }
        let db = Connection::open(project_dir.join(DB_FILE))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        run_migrations(&db)?;
        let db_conn = Arc::new(Mutex::new(db));
        let (metadata, config) = Self::read_meta(&project_dir)?;
        Ok(Self {
            root_dir,
            metadata,
            config,
            last_autosave: std::time::Instant::now(),
            db_conn,
        })
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    pub fn save(&self) -> Result<()> {
        self.write_meta()
    }

    /// Check if autosave is due and save if so.
    pub fn maybe_autosave(&mut self) -> Result<bool> {
        if self.config.autosave_interval_secs == 0 {
            return Ok(false);
        }
        let elapsed = self.last_autosave.elapsed();
        if elapsed >= Duration::from_secs(self.config.autosave_interval_secs) {
            self.write_meta()?;
            self.last_autosave = std::time::Instant::now();
            return Ok(true);
        }
        Ok(false)
    }

    fn write_meta(&self) -> Result<()> {
        let pf = ProjectFileMeta {
            metadata: self.metadata.clone(),
            config: self.config.clone(),
        };
        let json = serde_json::to_string_pretty(&pf).map_err(ProjectError::CorruptMetadata)?;
        fs::write(self.project_dir().join(META_FILE), json)?;
        Ok(())
    }

    fn read_meta(project_dir: &Path) -> Result<(ProjectMetadata, ProjectConfig)> {
        let raw = fs::read_to_string(project_dir.join(META_FILE))?;
        let pf: ProjectFileMeta =
            serde_json::from_str(&raw).map_err(ProjectError::CorruptMetadata)?;
        Ok((pf.metadata, pf.config))
    }

    // ── Binary management ─────────────────────────────────────────────────────

    pub fn add_binary_from_path(&self, path: impl AsRef<Path>) -> Result<BinaryEntry> {
        let path = path.as_ref();
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let bytes = fs::read(path)?;
        let sha256 = sha256_hex(&bytes);
        let (format, arch) = classify_binary(&bytes, &self.config);
        let now = unix_now();
        let size = bytes.len() as i64;
        let db = self.open_db()?;
        db.execute(
            "INSERT OR IGNORE INTO binaries (sha256, path, format, arch, added_at, size_bytes) VALUES (?1,?2,?3,?4,?5,?6)",
            params![sha256, canonical.to_string_lossy().as_ref(), format, arch, now, size],
        )?;
        let id: u64 = db.query_row(
            "SELECT id FROM binaries WHERE sha256 = ?1",
            params![sha256],
            |r| r.get::<_, i64>(0),
        )? as u64;
        Ok(BinaryEntry {
            id,
            sha256,
            path: canonical.to_string_lossy().into_owned(),
            format,
            arch,
            added_at: now,
            size_bytes: Some(size),
            entry_point: None,
            base_addr: None,
        })
    }

    pub fn add_binary(&self, path: impl AsRef<Path>) -> Result<BinaryEntry> {
        self.add_binary_from_path(path)
    }

    #[must_use]
    pub fn list_binaries(&self) -> Vec<BinaryEntry> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT id,sha256,path,format,arch,added_at,size_bytes,entry_point,base_addr FROM binaries ORDER BY id") else { return vec![] };
        stmt.query_map([], |r| {
            Ok(BinaryEntry {
                id: r.get::<_, i64>(0)? as u64,
                sha256: r.get(1)?,
                path: r.get(2)?,
                format: r.get(3)?,
                arch: r.get(4)?,
                added_at: r.get(5)?,
                size_bytes: r.get(6)?,
                entry_point: r.get(7)?,
                base_addr: r.get(8)?,
            })
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn find_binary_by_sha256(&self, sha256: &str) -> Result<Option<BinaryEntry>> {
        let db = self.open_db()?;
        let mut stmt = db.prepare("SELECT id,sha256,path,format,arch,added_at,size_bytes,entry_point,base_addr FROM binaries WHERE sha256=?1")?;
        let mut rows = stmt.query(params![sha256])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(BinaryEntry {
                id: r.get::<_, i64>(0)? as u64,
                sha256: r.get(1)?,
                path: r.get(2)?,
                format: r.get(3)?,
                arch: r.get(4)?,
                added_at: r.get(5)?,
                size_bytes: r.get(6)?,
                entry_point: r.get(7)?,
                base_addr: r.get(8)?,
            }));
        }
        Ok(None)
    }

    pub fn remove_binary(&self, binary_id: u64) -> Result<bool> {
        let db = self.open_db()?;
        Ok(db.execute(
            "DELETE FROM binaries WHERE id=?1",
            params![binary_id as i64],
        )? > 0)
    }

    // ── Function management ───────────────────────────────────────────────────

    pub fn add_function_record(&self, binary_id: u64, addr: u64, name: &str) -> Result<u64> {
        let db = self.open_db()?;
        let now = unix_now();
        db.execute("INSERT OR IGNORE INTO functions (binary_id,addr,name,created_at,updated_at) VALUES (?1,?2,?3,?4,?5)", params![binary_id as i64, addr as i64, name, now, now])?;
        Ok(db.query_row(
            "SELECT id FROM functions WHERE binary_id=?1 AND addr=?2",
            params![binary_id as i64, addr as i64],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    pub fn get_function_by_addr(&self, binary_id: u64, addr: u64) -> Result<Option<FunctionEntry>> {
        let db = self.open_db()?;
        let mut stmt = db.prepare("SELECT id,binary_id,addr,name,size_bytes,is_thunk,calling_conv,return_type,flags,created_at,updated_at FROM functions WHERE binary_id=?1 AND addr=?2")?;
        let mut rows = stmt.query(params![binary_id as i64, addr as i64])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(FunctionEntry {
                id: r.get::<_, i64>(0)? as u64,
                binary_id: r.get::<_, i64>(1)? as u64,
                addr: r.get::<_, i64>(2)? as u64,
                name: r.get(3)?,
                size_bytes: r.get(4)?,
                is_thunk: r.get::<_, i64>(5)? != 0,
                calling_conv: r.get(6)?,
                return_type: r.get(7)?,
                flags: r.get(8)?,
                created_at: r.get::<_, i64>(9)? as u64,
                updated_at: r.get::<_, i64>(10)? as u64,
            }));
        }
        Ok(None)
    }

    #[must_use]
    pub fn list_functions(&self, binary_id: u64) -> Vec<FunctionEntry> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT id,binary_id,addr,name,size_bytes,is_thunk,calling_conv,return_type,flags,created_at,updated_at FROM functions WHERE binary_id=?1 ORDER BY addr") else { return vec![] };
        stmt.query_map(params![binary_id as i64], |r| {
            Ok(FunctionEntry {
                id: r.get::<_, i64>(0)? as u64,
                binary_id: r.get::<_, i64>(1)? as u64,
                addr: r.get::<_, i64>(2)? as u64,
                name: r.get(3)?,
                size_bytes: r.get(4)?,
                is_thunk: r.get::<_, i64>(5)? != 0,
                calling_conv: r.get(6)?,
                return_type: r.get(7)?,
                flags: r.get(8)?,
                created_at: r.get::<_, i64>(9)? as u64,
                updated_at: r.get::<_, i64>(10)? as u64,
            })
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn rename_function(&self, binary_id: u64, addr: u64, new_name: &str) -> Result<bool> {
        let db = self.open_db()?;
        Ok(db.execute(
            "UPDATE functions SET name=?1, updated_at=?2 WHERE binary_id=?3 AND addr=?4",
            params![new_name, unix_now(), binary_id as i64, addr as i64],
        )? > 0)
    }

    // ── Comments ──────────────────────────────────────────────────────────────

    pub fn add_comment_record(&self, binary_id: u64, addr: u64, text: &str) -> Result<()> {
        let db = self.open_db()?;
        let now = unix_now();
        db.execute(
            "INSERT INTO comments (binary_id,addr,body,created_at,updated_at) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(binary_id,addr,comment_type) DO UPDATE SET body=excluded.body, updated_at=excluded.updated_at",
            params![binary_id as i64, addr as i64, text, now, now],
        )?;
        Ok(())
    }

    pub fn get_comment(&self, binary_id: u64, addr: u64) -> Result<Option<String>> {
        let db = self.open_db()?;
        let mut stmt =
            db.prepare("SELECT body FROM comments WHERE binary_id=?1 AND addr=?2 LIMIT 1")?;
        let mut rows = stmt.query(params![binary_id as i64, addr as i64])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(r.get(0)?));
        }
        Ok(None)
    }

    // ── Xrefs ─────────────────────────────────────────────────────────────────

    pub fn add_xref_record(&self, binary_id: u64, from: u64, to: u64, kind: &str) -> Result<()> {
        let db = self.open_db()?;
        db.execute("INSERT OR IGNORE INTO xrefs (binary_id,from_addr,to_addr,xref_type) VALUES (?1,?2,?3,?4)", params![binary_id as i64, from as i64, to as i64, kind])?;
        Ok(())
    }

    #[must_use]
    pub fn xrefs_to(&self, binary_id: u64, addr: u64) -> Vec<(u64, u64, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare(
            "SELECT from_addr,to_addr,xref_type FROM xrefs WHERE binary_id=?1 AND to_addr=?2",
        ) else { return vec![] };
        stmt.query_map(params![binary_id as i64, addr as i64], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, String>(2)?,
            ))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    #[must_use]
    pub fn xrefs_from(&self, binary_id: u64, addr: u64) -> Vec<(u64, u64, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare(
            "SELECT from_addr,to_addr,xref_type FROM xrefs WHERE binary_id=?1 AND from_addr=?2",
        ) else { return vec![] };
        stmt.query_map(params![binary_id as i64, addr as i64], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, String>(2)?,
            ))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Events ────────────────────────────────────────────────────────────

    pub fn add_event_record(
        &self,
        kind: &str,
        binary_id: Option<u64>,
        payload: &[u8],
    ) -> Result<u64> {
        let db = self.open_db()?;
        let now = unix_now();
        let payload_text = String::from_utf8_lossy(payload).into_owned();
        db.execute(
            "INSERT INTO events (binary_id,kind,payload,occurred_at) VALUES (?1,?2,?3,?4)",
            params![binary_id.map(|id| id as i64), kind, payload_text, now],
        )?;
        Ok(db.last_insert_rowid() as u64)
    }

    #[must_use] 
    pub fn list_events(&self, kind: &str) -> Vec<EventEntry> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare(
            "SELECT id,binary_id,kind,payload,occurred_at FROM events WHERE kind=?1 ORDER BY id",
        ) else { return vec![] };
        stmt.query_map(params![kind], |r| {
            Ok(EventEntry {
                id: r.get::<_, i64>(0)? as u64,
                binary_id: r.get::<_, Option<i64>>(1)?.map(|v| v as u64),
                kind: r.get(2)?,
                payload: r.get::<_, String>(3)?.into_bytes(),
                occurred_at: r.get::<_, i64>(4)? as u64,
            })
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Bookmarks ─────────────────────────────────────────────────────────────

    pub fn add_bookmark(&self, binary_id: u64, addr: u64, label: &str, color: &str) -> Result<()> {
        let db = self.open_db()?;
        db.execute("INSERT OR REPLACE INTO bookmarks (binary_id,addr,label,color,created_at) VALUES (?1,?2,?3,?4,?5)", params![binary_id as i64, addr as i64, label, color, unix_now()])?;
        Ok(())
    }

    #[must_use] 
    pub fn list_bookmarks(&self, binary_id: u64) -> Vec<(u64, String, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db
            .prepare("SELECT addr,label,color FROM bookmarks WHERE binary_id=?1 ORDER BY addr") else { return vec![] };
        stmt.query_map(params![binary_id as i64], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Symbols ─────────────────────────────────────────────────────────────

    pub fn add_symbol(
        &self,
        binary_id: u64,
        addr: u64,
        name: &str,
        symbol_type: &str,
        source: &str,
    ) -> Result<()> {
        let db = self.open_db()?;
        db.execute("INSERT OR IGNORE INTO symbols (binary_id,addr,name,symbol_type,source) VALUES (?1,?2,?3,?4,?5)", params![binary_id as i64, addr as i64, name, symbol_type, source])?;
        Ok(())
    }

    #[must_use] 
    pub fn search_symbols(&self, binary_id: u64, prefix: &str) -> Vec<(u64, String, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let pattern = format!("{prefix}%");
        let Ok(mut stmt) = db.prepare("SELECT addr,name,symbol_type FROM symbols WHERE binary_id=?1 AND name LIKE ?2 ORDER BY addr") else { return vec![] };
        stmt.query_map(params![binary_id as i64, pattern], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Strings ─────────────────────────────────────────────────────────────

    pub fn add_string(&self, binary_id: u64, addr: u64, value: &str, encoding: &str) -> Result<()> {
        let db = self.open_db()?;
        db.execute("INSERT OR IGNORE INTO strings (binary_id,addr,value,encoding,length) VALUES (?1,?2,?3,?4,?5)", params![binary_id as i64, addr as i64, value, encoding, value.len() as i64])?;
        Ok(())
    }

    #[must_use] 
    pub fn search_strings_fts(&self, binary_id: u64, query: &str) -> Vec<(u64, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        // Wrap the query in double-quotes for FTS5 phrase matching, escaping any
        // embedded double-quotes to prevent FTS5 syntax injection.
        let fts5_query = format!("\"{}\"", query.replace('"', "\"\""));
        let Ok(mut stmt) = db.prepare("SELECT s.addr,s.value FROM strings_fts f JOIN strings s ON s.id=f.rowid WHERE strings_fts MATCH ?1 AND s.binary_id=?2 ORDER BY s.addr") else { return vec![] };
        stmt.query_map(params![fts5_query, binary_id as i64], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn upsert_triage_result(
        &self,
        binary_id: u64,
        scanner: &str,
        verdict: &str,
        score: f64,
        details: &str,
    ) -> Result<u64> {
        let db = self.open_db()?;
        let now = unix_now();
        db.execute(
            "INSERT INTO triage_results (binary_id,scanner,verdict,score,details,scanned_at) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(binary_id,scanner) DO UPDATE SET verdict=excluded.verdict, score=excluded.score, details=excluded.details, scanned_at=excluded.scanned_at",
            params![binary_id as i64, scanner, verdict, score, details, now],
        )?;
        Ok(db.query_row(
            "SELECT id FROM triage_results WHERE binary_id=?1 AND scanner=?2",
            params![binary_id as i64, scanner],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    #[must_use] 
    pub fn list_triage_results(&self, binary_id: u64) -> Vec<TriageResult> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT id,binary_id,scanner,verdict,score,details,scanned_at FROM triage_results WHERE binary_id=?1 ORDER BY scanner") else { return vec![] };
        stmt.query_map(params![binary_id as i64], |r| {
            Ok(TriageResult {
                id: r.get::<_, i64>(0)? as u64,
                binary_id: r.get::<_, i64>(1)? as u64,
                scanner: r.get(2)?,
                verdict: r.get(3)?,
                score: r.get(4)?,
                details: r.get(5)?,
                scanned_at: r.get::<_, i64>(6)? as u64,
            })
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Undo log ──────────────────────────────────────────────────────────────

    pub fn append_undo_entry(
        &self,
        session_id: &str,
        seq: u32,
        table_name: &str,
        operation: &str,
        row_id: i64,
        before_json: Option<&str>,
        after_json: Option<&str>,
    ) -> Result<()> {
        let db = self.open_db()?;
        db.execute(
            "INSERT OR IGNORE INTO undo_log (session_id,seq,table_name,operation,row_id,before_json,after_json,committed_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![session_id, seq, table_name, operation, row_id, before_json, after_json, unix_now()],
        )?;
        Ok(())
    }

    #[must_use] 
    pub fn list_undo_log(&self, session_id: &str) -> Vec<(u32, String, String, i64)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare(
            "SELECT seq,table_name,operation,row_id FROM undo_log WHERE session_id=?1 ORDER BY seq",
        ) else { return vec![] };
        stmt.query_map(params![session_id], |r| {
            Ok((
                r.get::<_, i32>(0)? as u32,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn add_patch(
        &self,
        binary_id: u64,
        addr: u64,
        original: &[u8],
        patched: &[u8],
        description: &str,
    ) -> Result<()> {
        let db = self.open_db()?;
        db.execute(
            "INSERT OR REPLACE INTO patches (binary_id,addr,original_bytes,patched_bytes,description,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![binary_id as i64, addr as i64, original, patched, description, unix_now()],
        )?;
        Ok(())
    }

    #[must_use] 
    pub fn list_patches(&self, binary_id: u64) -> Vec<(u64, Vec<u8>, Vec<u8>, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT addr,original_bytes,patched_bytes,description FROM patches WHERE binary_id=?1 ORDER BY addr") else { return vec![] };
        stmt.query_map(params![binary_id as i64], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    /// Save a binary snapshot for version tracking under `binary_id`.
    /// Automatically prunes older snapshots to keep at most `MAX_VERSION_SNAPSHOTS`.
    pub fn save_version_snapshot(
        &self,
        binary_id: u64,
        snapshot_data: &[u8],
        description: Option<&str>,
    ) -> Result<u64> {
        let db = self.open_db()?;
        let now = unix_now();
        db.execute("INSERT INTO version_history (binary_id,snapshot_data,created_at,description) VALUES (?1,?2,?3,?4)", params![binary_id as i64, snapshot_data, now, description])?;
        let id = db.last_insert_rowid() as u64;
        // Prune old snapshots
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM version_history WHERE binary_id=?1",
            params![binary_id as i64],
            |r| r.get(0),
        )?;
        if count > MAX_VERSION_SNAPSHOTS as i64 {
            let excess = count - MAX_VERSION_SNAPSHOTS as i64;
            db.execute(
                "DELETE FROM version_history WHERE id IN (SELECT id FROM version_history WHERE binary_id=?1 ORDER BY created_at ASC LIMIT ?2)",
                params![binary_id as i64, excess],
            )?;
        }
        Ok(id)
    }

    #[must_use] 
    pub fn list_version_snapshots(&self, binary_id: u64) -> Vec<(u64, u64, Option<String>)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT id,created_at,description FROM version_history WHERE binary_id=?1 ORDER BY created_at DESC") else { return vec![] };
        stmt.query_map(params![binary_id as i64], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Scripts ─────────────────────────────────────────────────────────────

    pub fn save_script(&self, name: &str, language: &str, body: &str) -> Result<u64> {
        let db = self.open_db()?;
        let now = unix_now();
        db.execute(
            "INSERT INTO scripts (name,language,body,created_at,updated_at) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(name) DO UPDATE SET language=excluded.language, body=excluded.body, updated_at=excluded.updated_at",
            params![name, language, body, now, now],
        )?;
        Ok(
            db.query_row("SELECT id FROM scripts WHERE name=?1", params![name], |r| {
                r.get::<_, i64>(0)
            })? as u64,
        )
    }

    pub fn get_script(&self, name: &str) -> Result<Option<(String, String)>> {
        let db = self.open_db()?;
        let mut stmt = db.prepare("SELECT language,body FROM scripts WHERE name=?1")?;
        let mut rows = stmt.query(params![name])?;
        if let Some(r) = rows.next()? {
            return Ok(Some((r.get(0)?, r.get(1)?)));
        }
        Ok(None)
    }

    #[must_use] 
    pub fn list_scripts(&self) -> Vec<(String, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT name,language FROM scripts ORDER BY name") else { return vec![] };
        stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|rows| rows.filter_map(std::result::Result::ok).collect())
            .unwrap_or_default()
    }

    // ── Notes ────────────────────────────────────────────────────────────────

    pub fn save_note(&self, title: &str, body: &str) -> Result<u64> {
        let db = self.open_db()?;
        db.execute(
            "INSERT INTO notes (title,body,created_at) VALUES (?1,?2,?3) ON CONFLICT(title) DO UPDATE SET body=excluded.body",
            params![title, body, unix_now()],
        )?;
        Ok(db.last_insert_rowid() as u64)
    }

    #[must_use] 
    pub fn list_notes(&self) -> Vec<(u64, String, String)> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT id,title,body FROM notes ORDER BY id") else { return vec![] };
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    // ── Layout state ──────────────────────────────────────────────────────────

    pub fn save_layout(&self, layout_json: &str) -> Result<()> {
        let db = self.open_db()?;
        db.execute("INSERT OR REPLACE INTO layout_state (id,layout_json,updated_at) VALUES (1,?1,?2)", params![layout_json, unix_now()])?;
        Ok(())
    }

    pub fn load_layout(&self) -> Result<Option<String>> {
        let db = self.open_db()?;
        let mut stmt = db.prepare("SELECT layout_json FROM layout_state WHERE id=1")?;
        let mut rows = stmt.query([])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(r.get(0)?));
        }
        Ok(None)
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn binary_stats(&self, binary_id: u64) -> BinaryStats {
        let Ok(db) = self.open_db() else { return BinaryStats::default() };
        let count = |sql: &str| -> u64 {
            db.query_row(sql, params![binary_id as i64], |r| r.get::<_, i64>(0))
                .map(|v| v as u64)
                .unwrap_or(0)
        };
        BinaryStats {
            function_count: count("SELECT COUNT(*) FROM functions WHERE binary_id=?1"),
            xref_count: count("SELECT COUNT(*) FROM xrefs WHERE binary_id=?1"),
            symbol_count: count("SELECT COUNT(*) FROM symbols WHERE binary_id=?1"),
            comment_count: count("SELECT COUNT(*) FROM comments WHERE binary_id=?1"),
            string_count: count("SELECT COUNT(*) FROM strings WHERE binary_id=?1"),
            bookmark_count: count("SELECT COUNT(*) FROM bookmarks WHERE binary_id=?1"),
        }
    }

    /// Export project metadata + function list for `binary_id` as JSON.
    pub fn export_json(&self, binary_id: u64) -> Result<String> {
        #[derive(Serialize)]
        struct Export<'a> {
            metadata: &'a ProjectMetadata,
            functions: Vec<FunctionEntry>,
        }
        let export = Export {
            metadata: &self.metadata,
            functions: self.list_functions(binary_id),
        };
        serde_json::to_string_pretty(&export).map_err(ProjectError::CorruptMetadata)
    }

    /// Import binary + auto-load PDB/DWARF debug info from adjacent files.
    pub fn import_binary_with_debug(&self, path: impl AsRef<Path>) -> Result<BinaryEntry> {
        let entry = self.add_binary_from_path(path.as_ref())?;
        // Auto-detect .pdb in same directory (Windows PE) or .dSYM bundle (macOS)
        let dir = path.as_ref().parent().unwrap_or(Path::new("."));
        let stem = path
            .as_ref()
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let pdb_path = dir.join(format!("{stem}.pdb"));
        if pdb_path.exists() {
            // In a real impl: load PDB, import symbols. Stub here.
            let _ = pdb_path;
        }
        Ok(entry)
    }

    // ── Collaboration delta ───────────────────────────────────────────────────

    /// Export events since `since_ts` (unix seconds) for collaboration sync.
    #[must_use] 
    pub fn export_delta(&self, since_ts: u64) -> Vec<EventEntry> {
        let Ok(db) = self.open_db() else { return vec![] };
        let Ok(mut stmt) = db.prepare("SELECT id,binary_id,kind,payload,occurred_at FROM events WHERE occurred_at>?1 ORDER BY id") else { return vec![] };
        stmt.query_map(params![since_ts], |r| {
            Ok(EventEntry {
                id: r.get::<_, i64>(0)? as u64,
                binary_id: r.get::<_, Option<i64>>(1)?.map(|v| v as u64),
                kind: r.get(2)?,
                payload: r.get::<_, String>(3)?.into_bytes(),
                occurred_at: r.get::<_, i64>(4)? as u64,
            })
        })
        .map(|rows| rows.filter_map(std::result::Result::ok).collect())
        .unwrap_or_default()
    }

    /// Import events from a collaborator's delta into the local event log.
    pub fn import_delta(&self, events: &[EventEntry]) -> Result<u64> {
        let db = self.open_db()?;
        let mut imported = 0u64;
        for evt in events {
            let payload = String::from_utf8_lossy(&evt.payload).into_owned();
            let rows = db.execute(
                "INSERT OR IGNORE INTO events (binary_id,kind,payload,occurred_at) VALUES (?1,?2,?3,?4)",
                params![evt.binary_id.map(|id| id as i64), &evt.kind, payload, evt.occurred_at],
            )?;
            imported += rows as u64;
        }
        Ok(imported)
    }

    // ── Accessors ──────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn name(&self) -> &str {
        &self.metadata.name
    }
    #[must_use] 
    pub fn metadata(&self) -> &ProjectMetadata {
        &self.metadata
    }
    pub fn metadata_mut(&mut self) -> &mut ProjectMetadata {
        &mut self.metadata
    }
    #[must_use] 
    pub fn config(&self) -> &ProjectConfig {
        &self.config
    }
    pub fn config_mut(&mut self) -> &mut ProjectConfig {
        &mut self.config
    }
    #[must_use] 
    pub fn project_dir(&self) -> PathBuf {
        self.root_dir.join(PROJECT_DIR_NAME)
    }
    #[must_use] 
    pub fn db_path(&self) -> PathBuf {
        self.project_dir().join(DB_FILE)
    }
    #[must_use] 
    pub fn recordings_dir(&self) -> PathBuf {
        self.project_dir().join("recordings")
    }
    #[must_use] 
    pub fn sandbox_dir(&self) -> PathBuf {
        self.project_dir().join("sandbox")
    }
    #[must_use] 
    pub fn attachments_dir(&self) -> PathBuf {
        self.project_dir().join("attachments")
    }
    #[must_use] 
    pub fn workflows_dir(&self) -> PathBuf {
        self.project_dir().join("workflows")
    }
    #[must_use] 
    pub fn scripts_dir(&self) -> PathBuf {
        self.project_dir().join("scripts")
    }
    #[must_use] 
    pub fn reports_dir(&self) -> PathBuf {
        self.project_dir().join("reports")
    }
    #[must_use] 
    pub fn views_dir(&self) -> PathBuf {
        self.project_dir().join("views")
    }
    #[must_use] 
    pub fn snapshots_dir(&self) -> PathBuf {
        self.project_dir().join("snapshots")
    }#[must_use] 
    

    fn open_db(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        let guard = self.db_conn.lock().map_err(|_| ProjectError::LockPoisoned)?;
        Ok(guard)
    }
}

// ── BinaryProject impl ─────────────────────────────────────────────────────

impl BinaryProject for Project {
    fn add_binary(&mut self, path: &Path, sha256: &str) -> Result<u64> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let db = self.open_db()?;
        let now = unix_now();
        db.execute("INSERT OR IGNORE INTO binaries (sha256,path,format,arch,added_at) VALUES (?1,?2,'','',?3)", params![sha256, canonical.to_string_lossy().as_ref(), now])?;
        Ok(db.query_row(
            "SELECT id FROM binaries WHERE sha256=?1",
            params![sha256],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }
    fn get_binary(&self, id: u64) -> Result<Option<BinaryEntry>> {
        let db = self.open_db()?;
        let mut stmt = db.prepare("SELECT id,sha256,path,format,arch,added_at,size_bytes,entry_point,base_addr FROM binaries WHERE id=?1")?;
        let mut rows = stmt.query(params![id as i64])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(BinaryEntry {
                id: r.get::<_, i64>(0)? as u64,
                sha256: r.get(1)?,
                path: r.get(2)?,
                format: r.get(3)?,
                arch: r.get(4)?,
                added_at: r.get::<_, i64>(5)? as u64,
                size_bytes: r.get(6)?,
                entry_point: r.get(7)?,
                base_addr: r.get(8)?,
            }));
        }
        Ok(None)
    }
    fn add_function(&mut self, binary_id: u64, addr: u64, name: &str) -> Result<u64> {
        self.add_function_record(binary_id, addr, name)
    }
    fn get_function(&self, binary_id: u64, addr: u64) -> Result<Option<FunctionEntry>> {
        self.get_function_by_addr(binary_id, addr)
    }
    fn add_comment(&mut self, binary_id: u64, addr: u64, text: &str) -> Result<()> {
        self.add_comment_record(binary_id, addr, text)
    }
    fn add_xref(&mut self, binary_id: u64, from: u64, to: u64, kind: &str) -> Result<()> {
        self.add_xref_record(binary_id, from, to, kind)
    }
    fn add_event(&mut self, kind: &str, actor: &str, payload: &[u8]) -> Result<u64> {
        let data_value: serde_json::Value = serde_json::from_slice(payload)
            .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(payload).into_owned()));
        let wrapped = serde_json::json!({
            "actor": actor,
            "data": data_value,
        })
        .to_string();
        self.add_event_record(kind, None, wrapped.as_bytes())
    }
}

// ── ProjectSession ────────────────────────────────────────────────────────────

/// Active session attached to an open project.
#[derive(Debug)]
pub struct ProjectSession {
    /// The associated project (shared, Arc'd).
    pub project: Arc<Mutex<Project>>,
    /// IDs of currently open binary views.
    pub open_view_ids: Vec<u64>,
    /// Active script names.
    pub active_scripts: Vec<String>,
    /// Session-level notes (transient).
    pub session_notes: String,
}

impl ProjectSession {
    #[must_use]
    pub fn new(project: Arc<Mutex<Project>>) -> Self {
        Self {
            project,
            open_view_ids: Vec::new(),
            active_scripts: Vec::new(),
            session_notes: String::new(),
        }
    }

    pub fn open_view(&mut self, binary_id: u64) {
        if !self.open_view_ids.contains(&binary_id) {
            self.open_view_ids.push(binary_id);
        }
    }
    pub fn close_view(&mut self, binary_id: u64) {
        self.open_view_ids.retain(|&id| id != binary_id);
    }
    pub fn activate_script(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.active_scripts.contains(&n) {
            self.active_scripts.push(n);
        }
    }
    pub fn deactivate_script(&mut self, name: &str) {
        self.active_scripts.retain(|s| s != name);
    }
    #[must_use]
    pub fn is_view_open(&self, binary_id: u64) -> bool {
        self.open_view_ids.contains(&binary_id)
    }
    #[must_use]
    pub fn open_view_count(&self) -> usize {
        self.open_view_ids.len()
    }
}

// ── ProjectManager ────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ProjectManager {
    projects: HashMap<String, Arc<Mutex<Project>>>,
}

impl ProjectManager {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&mut self, path: &Path) -> Result<Arc<Mutex<Project>>> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let key = canonical.to_string_lossy().into_owned();
        if let Some(existing) = self.projects.get(&key) {
            return Ok(Arc::clone(existing));
        }
        let project = Project::open(&canonical)?;
        let arc = Arc::new(Mutex::new(project));
        self.projects.insert(key, Arc::clone(&arc));
        Ok(arc)
    }

    pub fn create(&mut self, name: &str, path: &Path) -> Result<Arc<Mutex<Project>>> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let key = canonical.to_string_lossy().into_owned();
        let project = Project::new(name, &canonical)?;
        let arc = Arc::new(Mutex::new(project));
        self.projects.insert(key, Arc::clone(&arc));
        Ok(arc)
    }

    pub fn close(&mut self, id: &str) {
        self.projects.remove(id);
    }
    #[must_use] 
    pub fn list(&self) -> Vec<String> {
        let mut k: Vec<_> = self.projects.keys().cloned().collect();
        k.sort();
        k
    }
    pub fn get(&self, id: &str) -> Option<Arc<Mutex<Project>>> {
        self.projects.get(id).map(Arc::clone)
    }
    #[must_use] 
    pub fn len(&self) -> usize {
        self.projects.len()
    }
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.projects.is_empty()
    }

    #[must_use] 
    pub fn save_all(&self) -> Vec<(String, Result<()>)> {
        self.projects
            .iter()
            .map(|(key, arc)| {
                let r = arc
                    .lock()
                    .map_err(|_| ProjectError::LockPoisoned)
                    .and_then(|p| p.save());
                (key.clone(), r)
            })
            .collect()
    }

    pub fn recent_projects(&self) -> Vec<PathBuf> {
        self.projects.keys().map(PathBuf::from).collect()
    }

    /// Spawn an async tokio task that calls `maybe_autosave` on each managed
    /// project at the configured `autosave_interval_secs` cadence.
    ///
    /// The returned `JoinHandle` runs until dropped.  Call this once after
    /// building the manager inside a `#[tokio::main]` or `tokio::spawn` context.
    #[must_use] 
    pub fn spawn_autosave_task(
        &self,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let projects = self.projects.clone();
        tokio::spawn(async move {
            if interval_secs == 0 {
                return;
            }
            let mut ticker =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            ticker.tick().await; // skip the first immediate tick
            loop {
                ticker.tick().await;
                // Collect the arcs first so the lock is not held across .await
                let arcs: Vec<_> = projects.values().cloned().collect();
                tokio::task::spawn_blocking(move || {
                    for arc in arcs {
                        if let Ok(mut p) = arc.lock() {
                            let _ = p.maybe_autosave();
                        }
                    }
                })
                .await
                .ok();
            }
        })
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convert a Unix timestamp (seconds) to an ISO-8601 string using chrono.
fn unix_to_iso8601(secs: u64) -> String {
    use chrono::TimeZone as _;
    Utc.timestamp_opt(secs as i64, 0)
        .single().map_or_else(|| format!("{secs}"), |dt| dt.to_rfc3339())
}

#[must_use] 
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[must_use] 
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[must_use]
pub fn classify_binary(bytes: &[u8], config: &ProjectConfig) -> (String, String) {
    let fallback = config
        .default_arch
        .clone()
        .unwrap_or_else(|| "unknown".into());
    // An "MZ" prefix is enough to classify the input as PE: the rest of the
    // optional header may be missing or stripped, but the format is determined.
    if bytes.starts_with(b"MZ") {
        let arch = if bytes.len() > 0x40 {
            let off = u32::from_le_bytes([
                bytes.get(0x3c).copied().unwrap_or(0),
                bytes.get(0x3d).copied().unwrap_or(0),
                bytes.get(0x3e).copied().unwrap_or(0),
                bytes.get(0x3f).copied().unwrap_or(0),
            ]) as usize;
            if off.checked_add(6).is_some_and(|end| end < bytes.len()) && bytes[off..off + 4] == *b"PE\0\0" {
                match u16::from_le_bytes([bytes[off + 4], bytes[off + 5]]) {
                    0x8664 => "x86_64",
                    0x014c => "x86",
                    0xaa64 => "aarch64",
                    0x01c4 => "arm",
                    _ => "unknown",
                }
            } else {
                "unknown"
            }
        } else {
            "unknown"
        };
        return ("PE".into(), arch.into());
    }
    if bytes.starts_with(b"\x7fELF") {
        let arch = if bytes.len() > 19 {
            // EI_DATA at offset 5: 1 = little-endian, 2 = big-endian
            // Use rustre_core::endian::Endian to model byte order explicitly.
            let endian = if bytes.len() > 5 && bytes[5] == 0x02 {
                rustre_core::endian::Endian::Big
            } else {
                rustre_core::endian::Endian::Little
            };
            let e_machine = match endian {
                rustre_core::endian::Endian::Big => u16::from_be_bytes([bytes[18], bytes[19]]),
                rustre_core::endian::Endian::Little => u16::from_le_bytes([bytes[18], bytes[19]]),
            };
            match e_machine {
                0x0003 => "x86",
                0x003e => "x86_64",
                0x0028 => "arm",
                0x00b7 => "aarch64",
                0x00f3 => "riscv",
                0x0008 => "mips",
                _ => "unknown",
            }
        } else {
            "unknown"
        };
        return ("ELF".into(), arch.into());
    }
    if bytes.len() >= 4 {
        match u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) {
            0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe => return ("MachO".into(), fallback),
            0xcafebabe => return ("MachO-fat".into(), fallback),
            _ => {}
        }
    }
    if bytes.starts_with(b"\0asm") {
        return ("WASM".into(), "wasm32".into());
    }
    if bytes.starts_with(b"dex\n") {
        return ("DEX".into(), "dalvik".into());
    }
    ("unknown".into(), fallback)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // ── ProjectMetadata ───────────────────────────────────────────────────────

    #[test]
    fn metadata_name() {
        let m = ProjectMetadata::new("hello");
        assert_eq!(m.name, "hello");
    }
    #[test]
    fn metadata_version() {
        assert_eq!(ProjectMetadata::new("x").version, "1.0.0");
    }
    #[test]
    fn metadata_created_nonzero() {
        assert!(ProjectMetadata::new("x").created_at > 0);
    }
    #[test]
    fn metadata_desc_none() {
        assert!(ProjectMetadata::new("x").description.is_none());
    }
    #[test]
    fn metadata_tags_empty() {
        assert!(ProjectMetadata::new("x").tags.is_empty());
    }

    // ── KgBackend ─────────────────────────────────────────────────────────────

    #[test]
    fn kg_default_memory() {
        assert_eq!(KgBackend::default(), KgBackend::Memory);
    }
    #[test]
    fn kg_sqlite_roundtrip() {
        let b = KgBackend::Sqlite {
            path: "/tmp/kg.db".into(),
        };
        let j = serde_json::to_string(&b).unwrap();
        let b2: KgBackend = serde_json::from_str(&j).unwrap();
        assert_eq!(b, b2);
    }

    // ── ProjectConfig ─────────────────────────────────────────────────────────

    #[test]
    fn config_plugins_empty() {
        assert!(ProjectConfig::default().plugins.is_empty());
    }
    #[test]
    fn config_wal_true() {
        assert!(ProjectConfig::default().wal_mode);
    }
    #[test]
    fn config_undo_limit() {
        assert_eq!(ProjectConfig::default().undo_limit, 1000);
    }
    #[test]
    fn config_autosave() {
        assert_eq!(
            ProjectConfig::default().autosave_interval_secs,
            DEFAULT_AUTOSAVE_INTERVAL_SECS
        );
    }

    // ── Project::new ──────────────────────────────────────────────────────────

    #[test]
    fn new_creates_project_dir() {
        let d = tmp();
        let p = Project::new("t", d.path()).unwrap();
        assert!(p.project_dir().exists());
    }
    #[test]
    fn new_creates_subdirs() {
        let d = tmp();
        let p = Project::new("t", d.path()).unwrap();
        assert!(p.recordings_dir().exists());
        assert!(p.scripts_dir().exists());
        assert!(p.views_dir().exists());
        assert!(p.snapshots_dir().exists());
    }
    #[test]
    fn new_creates_db() {
        let d = tmp();
        let p = Project::new("t", d.path()).unwrap();
        assert!(p.db_path().exists());
    }
    #[test]
    fn new_creates_meta() {
        let d = tmp();
        let p = Project::new("t", d.path()).unwrap();
        assert!(p.project_dir().join("meta.json").exists());
    }
    #[test]
    fn new_duplicate_err() {
        let d = tmp();
        Project::new("a", d.path()).unwrap();
        assert!(matches!(
            Project::new("b", d.path()).unwrap_err(),
            ProjectError::AlreadyExists(_)
        ));
    }
    #[test]
    fn new_name_accessible() {
        let d = tmp();
        let p = Project::new("myproject", d.path()).unwrap();
        assert_eq!(p.name(), "myproject");
    }

    // ── Project::open ─────────────────────────────────────────────────────────

    #[test]
    fn open_missing_err() {
        let d = tmp();
        assert!(matches!(
            Project::open(d.path().join("nope")).unwrap_err(),
            ProjectError::NotFound(_)
        ));
    }
    #[test]
    fn open_after_new() {
        let d = tmp();
        Project::new("rt", d.path()).unwrap();
        let p = Project::open(d.path()).unwrap();
        assert_eq!(p.name(), "rt");
    }
    #[test]
    fn open_preserves_desc() {
        let d = tmp();
        {
            let mut p = Project::new("x", d.path()).unwrap();
            p.metadata_mut().description = Some("hi".into());
            p.save().unwrap();
        }
        let p2 = Project::open(d.path()).unwrap();
        assert_eq!(p2.metadata().description.as_deref(), Some("hi"));
    }

    // ── Project::save ─────────────────────────────────────────────────────────

    #[test]
    fn save_roundtrips_config() {
        let d = tmp();
        {
            let mut p = Project::new("cfg", d.path()).unwrap();
            p.config_mut().default_arch = Some("aarch64".into());
            p.save().unwrap();
        }
        assert_eq!(
            Project::open(d.path())
                .unwrap()
                .config()
                .default_arch
                .as_deref(),
            Some("aarch64")
        );
    }

    // ── Binary management ─────────────────────────────────────────────────────

    #[test]
    fn add_binary_returns_entry() {
        let d = tmp();
        let p = Project::new("bt", d.path()).unwrap();
        let bin = d.path().join("t.elf");
        let mut elf = vec![0x7f, b'E', b'L', b'F'];
        elf.extend([0u8; 20]);
        fs::write(&bin, &elf).unwrap();
        let e = p.add_binary_from_path(&bin).unwrap();
        assert!(!e.sha256.is_empty());
        assert_eq!(e.format, "ELF");
    }
    #[test]
    fn list_binaries_empty() {
        let d = tmp();
        let p = Project::new("lt", d.path()).unwrap();
        assert!(p.list_binaries().is_empty());
    }
    #[test]
    fn add_binary_in_list() {
        let d = tmp();
        let p = Project::new("lt2", d.path()).unwrap();
        let b = d.path().join("a.bin");
        fs::write(&b, b"MZ").unwrap();
        p.add_binary_from_path(&b).unwrap();
        let l = p.list_binaries();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].format, "PE");
    }
    #[test]
    fn add_binary_dedup() {
        let d = tmp();
        let p = Project::new("dedup", d.path()).unwrap();
        let b = d.path().join("dup.bin");
        fs::write(&b, b"hi").unwrap();
        p.add_binary_from_path(&b).unwrap();
        p.add_binary_from_path(&b).unwrap();
        assert_eq!(p.list_binaries().len(), 1);
    }

    // ── BinaryProject trait ───────────────────────────────────────────────────

    #[test]
    fn trait_add_binary() {
        let d = tmp();
        let mut p = Project::new("tr", d.path()).unwrap();
        let id = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/x.bin"),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        )
        .unwrap();
        assert!(id > 0);
    }
    #[test]
    fn trait_fn_get() {
        let d = tmp();
        let mut p = Project::new("fn", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/x.bin"),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        )
        .unwrap();
        BinaryProject::add_function(&mut p, bid, 0x1000, "main").unwrap();
        let f = BinaryProject::get_function(&p, bid, 0x1000).unwrap();
        assert!(f.is_some());
        assert_eq!(f.unwrap().name, "main");
    }
    #[test]
    fn trait_comment() {
        let d = tmp();
        let mut p = Project::new("cmt", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/x.bin"),
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        BinaryProject::add_comment(&mut p, bid, 0x2000, "hello").unwrap();
        assert_eq!(
            p.get_comment(bid, 0x2000).unwrap().as_deref(),
            Some("hello")
        );
    }
    #[test]
    fn trait_xref() {
        let d = tmp();
        let mut p = Project::new("xr", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/x.bin"),
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        BinaryProject::add_xref(&mut p, bid, 0x1000, 0x3000, "call").unwrap();
        let refs = p.xrefs_to(bid, 0x3000);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].2, "call");
    }
    #[test]
    fn trait_event() {
        let d = tmp();
        let mut p = Project::new("evt", d.path()).unwrap();
        let id = BinaryProject::add_event(&mut p, "analysis.start", "sys", b"{}").unwrap();
        assert!(id > 0);
        assert_eq!(p.list_events("analysis.start").len(), 1);
    }

    // ── detect_format_arch ────────────────────────────────────────────────────

    #[test]
    fn detect_wasm() {
        let (f, a) = classify_binary(b"\0asm\x01\0\0\0", &ProjectConfig::default());
        assert_eq!(f, "WASM");
        assert_eq!(a, "wasm32");
    }
    #[test]
    fn detect_dex() {
        let (f, a) = classify_binary(b"dex\n035\0", &ProjectConfig::default());
        assert_eq!(f, "DEX");
        assert_eq!(a, "dalvik");
    }
    #[test]
    fn detect_unknown() {
        let (f, _) = classify_binary(b"\x00", &ProjectConfig::default());
        assert_eq!(f, "unknown");
    }
    #[test]
    fn detect_fallback_arch() {
        let c = ProjectConfig {
            default_arch: Some("x86_64".into()),
            ..ProjectConfig::default()
        };
        let (_, a) = classify_binary(b"\x00\x00\x00\x00", &c);
        assert_eq!(a, "x86_64");
    }

    // ── Migrations ────────────────────────────────────────────────────────────

    #[test]
    fn migrations_count() {
        assert_eq!(get_migrations().len(), 4);
    }
    #[test]
    fn migrations_ascending() {
        let ms = get_migrations();
        for i in 1..ms.len() {
            assert!(ms[i].version > ms[i - 1].version);
        }
    }
    #[test]
    fn migrations_idempotent() {
        let d = tmp();
        let conn = Connection::open(d.path().join("t.db")).unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap();
    }
    #[test]
    fn run_pending_count() {
        let d = tmp();
        let conn = Connection::open(d.path().join("p.db")).unwrap();
        assert_eq!(run_pending_migrations(&conn).unwrap(), 4);
        assert_eq!(run_pending_migrations(&conn).unwrap(), 0);
    }
    #[test]
    fn migrations_triage_table() {
        let d = tmp();
        let conn = Connection::open(d.path().join("t.db")).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute_batch("SELECT 1 FROM triage_results LIMIT 1")
            .unwrap();
    }
    #[test]
    fn migrations_undo_log() {
        let d = tmp();
        let conn = Connection::open(d.path().join("u.db")).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute_batch("SELECT 1 FROM undo_log LIMIT 1")
            .unwrap();
    }
    #[test]
    fn migrations_patches_table() {
        let d = tmp();
        let conn = Connection::open(d.path().join("pa.db")).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute_batch("SELECT 1 FROM patches LIMIT 1").unwrap();
    }
    #[test]
    fn migrations_version_history() {
        let d = tmp();
        let conn = Connection::open(d.path().join("vh.db")).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute_batch("SELECT 1 FROM version_history LIMIT 1")
            .unwrap();
    }

    // ── ProjectManager ────────────────────────────────────────────────────────

    #[test]
    fn manager_create_list() {
        let d = tmp();
        let mut m = ProjectManager::new();
        m.create("a", d.path()).unwrap();
        assert_eq!(m.list().len(), 1);
    }
    #[test]
    fn manager_open_same_arc() {
        let d = tmp();
        let mut m = ProjectManager::new();
        Project::new("rp", d.path()).unwrap();
        let a = m.open(d.path()).unwrap();
        let b = m.open(d.path()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }
    #[test]
    fn manager_close() {
        let d = tmp();
        let mut m = ProjectManager::new();
        let arc = m.create("t", d.path()).unwrap();
        let key = {
            let p = arc.lock().unwrap();
            p.project_dir()
                .parent()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        m.close(&key);
        assert!(m.is_empty());
    }
    #[test]
    fn manager_len_empty() {
        let m = ProjectManager::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    // ── Triage ────────────────────────────────────────────────────────────────

    #[test]
    fn triage_upsert_list() {
        let d = tmp();
        let mut p = Project::new("tri", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/m.bin"),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        p.upsert_triage_result(bid, "vt", "malicious", 0.95, "Trojan")
            .unwrap();
        let r = p.list_triage_results(bid);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].verdict, "malicious");
    }
    #[test]
    fn triage_upsert_replaces() {
        let d = tmp();
        let mut p = Project::new("triu", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/x.bin"),
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        p.upsert_triage_result(bid, "yara", "suspicious", 0.5, "R1")
            .unwrap();
        p.upsert_triage_result(bid, "yara", "clean", 0.1, "None")
            .unwrap();
        let r = p.list_triage_results(bid);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].verdict, "clean");
    }

    // ── Bookmarks ─────────────────────────────────────────────────────────────

    #[test]
    fn bookmarks() {
        let d = tmp();
        let mut p = Project::new("bm", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/b.bin"),
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        p.add_bookmark(bid, 0x1000, "entry", "#ff0000").unwrap();
        p.add_bookmark(bid, 0x2000, "x", "#00ff00").unwrap();
        let bms = p.list_bookmarks(bid);
        assert_eq!(bms.len(), 2);
        assert_eq!(bms[0].0, 0x1000);
    }

    // ── Symbols ───────────────────────────────────────────────────────────────

    #[test]
    fn symbols_search() {
        let d = tmp();
        let mut p = Project::new("sym", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/s.bin"),
            "3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        p.add_symbol(bid, 0x1000, "malloc", "function", "import")
            .unwrap();
        p.add_symbol(bid, 0x1010, "free", "function", "import")
            .unwrap();
        p.add_symbol(bid, 0x1020, "main", "function", "export")
            .unwrap();
        assert_eq!(p.search_symbols(bid, "m").len(), 2);
    }

    // ── Undo log ──────────────────────────────────────────────────────────────

    #[test]
    fn undo_log() {
        let d = tmp();
        let p = Project::new("undo", d.path()).unwrap();
        p.append_undo_entry("s1", 0, "functions", "INSERT", 42, None, Some("{}"))
            .unwrap();
        p.append_undo_entry("s1", 1, "comments", "UPDATE", 7, Some("{}"), Some("{}"))
            .unwrap();
        let log = p.list_undo_log("s1");
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].1, "comments");
    }

    // ── Binary stats ──────────────────────────────────────────────────────────

    #[test]
    fn stats_zero() {
        let d = tmp();
        let mut p = Project::new("st", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/st.bin"),
            "4444444444444444444444444444444444444444444444444444444444444444",
        )
        .unwrap();
        let s = p.binary_stats(bid);
        assert_eq!(s.function_count, 0);
    }
    #[test]
    fn stats_increments() {
        let d = tmp();
        let mut p = Project::new("st2", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/st2.bin"),
            "5555555555555555555555555555555555555555555555555555555555555555",
        )
        .unwrap();
        BinaryProject::add_function(&mut p, bid, 0x1000, "main").unwrap();
        BinaryProject::add_function(&mut p, bid, 0x2000, "init").unwrap();
        assert_eq!(p.binary_stats(bid).function_count, 2);
    }

    // ── sha256_hex / entropy ───────────────────────────────────────────────────

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }
    #[test]
    fn entropy_uniform() {
        let d = vec![0xAA_u8; 1024];
        assert!((shannon_entropy(&d) - 0.0).abs() < 1e-9);
    }
    #[test]
    fn entropy_max() {
        let d: Vec<u8> = (0u8..=255).collect();
        assert!((shannon_entropy(&d) - 8.0).abs() < 1e-9);
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn project_dir_name() {
        assert_eq!(PROJECT_DIR_NAME, ".rustre-project");
    }
    #[test]
    fn schema_version() {
        assert_eq!(CURRENT_SCHEMA_VERSION, 4);
    }
    #[test]
    fn autosave_default() {
        assert_eq!(DEFAULT_AUTOSAVE_INTERVAL_SECS, 300);
    }
    #[test]
    fn max_version_snapshots() {
        assert_eq!(MAX_VERSION_SNAPSHOTS, 10);
    }

    // ── Patches ───────────────────────────────────────────────────────────────

    #[test]
    fn patches() {
        let d = tmp();
        let mut p = Project::new("pat", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/p.bin"),
            "6666666666666666666666666666666666666666666666666666666666666666",
        )
        .unwrap();
        p.add_patch(bid, 0x1000, &[0x90], &[0xCC], "nop->int3")
            .unwrap();
        let patches = p.list_patches(bid);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].0, 0x1000);
    }

    // ── Version history ───────────────────────────────────────────────────────

    #[test]
    fn version_history() {
        let d = tmp();
        let mut p = Project::new("vh", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/vh.bin"),
            "7777777777777777777777777777777777777777777777777777777777777777",
        )
        .unwrap();
        for i in 0..3u32 {
            p.save_version_snapshot(bid, &i.to_le_bytes(), Some(&format!("snap{i}")))
                .unwrap();
        }
        let snaps = p.list_version_snapshots(bid);
        assert_eq!(snaps.len(), 3);
    }
    #[test]
    fn version_history_pruning() {
        let d = tmp();
        let mut p = Project::new("vhp", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/vhp.bin"),
            "8888888888888888888888888888888888888888888888888888888888888888",
        )
        .unwrap();
        for i in 0..15u32 {
            p.save_version_snapshot(bid, &i.to_le_bytes(), None)
                .unwrap();
        }
        let snaps = p.list_version_snapshots(bid);
        assert!(snaps.len() <= MAX_VERSION_SNAPSHOTS);
    }

    // ── Scripts ───────────────────────────────────────────────────────────────

    #[test]
    fn scripts_save_get() {
        let d = tmp();
        let p = Project::new("sc", d.path()).unwrap();
        p.save_script("hello.py", "python", "print('hi')").unwrap();
        let (lang, body) = p.get_script("hello.py").unwrap().unwrap();
        assert_eq!(lang, "python");
        assert!(body.contains("hi"));
    }
    #[test]
    fn scripts_list() {
        let d = tmp();
        let p = Project::new("scl", d.path()).unwrap();
        p.save_script("a.py", "python", "pass").unwrap();
        p.save_script("b.lua", "lua", "return").unwrap();
        assert_eq!(p.list_scripts().len(), 2);
    }

    // ── Notes ─────────────────────────────────────────────────────────────────

    #[test]
    fn notes_save_list() {
        let d = tmp();
        let p = Project::new("nt", d.path()).unwrap();
        p.save_note("Note 1", "content here").unwrap();
        let notes = p.list_notes();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].2.contains("content"));
    }

    // ── Layout state ──────────────────────────────────────────────────────────

    #[test]
    fn layout_save_load() {
        let d = tmp();
        let p = Project::new("ly", d.path()).unwrap();
        p.save_layout(r#"{"panels": ["left","right"]}"#).unwrap();
        let j = p.load_layout().unwrap();
        assert!(j.is_some());
        assert!(j.unwrap().contains("panels"));
    }
    #[test]
    fn layout_none_initially() {
        let d = tmp();
        let p = Project::new("ly2", d.path()).unwrap();
        assert!(p.load_layout().unwrap().is_none());
    }

    // ── Collaboration delta ───────────────────────────────────────────────────

    #[test]
    fn delta_export_import() {
        let d1 = tmp();
        let d2 = tmp();
        let mut p1 = Project::new("src", d1.path()).unwrap();
        let p2 = Project::new("dst", d2.path()).unwrap();
        BinaryProject::add_event(&mut p1, "test.event", "user", b"{}").unwrap();
        let delta = p1.export_delta(0);
        assert!(!delta.is_empty());
        let imported = p2.import_delta(&delta).unwrap();
        assert_eq!(imported, delta.len() as u64);
    }

    // ── ProjectSession ────────────────────────────────────────────────────────

    #[test]
    fn session_open_close_view() {
        let d = tmp();
        let p = Project::new("sess", d.path()).unwrap();
        let arc = Arc::new(Mutex::new(p));
        let mut s = ProjectSession::new(Arc::clone(&arc));
        s.open_view(1);
        s.open_view(2);
        assert_eq!(s.open_view_count(), 2);
        s.close_view(1);
        assert_eq!(s.open_view_count(), 1);
        assert!(!s.is_view_open(1));
        assert!(s.is_view_open(2));
    }
    #[test]
    fn session_scripts() {
        let d = tmp();
        let p = Project::new("sess2", d.path()).unwrap();
        let arc = Arc::new(Mutex::new(p));
        let mut s = ProjectSession::new(arc);
        s.activate_script("exploit.py");
        assert_eq!(s.active_scripts.len(), 1);
        s.deactivate_script("exploit.py");
        assert!(s.active_scripts.is_empty());
    }

    // ── Export JSON ───────────────────────────────────────────────────────────

    #[test]
    fn export_json_ok() {
        let d = tmp();
        let mut p = Project::new("ej", d.path()).unwrap();
        let bid = BinaryProject::add_binary(
            &mut p,
            Path::new("/tmp/ej.bin"),
            "9999999999999999999999999999999999999999999999999999999999999999",
        )
        .unwrap();
        BinaryProject::add_function(&mut p, bid, 0x1000, "main").unwrap();
        let json = p.export_json(bid).unwrap();
        assert!(json.contains("main"));
        assert!(json.contains("metadata"));
    }
}
