// ============================================================================
// db/schema.rs — SQLite project database schema definitions
//
// The project database persists all analysis results, user annotations,
// patches, comments, bookmarks, settings, and type definitions.
// ============================================================================

/// The current schema version. Bump when migrations are needed.
pub const SCHEMA_VERSION: u32 = 1;

/// SQL to create all tables from scratch.
pub const CREATE_TABLES_SQL: &str = r"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

-- Schema version table
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER NOT NULL,
    applied_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Project metadata
CREATE TABLE IF NOT EXISTS project_meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

-- Binary files tracked by this project
CREATE TABLE IF NOT EXISTS binaries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    size        INTEGER NOT NULL,
    loaded_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    arch        TEXT,
    format      TEXT,
    base_addr   INTEGER NOT NULL DEFAULT 0,
    entry_point INTEGER NOT NULL DEFAULT 0
);

-- Segments
CREATE TABLE IF NOT EXISTS segments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    start_addr INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    flags      INTEGER NOT NULL DEFAULT 0,
    perm       TEXT    NOT NULL DEFAULT 'r',
    file_off   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_segments_addr ON segments(start_addr);

-- Functions
CREATE TABLE IF NOT EXISTS functions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    func_id    INTEGER NOT NULL,  -- internal func_id
    name       TEXT    NOT NULL,
    addr       INTEGER NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    flags      INTEGER NOT NULL DEFAULT 0,
    signature  TEXT,
    color_idx  INTEGER,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    modified_at TEXT   NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_functions_addr ON functions(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);

-- Symbols
CREATE TABLE IF NOT EXISTS symbols (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    sym_id     INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    addr       INTEGER NOT NULL,
    kind       TEXT    NOT NULL DEFAULT 'Function',
    size       INTEGER NOT NULL DEFAULT 0,
    visibility TEXT    NOT NULL DEFAULT 'Global'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_symbols_addr ON symbols(binary_id, addr);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);

-- Comments
CREATE TABLE IF NOT EXISTS comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr        INTEGER NOT NULL,
    text        TEXT    NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'Inline',  -- Inline | Block | Repeatable | Pre | Post
    author      TEXT    NOT NULL DEFAULT 'user',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    modified_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_comments_addr ON comments(binary_id, addr);

-- Patches
CREATE TABLE IF NOT EXISTS patches (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id    INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr         INTEGER NOT NULL,
    original     BLOB    NOT NULL,
    patched      BLOB    NOT NULL,
    comment      TEXT    NOT NULL DEFAULT '',
    author       TEXT    NOT NULL DEFAULT 'user',
    tag          TEXT    NOT NULL DEFAULT 'Manual',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patches_addr ON patches(binary_id, addr);

-- Bookmarks
CREATE TABLE IF NOT EXISTS bookmarks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    addr       INTEGER NOT NULL,
    label      TEXT    NOT NULL,
    color_idx  INTEGER,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Type definitions
CREATE TABLE IF NOT EXISTS type_defs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id    INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,  -- Struct | Enum | Typedef | Primitive | Pointer | Array | Function
    definition   TEXT    NOT NULL,  -- JSON-encoded TypeInfo
    source       TEXT    NOT NULL DEFAULT 'UserDefined',
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    modified_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_type_defs_name ON type_defs(binary_id, name);

-- Notes / notebooks
CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
    title       TEXT    NOT NULL,
    content     TEXT    NOT NULL DEFAULT '',
    addr        INTEGER,  -- optional associated address
    tags        TEXT    NOT NULL DEFAULT '',  -- comma-separated
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    modified_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Xrefs (cached; regenerated on load but persisted for fast startup)
CREATE TABLE IF NOT EXISTS xrefs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    from_addr   INTEGER NOT NULL,
    to_addr     INTEGER NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'Call'
);
CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(binary_id, from_addr);
CREATE INDEX IF NOT EXISTS idx_xrefs_to   ON xrefs(binary_id, to_addr);

-- Breakpoints (persistent across sessions)
CREATE TABLE IF NOT EXISTS breakpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    bp_id       INTEGER NOT NULL,
    addr        INTEGER NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'Software',
    enabled     INTEGER NOT NULL DEFAULT 1,
    condition   TEXT,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Settings key-value store
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Macro library (persisted macros)
CREATE TABLE IF NOT EXISTS macros (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    macro_id    TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    category    TEXT    NOT NULL DEFAULT 'User',
    definition  TEXT    NOT NULL,  -- JSON-encoded Macro
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    run_count   INTEGER NOT NULL DEFAULT 0
);

-- Script history
CREATE TABLE IF NOT EXISTS script_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    language    TEXT    NOT NULL DEFAULT 'python',
    source      TEXT    NOT NULL,
    result      TEXT,
    ran_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
";

/// SQL to insert the initial schema version.
pub const SEED_VERSION_SQL: &str = "INSERT INTO schema_version (version) VALUES (?1);";

/// Migration scripts indexed by (`from_version`, `to_version`).
pub const MIGRATIONS: &[(u32, u32, &str)] = &[
    // Future migrations go here, e.g.:
    // (1, 2, "ALTER TABLE functions ADD COLUMN demangled_name TEXT;"),
];

#[doc(hidden)]
pub const fn ensure_used_schema() -> usize {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let version = SCHEMA_VERSION as usize;
    let migrations: &[(u32, u32, &str)] = MIGRATIONS;
    version
        .saturating_add(CREATE_TABLES_SQL.len())
        .saturating_add(SEED_VERSION_SQL.len())
        .saturating_add(migrations.len())
}
