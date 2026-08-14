//! Project-level plugin management.
//!
//! Provides:
//! * [`PluginRecord`] — stored plugin descriptor (name, version, enabled, config JSON).
//! * [`PluginConfigStore`] — typed config read/write helpers.
//! * [`ProjectPluginManager`] — per-project enable/disable, invocation log, auto-load.
//!
//! All persistent state lives in the project SQLite database (a `plugins` table
//! and a `plugin_invocations` table, added via migrations that this module
//! applies on its own the first time it opens the database).

use rusqlite::{Connection, Result as SqlResult, params};
use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin not found: {0}")]
    NotFound(String),
    #[error("plugin already registered: {0}")]
    AlreadyExists(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PluginError>;

// ── PluginRecord ──────────────────────────────────────────────────────────────

/// A plugin descriptor stored in the project database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRecord {
    pub id: u64,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    /// JSON-encoded plugin-specific configuration.
    pub config_json: String,
    /// Optional path to the plugin shared library or script.
    pub path: Option<String>,
    pub registered_at: u64,
    pub updated_at: u64,
}

impl PluginRecord {
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            id: 0,
            name: name.into(),
            version: version.into(),
            enabled: true,
            config_json: "{}".into(),
            path: None,
            registered_at: now,
            updated_at: now,
        }
    }
    /// Parse `config_json` as a JSON object.
    pub fn config(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::from_str(&self.config_json)
    }
    /// Set config from any serialisable value.
    pub fn set_config<T: Serialize>(&mut self, value: &T) -> serde_json::Result<()> {
        self.config_json = serde_json::to_string(value)?;
        self.updated_at = unix_now();
        Ok(())
    }
}

// ── PluginConfigStore ─────────────────────────────────────────────────────────

/// Typed wrapper around a plugin's `config_json` field.
#[derive(Debug, Clone)]
pub struct PluginConfigStore {
    data: serde_json::Map<String, serde_json::Value>,
}

impl PluginConfigStore {
    /// Parse a JSON object string.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        let v: serde_json::Value = serde_json::from_str(json)?;
        let data = v.as_object().cloned().unwrap_or_default();
        Ok(Self { data })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            data: serde_json::Map::new(),
        }
    }

    pub fn set_str(&mut self, key: &str, val: &str) {
        self.data
            .insert(key.into(), serde_json::Value::String(val.into()));
    }
    pub fn set_bool(&mut self, key: &str, val: bool) {
        self.data.insert(key.into(), serde_json::Value::Bool(val));
    }
    pub fn set_i64(&mut self, key: &str, val: i64) {
        self.data
            .insert(key.into(), serde_json::Value::Number(val.into()));
    }
    pub fn set_value(&mut self, key: &str, val: serde_json::Value) {
        self.data.insert(key.into(), val);
    }
    pub fn remove(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.data.get(key)?.as_str()
    }
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.data.get(key)?.as_bool()
    }
    #[must_use]
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.data.get(key)?.as_i64()
    }
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_else(|_| "{}".into())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

// ── PluginInvocationLog ───────────────────────────────────────────────────────

/// A single logged plugin invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInvocation {
    pub id: u64,
    pub plugin_name: String,
    pub invoked_at: u64,
    pub success: bool,
    pub message: String,
    pub duration_ms: u32,
}

// ── DB helpers ────────────────────────────────────────────────────────────────

fn ensure_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS plugins (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    version         TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    config_json     TEXT NOT NULL DEFAULT '{}',
    path            TEXT,
    registered_at   INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS plugin_invocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_name     TEXT NOT NULL,
    invoked_at      INTEGER NOT NULL,
    success         INTEGER NOT NULL DEFAULT 1,
    message         TEXT NOT NULL DEFAULT '',
    duration_ms     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_plugin_name ON plugins(name);
CREATE INDEX IF NOT EXISTS idx_inv_plugin ON plugin_invocations(plugin_name);
CREATE INDEX IF NOT EXISTS idx_inv_ts ON plugin_invocations(invoked_at);
    "#,
    )?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── ProjectPluginManager ──────────────────────────────────────────────────────

/// Per-project plugin manager backed by SQLite.
pub struct ProjectPluginManager {
    db_path: PathBuf,
    /// Optional plugin search directory.
    plugin_dir: Option<PathBuf>,
}

impl std::fmt::Debug for ProjectPluginManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProjectPluginManager({:?})", self.db_path)
    }
}

impl ProjectPluginManager {
    /// Create a new manager pointing at `db_path`.
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
        ensure_tables(&conn)?;
        Ok(Self {
            db_path,
            plugin_dir: None,
        })
    }

    /// Set an optional directory to scan for plugin files.
    pub fn set_plugin_dir(&mut self, dir: impl AsRef<Path>) {
        self.plugin_dir = Some(dir.as_ref().to_path_buf());
    }

    fn open(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
        Ok(conn)
    }

    // ── CRUD ──────────────────────────────────────────────────────────────

    /// Register a new plugin. Returns its assigned ID.
    pub fn register(&self, record: &PluginRecord) -> Result<u64> {
        let conn = self.open()?;
        let now = unix_now();
        conn.execute(
            "INSERT INTO plugins (name, version, enabled, config_json, path, registered_at, updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                &record.name, &record.version, i64::from(record.enabled),
                &record.config_json, &record.path, now, now
            ],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Get a plugin by name.
    pub fn get(&self, name: &str) -> Result<Option<PluginRecord>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            "SELECT id,name,version,enabled,config_json,path,registered_at,updated_at \
             FROM plugins WHERE name=?1",
        )?;
        let mut rows = stmt.query(params![name])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(row_to_record(r)?));
        }
        Ok(None)
    }

    /// List all plugins.
    pub fn list_all(&self) -> Result<Vec<PluginRecord>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            "SELECT id,name,version,enabled,config_json,path,registered_at,updated_at \
             FROM plugins ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(row_to_record_owned(
                r.get::<_, i64>(0)? as u64,
                r.get(1)?,
                r.get(2)?,
                r.get::<_, i64>(3)? != 0,
                r.get(4)?,
                r.get(5)?,
                r.get::<_, i64>(6)? as u64,
                r.get::<_, i64>(7)? as u64,
            ))
        })?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// List only enabled plugins.
    pub fn list_enabled(&self) -> Result<Vec<PluginRecord>> {
        let all = self.list_all()?;
        Ok(all.into_iter().filter(|p| p.enabled).collect())
    }

    /// Enable a plugin.
    pub fn enable(&self, name: &str) -> Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE plugins SET enabled=1, updated_at=?1 WHERE name=?2",
            params![unix_now(), name],
        )?;
        Ok(n > 0)
    }

    /// Disable a plugin.
    pub fn disable(&self, name: &str) -> Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE plugins SET enabled=0, updated_at=?1 WHERE name=?2",
            params![unix_now(), name],
        )?;
        Ok(n > 0)
    }

    /// Update a plugin's config JSON.
    pub fn set_config(&self, name: &str, config_json: &str) -> Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE plugins SET config_json=?1, updated_at=?2 WHERE name=?3",
            params![config_json, unix_now(), name],
        )?;
        Ok(n > 0)
    }

    /// Update a plugin's version string.
    pub fn update_version(&self, name: &str, version: &str) -> Result<bool> {
        let conn = self.open()?;
        let n = conn.execute(
            "UPDATE plugins SET version=?1, updated_at=?2 WHERE name=?3",
            params![version, unix_now(), name],
        )?;
        Ok(n > 0)
    }

    /// Remove a plugin.
    pub fn unregister(&self, name: &str) -> Result<bool> {
        let conn = self.open()?;
        let n = conn.execute("DELETE FROM plugins WHERE name=?1", params![name])?;
        Ok(n > 0)
    }

    /// Check if a plugin is registered.
    #[must_use] 
    pub fn is_registered(&self, name: &str) -> bool {
        self.get(name).map(|r| r.is_some()).unwrap_or(false)
    }

    // ── Invocation log ────────────────────────────────────────────────────

    /// Append a plugin invocation log entry.
    pub fn log_invocation(
        &self,
        plugin_name: &str,
        success: bool,
        message: &str,
        duration_ms: u32,
    ) -> Result<u64> {
        let conn = self.open()?;
        conn.execute(
            "INSERT INTO plugin_invocations (plugin_name, invoked_at, success, message, duration_ms) \
             VALUES (?1,?2,?3,?4,?5)",
            params![plugin_name, unix_now(), i64::from(success), message, duration_ms],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Return the last `limit` invocations for `plugin_name`.
    pub fn invocation_log(&self, plugin_name: &str, limit: usize) -> Result<Vec<PluginInvocation>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            "SELECT id,plugin_name,invoked_at,success,message,duration_ms \
             FROM plugin_invocations WHERE plugin_name=?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![plugin_name, limit as i64], |r| {
            Ok(PluginInvocation {
                id: r.get::<_, i64>(0)? as u64,
                plugin_name: r.get(1)?,
                invoked_at: r.get::<_, i64>(2)? as u64,
                success: r.get::<_, i64>(3)? != 0,
                message: r.get(4)?,
                duration_ms: r.get::<_, i64>(5)? as u32,
            })
        })?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// Total number of invocations logged for a plugin.
    #[must_use]
    pub fn invocation_count(&self, plugin_name: &str) -> u64 {
        let Ok(conn) = self.open() else { return 0 };
        conn.query_row(
            "SELECT COUNT(*) FROM plugin_invocations WHERE plugin_name=?1",
            params![plugin_name],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u64)
        .unwrap_or(0)
    }

    // ── Auto-load ─────────────────────────────────────────────────────────

    /// Scan `plugin_dir` for `.so` / `.dll` / `.plugin.json` files and
    /// register any that are not yet in the database.
    /// Returns the list of newly-registered plugin names.
    pub fn auto_load_from_dir(&self) -> Result<Vec<String>> {
        let dir = match &self.plugin_dir {
            Some(d) => d.clone(),
            None => return Ok(vec![]),
        };
        let mut registered = Vec::new();
        let Ok(read_dir) = std::fs::read_dir(&dir) else { return Ok(vec![]) };
        for entry in read_dir.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let is_plugin = matches!(ext, "so" | "dll" | "dylib")
                || path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".plugin.json"));
            if !is_plugin { continue; }
            if self.is_registered(&name) {
                continue;
            }
            let mut rec = PluginRecord::new(&name, "0.0.0");
            rec.path = Some(path.to_string_lossy().into_owned());
            let _ = self.register(&rec);
            registered.push(name);
        }
        Ok(registered)
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    /// Number of registered plugins.
    #[must_use] 
    pub fn plugin_count(&self) -> usize {
        self.list_all().map(|v| v.len()).unwrap_or(0)
    }

    /// Number of enabled plugins.
    #[must_use] 
    pub fn enabled_count(&self) -> usize {
        self.list_enabled().map(|v| v.len()).unwrap_or(0)
    }
}

// ── Row helpers ───────────────────────────────────────────────────────────────

fn row_to_record(r: &rusqlite::Row<'_>) -> SqlResult<PluginRecord> {
    Ok(row_to_record_owned(
        r.get::<_, i64>(0)? as u64,
        r.get(1)?,
        r.get(2)?,
        r.get::<_, i64>(3)? != 0,
        r.get(4)?,
        r.get(5)?,
        r.get::<_, i64>(6)? as u64,
        r.get::<_, i64>(7)? as u64,
    ))
}

fn row_to_record_owned(
    id: u64,
    name: String,
    version: String,
    enabled: bool,
    config_json: String,
    path: Option<String>,
    registered_at: u64,
    updated_at: u64,
) -> PluginRecord {
    PluginRecord {
        id,
        name,
        version,
        enabled,
        config_json,
        path,
        registered_at,
        updated_at,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_manager() -> (TempDir, ProjectPluginManager) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("plugins.db");
        let mgr = ProjectPluginManager::new(&db).unwrap();
        (dir, mgr)
    }

    // ── PluginRecord ─────────────────────────────────────────────────────

    #[test]
    fn new_record_defaults() {
        let r = PluginRecord::new("my_plugin", "1.0.0");
        assert_eq!(r.name, "my_plugin");
        assert_eq!(r.version, "1.0.0");
        assert!(r.enabled);
        assert_eq!(r.config_json, "{}");
        assert!(r.registered_at > 0);
    }

    #[test]
    fn record_set_config_round_trip() {
        let mut r = PluginRecord::new("p", "0.1");
        r.set_config(&serde_json::json!({"key": "val"})).unwrap();
        let v = r.config().unwrap();
        assert_eq!(v["key"], "val");
    }

    // ── PluginConfigStore ────────────────────────────────────────────────

    #[test]
    fn config_store_set_get_str() {
        let mut s = PluginConfigStore::empty();
        s.set_str("host", "localhost");
        assert_eq!(s.get_str("host"), Some("localhost"));
        assert!(s.get_str("port").is_none());
    }

    #[test]
    fn config_store_set_get_bool() {
        let mut s = PluginConfigStore::empty();
        s.set_bool("verbose", true);
        assert_eq!(s.get_bool("verbose"), Some(true));
    }

    #[test]
    fn config_store_set_get_i64() {
        let mut s = PluginConfigStore::empty();
        s.set_i64("timeout", 30);
        assert_eq!(s.get_i64("timeout"), Some(30));
    }

    #[test]
    fn config_store_remove() {
        let mut s = PluginConfigStore::empty();
        s.set_str("k", "v");
        assert!(s.remove("k"));
        assert!(!s.remove("k"));
    }

    #[test]
    fn config_store_to_json_round_trip() {
        let mut s = PluginConfigStore::empty();
        s.set_str("a", "1");
        let json = s.to_json();
        let s2 = PluginConfigStore::from_json(&json).unwrap();
        assert_eq!(s2.get_str("a"), Some("1"));
    }

    #[test]
    fn config_store_from_json_object() {
        let s = PluginConfigStore::from_json(r#"{"x":42}"#).unwrap();
        assert_eq!(s.get_i64("x"), Some(42));
    }

    #[test]
    fn config_store_from_json_empty() {
        let s = PluginConfigStore::from_json("{}").unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn config_store_len() {
        let mut s = PluginConfigStore::empty();
        assert_eq!(s.len(), 0);
        s.set_str("a", "b");
        assert_eq!(s.len(), 1);
    }

    // ── ProjectPluginManager CRUD ────────────────────────────────────────

    #[test]
    fn register_and_get() {
        let (_d, mgr) = tmp_manager();
        let rec = PluginRecord::new("test_plugin", "1.2.3");
        let id = mgr.register(&rec).unwrap();
        assert!(id > 0);
        let got = mgr.get("test_plugin").unwrap().unwrap();
        assert_eq!(got.name, "test_plugin");
        assert_eq!(got.version, "1.2.3");
        assert!(got.enabled);
    }

    #[test]
    fn list_all_empty() {
        let (_d, mgr) = tmp_manager();
        assert!(mgr.list_all().unwrap().is_empty());
    }

    #[test]
    fn list_all_multiple() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("a", "1")).unwrap();
        mgr.register(&PluginRecord::new("b", "2")).unwrap();
        assert_eq!(mgr.list_all().unwrap().len(), 2);
    }

    #[test]
    fn enable_disable() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("p", "1")).unwrap();
        assert!(mgr.disable("p").unwrap());
        assert!(!mgr.get("p").unwrap().unwrap().enabled);
        assert!(mgr.enable("p").unwrap());
        assert!(mgr.get("p").unwrap().unwrap().enabled);
    }

    #[test]
    fn list_enabled_filters() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("on", "1")).unwrap();
        mgr.register(&PluginRecord::new("off", "1")).unwrap();
        mgr.disable("off").unwrap();
        let enabled = mgr.list_enabled().unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "on");
    }

    #[test]
    fn set_config_round_trip() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("p", "1")).unwrap();
        mgr.set_config("p", r#"{"key":"val"}"#).unwrap();
        let got = mgr.get("p").unwrap().unwrap();
        let v = got.config().unwrap();
        assert_eq!(v["key"], "val");
    }

    #[test]
    fn update_version() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("p", "1.0")).unwrap();
        assert!(mgr.update_version("p", "2.0").unwrap());
        assert_eq!(mgr.get("p").unwrap().unwrap().version, "2.0");
    }

    #[test]
    fn unregister_removes() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("p", "1")).unwrap();
        assert!(mgr.unregister("p").unwrap());
        assert!(mgr.get("p").unwrap().is_none());
    }

    #[test]
    fn is_registered_true_false() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("p", "1")).unwrap();
        assert!(mgr.is_registered("p"));
        assert!(!mgr.is_registered("q"));
    }

    // ── Invocation log ───────────────────────────────────────────────────

    #[test]
    fn log_invocation_and_retrieve() {
        let (_d, mgr) = tmp_manager();
        mgr.log_invocation("p", true, "ok", 10).unwrap();
        mgr.log_invocation("p", false, "err", 5).unwrap();
        let log = mgr.invocation_log("p", 10).unwrap();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn invocation_count() {
        let (_d, mgr) = tmp_manager();
        assert_eq!(mgr.invocation_count("p"), 0);
        mgr.log_invocation("p", true, "ok", 1).unwrap();
        assert_eq!(mgr.invocation_count("p"), 1);
    }

    #[test]
    fn invocation_log_limit() {
        let (_d, mgr) = tmp_manager();
        for i in 0..5 {
            mgr.log_invocation("p", true, "ok", i).unwrap();
        }
        let log = mgr.invocation_log("p", 3).unwrap();
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn invocation_log_empty_for_unknown_plugin() {
        let (_d, mgr) = tmp_manager();
        assert!(mgr.invocation_log("unknown", 10).unwrap().is_empty());
    }

    // ── Stats ────────────────────────────────────────────────────────────

    #[test]
    fn plugin_count_empty() {
        let (_d, mgr) = tmp_manager();
        assert_eq!(mgr.plugin_count(), 0);
    }

    #[test]
    fn plugin_count_after_register() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("a", "1")).unwrap();
        mgr.register(&PluginRecord::new("b", "1")).unwrap();
        assert_eq!(mgr.plugin_count(), 2);
    }

    #[test]
    fn enabled_count() {
        let (_d, mgr) = tmp_manager();
        mgr.register(&PluginRecord::new("a", "1")).unwrap();
        mgr.register(&PluginRecord::new("b", "1")).unwrap();
        mgr.disable("b").unwrap();
        assert_eq!(mgr.enabled_count(), 1);
    }

    // ── auto_load_from_dir ───────────────────────────────────────────────

    #[test]
    fn auto_load_no_dir_returns_empty() {
        let (_d, mgr) = tmp_manager();
        let names = mgr.auto_load_from_dir().unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn auto_load_scans_dir() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("p.db");
        let plugin_dir = dir.path().join("plugins");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(plugin_dir.join("my_plugin.so"), b"").unwrap();
        let mut mgr = ProjectPluginManager::new(&db).unwrap();
        mgr.set_plugin_dir(&plugin_dir);
        let names = mgr.auto_load_from_dir().unwrap();
        assert!(names.contains(&"my_plugin".to_string()));
        // Second scan should not re-register.
        let names2 = mgr.auto_load_from_dir().unwrap();
        assert!(names2.is_empty());
    }

    #[test]
    fn invocation_success_field() {
        let (_d, mgr) = tmp_manager();
        mgr.log_invocation("p", false, "fail msg", 0).unwrap();
        let log = mgr.invocation_log("p", 5).unwrap();
        assert!(!log[0].success);
        assert_eq!(log[0].message, "fail msg");
    }
}
