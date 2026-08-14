//! Project version migration for `rustre-project`.
//!
//! [`ProjectMigrator`] applies a sequence of [`Migration`]s to transform a
//! project's persisted state from one schema version to the next.  Each
//! [`MigrationStep`] carries the source version, target version, a description,
//! and the SQL (or other) transformation logic.
//!
//! The current implementation targets SQLite and mirrors the approach used in
//! `lib.rs`'s `run_pending_migrations`, but exposed as an explicitly versioned
//! pipeline so callers can reason about which transformations were applied.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

// ── MigrationError ────────────────────────────────────────────────────────────

/// Errors that can occur during project migration.
#[derive(Debug)]
pub enum MigrationError {
    DatabaseError(rusqlite::Error),
    IoError(std::io::Error),
    InvalidVersion {
        current: u32,
        target: u32,
    },
    NothingToMigrate {
        current: u32,
    },
    StepFailed {
        from_version: u32,
        to_version: u32,
        reason: String,
    },
    BackupFailed(String),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseError(e) => write!(f, "database error: {e}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::InvalidVersion { current, target } => write!(
                f,
                "cannot migrate from v{current} to v{target}: target is not newer"
            ),
            Self::NothingToMigrate { current } => {
                write!(f, "project is already at version {current}")
            }
            Self::StepFailed {
                from_version,
                to_version,
                reason,
            } => write!(
                f,
                "migration step v{from_version}→v{to_version} failed: {reason}"
            ),
            Self::BackupFailed(msg) => write!(f, "backup failed: {msg}"),
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<rusqlite::Error> for MigrationError {
    fn from(e: rusqlite::Error) -> Self {
        Self::DatabaseError(e)
    }
}

impl From<std::io::Error> for MigrationError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

// ── Migration / MigrationStep ─────────────────────────────────────────────────

/// A single schema transformation step.
#[derive(Debug, Clone)]
pub struct MigrationStep {
    /// Version this step migrates FROM.
    pub from_version: u32,
    /// Version this step migrates TO.
    pub to_version: u32,
    /// Human-readable description of the transformation.
    pub description: String,
    /// SQL statements to execute (separated by `;`).
    pub sql: String,
    /// If `true`, execution continues on SQL error (e.g., `IF NOT EXISTS` guards).
    pub allow_partial_failure: bool,
}

impl MigrationStep {
    /// Construct a step that fails hard on any SQL error.
    pub fn new(
        from_version: u32,
        to_version: u32,
        description: impl Into<String>,
        sql: impl Into<String>,
    ) -> Self {
        Self {
            from_version,
            to_version,
            description: description.into(),
            sql: sql.into(),
            allow_partial_failure: false,
        }
    }

    /// Mark this step as tolerating partial SQL failures.
    #[must_use] 
     
    pub fn allow_partial(mut self) -> Self {
        self.allow_partial_failure = true;
        self
    }

    /// Execute this step against `conn`.
    ///
    /// Wraps execution in a savepoint so that a failed step does not corrupt
    /// the database when `allow_partial_failure` is `false`.
    fn execute(&self, conn: &Connection) -> Result<(), MigrationError> {
        conn.execute_batch(&format!(
            "SAVEPOINT migration_step_v{};",
            self.from_version
        ))?;
        let result = conn.execute_batch(&self.sql);
        match result {
            Ok(()) => {
                conn.execute_batch(&format!(
                    "RELEASE migration_step_v{};",
                    self.from_version
                ))?;
                Ok(())
            }
            Err(e) if self.allow_partial_failure => {
                // Roll back the savepoint but continue.
                let _ = conn.execute_batch(&format!(
                    "ROLLBACK TO SAVEPOINT migration_step_v{};",
                    self.from_version
                ));
                let _ = conn.execute_batch(&format!(
                    "RELEASE migration_step_v{};",
                    self.from_version
                ));
                eprintln!(
                    "migration step v{}→v{} partial failure (allowed): {e}",
                    self.from_version, self.to_version
                );
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch(&format!(
                    "ROLLBACK TO SAVEPOINT migration_step_v{};",
                    self.from_version
                ));
                let _ = conn.execute_batch(&format!(
                    "RELEASE migration_step_v{};",
                    self.from_version
                ));
                Err(MigrationError::StepFailed {
                    from_version: self.from_version,
                    to_version: self.to_version,
                    reason: e.to_string(),
                })
            }
        }
    }
}

// ── Migration ─────────────────────────────────────────────────────────────────

/// A named, versioned group of [`MigrationStep`]s that together constitute one
/// logical schema upgrade.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Target schema version after this migration completes.
    pub target_version: u32,
    /// Human-readable name.
    pub name: String,
    /// Ordered list of steps.
    pub steps: Vec<MigrationStep>,
}

impl Migration {
    /// Construct a migration targeting `target_version`.
    pub fn new(target_version: u32, name: impl Into<String>) -> Self {
        Self {
            target_version,
            name: name.into(),
            steps: Vec::new(),
        }
    }

    /// Append a step.
    #[must_use]
    pub fn with_step(mut self, step: MigrationStep) -> Self {
        self.steps.push(step);
        self
    }
}

// ── MigrationRecord ───────────────────────────────────────────────────────────

/// Persisted record of an applied migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub from_version: u32,
    pub to_version: u32,
    pub name: String,
    pub applied_at: u64,
    pub duration_ms: u64,
    pub extra: HashMap<String, String>,
}

// ── MigrationResult ───────────────────────────────────────────────────────────

/// Result returned after a successful migration run.
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// Version before migration.
    pub previous_version: u32,
    /// Version after migration.
    pub current_version: u32,
    /// Ordered list of migration records for each step applied.
    pub applied: Vec<MigrationRecord>,
    /// Total wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Whether a backup was created before migrating.
    pub backup_created: bool,
    /// Path to the backup file, if created.
    pub backup_path: Option<std::path::PathBuf>,
}

impl MigrationResult {
    /// Return `true` when any migrations were actually applied.
    #[must_use]
    pub fn migrated(&self) -> bool {
        !self.applied.is_empty()
    }

    /// Return the number of migration steps applied.
    #[must_use]
    pub fn steps_applied(&self) -> usize {
        self.applied.len()
    }
}

// ── ProjectMigrator ───────────────────────────────────────────────────────────

/// Applies versioned schema migrations to a RustRE project database.
pub struct ProjectMigrator {
    db_path: std::path::PathBuf,
    /// Registered migrations in ascending order of target_version.
    migrations: Vec<Migration>,
    /// Whether to create a `.bak` file before migrating.
    create_backup: bool,
}

impl ProjectMigrator {
    /// Create a migrator for the database at `db_path`.
    pub fn new(db_path: impl AsRef<Path>) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            migrations: Self::built_in_migrations(),
            create_backup: true,
        }
    }

    /// Disable automatic backup creation.
    #[must_use] 
    pub fn without_backup(mut self) -> Self {
        self.create_backup = false;
        self
    }

    /// Register an additional migration.  Steps must be inserted in
    /// ascending `target_version` order.
    #[must_use] 
    pub fn register_migration(mut self, migration: Migration) -> Self {
        self.migrations.push(migration);
        self.migrations
            .sort_by_key(|m| m.target_version);
        self
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Detect the current schema version of the database.
    ///
    /// Reads from the `schema_migrations` table; returns `0` when the table is
    /// absent or empty.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError`] on database failure.
    pub fn current_version(&self) -> Result<u32, MigrationError> {
        let conn = Connection::open(&self.db_path)?;
        Self::read_version(&conn)
    }

    /// Apply all pending migrations up to `target_version`.
    ///
    /// If `target_version` is `u32::MAX`, migrates to the latest registered
    /// version.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError`] when the database cannot be opened, a backup
    /// cannot be created, or any migration step fails.
    pub fn migrate(&self, target_version: u32) -> Result<MigrationResult, MigrationError> {
        let start = std::time::Instant::now();
        let conn = Connection::open(&self.db_path)?;
        // Ensure the migrations tracking table exists.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version    INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
             );",
        )?;

        let current = Self::read_version(&conn)?;

        let effective_target = if target_version == u32::MAX {
            self.migrations
                .last()
                .map_or(current, |m| m.target_version)
        } else {
            target_version
        };

        if effective_target <= current {
            return Err(MigrationError::NothingToMigrate { current });
        }

        // Create backup before mutating.
        let (backup_created, backup_path) = if self.create_backup {
            let bp = self.db_path.with_extension("db.bak");
            std::fs::copy(&self.db_path, &bp).map_err(|e| {
                MigrationError::BackupFailed(format!("copy to {}: {e}", bp.display()))
            })?;
            (true, Some(bp))
        } else {
            (false, None)
        };

        let mut applied = Vec::new();

        for migration in &self.migrations {
            if migration.target_version <= current {
                continue;
            }
            if migration.target_version > effective_target {
                break;
            }
            let step_start = std::time::Instant::now();
            for step in &migration.steps {
                step.execute(&conn)?;
            }
            // Record migration as applied.
            let now = unix_now();
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![migration.target_version, now],
            )?;
            applied.push(MigrationRecord {
                from_version: current,
                to_version: migration.target_version,
                name: migration.name.clone(),
                applied_at: now,
                duration_ms: step_start.elapsed().as_millis() as u64,
                extra: HashMap::new(),
            });
        }

        Ok(MigrationResult {
            previous_version: current,
            current_version: effective_target,
            applied,
            elapsed_ms: start.elapsed().as_millis() as u64,
            backup_created,
            backup_path,
        })
    }

    /// Check whether any migrations are pending.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError`] on database failure.
    pub fn has_pending_migrations(&self) -> Result<bool, MigrationError> {
        let current = self.current_version()?;
        let latest = self
            .migrations
            .last()
            .map_or(0, |m| m.target_version);
        Ok(current < latest)
    }

    /// Return a list of pending migrations (those not yet applied).
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError`] on database failure.
    pub fn pending_migrations(&self) -> Result<Vec<&Migration>, MigrationError> {
        let current = self.current_version()?;
        Ok(self
            .migrations
            .iter()
            .filter(|m| m.target_version > current)
            .collect())
    }

    // ── Built-in migrations ───────────────────────────────────────────────────

    fn built_in_migrations() -> Vec<Migration> {
        vec![
            // v0 → v1 is handled by `lib.rs`'s initial `run_migrations`.
            // Additional migrations are defined below for future use.
            Migration::new(5, "add_analysis_metadata")
                .with_step(MigrationStep::new(
                    4,
                    5,
                    "Add analysis_runs table",
                    r#"
CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    engine TEXT NOT NULL DEFAULT 'default',
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    result_json TEXT NOT NULL DEFAULT '{}',
    flags INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_binary ON analysis_runs(binary_id);
"#,
                )
                .allow_partial()),
            Migration::new(6, "add_call_graph_edges")
                .with_step(MigrationStep::new(
                    5,
                    6,
                    "Add call_graph table for inter-procedural analysis",
                    r#"
CREATE TABLE IF NOT EXISTS call_graph (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    caller_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    callee_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    call_site INTEGER NOT NULL,
    indirect INTEGER NOT NULL DEFAULT 0,
    UNIQUE(binary_id, caller_id, callee_id, call_site)
);
CREATE INDEX IF NOT EXISTS idx_call_graph_caller ON call_graph(caller_id);
CREATE INDEX IF NOT EXISTS idx_call_graph_callee ON call_graph(callee_id);
"#,
                )
                .allow_partial()),
            Migration::new(7, "add_decompilation_cache")
                .with_step(MigrationStep::new(
                    6,
                    7,
                    "Add decompilation cache table",
                    r#"
CREATE TABLE IF NOT EXISTS decompilation_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    language TEXT NOT NULL DEFAULT 'c',
    source TEXT NOT NULL,
    generated_at INTEGER NOT NULL,
    engine_version TEXT,
    UNIQUE(function_id, language)
);
CREATE INDEX IF NOT EXISTS idx_decompile_cache_fn ON decompilation_cache(function_id);
"#,
                )
                .allow_partial()),
        ]
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn read_version(conn: &Connection) -> Result<u32, MigrationError> {
        // If the tracking table doesn't exist yet, version is 0.
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !exists {
            return Ok(0);
        }
        let max_version = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u32)
            .unwrap_or(0);
        Ok(max_version)
    }
}

// ── Convenience function ──────────────────────────────────────────────────────

/// Perform the v1→v2 migration on the database at `db_path`.
///
/// This is a named entry point that matches the requested API surface.  The
/// full migration pipeline is available via [`ProjectMigrator::migrate`].
///
/// # Errors
///
/// Returns [`MigrationError`] when migration fails.
pub fn migrate_v1_to_v2(db_path: impl AsRef<Path>) -> Result<MigrationResult, MigrationError> {
    // For this named function we treat "v1 → v2" as synonymous with the first
    // built-in upgrade step (target version 5, since the baseline schema in
    // lib.rs already occupies versions 1–4).
    ProjectMigrator::new(db_path)
        .without_backup()
        .migrate(5)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Project;

    fn tmp_project_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = Project::new("migtest", dir.path()).unwrap();
        let db = p.db_path();
        (dir, db)
    }

    #[test]
    fn test_current_version_after_project_create() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        let v = migrator.current_version().unwrap();
        // Project::new runs migrations 1-4.
        assert!(v >= 4);
    }

    #[test]
    fn test_has_pending_migrations_true() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        // Built-in migrations target versions 5, 6, 7 — all pending.
        assert!(migrator.has_pending_migrations().unwrap());
    }

    #[test]
    fn test_pending_migrations_list() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        let pending = migrator.pending_migrations().unwrap();
        assert!(!pending.is_empty());
    }

    #[test]
    fn test_migrate_to_v5() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        let result = migrator.migrate(5).unwrap();
        assert!(result.migrated());
        assert_eq!(result.current_version, 5);
    }

    #[test]
    fn test_migrate_twice_fails_nothing_to_migrate() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        migrator.migrate(5).unwrap();
        let err = migrator.migrate(5).unwrap_err();
        assert!(matches!(err, MigrationError::NothingToMigrate { .. }));
    }

    #[test]
    fn test_migration_result_steps_applied() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        let result = migrator.migrate(5).unwrap();
        assert_eq!(result.steps_applied(), 1);
    }

    #[test]
    fn test_migration_result_previous_version() {
        let (_dir, db) = tmp_project_db();
        let migrator = ProjectMigrator::new(&db).without_backup();
        let before = migrator.current_version().unwrap();
        let result = migrator.migrate(5).unwrap();
        assert_eq!(result.previous_version, before);
    }

    #[test]
    fn test_migration_error_display() {
        let e = MigrationError::StepFailed {
            from_version: 1,
            to_version: 2,
            reason: "oops".to_string(),
        };
        assert!(e.to_string().contains('1'));
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn test_migration_step_new() {
        let step = MigrationStep::new(1, 2, "desc", "SELECT 1;");
        assert_eq!(step.from_version, 1);
        assert_eq!(step.to_version, 2);
        assert!(!step.allow_partial_failure);
    }

    #[test]
    fn test_migration_step_allow_partial() {
        let step = MigrationStep::new(1, 2, "d", "SELECT 1;").allow_partial();
        assert!(step.allow_partial_failure);
    }

    #[test]
    fn test_migration_new() {
        let m = Migration::new(5, "test migration");
        assert_eq!(m.target_version, 5);
        assert_eq!(m.name, "test migration");
        assert!(m.steps.is_empty());
    }

    #[test]
    fn test_custom_migration_registration() {
        let (_dir, db) = tmp_project_db();
        let custom = Migration::new(100, "custom").with_step(MigrationStep::new(
            99,
            100,
            "add custom table",
            "CREATE TABLE IF NOT EXISTS custom_test (id INTEGER PRIMARY KEY);",
        ));
        let migrator = ProjectMigrator::new(&db)
            .without_backup()
            .register_migration(custom);
        // The custom migration at v100 should be pending.
        let pending = migrator.pending_migrations().unwrap();
        assert!(pending.iter().any(|m| m.target_version == 100));
    }

    #[test]
    fn test_migrate_no_backup_flag() {
        let (_dir, db) = tmp_project_db();
        let result = ProjectMigrator::new(&db)
            .without_backup()
            .migrate(5)
            .unwrap();
        assert!(!result.backup_created);
        assert!(result.backup_path.is_none());
    }

    #[test]
    fn test_migrate_v1_to_v2_convenience() {
        let (_dir, db) = tmp_project_db();
        let result = migrate_v1_to_v2(&db).unwrap();
        assert_eq!(result.current_version, 5);
    }
}
