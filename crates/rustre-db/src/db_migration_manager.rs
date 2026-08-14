//! `db_migration_manager` — Database schema migration management.
//!
//! Provides [`DbMigrationManager`], [`Migration`], [`MigrationVersion`], and
//! the primary entry point [`run_migrations`].

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

/// Errors produced by migration operations.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// A SQL execution error.
    #[error("sql error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// Migration version conflict (duplicate version numbers).
    #[error("duplicate migration version: {0}")]
    DuplicateVersion(u32),
    /// The migrations are out of order.
    #[error("migration version {0} is less than preceding version {1}")]
    OutOfOrder(u32, u32),
    /// A migration was already applied.
    #[error("migration version {0} is already applied")]
    AlreadyApplied(u32),
    /// A migration version that should be present is missing.
    #[error("missing migration version {0}")]
    MissingVersion(u32),
    /// A rollback was requested but the migration has no down script.
    #[error("migration {0} has no rollback script")]
    NoRollback(u32),
    /// Any other error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// MigrationVersion
// ---------------------------------------------------------------------------

/// A simple semantic version wrapper for migrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MigrationVersion(pub u32);

impl MigrationVersion {
    /// Create a new migration version from a raw integer.
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    /// The raw version number.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for MigrationVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

impl From<u32> for MigrationVersion {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// A single database migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    /// Unique version number — must be strictly increasing in the migration list.
    pub version: MigrationVersion,
    /// Human-readable name for this migration.
    pub name: String,
    /// SQL statements to apply (up direction).
    pub up_sql: String,
    /// SQL statements to reverse this migration (down direction), if supported.
    pub down_sql: Option<String>,
    /// Optional checksum of `up_sql` for integrity verification.
    pub checksum: Option<u64>,
}

impl Migration {
    /// Create a new migration with only an up script.
    #[must_use]
    pub fn new(
        version: impl Into<MigrationVersion>,
        name: impl Into<String>,
        up_sql: impl Into<String>,
    ) -> Self {
        let up_sql = up_sql.into();
        let checksum = Some(fnv1a_64(up_sql.as_bytes()));
        Self {
            version: version.into(),
            name: name.into(),
            up_sql,
            down_sql: None,
            checksum,
        }
    }

    /// Create a migration with both up and down scripts.
    #[must_use]
    pub fn with_rollback(
        version: impl Into<MigrationVersion>,
        name: impl Into<String>,
        up_sql: impl Into<String>,
        down_sql: impl Into<String>,
    ) -> Self {
        let up_sql = up_sql.into();
        let checksum = Some(fnv1a_64(up_sql.as_bytes()));
        Self {
            version: version.into(),
            name: name.into(),
            up_sql,
            down_sql: Some(down_sql.into()),
            checksum,
        }
    }

    /// Returns `true` if this migration supports rollback.
    #[must_use]
    pub const fn can_rollback(&self) -> bool {
        self.down_sql.is_some()
    }

    /// Verify that the stored checksum matches the current `up_sql`.
    #[must_use]
    pub fn checksum_valid(&self) -> bool {
        self.checksum.is_none_or(|cs| cs == fnv1a_64(self.up_sql.as_bytes()))
    }
}

impl fmt::Display for Migration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Migration[{}] '{}'", self.version, self.name)
    }
}

// ---------------------------------------------------------------------------
// MigrationRecord
// ---------------------------------------------------------------------------

/// A record of an applied migration stored in the `schema_migrations` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Version that was applied.
    pub version: MigrationVersion,
    /// Name of the migration.
    pub name: String,
    /// Unix timestamp when the migration was applied.
    pub applied_at: i64,
    /// Checksum of the `up_sql` at the time of application.
    pub checksum: Option<u64>,
}

// ---------------------------------------------------------------------------
// MigrationStatus
// ---------------------------------------------------------------------------

/// Status of a migration relative to the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    /// Applied and checksum matches.
    Applied,
    /// Applied but checksum has changed (`up_sql` was modified after apply).
    AppliedWithChecksumMismatch,
    /// Not yet applied.
    Pending,
    /// Applied in the database but not present in the migration list.
    Orphan,
}

impl fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied => write!(f, "applied"),
            Self::AppliedWithChecksumMismatch => write!(f, "applied(checksum-mismatch)"),
            Self::Pending => write!(f, "pending"),
            Self::Orphan => write!(f, "orphan"),
        }
    }
}

// ---------------------------------------------------------------------------
// MigrationReport
// ---------------------------------------------------------------------------

/// Summary report after running or checking migrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Total migrations considered.
    pub total: usize,
    /// Migrations that were already applied.
    pub already_applied: usize,
    /// Migrations applied in this run.
    pub newly_applied: usize,
    /// Migrations that failed.
    pub failed: usize,
    /// Per-migration status entries.
    pub statuses: Vec<(MigrationVersion, String, MigrationStatus)>,
}

impl MigrationReport {
    /// Returns `true` if all migrations applied successfully (no failures).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.failed == 0
    }
}

impl fmt::Display for MigrationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MigrationReport: total={} applied={} new={} failed={}",
            self.total, self.already_applied, self.newly_applied, self.failed
        )
    }
}

// ---------------------------------------------------------------------------
// DbMigrationManager
// ---------------------------------------------------------------------------

/// Manages database schema migrations for a `SQLite` connection.
///
/// Maintains a `schema_migrations` table to track which migrations have been
/// applied, and applies pending migrations in version order.
pub struct DbMigrationManager {
    conn: Arc<Mutex<Connection>>,
    migrations: Vec<Migration>,
    table_name: String,
}

impl DbMigrationManager {
    /// Create a new manager with the given connection and migrations.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::DuplicateVersion`] if any two migrations share
    /// a version number, or [`MigrationError::OutOfOrder`] if the list is not
    /// strictly increasing.
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        migrations: Vec<Migration>,
    ) -> Result<Self, MigrationError> {
        Self::validate_migration_list(&migrations)?;
        Ok(Self {
            conn,
            migrations,
            // "schema_migrations" is a known-safe identifier; no validation needed here.
            table_name: "schema_migrations".to_string(),
        })
    }

    /// Override the tracking table name (default: `schema_migrations`).
    ///
    /// The name is validated: it must be non-empty and contain only ASCII
    /// alphanumerics and underscores, since it is interpolated directly into
    /// SQL statements that do not support bound parameters for identifiers.
    ///
    /// # Panics
    ///
    /// Panics if `name` contains characters outside `[A-Za-z0-9_]` or is empty.
    #[must_use]
    pub fn with_table_name(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        assert!(
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "table_name must contain only ASCII alphanumerics and underscores, got: {name:?}"
        );
        self.table_name = name;
        self
    }

    /// Ensure the `schema_migrations` tracking table exists.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Sql`] on database errors.
    pub fn ensure_tracking_table(&self) -> Result<(), MigrationError> {
        self.conn.lock().execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {} (
                version     INTEGER NOT NULL PRIMARY KEY,
                name        TEXT    NOT NULL,
                applied_at  INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                checksum    INTEGER
            );",
            self.table_name
        ))?;
        Ok(())
    }

    /// Return the set of applied migration versions from the database.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Sql`] on database errors.
    pub fn applied_versions(&self) -> Result<HashMap<u32, MigrationRecord>, MigrationError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT version, name, applied_at, checksum FROM {}",
            self.table_name
        ))?;
        let records: Result<HashMap<u32, MigrationRecord>, rusqlite::Error> = stmt
            .query_map([], |row| {
                let version: u32 = row.get(0)?;
                let name: String = row.get(1)?;
                let applied_at: i64 = row.get(2)?;
                let checksum: Option<i64> = row.get(3)?;
                Ok((version, MigrationRecord {
                    version: MigrationVersion(version),
                    name,
                    applied_at,
                    checksum: checksum.map(i64::cast_unsigned),
                }))
            })?
            .collect();
        drop(stmt);
        drop(conn);
        Ok(records?)
    }

    /// Apply all pending migrations in version order.
    ///
    /// # Errors
    ///
    /// Returns the first [`MigrationError`] encountered.
    pub fn migrate_up(&self) -> Result<MigrationReport, MigrationError> {
        self.ensure_tracking_table()?;
        let applied = self.applied_versions()?;
        let mut report = MigrationReport {
            total: self.migrations.len(),
            already_applied: 0,
            newly_applied: 0,
            failed: 0,
            statuses: Vec::new(),
        };

        for migration in &self.migrations {
            let v = migration.version.as_u32();
            if let Some(record) = applied.get(&v) {
                let status = if record.checksum == migration.checksum {
                    MigrationStatus::Applied
                } else {
                    MigrationStatus::AppliedWithChecksumMismatch
                };
                report.already_applied += 1;
                report.statuses.push((migration.version, migration.name.clone(), status));
            } else {
                match self.apply_migration(migration) {
                    Ok(()) => {
                        report.newly_applied += 1;
                        report.statuses.push((
                            migration.version,
                            migration.name.clone(),
                            MigrationStatus::Applied,
                        ));
                    }
                    Err(e) => {
                        report.failed += 1;
                        report.statuses.push((
                            migration.version,
                            migration.name.clone(),
                            MigrationStatus::Pending,
                        ));
                        return Err(e);
                    }
                }
            }
        }
        Ok(report)
    }

    /// Roll back the latest applied migration.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NoRollback`] if the latest migration has no
    /// down script, or [`MigrationError::Sql`] on database errors.
    pub fn migrate_down_one(&self) -> Result<(), MigrationError> {
        self.ensure_tracking_table()?;
        let applied = self.applied_versions()?;
        let latest = applied.keys().max().copied();
        let Some(version) = latest else {
            return Ok(()); // nothing applied
        };
        let migration = self.migrations.iter().find(|m| m.version.as_u32() == version)
            .ok_or(MigrationError::MissingVersion(version))?;
        let down_sql = migration.down_sql.as_ref()
            .ok_or(MigrationError::NoRollback(version))?
            .clone();
        let conn = self.conn.lock();
        // Atomically execute the rollback SQL and remove the tracking row so
        // that a failure in either step does not leave the DB half-rolled-back.
        conn.execute_batch("BEGIN;")?;
        let result = (|| -> Result<(), MigrationError> {
            conn.execute_batch(&down_sql)?;
            conn.execute(
                &format!("DELETE FROM {} WHERE version = ?1", self.table_name),
                params![version],
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => conn.execute_batch("COMMIT;")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e);
            }
        }
        drop(conn);
        Ok(())
    }

    /// Roll back all applied migrations in reverse order.
    ///
    /// # Errors
    ///
    /// Returns the first [`MigrationError`] encountered during rollback.
    pub fn migrate_down_all(&self) -> Result<usize, MigrationError> {
        self.ensure_tracking_table()?;
        let applied = self.applied_versions()?;
        let mut versions: Vec<u32> = applied.keys().copied().collect();
        versions.sort_by(|a, b| b.cmp(a)); // reverse order
        let mut count = 0;
        for v in versions {
            let migration = self.migrations.iter().find(|m| m.version.as_u32() == v)
                .ok_or(MigrationError::MissingVersion(v))?;
            let down_sql = migration.down_sql.as_ref()
                .ok_or(MigrationError::NoRollback(v))?
                .clone();
            // Each rollback step is atomic: schema change + tracking-row removal
            // happen together so that a failure cannot leave us in a state where
            // the schema is rolled back but the version is still recorded.
            let conn = self.conn.lock();
            conn.execute_batch("BEGIN;")?;
            let result = (|| -> Result<(), MigrationError> {
                conn.execute_batch(&down_sql)?;
                conn.execute(
                    &format!("DELETE FROM {} WHERE version = ?1", self.table_name),
                    params![v],
                )?;
                Ok(())
            })();
            match result {
                Ok(()) => conn.execute_batch("COMMIT;")?,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    return Err(e);
                }
            }
            drop(conn);
            count += 1;
        }
        Ok(count)
    }

    /// Check the status of all migrations without applying any.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Sql`] on database errors.
    pub fn status(&self) -> Result<Vec<(Migration, MigrationStatus)>, MigrationError> {
        self.ensure_tracking_table()?;
        let applied = self.applied_versions()?;
        let mut result = Vec::new();
        for migration in &self.migrations {
            let v = migration.version.as_u32();
            let status = applied.get(&v).map_or(MigrationStatus::Pending, |record| if record.checksum == migration.checksum {
                    MigrationStatus::Applied
                } else {
                    MigrationStatus::AppliedWithChecksumMismatch
                });
            result.push((migration.clone(), status));
        }
        // Check for orphaned applied versions
        for v in applied.keys() {
            if !self.migrations.iter().any(|m| m.version.as_u32() == *v) {
                let record = &applied[v];
                let orphan_migration = Migration {
                    version: MigrationVersion(*v),
                    name: record.name.clone(),
                    up_sql: String::new(),
                    down_sql: None,
                    checksum: None,
                };
                result.push((orphan_migration, MigrationStatus::Orphan));
            }
        }
        result.sort_by_key(|(m, _)| m.version);
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn apply_migration(&self, migration: &Migration) -> Result<(), MigrationError> {
        let conn = self.conn.lock();
        // Wrap the schema change AND the tracking INSERT in a single transaction
        // so that a failure in either step leaves the database in a consistent
        // state (neither half-applied schema nor untracked migration).
        conn.execute_batch("BEGIN;")?;
        let result = (|| -> Result<(), MigrationError> {
            conn.execute_batch(&migration.up_sql)?;
            conn.execute(
                &format!(
                    "INSERT INTO {} (version, name, checksum) VALUES (?1, ?2, ?3)",
                    self.table_name
                ),
                params![
                    migration.version.as_u32(),
                    migration.name,
                    migration.checksum.map(u64::cast_signed),
                ],
            )?;
            Ok(())
        })();
        let outcome = match result {
            Ok(()) => {
                conn.execute_batch("COMMIT;")?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        };
        drop(conn);
        outcome
    }

    fn validate_migration_list(migrations: &[Migration]) -> Result<(), MigrationError> {
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut prev = 0u32;
        for m in migrations {
            let v = m.version.as_u32();
            if seen.contains(&v) {
                return Err(MigrationError::DuplicateVersion(v));
            }
            if v < prev {
                return Err(MigrationError::OutOfOrder(v, prev));
            }
            seen.insert(v);
            prev = v;
        }
        Ok(())
    }
}

impl fmt::Debug for DbMigrationManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DbMigrationManager(migrations={}, table='{}')",
            self.migrations.len(),
            self.table_name
        )
    }
}

// ---------------------------------------------------------------------------
// run_migrations — primary entry point
// ---------------------------------------------------------------------------

/// Apply all pending migrations to the given `SQLite` connection.
///
/// This is the primary one-shot entry point.  It creates the tracking table
/// if necessary and applies any pending migrations in order.
///
/// # Errors
///
/// Returns the first [`MigrationError`] encountered.
pub fn run_migrations(
    conn: Arc<Mutex<Connection>>,
    migrations: Vec<Migration>,
) -> Result<MigrationReport, MigrationError> {
    let manager = DbMigrationManager::new(conn, migrations)?;
    manager.migrate_up()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn open_db() -> Arc<Mutex<Connection>> {
        Arc::new(Mutex::new(Connection::open_in_memory().unwrap()))
    }

    fn sample_migrations() -> Vec<Migration> {
        vec![
            Migration::with_rollback(
                1u32, "create_functions",
                "CREATE TABLE functions (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
                "DROP TABLE functions;",
            ),
            Migration::with_rollback(
                2u32, "add_address_column",
                "ALTER TABLE functions ADD COLUMN address INTEGER;",
                "SELECT 1;", // SQLite cannot drop columns easily
            ),
            Migration::new(
                3u32, "create_symbols",
                "CREATE TABLE symbols (id INTEGER PRIMARY KEY, sym TEXT NOT NULL);",
            ),
        ]
    }

    #[test]
    fn test_migration_version_display() {
        assert_eq!(MigrationVersion(5).to_string(), "v5");
    }

    #[test]
    fn test_migration_version_ord() {
        assert!(MigrationVersion(1) < MigrationVersion(2));
    }

    #[test]
    fn test_migration_checksum_valid() {
        let m = Migration::new(1u32, "init", "CREATE TABLE t (id INTEGER);");
        assert!(m.checksum_valid());
    }

    #[test]
    fn test_run_migrations_basic() {
        let db = open_db();
        let report = run_migrations(db, sample_migrations()).unwrap();
        assert_eq!(report.total, 3);
        assert_eq!(report.newly_applied, 3);
        assert!(report.is_success());
    }

    #[test]
    fn test_run_migrations_idempotent() {
        let db = open_db();
        let _ = run_migrations(db.clone(), sample_migrations()).unwrap();
        let report = run_migrations(db, sample_migrations()).unwrap();
        assert_eq!(report.already_applied, 3);
        assert_eq!(report.newly_applied, 0);
    }

    #[test]
    fn test_migrate_down_one() {
        let db = open_db();
        let manager = DbMigrationManager::new(db, sample_migrations()).unwrap();
        manager.migrate_up().unwrap();
        // migration 3 has no rollback
        let err = manager.migrate_down_one();
        assert!(err.is_err());
    }

    #[test]
    fn test_migrate_down_all_partial() {
        let db = open_db();
        let migrations = vec![
            Migration::with_rollback(1u32, "t1",
                "CREATE TABLE t1 (id INTEGER);",
                "DROP TABLE t1;"),
            Migration::with_rollback(2u32, "t2",
                "CREATE TABLE t2 (id INTEGER);",
                "DROP TABLE t2;"),
        ];
        let manager = DbMigrationManager::new(db, migrations).unwrap();
        manager.migrate_up().unwrap();
        let count = manager.migrate_down_all().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_duplicate_version_error() {
        let migrations = vec![
            Migration::new(1u32, "a", "SELECT 1;"),
            Migration::new(1u32, "b", "SELECT 2;"),
        ];
        let db = open_db();
        let err = DbMigrationManager::new(db, migrations);
        assert!(matches!(err, Err(MigrationError::DuplicateVersion(1))));
    }

    #[test]
    fn test_out_of_order_error() {
        let migrations = vec![
            Migration::new(5u32, "a", "SELECT 1;"),
            Migration::new(3u32, "b", "SELECT 2;"),
        ];
        let db = open_db();
        let err = DbMigrationManager::new(db, migrations);
        assert!(matches!(err, Err(MigrationError::OutOfOrder(3, 5))));
    }

    #[test]
    fn test_status_shows_pending() {
        let db = open_db();
        let manager = DbMigrationManager::new(db, sample_migrations()).unwrap();
        let statuses = manager.status().unwrap();
        assert!(statuses.iter().all(|(_, s)| *s == MigrationStatus::Pending));
    }

    #[test]
    fn test_status_shows_applied_after_migrate() {
        let db = open_db();
        let manager = DbMigrationManager::new(db, sample_migrations()).unwrap();
        manager.migrate_up().unwrap();
        let statuses = manager.status().unwrap();
        let applied_count = statuses.iter()
            .filter(|(_, s)| *s == MigrationStatus::Applied).count();
        assert_eq!(applied_count, 3);
    }

    #[test]
    fn test_migration_display() {
        let m = Migration::new(42u32, "add_index", "CREATE INDEX idx ON t(id);");
        let s = m.to_string();
        assert!(s.contains("v42"));
        assert!(s.contains("add_index"));
    }

    #[test]
    fn test_migration_can_rollback() {
        let m = Migration::with_rollback(1u32, "a", "CREATE TABLE t(id INT);", "DROP TABLE t;");
        assert!(m.can_rollback());
        let m2 = Migration::new(2u32, "b", "SELECT 1;");
        assert!(!m2.can_rollback());
    }
}
