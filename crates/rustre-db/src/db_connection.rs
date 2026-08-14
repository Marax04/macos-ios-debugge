//! `db_connection` — `SQLite` connection pool, [`Database`], [`Connection`],
//! and [`Transaction`] handles.
//!
//! Provides a lightweight, dependency-free connection pool for `rusqlite`
//! built on top of `parking_lot::Mutex` and a bounded `Vec` free-list.
//!
//! The pool opens `SQLite` connections eagerly (up to `max_size`) and applies
//! a common set of pragmas (WAL journal, foreign keys, synchronous=NORMAL,
//! busy timeout) so every checked-out connection is consistent.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use rusqlite::{Connection as SqliteConnection, OpenFlags};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the connection pool / database layer.
#[derive(Debug, Error)]
pub enum DbError {
    /// A low-level `SQLite` error.
    #[error("sql error: {0}")]
    Sql(#[from] rusqlite::Error),
    /// Timed out waiting for a free connection.
    #[error("timed out waiting for a database connection after {0:?}")]
    AcquireTimeout(Duration),
    /// Invalid configuration (e.g. `max_size == 0`).
    #[error("invalid pool configuration: {0}")]
    InvalidConfig(String),
    /// The pool has been shut down.
    #[error("the database pool has been shut down")]
    Closed,
}

// ---------------------------------------------------------------------------
// DbLocation
// ---------------------------------------------------------------------------

/// Where the database lives.
#[derive(Debug, Clone)]
pub enum DbLocation {
    /// An on-disk `SQLite` file.
    File(PathBuf),
    /// A private in-memory database, scoped to the pool.
    Memory,
}

impl DbLocation {
    /// Open a fresh `rusqlite::Connection` for this location.
    fn open(&self) -> Result<SqliteConnection, rusqlite::Error> {
        match self {
            Self::File(path) => SqliteConnection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            ),
            Self::Memory => SqliteConnection::open_in_memory(),
        }
    }
}

// ---------------------------------------------------------------------------
// DbConfig
// ---------------------------------------------------------------------------

/// Configuration for [`Database::open`].
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Where the database lives.
    pub location: DbLocation,
    /// Maximum number of concurrent connections in the pool.
    pub max_size: usize,
    /// How long to wait for a free connection before returning
    /// [`DbError::AcquireTimeout`].
    pub acquire_timeout: Duration,
    /// `SQLite` `busy_timeout` (per-connection).
    pub busy_timeout: Duration,
    /// If `true`, enable WAL journal mode.
    pub enable_wal: bool,
    /// If `true`, enforce foreign-key constraints.
    pub enable_foreign_keys: bool,
}

impl DbConfig {
    /// Default config for an on-disk database at `path`.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            location: DbLocation::File(path.into()),
            ..Self::defaults()
        }
    }

    /// Default config for a private in-memory database.
    #[must_use]
    pub fn memory() -> Self {
        Self {
            location: DbLocation::Memory,
            // Each in-memory `Connection::open_in_memory()` is its own
            // database; pool size > 1 would give every checkout a fresh,
            // empty DB. Force single-conn for correctness.
            max_size: 1,
            ..Self::defaults()
        }
    }

    const fn defaults() -> Self {
        Self {
            location: DbLocation::Memory,
            max_size: 8,
            acquire_timeout: Duration::from_secs(30),
            busy_timeout: Duration::from_secs(5),
            enable_wal: true,
            enable_foreign_keys: true,
        }
    }
}

// ---------------------------------------------------------------------------
// PoolInner — shared state behind Database
// ---------------------------------------------------------------------------

struct PoolInner {
    config: DbConfig,
    /// Free list of available connections.
    idle: Mutex<Option<Vec<SqliteConnection>>>, // None = closed
    /// Notified when a connection is returned.
    cvar: Condvar,
    /// Total connections currently owned by the pool (idle + checked out).
    total: Mutex<usize>,
}

impl PoolInner {
    fn apply_pragmas(&self, conn: &SqliteConnection) -> Result<(), rusqlite::Error> {
        if self.config.enable_wal {
            // WAL is a no-op for in-memory DBs; ignore failures gracefully.
            let _: Result<String, _> = conn.query_row(
                "PRAGMA journal_mode = WAL;",
                [],
                |r| r.get::<_, String>(0),
            );
        }
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(
            None,
            "busy_timeout",
            i64::try_from(self.config.busy_timeout.as_millis()).unwrap_or(i64::MAX),
        )?;
        if self.config.enable_foreign_keys {
            conn.pragma_update(None, "foreign_keys", "ON")?;
        }
        Ok(())
    }

    fn open_new(&self) -> Result<SqliteConnection, DbError> {
        let conn = self.config.location.open()?;
        self.apply_pragmas(&conn)?;
        Ok(conn)
    }
}

// ---------------------------------------------------------------------------
// Database — public pool handle
// ---------------------------------------------------------------------------

/// A `SQLite` connection pool. Cheaply cloneable (`Arc` inside).
#[derive(Clone)]
pub struct Database {
    inner: Arc<PoolInner>,
}

impl Database {
    /// Open a database / connection pool with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::InvalidConfig`] if `max_size == 0`, or
    /// [`DbError::Sql`] if the first connection could not be opened.
    pub fn open(config: DbConfig) -> Result<Self, DbError> {
        if config.max_size == 0 {
            return Err(DbError::InvalidConfig("max_size must be >= 1".into()));
        }
        let inner = Arc::new(PoolInner {
            config,
            idle: Mutex::new(Some(Vec::new())),
            cvar: Condvar::new(),
            total: Mutex::new(0),
        });
        // Pre-warm one connection so configuration errors surface immediately.
        let conn = inner.open_new()?;
        {
            let mut idle = inner.idle.lock();
            if let Some(v) = idle.as_mut() {
                v.push(conn);
            }
            drop(idle);
            let mut total = inner.total.lock();
            *total = 1;
        }
        Ok(Self { inner })
    }

    /// Convenience constructor for an in-memory database (single connection).
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Sql`] if `SQLite` refuses to open the in-memory DB.
    pub fn open_in_memory() -> Result<Self, DbError> {
        Self::open(DbConfig::memory())
    }

    /// Convenience constructor for an on-disk database at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Sql`] if the file cannot be opened or created.
    pub fn open_file(path: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open(DbConfig::file(path.as_ref().to_path_buf()))
    }

    /// Maximum number of concurrent connections.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.inner.config.max_size
    }

    /// Number of currently checked-out connections.
    #[must_use]
    pub fn checked_out(&self) -> usize {
        let total = *self.inner.total.lock();
        let idle = self
            .inner
            .idle
            .lock()
            .as_ref()
            .map_or(0, std::vec::Vec::len);
        total.saturating_sub(idle)
    }

    /// Acquire a connection from the pool, blocking up to
    /// `config.acquire_timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::AcquireTimeout`] if no connection becomes available
    /// in time, [`DbError::Closed`] if the pool was shut down, or
    /// [`DbError::Sql`] if a new connection had to be opened and failed.
    pub fn acquire(&self) -> Result<Connection, DbError> {
        let deadline = Instant::now() + self.inner.config.acquire_timeout;
        let mut idle_guard = self.inner.idle.lock();
        loop {
            // Closed?
            let Some(idle) = idle_guard.as_mut() else {
                return Err(DbError::Closed);
            };
            if let Some(conn) = idle.pop() {
                return Ok(Connection::new(conn, self.inner.clone()));
            }
            // Can we open a new one?
            {
                let mut total = self.inner.total.lock();
                if *total < self.inner.config.max_size {
                    *total += 1;
                    drop(total);
                    // Release the idle lock while opening (open can be slow).
                    drop(idle_guard);
                    match self.inner.open_new() {
                        Ok(conn) => return Ok(Connection::new(conn, self.inner.clone())),
                        Err(e) => {
                            // Roll back the reservation on failure.
                            {
                                let mut total = self.inner.total.lock();
                                *total = total.saturating_sub(1);
                            }
                            return Err(e);
                        }
                    }
                }
            }
            // Wait for a connection to be returned.
            let now = Instant::now();
            if now >= deadline {
                return Err(DbError::AcquireTimeout(self.inner.config.acquire_timeout));
            }
            let timeout = deadline - now;
            let result = self.inner.cvar.wait_for(&mut idle_guard, timeout);
            if result.timed_out()
                && idle_guard.as_ref().is_some_and(std::vec::Vec::is_empty)
            {
                return Err(DbError::AcquireTimeout(self.inner.config.acquire_timeout));
            }
        }
    }

    /// Close the pool. Any outstanding connections are dropped when their
    /// holders go out of scope; further `acquire()` calls return
    /// [`DbError::Closed`].
    pub fn close(&self) {
        {
            let mut idle = self.inner.idle.lock();
            if let Some(v) = idle.take() {
                // Explicitly drop all idle connections.
                drop(v);
            }
        }
        self.inner.cvar.notify_all();
    }
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("max_size", &self.inner.config.max_size)
            .field("checked_out", &self.checked_out())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Connection — RAII checkout
// ---------------------------------------------------------------------------

/// An owned, checked-out `SQLite` connection. Returned to the pool on drop.
pub struct Connection {
    conn: Option<SqliteConnection>,
    pool: Arc<PoolInner>,
}

impl Connection {
    const fn new(conn: SqliteConnection, pool: Arc<PoolInner>) -> Self {
        Self {
            conn: Some(conn),
            pool,
        }
    }

    /// Borrow the underlying `rusqlite::Connection`.
    ///
    /// # Panics
    ///
    /// Panics if the connection has already been returned to the pool (only possible during `Drop`).
    #[must_use]
    pub const fn raw(&self) -> &SqliteConnection {
        // Safe: `conn` is only `None` after `Drop`.
        self.conn.as_ref().expect("connection already returned")
    }

    /// Mutably borrow the underlying `rusqlite::Connection`.
    ///
    /// # Panics
    ///
    /// Panics if the connection has already been returned to the pool (only possible during `Drop`).
    pub const fn raw_mut(&mut self) -> &mut SqliteConnection {
        self.conn.as_mut().expect("connection already returned")
    }

    /// Begin a transaction. Commit by calling [`Transaction::commit`];
    /// drop without committing to roll back.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Sql`] if `BEGIN` fails.
    pub fn transaction(&mut self) -> Result<Transaction<'_>, DbError> {
        let conn = self.raw_mut();
        conn.execute_batch("BEGIN DEFERRED;")?;
        Ok(Transaction {
            conn: Some(conn),
            done: false,
        })
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let mut idle = self.pool.idle.lock();
            if let Some(v) = idle.as_mut() {
                v.push(conn);
                self.pool.cvar.notify_one();
            } else {
                // Pool closed; drop the connection and decrement total.
                drop(conn);
                let mut total = self.pool.total.lock();
                *total = total.saturating_sub(1);
            }
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("open", &self.conn.is_some())
            .field("pool_total", &*self.pool.total.lock())
            .finish()
    }
}

impl std::ops::Deref for Connection {
    type Target = SqliteConnection;
    fn deref(&self) -> &Self::Target {
        self.raw()
    }
}

impl std::ops::DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.raw_mut()
    }
}

// ---------------------------------------------------------------------------
// Transaction — RAII manual transaction
// ---------------------------------------------------------------------------

/// A manual transaction. Drop without calling [`Self::commit`] to roll back.
pub struct Transaction<'c> {
    conn: Option<&'c mut SqliteConnection>,
    done: bool,
}

impl Transaction<'_> {
    /// Borrow the underlying connection.
    ///
    /// # Panics
    ///
    /// Panics if the transaction has already been committed or rolled back.
    #[must_use]
    pub const fn raw(&self) -> &SqliteConnection {
        self.conn.as_ref().expect("transaction already finished")
    }

    /// Mutably borrow the underlying connection.
    ///
    /// # Panics
    ///
    /// Panics if the transaction has already been committed or rolled back.
    pub const fn raw_mut(&mut self) -> &mut SqliteConnection {
        self.conn.as_mut().expect("transaction already finished")
    }

    /// Commit the transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Sql`] if `COMMIT` fails. On failure the
    /// transaction state is left to `SQLite`'s default behavior.
    pub fn commit(mut self) -> Result<(), DbError> {
        if let Some(conn) = self.conn.take() {
            conn.execute_batch("COMMIT;")?;
        }
        self.done = true;
        Ok(())
    }

    /// Explicitly roll back the transaction.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Sql`] if `ROLLBACK` fails.
    pub fn rollback(mut self) -> Result<(), DbError> {
        if let Some(conn) = self.conn.take() {
            conn.execute_batch("ROLLBACK;")?;
        }
        self.done = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done
            && let Some(conn) = self.conn.take() {
                let _ = conn.execute_batch("ROLLBACK;");
            }
    }
}

impl std::ops::Deref for Transaction<'_> {
    type Target = SqliteConnection;
    fn deref(&self) -> &Self::Target {
        self.raw()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_works() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.max_size(), 1);
    }

    #[test]
    fn acquire_returns_connection() {
        let db = Database::open_in_memory().unwrap();
        let c = db.acquire().unwrap();
        c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
    }

    #[test]
    fn transaction_commits() {
        let db = Database::open_in_memory().unwrap();
        let mut c = db.acquire().unwrap();
        c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        let tx = c.transaction().unwrap();
        tx.execute("INSERT INTO t (id) VALUES (1);", []).unwrap();
        tx.commit().unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM t;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn transaction_rolls_back_on_drop() {
        let db = Database::open_in_memory().unwrap();
        let mut c = db.acquire().unwrap();
        c.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        {
            let tx = c.transaction().unwrap();
            tx.execute("INSERT INTO t (id) VALUES (1);", []).unwrap();
            // drop without commit
        }
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM t;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn pool_returns_connection_on_drop() {
        let db = Database::open(DbConfig {
            location: DbLocation::File(std::env::temp_dir().join(format!(
                "rustre-db-test-{}.sqlite",
                uuid::Uuid::new_v4()
            ))),
            max_size: 2,
            ..DbConfig::defaults()
        })
        .unwrap();
        {
            let _c1 = db.acquire().unwrap();
            let _c2 = db.acquire().unwrap();
            assert_eq!(db.checked_out(), 2);
        }
        assert_eq!(db.checked_out(), 0);
    }

    #[test]
    fn acquire_timeout_fires() {
        let path = std::env::temp_dir().join(format!(
            "rustre-db-timeout-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let db = Database::open(DbConfig {
            location: DbLocation::File(path),
            max_size: 1,
            acquire_timeout: Duration::from_millis(50),
            ..DbConfig::defaults()
        })
        .unwrap();
        let _held = db.acquire().unwrap();
        let err = db.acquire().unwrap_err();
        assert!(matches!(err, DbError::AcquireTimeout(_)));
    }
}
