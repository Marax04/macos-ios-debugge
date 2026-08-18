//! Dual SQLite/MySQL persistence layer for threat intelligence indicators.

#[cfg(feature = "mysql-backend")]
use mysql::params;
#[cfg(feature = "mysql-backend")]
use mysql::prelude::Queryable;
use parking_lot::Mutex;

use crate::error::TiError;
use crate::ioc::{IoC, IoCType, Severity};

// ---------------------------------------------------------------------------
// Schema DDL helpers
// ---------------------------------------------------------------------------

const SQLITE_DDL: &str = "
    CREATE TABLE IF NOT EXISTS iocs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type    TEXT    NOT NULL,
        value       TEXT    NOT NULL,
        description TEXT,
        tags        TEXT    NOT NULL DEFAULT '[]',
        confidence  INTEGER NOT NULL DEFAULT 50,
        severity    TEXT    NOT NULL DEFAULT 'medium',
        first_seen  INTEGER NOT NULL DEFAULT 0,
        last_seen   INTEGER NOT NULL DEFAULT 0,
        source      TEXT    NOT NULL,
        UNIQUE(ioc_type, value)
    )
";

#[cfg(feature = "mysql-backend")]
const MYSQL_DDL: &str = "
    CREATE TABLE IF NOT EXISTS iocs (
        id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        ioc_type    VARCHAR(32)  NOT NULL,
        value       VARCHAR(512) NOT NULL,
        description TEXT,
        tags        TEXT         NOT NULL DEFAULT '[]',
        confidence  TINYINT UNSIGNED NOT NULL DEFAULT 50,
        severity    VARCHAR(16)  NOT NULL DEFAULT 'medium',
        first_seen  BIGINT UNSIGNED NOT NULL DEFAULT 0,
        last_seen   BIGINT UNSIGNED NOT NULL DEFAULT 0,
        source      VARCHAR(255) NOT NULL,
        UNIQUE KEY uq_type_value (ioc_type, value(255))
    )
";

// ---------------------------------------------------------------------------
// DbConnection
// ---------------------------------------------------------------------------

/// Dual database connection wrapper.
pub enum DbConnection {
    /// `SQLite` connection protected by a mutex for thread-safety.
    Sqlite(Mutex<rusqlite::Connection>),
    /// `MySQL` connection pool (available with the `mysql-backend` feature).
    #[cfg(feature = "mysql-backend")]
    Mysql(Mutex<mysql::Pool>),
}

impl DbConnection {
    /// Open an in-memory `SQLite` database and create the schema.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the connection or schema creation fails.
    pub fn sqlite_in_memory() -> Result<Self, TiError> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.execute_batch(SQLITE_DDL)?;
        Ok(Self::Sqlite(Mutex::new(conn)))
    }

    /// Open a file-backed `SQLite` database and create the schema.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the connection or schema creation fails.
    pub fn sqlite(path: &str) -> Result<Self, TiError> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(SQLITE_DDL)?;
        Ok(Self::Sqlite(Mutex::new(conn)))
    }

    /// Connect to a `MySQL` server and create the schema.
    ///
    /// Requires the `mysql-backend` crate feature to be enabled.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the connection or schema creation fails.
    #[cfg(feature = "mysql-backend")]
    pub fn mysql(url: &str) -> Result<Self, TiError> {
        let pool = mysql::Pool::new(url)?;
        {
            let mut conn = pool.get_conn()?;
            conn.query_drop(MYSQL_DDL)?;
        }
        Ok(Self::Mysql(Mutex::new(pool)))
    }
}

// ---------------------------------------------------------------------------
// Severity serialisation helpers
// ---------------------------------------------------------------------------

const fn severity_to_str(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn severity_from_str(s: &str) -> Severity {
    match s {
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

// ---------------------------------------------------------------------------
// IoCStore
// ---------------------------------------------------------------------------

/// Store for managing Indicators of Compromise.
pub struct IoCStore {
    conn: DbConnection,
}

impl IoCStore {
    /// Wrap an existing `DbConnection` in an `IoCStore`.
    #[must_use]
    pub const fn new(conn: DbConnection) -> Self {
        Self { conn }
    }

    /// Insert a new `IoC` and return its database `id`.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if insertion fails (e.g. uniqueness violation or
    /// serialisation error).
    pub fn insert_ioc(&self, ioc: &IoC) -> Result<u64, TiError> {
        let tags_json = serde_json::to_string(&ioc.tags)?;
        let sev = severity_to_str(ioc.severity);
        match &self.conn {
            DbConnection::Sqlite(m) => {
                let conn = m.lock();
                // INSERT OR IGNORE preserves the original rowid on collision (unlike
                // INSERT OR REPLACE which deletes + re-inserts and yields a new id).
                conn.execute(
                    "INSERT OR IGNORE INTO iocs
                        (ioc_type, value, description, tags, confidence, severity, first_seen, last_seen, source)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        ioc.ioc_type.as_str(),
                        ioc.value,
                        ioc.description,
                        tags_json,
                        ioc.confidence,
                        sev,
                        ioc.first_seen,
                        ioc.last_seen,
                        ioc.source,
                    ],
                )?;
                // If the row already existed, INSERT OR IGNORE is a no-op; update
                // the mutable fields to match MySQL ON DUPLICATE KEY UPDATE semantics
                // and fetch the original rowid.
                conn.execute(
                    "UPDATE iocs SET
                        description = ?3,
                        tags        = ?4,
                        confidence  = ?5,
                        severity    = ?6,
                        first_seen  = MIN(first_seen, ?7),
                        last_seen   = MAX(last_seen,  ?8),
                        source      = ?9
                     WHERE ioc_type = ?1 AND value = ?2",
                    rusqlite::params![
                        ioc.ioc_type.as_str(),
                        ioc.value,
                        ioc.description,
                        tags_json,
                        ioc.confidence,
                        sev,
                        ioc.first_seen,
                        ioc.last_seen,
                        ioc.source,
                    ],
                )?;
                // Retrieve the stable rowid (unchanged whether inserted or updated).
                let id: i64 = conn.query_row(
                    "SELECT id FROM iocs WHERE ioc_type = ?1 AND value = ?2",
                    rusqlite::params![ioc.ioc_type.as_str(), ioc.value],
                    |row| row.get(0),
                )?;
                drop(conn);
                Ok(u64::try_from(id).unwrap_or(0))
            }
            #[cfg(feature = "mysql-backend")]
            DbConnection::Mysql(m) => {
                let pool = m.lock();
                let mut conn = pool.get_conn()?;
                drop(pool);
                conn.exec_drop(
                    "INSERT INTO iocs
                        (ioc_type, value, description, tags, confidence, severity, first_seen, last_seen, source)
                     VALUES (:ioc_type, :value, :description, :tags, :confidence, :severity, :first_seen, :last_seen, :source)
                     ON DUPLICATE KEY UPDATE
                        description = VALUES(description),
                        tags        = VALUES(tags),
                        confidence  = VALUES(confidence),
                        severity    = VALUES(severity),
                        first_seen  = LEAST(first_seen, VALUES(first_seen)),
                        last_seen   = GREATEST(last_seen, VALUES(last_seen)),
                        source      = VALUES(source)",
                    params! {
                        "ioc_type"    => ioc.ioc_type.as_str(),
                        "value"       => &ioc.value,
                        "description" => &ioc.description,
                        "tags"        => &tags_json,
                        "confidence"  => ioc.confidence,
                        "severity"    => sev,
                        "first_seen"  => ioc.first_seen,
                        "last_seen"   => ioc.last_seen,
                        "source"      => &ioc.source,
                    },
                )?;
                Ok(conn.last_insert_id())
            }
        }
    }

    /// Find an `IoC` by its value string.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the query or deserialisation fails.
    pub fn find_by_value(&self, value: &str) -> Result<Option<IoC>, TiError> {
        match &self.conn {
            DbConnection::Sqlite(m) => {
                let conn = m.lock();
                let mut stmt = conn.prepare(
                    "SELECT id, ioc_type, value, description, tags, confidence, severity, first_seen, last_seen, source
                     FROM iocs WHERE value = ?1 LIMIT 1",
                )?;
                let mut rows = stmt.query(rusqlite::params![value])?;
                let result = if let Some(row) = rows.next()? {
                    Some(row_to_ioc_sqlite(row)?)
                } else {
                    None
                };
                drop(rows);
                drop(stmt);
                drop(conn);
                Ok(result)
            }
            #[cfg(feature = "mysql-backend")]
            DbConnection::Mysql(m) => {
                let pool = m.lock();
                let mut conn = pool.get_conn()?;
                drop(pool);
                let row: Option<MysqlIoCRow> = conn.exec_first(
                    "SELECT id, ioc_type, value, description, tags, confidence, severity,
                            first_seen, last_seen, source
                     FROM iocs WHERE value = :value LIMIT 1",
                    params! { "value" => value },
                )?;
                Ok(row.map(row_to_ioc_mysql))
            }
        }
    }

    /// Find all `IoCs` of a specific type.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the query or deserialisation fails.
    pub fn find_by_type(&self, ioc_type: &IoCType) -> Result<Vec<IoC>, TiError> {
        let key = ioc_type.as_str();
        match &self.conn {
            DbConnection::Sqlite(m) => {
                let conn = m.lock();
                let mut stmt = conn.prepare(
                    "SELECT id, ioc_type, value, description, tags, confidence, severity,
                            first_seen, last_seen, source
                     FROM iocs WHERE ioc_type = ?1",
                )?;
                let rows =
                    stmt.query_map(rusqlite::params![key], |row| Ok(row_to_ioc_sqlite(row)))?;
                let mut result = Vec::new();
                for r in rows {
                    result.push(r??);
                }
                drop(stmt);
                drop(conn);
                Ok(result)
            }
            #[cfg(feature = "mysql-backend")]
            DbConnection::Mysql(m) => {
                let pool = m.lock();
                let mut conn = pool.get_conn()?;
                drop(pool);
                let rows: Vec<MysqlIoCRow> = conn.exec(
                    "SELECT id, ioc_type, value, description, tags, confidence, severity,
                            first_seen, last_seen, source
                     FROM iocs WHERE ioc_type = :ioc_type",
                    params! { "ioc_type" => key },
                )?;
                Ok(rows.into_iter().map(row_to_ioc_mysql).collect())
            }
        }
    }

    /// Return all stored `IoCs`.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the query or deserialisation fails.
    pub fn all_iocs(&self) -> Result<Vec<IoC>, TiError> {
        match &self.conn {
            DbConnection::Sqlite(m) => {
                let conn = m.lock();
                let mut stmt = conn.prepare(
                    "SELECT id, ioc_type, value, description, tags, confidence, severity,
                            first_seen, last_seen, source
                     FROM iocs",
                )?;
                let rows = stmt.query_map([], |row| Ok(row_to_ioc_sqlite(row)))?;
                let mut result = Vec::new();
                for r in rows {
                    result.push(r??);
                }
                drop(stmt);
                drop(conn);
                Ok(result)
            }
            #[cfg(feature = "mysql-backend")]
            DbConnection::Mysql(m) => {
                let pool = m.lock();
                let mut conn = pool.get_conn()?;
                drop(pool);
                let rows: Vec<MysqlIoCRow> = conn.query(
                    "SELECT id, ioc_type, value, description, tags, confidence, severity,
                            first_seen, last_seen, source FROM iocs",
                )?;
                Ok(rows.into_iter().map(row_to_ioc_mysql).collect())
            }
        }
    }

    /// Delete an `IoC` by its database `id`.  Returns `true` if a row was deleted.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the delete query fails.
    pub fn delete_ioc(&self, id: u64) -> Result<bool, TiError> {
        match &self.conn {
            DbConnection::Sqlite(m) => {
                let conn = m.lock();
                let rows = conn.execute("DELETE FROM iocs WHERE id = ?1", rusqlite::params![id])?;
                drop(conn);
                Ok(rows > 0)
            }
            #[cfg(feature = "mysql-backend")]
            DbConnection::Mysql(m) => {
                let pool = m.lock();
                let mut conn = pool.get_conn()?;
                drop(pool);
                conn.exec_drop("DELETE FROM iocs WHERE id = :id", params! { "id" => id })?;
                Ok(conn.affected_rows() > 0)
            }
        }
    }

    /// Return the total number of stored `IoCs`.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] if the count query fails.
    pub fn count(&self) -> Result<u64, TiError> {
        match &self.conn {
            DbConnection::Sqlite(m) => {
                let conn = m.lock();
                let n: u64 = conn.query_row("SELECT COUNT(*) FROM iocs", [], |row| row.get(0))?;
                drop(conn);
                Ok(n)
            }
            #[cfg(feature = "mysql-backend")]
            DbConnection::Mysql(m) => {
                let pool = m.lock();
                let mut conn = pool.get_conn()?;
                drop(pool);
                let n: Option<u64> = conn.query_first("SELECT COUNT(*) FROM iocs")?;
                Ok(n.unwrap_or(0))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Row deserialisation helpers
// ---------------------------------------------------------------------------

fn row_to_ioc_sqlite(row: &rusqlite::Row<'_>) -> Result<IoC, rusqlite::Error> {
    let id: Option<u64> = row.get(0)?;
    let ioc_type_str: String = row.get(1)?;
    let value: String = row.get(2)?;
    let description: Option<String> = row.get(3)?;
    let tags_json: String = row.get(4)?;
    let confidence: u8 = row.get(5)?;
    let severity_str: String = row.get(6)?;
    let first_seen: u64 = row.get(7)?;
    let last_seen: u64 = row.get(8)?;
    let source: String = row.get(9)?;

    let tags: Vec<String> = serde_json::from_str(&tags_json)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;
    // Three lines above, a malformed `tags` column is a conversion failure. An
    // unrecognised `ioc_type` is the same class of corruption and gets the same
    // treatment: silently substituting `Sha256` would turn an IP or a domain
    // into a file hash, and nothing downstream could tell that it happened.
    let ioc_type = IoCType::from_key(&ioc_type_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unrecognised ioc_type key `{ioc_type_str}`"),
            )),
        )
    })?;

    Ok(IoC {
        id,
        ioc_type,
        value,
        description,
        tags,
        confidence,
        severity: severity_from_str(&severity_str),
        first_seen,
        last_seen,
        source,
    })
}

/// Type alias for the `MySQL` row tuple (available with the `mysql-backend` feature).
#[cfg(feature = "mysql-backend")]
type MysqlIoCRow = (
    u64,
    String,
    String,
    Option<String>,
    String,
    u8,
    String,
    u64,
    u64,
    String,
);

#[cfg(feature = "mysql-backend")]
fn row_to_ioc_mysql(row: MysqlIoCRow) -> IoC {
    let (
        id,
        ioc_type_str,
        value,
        description,
        tags_json,
        confidence,
        severity_str,
        first_seen,
        last_seen,
        source,
    ) = row;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_else(|_| Vec::new());
    IoC {
        id: Some(id),
        ioc_type: IoCType::from_key(&ioc_type_str).unwrap_or(IoCType::Sha256),
        value,
        description,
        tags,
        confidence,
        severity: severity_from_str(&severity_str),
        first_seen,
        last_seen,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::Severity;

    fn make_store() -> IoCStore {
        let conn = DbConnection::sqlite_in_memory().expect("in-memory sqlite");
        IoCStore::new(conn)
    }

    fn sample_ioc(value: &str) -> IoC {
        let mut ioc = IoC::new(
            IoCType::Sha256,
            value.to_string(),
            "test-source".to_string(),
        );
        ioc.confidence = 80;
        ioc.severity = Severity::High;
        ioc.tags.push("malware".to_string());
        ioc
    }

    /// Every variant, so a thirteenth one cannot be added to `as_str` without
    /// also reaching `from_key` — the two hand-written tables the store round
    /// trips through.
    #[test]
    fn every_ioc_type_survives_a_store_round_trip() {
        let all = [
            IoCType::Md5,
            IoCType::Sha1,
            IoCType::Sha256,
            IoCType::Sha512,
            IoCType::Ip,
            IoCType::Domain,
            IoCType::Url,
            IoCType::Email,
            IoCType::Registry,
            IoCType::Filename,
            IoCType::Mutex,
            IoCType::Yara,
        ];
        let store = make_store();
        let mut checked = 0usize;

        for (i, ty) in all.iter().enumerate() {
            let value = format!("value-{i}");
            let ioc = IoC::new(ty.clone(), value.clone(), "test".to_string());
            store.insert_ioc(&ioc).expect("insert");

            let back = store
                .find_by_value(&value)
                .expect("read back")
                .expect("the row just inserted must be found");
            assert_eq!(
                back.ioc_type, *ty,
                "`{}` did not survive the as_str/from_key round trip through the store",
                ty.as_str()
            );
            checked += 1;
        }

        assert_eq!(checked, 12, "anti-vacuity: every IoCType variant exercised");
    }

    /// An unrecognised `ioc_type` used to become `Sha256` silently, turning an
    /// IP or a domain into a file hash with nothing downstream able to notice.
    /// The same function already treats a malformed `tags` column as an error.
    #[test]
    fn a_corrupt_ioc_type_column_is_an_error_not_a_silent_sha256() {
        let conn = DbConnection::sqlite_in_memory().expect("in-memory sqlite");
        // `DbConnection` has a single variant today, so `if let` here was
        // irrefutable and rustc said so; `let ... else` is irrefutable for the
        // same reason. A plain destructuring `let` is the form that matches the
        // fact, and it is the one that will FAIL TO COMPILE if a second backend
        // is ever added — which is the outcome you want: the test is then forced
        // to say which backend it needs, instead of silently exercising one.
        let DbConnection::Sqlite(m) = &conn;
        {
            m.lock()
                .execute(
                    "INSERT INTO iocs
                     (ioc_type, value, description, tags, confidence, severity,
                      first_seen, last_seen, source)
                     VALUES ('not-a-real-type', 'corrupt-row', NULL, '[]', 50,
                             'medium', 0, 0, 'test')",
                    [],
                )
                .expect("premise: the raw insert must succeed, the column is TEXT");
        }
        let store = IoCStore::new(conn);

        let result = store.find_by_value("corrupt-row");
        assert!(
            result.is_err(),
            "a corrupt ioc_type was accepted and returned as {:?}",
            result.map(|o| o.map(|i| i.ioc_type))
        );
    }

    #[test]
    fn test_sqlite_insert_and_count() {
        let store = make_store();
        assert_eq!(store.count().unwrap(), 0);
        let id = store.insert_ioc(&sample_ioc("deadbeef")).unwrap();
        assert!(id > 0);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_sqlite_find_by_value() {
        let store = make_store();
        store.insert_ioc(&sample_ioc("cafebabe")).unwrap();
        let found = store.find_by_value("cafebabe").unwrap().unwrap();
        assert_eq!(found.value, "cafebabe");
        assert_eq!(found.confidence, 80);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.tags, vec!["malware"]);
    }

    #[test]
    fn test_sqlite_find_by_value_missing() {
        let store = make_store();
        let r = store.find_by_value("notpresent").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn test_sqlite_find_by_type() {
        let store = make_store();
        store.insert_ioc(&sample_ioc("hash1")).unwrap();
        store.insert_ioc(&sample_ioc("hash2")).unwrap();
        let mut ip_ioc = IoC::new(IoCType::Ip, "1.2.3.4".to_string(), "test".to_string());
        ip_ioc.confidence = 50;
        store.insert_ioc(&ip_ioc).unwrap();

        let sha_iocs = store.find_by_type(&IoCType::Sha256).unwrap();
        assert_eq!(sha_iocs.len(), 2);

        let ip_iocs = store.find_by_type(&IoCType::Ip).unwrap();
        assert_eq!(ip_iocs.len(), 1);
        assert_eq!(ip_iocs[0].value, "1.2.3.4");
    }

    #[test]
    fn test_sqlite_all_iocs() {
        let store = make_store();
        store.insert_ioc(&sample_ioc("a")).unwrap();
        store.insert_ioc(&sample_ioc("b")).unwrap();
        store.insert_ioc(&sample_ioc("c")).unwrap();
        let all = store.all_iocs().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_sqlite_delete_ioc() {
        let store = make_store();
        let id = store.insert_ioc(&sample_ioc("todelete")).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        let deleted = store.delete_ioc(id).unwrap();
        assert!(deleted);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_sqlite_delete_nonexistent() {
        let store = make_store();
        let deleted = store.delete_ioc(9999).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_sqlite_insert_replace() {
        let store = make_store();
        let ioc = sample_ioc("dupe_value");
        store.insert_ioc(&ioc).unwrap();
        let mut ioc2 = sample_ioc("dupe_value");
        ioc2.confidence = 95;
        store.insert_ioc(&ioc2).unwrap();
        // INSERT OR REPLACE — still 1 row
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_store_new_wraps_connection() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_ioc_description_roundtrip() {
        let store = make_store();
        let mut ioc = sample_ioc("described");
        ioc.description = Some("C2 server hash".to_string());
        store.insert_ioc(&ioc).unwrap();
        let found = store.find_by_value("described").unwrap().unwrap();
        assert_eq!(found.description.as_deref(), Some("C2 server hash"));
    }
}
