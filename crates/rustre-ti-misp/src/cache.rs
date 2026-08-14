//! `SQLite` + `MySQL` dual-backend cache for MISP events.

use mysql::params;
use mysql::prelude::Queryable;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::sync::Arc;

use crate::error::MispError;
use crate::models::MispEvent;

const DEFAULT_TTL_SECS: u64 = 3600;

/// Dual-backend MISP event cache.
pub struct MispCache {
    sqlite: Arc<Mutex<Connection>>,
    mysql_pool: Option<mysql::Pool>,
    ttl_secs: u64,
}

impl MispCache {
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Open a cache backed only by `SQLite`.
    pub fn open_sqlite(path: &str) -> Result<Self, MispError> {
        Self::open(path, None, DEFAULT_TTL_SECS)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Open a cache with `SQLite` primary and optional `MySQL` mirror.
    pub fn open(
        sqlite_path: &str,
        mysql_url: Option<&str>,
        ttl_secs: u64,
    ) -> Result<Self, MispError> {
        let conn = Connection::open(sqlite_path)?;
        Self::init_sqlite(&conn)?;

        let mysql_pool = mysql_url.map(mysql::Pool::new).transpose()?;
        if let Some(ref pool) = mysql_pool {
            Self::init_mysql(pool)?;
        }

        Ok(Self {
            sqlite: Arc::new(Mutex::new(conn)),
            mysql_pool,
            ttl_secs,
        })
    }

    fn init_sqlite(conn: &Connection) -> Result<(), MispError> {
        // `uuid` is the canonical key; `event_id` is a secondary hint that may
        // be 0 (absent) for locally-created events, so we use it as a non-unique
        // index rather than the primary key.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS misp_events (
                row_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id   INTEGER,
                uuid       TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL,
                cached_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_misp_event_id ON misp_events(event_id);",
        )?;
        Ok(())
    }

    fn init_mysql(pool: &mysql::Pool) -> Result<(), MispError> {
        let mut conn = pool.get_conn()?;
        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS misp_events (
                event_id   BIGINT UNSIGNED PRIMARY KEY,
                uuid       VARCHAR(64) NOT NULL UNIQUE,
                event_json LONGTEXT    NOT NULL,
                cached_at  BIGINT UNSIGNED NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        )?;
        Ok(())
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Store an event in the cache.
    pub fn put(&self, event: &MispEvent) -> Result<(), MispError> {
        let json = serde_json::to_string(event)?;
        let now = Self::now_secs() as i64;
        let event_id = i64::try_from(event.id.unwrap_or(0)).unwrap_or(i64::MAX);

        {
            let conn = self.sqlite.lock();
            conn.execute(
                "INSERT INTO misp_events (event_id, uuid, event_json, cached_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(uuid) DO UPDATE SET event_json = excluded.event_json, cached_at = excluded.cached_at",
                rusqlite::params![event_id, event.uuid, json, now],
            )?;
        }

        if let Some(ref pool) = self.mysql_pool {
            let mut conn = pool.get_conn()?;
            conn.exec_drop(
                "INSERT INTO misp_events (event_id, uuid, event_json, cached_at)
                 VALUES (:event_id, :uuid, :event_json, :cached_at)
                 ON DUPLICATE KEY UPDATE event_json = VALUES(event_json), cached_at = VALUES(cached_at)",
                params! {
                    "event_id" => event_id,
                    "uuid" => &event.uuid,
                    "event_json" => &json,
                    "cached_at" => now,
                },
            )?;
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Retrieve an event by its numeric ID.
    pub fn get_by_id(&self, id: u64) -> Result<Option<MispEvent>, MispError> {
        let now = Self::now_secs();
        let conn = self.sqlite.lock();
        let mut stmt =
            conn.prepare("SELECT event_json, cached_at FROM misp_events WHERE event_id = ?1")?;
        let mut rows = stmt.query(rusqlite::params![i64::try_from(id).unwrap_or(i64::MAX)])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let cached_at: i64 = row.get(1)?;
            if now.saturating_sub(cached_at as u64) <= self.ttl_secs {
                let event: MispEvent = serde_json::from_str(&json)?;
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Retrieve an event by its UUID.
    pub fn get_by_uuid(&self, uuid: &str) -> Result<Option<MispEvent>, MispError> {
        let now = Self::now_secs();
        let conn = self.sqlite.lock();
        let mut stmt =
            conn.prepare("SELECT event_json, cached_at FROM misp_events WHERE uuid = ?1")?;
        let mut rows = stmt.query(rusqlite::params![uuid])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let cached_at: i64 = row.get(1)?;
            if now.saturating_sub(cached_at as u64) <= self.ttl_secs {
                let event: MispEvent = serde_json::from_str(&json)?;
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Return all cached events (within TTL).
    pub fn list(&self) -> Result<Vec<MispEvent>, MispError> {
        let now = Self::now_secs();
        let cutoff = now.saturating_sub(self.ttl_secs) as i64;
        let conn = self.sqlite.lock();
        let mut stmt = conn.prepare("SELECT event_json FROM misp_events WHERE cached_at >= ?1")?;
        let rows = stmt.query_map(rusqlite::params![cutoff], |row| row.get::<_, String>(0))?;
        let mut events = Vec::new();
        for r in rows {
            let json = r?;
            let event: MispEvent = serde_json::from_str(&json)?;
            events.push(event);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{MispAnalysis, MispDistribution, MispThreatLevel};

    fn mem_cache() -> MispCache {
        MispCache::open(":memory:", None, 3600).unwrap()
    }

    #[test]
    fn test_cache_put_and_get_by_id() {
        let cache = mem_cache();
        let mut event = MispEvent::new(
            "Test",
            MispThreatLevel::Low,
            MispAnalysis::Completed,
            MispDistribution::All,
        );
        event.id = Some(42);
        cache.put(&event).unwrap();
        let fetched = cache.get_by_id(42).unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().info, "Test");
    }

    #[test]
    fn test_cache_get_by_uuid() {
        let cache = mem_cache();
        let event = MispEvent::new(
            "UUID Test",
            MispThreatLevel::High,
            MispAnalysis::Initial,
            MispDistribution::Community,
        );
        let uuid = event.uuid.clone();
        cache.put(&event).unwrap();
        let fetched = cache.get_by_uuid(&uuid).unwrap();
        assert!(fetched.is_some());
    }

    #[test]
    fn test_cache_list() {
        let cache = mem_cache();
        let e1 = MispEvent::new(
            "E1",
            MispThreatLevel::Low,
            MispAnalysis::Initial,
            MispDistribution::All,
        );
        let e2 = MispEvent::new(
            "E2",
            MispThreatLevel::Medium,
            MispAnalysis::Ongoing,
            MispDistribution::Organization,
        );
        cache.put(&e1).unwrap();
        cache.put(&e2).unwrap();
        let all = cache.list().unwrap();
        assert_eq!(all.len(), 2);
    }
}
