//! `SQLite` + `MySQL` dual-backend cache for Malpedia families and actors.

use mysql::params;
use mysql::prelude::Queryable;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::sync::Arc;

use crate::error::MalpediaError;
use crate::models::{MalpediaActor, MalpediaFamily};

/// Dual-backend Malpedia cache.
pub struct MalpediaCache {
    sqlite: Arc<Mutex<Connection>>,
    mysql_pool: Option<mysql::Pool>,
}

impl MalpediaCache {
    /// Open cache backed only by `SQLite`.
    ///
    /// # Errors
    /// Returns an error if the `SQLite` database cannot be opened or initialised.
    pub fn open_sqlite(path: &str) -> Result<Self, MalpediaError> {
        Self::open(path, None)
    }

    /// Open with optional `MySQL` mirror.
    ///
    /// # Errors
    /// Returns an error if either backend cannot be opened or initialised.
    pub fn open(sqlite_path: &str, mysql_url: Option<&str>) -> Result<Self, MalpediaError> {
        let conn = Connection::open(sqlite_path)?;
        Self::init_sqlite(&conn)?;
        let mysql_pool = mysql_url.map(mysql::Pool::new).transpose()?;
        if let Some(ref pool) = mysql_pool {
            Self::init_mysql(pool)?;
        }
        Ok(Self {
            sqlite: Arc::new(Mutex::new(conn)),
            mysql_pool,
        })
    }

    /// Execute a closure with an exclusive reference to the `SQLite` connection,
    /// releasing the lock immediately on return.
    fn with_sqlite<T, F>(&self, f: F) -> Result<T, MalpediaError>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    {
        let conn = self.sqlite.lock();
        f(&conn).map_err(MalpediaError::from)
    }

    fn init_sqlite(conn: &Connection) -> Result<(), MalpediaError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS malpedia_families (
                malpedia_name TEXT PRIMARY KEY,
                family_json   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS malpedia_actors (
                name        TEXT PRIMARY KEY,
                actor_json  TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    fn init_mysql(pool: &mysql::Pool) -> Result<(), MalpediaError> {
        let mut conn = pool.get_conn()?;
        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS malpedia_families (
                malpedia_name VARCHAR(128) PRIMARY KEY,
                family_json   LONGTEXT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        )?;
        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS malpedia_actors (
                name        VARCHAR(128) PRIMARY KEY,
                actor_json  LONGTEXT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Families
    // -----------------------------------------------------------------------

    /// # Errors
    /// Returns an error if serialisation or a database write fails.
    pub fn put_family(&self, family: &MalpediaFamily) -> Result<(), MalpediaError> {
        let json = serde_json::to_string(family)?;
        {
            let conn = self.sqlite.lock();
            conn.execute(
                "INSERT INTO malpedia_families (malpedia_name, family_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(malpedia_name) DO UPDATE SET family_json = excluded.family_json",
                rusqlite::params![family.malpedia_name, json],
            )?;
        }
        if let Some(ref pool) = self.mysql_pool {
            let mut conn = pool.get_conn()?;
            conn.exec_drop(
                "INSERT INTO malpedia_families (malpedia_name, family_json)
                 VALUES (:n, :j)
                 ON DUPLICATE KEY UPDATE family_json = VALUES(family_json)",
                params! { "n" => &family.malpedia_name, "j" => &json },
            )?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the database query or deserialisation fails.
    pub fn get_family(&self, name: &str) -> Result<Option<MalpediaFamily>, MalpediaError> {
        let json: Option<String> = self.with_sqlite(|conn| {
            let mut stmt = conn.prepare(
                "SELECT family_json FROM malpedia_families WHERE malpedia_name = ?1",
            )?;
            let mut rows = stmt.query(rusqlite::params![name])?;
            rows.next()?.map(|row| row.get(0)).transpose()
        })?;
        json.map(|j| serde_json::from_str(&j).map_err(MalpediaError::from))
            .transpose()
    }

    /// # Errors
    /// Returns an error if the database query or deserialisation fails.
    pub fn list_families(&self) -> Result<Vec<MalpediaFamily>, MalpediaError> {
        let jsons: Vec<String> = self.with_sqlite(|conn| {
            let mut stmt = conn.prepare("SELECT family_json FROM malpedia_families")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<_, _>>()
        })?;
        jsons
            .iter()
            .map(|j| serde_json::from_str(j).map_err(MalpediaError::from))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Actors
    // -----------------------------------------------------------------------

    /// # Errors
    /// Returns an error if serialisation or a database write fails.
    pub fn put_actor(&self, actor: &MalpediaActor) -> Result<(), MalpediaError> {
        let json = serde_json::to_string(actor)?;
        {
            let conn = self.sqlite.lock();
            conn.execute(
                "INSERT INTO malpedia_actors (name, actor_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET actor_json = excluded.actor_json",
                rusqlite::params![actor.name, json],
            )?;
        }
        if let Some(ref pool) = self.mysql_pool {
            let mut conn = pool.get_conn()?;
            conn.exec_drop(
                "INSERT INTO malpedia_actors (name, actor_json)
                 VALUES (:n, :j)
                 ON DUPLICATE KEY UPDATE actor_json = VALUES(actor_json)",
                params! { "n" => &actor.name, "j" => &json },
            )?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the database query or deserialisation fails.
    pub fn get_actor(&self, name: &str) -> Result<Option<MalpediaActor>, MalpediaError> {
        let json: Option<String> = self.with_sqlite(|conn| {
            let mut stmt =
                conn.prepare("SELECT actor_json FROM malpedia_actors WHERE name = ?1")?;
            let mut rows = stmt.query(rusqlite::params![name])?;
            rows.next()?.map(|row| row.get(0)).transpose()
        })?;
        json.map(|j| serde_json::from_str(&j).map_err(MalpediaError::from))
            .transpose()
    }

    /// # Errors
    /// Returns an error if the database query or deserialisation fails.
    pub fn list_actors(&self) -> Result<Vec<MalpediaActor>, MalpediaError> {
        let jsons: Vec<String> = self.with_sqlite(|conn| {
            let mut stmt = conn.prepare("SELECT actor_json FROM malpedia_actors")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<_, _>>()
        })?;
        jsons
            .iter()
            .map(|j| serde_json::from_str(j).map_err(MalpediaError::from))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{MalpediaFamily, MalpediaSample};

    fn mem_cache() -> MalpediaCache {
        MalpediaCache::open(":memory:", None).unwrap()
    }

    #[test]
    fn test_family_roundtrip() {
        let cache = mem_cache();
        let mut fam = MalpediaFamily::new("win.emotet", "Emotet");
        fam.samples
            .push(MalpediaSample::new("abc", "active", "1.0"));
        cache.put_family(&fam).unwrap();
        let fetched = cache.get_family("win.emotet").unwrap().unwrap();
        assert_eq!(fetched.common_name, "Emotet");
        assert_eq!(fetched.samples.len(), 1);
    }

    #[test]
    fn test_family_not_found() {
        let cache = mem_cache();
        let result = cache.get_family("win.nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_list_families() {
        let cache = mem_cache();
        cache
            .put_family(&MalpediaFamily::new("win.a", "A"))
            .unwrap();
        cache
            .put_family(&MalpediaFamily::new("win.b", "B"))
            .unwrap();
        let all = cache.list_families().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_actor_roundtrip() {
        let cache = mem_cache();
        let mut actor = MalpediaActor::new("Lazarus", "KP");
        actor.families = vec!["win.lazarus".to_string()];
        cache.put_actor(&actor).unwrap();
        let fetched = cache.get_actor("Lazarus").unwrap().unwrap();
        assert_eq!(fetched.country, "KP");
        assert_eq!(fetched.families, vec!["win.lazarus"]);
    }

    #[test]
    fn test_list_actors() {
        let cache = mem_cache();
        cache.put_actor(&MalpediaActor::new("APT29", "RU")).unwrap();
        cache
            .put_actor(&MalpediaActor::new("Lazarus", "KP"))
            .unwrap();
        let all = cache.list_actors().unwrap();
        assert_eq!(all.len(), 2);
    }
}
