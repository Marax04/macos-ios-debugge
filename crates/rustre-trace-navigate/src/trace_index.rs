//! Trace index: B-tree index of (`instruction_pointer`, time) → `trace_offset`.
//!
//! Provides fast range queries over large execution traces, incremental updates
//! as a trace streams in, and SQLite-backed persistence.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// ─── Core Types ──────────────────────────────────────────────────────────────

/// Monotonically increasing logical clock value inside a trace.
pub type TraceTime = u64;

/// Offset into the raw trace byte stream.
pub type TraceOffset = u64;

/// An instruction pointer value.
pub type Ip = u64;

/// One indexed entry in the trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Instruction pointer at this trace position.
    pub ip: Ip,
    /// Logical time (instruction count from start).
    pub time: TraceTime,
    /// Byte offset into the raw trace file/buffer.
    pub offset: TraceOffset,
    /// Optional thread id.
    pub thread_id: Option<u32>,
}

/// Range query parameters.
#[derive(Debug, Clone)]
pub struct IpTimeRange {
    pub ip_lo: Ip,
    pub ip_hi: Ip,
    pub time_lo: TraceTime,
    pub time_hi: TraceTime,
}

impl IpTimeRange {
    /// Query covering all times for a single address.
    #[must_use]
    pub const fn address(ip: Ip) -> Self {
        Self { ip_lo: ip, ip_hi: ip, time_lo: 0, time_hi: u64::MAX }
    }

    /// Query for all addresses in a range at any time.
    #[must_use]
    pub const fn address_range(lo: Ip, hi: Ip) -> Self {
        Self { ip_lo: lo, ip_hi: hi, time_lo: 0, time_hi: u64::MAX }
    }

    /// Restrict time window.
    #[must_use]
    pub const fn with_time(mut self, lo: TraceTime, hi: TraceTime) -> Self {
        self.time_lo = lo;
        self.time_hi = hi;
        self
    }
}

// ─── In-Memory Index ─────────────────────────────────────────────────────────

/// In-memory B-tree index: composite key (ip, time) → (offset, `thread_id`).
#[derive(Default)]
struct MemIndex {
    /// Primary key: (ip, time)
    by_ip_time: BTreeMap<(Ip, TraceTime), (TraceOffset, Option<u32>)>,
    /// Secondary key: time → ip (for forward/backward step without IP filter)
    by_time: BTreeMap<TraceTime, Ip>,
    /// Count of entries per IP (hot-path cache)
    ip_hit_count: BTreeMap<Ip, u64>,
    /// Total entries
    total: u64,
}

impl MemIndex {
    fn insert(&mut self, entry: &IndexEntry) {
        self.by_ip_time.insert((entry.ip, entry.time), (entry.offset, entry.thread_id));
        self.by_time.insert(entry.time, entry.ip);
        *self.ip_hit_count.entry(entry.ip).or_default() += 1;
        self.total += 1;
    }

    fn range_query(&self, q: &IpTimeRange) -> Vec<IndexEntry> {
        let lo = (q.ip_lo, q.time_lo);
        let hi = (q.ip_hi, q.time_hi);
        self.by_ip_time
            .range(lo..=hi)
            .filter(|((ip, time), _)| {
                *ip >= q.ip_lo && *ip <= q.ip_hi && *time >= q.time_lo && *time <= q.time_hi
            })
            .map(|((ip, time), (offset, tid))| IndexEntry {
                ip: *ip,
                time: *time,
                offset: *offset,
                thread_id: *tid,
            })
            .collect()
    }

    /// Find the entry at or just before the given time.
    fn entry_before(&self, time: TraceTime) -> Option<IndexEntry> {
        self.by_time
            .range(..=time)
            .next_back()
            .map(|(t, ip)| {
                let (offset, tid) = self.by_ip_time[&(*ip, *t)];
                IndexEntry { ip: *ip, time: *t, offset, thread_id: tid }
            })
    }

    /// Find the entry at or just after the given time.
    fn entry_after(&self, time: TraceTime) -> Option<IndexEntry> {
        self.by_time
            .range(time..)
            .next()
            .map(|(t, ip)| {
                let (offset, tid) = self.by_ip_time[&(*ip, *t)];
                IndexEntry { ip: *ip, time: *t, offset, thread_id: tid }
            })
    }

    /// Next visit to `ip` strictly after `after_time`.
    fn next_visit(&self, ip: Ip, after_time: TraceTime) -> Option<IndexEntry> {
        let lo = (ip, after_time.saturating_add(1));
        let hi = (ip, TraceTime::MAX);
        self.by_ip_time
            .range(lo..=hi)
            .next()
            .filter(|((i, _), _)| *i == ip)
            .map(|((i, t), (off, tid))| IndexEntry { ip: *i, time: *t, offset: *off, thread_id: *tid })
    }

    /// Previous visit to `ip` strictly before `before_time`.
    fn prev_visit(&self, ip: Ip, before_time: TraceTime) -> Option<IndexEntry> {
        if before_time == 0 {
            return None;
        }
        let hi = (ip, before_time - 1);
        self.by_ip_time
            .range((ip, 0)..=hi)
            .next_back()
            .filter(|((i, _), _)| *i == ip)
            .map(|((i, t), (off, tid))| IndexEntry { ip: *i, time: *t, offset: *off, thread_id: *tid })
    }

    /// Hot addresses sorted by visit count descending.
    fn hot_addresses(&self, limit: usize) -> Vec<(Ip, u64)> {
        let mut v: Vec<_> = self.ip_hit_count.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(limit);
        v
    }

    const fn len(&self) -> u64 {
        self.total
    }

    fn max_time(&self) -> Option<TraceTime> {
        self.by_time.keys().next_back().copied()
    }

    fn min_time(&self) -> Option<TraceTime> {
        self.by_time.keys().next().copied()
    }
}

// ─── SQLite Persistence ───────────────────────────────────────────────────────

fn open_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening trace index db at {}", path.display()))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS trace_index (
             ip      INTEGER NOT NULL,
             time    INTEGER NOT NULL,
             offset  INTEGER NOT NULL,
             tid     INTEGER,
             PRIMARY KEY (ip, time)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS idx_time ON trace_index(time);
         CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);",
    )
    .context("creating schema")?;
    Ok(conn)
}

fn load_from_db(conn: &Connection) -> Result<MemIndex> {
    let mut idx = MemIndex::default();
    let mut stmt = conn
        .prepare("SELECT ip, time, offset, tid FROM trace_index ORDER BY time")
        .context("prepare SELECT")?;
    let mut rows = stmt.query([]).context("query")?;
    while let Some(row) = rows.next().context("row")? {
        let entry = IndexEntry {
            ip: (row.get::<_, i64>(0)?).cast_unsigned(),
            time: (row.get::<_, i64>(1)?).cast_unsigned(),
            offset: (row.get::<_, i64>(2)?).cast_unsigned(),
            thread_id: row.get::<_, Option<i64>>(3)?.map(|v| u32::try_from(v).unwrap_or(0)),
        };
        idx.insert(&entry);
    }
    Ok(idx)
}

fn flush_batch_to_db(conn: &Connection, batch: &[IndexEntry]) -> Result<()> {
    let tx = conn.unchecked_transaction().context("begin tx")?;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO trace_index (ip, time, offset, tid) VALUES (?1,?2,?3,?4)",
            )
            .context("prepare insert")?;
        for e in batch {
            stmt.execute(params![
                e.ip.cast_signed(),
                e.time.cast_signed(),
                e.offset.cast_signed(),
                e.thread_id.map(i64::from),
            ])
            .context("insert entry")?;
        }
    }
    tx.commit().context("commit")?;
    Ok(())
}

// ─── TraceIndex ──────────────────────────────────────────────────────────────

/// Configuration for the trace index.
#[derive(Debug, Clone)]
pub struct TraceIndexConfig {
    /// How many pending entries to accumulate before flushing to `SQLite`.
    pub flush_batch_size: usize,
    /// Maximum in-memory entries before offloading cold entries to DB only.
    pub max_mem_entries: usize,
}

impl Default for TraceIndexConfig {
    fn default() -> Self {
        Self { flush_batch_size: 4096, max_mem_entries: 2_000_000 }
    }
}

/// Thread-safe trace index combining in-memory B-tree + optional `SQLite` backing.
pub struct TraceIndex {
    mem: Arc<RwLock<MemIndex>>,
    db: Option<Arc<std::sync::Mutex<Connection>>>,
    config: TraceIndexConfig,
    pending: Arc<std::sync::Mutex<Vec<IndexEntry>>>,
}

impl TraceIndex {
    /// Create a new purely in-memory index.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            mem: Arc::new(RwLock::new(MemIndex::default())),
            db: None,
            config: TraceIndexConfig::default(),
            pending: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Create or open a SQLite-backed index at `path`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn open(path: &Path, config: TraceIndexConfig) -> Result<Self> {
        let conn = open_db(path)?;
        let mem = load_from_db(&conn)?;
        Ok(Self {
            mem: Arc::new(RwLock::new(mem)),
            db: Some(Arc::new(std::sync::Mutex::new(conn))),
            config,
            pending: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    /// # Errors
    /// Returns an error if the operation fails.
    /// Incrementally add one entry (call from trace streaming loop).
    /// # Panics
    /// Panics if invariants are violated.
    pub async fn push(&self, entry: IndexEntry) -> Result<()> {
        // Insert into mem index.
        {
            let mut m = self.mem.write().await;
            m.insert(&entry);
        }
        // Accumulate for batch DB write.
        let should_flush = {
            let mut pend = self.pending.lock().unwrap();
            pend.push(entry);
            pend.len() >= self.config.flush_batch_size
        };
        if should_flush {
            self.flush_pending().await?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the operation fails.
    /// Flush any accumulated pending entries to `SQLite`.
    /// # Panics
    /// Panics if invariants are violated.
    pub async fn flush_pending(&self) -> Result<()> {
        let batch: Vec<IndexEntry> = {
            let mut pend = self.pending.lock().unwrap();
            std::mem::take(&mut *pend)
        };
        if batch.is_empty() {
            return Ok(());
        }
        if let Some(db) = &self.db {
            let db = db.clone();
            tokio::task::spawn_blocking(move || {
                let conn = db.lock().unwrap();
                flush_batch_to_db(&conn, &batch)
            })
            .await
            .context("spawn flush")??;
        }
        Ok(())
    }

    /// Range query: find all entries with ip in [`q.ip_lo`, `q.ip_hi`] and time in [`q.time_lo`, `q.time_hi`].
    pub async fn range_query(&self, q: &IpTimeRange) -> Vec<IndexEntry> {
        self.mem.read().await.range_query(q)
    }

    /// Find all visits to `ip`, optionally paginated.
    pub async fn visits_to_ip(
        &self,
        ip: Ip,
        page: usize,
        page_size: usize,
    ) -> Vec<IndexEntry> {
        let q = IpTimeRange::address(ip);
        let all = self.mem.read().await.range_query(&q);
        let start = page * page_size;
        if start >= all.len() {
            return vec![];
        }
        all[start..(all.len().min(start + page_size))].to_vec()
    }

    /// Count visits to `ip`.
    pub async fn visit_count(&self, ip: Ip) -> u64 {
        self.mem.read().await.ip_hit_count.get(&ip).copied().unwrap_or(0)
    }

    /// Entry at or just before `time`.
    pub async fn entry_before(&self, time: TraceTime) -> Option<IndexEntry> {
        self.mem.read().await.entry_before(time)
    }

    /// Entry at or just after `time`.
    pub async fn entry_after(&self, time: TraceTime) -> Option<IndexEntry> {
        self.mem.read().await.entry_after(time)
    }

    /// Next visit to `ip` strictly after `after_time`.
    pub async fn next_visit(&self, ip: Ip, after_time: TraceTime) -> Option<IndexEntry> {
        self.mem.read().await.next_visit(ip, after_time)
    }

    /// Previous visit to `ip` strictly before `before_time`.
    pub async fn prev_visit(&self, ip: Ip, before_time: TraceTime) -> Option<IndexEntry> {
        self.mem.read().await.prev_visit(ip, before_time)
    }

    /// Hot addresses (most visited), limited to `limit` entries.
    pub async fn hot_addresses(&self, limit: usize) -> Vec<(Ip, u64)> {
        self.mem.read().await.hot_addresses(limit)
    }

    /// Total indexed entries.
    pub async fn len(&self) -> u64 {
        self.mem.read().await.len()
    }

    /// Is the index empty?
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Time range covered by the index.
    pub async fn time_range(&self) -> Option<(TraceTime, TraceTime)> {
        let m = self.mem.read().await;
        Some((m.min_time()?, m.max_time()?))
    }

    /// # Errors
    /// Returns an error if the operation fails.
    /// Bulk-load from an iterator (faster than repeated `push`).
    /// # Panics
    /// Panics if invariants are violated.
    pub async fn bulk_load<I>(&self, entries: I) -> Result<()>
    where
        I: Iterator<Item = IndexEntry>,
    {
        // Collect all entries first so we can release the write lock before
        // awaiting spawn_blocking (holding an async RwLock across .await is a
        // deadlock risk — other tasks trying to read would be stuck).
        let all_entries: Vec<IndexEntry> = entries.collect();
        let flush_size = self.config.flush_batch_size;

        // Insert everything into the in-memory index without holding the lock
        // across any .await point.
        {
            let mut m = self.mem.write().await;
            for entry in &all_entries {
                m.insert(entry);
            }
        }

        // Flush to DB in batches outside the mem lock.
        if let Some(db) = &self.db {
            for chunk in all_entries.chunks(flush_size) {
                let db = db.clone();
                let b: Vec<IndexEntry> = chunk.to_vec();
                tokio::task::spawn_blocking(move || {
                    flush_batch_to_db(&db.lock().unwrap(), &b)
                })
                .await
                .context("bulk flush")??;
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the operation fails.
    /// Persist metadata key/value to DB.
    /// # Panics
    /// Panics if invariants are violated.
    pub async fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        if let Some(db) = &self.db {
            let db = db.clone();
            let key = key.to_owned();
            let value = value.to_owned();
            tokio::task::spawn_blocking(move || {
                db.lock().unwrap().execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES(?1, ?2)",
                    params![key, value],
                )
                .context("set_meta")?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("spawn set_meta")??;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the operation fails.
    /// Read metadata from DB.
    /// # Panics
    /// Panics if invariants are violated.
    pub async fn get_meta(&self, key: &str) -> Result<Option<String>> {
        if let Some(db) = &self.db {
            let db = db.clone();
            let key = key.to_owned();
            let val = tokio::task::spawn_blocking(move || {
                let val: Option<String> = db.lock().unwrap()
                    .query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get(0))
                    .optional()
                    .context("get_meta")?;
                Ok::<_, anyhow::Error>(val)
            })
            .await
            .context("spawn get_meta")??;
            return Ok(val);
        }
        Ok(None)
    }

    /// Return statistics about the index.
    pub async fn stats(&self) -> IndexStats {
        let m = self.mem.read().await;
        IndexStats {
            total_entries: m.total,
            min_time: m.min_time(),
            max_time: m.max_time(),
            unique_ips: m.ip_hit_count.len() as u64,
            top10_hot: m.hot_addresses(10),
        }
    }
}

/// Statistics about the index.
#[derive(Debug, Clone, Serialize)]
pub struct IndexStats {
    pub total_entries: u64,
    pub min_time: Option<TraceTime>,
    pub max_time: Option<TraceTime>,
    pub unique_ips: u64,
    pub top10_hot: Vec<(Ip, u64)>,
}

// ─── Incremental Streamer ─────────────────────────────────────────────────────

/// Receives raw trace events and incrementally builds the index.
pub struct IndexStreamer {
    index: Arc<TraceIndex>,
    current_time: TraceTime,
    current_offset: TraceOffset,
}

impl IndexStreamer {
    #[must_use]
    pub const fn new(index: Arc<TraceIndex>) -> Self {
        Self { index, current_time: 0, current_offset: 0 }
    }

    /// Feed one instruction event.  `ip` is the instruction pointer, `bytes` is
    /// the size of the instruction in the raw trace stream.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn feed(
        &mut self,
        ip: Ip,
        instruction_bytes: u32,
        thread_id: Option<u32>,
    ) -> Result<()> {
        let entry = IndexEntry {
            ip,
            time: self.current_time,
            offset: self.current_offset,
            thread_id,
        };
        self.index.push(entry).await?;
        self.current_time += 1;
        self.current_offset += u64::from(instruction_bytes);
        Ok(())
    }

    /// Finalize: flush all pending entries.
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn finish(self) -> Result<()> {
        self.index.flush_pending().await?;
        self.index
            .set_meta("stream_complete", "true")
            .await?;
        Ok(())
    }

    #[must_use]
    pub const fn current_time(&self) -> TraceTime {
        self.current_time
    }
}

// ─── Serialization helpers ────────────────────────────────────────────────────

/// Serialize the in-memory index to a binary blob (for checkpoint/restore without DB).
/// # Errors
/// Returns an error if the operation fails.
pub async fn serialize_index(idx: &TraceIndex) -> Result<Vec<u8>> {
    let entries: Vec<IndexEntry> = idx.mem.read().await
        .by_ip_time
        .iter()
        .map(|((ip, time), (offset, tid))| IndexEntry {
            ip: *ip,
            time: *time,
            offset: *offset,
            thread_id: *tid,
        })
        .collect();
    let bytes = bincode::serialize(&entries).context("bincode serialize")?;
    Ok(bytes)
}

/// Deserialize index entries from a binary blob and populate `idx`.
/// # Errors
/// Returns an error if the operation fails.
pub async fn deserialize_into(idx: &TraceIndex, data: &[u8]) -> Result<()> {
    let entries: Vec<IndexEntry> = bincode::deserialize(data).context("bincode deserialize")?;
    idx.bulk_load(entries.into_iter()).await
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ip: Ip, time: TraceTime, offset: TraceOffset) -> IndexEntry {
        IndexEntry { ip, time, offset, thread_id: None }
    }

    #[tokio::test]
    async fn test_push_and_range_query() {
        let idx = TraceIndex::in_memory();
        idx.push(make_entry(0x1000, 0, 0)).await.unwrap();
        idx.push(make_entry(0x1004, 1, 5)).await.unwrap();
        idx.push(make_entry(0x1000, 2, 10)).await.unwrap();
        idx.push(make_entry(0x2000, 3, 15)).await.unwrap();

        let q = IpTimeRange::address(0x1000);
        let hits = idx.range_query(&q).await;
        assert_eq!(hits.len(), 2);

        let q2 = IpTimeRange::address_range(0x1000, 0x1004);
        let hits2 = idx.range_query(&q2).await;
        assert_eq!(hits2.len(), 3);
    }

    #[tokio::test]
    async fn test_next_prev_visit() {
        let idx = TraceIndex::in_memory();
        for t in 0u64..10 {
            idx.push(make_entry(if t % 2 == 0 { 0x1000 } else { 0x1004 }, t, t * 5))
                .await
                .unwrap();
        }
        let nv = idx.next_visit(0x1000, 2).await;
        assert_eq!(nv.map(|e| e.time), Some(4));

        let pv = idx.prev_visit(0x1000, 6).await;
        assert_eq!(pv.map(|e| e.time), Some(4));
    }

    #[tokio::test]
    async fn test_hot_addresses() {
        let idx = TraceIndex::in_memory();
        for t in 0u64..100 {
            idx.push(make_entry(0x1000, t, t)).await.unwrap();
        }
        idx.push(make_entry(0x2000, 100, 100)).await.unwrap();
        let hot = idx.hot_addresses(1).await;
        assert_eq!(hot[0].0, 0x1000);
        assert_eq!(hot[0].1, 100);
    }

    #[tokio::test]
    async fn test_stats() {
        let idx = TraceIndex::in_memory();
        idx.push(make_entry(0x1000, 0, 0)).await.unwrap();
        idx.push(make_entry(0x2000, 5, 20)).await.unwrap();
        let s = idx.stats().await;
        assert_eq!(s.total_entries, 2);
        assert_eq!(s.min_time, Some(0));
        assert_eq!(s.max_time, Some(5));
        assert_eq!(s.unique_ips, 2);
    }
}
