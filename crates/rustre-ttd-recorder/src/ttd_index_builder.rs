//! TTD trace index builder.
//!
//! Parses a trace file path, builds sorted index entries, module/syscall/thread
//! timelines, and exports the index in a compact binary format.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use rusqlite::{params, Connection};
use rustre_trace::TraceSession;

// ─── IndexEntryType ───────────────────────────────────────────────────────────

/// Classification of what each index entry refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexEntryType {
    ThreadContext,
    Syscall,
    ApiCall,
    MemoryWrite,
    Exception,
    ModuleLoad,
    ModuleUnload,
    ThreadCreate,
    ThreadExit,
}

impl IndexEntryType {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ThreadContext => 0,
            Self::Syscall       => 1,
            Self::ApiCall       => 2,
            Self::MemoryWrite   => 3,
            Self::Exception     => 4,
            Self::ModuleLoad    => 5,
            Self::ModuleUnload  => 6,
            Self::ThreadCreate  => 7,
            Self::ThreadExit    => 8,
        }
    }

    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ThreadContext),
            1 => Some(Self::Syscall),
            2 => Some(Self::ApiCall),
            3 => Some(Self::MemoryWrite),
            4 => Some(Self::Exception),
            5 => Some(Self::ModuleLoad),
            6 => Some(Self::ModuleUnload),
            7 => Some(Self::ThreadCreate),
            8 => Some(Self::ThreadExit),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ThreadContext => "ThreadContext",
            Self::Syscall       => "Syscall",
            Self::ApiCall       => "ApiCall",
            Self::MemoryWrite   => "MemoryWrite",
            Self::Exception     => "Exception",
            Self::ModuleLoad    => "ModuleLoad",
            Self::ModuleUnload  => "ModuleUnload",
            Self::ThreadCreate  => "ThreadCreate",
            Self::ThreadExit    => "ThreadExit",
        }
    }
}

// ─── IndexEntry ───────────────────────────────────────────────────────────────

/// A single entry in the trace index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub timestamp_ns: u64,
    pub file_offset: u64,
    pub thread_id: u32,
    pub entry_type: IndexEntryType,
}

impl IndexEntry {
    #[must_use]
    pub const fn new(
        timestamp_ns: u64,
        file_offset: u64,
        thread_id: u32,
        entry_type: IndexEntryType,
    ) -> Self {
        Self { timestamp_ns, file_offset, thread_id, entry_type }
    }

    /// Serialise to 21 bytes: [u64 ts | u64 offset | u32 tid | u8 type].
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 21] {
        let mut buf = [0u8; 21];
        buf[0..8].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        buf[8..16].copy_from_slice(&self.file_offset.to_le_bytes());
        buf[16..20].copy_from_slice(&self.thread_id.to_le_bytes());
        buf[20] = self.entry_type.as_u8();
        buf
    }

    /// Deserialise from 21 bytes.
    #[must_use]
    pub fn from_bytes(buf: &[u8; 21]) -> Option<Self> {
        let timestamp_ns = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let file_offset  = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let thread_id    = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let entry_type   = IndexEntryType::from_u8(buf[20])?;
        Some(Self { timestamp_ns, file_offset, thread_id, entry_type })
    }
}

// ─── ModuleEvent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModuleEvent {
    pub timestamp_ns: u64,
    pub base: u64,
    pub size: u32,
    pub name: String,
    pub loaded: bool,
}

impl ModuleEvent {
    pub fn load(ts: u64, base: u64, size: u32, name: impl Into<String>) -> Self {
        Self { timestamp_ns: ts, base, size, name: name.into(), loaded: true }
    }
    pub fn unload(ts: u64, base: u64, size: u32, name: impl Into<String>) -> Self {
        Self { timestamp_ns: ts, base, size, name: name.into(), loaded: false }
    }
}

// ─── SyscallEvent ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SyscallEvent {
    pub timestamp_ns: u64,
    pub thread_id: u32,
    pub syscall_num: u32,
    pub args: [u64; 6],
    pub retval: u64,
}

// ─── ThreadEvent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreadEvent {
    pub timestamp_ns: u64,
    pub thread_id: u32,
    pub created: bool,
    pub exit_code: u32,
}

// ─── TraceIndex ──────────────────────────────────────────────────────────────

/// The complete index built from a TTD trace file.
pub struct TraceIndex {
    pub entries: Vec<IndexEntry>,
    pub module_timeline: Vec<ModuleEvent>,
    pub syscall_timeline: Vec<SyscallEvent>,
    pub thread_timeline: Vec<ThreadEvent>,
    /// Per-type entry counts.
    type_counts: HashMap<u8, u64>,
}

impl TraceIndex {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            module_timeline: Vec::new(),
            syscall_timeline: Vec::new(),
            thread_timeline: Vec::new(),
            type_counts: HashMap::new(),
        }
    }

    fn add_entry(&mut self, entry: IndexEntry) {
        *self.type_counts.entry(entry.entry_type.as_u8()).or_insert(0) += 1;
        self.entries.push(entry);
    }

    /// Sort all entries by timestamp.
    fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.timestamp_ns);
        self.module_timeline.sort_by_key(|e| e.timestamp_ns);
        self.syscall_timeline.sort_by_key(|e| e.timestamp_ns);
        self.thread_timeline.sort_by_key(|e| e.timestamp_ns);
    }

    /// Count entries of a specific type.
    #[must_use]
    pub fn count_type(&self, t: IndexEntryType) -> u64 {
        *self.type_counts.get(&t.as_u8()).unwrap_or(&0)
    }

    /// Search entries in a time range.
    #[must_use]
    pub fn search_by_time_range(&self, start_ns: u64, end_ns: u64) -> Vec<&IndexEntry> {
        // Binary search for start.
        let lo = self.entries.partition_point(|e| e.timestamp_ns < start_ns);
        let hi = self.entries.partition_point(|e| e.timestamp_ns <= end_ns);
        self.entries[lo..hi].iter().collect()
    }

    /// Return all entries for a specific thread.
    #[must_use]
    pub fn search_by_thread(&self, tid: u32) -> Vec<&IndexEntry> {
        self.entries.iter().filter(|e| e.thread_id == tid).collect()
    }

    /// Find the nearest entry at or before `timestamp_ns`.
    #[must_use]
    pub fn find_nearest_before(&self, timestamp_ns: u64) -> Option<&IndexEntry> {
        let pos = self.entries.partition_point(|e| e.timestamp_ns <= timestamp_ns);
        if pos == 0 { None } else { Some(&self.entries[pos - 1]) }
    }

    /// Find the nearest entry at or before `timestamp_ns` for a given thread.
    #[must_use]
    pub fn find_nearest_before_thread(&self, thread_id: u32, timestamp_ns: u64) -> Option<&IndexEntry> {
        self.entries.iter().rfind(|e| e.thread_id == thread_id && e.timestamp_ns <= timestamp_ns)
    }

    /// Export the index to binary format.
    /// Format: magic(4) | version(4) | `entry_count(8)` | entries(21*N) | ...
    #[must_use]
    pub fn export_index_binary(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 21 * self.entries.len());
        out.extend_from_slice(b"TTDI");       // magic
        out.extend_from_slice(&1u32.to_le_bytes()); // version 1
        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.to_bytes());
        }
        // Module timeline: count(4) + entries
        out.extend_from_slice(&(self.module_timeline.len() as u32).to_le_bytes());
        for m in &self.module_timeline {
            out.extend_from_slice(&m.timestamp_ns.to_le_bytes());
            out.extend_from_slice(&m.base.to_le_bytes());
            out.extend_from_slice(&m.size.to_le_bytes());
            let name_bytes = m.name.as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.push(u8::from(m.loaded));
        }
        // Syscall timeline
        out.extend_from_slice(&(self.syscall_timeline.len() as u32).to_le_bytes());
        for s in &self.syscall_timeline {
            out.extend_from_slice(&s.timestamp_ns.to_le_bytes());
            out.extend_from_slice(&s.thread_id.to_le_bytes());
            out.extend_from_slice(&s.syscall_num.to_le_bytes());
            for &arg in &s.args {
                out.extend_from_slice(&arg.to_le_bytes());
            }
            out.extend_from_slice(&s.retval.to_le_bytes());
        }
        out
    }

    /// Write the binary index to any `Write` sink.
    pub fn write_binary<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let bytes = self.export_index_binary();
        w.write_all(&bytes)
    }

    /// Return the time span covered by the index (`start_ns`, `end_ns`).
    #[must_use]
    pub fn time_span(&self) -> Option<(u64, u64)> {
        let first = self.entries.first()?.timestamp_ns;
        let last  = self.entries.last()?.timestamp_ns;
        Some((first, last))
    }

    /// Per-thread event counts.
    #[must_use]
    pub fn events_per_thread(&self) -> HashMap<u32, u64> {
        let mut map: HashMap<u32, u64> = HashMap::new();
        for e in &self.entries {
            *map.entry(e.thread_id).or_insert(0) += 1;
        }
        map
    }

    /// Persist the index to a `SQLite` database at `db_path`.
    ///
    /// Creates (or overwrites) a database with an `index_entries` table
    /// containing every [`IndexEntry`] and, separately, tables for the module,
    /// syscall, and thread timelines.  Using `SQLite` as the backing store lets
    /// callers run arbitrary SQL range queries over the index without loading
    /// the entire file into memory.
    ///
    /// # Errors
    /// Returns an [`io::Error`] if the database cannot be opened or any SQL
    /// statement fails.
    pub fn persist_to_sqlite(&self, db_path: &Path) -> io::Result<()> {
        let conn = Connection::open(db_path).map_err(|e| {
            io::Error::other(format!("rusqlite open: {e}"))
        })?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS index_entries (
                id          INTEGER PRIMARY KEY,
                timestamp_ns INTEGER NOT NULL,
                file_offset  INTEGER NOT NULL,
                thread_id    INTEGER NOT NULL,
                entry_type   INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_ts ON index_entries(timestamp_ns);
             CREATE INDEX IF NOT EXISTS idx_tid ON index_entries(thread_id);
             CREATE TABLE IF NOT EXISTS module_events (
                id           INTEGER PRIMARY KEY,
                timestamp_ns INTEGER NOT NULL,
                base         INTEGER NOT NULL,
                size         INTEGER NOT NULL,
                name         TEXT    NOT NULL,
                loaded       INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS syscall_events (
                id           INTEGER PRIMARY KEY,
                timestamp_ns INTEGER NOT NULL,
                thread_id    INTEGER NOT NULL,
                syscall_num  INTEGER NOT NULL,
                arg0 INTEGER, arg1 INTEGER, arg2 INTEGER,
                arg3 INTEGER, arg4 INTEGER, arg5 INTEGER,
                retval       INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS thread_events (
                id           INTEGER PRIMARY KEY,
                timestamp_ns INTEGER NOT NULL,
                thread_id    INTEGER NOT NULL,
                created      INTEGER NOT NULL,
                exit_code    INTEGER NOT NULL
             );",
        )
        .map_err(|e| io::Error::other(format!("rusqlite DDL: {e}")))?;

        // Bulk-insert index entries inside a single transaction for performance.
        let tx = conn.unchecked_transaction().map_err(|e| {
            io::Error::other(format!("rusqlite begin: {e}"))
        })?;
        for entry in &self.entries {
            tx.execute(
                "INSERT INTO index_entries (timestamp_ns, file_offset, thread_id, entry_type)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    entry.timestamp_ns as i64,
                    entry.file_offset  as i64,
                    i64::from(entry.thread_id),
                    i64::from(entry.entry_type.as_u8()),
                ],
            )
            .map_err(|e| io::Error::other(format!("rusqlite insert entry: {e}")))?;
        }
        for m in &self.module_timeline {
            tx.execute(
                "INSERT INTO module_events (timestamp_ns, base, size, name, loaded)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    m.timestamp_ns as i64,
                    m.base         as i64,
                    i64::from(m.size),
                    &m.name,
                    i64::from(m.loaded),
                ],
            )
            .map_err(|e| io::Error::other(format!("rusqlite insert module: {e}")))?;
        }
        for s in &self.syscall_timeline {
            tx.execute(
                "INSERT INTO syscall_events
                 (timestamp_ns, thread_id, syscall_num,
                  arg0, arg1, arg2, arg3, arg4, arg5, retval)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    s.timestamp_ns as i64,
                    i64::from(s.thread_id),
                    i64::from(s.syscall_num),
                    s.args[0] as i64,
                    s.args[1] as i64,
                    s.args[2] as i64,
                    s.args[3] as i64,
                    s.args[4] as i64,
                    s.args[5] as i64,
                    s.retval   as i64,
                ],
            )
            .map_err(|e| io::Error::other(format!("rusqlite insert syscall: {e}")))?;
        }
        for t in &self.thread_timeline {
            tx.execute(
                "INSERT INTO thread_events (timestamp_ns, thread_id, created, exit_code)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    t.timestamp_ns as i64,
                    i64::from(t.thread_id),
                    i64::from(t.created),
                    i64::from(t.exit_code),
                ],
            )
            .map_err(|e| io::Error::other(format!("rusqlite insert thread: {e}")))?;
        }
        tx.commit().map_err(|e| {
            io::Error::other(format!("rusqlite commit: {e}"))
        })?;
        Ok(())
    }

    /// Load index entries from a `SQLite` database previously written by
    /// [`persist_to_sqlite`](Self::persist_to_sqlite).
    ///
    /// # Errors
    /// Returns an [`io::Error`] if the database cannot be opened or queried.
    pub fn load_from_sqlite(db_path: &Path) -> io::Result<Self> {
        let conn = Connection::open(db_path).map_err(|e| {
            io::Error::other(format!("rusqlite open: {e}"))
        })?;
        let mut index = Self::new();

        // Load entries.
        let mut stmt = conn
            .prepare("SELECT timestamp_ns, file_offset, thread_id, entry_type FROM index_entries ORDER BY timestamp_ns")
            .map_err(|e| io::Error::other(format!("rusqlite prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u32,
                    row.get::<_, i64>(3)? as u8,
                ))
            })
            .map_err(|e| io::Error::other(format!("rusqlite query: {e}")))?;
        for row in rows {
            let (ts, offset, tid, type_byte) = row
                .map_err(|e| io::Error::other(format!("rusqlite row: {e}")))?;
            if let Some(entry_type) = IndexEntryType::from_u8(type_byte) {
                index.add_entry(IndexEntry::new(ts, offset, tid, entry_type));
            }
        }
        Ok(index)
    }

    /// Convert this index into a [`rustre_trace::TraceSession`] so it can be
    /// handled by the canonical trace serialization infrastructure (binary,
    /// RLE-compressed, or JSON formats) provided by the `rustre-trace` crate.
    ///
    /// Each [`IndexEntry`] becomes one [`TraceRecord`] carrying an
    /// `Instruction` event whose `addr` is the entry's file offset — a
    /// reasonable proxy for the instruction pointer in a TTD index, where the
    /// file offset identifies the exact position in the trace stream.  The
    /// session name and architecture tag are set by the caller.
    pub fn as_trace_session(&self, session_name: impl Into<String>) -> TraceSession {
        use rustre_trace::TraceEvent;
        let mut session = TraceSession::new(session_name, "ttd");
        for entry in &self.entries {
            let event = TraceEvent::Instruction {
                addr: entry.file_offset,
                size: 1,
            };
            session.push(event, entry.thread_id, entry.timestamp_ns);
        }
        session
    }
}

impl Default for TraceIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TtdIndexBuilder ─────────────────────────────────────────────────────────

/// Constructs a `TraceIndex` from a TTD trace (simulated in this implementation).
pub struct TtdIndexBuilder {
    pub trace_path: String,
    /// Simulated stream of raw records fed in for testing.
    synthetic_records: Vec<SyntheticRecord>,
}

/// An injectable synthetic trace record for testing and simulation.
#[derive(Debug, Clone)]
pub enum SyntheticRecord {
    Context { ts: u64, tid: u32, offset: u64 },
    Syscall { ts: u64, tid: u32, offset: u64, num: u32, args: [u64; 6], ret: u64 },
    ApiCall { ts: u64, tid: u32, offset: u64 },
    MemWrite { ts: u64, tid: u32, offset: u64 },
    Exception { ts: u64, tid: u32, offset: u64 },
    ModLoad { ts: u64, base: u64, size: u32, name: String },
    ModUnload { ts: u64, base: u64, size: u32, name: String },
    ThreadCreate { ts: u64, tid: u32 },
    ThreadExit { ts: u64, tid: u32, exit_code: u32 },
}

impl TtdIndexBuilder {
    pub fn new(trace_path: impl Into<String>) -> Self {
        Self {
            trace_path: trace_path.into(),
            synthetic_records: Vec::new(),
        }
    }

    /// Add a synthetic record (for testing without a real trace file).
    pub fn add_record(&mut self, record: SyntheticRecord) {
        self.synthetic_records.push(record);
    }

    /// Build the index from synthetic records (or would parse `trace_path` in production).
    pub fn build_index(&mut self) -> TraceIndex {
        let mut index = TraceIndex::new();

        for rec in &self.synthetic_records {
            match rec {
                SyntheticRecord::Context { ts, tid, offset } => {
                    index.add_entry(IndexEntry::new(*ts, *offset, *tid, IndexEntryType::ThreadContext));
                }
                SyntheticRecord::Syscall { ts, tid, offset, num, args, ret } => {
                    index.add_entry(IndexEntry::new(*ts, *offset, *tid, IndexEntryType::Syscall));
                    index.syscall_timeline.push(SyscallEvent {
                        timestamp_ns: *ts,
                        thread_id: *tid,
                        syscall_num: *num,
                        args: *args,
                        retval: *ret,
                    });
                }
                SyntheticRecord::ApiCall { ts, tid, offset } => {
                    index.add_entry(IndexEntry::new(*ts, *offset, *tid, IndexEntryType::ApiCall));
                }
                SyntheticRecord::MemWrite { ts, tid, offset } => {
                    index.add_entry(IndexEntry::new(*ts, *offset, *tid, IndexEntryType::MemoryWrite));
                }
                SyntheticRecord::Exception { ts, tid, offset } => {
                    index.add_entry(IndexEntry::new(*ts, *offset, *tid, IndexEntryType::Exception));
                }
                SyntheticRecord::ModLoad { ts, base, size, name } => {
                    index.add_entry(IndexEntry::new(*ts, 0, 0, IndexEntryType::ModuleLoad));
                    index.module_timeline.push(ModuleEvent::load(*ts, *base, *size, name.clone()));
                }
                SyntheticRecord::ModUnload { ts, base, size, name } => {
                    index.add_entry(IndexEntry::new(*ts, 0, 0, IndexEntryType::ModuleUnload));
                    index.module_timeline.push(ModuleEvent::unload(*ts, *base, *size, name.clone()));
                }
                SyntheticRecord::ThreadCreate { ts, tid } => {
                    index.add_entry(IndexEntry::new(*ts, 0, *tid, IndexEntryType::ThreadCreate));
                    index.thread_timeline.push(ThreadEvent {
                        timestamp_ns: *ts, thread_id: *tid, created: true, exit_code: 0,
                    });
                }
                SyntheticRecord::ThreadExit { ts, tid, exit_code } => {
                    index.add_entry(IndexEntry::new(*ts, 0, *tid, IndexEntryType::ThreadExit));
                    index.thread_timeline.push(ThreadEvent {
                        timestamp_ns: *ts, thread_id: *tid, created: false, exit_code: *exit_code,
                    });
                }
            }
        }

        index.sort();
        index
    }

    /// Build a minimal index from just a count of synthetic context events.
    #[must_use]
    pub fn build_synthetic(num_contexts: u32, num_threads: u32) -> TraceIndex {
        let mut builder = Self::new("synthetic://");
        let threads: Vec<u32> = (1..=num_threads).collect();
        for i in 0u32..num_contexts {
            let tid = threads[(i as usize) % threads.len()];
            builder.add_record(SyntheticRecord::Context {
                ts: u64::from(i) * 1000,
                tid,
                offset: u64::from(i) * 256,
            });
        }
        builder.build_index()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_index() -> TraceIndex {
        let mut builder = TtdIndexBuilder::new("test.run");
        builder.add_record(SyntheticRecord::ThreadCreate { ts: 100, tid: 1 });
        builder.add_record(SyntheticRecord::ModLoad { ts: 200, base: 0x7FFF_0000, size: 0x10000, name: "ntdll.dll".into() });
        builder.add_record(SyntheticRecord::Context { ts: 300, tid: 1, offset: 1024 });
        builder.add_record(SyntheticRecord::Syscall {
            ts: 400, tid: 1, offset: 2048,
            num: 0x26, args: [1, 2, 3, 4, 5, 6], ret: 0,
        });
        builder.add_record(SyntheticRecord::ApiCall { ts: 500, tid: 1, offset: 3000 });
        builder.add_record(SyntheticRecord::MemWrite { ts: 600, tid: 2, offset: 4000 });
        builder.add_record(SyntheticRecord::Exception { ts: 700, tid: 1, offset: 5000 });
        builder.add_record(SyntheticRecord::ModUnload { ts: 800, base: 0x7FFF_0000, size: 0x10000, name: "ntdll.dll".into() });
        builder.add_record(SyntheticRecord::ThreadExit { ts: 900, tid: 1, exit_code: 0 });
        builder.build_index()
    }

    #[test]
    fn test_build_index_entry_count() {
        let idx = build_sample_index();
        assert_eq!(idx.entries.len(), 9);
    }

    #[test]
    fn test_entries_sorted_by_time() {
        let idx = build_sample_index();
        for w in idx.entries.windows(2) {
            assert!(w[0].timestamp_ns <= w[1].timestamp_ns);
        }
    }

    #[test]
    fn test_count_type() {
        let idx = build_sample_index();
        assert_eq!(idx.count_type(IndexEntryType::Syscall), 1);
        assert_eq!(idx.count_type(IndexEntryType::ModuleLoad), 1);
        assert_eq!(idx.count_type(IndexEntryType::Exception), 1);
    }

    #[test]
    fn test_search_by_time_range() {
        let idx = build_sample_index();
        let results = idx.search_by_time_range(300, 600);
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_search_by_thread() {
        let idx = build_sample_index();
        let t1 = idx.search_by_thread(1);
        let t2 = idx.search_by_thread(2);
        assert!(!t1.is_empty());
        assert!(!t2.is_empty());
        assert!(t1.iter().all(|e| e.thread_id == 1));
    }

    #[test]
    fn test_find_nearest_before() {
        let idx = build_sample_index();
        let e = idx.find_nearest_before(350).unwrap();
        assert_eq!(e.timestamp_ns, 300);
    }

    #[test]
    fn test_find_nearest_before_none() {
        let idx = build_sample_index();
        assert!(idx.find_nearest_before(50).is_none());
    }

    #[test]
    fn test_time_span() {
        let idx = build_sample_index();
        let (start, end) = idx.time_span().unwrap();
        assert_eq!(start, 100);
        assert_eq!(end, 900);
    }

    #[test]
    fn test_module_timeline() {
        let idx = build_sample_index();
        assert_eq!(idx.module_timeline.len(), 2);
        assert!(idx.module_timeline[0].loaded);
        assert!(!idx.module_timeline[1].loaded);
    }

    #[test]
    fn test_syscall_timeline() {
        let idx = build_sample_index();
        assert_eq!(idx.syscall_timeline.len(), 1);
        assert_eq!(idx.syscall_timeline[0].syscall_num, 0x26);
        assert_eq!(idx.syscall_timeline[0].retval, 0);
    }

    #[test]
    fn test_export_index_binary_magic() {
        let idx = build_sample_index();
        let bytes = idx.export_index_binary();
        assert_eq!(&bytes[0..4], b"TTDI");
    }

    #[test]
    fn test_export_index_binary_entry_count() {
        let idx = build_sample_index();
        let bytes = idx.export_index_binary();
        let count = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(count, idx.entries.len() as u64);
    }

    #[test]
    fn test_index_entry_roundtrip() {
        let entry = IndexEntry::new(1_234_567, 98765, 42, IndexEntryType::ApiCall);
        let bytes = entry.to_bytes();
        let restored = IndexEntry::from_bytes(&bytes).unwrap();
        assert_eq!(entry, restored);
    }

    #[test]
    fn test_events_per_thread() {
        let idx = build_sample_index();
        let per_thread = idx.events_per_thread();
        assert!(per_thread.contains_key(&1));
        assert!(per_thread.contains_key(&2));
    }

    #[test]
    fn test_build_synthetic() {
        let idx = TtdIndexBuilder::build_synthetic(20, 4);
        assert_eq!(idx.entries.len(), 20);
        let threads = idx.events_per_thread();
        assert_eq!(threads.len(), 4);
    }

    #[test]
    fn test_write_binary_sink() {
        let idx = build_sample_index();
        let mut buf = Vec::new();
        idx.write_binary(&mut buf).unwrap();
        assert!(!buf.is_empty());
        assert_eq!(&buf[0..4], b"TTDI");
    }
}
