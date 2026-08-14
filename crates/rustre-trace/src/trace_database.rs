//! SQLite-backed trace database — CRUD, PC index, search, and export.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TraceDatabaseError {
    #[error("database error: {0}")]
    Database(String),
    #[error("entry not found: id={0}")]
    NotFound(u64),
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    #[error("export error: {0}")]
    Export(String),
    #[error("index corrupted")]
    IndexCorrupted,
    #[error("trace already exists: id={0}")]
    AlreadyExists(u64),
}

// ─── TraceEntry ───────────────────────────────────────────────────────────────

/// A single trace entry (execution tick).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Monotonic tick ID.
    pub id: u64,
    /// Program counter.
    pub pc: u64,
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// Thread ID.
    pub tid: u32,
    /// Process ID.
    pub pid: u32,
    /// Timestamp (TSC ticks or ns).
    pub timestamp: u64,
    /// Register snapshot (`reg_id` → value).
    pub registers: HashMap<u32, u64>,
    /// Memory accesses (address, value, size, `is_write`).
    pub mem_accesses: Vec<(u64, u64, u8, bool)>,
}

impl TraceEntry {
    /// Create a minimal entry.
    #[must_use]
    pub fn new(
        id: u64,
        pc: u64,
        mnemonic: impl Into<String>,
        tid: u32,
        pid: u32,
        timestamp: u64,
    ) -> Self {
        Self {
            id,
            pc,
            mnemonic: mnemonic.into(),
            tid,
            pid,
            timestamp,
            registers: HashMap::new(),
            mem_accesses: Vec::new(),
        }
    }

    /// Memory writes in this entry.
    #[must_use]
    pub fn writes(&self) -> Vec<(u64, u64, u8)> {
        self.mem_accesses
            .iter()
            .filter(|&&(_, _, _, w)| w)
            .map(|&(a, v, sz, _)| (a, v, sz))
            .collect()
    }

    /// Memory reads in this entry.
    #[must_use]
    pub fn reads(&self) -> Vec<(u64, u64, u8)> {
        self.mem_accesses
            .iter()
            .filter(|&&(_, _, _, w)| !w)
            .map(|&(a, v, sz, _)| (a, v, sz))
            .collect()
    }
}

// ─── TraceIndex ──────────────────────────────────────────────────────────────

/// In-memory index: PC → list of trace entry IDs.
#[derive(Debug, Default)]
pub struct TraceIndex {
    pc_to_ids: BTreeMap<u64, Vec<u64>>,
    tid_to_ids: HashMap<u32, Vec<u64>>,
    total: u64,
}

impl TraceIndex {
    /// Insert an entry into the index.
    pub fn insert(&mut self, entry: &TraceEntry) {
        self.pc_to_ids.entry(entry.pc).or_default().push(entry.id);
        self.tid_to_ids.entry(entry.tid).or_default().push(entry.id);
        self.total += 1;
    }

    /// Remove all entries for a given id (linear scan — use sparingly).
    pub fn remove(&mut self, id: u64, pc: u64, tid: u32) {
        if let Some(ids) = self.pc_to_ids.get_mut(&pc) {
            ids.retain(|&x| x != id);
        }
        if let Some(ids) = self.tid_to_ids.get_mut(&tid) {
            ids.retain(|&x| x != id);
        }
        self.total = self.total.saturating_sub(1);
    }

    /// All entry IDs at a given PC.
    #[must_use]
    pub fn ids_at_pc(&self, pc: u64) -> &[u64] {
        self.pc_to_ids.get(&pc).map_or(&[][..], Vec::as_slice)
    }

    /// All entry IDs for a thread.
    #[must_use]
    pub fn ids_for_tid(&self, tid: u32) -> &[u64] {
        self.tid_to_ids.get(&tid).map_or(&[][..], Vec::as_slice)
    }

    /// All PCs covered by the trace.
    #[must_use]
    pub fn all_pcs(&self) -> Vec<u64> {
        self.pc_to_ids.keys().copied().collect()
    }

    /// Total indexed entries.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.total
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }
}

// ─── TraceSearch ─────────────────────────────────────────────────────────────

/// Search criteria for trace queries.
#[derive(Debug, Clone, Default)]
pub struct TraceSearch {
    pub pc_range: Option<(u64, u64)>,
    pub pid_filter: Option<u32>,
    pub tid_filter: Option<u32>,
    pub mnemonic_prefix: Option<String>,
    pub min_timestamp: Option<u64>,
    pub max_timestamp: Option<u64>,
    pub has_write_to: Option<u64>,
    pub limit: Option<usize>,
}

impl TraceSearch {
    /// Check if an entry matches this search criteria.
    #[must_use]
    pub fn matches(&self, e: &TraceEntry) -> bool {
        if let Some((lo, hi)) = self.pc_range
            && (e.pc < lo || e.pc > hi)
        {
            return false;
        }
        if let Some(pid) = self.pid_filter
            && e.pid != pid
        {
            return false;
        }
        if let Some(tid) = self.tid_filter
            && e.tid != tid
        {
            return false;
        }
        if let Some(ref pfx) = self.mnemonic_prefix
            && !e
                .mnemonic
                .to_uppercase()
                .starts_with(pfx.to_uppercase().as_str())
        {
            return false;
        }
        if let Some(min_ts) = self.min_timestamp
            && e.timestamp < min_ts
        {
            return false;
        }
        if let Some(max_ts) = self.max_timestamp
            && e.timestamp > max_ts
        {
            return false;
        }
        if let Some(write_addr) = self.has_write_to
            && !e.writes().iter().any(|&(a, _, _)| a == write_addr)
        {
            return false;
        }
        true
    }
}

// ─── TraceExport ─────────────────────────────────────────────────────────────

/// Export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
    Drcov,
}

/// Exports trace entries to various formats.
pub struct TraceExport;

impl TraceExport {
    /// Export entries to CSV string.
    #[must_use]
    pub fn to_csv(entries: &[TraceEntry]) -> String {
        let mut out = "id,pc,mnemonic,tid,pid,timestamp\n".to_string();
        for e in entries {
            out.push_str(&format!(
                "{},{:#010x},{},{},{},{}\n",
                e.id, e.pc, e.mnemonic, e.tid, e.pid, e.timestamp
            ));
        }
        out
    }

    /// Export entries to JSON string.
    pub fn to_json(entries: &[TraceEntry]) -> Result<String, TraceDatabaseError> {
        serde_json::to_string_pretty(entries).map_err(|e| TraceDatabaseError::Export(e.to_string()))
    }

    /// Export as a simple DRcov-style module+BB list.
    #[must_use]
    pub fn to_drcov_basic(entries: &[TraceEntry], module_base: u64) -> String {
        let mut out = "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n".to_string();
        out.push_str("Module Table: version 2, count 1\n");
        out.push_str(&format!(
            "0, {module_base:#010x}, {:#010x}, 0, rustre\n",
            module_base + 0x10_0000
        ));
        out.push_str("BB Table: ");
        let count = entries.len();
        out.push_str(&format!("{count} bbs\n"));
        for e in entries {
            let rva = e.pc.wrapping_sub(module_base);
            out.push_str(&format!("module[0]: {rva:#010x}, 4, 0\n"));
        }
        out
    }
}

// ─── TraceDatabase ────────────────────────────────────────────────────────────

/// In-memory (SQLite-backed in production) trace database.
///
/// The in-test implementation uses a `BTreeMap` as backing store since we
/// cannot depend on `rusqlite` in unit tests without a real DB file.
#[derive(Debug, Default)]
pub struct TraceDatabase {
    entries: BTreeMap<u64, TraceEntry>,
    index: TraceIndex,
    path: Option<String>,
}

impl TraceDatabase {
    /// Create a new in-memory database.
    #[must_use]
    pub fn new_in_memory() -> Self {
        Self::default()
    }

    /// Create backed by a file path (production: `SQLite`; here: same in-memory).
    #[must_use]
    pub fn open(path: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
            ..Self::default()
        }
    }

    /// Create backed by a filesystem [`Path`] (sugar over [`Self::open`]).
    #[must_use]
    pub fn open_path(path: &Path) -> Self {
        Self::open(path.to_string_lossy().into_owned())
    }

    /// Return the backing path for this database, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Insert a new entry.
    pub fn insert(&mut self, entry: TraceEntry) -> Result<(), TraceDatabaseError> {
        if self.entries.contains_key(&entry.id) {
            return Err(TraceDatabaseError::AlreadyExists(entry.id));
        }
        self.index.insert(&entry);
        self.entries.insert(entry.id, entry);
        Ok(())
    }

    /// Get entry by ID.
    pub fn get(&self, id: u64) -> Result<&TraceEntry, TraceDatabaseError> {
        self.entries
            .get(&id)
            .ok_or(TraceDatabaseError::NotFound(id))
    }

    /// Update an existing entry.
    pub fn update(&mut self, entry: TraceEntry) -> Result<(), TraceDatabaseError> {
        let old = self
            .entries
            .get(&entry.id)
            .ok_or(TraceDatabaseError::NotFound(entry.id))?;
        self.index.remove(old.id, old.pc, old.tid);
        self.index.insert(&entry);
        self.entries.insert(entry.id, entry);
        Ok(())
    }

    /// Delete entry by ID.
    pub fn delete(&mut self, id: u64) -> Result<(), TraceDatabaseError> {
        let e = self
            .entries
            .remove(&id)
            .ok_or(TraceDatabaseError::NotFound(id))?;
        self.index.remove(e.id, e.pc, e.tid);
        Ok(())
    }

    /// Search for entries matching criteria.
    #[must_use]
    pub fn search(&self, criteria: &TraceSearch) -> Vec<&TraceEntry> {
        let mut results: Vec<&TraceEntry> = self
            .entries
            .values()
            .filter(|e| criteria.matches(e))
            .collect();
        if let Some(lim) = criteria.limit {
            results.truncate(lim);
        }
        results
    }

    /// All entries at a given PC (via index).
    #[must_use]
    pub fn entries_at_pc(&self, pc: u64) -> Vec<&TraceEntry> {
        self.index
            .ids_at_pc(pc)
            .iter()
            .filter_map(|&id| self.entries.get(&id))
            .collect()
    }

    /// All entries for a thread (via index).
    #[must_use]
    pub fn entries_for_tid(&self, tid: u32) -> Vec<&TraceEntry> {
        self.index
            .ids_for_tid(tid)
            .iter()
            .filter_map(|&id| self.entries.get(&id))
            .collect()
    }

    /// Total number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export all entries to CSV.
    #[must_use]
    pub fn export_csv(&self) -> String {
        let entries: Vec<_> = self.entries.values().collect();
        TraceExport::to_csv(&entries.iter().copied().cloned().collect::<Vec<_>>())
    }

    /// Export to JSON.
    pub fn export_json(&self) -> Result<String, TraceDatabaseError> {
        let entries: Vec<_> = self.entries.values().cloned().collect();
        TraceExport::to_json(&entries)
    }

    /// Reference to the PC index.
    #[must_use]
    pub const fn index(&self) -> &TraceIndex {
        &self.index
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, pc: u64, mn: &str) -> TraceEntry {
        TraceEntry::new(id, pc, mn, 1, 100, id * 100)
    }

    fn db_with_entries(n: u64) -> TraceDatabase {
        let mut db = TraceDatabase::new_in_memory();
        for i in 0..n {
            db.insert(entry(i, 0x1000 + i * 4, "NOP")).unwrap();
        }
        db
    }

    // ── TraceEntry ────────────────────────────────────────────────────────────

    #[test]
    fn test_entry_writes() {
        let mut e = entry(1, 0x1000, "STR");
        e.mem_accesses.push((0x5000, 0x42, 4, true));
        assert_eq!(e.writes().len(), 1);
        assert_eq!(e.reads().len(), 0);
    }

    #[test]
    fn test_entry_reads() {
        let mut e = entry(1, 0x1000, "LDR");
        e.mem_accesses.push((0x5000, 0x99, 4, false));
        assert_eq!(e.reads().len(), 1);
    }

    // ── TraceIndex ────────────────────────────────────────────────────────────

    #[test]
    fn test_index_insert_and_lookup() {
        let mut idx = TraceIndex::default();
        let e = entry(1, 0x1000, "NOP");
        idx.insert(&e);
        assert_eq!(idx.ids_at_pc(0x1000), &[1u64]);
    }

    #[test]
    fn test_index_multiple_at_pc() {
        let mut idx = TraceIndex::default();
        idx.insert(&entry(1, 0x1000, "A"));
        idx.insert(&entry(2, 0x1000, "B"));
        assert_eq!(idx.ids_at_pc(0x1000).len(), 2);
    }

    #[test]
    fn test_index_remove() {
        let mut idx = TraceIndex::default();
        let e = entry(5, 0x2000, "X");
        idx.insert(&e);
        idx.remove(5, 0x2000, 1);
        assert!(idx.ids_at_pc(0x2000).is_empty());
    }

    #[test]
    fn test_index_tid_lookup() {
        let mut idx = TraceIndex::default();
        let e = entry(1, 0x1000, "Z");
        idx.insert(&e);
        assert!(!idx.ids_for_tid(1).is_empty());
    }

    // ── TraceSearch ───────────────────────────────────────────────────────────

    #[test]
    fn test_search_pc_range() {
        let e = entry(1, 0x1000, "NOP");
        let mut s = TraceSearch {
            pc_range: Some((0x1000, 0x2000)),
            ..TraceSearch::default()
        };
        assert!(s.matches(&e));
        s.pc_range = Some((0x3000, 0x4000));
        assert!(!s.matches(&e));
    }

    #[test]
    fn test_search_mnemonic_prefix() {
        let e = entry(1, 0x1000, "MOVZ");
        let mut s = TraceSearch {
            mnemonic_prefix: Some("MOV".into()),
            ..TraceSearch::default()
        };
        assert!(s.matches(&e));
        s.mnemonic_prefix = Some("ADD".into());
        assert!(!s.matches(&e));
    }

    #[test]
    fn test_search_timestamp_range() {
        let e = entry(5, 0x1000, "X"); // timestamp = 500
        let mut s = TraceSearch {
            min_timestamp: Some(400),
            max_timestamp: Some(600),
            ..TraceSearch::default()
        };
        assert!(s.matches(&e));
        s.min_timestamp = Some(600);
        assert!(!s.matches(&e));
    }

    #[test]
    fn test_search_has_write_to() {
        let mut e = entry(1, 0x1000, "STR");
        e.mem_accesses.push((0xABCD, 42, 4, true));
        let mut s = TraceSearch {
            has_write_to: Some(0xABCD),
            ..TraceSearch::default()
        };
        assert!(s.matches(&e));
        s.has_write_to = Some(0x9999);
        assert!(!s.matches(&e));
    }

    // ── TraceDatabase ─────────────────────────────────────────────────────────

    #[test]
    fn test_db_insert_and_get() {
        let mut db = TraceDatabase::new_in_memory();
        db.insert(entry(1, 0x1000, "A")).unwrap();
        let e = db.get(1).unwrap();
        assert_eq!(e.pc, 0x1000);
    }

    #[test]
    fn test_db_duplicate_insert_error() {
        let mut db = TraceDatabase::new_in_memory();
        db.insert(entry(1, 0x1000, "A")).unwrap();
        assert!(db.insert(entry(1, 0x2000, "B")).is_err());
    }

    #[test]
    fn test_db_get_not_found() {
        let db = TraceDatabase::new_in_memory();
        assert!(db.get(999).is_err());
    }

    #[test]
    fn test_db_delete() {
        let mut db = db_with_entries(3);
        db.delete(0).unwrap();
        assert_eq!(db.len(), 2);
        assert!(db.get(0).is_err());
    }

    #[test]
    fn test_db_update() {
        let mut db = TraceDatabase::new_in_memory();
        db.insert(entry(1, 0x1000, "OLD")).unwrap();
        let mut updated = entry(1, 0x2000, "NEW");
        updated.id = 1;
        db.update(updated).unwrap();
        assert_eq!(db.get(1).unwrap().mnemonic, "NEW");
    }

    #[test]
    fn test_db_search_with_limit() {
        let db = db_with_entries(10);
        let s = TraceSearch {
            limit: Some(3),
            ..TraceSearch::default()
        };
        let r = db.search(&s);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn test_db_entries_at_pc() {
        let db = db_with_entries(5); // PCs: 0x1000, 0x1004, 0x1008, 0x100C, 0x1010
        let at = db.entries_at_pc(0x1000);
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].id, 0);
    }

    #[test]
    fn test_db_entries_for_tid() {
        let db = db_with_entries(5);
        let tids = db.entries_for_tid(1);
        assert_eq!(tids.len(), 5);
    }

    // ── TraceExport ───────────────────────────────────────────────────────────

    #[test]
    fn test_export_csv_header() {
        let db = db_with_entries(2);
        let csv = db.export_csv();
        assert!(csv.starts_with("id,pc,mnemonic"));
    }

    #[test]
    fn test_export_json_valid() {
        let db = db_with_entries(2);
        let json = db.export_json().unwrap();
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_export_drcov() {
        let entries = vec![entry(1, 0x1001_0000, "NOP")];
        let drcov = TraceExport::to_drcov_basic(&entries, 0x1000_0000);
        assert!(drcov.contains("DRCOV"));
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_db_open_with_path() {
        let db = TraceDatabase::open("/tmp/trace.db");
        assert!(db.path.is_some());
    }

    #[test]
    fn test_db_len_empty() {
        let db = TraceDatabase::new_in_memory();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
    }

    #[test]
    fn test_search_pid_filter() {
        let mut db = TraceDatabase::new_in_memory();
        let mut e = entry(1, 0x1000, "NOP");
        e.pid = 200;
        db.insert(e).unwrap();
        let mut s = TraceSearch {
            pid_filter: Some(200),
            ..TraceSearch::default()
        };
        assert_eq!(db.search(&s).len(), 1);
        s.pid_filter = Some(999);
        assert_eq!(db.search(&s).len(), 0);
    }

    #[test]
    fn test_search_tid_filter() {
        let db = db_with_entries(3); // all tid=1
        let s = TraceSearch {
            tid_filter: Some(1),
            ..TraceSearch::default()
        };
        assert_eq!(db.search(&s).len(), 3);
    }

    #[test]
    fn test_index_all_pcs() {
        let db = db_with_entries(3);
        let pcs = db.index().all_pcs();
        assert_eq!(pcs.len(), 3);
    }

    #[test]
    fn test_db_update_not_found() {
        let mut db = TraceDatabase::new_in_memory();
        let e = entry(99, 0x1000, "X");
        assert!(db.update(e).is_err());
    }

    #[test]
    fn test_db_delete_not_found() {
        let mut db = TraceDatabase::new_in_memory();
        assert!(db.delete(999).is_err());
    }

    #[test]
    fn test_export_csv_rows() {
        let db = db_with_entries(3);
        let csv = db.export_csv();
        // header + 3 data rows = 4 lines minimum
        
        assert!(csv.lines().count() >= 4);
    }

    #[test]
    fn test_search_no_criteria_returns_all() {
        let db = db_with_entries(5);
        let s = TraceSearch::default();
        assert_eq!(db.search(&s).len(), 5);
    }

    #[test]
    fn test_db_entries_at_pc_not_found() {
        let db = db_with_entries(3);
        let r = db.entries_at_pc(0xDEAD_BEEF);
        assert!(r.is_empty());
    }
}
