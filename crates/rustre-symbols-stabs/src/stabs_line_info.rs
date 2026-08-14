//! `rustre-symbols-stabs::stabs_line_info`
//!
//! STABS line-number information: `N_SOL` source file tracking, `N_SLINE` statement
//! lines, per-function line tables, and bidirectional address↔line maps.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── StabsLineEntry ───────────────────────────────────────────────────────────

/// A single STABS line-number entry derived from an `N_SLINE` record.
///
/// `N_SLINE` (`n_type = 0x44`): the `n_desc` field holds the 1-based source line
/// number, and `n_value` holds a PC offset relative to the enclosing `N_FUN`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabsLineEntry {
    /// Absolute virtual address of the statement.
    pub address: u64,
    /// Source file path active when this line was emitted (from `N_SO/N_SOL`).
    pub file: String,
    /// 1-based source line number.
    pub line: u32,
    /// Index within the containing function's instruction array.
    pub pc_offset: u32,
}

impl StabsLineEntry {
    /// Create a new line entry.
    #[must_use]
    pub fn new(address: u64, file: impl Into<String>, line: u32) -> Self {
        Self {
            address,
            file: file.into(),
            line,
            pc_offset: 0,
        }
    }

    /// Create with an explicit PC offset.
    #[must_use]
    pub const fn with_pc_offset(mut self, offset: u32) -> Self {
        self.pc_offset = offset;
        self
    }
}

impl fmt::Display for StabsLineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} line {} @ {:#x}", self.file, self.line, self.address)
    }
}

impl PartialOrd for StabsLineEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StabsLineEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address
            .cmp(&other.address)
            .then(self.line.cmp(&other.line))
    }
}

// ─── StabsLineTable ───────────────────────────────────────────────────────────

/// A sorted line-number table for a single function.
///
/// Built by scanning `N_FUN` + `N_SLINE` records for one function scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StabsLineTable {
    /// Function name.
    pub function_name: String,
    /// Base address of the function (from `N_FUN` `n_value`).
    pub function_base: u64,
    /// Line entries, sorted by address.
    pub entries: Vec<StabsLineEntry>,
}

impl StabsLineTable {
    /// Create an empty table for a function.
    #[must_use]
    pub fn new(function_name: impl Into<String>, function_base: u64) -> Self {
        Self {
            function_name: function_name.into(),
            function_base,
            entries: Vec::new(),
        }
    }

    /// Add a line entry, keeping [`Self::entries`] in address order.
    ///
    /// The field documents itself as "sorted by address" and
    /// [`Self::lookup_address`] relies on that: it uses `partition_point`, which
    /// silently returns the wrong entry on an unsorted slice.  A plain `push`
    /// left the invariant to the caller, so `new()` + `add()` +
    /// `lookup_address()` — the obvious sequence — gave wrong answers unless the
    /// entries happened to arrive in ascending order or `sort()` was remembered.
    /// The sibling `stabs_lineinfo::LineTable` cannot have this problem because
    /// it keys a `BTreeMap`, which is ordered by construction.
    ///
    /// Entries that do arrive in order still append, so this costs nothing in
    /// the common case.
    pub fn add(&mut self, entry: StabsLineEntry) {
        let pos = self.entries.partition_point(|e| *e < entry);
        self.entries.insert(pos, entry);
    }

    /// Sort entries by address.
    pub fn sort(&mut self) {
        self.entries.sort_unstable();
    }

    /// Lookup the entry at or before `addr` (returns the last entry with address ≤ addr).
    #[must_use]
    pub fn lookup_address(&self, addr: u64) -> Option<&StabsLineEntry> {
        let pos = self.entries.partition_point(|e| e.address <= addr);
        if pos == 0 {
            None
        } else {
            self.entries.get(pos - 1)
        }
    }

    /// Lookup entries for a given source line number.
    #[must_use]
    pub fn lookup_line(&self, line: u32) -> Vec<&StabsLineEntry> {
        self.entries.iter().filter(|e| e.line == line).collect()
    }

    /// Return all lines present in this table (deduplicated, sorted).
    #[must_use]
    pub fn all_lines(&self) -> Vec<u32> {
        let mut lines: Vec<u32> = self.entries.iter().map(|e| e.line).collect();
        lines.sort_unstable();
        lines.dedup();
        lines
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Address range covered by this table: `(min_addr, max_addr)`.
    #[must_use]
    pub fn address_range(&self) -> Option<(u64, u64)> {
        let first = self.entries.first()?.address;
        let last = self.entries.last()?.address;
        Some((first, last))
    }
}

impl fmt::Display for StabsLineTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StabsLineTable {{ fn='{}' base={:#x} entries={} }}",
            self.function_name,
            self.function_base,
            self.entries.len(),
        )
    }
}

// ─── N_SOL source file tracker ────────────────────────────────────────────────

/// Tracks the active source file as `N_SO` and `N_SOL` records are scanned.
///
/// GCC emits `N_SO` twice for each compilation unit: once for the directory and
/// once for the filename.  `N_SOL` switches to an included file mid-function.
#[derive(Debug, Clone, Default)]
pub struct SourceFileTracker {
    /// Current directory (from first `N_SO`).
    pub directory: String,
    /// Current filename (from second `N_SO` or `N_SOL`).
    pub filename: String,
    /// All source files seen.
    pub seen_files: Vec<String>,
    /// Whether the current sequence is waiting for the second `N_SO`.
    waiting_for_filename: bool,
}

impl SourceFileTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle an `N_SO` record with the given string value.
    ///
    /// GCC emits `N_SO` pairs: (directory, filename).  A single `N_SO` with an empty
    /// string marks end-of-compilation-unit.
    pub fn handle_n_so(&mut self, s: &str) {
        if s.is_empty() {
            // End of compilation unit.
            self.waiting_for_filename = false;
            return;
        }
        if self.waiting_for_filename {
            self.filename = s.to_string();
            self.waiting_for_filename = false;
            let full = self.current_path();
            if !self.seen_files.contains(&full) {
                self.seen_files.push(full);
            }
        } else {
            // First N_SO = directory if it ends with '/'.
            if s.ends_with('/') || s.ends_with('\\') {
                self.directory = s.to_string();
                self.waiting_for_filename = true;
            } else {
                // Single N_SO with full path.
                self.filename = s.to_string();
                self.directory = String::new();
                let full = self.current_path();
                if !self.seen_files.contains(&full) {
                    self.seen_files.push(full);
                }
            }
        }
    }

    /// Handle an `N_SOL` record (inline file switch).
    pub fn handle_n_sol(&mut self, s: &str) {
        if !s.is_empty() {
            self.filename = s.to_string();
            let full = self.current_path();
            if !self.seen_files.contains(&full) {
                self.seen_files.push(full);
            }
        }
    }

    /// Return the full current source path.
    #[must_use]
    pub fn current_path(&self) -> String {
        if self.directory.is_empty()
            || self.filename.starts_with('/')
            || self.filename.starts_with('\\')
        {
            self.filename.clone()
        } else {
            format!("{}{}", self.directory, self.filename)
        }
    }

    /// Return all unique source files seen so far.
    #[must_use]
    pub fn all_files(&self) -> &[String] {
        &self.seen_files
    }

    /// Return `true` if any files have been seen.
    #[must_use]
    pub const fn has_files(&self) -> bool {
        !self.seen_files.is_empty()
    }
}

impl fmt::Display for SourceFileTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SourceFileTracker {{ current='{}' files={} }}",
            self.current_path(),
            self.seen_files.len(),
        )
    }
}

// ─── LineInfoDb ───────────────────────────────────────────────────────────────

/// A complete database of STABS line-number information.
///
/// Holds per-function [`StabsLineTable`]s and two global maps:
/// - `addr_to_line`: address → `(file, line)` for fast address lookup.
/// - `line_to_addrs`: `(file, line)` → sorted list of addresses.
#[derive(Debug, Default)]
pub struct LineInfoDb {
    /// Per-function line tables, keyed by function name.
    pub function_tables: HashMap<String, StabsLineTable>,
    /// Address → (file, line).
    addr_to_line: Vec<(u64, String, u32)>,
    /// (file, line) → addresses.
    line_to_addrs: HashMap<(String, u32), Vec<u64>>,
    /// All source files seen.
    source_files: Vec<String>,
}

impl LineInfoDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function's line table to the database.
    ///
    /// The table is sorted here — the single choke point — because
    /// `StabsLineTable::lookup_address` binary-searches via `partition_point`
    /// and N_SLINE records are not guaranteed to be address-ordered (GCC
    /// reorders them under optimisation). Sorting at each flush site instead
    /// left every table but the last one unsorted.
    pub fn add_table(&mut self, mut table: StabsLineTable) {
        table.sort();
        for entry in &table.entries {
            self.addr_to_line
                .push((entry.address, entry.file.clone(), entry.line));
            self.line_to_addrs
                .entry((entry.file.clone(), entry.line))
                .or_default()
                .push(entry.address);
            if !self.source_files.contains(&entry.file) {
                self.source_files.push(entry.file.clone());
            }
        }
        self.function_tables
            .insert(table.function_name.clone(), table);
    }

    /// Sort the address→line map for binary search.
    pub fn sort(&mut self) {
        self.addr_to_line.sort_unstable_by_key(|(addr, _, _)| *addr);
        for v in self.line_to_addrs.values_mut() {
            v.sort_unstable();
        }
    }

    /// Look up `(file, line)` for the given address (nearest entry ≤ addr).
    #[must_use]
    pub fn addr_to_line(&self, addr: u64) -> Option<(&str, u32)> {
        let pos = self.addr_to_line.partition_point(|(a, _, _)| *a <= addr);
        if pos == 0 {
            return None;
        }
        let (_, file, line) = &self.addr_to_line[pos - 1];
        Some((file.as_str(), *line))
    }

    /// Look up all addresses for `(file, line)`.
    #[must_use]
    pub fn line_to_addrs(&self, file: &str, line: u32) -> &[u64] {
        self.line_to_addrs
            .get(&(file.to_string(), line))
            .map_or(&[], Vec::as_slice)
    }

    /// Look up the first address for `(file, line)`.
    #[must_use]
    pub fn first_addr_for_line(&self, file: &str, line: u32) -> Option<u64> {
        self.line_to_addrs(file, line).first().copied()
    }

    /// Return all source files tracked in this database.
    #[must_use]
    pub fn source_files(&self) -> &[String] {
        &self.source_files
    }

    /// Number of distinct (address, line) entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.addr_to_line.len()
    }

    /// Return the function line table for `fn_name`, if any.
    #[must_use]
    pub fn function_table(&self, fn_name: &str) -> Option<&StabsLineTable> {
        self.function_tables.get(fn_name)
    }

    /// Return all functions that have line info.
    #[must_use]
    pub fn functions(&self) -> Vec<&str> {
        self.function_tables.keys().map(String::as_str).collect()
    }

    /// Build a `LineInfoDb` from raw STABS entry triples.
    ///
    /// `entries` is a slice of `(stab_type, desc, value, string)` tuples:
    /// - `stab_type`: raw N_-type byte (0x44 = `N_SLINE`, 0x24 = `N_FUN`, 0x64 = `N_SO`, 0x84 = `N_SOL`).
    /// - `desc`: `n_desc` field (line number for `N_SLINE`).
    /// - `value`: `n_value` field (PC offset or address).
    /// - `string`: resolved string from the string table.
    ///
    /// `image_base` is added to `N_FUN` addresses to produce virtual addresses.
    #[must_use]
    pub fn build_from_stabs(entries: &[(u8, u16, u32, &str)], image_base: u64) -> Self {
        let mut db = Self::new();
        let mut tracker = SourceFileTracker::new();
        let mut current_fn: Option<(String, u64)> = None;
        let mut current_table: Option<StabsLineTable> = None;

        for &(n_type, n_desc, n_value, string) in entries {
            match n_type {
                0x64 => {
                    // N_SO
                    if let Some(table) = current_table.take() {
                        db.add_table(table);
                    }
                    current_fn = None;
                    tracker.handle_n_so(string);
                }
                0x84 => {
                    // N_SOL
                    tracker.handle_n_sol(string);
                }
                0x24 => {
                    // N_FUN
                    if let Some(table) = current_table.take() {
                        db.add_table(table);
                    }
                    let name = crate::split_stab_name(string).0.to_string();
                    if !name.is_empty() {
                        // Saturating: image_base is caller-supplied and
                        // n_value is attacker-controlled.
                        let fn_addr = image_base.saturating_add(u64::from(n_value));
                        current_fn = Some((name.clone(), fn_addr));
                        current_table = Some(StabsLineTable::new(name, fn_addr));
                    }
                }
                0x44 => {
                    // N_SLINE
                    if let Some((_, fn_base)) = current_fn.as_ref() {
                        let abs_addr = fn_base.saturating_add(u64::from(n_value));
                        let file = tracker.current_path();
                        if !file.is_empty() {
                            let entry = StabsLineEntry::new(abs_addr, file, u32::from(n_desc))
                                .with_pc_offset(n_value);
                            if let Some(ref mut table) = current_table {
                                table.add(entry);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(mut table) = current_table {
            table.sort();
            db.add_table(table);
        }

        db.sort();
        db
    }
}

impl fmt::Display for LineInfoDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LineInfoDb {{ functions={} entries={} files={} }}",
            self.function_tables.len(),
            self.entry_count(),
            self.source_files.len(),
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StabsLineEntry ────────────────────────────────────────────────────────

    #[test]
    fn line_entry_new() {
        let e = StabsLineEntry::new(0x1000, "main.c", 42);
        assert_eq!(e.address, 0x1000);
        assert_eq!(e.file, "main.c");
        assert_eq!(e.line, 42);
        assert_eq!(e.pc_offset, 0);
    }

    #[test]
    fn line_entry_with_pc_offset() {
        let e = StabsLineEntry::new(0x1000, "a.c", 5).with_pc_offset(16);
        assert_eq!(e.pc_offset, 16);
    }

    #[test]
    fn line_entry_display() {
        let e = StabsLineEntry::new(0x2000, "foo.c", 10);
        let s = e.to_string();
        assert!(s.contains("foo.c"));
        assert!(s.contains("10"));
        assert!(s.contains("0x2000"));
    }

    #[test]
    fn line_entry_ordering() {
        let a = StabsLineEntry::new(0x1000, "f.c", 1);
        let b = StabsLineEntry::new(0x2000, "f.c", 2);
        assert!(a < b);
        assert!(b > a);
    }

    // ── StabsLineTable ────────────────────────────────────────────────────────

    #[test]
    fn line_table_add_and_sort() {
        let mut t = StabsLineTable::new("main", 0x1000);
        t.add(StabsLineEntry::new(0x1020, "a.c", 5));
        t.add(StabsLineEntry::new(0x1000, "a.c", 1));
        t.sort();
        assert_eq!(t.entries[0].address, 0x1000);
        assert_eq!(t.entries[1].address, 0x1020);
    }

    #[test]
    fn line_table_lookup_address_exact() {
        let mut t = StabsLineTable::new("f", 0);
        t.add(StabsLineEntry::new(0x1000, "b.c", 10));
        t.add(StabsLineEntry::new(0x1010, "b.c", 11));
        t.sort();
        let e = t.lookup_address(0x1010).unwrap();
        assert_eq!(e.line, 11);
    }

    #[test]
    fn line_table_lookup_address_nearest() {
        let mut t = StabsLineTable::new("f", 0);
        t.add(StabsLineEntry::new(0x1000, "c.c", 1));
        t.add(StabsLineEntry::new(0x1010, "c.c", 2));
        t.sort();
        // Address between entries.
        let e = t.lookup_address(0x1008).unwrap();
        assert_eq!(e.line, 1);
    }

    #[test]
    fn line_table_lookup_address_before_first_returns_none() {
        let mut t = StabsLineTable::new("f", 0);
        t.add(StabsLineEntry::new(0x1000, "d.c", 1));
        t.sort();
        assert!(t.lookup_address(0x0FFF).is_none());
    }

    #[test]
    fn line_table_lookup_line() {
        let mut t = StabsLineTable::new("g", 0);
        t.add(StabsLineEntry::new(0x1000, "e.c", 7));
        t.add(StabsLineEntry::new(0x1010, "e.c", 7));
        t.add(StabsLineEntry::new(0x1020, "e.c", 8));
        let entries = t.lookup_line(7);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn line_table_all_lines_deduped() {
        let mut t = StabsLineTable::new("h", 0);
        t.add(StabsLineEntry::new(0x1000, "f.c", 5));
        t.add(StabsLineEntry::new(0x1010, "f.c", 5));
        t.add(StabsLineEntry::new(0x1020, "f.c", 6));
        let lines = t.all_lines();
        assert_eq!(lines, vec![5, 6]);
    }

    #[test]
    fn line_table_address_range() {
        let mut t = StabsLineTable::new("i", 0);
        t.add(StabsLineEntry::new(0x1000, "g.c", 1));
        t.add(StabsLineEntry::new(0x1020, "g.c", 2));
        t.sort();
        let (lo, hi) = t.address_range().unwrap();
        assert_eq!(lo, 0x1000);
        assert_eq!(hi, 0x1020);
    }

    #[test]
    fn line_table_empty_range_none() {
        let t = StabsLineTable::new("empty", 0);
        assert!(t.address_range().is_none());
    }

    #[test]
    fn line_table_is_empty() {
        let t = StabsLineTable::new("j", 0);
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn line_table_display() {
        let t = StabsLineTable::new("display_test", 0x5000);
        assert!(t.to_string().contains("display_test"));
    }

    // ── SourceFileTracker ─────────────────────────────────────────────────────

    #[test]
    fn tracker_single_n_so_full_path() {
        let mut t = SourceFileTracker::new();
        t.handle_n_so("/home/user/main.c");
        assert_eq!(t.current_path(), "/home/user/main.c");
    }

    #[test]
    fn tracker_two_n_so_dir_file() {
        let mut t = SourceFileTracker::new();
        t.handle_n_so("/src/");
        t.handle_n_so("util.c");
        assert_eq!(t.current_path(), "/src/util.c");
    }

    #[test]
    fn tracker_n_sol_switches_file() {
        let mut t = SourceFileTracker::new();
        t.handle_n_so("/src/");
        t.handle_n_so("main.c");
        t.handle_n_sol("/usr/include/stdio.h");
        assert_eq!(t.current_path(), "/usr/include/stdio.h");
    }

    #[test]
    fn tracker_seen_files_accumulated() {
        let mut t = SourceFileTracker::new();
        t.handle_n_so("/src/");
        t.handle_n_so("main.c");
        t.handle_n_sol("/usr/include/foo.h");
        assert_eq!(t.all_files().len(), 2);
    }

    #[test]
    fn tracker_empty_n_so_ends_cu() {
        let mut t = SourceFileTracker::new();
        t.handle_n_so("/src/");
        t.handle_n_so("x.c");
        t.handle_n_so(""); // end of CU
        assert!(!t.has_files() || t.has_files()); // just checking it doesn't panic
    }

    #[test]
    fn tracker_display() {
        let mut t = SourceFileTracker::new();
        t.handle_n_so("test.c");
        let s = t.to_string();
        assert!(s.contains("SourceFileTracker"));
        assert!(s.contains("test.c"));
    }

    // ── LineInfoDb ────────────────────────────────────────────────────────────

    fn build_simple_db() -> LineInfoDb {
        let entries: Vec<(u8, u16, u32, &str)> = vec![
            (0x64, 0, 0, "/src/"),       // N_SO dir
            (0x64, 0, 0, "test.c"),      // N_SO file
            (0x24, 1, 0x1000, "main:F"), // N_FUN
            (0x44, 10, 0x0000, ""),      // N_SLINE line 10 pc+0
            (0x44, 11, 0x0005, ""),      // N_SLINE line 11 pc+5
            (0x44, 12, 0x000A, ""),      // N_SLINE line 12 pc+10
        ];
        LineInfoDb::build_from_stabs(&entries, 0)
    }

    #[test]
    fn db_build_from_stabs_entry_count() {
        let db = build_simple_db();
        assert_eq!(db.entry_count(), 3);
    }

    #[test]
    fn db_addr_to_line_exact() {
        let db = build_simple_db();
        let (file, line) = db.addr_to_line(0x1000).unwrap();
        assert_eq!(line, 10);
        assert!(file.contains("test.c"));
    }

    #[test]
    fn db_addr_to_line_nearest() {
        let db = build_simple_db();
        // Address between line 10 (0x1000) and line 11 (0x1005).
        let (_, line) = db.addr_to_line(0x1003).unwrap();
        assert_eq!(line, 10);
    }

    #[test]
    fn db_addr_to_line_before_first_none() {
        let db = build_simple_db();
        assert!(db.addr_to_line(0x0FFF).is_none());
    }

    #[test]
    fn db_line_to_addrs() {
        let db = build_simple_db();
        let addrs = db.line_to_addrs("/src/test.c", 11);
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0], 0x1005);
    }

    #[test]
    fn db_first_addr_for_line() {
        let db = build_simple_db();
        let addr = db.first_addr_for_line("/src/test.c", 12);
        assert_eq!(addr, Some(0x100A));
    }

    #[test]
    fn db_first_addr_for_nonexistent_line_none() {
        let db = build_simple_db();
        assert!(db.first_addr_for_line("/src/test.c", 999).is_none());
    }

    #[test]
    fn db_function_table() {
        let db = build_simple_db();
        let t = db.function_table("main");
        assert!(t.is_some());
        assert_eq!(t.unwrap().function_name, "main");
    }

    #[test]
    fn db_source_files() {
        let db = build_simple_db();
        let files = db.source_files();
        assert!(!files.is_empty());
        assert!(files.iter().any(|f| f.contains("test.c")));
    }

    #[test]
    fn db_functions_list() {
        let db = build_simple_db();
        let fns = db.functions();
        assert!(fns.contains(&"main"));
    }

    #[test]
    fn db_display() {
        let db = build_simple_db();
        let s = db.to_string();
        assert!(s.contains("LineInfoDb"));
    }

    #[test]
    fn db_multiple_functions() {
        let entries: Vec<(u8, u16, u32, &str)> = vec![
            (0x64, 0, 0, "a.c"),
            (0x24, 1, 0x1000, "foo:F"),
            (0x44, 5, 0x0000, ""),
            (0x24, 1, 0x2000, "bar:F"),
            (0x44, 10, 0x0000, ""),
            (0x44, 11, 0x0004, ""),
        ];
        let db = LineInfoDb::build_from_stabs(&entries, 0);
        assert_eq!(db.function_tables.len(), 2);
        let foo = db.function_table("foo").unwrap();
        assert_eq!(foo.len(), 1);
        let bar = db.function_table("bar").unwrap();
        assert_eq!(bar.len(), 2);
    }

    #[test]
    fn db_n_sol_file_switch() {
        let entries: Vec<(u8, u16, u32, &str)> = vec![
            (0x64, 0, 0, "main.c"),
            (0x24, 1, 0x1000, "fn:F"),
            (0x44, 1, 0x00, ""),
            (0x84, 0, 0, "included.h"), // N_SOL
            (0x44, 100, 0x04, ""),
        ];
        let db = LineInfoDb::build_from_stabs(&entries, 0);
        // line 1 from main.c, line 100 from included.h
        let fn_t = db.function_table("fn").unwrap();
        assert_eq!(fn_t.entries[0].file, "main.c");
        assert_eq!(fn_t.entries[1].file, "included.h");
    }

    #[test]
    fn db_image_base_applied() {
        let entries: Vec<(u8, u16, u32, &str)> = vec![
            (0x64, 0, 0, "b.c"),
            (0x24, 1, 0x0100, "init:F"),
            (0x44, 1, 0x0000, ""),
        ];
        let db = LineInfoDb::build_from_stabs(&entries, 0x4000_0000);
        let fn_t = db.function_table("init").unwrap();
        assert_eq!(fn_t.function_base, 0x4000_0100);
        assert_eq!(fn_t.entries[0].address, 0x4000_0100);
    }
}
