//! STABS line information and source mapping.
//!
//! Builds a [`LineTable`] from STABS records for precise address→line lookup.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// LineEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A mapping between a machine address and a source location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineEntry {
    /// Machine address (inclusive start).
    pub address: u64,
    /// 1-based source line number.
    pub line: u32,
    /// 1-based column (0 = unknown).
    pub column: u16,
    /// Source file path.
    pub file: String,
    /// Compilation unit this entry belongs to.
    pub cu: String,
    /// End address of this line entry (exclusive; 0 = unknown).
    pub end_address: u64,
}

impl LineEntry {
    /// Build an entry with unknown column and end address.
    pub fn new(address: u64, line: u32, file: impl Into<String>, cu: impl Into<String>) -> Self {
        Self {
            address,
            line,
            column: 0,
            file: file.into(),
            cu: cu.into(),
            end_address: 0,
        }
    }

    /// Returns true if `addr` falls within this entry's address range.
    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        if self.end_address == 0 {
            addr >= self.address
        } else {
            addr >= self.address && addr < self.end_address
        }
    }
}

impl fmt::Display for LineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}  [0x{:x}]", self.file, self.line, self.address)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LineTable
// ─────────────────────────────────────────────────────────────────────────────

/// A sorted address→[`LineEntry`] table.
#[derive(Debug, Default)]
pub struct LineTable {
    entries: BTreeMap<u64, LineEntry>,
}

impl LineTable {
    /// Create an empty table.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a line entry.
    pub fn insert(&mut self, entry: LineEntry) {
        self.entries.insert(entry.address, entry);
    }

    /// Look up the line entry for the given address (exact or nearest below).
    #[must_use] 
    pub fn lookup(&self, addr: u64) -> Option<&LineEntry> {
        self.entries.range(..=addr).next_back().map(|(_, e)| e)
    }

    /// Look up the exact entry for an address.
    #[must_use] 
    pub fn lookup_exact(&self, addr: u64) -> Option<&LineEntry> {
        self.entries.get(&addr)
    }

    /// All entries sorted by address.
    #[must_use] 
    pub fn entries(&self) -> Vec<&LineEntry> {
        self.entries.values().collect()
    }

    /// Number of entries.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Returns `true` if the table has no entries.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries for a specific source file.
    #[must_use] 
    pub fn entries_for_file<'a>(&'a self, file: &str) -> Vec<&'a LineEntry> {
        self.entries.values().filter(|e| e.file == file).collect()
    }

    /// All distinct source files referenced.
    #[must_use] 
    pub fn source_files(&self) -> Vec<String> {
        let mut files: Vec<String> = self
            .entries
            .values()
            .map(|e| e.file.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        files.sort();
        files
    }

    /// Backfill end addresses from subsequent entry start addresses.
    pub fn fill_end_addresses(&mut self) {
        let addrs: Vec<u64> = self.entries.keys().copied().collect();
        for i in 0..addrs.len().saturating_sub(1) {
            let next = addrs[i + 1];
            if let Some(e) = self.entries.get_mut(&addrs[i])
                && e.end_address == 0 {
                    e.end_address = next;
                }
        }
    }

    /// Build a reverse map: source line → list of addresses.
    #[must_use] 
    pub fn reverse_lookup(&self, file: &str, line: u32) -> Vec<u64> {
        self.entries
            .values()
            .filter(|e| e.file == file && e.line == line)
            .map(|e| e.address)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompilationUnit
// ─────────────────────────────────────────────────────────────────────────────

/// A compilation unit (`N_SO` records).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationUnit {
    /// Main source file (`N_SO` with filename).
    pub main_file: String,
    /// Object file (`N_SO` with path ending in `.o`).
    pub object_file: Option<String>,
    /// Start address.
    pub start_addr: u64,
    /// End address.
    pub end_addr: u64,
    /// Compiler/language info.
    pub compiler: Option<String>,
    /// Functions defined in this CU (by address).
    pub function_addrs: Vec<u64>,
}

impl CompilationUnit {
    /// Create a compilation unit starting at `start`.
    pub fn new(main_file: impl Into<String>, start: u64) -> Self {
        Self {
            main_file: main_file.into(),
            object_file: None,
            start_addr: start,
            end_addr: 0,
            compiler: None,
            function_addrs: Vec::new(),
        }
    }

    /// Size in bytes (`end - start`, saturating).
    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.end_addr.saturating_sub(self.start_addr)
    }
    /// Number of functions recorded in this CU.
    #[must_use] 
    pub const fn function_count(&self) -> usize {
        self.function_addrs.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsLineParser
// ─────────────────────────────────────────────────────────────────────────────

/// Incrementally builds a [`LineTable`] and list of [`CompilationUnit`]s
/// from a stream of STABS line records.
#[derive(Default)]
pub struct StabsLineParser {
    /// Line table built so far.
    pub line_table: LineTable,
    /// Completed compilation units.
    pub compilation_units: Vec<CompilationUnit>,
    current_cu: Option<CompilationUnit>,
    current_file: String,
}

/// A line-oriented STABS record.
#[derive(Debug, Clone)]
pub enum LineRecord {
    /// `N_SO`: source file / compilation unit boundary.
    So {
        /// File name (empty marks end of CU).
        name: String,
        /// Boundary address.
        addr: u64,
    },
    /// `N_SOL`: inline source file change.
    Sol {
        /// New active file.
        name: String,
        /// Address of the change.
        addr: u64,
    },
    /// `N_SLINE`: source line mapping.
    Sline {
        /// Line number.
        line: u32,
        /// Code address.
        addr: u64,
    },
    /// `N_FUN`: function entry.
    Fun {
        /// Function name.
        name: String,
        /// Function address.
        addr: u64,
    },
}

impl StabsLineParser {
    /// Create an empty parser.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a single line record.
    pub fn feed(&mut self, rec: LineRecord) {
        match rec {
            LineRecord::So { name, addr } => {
                if name.is_empty() {
                    // End of compilation unit
                    if let Some(mut cu) = self.current_cu.take() {
                        cu.end_addr = addr;
                        self.compilation_units.push(cu);
                    }
                } else if std::path::Path::new(&name).extension().is_some_and(|e| e.eq_ignore_ascii_case("o")) || std::path::Path::new(&name).extension().is_some_and(|e| e.eq_ignore_ascii_case("obj")) {
                    if let Some(ref mut cu) = self.current_cu {
                        cu.object_file = Some(name);
                    }
                } else {
                    // New compilation unit
                    if let Some(old_cu) = self.current_cu.take() {
                        self.compilation_units.push(old_cu);
                    }
                    self.current_cu = Some(CompilationUnit::new(&name, addr));
                    self.current_file = name;
                }
            }
            LineRecord::Sol { name, addr: _ } => {
                self.current_file = name;
            }
            LineRecord::Sline { line, addr } => {
                let cu_name = self
                    .current_cu
                    .as_ref()
                    .map(|cu| cu.main_file.clone())
                    .unwrap_or_default();
                let entry = LineEntry::new(addr, line, &self.current_file, &cu_name);
                self.line_table.insert(entry);
            }
            LineRecord::Fun { name: _, addr } => {
                if let Some(ref mut cu) = self.current_cu {
                    cu.function_addrs.push(addr);
                }
            }
        }
    }

    /// Feed multiple records in order.
    pub fn feed_all(&mut self, records: Vec<LineRecord>) {
        for r in records {
            self.feed(r);
        }
    }

    /// Finalize and return the line table and compilation units.
    #[must_use] 
    pub fn finish(mut self) -> (LineTable, Vec<CompilationUnit>) {
        if let Some(cu) = self.current_cu.take() {
            self.compilation_units.push(cu);
        }
        self.line_table.fill_end_addresses();
        (self.line_table, self.compilation_units)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InlineInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Information about an inlined function call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineInfo {
    /// Name of the inlined callee.
    pub callee_name: String,
    /// File of the call site.
    pub call_file: String,
    /// Line of the call site.
    pub call_line: u32,
    /// Start address of the inlined range.
    pub inline_site_start: u64,
    /// End address of the inlined range (exclusive).
    pub inline_site_end: u64,
}

impl InlineInfo {
    /// Returns `true` if `addr` falls within the inlined range.
    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.inline_site_start && addr < self.inline_site_end
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(addr: u64, line: u32, file: &str) -> LineEntry {
        LineEntry::new(addr, line, file, "test.c")
    }

    // --- LineEntry ---

    #[test]
    fn line_entry_display() {
        let e = entry(0x1000, 42, "foo.c");
        let s = format!("{e}");
        assert!(s.contains("foo.c"));
        assert!(s.contains("42"));
    }

    #[test]
    fn line_entry_contains_no_end() {
        let e = entry(0x1000, 1, "f.c");
        assert!(e.contains(0x1000));
        assert!(e.contains(0x1010));
    }

    #[test]
    fn line_entry_contains_with_end() {
        let mut e = entry(0x1000, 1, "f.c");
        e.end_address = 0x1010;
        assert!(e.contains(0x1008));
        assert!(!e.contains(0x1010));
    }

    // --- LineTable ---

    #[test]
    fn line_table_lookup_exact() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 10, "a.c"));
        assert_eq!(t.lookup_exact(0x1000).unwrap().line, 10);
    }

    #[test]
    fn line_table_lookup_nearest() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 5, "a.c"));
        t.insert(entry(0x1010, 6, "a.c"));
        assert_eq!(t.lookup(0x1008).unwrap().line, 5);
    }

    #[test]
    fn line_table_lookup_before_start() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 1, "f.c"));
        assert!(t.lookup(0x0fff).is_none());
    }

    #[test]
    fn line_table_source_files() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 1, "a.c"));
        t.insert(entry(0x1010, 2, "b.c"));
        t.insert(entry(0x1020, 3, "a.c"));
        let files = t.source_files();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn line_table_entries_for_file() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 1, "main.c"));
        t.insert(entry(0x1010, 2, "util.c"));
        let main_entries = t.entries_for_file("main.c");
        assert_eq!(main_entries.len(), 1);
    }

    #[test]
    fn line_table_fill_end_addresses() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 1, "f.c"));
        t.insert(entry(0x1010, 2, "f.c"));
        t.fill_end_addresses();
        assert_eq!(t.lookup_exact(0x1000).unwrap().end_address, 0x1010);
    }

    #[test]
    fn line_table_reverse_lookup() {
        let mut t = LineTable::new();
        t.insert(entry(0x1000, 10, "x.c"));
        t.insert(entry(0x1010, 10, "x.c"));
        let addrs = t.reverse_lookup("x.c", 10);
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn line_table_is_empty() {
        let t = LineTable::new();
        assert!(t.is_empty());
    }

    // --- CompilationUnit ---

    #[test]
    fn cu_size() {
        let mut cu = CompilationUnit::new("main.c", 0x1000);
        cu.end_addr = 0x2000;
        assert_eq!(cu.size(), 0x1000);
    }

    #[test]
    fn cu_function_count() {
        let mut cu = CompilationUnit::new("main.c", 0);
        cu.function_addrs.push(0x1000);
        cu.function_addrs.push(0x1100);
        assert_eq!(cu.function_count(), 2);
    }

    // --- StabsLineParser ---

    #[test]
    fn parser_simple_cu() {
        let mut p = StabsLineParser::new();
        p.feed(LineRecord::So {
            name: "main.c".into(),
            addr: 0x1000,
        });
        p.feed(LineRecord::Sline {
            line: 10,
            addr: 0x1000,
        });
        p.feed(LineRecord::Sline {
            line: 11,
            addr: 0x1004,
        });
        p.feed(LineRecord::So {
            name: String::new(),
            addr: 0x2000,
        });
        let (table, cus) = p.finish();
        assert_eq!(table.len(), 2);
        assert_eq!(cus.len(), 1);
        assert_eq!(cus[0].main_file, "main.c");
    }

    #[test]
    fn parser_sol_changes_file() {
        let mut p = StabsLineParser::new();
        p.feed(LineRecord::So {
            name: "main.c".into(),
            addr: 0x1000,
        });
        p.feed(LineRecord::Sol {
            name: "header.h".into(),
            addr: 0x1000,
        });
        p.feed(LineRecord::Sline {
            line: 5,
            addr: 0x1000,
        });
        let (table, _) = p.finish();
        let e = table.lookup_exact(0x1000).unwrap();
        assert_eq!(e.file, "header.h");
    }

    #[test]
    fn parser_fun_records_addr() {
        let mut p = StabsLineParser::new();
        p.feed(LineRecord::So {
            name: "f.c".into(),
            addr: 0,
        });
        p.feed(LineRecord::Fun {
            name: "foo".into(),
            addr: 0x1000,
        });
        let (_, cus) = p.finish();
        assert!(cus[0].function_addrs.contains(&0x1000));
    }

    #[test]
    fn parser_two_cus() {
        let mut p = StabsLineParser::new();
        p.feed(LineRecord::So {
            name: "a.c".into(),
            addr: 0x1000,
        });
        p.feed(LineRecord::Sline {
            line: 1,
            addr: 0x1000,
        });
        p.feed(LineRecord::So {
            name: String::new(),
            addr: 0x2000,
        });
        p.feed(LineRecord::So {
            name: "b.c".into(),
            addr: 0x2000,
        });
        p.feed(LineRecord::Sline {
            line: 1,
            addr: 0x2000,
        });
        p.feed(LineRecord::So {
            name: String::new(),
            addr: 0x3000,
        });
        let (_, cus) = p.finish();
        assert_eq!(cus.len(), 2);
    }

    // --- InlineInfo ---

    #[test]
    fn inline_info_contains() {
        let info = InlineInfo {
            callee_name: "inlined".into(),
            call_file: "f.c".into(),
            call_line: 5,
            inline_site_start: 0x1000,
            inline_site_end: 0x1020,
        };
        assert!(info.contains(0x1010));
        assert!(!info.contains(0x1020));
    }
}
