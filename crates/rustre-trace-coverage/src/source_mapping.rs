//! Map coverage data back to source lines via DWARF debug information.
//!
//! Provides line-level and function-level coverage attribution by parsing
//! DWARF `.debug_line` and `.debug_info` sections. When DWARF is unavailable,
//! falls back to address-only attribution.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

// ─── Source location ──────────────────────────────────────────────────────────

/// A fully qualified source location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Absolute or relative path to the source file.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number (0 means unknown).
    pub column: u32,
}

impl SourceLocation {
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
        }
    }

    pub fn file_line(file: impl Into<String>, line: u32) -> Self {
        Self::new(file, line, 0)
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.column > 0 {
            write!(f, "{}:{}:{}", self.file, self.line, self.column)
        } else {
            write!(f, "{}:{}", self.file, self.line)
        }
    }
}

// ─── DWARF line table entry ───────────────────────────────────────────────────

/// A single row from a DWARF `.debug_line` line number program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineEntry {
    /// Machine code address of this row.
    pub address: u64,
    /// File index into the file table.
    pub file_index: u32,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column (0 = unknown).
    pub column: u32,
    /// True if this row marks the start of a statement.
    pub is_stmt: bool,
    /// True if this row marks the end of a sequence.
    pub end_sequence: bool,
    /// True if this is the prologue end (first real user code).
    pub prologue_end: bool,
}

impl LineEntry {
    #[must_use] 
    pub fn location(&self, file_table: &[String]) -> Option<SourceLocation> {
        let file = file_table.get(self.file_index as usize)?;
        Some(SourceLocation::new(file.clone(), self.line, self.column))
    }
}

// ─── DWARF source line table ──────────────────────────────────────────────────

/// A compilation unit's line number table parsed from DWARF `.debug_line`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineTable {
    /// Compilation unit path (directory + name).
    pub comp_dir: String,
    /// File table (indexed by `file_index` in `LineEntry`).
    pub files: Vec<String>,
    /// Line table rows sorted by address.
    pub rows: Vec<LineEntry>,
}

impl LineTable {
    pub fn new(comp_dir: impl Into<String>) -> Self {
        Self {
            comp_dir: comp_dir.into(),
            files: vec![String::new()], // index 0 is unused in DWARF
            rows: vec![],
        }
    }

    /// Add a file to the file table and return its 1-based index.
    pub fn add_file(&mut self, path: impl Into<String>) -> u32 {
        self.files.push(path.into());
        crate::usize_to_u32_sat(self.files.len() - 1)
    }

    /// Sort rows by address for binary search.
    pub fn sort(&mut self) {
        self.rows.sort_by_key(|r| r.address);
    }

    /// Look up the source location for a given address.
    ///
    /// Returns the location from the row whose address is the largest that is
    /// still ≤ the given address (floor lookup).
    #[must_use] 
    pub fn lookup(&self, address: u64) -> Option<SourceLocation> {
        if self.rows.is_empty() {
            return None;
        }
        // Binary search for largest addr <= address
        let idx = match self
            .rows
            .binary_search_by_key(&address, |r| r.address)
        {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let row = &self.rows[idx];
        if row.end_sequence {
            // end_sequence rows don't represent real code
            if idx == 0 {
                return None;
            }
            return self.rows.get(idx - 1)?.location(&self.files);
        }
        row.location(&self.files)
    }

    /// Returns all addresses in [start, end) and their source locations.
    #[must_use] 
    pub fn locations_in_range(&self, range: Range<u64>) -> Vec<(u64, SourceLocation)> {
        let mut result = Vec::new();
        for row in &self.rows {
            if row.address >= range.start && row.address < range.end && !row.end_sequence
                && let Some(loc) = row.location(&self.files) {
                    result.push((row.address, loc));
                }
        }
        result
    }
}

// ─── Function debug info ──────────────────────────────────────────────────────

/// Debug metadata for a single function from DWARF `.debug_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDebugInfo {
    /// Demangled name.
    pub name: String,
    /// Mangled linkage name.
    pub linkage_name: Option<String>,
    /// Low PC (start address).
    pub low_pc: u64,
    /// High PC (exclusive end address).
    pub high_pc: u64,
    /// Source file declaration.
    pub decl_file: Option<String>,
    /// Source line declaration.
    pub decl_line: Option<u32>,
    /// Inline call site info (for inlined functions).
    pub is_inline: bool,
}

impl FunctionDebugInfo {
    #[must_use] 
    pub const fn contains(&self, address: u64) -> bool {
        address >= self.low_pc && address < self.high_pc
    }

    #[must_use] 
    pub const fn address_range(&self) -> Range<u64> {
        self.low_pc..self.high_pc
    }

    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.high_pc.saturating_sub(self.low_pc)
    }
}

// ─── Source map database ──────────────────────────────────────────────────────

/// Aggregated DWARF debug information for a binary.
///
/// In a real implementation, this would be populated by parsing ELF/PE DWARF
/// sections via `gimli`. Here we provide the data model and lookup logic.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceMap {
    /// Per-CU line tables.
    pub line_tables: Vec<LineTable>,
    /// All functions sorted by `low_pc`.
    pub functions: Vec<FunctionDebugInfo>,
    /// Module base address (for ASLR adjustment).
    pub base_address: u64,
    /// Whether the binary had DWARF info.
    pub has_debug_info: bool,
}

impl SourceMap {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a line table (from one compilation unit).
    pub fn add_line_table(&mut self, mut table: LineTable) {
        table.sort();
        self.line_tables.push(table);
        self.has_debug_info = true;
    }

    /// Add a function entry.
    pub fn add_function(&mut self, func: FunctionDebugInfo) {
        self.functions.push(func);
        // Keep sorted by low_pc
        self.functions.sort_by_key(|f| f.low_pc);
        self.has_debug_info = true;
    }

    /// Adjust an address by subtracting the module base (for ASLR-slid addresses).
    #[must_use] 
    pub const fn adjust_address(&self, address: u64) -> u64 {
        address.saturating_sub(self.base_address)
    }

    /// Look up the source location for a given (possibly slid) address.
    #[must_use] 
    pub fn lookup_location(&self, address: u64) -> Option<SourceLocation> {
        let addr = self.adjust_address(address);
        for table in &self.line_tables {
            if let Some(loc) = table.lookup(addr) {
                return Some(loc);
            }
        }
        None
    }

    /// Look up the function that contains a given address.
    #[must_use] 
    pub fn lookup_function(&self, address: u64) -> Option<&FunctionDebugInfo> {
        let addr = self.adjust_address(address);
        // Binary search for candidate
        let pos = self
            .functions
            .partition_point(|f| f.low_pc <= addr);
        // pos is the first function whose low_pc > addr
        // Walk backwards to find containing function
        for i in (0..pos).rev() {
            if self.functions[i].contains(addr) {
                return Some(&self.functions[i]);
            }
        }
        None
    }

    /// Returns all functions that overlap the given address range.
    #[must_use] 
    pub fn functions_in_range(&self, range: Range<u64>) -> Vec<&FunctionDebugInfo> {
        self.functions
            .iter()
            .filter(|f| f.low_pc < range.end && f.high_pc > range.start)
            .collect()
    }
}

// ─── Coverage-to-source attribution ──────────────────────────────────────────

/// Per-source-file line coverage data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCoverage {
    /// Source file path.
    pub file: String,
    /// Map from 1-based line number to (`hit_count`, `total_executions`).
    pub lines: BTreeMap<u32, LineHitData>,
}

/// Hit data for a single source line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LineHitData {
    /// Total execution count for all addresses on this line.
    pub hit_count: u64,
    /// Number of distinct addresses on this line.
    pub address_count: u32,
    /// Whether any address on this line was executed.
    pub is_covered: bool,
}

impl FileCoverage {
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            lines: BTreeMap::new(),
        }
    }

    pub fn record_hit(&mut self, line: u32, count: u64) {
        let entry = self.lines.entry(line).or_default();
        entry.hit_count += count;
        entry.address_count += 1;
        if count > 0 {
            entry.is_covered = true;
        }
    }

    #[must_use] 
    pub fn covered_lines(&self) -> usize {
        self.lines.values().filter(|l| l.is_covered).count()
    }

    #[must_use] 
    pub fn total_lines(&self) -> usize {
        self.lines.len()
    }

    #[must_use] 
    pub fn line_coverage_pct(&self) -> f64 {
        let total = self.total_lines();
        if total == 0 {
            return 0.0;
        }
        crate::usize_to_f64(self.covered_lines()) / crate::usize_to_f64(total) * 100.0
    }

    #[must_use] 
    pub fn uncovered_lines(&self) -> Vec<u32> {
        self.lines
            .iter()
            .filter(|(_, l)| !l.is_covered)
            .map(|(&line, _)| line)
            .collect()
    }
}

/// Per-function source-level coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSourceCoverage {
    pub name: String,
    pub file: Option<String>,
    pub decl_line: Option<u32>,
    pub covered_lines: u32,
    pub total_lines: u32,
    pub call_count: u64,
    pub line_coverage_pct: f64,
}

// ─── Source coverage report ───────────────────────────────────────────────────

/// Full source-level coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCoverageReport {
    /// Module name.
    pub module: String,
    /// Per-file coverage.
    pub files: Vec<FileCoverage>,
    /// Per-function source coverage.
    pub functions: Vec<FunctionSourceCoverage>,
    /// Total covered source lines across all files.
    pub total_covered_lines: u32,
    /// Total instrumented source lines across all files.
    pub total_lines: u32,
    /// Whether DWARF debug info was available.
    pub has_debug_info: bool,
}

impl SourceCoverageReport {
    #[must_use] 
    pub fn line_coverage_pct(&self) -> f64 {
        if self.total_lines == 0 {
            return 0.0;
        }
        f64::from(self.total_covered_lines) / f64::from(self.total_lines) * 100.0
    }

    #[must_use] 
    pub fn find_file(&self, path: &str) -> Option<&FileCoverage> {
        self.files.iter().find(|f| f.file == path)
    }

    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

// ─── Attribution engine ───────────────────────────────────────────────────────

/// Maps a set of (address, `hit_count`) pairs to source-level coverage via a
/// `SourceMap`.
pub struct SourceAttributor {
    source_map: SourceMap,
}

impl SourceAttributor {
    #[must_use] 
    pub const fn new(source_map: SourceMap) -> Self {
        Self { source_map }
    }

    /// Attribute a slice of (address, `hit_count`) pairs to source locations.
    ///
    /// Returns a `SourceCoverageReport` with per-file and per-function data.
    #[must_use] 
    pub fn attribute(
        &self,
        module: &str,
        hits: &[(u64, u32)],
    ) -> SourceCoverageReport {
        let mut file_cov: HashMap<String, FileCoverage> = HashMap::new();

        for &(addr, count) in hits {
            if let Some(loc) = self.source_map.lookup_location(addr) {
                let fc = file_cov
                    .entry(loc.file.clone())
                    .or_insert_with(|| FileCoverage::new(loc.file.clone()));
                fc.record_hit(loc.line, u64::from(count));
            }
        }

        // Per-function attribution
        let mut func_cov: Vec<FunctionSourceCoverage> = Vec::new();
        for func in &self.source_map.functions {
            // Collect all hits in this function's address range
            let mut covered_lines: HashSet<u32> = HashSet::new();
            let mut total_calls: u64 = 0;

            for &(addr, count) in hits {
                let adjusted = self.source_map.adjust_address(addr);
                if func.contains(adjusted)
                    && let Some(loc) = self.source_map.lookup_location(addr) {
                        if count > 0 {
                            covered_lines.insert(loc.line);
                        }
                        total_calls += u64::from(count);
                    }
            }

            // Collect total instrumented lines in range
            let total_lines: u32 = {
                let mut seen_lines: HashSet<u32> = HashSet::new();
                for table in &self.source_map.line_tables {
                    for (_, loc) in table.locations_in_range(func.address_range()) {
                        seen_lines.insert(loc.line);
                    }
                }
                crate::usize_to_u32_sat(seen_lines.len())
            };

            let covered = crate::usize_to_u32_sat(covered_lines.len());
            let pct = if total_lines > 0 {
                f64::from(covered) / f64::from(total_lines) * 100.0
            } else {
                0.0
            };

            func_cov.push(FunctionSourceCoverage {
                name: func.name.clone(),
                file: func.decl_file.clone(),
                decl_line: func.decl_line,
                covered_lines: covered,
                total_lines,
                call_count: total_calls,
                line_coverage_pct: pct,
            });
        }

        // Aggregate totals
        let mut total_covered = 0u32;
        let mut total_lines_all = 0u32;
        for fc in file_cov.values() {
            total_covered += crate::usize_to_u32_sat(fc.covered_lines());
            total_lines_all += crate::usize_to_u32_sat(fc.total_lines());
        }

        let mut files: Vec<FileCoverage> = file_cov.into_values().collect();
        files.sort_by(|a, b| a.file.cmp(&b.file));

        SourceCoverageReport {
            module: module.to_owned(),
            files,
            functions: func_cov,
            total_covered_lines: total_covered,
            total_lines: total_lines_all,
            has_debug_info: self.source_map.has_debug_info,
        }
    }
}

// ─── DWARF stub parser ────────────────────────────────────────────────────────

/// Stub DWARF parser that builds a `SourceMap` from raw section bytes.
///
/// In production this would use `gimli` crate. Here we provide the interface
/// and a fake implementation for testing.
pub struct DwarfParser;

impl DwarfParser {
    /// Parse DWARF info from raw section data.
    /// Returns `None` if no DWARF is present or parsing fails.
    #[must_use] 
    pub const fn parse(
        _debug_line: &[u8],
        _debug_info: &[u8],
        _debug_abbrev: &[u8],
        _debug_str: &[u8],
    ) -> Option<SourceMap> {
        // A production implementation would use `gimli::read::Dwarf` here.
        // For this stub, return None to indicate missing debug info.
        None
    }

    /// Build a mock `SourceMap` with synthetic data for testing.
    #[must_use] 
    pub fn mock_source_map() -> SourceMap {
        let mut sm = SourceMap::new();

        let mut lt = LineTable::new("/src");
        let fi = lt.add_file("/src/main.c");
        lt.rows.push(LineEntry {
            address: 0x1000,
            file_index: fi,
            line: 10,
            column: 1,
            is_stmt: true,
            end_sequence: false,
            prologue_end: true,
        });
        lt.rows.push(LineEntry {
            address: 0x1010,
            file_index: fi,
            line: 12,
            column: 1,
            is_stmt: true,
            end_sequence: false,
            prologue_end: false,
        });
        lt.rows.push(LineEntry {
            address: 0x1020,
            file_index: fi,
            line: 14,
            column: 1,
            is_stmt: true,
            end_sequence: false,
            prologue_end: false,
        });
        lt.rows.push(LineEntry {
            address: 0x1030,
            file_index: fi,
            line: 0,
            column: 0,
            is_stmt: false,
            end_sequence: true,
            prologue_end: false,
        });
        lt.sort();
        sm.add_line_table(lt);

        sm.add_function(FunctionDebugInfo {
            name: "main".to_owned(),
            linkage_name: Some("_main".to_owned()),
            low_pc: 0x1000,
            high_pc: 0x1030,
            decl_file: Some("/src/main.c".to_owned()),
            decl_line: Some(9),
            is_inline: false,
        });

        sm
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_table_lookup() {
        let sm = DwarfParser::mock_source_map();
        let loc = sm.lookup_location(0x1000).unwrap();
        assert_eq!(loc.line, 10);
        assert_eq!(loc.file, "/src/main.c");
    }

    #[test]
    fn test_line_table_floor_lookup() {
        let sm = DwarfParser::mock_source_map();
        // Address between 0x1000 and 0x1010 should map to line 10
        let loc = sm.lookup_location(0x1008).unwrap();
        assert_eq!(loc.line, 10);
    }

    #[test]
    fn test_function_lookup() {
        let sm = DwarfParser::mock_source_map();
        let func = sm.lookup_function(0x1015).unwrap();
        assert_eq!(func.name, "main");
    }

    #[test]
    fn test_function_lookup_out_of_range() {
        let sm = DwarfParser::mock_source_map();
        let func = sm.lookup_function(0x9999);
        assert!(func.is_none());
    }

    #[test]
    fn test_source_attribution() {
        let sm = DwarfParser::mock_source_map();
        let attributor = SourceAttributor::new(sm);
        let hits = vec![(0x1000u64, 5u32), (0x1010, 3), (0x1020, 0)];
        let report = attributor.attribute("test.exe", &hits);
        assert!(report.has_debug_info);
        assert_eq!(report.files.len(), 1);
        let fc = &report.files[0];
        assert_eq!(fc.file, "/src/main.c");
        assert_eq!(fc.covered_lines(), 2); // lines 10 and 12 have hits > 0
        assert_eq!(fc.total_lines(), 3);   // lines 10, 12, 14
    }

    #[test]
    fn test_file_coverage_pct() {
        let mut fc = FileCoverage::new("test.c");
        fc.record_hit(1, 5);
        fc.record_hit(2, 0);
        fc.record_hit(3, 3);
        assert_eq!(fc.covered_lines(), 2);
        assert_eq!(fc.total_lines(), 3);
        let pct = fc.line_coverage_pct();
        assert!((pct - 66.666).abs() < 0.01);
    }

    #[test]
    fn test_uncovered_lines() {
        let mut fc = FileCoverage::new("test.c");
        fc.record_hit(10, 1);
        fc.record_hit(11, 0);
        fc.record_hit(12, 0);
        let uncov = fc.uncovered_lines();
        assert_eq!(uncov, vec![11, 12]);
    }

    #[test]
    fn test_source_location_display() {
        let loc = SourceLocation::new("foo.c", 42, 7);
        assert_eq!(loc.to_string(), "foo.c:42:7");
        let loc2 = SourceLocation::file_line("bar.c", 10);
        assert_eq!(loc2.to_string(), "bar.c:10");
    }

    #[test]
    fn test_json_roundtrip() {
        let sm = DwarfParser::mock_source_map();
        let attributor = SourceAttributor::new(sm);
        let hits = vec![(0x1000u64, 1u32)];
        let report = attributor.attribute("mod", &hits);
        let json = report.to_json().unwrap();
        assert!(json.contains("main.c"));
    }
}
