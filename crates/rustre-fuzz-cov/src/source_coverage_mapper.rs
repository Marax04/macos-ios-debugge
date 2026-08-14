//! Source-level coverage mapping.
//!
//! Maps raw bitmap / PC-guard coverage data to source file line numbers
//! using a simple in-memory mapping table (populated from debug info, LCOV
//! data, or `DRcov` entries).  Produces per-file and per-function coverage reports.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::CovError;

// ─── SourceLine ───────────────────────────────────────────────────────────────

/// A single source line with its coverage status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLine {
    /// 1-based line number.
    pub line: u32,
    /// Hit count (0 = not covered).
    pub hits: u64,
    /// Whether this line is executable (false for blank/comment lines).
    pub executable: bool,
}

impl SourceLine {
    /// Create an executable line with a given hit count.
    #[must_use]
    pub const fn hit(line: u32, hits: u64) -> Self {
        Self { line, hits, executable: true }
    }

    /// Create an executable line with zero hits.
    #[must_use]
    pub const fn missed(line: u32) -> Self {
        Self { line, hits: 0, executable: true }
    }

    /// Returns `true` if the line was executed at least once.
    #[must_use]
    pub const fn is_covered(&self) -> bool {
        self.hits > 0
    }
}

// ─── FunctionCoverage ─────────────────────────────────────────────────────────

/// Coverage record for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCoverage {
    /// Function name (mangled or demangled).
    pub name: String,
    /// Source file containing this function.
    pub file: PathBuf,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line (inclusive, if known).
    pub end_line: Option<u32>,
    /// Total times the function entry was executed.
    pub call_count: u64,
    /// Total executable lines.
    pub total_lines: usize,
    /// Covered lines.
    pub covered_lines: usize,
}

impl FunctionCoverage {
    /// Line coverage percentage.
    #[must_use]
    pub fn line_coverage_pct(&self) -> f64 {
        if self.total_lines == 0 { return 100.0; }
        crate::casts::usize_to_f64(self.covered_lines) / crate::casts::usize_to_f64(self.total_lines) * 100.0
    }
}

// ─── FileCoverage ─────────────────────────────────────────────────────────────

/// Coverage data for a single source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverage {
    /// Absolute or relative path to the source file.
    pub path: PathBuf,
    /// All lines that were tracked (sorted by line number).
    pub lines: Vec<SourceLine>,
    /// Functions defined in this file.
    pub functions: Vec<FunctionCoverage>,
}

impl FileCoverage {
    /// Create an empty file coverage record.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), lines: Vec::new(), functions: Vec::new() }
    }

    /// Number of executable lines.
    #[must_use]
    pub fn executable_lines(&self) -> usize {
        self.lines.iter().filter(|l| l.executable).count()
    }

    /// Number of covered lines.
    #[must_use]
    pub fn covered_lines(&self) -> usize {
        self.lines.iter().filter(|l| l.is_covered()).count()
    }

    /// Line coverage percentage.
    #[must_use]
    pub fn line_coverage_pct(&self) -> f64 {
        let exec = self.executable_lines();
        if exec == 0 { return 100.0; }
        crate::casts::usize_to_f64(self.covered_lines()) / crate::casts::usize_to_f64(exec) * 100.0
    }

    /// Look up a specific line.
    #[must_use]
    pub fn get_line(&self, lineno: u32) -> Option<&SourceLine> {
        self.lines.iter().find(|l| l.line == lineno)
    }

    /// Merge another `FileCoverage` into `self` (accumulate hit counts).
    pub fn merge_from(&mut self, other: &Self) {
        let mut by_line: HashMap<u32, u64> = self.lines.iter()
            .map(|l| (l.line, l.hits))
            .collect();
        for l in &other.lines {
            *by_line.entry(l.line).or_insert(0) += l.hits;
        }
        for line in &mut self.lines {
            if let Some(&hits) = by_line.get(&line.line) {
                line.hits = hits;
            }
        }
        // Add lines present in other but not in self.
        let self_lines: std::collections::HashSet<u32> =
            self.lines.iter().map(|l| l.line).collect();
        for l in &other.lines {
            if !self_lines.contains(&l.line) {
                self.lines.push(l.clone());
            }
        }
        self.lines.sort_by_key(|l| l.line);
    }

    /// Lines that were NOT covered (executable but hits == 0).
    #[must_use]
    pub fn uncovered_lines(&self) -> Vec<u32> {
        self.lines.iter()
            .filter(|l| l.executable && !l.is_covered())
            .map(|l| l.line)
            .collect()
    }
}

// ─── CoverageReport ──────────────────────────────────────────────────────────

/// Aggregate coverage report across multiple source files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Per-file coverage data, keyed by canonical file path.
    pub files: BTreeMap<String, FileCoverage>,
    /// Total executable lines across all files.
    pub total_lines: usize,
    /// Total covered lines across all files.
    pub covered_lines: usize,
    /// Total functions.
    pub total_functions: usize,
    /// Covered functions (`call_count` > 0).
    pub covered_functions: usize,
}

impl CoverageReport {
    /// Create an empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a `FileCoverage` to the report.
    pub fn add_file(&mut self, fc: FileCoverage) {
        self.total_lines += fc.executable_lines();
        self.covered_lines += fc.covered_lines();
        self.total_functions += fc.functions.len();
        self.covered_functions += fc.functions.iter().filter(|f| f.call_count > 0).count();
        let key = fc.path.to_string_lossy().into_owned();
        self.files.entry(key)
            .and_modify(|existing| existing.merge_from(&fc))
            .or_insert(fc);
    }

    /// Overall line coverage percentage.
    #[must_use]
    pub fn line_coverage_pct(&self) -> f64 {
        if self.total_lines == 0 { return 100.0; }
        crate::casts::usize_to_f64(self.covered_lines) / crate::casts::usize_to_f64(self.total_lines) * 100.0
    }

    /// Overall function coverage percentage.
    #[must_use]
    pub fn function_coverage_pct(&self) -> f64 {
        if self.total_functions == 0 { return 100.0; }
        crate::casts::usize_to_f64(self.covered_functions) / crate::casts::usize_to_f64(self.total_functions) * 100.0
    }

    /// Summary text.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Lines: {}/{} ({:.2}%)  Functions: {}/{} ({:.2}%)  Files: {}",
            self.covered_lines, self.total_lines, self.line_coverage_pct(),
            self.covered_functions, self.total_functions, self.function_coverage_pct(),
            self.files.len(),
        )
    }

    /// Files sorted by coverage percentage ascending (most in need of coverage first).
    #[must_use]
    pub fn files_by_coverage_asc(&self) -> Vec<&FileCoverage> {
        let mut files: Vec<&FileCoverage> = self.files.values().collect();
        files.sort_by(|a, b| a.line_coverage_pct()
            .partial_cmp(&b.line_coverage_pct())
            .unwrap_or(std::cmp::Ordering::Equal));
        files
    }
}

// ─── SourceCoverageMapper ─────────────────────────────────────────────────────

/// Maps raw edge/PC coverage to source-level line data.
///
/// The mapping table is populated from LCOV `.info` text, `DRcov` entries, or
/// debug-info extraction (not implemented here — callers feed the data in).
pub struct SourceCoverageMapper {
    /// Edge index → (file path, line number) mapping.
    edge_to_line: HashMap<u32, (PathBuf, u32)>,
    /// PC address → (file path, line number) mapping.
    pc_to_line: HashMap<u64, (PathBuf, u32)>,
    /// Function name → (file, `start_line`, `end_line`).
    func_range: HashMap<String, (PathBuf, u32, Option<u32>)>,
}

impl SourceCoverageMapper {
    /// Create an empty mapper.
    #[must_use]
    pub fn new() -> Self {
        Self {
            edge_to_line: HashMap::new(),
            pc_to_line: HashMap::new(),
            func_range: HashMap::new(),
        }
    }

    /// Register an edge-index → source mapping.
    pub fn register_edge(&mut self, edge: u32, file: impl Into<PathBuf>, line: u32) {
        self.edge_to_line.insert(edge, (file.into(), line));
    }

    /// Register a PC → source mapping.
    pub fn register_pc(&mut self, pc: u64, file: impl Into<PathBuf>, line: u32) {
        self.pc_to_line.insert(pc, (file.into(), line));
    }

    /// Register a function entry.
    pub fn register_function(
        &mut self,
        name: impl Into<String>,
        file: impl Into<PathBuf>,
        start_line: u32,
        end_line: Option<u32>,
    ) {
        self.func_range.insert(name.into(), (file.into(), start_line, end_line));
    }

    /// Bulk-load from an LCOV-style line mapping (file, line, hits triples).
    pub fn load_from_lcov_lines(&mut self, entries: &[(PathBuf, u32, u64)]) {
        for (i, (path, line, _hits)) in entries.iter().enumerate() {
            self.register_edge(crate::casts::usize_to_u32(i), path.clone(), *line);
        }
    }

    /// Apply a raw bitmap to produce a `CoverageReport`.
    ///
    /// Each non-zero byte at position `i` means edge `i` was hit `data[i]` times.
    #[must_use]
    pub fn map_bitmap(&self, bitmap: &[u8]) -> CoverageReport {
        let mut file_lines: HashMap<String, HashMap<u32, u64>> = HashMap::new();

        for (i, &hits) in bitmap.iter().enumerate() {
            if hits == 0 { continue; }
            if let Some((path, line)) = self.edge_to_line.get(&crate::casts::usize_to_u32(i)) {
                let key = path.to_string_lossy().into_owned();
                *file_lines.entry(key).or_default().entry(*line).or_insert(0) += u64::from(hits);
            }
        }

        let mut report = CoverageReport::new();
        for (path_str, lines_hits) in file_lines {
            let mut fc = FileCoverage::new(&path_str);
            for (line, hits) in lines_hits {
                fc.lines.push(SourceLine::hit(line, hits));
            }
            fc.lines.sort_by_key(|l| l.line);
            // Also include function coverage if registered.
            for (fname, (fpath, fstart, fend)) in &self.func_range {
                if fpath.to_string_lossy() == path_str.as_str() {
                    let call_count = fc.lines.iter()
                        .filter(|l| l.line == *fstart)
                        .map(|l| l.hits)
                        .sum();
                    let covered = fc.lines.iter()
                        .filter(|l| l.executable && l.is_covered())
                        .count();
                    fc.functions.push(FunctionCoverage {
                        name: fname.clone(),
                        file: fpath.clone(),
                        start_line: *fstart,
                        end_line: *fend,
                        call_count,
                        total_lines: fc.lines.len(),
                        covered_lines: covered,
                    });
                }
            }
            report.add_file(fc);
        }

        report
    }

    /// Apply a PC-guard hit set to produce a `CoverageReport`.
    #[must_use]
    pub fn map_pc_set(&self, pcs: &[u64]) -> CoverageReport {
        let mut file_lines: HashMap<String, HashMap<u32, u64>> = HashMap::new();
        for &pc in pcs {
            if let Some((path, line)) = self.pc_to_line.get(&pc) {
                let key = path.to_string_lossy().into_owned();
                *file_lines.entry(key).or_default().entry(*line).or_insert(0) += 1;
            }
        }
        let mut report = CoverageReport::new();
        for (path_str, lines_hits) in file_lines {
            let mut fc = FileCoverage::new(&path_str);
            for (line, hits) in lines_hits {
                fc.lines.push(SourceLine::hit(line, hits));
            }
            fc.lines.sort_by_key(|l| l.line);
            report.add_file(fc);
        }
        report
    }

    /// Load a LCOV info file and populate the mapper.
    ///
    /// Minimal parser: reads `SF:`, `DA:`, `FN:`, `end_of_record` markers.
    ///
    /// # Errors
    /// Returns `CovError::Io` if the file cannot be read.
    pub fn load_lcov_file(&mut self, path: &Path) -> Result<Vec<(PathBuf, u32, u64)>, CovError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CovError::Io(e.to_string()))?;
        let mut entries = Vec::new();
        let mut current_file: Option<PathBuf> = None;

        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("SF:") {
                current_file = Some(PathBuf::from(rest.trim()));
            } else if let Some(rest) = line.strip_prefix("DA:") {
                if let Some(ref path) = current_file {
                    let parts: Vec<&str> = rest.splitn(3, ',').collect();
                    if parts.len() >= 2 {
                        let lineno = parts[0].trim().parse::<u32>().unwrap_or(0);
                        let hits = parts[1].trim().parse::<u64>().unwrap_or(0);
                        entries.push((path.clone(), lineno, hits));
                    }
                }
            } else if line == "end_of_record" {
                current_file = None;
            }
        }

        for (i, (path, line, _hits)) in entries.iter().enumerate() {
            self.register_edge(crate::casts::usize_to_u32(i), path.clone(), *line);
        }

        Ok(entries)
    }
}

impl Default for SourceCoverageMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_line_coverage() {
        let l = SourceLine::hit(10, 5);
        assert!(l.is_covered());
        let l2 = SourceLine::missed(11);
        assert!(!l2.is_covered());
    }

    #[test]
    fn file_coverage_pct() {
        let mut fc = FileCoverage::new("foo.rs");
        fc.lines.push(SourceLine::hit(1, 2));
        fc.lines.push(SourceLine::missed(2));
        assert!((fc.line_coverage_pct() - 50.0).abs() < 0.1);
    }

    #[test]
    fn file_coverage_uncovered() {
        let mut fc = FileCoverage::new("foo.rs");
        fc.lines.push(SourceLine::hit(1, 1));
        fc.lines.push(SourceLine::missed(2));
        fc.lines.push(SourceLine::missed(3));
        assert_eq!(fc.uncovered_lines(), vec![2, 3]);
    }

    #[test]
    fn mapper_edge_registration() {
        let mut mapper = SourceCoverageMapper::new();
        mapper.register_edge(0, "src/main.rs", 42);
        let bitmap = vec![3u8, 0, 0];
        let report = mapper.map_bitmap(&bitmap);
        assert!(!report.files.is_empty());
    }

    #[test]
    fn mapper_bitmap_hit_count() {
        let mut mapper = SourceCoverageMapper::new();
        mapper.register_edge(0, "a.rs", 1);
        mapper.register_edge(1, "a.rs", 2);
        let bitmap = vec![1u8, 5];
        let report = mapper.map_bitmap(&bitmap);
        let fc = report.files.values().next().unwrap();
        assert_eq!(fc.covered_lines(), 2);
    }

    #[test]
    fn report_summary_format() {
        let mut report = CoverageReport::new();
        let mut fc = FileCoverage::new("lib.rs");
        fc.lines.push(SourceLine::hit(1, 1));
        fc.lines.push(SourceLine::missed(2));
        report.add_file(fc);
        let s = report.summary();
        assert!(s.contains("Lines:"));
    }

    #[test]
    fn file_coverage_merge() {
        let mut a = FileCoverage::new("x.rs");
        a.lines.push(SourceLine::hit(1, 3));
        a.lines.push(SourceLine::missed(2));
        let mut b = FileCoverage::new("x.rs");
        b.lines.push(SourceLine::hit(1, 2));
        b.lines.push(SourceLine::hit(2, 4));
        a.merge_from(&b);
        assert_eq!(a.get_line(1).unwrap().hits, 5);
        assert_eq!(a.get_line(2).unwrap().hits, 4);
    }

    #[test]
    fn pc_to_line() {
        let mut mapper = SourceCoverageMapper::new();
        mapper.register_pc(0xDEAD_BEEF, "y.rs", 10);
        let report = mapper.map_pc_set(&[0xDEAD_BEEF, 0xDEAD_BEEF]);
        let fc = report.files.values().next().unwrap();
        assert_eq!(fc.get_line(10).unwrap().hits, 2);
    }

    #[test]
    fn empty_report() {
        let report = CoverageReport::new();
        assert!((report.line_coverage_pct() - 100.0).abs() < f64::EPSILON);
    }
}
