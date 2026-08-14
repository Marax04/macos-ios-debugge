//! `lcov_export` — LCOV coverage export and `DRcov` import utilities.

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use crate::{CoverageRun, DrcovFile};

// ── LcovRecord ────────────────────────────────────────────────────────────────

/// A full LCOV record for a single source file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LcovRecord {
    /// `TN:` — test name.
    pub test_name: String,
    /// `SF:` — source file path.
    pub source_file: String,
    /// `FN:` entries: (`line_number`, `function_name`).
    pub functions: Vec<(u32, String)>,
    /// `FNDA:` entries: (`hit_count`, `function_name`).
    pub function_hits: Vec<(u64, String)>,
    /// `DA:` entries: (`line_number`, `hit_count`).
    pub line_hits: Vec<(u32, u64)>,
    /// `BRDA:` entries: (line, block, branch, `taken_count`).
    pub branch_data: Vec<(u32, u32, u32, u64)>,
    /// `BRH:` total branches hit.
    pub brh: u64,
    /// `FNH:` functions hit count.
    pub fnh: u64,
    /// `FNF:` functions found count.
    pub fnf: u64,
    /// `LH:` lines hit count.
    pub lh: u64,
    /// `LF:` lines found count.
    pub lf: u64,
}

impl LcovRecord {
    /// Create a new record for the given source file.
    #[must_use]
    pub fn new(source_file: impl Into<String>) -> Self {
        Self {
            source_file: source_file.into(),
            ..Default::default()
        }
    }

    /// Add a `DA:` (line data) entry.
    pub fn add_line(&mut self, line: u32, hits: u64) {
        self.line_hits.push((line, hits));
    }

    /// Add a `FN:` and corresponding `FNDA:` entry.
    pub fn add_function(&mut self, line: u32, name: impl Into<String>, hits: u64) {
        let n = name.into();
        self.functions.push((line, n.clone()));
        self.function_hits.push((hits, n));
    }

    /// Add a `BRDA:` entry.
    pub fn add_branch(&mut self, line: u32, block: u32, branch: u32, taken: u64) {
        self.branch_data.push((line, block, branch, taken));
    }

    /// Recompute `LH`, `LF`, `FNH`, `FNF`, `BRH` from stored data.
    pub fn recompute_summaries(&mut self) {
        self.lf = self.line_hits.len() as u64;
        self.lh = self.line_hits.iter().filter(|(_, h)| *h > 0).count() as u64;
        self.fnf = self.functions.len() as u64;
        self.fnh = self.function_hits.iter().filter(|(h, _)| *h > 0).count() as u64;
        self.brh = self
            .branch_data
            .iter()
            .filter(|(_, _, _, t)| *t > 0)
            .count() as u64;
    }

    /// Line coverage percentage (0.0–100.0).
    #[must_use]
    pub fn line_coverage_pct(&self) -> f64 {
        if self.lf == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.lh) / crate::casts::u64_to_f64(self.lf) * 100.0
        }
    }

    /// Branch coverage percentage.
    #[must_use]
    pub fn branch_coverage_pct(&self) -> f64 {
        let total = crate::casts::usize_to_f64(self.branch_data.len());
        if total == 0.0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.brh) / total * 100.0
        }
    }

    /// Function coverage percentage.
    #[must_use]
    pub fn function_coverage_pct(&self) -> f64 {
        if self.fnf == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.fnh) / crate::casts::u64_to_f64(self.fnf) * 100.0
        }
    }
}

// ── LcovWriter ────────────────────────────────────────────────────────────────

/// Writes LCOV-format `.info` text from [`LcovRecord`]s.
pub struct LcovWriter;

impl LcovWriter {
    /// Serialise a list of records to a LCOV `.info` string.
    #[must_use]
    pub fn write(records: &[LcovRecord]) -> String {
        let mut out = String::new();
        for rec in records {
            Self::write_record(&mut out, rec);
        }
        out
    }

    /// Write a single record to `out`.
    pub fn write_record(out: &mut String, rec: &LcovRecord) {
        let _ = writeln!(out, "TN:{}", rec.test_name);
        let _ = writeln!(out, "SF:{}", rec.source_file);

        for (line, name) in &rec.functions {
            let _ = writeln!(out, "FN:{line},{name}");
        }
        for (hits, name) in &rec.function_hits {
            let _ = writeln!(out, "FNDA:{hits},{name}");
        }
        let _ = writeln!(out, "FNF:{}", rec.fnf);
        let _ = writeln!(out, "FNH:{}", rec.fnh);

        for (line, hits) in &rec.line_hits {
            let _ = writeln!(out, "DA:{line},{hits}");
        }

        for (line, block, branch, taken) in &rec.branch_data {
            let _ = writeln!(out, "BRDA:{line},{block},{branch},{taken}");
        }
        let _ = writeln!(out, "BRH:{}", rec.brh);
        let _ = writeln!(out, "LF:{}", rec.lf);
        let _ = writeln!(out, "LH:{}", rec.lh);
        out.push_str("end_of_record\n");
    }

    /// Parse a LCOV `.info` string back into records.
    #[must_use]
    pub fn parse(text: &str) -> Vec<LcovRecord> {
        let mut records = Vec::new();
        let mut current = LcovRecord::default();
        let mut in_record = false;

        for line in text.lines() {
            let line = line.trim();
            if line == "end_of_record" {
                records.push(current);
                current = LcovRecord::default();
                in_record = false;
                continue;
            }
            in_record = true;
            if let Some(v) = line.strip_prefix("TN:") {
                v.clone_into(&mut current.test_name);
            } else if let Some(v) = line.strip_prefix("SF:") {
                v.clone_into(&mut current.source_file);
            } else if let Some(v) = line.strip_prefix("FN:") {
                if let Some((l, n)) = v.split_once(',') {
                    let ln = l.parse().unwrap_or(0);
                    current.functions.push((ln, n.to_owned()));
                }
            } else if let Some(v) = line.strip_prefix("FNDA:") {
                if let Some((h, n)) = v.split_once(',') {
                    let hits = h.parse().unwrap_or(0);
                    current.function_hits.push((hits, n.to_owned()));
                }
            } else if let Some(v) = line.strip_prefix("DA:") {
                let mut parts = v.splitn(3, ',');
                if let (Some(ln), Some(h)) = (parts.next(), parts.next()) {
                    let line_no = ln.parse().unwrap_or(0);
                    let hits = h.parse().unwrap_or(0);
                    current.line_hits.push((line_no, hits));
                }
            } else if let Some(v) = line.strip_prefix("BRDA:") {
                let mut p = v.splitn(4, ',');
                if let (Some(l), Some(bl), Some(br), Some(t)) =
                    (p.next(), p.next(), p.next(), p.next())
                {
                    current.branch_data.push((
                        l.parse().unwrap_or(0),
                        bl.parse().unwrap_or(0),
                        br.parse().unwrap_or(0),
                        t.parse().unwrap_or(0),
                    ));
                }
            } else if let Some(v) = line.strip_prefix("BRH:") {
                current.brh = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("FNH:") {
                current.fnh = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("FNF:") {
                current.fnf = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("LH:") {
                current.lh = v.parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("LF:") {
                current.lf = v.parse().unwrap_or(0);
            }
        }
        // If file ends without end_of_record:
        if in_record {
            records.push(current);
        }
        records
    }
}

// ── DrcovImporter ─────────────────────────────────────────────────────────────

/// Import `DynamoRIO` `DRcov` files and convert them to [`CoverageRun`]s.
pub struct DrcovImporter;

impl DrcovImporter {
    /// Import a `DRcov` binary blob and produce a [`CoverageRun`].
    ///
    /// # Errors
    /// Returns a description string on parse failure.
    pub fn import(data: &[u8], run_name: impl Into<String>) -> Result<CoverageRun, String> {
        let drcov = DrcovFile::parse(data).map_err(|e| e.to_string())?;
        let mut run = CoverageRun::new(run_name);
        for bb in &drcov.bbs {
            if let Some(addr) = bb.absolute_addr(&drcov.modules) {
                run.hit(addr);
            }
        }
        Ok(run)
    }

    /// Import multiple `DRcov` blobs and merge them.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn import_and_merge(blobs: &[(Vec<u8>, String)]) -> Result<CoverageRun, String> {
        let mut merged = CoverageRun::new("merged");
        for (data, name) in blobs {
            let run = Self::import(data, name.clone())?;
            merged.merge(&run);
        }
        Ok(merged)
    }
}

// ── CoverageReport ────────────────────────────────────────────────────────────

/// Aggregate coverage report with line, branch, and function percentages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Source file.
    pub source_file: String,
    /// Line coverage percentage (0.0–100.0).
    pub line_pct: f64,
    /// Branch coverage percentage.
    pub branch_pct: f64,
    /// Function coverage percentage.
    pub function_pct: f64,
    /// Total lines found.
    pub lines_found: u64,
    /// Total lines hit.
    pub lines_hit: u64,
    /// Uncovered lines (zero hits).
    pub uncovered_lines: Vec<u32>,
}

impl CoverageReport {
    /// Build a report from an [`LcovRecord`].
    #[must_use]
    pub fn from_record(rec: &LcovRecord) -> Self {
        let uncovered: Vec<u32> = rec
            .line_hits
            .iter()
            .filter(|(_, h)| *h == 0)
            .map(|(l, _)| *l)
            .collect();
        Self {
            source_file: rec.source_file.clone(),
            line_pct: rec.line_coverage_pct(),
            branch_pct: rec.branch_coverage_pct(),
            function_pct: rec.function_coverage_pct(),
            lines_found: rec.lf,
            lines_hit: rec.lh,
            uncovered_lines: uncovered,
        }
    }

    /// Whether the file is fully covered.
    #[must_use]
    pub fn is_fully_covered(&self) -> bool {
        self.line_pct >= 100.0
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: lines={:.1}% branches={:.1}% fns={:.1}%",
            self.source_file, self.line_pct, self.branch_pct, self.function_pct
        )
    }
}

// ── CoverageDiff ──────────────────────────────────────────────────────────────

/// Diff between two coverage reports for the same source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDiffReport {
    pub source_file: String,
    /// Lines covered in run B but not in run A (new coverage).
    pub newly_covered: Vec<u32>,
    /// Lines covered in run A but not in run B (regression).
    pub newly_uncovered: Vec<u32>,
    /// Change in line coverage percentage.
    pub line_pct_delta: f64,
}

impl CoverageDiffReport {
    /// Compute diff between two `LcovRecords` for the same file.
    #[must_use]
    pub fn diff(a: &LcovRecord, b: &LcovRecord) -> Self {
        let a_covered: std::collections::HashSet<u32> = a
            .line_hits
            .iter()
            .filter(|(_, h)| *h > 0)
            .map(|(l, _)| *l)
            .collect();
        let b_covered: std::collections::HashSet<u32> = b
            .line_hits
            .iter()
            .filter(|(_, h)| *h > 0)
            .map(|(l, _)| *l)
            .collect();

        let mut newly_covered: Vec<u32> = b_covered.difference(&a_covered).copied().collect();
        let mut newly_uncovered: Vec<u32> = a_covered.difference(&b_covered).copied().collect();
        newly_covered.sort_unstable();
        newly_uncovered.sort_unstable();

        Self {
            source_file: a.source_file.clone(),
            newly_covered,
            newly_uncovered,
            line_pct_delta: b.line_coverage_pct() - a.line_coverage_pct(),
        }
    }

    /// Whether any new coverage was gained.
    #[must_use]
    pub const fn has_new_coverage(&self) -> bool {
        !self.newly_covered.is_empty()
    }

    /// Whether any coverage was lost.
    #[must_use]
    pub const fn has_regression(&self) -> bool {
        !self.newly_uncovered.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record() -> LcovRecord {
        let mut r = LcovRecord::new("src/main.rs");
        r.test_name = "unit".to_owned();
        r.add_line(1, 5);
        r.add_line(2, 0);
        r.add_line(3, 3);
        r.add_function(1, "main", 1);
        r.add_branch(1, 0, 0, 2);
        r.add_branch(1, 0, 1, 0);
        r.recompute_summaries();
        r
    }

    #[test]
    fn test_lcov_record_new() {
        let r = LcovRecord::new("a.rs");
        assert_eq!(r.source_file, "a.rs");
    }

    #[test]
    fn test_lcov_record_summaries() {
        let r = make_record();
        assert_eq!(r.lf, 3);
        assert_eq!(r.lh, 2);
        assert_eq!(r.fnf, 1);
        assert_eq!(r.fnh, 1);
        assert_eq!(r.brh, 1);
    }

    #[test]
    fn test_lcov_record_line_pct() {
        let r = make_record();
        let pct = r.line_coverage_pct();
        assert!((pct - 66.666).abs() < 0.1);
    }

    #[test]
    fn test_lcov_record_branch_pct() {
        let r = make_record();
        let pct = r.branch_coverage_pct();
        assert!((pct - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_lcov_record_function_pct() {
        let r = make_record();
        assert!((r.function_coverage_pct() - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_lcov_writer_round_trip() {
        let r = make_record();
        let text = LcovWriter::write(&[r]);
        assert!(text.contains("SF:src/main.rs"));
        assert!(text.contains("TN:unit"));
        assert!(text.contains("end_of_record"));
        assert!(text.contains("DA:1,5"));
    }

    #[test]
    fn test_lcov_writer_parse_round_trip() {
        let r = make_record();
        let text = LcovWriter::write(std::slice::from_ref(&r));
        let parsed = LcovWriter::parse(&text);
        assert_eq!(parsed.len(), 1);
        let p = &parsed[0];
        assert_eq!(p.source_file, "src/main.rs");
        assert_eq!(p.lf, r.lf);
        assert_eq!(p.lh, r.lh);
    }

    #[test]
    fn test_lcov_writer_multiple_records() {
        let r1 = make_record();
        let mut r2 = make_record();
        r2.source_file = "src/lib.rs".to_owned();
        let text = LcovWriter::write(&[r1, r2]);
        let parsed = LcovWriter::parse(&text);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_lcov_writer_branch_data_roundtrip() {
        let r = make_record();
        let text = LcovWriter::write(&[r]);
        assert!(text.contains("BRDA:1,0,0,2"));
        assert!(text.contains("BRDA:1,0,1,0"));
    }

    #[test]
    fn test_coverage_report_from_record() {
        let r = make_record();
        let report = CoverageReport::from_record(&r);
        assert_eq!(report.source_file, "src/main.rs");
        assert_eq!(report.uncovered_lines, vec![2]);
        assert!(!report.is_fully_covered());
    }

    #[test]
    fn test_coverage_report_fully_covered() {
        let mut r = LcovRecord::new("x.rs");
        r.add_line(1, 1);
        r.recompute_summaries();
        let rep = CoverageReport::from_record(&r);
        assert!(rep.is_fully_covered());
    }

    #[test]
    fn test_coverage_report_summary() {
        let r = make_record();
        let rep = CoverageReport::from_record(&r);
        let s = rep.summary();
        assert!(s.contains("src/main.rs"));
    }

    #[test]
    fn test_coverage_diff_new_coverage() {
        let mut a = LcovRecord::new("f.rs");
        a.add_line(1, 1);
        a.add_line(2, 0);
        a.recompute_summaries();

        let mut b = LcovRecord::new("f.rs");
        b.add_line(1, 1);
        b.add_line(2, 3); // newly covered
        b.recompute_summaries();

        let diff = CoverageDiffReport::diff(&a, &b);
        assert!(diff.has_new_coverage());
        assert!(diff.newly_covered.contains(&2));
        assert!(!diff.has_regression());
    }

    #[test]
    fn test_coverage_diff_regression() {
        let mut a = LcovRecord::new("f.rs");
        a.add_line(1, 5);
        a.recompute_summaries();
        let mut b = LcovRecord::new("f.rs");
        b.add_line(1, 0);
        b.recompute_summaries();

        let diff = CoverageDiffReport::diff(&a, &b);
        assert!(diff.has_regression());
        assert!(!diff.has_new_coverage());
        assert!(diff.line_pct_delta < 0.0);
    }

    #[test]
    fn test_coverage_diff_no_change() {
        let r = make_record();
        let diff = CoverageDiffReport::diff(&r, &r);
        assert!(!diff.has_new_coverage());
        assert!(!diff.has_regression());
        assert!((diff.line_pct_delta).abs() < 0.001);
    }

    #[test]
    fn test_drcov_importer_empty_blob_error() {
        let result = DrcovImporter::import(b"not a drcov file", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_drcov_importer_merge_empty() {
        let result = DrcovImporter::import_and_merge(&[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().distinct_blocks(), 0);
    }

    #[test]
    fn test_lcov_writer_fn_entries() {
        let r = make_record();
        let text = LcovWriter::write(&[r]);
        assert!(text.contains("FN:1,main"));
        assert!(text.contains("FNDA:1,main"));
    }

    #[test]
    fn test_lcov_record_add_branch_count() {
        let r = make_record();
        assert_eq!(r.branch_data.len(), 2);
    }
}
