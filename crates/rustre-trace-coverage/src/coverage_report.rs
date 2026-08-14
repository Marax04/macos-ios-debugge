//! Coverage report generation — functions, basic blocks, and edges covered;
//! comparison between runs; JSON, HTML, and LCOV output formats.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as FmtWrite;

// ─── Coverage data types ──────────────────────────────────────────────────────

/// Coverage information for a single basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Start address of the block.
    pub address: u64,
    /// End address (inclusive last instruction).
    pub end_address: u64,
    /// Number of times this block was executed.
    pub hit_count: u32,
    /// Source file (if debug info available).
    pub source_file: Option<String>,
    /// Source line number of the first instruction.
    pub source_line: Option<u32>,
    /// Number of source lines this block spans.
    pub line_span: u32,
}

impl BlockInfo {
    #[must_use] 
    pub const fn is_covered(&self) -> bool {
        self.hit_count > 0
    }

    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.end_address.saturating_sub(self.address) + 1
    }
}

/// Coverage information for a control-flow edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInfo {
    pub source_block: u64,
    pub target_block: u64,
    pub hit_count: u32,
}

impl EdgeInfo {
    #[must_use] 
    pub const fn is_covered(&self) -> bool {
        self.hit_count > 0
    }
}

/// Coverage information for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCoverage {
    /// Demangled function name.
    pub name: String,
    /// Mangled name (if different).
    pub mangled_name: Option<String>,
    /// Start address.
    pub start_address: u64,
    /// End address.
    pub end_address: u64,
    /// Source file.
    pub source_file: Option<String>,
    /// Source line of function start.
    pub source_line: Option<u32>,
    /// Basic blocks belonging to this function.
    pub blocks: Vec<BlockInfo>,
    /// Edges within this function.
    pub edges: Vec<EdgeInfo>,
    /// Total number of times this function was called.
    pub call_count: u32,
}

impl FunctionCoverage {
    #[must_use] 
    pub fn covered_block_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_covered()).count()
    }

    #[must_use] 
    pub const fn total_block_count(&self) -> usize {
        self.blocks.len()
    }

    #[must_use] 
    pub fn block_coverage_pct(&self) -> f64 {
        let total = self.total_block_count();
        if total == 0 {
            return 0.0;
        }
        crate::usize_to_f64(self.covered_block_count()) / crate::usize_to_f64(total) * 100.0
    }

    #[must_use]
    pub fn covered_edge_count(&self) -> usize {
        self.edges.iter().filter(|e| e.is_covered()).count()
    }

    #[must_use] 
    pub const fn total_edge_count(&self) -> usize {
        self.edges.len()
    }

    #[must_use] 
    pub fn edge_coverage_pct(&self) -> f64 {
        let total = self.total_edge_count();
        if total == 0 {
            return 0.0;
        }
        crate::usize_to_f64(self.covered_edge_count()) / crate::usize_to_f64(total) * 100.0
    }

    #[must_use] 
    pub fn is_any_covered(&self) -> bool {
        self.blocks.iter().any(BlockInfo::is_covered)
    }

    #[must_use] 
    pub fn is_fully_covered(&self) -> bool {
        !self.blocks.is_empty() && self.blocks.iter().all(BlockInfo::is_covered)
    }
}

// ─── Coverage run ─────────────────────────────────────────────────────────────

/// A single recorded coverage run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRunReport {
    /// Run identifier / label.
    pub run_id: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Module name (binary name).
    pub module: String,
    /// Module base address.
    pub module_base: u64,
    /// Timestamp when the run was captured (UNIX seconds).
    pub timestamp: i64,
    /// Per-function coverage data.
    pub functions: Vec<FunctionCoverage>,
    /// Total unique basic blocks observed (across all functions).
    pub total_blocks: u32,
    /// Total covered basic blocks.
    pub covered_blocks: u32,
    /// Total unique edges observed.
    pub total_edges: u32,
    /// Covered edges.
    pub covered_edges: u32,
}

impl CoverageRunReport {
    pub fn new(run_id: impl Into<String>, module: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            description: None,
            module: module.into(),
            module_base: 0,
            timestamp: 0,
            functions: vec![],
            total_blocks: 0,
            covered_blocks: 0,
            total_edges: 0,
            covered_edges: 0,
        }
    }

    /// Recompute aggregate stats from the functions list.
    pub fn recompute_stats(&mut self) {
        let mut total_blocks = 0u32;
        let mut covered_blocks = 0u32;
        let mut total_edges = 0u32;
        let mut covered_edges = 0u32;
        for func in &self.functions {
            total_blocks = total_blocks.saturating_add(crate::usize_to_u32_sat(func.blocks.len()));
            covered_blocks = covered_blocks.saturating_add(crate::usize_to_u32_sat(func.covered_block_count()));
            total_edges = total_edges.saturating_add(crate::usize_to_u32_sat(func.edges.len()));
            covered_edges = covered_edges.saturating_add(crate::usize_to_u32_sat(func.covered_edge_count()));
        }
        self.total_blocks = total_blocks;
        self.covered_blocks = covered_blocks;
        self.total_edges = total_edges;
        self.covered_edges = covered_edges;
    }

    #[must_use] 
    pub fn block_coverage_pct(&self) -> f64 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        f64::from(self.covered_blocks) / f64::from(self.total_blocks) * 100.0
    }

    #[must_use] 
    pub fn edge_coverage_pct(&self) -> f64 {
        if self.total_edges == 0 {
            return 0.0;
        }
        f64::from(self.covered_edges) / f64::from(self.total_edges) * 100.0
    }

    #[must_use] 
    pub fn function_coverage_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_any_covered()).count()
    }

    #[must_use] 
    pub fn function_full_coverage_count(&self) -> usize {
        self.functions.iter().filter(|f| f.is_fully_covered()).count()
    }

    #[must_use] 
    pub fn find_function(&self, name: &str) -> Option<&FunctionCoverage> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Returns functions sorted by descending block coverage percentage.
    #[must_use] 
    pub fn functions_by_coverage(&self) -> Vec<&FunctionCoverage> {
        let mut funcs: Vec<&FunctionCoverage> = self.functions.iter().collect();
        funcs.sort_by(|a, b| {
            b.block_coverage_pct()
                .partial_cmp(&a.block_coverage_pct())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        funcs
    }

    /// Returns uncovered functions.
    #[must_use] 
    pub fn uncovered_functions(&self) -> Vec<&FunctionCoverage> {
        self.functions.iter().filter(|f| !f.is_any_covered()).collect()
    }
}

// ─── Comparison between runs ──────────────────────────────────────────────────

/// What happened to a function between two coverage runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionDelta {
    /// Function appeared in run B but not A.
    New,
    /// Function disappeared from run A but not B.
    Removed,
    /// Coverage increased.
    Improved { prev_pct: u8, curr_pct: u8 },
    /// Coverage decreased.
    Regressed { prev_pct: u8, curr_pct: u8 },
    /// Coverage unchanged.
    Unchanged { pct: u8 },
}

/// Per-function comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionComparison {
    pub name: String,
    pub delta: FunctionDelta,
    pub prev_covered_blocks: u32,
    pub curr_covered_blocks: u32,
    pub prev_covered_edges: u32,
    pub curr_covered_edges: u32,
}

/// Comparison result between two coverage runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageComparison {
    pub run_a_id: String,
    pub run_b_id: String,
    pub module: String,
    pub prev_block_pct: f64,
    pub curr_block_pct: f64,
    pub block_pct_delta: f64,
    pub prev_edge_pct: f64,
    pub curr_edge_pct: f64,
    pub edge_pct_delta: f64,
    pub newly_covered_blocks: u32,
    pub regressed_blocks: u32,
    pub function_comparisons: Vec<FunctionComparison>,
}

impl CoverageComparison {
    #[must_use] 
    pub fn compare(run_a: &CoverageRunReport, run_b: &CoverageRunReport) -> Self {
        let block_pct_delta = run_b.block_coverage_pct() - run_a.block_coverage_pct();
        let edge_pct_delta = run_b.edge_coverage_pct() - run_a.edge_coverage_pct();

        // Build lookup maps
        let a_funcs: HashMap<&str, &FunctionCoverage> =
            run_a.functions.iter().map(|f| (f.name.as_str(), f)).collect();
        let b_funcs: HashMap<&str, &FunctionCoverage> =
            run_b.functions.iter().map(|f| (f.name.as_str(), f)).collect();

        let mut all_names: HashSet<&str> = HashSet::new();
        all_names.extend(a_funcs.keys());
        all_names.extend(b_funcs.keys());

        let mut function_comparisons: Vec<FunctionComparison> = Vec::new();
        let mut newly_covered = 0u32;
        let mut regressed = 0u32;

        for &name in &all_names {
            let fa = a_funcs.get(name);
            let fb = b_funcs.get(name);

            match (fa, fb) {
                (None, Some(fb)) => {
                    newly_covered += crate::usize_to_u32_sat(fb.covered_block_count());
                    function_comparisons.push(FunctionComparison {
                        name: name.to_owned(),
                        delta: FunctionDelta::New,
                        prev_covered_blocks: 0,
                        curr_covered_blocks: crate::usize_to_u32_sat(fb.covered_block_count()),
                        prev_covered_edges: 0,
                        curr_covered_edges: crate::usize_to_u32_sat(fb.covered_edge_count()),
                    });
                }
                (Some(fa), None) => {
                    regressed += crate::usize_to_u32_sat(fa.covered_block_count());
                    function_comparisons.push(FunctionComparison {
                        name: name.to_owned(),
                        delta: FunctionDelta::Removed,
                        prev_covered_blocks: crate::usize_to_u32_sat(fa.covered_block_count()),
                        curr_covered_blocks: 0,
                        prev_covered_edges: crate::usize_to_u32_sat(fa.covered_edge_count()),
                        curr_covered_edges: 0,
                    });
                }
                (Some(fa), Some(fb)) => {
                    let prev_pct = crate::f64_to_u8_clamp(fa.block_coverage_pct());
                    let curr_pct = crate::f64_to_u8_clamp(fb.block_coverage_pct());
                    let prev_cov = crate::usize_to_u32_sat(fa.covered_block_count());
                    let curr_cov = crate::usize_to_u32_sat(fb.covered_block_count());
                    let delta = match curr_pct.cmp(&prev_pct) {
                        std::cmp::Ordering::Greater => {
                            newly_covered += curr_cov.saturating_sub(prev_cov);
                            FunctionDelta::Improved { prev_pct, curr_pct }
                        }
                        std::cmp::Ordering::Less => {
                            regressed += prev_cov.saturating_sub(curr_cov);
                            FunctionDelta::Regressed { prev_pct, curr_pct }
                        }
                        std::cmp::Ordering::Equal => FunctionDelta::Unchanged { pct: curr_pct }
                    };
                    function_comparisons.push(FunctionComparison {
                        name: name.to_owned(),
                        delta,
                        prev_covered_blocks: prev_cov,
                        curr_covered_blocks: curr_cov,
                        prev_covered_edges: crate::usize_to_u32_sat(fa.covered_edge_count()),
                        curr_covered_edges: crate::usize_to_u32_sat(fb.covered_edge_count()),
                    });
                }
                (None, None) => {}
            }
        }

        function_comparisons.sort_by(|a, b| a.name.cmp(&b.name));

        Self {
            run_a_id: run_a.run_id.clone(),
            run_b_id: run_b.run_id.clone(),
            module: run_a.module.clone(),
            prev_block_pct: run_a.block_coverage_pct(),
            curr_block_pct: run_b.block_coverage_pct(),
            block_pct_delta,
            prev_edge_pct: run_a.edge_coverage_pct(),
            curr_edge_pct: run_b.edge_coverage_pct(),
            edge_pct_delta,
            newly_covered_blocks: newly_covered,
            regressed_blocks: regressed,
            function_comparisons,
        }
    }

    #[must_use] 
    pub fn improved_functions(&self) -> Vec<&FunctionComparison> {
        self.function_comparisons
            .iter()
            .filter(|fc| matches!(fc.delta, FunctionDelta::Improved { .. } | FunctionDelta::New))
            .collect()
    }

    #[must_use] 
    pub fn regressed_functions(&self) -> Vec<&FunctionComparison> {
        self.function_comparisons
            .iter()
            .filter(|fc| {
                matches!(fc.delta, FunctionDelta::Regressed { .. } | FunctionDelta::Removed)
            })
            .collect()
    }
}

// ─── JSON output ──────────────────────────────────────────────────────────────

impl CoverageRunReport {
    /// Serialize to a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if deserialization fails.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

// ─── LCOV output ──────────────────────────────────────────────────────────────

/// Generate LCOV info format from a coverage run report.
///
/// LCOV format: TN (test name), SF (source file), FN/FNDA/FNF/FNH (function
/// records), DA (line data), LH/LF (line summary), `end_of_record`.
#[must_use] 
pub fn to_lcov(report: &CoverageRunReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "TN:{}", report.run_id);

    // Group functions by source file
    let mut by_file: BTreeMap<&str, Vec<&FunctionCoverage>> = BTreeMap::new();
    for func in &report.functions {
        let sf = func.source_file.as_deref().unwrap_or("<unknown>");
        by_file.entry(sf).or_default().push(func);
    }

    for (source_file, funcs) in &by_file {
        let _ = writeln!(out, "SF:{source_file}");

        // FN: line,name
        for func in funcs {
            if let Some(line) = func.source_line {
                let _ = writeln!(out, "FN:{},{}", line, func.name);
            }
        }

        // FNDA: count,name
        let mut fn_hit = 0u32;
        let fn_total = funcs.len();
        for func in funcs {
            let _ = writeln!(out, "FNDA:{},{}", func.call_count, func.name);
            if func.call_count > 0 {
                fn_hit += 1;
            }
        }
        let _ = writeln!(out, "FNF:{fn_total}");
        let _ = writeln!(out, "FNH:{fn_hit}");

        // DA: line,count (from block info)
        let mut line_data: BTreeMap<u32, u32> = BTreeMap::new();
        for func in funcs {
            for block in &func.blocks {
                if let Some(line) = block.source_line {
                    let entry = line_data.entry(line).or_insert(0);
                    *entry += block.hit_count;
                }
            }
        }

        let mut lines_hit = 0u32;
        let lines_total = line_data.len();
        for (line, count) in &line_data {
            let _ = writeln!(out, "DA:{line},{count}");
            if *count > 0 {
                lines_hit += 1;
            }
        }

        let _ = writeln!(out, "LH:{lines_hit}");
        let _ = writeln!(out, "LF:{lines_total}");
        let _ = writeln!(out, "end_of_record");
    }

    out
}

// ─── HTML output ──────────────────────────────────────────────────────────────

/// Generate a standalone HTML coverage report.
#[must_use] 
pub fn to_html(report: &CoverageRunReport) -> String {
    let block_pct = report.block_coverage_pct();
    let edge_pct = report.edge_coverage_pct();
    let fn_covered = report.function_coverage_count();
    let fn_total = report.functions.len();

    let pct_color = |p: f64| -> &'static str {
        if p >= 80.0 { "#2ecc71" } else if p >= 50.0 { "#f39c12" } else { "#e74c3c" }
    };

    let mut func_rows = String::new();
    for func in report.functions_by_coverage() {
        let bpct = func.block_coverage_pct();
        let epct = func.edge_coverage_pct();
        let color = pct_color(bpct);
        let _ = write!(
            func_rows,
            "<tr><td style='font-family:monospace'>{}</td>\
             <td>{}</td>\
             <td style='color:{color}'>{:.1}% ({}/{})</td>\
             <td style='color:{}'>{:.1}% ({}/{})</td></tr>",
            html_escape(&func.name),
            func.source_file.as_deref().unwrap_or("-"),
            bpct,
            func.covered_block_count(),
            func.total_block_count(),
            pct_color(epct),
            epct,
            func.covered_edge_count(),
            func.total_edge_count(),
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Coverage Report — {module}</title>
<style>
body{{font-family:sans-serif;background:#1e1e1e;color:#d4d4d4;margin:2em}}
h1{{color:#569cd6}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #444;padding:6px 12px;text-align:left}}
th{{background:#2d2d2d}}
tr:nth-child(even){{background:#252525}}
.bar-bg{{background:#333;border-radius:4px;height:16px;width:200px;display:inline-block}}
.bar-fill{{background:#569cd6;height:16px;border-radius:4px;display:inline-block}}
</style>
</head><body>
<h1>Coverage Report — {module}</h1>
<p>Run: <b>{run_id}</b> &nbsp;|&nbsp; Timestamp: {ts}</p>
<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Block coverage</td><td style='color:{bc}'>{block_pct:.1}% ({covered_blocks}/{total_blocks})</td></tr>
<tr><td>Edge coverage</td><td style='color:{ec}'>{edge_pct:.1}% ({covered_edges}/{total_edges})</td></tr>
<tr><td>Functions covered</td><td>{fn_covered}/{fn_total}</td></tr>
</table>
<h2>Functions</h2>
<table>
<tr><th>Function</th><th>Source</th><th>Block Coverage</th><th>Edge Coverage</th></tr>
{func_rows}
</table>
</body></html>"#,
        module = html_escape(&report.module),
        run_id = html_escape(&report.run_id),
        ts = report.timestamp,
        bc = pct_color(block_pct),
        block_pct = block_pct,
        covered_blocks = report.covered_blocks,
        total_blocks = report.total_blocks,
        ec = pct_color(edge_pct),
        edge_pct = edge_pct,
        covered_edges = report.covered_edges,
        total_edges = report.total_edges,
        fn_covered = fn_covered,
        fn_total = fn_total,
        func_rows = func_rows,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(name: &str, blocks_total: u32, blocks_hit: u32) -> FunctionCoverage {
        let blocks: Vec<BlockInfo> = (0..blocks_total)
            .map(|i| BlockInfo {
                address: 0x1000 + u64::from(i) * 0x10,
                end_address: 0x100F + u64::from(i) * 0x10,
                hit_count: u32::from(i < blocks_hit),
                source_file: Some("main.c".to_owned()),
                source_line: Some(10 + i),
                line_span: 1,
            })
            .collect();
        FunctionCoverage {
            name: name.to_owned(),
            mangled_name: None,
            start_address: 0x1000,
            end_address: 0x2000,
            source_file: Some("main.c".to_owned()),
            source_line: Some(10),
            blocks,
            edges: vec![],
            call_count: u32::from(blocks_hit > 0),
        }
    }

    fn make_report(run_id: &str) -> CoverageRunReport {
        let mut r = CoverageRunReport::new(run_id, "test.exe");
        r.functions.push(make_func("foo", 10, 8));
        r.functions.push(make_func("bar", 5, 0));
        r.functions.push(make_func("baz", 4, 4));
        r.recompute_stats();
        r
    }

    #[test]
    fn test_block_coverage_pct() {
        let r = make_report("run1");
        // 12 covered / 19 total
        let pct = r.block_coverage_pct();
        assert!(pct > 0.0 && pct < 100.0);
    }

    #[test]
    fn test_uncovered_functions() {
        let r = make_report("run1");
        let uncov = r.uncovered_functions();
        assert_eq!(uncov.len(), 1);
        assert_eq!(uncov[0].name, "bar");
    }

    #[test]
    fn test_json_roundtrip() {
        let r = make_report("run1");
        let json = r.to_json().unwrap();
        let r2 = CoverageRunReport::from_json(&json).unwrap();
        assert_eq!(r.run_id, r2.run_id);
        assert_eq!(r.functions.len(), r2.functions.len());
    }

    #[test]
    fn test_comparison() {
        let r1 = make_report("run1");
        let mut r2 = make_report("run2");
        // Improve bar coverage in run2
        r2.functions[1] = make_func("bar", 5, 3);
        r2.recompute_stats();
        let cmp = CoverageComparison::compare(&r1, &r2);
        assert!(cmp.block_pct_delta > 0.0);
        assert!(!cmp.improved_functions().is_empty());
    }

    #[test]
    fn test_lcov_output() {
        let r = make_report("run1");
        let lcov = to_lcov(&r);
        assert!(lcov.contains("TN:run1"));
        assert!(lcov.contains("SF:main.c"));
        assert!(lcov.contains("end_of_record"));
    }

    #[test]
    fn test_html_output() {
        let r = make_report("run1");
        let html = to_html(&r);
        assert!(html.contains("Coverage Report"));
        assert!(html.contains("foo"));
        assert!(html.contains("bar"));
    }

    #[test]
    fn test_function_sort_by_coverage() {
        let r = make_report("run1");
        let sorted = r.functions_by_coverage();
        // baz is 100%, foo is 80%, bar is 0%
        assert_eq!(sorted[0].name, "baz");
        assert_eq!(sorted[sorted.len() - 1].name, "bar");
    }
}
