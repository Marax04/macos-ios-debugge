//! `rustre-trace-coverage` —  Full Lighthouse-style code coverage recording and reporting.
//!
//! Provides:
//! - `CoverageData` / `CoverageRun`: multiple named runs with BB and edge hit maps
//! - Format loaders: `DRcov`, LCOV, custom binary (addr+count pairs), AFL bitmap
//! - Coverage merge (union with sum), diff (A-only, B-only, both)
//! - BB coloring data: `is_covered`, `visit_count` per address
//! - Function-level stats: `total_bb`, `covered_bb`, `coverage_pct`
//! - Export: `LightHouse` JSON, LCOV info, HTML report
//! - Heatmap: sorted (addr, count) for gradient display

pub mod cast_helpers;
pub use cast_helpers::*;
pub mod bb_heatmap;
pub mod coverage_bitmap;
pub mod coverage_diff;
pub mod coverage_guided_analysis;
pub mod coverage_map;
pub mod coverage_merge;
pub mod coverage_report;
pub mod differential_coverage;
pub mod drcov_import;
pub mod lighthouse_compat;
pub mod source_mapping;
pub mod coverage_bitmap_ext;
pub mod branch_coverage;
pub mod function_coverage;
pub mod coverage_visualizer;
pub mod coverage_timeline;
pub mod path_coverage;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors produced by the coverage subsystem.
#[derive(Debug, Error)]
pub enum CovError {
    /// Bitmap size mismatch.
    #[error("size mismatch: {a} != {b}")]
    SizeMismatch { a: usize, b: usize },
    /// Index out of bounds.
    #[error("invalid index: {0}")]
    InvalidIndex(usize),
    /// Source file not found.
    #[error("source file not found: {0}")]
    SourceNotFound(String),
    /// Incompatible coverage maps.
    #[error("incompatible coverage: {0}")]
    IncompatibleCoverage(String),
    /// Serialization error.
    #[error("serialization: {0}")]
    Serialization(String),
    /// Parse error.
    #[error("parse error: {0}")]
    ParseError(String),
    /// I/O error.
    #[error("io error: {0}")]
    Io(String),
}

// â"€â"€â"€ CovEdge â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A directed control-flow edge between two addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CovEdge {
    /// Source address.
    pub from: u64,
    /// Destination address.
    pub to: u64,
}

impl CovEdge {
    /// Create a new edge.
    #[must_use]
    pub const fn new(from: u64, to: u64) -> Self {
        Self { from, to }
    }
}

impl fmt::Display for CovEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}->0x{:x}", self.from, self.to)
    }
}

// â"€â"€â"€ CovBitmap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An AFL-style bit-array for edge coverage tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovBitmap {
    /// Raw byte storage.
    pub bits: Vec<u8>,
    /// Logical number of bits.
    pub size: usize,
}

impl CovBitmap {
    /// Create a zeroed bitmap of `size` bits.
    #[must_use]
    pub fn new(size: usize) -> Self {
        let bytes = if size == 0 { 0 } else { size.div_ceil(8) };
        Self {
            bits: vec![0u8; bytes],
            size,
        }
    }

    /// Create from a raw 64 KB AFL bitmap.
    #[must_use]
    pub fn from_afl_bitmap(data: &[u8]) -> Self {
        let size = data.len() * 8;
        Self {
            bits: data.to_vec(),
            size,
        }
    }

    /// Set bit `idx`.
    pub fn set(&mut self, idx: usize) {
        if idx < self.size {
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Clear bit `idx`.
    pub fn clear(&mut self, idx: usize) {
        if idx < self.size {
            self.bits[idx / 8] &= !(1 << (idx % 8));
        }
    }

    /// Toggle bit `idx`.
    pub fn toggle(&mut self, idx: usize) {
        if idx < self.size {
            self.bits[idx / 8] ^= 1 << (idx % 8);
        }
    }

    /// Test bit `idx`.
    #[must_use]
    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.size {
            return false;
        }
        (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }

    /// Count set bits.
    #[must_use]
    pub fn count_set(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Count clear bits.
    #[must_use]
    pub fn count_clear(&self) -> usize {
        self.size.saturating_sub(self.count_set())
    }

    /// Bitwise union.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let size = self.size.max(other.size);
        let bytes = size.div_ceil(8);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot =
                self.bits.get(i).copied().unwrap_or(0) | other.bits.get(i).copied().unwrap_or(0);
        }
        Self { bits: result, size }
    }

    /// Bitwise intersection.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        let size = self.size.min(other.size);
        let bytes = size.div_ceil(8);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot =
                self.bits.get(i).copied().unwrap_or(0) & other.bits.get(i).copied().unwrap_or(0);
        }
        Self { bits: result, size }
    }

    /// Bitwise difference (self AND NOT other).
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        let size = self.size;
        let bytes = size.div_ceil(8);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot =
                self.bits.get(i).copied().unwrap_or(0) & !other.bits.get(i).copied().unwrap_or(0);
        }
        Self { bits: result, size }
    }

    /// In-place OR.
    pub fn or_assign(&mut self, other: &Self) {
        let max_len = self.bits.len().max(other.bits.len());
        self.bits.resize(max_len, 0);
        self.size = self.size.max(other.size);
        for (i, &b) in other.bits.iter().enumerate() {
            self.bits[i] |= b;
        }
    }

    /// Jaccard similarity coefficient.
    #[must_use]
    pub fn jaccard(&self, other: &Self) -> f64 {
        let len = self.bits.len().max(other.bits.len());
        let mut inter = 0usize;
        let mut uni = 0usize;
        for i in 0..len {
            let a = self.bits.get(i).copied().unwrap_or(0);
            let b = other.bits.get(i).copied().unwrap_or(0);
            inter += (a & b).count_ones() as usize;
            uni += (a | b).count_ones() as usize;
        }
        if uni == 0 {
            1.0
        } else {
            usize_to_f64(inter) / usize_to_f64(uni)
        }
    }

    /// Fraction of bits set.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.size == 0 {
            return 1.0;
        }
        usize_to_f64(self.count_set()) / usize_to_f64(self.size)
    }

    /// All set bit indices.
    #[must_use]
    pub fn set_bits(&self) -> Vec<usize> {
        (0..self.size).filter(|&i| self.get(i)).collect()
    }

    /// All clear bit indices.
    #[must_use]
    pub fn clear_bits(&self) -> Vec<usize> {
        (0..self.size).filter(|&i| !self.get(i)).collect()
    }

    /// Returns `true` if all bits are set.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.count_set() == self.size
    }

    /// Returns `true` if no bits are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    /// Record an AFL edge (hash of `prev_pc` ^ `cur_pc`).
    pub fn record_edge(&mut self, prev_pc: u64, cur_pc: u64) {
        if self.size > 0 {
            let hash = u64_to_usize_sat(prev_pc ^ cur_pc) % self.size;
            self.set(hash);
        }
    }
}

// â"€â"€â"€ CoverageRun â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// One named coverage run: a set of basic-block and edge hit counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRun {
    /// Name/label for this run (e.g., "fuzz-input-42").
    pub name: String,
    /// Basic-block start addresses -> hit count.
    pub bb_hits: HashMap<u64, u64>,
    /// Edge (from, to) -> hit count.
    pub edge_hits: HashMap<(u64, u64), u64>,
    /// Unix timestamp of when this run was recorded (0 = unknown).
    pub timestamp: u64,
    /// Optional source file tag.
    pub source_tag: String,
}

impl CoverageRun {
    /// Create an empty run.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bb_hits: HashMap::new(),
            edge_hits: HashMap::new(),
            timestamp: 0,
            source_tag: String::new(),
        }
    }

    /// Set the timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    /// Set the source tag.
    #[must_use]
    pub fn with_source_tag(mut self, tag: impl Into<String>) -> Self {
        self.source_tag = tag.into();
        self
    }

    /// Record a basic-block hit.
    pub fn record_bb(&mut self, addr: u64) {
        *self.bb_hits.entry(addr).or_insert(0) += 1;
    }

    /// Record N basic-block hits.
    pub fn record_bb_n(&mut self, addr: u64, n: u64) {
        *self.bb_hits.entry(addr).or_insert(0) += n;
    }

    /// Record a directed edge hit.
    pub fn record_edge(&mut self, from: u64, to: u64) {
        *self.edge_hits.entry((from, to)).or_insert(0) += 1;
    }

    /// Record N edge hits.
    pub fn record_edge_n(&mut self, from: u64, to: u64, n: u64) {
        *self.edge_hits.entry((from, to)).or_insert(0) += n;
    }

    /// Returns `true` if `addr` was covered.
    #[must_use]
    pub fn is_covered(&self, addr: u64) -> bool {
        self.bb_hits.contains_key(&addr)
    }

    /// Visit count for `addr` (0 if not covered).
    #[must_use]
    pub fn visit_count(&self, addr: u64) -> u64 {
        self.bb_hits.get(&addr).copied().unwrap_or(0)
    }

    /// Number of unique BBs covered.
    #[must_use]
    pub fn unique_bbs(&self) -> usize {
        self.bb_hits.len()
    }

    /// Number of unique edges covered.
    #[must_use]
    pub fn unique_edges(&self) -> usize {
        self.edge_hits.len()
    }

    /// Total BB executions.
    #[must_use]
    pub fn total_bb_executions(&self) -> u64 {
        self.bb_hits.values().sum()
    }

    /// Hot basic blocks (sorted by count descending).
    #[must_use]
    pub fn hot_bbs(&self, n: usize) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.bb_hits.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Heatmap: sorted list of (addr, count) for gradient display.
    #[must_use]
    pub fn heatmap(&self) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.bb_hits.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_unstable_by_key(|(a, _)| *a);
        pairs
    }
}

// â"€â"€â"€ CoverageData â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Container for multiple coverage runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageData {
    /// All recorded runs.
    pub runs: Vec<CoverageRun>,
    /// Human-readable label for this dataset.
    pub label: String,
}

impl CoverageData {
    /// Create an empty dataset.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            runs: Vec::new(),
            label: label.into(),
        }
    }

    /// Add a run.
    pub fn add_run(&mut self, run: CoverageRun) {
        self.runs.push(run);
    }

    /// Merge all runs into a single `CoverageRun` (union with sum).
    #[must_use]
    pub fn merge_all(&self) -> CoverageRun {
        let mut merged = CoverageRun::new(&self.label);
        for run in &self.runs {
            for (&addr, &count) in &run.bb_hits {
                *merged.bb_hits.entry(addr).or_insert(0) += count;
            }
            for (&(from, to), &count) in &run.edge_hits {
                *merged.edge_hits.entry((from, to)).or_insert(0) += count;
            }
        }
        merged
    }

    /// Number of runs.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Total unique BBs across all runs (union).
    #[must_use]
    pub fn total_unique_bbs(&self) -> usize {
        self.runs
            .iter()
            .flat_map(|r| r.bb_hits.keys())
            .collect::<HashSet<_>>()
            .len()
    }

    /// All unique BB addresses across all runs.
    #[must_use]
    pub fn all_bb_addresses(&self) -> HashSet<u64> {
        self.runs
            .iter()
            .flat_map(|r| r.bb_hits.keys().copied())
            .collect()
    }
}

// â"€â"€â"€ CoverageDiff â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Difference between two coverage runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDiff {
    /// BBs only in run A.
    pub new_in_a: HashSet<u64>,
    /// BBs only in run B.
    pub new_in_b: HashSet<u64>,
    /// BBs present in both.
    pub in_both: HashSet<u64>,
    /// Edge (from,to) only in A.
    pub edges_only_in_a: HashSet<(u64, u64)>,
    /// Edge (from,to) only in B.
    pub edges_only_in_b: HashSet<(u64, u64)>,
    /// Jaccard similarity of BB coverage.
    pub jaccard: f64,
}

impl CoverageDiff {
    /// Compute the diff between two runs.
    #[must_use]
    pub fn compute(a: &CoverageRun, b: &CoverageRun) -> Self {
        let set_a: HashSet<u64> = a.bb_hits.keys().copied().collect();
        let set_b: HashSet<u64> = b.bb_hits.keys().copied().collect();
        let ea: HashSet<(u64, u64)> = a.edge_hits.keys().copied().collect();
        let eb: HashSet<(u64, u64)> = b.edge_hits.keys().copied().collect();

        let new_in_a: HashSet<u64> = set_a.difference(&set_b).copied().collect();
        let new_in_b: HashSet<u64> = set_b.difference(&set_a).copied().collect();
        let in_both: HashSet<u64> = set_a.intersection(&set_b).copied().collect();
        let uni = set_a.union(&set_b).count();
        let jaccard = if uni == 0 {
            1.0
        } else {
            usize_to_f64(in_both.len()) / usize_to_f64(uni)
        };

        Self {
            new_in_a,
            new_in_b,
            in_both,
            edges_only_in_a: ea.difference(&eb).copied().collect(),
            edges_only_in_b: eb.difference(&ea).copied().collect(),
            jaccard,
        }
    }

    /// Overlap percentage (0-100).
    #[must_use]
    pub fn overlap_pct(&self) -> f64 {
        self.jaccard * 100.0
    }
}

// â"€â"€â"€ FunctionStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Function-level coverage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionStats {
    /// Function name.
    pub name: String,
    /// Start address.
    pub start_addr: u64,
    /// End address (exclusive).
    pub end_addr: u64,
    /// Total basic blocks in this function.
    pub total_bb: usize,
    /// Covered basic blocks.
    pub covered_bb: usize,
    /// Number of times this function was called.
    pub call_count: u64,
}

impl FunctionStats {
    /// Create a new function stats record.
    #[must_use]
    pub fn new(name: impl Into<String>, start_addr: u64, end_addr: u64, total_bb: usize) -> Self {
        Self {
            name: name.into(),
            start_addr,
            end_addr,
            total_bb,
            covered_bb: 0,
            call_count: 0,
        }
    }

    /// Coverage percentage for this function (0-100).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.total_bb == 0 {
            return 100.0;
        }
        usize_to_f64(self.covered_bb) / usize_to_f64(self.total_bb) * 100.0
    }

    /// Returns `true` if this function has been called at least once.
    #[must_use]
    pub const fn was_called(&self) -> bool {
        self.call_count > 0
    }

    /// Returns `true` if every basic block in this function was covered.
    #[must_use]
    pub const fn is_fully_covered(&self) -> bool {
        self.covered_bb >= self.total_bb && self.total_bb > 0
    }
}

/// Computes per-function coverage stats from a run and a function table.
#[must_use]
pub fn compute_function_stats(
    run: &CoverageRun,
    functions: &[FunctionStats],
) -> Vec<FunctionStats> {
    functions
        .iter()
        .map(|f| {
            let mut fs = f.clone();
            // Count which BBs in this address range were covered.
            let covered = run
                .bb_hits
                .keys()
                .filter(|&&addr| addr >= f.start_addr && addr < f.end_addr)
                .count();
            fs.covered_bb = covered;
            // Approximate call count from BB hit count at entry point.
            fs.call_count = run.bb_hits.get(&f.start_addr).copied().unwrap_or(0);
            fs
        })
        .collect()
}

// â"€â"€â"€ DRcov Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Module entry from a `DRcov` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovModule {
    pub id: u32,
    pub base: u64,
    pub end: u64,
    pub name: String,
}

/// Basic block entry from a `DRcov` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovBasicBlock {
    pub start: u64,
    pub size: u16,
    pub mod_id: u16,
}

/// Parsed `DRcov` coverage data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovData {
    pub modules: Vec<DrcovModule>,
    pub basic_blocks: Vec<DrcovBasicBlock>,
}

impl DrcovData {
    /// Parse a `DRcov` text-format file.
    ///
    /// Supports the standard:
    /// ```text
    /// DRCOV VERSION: 2
    /// DRCOV FLAVOR: drcov
    /// Module Table: version 2, count N
    /// Columns: id, base, end, entry, checksum, timestamp, path
    /// 0, 0x400000, 0x500000, 0x401000, 0xABCD, 0x1234, /path/to/binary
    /// BB Table: N bbs
    /// 0x1234, 10, 0
    /// ```
    #[must_use]
    pub fn parse(input: &str) -> Self {
        let mut modules = Vec::new();
        let mut basic_blocks = Vec::new();
        let mut in_modules = false;
        let mut in_bbs = false;

        for line in input.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with("DRCOV VERSION:")
                || line.starts_with("DRCOV FLAVOR:")
            {
                continue;
            }
            if line.starts_with("Module Table:") {
                in_modules = true;
                in_bbs = false;
                continue;
            }
            if line.starts_with("BB Table:") {
                in_bbs = true;
                in_modules = false;
                continue;
            }
            if line.starts_with("Columns:") {
                continue;
            }
            if in_modules {
                let parts: Vec<&str> = line.splitn(7, ',').map(str::trim).collect();
                if parts.len() >= 3 {
                    let id = parts[0].parse::<u32>().unwrap_or(0);
                    let base = parse_hex_or_dec(parts[1]);
                    let end = parse_hex_or_dec(parts[2]);
                    let path = parts.get(6).copied().unwrap_or("unknown");
                    let name = path.rsplit(['/', '\\']).next().unwrap_or("unknown").to_string();
                    modules.push(DrcovModule {
                        id,
                        base,
                        end,
                        name,
                    });
                }
            } else if in_bbs {
                let parts: Vec<&str> = line.splitn(3, ',').map(str::trim).collect();
                if parts.len() >= 3 {
                    let start = parse_hex_or_dec(parts[0]);
                    let size = parts[1].parse::<u16>().unwrap_or(0);
                    let mod_id = parts[2].parse::<u16>().unwrap_or(0);
                    basic_blocks.push(DrcovBasicBlock {
                        start,
                        size,
                        mod_id,
                    });
                }
            }
        }

        Self {
            modules,
            basic_blocks,
        }
    }

    /// Resolve BB absolute addresses.
    #[must_use]
    pub fn resolve_addresses(&self) -> Vec<u64> {
        let mod_map: HashMap<u16, u64> =
            self.modules.iter().map(|m| (u32_to_u16_sat(m.id), m.base)).collect();
        self.basic_blocks
            .iter()
            .filter_map(|bb| mod_map.get(&bb.mod_id).map(|base| base + bb.start))
            .collect()
    }

    /// Convert to a `CoverageRun`.
    #[must_use]
    pub fn to_run(&self, name: impl Into<String>) -> CoverageRun {
        let mut run = CoverageRun::new(name);
        for addr in self.resolve_addresses() {
            run.record_bb(addr);
        }
        run
    }
}

/// Parse a string as hex (0x prefix) or decimal.
fn parse_hex_or_dec(s: &str) -> u64 {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(
        || s.parse::<u64>().unwrap_or(0),
        |hex| u64::from_str_radix(hex, 16).unwrap_or(0),
    )
}

// â"€â"€â"€ LCOV Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// One record from an LCOV info file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LcovRecord {
    /// Source file path (from SF: line).
    pub source_file: String,
    /// Test name (from TN: line).
    pub test_name: String,
    /// Line number -> hit count (from DA: lines).
    pub line_hits: BTreeMap<u64, u64>,
    /// Function name -> (line, hits) (from FN/FNDA lines).
    pub function_hits: HashMap<String, (u64, u64)>,
    /// Branch hits: (line, block, branch) -> count.
    pub branch_hits: HashMap<(u64, u64, u64), u64>,
    /// Total lines found (from LF:).
    pub lines_found: u64,
    /// Total lines hit (from LH:).
    pub lines_hit: u64,
    /// Total functions found (from FNF:).
    pub functions_found: u64,
    /// Total functions hit (from FNH:).
    pub functions_hit: u64,
    /// Total branches found (from BRF:).
    pub branches_found: u64,
    /// Total branches hit (from BRH:).
    pub branches_hit: u64,
}

impl LcovRecord {
    /// Create an empty record.
    #[must_use]
    pub fn new() -> Self {
        Self {
            source_file: String::new(),
            test_name: String::new(),
            line_hits: BTreeMap::new(),
            function_hits: HashMap::new(),
            branch_hits: HashMap::new(),
            lines_found: 0,
            lines_hit: 0,
            functions_found: 0,
            functions_hit: 0,
            branches_found: 0,
            branches_hit: 0,
        }
    }

    /// Line coverage ratio.
    #[must_use]
    pub fn line_coverage_ratio(&self) -> f64 {
        if self.lines_found == 0 {
            1.0
        } else {
            crate::u64_to_f64(self.lines_hit) / crate::u64_to_f64(self.lines_found)
        }
    }

    /// Function coverage ratio.
    #[must_use]
    pub fn function_coverage_ratio(&self) -> f64 {
        if self.functions_found == 0 {
            1.0
        } else {
            crate::u64_to_f64(self.functions_hit) / crate::u64_to_f64(self.functions_found)
        }
    }
}

impl Default for LcovRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an LCOV info file into a list of records (one per `end_of_record`).
///
/// Understands: TN:, SF:, FN:, FNDA:, FNF:, FNH:, DA:, BRDA:, BRF:, BRH:,
/// LF:, LH:, `end_of_record`.
#[must_use]
pub fn parse_lcov(input: &str) -> Vec<LcovRecord> {
    let mut records = Vec::new();
    let mut current = LcovRecord::new();
    // Track FN: name -> line mappings for joining with FNDA:
    let mut fn_line_map: HashMap<String, u64> = HashMap::new();

    for line in input.lines() {
        let line = line.trim();
        if line == "end_of_record" {
            records.push(current);
            current = LcovRecord::new();
            fn_line_map.clear();
            continue;
        }
        if let Some(val) = line.strip_prefix("TN:") {
            current.test_name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("SF:") {
            current.source_file = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("FN:") {
            // FN:<line>,<name>
            let parts: Vec<&str> = val.splitn(2, ',').collect();
            if parts.len() == 2 {
                let line_no = parts[0].trim().parse::<u64>().unwrap_or(0);
                let name = parts[1].trim().to_string();
                fn_line_map.insert(name, line_no);
            }
        } else if let Some(val) = line.strip_prefix("FNDA:") {
            // FNDA:<count>,<name>
            let parts: Vec<&str> = val.splitn(2, ',').collect();
            if parts.len() == 2 {
                let count = parts[0].trim().parse::<u64>().unwrap_or(0);
                let name = parts[1].trim().to_string();
                let fn_line = fn_line_map.get(&name).copied().unwrap_or(0);
                current.function_hits.insert(name, (fn_line, count));
            }
        } else if let Some(val) = line.strip_prefix("DA:") {
            // DA:<line>,<count>
            let parts: Vec<&str> = val.splitn(2, ',').collect();
            if parts.len() == 2 {
                let line_no = parts[0].trim().parse::<u64>().unwrap_or(0);
                let count = parts[1].trim().parse::<u64>().unwrap_or(0);
                current.line_hits.insert(line_no, count);
            }
        } else if let Some(val) = line.strip_prefix("BRDA:") {
            // BRDA:<line>,<block>,<branch>,<count>
            let parts: Vec<&str> = val.splitn(4, ',').collect();
            if parts.len() == 4 {
                let ln = parts[0].trim().parse::<u64>().unwrap_or(0);
                let blk = parts[1].trim().parse::<u64>().unwrap_or(0);
                let br = parts[2].trim().parse::<u64>().unwrap_or(0);
                let count = parts[3].trim().parse::<u64>().unwrap_or(0);
                current.branch_hits.insert((ln, blk, br), count);
            }
        } else if let Some(val) = line.strip_prefix("LF:") {
            current.lines_found = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("LH:") {
            current.lines_hit = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("FNF:") {
            current.functions_found = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("FNH:") {
            current.functions_hit = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("BRF:") {
            current.branches_found = val.trim().parse::<u64>().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("BRH:") {
            current.branches_hit = val.trim().parse::<u64>().unwrap_or(0);
        }
    }
    // Handle trailing record without end_of_record
    if !current.source_file.is_empty() {
        records.push(current);
    }
    records
}

/// Serialize a list of `LcovRecord`s back to LCOV info format.
#[must_use]
pub fn to_lcov_string(records: &[LcovRecord]) -> String {
    let mut out = String::new();
    for rec in records {
        writeln!(out, "TN:{}", rec.test_name).ok();
        writeln!(out, "SF:{}", rec.source_file).ok();
        for (name, (line, _)) in &rec.function_hits {
            writeln!(out, "FN:{line},{name}").ok();
        }
        for (name, (_, count)) in &rec.function_hits {
            writeln!(out, "FNDA:{count},{name}").ok();
        }
        writeln!(out, "FNF:{}", rec.functions_found).ok();
        writeln!(out, "FNH:{}", rec.functions_hit).ok();
        for (line, count) in &rec.line_hits {
            writeln!(out, "DA:{line},{count}").ok();
        }
        for ((ln, blk, br), count) in &rec.branch_hits {
            writeln!(out, "BRDA:{ln},{blk},{br},{count}").ok();
        }
        writeln!(out, "BRF:{}", rec.branches_found).ok();
        writeln!(out, "BRH:{}", rec.branches_hit).ok();
        writeln!(out, "LF:{}", rec.lines_found).ok();
        writeln!(out, "LH:{}", rec.lines_hit).ok();
        out.push_str("end_of_record\n");
    }
    out
}

// â"€â"€â"€ Custom Binary Format Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse a custom binary coverage format: repeated (u64 addr, u64 count) pairs (little-endian).
///
/// # Errors
/// Returns `CovError::ParseError` if the data length is not a multiple of 16.
///
/// # Panics
/// Panics if the internal slice-to-array conversion fails (cannot happen when
/// `data.len()` is a multiple of 16).
pub fn parse_custom_binary(data: &[u8]) -> Result<CoverageRun, CovError> {
    if !data.len().is_multiple_of(16) {
        return Err(CovError::ParseError(format!(
            "custom binary: length {} is not a multiple of 16",
            data.len()
        )));
    }
    let mut run = CoverageRun::new("custom_binary");
    for chunk in data.chunks_exact(16) {
        let addr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let count = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        run.record_bb_n(addr, count);
    }
    Ok(run)
}

/// Serialize a coverage run to the custom binary format.
#[must_use]
pub fn to_custom_binary(run: &CoverageRun) -> Vec<u8> {
    let mut out = Vec::with_capacity(run.bb_hits.len() * 16);
    for (&addr, &count) in &run.bb_hits {
        out.extend_from_slice(&addr.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
    }
    out
}

// â"€â"€â"€ AFL Bitmap Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Load an AFL-style 64 KB edge coverage bitmap into a `CovBitmap`.
///
/// Each set bit at position `i` means that the hash of some edge `(prev_pc ^ cur_pc) % 65536`
/// was triggered at least once during fuzzing.
#[must_use]
pub fn load_afl_bitmap(data: &[u8]) -> CovBitmap {
    CovBitmap::from_afl_bitmap(data)
}

/// Count the number of edges set in an AFL bitmap.
#[must_use]
pub fn afl_bitmap_coverage(bitmap: &CovBitmap) -> usize {
    bitmap.count_set()
}

/// Compare two AFL bitmaps and return how many new edges are in `b` vs `a`.
#[must_use]
pub fn afl_new_coverage(a: &CovBitmap, b: &CovBitmap) -> usize {
    let diff = b.difference(a);
    diff.count_set()
}

// â"€â"€â"€ CoverageMerge â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Merge two `CoverageRun`s into one by summing all hit counts (union).
#[must_use]
pub fn merge_runs(a: &CoverageRun, b: &CoverageRun, name: impl Into<String>) -> CoverageRun {
    let mut merged = a.clone();
    merged.name = name.into();
    for (&addr, &count) in &b.bb_hits {
        *merged.bb_hits.entry(addr).or_insert(0) += count;
    }
    for (&(from, to), &count) in &b.edge_hits {
        *merged.edge_hits.entry((from, to)).or_insert(0) += count;
    }
    merged
}

/// Merge all runs in a `CoverageData` into one.
#[must_use]
pub fn merge_all_runs(data: &CoverageData) -> CoverageRun {
    data.merge_all()
}

// â"€â"€â"€ LightHouse JSON Export â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// LightHouse-compatible JSON export of a coverage run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LighthouseJson {
    pub name: String,
    /// Map from hex address string to hit count.
    pub coverage: HashMap<String, u64>,
    pub timestamp: u64,
}

impl LighthouseJson {
    /// Create from a `CoverageRun`.
    #[must_use]
    pub fn from_run(run: &CoverageRun) -> Self {
        let coverage = run
            .bb_hits
            .iter()
            .map(|(&addr, &count)| (format!("0x{addr:x}"), count))
            .collect();
        Self {
            name: run.name.clone(),
            coverage,
            timestamp: run.timestamp,
        }
    }

    /// Serialize to JSON string.
    ///
    /// # Errors
    /// Returns `CovError::Serialization` on failure.
    pub fn to_json(&self) -> Result<String, CovError> {
        serde_json::to_string_pretty(self).map_err(|e| CovError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    ///
    /// # Errors
    /// Returns `CovError::ParseError` on failure.
    pub fn from_json(s: &str) -> Result<Self, CovError> {
        serde_json::from_str(s).map_err(|e| CovError::ParseError(e.to_string()))
    }

    /// Convert back to a `CoverageRun`.
    #[must_use]
    pub fn to_run(&self) -> CoverageRun {
        let mut run = CoverageRun::new(&self.name);
        run.timestamp = self.timestamp;
        for (addr_str, &count) in &self.coverage {
            let addr = parse_hex_or_dec(addr_str);
            run.record_bb_n(addr, count);
        }
        run
    }
}

// â"€â"€â"€ HTML Report â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Generate a minimal HTML coverage report for a list of function stats.
#[must_use]
pub fn generate_html_report(
    title: &str,
    run: &CoverageRun,
    function_stats: &[FunctionStats],
) -> String {
    let total_bbs: usize = run.bb_hits.len();
    let total_executions: u64 = run.total_bb_executions();
    let unique_edges: usize = run.unique_edges();

    let mut rows = String::new();
    for fs in function_stats {
        let pct = fs.coverage_pct();
        let color = if pct >= 80.0 {
            "#2ecc71"
        } else if pct >= 50.0 {
            "#f39c12"
        } else {
            "#e74c3c"
        };
        writeln!(rows,
            "<tr><td><code>{}</code></td><td>0x{:x}</td><td>{}/{}</td>\
             <td style=\"background:{};color:white\">{:.1}%</td><td>{}</td></tr>",
            fs.name, fs.start_addr, fs.covered_bb, fs.total_bb, color, pct, fs.call_count
        ).ok();
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{title}</title>
<style>
  body {{ font-family: sans-serif; margin: 2em; background: #1a1a2e; color: #e0e0e0; }}
  h1 {{ color: #00d4ff; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
  th {{ background: #16213e; }}
  tr:nth-child(even) {{ background: #0f3460; }}
  .stat {{ display: inline-block; margin: 1em; padding: 1em; background: #16213e; border-radius: 8px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div>
  <span class="stat">BBs Covered: <b>{total_bbs}</b></span>
  <span class="stat">Total Executions: <b>{total_executions}</b></span>
  <span class="stat">Unique Edges: <b>{unique_edges}</b></span>
</div>
<h2>Function Coverage</h2>
<table>
<tr><th>Function</th><th>Address</th><th>BBs</th><th>Coverage</th><th>Calls</th></tr>
{rows}
</table>
</body>
</html>
"#
    )
}

// â"€â"€â"€ Heatmap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A sorted coverage heatmap for display as a gradient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageHeatmap {
    /// Sorted list of (address, `normalised_heat`) where heat is in [0.0, 1.0].
    pub entries: Vec<(u64, f64)>,
    /// Maximum raw hit count.
    pub max_count: u64,
}

impl CoverageHeatmap {
    /// Build from a coverage run.
    #[must_use]
    pub fn build(run: &CoverageRun) -> Self {
        let max_count = run.bb_hits.values().copied().max().unwrap_or(1);
        let mut entries: Vec<(u64, f64)> = run
            .bb_hits
            .iter()
            .map(|(&addr, &count)| (addr, crate::u64_to_f64(count) / crate::u64_to_f64(max_count)))
            .collect();
        entries.sort_unstable_by_key(|(a, _)| *a);
        Self { entries, max_count }
    }

    /// Heat at a specific address (0.0 if not covered).
    #[must_use]
    pub fn heat_at(&self, addr: u64) -> f64 {
        self.entries
            .iter()
            .find(|(a, _)| *a == addr)
            .map_or(0.0, |(_, h)| *h)
    }

    /// Top-N hottest entries.
    #[must_use]
    pub fn hottest(&self, n: usize) -> Vec<(u64, f64)> {
        let mut sorted = self.entries.clone();
        sorted.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(n);
        sorted
    }
}

// â"€â"€â"€ BlockColorInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// BB coloring data for a single address in the binary view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockColorInfo {
    /// Basic block start address.
    pub addr: u64,
    /// Whether this block was covered.
    pub is_covered: bool,
    /// Number of times this block was visited.
    pub visit_count: u64,
    /// Normalised heat (0.0-1.0).
    pub heat: f64,
}

impl BlockColorInfo {
    /// Create from a run.
    #[must_use]
    pub fn for_addr(run: &CoverageRun, addr: u64, max_count: u64) -> Self {
        let count = run.bb_hits.get(&addr).copied().unwrap_or(0);
        let max = max_count.max(1);
        Self {
            addr,
            is_covered: count > 0,
            visit_count: count,
            heat: crate::u64_to_f64(count) / crate::u64_to_f64(max),
        }
    }

    /// RGBA color for the block based on heat.
    #[must_use]
    pub fn rgba_color(&self) -> (u8, u8, u8, u8) {
        if !self.is_covered {
            return (64, 64, 64, 255); // grey = not covered
        }
        // Scale from blue (cold) to red (hot)
        let h = self.heat;
        let r = crate::f64_to_u8_clamp(255.0 * h);
        let g = crate::f64_to_u8_clamp(128.0 * (1.0 - h));
        let b = crate::f64_to_u8_clamp(255.0 * (1.0 - h));
        (r, g, b, 255)
    }
}

/// Generate color info for all known addresses in a run.
#[must_use]
pub fn generate_block_colors(run: &CoverageRun, known_addrs: &[u64]) -> Vec<BlockColorInfo> {
    let max_count = run.bb_hits.values().copied().max().unwrap_or(1);
    known_addrs
        .iter()
        .map(|&addr| BlockColorInfo::for_addr(run, addr, max_count))
        .collect()
}

// â"€â"€â"€ CoverageSession â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A named analysis session that accumulates multiple coverage runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSession {
    /// Session name.
    pub name: String,
    /// Accumulated data.
    pub data: CoverageData,
    /// AFL-style bitmap for fast new-coverage detection.
    pub bitmap: CovBitmap,
}

impl CoverageSession {
    /// Create a new session.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let nm = name.into();
        Self {
            name: nm.clone(),
            data: CoverageData::new(nm),
            bitmap: CovBitmap::new(65536),
        }
    }

    /// Add a run to the session and update the bitmap.
    pub fn add_run(&mut self, run: CoverageRun) {
        // Update bitmap with new BB addresses.
        if self.bitmap.size > 0 {
            for &addr in run.bb_hits.keys() {
                let bit = crate::u64_to_usize_sat(addr) % self.bitmap.size;
                self.bitmap.set(bit);
            }
        }
        self.data.add_run(run);
    }

    /// Merged view of all runs.
    #[must_use]
    pub fn merged(&self) -> CoverageRun {
        self.data.merge_all()
    }

    /// Number of runs.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.data.run_count()
    }

    /// Bitmap coverage ratio.
    #[must_use]
    pub fn bitmap_coverage(&self) -> f64 {
        self.bitmap.coverage_ratio()
    }

    /// Export merged run as `LightHouse` JSON.
    ///
    /// # Errors
    /// Returns `CovError::Serialization` on serialization failure.
    pub fn export_lighthouse_json(&self) -> Result<String, CovError> {
        let merged = self.merged();
        LighthouseJson::from_run(&merged).to_json()
    }

    /// Export as LCOV info string (using address/4 + 1 as pseudo line numbers).
    #[must_use]
    pub fn export_lcov(&self) -> String {
        let merged = self.merged();
        let mut rec = LcovRecord::new();
        rec.source_file.clone_from(&self.name);
        for (&addr, &count) in &merged.bb_hits {
            // Use the raw address as the line key to avoid collisions from the
            // previous (addr / 4) + 1 mapping, which silently merged distinct
            // addresses that fell in the same 4-byte bucket.
            rec.line_hits.insert(addr, count);
        }
        rec.lines_found = u64::try_from(rec.line_hits.len()).unwrap_or(u64::MAX);
        rec.lines_hit = u64::try_from(rec.line_hits.values().filter(|&&c| c > 0).count()).unwrap_or(u64::MAX);
        to_lcov_string(&[rec])
    }

    /// Generate a coverage summary struct.
    #[must_use]
    pub fn summary(&self) -> CoverageSummary {
        let merged = self.merged();
        CoverageSummary {
            session_name: self.name.clone(),
            run_count: self.run_count(),
            unique_bbs: merged.unique_bbs(),
            unique_edges: merged.unique_edges(),
            total_executions: merged.total_bb_executions(),
            bitmap_coverage_ratio: self.bitmap_coverage(),
        }
    }
}

// â"€â"€â"€ CoverageSummary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Summary statistics for a coverage session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub session_name: String,
    pub run_count: usize,
    pub unique_bbs: usize,
    pub unique_edges: usize,
    pub total_executions: u64,
    pub bitmap_coverage_ratio: f64,
}

impl fmt::Display for CoverageSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoverageSession({}) runs={} unique_bbs={} unique_edges={} total_exec={} bitmap={:.1}%",
            self.session_name,
            self.run_count,
            self.unique_bbs,
            self.unique_edges,
            self.total_executions,
            self.bitmap_coverage_ratio * 100.0,
        )
    }
}

// â"€â"€â"€ CoverageComparator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Compares two sessions and reports new/regressed coverage.
pub struct CoverageComparator {
    pub baseline: CoverageRun,
    pub current: CoverageRun,
}

impl CoverageComparator {
    /// Create a new comparator.
    #[must_use]
    pub const fn new(baseline: CoverageRun, current: CoverageRun) -> Self {
        Self { baseline, current }
    }

    /// Compute the diff.
    #[must_use]
    pub fn diff(&self) -> CoverageDiff {
        CoverageDiff::compute(&self.baseline, &self.current)
    }

    /// BBs gained (in current but not baseline).
    #[must_use]
    pub fn gained(&self) -> HashSet<u64> {
        self.diff().new_in_b
    }

    /// BBs lost (in baseline but not current —" regressions).
    #[must_use]
    pub fn lost(&self) -> HashSet<u64> {
        self.diff().new_in_a
    }

    /// Coverage delta: current - baseline in unique BB count.
    #[must_use]
    pub fn delta_bbs(&self) -> i64 {
        let gained = crate::usize_to_i64_sat(self.gained().len());
        let lost = crate::usize_to_i64_sat(self.lost().len());
        gained - lost
    }
}

// â"€â"€â"€ CoverageDatabase â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// In-memory coverage storage (no `SQLite` dependency).
#[derive(Debug, Clone, Default)]
pub struct CoverageDatabase {
    /// `session_id` -> (name, `bb_hits`)
    sessions: HashMap<u64, (String, HashMap<u64, u64>)>,
    next_id: u64,
}

impl CoverageDatabase {
    /// Create a new empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new session, returning its ID.
    pub fn create_session(&mut self, name: &str) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(id, (name.to_string(), HashMap::new()));
        id
    }

    /// Record a hit for `address` in `session_id`.
    ///
    /// # Errors
    /// Returns `CovError::InvalidIndex` if `session_id` does not exist.
    pub fn record_hit(&mut self, session_id: u64, address: u64) -> Result<(), CovError> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| CovError::InvalidIndex(crate::u64_to_usize_sat(session_id)))?;
        *session.1.entry(address).or_insert(0) += 1;
        Ok(())
    }

    /// Get hit count for `address` in `session_id`.
    #[must_use]
    pub fn get_hits(&self, session_id: u64, address: u64) -> u64 {
        self.sessions
            .get(&session_id)
            .and_then(|(_, hits)| hits.get(&address))
            .copied()
            .unwrap_or(0)
    }

    /// Export a session as a `CoverageRun`.
    ///
    /// # Errors
    /// Returns `CovError::InvalidIndex` if `session_id` does not exist.
    pub fn export_run(&self, session_id: u64) -> Result<CoverageRun, CovError> {
        let (name, hits) = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| CovError::InvalidIndex(crate::u64_to_usize_sat(session_id)))?;
        let mut run = CoverageRun::new(name.as_str());
        for (&addr, &count) in hits {
            run.record_bb_n(addr, count);
        }
        Ok(run)
    }

    /// All session IDs.
    #[must_use]
    pub fn session_ids(&self) -> Vec<u64> {
        self.sessions.keys().copied().collect()
    }

    /// Number of sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// â"€â"€â"€ EdgeMap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Tracks directed control-flow edges with hit counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeMap {
    pub edges: HashMap<CovEdge, u64>,
}

impl EdgeMap {
    /// Create an empty edge map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hit for edge `from -> to`.
    pub fn record(&mut self, from: u64, to: u64) {
        *self.edges.entry(CovEdge { from, to }).or_insert(0) += 1;
    }

    /// Record N hits.
    pub fn record_n(&mut self, from: u64, to: u64, n: u64) {
        *self.edges.entry(CovEdge { from, to }).or_insert(0) += n;
    }

    /// Returns `true` if the edge was recorded.
    #[must_use]
    pub fn contains(&self, from: u64, to: u64) -> bool {
        self.edges.contains_key(&CovEdge { from, to })
    }

    /// Hit count for an edge.
    #[must_use]
    pub fn hit_count(&self, from: u64, to: u64) -> u64 {
        self.edges.get(&CovEdge { from, to }).copied().unwrap_or(0)
    }

    /// Total unique edges.
    #[must_use]
    pub fn count(&self) -> usize {
        self.edges.len()
    }

    /// Total hits.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.edges.values().sum()
    }

    /// Merge another edge map.
    pub fn merge(&mut self, other: &Self) {
        for (e, &c) in &other.edges {
            *self.edges.entry(e.clone()).or_insert(0) += c;
        }
    }

    /// Hottest edges sorted by hit count.
    #[must_use]
    pub fn hottest_edges(&self, n: usize) -> Vec<(CovEdge, u64)> {
        let mut pairs: Vec<(CovEdge, u64)> =
            self.edges.iter().map(|(e, &c)| (e.clone(), c)).collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

// â"€â"€â"€ BlockCoverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Basic-block coverage with hit counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockCoverage {
    pub blocks: BTreeMap<u64, u64>,
}

impl BlockCoverage {
    /// Create empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hit.
    pub fn record_hit(&mut self, addr: u64) {
        *self.blocks.entry(addr).or_insert(0) += 1;
    }

    /// Record N hits.
    pub fn record_hits(&mut self, addr: u64, n: u64) {
        *self.blocks.entry(addr).or_insert(0) += n;
    }

    /// Hit count for `addr`.
    #[must_use]
    pub fn hit_count(&self, addr: u64) -> u64 {
        self.blocks.get(&addr).copied().unwrap_or(0)
    }

    /// Returns `true` if `addr` was hit.
    #[must_use]
    pub fn was_hit(&self, addr: u64) -> bool {
        self.blocks.contains_key(&addr)
    }

    /// Number of unique blocks hit.
    #[must_use]
    pub fn unique_blocks_hit(&self) -> usize {
        self.blocks.len()
    }

    /// Total hits.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.blocks.values().sum()
    }

    /// Merge another map.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.blocks {
            *self.blocks.entry(addr).or_insert(0) += count;
        }
    }

    /// Block coverage ratio given total known blocks.
    #[must_use]
    pub fn coverage_ratio(&self, total_blocks: usize) -> f64 {
        if total_blocks == 0 {
            return 1.0;
        }
        crate::usize_to_f64(self.blocks.len()) / crate::usize_to_f64(total_blocks)
    }

    /// Hot blocks sorted by hit count.
    #[must_use]
    pub fn hot_blocks(&self, n: usize) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self.blocks.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ CovBitmap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_bitmap_set_get() {
        let mut bm = CovBitmap::new(64);
        bm.set(0);
        bm.set(7);
        bm.set(63);
        assert!(bm.get(0));
        assert!(bm.get(7));
        assert!(bm.get(63));
        assert!(!bm.get(1));
    }

    #[test]
    fn test_bitmap_count_set() {
        let mut bm = CovBitmap::new(32);
        bm.set(0);
        bm.set(5);
        bm.set(10);
        assert_eq!(bm.count_set(), 3);
    }

    #[test]
    fn test_bitmap_union() {
        let mut a = CovBitmap::new(8);
        let mut b = CovBitmap::new(8);
        a.set(0);
        a.set(1);
        b.set(1);
        b.set(2);
        let u = a.union(&b);
        assert!(u.get(0));
        assert!(u.get(1));
        assert!(u.get(2));
    }

    #[test]
    fn test_bitmap_intersection() {
        let mut a = CovBitmap::new(8);
        let mut b = CovBitmap::new(8);
        a.set(0);
        a.set(1);
        b.set(1);
        b.set(2);
        let i = a.intersection(&b);
        assert!(!i.get(0));
        assert!(i.get(1));
        assert!(!i.get(2));
    }

    #[test]
    fn test_bitmap_difference() {
        let mut a = CovBitmap::new(8);
        let mut b = CovBitmap::new(8);
        a.set(0);
        a.set(1);
        b.set(1);
        let d = a.difference(&b);
        assert!(d.get(0));
        assert!(!d.get(1));
    }

    #[test]
    fn test_bitmap_jaccard_identical() {
        let mut a = CovBitmap::new(16);
        a.set(0);
        a.set(4);
        let b = a.clone();
        assert!((a.jaccard(&b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_bitmap_jaccard_disjoint() {
        let mut a = CovBitmap::new(16);
        let mut b = CovBitmap::new(16);
        a.set(0);
        b.set(8);
        assert!((a.jaccard(&b) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_bitmap_is_full_is_empty() {
        let mut bm = CovBitmap::new(4);
        assert!(bm.is_empty());
        assert!(!bm.is_full());
        bm.set(0);
        bm.set(1);
        bm.set(2);
        bm.set(3);
        assert!(!bm.is_empty());
        assert!(bm.is_full());
    }

    #[test]
    fn test_afl_bitmap_round_trip() {
        let data = vec![0b0000_0011u8, 0b1000_0000];
        let bm = load_afl_bitmap(&data);
        assert!(bm.get(0));
        assert!(bm.get(1));
        assert!(bm.get(15));
        assert!(!bm.get(2));
    }

    #[test]
    fn test_afl_new_coverage() {
        let mut a = CovBitmap::new(16);
        let mut b = CovBitmap::new(16);
        a.set(0);
        b.set(0);
        b.set(1);
        assert_eq!(afl_new_coverage(&a, &b), 1);
    }

    // â"€â"€ CoverageRun â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_run_record_bb() {
        let mut run = CoverageRun::new("test");
        run.record_bb(0x1000);
        run.record_bb(0x1000);
        run.record_bb(0x2000);
        assert_eq!(run.visit_count(0x1000), 2);
        assert!(run.is_covered(0x1000));
        assert!(!run.is_covered(0x9999));
    }

    #[test]
    fn test_run_record_edge() {
        let mut run = CoverageRun::new("test");
        run.record_edge(0x1000, 0x2000);
        run.record_edge(0x1000, 0x2000);
        assert_eq!(run.edge_hits.get(&(0x1000, 0x2000)), Some(&2));
    }

    #[test]
    fn test_run_hot_bbs() {
        let mut run = CoverageRun::new("t");
        run.record_bb_n(0x1000, 10);
        run.record_bb_n(0x2000, 3);
        run.record_bb_n(0x3000, 7);
        let hot = run.hot_bbs(2);
        assert_eq!(hot[0].0, 0x1000);
        assert_eq!(hot[0].1, 10);
    }

    // â"€â"€ CoverageData â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_data_merge_all() {
        let mut data = CoverageData::new("d");
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x1000);
        r2.record_bb(0x2000);
        data.add_run(r1);
        data.add_run(r2);
        let merged = data.merge_all();
        assert_eq!(merged.visit_count(0x1000), 2);
        assert_eq!(merged.visit_count(0x2000), 1);
    }

    #[test]
    fn test_coverage_data_total_unique_bbs() {
        let mut data = CoverageData::new("d");
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x2000);
        data.add_run(r1);
        data.add_run(r2);
        assert_eq!(data.total_unique_bbs(), 2);
    }

    // â"€â"€ CoverageDiff â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_diff_compute() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        a.record_bb(0x2000);
        let mut b = CoverageRun::new("b");
        b.record_bb(0x2000);
        b.record_bb(0x3000);
        let diff = CoverageDiff::compute(&a, &b);
        assert!(diff.new_in_a.contains(&0x1000));
        assert!(diff.new_in_b.contains(&0x3000));
        assert!(diff.in_both.contains(&0x2000));
    }

    #[test]
    fn test_coverage_diff_jaccard_identical() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        let b = a.clone();
        let diff = CoverageDiff::compute(&a, &b);
        assert!((diff.jaccard - 1.0).abs() < 1e-9);
    }

    // â"€â"€ FunctionStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_function_stats_coverage_pct() {
        let mut fs = FunctionStats::new("foo", 0x1000, 0x2000, 10);
        fs.covered_bb = 5;
        assert!((fs.coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_function_stats_is_fully_covered() {
        let mut fs = FunctionStats::new("bar", 0x1000, 0x2000, 3);
        fs.covered_bb = 3;
        assert!(fs.is_fully_covered());
    }

    #[test]
    fn test_compute_function_stats() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 5); // entry
        run.record_bb_n(0x1010, 3);
        run.record_bb_n(0x1020, 1);
        let funcs = vec![FunctionStats::new("f", 0x1000, 0x2000, 4)];
        let stats = compute_function_stats(&run, &funcs);
        assert_eq!(stats[0].covered_bb, 3);
        assert_eq!(stats[0].call_count, 5);
    }

    // â"€â"€ DrcovData â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_drcov_parse_empty() {
        let d = DrcovData::parse("");
        assert!(d.modules.is_empty());
        assert!(d.basic_blocks.is_empty());
    }

    #[test]
    fn test_drcov_parse_module_line() {
        let input = "Module Table: version 2, count 1\n\
                     Columns: id, base, end, entry, checksum, timestamp, path\n\
                     0, 0x400000, 0x500000, 0x401000, 0, 0, /bin/ls\n";
        let d = DrcovData::parse(input);
        assert_eq!(d.modules.len(), 1);
        assert_eq!(d.modules[0].base, 0x400000);
        assert_eq!(d.modules[0].name, "ls");
    }

    #[test]
    fn test_drcov_resolve_addresses() {
        let d = DrcovData {
            modules: vec![DrcovModule {
                id: 0,
                base: 0x400000,
                end: 0x500000,
                name: "test".into(),
            }],
            basic_blocks: vec![DrcovBasicBlock {
                start: 0x1000,
                size: 10,
                mod_id: 0,
            }],
        };
        let addrs = d.resolve_addresses();
        assert_eq!(addrs, vec![0x401000]);
    }

    // â"€â"€ LCOV Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lcov_parse_basic() {
        let input = "TN:test_suite\nSF:main.c\nDA:10,5\nDA:20,0\nLF:2\nLH:1\nend_of_record\n";
        let records = parse_lcov(input);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_file, "main.c");
        assert_eq!(records[0].line_hits.get(&10), Some(&5));
        assert_eq!(records[0].lines_found, 2);
        assert_eq!(records[0].lines_hit, 1);
    }

    #[test]
    fn test_lcov_parse_functions() {
        let input = "TN:\nSF:foo.c\nFN:10,my_func\nFNDA:3,my_func\nFNF:1\nFNH:1\nLF:0\nLH:0\nend_of_record\n";
        let records = parse_lcov(input);
        assert_eq!(records.len(), 1);
        assert!(records[0].function_hits.contains_key("my_func"));
        let (line, count) = records[0].function_hits["my_func"];
        assert_eq!(line, 10);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_to_lcov_string_round_trip() {
        let input = "TN:t\nSF:a.c\nDA:1,2\nLF:1\nLH:1\nend_of_record\n";
        let records = parse_lcov(input);
        let out = to_lcov_string(&records);
        assert!(out.contains("SF:a.c"));
        assert!(out.contains("DA:1,2"));
        assert!(out.contains("end_of_record"));
    }

    // â"€â"€ Custom Binary Format â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_custom_binary_round_trip() {
        let mut run = CoverageRun::new("test");
        run.record_bb_n(0x1000, 5);
        run.record_bb_n(0x2000, 10);
        let bytes = to_custom_binary(&run);
        let loaded = parse_custom_binary(&bytes).unwrap();
        assert_eq!(loaded.visit_count(0x1000), 5);
        assert_eq!(loaded.visit_count(0x2000), 10);
    }

    #[test]
    fn test_custom_binary_invalid_length() {
        assert!(parse_custom_binary(&[1, 2, 3]).is_err());
    }

    // â"€â"€ merge_runs â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_merge_runs() {
        let mut a = CoverageRun::new("a");
        a.record_bb_n(0x1000, 3);
        let mut b = CoverageRun::new("b");
        b.record_bb_n(0x1000, 2);
        b.record_bb_n(0x2000, 1);
        let merged = merge_runs(&a, &b, "merged");
        assert_eq!(merged.visit_count(0x1000), 5);
        assert_eq!(merged.visit_count(0x2000), 1);
    }

    // â"€â"€ LighthouseJson â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lighthouse_json_round_trip() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 7);
        let lh = LighthouseJson::from_run(&run);
        let json = lh.to_json().unwrap();
        assert!(json.contains("0x1000"));
        let lh2 = LighthouseJson::from_json(&json).unwrap();
        let run2 = lh2.to_run();
        assert_eq!(run2.visit_count(0x1000), 7);
    }

    // â"€â"€ CoverageHeatmap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_heatmap_heat_at() {
        let mut run = CoverageRun::new("t");
        run.record_bb_n(0x1000, 10);
        run.record_bb_n(0x2000, 1);
        let hm = CoverageHeatmap::build(&run);
        let hot = hm.heat_at(0x1000);
        let cold = hm.heat_at(0x2000);
        assert!(hot > cold);
        assert!((hot - 1.0).abs() < 1e-9);
    }

    // â"€â"€ BlockColorInfo â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_block_color_info_covered() {
        let mut run = CoverageRun::new("t");
        run.record_bb_n(0x1000, 10);
        let bci = BlockColorInfo::for_addr(&run, 0x1000, 10);
        assert!(bci.is_covered);
        assert_eq!(bci.visit_count, 10);
        let (r, _g, _b, a) = bci.rgba_color();
        assert_eq!(r, 255);
        assert_eq!(a, 255);
    }

    #[test]
    fn test_block_color_info_not_covered() {
        let run = CoverageRun::new("t");
        let bci = BlockColorInfo::for_addr(&run, 0xDEAD, 10);
        assert!(!bci.is_covered);
        let (r, g, b, _) = bci.rgba_color();
        assert_eq!(r, 64);
        assert_eq!(g, 64);
        assert_eq!(b, 64);
    }

    // â"€â"€ CoverageSession â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_session_add_run_merged() {
        let mut session = CoverageSession::new("s");
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x2000);
        session.add_run(r1);
        session.add_run(r2);
        let merged = session.merged();
        assert_eq!(merged.unique_bbs(), 2);
    }

    #[test]
    fn test_coverage_session_export_lcov() {
        let mut session = CoverageSession::new("lcov_test");
        let mut r = CoverageRun::new("r");
        r.record_bb(0x1000);
        session.add_run(r);
        let lcov = session.export_lcov();
        assert!(lcov.contains("SF:lcov_test"));
        assert!(lcov.contains("end_of_record"));
    }

    #[test]
    fn test_coverage_session_export_lighthouse_json() {
        let mut session = CoverageSession::new("lh_test");
        let mut r = CoverageRun::new("r");
        r.record_bb_n(0x4000, 3);
        session.add_run(r);
        let json = session.export_lighthouse_json().unwrap();
        assert!(json.contains("0x4000"));
    }

    #[test]
    fn test_coverage_session_summary_display() {
        let session = CoverageSession::new("test_session");
        let summary = session.summary();
        let s = summary.to_string();
        assert!(s.contains("test_session"));
    }

    // â"€â"€ CoverageComparator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_comparator_delta_positive() {
        let mut baseline = CoverageRun::new("base");
        baseline.record_bb(0x1000);
        let mut current = CoverageRun::new("cur");
        current.record_bb(0x1000);
        current.record_bb(0x2000);
        current.record_bb(0x3000);
        let cmp = CoverageComparator::new(baseline, current);
        assert_eq!(cmp.delta_bbs(), 2);
    }

    #[test]
    fn test_comparator_delta_regression() {
        let mut baseline = CoverageRun::new("base");
        baseline.record_bb(0x1000);
        baseline.record_bb(0x2000);
        let current = CoverageRun::new("cur");
        let cmp = CoverageComparator::new(baseline, current);
        assert_eq!(cmp.delta_bbs(), -2);
    }

    // â"€â"€ CoverageDatabase â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_database_basic() {
        let mut db = CoverageDatabase::new();
        let id = db.create_session("s1");
        db.record_hit(id, 0x1000).unwrap();
        db.record_hit(id, 0x1000).unwrap();
        db.record_hit(id, 0x2000).unwrap();
        assert_eq!(db.get_hits(id, 0x1000), 2);
        let run = db.export_run(id).unwrap();
        assert_eq!(run.visit_count(0x1000), 2);
    }

    #[test]
    fn test_coverage_database_invalid_session() {
        let mut db = CoverageDatabase::new();
        assert!(db.record_hit(9999, 0x1000).is_err());
        assert!(db.export_run(9999).is_err());
    }

    // â"€â"€ EdgeMap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_edge_map_record_hit_count() {
        let mut em = EdgeMap::new();
        em.record(0x100, 0x200);
        em.record(0x100, 0x200);
        em.record_n(0x100, 0x200, 3);
        assert_eq!(em.hit_count(0x100, 0x200), 5);
        assert_eq!(em.count(), 1);
    }

    #[test]
    fn test_edge_map_merge() {
        let mut a = EdgeMap::new();
        let mut b = EdgeMap::new();
        a.record(0x100, 0x200);
        b.record(0x100, 0x200);
        b.record(0x300, 0x400);
        a.merge(&b);
        assert_eq!(a.hit_count(0x100, 0x200), 2);
        assert_eq!(a.hit_count(0x300, 0x400), 1);
    }

    // â"€â"€ BlockCoverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_block_coverage_record() {
        let mut bc = BlockCoverage::new();
        bc.record_hit(0x1000);
        bc.record_hits(0x1000, 4);
        assert_eq!(bc.hit_count(0x1000), 5);
        assert!(bc.was_hit(0x1000));
    }

    #[test]
    fn test_block_coverage_merge() {
        let mut a = BlockCoverage::new();
        let mut b = BlockCoverage::new();
        a.record_hit(0x1000);
        b.record_hit(0x1000);
        b.record_hit(0x2000);
        a.merge(&b);
        assert_eq!(a.hit_count(0x1000), 2);
        assert_eq!(a.hit_count(0x2000), 1);
    }

    // â"€â"€ parse_hex_or_dec â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_hex_or_dec() {
        assert_eq!(parse_hex_or_dec("0x400000"), 0x400000);
        assert_eq!(parse_hex_or_dec("1024"), 1024);
        assert_eq!(parse_hex_or_dec("  0xFF  "), 0xFF);
    }

    // â"€â"€ HTML Report â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_generate_html_report_contains_basics() {
        let run = CoverageRun::new("test_run");
        let funcs = vec![FunctionStats::new("main", 0x1000, 0x2000, 5)];
        let html = generate_html_report("Test Report", &run, &funcs);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test Report"));
        assert!(html.contains("main"));
    }
}

// â"€â"€â"€ CoverageTimeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A time-ordered series of coverage snapshots, used to track coverage growth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Unix timestamp (or 0 if unavailable).
    pub timestamp: u64,
    /// Label (e.g., fuzzer corpus size, iteration count).
    pub label: String,
    /// Number of unique BBs covered at this point.
    pub unique_bbs: usize,
    /// Number of unique edges covered at this point.
    pub unique_edges: usize,
    /// Cumulative BB hit count.
    pub total_bb_hits: u64,
}

impl CoverageSnapshot {
    /// Create a snapshot from a run.
    #[must_use]
    pub fn from_run(run: &CoverageRun, seq: u64, label: impl Into<String>) -> Self {
        Self {
            seq,
            timestamp: run.timestamp,
            label: label.into(),
            unique_bbs: run.unique_bbs(),
            unique_edges: run.unique_edges(),
            total_bb_hits: run.total_bb_executions(),
        }
    }
}

/// Tracks how coverage grows over multiple runs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageTimeline {
    pub snapshots: Vec<CoverageSnapshot>,
}

impl CoverageTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a snapshot.
    pub fn push(&mut self, snap: CoverageSnapshot) {
        self.snapshots.push(snap);
    }

    /// Add a snapshot from a run.
    pub fn add_run_snapshot(&mut self, run: &CoverageRun, label: impl Into<String>) {
        let seq = self.snapshots.len() as u64;
        self.push(CoverageSnapshot::from_run(run, seq, label));
    }

    /// Number of snapshots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns `true` if no snapshots have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Coverage growth: (seq, `unique_bbs`) pairs.
    #[must_use]
    pub fn bb_growth(&self) -> Vec<(u64, usize)> {
        self.snapshots
            .iter()
            .map(|s| (s.seq, s.unique_bbs))
            .collect()
    }

    /// Edge growth: (seq, `unique_edges`) pairs.
    #[must_use]
    pub fn edge_growth(&self) -> Vec<(u64, usize)> {
        self.snapshots
            .iter()
            .map(|s| (s.seq, s.unique_edges))
            .collect()
    }

    /// Find the first snapshot where `unique_bbs >= target`.
    #[must_use]
    pub fn first_reaching_bbs(&self, target: usize) -> Option<&CoverageSnapshot> {
        self.snapshots.iter().find(|s| s.unique_bbs >= target)
    }

    /// Latest BB count.
    #[must_use]
    pub fn latest_bb_count(&self) -> usize {
        self.snapshots.last().map_or(0, |s| s.unique_bbs)
    }

    /// Returns `true` if coverage is still growing (last snapshot > second-to-last).
    #[must_use]
    pub fn is_growing(&self) -> bool {
        if self.snapshots.len() < 2 {
            return false;
        }
        let n = self.snapshots.len();
        self.snapshots[n - 1].unique_bbs > self.snapshots[n - 2].unique_bbs
    }

    /// Total new BBs across all snapshots.
    #[must_use]
    pub fn total_bb_gain(&self) -> usize {
        if self.snapshots.is_empty() {
            return 0;
        }
        self.snapshots
            .last()
            .map_or(0, |s| s.unique_bbs)
            .saturating_sub(self.snapshots.first().map_or(0, |s| s.unique_bbs))
    }
}

// â"€â"€â"€ CoverageFilter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Filters a coverage run to a specific address range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageFilter {
    /// Start of the address range (inclusive).
    pub lo: u64,
    /// End of the address range (inclusive).
    pub hi: u64,
}

impl CoverageFilter {
    /// Create a new filter.
    #[must_use]
    pub const fn new(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    /// Returns `true` if `addr` is within the filter range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.lo && addr <= self.hi
    }

    /// Apply the filter to a run, returning a new run with only matching entries.
    #[must_use]
    pub fn apply(&self, run: &CoverageRun) -> CoverageRun {
        let mut filtered = CoverageRun::new(format!("{}_filtered", run.name));
        for (&addr, &count) in &run.bb_hits {
            if self.contains(addr) {
                filtered.record_bb_n(addr, count);
            }
        }
        for (&(from, to), &count) in &run.edge_hits {
            if self.contains(from) && self.contains(to) {
                filtered.record_edge_n(from, to, count);
            }
        }
        filtered
    }

    /// Returns the number of BBs in a run that fall within this filter.
    #[must_use]
    pub fn count_matching(&self, run: &CoverageRun) -> usize {
        run.bb_hits.keys().filter(|&&a| self.contains(a)).count()
    }
}

// â"€â"€â"€ CoverageAnnotator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Annotates a coverage run with human-readable labels from a symbol table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageAnnotator {
    /// Map from address to function/symbol name.
    symbols: std::collections::BTreeMap<u64, String>,
}

impl CoverageAnnotator {
    /// Create an empty annotator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a symbol.
    pub fn add_symbol(&mut self, addr: u64, name: impl Into<String>) {
        self.symbols.insert(addr, name.into());
    }

    /// Annotated hit list: (addr, `name_or_hex`, count).
    #[must_use]
    pub fn annotated_hits(&self, run: &CoverageRun) -> Vec<(u64, String, u64)> {
        let mut hits: Vec<(u64, String, u64)> = run
            .bb_hits
            .iter()
            .map(|(&addr, &count)| {
                let name = self
                    .symbols
                    .range(..=addr)
                    .next_back()
                    .map_or_else(|| format!("0x{addr:x}"), |(sym_addr, sym_name)| {
                        if addr == *sym_addr {
                            sym_name.clone()
                        } else {
                            format!("{}+0x{:x}", sym_name, addr - sym_addr)
                        }
                    });
                (addr, name, count)
            })
            .collect();
        hits.sort_unstable_by_key(|(a, _, _)| *a);
        hits
    }

    /// All symbols in address order.
    #[must_use]
    pub fn symbols_sorted(&self) -> Vec<(u64, &str)> {
        self.symbols.iter().map(|(a, n)| (*a, n.as_str())).collect()
    }

    /// Lookup the symbol name closest to `addr`.
    #[must_use]
    pub fn lookup(&self, addr: u64) -> Option<String> {
        self.symbols
            .range(..=addr)
            .next_back()
            .map(|(sym_addr, sym_name)| {
                if addr == *sym_addr {
                    sym_name.clone()
                } else {
                    format!("{}+0x{:x}", sym_name, addr - sym_addr)
                }
            })
    }
}

// â"€â"€â"€ CoverageExporter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Exports coverage data in various formats.
pub struct CoverageExporter;

impl CoverageExporter {
    /// Export a run as a tab-separated value file (address, `hit_count`, name).
    #[must_use]
    pub fn to_tsv(run: &CoverageRun, annotator: Option<&CoverageAnnotator>) -> String {
        let mut lines = vec!["address\thit_count\tname".to_string()];
        let mut pairs: Vec<(u64, u64)> = run.bb_hits.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_unstable_by_key(|(a, _)| *a);
        for (addr, count) in pairs {
            let name = annotator
                .and_then(|ann| ann.lookup(addr))
                .unwrap_or_else(|| format!("0x{addr:x}"));
            lines.push(format!("0x{addr:x}\t{count}\t{name}"));
        }
        lines.join("\n")
    }

    /// Export a run as a CSV file.
    #[must_use]
    pub fn to_csv(run: &CoverageRun) -> String {
        let mut lines = vec!["address,hit_count".to_string()];
        let mut pairs: Vec<(u64, u64)> = run.bb_hits.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_unstable_by_key(|(a, _)| *a);
        for (addr, count) in pairs {
            lines.push(format!("0x{addr:x},{count}"));
        }
        lines.join("\n")
    }

    /// Export a diff as a human-readable text report.
    #[must_use]
    pub fn diff_to_text(diff: &CoverageDiff) -> String {
        let mut lines = Vec::new();
        lines.push("=== Coverage Diff ===".to_string());
        lines.push(format!("Jaccard similarity: {:.2}%", diff.overlap_pct()));
        lines.push(format!("BBs in both: {}", diff.in_both.len()));
        lines.push(format!("BBs only in A: {}", diff.new_in_a.len()));
        lines.push(format!("BBs only in B: {}", diff.new_in_b.len()));
        lines.push("--- New in B (gains) ---".to_string());
        let mut bbs_b: Vec<u64> = diff.new_in_b.iter().copied().collect();
        bbs_b.sort_unstable();
        for addr in bbs_b.iter().take(20) {
            lines.push(format!("  + 0x{addr:x}"));
        }
        if bbs_b.len() > 20 {
            lines.push(format!("  ... and {} more", bbs_b.len() - 20));
        }
        lines.join("\n")
    }
}

// â"€â"€â"€ AdaptiveCoverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Adaptive coverage scheduler: tracks which BBs are "interesting" (low visit count)
/// and prioritises them for guided fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveCoverage {
    /// All known BB addresses.
    known_bbs: HashSet<u64>,
    /// Current visit counts.
    visit_counts: std::collections::HashMap<u64, u64>,
    /// Threshold below which a BB is considered "under-explored".
    pub interesting_threshold: u64,
}

impl AdaptiveCoverage {
    /// Create a new adaptive coverage tracker.
    #[must_use]
    pub fn new(interesting_threshold: u64) -> Self {
        Self {
            known_bbs: HashSet::new(),
            visit_counts: std::collections::HashMap::new(),
            interesting_threshold,
        }
    }

    /// Register all BB addresses known in the binary.
    pub fn register_known_bbs(&mut self, addrs: impl IntoIterator<Item = u64>) {
        self.known_bbs.extend(addrs);
    }

    /// Ingest a coverage run.
    pub fn ingest(&mut self, run: &CoverageRun) {
        for (&addr, &count) in &run.bb_hits {
            *self.visit_counts.entry(addr).or_insert(0) += count;
            self.known_bbs.insert(addr);
        }
    }

    /// BBs that have never been covered.
    #[must_use]
    pub fn uncovered(&self) -> Vec<u64> {
        self.known_bbs
            .iter()
            .filter(|&&a| self.visit_counts.get(&a).copied().unwrap_or(0) == 0)
            .copied()
            .collect()
    }

    /// BBs with visit count below `interesting_threshold`.
    #[must_use]
    pub fn under_explored(&self) -> Vec<(u64, u64)> {
        self.visit_counts
            .iter()
            .filter(|&(_, &c)| c < self.interesting_threshold)
            .map(|(&a, &c)| (a, c))
            .collect()
    }

    /// Coverage ratio: covered / total known BBs.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        let total = self.known_bbs.len();
        if total == 0 {
            return 1.0;
        }
        let covered = self.visit_counts.len();
        crate::usize_to_f64(covered) / crate::usize_to_f64(total)
    }

    /// Returns `true` if all known BBs have been covered.
    #[must_use]
    pub fn is_fully_covered(&self) -> bool {
        self.uncovered().is_empty()
    }
}

// â"€â"€â"€ Extended Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extended_tests {
    use super::*;

    // â"€â"€ CoverageTimeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_timeline_add_snapshots() {
        let mut tl = CoverageTimeline::new();
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        tl.add_run_snapshot(&r1, "iter-1");
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x1000);
        r2.record_bb(0x2000);
        tl.add_run_snapshot(&r2, "iter-2");
        assert_eq!(tl.len(), 2);
        assert_eq!(tl.latest_bb_count(), 2);
    }

    #[test]
    fn test_timeline_is_growing() {
        let mut tl = CoverageTimeline::new();
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        tl.add_run_snapshot(&r1, "1");
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x1000);
        r2.record_bb(0x2000);
        tl.add_run_snapshot(&r2, "2");
        assert!(tl.is_growing());
    }

    #[test]
    fn test_timeline_first_reaching_bbs() {
        let mut tl = CoverageTimeline::new();
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        tl.add_run_snapshot(&r1, "1");
        let found = tl.first_reaching_bbs(1);
        assert!(found.is_some());
        assert_eq!(found.unwrap().label, "1");
    }

    #[test]
    fn test_timeline_bb_growth() {
        let mut tl = CoverageTimeline::new();
        let r1 = CoverageRun::new("r1");
        tl.add_run_snapshot(&r1, "0");
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x1000);
        tl.add_run_snapshot(&r2, "1");
        let growth = tl.bb_growth();
        assert_eq!(growth.len(), 2);
        assert_eq!(growth[0].1, 0);
        assert_eq!(growth[1].1, 1);
    }

    // â"€â"€ CoverageFilter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_filter_contains() {
        let f = CoverageFilter::new(0x1000, 0x2000);
        assert!(f.contains(0x1000));
        assert!(f.contains(0x1500));
        assert!(f.contains(0x2000));
        assert!(!f.contains(0x0FFF));
        assert!(!f.contains(0x2001));
    }

    #[test]
    fn test_filter_apply() {
        let f = CoverageFilter::new(0x1000, 0x2000);
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000); // in range
        run.record_bb(0x3000); // out of range
        let filtered = f.apply(&run);
        assert_eq!(filtered.unique_bbs(), 1);
        assert!(filtered.is_covered(0x1000));
        assert!(!filtered.is_covered(0x3000));
    }

    #[test]
    fn test_filter_count_matching() {
        let f = CoverageFilter::new(0x1000, 0x1FFF);
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000);
        run.record_bb(0x1500);
        run.record_bb(0x2000);
        assert_eq!(f.count_matching(&run), 2);
    }

    // â"€â"€ CoverageAnnotator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_annotator_lookup_exact() {
        let mut ann = CoverageAnnotator::new();
        ann.add_symbol(0x1000, "main");
        assert_eq!(ann.lookup(0x1000), Some("main".to_string()));
    }

    #[test]
    fn test_annotator_lookup_offset() {
        let mut ann = CoverageAnnotator::new();
        ann.add_symbol(0x1000, "foo");
        let result = ann.lookup(0x1010).unwrap();
        assert!(result.contains("foo"));
        assert!(result.contains("+0x10"));
    }

    #[test]
    fn test_annotator_annotated_hits() {
        let mut ann = CoverageAnnotator::new();
        ann.add_symbol(0x1000, "main");
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 5);
        let hits = ann.annotated_hits(&run);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "main");
        assert_eq!(hits[0].2, 5);
    }

    // â"€â"€ CoverageExporter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_exporter_to_csv() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 3);
        let csv = CoverageExporter::to_csv(&run);
        assert!(csv.contains("address,hit_count"));
        assert!(csv.contains("0x1000,3"));
    }

    #[test]
    fn test_exporter_to_tsv() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x2000, 7);
        let tsv = CoverageExporter::to_tsv(&run, None);
        assert!(tsv.contains("0x2000\t7"));
    }

    #[test]
    fn test_exporter_diff_to_text() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        a.record_bb(0x2000);
        let mut b = CoverageRun::new("b");
        b.record_bb(0x2000);
        b.record_bb(0x3000);
        let diff = CoverageDiff::compute(&a, &b);
        let text = CoverageExporter::diff_to_text(&diff);
        assert!(text.contains("Coverage Diff"));
        assert!(text.contains("0x3000"));
    }

    // â"€â"€ AdaptiveCoverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_adaptive_uncovered() {
        let mut ac = AdaptiveCoverage::new(5);
        ac.register_known_bbs(vec![0x1000, 0x2000, 0x3000]);
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000);
        ac.ingest(&run);
        let uncovered = ac.uncovered();
        assert_eq!(uncovered.len(), 2);
        assert!(uncovered.contains(&0x2000) || uncovered.contains(&0x3000));
    }

    #[test]
    fn test_adaptive_under_explored() {
        let mut ac = AdaptiveCoverage::new(10);
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 2); // under threshold
        run.record_bb_n(0x2000, 15); // over threshold
        ac.ingest(&run);
        let under = ac.under_explored();
        assert!(under.iter().any(|(a, _)| *a == 0x1000));
        assert!(!under.iter().any(|(a, _)| *a == 0x2000));
    }

    #[test]
    fn test_adaptive_coverage_ratio() {
        let mut ac = AdaptiveCoverage::new(5);
        ac.register_known_bbs(vec![0x1000, 0x2000]);
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000);
        ac.ingest(&run);
        assert!((ac.coverage_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_adaptive_fully_covered() {
        let mut ac = AdaptiveCoverage::new(5);
        ac.register_known_bbs(vec![0x1000, 0x2000]);
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000);
        run.record_bb(0x2000);
        ac.ingest(&run);
        assert!(ac.is_fully_covered());
    }

    // â"€â"€ CoverageSnapshot â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_snapshot_from_run() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 10);
        run.record_edge(0x1000, 0x2000);
        let snap = CoverageSnapshot::from_run(&run, 0, "snap-0");
        assert_eq!(snap.unique_bbs, 1);
        assert_eq!(snap.unique_edges, 1);
        assert_eq!(snap.total_bb_hits, 10);
    }

    // â"€â"€ EdgeMap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_edge_map_hottest_edges() {
        let mut em = EdgeMap::new();
        em.record_n(0x100, 0x200, 100);
        em.record_n(0x200, 0x300, 50);
        em.record_n(0x300, 0x400, 1);
        let hot = em.hottest_edges(2);
        assert_eq!(hot.len(), 2);
        assert_eq!(hot[0].1, 100);
        assert_eq!(hot[1].1, 50);
    }

    // â"€â"€ BlockCoverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_block_coverage_hot_blocks() {
        let mut bc = BlockCoverage::new();
        bc.record_hits(0x1000, 50);
        bc.record_hits(0x2000, 10);
        bc.record_hits(0x3000, 100);
        let hot = bc.hot_blocks(2);
        assert_eq!(hot[0].0, 0x3000);
        assert_eq!(hot[1].0, 0x1000);
    }

    #[test]
    fn test_block_coverage_ratio_zero_total() {
        let bc = BlockCoverage::new();
        assert!((bc.coverage_ratio(0) - 1.0).abs() < 1e-9);
    }
}

// â"€â"€â"€ CoverageQuery â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A composable query over coverage data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageQuery {
    /// Minimum hit count (inclusive); 0 = any.
    pub min_hits: u64,
    /// Maximum hit count (inclusive); `u64::MAX` = any.
    pub max_hits: u64,
    /// Address range low (inclusive); 0 = any.
    pub addr_lo: u64,
    /// Address range high (inclusive); `u64::MAX` = any.
    pub addr_hi: u64,
    /// Maximum results to return; 0 = all.
    pub limit: usize,
    /// Sort order.
    pub sort: CoverageQuerySort,
}

/// Sort order for coverage query results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageQuerySort {
    /// Sort by address ascending.
    ByAddress,
    /// Sort by hit count descending.
    ByHitCount,
    /// No particular order.
    Unsorted,
}

impl CoverageQuery {
    /// A query that returns all results.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            min_hits: 0,
            max_hits: u64::MAX,
            addr_lo: 0,
            addr_hi: u64::MAX,
            limit: 0,
            sort: CoverageQuerySort::ByAddress,
        }
    }

    /// Filter by minimum hit count.
    #[must_use]
    pub const fn min_hits(mut self, n: u64) -> Self {
        self.min_hits = n;
        self
    }

    /// Filter by maximum hit count.
    #[must_use]
    pub const fn max_hits(mut self, n: u64) -> Self {
        self.max_hits = n;
        self
    }

    /// Filter to an address range.
    #[must_use]
    pub const fn in_range(mut self, lo: u64, hi: u64) -> Self {
        self.addr_lo = lo;
        self.addr_hi = hi;
        self
    }

    /// Limit the number of results.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }

    /// Sort by hit count descending.
    #[must_use]
    pub const fn hottest_first(mut self) -> Self {
        self.sort = CoverageQuerySort::ByHitCount;
        self
    }

    /// Execute this query against a `CoverageRun`.
    #[must_use]
    pub fn execute(&self, run: &CoverageRun) -> Vec<(u64, u64)> {
        let mut results: Vec<(u64, u64)> = run
            .bb_hits
            .iter()
            .filter(|&(&addr, &count)| {
                count >= self.min_hits
                    && count <= self.max_hits
                    && addr >= self.addr_lo
                    && addr <= self.addr_hi
            })
            .map(|(&a, &c)| (a, c))
            .collect();

        match self.sort {
            CoverageQuerySort::ByAddress => results.sort_unstable_by_key(|(a, _)| *a),
            CoverageQuerySort::ByHitCount => results.sort_unstable_by(|a, b| b.1.cmp(&a.1)),
            CoverageQuerySort::Unsorted => {}
        }

        if self.limit > 0 {
            results.truncate(self.limit);
        }
        results
    }

    /// Count how many BBs match this query.
    #[must_use]
    pub fn count(&self, run: &CoverageRun) -> usize {
        run.bb_hits
            .iter()
            .filter(|&(&addr, &count)| {
                count >= self.min_hits
                    && count <= self.max_hits
                    && addr >= self.addr_lo
                    && addr <= self.addr_hi
            })
            .count()
    }
}

// â"€â"€â"€ CoveragePatch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A coverage patch: a delta to apply to a coverage run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoveragePatch {
    /// Addresses to add (with their counts).
    pub add: HashMap<u64, u64>,
    /// Addresses to remove.
    pub remove: HashSet<u64>,
    /// Scale factor to apply to all existing counts (1.0 = no change).
    pub scale: f64,
}

impl CoveragePatch {
    /// Create an empty patch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            add: HashMap::new(),
            remove: HashSet::new(),
            scale: 1.0,
        }
    }

    /// Add a BB hit.
    pub fn add_bb(&mut self, addr: u64, count: u64) {
        *self.add.entry(addr).or_insert(0) += count;
    }

    /// Mark a BB for removal.
    pub fn remove_bb(&mut self, addr: u64) {
        self.remove.insert(addr);
    }

    /// Set scale factor.
    #[must_use]
    pub const fn with_scale(mut self, scale: f64) -> Self {
        self.scale = scale;
        self
    }

    /// Apply this patch to a run, returning a new run.
    #[must_use]
    pub fn apply(&self, run: &CoverageRun) -> CoverageRun {
        let mut patched = run.clone();
        // Apply scale.
        if (self.scale - 1.0).abs() > 1e-9 {
            for count in patched.bb_hits.values_mut() {
                *count = crate::f64_to_u64_clamp(crate::u64_to_f64(*count) * self.scale);
            }
        }
        // Remove.
        for addr in &self.remove {
            patched.bb_hits.remove(addr);
        }
        // Add.
        for (&addr, &count) in &self.add {
            *patched.bb_hits.entry(addr).or_insert(0) += count;
        }
        patched
    }
}

// â"€â"€â"€ CoverageReport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A structured coverage report with per-function stats and overall summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCoverageReport {
    /// Report title.
    pub title: String,
    /// Merged coverage run.
    pub merged_run: CoverageRun,
    /// Per-function stats.
    pub function_stats: Vec<FunctionStats>,
    /// Heatmap.
    pub heatmap: CoverageHeatmap,
    /// Timeline (if available).
    pub timeline: Option<CoverageTimeline>,
    /// Summary.
    pub summary: CoverageSummary,
}

impl FullCoverageReport {
    /// Build a full report from a session and a list of known functions.
    #[must_use]
    pub fn build(
        title: impl Into<String>,
        session: &CoverageSession,
        functions: &[FunctionStats],
    ) -> Self {
        let merged = session.merged();
        let heatmap = CoverageHeatmap::build(&merged);
        let function_stats = compute_function_stats(&merged, functions);
        let summary = session.summary();
        Self {
            title: title.into(),
            merged_run: merged,
            function_stats,
            heatmap,
            timeline: None,
            summary,
        }
    }

    /// Attach a timeline to the report.
    #[must_use]
    pub fn with_timeline(mut self, timeline: CoverageTimeline) -> Self {
        self.timeline = Some(timeline);
        self
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns `CovError::Serialization` if serialization fails.
    pub fn to_json(&self) -> Result<String, CovError> {
        serde_json::to_string_pretty(self).map_err(|e| CovError::Serialization(e.to_string()))
    }

    /// Generate an HTML report.
    #[must_use]
    pub fn to_html(&self) -> String {
        generate_html_report(&self.title, &self.merged_run, &self.function_stats)
    }

    /// Overall coverage percentage (based on function stats).
    #[must_use]
    pub fn overall_coverage_pct(&self) -> f64 {
        if self.function_stats.is_empty() {
            return 0.0;
        }
        let total_bbs: usize = self.function_stats.iter().map(|f| f.total_bb).sum();
        let covered_bbs: usize = self.function_stats.iter().map(|f| f.covered_bb).sum();
        if total_bbs == 0 {
            return 100.0;
        }
        crate::usize_to_f64(covered_bbs) / crate::usize_to_f64(total_bbs) * 100.0
    }

    /// Functions sorted by coverage percentage (ascending —" least covered first).
    #[must_use]
    pub fn least_covered_functions(&self, n: usize) -> Vec<&FunctionStats> {
        let mut sorted: Vec<&FunctionStats> = self.function_stats.iter().collect();
        sorted.sort_unstable_by(|a, b| {
            a.coverage_pct()
                .partial_cmp(&b.coverage_pct())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(n);
        sorted
    }

    /// Functions that are fully covered.
    #[must_use]
    pub fn fully_covered_functions(&self) -> Vec<&FunctionStats> {
        self.function_stats
            .iter()
            .filter(|f| f.is_fully_covered())
            .collect()
    }

    /// Functions that were never called.
    #[must_use]
    pub fn uncalled_functions(&self) -> Vec<&FunctionStats> {
        self.function_stats
            .iter()
            .filter(|f| !f.was_called())
            .collect()
    }
}

// â"€â"€â"€ MergeStrategy â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Strategy for merging multiple coverage runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Sum all hit counts.
    Sum,
    /// Keep the maximum hit count per address.
    Max,
    /// Keep the minimum hit count per address (only for covered BBs).
    Min,
    /// Set all covered hit counts to 1.
    Binary,
}

/// Merge multiple runs according to a strategy.
#[must_use]
pub fn merge_runs_with_strategy(
    runs: &[CoverageRun],
    strategy: &MergeStrategy,
    name: impl Into<String>,
) -> CoverageRun {
    let mut merged = CoverageRun::new(name);
    for run in runs {
        for (&addr, &count) in &run.bb_hits {
            let entry = merged.bb_hits.entry(addr).or_insert(0);
            *entry = match strategy {
                MergeStrategy::Sum => entry.saturating_add(count),
                MergeStrategy::Max => (*entry).max(count),
                MergeStrategy::Min if *entry == 0 => count,
                MergeStrategy::Min => (*entry).min(count),
                MergeStrategy::Binary => 1,
            };
        }
    }
    merged
}

// â"€â"€â"€ Final Coverage Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod final_cov_tests {
    use super::*;

    // â"€â"€ CoverageQuery â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_query_all_returns_everything() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 5);
        run.record_bb_n(0x2000, 10);
        let results = CoverageQuery::all().execute(&run);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_min_hits() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 1);
        run.record_bb_n(0x2000, 10);
        let results = CoverageQuery::all().min_hits(5).execute(&run);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0x2000);
    }

    #[test]
    fn test_query_max_hits() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 5);
        run.record_bb_n(0x2000, 100);
        let results = CoverageQuery::all().max_hits(10).execute(&run);
        assert!(results.iter().all(|(_, c)| *c <= 10));
    }

    #[test]
    fn test_query_in_range() {
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000);
        run.record_bb(0x5000);
        let results = CoverageQuery::all().in_range(0x1000, 0x2000).execute(&run);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0x1000);
    }

    #[test]
    fn test_query_limit() {
        let mut run = CoverageRun::new("r");
        for i in 0..10u64 {
            run.record_bb(0x1000 + i * 4);
        }
        let results = CoverageQuery::all().limit(3).execute(&run);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_hottest_first() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 1);
        run.record_bb_n(0x2000, 100);
        let results = CoverageQuery::all().hottest_first().execute(&run);
        assert_eq!(results[0].0, 0x2000);
    }

    #[test]
    fn test_query_count() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 5);
        run.record_bb_n(0x2000, 15);
        run.record_bb_n(0x3000, 25);
        let count = CoverageQuery::all().min_hits(10).count(&run);
        assert_eq!(count, 2);
    }

    // â"€â"€ CoveragePatch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_patch_add_bb() {
        let run = CoverageRun::new("r");
        let mut patch = CoveragePatch::new();
        patch.add_bb(0x1000, 5);
        let patched = patch.apply(&run);
        assert_eq!(patched.visit_count(0x1000), 5);
    }

    #[test]
    fn test_patch_remove_bb() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 10);
        let mut patch = CoveragePatch::new();
        patch.remove_bb(0x1000);
        let patched = patch.apply(&run);
        assert!(!patched.is_covered(0x1000));
    }

    #[test]
    fn test_patch_scale() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 10);
        let patch = CoveragePatch::new().with_scale(0.5);
        let patched = patch.apply(&run);
        assert_eq!(patched.visit_count(0x1000), 5);
    }

    // â"€â"€ MergeStrategy â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_merge_strategy_sum() {
        let mut a = CoverageRun::new("a");
        a.record_bb_n(0x1000, 3);
        let mut b = CoverageRun::new("b");
        b.record_bb_n(0x1000, 5);
        let merged = merge_runs_with_strategy(&[a, b], &MergeStrategy::Sum, "merged");
        assert_eq!(merged.visit_count(0x1000), 8);
    }

    #[test]
    fn test_merge_strategy_max() {
        let mut a = CoverageRun::new("a");
        a.record_bb_n(0x1000, 3);
        let mut b = CoverageRun::new("b");
        b.record_bb_n(0x1000, 7);
        let merged = merge_runs_with_strategy(&[a, b], &MergeStrategy::Max, "merged");
        assert_eq!(merged.visit_count(0x1000), 7);
    }

    #[test]
    fn test_merge_strategy_min() {
        let mut a = CoverageRun::new("a");
        a.record_bb_n(0x1000, 3);
        let mut b = CoverageRun::new("b");
        b.record_bb_n(0x1000, 7);
        let merged = merge_runs_with_strategy(&[a, b], &MergeStrategy::Min, "merged");
        assert_eq!(merged.visit_count(0x1000), 3);
    }

    #[test]
    fn test_merge_strategy_binary() {
        let mut a = CoverageRun::new("a");
        a.record_bb_n(0x1000, 99);
        let merged = merge_runs_with_strategy(&[a], &MergeStrategy::Binary, "merged");
        assert_eq!(merged.visit_count(0x1000), 1);
    }

    // â"€â"€ FullCoverageReport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_full_report_build() {
        let mut session = CoverageSession::new("s");
        let mut r = CoverageRun::new("r");
        r.record_bb_n(0x1000, 10);
        session.add_run(r);
        let funcs = vec![FunctionStats::new("main", 0x1000, 0x2000, 3)];
        let report = FullCoverageReport::build("Test", &session, &funcs);
        assert_eq!(report.title, "Test");
        assert_eq!(report.function_stats.len(), 1);
    }

    #[test]
    fn test_full_report_overall_coverage_pct() {
        let mut session = CoverageSession::new("s");
        let mut r = CoverageRun::new("r");
        r.record_bb_n(0x1000, 1);
        r.record_bb_n(0x1010, 1);
        session.add_run(r);
        let mut funcs = vec![FunctionStats::new("foo", 0x1000, 0x2000, 4)];
        funcs[0].covered_bb = 2;
        let report = FullCoverageReport::build("T", &session, &funcs);
        assert!((report.overall_coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_full_report_to_html_contains_title() {
        let session = CoverageSession::new("html_test");
        let report = FullCoverageReport::build("HTML Title", &session, &[]);
        let html = report.to_html();
        assert!(html.contains("HTML Title"));
    }

    #[test]
    fn test_full_report_to_json() {
        let session = CoverageSession::new("json_test");
        let report = FullCoverageReport::build("J", &session, &[]);
        let json = report.to_json().unwrap();
        assert!(json.contains("json_test"));
    }

    #[test]
    fn test_full_report_uncalled_functions() {
        let session = CoverageSession::new("s");
        let funcs = vec![
            FunctionStats::new("called", 0x1000, 0x2000, 3),
            FunctionStats::new("uncalled", 0x3000, 0x4000, 2),
        ];
        let report = FullCoverageReport::build("T", &session, &funcs);
        let uncalled = report.uncalled_functions();
        // Both have call_count=0 since the session is empty.
        assert_eq!(uncalled.len(), 2);
    }

    #[test]
    fn test_full_report_least_covered() {
        let mut session = CoverageSession::new("s");
        let mut r = CoverageRun::new("r");
        r.record_bb_n(0x1000, 1);
        session.add_run(r);
        let funcs = vec![
            FunctionStats::new("full", 0x1000, 0x2000, 1),
            FunctionStats::new("empty", 0x3000, 0x4000, 3),
        ];
        let report = FullCoverageReport::build("T", &session, &funcs);
        let lc = report.least_covered_functions(1);
        assert_eq!(lc.len(), 1);
    }

    // â"€â"€ CoverageTimeline (additional) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_timeline_total_bb_gain() {
        let mut tl = CoverageTimeline::new();
        let r0 = CoverageRun::new("r0");
        tl.add_run_snapshot(&r0, "0");
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        r1.record_bb(0x2000);
        tl.add_run_snapshot(&r1, "1");
        // gain is 2 - 0 = 2
        assert_eq!(tl.total_bb_gain(), 2);
    }

    #[test]
    fn test_timeline_edge_growth() {
        let mut tl = CoverageTimeline::new();
        let mut r = CoverageRun::new("r");
        r.record_edge(0x1000, 0x2000);
        tl.add_run_snapshot(&r, "e");
        let growth = tl.edge_growth();
        assert_eq!(growth.len(), 1);
        assert_eq!(growth[0].1, 1);
    }
}

// â"€â"€â"€ CoverageIntersector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Computes the intersection, union, and Jaccard coefficient of multiple runs.
pub struct CoverageIntersector;

impl CoverageIntersector {
    /// Intersection of two runs: addresses present in both.
    #[must_use]
    pub fn intersect(a: &CoverageRun, b: &CoverageRun) -> HashSet<u64> {
        let sa: HashSet<u64> = a.bb_hits.keys().copied().collect();
        let sb: HashSet<u64> = b.bb_hits.keys().copied().collect();
        sa.intersection(&sb).copied().collect()
    }

    /// Union of two runs: addresses present in either.
    #[must_use]
    pub fn union(a: &CoverageRun, b: &CoverageRun) -> HashSet<u64> {
        let sa: HashSet<u64> = a.bb_hits.keys().copied().collect();
        let sb: HashSet<u64> = b.bb_hits.keys().copied().collect();
        sa.union(&sb).copied().collect()
    }

    /// Jaccard similarity coefficient.
    #[must_use]
    pub fn jaccard(a: &CoverageRun, b: &CoverageRun) -> f64 {
        let inter = Self::intersect(a, b).len();
        let uni = Self::union(a, b).len();
        if uni == 0 {
            1.0
        } else {
            crate::usize_to_f64(inter) / crate::usize_to_f64(uni)
        }
    }

    /// Intersection of many runs.
    #[must_use]
    pub fn intersect_all(runs: &[CoverageRun]) -> HashSet<u64> {
        if runs.is_empty() {
            return HashSet::new();
        }
        let mut result: HashSet<u64> = runs[0].bb_hits.keys().copied().collect();
        for run in &runs[1..] {
            let s: HashSet<u64> = run.bb_hits.keys().copied().collect();
            result = result.intersection(&s).copied().collect();
        }
        result
    }

    /// Union of many runs.
    #[must_use]
    pub fn union_all(runs: &[CoverageRun]) -> HashSet<u64> {
        let mut result = HashSet::new();
        for run in runs {
            result.extend(run.bb_hits.keys().copied());
        }
        result
    }
}

// â"€â"€â"€ BranchCoverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Track which side of each conditional branch was taken.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BranchTracker {
    /// `branch_addr` -> (`taken_count`, `not_taken_count`)
    branches: HashMap<u64, (u64, u64)>,
}

impl BranchTracker {
    /// Create empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a branch outcome.
    pub fn record(&mut self, addr: u64, taken: bool) {
        let entry = self.branches.entry(addr).or_insert((0, 0));
        if taken {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }

    /// Returns `true` if both sides of the branch at `addr` have been taken.
    #[must_use]
    pub fn is_fully_covered(&self, addr: u64) -> bool {
        self.branches
            .get(&addr)
            .is_some_and(|(t, nt)| *t > 0 && *nt > 0)
    }

    /// Overall branch coverage ratio (fully covered / total branches).
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.branches.is_empty() {
            return 1.0;
        }
        let fully: usize = self
            .branches
            .values()
            .filter(|(t, nt)| *t > 0 && *nt > 0)
            .count();
        crate::usize_to_f64(fully) / crate::usize_to_f64(self.branches.len())
    }

    /// All branches that have only been taken one way.
    #[must_use]
    pub fn one_sided_branches(&self) -> Vec<u64> {
        self.branches
            .iter()
            .filter(|(_, (t, nt))| (*t > 0) ^ (*nt > 0))
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// All branch addresses.
    #[must_use]
    pub fn all_branches(&self) -> Vec<u64> {
        self.branches.keys().copied().collect()
    }

    /// Merge another tracker.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &(t, nt)) in &other.branches {
            let entry = self.branches.entry(addr).or_insert((0, 0));
            entry.0 += t;
            entry.1 += nt;
        }
    }
}

// â"€â"€â"€ CoverageImporter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Import coverage from various external sources.
pub struct CoverageImporter;

impl CoverageImporter {
    /// Import from a `DRcov` file (text format).
    #[must_use]
    pub fn from_drcov(content: &str, name: impl Into<String>) -> CoverageRun {
        DrcovData::parse(content).to_run(name)
    }

    /// Import from LCOV info format.
    /// Maps line numbers to pseudo-addresses (line * 4).
    #[must_use]
    pub fn from_lcov(content: &str, name: impl Into<String>) -> CoverageRun {
        let records = parse_lcov(content);
        let mut run = CoverageRun::new(name);
        for rec in &records {
            for (&line, &count) in &rec.line_hits {
                run.record_bb_n(line * 4, count);
            }
        }
        run
    }

    /// Import from custom binary (addr+count pairs).
    ///
    /// # Errors
    /// Returns `CovError::ParseError` if the data is malformed.
    pub fn from_binary(data: &[u8], name: impl Into<String>) -> Result<CoverageRun, CovError> {
        let mut run = parse_custom_binary(data)?;
        run.name = name.into();
        Ok(run)
    }

    /// Import from a `LightHouse` JSON string.
    ///
    /// # Errors
    /// Returns `CovError::ParseError` on malformed JSON.
    pub fn from_lighthouse_json(json: &str) -> Result<CoverageRun, CovError> {
        let lh = LighthouseJson::from_json(json)?;
        Ok(lh.to_run())
    }

    /// Import from an AFL 64KB bitmap.
    /// Returns a `CovBitmap` (individual addresses are not recoverable from bitmap alone).
    #[must_use]
    pub fn from_afl_bitmap(data: &[u8]) -> CovBitmap {
        load_afl_bitmap(data)
    }
}

// â"€â"€â"€ RunMetadata â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Optional metadata attached to a coverage run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunMetadata {
    /// Input file that triggered this run.
    pub input_file: Option<String>,
    /// Fuzzer name.
    pub fuzzer: Option<String>,
    /// Fuzzer seed.
    pub seed: Option<u64>,
    /// Duration of the run in milliseconds.
    pub duration_ms: Option<u64>,
    /// Exit code.
    pub exit_code: Option<i32>,
    /// Standard output snippet.
    pub stdout_snippet: Option<String>,
    /// Whether the run crashed.
    pub crashed: bool,
    /// Whether the run timed out.
    pub timed_out: bool,
}

impl RunMetadata {
    /// Create empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark as crashed.
    #[must_use]
    pub const fn crashed(mut self) -> Self {
        self.crashed = true;
        self
    }

    /// Mark as timed out.
    #[must_use]
    pub const fn timed_out(mut self) -> Self {
        self.timed_out = true;
        self
    }

    /// Set input file.
    #[must_use]
    pub fn with_input(mut self, file: impl Into<String>) -> Self {
        self.input_file = Some(file.into());
        self
    }

    /// Set fuzzer.
    #[must_use]
    pub fn with_fuzzer(mut self, fuzzer: impl Into<String>) -> Self {
        self.fuzzer = Some(fuzzer.into());
        self
    }
}

/// Annotated coverage run: run + optional metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedRun {
    pub run: CoverageRun,
    pub metadata: RunMetadata,
}

impl AnnotatedRun {
    /// Create an annotated run.
    #[must_use]
    pub const fn new(run: CoverageRun, metadata: RunMetadata) -> Self {
        Self { run, metadata }
    }

    /// Create from a plain run with no metadata.
    #[must_use]
    pub fn plain(run: CoverageRun) -> Self {
        Self::new(run, RunMetadata::default())
    }

    /// Returns `true` if this run triggered a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        self.metadata.crashed
    }

    /// Returns `true` if this run timed out.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        self.metadata.timed_out
    }
}

// â"€â"€â"€ Further extended tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod further_extended_tests {
    use super::*;

    // â"€â"€ CoverageIntersector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_intersector_intersect() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        a.record_bb(0x2000);
        let mut b = CoverageRun::new("b");
        b.record_bb(0x2000);
        b.record_bb(0x3000);
        let inter = CoverageIntersector::intersect(&a, &b);
        assert_eq!(inter.len(), 1);
        assert!(inter.contains(&0x2000));
    }

    #[test]
    fn test_intersector_union() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        let mut b = CoverageRun::new("b");
        b.record_bb(0x2000);
        let uni = CoverageIntersector::union(&a, &b);
        assert_eq!(uni.len(), 2);
    }

    #[test]
    fn test_intersector_jaccard_identical() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        let b = a.clone();
        assert!((CoverageIntersector::jaccard(&a, &b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_intersector_jaccard_disjoint() {
        let mut a = CoverageRun::new("a");
        a.record_bb(0x1000);
        let mut b = CoverageRun::new("b");
        b.record_bb(0x2000);
        assert!((CoverageIntersector::jaccard(&a, &b) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_intersector_union_all_empty() {
        let runs: Vec<CoverageRun> = vec![];
        let uni = CoverageIntersector::union_all(&runs);
        assert!(uni.is_empty());
    }

    #[test]
    fn test_intersector_intersect_all() {
        let mut r1 = CoverageRun::new("r1");
        r1.record_bb(0x1000);
        r1.record_bb(0x2000);
        let mut r2 = CoverageRun::new("r2");
        r2.record_bb(0x1000);
        r2.record_bb(0x3000);
        let mut r3 = CoverageRun::new("r3");
        r3.record_bb(0x1000);
        r3.record_bb(0x4000);
        let inter = CoverageIntersector::intersect_all(&[r1, r2, r3]);
        assert_eq!(inter.len(), 1);
        assert!(inter.contains(&0x1000));
    }

    // â"€â"€ BranchTracker â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_branch_tracker_is_fully_covered() {
        let mut bt = BranchTracker::new();
        bt.record(0x1000, true);
        bt.record(0x1000, false);
        assert!(bt.is_fully_covered(0x1000));
    }

    #[test]
    fn test_branch_tracker_not_fully_covered() {
        let mut bt = BranchTracker::new();
        bt.record(0x1000, true);
        assert!(!bt.is_fully_covered(0x1000));
    }

    #[test]
    fn test_branch_tracker_coverage_ratio() {
        let mut bt = BranchTracker::new();
        bt.record(0x1000, true);
        bt.record(0x1000, false); // fully covered
        bt.record(0x2000, true); // one-sided
        assert!((bt.coverage_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_branch_tracker_one_sided() {
        let mut bt = BranchTracker::new();
        bt.record(0x1000, true);
        bt.record(0x2000, true);
        bt.record(0x2000, false);
        let one_sided = bt.one_sided_branches();
        assert_eq!(one_sided.len(), 1);
        assert!(one_sided.contains(&0x1000));
    }

    #[test]
    fn test_branch_tracker_merge() {
        let mut a = BranchTracker::new();
        a.record(0x1000, true);
        let mut b = BranchTracker::new();
        b.record(0x1000, false);
        a.merge(&b);
        assert!(a.is_fully_covered(0x1000));
    }

    // â"€â"€ CoverageImporter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_importer_from_lcov() {
        let input = "TN:\nSF:main.c\nDA:10,5\nDA:20,3\nLF:2\nLH:2\nend_of_record\n";
        let run = CoverageImporter::from_lcov(input, "lcov_run");
        assert_eq!(run.name, "lcov_run");
        assert_eq!(run.visit_count(10 * 4), 5);
        assert_eq!(run.visit_count(20 * 4), 3);
    }

    #[test]
    fn test_importer_from_binary() {
        let mut run = CoverageRun::new("orig");
        run.record_bb_n(0x1234, 9);
        let bytes = to_custom_binary(&run);
        let imported = CoverageImporter::from_binary(&bytes, "imported").unwrap();
        assert_eq!(imported.visit_count(0x1234), 9);
    }

    #[test]
    fn test_importer_from_lighthouse_json() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0xABCD, 7);
        let lh = LighthouseJson::from_run(&run);
        let json = lh.to_json().unwrap();
        let imported = CoverageImporter::from_lighthouse_json(&json).unwrap();
        assert_eq!(imported.visit_count(0xABCD), 7);
    }

    #[test]
    fn test_importer_from_afl_bitmap() {
        let data = vec![0b0000_0001u8; 2]; // bit 0 set in each byte
        let bm = CoverageImporter::from_afl_bitmap(&data);
        assert!(bm.get(0));
        assert!(bm.get(8));
    }

    // â"€â"€ AnnotatedRun â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_annotated_run_plain() {
        let run = CoverageRun::new("r");
        let ar = AnnotatedRun::plain(run);
        assert!(!ar.is_crash());
        assert!(!ar.is_timeout());
    }

    #[test]
    fn test_annotated_run_crash() {
        let run = CoverageRun::new("r");
        let meta = RunMetadata::new().crashed();
        let ar = AnnotatedRun::new(run, meta);
        assert!(ar.is_crash());
    }

    #[test]
    fn test_annotated_run_timeout() {
        let run = CoverageRun::new("r");
        let meta = RunMetadata::new().timed_out();
        let ar = AnnotatedRun::new(run, meta);
        assert!(ar.is_timeout());
    }

    #[test]
    fn test_run_metadata_with_input() {
        let meta = RunMetadata::new().with_input("corpus/sample.bin");
        assert_eq!(meta.input_file.as_deref(), Some("corpus/sample.bin"));
    }

    // â"€â"€ CovError display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cov_error_parse_error() {
        let e = CovError::ParseError("bad format".to_string());
        assert!(e.to_string().contains("bad format"));
    }

    #[test]
    fn test_cov_error_io() {
        let e = CovError::Io("disk full".to_string());
        assert!(e.to_string().contains("disk full"));
    }

    // â"€â"€ MergeStrategy (additional) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_merge_strategy_multiple_runs() {
        let mut runs = Vec::new();
        for i in 0u64..5 {
            let mut r = CoverageRun::new(format!("r{i}"));
            r.record_bb_n(0x1000, i + 1);
            runs.push(r);
        }
        let merged = merge_runs_with_strategy(&runs, &MergeStrategy::Max, "merged");
        assert_eq!(merged.visit_count(0x1000), 5); // max of 1..5
    }

    // â"€â"€ AdaptiveCoverage additional â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_adaptive_register_then_ingest() {
        let mut ac = AdaptiveCoverage::new(2);
        ac.register_known_bbs(vec![0x1000, 0x2000, 0x3000]);
        assert_eq!(ac.coverage_ratio(), 0.0);
        let mut r = CoverageRun::new("r");
        r.record_bb(0x1000);
        ac.ingest(&r);
        assert!((ac.coverage_ratio() - 1.0 / 3.0).abs() < 1e-9);
    }
}

// â"€â"€â"€ CoverageRunSplitter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Splits a coverage run into per-module slices given a module map.
pub struct CoverageRunSplitter;

impl CoverageRunSplitter {
    /// Split `run` by module boundaries.
    /// `modules`: list of (`module_name`, `base_addr`, size).
    #[must_use]
    pub fn split(run: &CoverageRun, modules: &[(String, u64, u64)]) -> Vec<(String, CoverageRun)> {
        modules
            .iter()
            .map(|(name, base, size)| {
                let filter = CoverageFilter::new(*base, base + size - 1);
                let sliced = filter.apply(run);
                (name.clone(), sliced)
            })
            .collect()
    }

    /// Split and keep only modules with at least one covered BB.
    #[must_use]
    pub fn split_nonempty(
        run: &CoverageRun,
        modules: &[(String, u64, u64)],
    ) -> Vec<(String, CoverageRun)> {
        Self::split(run, modules)
            .into_iter()
            .filter(|(_, r)| !r.bb_hits.is_empty())
            .collect()
    }
}

// â"€â"€â"€ CoverageScore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A weighted coverage score combining BB, edge, and branch coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageScore {
    /// Basic-block coverage ratio [0,1].
    pub bb_ratio: f64,
    /// Edge coverage ratio [0,1].
    pub edge_ratio: f64,
    /// Branch coverage ratio [0,1].
    pub branch_ratio: f64,
    /// Combined score [0,100].
    pub score: f64,
}

impl CoverageScore {
    /// Compute a weighted coverage score.
    ///
    /// Weights: BB=0.5, edge=0.3, branch=0.2.
    #[must_use]
    pub fn compute(bb: f64, edge: f64, branch: f64) -> Self {
        let score = branch.mul_add(0.2, bb.mul_add(0.5, edge * 0.3)) * 100.0;
        Self {
            bb_ratio: bb,
            edge_ratio: edge,
            branch_ratio: branch,
            score,
        }
    }

    /// Grade: A (>=90), B (>=75), C (>=60), D (>=40), F (<40).
    #[must_use]
    pub fn grade(&self) -> &'static str {
        if self.score >= 90.0 {
            "A"
        } else if self.score >= 75.0 {
            "B"
        } else if self.score >= 60.0 {
            "C"
        } else if self.score >= 40.0 {
            "D"
        } else {
            "F"
        }
    }
}

impl std::fmt::Display for CoverageScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Score {:.1}/100 ({}) bb={:.1}% edge={:.1}% branch={:.1}%",
            self.score,
            self.grade(),
            self.bb_ratio * 100.0,
            self.edge_ratio * 100.0,
            self.branch_ratio * 100.0,
        )
    }
}

// â"€â"€â"€ CoverageRun display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl std::fmt::Display for CoverageRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoverageRun({}) bbs={} edges={} total_hits={}",
            self.name,
            self.unique_bbs(),
            self.unique_edges(),
            self.total_bb_executions(),
        )
    }
}

// â"€â"€â"€ Additional tests for new types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extra_cov_tests {
    use super::*;

    // â"€â"€ CoverageRunSplitter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_splitter_basic() {
        let mut run = CoverageRun::new("r");
        run.record_bb(0x1000); // in module A
        run.record_bb(0x5000); // in module B
        let modules = vec![
            ("modA".to_string(), 0x1000u64, 0x1000u64),
            ("modB".to_string(), 0x5000u64, 0x1000u64),
        ];
        let split = CoverageRunSplitter::split(&run, &modules);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].1.unique_bbs(), 1);
        assert_eq!(split[1].1.unique_bbs(), 1);
    }

    #[test]
    fn test_splitter_nonempty() {
        let run = CoverageRun::new("r"); // nothing covered
        let modules = vec![("modA".to_string(), 0x1000u64, 0x1000u64)];
        let split = CoverageRunSplitter::split_nonempty(&run, &modules);
        assert!(split.is_empty());
    }

    // â"€â"€ CoverageScore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_score_a_grade() {
        let s = CoverageScore::compute(0.95, 0.92, 0.90);
        assert_eq!(s.grade(), "A");
        assert!(s.score >= 90.0);
    }

    #[test]
    fn test_coverage_score_f_grade() {
        let s = CoverageScore::compute(0.1, 0.1, 0.1);
        assert_eq!(s.grade(), "F");
    }

    #[test]
    fn test_coverage_score_display() {
        let s = CoverageScore::compute(0.8, 0.7, 0.6);
        let d = s.to_string();
        assert!(d.contains("Score"));
        assert!(d.contains("bb="));
    }

    #[test]
    fn test_coverage_score_zero() {
        let s = CoverageScore::compute(0.0, 0.0, 0.0);
        assert!((s.score - 0.0).abs() < 1e-9);
        assert_eq!(s.grade(), "F");
    }

    #[test]
    fn test_coverage_score_full() {
        let s = CoverageScore::compute(1.0, 1.0, 1.0);
        assert!((s.score - 100.0).abs() < 1e-9);
        assert_eq!(s.grade(), "A");
    }

    // â"€â"€ CoverageRun Display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_run_display() {
        let mut run = CoverageRun::new("my_run");
        run.record_bb_n(0x1000, 5);
        run.record_edge(0x1000, 0x2000);
        let s = run.to_string();
        assert!(s.contains("my_run"));
        assert!(s.contains("bbs=1"));
    }

    // â"€â"€ BranchTracker (all branches) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_branch_tracker_all_branches() {
        let mut bt = BranchTracker::new();
        bt.record(0x1000, true);
        bt.record(0x2000, false);
        let all = bt.all_branches();
        assert_eq!(all.len(), 2);
    }

    // â"€â"€ CoverageQuery with multiple filters â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_query_combined_filters() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 3); // in range, above threshold
        run.record_bb_n(0x1500, 15); // in range, above threshold
        run.record_bb_n(0x3000, 7); // out of range
        let results = CoverageQuery::all()
            .min_hits(2)
            .in_range(0x1000, 0x2000)
            .hottest_first()
            .execute(&run);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, 0x1500); // hottest first
    }

    // â"€â"€ DrcovData to_run â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_drcov_to_run() {
        let d = DrcovData {
            modules: vec![DrcovModule {
                id: 0,
                base: 0x400000,
                end: 0x500000,
                name: "t".into(),
            }],
            basic_blocks: vec![
                DrcovBasicBlock {
                    start: 0x1000,
                    size: 4,
                    mod_id: 0,
                },
                DrcovBasicBlock {
                    start: 0x1004,
                    size: 4,
                    mod_id: 0,
                },
            ],
        };
        let run = d.to_run("drcov_run");
        assert_eq!(run.name, "drcov_run");
        assert_eq!(run.unique_bbs(), 2);
    }

    // â"€â"€ FunctionStats coverage_pct edge cases â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_function_stats_zero_total_bb() {
        let fs = FunctionStats::new("empty_fn", 0x1000, 0x2000, 0);
        assert!((fs.coverage_pct() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_function_stats_not_fully_covered() {
        let mut fs = FunctionStats::new("partial", 0x1000, 0x2000, 5);
        fs.covered_bb = 4;
        assert!(!fs.is_fully_covered());
    }

    // â"€â"€ CoverageSession bitmap â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_session_bitmap_grows() {
        let mut session = CoverageSession::new("s");
        let bm0 = session.bitmap.count_set();
        let mut r = CoverageRun::new("r");
        r.record_bb(0x1000);
        session.add_run(r);
        let bm1 = session.bitmap.count_set();
        assert!(bm1 >= bm0);
    }

    // â"€â"€ LcovRecord line/function coverage ratios â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lcov_record_line_coverage_ratio() {
        let mut rec = LcovRecord::new();
        rec.lines_found = 10;
        rec.lines_hit = 8;
        assert!((rec.line_coverage_ratio() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_lcov_record_function_coverage_ratio() {
        let mut rec = LcovRecord::new();
        rec.functions_found = 5;
        rec.functions_hit = 3;
        assert!((rec.function_coverage_ratio() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn test_lcov_record_zero_found() {
        let rec = LcovRecord::new();
        assert!((rec.line_coverage_ratio() - 1.0).abs() < 1e-9);
        assert!((rec.function_coverage_ratio() - 1.0).abs() < 1e-9);
    }

    // â"€â"€ CoverageFilter edge (to == lo) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_filter_single_address() {
        let f = CoverageFilter::new(0x1000, 0x1000);
        assert!(f.contains(0x1000));
        assert!(!f.contains(0x1001));
        assert!(!f.contains(0x0FFF));
    }

    // â"€â"€ CoverageAnnotator empty lookup â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_annotator_lookup_empty() {
        let ann = CoverageAnnotator::new();
        assert!(ann.lookup(0x1000).is_none());
    }

    // â"€â"€ CoveragePatch empty â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_patch_empty_does_not_change() {
        let mut run = CoverageRun::new("r");
        run.record_bb_n(0x1000, 7);
        let patch = CoveragePatch::new();
        let patched = patch.apply(&run);
        assert_eq!(patched.visit_count(0x1000), 7);
    }

    // â"€â"€ FullCoverageReport fully_covered â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_full_report_fully_covered_functions() {
        let mut session = CoverageSession::new("s");
        let mut r = CoverageRun::new("r");
        r.record_bb(0x1000);
        session.add_run(r);
        let mut funcs = vec![FunctionStats::new("f", 0x1000, 0x2000, 1)];
        funcs[0].covered_bb = 1;
        let report = FullCoverageReport::build("T", &session, &funcs);
        let fully = report.fully_covered_functions();
        assert_eq!(fully.len(), 1);
    }

    // â"€â"€ CoverageRunSplitter all-empty â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_splitter_all_empty_modules() {
        let run = CoverageRun::new("empty");
        let mods = vec![
            ("a".to_string(), 0x1000u64, 0x1000u64),
            ("b".to_string(), 0x5000u64, 0x1000u64),
        ];
        let split = CoverageRunSplitter::split_nonempty(&run, &mods);
        assert!(split.is_empty());
    }

    // â"€â"€ CoverageScore B grade â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_score_b_grade() {
        let s = CoverageScore::compute(0.8, 0.75, 0.70);
        assert_eq!(s.grade(), "B");
    }

    // â"€â"€ CoverageScore C grade â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coverage_score_c_grade() {
        let s = CoverageScore::compute(0.6, 0.6, 0.6);
        assert_eq!(s.grade(), "C");
    }

    // â"€â"€ BranchTracker empty coverage_ratio â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_branch_tracker_empty_coverage_ratio() {
        let bt = BranchTracker::new();
        assert!((bt.coverage_ratio() - 1.0).abs() < 1e-9);
    }

    // â"€â"€ CoverageAnnotator symbols_sorted â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_annotator_symbols_sorted_order() {
        let mut ann = CoverageAnnotator::new();
        ann.add_symbol(0x3000, "bar");
        ann.add_symbol(0x1000, "foo");
        let sorted = ann.symbols_sorted();
        assert_eq!(sorted[0].0, 0x1000);
        assert_eq!(sorted[1].0, 0x3000);
    }
}

