//! `rustre-fuzz-cov`
//!
//! Coverage tracking for the `RustRE` fuzzing suite.  Supports `DRcov` (`DrMemory` /
//! `DynamoRIO`) and lcov `.info` formats, `SanitizerCoverage` PC-guard bitmaps,
//! edge-coverage bitmaps, CMPLOG value-pair recording, corpus pruning by
//! coverage contribution, and a generic [`CoverageDatabase`] for aggregating
//! multiple runs.

pub mod casts;
pub mod block_coverage_tracker;
pub mod coverage_diff;
pub mod edge_coverage;
pub mod coverage_feedback;
pub mod edge_coverage_tracker;
pub mod coverage_guide;
pub mod coverage_minimizer;
pub mod coverage_persistence;
pub mod coverage_statistics;
pub mod lcov_export;
pub mod pt_integration;
pub mod qemu_tcg_cov;
pub mod sancov_instrumentation;
pub mod source_coverage_tracker;
pub mod coverage_map_merger;
pub mod source_coverage_mapper;
pub mod coverage_diff_reporter;

use std::fmt::Write as _;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by coverage parsing / serialisation.
#[derive(Debug, Error)]
pub enum CovError {
    /// Unexpected end-of-data or malformed header.
    #[error("parse error: {0}")]
    Parse(String),
    /// An I/O error (file not found, permission denied, …).
    #[error("io error: {0}")]
    Io(String),
    /// The format version is not supported.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    /// An integer overflow or arithmetic error.
    #[error("arithmetic overflow in {0}")]
    Overflow(String),
    /// Empty input provided where non-empty data is required.
    #[error("empty input")]
    EmptyInput,
}

// ─── DrcovModule ──────────────────────────────────────────────────────────────

/// A module (shared library or executable) entry in a `DRcov` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrcovModule {
    /// Module index.
    pub id: u32,
    /// Full path on disk.
    pub path: String,
    /// Load address.
    pub base: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Optional checksum.
    pub checksum: u32,
}

impl DrcovModule {
    /// Create a new module descriptor.
    #[must_use]
    pub fn new(id: u32, path: impl Into<String>, base: u64, end: u64) -> Self {
        Self {
            id,
            path: path.into(),
            base,
            end,
            checksum: 0,
        }
    }

    /// Create a module with checksum.
    #[must_use]
    pub const fn with_checksum(mut self, checksum: u32) -> Self {
        self.checksum = checksum;
        self
    }

    /// Size of the module in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.base)
    }

    /// Returns `true` if `addr` falls within this module's address range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }

    /// Convert an absolute address to a module-relative offset.
    /// Returns `None` if the address is outside this module.
    #[must_use]
    pub const fn to_offset(&self, addr: u64) -> Option<u64> {
        if self.contains(addr) {
            Some(addr - self.base)
        } else {
            None
        }
    }
}

// ─── DrcovEntry ───────────────────────────────────────────────────────────────

/// A single basic-block hit entry in a `DRcov` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrcovEntry {
    /// Index into the module table.
    pub module_id: u16,
    /// Offset from module base.
    pub start: u32,
    /// Size of the basic block in bytes.
    pub size: u16,
}

impl DrcovEntry {
    /// Create a new entry.
    #[must_use]
    pub const fn new(module_id: u16, start: u32, size: u16) -> Self {
        Self {
            module_id,
            start,
            size,
        }
    }

    /// Absolute address of the block, given the modules table.
    #[must_use]
    pub fn absolute_addr(&self, modules: &[DrcovModule]) -> Option<u64> {
        modules
            .iter()
            .find(|m| m.id == u32::from(self.module_id))
            .map(|m| m.base + u64::from(self.start))
    }

    /// End address of the block (exclusive).
    #[must_use]
    pub fn end_addr(&self, modules: &[DrcovModule]) -> Option<u64> {
        self.absolute_addr(modules)
            .map(|a| a + u64::from(self.size))
    }
}

// ─── DrcovFile ────────────────────────────────────────────────────────────────

/// An in-memory representation of a `DRcov` coverage file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DrcovFile {
    /// `DRcov` format version (typically 2).
    pub version: u32,
    /// Flavor string (e.g. `"drcov"`, `"drcov lite"`).
    pub flavor: String,
    /// Module table.
    pub modules: Vec<DrcovModule>,
    /// Basic-block hit list.
    pub bbs: Vec<DrcovEntry>,
}

impl DrcovFile {
    /// Parse a `DRcov` binary/text file from `data`.
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] on malformed data.
    pub fn parse(data: &[u8]) -> Result<Self, CovError> {
        let text =
            std::str::from_utf8(data).map_err(|e| CovError::Parse(format!("utf8 error: {e}")))?;

        let mut file = Self::default();
        let mut lines = text.lines();

        let version_line = lines
            .next()
            .ok_or_else(|| CovError::Parse("missing version line".into()))?;
        if let Some(rest) = version_line.strip_prefix("DRCOV VERSION: ") {
            file.version = rest
                .trim()
                .parse::<u32>()
                .map_err(|_| CovError::Parse("bad version number".into()))?;
        } else {
            return Err(CovError::Parse("missing DRCOV VERSION header".into()));
        }

        let flavor_line = lines
            .next()
            .ok_or_else(|| CovError::Parse("missing flavor line".into()))?;
        if let Some(rest) = flavor_line.strip_prefix("DRCOV FLAVOR: ") {
            file.flavor = rest.trim().to_string();
        }

        let mut module_count: usize = 0;
        for line in lines.by_ref() {
            if line.starts_with("Module Table:") {
                for part in line.split(',') {
                    let part = part.trim();
                    if let Some(n) = part.strip_prefix("count ") {
                        module_count = n.trim().parse::<usize>().unwrap_or(0);
                    }
                }
                break;
            }
        }
        lines.next(); // skip Columns header

        for _ in 0..module_count {
            let line = lines
                .next()
                .ok_or_else(|| CovError::Parse("truncated module table".into()))?;
            let parts: Vec<&str> = line.splitn(7, ',').collect();
            if parts.len() < 7 {
                return Err(CovError::Parse(format!("bad module line: {line}")));
            }
            let id = parts[0]
                .trim()
                .parse::<u32>()
                .map_err(|_| CovError::Parse("bad module id".into()))?;
            let base = u64::from_str_radix(parts[1].trim().trim_start_matches("0x"), 16)
                .map_err(|_| CovError::Parse("bad module base".into()))?;
            let end = u64::from_str_radix(parts[2].trim().trim_start_matches("0x"), 16)
                .map_err(|_| CovError::Parse("bad module end".into()))?;
            let path = parts[6].trim().to_string();
            file.modules.push(DrcovModule::new(id, path, base, end));
        }

        let mut bb_count: usize = 0;
        for line in lines.by_ref() {
            if let Some(rest) = line.strip_prefix("BB Table:") {
                if let Some(n) = rest.split_whitespace().next() {
                    bb_count = n.parse::<usize>().unwrap_or(0);
                }
                break;
            }
        }

        let binary_start = locate_binary_start(data, "BB Table:");
        if let Some(offset) = binary_start {
            let binary = &data[offset..];
            let entry_size = 8;
            let max_entries = binary.len() / entry_size;
            let count = bb_count.min(max_entries);
            for i in 0..count {
                let base = i * entry_size;
                let start = u32::from_le_bytes([
                    binary[base],
                    binary[base + 1],
                    binary[base + 2],
                    binary[base + 3],
                ]);
                let size = u16::from_le_bytes([binary[base + 4], binary[base + 5]]);
                let module_id = u16::from_le_bytes([binary[base + 6], binary[base + 7]]);
                file.bbs.push(DrcovEntry::new(module_id, start, size));
            }
        }

        Ok(file)
    }

    /// Serialise this coverage file to `DRcov` v2 text + binary format.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = String::new();
        let _ = writeln!(out, "DRCOV VERSION: {}", self.version);
        let _ = writeln!(out, "DRCOV FLAVOR: {}", self.flavor);
        let _ = writeln!(
            out,
            "Module Table: version 2, count {}",
            self.modules.len()
        );
        out.push_str("Columns: id, base, end, entry, checksum, timestamp, path\n");
        for m in &self.modules {
            let _ = writeln!(
                out,
                "{}, 0x{:x}, 0x{:x}, 0x0, 0x{:08x}, 0x0, {}",
                m.id, m.base, m.end, m.checksum, m.path
            );
        }
        let _ = writeln!(out, "BB Table: {} bbs", self.bbs.len());

        let mut bytes = out.into_bytes();
        for bb in &self.bbs {
            bytes.extend_from_slice(&bb.start.to_le_bytes());
            bytes.extend_from_slice(&bb.size.to_le_bytes());
            bytes.extend_from_slice(&bb.module_id.to_le_bytes());
        }
        bytes
    }

    /// Count the number of basic blocks per module.
    #[must_use]
    pub fn blocks_per_module(&self) -> HashMap<u16, usize> {
        let mut map = HashMap::new();
        for bb in &self.bbs {
            *map.entry(bb.module_id).or_insert(0) += 1;
        }
        map
    }

    /// Merge another `DrcovFile`'s basic-block hits into this one.
    /// Only merges BB entries; modules are not duplicated.
    pub fn merge_bbs(&mut self, other: &Self) {
        self.bbs.extend_from_slice(&other.bbs);
    }
}

fn locate_binary_start(data: &[u8], marker: &str) -> Option<usize> {
    let marker_bytes = marker.as_bytes();
    for i in 0..=data.len().saturating_sub(marker_bytes.len()) {
        if data[i..].starts_with(marker_bytes) {
            let line_end = data[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(data.len(), |pos| i + pos + 1);
            return Some(line_end);
        }
    }
    None
}

// ─── CoverageRun ──────────────────────────────────────────────────────────────

/// A single fuzzing or test run's coverage data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRun {
    /// Human-readable name for the run.
    pub name: String,
    /// Map from absolute basic-block address to hit count.
    pub bb_hits: HashMap<u64, u64>,
    /// When this run was captured.
    pub timestamp: SystemTime,
    /// Optional source: file path that produced this run.
    pub source: Option<String>,
    /// Total number of executions that contributed to this run.
    pub total_executions: u64,
}

impl CoverageRun {
    /// Create a new empty run.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bb_hits: HashMap::new(),
            timestamp: SystemTime::now(),
            source: None,
            total_executions: 0,
        }
    }

    /// Record a hit at `addr`.
    pub fn hit(&mut self, addr: u64) {
        *self.bb_hits.entry(addr).or_insert(0) += 1;
    }

    /// Record `count` hits at `addr`.
    pub fn hit_n(&mut self, addr: u64, count: u64) {
        *self.bb_hits.entry(addr).or_insert(0) += count;
    }

    /// Number of distinct basic blocks hit.
    #[must_use]
    pub fn distinct_blocks(&self) -> usize {
        self.bb_hits.len()
    }

    /// Total cumulative hits across all blocks.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.bb_hits.values().sum()
    }

    /// Blocks hit exactly once.
    #[must_use]
    pub fn singleton_blocks(&self) -> Vec<u64> {
        self.bb_hits
            .iter()
            .filter(|&(_, &c)| c == 1)
            .map(|(&a, _)| a)
            .collect()
    }

    /// Merge another run's hits into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.bb_hits {
            *self.bb_hits.entry(addr).or_insert(0) += count;
        }
        self.total_executions += other.total_executions;
    }

    /// Hot blocks (hit count >= `threshold`).
    #[must_use]
    pub fn hot_blocks(&self, threshold: u64) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .bb_hits
            .iter()
            .filter(|&(_, &c)| c >= threshold)
            .map(|(&a, _)| a)
            .collect();
        out.sort_unstable();
        out
    }

    /// Whether `addr` was hit.
    #[must_use]
    pub fn was_hit(&self, addr: u64) -> bool {
        self.bb_hits.get(&addr).copied().unwrap_or(0) > 0
    }

    /// Coverage density: `distinct_blocks / total_unique_known` (0.0–1.0).
    /// Returns 0.0 when `total` is 0.
    #[must_use]
    pub fn density(&self, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            crate::casts::usize_to_f64(self.distinct_blocks()) / crate::casts::u64_to_f64(total)
        }
    }
}

// ─── CoverageDiff ─────────────────────────────────────────────────────────────

/// Difference between two coverage runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageDiff {
    /// Addresses hit only in run A.
    pub only_in_a: Vec<u64>,
    /// Addresses hit only in run B.
    pub only_in_b: Vec<u64>,
    /// Addresses hit in both runs.
    pub in_both: Vec<u64>,
}

impl CoverageDiff {
    /// Jaccard similarity index.
    #[must_use]
    pub fn jaccard(&self) -> f64 {
        let union = self.only_in_a.len() + self.only_in_b.len() + self.in_both.len();
        if union == 0 {
            1.0
        } else {
            crate::casts::usize_to_f64(self.in_both.len()) / crate::casts::usize_to_f64(union)
        }
    }

    /// True if both runs cover exactly the same blocks.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty()
    }
}

// ─── CoverageStats ────────────────────────────────────────────────────────────

/// Summary statistics for a single coverage run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    /// Total number of known basic blocks (may be 0 if unknown).
    pub total_blocks: u64,
    /// Number of blocks actually hit.
    pub hit_blocks: u64,
    /// Coverage percentage (0.0–100.0), or 0 if `total_blocks` is 0.
    pub coverage_pct: f64,
    /// Number of blocks hit exactly once ("unique" first-time hits).
    pub unique_blocks: u64,
    /// Maximum hit count for any single block.
    pub max_hit_count: u64,
    /// Total cumulative hits.
    pub total_hits: u64,
}

// ─── CoverageDatabase ─────────────────────────────────────────────────────────

/// Aggregates multiple coverage runs and supports diff/stats queries.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CoverageDatabase {
    /// All registered runs.
    pub runs: Vec<CoverageRun>,
}

impl CoverageDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a run to the database.
    pub fn add_run(&mut self, run: CoverageRun) {
        self.runs.push(run);
    }

    /// Load a `DRcov` file and create a [`CoverageRun`] from it.
    ///
    /// # Errors
    /// Returns [`CovError`] if the file cannot be read or parsed.
    pub fn load_drcov(path: &Path) -> Result<CoverageRun, CovError> {
        let data = std::fs::read(path).map_err(|e| CovError::Io(e.to_string()))?;
        let drcov = DrcovFile::parse(&data)?;
        let mut run = CoverageRun::new(path.display().to_string());
        for bb in &drcov.bbs {
            if let Some(addr) = bb.absolute_addr(&drcov.modules) {
                run.hit(addr);
            }
        }
        Ok(run)
    }

    /// Compute the diff between two runs.
    #[must_use]
    pub fn diff(a: &CoverageRun, b: &CoverageRun) -> CoverageDiff {
        let mut diff = CoverageDiff::default();
        for &addr in a.bb_hits.keys() {
            if b.bb_hits.contains_key(&addr) {
                diff.in_both.push(addr);
            } else {
                diff.only_in_a.push(addr);
            }
        }
        for &addr in b.bb_hits.keys() {
            if !a.bb_hits.contains_key(&addr) {
                diff.only_in_b.push(addr);
            }
        }
        diff.only_in_a.sort_unstable();
        diff.only_in_b.sort_unstable();
        diff.in_both.sort_unstable();
        diff
    }

    /// Compute summary statistics for `run`.
    ///
    /// `total_known_blocks` is the total number of known basic blocks in the
    /// target (e.g. derived from static analysis).  Pass `0` when unknown; in
    /// that case `total_blocks` will equal `hit_blocks` and `coverage_pct` will
    /// be `0.0` to signal that the percentage cannot be computed.
    #[must_use]
    pub fn stats(run: &CoverageRun, total_known_blocks: u64) -> CoverageStats {
        let hit_blocks = run.bb_hits.len() as u64;
        let unique_blocks = run.bb_hits.values().filter(|&&c| c == 1).count() as u64;
        let max_hit_count = run.bb_hits.values().copied().max().unwrap_or(0);
        let total_hits: u64 = run.bb_hits.values().sum();
        let total_blocks = if total_known_blocks > 0 {
            total_known_blocks
        } else {
            hit_blocks
        };
        let coverage_pct = if total_blocks > 0 {
            (crate::casts::u64_to_f64(hit_blocks) / crate::casts::u64_to_f64(total_blocks)) * 100.0
        } else {
            0.0
        };
        CoverageStats {
            total_blocks,
            hit_blocks,
            coverage_pct,
            unique_blocks,
            max_hit_count,
            total_hits,
        }
    }

    /// Merge all runs in this database into a single aggregated run.
    #[must_use]
    pub fn aggregate(&self) -> CoverageRun {
        let mut agg = CoverageRun::new("aggregate");
        for run in &self.runs {
            agg.merge(run);
        }
        agg
    }

    /// Return all addresses that appear in every run (intersection).
    #[must_use]
    pub fn intersection(&self) -> Vec<u64> {
        if self.runs.is_empty() {
            return Vec::new();
        }
        let first: HashSet<u64> = self.runs[0].bb_hits.keys().copied().collect();
        let mut result = first;
        for run in &self.runs[1..] {
            let set: HashSet<u64> = run.bb_hits.keys().copied().collect();
            result.retain(|a| set.contains(a));
        }
        let mut v: Vec<u64> = result.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Return all addresses that appear in at least one run (union).
    #[must_use]
    pub fn union_coverage(&self) -> Vec<u64> {
        let mut set = HashSet::new();
        for run in &self.runs {
            set.extend(run.bb_hits.keys().copied());
        }
        let mut v: Vec<u64> = set.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Find runs that contributed at least one new block not seen in earlier runs.
    #[must_use]
    pub fn unique_runs(&self) -> Vec<&CoverageRun> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for run in &self.runs {
            let new: HashSet<u64> = run.bb_hits.keys().copied().collect();
            if new.iter().any(|a| !seen.contains(a)) {
                result.push(run);
                seen.extend(new);
            }
        }
        result
    }
}

// ─── LcovRecord / LcovParser ──────────────────────────────────────────────────

/// Result of parsing a single lcov record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LcovRecord {
    /// Source file path (from `SF:` tag).
    pub source_file: Option<String>,
    /// Test name (from `TN:` tag).
    pub test_name: Option<String>,
    /// Function hit counts: function name → hit count.
    pub functions: HashMap<String, u64>,
    /// Function start lines: function name → line number.
    pub function_lines: HashMap<String, u32>,
    /// Line hit counts: line number → hit count.
    pub line_hits: HashMap<u32, u64>,
    /// Branch hit count (total `BRH:` value).
    pub branch_hits: u64,
    /// Total branches found (from `BRF:`).
    pub branch_found: u64,
    /// Total lines found (from `LF:`).
    pub lines_found: u64,
    /// Total lines hit (from `LH:`).
    pub lines_hit: u64,
}

impl LcovRecord {
    /// Line coverage percentage.
    #[must_use]
    pub fn line_coverage_pct(&self) -> f64 {
        if self.lines_found == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.lines_hit) / crate::casts::u64_to_f64(self.lines_found) * 100.0
        }
    }

    /// Whether all known lines are covered.
    #[must_use]
    pub const fn is_fully_covered(&self) -> bool {
        self.lines_found > 0 && self.lines_hit >= self.lines_found
    }

    /// Number of functions hit at least once.
    #[must_use]
    pub fn functions_hit(&self) -> usize {
        self.functions.values().filter(|&&c| c > 0).count()
    }
}

/// Parser for lcov `.info` files.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LcovParser {
    /// All parsed records (one per `end_of_record` section).
    pub records: Vec<LcovRecord>,
}

impl LcovParser {
    /// Create a new empty parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a complete lcov `.info` file from `text`.
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] on malformed data.
    pub fn parse(&mut self, text: &str) -> Result<(), CovError> {
        let mut current = LcovRecord::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "end_of_record" {
                self.records.push(current);
                current = LcovRecord::default();
                continue;
            }
            if let Some(rest) = line.strip_prefix("TN:") {
                current.test_name = Some(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("SF:") {
                current.source_file = Some(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("FN:") {
                if let Some((line_str, name)) = rest.split_once(',') {
                    let line_no: u32 = line_str.trim().parse().unwrap_or(0);
                    current.function_lines.insert(name.to_string(), line_no);
                    current.functions.entry(name.to_string()).or_insert(0);
                }
            } else if let Some(rest) = line.strip_prefix("FNDA:") {
                if let Some((count_str, name)) = rest.split_once(',') {
                    let count: u64 = count_str.parse().unwrap_or(0);
                    *current.functions.entry(name.to_string()).or_insert(0) += count;
                }
            } else if let Some(rest) = line.strip_prefix("DA:") {
                let mut parts = rest.split(',');
                if let (Some(line_str), Some(count_str)) = (parts.next(), parts.next()) {
                    let line_no: u32 = line_str.trim().parse().unwrap_or(0);
                    let count: u64 = count_str.trim().parse().unwrap_or(0);
                    *current.line_hits.entry(line_no).or_insert(0) += count;
                }
            } else if let Some(rest) = line.strip_prefix("BRH:") {
                let count: u64 = rest.trim().parse().unwrap_or(0);
                current.branch_hits += count;
            } else if let Some(rest) = line.strip_prefix("BRF:") {
                let count: u64 = rest.trim().parse().unwrap_or(0);
                current.branch_found = count;
            } else if let Some(rest) = line.strip_prefix("LF:") {
                let count: u64 = rest.trim().parse().unwrap_or(0);
                current.lines_found = count;
            } else if let Some(rest) = line.strip_prefix("LH:") {
                let count: u64 = rest.trim().parse().unwrap_or(0);
                current.lines_hit = count;
            }
        }
        Ok(())
    }

    /// Total number of distinct source lines hit across all records.
    #[must_use]
    pub fn total_lines_hit(&self) -> usize {
        self.records
            .iter()
            .map(|r| r.line_hits.values().filter(|&&c| c > 0).count())
            .sum()
    }

    /// Aggregate all records into a single flat line-hits map (file → (line → count)).
    #[must_use]
    pub fn aggregate_by_file(&self) -> HashMap<String, HashMap<u32, u64>> {
        let mut out: HashMap<String, HashMap<u32, u64>> = HashMap::new();
        for rec in &self.records {
            if let Some(ref sf) = rec.source_file {
                let file_map = out.entry(sf.clone()).or_default();
                for (&line, &count) in &rec.line_hits {
                    *file_map.entry(line).or_insert(0) += count;
                }
            }
        }
        out
    }

    /// Total branches hit across all records.
    #[must_use]
    pub fn total_branch_hits(&self) -> u64 {
        self.records.iter().map(|r| r.branch_hits).sum()
    }

    /// Overall line coverage percentage across all records.
    #[must_use]
    pub fn overall_line_coverage_pct(&self) -> f64 {
        let found: u64 = self.records.iter().map(|r| r.lines_found).sum();
        let hit: u64 = self.records.iter().map(|r| r.lines_hit).sum();
        if found == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(hit) / crate::casts::u64_to_f64(found) * 100.0
        }
    }

    /// All source files referenced.
    #[must_use]
    pub fn source_files(&self) -> Vec<&str> {
        self.records
            .iter()
            .filter_map(|r| r.source_file.as_deref())
            .collect()
    }
}

// ─── PcGuardBitmap ────────────────────────────────────────────────────────────

/// A `SanitizerCoverage` PC-guard coverage bitmap.
///
/// Each byte represents one edge (guard). Non-zero means the edge was hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcGuardBitmap {
    /// Raw bitmap bytes.
    pub bits: Vec<u8>,
}

impl PcGuardBitmap {
    /// Create a new bitmap of `size` bytes (all zero).
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            bits: vec![0u8; size],
        }
    }

    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bits: bytes }
    }

    /// Record a hit at guard index `idx`.
    ///
    /// Silently ignored if `idx >= self.bits.len()`.
    pub fn record_hit(&mut self, idx: usize) {
        if let Some(b) = self.bits.get_mut(idx) {
            *b = b.saturating_add(1);
        }
    }

    /// Number of guards that were hit at least once.
    #[must_use]
    pub fn coverage_count(&self) -> usize {
        self.bits.iter().filter(|&&b| b > 0).count()
    }

    /// Coverage density (0.0–1.0).
    #[must_use]
    pub fn density(&self) -> f64 {
        if self.bits.is_empty() {
            0.0
        } else {
            crate::casts::usize_to_f64(self.coverage_count()) / crate::casts::usize_to_f64(self.bits.len())
        }
    }

    /// Merge another bitmap into this one (OR-merge).
    pub fn merge(&mut self, other: &Self) {
        let len = self.bits.len().min(other.bits.len());
        for i in 0..len {
            if other.bits[i] > 0 {
                self.bits[i] = self.bits[i].saturating_add(other.bits[i]);
            }
        }
    }

    /// Reset all bits.
    pub fn reset(&mut self) {
        self.bits.iter_mut().for_each(|b| *b = 0);
    }

    /// Return indices of all hit guards.
    #[must_use]
    pub fn hit_guards(&self) -> Vec<usize> {
        self.bits
            .iter()
            .enumerate()
            .filter(|(_, b)| **b > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// FNV-1a hash of the bitmap (for deduplication).
    #[must_use]
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.bits {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Return the number of new guards set when merging `other` into a copy.
    #[must_use]
    pub fn new_bits_from(&self, other: &Self) -> usize {
        let len = self.bits.len().min(other.bits.len());
        (0..len)
            .filter(|&i| other.bits[i] > 0 && self.bits[i] == 0)
            .count()
    }
}

// ─── EdgeCoverageMap ──────────────────────────────────────────────────────────

/// An edge-coverage map that tracks (from, to) pairs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeCoverageMap {
    /// Map of edge (from, to) → hit count.
    edges: BTreeMap<(u64, u64), u64>,
}

impl EdgeCoverageMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transition from `from` to `to`.
    pub fn record(&mut self, from: u64, to: u64) {
        *self.edges.entry((from, to)).or_insert(0) += 1;
    }

    /// Record `count` transitions from `from` to `to`.
    pub fn record_n(&mut self, from: u64, to: u64, count: u64) {
        *self.edges.entry((from, to)).or_insert(0) += count;
    }

    /// Total number of distinct edges seen.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Total number of edge traversals.
    #[must_use]
    pub fn total_traversals(&self) -> u64 {
        self.edges.values().sum()
    }

    /// Whether an edge `(from, to)` was ever traversed.
    #[must_use]
    pub fn has_edge(&self, from: u64, to: u64) -> bool {
        self.edges.get(&(from, to)).copied().unwrap_or(0) > 0
    }

    /// Hit count for a specific edge.
    #[must_use]
    pub fn edge_hits(&self, from: u64, to: u64) -> u64 {
        self.edges.get(&(from, to)).copied().unwrap_or(0)
    }

    /// Merge another map's edges into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&edge, &count) in &other.edges {
            *self.edges.entry(edge).or_insert(0) += count;
        }
    }

    /// Return hot edges with count >= `threshold`.
    #[must_use]
    pub fn hot_edges(&self, threshold: u64) -> Vec<(u64, u64, u64)> {
        self.edges
            .iter()
            .filter(|(_, c)| **c >= threshold)
            .map(|(&(f, t), &c)| (f, t, c))
            .collect()
    }

    /// Reset all edges.
    pub fn reset(&mut self) {
        self.edges.clear();
    }

    /// All successor addresses of `from`.
    #[must_use]
    pub fn successors(&self, from: u64) -> Vec<u64> {
        self.edges
            .range((from, 0)..(from, u64::MAX))
            .map(|(&(_, to), _)| to)
            .collect()
    }
}

// ─── CmplogEntry ──────────────────────────────────────────────────────────────

/// A single CMPLOG value-pair record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmplogEntry {
    /// Program counter where the comparison happened.
    pub pc: u64,
    /// Left-hand value.
    pub lhs: u64,
    /// Right-hand value.
    pub rhs: u64,
    /// Size of values in bytes (1, 2, 4, 8).
    pub size: u8,
    /// Whether this is a function-call hook.
    pub is_fn_hook: bool,
}

impl CmplogEntry {
    /// Create a new record.
    #[must_use]
    pub const fn new(pc: u64, lhs: u64, rhs: u64, size: u8, is_fn_hook: bool) -> Self {
        Self {
            pc,
            lhs,
            rhs,
            size,
            is_fn_hook,
        }
    }

    /// Whether the two sides were equal.
    #[must_use]
    pub const fn is_equal(&self) -> bool {
        self.lhs == self.rhs
    }

    /// XOR difference between lhs and rhs.
    #[must_use]
    pub const fn diff(&self) -> u64 {
        self.lhs ^ self.rhs
    }

    /// Popcount of the difference.
    #[must_use]
    pub const fn bit_diff(&self) -> u32 {
        self.diff().count_ones()
    }

    /// Mask for the effective bit width of `size` bytes.
    #[must_use]
    pub const fn mask(&self) -> u64 {
        match self.size {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffff_ffff,
            _ => u64::MAX,
        }
    }
}

// ─── CmplogMap ────────────────────────────────────────────────────────────────

/// Stores all CMPLOG records from a single execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CmplogMap {
    /// All recorded entries.
    pub entries: Vec<CmplogEntry>,
}

impl CmplogMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn record(&mut self, entry: CmplogEntry) {
        self.entries.push(entry);
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// All entries where lhs != rhs.
    #[must_use]
    pub fn unequal_entries(&self) -> Vec<&CmplogEntry> {
        self.entries.iter().filter(|e| !e.is_equal()).collect()
    }

    /// Unique PC values seen.
    #[must_use]
    pub fn unique_pcs(&self) -> Vec<u64> {
        let mut pcs: Vec<u64> = self.entries.iter().map(|e| e.pc).collect();
        pcs.sort_unstable();
        pcs.dedup();
        pcs
    }

    /// Suggest byte-string mutations by extracting rhs values from unequal entries.
    #[must_use]
    pub fn suggest_mutations(&self) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|e| !e.is_equal())
            .map(|e| {
                let n = e.size as usize;
                e.rhs.to_le_bytes()[..n.min(8)].to_vec()
            })
            .collect()
    }

    /// Total entries recorded.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── CorpusPruner ─────────────────────────────────────────────────────────────

/// Prunes a corpus to the minimal set that covers all observed edges.
///
/// Implements a greedy set-cover algorithm similar to AFL's favorite selection.
#[derive(Debug, Default)]
pub struct CorpusPruner;

impl CorpusPruner {
    /// Create a new pruner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Given a list of `(input_id, set_of_edges_covered)`, return the minimal
    /// subset of input IDs that covers all edges.
    ///
    /// # Panics
    /// Does not panic.
    #[must_use]
    pub fn prune<I>(&self, inputs: I) -> Vec<usize>
    where
        I: IntoIterator<Item = (usize, Vec<u64>)>,
    {
        // Collect inputs and build edge → list of input IDs mapping.
        let inputs: Vec<(usize, Vec<u64>)> = inputs.into_iter().collect();
        let mut edge_to_inputs: HashMap<u64, Vec<usize>> = HashMap::new();
        for (id, edges) in &inputs {
            for &e in edges {
                edge_to_inputs.entry(e).or_default().push(*id);
            }
        }

        let all_edges: HashSet<u64> = edge_to_inputs.keys().copied().collect();
        let mut covered: HashSet<u64> = HashSet::new();
        let mut selected: Vec<usize> = Vec::new();

        while covered.len() < all_edges.len() {
            // Greedy: pick the input covering the most uncovered edges.
            let best = inputs
                .iter()
                .max_by_key(|(_, edges)| edges.iter().filter(|e| !covered.contains(e)).count());
            if let Some((id, edges)) = best {
                let new: Vec<u64> = edges
                    .iter()
                    .filter(|e| !covered.contains(e))
                    .copied()
                    .collect();
                if new.is_empty() {
                    break;
                }
                covered.extend(new);
                selected.push(*id);
            } else {
                break;
            }
        }

        selected.sort_unstable();
        selected
    }
}

// ─── CoverageHistogram ────────────────────────────────────────────────────────

/// A histogram of hit counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageHistogram {
    /// Bucket → count of blocks with that hit count.
    pub buckets: BTreeMap<u64, u64>,
}

impl CoverageHistogram {
    /// Create an empty histogram.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a histogram from a coverage run.
    #[must_use]
    pub fn from_run(run: &CoverageRun) -> Self {
        let mut h = Self::new();
        for &count in run.bb_hits.values() {
            *h.buckets.entry(count).or_insert(0) += 1;
        }
        h
    }

    /// Total number of blocks represented in the histogram.
    #[must_use]
    pub fn total_blocks(&self) -> u64 {
        self.buckets.values().sum()
    }

    /// Maximum hit count bucket.
    #[must_use]
    pub fn max_bucket(&self) -> u64 {
        self.buckets.keys().copied().max().unwrap_or(0)
    }

    /// Median hit count (approximate).
    #[must_use]
    pub fn median(&self) -> u64 {
        let total = self.total_blocks();
        if total == 0 {
            return 0;
        }
        let mid = total / 2;
        let mut acc = 0u64;
        for (&k, &v) in &self.buckets {
            acc += v;
            if acc >= mid {
                return k;
            }
        }
        0
    }

    /// Mean hit count.
    #[must_use]
    pub fn mean(&self) -> f64 {
        let total_blocks = self.total_blocks();
        if total_blocks == 0 {
            return 0.0;
        }
        let sum: u64 = self.buckets.iter().map(|(&k, &v)| k * v).sum();
        crate::casts::u64_to_f64(sum) / crate::casts::u64_to_f64(total_blocks)
    }
}

// ─── DrcovHeader ─────────────────────────────────────────────────────────────

/// Parsed header from a `DRcov` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrcovHeader {
    /// Format version (e.g. 2).
    pub version: u32,
    /// Flavor string (e.g. `"drcov"`).
    pub flavor: String,
    /// Number of modules listed in the module table.
    pub module_count: u32,
}

impl DrcovHeader {
    /// Parse the three mandatory `DRcov` header lines from `data`.
    ///
    /// Returns `(header, bytes_consumed)` so the caller can slice past the
    /// header before parsing the module table.
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] for any malformed or missing header field.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), CovError> {
        let text =
            std::str::from_utf8(data).map_err(|e| CovError::Parse(format!("utf8 error: {e}")))?;

        let mut consumed = 0usize;
        let mut lines = text.lines();

        // ── line 1: "DRCOV VERSION: N" ──────────────────────────────────────
        let version_line = lines
            .next()
            .ok_or_else(|| CovError::Parse("missing DRCOV VERSION line".into()))?;
        consumed += version_line.len()
            + if data.get(consumed + version_line.len()) == Some(&b'\r') {
                2
            } else {
                1
            };
        let version = version_line
            .strip_prefix("DRCOV VERSION: ")
            .ok_or_else(|| CovError::Parse("missing DRCOV VERSION prefix".into()))?
            .trim()
            .parse::<u32>()
            .map_err(|_| CovError::Parse("bad version number".into()))?;

        // ── line 2: "DRCOV FLAVOR: <flavor>" ────────────────────────────────
        let flavor_line = lines
            .next()
            .ok_or_else(|| CovError::Parse("missing DRCOV FLAVOR line".into()))?;
        consumed += flavor_line.len()
            + if data.get(consumed + flavor_line.len()) == Some(&b'\r') {
                2
            } else {
                1
            };
        let flavor = flavor_line
            .strip_prefix("DRCOV FLAVOR: ")
            .ok_or_else(|| CovError::Parse("missing DRCOV FLAVOR prefix".into()))?
            .trim()
            .to_string();

        // ── line 3: "Module Table: version N, count M" ──────────────────────
        let mod_table_line = lines
            .next()
            .ok_or_else(|| CovError::Parse("missing Module Table line".into()))?;
        consumed += mod_table_line.len()
            + if data.get(consumed + mod_table_line.len()) == Some(&b'\r') {
                2
            } else {
                1
            };
        if !mod_table_line.starts_with("Module Table:") {
            return Err(CovError::Parse(format!(
                "expected 'Module Table:' header, got: {mod_table_line}"
            )));
        }
        let mut module_count = 0u32;
        for part in mod_table_line.split(',') {
            let part = part.trim();
            if let Some(n) = part.strip_prefix("count ") {
                module_count = n
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| CovError::Parse("bad module count".into()))?;
            }
        }

        Ok((
            Self {
                version,
                flavor,
                module_count,
            },
            consumed,
        ))
    }
}

// ─── DrcovBasicBlock ──────────────────────────────────────────────────────────

/// A single basic-block entry from the `DRcov` BB table (8 bytes on disk).
///
/// Layout: `[start: u32 LE][size: u16 LE][module_id: u16 LE]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrcovBasicBlock {
    /// Offset from the module's base address.
    pub start: u32,
    /// Size of the basic block in bytes.
    pub size: u16,
    /// Index into the module table.
    pub module_id: u16,
}

impl DrcovBasicBlock {
    /// Parse the BB table from `data`.
    ///
    /// Expects the text header `"BB Table: N bbs\n"` followed immediately by
    /// `N * 8` bytes of binary entries.
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] when the header or binary data is malformed.
    pub fn parse_bb_table(data: &[u8]) -> Result<Vec<Self>, CovError> {
        // Find "BB Table: " header.
        let marker = b"BB Table: ";
        let marker_pos = data
            .windows(marker.len())
            .position(|w| w == marker)
            .ok_or_else(|| CovError::Parse("BB Table header not found".into()))?;

        // Read the count from the header line.
        let header_start = marker_pos + marker.len();
        let newline = data[header_start..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| CovError::Parse("BB Table header not terminated".into()))?;
        let header_text = std::str::from_utf8(&data[header_start..header_start + newline])
            .map_err(|e| CovError::Parse(format!("utf8 in BB header: {e}")))?;
        let bb_count: usize = header_text
            .split_whitespace()
            .next()
            .ok_or_else(|| CovError::Parse("empty BB count field".into()))?
            .parse::<usize>()
            .map_err(|_| CovError::Parse("bad BB count".into()))?;

        let binary_offset = header_start + newline + 1;
        let binary = &data[binary_offset..];
        let entry_size = 8usize;
        let available = binary.len() / entry_size;
        let count = bb_count.min(available);

        let mut bbs = Vec::with_capacity(count);
        for i in 0..count {
            let b = i * entry_size;
            let start =
                u32::from_le_bytes([binary[b], binary[b + 1], binary[b + 2], binary[b + 3]]);
            let size = u16::from_le_bytes([binary[b + 4], binary[b + 5]]);
            let module_id = u16::from_le_bytes([binary[b + 6], binary[b + 7]]);
            bbs.push(Self {
                start,
                size,
                module_id,
            });
        }
        Ok(bbs)
    }

    /// Absolute address of this block given a module base.
    #[must_use]
    pub fn absolute_addr(&self, module_base: u64) -> u64 {
        module_base.saturating_add(u64::from(self.start))
    }
}

// ─── DrcovModuleV2 ────────────────────────────────────────────────────────────

/// A fully-parsed module entry, including the `entry` field required by the
/// spec.  Named `DrcovModuleV2` to avoid colliding with the existing
/// [`DrcovModule`] type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrcovModuleV2 {
    /// Module index.
    pub id: u32,
    /// Load base address.
    pub base: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Entry point address.
    pub entry: u64,
    /// Full path on disk.
    pub path: String,
}

impl DrcovModuleV2 {
    /// Parse the module table from `data`.
    ///
    /// Expects tab- or comma-separated entries.  Skips any leading "Columns:"
    /// header line.
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] on malformed lines.
    pub fn parse_table(data: &[u8], count: u32) -> Result<Vec<Self>, CovError> {
        // Cap allocation to prevent OOM from attacker-controlled `count` (max u32 = 4G entries).
        const MAX_MODULE_COUNT: usize = 65_536;
        let text =
            std::str::from_utf8(data).map_err(|e| CovError::Parse(format!("utf8 error: {e}")))?;

        let capacity = (count as usize).min(MAX_MODULE_COUNT);
        let mut modules = Vec::with_capacity(capacity);
        let mut iter = text.lines();

        // Skip optional "Columns:" header.
        if let Some(first) = iter.next()
            && !first.trim_start().starts_with("Columns:") {
                // Not a columns header — parse it as first data row.
                if let Some(m) = Self::parse_line(first)? {
                    modules.push(m);
                }
            }

        for line in iter {
            if modules.len() >= count as usize {
                break;
            }
            if let Some(m) = Self::parse_line(line)? {
                modules.push(m);
            }
        }
        Ok(modules)
    }

    fn parse_line(line: &str) -> Result<Option<Self>, CovError> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }
        // Support both tab-separated and comma-separated formats.
        let parts: Vec<&str> = if line.contains('\t') {
            line.splitn(5, '\t').collect()
        } else {
            line.splitn(7, ',').map(str::trim).collect()
        };
        if parts.len() < 5 {
            return Err(CovError::Parse(format!(
                "too few columns in module line: {line}"
            )));
        }
        let id = parts[0]
            .trim()
            .parse::<u32>()
            .map_err(|_| CovError::Parse(format!("bad module id: '{}'", parts[0])))?;
        let parse_hex = |s: &str| -> Result<u64, CovError> {
            let s = s.trim().trim_start_matches("0x");
            u64::from_str_radix(s, 16).map_err(|_| CovError::Parse(format!("bad hex value: '{s}'")))
        };
        let base = parse_hex(parts[1])?;
        let end = parse_hex(parts[2])?;
        let entry = parse_hex(parts[3])?;
        // Path is the last field; comma-format has checksum/timestamp before path.
        let path = parts[parts.len() - 1].trim().to_string();
        Ok(Some(Self {
            id,
            base,
            end,
            entry,
            path,
        }))
    }

    /// Returns `true` if `addr` falls within `[base, end)`.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }

    /// Size of the module in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.base)
    }
}

// ─── DrcovFileV2 ─────────────────────────────────────────────────────────────

/// A fully-parsed `DRcov` file (header + module table + BB table).
///
/// This is distinct from the existing [`DrcovFile`] to keep backward
/// compatibility while providing the richer API required by §18.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrcovFileV2 {
    /// Parsed header (version, flavor, `module_count`).
    pub header: DrcovHeader,
    /// Module table.
    pub modules: Vec<DrcovModuleV2>,
    /// Basic-block hit list.
    pub bbs: Vec<DrcovBasicBlock>,
}

impl DrcovFileV2 {
    /// Open `path`, read the file, and parse a [`DrcovFileV2`].
    ///
    /// # Errors
    /// Returns [`CovError::Io`] or [`CovError::Parse`] on failure.
    pub fn load(path: &Path) -> Result<Self, CovError> {
        let data = std::fs::read(path).map_err(|e| CovError::Io(e.to_string()))?;
        Self::parse(&data)
    }

    /// Parse a `DRcov` file from raw bytes.
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] on malformed data.
    pub fn parse(data: &[u8]) -> Result<Self, CovError> {
        let (header, hdr_consumed) = DrcovHeader::parse(data)?;
        let rest = &data[hdr_consumed..];

        // Parse the module table (rest starts right after the "Module Table:" line).
        let modules = DrcovModuleV2::parse_table(rest, header.module_count)?;

        // Parse the BB table from the full buffer (locate_binary_start finds it).
        let bbs = DrcovBasicBlock::parse_bb_table(data)?;

        Ok(Self {
            header,
            modules,
            bbs,
        })
    }

    /// Convert all basic blocks to `(absolute_addr, size)` pairs.
    ///
    /// Blocks whose `module_id` does not match any module are silently skipped.
    #[must_use]
    pub fn absolute_bbs(&self) -> Vec<(u64, u16)> {
        self.bbs
            .iter()
            .filter_map(|bb| {
                self.modules
                    .iter()
                    .find(|m| m.id == u32::from(bb.module_id))
                    .map(|m| (m.base + u64::from(bb.start), bb.size))
            })
            .collect()
    }

    /// All basic blocks whose absolute address falls within `[start, end)`.
    #[must_use]
    pub fn bbs_in_range(&self, start: u64, end: u64) -> Vec<(u64, u16)> {
        self.absolute_bbs()
            .into_iter()
            .filter(|(addr, _)| *addr >= start && *addr < end)
            .collect()
    }

    /// Total number of distinct modules.
    #[must_use]
    pub const fn module_count(&self) -> usize {
        self.modules.len()
    }
}

// ─── LcovParser (§18.1 variant) ──────────────────────────────────────────────

/// Per-file coverage data from an lcov `.info` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileCoverage {
    /// Source file path.
    pub source_file: std::path::PathBuf,
    /// Map from line number to hit count.
    pub lines: HashMap<u32, u32>,
    /// Map from function name to hit count.
    pub functions: HashMap<String, u32>,
}

impl FileCoverage {
    /// Number of lines with at least one hit.
    #[must_use]
    pub fn lines_hit(&self) -> usize {
        self.lines.values().filter(|&&c| c > 0).count()
    }

    /// Number of functions with at least one hit.
    #[must_use]
    pub fn functions_hit(&self) -> usize {
        self.functions.values().filter(|&&c| c > 0).count()
    }

    /// Line coverage as a percentage (0.0–100.0).
    #[must_use]
    pub fn line_coverage_pct(&self) -> f32 {
        let total = self.lines.len();
        if total == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f32(self.lines_hit()) / crate::casts::usize_to_f32(total) * 100.0
    }
}

/// Aggregated lcov coverage data keyed by source file path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageData {
    /// Per-file coverage data.
    pub files: HashMap<String, FileCoverage>,
}

impl CoverageData {
    /// Create an empty instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total lines hit across all files.
    #[must_use]
    pub fn total_lines_hit(&self) -> usize {
        self.files.values().map(FileCoverage::lines_hit).sum()
    }

    /// Total lines tracked across all files.
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.files.values().map(|f| f.lines.len()).sum()
    }

    /// Overall line coverage as a percentage.
    #[must_use]
    pub fn overall_line_coverage_pct(&self) -> f32 {
        let total = self.total_lines();
        if total == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f32(self.total_lines_hit()) / crate::casts::usize_to_f32(total) * 100.0
    }
}

/// Parser for lcov `.info` files (§18.1 variant).
///
/// Produces a [`CoverageData`] aggregate keyed by source file.
pub struct LcovInfoParser;

impl LcovInfoParser {
    /// Parse an lcov `.info` file from `content`.
    ///
    /// Handles the following record types:
    /// - `SF:` — source file
    /// - `DA:` — line, hits
    /// - `FN:` — line, `function_name`
    /// - `FNDA:` — hits, `function_name`
    /// - `end_of_record`
    ///
    /// # Errors
    /// Returns [`CovError::Parse`] on malformed data.
    pub fn parse(content: &str) -> Result<CoverageData, CovError> {
        let mut data = CoverageData::default();
        let mut current_file: Option<String> = None;
        let mut current: FileCoverage = FileCoverage::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "end_of_record" {
                if let Some(sf) = current_file.take() {
                    let entry = data.files.entry(sf.clone()).or_default();
                    entry.source_file = std::path::PathBuf::from(sf);
                    // Merge into existing entry (multiple records per file).
                    for (k, v) in current.lines.drain() {
                        *entry.lines.entry(k).or_insert(0) += v;
                    }
                    for (k, v) in current.functions.drain() {
                        *entry.functions.entry(k).or_insert(0) += v;
                    }
                }
                current = FileCoverage::default();
                continue;
            }
            if let Some(rest) = line.strip_prefix("SF:") {
                current_file = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("DA:") {
                // DA:<line_number>,<count>[,<checksum>]
                let mut parts = rest.splitn(3, ',');
                if let (Some(line_str), Some(count_str)) = (parts.next(), parts.next()) {
                    let line_no: u32 = line_str
                        .trim()
                        .parse()
                        .map_err(|_| CovError::Parse(format!("bad DA line: {line}")))?;
                    let count: u32 = count_str.trim().parse().unwrap_or(0);
                    *current.lines.entry(line_no).or_insert(0) += count;
                }
            } else if let Some(rest) = line.strip_prefix("FN:") {
                // FN:<line_number>,<function_name>
                if let Some((_line_str, name)) = rest.split_once(',') {
                    current
                        .functions
                        .entry(name.trim().to_string())
                        .or_insert(0);
                }
            } else if let Some(rest) = line.strip_prefix("FNDA:") {
                // FNDA:<count>,<function_name>
                if let Some((count_str, name)) = rest.split_once(',') {
                    let count: u32 = count_str.trim().parse().unwrap_or(0);
                    *current
                        .functions
                        .entry(name.trim().to_string())
                        .or_insert(0) += count;
                }
            }
            // All other record types (BRH, BRF, LF, LH, TN, …) are silently
            // accepted but not stored separately in FileCoverage.
        }
        Ok(data)
    }
}

// ─── HeatmapColors ────────────────────────────────────────────────────────────

/// Lighthouse-style heatmap colour mapping for coverage hit counts.
///
/// Colour scale (§18.1):
/// - 0 hits     → gray       `[128, 128, 128]`
/// - low        → blue       `[0,   0,   255]`
/// - medium     → yellow     `[255, 255, 0  ]`
/// - high       → red        `[255, 0,   0  ]`
/// - max hits   → bright red `[255, 64,  64 ]`
pub struct HeatmapColors;

impl HeatmapColors {
    /// Return the RGB colour for a block with `hits` out of `max_hits`.
    ///
    /// Interpolates linearly between the five colour stops above.
    #[must_use]
    pub fn color_for_hits(hits: u32, max_hits: u32) -> [u8; 3] {
        const BLUE: [u8; 3] = [0, 0, 255];
        const YELLOW: [u8; 3] = [255, 255, 0];
        const RED: [u8; 3] = [255, 0, 0];
        const BRIGHT_RED: [u8; 3] = [255, 64, 64];
        if hits == 0 {
            return [128, 128, 128]; // gray — not covered
        }
        if max_hits == 0 || hits >= max_hits {
            return [255, 64, 64]; // bright red — maximum hits
        }
        // Normalise to [0.0, 1.0].

        let t = crate::casts::u32_to_f32(hits) / crate::casts::u32_to_f32(max_hits);

        // Four colour-stop intervals:
        //   [0.0, 0.25) → blue  → yellow
        //   [0.25, 0.5) → yellow → red  (already a typo in spec; keep as blue→yellow→red→bright red)
        //   [0.5, 0.75) → yellow → red
        //   [0.75, 1.0] → red  → bright red
        //
        // Stops at t = 0 (blue), 0.33 (yellow), 0.66 (red), 1.0 (bright red).
        let lerp = |a: u8, b: u8, frac: f32| -> u8 {
            let a = f32::from(a);
            let b = f32::from(b);
            crate::casts::f32_to_u8((b - a).mul_add(frac, a).round().clamp(0.0, 255.0))
        };
        let lerp_rgb = |ca: [u8; 3], cb: [u8; 3], frac: f32| -> [u8; 3] {
            [
                lerp(ca[0], cb[0], frac),
                lerp(ca[1], cb[1], frac),
                lerp(ca[2], cb[2], frac),
            ]
        };

        if t < 1.0 / 3.0 {
            lerp_rgb(BLUE, YELLOW, t * 3.0)
        } else if t < 2.0 / 3.0 {
            lerp_rgb(YELLOW, RED, (t - 1.0 / 3.0) * 3.0)
        } else {
            lerp_rgb(RED, BRIGHT_RED, (t - 2.0 / 3.0) * 3.0)
        }
    }
}

// ─── CoverageRunV2 ────────────────────────────────────────────────────────────

/// A single coverage run backed by a [`DrcovFileV2`], with a display colour
/// and an enabled/disabled toggle (Lighthouse-style §18.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRunV2 {
    /// Human-readable name.
    pub name: String,
    /// The underlying parsed `DRcov` file.
    pub file: DrcovFileV2,
    /// RGB display colour for this run in the visualiser.
    pub color: [u8; 3],
    /// Whether this run contributes to hit-count queries.
    pub enabled: bool,
}

impl CoverageRunV2 {
    /// Create a new run with the given name, file, colour, and enabled state.
    #[must_use]
    pub fn new(name: impl Into<String>, file: DrcovFileV2, color: [u8; 3]) -> Self {
        Self {
            name: name.into(),
            file,
            color,
            enabled: true,
        }
    }

    /// Toggle the enabled state.
    pub const fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }

    /// Whether this run covers `addr` (absolute address).
    #[must_use]
    pub fn covers(&self, addr: u64) -> bool {
        self.file.absolute_bbs().iter().any(|(a, _)| *a == addr)
    }
}

// ─── CoverageDatabaseV2 ──────────────────────────────────────────────────────

/// Aggregates multiple [`CoverageRunV2`] entries and provides Lighthouse-style
/// multi-run coverage queries (§18.1).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CoverageDatabaseV2 {
    /// All registered runs (including disabled ones).
    pub runs: Vec<CoverageRunV2>,
}

impl CoverageDatabaseV2 {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a `DRcov` file, wrap it in a [`CoverageRunV2`], add it to the
    /// database, and return its index.
    ///
    /// A default grey colour is assigned; callers can change it via
    /// `runs[idx].color`.
    ///
    /// # Errors
    /// Returns [`CovError::Io`] or [`CovError::Parse`] on failure.
    pub fn add_run(&mut self, name: String, path: &Path) -> Result<u32, CovError> {
        let file = DrcovFileV2::load(path)?;
        let idx = crate::casts::usize_to_u32(self.runs.len());
        let color = default_run_color(idx);
        self.runs.push(CoverageRunV2::new(name, file, color));
        Ok(idx)
    }

    /// Remove the run at `index`.
    ///
    /// All indices above `index` shift down by one.
    pub fn remove_run(&mut self, index: u32) {
        let i = index as usize;
        if i < self.runs.len() {
            self.runs.remove(i);
        }
    }

    /// Toggle the enabled state of the run at `index`.
    pub fn toggle_run(&mut self, index: u32) {
        if let Some(run) = self.runs.get_mut(index as usize) {
            run.toggle();
        }
    }

    /// Count how many *enabled* runs cover the basic block at `addr` of `size`
    /// bytes.
    ///
    /// A run is considered to cover a block when its absolute BB list contains
    /// an entry with the exact same address.
    #[must_use]
    pub fn hit_count(&self, addr: u64, _size: u16) -> u32 {
        let n = self.runs
            .iter()
            .filter(|r| r.enabled)
            .filter(|r| r.file.absolute_bbs().iter().any(|(a, _)| *a == addr))
            .count();
        crate::casts::usize_to_u32(n)
    }

    /// Percentage of basic blocks in `[func_start, func_end)` that are covered
    /// by at least one enabled run.
    ///
    /// Returns `0.0` when there are no known blocks in the range.
    #[must_use]
    pub fn coverage_percent(&self, func_start: u64, func_end: u64) -> f32 {
        // Union of all BB addresses from enabled runs in range.
        let mut all_in_range: HashSet<u64> = HashSet::new();
        let mut covered: HashSet<u64> = HashSet::new();

        for run in self.runs.iter().filter(|r| r.enabled) {
            for (addr, _size) in run.file.bbs_in_range(func_start, func_end) {
                all_in_range.insert(addr);
                covered.insert(addr);
            }
        }
        // Also include blocks from *disabled* runs so denominator is stable.
        for run in self.runs.iter().filter(|r| !r.enabled) {
            for (addr, _size) in run.file.bbs_in_range(func_start, func_end) {
                all_in_range.insert(addr);
            }
        }
        let total = all_in_range.len();
        if total == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f32(covered.len()) / crate::casts::usize_to_f32(total) * 100.0
    }

    /// Compute the differential between run `run_a` and run `run_b`.
    ///
    /// Returns a [`CoverageDiff`] with addresses (not offsets) partitioned into
    /// three categories.
    ///
    /// Returns an empty diff if either index is out of range.
    #[must_use]
    pub fn differential(&self, run_a: u32, run_b: u32) -> CoverageDiff {
        let (a_idx, b_idx) = (run_a as usize, run_b as usize);
        if a_idx >= self.runs.len() || b_idx >= self.runs.len() {
            return CoverageDiff::default();
        }
        let a_set: HashSet<u64> = self.runs[a_idx]
            .file
            .absolute_bbs()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        let b_set: HashSet<u64> = self.runs[b_idx]
            .file
            .absolute_bbs()
            .into_iter()
            .map(|(a, _)| a)
            .collect();

        let mut diff = CoverageDiff::default();
        for &addr in &a_set {
            if b_set.contains(&addr) {
                diff.in_both.push(addr);
            } else {
                diff.only_in_a.push(addr);
            }
        }
        for &addr in &b_set {
            if !a_set.contains(&addr) {
                diff.only_in_b.push(addr);
            }
        }
        diff.only_in_a.sort_unstable();
        diff.only_in_b.sort_unstable();
        diff.in_both.sort_unstable();
        diff
    }

    /// Number of runs in the database (enabled and disabled).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.runs.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Iterate over enabled runs.
    pub fn enabled_runs(&self) -> impl Iterator<Item = &CoverageRunV2> {
        self.runs.iter().filter(|r| r.enabled)
    }

    /// Union of all BB addresses across all enabled runs.
    #[must_use]
    pub fn union_addresses(&self) -> Vec<u64> {
        let mut set: HashSet<u64> = HashSet::new();
        for run in self.runs.iter().filter(|r| r.enabled) {
            for (addr, _) in run.file.absolute_bbs() {
                set.insert(addr);
            }
        }
        let mut v: Vec<u64> = set.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Intersection of BB addresses across all enabled runs.
    #[must_use]
    pub fn intersection_addresses(&self) -> Vec<u64> {
        let enabled: Vec<_> = self.runs.iter().filter(|r| r.enabled).collect();
        if enabled.is_empty() {
            return Vec::new();
        }
        let first: HashSet<u64> = enabled[0]
            .file
            .absolute_bbs()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        let mut result = first;
        for run in &enabled[1..] {
            let set: HashSet<u64> = run
                .file
                .absolute_bbs()
                .into_iter()
                .map(|(a, _)| a)
                .collect();
            result.retain(|a| set.contains(a));
        }
        let mut v: Vec<u64> = result.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Maximum hit count for any address across all enabled runs (useful for
    /// normalising [`HeatmapColors::color_for_hits`]).
    #[must_use]
    pub fn max_hit_count(&self) -> u32 {
        let union = self.union_addresses();
        union
            .iter()
            .map(|&addr| self.hit_count(addr, 0))
            .max()
            .unwrap_or(0)
    }

    /// Build a sorted `Vec<(addr, hit_count, rgb_color)>` for every address in
    /// the union of enabled runs — ready for a heatmap renderer.
    #[must_use]
    pub fn heatmap(&self) -> Vec<(u64, u32, [u8; 3])> {
        let max = self.max_hit_count();
        self.union_addresses()
            .into_iter()
            .map(|addr| {
                let hits = self.hit_count(addr, 0);
                let color = HeatmapColors::color_for_hits(hits, max);
                (addr, hits, color)
            })
            .collect()
    }
}

/// Generate a visually distinct default colour for run index `n`.
const fn default_run_color(n: u32) -> [u8; 3] {
    // Six evenly-spaced hues around the colour wheel, cycling on overflow.
    const PALETTE: [[u8; 3]; 8] = [
        [255, 80, 80],   // red
        [80, 180, 255],  // sky blue
        [80, 255, 80],   // green
        [255, 200, 0],   // amber
        [180, 80, 255],  // violet
        [0, 220, 200],   // teal
        [255, 140, 0],   // orange
        [140, 140, 255], // periwinkle
    ];
    PALETTE[(n as usize) % PALETTE.len()]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DrcovModule ───────────────────────────────────────────────────────────

    #[test]
    fn drcov_module_size() {
        let m = DrcovModule::new(0, "/bin/ls", 0x1000, 0x5000);
        assert_eq!(m.size(), 0x4000);
    }

    #[test]
    fn drcov_module_zero_size_on_underflow() {
        let m = DrcovModule::new(0, "/x", 0x5000, 0x1000);
        assert_eq!(m.size(), 0);
    }

    #[test]
    fn drcov_module_contains() {
        let m = DrcovModule::new(0, "/x", 0x1000, 0x2000);
        assert!(m.contains(0x1000));
        assert!(m.contains(0x1fff));
        assert!(!m.contains(0x2000));
        assert!(!m.contains(0x0fff));
    }

    #[test]
    fn drcov_module_to_offset() {
        let m = DrcovModule::new(0, "/x", 0x1000, 0x2000);
        assert_eq!(m.to_offset(0x1100), Some(0x100));
        assert_eq!(m.to_offset(0x0fff), None);
    }

    #[test]
    fn drcov_module_with_checksum() {
        let m = DrcovModule::new(0, "/x", 0, 100).with_checksum(0xdead_beef);
        assert_eq!(m.checksum, 0xdead_beef);
    }

    // ── DrcovEntry ────────────────────────────────────────────────────────────

    #[test]
    fn drcov_entry_absolute_addr() {
        let modules = vec![DrcovModule::new(0, "/bin/ls", 0x1000_0000, 0x1001_0000)];
        let entry = DrcovEntry::new(0, 0x100, 4);
        assert_eq!(entry.absolute_addr(&modules), Some(0x1000_0100));
    }

    #[test]
    fn drcov_entry_no_matching_module() {
        let modules: Vec<DrcovModule> = vec![];
        let entry = DrcovEntry::new(0, 0x100, 4);
        assert_eq!(entry.absolute_addr(&modules), None);
    }

    #[test]
    fn drcov_entry_end_addr() {
        let modules = vec![DrcovModule::new(0, "/bin/ls", 0x1000, 0x9000)];
        let entry = DrcovEntry::new(0, 0x100, 16);
        assert_eq!(entry.end_addr(&modules), Some(0x1110));
    }

    // ── DrcovFile serialise / parse round-trip ────────────────────────────────

    #[test]
    fn drcov_serialize_roundtrip_modules() {
        let mut f = DrcovFile {
            version: 2,
            flavor: "drcov".to_string(),
            ..DrcovFile::default()
        };
        f.modules.push(DrcovModule::new(
            0,
            "/usr/lib/libc.so",
            0x7fff_0000,
            0x7fff_8000,
        ));
        let serialised = f.serialize();
        let text = String::from_utf8_lossy(&serialised);
        assert!(text.contains("DRCOV VERSION: 2"));
        assert!(text.contains("libc.so"));
    }

    #[test]
    fn drcov_parse_minimal() {
        let raw = b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n\
            Module Table: version 2, count 1\n\
            Columns: id, base, end, entry, checksum, timestamp, path\n\
            0, 0x1000, 0x2000, 0x0, 0x0, 0x0, /bin/ls\n\
            BB Table: 0 bbs\n";
        let file = DrcovFile::parse(raw).unwrap();
        assert_eq!(file.version, 2);
        assert_eq!(file.modules.len(), 1);
        assert_eq!(file.modules[0].path, "/bin/ls");
    }

    #[test]
    fn drcov_parse_bad_version() {
        let raw = b"NOPE VERSION: 2\n";
        assert!(DrcovFile::parse(raw).is_err());
    }

    #[test]
    fn drcov_serialize_bb_entries() {
        let mut f = DrcovFile {
            version: 2,
            flavor: "drcov".to_string(),
            ..DrcovFile::default()
        };
        f.bbs.push(DrcovEntry::new(0, 0x10, 4));
        let serialised = f.serialize();
        assert!(serialised.len() > 8);
    }

    #[test]
    fn drcov_blocks_per_module() {
        let mut f = DrcovFile::default();
        f.bbs.push(DrcovEntry::new(0, 0x10, 4));
        f.bbs.push(DrcovEntry::new(0, 0x20, 4));
        f.bbs.push(DrcovEntry::new(1, 0x30, 4));
        let bpm = f.blocks_per_module();
        assert_eq!(bpm.get(&0), Some(&2));
        assert_eq!(bpm.get(&1), Some(&1));
    }

    #[test]
    fn drcov_merge_bbs() {
        let mut f1 = DrcovFile::default();
        f1.bbs.push(DrcovEntry::new(0, 0x10, 4));
        let mut f2 = DrcovFile::default();
        f2.bbs.push(DrcovEntry::new(0, 0x20, 4));
        f2.bbs.push(DrcovEntry::new(0, 0x30, 4));
        f1.merge_bbs(&f2);
        assert_eq!(f1.bbs.len(), 3);
    }

    // ── CoverageRun ───────────────────────────────────────────────────────────

    #[test]
    fn coverage_run_hit() {
        let mut run = CoverageRun::new("test");
        run.hit(0x1000);
        run.hit(0x1000);
        run.hit(0x2000);
        assert_eq!(*run.bb_hits.get(&0x1000).unwrap(), 2);
        assert_eq!(run.distinct_blocks(), 2);
    }

    #[test]
    fn coverage_run_empty() {
        let run = CoverageRun::new("empty");
        assert_eq!(run.distinct_blocks(), 0);
    }

    #[test]
    fn coverage_run_hit_n() {
        let mut run = CoverageRun::new("r");
        run.hit_n(0xdead_beef, 10);
        assert_eq!(*run.bb_hits.get(&0xdead_beef).unwrap(), 10);
    }

    #[test]
    fn coverage_run_total_hits() {
        let mut run = CoverageRun::new("r");
        run.hit(0x100);
        run.hit(0x100);
        run.hit(0x200);
        assert_eq!(run.total_hits(), 3);
    }

    #[test]
    fn coverage_run_singleton_blocks() {
        let mut run = CoverageRun::new("r");
        run.hit(0x100); // singleton
        run.hit(0x200);
        run.hit(0x200); // not singleton
        let s = run.singleton_blocks();
        assert_eq!(s.len(), 1);
        assert!(s.contains(&0x100));
    }

    #[test]
    fn coverage_run_hot_blocks() {
        let mut run = CoverageRun::new("r");
        run.hit_n(0x100, 5);
        run.hit_n(0x200, 1);
        let hot = run.hot_blocks(3);
        assert!(hot.contains(&0x100));
        assert!(!hot.contains(&0x200));
    }

    #[test]
    fn coverage_run_was_hit() {
        let mut run = CoverageRun::new("r");
        run.hit(0x100);
        assert!(run.was_hit(0x100));
        assert!(!run.was_hit(0x200));
    }

    #[test]
    fn coverage_run_merge() {
        let mut a = CoverageRun::new("a");
        a.hit(0x100);
        let mut b = CoverageRun::new("b");
        b.hit(0x100);
        b.hit(0x200);
        a.merge(&b);
        assert_eq!(*a.bb_hits.get(&0x100).unwrap(), 2);
        assert!(a.was_hit(0x200));
    }

    #[test]
    fn coverage_run_density() {
        let mut run = CoverageRun::new("r");
        run.hit(0x100);
        assert!((run.density(0) - 0.0).abs() < 1e-9);
        assert!((run.density(4) - 0.25).abs() < 1e-9);
    }

    // ── CoverageDiff ──────────────────────────────────────────────────────────

    #[test]
    fn coverage_database_diff() {
        let mut a = CoverageRun::new("a");
        a.hit(0x1000);
        a.hit(0x2000);
        let mut b = CoverageRun::new("b");
        b.hit(0x2000);
        b.hit(0x3000);
        let diff = CoverageDatabase::diff(&a, &b);
        assert_eq!(diff.only_in_a, vec![0x1000]);
        assert_eq!(diff.only_in_b, vec![0x3000]);
        assert_eq!(diff.in_both, vec![0x2000]);
    }

    #[test]
    fn coverage_diff_jaccard_identical() {
        let mut a = CoverageRun::new("a");
        a.hit(0x100);
        let mut b = CoverageRun::new("b");
        b.hit(0x100);
        let diff = CoverageDatabase::diff(&a, &b);
        assert!((diff.jaccard() - 1.0).abs() < 1e-9);
        assert!(diff.is_identical());
    }

    #[test]
    fn coverage_diff_jaccard_disjoint() {
        let mut a = CoverageRun::new("a");
        a.hit(0x100);
        let mut b = CoverageRun::new("b");
        b.hit(0x200);
        let diff = CoverageDatabase::diff(&a, &b);
        assert!((diff.jaccard() - 0.0).abs() < 1e-9);
        assert!(!diff.is_identical());
    }

    // ── CoverageDatabase ──────────────────────────────────────────────────────

    #[test]
    fn coverage_database_stats() {
        let mut run = CoverageRun::new("r");
        run.hit(0x100);
        run.hit(0x100);
        run.hit(0x200);
        let stats = CoverageDatabase::stats(&run, 10);
        assert_eq!(stats.hit_blocks, 2);
        assert_eq!(stats.unique_blocks, 1);
        assert!(stats.coverage_pct > 0.0);
        assert_eq!(stats.max_hit_count, 2);
        assert_eq!(stats.total_hits, 3);
    }

    #[test]
    fn coverage_database_stats_empty() {
        let run = CoverageRun::new("empty");
        let stats = CoverageDatabase::stats(&run, 0);
        assert_eq!(stats.hit_blocks, 0);
        assert!(stats.coverage_pct.abs() < f64::EPSILON);
    }

    #[test]
    fn coverage_database_add_run() {
        let mut db = CoverageDatabase::new();
        db.add_run(CoverageRun::new("r1"));
        db.add_run(CoverageRun::new("r2"));
        assert_eq!(db.runs.len(), 2);
    }

    #[test]
    fn coverage_database_aggregate() {
        let mut db = CoverageDatabase::new();
        let mut r1 = CoverageRun::new("r1");
        r1.hit(0x100);
        let mut r2 = CoverageRun::new("r2");
        r2.hit(0x200);
        db.add_run(r1);
        db.add_run(r2);
        let agg = db.aggregate();
        assert!(agg.was_hit(0x100));
        assert!(agg.was_hit(0x200));
    }

    #[test]
    fn coverage_database_intersection() {
        let mut db = CoverageDatabase::new();
        let mut r1 = CoverageRun::new("r1");
        r1.hit(0x100);
        r1.hit(0x200);
        let mut r2 = CoverageRun::new("r2");
        r2.hit(0x200);
        r2.hit(0x300);
        db.add_run(r1);
        db.add_run(r2);
        let inter = db.intersection();
        assert_eq!(inter, vec![0x200]);
    }

    #[test]
    fn coverage_database_union_coverage() {
        let mut db = CoverageDatabase::new();
        let mut r1 = CoverageRun::new("r1");
        r1.hit(0x100);
        let mut r2 = CoverageRun::new("r2");
        r2.hit(0x200);
        db.add_run(r1);
        db.add_run(r2);
        let u = db.union_coverage();
        assert!(u.contains(&0x100));
        assert!(u.contains(&0x200));
    }

    // ── LcovParser ────────────────────────────────────────────────────────────

    fn sample_lcov() -> &'static str {
        "TN:my_test\n\
         SF:/src/main.rs\n\
         FN:10,main\n\
         FNDA:3,main\n\
         DA:10,3\n\
         DA:11,0\n\
         DA:12,1\n\
         BRH:2\n\
         BRF:4\n\
         LF:3\n\
         LH:2\n\
         end_of_record\n"
    }

    #[test]
    fn lcov_parse_source_file() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0].source_file.as_deref(), Some("/src/main.rs"));
    }

    #[test]
    fn lcov_parse_test_name() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        assert_eq!(p.records[0].test_name.as_deref(), Some("my_test"));
    }

    #[test]
    fn lcov_parse_function_hit() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        let count = p.records[0].functions.get("main").copied().unwrap_or(0);
        assert_eq!(count, 3);
    }

    #[test]
    fn lcov_parse_line_hits() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        assert_eq!(*p.records[0].line_hits.get(&10).unwrap(), 3);
        assert_eq!(*p.records[0].line_hits.get(&12).unwrap(), 1);
    }

    #[test]
    fn lcov_parse_branch_hits() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        assert_eq!(p.records[0].branch_hits, 2);
        assert_eq!(p.records[0].branch_found, 4);
    }

    #[test]
    fn lcov_total_lines_hit() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        assert_eq!(p.total_lines_hit(), 2);
    }

    #[test]
    fn lcov_multiple_records() {
        let data = format!(
            "{}{}",
            sample_lcov(),
            "SF:/src/lib.rs\nDA:1,1\nend_of_record\n"
        );
        let mut p = LcovParser::new();
        p.parse(&data).unwrap();
        assert_eq!(p.records.len(), 2);
    }

    #[test]
    fn lcov_record_line_coverage_pct() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        let pct = p.records[0].line_coverage_pct();
        // LF:3, LH:2 → 66.6%
        assert!((pct - 200.0 / 3.0).abs() < 1e-6, "pct={pct}");
    }

    #[test]
    fn lcov_record_functions_hit() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        assert_eq!(p.records[0].functions_hit(), 1);
    }

    #[test]
    fn lcov_aggregate_by_file() {
        let data = format!(
            "{}{}",
            sample_lcov(),
            "SF:/src/main.rs\nDA:10,2\nend_of_record\n"
        );
        let mut p = LcovParser::new();
        p.parse(&data).unwrap();
        let agg = p.aggregate_by_file();
        let main_map = agg.get("/src/main.rs").unwrap();
        // Line 10: 3 + 2 = 5
        assert_eq!(*main_map.get(&10).unwrap(), 5);
    }

    #[test]
    fn lcov_source_files() {
        let mut p = LcovParser::new();
        p.parse(sample_lcov()).unwrap();
        let files = p.source_files();
        assert!(files.contains(&"/src/main.rs"));
    }

    // ── PcGuardBitmap ─────────────────────────────────────────────────────────

    #[test]
    fn pcguard_new_all_zero() {
        let b = PcGuardBitmap::new(64);
        assert_eq!(b.coverage_count(), 0);
        assert!((b.density() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn pcguard_record_hit() {
        let mut b = PcGuardBitmap::new(64);
        b.record_hit(5);
        assert_eq!(b.bits[5], 1);
        assert_eq!(b.coverage_count(), 1);
    }

    #[test]
    fn pcguard_reset() {
        let mut b = PcGuardBitmap::new(64);
        b.record_hit(0);
        b.reset();
        assert_eq!(b.coverage_count(), 0);
    }

    #[test]
    fn pcguard_merge() {
        let mut a = PcGuardBitmap::new(8);
        a.record_hit(0);
        let mut b = PcGuardBitmap::new(8);
        b.record_hit(1);
        a.merge(&b);
        assert!(a.bits[0] > 0);
        assert!(a.bits[1] > 0);
    }

    #[test]
    fn pcguard_new_bits_from() {
        let base = PcGuardBitmap::new(8);
        let mut other = PcGuardBitmap::new(8);
        other.record_hit(3);
        let n = base.new_bits_from(&other);
        assert_eq!(n, 1);
    }

    #[test]
    fn pcguard_hash_deterministic() {
        let mut b = PcGuardBitmap::new(8);
        b.record_hit(2);
        let h1 = b.hash();
        let h2 = b.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn pcguard_hit_guards() {
        let mut b = PcGuardBitmap::new(8);
        b.record_hit(1);
        b.record_hit(3);
        let guards = b.hit_guards();
        assert_eq!(guards, vec![1, 3]);
    }

    // ── EdgeCoverageMap ───────────────────────────────────────────────────────

    #[test]
    fn edge_map_record() {
        let mut m = EdgeCoverageMap::new();
        m.record(0x100, 0x200);
        assert!(m.has_edge(0x100, 0x200));
        assert_eq!(m.edge_hits(0x100, 0x200), 1);
    }

    #[test]
    fn edge_map_record_n() {
        let mut m = EdgeCoverageMap::new();
        m.record_n(0x100, 0x200, 5);
        assert_eq!(m.edge_hits(0x100, 0x200), 5);
    }

    #[test]
    fn edge_map_merge() {
        let mut a = EdgeCoverageMap::new();
        a.record(0x100, 0x200);
        let mut b = EdgeCoverageMap::new();
        b.record(0x200, 0x300);
        a.merge(&b);
        assert!(a.has_edge(0x100, 0x200));
        assert!(a.has_edge(0x200, 0x300));
    }

    #[test]
    fn edge_map_hot_edges() {
        let mut m = EdgeCoverageMap::new();
        m.record_n(0x100, 0x200, 10);
        m.record_n(0x300, 0x400, 2);
        let hot = m.hot_edges(5);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0], (0x100, 0x200, 10));
    }

    #[test]
    fn edge_map_successors() {
        let mut m = EdgeCoverageMap::new();
        m.record(0x100, 0x200);
        m.record(0x100, 0x300);
        let succ = m.successors(0x100);
        assert_eq!(succ.len(), 2);
        assert!(succ.contains(&0x200));
        assert!(succ.contains(&0x300));
    }

    // ── CmplogEntry / CmplogMap ───────────────────────────────────────────────

    #[test]
    fn cmplog_entry_equal() {
        let e = CmplogEntry::new(0x1000, 42, 42, 8, false);
        assert!(e.is_equal());
        assert_eq!(e.diff(), 0);
    }

    #[test]
    fn cmplog_entry_unequal() {
        let e = CmplogEntry::new(0x1000, 0xFF, 0x00, 1, false);
        assert!(!e.is_equal());
        assert_eq!(e.diff(), 0xFF);
        assert_eq!(e.bit_diff(), 8);
    }

    #[test]
    fn cmplog_entry_mask() {
        let e1 = CmplogEntry::new(0, 0, 0, 1, false);
        assert_eq!(e1.mask(), 0xff);
        let e4 = CmplogEntry::new(0, 0, 0, 4, false);
        assert_eq!(e4.mask(), 0xffff_ffff);
    }

    #[test]
    fn cmplog_map_suggest_mutations() {
        let mut m = CmplogMap::new();
        m.record(CmplogEntry::new(0x100, 0x41, 0x42, 1, false));
        let muts = m.suggest_mutations();
        assert!(!muts.is_empty());
        assert_eq!(muts[0], vec![0x42]);
    }

    #[test]
    fn cmplog_map_unique_pcs() {
        let mut m = CmplogMap::new();
        m.record(CmplogEntry::new(0x100, 1, 2, 1, false));
        m.record(CmplogEntry::new(0x100, 3, 4, 1, false));
        m.record(CmplogEntry::new(0x200, 5, 6, 1, false));
        let pcs = m.unique_pcs();
        assert_eq!(pcs, vec![0x100, 0x200]);
    }

    #[test]
    fn cmplog_map_is_empty() {
        let m = CmplogMap::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    // ── CorpusPruner ──────────────────────────────────────────────────────────

    #[test]
    fn corpus_pruner_minimal_set() {
        let pruner = CorpusPruner::new();
        let inputs = vec![
            (0usize, vec![1u64, 2, 3]),
            (1usize, vec![2u64, 3]),
            (2usize, vec![4u64]),
        ];
        let selected = pruner.prune(inputs);
        // Input 0 covers {1,2,3} and input 2 covers {4}
        assert!(selected.contains(&0) || selected.contains(&1));
        assert!(selected.contains(&2));
        // Should not select more than needed
        assert!(selected.len() <= 3);
    }

    #[test]
    fn corpus_pruner_empty_input() {
        let pruner = CorpusPruner::new();
        let selected = pruner.prune(vec![]);
        assert!(selected.is_empty());
    }

    #[test]
    fn corpus_pruner_single_input() {
        let pruner = CorpusPruner::new();
        let selected = pruner.prune(vec![(0usize, vec![1u64])]);
        assert_eq!(selected, vec![0]);
    }

    // ── CoverageHistogram ─────────────────────────────────────────────────────

    #[test]
    fn histogram_from_run() {
        let mut run = CoverageRun::new("r");
        run.hit_n(0x100, 1);
        run.hit_n(0x200, 2);
        run.hit_n(0x300, 2);
        let h = CoverageHistogram::from_run(&run);
        assert_eq!(h.buckets.get(&1), Some(&1));
        assert_eq!(h.buckets.get(&2), Some(&2));
        assert_eq!(h.total_blocks(), 3);
    }

    #[test]
    fn histogram_max_bucket() {
        let mut run = CoverageRun::new("r");
        run.hit_n(0x100, 100);
        let h = CoverageHistogram::from_run(&run);
        assert_eq!(h.max_bucket(), 100);
    }

    #[test]
    fn histogram_mean() {
        let mut run = CoverageRun::new("r");
        run.hit_n(0x100, 2);
        run.hit_n(0x200, 4);
        let h = CoverageHistogram::from_run(&run);
        let mean = h.mean();
        assert!((mean - 3.0).abs() < 1e-9, "expected 3.0, got {mean}");
    }

    #[test]
    fn histogram_empty() {
        let run = CoverageRun::new("r");
        let h = CoverageHistogram::from_run(&run);
        assert_eq!(h.total_blocks(), 0);
        assert_eq!(h.max_bucket(), 0);
        assert!((h.mean() - 0.0).abs() < 1e-9);
    }

    // ── CovError ──────────────────────────────────────────────────────────────

    #[test]
    fn cov_error_parse_display() {
        let e = CovError::Parse("bad header".to_string());
        assert!(e.to_string().contains("bad header"));
    }

    #[test]
    fn cov_error_io_display() {
        let e = CovError::Io("file not found".to_string());
        assert!(e.to_string().contains("file not found"));
    }

    #[test]
    fn cov_error_unsupported_version() {
        let e = CovError::UnsupportedVersion(99);
        assert!(e.to_string().contains("99"));
    }

    // ── DrcovHeader ───────────────────────────────────────────────────────────

    fn sample_drcov_bytes() -> Vec<u8> {
        let text = "DRCOV VERSION: 2\n\
                    DRCOV FLAVOR: drcov\n\
                    Module Table: version 2, count 1\n\
                    Columns: id, base, end, entry, checksum, timestamp, path\n\
                    0, 0x1000, 0x5000, 0x1100, 0x0, 0x0, /bin/test\n\
                    BB Table: 2 bbs\n";
        let mut v = text.as_bytes().to_vec();
        // BB entry 1: start=0x100, size=8, module_id=0
        v.extend_from_slice(&0x0000_0100u32.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        // BB entry 2: start=0x200, size=4, module_id=0
        v.extend_from_slice(&0x0000_0200u32.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v
    }

    #[test]
    fn drcov_header_parse_version() {
        let data = sample_drcov_bytes();
        let (hdr, _) = DrcovHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, 2);
    }

    #[test]
    fn drcov_header_parse_flavor() {
        let data = sample_drcov_bytes();
        let (hdr, _) = DrcovHeader::parse(&data).unwrap();
        assert_eq!(hdr.flavor, "drcov");
    }

    #[test]
    fn drcov_header_parse_module_count() {
        let data = sample_drcov_bytes();
        let (hdr, _) = DrcovHeader::parse(&data).unwrap();
        assert_eq!(hdr.module_count, 1);
    }

    #[test]
    fn drcov_header_consumed_offset_positive() {
        let data = sample_drcov_bytes();
        let (_, consumed) = DrcovHeader::parse(&data).unwrap();
        assert!(consumed > 0);
    }

    #[test]
    fn drcov_header_missing_version_prefix() {
        let bad = b"NOPE VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: count 0\n";
        assert!(DrcovHeader::parse(bad).is_err());
    }

    #[test]
    fn drcov_header_missing_flavor_prefix() {
        let bad = b"DRCOV VERSION: 2\nNOFLAVOR: x\nModule Table: count 0\n";
        assert!(DrcovHeader::parse(bad).is_err());
    }

    // ── DrcovModuleV2 ─────────────────────────────────────────────────────────

    #[test]
    fn drcov_module_v2_parse_table() {
        let text = "Columns: id, base, end, entry, checksum, timestamp, path\n\
                    0, 0x1000, 0x5000, 0x1100, 0x0, 0x0, /bin/test\n";
        let modules = DrcovModuleV2::parse_table(text.as_bytes(), 1).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].id, 0);
        assert_eq!(modules[0].base, 0x1000);
        assert_eq!(modules[0].end, 0x5000);
        assert_eq!(modules[0].entry, 0x1100);
        assert_eq!(modules[0].path, "/bin/test");
    }

    #[test]
    fn drcov_module_v2_contains() {
        let m = DrcovModuleV2 {
            id: 0,
            base: 0x1000,
            end: 0x5000,
            entry: 0,
            path: String::new(),
        };
        assert!(m.contains(0x1000));
        assert!(m.contains(0x4fff));
        assert!(!m.contains(0x5000));
    }

    #[test]
    fn drcov_module_v2_size() {
        let m = DrcovModuleV2 {
            id: 0,
            base: 0x1000,
            end: 0x5000,
            entry: 0,
            path: String::new(),
        };
        assert_eq!(m.size(), 0x4000);
    }

    // ── DrcovBasicBlock ───────────────────────────────────────────────────────

    #[test]
    fn drcov_basic_block_parse_bb_table() {
        let data = sample_drcov_bytes();
        let bbs = DrcovBasicBlock::parse_bb_table(&data).unwrap();
        assert_eq!(bbs.len(), 2);
        assert_eq!(bbs[0].start, 0x100);
        assert_eq!(bbs[0].size, 8);
        assert_eq!(bbs[0].module_id, 0);
        assert_eq!(bbs[1].start, 0x200);
        assert_eq!(bbs[1].size, 4);
    }

    #[test]
    fn drcov_basic_block_absolute_addr() {
        let bb = DrcovBasicBlock {
            start: 0x100,
            size: 4,
            module_id: 0,
        };
        assert_eq!(bb.absolute_addr(0x1000), 0x1100);
    }

    #[test]
    fn drcov_basic_block_missing_header() {
        let bad = b"no bb table here";
        assert!(DrcovBasicBlock::parse_bb_table(bad).is_err());
    }

    // ── DrcovFileV2 ───────────────────────────────────────────────────────────

    #[test]
    fn drcov_file_v2_parse() {
        let data = sample_drcov_bytes();
        let f = DrcovFileV2::parse(&data).unwrap();
        assert_eq!(f.header.version, 2);
        assert_eq!(f.modules.len(), 1);
        assert_eq!(f.bbs.len(), 2);
    }

    #[test]
    fn drcov_file_v2_absolute_bbs() {
        let data = sample_drcov_bytes();
        let f = DrcovFileV2::parse(&data).unwrap();
        let abs = f.absolute_bbs();
        assert_eq!(abs.len(), 2);
        // module base = 0x1000, starts = 0x100, 0x200
        assert!(abs.iter().any(|(a, _)| *a == 0x1100));
        assert!(abs.iter().any(|(a, _)| *a == 0x1200));
    }

    #[test]
    fn drcov_file_v2_bbs_in_range() {
        let data = sample_drcov_bytes();
        let f = DrcovFileV2::parse(&data).unwrap();
        let in_range = f.bbs_in_range(0x1100, 0x1200);
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].0, 0x1100);
    }

    #[test]
    fn drcov_file_v2_module_count() {
        let data = sample_drcov_bytes();
        let f = DrcovFileV2::parse(&data).unwrap();
        assert_eq!(f.module_count(), 1);
    }

    // ── LcovInfoParser ────────────────────────────────────────────────────────

    fn sample_lcov_info() -> &'static str {
        "TN:suite\n\
         SF:/src/foo.rs\n\
         FN:10,foo\n\
         FNDA:3,foo\n\
         DA:10,3\n\
         DA:11,0\n\
         DA:12,2\n\
         LF:3\n\
         LH:2\n\
         end_of_record\n\
         SF:/src/bar.rs\n\
         FN:1,bar\n\
         FNDA:0,bar\n\
         DA:1,0\n\
         LF:1\n\
         LH:0\n\
         end_of_record\n"
    }

    #[test]
    fn lcov_info_parser_files() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        assert!(data.files.contains_key("/src/foo.rs"));
        assert!(data.files.contains_key("/src/bar.rs"));
    }

    #[test]
    fn lcov_info_parser_line_hits() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        let foo = &data.files["/src/foo.rs"];
        assert_eq!(foo.lines.get(&10), Some(&3));
        assert_eq!(foo.lines.get(&11), Some(&0));
        assert_eq!(foo.lines.get(&12), Some(&2));
    }

    #[test]
    fn lcov_info_parser_function_hits() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        let foo = &data.files["/src/foo.rs"];
        assert_eq!(foo.functions.get("foo"), Some(&3));
    }

    #[test]
    fn lcov_info_parser_zero_function_hits() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        let bar = &data.files["/src/bar.rs"];
        assert_eq!(bar.functions.get("bar"), Some(&0));
    }

    #[test]
    fn lcov_info_file_coverage_lines_hit() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        assert_eq!(data.files["/src/foo.rs"].lines_hit(), 2);
        assert_eq!(data.files["/src/bar.rs"].lines_hit(), 0);
    }

    #[test]
    fn lcov_info_file_coverage_pct() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        let pct = data.files["/src/foo.rs"].line_coverage_pct();
        // 2 of 3 lines hit → 66.66%
        assert!((pct - 200.0 / 3.0).abs() < 0.1, "pct={pct}");
    }

    #[test]
    fn lcov_info_overall_coverage_pct() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        // foo: 2/3, bar: 0/1 → 2/4 = 50%
        let pct = data.overall_line_coverage_pct();
        assert!((pct - 50.0).abs() < 0.1, "pct={pct}");
    }

    #[test]
    fn lcov_info_total_lines_hit() {
        let data = LcovInfoParser::parse(sample_lcov_info()).unwrap();
        assert_eq!(data.total_lines_hit(), 2);
    }

    #[test]
    fn lcov_info_merge_multiple_records_same_file() {
        let content = "SF:/src/foo.rs\nDA:1,1\nend_of_record\n\
                       SF:/src/foo.rs\nDA:1,2\nDA:2,1\nend_of_record\n";
        let data = LcovInfoParser::parse(content).unwrap();
        let foo = &data.files["/src/foo.rs"];
        assert_eq!(foo.lines.get(&1), Some(&3));
        assert_eq!(foo.lines.get(&2), Some(&1));
    }

    #[test]
    fn lcov_info_empty_input() {
        let data = LcovInfoParser::parse("").unwrap();
        assert!(data.files.is_empty());
    }

    // ── HeatmapColors ─────────────────────────────────────────────────────────

    #[test]
    fn heatmap_zero_hits_is_gray() {
        assert_eq!(HeatmapColors::color_for_hits(0, 100), [128, 128, 128]);
    }

    #[test]
    fn heatmap_max_hits_is_bright_red() {
        assert_eq!(HeatmapColors::color_for_hits(100, 100), [255, 64, 64]);
    }

    #[test]
    fn heatmap_max_hits_zero_max() {
        // When max_hits is 0, even 0 hits returns gray (hits==0 branch).
        assert_eq!(HeatmapColors::color_for_hits(0, 0), [128, 128, 128]);
    }

    #[test]
    fn heatmap_low_hits_is_bluish() {
        // Very low fraction → closer to blue than yellow.
        let c = HeatmapColors::color_for_hits(1, 100);
        // Blue channel should dominate at low hits.
        assert!(c[2] > c[0], "expected blue > red at low hits, got {c:?}");
    }

    #[test]
    fn heatmap_mid_hits_is_yellowish() {
        // ~50% → should be near yellow (high red + high green, low blue).
        let c = HeatmapColors::color_for_hits(50, 100);
        assert!(
            c[0] > 100,
            "expected red component high at mid hits, got {c:?}"
        );
        assert!(
            c[2] < 200,
            "expected blue component reduced at mid hits, got {c:?}"
        );
    }

    #[test]
    fn heatmap_high_hits_is_reddish() {
        // Near max → should be close to [255, 64, 64].
        let c = HeatmapColors::color_for_hits(95, 100);
        assert!(c[0] > 200, "expected high red at high hits, got {c:?}");
    }

    #[test]
    fn heatmap_monotone_red_channel() {
        // Red channel should not decrease as hits increase from 1 to max.
        let max = 10u32;
        let mut prev_r = 0u8;
        for h in 1..=max {
            let c = HeatmapColors::color_for_hits(h, max);
            // Allow equal (plateau at 255) but not a decrease greater than 1
            // (rounding artefacts).
            assert!(
                c[0] >= prev_r.saturating_sub(1),
                "red decreased at hits={h}: {prev_r} → {}",
                c[0]
            );
            prev_r = c[0];
        }
    }

    // ── CoverageDatabaseV2 ────────────────────────────────────────────────────

    /// Build a minimal `DrcovFileV2` in memory without touching the filesystem.
    fn make_drcov_file_v2(base: u64, offsets: &[u32]) -> DrcovFileV2 {
        let header = DrcovHeader {
            version: 2,
            flavor: "drcov".to_string(),
            module_count: 1,
        };
        let modules = vec![DrcovModuleV2 {
            id: 0,
            base,
            end: base + 0x10000,
            entry: base,
            path: "/test/binary".to_string(),
        }];
        let bbs = offsets
            .iter()
            .map(|&start| DrcovBasicBlock {
                start,
                size: 4,
                module_id: 0,
            })
            .collect();
        DrcovFileV2 {
            header,
            modules,
            bbs,
        }
    }

    #[test]
    fn db_v2_add_run_in_memory() {
        let mut db = CoverageDatabaseV2::new();
        let f = make_drcov_file_v2(0x1000, &[0x100, 0x200, 0x300]);
        db.runs.push(CoverageRunV2::new("run0", f, [255, 0, 0]));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn db_v2_hit_count_single_run() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100, 0x200]),
            [0, 0, 255],
        ));
        // addr 0x1100 = base 0x1000 + offset 0x100 → should be hit
        assert_eq!(db.hit_count(0x1100, 4), 1);
        assert_eq!(db.hit_count(0x1200, 4), 1);
        assert_eq!(db.hit_count(0x9999, 4), 0);
    }

    #[test]
    fn db_v2_hit_count_two_runs() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        db.runs.push(CoverageRunV2::new(
            "r1",
            make_drcov_file_v2(0x1000, &[0x100, 0x200]),
            [0, 255, 0],
        ));
        assert_eq!(db.hit_count(0x1100, 4), 2);
        assert_eq!(db.hit_count(0x1200, 4), 1);
    }

    #[test]
    fn db_v2_disabled_run_not_counted() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        db.toggle_run(0); // disable r0
        assert_eq!(db.hit_count(0x1100, 4), 0);
    }

    #[test]
    fn db_v2_toggle_run_re_enables() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        db.toggle_run(0);
        assert_eq!(db.hit_count(0x1100, 4), 0);
        db.toggle_run(0); // re-enable
        assert_eq!(db.hit_count(0x1100, 4), 1);
    }

    #[test]
    fn db_v2_remove_run() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        db.runs.push(CoverageRunV2::new(
            "r1",
            make_drcov_file_v2(0x2000, &[0x100]),
            [0, 255, 0],
        ));
        db.remove_run(0);
        assert_eq!(db.len(), 1);
        assert_eq!(db.runs[0].name, "r1");
    }

    #[test]
    fn db_v2_coverage_percent_full() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100, 0x200, 0x300]),
            [255, 0, 0],
        ));
        // All three BBs lie in [0x1100, 0x1400).
        let pct = db.coverage_percent(0x1100, 0x1400);
        assert!((pct - 100.0).abs() < 0.1, "pct={pct}");
    }

    #[test]
    fn db_v2_coverage_percent_partial() {
        let mut db = CoverageDatabaseV2::new();
        // r0 covers offset 0x100 only; r1 (disabled) covers 0x200.
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        let mut r1 = CoverageRunV2::new("r1", make_drcov_file_v2(0x1000, &[0x200]), [0, 255, 0]);
        r1.enabled = false;
        db.runs.push(r1);
        // 1 of 2 total BBs covered.
        let pct = db.coverage_percent(0x1100, 0x1300);
        assert!((pct - 50.0).abs() < 0.1, "pct={pct}");
    }

    #[test]
    fn db_v2_coverage_percent_empty_range() {
        let db = CoverageDatabaseV2::new();
        assert!((db.coverage_percent(0x0, 0x1000) - 0.0).abs() < 0.001);
    }

    #[test]
    fn db_v2_differential() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100, 0x200]),
            [255, 0, 0],
        ));
        db.runs.push(CoverageRunV2::new(
            "r1",
            make_drcov_file_v2(0x1000, &[0x200, 0x300]),
            [0, 255, 0],
        ));
        let diff = db.differential(0, 1);
        assert_eq!(diff.only_in_a, vec![0x1100u64]);
        assert_eq!(diff.only_in_b, vec![0x1300u64]);
        assert_eq!(diff.in_both, vec![0x1200u64]);
    }

    #[test]
    fn db_v2_union_addresses() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        db.runs.push(CoverageRunV2::new(
            "r1",
            make_drcov_file_v2(0x1000, &[0x200]),
            [0, 255, 0],
        ));
        let union = db.union_addresses();
        assert!(union.contains(&0x1100));
        assert!(union.contains(&0x1200));
    }

    #[test]
    fn db_v2_intersection_addresses() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100, 0x200]),
            [255, 0, 0],
        ));
        db.runs.push(CoverageRunV2::new(
            "r1",
            make_drcov_file_v2(0x1000, &[0x200, 0x300]),
            [0, 255, 0],
        ));
        let inter = db.intersection_addresses();
        assert_eq!(inter, vec![0x1200u64]);
    }

    #[test]
    fn db_v2_heatmap_length_matches_union() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100, 0x200]),
            [255, 0, 0],
        ));
        let hm = db.heatmap();
        assert_eq!(hm.len(), db.union_addresses().len());
    }

    #[test]
    fn db_v2_heatmap_color_non_zero_hits() {
        let mut db = CoverageDatabaseV2::new();
        db.runs.push(CoverageRunV2::new(
            "r0",
            make_drcov_file_v2(0x1000, &[0x100]),
            [255, 0, 0],
        ));
        let hm = db.heatmap();
        // Single run, single BB → hits=1, max_hits=1 → bright red
        assert_eq!(hm[0].2, [255, 64, 64]);
    }

    // ── FileCoverage & CoverageData ───────────────────────────────────────────

    #[test]
    fn file_coverage_functions_hit() {
        let mut fc = FileCoverage::default();
        fc.functions.insert("foo".into(), 3);
        fc.functions.insert("bar".into(), 0);
        assert_eq!(fc.functions_hit(), 1);
    }

    #[test]
    fn file_coverage_empty() {
        let fc = FileCoverage::default();
        assert_eq!(fc.lines_hit(), 0);
        assert!((fc.line_coverage_pct() - 0.0).abs() < 0.001);
    }

    #[test]
    fn coverage_data_total_lines() {
        let mut data = CoverageData::new();
        let mut fc = FileCoverage::default();
        fc.lines.insert(1, 1);
        fc.lines.insert(2, 0);
        data.files.insert("/f.rs".into(), fc);
        assert_eq!(data.total_lines(), 2);
        assert_eq!(data.total_lines_hit(), 1);
    }
}
