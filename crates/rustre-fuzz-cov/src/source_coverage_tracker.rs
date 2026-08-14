//! Source-level coverage tracking: LLVM `SanitizerCoverage` integration;
//! PC guard tables; function coverage; line coverage.

use std::fmt::Write as _;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{CovError, PcGuardBitmap};

// ─── PcGuardTable ─────────────────────────────────────────────────────────────

/// A `SanitizerCoverage` PC-guard table: maps guard index → PC address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcGuardTable {
    /// Guard index → absolute PC address.
    pub guards: Vec<u64>,
    /// Binary/module name this table belongs to.
    pub module: String,
    /// Base address of the module (used to convert relative PCs).
    pub module_base: u64,
}

impl PcGuardTable {
    /// Create a new, empty PC-guard table.
    #[must_use]
    pub fn new(module: impl Into<String>, module_base: u64) -> Self {
        Self {
            guards: Vec::new(),
            module: module.into(),
            module_base,
        }
    }

    /// Register a PC guard at `absolute_pc`.
    pub fn register_guard(&mut self, absolute_pc: u64) {
        self.guards.push(absolute_pc);
    }

    /// Number of registered guards.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.guards.len()
    }

    /// Whether no guards are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    /// Return the PC for guard index `idx`.
    #[must_use]
    pub fn pc_for_guard(&self, idx: usize) -> Option<u64> {
        self.guards.get(idx).copied()
    }

    /// Return the guard index for a given PC, or `None` if not found.
    #[must_use]
    pub fn guard_for_pc(&self, pc: u64) -> Option<usize> {
        self.guards.iter().position(|&g| g == pc)
    }

    /// Convert to a bitmap of length `self.len()` (all zeros initially).
    #[must_use]
    pub fn empty_bitmap(&self) -> PcGuardBitmap {
        PcGuardBitmap::new(self.guards.len())
    }

    /// Load PC guard table from a binary blob.
    ///
    /// Format: `[n: u32 LE][pc_0: u64 LE] … [pc_{n-1}: u64 LE]`
    ///
    /// # Errors
    /// Returns `CovError::Parse` on malformed data.
    pub fn from_binary(data: &[u8], module: impl Into<String>, module_base: u64) -> Result<Self, CovError> {
        if data.len() < 4 {
            return Err(CovError::Parse("PC guard table too short".into()));
        }
        let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let required = 4 + n * 8;
        if data.len() < required {
            return Err(CovError::Parse(format!(
                "PC guard table truncated: need {required} bytes, got {}", data.len()
            )));
        }
        let mut guards = Vec::with_capacity(n);
        for i in 0..n {
            let off = 4 + i * 8;
            let pc = u64::from_le_bytes([
                data[off], data[off+1], data[off+2], data[off+3],
                data[off+4], data[off+5], data[off+6], data[off+7],
            ]);
            guards.push(pc);
        }
        Ok(Self { guards, module: module.into(), module_base })
    }

    /// Serialize to binary blob.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        let n = crate::casts::usize_to_u32(self.guards.len());
        let mut out = Vec::with_capacity(4 + self.guards.len() * 8);
        out.extend_from_slice(&n.to_le_bytes());
        for &pc in &self.guards {
            out.extend_from_slice(&pc.to_le_bytes());
        }
        out
    }
}

// ─── FunctionCoverageEntry ─────────────────────────────────────────────────────

/// Coverage data for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCoverageEntry {
    /// Function name (demangled if possible).
    pub name: String,
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Source file, if known.
    pub source_file: Option<String>,
    /// Starting line number, if known.
    pub start_line: Option<u32>,
    /// Number of times this function was called/entered.
    pub hit_count: u64,
    /// Basic blocks within this function that were hit.
    pub covered_blocks: HashSet<u64>,
    /// Total basic blocks in this function (0 = unknown).
    pub total_blocks: usize,
}

impl FunctionCoverageEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, start: u64, end: u64) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            source_file: None,
            start_line: None,
            hit_count: 0,
            covered_blocks: HashSet::new(),
            total_blocks: 0,
        }
    }

    /// Whether this function was called at least once.
    #[must_use]
    pub const fn is_covered(&self) -> bool {
        self.hit_count > 0
    }

    /// Block coverage percentage (0.0–100.0).
    #[must_use]
    pub fn block_coverage_pct(&self) -> f64 {
        if self.total_blocks == 0 { return 0.0; }
        crate::casts::usize_to_f64(self.covered_blocks.len()) / crate::casts::usize_to_f64(self.total_blocks) * 100.0
    }

    /// Record a hit at `block_addr`.
    pub fn record_hit(&mut self, block_addr: u64) {
        self.hit_count += 1;
        self.covered_blocks.insert(block_addr);
    }
}

// ─── LineCoverageMap ──────────────────────────────────────────────────────────

/// Line-level coverage data for one source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineCoverageMap {
    /// Source file path.
    pub path: PathBuf,
    /// Line number → hit count.
    pub hits: BTreeMap<u32, u64>,
    /// Total executable lines discovered (0 = unknown).
    pub total_executable: u32,
}

impl LineCoverageMap {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            hits: BTreeMap::new(),
            total_executable: 0,
        }
    }

    /// Record a hit at `line`.
    pub fn record(&mut self, line: u32) {
        *self.hits.entry(line).or_insert(0) += 1;
    }

    /// Record `count` hits at `line`.
    pub fn record_n(&mut self, line: u32, count: u64) {
        *self.hits.entry(line).or_insert(0) += count;
    }

    /// Lines hit at least once.
    #[must_use]
    pub fn covered_lines(&self) -> Vec<u32> {
        self.hits.iter().filter(|&(_, &c)| c > 0).map(|(&l, _)| l).collect()
    }

    /// Coverage percentage (0.0–100.0).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.total_executable == 0 { return 0.0; }
        let covered = crate::casts::usize_to_f64(self.hits.values().filter(|&&c| c > 0).count());
        covered / f64::from(self.total_executable) * 100.0
    }

    /// Merge another map into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&line, &count) in &other.hits {
            *self.hits.entry(line).or_insert(0) += count;
        }
    }
}

// ─── SancovInstrumentation ────────────────────────────────────────────────────

/// Runtime state for LLVM `SanitizerCoverage` PC-guard instrumentation.
///
/// In a real deployment, the callbacks (`__sanitizer_cov_trace_pc_guard_init`,
/// `__sanitizer_cov_trace_pc_guard`) would call into this struct.  Here we
/// provide the data model and analysis logic.
#[derive(Debug, Default)]
pub struct SancovInstrumentation {
    /// All registered PC-guard tables keyed by module name.
    pub tables: HashMap<String, PcGuardTable>,
    /// Current hit bitmap keyed by module name.
    pub bitmaps: HashMap<String, PcGuardBitmap>,
    /// Total number of guard callbacks recorded.
    pub total_callbacks: u64,
}

impl SancovInstrumentation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new PC-guard table for `module`.
    pub fn register_table(&mut self, table: PcGuardTable) {
        let bitmap = table.empty_bitmap();
        self.bitmaps.insert(table.module.clone(), bitmap);
        self.tables.insert(table.module.clone(), table);
    }

    /// Simulate a guard callback: mark guard `idx` in `module` as hit.
    ///
    /// This is what `__sanitizer_cov_trace_pc_guard` would call.
    pub fn trace_pc_guard(&mut self, module: &str, guard_idx: usize) {
        self.total_callbacks += 1;
        if let Some(bitmap) = self.bitmaps.get_mut(module)
            && guard_idx < bitmap.bits.len() {
                bitmap.record_hit(guard_idx);
            }
    }

    /// Number of unique guards hit across all modules.
    #[must_use]
    pub fn unique_guards_hit(&self) -> usize {
        self.bitmaps.values().map(super::PcGuardBitmap::coverage_count).sum()
    }

    /// Coverage density across all modules (0.0–1.0).
    #[must_use]
    pub fn global_density(&self) -> f64 {
        let total: usize = self.bitmaps.values().map(|b| b.bits.len()).sum();
        let hit: usize = self.bitmaps.values().map(super::PcGuardBitmap::coverage_count).sum();
        if total == 0 { 0.0 } else { crate::casts::usize_to_f64(hit) / crate::casts::usize_to_f64(total) }
    }

    /// Return all PCs that were hit (across all modules).
    #[must_use]
    pub fn hit_pcs(&self) -> Vec<u64> {
        let mut pcs = Vec::new();
        for (module, bitmap) in &self.bitmaps {
            if let Some(table) = self.tables.get(module) {
                for idx in bitmap.hit_guards() {
                    if let Some(pc) = table.pc_for_guard(idx) {
                        pcs.push(pc);
                    }
                }
            }
        }
        pcs.sort_unstable();
        pcs
    }

    /// Merge another instrumentation's bitmaps into this one.
    pub fn merge(&mut self, other: &Self) {
        for (module, other_bitmap) in &other.bitmaps {
            self.bitmaps.entry(module.clone())
                .and_modify(|b| b.merge(other_bitmap))
                .or_insert_with(|| other_bitmap.clone());
        }
        self.total_callbacks += other.total_callbacks;
    }

    /// Reset all bitmaps (but keep registered tables).
    pub fn reset(&mut self) {
        for bitmap in self.bitmaps.values_mut() {
            bitmap.reset();
        }
        self.total_callbacks = 0;
    }

    /// Export to a flat map of PC → hit count for persistence.
    #[must_use]
    pub fn to_pc_hit_map(&self) -> HashMap<u64, u64> {
        let mut map = HashMap::new();
        for (module, bitmap) in &self.bitmaps {
            if let Some(table) = self.tables.get(module) {
                for idx in bitmap.hit_guards() {
                    if let Some(pc) = table.pc_for_guard(idx) {
                        let count = u64::from(bitmap.bits[idx]);
                        *map.entry(pc).or_insert(0) += count;
                    }
                }
            }
        }
        map
    }
}

// ─── SourceCoverageTracker ────────────────────────────────────────────────────

/// Aggregates PC-guard hit data and maps it to source-level coverage.
pub struct SourceCoverageTracker {
    /// The sancov instrumentation layer.
    pub sancov: SancovInstrumentation,
    /// Line coverage keyed by canonical file path.
    pub line_coverage: HashMap<String, LineCoverageMap>,
    /// Function coverage keyed by function name.
    pub function_coverage: HashMap<String, FunctionCoverageEntry>,
    /// PC → (file, line) debug-info map. In production this would come from DWARF.
    pub debug_info: HashMap<u64, (String, u32)>,
    /// PC → function name debug-info map.
    pub pc_to_func: HashMap<u64, String>,
}

impl SourceCoverageTracker {
    /// Create a new, empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sancov: SancovInstrumentation::new(),
            line_coverage: HashMap::new(),
            function_coverage: HashMap::new(),
            debug_info: HashMap::new(),
            pc_to_func: HashMap::new(),
        }
    }

    /// Register a PC-guard table.
    pub fn register_table(&mut self, table: PcGuardTable) {
        self.sancov.register_table(table);
    }

    /// Register a function with its address range and source location.
    pub fn register_function(
        &mut self,
        name: impl Into<String>,
        start: u64,
        end: u64,
        source_file: Option<String>,
        start_line: Option<u32>,
        total_blocks: usize,
    ) {
        let name_s = name.into();
        // Map all PCs in range to this function name.
        for pc in start..end.min(start + 4096) {
            self.pc_to_func.insert(pc, name_s.clone());
        }
        let mut entry = FunctionCoverageEntry::new(name_s.clone(), start, end);
        entry.source_file = source_file;
        entry.start_line = start_line;
        entry.total_blocks = total_blocks;
        self.function_coverage.insert(name_s, entry);
    }

    /// Register a (PC → source line) mapping for debug info.
    pub fn register_debug_info(&mut self, pc: u64, file: impl Into<String>, line: u32) {
        self.debug_info.insert(pc, (file.into(), line));
    }

    /// Record a hit at absolute PC `addr` (from sancov callback or other source).
    pub fn record_hit(&mut self, addr: u64) {
        // Update sancov.
        self.sancov.total_callbacks += 1;

        // Update line coverage if debug info is available.
        if let Some((file, line)) = self.debug_info.get(&addr).cloned() {
            self.line_coverage
                .entry(file.clone())
                .or_insert_with(|| LineCoverageMap::new(&file))
                .record(*self.debug_info.get(&addr).map_or(&line, |(_, l)| l));
        }

        // Update function coverage.
        if let Some(fname) = self.pc_to_func.get(&addr).cloned()
            && let Some(entry) = self.function_coverage.get_mut(&fname) {
                entry.record_hit(addr);
            }
    }

    /// Record hits from a PC → count map (e.g. imported from drcov).
    pub fn record_hits_from_map(&mut self, hits: &HashMap<u64, u64>) {
        for (&pc, &count) in hits {
            for _ in 0..count {
                self.record_hit(pc);
            }
        }
    }

    /// Overall function coverage: (`functions_covered`, `functions_total`).
    #[must_use]
    pub fn function_coverage_counts(&self) -> (usize, usize) {
        let total = self.function_coverage.len();
        let covered = self.function_coverage.values().filter(|f| f.is_covered()).count();
        (covered, total)
    }

    /// Overall line coverage: (`lines_covered`, `lines_total`).
    #[must_use]
    pub fn line_coverage_counts(&self) -> (usize, usize) {
        let total: usize = self.line_coverage.values()
            .map(|m| m.total_executable as usize)
            .sum();
        let covered: usize = self.line_coverage.values()
            .map(|m| m.covered_lines().len())
            .sum();
        (covered, total)
    }

    /// Export all line coverage to the lcov `.info` format.
    #[must_use]
    pub fn export_lcov(&self) -> String {
        let mut out = String::new();
        for (file, map) in &self.line_coverage {
            let _ = writeln!(out, "TN:\nSF:{file}");
            for (&line, &count) in &map.hits {
                let _ = writeln!(out, "DA:{line},{count}");
            }
            let lh = map.covered_lines().len();
            let lf = map.total_executable as usize;
            let _ = writeln!(out, "LH:{lh}\nLF:{lf}\nend_of_record");
        }
        out
    }

    /// Generate a coverage summary JSON value.
    #[must_use]
    pub fn summary_json(&self) -> serde_json::Value {
        let (fn_cov, fn_total) = self.function_coverage_counts();
        let (ln_cov, ln_total) = self.line_coverage_counts();
        let guard_hit = self.sancov.unique_guards_hit();
        serde_json::json!({
            "function_coverage": {
                "covered": fn_cov,
                "total": fn_total,
                "pct": if fn_total == 0 { 0.0 } else { crate::casts::usize_to_f64(fn_cov) / crate::casts::usize_to_f64(fn_total) * 100.0 },
            },
            "line_coverage": {
                "covered": ln_cov,
                "total": ln_total,
                "pct": if ln_total == 0 { 0.0 } else { crate::casts::usize_to_f64(ln_cov) / crate::casts::usize_to_f64(ln_total) * 100.0 },
            },
            "pc_guards": {
                "hit": guard_hit,
                "global_density_pct": self.sancov.global_density() * 100.0,
            },
            "total_callbacks": self.sancov.total_callbacks,
        })
    }

    /// Reset all coverage data (keep registration).
    pub fn reset(&mut self) {
        self.sancov.reset();
        for map in self.line_coverage.values_mut() {
            map.hits.clear();
        }
        for entry in self.function_coverage.values_mut() {
            entry.hit_count = 0;
            entry.covered_blocks.clear();
        }
    }

    /// Merge another tracker's coverage into this one.
    pub fn merge(&mut self, other: &Self) {
        self.sancov.merge(&other.sancov);
        for (file, other_map) in &other.line_coverage {
            self.line_coverage
                .entry(file.clone())
                .and_modify(|m| m.merge(other_map))
                .or_insert_with(|| other_map.clone());
        }
        for (name, other_entry) in &other.function_coverage {
            self.function_coverage
                .entry(name.clone())
                .and_modify(|e| {
                    e.hit_count += other_entry.hit_count;
                    e.covered_blocks.extend(other_entry.covered_blocks.iter().copied());
                })
                .or_insert_with(|| other_entry.clone());
        }
    }
}

impl Default for SourceCoverageTracker {
    fn default() -> Self { Self::new() }
}

// ─── CoverageSnapshot ─────────────────────────────────────────────────────────

/// A serializable snapshot of coverage from one run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    pub run_id: String,
    pub timestamp_ms: u64,
    /// PC → hit count.
    pub pc_hits: HashMap<u64, u64>,
    /// File → (line → count).
    pub line_hits: HashMap<String, HashMap<u32, u64>>,
    /// Function → hit count.
    pub function_hits: HashMap<String, u64>,
    pub total_callbacks: u64,
}

impl CoverageSnapshot {
    /// Create a snapshot from a `SourceCoverageTracker`.
    #[must_use]
    pub fn from_tracker(run_id: impl Into<String>, tracker: &SourceCoverageTracker) -> Self {
        let pc_hits = tracker.sancov.to_pc_hit_map();
        let line_hits: HashMap<String, HashMap<u32, u64>> = tracker.line_coverage.iter()
            .map(|(file, map)| {
                let hits: HashMap<u32, u64> = map.hits.iter().map(|(&l, &c)| (l, c)).collect();
                (file.clone(), hits)
            })
            .collect();
        let function_hits: HashMap<String, u64> = tracker.function_coverage.iter()
            .map(|(name, e)| (name.clone(), e.hit_count))
            .collect();
        let now = crate::casts::u128_to_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        );
        Self {
            run_id: run_id.into(),
            timestamp_ms: now,
            pc_hits,
            line_hits,
            function_hits,
            total_callbacks: tracker.sancov.total_callbacks,
        }
    }

    /// Apply this snapshot's data to a tracker (additive merge).
    pub fn apply_to(&self, tracker: &mut SourceCoverageTracker) {
        tracker.record_hits_from_map(&self.pc_hits);
        for (file, line_map) in &self.line_hits {
            let lmap = tracker.line_coverage
                .entry(file.clone())
                .or_insert_with(|| LineCoverageMap::new(file));
            for (&line, &count) in line_map {
                lmap.record_n(line, count);
            }
        }
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on failure.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> PcGuardTable {
        let mut t = PcGuardTable::new("test_module", 0x4000_0000);
        for i in 0..16u64 {
            t.register_guard(0x4000_0000 + i * 4);
        }
        t
    }

    #[test]
    fn test_pc_guard_table_register() {
        let t = make_table();
        assert_eq!(t.len(), 16);
        assert_eq!(t.pc_for_guard(0), Some(0x4000_0000));
        assert_eq!(t.guard_for_pc(0x4000_0000), Some(0));
    }

    #[test]
    fn test_pc_guard_table_binary_roundtrip() {
        let t = make_table();
        let bytes = t.to_binary();
        let t2 = PcGuardTable::from_binary(&bytes, "test_module", 0x4000_0000).unwrap();
        assert_eq!(t.guards, t2.guards);
    }

    #[test]
    fn test_sancov_trace() {
        let mut sancov = SancovInstrumentation::new();
        sancov.register_table(make_table());
        sancov.trace_pc_guard("test_module", 3);
        sancov.trace_pc_guard("test_module", 3);
        sancov.trace_pc_guard("test_module", 7);
        assert_eq!(sancov.unique_guards_hit(), 2);
        assert_eq!(sancov.total_callbacks, 3);
    }

    #[test]
    fn test_sancov_hit_pcs() {
        let mut sancov = SancovInstrumentation::new();
        sancov.register_table(make_table());
        sancov.trace_pc_guard("test_module", 0);
        sancov.trace_pc_guard("test_module", 5);
        let pcs = sancov.hit_pcs();
        assert_eq!(pcs.len(), 2);
        assert!(pcs.contains(&0x4000_0000));
    }

    #[test]
    fn test_source_coverage_tracker_function_coverage() {
        let mut tracker = SourceCoverageTracker::new();
        tracker.register_function("my_func", 0x1000, 0x1100, None, Some(10), 5);
        tracker.record_hit(0x1000);
        tracker.record_hit(0x1020);
        let (cov, total) = tracker.function_coverage_counts();
        assert_eq!(total, 1);
        assert_eq!(cov, 1);
    }

    #[test]
    fn test_line_coverage_map() {
        let mut map = LineCoverageMap::new("src/main.rs");
        map.total_executable = 10;
        map.record(1);
        map.record(2);
        map.record(2);
        assert_eq!(map.covered_lines().len(), 2);
        assert_eq!(*map.hits.get(&2).unwrap(), 2);
        let pct = map.coverage_pct();
        assert!((pct - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_export_lcov() {
        let mut tracker = SourceCoverageTracker::new();
        tracker.register_debug_info(0x1000, "foo.rs", 5);
        tracker.record_hit(0x1000);
        let lcov = tracker.export_lcov();
        assert!(lcov.contains("SF:foo.rs"));
        assert!(lcov.contains("DA:5,"));
        assert!(lcov.contains("end_of_record"));
    }

    #[test]
    fn test_coverage_snapshot_roundtrip() {
        let mut tracker = SourceCoverageTracker::new();
        tracker.register_function("f1", 0x2000, 0x2100, None, None, 3);
        tracker.record_hit(0x2000);
        let snap = CoverageSnapshot::from_tracker("run1", &tracker);
        assert_eq!(snap.run_id, "run1");
        let json = snap.to_json().unwrap();
        let snap2 = CoverageSnapshot::from_json(&json).unwrap();
        assert_eq!(snap2.run_id, "run1");
    }

    #[test]
    fn test_tracker_merge() {
        let mut t1 = SourceCoverageTracker::new();
        let mut t2 = SourceCoverageTracker::new();
        t1.register_function("g1", 0x3000, 0x3100, None, None, 2);
        t2.register_function("g1", 0x3000, 0x3100, None, None, 2);
        t1.record_hit(0x3000);
        t2.record_hit(0x3040);
        t1.merge(&t2);
        let entry = t1.function_coverage.get("g1").unwrap();
        assert!(entry.covered_blocks.contains(&0x3000));
        // g1 was hit in t2, merged into t1
        assert!(entry.hit_count >= 1);
    }

    #[test]
    fn test_empty_table() {
        let t = PcGuardTable::new("empty", 0);
        assert!(t.is_empty());
        assert_eq!(t.pc_for_guard(0), None);
    }
}
