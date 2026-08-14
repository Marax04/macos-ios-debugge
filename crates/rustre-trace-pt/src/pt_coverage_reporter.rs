//! `pt_coverage_reporter` — Build coverage reports from Intel PT decoded blocks.
//!
//! Aggregates a set of decoded basic blocks and a target address map to
//! produce per-module / per-function coverage percentages and to identify
//! uncovered ("gap") regions.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::ops::Range;

// ── CoverageEntry ─────────────────────────────────────────────────────────────

/// A single coverage entry describing an address range and whether it was hit.
#[derive(Debug, Clone)]
pub struct CoverageEntry {
    /// Start address of this entry (e.g., function or basic block start).
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Human-readable label (function name, symbol, etc.).
    pub label: String,
    /// Module / image this entry belongs to.
    pub module: String,
    /// Whether this range was executed at least once.
    pub covered: bool,
    /// How many times this range was executed.
    pub hit_count: u64,
}

impl CoverageEntry {
    /// Create a new coverage entry.
    #[must_use]
    pub fn new(start: u64, end: u64, label: impl Into<String>, module: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: label.into(),
            module: module.into(),
            covered: false,
            hit_count: 0,
        }
    }

    /// Size in bytes of this entry.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Mark as covered with a hit count.
    pub const fn mark_covered(&mut self, hits: u64) {
        self.covered = true;
        self.hit_count += hits;
    }

    /// Return `true` if `ip` falls within `[start, end)`.
    #[must_use]
    pub const fn contains(&self, ip: u64) -> bool {
        ip >= self.start && ip < self.end
    }
}

impl fmt::Display for CoverageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}!{} 0x{:x}-0x{:x} [", self.module, self.label, self.start, self.end)?;
        if self.covered {
            write!(f, "HIT({})]", self.hit_count)
        } else {
            write!(f, "MISS]")
        }
    }
}

// ── CoverageGap ───────────────────────────────────────────────────────────────

/// An uncovered address range (gap in PT coverage).
#[derive(Debug, Clone)]
pub struct CoverageGap {
    /// Start address of the gap.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Module / image this gap belongs to.
    pub module: String,
    /// Labels of the functions that contain this gap (may be multiple if
    /// the gap spans a function boundary).
    pub containing_functions: Vec<String>,
}

impl CoverageGap {
    /// Size of the gap in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Return the address range as a `Range<u64>`.
    #[must_use]
    pub const fn range(&self) -> Range<u64> {
        self.start..self.end
    }
}

impl fmt::Display for CoverageGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GAP {}!? 0x{:x}-0x{:x} ({} bytes)",
            self.module,
            self.start,
            self.end,
            self.size(),
        )
    }
}

// ── ModuleCoverage ────────────────────────────────────────────────────────────

/// Aggregate coverage statistics for a single module.
#[derive(Debug, Clone, Default)]
pub struct ModuleCoverage {
    /// Module name.
    pub name: String,
    /// Total number of tracked functions/ranges.
    pub total_entries: usize,
    /// Number of entries that were covered.
    pub covered_entries: usize,
    /// Total bytes tracked.
    pub total_bytes: u64,
    /// Bytes that were covered.
    pub covered_bytes: u64,
    /// Gaps within this module.
    pub gaps: Vec<CoverageGap>,
}

impl ModuleCoverage {
    /// Return coverage percentage by entry count.
    #[must_use]
    pub fn entry_coverage_pct(&self) -> f64 {
        if self.total_entries == 0 {
            return 0.0;
        }
        100.0 * crate::cast_helpers::usize_to_f64(self.covered_entries) / crate::cast_helpers::usize_to_f64(self.total_entries)
    }

    /// Return coverage percentage by byte count.
    #[must_use]
    pub fn byte_coverage_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        100.0 * crate::cast_helpers::u64_to_f64(self.covered_bytes) / crate::cast_helpers::u64_to_f64(self.total_bytes)
    }
}

impl fmt::Display for ModuleCoverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}/{} entries ({:.1}%) {}/{} bytes ({:.1}%) gaps={}",
            self.name,
            self.covered_entries,
            self.total_entries,
            self.entry_coverage_pct(),
            self.covered_bytes,
            self.total_bytes,
            self.byte_coverage_pct(),
            self.gaps.len(),
        )
    }
}

// ── PtCoverageReporter ────────────────────────────────────────────────────────

/// Builds a coverage report from PT decoded block data.
///
/// Usage:
/// 1. Register all known address ranges with [`add_entry`].
/// 2. Call [`record_hit`] for every decoded block start IP.
/// 3. Call [`finalize`] to compute gaps and per-module stats.
#[derive(Debug)]
pub struct PtCoverageReporter {
    /// Registered coverage entries, stored as a `BTree` for range queries.
    entries: BTreeMap<u64, CoverageEntry>,
    /// Set of IPs that were hit.
    hits: HashMap<u64, u64>,
    /// Per-module statistics (populated after `finalize()`).
    pub module_stats: HashMap<String, ModuleCoverage>,
    /// All detected gaps (populated after `finalize()`).
    pub gaps: Vec<CoverageGap>,
    /// Whether `finalize()` has been called.
    pub finalized: bool,
}

impl PtCoverageReporter {
    /// Create a new, empty reporter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            hits: HashMap::new(),
            module_stats: HashMap::new(),
            gaps: Vec::new(),
            finalized: false,
        }
    }

    /// Register a coverage entry (a known function or block range).
    pub fn add_entry(&mut self, entry: CoverageEntry) {
        self.entries.insert(entry.start, entry);
    }

    /// Register multiple entries at once.
    pub fn add_entries(&mut self, entries: impl IntoIterator<Item = CoverageEntry>) {
        for e in entries {
            self.add_entry(e);
        }
    }

    /// Record a hit at `ip` (from a decoded PT block).
    pub fn record_hit(&mut self, ip: u64, count: u64) {
        *self.hits.entry(ip).or_insert(0) += count;
    }

    /// Record hits from a slice of `(ip, count)` pairs.
    pub fn record_hits(&mut self, hits: impl IntoIterator<Item = (u64, u64)>) {
        for (ip, count) in hits {
            self.record_hit(ip, count);
        }
    }

    /// Compute coverage, gaps, and per-module stats.
    pub fn finalize(&mut self) {
        // 1. Mark entries as covered where we have hits.
        for (&ip, &count) in &self.hits {
            // Walk backwards in the BTree to find the entry that contains ip.
            let range_end = ip + 1;
            for (_, entry) in self.entries.range_mut(..range_end).rev() {
                if entry.contains(ip) {
                    entry.mark_covered(count);
                    break;
                }
            }
        }

        // 2. Build per-module stats.
        let mut module_map: HashMap<String, ModuleCoverage> = HashMap::new();
        for entry in self.entries.values() {
            let ms = module_map.entry(entry.module.clone()).or_insert_with(|| {
                ModuleCoverage {
                    name: entry.module.clone(),
                    ..Default::default()
                }
            });
            ms.total_entries += 1;
            ms.total_bytes += entry.size();
            if entry.covered {
                ms.covered_entries += 1;
                ms.covered_bytes += entry.size();
            }
        }

        // 3. Find gaps: collect sorted uncovered entry start addresses.
        let mut all_modules: HashSet<String> = HashSet::new();
        for entry in self.entries.values() {
            all_modules.insert(entry.module.clone());
        }

        for module in &all_modules {
            let mut sorted_entries: Vec<&CoverageEntry> = self
                .entries
                .values()
                .filter(|e| &e.module == module)
                .collect();
            sorted_entries.sort_by_key(|e| e.start);

            let mut i = 0;
            while i < sorted_entries.len() {
                if sorted_entries[i].covered {
                    i += 1;
                } else {
                    // Merge consecutive uncovered entries.
                    let gap_start = sorted_entries[i].start;
                    let mut gap_end = sorted_entries[i].end;
                    let mut funcs = vec![sorted_entries[i].label.clone()];
                    let mut j = i + 1;
                    while j < sorted_entries.len()
                        && !sorted_entries[j].covered
                        && sorted_entries[j].start == gap_end
                    {
                        gap_end = sorted_entries[j].end;
                        funcs.push(sorted_entries[j].label.clone());
                        j += 1;
                    }
                    let gap = CoverageGap {
                        start: gap_start,
                        end: gap_end,
                        module: module.clone(),
                        containing_functions: funcs,
                    };
                    if let Some(ms) = module_map.get_mut(module) {
                        ms.gaps.push(gap.clone());
                    }
                    self.gaps.push(gap);
                    i = j;
                }
            }
        }

        self.module_stats = module_map;
        self.finalized = true;
    }

    /// Total entry-level coverage percentage across all modules.
    #[must_use]
    pub fn overall_entry_coverage_pct(&self) -> f64 {
        let total: usize = self.module_stats.values().map(|m| m.total_entries).sum();
        let covered: usize = self.module_stats.values().map(|m| m.covered_entries).sum();
        if total == 0 {
            return 0.0;
        }
        100.0 * crate::cast_helpers::usize_to_f64(covered) / crate::cast_helpers::usize_to_f64(total)
    }

    /// Total byte coverage percentage across all modules.
    #[must_use]
    pub fn overall_byte_coverage_pct(&self) -> f64 {
        let total: u64 = self.module_stats.values().map(|m| m.total_bytes).sum();
        let covered: u64 = self.module_stats.values().map(|m| m.covered_bytes).sum();
        if total == 0 {
            return 0.0;
        }
        100.0 * crate::cast_helpers::u64_to_f64(covered) / crate::cast_helpers::u64_to_f64(total)
    }

    /// Return a formatted coverage report.
    #[must_use]
    pub fn format_report(&self) -> String {
        let mut out = format!(
            "=== PT Coverage Report ===\n\
             Overall entry coverage: {:.1}%\n\
             Overall byte  coverage: {:.1}%\n\n",
            self.overall_entry_coverage_pct(),
            self.overall_byte_coverage_pct(),
        );

        let mut mods: Vec<&ModuleCoverage> = self.module_stats.values().collect();
        mods.sort_by(|a, b| a.name.cmp(&b.name));
        for m in mods {
            use std::fmt::Write as _;
            let _ = writeln!(out, "  {m}");
            for gap in &m.gaps {
                let _ = writeln!(out, "    {gap}");
            }
        }
        out
    }

    /// Iterate over all registered entries (sorted by start address).
    pub fn all_entries(&self) -> impl Iterator<Item = &CoverageEntry> {
        self.entries.values()
    }
}

impl Default for PtCoverageReporter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_reporter() -> PtCoverageReporter {
        let mut r = PtCoverageReporter::new();
        r.add_entry(CoverageEntry::new(0x1000, 0x1100, "func_a", "mylib"));
        r.add_entry(CoverageEntry::new(0x1100, 0x1200, "func_b", "mylib"));
        r.add_entry(CoverageEntry::new(0x2000, 0x2080, "func_c", "otherlib"));
        r.record_hit(0x1000, 5); // covers func_a
        r.record_hit(0x2000, 1); // covers func_c
        r.finalize();
        r
    }

    #[test]
    fn test_finalize_marks_covered() {
        let r = sample_reporter();
        let fa = r.entries[&0x1000].covered;
        let fb = r.entries[&0x1100].covered;
        assert!(fa, "func_a should be covered");
        assert!(!fb, "func_b should not be covered");
    }

    #[test]
    fn test_entry_coverage_pct_mylib() {
        let r = sample_reporter();
        let ms = &r.module_stats["mylib"];
        // 1 of 2 covered
        assert!((ms.entry_coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_byte_coverage_pct_mylib() {
        let r = sample_reporter();
        let ms = &r.module_stats["mylib"];
        // func_a is 256 bytes, func_b is 256 bytes; only func_a covered
        assert!((ms.byte_coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_otherlib_fully_covered() {
        let r = sample_reporter();
        let ms = &r.module_stats["otherlib"];
        assert!((ms.entry_coverage_pct() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_gaps_detected() {
        let r = sample_reporter();
        // func_b in mylib is uncovered => one gap
        assert!(!r.gaps.is_empty());
        let mylib_gap = r.gaps.iter().find(|g| g.module == "mylib");
        assert!(mylib_gap.is_some());
    }

    #[test]
    fn test_gap_range() {
        let r = sample_reporter();
        let gap = r.gaps.iter().find(|g| g.module == "mylib").unwrap();
        // func_b gap
        assert_eq!(gap.start, 0x1100);
        assert_eq!(gap.end, 0x1200);
    }

    #[test]
    fn test_gap_size() {
        let gap = CoverageGap {
            start: 0x1000,
            end: 0x1080,
            module: "m".into(),
            containing_functions: vec![],
        };
        assert_eq!(gap.size(), 0x80);
    }

    #[test]
    fn test_gap_display() {
        let gap = CoverageGap {
            start: 0x1000,
            end: 0x1080,
            module: "mylib".into(),
            containing_functions: vec!["func_b".into()],
        };
        let s = gap.to_string();
        assert!(s.contains("GAP"));
        assert!(s.contains("mylib"));
    }

    #[test]
    fn test_overall_entry_pct() {
        let r = sample_reporter();
        // 2 of 3 entries covered
        let pct = r.overall_entry_coverage_pct();
        assert!((pct - 66.666).abs() < 0.01);
    }

    #[test]
    fn test_overall_byte_pct() {
        let r = sample_reporter();
        // func_a (256) + func_c (128) = 384 covered out of 640 total
        let pct = r.overall_byte_coverage_pct();
        assert!((pct - 60.0).abs() < 0.01);
    }

    #[test]
    fn test_format_report_contains_pct() {
        let r = sample_reporter();
        let s = r.format_report();
        assert!(s.contains("PT Coverage Report"));
        assert!(s.contains('%'));
    }

    #[test]
    fn test_coverage_entry_contains() {
        let e = CoverageEntry::new(0x1000, 0x1100, "f", "m");
        assert!(e.contains(0x1000));
        assert!(e.contains(0x10ff));
        assert!(!e.contains(0x1100));
    }

    #[test]
    fn test_coverage_entry_size() {
        let e = CoverageEntry::new(0x1000, 0x1100, "f", "m");
        assert_eq!(e.size(), 0x100);
    }

    #[test]
    fn test_coverage_entry_display_hit() {
        let mut e = CoverageEntry::new(0x1000, 0x1100, "func_a", "mylib");
        e.mark_covered(3);
        let s = e.to_string();
        assert!(s.contains("HIT(3)"));
    }

    #[test]
    fn test_coverage_entry_display_miss() {
        let e = CoverageEntry::new(0x2000, 0x2100, "func_b", "mylib");
        assert!(e.to_string().contains("MISS"));
    }

    #[test]
    fn test_module_coverage_display() {
        let m = ModuleCoverage {
            name: "mylib".into(),
            total_entries: 10,
            covered_entries: 5,
            total_bytes: 1000,
            covered_bytes: 500,
            gaps: vec![],
        };
        let s = m.to_string();
        assert!(s.contains("mylib"));
        assert!(s.contains("50.0%"));
    }

    #[test]
    fn test_hit_count_accumulation() {
        let r = sample_reporter();
        let fa = &r.entries[&0x1000];
        assert_eq!(fa.hit_count, 5);
    }

    #[test]
    fn test_empty_reporter() {
        let mut r = PtCoverageReporter::new();
        r.finalize();
        assert_eq!(r.overall_entry_coverage_pct(), 0.0);
        assert!(r.gaps.is_empty());
    }

    #[test]
    fn test_add_entries_bulk() {
        let mut r = PtCoverageReporter::new();
        r.add_entries(vec![
            CoverageEntry::new(0x1000, 0x1100, "a", "m"),
            CoverageEntry::new(0x1100, 0x1200, "b", "m"),
        ]);
        assert_eq!(r.entries.len(), 2);
    }

    #[test]
    fn test_record_hits_bulk() {
        let mut r = PtCoverageReporter::new();
        r.add_entry(CoverageEntry::new(0x1000, 0x1100, "a", "m"));
        r.record_hits(vec![(0x1000, 2), (0x1000, 3)]);
        r.finalize();
        assert_eq!(r.entries[&0x1000].hit_count, 5);
    }
}
