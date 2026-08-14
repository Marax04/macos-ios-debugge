//! `sanitizer_dashboard` — Aggregate sanitizer findings into a dashboard.
//!
//! This module collects [`DashboardEntry`] records produced by the various
//! report parsers (`ASan`, `MSan`, `TSan`, `UBSan`) and presents them as a unified
//! table with per-sanitizer counts, severity breakdowns, and a text summary.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use crate::{CrashSeverity, SanitizerTool};

// ── SanitizerKindExt ─────────────────────────────────────────────────────────

/// Extended categorization of a sanitizer finding.
///
/// This type maps more closely to the family of tool that produced the finding
/// than the lower-level [`crate::SanitizerKind`], which describes the
/// programming error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanitizerKind {
    /// `AddressSanitizer` (heap/stack/global memory errors).
    Asan,
    /// `MemorySanitizer` (uninitialised reads).
    Msan,
    /// `ThreadSanitizer` (data races, deadlocks).
    Tsan,
    /// `UndefinedBehaviourSanitizer` (integer overflow, misalignment, …).
    Ubsan,
    /// `LeakSanitizer` (memory leaks).
    Lsan,
    /// Unknown or unrecognised tool.
    Unknown,
}

impl SanitizerKind {
    /// Convert from the crate-level [`SanitizerTool`] enum.
    #[must_use]
    pub const fn from_tool(tool: SanitizerTool) -> Self {
        match tool {
            SanitizerTool::ASan => Self::Asan,
            SanitizerTool::MSan => Self::Msan,
            SanitizerTool::TSan => Self::Tsan,
            SanitizerTool::UBSan => Self::Ubsan,
            SanitizerTool::LSan => Self::Lsan,
            SanitizerTool::Unknown => Self::Unknown,
        }
    }

    /// Short abbreviated name.
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Asan => "ASan",
            Self::Msan => "MSan",
            Self::Tsan => "TSan",
            Self::Ubsan => "UBSan",
            Self::Lsan => "LSan",
            Self::Unknown => "?",
        }
    }
}

impl fmt::Display for SanitizerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short_name())
    }
}

// ── DashboardEntry ────────────────────────────────────────────────────────────

/// A single sanitizer finding recorded on the dashboard.
#[derive(Debug, Clone)]
pub struct DashboardEntry {
    /// Which sanitizer produced this entry.
    pub kind: SanitizerKind,
    /// Short error type string (e.g. `"heap-buffer-overflow"`).
    pub error_type: String,
    /// Memory address involved (if applicable).
    pub address: Option<u64>,
    /// Severity classification.
    pub severity: CrashSeverity,
    /// Top-of-stack function name, if resolved.
    pub top_function: Option<String>,
    /// Source file of the crash, if resolved.
    pub source_file: Option<String>,
    /// Source line of the crash, if resolved.
    pub source_line: Option<u32>,
    /// Number of times this exact signature has been seen.
    pub hit_count: u64,
    /// Arbitrary human-readable note attached to this entry.
    pub note: Option<String>,
}

impl DashboardEntry {
    /// Create a new entry with `hit_count = 1`.
    #[must_use]
    pub fn new(
        kind: SanitizerKind,
        error_type: impl Into<String>,
        severity: CrashSeverity,
    ) -> Self {
        Self {
            kind,
            error_type: error_type.into(),
            address: None,
            severity,
            top_function: None,
            source_file: None,
            source_line: None,
            hit_count: 1,
            note: None,
        }
    }

    #[must_use]
    /// Attach a top-function name.
    pub fn with_function(mut self, func: impl Into<String>) -> Self {
        self.top_function = Some(func.into());
        self
    }

    #[must_use]
    /// Attach a source location.
    pub fn with_location(mut self, file: impl Into<String>, line: u32) -> Self {
        self.source_file = Some(file.into());
        self.source_line = Some(line);
        self
    }

    /// Attach a memory address.
    #[must_use] 
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    /// Attach a human-readable note.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Return a one-line description of this entry.
    #[must_use]
    pub fn one_line(&self) -> String {
        let addr = self
            .address
            .map_or_else(|| "?".to_owned(), |a| format!("0x{a:x}"));
        let func = self.top_function.as_deref().unwrap_or("<unknown>");
        format!(
            "[{}] {} | {} | {} | {} | hits={}",
            self.kind, self.severity, self.error_type, addr, func, self.hit_count
        )
    }
}

impl fmt::Display for DashboardEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.one_line())
    }
}

// ── SanitizerDashboard ────────────────────────────────────────────────────────

/// Collects and summarises sanitizer findings from multiple sources.
///
/// Call [`SanitizerDashboard::add`] to register findings produced by the
/// `ASan`, `MSan`, and `TSan` parsers, then use [`generate_summary`] or the
/// individual accessors to query the aggregated data.
#[derive(Debug, Default)]
pub struct SanitizerDashboard {
    /// All registered entries (in insertion order).
    pub entries: Vec<DashboardEntry>,
}

impl SanitizerDashboard {
    /// Create an empty dashboard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pre-built entry to the dashboard.
    pub fn add(&mut self, entry: DashboardEntry) {
        self.entries.push(entry);
    }

    /// Add a finding using the raw fields.
    pub fn record(
        &mut self,
        kind: SanitizerKind,
        error_type: impl Into<String>,
        severity: CrashSeverity,
        top_function: Option<String>,
        address: Option<u64>,
    ) {
        let mut entry = DashboardEntry::new(kind, error_type, severity);
        entry.top_function = top_function;
        entry.address = address;
        self.entries.push(entry);
    }

    /// Return the total number of entries.
    #[must_use]
    pub const fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Return entries filtered to a specific sanitizer kind.
    #[must_use]
    pub fn by_kind(&self, kind: SanitizerKind) -> Vec<&DashboardEntry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    /// Return entries at or above the given severity.
    #[must_use]
    pub fn by_min_severity(&self, min: CrashSeverity) -> Vec<&DashboardEntry> {
        self.entries.iter().filter(|e| e.severity >= min).collect()
    }

    /// Return entries for the given error type.
    #[must_use]
    pub fn by_error_type(&self, error_type: &str) -> Vec<&DashboardEntry> {
        self.entries
            .iter()
            .filter(|e| e.error_type == error_type)
            .collect()
    }

    /// Count entries per sanitizer kind.
    #[must_use]
    pub fn counts_by_kind(&self) -> HashMap<SanitizerKind, usize> {
        let mut map: HashMap<SanitizerKind, usize> = HashMap::new();
        for e in &self.entries {
            *map.entry(e.kind).or_insert(0) += 1;
        }
        map
    }

    /// Count entries per severity.
    #[must_use]
    pub fn counts_by_severity(&self) -> HashMap<CrashSeverity, usize> {
        let mut map: HashMap<CrashSeverity, usize> = HashMap::new();
        for e in &self.entries {
            *map.entry(e.severity).or_insert(0) += 1;
        }
        map
    }

    /// Return the highest severity seen across all entries, or `None` if empty.
    #[must_use]
    pub fn max_severity(&self) -> Option<CrashSeverity> {
        self.entries.iter().map(|e| e.severity).max()
    }

    /// Return the most frequently hit error type.
    #[must_use]
    pub fn dominant_error_type(&self) -> Option<&str> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for e in &self.entries {
            *counts.entry(e.error_type.as_str()).or_insert(0) += crate::cast::u64_to_usize(e.hit_count);
        }
        // Total order on ties, so the answer does not vary between runs.
        counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, _)| k)
    }

    /// Return addresses seen more than once (potential hot spots).
    #[must_use]
    pub fn repeated_addresses(&self) -> Vec<(u64, usize)> {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for e in &self.entries {
            if let Some(addr) = e.address {
                *counts.entry(addr).or_insert(0) += 1;
            }
        }
        let mut repeated: Vec<(u64, usize)> = counts
            .into_iter()
            .filter(|(_, c)| *c > 1)
            .collect();
        repeated.sort_by(|a, b| b.1.cmp(&a.1));
        repeated
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── generate_summary ──────────────────────────────────────────────────────────

/// Generate a multi-line text summary of the dashboard.
///
/// The summary includes:
/// - Per-sanitizer entry counts.
/// - Per-severity entry counts.
/// - The highest severity seen.
/// - The most common error type.
/// - The first few entries as one-liners.
#[must_use]
pub fn generate_summary(dashboard: &SanitizerDashboard) -> String {
    // Header ≈ 60 bytes + ~50 bytes per entry (kind/severity rows + top entries).
    let mut out = String::with_capacity(128 + dashboard.entries.len() * 80);

    let _ = writeln!(out, "=== Sanitizer Dashboard ({} entries) ===", dashboard.total_entries());

    // By kind
    let by_kind = dashboard.counts_by_kind();
    if !by_kind.is_empty() {
        out.push_str("\nBy sanitizer:\n");
        let mut kinds: Vec<(&SanitizerKind, &usize)> = by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1));
        for (k, c) in kinds {
            let _ = writeln!(out, "  {:6} : {}", k.short_name(), c);
        }
    }

    // By severity
    let by_sev = dashboard.counts_by_severity();
    if !by_sev.is_empty() {
        out.push_str("\nBy severity:\n");
        let mut sevs: Vec<(&CrashSeverity, &usize)> = by_sev.iter().collect();
        sevs.sort_by(|a, b| b.0.cmp(a.0));
        for (s, c) in sevs {
            let _ = writeln!(out, "  {:8} : {}", s.to_string(), c);
        }
    }

    // Headline stats
    if let Some(max) = dashboard.max_severity() {
        let _ = writeln!(out, "\nHighest severity : {max}");
    }
    if let Some(err) = dashboard.dominant_error_type() {
        let _ = writeln!(out, "Most common error: {err}");
    }

    // Hot addresses
    let repeated = dashboard.repeated_addresses();
    if !repeated.is_empty() {
        out.push_str("\nRepeated addresses (hot spots):\n");
        for (addr, count) in repeated.iter().take(5) {
            let _ = writeln!(out, "  0x{addr:x} × {count}");
        }
    }

    // First few entries
    if !dashboard.entries.is_empty() {
        out.push_str("\nTop entries:\n");
        for entry in dashboard.entries.iter().take(10) {
            let _ = writeln!(out, "  {}", entry.one_line());
        }
    }

    out
}

// ── DashboardBuilder ──────────────────────────────────────────────────────────

/// Fluent builder for constructing a [`SanitizerDashboard`] from parsed reports.
#[derive(Debug, Default)]
pub struct DashboardBuilder {
    inner: SanitizerDashboard,
}

impl DashboardBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a raw entry.
    #[must_use] 
    pub fn entry(mut self, entry: DashboardEntry) -> Self {
        self.inner.add(entry);
        self
    }

    #[must_use]
    /// Shorthand: add an `ASan` entry.
    pub fn asan(
        mut self,
        error_type: impl Into<String>,
        severity: CrashSeverity,
        func: Option<String>,
        addr: Option<u64>,
    ) -> Self {
        self.inner
            .record(SanitizerKind::Asan, error_type, severity, func, addr);
        self
    }

    #[must_use]
    /// Shorthand: add an `MSan` entry.
    pub fn msan(
        mut self,
        error_type: impl Into<String>,
        severity: CrashSeverity,
        func: Option<String>,
    ) -> Self {
        self.inner
            .record(SanitizerKind::Msan, error_type, severity, func, None);
        self
    }

    #[must_use]
    /// Shorthand: add a `TSan` entry.
    pub fn tsan(
        mut self,
        error_type: impl Into<String>,
        severity: CrashSeverity,
        func: Option<String>,
    ) -> Self {
        self.inner
            .record(SanitizerKind::Tsan, error_type, severity, func, None);
        self
    }

    /// Finalise and return the dashboard.
    #[must_use]
    pub fn build(self) -> SanitizerDashboard {
        self.inner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dashboard() -> SanitizerDashboard {
        DashboardBuilder::new()
            .asan(
                "heap-buffer-overflow",
                CrashSeverity::High,
                Some("func_a".to_owned()),
                Some(0x1000),
            )
            .asan(
                "use-after-free",
                CrashSeverity::Critical,
                Some("func_b".to_owned()),
                Some(0x2000),
            )
            .msan(
                "use-of-uninitialized-value",
                CrashSeverity::Medium,
                Some("func_c".to_owned()),
            )
            .tsan("data race", CrashSeverity::High, Some("func_d".to_owned()))
            .build()
    }

    #[test]
    fn test_total_entries() {
        let d = make_dashboard();
        assert_eq!(d.total_entries(), 4);
    }

    #[test]
    fn test_by_kind_asan() {
        let d = make_dashboard();
        assert_eq!(d.by_kind(SanitizerKind::Asan).len(), 2);
    }

    #[test]
    fn test_by_kind_msan() {
        let d = make_dashboard();
        assert_eq!(d.by_kind(SanitizerKind::Msan).len(), 1);
    }

    #[test]
    fn test_by_kind_tsan() {
        let d = make_dashboard();
        assert_eq!(d.by_kind(SanitizerKind::Tsan).len(), 1);
    }

    #[test]
    fn test_by_min_severity_high() {
        let d = make_dashboard();
        let high = d.by_min_severity(CrashSeverity::High);
        assert_eq!(high.len(), 3);
    }

    #[test]
    fn test_by_min_severity_critical() {
        let d = make_dashboard();
        let crit = d.by_min_severity(CrashSeverity::Critical);
        assert_eq!(crit.len(), 1);
    }

    #[test]
    fn test_by_error_type() {
        let d = make_dashboard();
        let r = d.by_error_type("heap-buffer-overflow");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_counts_by_kind() {
        let d = make_dashboard();
        let m = d.counts_by_kind();
        assert_eq!(m.get(&SanitizerKind::Asan), Some(&2));
        assert_eq!(m.get(&SanitizerKind::Msan), Some(&1));
        assert_eq!(m.get(&SanitizerKind::Tsan), Some(&1));
    }

    #[test]
    fn test_counts_by_severity() {
        let d = make_dashboard();
        let m = d.counts_by_severity();
        assert_eq!(m.get(&CrashSeverity::High), Some(&2));
        assert_eq!(m.get(&CrashSeverity::Critical), Some(&1));
    }

    #[test]
    fn test_max_severity() {
        let d = make_dashboard();
        assert_eq!(d.max_severity(), Some(CrashSeverity::Critical));
    }

    #[test]
    fn test_dominant_error_type() {
        let d = make_dashboard();
        // asan has 2 entries with different types, so no clear dominant unless one repeats
        // Just verify it returns something
        assert!(d.dominant_error_type().is_some());
    }

    #[test]
    fn test_repeated_addresses_none() {
        let d = make_dashboard();
        let r = d.repeated_addresses();
        assert!(r.is_empty());
    }

    #[test]
    fn test_repeated_addresses_with_repeats() {
        let mut d = SanitizerDashboard::new();
        let e1 = DashboardEntry::new(SanitizerKind::Asan, "overflow", CrashSeverity::High)
            .with_address(0xAAAA);
        let e2 = DashboardEntry::new(SanitizerKind::Msan, "uninit", CrashSeverity::Medium)
            .with_address(0xAAAA);
        d.add(e1);
        d.add(e2);
        let r = d.repeated_addresses();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0], (0xAAAA, 2));
    }

    #[test]
    fn test_generate_summary_contains_header() {
        let d = make_dashboard();
        let s = generate_summary(&d);
        assert!(s.contains("Sanitizer Dashboard"));
    }

    #[test]
    fn test_generate_summary_contains_kind() {
        let d = make_dashboard();
        let s = generate_summary(&d);
        assert!(s.contains("ASan"));
        assert!(s.contains("MSan"));
        assert!(s.contains("TSan"));
    }

    #[test]
    fn test_generate_summary_contains_severity() {
        let d = make_dashboard();
        let s = generate_summary(&d);
        assert!(s.contains("HIGH") || s.contains("CRITICAL"));
    }

    #[test]
    fn test_entry_one_line() {
        let e = DashboardEntry::new(SanitizerKind::Asan, "use-after-free", CrashSeverity::Critical)
            .with_function("bad_fn")
            .with_address(0xdead);
        let s = e.one_line();
        assert!(s.contains("ASan"));
        assert!(s.contains("use-after-free"));
        assert!(s.contains("bad_fn"));
    }

    #[test]
    fn test_entry_display() {
        let e = DashboardEntry::new(SanitizerKind::Msan, "uninit", CrashSeverity::Medium);
        assert!(e.to_string().contains("MSan"));
    }

    #[test]
    fn test_sanitizer_kind_display() {
        assert_eq!(SanitizerKind::Asan.to_string(), "ASan");
        assert_eq!(SanitizerKind::Unknown.to_string(), "?");
    }

    #[test]
    fn test_sanitizer_kind_from_tool() {
        assert_eq!(SanitizerKind::from_tool(SanitizerTool::ASan), SanitizerKind::Asan);
        assert_eq!(SanitizerKind::from_tool(SanitizerTool::TSan), SanitizerKind::Tsan);
        assert_eq!(SanitizerKind::from_tool(SanitizerTool::Unknown), SanitizerKind::Unknown);
    }

    #[test]
    fn test_clear() {
        let mut d = make_dashboard();
        d.clear();
        assert_eq!(d.total_entries(), 0);
    }

    #[test]
    fn test_empty_dashboard_summary() {
        let d = SanitizerDashboard::new();
        let s = generate_summary(&d);
        assert!(s.contains("0 entries"));
    }

    #[test]
    fn test_with_note() {
        let e = DashboardEntry::new(SanitizerKind::Lsan, "leak", CrashSeverity::Info)
            .with_note("tracked via valgrind");
        assert_eq!(e.note.as_deref(), Some("tracked via valgrind"));
    }

    #[test]
    fn test_with_location() {
        let e = DashboardEntry::new(SanitizerKind::Ubsan, "integer-overflow", CrashSeverity::Low)
            .with_location("calc.c", 77);
        assert_eq!(e.source_file.as_deref(), Some("calc.c"));
        assert_eq!(e.source_line, Some(77));
    }
}
