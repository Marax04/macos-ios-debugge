//! `crash_analyzer` — Triage, categorize, and deduplicate crashes found during
//! fuzzing.  Provides [`CrashAnalyzer`], [`CrashReport`], and [`CrashCategory`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{CrashRecord, FuzzRng, fnv1a};

// ── CrashCategory ─────────────────────────────────────────────────────────────

/// High-level crash category derived from signal, fault address, and heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashCategory {
    /// Stack buffer overflow (fault address is inside a known stack range).
    StackOverflow,
    /// Heap buffer overflow or use-after-free (fault in heap range).
    HeapCorruption,
    /// Null pointer dereference (fault address near zero).
    NullDeref,
    /// Integer overflow / divide-by-zero (SIGFPE).
    IntegerError,
    /// Out-of-bounds read (SIGSEGV + read access).
    OutOfBoundsRead,
    /// Out-of-bounds write (SIGSEGV + write access).
    OutOfBoundsWrite,
    /// Assertion failure / abort (SIGABRT).
    AssertionFailure,
    /// Use-after-free confirmed by a sanitizer annotation.
    UseAfterFree,
    /// Double-free confirmed by sanitizer.
    DoubleFree,
    /// Process terminated by sanitizer (SIGABRT from ASAN/UBSAN etc.).
    SanitizerKill,
    /// Illegal instruction / bad opcode (SIGILL).
    IllegalInstruction,
    /// Bus error — misaligned access (SIGBUS).
    BusError,
    /// Crash category could not be determined.
    Unknown,
}

impl CrashCategory {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StackOverflow => "stack_overflow",
            Self::HeapCorruption => "heap_corruption",
            Self::NullDeref => "null_deref",
            Self::IntegerError => "integer_error",
            Self::OutOfBoundsRead => "oob_read",
            Self::OutOfBoundsWrite => "oob_write",
            Self::AssertionFailure => "assertion_failure",
            Self::UseAfterFree => "use_after_free",
            Self::DoubleFree => "double_free",
            Self::SanitizerKill => "sanitizer_kill",
            Self::IllegalInstruction => "illegal_instruction",
            Self::BusError => "bus_error",
            Self::Unknown => "unknown",
        }
    }

    /// Rough exploitability score (higher = more interesting to an attacker).
    #[must_use]
    pub const fn exploitability(self) -> u8 {
        match self {
            Self::StackOverflow | Self::HeapCorruption | Self::UseAfterFree | Self::DoubleFree => 4,
            Self::OutOfBoundsWrite => 3,
            Self::OutOfBoundsRead => 2,
            Self::NullDeref | Self::IllegalInstruction | Self::BusError => 1,
            Self::IntegerError | Self::AssertionFailure | Self::SanitizerKill => 1,
            Self::Unknown => 0,
        }
    }

    /// All defined categories.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::StackOverflow,
            Self::HeapCorruption,
            Self::NullDeref,
            Self::IntegerError,
            Self::OutOfBoundsRead,
            Self::OutOfBoundsWrite,
            Self::AssertionFailure,
            Self::UseAfterFree,
            Self::DoubleFree,
            Self::SanitizerKill,
            Self::IllegalInstruction,
            Self::BusError,
            Self::Unknown,
        ]
    }
}

impl std::fmt::Display for CrashCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── SanitizerHint ─────────────────────────────────────────────────────────────

/// Sanitizer output that may accompany a crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerHint {
    /// Raw sanitizer output (e.g. ASAN report text).
    pub raw: String,
    /// Detected bug type keyword (e.g. "heap-buffer-overflow").
    pub bug_type: Option<String>,
    /// Detected sanitizer (e.g. "`AddressSanitizer`").
    pub sanitizer: Option<String>,
    /// Extracted stack frames (function names).
    pub frames: Vec<String>,
}

impl SanitizerHint {
    /// Parse an ASAN/UBSAN/MSan report from raw text.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut hint = Self {
            raw: text.to_owned(),
            bug_type: None,
            sanitizer: None,
            frames: Vec::new(),
        };

        // Detect sanitizer.
        for line in text.lines() {
            if line.contains("AddressSanitizer") {
                hint.sanitizer = Some("AddressSanitizer".to_owned());
            } else if line.contains("MemorySanitizer") {
                hint.sanitizer = Some("MemorySanitizer".to_owned());
            } else if line.contains("UndefinedBehaviorSanitizer") || line.contains("UBSan") {
                hint.sanitizer = Some("UBSan".to_owned());
            } else if line.contains("ThreadSanitizer") {
                hint.sanitizer = Some("ThreadSanitizer".to_owned());
            }
        }

        // Extract bug type from "ERROR: <sanitizer>: <bug-type>" lines.
        for line in text.lines() {
            if let Some(idx) = line.find("ERROR:") {
                let after = line[idx + 6..].trim();
                if let Some(colon) = after.find(':') {
                    let bug = after[colon + 1..].trim().to_owned();
                    if !bug.is_empty() {
                        hint.bug_type = Some(bug);
                        break;
                    }
                }
            }
        }

        // Extract stack frames from lines matching "    #N 0x... in <func>".
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#')
                && let Some(in_idx) = trimmed.find(" in ")
            {
                let frame = trimmed[in_idx + 4..].trim();
                let func = frame.split_whitespace().next().unwrap_or("?").to_owned();
                hint.frames.push(func);
            }
        }

        hint
    }

    /// Derive a [`CrashCategory`] from this hint.
    #[must_use]
    pub fn infer_category(&self) -> Option<CrashCategory> {
        let bug = self.bug_type.as_deref().unwrap_or("").to_lowercase();
        if bug.contains("heap-buffer-overflow") || bug.contains("heap-use-after-free") {
            return Some(CrashCategory::HeapCorruption);
        }
        if bug.contains("use-after-free") {
            return Some(CrashCategory::UseAfterFree);
        }
        if bug.contains("double-free") {
            return Some(CrashCategory::DoubleFree);
        }
        if bug.contains("stack-buffer-overflow") || bug.contains("stack-overflow") {
            return Some(CrashCategory::StackOverflow);
        }
        if bug.contains("null-deref") || bug.contains("null pointer") {
            return Some(CrashCategory::NullDeref);
        }
        if bug.contains("integer-overflow") || bug.contains("signed-integer-overflow") {
            return Some(CrashCategory::IntegerError);
        }
        None
    }
}

// ── CrashReport ───────────────────────────────────────────────────────────────

/// A complete triage report for a single crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    /// Unique report id.
    pub id: u64,
    /// The underlying raw crash record.
    pub record: CrashRecord,
    /// Inferred crash category.
    pub category: CrashCategory,
    /// Exploitability estimate (0-5).
    pub exploitability: u8,
    /// Hash of the normalised stack trace (used for deduplication).
    pub stack_hash: u64,
    /// Human-readable triage summary.
    pub summary: String,
    /// Optional sanitizer hint extracted from the crash output.
    pub sanitizer_hint: Option<SanitizerHint>,
    /// When this report was created.
    pub triaged_at: SystemTime,
    /// Whether this crash has been verified (still reproducible).
    pub verified: bool,
    /// Whether this crash has been minimized.
    pub minimized: bool,
    /// Number of times this crash has been independently triggered.
    pub hit_count: u64,
}

impl CrashReport {
    /// Create a new crash report.
    #[must_use]
    pub fn new(id: u64, record: CrashRecord, category: CrashCategory, stack_hash: u64) -> Self {
        let exploitability = category.exploitability();
        let summary = format!(
            "[{}] signal={} fault={:?} exploitability={}/5",
            category.name(),
            record.signal,
            record.fault_addr,
            exploitability
        );
        Self {
            id,
            record,
            category,
            exploitability,
            stack_hash,
            summary,
            sanitizer_hint: None,
            triaged_at: SystemTime::now(),
            verified: false,
            minimized: false,
            hit_count: 1,
        }
    }

    /// Attach a sanitizer hint to this report and re-infer category if possible.
    #[must_use]
    pub fn with_sanitizer_hint(mut self, hint: SanitizerHint) -> Self {
        if let Some(cat) = hint.infer_category() {
            self.category = cat;
            self.exploitability = cat.exploitability();
        }
        self.sanitizer_hint = Some(hint);
        self
    }

    /// Return `true` if this crash is considered high severity (exploitability >= 3).
    #[must_use]
    pub const fn is_high_severity(&self) -> bool {
        self.exploitability >= 3
    }
}

// ── AnalysisConfig ────────────────────────────────────────────────────────────

/// Configuration for [`CrashAnalyzer`].
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// If `true`, deduplicate crashes by stack hash; otherwise by coverage hash.
    pub dedup_by_stack: bool,
    /// Minimum exploitability to retain in the triaged list.
    pub min_exploitability: u8,
    /// Maximum number of reports to retain.
    pub max_reports: usize,
    /// Stack depth to consider when hashing frames (0 = all frames).
    pub stack_depth: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            dedup_by_stack: true,
            min_exploitability: 0,
            max_reports: 1000,
            stack_depth: 8,
        }
    }
}

// ── CrashAnalyzer ─────────────────────────────────────────────────────────────

/// Accepts raw crashes, categorizes them, deduplicates by stack hash or
/// coverage hash, and maintains a triaged report list.
pub struct CrashAnalyzer {
    /// Configuration.
    pub config: AnalysisConfig,
    /// All triaged reports, keyed by dedup key.
    reports: BTreeMap<u64, CrashReport>,
    /// Next report id.
    next_id: u64,
    /// Set of dedup keys already seen.
    dedup_keys: HashSet<u64>,
    /// Per-category counts.
    category_counts: HashMap<CrashCategory, u64>,
    /// Total crashes submitted (including duplicates).
    total_submitted: u64,
}

impl CrashAnalyzer {
    /// Create a new analyzer with the given config.
    #[must_use]
    pub fn new(config: AnalysisConfig) -> Self {
        Self {
            config,
            reports: BTreeMap::new(),
            next_id: 0,
            dedup_keys: HashSet::new(),
            category_counts: HashMap::new(),
            total_submitted: 0,
        }
    }

    /// Create an analyzer with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(AnalysisConfig::default())
    }

    // ── Submission ────────────────────────────────────────────────────────────

    /// Submit a crash record for analysis.
    ///
    /// Returns `Some(report_id)` if this is a new unique crash, or `None` if it
    /// was already known (duplicate).
    pub fn submit(&mut self, record: CrashRecord) -> Option<u64> {
        self.total_submitted += 1;
        let category = categorize_crash(&record);
        let stack_hash = compute_stack_hash(&record, self.config.stack_depth);
        let dedup_key = if self.config.dedup_by_stack {
            stack_hash
        } else {
            record.coverage_hash
        };

        if let Some(existing) = self.reports.get_mut(&dedup_key) {
            existing.hit_count = existing.hit_count.saturating_add(1);
            return None;
        }

        if self.config.min_exploitability > 0
            && category.exploitability() < self.config.min_exploitability
        {
            return None;
        }

        let id = self.next_id;
        self.next_id += 1;

        *self.category_counts.entry(category).or_insert(0) += 1;
        self.dedup_keys.insert(dedup_key);

        let report = CrashReport::new(id, record, category, stack_hash);

        // Enforce max reports by removing the least-exploitable entry.
        if self.config.max_reports > 0 && self.reports.len() >= self.config.max_reports {
            self.evict_least_exploitable();
        }

        self.reports.insert(dedup_key, report);
        Some(id)
    }

    /// Submit a crash with an optional sanitizer hint string.
    pub fn submit_with_hint(&mut self, record: CrashRecord, sanitizer_output: &str) -> Option<u64> {
        let mut modified = record;

        // Extract stack frames from sanitizer output.
        let hint = SanitizerHint::parse(sanitizer_output);
        let frame_hashes: Vec<u64> = hint.frames.iter().map(|f| fnv1a(f.as_bytes())).collect();
        if !frame_hashes.is_empty() {
            modified.set_stack_hash(&frame_hashes);
        }

        let id = self.submit(modified)?;

        // Attach hint to the newly created report.
        let dedup_key = {
            let r = self.reports.values().find(|r| r.id == id)?;
            r.stack_hash
        };
        if let Some(report) = self.reports.get_mut(&dedup_key) {
            if let Some(cat) = hint.infer_category() {
                report.category = cat;
                report.exploitability = cat.exploitability();
            }
            report.sanitizer_hint = Some(hint);
        }

        Some(id)
    }

    fn evict_least_exploitable(&mut self) {
        let victim_key = self
            .reports
            .values()
            .min_by_key(|r| (r.exploitability, r.hit_count))
            .map(|r| r.stack_hash);

        if let Some(key) = victim_key
            && let Some(report) = self.reports.remove(&key)
        {
            self.dedup_keys.remove(&key);
            let count = self.category_counts.entry(report.category).or_insert(0);
            *count = count.saturating_sub(1);
        }
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Number of unique triaged crashes.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.reports.len()
    }

    /// Total crashes submitted (including duplicates).
    #[must_use]
    pub const fn total_submitted(&self) -> u64 {
        self.total_submitted
    }

    /// Number of duplicates deduplicated out.
    #[must_use]
    pub const fn duplicate_count(&self) -> u64 {
        self.total_submitted.saturating_sub(self.next_id)
    }

    /// Return all triaged crash reports sorted by exploitability descending.
    #[must_use]
    pub fn triaged_crashes(&self) -> Vec<&CrashReport> {
        let mut v: Vec<&CrashReport> = self.reports.values().collect();
        v.sort_unstable_by(|a, b| {
            b.exploitability
                .cmp(&a.exploitability)
                .then(b.hit_count.cmp(&a.hit_count))
        });
        v
    }

    /// Return only high-severity crashes (exploitability >= 3).
    #[must_use]
    pub fn high_severity_crashes(&self) -> Vec<&CrashReport> {
        self.triaged_crashes()
            .into_iter()
            .filter(|r| r.is_high_severity())
            .collect()
    }

    /// Return crashes grouped by category.
    #[must_use]
    pub fn by_category(&self) -> HashMap<CrashCategory, Vec<&CrashReport>> {
        let mut map: HashMap<CrashCategory, Vec<&CrashReport>> = HashMap::new();
        for report in self.reports.values() {
            map.entry(report.category).or_default().push(report);
        }
        map
    }

    /// Return the count of crashes per category.
    #[must_use]
    pub const fn category_counts(&self) -> &HashMap<CrashCategory, u64> {
        &self.category_counts
    }

    /// Get a specific report by id.
    #[must_use]
    pub fn get_report(&self, id: u64) -> Option<&CrashReport> {
        self.reports.values().find(|r| r.id == id)
    }

    /// Iterate over all crash reports in dedup-key order.
    pub fn iter(&self) -> impl Iterator<Item = &CrashReport> {
        self.reports.values()
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// Mark a crash report as verified.
    pub fn mark_verified(&mut self, id: u64) {
        if let Some(report) = self.reports.values_mut().find(|r| r.id == id) {
            report.verified = true;
        }
    }

    /// Mark a crash report as minimized.
    pub fn mark_minimized(&mut self, id: u64) {
        if let Some(report) = self.reports.values_mut().find(|r| r.id == id) {
            report.minimized = true;
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    /// Generate a text summary of all triaged crashes.
    #[must_use]
    pub fn summary_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Crash Triage Summary\n\
             Total submitted : {}\n\
             Unique crashes  : {}\n\
             Duplicates      : {}\n\n",
            self.total_submitted,
            self.unique_count(),
            self.duplicate_count(),
        ));

        // Category breakdown.
        let mut cats: Vec<(CrashCategory, u64)> = self
            .category_counts
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();
        cats.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        out.push_str("By Category:\n");
        for (cat, count) in &cats {
            out.push_str(&format!("  {:30} {}\n", cat.name(), count));
        }
        out.push('\n');

        // Top 10 crashes by exploitability.
        out.push_str("Top Crashes (by exploitability):\n");
        for report in self.triaged_crashes().iter().take(10) {
            out.push_str(&format!(
                "  id={:<4} exploitability={}/5 hits={:<5} category={}\n",
                report.id,
                report.exploitability,
                report.hit_count,
                report.category.name()
            ));
        }

        out
    }
}

impl Default for CrashAnalyzer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ── Categorization logic ──────────────────────────────────────────────────────

/// Infer a [`CrashCategory`] from a [`CrashRecord`].
#[must_use]
pub fn categorize_crash(record: &CrashRecord) -> CrashCategory {
    // Signal-based primary classification.
    match record.signal {
        // SIGFPE
        8 => return CrashCategory::IntegerError,
        // SIGILL
        4 => return CrashCategory::IllegalInstruction,
        // SIGBUS
        7 => return CrashCategory::BusError,
        // SIGABRT
        6 => return CrashCategory::AssertionFailure,
        // SIGSEGV = 11
        11 => {}
        _ => return CrashCategory::Unknown,
    }

    // SIGSEGV heuristics based on fault address.
    if let Some(addr) = record.fault_addr {
        if addr < 0x1000 {
            return CrashCategory::NullDeref;
        }
        // Typical heap range on 64-bit Linux.
        if (0x0000_7f00_0000_0000..=0x0000_7fff_ffff_ffff).contains(&addr) {
            return CrashCategory::HeapCorruption;
        }
        // Typical stack range on 64-bit Linux.
        if (0x0000_7fff_0000_0000..=0x0000_7fff_ffff_ffff).contains(&addr) {
            return CrashCategory::StackOverflow;
        }
    }

    // Description-based heuristics.
    let desc = record.description.to_lowercase();
    if desc.contains("use-after-free") || desc.contains("uaf") {
        return CrashCategory::UseAfterFree;
    }
    if desc.contains("double-free") {
        return CrashCategory::DoubleFree;
    }
    if desc.contains("oob_write") || desc.contains("out-of-bounds write") {
        return CrashCategory::OutOfBoundsWrite;
    }
    if desc.contains("oob_read") || desc.contains("out-of-bounds read") {
        return CrashCategory::OutOfBoundsRead;
    }

    CrashCategory::Unknown
}

/// Compute a stack-frame hash from a crash record.
fn compute_stack_hash(record: &CrashRecord, depth: usize) -> u64 {
    if let Some(sh) = record.stack_hash {
        return sh;
    }
    // Fallback: hash (coverage_hash, signal, fault_addr).
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&record.coverage_hash.to_le_bytes());
    data.extend_from_slice(&(record.signal as u64).to_le_bytes());
    data.extend_from_slice(&record.fault_addr.unwrap_or(0).to_le_bytes());
    let _ = depth; // would be used if we had actual frames
    fnv1a(&data)
}

// ── CrashBucket ───────────────────────────────────────────────────────────────

/// A bucket that groups semantically similar crashes by category + signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashBucket {
    /// Category for all entries in this bucket.
    pub category: CrashCategory,
    /// Signal shared by all entries.
    pub signal: i32,
    /// Ids of crash reports in this bucket.
    pub report_ids: Vec<u64>,
    /// Combined hit count.
    pub total_hits: u64,
}

/// Deterministically sample at most `limit` reports from a slice using a
/// caller-provided [`FuzzRng`]. Used by the triage UI to display a
/// representative subset of large crash buckets without bias.
#[must_use]
pub fn sample_reports<'a>(
    reports: &[&'a CrashReport],
    limit: usize,
    rng: &mut FuzzRng,
) -> Vec<&'a CrashReport> {
    if reports.len() <= limit {
        return reports.to_vec();
    }
    let mut idx: Vec<usize> = (0..reports.len()).collect();
    // Fisher-Yates partial shuffle.
    for i in 0..limit {
        let j = i + rng.next_usize(idx.len() - i);
        idx.swap(i, j);
    }
    idx.into_iter().take(limit).map(|i| reports[i]).collect()
}

/// Group a list of crash reports into buckets by (category, signal).
#[must_use]
pub fn bucket_crashes(reports: &[&CrashReport]) -> Vec<CrashBucket> {
    let mut map: BTreeMap<(u64, i32), CrashBucket> = BTreeMap::new();
    for report in reports {
        let key = (report.category as u64, report.record.signal);
        let bucket = map.entry(key).or_insert_with(|| CrashBucket {
            category: report.category,
            signal: report.record.signal,
            report_ids: Vec::new(),
            total_hits: 0,
        });
        bucket.report_ids.push(report.id);
        bucket.total_hits += report.hit_count;
    }
    let mut buckets: Vec<CrashBucket> = map.into_values().collect();
    buckets.sort_unstable_by(|a, b| b.total_hits.cmp(&a.total_hits));
    buckets
}

// ── CrashTimeline ─────────────────────────────────────────────────────────────

/// Tracks when unique crashes were first seen over the course of a campaign.
#[derive(Debug, Clone, Default)]
pub struct CrashTimeline {
    /// (timestamp, `crash_report_id`) pairs in chronological order.
    pub events: Vec<(SystemTime, u64)>,
}

impl CrashTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new crash event.
    pub fn record(&mut self, report_id: u64) {
        self.events.push((SystemTime::now(), report_id));
    }

    /// Return the number of unique crashes found so far.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.events.len()
    }

    /// Return events within a given elapsed-seconds window.
    #[must_use]
    pub fn recent(&self, within_secs: u64) -> Vec<(SystemTime, u64)> {
        let cutoff = SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(within_secs))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.events
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .copied()
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CrashRecord;

    fn make_record(signal: i32, fault_addr: Option<u64>, coverage_hash: u64) -> CrashRecord {
        CrashRecord::new(0, vec![1, 2, 3], signal, fault_addr, coverage_hash)
    }

    #[test]
    fn categorize_sigsegv_null() {
        let record = make_record(11, Some(0x8), 0x1234);
        assert_eq!(categorize_crash(&record), CrashCategory::NullDeref);
    }

    #[test]
    fn categorize_sigfpe() {
        let record = make_record(8, None, 0xabcd);
        assert_eq!(categorize_crash(&record), CrashCategory::IntegerError);
    }

    #[test]
    fn categorize_sigill() {
        let record = make_record(4, None, 0x5678);
        assert_eq!(categorize_crash(&record), CrashCategory::IllegalInstruction);
    }

    #[test]
    fn submit_new_crash_returns_id() {
        let mut analyzer = CrashAnalyzer::with_defaults();
        let record = make_record(11, Some(0x10), 0xbeef);
        let id = analyzer.submit(record);
        assert!(id.is_some());
        assert_eq!(analyzer.unique_count(), 1);
    }

    #[test]
    fn submit_duplicate_returns_none() {
        let mut analyzer = CrashAnalyzer::with_defaults();
        let r1 = make_record(11, Some(0x10), 0xbeef);
        let r2 = make_record(11, Some(0x10), 0xbeef);
        analyzer.submit(r1);
        let dup = analyzer.submit(r2);
        assert!(dup.is_none());
        assert_eq!(analyzer.unique_count(), 1);
    }

    #[test]
    fn triaged_crashes_sorted_by_exploitability() {
        let mut analyzer = CrashAnalyzer::with_defaults();
        // SIGABRT = low exploitability
        analyzer.submit(make_record(6, None, 0x1));
        // SIGSEGV to heap = high exploitability
        analyzer.submit(make_record(11, Some(0x0000_7f10_0000_0000), 0x2));
        let triaged = analyzer.triaged_crashes();
        assert!(triaged[0].exploitability >= triaged[1].exploitability);
    }

    #[test]
    fn category_name_round_trip() {
        for &cat in CrashCategory::all() {
            assert!(!cat.name().is_empty());
        }
    }

    #[test]
    fn sanitizer_hint_parse_bug_type() {
        let report = "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n\
                      #0 0xabcd in foo\n\
                      #1 0x1234 in bar\n";
        let hint = SanitizerHint::parse(report);
        assert_eq!(hint.sanitizer.as_deref(), Some("AddressSanitizer"));
        assert!(hint.bug_type.as_deref().unwrap_or("").contains("heap-buffer-overflow"));
        assert_eq!(hint.frames.len(), 2);
    }

    #[test]
    fn sanitizer_hint_infer_category_heap() {
        let hint = SanitizerHint {
            raw: String::new(),
            bug_type: Some("heap-buffer-overflow".to_owned()),
            sanitizer: Some("AddressSanitizer".to_owned()),
            frames: vec![],
        };
        assert_eq!(hint.infer_category(), Some(CrashCategory::HeapCorruption));
    }

    #[test]
    fn bucket_crashes_groups_correctly() {
        let mut analyzer = CrashAnalyzer::with_defaults();
        analyzer.submit(make_record(11, Some(5), 0x1));
        analyzer.submit(make_record(8, None, 0x2));
        let triaged = analyzer.triaged_crashes();
        let buckets = bucket_crashes(&triaged);
        assert!(!buckets.is_empty());
    }

    #[test]
    fn crash_timeline_records_and_retrieves() {
        let mut timeline = CrashTimeline::new();
        timeline.record(0);
        timeline.record(1);
        assert_eq!(timeline.count(), 2);
        let recent = timeline.recent(10);
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn high_severity_filter() {
        let mut analyzer = CrashAnalyzer::with_defaults();
        analyzer.submit(make_record(6, None, 0x10));   // SIGABRT = low
        analyzer.submit(make_record(11, Some(0x0000_7f00_0000_1234), 0x20)); // heap = high
        let hs = analyzer.high_severity_crashes();
        assert!(hs.iter().all(|r| r.exploitability >= 3));
    }
}
