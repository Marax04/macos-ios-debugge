//! AFL analysis subsystem: crash analysis, hang analysis, coverage analysis,
//! queue analysis, statistics parsing, and the top-level `AflAnalysis` report.
//!
//! # Structs
//! - [`AflAnalysis`]       — top-level analysis coordinator
//! - [`CrashAnalyzer`]     — classifies and deduplicates AFL crash inputs
//! - [`HangAnalyzer`]      — categorises hang/timeout inputs
//! - [`CoverageAnalyzer`]  — computes coverage statistics from AFL bitmaps
//! - [`QueueAnalyzer`]     — processes AFL queue entries
//! - [`StatisticsParser`]  — parses `fuzzer_stats` files
//! - [`AflReport`]         — final combined report

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AflShmCoverage, AflStats};
// Re-export AFL-specific helpers so callers analysing crash/coverage
// output can construct the same auxiliary types this module produces.
pub use crate::RngCore;
pub use crate::{CmplogMap, ForkServer, PersistentMode, XorShiftRng};
use rustre_fuzz::fnv1a;
pub use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the AFL analysis subsystem.
#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("coverage error: {0}")]
    Coverage(String),
    #[error("crash error: {0}")]
    Crash(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("empty input")]
    Empty,
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashSeverity
// ─────────────────────────────────────────────────────────────────────────────

/// Exploitability / severity estimate for a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum CrashSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for CrashSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashKind
// ─────────────────────────────────────────────────────────────────────────────

/// Category of AFL crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CrashKind {
    Segfault,
    Abort,
    FloatingPoint,
    StackOverflow,
    HeapCorruption,
    IntegerOverflow,
    UseAfterFree,
    NullDereference,
    Timeout,
    UnknownSignal(i32),
}

impl CrashKind {
    /// Estimate severity from kind.
    #[must_use]
    pub const fn severity(&self) -> CrashSeverity {
        match self {
            Self::UseAfterFree | Self::HeapCorruption => CrashSeverity::Critical,
            Self::StackOverflow | Self::Segfault => CrashSeverity::High,
            Self::Abort | Self::NullDereference | Self::UnknownSignal(_) => CrashSeverity::Medium,
            Self::IntegerOverflow | Self::FloatingPoint => CrashSeverity::Low,
            Self::Timeout => CrashSeverity::Info,
        }
    }

    /// Derive kind from POSIX signal number.
    #[must_use]
    pub const fn from_signal(signal: i32) -> Self {
        match signal {
            11 => Self::Segfault,
            6 => Self::Abort,
            8 => Self::FloatingPoint,
            14 => Self::Timeout,
            _ => Self::UnknownSignal(signal),
        }
    }
}

impl std::fmt::Display for CrashKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Segfault => write!(f, "segfault"),
            Self::Abort => write!(f, "abort"),
            Self::FloatingPoint => write!(f, "fpe"),
            Self::StackOverflow => write!(f, "stack-overflow"),
            Self::HeapCorruption => write!(f, "heap-corruption"),
            Self::IntegerOverflow => write!(f, "int-overflow"),
            Self::UseAfterFree => write!(f, "use-after-free"),
            Self::NullDereference => write!(f, "null-deref"),
            Self::Timeout => write!(f, "timeout"),
            Self::UnknownSignal(n) => write!(f, "signal({n})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single crash entry produced by AFL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashEntry {
    /// Unique ID within the analysis session.
    pub id: u64,
    /// Raw crash bytes.
    pub data: Vec<u8>,
    /// FNV-1a hash of the data.
    pub hash: u64,
    /// Coverage bitmap hash (from AFL).
    pub coverage_hash: u64,
    /// Signal that killed the target.
    pub signal: i32,
    /// Derived crash kind.
    pub kind: CrashKind,
    /// Estimated severity.
    pub severity: CrashSeverity,
    /// When first seen.
    pub first_seen: SystemTime,
    /// How many times this crash was reproduced.
    pub occurrence_count: u64,
    /// Optional fault address.
    pub fault_addr: Option<u64>,
    /// Minimised input, if available.
    pub minimised: Option<Vec<u8>>,
    /// Human-readable description.
    pub description: String,
}

impl CrashEntry {
    /// Create a new crash entry.
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, signal: i32, coverage_hash: u64) -> Self {
        let hash = fnv1a(&data);
        let kind = CrashKind::from_signal(signal);
        let severity = kind.severity();
        let description = format!("signal={signal} cov={coverage_hash:016x}");
        Self {
            id,
            data,
            hash,
            coverage_hash,
            signal,
            kind,
            severity,
            first_seen: SystemTime::now(),
            occurrence_count: 1,
            fault_addr: None,
            minimised: None,
            description,
        }
    }

    /// Deduplication key (coverage hash, or data hash if no coverage).
    #[must_use]
    pub const fn dedup_key(&self) -> u64 {
        if self.coverage_hash != 0 {
            self.coverage_hash
        } else {
            self.hash
        }
    }

    /// Set a fault address.
    pub const fn set_fault_addr(&mut self, addr: u64) {
        self.fault_addr = Some(addr);
    }

    /// Set a minimised version of the crash input.
    pub fn set_minimised(&mut self, data: Vec<u8>) {
        self.minimised = Some(data);
    }

    /// Returns the minimised data if available, otherwise the original.
    #[must_use]
    pub fn effective_data(&self) -> &[u8] {
        self.minimised.as_deref().unwrap_or(&self.data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies and deduplicates AFL crash inputs.
#[derive(Debug, Default)]
pub struct CrashAnalyzer {
    /// All crashes, keyed by dedup key.
    crashes: HashMap<u64, CrashEntry>,
    /// Insertion order.
    order: Vec<u64>,
    /// Next id.
    next_id: u64,
    /// Coverage hashes of known crashes.
    known_hashes: HashSet<u64>,
}

impl CrashAnalyzer {
    /// Create an empty analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new crash.  Returns `true` if novel (new dedup key).
    pub fn submit(&mut self, data: Vec<u8>, signal: i32, coverage_hash: u64) -> bool {
        let id = self.next_id;
        self.next_id += 1;
        let entry = CrashEntry::new(id, data, signal, coverage_hash);
        let key = entry.dedup_key();
        if let Some(existing) = self.crashes.get_mut(&key) {
            existing.occurrence_count += 1;
            return false;
        }
        self.known_hashes.insert(key);
        self.order.push(key);
        self.crashes.insert(key, entry);
        true
    }

    /// Number of unique crashes.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.crashes.len()
    }

    /// All unique crashes in insertion order.
    #[must_use]
    pub fn all_crashes(&self) -> Vec<&CrashEntry> {
        self.order
            .iter()
            .filter_map(|k| self.crashes.get(k))
            .collect()
    }

    /// Crashes by severity (descending).
    #[must_use]
    pub fn by_severity(&self) -> Vec<&CrashEntry> {
        let mut v: Vec<&CrashEntry> = self.crashes.values().collect();
        v.sort_unstable_by(|a, b| b.severity.cmp(&a.severity));
        v
    }

    /// Crashes with at least `severity`.
    #[must_use]
    pub fn at_least(&self, severity: CrashSeverity) -> Vec<&CrashEntry> {
        self.crashes
            .values()
            .filter(|c| c.severity >= severity)
            .collect()
    }

    /// Returns `true` if `coverage_hash` is already known.
    #[must_use]
    pub fn is_known(&self, coverage_hash: u64) -> bool {
        self.known_hashes.contains(&coverage_hash)
    }

    /// Clear all crashes.
    pub fn clear(&mut self) {
        self.crashes.clear();
        self.order.clear();
        self.known_hashes.clear();
    }

    /// Severity distribution: kind → count.
    #[must_use]
    pub fn severity_distribution(&self) -> HashMap<CrashSeverity, usize> {
        let mut map: HashMap<CrashSeverity, usize> = HashMap::new();
        for c in self.crashes.values() {
            *map.entry(c.severity).or_insert(0) += 1;
        }
        map
    }

    /// Most common crash kind.
    #[must_use]
    pub fn most_common_kind(&self) -> Option<CrashKind> {
        let mut counts: HashMap<String, (CrashKind, usize)> = HashMap::new();
        for c in self.crashes.values() {
            let key = c.kind.to_string();
            let e = counts.entry(key).or_insert_with(|| (c.kind.clone(), 0));
            e.1 += 1;
        }
        counts.into_values().max_by_key(|(_, n)| *n).map(|(k, _)| k)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HangEntry
// ─────────────────────────────────────────────────────────────────────────────

/// An input that caused a hang / timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HangEntry {
    pub id: u64,
    pub data: Vec<u8>,
    pub hash: u64,
    pub timeout_ms: u64,
    pub first_seen: SystemTime,
    pub occurrence_count: u64,
    pub coverage_hash: u64,
}

impl HangEntry {
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, timeout_ms: u64, coverage_hash: u64) -> Self {
        let hash = fnv1a(&data);
        Self {
            id,
            data,
            hash,
            timeout_ms,
            first_seen: SystemTime::now(),
            occurrence_count: 1,
            coverage_hash,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HangAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Categorises hang/timeout inputs.
#[derive(Debug, Default)]
pub struct HangAnalyzer {
    hangs: HashMap<u64, HangEntry>,
    next_id: u64,
    /// Total hangs submitted (including duplicates).
    pub total_submitted: u64,
}

impl HangAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a hang.  Returns `true` if novel.
    pub fn submit(&mut self, data: Vec<u8>, timeout_ms: u64, coverage_hash: u64) -> bool {
        self.total_submitted += 1;
        let hash = fnv1a(&data);
        if let Some(e) = self.hangs.get_mut(&hash) {
            e.occurrence_count += 1;
            return false;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.hangs
            .insert(hash, HangEntry::new(id, data, timeout_ms, coverage_hash));
        true
    }

    /// Number of unique hangs.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.hangs.len()
    }

    /// All unique hangs sorted by timeout (descending).
    #[must_use]
    pub fn sorted_by_timeout(&self) -> Vec<&HangEntry> {
        let mut v: Vec<&HangEntry> = self.hangs.values().collect();
        v.sort_unstable_by(|a, b| b.timeout_ms.cmp(&a.timeout_ms));
        v
    }

    /// Average timeout across all unique hangs.
    #[must_use]
    pub fn avg_timeout_ms(&self) -> f64 {
        if self.hangs.is_empty() {
            return 0.0;
        }
        let total: u64 = self.hangs.values().map(|h| h.timeout_ms).sum();
        f64::from(u32::try_from(total).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.hangs.len()).unwrap_or(u32::MAX))
    }

    /// Duplicate rate: (total - unique) / total.
    #[must_use]
    pub fn duplicate_rate(&self) -> f64 {
        if self.total_submitted == 0 {
            return 0.0;
        }
        let unique = self.hangs.len() as u64;
        f64::from(u32::try_from(self.total_submitted - unique).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_submitted).unwrap_or(u32::MAX))
    }

    pub fn clear(&mut self) {
        self.hangs.clear();
        self.total_submitted = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageSnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A point-in-time coverage measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    /// When this snapshot was taken.
    pub timestamp: SystemTime,
    /// Number of covered edges.
    pub covered_edges: usize,
    /// Total executions when snapshot was taken.
    pub total_executions: u64,
    /// Bitmap hash.
    pub bitmap_hash: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// CoverageAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Computes coverage statistics from AFL bitmaps.
#[derive(Debug)]
pub struct CoverageAnalyzer {
    /// Global accumulated bitmap.
    pub global_bitmap: AflShmCoverage,
    /// Snapshots over time.
    pub snapshots: Vec<CoverageSnapshot>,
    /// Total executions fed into this analyzer.
    pub total_executions: u64,
    /// Number of bitmaps processed.
    pub bitmap_count: u64,
    /// Peak covered edges across all snapshots.
    pub peak_covered: usize,
}

impl CoverageAnalyzer {
    /// Create an analyzer for an AFL bitmap of `size` bytes.
    ///
    /// `size` is capped at 16 MiB to prevent dos-memory-exhaustion when the
    /// caller derives `size` from untrusted input (e.g. a parsed stats file).
    #[must_use]
    pub fn new(size: usize) -> Self {
        // dos-memory-exhaustion: an untrusted size could allocate gigabytes.
        // AFL's own maximum map size is 8 MiB; 16 MiB is a generous upper bound.
        const MAX_BITMAP_BYTES: usize = 16 * 1024 * 1024;
        let size = size.min(MAX_BITMAP_BYTES);
        Self {
            global_bitmap: AflShmCoverage::new(size),
            snapshots: Vec::new(),
            total_executions: 0,
            bitmap_count: 0,
            peak_covered: 0,
        }
    }

    /// Merge a new run's bitmap into the global coverage.
    ///
    /// Returns the number of newly covered bytes.
    pub fn add_run(&mut self, bitmap: &[u8], executions: u64) -> usize {
        let new_bytes = self.global_bitmap.merge(bitmap);
        self.total_executions += executions;
        self.bitmap_count += 1;
        let covered = self.global_bitmap.count_non_zero();
        if covered > self.peak_covered {
            self.peak_covered = covered;
        }
        self.snapshot();
        new_bytes
    }

    /// Take a coverage snapshot.
    pub fn snapshot(&mut self) {
        self.snapshots.push(CoverageSnapshot {
            timestamp: SystemTime::now(),
            covered_edges: self.global_bitmap.count_non_zero(),
            total_executions: self.total_executions,
            bitmap_hash: self.global_bitmap.hash(),
        });
    }

    /// Coverage density: covered / `total_bytes`.
    #[must_use]
    pub fn density(&self) -> f64 {
        let total = self.global_bitmap.size;
        if total == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.global_bitmap.count_non_zero()).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// Coverage growth rate: peak / `total_executions` * 1e6.
    #[must_use]
    pub fn growth_rate(&self) -> f64 {
        if self.total_executions == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.peak_covered).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_executions).unwrap_or(u32::MAX)) * 1_000_000.0
    }

    /// Bucketted coverage count (AFL-style).
    #[must_use]
    pub fn bucketed_count(&self) -> usize {
        self.global_bitmap
            .bucketed()
            .iter()
            .filter(|&&b| b > 0)
            .count()
    }

    /// Clear all coverage data.
    pub fn clear(&mut self) {
        self.global_bitmap.clear();
        self.snapshots.clear();
        self.total_executions = 0;
        self.bitmap_count = 0;
        self.peak_covered = 0;
    }

    /// Coverage progression: list of (`execution_count`, `covered_edges`) tuples.
    #[must_use]
    pub fn progression(&self) -> Vec<(u64, usize)> {
        self.snapshots
            .iter()
            .map(|s| (s.total_executions, s.covered_edges))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QueueEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A queue entry analysed from the AFL queue directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: u64,
    pub data: Vec<u8>,
    pub hash: u64,
    pub coverage_bits: u32,
    pub exec_time_us: u64,
    pub selected_count: u64,
    pub interesting_count: u64,
    pub is_favored: bool,
    pub is_minimised: bool,
    pub discovered_at: SystemTime,
}

impl QueueEntry {
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, coverage_bits: u32, exec_time_us: u64) -> Self {
        let hash = fnv1a(&data);
        Self {
            id,
            data,
            hash,
            coverage_bits,
            exec_time_us,
            selected_count: 0,
            interesting_count: 0,
            is_favored: false,
            is_minimised: false,
            discovered_at: SystemTime::now(),
        }
    }

    /// Score used by the power schedule (higher = more mutations).
    #[must_use]
    pub fn score(&self) -> f64 {
        if self.selected_count == 0 {
            return f64::MAX;
        }
        let ir = f64::from(u32::try_from(self.interesting_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.selected_count).unwrap_or(u32::MAX));
        let tf = if self.exec_time_us == 0 {
            10.0
        } else {
            10_000.0 / f64::from(u32::try_from(self.exec_time_us).unwrap_or(u32::MAX))
        };
        (1.0 + ir) * tf * f64::from(self.coverage_bits)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QueueAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Processes AFL queue entries to surface insights.
#[derive(Debug, Default)]
pub struct QueueAnalyzer {
    pub entries: Vec<QueueEntry>,
    seen_hashes: HashSet<u64>,
}

impl QueueAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a queue entry.  Returns `false` if already seen (by data hash).
    pub fn add(&mut self, entry: QueueEntry) -> bool {
        if !self.seen_hashes.insert(entry.hash) {
            return false;
        }
        self.entries.push(entry);
        true
    }

    /// Top-N entries by score.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<&QueueEntry> {
        let mut v: Vec<&QueueEntry> = self.entries.iter().collect();
        v.sort_unstable_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v.truncate(n);
        v
    }

    /// Favored entries.
    #[must_use]
    pub fn favored(&self) -> Vec<&QueueEntry> {
        self.entries.iter().filter(|e| e.is_favored).collect()
    }

    /// Average coverage bits per entry.
    #[must_use]
    pub fn avg_coverage_bits(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.entries.iter().map(|e| u64::from(e.coverage_bits)).sum();
        f64::from(u32::try_from(sum).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.entries.len()).unwrap_or(u32::MAX))
    }

    /// Average execution time in microseconds.
    #[must_use]
    pub fn avg_exec_time_us(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.entries.iter().map(|e| e.exec_time_us).sum();
        f64::from(u32::try_from(sum).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.entries.len()).unwrap_or(u32::MAX))
    }

    /// Total unique entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Prune entries with coverage below `min_bits`.
    pub fn prune(&mut self, min_bits: u32) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.coverage_bits >= min_bits);
        before - self.entries.len()
    }

    /// Select favored set using greedy set-cover by coverage bits.
    pub fn compute_favorites(&mut self) {
        let mut covered_bits: HashSet<u32> = HashSet::new();
        let mut ids: Vec<usize> = (0..self.entries.len()).collect();
        ids.sort_unstable_by(|&a, &b| {
            self.entries[b]
                .coverage_bits
                .cmp(&self.entries[a].coverage_bits)
        });
        for i in 0..self.entries.len() {
            self.entries[i].is_favored = false;
        }
        for idx in ids {
            let bits = self.entries[idx].coverage_bits;
            if bits == 0 {
                continue;
            }
            if covered_bits.insert(bits) {
                self.entries[idx].is_favored = true;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StatisticsParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses and enriches `fuzzer_stats` files.
#[derive(Debug, Default)]
pub struct StatisticsParser {
    /// Parsed snapshots in order.
    pub snapshots: Vec<AflStats>,
}

impl StatisticsParser {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and store a `fuzzer_stats` text snapshot.
    ///
    /// # Errors
    /// Returns [`AnalysisError::Parse`] on malformed input.
    ///
    /// # Panics
    /// Panics if the internal snapshot list is unexpectedly empty after a push (should never happen).
    pub fn parse_snapshot(&mut self, text: &str) -> Result<&AflStats, AnalysisError> {
        let stats = AflStats::parse(text).map_err(|e| AnalysisError::Parse(e.to_string()))?;
        self.snapshots.push(stats);
        Ok(self.snapshots.last().unwrap())
    }

    /// Latest snapshot.
    #[must_use]
    pub fn latest(&self) -> Option<&AflStats> {
        self.snapshots.last()
    }

    /// Number of snapshots.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Executions-per-second trend: vec of (`snapshot_index`, `execs_per_sec`).
    #[must_use]
    pub fn exec_trend(&self) -> Vec<(usize, f64)> {
        self.snapshots
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.execs_per_sec))
            .collect()
    }

    /// Max executions across all snapshots.
    #[must_use]
    pub fn max_executions(&self) -> u64 {
        self.snapshots
            .iter()
            .map(|s| s.execs_done)
            .max()
            .unwrap_or(0)
    }

    /// Latest crash count.
    #[must_use]
    pub fn latest_crashes(&self) -> u64 {
        self.latest().map_or(0, |s| s.crashes_found)
    }

    /// Latest stability percentage.
    #[must_use]
    pub fn latest_stability(&self) -> f64 {
        self.latest().map_or(0.0, |s| s.stability)
    }

    /// Average stability across all snapshots.
    #[must_use]
    pub fn avg_stability(&self) -> f64 {
        if self.snapshots.is_empty() {
            return 0.0;
        }
        self.snapshots.iter().map(|s| s.stability).sum::<f64>() / f64::from(u32::try_from(self.snapshots.len()).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AflReport
// ─────────────────────────────────────────────────────────────────────────────

/// Final combined AFL analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AflReport {
    /// Campaign target.
    pub target: String,
    /// When generated.
    pub generated_at: SystemTime,
    /// Total executions.
    pub total_executions: u64,
    /// Total unique crashes.
    pub unique_crashes: usize,
    /// Total unique hangs.
    pub unique_hangs: usize,
    /// Coverage density [0, 1].
    pub coverage_density: f64,
    /// Number of queue entries.
    pub queue_size: usize,
    /// AFL stats from the latest snapshot.
    pub latest_stats: Option<AflStats>,
    /// Severity distribution.
    pub severity_dist: HashMap<String, usize>,
    /// Top-5 crash descriptions.
    pub top_crashes: Vec<String>,
    /// Notes.
    pub notes: String,
}

impl AflReport {
    /// Build an `AflReport` from the component analyzers.
    #[must_use]
    pub fn build(
        target: impl Into<String>,
        crash_analyzer: &CrashAnalyzer,
        hang_analyzer: &HangAnalyzer,
        cov_analyzer: &CoverageAnalyzer,
        queue_analyzer: &QueueAnalyzer,
        stats_parser: &StatisticsParser,
    ) -> Self {
        let severity_dist: HashMap<String, usize> = crash_analyzer
            .severity_distribution()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        let top_crashes: Vec<String> = crash_analyzer
            .by_severity()
            .iter()
            .take(5)
            .map(|c| c.description.clone())
            .collect();

        Self {
            target: target.into(),
            generated_at: SystemTime::now(),
            total_executions: cov_analyzer.total_executions,
            unique_crashes: crash_analyzer.unique_count(),
            unique_hangs: hang_analyzer.unique_count(),
            coverage_density: cov_analyzer.density(),
            queue_size: queue_analyzer.len(),
            latest_stats: stats_parser.latest().cloned(),
            severity_dist,
            top_crashes,
            notes: String::new(),
        }
    }

    /// Overall health score [0.0, 1.0]: higher = fewer crashes, better coverage.
    #[must_use]
    pub fn health_score(&self) -> f64 {
        let crash_penalty = (f64::from(u32::try_from(self.unique_crashes).unwrap_or(u32::MAX)) * 0.01).min(0.5);
        let cov_bonus = self.coverage_density.min(1.0) * 0.5;
        (1.0 - crash_penalty + cov_bonus).clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AflAnalysis  (top-level coordinator)
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level AFL analysis coordinator.
pub struct AflAnalysis {
    /// Target identifier.
    pub target: String,
    /// Crash analyzer.
    pub crash_analyzer: CrashAnalyzer,
    /// Hang analyzer.
    pub hang_analyzer: HangAnalyzer,
    /// Coverage analyzer.
    pub coverage_analyzer: CoverageAnalyzer,
    /// Queue analyzer.
    pub queue_analyzer: QueueAnalyzer,
    /// Statistics parser.
    pub stats_parser: StatisticsParser,
}

impl AflAnalysis {
    /// Create a new analysis session.
    #[must_use]
    pub fn new(target: impl Into<String>, bitmap_size: usize) -> Self {
        Self {
            target: target.into(),
            crash_analyzer: CrashAnalyzer::new(),
            hang_analyzer: HangAnalyzer::new(),
            coverage_analyzer: CoverageAnalyzer::new(bitmap_size),
            queue_analyzer: QueueAnalyzer::new(),
            stats_parser: StatisticsParser::new(),
        }
    }

    /// Process a crash input.  Returns `true` if novel.
    pub fn ingest_crash(&mut self, data: Vec<u8>, signal: i32, coverage_hash: u64) -> bool {
        self.crash_analyzer.submit(data, signal, coverage_hash)
    }

    /// Process a hang input.  Returns `true` if novel.
    pub fn ingest_hang(&mut self, data: Vec<u8>, timeout_ms: u64, coverage_hash: u64) -> bool {
        self.hang_analyzer.submit(data, timeout_ms, coverage_hash)
    }

    /// Process a coverage bitmap.
    pub fn ingest_bitmap(&mut self, bitmap: &[u8], executions: u64) -> usize {
        // add_run already calls snapshot() internally; calling it again here
        // would record a duplicate snapshot per bitmap ingestion, inflating
        // progression() output and growth_rate() calculations.
        self.coverage_analyzer.add_run(bitmap, executions)
    }

    /// Parse a `fuzzer_stats` text file.
    ///
    /// # Errors
    /// Returns [`AnalysisError::Parse`] on failure.
    pub fn ingest_stats(&mut self, text: &str) -> Result<(), AnalysisError> {
        self.stats_parser.parse_snapshot(text)?;
        Ok(())
    }

    /// Add a queue entry.
    pub fn ingest_queue_entry(&mut self, data: Vec<u8>, coverage_bits: u32, exec_us: u64) {
        let id = self.queue_analyzer.len() as u64;
        let entry = QueueEntry::new(id, data, coverage_bits, exec_us);
        self.queue_analyzer.add(entry);
    }

    /// Build the final report.
    #[must_use]
    pub fn report(&self) -> AflReport {
        AflReport::build(
            &self.target,
            &self.crash_analyzer,
            &self.hang_analyzer,
            &self.coverage_analyzer,
            &self.queue_analyzer,
            &self.stats_parser,
        )
    }

    /// Reset all analyzers.
    pub fn reset(&mut self) {
        self.crash_analyzer.clear();
        self.hang_analyzer.clear();
        self.coverage_analyzer.clear();
        self.queue_analyzer = QueueAnalyzer::new();
        self.stats_parser = StatisticsParser::new();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CrashKind ─────────────────────────────────────────────────────────────

    #[test]
    fn crash_kind_from_signal() {
        assert_eq!(CrashKind::from_signal(11), CrashKind::Segfault);
        assert_eq!(CrashKind::from_signal(6), CrashKind::Abort);
        assert_eq!(CrashKind::from_signal(8), CrashKind::FloatingPoint);
        assert_eq!(CrashKind::from_signal(99), CrashKind::UnknownSignal(99));
    }

    #[test]
    fn crash_kind_severity() {
        assert_eq!(CrashKind::UseAfterFree.severity(), CrashSeverity::Critical);
        assert_eq!(CrashKind::Segfault.severity(), CrashSeverity::High);
        assert_eq!(CrashKind::Abort.severity(), CrashSeverity::Medium);
        assert_eq!(CrashKind::Timeout.severity(), CrashSeverity::Info);
    }

    #[test]
    fn crash_severity_ordering() {
        assert!(CrashSeverity::Critical > CrashSeverity::High);
        assert!(CrashSeverity::High > CrashSeverity::Medium);
        assert!(CrashSeverity::Medium > CrashSeverity::Low);
        assert!(CrashSeverity::Low > CrashSeverity::Info);
    }

    // ── CrashEntry ────────────────────────────────────────────────────────────

    #[test]
    fn crash_entry_new() {
        let e = CrashEntry::new(0, vec![0xCC], 11, 0xAABB);
        assert_eq!(e.signal, 11);
        assert_eq!(e.kind, CrashKind::Segfault);
        assert_eq!(e.severity, CrashSeverity::High);
    }

    #[test]
    fn crash_entry_dedup_key_prefers_coverage_hash() {
        let e = CrashEntry::new(0, vec![1, 2], 11, 0x12345678);
        assert_eq!(e.dedup_key(), 0x12345678);
    }

    #[test]
    fn crash_entry_dedup_key_uses_data_hash_if_zero() {
        let e = CrashEntry::new(0, vec![1], 11, 0);
        assert_ne!(e.dedup_key(), 0);
    }

    #[test]
    fn crash_entry_effective_data_prefers_minimised() {
        let mut e = CrashEntry::new(0, vec![1, 2, 3, 4], 11, 0);
        e.set_minimised(vec![1]);
        assert_eq!(e.effective_data(), &[1]);
    }

    #[test]
    fn crash_entry_effective_data_original_if_no_min() {
        let e = CrashEntry::new(0, vec![1, 2], 11, 0);
        assert_eq!(e.effective_data(), &[1, 2]);
    }

    // ── CrashAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn crash_analyzer_submit_novel() {
        let mut a = CrashAnalyzer::new();
        assert!(a.submit(vec![1], 11, 0x1111));
        assert_eq!(a.unique_count(), 1);
    }

    #[test]
    fn crash_analyzer_submit_duplicate() {
        let mut a = CrashAnalyzer::new();
        a.submit(vec![1], 11, 0x1111);
        assert!(!a.submit(vec![2], 11, 0x1111)); // same cov hash
        assert_eq!(a.unique_count(), 1);
    }

    #[test]
    fn crash_analyzer_by_severity_ordering() {
        let mut a = CrashAnalyzer::new();
        a.submit(vec![1], 11, 0x1111); // Segfault → High
        a.submit(vec![2], 14, 0x2222); // Timeout  → Info
        let sorted = a.by_severity();
        assert!(sorted[0].severity >= sorted[1].severity);
    }

    #[test]
    fn crash_analyzer_at_least() {
        let mut a = CrashAnalyzer::new();
        a.submit(vec![1], 11, 0x1111); // High
        a.submit(vec![2], 6, 0x2222); // Medium
        assert_eq!(a.at_least(CrashSeverity::High).len(), 1);
    }

    #[test]
    fn crash_analyzer_is_known() {
        let mut a = CrashAnalyzer::new();
        a.submit(vec![1], 11, 0xABCD);
        assert!(a.is_known(0xABCD));
        assert!(!a.is_known(0x0000));
    }

    #[test]
    fn crash_analyzer_severity_distribution() {
        let mut a = CrashAnalyzer::new();
        a.submit(vec![1], 11, 0x0001);
        a.submit(vec![2], 11, 0x0002);
        a.submit(vec![3], 6, 0x0003);
        let dist = a.severity_distribution();
        assert!(dist.values().sum::<usize>() >= 3);
    }

    #[test]
    fn crash_analyzer_clear() {
        let mut a = CrashAnalyzer::new();
        a.submit(vec![1], 11, 0x1);
        a.clear();
        assert_eq!(a.unique_count(), 0);
    }

    // ── HangAnalyzer ──────────────────────────────────────────────────────────

    #[test]
    fn hang_analyzer_submit_novel() {
        let mut a = HangAnalyzer::new();
        assert!(a.submit(vec![1, 2], 1000, 0));
        assert_eq!(a.unique_count(), 1);
    }

    #[test]
    fn hang_analyzer_submit_duplicate() {
        let mut a = HangAnalyzer::new();
        a.submit(vec![1], 1000, 0);
        assert!(!a.submit(vec![1], 2000, 0)); // same data hash
        assert_eq!(a.unique_count(), 1);
        assert_eq!(a.total_submitted, 2);
    }

    #[test]
    fn hang_analyzer_avg_timeout() {
        let mut a = HangAnalyzer::new();
        a.submit(vec![1], 1000, 0);
        a.submit(vec![2], 3000, 0);
        let avg = a.avg_timeout_ms();
        assert!((avg - 2000.0).abs() < 1e-9);
    }

    #[test]
    fn hang_analyzer_duplicate_rate() {
        let mut a = HangAnalyzer::new();
        a.submit(vec![1], 1000, 0);
        a.submit(vec![1], 1000, 0); // dup
        assert!((a.duplicate_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn hang_analyzer_clear() {
        let mut a = HangAnalyzer::new();
        a.submit(vec![1], 100, 0);
        a.clear();
        assert_eq!(a.unique_count(), 0);
        assert_eq!(a.total_submitted, 0);
    }

    // ── CoverageAnalyzer ──────────────────────────────────────────────────────

    #[test]
    fn coverage_analyzer_add_run_new_bytes() {
        let mut a = CoverageAnalyzer::new(4);
        let bitmap = vec![0x01u8, 0, 0, 0];
        let new = a.add_run(&bitmap, 100);
        assert_eq!(new, 1);
    }

    #[test]
    fn coverage_analyzer_density() {
        let mut a = CoverageAnalyzer::new(4);
        a.add_run(&[0xFF, 0, 0, 0], 100);
        assert!(a.density() > 0.0 && a.density() <= 1.0);
    }

    #[test]
    fn coverage_analyzer_snapshot() {
        let mut a = CoverageAnalyzer::new(4);
        a.add_run(&[0x01], 10);
        a.snapshot();
        assert_eq!(a.snapshots.len(), 2); // add_run auto-snapshots + manual
    }

    #[test]
    fn coverage_analyzer_clear() {
        let mut a = CoverageAnalyzer::new(4);
        a.add_run(&[0xFF, 0xFF, 0xFF, 0xFF], 100);
        a.clear();
        assert_eq!(a.total_executions, 0);
        assert_eq!(a.peak_covered, 0);
    }

    #[test]
    fn coverage_analyzer_growth_rate() {
        let mut a = CoverageAnalyzer::new(4);
        a.add_run(&[0xFF, 0xFF, 0xFF, 0xFF], 1_000_000);
        assert!(a.growth_rate() >= 0.0);
    }

    #[test]
    fn coverage_analyzer_progression() {
        let mut a = CoverageAnalyzer::new(4);
        a.add_run(&[0x01], 100);
        a.add_run(&[0x02], 200);
        let prog = a.progression();
        assert!(prog.len() >= 2);
    }

    // ── QueueEntry ────────────────────────────────────────────────────────────

    #[test]
    fn queue_entry_score_untried() {
        let e = QueueEntry::new(0, vec![1], 10, 100);
        assert_eq!(e.score(), f64::MAX);
    }

    #[test]
    fn queue_entry_score_tried() {
        let mut e = QueueEntry::new(0, vec![1], 10, 100);
        e.selected_count = 5;
        e.interesting_count = 2;
        assert!(e.score() > 0.0);
    }

    // ── QueueAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn queue_analyzer_add_unique() {
        let mut a = QueueAnalyzer::new();
        assert!(a.add(QueueEntry::new(0, vec![1], 10, 100)));
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn queue_analyzer_add_duplicate() {
        let mut a = QueueAnalyzer::new();
        a.add(QueueEntry::new(0, vec![1], 10, 100));
        assert!(!a.add(QueueEntry::new(1, vec![1], 20, 200))); // same data
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn queue_analyzer_avg_coverage_bits() {
        let mut a = QueueAnalyzer::new();
        a.add(QueueEntry::new(0, vec![1], 10, 100));
        a.add(QueueEntry::new(1, vec![2], 20, 100));
        assert!((a.avg_coverage_bits() - 15.0).abs() < 1e-9);
    }

    #[test]
    fn queue_analyzer_prune() {
        let mut a = QueueAnalyzer::new();
        a.add(QueueEntry::new(0, vec![1], 5, 100));
        a.add(QueueEntry::new(1, vec![2], 20, 100));
        let removed = a.prune(10);
        assert_eq!(removed, 1);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn queue_analyzer_compute_favorites() {
        let mut a = QueueAnalyzer::new();
        a.add(QueueEntry::new(0, vec![1], 10, 100));
        a.add(QueueEntry::new(1, vec![2], 10, 100));
        a.add(QueueEntry::new(2, vec![3], 20, 100));
        a.compute_favorites();
        let favored_count = a.entries.iter().filter(|e| e.is_favored).count();
        assert!(favored_count >= 1);
    }

    // ── StatisticsParser ──────────────────────────────────────────────────────

    #[test]
    fn stats_parser_snapshot() {
        let text =
            "start_time : 1000\nexecs_done : 5000\nexecs_per_sec : 100.00\nstability : 99.00%\n";
        let mut p = StatisticsParser::new();
        p.parse_snapshot(text).unwrap();
        assert_eq!(p.snapshot_count(), 1);
        assert_eq!(p.max_executions(), 5000);
    }

    #[test]
    fn stats_parser_latest_crashes() {
        let text = "crashes_found : 42\n";
        let mut p = StatisticsParser::new();
        p.parse_snapshot(text).unwrap();
        assert_eq!(p.latest_crashes(), 42);
    }

    #[test]
    fn stats_parser_exec_trend() {
        let mut p = StatisticsParser::new();
        p.parse_snapshot("execs_per_sec : 100.0\n").unwrap();
        p.parse_snapshot("execs_per_sec : 200.0\n").unwrap();
        let trend = p.exec_trend();
        assert_eq!(trend.len(), 2);
    }

    #[test]
    fn stats_parser_avg_stability() {
        let mut p = StatisticsParser::new();
        p.parse_snapshot("stability : 90.00%\n").unwrap();
        p.parse_snapshot("stability : 80.00%\n").unwrap();
        assert!((p.avg_stability() - 85.0).abs() < 1e-9);
    }

    // ── AflReport ─────────────────────────────────────────────────────────────

    #[test]
    fn afl_report_build() {
        let ca = CrashAnalyzer::new();
        let ha = HangAnalyzer::new();
        let cov = CoverageAnalyzer::new(4);
        let qa = QueueAnalyzer::new();
        let sp = StatisticsParser::new();
        let r = AflReport::build("target", &ca, &ha, &cov, &qa, &sp);
        assert_eq!(r.unique_crashes, 0);
        assert_eq!(r.unique_hangs, 0);
    }

    #[test]
    fn afl_report_health_score_no_crashes() {
        let ca = CrashAnalyzer::new();
        let ha = HangAnalyzer::new();
        let cov = CoverageAnalyzer::new(4);
        let qa = QueueAnalyzer::new();
        let sp = StatisticsParser::new();
        let r = AflReport::build("t", &ca, &ha, &cov, &qa, &sp);
        assert!(r.health_score() >= 0.0 && r.health_score() <= 1.0);
    }

    // ── AflAnalysis ───────────────────────────────────────────────────────────

    #[test]
    fn afl_analysis_ingest_crash() {
        let mut a = AflAnalysis::new("target", AflShmCoverage::AFL_MAP_SIZE);
        assert!(a.ingest_crash(vec![0xCC], 11, 0x1234));
        assert_eq!(a.crash_analyzer.unique_count(), 1);
    }

    #[test]
    fn afl_analysis_ingest_hang() {
        let mut a = AflAnalysis::new("target", 64);
        assert!(a.ingest_hang(vec![1, 2], 5000, 0));
        assert_eq!(a.hang_analyzer.unique_count(), 1);
    }

    #[test]
    fn afl_analysis_ingest_bitmap() {
        let mut a = AflAnalysis::new("target", 4);
        let new = a.ingest_bitmap(&[0x01, 0, 0, 0], 1000);
        assert_eq!(new, 1);
    }

    #[test]
    fn afl_analysis_ingest_stats() {
        let mut a = AflAnalysis::new("target", 4);
        a.ingest_stats("execs_done : 1000\n").unwrap();
        assert_eq!(a.stats_parser.max_executions(), 1000);
    }

    #[test]
    fn afl_analysis_report() {
        let mut a = AflAnalysis::new("my-target", 64);
        a.ingest_crash(vec![1], 11, 0xABCD);
        let r = a.report();
        assert_eq!(r.target, "my-target");
        assert_eq!(r.unique_crashes, 1);
    }

    #[test]
    fn afl_analysis_reset() {
        let mut a = AflAnalysis::new("t", 64);
        a.ingest_crash(vec![1], 11, 0x01);
        a.reset();
        assert_eq!(a.crash_analyzer.unique_count(), 0);
    }
}
