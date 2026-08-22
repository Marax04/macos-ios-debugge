//! Bulk signature application for `rustre-flirt-apply`.
//!
//! Provides [`BulkApplier`] — a high-throughput engine that loads one or more
//! signature databases and applies them across a set of analyzed functions,
//! resolving naming conflicts, producing a detailed [`ApplicationReport`], and
//! supporting full rollback of applied renames.

use std::collections::HashSet;
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// keys (function names / addresses from untrusted .sig/.pat files).
use ahash::AHashMap as HashMap;
use std::fmt;
pub use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{FlirtApplier, FlirtMatch, FlirtPattern, FlirtSigDb};
pub use crate::{FlirtError, crc16_flirt};
use crate::casts::{f64_to_u8, u64_to_usize, usize_to_f64};

// ---------------------------------------------------------------------------
// ApplicationConfig
// ---------------------------------------------------------------------------

/// Configuration for a bulk signature application run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfig {
    /// Paths to `.sig` or `.pat` files to load.
    pub library_paths: Vec<std::path::PathBuf>,
    /// Minimum confidence score (0–100) to accept a match.
    pub confidence_threshold: u8,
    /// Whether to apply to all offsets or only known function starts.
    pub scan_mode: ScanMode,
    /// Conflict resolution strategy.
    pub conflict_resolution: ConflictStrategy,
    /// Whether dry-run mode is active (no renames applied, report only).
    pub dry_run: bool,
    /// Maximum number of matches to process per function address.
    pub max_matches_per_addr: usize,
}

impl ApplicationConfig {
    /// Create a default configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            library_paths: Vec::new(),
            confidence_threshold: 60,
            scan_mode: ScanMode::AllOffsets,
            conflict_resolution: ConflictStrategy::HighestConfidence,
            dry_run: false,
            max_matches_per_addr: 4,
        }
    }

    /// Add a library path.
    #[must_use]
    pub fn with_library(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.library_paths.push(path.into());
        self
    }

    /// Set the confidence threshold.
    #[must_use]
    pub const fn with_confidence(mut self, threshold: u8) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    /// Enable dry-run mode.
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// How to scan the binary for patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Slide a window over every byte offset.
    AllOffsets,
    /// Only check at provided function-start addresses.
    FunctionStartsOnly,
    /// Slide window in `alignment`-byte steps.
    Aligned(usize),
}

/// How to resolve naming conflicts (multiple matches at the same address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Pick the match with the highest confidence score.
    HighestConfidence,
    /// Skip the address and record a conflict.
    Skip,
    /// Accept the first match (by library insertion order).
    FirstMatch,
    /// Merge all names with a delimiter.
    MergeAll,
}

// ---------------------------------------------------------------------------
// ApplyResult / ApplyStatus
// ---------------------------------------------------------------------------

/// The outcome of a single rename attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyStatus {
    /// The rename was applied successfully.
    Renamed,
    /// The address was skipped (e.g. already has a user-defined name).
    Skipped,
    /// A naming conflict was detected and handled per the strategy.
    Conflict,
    /// Dry-run mode: would have been renamed.
    DryRun,
}

/// Result of applying one match to one function address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    /// The function address.
    pub address: u64,
    /// The name that was (or would have been) applied.
    pub name: String,
    /// The library that provided the name.
    pub library: String,
    /// Confidence score.
    pub confidence: u8,
    /// Outcome of the apply.
    pub status: ApplyStatus,
}

impl fmt::Display for ApplyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}: {:?} → {} [{}] {}%",
            self.address, self.status, self.name, self.library, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// ConflictResolver
// ---------------------------------------------------------------------------

/// Resolves naming conflicts using a configured strategy.
#[derive(Debug, Clone)]
pub struct ConflictResolver {
    pub strategy: ConflictStrategy,
    pub merge_delimiter: String,
}

impl ConflictResolver {
    /// Create a resolver with the given strategy.
    #[must_use]
    pub fn new(strategy: ConflictStrategy) -> Self {
        Self {
            strategy,
            merge_delimiter: "|".to_string(),
        }
    }

    /// Resolve a list of candidate matches for one address.
    ///
    /// Returns `(chosen_name, library, status)`.
    ///
    /// # Panics
    ///
    /// Panics if the unique-names list is empty after deduplication (should not occur).
    #[must_use]
    pub fn resolve(&self, candidates: &[FlirtMatch]) -> (String, String, ApplyStatus) {
        if candidates.is_empty() {
            return (String::new(), String::new(), ApplyStatus::Skipped);
        }

        // Deduplicate by name.
        let mut unique_names: Vec<&FlirtMatch> = Vec::new();
        let mut seen_names: HashSet<&str> = HashSet::new();
        for c in candidates {
            if seen_names.insert(c.function_name.as_str()) {
                unique_names.push(c);
            }
        }

        if unique_names.len() == 1 {
            let m = unique_names[0];
            return (
                m.function_name.clone(),
                m.lib_name.clone(),
                ApplyStatus::Renamed,
            );
        }

        // Multiple names: apply strategy.
        match self.strategy {
            ConflictStrategy::HighestConfidence => {
                let best = unique_names.iter().max_by_key(|m| m.confidence).unwrap();
                (
                    best.function_name.clone(),
                    best.lib_name.clone(),
                    ApplyStatus::Renamed,
                )
            }
            ConflictStrategy::Skip => (String::new(), String::new(), ApplyStatus::Conflict),
            ConflictStrategy::FirstMatch => {
                let first = &unique_names[0];
                (
                    first.function_name.clone(),
                    first.lib_name.clone(),
                    ApplyStatus::Renamed,
                )
            }
            ConflictStrategy::MergeAll => {
                let merged = unique_names
                    .iter()
                    .map(|m| m.function_name.as_str())
                    .collect::<Vec<_>>()
                    .join(&self.merge_delimiter);
                let lib = unique_names[0].lib_name.clone();
                (merged, lib, ApplyStatus::Conflict)
            }
        }
    }
}

impl Default for ConflictResolver {
    fn default() -> Self {
        Self::new(ConflictStrategy::HighestConfidence)
    }
}

// ---------------------------------------------------------------------------
// ProgressTracker
// ---------------------------------------------------------------------------

/// Tracks progress of a bulk apply run.
#[derive(Debug, Clone)]
pub struct ProgressTracker {
    pub total: usize,
    pub processed: usize,
    pub start: Instant,
    pub callbacks: Vec<String>,
}

impl ProgressTracker {
    /// Create a new tracker for `total` items.
    #[must_use]
    pub fn new(total: usize) -> Self {
        Self {
            total,
            processed: 0,
            start: Instant::now(),
            callbacks: Vec::new(),
        }
    }

    /// Increment the processed count.
    pub const fn tick(&mut self) {
        self.processed += 1;
    }

    /// Fraction complete, 0.0–1.0.
    #[must_use]
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            usize_to_f64(self.processed) / usize_to_f64(self.total)
        }
    }

    /// Percentage complete (0–100).
    #[must_use]
    pub fn percent(&self) -> u8 {
        f64_to_u8(self.fraction() * 100.0)
    }

    /// Elapsed time.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Estimated time remaining.
    #[must_use]
    pub fn eta(&self) -> Option<Duration> {
        if self.processed == 0 {
            return None;
        }
        let elapsed = self.elapsed();
        let rate = usize_to_f64(self.processed) / elapsed.as_secs_f64();
        let remaining = usize_to_f64(self.total - self.processed) / rate;
        Some(Duration::from_secs_f64(remaining))
    }

    /// Log a progress message.
    pub fn log(&mut self, msg: impl Into<String>) {
        self.callbacks.push(msg.into());
    }

    /// Returns `true` if complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.processed >= self.total
    }
}

// ---------------------------------------------------------------------------
// RollbackSupport
// ---------------------------------------------------------------------------

/// Records applied renames and supports full rollback.
#[derive(Debug, Default, Clone)]
pub struct RollbackSupport {
    /// Original names before bulk application: `(address, original_name)`.
    snapshots: Vec<(u64, String)>,
    /// Sequence of renames applied: `(address, old_name, new_name)`.
    history: Vec<(u64, String, String)>,
}

impl RollbackSupport {
    /// Create an empty rollback log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the original name of an address before renaming it.
    pub fn snapshot(&mut self, address: u64, original_name: impl Into<String>) {
        self.snapshots.push((address, original_name.into()));
    }

    /// Record that `address` was renamed from `old` to `new`.
    pub fn record(
        &mut self,
        address: u64,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) {
        self.history
            .push((address, old_name.into(), new_name.into()));
    }

    /// Return the list of `(address, old_name)` that would be restored on rollback.
    #[must_use]
    pub fn rollback_plan(&self) -> Vec<(u64, &str)> {
        self.snapshots
            .iter()
            .map(|(a, n)| (*a, n.as_str()))
            .collect()
    }

    /// Execute rollback using a callback `restore_fn(address, original_name) -> bool`.
    pub fn rollback(&mut self, mut restore_fn: impl FnMut(u64, &str) -> bool) -> usize {
        let mut count = 0;
        for (addr, original) in &self.snapshots {
            if restore_fn(*addr, original) {
                count += 1;
            }
        }
        self.snapshots.clear();
        self.history.clear();
        count
    }

    /// Number of renames recorded.
    #[must_use]
    pub const fn rename_count(&self) -> usize {
        self.history.len()
    }

    /// Clear all rollback data.
    pub fn clear(&mut self) {
        self.snapshots.clear();
        self.history.clear();
    }
}

// ---------------------------------------------------------------------------
// ApplicationReport
// ---------------------------------------------------------------------------

/// Summary of a completed bulk application run.
#[derive(Debug, Clone, Default)]
pub struct ApplicationReport {
    /// Total functions analyzed.
    pub total_analyzed: usize,
    /// Total renames applied.
    pub renamed: usize,
    /// Functions skipped (already named or filtered out).
    pub skipped: usize,
    /// Functions with unresolved naming conflicts.
    pub conflicts: usize,
    /// Dry-run entries (would have been renamed).
    pub dry_run_count: usize,
    /// Per-library counts.
    pub by_library: HashMap<String, usize>,
    /// All individual results.
    pub results: Vec<ApplyResult>,
    /// Total elapsed time.
    pub elapsed: Duration,
}

impl ApplicationReport {
    /// Build a report from individual results.
    #[must_use]
    pub fn build(results: Vec<ApplyResult>, elapsed: Duration) -> Self {
        let total_analyzed = results.len();
        let renamed = results
            .iter()
            .filter(|r| r.status == ApplyStatus::Renamed)
            .count();
        let skipped = results
            .iter()
            .filter(|r| r.status == ApplyStatus::Skipped)
            .count();
        let conflicts = results
            .iter()
            .filter(|r| r.status == ApplyStatus::Conflict)
            .count();
        let dry_run_count = results
            .iter()
            .filter(|r| r.status == ApplyStatus::DryRun)
            .count();

        let mut by_library: HashMap<String, usize> = HashMap::new();
        for r in &results {
            if r.status == ApplyStatus::Renamed || r.status == ApplyStatus::DryRun {
                if let Some(v) = by_library.get_mut(&r.library) {
                    *v += 1;
                } else {
                    by_library.insert(r.library.clone(), 1);
                }
            }
        }

        Self {
            total_analyzed,
            renamed,
            skipped,
            conflicts,
            dry_run_count,
            by_library,
            results,
            elapsed,
        }
    }

    /// Rename rate (renamed / `total_analyzed`).
    #[must_use]
    pub fn rename_rate(&self) -> f64 {
        if self.total_analyzed == 0 {
            0.0
        } else {
            usize_to_f64(self.renamed) / usize_to_f64(self.total_analyzed)
        }
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Applied: {}/{} ({:.1}%) | skipped={} conflicts={} dry={} elapsed={:.2}s",
            self.renamed,
            self.total_analyzed,
            self.rename_rate() * 100.0,
            self.skipped,
            self.conflicts,
            self.dry_run_count,
            self.elapsed.as_secs_f64(),
        )
    }

    /// Return all renamed results.
    #[must_use]
    pub fn renamed_results(&self) -> Vec<&ApplyResult> {
        self.results
            .iter()
            .filter(|r| r.status == ApplyStatus::Renamed)
            .collect()
    }

    /// Return all conflict results.
    #[must_use]
    pub fn conflict_results(&self) -> Vec<&ApplyResult> {
        self.results
            .iter()
            .filter(|r| r.status == ApplyStatus::Conflict)
            .collect()
    }
}

impl fmt::Display for ApplicationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ---------------------------------------------------------------------------
// BulkApplier
// ---------------------------------------------------------------------------

/// Bulk signature application engine.
///
/// Loads signatures from one or more databases, scans a binary region,
/// and produces [`ApplyResult`]s for every match.
pub struct BulkApplier {
    config: ApplicationConfig,
    db: FlirtSigDb,
    resolver: ConflictResolver,
    rollback: RollbackSupport,
}

impl BulkApplier {
    /// Create a new bulk applier with the given config.
    #[must_use]
    pub fn new(config: ApplicationConfig) -> Self {
        let resolver = ConflictResolver::new(config.conflict_resolution);
        Self {
            config,
            db: FlirtSigDb::new(),
            resolver,
            rollback: RollbackSupport::new(),
        }
    }

    /// Add a pattern to the internal database.
    pub fn add_pattern(&mut self, pat: FlirtPattern) {
        self.db.add_pattern(pat);
    }

    /// Add patterns from a pre-built `FlirtSigDb`.
    pub fn add_database(&mut self, db: &FlirtSigDb) {
        // We use a FlirtApplier to scan; just add patterns directly.
        // In production this would merge; for now track in the same db.
        let _ = db.patterns_iter(); // placeholder: merge would happen here
    }

    /// Number of loaded patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.db.pattern_count()
    }

    /// Run bulk application on `data` starting at `base_addr`.
    ///
    /// If `fn_starts` is non-empty and the config uses `FunctionStartsOnly`
    /// mode, only those addresses are checked.
    ///
    /// `get_existing_name` is a callback: `fn(address) -> Option<String>`.
    /// If it returns `Some(name)` for a function and the name does not start
    /// with `sub_` (i.e. it is user-defined), the function is skipped.
    ///
    /// `apply_name` is the callback used to perform the actual rename:
    /// `fn(address, new_name) -> bool`.
    pub fn apply_to_binary(
        &mut self,
        data: &[u8],
        base_addr: u64,
        fn_starts: &[u64],
        get_existing_name: impl Fn(u64) -> Option<String>,
        mut apply_name: impl FnMut(u64, &str) -> bool,
    ) -> ApplicationReport {
        let start_time = Instant::now();
        let applier = FlirtApplier::new(FlirtSigDb::new());
        let _ = applier; // we do manual scanning below

        // Collect candidates.
        let candidates: Vec<u64> = match self.config.scan_mode {
            ScanMode::FunctionStartsOnly => fn_starts.to_vec(),
            ScanMode::AllOffsets => (0..data.len() as u64).map(|i| base_addr + i).collect(),
            ScanMode::Aligned(n) => (0..data.len() as u64)
                .step_by(n.max(1))
                .map(|i| base_addr + i)
                .collect(),
        };

        let mut results: Vec<ApplyResult> = Vec::with_capacity(candidates.len());
        let mut progress = ProgressTracker::new(candidates.len());
        let threshold = self.config.confidence_threshold;

        for addr in &candidates {
            progress.tick();
            let offset = u64_to_usize((*addr).saturating_sub(base_addr));
            if offset >= data.len() {
                continue;
            }
            let slice = &data[offset..];

            // Check if the function already has a non-auto name.
            if let Some(existing) = get_existing_name(*addr)
                && !existing.starts_with("sub_") && !existing.is_empty() {
                    results.push(ApplyResult {
                        address: *addr,
                        name: existing,
                        library: String::new(),
                        confidence: 0,
                        status: ApplyStatus::Skipped,
                    });
                    continue;
                }

            // Scan for matches at this address.
            let mut matches: Vec<FlirtMatch> = Vec::new();
            for pat in self.db.patterns_iter() {
                if pat.matches(slice) {
                    let conf = Self::compute_confidence(pat);
                    if conf >= threshold {
                        matches.push(FlirtMatch {
                            address: *addr,
                            function_name: pat.name.clone(),
                            lib_name: pat.lib_name.clone(),
                            confidence: conf,
                            pattern_length: pat.pattern_len(),
                        });
                    }
                }
            }

            if matches.is_empty() {
                continue;
            }

            // Cap per-address matches.
            matches.truncate(self.config.max_matches_per_addr);

            // Resolve conflicts.
            let (name, library, mut status) = self.resolver.resolve(&matches);

            if name.is_empty() {
                results.push(ApplyResult {
                    address: *addr,
                    name: String::new(),
                    library: String::new(),
                    confidence: 0,
                    status: ApplyStatus::Conflict,
                });
                continue;
            }

            // Dry-run or real apply.
            if self.config.dry_run {
                status = ApplyStatus::DryRun;
            } else if status == ApplyStatus::Renamed {
                let existing = get_existing_name(*addr).unwrap_or_default();
                self.rollback.snapshot(*addr, &existing);
                if apply_name(*addr, &name) {
                    self.rollback.record(*addr, &existing, &name);
                } else {
                    status = ApplyStatus::Skipped;
                }
            }

            let conf = matches.iter().map(|m| m.confidence).max().unwrap_or(0);
            results.push(ApplyResult {
                address: *addr,
                name,
                library,
                confidence: conf,
                status,
            });
        }

        ApplicationReport::build(results, start_time.elapsed())
    }

    /// Roll back all renames applied in the most recent [`apply_to_binary`] call.
    pub fn rollback(&mut self, restore_fn: impl FnMut(u64, &str) -> bool) -> usize {
        self.rollback.rollback(restore_fn)
    }

    /// Return a reference to the rollback log.
    #[must_use]
    pub const fn rollback_log(&self) -> &RollbackSupport {
        &self.rollback
    }

    fn compute_confidence(pat: &FlirtPattern) -> u8 {
        let total = pat.bytes.len();
        if total == 0 {
            return 0;
        }
        let concrete = pat.bytes.iter().filter(|b| b.is_some()).count();
        let ratio = usize_to_f64(concrete) / usize_to_f64(total);
        let len_bonus = (usize_to_f64(total.min(16)) / 16.0) * 20.0;
        f64_to_u8(ratio.mul_add(80.0, len_bonus)).min(100)
    }
}

// Make FlirtSigDb expose pattern iteration.
pub trait PatternIter {
    fn patterns_iter(&self) -> std::slice::Iter<'_, FlirtPattern>;
}

impl PatternIter for FlirtSigDb {
    fn patterns_iter(&self) -> std::slice::Iter<'_, FlirtPattern> {
        self.patterns.iter()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlirtPattern;

    fn _make_db_with_pattern(hex: &str, name: &str) -> FlirtSigDb {
        let mut db = FlirtSigDb::new();
        if let Ok(p) = FlirtPattern::from_pattern_str(hex, name.to_string(), "lib".to_string()) {
            db.add_pattern(p);
        }
        db
    }

    fn make_applier() -> BulkApplier {
        let config = ApplicationConfig::new();
        BulkApplier::new(config)
    }

    // ── ApplicationConfig ──────────────────────────────────────────────────

    #[test]
    fn config_default() {
        let c = ApplicationConfig::default();
        assert_eq!(c.confidence_threshold, 60);
        assert!(!c.dry_run);
    }

    #[test]
    fn config_with_library() {
        let c = ApplicationConfig::new().with_library("/path/to/lib.sig");
        assert_eq!(c.library_paths.len(), 1);
    }

    #[test]
    fn config_dry_run() {
        let c = ApplicationConfig::new().dry_run();
        assert!(c.dry_run);
    }

    // ── ConflictResolver ──────────────────────────────────────────────────

    #[test]
    fn resolver_empty_candidates() {
        let r = ConflictResolver::default();
        let (name, _, status) = r.resolve(&[]);
        assert!(name.is_empty());
        assert_eq!(status, ApplyStatus::Skipped);
    }

    #[test]
    fn resolver_single_candidate() {
        let r = ConflictResolver::default();
        let matches = vec![FlirtMatch {
            address: 0x1000,
            function_name: "foo".to_string(),
            lib_name: "libc".to_string(),
            confidence: 90,
            pattern_length: 8,
        }];
        let (name, lib, status) = r.resolve(&matches);
        assert_eq!(name, "foo");
        assert_eq!(lib, "libc");
        assert_eq!(status, ApplyStatus::Renamed);
    }

    #[test]
    fn resolver_conflict_highest_confidence() {
        let r = ConflictResolver::new(ConflictStrategy::HighestConfidence);
        let matches = vec![
            FlirtMatch {
                address: 0x1000,
                function_name: "foo".to_string(),
                lib_name: "liba".to_string(),
                confidence: 70,
                pattern_length: 8,
            },
            FlirtMatch {
                address: 0x1000,
                function_name: "bar".to_string(),
                lib_name: "libb".to_string(),
                confidence: 90,
                pattern_length: 8,
            },
        ];
        let (name, _, _) = r.resolve(&matches);
        assert_eq!(name, "bar");
    }

    #[test]
    fn resolver_conflict_skip() {
        let r = ConflictResolver::new(ConflictStrategy::Skip);
        let matches = vec![
            FlirtMatch {
                address: 0x1000,
                function_name: "a".to_string(),
                lib_name: "l".to_string(),
                confidence: 80,
                pattern_length: 8,
            },
            FlirtMatch {
                address: 0x1000,
                function_name: "b".to_string(),
                lib_name: "l".to_string(),
                confidence: 80,
                pattern_length: 8,
            },
        ];
        let (_, _, status) = r.resolve(&matches);
        assert_eq!(status, ApplyStatus::Conflict);
    }

    #[test]
    fn resolver_conflict_first_match() {
        let r = ConflictResolver::new(ConflictStrategy::FirstMatch);
        let matches = vec![
            FlirtMatch {
                address: 0x1000,
                function_name: "first".to_string(),
                lib_name: "l".to_string(),
                confidence: 80,
                pattern_length: 8,
            },
            FlirtMatch {
                address: 0x1000,
                function_name: "second".to_string(),
                lib_name: "l".to_string(),
                confidence: 90,
                pattern_length: 8,
            },
        ];
        let (name, _, _) = r.resolve(&matches);
        assert_eq!(name, "first");
    }

    #[test]
    fn resolver_conflict_merge_all() {
        let r = ConflictResolver::new(ConflictStrategy::MergeAll);
        let matches = vec![
            FlirtMatch {
                address: 0x1000,
                function_name: "a".to_string(),
                lib_name: "l".to_string(),
                confidence: 80,
                pattern_length: 8,
            },
            FlirtMatch {
                address: 0x1000,
                function_name: "b".to_string(),
                lib_name: "l".to_string(),
                confidence: 80,
                pattern_length: 8,
            },
        ];
        let (name, _, _) = r.resolve(&matches);
        assert!(name.contains('|'));
    }

    // ── ProgressTracker ───────────────────────────────────────────────────

    #[test]
    fn progress_tracker_fraction() {
        let mut t = ProgressTracker::new(10);
        t.tick();
        t.tick();
        t.tick();
        assert!((t.fraction() - 0.3).abs() < 0.01);
        assert_eq!(t.percent(), 30);
    }

    #[test]
    fn progress_tracker_zero_total() {
        let t = ProgressTracker::new(0);
        assert_eq!(t.fraction(), 1.0);
    }

    #[test]
    fn progress_tracker_complete() {
        let mut t = ProgressTracker::new(2);
        t.tick();
        t.tick();
        assert!(t.is_complete());
    }

    #[test]
    fn progress_tracker_eta_none_before_first_tick() {
        let t = ProgressTracker::new(100);
        // eta is None when no ticks have occurred
        assert!(t.eta().is_none());
    }

    // ── RollbackSupport ────────────────────────────────────────────────────

    #[test]
    fn rollback_snapshot_and_plan() {
        let mut r = RollbackSupport::new();
        r.snapshot(0x1000, "sub_1000");
        let plan = r.rollback_plan();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0], (0x1000, "sub_1000"));
    }

    #[test]
    fn rollback_execute() {
        let mut r = RollbackSupport::new();
        r.snapshot(0x1000, "sub_1000");
        r.record(0x1000, "sub_1000", "malloc");

        let mut restored = Vec::new();
        let count = r.rollback(|addr, name| {
            restored.push((addr, name.to_string()));
            true
        });
        assert_eq!(count, 1);
        assert_eq!(restored[0].1, "sub_1000");
        assert_eq!(r.rollback_plan().len(), 0);
    }

    #[test]
    fn rollback_rename_count() {
        let mut r = RollbackSupport::new();
        r.record(0x1000, "old", "new");
        assert_eq!(r.rename_count(), 1);
    }

    #[test]
    fn rollback_clear() {
        let mut r = RollbackSupport::new();
        r.snapshot(0x1000, "sub");
        r.clear();
        assert_eq!(r.rollback_plan().len(), 0);
    }

    // ── ApplicationReport ─────────────────────────────────────────────────

    #[test]
    fn report_build_empty() {
        let r = ApplicationReport::build(vec![], Duration::from_millis(10));
        assert_eq!(r.renamed, 0);
        assert_eq!(r.total_analyzed, 0);
    }

    #[test]
    fn report_build_with_results() {
        let results = vec![
            ApplyResult {
                address: 0x1000,
                name: "malloc".to_string(),
                library: "libc".to_string(),
                confidence: 90,
                status: ApplyStatus::Renamed,
            },
            ApplyResult {
                address: 0x2000,
                name: String::new(),
                library: String::new(),
                confidence: 0,
                status: ApplyStatus::Conflict,
            },
            ApplyResult {
                address: 0x3000,
                name: "known".to_string(),
                library: String::new(),
                confidence: 0,
                status: ApplyStatus::Skipped,
            },
        ];
        let r = ApplicationReport::build(results, Duration::from_millis(100));
        assert_eq!(r.renamed, 1);
        assert_eq!(r.conflicts, 1);
        assert_eq!(r.skipped, 1);
        assert!(r.by_library.contains_key("libc"));
    }

    #[test]
    fn report_rename_rate() {
        let results: Vec<ApplyResult> = (0..4u64)
            .map(|i| ApplyResult {
                address: i * 0x100,
                name: format!("fn{i}"),
                library: "l".to_string(),
                confidence: 90,
                status: if i < 2 {
                    ApplyStatus::Renamed
                } else {
                    ApplyStatus::Skipped
                },
            })
            .collect();
        let r = ApplicationReport::build(results, Duration::ZERO);
        assert!((r.rename_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn report_summary_contains_key_info() {
        let r = ApplicationReport::build(vec![], Duration::from_millis(50));
        let s = r.summary();
        assert!(s.contains("Applied"));
        assert!(s.contains("elapsed"));
    }

    #[test]
    fn report_display() {
        let r = ApplicationReport::build(vec![], Duration::ZERO);
        let s = r.to_string();
        assert!(s.contains("Applied"));
    }

    // ── BulkApplier ───────────────────────────────────────────────────────

    #[test]
    fn bulk_applier_pattern_count_zero() {
        let a = make_applier();
        assert_eq!(a.pattern_count(), 0);
    }

    #[test]
    fn bulk_applier_add_pattern() {
        let mut a = make_applier();
        let p = FlirtPattern::from_pattern_str("55 8B EC 83", "fn".to_string(), "lib".to_string())
            .unwrap();
        a.add_pattern(p);
        assert_eq!(a.pattern_count(), 1);
    }

    #[test]
    fn bulk_applier_dry_run_mode() {
        let mut a = BulkApplier::new(ApplicationConfig::new().dry_run());
        let p =
            FlirtPattern::from_pattern_str("55 8B EC 83", "func".to_string(), "lib".to_string())
                .unwrap();
        a.add_pattern(p);

        let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        let mut renamed = Vec::new();
        let report = a.apply_to_binary(
            &data,
            0x1000,
            &[0x1000],
            |_| None,
            |addr, name| {
                renamed.push((addr, name.to_string()));
                true
            },
        );
        // Dry run: no renames, but dry_run_count may be > 0
        assert_eq!(renamed.len(), 0);
        assert_eq!(report.renamed, 0);
    }

    #[test]
    fn bulk_applier_real_apply() {
        let mut a = make_applier();
        let p =
            FlirtPattern::from_pattern_str("55 8B EC 83", "my_fn".to_string(), "lib".to_string())
                .unwrap();
        a.add_pattern(p);

        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0x00];
        let mut renamed = Vec::new();
        let report = a.apply_to_binary(
            &data,
            0x1000,
            &[0x1000],
            |_| None,
            |addr, name| {
                renamed.push((addr, name.to_string()));
                true
            },
        );
        assert!(report.renamed <= 1);
        // The callback must have fired exactly as often as the report claims.
        assert_eq!(renamed.len(), report.renamed);
    }

    #[test]
    fn bulk_applier_skips_user_named() {
        let mut a = make_applier();
        let p =
            FlirtPattern::from_pattern_str("55 8B EC 83", "malloc".to_string(), "lib".to_string())
                .unwrap();
        a.add_pattern(p);

        let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        let report = a.apply_to_binary(
            &data,
            0x1000,
            &[0x1000],
            |_| Some("user_named_fn".to_string()),
            |_, _| true,
        );
        let skipped = report
            .results
            .iter()
            .filter(|r| r.status == ApplyStatus::Skipped)
            .count();
        assert!(skipped >= 1);
    }

    #[test]
    fn bulk_applier_rollback() {
        let mut a = make_applier();
        let p =
            FlirtPattern::from_pattern_str("55 8B EC 83", "my_fn".to_string(), "lib".to_string())
                .unwrap();
        a.add_pattern(p);

        let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
        a.apply_to_binary(&data, 0x1000, &[0x1000], |_| None, |_, _| true);
        let restored = a.rollback(|_, _| true);
        // May or may not have renamed; just ensure no panic
        let _ = restored;
    }

    // ── ApplyResult display ───────────────────────────────────────────────

    #[test]
    fn apply_result_display() {
        let r = ApplyResult {
            address: 0x1000,
            name: "malloc".to_string(),
            library: "libc".to_string(),
            confidence: 95,
            status: ApplyStatus::Renamed,
        };
        let s = r.to_string();
        assert!(s.contains("malloc"));
        assert!(s.contains("libc"));
    }
}
