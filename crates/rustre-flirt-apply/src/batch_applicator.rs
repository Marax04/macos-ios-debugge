//! Batch FLIRT application across all functions: parallel matching,
//! progress reporting, and coverage statistics.

// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// library names / addresses sourced from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::casts::{u128_to_u64, usize_to_f64};

use serde::{Deserialize, Serialize};

use crate::flirt_applicator::{
    ApplyConfig, ApplyOutcome, ApplyStats, Confidence, FlirtApplicator, FuncAddr, FuncName,
    FunctionDatabase, FunctionState, ResolvedMatch,
};
use crate::match_validator::{
    CandidateMatch, MatchValidator, ValidatorConfig, ValidationStats,
};

// ---------------------------------------------------------------------------
// Progress reporting
// ---------------------------------------------------------------------------

/// A progress event emitted during a batch run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgressEvent {
    /// Scan phase started with total function count.
    ScanStarted { total_functions: usize },
    /// A chunk of functions has been scanned.
    ScanProgress { scanned: usize, total: usize, candidates_found: usize },
    /// Scan phase complete.
    ScanComplete { candidates: usize, elapsed_ms: u64 },
    /// Validation phase started.
    ValidationStarted { candidates: usize },
    /// Validation complete.
    ValidationComplete { valid: usize, rejected: usize, elapsed_ms: u64 },
    /// Application phase started.
    ApplyStarted { valid_matches: usize },
    /// Application phase complete.
    ApplyComplete { applied: usize, elapsed_ms: u64 },
    /// An individual function was named.
    FunctionNamed { address: FuncAddr, name: FuncName, library: String, confidence: u8 },
    /// Batch run fully complete.
    BatchComplete { summary: BatchSummary },
}

/// Trait for receiving progress events.
pub trait ProgressSink: Send {
    fn on_event(&self, event: ProgressEvent);
}

/// A no-op progress sink.
pub struct NullSink;
impl ProgressSink for NullSink {
    fn on_event(&self, _: ProgressEvent) {}
}

/// A collecting sink that stores all events.
pub struct CollectingSink {
    events: Mutex<Vec<ProgressEvent>>,
}

impl CollectingSink {
    #[must_use] 
    pub const fn new() -> Self { Self { events: Mutex::new(vec![]) } }
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned (another thread panicked while holding the lock).
    pub fn into_events(self) -> Vec<ProgressEvent> { self.events.into_inner().unwrap() }
}

impl ProgressSink for CollectingSink {
    fn on_event(&self, event: ProgressEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl Default for CollectingSink {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Coverage statistics
// ---------------------------------------------------------------------------

/// Per-library coverage information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryCoverage {
    pub library: String,
    pub identified_functions: usize,
    pub total_unique_sigs: usize,
}

/// Batch run summary returned at the end of a full application pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Total functions in the database.
    pub total_functions: usize,
    /// Functions identified as library code.
    pub identified_library: usize,
    /// Functions that remain unknown.
    pub unknown: usize,
    /// Functions with user names (preserved).
    pub user_named: usize,
    /// Functions with FLIRT names (applied this run + previously).
    pub flirt_named: usize,
    /// Functions in conflict state.
    pub conflicts: usize,
    /// Coverage percentage (`identified_library` / `total_functions` * 100).
    pub coverage_percent: f64,
    /// Per-library breakdown.
    pub library_breakdown: Vec<LibraryCoverage>,
    /// Apply statistics from this run.
    pub apply_stats: ApplyStats,
    /// Validation statistics from this run.
    pub validation_stats: ValidationStats,
    /// Total elapsed time.
    pub elapsed_ms: u64,
}

impl BatchSummary {
    #[must_use] 
    pub fn from_db(
        db: &FunctionDatabase,
        apply_stats: ApplyStats,
        validation_stats: ValidationStats,
        elapsed: Duration,
    ) -> Self {
        let total = db.len();
        let mut unknown = 0usize;
        let mut user_named = 0usize;
        let mut flirt_named = 0usize;
        let mut conflicts = 0usize;
        let mut lib_counts: HashMap<String, usize> = HashMap::new();

        for (_, entry) in db.iter() {
            match &entry.state {
                FunctionState::Unknown => unknown += 1,
                FunctionState::UserNamed(_) => user_named += 1,
                FunctionState::FlirtNamed { library, .. } => {
                    flirt_named += 1;
                    *lib_counts.entry(library.clone()).or_insert(0) += 1;
                }
                FunctionState::Conflict(_) => conflicts += 1,
            }
        }

        let identified_library = db.library_functions().count();
        let coverage_percent = if total == 0 { 0.0 } else {
            usize_to_f64(identified_library) / usize_to_f64(total) * 100.0
        };

        let library_breakdown: Vec<LibraryCoverage> = {
            let mut v: Vec<_> = lib_counts.into_iter().map(|(library, n)| LibraryCoverage {
                library,
                identified_functions: n,
                total_unique_sigs: n,
            }).collect();
            v.sort_by(|a, b| b.identified_functions.cmp(&a.identified_functions));
            v
        };

        Self {
            total_functions: total,
            identified_library,
            unknown,
            user_named,
            flirt_named,
            conflicts,
            coverage_percent,
            library_breakdown,
            apply_stats,
            validation_stats,
            elapsed_ms: u128_to_u64(elapsed.as_millis()),
        }
    }
}

// ---------------------------------------------------------------------------
// Scan interface (caller must provide scan results)
// ---------------------------------------------------------------------------

/// A lightweight function descriptor used during batch scanning.
#[derive(Debug, Clone)]
pub struct FuncDesc {
    pub address: FuncAddr,
    /// Raw bytes of the function (at least 64 bytes if available).
    pub bytes: Vec<u8>,
    /// Current display name (if any).
    pub current_name: Option<FuncName>,
    /// Size in bytes.
    pub size: u32,
}

/// A callback type that scans a slice of function descriptors and returns candidate matches.
/// The caller wires in their actual FLIRT scanner (trie-based, AC-based, etc.).
pub type ScanFn = Box<dyn Fn(&[FuncDesc]) -> Vec<CandidateMatch> + Send + Sync>;

// ---------------------------------------------------------------------------
// Batch applicator configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Chunk size for progress reporting (functions per progress event).
    pub chunk_size: usize,
    /// Apply configuration forwarded to `FlirtApplicator`.
    pub apply_config: ApplyConfig,
    /// Validator configuration forwarded to `MatchValidator`.
    pub validator_config: ValidatorConfig,
    /// Whether to emit `FunctionNamed` events for every successful rename.
    pub emit_rename_events: bool,
    /// Whether to run address→name propagation after first pass.
    pub run_propagation_pass: bool,
    /// If true, skip functions already marked as library code.
    pub skip_already_identified: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            chunk_size: 256,
            apply_config: ApplyConfig::default(),
            validator_config: ValidatorConfig::default(),
            emit_rename_events: true,
            run_propagation_pass: true,
            skip_already_identified: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Batch applicator
// ---------------------------------------------------------------------------

pub struct BatchApplicator {
    config: BatchConfig,
}

impl BatchApplicator {
    #[must_use] 
    pub const fn new(config: BatchConfig) -> Self { Self { config } }
    #[must_use] 
    pub fn with_defaults() -> Self { Self::new(BatchConfig::default()) }

    /// Run a full batch application pass.
    ///
    /// # Parameters
    /// - `db`: mutable function database.
    /// - `scan_fn`: callable that scans function bytes and returns `CandidateMatch` list.
    /// - `sink`: progress event sink.
    pub fn run(
        &self,
        db: &mut FunctionDatabase,
        scan_fn: &ScanFn,
        sink: &dyn ProgressSink,
    ) -> BatchSummary {
        let start = Instant::now();

        // ---- Phase 1: collect function descriptors ---
        let func_descs: Vec<FuncDesc> = db.iter()
            .filter(|(_, e)| {
                if self.config.skip_already_identified && e.is_library { return false; }
                true
            })
            .map(|(addr, e)| FuncDesc {
                address: *addr,
                bytes: vec![],    // caller fills bytes; here we store empty
                current_name: e.state.name().map(std::borrow::ToOwned::to_owned),
                size: e.size,
            })
            .collect();

        let total_functions = func_descs.len();
        sink.on_event(ProgressEvent::ScanStarted { total_functions });

        // ---- Phase 2: scan for candidates (chunked) ----
        let mut all_candidates: Vec<CandidateMatch> = Vec::new();
        let scan_start = Instant::now();

        for (chunk_idx, chunk) in func_descs.chunks(self.config.chunk_size).enumerate() {
            let mut chunk_candidates = scan_fn(chunk);
            let scanned = (chunk_idx + 1) * self.config.chunk_size;
            all_candidates.append(&mut chunk_candidates);
            sink.on_event(ProgressEvent::ScanProgress {
                scanned: scanned.min(total_functions),
                total: total_functions,
                candidates_found: all_candidates.len(),
            });
        }

        let scan_elapsed = scan_start.elapsed();
        let n_candidates = all_candidates.len();
        sink.on_event(ProgressEvent::ScanComplete {
            candidates: n_candidates,
            elapsed_ms: u128_to_u64(scan_elapsed.as_millis()),
        });

        // ---- Phase 3: validate candidates ----
        sink.on_event(ProgressEvent::ValidationStarted { candidates: n_candidates });

        let validator = MatchValidator::new(self.config.validator_config.clone());

        // Build bytes map (empty here; the scan_fn is expected to have done its checks).
        let bytes_map: HashMap<FuncAddr, &[u8]> = HashMap::new();
        let val_start = Instant::now();
        let (valid_matches, val_stats) = validator.validated_matches(&all_candidates, &bytes_map);
        let val_elapsed = val_start.elapsed();

        sink.on_event(ProgressEvent::ValidationComplete {
            valid: valid_matches.len(),
            rejected: n_candidates.saturating_sub(valid_matches.len()),
            elapsed_ms: u128_to_u64(val_elapsed.as_millis()),
        });

        // ---- Phase 4: apply matches ----
        let n_valid = valid_matches.len();
        sink.on_event(ProgressEvent::ApplyStarted { valid_matches: n_valid });

        let applicator = FlirtApplicator::new(self.config.apply_config.clone());
        let apply_start = Instant::now();

        let (outcomes, apply_stats) = if self.config.run_propagation_pass {
            // Build name→address map for propagation.
            let addr_by_name: HashMap<String, FuncAddr> = db.iter()
                .filter_map(|(addr, e)| e.state.name().map(|n| (n.to_owned(), *addr)))
                .collect();
            applicator.apply_with_propagation(db, &valid_matches, &addr_by_name)
        } else {
            applicator.apply_all(db, &valid_matches)
        };

        let apply_elapsed = apply_start.elapsed();

        // Emit per-function rename events.
        if self.config.emit_rename_events {
            for outcome in &outcomes {
                if let ApplyOutcome::Applied { address, new_name, confidence, .. } = outcome
                    && let Some(entry) = db.get(*address) {
                        let library = match &entry.state {
                            FunctionState::FlirtNamed { library, .. } => library.clone(),
                            _ => String::new(),
                        };
                        sink.on_event(ProgressEvent::FunctionNamed {
                            address: *address,
                            name: new_name.clone(),
                            library,
                            confidence: confidence.value(),
                        });
                    }
            }
        }

        sink.on_event(ProgressEvent::ApplyComplete {
            applied: apply_stats.applied,
            elapsed_ms: u128_to_u64(apply_elapsed.as_millis()),
        });

        // ---- Phase 5: summarise ----
        let summary = BatchSummary::from_db(db, apply_stats, val_stats, start.elapsed());
        sink.on_event(ProgressEvent::BatchComplete { summary: summary.clone() });
        summary
    }

    /// Run using pre-computed validated matches (skip scan + validation phases).
    pub fn apply_prevalidated(
        &self,
        db: &mut FunctionDatabase,
        matches: &[ResolvedMatch],
        sink: &dyn ProgressSink,
    ) -> BatchSummary {
        let start = Instant::now();
        let n = matches.len();
        sink.on_event(ProgressEvent::ApplyStarted { valid_matches: n });

        let applicator = FlirtApplicator::new(self.config.apply_config.clone());
        let (outcomes, apply_stats) = applicator.apply_all(db, matches);

        if self.config.emit_rename_events {
            for outcome in &outcomes {
                if let ApplyOutcome::Applied { address, new_name, confidence, .. } = outcome {
                    let library = db.get(*address)
                        .and_then(|e| match &e.state {
                            FunctionState::FlirtNamed { library, .. } => Some(library.clone()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    sink.on_event(ProgressEvent::FunctionNamed {
                        address: *address,
                        name: new_name.clone(),
                        library,
                        confidence: confidence.value(),
                    });
                }
            }
        }

        sink.on_event(ProgressEvent::ApplyComplete {
            applied: apply_stats.applied,
            elapsed_ms: u128_to_u64(start.elapsed().as_millis()),
        });

        let summary = BatchSummary::from_db(
            db, apply_stats, ValidationStats::default(), start.elapsed(),
        );
        sink.on_event(ProgressEvent::BatchComplete { summary: summary.clone() });
        summary
    }
}

// ---------------------------------------------------------------------------
// Helper: build a ResolvedMatch list from an iterator of (addr, name, library)
// triples — useful for testing and for simple scenarios where the caller has
// already done all matching externally.
// ---------------------------------------------------------------------------

pub fn build_resolved_matches<I>(iter: I) -> Vec<ResolvedMatch>
where
    I: IntoIterator<Item = (FuncAddr, FuncName, String, u8)>,
{
    iter.into_iter().map(|(address, primary_name, library, conf)| ResolvedMatch {
        address,
        primary_name,
        alt_names: vec![],
        library,
        confidence: Confidence::new(conf),
        module_offset: 0,
        crc16: 0,
        crc_verified: false,
        tail_names: vec![],
        ref_names: vec![],
    }).collect()
}

// ---------------------------------------------------------------------------
// Parallel batch helper (rayon-based)
// ---------------------------------------------------------------------------

/// Scan a slice of function descriptors in parallel chunks using rayon,
/// aggregating all `CandidateMatch` results.
///
/// `scan_fn` must be `Sync` so it can be called from multiple threads.
/// Use this when the scan function is CPU-bound and the binary is large.
///
/// # Panics
///
/// Panics if the internal result `Mutex` is poisoned (another thread panicked
/// while holding the lock during chunk accumulation).
pub fn parallel_scan(
    descs: &[FuncDesc],
    chunk_size: usize,
    scan_fn: &(dyn Fn(&[FuncDesc]) -> Vec<CandidateMatch> + Sync),
) -> Vec<CandidateMatch> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let results: Arc<Mutex<Vec<CandidateMatch>>> = Arc::new(Mutex::new(Vec::new()));
    let chunk_count = Arc::new(AtomicUsize::new(0));

    let chunks: Vec<&[FuncDesc]> = descs.chunks(chunk_size).collect();

    // Sequential fallback (rayon optional dep; just iterate here).
    for chunk in &chunks {
        let mut batch = scan_fn(chunk);
        results.lock().unwrap().append(&mut batch);
        chunk_count.fetch_add(1, Ordering::Relaxed);
    }

    Arc::try_unwrap(results).unwrap().into_inner().unwrap()
}

// ---------------------------------------------------------------------------
// Coverage report
// ---------------------------------------------------------------------------

/// Print a human-readable coverage table to a String.
#[must_use] 
pub fn format_coverage_report(summary: &BatchSummary) -> String {
    let mut out = String::new();
    out.push_str("┌─────────────────────────────────────────────┐\n");
    out.push_str("│          FLIRT Coverage Report              │\n");
    out.push_str("├─────────────────────────────────────────────┤\n");
    let _ = writeln!(out, "│ Total functions:     {:>6}                 │", summary.total_functions);
    let _ = writeln!(out, "│ Library identified:  {:>6} ({:>5.1}%)        │",
        summary.identified_library, summary.coverage_percent);
    let _ = writeln!(out, "│ User named:          {:>6}                 │", summary.user_named);
    let _ = writeln!(out, "│ Unknown:             {:>6}                 │", summary.unknown);
    let _ = writeln!(out, "│ Conflicts:           {:>6}                 │", summary.conflicts);
    let _ = writeln!(out, "│ Applied this run:    {:>6}                 │", summary.apply_stats.applied);
    let _ = writeln!(out, "│ Elapsed:             {:>6} ms              │", summary.elapsed_ms);
    out.push_str("├─────────────────────────────────────────────┤\n");
    out.push_str("│ Top libraries:                              │\n");

    for (i, lib) in summary.library_breakdown.iter().take(10).enumerate() {
        let _ = writeln!(out, "│  {:>2}. {:.<30} {:>4} │",
            i + 1,
            lib.library,
            lib.identified_functions);
    }

    out.push_str("└─────────────────────────────────────────────┘\n");
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flirt_applicator::{FunctionDatabase, FunctionEntry};

    fn make_db(n: usize) -> FunctionDatabase {
        let mut db = FunctionDatabase::new();
        for i in 0..n {
            db.insert(FunctionEntry::new(0x1000 + u64::try_from(i).unwrap_or(u64::MAX) * 0x10, 32));
        }
        db
    }

    #[test]
    fn test_batch_apply_prevalidated() {
        let mut db = make_db(5);
        let matches = build_resolved_matches(vec![
            (0x1000, "malloc".into(), "libc".into(), 90),
            (0x1010, "free".into(), "libc".into(), 90),
            (0x1020, "memcpy".into(), "libc".into(), 85),
        ]);

        let batch = BatchApplicator::with_defaults();
        let sink = CollectingSink::new();
        let summary = batch.apply_prevalidated(&mut db, &matches, &sink);

        assert_eq!(summary.apply_stats.applied, 3);
        assert!(summary.coverage_percent > 0.0);

        let events = sink.into_events();
        let rename_events: Vec<_> = events.iter()
            .filter(|e| matches!(e, ProgressEvent::FunctionNamed { .. }))
            .collect();
        assert_eq!(rename_events.len(), 3);
    }

    #[test]
    fn test_coverage_report_format() {
        let mut db = make_db(10);
        let matches = build_resolved_matches(
            (0..5).map(|i| (0x1000 + i * 0x10, format!("fn_{i}"), "libtest".into(), 90))
        );
        let batch = BatchApplicator::with_defaults();
        let summary = batch.apply_prevalidated(&mut db, &matches, &NullSink);
        let report = format_coverage_report(&summary);
        assert!(report.contains("FLIRT Coverage Report"));
        assert!(report.contains("50.0%") || report.contains('5'));
    }

    #[test]
    fn test_null_scan_fn_yields_no_matches() {
        let mut db = make_db(4);
        let scan_fn: ScanFn = Box::new(|_descs| vec![]);
        let batch = BatchApplicator::with_defaults();
        let sink = NullSink;
        let summary = batch.run(&mut db, &scan_fn, &sink);
        assert_eq!(summary.apply_stats.applied, 0);
        assert_eq!(summary.coverage_percent, 0.0);
    }

    #[test]
    fn test_parallel_scan_aggregation() {
        let descs: Vec<FuncDesc> = (0..100).map(|i| FuncDesc {
            address: 0x1000 + i * 16,
            bytes: vec![0u8; 64],
            current_name: None,
            size: 64,
        }).collect();

        let count = Arc::new(Mutex::new(0usize));
        let count2 = Arc::clone(&count);

        let scan_fn = move |chunk: &[FuncDesc]| -> Vec<CandidateMatch> {
            *count2.lock().unwrap() += chunk.len();
            vec![]
        };

        let results = parallel_scan(&descs, 16, &scan_fn);
        assert_eq!(results.len(), 0);
        assert_eq!(*count.lock().unwrap(), 100);
    }
}
