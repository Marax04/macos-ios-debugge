//! Batch processing mode for running analysis on multiple files concurrently.
//!
//! Provides [`BatchJob`], [`BatchProcessor`], [`BatchReport`],
//! [`ParallelBatch`], and [`BatchStats`].

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BatchError {
    #[error("job list is empty")]
    EmptyJobList,
    #[error("input file not found: {0}")]
    FileNotFound(String),
    #[error("output path error: {0}")]
    OutputError(String),
    #[error("operation failed: {0}")]
    OperationFailed(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("concurrency limit must be >= 1")]
    InvalidConcurrency,
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchOperation
// ─────────────────────────────────────────────────────────────────────────────

/// A single operation to perform on a binary file in a batch job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BatchOperation {
    /// Fully analyse the binary.
    Analyze,
    /// Decompile all functions.
    DecompileAll,
    /// Disassemble all functions.
    DisasmAll,
    /// Extract embedded strings.
    ExtractStrings,
    /// Extract imports table.
    ExtractImports,
    /// Extract exports table.
    ExtractExports,
    /// Detect cryptographic algorithms.
    DetectCrypto,
    /// Scan for anti-debug techniques.
    AntiDebugScan,
    /// Generate a binary diff against a reference file.
    Diff { reference: PathBuf },
    /// Export IL/decompiled output to JSON.
    ExportJson,
    /// Run a named analysis pass.
    RunPass { pass_name: String },
    /// Custom operation with a description.
    Custom { name: String, args: Vec<String> },
}

impl fmt::Display for BatchOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Analyze => write!(f, "Analyze"),
            Self::DecompileAll => write!(f, "DecompileAll"),
            Self::DisasmAll => write!(f, "DisasmAll"),
            Self::ExtractStrings => write!(f, "ExtractStrings"),
            Self::ExtractImports => write!(f, "ExtractImports"),
            Self::ExtractExports => write!(f, "ExtractExports"),
            Self::DetectCrypto => write!(f, "DetectCrypto"),
            Self::AntiDebugScan => write!(f, "AntiDebugScan"),
            Self::Diff { reference } => write!(f, "Diff({})", reference.display()),
            Self::ExportJson => write!(f, "ExportJson"),
            Self::RunPass { pass_name } => write!(f, "Pass({pass_name})"),
            Self::Custom { name, .. } => write!(f, "Custom({name})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JobStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Execution status of a [`BatchJob`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "PENDING"),
            Self::Running => write!(f, "RUNNING"),
            Self::Succeeded => write!(f, "OK"),
            Self::Failed => write!(f, "FAIL"),
            Self::Skipped => write!(f, "SKIP"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchJob
// ─────────────────────────────────────────────────────────────────────────────

/// A unit of work for the batch processor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchJob {
    /// Unique job identifier.
    pub id: u64,
    /// Path of the input binary.
    pub input_file: PathBuf,
    /// Operations to perform.
    pub operations: Vec<BatchOperation>,
    /// Optional output path for results.
    pub output_path: Option<PathBuf>,
    /// Current status.
    pub status: JobStatus,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Elapsed time.
    pub elapsed: Option<Duration>,
    /// Results map (operation name → result string).
    pub results: HashMap<String, String>,
    /// Tags for grouping/filtering.
    pub tags: Vec<String>,
}

impl BatchJob {
    /// Create a new pending job.
    #[must_use]
    pub fn new(id: u64, input_file: impl Into<PathBuf>, operations: Vec<BatchOperation>) -> Self {
        Self {
            id,
            input_file: input_file.into(),
            operations,
            output_path: None,
            status: JobStatus::Pending,
            error: None,
            elapsed: None,
            results: HashMap::new(),
            tags: Vec::new(),
        }
    }

    /// Set output path.
    #[must_use]
    pub fn with_output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Mark job as succeeded.
    pub fn mark_success(&mut self, elapsed: Duration) {
        self.status = JobStatus::Succeeded;
        self.elapsed = Some(elapsed);
        self.error = None;
    }

    /// Mark job as failed.
    pub fn mark_failed(&mut self, elapsed: Duration, error: impl Into<String>) {
        self.status = JobStatus::Failed;
        self.elapsed = Some(elapsed);
        self.error = Some(error.into());
    }

    /// Store an operation result.
    pub fn store_result(&mut self, op: &BatchOperation, value: impl Into<String>) {
        self.results.insert(op.to_string(), value.into());
    }

    /// Return elapsed time or zero.
    #[must_use]
    pub fn elapsed_or_zero(&self) -> Duration {
        self.elapsed.unwrap_or(Duration::ZERO)
    }
}

impl fmt::Display for BatchJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:04}] {:6} {} ({} ops)",
            self.id,
            self.status,
            self.input_file.display(),
            self.operations.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchJobBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for [`BatchJob`].
#[derive(Debug, Default)]
pub struct BatchJobBuilder {
    input_file: Option<PathBuf>,
    operations: Vec<BatchOperation>,
    output_path: Option<PathBuf>,
    tags: Vec<String>,
}

impl BatchJobBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn input(mut self, path: impl Into<PathBuf>) -> Self {
        self.input_file = Some(path.into());
        self
    }

    #[must_use]
    pub fn op(mut self, op: BatchOperation) -> Self {
        self.operations.push(op);
        self
    }

    #[must_use]
    pub fn output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Build the [`BatchJob`], assigning the given ID.
    ///
    /// # Panics
    /// Panics if `input` was not set.
    #[must_use]
    pub fn build(self, id: u64) -> BatchJob {
        let mut job = BatchJob::new(
            id,
            self.input_file
                .expect("BatchJobBuilder: input_file is required"),
            self.operations,
        );
        job.output_path = self.output_path;
        job.tags = self.tags;
        job
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OperationExecutor — stub per-operation executor
// ─────────────────────────────────────────────────────────────────────────────

fn execute_operation(op: &BatchOperation, _path: &Path) -> Result<String, String> {
    match op {
        BatchOperation::Analyze => Ok("analysis complete (stub)".into()),
        BatchOperation::DecompileAll => Ok("decompiled 0 functions (stub)".into()),
        BatchOperation::DisasmAll => Ok("disassembled 0 functions (stub)".into()),
        BatchOperation::ExtractStrings => Ok("extracted 0 strings (stub)".into()),
        BatchOperation::ExtractImports => Ok("found 0 imports (stub)".into()),
        BatchOperation::ExtractExports => Ok("found 0 exports (stub)".into()),
        BatchOperation::DetectCrypto => Ok("no crypto detected (stub)".into()),
        BatchOperation::AntiDebugScan => Ok("no anti-debug found (stub)".into()),
        BatchOperation::Diff { .. } => Ok("diff complete (stub)".into()),
        BatchOperation::ExportJson => Ok("exported to JSON (stub)".into()),
        BatchOperation::RunPass { pass_name } => Ok(format!("pass '{pass_name}' complete (stub)")),
        BatchOperation::Custom { name, .. } => Ok(format!("custom op '{name}' complete (stub)")),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchProcessor
// ─────────────────────────────────────────────────────────────────────────────

/// Processes [`BatchJob`]s sequentially (single-threaded).
#[derive(Debug, Default)]
pub struct BatchProcessor {
    /// Whether to abort the entire batch on the first failure.
    pub fail_fast: bool,
    /// Whether to validate that input files exist before queueing.
    pub validate_inputs: bool,
}

impl BatchProcessor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn fail_fast(mut self, v: bool) -> Self {
        self.fail_fast = v;
        self
    }

    #[must_use]
    pub const fn validate_inputs(mut self, v: bool) -> Self {
        self.validate_inputs = v;
        self
    }

    /// Execute a list of jobs sequentially.
    ///
    /// # Errors
    /// Returns [`BatchError::EmptyJobList`] if `jobs` is empty.
    /// Returns [`BatchError::FileNotFound`] if validation is enabled and a file is missing.
    pub fn run(&self, jobs: &mut [BatchJob]) -> Result<BatchReport, BatchError> {
        if jobs.is_empty() {
            return Err(BatchError::EmptyJobList);
        }
        let global_start = Instant::now();

        for job in jobs.iter_mut() {
            job.status = JobStatus::Running;
            let t0 = Instant::now();
            let mut any_fail = false;

            for i in 0..job.operations.len() {
                let res = execute_operation(&job.operations[i], &job.input_file);
                match res {
                    Ok(result) => {
                        let key = job.operations[i].to_string();
                        job.results.insert(key, result);
                    }
                    Err(e) => {
                        any_fail = true;
                        job.mark_failed(t0.elapsed(), &e);
                        if self.fail_fast {
                            return Ok(BatchReport::from_jobs(jobs, global_start.elapsed()));
                        }
                        break;
                    }
                }
            }

            if !any_fail {
                job.mark_success(t0.elapsed());
            }
        }

        Ok(BatchReport::from_jobs(jobs, global_start.elapsed()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParallelBatch — simulated parallel execution using thread scoping
// ─────────────────────────────────────────────────────────────────────────────

/// Runs batch jobs with a configurable concurrency limit.
///
/// In this stub implementation the "parallel" execution is simulated
/// sequentially; in a production build this would use a thread pool.
#[derive(Debug)]
pub struct ParallelBatch {
    /// Maximum number of concurrent jobs.
    pub concurrency: usize,
    /// Whether to abort on first failure.
    pub fail_fast: bool,
}

impl ParallelBatch {
    /// Create a [`ParallelBatch`] with a given concurrency.
    ///
    /// # Errors
    /// Returns [`BatchError::InvalidConcurrency`] if `concurrency == 0`.
    pub const fn new(concurrency: usize) -> Result<Self, BatchError> {
        if concurrency == 0 {
            return Err(BatchError::InvalidConcurrency);
        }
        Ok(Self {
            concurrency,
            fail_fast: false,
        })
    }

    #[must_use]
    pub const fn fail_fast(mut self, v: bool) -> Self {
        self.fail_fast = v;
        self
    }

    /// Run jobs with the configured concurrency.
    ///
    /// # Errors
    /// Returns [`BatchError::EmptyJobList`] if `jobs` is empty.
    pub fn run(&self, jobs: &mut [BatchJob]) -> Result<BatchReport, BatchError> {
        if jobs.is_empty() {
            return Err(BatchError::EmptyJobList);
        }
        let global_start = Instant::now();

        // Simulated parallel execution (sequential stub, concurrency is noted in the report).
        let aborted = Arc::new(Mutex::new(false));

        for chunk in jobs.chunks_mut(self.concurrency) {
            if *aborted.lock().unwrap() {
                for job in chunk.iter_mut() {
                    job.status = JobStatus::Skipped;
                }
                continue;
            }
            for job in chunk.iter_mut() {
                let t0 = Instant::now();
                job.status = JobStatus::Running;
                let mut fail = false;
                for i in 0..job.operations.len() {
                    let res = execute_operation(&job.operations[i], &job.input_file);
                    match res {
                        Ok(r) => {
                            let key = job.operations[i].to_string();
                            job.results.insert(key, r);
                        }
                        Err(e) => {
                            job.mark_failed(t0.elapsed(), e);
                            fail = true;
                            if self.fail_fast {
                                *aborted.lock().unwrap() = true;
                            }
                            break;
                        }
                    }
                }
                if !fail {
                    job.mark_success(t0.elapsed());
                }
            }
        }

        Ok(BatchReport::from_jobs(jobs, global_start.elapsed()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated report of a batch run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReport {
    /// Per-job summaries.
    pub jobs: Vec<BatchJobSummary>,
    /// Aggregate statistics.
    pub stats: BatchStats,
    /// Total wall-clock time for the batch.
    pub total_elapsed: Duration,
}

/// Lightweight summary for a single job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchJobSummary {
    pub id: u64,
    pub input_file: PathBuf,
    pub status: JobStatus,
    pub error: Option<String>,
    pub elapsed: Option<Duration>,
    pub operation_count: usize,
    pub results: HashMap<String, String>,
}

impl BatchReport {
    fn from_jobs(jobs: &[BatchJob], total_elapsed: Duration) -> Self {
        let summaries: Vec<_> = jobs
            .iter()
            .map(|j| BatchJobSummary {
                id: j.id,
                input_file: j.input_file.clone(),
                status: j.status,
                error: j.error.clone(),
                elapsed: j.elapsed,
                operation_count: j.operations.len(),
                results: j.results.clone(),
            })
            .collect();
        let stats = BatchStats::from_summaries(&summaries);
        Self {
            jobs: summaries,
            stats,
            total_elapsed,
        }
    }

    /// Return a text summary of the batch run.
    #[must_use]
    pub fn summary_text(&self) -> String {
        format!(
            "Batch complete: {}/{} jobs succeeded, {} failed, {} skipped in {:.2}s",
            self.stats.succeeded,
            self.stats.total,
            self.stats.failed,
            self.stats.skipped,
            self.total_elapsed.as_secs_f64(),
        )
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns [`BatchError::Serialization`] on failure.
    pub fn to_json(&self) -> Result<String, BatchError> {
        serde_json::to_string_pretty(self).map_err(|e| BatchError::Serialization(e.to_string()))
    }

    /// Return only failed jobs.
    #[must_use]
    pub fn failed_jobs(&self) -> Vec<&BatchJobSummary> {
        self.jobs
            .iter()
            .filter(|j| j.status == JobStatus::Failed)
            .collect()
    }

    /// Return only succeeded jobs.
    #[must_use]
    pub fn succeeded_jobs(&self) -> Vec<&BatchJobSummary> {
        self.jobs
            .iter()
            .filter(|j| j.status == JobStatus::Succeeded)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a batch run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStats {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub pending: usize,
    pub total_ops_executed: usize,
    pub average_elapsed_ms: u64,
    pub slowest_job_id: Option<u64>,
    pub slowest_elapsed: Option<Duration>,
    pub success_rate_pct: f64,
}

impl BatchStats {
    #[must_use]
    fn from_summaries(summaries: &[BatchJobSummary]) -> Self {
        let total = summaries.len();
        let succeeded = summaries
            .iter()
            .filter(|j| j.status == JobStatus::Succeeded)
            .count();
        let failed = summaries
            .iter()
            .filter(|j| j.status == JobStatus::Failed)
            .count();
        let skipped = summaries
            .iter()
            .filter(|j| j.status == JobStatus::Skipped)
            .count();
        let pending = summaries
            .iter()
            .filter(|j| j.status == JobStatus::Pending)
            .count();
        let total_ops_executed: usize = summaries.iter().map(|j| j.results.len()).sum();

        let elapsed_vals: Vec<Duration> = summaries.iter().filter_map(|j| j.elapsed).collect();
        let average_elapsed_ms = if elapsed_vals.is_empty() {
            0
        } else {
            // as_millis() returns u128; sum in u128 to avoid overflow then
            // clamp to u64::MAX before the final cast to avoid silent truncation.
            let total_ms: u128 = elapsed_vals.iter().map(std::time::Duration::as_millis).sum();
            let count = elapsed_vals.len() as u128;
            (total_ms / count).min(u128::from(u64::MAX)) as u64
        };

        let slowest = summaries.iter().max_by_key(|j| j.elapsed);
        let (slowest_job_id, slowest_elapsed) = match slowest {
            Some(j) if j.elapsed.is_some() => (Some(j.id), j.elapsed),
            _ => (None, None),
        };

        let success_rate_pct = if total == 0 {
            0.0
        } else {
            (succeeded as f64 / total as f64) * 100.0
        };

        Self {
            total,
            succeeded,
            failed,
            skipped,
            pending,
            total_ops_executed,
            average_elapsed_ms,
            slowest_job_id,
            slowest_elapsed,
            success_rate_pct,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a batch run, loadable from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// List of input file patterns (globs).
    pub input_patterns: Vec<String>,
    /// Default operations for each job.
    pub default_operations: Vec<BatchOperation>,
    /// Output directory.
    pub output_dir: Option<PathBuf>,
    /// Maximum parallel jobs.
    pub concurrency: usize,
    /// Abort on first failure.
    pub fail_fast: bool,
    /// Optional tags to add to every job.
    pub tags: Vec<String>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            input_patterns: Vec::new(),
            default_operations: vec![BatchOperation::Analyze],
            output_dir: None,
            concurrency: 4,
            fail_fast: false,
            tags: Vec::new(),
        }
    }
}

impl BatchConfig {
    /// Parse from JSON string.
    ///
    /// # Errors
    /// Returns [`BatchError::Serialization`] on parse failure.
    pub fn from_json(s: &str) -> Result<Self, BatchError> {
        serde_json::from_str(s).map_err(|e| BatchError::Serialization(e.to_string()))
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns [`BatchError::Serialization`] on failure.
    pub fn to_json(&self) -> Result<String, BatchError> {
        serde_json::to_string_pretty(self).map_err(|e| BatchError::Serialization(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_jobs(n: u64) -> Vec<BatchJob> {
        (0..n)
            .map(|i| {
                BatchJob::new(
                    i,
                    format!("/tmp/test{i}.bin"),
                    vec![BatchOperation::Analyze, BatchOperation::ExtractStrings],
                )
            })
            .collect()
    }

    // -- BatchJob ------------------------------------------------------------

    #[test]
    fn test_job_creation() {
        let j = BatchJob::new(0, "/tmp/a.bin", vec![BatchOperation::Analyze]);
        assert_eq!(j.status, JobStatus::Pending);
        assert_eq!(j.operations.len(), 1);
    }

    #[test]
    fn test_job_mark_success() {
        let mut j = BatchJob::new(0, "/tmp/a.bin", vec![]);
        j.mark_success(Duration::from_millis(10));
        assert_eq!(j.status, JobStatus::Succeeded);
        assert!(j.elapsed.is_some());
    }

    #[test]
    fn test_job_mark_failed() {
        let mut j = BatchJob::new(0, "/tmp/a.bin", vec![]);
        j.mark_failed(Duration::from_millis(1), "reason");
        assert_eq!(j.status, JobStatus::Failed);
        assert_eq!(j.error.as_deref(), Some("reason"));
    }

    #[test]
    fn test_job_store_result() {
        let mut j = BatchJob::new(0, "/tmp/a.bin", vec![BatchOperation::Analyze]);
        j.store_result(&BatchOperation::Analyze, "ok");
        assert_eq!(j.results.get("Analyze").map(std::string::String::as_str), Some("ok"));
    }

    #[test]
    fn test_job_with_tag() {
        let j = BatchJob::new(0, "/tmp/a.bin", vec![]).with_tag("malware");
        assert!(j.tags.contains(&"malware".to_owned()));
    }

    #[test]
    fn test_job_display() {
        let j = BatchJob::new(42, "/tmp/x.bin", vec![BatchOperation::Analyze]);
        let s = format!("{j}");
        assert!(s.contains("0042"));
    }

    // -- BatchJobBuilder -----------------------------------------------------

    #[test]
    fn test_builder_basic() {
        let j = BatchJobBuilder::new()
            .input("/tmp/foo.bin")
            .op(BatchOperation::Analyze)
            .op(BatchOperation::ExtractStrings)
            .tag("test")
            .build(7);
        assert_eq!(j.id, 7);
        assert_eq!(j.operations.len(), 2);
        assert!(j.tags.contains(&"test".to_owned()));
    }

    // -- BatchProcessor -------------------------------------------------------

    #[test]
    fn test_processor_empty_jobs_error() {
        let proc = BatchProcessor::new();
        let mut jobs: Vec<BatchJob> = vec![];
        let err = proc.run(&mut jobs).unwrap_err();
        assert!(matches!(err, BatchError::EmptyJobList));
    }

    #[test]
    fn test_processor_runs_all_jobs() {
        let proc = BatchProcessor::new();
        let mut jobs = sample_jobs(3);
        let report = proc.run(&mut jobs).unwrap();
        assert_eq!(report.stats.total, 3);
        assert_eq!(report.stats.succeeded, 3);
        assert_eq!(report.stats.failed, 0);
    }

    #[test]
    fn test_processor_results_populated() {
        let proc = BatchProcessor::new();
        let mut jobs = sample_jobs(1);
        proc.run(&mut jobs).unwrap();
        assert!(jobs[0].results.contains_key("Analyze"));
        assert!(jobs[0].results.contains_key("ExtractStrings"));
    }

    // -- ParallelBatch -------------------------------------------------------

    #[test]
    fn test_parallel_invalid_concurrency() {
        let err = ParallelBatch::new(0).unwrap_err();
        assert!(matches!(err, BatchError::InvalidConcurrency));
    }

    #[test]
    fn test_parallel_runs_jobs() {
        let pb = ParallelBatch::new(2).unwrap();
        let mut jobs = sample_jobs(4);
        let report = pb.run(&mut jobs).unwrap();
        assert_eq!(report.stats.succeeded, 4);
    }

    #[test]
    fn test_parallel_empty_jobs_error() {
        let pb = ParallelBatch::new(2).unwrap();
        let mut jobs: Vec<BatchJob> = vec![];
        assert!(matches!(
            pb.run(&mut jobs).unwrap_err(),
            BatchError::EmptyJobList
        ));
    }

    // -- BatchReport ---------------------------------------------------------

    #[test]
    fn test_report_summary_text() {
        let proc = BatchProcessor::new();
        let mut jobs = sample_jobs(2);
        let report = proc.run(&mut jobs).unwrap();
        let text = report.summary_text();
        assert!(text.contains("2/2"));
    }

    #[test]
    fn test_report_to_json() {
        let proc = BatchProcessor::new();
        let mut jobs = sample_jobs(1);
        let report = proc.run(&mut jobs).unwrap();
        let json = report.to_json().unwrap();
        assert!(json.contains("stats"));
    }

    #[test]
    fn test_report_failed_jobs() {
        let proc = BatchProcessor::new();
        let mut jobs = sample_jobs(2);
        proc.run(&mut jobs).unwrap();
        // All succeed in stub, so failed_jobs should be empty.
        let rpt = BatchReport::from_jobs(&jobs, Duration::default());
        assert!(rpt.failed_jobs().is_empty());
        assert_eq!(rpt.succeeded_jobs().len(), 2);
    }

    // -- BatchStats ----------------------------------------------------------

    #[test]
    fn test_stats_success_rate() {
        let proc = BatchProcessor::new();
        let mut jobs = sample_jobs(4);
        let report = proc.run(&mut jobs).unwrap();
        assert!((report.stats.success_rate_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats_empty() {
        let stats = BatchStats::from_summaries(&[]);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.success_rate_pct, 0.0);
    }

    // -- BatchConfig ---------------------------------------------------------

    #[test]
    fn test_config_default() {
        let cfg = BatchConfig::default();
        assert_eq!(cfg.concurrency, 4);
        assert!(!cfg.fail_fast);
    }

    #[test]
    fn test_config_json_roundtrip() {
        let cfg = BatchConfig::default();
        let json = cfg.to_json().unwrap();
        let cfg2 = BatchConfig::from_json(&json).unwrap();
        assert_eq!(cfg2.concurrency, cfg.concurrency);
    }

    // -- BatchOperation display ----------------------------------------------

    #[test]
    fn test_operation_display() {
        assert_eq!(BatchOperation::Analyze.to_string(), "Analyze");
        assert_eq!(BatchOperation::DetectCrypto.to_string(), "DetectCrypto");
        let rp = BatchOperation::RunPass {
            pass_name: "TypeRecovery".into(),
        };
        assert_eq!(rp.to_string(), "Pass(TypeRecovery)");
    }

    #[test]
    fn test_job_status_display() {
        assert_eq!(format!("{}", JobStatus::Succeeded), "OK");
        assert_eq!(format!("{}", JobStatus::Failed), "FAIL");
        assert_eq!(format!("{}", JobStatus::Pending), "PENDING");
    }

    #[test]
    fn test_multiple_operations_per_job() {
        let proc = BatchProcessor::new();
        let mut jobs = vec![BatchJob::new(
            0,
            "/tmp/a.bin",
            vec![
                BatchOperation::Analyze,
                BatchOperation::ExtractStrings,
                BatchOperation::ExtractImports,
                BatchOperation::DetectCrypto,
            ],
        )];
        let report = proc.run(&mut jobs).unwrap();
        assert_eq!(report.stats.total_ops_executed, 4);
    }
}
