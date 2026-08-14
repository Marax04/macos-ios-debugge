//! Fuzz orchestrator: multi-job scheduling, clustering, resource limiting, pipeline,
//! and high-level campaign reporting for the `RustRE` fuzzing suite.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal,
    clippy::format_push_string,
    clippy::format_in_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::redundant_guards,
    clippy::map_unwrap_or,
    clippy::if_not_else,
    clippy::struct_excessive_bools,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::default_trait_access,
    clippy::wildcard_imports,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::needless_continue,
    clippy::implicit_hasher,
    clippy::ignored_unit_patterns,
    clippy::semicolon_if_nothing_returned,
    clippy::stable_sort_primitive,
    clippy::trivially_copy_pass_by_ref,
    clippy::ptr_as_ptr,
    clippy::ref_option,
    clippy::fn_params_excessive_bools,
    clippy::assigning_clones
)]
//!
//! # Structs
//! - [`FuzzJob`]           — a unit of fuzzing work
//! - [`FuzzCluster`]       — a group of co-located fuzzing workers
//! - [`JobScheduler`]      — assigns jobs to clusters
//! - [`ResourceLimiter`]   — enforces per-job CPU / memory / time quotas
//! - [`FuzzPipeline`]      — sequential stages applied to each job's output
//! - [`FuzzOrchestrator`]  — top-level coordinator
//! - [`OrchestratorReport`]— summary produced after a campaign

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CrashRecord, FuzzerStats};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the orchestrator subsystem.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("job {0} not found")]
    JobNotFound(u64),
    #[error("cluster {0} not found")]
    ClusterNotFound(u64),
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    #[error("pipeline stage failed: {stage} — {reason}")]
    PipelineStageFailed { stage: String, reason: String },
    #[error("no available cluster for job {0}")]
    NoClusterAvailable(u64),
    #[error("scheduler error: {0}")]
    Scheduler(String),
    #[error("orchestrator already running")]
    AlreadyRunning,
    #[error("orchestrator not running")]
    NotRunning,
}

// ─────────────────────────────────────────────────────────────────────────────
// JobState
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of a single fuzzing job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobState {
    /// Queued but not yet dispatched.
    Pending,
    /// Assigned to a cluster worker and actively running.
    Running,
    /// Finished successfully.
    Finished,
    /// Terminated abnormally (crash, OOM, timeout).
    Failed,
    /// Explicitly cancelled by the user or orchestrator.
    Cancelled,
    /// Paused (suspended, can be resumed).
    Paused,
}

impl std::fmt::Display for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Finished => write!(f, "finished"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Paused => write!(f, "paused"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JobPriority
// ─────────────────────────────────────────────────────────────────────────────

/// Priority class for job scheduling.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum JobPriority {
    Low = 0,
    #[default]
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for JobPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Normal => write!(f, "normal"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceLimits
// ─────────────────────────────────────────────────────────────────────────────

/// Per-job resource constraints.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceLimits {
    /// Maximum wall-clock runtime.
    pub max_duration: Option<Duration>,
    /// Maximum RSS in mebibytes (0 = unlimited).
    pub max_memory_mb: u64,
    /// Maximum number of target executions (0 = unlimited).
    pub max_executions: u64,
    /// Maximum input corpus size in MiB (0 = unlimited).
    pub max_corpus_mb: u64,
    /// Maximum number of unique crashes to collect before stopping.
    pub max_crashes: u64,
    /// Maximum CPU percentage allowed (1–100, 0 = unlimited).
    pub max_cpu_pct: u8,
}

impl ResourceLimits {
    /// Unlimited (no constraints).
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// A conservative default: 1 hour, 2 GiB RAM, 10 M execs.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            max_duration: Some(Duration::from_hours(1)),
            max_memory_mb: 2048,
            max_executions: 10_000_000,
            max_corpus_mb: 512,
            max_crashes: 100,
            max_cpu_pct: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzJob
// ─────────────────────────────────────────────────────────────────────────────

/// A single unit of fuzzing work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzJob {
    /// Unique job identifier.
    pub id: u64,
    /// Human-readable name.
    pub name: String,
    /// Target binary or harness identifier.
    pub target: String,
    /// Seed corpus paths.
    pub seeds: Vec<String>,
    /// Dictionary file paths.
    pub dictionaries: Vec<String>,
    /// Current lifecycle state.
    pub state: JobState,
    /// Scheduling priority.
    pub priority: JobPriority,
    /// Resource limits for this job.
    pub limits: ResourceLimits,
    /// Accumulated statistics (updated by the worker).
    pub stats: FuzzerStats,
    /// Crashes collected during this job.
    pub crashes: Vec<CrashRecord>,
    /// When the job was created.
    pub created_at: SystemTime,
    /// When the job started (if ever).
    pub started_at: Option<SystemTime>,
    /// When the job ended (if ever).
    pub ended_at: Option<SystemTime>,
    /// Cluster that this job was / is running on.
    pub assigned_cluster: Option<u64>,
    /// Free-form tags for categorisation.
    pub tags: Vec<String>,
    /// Extra metadata key → value.
    pub metadata: HashMap<String, String>,
}

impl FuzzJob {
    /// Create a new pending job.
    #[must_use]
    pub fn new(id: u64, name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            target: target.into(),
            seeds: Vec::new(),
            dictionaries: Vec::new(),
            state: JobState::Pending,
            priority: JobPriority::Normal,
            limits: ResourceLimits::default(),
            stats: FuzzerStats::new(),
            crashes: Vec::new(),
            created_at: SystemTime::now(),
            started_at: None,
            ended_at: None,
            assigned_cluster: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Builder: add a seed directory.
    #[must_use]
    pub fn with_seed(mut self, seed: impl Into<String>) -> Self {
        self.seeds.push(seed.into());
        self
    }

    /// Builder: set priority.
    #[must_use]
    pub const fn with_priority(mut self, p: JobPriority) -> Self {
        self.priority = p;
        self
    }

    /// Builder: set resource limits.
    #[must_use]
    pub const fn with_limits(mut self, l: ResourceLimits) -> Self {
        self.limits = l;
        self
    }

    /// Builder: add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Mark this job as running now.
    ///
    /// Guard: if the job has already been started (state != Pending) this is a
    /// no-op, preventing `start()` from being called twice and resetting
    /// `started_at` on a job that is already `Running` or terminal.
    pub fn start(&mut self) {
        if self.state != JobState::Pending {
            return;
        }
        self.state = JobState::Running;
        self.started_at = Some(SystemTime::now());
    }

    /// Mark this job as finished.
    pub fn finish(&mut self) {
        self.state = JobState::Finished;
        self.ended_at = Some(SystemTime::now());
    }

    /// Mark this job as failed.
    pub fn fail(&mut self) {
        self.state = JobState::Failed;
        self.ended_at = Some(SystemTime::now());
    }

    /// Mark this job as cancelled.
    pub fn cancel(&mut self) {
        self.state = JobState::Cancelled;
        self.ended_at = Some(SystemTime::now());
    }

    /// Wall-clock runtime, if started.
    #[must_use]
    pub fn runtime(&self) -> Option<Duration> {
        let start = self.started_at?;
        let end = self.ended_at.unwrap_or_else(SystemTime::now);
        end.duration_since(start).ok()
    }

    /// Returns `true` if the job is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            JobState::Finished | JobState::Failed | JobState::Cancelled
        )
    }

    /// Add a crash to this job's crash list.
    pub fn record_crash(&mut self, crash: CrashRecord) {
        self.crashes.push(crash);
        self.stats.crashes += 1;
    }

    /// Number of unique crashes (by dedup key).
    #[must_use]
    pub fn unique_crash_count(&self) -> usize {
        use std::collections::HashSet;
        self.crashes
            .iter()
            .map(super::CrashRecord::dedup_key)
            .collect::<HashSet<_>>()
            .len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClusterKind
// ─────────────────────────────────────────────────────────────────────────────

/// Cluster backend kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterKind {
    /// Local threads (single machine).
    Local,
    /// Remote SSH workers.
    Remote { host: String },
    /// Kubernetes pods.
    Kubernetes { namespace: String },
    /// Docker containers.
    Docker { image: String },
}

impl std::fmt::Display for ClusterKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Remote { host } => write!(f, "remote:{host}"),
            Self::Kubernetes { namespace } => write!(f, "k8s:{namespace}"),
            Self::Docker { image } => write!(f, "docker:{image}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzCluster
// ─────────────────────────────────────────────────────────────────────────────

/// A group of co-located fuzzing workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCluster {
    /// Unique cluster identifier.
    pub id: u64,
    /// Human-readable name.
    pub name: String,
    /// Backend kind.
    pub kind: ClusterKind,
    /// Number of worker slots.
    pub workers: u32,
    /// Jobs currently assigned to this cluster.
    pub active_jobs: Vec<u64>,
    /// Total jobs ever processed.
    pub completed_jobs: u64,
    /// Whether this cluster is available for new jobs.
    pub available: bool,
    /// CPU architecture tag (e.g. "`x86_64`", "aarch64").
    pub arch: String,
    /// Optional maximum number of simultaneously active jobs.
    pub max_concurrent: Option<u32>,
    /// Free-form labels.
    pub labels: HashMap<String, String>,
}

impl FuzzCluster {
    /// Create a new local cluster with `workers` threads.
    #[must_use]
    pub fn local(id: u64, name: impl Into<String>, workers: u32) -> Self {
        Self {
            id,
            name: name.into(),
            kind: ClusterKind::Local,
            workers,
            active_jobs: Vec::new(),
            completed_jobs: 0,
            available: true,
            arch: "x86_64".to_string(),
            max_concurrent: Some(workers),
            labels: HashMap::new(),
        }
    }

    /// Returns `true` when this cluster can accept at least one more job.
    #[must_use]
    pub fn can_accept_job(&self) -> bool {
        if !self.available {
            return false;
        }
        match self.max_concurrent {
            Some(max) => (u32::try_from(self.active_jobs.len()).unwrap_or(u32::MAX)) < max,
            None => true,
        }
    }

    /// Assign `job_id` to this cluster.  Returns `false` if at capacity.
    pub fn assign(&mut self, job_id: u64) -> bool {
        if !self.can_accept_job() {
            return false;
        }
        self.active_jobs.push(job_id);
        true
    }

    /// Release `job_id` from this cluster.
    pub fn release(&mut self, job_id: u64) {
        self.active_jobs.retain(|&id| id != job_id);
        self.completed_jobs += 1;
    }

    /// Current utilisation as a fraction `[0.0, 1.0]`.
    #[must_use]
    pub fn utilisation(&self) -> f64 {
        let cap = f64::from(self.max_concurrent.unwrap_or(self.workers));
        if cap <= 0.0 {
            return 0.0;
        }
        (self.active_jobs.len() as f64 / cap).min(1.0)
    }

    /// Number of free worker slots.
    #[must_use]
    pub fn free_slots(&self) -> u32 {
        let cap = self.max_concurrent.unwrap_or(self.workers);
        cap.saturating_sub(u32::try_from(self.active_jobs.len()).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SchedulingPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy used by the [`JobScheduler`] to assign jobs to clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SchedulingPolicy {
    /// Assign to the cluster with the most free slots.
    MaxFreeSlots,
    /// Simple round-robin across available clusters.
    RoundRobin,
    /// Assign highest-priority jobs first.
    PriorityFirst,
    /// Assign to the cluster with the lowest current utilisation.
    #[default]
    LeastLoaded,
}

// ─────────────────────────────────────────────────────────────────────────────
// JobScheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Assigns fuzzing jobs to clusters according to a configurable policy.
#[derive(Debug)]
pub struct JobScheduler {
    /// Active clusters (keyed by cluster id).
    pub clusters: HashMap<u64, FuzzCluster>,
    /// Pending job queue (by priority, then FIFO).
    queue: VecDeque<u64>,
    /// Scheduling policy.
    pub policy: SchedulingPolicy,
    /// Round-robin cursor.
    rr_cursor: usize,
    /// Total assignments made.
    pub total_assignments: u64,
    /// Total rejections (no cluster available).
    pub total_rejections: u64,
}

impl JobScheduler {
    /// Create a scheduler with the given policy.
    #[must_use]
    pub fn new(policy: SchedulingPolicy) -> Self {
        Self {
            clusters: HashMap::new(),
            queue: VecDeque::new(),
            policy,
            rr_cursor: 0,
            total_assignments: 0,
            total_rejections: 0,
        }
    }

    /// Register a cluster.
    pub fn add_cluster(&mut self, cluster: FuzzCluster) {
        self.clusters.insert(cluster.id, cluster);
    }

    /// Remove a cluster by id.
    pub fn remove_cluster(&mut self, id: u64) -> Option<FuzzCluster> {
        self.clusters.remove(&id)
    }

    /// Enqueue a job id for scheduling.
    pub fn enqueue(&mut self, job_id: u64) {
        self.queue.push_back(job_id);
    }

    /// Pop and assign the next queued job.
    /// Returns `(job_id, cluster_id)` if a suitable cluster is available,
    /// or `None` if all clusters are at capacity or the queue is empty.
    pub fn schedule_next(&mut self) -> Option<(u64, u64)> {
        if self.queue.is_empty() {
            return None;
        }
        let cluster_id = match self.pick_cluster() {
            Some(id) => id,
            None => {
                self.total_rejections += 1;
                return None;
            }
        };
        let job_id = self.queue.pop_front()?;
        let cluster = self.clusters.get_mut(&cluster_id)?;
        if cluster.assign(job_id) {
            self.total_assignments += 1;
            Some((job_id, cluster_id))
        } else {
            self.queue.push_front(job_id); // put back
            self.total_rejections += 1;
            None
        }
    }

    /// Schedule all pending jobs until no more assignments can be made.
    /// Returns a list of `(job_id, cluster_id)` pairs.
    pub fn schedule_all(&mut self) -> Vec<(u64, u64)> {
        let mut assignments = Vec::new();
        while let Some(pair) = self.schedule_next() {
            assignments.push(pair);
        }
        assignments
    }

    /// Notify the scheduler that `job_id` completed on `cluster_id`.
    pub fn complete(&mut self, job_id: u64, cluster_id: u64) {
        if let Some(c) = self.clusters.get_mut(&cluster_id) {
            c.release(job_id);
        }
    }

    /// Number of pending jobs in the queue.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Total active jobs across all clusters.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.clusters.values().map(|c| c.active_jobs.len()).sum()
    }

    fn pick_cluster(&mut self) -> Option<u64> {
        let available: Vec<u64> = self
            .clusters
            .values()
            .filter(|c| c.can_accept_job())
            .map(|c| c.id)
            .collect();
        if available.is_empty() {
            return None;
        }
        match self.policy {
            SchedulingPolicy::RoundRobin => {
                let idx = self.rr_cursor % available.len();
                self.rr_cursor = (self.rr_cursor + 1) % available.len();
                Some(available[idx])
            }
            SchedulingPolicy::MaxFreeSlots => available
                .into_iter()
                .max_by_key(|id| self.clusters[id].free_slots()),
            SchedulingPolicy::LeastLoaded | SchedulingPolicy::PriorityFirst => {
                available.into_iter().min_by(|a, b| {
                    self.clusters[a]
                        .utilisation()
                        .partial_cmp(&self.clusters[b].utilisation())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceLimiter
// ─────────────────────────────────────────────────────────────────────────────

/// Enforces per-job resource quotas and emits violations.
#[derive(Debug, Clone)]
pub struct ResourceLimiter {
    /// Current memory usage per job (MB).
    memory_usage: HashMap<u64, u64>,
    /// Execution count per job.
    exec_count: HashMap<u64, u64>,
    /// Start times per job.
    start_times: HashMap<u64, SystemTime>,
    /// Crash counts per job.
    crash_counts: HashMap<u64, u64>,
}

impl ResourceLimiter {
    /// Create an empty limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            memory_usage: HashMap::new(),
            exec_count: HashMap::new(),
            start_times: HashMap::new(),
            crash_counts: HashMap::new(),
        }
    }

    /// Register a job as started.
    pub fn register_start(&mut self, job_id: u64) {
        self.start_times.insert(job_id, SystemTime::now());
        self.exec_count.entry(job_id).or_insert(0);
        self.memory_usage.entry(job_id).or_insert(0);
        self.crash_counts.entry(job_id).or_insert(0);
    }

    /// Update memory usage for a job.
    pub fn update_memory(&mut self, job_id: u64, mb: u64) {
        self.memory_usage.insert(job_id, mb);
    }

    /// Record one execution for a job.
    pub fn record_execution(&mut self, job_id: u64) {
        *self.exec_count.entry(job_id).or_insert(0) += 1;
    }

    /// Record a crash for a job.
    pub fn record_crash(&mut self, job_id: u64) {
        *self.crash_counts.entry(job_id).or_insert(0) += 1;
    }

    /// Check whether `limits` are violated for `job_id`.
    ///
    /// Returns `Err(OrchestratorError::ResourceLimitExceeded)` on violation.
    pub fn check(&self, job_id: u64, limits: &ResourceLimits) -> Result<(), OrchestratorError> {
        // Duration
        if let Some(max_dur) = limits.max_duration
            && let Some(&start) = self.start_times.get(&job_id)
        {
            let elapsed = start.elapsed().unwrap_or_default();
            if elapsed > max_dur {
                return Err(OrchestratorError::ResourceLimitExceeded(format!(
                    "job {job_id} exceeded max duration {max_dur:?}"
                )));
            }
        }
        // Memory
        if limits.max_memory_mb > 0 {
            let used = self.memory_usage.get(&job_id).copied().unwrap_or(0);
            if used > limits.max_memory_mb {
                return Err(OrchestratorError::ResourceLimitExceeded(format!(
                    "job {job_id} memory {used} MB > limit {} MB",
                    limits.max_memory_mb
                )));
            }
        }
        // Executions
        if limits.max_executions > 0 {
            let done = self.exec_count.get(&job_id).copied().unwrap_or(0);
            if done >= limits.max_executions {
                return Err(OrchestratorError::ResourceLimitExceeded(format!(
                    "job {job_id} executions {done} >= limit {}",
                    limits.max_executions
                )));
            }
        }
        // Crashes
        if limits.max_crashes > 0 {
            let crashes = self.crash_counts.get(&job_id).copied().unwrap_or(0);
            if crashes >= limits.max_crashes {
                return Err(OrchestratorError::ResourceLimitExceeded(format!(
                    "job {job_id} crashes {crashes} >= limit {}",
                    limits.max_crashes
                )));
            }
        }
        Ok(())
    }

    /// Elapsed time for a job in seconds.
    #[must_use]
    pub fn elapsed_secs(&self, job_id: u64) -> f64 {
        self.start_times
            .get(&job_id)
            .and_then(|t| t.elapsed().ok())
            .map_or(0.0, |d| d.as_secs_f64())
    }

    /// Execution count for a job.
    #[must_use]
    pub fn exec_count(&self, job_id: u64) -> u64 {
        self.exec_count.get(&job_id).copied().unwrap_or(0)
    }

    /// Memory usage for a job.
    #[must_use]
    pub fn memory_mb(&self, job_id: u64) -> u64 {
        self.memory_usage.get(&job_id).copied().unwrap_or(0)
    }

    /// Deregister a finished job.
    pub fn deregister(&mut self, job_id: u64) {
        self.start_times.remove(&job_id);
        self.exec_count.remove(&job_id);
        self.memory_usage.remove(&job_id);
        self.crash_counts.remove(&job_id);
    }
}

impl Default for ResourceLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PipelineStage
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of processing a pipeline stage performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStageKind {
    /// Minimise inputs in the corpus.
    Minimise,
    /// Deduplicate crashes.
    DeduplicateCrashes,
    /// Export coverage data.
    ExportCoverage,
    /// Merge corpora from multiple jobs.
    MergeCorpora,
    /// Run a custom post-processor (name of the processor).
    Custom(String),
    /// Sync corpus to a remote store.
    SyncRemote,
    /// Analyse crashes with a symbolic executor.
    CrashAnalysis,
    /// Generate a human-readable report.
    Report,
}

impl std::fmt::Display for PipelineStageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimise => write!(f, "minimise"),
            Self::DeduplicateCrashes => write!(f, "dedup_crashes"),
            Self::ExportCoverage => write!(f, "export_coverage"),
            Self::MergeCorpora => write!(f, "merge_corpora"),
            Self::Custom(n) => write!(f, "custom:{n}"),
            Self::SyncRemote => write!(f, "sync_remote"),
            Self::CrashAnalysis => write!(f, "crash_analysis"),
            Self::Report => write!(f, "report"),
        }
    }
}

/// One stage in a fuzzing pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    /// Stage identifier.
    pub id: u64,
    /// Human-readable label.
    pub name: String,
    /// Kind of processing this stage performs.
    pub kind: PipelineStageKind,
    /// Whether this stage is enabled.
    pub enabled: bool,
    /// Extra key-value options.
    pub options: HashMap<String, String>,
    /// Whether a failure in this stage should abort the pipeline.
    pub abort_on_failure: bool,
}

impl PipelineStage {
    /// Create an enabled stage.
    #[must_use]
    pub fn new(id: u64, name: impl Into<String>, kind: PipelineStageKind) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            enabled: true,
            options: HashMap::new(),
            abort_on_failure: true,
        }
    }

    /// Set an option.
    #[must_use]
    pub fn with_option(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.options.insert(key.into(), val.into());
        self
    }

    /// Do not abort the pipeline on failure.
    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.abort_on_failure = false;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PipelineResult
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of executing one pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage_id: u64,
    pub stage_name: String,
    pub success: bool,
    pub message: String,
    pub duration: Duration,
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// An ordered sequence of post-processing stages applied to fuzzing job output.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FuzzPipeline {
    /// Ordered stages.
    pub stages: Vec<PipelineStage>,
    /// Results from the most recent execution.
    pub last_results: Vec<StageResult>,
    /// Total pipeline runs.
    pub run_count: u64,
}

impl FuzzPipeline {
    /// Create an empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a stage.
    pub fn add_stage(&mut self, stage: PipelineStage) {
        self.stages.push(stage);
    }

    /// Insert a stage at a specific position.
    pub fn insert_stage(&mut self, pos: usize, stage: PipelineStage) {
        self.stages.insert(pos.min(self.stages.len()), stage);
    }

    /// Remove a stage by id.  Returns `true` if one was found.
    pub fn remove_stage(&mut self, stage_id: u64) -> bool {
        let before = self.stages.len();
        self.stages.retain(|s| s.id != stage_id);
        self.stages.len() != before
    }

    /// Enable/disable a stage by id.
    pub fn set_stage_enabled(&mut self, stage_id: u64, enabled: bool) {
        if let Some(s) = self.stages.iter_mut().find(|s| s.id == stage_id) {
            s.enabled = enabled;
        }
    }

    /// Execute the pipeline for a given job.
    ///
    /// Stages are simulated; in production each stage would invoke a real
    /// sub-system.  Returns the list of stage results.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::PipelineStageFailed`] if a critical stage
    /// fails.
    pub fn execute(&mut self, job: &FuzzJob) -> Result<Vec<StageResult>, OrchestratorError> {
        self.run_count += 1;
        let mut results = Vec::new();
        for stage in &self.stages {
            if !stage.enabled {
                continue;
            }
            let start = std::time::Instant::now();
            // Simulate stage execution (succeed always in this model).
            let success = true;
            let message = format!(
                "stage '{}' completed for job '{}' ({} crashes)",
                stage.name,
                job.name,
                job.crashes.len()
            );
            let duration = start.elapsed();
            let result = StageResult {
                stage_id: stage.id,
                stage_name: stage.name.clone(),
                success,
                message,
                duration,
            };
            if !success && stage.abort_on_failure {
                self.last_results = results.clone();
                return Err(OrchestratorError::PipelineStageFailed {
                    stage: stage.name.clone(),
                    reason: "simulated failure".into(),
                });
            }
            results.push(result);
        }
        self.last_results = results.clone();
        Ok(results)
    }

    /// Number of enabled stages.
    #[must_use]
    pub fn enabled_stage_count(&self) -> usize {
        self.stages.iter().filter(|s| s.enabled).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OrchestratorReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report produced after a campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorReport {
    /// Campaign name.
    pub campaign_name: String,
    /// When the report was generated.
    pub generated_at: SystemTime,
    /// Total jobs submitted.
    pub total_jobs: u64,
    /// Jobs that completed successfully.
    pub finished_jobs: u64,
    /// Jobs that failed.
    pub failed_jobs: u64,
    /// Jobs that were cancelled.
    pub cancelled_jobs: u64,
    /// Total target executions across all jobs.
    pub total_executions: u64,
    /// Total unique crashes across all jobs.
    pub total_unique_crashes: u64,
    /// Aggregate executions per second.
    pub avg_exec_per_sec: f64,
    /// Peak memory usage across all jobs (MB).
    pub peak_memory_mb: u64,
    /// Total campaign wall-clock duration.
    pub total_duration: Duration,
    /// Per-job summaries.
    pub job_summaries: Vec<JobSummary>,
    /// Pipeline results from the post-processing phase.
    pub pipeline_results: Vec<StageResult>,
    /// Free-form notes.
    pub notes: String,
}

/// Per-job summary entry in a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSummary {
    pub id: u64,
    pub name: String,
    pub state: JobState,
    pub executions: u64,
    pub unique_crashes: usize,
    pub runtime_secs: f64,
    pub corpus_size: u64,
}

impl OrchestratorReport {
    /// Build a report from the orchestrator state.
    #[must_use]
    pub fn build(
        campaign_name: &str,
        jobs: &[FuzzJob],
        pipeline_results: Vec<StageResult>,
        total_duration: Duration,
    ) -> Self {
        let total_jobs = jobs.len() as u64;
        let finished_jobs = jobs
            .iter()
            .filter(|j| j.state == JobState::Finished)
            .count() as u64;
        let failed_jobs = jobs.iter().filter(|j| j.state == JobState::Failed).count() as u64;
        let cancelled_jobs = jobs
            .iter()
            .filter(|j| j.state == JobState::Cancelled)
            .count() as u64;
        let total_executions: u64 = jobs.iter().map(|j| j.stats.executions).sum();
        let total_unique_crashes: u64 = jobs.iter().map(|j| j.unique_crash_count() as u64).sum();
        let secs = total_duration.as_secs_f64();
        let avg_exec_per_sec = if secs > 0.0 {
            total_executions as f64 / secs
        } else {
            0.0
        };

        let job_summaries = jobs
            .iter()
            .map(|j| JobSummary {
                id: j.id,
                name: j.name.clone(),
                state: j.state,
                executions: j.stats.executions,
                unique_crashes: j.unique_crash_count(),
                runtime_secs: j.runtime().map_or(0.0, |d| d.as_secs_f64()),
                corpus_size: j.stats.corpus_size,
            })
            .collect();

        Self {
            campaign_name: campaign_name.to_string(),
            generated_at: SystemTime::now(),
            total_jobs,
            finished_jobs,
            failed_jobs,
            cancelled_jobs,
            total_executions,
            total_unique_crashes,
            avg_exec_per_sec,
            peak_memory_mb: 0,
            total_duration,
            job_summaries,
            pipeline_results,
            notes: String::new(),
        }
    }

    /// Success rate: finished / total (0.0–1.0).
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_jobs == 0 {
            return 1.0;
        }
        self.finished_jobs as f64 / self.total_jobs as f64
    }

    /// Crash density: crashes / 1 M executions.
    #[must_use]
    pub fn crash_density(&self) -> f64 {
        if self.total_executions == 0 {
            return 0.0;
        }
        self.total_unique_crashes as f64 / (self.total_executions as f64 / 1_000_000.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuzzOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level campaign coordinator.
///
/// Manages job lifecycle, cluster assignment, resource limits, and pipeline
/// execution for an entire fuzzing campaign.
pub struct FuzzOrchestrator {
    /// Campaign name.
    pub name: String,
    /// All jobs (pending + active + terminal).
    pub jobs: HashMap<u64, FuzzJob>,
    /// Job scheduler.
    pub scheduler: JobScheduler,
    /// Resource limiter.
    pub limiter: ResourceLimiter,
    /// Post-processing pipeline.
    pub pipeline: FuzzPipeline,
    /// Next job id.
    next_job_id: u64,
    /// Whether the orchestrator is actively running.
    pub running: bool,
    /// Campaign start time.
    pub started_at: Option<SystemTime>,
    /// Campaign end time.
    pub ended_at: Option<SystemTime>,
}

impl FuzzOrchestrator {
    /// Create a new orchestrator for campaign `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            jobs: HashMap::new(),
            scheduler: JobScheduler::new(SchedulingPolicy::LeastLoaded),
            limiter: ResourceLimiter::new(),
            pipeline: FuzzPipeline::new(),
            next_job_id: 1,
            running: false,
            started_at: None,
            ended_at: None,
        }
    }

    /// Register a cluster with the scheduler.
    pub fn add_cluster(&mut self, cluster: FuzzCluster) {
        self.scheduler.add_cluster(cluster);
    }

    /// Submit a new job.  Returns the assigned job id.
    pub fn submit_job(&mut self, mut job: FuzzJob) -> u64 {
        let id = self.next_job_id;
        self.next_job_id += 1;
        job.id = id;
        self.scheduler.enqueue(id);
        self.jobs.insert(id, job);
        id
    }

    /// Start the orchestrator campaign.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::AlreadyRunning`] if already started.
    pub fn start(&mut self) -> Result<(), OrchestratorError> {
        if self.running {
            return Err(OrchestratorError::AlreadyRunning);
        }
        self.running = true;
        self.started_at = Some(SystemTime::now());
        Ok(())
    }

    /// Stop the campaign.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::NotRunning`] if not running.
    pub fn stop(&mut self) -> Result<(), OrchestratorError> {
        if !self.running {
            return Err(OrchestratorError::NotRunning);
        }
        self.running = false;
        self.ended_at = Some(SystemTime::now());
        Ok(())
    }

    /// Schedule as many pending jobs as possible.  Returns assignment pairs.
    pub fn tick(&mut self) -> Vec<(u64, u64)> {
        let assignments = self.scheduler.schedule_all();
        for &(job_id, cluster_id) in &assignments {
            if let Some(job) = self.jobs.get_mut(&job_id) {
                job.start();
                job.assigned_cluster = Some(cluster_id);
                self.limiter.register_start(job_id);
            }
        }
        assignments
    }

    /// Signal that job `job_id` has completed.  Runs the pipeline.
    ///
    /// # Errors
    /// Propagates pipeline errors.
    pub fn complete_job(
        &mut self,
        job_id: u64,
        cluster_id: u64,
    ) -> Result<Vec<StageResult>, OrchestratorError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(OrchestratorError::JobNotFound(job_id))?;
        job.finish();
        let cluster_id = job.assigned_cluster.unwrap_or(cluster_id);
        self.scheduler.complete(job_id, cluster_id);
        self.limiter.deregister(job_id);

        // Clone job for pipeline (pipeline needs shared &FuzzJob)
        let job_clone = self.jobs[&job_id].clone();
        self.pipeline.execute(&job_clone)
    }

    /// Cancel a job.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::JobNotFound`] if not found.
    pub fn cancel_job(&mut self, job_id: u64) -> Result<(), OrchestratorError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(OrchestratorError::JobNotFound(job_id))?;
        job.cancel();
        if let Some(cid) = job.assigned_cluster {
            self.scheduler.complete(job_id, cid);
        }
        self.limiter.deregister(job_id);
        Ok(())
    }

    /// Check resource limits for all running jobs; cancel any that exceeded limits.
    pub fn enforce_limits(&mut self) -> Vec<u64> {
        let running: Vec<(u64, ResourceLimits)> = self
            .jobs
            .values()
            .filter(|j| j.state == JobState::Running)
            .map(|j| (j.id, j.limits.clone()))
            .collect();

        let mut cancelled = Vec::new();
        for (job_id, limits) in running {
            if self.limiter.check(job_id, &limits).is_err() {
                let _ = self.cancel_job(job_id);
                cancelled.push(job_id);
            }
        }
        cancelled
    }

    /// Build a final campaign report.
    #[must_use]
    pub fn report(&self) -> OrchestratorReport {
        let duration = match (self.started_at, self.ended_at) {
            (Some(s), Some(e)) => e.duration_since(s).unwrap_or_default(),
            (Some(s), None) => s.elapsed().unwrap_or_default(),
            _ => Duration::ZERO,
        };
        let jobs: Vec<FuzzJob> = self.jobs.values().cloned().collect();
        OrchestratorReport::build(
            &self.name,
            &jobs,
            self.pipeline.last_results.clone(),
            duration,
        )
    }

    /// Number of jobs in each state.
    #[must_use]
    pub fn job_state_counts(&self) -> HashMap<JobState, usize> {
        let mut counts = HashMap::new();
        for job in self.jobs.values() {
            *counts.entry(job.state).or_insert(0) += 1;
        }
        counts
    }

    /// Lookup a job by id.
    #[must_use]
    pub fn get_job(&self, id: u64) -> Option<&FuzzJob> {
        self.jobs.get(&id)
    }

    /// All jobs in the given state.
    #[must_use]
    pub fn jobs_in_state(&self, state: JobState) -> Vec<&FuzzJob> {
        self.jobs.values().filter(|j| j.state == state).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_job(name: &str) -> FuzzJob {
        FuzzJob::new(0, name, "target/fuzz")
    }

    fn make_cluster() -> FuzzCluster {
        FuzzCluster::local(1, "local-1", 4)
    }

    // ── JobState ─────────────────────────────────────────────────────────────

    #[test]
    fn job_state_display() {
        assert_eq!(JobState::Pending.to_string(), "pending");
        assert_eq!(JobState::Running.to_string(), "running");
        assert_eq!(JobState::Finished.to_string(), "finished");
        assert_eq!(JobState::Failed.to_string(), "failed");
        assert_eq!(JobState::Cancelled.to_string(), "cancelled");
        assert_eq!(JobState::Paused.to_string(), "paused");
    }

    #[test]
    fn job_priority_ordering() {
        assert!(JobPriority::Critical > JobPriority::High);
        assert!(JobPriority::High > JobPriority::Normal);
        assert!(JobPriority::Normal > JobPriority::Low);
    }

    // ── ResourceLimits ────────────────────────────────────────────────────────

    #[test]
    fn resource_limits_default_unlimited() {
        let l = ResourceLimits::unlimited();
        assert!(l.max_duration.is_none());
        assert_eq!(l.max_memory_mb, 0);
        assert_eq!(l.max_executions, 0);
    }

    #[test]
    fn resource_limits_conservative() {
        let l = ResourceLimits::conservative();
        assert!(l.max_duration.is_some());
        assert!(l.max_memory_mb > 0);
    }

    // ── FuzzJob ───────────────────────────────────────────────────────────────

    #[test]
    fn fuzz_job_new_pending() {
        let j = make_job("test");
        assert_eq!(j.state, JobState::Pending);
        assert!(j.crashes.is_empty());
    }

    #[test]
    fn fuzz_job_start_finish() {
        let mut j = make_job("j1");
        j.start();
        assert_eq!(j.state, JobState::Running);
        assert!(j.started_at.is_some());
        j.finish();
        assert_eq!(j.state, JobState::Finished);
        assert!(j.ended_at.is_some());
    }

    #[test]
    fn fuzz_job_cancel() {
        let mut j = make_job("j2");
        j.start();
        j.cancel();
        assert_eq!(j.state, JobState::Cancelled);
        assert!(j.is_terminal());
    }

    #[test]
    fn fuzz_job_fail() {
        let mut j = make_job("j3");
        j.start();
        j.fail();
        assert_eq!(j.state, JobState::Failed);
        assert!(j.is_terminal());
    }

    #[test]
    fn fuzz_job_pending_not_terminal() {
        let j = make_job("j4");
        assert!(!j.is_terminal());
    }

    #[test]
    fn fuzz_job_with_seed_and_priority() {
        let j = make_job("j5")
            .with_seed("/corpus")
            .with_priority(JobPriority::High)
            .with_tag("afl");
        assert_eq!(j.seeds, vec!["/corpus"]);
        assert_eq!(j.priority, JobPriority::High);
        assert_eq!(j.tags, vec!["afl"]);
    }

    #[test]
    fn fuzz_job_unique_crashes() {
        let mut j = make_job("j6");
        let cr = CrashRecord::new(0, vec![0xCC], 11, Some(0xdead), 0xAABB);
        j.record_crash(cr.clone());
        j.record_crash(cr);
        // Both have the same dedup_key → 1 unique.
        assert_eq!(j.unique_crash_count(), 1);
    }

    #[test]
    fn fuzz_job_runtime_none_if_not_started() {
        let j = make_job("j7");
        assert!(j.runtime().is_none());
    }

    #[test]
    fn fuzz_job_runtime_some_if_started() {
        let mut j = make_job("j8");
        j.start();
        assert!(j.runtime().is_some());
    }

    // ── FuzzCluster ───────────────────────────────────────────────────────────

    #[test]
    fn cluster_can_accept_job() {
        let c = make_cluster();
        assert!(c.can_accept_job());
        assert_eq!(c.free_slots(), 4);
    }

    #[test]
    fn cluster_assign_and_release() {
        let mut c = make_cluster();
        assert!(c.assign(1));
        assert_eq!(c.active_jobs.len(), 1);
        c.release(1);
        assert!(c.active_jobs.is_empty());
        assert_eq!(c.completed_jobs, 1);
    }

    #[test]
    fn cluster_at_capacity() {
        let mut c = FuzzCluster::local(1, "c", 1);
        assert!(c.assign(1));
        assert!(!c.can_accept_job());
        assert!(!c.assign(2));
    }

    #[test]
    fn cluster_utilisation() {
        let mut c = FuzzCluster::local(1, "c", 4);
        c.assign(1);
        c.assign(2);
        assert!((c.utilisation() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn cluster_unavailable() {
        let mut c = make_cluster();
        c.available = false;
        assert!(!c.can_accept_job());
    }

    // ── JobScheduler ──────────────────────────────────────────────────────────

    #[test]
    fn scheduler_schedule_one_job() {
        let mut sched = JobScheduler::new(SchedulingPolicy::LeastLoaded);
        sched.add_cluster(make_cluster());
        sched.enqueue(42);
        let pair = sched.schedule_next();
        assert!(pair.is_some());
        let (job_id, _) = pair.unwrap();
        assert_eq!(job_id, 42);
    }

    #[test]
    fn scheduler_empty_queue_returns_none() {
        let mut sched = JobScheduler::new(SchedulingPolicy::LeastLoaded);
        sched.add_cluster(make_cluster());
        assert!(sched.schedule_next().is_none());
    }

    #[test]
    fn scheduler_no_cluster_returns_none() {
        let mut sched = JobScheduler::new(SchedulingPolicy::LeastLoaded);
        sched.enqueue(1);
        assert!(sched.schedule_next().is_none());
        assert_eq!(sched.total_rejections, 1);
    }

    #[test]
    fn scheduler_schedule_all() {
        let mut sched = JobScheduler::new(SchedulingPolicy::MaxFreeSlots);
        sched.add_cluster(FuzzCluster::local(1, "c", 3));
        for i in 1u64..=3 {
            sched.enqueue(i);
        }
        let assignments = sched.schedule_all();
        assert_eq!(assignments.len(), 3);
    }

    #[test]
    fn scheduler_round_robin() {
        let mut sched = JobScheduler::new(SchedulingPolicy::RoundRobin);
        sched.add_cluster(FuzzCluster::local(1, "a", 4));
        sched.add_cluster(FuzzCluster::local(2, "b", 4));
        sched.enqueue(1);
        let r = sched.schedule_next();
        assert!(r.is_some());
    }

    #[test]
    fn scheduler_complete_releases_slot() {
        let mut sched = JobScheduler::new(SchedulingPolicy::LeastLoaded);
        sched.add_cluster(FuzzCluster::local(1, "c", 1));
        sched.enqueue(1);
        let (j, c) = sched.schedule_next().unwrap();
        sched.complete(j, c);
        sched.enqueue(2);
        assert!(sched.schedule_next().is_some());
    }

    // ── ResourceLimiter ───────────────────────────────────────────────────────

    #[test]
    fn limiter_exec_tracking() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        lim.record_execution(1);
        lim.record_execution(1);
        assert_eq!(lim.exec_count(1), 2);
    }

    #[test]
    fn limiter_memory_tracking() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        lim.update_memory(1, 512);
        assert_eq!(lim.memory_mb(1), 512);
    }

    #[test]
    fn limiter_check_within_limits() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        lim.record_execution(1);
        let limits = ResourceLimits {
            max_executions: 10,
            ..Default::default()
        };
        assert!(lim.check(1, &limits).is_ok());
    }

    #[test]
    fn limiter_check_exec_limit_exceeded() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        for _ in 0..5 {
            lim.record_execution(1);
        }
        let limits = ResourceLimits {
            max_executions: 5,
            ..Default::default()
        };
        assert!(lim.check(1, &limits).is_err());
    }

    #[test]
    fn limiter_check_memory_exceeded() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        lim.update_memory(1, 3000);
        let limits = ResourceLimits {
            max_memory_mb: 2048,
            ..Default::default()
        };
        assert!(lim.check(1, &limits).is_err());
    }

    #[test]
    fn limiter_check_crash_limit() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        lim.record_crash(1);
        let limits = ResourceLimits {
            max_crashes: 1,
            ..Default::default()
        };
        assert!(lim.check(1, &limits).is_err());
    }

    #[test]
    fn limiter_deregister() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        lim.deregister(1);
        assert_eq!(lim.exec_count(1), 0);
    }

    #[test]
    fn limiter_elapsed_positive_after_start() {
        let mut lim = ResourceLimiter::new();
        lim.register_start(1);
        assert!(lim.elapsed_secs(1) >= 0.0);
    }

    // ── FuzzPipeline ──────────────────────────────────────────────────────────

    #[test]
    fn pipeline_add_and_execute() {
        let mut p = FuzzPipeline::new();
        p.add_stage(PipelineStage::new(1, "min", PipelineStageKind::Minimise));
        p.add_stage(PipelineStage::new(
            2,
            "dedup",
            PipelineStageKind::DeduplicateCrashes,
        ));
        let job = make_job("j");
        let results = p.execute(&job).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(p.run_count, 1);
    }

    #[test]
    fn pipeline_disabled_stage_skipped() {
        let mut p = FuzzPipeline::new();
        p.add_stage(PipelineStage::new(1, "s", PipelineStageKind::Report));
        p.set_stage_enabled(1, false);
        let results = p.execute(&make_job("j")).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn pipeline_remove_stage() {
        let mut p = FuzzPipeline::new();
        p.add_stage(PipelineStage::new(1, "s1", PipelineStageKind::Report));
        p.add_stage(PipelineStage::new(2, "s2", PipelineStageKind::Report));
        assert!(p.remove_stage(1));
        assert_eq!(p.stages.len(), 1);
    }

    #[test]
    fn pipeline_enabled_count() {
        let mut p = FuzzPipeline::new();
        p.add_stage(PipelineStage::new(1, "s1", PipelineStageKind::Report));
        p.add_stage(PipelineStage::new(2, "s2", PipelineStageKind::Report));
        p.set_stage_enabled(1, false);
        assert_eq!(p.enabled_stage_count(), 1);
    }

    #[test]
    fn pipeline_stage_options() {
        let s = PipelineStage::new(1, "s", PipelineStageKind::Custom("x".into()))
            .with_option("key", "val");
        assert_eq!(s.options.get("key"), Some(&"val".to_string()));
    }

    // ── OrchestratorReport ────────────────────────────────────────────────────

    #[test]
    fn report_success_rate_all_finished() {
        let mut j1 = make_job("j1");
        j1.finish();
        let mut j2 = make_job("j2");
        j2.finish();
        let report = OrchestratorReport::build("c", &[j1, j2], vec![], Duration::from_secs(60));
        assert!((report.success_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn report_success_rate_partial() {
        let mut j1 = make_job("j1");
        j1.finish();
        let mut j2 = make_job("j2");
        j2.fail();
        let report = OrchestratorReport::build("c", &[j1, j2], vec![], Duration::from_secs(60));
        assert!((report.success_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn report_crash_density() {
        let mut j = make_job("j");
        j.stats.executions = 1_000_000;
        let cr = CrashRecord::new(0, vec![], 11, None, 0xAB);
        j.crashes.push(cr);
        let report = OrchestratorReport::build("c", &[j], vec![], Duration::from_secs(1));
        assert!((report.crash_density() - 1.0).abs() < 1e-6);
    }

    // ── FuzzOrchestrator ──────────────────────────────────────────────────────

    #[test]
    fn orchestrator_submit_and_tick() {
        let mut orch = FuzzOrchestrator::new("campaign");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        let id = orch.submit_job(make_job("j"));
        let pairs = orch.tick();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, id);
    }

    #[test]
    fn orchestrator_already_running_error() {
        let mut orch = FuzzOrchestrator::new("c");
        orch.start().unwrap();
        assert!(orch.start().is_err());
    }

    #[test]
    fn orchestrator_not_running_stop_error() {
        let mut orch = FuzzOrchestrator::new("c");
        assert!(orch.stop().is_err());
    }

    #[test]
    fn orchestrator_cancel_job() {
        let mut orch = FuzzOrchestrator::new("c");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        let id = orch.submit_job(make_job("j"));
        orch.tick();
        orch.cancel_job(id).unwrap();
        assert_eq!(orch.get_job(id).unwrap().state, JobState::Cancelled);
    }

    #[test]
    fn orchestrator_cancel_unknown_job() {
        let mut orch = FuzzOrchestrator::new("c");
        assert!(matches!(
            orch.cancel_job(999),
            Err(OrchestratorError::JobNotFound(999))
        ));
    }

    #[test]
    fn orchestrator_complete_job() {
        let mut orch = FuzzOrchestrator::new("c");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        let id = orch.submit_job(make_job("j"));
        let pairs = orch.tick();
        let cluster_id = pairs[0].1;
        let results = orch.complete_job(id, cluster_id).unwrap();
        assert!(results.is_empty()); // no pipeline stages added
        assert_eq!(orch.get_job(id).unwrap().state, JobState::Finished);
    }

    #[test]
    fn orchestrator_enforce_limits() {
        let mut orch = FuzzOrchestrator::new("c");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        let id = orch.submit_job(make_job("j").with_limits(ResourceLimits {
            max_executions: 1,
            ..Default::default()
        }));
        orch.tick();
        // Simulate exceeding the exec limit
        for _ in 0..5 {
            orch.limiter.record_execution(id);
        }
        let cancelled = orch.enforce_limits();
        assert!(cancelled.contains(&id));
    }

    #[test]
    fn orchestrator_report_summary() {
        let mut orch = FuzzOrchestrator::new("my-campaign");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        orch.submit_job(make_job("j1"));
        orch.tick();
        orch.stop().unwrap();
        let report = orch.report();
        assert_eq!(report.campaign_name, "my-campaign");
        assert_eq!(report.total_jobs, 1);
    }

    #[test]
    fn orchestrator_jobs_in_state() {
        let mut orch = FuzzOrchestrator::new("c");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        orch.submit_job(make_job("j1"));
        orch.submit_job(make_job("j2"));
        orch.tick(); // assigns both
        assert_eq!(orch.jobs_in_state(JobState::Running).len(), 2);
    }

    #[test]
    fn orchestrator_job_state_counts() {
        let mut orch = FuzzOrchestrator::new("c");
        orch.add_cluster(make_cluster());
        orch.start().unwrap();
        orch.submit_job(make_job("j1"));
        orch.tick();
        let counts = orch.job_state_counts();
        assert!(counts.get(&JobState::Running).copied().unwrap_or(0) > 0);
    }
}
