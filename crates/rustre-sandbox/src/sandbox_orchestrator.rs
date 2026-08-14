//! `sandbox_orchestrator` — Sandbox job orchestration and scheduling.
//!
//! Provides [`SandboxOrchestrator`] which manages a pool of sandboxes via
//! [`SandboxCluster`].  Jobs are submitted as [`SandboxJob`]s with a
//! [`JobPriority`], queued by [`JobScheduler`], and their results aggregated
//! by [`ResultAggregator`].

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    #[error("job not found: {0}")]
    JobNotFound(u64),
    #[error("sandbox not found: {0}")]
    SandboxNotFound(u64),
    #[error("scheduler full: capacity {0}")]
    SchedulerFull(usize),
    #[error("no available sandbox")]
    NoAvailableSandbox,
    #[error("job already completed: {0}")]
    AlreadyCompleted(u64),
    #[error("cluster error: {0}")]
    ClusterError(String),
    #[error("aggregator error: {0}")]
    AggregatorError(String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

// ─── JobPriority ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JobPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for JobPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── JobState ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── SandboxJob ───────────────────────────────────────────────────────────────

/// A unit of work to be executed inside a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxJob {
    pub id: u64,
    pub priority: JobPriority,
    pub state: JobState,
    pub sample_path: PathBuf,
    pub timeout_secs: u64,
    pub tags: Vec<String>,
    pub created_at_ms: u64,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub sandbox_id: Option<u64>,
    pub error: Option<String>,
}

impl SandboxJob {
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()
            .min(u128::from(u64::MAX))
            .try_into()
            .unwrap_or(u64::MAX)
    }

    #[must_use] 
    pub fn new(id: u64, sample_path: PathBuf, priority: JobPriority) -> Self {
        Self {
            id,
            priority,
            state: JobState::Pending,
            sample_path,
            timeout_secs: 120,
            tags: Vec::new(),
            created_at_ms: Self::now_ms(),
            started_at_ms: None,
            finished_at_ms: None,
            sandbox_id: None,
            error: None,
        }
    }

    #[must_use] 
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use] 
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            JobState::Completed | JobState::Failed | JobState::Cancelled | JobState::TimedOut
        )
    }

    #[must_use] 
    pub const fn duration_ms(&self) -> Option<u64> {
        match (self.started_at_ms, self.finished_at_ms) {
            (Some(s), Some(f)) => Some(f.saturating_sub(s)),
            _ => None,
        }
    }

    pub fn mark_started(&mut self, sandbox_id: u64) {
        self.state = JobState::Running;
        self.sandbox_id = Some(sandbox_id);
        self.started_at_ms = Some(Self::now_ms());
    }

    pub fn mark_completed(&mut self) {
        self.state = JobState::Completed;
        self.finished_at_ms = Some(Self::now_ms());
    }

    pub fn mark_failed(&mut self, err: impl Into<String>) {
        self.state = JobState::Failed;
        self.error = Some(err.into());
        self.finished_at_ms = Some(Self::now_ms());
    }

    pub fn mark_cancelled(&mut self) {
        self.state = JobState::Cancelled;
        self.finished_at_ms = Some(Self::now_ms());
    }
}

// Priority queue ordering wrapper
#[derive(Debug)]
struct PendingJob {
    priority: JobPriority,
    created_at_ms: u64,
    id: u64,
}

impl PartialEq for PendingJob {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PendingJob {}

impl PartialOrd for PendingJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then older job first (lower timestamp)
        self.priority
            .cmp(&other.priority)
            .then(other.created_at_ms.cmp(&self.created_at_ms))
    }
}

// ─── JobScheduler ─────────────────────────────────────────────────────────────

/// Priority-queue-based job scheduler.
#[derive(Debug)]
pub struct JobScheduler {
    queue: Mutex<BinaryHeap<PendingJob>>,
    capacity: usize,
    enqueued: AtomicU64,
    dequeued: AtomicU64,
}

impl JobScheduler {
    #[must_use] 
    pub const fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(BinaryHeap::new()),
            capacity,
            enqueued: AtomicU64::new(0),
            dequeued: AtomicU64::new(0),
        }
    }

    /// # Errors
    /// Returns [`OrchestratorError::SchedulerFull`] when the queue is at capacity.
    pub fn enqueue(&self, job: &SandboxJob) -> Result<(), OrchestratorError> {
        {
            let mut q = self.queue.lock();
            if q.len() >= self.capacity {
                return Err(OrchestratorError::SchedulerFull(self.capacity));
            }
            q.push(PendingJob {
                priority: job.priority,
                created_at_ms: job.created_at_ms,
                id: job.id,
            });
        }
        self.enqueued.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(())
    }

    /// Pop the next job ID to run.
    pub fn pop_next(&self) -> Option<u64> {
        let id = self.queue.lock().pop().map(|j| j.id);
        if id.is_some() {
            self.dequeued.fetch_add(1, AtomicOrdering::Relaxed);
        }
        id
    }

    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn total_enqueued(&self) -> u64 {
        self.enqueued.load(AtomicOrdering::Relaxed)
    }

    pub fn total_dequeued(&self) -> u64 {
        self.dequeued.load(AtomicOrdering::Relaxed)
    }
}

// ─── SandboxInstance ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxStatus {
    Idle,
    Busy,
    Draining,
    Offline,
}

/// Represents one sandbox instance in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInstance {
    pub id: u64,
    pub status: SandboxStatus,
    pub current_job: Option<u64>,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub uptime_ms: u64,
}

impl SandboxInstance {
    #[must_use] 
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            status: SandboxStatus::Idle,
            current_job: None,
            jobs_completed: 0,
            jobs_failed: 0,
            uptime_ms: 0,
        }
    }

    #[must_use] 
    pub fn is_available(&self) -> bool {
        self.status == SandboxStatus::Idle
    }

    pub const fn assign(&mut self, job_id: u64) {
        self.status = SandboxStatus::Busy;
        self.current_job = Some(job_id);
    }

    pub const fn release(&mut self, success: bool) {
        self.status = SandboxStatus::Idle;
        self.current_job = None;
        if success {
            self.jobs_completed += 1;
        } else {
            self.jobs_failed += 1;
        }
    }
}

// ─── SandboxCluster ───────────────────────────────────────────────────────────

/// Pool of sandbox instances.
#[derive(Debug)]
pub struct SandboxCluster {
    instances: RwLock<HashMap<u64, SandboxInstance>>,
    next_id: AtomicU64,
}

impl SandboxCluster {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    #[must_use] 
    pub fn with_capacity(n: usize) -> Self {
        let cluster = Self::new();
        for _ in 0..n {
            cluster.add_instance();
        }
        cluster
    }

    pub fn add_instance(&self) -> u64 {
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        self.instances.write().insert(id, SandboxInstance::new(id));
        id
    }

    /// # Errors
    /// Returns [`OrchestratorError::SandboxNotFound`] if `id` is unknown.
    pub fn remove_instance(&self, id: u64) -> Result<(), OrchestratorError> {
        self.instances
            .write()
            .remove(&id)
            .ok_or(OrchestratorError::SandboxNotFound(id))?;
        Ok(())
    }

    pub fn get(&self, id: u64) -> Option<SandboxInstance> {
        self.instances.read().get(&id).cloned()
    }

    pub fn pick_available(&self) -> Option<u64> {
        self.instances
            .read()
            .values()
            .find(|s| s.is_available())
            .map(|s| s.id)
    }

    /// # Errors
    /// Returns [`OrchestratorError::SandboxNotFound`] if `sandbox_id` is unknown.
    pub fn assign_job(&self, sandbox_id: u64, job_id: u64) -> Result<(), OrchestratorError> {
        self.instances
            .write()
            .get_mut(&sandbox_id)
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?
            .assign(job_id);
        Ok(())
    }

    /// # Errors
    /// Returns [`OrchestratorError::SandboxNotFound`] if `sandbox_id` is unknown.
    pub fn release_sandbox(&self, sandbox_id: u64, success: bool) -> Result<(), OrchestratorError> {
        self.instances
            .write()
            .get_mut(&sandbox_id)
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?
            .release(success);
        Ok(())
    }

    pub fn total_count(&self) -> usize {
        self.instances.read().len()
    }

    pub fn idle_count(&self) -> usize {
        self.instances
            .read()
            .values()
            .filter(|s| s.is_available())
            .count()
    }

    pub fn busy_count(&self) -> usize {
        self.instances
            .read()
            .values()
            .filter(|s| s.status == SandboxStatus::Busy)
            .count()
    }

    pub fn all_instances(&self) -> Vec<SandboxInstance> {
        self.instances.read().values().cloned().collect()
    }
}

impl Default for SandboxCluster {
    fn default() -> Self {
        Self::new()
    }
}

// ─── JobResult ────────────────────────────────────────────────────────────────

/// Outcome of a completed sandbox job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: u64,
    pub success: bool,
    pub iocs: Vec<String>,
    pub dropped_files: Vec<PathBuf>,
    pub network_connections: Vec<String>,
    pub behavior_summary: String,
    pub score: f32,
}

impl JobResult {
    #[must_use] 
    pub const fn success(job_id: u64) -> Self {
        Self {
            job_id,
            success: true,
            iocs: Vec::new(),
            dropped_files: Vec::new(),
            network_connections: Vec::new(),
            behavior_summary: String::new(),
            score: 0.0,
        }
    }

    #[must_use] 
    pub fn failure(job_id: u64) -> Self {
        Self {
            success: false,
            ..Self::success(job_id)
        }
    }

    #[must_use] 
    pub fn is_malicious(&self) -> bool {
        self.score >= 7.0
    }

    #[must_use] 
    pub const fn ioc_count(&self) -> usize {
        self.iocs.len()
    }
}

// ─── ResultAggregator ─────────────────────────────────────────────────────────

/// Collects and summarizes job results.
#[derive(Debug, Default)]
pub struct ResultAggregator {
    results: Mutex<HashMap<u64, JobResult>>,
    total_processed: AtomicU64,
    total_malicious: AtomicU64,
}

impl ResultAggregator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, result: JobResult) {
        self.total_processed.fetch_add(1, AtomicOrdering::Relaxed);
        if result.is_malicious() {
            self.total_malicious.fetch_add(1, AtomicOrdering::Relaxed);
        }
        self.results.lock().insert(result.job_id, result);
    }

    pub fn get(&self, job_id: u64) -> Option<JobResult> {
        self.results.lock().get(&job_id).cloned()
    }

    pub fn all_results(&self) -> Vec<JobResult> {
        self.results.lock().values().cloned().collect()
    }

    pub fn malicious_results(&self) -> Vec<JobResult> {
        self.results
            .lock()
            .values()
            .filter(|r| r.is_malicious())
            .cloned()
            .collect()
    }

    pub fn total_processed(&self) -> u64 {
        self.total_processed.load(AtomicOrdering::Relaxed)
    }

    pub fn total_malicious(&self) -> u64 {
        self.total_malicious.load(AtomicOrdering::Relaxed)
    }

    pub fn malicious_rate(&self) -> f64 {
        let t = self.total_processed();
        if t == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.total_malicious()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(t).unwrap_or(u32::MAX))
        }
    }

    pub fn top_ioc_counts(&self, n: usize) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self
            .results
            .lock()
            .values()
            .map(|r| (r.job_id, r.ioc_count()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// ─── SandboxOrchestrator ──────────────────────────────────────────────────────

/// Central orchestrator: accepts jobs, schedules them to sandboxes, collects results.
#[derive(Debug)]
pub struct SandboxOrchestrator {
    jobs: RwLock<HashMap<u64, SandboxJob>>,
    scheduler: JobScheduler,
    cluster: Arc<SandboxCluster>,
    aggregator: Arc<ResultAggregator>,
    next_job_id: AtomicU64,
    running: Mutex<bool>,
}

impl SandboxOrchestrator {
    #[must_use] 
    pub fn new(scheduler_capacity: usize, sandbox_count: usize) -> Self {
        Self {
            jobs: RwLock::new(HashMap::new()),
            scheduler: JobScheduler::new(scheduler_capacity),
            cluster: Arc::new(SandboxCluster::with_capacity(sandbox_count)),
            aggregator: Arc::new(ResultAggregator::new()),
            next_job_id: AtomicU64::new(1),
            running: Mutex::new(false),
        }
    }

    pub fn start(&self) {
        *self.running.lock() = true;
    }

    pub fn stop(&self) {
        *self.running.lock() = false;
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock()
    }

    // ── Job management ────────────────────────────────────────────────────

    /// # Errors
    /// Returns [`OrchestratorError::SchedulerFull`] if the scheduler queue is full.
    pub fn submit_job(
        &self,
        sample_path: PathBuf,
        priority: JobPriority,
    ) -> Result<u64, OrchestratorError> {
        let id = self.next_job_id.fetch_add(1, AtomicOrdering::Relaxed);
        let job = SandboxJob::new(id, sample_path, priority);
        self.scheduler.enqueue(&job)?;
        self.jobs.write().insert(id, job);
        Ok(id)
    }

    /// # Errors
    /// Returns [`OrchestratorError::JobNotFound`] or [`OrchestratorError::AlreadyCompleted`].
    pub fn cancel_job(&self, id: u64) -> Result<(), OrchestratorError> {
        let job = &mut *self.jobs.write();
        let job = job
            .get_mut(&id)
            .ok_or(OrchestratorError::JobNotFound(id))?;
        if job.is_terminal() {
            return Err(OrchestratorError::AlreadyCompleted(id));
        }
        job.mark_cancelled();
        Ok(())
    }

    pub fn get_job(&self, id: u64) -> Option<SandboxJob> {
        self.jobs.read().get(&id).cloned()
    }

    pub fn jobs_by_state(&self, state: JobState) -> Vec<SandboxJob> {
        self.jobs
            .read()
            .values()
            .filter(|j| j.state == state)
            .cloned()
            .collect()
    }

    /// Simulate dispatching the next pending job (synchronous).
    ///
    /// # Errors
    /// Returns [`OrchestratorError::NoAvailableSandbox`] when the scheduler or
    /// cluster has nothing available, or propagates errors from
    /// [`SandboxCluster::assign_job`] / [`Self::complete_job`].
    pub fn dispatch_next(&self) -> Result<u64, OrchestratorError> {
        let job_id = self
            .scheduler
            .pop_next()
            .ok_or(OrchestratorError::NoAvailableSandbox)?;

        let sandbox_id = self
            .cluster
            .pick_available()
            .ok_or(OrchestratorError::NoAvailableSandbox)?;

        // Check job wasn't cancelled
        {
            let jobs = self.jobs.read();
            if let Some(job) = jobs.get(&job_id)
                && job.state == JobState::Cancelled {
                    return Err(OrchestratorError::JobNotFound(job_id));
                }
        }

        self.cluster.assign_job(sandbox_id, job_id)?;
        {
            let mut jobs = self.jobs.write();
            if let Some(job) = jobs.get_mut(&job_id) {
                job.mark_started(sandbox_id);
            }
        }

        // Simulate immediate completion
        self.complete_job(job_id, true)?;

        Ok(job_id)
    }

    /// # Errors
    /// Returns [`OrchestratorError::JobNotFound`] if `job_id` is unknown, or
    /// propagates errors from [`SandboxCluster::release_sandbox`].
    pub fn complete_job(&self, job_id: u64, success: bool) -> Result<(), OrchestratorError> {
        let sandbox_id = {
            let jobs = self.jobs.read();
            jobs.get(&job_id)
                .ok_or(OrchestratorError::JobNotFound(job_id))?
                .sandbox_id
        };

        if let Some(sb_id) = sandbox_id {
            self.cluster.release_sandbox(sb_id, success)?;
        }

        self.jobs.write().get_mut(&job_id).map_or(
            Err(OrchestratorError::JobNotFound(job_id)),
            |job| {
                if success { job.mark_completed(); } else { job.mark_failed("simulation failure"); }
                Ok(())
            },
        )?;

        let result = if success {
            JobResult::success(job_id)
        } else {
            JobResult::failure(job_id)
        };
        self.aggregator.add(result);

        Ok(())
    }

    // ── Cluster / stats ───────────────────────────────────────────────────

    pub fn cluster(&self) -> &SandboxCluster {
        &self.cluster
    }

    pub fn aggregator(&self) -> &ResultAggregator {
        &self.aggregator
    }

    pub const fn scheduler(&self) -> &JobScheduler {
        &self.scheduler
    }

    pub fn total_jobs(&self) -> usize {
        self.jobs.read().len()
    }

    pub fn pending_count(&self) -> usize {
        self.scheduler.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_orch() -> SandboxOrchestrator {
        let o = SandboxOrchestrator::new(256, 4);
        o.start();
        o
    }

    fn sample() -> PathBuf {
        PathBuf::from("/tmp/sample.exe")
    }

    // --- JobPriority ---

    #[test]
    fn test_priority_ordering() {
        assert!(JobPriority::Critical > JobPriority::High);
        assert!(JobPriority::High > JobPriority::Normal);
        assert!(JobPriority::Normal > JobPriority::Low);
    }

    // --- SandboxJob ---

    #[test]
    fn test_job_new() {
        let j = SandboxJob::new(1, sample(), JobPriority::Normal);
        assert_eq!(j.id, 1);
        assert_eq!(j.state, JobState::Pending);
        assert!(!j.is_terminal());
    }

    #[test]
    fn test_job_mark_started() {
        let mut j = SandboxJob::new(1, sample(), JobPriority::Normal);
        j.mark_started(42);
        assert_eq!(j.state, JobState::Running);
        assert_eq!(j.sandbox_id, Some(42));
    }

    #[test]
    fn test_job_mark_completed() {
        let mut j = SandboxJob::new(1, sample(), JobPriority::Normal);
        j.mark_started(1);
        j.mark_completed();
        assert_eq!(j.state, JobState::Completed);
        assert!(j.is_terminal());
        assert!(j.duration_ms().is_some());
    }

    #[test]
    fn test_job_mark_failed() {
        let mut j = SandboxJob::new(1, sample(), JobPriority::Normal);
        j.mark_failed("timeout");
        assert_eq!(j.state, JobState::Failed);
        assert!(j.error.is_some());
    }

    #[test]
    fn test_job_mark_cancelled() {
        let mut j = SandboxJob::new(1, sample(), JobPriority::Normal);
        j.mark_cancelled();
        assert_eq!(j.state, JobState::Cancelled);
    }

    #[test]
    fn test_job_with_timeout_tag() {
        let j = SandboxJob::new(1, sample(), JobPriority::Low)
            .with_timeout(300)
            .with_tag("malware")
            .with_tag("x64");
        assert_eq!(j.timeout_secs, 300);
        assert_eq!(j.tags.len(), 2);
    }

    // --- JobScheduler ---

    #[test]
    fn test_scheduler_enqueue_dequeue() {
        let sched = JobScheduler::new(10);
        let j = SandboxJob::new(1, sample(), JobPriority::Normal);
        sched.enqueue(&j).unwrap();
        assert_eq!(sched.len(), 1);
        let id = sched.pop_next().unwrap();
        assert_eq!(id, 1);
        assert!(sched.is_empty());
    }

    #[test]
    fn test_scheduler_priority_order() {
        let sched = JobScheduler::new(10);
        let j_low = SandboxJob::new(1, sample(), JobPriority::Low);
        let j_crit = SandboxJob::new(2, sample(), JobPriority::Critical);
        sched.enqueue(&j_low).unwrap();
        sched.enqueue(&j_crit).unwrap();
        assert_eq!(sched.pop_next(), Some(2)); // Critical first
        assert_eq!(sched.pop_next(), Some(1));
    }

    #[test]
    fn test_scheduler_full() {
        let sched = JobScheduler::new(1);
        sched
            .enqueue(&SandboxJob::new(1, sample(), JobPriority::Normal))
            .unwrap();
        assert!(matches!(
            sched.enqueue(&SandboxJob::new(2, sample(), JobPriority::Normal)),
            Err(OrchestratorError::SchedulerFull(1))
        ));
    }

    #[test]
    fn test_scheduler_stats() {
        let sched = JobScheduler::new(10);
        sched
            .enqueue(&SandboxJob::new(1, sample(), JobPriority::Normal))
            .unwrap();
        sched.pop_next();
        assert_eq!(sched.total_enqueued(), 1);
        assert_eq!(sched.total_dequeued(), 1);
    }

    // --- SandboxCluster ---

    #[test]
    fn test_cluster_add_instance() {
        let cluster = SandboxCluster::new();
        let id = cluster.add_instance();
        assert!(cluster.get(id).is_some());
        assert_eq!(cluster.total_count(), 1);
        assert_eq!(cluster.idle_count(), 1);
    }

    #[test]
    fn test_cluster_with_capacity() {
        let cluster = SandboxCluster::with_capacity(3);
        assert_eq!(cluster.total_count(), 3);
        assert_eq!(cluster.idle_count(), 3);
    }

    #[test]
    fn test_cluster_assign_and_release() {
        let cluster = SandboxCluster::with_capacity(1);
        let sb_id = cluster.pick_available().unwrap();
        cluster.assign_job(sb_id, 42).unwrap();
        assert_eq!(cluster.busy_count(), 1);
        cluster.release_sandbox(sb_id, true).unwrap();
        assert_eq!(cluster.idle_count(), 1);
    }

    #[test]
    fn test_cluster_no_available_when_all_busy() {
        let cluster = SandboxCluster::with_capacity(1);
        let id = cluster.pick_available().unwrap();
        cluster.assign_job(id, 1).unwrap();
        assert!(cluster.pick_available().is_none());
    }

    #[test]
    fn test_cluster_remove_instance() {
        let cluster = SandboxCluster::with_capacity(2);
        let ids: Vec<u64> = cluster.all_instances().iter().map(|i| i.id).collect();
        cluster.remove_instance(ids[0]).unwrap();
        assert_eq!(cluster.total_count(), 1);
    }

    // --- ResultAggregator ---

    #[test]
    fn test_aggregator_add_and_get() {
        let agg = ResultAggregator::new();
        agg.add(JobResult::success(1));
        assert!(agg.get(1).is_some());
        assert_eq!(agg.total_processed(), 1);
    }

    #[test]
    fn test_aggregator_malicious() {
        let agg = ResultAggregator::new();
        let mut r = JobResult::success(1);
        r.score = 9.0;
        agg.add(r);
        assert_eq!(agg.total_malicious(), 1);
        assert!(!agg.malicious_results().is_empty());
    }

    #[test]
    fn test_aggregator_malicious_rate() {
        let agg = ResultAggregator::new();
        agg.add(JobResult::success(1)); // not malicious
        let mut r2 = JobResult::success(2);
        r2.score = 8.0;
        agg.add(r2);
        assert!((agg.malicious_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_aggregator_top_ioc_counts() {
        let agg = ResultAggregator::new();
        let mut r = JobResult::success(1);
        r.iocs = vec!["ioc1".into(), "ioc2".into()];
        agg.add(r);
        let top = agg.top_ioc_counts(1);
        assert_eq!(top[0].1, 2);
    }

    // --- SandboxOrchestrator ---

    #[test]
    fn test_orchestrator_submit_and_dispatch() {
        let orch = make_orch();
        let id = orch.submit_job(sample(), JobPriority::Normal).unwrap();
        orch.dispatch_next().unwrap();
        let job = orch.get_job(id).unwrap();
        assert_eq!(job.state, JobState::Completed);
    }

    #[test]
    fn test_orchestrator_cancel_pending() {
        let orch = make_orch();
        let id = orch.submit_job(sample(), JobPriority::Low).unwrap();
        orch.cancel_job(id).unwrap();
        let job = orch.get_job(id).unwrap();
        assert_eq!(job.state, JobState::Cancelled);
    }

    #[test]
    fn test_orchestrator_cancel_completed_errors() {
        let orch = make_orch();
        let id = orch.submit_job(sample(), JobPriority::Normal).unwrap();
        orch.dispatch_next().unwrap();
        assert!(matches!(
            orch.cancel_job(id),
            Err(OrchestratorError::AlreadyCompleted(_))
        ));
    }

    #[test]
    fn test_orchestrator_empty_scheduler_errors() {
        let orch = make_orch();
        assert!(matches!(
            orch.dispatch_next(),
            Err(OrchestratorError::NoAvailableSandbox)
        ));
    }

    #[test]
    fn test_orchestrator_stats() {
        let orch = make_orch();
        orch.submit_job(sample(), JobPriority::Normal).unwrap();
        assert_eq!(orch.total_jobs(), 1);
        assert_eq!(orch.pending_count(), 1);
    }

    #[test]
    fn test_orchestrator_aggregator_updated() {
        let orch = make_orch();
        orch.submit_job(sample(), JobPriority::Normal).unwrap();
        orch.dispatch_next().unwrap();
        assert_eq!(orch.aggregator().total_processed(), 1);
    }

    #[test]
    fn test_job_result_is_malicious() {
        let mut r = JobResult::success(1);
        r.score = 7.5;
        assert!(r.is_malicious());
        r.score = 6.9;
        assert!(!r.is_malicious());
    }

    #[test]
    fn test_job_priority_display() {
        assert_eq!(JobPriority::Critical.to_string(), "Critical");
        assert_eq!(JobPriority::Low.to_string(), "Low");
    }

    #[test]
    fn test_job_state_display() {
        assert_eq!(JobState::Pending.to_string(), "Pending");
        assert_eq!(JobState::Completed.to_string(), "Completed");
    }

    #[test]
    fn test_sandbox_status_is_available() {
        assert!(SandboxInstance::new(1).is_available());
        let mut inst = SandboxInstance::new(1);
        inst.assign(42);
        assert!(!inst.is_available());
    }

    #[test]
    fn test_sandbox_instance_release_failure() {
        let cluster = SandboxCluster::with_capacity(1);
        let id = cluster.pick_available().unwrap();
        cluster.assign_job(id, 1).unwrap();
        cluster.release_sandbox(id, false).unwrap();
        let inst = cluster.get(id).unwrap();
        assert_eq!(inst.jobs_failed, 1);
        assert_eq!(inst.jobs_completed, 0);
    }

    #[test]
    fn test_orchestrator_jobs_by_state() {
        let orch = make_orch();
        orch.submit_job(sample(), JobPriority::Normal).unwrap();
        let pending = orch.jobs_by_state(JobState::Pending);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_orchestrator_multiple_dispatches() {
        let orch = make_orch();
        for _ in 0..3 {
            orch.submit_job(sample(), JobPriority::Normal).unwrap();
        }
        for _ in 0..3 {
            orch.dispatch_next().unwrap();
        }
        assert_eq!(orch.aggregator().total_processed(), 3);
    }

    #[test]
    fn test_aggregator_all_results() {
        let agg = ResultAggregator::new();
        agg.add(JobResult::success(1));
        agg.add(JobResult::success(2));
        assert_eq!(agg.all_results().len(), 2);
    }

    #[test]
    fn test_job_duration_none_before_start() {
        let j = SandboxJob::new(1, sample(), JobPriority::Normal);
        assert!(j.duration_ms().is_none());
    }

    #[test]
    fn test_orchestrator_start_stop() {
        let orch = SandboxOrchestrator::new(10, 2);
        assert!(!orch.is_running());
        orch.start();
        assert!(orch.is_running());
        orch.stop();
        assert!(!orch.is_running());
    }
}
