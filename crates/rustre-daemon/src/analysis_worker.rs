//! `analysis_worker` — Background analysis worker pool.
//!
//! # Overview
//!
//! [`WorkQueue`] is a thread-safe priority work queue.  Each item is an
//! [`AnalysisJob`] carrying the binary to analyse and the desired depth.
//! One or more worker threads dequeue jobs, execute them (stub: real analysis
//! would delegate to `rustre-analysis`), and publish [`JobResult`]s via a
//! [`crossbeam_channel`]-style channel.
//!
//! Jobs can be cancelled via [`CancellationToken`] before or during execution.
//! Progress is reported through a `progress_tx` sender cloned per job.
//!
//! # Thread model
//!
//! ```text
//!  caller ──► WorkQueue::push()
//!                   │
//!                   ▼
//!           shared VecDeque sorted by Priority
//!                   │
//!                   ▼ (condvar wakeup)
//!           Worker thread N ──► JobResult channel ──► caller recv()
//! ```

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── JobId ─────────────────────────────────────────────────────────────────────

/// Unique identifier for a queued analysis job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(String);

impl JobId {
    /// Create a job id from a string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Generate a pseudo-unique job id.
    #[must_use]
    pub fn generate() -> Self {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self(format!("job-{ns:x}"))
    }

    /// Return the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── JobPriority ───────────────────────────────────────────────────────────────

/// Priority level for queued analysis jobs.
///
/// Higher numeric value = higher priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[derive(Default)]
pub enum JobPriority {
    /// Low priority — batch / background work.
    Low = 1,
    /// Normal priority — interactive analysis requests.
    #[default]
    Normal = 5,
    /// High priority — user-facing foreground requests.
    High = 10,
    /// Critical — pre-empts all other work.
    Critical = 100,
}


impl fmt::Display for JobPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

// ── AnalysisJob ───────────────────────────────────────────────────────────────

/// A unit of analysis work to be processed by a worker thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJob {
    /// Unique identifier for this job.
    pub id: JobId,
    /// Path to the binary file to analyse.
    pub binary_path: PathBuf,
    /// Optionally link this job to an existing session.
    pub session_id: Option<String>,
    /// Whether to perform deep (expensive) analysis.
    pub deep: bool,
    /// Priority in the work queue.
    pub priority: JobPriority,
    /// Epoch timestamp when the job was created.
    pub created_at: u64,
    /// Optional timeout in seconds (0 = no timeout).
    pub timeout_secs: u64,
}

impl AnalysisJob {
    /// Create an analysis job with default priority.
    #[must_use]
    pub fn new(binary_path: PathBuf) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            id: JobId::generate(),
            binary_path,
            session_id: None,
            deep: false,
            priority: JobPriority::Normal,
            created_at,
            timeout_secs: 0,
        }
    }

    /// Set the session id.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Enable deep analysis.
    #[must_use]
    pub const fn with_deep(mut self, deep: bool) -> Self {
        self.deep = deep;
        self
    }

    /// Set the priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: JobPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set a timeout in seconds.
    #[must_use]
    pub const fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

// Internal wrapper that implements Ord for the BinaryHeap (max-heap by priority
// then FIFO by insertion order using a sequence counter).
struct PrioritisedJob {
    job: AnalysisJob,
    seq: u64,
}

impl PartialEq for PrioritisedJob {
    fn eq(&self, other: &Self) -> bool {
        self.job.priority == other.job.priority && self.seq == other.seq
    }
}

impl Eq for PrioritisedJob {}

impl PartialOrd for PrioritisedJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritisedJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first; for equal priority, lower seq first (FIFO).
        match self.job.priority.cmp(&other.job.priority) {
            Ordering::Equal => other.seq.cmp(&self.seq), // lower seq = arrived earlier
            ord => ord,
        }
    }
}

// ── CancellationToken ─────────────────────────────────────────────────────────

/// A cheap clone-able token that can be used to cancel an in-flight job.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl CancellationToken {
    /// Create a new uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal cancellation.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Return `true` if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ── ProgressReport ────────────────────────────────────────────────────────────

/// A progress update emitted by a worker during job execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressReport {
    /// The job this report belongs to.
    pub job_id: JobId,
    /// Completion percentage in `[0, 100]`.
    pub percent: u8,
    /// Human-readable phase name.
    pub phase: String,
    /// Optional structured extra data.
    pub data: Option<serde_json::Value>,
}

impl ProgressReport {
    /// Create a progress report.
    #[must_use]
    pub fn new(job_id: JobId, percent: u8, phase: impl Into<String>) -> Self {
        Self {
            job_id,
            percent: percent.min(100),
            phase: phase.into(),
            data: None,
        }
    }
}

// ── JobResult ─────────────────────────────────────────────────────────────────

/// The outcome of a completed (or failed/cancelled) analysis job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// The id of the job that produced this result.
    pub job_id: JobId,
    /// Session the job was associated with, if any.
    pub session_id: Option<String>,
    /// Whether the job completed without error.
    pub success: bool,
    /// Human-readable status message.
    pub message: String,
    /// Duration the job took to run.
    pub elapsed_ms: u64,
    /// Function count discovered (stub).
    pub function_count: usize,
    /// String count discovered (stub).
    pub string_count: usize,
    /// Whether the job was cancelled.
    pub cancelled: bool,
    /// Error detail if `success == false`.
    pub error: Option<String>,
}

impl JobResult {
    /// Build a successful result.
    #[must_use]
    pub fn success(job_id: JobId, session_id: Option<String>, elapsed_ms: u64) -> Self {
        Self {
            job_id,
            session_id,
            success: true,
            message: "analysis complete".into(),
            elapsed_ms,
            function_count: 0,
            string_count: 0,
            cancelled: false,
            error: None,
        }
    }

    /// Build a failed result.
    #[must_use]
    pub fn failure(
        job_id: JobId,
        session_id: Option<String>,
        elapsed_ms: u64,
        error: impl Into<String>,
    ) -> Self {
        let err = error.into();
        Self {
            job_id,
            session_id,
            success: false,
            message: "analysis failed".into(),
            elapsed_ms,
            function_count: 0,
            string_count: 0,
            cancelled: false,
            error: Some(err),
        }
    }

    /// Build a cancelled result.
    #[must_use]
    pub fn cancelled(job_id: JobId, session_id: Option<String>, elapsed_ms: u64) -> Self {
        Self {
            job_id,
            session_id,
            success: false,
            message: "analysis cancelled".into(),
            elapsed_ms,
            function_count: 0,
            string_count: 0,
            cancelled: true,
            error: None,
        }
    }
}

// ── WorkQueue ─────────────────────────────────────────────────────────────────

/// Shared inner state of the work queue.
struct QueueInner {
    heap: BinaryHeap<PrioritisedJob>,
    next_seq: u64,
    shutdown: bool,
}

/// A thread-safe priority work queue for [`AnalysisJob`]s.
///
/// Clone cheaply — all clones share the same backing state.
#[derive(Clone)]
pub struct WorkQueue {
    inner: Arc<(Mutex<QueueInner>, Condvar)>,
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkQueue {
    /// Create a new empty work queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new((
                Mutex::new(QueueInner {
                    heap: BinaryHeap::new(),
                    next_seq: 0,
                    shutdown: false,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Enqueue a job.  Returns the assigned sequence number.
    #[must_use] 
    pub fn push(&self, job: AnalysisJob) -> u64 {
        let (lock, cvar) = &*self.inner;
        let mut inner = lock.lock().expect("WorkQueue mutex poisoned");
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.heap.push(PrioritisedJob { job, seq });
        cvar.notify_one();
        seq
    }

    /// Pop the highest-priority job, blocking until one is available or the
    /// queue is shut down.
    ///
    /// Returns `None` when the queue is shut down and empty.
    #[must_use] 
    pub fn pop(&self) -> Option<AnalysisJob> {
        let (lock, cvar) = &*self.inner;
        let mut inner = lock.lock().expect("WorkQueue mutex poisoned");
        loop {
            if let Some(pj) = inner.heap.pop() {
                return Some(pj.job);
            }
            if inner.shutdown {
                return None;
            }
            inner = cvar.wait(inner).expect("WorkQueue condvar wait poisoned");
        }
    }

    /// Non-blocking pop — returns `None` immediately if empty.
    #[must_use]
    pub fn try_pop(&self) -> Option<AnalysisJob> {
        let (lock, _) = &*self.inner;
        lock.lock().ok()?.heap.pop().map(|pj| pj.job)
    }

    /// Return the current depth of the queue (pending jobs only).
    #[must_use]
    pub fn len(&self) -> usize {
        let (lock, _) = &*self.inner;
        lock.lock().map(|g| g.heap.len()).unwrap_or(0)
    }

    /// Return `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Signal the queue to shut down.  Blocked [`WorkQueue::pop`] calls will
    /// wake up and return `None`.
    pub fn shutdown(&self) {
        let (lock, cvar) = &*self.inner;
        if let Ok(mut inner) = lock.lock() {
            inner.shutdown = true;
            cvar.notify_all();
        }
    }
}

// ── WorkerPool ────────────────────────────────────────────────────────────────

/// Statistics for the worker pool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerPoolStats {
    /// Total jobs that completed successfully.
    pub jobs_succeeded: u64,
    /// Total jobs that failed.
    pub jobs_failed: u64,
    /// Total jobs that were cancelled.
    pub jobs_cancelled: u64,
    /// Total jobs dispatched (all outcomes).
    pub jobs_total: u64,
}

impl WorkerPoolStats {
    /// Return the number of still-pending jobs in the queue.
    #[must_use]
    pub const fn pending(&self) -> u64 {
        // Computed externally; here it's informational only.
        0
    }
}

/// A pool of worker threads that drain a [`WorkQueue`].
///
/// Results are sent through a `std::sync::mpsc` channel.  Call
/// [`WorkerPool::result_receiver`] to get a receiver.
pub struct WorkerPool {
    queue: WorkQueue,
    pub result_tx: std::sync::mpsc::Sender<JobResult>,
    result_rx: Option<std::sync::mpsc::Receiver<JobResult>>,
    pub progress_tx: std::sync::mpsc::Sender<ProgressReport>,
    progress_rx: Option<std::sync::mpsc::Receiver<ProgressReport>>,
    stats: Arc<Mutex<WorkerPoolStats>>,
    handles: Vec<thread::JoinHandle<()>>,
    token: CancellationToken,
}

impl WorkerPool {
    /// Create a pool with `workers` background threads.
    ///
    /// # Panics
    /// Panics if `workers == 0`.
    #[must_use]
    pub fn new(workers: usize) -> Self {
        assert!(
            workers > 0,
            "WorkerPool requires at least one worker thread"
        );

        let queue = WorkQueue::new();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        let stats = Arc::new(Mutex::new(WorkerPoolStats::default()));
        let token = CancellationToken::new();
        let mut handles = Vec::with_capacity(workers);

        for worker_id in 0..workers {
            let q = queue.clone();
            let tx = result_tx.clone();
            let ptx = progress_tx.clone();
            let sts = stats.clone();
            let tok = token.clone();

            let handle = thread::Builder::new()
                .name(format!("rustre-worker-{worker_id}"))
                .spawn(move || {
                    worker_loop(worker_id, q, tx, ptx, sts, tok);
                })
                .expect("spawn worker thread");

            handles.push(handle);
        }

        Self {
            queue,
            result_tx,
            result_rx: Some(result_rx),
            progress_tx,
            progress_rx: Some(progress_rx),
            stats,
            handles,
            token,
        }
    }

    /// Submit a job to the work queue.  Returns the internal sequence number.
    #[must_use] 
    pub fn submit(&self, job: AnalysisJob) -> u64 {
        self.queue.push(job)
    }

    /// Take ownership of the result channel receiver.
    ///
    /// May only be called once; returns `None` on subsequent calls.
    #[must_use]
    pub const fn result_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<JobResult>> {
        self.result_rx.take()
    }

    /// Take ownership of the progress channel receiver.
    ///
    /// May only be called once; returns `None` on subsequent calls.
    #[must_use]
    pub const fn progress_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<ProgressReport>> {
        self.progress_rx.take()
    }

    /// Return a snapshot of pool statistics.
    #[must_use]
    pub fn stats(&self) -> WorkerPoolStats {
        self.stats.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Return the number of jobs currently waiting in the queue.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    /// Signal all workers to stop after finishing their current job, then join
    /// every worker thread.
    pub fn shutdown(self) {
        self.token.cancel();
        self.queue.shutdown();
        for h in self.handles {
            let _ = h.join();
        }
    }
}

// ── Worker loop ───────────────────────────────────────────────────────────────

fn worker_loop(
    _worker_id: usize,
    queue: WorkQueue,
    result_tx: std::sync::mpsc::Sender<JobResult>,
    progress_tx: std::sync::mpsc::Sender<ProgressReport>,
    stats: Arc<Mutex<WorkerPoolStats>>,
    global_token: CancellationToken,
) {
    while let Some(job) = queue.pop() {
        if global_token.is_cancelled() {
            let _ = result_tx.send(JobResult::cancelled(
                job.id.clone(),
                job.session_id.clone(),
                0,
            ));
            continue;
        }

        let start = Instant::now();
        let result = execute_job(&job, &progress_tx, &global_token);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let outcome = match result {
            ExecutionOutcome::Success { functions, strings } => {
                let mut r = JobResult::success(job.id.clone(), job.session_id.clone(), elapsed_ms);
                r.function_count = functions;
                r.string_count = strings;
                r
            }
            ExecutionOutcome::Cancelled => {
                JobResult::cancelled(job.id.clone(), job.session_id.clone(), elapsed_ms)
            }
            ExecutionOutcome::Failed(err) => {
                JobResult::failure(job.id.clone(), job.session_id.clone(), elapsed_ms, err)
            }
        };

        {
            let mut s = stats.lock().expect("stats mutex poisoned");
            s.jobs_total += 1;
            if outcome.success {
                s.jobs_succeeded += 1;
            } else if outcome.cancelled {
                s.jobs_cancelled += 1;
            } else {
                s.jobs_failed += 1;
            }
        }

        let _ = result_tx.send(outcome);
    }
}

pub enum ExecutionOutcome {
    Success { functions: usize, strings: usize },
    Cancelled,
    Failed(String),
}

/// Stub analysis execution — in production this would invoke `rustre-analysis`.
fn execute_job(
    job: &AnalysisJob,
    progress_tx: &std::sync::mpsc::Sender<ProgressReport>,
    token: &CancellationToken,
) -> ExecutionOutcome {
    // Phase 1 — load binary.
    if token.is_cancelled() {
        return ExecutionOutcome::Cancelled;
    }
    let _ = progress_tx.send(ProgressReport::new(job.id.clone(), 10, "loading binary"));

    if !job.binary_path.as_os_str().is_empty() && job.timeout_secs > 0 {
        // Simulate a configurable delay (bounded to 50 ms for tests).
        let delay = Duration::from_millis(job.timeout_secs.min(50));
        std::thread::sleep(delay);
    }

    // Phase 2 — disassemble.
    if token.is_cancelled() {
        return ExecutionOutcome::Cancelled;
    }
    let _ = progress_tx.send(ProgressReport::new(job.id.clone(), 40, "disassembling"));

    // Phase 3 — lift to IL.
    if token.is_cancelled() {
        return ExecutionOutcome::Cancelled;
    }
    let _ = progress_tx.send(ProgressReport::new(job.id.clone(), 70, "lifting to IL"));

    // Phase 4 — decompile (deep only).
    if job.deep {
        if token.is_cancelled() {
            return ExecutionOutcome::Cancelled;
        }
        let _ = progress_tx.send(ProgressReport::new(job.id.clone(), 90, "decompiling"));
    }

    let _ = progress_tx.send(ProgressReport::new(job.id.clone(), 100, "complete"));
    ExecutionOutcome::Success {
        functions: 42,
        strings: 128,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn job(path: &str) -> AnalysisJob {
        AnalysisJob::new(PathBuf::from(path))
    }

    // ── JobId ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_job_id_display() {
        let id = JobId::new("abc");
        assert_eq!(id.to_string(), "abc");
    }

    #[test]
    fn test_job_id_generate_nonempty() {
        let id = JobId::generate();
        assert!(!id.as_str().is_empty());
        assert!(id.as_str().starts_with("job-"));
    }

    // ── JobPriority ───────────────────────────────────────────────────────────

    #[test]
    fn test_priority_ordering() {
        assert!(JobPriority::Critical > JobPriority::High);
        assert!(JobPriority::High > JobPriority::Normal);
        assert!(JobPriority::Normal > JobPriority::Low);
    }

    // ── AnalysisJob builder ───────────────────────────────────────────────────

    #[test]
    fn test_job_builder() {
        let j = job("/bin/ls")
            .with_deep(true)
            .with_priority(JobPriority::High)
            .with_timeout(30)
            .with_session("s1");
        assert!(j.deep);
        assert_eq!(j.priority, JobPriority::High);
        assert_eq!(j.timeout_secs, 30);
        assert_eq!(j.session_id.as_deref(), Some("s1"));
    }

    // ── CancellationToken ─────────────────────────────────────────────────────

    #[test]
    fn test_cancellation_token_default_not_cancelled() {
        let t = CancellationToken::new();
        assert!(!t.is_cancelled());
        t.cancel();
        assert!(t.is_cancelled());
    }

    #[test]
    fn test_cancellation_token_clone_shared() {
        let t = CancellationToken::new();
        let t2 = t.clone();
        t.cancel();
        assert!(t2.is_cancelled());
    }

    // ── WorkQueue ─────────────────────────────────────────────────────────────

    #[test]
    fn test_work_queue_push_try_pop() {
        let q = WorkQueue::new();
        assert!(q.is_empty());
        let _ = q.push(job("/a"));
        let _ = q.push(job("/b"));
        assert_eq!(q.len(), 2);
        let j = q.try_pop().unwrap();
        assert!(!j.binary_path.as_os_str().is_empty());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_work_queue_priority_order() {
        let q = WorkQueue::new();
        let _ = q.push(job("/low").with_priority(JobPriority::Low));
        let _ = q.push(job("/critical").with_priority(JobPriority::Critical));
        let _ = q.push(job("/normal").with_priority(JobPriority::Normal));

        let first = q.try_pop().unwrap();
        assert_eq!(first.priority, JobPriority::Critical);
        let second = q.try_pop().unwrap();
        assert_eq!(second.priority, JobPriority::Normal);
        let third = q.try_pop().unwrap();
        assert_eq!(third.priority, JobPriority::Low);
    }

    #[test]
    fn test_work_queue_fifo_same_priority() {
        let q = WorkQueue::new();
        let mut j1 = job("/first");
        j1.id = JobId::new("first");
        let mut j2 = job("/second");
        j2.id = JobId::new("second");
        let _ = q.push(j1);
        let _ = q.push(j2);

        let a = q.try_pop().unwrap();
        let b = q.try_pop().unwrap();
        assert_eq!(a.id.as_str(), "first");
        assert_eq!(b.id.as_str(), "second");
    }

    #[test]
    fn test_work_queue_shutdown_unblocks_pop() {
        let q = WorkQueue::new();
        let q2 = q.clone();

        let handle = thread::spawn(move || q2.pop());
        thread::sleep(Duration::from_millis(20));
        q.shutdown();
        let result = handle.join().unwrap();
        assert!(result.is_none());
    }

    // ── WorkerPool ────────────────────────────────────────────────────────────

    #[test]
    fn test_worker_pool_processes_job() {
        let mut pool = WorkerPool::new(2);
        let rx = pool.result_receiver().unwrap();

        let j = job("/bin/ls");
        let jid = j.id.clone();
        let _ = pool.submit(j);

        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.job_id, jid);
        assert!(result.success);
        assert_eq!(result.function_count, 42);

        pool.shutdown();
    }

    #[test]
    fn test_worker_pool_progress_reports() {
        let mut pool = WorkerPool::new(1);
        let _rx = pool.result_receiver().unwrap();
        let prx = pool.progress_receiver().unwrap();

        let _ = pool.submit(job("/bin/test"));

        // Collect some progress reports.
        let mut phases = Vec::new();
        for _ in 0..10 {
            if let Ok(p) = prx.recv_timeout(Duration::from_secs(2)) {
                phases.push(p.phase.clone());
                if p.percent == 100 {
                    break;
                }
            }
        }
        assert!(!phases.is_empty());
        pool.shutdown();
    }

    #[test]
    fn test_worker_pool_stats_after_job() {
        let mut pool = WorkerPool::new(1);
        let rx = pool.result_receiver().unwrap();

        let _ = pool.submit(job("/bin/ls"));
        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let stats = pool.stats();
        assert_eq!(stats.jobs_succeeded, 1);
        assert_eq!(stats.jobs_total, 1);
        pool.shutdown();
    }

    #[test]
    fn test_worker_pool_cancellation() {
        let mut pool = WorkerPool::new(1);
        let rx = pool.result_receiver().unwrap();

        // Cancel immediately before any job processes.
        pool.token.cancel();
        let _ = pool.submit(job("/bin/ls"));

        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(result.cancelled);

        pool.shutdown();
    }

    // ── JobResult ─────────────────────────────────────────────────────────────

    #[test]
    fn test_job_result_success() {
        let r = JobResult::success(JobId::new("j1"), None, 100);
        assert!(r.success);
        assert!(!r.cancelled);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_job_result_failure() {
        let r = JobResult::failure(JobId::new("j2"), None, 200, "bad magic");
        assert!(!r.success);
        assert!(r.error.as_deref().unwrap().contains("bad magic"));
    }

    #[test]
    fn test_job_result_cancelled() {
        let r = JobResult::cancelled(JobId::new("j3"), Some("s1".into()), 0);
        assert!(r.cancelled);
        assert!(!r.success);
        assert_eq!(r.session_id.as_deref(), Some("s1"));
    }

    // ── ProgressReport ────────────────────────────────────────────────────────

    #[test]
    fn test_progress_report_percent_capped() {
        let r = ProgressReport::new(JobId::new("j"), 255, "test");
        assert_eq!(r.percent, 100);
    }
}
