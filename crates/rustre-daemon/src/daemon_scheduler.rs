//! Priority-queue job scheduler for the RustRE daemon.
//!
//! Maintains a persistent SQLite queue of analysis jobs, dispatches them to a
//! configurable worker pool, supports cancellation, and exposes
//! Prometheus-format metrics.
//!
//! Architecture overview:
//! ```text
//! ┌──────────────────────────────────────────┐
//! │  DaemonScheduler                         │
//! │  ┌─────────────────┐  ┌───────────────┐  │
//! │  │  PriorityQueue  │  │  WorkerPool   │  │
//! │  │  (min-heap by   │  │  (N threads)  │  │
//! │  │   priority+time)│  └───────────────┘  │
//! │  └─────────────────┘                     │
//! │  ┌─────────────────┐  ┌───────────────┐  │
//! │  │  SQLite persist  │  │  Metrics      │  │
//! │  └─────────────────┘  └───────────────┘  │
//! └──────────────────────────────────────────┘
//! ```

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time;

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors produced by the scheduler.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("database error: {0}")]
    Database(String),

    #[error("job not found: {id}")]
    NotFound { id: String },

    #[error("queue is full (capacity {cap})")]
    QueueFull { cap: usize },

    #[error("worker pool already started")]
    AlreadyStarted,

    #[error("job {id} is not cancellable in state {state:?}")]
    NotCancellable { id: String, state: JobState },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("shutdown in progress")]
    Shutdown,
}

// ──────────────────────────────────────────────────────────────────────────────
// Job types
// ──────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of an analysis job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        };
        f.write_str(s)
    }
}

/// Priority level for scheduling (lower value = higher priority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Normal
    }
}

/// A scheduled analysis job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Globally unique job ID (UUID-v4-like).
    pub id: String,
    /// SHA-256 hex of the binary being analysed.
    pub binary_hash: String,
    /// Name of the binary file for display.
    pub binary_name: String,
    /// Analysis profile: "quick" | "full" | "deep".
    pub profile: String,
    /// Priority for queue ordering.
    pub priority: Priority,
    /// Current lifecycle state.
    pub state: JobState,
    /// Unix timestamp (ms) when the job was enqueued.
    pub created_at_ms: u64,
    /// Unix timestamp (ms) when execution started (if any).
    pub started_at_ms: Option<u64>,
    /// Unix timestamp (ms) when execution finished (if any).
    pub completed_at_ms: Option<u64>,
    /// Path to the result artefact (if completed).
    pub result_path: Option<String>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Submitting user / client identity.
    pub submitter: String,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl Job {
    /// Create a new job in the `Queued` state.
    #[must_use]
    pub fn new(
        binary_hash: impl Into<String>,
        binary_name: impl Into<String>,
        profile: impl Into<String>,
        priority: Priority,
        submitter: impl Into<String>,
    ) -> Self {
        Self {
            id: gen_id(),
            binary_hash: binary_hash.into(),
            binary_name: binary_name.into(),
            profile: profile.into(),
            priority,
            state: JobState::Queued,
            created_at_ms: now_ms(),
            started_at_ms: None,
            completed_at_ms: None,
            result_path: None,
            error: None,
            submitter: submitter.into(),
            metadata: HashMap::new(),
        }
    }

    /// Elapsed time since creation in milliseconds.
    #[must_use]
    pub fn age_ms(&self) -> u64 {
        now_ms().saturating_sub(self.created_at_ms)
    }

    /// Execution duration in milliseconds (for completed/failed jobs).
    #[must_use]
    pub fn execution_ms(&self) -> Option<u64> {
        Some(self.completed_at_ms?.saturating_sub(self.started_at_ms?))
    }

    /// Whether the job can still be cancelled.
    #[must_use]
    pub fn is_cancellable(&self) -> bool {
        matches!(self.state, JobState::Queued | JobState::Running)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Priority queue entry (for BinaryHeap)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct QueueEntry {
    priority: Priority,
    created_at_ms: u64,
    job_id: String,
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.created_at_ms == other.created_at_ms
    }
}

impl Eq for QueueEntry {}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower priority value = higher urgency; earlier creation = higher urgency.
        other.priority.cmp(&self.priority)
            .then_with(|| other.created_at_ms.cmp(&self.created_at_ms))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SQLite persistence
// ──────────────────────────────────────────────────────────────────────────────

/// SQLite-backed job store.
pub struct JobStore {
    db_path: PathBuf,
    conn: Mutex<Option<rusqlite_stub::Connection>>,
}

impl JobStore {
    /// Open (or create) the SQLite database at `path`.
    ///
    /// # Errors
    /// Returns `SchedulerError::Database` if the database cannot be opened or
    /// the schema cannot be applied.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SchedulerError> {
        let db_path = path.as_ref().to_path_buf();
        let conn = rusqlite_stub::Connection::open(&db_path)
            .map_err(|e| SchedulerError::Database(e.to_string()))?;
        conn.execute_batch(CREATE_SCHEMA)
            .map_err(|e| SchedulerError::Database(e.to_string()))?;
        Ok(Self {
            db_path,
            conn: Mutex::new(Some(conn)),
        })
    }

    /// Persist a new job.
    ///
    /// # Errors
    /// Returns `SchedulerError::Database` on persistence failure.
    pub fn insert(&self, job: &Job) -> Result<(), SchedulerError> {
        let json = serde_json::to_string(job)
            .map_err(|e| SchedulerError::Serialization(e.to_string()))?;
        let guard = self.conn.lock();
        let conn = guard.as_ref()
            .ok_or_else(|| SchedulerError::Database("store is closed".to_owned()))?;
        conn.execute(
            "INSERT OR REPLACE INTO jobs (id, binary_hash, state, created_at_ms, json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                &job.id,
                &job.binary_hash,
                &job.state.to_string(),
                &job.created_at_ms.to_string(),
                &json,
            ],
        ).map_err(|e| SchedulerError::Database(e.to_string()))?;
        Ok(())
    }

    /// Update the state and result fields of a job.
    ///
    /// # Errors
    /// Returns `SchedulerError::Database` on persistence failure.
    pub fn update(&self, job: &Job) -> Result<(), SchedulerError> {
        self.insert(job) // INSERT OR REPLACE handles updates too
    }

    /// Load a job by ID.
    ///
    /// # Errors
    /// Returns `SchedulerError::NotFound` if the job does not exist.
    pub fn load(&self, id: &str) -> Result<Job, SchedulerError> {
        let guard = self.conn.lock();
        let conn = guard.as_ref()
            .ok_or_else(|| SchedulerError::Database("store is closed".to_owned()))?;
        let json: String = conn.query_row(
            "SELECT json FROM jobs WHERE id = ?1",
            &[id],
            |row| row.get(0),
        ).map_err(|_| SchedulerError::NotFound { id: id.to_owned() })?;
        serde_json::from_str(&json)
            .map_err(|e| SchedulerError::Serialization(e.to_string()))
    }

    /// Load all jobs matching the given state.
    ///
    /// # Errors
    /// Returns `SchedulerError::Database` on query failure.
    pub fn load_by_state(&self, state: JobState) -> Result<Vec<Job>, SchedulerError> {
        let guard = self.conn.lock();
        let conn = guard.as_ref()
            .ok_or_else(|| SchedulerError::Database("store is closed".to_owned()))?;
        let rows = conn.query_map(
            "SELECT json FROM jobs WHERE state = ?1 ORDER BY created_at_ms ASC",
            &[&state.to_string()],
            |row| row.get::<_, String>(0),
        ).map_err(|e| SchedulerError::Database(e.to_string()))?;
        let mut jobs = Vec::new();
        for row in rows {
            let json = row.map_err(|e| SchedulerError::Database(e.to_string()))?;
            let job: Job = serde_json::from_str(&json)
                .map_err(|e| SchedulerError::Serialization(e.to_string()))?;
            jobs.push(job);
        }
        Ok(jobs)
    }

    /// Delete all completed/cancelled jobs older than `max_age`.
    ///
    /// # Errors
    /// Returns `SchedulerError::Database` on failure.
    pub fn prune(&self, max_age: Duration) -> Result<u64, SchedulerError> {
        // as_millis() returns u128; clamp to u64::MAX before narrowing to avoid
        // a silent truncation that would make the cutoff wrap to a future time.
        let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
        let cutoff_ms = now_ms().saturating_sub(max_age_ms);
        let guard = self.conn.lock();
        let conn = guard.as_ref()
            .ok_or_else(|| SchedulerError::Database("store is closed".to_owned()))?;
        let deleted = conn.execute(
            "DELETE FROM jobs WHERE state IN ('completed','cancelled','failed') \
             AND created_at_ms < ?1",
            &[&cutoff_ms.to_string()],
        ).map_err(|e| SchedulerError::Database(e.to_string()))? as u64;
        Ok(deleted)
    }

    /// Return the path to the database file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.db_path
    }
}

const CREATE_SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    binary_hash   TEXT NOT NULL,
    state         TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    json          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_jobs_hash  ON jobs(binary_hash);
";

// ──────────────────────────────────────────────────────────────────────────────
// Worker pool
// ──────────────────────────────────────────────────────────────────────────────

/// A work item dispatched to a pool thread.
pub struct WorkItem {
    pub job: Job,
    pub result_tx: oneshot::Sender<JobOutcome>,
}

/// Outcome reported by a worker after processing a job.
#[derive(Debug)]
pub struct JobOutcome {
    pub job_id: String,
    pub success: bool,
    pub result_path: Option<String>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

/// Fixed-size async worker pool.
pub struct WorkerPool {
    sender: mpsc::Sender<WorkItem>,
    worker_count: usize,
}

impl WorkerPool {
    /// Spawn `n` worker tasks listening on the internal channel.
    ///
    /// Each worker calls `handler` to process a `Job`.
    #[must_use]
    pub fn spawn<F, Fut>(n: usize, handler: Arc<F>) -> (Self, mpsc::Receiver<JobOutcome>)
    where
        F: Fn(Job) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = JobOutcome> + Send + 'static,
    {
        let (work_tx, work_rx) = mpsc::channel::<WorkItem>(512);
        let (done_tx, done_rx) = mpsc::channel::<JobOutcome>(512);

        let shared_rx = Arc::new(tokio::sync::Mutex::new(work_rx));

        for _ in 0..n {
            let done_tx = done_tx.clone();
            let handler = Arc::clone(&handler);
            let rx = Arc::clone(&shared_rx);
            tokio::spawn(async move {
                loop {
                    let item = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    match item {
                        Some(work_item) => {
                            let outcome = handler(work_item.job).await;
                            let _ = done_tx.send(outcome).await;
                        }
                        None => break,
                    }
                }
            });
        }

        (Self { sender: work_tx, worker_count: n }, done_rx)
    }

    /// Submit a job to the pool.
    ///
    /// # Errors
    /// Returns `SchedulerError::Shutdown` if the pool has been shut down.
    pub async fn submit(&self, item: WorkItem) -> Result<(), SchedulerError> {
        self.sender.send(item).await.map_err(|_| SchedulerError::Shutdown)
    }

    /// Number of workers in the pool.
    #[must_use]
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Metrics
// ──────────────────────────────────────────────────────────────────────────────

/// Scheduler metrics (Prometheus-format on request).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedulerMetrics {
    pub total_submitted: u64,
    pub total_completed: u64,
    pub total_failed: u64,
    pub total_cancelled: u64,
    pub currently_queued: usize,
    pub currently_running: usize,
    pub avg_wait_ms: f64,
    pub avg_exec_ms: f64,
}

impl SchedulerMetrics {
    /// Render metrics in Prometheus text exposition format.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        format!(
            "# HELP rustre_scheduler_submitted_total Total jobs submitted\n\
             # TYPE rustre_scheduler_submitted_total counter\n\
             rustre_scheduler_submitted_total {}\n\
             # HELP rustre_scheduler_completed_total Total jobs completed\n\
             # TYPE rustre_scheduler_completed_total counter\n\
             rustre_scheduler_completed_total {}\n\
             # HELP rustre_scheduler_failed_total Total jobs failed\n\
             # TYPE rustre_scheduler_failed_total counter\n\
             rustre_scheduler_failed_total {}\n\
             # HELP rustre_scheduler_cancelled_total Total jobs cancelled\n\
             # TYPE rustre_scheduler_cancelled_total counter\n\
             rustre_scheduler_cancelled_total {}\n\
             # HELP rustre_scheduler_queued Current jobs in queue\n\
             # TYPE rustre_scheduler_queued gauge\n\
             rustre_scheduler_queued {}\n\
             # HELP rustre_scheduler_running Current jobs running\n\
             # TYPE rustre_scheduler_running gauge\n\
             rustre_scheduler_running {}\n\
             # HELP rustre_scheduler_avg_wait_ms Average queue wait time\n\
             # TYPE rustre_scheduler_avg_wait_ms gauge\n\
             rustre_scheduler_avg_wait_ms {:.2}\n\
             # HELP rustre_scheduler_avg_exec_ms Average execution time\n\
             # TYPE rustre_scheduler_avg_exec_ms gauge\n\
             rustre_scheduler_avg_exec_ms {:.2}\n",
            self.total_submitted,
            self.total_completed,
            self.total_failed,
            self.total_cancelled,
            self.currently_queued,
            self.currently_running,
            self.avg_wait_ms,
            self.avg_exec_ms,
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DaemonScheduler — the main facade
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for the daemon scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Number of analysis worker threads.
    pub worker_count: usize,
    /// Maximum number of jobs allowed in the in-memory priority queue.
    pub max_queue_depth: usize,
    /// Path to the SQLite persistence file.
    pub db_path: String,
    /// How long to retain completed/failed jobs in the database.
    pub retention: Duration,
    /// Interval between automatic pruning passes.
    pub prune_interval: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            max_queue_depth: 1024,
            db_path: "scheduler.db".to_owned(),
            retention: Duration::from_secs(7 * 24 * 3600),
            prune_interval: Duration::from_secs(3600),
        }
    }
}

/// The priority-queue job scheduler.
pub struct DaemonScheduler {
    config: SchedulerConfig,
    /// In-memory priority queue of pending job IDs.
    queue: Mutex<BinaryHeap<QueueEntry>>,
    /// All known jobs (by ID).
    jobs: RwLock<HashMap<String, Job>>,
    /// Metrics counters.
    metrics: Mutex<SchedulerMetrics>,
    /// SQLite store.
    store: Arc<JobStore>,
}

impl DaemonScheduler {
    /// Create and initialise the scheduler.
    ///
    /// # Errors
    /// Returns `SchedulerError::Database` if the database cannot be opened.
    pub fn new(config: SchedulerConfig) -> Result<Arc<Self>, SchedulerError> {
        let store = Arc::new(JobStore::open(&config.db_path)?);
        let mut jobs_map: HashMap<String, Job> = HashMap::new();
        let mut heap: BinaryHeap<QueueEntry> = BinaryHeap::new();

        // Recover queued jobs from the database on start.
        let queued = store.load_by_state(JobState::Queued)?;
        for job in queued {
            heap.push(QueueEntry {
                priority: job.priority,
                created_at_ms: job.created_at_ms,
                job_id: job.id.clone(),
            });
            jobs_map.insert(job.id.clone(), job);
        }
        // Jobs that were Running when we crashed should be re-queued.
        let running = store.load_by_state(JobState::Running)?;
        for mut job in running {
            job.state = JobState::Queued;
            job.started_at_ms = None;
            heap.push(QueueEntry {
                priority: job.priority,
                created_at_ms: job.created_at_ms,
                job_id: job.id.clone(),
            });
            jobs_map.insert(job.id.clone(), job);
        }

        Ok(Arc::new(Self {
            config,
            queue: Mutex::new(heap),
            jobs: RwLock::new(jobs_map),
            metrics: Mutex::new(SchedulerMetrics::default()),
            store,
        }))
    }

    /// Enqueue a new analysis job.
    ///
    /// # Errors
    /// Returns `SchedulerError::QueueFull` if the in-memory queue is at capacity,
    /// or `SchedulerError::Database` on persistence failure.
    pub fn enqueue(&self, job: Job) -> Result<String, SchedulerError> {
        {
            let q = self.queue.lock();
            if q.len() >= self.config.max_queue_depth {
                return Err(SchedulerError::QueueFull {
                    cap: self.config.max_queue_depth,
                });
            }
        }
        self.store.insert(&job)?;
        let entry = QueueEntry {
            priority: job.priority,
            created_at_ms: job.created_at_ms,
            job_id: job.id.clone(),
        };
        let id = job.id.clone();
        self.jobs.write().insert(id.clone(), job);
        self.queue.lock().push(entry);
        self.metrics.lock().total_submitted += 1;
        Ok(id)
    }

    /// Dequeue the highest-priority job (if any).
    ///
    /// Returns `None` when the queue is empty.
    #[must_use]
    pub fn dequeue(&self) -> Option<Job> {
        loop {
            let entry = self.queue.lock().pop()?;
            let mut jobs = self.jobs.write();
            if let Some(job) = jobs.get_mut(&entry.job_id) {
                if job.state == JobState::Queued {
                    job.state = JobState::Running;
                    job.started_at_ms = Some(now_ms());
                    let job = job.clone();
                    drop(jobs);
                    let _ = self.store.update(&job);
                    self.metrics.lock().currently_running += 1;
                    return Some(job);
                }
                // Job was cancelled while in queue — skip it.
            }
        }
    }

    /// Mark a job as completed.
    ///
    /// # Errors
    /// Returns `SchedulerError::NotFound` if the job is unknown.
    pub fn complete(&self, job_id: &str, result_path: Option<String>)
        -> Result<(), SchedulerError>
    {
        let mut jobs = self.jobs.write();
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| SchedulerError::NotFound { id: job_id.to_owned() })?;
        job.state = JobState::Completed;
        job.completed_at_ms = Some(now_ms());
        job.result_path = result_path;
        let job = job.clone();
        drop(jobs);
        self.store.update(&job)?;
        let mut m = self.metrics.lock();
        m.total_completed += 1;
        m.currently_running = m.currently_running.saturating_sub(1);
        Ok(())
    }

    /// Mark a job as failed.
    ///
    /// # Errors
    /// Returns `SchedulerError::NotFound` if the job is unknown.
    pub fn fail(&self, job_id: &str, error: impl Into<String>)
        -> Result<(), SchedulerError>
    {
        let mut jobs = self.jobs.write();
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| SchedulerError::NotFound { id: job_id.to_owned() })?;
        job.state = JobState::Failed;
        job.completed_at_ms = Some(now_ms());
        job.error = Some(error.into());
        let job = job.clone();
        drop(jobs);
        self.store.update(&job)?;
        let mut m = self.metrics.lock();
        m.total_failed += 1;
        m.currently_running = m.currently_running.saturating_sub(1);
        Ok(())
    }

    /// Cancel a job that is queued or running.
    ///
    /// # Errors
    /// Returns `SchedulerError::NotFound` or `SchedulerError::NotCancellable`.
    pub fn cancel(&self, job_id: &str) -> Result<(), SchedulerError> {
        let mut jobs = self.jobs.write();
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| SchedulerError::NotFound { id: job_id.to_owned() })?;
        if !job.is_cancellable() {
            return Err(SchedulerError::NotCancellable {
                id: job_id.to_owned(),
                state: job.state,
            });
        }
        job.state = JobState::Cancelled;
        job.completed_at_ms = Some(now_ms());
        let job = job.clone();
        drop(jobs);
        self.store.update(&job)?;
        self.metrics.lock().total_cancelled += 1;
        Ok(())
    }

    /// Get a snapshot of a job by ID.
    ///
    /// # Errors
    /// Returns `SchedulerError::NotFound` if the job is unknown in memory.
    pub fn get(&self, job_id: &str) -> Result<Job, SchedulerError> {
        self.jobs.read()
            .get(job_id)
            .cloned()
            .ok_or_else(|| SchedulerError::NotFound { id: job_id.to_owned() })
    }

    /// List all jobs, optionally filtered by state.
    #[must_use]
    pub fn list(&self, filter: Option<JobState>) -> Vec<Job> {
        let jobs = self.jobs.read();
        jobs.values()
            .filter(|j| filter.map_or(true, |s| j.state == s))
            .cloned()
            .collect()
    }

    /// Return current metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> SchedulerMetrics {
        let mut m = self.metrics.lock().clone();
        m.currently_queued = self.queue.lock().len();
        m
    }

    /// Return the Prometheus-format metrics string.
    #[must_use]
    pub fn prometheus_metrics(&self) -> String {
        self.metrics().to_prometheus()
    }

    /// Start the periodic prune background task.
    pub fn start_prune_task(self: Arc<Self>) {
        let interval = self.config.prune_interval;
        let retention = self.config.retention;
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            loop {
                ticker.tick().await;
                let _ = self.store.prune(retention);
            }
        });
    }

    /// Return the number of jobs currently in the in-memory queue.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.lock().len()
    }

    /// Return the number of jobs in the in-memory map.
    #[must_use]
    pub fn total_known_jobs(&self) -> usize {
        self.jobs.read().len()
    }

    /// Health check endpoint data.
    #[must_use]
    pub fn health(&self) -> HealthStatus {
        HealthStatus {
            ok: true,
            queue_depth: self.queue_depth(),
            worker_count: self.config.worker_count,
            db_path: self.config.db_path.clone(),
        }
    }
}

/// Health status returned by the scheduler health endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub ok: bool,
    pub queue_depth: usize,
    pub worker_count: usize,
    pub db_path: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn gen_id() -> String {
    format!("job-{}", uuid::Uuid::new_v4())
}

// ──────────────────────────────────────────────────────────────────────────────
// Stub for rusqlite (to avoid hard dependency on the crate in this file)
// ──────────────────────────────────────────────────────────────────────────────

mod rusqlite_stub {
    //! Minimal stub that mirrors the `rusqlite` public API surface used here.
    //! Replace with the real `rusqlite` crate in Cargo.toml.

    use std::path::Path;

    pub struct Connection {
        _path: std::path::PathBuf,
        store: std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>,
    }

    impl Connection {
        pub fn open(path: &Path) -> Result<Self, StubError> {
            Ok(Self {
                _path: path.to_path_buf(),
                store: std::sync::Mutex::new(std::collections::HashMap::new()),
            })
        }

        pub fn execute_batch(&self, _sql: &str) -> Result<(), StubError> {
            Ok(())
        }

        pub fn execute(&self, sql: &str, params: &[&str]) -> Result<usize, StubError> {
            if sql.contains("INSERT OR REPLACE INTO jobs") {
                if params.len() < 5 {
                    return Err(StubError::Other(format!(
                        "INSERT OR REPLACE INTO jobs requires 5 params, got {}",
                        params.len()
                    )));
                }
                let id = params[0].to_owned();
                let json = params[4].to_owned();
                let state = params[2].to_owned();
                let mut map = self.store.lock().unwrap();
                map.entry(format!("job:{}", id)).or_default().clear();
                map.entry(format!("job:{}", id)).or_default().push(json.clone());
                map.entry(format!("state:{}", state)).or_default().push(id);
                return Ok(1);
            }
            if sql.contains("DELETE FROM jobs") {
                return Ok(0);
            }
            Ok(0)
        }

        pub fn query_row<T, F>(&self, sql: &str, params: &[&str], f: F)
            -> Result<T, StubError>
        where
            F: FnOnce(&Row) -> T,
        {
            if sql.contains("SELECT json FROM jobs WHERE id") && !params.is_empty() {
                let map = self.store.lock().unwrap();
                if let Some(rows) = map.get(&format!("job:{}", params[0])) {
                    if let Some(json) = rows.first() {
                        let row = Row { values: vec![json.clone()] };
                        return Ok(f(&row));
                    }
                }
            }
            Err(StubError::NotFound)
        }

        pub fn query_map<T, F>(
            &self,
            sql: &str,
            params: &[&str],
            f: F,
        ) -> Result<Vec<Result<T, StubError>>, StubError>
        where
            F: Fn(&Row) -> T,
        {
            let mut results = Vec::new();
            if sql.contains("SELECT json FROM jobs WHERE state") && !params.is_empty() {
                let map = self.store.lock().unwrap();
                let ids = map.get(&format!("state:{}", params[0]))
                    .cloned()
                    .unwrap_or_default();
                for id in ids {
                    if let Some(rows) = map.get(&format!("job:{}", id)) {
                        if let Some(json) = rows.first() {
                            let row = Row { values: vec![json.clone()] };
                            results.push(Ok(f(&row)));
                        }
                    }
                }
            }
            Ok(results)
        }
    }

    pub struct Row {
        values: Vec<String>,
    }

    impl Row {
        pub fn get<I, T: From<String>>(&self, idx: I) -> T
        where
            I: TryInto<usize>,
            I::Error: std::fmt::Debug,
        {
            self.values[idx.try_into().expect("row index out of usize range")]
                .clone()
                .into()
        }
    }

    #[derive(Debug)]
    pub enum StubError {
        NotFound,
        Other(String),
    }

    impl std::fmt::Display for StubError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotFound => write!(f, "not found"),
                Self::Other(s) => write!(f, "{}", s),
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scheduler() -> Arc<DaemonScheduler> {
        let cfg = SchedulerConfig {
            db_path: ":memory:".to_owned(),
            ..Default::default()
        };
        DaemonScheduler::new(cfg).unwrap()
    }

    fn make_job(priority: Priority) -> Job {
        Job::new("aabbccdd", "test.exe", "quick", priority, "tester")
    }

    #[test]
    fn enqueue_and_dequeue_fifo_same_priority() {
        let s = make_scheduler();
        let j1 = make_job(Priority::Normal);
        let j2 = make_job(Priority::Normal);
        let id1 = j1.id.clone();
        s.enqueue(j1).unwrap();
        s.enqueue(j2).unwrap();
        let first = s.dequeue().unwrap();
        assert_eq!(first.id, id1);
    }

    #[test]
    fn enqueue_higher_priority_dequeues_first() {
        let s = make_scheduler();
        let low = make_job(Priority::Low);
        let high = make_job(Priority::High);
        let high_id = high.id.clone();
        s.enqueue(low).unwrap();
        s.enqueue(high).unwrap();
        let first = s.dequeue().unwrap();
        assert_eq!(first.id, high_id);
    }

    #[test]
    fn dequeue_empty_returns_none() {
        let s = make_scheduler();
        assert!(s.dequeue().is_none());
    }

    #[test]
    fn complete_job_updates_state() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        let _ = s.dequeue();
        s.complete(&id, Some("/tmp/result".to_owned())).unwrap();
        let job = s.get(&id).unwrap();
        assert_eq!(job.state, JobState::Completed);
        assert_eq!(job.result_path.as_deref(), Some("/tmp/result"));
    }

    #[test]
    fn fail_job_updates_state() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        let _ = s.dequeue();
        s.fail(&id, "OOM").unwrap();
        let job = s.get(&id).unwrap();
        assert_eq!(job.state, JobState::Failed);
        assert_eq!(job.error.as_deref(), Some("OOM"));
    }

    #[test]
    fn cancel_queued_job() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        s.cancel(&id).unwrap();
        let job = s.get(&id).unwrap();
        assert_eq!(job.state, JobState::Cancelled);
    }

    #[test]
    fn cancel_completed_job_fails() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        let _ = s.dequeue();
        s.complete(&id, None).unwrap();
        assert!(s.cancel(&id).is_err());
    }

    #[test]
    fn get_unknown_job_returns_not_found() {
        let s = make_scheduler();
        assert!(s.get("no-such-id").is_err());
    }

    #[test]
    fn queue_depth_tracks_enqueue_dequeue() {
        let s = make_scheduler();
        assert_eq!(s.queue_depth(), 0);
        s.enqueue(make_job(Priority::Normal)).unwrap();
        assert_eq!(s.queue_depth(), 1);
        let _ = s.dequeue();
        assert_eq!(s.queue_depth(), 0);
    }

    #[test]
    fn metrics_submitted_increments() {
        let s = make_scheduler();
        s.enqueue(make_job(Priority::Normal)).unwrap();
        assert_eq!(s.metrics().total_submitted, 1);
    }

    #[test]
    fn metrics_completed_increments() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        let _ = s.dequeue();
        s.complete(&id, None).unwrap();
        assert_eq!(s.metrics().total_completed, 1);
    }

    #[test]
    fn metrics_failed_increments() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        let _ = s.dequeue();
        s.fail(&id, "err").unwrap();
        assert_eq!(s.metrics().total_failed, 1);
    }

    #[test]
    fn metrics_cancelled_increments() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        s.cancel(&id).unwrap();
        assert_eq!(s.metrics().total_cancelled, 1);
    }

    #[test]
    fn prometheus_metrics_contains_keys() {
        let s = make_scheduler();
        let prom = s.prometheus_metrics();
        assert!(prom.contains("rustre_scheduler_submitted_total"));
        assert!(prom.contains("rustre_scheduler_queued"));
    }

    #[test]
    fn list_filter_by_state() {
        let s = make_scheduler();
        s.enqueue(make_job(Priority::Normal)).unwrap();
        s.enqueue(make_job(Priority::Low)).unwrap();
        let dequeued = s.dequeue().unwrap();
        s.complete(&dequeued.id, None).unwrap();
        let queued = s.list(Some(JobState::Queued));
        assert_eq!(queued.len(), 1);
        let completed = s.list(Some(JobState::Completed));
        assert_eq!(completed.len(), 1);
    }

    #[test]
    fn list_no_filter_returns_all() {
        let s = make_scheduler();
        s.enqueue(make_job(Priority::Normal)).unwrap();
        s.enqueue(make_job(Priority::Normal)).unwrap();
        assert_eq!(s.list(None).len(), 2);
    }

    #[test]
    fn health_returns_ok() {
        let s = make_scheduler();
        let h = s.health();
        assert!(h.ok);
        assert_eq!(h.worker_count, 4);
    }

    #[test]
    fn queue_full_returns_error() {
        let cfg = SchedulerConfig {
            max_queue_depth: 2,
            db_path: ":memory:".to_owned(),
            ..Default::default()
        };
        let s = DaemonScheduler::new(cfg).unwrap();
        s.enqueue(make_job(Priority::Normal)).unwrap();
        s.enqueue(make_job(Priority::Normal)).unwrap();
        assert!(matches!(
            s.enqueue(make_job(Priority::Normal)),
            Err(SchedulerError::QueueFull { .. })
        ));
    }

    #[test]
    fn job_age_ms_positive() {
        let j = make_job(Priority::Normal);
        assert!(j.age_ms() < 1000); // should be very fast
    }

    #[test]
    fn job_execution_ms_none_before_complete() {
        let j = make_job(Priority::Normal);
        assert!(j.execution_ms().is_none());
    }

    #[test]
    fn priority_ordering() {
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Normal < Priority::Low);
        assert!(Priority::Low < Priority::Background);
    }

    #[test]
    fn job_state_display() {
        assert_eq!(JobState::Queued.to_string(), "queued");
        assert_eq!(JobState::Completed.to_string(), "completed");
    }

    #[test]
    fn cancelled_job_skipped_on_dequeue() {
        let s = make_scheduler();
        let j = make_job(Priority::Normal);
        let id = s.enqueue(j).unwrap();
        s.cancel(&id).unwrap();
        // Queue still has the entry but dequeue should skip it.
        assert!(s.dequeue().is_none());
    }

    #[test]
    fn total_known_jobs_tracks_enqueue() {
        let s = make_scheduler();
        assert_eq!(s.total_known_jobs(), 0);
        s.enqueue(make_job(Priority::Normal)).unwrap();
        assert_eq!(s.total_known_jobs(), 1);
    }
}
