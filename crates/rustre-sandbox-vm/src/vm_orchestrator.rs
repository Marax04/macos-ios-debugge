//! VM orchestrator — pool management, job queue, lifecycle,
//! snapshot manager, and metrics.

pub use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
pub use std::sync::Arc;
pub use std::sync::atomic::{AtomicU64, Ordering};
pub use std::time::{Duration, Instant};

/// Cast `u64` to `f64` (precision loss intentionally accepted for ratio metrics).
#[inline]
const fn u64_to_f64(v: u64) -> f64 { v as f64 }

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrchestratorError {
    #[error("no VMs available")]
    NoVmsAvailable,
    #[error("VM {0} not found")]
    VmNotFound(String),
    #[error("job {0} not found")]
    JobNotFound(u64),
    #[error("snapshot '{0}' not found on VM {1}")]
    SnapshotNotFound(String, String),
    #[error("pool exhausted (max {0} VMs)")]
    PoolExhausted(usize),
    #[error("VM {0} in wrong state: {1}")]
    WrongState(String, String),
    #[error("timeout waiting for VM")]
    Timeout,
    #[error("queue full (max {0} jobs)")]
    QueueFull(usize),
}

// ─── VmState ─────────────────────────────────────────────────────────────────

/// State of a single sandbox VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmState {
    /// VM is off, no resources allocated.
    Off,
    /// VM is starting up.
    Starting,
    /// VM is running and idle (ready for a job).
    Idle,
    /// VM is executing a sandbox job.
    Running,
    /// VM is being snapshotted.
    Snapshotting,
    /// VM is being restored to a snapshot.
    Restoring,
    /// VM encountered an error.
    Error,
    /// VM is shutting down.
    ShuttingDown,
}

impl VmState {
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Idle)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Starting => "starting",
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Snapshotting => "snapshotting",
            Self::Restoring => "restoring",
            Self::Error => "error",
            Self::ShuttingDown => "shutting_down",
        }
    }
}

// ─── VmLifecycle ─────────────────────────────────────────────────────────────

/// Represents the lifecycle of a single VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLifecycle {
    pub vm_id: String,
    pub state: VmState,
    pub created_at: u64,
    pub last_started: Option<u64>,
    pub last_job_id: Option<u64>,
    pub job_count: u64,
    pub error_count: u32,
    pub base_image: String,
}

impl VmLifecycle {
    /// Create a new VM lifecycle record.
    #[must_use]
    pub fn new(vm_id: impl Into<String>, base_image: impl Into<String>, now: u64) -> Self {
        Self {
            vm_id: vm_id.into(),
            state: VmState::Off,
            created_at: now,
            last_started: None,
            last_job_id: None,
            job_count: 0,
            error_count: 0,
            base_image: base_image.into(),
        }
    }

    /// Transition to a new state.
    pub const fn transition(&mut self, new: VmState) {
        self.state = new;
    }

    /// Record a job completion.
    pub const fn finish_job(&mut self, job_id: u64) {
        self.last_job_id = Some(job_id);
        self.job_count += 1;
        self.state = VmState::Idle;
    }

    /// Record an error.
    pub const fn record_error(&mut self) {
        self.error_count += 1;
        self.state = VmState::Error;
    }

    /// Whether this VM is healthy enough to accept jobs.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.error_count < 5 && !matches!(self.state, VmState::Error)
    }
}

// ─── SnapshotManager ─────────────────────────────────────────────────────────

/// A snapshot entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub vm_id: String,
    pub name: String,
    pub created_at: u64,
    pub size_bytes: u64,
    pub description: Option<String>,
    pub is_base: bool,
}

/// Manages snapshots for all VMs.
#[derive(Debug, Default)]
pub struct SnapshotManager {
    snapshots: HashMap<String, Vec<SnapshotEntry>>,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a snapshot record.
    pub fn add(&mut self, entry: SnapshotEntry) {
        self.snapshots
            .entry(entry.vm_id.clone())
            .or_default()
            .push(entry);
    }

    /// Get all snapshots for a VM.
    #[must_use]
    pub fn for_vm(&self, vm_id: &str) -> &[SnapshotEntry] {
        self.snapshots
            .get(vm_id)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Find a specific snapshot by VM and name.
    #[must_use]
    pub fn find(&self, vm_id: &str, name: &str) -> Option<&SnapshotEntry> {
        self.snapshots.get(vm_id)?.iter().find(|s| s.name == name)
    }

    /// Delete a snapshot.
    pub fn delete(&mut self, vm_id: &str, name: &str) -> bool {
        if let Some(snaps) = self.snapshots.get_mut(vm_id) {
            let before = snaps.len();
            snaps.retain(|s| s.name != name);
            return snaps.len() < before;
        }
        false
    }

    /// Total snapshot count.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.snapshots.values().map(std::vec::Vec::len).sum()
    }

    /// Total snapshot storage in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.snapshots
            .values()
            .flat_map(|v| v.iter())
            .map(|s| s.size_bytes)
            .sum()
    }
}

// ─── JobQueue ────────────────────────────────────────────────────────────────

/// Priority level for sandbox jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JobPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// State of a sandbox job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Queued,
    Assigned,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// A sandbox analysis job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxJob {
    pub id: u64,
    pub sample_path: String,
    pub state: JobState,
    pub priority: JobPriority,
    pub assigned_vm: Option<String>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub timeout_sec: u32,
    pub result_path: Option<String>,
}

impl SandboxJob {
    /// Create a new job.
    #[must_use]
    pub fn new(id: u64, sample: impl Into<String>, priority: JobPriority, now: u64) -> Self {
        Self {
            id,
            sample_path: sample.into(),
            state: JobState::Queued,
            priority,
            assigned_vm: None,
            created_at: now,
            started_at: None,
            finished_at: None,
            timeout_sec: 120,
            result_path: None,
        }
    }

    /// Duration from queue to finish.
    #[must_use]
    pub fn turnaround_secs(&self) -> Option<u64> {
        let fin = self.finished_at?;
        Some(fin.saturating_sub(self.created_at))
    }
}

/// Priority queue for sandbox jobs.
#[derive(Debug, Default)]
pub struct JobQueue {
    jobs: VecDeque<SandboxJob>,
    max_size: usize,
    counter: u64,
}

impl JobQueue {
    /// Create a new job queue.
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self {
            jobs: VecDeque::new(),
            max_size,
            counter: 0,
        }
    }

    /// Enqueue a new job.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::QueueFull`] if the queue has reached `max_size`.
    pub fn enqueue(
        &mut self,
        sample: impl Into<String>,
        priority: JobPriority,
        now: u64,
    ) -> Result<u64, OrchestratorError> {
        if self.jobs.len() >= self.max_size {
            return Err(OrchestratorError::QueueFull(self.max_size));
        }
        self.counter += 1;
        let job = SandboxJob::new(self.counter, sample, priority, now);
        // Insert in priority order (highest first).
        let pos = self
            .jobs
            .iter()
            .position(|j| j.priority < priority)
            .unwrap_or(self.jobs.len());
        self.jobs.insert(pos, job);
        Ok(self.counter)
    }

    /// Dequeue the highest-priority queued job.
    pub fn dequeue(&mut self) -> Option<SandboxJob> {
        let pos = self.jobs.iter().position(|j| j.state == JobState::Queued)?;
        let mut job = self.jobs.remove(pos)?;
        job.state = JobState::Assigned;
        Some(job)
    }

    /// Queue depth (waiting jobs).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.jobs
            .iter()
            .filter(|j| j.state == JobState::Queued)
            .count()
    }

    /// Find a job by ID.
    #[must_use]
    pub fn find(&self, id: u64) -> Option<&SandboxJob> {
        self.jobs.iter().find(|j| j.id == id)
    }
}

// ─── VmPool ──────────────────────────────────────────────────────────────────

/// Pool of available sandbox VMs.
#[derive(Debug, Default)]
pub struct VmPool {
    vms: HashMap<String, VmLifecycle>,
    max_size: usize,
}

impl VmPool {
    /// Create a new pool with a maximum capacity.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            vms: HashMap::new(),
            max_size,
        }
    }

    /// Add a VM to the pool.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::PoolExhausted`] if the pool has reached `max_size`.
    pub fn add_vm(
        &mut self,
        vm_id: impl Into<String>,
        base_image: impl Into<String>,
        now: u64,
    ) -> Result<(), OrchestratorError> {
        if self.vms.len() >= self.max_size {
            return Err(OrchestratorError::PoolExhausted(self.max_size));
        }
        let id = vm_id.into();
        self.vms
            .insert(id.clone(), VmLifecycle::new(id, base_image, now));
        Ok(())
    }

    /// Get a mutable reference to a VM.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::VmNotFound`] if no VM with `vm_id` exists in the pool.
    pub fn get_mut(&mut self, vm_id: &str) -> Result<&mut VmLifecycle, OrchestratorError> {
        self.vms
            .get_mut(vm_id)
            .ok_or_else(|| OrchestratorError::VmNotFound(vm_id.to_string()))
    }

    /// Pick an idle, healthy VM.
    #[must_use]
    pub fn pick_idle(&self) -> Option<&str> {
        self.vms
            .values()
            .find(|v| v.state.is_available() && v.is_healthy())
            .map(|v| v.vm_id.as_str())
    }

    /// Count of idle VMs.
    #[must_use]
    pub fn idle_count(&self) -> usize {
        self.vms.values().filter(|v| v.state.is_available()).count()
    }

    /// Count of all VMs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vms.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vms.is_empty()
    }
}

// ─── VmMetrics ───────────────────────────────────────────────────────────────

/// Aggregated metrics for the orchestrator.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VmMetrics {
    pub total_jobs_submitted: u64,
    pub total_jobs_completed: u64,
    pub total_jobs_failed: u64,
    pub avg_turnaround_secs: f64,
    pub vm_error_count: u32,
    pub snapshot_count: usize,
    pub snapshot_bytes: u64,
    pub queue_depth_max: usize,
}

impl VmMetrics {
    /// Completion ratio.
    #[must_use]
    pub fn completion_rate(&self) -> f64 {
        if self.total_jobs_submitted == 0 {
            return 0.0;
        }
        u64_to_f64(self.total_jobs_completed) / u64_to_f64(self.total_jobs_submitted)
    }

    /// Failure ratio.
    #[must_use]
    pub fn failure_rate(&self) -> f64 {
        if self.total_jobs_submitted == 0 {
            return 0.0;
        }
        u64_to_f64(self.total_jobs_failed) / u64_to_f64(self.total_jobs_submitted)
    }
}

// ─── VmOrchestrator ──────────────────────────────────────────────────────────

/// Top-level VM orchestrator — coordinates pool, queue, snapshots, metrics.
pub struct VmOrchestrator {
    pub pool: VmPool,
    pub queue: JobQueue,
    pub snapshots: SnapshotManager,
    pub metrics: VmMetrics,
    now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl VmOrchestrator {
    /// Create with a fixed clock source (useful for tests).
    #[must_use]
    pub fn with_clock(
        max_vms: usize,
        max_queue: usize,
        now_fn: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            pool: VmPool::new(max_vms),
            queue: JobQueue::new(max_queue),
            snapshots: SnapshotManager::new(),
            metrics: VmMetrics::default(),
            now_fn: Box::new(now_fn),
        }
    }

    /// Create with wall-clock time.
    #[must_use]
    pub fn new(max_vms: usize, max_queue: usize) -> Self {
        Self::with_clock(max_vms, max_queue, || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })
    }

    fn now(&self) -> u64 {
        (self.now_fn)()
    }

    /// Register a VM.
    ///
    /// # Errors
    /// Propagates errors from [`VmPool::add_vm`] (pool exhausted).
    pub fn register_vm(
        &mut self,
        vm_id: impl Into<String>,
        base_image: impl Into<String>,
    ) -> Result<(), OrchestratorError> {
        self.pool.add_vm(vm_id, base_image, self.now())
    }

    /// Set a VM to idle (ready for jobs).
    ///
    /// # Errors
    /// Returns [`OrchestratorError::VmNotFound`] if `vm_id` is not in the pool.
    pub fn set_vm_idle(&mut self, vm_id: &str) -> Result<(), OrchestratorError> {
        self.pool.get_mut(vm_id)?.transition(VmState::Idle);
        Ok(())
    }

    /// Submit a new analysis job.
    ///
    /// # Errors
    /// Propagates queue-full errors from [`JobQueue::enqueue`].
    pub fn submit_job(
        &mut self,
        sample: impl Into<String>,
        priority: JobPriority,
    ) -> Result<u64, OrchestratorError> {
        let now = self.now();
        let id = self.queue.enqueue(sample, priority, now)?;
        self.metrics.total_jobs_submitted += 1;
        let depth = self.queue.depth();
        if depth > self.metrics.queue_depth_max {
            self.metrics.queue_depth_max = depth;
        }
        Ok(id)
    }

    /// Assign the next queued job to an idle VM.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::NoVmsAvailable`] if no idle VM or no queued job exists.
    /// Also propagates VM lookup errors.
    pub fn assign_next(&mut self) -> Result<(String, u64), OrchestratorError> {
        let vm_id = self
            .pool
            .pick_idle()
            .ok_or(OrchestratorError::NoVmsAvailable)?
            .to_string();
        let mut job = self
            .queue
            .dequeue()
            .ok_or(OrchestratorError::NoVmsAvailable)?;
        let now = self.now();
        job.assigned_vm = Some(vm_id.clone());
        job.state = JobState::Running;
        job.started_at = Some(now);
        let job_id = job.id;
        self.pool.get_mut(&vm_id)?.transition(VmState::Running);
        self.pool.get_mut(&vm_id)?.last_job_id = Some(job_id);
        Ok((vm_id, job_id))
    }

    /// Mark a job as completed.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::VmNotFound`] if `vm_id` is not in the pool.
    pub fn complete_job(&mut self, vm_id: &str, job_id: u64) -> Result<(), OrchestratorError> {
        self.pool.get_mut(vm_id)?.finish_job(job_id);
        self.metrics.total_jobs_completed += 1;
        Ok(())
    }

    /// Mark a job as failed.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::VmNotFound`] if `vm_id` is not in the pool.
    pub fn fail_job(&mut self, vm_id: &str) -> Result<(), OrchestratorError> {
        self.pool.get_mut(vm_id)?.record_error();
        self.metrics.total_jobs_failed += 1;
        self.metrics.vm_error_count += 1;
        Ok(())
    }

    /// Take a snapshot of a VM.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::VmNotFound`] if `vm_id` is not in the pool.
    pub fn snapshot(
        &mut self,
        vm_id: &str,
        name: impl Into<String>,
        size_bytes: u64,
    ) -> Result<(), OrchestratorError> {
        let now = self.now();
        let vm = self.pool.get_mut(vm_id)?;
        vm.transition(VmState::Snapshotting);
        let entry = SnapshotEntry {
            vm_id: vm_id.to_string(),
            name: name.into(),
            created_at: now,
            size_bytes,
            description: None,
            is_base: false,
        };
        self.snapshots.add(entry);
        self.metrics.snapshot_count += 1;
        self.metrics.snapshot_bytes += size_bytes;
        self.pool.get_mut(vm_id)?.transition(VmState::Idle);
        Ok(())
    }

    /// Restore a VM to a snapshot.
    ///
    /// # Errors
    /// Returns [`OrchestratorError::SnapshotNotFound`] if the snapshot does not exist.
    /// Returns [`OrchestratorError::VmNotFound`] if `vm_id` is not in the pool.
    pub fn restore_snapshot(&mut self, vm_id: &str, name: &str) -> Result<(), OrchestratorError> {
        if self.snapshots.find(vm_id, name).is_none() {
            return Err(OrchestratorError::SnapshotNotFound(
                name.to_string(),
                vm_id.to_string(),
            ));
        }
        let vm = self.pool.get_mut(vm_id)?;
        vm.transition(VmState::Restoring);
        vm.transition(VmState::Idle);
        Ok(())
    }

    /// Overall metrics snapshot.
    #[must_use]
    pub const fn current_metrics(&self) -> &VmMetrics {
        &self.metrics
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn orch() -> VmOrchestrator {
        VmOrchestrator::with_clock(4, 32, || 1000)
    }

    fn setup_vm(o: &mut VmOrchestrator) {
        o.register_vm("vm-1", "win10-base").unwrap();
        o.set_vm_idle("vm-1").unwrap();
    }

    // ── VmState ──────────────────────────────────────────────────────────────

    #[test]
    fn test_idle_is_available() {
        assert!(VmState::Idle.is_available());
    }
    #[test]
    fn test_running_not_available() {
        assert!(!VmState::Running.is_available());
    }
    #[test]
    fn test_state_labels() {
        assert_eq!(VmState::Error.label(), "error");
    }

    // ── VmLifecycle ──────────────────────────────────────────────────────────

    #[test]
    fn test_lifecycle_new_is_off() {
        let v = VmLifecycle::new("vm-1", "base", 0);
        assert_eq!(v.state, VmState::Off);
    }

    #[test]
    fn test_lifecycle_transition() {
        let mut v = VmLifecycle::new("vm-1", "base", 0);
        v.transition(VmState::Idle);
        assert_eq!(v.state, VmState::Idle);
    }

    #[test]
    fn test_lifecycle_finish_job() {
        let mut v = VmLifecycle::new("vm-1", "base", 0);
        v.transition(VmState::Running);
        v.finish_job(42);
        assert_eq!(v.state, VmState::Idle);
        assert_eq!(v.job_count, 1);
    }

    #[test]
    fn test_lifecycle_record_error() {
        let mut v = VmLifecycle::new("vm-1", "base", 0);
        v.record_error();
        assert!(!v.is_healthy() || v.error_count == 1);
    }

    // ── SnapshotManager ──────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_add_and_find() {
        let mut sm = SnapshotManager::new();
        sm.add(SnapshotEntry {
            vm_id: "vm-1".into(),
            name: "snap1".into(),
            created_at: 0,
            size_bytes: 1024,
            description: None,
            is_base: true,
        });
        assert!(sm.find("vm-1", "snap1").is_some());
    }

    #[test]
    fn test_snapshot_delete() {
        let mut sm = SnapshotManager::new();
        sm.add(SnapshotEntry {
            vm_id: "vm-1".into(),
            name: "s1".into(),
            created_at: 0,
            size_bytes: 512,
            description: None,
            is_base: false,
        });
        assert!(sm.delete("vm-1", "s1"));
        assert!(sm.find("vm-1", "s1").is_none());
    }

    #[test]
    fn test_snapshot_total_bytes() {
        let mut sm = SnapshotManager::new();
        sm.add(SnapshotEntry {
            vm_id: "vm-1".into(),
            name: "a".into(),
            created_at: 0,
            size_bytes: 1000,
            description: None,
            is_base: false,
        });
        sm.add(SnapshotEntry {
            vm_id: "vm-1".into(),
            name: "b".into(),
            created_at: 0,
            size_bytes: 500,
            description: None,
            is_base: false,
        });
        assert_eq!(sm.total_bytes(), 1500);
    }

    // ── JobQueue ─────────────────────────────────────────────────────────────

    #[test]
    fn test_queue_enqueue_dequeue() {
        let mut q = JobQueue::new(10);
        let id = q.enqueue("sample.exe", JobPriority::Normal, 0).unwrap();
        let job = q.dequeue().unwrap();
        assert_eq!(job.id, id);
    }

    #[test]
    fn test_queue_priority_order() {
        let mut q = JobQueue::new(10);
        q.enqueue("low.exe", JobPriority::Low, 0).unwrap();
        q.enqueue("critical.exe", JobPriority::Critical, 0).unwrap();
        q.enqueue("normal.exe", JobPriority::Normal, 0).unwrap();
        let first = q.dequeue().unwrap();
        assert_eq!(first.priority, JobPriority::Critical);
    }

    #[test]
    fn test_queue_full_error() {
        let mut q = JobQueue::new(2);
        q.enqueue("a", JobPriority::Normal, 0).unwrap();
        q.enqueue("b", JobPriority::Normal, 0).unwrap();
        assert!(q.enqueue("c", JobPriority::Normal, 0).is_err());
    }

    #[test]
    fn test_queue_depth() {
        let mut q = JobQueue::new(10);
        q.enqueue("a", JobPriority::Normal, 0).unwrap();
        q.enqueue("b", JobPriority::Normal, 0).unwrap();
        assert_eq!(q.depth(), 2);
    }

    // ── VmPool ───────────────────────────────────────────────────────────────

    #[test]
    fn test_pool_add_and_idle() {
        let mut p = VmPool::new(2);
        p.add_vm("vm-1", "base", 0).unwrap();
        p.get_mut("vm-1").unwrap().transition(VmState::Idle);
        assert_eq!(p.idle_count(), 1);
    }

    #[test]
    fn test_pool_exhausted() {
        let mut p = VmPool::new(1);
        p.add_vm("vm-1", "base", 0).unwrap();
        assert!(p.add_vm("vm-2", "base", 0).is_err());
    }

    // ── VmMetrics ────────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_completion_rate() {
        let m = VmMetrics {
            total_jobs_submitted: 10,
            total_jobs_completed: 8,
            ..Default::default()
        };
        assert!((m.completion_rate() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_metrics_failure_rate() {
        let m = VmMetrics {
            total_jobs_submitted: 10,
            total_jobs_failed: 2,
            ..Default::default()
        };
        assert!((m.failure_rate() - 0.2).abs() < 1e-9);
    }

    // ── VmOrchestrator ───────────────────────────────────────────────────────

    #[test]
    fn test_orchestrator_submit_and_assign() {
        let mut o = orch();
        setup_vm(&mut o);
        let job_id = o.submit_job("sample.exe", JobPriority::Normal).unwrap();
        let (vm, jid) = o.assign_next().unwrap();
        assert_eq!(jid, job_id);
        assert_eq!(vm, "vm-1");
    }

    #[test]
    fn test_orchestrator_no_vms_error() {
        let mut o = orch();
        o.submit_job("s.exe", JobPriority::Normal).unwrap();
        assert!(o.assign_next().is_err());
    }

    #[test]
    fn test_orchestrator_complete_job() {
        let mut o = orch();
        setup_vm(&mut o);
        let jid = o.submit_job("s.exe", JobPriority::Normal).unwrap();
        let (vm, _) = o.assign_next().unwrap();
        o.complete_job(&vm, jid).unwrap();
        assert_eq!(o.metrics.total_jobs_completed, 1);
    }

    #[test]
    fn test_orchestrator_snapshot_restore() {
        let mut o = orch();
        setup_vm(&mut o);
        o.snapshot("vm-1", "clean-state", 1024 * 1024).unwrap();
        assert!(o.snapshots.find("vm-1", "clean-state").is_some());
        o.restore_snapshot("vm-1", "clean-state").unwrap();
        assert_eq!(o.pool.get_mut("vm-1").unwrap().state, VmState::Idle);
    }

    #[test]
    fn test_orchestrator_snapshot_not_found() {
        let mut o = orch();
        setup_vm(&mut o);
        assert!(o.restore_snapshot("vm-1", "nonexistent").is_err());
    }

    #[test]
    fn test_orchestrator_fail_job() {
        let mut o = orch();
        setup_vm(&mut o);
        o.submit_job("s.exe", JobPriority::Normal).unwrap();
        o.assign_next().unwrap();
        o.fail_job("vm-1").unwrap();
        assert_eq!(o.metrics.total_jobs_failed, 1);
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_vm_state_off_not_available() {
        assert!(!VmState::Off.is_available());
    }

    #[test]
    fn test_job_priority_order() {
        assert!(JobPriority::Critical > JobPriority::High);
        assert!(JobPriority::High > JobPriority::Normal);
        assert!(JobPriority::Normal > JobPriority::Low);
    }

    #[test]
    fn test_job_turnaround_some() {
        let mut j = SandboxJob::new(1, "x", JobPriority::Normal, 100);
        j.finished_at = Some(200);
        assert_eq!(j.turnaround_secs(), Some(100));
    }

    #[test]
    fn test_job_turnaround_none_when_not_finished() {
        let j = SandboxJob::new(1, "x", JobPriority::Normal, 0);
        assert_eq!(j.turnaround_secs(), None);
    }

    #[test]
    fn test_pool_pick_idle_none_when_all_running() {
        let mut p = VmPool::new(2);
        p.add_vm("vm-1", "base", 0).unwrap();
        p.get_mut("vm-1").unwrap().transition(VmState::Running);
        assert!(p.pick_idle().is_none());
    }

    #[test]
    fn test_metrics_zero_completion() {
        let m = VmMetrics::default();
        assert_eq!(m.completion_rate(), 0.0);
        assert_eq!(m.failure_rate(), 0.0);
    }

    #[test]
    fn test_snapshot_for_vm_empty() {
        let sm = SnapshotManager::new();
        assert!(sm.for_vm("vm-99").is_empty());
    }

    #[test]
    fn test_orchestrator_vm_not_found() {
        let mut o = orch();
        assert!(o.set_vm_idle("nonexistent").is_err());
    }
}
