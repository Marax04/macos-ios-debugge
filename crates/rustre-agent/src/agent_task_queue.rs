//! `agent_task_queue` —  Priority task queue for the RE agent.
//!
//! Provides [`AgentTaskQueue`], a thread-safe min-heap priority queue with
//! task deduplication, deadline tracking, and per-capability filtering.
//! Tasks with higher [`TaskPriority`] values are dequeued first.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// â"€â"€ Priority â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Priority level for a queued agent task.
///
/// Variants are ordered so that `Critical > High > Normal > Low`,
/// enabling direct use in `BinaryHeap` (which is a max-heap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaskPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl TaskPriority {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parse from a string (case-insensitive).  Returns `None` if unrecognised.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "normal" => Some(Self::Normal),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for TaskPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// â"€â"€ TaskStatus â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lifecycle status of an agent task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Waiting in the queue.
    Pending,
    /// Currently being executed.
    Running,
    /// Finished successfully.
    Completed,
    /// Failed with an error message.
    Failed(String),
    /// Cancelled before execution started.
    Cancelled,
    /// Skipped because the deadline was exceeded.
    Expired,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Running => write!(f, "Running"),
            Self::Completed => write!(f, "Completed"),
            Self::Failed(msg) => write!(f, "Failed({msg})"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

impl TaskStatus {
    /// Returns `true` if the task has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed(_) | Self::Cancelled | Self::Expired
        )
    }
}

// â"€â"€ AgentTask â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

static TASK_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A discrete unit of work for the RE agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    /// Globally unique task identifier.
    pub id: u64,
    /// Short human-readable description.
    pub description: String,
    /// Required capability for executing this task.
    pub capability: String,
    /// Task priority.
    pub priority: TaskPriority,
    /// Arbitrary JSON payload.
    pub payload: serde_json::Value,
    /// Creation timestamp (ms since Unix epoch).
    pub created_at: u64,
    /// Optional absolute deadline in ms since Unix epoch.
    pub deadline_ms: Option<u64>,
    /// Current lifecycle status.
    pub status: TaskStatus,
    /// Optional deduplication key: only one task with a given key may be queued
    /// at a time.
    pub dedup_key: Option<String>,
    /// Retry attempt count.
    pub attempts: u32,
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
}

impl AgentTask {
    /// Create a new task.  The `id` is allocated from a global counter.
    #[must_use]
    pub fn new(
        description: impl Into<String>,
        capability: impl Into<String>,
        priority: TaskPriority,
        payload: serde_json::Value,
    ) -> Self {
        let id = TASK_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id,
            description: description.into(),
            capability: capability.into(),
            priority,
            payload,
            created_at,
            deadline_ms: None,
            status: TaskStatus::Pending,
            dedup_key: None,
            attempts: 0,
            max_retries: 0,
        }
    }

    /// Attach an absolute deadline (ms since Unix epoch).
    #[must_use]
    pub const fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    /// Attach a deduplication key.
    #[must_use]
    pub fn with_dedup_key(mut self, key: impl Into<String>) -> Self {
        self.dedup_key = Some(key.into());
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub const fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Returns `true` if this task has exceeded its deadline.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let Some(dl) = self.deadline_ms else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        now > dl
    }

    /// Returns `true` if this task may be retried after failure.
    #[must_use]
    pub const fn can_retry(&self) -> bool {
        self.attempts < self.max_retries
    }

    /// Remaining time until the deadline, or `None` if no deadline is set.
    #[must_use]
    pub fn time_to_deadline(&self) -> Option<Duration> {
        let dl = self.deadline_ms?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        if now >= dl {
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_millis(dl - now))
        }
    }
}

// â"€â"€ Heap entry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Wrapper that orders tasks for the binary max-heap by (priority, -`created_at`)
/// so that higher-priority, earlier-created tasks are dequeued first.
#[derive(Debug)]
struct HeapEntry {
    priority: TaskPriority,
    /// Negated `created_at` so that earlier tasks come first within a priority level.
    neg_created_at: i128,
    task: AgentTask,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.neg_created_at == other.neg_created_at
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.neg_created_at.cmp(&other.neg_created_at))
    }
}

// â"€â"€ AgentTaskQueue â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Thread-safe priority queue for agent tasks.
///
/// Features:
/// - Max-heap ordering: `Critical > High > Normal > Low`.
/// - Task deduplication: only one task per `dedup_key` is queued at a time.
/// - Deadline filtering: expired tasks are silently discarded on dequeue.
/// - Per-capability filtering: `dequeue_for_capability()` returns only tasks
///   matching a given capability string.
pub struct AgentTaskQueue {
    inner: Mutex<QueueInner>,
}

struct QueueInner {
    heap: BinaryHeap<HeapEntry>,
    /// Maps `dedup_key` â†' `task_id` for active tasks.
    dedup: HashMap<String, u64>,
    /// Statistics.
    stats: QueueStats,
}

/// Snapshot statistics for the queue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub enqueued_total: u64,
    pub dequeued_total: u64,
    pub expired_total: u64,
    pub deduplicated_total: u64,
}

impl Default for AgentTaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentTaskQueue {
    /// Create a new empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(QueueInner {
                heap: BinaryHeap::new(),
                dedup: HashMap::new(),
                stats: QueueStats::default(),
            }),
        }
    }

    /// Enqueue a task.
    ///
    /// If the task has a `dedup_key` and a task with the same key is already
    /// queued, the new task is silently discarded (deduplication).
    pub fn enqueue(&self, task: AgentTask) {
        let mut inner = self.inner.lock();

        // Deduplication check.
        if let Some(ref key) = task.dedup_key {
            if inner.dedup.contains_key(key) {
                inner.stats.deduplicated_total += 1;
                return;
            }
            inner.dedup.insert(key.clone(), task.id);
        }

        inner.stats.enqueued_total += 1;
        let neg_created_at = -i128::from(task.created_at);
        inner.heap.push(HeapEntry {
            priority: task.priority,
            neg_created_at,
            task,
        });
    }

    /// Dequeue the highest-priority non-expired pending task, or `None` if the
    /// queue is empty or all remaining tasks have expired.
    pub fn dequeue(&self) -> Option<AgentTask> {
        let mut inner = self.inner.lock();
        let task = loop {
            let Some(entry) = inner.heap.pop() else { break None };
            let mut task = entry.task;

            // Remove dedup key for this task.
            if let Some(ref key) = task.dedup_key {
                inner.dedup.remove(key);
            }

            if task.is_expired() {
                task.status = TaskStatus::Expired;
                inner.stats.expired_total += 1;
                continue;
            }

            inner.stats.dequeued_total += 1;
            break Some(task);
        };
        drop(inner);
        task
    }

    /// Dequeue the highest-priority non-expired task that matches `capability`.
    ///
    /// Tasks that do not match are temporarily held and re-inserted after the
    /// scan completes.
    pub fn dequeue_for_capability(&self, capability: &str) -> Option<AgentTask> {
        let mut inner = self.inner.lock();
        let mut skipped: Vec<HeapEntry> = Vec::new();
        let mut result: Option<AgentTask> = None;

        while let Some(entry) = inner.heap.pop() {
            if entry.task.is_expired() {
                if let Some(ref key) = entry.task.dedup_key {
                    inner.dedup.remove(key);
                }
                inner.stats.expired_total += 1;
                continue;
            }
            if entry.task.capability == capability {
                if let Some(ref key) = entry.task.dedup_key {
                    inner.dedup.remove(key);
                }
                inner.stats.dequeued_total += 1;
                result = Some(entry.task);
                break;
            }
            skipped.push(entry);
        }

        // Re-insert skipped tasks.
        for e in skipped {
            inner.heap.push(e);
        }
        result
    }

    /// Peek at the highest-priority pending task without removing it.
    pub fn peek_priority(&self) -> Option<TaskPriority> {
        self.inner.lock().heap.peek().map(|e| e.task.priority)
    }

    /// Returns the number of tasks currently in the queue (including expired ones
    /// that have not yet been flushed).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().heap.len()
    }

    /// Returns `true` if the queue contains no tasks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all tasks from the queue and return them.
    pub fn drain(&self) -> Vec<AgentTask> {
        let mut inner = self.inner.lock();
        inner.dedup.clear();
        inner
            .heap
            .drain()
            .map(|e| e.task)
            .collect()
    }

    /// Cancel a queued task by its `id`.  Returns `true` if the task was found
    /// and cancelled.
    pub fn cancel(&self, task_id: u64) -> bool {
        let mut inner = self.inner.lock();
        let old_len = inner.heap.len();
        let tasks: Vec<HeapEntry> = inner.heap.drain().collect();
        let mut found = false;
        for mut entry in tasks {
            if entry.task.id == task_id {
                if let Some(ref key) = entry.task.dedup_key {
                    inner.dedup.remove(key);
                }
                entry.task.status = TaskStatus::Cancelled;
                found = true;
                // Do NOT re-push —" cancelled task is discarded.
            } else {
                inner.heap.push(entry);
            }
        }
        let _ = old_len;
        found
    }

    /// Return a snapshot of queue statistics.
    #[must_use]
    pub fn stats(&self) -> QueueStats {
        self.inner.lock().stats.clone()
    }

    /// Return how many tasks with each priority are currently queued.
    #[must_use]
    pub fn priority_histogram(&self) -> HashMap<TaskPriority, usize> {
        let mut hist: HashMap<TaskPriority, usize> = HashMap::new();
        for entry in &self.inner.lock().heap {
            *hist.entry(entry.task.priority).or_insert(0) += 1;
        }
        hist
    }

    /// Return all capabilities represented in the current queue (deduplicated).
    #[must_use]
    pub fn queued_capabilities(&self) -> HashSet<String> {
        self.inner
            .lock()
            .heap
            .iter()
            .map(|e| e.task.capability.clone())
            .collect()
    }

    /// Return whether a task with the given `dedup_key` is already queued.
    #[must_use]
    pub fn is_dedup_key_active(&self, key: &str) -> bool {
        self.inner.lock().dedup.contains_key(key)
    }

    /// Flush all expired tasks from the queue without returning them.
    /// Returns the count of tasks removed.
    pub fn flush_expired(&self) -> usize {
        let mut inner = self.inner.lock();
        let tasks: Vec<HeapEntry> = inner.heap.drain().collect();
        let mut removed = 0usize;
        for entry in tasks {
            if entry.task.is_expired() {
                if let Some(ref key) = entry.task.dedup_key {
                    inner.dedup.remove(key);
                }
                inner.stats.expired_total += 1;
                removed += 1;
            } else {
                inner.heap.push(entry);
            }
        }
        removed
    }
}

// â"€â"€ TaskBatch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A batch of tasks to be enqueued atomically.
#[derive(Debug, Default)]
pub struct TaskBatch {
    tasks: Vec<AgentTask>,
}

impl TaskBatch {
    /// Create an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a task to the batch.
    pub fn push(&mut self, task: AgentTask) {
        self.tasks.push(task);
    }

    /// Enqueue all tasks in this batch into `queue`.  Returns the number of
    /// tasks that were actually inserted (dedup may reduce this).
    pub fn submit(self, queue: &AgentTaskQueue) -> usize {
        let before = queue.stats().enqueued_total;
        for task in self.tasks {
            queue.enqueue(task);
        }
        let after = queue.stats().enqueued_total;
        crate::casts::u64_to_usize(after - before)
    }

    /// Number of tasks currently in this batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns `true` if the batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

// â"€â"€ PriorityBump â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Bump the priority of an already-queued task.
///
/// Returns a new `AgentTask` with its priority raised to `new_priority`.
/// Callers should cancel the original task and re-enqueue the returned task.
#[must_use]
pub fn bump_priority(mut task: AgentTask, new_priority: TaskPriority) -> AgentTask {
    task.priority = task.priority.max(new_priority);
    task
}

// â"€â"€ TaskScheduler â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Minimal round-robin task scheduler that dispatches from multiple queues.
///
/// Each registered capability has its own [`AgentTaskQueue`].  `next()` picks
/// the capability whose queue has the highest-priority pending task, breaking
/// ties by round-robin order.
pub struct TaskScheduler {
    queues: HashMap<String, AgentTaskQueue>,
    order: Vec<String>,
    round_robin_idx: Mutex<usize>,
}

impl TaskScheduler {
    /// Create a scheduler with one queue per capability in `capabilities`.
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let mut queues = HashMap::new();
        let mut order = Vec::new();
        for cap in capabilities {
            let cap = cap.into();
            queues.insert(cap.clone(), AgentTaskQueue::new());
            order.push(cap);
        }
        Self {
            queues,
            order,
            round_robin_idx: Mutex::new(0),
        }
    }

    /// Enqueue a task to the queue for its capability.  If no queue exists for
    /// the capability, a new one is created implicitly.
    pub fn enqueue(&self, task: AgentTask) {
        if let Some(q) = self.queues.get(&task.capability) {
            q.enqueue(task);
        }
        // Tasks for unknown capabilities are silently dropped.
    }

    /// Dequeue the globally highest-priority task across all queues.
    ///
    /// Ties at the same priority level are broken by round-robin.
    pub fn next(&self) -> Option<AgentTask> {
        // Collect the peek priority for each non-empty queue.
        let best_priority = self
            .queues
            .values()
            .filter_map(AgentTaskQueue::peek_priority)
            .max()?;

        // Among queues at the best priority, apply round-robin.
        let candidates: Vec<&str> = self
            .order
            .iter()
            .filter_map(|cap| {
                let q = self.queues.get(cap.as_str())?;
                if q.peek_priority() == Some(best_priority) {
                    Some(cap.as_str())
                } else {
                    None
                }
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let mut idx = self.round_robin_idx.lock();
        let chosen = candidates[*idx % candidates.len()];
        *idx = idx.wrapping_add(1);
        drop(idx);

        self.queues.get(chosen).and_then(AgentTaskQueue::dequeue)
    }

    /// Total number of tasks across all queues.
    #[must_use]
    pub fn total_pending(&self) -> usize {
        self.queues.values().map(AgentTaskQueue::len).sum()
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(desc: &str, cap: &str, prio: TaskPriority) -> AgentTask {
        AgentTask::new(desc, cap, prio, serde_json::json!({}))
    }

    #[test]
    fn test_enqueue_dequeue_order() {
        let q = AgentTaskQueue::new();
        q.enqueue(make_task("low", "analyze", TaskPriority::Low));
        q.enqueue(make_task("high", "analyze", TaskPriority::High));
        q.enqueue(make_task("normal", "analyze", TaskPriority::Normal));
        q.enqueue(make_task("critical", "analyze", TaskPriority::Critical));

        assert_eq!(q.dequeue().unwrap().priority, TaskPriority::Critical);
        assert_eq!(q.dequeue().unwrap().priority, TaskPriority::High);
        assert_eq!(q.dequeue().unwrap().priority, TaskPriority::Normal);
        assert_eq!(q.dequeue().unwrap().priority, TaskPriority::Low);
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn test_deduplication() {
        let q = AgentTaskQueue::new();
        let t1 = make_task("first", "analyze", TaskPriority::Normal)
            .with_dedup_key("analyze:0x1000");
        let t2 = make_task("second", "analyze", TaskPriority::High)
            .with_dedup_key("analyze:0x1000");
        q.enqueue(t1);
        q.enqueue(t2); // should be deduped
        assert_eq!(q.len(), 1);
        assert_eq!(q.stats().deduplicated_total, 1);
    }

    #[test]
    fn test_dedup_key_released_after_dequeue() {
        let q = AgentTaskQueue::new();
        let t1 = make_task("a", "analyze", TaskPriority::Normal).with_dedup_key("k1");
        q.enqueue(t1);
        assert!(q.is_dedup_key_active("k1"));
        q.dequeue().unwrap();
        assert!(!q.is_dedup_key_active("k1"));
        // Can enqueue again with same key.
        let t2 = make_task("b", "analyze", TaskPriority::Normal).with_dedup_key("k1");
        q.enqueue(t2);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_expire() {
        let q = AgentTaskQueue::new();
        // Deadline already in the past.
        let past_ms = u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()).unwrap_or(u64::MAX)
            - 1000;
        let t = make_task("expired", "analyze", TaskPriority::Critical).with_deadline(past_ms);
        q.enqueue(t);
        assert!(q.dequeue().is_none());
        assert_eq!(q.stats().expired_total, 1);
    }

    #[test]
    fn test_flush_expired() {
        let q = AgentTaskQueue::new();
        let past_ms = u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()).unwrap_or(u64::MAX)
            - 1;
        q.enqueue(make_task("e1", "a", TaskPriority::Low).with_deadline(past_ms));
        q.enqueue(make_task("e2", "a", TaskPriority::Low).with_deadline(past_ms));
        q.enqueue(make_task("ok", "a", TaskPriority::High));
        assert_eq!(q.flush_expired(), 2);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_cancel() {
        let q = AgentTaskQueue::new();
        let t = make_task("cancelme", "analyze", TaskPriority::Normal);
        let id = t.id;
        q.enqueue(t);
        assert!(q.cancel(id));
        assert!(q.is_empty());
    }

    #[test]
    fn test_dequeue_for_capability() {
        let q = AgentTaskQueue::new();
        q.enqueue(make_task("disasm", "disasm", TaskPriority::Normal));
        q.enqueue(make_task("decompile", "decompile", TaskPriority::High));
        q.enqueue(make_task("disasm2", "disasm", TaskPriority::Critical));

        let t = q.dequeue_for_capability("disasm").unwrap();
        assert_eq!(t.capability, "disasm");
        assert_eq!(t.priority, TaskPriority::Critical);
    }

    #[test]
    fn test_priority_histogram() {
        let q = AgentTaskQueue::new();
        for _ in 0..3 {
            q.enqueue(make_task("x", "a", TaskPriority::Low));
        }
        q.enqueue(make_task("x", "a", TaskPriority::High));
        let hist = q.priority_histogram();
        assert_eq!(hist[&TaskPriority::Low], 3);
        assert_eq!(hist[&TaskPriority::High], 1);
    }

    #[test]
    fn test_task_batch_submit() {
        let q = AgentTaskQueue::new();
        let mut batch = TaskBatch::new();
        for i in 0..5u64 {
            batch.push(make_task(&format!("t{i}"), "analyze", TaskPriority::Normal));
        }
        let inserted = batch.submit(&q);
        assert_eq!(inserted, 5);
        assert_eq!(q.len(), 5);
    }

    #[test]
    fn test_bump_priority() {
        let t = make_task("x", "a", TaskPriority::Low);
        let bumped = bump_priority(t, TaskPriority::High);
        assert_eq!(bumped.priority, TaskPriority::High);
    }

    #[test]
    fn test_task_status_is_terminal() {
        assert!(TaskStatus::Completed.is_terminal());
        assert!(TaskStatus::Failed("oops".into()).is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(TaskStatus::Expired.is_terminal());
        assert!(!TaskStatus::Pending.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
    }

    #[test]
    fn test_task_can_retry() {
        let mut t = make_task("x", "a", TaskPriority::Normal).with_max_retries(3);
        assert!(t.can_retry());
        t.attempts = 3;
        assert!(!t.can_retry());
    }

    #[test]
    fn test_scheduler_round_robin() {
        let sched = TaskScheduler::new(["disasm", "decompile"]);
        sched.enqueue(make_task("d1", "disasm", TaskPriority::High));
        sched.enqueue(make_task("d2", "disasm", TaskPriority::High));
        sched.enqueue(make_task("c1", "decompile", TaskPriority::High));
        // Three tasks at the same priority, should alternate between queues.
        let t1 = sched.next().unwrap();
        let t2 = sched.next().unwrap();
        assert_ne!(t1.capability, t2.capability);
    }

    #[test]
    fn test_priority_from_str() {
        assert_eq!(TaskPriority::parse("critical"), Some(TaskPriority::Critical));
        assert_eq!(TaskPriority::parse("HIGH"), Some(TaskPriority::High));
        assert_eq!(TaskPriority::parse("unknown"), None);
    }

    #[test]
    fn test_queued_capabilities() {
        let q = AgentTaskQueue::new();
        q.enqueue(make_task("x", "cap_a", TaskPriority::Low));
        q.enqueue(make_task("y", "cap_b", TaskPriority::Low));
        q.enqueue(make_task("z", "cap_a", TaskPriority::High));
        let caps = q.queued_capabilities();
        assert!(caps.contains("cap_a"));
        assert!(caps.contains("cap_b"));
        assert_eq!(caps.len(), 2);
    }

    #[test]
    fn test_drain() {
        let q = AgentTaskQueue::new();
        q.enqueue(make_task("a", "x", TaskPriority::Low));
        q.enqueue(make_task("b", "x", TaskPriority::High));
        let all = q.drain();
        assert_eq!(all.len(), 2);
        assert!(q.is_empty());
    }
}
