//! `task_planner` — break complex reverse engineering tasks into ordered subtasks.
//!
//! Provides a DAG-based [`TaskGraph`] with topological scheduling, priority
//! levels, and per-task result tracking.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ─── TaskPriority ────────────────────────────────────────────────────────────

/// Scheduling priority for a task node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum TaskPriority {
    Low = 0,
    #[default]
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for TaskPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Normal => write!(f, "normal"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}


// ─── TaskStatus ──────────────────────────────────────────────────────────────

/// Lifecycle status of a single task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Waiting for dependencies to complete.
    Pending,
    /// All dependencies satisfied; ready to run.
    Ready,
    /// Currently executing.
    Running,
    /// Finished successfully.
    Completed,
    /// Finished with an error.
    Failed(String),
    /// Cancelled before execution.
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Ready => write!(f, "ready"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed(e) => write!(f, "failed({e})"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ─── SubtaskResult ───────────────────────────────────────────────────────────

/// Output produced when a subtask completes (successfully or not).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtaskResult {
    /// ID of the task that produced this result.
    pub task_id: u64,
    /// Human-readable summary.
    pub summary: String,
    /// Structured output data.
    pub data: serde_json::Value,
    /// Whether the subtask succeeded.
    pub success: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

impl SubtaskResult {
    /// Create a successful result.
    #[must_use]
    pub fn ok(
        task_id: u64,
        summary: impl Into<String>,
        data: serde_json::Value,
        duration_ms: u64,
    ) -> Self {
        Self {
            task_id,
            summary: summary.into(),
            data,
            success: true,
            duration_ms,
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn err(task_id: u64, reason: impl Into<String>) -> Self {
        Self {
            task_id,
            summary: reason.into(),
            data: serde_json::Value::Null,
            success: false,
            duration_ms: 0,
        }
    }
}

// ─── Task ────────────────────────────────────────────────────────────────────

/// A single unit of work in the planning graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    /// Unique identifier within the graph.
    pub id: u64,
    /// Human-readable description.
    pub description: String,
    /// IDs of tasks that must complete before this one can start.
    pub dependencies: Vec<u64>,
    /// Current lifecycle status.
    pub status: TaskStatus,
    /// Scheduling priority.
    pub priority: TaskPriority,
    /// Optional estimated duration in milliseconds.
    pub estimated_ms: Option<u64>,
    /// Result produced after execution.
    pub result: Option<SubtaskResult>,
    /// Free-form metadata tags.
    pub tags: Vec<String>,
}

impl Task {
    /// Create a new task with `Pending` status.
    #[must_use]
    pub fn new(
        id: u64,
        description: impl Into<String>,
        dependencies: Vec<u64>,
        priority: TaskPriority,
    ) -> Self {
        Self {
            id,
            description: description.into(),
            dependencies,
            status: TaskStatus::Pending,
            priority,
            estimated_ms: None,
            result: None,
            tags: Vec::new(),
        }
    }

    /// Attach an estimated duration.
    #[must_use]
    pub const fn with_estimated_ms(mut self, ms: u64) -> Self {
        self.estimated_ms = Some(ms);
        self
    }

    /// Attach a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Returns `true` if the task is in a terminal state.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(
            self.status,
            TaskStatus::Completed | TaskStatus::Failed(_) | TaskStatus::Cancelled
        )
    }

    /// Returns `true` if all dependencies are satisfied (completed).
    #[must_use]
    pub fn deps_satisfied(&self, completed: &HashSet<u64>) -> bool {
        self.dependencies.iter().all(|d| completed.contains(d))
    }
}

// ─── TaskGraph ───────────────────────────────────────────────────────────────

/// Directed acyclic graph of [`Task`] nodes.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TaskGraph {
    tasks: HashMap<u64, Task>,
    next_id: u64,
}

impl TaskGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a task, auto-assigning an ID if `task.id == 0`.
    pub fn add_task(&mut self, mut task: Task) -> u64 {
        if task.id == 0 {
            self.next_id += 1;
            task.id = self.next_id;
        } else if task.id > self.next_id {
            self.next_id = task.id;
        }
        let id = task.id;
        self.tasks.insert(id, task);
        id
    }

    /// Retrieve a task by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Task> {
        self.tasks.get(&id)
    }

    /// Retrieve a task mutably by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Task> {
        self.tasks.get_mut(&id)
    }

    /// Number of tasks in the graph.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns `true` if the graph contains no tasks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Collect IDs of all tasks in the given status.
    #[must_use]
    pub fn tasks_in_status(&self, status: &TaskStatus) -> Vec<u64> {
        self.tasks
            .values()
            .filter(|t| &t.status == status)
            .map(|t| t.id)
            .collect()
    }

    /// Mark a task as completed and attach its result.
    pub fn complete_task(&mut self, id: u64, result: SubtaskResult) {
        if let Some(t) = self.tasks.get_mut(&id) {
            t.result = Some(result);
            t.status = TaskStatus::Completed;
        }
    }

    /// Mark a task as failed.
    pub fn fail_task(&mut self, id: u64, reason: impl Into<String>) {
        if let Some(t) = self.tasks.get_mut(&id) {
            t.status = TaskStatus::Failed(reason.into());
        }
    }

    /// Promote `Pending` tasks whose dependencies are all `Completed` to `Ready`.
    pub fn refresh_ready(&mut self) {
        let completed: HashSet<u64> = self
            .tasks
            .values()
            .filter(|t| t.status == TaskStatus::Completed)
            .map(|t| t.id)
            .collect();
        for task in self.tasks.values_mut() {
            if task.status == TaskStatus::Pending && task.deps_satisfied(&completed) {
                task.status = TaskStatus::Ready;
            }
        }
    }

    /// Detect cycles using DFS. Returns the cycle as a Vec of IDs if one exists.
    #[must_use]
    pub fn find_cycle(&self) -> Option<Vec<u64>> {
        fn dfs(
            id: u64,
            tasks: &HashMap<u64, Task>,
            visited: &mut HashSet<u64>,
            stack: &mut HashSet<u64>,
            path: &mut Vec<u64>,
        ) -> bool {
            if stack.contains(&id) {
                return true;
            }
            if visited.contains(&id) {
                return false;
            }
            visited.insert(id);
            stack.insert(id);
            path.push(id);
            if let Some(task) = tasks.get(&id) {
                for &dep in &task.dependencies {
                    if dfs(dep, tasks, visited, stack, path) {
                        return true;
                    }
                }
            }
            stack.remove(&id);
            path.pop();
            false
        }

        let mut visited: HashSet<u64> = HashSet::new();
        let mut stack: HashSet<u64> = HashSet::new();
        let mut path: Vec<u64> = Vec::new();

        for &id in self.tasks.keys() {
            if dfs(id, &self.tasks, &mut visited, &mut stack, &mut path) {
                return Some(path.clone());
            }
        }
        None
    }
}

// ─── TaskScheduler ───────────────────────────────────────────────────────────

/// Produces a topologically-sorted execution order from a [`TaskGraph`].
#[derive(Debug)]
pub struct TaskScheduler {
    graph: TaskGraph,
}

impl TaskScheduler {
    /// Create a scheduler wrapping `graph`.
    #[must_use]
    pub const fn new(graph: TaskGraph) -> Self {
        Self { graph }
    }

    /// Return a reference to the underlying graph.
    #[must_use]
    pub const fn graph(&self) -> &TaskGraph {
        &self.graph
    }

    /// Return a mutable reference to the underlying graph.
    pub const fn graph_mut(&mut self) -> &mut TaskGraph {
        &mut self.graph
    }

    /// Compute a topological ordering of all tasks.
    ///
    /// Within each topological level, tasks are sorted by priority (descending)
    /// so higher-priority work is scheduled first.
    ///
    /// Returns `None` if a cycle is detected.
    #[must_use]
    pub fn topological_order(&self) -> Option<Vec<u64>> {
        // Kahn's algorithm
        let tasks = &self.graph.tasks;
        let mut in_degree: HashMap<u64, usize> = tasks.keys().map(|&id| (id, 0)).collect();

        for task in tasks.values() {
            for &dep in &task.dependencies {
                if tasks.contains_key(&dep) {
                    *in_degree.entry(task.id).or_insert(0) += 1;
                }
            }
        }

        // Recalculate properly: count how many *of task's own deps* are present.
        let mut in_deg: HashMap<u64, usize> = tasks.keys().map(|&id| (id, 0)).collect();
        for task in tasks.values() {
            for &dep in &task.dependencies {
                if tasks.contains_key(&dep) {
                    *in_deg.entry(task.id).or_insert(0) += 1;
                }
            }
        }
        let _ = in_degree; // shadowed above

        // Seeds: tasks with in-degree 0, sorted by priority desc.
        let mut queue: VecDeque<u64> = {
            let mut seeds: Vec<u64> = in_deg
                .iter()
                .filter(|&(_, &d)| d == 0)
                .map(|(&id, _)| id)
                .collect();
            seeds.sort_by(|a, b| {
                let pa = tasks[b].priority;
                let pb = tasks[a].priority;
                pa.cmp(&pb)
            });
            seeds.into()
        };

        let mut result = Vec::with_capacity(tasks.len());
        // Build reverse adjacency: dep → tasks that depend on dep.
        let mut rev: HashMap<u64, Vec<u64>> = HashMap::new();
        for task in tasks.values() {
            for &dep in &task.dependencies {
                rev.entry(dep).or_default().push(task.id);
            }
        }

        while let Some(id) = queue.pop_front() {
            result.push(id);
            if let Some(dependents) = rev.get(&id) {
                let mut next: Vec<u64> = dependents
                    .iter()
                    .filter_map(|&d| {
                        let deg = in_deg.get_mut(&d)?;
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 { Some(d) } else { None }
                    })
                    .collect();
                next.sort_by(|a, b| tasks[b].priority.cmp(&tasks[a].priority));
                for n in next {
                    queue.push_back(n);
                }
            }
        }

        if result.len() == tasks.len() {
            Some(result)
        } else {
            None
        }
    }

    /// Return all tasks that are currently `Ready`, sorted by priority desc.
    #[must_use]
    pub fn ready_tasks(&self) -> Vec<&Task> {
        let mut ready: Vec<&Task> = self
            .graph
            .tasks
            .values()
            .filter(|t| t.status == TaskStatus::Ready)
            .collect();
        ready.sort_by(|a, b| b.priority.cmp(&a.priority));
        ready
    }

    /// Advance the scheduler state: refresh ready, return next task to run.
    pub fn next_task(&mut self) -> Option<u64> {
        self.graph.refresh_ready();
        self.ready_tasks().first().map(|t| t.id)
    }
}

impl Iterator for TaskScheduler {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        self.next_task()
    }
}

// ─── TaskPlanner ─────────────────────────────────────────────────────────────

/// High-level planner that decomposes a top-level RE goal into subtasks.
pub struct TaskPlanner {
    graph: TaskGraph,
    goal: String,
}

impl TaskPlanner {
    /// Create a new planner with the given high-level goal description.
    #[must_use]
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            graph: TaskGraph::new(),
            goal: goal.into(),
        }
    }

    /// The high-level goal this planner is working towards.
    #[must_use]
    pub fn goal(&self) -> &str {
        &self.goal
    }

    /// Add a subtask and return its assigned ID.
    pub fn add_subtask(
        &mut self,
        description: impl Into<String>,
        deps: Vec<u64>,
        priority: TaskPriority,
    ) -> u64 {
        let task = Task::new(0, description, deps, priority);
        self.graph.add_task(task)
    }

    /// Build the internal scheduler.
    #[must_use]
    pub fn build_scheduler(self) -> TaskScheduler {
        TaskScheduler::new(self.graph)
    }

    /// Convenience: decompose a standard "full analysis" pipeline into subtasks.
    /// Returns a ready-to-run `TaskScheduler`.
    #[must_use]
    pub fn standard_re_pipeline(goal: impl Into<String>) -> TaskScheduler {
        let mut planner = Self::new(goal);

        let disasm = planner.add_subtask("Disassemble binary", vec![], TaskPriority::High);
        let strings = planner.add_subtask("Extract strings", vec![], TaskPriority::Normal);
        let imports =
            planner.add_subtask("Resolve imports / exports", vec![], TaskPriority::Normal);
        let decompile =
            planner.add_subtask("Decompile key functions", vec![disasm], TaskPriority::High);
        let type_rec = planner.add_subtask("Recover types", vec![decompile], TaskPriority::Normal);
        let rename = planner.add_subtask(
            "Rename symbols",
            vec![type_rec, strings],
            TaskPriority::Normal,
        );
        let ioc = planner.add_subtask("Extract IOCs", vec![strings, imports], TaskPriority::High);
        let _report = planner.add_subtask("Generate report", vec![rename, ioc], TaskPriority::Low);

        planner.build_scheduler()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(id: u64, deps: Vec<u64>, priority: TaskPriority) -> Task {
        Task::new(id, format!("task-{id}"), deps, priority)
    }

    // ── TaskPriority ────────────────────────────────────────────────────────

    #[test]
    fn test_priority_ordering() {
        assert!(TaskPriority::Critical > TaskPriority::High);
        assert!(TaskPriority::High > TaskPriority::Normal);
        assert!(TaskPriority::Normal > TaskPriority::Low);
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(TaskPriority::Critical.to_string(), "critical");
        assert_eq!(TaskPriority::Low.to_string(), "low");
    }

    // ── TaskStatus ──────────────────────────────────────────────────────────

    #[test]
    fn test_task_status_display() {
        assert_eq!(TaskStatus::Pending.to_string(), "pending");
        assert_eq!(TaskStatus::Completed.to_string(), "completed");
        assert_eq!(
            TaskStatus::Failed("oops".into()).to_string(),
            "failed(oops)"
        );
    }

    // ── Task ────────────────────────────────────────────────────────────────

    #[test]
    fn test_task_new_pending() {
        let t = make_task(1, vec![], TaskPriority::Normal);
        assert_eq!(t.status, TaskStatus::Pending);
        assert!(t.result.is_none());
    }

    #[test]
    fn test_task_is_done() {
        let mut t = make_task(1, vec![], TaskPriority::Normal);
        assert!(!t.is_done());
        t.status = TaskStatus::Completed;
        assert!(t.is_done());
        t.status = TaskStatus::Cancelled;
        assert!(t.is_done());
    }

    #[test]
    fn test_task_deps_satisfied() {
        let t = make_task(3, vec![1, 2], TaskPriority::Normal);
        let mut done = HashSet::new();
        assert!(!t.deps_satisfied(&done));
        done.insert(1);
        assert!(!t.deps_satisfied(&done));
        done.insert(2);
        assert!(t.deps_satisfied(&done));
    }

    #[test]
    fn test_task_with_tag_and_estimated_ms() {
        let t = Task::new(1, "t", vec![], TaskPriority::High)
            .with_estimated_ms(5000)
            .with_tag("re")
            .with_tag("analysis");
        assert_eq!(t.estimated_ms, Some(5000));
        assert_eq!(t.tags.len(), 2);
    }

    // ── SubtaskResult ───────────────────────────────────────────────────────

    #[test]
    fn test_subtask_result_ok() {
        let r = SubtaskResult::ok(1, "done", serde_json::json!({"found": 3}), 100);
        assert!(r.success);
        assert_eq!(r.task_id, 1);
    }

    #[test]
    fn test_subtask_result_err() {
        let r = SubtaskResult::err(2, "timeout");
        assert!(!r.success);
        assert!(r.summary.contains("timeout"));
    }

    // ── TaskGraph ───────────────────────────────────────────────────────────

    #[test]
    fn test_graph_add_and_get() {
        let mut g = TaskGraph::new();
        let t = make_task(5, vec![], TaskPriority::High);
        g.add_task(t);
        assert_eq!(g.len(), 1);
        assert_eq!(g.get(5).unwrap().id, 5);
    }

    #[test]
    fn test_graph_complete_task() {
        let mut g = TaskGraph::new();
        g.add_task(make_task(1, vec![], TaskPriority::Normal));
        let res = SubtaskResult::ok(1, "done", serde_json::Value::Null, 0);
        g.complete_task(1, res);
        assert_eq!(g.get(1).unwrap().status, TaskStatus::Completed);
    }

    #[test]
    fn test_graph_refresh_ready() {
        let mut g = TaskGraph::new();
        g.add_task(make_task(1, vec![], TaskPriority::Normal));
        g.add_task(make_task(2, vec![1], TaskPriority::Normal));
        g.refresh_ready();
        // Task 1 has no deps → ready; task 2 has dep on 1 which isn't done → pending.
        assert_eq!(g.get(1).unwrap().status, TaskStatus::Ready);
        assert_eq!(g.get(2).unwrap().status, TaskStatus::Pending);
    }

    #[test]
    fn test_graph_no_cycle() {
        let mut g = TaskGraph::new();
        g.add_task(make_task(1, vec![], TaskPriority::Normal));
        g.add_task(make_task(2, vec![1], TaskPriority::Normal));
        assert!(g.find_cycle().is_none());
    }

    // ── TaskScheduler ───────────────────────────────────────────────────────

    #[test]
    fn test_scheduler_topological_order() {
        let mut g = TaskGraph::new();
        g.add_task(make_task(1, vec![], TaskPriority::Normal));
        g.add_task(make_task(2, vec![1], TaskPriority::Normal));
        g.add_task(make_task(3, vec![2], TaskPriority::Normal));
        let sched = TaskScheduler::new(g);
        let order = sched.topological_order().unwrap();
        let pos: HashMap<u64, usize> = order
            .iter()
            .copied()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect();
        assert!(pos[&1] < pos[&2]);
        assert!(pos[&2] < pos[&3]);
    }

    #[test]
    fn test_scheduler_ready_tasks_sorted_by_priority() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new(1, "low", vec![], TaskPriority::Low));
        g.add_task(Task::new(2, "critical", vec![], TaskPriority::Critical));
        g.add_task(Task::new(3, "normal", vec![], TaskPriority::Normal));
        g.refresh_ready();
        let sched = TaskScheduler::new(g);
        let ready = sched.ready_tasks();
        assert_eq!(ready[0].id, 2); // Critical first
    }

    // ── TaskPlanner ─────────────────────────────────────────────────────────

    #[test]
    fn test_standard_re_pipeline_builds() {
        let sched = TaskPlanner::standard_re_pipeline("Analyse malware.exe");
        assert!(!sched.graph().is_empty());
        let order = sched.topological_order();
        assert!(order.is_some());
    }

    #[test]
    fn test_planner_goal_string() {
        let p = TaskPlanner::new("reverse sample.bin");
        assert_eq!(p.goal(), "reverse sample.bin");
    }
}
