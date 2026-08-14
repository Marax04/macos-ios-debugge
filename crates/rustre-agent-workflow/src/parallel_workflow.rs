//! `parallel_workflow` — Parallel workflow execution for RE automation.
//!
//! Supports independent branch execution, join points, dependency tracking,
//! and critical-path optimisation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
pub use std::sync::{Arc, Mutex};
pub use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParallelWorkflowError {
    BranchNotFound(String),
    CyclicDependency(Vec<String>),
    JoinTimeout { join_id: String, waited_ms: u64 },
    SchedulerError(String),
    BranchFailed { branch_id: String, reason: String },
}

impl fmt::Display for ParallelWorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BranchNotFound(id) => write!(f, "branch not found: {id}"),
            Self::CyclicDependency(cycle) => {
                write!(f, "cyclic dependency: {}", cycle.join(" → "))
            }
            Self::JoinTimeout { join_id, waited_ms } => {
                write!(f, "join '{join_id}' timed out after {waited_ms}ms")
            }
            Self::SchedulerError(msg) => write!(f, "scheduler error: {msg}"),
            Self::BranchFailed { branch_id, reason } => {
                write!(f, "branch '{branch_id}' failed: {reason}")
            }
        }
    }
}

impl std::error::Error for ParallelWorkflowError {}

// ─── BranchStatus ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BranchStatus {
    Pending,
    Ready, // All dependencies satisfied.
    Running,
    Completed,
    Failed,
    Skipped,
}

// ─── BranchResult ────────────────────────────────────────────────────────────

/// Output produced by a completed branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchResult {
    pub branch_id: String,
    pub status: BranchStatus,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub duration_ms: u64,
}

impl BranchResult {
    pub fn success(
        branch_id: impl Into<String>,
        output: serde_json::Value,
        duration_ms: u64,
    ) -> Self {
        Self {
            branch_id: branch_id.into(),
            status: BranchStatus::Completed,
            output: Some(output),
            error: None,
            started_at_ms: 0,
            completed_at_ms: duration_ms,
            duration_ms,
        }
    }

    pub fn failure(
        branch_id: impl Into<String>,
        reason: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            branch_id: branch_id.into(),
            status: BranchStatus::Failed,
            output: None,
            error: Some(reason.into()),
            started_at_ms: 0,
            completed_at_ms: duration_ms,
            duration_ms,
        }
    }
}

// ─── WorkflowBranch ──────────────────────────────────────────────────────────

/// An independent execution path in a parallel workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowBranch {
    pub id: String,
    pub name: String,
    pub description: String,
    /// IDs of branches that must complete before this one can start.
    pub depends_on: Vec<String>,
    /// Estimated execution time in milliseconds (for scheduling).
    pub estimated_duration_ms: u64,
    /// Current status.
    pub status: BranchStatus,
    /// Tags for routing to executor pools.
    pub tags: Vec<String>,
    /// Priority within the scheduler (higher = runs sooner when ready).
    pub priority: u8,
    /// Whether this branch is on the critical path.
    pub is_critical: bool,
}

impl WorkflowBranch {
    pub fn new(id: impl Into<String>, name: impl Into<String>, estimated_duration_ms: u64) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            depends_on: Vec::new(),
            estimated_duration_ms,
            status: BranchStatus::Pending,
            tags: Vec::new(),
            priority: 5,
            is_critical: false,
        }
    }

    #[must_use]
    pub fn depends_on(mut self, dep: impl Into<String>) -> Self {
        self.depends_on.push(dep.into());
        self
    }

    #[must_use] 
    pub fn with_priority(mut self, p: u8) -> Self {
        self.priority = p.clamp(1, 10);
        self
    }

    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    #[must_use]
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Returns true when all dependencies are in the provided completed set.
    #[must_use] 
    pub fn is_ready(&self, completed: &HashSet<String>) -> bool {
        self.depends_on.iter().all(|d| completed.contains(d))
    }
}

// ─── JoinPoint ───────────────────────────────────────────────────────────────

/// Synchronisation point that waits for a set of branches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinPoint {
    pub id: String,
    /// Branch IDs to wait for.
    pub wait_for: Vec<String>,
    /// Maximum wait time in milliseconds (None = unlimited).
    pub timeout_ms: Option<u64>,
    /// Whether to fail the workflow if any branch in `wait_for` failed.
    pub fail_on_branch_failure: bool,
}

impl JoinPoint {
    pub fn new(id: impl Into<String>, wait_for: Vec<String>) -> Self {
        Self {
            id: id.into(),
            wait_for,
            timeout_ms: None,
            fail_on_branch_failure: true,
        }
    }

    #[must_use] 
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Check whether all required branches have completed given results so far.
    #[must_use] 
    pub fn is_satisfied(&self, results: &HashMap<String, BranchResult>) -> bool {
        self.wait_for.iter().all(|id| {
            results
                .get(id)
                .is_some_and(|r| r.status == BranchStatus::Completed)
        })
    }

    /// True if any required branch has failed.
    #[must_use] 
    pub fn has_failed(&self, results: &HashMap<String, BranchResult>) -> bool {
        self.wait_for.iter().any(|id| {
            results
                .get(id)
                .is_some_and(|r| r.status == BranchStatus::Failed)
        })
    }
}

// ─── DependencyGraph ─────────────────────────────────────────────────────────

/// Directed acyclic graph of branch dependencies.
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// Adjacency list: `branch_id` → set of branches it depends on.
    edges: HashMap<String, HashSet<String>>,
    /// Reverse edges: `branch_id` → set of branches that depend on it.
    reverse_edges: HashMap<String, HashSet<String>>,
}

impl DependencyGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node (idempotent).
    pub fn add_node(&mut self, id: &str) {
        self.edges.entry(id.to_string()).or_default();
        self.reverse_edges.entry(id.to_string()).or_default();
    }

    /// Add a dependency edge (from depends on to).
    pub fn add_edge(&mut self, from: &str, to: &str) {
        self.add_node(from);
        self.add_node(to);
        self.edges
            .entry(from.to_string())
            .or_default()
            .insert(to.to_string());
        self.reverse_edges
            .entry(to.to_string())
            .or_default()
            .insert(from.to_string());
    }

    /// Detect cycles via DFS; returns the cycle if found.
    #[must_use] 
    pub fn detect_cycle(&self) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        for node in self.edges.keys() {
            if !visited.contains(node)
                && let Some(cycle) = self.dfs_cycle(node, &mut visited, &mut rec_stack, &mut path) {
                    return Some(cycle);
                }
        }
        None
    }

    fn dfs_cycle(
        &self,
        node: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbours) = self.edges.get(node) {
            for neighbour in neighbours {
                if !visited.contains(neighbour) {
                    if let Some(cycle) = self.dfs_cycle(neighbour, visited, rec_stack, path) {
                        return Some(cycle);
                    }
                } else if rec_stack.contains(neighbour) {
                    // Found cycle — extract it.
                    let start = path.iter().position(|n| n == neighbour).unwrap_or(0);
                    return Some(path[start..].to_vec());
                }
            }
        }

        rec_stack.remove(node);
        path.pop();
        None
    }

    /// Topological sort (Kahn's algorithm). Returns sorted order or cycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn topological_sort(&self) -> Result<Vec<String>, Vec<String>> {
        if let Some(cycle) = self.detect_cycle() {
            return Err(cycle);
        }

        // in_degree[n] = number of dependencies n has (edges[n].len())
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for (node, deps) in &self.edges {
            in_degree.insert(node, deps.len());
            // Ensure dependency nodes are also present
            for dep in deps {
                in_degree.entry(dep).or_insert(0);
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&n, _)| n)
            .collect();

        let mut order = Vec::new();
        while let Some(node) = queue.pop_front() {
            order.push(node.to_string());
            if let Some(rev) = self.reverse_edges.get(node) {
                for dep in rev {
                    let deg = in_degree.get_mut(dep.as_str()).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep);
                    }
                }
            }
        }

        Ok(order)
    }

    /// Compute the longest path length from each node (for critical path).
    #[must_use] 
    pub fn longest_paths(&self, durations: &HashMap<String, u64>) -> HashMap<String, u64> {
        let Ok(sorted) = self.topological_sort() else { return HashMap::new() };

        let mut dist: HashMap<String, u64> = HashMap::new();
        for node in &sorted {
            dist.insert(node.clone(), *durations.get(node).unwrap_or(&0));
        }

        for node in &sorted {
            let node_dist = dist[node];
            if let Some(rev) = self.reverse_edges.get(node) {
                for succ in rev {
                    let succ_dur = *durations.get(succ).unwrap_or(&0);
                    let entry = dist.entry(succ.clone()).or_insert(0);
                    *entry = (*entry).max(node_dist + succ_dur);
                }
            }
        }
        dist
    }

    /// Number of nodes.
    #[must_use] 
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }
}

// ─── WorkflowOptimizer ───────────────────────────────────────────────────────

/// Analyses a workflow's dependency graph and marks critical-path branches.
pub struct WorkflowOptimizer;

impl WorkflowOptimizer {
    /// Mark critical-path branches and return the estimated critical-path duration.
    pub fn optimize(branches: &mut [WorkflowBranch]) -> u64 {
        let mut graph = DependencyGraph::new();
        let mut durations = HashMap::new();

        for b in branches.iter() {
            graph.add_node(&b.id);
            durations.insert(b.id.clone(), b.estimated_duration_ms);
            for dep in &b.depends_on {
                graph.add_edge(&b.id, dep);
            }
        }

        let longest = graph.longest_paths(&durations);
        let max_duration = longest.values().copied().max().unwrap_or(0);

        for branch in branches.iter_mut() {
            if let Some(&d) = longest.get(&branch.id) {
                branch.is_critical = d == max_duration;
            }
        }
        max_duration
    }

    /// Estimate total wall-clock time assuming unlimited parallelism.
    #[must_use] 
    pub fn critical_path_duration(branches: &[WorkflowBranch]) -> u64 {
        let mut graph = DependencyGraph::new();
        let mut durations = HashMap::new();
        for b in branches {
            graph.add_node(&b.id);
            durations.insert(b.id.clone(), b.estimated_duration_ms);
            for dep in &b.depends_on {
                graph.add_edge(&b.id, dep);
            }
        }
        let longest = graph.longest_paths(&durations);
        longest.values().copied().max().unwrap_or(0)
    }
}

// ─── ParallelScheduler ───────────────────────────────────────────────────────

/// Schedules branches for execution respecting dependencies and priorities.
#[derive(Debug, Default)]
pub struct ParallelScheduler {
    completed: HashSet<String>,
    failed: HashSet<String>,
    running: HashSet<String>,
    results: HashMap<String, BranchResult>,
}

impl ParallelScheduler {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the next batch of branches that are ready to execute.
    #[must_use] 
    pub fn ready_branches<'a>(&self, branches: &'a [WorkflowBranch]) -> Vec<&'a WorkflowBranch> {
        let mut ready: Vec<&WorkflowBranch> = branches
            .iter()
            .filter(|b| {
                b.status == BranchStatus::Pending
                    && !self.running.contains(&b.id)
                    && !self.completed.contains(&b.id)
                    && !self.failed.contains(&b.id)
                    && b.is_ready(&self.completed)
            })
            .collect();

        // Sort by priority descending, then critical path first.
        ready.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(b.is_critical.cmp(&a.is_critical))
                .then(a.estimated_duration_ms.cmp(&b.estimated_duration_ms)) // shorter first
        });
        ready
    }

    /// Record a branch as started.
    pub fn mark_running(&mut self, branch_id: &str) {
        self.running.insert(branch_id.to_string());
    }

    /// Record a completed branch result.
    pub fn record_result(&mut self, result: BranchResult) {
        self.running.remove(&result.branch_id);
        match result.status {
            BranchStatus::Completed => {
                self.completed.insert(result.branch_id.clone());
            }
            BranchStatus::Failed => {
                self.failed.insert(result.branch_id.clone());
            }
            _ => {}
        }
        self.results.insert(result.branch_id.clone(), result);
    }

    /// Check if all branches are done (completed or failed).
    #[must_use] 
    pub fn all_done(&self, branches: &[WorkflowBranch]) -> bool {
        branches
            .iter()
            .all(|b| self.completed.contains(&b.id) || self.failed.contains(&b.id))
    }

    /// Access collected results.
    #[must_use] 
    pub const fn results(&self) -> &HashMap<String, BranchResult> {
        &self.results
    }

    /// Number of currently running branches.
    #[must_use] 
    pub fn running_count(&self) -> usize {
        self.running.len()
    }

    /// Number of completed branches.
    #[must_use] 
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Number of failed branches.
    #[must_use] 
    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }
}

// ─── ParallelWorkflow ─────────────────────────────────────────────────────────

/// A complete parallel workflow definition.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ParallelWorkflow {
    pub id: String,
    pub name: String,
    pub branches: Vec<WorkflowBranch>,
    pub join_points: Vec<JoinPoint>,
    /// Global timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Maximum number of branches to run concurrently (0 = unlimited).
    pub max_concurrency: usize,
    /// Whether to continue if a non-critical branch fails.
    pub continue_on_failure: bool,
}

impl ParallelWorkflow {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            branches: Vec::new(),
            join_points: Vec::new(),
            timeout_ms: None,
            max_concurrency: 0,
            continue_on_failure: true,
        }
    }

    /// Add a branch.
    pub fn add_branch(&mut self, branch: WorkflowBranch) {
        self.branches.push(branch);
    }

    /// Add a join point.
    pub fn add_join(&mut self, join: JoinPoint) {
        self.join_points.push(join);
    }

    /// Validate the workflow (no cycles, all dependencies exist).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> Result<(), ParallelWorkflowError> {
        let ids: HashSet<&str> = self.branches.iter().map(|b| b.id.as_str()).collect();

        // Check all dependencies exist.
        for branch in &self.branches {
            for dep in &branch.depends_on {
                if !ids.contains(dep.as_str()) {
                    return Err(ParallelWorkflowError::BranchNotFound(dep.clone()));
                }
            }
        }

        // Check for cycles.
        let mut graph = DependencyGraph::new();
        for branch in &self.branches {
            graph.add_node(&branch.id);
            for dep in &branch.depends_on {
                graph.add_edge(&branch.id, dep);
            }
        }
        if let Some(cycle) = graph.detect_cycle() {
            return Err(ParallelWorkflowError::CyclicDependency(cycle));
        }
        Ok(())
    }

    /// Optimise (mark critical path) and return critical-path duration.
    pub fn optimize(&mut self) -> u64 {
        WorkflowOptimizer::optimize(&mut self.branches)
    }

    /// Simulate execution and return results.
    /// Branch execution is simulated synchronously (no real async here).
    pub fn simulate<F>(&self, mut executor: F) -> HashMap<String, BranchResult>
    where
        F: FnMut(&WorkflowBranch) -> BranchResult,
    {
        let mut scheduler = ParallelScheduler::new();
        let mut branches = self.branches.clone();

        // A simple iterative simulation loop.
        let max_iter = self.branches.len().saturating_add(1);
        for _ in 0..max_iter {
            if scheduler.all_done(&branches) {
                break;
            }
            let ready: Vec<WorkflowBranch> = scheduler
                .ready_branches(&branches)
                .into_iter()
                .cloned()
                .collect();
            for b in ready {
                scheduler.mark_running(&b.id);
                let result = executor(&b);
                // Update branch status in our local copy.
                if let Some(branch) = branches.iter_mut().find(|br| br.id == b.id) {
                    branch.status = result.status;
                }
                scheduler.record_result(result);
            }
        }
        scheduler.results().clone()
    }

    /// Number of branches.
    #[must_use] 
    pub const fn branch_count(&self) -> usize {
        self.branches.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_branch(id: &str, duration: u64) -> WorkflowBranch {
        WorkflowBranch::new(id, id, duration)
    }

    #[test]
    fn branch_ready_no_deps() {
        let b = make_branch("b1", 100);
        let completed = HashSet::new();
        assert!(b.is_ready(&completed));
    }

    #[test]
    fn branch_not_ready_with_pending_dep() {
        let b = make_branch("b2", 100).depends_on("b1");
        let completed = HashSet::new();
        assert!(!b.is_ready(&completed));
    }

    #[test]
    fn branch_ready_with_satisfied_dep() {
        let b = make_branch("b2", 100).depends_on("b1");
        let mut completed = HashSet::new();
        completed.insert("b1".to_string());
        assert!(b.is_ready(&completed));
    }

    #[test]
    fn dependency_graph_no_cycle() {
        let mut g = DependencyGraph::new();
        g.add_node("a");
        g.add_node("b");
        g.add_edge("b", "a"); // b depends on a
        assert!(g.detect_cycle().is_none());
    }

    #[test]
    fn dependency_graph_cycle_detected() {
        let mut g = DependencyGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "c");
        g.add_edge("c", "a"); // cycle
        assert!(g.detect_cycle().is_some());
    }

    #[test]
    fn dependency_graph_topological_sort_order() {
        let mut g = DependencyGraph::new();
        g.add_node("a");
        g.add_edge("b", "a");
        g.add_edge("c", "b");
        let sorted = g.topological_sort().unwrap();
        // c comes before b, b comes before a in dependency order.
        let pos_a = sorted.iter().position(|x| x == "a").unwrap();
        let pos_b = sorted.iter().position(|x| x == "b").unwrap();
        let pos_c = sorted.iter().position(|x| x == "c").unwrap();
        // "a" has no deps so appears first in Kahn's output.
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn dependency_graph_topological_sort_fails_on_cycle() {
        let mut g = DependencyGraph::new();
        g.add_edge("a", "b");
        g.add_edge("b", "a");
        assert!(g.topological_sort().is_err());
    }

    #[test]
    fn workflow_optimizer_marks_critical() {
        let mut branches = vec![
            make_branch("a", 100),
            make_branch("b", 200).depends_on("a"),
            make_branch("c", 50).depends_on("a"),
        ];
        let cp = WorkflowOptimizer::optimize(&mut branches);
        assert!(cp > 0);
    }

    #[test]
    fn workflow_optimizer_critical_path_duration() {
        let branches = vec![make_branch("a", 100), make_branch("b", 200).depends_on("a")];
        let cp = WorkflowOptimizer::critical_path_duration(&branches);
        // b depends on a: 100 + 200 = 300ms
        assert_eq!(cp, 300);
    }

    #[test]
    fn scheduler_ready_branches_no_deps() {
        let scheduler = ParallelScheduler::new();
        let branches = vec![make_branch("a", 10), make_branch("b", 20)];
        let ready = scheduler.ready_branches(&branches);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn scheduler_ready_respects_dependencies() {
        let scheduler = ParallelScheduler::new();
        let branches = vec![make_branch("a", 10), make_branch("b", 20).depends_on("a")];
        let ready = scheduler.ready_branches(&branches);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "a");
    }

    #[test]
    fn scheduler_record_result_completed() {
        let mut scheduler = ParallelScheduler::new();
        scheduler.mark_running("a");
        scheduler.record_result(BranchResult::success("a", json!({}), 10));
        assert_eq!(scheduler.completed_count(), 1);
        assert_eq!(scheduler.running_count(), 0);
    }

    #[test]
    fn scheduler_record_result_failed() {
        let mut scheduler = ParallelScheduler::new();
        scheduler.mark_running("b");
        scheduler.record_result(BranchResult::failure("b", "timeout", 100));
        assert_eq!(scheduler.failed_count(), 1);
    }

    #[test]
    fn scheduler_all_done() {
        let mut scheduler = ParallelScheduler::new();
        let branches = vec![make_branch("a", 10)];
        scheduler.record_result(BranchResult::success("a", json!({}), 10));
        assert!(scheduler.all_done(&branches));
    }

    #[test]
    fn join_point_satisfied() {
        let jp = JoinPoint::new("j1", vec!["a".into(), "b".into()]);
        let mut results = HashMap::new();
        results.insert("a".into(), BranchResult::success("a", json!({}), 10));
        results.insert("b".into(), BranchResult::success("b", json!({}), 10));
        assert!(jp.is_satisfied(&results));
    }

    #[test]
    fn join_point_not_satisfied() {
        let jp = JoinPoint::new("j1", vec!["a".into(), "b".into()]);
        let mut results = HashMap::new();
        results.insert("a".into(), BranchResult::success("a", json!({}), 10));
        // b not in results
        assert!(!jp.is_satisfied(&results));
    }

    #[test]
    fn join_point_failed_branches() {
        let jp = JoinPoint::new("j1", vec!["a".into()]);
        let mut results = HashMap::new();
        results.insert("a".into(), BranchResult::failure("a", "err", 10));
        assert!(jp.has_failed(&results));
    }

    #[test]
    fn workflow_validate_no_error() {
        let mut wf = ParallelWorkflow::new("wf1", "test");
        wf.add_branch(make_branch("a", 10));
        wf.add_branch(make_branch("b", 20).depends_on("a"));
        assert!(wf.validate().is_ok());
    }

    #[test]
    fn workflow_validate_missing_dep() {
        let mut wf = ParallelWorkflow::new("wf1", "test");
        wf.add_branch(make_branch("b", 20).depends_on("nonexistent"));
        assert!(matches!(
            wf.validate(),
            Err(ParallelWorkflowError::BranchNotFound(_))
        ));
    }

    #[test]
    fn workflow_validate_cycle() {
        let mut wf = ParallelWorkflow::new("wf1", "test");
        let a = make_branch("a", 10).depends_on("b");
        let b = make_branch("b", 10).depends_on("a");
        wf.add_branch(a);
        wf.add_branch(b);
        assert!(matches!(
            wf.validate(),
            Err(ParallelWorkflowError::CyclicDependency(_))
        ));
    }

    #[test]
    fn workflow_simulate_all_succeed() {
        let mut wf = ParallelWorkflow::new("wf1", "test");
        wf.add_branch(make_branch("a", 10));
        wf.add_branch(make_branch("b", 20).depends_on("a"));
        wf.add_branch(make_branch("c", 15).depends_on("a"));

        let results = wf.simulate(|b| {
            BranchResult::success(&b.id, json!({"id": &b.id}), b.estimated_duration_ms)
        });
        assert_eq!(results.len(), 3);
        for r in results.values() {
            assert_eq!(r.status, BranchStatus::Completed);
        }
    }

    #[test]
    fn workflow_simulate_one_fails() {
        let mut wf = ParallelWorkflow::new("wf1", "test");
        wf.add_branch(make_branch("a", 10));

        let results =
            wf.simulate(|b| BranchResult::failure(&b.id, "error", b.estimated_duration_ms));
        assert_eq!(results["a"].status, BranchStatus::Failed);
    }

    #[test]
    fn workflow_optimize_no_panic() {
        let mut wf = ParallelWorkflow::new("wf1", "test");
        wf.add_branch(make_branch("a", 10));
        wf.add_branch(make_branch("b", 100).depends_on("a"));
        let cp = wf.optimize();
        assert!(cp > 0);
    }

    #[test]
    fn branch_priority_clamp() {
        let b = make_branch("b", 10).with_priority(99);
        assert_eq!(b.priority, 10);
    }

    #[test]
    fn scheduler_priority_ordering() {
        let scheduler = ParallelScheduler::new();
        let branches = vec![
            make_branch("low", 10).with_priority(1),
            make_branch("high", 10).with_priority(9),
        ];
        let ready = scheduler.ready_branches(&branches);
        assert_eq!(ready[0].id, "high");
    }

    #[test]
    fn branch_result_success_status() {
        let r = BranchResult::success("x", json!({}), 50);
        assert_eq!(r.status, BranchStatus::Completed);
        assert!(r.error.is_none());
    }

    #[test]
    fn branch_result_failure_status() {
        let r = BranchResult::failure("x", "err", 50);
        assert_eq!(r.status, BranchStatus::Failed);
        assert!(r.output.is_none());
    }

    #[test]
    fn parallel_workflow_error_display() {
        let e = ParallelWorkflowError::BranchNotFound("b1".into());
        assert!(e.to_string().contains("b1"));
    }

    #[test]
    fn dependency_graph_node_count() {
        let mut g = DependencyGraph::new();
        g.add_node("a");
        g.add_node("b");
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn join_point_with_timeout() {
        let jp = JoinPoint::new("j", vec![]).with_timeout(5000);
        assert_eq!(jp.timeout_ms, Some(5000));
    }

    #[test]
    fn workflow_branch_count() {
        let mut wf = ParallelWorkflow::new("w", "w");
        wf.add_branch(make_branch("a", 10));
        wf.add_branch(make_branch("b", 20));
        assert_eq!(wf.branch_count(), 2);
    }
}
