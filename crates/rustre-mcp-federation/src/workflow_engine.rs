//! `workflow_engine` — DAG-based workflow orchestration for RE tool sequences.
//!
//! Supports DAG tool-call graphs, conditional branching based on output,
//! parallel fan-out, result accumulation, checkpoint/resume, and timeouts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// NodeId / WorkflowId
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a workflow node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    #[must_use]
    pub fn generated() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Unique identifier for a workflow execution instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkflowId(Uuid);

impl WorkflowId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for WorkflowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for WorkflowId {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConditionExpr — simple expression language for branching
// ─────────────────────────────────────────────────────────────────────────────

/// A simple condition evaluated against a JSON value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionExpr {
    /// Always true.
    Always,
    /// Always false.
    Never,
    /// Field `path` (dot-separated) equals `value`.
    FieldEq { path: String, value: serde_json::Value },
    /// Field `path` is present and non-null.
    FieldExists { path: String },
    /// Field `path` (numeric) is greater than `threshold`.
    FieldGt { path: String, threshold: f64 },
    /// Logical AND.
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    /// Logical OR.
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    /// Logical NOT.
    Not(Box<ConditionExpr>),
}

impl ConditionExpr {
    /// Evaluate the condition against a JSON `context` value.
    #[must_use]
    pub fn evaluate(&self, ctx: &serde_json::Value) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::FieldEq { path, value } => {
                Self::get_field(ctx, path).as_ref() == Some(value)
            }
            Self::FieldExists { path } => Self::get_field(ctx, path).is_some(),
            Self::FieldGt { path, threshold } => {
                Self::get_field(ctx, path)
                    .and_then(|v| v.as_f64())
                    .map(|n| n > *threshold)
                    .unwrap_or(false)
            }
            Self::And(a, b) => a.evaluate(ctx) && b.evaluate(ctx),
            Self::Or(a, b) => a.evaluate(ctx) || b.evaluate(ctx),
            Self::Not(inner) => !inner.evaluate(ctx),
        }
    }

    fn get_field(ctx: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
        let mut cur = ctx;
        for part in path.split('.') {
            cur = cur.get(part)?;
        }
        Some(cur.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeKind — what a node does
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of action a workflow node represents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeKind {
    /// Call a specific MCP tool.
    ToolCall {
        tool_name: String,
        server_hint: Option<String>,
        params_template: serde_json::Value,
    },
    /// Fan out to multiple nodes in parallel, waiting for all.
    ParallelFanOut { children: Vec<NodeId> },
    /// Conditional branch: evaluate condition on result, pick successor.
    Branch {
        condition: ConditionExpr,
        on_true: NodeId,
        on_false: NodeId,
    },
    /// Accumulate results from multiple predecessors into a single value.
    Accumulate { strategy: AccumulateStrategy },
    /// A no-op start/end marker.
    Marker { label: String },
    /// Wait for a fixed duration (useful in testing).
    Delay { millis: u64 },
}

/// How to accumulate results from multiple predecessors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccumulateStrategy {
    /// Merge all results into a JSON object.
    Merge,
    /// Concatenate array results.
    Concat,
    /// Return the first non-null result.
    FirstNonNull,
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowNode
// ─────────────────────────────────────────────────────────────────────────────

/// A single node in the workflow DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowNode {
    pub id: NodeId,
    pub kind: NodeKind,
    /// Nodes that must complete before this one can start.
    pub dependencies: Vec<NodeId>,
    /// Per-node timeout (overrides workflow default when set).
    pub timeout: Option<Duration>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Whether a failure here aborts the whole workflow.
    pub critical: bool,
}

impl WorkflowNode {
    #[must_use]
    pub fn new(id: impl Into<NodeId>, kind: NodeKind) -> Self {
        Self {
            id: id.into(),
            kind,
            dependencies: Vec::new(),
            timeout: None,
            label: None,
            critical: true,
        }
    }

    #[must_use]
    pub fn with_deps(mut self, deps: Vec<NodeId>) -> Self {
        self.dependencies = deps;
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    #[must_use]
    pub fn non_critical(mut self) -> Self {
        self.critical = false;
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowDef — the static DAG definition
// ─────────────────────────────────────────────────────────────────────────────

/// The static definition of a workflow (immutable after construction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDef {
    pub name: String,
    pub description: String,
    pub nodes: HashMap<NodeId, WorkflowNode>,
    pub entry_node: NodeId,
    pub default_timeout: Duration,
    pub max_parallel: usize,
}

impl WorkflowDef {
    #[must_use]
    pub fn new(name: impl Into<String>, entry: impl Into<NodeId>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            nodes: HashMap::new(),
            entry_node: entry.into(),
            default_timeout: Duration::from_secs(60),
            max_parallel: 8,
        }
    }

    /// Add a node to the workflow.
    pub fn add_node(&mut self, node: WorkflowNode) -> &mut Self {
        self.nodes.insert(node.id.clone(), node);
        self
    }

    /// Validate the DAG (checks for cycles and missing dependency references).
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        // Check that the entry node exists
        if !self.nodes.contains_key(&self.entry_node) {
            errors.push(format!("entry node '{}' not defined", self.entry_node));
        }
        // Check dependency references
        for (id, node) in &self.nodes {
            for dep in &node.dependencies {
                if !self.nodes.contains_key(dep) {
                    errors.push(format!("node '{id}' depends on undefined node '{dep}'"));
                }
            }
        }
        // Cycle detection via DFS
        if self.has_cycle() {
            errors.push("workflow DAG contains a cycle".into());
        }
        errors
    }

    fn has_cycle(&self) -> bool {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        for id in self.nodes.keys() {
            if self.dfs_cycle(id, &mut visited, &mut rec_stack) {
                return true;
            }
        }
        false
    }

    fn dfs_cycle(
        &self,
        id: &NodeId,
        visited: &mut HashSet<NodeId>,
        rec_stack: &mut HashSet<NodeId>,
    ) -> bool {
        if rec_stack.contains(id) {
            return true;
        }
        if visited.contains(id) {
            return false;
        }
        visited.insert(id.clone());
        rec_stack.insert(id.clone());
        if let Some(node) = self.nodes.get(id) {
            for dep in &node.dependencies {
                if self.dfs_cycle(dep, visited, rec_stack) {
                    return true;
                }
            }
        }
        rec_stack.remove(id);
        false
    }

    /// Compute a topological ordering of all nodes.
    #[must_use]
    pub fn topological_order(&self) -> Option<Vec<NodeId>> {
        let mut in_degree: HashMap<&NodeId, usize> = self.nodes.keys().map(|k| (k, 0)).collect();
        for node in self.nodes.values() {
            for dep in &node.dependencies {
                if let Some(d) = in_degree.get_mut(dep) {
                    *d += 1;
                }
            }
        }
        // Kahn's algorithm
        let mut queue: VecDeque<&NodeId> = in_degree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(k, _)| *k)
            .collect();
        let mut order = Vec::new();
        let mut processed = 0;
        while let Some(id) = queue.pop_front() {
            order.push(id.clone());
            processed += 1;
            if let Some(node) = self.nodes.get(id) {
                for next in &node.dependencies {
                    if let Some(d) = in_degree.get_mut(next) {
                        *d -= 1;
                        if *d == 0 {
                            queue.push_back(next);
                        }
                    }
                }
            }
        }
        if processed == self.nodes.len() {
            Some(order)
        } else {
            None // cycle detected
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeStatus / WorkflowStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Execution status of a single node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Pending,
    Running,
    Succeeded,
    Failed { reason: String },
    Skipped,
    TimedOut,
}

impl NodeStatus {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed { .. } | Self::Skipped | Self::TimedOut
        )
    }
}

/// Overall workflow execution status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowStatus {
    NotStarted,
    Running,
    Succeeded,
    Failed { reason: String },
    TimedOut,
    Aborted,
    /// Suspended (checkpoint saved), awaiting resume.
    Suspended,
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowCheckpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Serializable checkpoint for pausing and resuming a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCheckpoint {
    pub workflow_id: WorkflowId,
    pub workflow_name: String,
    pub node_statuses: HashMap<String, String>, // NodeId.0 → status label
    pub node_results: HashMap<String, serde_json::Value>,
    pub accumulated: serde_json::Value,
    pub checkpoint_at_ms: u64,
}

impl WorkflowCheckpoint {
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn new(id: WorkflowId, name: impl Into<String>) -> Self {
        Self {
            workflow_id: id,
            workflow_name: name.into(),
            node_statuses: HashMap::new(),
            node_results: HashMap::new(),
            accumulated: serde_json::Value::Null,
            checkpoint_at_ms: Self::now_ms(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowExecution
// ─────────────────────────────────────────────────────────────────────────────

/// A live execution instance of a `WorkflowDef`.
pub struct WorkflowExecution {
    pub id: WorkflowId,
    pub def: WorkflowDef,
    pub status: WorkflowStatus,
    /// Execution status per node.
    pub node_statuses: HashMap<NodeId, NodeStatus>,
    /// Results produced per node.
    pub node_results: HashMap<NodeId, serde_json::Value>,
    /// Accumulated result (built by Accumulate nodes).
    pub accumulated: serde_json::Value,
    pub started_at: Option<Instant>,
    pub completed_at: Option<Instant>,
    /// Per-execution initial parameters.
    pub input: serde_json::Value,
}

impl WorkflowExecution {
    #[must_use]
    pub fn new(def: WorkflowDef, input: serde_json::Value) -> Self {
        let node_statuses: HashMap<NodeId, NodeStatus> = def
            .nodes
            .keys()
            .map(|k| (k.clone(), NodeStatus::Pending))
            .collect();
        Self {
            id: WorkflowId::new(),
            def,
            status: WorkflowStatus::NotStarted,
            node_statuses,
            node_results: HashMap::new(),
            accumulated: serde_json::Value::Null,
            started_at: None,
            completed_at: None,
            input,
        }
    }

    /// Returns nodes whose all dependencies have succeeded (ready to run).
    #[must_use]
    pub fn ready_nodes(&self) -> Vec<&NodeId> {
        self.def
            .nodes
            .keys()
            .filter(|id| {
                matches!(self.node_statuses.get(*id), Some(NodeStatus::Pending))
                    && self.def.nodes[*id].dependencies.iter().all(|dep| {
                        matches!(
                            self.node_statuses.get(dep),
                            Some(NodeStatus::Succeeded) | Some(NodeStatus::Skipped)
                        )
                    })
            })
            .collect()
    }

    /// Mark a node as succeeded and store its result.
    pub fn mark_succeeded(&mut self, id: &NodeId, result: serde_json::Value) {
        self.node_statuses.insert(id.clone(), NodeStatus::Succeeded);
        self.node_results.insert(id.clone(), result);
    }

    /// Mark a node as failed.
    pub fn mark_failed(&mut self, id: &NodeId, reason: impl Into<String>) {
        let r = reason.into();
        let critical = self.def.nodes.get(id).map(|n| n.critical).unwrap_or(true);
        self.node_statuses
            .insert(id.clone(), NodeStatus::Failed { reason: r.clone() });
        if critical {
            self.status = WorkflowStatus::Failed { reason: r };
        }
    }

    /// Mark a node as skipped (e.g. branch not taken).
    pub fn mark_skipped(&mut self, id: &NodeId) {
        self.node_statuses.insert(id.clone(), NodeStatus::Skipped);
    }

    /// Returns `true` when all nodes are in a terminal state.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.node_statuses.values().all(NodeStatus::is_terminal)
    }

    /// Progress as fraction complete (0.0 – 1.0).
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.node_statuses.is_empty() {
            return 1.0;
        }
        let done = self
            .node_statuses
            .values()
            .filter(|s| s.is_terminal())
            .count();
        done as f64 / self.node_statuses.len() as f64
    }

    /// Serialize a checkpoint of the current state.
    #[must_use]
    pub fn checkpoint(&self) -> WorkflowCheckpoint {
        let mut cp = WorkflowCheckpoint::new(self.id.clone(), &self.def.name);
        for (id, status) in &self.node_statuses {
            let label = match status {
                NodeStatus::Pending => "pending",
                NodeStatus::Running => "running",
                NodeStatus::Succeeded => "succeeded",
                NodeStatus::Failed { .. } => "failed",
                NodeStatus::Skipped => "skipped",
                NodeStatus::TimedOut => "timed_out",
            };
            cp.node_statuses.insert(id.to_string(), label.into());
        }
        for (id, result) in &self.node_results {
            cp.node_results.insert(id.to_string(), result.clone());
        }
        cp.accumulated = self.accumulated.clone();
        cp
    }

    /// Restore execution state from a checkpoint.
    pub fn restore_from_checkpoint(&mut self, cp: &WorkflowCheckpoint) {
        for (id_str, status_str) in &cp.node_statuses {
            let id = NodeId::new(id_str.clone());
            let status = match status_str.as_str() {
                "succeeded" => NodeStatus::Succeeded,
                "failed" => NodeStatus::Failed { reason: "restored".into() },
                "skipped" => NodeStatus::Skipped,
                "timed_out" => NodeStatus::TimedOut,
                _ => NodeStatus::Pending,
            };
            self.node_statuses.insert(id, status);
        }
        for (id_str, result) in &cp.node_results {
            self.node_results.insert(NodeId::new(id_str.clone()), result.clone());
        }
        self.accumulated = cp.accumulated.clone();
    }

    /// Evaluate accumulated result using an `AccumulateStrategy`.
    pub fn accumulate(&mut self, strategy: &AccumulateStrategy, predecessor_ids: &[NodeId]) {
        let values: Vec<serde_json::Value> = predecessor_ids
            .iter()
            .filter_map(|id| self.node_results.get(id))
            .cloned()
            .collect();
        self.accumulated = match strategy {
            AccumulateStrategy::Merge => {
                let mut obj = serde_json::Map::new();
                for v in &values {
                    if let serde_json::Value::Object(m) = v {
                        obj.extend(m.iter().map(|(k, v)| (k.clone(), v.clone())));
                    }
                }
                serde_json::Value::Object(obj)
            }
            AccumulateStrategy::Concat => {
                let mut arr: Vec<serde_json::Value> = Vec::new();
                for v in &values {
                    match v {
                        serde_json::Value::Array(a) => arr.extend(a.iter().cloned()),
                        other => arr.push(other.clone()),
                    }
                }
                serde_json::Value::Array(arr)
            }
            AccumulateStrategy::FirstNonNull => values
                .into_iter()
                .find(|v| !v.is_null())
                .unwrap_or(serde_json::Value::Null),
        };
    }

    /// Execution duration (or elapsed so far if still running).
    #[must_use]
    pub fn duration(&self) -> Option<Duration> {
        let start = self.started_at?;
        let end = self.completed_at.unwrap_or_else(Instant::now);
        Some(end.duration_since(start))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Synchronous workflow engine that executes a `WorkflowDef`.
///
/// The engine is intentionally synchronous so it can be embedded into async
/// systems without requiring its own Tokio runtime.  Async tool invocations
/// are handled by the caller via the `ToolDispatch` trait.
pub struct WorkflowEngine;

/// Trait for dispatching actual tool calls from within the engine.
pub trait ToolDispatch: Send + Sync {
    fn call(
        &self,
        tool_name: &str,
        server_hint: Option<&str>,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// A simple stub dispatcher (for testing without real MCP servers).
pub struct StubDispatch {
    responses: HashMap<String, serde_json::Value>,
}

impl StubDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self { responses: HashMap::new() }
    }

    pub fn register(mut self, tool: impl Into<String>, response: serde_json::Value) -> Self {
        self.responses.insert(tool.into(), response);
        self
    }
}

impl Default for StubDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolDispatch for StubDispatch {
    fn call(
        &self,
        tool_name: &str,
        _server: Option<&str>,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.responses
            .get(tool_name)
            .cloned()
            .map_or_else(|| Ok(serde_json::json!({"stub": true, "tool": tool_name})), Ok)
    }
}

impl WorkflowEngine {
    /// Execute a workflow synchronously given a dispatcher and input.
    ///
    /// Returns the completed `WorkflowExecution`.
    pub fn run(
        def: WorkflowDef,
        input: serde_json::Value,
        dispatch: &dyn ToolDispatch,
        global_timeout: Duration,
    ) -> WorkflowExecution {
        let errors = def.validate();
        let mut exec = WorkflowExecution::new(def, input);
        if !errors.is_empty() {
            exec.status = WorkflowStatus::Failed {
                reason: errors.join("; "),
            };
            return exec;
        }

        exec.status = WorkflowStatus::Running;
        exec.started_at = Some(Instant::now());
        let deadline = Instant::now() + global_timeout;
        // Safety: each iteration must make progress (at least one ready node
        // transitions to a terminal state).  Cap at node_count * 2 to detect
        // infinite loops caused by buggy node implementations.
        let max_iterations = exec.def.nodes.len().saturating_mul(2).max(1);
        let mut iteration = 0usize;

        // Iterative BFS execution
        loop {
            if iteration >= max_iterations {
                exec.status = WorkflowStatus::Failed {
                    reason: "workflow exceeded maximum iteration count; possible infinite loop"
                        .into(),
                };
                break;
            }
            iteration += 1;
            if Instant::now() > deadline {
                exec.status = WorkflowStatus::TimedOut;
                break;
            }
            if matches!(exec.status, WorkflowStatus::Failed { .. }) {
                break;
            }
            let ready: Vec<NodeId> = exec.ready_nodes().into_iter().cloned().collect();
            if ready.is_empty() {
                break;
            }
            for node_id in ready {
                Self::execute_node(&node_id, &mut exec, dispatch);
                if matches!(exec.status, WorkflowStatus::Failed { .. }) {
                    break;
                }
            }
        }

        if matches!(exec.status, WorkflowStatus::Running) {
            exec.status = WorkflowStatus::Succeeded;
        }
        exec.completed_at = Some(Instant::now());
        exec
    }

    fn execute_node(
        node_id: &NodeId,
        exec: &mut WorkflowExecution,
        dispatch: &dyn ToolDispatch,
    ) {
        exec.node_statuses.insert(node_id.clone(), NodeStatus::Running);

        let node = match exec.def.nodes.get(node_id) {
            Some(n) => n.clone(),
            None => {
                exec.mark_failed(node_id, format!("node '{node_id}' not found in definition"));
                return;
            }
        };

        let node_timeout = node.timeout.unwrap_or(exec.def.default_timeout);
        let t_start = Instant::now();

        let result = Self::run_node_kind(node_id, &node.kind, exec, dispatch);

        if t_start.elapsed() > node_timeout {
            exec.node_statuses.insert(node_id.clone(), NodeStatus::TimedOut);
            if node.critical {
                exec.status =
                    WorkflowStatus::Failed { reason: format!("node '{node_id}' timed out") };
            }
            return;
        }

        match result {
            Ok(val) => exec.mark_succeeded(node_id, val),
            Err(e) => exec.mark_failed(node_id, e),
        }
    }

    fn run_node_kind(
        node_id: &NodeId,
        kind: &NodeKind,
        exec: &mut WorkflowExecution,
        dispatch: &dyn ToolDispatch,
    ) -> Result<serde_json::Value, String> {
        match kind {
            NodeKind::ToolCall { tool_name, server_hint, params_template } => {
                let params = Self::render_template(params_template, &exec.input, &exec.node_results);
                dispatch.call(tool_name, server_hint.as_deref(), params)
            }
            NodeKind::Branch { condition, on_true, on_false } => {
                let ctx = exec.node_results.get(node_id).cloned().unwrap_or(serde_json::Value::Null);
                let next = if condition.evaluate(&ctx) { on_true } else { on_false };
                // Mark the unchosen branch as skipped
                let skip_id = if condition.evaluate(&ctx) { on_false } else { on_true };
                exec.mark_skipped(skip_id);
                Ok(serde_json::json!({ "branch_taken": next.to_string() }))
            }
            NodeKind::ParallelFanOut { children } => {
                // Simplified synchronous fan-out (real parallel via async is in the async layer)
                let mut results = serde_json::Map::new();
                for child_id in children {
                    Self::execute_node(child_id, exec, dispatch);
                    let r = exec.node_results.get(child_id).cloned().unwrap_or(serde_json::Value::Null);
                    results.insert(child_id.to_string(), r);
                }
                Ok(serde_json::Value::Object(results))
            }
            NodeKind::Accumulate { strategy } => {
                let predecessors: Vec<NodeId> = exec
                    .def
                    .nodes
                    .get(node_id)
                    .map(|n| n.dependencies.clone())
                    .unwrap_or_default();
                exec.accumulate(strategy, &predecessors);
                Ok(exec.accumulated.clone())
            }
            NodeKind::Marker { label } => {
                Ok(serde_json::json!({ "marker": label }))
            }
            NodeKind::Delay { millis } => {
                // Clamp the delay to at most 60 seconds to prevent a single
                // node from stalling the engine indefinitely.
                let clamped = (*millis).min(60_000);
                std::thread::sleep(Duration::from_millis(clamped));
                Ok(serde_json::json!({ "delayed_ms": clamped }))
            }
        }
    }

    /// Simple template rendering: replaces `{{field}}` placeholders from input/results.
    #[must_use]
    pub fn render_template(
        template: &serde_json::Value,
        input: &serde_json::Value,
        _results: &HashMap<NodeId, serde_json::Value>,
    ) -> serde_json::Value {
        // Basic implementation: if template is a string with {{key}}, substitute from input.
        match template {
            serde_json::Value::String(s) => {
                let mut result = s.clone();
                if let serde_json::Value::Object(map) = input {
                    for (k, v) in map {
                        let placeholder = format!("{{{{{k}}}}}");
                        if let Some(sv) = v.as_str() {
                            result = result.replace(&placeholder, sv);
                        }
                    }
                }
                serde_json::Value::String(result)
            }
            serde_json::Value::Object(map) => {
                let rendered: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::render_template(v, input, _results)))
                    .collect();
                serde_json::Value::Object(rendered)
            }
            other => other.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stub() -> StubDispatch {
        StubDispatch::new()
            .register("decompile", serde_json::json!({"code": "void foo() {}"}))
            .register("disasm", serde_json::json!({"instructions": ["nop", "ret"]}))
    }

    #[test]
    fn test_simple_workflow_one_node() {
        let mut def = WorkflowDef::new("simple", NodeId::from("decompile"));
        def.add_node(WorkflowNode::new(
            "decompile",
            NodeKind::ToolCall {
                tool_name: "decompile".into(),
                server_hint: None,
                params_template: serde_json::json!({"address": "0x1000"}),
            },
        ));
        let exec = WorkflowEngine::run(
            def,
            serde_json::json!({}),
            &stub(),
            Duration::from_secs(5),
        );
        assert_eq!(exec.status, WorkflowStatus::Succeeded);
        assert!(exec.node_results.contains_key(&NodeId::from("decompile")));
    }

    #[test]
    fn test_workflow_sequential_dependency() {
        let mut def = WorkflowDef::new("seq", NodeId::from("step1"));
        def.add_node(WorkflowNode::new(
            "step1",
            NodeKind::ToolCall {
                tool_name: "decompile".into(),
                server_hint: None,
                params_template: serde_json::json!({}),
            },
        ));
        def.add_node(
            WorkflowNode::new(
                "step2",
                NodeKind::ToolCall {
                    tool_name: "disasm".into(),
                    server_hint: None,
                    params_template: serde_json::json!({}),
                },
            )
            .with_deps(vec![NodeId::from("step1")]),
        );
        let exec = WorkflowEngine::run(def, serde_json::json!({}), &stub(), Duration::from_secs(5));
        assert_eq!(exec.status, WorkflowStatus::Succeeded);
        assert!(exec.node_results.contains_key(&NodeId::from("step2")));
    }

    #[test]
    fn test_workflow_validate_missing_entry() {
        let def = WorkflowDef::new("bad", NodeId::from("missing_node"));
        let errors = def.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_condition_expr_field_eq() {
        let ctx = serde_json::json!({"status": "ok"});
        let cond = ConditionExpr::FieldEq {
            path: "status".into(),
            value: serde_json::json!("ok"),
        };
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_expr_and() {
        let ctx = serde_json::json!({"a": 1, "b": 2});
        let cond = ConditionExpr::And(
            Box::new(ConditionExpr::FieldExists { path: "a".into() }),
            Box::new(ConditionExpr::FieldExists { path: "b".into() }),
        );
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_condition_expr_gt() {
        let ctx = serde_json::json!({"score": 0.9});
        let cond = ConditionExpr::FieldGt { path: "score".into(), threshold: 0.5 };
        assert!(cond.evaluate(&ctx));
    }

    #[test]
    fn test_workflow_accumulate() {
        let mut def = WorkflowDef::new("acc", NodeId::from("s1"));
        def.add_node(WorkflowNode::new(
            "s1",
            NodeKind::ToolCall {
                tool_name: "decompile".into(),
                server_hint: None,
                params_template: serde_json::json!({}),
            },
        ));
        def.add_node(WorkflowNode::new(
            "s2",
            NodeKind::ToolCall {
                tool_name: "disasm".into(),
                server_hint: None,
                params_template: serde_json::json!({}),
            },
        ));
        def.add_node(
            WorkflowNode::new("accum", NodeKind::Accumulate { strategy: AccumulateStrategy::Merge })
                .with_deps(vec![NodeId::from("s1"), NodeId::from("s2")]),
        );
        let exec = WorkflowEngine::run(def, serde_json::json!({}), &stub(), Duration::from_secs(5));
        assert_eq!(exec.status, WorkflowStatus::Succeeded);
        assert!(!exec.accumulated.is_null());
    }

    #[test]
    fn test_workflow_checkpoint_and_restore() {
        let mut def = WorkflowDef::new("cp", NodeId::from("n1"));
        def.add_node(WorkflowNode::new(
            "n1",
            NodeKind::ToolCall {
                tool_name: "decompile".into(),
                server_hint: None,
                params_template: serde_json::json!({}),
            },
        ));
        let exec1 = WorkflowEngine::run(
            def.clone(),
            serde_json::json!({}),
            &stub(),
            Duration::from_secs(5),
        );
        let cp = exec1.checkpoint();
        assert!(cp.node_statuses.contains_key("n1"));
        // Restore into a new execution
        let mut exec2 = WorkflowExecution::new(def, serde_json::json!({}));
        exec2.restore_from_checkpoint(&cp);
        assert_eq!(
            exec2.node_statuses.get(&NodeId::from("n1")),
            Some(&NodeStatus::Succeeded)
        );
    }

    #[test]
    fn test_render_template() {
        let template = serde_json::json!({ "path": "{{binary}}" });
        let input = serde_json::json!({"binary": "/bin/ls"});
        let rendered = WorkflowEngine::render_template(&template, &input, &HashMap::new());
        assert_eq!(rendered["path"], "/bin/ls");
    }

    #[test]
    fn test_topological_order() {
        let mut def = WorkflowDef::new("topo", NodeId::from("a"));
        def.add_node(WorkflowNode::new("a", NodeKind::Marker { label: "a".into() }));
        def.add_node(
            WorkflowNode::new("b", NodeKind::Marker { label: "b".into() })
                .with_deps(vec![NodeId::from("a")]),
        );
        let order = def.topological_order().unwrap();
        assert_eq!(order.len(), 2);
    }
}
