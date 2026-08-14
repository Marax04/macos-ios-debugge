//! Workflow DSL for defining analysis pipelines as directed graphs.
//!
//! A workflow is a directed acyclic graph (DAG) of steps.  Each step has:
//! - An agent capability it requires.
//! - An input produced by previous steps (or the workflow trigger).
//! - Retry / timeout / fallback configuration.
//!
//! Steps are connected via `depends_on` edges.  The DSL supports:
//! - Sequential chains: A → B → C.
//! - Parallel fan-out: A → [B, C, D] → E (E waits for all of B, C, D).
//! - Conditional branching: route to different sub-graphs based on predicates.
//! - Error handling: per-step fallback steps and global error strategies.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{RetryConfig, WorkflowError, ErrorStrategy};

// ─── Step identifier ──────────────────────────────────────────────────────────

/// A stable step identifier within a workflow definition.
pub type DslStepId = String;

// ─── DslStep ──────────────────────────────────────────────────────────────────

/// A step in the workflow DSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DslStep {
    /// Unique ID within the workflow.
    pub id: DslStepId,
    /// Human-readable name.
    pub name: String,
    /// Agent capability required to run this step.
    pub capability: String,
    /// Input specification: where does this step get its data?
    pub input: DslInput,
    /// Steps that must complete before this one starts.
    pub depends_on: Vec<DslStepId>,
    /// Retry configuration.
    pub retry: RetryConfig,
    /// Per-step timeout.
    pub timeout: Option<Duration>,
    /// Fallback step ID if this step fails permanently.
    pub fallback: Option<DslStepId>,
    /// Condition that must be true for this step to run.
    pub condition: Option<DslCondition>,
    /// Static parameters passed to the agent.
    pub params: HashMap<String, serde_json::Value>,
    /// If true, failures in this step are non-fatal (workflow continues).
    pub optional: bool,
    /// Tags for grouping / filtering steps.
    pub tags: Vec<String>,
}

impl DslStep {
    pub fn new(id: impl Into<String>, name: impl Into<String>, capability: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            capability: capability.into(),
            input: DslInput::Trigger,
            depends_on: Vec::new(),
            retry: RetryConfig::default(),
            timeout: None,
            fallback: None,
            condition: None,
            params: HashMap::new(),
            optional: false,
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub fn depends_on(mut self, step_id: impl Into<String>) -> Self {
        self.depends_on.push(step_id.into());
        self
    }

    #[must_use]
    pub fn with_input(mut self, input: DslInput) -> Self {
        self.input = input;
        self
    }

    #[must_use]
    pub const fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub fn with_fallback(mut self, fallback_id: impl Into<String>) -> Self {
        self.fallback = Some(fallback_id.into());
        self
    }

    #[must_use]
    pub fn with_condition(mut self, condition: DslCondition) -> Self {
        self.condition = Some(condition);
        self
    }

    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }

    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

// ─── DslInput ─────────────────────────────────────────────────────────────────

/// Specifies where a step reads its input from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum DslInput {
    /// Use the workflow trigger input directly.
    Trigger,
    /// Use the full output of a prior step.
    StepOutput(DslStepId),
    /// Use a specific named artifact from a prior step.
    StepArtifact { step: DslStepId, artifact: String },
    /// Merge outputs from multiple prior steps (all must complete).
    Merge(Vec<DslStepId>),
    /// Static inline value (for seed / configuration steps).
    Static(serde_json::Value),
}

// ─── DslCondition ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op")]
pub enum DslCondition {
    /// Run if a prior step succeeded.
    PriorSucceeded { step: DslStepId },
    /// Run if a prior step failed.
    PriorFailed { step: DslStepId },
    /// Run if a named artifact exists in a prior step's output.
    ArtifactExists { step: DslStepId, artifact: String },
    /// Run if a named output key matches a value.
    OutputEquals {
        step: DslStepId,
        key: String,
        value: serde_json::Value,
    },
    /// Logical AND of conditions.
    And(Vec<Self>),
    /// Logical OR of conditions.
    Or(Vec<Self>),
    /// Logical NOT.
    Not(Box<Self>),
    /// Always true.
    Always,
    /// Always false (skip step unconditionally).
    Never,
}

#[derive(Serialize)]
#[serde(tag = "op")]
enum DslConditionSurrogate<'a> {
    PriorSucceeded { step: &'a DslStepId },
    PriorFailed { step: &'a DslStepId },
    ArtifactExists { step: &'a DslStepId, artifact: &'a String },
    OutputEquals {
        step: &'a DslStepId,
        key: &'a String,
        value: &'a serde_json::Value,
    },
    And(serde_json::Value),
    Or(serde_json::Value),
    Not(serde_json::Value),
    Always,
    Never,
}

impl Serialize for DslCondition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::PriorSucceeded { step } => {
                DslConditionSurrogate::PriorSucceeded { step }.serialize(serializer)
            }
            Self::PriorFailed { step } => {
                DslConditionSurrogate::PriorFailed { step }.serialize(serializer)
            }
            Self::ArtifactExists { step, artifact } => {
                DslConditionSurrogate::ArtifactExists { step, artifact }.serialize(serializer)
            }
            Self::OutputEquals { step, key, value } => {
                DslConditionSurrogate::OutputEquals { step, key, value }.serialize(serializer)
            }
            Self::And(conds) => {
                let val = serde_json::to_value(conds).map_err(serde::ser::Error::custom)?;
                DslConditionSurrogate::And(val).serialize(serializer)
            }
            Self::Or(conds) => {
                let val = serde_json::to_value(conds).map_err(serde::ser::Error::custom)?;
                DslConditionSurrogate::Or(val).serialize(serializer)
            }
            Self::Not(cond) => {
                let val = serde_json::to_value(cond).map_err(serde::ser::Error::custom)?;
                DslConditionSurrogate::Not(val).serialize(serializer)
            }
            Self::Always => DslConditionSurrogate::Always.serialize(serializer),
            Self::Never => DslConditionSurrogate::Never.serialize(serializer),
        }
    }
}
impl DslCondition {
    /// Evaluate the condition against a map of step results.
    #[must_use]
    pub fn evaluate(&self, results: &HashMap<DslStepId, StepOutcome>) -> bool {
        match self {
            Self::PriorSucceeded { step } => {
                results.get(step).is_some_and(|r| r.succeeded)
            }
            Self::PriorFailed { step } => {
                results.get(step).is_some_and(|r| !r.succeeded)
            }
            Self::ArtifactExists { step, artifact } => results
                .get(step)
                .is_some_and(|r| r.artifacts.contains_key(artifact)),
            Self::OutputEquals { step, key, value } => results
                .get(step)
                .and_then(|r| r.outputs.get(key))
                .is_some_and(|v| v == value),
            Self::And(conds) => conds.iter().all(|c| c.evaluate(results)),
            Self::Or(conds) => conds.iter().any(|c| c.evaluate(results)),
            Self::Not(cond) => !cond.evaluate(results),
            Self::Always => true,
            Self::Never => false,
        }
    }
}

// ─── StepOutcome ─────────────────────────────────────────────────────────────

/// The outcome of a completed step (used for condition evaluation).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StepOutcome {
    pub succeeded: bool,
    pub outputs: HashMap<String, serde_json::Value>,
    pub artifacts: HashMap<String, serde_json::Value>,
    pub error: Option<String>,
    pub skipped: bool,
}

// ─── WorkflowDef ─────────────────────────────────────────────────────────────

/// A complete workflow definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDef {
    /// Unique workflow identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// All steps.
    pub steps: Vec<DslStep>,
    /// Global error strategy.
    pub error_strategy: ErrorStrategy,
    /// Global timeout for the entire workflow.
    pub global_timeout: Option<Duration>,
    /// Description for documentation purposes.
    pub description: String,
    /// Tags for cataloguing.
    pub tags: Vec<String>,
}

impl WorkflowDef {
    /// Create a new empty workflow definition.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            steps: Vec::new(),
            error_strategy: ErrorStrategy::Stop,
            global_timeout: None,
            description: String::new(),
            tags: Vec::new(),
        }
    }

    /// Add a step.
    #[must_use]
    pub fn add_step(mut self, step: DslStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Set the global error strategy.
    #[must_use]
    pub const fn error_strategy(mut self, strategy: ErrorStrategy) -> Self {
        self.error_strategy = strategy;
        self
    }

    /// Set a global timeout.
    #[must_use]
    pub const fn global_timeout(mut self, timeout: Duration) -> Self {
        self.global_timeout = Some(timeout);
        self
    }

    /// Set description.
    #[must_use]
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Validate the workflow DAG for cycles and missing dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        let step_ids: HashSet<&str> = self.steps.iter().map(|s| s.id.as_str()).collect();

        // Check all dependency references exist.
        for step in &self.steps {
            for dep in &step.depends_on {
                if !step_ids.contains(dep.as_str()) {
                    return Err(WorkflowError::InvalidWorkflow(format!(
                        "Step '{}' depends on unknown step '{}'",
                        step.id, dep
                    )));
                }
            }
            if let Some(ref fb) = step.fallback
                && !step_ids.contains(fb.as_str()) {
                    return Err(WorkflowError::InvalidWorkflow(format!(
                        "Step '{}' fallback references unknown step '{}'",
                        step.id, fb
                    )));
                }
        }

        // Topological sort to detect cycles.
        self.topological_order().map(|_| ())
    }

    /// Return steps in topological order (Kahn's algorithm).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn topological_order(&self) -> Result<Vec<&DslStep>, WorkflowError> {
        let id_to_idx: HashMap<&str, usize> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| (s.id.as_str(), i))
            .collect();

        let n = self.steps.len();
        let mut in_degree = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

        for step in &self.steps {
            let &dst = id_to_idx.get(step.id.as_str()).unwrap();
            for dep in &step.depends_on {
                if let Some(&src) = id_to_idx.get(dep.as_str()) {
                    adj[src].push(dst);
                    in_degree[dst] += 1;
                }
            }
        }

        let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut order = Vec::with_capacity(n);

        while let Some(i) = queue.pop_front() {
            order.push(&self.steps[i]);
            for &j in &adj[i] {
                in_degree[j] -= 1;
                if in_degree[j] == 0 {
                    queue.push_back(j);
                }
            }
        }

        if order.len() != n {
            return Err(WorkflowError::InvalidWorkflow(
                "Workflow contains a cycle".into(),
            ));
        }

        Ok(order)
    }

    /// Return all steps that have no dependencies (roots).
    #[must_use]
    pub fn root_steps(&self) -> Vec<&DslStep> {
        self.steps
            .iter()
            .filter(|s| s.depends_on.is_empty())
            .collect()
    }

    /// Return all steps with no dependants (leaves).
    #[must_use]
    pub fn leaf_steps(&self) -> Vec<&DslStep> {
        let deps: HashSet<&str> = self
            .steps
            .iter()
            .flat_map(|s| s.depends_on.iter().map(std::string::String::as_str))
            .collect();
        self.steps
            .iter()
            .filter(|s| !deps.contains(s.id.as_str()))
            .collect()
    }

    /// Return all steps that depend on the given step ID.
    #[must_use]
    pub fn dependants_of(&self, step_id: &str) -> Vec<&DslStep> {
        self.steps
            .iter()
            .filter(|s| s.depends_on.iter().any(|d| d == step_id))
            .collect()
    }

    /// Find a step by ID.
    #[must_use]
    pub fn step(&self, id: &str) -> Option<&DslStep> {
        self.steps.iter().find(|s| s.id == id)
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Generate a DOT graph representation.
    #[must_use]
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph workflow {\n  rankdir=TB;\n");
        for step in &self.steps {
            let label = format!("{}\n({})", step.name, step.capability);
            let _ = writeln!(out,
                "  \"{}\" [label=\"{}\", shape=box];",
                step.id, label
            );
            for dep in &step.depends_on {
                let _ = writeln!(out, "  \"{}\" -> \"{}\";", dep, step.id);
            }
        }
        out.push_str("}\n");
        out
    }
}

impl fmt::Display for WorkflowDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Workflow[{}] v{} ({} steps)",
            self.name,
            self.version,
            self.steps.len()
        )
    }
}

// ─── WorkflowBuilder ─────────────────────────────────────────────────────────

/// Fluent builder for composing workflow definitions.
pub struct WorkflowBuilder {
    def: WorkflowDef,
    /// Last step added (used for automatic chaining with `.then()`).
    last_step_id: Option<String>,
}

impl WorkflowBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            def: WorkflowDef::new(id, name, "1.0.0"),
            last_step_id: None,
        }
    }

    #[must_use]
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.def.version = v.into();
        self
    }

    #[must_use]
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.def.description = d.into();
        self
    }

    #[must_use]
    pub const fn error_strategy(mut self, s: ErrorStrategy) -> Self {
        self.def.error_strategy = s;
        self
    }

    #[must_use]
    pub const fn global_timeout(mut self, t: Duration) -> Self {
        self.def.global_timeout = Some(t);
        self
    }

    /// Add a step with explicit dependency.
    #[must_use]
    pub fn step(mut self, step: DslStep) -> Self {
        self.last_step_id = Some(step.id.clone());
        self.def.steps.push(step);
        self
    }

    /// Chain a step after the last added step.
    #[must_use]
    pub fn then(mut self, mut step: DslStep) -> Self {
        if let Some(ref prev) = self.last_step_id {
            if !step.depends_on.contains(prev) {
                step.depends_on.push(prev.clone());
            }
            // Use prior step's output as input unless already set.
            if matches!(step.input, DslInput::Trigger) {
                step.input = DslInput::StepOutput(prev.clone());
            }
        }
        self.last_step_id = Some(step.id.clone());
        self.def.steps.push(step);
        self
    }

    /// Add a parallel group: all steps run in parallel after the last step.
    /// Returns builder with `last_step_id` set to the merge step (if provided).
    #[must_use]
    pub fn parallel(
        mut self,
        steps: Vec<DslStep>,
        merge_step: Option<DslStep>,
    ) -> Self {
        let prior = self.last_step_id.clone();
        let mut step_ids = Vec::new();
        for mut s in steps {
            if let Some(ref p) = prior
                && !s.depends_on.contains(p) {
                    s.depends_on.push(p.clone());
                }
            step_ids.push(s.id.clone());
            self.def.steps.push(s);
        }
        if let Some(mut merge) = merge_step {
            merge.depends_on.extend(step_ids.iter().cloned());
            merge.input = DslInput::Merge(step_ids);
            self.last_step_id = Some(merge.id.clone());
            self.def.steps.push(merge);
        } else {
            self.last_step_id = step_ids.last().cloned();
        }
        self
    }

    /// Returns an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn build(self) -> Result<WorkflowDef, WorkflowError> {
        self.def.validate()?;
        Ok(self.def)
    }

    /// Build without validation (for unit tests).
    #[must_use]
    pub fn build_unchecked(self) -> WorkflowDef {
        self.def
    }
}

// ─── DslStepBuilder ──────────────────────────────────────────────────────────

/// Builder for a single DSL step.
pub struct DslStepBuilder {
    step: DslStep,
}

impl DslStepBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>, capability: impl Into<String>) -> Self {
        Self {
            step: DslStep::new(id, name, capability),
        }
    }

    #[must_use]
    pub fn depends_on(mut self, id: impl Into<String>) -> Self {
        self.step.depends_on.push(id.into());
        self
    }

    #[must_use]
    pub fn input(mut self, input: DslInput) -> Self {
        self.step.input = input;
        self
    }

    #[must_use]
    pub const fn timeout(mut self, t: Duration) -> Self {
        self.step.timeout = Some(t);
        self
    }

    #[must_use]
    pub fn retries(mut self, max: u32, delay: Duration) -> Self {
        self.step.retry.max_attempts = max;
        self.step.retry.backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        self
    }

    #[must_use]
    pub fn fallback(mut self, id: impl Into<String>) -> Self {
        self.step.fallback = Some(id.into());
        self
    }

    #[must_use]
    pub fn condition(mut self, c: DslCondition) -> Self {
        self.step.condition = Some(c);
        self
    }

    #[must_use]
    pub fn param(mut self, k: impl Into<String>, v: serde_json::Value) -> Self {
        self.step.params.insert(k.into(), v);
        self
    }

    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.step.optional = true;
        self
    }

    #[must_use]
    pub fn build(self) -> DslStep {
        self.step
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_step(id: &str, cap: &str, deps: &[&str]) -> DslStep {
        let mut s = DslStep::new(id, id, cap);
        for d in deps {
            s.depends_on.push(d.to_string());
        }
        s
    }

    #[test]
    fn test_topological_order_linear() {
        let def = WorkflowDef::new("w", "W", "1.0")
            .add_step(simple_step("a", "triage", &[]))
            .add_step(simple_step("b", "pe", &["a"]))
            .add_step(simple_step("c", "yara", &["b"]));
        let order = def.topological_order().unwrap();
        let ids: Vec<&str> = order.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids.iter().position(|&x| x == "a"), Some(0));
        assert!(ids.iter().position(|&x| x == "b") > ids.iter().position(|&x| x == "a"));
        assert!(ids.iter().position(|&x| x == "c") > ids.iter().position(|&x| x == "b"));
    }

    #[test]
    fn test_cycle_detection() {
        let def = WorkflowDef::new("w", "W", "1.0")
            .add_step(simple_step("a", "cap", &["b"]))
            .add_step(simple_step("b", "cap", &["a"]));
        assert!(def.topological_order().is_err());
    }

    #[test]
    fn test_missing_dependency_validation() {
        let def = WorkflowDef::new("w", "W", "1.0")
            .add_step(simple_step("a", "cap", &["nonexistent"]));
        assert!(def.validate().is_err());
    }

    #[test]
    fn test_workflow_builder_chain() {
        let wf = WorkflowBuilder::new("test", "Test")
            .step(DslStep::new("a", "A", "triage"))
            .then(DslStep::new("b", "B", "pe"))
            .then(DslStep::new("c", "C", "yara"))
            .build()
            .unwrap();
        let b = wf.step("b").unwrap();
        assert!(b.depends_on.contains(&"a".to_string()));
        let c = wf.step("c").unwrap();
        assert!(c.depends_on.contains(&"b".to_string()));
    }

    #[test]
    fn test_parallel_group() {
        let wf = WorkflowBuilder::new("test", "Test")
            .step(DslStep::new("init", "Init", "init"))
            .parallel(
                vec![
                    DslStep::new("scan1", "Scan1", "scan"),
                    DslStep::new("scan2", "Scan2", "scan"),
                ],
                Some(DslStep::new("merge", "Merge", "merge")),
            )
            .build()
            .unwrap();
        let merge = wf.step("merge").unwrap();
        assert!(merge.depends_on.contains(&"scan1".to_string()));
        assert!(merge.depends_on.contains(&"scan2".to_string()));
    }

    #[test]
    fn test_condition_evaluation() {
        let mut results = HashMap::new();
        results.insert(
            "step_a".to_string(),
            StepOutcome {
                succeeded: true,
                ..Default::default()
            },
        );
        let cond = DslCondition::PriorSucceeded {
            step: "step_a".to_string(),
        };
        assert!(cond.evaluate(&results));

        let cond_fail = DslCondition::PriorFailed {
            step: "step_a".to_string(),
        };
        assert!(!cond_fail.evaluate(&results));
    }

    #[test]
    fn test_dot_output() {
        let def = WorkflowDef::new("w", "W", "1.0")
            .add_step(simple_step("a", "cap", &[]))
            .add_step(simple_step("b", "cap", &["a"]));
        let dot = def.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("\"a\" -> \"b\""));
    }
}
