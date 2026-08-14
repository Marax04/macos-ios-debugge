//! Workflow definition validator.
//!
//! Validates a workflow before it is handed to the executor, catching
//! structural errors such as circular dependencies, references to unknown steps,
//! invalid conditions, and missing outputs.

use std::collections::{HashMap, HashSet, VecDeque};

// ── ValidationError ───────────────────────────────────────────────────────────

/// Categories of workflow validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A cycle was detected in the step dependency graph.
    CircularDependency {
        /// The cycle expressed as an ordered path of step IDs.
        cycle: Vec<String>,
    },
    /// A step's dependency list references a step that does not exist.
    UnknownStep {
        /// The step that has the bad reference.
        from_step: String,
        /// The referenced step that does not exist.
        unknown_step: String,
    },
    /// A condition expression is syntactically invalid or references an unknown variable.
    InvalidCondition {
        /// The step containing the bad condition.
        step_id: String,
        /// The condition text that failed validation.
        condition: String,
        /// Human-readable reason.
        reason: String,
    },
    /// A step declares an output that is never produced.
    MissingOutput {
        /// The step that is missing an output.
        step_id: String,
        /// The declared output key that was missing.
        output_key: String,
    },
    /// The workflow has no steps at all.
    EmptyWorkflow,
    /// Two steps share the same ID.
    DuplicateStepId(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CircularDependency { cycle } => {
                write!(f, "circular dependency: {}", cycle.join(" → "))
            }
            Self::UnknownStep {
                from_step,
                unknown_step,
            } => {
                write!(
                    f,
                    "step '{from_step}' depends on unknown step '{unknown_step}'"
                )
            }
            Self::InvalidCondition {
                step_id,
                condition,
                reason,
            } => {
                write!(
                    f,
                    "step '{step_id}' has invalid condition '{condition}': {reason}"
                )
            }
            Self::MissingOutput {
                step_id,
                output_key,
            } => {
                write!(
                    f,
                    "step '{step_id}' is missing declared output '{output_key}'"
                )
            }
            Self::EmptyWorkflow => write!(f, "workflow has no steps"),
            Self::DuplicateStepId(id) => write!(f, "duplicate step ID: '{id}'"),
        }
    }
}

impl std::error::Error for ValidationError {}

// ── ValidationReport ──────────────────────────────────────────────────────────

/// The result of validating a workflow definition.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Whether the workflow passed all validation checks.
    pub is_valid: bool,
    /// All validation errors found (empty if `is_valid`).
    pub errors: Vec<ValidationError>,
    /// Informational warnings (non-fatal).
    pub warnings: Vec<String>,
    /// Topologically sorted step IDs (populated only when valid).
    pub execution_order: Vec<String>,
}

impl ValidationReport {
    /// Create a valid report with no errors.
    #[must_use]
    pub const fn ok(execution_order: Vec<String>) -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            execution_order,
        }
    }

    /// Create a failed report from a list of errors.
    #[must_use]
    pub const fn failed(errors: Vec<ValidationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            warnings: Vec::new(),
            execution_order: Vec::new(),
        }
    }

    /// Return `true` if there are no errors.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Return the number of errors.
    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.errors.len()
    }
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid {
            write!(f, "Workflow valid ({} steps)", self.execution_order.len())
        } else {
            write!(f, "Workflow invalid ({} error(s))", self.errors.len())
        }
    }
}

// ── WorkflowStepDef ───────────────────────────────────────────────────────────

/// A lightweight description of one step used for validation.
#[derive(Debug, Clone)]
pub struct WorkflowStepDef {
    /// Unique step identifier.
    pub id: String,
    /// IDs of steps that must complete before this step can run.
    pub depends_on: Vec<String>,
    /// Optional condition expression (e.g. `"output.status == 'success'"`).
    pub condition: Option<String>,
    /// Output keys this step is expected to produce.
    pub declared_outputs: Vec<String>,
    /// Output keys actually produced (e.g., from schema introspection).
    pub actual_outputs: Vec<String>,
}

impl WorkflowStepDef {
    /// Create a minimal step definition with no dependencies.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            depends_on: Vec::new(),
            condition: None,
            declared_outputs: Vec::new(),
            actual_outputs: Vec::new(),
        }
    }

    /// Add a dependency.
    #[must_use]
    pub fn with_dep(mut self, dep: impl Into<String>) -> Self {
        self.depends_on.push(dep.into());
        self
    }

    /// Set the condition expression.
    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Declare an expected output key.
    #[must_use]
    pub fn with_declared_output(mut self, key: impl Into<String>) -> Self {
        self.declared_outputs.push(key.into());
        self
    }

    /// Register an actual output key.
    #[must_use]
    pub fn with_actual_output(mut self, key: impl Into<String>) -> Self {
        self.actual_outputs.push(key.into());
        self
    }
}

// ── WorkflowValidator ─────────────────────────────────────────────────────────

/// Validates a workflow definition before execution.
pub struct WorkflowValidator;

impl WorkflowValidator {
    /// Validate a list of step definitions, returning a [`ValidationReport`].
    #[must_use]
    pub fn validate(steps: &[WorkflowStepDef]) -> ValidationReport {
        let mut errors = Vec::new();

        // ── 1. Empty workflow ─────────────────────────────────────────────────
        if steps.is_empty() {
            return ValidationReport::failed(vec![ValidationError::EmptyWorkflow]);
        }

        // ── 2. Duplicate IDs ──────────────────────────────────────────────────
        let mut seen_ids: HashSet<&str> = HashSet::new();
        for step in steps {
            if !seen_ids.insert(step.id.as_str()) {
                errors.push(ValidationError::DuplicateStepId(step.id.clone()));
            }
        }

        // Build ID set for dependency resolution.
        let id_set: HashSet<&str> = steps.iter().map(|s| s.id.as_str()).collect();

        // ── 3. Unknown step references ────────────────────────────────────────
        for step in steps {
            for dep in &step.depends_on {
                if !id_set.contains(dep.as_str()) {
                    errors.push(ValidationError::UnknownStep {
                        from_step: step.id.clone(),
                        unknown_step: dep.clone(),
                    });
                }
            }
        }

        // ── 4. Condition validation ───────────────────────────────────────────
        for step in steps {
            if let Some(cond) = &step.condition
                && let Some(err) = Self::validate_condition(&step.id, cond) {
                    errors.push(err);
                }
        }

        // ── 5. Missing outputs ────────────────────────────────────────────────
        for step in steps {
            let actual: HashSet<&str> = step.actual_outputs.iter().map(std::string::String::as_str).collect();
            for declared in &step.declared_outputs {
                if !actual.contains(declared.as_str()) {
                    errors.push(ValidationError::MissingOutput {
                        step_id: step.id.clone(),
                        output_key: declared.clone(),
                    });
                }
            }
        }

        // ── 6. Cycle detection (Kahn's algorithm) ─────────────────────────────
        if errors.is_empty() {
            match Self::topological_sort(steps) {
                Ok(order) => return ValidationReport::ok(order),
                Err(cycle) => {
                    errors.push(ValidationError::CircularDependency { cycle });
                }
            }
        }

        ValidationReport::failed(errors)
    }

    /// Validate a condition string.  We accept any non-empty condition that
    /// does not contain obviously disallowed tokens (e.g. shell metacharacters).
    fn validate_condition(step_id: &str, cond: &str) -> Option<ValidationError> {
        let cond = cond.trim();
        if cond.is_empty() {
            return Some(ValidationError::InvalidCondition {
                step_id: step_id.to_string(),
                condition: cond.to_string(),
                reason: "condition is empty".to_string(),
            });
        }
        // Reject shell injection patterns
        for banned in &[';', '|', '&', '`', '$', '(', ')'] {
            if cond.contains(*banned) {
                return Some(ValidationError::InvalidCondition {
                    step_id: step_id.to_string(),
                    condition: cond.to_string(),
                    reason: format!("condition contains disallowed character '{banned}'"),
                });
            }
        }
        None
    }

    /// Kahn's topological sort.  Returns the sorted order on success or
    /// a cycle path on failure.
    fn topological_sort(steps: &[WorkflowStepDef]) -> Result<Vec<String>, Vec<String>> {
        let id_to_idx: HashMap<&str, usize> = steps
            .iter()
            .enumerate()
            .map(|(i, s)| (s.id.as_str(), i))
            .collect();

        let n = steps.len();
        let mut in_degree = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![vec![]; n];

        for step in steps {
            let from = id_to_idx[step.id.as_str()];
            for dep in &step.depends_on {
                if let Some(&to) = id_to_idx.get(dep.as_str()) {
                    adj[to].push(from);
                    in_degree[from] += 1;
                }
            }
        }

        let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut order = Vec::with_capacity(n);

        while let Some(node) = queue.pop_front() {
            order.push(steps[node].id.clone());
            for &next in &adj[node] {
                in_degree[next] -= 1;
                if in_degree[next] == 0 {
                    queue.push_back(next);
                }
            }
        }

        if order.len() == n {
            Ok(order)
        } else {
            // Collect remaining nodes as the cycle indicator
            let in_cycle: Vec<String> = (0..n)
                .filter(|&i| in_degree[i] > 0)
                .map(|i| steps[i].id.clone())
                .collect();
            Err(in_cycle)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_workflow_is_invalid() {
        let report = WorkflowValidator::validate(&[]);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::EmptyWorkflow))
        );
    }

    #[test]
    fn test_single_step_is_valid() {
        let steps = vec![WorkflowStepDef::new("step1")];
        let report = WorkflowValidator::validate(&steps);
        assert!(report.is_valid);
        assert_eq!(report.execution_order, vec!["step1"]);
    }

    #[test]
    fn test_linear_dependency_chain() {
        let steps = vec![
            WorkflowStepDef::new("a"),
            WorkflowStepDef::new("b").with_dep("a"),
            WorkflowStepDef::new("c").with_dep("b"),
        ];
        let report = WorkflowValidator::validate(&steps);
        assert!(report.is_valid);
        assert_eq!(report.execution_order, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_unknown_step_reference() {
        let steps = vec![WorkflowStepDef::new("a").with_dep("nonexistent")];
        let report = WorkflowValidator::validate(&steps);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::UnknownStep { .. }))
        );
    }

    #[test]
    fn test_circular_dependency_detected() {
        let steps = vec![
            WorkflowStepDef::new("a").with_dep("b"),
            WorkflowStepDef::new("b").with_dep("a"),
        ];
        let report = WorkflowValidator::validate(&steps);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::CircularDependency { .. }))
        );
    }

    #[test]
    fn test_invalid_condition_empty() {
        let steps = vec![WorkflowStepDef::new("a").with_condition("")];
        let report = WorkflowValidator::validate(&steps);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidCondition { .. }))
        );
    }

    #[test]
    fn test_invalid_condition_shell_injection() {
        let steps = vec![WorkflowStepDef::new("a").with_condition("x == 1; rm -rf /")];
        let report = WorkflowValidator::validate(&steps);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidCondition { .. }))
        );
    }

    #[test]
    fn test_valid_condition_accepted() {
        let steps = vec![WorkflowStepDef::new("a").with_condition("output.status == success")];
        let report = WorkflowValidator::validate(&steps);
        assert!(report.is_valid);
    }

    #[test]
    fn test_missing_output_detected() {
        let step = WorkflowStepDef::new("a")
            .with_declared_output("result")
            .with_actual_output("other_key");
        let report = WorkflowValidator::validate(&[step]);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::MissingOutput { .. }))
        );
    }

    #[test]
    fn test_duplicate_step_id() {
        let steps = vec![WorkflowStepDef::new("dup"), WorkflowStepDef::new("dup")];
        let report = WorkflowValidator::validate(&steps);
        assert!(!report.is_valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::DuplicateStepId(_)))
        );
    }

    #[test]
    fn test_validation_report_display_valid() {
        let report = ValidationReport::ok(vec!["a".to_string(), "b".to_string()]);
        let s = report.to_string();
        assert!(s.contains("valid"));
    }

    #[test]
    fn test_validation_error_display_cycle() {
        let err = ValidationError::CircularDependency {
            cycle: vec!["a".to_string(), "b".to_string(), "a".to_string()],
        };
        assert!(err.to_string().contains("circular"));
    }
}
