//! Exhaustive blitz tests for rustre-agent-workflow.
//!
//! Targets the pure / parser / DSL / template / validator surfaces.

use std::collections::HashMap;
use std::time::Duration;

use rustre_agent_workflow::workflow_dsl::{
    DslCondition, DslInput, DslStep, DslStepBuilder, StepOutcome, WorkflowBuilder, WorkflowDef as DslWorkflowDef,
};
use rustre_agent_workflow::workflow_templates::{self, TEMPLATE_NAMES};
use rustre_agent_workflow::workflow_validator::{
    ValidationError, ValidationReport, WorkflowStepDef, WorkflowValidator,
};
use rustre_agent_workflow::{
    ErrorStrategy, InputDef, InputSpec, RetryConfig, RunStatus, SpecWorkflowError,
    SpecWorkflowStep, StepDef, StepId, StepResult, StepStatus, TemplateEngine, Workflow,
    WorkflowCondition, WorkflowDef as SpecWorkflowDef, WorkflowError, WorkflowRun, WorkflowRunner,
    WorkflowState, WorkflowStatus, WorkflowStep, WorkflowYaml, load_workflow_file,
    load_workflow_spec, parse_workflow_spec, parse_workflow_yaml,
};

// ─── RetryConfig::delay_ms ────────────────────────────────────────────────────

#[test]
fn retry_delay_attempt_one_is_zero() {
    let r = RetryConfig {
        max_attempts: 5,
        backoff_ms: 100,
        exponential: true,
    };
    assert_eq!(r.delay_ms(1), 0);
    assert_eq!(r.delay_ms(0), 0);
}

#[test]
fn retry_delay_linear() {
    let r = RetryConfig {
        max_attempts: 5,
        backoff_ms: 250,
        exponential: false,
    };
    assert_eq!(r.delay_ms(2), 250);
    assert_eq!(r.delay_ms(3), 250);
    assert_eq!(r.delay_ms(100), 250);
}

#[test]
fn retry_delay_exponential() {
    let r = RetryConfig {
        max_attempts: 10,
        backoff_ms: 100,
        exponential: true,
    };
    assert_eq!(r.delay_ms(2), 100); // 100 * 2^0
    assert_eq!(r.delay_ms(3), 200); // 100 * 2^1
    assert_eq!(r.delay_ms(4), 400);
    assert_eq!(r.delay_ms(5), 800);
}

#[test]
fn retry_delay_exponential_saturates_no_panic() {
    let r = RetryConfig {
        max_attempts: 64,
        backoff_ms: u64::MAX / 2,
        exponential: true,
    };
    // Must not panic.
    let _ = r.delay_ms(63);
    let _ = r.delay_ms(100);
}

#[test]
fn retry_config_default() {
    let r = RetryConfig::default();
    assert_eq!(r.max_attempts, 1);
    assert_eq!(r.backoff_ms, 0);
    assert!(!r.exponential);
}

// ─── WorkflowError display ────────────────────────────────────────────────────

#[test]
fn workflow_error_display_variants() {
    assert!(WorkflowError::NotFound("x".into()).to_string().contains('x'));
    assert!(WorkflowError::InvalidWorkflow("bad".into()).to_string().contains("bad"));
    assert!(WorkflowError::StepFailed {
        step: "s1".into(),
        message: "boom".into()
    }
    .to_string()
    .contains("s1"));
    assert!(WorkflowError::Cancelled.to_string().contains("cancelled"));
    assert!(WorkflowError::RetriesExceeded("s".into()).to_string().contains('s'));
    assert!(WorkflowError::RollbackFailed("r".into()).to_string().contains('r'));
    assert!(WorkflowError::ConditionError("c".into()).to_string().contains('c'));
    assert!(WorkflowError::DbError("d".into()).to_string().contains('d'));
    assert!(
        WorkflowError::SerializationError("s".into())
            .to_string()
            .contains('s')
    );
}

#[test]
fn workflow_error_from_serde_json() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("{not json");
    let e: WorkflowError = bad.unwrap_err().into();
    assert!(matches!(e, WorkflowError::SerializationError(_)));
}

// ─── WorkflowState ────────────────────────────────────────────────────────────

#[test]
fn workflow_state_vars() {
    let mut st = WorkflowState::new("wf");
    assert_eq!(st.workflow_id, "wf");
    assert!(st.get_var("x").is_none());
    st.set_var("x", serde_json::json!(42));
    assert_eq!(st.get_var("x"), Some(&serde_json::json!(42)));
}

#[test]
fn workflow_status_eq() {
    assert_eq!(WorkflowStatus::Pending, WorkflowStatus::Pending);
    assert_ne!(WorkflowStatus::Pending, WorkflowStatus::Running);
    assert_ne!(
        WorkflowStatus::Failed("a".into()),
        WorkflowStatus::Failed("b".into())
    );
}

#[test]
fn workflow_step_constructor_defaults() {
    let s = WorkflowStep::new("id", "agent");
    assert_eq!(s.id, "id");
    assert_eq!(s.agent, "agent");
    assert!(matches!(s.condition, Some(WorkflowCondition::Always)));
}

#[test]
fn workflow_constructor() {
    let wf = Workflow::new(
        "id",
        "name",
        vec![WorkflowStep::new("a", "ag")],
        ErrorStrategy::Continue,
    );
    assert_eq!(wf.id, "id");
    assert_eq!(wf.steps.len(), 1);
    assert!(matches!(wf.on_error, ErrorStrategy::Continue));
}

// ─── Spec types (lib.rs §spec) ────────────────────────────────────────────────

#[test]
fn spec_step_id_display_and_eq() {
    let a = StepId::new(7);
    let b = StepId::new(7);
    assert_eq!(a, b);
    assert_eq!(a.to_string(), "Step(7)");
    use std::collections::HashSet;
    let mut h = HashSet::new();
    h.insert(a);
    assert!(h.contains(&b));
}

#[test]
fn spec_workflow_topological_diamond() {
    let mut def = SpecWorkflowDef::new("diamond");
    def.add_step(SpecWorkflowStep::new(1, "root", "cap"));
    def.add_step(SpecWorkflowStep::new(2, "l", "cap").with_dep(StepId::new(1)));
    def.add_step(SpecWorkflowStep::new(3, "r", "cap").with_dep(StepId::new(1)));
    def.add_step(
        SpecWorkflowStep::new(4, "join", "cap")
            .with_dep(StepId::new(2))
            .with_dep(StepId::new(3)),
    );
    let order = def.topological_order().unwrap();
    assert_eq!(order.len(), 4);
    let pos = |n: u32| order.iter().position(|s| s.inner == n).unwrap();
    assert!(pos(1) < pos(2));
    assert!(pos(1) < pos(3));
    assert!(pos(2) < pos(4));
    assert!(pos(3) < pos(4));
}

#[test]
fn spec_workflow_cycle() {
    let mut def = SpecWorkflowDef::new("cycle");
    def.add_step(SpecWorkflowStep::new(1, "a", "cap").with_dep(StepId::new(2)));
    def.add_step(SpecWorkflowStep::new(2, "b", "cap").with_dep(StepId::new(1)));
    let err = def.topological_order().unwrap_err();
    assert!(matches!(err, SpecWorkflowError::CycleDetected));
}

#[test]
fn spec_workflow_missing_dep() {
    let mut def = SpecWorkflowDef::new("m");
    def.add_step(SpecWorkflowStep::new(1, "a", "c").with_dep(StepId::new(99)));
    let err = def.validate().unwrap_err();
    assert!(matches!(err, SpecWorkflowError::MissingStep(99)));
}

#[test]
fn spec_runner_executes_in_topological_order() {
    let mut def = SpecWorkflowDef::new("d");
    def.add_step(SpecWorkflowStep::new(1, "first", "c"));
    def.add_step(SpecWorkflowStep::new(2, "second", "c").with_dep(StepId::new(1)));
    let run = WorkflowRunner::new().execute(def);
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.succeeded_count(), 2);
}

#[test]
fn spec_runner_cycle_yields_failed_status() {
    let mut def = SpecWorkflowDef::new("cyc");
    def.add_step(SpecWorkflowStep::new(1, "a", "c").with_dep(StepId::new(2)));
    def.add_step(SpecWorkflowStep::new(2, "b", "c").with_dep(StepId::new(1)));
    let run = WorkflowRunner::new().execute(def);
    assert!(matches!(run.status, RunStatus::Failed(_)));
    assert_eq!(run.succeeded_count(), 0);
}

#[test]
fn step_result_succeeded_and_failed() {
    let ok = StepResult {
        step_id: StepId::new(1),
        status: StepStatus::Completed("good".into()),
        output: None,
        duration_ms: 0,
    };
    assert!(ok.succeeded());

    let bad = StepResult {
        step_id: StepId::new(2),
        status: StepStatus::Failed("err".into()),
        output: None,
        duration_ms: 0,
    };
    assert!(!bad.succeeded());

    let skipped = StepResult {
        step_id: StepId::new(3),
        status: StepStatus::Skipped,
        output: None,
        duration_ms: 0,
    };
    assert!(!skipped.succeeded());
}

#[test]
fn workflow_run_counts_zero_on_empty() {
    let run = WorkflowRun {
        def_name: "e".into(),
        results: HashMap::new(),
        status: RunStatus::Completed,
    };
    assert_eq!(run.succeeded_count(), 0);
    assert_eq!(run.failed_count(), 0);
}

#[test]
fn spec_workflow_serde_roundtrip() {
    let mut def = SpecWorkflowDef::new("rt");
    def.add_step(SpecWorkflowStep::new(1, "a", "cap"));
    let s = serde_json::to_string(&def).unwrap();
    let back: SpecWorkflowDef = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "rt");
    assert_eq!(back.steps.len(), 1);
}

// ─── ValidationReport / WorkflowValidator ─────────────────────────────────────

#[test]
fn validator_empty_workflow() {
    let r = WorkflowValidator::validate(&[]);
    assert!(!r.is_valid);
    assert_eq!(r.error_count(), 1);
    assert!(matches!(r.errors[0], ValidationError::EmptyWorkflow));
}

#[test]
fn validator_diamond_orders_correctly() {
    let steps = vec![
        WorkflowStepDef::new("a"),
        WorkflowStepDef::new("b").with_dep("a"),
        WorkflowStepDef::new("c").with_dep("a"),
        WorkflowStepDef::new("d").with_dep("b").with_dep("c"),
    ];
    let r = WorkflowValidator::validate(&steps);
    assert!(r.is_valid, "errors: {:?}", r.errors);
    let pos = |x: &str| r.execution_order.iter().position(|s| s == x).unwrap();
    assert!(pos("a") < pos("b"));
    assert!(pos("a") < pos("c"));
    assert!(pos("b") < pos("d"));
    assert!(pos("c") < pos("d"));
}

#[test]
fn validator_cycle_marks_invalid() {
    let steps = vec![
        WorkflowStepDef::new("a").with_dep("b"),
        WorkflowStepDef::new("b").with_dep("a"),
    ];
    let r = WorkflowValidator::validate(&steps);
    assert!(!r.is_valid);
    assert!(
        r.errors
            .iter()
            .any(|e| matches!(e, ValidationError::CircularDependency { .. }))
    );
}

#[test]
fn validator_self_loop() {
    let steps = vec![WorkflowStepDef::new("a").with_dep("a")];
    let r = WorkflowValidator::validate(&steps);
    assert!(!r.is_valid);
}

#[test]
fn validator_duplicate_id() {
    let steps = vec![WorkflowStepDef::new("d"), WorkflowStepDef::new("d")];
    let r = WorkflowValidator::validate(&steps);
    assert!(!r.is_valid);
    assert!(
        r.errors
            .iter()
            .any(|e| matches!(e, ValidationError::DuplicateStepId(s) if s == "d"))
    );
}

#[test]
fn validator_unknown_dep() {
    let steps = vec![WorkflowStepDef::new("a").with_dep("ghost")];
    let r = WorkflowValidator::validate(&steps);
    assert!(!r.is_valid);
    assert!(
        r.errors
            .iter()
            .any(|e| matches!(e, ValidationError::UnknownStep { unknown_step, .. } if unknown_step == "ghost"))
    );
}

#[test]
fn validator_condition_rejects_shell_metacharacters() {
    for ch in [";", "|", "&", "`", "$", "(", ")"] {
        let cond = format!("x == 1 {ch} bad");
        let steps = vec![WorkflowStepDef::new("a").with_condition(cond.clone())];
        let r = WorkflowValidator::validate(&steps);
        assert!(!r.is_valid, "should reject condition containing {ch:?}");
    }
}

#[test]
fn validator_condition_empty_after_trim() {
    let steps = vec![WorkflowStepDef::new("a").with_condition("    ")];
    let r = WorkflowValidator::validate(&steps);
    assert!(!r.is_valid);
}

#[test]
fn validator_missing_output() {
    let s = WorkflowStepDef::new("a")
        .with_declared_output("must_have")
        .with_actual_output("other");
    let r = WorkflowValidator::validate(&[s]);
    assert!(!r.is_valid);
    assert!(
        r.errors
            .iter()
            .any(|e| matches!(e, ValidationError::MissingOutput { output_key, .. } if output_key == "must_have"))
    );
}

#[test]
fn validator_declared_and_actual_match() {
    let s = WorkflowStepDef::new("a")
        .with_declared_output("k")
        .with_actual_output("k");
    let r = WorkflowValidator::validate(&[s]);
    assert!(r.is_valid);
}

#[test]
fn validation_report_display_invalid() {
    let r = ValidationReport::failed(vec![ValidationError::EmptyWorkflow]);
    let s = r.to_string();
    assert!(s.contains("invalid"));
    assert!(r.has_errors());
}

#[test]
fn validation_error_display_unknown_step() {
    let e = ValidationError::UnknownStep {
        from_step: "a".into(),
        unknown_step: "b".into(),
    };
    let s = e.to_string();
    assert!(s.contains('a') && s.contains('b'));
}

#[test]
fn validation_error_display_missing_output() {
    let e = ValidationError::MissingOutput {
        step_id: "step1".into(),
        output_key: "out_key".into(),
    };
    let s = e.to_string();
    assert!(s.contains("step1") && s.contains("out_key"));
}

#[test]
fn validation_error_display_duplicate_and_empty() {
    assert!(
        ValidationError::DuplicateStepId("foo".into())
            .to_string()
            .contains("foo")
    );
    assert!(
        ValidationError::EmptyWorkflow.to_string().to_lowercase().contains("no")
    );
}

// ─── DslCondition ────────────────────────────────────────────────────────────

fn outcome(ok: bool) -> StepOutcome {
    StepOutcome {
        succeeded: ok,
        outputs: HashMap::new(),
        artifacts: HashMap::new(),
        error: None,
        skipped: false,
    }
}

#[test]
fn dsl_condition_always_never() {
    let m = HashMap::new();
    assert!(DslCondition::Always.evaluate(&m));
    assert!(!DslCondition::Never.evaluate(&m));
}

#[test]
fn dsl_condition_prior_succeeded_missing_step_is_false() {
    let m = HashMap::new();
    let c = DslCondition::PriorSucceeded {
        step: "x".into(),
    };
    assert!(!c.evaluate(&m));
}

#[test]
fn dsl_condition_prior_failed_missing_step_is_false() {
    // Implementation: results.get(step).map(|r| !r.succeeded).unwrap_or(false)
    // So missing step yields false (which is debatable, but documented behavior).
    let m = HashMap::new();
    let c = DslCondition::PriorFailed {
        step: "x".into(),
    };
    assert!(!c.evaluate(&m));
}

#[test]
fn dsl_condition_artifact_exists() {
    let mut o = outcome(true);
    o.artifacts.insert("a".into(), serde_json::json!(1));
    let mut m = HashMap::new();
    m.insert("s".to_string(), o);
    assert!(DslCondition::ArtifactExists {
        step: "s".into(),
        artifact: "a".into(),
    }
    .evaluate(&m));
    assert!(!DslCondition::ArtifactExists {
        step: "s".into(),
        artifact: "missing".into(),
    }
    .evaluate(&m));
}

#[test]
fn dsl_condition_output_equals() {
    let mut o = outcome(true);
    o.outputs.insert("k".into(), serde_json::json!("v"));
    let mut m = HashMap::new();
    m.insert("s".to_string(), o);
    assert!(DslCondition::OutputEquals {
        step: "s".into(),
        key: "k".into(),
        value: serde_json::json!("v"),
    }
    .evaluate(&m));
    assert!(!DslCondition::OutputEquals {
        step: "s".into(),
        key: "k".into(),
        value: serde_json::json!("other"),
    }
    .evaluate(&m));
}

#[test]
fn dsl_condition_and_or_not() {
    let m = HashMap::new();
    let t = DslCondition::Always;
    let f = DslCondition::Never;

    assert!(DslCondition::And(vec![t.clone(), t.clone()]).evaluate(&m));
    assert!(!DslCondition::And(vec![t.clone(), f.clone()]).evaluate(&m));
    assert!(DslCondition::And(vec![]).evaluate(&m)); // all() on empty == true
    assert!(DslCondition::Or(vec![f.clone(), t.clone()]).evaluate(&m));
    assert!(!DslCondition::Or(vec![f.clone(), f.clone()]).evaluate(&m));
    assert!(!DslCondition::Or(vec![]).evaluate(&m)); // any() on empty == false
    assert!(DslCondition::Not(Box::new(f)).evaluate(&m));
    assert!(!DslCondition::Not(Box::new(t)).evaluate(&m));
}

// ─── DSL WorkflowBuilder / WorkflowDef ───────────────────────────────────────

#[test]
fn dsl_builder_then_chains_dep_and_input() {
    let wf = WorkflowBuilder::new("w", "W")
        .step(DslStep::new("a", "A", "cap"))
        .then(DslStep::new("b", "B", "cap"))
        .build()
        .unwrap();
    let b = wf.step("b").unwrap();
    assert!(b.depends_on.iter().any(|d| d == "a"));
    assert!(matches!(b.input, DslInput::StepOutput(ref s) if s == "a"));
}

#[test]
fn dsl_builder_parallel_with_merge() {
    let wf = WorkflowBuilder::new("w", "W")
        .step(DslStep::new("seed", "Seed", "init"))
        .parallel(
            vec![
                DslStep::new("p1", "P1", "cap"),
                DslStep::new("p2", "P2", "cap"),
            ],
            Some(DslStep::new("merge", "M", "merge")),
        )
        .build()
        .unwrap();
    let merge = wf.step("merge").unwrap();
    assert!(merge.depends_on.contains(&"p1".to_string()));
    assert!(merge.depends_on.contains(&"p2".to_string()));
    assert!(matches!(merge.input, DslInput::Merge(ref v) if v.len() == 2));
    // Parallel branches inherit dep on seed.
    let p1 = wf.step("p1").unwrap();
    assert!(p1.depends_on.contains(&"seed".to_string()));
}

#[test]
fn dsl_builder_parallel_no_merge() {
    let wf = WorkflowBuilder::new("w", "W")
        .step(DslStep::new("seed", "Seed", "init"))
        .parallel(
            vec![
                DslStep::new("p1", "P1", "cap"),
                DslStep::new("p2", "P2", "cap"),
            ],
            None,
        )
        .build_unchecked();
    assert_eq!(wf.steps.len(), 3);
}

#[test]
fn dsl_build_fails_on_invalid_dep() {
    let r = WorkflowBuilder::new("w", "W")
        .step(DslStep::new("a", "A", "cap").depends_on("missing"))
        .build();
    assert!(r.is_err());
}

#[test]
fn dsl_workflow_def_roots_and_leaves() {
    let def = DslWorkflowDef::new("w", "W", "1.0")
        .add_step(DslStep::new("root", "R", "c"))
        .add_step(DslStep::new("mid", "M", "c").depends_on("root"))
        .add_step(DslStep::new("leaf", "L", "c").depends_on("mid"));
    let roots: Vec<_> = def.root_steps().into_iter().map(|s| s.id.as_str()).collect();
    assert_eq!(roots, vec!["root"]);
    let leaves: Vec<_> = def.leaf_steps().into_iter().map(|s| s.id.as_str()).collect();
    assert_eq!(leaves, vec!["leaf"]);
}

#[test]
fn dsl_workflow_def_dependants_of() {
    let def = DslWorkflowDef::new("w", "W", "1.0")
        .add_step(DslStep::new("a", "A", "c"))
        .add_step(DslStep::new("b", "B", "c").depends_on("a"))
        .add_step(DslStep::new("c", "C", "c").depends_on("a"));
    let deps: Vec<_> = def.dependants_of("a").into_iter().map(|s| s.id.as_str()).collect();
    assert!(deps.contains(&"b") && deps.contains(&"c"));
    assert!(def.dependants_of("nothing").is_empty());
}

#[test]
fn dsl_workflow_def_to_dot_contains_edges() {
    let def = DslWorkflowDef::new("w", "W", "1.0")
        .add_step(DslStep::new("a", "A", "c"))
        .add_step(DslStep::new("b", "B", "c").depends_on("a"));
    let dot = def.to_dot();
    assert!(dot.starts_with("digraph"));
    assert!(dot.contains("\"a\" -> \"b\""));
    assert!(dot.ends_with("}\n"));
}

#[test]
fn dsl_workflow_def_display() {
    let def = DslWorkflowDef::new("id", "MyName", "2.0")
        .add_step(DslStep::new("a", "A", "c"));
    let s = format!("{def}");
    assert!(s.contains("MyName"));
    assert!(s.contains("2.0"));
    assert!(s.contains("1 steps"));
}

#[test]
fn dsl_workflow_json_roundtrip() {
    let def = DslWorkflowDef::new("w", "W", "1.0")
        .add_step(DslStep::new("a", "A", "cap"))
        .add_step(DslStep::new("b", "B", "cap").depends_on("a"));
    let json = def.to_json().unwrap();
    let back = DslWorkflowDef::from_json(&json).unwrap();
    assert_eq!(back.id, "w");
    assert_eq!(back.steps.len(), 2);
}

#[test]
fn dsl_workflow_fallback_unknown_step_invalid() {
    let mut s = DslStep::new("a", "A", "c");
    s.fallback = Some("ghost".to_string());
    let def = DslWorkflowDef::new("w", "W", "1.0").add_step(s);
    assert!(def.validate().is_err());
}

#[test]
fn dsl_step_builder_chains() {
    let s = DslStepBuilder::new("id", "name", "cap")
        .depends_on("x")
        .input(DslInput::Trigger)
        .timeout(Duration::from_secs(5))
        .retries(3, Duration::from_millis(250))
        .fallback("fb")
        .condition(DslCondition::Always)
        .param("k", serde_json::json!("v"))
        .optional()
        .build();
    assert_eq!(s.id, "id");
    assert_eq!(s.depends_on, vec!["x"]);
    assert_eq!(s.timeout, Some(Duration::from_secs(5)));
    assert_eq!(s.retry.max_attempts, 3);
    assert_eq!(s.retry.backoff_ms, 250);
    assert_eq!(s.fallback.as_deref(), Some("fb"));
    assert!(s.optional);
    assert!(s.params.get("k").is_some());
}

// ─── Templates ───────────────────────────────────────────────────────────────

#[test]
fn templates_all_instantiate_and_validate() {
    for name in TEMPLATE_NAMES {
        let wf = workflow_templates::instantiate(name)
            .unwrap_or_else(|e| panic!("template {name} failed: {e}"));
        wf.validate()
            .unwrap_or_else(|e| panic!("template {name} validate failed: {e}"));
        assert!(!wf.steps.is_empty(), "template {name} has no steps");
    }
}

#[test]
fn templates_unknown_name_errors() {
    let e = workflow_templates::instantiate("does_not_exist").unwrap_err();
    assert!(matches!(e, WorkflowError::InvalidWorkflow(_)));
}

#[test]
fn templates_list_metadata_matches_registry() {
    let infos = workflow_templates::list_templates();
    assert_eq!(infos.len(), TEMPLATE_NAMES.len());
    for info in infos {
        assert!(info.step_count > 0);
        assert!(!info.id.is_empty());
        assert!(!info.name.is_empty());
    }
}

// ─── YAML parsing ────────────────────────────────────────────────────────────

#[test]
fn yaml_parse_minimal() {
    let yaml = r"
name: w
steps:
  - id: s1
    tool: t
";
    let wf: WorkflowYaml = parse_workflow_yaml(yaml).unwrap();
    assert_eq!(wf.name, "w");
    assert_eq!(wf.steps.len(), 1);
}

#[test]
fn yaml_parse_malformed_returns_serialization_error() {
    let e = parse_workflow_yaml("name: w\nsteps: [not valid }}").unwrap_err();
    assert!(matches!(e, WorkflowError::SerializationError(_)));
}

#[test]
fn yaml_parse_inputs_with_defaults() {
    let yaml = r#"
name: w
inputs:
  count:
    type: int
    default: 7
  mode:
    type: string
    default: "fast"
  enabled:
    type: bool
  path:
    type: file
steps:
  - id: a
    tool: t
"#;
    let wf = parse_workflow_yaml(yaml).unwrap();
    assert_eq!(wf.inputs.len(), 4);
    match wf.inputs.get("count").unwrap() {
        InputSpec::Int { default: Some(7) } => {}
        other => panic!("unexpected: {other:?}"),
    }
    match wf.inputs.get("mode").unwrap() {
        InputSpec::String { default: Some(s) } if s == "fast" => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn load_workflow_file_missing() {
    let e = load_workflow_file(std::path::Path::new(
        "/definitely/does/not/exist/abcxyz.yaml",
    ))
    .unwrap_err();
    assert!(matches!(e, WorkflowError::SerializationError(_)));
}

// ─── WorkflowSpec ────────────────────────────────────────────────────────────

#[test]
fn spec_parse_minimal_and_required_inputs() {
    let yaml = r"
name: x
inputs:
  binary:
    type: file
    required: true
  optional_var:
    type: string
steps:
  - id: a
    tool: t
";
    let spec = parse_workflow_spec(yaml).unwrap();
    let req = spec.required_inputs();
    assert_eq!(req, vec!["binary"]);
}

#[test]
fn spec_validate_inputs_missing() {
    let yaml = r"
name: x
inputs:
  binary:
    type: file
    required: true
steps:
  - id: a
    tool: t
";
    let spec = parse_workflow_spec(yaml).unwrap();
    let supplied = HashMap::new();
    let e = spec.validate_inputs(&supplied).unwrap_err();
    assert!(matches!(e, WorkflowError::StepFailed { .. }));
}

#[test]
fn spec_validate_inputs_present() {
    let yaml = r"
name: x
inputs:
  binary:
    type: file
    required: true
steps:
  - id: a
    tool: t
";
    let spec = parse_workflow_spec(yaml).unwrap();
    let mut supplied = HashMap::new();
    supplied.insert("binary".to_string(), serde_json::json!("/x"));
    assert!(spec.validate_inputs(&supplied).is_ok());
}

#[test]
fn input_def_is_required_default_false() {
    let def = InputDef {
        type_: "string".into(),
        default: None,
        required: None,
    };
    assert!(!def.is_required());
}

#[test]
fn step_def_error_policy_default_fail() {
    let s = StepDef {
        id: "a".into(),
        tool: Some("t".into()),
        custom: None,
        args: None,
        out: None,
        when: None,
        on_error: None,
        inputs: None,
    };
    assert_eq!(s.error_policy(), "fail");
    assert!(!s.continues_on_error());
}

#[test]
fn step_def_error_policy_continue_case_insensitive() {
    let s = StepDef {
        id: "a".into(),
        tool: Some("t".into()),
        custom: None,
        args: None,
        out: None,
        when: None,
        on_error: Some("CONTINUE".into()),
        inputs: None,
    };
    assert!(s.continues_on_error());
}

#[test]
fn load_workflow_spec_missing_file() {
    let e =
        load_workflow_spec(std::path::Path::new("/no/such/spec.yaml")).unwrap_err();
    assert!(matches!(e, WorkflowError::SerializationError(_)));
}

// ─── TemplateEngine ──────────────────────────────────────────────────────────

fn ctx(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

#[test]
fn template_render_basic_substitution() {
    let c = ctx(&[("x", serde_json::json!("yes"))]);
    assert_eq!(TemplateEngine::render("v={{ x }}", &c).unwrap(), "v=yes");
}

#[test]
fn template_render_missing_var_is_empty() {
    let c = ctx(&[]);
    assert_eq!(TemplateEngine::render("v={{ missing }}", &c).unwrap(), "v=");
}

#[test]
fn template_render_nested_field_navigation() {
    let c = ctx(&[("obj", serde_json::json!({"a": {"b": "deep"}}))]);
    assert_eq!(
        TemplateEngine::render("{{ obj.a.b }}", &c).unwrap(),
        "deep"
    );
}

#[test]
fn template_render_array_index_navigation() {
    let c = ctx(&[("arr", serde_json::json!(["zero", "one", "two"]))]);
    assert_eq!(
        TemplateEngine::render("{{ arr.1 }}", &c).unwrap(),
        "one"
    );
}

#[test]
fn template_render_len_object() {
    let c = ctx(&[("obj", serde_json::json!({"a": 1, "b": 2}))]);
    assert_eq!(TemplateEngine::render("{{ len(obj) }}", &c).unwrap(), "2");
}

#[test]
fn template_render_len_unknown_returns_zero() {
    let c = ctx(&[]);
    assert_eq!(TemplateEngine::render("{{ len(none) }}", &c).unwrap(), "0");
}

#[test]
fn template_render_multiple_placeholders() {
    let c = ctx(&[
        ("a", serde_json::json!(1)),
        ("b", serde_json::json!(true)),
    ]);
    assert_eq!(
        TemplateEngine::render("{{ a }},{{ b }}", &c).unwrap(),
        "1,true"
    );
}

#[test]
fn template_render_no_placeholders() {
    let c = ctx(&[]);
    assert_eq!(TemplateEngine::render("plain", &c).unwrap(), "plain");
}

#[test]
fn template_render_unclosed_braces_does_not_loop_forever() {
    let c = ctx(&[]);
    // {{ without matching }} should break out gracefully.
    let out = TemplateEngine::render("xxx {{ unterminated", &c).unwrap();
    assert!(out.contains("xxx"));
}

#[test]
fn template_evaluate_condition_literals() {
    let c = ctx(&[]);
    assert!(TemplateEngine::evaluate_condition("true", &c));
    assert!(TemplateEngine::evaluate_condition("True", &c));
    assert!(!TemplateEngine::evaluate_condition("false", &c));
    assert!(TemplateEngine::evaluate_condition("completed", &c));
}

#[test]
fn template_evaluate_condition_truthy_types() {
    assert!(TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::json!(1))])
    ));
    assert!(!TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::json!(0))])
    ));
    assert!(TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::json!("nonempty"))])
    ));
    assert!(!TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::json!(""))])
    ));
    assert!(TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::json!([1]))])
    ));
    assert!(!TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::Value::Array(vec![]))])
    ));
    assert!(!TemplateEngine::evaluate_condition(
        "x",
        &ctx(&[("x", serde_json::Value::Null)])
    ));
}

#[test]
fn template_evaluate_condition_eq_ne() {
    let c = ctx(&[("mode", serde_json::json!("debug"))]);
    assert!(TemplateEngine::evaluate_condition("mode == debug", &c));
    assert!(!TemplateEngine::evaluate_condition("mode == release", &c));
    assert!(TemplateEngine::evaluate_condition("mode != release", &c));
    assert!(!TemplateEngine::evaluate_condition("mode != debug", &c));
}

#[test]
fn template_evaluate_comparison_numeric() {
    let c = ctx(&[("count", serde_json::json!(5))]);
    assert!(TemplateEngine::evaluate_comparison("count > 0", &c));
    assert!(TemplateEngine::evaluate_comparison("count >= 5", &c));
    assert!(TemplateEngine::evaluate_comparison("count < 10", &c));
    assert!(TemplateEngine::evaluate_comparison("count <= 5", &c));
    assert!(TemplateEngine::evaluate_comparison("count == 5", &c));
    assert!(!TemplateEngine::evaluate_comparison("count == 6", &c));
    assert!(TemplateEngine::evaluate_comparison("count != 6", &c));
}

#[test]
fn template_evaluate_comparison_with_len() {
    let c = ctx(&[("items", serde_json::json!([1, 2, 3]))]);
    assert!(TemplateEngine::evaluate_comparison("len(items) == 3", &c));
    assert!(TemplateEngine::evaluate_comparison("len(items) >= 1", &c));
    assert!(!TemplateEngine::evaluate_comparison("len(items) > 3", &c));
}

#[test]
fn template_evaluate_comparison_quoted_string() {
    let c = ctx(&[("mode", serde_json::json!("release"))]);
    assert!(TemplateEngine::evaluate_comparison("mode == 'release'", &c));
    assert!(!TemplateEngine::evaluate_comparison("mode == 'debug'", &c));
}

#[test]
fn template_evaluate_comparison_braced_wrapper() {
    let c = ctx(&[("n", serde_json::json!(7))]);
    assert!(TemplateEngine::evaluate_comparison("{{ n > 3 }}", &c));
}

// ─── WorkflowRunner YAML execution ───────────────────────────────────────────

#[test]
fn run_yaml_tool_step_completes() {
    let yaml = r"
name: w
inputs: {}
steps:
  - id: a
    tool: tool.a
    out: a_out
";
    let wf = parse_workflow_yaml(yaml).unwrap();
    let state = WorkflowRunner::new()
        .run_yaml(&wf, HashMap::new())
        .unwrap();
    assert_eq!(state.status, RunStatus::Completed);
    assert!(state.outputs.contains_key("a_out"));
}

#[test]
fn run_yaml_when_false_skips() {
    let yaml = r#"
name: w
inputs: {}
steps:
  - id: a
    tool: tool.a
    when: "false"
    out: a_out
"#;
    let wf = parse_workflow_yaml(yaml).unwrap();
    let state = WorkflowRunner::new()
        .run_yaml(&wf, HashMap::new())
        .unwrap();
    assert_eq!(state.status, RunStatus::Completed);
    assert!(!state.outputs.contains_key("a_out"));
}

#[test]
fn run_yaml_on_error_fail_stops() {
    // step with neither tool nor custom is an error
    let yaml = r"
name: w
inputs: {}
steps:
  - id: bad
";
    let wf = parse_workflow_yaml(yaml).unwrap();
    let e = WorkflowRunner::new()
        .run_yaml(&wf, HashMap::new())
        .unwrap_err();
    assert!(matches!(e, SpecWorkflowError::ExecFailed { .. }));
}

#[test]
fn run_yaml_on_error_continue_proceeds() {
    let yaml = r"
name: w
inputs: {}
steps:
  - id: bad
    on_error: continue
  - id: good
    tool: t
    out: good_out
";
    let wf = parse_workflow_yaml(yaml).unwrap();
    let state = WorkflowRunner::new()
        .run_yaml(&wf, HashMap::new())
        .unwrap();
    assert_eq!(state.status, RunStatus::Completed);
    assert!(state.outputs.contains_key("bad_error"));
    assert!(state.outputs.contains_key("good_out"));
}

#[test]
fn run_yaml_step_output_visible_to_next_template() {
    let yaml = r#"
name: w
inputs: {}
steps:
  - id: a
    tool: t.a
    out: a_out
  - id: b
    tool: t.b
    args:
      from: "{{ a_out }}"
    out: b_out
"#;
    let wf = parse_workflow_yaml(yaml).unwrap();
    let state = WorkflowRunner::new()
        .run_yaml(&wf, HashMap::new())
        .unwrap();
    assert_eq!(state.status, RunStatus::Completed);
    // b_out should exist and reference a non-empty rendering
    assert!(state.outputs.contains_key("b_out"));
}
