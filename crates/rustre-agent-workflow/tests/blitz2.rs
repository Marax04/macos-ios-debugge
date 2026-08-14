//! Blitz2: deep adversarial tests for rustre-agent-workflow.
//!
//! Targets pure / deterministic surfaces of the crate:
//! - `RetryConfig` delay math (boundary, overflow, exponential saturation)
//! - `WorkflowState` / Workflow / `WorkflowStatus`
//! - Spec `WorkflowDef` / `WorkflowRunner` topological ordering
//! - `WorkflowYaml` parser
//! - `WorkflowStore` persistence (in-memory)
//! - Builtin workflows catalogue
//! - `SpecWorkflowError` display
//! - Hash/Eq consistency where applicable
//! - Send/Sync threaded stress

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_agent_workflow::{
    builtin_workflows, parse_workflow_yaml, ErrorStrategy, RetryConfig, RunStatus,
    SpecWorkflowError, SpecWorkflowStep, StepId, StepResult, StepStatus, Workflow,
    WorkflowCondition, WorkflowDef as SpecWorkflowDef, WorkflowError, WorkflowRun,
    WorkflowRunner, WorkflowState, WorkflowStatus, WorkflowStep, WorkflowStore,
};

// ────────────────────────────────────────────────────────────────────────────
// Seeded LCG fuzzer (no rand, no std::time)
// ────────────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    const fn next_in(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.next_u32() % n
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RetryConfig
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_retry_default_values() {
    let r = RetryConfig::default();
    assert_eq!(r.max_attempts, 1);
    assert_eq!(r.backoff_ms, 0);
    assert!(!r.exponential);
    assert_eq!(r.delay_ms(1), 0);
    assert_eq!(r.delay_ms(0), 0);
    assert_eq!(r.delay_ms(u32::MAX), 0);
}

#[test]
fn b2_retry_linear_constant() {
    let r = RetryConfig {
        max_attempts: 8,
        backoff_ms: 75,
        exponential: false,
    };
    for a in 2u32..32 {
        assert_eq!(r.delay_ms(a), 75, "linear delay constant for attempt {a}");
    }
    assert_eq!(r.delay_ms(1), 0);
}

#[test]
fn b2_retry_exponential_growth() {
    let r = RetryConfig {
        max_attempts: 16,
        backoff_ms: 50,
        exponential: true,
    };
    let mut expected = 50u64;
    for a in 2u32..10 {
        assert_eq!(r.delay_ms(a), expected, "attempt {a}");
        expected = expected.saturating_mul(2);
    }
}

#[test]
fn b2_retry_exponential_saturates() {
    let r = RetryConfig {
        max_attempts: u32::MAX,
        backoff_ms: u64::MAX,
        exponential: true,
    };
    // Must never panic; saturating math holds.
    for a in 2u32..50 {
        let _ = r.delay_ms(a);
    }
    assert!(r.delay_ms(50) > 0);
}

#[test]
fn b2_retry_fuzz_no_panic() {
    let mut g = Lcg::new();
    for _ in 0..200 {
        let r = RetryConfig {
            max_attempts: g.next_u32(),
            backoff_ms: g.next_u64(),
            exponential: g.next_u32() & 1 == 0,
        };
        for _ in 0..8 {
            let _ = r.delay_ms(g.next_u32());
        }
    }
}

#[test]
fn b2_retry_attempt_one_always_zero() {
    let mut g = Lcg::new();
    for _ in 0..60 {
        let r = RetryConfig {
            max_attempts: g.next_u32(),
            backoff_ms: g.next_u64() | 1, // non-zero
            exponential: g.next_u32() & 1 == 0,
        };
        assert_eq!(r.delay_ms(1), 0);
        assert_eq!(r.delay_ms(0), 0);
    }
}

#[test]
fn b2_retry_serde_round_trip() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let r = RetryConfig {
            max_attempts: g.next_u32() % 1000,
            backoff_ms: g.next_u64() % 1_000_000,
            exponential: g.next_u32() & 1 == 0,
        };
        let j = serde_json::to_string(&r).unwrap();
        let r2: RetryConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(r.max_attempts, r2.max_attempts);
        assert_eq!(r.backoff_ms, r2.backoff_ms);
        assert_eq!(r.exponential, r2.exponential);
        // and delay matches
        assert_eq!(r.delay_ms(3), r2.delay_ms(3));
    }
}

// ────────────────────────────────────────────────────────────────────────────
// WorkflowState
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_state_new_pending() {
    let s = WorkflowState::new("abc");
    assert_eq!(s.workflow_id, "abc");
    assert_eq!(s.current_step, 0);
    assert!(s.variables.is_empty());
    assert!(s.step_results.is_empty());
    assert_eq!(s.status, WorkflowStatus::Pending);
}

#[test]
fn b2_state_set_get_vars_many() {
    let mut s = WorkflowState::new("wf");
    let mut g = Lcg::new();
    let mut expected: HashMap<String, serde_json::Value> = HashMap::new();
    for _ in 0..50 {
        let key = format!("k{}", g.next_u32() % 30);
        let val = serde_json::json!(g.next_u32());
        s.set_var(&key, val.clone());
        expected.insert(key, val);
    }
    for (k, v) in &expected {
        assert_eq!(s.get_var(k), Some(v));
    }
    assert!(s.get_var("__missing__").is_none());
}

#[test]
fn b2_state_serde_round_trip() {
    let mut s = WorkflowState::new("rt");
    s.set_var("x", serde_json::json!(42));
    s.set_var("name", serde_json::json!("alice"));
    s.status = WorkflowStatus::Running;
    let j = serde_json::to_string(&s).unwrap();
    let back: WorkflowState = serde_json::from_str(&j).unwrap();
    assert_eq!(back.workflow_id, "rt");
    assert_eq!(back.get_var("x"), Some(&serde_json::json!(42)));
    assert_eq!(back.status, WorkflowStatus::Running);
}

// ────────────────────────────────────────────────────────────────────────────
// WorkflowStatus equality
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_workflow_status_equality_matrix() {
    let variants = [
        WorkflowStatus::Pending,
        WorkflowStatus::Running,
        WorkflowStatus::Succeeded,
        WorkflowStatus::Cancelled,
        WorkflowStatus::Failed("x".to_string()),
        WorkflowStatus::Failed("y".to_string()),
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            assert_eq!(a == b, i == j, "i={i} j={j}");
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// WorkflowStep / Workflow constructors
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_workflow_step_new_defaults() {
    let s = WorkflowStep::new("s1", "agent-a");
    assert_eq!(s.id, "s1");
    assert_eq!(s.agent, "agent-a");
    assert!(s.input_mapping.is_empty());
    assert!(s.output_mapping.is_empty());
    assert!(matches!(s.condition, Some(WorkflowCondition::Always)));
    assert_eq!(s.retry.max_attempts, 1);
}

#[test]
fn b2_workflow_new_fields() {
    let w = Workflow::new(
        "wid",
        "Workflow Name",
        vec![WorkflowStep::new("a", "agt")],
        ErrorStrategy::Continue,
    );
    assert_eq!(w.id, "wid");
    assert_eq!(w.name, "Workflow Name");
    assert_eq!(w.steps.len(), 1);
    assert!(matches!(w.on_error, ErrorStrategy::Continue));
}

#[test]
fn b2_workflow_serde_round_trip() {
    let w = Workflow::new(
        "x",
        "X",
        vec![
            WorkflowStep::new("a", "agt"),
            WorkflowStep::new("b", "agt2"),
        ],
        ErrorStrategy::Stop,
    );
    let j = serde_json::to_string(&w).unwrap();
    let back: Workflow = serde_json::from_str(&j).unwrap();
    assert_eq!(back.id, "x");
    assert_eq!(back.steps.len(), 2);
    assert_eq!(back.steps[1].id, "b");
}

// ────────────────────────────────────────────────────────────────────────────
// builtin_workflows
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_builtin_workflows_non_empty_and_unique_ids() {
    let wfs = builtin_workflows();
    assert!(wfs.len() >= 4);
    let mut ids: Vec<&str> = wfs.iter().map(|w| w.id.as_str()).collect();
    ids.sort_unstable();
    let unique_count = {
        let mut s = ids.clone();
        s.dedup();
        s.len()
    };
    assert_eq!(unique_count, wfs.len(), "ids must be unique");
}

#[test]
fn b2_builtin_workflows_have_steps_and_unique_step_ids() {
    for w in builtin_workflows() {
        assert!(!w.steps.is_empty(), "workflow {} has no steps", w.id);
        let mut ids: Vec<&str> = w.steps.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        let original_len = ids.len();
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "duplicate step ids in {}",
            w.id
        );
    }
}

#[test]
fn b2_builtin_workflows_serde_round_trip() {
    for w in builtin_workflows() {
        let j = serde_json::to_string(&w).unwrap();
        let back: Workflow = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id, w.id);
        assert_eq!(back.steps.len(), w.steps.len());
    }
}

#[test]
fn b2_builtin_workflows_specific_present() {
    let wfs = builtin_workflows();
    let names: Vec<&str> = wfs.iter().map(|w| w.id.as_str()).collect();
    for must in [
        "full_re_analysis",
        "malware_triage",
        "function_rename",
        "vuln_hunt",
    ] {
        assert!(names.contains(&must), "missing {must}");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Spec WorkflowDef + WorkflowRunner: topological ordering
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_spec_topo_chain_50() {
    let mut def = SpecWorkflowDef::new("chain");
    def.add_step(SpecWorkflowStep::new(1, "s1", "cap"));
    for i in 2u32..=50 {
        def.add_step(SpecWorkflowStep::new(i, format!("s{i}"), "cap").with_dep(StepId::new(i - 1)));
    }
    let order = def.topological_order().unwrap();
    assert_eq!(order.len(), 50);
    for (idx, sid) in order.iter().enumerate() {
        assert_eq!(sid.inner, u32::try_from(idx).unwrap() + 1);
    }
}

#[test]
fn b2_spec_topo_cycle_2() {
    let mut def = SpecWorkflowDef::new("cyc");
    def.add_step(SpecWorkflowStep::new(1, "a", "c").with_dep(StepId::new(2)));
    def.add_step(SpecWorkflowStep::new(2, "b", "c").with_dep(StepId::new(1)));
    let e = def.topological_order().unwrap_err();
    assert!(matches!(e, SpecWorkflowError::CycleDetected));
}

#[test]
fn b2_spec_topo_self_cycle() {
    let mut def = SpecWorkflowDef::new("self");
    def.add_step(SpecWorkflowStep::new(1, "a", "c").with_dep(StepId::new(1)));
    assert!(matches!(
        def.topological_order().unwrap_err(),
        SpecWorkflowError::CycleDetected
    ));
}

#[test]
fn b2_spec_topo_missing_dep_error() {
    let mut def = SpecWorkflowDef::new("miss");
    def.add_step(SpecWorkflowStep::new(1, "a", "c").with_dep(StepId::new(999)));
    let e = def.topological_order().unwrap_err();
    assert!(matches!(e, SpecWorkflowError::MissingStep(999)));
}

#[test]
fn b2_spec_topo_diamond_valid() {
    let mut def = SpecWorkflowDef::new("d");
    def.add_step(SpecWorkflowStep::new(1, "root", "c"));
    def.add_step(SpecWorkflowStep::new(2, "l", "c").with_dep(StepId::new(1)));
    def.add_step(SpecWorkflowStep::new(3, "r", "c").with_dep(StepId::new(1)));
    let mut leaf = SpecWorkflowStep::new(4, "leaf", "c");
    leaf.depends_on.push(StepId::new(2));
    leaf.depends_on.push(StepId::new(3));
    def.add_step(leaf);
    let order = def.topological_order().unwrap();
    assert_eq!(order.len(), 4);
    // root must come first; leaf last.
    assert_eq!(order[0].inner, 1);
    assert_eq!(order[3].inner, 4);
}

#[test]
fn b2_spec_validate_ok_chain() {
    let mut def = SpecWorkflowDef::new("ok");
    def.add_step(SpecWorkflowStep::new(1, "a", "c"));
    def.add_step(SpecWorkflowStep::new(2, "b", "c").with_dep(StepId::new(1)));
    def.validate().unwrap();
}

#[test]
fn b2_spec_runner_executes_all_steps() {
    let mut def = SpecWorkflowDef::new("run");
    def.add_step(SpecWorkflowStep::new(1, "a", "c"));
    def.add_step(SpecWorkflowStep::new(2, "b", "c").with_dep(StepId::new(1)));
    def.add_step(SpecWorkflowStep::new(3, "c", "c").with_dep(StepId::new(2)));
    let run = WorkflowRunner::new().execute(def);
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.succeeded_count(), 3);
    assert_eq!(run.failed_count(), 0);
    assert_eq!(run.def_name, "run");
}

#[test]
fn b2_spec_runner_cycle_is_failed_run() {
    let mut def = SpecWorkflowDef::new("bad");
    def.add_step(SpecWorkflowStep::new(1, "a", "c").with_dep(StepId::new(2)));
    def.add_step(SpecWorkflowStep::new(2, "b", "c").with_dep(StepId::new(1)));
    let run = WorkflowRunner::new().execute(def);
    assert!(matches!(run.status, RunStatus::Failed(_)));
    assert_eq!(run.results.len(), 0);
}

#[test]
fn b2_step_id_display_round_trip() {
    for n in [0u32, 1, 7, 256, u32::MAX] {
        let s = StepId::new(n).to_string();
        assert_eq!(s, format!("Step({n})"));
    }
}

#[test]
fn b2_step_id_eq_consistent() {
    // Hash/Eq on StepId? StepId derives Serialize/Deserialize but not Hash by default.
    // Just verify PartialEq (it's used inside the runner via ==).
    assert_eq!(StepId::new(7), StepId::new(7));
    assert_ne!(StepId::new(7), StepId::new(8));
}

#[test]
fn b2_step_status_display_all() {
    assert_eq!(StepStatus::Pending.to_string(), "Pending");
    assert_eq!(StepStatus::Running.to_string(), "Running");
    assert_eq!(StepStatus::Skipped.to_string(), "Skipped");
    assert_eq!(
        StepStatus::Completed("k".into()).to_string(),
        "Completed(k)"
    );
    assert_eq!(StepStatus::Failed("e".into()).to_string(), "Failed(e)");
}

#[test]
fn b2_step_result_succeeded_and_failed() {
    let ok = StepResult {
        step_id: StepId::new(1),
        status: StepStatus::Completed("ok".to_string()),
        output: None,
        duration_ms: 0,
    };
    assert!(ok.succeeded());
    let bad = StepResult {
        step_id: StepId::new(2),
        status: StepStatus::Failed("e".to_string()),
        output: None,
        duration_ms: 0,
    };
    assert!(!bad.succeeded());
}

#[test]
fn b2_run_status_display() {
    assert_eq!(RunStatus::NotStarted.to_string(), "NotStarted");
    assert_eq!(RunStatus::Running.to_string(), "Running");
    assert_eq!(RunStatus::Completed.to_string(), "Completed");
    assert_eq!(RunStatus::Failed("p".into()).to_string(), "Failed(p)");
}

#[test]
fn b2_spec_error_display_includes_payload() {
    assert!(
        SpecWorkflowError::MissingStep(7)
            .to_string()
            .contains('7')
    );
    assert!(
        SpecWorkflowError::ExecFailed {
            step: 12,
            reason: "boom".into(),
        }
        .to_string()
        .contains("boom")
    );
    assert!(
        SpecWorkflowError::InvalidDef("nope".into())
            .to_string()
            .contains("nope")
    );
}

#[test]
fn b2_workflow_run_counts_mixed() {
    let mut results = HashMap::new();
    results.insert(
        1u32,
        StepResult {
            step_id: StepId::new(1),
            status: StepStatus::Completed("ok".to_string()),
            output: None,
            duration_ms: 0,
        },
    );
    results.insert(
        2u32,
        StepResult {
            step_id: StepId::new(2),
            status: StepStatus::Failed("err".to_string()),
            output: None,
            duration_ms: 0,
        },
    );
    results.insert(
        3u32,
        StepResult {
            step_id: StepId::new(3),
            status: StepStatus::Skipped,
            output: None,
            duration_ms: 0,
        },
    );
    let run = WorkflowRun {
        def_name: "w".into(),
        results,
        status: RunStatus::Completed,
    };
    assert_eq!(run.succeeded_count(), 1);
    assert_eq!(run.failed_count(), 1);
}

// ────────────────────────────────────────────────────────────────────────────
// YAML parser
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_yaml_parse_minimal() {
    let yaml = r"
name: test
description: simple
steps:
  - id: s1
    tool: binary.info
";
    let wf = parse_workflow_yaml(yaml).unwrap();
    assert_eq!(wf.name, "test");
    assert_eq!(wf.steps.len(), 1);
    assert_eq!(wf.steps[0].id, "s1");
    assert_eq!(wf.steps[0].tool.as_deref(), Some("binary.info"));
}

#[test]
fn b2_yaml_parse_with_inputs() {
    let yaml = r#"
name: wf
description: ""
inputs:
  path:
    type: file
  count:
    type: int
    default: 10
  flag:
    type: bool
steps:
  - id: a
    tool: do.it
"#;
    let wf = parse_workflow_yaml(yaml).unwrap();
    assert_eq!(wf.inputs.len(), 3);
    assert!(wf.inputs.contains_key("path"));
    assert!(wf.inputs.contains_key("count"));
}

#[test]
fn b2_yaml_parse_malformed_returns_err() {
    let yaml = "this is: not [valid yaml: ]\nname";
    let res = parse_workflow_yaml(yaml);
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        WorkflowError::SerializationError(_)
    ));
}

#[test]
fn b2_yaml_parse_empty_returns_err() {
    let res = parse_workflow_yaml("");
    assert!(res.is_err());
}

#[test]
fn b2_yaml_parse_missing_required_fields() {
    let res = parse_workflow_yaml("description: only\n");
    assert!(res.is_err()); // 'name' and 'steps' required
}

#[test]
fn b2_yaml_fuzz_no_panic() {
    // Feed deterministic garbage; parser must return Err (or a benign Ok), never panic.
    let mut g = Lcg::new();
    for _ in 0..40 {
        let len = (g.next_in(80)) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (g.next_u32() & 0x7f) as u8).collect();
        // map to a printable subset for YAML
        let s: String = bytes
            .iter()
            .map(|b| {
                if (*b as char).is_ascii_graphic() || *b == b' ' || *b == b'\n' {
                    *b as char
                } else {
                    ' '
                }
            })
            .collect();
        let _ = parse_workflow_yaml(&s);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// WorkflowStore (in-memory SQLite)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_store_in_memory_init_ok() {
    let _store = WorkflowStore::in_memory().unwrap();
}

#[test]
fn b2_store_save_and_load_workflow() {
    let store = WorkflowStore::in_memory().unwrap();
    let w = Workflow::new(
        "id1",
        "Name 1",
        vec![WorkflowStep::new("s", "a")],
        ErrorStrategy::Stop,
    );
    store.save_workflow(&w).unwrap();
    let back = store.load_workflow("id1").unwrap();
    assert_eq!(back.id, "id1");
    assert_eq!(back.name, "Name 1");
    assert_eq!(back.steps.len(), 1);
}

#[test]
fn b2_store_load_missing_returns_not_found() {
    let store = WorkflowStore::in_memory().unwrap();
    let e = store.load_workflow("ghost").unwrap_err();
    assert!(matches!(e, WorkflowError::NotFound(_)));
}

#[test]
fn b2_store_list_workflows_returns_all() {
    let store = WorkflowStore::in_memory().unwrap();
    for i in 0..10 {
        let w = Workflow::new(
            format!("w{i}"),
            format!("N{i}"),
            vec![],
            ErrorStrategy::Stop,
        );
        store.save_workflow(&w).unwrap();
    }
    let list = store.list_workflows().unwrap();
    assert_eq!(list.len(), 10);
}

#[test]
fn b2_store_save_and_load_state() {
    let store = WorkflowStore::in_memory().unwrap();
    let mut s = WorkflowState::new("wfid");
    s.status = WorkflowStatus::Running;
    s.set_var("k", serde_json::json!("v"));
    let rowid = store.save_state(&s).unwrap();
    assert!(rowid > 0);
    let back = store.load_latest_state("wfid").unwrap();
    assert_eq!(back.workflow_id, "wfid");
    assert_eq!(back.get_var("k"), Some(&serde_json::json!("v")));
}

#[test]
fn b2_store_load_latest_state_missing() {
    let store = WorkflowStore::in_memory().unwrap();
    assert!(matches!(
        store.load_latest_state("none").unwrap_err(),
        WorkflowError::NotFound(_)
    ));
}

#[test]
fn b2_store_delete_states_count() {
    let store = WorkflowStore::in_memory().unwrap();
    let s = WorkflowState::new("del");
    for _ in 0..5 {
        store.save_state(&s).unwrap();
    }
    let count = store.delete_states("del").unwrap();
    assert_eq!(count, 5);
    let count2 = store.delete_states("del").unwrap();
    assert_eq!(count2, 0);
}

#[test]
fn b2_store_add_workflow_and_status() {
    let store = WorkflowStore::in_memory().unwrap();
    store.add_workflow("run1", "name").unwrap();
    let st = store.get_workflow_status("run1").unwrap();
    assert_eq!(st, "running");
    store.set_workflow_status("run1", "succeeded").unwrap();
    assert_eq!(store.get_workflow_status("run1").unwrap(), "succeeded");
}

#[test]
fn b2_store_get_status_missing() {
    let store = WorkflowStore::in_memory().unwrap();
    assert!(matches!(
        store.get_workflow_status("none").unwrap_err(),
        WorkflowError::NotFound(_)
    ));
}

#[test]
fn b2_store_update_step_result_upsert() {
    let store = WorkflowStore::in_memory().unwrap();
    store.add_workflow("r", "n").unwrap();
    // insert
    store
        .update_step_result("r", "s1", "running", None, None)
        .unwrap();
    // update (upsert path)
    store
        .update_step_result("r", "s1", "succeeded", Some("{\"ok\":1}"), None)
        .unwrap();
    // failure path
    store
        .update_step_result("r", "s2", "failed", None, Some("boom"))
        .unwrap();
}

// ────────────────────────────────────────────────────────────────────────────
// Builtin workflows: every step references some agent name (non-empty)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_builtin_workflows_all_steps_have_nonempty_agent() {
    for w in builtin_workflows() {
        for s in &w.steps {
            assert!(!s.agent.is_empty(), "wf {} step {} empty agent", w.id, s.id);
            assert!(!s.id.is_empty(), "wf {} empty step id", w.id);
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Send/Sync threaded stress
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_workflow_store_thread_stress() {
    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let mut handles = Vec::new();
    for t in 0..4u32 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let id = format!("t{t}_w{i}");
                let w = Workflow::new(&id, "n", vec![], ErrorStrategy::Stop);
                store.save_workflow(&w).unwrap();
                let back = store.load_workflow(&id).unwrap();
                assert_eq!(back.id, id);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let list = store.list_workflows().unwrap();
    assert_eq!(list.len(), 400);
}

#[test]
fn b2_spec_workflow_runner_thread_stress() {
    let runner = Arc::new(WorkflowRunner::new());
    let mut handles = Vec::new();
    for t in 0..4u32 {
        let runner = Arc::clone(&runner);
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let mut def = SpecWorkflowDef::new(format!("t{t}_d{i}"));
                def.add_step(SpecWorkflowStep::new(1, "a", "cap"));
                def.add_step(SpecWorkflowStep::new(2, "b", "cap").with_dep(StepId::new(1)));
                let run = runner.execute(def);
                assert_eq!(run.status, RunStatus::Completed);
                assert_eq!(run.succeeded_count(), 2);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// WorkflowError display + From conversions
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_workflow_error_display_variants() {
    let e = WorkflowError::NotFound("x".to_string());
    assert!(e.to_string().contains('x'));
    let e = WorkflowError::InvalidWorkflow("bad".to_string());
    assert!(e.to_string().contains("bad"));
    let e = WorkflowError::StepFailed {
        step: "s".into(),
        message: "m".into(),
    };
    assert!(e.to_string().contains('s'));
    assert!(e.to_string().contains('m'));
    let e = WorkflowError::ConditionError("c".into());
    assert!(e.to_string().contains('c'));
    let e = WorkflowError::Cancelled;
    assert!(e.to_string().to_lowercase().contains("cancel"));
    let e = WorkflowError::RetriesExceeded("rs".into());
    assert!(e.to_string().contains("rs"));
    let e = WorkflowError::RollbackFailed("rb".into());
    assert!(e.to_string().contains("rb"));
}

#[test]
fn b2_workflow_error_from_serde() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("{not json");
    let err: WorkflowError = bad.unwrap_err().into();
    assert!(matches!(err, WorkflowError::SerializationError(_)));
}

#[test]
fn b2_workflow_error_from_rusqlite() {
    let e = rusqlite::Error::InvalidQuery;
    let we: WorkflowError = e.into();
    assert!(matches!(we, WorkflowError::DbError(_)));
}

// ────────────────────────────────────────────────────────────────────────────
// Boundary input fuzz on builtin_workflows JSON round-trip
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn b2_builtin_serde_all_round_trip_deeply_equal() {
    for w in builtin_workflows() {
        let j = serde_json::to_value(&w).unwrap();
        let back: Workflow = serde_json::from_value(j.clone()).unwrap();
        // re-serialize and compare values
        let j2 = serde_json::to_value(&back).unwrap();
        assert_eq!(j, j2, "round trip differs for workflow {}", w.id);
    }
}
