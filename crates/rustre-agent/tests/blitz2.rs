//! Blitz2 tests for rustre-agent: deep coverage of lib.rs public surface.
//!
//! Round-trip, boundary, fuzz, hash/Eq, Send/Sync, state-machine tests.

use rustre_agent::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;

// ─── Seeded LCG ──────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─── AgentId ─────────────────────────────────────────────────────────────────

#[test]
fn agent_id_display_zero() {
    assert_eq!(AgentId::new(0).to_string(), "Agent(0)");
}

#[test]
fn agent_id_display_max() {
    assert_eq!(AgentId::new(u64::MAX).to_string(), format!("Agent({})", u64::MAX));
}

#[test]
fn agent_id_hash_eq_consistent_50() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let v = lcg.next();
        let a = AgentId::new(v);
        let b = AgentId::new(v);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn agent_id_distinct_inputs_unequal() {
    let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
    let mut prev = lcg.next();
    for _ in 0..30 {
        let cur = lcg.next();
        if cur != prev {
            assert_ne!(AgentId::new(cur), AgentId::new(prev));
        }
        prev = cur;
    }
}

#[test]
fn agent_id_copy_semantics() {
    let a = AgentId::new(42);
    let b = a;
    assert_eq!(a.inner, b.inner);
}

#[test]
fn agent_id_serde_roundtrip_50() {
    let mut lcg = Lcg::new(7);
    for _ in 0..50 {
        let v = lcg.next();
        let a = AgentId::new(v);
        let s = serde_json::to_string(&a).unwrap();
        let back: AgentId = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }
}

// ─── MessageRole ─────────────────────────────────────────────────────────────

#[test]
fn message_role_as_str_all() {
    assert_eq!(MessageRole::System.as_str(), "system");
    assert_eq!(MessageRole::User.as_str(), "user");
    assert_eq!(MessageRole::Assistant.as_str(), "assistant");
    assert_eq!(MessageRole::Tool.as_str(), "tool");
}

#[test]
fn message_role_eq() {
    assert_eq!(MessageRole::User, MessageRole::User);
    assert_ne!(MessageRole::User, MessageRole::System);
}

// ─── MessageKind ─────────────────────────────────────────────────────────────

#[test]
fn message_kind_display_all() {
    for k in [MessageKind::Query, MessageKind::Response, MessageKind::Event,
              MessageKind::Error, MessageKind::Shutdown] {
        assert!(!k.to_string().is_empty());
    }
}

#[test]
fn message_kind_serde_roundtrip() {
    for k in [MessageKind::Query, MessageKind::Response, MessageKind::Event,
              MessageKind::Error, MessageKind::Shutdown] {
        let s = serde_json::to_string(&k).unwrap();
        let back: MessageKind = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
    }
}

// ─── SpecAgentMessage ────────────────────────────────────────────────────────

#[test]
fn spec_agent_message_ids_unique_50() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..50 {
        let m = SpecAgentMessage::new(
            AgentId::new(1),
            AgentId::new(2),
            MessageKind::Query,
            serde_json::json!({}),
        );
        assert!(ids.insert(m.id));
    }
}

#[test]
fn spec_agent_message_is_query_response() {
    for k in [MessageKind::Query, MessageKind::Response, MessageKind::Event,
              MessageKind::Error, MessageKind::Shutdown] {
        let m = SpecAgentMessage::new(AgentId::new(0), AgentId::new(0), k.clone(), serde_json::json!(null));
        assert_eq!(m.is_query(), k == MessageKind::Query);
        assert_eq!(m.is_response(), k == MessageKind::Response);
    }
}

// ─── AgentStatus ─────────────────────────────────────────────────────────────

#[test]
fn agent_status_display_all() {
    assert_eq!(AgentStatus::Idle.to_string(), "Idle");
    assert_eq!(AgentStatus::Running.to_string(), "Running");
    assert_eq!(AgentStatus::Waiting.to_string(), "Waiting");
    assert_eq!(AgentStatus::Stopped.to_string(), "Stopped");
    assert_eq!(AgentStatus::AgentError("oops".to_string()).to_string(), "Error(oops)");
}

#[test]
fn agent_status_eq() {
    assert_eq!(AgentStatus::Idle, AgentStatus::Idle);
    assert_ne!(AgentStatus::Idle, AgentStatus::Running);
    assert_eq!(
        AgentStatus::AgentError("x".to_string()),
        AgentStatus::AgentError("x".to_string())
    );
}

// ─── SpecAgentCapability ─────────────────────────────────────────────────────

#[test]
fn spec_capability_hash_eq_30_pairs() {
    let caps = [
        SpecAgentCapability::Analyze,
        SpecAgentCapability::Decompile,
        SpecAgentCapability::Debug,
        SpecAgentCapability::Search,
        SpecAgentCapability::Generate,
        SpecAgentCapability::ThreatIntel,
    ];
    for c in &caps {
        let a = c.clone();
        let b = c.clone();
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
    // Generic variants
    let mut lcg = Lcg::new(99);
    for _ in 0..24 {
        let s = format!("g-{}", lcg.next());
        let a = SpecAgentCapability::Generic(s.clone());
        let b = SpecAgentCapability::Generic(s);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

// ─── AgentCapability ─────────────────────────────────────────────────────────

#[test]
fn agent_capability_hash_consistency() {
    let caps = [
        AgentCapability::Disassembly,
        AgentCapability::Decompilation,
        AgentCapability::TypeRecovery,
        AgentCapability::SymbolRename,
        AgentCapability::PatternMatching,
        AgentCapability::ScriptExecution,
        AgentCapability::NetworkAnalysis,
        AgentCapability::MalwareAnalysis,
        AgentCapability::VulnerabilityDetection,
    ];
    for c in &caps {
        assert_eq!(hash_of(&c.clone()), hash_of(&c.clone()));
    }
}

// ─── ExtendedCapability ──────────────────────────────────────────────────────

#[test]
fn extended_capability_display_roundtrip() {
    use ExtendedCapability::*;
    for c in [Disassemble, Decompile, Analyze, Explain, Rename,
              Document, FindVulns, ExplainSuspicious, GenerateSignature, CorrelateThreats] {
        assert!(!c.to_string().is_empty());
        assert_eq!(hash_of(&c.clone()), hash_of(&c.clone()));
    }
}

// ─── TaskPriority ────────────────────────────────────────────────────────────

#[test]
fn task_priority_ordering() {
    use TaskPriority::*;
    assert!(Critical > High);
    assert!(High > Normal);
    assert!(Normal > Low);
}

#[test]
fn task_priority_serde_roundtrip() {
    for p in [TaskPriority::Low, TaskPriority::Normal, TaskPriority::High, TaskPriority::Critical] {
        let s = serde_json::to_string(&p).unwrap();
        let back: TaskPriority = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }
}

// ─── AgentTask ───────────────────────────────────────────────────────────────

#[test]
fn agent_task_no_deadline_never_expired() {
    let t = AgentTask::new(0, "x", ExtendedCapability::Analyze, TaskPriority::Low, serde_json::json!({}));
    assert!(!t.is_expired());
}

#[test]
fn agent_task_with_far_future_deadline_not_expired() {
    let t = AgentTask::new(0, "x", ExtendedCapability::Analyze, TaskPriority::Low, serde_json::json!({}))
        .with_deadline(u64::MAX);
    assert!(!t.is_expired());
}

#[test]
fn agent_task_with_past_deadline_expired() {
    let t = AgentTask::new(0, "x", ExtendedCapability::Analyze, TaskPriority::Low, serde_json::json!({}))
        .with_deadline(1);
    assert!(t.is_expired());
}

// ─── AgentTaskQueue ──────────────────────────────────────────────────────────

#[test]
fn task_queue_priority_order_fuzz() {
    let q = AgentTaskQueue::new();
    let mut lcg = Lcg::new(0x00C0_FFEE);
    let prios = [TaskPriority::Low, TaskPriority::Normal, TaskPriority::High, TaskPriority::Critical];
    for i in 0..40u64 {
        let p = prios[(lcg.next() % 4) as usize];
        q.push(AgentTask::new(i, "t", ExtendedCapability::Analyze, p, serde_json::json!({})));
    }
    assert_eq!(q.len(), 40);
    // Pop in non-increasing priority order
    let mut prev = TaskPriority::Critical;
    while let Some(t) = q.pop() {
        assert!(t.priority <= prev);
        prev = t.priority;
    }
    assert!(q.is_empty());
}

#[test]
fn task_queue_drains_skip_expired_after_push() {
    let q = AgentTaskQueue::new();
    q.push(
        AgentTask::new(1, "exp", ExtendedCapability::Analyze, TaskPriority::Critical, serde_json::json!({}))
            .with_deadline(1)
    );
    q.push(AgentTask::new(2, "fresh", ExtendedCapability::Analyze, TaskPriority::Low, serde_json::json!({})));
    // Critical is expired; pop should return fresh (Low) only.
    let popped = q.pop().unwrap();
    assert_eq!(popped.id, 2);
    assert!(q.pop().is_none());
}

#[test]
fn task_queue_peek_does_not_remove() {
    let q = AgentTaskQueue::new();
    q.push(AgentTask::new(1, "a", ExtendedCapability::Analyze, TaskPriority::High, serde_json::json!({})));
    assert!(q.peek().is_some());
    assert_eq!(q.len(), 1);
}

#[test]
fn task_queue_send_sync_threaded_stress() {
    let q = Arc::new(AgentTaskQueue::new());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let q = Arc::clone(&q);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                q.push(AgentTask::new(tid * 1000 + i, "t", ExtendedCapability::Analyze,
                                       TaskPriority::Normal, serde_json::json!({})));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(q.len(), 400);
}

// ─── AgentMemory ─────────────────────────────────────────────────────────────

#[test]
fn agent_memory_store_get_overwrite() {
    let m = AgentMemory::new(10);
    m.store(MemoryEntry::new("k", serde_json::json!(1)));
    m.store(MemoryEntry::new("k", serde_json::json!(2)));
    assert_eq!(m.get("k").unwrap().value, serde_json::json!(2));
    assert_eq!(m.len(), 1);
}

#[test]
fn agent_memory_capacity_zero_evicts_immediately() {
    let m = AgentMemory::new(0);
    m.store(MemoryEntry::new("k", serde_json::json!(1)));
    // capacity 0: store evicts oldest before insert; len after insert is 1.
    // Per code: if len >= cap, evict. Then insert.
    assert!(m.len() <= 1);
}

#[test]
fn agent_memory_threaded_stress() {
    let m = Arc::new(AgentMemory::new(10_000));
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let m = Arc::clone(&m);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                m.store(MemoryEntry::new(format!("k-{tid}-{i}"), serde_json::json!(i)));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(m.len(), 400);
}

#[test]
fn agent_memory_fuzz_keys() {
    let mut lcg = Lcg::new(0xFEED_FACE);
    let m = AgentMemory::new(10_000);
    for _ in 0..50 {
        let k = format!("key-{}", lcg.next());
        m.store(MemoryEntry::new(k.clone(), serde_json::json!(lcg.next())));
        assert!(m.get(&k).is_some());
    }
}

// ─── AgentObservation ────────────────────────────────────────────────────────

#[test]
fn observation_confidence_clamped_50() {
    let mut lcg = Lcg::new(11);
    for _ in 0..50 {
        let raw = (rustre_agent::casts::u64_to_f32(lcg.next()) / rustre_agent::casts::u64_to_f32(u64::from(u32::MAX))).mul_add(4.0, -2.0);
        let o = AgentObservation::new(ObservationKind::Anomaly, "x", raw);
        assert!(o.confidence >= 0.0 && o.confidence <= 1.0);
    }
}

#[test]
fn observation_at_address_with_evidence() {
    let o = AgentObservation::new(ObservationKind::CryptoUsage, "AES", 0.9)
        .at_address(0xDEAD_BEEF)
        .with_evidence(vec!["e1".to_string(), "e2".to_string()]);
    assert_eq!(o.address, Some(0xDEAD_BEEF));
    assert_eq!(o.evidence.len(), 2);
}

// ─── AgentReasoning ──────────────────────────────────────────────────────────

#[test]
fn reasoning_steps_numbered_1_to_n() {
    let mut r = AgentReasoning::new(1);
    for i in 0..20 {
        r.add_step(format!("step {i}"), None);
    }
    for (idx, step) in r.steps.iter().enumerate() {
        assert_eq!(step.step_number as usize, idx + 1);
    }
}

// ─── AgentPlan ───────────────────────────────────────────────────────────────

#[test]
fn agent_plan_total_estimate_sums() {
    let mut p = AgentPlan::new("g");
    let mut total = 0u64;
    let mut lcg = Lcg::new(3);
    for i in 0..10 {
        let ms = lcg.next() % 1000;
        total += ms;
        p.add_step(PlanStep {
            index: i,
            capability: ExtendedCapability::Analyze,
            description: "s".to_string(),
            estimated_ms: ms,
            depends_on: vec![],
        });
    }
    assert_eq!(p.estimated_total_ms, total);
    assert_eq!(p.step_count(), 10);
}

// ─── AgentConversation ───────────────────────────────────────────────────────

#[test]
fn conversation_role_filter() {
    let mut c = AgentConversation::new("s");
    c.add_message(MessageRole::User, "u1");
    c.add_message(MessageRole::Assistant, "a1");
    c.add_message(MessageRole::User, "u2");
    c.add_message(MessageRole::System, "sys");
    c.add_message(MessageRole::Tool, "tool");
    assert_eq!(c.message_count(), 5);
    assert_eq!(c.user_messages().len(), 2);
    assert_eq!(c.assistant_messages().len(), 1);
}

#[test]
fn conversation_tool_call_result_independent() {
    let mut c = AgentConversation::new("s");
    c.add_tool_call(AgentToolCall::new("c1", "t", serde_json::json!({})));
    c.add_tool_result(AgentToolResult::success("c1", "t", serde_json::json!({}), 10));
    assert_eq!(c.tool_calls.len(), 1);
    assert_eq!(c.tool_results.len(), 1);
}

// ─── AgentSession ────────────────────────────────────────────────────────────

#[test]
fn session_state_machine_active_to_complete() {
    let mut s = AgentSession::new("s");
    assert!(s.is_active());
    s.complete();
    assert!(!s.is_active());
    assert_eq!(s.status, SessionStatus::Completed);
}

#[test]
fn session_state_machine_active_to_failed() {
    let mut s = AgentSession::new("s");
    s.fail("boom");
    if let SessionStatus::Failed(reason) = &s.status {
        assert_eq!(reason, "boom");
    } else { panic!("wrong status"); }
}

#[test]
fn session_add_observation_plan_reasoning() {
    let mut s = AgentSession::new("s");
    s.add_observation(AgentObservation::new(ObservationKind::Anomaly, "x", 0.5));
    s.add_plan(AgentPlan::new("g"));
    s.add_reasoning(AgentReasoning::new(1));
    assert_eq!(s.observations.len(), 1);
    assert_eq!(s.plans.len(), 1);
    assert_eq!(s.reasoning_chains.len(), 1);
}

// ─── AgentMetrics ────────────────────────────────────────────────────────────

#[test]
fn metrics_zero_rates() {
    let m = AgentMetrics::new();
    assert!(m.success_rate().abs() < 1e-9);
    assert!(m.avg_duration_ms().abs() < 1e-9);
    assert!(m.tool_success_rate().abs() < 1e-9);
}

#[test]
fn metrics_overflow_safe_large_inputs() {
    let mut m = AgentMetrics::new();
    for _ in 0..1000 {
        m.record_success(100, 50);
    }
    assert_eq!(m.tasks_completed, 1000);
    assert_eq!(m.total_duration_ms, 100_000);
    assert!((m.success_rate() - 1.0).abs() < 1e-9);
}

// ─── AgentRateLimiter ────────────────────────────────────────────────────────

#[test]
fn rate_limiter_zero_capacity_blocks_all() {
    let rl = AgentRateLimiter::new(0, 0);
    assert!(!rl.try_acquire(1));
}

#[test]
fn rate_limiter_acquire_more_than_capacity_fails() {
    let rl = AgentRateLimiter::new(5, 0);
    assert!(!rl.try_acquire(6));
}

#[test]
fn rate_limiter_threaded_stress() {
    let rl = Arc::new(AgentRateLimiter::new(1000, 0));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let rl = Arc::clone(&rl);
        handles.push(std::thread::spawn(move || {
            let mut taken = 0;
            for _ in 0..100 {
                if rl.try_acquire(1) { taken += 1; }
            }
            taken
        }));
    }
    let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total <= 1000);
    assert!(total >= 400 - 1); // most attempts succeed since cap=1000
}

// ─── AgentPromptGenerator ────────────────────────────────────────────────────

#[test]
fn prompt_generator_safe_truncate_utf8_no_panic() {
    let pg = AgentPromptGenerator::new("sys", 5);
    // 4-byte multi-byte chars to stress safe_truncate boundary
    let s = "héllo wörld 🎉🎉🎉";
    let p = pg.disassembly_prompt(s, "x86");
    // Just must not panic
    assert!(p.contains("sys"));
}

#[test]
fn prompt_generator_truncate_boundary_fuzz() {
    let mut lcg = Lcg::new(0xBEEF);
    for _ in 0..20 {
        let len = (lcg.next() % 64) as usize;
        let limit = (lcg.next() % 32) as usize;
        let s: String = (0..len).map(|i| if i % 3 == 0 { 'é' } else { 'a' }).collect();
        let pg = AgentPromptGenerator::new("p", limit);
        let _ = pg.disassembly_prompt(&s, "x");
        let _ = pg.vuln_analysis_prompt(&s);
        let _ = pg.rename_prompt(&s);
    }
}

#[test]
fn prompt_generator_yara_and_malware() {
    let pg = AgentPromptGenerator::new("sys", 100);
    let y = pg.yara_prompt(&["a".into(), "b".into()], &["imp".into()]);
    assert!(y.contains("a, b"));
    assert!(y.contains("imp"));
    let m = pg.malware_prompt("does X", &["1.2.3.4".into()]);
    assert!(m.contains("does X"));
    assert!(m.contains("1.2.3.4"));
}

// ─── AgentResponseParser ─────────────────────────────────────────────────────

#[test]
fn response_parser_no_json_errors() {
    let r = AgentResponseParser::extract_json("no json here");
    assert!(matches!(r, Err(AgentError::ParseError(_))));
}

#[test]
fn response_parser_fuzz_never_panics() {
    let mut lcg = Lcg::new(0xCAFE);
    for _ in 0..50 {
        let len = (lcg.next() % 200) as usize;
        let s: String = (0..len).map(|_| {
            let c = (lcg.next() % 128) as u8;
            c as char
        }).collect();
        let _ = AgentResponseParser::extract_json(&s);
        let _ = AgentResponseParser::parse_renames(&s);
        let _ = AgentResponseParser::parse_vulnerabilities(&s);
        let _ = AgentResponseParser::parse_confidence(&s);
    }
}

#[test]
fn response_parser_confidence_default_when_missing() {
    let c = AgentResponseParser::parse_confidence("nothing here");
    assert!((c - 0.5).abs() < 1e-9);
}

#[test]
fn response_parser_confidence_unit_interval() {
    let c = AgentResponseParser::parse_confidence("score 0.42");
    assert!((c - 0.42).abs() < 0.01);
}

#[test]
fn response_parser_renames_non_object_errors() {
    let r = AgentResponseParser::parse_renames(r"[1,2,3]");
    assert!(r.is_err());
}

#[test]
fn response_parser_extract_json_code_fence_unterminated() {
    // start fence but no end → falls through to bare {} search or err
    let r = AgentResponseParser::extract_json("```json\n{\"a\":1");
    // Bare json search finds `{` and `}` of `{"a":1`? rfind '}' would be None → err.
    assert!(r.is_err());
}

// ─── AgentSelfImprovement ────────────────────────────────────────────────────

#[test]
fn self_improvement_rating_clamped() {
    let si = AgentSelfImprovement::new();
    si.record_feedback(1, "r", 100, "");
    si.record_feedback(2, "r", -100, "");
    assert_eq!(si.feedback_count(), 2);
    // ratings clamped to [-5, 5]; average should be 0
    assert!((si.average_rating() - 0.0).abs() < 1e-9);
}

#[test]
fn self_improvement_empty_avg_zero() {
    let si = AgentSelfImprovement::new();
    assert!(si.average_rating().abs() < 1e-9);
}

#[test]
fn self_improvement_threaded() {
    let si = Arc::new(AgentSelfImprovement::new());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let si = Arc::clone(&si);
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                si.record_feedback(tid * 100 + i, "r", (i % 5) as i8, "c");
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(si.feedback_count(), 400);
}

// ─── AgentPluginRegistry ─────────────────────────────────────────────────────

struct DummyPlugin;
impl AgentPlugin for DummyPlugin {
    fn plugin_name(&self) -> &'static str { "dummy" }
    fn plugin_version(&self) -> &'static str { "1.0" }
    fn supports_capability(&self, c: &ExtendedCapability) -> bool {
        matches!(c, ExtendedCapability::Analyze)
    }
    fn execute(&self, _t: &AgentTask, _c: &AgentContext) -> Result<AgentOutput, AgentError> {
        Ok(AgentOutput::simple("ok", 1.0))
    }
}

#[test]
fn plugin_registry_register_find() {
    let reg = AgentPluginRegistry::new();
    reg.register(Arc::new(DummyPlugin));
    assert_eq!(reg.plugin_count(), 1);
    assert!(reg.find_for_capability(&ExtendedCapability::Analyze).is_some());
    assert!(reg.find_for_capability(&ExtendedCapability::Disassemble).is_none());
    assert_eq!(reg.plugin_names(), vec!["dummy".to_string()]);
}

// ─── AgentRegistry (spec) ────────────────────────────────────────────────────

fn make_spec_info(id: u64) -> AgentInfo {
    AgentInfo {
        id: AgentId::new(id),
        name: format!("a-{id}"),
        capabilities: vec![SpecAgentCapability::Analyze],
        status: AgentStatus::Idle,
    }
}

#[test]
fn agent_registry_50_inserts() {
    let reg = AgentRegistry::new();
    let mut lcg = Lcg::new(123);
    let mut seen = std::collections::HashSet::new();
    let mut inserted = 0;
    for _ in 0..50 {
        let id = lcg.next();
        if seen.insert(id) {
            reg.register(Arc::new(MockAgent::new(make_spec_info(id))));
            inserted += 1;
        }
    }
    assert_eq!(reg.count(), inserted);
    assert_eq!(reg.list_ids().len(), inserted);
}

// ─── Confidence clamping for AgentOutput ─────────────────────────────────────

#[test]
fn agent_output_confidence_clamp_fuzz_50() {
    let mut lcg = Lcg::new(0xAA);
    for _ in 0..50 {
        let raw = (rustre_agent::casts::u64_to_f32(lcg.next()) / rustre_agent::casts::u64_to_f32(u64::from(u32::MAX))).mul_add(4.0, -2.0);
        let o = AgentOutput::simple("r", raw);
        assert!(o.confidence >= 0.0 && o.confidence <= 1.0);
    }
}

// ─── AgentInput chained context ─────────────────────────────────────────────

#[test]
fn agent_input_chained_context_preserves_all() {
    let mut input = AgentInput::simple("t");
    for i in 0..30 {
        input = input.with_context(format!("k{i}"), serde_json::json!(i));
    }
    assert_eq!(input.context.len(), 30);
    for i in 0..30 {
        assert_eq!(input.context[&format!("k{i}")], serde_json::json!(i));
    }
}

// ─── Artifact roundtrip ──────────────────────────────────────────────────────

#[test]
fn artifact_text_roundtrip_50() {
    let mut lcg = Lcg::new(0xABBA);
    for _ in 0..50 {
        let n = (lcg.next() % 32) as usize;
        let content: String = (0..n).map(|_| (b'a' + (lcg.next() % 26) as u8) as char).collect();
        let art = Artifact::text("n.txt", ArtifactType::Report, content.clone());
        assert_eq!(art.as_text().unwrap(), content);
    }
}

#[test]
fn artifact_invalid_utf8_errors() {
    let art = Artifact {
        name: "x".to_string(),
        ty: ArtifactType::Report,
        data: vec![0xFF, 0xFE, 0xFD],
    };
    assert!(art.as_text().is_err());
}

// ─── Serde roundtrip on actions/patches ──────────────────────────────────────

#[test]
fn action_serde_roundtrip_all_variants() {
    let actions = vec![
        AgentAction::RenameSymbol { addr: 0x100, name: "foo".to_string() },
        AgentAction::AddComment { addr: 0x200, comment: "c".to_string() },
        AgentAction::ApplyType { addr: 0x300, ty: "int".to_string() },
        AgentAction::CreateBookmark { addr: 0x400, name: "b".to_string() },
        AgentAction::RunScript { code: "print(1)".to_string(), engine: "python".to_string() },
        AgentAction::ApplyPatch(Patch {
            address: 0x500, original: vec![0x90], patched: vec![0xCC], description: "d".to_string(),
        }),
    ];
    for a in &actions {
        let s = serde_json::to_string(a).unwrap();
        let _: AgentAction = serde_json::from_str(&s).unwrap();
    }
}

#[test]
fn patch_serde_roundtrip_boundary_addresses() {
    for addr in [0u64, 1, u64::MAX - 1, u64::MAX] {
        let p = Patch { address: addr, original: vec![], patched: vec![1,2,3], description: "x".into() };
        let s = serde_json::to_string(&p).unwrap();
        let back: Patch = serde_json::from_str(&s).unwrap();
        assert_eq!(back.address, addr);
        assert_eq!(back.patched, vec![1,2,3]);
    }
}

// ─── Orchestrator routing edge cases ─────────────────────────────────────────

#[tokio::test]
async fn orchestrator_get_config_missing() {
    let orch = AgentOrchestrator::new();
    assert!(orch.get_config("ghost").is_none());
}

#[tokio::test]
async fn orchestrator_route_empty_caps_picks_first() {
    let orch = AgentOrchestrator::new();
    orch.register(Box::new(NoOpAgent::new("a", vec![])), AgentConfig::default())
        .await.unwrap();
    let ctx = AgentContext::new(None, "x", "l");
    let out = orch.route(&[], AgentInput::simple("t"), &ctx).await.unwrap();
    assert!(out.result.contains('t'));
}

// ─── DisasmAgent / VulnAgent behavior ─────────────────────────────────────────

#[tokio::test]
async fn disasm_agent_empty_task_no_panic() {
    let agent = DisasmAgent::new();
    let input = AgentInput::simple("");
    let ctx = AgentContext::default();
    let out = agent.process(input, &ctx).await.unwrap();
    assert!(out.result.contains("disasm-agent"));
}

#[tokio::test]
async fn vuln_agent_fuzz_inputs_never_panic() {
    let agent = VulnAgent::new();
    let mut lcg = Lcg::new(0xFADE);
    let ctx = AgentContext::default();
    for _ in 0..30 {
        let n = (lcg.next() % 200) as usize;
        let s: String = (0..n).map(|_| (b' ' + (lcg.next() % 90) as u8) as char).collect();
        let input = AgentInput::simple(s);
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.confidence >= 0.0 && out.confidence <= 1.0);
    }
}

#[tokio::test]
async fn vuln_agent_confidence_bounded() {
    let agent = VulnAgent::new();
    let input = AgentInput::simple("gets(buf) strcpy(a,b) sprintf(x,y) system(z) printf(p)");
    let ctx = AgentContext::default();
    let out = agent.process(input, &ctx).await.unwrap();
    assert!(out.confidence > 0.0 && out.confidence <= 1.0);
}

// ─── MemoryEntry tags ────────────────────────────────────────────────────────

#[test]
fn memory_entry_with_tags() {
    let e = MemoryEntry::new("k", serde_json::json!(1))
        .with_tags(vec!["a".into(), "b".into()]);
    assert_eq!(e.tags.len(), 2);
}

// ─── AgentToolResult serde ───────────────────────────────────────────────────

#[test]
fn tool_result_serde_roundtrip() {
    let r = AgentToolResult::failure("c", "t", "err");
    let s = serde_json::to_string(&r).unwrap();
    let back: AgentToolResult = serde_json::from_str(&s).unwrap();
    assert!(!back.success);
    assert_eq!(back.error.as_deref(), Some("err"));
}

// ─── PathBuf in AgentContext ─────────────────────────────────────────────────

#[test]
fn agent_context_with_path_serde() {
    let ctx = AgentContext::new(Some(PathBuf::from("/a/b")), "arm", "linux");
    let s = serde_json::to_string(&ctx).unwrap();
    let back: AgentContext = serde_json::from_str(&s).unwrap();
    assert_eq!(back.architecture, "arm");
    assert_eq!(back.binary_path, Some(PathBuf::from("/a/b")));
}

// ─── Default impls ───────────────────────────────────────────────────────────

#[test]
fn default_impls_smoke() {
    let _ = AgentOrchestrator::default();
    let _ = AgentTaskQueue::default();
    let _ = AgentRegistry::default();
    let _ = AgentPluginRegistry::default();
    let _ = AgentSelfImprovement::default();
    let _ = DisasmAgent::default();
    let _ = VulnAgent::default();
    let _ = AgentContext::default();
    let _ = AgentMetrics::default();
}
