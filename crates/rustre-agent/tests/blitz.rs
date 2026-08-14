//! Blitz tests for rustre-agent — focus on `reasoning_engine` public surface.

use rustre_agent::reasoning_engine::{
    shannon_entropy, Confidence, ContradictionDetector, Evidence, EvidenceCollector, EvidenceKind,
    ExportFormat, Hypothesis, HypothesisStatus, ReasoningCache, ReasoningChain, ReasoningEngine,
    ReasoningEngineConfig, ReasoningError, ReasoningExport, ReasoningStep, StepKind, SubTask,
    TaskDecomposer,
};

// ─── Confidence ───────────────────────────────────────────────────────────────

#[test]
fn confidence_new_clamps_high() {
    assert!((Confidence::new(2.0).value() - 1.0).abs() < 1e-9);
}

#[test]
fn confidence_new_clamps_low() {
    assert!(Confidence::new(-1.0).value().abs() < 1e-9);
}

#[test]
fn confidence_new_passthrough() {
    assert!((Confidence::new(0.42).value() - 0.42).abs() < 1e-9);
}

#[test]
fn confidence_default_is_half() {
    assert!((Confidence::default().value() - 0.5).abs() < 1e-9);
}

#[test]
fn confidence_at_least() {
    assert!(Confidence::new(0.7).at_least(0.5));
    assert!(!Confidence::new(0.3).at_least(0.5));
    assert!(Confidence::new(0.5).at_least(0.5));
}

#[test]
fn confidence_and_product() {
    let a = Confidence::new(0.5);
    let b = Confidence::new(0.5);
    let r = a.and(b);
    assert!((r.value() - 0.25).abs() < 1e-9);
}

#[test]
fn confidence_or_probabilistic() {
    let a = Confidence::new(0.5);
    let b = Confidence::new(0.5);
    let r = a.or(b);
    // 0.5 + 0.5 - 0.25 = 0.75
    assert!((r.value() - 0.75).abs() < 1e-9);
}

#[test]
fn confidence_display_format() {
    let c = Confidence::new(0.875);
    let s = c.to_string();
    assert!(s.contains("87.5"));
    assert!(s.ends_with('%'));
}

#[test]
fn confidence_or_with_zero() {
    let a = Confidence::new(0.0);
    let b = Confidence::new(0.8);
    let r = a.or(b);
    assert!((r.value() - 0.8).abs() < 1e-9);
}

#[test]
fn confidence_and_with_one() {
    let r = Confidence::new(1.0).and(Confidence::new(0.6));
    assert!((r.value() - 0.6).abs() < 1e-9);
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

#[test]
fn evidence_weight_clamped_high() {
    let e = Evidence::new("e1", "desc", EvidenceKind::Disassembly, 5.0);
    assert!((e.weight - 1.0).abs() < 1e-9);
}

#[test]
fn evidence_weight_clamped_low() {
    let e = Evidence::new("e1", "d", EvidenceKind::Disassembly, -10.0);
    assert!((e.weight + 1.0).abs() < 1e-9);
}

#[test]
fn evidence_is_supportive() {
    let e = Evidence::new("e", "d", EvidenceKind::StringLiteral, 0.5);
    assert!(e.is_supportive());
    assert!(!e.is_contradictory());
}

#[test]
fn evidence_is_contradictory() {
    let e = Evidence::new("e", "d", EvidenceKind::StringLiteral, -0.5);
    assert!(e.is_contradictory());
    assert!(!e.is_supportive());
}

#[test]
fn evidence_zero_weight_is_neither() {
    let e = Evidence::new("e", "d", EvidenceKind::Symbol, 0.0);
    assert!(!e.is_supportive());
    assert!(!e.is_contradictory());
}

#[test]
fn evidence_with_address_and_payload() {
    let e = Evidence::new("e", "d", EvidenceKind::Symbol, 0.3)
        .at_address(0xDEAD_BEEF)
        .with_payload("payload");
    assert_eq!(e.address, Some(0xDEAD_BEEF));
    assert_eq!(e.payload.as_deref(), Some("payload"));
}

// ─── shannon_entropy ──────────────────────────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert!(shannon_entropy(&[]).abs() < 1e-9);
}

#[test]
fn entropy_uniform_byte_is_zero() {
    assert!(shannon_entropy(&[0xAA; 1024]).abs() < 1e-9);
}

#[test]
fn entropy_uniform_distribution_near_8() {
    let data: Vec<u8> = (0..=255).collect();
    let e = shannon_entropy(&data);
    assert!((e - 8.0).abs() < 1e-9, "expected ~8.0, got {e}");
}

#[test]
fn entropy_two_balanced_symbols_is_one() {
    let mut data = vec![0u8; 500];
    data.extend(vec![1u8; 500]);
    let e = shannon_entropy(&data);
    assert!((e - 1.0).abs() < 1e-9);
}

// ─── Hypothesis ───────────────────────────────────────────────────────────────

#[test]
fn hypothesis_initial_state() {
    let h = Hypothesis::new("h1", "claim");
    assert_eq!(h.status, HypothesisStatus::Pending);
    assert!((h.confidence.value() - 0.5).abs() < 1e-9);
    assert!(h.evidence.is_empty());
}

#[test]
fn hypothesis_tag_and_parent() {
    let h = Hypothesis::new("h", "c")
        .tag("crypto")
        .with_parent("parent-h");
    assert_eq!(h.tags, vec!["crypto"]);
    assert_eq!(h.parent_id.as_deref(), Some("parent-h"));
}

#[test]
fn hypothesis_confirmed_after_strong_positive_evidence() {
    let mut h = Hypothesis::new("h", "is AES");
    for i in 0..5 {
        h.add_evidence(Evidence::new(
            format!("e{i}"),
            "d",
            EvidenceKind::CryptographicConstant,
            1.0,
        ));
    }
    // start 0.5 + 5 * 0.15 = 1.25 -> clamped to 1.0 -> >= 0.75
    assert_eq!(h.status, HypothesisStatus::Confirmed);
    assert!(h.confidence.value() >= 0.75);
}

#[test]
fn hypothesis_refuted_after_strong_negative_evidence() {
    let mut h = Hypothesis::new("h", "is malware");
    for i in 0..5 {
        h.add_evidence(Evidence::new(
            format!("e{i}"),
            "d",
            EvidenceKind::Symbol,
            -1.0,
        ));
    }
    assert_eq!(h.status, HypothesisStatus::Refuted);
    assert!(h.confidence.value() <= 0.25);
}

#[test]
fn hypothesis_empty_evidence_recalc_resets_to_default() {
    let mut h = Hypothesis::new("h", "c");
    h.recalculate_confidence();
    assert!((h.confidence.value() - 0.5).abs() < 1e-9);
}

#[test]
fn hypothesis_support_and_contradiction_weights() {
    let mut h = Hypothesis::new("h", "c");
    h.add_evidence(Evidence::new("e1", "d", EvidenceKind::Symbol, 0.8));
    h.add_evidence(Evidence::new("e2", "d", EvidenceKind::Symbol, 0.4));
    h.add_evidence(Evidence::new("e3", "d", EvidenceKind::Symbol, -0.6));
    assert!((h.support_weight() - 1.2).abs() < 1e-9);
    assert!((h.contradiction_weight() - 0.6).abs() < 1e-9);
}

// ─── EvidenceCollector ────────────────────────────────────────────────────────

#[test]
fn collector_empty_no_entropy_evidence() {
    let mut c = EvidenceCollector::new();
    let evs = c.collect_entropy_evidence(&[1, 2, 3], 64);
    assert!(evs.is_empty());
}

#[test]
fn collector_detects_high_entropy() {
    let mut c = EvidenceCollector::new();
    let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let evs = c.collect_entropy_evidence(&data, 256);
    assert!(!evs.is_empty(), "expected high-entropy detection");
}

#[test]
fn collector_low_entropy_no_findings() {
    let mut c = EvidenceCollector::new();
    let evs = c.collect_entropy_evidence(&vec![0u8; 1024], 256);
    assert!(evs.is_empty());
}

#[test]
fn collector_crypto_constants_md5() {
    let mut c = EvidenceCollector::new();
    // 0x67452301 little-endian
    let bytes = [0x01, 0x23, 0x45, 0x67];
    let evs = c.collect_crypto_constants(&bytes);
    assert_eq!(evs.len(), 1);
}

#[test]
fn collector_crypto_constants_none() {
    let mut c = EvidenceCollector::new();
    let evs = c.collect_crypto_constants(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(evs.is_empty());
}

#[test]
fn collector_drain_consumes() {
    let mut c = EvidenceCollector::new();
    c.add(Evidence::new("x", "d", EvidenceKind::Symbol, 0.1));
    assert_eq!(c.peek().len(), 1);
    let d = c.drain();
    assert_eq!(d.len(), 1);
    assert_eq!(c.peek().len(), 0);
}

// ─── ContradictionDetector ────────────────────────────────────────────────────

#[test]
fn contradiction_detects_32_vs_64() {
    let detector = ContradictionDetector::new();
    let mut a = Hypothesis::new("a", "32-bit binary").tag("32-bit");
    let mut b = Hypothesis::new("b", "64-bit binary").tag("64-bit");
    // Force Confirmed status.
    for _ in 0..5 {
        a.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
        b.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
    }
    let cs = detector.detect(&[a, b]);
    assert_eq!(cs.len(), 1);
}

#[test]
fn contradiction_ignores_pending_hypotheses() {
    let detector = ContradictionDetector::new();
    let a = Hypothesis::new("a", "x").tag("32-bit");
    let b = Hypothesis::new("b", "y").tag("64-bit");
    // Both are Pending, no evidence -> should NOT be detected.
    let cs = detector.detect(&[a, b]);
    assert!(cs.is_empty());
}

#[test]
fn contradiction_custom_rule() {
    let mut detector = ContradictionDetector::new();
    detector.add_exclusion_rule("foo", "bar");
    let mut a = Hypothesis::new("a", "x").tag("foo");
    let mut b = Hypothesis::new("b", "y").tag("bar");
    for _ in 0..5 {
        a.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
        b.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
    }
    assert_eq!(detector.detect(&[a, b]).len(), 1);
}

// ─── ReasoningChain ───────────────────────────────────────────────────────────

#[test]
fn chain_new_empty() {
    let c = ReasoningChain::new("t");
    assert_eq!(c.title, "t");
    assert!(c.steps.is_empty());
    assert!(c.hypotheses.is_empty());
}

#[test]
fn chain_add_hypothesis_logs_step() {
    let mut c = ReasoningChain::new("t");
    c.add_hypothesis(Hypothesis::new("h1", "claim"));
    assert_eq!(c.steps.len(), 1);
    assert_eq!(c.steps[0].kind, StepKind::FormulateHypothesis);
    assert_eq!(c.hypotheses.len(), 1);
}

#[test]
fn chain_update_unknown_hypothesis_errors() {
    let mut c = ReasoningChain::new("t");
    let r = c.update_hypothesis("nonexistent", vec![]);
    assert!(matches!(r, Err(ReasoningError::HypothesisNotFound(_))));
}

#[test]
fn chain_update_with_evidence() {
    let mut c = ReasoningChain::new("t");
    c.add_hypothesis(Hypothesis::new("h1", "claim"));
    let r = c.update_hypothesis(
        "h1",
        vec![Evidence::new("e1", "d", EvidenceKind::Symbol, 0.5)],
    );
    assert!(r.is_ok());
    assert_eq!(c.steps.len(), 2);
    assert_eq!(c.steps[1].kind, StepKind::TestHypothesis);
    assert_eq!(c.steps[1].evidence_ids, vec!["e1"]);
}

#[test]
fn chain_conclude_adds_step() {
    let mut c = ReasoningChain::new("t");
    c.conclude("final");
    assert_eq!(c.conclusion.as_deref(), Some("final"));
    assert_eq!(c.steps.last().unwrap().kind, StepKind::Conclude);
}

#[test]
fn chain_confirmed_sorted() {
    let mut c = ReasoningChain::new("t");
    let mut h1 = Hypothesis::new("h1", "c1");
    let mut h2 = Hypothesis::new("h2", "c2");
    for _ in 0..5 {
        h1.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
        h2.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
    }
    c.add_hypothesis(h1);
    c.add_hypothesis(h2);
    let confirmed = c.confirmed_hypotheses();
    assert_eq!(confirmed.len(), 2);
}

#[test]
fn chain_top_hypothesis_picks_highest() {
    let mut c = ReasoningChain::new("t");
    let mut h1 = Hypothesis::new("low", "c");
    h1.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, -0.5));
    let mut h2 = Hypothesis::new("high", "c");
    for _ in 0..3 {
        h2.add_evidence(Evidence::new("e", "d", EvidenceKind::Symbol, 1.0));
    }
    c.add_hypothesis(h1);
    c.add_hypothesis(h2);
    let top = c.top_hypothesis().unwrap();
    assert_eq!(top.id, "high");
}

// ─── TaskDecomposer ───────────────────────────────────────────────────────────

#[test]
fn decompose_malware_emits_subtasks() {
    let d = TaskDecomposer::new();
    let tasks = d.decompose("Analyze this malware sample").unwrap();
    assert!(!tasks.is_empty());
    // sorted descending by priority
    for w in tasks.windows(2) {
        assert!(w[0].priority >= w[1].priority);
    }
}

#[test]
fn decompose_crypto_branch() {
    let tasks = TaskDecomposer::new().decompose("crypto analysis").unwrap();
    assert!(tasks.iter().any(|t| t.description.contains("crypto")));
}

#[test]
fn decompose_unknown_uses_fallback() {
    let tasks = TaskDecomposer::new()
        .decompose("just look at this random thing")
        .unwrap();
    assert_eq!(tasks.len(), 4);
}

#[test]
fn subtask_difficulty_capped() {
    let s = SubTask::new("s", "desc", 99, 99);
    assert_eq!(s.difficulty, 10);
    assert_eq!(s.priority, 10);
}

// ─── ReasoningCache ───────────────────────────────────────────────────────────

#[test]
fn cache_insert_and_get() {
    let mut c = ReasoningCache::with_capacity(2);
    c.insert("k1", ReasoningChain::new("t1"));
    assert_eq!(c.len(), 1);
    let got = c.get("k1");
    assert!(got.is_some());
    assert_eq!(c.total_hits(), 1);
}

#[test]
fn cache_evicts_lru() {
    let mut c = ReasoningCache::with_capacity(2);
    c.insert("a", ReasoningChain::new("a"));
    c.insert("b", ReasoningChain::new("b"));
    c.insert("c", ReasoningChain::new("c")); // should evict "a"
    assert!(c.get("a").is_none());
    assert!(c.get("b").is_some());
    assert!(c.get("c").is_some());
    assert_eq!(c.len(), 2);
}

#[test]
fn cache_clear() {
    let mut c = ReasoningCache::with_capacity(5);
    c.insert("k", ReasoningChain::new("t"));
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn cache_entry_age_for_missing_is_none() {
    let c = ReasoningCache::with_capacity(2);
    assert!(c.entry_age("nope").is_none());
}

#[test]
fn cache_oldest_age_empty_is_none() {
    let c = ReasoningCache::with_capacity(2);
    assert!(c.oldest_entry_age().is_none());
}

// ─── ReasoningExport ──────────────────────────────────────────────────────────

#[test]
fn export_json_roundtrip() {
    let mut chain = ReasoningChain::new("test");
    chain.add_hypothesis(Hypothesis::new("h1", "claim"));
    let s = ReasoningExport::export(&chain, ExportFormat::Json).unwrap();
    assert!(s.contains("h1"));
    let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed["title"], "test");
}

#[test]
fn export_markdown_contains_sections() {
    let mut chain = ReasoningChain::new("MyChain");
    chain.add_hypothesis(Hypothesis::new("h", "claim"));
    chain.conclude("done");
    let md = ReasoningExport::export(&chain, ExportFormat::Markdown).unwrap();
    assert!(md.contains("# Reasoning Chain: MyChain"));
    assert!(md.contains("## Steps"));
    assert!(md.contains("## Hypotheses"));
    assert!(md.contains("## Conclusion"));
}

#[test]
fn export_plain_text() {
    let mut chain = ReasoningChain::new("PT");
    chain.conclude("c");
    let pt = ReasoningExport::export(&chain, ExportFormat::PlainText).unwrap();
    assert!(pt.contains("REASONING CHAIN: PT"));
    assert!(pt.contains("CONCLUSION: c"));
}

// ─── ReasoningEngine ──────────────────────────────────────────────────────────

#[test]
fn engine_default_config() {
    let cfg = ReasoningEngineConfig::default();
    assert!(cfg.confirmation_threshold > cfg.refutation_threshold);
}

#[test]
fn engine_start_chain() {
    let e = ReasoningEngine::new();
    let c = e.start_chain("goal");
    assert_eq!(c.title, "goal");
}

#[test]
fn engine_add_hypothesis_via_engine() {
    let e = ReasoningEngine::new();
    let mut chain = e.start_chain("g");
    e.add_hypothesis(&mut chain, Hypothesis::new("h", "c"));
    assert_eq!(chain.hypotheses.len(), 1);
}

#[test]
fn engine_collect_and_attach_unknown_errors() {
    let e = ReasoningEngine::new();
    let mut chain = e.start_chain("g");
    let r = e.collect_and_attach(&mut chain, "nope", vec![]);
    assert!(matches!(r, Err(ReasoningError::HypothesisNotFound(_))));
}

#[test]
fn engine_collect_and_attach_ok() {
    let e = ReasoningEngine::new();
    let mut chain = e.start_chain("g");
    e.add_hypothesis(&mut chain, Hypothesis::new("h", "c"));
    let r = e.collect_and_attach(
        &mut chain,
        "h",
        vec![Evidence::new("e", "d", EvidenceKind::Symbol, 0.5)],
    );
    assert!(r.is_ok());
    assert!(!chain.hypotheses["h"].evidence.is_empty());
}

#[test]
fn engine_decompose_goal_malware() {
    let e = ReasoningEngine::new();
    let tasks = e.decompose_goal("malware analysis").unwrap();
    assert!(!tasks.is_empty());
}

// ─── ReasoningError ───────────────────────────────────────────────────────────

#[test]
fn reasoning_error_display() {
    let e = ReasoningError::HypothesisNotFound("foo".into());
    assert!(e.to_string().contains("foo"));
    let e2 = ReasoningError::InvalidState("bad".into());
    assert!(e2.to_string().contains("bad"));
    let e3 = ReasoningError::SerdeError("s".into());
    assert!(e3.to_string().contains("serde"));
    let e4 = ReasoningError::CacheError("c".into());
    assert!(e4.to_string().contains("cache"));
    let e5 = ReasoningError::DecompositionError("d".into());
    assert!(e5.to_string().contains("decomposition"));
}

// ─── ReasoningStep ────────────────────────────────────────────────────────────

#[test]
fn reasoning_step_new_defaults() {
    let s = ReasoningStep::new(0, StepKind::CollectEvidence, "x");
    assert_eq!(s.index, 0);
    assert!(s.hypothesis_id.is_none());
    assert!(s.evidence_ids.is_empty());
    assert!(s.confidence_after.is_none());
}
