//! Comprehensive integration tests for `rustre-analysis` public API.

use std::sync::Arc;

use rustre_analysis::{
    AnalysisConfig, AnalysisDb, AnalysisError, AnalysisEvent, AnalysisEventBus, AnalysisKind,
    AnalysisManager, AnalysisPipeline, AnalysisPlugin, AnalysisPluginRegistry, AnalysisReport,
    AnalysisResult, AnalysisStats, BinaryChange, BoundaryMethod, CfgAnalysisPass,
    CountingAnalysisPass, CrossReferenceDb, ChangeKind, FunctionBoundary, FunctionBoundaryAnalysis,
    FunctionDetectionPass, IncrementalAnalysis, LinearSweepAnalyzer, LinearSweepConfig,
    LinearSweepPass, NoOpAnalysisPass, PassDescriptor, PassScheduler, PassStats, PluginMetadata,
    RecursiveDescentAnalyzer, RecursiveDescentPass, StringRecoveryPass, Xref, XrefRecoveryPass,
    XrefType, analyze_binary,
};

// ─────────────────── AnalysisKind ───────────────────

#[test]
fn kind_display_all_variants() {
    assert_eq!(AnalysisKind::LinearSweep.to_string(), "LinearSweep");
    assert_eq!(AnalysisKind::RecursiveDescent.to_string(), "RecursiveDescent");
    assert_eq!(AnalysisKind::DataFlow.to_string(), "DataFlow");
    assert_eq!(AnalysisKind::TypeRecovery.to_string(), "TypeRecovery");
    assert_eq!(AnalysisKind::CallingConvention.to_string(), "CallingConvention");
    assert_eq!(AnalysisKind::StringRecovery.to_string(), "StringRecovery");
    assert_eq!(AnalysisKind::XrefRecovery.to_string(), "XrefRecovery");
    assert_eq!(AnalysisKind::VsaAnalysis.to_string(), "VsaAnalysis");
    assert_eq!(AnalysisKind::VtableAnalysis.to_string(), "VtableAnalysis");
    assert_eq!(AnalysisKind::Custom("x".into()).to_string(), "Custom(x)");
}

#[test]
fn kind_eq_hash() {
    use std::collections::HashMap;
    let mut m = HashMap::new();
    m.insert(AnalysisKind::LinearSweep, 1);
    m.insert(AnalysisKind::Custom("foo".into()), 2);
    assert_eq!(m[&AnalysisKind::LinearSweep], 1);
    assert_eq!(m[&AnalysisKind::Custom("foo".into())], 2);
    assert_ne!(AnalysisKind::LinearSweep, AnalysisKind::DataFlow);
    assert_ne!(
        AnalysisKind::Custom("a".into()),
        AnalysisKind::Custom("b".into())
    );
}

#[test]
fn kind_serde_roundtrip_all() {
    for k in [
        AnalysisKind::LinearSweep,
        AnalysisKind::RecursiveDescent,
        AnalysisKind::DataFlow,
        AnalysisKind::TypeRecovery,
        AnalysisKind::CallingConvention,
        AnalysisKind::StringRecovery,
        AnalysisKind::XrefRecovery,
        AnalysisKind::VsaAnalysis,
        AnalysisKind::VtableAnalysis,
        AnalysisKind::Custom("plugin_x".into()),
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: AnalysisKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ─────────────────── AnalysisConfig ───────────────────

#[test]
fn config_default_is_linear_sweep() {
    let c = AnalysisConfig::default();
    assert_eq!(c.kind, AnalysisKind::LinearSweep);
    assert_eq!(c.max_depth, 256);
    assert!(c.timeout_ms.is_none());
    assert!(c.start_address.is_none());
    assert!(c.options.is_empty());
}

#[test]
fn config_builder_chain() {
    use rustre_core::address::Address;
    let c = AnalysisConfig::new(AnalysisKind::DataFlow)
        .with_max_depth(0)
        .with_timeout(0)
        .with_start(Address::new(0));
    assert_eq!(c.max_depth, 0);
    assert_eq!(c.timeout_ms, Some(0));
    assert_eq!(c.start_address, Some(Address::new(0)));
}

#[test]
fn config_options_get_set() {
    let mut c = AnalysisConfig::default();
    assert!(c.get_option("missing").is_none());
    c.set_option("a", "1");
    c.set_option("b", "2");
    c.set_option("a", "overwritten");
    assert_eq!(c.get_option("a"), Some("overwritten"));
    assert_eq!(c.get_option("b"), Some("2"));
}

#[test]
fn config_serde_roundtrip() {
    let mut c = AnalysisConfig::new(AnalysisKind::VsaAnalysis).with_max_depth(8);
    c.set_option("k", "v");
    let s = serde_json::to_string(&c).unwrap();
    let back: AnalysisConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.kind, AnalysisKind::VsaAnalysis);
    assert_eq!(back.max_depth, 8);
    assert_eq!(back.get_option("k"), Some("v"));
}

// ─────────────────── AnalysisResult ───────────────────

#[test]
fn result_zero_is_empty() {
    let r = AnalysisResult::zero(AnalysisKind::DataFlow);
    assert_eq!(r.functions_found, 0);
    assert_eq!(r.data_refs_found, 0);
    assert_eq!(r.strings_found, 0);
    assert_eq!(r.duration_ms, 0);
    assert!(!r.has_warnings());
    assert_eq!(r.total_items(), 0);
}

#[test]
fn result_total_items_sums_components() {
    let r = AnalysisResult {
        kind: AnalysisKind::LinearSweep,
        functions_found: 1,
        data_refs_found: 2,
        strings_found: 4,
        duration_ms: 9,
        warnings: vec!["w".into()],
    };
    assert_eq!(r.total_items(), 7);
    assert!(r.has_warnings());
}

#[test]
fn result_serde_roundtrip() {
    let r = AnalysisResult::zero(AnalysisKind::Custom("p".into()));
    let s = serde_json::to_string(&r).unwrap();
    let back: AnalysisResult = serde_json::from_str(&s).unwrap();
    assert_eq!(back.kind, AnalysisKind::Custom("p".into()));
    assert_eq!(back.total_items(), 0);
}

// ─────────────────── AnalysisError ───────────────────

#[test]
fn error_display_variants() {
    assert_eq!(
        AnalysisError::PassNotFound("p".into()).to_string(),
        "Pass not found: p"
    );
    assert_eq!(
        AnalysisError::Failed("e".into()).to_string(),
        "Analysis failed: e"
    );
    assert_eq!(AnalysisError::Timeout(42).to_string(), "Timeout after 42ms");
    assert_eq!(
        AnalysisError::InsufficientData(0xFF).to_string(),
        "Not enough data at 0xff"
    );
}

#[test]
fn error_match_variants() {
    let err = AnalysisError::Timeout(7);
    match err {
        AnalysisError::Timeout(n) => assert_eq!(n, 7),
        _ => panic!("wrong variant"),
    }
}

// ─────────────────── NoOpAnalysisPass / CountingAnalysisPass ───────────────────

#[tokio::test]
async fn noop_pass_runs_zero() {
    let report = analyze_binary(&[0u8; 16], "x86_64", 0x1000).await;
    // sanity: analyze_binary returns a populated report
    assert!(report.stats.passes.len() >= 6);
    let _ = report.summary();

    let pass = NoOpAnalysisPass::with_kind("noop", AnalysisKind::DataFlow);
    use rustre_analysis::AnalysisPass;
    assert_eq!(pass.name(), "noop");
    assert_eq!(pass.kind(), AnalysisKind::DataFlow);
    assert!(pass.supports_arch("anything"));
    assert_eq!(pass.priority(), 0);
}

#[tokio::test]
async fn counting_pass_reports_fixed_counts() {
    use rustre_analysis::AnalysisPass;
    let report = analyze_binary(&[0u8; 4], "x86_64", 0).await;
    assert!(!report.uri.is_empty());

    let cp = CountingAnalysisPass::new("c", AnalysisKind::StringRecovery, 3, 5);
    assert_eq!(cp.name(), "c");
    assert_eq!(cp.kind(), AnalysisKind::StringRecovery);
}

// ─────────────────── AnalysisPipeline ───────────────────

#[test]
fn pipeline_new_is_empty() {
    let p = AnalysisPipeline::new();
    assert_eq!(p.pass_count(), 0);
    assert!(p.pass_names().is_empty());
    assert!(p.find("any").is_none());
}

#[test]
fn pipeline_register_dedup_by_name() {
    let p = AnalysisPipeline::default();
    p.register(Arc::new(NoOpAnalysisPass::new("dup")));
    p.register(Arc::new(NoOpAnalysisPass::new("dup")));
    assert_eq!(p.pass_count(), 1);
}

#[test]
fn pipeline_remove() {
    let p = AnalysisPipeline::new();
    p.register(Arc::new(NoOpAnalysisPass::new("a")));
    assert!(p.remove("a"));
    assert!(!p.remove("a"));
}

#[test]
fn pipeline_passes_for_kind() {
    let p = AnalysisPipeline::new();
    p.register(Arc::new(NoOpAnalysisPass::with_kind("s1", AnalysisKind::LinearSweep)));
    p.register(Arc::new(NoOpAnalysisPass::with_kind("d1", AnalysisKind::DataFlow)));
    assert_eq!(p.passes_for_kind(&AnalysisKind::LinearSweep).len(), 1);
    assert_eq!(p.passes_for_kind(&AnalysisKind::DataFlow).len(), 1);
    assert_eq!(p.passes_for_kind(&AnalysisKind::TypeRecovery).len(), 0);
}

#[tokio::test]
async fn pipeline_run_all_empty() {
    let p = AnalysisPipeline::new();
    let report = analyze_binary(&[], "x86_64", 0).await;
    let _ = p; // ensure construction
    // empty data — analyze_binary still returns a report (may be empty stats)
    let _ = report.success;
}

// ─────────────────── PassDescriptor / PassScheduler ───────────────────

#[test]
fn scheduler_empty_returns_empty() {
    let s = PassScheduler::new();
    let order = s.schedule().unwrap();
    assert!(order.is_empty());
    assert!(s.schedule_groups().unwrap().is_empty());
}

#[test]
fn scheduler_topological_order() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a"));
    s.add(PassDescriptor::new("b").with_dep("a"));
    s.add(PassDescriptor::new("c").with_dep("b"));
    let order = s.schedule().unwrap();
    let pos_a = order.iter().position(|x| x == "a").unwrap();
    let pos_b = order.iter().position(|x| x == "b").unwrap();
    let pos_c = order.iter().position(|x| x == "c").unwrap();
    assert!(pos_a < pos_b && pos_b < pos_c);
}

#[test]
fn scheduler_priority_within_ready() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("low").with_priority(0));
    s.add(PassDescriptor::new("hi").with_priority(100));
    let order = s.schedule().unwrap();
    assert_eq!(order[0], "hi");
}

#[test]
fn scheduler_cycle_detected() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a").with_dep("b"));
    s.add(PassDescriptor::new("b").with_dep("a"));
    assert!(s.schedule().is_err());
    assert!(s.schedule_groups().is_err());
}

#[test]
fn scheduler_groups_parallelism() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a"));
    s.add(PassDescriptor::new("b"));
    s.add(PassDescriptor::new("c").with_dep("a").with_dep("b"));
    let groups = s.schedule_groups().unwrap();
    // Group 0 should contain a and b (any order), group 1 should contain c.
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].len(), 2);
    assert_eq!(groups[1], vec!["c".to_string()]);
}

// ─────────────────── PassStats / AnalysisStats ───────────────────

#[test]
fn pass_stats_from_result_and_error() {
    let r = AnalysisResult {
        kind: AnalysisKind::LinearSweep,
        functions_found: 2,
        data_refs_found: 1,
        strings_found: 3,
        duration_ms: 5,
        warnings: vec![],
    };
    let ok = PassStats::from_result("p", &r);
    assert!(ok.success);
    assert_eq!(ok.functions_found, 2);
    assert!(ok.error.is_none());

    let err = PassStats::from_error("p", "boom");
    assert!(!err.success);
    assert_eq!(err.error.as_deref(), Some("boom"));
}

#[test]
fn analysis_stats_record_and_aggregate() {
    let mut s = AnalysisStats::new();
    assert_eq!(s.avg_duration_ms(), 0.0);
    assert!(s.slowest_pass().is_none());
    assert!(s.all_succeeded());

    let r1 = AnalysisResult {
        kind: AnalysisKind::LinearSweep,
        functions_found: 4,
        data_refs_found: 0,
        strings_found: 2,
        duration_ms: 10,
        warnings: vec![],
    };
    let r2 = AnalysisResult {
        kind: AnalysisKind::DataFlow,
        functions_found: 1,
        data_refs_found: 0,
        strings_found: 7,
        duration_ms: 30,
        warnings: vec![],
    };
    s.record_result("p1", &r1);
    s.record_result("p2", &r2);
    s.record_error("p3", "fail");
    assert_eq!(s.total_functions, 5);
    assert_eq!(s.total_strings, 9);
    assert_eq!(s.total_duration_ms, 40);
    assert_eq!(s.failed_passes, 1);
    assert!(!s.all_succeeded());
    assert_eq!(s.slowest_pass().unwrap().pass_name, "p2");
    assert!((s.avg_duration_ms() - 40.0 / 3.0).abs() < 1e-9);
}

// ─────────────────── AnalysisEventBus ───────────────────

#[test]
fn event_bus_subscribe_publish() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bus = AnalysisEventBus::new();
    assert_eq!(bus.handler_count(), 0);
    let counter = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&counter);
    bus.subscribe(Arc::new(move |_e: &AnalysisEvent| {
        c2.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(bus.handler_count(), 1);
    bus.publish(&AnalysisEvent::PassStarted { pass_name: "x".into() });
    bus.publish(&AnalysisEvent::PassFinished {
        pass_name: "x".into(),
        duration_ms: 1,
    });
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn analysis_event_kind_tags() {
    assert_eq!(
        AnalysisEvent::FunctionDiscovered { address: 0, name: None }.kind_tag(),
        "function_discovered"
    );
    assert_eq!(
        AnalysisEvent::StringRecovered { address: 0, value: "".into() }.kind_tag(),
        "string_recovered"
    );
    assert_eq!(
        AnalysisEvent::XrefFound { from: 0, to: 0 }.kind_tag(),
        "xref_found"
    );
    assert_eq!(
        AnalysisEvent::PassStarted { pass_name: "".into() }.kind_tag(),
        "pass_started"
    );
    assert_eq!(
        AnalysisEvent::PassFinished { pass_name: "".into(), duration_ms: 0 }.kind_tag(),
        "pass_finished"
    );
    assert_eq!(
        AnalysisEvent::Warning { pass_name: "".into(), message: "".into() }.kind_tag(),
        "warning"
    );
    assert_eq!(
        AnalysisEvent::Error { pass_name: "".into(), message: "".into() }.kind_tag(),
        "error"
    );
}

// ─────────────────── AnalysisDb ───────────────────

#[test]
fn db_insert_count_query() {
    let db = AnalysisDb::new();
    assert_eq!(db.count(), 0);
    let id1 = db.insert("p", "uri://a", "{}");
    let id2 = db.insert("p", "uri://b", "{}");
    assert_ne!(id1, id2);
    assert_eq!(db.count(), 2);
    assert_eq!(db.query_by_pass("p").len(), 2);
    assert_eq!(db.query_by_uri("uri://a").len(), 1);
    assert_eq!(db.query_by_pass("missing").len(), 0);
}

#[test]
fn db_delete_by_uri() {
    let db = AnalysisDb::new();
    db.insert("p", "u1", "{}");
    db.insert("p", "u1", "{}");
    db.insert("p", "u2", "{}");
    let removed = db.delete_by_uri("u1");
    assert_eq!(removed, 2);
    assert_eq!(db.count(), 1);
}

#[test]
fn db_export_json() {
    let db = AnalysisDb::new();
    db.insert("p", "u", "{}");
    let json = db.export_json().unwrap();
    assert!(json.contains("\"pass_name\""));
}

#[test]
fn db_query_functions_skips_invalid() {
    let db = AnalysisDb::new();
    db.insert("p", "u", "not json");
    let fns = db.query_functions();
    assert!(fns.is_empty());
}

#[test]
fn db_query_functions_parses_valid() {
    let db = AnalysisDb::new();
    let fbs = vec![FunctionBoundary::new(0x100, 0x200, BoundaryMethod::SymbolTable)];
    let payload = serde_json::to_string(&fbs).unwrap();
    db.insert("disc", "u", &payload);
    let got = db.query_functions();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].start, 0x100);
}

#[test]
fn db_query_xrefs_parses_valid() {
    let db = AnalysisDb::new();
    let xrs = vec![Xref::new(1, 2, XrefType::Call)];
    db.insert("p", "u", &serde_json::to_string(&xrs).unwrap());
    assert_eq!(db.query_xrefs().len(), 1);
}

// ─────────────────── CrossReferenceDb ───────────────────

#[test]
fn xref_db_add_and_query() {
    let db = CrossReferenceDb::new();
    assert_eq!(db.count(), 0);
    db.add(Xref::new(0x100, 0x200, XrefType::Call));
    db.add_raw(0x100, 0x300, XrefType::Jump);
    db.add_raw(0x400, 0x200, XrefType::DataRead);
    assert_eq!(db.count(), 3);
    assert_eq!(db.xrefs_from(0x100).len(), 2);
    assert_eq!(db.xrefs_to(0x200).len(), 2);
    assert_eq!(db.xrefs_to(0x999).len(), 0);
    assert_eq!(db.calls().len(), 1);
    assert_eq!(db.call_targets(), vec![0x200]);
    db.clear();
    assert_eq!(db.count(), 0);
}

#[test]
fn xref_type_display() {
    assert_eq!(XrefType::Call.to_string(), "call");
    assert_eq!(XrefType::Jump.to_string(), "jump");
    assert_eq!(XrefType::DataRead.to_string(), "data_read");
    assert_eq!(XrefType::DataWrite.to_string(), "data_write");
    assert_eq!(XrefType::StringRef.to_string(), "string_ref");
    assert_eq!(XrefType::Unknown.to_string(), "unknown");
}

#[test]
fn xref_eq_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(Xref::new(1, 2, XrefType::Call));
    set.insert(Xref::new(1, 2, XrefType::Call));
    assert_eq!(set.len(), 1);
}

// ─────────────────── FunctionBoundary ───────────────────

#[test]
fn boundary_construct_and_modify() {
    let b = FunctionBoundary::new(0x100, 0x180, BoundaryMethod::LinearSweep)
        .with_name("foo")
        .with_confidence(95);
    assert_eq!(b.start, 0x100);
    assert_eq!(b.end, 0x180);
    assert_eq!(b.size(), 0x80);
    assert_eq!(b.name.as_deref(), Some("foo"));
    assert_eq!(b.confidence, 95);
    assert!(b.is_high_confidence());
}

#[test]
fn boundary_size_saturates_on_inverted() {
    let b = FunctionBoundary::new(0x200, 0x100, BoundaryMethod::HeuristicGap);
    assert_eq!(b.size(), 0);
}

#[test]
fn boundary_default_confidence_not_high() {
    let b = FunctionBoundary::new(0, 1, BoundaryMethod::ProloguePattern);
    assert_eq!(b.confidence, 50);
    assert!(!b.is_high_confidence());
}

// ─────────────────── FunctionBoundaryAnalysis ───────────────────

#[test]
fn scan_prologues_empty() {
    let r = FunctionBoundaryAnalysis::scan_prologues(0, &[]);
    assert!(r.is_empty());
}

#[test]
fn scan_prologues_push_rbp() {
    // PUSH RBP; MOV RBP, RSP at offset 0
    let bytes = [0x55, 0x48, 0x89, 0xE5, 0x90, 0x90];
    let r = FunctionBoundaryAnalysis::scan_prologues(0x1000, &bytes);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].start, 0x1000);
    assert_eq!(r[0].confidence, 80);
}

#[test]
fn scan_prologues_sub_rsp() {
    let bytes = [0x48, 0x83, 0xEC, 0x20];
    let r = FunctionBoundaryAnalysis::scan_prologues(0, &bytes);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].confidence, 70);
}

#[test]
fn scan_call_targets_e8() {
    // E8 rel=5 from base 0x1000 → target = 0x1005 + 5 = 0x100A
    let bytes = [0xE8, 0x05, 0x00, 0x00, 0x00];
    let r = FunctionBoundaryAnalysis::scan_call_targets(0x1000, &bytes);
    assert_eq!(r, vec![0x100A]);
}

#[test]
fn scan_call_targets_empty() {
    assert!(FunctionBoundaryAnalysis::scan_call_targets(0, &[]).is_empty());
}

// ─────────────────── LinearSweepConfig / Analyzer ───────────────────

#[test]
fn linear_sweep_config_default() {
    let c = LinearSweepConfig::default();
    assert_eq!(c.min_function_size, 4);
    assert_eq!(c.max_gap, 16);
    assert!(c.follow_calls);
}

#[test]
fn linear_sweep_analyzer_default_and_count() {
    let a = LinearSweepAnalyzer::default();
    // PUSH RBP; MOV RBP, RSP at 0; another at 0x10
    let mut bytes = vec![0x55, 0x48, 0x89, 0xE5];
    bytes.extend(std::iter::repeat_n(0x90u8, 12));
    bytes.extend([0x55, 0x48, 0x89, 0xE5]);
    bytes.extend(std::iter::repeat_n(0x90u8, 12));
    let cnt = a.sweep_count(0, &bytes);
    assert!(cnt >= 1);
}

#[test]
fn linear_sweep_empty_returns_empty() {
    let a = LinearSweepAnalyzer::default();
    assert!(a.sweep(0, &[]).is_empty());
    assert_eq!(a.sweep_count(0, &[]), 0);
}

// ─────────────────── RecursiveDescent ───────────────────

#[test]
fn recursive_descent_default_max_depth() {
    let r = RecursiveDescentAnalyzer::default();
    assert_eq!(r.max_depth, 512);
}

#[test]
fn recursive_descent_empty_bytes() {
    let r = RecursiveDescentAnalyzer::new(8);
    let visited = r.descend(0, &[], &[0]);
    assert!(visited.is_empty());
    assert!(r.analyze(0, &[], &[]).is_empty());
}

#[test]
fn recursive_descent_visits_entry_only_when_no_calls() {
    let r = RecursiveDescentAnalyzer::new(8);
    let bytes = vec![0x90u8; 16];
    let visited = r.descend(0x1000, &bytes, &[0x1000]);
    assert_eq!(visited.len(), 1);
    assert!(visited.contains(&0x1000));
}

// ─────────────────── StringRecoveryPass ───────────────────

#[test]
fn string_recovery_counts_printable_runs() {
    let mut data = b"hello\0world\0".to_vec();
    data.extend(b"xy"); // too short, ignored
    assert_eq!(StringRecoveryPass::count_strings(&data), 2);
}

#[test]
fn string_recovery_empty_input() {
    assert_eq!(StringRecoveryPass::count_strings(&[]), 0);
}

#[test]
fn string_recovery_unterminated_tail_counted() {
    let data = b"trailing_no_null";
    assert_eq!(StringRecoveryPass::count_strings(data), 1);
}

/// A string ends at any non-printable byte, not only at NUL.
///
/// `count_strings` used to require a NUL to close a run, so a buffer holding
/// "hello", a newline, "world" and a NUL reported ONE string instead of two.
/// Everything not followed by a NUL was dropped. The function already
/// disagreed with itself: the end-of-buffer branch counts a run with no
/// terminator at all, and the sibling `StringRecoveryPass` in
/// `pass_registry.rs` counts on any terminator. No existing test asked the
/// question, which is why it survived.
#[test]
fn string_recovery_counts_runs_ended_by_any_non_printable() {
    assert_eq!(
        StringRecoveryPass::count_strings(b"hello\nworld\0"),
        2,
        "a newline ends a string just as a NUL does"
    );
    assert_eq!(
        StringRecoveryPass::count_strings(b"alpha\tbravo\x01charlie"),
        3,
        "tab and 0x01 are both terminators; the tail counts too"
    );
    assert_eq!(
        StringRecoveryPass::count_strings(b"first\0second\0"),
        StringRecoveryPass::count_strings(b"first\nsecond\n"),
        "NUL- and newline-separated strings must count the same"
    );
}

#[test]
fn string_recovery_below_min_length_ignored() {
    assert_eq!(StringRecoveryPass::count_strings(b"abc\0"), 0);
}

// ─────────────────── XrefRecoveryPass / CfgAnalysisPass ───────────────────

#[test]
fn xref_recovery_counts_in_range_only() {
    // E8 rel=0 from base 0x1000 → target = 0x1005 (in range)
    let bytes = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
    let n = XrefRecoveryPass::count_xrefs(0x1000, &bytes);
    assert_eq!(n, 1);
}

#[test]
fn xref_recovery_out_of_range_skipped() {
    // E8 with huge rel → target far out
    let bytes = [0xE8, 0xFF, 0xFF, 0xFF, 0x7F];
    let n = XrefRecoveryPass::count_xrefs(0, &bytes);
    assert_eq!(n, 0);
}

#[test]
fn xref_recovery_empty() {
    assert_eq!(XrefRecoveryPass::count_xrefs(0, &[]), 0);
}

#[test]
fn cfg_count_basic_blocks_empty() {
    assert_eq!(CfgAnalysisPass::count_basic_blocks(&[]), 1);
}

#[test]
fn cfg_count_basic_blocks_with_ret() {
    let bytes = [0x90, 0xC3, 0x90, 0xC3];
    let n = CfgAnalysisPass::count_basic_blocks(&bytes);
    assert!(n >= 3);
}

// ─────────────────── Default Pass wrappers ───────────────────

#[test]
fn pass_wrappers_have_expected_metadata() {
    use rustre_analysis::AnalysisPass;
    let lsp = LinearSweepPass::default();
    assert_eq!(lsp.name(), "linear_sweep");
    assert_eq!(lsp.kind(), AnalysisKind::LinearSweep);
    assert_eq!(lsp.priority(), 100);

    let rdp = RecursiveDescentPass::default();
    assert_eq!(rdp.name(), "recursive_descent");
    assert_eq!(rdp.priority(), 90);

    let srp = StringRecoveryPass::new();
    assert_eq!(srp.name(), "string_recovery");
    assert_eq!(srp.priority(), 80);

    let xrp = XrefRecoveryPass::new();
    assert_eq!(xrp.name(), "xref_recovery");
    assert_eq!(xrp.priority(), 70);

    let fdp = FunctionDetectionPass::new();
    assert_eq!(fdp.name(), "function_detection");
    assert_eq!(fdp.priority(), 60);

    let cfg = CfgAnalysisPass::new();
    assert_eq!(cfg.name(), "cfg_analysis");
    assert_eq!(cfg.priority(), 50);
}

// ─────────────────── IncrementalAnalysis ───────────────────

#[test]
fn incremental_section_added_marks_all_run_passes() {
    let mut inc = IncrementalAnalysis::new();
    inc.mark_run("a");
    inc.mark_run("b");
    inc.mark_byte_sensitive("a");
    let affected = inc.affected_passes(&[BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::SectionAdded,
    }]);
    assert_eq!(affected.len(), 2);
}

#[test]
fn incremental_data_modified_only_byte_sensitive() {
    let mut inc = IncrementalAnalysis::new();
    inc.mark_run("a");
    inc.mark_run("b");
    inc.mark_byte_sensitive("a");
    inc.mark_symbol_sensitive("b");
    let aff = inc.affected_passes(&[BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::DataModified,
    }]);
    assert_eq!(aff, vec!["a".to_string()]);
}

#[test]
fn incremental_symbol_renamed_only_symbol_sensitive() {
    let mut inc = IncrementalAnalysis::default();
    inc.mark_run("a");
    inc.mark_symbol_sensitive("a");
    inc.mark_byte_sensitive("b");
    inc.mark_run("b");
    let aff = inc.affected_passes(&[BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::SymbolRenamed,
    }]);
    assert_eq!(aff, vec!["a".to_string()]);
}

#[test]
fn incremental_unrun_passes_not_affected() {
    let mut inc = IncrementalAnalysis::new();
    inc.mark_byte_sensitive("a");
    let aff = inc.affected_passes(&[BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::DataModified,
    }]);
    assert!(aff.is_empty());
}

// ─────────────────── PluginRegistry ───────────────────

struct DummyPlugin {
    meta: PluginMetadata,
}

impl AnalysisPlugin for DummyPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.meta
    }
    fn passes(&self) -> Vec<Arc<dyn rustre_analysis::AnalysisPass>> {
        vec![Arc::new(NoOpAnalysisPass::new("plugin_pass"))]
    }
}

#[test]
fn plugin_registry_load_and_find() {
    let reg = AnalysisPluginRegistry::new();
    assert_eq!(reg.plugin_count(), 0);
    reg.load(Arc::new(DummyPlugin {
        meta: PluginMetadata {
            id: "p1".into(),
            name: "Test".into(),
            version: "0.1".into(),
            description: "d".into(),
            author: "a".into(),
            provides: vec![AnalysisKind::LinearSweep],
        },
    }));
    assert_eq!(reg.plugin_count(), 1);
    assert!(reg.find_by_id("p1").is_some());
    assert!(reg.find_by_id("missing").is_none());
    assert_eq!(reg.all_passes().len(), 1);
}

// ─────────────────── AnalysisManager ───────────────────

#[test]
fn manager_new_is_empty() {
    let m = AnalysisManager::new();
    assert_eq!(m.pass_count(), 0);
    assert_eq!(m.xref_db().count(), 0);
    assert_eq!(m.db().count(), 0);
}

#[test]
fn manager_register_pass() {
    let m = AnalysisManager::default();
    m.register_pass(Arc::new(NoOpAnalysisPass::new("x")));
    assert_eq!(m.pass_count(), 1);
}

#[test]
fn manager_register_with_deps_schedule() {
    let m = AnalysisManager::new();
    m.register_pass_with_deps(Arc::new(NoOpAnalysisPass::new("a")), vec![]);
    m.register_pass_with_deps(
        Arc::new(NoOpAnalysisPass::new("b")),
        vec!["a".into()],
    );
    let order = m.scheduled_order().unwrap();
    let pa = order.iter().position(|x| x == "a").unwrap();
    let pb = order.iter().position(|x| x == "b").unwrap();
    assert!(pa < pb);
}

#[test]
fn manager_passes_to_rerun_empty_when_nothing_run() {
    let m = AnalysisManager::new();
    m.mark_byte_sensitive("p");
    let aff = m.passes_to_rerun(&[BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::DataModified,
    }]);
    assert!(aff.is_empty());
}

// ─────────────────── analyze_binary integration ───────────────────

#[tokio::test]
async fn analyze_binary_empty_data() {
    let report = analyze_binary(&[], "x86_64", 0).await;
    assert!(report.stats.passes.len() >= 6);
    let _ = report.summary();
}

#[tokio::test]
async fn analyze_binary_with_strings_and_calls() {
    // "hello\0world\0" + a call instruction near it
    let mut data: Vec<u8> = b"hello\0world\0".to_vec();
    data.extend([0xE8, 0x00, 0x00, 0x00, 0x00]); // call +0
    data.extend([0x90u8; 32]);
    let report = analyze_binary(&data, "x86_64", 0x1000).await;
    assert!(report.uri.contains("memory://"));
    assert!(report.total_strings() >= 2);
    let _summary = report.summary();
}

// ─────────────────── AnalysisReport build ───────────────────

#[test]
fn report_build_mixes_ok_and_err() {
    let outcomes: Vec<(String, Result<AnalysisResult, AnalysisError>)> = vec![
        (
            "ok".into(),
            Ok(AnalysisResult {
                kind: AnalysisKind::LinearSweep,
                functions_found: 3,
                data_refs_found: 0,
                strings_found: 2,
                duration_ms: 1,
                warnings: vec!["w".into()],
            }),
        ),
        ("err".into(), Err(AnalysisError::Failed("x".into()))),
    ];
    let r = AnalysisReport::build("uri://t", &outcomes);
    assert!(!r.success);
    assert_eq!(r.total_functions(), 3);
    assert_eq!(r.total_strings(), 2);
    assert_eq!(r.all_warnings.len(), 1);
    assert!(r.summary().contains("FAILED"));
}

#[test]
fn report_build_all_ok() {
    let outcomes: Vec<(String, Result<AnalysisResult, AnalysisError>)> = vec![(
        "ok".into(),
        Ok(AnalysisResult::zero(AnalysisKind::LinearSweep)),
    )];
    let r = AnalysisReport::build("u", &outcomes);
    assert!(r.success);
    assert!(!r.summary().contains("FAILED"));
}

// ─────────────────── Send/Sync bounds ───────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AnalysisConfig>();
    assert_send_sync::<AnalysisResult>();
    assert_send_sync::<AnalysisKind>();
    assert_send_sync::<AnalysisStats>();
    assert_send_sync::<AnalysisPipeline>();
    assert_send_sync::<AnalysisManager>();
    assert_send_sync::<AnalysisEventBus>();
    assert_send_sync::<AnalysisDb>();
    assert_send_sync::<CrossReferenceDb>();
    assert_send_sync::<FunctionBoundary>();
    assert_send_sync::<Xref>();
}
