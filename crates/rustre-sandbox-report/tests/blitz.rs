//! Exhaustive blitz test suite for `rustre-sandbox-report` public API.

use std::collections::HashMap;
use std::path::PathBuf;

use rustre_sandbox_report::{
    AttackMapping, AttackTactic, AttackTechnique, Behavior, BehaviorClassifier, BehaviorTimeline,
    Indicator, IndicatorCategory, Ioc, IocCollection, IocKind, IocSet, ReportError, ReportFormat,
    ReportRenderer, ReportSection, ReportStore, SandboxEvent, SandboxEventKind, SandboxReport,
    SandboxReportBuilder, SandboxReportRenderer, ScoreEngine, Severity, Verdict,
};

// ---------- Severity ----------

#[test]
fn severity_scores_exact() {
    assert_eq!(Severity::Info.score(), 0);
    assert_eq!(Severity::Low.score(), 25);
    assert_eq!(Severity::Medium.score(), 50);
    assert_eq!(Severity::High.score(), 75);
    assert_eq!(Severity::Critical.score(), 100);
}

#[test]
fn severity_parse_all_lower() {
    for (s, expected) in [
        ("info", Severity::Info),
        ("low", Severity::Low),
        ("medium", Severity::Medium),
        ("high", Severity::High),
        ("critical", Severity::Critical),
    ] {
        assert_eq!(Severity::parse(s).unwrap(), expected);
    }
}

#[test]
fn severity_parse_case_insensitive() {
    assert_eq!(Severity::parse("INFO").unwrap(), Severity::Info);
    assert_eq!(Severity::parse("HiGh").unwrap(), Severity::High);
}

#[test]
fn severity_parse_unknown_err() {
    let err = Severity::parse("nuclear").unwrap_err();
    match err {
        ReportError::InvalidData(msg) => assert!(msg.contains("nuclear")),
        _ => panic!("expected InvalidData, got {err:?}"),
    }
}

#[test]
fn severity_parse_empty_err() {
    assert!(Severity::parse("").is_err());
}

#[test]
fn severity_ord() {
    let mut v = vec![Severity::High, Severity::Info, Severity::Critical, Severity::Low];
    v.sort();
    assert_eq!(
        v,
        vec![Severity::Info, Severity::Low, Severity::High, Severity::Critical]
    );
}

#[test]
fn severity_display_roundtrip() {
    for s in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let rendered = s.to_string();
        let parsed = Severity::parse(&rendered).unwrap();
        assert_eq!(parsed, s);
    }
}

// ---------- IocKind ----------

#[test]
fn ioc_kind_display_known() {
    assert_eq!(IocKind::Ip.to_string(), "ip");
    assert_eq!(IocKind::Domain.to_string(), "domain");
    assert_eq!(IocKind::Url.to_string(), "url");
    assert_eq!(IocKind::FilePath.to_string(), "filepath");
    assert_eq!(IocKind::FileHash.to_string(), "filehash");
    assert_eq!(IocKind::RegistryKey.to_string(), "registry_key");
    assert_eq!(IocKind::Mutex.to_string(), "mutex");
    assert_eq!(IocKind::Email.to_string(), "email");
}

#[test]
fn ioc_kind_display_other() {
    assert_eq!(IocKind::Other("custom".to_string()).to_string(), "custom");
}

// ---------- Ioc ----------

#[test]
fn ioc_new_clamps_confidence() {
    let i = Ioc::new(IocKind::Ip, "1.1.1.1", 250, "ctx");
    assert_eq!(i.confidence, 100, "confidence should clamp to 100");
}

#[test]
fn ioc_new_keeps_low_confidence() {
    let i = Ioc::new(IocKind::Ip, "1.1.1.1", 5, "ctx");
    assert_eq!(i.confidence, 5);
}

#[test]
fn ioc_is_confident_boundary() {
    let i = Ioc::new(IocKind::Ip, "1.1.1.1", 50, "");
    assert!(i.is_confident(50));
    assert!(i.is_confident(49));
    assert!(!i.is_confident(51));
}

// ---------- IocSet ----------

#[test]
fn ioc_set_new_is_empty() {
    let s = IocSet::new();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn ioc_set_default_is_empty() {
    let s = IocSet::default();
    assert!(s.is_empty());
}

#[test]
fn ioc_set_add_increases_len() {
    let mut s = IocSet::new();
    s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 90, ""));
    s.add(Ioc::new(IocKind::Ip, "2.2.2.2", 90, ""));
    assert_eq!(s.len(), 2);
}

#[test]
fn ioc_set_by_kind_filters() {
    let mut s = IocSet::new();
    s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 90, ""));
    s.add(Ioc::new(IocKind::Domain, "x.com", 90, ""));
    s.add(Ioc::new(IocKind::Ip, "2.2.2.2", 90, ""));
    assert_eq!(s.by_kind(&IocKind::Ip).len(), 2);
    assert_eq!(s.by_kind(&IocKind::Domain).len(), 1);
    assert_eq!(s.by_kind(&IocKind::Mutex).len(), 0);
}

#[test]
fn ioc_set_confident_threshold() {
    let mut s = IocSet::new();
    s.add(Ioc::new(IocKind::Ip, "a", 10, ""));
    s.add(Ioc::new(IocKind::Ip, "b", 50, ""));
    s.add(Ioc::new(IocKind::Ip, "c", 90, ""));
    assert_eq!(s.confident(0).len(), 3);
    assert_eq!(s.confident(50).len(), 2);
    assert_eq!(s.confident(91).len(), 0);
}

#[test]
fn ioc_set_dedup_by_kind_and_value() {
    let mut s = IocSet::new();
    s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 100, "a"));
    s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 50, "b"));
    s.add(Ioc::new(IocKind::Domain, "1.1.1.1", 50, "c"));
    s.deduplicate();
    assert_eq!(s.len(), 2);
}

#[test]
fn ioc_set_mock_populated() {
    let s = IocSet::mock();
    assert!(s.len() >= 6);
    assert!(!s.by_kind(&IocKind::Ip).is_empty());
    assert!(!s.by_kind(&IocKind::FileHash).is_empty());
}

// ---------- AttackTactic / Mapping ----------

#[test]
fn attack_tactic_display_all() {
    use AttackTactic::*;
    let table = [
        (InitialAccess, "initial_access"),
        (Execution, "execution"),
        (Persistence, "persistence"),
        (PrivilegeEscalation, "privilege_escalation"),
        (DefenseEvasion, "defense_evasion"),
        (CredentialAccess, "credential_access"),
        (Discovery, "discovery"),
        (LateralMovement, "lateral_movement"),
        (Collection, "collection"),
        (CommandAndControl, "command_and_control"),
        (Exfiltration, "exfiltration"),
        (Impact, "impact"),
    ];
    for (t, s) in table {
        assert_eq!(t.to_string(), s);
    }
}

#[test]
fn attack_technique_full_id_with_sub() {
    let t = AttackTechnique {
        id: "T1055".into(),
        sub_id: Some("T1055.001".into()),
        name: "x".into(),
        tactic: AttackTactic::DefenseEvasion,
        evidence: vec![],
        confidence: 80,
    };
    assert_eq!(t.full_id(), "T1055.001");
}

#[test]
fn attack_technique_full_id_without_sub() {
    let t = AttackTechnique {
        id: "T1055".into(),
        sub_id: None,
        name: "x".into(),
        tactic: AttackTactic::DefenseEvasion,
        evidence: vec![],
        confidence: 80,
    };
    assert_eq!(t.full_id(), "T1055");
}

#[test]
fn attack_mapping_new_and_default_empty() {
    assert!(AttackMapping::new().techniques.is_empty());
    assert!(AttackMapping::default().techniques.is_empty());
}

#[test]
fn attack_mapping_from_behaviors_known_tags() {
    let m = AttackMapping::from_behaviors(&[
        "injection",
        "persistence",
        "anti-analysis",
        "c2",
        "dropper",
        "keylogger",
        "ransomware",
        "screenshot",
        "worm",
    ]);
    assert_eq!(m.techniques.len(), 9);
}

#[test]
fn attack_mapping_from_behaviors_unknown_ignored() {
    let m = AttackMapping::from_behaviors(&["banana", "spaghetti"]);
    assert!(m.techniques.is_empty());
}

#[test]
fn attack_mapping_from_behaviors_antianalysis_alias() {
    let m = AttackMapping::from_behaviors(&["antianalysis"]);
    assert_eq!(m.techniques.len(), 1);
    assert_eq!(m.techniques[0].id, "T1497");
}

#[test]
fn attack_mapping_by_tactic() {
    let m = AttackMapping::from_behaviors(&["injection", "c2", "persistence"]);
    assert_eq!(m.by_tactic(&AttackTactic::DefenseEvasion).len(), 1);
    assert_eq!(m.by_tactic(&AttackTactic::CommandAndControl).len(), 1);
    assert_eq!(m.by_tactic(&AttackTactic::Persistence).len(), 1);
    assert_eq!(m.by_tactic(&AttackTactic::Impact).len(), 0);
}

#[test]
fn attack_mapping_tactics_present_sorted_unique() {
    let m = AttackMapping::from_behaviors(&["injection", "anti-analysis", "c2", "dropper"]);
    let t = m.tactics_present();
    let mut sorted = t.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(t, sorted);
}

#[test]
fn attack_mapping_technique_ids_uses_full_id() {
    let m = AttackMapping::from_behaviors(&["injection", "ransomware"]);
    let ids = m.technique_ids();
    assert!(ids.contains(&"T1055.001"));
    assert!(ids.contains(&"T1486"));
}

#[test]
fn attack_mapping_high_confidence() {
    let m = AttackMapping::from_behaviors(&["dropper", "worm", "ransomware"]);
    // dropper=80, worm=75, ransomware=97  → high (>=80) = dropper + ransomware
    let hc = m.high_confidence();
    assert_eq!(hc.len(), 2);
}

// ---------- Indicator ----------

#[test]
fn indicator_with_ioc_and_technique_chained() {
    let i = Indicator::new("n", "d", Severity::Low, IndicatorCategory::Other)
        .with_ioc("xx")
        .with_technique("T1")
        .with_technique("T2");
    assert_eq!(i.ioc.as_deref(), Some("xx"));
    assert_eq!(i.technique_ids, vec!["T1", "T2"]);
}

#[test]
fn indicator_category_display() {
    assert_eq!(IndicatorCategory::Injection.to_string(), "injection");
    assert_eq!(IndicatorCategory::Network.to_string(), "network");
    assert_eq!(IndicatorCategory::Ransomware.to_string(), "ransomware");
    assert_eq!(IndicatorCategory::Other.to_string(), "other");
}

// ---------- Behavior ----------

#[test]
fn behavior_new_defaults() {
    let b = Behavior::new("n", "d", Severity::High, "cat");
    assert!(b.apis.is_empty());
    assert_eq!(b.first_seen_ms, 0);
    assert_eq!(b.pid, 0);
}

#[test]
fn behavior_with_api_appends() {
    let b = Behavior::new("n", "d", Severity::High, "cat")
        .with_api("A")
        .with_api("B");
    assert_eq!(b.apis, vec!["A", "B"]);
}

// ---------- Verdict ----------

#[test]
fn verdict_display() {
    assert_eq!(Verdict::Clean.to_string(), "clean");
    assert_eq!(Verdict::Low.to_string(), "low");
    assert_eq!(Verdict::Suspicious.to_string(), "suspicious");
    assert_eq!(Verdict::Malicious.to_string(), "malicious");
    assert_eq!(Verdict::Unknown.to_string(), "unknown");
}

// ---------- ScoreEngine ----------

#[test]
fn score_engine_empty_is_clean() {
    let e = ScoreEngine::new();
    assert_eq!(e.compute(&[]), 0);
    assert_eq!(e.verdict(0), Verdict::Clean);
}

#[test]
fn score_engine_low_bucket() {
    let e = ScoreEngine::new();
    assert_eq!(e.verdict(1), Verdict::Low);
    assert_eq!(e.verdict(30), Verdict::Low);
}

#[test]
fn score_engine_suspicious_bucket() {
    let e = ScoreEngine::new();
    assert_eq!(e.verdict(31), Verdict::Suspicious);
    assert_eq!(e.verdict(70), Verdict::Suspicious);
}

#[test]
fn score_engine_malicious_bucket() {
    let e = ScoreEngine::new();
    assert_eq!(e.verdict(71), Verdict::Malicious);
    assert_eq!(e.verdict(100), Verdict::Malicious);
    assert_eq!(e.verdict(9_999), Verdict::Malicious);
}

#[test]
fn score_engine_caps_at_100() {
    let e = ScoreEngine::new();
    let inds = vec![
        Indicator::new("n", "d", Severity::Critical, IndicatorCategory::Injection); 20
    ];
    let s = e.compute(&inds);
    assert!(s <= 100, "score {s} exceeds cap");
    assert_eq!(s, 100);
}

#[test]
fn score_engine_default_eq_new() {
    let a = ScoreEngine::new().compute(&[Indicator::new(
        "x",
        "y",
        Severity::Medium,
        IndicatorCategory::Network,
    )]);
    let b = ScoreEngine::default().compute(&[Indicator::new(
        "x",
        "y",
        Severity::Medium,
        IndicatorCategory::Network,
    )]);
    assert_eq!(a, b);
}

#[test]
fn score_engine_weight_math() {
    // Medium (50) * injection weight 25 / 100 = 12
    let e = ScoreEngine::new();
    let inds = vec![Indicator::new(
        "n",
        "d",
        Severity::Medium,
        IndicatorCategory::Injection,
    )];
    assert_eq!(e.compute(&inds), 12);
}

#[test]
fn score_engine_has_critical_true() {
    let inds = vec![
        Indicator::new("n", "d", Severity::Low, IndicatorCategory::Other),
        Indicator::new("n", "d", Severity::Critical, IndicatorCategory::Injection),
    ];
    assert!(ScoreEngine::has_critical(&inds));
}

#[test]
fn score_engine_has_critical_false() {
    let inds = vec![Indicator::new(
        "n",
        "d",
        Severity::High,
        IndicatorCategory::Other,
    )];
    assert!(!ScoreEngine::has_critical(&inds));
}

// ---------- BehaviorClassifier ----------

#[test]
fn classifier_full_injection_chain() {
    let c = BehaviorClassifier::new();
    let (inds, behs) = c.classify(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Injection));
    assert!(behs.iter().any(|b| b.name == "Process Injection"));
}

#[test]
fn classifier_partial_injection_does_not_trigger() {
    let c = BehaviorClassifier::new();
    let (inds, behs) = c.classify(&["VirtualAllocEx", "WriteProcessMemory"]);
    assert!(!inds.iter().any(|i| i.name == "Classic Process Injection"));
    assert!(behs.is_empty());
}

#[test]
fn classifier_persistence_via_regset() {
    let c = BehaviorClassifier::new();
    let (inds, _) = c.classify(&["RegSetValue"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Persistence));
}

#[test]
fn classifier_persistence_via_ntsetvalue() {
    let c = BehaviorClassifier::new();
    let (inds, _) = c.classify(&["NtSetValueKey"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Persistence));
}

#[test]
fn classifier_network_triggers() {
    let c = BehaviorClassifier::new();
    let (inds, behs) = c.classify(&["InternetConnect"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Network));
    assert!(behs.iter().any(|b| b.category == "network"));
}

#[test]
fn classifier_anti_debug() {
    let c = BehaviorClassifier::new();
    let (inds, _) = c.classify(&["IsDebuggerPresent"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Evasion));
}

#[test]
fn classifier_crypto() {
    let c = BehaviorClassifier::new();
    let (inds, _) = c.classify(&["CryptEncrypt"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Crypto));
}

#[test]
fn classifier_keylog() {
    let c = BehaviorClassifier::new();
    let (inds, _) = c.classify(&["SetWindowsHookEx"]);
    assert!(inds.iter().any(|i| i.category == IndicatorCategory::Keylogging));
}

#[test]
fn classifier_screenshot() {
    let c = BehaviorClassifier::new();
    let (inds, _) = c.classify(&["BitBlt"]);
    assert!(inds.iter().any(|i| i.name == "Screen Capture"));
}

#[test]
fn classifier_empty_apis() {
    let c = BehaviorClassifier::new();
    let (inds, behs) = c.classify(&[]);
    assert!(inds.is_empty());
    assert!(behs.is_empty());
}

#[test]
fn classifier_infer_family_ransomware() {
    let inds = vec![Indicator::new(
        "n",
        "d",
        Severity::Critical,
        IndicatorCategory::Ransomware,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&inds), "ransomware");
}

#[test]
fn classifier_infer_family_spyware() {
    let inds = vec![
        Indicator::new("n", "d", Severity::High, IndicatorCategory::Keylogging),
        Indicator::new("n", "d", Severity::Medium, IndicatorCategory::Network),
    ];
    assert_eq!(BehaviorClassifier::infer_family(&inds), "spyware");
}

#[test]
fn classifier_infer_family_trojan() {
    let inds = vec![
        Indicator::new("n", "d", Severity::High, IndicatorCategory::Injection),
        Indicator::new("n", "d", Severity::Medium, IndicatorCategory::Network),
    ];
    assert_eq!(BehaviorClassifier::infer_family(&inds), "trojan");
}

#[test]
fn classifier_infer_family_injector() {
    let inds = vec![Indicator::new(
        "n",
        "d",
        Severity::High,
        IndicatorCategory::Injection,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&inds), "injector");
}

#[test]
fn classifier_infer_family_downloader() {
    let inds = vec![Indicator::new(
        "n",
        "d",
        Severity::Medium,
        IndicatorCategory::Network,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&inds), "downloader");
}

#[test]
fn classifier_infer_family_unknown() {
    let inds = vec![Indicator::new(
        "n",
        "d",
        Severity::Low,
        IndicatorCategory::Other,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&inds), "unknown");
}

// ---------- ReportSection ----------

#[test]
fn report_section_fields() {
    let s = ReportSection::new("T", "C", 5);
    assert_eq!(s.title, "T");
    assert_eq!(s.content, "C");
    assert_eq!(s.order, 5);
}

// ---------- SandboxReport ----------

#[test]
fn report_new_defaults() {
    let r = SandboxReport::new("s", "h");
    assert_eq!(r.sample, "s");
    assert_eq!(r.sha256, "h");
    assert_eq!(r.analysis_ms, 0);
    assert_eq!(r.score, 0);
    assert_eq!(r.verdict, Verdict::Unknown);
    assert!(r.indicators.is_empty());
}

#[test]
fn report_add_section_sorts_by_order() {
    let mut r = SandboxReport::new("s", "h");
    r.add_section(ReportSection::new("a", "", 3));
    r.add_section(ReportSection::new("b", "", 1));
    r.add_section(ReportSection::new("c", "", 2));
    let orders: Vec<u32> = r.sections.iter().map(|s| s.order).collect();
    assert_eq!(orders, vec![1, 2, 3]);
}

#[test]
fn report_add_tag_indicator_behavior_ttp() {
    let mut r = SandboxReport::new("s", "h");
    r.add_tag("t");
    r.add_indicator(Indicator::new("n", "d", Severity::Low, IndicatorCategory::Other));
    r.add_behavior(Behavior::new("n", "d", Severity::Low, "c"));
    r.add_ttp("T1");
    assert_eq!(r.tags.len(), 1);
    assert_eq!(r.indicators.len(), 1);
    assert_eq!(r.behaviors.len(), 1);
    assert_eq!(r.ttps, vec!["T1"]);
}

#[test]
fn report_compute_score_critical_forces_malicious() {
    let mut r = SandboxReport::new("s", "h");
    r.add_indicator(Indicator::new(
        "n",
        "d",
        Severity::Critical,
        IndicatorCategory::Injection,
    ));
    r.compute_score();
    assert_eq!(r.verdict, Verdict::Malicious);
}

#[test]
fn report_compute_score_clean_when_empty() {
    let mut r = SandboxReport::new("s", "h");
    r.compute_score();
    assert_eq!(r.score, 0);
    assert_eq!(r.verdict, Verdict::Clean);
}

#[test]
fn report_build_attack_mapping_from_tags() {
    let mut r = SandboxReport::new("s", "h");
    r.add_tag("injection");
    r.add_tag("c2");
    r.build_attack_mapping();
    assert_eq!(r.attack.techniques.len(), 2);
}

#[test]
fn report_infer_family_sets_field() {
    let mut r = SandboxReport::new("s", "h");
    r.add_indicator(Indicator::new(
        "n",
        "d",
        Severity::Critical,
        IndicatorCategory::Ransomware,
    ));
    r.infer_family();
    assert_eq!(r.family, "ransomware");
}

#[test]
fn report_critical_indicators_filters() {
    let mut r = SandboxReport::new("s", "h");
    r.add_indicator(Indicator::new("n", "d", Severity::Low, IndicatorCategory::Other));
    r.add_indicator(Indicator::new(
        "n",
        "d",
        Severity::Critical,
        IndicatorCategory::Injection,
    ));
    assert_eq!(r.critical_indicators().len(), 1);
}

#[test]
fn report_indicators_by_category() {
    let mut r = SandboxReport::new("s", "h");
    r.add_indicator(Indicator::new("a", "d", Severity::Low, IndicatorCategory::Network));
    r.add_indicator(Indicator::new("b", "d", Severity::Low, IndicatorCategory::Network));
    r.add_indicator(Indicator::new("c", "d", Severity::Low, IndicatorCategory::Other));
    assert_eq!(r.indicators_by_category(&IndicatorCategory::Network).len(), 2);
}

#[test]
fn report_to_json_roundtrips() {
    let r = SandboxReport::mock();
    let j = r.to_json().unwrap();
    let back: SandboxReport = serde_json::from_str(&j).unwrap();
    assert_eq!(back.sample, r.sample);
    assert_eq!(back.indicators.len(), r.indicators.len());
}

#[test]
fn report_to_markdown_contains_sample() {
    let r = SandboxReport::mock();
    let md = r.to_markdown();
    assert!(md.contains(&r.sample));
    assert!(md.contains("## Indicators"));
}

#[test]
fn report_to_html_contains_sample() {
    let r = SandboxReport::mock();
    let html = r.to_html();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains(&r.sample));
}

#[test]
fn report_mock_passes_self_check() {
    let r = SandboxReport::mock();
    assert!(!r.indicators.is_empty());
    assert!(!r.iocs.is_empty());
    assert!(!r.attack.techniques.is_empty());
    assert_eq!(r.verdict, Verdict::Malicious);
}

// ---------- ReportRenderer ----------

#[test]
fn renderer_json_pretty_valid() {
    let r = SandboxReport::mock();
    let j = ReportRenderer::new().render_json(&r).unwrap();
    let _: serde_json::Value = serde_json::from_str(&j).unwrap();
}

#[test]
fn renderer_markdown_empty_report() {
    let r = SandboxReport::new("s", "h");
    let md = ReportRenderer::new().render_markdown(&r);
    assert!(md.contains("_No indicators found._"));
    assert!(md.contains("_No ATT&CK mappings._"));
    assert!(md.contains("_No IOCs extracted._"));
}

#[test]
fn renderer_html_escapes_sample() {
    let mut r = SandboxReport::new("<evil>", "h");
    r.compute_score();
    let html = ReportRenderer::new().render_html(&r);
    assert!(html.contains("&lt;evil&gt;"));
    assert!(!html.contains("<evil>"));
}

#[test]
fn renderer_html_escapes_quotes_and_amp() {
    let mut r = SandboxReport::new("a&b\"c'", "h");
    r.compute_score();
    let html = ReportRenderer::new().render_html(&r);
    assert!(html.contains("&amp;"));
    assert!(html.contains("&quot;"));
    assert!(html.contains("&#39;"));
}

// ---------- ReportFormat ----------

#[test]
fn report_format_extension() {
    assert_eq!(ReportFormat::Json.extension(), "json");
    assert_eq!(ReportFormat::Html.extension(), "html");
    assert_eq!(ReportFormat::Pdf.extension(), "pdf");
    assert_eq!(ReportFormat::Csv.extension(), "csv");
    assert_eq!(ReportFormat::Markdown.extension(), "md");
}

#[test]
fn report_format_display() {
    assert_eq!(ReportFormat::Markdown.to_string(), "markdown");
}

#[test]
fn report_format_from_extension_known() {
    assert_eq!(ReportFormat::from_extension("json").unwrap(), ReportFormat::Json);
    assert_eq!(ReportFormat::from_extension(".HTML").unwrap(), ReportFormat::Html);
    assert_eq!(ReportFormat::from_extension("htm").unwrap(), ReportFormat::Html);
    assert_eq!(ReportFormat::from_extension(".pdf").unwrap(), ReportFormat::Pdf);
    assert_eq!(ReportFormat::from_extension("CSV").unwrap(), ReportFormat::Csv);
    assert_eq!(ReportFormat::from_extension("md").unwrap(), ReportFormat::Markdown);
    assert_eq!(
        ReportFormat::from_extension("markdown").unwrap(),
        ReportFormat::Markdown
    );
}

#[test]
fn report_format_from_extension_unknown_err() {
    assert!(ReportFormat::from_extension("xyz").is_err());
    assert!(ReportFormat::from_extension("").is_err());
}

// ---------- IocCollection ----------

#[test]
fn ioc_collection_empty_default() {
    let c = IocCollection::new();
    assert!(c.is_empty());
    assert_eq!(c.total(), 0);
    assert!(c.summary_text().is_empty());
}

#[test]
fn ioc_collection_mock_populated() {
    let c = IocCollection::mock();
    assert!(!c.is_empty());
    assert!(c.total() >= 7);
}

#[test]
fn ioc_collection_summary_includes_sections() {
    let c = IocCollection::mock();
    let s = c.summary_text();
    assert!(s.contains("IPs:"));
    assert!(s.contains("Domains:"));
    assert!(s.contains("URLs:"));
    assert!(s.contains("Hashes:"));
    assert!(s.contains("Registry:"));
    assert!(s.contains("Mutexes:"));
    assert!(s.contains("Paths:"));
}

#[test]
fn ioc_collection_csv_header_and_rows() {
    let c = IocCollection::mock();
    let csv = c.to_csv();
    assert!(csv.starts_with("type,value\n"));
    assert!(csv.contains("ip,185.220.101.1"));
    assert!(csv.contains("domain,c2server.evil"));
    // header + 1 per row
    assert_eq!(csv.lines().count(), 1 + c.total());
}

#[test]
fn ioc_collection_total_counts_all_buckets() {
    let mut c = IocCollection::new();
    c.ips.push("a".into());
    c.domains.push("b".into());
    c.urls.push("c".into());
    c.file_paths.push("d".into());
    c.registry_keys.push("e".into());
    c.mutexes.push("f".into());
    c.hashes.push("g".into());
    c.btc_addresses.push("h".into());
    assert_eq!(c.total(), 8);
}

// ---------- SandboxReportBuilder ----------

#[test]
fn builder_json_contains_report_and_iocs() {
    let r = SandboxReport::mock();
    let mut b = SandboxReportBuilder::new(r);
    b.add_iocs(IocCollection::mock());
    let j = b.build_json();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert!(v.get("report").is_some());
    assert!(v.get("iocs").is_some());
}

#[test]
fn builder_json_skips_none_iocs() {
    let r = SandboxReport::mock();
    let b = SandboxReportBuilder::new(r);
    let j = b.build_json();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert!(v.get("iocs").is_none());
    assert!(v.get("ttp_map").is_none());
}

#[test]
fn builder_markdown_sections_present() {
    let r = SandboxReport::mock();
    let b = SandboxReportBuilder::new(r);
    let md = b.build_markdown();
    assert!(md.contains("# Sandbox Analysis Report"));
    assert!(md.contains("## Executive Summary"));
    assert!(md.contains("## File Information"));
    assert!(md.contains("## Behavioral Analysis"));
    assert!(md.contains("## IOCs"));
    assert!(md.contains("## MITRE ATT&CK Mapping"));
    assert!(md.contains("## Dropped Files"));
}

#[test]
fn builder_markdown_empty_dropped_message() {
    let mut r = SandboxReport::new("s", "h");
    r.compute_score();
    let b = SandboxReportBuilder::new(r);
    let md = b.build_markdown();
    assert!(md.contains("_No dropped files recorded._"));
}

#[test]
fn builder_html_full_document() {
    let r = SandboxReport::mock();
    let mut b = SandboxReportBuilder::new(r);
    b.add_iocs(IocCollection::mock());
    let mut map = HashMap::new();
    map.insert("T1055".to_string(), vec!["evidence1".to_string()]);
    b.add_ttp_map(map);
    let html = b.build_html();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Sandbox Analysis Report"));
    assert!(html.contains("Executive Summary"));
    assert!(html.contains("MITRE ATT&amp;CK Mapping"));
    assert!(html.contains("T1055"));
}

#[test]
fn builder_csv_header_and_built_in_iocs() {
    let r = SandboxReport::mock();
    let b = SandboxReportBuilder::new(r);
    let csv = b.build_csv();
    assert!(csv.starts_with("type,value,confidence\n"));
    assert!(csv.contains("ip,185.220.101.1,95"));
}

#[test]
fn builder_csv_escapes_commas() {
    let mut r = SandboxReport::new("s", "h");
    r.iocs.add(Ioc::new(IocKind::Other("k".into()), "a,b", 50, ""));
    let b = SandboxReportBuilder::new(r);
    let csv = b.build_csv();
    assert!(csv.contains("\"a,b\""), "csv was:\n{csv}");
}

#[test]
fn builder_csv_escapes_quotes() {
    let mut r = SandboxReport::new("s", "h");
    r.iocs
        .add(Ioc::new(IocKind::Other("k".into()), "a\"b", 50, ""));
    let b = SandboxReportBuilder::new(r);
    let csv = b.build_csv();
    assert!(csv.contains("\"a\"\"b\""), "csv was:\n{csv}");
}

#[test]
fn builder_csv_includes_collection_with_empty_confidence() {
    let r = SandboxReport::new("s", "h");
    let mut b = SandboxReportBuilder::new(r);
    b.add_iocs(IocCollection::mock());
    let csv = b.build_csv();
    // each collection line ends with a trailing comma (empty confidence field)
    assert!(csv.lines().any(|l| l.starts_with("ip,") && l.ends_with(',')));
}

#[test]
fn builder_accessors() {
    let r = SandboxReport::mock();
    let mut b = SandboxReportBuilder::new(r.clone());
    assert_eq!(b.report().sample, r.sample);
    assert!(b.iocs().is_none());
    b.add_iocs(IocCollection::mock());
    assert!(b.iocs().is_some());
}

// ---------- ReportStore ----------

#[test]
fn store_save_and_load_roundtrip() {
    let dir = std::env::temp_dir().join(format!(
        "rustre_sandbox_report_blitz_{}",
        std::process::id()
    ));
    let path: PathBuf = dir.join("nested").join("report.json");
    let content = "{\"hello\":1}";
    ReportStore::save(content, ReportFormat::Json, &path).unwrap();
    let loaded = ReportStore::load(&path).unwrap();
    assert_eq!(loaded, content);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn store_save_and_reload_helper() {
    let dir = std::env::temp_dir().join(format!(
        "rustre_sandbox_report_blitz2_{}",
        std::process::id()
    ));
    let path = dir.join("a.md");
    let s = ReportStore::save_and_reload("hello", ReportFormat::Markdown, &path).unwrap();
    assert_eq!(s, "hello");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn store_load_invalid_utf8_fails() {
    let dir = std::env::temp_dir().join(format!(
        "rustre_sandbox_report_blitz3_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bin");
    std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
    assert!(ReportStore::load(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn store_load_missing_fails() {
    let p = std::env::temp_dir().join("rustre_sandbox_report_blitz_definitely_missing.json");
    let _ = std::fs::remove_file(&p);
    assert!(ReportStore::load(&p).is_err());
}

// ---------- SandboxEvent / EventKind ----------

#[test]
fn event_kind_display_variants() {
    assert_eq!(SandboxEventKind::ApiCall("X".into()).to_string(), "api:X");
    assert_eq!(SandboxEventKind::FileOp("/x".into()).to_string(), "file:/x");
    assert_eq!(SandboxEventKind::NetworkConn.to_string(), "net");
    assert_eq!(SandboxEventKind::RegistryOp.to_string(), "reg");
    assert_eq!(SandboxEventKind::ProcessSpawn.to_string(), "proc");
    assert_eq!(SandboxEventKind::CodeInjection.to_string(), "inject");
    assert_eq!(SandboxEventKind::DeleteShadowCopies.to_string(), "vss_delete");
    assert_eq!(SandboxEventKind::ExtensionChange.to_string(), "ext_change");
    assert_eq!(SandboxEventKind::ScreenCapture.to_string(), "screenshot");
    assert_eq!(SandboxEventKind::KeyboardHook.to_string(), "keyhook");
    assert_eq!(SandboxEventKind::HighCpuLoad.to_string(), "cpu_high");
    assert_eq!(SandboxEventKind::ModuleLoad("M".into()).to_string(), "mod:M");
    assert_eq!(SandboxEventKind::MutexCreate.to_string(), "mutex");
    assert_eq!(SandboxEventKind::Other("z".into()).to_string(), "other:z");
}

#[test]
fn event_new_stores_fields() {
    let e = SandboxEvent::new(123, 7, SandboxEventKind::NetworkConn, "d");
    assert_eq!(e.ts_ms, 123);
    assert_eq!(e.pid, 7);
    assert_eq!(e.detail, "d");
}

// ---------- BehaviorTimeline ----------

#[test]
fn timeline_empty_methods() {
    let t = BehaviorTimeline::build(&[]);
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert_eq!(t.start_ms(), 0);
    assert_eq!(t.end_ms(), 0);
    assert_eq!(t.duration_ms(), 0);
    assert_eq!(t.summary(), "(no events)");
}

#[test]
fn timeline_sorts_by_ts() {
    let events = vec![
        SandboxEvent::new(3000, 1, SandboxEventKind::NetworkConn, ""),
        SandboxEvent::new(1000, 1, SandboxEventKind::RegistryOp, ""),
        SandboxEvent::new(2000, 1, SandboxEventKind::ProcessSpawn, ""),
    ];
    let t = BehaviorTimeline::build(&events);
    let ts: Vec<u64> = t.events().iter().map(|e| e.ts_ms).collect();
    assert_eq!(ts, vec![1000, 2000, 3000]);
    assert_eq!(t.start_ms(), 1000);
    assert_eq!(t.end_ms(), 3000);
    assert_eq!(t.duration_ms(), 2000);
}

#[test]
fn timeline_summary_buckets_per_second() {
    let events = vec![
        SandboxEvent::new(0, 1, SandboxEventKind::NetworkConn, ""),
        SandboxEvent::new(500, 1, SandboxEventKind::RegistryOp, ""),
        SandboxEvent::new(1500, 1, SandboxEventKind::ProcessSpawn, ""),
    ];
    let t = BehaviorTimeline::build(&events);
    let s = t.summary();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("t=     0s"));
    assert!(lines[0].contains("[   2 events]"));
    assert!(lines[1].contains("t=     1s"));
}

#[test]
fn timeline_summary_truncates_many_kinds() {
    let mut events = vec![];
    for i in 0..7u64 {
        events.push(SandboxEvent::new(
            i,
            1,
            SandboxEventKind::Other(format!("k{i}")),
            "",
        ));
    }
    let t = BehaviorTimeline::build(&events);
    let s = t.summary();
    assert!(s.contains(", ..."), "expected truncation in: {s}");
}

// ---------- SandboxReportRenderer ----------

#[test]
fn sandbox_renderer_json_valid() {
    let r = SandboxReport::mock();
    let rr = SandboxReportRenderer::new(&r);
    let j = rr.render_json(&r);
    let _: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert_eq!(rr.report().sample, r.sample);
}

#[test]
fn sandbox_renderer_markdown_sections() {
    let r = SandboxReport::mock();
    let rr = SandboxReportRenderer::new(&r);
    let md = rr.render_markdown(&r);
    assert!(md.contains("# Sandbox Analysis Report"));
    assert!(md.contains("## Indicators"));
    assert!(md.contains("## Behaviors"));
    assert!(md.contains("## MITRE ATT&CK"));
}

#[test]
fn sandbox_renderer_markdown_escapes_pipes() {
    let mut r = SandboxReport::new("s", "h");
    r.add_indicator(Indicator::new(
        "name|with|pipes",
        "desc",
        Severity::Low,
        IndicatorCategory::Other,
    ));
    let rr = SandboxReportRenderer::new(&r);
    let md = rr.render_markdown(&r);
    assert!(md.contains(r"name\|with\|pipes"));
}

#[test]
fn sandbox_renderer_html_caps_score_display() {
    let mut r = SandboxReport::new("s", "h");
    r.score = 9_999;
    let rr = SandboxReportRenderer::new(&r);
    let html = rr.render_html(&r);
    // bar should be width:100%
    assert!(html.contains("width:100%"));
}

#[test]
fn sandbox_renderer_html_no_tags_marker() {
    let r = SandboxReport::new("s", "h");
    let rr = SandboxReportRenderer::new(&r);
    let html = rr.render_html(&r);
    assert!(html.contains("class=\"no-data\""));
}
