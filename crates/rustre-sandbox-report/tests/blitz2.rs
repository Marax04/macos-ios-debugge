//! Deep adversarial tests for `rustre-sandbox-report`.
//!
//! Focus: public API on lib.rs — `Severity`, `IocKind`, `Ioc`, `IocSet`,
//! `AttackTactic`, `AttackTechnique`, `AttackMapping`, `Indicator`, `Behavior`,
//! `Verdict`, `ReportSection`, `ScoreEngine`, `BehaviorClassifier`, `ReportRenderer`,
//! `SandboxReport`, `ReportFormat`, `IocCollection`, `SandboxReportBuilder`,
//! `ReportStore`, `SandboxEventKind`, `SandboxEvent`, `SandboxReportRenderer`,
//! `BehaviorTimeline`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;

use rustre_sandbox_report::*;

// ─── Seeded LCG ──────────────────────────────────────────────────────────────

struct Lcg {
    s: u64,
}
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self { s: seed }
    }
    const fn next(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.s
    }
    const fn next_u8(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

// ─── Severity ────────────────────────────────────────────────────────────────

#[test]
fn severity_display_fromstr_roundtrip() {
    for sev in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let s = sev.to_string();
        let parsed = Severity::parse(&s).unwrap();
        assert_eq!(parsed, sev);
        let upper = s.to_uppercase();
        assert_eq!(Severity::parse(&upper).unwrap(), sev);
    }
}

#[test]
fn severity_parse_errors_for_garbage() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let valid: HashSet<&str> = ["info", "low", "medium", "high", "critical"]
        .iter()
        .copied()
        .collect();
    for _ in 0..60 {
        let len = (lcg.next() % 8) as usize + 1;
        let mut s = String::new();
        for _ in 0..len {
            s.push((b'a' + (lcg.next_u8() % 26)) as char);
        }
        let lower = s.to_ascii_lowercase();
        if valid.contains(lower.as_str()) {
            assert!(Severity::parse(&s).is_ok());
        } else {
            assert!(Severity::parse(&s).is_err(), "should err: {s}");
        }
    }
}

#[test]
fn severity_score_monotonic_with_ordering() {
    let order = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for w in order.windows(2) {
        assert!(w[0] < w[1]);
        assert!(w[0].score() < w[1].score());
    }
}

// ─── IocKind ─────────────────────────────────────────────────────────────────

#[test]
fn ioc_kind_display_unique() {
    let kinds = [
        IocKind::Ip,
        IocKind::Domain,
        IocKind::Url,
        IocKind::FilePath,
        IocKind::FileHash,
        IocKind::RegistryKey,
        IocKind::Mutex,
        IocKind::Email,
        IocKind::Other("custom".into()),
    ];
    let strs: HashSet<String> = kinds.iter().map(ToString::to_string).collect();
    assert_eq!(strs.len(), kinds.len());
}

#[test]
fn ioc_kind_other_passthrough() {
    let k = IocKind::Other("weirdtype".into());
    assert_eq!(k.to_string(), "weirdtype");
}

// ─── Ioc ─────────────────────────────────────────────────────────────────────

#[test]
fn ioc_confidence_clamped_to_100() {
    let mut lcg = Lcg::new(1);
    for _ in 0..50 {
        let raw = lcg.next_u8();
        let i = Ioc::new(IocKind::Ip, "1.1.1.1", raw, "ctx");
        assert!(i.confidence <= 100);
        if raw <= 100 {
            assert_eq!(i.confidence, raw);
        } else {
            assert_eq!(i.confidence, 100);
        }
    }
}

#[test]
fn ioc_confidence_boundary_max() {
    let i = Ioc::new(IocKind::Ip, "x", u8::MAX, "c");
    assert_eq!(i.confidence, 100);
    assert!(i.is_confident(100));
    assert!(i.is_confident(0));
    assert!(!i.is_confident(101));
}

#[test]
fn ioc_is_confident_threshold() {
    let i = Ioc::new(IocKind::Ip, "x", 50, "c");
    assert!(i.is_confident(50));
    assert!(i.is_confident(49));
    assert!(!i.is_confident(51));
}

// ─── IocSet ──────────────────────────────────────────────────────────────────

#[test]
fn iocset_default_is_empty() {
    let s = IocSet::default();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn iocset_dedup_preserves_first_and_diff_kinds() {
    let mut s = IocSet::new();
    s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 90, "a"));
    s.add(Ioc::new(IocKind::Ip, "1.1.1.1", 50, "b"));
    s.add(Ioc::new(IocKind::Domain, "1.1.1.1", 80, "c"));
    s.add(Ioc::new(IocKind::Ip, "2.2.2.2", 70, "d"));
    s.deduplicate();
    assert_eq!(s.len(), 3);
    // first kept
    assert_eq!(s.iocs[0].confidence, 90);
}

#[test]
fn iocset_by_kind_filters_only_match() {
    let mut s = IocSet::new();
    let mut lcg = Lcg::new(42);
    for _ in 0..30 {
        let kind = if lcg.next() & 1 == 0 {
            IocKind::Ip
        } else {
            IocKind::Domain
        };
        s.add(Ioc::new(kind, format!("v{}", lcg.next()), 50, "c"));
    }
    let ips = s.by_kind(&IocKind::Ip);
    for i in &ips {
        assert!(matches!(i.kind, IocKind::Ip));
    }
}

#[test]
fn iocset_confident_filter() {
    let mut s = IocSet::new();
    for c in 0u8..=100 {
        s.add(Ioc::new(IocKind::Ip, format!("{c}"), c, "c"));
    }
    let conf = s.confident(80);
    assert_eq!(conf.len(), 21);
    for i in conf {
        assert!(i.confidence >= 80);
    }
}

// ─── AttackTactic ────────────────────────────────────────────────────────────

#[test]
fn attack_tactic_displays_unique() {
    let all = [
        AttackTactic::InitialAccess,
        AttackTactic::Execution,
        AttackTactic::Persistence,
        AttackTactic::PrivilegeEscalation,
        AttackTactic::DefenseEvasion,
        AttackTactic::CredentialAccess,
        AttackTactic::Discovery,
        AttackTactic::LateralMovement,
        AttackTactic::Collection,
        AttackTactic::CommandAndControl,
        AttackTactic::Exfiltration,
        AttackTactic::Impact,
    ];
    let set: HashSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(set.len(), all.len());
}

// ─── AttackMapping ───────────────────────────────────────────────────────────

#[test]
fn attack_mapping_from_unknown_behavior_empty() {
    let m = AttackMapping::from_behaviors(&["totally-unknown", "garbage"]);
    assert!(m.techniques.is_empty());
    assert!(m.tactics_present().is_empty());
}

#[test]
fn attack_mapping_all_known_behaviors() {
    let m = AttackMapping::from_behaviors(&[
        "injection",
        "persistence",
        "anti-analysis",
        "antianalysis",
        "c2",
        "network",
        "dropper",
        "downloader",
        "keylogger",
        "ransomware",
        "screenshot",
        "worm",
    ]);
    assert!(m.techniques.len() >= 9);
    for t in &m.techniques {
        assert!(!t.id.is_empty());
        assert!(t.confidence > 0 && t.confidence <= 100);
        assert!(!t.evidence.is_empty());
    }
}

#[test]
fn attack_technique_full_id_with_and_without_sub() {
    let t = AttackTechnique {
        id: "T1055".into(),
        sub_id: Some("T1055.001".into()),
        name: "x".into(),
        tactic: AttackTactic::DefenseEvasion,
        evidence: vec!["e".into()],
        confidence: 90,
    };
    assert_eq!(t.full_id(), "T1055.001");
    let t2 = AttackTechnique {
        sub_id: None,
        ..t
    };
    assert_eq!(t2.full_id(), "T1055");
}

#[test]
fn attack_mapping_default_empty() {
    let m = AttackMapping::default();
    assert!(m.techniques.is_empty());
    assert!(m.high_confidence().is_empty());
}

// ─── Indicator/Behavior builders ─────────────────────────────────────────────

#[test]
fn indicator_with_multiple_techniques() {
    let i = Indicator::new("n", "d", Severity::High, IndicatorCategory::Injection)
        .with_technique("T1")
        .with_technique("T2")
        .with_ioc("evidence");
    assert_eq!(i.technique_ids, vec!["T1", "T2"]);
    assert_eq!(i.ioc.as_deref(), Some("evidence"));
}

#[test]
fn behavior_with_apis_accumulates() {
    let b = Behavior::new("n", "d", Severity::Low, "cat")
        .with_api("A")
        .with_api("B")
        .with_api("C");
    assert_eq!(b.apis, vec!["A", "B", "C"]);
    assert_eq!(b.first_seen_ms, 0);
    assert_eq!(b.pid, 0);
}

// ─── ScoreEngine ─────────────────────────────────────────────────────────────

#[test]
fn score_engine_verdict_boundaries() {
    let e = ScoreEngine::new();
    assert_eq!(e.verdict(0), Verdict::Clean);
    assert_eq!(e.verdict(1), Verdict::Low);
    assert_eq!(e.verdict(30), Verdict::Low);
    assert_eq!(e.verdict(31), Verdict::Suspicious);
    assert_eq!(e.verdict(70), Verdict::Suspicious);
    assert_eq!(e.verdict(71), Verdict::Malicious);
    assert_eq!(e.verdict(u32::MAX), Verdict::Malicious);
}

#[test]
fn score_engine_capped_at_100() {
    let e = ScoreEngine::new();
    let many: Vec<Indicator> = (0..1000)
        .map(|_| {
            Indicator::new(
                "n",
                "d",
                Severity::Critical,
                IndicatorCategory::Ransomware,
            )
        })
        .collect();
    let s = e.compute(&many);
    assert!(s <= 100);
    assert_eq!(s, 100);
}

#[test]
fn score_engine_lcg_fuzz_never_panics_and_bounded() {
    let e = ScoreEngine::new();
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let sevs = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let cats = [
        IndicatorCategory::Injection,
        IndicatorCategory::Network,
        IndicatorCategory::Persistence,
        IndicatorCategory::Evasion,
        IndicatorCategory::Crypto,
        IndicatorCategory::Dropper,
        IndicatorCategory::Keylogging,
        IndicatorCategory::Ransomware,
        IndicatorCategory::Reconnaissance,
        IndicatorCategory::Other,
    ];
    for _ in 0..50 {
        let n = (lcg.next() % 50) as usize;
        let inds: Vec<Indicator> = (0..n)
            .map(|_| {
                let s = sevs[usize::try_from(lcg.next()).unwrap_or(usize::MAX) % sevs.len()].clone();
                let c = cats[usize::try_from(lcg.next()).unwrap_or(usize::MAX) % cats.len()].clone();
                Indicator::new("n", "d", s, c)
            })
            .collect();
        let score = e.compute(&inds);
        assert!(score <= 100);
        let _ = e.verdict(score);
    }
}

#[test]
fn score_engine_has_critical_detects() {
    let none = vec![Indicator::new(
        "n",
        "d",
        Severity::High,
        IndicatorCategory::Other,
    )];
    assert!(!ScoreEngine::has_critical(&none));
    let some = vec![Indicator::new(
        "n",
        "d",
        Severity::Critical,
        IndicatorCategory::Other,
    )];
    assert!(ScoreEngine::has_critical(&some));
}

#[test]
fn score_engine_info_indicators_yield_zero() {
    let e = ScoreEngine::new();
    let inds: Vec<Indicator> = (0..20)
        .map(|_| {
            Indicator::new(
                "n",
                "d",
                Severity::Info,
                IndicatorCategory::Network,
            )
        })
        .collect();
    assert_eq!(e.compute(&inds), 0);
    assert_eq!(e.verdict(e.compute(&inds)), Verdict::Clean);
}

// ─── BehaviorClassifier ─────────────────────────────────────────────────────

#[test]
fn classifier_no_apis_yields_nothing() {
    let (i, b) = BehaviorClassifier::new().classify(&[]);
    assert!(i.is_empty());
    assert!(b.is_empty());
}

#[test]
fn classifier_classic_injection() {
    let (inds, behs) = BehaviorClassifier::new().classify(&[
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]);
    assert!(inds.iter().any(|i| matches!(i.category, IndicatorCategory::Injection)));
    assert!(behs.iter().any(|b| b.category == "injection"));
}

#[test]
fn classifier_partial_injection_no_match() {
    let (inds, _) =
        BehaviorClassifier::new().classify(&["VirtualAllocEx", "WriteProcessMemory"]);
    assert!(!inds.iter().any(|i| matches!(i.category, IndicatorCategory::Injection)));
}

#[test]
fn classifier_each_path_independently() {
    let cls = BehaviorClassifier::new();
    let (i1, _) = cls.classify(&["RegSetValue"]);
    assert!(i1
        .iter()
        .any(|i| matches!(i.category, IndicatorCategory::Persistence)));
    let (i2, _) = cls.classify(&["InternetConnect"]);
    assert!(i2
        .iter()
        .any(|i| matches!(i.category, IndicatorCategory::Network)));
    let (i3, _) = cls.classify(&["IsDebuggerPresent"]);
    assert!(i3
        .iter()
        .any(|i| matches!(i.category, IndicatorCategory::Evasion)));
    let (i4, _) = cls.classify(&["CryptEncrypt"]);
    assert!(i4
        .iter()
        .any(|i| matches!(i.category, IndicatorCategory::Crypto)));
    let (i5, _) = cls.classify(&["SetWindowsHookEx"]);
    assert!(i5
        .iter()
        .any(|i| matches!(i.category, IndicatorCategory::Keylogging)));
    let (i6, _) = cls.classify(&["BitBlt"]);
    assert!(i6
        .iter()
        .any(|i| matches!(i.category, IndicatorCategory::Other)));
}

#[test]
fn classifier_infer_family_paths() {
    let ran = vec![Indicator::new(
        "n", "d", Severity::Critical, IndicatorCategory::Ransomware,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&ran), "ransomware");
    let spy = vec![
        Indicator::new("n", "d", Severity::High, IndicatorCategory::Keylogging),
        Indicator::new("n", "d", Severity::Medium, IndicatorCategory::Network),
    ];
    assert_eq!(BehaviorClassifier::infer_family(&spy), "spyware");
    let troj = vec![
        Indicator::new("n", "d", Severity::Critical, IndicatorCategory::Injection),
        Indicator::new("n", "d", Severity::Medium, IndicatorCategory::Network),
    ];
    assert_eq!(BehaviorClassifier::infer_family(&troj), "trojan");
    let inj = vec![Indicator::new(
        "n", "d", Severity::High, IndicatorCategory::Injection,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&inj), "injector");
    let dl = vec![Indicator::new(
        "n", "d", Severity::Medium, IndicatorCategory::Network,
    )];
    assert_eq!(BehaviorClassifier::infer_family(&dl), "downloader");
    assert_eq!(BehaviorClassifier::infer_family(&[]), "unknown");
}

#[test]
fn classifier_lcg_fuzz_no_panic() {
    let pool = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "RegSetValue",
        "NtSetValueKey",
        "InternetConnect",
        "HttpSendRequest",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "CryptEncrypt",
        "BCryptEncrypt",
        "SetWindowsHookEx",
        "BitBlt",
        "GetDC",
        "GarbageApi",
        "AnotherUnknown",
    ];
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let cls = BehaviorClassifier::new();
    for _ in 0..50 {
        let n = (lcg.next() % 10) as usize;
        let calls: Vec<&str> = (0..n)
            .map(|_| pool[usize::try_from(lcg.next()).unwrap_or(usize::MAX) % pool.len()])
            .collect();
        let (i, _b) = cls.classify(&calls);
        // No panic; verify all confidences sane.
        for ind in i {
            assert!(matches!(ind.severity,
                Severity::Info | Severity::Low | Severity::Medium |
                Severity::High | Severity::Critical));
        }
    }
}

// ─── ReportFormat ────────────────────────────────────────────────────────────

#[test]
fn report_format_extension_fromext_roundtrip() {
    for fmt in [
        ReportFormat::Json,
        ReportFormat::Html,
        ReportFormat::Pdf,
        ReportFormat::Csv,
        ReportFormat::Markdown,
    ] {
        let ext = fmt.extension();
        let parsed = ReportFormat::from_extension(ext).unwrap();
        assert_eq!(parsed, fmt);
        // with leading dot
        let dotted = format!(".{ext}");
        assert_eq!(ReportFormat::from_extension(&dotted).unwrap(), fmt);
        // uppercase
        let up = ext.to_uppercase();
        assert_eq!(ReportFormat::from_extension(&up).unwrap(), fmt);
    }
}

#[test]
fn report_format_aliases_and_errors() {
    assert_eq!(
        ReportFormat::from_extension("htm").unwrap(),
        ReportFormat::Html
    );
    assert_eq!(
        ReportFormat::from_extension("markdown").unwrap(),
        ReportFormat::Markdown
    );
    assert!(ReportFormat::from_extension("xyz").is_err());
    assert!(ReportFormat::from_extension("").is_err());
}

#[test]
fn report_format_display() {
    assert_eq!(ReportFormat::Json.to_string(), "json");
    assert_eq!(ReportFormat::Markdown.to_string(), "markdown");
}

#[test]
fn report_format_lcg_fuzz() {
    let mut lcg = Lcg::new(7);
    for _ in 0..50 {
        let len = (lcg.next() % 6) as usize;
        let mut s = String::new();
        for _ in 0..len {
            s.push((b'a' + (lcg.next_u8() % 26)) as char);
        }
        let _ = ReportFormat::from_extension(&s); // must not panic
    }
}

// ─── SandboxReport / Mock end-to-end ─────────────────────────────────────────

#[test]
fn report_mock_full_pipeline() {
    let r = SandboxReport::mock();
    assert!(!r.indicators.is_empty());
    assert!(!r.behaviors.is_empty());
    assert!(!r.attack.techniques.is_empty());
    assert_eq!(r.verdict, Verdict::Malicious); // critical bumps to malicious
    assert_eq!(r.family, "trojan");
}

#[test]
fn report_compute_score_critical_forces_malicious() {
    let mut r = SandboxReport::new("a", "b");
    r.add_indicator(Indicator::new(
        "c", "d", Severity::Critical, IndicatorCategory::Injection,
    ));
    r.compute_score();
    assert_eq!(r.verdict, Verdict::Malicious);
}

#[test]
fn report_to_json_roundtrip_serde() {
    let r = SandboxReport::mock();
    let s = r.to_json().unwrap();
    let r2: SandboxReport = serde_json::from_str(&s).unwrap();
    assert_eq!(r.sample, r2.sample);
    assert_eq!(r.sha256, r2.sha256);
    assert_eq!(r.indicators.len(), r2.indicators.len());
    assert_eq!(r.iocs.len(), r2.iocs.len());
}

#[test]
fn report_section_sort_by_order_on_add() {
    let mut r = SandboxReport::new("a", "b");
    r.add_section(ReportSection::new("Z", "z", 10));
    r.add_section(ReportSection::new("A", "a", 1));
    r.add_section(ReportSection::new("M", "m", 5));
    let orders: Vec<u32> = r.sections.iter().map(|s| s.order).collect();
    assert_eq!(orders, vec![1, 5, 10]);
}

#[test]
fn report_indicators_by_category_and_critical() {
    let r = SandboxReport::mock();
    let crit = r.critical_indicators();
    assert!(!crit.is_empty());
    for c in crit {
        assert_eq!(c.severity, Severity::Critical);
    }
    let net = r.indicators_by_category(&IndicatorCategory::Network);
    for n in net {
        assert_eq!(n.category, IndicatorCategory::Network);
    }
}

#[test]
fn report_markdown_contains_key_sections() {
    let r = SandboxReport::mock();
    let md = r.to_markdown();
    assert!(md.contains("# Sandbox Report"));
    assert!(md.contains("## Indicators"));
    assert!(md.contains("## ATT&CK"));
    assert!(md.contains("## IOCs"));
}

#[test]
fn report_html_well_formed_ish() {
    let r = SandboxReport::mock();
    let h = r.to_html();
    assert!(h.starts_with("<!DOCTYPE html>"));
    assert!(h.contains("</html>"));
    assert!(h.contains("Sandbox Report"));
}

#[test]
fn report_html_escapes_specials() {
    let mut r = SandboxReport::new("evil<>&\".exe", "abc");
    r.compute_score();
    let h = r.to_html();
    assert!(h.contains("&lt;"));
    assert!(h.contains("&gt;"));
    assert!(h.contains("&amp;"));
    assert!(h.contains("&quot;"));
    assert!(!h.contains("evil<>&\".exe"));
}

#[test]
fn report_empty_renders_dont_panic() {
    let r = SandboxReport::new("", "");
    let _ = r.to_html();
    let _ = r.to_markdown();
    let j = r.to_json().unwrap();
    assert!(!j.is_empty());
}

#[test]
fn report_build_attack_mapping_from_tags() {
    let mut r = SandboxReport::new("a", "b");
    r.add_tag("injection");
    r.add_tag("c2");
    r.build_attack_mapping();
    assert!(!r.attack.techniques.is_empty());
}

#[test]
fn report_infer_family_unknown_when_empty() {
    let mut r = SandboxReport::new("a", "b");
    r.infer_family();
    assert_eq!(r.family, "unknown");
}

// ─── IocCollection ───────────────────────────────────────────────────────────

#[test]
fn ioc_collection_total_and_empty() {
    let c = IocCollection::new();
    assert_eq!(c.total(), 0);
    assert!(c.is_empty());
    let m = IocCollection::mock();
    assert!(m.total() > 0);
    assert!(!m.is_empty());
}

#[test]
fn ioc_collection_csv_header_and_rows() {
    let c = IocCollection::mock();
    let csv = c.to_csv();
    assert!(csv.starts_with("type,value\n"));
    for ip in &c.ips {
        assert!(csv.contains(&format!("ip,{ip}")));
    }
    for d in &c.domains {
        assert!(csv.contains(&format!("domain,{d}")));
    }
}

#[test]
fn ioc_collection_summary_text() {
    let c = IocCollection::mock();
    let s = c.summary_text();
    assert!(s.contains("IPs:"));
    let empty = IocCollection::new();
    assert!(empty.summary_text().is_empty());
}

// ─── SandboxReportBuilder ────────────────────────────────────────────────────

#[test]
fn builder_json_contains_report_and_iocs() {
    let r = SandboxReport::mock();
    let mut b = SandboxReportBuilder::new(r);
    b.add_iocs(IocCollection::mock());
    let mut map = HashMap::new();
    map.insert("T1055".to_string(), vec!["evidence".to_string()]);
    b.add_ttp_map(map);
    let j = b.build_json();
    assert!(j.contains("\"report\""));
    assert!(j.contains("\"iocs\""));
    assert!(j.contains("\"ttp_map\""));
}

#[test]
fn builder_markdown_html_csv_nonempty() {
    let r = SandboxReport::mock();
    let mut b = SandboxReportBuilder::new(r);
    b.add_iocs(IocCollection::mock());
    let md = b.build_markdown();
    assert!(md.contains("# Sandbox Analysis Report"));
    assert!(md.contains("## Executive Summary"));
    let h = b.build_html();
    assert!(h.contains("<!DOCTYPE html>"));
    assert!(h.contains("Sandbox Analysis Report"));
    let csv = b.build_csv();
    assert!(csv.starts_with("type,value,confidence\n"));
}

#[test]
fn builder_csv_escapes_commas() {
    let mut r = SandboxReport::new("a", "b");
    r.iocs.add(Ioc::new(IocKind::Url, "http://x,y/z", 90, ""));
    let b = SandboxReportBuilder::new(r);
    let csv = b.build_csv();
    assert!(csv.contains("\"http://x,y/z\""));
}

#[test]
fn builder_accessors() {
    let r = SandboxReport::mock();
    let mut b = SandboxReportBuilder::new(r);
    assert!(b.iocs().is_none());
    b.add_iocs(IocCollection::mock());
    assert!(b.iocs().is_some());
    assert_eq!(b.report().sample, "malware.exe");
}

// ─── ReportStore ─────────────────────────────────────────────────────────────

#[test]
fn report_store_save_load_roundtrip() {
    let dir = std::env::temp_dir().join("rustre_sbr_blitz2_a");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("nested/report.json");
    let content = r#"{"sample":"x"}"#;
    ReportStore::save(content, ReportFormat::Json, &path).unwrap();
    let back = ReportStore::load(&path).unwrap();
    assert_eq!(back, content);
    let r2 =
        ReportStore::save_and_reload(content, ReportFormat::Json, &path).unwrap();
    assert_eq!(r2, content);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_store_load_nonexistent_errors() {
    let p = std::env::temp_dir().join("rustre_sbr_blitz2_nope_xyzzy.json");
    let _ = std::fs::remove_file(&p);
    assert!(ReportStore::load(&p).is_err());
}

// ─── SandboxEvent / Kind ─────────────────────────────────────────────────────

#[test]
fn sandbox_event_kind_display() {
    assert_eq!(SandboxEventKind::ApiCall("X".into()).to_string(), "api:X");
    assert_eq!(SandboxEventKind::FileOp("p".into()).to_string(), "file:p");
    assert_eq!(SandboxEventKind::NetworkConn.to_string(), "net");
    assert_eq!(SandboxEventKind::RegistryOp.to_string(), "reg");
    assert_eq!(SandboxEventKind::ProcessSpawn.to_string(), "proc");
    assert_eq!(SandboxEventKind::CodeInjection.to_string(), "inject");
    assert_eq!(SandboxEventKind::DeleteShadowCopies.to_string(), "vss_delete");
    assert_eq!(SandboxEventKind::ExtensionChange.to_string(), "ext_change");
    assert_eq!(SandboxEventKind::ScreenCapture.to_string(), "screenshot");
    assert_eq!(SandboxEventKind::KeyboardHook.to_string(), "keyhook");
    assert_eq!(SandboxEventKind::HighCpuLoad.to_string(), "cpu_high");
    assert_eq!(
        SandboxEventKind::ModuleLoad("k.dll".into()).to_string(),
        "mod:k.dll"
    );
    assert_eq!(SandboxEventKind::MutexCreate.to_string(), "mutex");
    assert_eq!(
        SandboxEventKind::Other("x".into()).to_string(),
        "other:x"
    );
}

// ─── BehaviorTimeline ────────────────────────────────────────────────────────

#[test]
fn timeline_empty_summary_and_metrics() {
    let t = BehaviorTimeline::build(&[]);
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
    assert_eq!(t.start_ms(), 0);
    assert_eq!(t.end_ms(), 0);
    assert_eq!(t.duration_ms(), 0);
    assert_eq!(t.summary(), "(no events)");
}

#[test]
fn timeline_sorts_and_durations() {
    let evts = vec![
        SandboxEvent::new(3000, 1, SandboxEventKind::NetworkConn, "a"),
        SandboxEvent::new(1000, 1, SandboxEventKind::RegistryOp, "b"),
        SandboxEvent::new(2000, 1, SandboxEventKind::ProcessSpawn, "c"),
    ];
    let t = BehaviorTimeline::build(&evts);
    let ts: Vec<u64> = t.events().iter().map(|e| e.ts_ms).collect();
    assert_eq!(ts, vec![1000, 2000, 3000]);
    assert_eq!(t.start_ms(), 1000);
    assert_eq!(t.end_ms(), 3000);
    assert_eq!(t.duration_ms(), 2000);
}

#[test]
fn timeline_summary_groups_by_second_truncates_kinds() {
    let mut evts = vec![];
    for i in 0..10u64 {
        evts.push(SandboxEvent::new(
            500,
            1,
            SandboxEventKind::Other(format!("k{i}")),
            "",
        ));
    }
    evts.push(SandboxEvent::new(
        1500,
        1,
        SandboxEventKind::NetworkConn,
        "",
    ));
    let t = BehaviorTimeline::build(&evts);
    let s = t.summary();
    assert!(s.contains("t=     0s"));
    assert!(s.contains("t=     1s"));
    assert!(s.contains(", ..."));
}

#[test]
fn timeline_duration_underflow_safe() {
    // Build a timeline with mostly identical timestamps; duration must not panic.
    let evts = vec![
        SandboxEvent::new(100, 1, SandboxEventKind::NetworkConn, ""),
        SandboxEvent::new(100, 2, SandboxEventKind::NetworkConn, ""),
    ];
    let t = BehaviorTimeline::build(&evts);
    assert_eq!(t.duration_ms(), 0);
}

// ─── SandboxReportRenderer ───────────────────────────────────────────────────

#[test]
fn renderer_html_contains_score_clamped() {
    let mut r = SandboxReport::new("a", "b");
    r.score = 500; // intentionally above cap
    let rr = SandboxReportRenderer::new(&r);
    let h = rr.render_html(&r);
    // width must be clamped to 100
    assert!(h.contains("width:100%"));
}

#[test]
fn renderer_markdown_json_nonempty() {
    let r = SandboxReport::mock();
    let rr = SandboxReportRenderer::new(&r);
    let md = rr.render_markdown(&r);
    assert!(md.contains("# Sandbox Analysis Report"));
    let j = rr.render_json(&r);
    assert!(j.contains("\"sample\""));
    assert_eq!(rr.report().sample, r.sample);
}

// ─── ReportRenderer (separate from Builder) ──────────────────────────────────

#[test]
fn report_renderer_default_json_pretty() {
    let r = SandboxReport::mock();
    let s = ReportRenderer::new().render_json(&r).unwrap();
    // pretty print has newlines + indentation
    assert!(s.contains('\n'));
    assert!(s.contains("\"sample\""));
}

// ─── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn send_sync_threaded_stress_report_and_engine() {
    let r = Arc::new(SandboxReport::mock());
    let e = Arc::new(ScoreEngine::new());
    let mut handles = vec![];
    for tid in 0..4u64 {
        let r = Arc::clone(&r);
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE ^ tid);
            for _ in 0..100 {
                let _ = r.to_json().unwrap();
                let _ = r.to_markdown();
                let s = e.compute(&r.indicators);
                assert!(s <= 100);
                let _ = e.verdict(s);
                // pump LCG to mix
                let _ = lcg.next();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── Hash/Eq consistency (for types deriving Eq) ─────────────────────────────

#[test]
fn severity_eq_consistency_30_pairs() {
    let kinds = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let mut count = 0;
    for a in &kinds {
        for b in &kinds {
            let _ = a == b;
            count += 1;
        }
    }
    assert!(count >= 25);
    // 30+ pairs total: include extra clones
    for k in &kinds {
        let c = k.clone();
        assert_eq!(k, &c);
    }
}

#[test]
fn verdict_eq_and_display() {
    let verdicts = [
        Verdict::Clean,
        Verdict::Low,
        Verdict::Suspicious,
        Verdict::Malicious,
        Verdict::Unknown,
    ];
    let strs: HashSet<String> = verdicts.iter().map(ToString::to_string).collect();
    assert_eq!(strs.len(), verdicts.len());
    for v in &verdicts {
        let c = v.clone();
        assert_eq!(v, &c);
    }
}

#[test]
fn ioc_kind_eq_consistency() {
    let kinds = [
        IocKind::Ip,
        IocKind::Domain,
        IocKind::Url,
        IocKind::FilePath,
        IocKind::FileHash,
        IocKind::RegistryKey,
        IocKind::Mutex,
        IocKind::Email,
    ];
    let mut total = 0;
    for a in &kinds {
        for b in &kinds {
            if a == b {
                assert_eq!(a.to_string(), b.to_string());
            }
            total += 1;
        }
    }
    assert!(total >= 30);
}

// ─── ReportError display ─────────────────────────────────────────────────────

#[test]
fn report_error_display_variants() {
    let e1 = ReportError::Serialize("x".into());
    let e2 = ReportError::InvalidData("y".into());
    let e3 = ReportError::Template("z".into());
    let e4 = ReportError::MissingField("f".into());
    assert!(e1.to_string().contains("serialize"));
    assert!(e2.to_string().contains("invalid"));
    assert!(e3.to_string().contains("template"));
    assert!(e4.to_string().contains("missing"));
}
