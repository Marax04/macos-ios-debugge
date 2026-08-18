//! Exhaustive blitz test suite for rustre-ti-vt. Surfaces bugs in
//! public APIs across cache, error, models, `rate_limit`, `threat_score`,
//! `vt_reputation`, and root-level lib.rs items.

use std::collections::HashMap;
use std::time::Duration;

use rustre_ti_vt::cache::{CacheKind, VtCache};
use rustre_ti_vt::error::VtError;
use rustre_ti_vt::models::{
    VtAnalysisId, VtAnalysisReport, VtAnalysisStatus, VtDomainReport, VtEngineResult,
    VtFileReport, VtIpReport, VtStats, VtUrlReport,
};
use rustre_ti_vt::rate_limit::VtRateLimiter;
use rustre_ti_vt::threat_score::{
    batch_score, BatchScoreSummary, SandboxVerdict, ScoringWeights, ThreatLevel as TsLevel,
    ThreatScorer, ThreatSignals,
};
use rustre_ti_vt::vt_reputation::{
    CategoryScore, ReputationScore, ThreatLevel as RepLevel, VendorVote, VtReputation,
};
use rustre_ti_vt::{
    mock_file_report, mock_ip_report, VirusTotalClient, VtAVResult, VtAnalysisStats, VtApiKey,
    VtBehavior, VtConnection, VtDnsLookup, VtFileReportFull, VtPopularThreatClassification,
    VtRelationshipType, VtSearchQuery, VtThreatClassItem, VtTokenBucketLimiter,
};
use serde_json::json;

// ─────────────────────────── models::VtStats ────────────────────────────

#[test]
fn vtstats_total_sum() {
    let s = VtStats { malicious: 1, suspicious: 2, undetected: 3, harmless: 4, timeout: 5 };
    assert_eq!(s.total(), 15);
}

#[test]
fn vtstats_default_zero_total() {
    assert_eq!(VtStats::default().total(), 0);
}

#[test]
fn vtstats_ratio_zero_div() {
    assert_eq!(VtStats::default().detection_ratio(), 0.0);
}

#[test]
fn vtstats_ratio_full_malicious() {
    let s = VtStats { malicious: 10, ..Default::default() };
    assert!((s.detection_ratio() - 1.0).abs() < f32::EPSILON);
}

#[test]
fn vtstats_ratio_includes_suspicious() {
    let s = VtStats { malicious: 1, suspicious: 1, undetected: 2, harmless: 0, timeout: 0 };
    assert!((s.detection_ratio() - 0.5).abs() < 1e-6);
}

#[test]
fn vt_file_report_score_zero() {
    let r = VtFileReport {
        sha256: "a".into(), md5: "b".into(), sha1: "c".into(),
        name: None, size: 0, type_tag: "x".into(),
        last_analysis_stats: VtStats::default(),
        last_analysis_results: HashMap::new(),
        first_submission_date: 0, tags: vec![],
    };
    assert!(!r.is_malicious());
    assert_eq!(r.vt_score(), 0.0);
}

#[test]
fn vt_analysis_id_display_and_str() {
    let a = VtAnalysisId::new("abc");
    assert_eq!(a.as_str(), "abc");
    assert_eq!(format!("{a}"), "abc");
}

#[test]
fn vt_analysis_status_serde_known() {
    let s: VtAnalysisStatus = serde_json::from_str("\"completed\"").unwrap();
    assert_eq!(s, VtAnalysisStatus::Completed);
    assert_eq!(format!("{s}"), "completed");
}

#[test]
fn vt_analysis_status_serde_unknown_falls_back() {
    let s: VtAnalysisStatus = serde_json::from_str("\"bogus_state\"").unwrap();
    assert_eq!(s, VtAnalysisStatus::Unknown);
}

#[test]
fn vt_analysis_status_serde_queued() {
    let s: VtAnalysisStatus = serde_json::from_str("\"queued\"").unwrap();
    assert_eq!(s, VtAnalysisStatus::Queued);
}

#[test]
fn vt_analysis_report_is_complete_and_ratio() {
    let mut stats = VtStats::default();
    stats.malicious = 3;
    stats.undetected = 7;
    let r = VtAnalysisReport {
        id: "x".into(),
        status: VtAnalysisStatus::Completed,
        results: HashMap::new(),
        stats,
        sha256: None,
    };
    assert!(r.is_complete());
    assert!(r.is_malicious());
    assert_eq!(r.detection_ratio(), "3/10");
}

#[test]
fn vt_ip_report_roundtrip() {
    let r = VtIpReport {
        ip_address: "1.2.3.4".into(),
        country: Some("US".into()),
        as_owner: None,
        asn: Some(15169),
        last_analysis_stats: VtStats::default(),
        tags: vec!["scanner".into()],
    };
    let j = serde_json::to_string(&r).unwrap();
    let d: VtIpReport = serde_json::from_str(&j).unwrap();
    assert_eq!(d.ip_address, "1.2.3.4");
    assert_eq!(d.asn, Some(15169));
}

#[test]
fn vt_domain_report_roundtrip() {
    let mut cats = HashMap::new();
    cats.insert("forcepoint".into(), "malicious".into());
    let r = VtDomainReport {
        domain: "evil.com".into(),
        registrar: None,
        creation_date: Some(1_700_000_000),
        last_analysis_stats: VtStats::default(),
        tags: vec![],
        categories: cats,
    };
    let j = serde_json::to_string(&r).unwrap();
    let d: VtDomainReport = serde_json::from_str(&j).unwrap();
    assert_eq!(d.categories["forcepoint"], "malicious");
}

#[test]
fn vt_url_report_construct() {
    let r = VtUrlReport {
        url: "http://x".into(), final_url: None, title: None,
        last_analysis_stats: VtStats::default(),
        tags: vec![], threat_names: vec!["a".into()],
    };
    assert_eq!(r.threat_names.len(), 1);
}

#[test]
fn vt_engine_result_serde() {
    let e = VtEngineResult {
        category: "malicious".into(), engine_name: "X".into(),
        result: Some("Trojan.A".into()), method: "sig".into(),
    };
    let j = serde_json::to_string(&e).unwrap();
    let d: VtEngineResult = serde_json::from_str(&j).unwrap();
    assert_eq!(d.engine_name, "X");
}

// ─────────────────────────── error ──────────────────────────────────────

#[test]
fn vt_error_constructors() {
    let n = VtError::not_found("x");
    assert!(matches!(n, VtError::NotFound(_)));
    let i = VtError::invalid_response("bad");
    assert!(matches!(i, VtError::InvalidResponse(_)));
}

#[test]
fn vt_error_display_http() {
    let e = VtError::Http { status: 503, body: "oops".into() };
    let s = format!("{e}");
    assert!(s.contains("503"));
    assert!(s.contains("oops"));
}

#[test]
fn vt_error_into_ti_error_variants() {
    use rustre_threatintel::TiError;
    let t: TiError = VtError::NotFound("a".into()).into();
    assert!(matches!(t, TiError::NotFound(_)));
    let t: TiError = VtError::RateLimited { retry_after_secs: 1 }.into();
    assert!(matches!(t, TiError::RateLimit(_)));
    let t: TiError = VtError::InvalidResponse("p".into()).into();
    assert!(matches!(t, TiError::Parse(_)));
    let t: TiError = VtError::Http { status: 500, body: String::new() }.into();
    assert!(matches!(t, TiError::Http(_)));
}

// ─────────────────────────── rate_limit ─────────────────────────────────

#[test]
fn ratelimit_default_free_tier_has_4() {
    let l = VtRateLimiter::default_free_tier();
    assert!((l.available_tokens() - 4.0).abs() < 0.01);
}

#[test]
fn ratelimit_acquire_until_empty() {
    let l = VtRateLimiter::new(3, 60); // 1/s
    assert!(l.try_acquire().is_ok());
    assert!(l.try_acquire().is_ok());
    assert!(l.try_acquire().is_ok());
    assert!(l.try_acquire().is_err());
}

#[test]
fn ratelimit_wait_under_1s() {
    let l = VtRateLimiter::new(1, 60);
    l.try_acquire().unwrap();
    let w = l.try_acquire().unwrap_err();
    assert!(w.as_secs_f64() <= 1.05);
}

#[test]
fn ratelimit_capacity_cap() {
    let l = VtRateLimiter::new(2, 6000); // refill 100/s
    std::thread::sleep(Duration::from_millis(50));
    let avail = l.available_tokens();
    assert!(avail <= 2.0 + 0.001, "must not exceed capacity, got {avail}");
}

// ─────────────────────────── cache ──────────────────────────────────────

fn mem_cache(ttl: u64) -> VtCache {
    VtCache::open_with_ttl(":memory:", ttl).unwrap()
}

#[test]
fn cache_roundtrip_all_kinds() {
    let c = mem_cache(3600);
    for (k, key) in [
        (CacheKind::File, "f"),
        (CacheKind::Ip, "1.1.1.1"),
        (CacheKind::Domain, "x.com"),
        (CacheKind::Url, "http://x"),
    ] {
        c.put(k, key, &json!({"k": key})).unwrap();
        let v = c.get(k, key).unwrap().unwrap();
        assert_eq!(v["k"], key);
    }
}

#[test]
fn cache_namespacing_kinds() {
    let c = mem_cache(3600);
    c.put(CacheKind::File, "same", &json!({"v": "file"})).unwrap();
    c.put(CacheKind::Ip, "same", &json!({"v": "ip"})).unwrap();
    assert_eq!(c.get(CacheKind::File, "same").unwrap().unwrap()["v"], "file");
    assert_eq!(c.get(CacheKind::Ip, "same").unwrap().unwrap()["v"], "ip");
}

#[test]
fn cache_invalidate_only_target() {
    let c = mem_cache(3600);
    c.put(CacheKind::File, "a", &json!(1)).unwrap();
    c.put(CacheKind::File, "b", &json!(2)).unwrap();
    c.invalidate(CacheKind::File, "a").unwrap();
    assert!(c.get(CacheKind::File, "a").unwrap().is_none());
    assert!(c.get(CacheKind::File, "b").unwrap().is_some());
}

#[test]
fn cache_purge_expired_returns_count() {
    let c = mem_cache(0); // everything expires
    c.put(CacheKind::File, "x", &json!(1)).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let purged = c.purge_expired().unwrap();
    assert!(purged >= 1, "should purge at least 1 expired row, got {purged}");
    assert!(c.get(CacheKind::File, "x").unwrap().is_none());
}

#[test]
fn cache_overwrite_updates_value() {
    let c = mem_cache(3600);
    c.put(CacheKind::Url, "u", &json!({"v": 1})).unwrap();
    c.put(CacheKind::Url, "u", &json!({"v": 2})).unwrap();
    assert_eq!(c.get(CacheKind::Url, "u").unwrap().unwrap()["v"], 2);
}

// ─────────────────────────── threat_score ───────────────────────────────

#[test]
fn ts_detection_ratio_div0() {
    assert_eq!(ThreatSignals::new().detection_ratio(), 0.0);
}

#[test]
fn ts_threat_level_thresholds() {
    assert_eq!(TsLevel::from_score(0), TsLevel::Clean);
    assert_eq!(TsLevel::from_score(15), TsLevel::Clean);
    assert_eq!(TsLevel::from_score(16), TsLevel::Suspicious);
    assert_eq!(TsLevel::from_score(35), TsLevel::Suspicious);
    assert_eq!(TsLevel::from_score(36), TsLevel::ProbablyMalicious);
    assert_eq!(TsLevel::from_score(60), TsLevel::ProbablyMalicious);
    assert_eq!(TsLevel::from_score(61), TsLevel::Malicious);
    assert_eq!(TsLevel::from_score(80), TsLevel::Malicious);
    assert_eq!(TsLevel::from_score(81), TsLevel::HighlyMalicious);
    assert_eq!(TsLevel::from_score(100), TsLevel::HighlyMalicious);
}

#[test]
fn ts_threat_level_as_str() {
    assert_eq!(TsLevel::Clean.as_str(), "clean");
    assert_eq!(TsLevel::Suspicious.as_str(), "suspicious");
    assert_eq!(TsLevel::HighlyMalicious.as_str(), "highly_malicious");
}

#[test]
fn ts_default_weights_sum_to_one() {
    assert!(ScoringWeights::default().is_valid());
}

#[test]
fn ts_av_heavy_weights_valid() {
    assert!(ScoringWeights::av_heavy().is_valid());
}

#[test]
fn ts_sandbox_heavy_weights_valid() {
    assert!(ScoringWeights::sandbox_heavy().is_valid());
}

#[test]
fn ts_sandbox_verdict_classification() {
    let m = SandboxVerdict { verdict: "malicious".into(), malware_family: None, confidence: Some(1.0) };
    assert!(m.is_malicious());
    assert!(!m.is_suspicious());
    assert!((m.weighted_score() - 1.0).abs() < 1e-9);

    let s = SandboxVerdict { verdict: "suspicious".into(), malware_family: None, confidence: Some(1.0) };
    assert!(s.is_suspicious());
    assert!((s.weighted_score() - 0.5).abs() < 1e-9);

    let c = SandboxVerdict { verdict: "clean".into(), malware_family: None, confidence: Some(1.0) };
    assert_eq!(c.weighted_score(), 0.0);
}

#[test]
fn ts_sandbox_verdict_default_confidence() {
    let m = SandboxVerdict { verdict: "malicious".into(), malware_family: None, confidence: None };
    assert!((m.weighted_score() - 0.8).abs() < 1e-9);
}

#[test]
fn ts_clean_low_score() {
    let s = ThreatSignals::new().with_detections(0, 70).with_community(50, 0, 100);
    let bd = ThreatScorer::new().score(&s);
    assert!(bd.final_score < 25, "clean score too high: {}", bd.final_score);
}

#[test]
fn ts_malicious_high_score() {
    let mut s = ThreatSignals::new().with_detections(60, 70).with_community(-90, 50, 0);
    s.threat_families = vec!["WannaCry".into()];
    s.sandbox_verdicts.insert("Cuckoo".into(), SandboxVerdict {
        verdict: "malicious".into(), malware_family: None, confidence: Some(0.95),
    });
    let bd = ThreatScorer::new().score(&s);
    assert!(bd.final_score > 60, "malicious score too low: {}", bd.final_score);
}

#[test]
fn ts_quick_score_matches_full() {
    let s = ThreatSignals::new().with_detections(30, 70);
    let scorer = ThreatScorer::new();
    assert_eq!(scorer.quick_score(&s), scorer.score(&s).final_score);
}

#[test]
fn ts_batch_score_preserves_ids_and_order() {
    let pairs: Vec<_> = (0..10)
        .map(|i| (format!("id{i}"), ThreatSignals::new().with_detections(i, 10)))
        .collect();
    let results = batch_score(&pairs, None);
    assert_eq!(results.len(), 10);
    for (i, (id, _)) in results.iter().enumerate() {
        assert_eq!(id, &format!("id{i}"));
    }
}

#[test]
fn ts_batch_summary_empty() {
    let s = BatchScoreSummary::from_scores(&[]);
    assert_eq!(s.total, 0);
    assert_eq!(s.mean_score, 0.0);
}

#[test]
fn ts_batch_summary_counts() {
    let pairs = vec![
        ("a".into(), ThreatSignals::new()),
        ("b".into(), {
            let mut s = ThreatSignals::new().with_detections(60, 70).with_community(-90, 100, 0);
            s.threat_families = vec!["X".into()];
            s
        }),
    ];
    let r = batch_score(&pairs, None);
    let sum = BatchScoreSummary::from_scores(&r);
    assert_eq!(sum.total, 2);
    assert!(sum.max_score >= sum.min_score);
}

#[test]
fn ts_age_penalty_for_first_seen() {
    let s = ThreatSignals::new();
    let bd = ThreatScorer::new().score(&s);
    // first_seen_utc is None => 0.8 age signal but small weight (0.05)
    // and detection is 0 ratio so detection_score is 0. Should still
    // be > 0 due to age contribution.
    assert!(bd.age_score > 0.5);
}

#[test]
fn ts_file_type_mismatch_flags() {
    let mut s = ThreatSignals::new();
    s.file_extension = Some("pdf".into());
    s.detected_mime = Some("application/x-dosexec".into());
    s.type_tag = Some("peexe".into());
    let bd = ThreatScorer::new().score(&s);
    assert!(bd.file_type_score >= 0.7, "expected mismatch flag, got {}", bd.file_type_score);
}

#[test]
fn ts_pe_match_no_mismatch() {
    let mut s = ThreatSignals::new();
    s.file_extension = Some("exe".into());
    s.detected_mime = Some("application/x-dosexec".into());
    s.type_tag = Some("peexe".into());
    s.file_size = Some(50_000);
    let bd = ThreatScorer::new().score(&s);
    // Should not contain the mismatch penalty 0.7
    assert!(bd.file_type_score < 0.5);
}

#[test]
fn ts_composite_within_0_1() {
    let mut s = ThreatSignals::new().with_detections(70, 70).with_community(-100, 1000, 0);
    s.threat_families = vec!["x".into()];
    s.sandbox_verdicts.insert("a".into(), SandboxVerdict {
        verdict: "malicious".into(), malware_family: None, confidence: Some(1.0),
    });
    let bd = ThreatScorer::new().score(&s);
    assert!(bd.composite_raw >= 0.0 && bd.composite_raw <= 1.0);
    assert!(bd.final_score <= 100);
}

// ─────────────────────────── vt_reputation ──────────────────────────────

#[test]
fn rep_threat_level_severity_order() {
    assert!(RepLevel::Clean.severity() < RepLevel::Critical.severity());
    assert_eq!(RepLevel::Clean.severity(), 0);
}

#[test]
fn rep_threat_level_from_ratio_boundaries() {
    assert_eq!(RepLevel::from_ratio(0.0), RepLevel::Clean);
    assert_eq!(RepLevel::from_ratio(0.01), RepLevel::Suspicious);
    assert_eq!(RepLevel::from_ratio(0.15), RepLevel::Malicious);
    assert_eq!(RepLevel::from_ratio(0.5), RepLevel::HighThreat);
    assert_eq!(RepLevel::from_ratio(0.75), RepLevel::Critical);
    assert_eq!(RepLevel::from_ratio(1.0), RepLevel::Critical);
}

#[test]
fn rep_should_block_matrix() {
    assert!(!RepLevel::Clean.should_block());
    assert!(!RepLevel::Suspicious.should_block());
    assert!(RepLevel::Malicious.should_block());
    assert!(RepLevel::HighThreat.should_block());
    assert!(RepLevel::Critical.should_block());
}

#[test]
fn rep_threat_level_display() {
    assert_eq!(format!("{}", RepLevel::Critical), "critical");
}

#[test]
fn rep_vendor_vote_malicious_contributes_weight() {
    let v = VendorVote::malicious("X", "Trojan").with_weight(2.5);
    assert_eq!(v.score_contribution(), 2.5);
}

#[test]
fn rep_vendor_vote_clean_zero_contribution() {
    let v = VendorVote::clean("X");
    assert_eq!(v.score_contribution(), 0.0);
}

#[test]
fn rep_category_score_prevalence_zero_total() {
    let c = CategoryScore::new("trojan", 5, 0);
    assert_eq!(c.prevalence, 0.0);
}

#[test]
fn rep_category_is_prevalent_boundary() {
    let c = CategoryScore::new("x", 1, 10);
    assert!(c.is_prevalent()); // 0.10 >= 0.10
    let c = CategoryScore::new("y", 9, 100);
    assert!(!c.is_prevalent()); // 0.09
}

#[test]
fn rep_score_from_empty_votes_is_clean() {
    let s = ReputationScore::from_votes("ind", &[]);
    assert_eq!(s.threat_level, RepLevel::Clean);
    assert_eq!(s.malicious_count, 0);
    assert_eq!(s.clean_count, 0);
    assert!(!s.is_malicious());
}

#[test]
fn rep_score_all_malicious() {
    let votes = vec![
        VendorVote::malicious("A", "Trojan.A"),
        VendorVote::malicious("B", "Trojan.B"),
    ];
    let s = ReputationScore::from_votes("h", &votes);
    assert!((s.detection_ratio - 1.0).abs() < f32::EPSILON);
    assert_eq!(s.malicious_count, 2);
    assert_eq!(s.clean_count, 0);
    assert!(s.is_malicious());
}

#[test]
fn rep_score_mixed_votes_ratio_string() {
    let votes = vec![
        VendorVote::malicious("A", "Trojan"),
        VendorVote::clean("B"),
        VendorVote::clean("C"),
    ];
    let s = ReputationScore::from_votes("h", &votes);
    assert_eq!(s.ratio_string(), "1/3");
}

#[test]
fn rep_dominant_category_picked() {
    let votes = vec![
        VendorVote::malicious("A", "Ransomware.Wcry"),
        VendorVote::malicious("B", "Ransomware.Crypt"),
        VendorVote::malicious("C", "Trojan.X"),
    ];
    let s = ReputationScore::from_votes("h", &votes);
    let d = s.dominant_category().expect("dominant present");
    assert_eq!(d.category, "ransomware");
}

#[test]
fn rep_update_staleness() {
    let votes = vec![VendorVote::malicious("A", "x")];
    let mut s = ReputationScore::from_votes("h", &votes);
    s.update_staleness(86_400);
    assert!(!s.is_stale, "freshly computed should not be stale within 24h");
    // Sleep then mark as stale with threshold=0 (strict >).
    std::thread::sleep(Duration::from_millis(1500));
    s.update_staleness(0);
    assert!(s.is_stale);
}

#[test]
fn vt_reputation_ingest_and_threshold() {
    let mut rep = VtReputation::new().with_stale_threshold(60);
    rep.ingest("h1", vec![VendorVote::malicious("A", "Trojan.X")]);
    // Just ensure it doesn't panic and the cache size grew via re-ingest.
    rep.ingest("h2", vec![VendorVote::clean("B")]);
}

// ─────────────────────────── lib.rs root items ──────────────────────────

#[test]
fn vt_api_key_valid_hex64() {
    let k = VtApiKey::public("a".repeat(64));
    assert!(k.is_valid());
}

#[test]
fn vt_api_key_invalid_short() {
    let k = VtApiKey::public("abc".into());
    assert!(!k.is_valid());
}

#[test]
fn vt_api_key_invalid_non_hex() {
    let k = VtApiKey::public("z".repeat(64));
    assert!(!k.is_valid());
}

#[test]
fn vt_api_key_premium_and_public_differ() {
    let pub_k = VtApiKey::public("k".into());
    let prem_k = VtApiKey::premium("k".into());
    assert!(!pub_k.premium && prem_k.premium);
    assert!(prem_k.rate_limit_per_minute > pub_k.rate_limit_per_minute);
}

#[test]
fn vt_token_bucket_initial_full() {
    let l = VtTokenBucketLimiter::new(60); // 1/s
    assert!((l.available_tokens() - 60.0).abs() < 0.5);
    assert_eq!(l.wait_time(), 0.0);
}

#[test]
fn vt_token_bucket_consume_until_empty() {
    let l = VtTokenBucketLimiter::new(60); // 1/s
    let mut consumed = 0;
    for _ in 0..60 {
        if l.try_consume() { consumed += 1; }
    }
    assert_eq!(consumed, 60);
    assert!(!l.try_consume());
    assert!(l.wait_time() > 0.0);
}

#[test]
fn vt_analysis_stats_total_all_buckets() {
    let s = VtAnalysisStats {
        malicious: 1, suspicious: 1, undetected: 1, timeout: 1,
        confirmed_timeout: 1, failure: 1, type_unsupported: 1, harmless: 1,
    };
    assert_eq!(s.total(), 8);
    assert_eq!(s.detection_ratio(), "1/8");
}

#[test]
fn vt_av_result_classifications() {
    let m = VtAVResult { category: "malicious".into(), engine_name: "X".into(),
        engine_version: None, engine_update: None, result: None, method: None };
    let s = VtAVResult { category: "suspicious".into(), engine_name: "Y".into(),
        engine_version: None, engine_update: None, result: None, method: None };
    let u = VtAVResult { category: "undetected".into(), engine_name: "Z".into(),
        engine_version: None, engine_update: None, result: None, method: None };
    assert!(m.is_malicious() && !m.is_suspicious());
    assert!(s.is_suspicious() && !s.is_malicious());
    assert!(!u.is_malicious() && !u.is_suspicious());
}

#[test]
fn vt_file_report_full_threat_label_and_malicious() {
    let mut full = VtFileReportFull {
        sha256: "x".into(), sha1: "y".into(), md5: "z".into(),
        meaningful_name: None, size: 0, type_tag: None, type_description: None,
        magic: None, creation_date: None, first_submission_date: None,
        last_analysis_date: None, last_submission_date: None, times_submitted: 0,
        last_analysis_results: HashMap::new(),
        last_analysis_stats: VtAnalysisStats::default(),
        reputation: 0,
        popular_threat_classification: Some(VtPopularThreatClassification {
            suggested_threat_label: Some("trojan.wannacry".into()),
            popular_threat_category: vec![VtThreatClassItem { value: "trojan".into(), count: 10 }],
            popular_threat_name: vec![],
        }),
        sandbox_verdicts: vec![],
        names: vec![], tags: vec![],
        imphash: None, ssdeep: None, tlsh: None, authentihash: None, signature_info: None,
    };
    assert!(!full.is_malicious());
    full.last_analysis_stats.malicious = 1;
    assert!(full.is_malicious());
    assert_eq!(full.threat_label(), Some("trojan.wannacry"));
    full.last_analysis_results.insert("Eng".into(), VtAVResult {
        category: "malicious".into(), engine_name: "Eng".into(),
        engine_version: None, engine_update: None, result: None, method: None,
    });
    assert_eq!(full.malicious_results().len(), 1);
}

#[test]
fn vt_search_query_builder() {
    let q = VtSearchQuery::new("type:peexe")
        .with_tag("apt")
        .with_type("peexe")
        .with_size_range(100, 10_000)
        .with_limit(50);
    assert_eq!(q.query, "type:peexe");
    assert_eq!(q.tags, vec!["apt"]);
    assert_eq!(q.type_, Some("peexe".into()));
    assert_eq!(q.size_min, Some(100));
    assert_eq!(q.size_max, Some(10_000));
    assert_eq!(q.limit, Some(50));
}

#[test]
fn vt_behavior_contacted_ips_and_domains() {
    let mut b = VtBehavior::new("h".into(), "Cuckoo".into());
    b.network.tcp_connections.push(VtConnection {
        destination_ip: "1.1.1.1".into(), destination_port: 80,
        protocol: "tcp".into(), transport_layer_protocol: None,
    });
    b.network.udp_connections.push(VtConnection {
        destination_ip: "2.2.2.2".into(), destination_port: 53,
        protocol: "udp".into(), transport_layer_protocol: None,
    });
    b.network.dns_lookups.push(VtDnsLookup {
        hostname: "evil.com".into(), resolved_ips: vec![],
    });
    let ips = b.contacted_ips();
    assert!(ips.contains(&"1.1.1.1"));
    assert!(ips.contains(&"2.2.2.2"));
    assert_eq!(b.contacted_domains(), vec!["evil.com"]);
}

#[test]
fn vt_relationship_type_serde() {
    let v = VtRelationshipType::ContactedIps;
    let j = serde_json::to_string(&v).unwrap();
    let d: VtRelationshipType = serde_json::from_str(&j).unwrap();
    assert_eq!(d, VtRelationshipType::ContactedIps);
}

#[test]
fn mock_file_report_never_invents_a_verdict() {
    // Both used to be graded by whether the string contained "bad".
    assert!(mock_file_report("deadbeefbad").is_err());
    assert!(mock_file_report("01234567").is_err());
}

#[test]
fn mock_ip_report_never_invents_a_verdict() {
    assert!(mock_ip_report("10.0.0.5").is_err());
    assert!(mock_ip_report("8.8.8.8").is_err());
}

#[test]
fn virustotal_client_constructs() {
    let c = VirusTotalClient::new("key".into())
        .with_base_url("https://x".into())
        .with_timeout(Duration::from_secs(5));
    // Just verify it constructs and exposes no panic.
    let _ = c;
}
