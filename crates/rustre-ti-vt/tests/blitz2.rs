//! Deep adversarial tests for rustre-ti-vt.

use rustre_threatintel::{IoC, IoCType};
use rustre_ti_vt::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn client() -> VirusTotalClient {
    VirusTotalClient::new("test-key".to_string())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---------------- VtApiKey ----------------

#[test]
fn t01_api_key_public_valid_hex() {
    let k = VtApiKey::public("a".repeat(64));
    assert!(k.is_valid());
    assert_eq!(k.rate_limit_per_minute, 4);
    assert!(!k.premium);
    assert_eq!(k.daily_quota, Some(500));
}

#[test]
fn t02_api_key_invalid_too_short() {
    let k = VtApiKey::public("abc".to_string());
    assert!(!k.is_valid());
}

#[test]
fn t03_api_key_invalid_non_hex() {
    let k = VtApiKey::public("z".repeat(64));
    assert!(!k.is_valid());
}

#[test]
fn t04_api_key_premium_settings() {
    let k = VtApiKey::premium("0".repeat(64));
    assert!(k.premium);
    assert_eq!(k.rate_limit_per_minute, 500);
    assert!(k.daily_quota.is_none());
    assert!(k.is_valid());
}

#[test]
fn t05_api_key_fuzz_validation_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() % 130) as usize;
        let s: String = (0..len)
            .map(|_| {
                let c = (g() % 128) as u8;
                c as char
            })
            .collect();
        let _ = VtApiKey::public(s).is_valid();
    }
}

#[test]
fn t06_api_key_boundary_63_chars() {
    let k = VtApiKey::public("a".repeat(63));
    assert!(!k.is_valid());
}

#[test]
fn t07_api_key_boundary_65_chars() {
    let k = VtApiKey::public("a".repeat(65));
    assert!(!k.is_valid());
}

#[test]
fn t08_api_key_all_digits_valid() {
    let k = VtApiKey::public("0123456789".repeat(7).chars().take(64).collect());
    assert!(k.is_valid());
}

#[test]
fn t09_api_key_serde_roundtrip() {
    let k = VtApiKey::public("a".repeat(64));
    let j = serde_json::to_string(&k).unwrap();
    let k2: VtApiKey = serde_json::from_str(&j).unwrap();
    assert_eq!(k.key, k2.key);
    assert_eq!(k.premium, k2.premium);
}

// ---------------- VtTokenBucketLimiter ----------------

#[test]
fn t10_token_bucket_initial_full() {
    let l = VtTokenBucketLimiter::new(60);
    assert!((l.available_tokens() - 60.0).abs() < 0.5);
}

#[test]
fn t11_token_bucket_consume_decreases() {
    let l = VtTokenBucketLimiter::new(10);
    let before = l.available_tokens();
    assert!(l.try_consume());
    let after = l.available_tokens();
    assert!(after <= before);
}

#[test]
fn t12_token_bucket_drain() {
    let l = VtTokenBucketLimiter::new(3);
    let mut consumed = 0;
    for _ in 0..100 {
        if l.try_consume() {
            consumed += 1;
        }
    }
    assert!(consumed >= 3);
}

#[test]
fn t13_token_bucket_wait_time_non_negative() {
    let l = VtTokenBucketLimiter::new(1);
    for _ in 0..50 {
        let _ = l.try_consume();
    }
    assert!(l.wait_time() >= 0.0);
}

#[test]
fn t14_token_bucket_send_sync_threaded() {
    let l = Arc::new(VtTokenBucketLimiter::new(1000));
    let mut handles = vec![];
    for _ in 0..4 {
        let l = Arc::clone(&l);
        handles.push(thread::spawn(move || {
            let mut ok = 0;
            for _ in 0..100 {
                if l.try_consume() {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let total: i32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total > 0);
}

#[test]
fn t15_token_bucket_fuzz_rpm_construction() {
    let mut g = lcg();
    for _ in 0..50 {
        let rpm = (g() % 10_000) as u32 + 1;
        let l = VtTokenBucketLimiter::new(rpm);
        assert!(l.available_tokens() >= 0.0);
        let _ = l.try_consume();
    }
}

// ---------------- VtAnalysisStats ----------------

#[test]
fn t16_analysis_stats_total_sums_all() {
    let s = VtAnalysisStats {
        malicious: 1,
        suspicious: 2,
        undetected: 3,
        timeout: 4,
        confirmed_timeout: 5,
        failure: 6,
        type_unsupported: 7,
        harmless: 8,
    };
    assert_eq!(s.total(), 36);
}

#[test]
fn t17_analysis_stats_detection_ratio_format() {
    let s = VtAnalysisStats {
        malicious: 5,
        undetected: 67,
        ..Default::default()
    };
    assert_eq!(s.detection_ratio(), "5/72");
}

#[test]
fn t18_analysis_stats_zero() {
    let s = VtAnalysisStats::default();
    assert_eq!(s.total(), 0);
    assert_eq!(s.detection_ratio(), "0/0");
}

#[test]
fn t19_analysis_stats_max_no_overflow() {
    // Sum equals each field, so use moderate maxes safely (no overflow).
    let s = VtAnalysisStats {
        malicious: 1_000_000,
        suspicious: 1_000_000,
        undetected: 1_000_000,
        timeout: 1_000_000,
        confirmed_timeout: 1_000_000,
        failure: 1_000_000,
        type_unsupported: 1_000_000,
        harmless: 1_000_000,
    };
    assert_eq!(s.total(), 8_000_000);
}

// ---------------- VtStats (models) ----------------

#[test]
fn t20_vt_stats_total_and_ratio() {
    let s = VtStats {
        malicious: 10,
        suspicious: 0,
        undetected: 90,
        harmless: 0,
        timeout: 0,
    };
    assert_eq!(s.total(), 100);
    assert!((s.detection_ratio() - 0.1).abs() < 1e-4);
}

#[test]
fn t21_vt_stats_empty_ratio_zero() {
    assert!(VtStats::default().detection_ratio() == 0.0);
}

#[test]
fn t22_vt_stats_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let s = VtStats {
            malicious: (g() & 0xFFFF) as u32,
            suspicious: (g() & 0xFFFF) as u32,
            undetected: (g() & 0xFFFF) as u32,
            harmless: (g() & 0xFFFF) as u32,
            timeout: (g() & 0xFFFF) as u32,
        };
        let r = s.detection_ratio();
        assert!((0.0..=1.0).contains(&r));
    }
}

// ---------------- VtAnalysisStatus ----------------

#[test]
fn t23_analysis_status_display() {
    assert_eq!(format!("{}", VtAnalysisStatus::Queued), "queued");
    assert_eq!(format!("{}", VtAnalysisStatus::InProgress), "in-progress");
    assert_eq!(format!("{}", VtAnalysisStatus::Completed), "completed");
    assert_eq!(format!("{}", VtAnalysisStatus::Unknown), "unknown");
}

#[test]
fn t24_analysis_status_serde_known() {
    let j = serde_json::to_string(&VtAnalysisStatus::Queued).unwrap();
    let back: VtAnalysisStatus = serde_json::from_str(&j).unwrap();
    assert_eq!(back, VtAnalysisStatus::Queued);
}

#[test]
fn t25_analysis_status_serde_unknown_fallback() {
    let back: VtAnalysisStatus = serde_json::from_str("\"weirdvalue\"").unwrap();
    assert_eq!(back, VtAnalysisStatus::Unknown);
}

#[test]
fn t26_analysis_id_display_and_as_str() {
    let id = VtAnalysisId::new("abc-123");
    assert_eq!(id.as_str(), "abc-123");
    assert_eq!(format!("{id}"), "abc-123");
}

#[test]
fn t27_analysis_id_serde_roundtrip() {
    let id = VtAnalysisId::new("xyz");
    let j = serde_json::to_string(&id).unwrap();
    let back: VtAnalysisId = serde_json::from_str(&j).unwrap();
    assert_eq!(back.as_str(), "xyz");
}

// ---------------- VtAVResult ----------------

#[test]
fn t28_av_result_is_malicious_vs_suspicious() {
    let mut r = VtAVResult {
        category: "malicious".to_string(),
        engine_name: "x".to_string(),
        engine_version: None,
        engine_update: None,
        result: None,
        method: None,
    };
    assert!(r.is_malicious());
    assert!(!r.is_suspicious());
    r.category = "suspicious".to_string();
    assert!(!r.is_malicious());
    assert!(r.is_suspicious());
    r.category = "undetected".to_string();
    assert!(!r.is_malicious());
    assert!(!r.is_suspicious());
}

// ---------------- VtSearchQuery ----------------

#[test]
fn t29_search_query_builder_chain() {
    let q = VtSearchQuery::new("malware")
        .with_tag("trojan")
        .with_tag("apt")
        .with_type("peexe")
        .with_size_range(1, 99)
        .with_limit(42);
    assert_eq!(q.query, "malware");
    assert_eq!(q.tags.len(), 2);
    assert_eq!(q.type_.as_deref(), Some("peexe"));
    assert_eq!(q.size_min, Some(1));
    assert_eq!(q.size_max, Some(99));
    assert_eq!(q.limit, Some(42));
}

#[test]
fn t30_search_query_default_empty() {
    let q = VtSearchQuery::default();
    assert!(q.query.is_empty());
    assert!(q.tags.is_empty());
    assert!(q.limit.is_none());
}

#[test]
fn t31_search_query_serde() {
    let q = VtSearchQuery::new("apt28").with_limit(10);
    let j = serde_json::to_string(&q).unwrap();
    let back: VtSearchQuery = serde_json::from_str(&j).unwrap();
    assert_eq!(back.query, "apt28");
    assert_eq!(back.limit, Some(10));
}

// ---------------- mock_file_report / mock_ip_report ----------------

#[test]
fn t32_mock_file_report_bad_detected() {
    let r = mock_file_report("bad_hash_evil");
    assert!(r.is_malicious());
    assert!(r.malicious_count() >= 1);
}

#[test]
fn t33_mock_file_report_clean() {
    let r = mock_file_report("safe");
    assert!(!r.is_malicious());
    assert_eq!(r.malicious_count(), 0);
}

#[test]
fn t34_mock_ip_report_clean_and_malicious() {
    assert!(!mock_ip_report("8.8.8.8").is_malicious());
    assert!(mock_ip_report("10.0.0.1").is_malicious());
    assert!(mock_ip_report("evil_thing").is_malicious());
}

#[test]
fn t35_mock_file_report_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let s = format!("h{:x}", g());
        let r = mock_file_report(&s);
        assert_eq!(r.sha256, s);
    }
}

// ---------------- VtBehavior ----------------

#[test]
fn t36_behavior_new_empty() {
    let b = VtBehavior::new("h".to_string(), "Sandbox".to_string());
    assert_eq!(b.sha256, "h");
    assert_eq!(b.sandbox_name, "Sandbox");
    assert!(b.processes.is_empty());
    assert!(b.contacted_ips().is_empty());
    assert!(b.contacted_domains().is_empty());
}

#[test]
fn t37_behavior_contacted_ips_and_domains() {
    let mut b = VtBehavior::new("h".to_string(), "s".to_string());
    b.network.tcp_connections.push(VtConnection {
        destination_ip: "1.1.1.1".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        transport_layer_protocol: None,
    });
    b.network.udp_connections.push(VtConnection {
        destination_ip: "2.2.2.2".to_string(),
        destination_port: 53,
        protocol: "udp".to_string(),
        transport_layer_protocol: None,
    });
    b.network.dns_lookups.push(VtDnsLookup {
        hostname: "x.example".to_string(),
        resolved_ips: vec![],
    });
    let ips = b.contacted_ips();
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"1.1.1.1"));
    assert!(ips.contains(&"2.2.2.2"));
    assert_eq!(b.contacted_domains(), vec!["x.example"]);
}

// ---------------- VtFileReportFull ----------------

#[test]
fn t38_file_report_full_helpers() {
    let mut results = HashMap::new();
    results.insert(
        "AV1".to_string(),
        VtAVResult {
            category: "malicious".to_string(),
            engine_name: "AV1".to_string(),
            engine_version: None,
            engine_update: None,
            result: Some("X".to_string()),
            method: None,
        },
    );
    let r = VtFileReportFull {
        sha256: "s".to_string(),
        sha1: "1".to_string(),
        md5: "m".to_string(),
        meaningful_name: None,
        size: 0,
        type_tag: None,
        type_description: None,
        magic: None,
        creation_date: None,
        first_submission_date: None,
        last_analysis_date: None,
        last_submission_date: None,
        times_submitted: 0,
        last_analysis_results: results,
        last_analysis_stats: VtAnalysisStats {
            malicious: 1,
            ..Default::default()
        },
        reputation: -1,
        popular_threat_classification: Some(VtPopularThreatClassification {
            suggested_threat_label: Some("trojan/x".to_string()),
            popular_threat_category: vec![],
            popular_threat_name: vec![],
        }),
        sandbox_verdicts: vec![],
        names: vec![],
        tags: vec![],
        imphash: None,
        ssdeep: None,
        tlsh: None,
        authentihash: None,
        signature_info: None,
    };
    assert!(r.is_malicious());
    assert_eq!(r.detection_ratio(), "1/1");
    assert_eq!(r.malicious_results().len(), 1);
    assert_eq!(r.threat_label(), Some("trojan/x"));
}

// ---------------- Async client methods ----------------

#[test]
fn t39_scan_file_returns_id() {
    let r = rt().block_on(async {
        client().scan_file(&[]).await
    });
    assert!(r.is_ok());
    assert!(!r.unwrap().is_empty());
}

#[test]
fn t40_scan_url_varies_with_length() {
    let r = rt().block_on(async {
        (
            client().scan_url("http://a.com").await.unwrap(),
            client().scan_url("http://abcdef.com").await.unwrap(),
        )
    });
    assert_ne!(r.0, r.1);
}

#[test]
fn t41_get_file_report_clean_and_evil() {
    let (clean, evil) = rt().block_on(async {
        (
            client().get_file_report("safehash").await.unwrap(),
            client().get_file_report("evilhash").await.unwrap(),
        )
    });
    assert!(!clean.is_malicious());
    assert!(evil.is_malicious());
    assert!(evil.threat_label().is_some());
    assert!(clean.threat_label().is_none());
}

#[test]
fn t42_get_url_report_branches() {
    let (clean, mal) = rt().block_on(async {
        (
            client().get_url_report("http://clean.com").await.unwrap(),
            client().get_url_report("http://evil.com").await.unwrap(),
        )
    });
    assert!(!clean.is_malicious());
    assert!(mal.is_malicious());
}

#[test]
fn t43_get_domain_report_dns_records() {
    let r = rt().block_on(async { client().get_domain_report("x.com").await.unwrap() });
    assert_eq!(r.id, "x.com");
    assert_eq!(r.last_dns_records.len(), 1);
}

#[test]
fn t44_get_ip_report_branches() {
    let (clean, mal) = rt().block_on(async {
        (
            client().get_ip_report("8.8.8.8").await.unwrap(),
            client().get_ip_report("10.0.0.5").await.unwrap(),
        )
    });
    assert!(!clean.is_malicious());
    assert!(mal.is_malicious());
}

#[test]
fn t45_search_limit_capped_at_5() {
    let q = VtSearchQuery::new("x").with_limit(100);
    let r = rt().block_on(async { client().search(&q).await.unwrap() });
    assert_eq!(r.len(), 5);
}

#[test]
fn t46_search_limit_default_5() {
    let q = VtSearchQuery::new("x");
    let r = rt().block_on(async { client().search(&q).await.unwrap() });
    assert_eq!(r.len(), 5);
}

#[test]
fn t47_get_behavior_dns_seeded() {
    let b = rt().block_on(async { client().get_behavior("h").await.unwrap() });
    assert!(!b.network.dns_lookups.is_empty());
    assert!(!b.mutexes.is_empty());
}

#[test]
fn t48_get_relationships_returns_at_least_one() {
    let r = rt().block_on(async {
        client()
            .get_relationships("id", &VtRelationshipType::ContactedIps)
            .await
            .unwrap()
    });
    assert!(!r.is_empty());
}

#[test]
fn t49_get_collections_returns_one() {
    let r = rt().block_on(async { client().get_collections("id").await.unwrap() });
    assert_eq!(r.len(), 1);
    assert!(r[0].files_count >= 1);
}

#[test]
fn t50_get_votes_and_comments() {
    let (v, c) = rt().block_on(async {
        (
            client().get_votes("x").await.unwrap(),
            client().get_comments("x").await.unwrap(),
        )
    });
    assert!(!v.is_empty());
    assert!(!c.is_empty());
}

// ---------------- client config builders ----------------

#[test]
fn t51_client_with_base_url_and_timeout() {
    let c = client()
        .with_base_url("http://localhost".to_string())
        .with_timeout(Duration::from_secs(7));
    assert_eq!(c.timeout(), Duration::from_secs(7));
}

#[test]
fn t52_client_with_rate_limiter() {
    let _c = client().with_rate_limiter(VtTokenBucketLimiter::new(123));
}

// ---------------- VtRelationshipType ----------------

#[test]
fn t53_relationship_type_eq_and_other() {
    assert_eq!(
        VtRelationshipType::ContactedIps,
        VtRelationshipType::ContactedIps
    );
    assert_ne!(
        VtRelationshipType::ContactedIps,
        VtRelationshipType::ContactedDomains
    );
    let a = VtRelationshipType::Other("x".to_string());
    let b = VtRelationshipType::Other("x".to_string());
    let c = VtRelationshipType::Other("y".to_string());
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn t54_relationship_type_serde() {
    let rt = VtRelationshipType::EmbeddedFiles;
    let j = serde_json::to_string(&rt).unwrap();
    let back: VtRelationshipType = serde_json::from_str(&j).unwrap();
    assert_eq!(rt, back);
}

// ---------------- VtClientError display ----------------

#[test]
fn t55_vt_client_error_display_all_variants() {
    for e in [
        VtClientError::RateLimitExceeded,
        VtClientError::NotFound("x".to_string()),
        VtClientError::AuthenticationError,
        VtClientError::QuotaExceeded,
        VtClientError::Http("500".to_string()),
        VtClientError::Parse("bad".to_string()),
        VtClientError::InvalidHash("abc".to_string()),
        VtClientError::InvalidUrl("ftp://x".to_string()),
        VtClientError::Other("o".to_string()),
    ] {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

// ---------------- VtError ----------------

#[test]
fn t56_vt_error_constructors_and_conversion() {
    let e = VtError::not_found("zzz");
    match e {
        VtError::NotFound(s) => assert_eq!(s, "zzz"),
        _ => panic!("wrong variant"),
    }
    let e = VtError::invalid_response("bad json");
    let ti: rustre_threatintel::TiError = e.into();
    let _ = format!("{ti}");
}

#[test]
fn t57_vt_error_rate_limited_into_ti() {
    let e = VtError::RateLimited {
        retry_after_secs: 10,
    };
    let ti: rustre_threatintel::TiError = e.into();
    let _ = format!("{ti}");
}

#[test]
fn t58_vt_error_http_into_ti() {
    let e = VtError::Http {
        status: 502,
        body: "bad gateway".to_string(),
    };
    let ti: rustre_threatintel::TiError = e.into();
    let s = format!("{ti}");
    assert!(s.contains("502"));
}

// ---------------- Provider trait ----------------

#[test]
fn t59_provider_supported_types_includes_hashes() {
    let c = client();
    let supported = TiProviderShim::supported(&c);
    assert!(supported.contains(&IoCType::Sha256));
    assert!(supported.contains(&IoCType::Md5));
    assert!(supported.contains(&IoCType::Ip));
    assert!(supported.contains(&IoCType::Domain));
    assert!(supported.contains(&IoCType::Url));
}

// Helper to call supported_ioc_types via the TiProvider trait without
// importing in every test.
struct TiProviderShim;
impl TiProviderShim {
    fn supported(c: &VirusTotalClient) -> Vec<IoCType> {
        use rustre_threatintel::TiProvider;
        c.supported_ioc_types()
    }
}

#[test]
fn t60_provider_lookup_async() {
    use rustre_threatintel::TiProvider;
    let ioc = IoC::new(
        IoCType::Sha256,
        "evil_value".to_string(),
        "src".to_string(),
    );
    let r = rt().block_on(async { client().lookup(&ioc).await.unwrap() });
    assert_eq!(r.ioc.value, "evil_value");
    assert!(r.verdicts.iter().any(|v| v.malicious));
    assert!(!r.malware_families.is_empty());
}

// ---------------- Fuzz scan_url ----------------

#[test]
fn t61_scan_url_fuzz_never_errors() {
    let mut g = lcg();
    rt().block_on(async {
        for _ in 0..30 {
            let n = (g() % 100) as usize;
            let url: String = (0..n)
                .map(|_| char::from(b'a' + (g() % 26) as u8))
                .collect();
            let r = client().scan_url(&url).await;
            assert!(r.is_ok());
        }
    });
}

// ---------------- VtCollection / VtVote / VtComment serde ----------------

#[test]
fn t62_vt_collection_serde_roundtrip() {
    let c = VtCollection {
        id: "id".to_string(),
        name: "n".to_string(),
        description: None,
        owner: None,
        creation_date: 1,
        tags: vec!["a".to_string()],
        files_count: 0,
        urls_count: 0,
        domains_count: 0,
        ips_count: 0,
    };
    let j = serde_json::to_string(&c).unwrap();
    let back: VtCollection = serde_json::from_str(&j).unwrap();
    assert_eq!(back.id, "id");
}
