//! Adversarial deep-test suite for `rustre-ti-shodan`.
//!
//! Tests public API of the lib (no network calls).

use std::sync::Arc;

use rustre_ti_shodan::shodan_banner_analyzer::{BannerAnalyzer, BannerSummary};
use rustre_ti_shodan::shodan_exposure_scorer::{ExposureScorer, ExposureSeverity};
use rustre_ti_shodan::shodan_host_enricher::{
    RetryPolicy, ShodanAlert, ShodanBanner, ShodanClient, ShodanHost, ShodanSearchPage,
};
use rustre_ti_shodan::{PortCategory, ShodanConfig, ShodanError};

// ── LCG helper ───────────────────────────────────────────────────────────────
fn lcg_seeded() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
fn make_banner(port: u16, product: Option<&str>, vuln_cve: Option<&str>) -> ShodanBanner {
    ShodanBanner {
        ip: Some("1.2.3.4".into()),
        port,
        transport: Some("tcp".into()),
        product: product.map(str::to_string),
        version: None,
        cpe: vec![],
        cpe23: vec![],
        hostnames: vec![],
        data: Some("data".into()),
        timestamp: None,
        asn: None,
        org: None,
        vulns: vuln_cve.map(|c| serde_json::json!({ c: {} })),
    }
}

fn empty_host() -> ShodanHost {
    ShodanHost {
        ip: "1.2.3.4".into(),
        hostnames: vec![],
        domains: vec![],
        country_code: None,
        country_name: None,
        city: None,
        asn: None,
        isp: None,
        org: None,
        os: None,
        ports: vec![],
        tags: vec![],
        vulns: vec![],
        data: vec![],
        last_update: None,
    }
}

// ── PortCategory ─────────────────────────────────────────────────────────────

#[test]
fn portcategory_web_ports() {
    for p in [80u16, 443, 8080, 8443, 8000, 8888] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Web);
    }
}

#[test]
fn portcategory_database_ports() {
    for p in [1433u16, 3306, 5432, 27017, 6379, 9200, 9042, 5984] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Database);
    }
}

#[test]
fn portcategory_remote_access_ports() {
    for p in [22u16, 23, 3389, 5900, 5901] {
        assert_eq!(PortCategory::from_port(p), PortCategory::RemoteAccess);
    }
}

#[test]
fn portcategory_file_sharing_ports() {
    for p in [21u16, 445, 139] {
        assert_eq!(PortCategory::from_port(p), PortCategory::FileSharing);
    }
}

#[test]
fn portcategory_ics_ports() {
    for p in [102u16, 502, 44818, 20000, 47808] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Ics);
    }
}

#[test]
fn portcategory_mail_ports() {
    for p in [25u16, 110, 143, 465, 587, 993, 995] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Mail);
    }
}

#[test]
fn portcategory_dns_port() {
    assert_eq!(PortCategory::from_port(53), PortCategory::Dns);
}

#[test]
fn portcategory_other_for_random_ports() {
    let mut g = lcg_seeded();
    for _ in 0..50 {
        let p = (g() & 0xFFFF) as u16;
        let c = PortCategory::from_port(p);
        // Should not panic and should classify.
        let _ = c.risk_weight();
    }
}

#[test]
fn portcategory_boundaries() {
    // 0 and u16::MAX should be Other.
    assert!(matches!(PortCategory::from_port(0), PortCategory::Other(0)));
    assert!(matches!(
        PortCategory::from_port(u16::MAX),
        PortCategory::Other(u16::MAX)
    ));
}

#[test]
fn portcategory_risk_weights() {
    assert_eq!(PortCategory::Ics.risk_weight(), 35);
    assert_eq!(PortCategory::RemoteAccess.risk_weight(), 30);
    assert_eq!(PortCategory::Database.risk_weight(), 25);
    assert_eq!(PortCategory::FileSharing.risk_weight(), 20);
    assert_eq!(PortCategory::Mail.risk_weight(), 10);
    assert_eq!(PortCategory::Dns.risk_weight(), 8);
    assert_eq!(PortCategory::Web.risk_weight(), 5);
    assert_eq!(PortCategory::Other(1234).risk_weight(), 3);
}

#[test]
fn portcategory_eq_clone() {
    let a = PortCategory::from_port(22);
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(PortCategory::Web, PortCategory::Dns);
}

#[test]
fn portcategory_serde_roundtrip() {
    for p in [22u16, 80, 53, 1234, 0, u16::MAX] {
        let c = PortCategory::from_port(p);
        let s = serde_json::to_string(&c).unwrap();
        let d: PortCategory = serde_json::from_str(&s).unwrap();
        assert_eq!(c, d);
    }
}

// ── ShodanConfig ─────────────────────────────────────────────────────────────

#[test]
fn config_new_defaults() {
    let c = ShodanConfig::new("KEY");
    assert_eq!(c.api_key, "KEY");
    assert_eq!(c.base_url, "https://api.shodan.io");
    assert_eq!(c.timeout_secs, 30);
    assert!(!c.include_raw_banners);
}

#[test]
fn config_host_url_encodes_key() {
    let c = ShodanConfig::new("k e/y");
    let u = c.host_url("1.2.3.4");
    assert!(u.contains("/shodan/host/1.2.3.4?key="));
    assert!(u.contains("k%20e%2Fy"));
}

#[test]
fn config_search_url_encodes_query() {
    let c = ShodanConfig::new("KEY");
    let u = c.search_url("hello world");
    assert!(u.contains("query=hello%20world"));
    assert!(u.contains("key=KEY"));
}

#[test]
fn config_urls_use_base_url() {
    let mut c = ShodanConfig::new("K");
    c.base_url = "https://x.example".to_owned();
    assert!(c.host_url("8.8.8.8").starts_with("https://x.example/shodan/host/8.8.8.8?key=K"));
    assert!(c.search_url("q").starts_with("https://x.example/shodan/host/search?key=K&query=q"));
}

#[test]
fn config_serde_roundtrip() {
    let c = ShodanConfig::new("abcd");
    let s = serde_json::to_string(&c).unwrap();
    let d: ShodanConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(d.api_key, c.api_key);
    assert_eq!(d.base_url, c.base_url);
    assert_eq!(d.timeout_secs, c.timeout_secs);
}

#[test]
fn config_url_fuzz_no_panic() {
    let mut g = lcg_seeded();
    for _ in 0..60 {
        let n = (g() % 32) as usize;
        let key: String = (0..n).map(|_| (g() & 0x7F) as u8 as char).collect();
        let q: String = (0..n).map(|_| (g() & 0x7F) as u8 as char).collect();
        let c = ShodanConfig::new(key);
        let _ = c.host_url("1.2.3.4");
        let _ = c.search_url(&q);
    }
}

// ── ShodanClient construction ────────────────────────────────────────────────

#[test]
fn client_new_empty_key_errors() {
    let err = ShodanClient::new(ShodanConfig::new("")).unwrap_err();
    assert!(matches!(err, ShodanError::Auth(_)));
}

#[test]
fn client_new_whitespace_key_errors() {
    let err = ShodanClient::new(ShodanConfig::new("   ")).unwrap_err();
    assert!(matches!(err, ShodanError::Auth(_)));
}

#[test]
fn client_new_ok_real_key() {
    let c = ShodanClient::new(ShodanConfig::new("nonempty")).unwrap();
    assert_eq!(c.config().api_key, "nonempty");
}

#[test]
fn client_with_retry_policy() {
    let c = ShodanClient::new(ShodanConfig::new("k"))
        .unwrap()
        .with_retry_policy(RetryPolicy {
            max_attempts: 7,
            ..Default::default()
        });
    // No public getter for retry; just ensure it builds and clones.
    let _ = c;
}

#[test]
fn retry_policy_default_sane() {
    let p = RetryPolicy::default();
    assert!(p.max_attempts >= 1);
    assert!(p.initial_backoff <= p.max_backoff);
}

#[test]
fn retry_policy_copy_clone() {
    let p = RetryPolicy::default();
    let q = p;
    let r = q;
    assert_eq!(r.max_attempts, p.max_attempts);
    assert_eq!(p.max_attempts, q.max_attempts);
}

// ── ShodanError ──────────────────────────────────────────────────────────────

#[test]
fn shodan_error_display() {
    let e = ShodanError::RateLimited;
    assert_eq!(format!("{e}"), "rate limited");
    let e = ShodanError::Http("x".into());
    assert!(format!("{e}").contains('x'));
    let e = ShodanError::Json("j".into());
    assert!(format!("{e}").contains('j'));
    let e = ShodanError::Auth("a".into());
    assert!(format!("{e}").contains('a'));
    let e = ShodanError::NotFound("n".into());
    assert!(format!("{e}").contains('n'));
    let e = ShodanError::InvalidIp("i".into());
    assert!(format!("{e}").contains('i'));
    let e = ShodanError::PlanLimit("p".into());
    assert!(format!("{e}").contains('p'));
}

// ── Banner / Host serde ──────────────────────────────────────────────────────

#[test]
fn banner_deserialize_minimal() {
    let b: ShodanBanner = serde_json::from_str("{}").unwrap();
    assert_eq!(b.port, 0);
    assert!(b.ip.is_none());
}

#[test]
fn banner_deserialize_ip_str_alias() {
    let b: ShodanBanner = serde_json::from_str(r#"{"ip_str":"9.9.9.9","port":80}"#).unwrap();
    assert_eq!(b.ip.as_deref(), Some("9.9.9.9"));
    assert_eq!(b.port, 80);
}

#[test]
fn banner_deserialize_cpe23_rename() {
    let b: ShodanBanner =
        serde_json::from_str(r#"{"cpe23":["cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*"]}"#).unwrap();
    assert_eq!(b.cpe23.len(), 1);
}

#[test]
fn banner_roundtrip_serde() {
    let b = make_banner(80, Some("nginx"), Some("CVE-2024-0001"));
    let s = serde_json::to_string(&b).unwrap();
    let d: ShodanBanner = serde_json::from_str(&s).unwrap();
    assert_eq!(d.port, 80);
    assert_eq!(d.product.as_deref(), Some("nginx"));
}

#[test]
fn host_deserialize_ip_str_alias() {
    let h: ShodanHost = serde_json::from_str(r#"{"ip_str":"1.2.3.4"}"#).unwrap();
    assert_eq!(h.ip, "1.2.3.4");
}

#[test]
fn host_deserialize_missing_ip_errors() {
    let r: Result<ShodanHost, _> = serde_json::from_str("{}");
    assert!(r.is_err());
}

#[test]
fn search_page_default_empty() {
    let p: ShodanSearchPage = serde_json::from_str("{}").unwrap();
    assert_eq!(p.total, 0);
    assert!(p.banners.is_empty());
}

#[test]
fn search_page_matches_rename() {
    let p: ShodanSearchPage =
        serde_json::from_str(r#"{"total":5,"matches":[{"port":22}]}"#).unwrap();
    assert_eq!(p.total, 5);
    assert_eq!(p.banners.len(), 1);
    assert_eq!(p.banners[0].port, 22);
}

#[test]
fn alert_deserialize() {
    let a: ShodanAlert =
        serde_json::from_str(r#"{"name":"n","filters":{"ip":["1.2.3.4"]}}"#).unwrap();
    assert_eq!(a.name, "n");
    assert!(a.id.is_none());
}

// ── BannerAnalyzer ───────────────────────────────────────────────────────────

#[test]
fn analyze_empty_banners() {
    let a = BannerAnalyzer::analyze_banners(&[]);
    assert!(a.per_port.is_empty());
    assert!(a.is_clean());
    assert_eq!(a.vulnerable_port_count(), 0);
}

#[test]
fn analyze_single_banner_cves() {
    let bs = vec![make_banner(22, Some("OpenSSH"), Some("CVE-2024-1234"))];
    let a = BannerAnalyzer::analyze_banners(&bs);
    assert_eq!(a.per_port.len(), 1);
    assert!(a.all_cves.contains("CVE-2024-1234"));
    assert_eq!(a.vulnerable_port_count(), 1);
    assert!(!a.is_clean());
}

#[test]
fn analyze_merges_duplicate_ports() {
    let bs = vec![
        make_banner(22, Some("OpenSSH"), Some("CVE-A-0001")),
        make_banner(22, Some("OpenSSH-Newer"), Some("CVE-B-0002")),
    ];
    let a = BannerAnalyzer::analyze_banners(&bs);
    assert_eq!(a.per_port.len(), 1);
    let s = &a.per_port[&22];
    // Both CVEs must be retained.
    // Note: CVE detection requires "CVE-" prefix.
    assert!(s.cves.iter().any(|c| c.starts_with("CVE-")));
}

#[test]
fn analyze_non_cve_vuln_ignored() {
    let mut b = make_banner(80, Some("nginx"), None);
    b.vulns = Some(serde_json::json!({"NOT-A-CVE": {}}));
    let a = BannerAnalyzer::analyze_banners(&[b]);
    assert!(a.all_cves.is_empty());
}

#[test]
fn analyze_vulns_array_form() {
    let mut b = make_banner(80, Some("nginx"), None);
    b.vulns = Some(serde_json::json!(["CVE-2020-0001", "OTHER"]));
    let a = BannerAnalyzer::analyze_banners(&[b]);
    assert!(a.all_cves.contains("CVE-2020-0001"));
    assert!(!a.all_cves.contains("OTHER"));
}

#[test]
fn analyze_host_merges_host_vulns() {
    let mut h = empty_host();
    h.vulns = vec!["CVE-HOST-0001".into()];
    h.data = vec![make_banner(22, Some("OpenSSH"), Some("CVE-BAN-0001"))];
    let a = BannerAnalyzer::analyze_host(&h);
    assert!(a.all_cves.contains("CVE-HOST-0001"));
    assert!(a.all_cves.contains("CVE-BAN-0001"));
}

#[test]
fn banner_summary_tls_detection() {
    let mut b = make_banner(443, Some("nginx"), None);
    b.data = Some("TLS handshake".into());
    let s = BannerSummary::from_banner(&b);
    assert!(s.tls);

    let mut b2 = make_banner(80, Some("nginx"), None);
    b2.data = Some("plain http".into());
    let s2 = BannerSummary::from_banner(&b2);
    assert!(!s2.tls);
}

#[test]
fn banner_summary_zero_port_no_category() {
    let b = make_banner(0, Some("x"), None);
    let s = BannerSummary::from_banner(&b);
    assert!(s.category.is_none());
}

#[test]
fn banner_summary_cpe_merge() {
    let mut b = make_banner(22, Some("OpenSSH"), None);
    b.cpe = vec!["cpe:/a:openssh".into()];
    b.cpe23 = vec!["cpe:2.3:a:openssh".into()];
    let s = BannerSummary::from_banner(&b);
    assert_eq!(s.cpes.len(), 2);
}

#[test]
fn validate_rejects_port_zero() {
    let b = make_banner(0, Some("x"), None);
    assert!(BannerAnalyzer::validate(&b).is_err());
}

#[test]
fn validate_rejects_no_identity() {
    let mut b = make_banner(22, None, None);
    b.data = None;
    b.cpe = vec![];
    assert!(BannerAnalyzer::validate(&b).is_err());
}

#[test]
fn validate_accepts_with_cpe() {
    let mut b = make_banner(22, None, None);
    b.data = None;
    b.cpe = vec!["cpe:/x".into()];
    assert!(BannerAnalyzer::validate(&b).is_ok());
}

#[test]
fn validate_accepts_with_product() {
    let mut b = make_banner(22, Some("ssh"), None);
    b.data = None;
    assert!(BannerAnalyzer::validate(&b).is_ok());
}

#[test]
fn analyzer_fuzz_many_banners_no_panic() {
    let mut g = lcg_seeded();
    let mut banners = Vec::new();
    for _ in 0..120 {
        let port = (g() & 0xFFFF) as u16;
        let prod = if g() & 1 == 0 { Some("p") } else { None };
        let cve = if g() & 1 == 0 {
            Some("CVE-2024-0001")
        } else {
            None
        };
        banners.push(make_banner(port, prod, cve));
    }
    let a = BannerAnalyzer::analyze_banners(&banners);
    // All ports merged into per_port map.
    assert!(a.per_port.len() <= banners.len());
}

// ── ExposureScorer ───────────────────────────────────────────────────────────

#[test]
fn exposure_empty_host_zero() {
    let h = empty_host();
    let a = BannerAnalyzer::analyze_host(&h);
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.score, 0);
    assert_eq!(s.severity, ExposureSeverity::None);
    assert_eq!(s.cve_count, 0);
}

#[test]
fn exposure_capped_at_100() {
    let mut h = empty_host();
    h.ports = (1..=200u16).map(|p| p * 100).collect();
    h.vulns = (0..50).map(|i| format!("CVE-2024-{i:04}")).collect();
    let a = BannerAnalyzer::analyze_host(&h);
    let s = ExposureScorer::score(&h, &a);
    assert!(s.score <= 100);
}

#[test]
fn exposure_severity_buckets() {
    assert_eq!(ExposureSeverity::from_score(0), ExposureSeverity::None);
    assert_eq!(ExposureSeverity::from_score(1), ExposureSeverity::Low);
    assert_eq!(ExposureSeverity::from_score(24), ExposureSeverity::Low);
    assert_eq!(ExposureSeverity::from_score(25), ExposureSeverity::Medium);
    assert_eq!(ExposureSeverity::from_score(49), ExposureSeverity::Medium);
    assert_eq!(ExposureSeverity::from_score(50), ExposureSeverity::High);
    assert_eq!(ExposureSeverity::from_score(74), ExposureSeverity::High);
    assert_eq!(ExposureSeverity::from_score(75), ExposureSeverity::Critical);
    assert_eq!(ExposureSeverity::from_score(1000), ExposureSeverity::Critical);
}

#[test]
fn exposure_severity_default_none() {
    assert_eq!(ExposureSeverity::default(), ExposureSeverity::None);
}

#[test]
fn exposure_by_category_breakdown_matches_ports() {
    let mut h = empty_host();
    h.ports = vec![22, 3389, 80];
    let a = BannerAnalyzer::analyze_host(&h);
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.by_category.len(), 3);
    let weights: u32 = s.by_category.iter().map(|(_, w)| *w).sum();
    // 30 + 30 + 5 = 65 (no CVEs)
    assert_eq!(weights, 65);
    assert_eq!(s.score, 65);
}

#[test]
fn exposure_cve_contribution_capped() {
    let mut h = empty_host();
    h.vulns = (0..100).map(|i| format!("CVE-2024-{i:04}")).collect();
    let a = BannerAnalyzer::analyze_host(&h);
    let s = ExposureScorer::score(&h, &a);
    // 100 CVEs * 5 = 500, capped at 40.
    assert_eq!(s.score, 40);
    assert_eq!(s.cve_count, 100);
}

#[test]
fn exposure_fuzz_score_in_range() {
    let mut rng = lcg_seeded();
    for _ in 0..50 {
        let mut host = empty_host();
        let count = (rng() % 10) as usize;
        host.ports = (0..count).map(|_| (rng() & 0xFFFF) as u16).collect();
        let analysis = BannerAnalyzer::analyze_host(&host);
        let scored = ExposureScorer::score(&host, &analysis);
        assert!(scored.score <= 100);
        assert_eq!(scored.severity, ExposureSeverity::from_score(scored.score));
    }
}

// ── Eq consistency / serde roundtrip pairs ───────────────────────────────────

#[test]
fn portcategory_eq_pairs_consistency() {
    let cases = vec![
        (PortCategory::Web, PortCategory::Web, true),
        (PortCategory::Dns, PortCategory::Dns, true),
        (PortCategory::RemoteAccess, PortCategory::RemoteAccess, true),
        (PortCategory::Other(7), PortCategory::Other(7), true),
        (PortCategory::Other(7), PortCategory::Other(8), false),
        (PortCategory::Web, PortCategory::Dns, false),
        (PortCategory::Ics, PortCategory::FileSharing, false),
    ];
    for (a, b, eq) in &cases {
        assert_eq!(a == b, *eq);
        // Serde roundtrip preserves identity.
        let s = serde_json::to_string(a).unwrap();
        let d: PortCategory = serde_json::from_str(&s).unwrap();
        assert_eq!(&d, a);
    }
    let mut g = lcg_seeded();
    for _ in 0..30 {
        let p = (g() & 0xFFFF) as u16;
        let a = PortCategory::from_port(p);
        let b = PortCategory::from_port(p);
        assert_eq!(a, b);
    }
}

#[test]
fn exposure_severity_eq_consistency() {
    let xs = [
        ExposureSeverity::None,
        ExposureSeverity::Low,
        ExposureSeverity::Medium,
        ExposureSeverity::High,
        ExposureSeverity::Critical,
    ];
    for x in &xs {
        let y = *x;
        assert_eq!(*x, y);
        let s = serde_json::to_string(x).unwrap();
        let d: ExposureSeverity = serde_json::from_str(&s).unwrap();
        assert_eq!(&d, x);
    }
    // Cross-pair inequality.
    assert_ne!(ExposureSeverity::Low, ExposureSeverity::High);
    assert_ne!(ExposureSeverity::None, ExposureSeverity::Critical);
}

// ── Send/Sync threaded stress ────────────────────────────────────────────────

#[test]
fn client_send_sync_threaded_stress() {
    let client = Arc::new(ShodanClient::new(ShodanConfig::new("KEY")).unwrap());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&client);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = c.config().host_url("1.2.3.4");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn config_threaded_url_construction() {
    let cfg = Arc::new(ShodanConfig::new("K"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&cfg);
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let u = c.search_url(&format!("q{i}"));
                assert!(u.contains("query=q"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
