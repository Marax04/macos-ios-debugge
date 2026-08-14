//! Exhaustive blitz tests for `rustre-ti-shodan`.

use rustre_ti_shodan::shodan_banner_analyzer::{BannerAnalyzer, BannerSummary, HostBannerAnalysis};
use rustre_ti_shodan::shodan_exposure_scorer::{ExposureScorer, ExposureSeverity};
use rustre_ti_shodan::shodan_host_enricher::{
    RetryPolicy, ShodanBanner, ShodanClient, ShodanHost, ShodanSearchPage,
};
use rustre_ti_shodan::{PortCategory, ShodanConfig, ShodanError};
use std::time::Duration;

// ─── helpers ────────────────────────────────────────────────────────────────

const fn empty_banner(port: u16) -> ShodanBanner {
    ShodanBanner {
        ip: None,
        port,
        transport: None,
        product: None,
        version: None,
        cpe: vec![],
        cpe23: vec![],
        hostnames: vec![],
        data: None,
        timestamp: None,
        asn: None,
        org: None,
        vulns: None,
    }
}

fn empty_host(ip: &str) -> ShodanHost {
    ShodanHost {
        ip: ip.into(),
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

// ─── PortCategory ────────────────────────────────────────────────────────────

#[test]
fn port_category_web() {
    for p in [80u16, 443, 8080, 8443, 8000, 8888] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Web);
    }
}

#[test]
fn port_category_database() {
    for p in [1433u16, 3306, 5432, 27017, 6379, 9200, 9042, 5984] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Database);
    }
}

#[test]
fn port_category_remote_access() {
    for p in [22u16, 23, 3389, 5900, 5901] {
        assert_eq!(PortCategory::from_port(p), PortCategory::RemoteAccess);
    }
}

#[test]
fn port_category_file_sharing() {
    for p in [21u16, 445, 139] {
        assert_eq!(PortCategory::from_port(p), PortCategory::FileSharing);
    }
}

#[test]
fn port_category_ics() {
    for p in [102u16, 502, 44818, 20000, 47808] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Ics);
    }
}

#[test]
fn port_category_mail() {
    for p in [25u16, 110, 143, 465, 587, 993, 995] {
        assert_eq!(PortCategory::from_port(p), PortCategory::Mail);
    }
}

#[test]
fn port_category_dns() {
    assert_eq!(PortCategory::from_port(53), PortCategory::Dns);
}

#[test]
fn port_category_other_boundaries() {
    assert_eq!(PortCategory::from_port(0), PortCategory::Other(0));
    assert_eq!(PortCategory::from_port(1), PortCategory::Other(1));
    assert_eq!(PortCategory::from_port(65535), PortCategory::Other(65535));
    assert_eq!(PortCategory::from_port(12345), PortCategory::Other(12345));
}

#[test]
fn port_category_risk_weights() {
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
fn port_category_serde_round_trip() {
    for c in [
        PortCategory::Web,
        PortCategory::Database,
        PortCategory::RemoteAccess,
        PortCategory::FileSharing,
        PortCategory::Ics,
        PortCategory::Mail,
        PortCategory::Dns,
        PortCategory::Other(9999),
    ] {
        let s = serde_json::to_string(&c).unwrap();
        let d: PortCategory = serde_json::from_str(&s).unwrap();
        assert_eq!(c, d);
    }
}

// ─── ShodanConfig ────────────────────────────────────────────────────────────

#[test]
fn config_new_defaults() {
    let c = ShodanConfig::new("abc");
    assert_eq!(c.api_key, "abc");
    assert_eq!(c.base_url, "https://api.shodan.io");
    assert_eq!(c.timeout_secs, 30);
    assert!(!c.include_raw_banners);
}

#[test]
fn config_host_url_encodes_key() {
    let c = ShodanConfig::new("k e/y");
    let u = c.host_url("1.2.3.4");
    assert!(u.contains("/shodan/host/1.2.3.4"));
    assert!(u.contains("key=k%20e%2Fy"));
}

#[test]
fn config_search_url_encodes_key_and_query() {
    let c = ShodanConfig::new("k+y");
    let u = c.search_url("port:22 country:US");
    assert!(u.contains("query=port%3A22%20country%3AUS"));
    assert!(u.contains("key=k%2By"));
}

#[test]
fn config_serde_round_trip() {
    let c = ShodanConfig::new("zzz");
    let s = serde_json::to_string(&c).unwrap();
    let d: ShodanConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(d.api_key, "zzz");
    assert_eq!(d.base_url, "https://api.shodan.io");
    assert_eq!(d.timeout_secs, 30);
}

// ─── ShodanClient::new ───────────────────────────────────────────────────────

#[test]
fn client_new_rejects_empty_key() {
    let err = ShodanClient::new(ShodanConfig::new("")).unwrap_err();
    assert!(matches!(err, ShodanError::Auth(_)));
}

#[test]
fn client_new_rejects_whitespace_key() {
    let err = ShodanClient::new(ShodanConfig::new("   \t\n")).unwrap_err();
    assert!(matches!(err, ShodanError::Auth(_)));
}

#[test]
fn client_new_accepts_real_key() {
    let c = ShodanClient::new(ShodanConfig::new("real")).expect("should build");
    assert_eq!(c.config().api_key, "real");
}

#[test]
fn client_with_retry_policy_overrides() {
    let c = ShodanClient::new(ShodanConfig::new("real"))
        .unwrap()
        .with_retry_policy(RetryPolicy {
            max_attempts: 7,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
        });
    // Indirect — we only check it didn't panic and config is preserved.
    assert_eq!(c.config().api_key, "real");
}

#[test]
fn retry_policy_defaults() {
    let r = RetryPolicy::default();
    assert_eq!(r.max_attempts, 4);
    assert_eq!(r.initial_backoff, Duration::from_millis(400));
    assert_eq!(r.max_backoff, Duration::from_secs(20));
}

// ─── ShodanError display ─────────────────────────────────────────────────────

#[test]
fn shodan_error_display() {
    assert_eq!(format!("{}", ShodanError::RateLimited), "rate limited");
    assert_eq!(format!("{}", ShodanError::Http("x".into())), "http error: x");
    assert_eq!(format!("{}", ShodanError::Json("y".into())), "json error: y");
    assert_eq!(format!("{}", ShodanError::Auth("z".into())), "auth error: z");
    assert_eq!(
        format!("{}", ShodanError::NotFound("a".into())),
        "not found: a"
    );
    assert_eq!(
        format!("{}", ShodanError::InvalidIp("b".into())),
        "invalid ip: b"
    );
    assert_eq!(
        format!("{}", ShodanError::PlanLimit("c".into())),
        "api plan limit: c"
    );
}

// ─── BannerSummary / BannerAnalyzer ──────────────────────────────────────────

#[test]
fn banner_summary_port_zero_no_category() {
    let b = empty_banner(0);
    let s = BannerSummary::from_banner(&b);
    assert_eq!(s.port, 0);
    assert!(s.category.is_none());
}

#[test]
fn banner_summary_nonzero_port_has_category() {
    let b = empty_banner(22);
    let s = BannerSummary::from_banner(&b);
    assert_eq!(s.category, Some(PortCategory::RemoteAccess));
}

#[test]
fn banner_summary_tls_detection_tls_substring() {
    let mut b = empty_banner(443);
    b.data = Some("HTTP/1.1 200 OK via TLS handshake".into());
    let s = BannerSummary::from_banner(&b);
    assert!(s.tls);
}

#[test]
fn banner_summary_tls_detection_ssl_substring() {
    let mut b = empty_banner(443);
    b.data = Some("openssl negotiation".into());
    let s = BannerSummary::from_banner(&b);
    assert!(s.tls);
}

#[test]
fn banner_summary_no_tls_when_data_plain() {
    let mut b = empty_banner(80);
    b.data = Some("plain http".into());
    let s = BannerSummary::from_banner(&b);
    assert!(!s.tls);
}

#[test]
fn banner_summary_no_tls_when_data_none() {
    let b = empty_banner(80);
    let s = BannerSummary::from_banner(&b);
    assert!(!s.tls);
}

#[test]
fn banner_summary_cpe_union() {
    let mut b = empty_banner(80);
    b.cpe = vec!["cpe:/a:nginx".into()];
    b.cpe23 = vec!["cpe:2.3:a:nginx".into(), "cpe:/a:nginx".into()];
    let s = BannerSummary::from_banner(&b);
    assert_eq!(s.cpes.len(), 2); // dedup
    assert!(s.cpes.contains("cpe:/a:nginx"));
    assert!(s.cpes.contains("cpe:2.3:a:nginx"));
}

#[test]
fn banner_summary_cves_from_object() {
    let mut b = empty_banner(80);
    b.vulns = Some(serde_json::json!({
        "CVE-2024-0001": {},
        "CVE-2025-1234": {},
        "noncve-key": {},
    }));
    let s = BannerSummary::from_banner(&b);
    assert_eq!(s.cves.len(), 2);
    assert!(s.cves.contains("CVE-2024-0001"));
    assert!(s.cves.contains("CVE-2025-1234"));
}

#[test]
fn banner_summary_cves_from_array() {
    let mut b = empty_banner(80);
    b.vulns = Some(serde_json::json!(["CVE-2020-1", "not-a-cve", "CVE-2020-2"]));
    let s = BannerSummary::from_banner(&b);
    assert_eq!(s.cves.len(), 2);
    assert!(s.cves.contains("CVE-2020-1"));
    assert!(s.cves.contains("CVE-2020-2"));
}

#[test]
fn banner_summary_cves_empty_when_other_value() {
    let mut b = empty_banner(80);
    b.vulns = Some(serde_json::json!("just a string"));
    let s = BannerSummary::from_banner(&b);
    assert!(s.cves.is_empty());
}

#[test]
fn banner_summary_cves_empty_when_none() {
    let b = empty_banner(80);
    let s = BannerSummary::from_banner(&b);
    assert!(s.cves.is_empty());
}

#[test]
fn analyzer_empty_banners() {
    let a = BannerAnalyzer::analyze_banners(&[]);
    assert!(a.per_port.is_empty());
    assert!(a.all_cves.is_empty());
    assert!(a.all_cpes.is_empty());
    assert!(a.products.is_empty());
    assert!(a.is_clean());
    assert_eq!(a.vulnerable_port_count(), 0);
}

#[test]
fn analyzer_collects_products_and_cpes() {
    let mut b1 = empty_banner(22);
    b1.product = Some("OpenSSH".into());
    b1.cpe = vec!["cpe:/a:openbsd:openssh".into()];
    let mut b2 = empty_banner(80);
    b2.product = Some("nginx".into());
    b2.cpe23 = vec!["cpe:2.3:a:nginx".into()];
    let a = BannerAnalyzer::analyze_banners(&[b1, b2]);
    assert_eq!(a.products.len(), 2);
    assert!(a.products.contains("OpenSSH"));
    assert!(a.products.contains("nginx"));
    assert_eq!(a.all_cpes.len(), 2);
}

#[test]
fn analyzer_dedupes_products() {
    let mut b1 = empty_banner(22);
    b1.product = Some("OpenSSH".into());
    let mut b2 = empty_banner(2222);
    b2.product = Some("OpenSSH".into());
    let a = BannerAnalyzer::analyze_banners(&[b1, b2]);
    assert_eq!(a.products.len(), 1);
}

#[test]
fn analyzer_same_port_overwrites() {
    // Two banners on the same port — the BTreeMap stores last insertion.
    let mut b1 = empty_banner(22);
    b1.product = Some("OpenSSH".into());
    let mut b2 = empty_banner(22);
    b2.product = Some("Dropbear".into());
    let a = BannerAnalyzer::analyze_banners(&[b1, b2]);
    assert_eq!(a.per_port.len(), 1);
    assert_eq!(a.per_port[&22].product.as_deref(), Some("Dropbear"));
    // Products set retains both (it's accumulated before insertion).
    assert_eq!(a.products.len(), 2);
}

#[test]
fn analyzer_vulnerable_port_count() {
    let mut b1 = empty_banner(22);
    b1.vulns = Some(serde_json::json!({"CVE-1-1": {}}));
    let b2 = empty_banner(80);
    let mut b3 = empty_banner(443);
    b3.vulns = Some(serde_json::json!(["CVE-3-3"]));
    let a = BannerAnalyzer::analyze_banners(&[b1, b2, b3]);
    assert_eq!(a.vulnerable_port_count(), 2);
    assert!(!a.is_clean());
}

#[test]
fn analyzer_analyze_host_merges_top_level_vulns() {
    let mut h = empty_host("1.2.3.4");
    h.vulns = vec!["CVE-HOST-1".into(), "CVE-HOST-2".into()];
    let mut b = empty_banner(22);
    b.vulns = Some(serde_json::json!({"CVE-BAN-1": {}}));
    h.data = vec![b];
    let a = BannerAnalyzer::analyze_host(&h);
    assert_eq!(a.all_cves.len(), 3);
    assert!(a.all_cves.contains("CVE-HOST-1"));
    assert!(a.all_cves.contains("CVE-HOST-2"));
    assert!(a.all_cves.contains("CVE-BAN-1"));
}

#[test]
fn analyzer_validate_rejects_port_zero() {
    let b = empty_banner(0);
    let e = BannerAnalyzer::validate(&b).unwrap_err();
    assert!(matches!(e, ShodanError::Json(_)));
}

#[test]
fn analyzer_validate_rejects_empty_identifiers() {
    let b = empty_banner(22);
    let e = BannerAnalyzer::validate(&b).unwrap_err();
    assert!(matches!(e, ShodanError::Json(_)));
}

#[test]
fn analyzer_validate_accepts_with_product() {
    let mut b = empty_banner(22);
    b.product = Some("OpenSSH".into());
    BannerAnalyzer::validate(&b).unwrap();
}

#[test]
fn analyzer_validate_accepts_with_data() {
    let mut b = empty_banner(22);
    b.data = Some("SSH-2.0".into());
    BannerAnalyzer::validate(&b).unwrap();
}

#[test]
fn analyzer_validate_accepts_with_cpe() {
    let mut b = empty_banner(22);
    b.cpe = vec!["cpe:/a:openssh".into()];
    BannerAnalyzer::validate(&b).unwrap();
}

// ─── Exposure scoring ────────────────────────────────────────────────────────

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
    assert_eq!(ExposureSeverity::from_score(100), ExposureSeverity::Critical);
    assert_eq!(
        ExposureSeverity::from_score(u32::MAX),
        ExposureSeverity::Critical
    );
}

#[test]
fn exposure_severity_default() {
    assert_eq!(ExposureSeverity::default(), ExposureSeverity::None);
}

#[test]
fn exposure_score_empty_host_zero() {
    let h = empty_host("1.2.3.4");
    let a = HostBannerAnalysis::default();
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.score, 0);
    assert_eq!(s.cve_count, 0);
    assert_eq!(s.severity, ExposureSeverity::None);
    assert!(s.by_category.is_empty());
}

#[test]
fn exposure_score_single_web_port() {
    let mut h = empty_host("1.2.3.4");
    h.ports = vec![80];
    let a = HostBannerAnalysis::default();
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.score, 5);
    assert_eq!(s.severity, ExposureSeverity::Low);
    assert_eq!(s.by_category.len(), 1);
    assert_eq!(s.by_category[0].0, PortCategory::Web);
    assert_eq!(s.by_category[0].1, 5);
}

#[test]
fn exposure_score_capped_at_100() {
    // 10 ICS ports * 35 = 350 risk + ports → capped at 100.
    let mut h = empty_host("1.2.3.4");
    h.ports = vec![102, 502, 44818, 20000, 47808, 102, 502, 44818, 20000, 47808];
    let a = HostBannerAnalysis::default();
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.score, 100);
    assert_eq!(s.severity, ExposureSeverity::Critical);
}

#[test]
fn exposure_score_cve_contribution_capped() {
    let mut h = empty_host("1.2.3.4");
    h.ports = vec![]; // only CVE contribution
    let mut a = HostBannerAnalysis::default();
    for i in 0..20 {
        a.all_cves.insert(format!("CVE-2024-{i:04}"));
    }
    let s = ExposureScorer::score(&h, &a);
    // 20 CVEs * 5 = 100, capped at 40.
    assert_eq!(s.score, 40);
    assert_eq!(s.cve_count, 20);
    assert_eq!(s.severity, ExposureSeverity::Medium);
}

#[test]
fn exposure_score_cve_contribution_below_cap() {
    let mut h = empty_host("1.2.3.4");
    h.ports = vec![];
    let mut a = HostBannerAnalysis::default();
    a.all_cves.insert("CVE-2024-0001".into());
    a.all_cves.insert("CVE-2024-0002".into());
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.score, 10);
    assert_eq!(s.cve_count, 2);
}

#[test]
fn exposure_score_by_category_order_matches_ports() {
    let mut h = empty_host("1.2.3.4");
    h.ports = vec![22, 80, 53];
    let a = HostBannerAnalysis::default();
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.by_category.len(), 3);
    assert_eq!(s.by_category[0].0, PortCategory::RemoteAccess);
    assert_eq!(s.by_category[1].0, PortCategory::Web);
    assert_eq!(s.by_category[2].0, PortCategory::Dns);
    assert_eq!(s.score, 30 + 5 + 8);
}

#[test]
fn exposure_score_combines_ports_and_cves() {
    let mut h = empty_host("1.2.3.4");
    h.ports = vec![22]; // 30
    let mut a = HostBannerAnalysis::default();
    a.all_cves.insert("CVE-1".into()); // +5
    let s = ExposureScorer::score(&h, &a);
    assert_eq!(s.score, 35);
    assert_eq!(s.severity, ExposureSeverity::Medium);
}

// ─── ShodanSearchPage serde ──────────────────────────────────────────────────

#[test]
fn search_page_deserializes_matches_alias() {
    let j = r#"{"total":42,"matches":[]}"#;
    let p: ShodanSearchPage = serde_json::from_str(j).unwrap();
    assert_eq!(p.total, 42);
    assert!(p.banners.is_empty());
}

#[test]
fn search_page_defaults() {
    let p: ShodanSearchPage = serde_json::from_str("{}").unwrap();
    assert_eq!(p.total, 0);
    assert!(p.banners.is_empty());
}

#[test]
fn shodan_banner_ip_str_alias() {
    let j = r#"{"ip_str":"5.6.7.8","port":443}"#;
    let b: ShodanBanner = serde_json::from_str(j).unwrap();
    assert_eq!(b.ip.as_deref(), Some("5.6.7.8"));
    assert_eq!(b.port, 443);
}

#[test]
fn shodan_host_ip_str_alias_and_defaults() {
    let j = r#"{"ip_str":"9.9.9.9"}"#;
    let h: ShodanHost = serde_json::from_str(j).unwrap();
    assert_eq!(h.ip, "9.9.9.9");
    assert!(h.ports.is_empty());
    assert!(h.vulns.is_empty());
    assert!(h.data.is_empty());
}

#[test]
fn shodan_banner_defaults() {
    let b: ShodanBanner = serde_json::from_str("{}").unwrap();
    assert_eq!(b.port, 0);
    assert!(b.ip.is_none());
    assert!(b.cpe.is_empty());
    assert!(b.cpe23.is_empty());
}

// ─── Client send/sync ────────────────────────────────────────────────────────

#[test]
fn client_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ShodanClient>();
    assert_send_sync::<ShodanConfig>();
    assert_send_sync::<ShodanError>();
}
