//! Blitz tests for rustre-ti-otx.

use rustre_ti_otx::otx_ioc_extractor::{
    ExtractionConfig, IocType, OtxIoc, OtxIocExtractor,
};
use rustre_ti_otx::otx_pulse_parser::{
    OtxIndicator, OtxIndicatorType, OtxPulse, OtxPulseParser, ParseConfig,
};
use rustre_ti_otx::otx_subscription_manager::{
    IndicatorKind, IndicatorSection, OtxClient, RetryPolicy,
};
use rustre_ti_otx::{OtxConfig, OtxError, ThreatLevel};

// ─── ThreatLevel ────────────────────────────────────────────────────────────

#[test]
fn threat_level_from_int_known() {
    assert_eq!(ThreatLevel::from_int(1), ThreatLevel::Low);
    assert_eq!(ThreatLevel::from_int(2), ThreatLevel::Medium);
    assert_eq!(ThreatLevel::from_int(3), ThreatLevel::High);
    assert_eq!(ThreatLevel::from_int(4), ThreatLevel::Critical);
}

#[test]
fn threat_level_from_int_unknown() {
    assert_eq!(ThreatLevel::from_int(0), ThreatLevel::Unknown);
    assert_eq!(ThreatLevel::from_int(5), ThreatLevel::Unknown);
    assert_eq!(ThreatLevel::from_int(u8::MAX), ThreatLevel::Unknown);
}

#[test]
fn threat_level_severity_roundtrip() {
    for v in 1..=4u8 {
        assert_eq!(ThreatLevel::from_int(v).severity(), v);
    }
    assert_eq!(ThreatLevel::Unknown.severity(), 0);
}

#[test]
fn threat_level_ord() {
    assert!(ThreatLevel::Low < ThreatLevel::Medium);
    assert!(ThreatLevel::Medium < ThreatLevel::High);
    assert!(ThreatLevel::High < ThreatLevel::Critical);
    assert!(ThreatLevel::Unknown < ThreatLevel::Low);
}

#[test]
fn threat_level_display() {
    assert_eq!(format!("{}", ThreatLevel::Critical), "critical");
    assert_eq!(format!("{}", ThreatLevel::Unknown), "unknown");
}

// ─── OtxConfig ──────────────────────────────────────────────────────────────

#[test]
fn config_defaults() {
    let c = OtxConfig::new("k");
    assert_eq!(c.api_key, "k");
    assert_eq!(c.base_url, "https://otx.alienvault.com");
    assert_eq!(c.timeout_secs, 30);
    assert_eq!(c.page_size, 50);
}

#[test]
fn config_pulse_url() {
    let c = OtxConfig::new("k");
    assert_eq!(
        c.pulse_url("abc"),
        "https://otx.alienvault.com/api/v1/pulses/abc"
    );
}

#[test]
fn config_subscribed_url() {
    let c = OtxConfig::new("k");
    assert_eq!(
        c.subscribed_url(),
        "https://otx.alienvault.com/api/v1/pulses/subscribed"
    );
}

#[test]
fn config_serde_roundtrip() {
    let c = OtxConfig::new("zzz");
    let j = serde_json::to_string(&c).unwrap();
    let back: OtxConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(back.api_key, "zzz");
}

// ─── OtxIndicatorType ───────────────────────────────────────────────────────

#[test]
fn indicator_type_is_network() {
    assert!(OtxIndicatorType::Ipv4.is_network());
    assert!(OtxIndicatorType::Ipv6.is_network());
    assert!(OtxIndicatorType::Domain.is_network());
    assert!(OtxIndicatorType::Hostname.is_network());
    assert!(OtxIndicatorType::Url.is_network());
    assert!(OtxIndicatorType::Uri.is_network());
    assert!(OtxIndicatorType::CidrIpv4.is_network());
    assert!(OtxIndicatorType::CidrIpv6.is_network());
    assert!(!OtxIndicatorType::FileHashMd5.is_network());
    assert!(!OtxIndicatorType::Cve.is_network());
}

#[test]
fn indicator_type_is_hash() {
    assert!(OtxIndicatorType::FileHashMd5.is_hash());
    assert!(OtxIndicatorType::FileHashSha1.is_hash());
    assert!(OtxIndicatorType::FileHashSha256.is_hash());
    assert!(!OtxIndicatorType::Ipv4.is_hash());
    assert!(!OtxIndicatorType::Mutex.is_hash());
}

#[test]
fn indicator_type_display_values() {
    assert_eq!(OtxIndicatorType::Ipv4.to_string(), "IPv4");
    assert_eq!(OtxIndicatorType::Ipv6.to_string(), "IPv6");
    assert_eq!(OtxIndicatorType::FileHashMd5.to_string(), "MD5");
    assert_eq!(OtxIndicatorType::FileHashSha1.to_string(), "SHA1");
    assert_eq!(OtxIndicatorType::FileHashSha256.to_string(), "SHA256");
    assert_eq!(OtxIndicatorType::Cve.to_string(), "CVE");
    assert_eq!(OtxIndicatorType::CidrIpv4.to_string(), "CIDR_IPv4");
}

// ─── OtxIndicator ───────────────────────────────────────────────────────────

#[test]
fn indicator_is_valid() {
    assert!(OtxIndicator::ip(1, "1.2.3.4").is_valid());
    let empty = OtxIndicator::ip(1, "");
    assert!(!empty.is_valid());
    let ws = OtxIndicator::ip(1, "   ");
    assert!(!ws.is_valid());
}

#[test]
fn indicator_constructors() {
    let ip = OtxIndicator::ip(7, "9.9.9.9");
    assert_eq!(ip.indicator_type, OtxIndicatorType::Ipv4);
    assert_eq!(ip.id, 7);
    let d = OtxIndicator::domain(1, "x.com");
    assert_eq!(d.indicator_type, OtxIndicatorType::Domain);
    let h = OtxIndicator::sha256(2, "deadbeef");
    assert_eq!(h.indicator_type, OtxIndicatorType::FileHashSha256);
}

// ─── OtxPulse ───────────────────────────────────────────────────────────────

#[test]
fn pulse_sample_threat_level() {
    assert_eq!(OtxPulse::sample().threat_level(), ThreatLevel::High);
}

#[test]
fn pulse_sample_indicator_counts() {
    let p = OtxPulse::sample();
    let c = p.indicator_counts();
    assert_eq!(c.get("IPv4"), Some(&1));
    assert_eq!(c.get("domain"), Some(&1));
    assert_eq!(c.get("SHA256"), Some(&1));
}

#[test]
fn pulse_network_and_hash_indicators() {
    let p = OtxPulse::sample();
    assert_eq!(p.network_indicators().len(), 2);
    assert_eq!(p.hash_indicators().len(), 1);
}

#[test]
fn pulse_has_attack_mapping() {
    assert!(OtxPulse::sample().has_attack_mapping());
    let mut p = OtxPulse::sample();
    p.attack_ids.clear();
    assert!(!p.has_attack_mapping());
}

#[test]
fn pulse_threat_level_none_id() {
    let mut p = OtxPulse::sample();
    p.threat_level_id = None;
    assert_eq!(p.threat_level(), ThreatLevel::Unknown);
}

// ─── IocType ────────────────────────────────────────────────────────────────

#[test]
fn ioc_type_display() {
    assert_eq!(IocType::IpAddress.to_string(), "ip_address");
    assert_eq!(IocType::FileHashMd5.to_string(), "md5");
    assert_eq!(IocType::Cve.to_string(), "cve");
}

#[test]
fn ioc_type_from_indicator_type() {
    assert_eq!(IocType::from(&OtxIndicatorType::Ipv4), IocType::IpAddress);
    assert_eq!(IocType::from(&OtxIndicatorType::CidrIpv6), IocType::IpAddress);
    assert_eq!(IocType::from(&OtxIndicatorType::Hostname), IocType::Domain);
    assert_eq!(IocType::from(&OtxIndicatorType::Uri), IocType::Url);
    assert_eq!(IocType::from(&OtxIndicatorType::Other), IocType::Other);
}

// ─── OtxIoc ─────────────────────────────────────────────────────────────────

#[test]
fn ioc_from_indicator() {
    let i = OtxIndicator::ip(1, "1.1.1.1");
    let ioc = OtxIoc::from_indicator(&i, "p1");
    assert_eq!(ioc.value, "1.1.1.1");
    assert_eq!(ioc.ioc_type, IocType::IpAddress);
    assert_eq!(ioc.pulse_ids, vec!["p1".to_string()]);
    assert_eq!(ioc.occurrence_count, 1);
    assert_eq!(ioc.first_seen, ioc.last_seen);
}

#[test]
fn ioc_is_network_is_hash() {
    let i = OtxIndicator::ip(1, "1.1.1.1");
    let ioc = OtxIoc::from_indicator(&i, "p");
    assert!(ioc.is_network());
    assert!(!ioc.is_hash());

    let h = OtxIndicator::sha256(2, "abc");
    let hioc = OtxIoc::from_indicator(&h, "p");
    assert!(hioc.is_hash());
    assert!(!hioc.is_network());
}

#[test]
fn ioc_merge_new_pulse_id_increments() {
    let i = OtxIndicator::ip(1, "1.1.1.1");
    let mut ioc = OtxIoc::from_indicator(&i, "p1");
    ioc.merge(&i, "p2".into(), "2025-01-01T00:00:00Z");
    assert_eq!(ioc.occurrence_count, 2);
    assert_eq!(ioc.pulse_ids.len(), 2);
    assert_eq!(ioc.last_seen, "2025-01-01T00:00:00Z");
}

#[test]
fn ioc_merge_same_pulse_id_no_increment() {
    let i = OtxIndicator::ip(1, "1.1.1.1");
    let mut ioc = OtxIoc::from_indicator(&i, "p1");
    ioc.merge(&i, "p1".into(), "2025-01-01T00:00:00Z");
    assert_eq!(ioc.occurrence_count, 1);
    assert_eq!(ioc.pulse_ids.len(), 1);
}

#[test]
fn ioc_merge_earlier_first_seen() {
    let mut i = OtxIndicator::ip(1, "1.1.1.1");
    i.created = "2024-06-01T00:00:00Z".to_string();
    let mut ioc = OtxIoc::from_indicator(&i, "p1");
    let mut i2 = i;
    i2.created = "2023-01-01T00:00:00Z".to_string();
    ioc.merge(&i2, "p2".into(), "2024-12-01T00:00:00Z");
    assert_eq!(ioc.first_seen, "2023-01-01T00:00:00Z");
}

#[test]
fn ioc_merge_active_sticky() {
    let mut i = OtxIndicator::ip(1, "1.1.1.1");
    i.is_active = false;
    let mut ioc = OtxIoc::from_indicator(&i, "p1");
    assert!(!ioc.is_active);
    let mut i2 = i;
    i2.is_active = true;
    ioc.merge(&i2, "p2".into(), "2024-12-01T00:00:00Z");
    assert!(ioc.is_active);
}

// ─── OtxIocExtractor ────────────────────────────────────────────────────────

#[test]
fn extract_from_pulse_basic() {
    let e = OtxIocExtractor::default_config();
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert_eq!(r.iocs.len(), 3);
    assert_eq!(r.raw_indicator_count, 3);
    assert_eq!(r.duplicate_count, 0);
}

#[test]
fn extract_from_empty_pulse_id_errors() {
    let e = OtxIocExtractor::default_config();
    let mut p = OtxPulse::sample();
    p.id = String::new();
    match e.extract_from_pulse(&p) {
        Err(OtxError::InvalidInput(_)) => {}
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn extract_iocs_empty_input() {
    let e = OtxIocExtractor::default_config();
    let r = e.extract_iocs(&[]).unwrap();
    assert_eq!(r.iocs.len(), 0);
    assert_eq!(r.raw_indicator_count, 0);
    assert_eq!(r.duplicate_count, 0);
}

#[test]
fn extract_dedup_across_pulses() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "other".into();
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    assert_eq!(r.iocs.len(), 3);
    for ioc in &r.iocs {
        assert_eq!(ioc.occurrence_count, 2);
        assert_eq!(ioc.pulse_ids.len(), 2);
    }
}

#[test]
fn extract_no_dedup_keeps_all() {
    let cfg = ExtractionConfig {
        deduplicate: false,
        ..Default::default()
    };
    let e = OtxIocExtractor::new(cfg);
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "other".into();
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    assert_eq!(r.raw_indicator_count, 6);
    assert_eq!(r.iocs.len(), 6);
}

#[test]
fn extract_type_filter() {
    let cfg = ExtractionConfig {
        include_types: vec![IocType::FileHashSha256],
        ..Default::default()
    };
    let e = OtxIocExtractor::new(cfg);
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert_eq!(r.iocs.len(), 1);
    assert_eq!(r.iocs[0].ioc_type, IocType::FileHashSha256);
    assert_eq!(r.excluded_count, 2);
}

#[test]
fn extract_min_occurrences() {
    let cfg = ExtractionConfig {
        min_occurrences: 2,
        ..Default::default()
    };
    let e = OtxIocExtractor::new(cfg);
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert_eq!(r.iocs.len(), 0);
    assert_eq!(r.excluded_count, 3);
}

#[test]
fn extract_skip_inactive() {
    let cfg = ExtractionConfig {
        skip_inactive: true,
        ..Default::default()
    };
    let e = OtxIocExtractor::new(cfg);
    let mut p = OtxPulse::sample();
    for ind in &mut p.indicators {
        ind.is_active = false;
    }
    let r = e.extract_from_pulse(&p).unwrap();
    assert_eq!(r.iocs.len(), 0);
}

#[test]
fn extract_max_iocs_truncates() {
    let cfg = ExtractionConfig {
        max_iocs: Some(2),
        ..Default::default()
    };
    let e = OtxIocExtractor::new(cfg);
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert_eq!(r.iocs.len(), 2);
}

#[test]
fn extract_network_iocs() {
    let e = OtxIocExtractor::default_config();
    let iocs = e.extract_network_iocs(&[OtxPulse::sample()]).unwrap();
    assert_eq!(iocs.len(), 2);
    assert!(iocs.iter().all(rustre_ti_otx::otx_ioc_extractor::OtxIoc::is_network));
}

#[test]
fn extract_hash_iocs() {
    let e = OtxIocExtractor::default_config();
    let iocs = e.extract_hash_iocs(&[OtxPulse::sample()]).unwrap();
    assert_eq!(iocs.len(), 1);
    assert!(iocs[0].is_hash());
}

#[test]
fn extract_corroborated_iocs() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "p2".into();
    let iocs = e.extract_corroborated_iocs(&[p1, p2], 2).unwrap();
    assert_eq!(iocs.len(), 3);
    let iocs0 = e.extract_corroborated_iocs(&[OtxPulse::sample()], 2).unwrap();
    assert_eq!(iocs0.len(), 0);
}

#[test]
fn extraction_result_groupings() {
    let e = OtxIocExtractor::default_config();
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    let grouped = r.grouped();
    assert!(grouped.contains_key("ip_address"));
    assert!(grouped.contains_key("domain"));
    assert!(grouped.contains_key("sha256"));
    let counts = r.type_counts();
    assert_eq!(counts.get("ip_address").copied(), Some(1));
}

#[test]
fn extraction_result_by_frequency_sorted_desc() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "p2".into();
    p2.indicators.truncate(1);
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    let by = r.by_frequency();
    for w in by.windows(2) {
        assert!(w[0].occurrence_count >= w[1].occurrence_count);
    }
}

#[test]
fn score_ioc_caps_at_100() {
    let mut i = OtxIndicator::ip(1, "1.1.1.1");
    i.is_active = true;
    let mut ioc = OtxIoc::from_indicator(&i, "p");
    ioc.occurrence_count = 1_000_000;
    let s = OtxIocExtractor::score_ioc(&ioc);
    assert!(s <= 100);
}

#[test]
fn score_ioc_type_ordering() {
    let mk = |t: IocType| OtxIoc {
        value: "v".into(),
        ioc_type: t,
        raw_type: "x".into(),
        pulse_ids: vec!["p".into()],
        description: None,
        occurrence_count: 1,
        first_seen: "2024-01-01T00:00:00Z".into(),
        last_seen: "2024-01-01T00:00:00Z".into(),
        is_active: true,
    };
    assert!(OtxIocExtractor::score_ioc(&mk(IocType::IpAddress))
        > OtxIocExtractor::score_ioc(&mk(IocType::FilePath)));
    assert!(OtxIocExtractor::score_ioc(&mk(IocType::Cve))
        > OtxIocExtractor::score_ioc(&mk(IocType::Other)));
}

#[test]
fn contributing_pulses_unique() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "p2".into();
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    let set = OtxIocExtractor::contributing_pulses(&r);
    assert_eq!(set.len(), 2);
}

// ─── OtxPulseParser ─────────────────────────────────────────────────────────

fn make_parser() -> OtxPulseParser {
    OtxPulseParser::with_defaults(OtxConfig::new("k"))
}

#[test]
fn parse_invalid_json_returns_json_error() {
    let p = make_parser();
    match p.parse_pulse("{not json") {
        Err(OtxError::Json(_)) => {}
        o => panic!("{o:?}"),
    }
}

#[test]
fn parse_missing_id_errors() {
    let p = make_parser();
    let r = p.parse_pulse(r#"{"name":"x"}"#);
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn parse_minimal_pulse_defaults() {
    let p = make_parser();
    let pulse = p
        .parse_pulse(r#"{"id":"abc"}"#)
        .expect("should parse with defaults");
    assert_eq!(pulse.id, "abc");
    assert_eq!(pulse.name, "Unnamed");
    assert_eq!(pulse.author_name, "unknown");
    assert_eq!(pulse.indicators.len(), 0);
    assert_eq!(pulse.created, "1970-01-01T00:00:00Z");
    assert!(!pulse.public);
    assert_eq!(pulse.revision, 1);
}

#[test]
fn parse_pulse_roundtrip_preserves_fields() {
    let p = make_parser();
    let sample = OtxPulse::sample();
    let json = serde_json::to_string(&sample).unwrap();
    let back = p.parse_pulse(&json).unwrap();
    assert_eq!(back.id, sample.id);
    assert_eq!(back.name, sample.name);
    assert_eq!(back.indicators.len(), sample.indicators.len());
}

#[test]
fn parse_subscribed_page_skips_bad_entries() {
    let p = make_parser();
    let body = r#"{
        "results": [
            {"id":"ok1","name":"a"},
            {"name":"missing id"},
            {"id":"ok2"}
        ]
    }"#;
    let v = p.parse_subscribed_page(body).unwrap();
    assert_eq!(v.len(), 2);
}

#[test]
fn parse_subscribed_page_missing_results_errors() {
    let p = make_parser();
    let r = p.parse_subscribed_page(r#"{"count":0}"#);
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn parse_pulse_threat_level_overflow_clamped() {
    let p = make_parser();
    let body = r#"{"id":"x","threat_level_id":9999999999}"#;
    let pulse = p.parse_pulse(body).unwrap();
    assert_eq!(pulse.threat_level_id, Some(u8::MAX));
}

#[test]
fn parse_pulse_subscriber_count_overflow_clamped() {
    let p = make_parser();
    let body = r#"{"id":"x","subscriber_count":99999999999}"#;
    let pulse = p.parse_pulse(body).unwrap();
    assert_eq!(pulse.subscriber_count, u32::MAX);
}

#[test]
fn parse_pulse_public_truthy() {
    let p = make_parser();
    let pulse_t = p.parse_pulse(r#"{"id":"x","public":1}"#).unwrap();
    assert!(pulse_t.public);
    let pulse_f = p.parse_pulse(r#"{"id":"x","public":0}"#).unwrap();
    assert!(!pulse_f.public);
}

#[test]
fn parse_pulse_with_attack_ids_display_names() {
    let p = make_parser();
    let body = r#"{
        "id":"x",
        "attack_ids":[{"display_name":"T1071"},{"id":"T1055"}]
    }"#;
    let pulse = p.parse_pulse(body).unwrap();
    assert_eq!(pulse.attack_ids, vec!["T1071".to_string(), "T1055".into()]);
}

#[test]
fn parse_pulse_max_indicators() {
    let cfg = ParseConfig { max_indicators: Some(1), ..ParseConfig::default() };
    let p = OtxPulseParser::new(OtxConfig::new("k"), cfg);
    let json = serde_json::to_string(&OtxPulse::sample()).unwrap();
    let pulse = p.parse_pulse(&json).unwrap();
    assert_eq!(pulse.indicators.len(), 1);
}

#[test]
fn parse_pulse_allowed_types_filter() {
    let cfg = ParseConfig {
        allowed_types: vec![OtxIndicatorType::FileHashSha256],
        ..Default::default()
    };
    let p = OtxPulseParser::new(OtxConfig::new("k"), cfg);
    let json = serde_json::to_string(&OtxPulse::sample()).unwrap();
    let pulse = p.parse_pulse(&json).unwrap();
    assert!(pulse
        .indicators
        .iter()
        .all(|i| i.indicator_type == OtxIndicatorType::FileHashSha256));
    assert_eq!(pulse.indicators.len(), 1);
}

#[test]
fn parse_pulse_skip_inactive_default() {
    let p = make_parser();
    let body = r#"{
        "id":"x",
        "indicators":[
            {"id":1,"type":"IPV4","indicator":"1.1.1.1","is_active":0},
            {"id":2,"type":"IPV4","indicator":"2.2.2.2","is_active":1}
        ]
    }"#;
    let pulse = p.parse_pulse(body).unwrap();
    assert_eq!(pulse.indicators.len(), 1);
    assert_eq!(pulse.indicators[0].indicator, "2.2.2.2");
}

#[test]
fn parse_pulse_skip_invalid_default() {
    let p = make_parser();
    let body = r#"{
        "id":"x",
        "indicators":[
            {"id":1,"type":"IPV4","indicator":"   ","is_active":1},
            {"id":2,"type":"IPV4","indicator":"2.2.2.2","is_active":1}
        ]
    }"#;
    let pulse = p.parse_pulse(body).unwrap();
    assert_eq!(pulse.indicators.len(), 1);
}

#[test]
fn parse_pulse_unknown_indicator_type_maps_other() {
    let p = make_parser();
    let body = r#"{
        "id":"x",
        "indicators":[{"id":1,"type":"WEIRDO","indicator":"v","is_active":1}]
    }"#;
    let pulse = p.parse_pulse(body).unwrap();
    assert_eq!(pulse.indicators.len(), 1);
    assert_eq!(pulse.indicators[0].indicator_type, OtxIndicatorType::Other);
}

#[test]
fn parser_pulse_url_uses_config() {
    let p = make_parser();
    assert!(p.pulse_url("abc").ends_with("/pulses/abc"));
}

// ─── Subscription manager: sync-only checks ─────────────────────────────────

#[test]
fn indicator_kind_segments() {
    assert_eq!(IndicatorKind::IPv4.api_segment(), "IPv4");
    assert_eq!(IndicatorKind::IPv6.api_segment(), "IPv6");
    assert_eq!(IndicatorKind::Domain.api_segment(), "domain");
    assert_eq!(IndicatorKind::Hostname.api_segment(), "hostname");
    assert_eq!(IndicatorKind::Url.api_segment(), "url");
    assert_eq!(IndicatorKind::FileHash.api_segment(), "file");
    assert_eq!(IndicatorKind::Cve.api_segment(), "cve");
}

#[test]
fn indicator_section_segments() {
    assert_eq!(IndicatorSection::General.api_segment(), "general");
    assert_eq!(IndicatorSection::Malware.api_segment(), "malware");
    assert_eq!(IndicatorSection::UrlList.api_segment(), "url_list");
    assert_eq!(IndicatorSection::PassiveDns.api_segment(), "passive_dns");
    assert_eq!(IndicatorSection::Reputation.api_segment(), "reputation");
    assert_eq!(IndicatorSection::Geo.api_segment(), "geo");
    assert_eq!(IndicatorSection::Analysis.api_segment(), "analysis");
}

#[test]
fn retry_policy_default_sanity() {
    let r = RetryPolicy::default();
    assert!(r.max_attempts >= 2);
    assert!(r.initial_backoff < r.max_backoff);
}

#[test]
fn client_new_succeeds_with_ascii_key() {
    let c = OtxClient::new(OtxConfig::new("abc-123"));
    assert!(c.is_ok());
    let c = c.unwrap();
    assert_eq!(c.config().api_key, "abc-123");
}

#[test]
fn client_new_rejects_invalid_header_key() {
    let mut cfg = OtxConfig::new("bad\nkey");
    cfg.timeout_secs = 5;
    let r = OtxClient::new(cfg);
    assert!(matches!(r, Err(OtxError::Auth(_))));
}

#[test]
fn client_with_retry_policy() {
    let c = OtxClient::new(OtxConfig::new("k")).unwrap();
    let policy = RetryPolicy {
        max_attempts: 7,
        initial_backoff: std::time::Duration::from_millis(50),
        max_backoff: std::time::Duration::from_secs(1),
    };
    let c = c.with_retry_policy(policy);
    // No accessor for retry; ensure it remains usable.
    assert_eq!(c.config().api_key, "k");
}

#[test]
fn client_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OtxClient>();
}

// ─── Async-tested pieces ────────────────────────────────────────────────────

#[tokio::test]
async fn subscription_watermark_get_set() {
    use rustre_ti_otx::otx_subscription_manager::OtxSubscription;
    let client = OtxClient::new(OtxConfig::new("k")).unwrap();
    let sub = OtxSubscription::new(client, std::time::Duration::from_secs(60), None);
    assert!(sub.watermark().await.is_none());
    sub.set_watermark(Some("2024-01-01T00:00:00Z".into())).await;
    assert_eq!(sub.watermark().await.as_deref(), Some("2024-01-01T00:00:00Z"));
}
