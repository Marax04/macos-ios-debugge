//! Deep adversarial integration tests for `rustre-ti-otx`.

use rustre_ti_otx::otx_ioc_extractor::{
    ExtractionConfig, ExtractionResult, IocType, OtxIoc, OtxIocExtractor,
};
use rustre_ti_otx::otx_pulse_parser::{
    OtxIndicator, OtxIndicatorType, OtxPulse, OtxPulseParser, ParseConfig,
};
use rustre_ti_otx::otx_subscription_manager::{
    IndicatorKind, IndicatorSection, OtxClient, RetryPolicy,
};
use rustre_ti_otx::{OtxConfig, OtxError, ThreatLevel};

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

// ─── Seeded LCG ──────────────────────────────────────────────────────────────

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

struct Lcg(u64);
impl Lcg {
    const fn new(s: u64) -> Self { Self(s) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parser() -> OtxPulseParser {
    OtxPulseParser::with_defaults(OtxConfig::new("test-key"))
}

fn parser_with(cfg: ParseConfig) -> OtxPulseParser {
    OtxPulseParser::new(OtxConfig::new("test-key"), cfg)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn t01_otxconfig_new_defaults() {
    let c = OtxConfig::new("k");
    assert_eq!(c.api_key, "k");
    assert_eq!(c.base_url, "https://otx.alienvault.com");
    assert_eq!(c.timeout_secs, 30);
    assert_eq!(c.page_size, 50);
}

#[test]
fn t02_pulse_url_format() {
    let c = OtxConfig::new("k");
    assert_eq!(c.pulse_url("abc"),
        "https://otx.alienvault.com/api/v1/pulses/abc");
    assert!(c.subscribed_url().ends_with("/api/v1/pulses/subscribed"));
}

#[test]
fn t03_threatlevel_from_int_complete() {
    assert_eq!(ThreatLevel::from_int(0), ThreatLevel::Unknown);
    assert_eq!(ThreatLevel::from_int(1), ThreatLevel::Low);
    assert_eq!(ThreatLevel::from_int(2), ThreatLevel::Medium);
    assert_eq!(ThreatLevel::from_int(3), ThreatLevel::High);
    assert_eq!(ThreatLevel::from_int(4), ThreatLevel::Critical);
    for v in 5u8..=255u8 {
        assert_eq!(ThreatLevel::from_int(v), ThreatLevel::Unknown);
    }
}

#[test]
fn t04_threatlevel_severity_roundtrip() {
    for v in 1u8..=4u8 {
        let tl = ThreatLevel::from_int(v);
        assert_eq!(tl.severity(), v);
    }
    assert_eq!(ThreatLevel::Unknown.severity(), 0);
}

#[test]
fn t05_threatlevel_display() {
    assert_eq!(ThreatLevel::Low.to_string(), "low");
    assert_eq!(ThreatLevel::Medium.to_string(), "medium");
    assert_eq!(ThreatLevel::High.to_string(), "high");
    assert_eq!(ThreatLevel::Critical.to_string(), "critical");
    assert_eq!(ThreatLevel::Unknown.to_string(), "unknown");
}

#[test]
fn t06_threatlevel_ord() {
    assert!(ThreatLevel::Unknown < ThreatLevel::Low);
    assert!(ThreatLevel::Low < ThreatLevel::Medium);
    assert!(ThreatLevel::Medium < ThreatLevel::High);
    assert!(ThreatLevel::High < ThreatLevel::Critical);
}

#[test]
fn t07_indicator_type_is_network() {
    use OtxIndicatorType::*;
    let net = [Ipv4, Ipv6, Domain, Hostname, Url, Uri, CidrIpv4, CidrIpv6];
    for t in &net { assert!(t.is_network(), "{t:?}"); }
    let nonet = [Email, FileHashMd5, FileHashSha1, FileHashSha256,
                 FilePath, Mutex, Cve, Yara, Other];
    for t in &nonet { assert!(!t.is_network(), "{t:?}"); }
}

#[test]
fn t08_indicator_type_is_hash() {
    use OtxIndicatorType::*;
    for t in [FileHashMd5, FileHashSha1, FileHashSha256] {
        assert!(t.is_hash());
    }
    for t in [Ipv4, Domain, Email, Url, Mutex, Cve, Other] {
        assert!(!t.is_hash());
    }
}

#[test]
fn t09_indicator_type_display_unique() {
    use OtxIndicatorType::*;
    let all = [Ipv4, Ipv6, Domain, Hostname, Email, Url, Uri,
               FileHashMd5, FileHashSha1, FileHashSha256, FilePath,
               Mutex, Cve, Yara, CidrIpv4, CidrIpv6, Other];
    let mut seen = HashSet::new();
    for t in &all {
        let s = t.to_string();
        assert!(seen.insert(s.clone()), "duplicate display: {s}");
    }
}

#[test]
fn t10_indicator_type_serde_roundtrip() {
    use OtxIndicatorType::*;
    for t in [Ipv4, Ipv6, Domain, Hostname, Email, Url, Uri,
              FileHashMd5, FileHashSha1, FileHashSha256, FilePath,
              Mutex, Cve, Yara, CidrIpv4, CidrIpv6] {
        let j = serde_json::to_string(&t).unwrap();
        let back: OtxIndicatorType = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}

#[test]
fn t11_indicator_type_serde_other_fallback() {
    let v: OtxIndicatorType =
        serde_json::from_str("\"SOMETHING_WEIRD\"").unwrap();
    assert_eq!(v, OtxIndicatorType::Other);
}

#[test]
fn t12_indicator_helpers_validity() {
    let i1 = OtxIndicator::ip(1, "1.2.3.4");
    assert!(i1.is_valid());
    let i2 = OtxIndicator::ip(2, "  ");
    assert!(!i2.is_valid());
    let i3 = OtxIndicator::domain(3, "x.com");
    assert!(i3.is_valid());
    let i4 = OtxIndicator::sha256(4, "abc");
    assert!(i4.is_valid());
    assert_eq!(i4.indicator_type, OtxIndicatorType::FileHashSha256);
}

#[test]
fn t13_pulse_sample_invariants() {
    let p = OtxPulse::sample();
    assert!(!p.id.is_empty());
    assert!(p.has_attack_mapping());
    assert_eq!(p.threat_level(), ThreatLevel::High);
    assert_eq!(p.indicators.len(), 3);
    assert_eq!(p.network_indicators().len(), 2);
    assert_eq!(p.hash_indicators().len(), 1);
}

#[test]
fn t14_pulse_indicator_counts() {
    let p = OtxPulse::sample();
    let c = p.indicator_counts();
    assert_eq!(c.get("IPv4").copied().unwrap_or(0), 1);
    assert_eq!(c.get("domain").copied().unwrap_or(0), 1);
    assert_eq!(c.get("SHA256").copied().unwrap_or(0), 1);
    assert_eq!(c.values().sum::<usize>(), 3);
}

#[test]
fn t15_pulse_threat_level_none() {
    let mut p = OtxPulse::sample();
    p.threat_level_id = None;
    assert_eq!(p.threat_level(), ThreatLevel::Unknown);
}

#[test]
fn t16_parse_roundtrip_sample() {
    let p = OtxPulse::sample();
    let j = serde_json::to_string(&p).unwrap();
    let r = parser().parse_pulse(&j).unwrap();
    assert_eq!(r.id, p.id);
    assert_eq!(r.indicators.len(), p.indicators.len());
}

#[test]
fn t17_parse_pulse_missing_id() {
    let r = parser().parse_pulse(r#"{"name":"x"}"#);
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn t18_parse_pulse_invalid_json() {
    let r = parser().parse_pulse("{not json");
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn t19_parse_pulse_too_large() {
    let big = "x".repeat(16 * 1024 * 1024 + 1);
    let r = parser().parse_pulse(&big);
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn t20_parse_pulse_minimal_id_only() {
    let j = r#"{"id":"only-id"}"#;
    let p = parser().parse_pulse(j).unwrap();
    assert_eq!(p.id, "only-id");
    assert_eq!(p.name, "Unnamed");
    assert_eq!(p.author_name, "unknown");
    assert!(p.indicators.is_empty());
}

#[test]
fn t21_parse_pulse_empty_description_becomes_none() {
    let j = r#"{"id":"p1","description":""}"#;
    let p = parser().parse_pulse(j).unwrap();
    assert!(p.description.is_none());
}

#[test]
fn t22_parse_pulse_skip_inactive() {
    let j = r#"{
        "id":"p1",
        "indicators":[
            {"id":1,"type":"IPv4","indicator":"1.1.1.1","is_active":true,"created":"2024"},
            {"id":2,"type":"IPv4","indicator":"2.2.2.2","is_active":false,"created":"2024"}
        ]
    }"#;
    let p = parser().parse_pulse(j).unwrap();
    assert_eq!(p.indicators.len(), 1);
    assert_eq!(p.indicators[0].indicator, "1.1.1.1");
}

#[test]
fn t23_parse_pulse_skip_invalid_empty() {
    let j = r#"{
        "id":"p1",
        "indicators":[
            {"id":1,"type":"IPv4","indicator":"","is_active":true},
            {"id":2,"type":"IPv4","indicator":"   ","is_active":true},
            {"id":3,"type":"IPv4","indicator":"3.3.3.3","is_active":true}
        ]
    }"#;
    let p = parser().parse_pulse(j).unwrap();
    assert_eq!(p.indicators.len(), 1);
}

#[test]
fn t24_parse_pulse_no_skip_invalid() {
    let cfg = ParseConfig {
        skip_inactive: false, skip_invalid: false,
        max_indicators: None, allowed_types: vec![]
    };
    let j = r#"{
        "id":"p1",
        "indicators":[
            {"id":1,"type":"IPv4","indicator":"","is_active":true},
            {"id":2,"type":"IPv4","indicator":"x","is_active":false}
        ]
    }"#;
    let p = parser_with(cfg).parse_pulse(j).unwrap();
    assert_eq!(p.indicators.len(), 2);
}

#[test]
fn t25_parse_pulse_max_indicators_truncates() {
    let cfg = ParseConfig { skip_inactive: true, skip_invalid: true,
        max_indicators: Some(2), allowed_types: vec![] };
    let j = serde_json::to_string(&OtxPulse::sample()).unwrap();
    let p = parser_with(cfg).parse_pulse(&j).unwrap();
    assert_eq!(p.indicators.len(), 2);
}

#[test]
fn t26_parse_pulse_threat_level_overflow_clamps() {
    let j = r#"{"id":"p1","threat_level_id":99999}"#;
    let p = parser().parse_pulse(j).unwrap();
    assert_eq!(p.threat_level_id, Some(u8::MAX));
}

#[test]
fn t27_parse_pulse_subscriber_count_overflow_saturates() {
    let big = u64::from(u32::MAX) + 100;
    let j = format!(r#"{{"id":"p1","subscriber_count":{big}}}"#);
    let p = parser().parse_pulse(&j).unwrap();
    assert_eq!(p.subscriber_count, u32::MAX);
}

#[test]
fn t28_parse_pulse_attack_ids_display_name_or_id() {
    let j = r#"{
        "id":"p1",
        "attack_ids":[
            {"display_name":"T1071"},
            {"id":"T1055"},
            {"display_name":"T9999","id":"ignored"}
        ]
    }"#;
    let p = parser().parse_pulse(j).unwrap();
    assert_eq!(p.attack_ids, vec!["T1071", "T1055", "T9999"]);
}

#[test]
fn t29_parse_pulse_public_zero_one() {
    let j0 = r#"{"id":"p","public":0}"#;
    let j1 = r#"{"id":"p","public":1}"#;
    assert!(!parser().parse_pulse(j0).unwrap().public);
    assert!(parser().parse_pulse(j1).unwrap().public);
}

#[test]
fn t30_parse_subscribed_page_ok() {
    let p1 = serde_json::to_value(OtxPulse::sample()).unwrap();
    let j = serde_json::json!({"results":[p1.clone(), p1]});
    let v = parser().parse_subscribed_page(&j.to_string()).unwrap();
    assert_eq!(v.len(), 2);
}

#[test]
fn t31_parse_subscribed_page_missing_results() {
    let r = parser().parse_subscribed_page("{}");
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn t32_parse_subscribed_page_skips_bad_entries() {
    let good = serde_json::to_value(OtxPulse::sample()).unwrap();
    let j = serde_json::json!({"results":[good, {"name":"no id"}]});
    let v = parser().parse_subscribed_page(&j.to_string()).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn t33_parse_subscribed_page_too_large() {
    let big = "x".repeat(16 * 1024 * 1024 + 1);
    let r = parser().parse_subscribed_page(&big);
    assert!(matches!(r, Err(OtxError::Json(_))));
}

#[test]
fn t34_parser_pulse_url() {
    let p = parser();
    assert!(p.pulse_url("abc").ends_with("/api/v1/pulses/abc"));
}

#[test]
fn t35_lcg_fuzz_parse_pulse_never_panics() {
    let mut lcg = Lcg::new(lcg_seed());
    let p = parser();
    for _ in 0..200 {
        let n = (lcg.next() % 256) as usize;
        let bytes: Vec<u8> = (0..n).map(|_| (lcg.next() & 0x7f) as u8).collect();
        let s = String::from_utf8_lossy(&bytes).to_string();
        // Must return Ok or specific Err, never panic
        let _ = p.parse_pulse(&s);
    }
}

#[test]
fn t36_lcg_fuzz_parse_subscribed_never_panics() {
    let mut lcg = Lcg::new(lcg_seed());
    let p = parser();
    for _ in 0..200 {
        let n = (lcg.next() % 256) as usize;
        let bytes: Vec<u8> = (0..n).map(|_| (lcg.next() & 0x7f) as u8).collect();
        let s = String::from_utf8_lossy(&bytes).to_string();
        let _ = p.parse_subscribed_page(&s);
    }
}

#[test]
fn t37_lcg_fuzz_threatlevel_from_int() {
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..100 {
        let v = (lcg.next() & 0xff) as u8;
        let tl = ThreatLevel::from_int(v);
        // severity must always be in [0,4]
        assert!(tl.severity() <= 4);
    }
}

#[test]
fn t38_ioctype_display_unique() {
    use IocType::*;
    let all = [IpAddress, Domain, Url, FileHashMd5, FileHashSha1,
               FileHashSha256, Email, FilePath, Mutex, Cve, Yara, Other];
    let mut seen = HashSet::new();
    for t in &all {
        assert!(seen.insert(t.to_string()));
    }
}

#[test]
fn t39_ioctype_from_otx_mapping() {
    use OtxIndicatorType as O;
    use IocType as I;
    assert_eq!(I::from(&O::Ipv4), I::IpAddress);
    assert_eq!(I::from(&O::Ipv6), I::IpAddress);
    assert_eq!(I::from(&O::CidrIpv4), I::IpAddress);
    assert_eq!(I::from(&O::CidrIpv6), I::IpAddress);
    assert_eq!(I::from(&O::Domain), I::Domain);
    assert_eq!(I::from(&O::Hostname), I::Domain);
    assert_eq!(I::from(&O::Url), I::Url);
    assert_eq!(I::from(&O::Uri), I::Url);
    assert_eq!(I::from(&O::Other), I::Other);
}

#[test]
fn t40_extraction_basic_sample() {
    let e = OtxIocExtractor::default_config();
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert_eq!(r.iocs.len(), 3);
    assert_eq!(r.raw_indicator_count, 3);
    assert_eq!(r.duplicate_count, 0);
}

#[test]
fn t41_extraction_empty_pulse_id_err() {
    let e = OtxIocExtractor::default_config();
    let mut p = OtxPulse::sample();
    p.id = String::new();
    let r = e.extract_from_pulse(&p);
    assert!(matches!(r, Err(OtxError::InvalidInput(_))));
}

#[test]
fn t42_extraction_dedup_merges_pulse_ids() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "p2".to_string();
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    for ioc in &r.iocs {
        assert_eq!(ioc.occurrence_count, 2);
        assert_eq!(ioc.pulse_ids.len(), 2);
    }
}

#[test]
fn t43_extraction_min_occurrences_filter() {
    let cfg = ExtractionConfig { min_occurrences: 2, ..Default::default() };
    let e = OtxIocExtractor::new(cfg);
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert!(r.iocs.is_empty()); // occurrence_count is 1
    assert_eq!(r.excluded_count, 3);
}

#[test]
fn t44_extraction_max_iocs_truncates() {
    let cfg = ExtractionConfig { max_iocs: Some(1), ..Default::default() };
    let e = OtxIocExtractor::new(cfg);
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    assert_eq!(r.iocs.len(), 1);
}

#[test]
fn t45_extraction_skip_inactive() {
    let cfg = ExtractionConfig { skip_inactive: true, ..Default::default() };
    let e = OtxIocExtractor::new(cfg);
    let mut p = OtxPulse::sample();
    for i in &mut p.indicators { i.is_active = false; }
    let r = e.extract_from_pulse(&p).unwrap();
    assert!(r.iocs.is_empty());
}

#[test]
fn t46_extraction_no_dedup() {
    let cfg = ExtractionConfig { deduplicate: false, ..Default::default() };
    let e = OtxIocExtractor::new(cfg);
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "p2".to_string();
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    assert_eq!(r.iocs.len(), 6);
}

#[test]
fn t47_extraction_network_only() {
    let e = OtxIocExtractor::default_config();
    let v = e.extract_network_iocs(&[OtxPulse::sample()]).unwrap();
    assert_eq!(v.len(), 2);
    assert!(v.iter().all(rustre_ti_otx::otx_ioc_extractor::OtxIoc::is_network));
}

#[test]
fn t48_extraction_hash_only() {
    let e = OtxIocExtractor::default_config();
    let v = e.extract_hash_iocs(&[OtxPulse::sample()]).unwrap();
    assert_eq!(v.len(), 1);
    assert!(v[0].is_hash());
}

#[test]
fn t49_extraction_corroborated() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample(); p2.id = "p2".into();
    let v = e.extract_corroborated_iocs(&[p1, p2], 2).unwrap();
    assert_eq!(v.len(), 3);
    let v0 = e.extract_corroborated_iocs(&[OtxPulse::sample()], 2).unwrap();
    assert!(v0.is_empty());
}

#[test]
fn t50_score_ioc_caps_100() {
    let ioc = OtxIoc {
        value: "x".into(),
        ioc_type: IocType::IpAddress,
        raw_type: "IPv4".into(),
        pulse_ids: vec!["a".into(); 100],
        description: None,
        occurrence_count: 100,
        first_seen: "x".into(), last_seen: "x".into(),
        is_active: true,
    };
    let s = OtxIocExtractor::score_ioc(&ioc);
    assert!(s <= 100);
    assert!(s >= 20);
}

#[test]
fn t51_score_ioc_other_low() {
    let ioc = OtxIoc {
        value: "x".into(), ioc_type: IocType::Other,
        raw_type: "OTHER".into(), pulse_ids: vec!["a".into()],
        description: None, occurrence_count: 1,
        first_seen: "x".into(), last_seen: "x".into(), is_active: false,
    };
    assert_eq!(OtxIocExtractor::score_ioc(&ioc), 3 + 4);
}

#[test]
fn t52_merge_keeps_earliest_and_latest() {
    let i1 = OtxIndicator {
        id: 1, indicator_type: OtxIndicatorType::Ipv4,
        indicator: "1.1.1.1".into(), description: None, title: None,
        created: "2024-03-01T00:00:00Z".into(),
        is_active: true, related_cve: None,
    };
    let mut ioc = OtxIoc::from_indicator(&i1, "p1");
    let i2 = OtxIndicator {
        created: "2024-01-01T00:00:00Z".into(),
        ..i1
    };
    ioc.merge(&i2, "p2".into(), "2024-12-31T00:00:00Z");
    assert_eq!(ioc.first_seen, "2024-01-01T00:00:00Z");
    assert_eq!(ioc.last_seen, "2024-12-31T00:00:00Z");
    assert_eq!(ioc.pulse_ids, vec!["p1", "p2"]);
    assert_eq!(ioc.occurrence_count, 2);
}

#[test]
fn t53_merge_duplicate_pulse_id_no_increment() {
    let i1 = OtxIndicator::ip(1, "1.1.1.1");
    let mut ioc = OtxIoc::from_indicator(&i1, "p1");
    ioc.merge(&i1, "p1".into(), "2024-01-02T00:00:00Z");
    assert_eq!(ioc.pulse_ids.len(), 1);
    assert_eq!(ioc.occurrence_count, 1);
}

#[test]
fn t54_merge_active_sticks() {
    let mut i1 = OtxIndicator::ip(1, "1.1.1.1");
    i1.is_active = false;
    let mut ioc = OtxIoc::from_indicator(&i1, "p1");
    assert!(!ioc.is_active);
    let mut i2 = OtxIndicator::ip(1, "1.1.1.1");
    i2.is_active = true;
    ioc.merge(&i2, "p2".into(), "2024-12-31");
    assert!(ioc.is_active);
}

#[test]
fn t55_extraction_result_grouped_and_counts() {
    let e = OtxIocExtractor::default_config();
    let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
    let g = r.grouped();
    let c = r.type_counts();
    assert_eq!(g.len(), c.len());
    for (k, v) in g {
        assert_eq!(c.get(&k).copied(), Some(v.len()));
    }
}

#[test]
fn t56_extraction_by_frequency_descending() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample();
    p2.id = "p2".into();
    p2.indicators.truncate(1);
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    let sorted = r.by_frequency();
    for w in sorted.windows(2) {
        assert!(w[0].occurrence_count >= w[1].occurrence_count);
    }
}

#[test]
fn t57_contributing_pulses() {
    let e = OtxIocExtractor::default_config();
    let p1 = OtxPulse::sample();
    let mut p2 = OtxPulse::sample(); p2.id = "p2".into();
    let r = e.extract_iocs(&[p1, p2]).unwrap();
    let s = OtxIocExtractor::contributing_pulses(&r);
    assert!(s.contains("pulse-abc-123"));
    assert!(s.contains("p2"));
}

#[test]
fn t58_indicator_kind_segments() {
    assert_eq!(IndicatorKind::IPv4.api_segment(), "IPv4");
    assert_eq!(IndicatorKind::IPv6.api_segment(), "IPv6");
    assert_eq!(IndicatorKind::Domain.api_segment(), "domain");
    assert_eq!(IndicatorKind::Hostname.api_segment(), "hostname");
    assert_eq!(IndicatorKind::Url.api_segment(), "url");
    assert_eq!(IndicatorKind::FileHash.api_segment(), "file");
    assert_eq!(IndicatorKind::Cve.api_segment(), "cve");
}

#[test]
fn t59_indicator_section_segments() {
    assert_eq!(IndicatorSection::General.api_segment(), "general");
    assert_eq!(IndicatorSection::Malware.api_segment(), "malware");
    assert_eq!(IndicatorSection::UrlList.api_segment(), "url_list");
    assert_eq!(IndicatorSection::PassiveDns.api_segment(), "passive_dns");
    assert_eq!(IndicatorSection::Reputation.api_segment(), "reputation");
    assert_eq!(IndicatorSection::Geo.api_segment(), "geo");
    assert_eq!(IndicatorSection::Analysis.api_segment(), "analysis");
}

#[test]
fn t60_indicator_kind_hash_eq() {
    let mut m = HashMap::new();
    m.insert(IndicatorKind::IPv4, 1);
    m.insert(IndicatorKind::Domain, 2);
    assert_eq!(m.get(&IndicatorKind::IPv4), Some(&1));
    assert_eq!(m.get(&IndicatorKind::Domain), Some(&2));
    // 30+ pairs
    let kinds = [IndicatorKind::IPv4, IndicatorKind::IPv6,
        IndicatorKind::Domain, IndicatorKind::Hostname,
        IndicatorKind::Url, IndicatorKind::FileHash, IndicatorKind::Cve];
    for a in &kinds {
        for b in &kinds {
            let mut h1 = std::collections::hash_map::DefaultHasher::new();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            a.hash(&mut h1); b.hash(&mut h2);
            if a == b {
                assert_eq!(h1.finish(), h2.finish());
            }
        }
    }
}

#[test]
fn t61_retry_defaults_sane() {
    let r = RetryPolicy::default();
    assert!(r.max_attempts >= 2);
    assert!(r.initial_backoff < r.max_backoff);
}

#[test]
fn t62_otxclient_new_ok() {
    let r = OtxClient::new(OtxConfig::new("valid-key"));
    assert!(r.is_ok());
    let c = r.unwrap();
    assert_eq!(c.config().api_key, "valid-key");
}

#[test]
fn t63_otxclient_new_invalid_header_key() {
    // Newline in header value is invalid.
    let r = OtxClient::new(OtxConfig::new("bad\nkey"));
    assert!(matches!(r, Err(OtxError::Auth(_))));
}

#[test]
fn t64_otxclient_with_retry_policy() {
    let c = OtxClient::new(OtxConfig::new("k")).unwrap();
    let r = RetryPolicy { max_attempts: 7,
        initial_backoff: std::time::Duration::from_millis(10),
        max_backoff: std::time::Duration::from_secs(1) };
    let _c2 = c.with_retry_policy(r);
}

#[test]
fn t65_otxclient_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OtxClient>();
    assert_send_sync::<OtxConfig>();
}

#[test]
fn t66_threaded_stress_threatlevel() {
    let mut handles = vec![];
    for tid in 0_u64..4 {
        handles.push(thread::spawn(move || {
            let mut lcg = Lcg::new(lcg_seed().wrapping_add(tid));
            for _ in 0..100 {
                let v = (lcg.next() & 0xff) as u8;
                let tl = ThreatLevel::from_int(v);
                assert!(tl.severity() <= 4);
                let _ = tl.to_string();
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn t67_threaded_stress_parser() {
    let p = Arc::new(parser());
    let j = Arc::new(serde_json::to_string(&OtxPulse::sample()).unwrap());
    let mut handles = vec![];
    for _ in 0..4 {
        let p = Arc::clone(&p);
        let j = Arc::clone(&j);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = p.parse_pulse(&j).unwrap();
                assert_eq!(r.indicators.len(), 3);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn t68_threaded_stress_extractor() {
    let e = Arc::new(OtxIocExtractor::default_config());
    let mut handles = vec![];
    for _ in 0..4 {
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = e.extract_from_pulse(&OtxPulse::sample()).unwrap();
                assert_eq!(r.iocs.len(), 3);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn t69_otxconfig_serde_roundtrip() {
    let c = OtxConfig::new("k");
    let j = serde_json::to_string(&c).unwrap();
    let c2: OtxConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(c.api_key, c2.api_key);
    assert_eq!(c.base_url, c2.base_url);
}

#[test]
fn t70_pulse_serde_roundtrip() {
    let p = OtxPulse::sample();
    let j = serde_json::to_string(&p).unwrap();
    let p2: OtxPulse = serde_json::from_str(&j).unwrap();
    assert_eq!(p.id, p2.id);
    assert_eq!(p.indicators.len(), p2.indicators.len());
}

#[test]
fn t71_lcg_50_inputs_parse_pulse_with_id() {
    let p = parser();
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let id = format!("pulse-{:x}", lcg.next());
        let j = format!(r#"{{"id":"{id}"}}"#);
        let parsed = p.parse_pulse(&j).unwrap();
        assert_eq!(parsed.id, id);
    }
}

#[test]
fn t72_extraction_50_random_pulses_invariants() {
    let e = OtxIocExtractor::default_config();
    let mut lcg = Lcg::new(lcg_seed());
    let mut pulses = vec![];
    for i in 0..10 {
        let mut p = OtxPulse::sample();
        p.id = format!("p-{i}");
        // tweak indicator value with LCG-derived data
        for ind in &mut p.indicators {
            let nybble = (lcg.next() & 0xf) as u8;
            ind.indicator = format!("{nybble}.{nybble}.{nybble}.{nybble}");
        }
        pulses.push(p);
    }
    let r = e.extract_iocs(&pulses).unwrap();
    assert!(r.raw_indicator_count == 30);
    // sorted by type then value
    for w in r.iocs.windows(2) {
        let a = (w[0].ioc_type.to_string(), w[0].value.clone());
        let b = (w[1].ioc_type.to_string(), w[1].value.clone());
        assert!(a <= b);
    }
}

#[test]
fn t73_extraction_result_default() {
    let r = ExtractionResult::default();
    assert!(r.iocs.is_empty());
    assert_eq!(r.raw_indicator_count, 0);
}

#[test]
fn t74_parse_config_default_values() {
    let c = ParseConfig::default();
    assert!(c.skip_inactive);
    assert!(c.skip_invalid);
    assert!(c.max_indicators.is_none());
    assert!(c.allowed_types.is_empty());
}

#[test]
fn t75_extraction_config_default_values() {
    let c = ExtractionConfig::default();
    assert!(c.deduplicate);
    assert_eq!(c.min_occurrences, 1);
    assert!(!c.skip_inactive);
    assert!(c.max_iocs.is_none());
}

#[test]
fn t76_indicator_type_hash_consistency() {
    use OtxIndicatorType::*;
    let pairs = [(Ipv4, Ipv4), (Domain, Domain), (FileHashMd5, FileHashMd5),
                 (Url, Url), (Cve, Cve), (Other, Other)];
    for (a, b) in pairs {
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1); b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn t77_ioctype_hash_consistency() {
    use IocType::*;
    let all = [IpAddress, Domain, Url, FileHashMd5, FileHashSha1,
               FileHashSha256, Email, FilePath, Mutex, Cve, Yara, Other];
    let set: HashSet<_> = all.iter().cloned().collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn t78_lcg_fuzz_extraction_never_panics() {
    let e = OtxIocExtractor::default_config();
    let mut lcg = Lcg::new(lcg_seed());
    for _ in 0..50 {
        let mut p = OtxPulse::sample();
        p.id = format!("p-{}", lcg.next());
        let count = (lcg.next() % 5) as usize;
        p.indicators.truncate(count);
        let _ = e.extract_from_pulse(&p);
    }
}
