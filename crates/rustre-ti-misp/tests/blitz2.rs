//! Deep adversarial coverage for rustre-ti-misp public API.

use rustre_ti_misp::{
    MispAnalysis, MispApiClient, MispAttribute, MispAttributeFull, MispAttributeType,
    MispDistribution, MispDistributionLevel, MispError, MispEvent, MispEventFull, MispEventSpec,
    MispGalaxy, MispGalaxyCluster, MispObject, MispObjectFull, MispOrg, MispSearch, MispSharingGroup,
    MispSighting, MispTag, MispThreatLevel, MispThreatLevelId, MispWarningList, NewMispAttribute,
    NewMispEvent,
};
use rustre_ti_misp::models::MispAttribute as AttrAlias;
use std::collections::HashSet;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn client() -> MispApiClient {
    MispApiClient::new("https://misp.test".to_string(), "k".to_string())
}

// ---------- MispAttributeType ----------

#[test]
fn attr_type_roundtrip_known() {
    let pairs = [
        (MispAttributeType::Md5, "md5"),
        (MispAttributeType::Sha1, "sha1"),
        (MispAttributeType::Sha256, "sha256"),
        (MispAttributeType::Sha512, "sha512"),
        (MispAttributeType::IpSrc, "ip-src"),
        (MispAttributeType::IpDst, "ip-dst"),
        (MispAttributeType::Domain, "domain"),
        (MispAttributeType::Hostname, "hostname"),
        (MispAttributeType::Email, "email"),
        (MispAttributeType::EmailSrc, "email-src"),
        (MispAttributeType::EmailDst, "email-dst"),
        (MispAttributeType::Mutex, "mutex"),
        (MispAttributeType::Yara, "yara"),
        (MispAttributeType::MalwareSample, "malware-sample"),
        (MispAttributeType::ThreatActor, "threat-actor"),
        (MispAttributeType::Vulnerability, "vulnerability"),
        (MispAttributeType::BtcAddress, "btc"),
        (MispAttributeType::Asn, "AS"),
        (MispAttributeType::Filename, "filename"),
        (MispAttributeType::Ssdeep, "ssdeep"),
        (MispAttributeType::Tlsh, "tlsh"),
        (MispAttributeType::Imphash, "imphash"),
        (MispAttributeType::Sha224, "sha224"),
        (MispAttributeType::Sha384, "sha384"),
    ];
    for (variant, s) in pairs {
        assert_eq!(variant.as_misp_str(), s);
        assert_eq!(MispAttributeType::from_misp_str(s), Some(variant));
    }
}

#[test]
fn attr_type_unknown_strs() {
    let mut g = lcg();
    for _ in 0..60 {
        let n = g();
        let bogus = format!("nonsense-{n:x}");
        assert_eq!(MispAttributeType::from_misp_str(&bogus), None);
    }
    assert_eq!(MispAttributeType::from_misp_str(""), None);
    assert_eq!(MispAttributeType::from_misp_str("\0"), None);
}

#[test]
fn attr_type_url_uri_alias() {
    // The parser collapses uri -> Url.
    assert_eq!(MispAttributeType::from_misp_str("url"), Some(MispAttributeType::Url));
    assert_eq!(MispAttributeType::from_misp_str("uri"), Some(MispAttributeType::Url));
}

#[test]
fn attr_type_regkey_alias() {
    assert_eq!(MispAttributeType::from_misp_str("regkey"), Some(MispAttributeType::Regkey));
    assert_eq!(MispAttributeType::from_misp_str("regkey|value"), Some(MispAttributeType::Regkey));
}

#[test]
fn attr_type_ip_collapsed() {
    // Ip variant emits ip-dst.
    assert_eq!(MispAttributeType::Ip.as_misp_str(), "ip-dst");
}

#[test]
fn attr_type_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let variants = [
        MispAttributeType::Md5,
        MispAttributeType::Sha1,
        MispAttributeType::Sha256,
        MispAttributeType::Sha512,
        MispAttributeType::IpSrc,
        MispAttributeType::IpDst,
        MispAttributeType::Domain,
        MispAttributeType::Hostname,
        MispAttributeType::Url,
        MispAttributeType::Email,
        MispAttributeType::Mutex,
        MispAttributeType::Yara,
        MispAttributeType::Filename,
        MispAttributeType::Asn,
        MispAttributeType::BtcAddress,
        MispAttributeType::Vulnerability,
        MispAttributeType::ThreatActor,
        MispAttributeType::Ssdeep,
        MispAttributeType::Tlsh,
        MispAttributeType::Imphash,
        MispAttributeType::Sha224,
        MispAttributeType::Sha384,
        MispAttributeType::EmailSrc,
        MispAttributeType::EmailDst,
        MispAttributeType::EmailSubject,
        MispAttributeType::Comment,
        MispAttributeType::Other,
        MispAttributeType::Text,
        MispAttributeType::Link,
        MispAttributeType::Process,
    ];
    let mut seen = HashSet::new();
    for v in &variants {
        assert_eq!(v.clone(), v.clone());
        let mut h1 = DefaultHasher::new();
        v.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        v.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        seen.insert(v.clone());
    }
    // All variants distinct, but Registry/Regkey share as_misp_str (designed).
    assert!(seen.len() >= 30);
}

#[test]
fn attr_type_serde_kebab_case() {
    let json = serde_json::to_string(&MispAttributeType::IpSrc).unwrap();
    assert_eq!(json, "\"ip-src\"");
    let back: MispAttributeType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, MispAttributeType::IpSrc);
}

// ---------- MispDistributionLevel ----------

#[test]
fn distribution_level_value_roundtrip() {
    for v in 0u8..=5 {
        let d = MispDistributionLevel::from_value(v).unwrap();
        assert_eq!(d.value(), v);
    }
}

#[test]
fn distribution_level_invalid_values() {
    for v in 6u8..=255 {
        assert!(MispDistributionLevel::from_value(v).is_none(), "v={v}");
    }
}

#[test]
fn distribution_level_ordering() {
    assert!(MispDistributionLevel::OrgOnly < MispDistributionLevel::Community);
    assert!(MispDistributionLevel::Community < MispDistributionLevel::AllCommunities);
    assert!(MispDistributionLevel::SharingGroup < MispDistributionLevel::NoDistribution);
}

#[test]
fn distribution_level_display() {
    assert_eq!(MispDistributionLevel::OrgOnly.to_string(), "Organisation only");
    assert_eq!(MispDistributionLevel::Community.to_string(), "Community");
    assert_eq!(MispDistributionLevel::Connected.to_string(), "Connected communities");
    assert_eq!(MispDistributionLevel::AllCommunities.to_string(), "All communities");
    assert_eq!(MispDistributionLevel::SharingGroup.to_string(), "Sharing group");
    assert_eq!(MispDistributionLevel::NoDistribution.to_string(), "No distribution");
}

// ---------- MispThreatLevelId ----------

#[test]
fn threat_level_id_roundtrip() {
    for v in 1u8..=4 {
        let t = MispThreatLevelId::from_value(v).unwrap();
        assert_eq!(t.value(), v);
    }
}

#[test]
fn threat_level_id_invalid() {
    assert!(MispThreatLevelId::from_value(0).is_none());
    let mut g = lcg();
    for _ in 0..30 {
        let v = (g() as u8) | 0x80; // ensure >=128
        assert!(MispThreatLevelId::from_value(v).is_none(), "v={v}");
    }
}

#[test]
fn threat_level_display_strings() {
    assert_eq!(MispThreatLevelId::High.to_string(), "High");
    assert_eq!(MispThreatLevelId::Medium.to_string(), "Medium");
    assert_eq!(MispThreatLevelId::Low.to_string(), "Low");
    assert_eq!(MispThreatLevelId::Undefined.to_string(), "Undefined");
}

// ---------- models::MispThreatLevel ----------

#[test]
fn model_threat_level_id_roundtrip() {
    for level in [
        MispThreatLevel::High,
        MispThreatLevel::Medium,
        MispThreatLevel::Low,
        MispThreatLevel::Undefined,
    ] {
        let id = level.as_id();
        assert_eq!(MispThreatLevel::from_id(id), level);
    }
}

#[test]
fn model_threat_level_unknown_id_undefined() {
    let mut g = lcg();
    for _ in 0..50 {
        let id = (g() % 250 + 5) as u8;
        assert_eq!(MispThreatLevel::from_id(id), MispThreatLevel::Undefined);
    }
    assert_eq!(MispThreatLevel::from_id(0), MispThreatLevel::Undefined);
}

// ---------- models::MispAnalysis ----------

#[test]
fn model_analysis_known_roundtrip() {
    assert_eq!(MispAnalysis::from_id(MispAnalysis::Ongoing.as_id()), MispAnalysis::Ongoing);
    assert_eq!(MispAnalysis::from_id(MispAnalysis::Completed.as_id()), MispAnalysis::Completed);
    assert_eq!(MispAnalysis::from_id(MispAnalysis::Initial.as_id()), MispAnalysis::Initial);
}

#[test]
fn model_analysis_unknown_defaults_initial() {
    let mut g = lcg();
    for _ in 0..50 {
        let id = (g() % 250 + 3) as u8;
        assert_eq!(MispAnalysis::from_id(id), MispAnalysis::Initial);
    }
}

// ---------- models::MispDistribution ----------

#[test]
fn model_distribution_ids() {
    assert_eq!(MispDistribution::Organization.as_id(), 0);
    assert_eq!(MispDistribution::Community.as_id(), 1);
    assert_eq!(MispDistribution::Connected.as_id(), 2);
    assert_eq!(MispDistribution::All.as_id(), 3);
    assert_eq!(MispDistribution::SharingGroup.as_id(), 4);
    assert_eq!(MispDistribution::Inherit.as_id(), 5);
}

// ---------- MispTag ----------

#[test]
fn tag_tlp_colors_known() {
    assert_eq!(MispTag::tlp("WHITE").color, "#FFFFFF");
    assert_eq!(MispTag::tlp("GREEN").color, "#33FF00");
    assert_eq!(MispTag::tlp("AMBER").color, "#FFC000");
    assert_eq!(MispTag::tlp("RED").color, "#FF0033");
    assert_eq!(MispTag::tlp("white").color, "#FFFFFF");
    assert_eq!(MispTag::tlp("UNKNOWN").color, "#CCCCCC");
}

#[test]
fn tag_tlp_name_lowercase() {
    assert_eq!(MispTag::tlp("RED").name, "tlp:red");
    assert_eq!(MispTag::tlp("AMBER").name, "tlp:amber");
}

#[test]
fn tag_eq_hash() {
    let t1 = MispTag::new("a", "#000");
    let t2 = MispTag::new("a", "#000");
    let t3 = MispTag::new("b", "#000");
    assert_eq!(t1, t2);
    assert_ne!(t1, t3);
}

// ---------- MispAttribute (models) ----------

#[test]
fn attribute_builder_defaults() {
    let a = MispAttribute::new("cat", "ty", "v");
    assert!(!a.to_ids);
    assert!(a.comment.is_empty());
    assert!(a.tags.is_empty());
    assert!(a.id.is_none());
    assert!(a.event_id.is_none());
}

#[test]
fn attribute_builder_chain() {
    let a = AttrAlias::new("c", "md5", "abc")
        .with_to_ids(true)
        .with_comment("note")
        .with_tag(MispTag::tlp("RED"));
    assert!(a.to_ids);
    assert_eq!(a.comment, "note");
    assert_eq!(a.tags.len(), 1);
}

#[test]
fn attribute_serde_type_rename() {
    let a = MispAttribute::new("cat", "sha256", "abc");
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"type\":\"sha256\""));
    let back: MispAttribute = serde_json::from_str(&json).unwrap();
    assert_eq!(back.ty, "sha256");
}

// ---------- MispObject ----------

#[test]
fn object_new_empty() {
    let o = MispObject::new("file", "malware", "desc");
    assert_eq!(o.name, "file");
    assert!(o.attributes.is_empty());
}

// ---------- MispEvent (models) ----------

#[test]
fn event_total_attribute_count_combined() {
    let mut e = MispEvent::new(
        "info",
        MispThreatLevel::High,
        MispAnalysis::Initial,
        MispDistribution::Community,
    );
    e.add_attribute(MispAttribute::new("c", "t", "v"));
    let mut o = MispObject::new("o", "mc", "d");
    o.attributes.push(MispAttribute::new("c", "t", "v"));
    o.attributes.push(MispAttribute::new("c", "t", "v"));
    e.add_object(o);
    e.add_tag(MispTag::tlp("RED"));
    assert_eq!(e.total_attribute_count(), 3);
    assert_eq!(e.tags.len(), 1);
    assert!(!e.uuid.is_empty());
}

#[test]
fn event_uuid_format_36_chars() {
    let e = MispEvent::new("i", MispThreatLevel::Low, MispAnalysis::Initial, MispDistribution::Inherit);
    assert_eq!(e.uuid.len(), 36);
    assert_eq!(e.uuid.chars().filter(|c| *c == '-').count(), 4);
}

// ---------- NewMispEvent ----------

#[test]
fn new_event_defaults() {
    let n = NewMispEvent::new("hi");
    assert_eq!(n.info, "hi");
    assert_eq!(n.threat_level_id, 4);
    assert_eq!(n.analysis, 0);
    assert!(n.date.is_none());
    assert!(n.tags.is_empty());
}

#[test]
fn new_event_builder_chain() {
    let n = NewMispEvent::new("e")
        .with_threat_level(MispThreatLevel::High)
        .with_analysis(MispAnalysis::Completed)
        .with_distribution(MispDistribution::All)
        .with_tag("tlp:red")
        .with_tag("apt");
    assert_eq!(n.threat_level_id, 1);
    assert_eq!(n.analysis, 2);
    assert_eq!(n.distribution.as_id(), 3);
    assert_eq!(n.tags.len(), 2);
}

// ---------- NewMispAttribute ----------

#[test]
fn new_attribute_defaults() {
    let n = NewMispAttribute::new("cat", "sha256", "v");
    assert!(!n.to_ids);
    assert_eq!(n.distribution.as_id(), MispDistribution::Inherit.as_id());
}

#[test]
fn new_attribute_builder() {
    let n = NewMispAttribute::new("c", "md5", "v")
        .with_to_ids(true)
        .with_comment("x")
        .with_distribution(MispDistribution::Organization);
    assert!(n.to_ids);
    assert_eq!(n.comment, "x");
    assert_eq!(n.distribution.as_id(), 0);
}

// ---------- MispApiClient ----------

#[test]
fn client_construction_defaults() {
    let c = client();
    assert!(c.verify_ssl);
    assert_eq!(c.timeout_secs, 30);
}

#[test]
fn client_without_ssl() {
    let c = client().without_ssl_verify();
    assert!(!c.verify_ssl);
}

#[test]
fn client_with_timeout() {
    let c = client().with_timeout(99);
    assert_eq!(c.timeout_secs, 99);
}

#[test]
fn client_parse_attribute_types_known() {
    use rustre_threatintel::IoCType;
    let pairs = [
        ("md5", IoCType::Md5),
        ("sha1", IoCType::Sha1),
        ("sha256", IoCType::Sha256),
        ("sha512", IoCType::Sha512),
        ("ip-src", IoCType::Ip),
        ("ip-dst", IoCType::Ip),
        ("domain", IoCType::Domain),
        ("hostname", IoCType::Domain),
        ("url", IoCType::Url),
        ("uri", IoCType::Url),
        ("email", IoCType::Email),
        ("email-src", IoCType::Email),
        ("email-dst", IoCType::Email),
        ("mutex", IoCType::Mutex),
        ("yara", IoCType::Yara),
        ("filename", IoCType::Filename),
        ("regkey", IoCType::Registry),
        ("regkey|value", IoCType::Registry),
    ];
    for (s, t) in pairs {
        assert_eq!(MispApiClient::parse_misp_attribute_type(s), Some(t));
    }
}

#[test]
fn client_parse_attribute_types_fuzz_unknown_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = g();
        let s = format!("{n:x}-fuzz");
        let _ = MispApiClient::parse_misp_attribute_type(&s);
    }
    assert!(MispApiClient::parse_misp_attribute_type("").is_none());
    assert!(MispApiClient::parse_misp_attribute_type("\x00\x7f").is_none());
}

// ---------- MispSearch builder ----------

#[test]
fn search_builder_chain() {
    let s = MispSearch::new()
        .with_value("v")
        .with_type("sha256")
        .with_tag("malware")
        .with_tag("emotet")
        .without_tag("fp")
        .with_date_range("2024-01-01", "2024-12-31")
        .with_limit(100)
        .with_threat_level(1);
    assert_eq!(s.value.as_deref(), Some("v"));
    assert_eq!(s.type_attribute.as_deref(), Some("sha256"));
    assert_eq!(s.tags.len(), 2);
    assert_eq!(s.not_tags.len(), 1);
    assert_eq!(s.date_from.as_deref(), Some("2024-01-01"));
    assert_eq!(s.date_to.as_deref(), Some("2024-12-31"));
    assert_eq!(s.limit, Some(100));
    assert_eq!(s.threat_level_id, Some(1));
}

#[test]
fn search_default_is_empty() {
    let s = MispSearch::new();
    assert!(s.value.is_none());
    assert!(s.tags.is_empty());
    assert!(!s.include_objects);
}

#[test]
fn search_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = g();
        let s = MispSearch::new()
            .with_value(format!("v{n}"))
            .with_limit((n % 1000) as usize);
        let json = serde_json::to_string(&s).unwrap();
        let back: MispSearch = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, s.value);
        assert_eq!(back.limit, s.limit);
    }
}

// ---------- MispEventFull / MispAttributeFull / MispObjectFull ----------

#[test]
fn event_full_new_defaults() {
    let e = MispEventFull::new("test".to_string());
    assert_eq!(e.info, "test");
    assert_eq!(e.threat_level_id, 4);
    assert_eq!(e.analysis, 0);
    assert!(!e.published);
    assert!(e.attributes.is_empty());
}

#[test]
fn event_full_ioc_count_filters_non_ioc() {
    let mut e = MispEventFull::new("t".to_string());
    e.add_attribute(MispAttributeFull::new(1, "sha256".to_string(), "h".to_string()));
    e.add_attribute(MispAttributeFull::new(2, "md5".to_string(), "h".to_string()));
    e.add_attribute(MispAttributeFull::new(3, "comment".to_string(), "n".to_string()));
    e.add_attribute(MispAttributeFull::new(4, "text".to_string(), "n".to_string()));
    assert_eq!(e.ioc_count(), 2);
}

#[test]
fn event_full_has_ids_attributes_flag() {
    let mut e = MispEventFull::new("t".to_string());
    let mut a = MispAttributeFull::new(1, "md5".to_string(), "h".to_string());
    a.to_ids = true;
    e.add_attribute(a);
    assert!(e.has_ids_attributes());
    let mut e2 = MispEventFull::new("t".to_string());
    e2.add_attribute(MispAttributeFull::new(1, "md5".to_string(), "h".to_string()));
    assert!(!e2.has_ids_attributes());
}

#[test]
fn attribute_full_as_ioc_type() {
    let a = MispAttributeFull::new(1, "sha256".to_string(), "h".to_string());
    assert!(a.as_ioc_type().is_some());
    let b = MispAttributeFull::new(1, "comment".to_string(), "n".to_string());
    assert!(b.as_ioc_type().is_none());
}

#[test]
fn object_full_add_attribute() {
    let mut o = MispObjectFull::new("file".to_string(), "malware".to_string());
    o.add_attribute(MispAttributeFull::new(1, "md5".to_string(), "v".to_string()));
    assert_eq!(o.attributes.len(), 1);
}

// ---------- MispGalaxy ----------

#[test]
fn galaxy_find_and_add() {
    let mut g = MispGalaxy::new("MITRE ATT&CK".to_string(), "mitre-attack".to_string());
    for i in 0..50 {
        g.add_cluster(MispGalaxyCluster::new(
            format!("u{i}"),
            format!("T{i:04}"),
            "technique".to_string(),
        ));
    }
    assert!(g.find_cluster("T0000").is_some());
    assert!(g.find_cluster("T0049").is_some());
    assert!(g.find_cluster("T9999").is_none());
    assert_eq!(g.clusters.len(), 50);
}

// ---------- MispSharingGroup / MispOrg ----------

#[test]
fn sharing_group_orgs() {
    let mut sg = MispSharingGroup::new(1, "g".to_string());
    for i in 0..10 {
        sg.add_org(MispOrg::new(i, format!("o{i}"), format!("u{i}")));
    }
    assert_eq!(sg.organisations.len(), 10);
    assert!(sg.active);
}

// ---------- MispSighting ----------

#[test]
fn sighting_false_positive_predicate() {
    let s0 = MispSighting::new("a".to_string(), 0);
    let s1 = MispSighting::new("a".to_string(), 1);
    let s2 = MispSighting::new("a".to_string(), 2);
    assert!(!s0.is_false_positive());
    assert!(s1.is_false_positive());
    assert!(!s2.is_false_positive());
}

// ---------- MispWarningList ----------

#[test]
fn warning_list_matches_boundary() {
    let mut wl = MispWarningList::new(1, "wl".to_string());
    wl.entries = vec!["8.8.8.8".to_string(), "a".to_string()];
    assert!(wl.matches("8.8.8.8"));
    assert!(wl.matches("a"));
    assert!(!wl.matches(""));
    assert!(!wl.matches("8.8.8.9"));
}

// ---------- MispEventSpec backward-compat ----------

#[test]
fn event_spec_has_ids_attributes_empty() {
    let e = MispEventSpec {
        id: 0,
        uuid: "u".to_string(),
        info: "i".to_string(),
        date: "2024-01-01".to_string(),
        threat_level_id: 4,
        attributes: vec![],
        tags: vec![],
    };
    assert!(!e.has_ids_attributes());
}

// ---------- Async API smoke / fuzz ----------

#[tokio::test]
async fn async_get_event_requires_instance() {
    assert!(client().get_event(7).await.is_err());
}

#[tokio::test]
// Every call below needs the live MISP instance.  They used to succeed
// offline: three events for any search, `id = 1` for an event never created,
// `true` for a publish that never happened, and a warning-list verdict from a
// two-name substring test.

async fn async_search_events_requires_instance() {
    let c = client();
    assert!(c.search_events(&MispSearch::new().with_limit(100)).await.is_err());
    assert!(c.search_events(&MispSearch::new().with_limit(1)).await.is_err());
}

#[tokio::test]
async fn async_search_events_default_requires_instance() {
    assert!(client().search_events(&MispSearch::new()).await.is_err());
}

#[tokio::test]
async fn async_create_event_requires_instance() {
    let e = MispEventFull::new("x".to_string());
    assert!(client().create_event(e).await.is_err());
}

#[tokio::test]
async fn async_add_attribute_requires_instance() {
    let a = MispAttributeFull::new(0, "md5".to_string(), "v".to_string());
    assert!(client().add_attribute(99, a).await.is_err());
}

#[tokio::test]
async fn async_publish_event_requires_instance() {
    assert!(client().publish_event(1).await.is_err());
}

#[tokio::test]
async fn async_check_warning_list_never_guesses() {
    let c = client();
    let mut g = lcg();
    for _ in 0..30 {
        let n = g();
        let v = format!("host-{n:x}.example.com");
        assert!(c.check_warning_lists(&v).await.is_err());
    }
    // These two used to be reported as warning-listed on a substring match.
    assert!(c.check_warning_lists("google.com").await.is_err());
    assert!(c.check_warning_lists("microsoft.com").await.is_err());
}

// ---------- TiProvider impl ----------

#[tokio::test]
async fn provider_lookup_needs_a_reachable_instance() {
    use rustre_threatintel::{IoC, IoCType, TiProvider};
    // 192.0.2.1 is RFC 5737 TEST-NET-1: it never answers.
    let c = MispApiClient::new("https://192.0.2.1".to_string(), "k".to_string());
    let ioc = IoC::new(IoCType::Sha256, "cleanhash".to_string(), "t".to_string());
    // The lookup fails; it does not fall back to a manufactured verdict.
    assert!(c.lookup(&ioc).await.is_err());
}

#[tokio::test]
async fn provider_lookup_does_not_flag_on_the_name_alone() {
    use rustre_threatintel::{IoC, IoCType, TiProvider};
    let c = MispApiClient::new("https://192.0.2.1".to_string(), "k".to_string());
    let ioc = IoC::new(IoCType::Domain, "evil.example.com".to_string(), "t".to_string());
    // "evil" in the name used to be enough for a malicious verdict.
    assert!(c.lookup(&ioc).await.is_err());
}

#[test]
fn provider_supported_types_contains_core() {
    use rustre_threatintel::{IoCType, TiProvider};
    let v = client().supported_ioc_types();
    for t in [IoCType::Md5, IoCType::Sha256, IoCType::Ip, IoCType::Domain] {
        assert!(v.contains(&t), "missing {t:?}");
    }
}

// ---------- MispError ----------

#[test]
fn error_helpers_and_display() {
    let e = MispError::not_found("x");
    assert!(e.to_string().contains("not found"));
    let e2 = MispError::invalid_input("bad");
    assert!(e2.to_string().contains("invalid"));
    let e3 = MispError::AuthError;
    assert!(e3.to_string().contains("API key"));
    let e4 = MispError::Http { status: 500, body: "boom".to_string() };
    assert!(e4.to_string().contains("500"));
}

#[test]
fn error_into_ti_error() {
    let e: rustre_threatintel::TiError = MispError::not_found("x").into();
    assert!(matches!(e, rustre_threatintel::TiError::NotFound(_)));
    let e: rustre_threatintel::TiError = MispError::AuthError.into();
    assert!(matches!(e, rustre_threatintel::TiError::InvalidApiKey(_)));
    let e: rustre_threatintel::TiError = MispError::Http { status: 1, body: "b".into() }.into();
    assert!(matches!(e, rustre_threatintel::TiError::Http(_)));
}

// ---------- Send+Sync threaded stress ----------

#[test]
fn send_sync_threaded_stress_event_creation() {
    use std::sync::Arc;
    use std::thread;
    let info = Arc::new("shared".to_string());
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let info = info.clone();
            thread::spawn(move || {
                let mut count = 0;
                for i in 0..100 {
                    let mut e = MispEvent::new(
                        format!("{}-{t}-{i}", *info),
                        MispThreatLevel::Medium,
                        MispAnalysis::Initial,
                        MispDistribution::Community,
                    );
                    e.add_attribute(MispAttribute::new("c", "md5", format!("h{i}")));
                    count += e.total_attribute_count();
                }
                count
            })
        })
        .collect();
    let mut total = 0;
    for h in handles {
        total += h.join().unwrap();
    }
    assert_eq!(total, 4 * 100);
}

#[test]
fn send_sync_threaded_client_parse() {
    use std::thread;
    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(|| {
                let mut count = 0;
                for _ in 0..100 {
                    if MispApiClient::parse_misp_attribute_type("sha256").is_some() {
                        count += 1;
                    }
                }
                count
            })
        })
        .collect();
    let mut total = 0;
    for h in handles {
        total += h.join().unwrap();
    }
    assert_eq!(total, 400);
}

// ---------- Serde fuzz on MispEvent ----------

#[test]
fn event_full_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = g();
        let mut e = MispEventFull::new(format!("info-{n}"));
        e.id = n;
        e.threat_level_id = ((n % 4) + 1) as u8;
        let json = serde_json::to_string(&e).unwrap();
        let back: MispEventFull = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, e.id);
        assert_eq!(back.info, e.info);
        assert_eq!(back.threat_level_id, e.threat_level_id);
    }
}

#[test]
fn event_models_serde_roundtrip_fuzz() {
    let mut g = lcg();
    let levels = [
        MispThreatLevel::High,
        MispThreatLevel::Medium,
        MispThreatLevel::Low,
        MispThreatLevel::Undefined,
    ];
    let analyses = [MispAnalysis::Initial, MispAnalysis::Ongoing, MispAnalysis::Completed];
    let dists = [
        MispDistribution::Organization,
        MispDistribution::Community,
        MispDistribution::All,
        MispDistribution::Inherit,
    ];
    for _ in 0..50 {
        let n = g();
        let level = levels[(n as usize) % levels.len()];
        let an = analyses[(n as usize >> 8) % analyses.len()];
        let dist = dists[(n as usize >> 16) % dists.len()];
        let e = MispEvent::new(format!("e{n}"), level, an, dist);
        let json = serde_json::to_string(&e).unwrap();
        let back: MispEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.info, e.info);
        assert_eq!(back.threat_level, level);
        assert_eq!(back.analysis, an);
    }
}

// ---------- Truncated / malformed JSON ----------

#[test]
fn malformed_json_returns_err_no_panic() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = g();
        let bad = format!("{{ \"id\": {n}, \"info\": \"x\" "); // truncated
        let r: Result<MispEventFull, _> = serde_json::from_str(&bad);
        assert!(r.is_err());
    }
    let r: Result<MispEvent, _> = serde_json::from_str("");
    assert!(r.is_err());
    let r: Result<MispEvent, _> = serde_json::from_str("null");
    assert!(r.is_err());
}

// ---------- Integer boundary ----------

#[test]
fn event_full_id_max_min() {
    let mut e = MispEventFull::new("e".to_string());
    e.id = u64::MAX;
    let json = serde_json::to_string(&e).unwrap();
    let back: MispEventFull = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id, u64::MAX);
    e.id = 0;
    let json = serde_json::to_string(&e).unwrap();
    let back: MispEventFull = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id, 0);
}

#[test]
fn distribution_level_value_no_overflow() {
    // Round-trip across the whole u8 space; only 0..=5 are valid.
    let mut valid = 0usize;
    for v in 0u8..=255 {
        if let Some(d) = MispDistributionLevel::from_value(v) {
            assert_eq!(d.value(), v);
            valid += 1;
        }
    }
    assert_eq!(valid, 6);
}
