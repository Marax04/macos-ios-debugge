//! Blitz test suite for rustre-ti-misp — exercises public API surface to
//! flush out edge-case bugs and round-trip violations.

use rustre_ti_misp::client::MispRawClient;
use rustre_ti_misp::error::MispError;
use rustre_ti_misp::export::to_stix_bundle;
use rustre_ti_misp::import::import_csv;
use rustre_ti_misp::misp_attribute_types::{
    AttributeCategory, AttributeTypeRegistry, MispAttrType,
};
use rustre_ti_misp::misp_client::{
    HttpMethod, MispClientConfig, Page, RawResponse, Request, RawMispClient, paginated_query,
    event_url, attribute_url, tag_url,
};
use rustre_ti_misp::models::{
    MispAnalysis, MispAttribute, MispDistribution, MispEvent, MispObject, MispTag,
    MispThreatLevel, NewMispAttribute, NewMispEvent,
};

// ─── MispThreatLevel ──────────────────────────────────────────────────────────

#[test]
fn threat_level_all_known_ids_roundtrip() {
    for (l, id) in [
        (MispThreatLevel::High, 1u8),
        (MispThreatLevel::Medium, 2),
        (MispThreatLevel::Low, 3),
        (MispThreatLevel::Undefined, 4),
    ] {
        assert_eq!(l.as_id(), id);
        assert_eq!(MispThreatLevel::from_id(id), l);
    }
}

#[test]
fn threat_level_from_id_unknown_defaults_undefined() {
    assert_eq!(MispThreatLevel::from_id(0), MispThreatLevel::Undefined);
    assert_eq!(MispThreatLevel::from_id(99), MispThreatLevel::Undefined);
    assert_eq!(MispThreatLevel::from_id(255), MispThreatLevel::Undefined);
}

// ─── MispAnalysis ─────────────────────────────────────────────────────────────

#[test]
fn analysis_all_ids_roundtrip() {
    for a in [MispAnalysis::Initial, MispAnalysis::Ongoing, MispAnalysis::Completed] {
        let id = a.as_id();
        assert_eq!(MispAnalysis::from_id(id), a, "roundtrip failed for {:?} (id={})", a, id);
    }
}

#[test]
fn analysis_unknown_id_defaults_initial() {
    assert_eq!(MispAnalysis::from_id(3), MispAnalysis::Initial);
    assert_eq!(MispAnalysis::from_id(255), MispAnalysis::Initial);
}

// ─── MispDistribution ─────────────────────────────────────────────────────────

#[test]
fn distribution_ids_are_unique() {
    let ids: Vec<u8> = [
        MispDistribution::Organization,
        MispDistribution::Community,
        MispDistribution::Connected,
        MispDistribution::All,
        MispDistribution::SharingGroup,
        MispDistribution::Inherit,
    ]
    .iter()
    .map(|d| d.as_id())
    .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "distribution ids collide: {ids:?}");
}

// ─── MispTag ──────────────────────────────────────────────────────────────────

#[test]
fn tlp_tag_case_insensitive_and_unknown() {
    assert_eq!(MispTag::tlp("white").color, "#FFFFFF");
    assert_eq!(MispTag::tlp("WHITE").color, "#FFFFFF");
    assert_eq!(MispTag::tlp("Green").color, "#33FF00");
    assert_eq!(MispTag::tlp("amber").color, "#FFC000");
    assert_eq!(MispTag::tlp("red").color, "#FF0033");
    // unknown → default grey
    assert_eq!(MispTag::tlp("purple").color, "#CCCCCC");
}

#[test]
fn tlp_tag_name_is_lowercased() {
    assert_eq!(MispTag::tlp("RED").name, "tlp:red");
    assert_eq!(MispTag::tlp("Amber").name, "tlp:amber");
}

// ─── MispEvent / MispAttribute / MispObject ──────────────────────────────────

#[test]
fn event_total_attribute_count_empty() {
    let e = MispEvent::new(
        "x",
        MispThreatLevel::Low,
        MispAnalysis::Initial,
        MispDistribution::All,
    );
    assert_eq!(e.total_attribute_count(), 0);
}

#[test]
fn event_uuid_format_is_uuid_v4_like() {
    let e = MispEvent::new(
        "x",
        MispThreatLevel::Low,
        MispAnalysis::Initial,
        MispDistribution::All,
    );
    // 8-4-4-4-12 hex layout
    let parts: Vec<&str> = e.uuid.split('-').collect();
    assert_eq!(parts.len(), 5, "uuid {} has wrong segment count", e.uuid);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
    // version nibble = '4'
    assert!(parts[2].starts_with('4'), "expected v4 uuid, got {}", e.uuid);
    // variant nibble must be 8|9|a|b
    let var = parts[3].chars().next().unwrap();
    assert!(
        matches!(var, '8' | '9' | 'a' | 'b'),
        "uuid variant nibble must be 8/9/a/b, got {var} in {}",
        e.uuid
    );
}

#[test]
fn event_serde_roundtrip_with_attrs_objects_tags() {
    let mut e = MispEvent::new(
        "RT",
        MispThreatLevel::Medium,
        MispAnalysis::Ongoing,
        MispDistribution::Community,
    );
    e.add_attribute(
        MispAttribute::new("Network activity", "ip-dst", "1.2.3.4")
            .with_to_ids(true)
            .with_comment("c2")
            .with_tag(MispTag::tlp("AMBER")),
    );
    let mut obj = MispObject::new("file", "malware", "f");
    obj.attributes.push(MispAttribute::new("Payload delivery", "md5", "abc"));
    e.add_object(obj);
    e.add_tag(MispTag::new("custom:tag", "#123456"));
    let json = serde_json::to_string(&e).unwrap();
    let back: MispEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.info, "RT");
    assert_eq!(back.total_attribute_count(), 2);
    assert_eq!(back.tags.len(), 1);
    assert_eq!(back.attributes[0].tags.len(), 1);
    assert!(back.attributes[0].to_ids);
}

#[test]
fn new_misp_event_defaults() {
    let n = NewMispEvent::new("info");
    assert_eq!(n.threat_level_id, 4);
    assert_eq!(n.analysis, 0);
    assert!(matches!(n.distribution, MispDistribution::Community));
    assert!(n.date.is_none());
}

#[test]
fn new_misp_event_builder_chain() {
    let n = NewMispEvent::new("x")
        .with_threat_level(MispThreatLevel::High)
        .with_analysis(MispAnalysis::Completed)
        .with_distribution(MispDistribution::All)
        .with_tag("t1")
        .with_tag("t2");
    assert_eq!(n.threat_level_id, 1);
    assert_eq!(n.analysis, 2);
    assert_eq!(n.tags, vec!["t1", "t2"]);
}

#[test]
fn new_misp_attribute_defaults_and_builder() {
    let a = NewMispAttribute::new("Network activity", "ip-dst", "1.1.1.1")
        .with_to_ids(true)
        .with_comment("hi")
        .with_distribution(MispDistribution::All);
    assert!(a.to_ids);
    assert_eq!(a.comment, "hi");
    assert!(matches!(a.distribution, MispDistribution::All));
}

// ─── import::import_csv ───────────────────────────────────────────────────────

#[test]
fn csv_import_empty_yields_empty_event() {
    let e = import_csv("", "empty").unwrap();
    assert_eq!(e.attributes.len(), 0);
    assert_eq!(e.info, "empty");
}

#[test]
fn csv_import_only_comments() {
    let e = import_csv("# a\n# b\n#c", "x").unwrap();
    assert_eq!(e.attributes.len(), 0);
}

#[test]
fn csv_import_unknown_type_defaults_other_no_ids() {
    let e = import_csv("totally-bogus-type,whatever", "x").unwrap();
    assert_eq!(e.attributes.len(), 1);
    assert_eq!(e.attributes[0].category, "Other");
    assert!(!e.attributes[0].to_ids);
}

#[test]
fn csv_import_filename_to_ids_false() {
    let e = import_csv("filename,evil.exe", "x").unwrap();
    assert!(!e.attributes[0].to_ids);
    assert_eq!(e.attributes[0].category, "Payload delivery");
}

#[test]
fn csv_import_value_with_comma_in_comment_field_is_kept_whole() {
    // splitn(3, ',') means the 3rd part may itself contain commas.
    let e = import_csv("ip-dst,1.2.3.4,note,with,commas", "x").unwrap();
    assert_eq!(e.attributes[0].comment, "note,with,commas");
}

#[test]
fn csv_import_error_is_invalid_input_variant() {
    let err = import_csv("solo", "x").unwrap_err();
    match err {
        MispError::InvalidInput(msg) => assert!(msg.contains("line 1")),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn csv_import_whitespace_trimmed() {
    let e = import_csv("  ip-dst  ,  9.9.9.9  ,  spaced  ", "x").unwrap();
    assert_eq!(e.attributes[0].ty, "ip-dst");
    assert_eq!(e.attributes[0].value, "9.9.9.9");
    assert_eq!(e.attributes[0].comment, "spaced");
}

#[test]
fn csv_import_yara_category() {
    let e = import_csv("yara,rule x{}", "x").unwrap();
    assert_eq!(e.attributes[0].category, "Other");
    assert!(!e.attributes[0].to_ids);
}

#[test]
fn csv_import_registry_and_mutex() {
    let e = import_csv(
        "registry-key,HKLM\\evil\nmutex,Global\\foo",
        "x",
    )
    .unwrap();
    assert_eq!(e.attributes.len(), 2);
    assert_eq!(e.attributes[0].category, "Artifacts dropped");
    assert!(e.attributes[0].to_ids);
}

// ─── export::to_stix_bundle ───────────────────────────────────────────────────

#[test]
fn stix_bundle_no_indicators_when_no_to_ids() {
    let mut e = MispEvent::new(
        "x",
        MispThreatLevel::Low,
        MispAnalysis::Initial,
        MispDistribution::All,
    );
    e.add_attribute(MispAttribute::new("Network activity", "ip-dst", "1.1.1.1")); // to_ids=false
    let s = to_stix_bundle(&e);
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let objs = v["objects"].as_array().unwrap();
    // Only the report
    assert_eq!(objs.len(), 1);
    assert_eq!(objs[0]["type"], "report");
}

#[test]
fn stix_bundle_confidence_per_threat_level() {
    for (lvl, expected) in [
        (MispThreatLevel::High, 85),
        (MispThreatLevel::Medium, 60),
        (MispThreatLevel::Low, 30),
        (MispThreatLevel::Undefined, 10),
    ] {
        let e = MispEvent::new("x", lvl, MispAnalysis::Initial, MispDistribution::All);
        let s = to_stix_bundle(&e);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["confidence"], expected, "threat {:?}", lvl);
    }
}

#[test]
fn stix_bundle_escapes_single_quote_in_value() {
    let mut e = MispEvent::new(
        "x",
        MispThreatLevel::Low,
        MispAnalysis::Initial,
        MispDistribution::All,
    );
    let mut a = MispAttribute::new("Network activity", "domain", "evil'site.com");
    a.to_ids = true;
    e.add_attribute(a);
    let s = to_stix_bundle(&e);
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let indicator = objs.iter().find(|o| o["type"] == "indicator").unwrap();
    let pattern = indicator["pattern"].as_str().unwrap();
    assert!(pattern.contains("\\'"), "expected escaped quote in {pattern}");
}

#[test]
fn stix_bundle_skips_unknown_attr_type_for_indicators() {
    let mut e = MispEvent::new(
        "x",
        MispThreatLevel::Low,
        MispAnalysis::Initial,
        MispDistribution::All,
    );
    let mut a = MispAttribute::new("Other", "bogus-type", "v");
    a.to_ids = true;
    e.add_attribute(a);
    let s = to_stix_bundle(&e);
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let objs = v["objects"].as_array().unwrap();
    assert_eq!(objs.len(), 1); // no indicator generated
}

// ─── misp_attribute_types::MispAttrType ──────────────────────────────────────

#[test]
fn attr_type_as_str_and_from_str_roundtrip_basic_set() {
    let set = [
        MispAttrType::Md5, MispAttrType::Sha1, MispAttrType::Sha256, MispAttrType::Sha512,
        MispAttrType::IpSrc, MispAttrType::IpDst, MispAttrType::Domain, MispAttrType::Url,
        MispAttrType::EmailSrc, MispAttrType::Mutex, MispAttrType::Regkey, MispAttrType::Yara,
        MispAttrType::BtcAddress, MispAttrType::Vulnerability,
    ];
    for t in set {
        let s = t.as_str();
        let back = MispAttrType::from_str(s).expect(s);
        assert_eq!(back, t, "roundtrip {s}");
    }
}

#[test]
fn attr_type_from_str_unknown_returns_none() {
    assert!(MispAttrType::from_str("not-a-type-at-all").is_none());
    assert!(MispAttrType::from_str("").is_none());
}

#[test]
fn attr_type_stix_pattern_quote_escape() {
    let p = MispAttrType::Domain.to_stix_pattern("o'reilly.com").unwrap();
    assert!(p.contains("o\\'reilly.com"));
}

#[test]
fn attr_type_stix_pattern_regkey_value_split() {
    let p = MispAttrType::RegkeyAndValue
        .to_stix_pattern("HKLM\\Run|evil.exe")
        .unwrap();
    assert!(p.contains("windows-registry-key:key"));
    assert!(p.contains("windows-registry-key:values"));
    assert!(p.contains("evil.exe"));
}

#[test]
fn attr_type_stix_pattern_regkey_value_no_split_when_no_pipe() {
    let p = MispAttrType::RegkeyAndValue
        .to_stix_pattern("HKLM\\Run")
        .unwrap();
    assert!(p.contains("windows-registry-key:key"));
    assert!(!p.contains("values"));
}

#[test]
fn attr_type_is_ioc_inclusion() {
    assert!(MispAttrType::Sha256.is_ioc());
    assert!(MispAttrType::IpDst.is_ioc());
    assert!(!MispAttrType::Comment.is_ioc());
    assert!(!MispAttrType::Text.is_ioc());
}

#[test]
fn attr_type_is_composite_matches_pipe_in_str() {
    for t in MispAttrType::all_hash_types() {
        let s = t.as_str();
        // Pure hash types have no pipe
        assert!(!s.contains('|'), "{s}");
        assert!(!t.is_composite(), "{s} should not be composite");
    }
}

#[test]
fn attr_type_all_hash_and_network_have_hash_and_network_categories() {
    for t in MispAttrType::all_hash_types() {
        assert_eq!(t.default_category(), AttributeCategory::Payload, "{}", t.as_str());
    }
    for t in MispAttrType::all_network_types() {
        assert_eq!(t.default_category(), AttributeCategory::Network, "{}", t.as_str());
    }
}

#[test]
fn attribute_category_misp_str_roundtrip_known() {
    for c in [
        AttributeCategory::Antivirus,
        AttributeCategory::ExternalAnalysis,
        AttributeCategory::Network,
        AttributeCategory::Artifacts,
        AttributeCategory::SocialNetwork,
        AttributeCategory::Financial,
        AttributeCategory::Targeting,
    ] {
        let s = c.as_misp_str();
        let back = AttributeCategory::from_misp_str(s);
        assert_eq!(back, c, "roundtrip {s}");
    }
}

#[test]
fn attribute_category_unknown_misp_str_is_other() {
    assert_eq!(
        AttributeCategory::from_misp_str("Made up category"),
        AttributeCategory::Other
    );
}

#[test]
fn registry_lookup_known_types() {
    let r = AttributeTypeRegistry::new();
    for k in ["md5", "sha256", "ip-dst", "domain", "btc", "yara"] {
        assert!(r.lookup(k).is_some(), "registry missing {k}");
    }
    assert!(r.lookup("ip-foo").is_none());
}

#[test]
fn registry_ioc_subset_contained_in_lookup() {
    let r = AttributeTypeRegistry::new();
    let iocs = r.ioc_types();
    assert!(!iocs.is_empty());
    for m in iocs {
        assert!(m.is_ioc);
        assert!(r.lookup(m.type_str).is_some());
    }
}

#[test]
fn registry_all_type_strings_sorted_and_unique() {
    let r = AttributeTypeRegistry::new();
    let s = r.all_type_strings();
    let mut sorted = s.clone();
    sorted.sort_unstable();
    assert_eq!(s, sorted);
    let mut dedup = s.clone();
    dedup.dedup();
    assert_eq!(s.len(), dedup.len());
}

// ─── misp_client ──────────────────────────────────────────────────────────────

#[test]
fn http_method_display() {
    assert_eq!(format!("{}", HttpMethod::Get), "GET");
    assert_eq!(format!("{}", HttpMethod::Post), "POST");
    assert_eq!(format!("{}", HttpMethod::Put), "PUT");
    assert_eq!(format!("{}", HttpMethod::Delete), "DELETE");
}

#[test]
fn client_config_host_port_https_default() {
    let c = MispClientConfig::new("https://misp.example.com", "k");
    assert_eq!(c.host_port(), ("misp.example.com".into(), 443));
}

#[test]
fn client_config_host_port_http_default() {
    let c = MispClientConfig::new("http://misp.example.com", "k");
    assert_eq!(c.host_port(), ("misp.example.com".into(), 80));
}

#[test]
fn client_config_host_port_explicit_port() {
    let c = MispClientConfig::new("https://h:8443", "k");
    assert_eq!(c.host_port(), ("h".into(), 8443));
}

#[test]
fn client_config_host_port_with_path_after_port() {
    // BUG candidate: host_port only handles "host[:port]" and won't strip path.
    let c = MispClientConfig::new("https://h:8443/api", "k");
    let (host, port) = c.host_port();
    assert_eq!(host, "h", "host should be 'h'");
    assert_eq!(port, 8443, "port should be 8443 even with trailing path");
}

#[test]
fn client_config_is_https_true_false() {
    assert!(MispClientConfig::new("https://x", "").is_https());
    assert!(!MispClientConfig::new("http://x", "").is_https());
}

#[test]
fn raw_response_helpers() {
    let mut h = std::collections::HashMap::new();
    h.insert("content-type".into(), "application/json".into());
    h.insert("content-length".into(), "42".into());
    let r = RawResponse {
        status: 201,
        headers: h,
        body: b"{}".to_vec(),
    };
    assert!(r.is_success());
    assert!(r.is_json());
    assert_eq!(r.content_length(), Some(42));
    assert_eq!(r.body_str().unwrap(), "{}");
}

#[test]
fn raw_response_failure_status() {
    let r = RawResponse {
        status: 500,
        headers: std::collections::HashMap::new(),
        body: vec![],
    };
    assert!(!r.is_success());
    assert!(!r.is_json());
    assert_eq!(r.content_length(), None);
}

#[test]
fn request_builders() {
    let g = Request::get("/p");
    assert_eq!(g.method, HttpMethod::Get);
    assert!(g.body.is_none());
    let p = Request::post("/p", b"x".to_vec());
    assert_eq!(p.method, HttpMethod::Post);
    assert_eq!(p.body.as_deref(), Some(&b"x"[..]));
    let pu = Request::put("/p", vec![1]);
    assert_eq!(pu.method, HttpMethod::Put);
    let d = Request::delete("/p");
    assert_eq!(d.method, HttpMethod::Delete);
    assert!(d.body.is_none());
}

#[test]
fn request_header_chain() {
    let r = Request::get("/p").header("X-A", "1").header("X-B", "2");
    assert_eq!(r.headers.get("X-A").map(String::as_str), Some("1"));
    assert_eq!(r.headers.get("X-B").map(String::as_str), Some("2"));
}

#[test]
fn request_json_body_sets_content_type() {
    let r = Request::json_body("/p", HttpMethod::Post, &serde_json::json!({"a":1})).unwrap();
    assert_eq!(
        r.headers.get("Content-Type").map(String::as_str),
        Some("application/json")
    );
    assert!(r.body.is_some());
}

#[test]
fn url_builders() {
    assert_eq!(event_url("https://m", 42), "https://m/events/42");
    assert_eq!(attribute_url("https://m", 7), "https://m/attributes/7");
    assert_eq!(tag_url("https://m", "tlp:white"), "https://m/tags/add/tlp:white");
}

#[test]
fn tag_url_encodes_space_and_slash() {
    let u = tag_url("https://m", "my tag/with");
    assert!(u.contains("my%20tag%2Fwith"), "got {u}");
}

#[test]
fn page_is_last_with_total() {
    let p: Page<u32> = Page { items: vec![1, 2], page: 1, page_size: 100, total: Some(2) };
    assert!(p.is_last());
}

#[test]
fn page_is_last_without_total_uses_short_page() {
    let p: Page<u32> = Page { items: vec![1, 2, 3], page: 1, page_size: 100, total: None };
    assert!(p.is_last());
    let p2: Page<u32> = Page { items: (0..100).collect(), page: 1, page_size: 100, total: None };
    assert!(!p2.is_last());
}

#[test]
fn paginated_query_injects_page_and_limit() {
    let base = serde_json::Map::new();
    let q = paginated_query(base, 3, 50);
    assert_eq!(q["page"], 3);
    assert_eq!(q["limit"], 50);
}

// ─── error::MispError ─────────────────────────────────────────────────────────

#[test]
fn misp_error_constructors_and_display() {
    let nf = MispError::not_found("event 5");
    assert!(format!("{nf}").contains("event 5"));
    let inv = MispError::invalid_input("bad");
    assert!(format!("{inv}").contains("bad"));
    let auth = MispError::AuthError;
    assert!(format!("{auth}").to_lowercase().contains("api key"));
}

#[test]
fn misp_error_conversion_into_ti_error() {
    use rustre_threatintel::TiError;
    let e: TiError = MispError::not_found("x").into();
    assert!(matches!(e, TiError::NotFound(_)));
    let e: TiError = MispError::AuthError.into();
    assert!(matches!(e, TiError::InvalidApiKey(_)));
    let e: TiError = MispError::Http { status: 500, body: "boom".into() }.into();
    assert!(matches!(e, TiError::Http(_)));
    let e: TiError = MispError::invalid_input("bad").into();
    assert!(matches!(e, TiError::Parse(_)));
}

// ─── Send/Sync exposure ───────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_types_are_send_sync() {
    assert_send_sync::<MispEvent>();
    assert_send_sync::<MispAttribute>();
    assert_send_sync::<MispTag>();
    assert_send_sync::<MispObject>();
    assert_send_sync::<NewMispEvent>();
    assert_send_sync::<NewMispAttribute>();
    assert_send_sync::<MispClientConfig>();
    assert_send_sync::<RawMispClient>();
    assert_send_sync::<MispRawClient>();
    assert_send_sync::<MispError>();
}

// ─── Hash / Eq sanity ────────────────────────────────────────────────────────

#[test]
fn misp_tag_eq_consistency() {
    assert_eq!(MispTag::tlp("RED"), MispTag::tlp("RED"));
    assert_ne!(MispTag::tlp("RED"), MispTag::tlp("GREEN"));
}
