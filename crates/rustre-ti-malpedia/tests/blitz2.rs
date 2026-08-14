//! Deep adversarial test suite for rustre-ti-malpedia (Y144).

use rustre_ti_malpedia::{
    ActorAttribution, AttributionMethod, FamilyAliasResolver, FamilyClassifier, FamilyMatcher,
    MalpediaActor, MalpediaActorSpec, MalpediaApiClient, MalpediaApiKey, MalpediaClientError,
    MalpediaFamily, MalpediaFamilySpec, MalpediaFamilySummary, MalpediaLocalDb, MalpediaSample,
    MalpediaSampleSpec, MalpediaSearchQuery, MalpediaStats, MalpediaYaraRule, SignatureScoreResult,
};
use rustre_threatintel::{IoC, IoCType, MalwareType, TiProvider};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
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

// ---------------------- normalize_family_name ----------------------

#[test]
fn test_normalize_lowercase() {
    assert_eq!(
        MalpediaApiClient::normalize_family_name("EMOTET"),
        "emotet"
    );
}

#[test]
fn test_normalize_space_and_hyphen() {
    assert_eq!(
        MalpediaApiClient::normalize_family_name("Cobalt-Strike Beacon"),
        "cobalt_strike_beacon"
    );
}

#[test]
fn test_normalize_empty() {
    assert_eq!(MalpediaApiClient::normalize_family_name(""), "");
}

#[test]
fn test_normalize_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let n = (g() % 32) as usize;
        let s: String = (0..n)
            .map(|_| {
                let c = (g() % 96) as u8 + 32;
                c as char
            })
            .collect();
        let out = MalpediaApiClient::normalize_family_name(&s);
        assert!(!out.contains(' '));
        assert!(!out.contains('-'));
    }
}

// ---------------------- family_to_malware_type ----------------------

#[test]
fn test_type_all_known() {
    let cases = [
        ("ransomware", MalwareType::Ransomware),
        ("trojan", MalwareType::Trojan),
        ("backdoor", MalwareType::Backdoor),
        ("rootkit", MalwareType::Rootkit),
        ("worm", MalwareType::Worm),
        ("virus", MalwareType::Virus),
        ("spyware", MalwareType::Spyware),
        ("stalkerware", MalwareType::Spyware),
        ("adware", MalwareType::Adware),
        ("dropper", MalwareType::Dropper),
        ("loader", MalwareType::Dropper),
        ("downloader", MalwareType::Downloader),
        ("banker", MalwareType::Banker),
        ("banking", MalwareType::Banker),
        ("stealer", MalwareType::Stealer),
        ("infostealer", MalwareType::Stealer),
        ("botnet", MalwareType::Botnet),
        ("bot", MalwareType::Botnet),
        ("cryptominer", MalwareType::Cryptominer),
        ("miner", MalwareType::Cryptominer),
        ("fileless", MalwareType::Fileless),
        ("pua", MalwareType::PotentiallyUnwanted),
        ("pup", MalwareType::PotentiallyUnwanted),
        ("", MalwareType::Unknown),
        ("nonsense_xyz", MalwareType::Unknown),
    ];
    for (input, expected) in cases {
        assert_eq!(
            MalpediaApiClient::family_to_malware_type(input),
            expected,
            "input={input}"
        );
    }
}

#[test]
fn test_type_case_insensitive() {
    assert_eq!(
        MalpediaApiClient::family_to_malware_type("RANSOMWARE"),
        MalwareType::Ransomware
    );
    assert_eq!(
        MalpediaApiClient::family_to_malware_type("BaNkEr"),
        MalwareType::Banker
    );
}

// ---------------------- MalpediaApiKey ----------------------

#[test]
fn test_api_key_new_invalid() {
    let k = MalpediaApiKey::new("abc".to_string());
    assert!(!k.is_valid());
}

#[test]
fn test_api_key_mark_validated() {
    let mut k = MalpediaApiKey::new("abc".to_string());
    k.mark_validated();
    assert!(k.is_valid());
}

#[test]
fn test_api_key_empty_validated_still_invalid() {
    let mut k = MalpediaApiKey::new(String::new());
    k.mark_validated();
    assert!(!k.is_valid());
}

#[test]
fn test_api_key_serde_roundtrip() {
    let k = MalpediaApiKey::new("xyz".to_string());
    let json = serde_json::to_string(&k).unwrap();
    let dk: MalpediaApiKey = serde_json::from_str(&json).unwrap();
    assert_eq!(dk.key, "xyz");
    assert!(!dk.validated);
}

// ---------------------- MalpediaApiClient ----------------------

#[test]
fn test_client_authenticated_some_nonempty() {
    let c = MalpediaApiClient::new(Some("k".to_string()));
    assert!(c.is_authenticated());
}

#[test]
fn test_client_authenticated_none() {
    let c = MalpediaApiClient::new(None);
    assert!(!c.is_authenticated());
}

#[test]
fn test_client_authenticated_some_empty() {
    let c = MalpediaApiClient::new(Some(String::new()));
    assert!(!c.is_authenticated());
}

#[test]
fn test_client_authenticate_err_when_none() {
    let c = MalpediaApiClient::new(None);
    assert!(matches!(
        c.authenticate(),
        Err(MalpediaClientError::NotAuthenticated)
    ));
}

#[test]
fn test_client_with_timeout_and_getter() {
    let c = MalpediaApiClient::new(None).with_timeout(Duration::from_secs(11));
    assert_eq!(c.timeout(), Duration::from_secs(11));
}

#[test]
fn test_client_with_ttl_and_base_url_chain() {
    let _ = MalpediaApiClient::new(None)
        .with_ttl(60)
        .with_base_url("http://example/".to_string());
}

#[test]
fn test_client_get_stats_cached() {
    let c = MalpediaApiClient::new(None);
    let s1 = c.get_stats().unwrap();
    let s2 = c.get_stats().unwrap();
    assert_eq!(s1.family_count, s2.family_count);
}

#[test]
fn test_client_search_family_mock_returns_some() {
    let c = MalpediaApiClient::new(None);
    let r = c.search_family("emotet").unwrap();
    assert!(!r.is_empty());
}

#[test]
fn test_client_get_yara_rules() {
    let c = MalpediaApiClient::new(None);
    let r = c.get_yara_rules("emotet").unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].family, "emotet");
    assert!(r[0].name.starts_with("detect_"));
}

#[test]
fn test_client_search_by_hash_evil_and_bad() {
    let c = MalpediaApiClient::new(None);
    assert!(c.search_by_hash("evil_thing").unwrap().is_some());
    assert!(c.search_by_hash("verybad_x").unwrap().is_some());
    assert!(c.search_by_hash("clean").unwrap().is_none());
}

#[test]
fn test_client_list_families_mock_count() {
    let c = MalpediaApiClient::new(None);
    let r = c.list_families(None, None).unwrap();
    assert_eq!(r.len(), 3);
}

#[test]
fn test_client_list_families_pagination_with_db() {
    let db = MalpediaLocalDb::new();
    db.populate_mock_data();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let r = c.list_families(Some(1), Some(0)).unwrap();
    assert_eq!(r.len(), 1);
    let r2 = c.list_families(Some(10), Some(100)).unwrap();
    assert!(r2.is_empty());
}

#[test]
fn test_client_get_family_not_found_with_db() {
    let db = MalpediaLocalDb::new();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let r = c.get_family("nope");
    assert!(matches!(r, Err(MalpediaClientError::FamilyNotFound(_))));
}

#[test]
fn test_client_get_actor_not_found_with_db() {
    let db = MalpediaLocalDb::new();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let r = c.get_actor("nope");
    assert!(matches!(r, Err(MalpediaClientError::ActorNotFound(_))));
}

#[test]
fn test_client_get_sample_not_found_with_db() {
    let db = MalpediaLocalDb::new();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let r = c.get_sample("nope");
    assert!(matches!(r, Err(MalpediaClientError::SampleNotFound(_))));
}

#[test]
fn test_client_search_with_query_obj_filters_platform() {
    let db = MalpediaLocalDb::new();
    db.populate_mock_data();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let q = MalpediaSearchQuery::new()
        .with_query("emotet")
        .with_platform("win");
    let r = c.search(&q).unwrap();
    assert!(r.iter().all(|f| f.platform.eq_ignore_ascii_case("win")));
}

#[test]
fn test_client_search_platform_filter_excludes() {
    let db = MalpediaLocalDb::new();
    db.populate_mock_data();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let q = MalpediaSearchQuery::new()
        .with_query("emotet")
        .with_platform("linux");
    let r = c.search(&q).unwrap();
    assert!(r.is_empty());
}

#[test]
fn test_client_search_malware_type_filter() {
    let db = MalpediaLocalDb::new();
    db.populate_mock_data();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let q = MalpediaSearchQuery::new()
        .with_query("")
        .with_malware_type("ransomware");
    let r = c.search(&q).unwrap();
    assert!(r.iter().all(|f| f.malware_type.eq_ignore_ascii_case("ransomware")));
}

#[test]
fn test_client_search_limit_zero_returns_empty() {
    let db = MalpediaLocalDb::new();
    db.populate_mock_data();
    let c = MalpediaApiClient::new(None).with_local_db(db);
    let q = MalpediaSearchQuery::new().with_query("").with_limit(0);
    let r = c.search(&q).unwrap();
    assert!(r.is_empty());
}

// ---------------------- TiProvider impl ----------------------

#[tokio::test]
async fn test_provider_lookup_clean() {
    let c = MalpediaApiClient::new(Some("k".to_string()));
    let ioc = IoC::new(IoCType::Sha256, "abc123".to_string(), "t".to_string());
    let r = c.lookup(&ioc).await.unwrap();
    assert!(!r.is_malicious());
}

#[tokio::test]
async fn test_provider_lookup_malicious_evil() {
    let c = MalpediaApiClient::new(Some("k".to_string()));
    let ioc = IoC::new(IoCType::Sha256, "evil_dead".to_string(), "t".to_string());
    let r = c.lookup(&ioc).await.unwrap();
    assert!(r.is_malicious());
    assert!(!r.malware_families.is_empty());
}

#[tokio::test]
async fn test_provider_lookup_non_hash_no_verdict() {
    let c = MalpediaApiClient::new(Some("k".to_string()));
    let ioc = IoC::new(IoCType::Ip, "1.2.3.4".to_string(), "t".to_string());
    let r = c.lookup(&ioc).await.unwrap();
    assert!(r.verdicts.is_empty());
}

#[test]
fn test_provider_supported_types_has_all_hash_kinds() {
    let c = MalpediaApiClient::new(None);
    let t = c.supported_ioc_types();
    for hk in [IoCType::Md5, IoCType::Sha1, IoCType::Sha256, IoCType::Sha512] {
        assert!(t.contains(&hk), "missing {hk:?}");
    }
}

// ---------------------- MalpediaLocalDb ----------------------

#[test]
fn test_local_db_empty_counts() {
    let db = MalpediaLocalDb::new();
    assert_eq!(db.family_count(), 0);
    assert_eq!(db.actor_count(), 0);
    assert_eq!(db.sample_count(), 0);
    assert!(db.list_families().is_empty());
    assert!(db.list_actors().is_empty());
    assert!(db.get_family("x").is_none());
}

#[test]
fn test_local_db_sample_lookup_case_insensitive() {
    let db = MalpediaLocalDb::new();
    db.insert_sample(MalpediaSampleSpec::new(
        "AABBCC".to_string(),
        "f".to_string(),
    ));
    assert!(db.get_sample("aabbcc").is_some());
    assert!(db.get_sample("AABBCC").is_some());
}

#[test]
fn test_local_db_find_by_hash_sha1_md5() {
    let db = MalpediaLocalDb::new();
    let mut s = MalpediaSampleSpec::new("aa".to_string(), "f".to_string());
    s.sha1 = Some("BB".to_string());
    s.md5 = Some("CC".to_string());
    db.insert_sample(s);
    assert!(db.find_by_hash("bb").is_some());
    assert!(db.find_by_hash("cc").is_some());
    assert!(db.find_by_hash("dd").is_none());
}

#[test]
fn test_local_db_search_families_by_alias() {
    let db = MalpediaLocalDb::new();
    db.populate_mock_data();
    let r = db.search_families("heodo");
    assert!(!r.is_empty());
}

#[test]
fn test_local_db_concurrent_inserts() {
    let db = Arc::new(MalpediaLocalDb::new());
    let mut handles = vec![];
    for t in 0..4 {
        let db2 = db.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                db2.insert_sample(MalpediaSampleSpec::new(
                    format!("{t}_{i}"),
                    "f".to_string(),
                ));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.sample_count(), 400);
}

// ---------------------- FamilyAliasResolver ----------------------

#[test]
fn test_alias_resolver_empty_unknown() {
    let r = FamilyAliasResolver::new();
    assert_eq!(r.count(), 0);
    assert!(r.resolve("anything").is_none());
}

#[test]
fn test_alias_resolver_case_insensitive() {
    let r = FamilyAliasResolver::with_defaults();
    assert_eq!(r.resolve("HEODO"), Some("win.emotet"));
    assert_eq!(r.resolve("Cobalt Strike"), Some("win.cobalt_strike"));
}

#[test]
fn test_alias_resolver_register_custom() {
    let mut r = FamilyAliasResolver::new();
    r.register("FooBar", "win.foo");
    assert_eq!(r.resolve("foobar"), Some("win.foo"));
    assert_eq!(r.count(), 1);
}

#[test]
fn test_alias_resolver_or_normalize_fallback() {
    let r = FamilyAliasResolver::new();
    assert_eq!(r.resolve_or_normalize("Bad Guy"), "bad_guy");
}

// ---------------------- FamilyClassifier ----------------------

#[test]
fn test_classifier_empty_no_match() {
    let c = FamilyClassifier::new();
    assert!(c.classify("anything").is_none());
    assert!(c.score("anything").is_empty());
}

#[test]
fn test_classifier_multi_match_sorted() {
    let c = FamilyClassifier::with_defaults();
    let s = c.score("emotet heodo geodo banking");
    assert!(!s.is_empty());
    // sorted desc
    for w in s.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn test_classifier_register_and_classify() {
    let mut c = FamilyClassifier::new();
    c.register("F1", "d", "t", vec!["needle".to_string()]);
    assert_eq!(c.classify("haystack needle pin").as_deref(), Some("F1"));
}

// ---------------------- ActorAttribution + Method Display ----------------------

#[test]
fn test_attribution_threshold_boundary_74_75() {
    let a = ActorAttribution::new("X".to_string(), 74, AttributionMethod::OsInt);
    assert!(!a.is_high_confidence());
    let b = ActorAttribution::new("X".to_string(), 75, AttributionMethod::OsInt);
    assert!(b.is_high_confidence());
}

#[test]
fn test_attribution_add_evidence() {
    let mut a = ActorAttribution::new("X".to_string(), 50, AttributionMethod::Combined);
    a.add_evidence("e1");
    a.add_evidence("e2".to_string());
    assert_eq!(a.evidence.len(), 2);
}

#[test]
fn test_attribution_method_display_all() {
    use AttributionMethod::*;
    for m in [
        SharedInfrastructure,
        SharedMalware,
        YaraMatch,
        SharedTtps,
        HumInt,
        OsInt,
        TechnicalIndicators,
        Combined,
    ] {
        let s = format!("{m}");
        assert!(!s.is_empty());
    }
}

#[test]
fn test_attribution_method_eq() {
    assert_eq!(AttributionMethod::YaraMatch, AttributionMethod::YaraMatch);
    assert_ne!(AttributionMethod::YaraMatch, AttributionMethod::OsInt);
}

// ---------------------- MalpediaYaraRule ----------------------

#[test]
fn test_yara_rule_text_contains_all_sections() {
    let mut r = MalpediaYaraRule::new("r1".to_string(), "win.f".to_string());
    r.description = "desc".to_string();
    r.author = Some("me".to_string());
    r.tags.push("apt".to_string());
    r.strings.push(("$a".to_string(), "\"x\"".to_string()));
    let t = r.to_yara_text();
    assert!(t.contains("rule r1"));
    assert!(t.contains("desc"));
    assert!(t.contains("me"));
    assert!(t.contains("apt"));
    assert!(t.contains("condition"));
}

// ---------------------- MalpediaFamilySpec ----------------------

#[test]
fn test_family_spec_platform_prefix_with_dot() {
    let mut f = MalpediaApiClient::new(None).mock_family_response("emotet");
    f.name = "win.emotet".to_string();
    f.platform = "ignored".to_string();
    assert_eq!(f.platform_prefix(), "win");
}

#[test]
fn test_family_spec_has_sample_case_insensitive() {
    let mut f = MalpediaApiClient::new(None).mock_family_response("emotet");
    f.samples = vec!["AABB".to_string()];
    assert!(f.has_sample("aabb"));
    assert!(f.has_sample("AABB"));
    assert!(!f.has_sample("cc"));
}

#[test]
fn test_family_spec_as_malware_type() {
    let mut f = MalpediaApiClient::new(None).mock_family_response("x");
    f.malware_type = "ransomware".to_string();
    assert_eq!(f.as_malware_type(), MalwareType::Ransomware);
}

#[test]
fn test_family_spec_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let mut f = MalpediaApiClient::new(None).mock_family_response("emotet");
        f.attribution_techniques_pad(g());
        let s = serde_json::to_string(&f).unwrap();
        let d: MalpediaFamilySpec = serde_json::from_str(&s).unwrap();
        assert_eq!(d.name, f.name);
        assert_eq!(d.samples, f.samples);
    }
}

// helper trait — added inline because test doesn't actually modify schema.
trait Pad {
    fn attribution_techniques_pad(&mut self, _seed: u64);
}
impl Pad for MalpediaFamilySpec {
    fn attribution_techniques_pad(&mut self, seed: u64) {
        self.attack_techniques
            .push(format!("T{}", seed % 9999));
    }
}

// ---------------------- MalpediaSampleSpec / ActorSpec ----------------------

#[test]
fn test_sample_spec_serde_roundtrip() {
    let s = MalpediaSampleSpec::new("hash".to_string(), "fam".to_string());
    let j = serde_json::to_string(&s).unwrap();
    let d: MalpediaSampleSpec = serde_json::from_str(&j).unwrap();
    assert_eq!(d.sha256, "hash");
    assert_eq!(d.family, "fam");
    assert!(!d.packed);
}

#[test]
fn test_actor_spec_defaults() {
    let a = MalpediaActorSpec::new("APT99".to_string());
    assert_eq!(a.attribution_confidence, 50);
    assert!(a.aliases.is_empty());
}

// ---------------------- MalpediaSearchQuery ----------------------

#[test]
fn test_search_query_default_empty() {
    let q = MalpediaSearchQuery::new();
    assert!(q.query.is_none());
    assert!(!q.include_yara);
    assert!(!q.include_samples);
}

#[test]
fn test_search_query_builder_chain() {
    let q = MalpediaSearchQuery::new()
        .with_query("a")
        .with_platform("win")
        .with_malware_type("trojan")
        .with_limit(7)
        .include_yara()
        .include_samples();
    assert_eq!(q.platform.as_deref(), Some("win"));
    assert_eq!(q.malware_type.as_deref(), Some("trojan"));
    assert_eq!(q.limit, Some(7));
    assert!(q.include_yara);
    assert!(q.include_samples);
}

// ---------------------- MalpediaStats ----------------------

#[test]
fn test_stats_new_default() {
    let s = MalpediaStats::new();
    assert_eq!(s.family_count, 0);
    assert!(s.platform_breakdown.is_empty());
}

#[test]
fn test_stats_mock_breakdowns() {
    let s = MalpediaStats::mock();
    assert!(s.platform_breakdown.contains_key("win"));
    assert!(s.actor_country_breakdown.contains_key("RU"));
}

#[test]
fn test_stats_serde_roundtrip() {
    let s = MalpediaStats::mock();
    let j = serde_json::to_string(&s).unwrap();
    let d: MalpediaStats = serde_json::from_str(&j).unwrap();
    assert_eq!(d.family_count, s.family_count);
}

// ---------------------- SignatureScoreResult ----------------------

#[test]
fn test_signature_score_zero_max() {
    let r = SignatureScoreResult::new("f".to_string(), 5, 0);
    assert_eq!(r.confidence_pct, 0);
}

#[test]
fn test_signature_score_full() {
    let r = SignatureScoreResult::new("f".to_string(), 10, 10);
    assert_eq!(r.confidence_pct, 100);
}

#[test]
fn test_signature_score_half() {
    let r = SignatureScoreResult::new("f".to_string(), 5, 10);
    assert_eq!(r.confidence_pct, 50);
}

#[test]
fn test_signature_score_fuzz_bounds() {
    let mut g = lcg();
    for _ in 0..100 {
        let max = (g() % 1000) as u32 + 1;
        let score = u32::try_from(g() & 0xFFFF_FFFF).unwrap_or(u32::MAX) % (max + 1);
        let r = SignatureScoreResult::new("f".to_string(), score, max);
        assert!(r.confidence_pct <= 100);
    }
}

// ---------------------- models: MalpediaFamily / MalpediaSample / Matcher ----------------------

#[test]
fn test_model_family_has_sample_case_insensitive() {
    let mut f = MalpediaFamily::new("win.foo", "Foo");
    f.samples.push(MalpediaSample::new("ABCD", "active", "1"));
    assert!(f.has_sample("abcd"));
    assert!(!f.has_sample("zz"));
    assert_eq!(f.sample_count(), 1);
}

#[test]
fn test_model_sample_is_active() {
    assert!(MalpediaSample::new("h", "ACTIVE", "1").is_active());
    assert!(!MalpediaSample::new("h", "retired", "1").is_active());
}

#[test]
fn test_model_sample_eq_consistent_30() {
    let mut seen = HashSet::new();
    let mut g = lcg();
    for _ in 0..30 {
        let s1 = MalpediaSample::new(format!("h{}", g() % 5), "active", "1");
        let s2 = s1.clone();
        assert_eq!(s1, s2);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        // MalpediaSample doesn't impl Hash, so just verify Eq.
        s1.sha256.hash(&mut h1);
        s2.sha256.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        seen.insert(s1.sha256.clone());
    }
    assert!(!seen.is_empty());
}

#[test]
fn test_family_summary_from_family() {
    let f = MalpediaFamily::new("win.x", "X");
    let s: MalpediaFamilySummary = (&f).into();
    assert_eq!(s.malpedia_name, "win.x");
    assert_eq!(s.common_name, "X");
}

#[test]
fn test_matcher_empty_is_empty() {
    let m = FamilyMatcher::new(vec![]);
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert!(m.by_name("anything").is_empty());
    assert!(m.by_sha256("anything").is_empty());
}

#[test]
fn test_matcher_by_name_normalises_separators() {
    let mut f = MalpediaFamily::new("win.emotet", "Emotet");
    f.alt_names.push("Heodo".to_string());
    let m = FamilyMatcher::new(vec![f]);
    assert_eq!(m.by_name("win emotet").len(), 1);
    assert_eq!(m.by_name("win_emotet").len(), 1);
    assert_eq!(m.by_name("WIN.EMOTET").len(), 1);
    assert_eq!(m.by_name("heodo").len(), 1);
    assert!(m.by_name("nothing").is_empty());
}

#[test]
fn test_actor_model_basic() {
    let a = MalpediaActor::new("APT1", "CN");
    assert_eq!(a.country, "CN");
    assert!(a.families.is_empty());
}

// ---------------------- Send + Sync threaded stress ----------------------

#[test]
fn test_local_db_send_sync_4x100() {
    let db = Arc::new(MalpediaLocalDb::new());
    let mut handles = vec![];
    for t in 0..4 {
        let db2 = db.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let name = format!("win.f{t}_{i}");
                db2.insert_family(MalpediaFamilySpec {
                    name: name.clone(),
                    common_name: name.clone(),
                    malware_type: "trojan".to_string(),
                    aliases: vec![],
                    platform: "win".to_string(),
                    country: None,
                    description: None,
                    yara_rules: vec![],
                    samples: vec![],
                    references: vec![],
                    attack_techniques: vec![],
                    notes: None,
                    url: None,
                });
                let _ = db2.get_family(&name);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.family_count(), 400);
}

// ---------------------- MalpediaClientError display ----------------------

#[test]
fn test_client_error_display_variants() {
    let cases: Vec<MalpediaClientError> = vec![
        MalpediaClientError::NotAuthenticated,
        MalpediaClientError::FamilyNotFound("f".to_string()),
        MalpediaClientError::ActorNotFound("a".to_string()),
        MalpediaClientError::SampleNotFound("s".to_string()),
        MalpediaClientError::Http("h".to_string()),
        MalpediaClientError::RateLimitExceeded,
        MalpediaClientError::Parse("p".to_string()),
        MalpediaClientError::Cache("c".to_string()),
        MalpediaClientError::Database("d".to_string()),
        MalpediaClientError::Other("o".to_string()),
    ];
    for e in cases {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}
