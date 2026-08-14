//! Blitz test suite for rustre-ti-malpedia. Tests-only file; production code untouched.

use rustre_ti_malpedia::{
    DatabaseStats, FamilyDistribution, FamilyMatcher, MalpediaActor, MalpediaCache,
    MalpediaFamily, MalpediaFamilySummary, MalpediaSample, RelatedSampleSearch, SampleDatabase,
    SampleMatch, SampleMetadata, TimelineEntry, actor_country_distribution, platform_distribution,
    to_attack_navigator,
};
use rustre_ti_malpedia::attribution_engine::{
    AttributionConfig, AttributionEngine, AttributionMethod, AttributionSample, ClusterReason,
    Evidence, EvidenceKind, FamilyAttribution, HashKind, SampleCluster, TLSH_SIMILARITY_THRESHOLD,
    TypedHash, tlsh_distance,
};
use rustre_ti_malpedia::error::MalpediaError;
use rustre_ti_malpedia::sample_search::ClusterReport;

// ---------------------------------------------------------------------------
// models
// ---------------------------------------------------------------------------

#[test]
fn sample_is_active_case_insensitive() {
    assert!(MalpediaSample::new("h", "ACTIVE", "1").is_active());
    assert!(MalpediaSample::new("h", "Active", "1").is_active());
    assert!(!MalpediaSample::new("h", "active ", "1").is_active()); // trailing space != "active"
    assert!(!MalpediaSample::new("h", "deprecated", "1").is_active());
    assert!(!MalpediaSample::new("h", "", "1").is_active());
}

#[test]
fn family_has_sample_case_insensitive() {
    let mut f = MalpediaFamily::new("win.x", "X");
    f.samples.push(MalpediaSample::new("AaBbCc", "active", "1"));
    assert!(f.has_sample("aabbcc"));
    assert!(f.has_sample("AABBCC"));
    assert!(f.has_sample("AaBbCc"));
    assert!(!f.has_sample(""));
    assert!(!f.has_sample("aabbcc0"));
}

#[test]
fn family_sample_count_const() {
    let mut f = MalpediaFamily::new("win.x", "X");
    assert_eq!(f.sample_count(), 0);
    f.samples.push(MalpediaSample::new("a", "active", "1"));
    f.samples.push(MalpediaSample::new("b", "active", "1"));
    assert_eq!(f.sample_count(), 2);
}

#[test]
fn family_summary_from_family() {
    let f = MalpediaFamily::new("win.emotet", "Emotet");
    let s: MalpediaFamilySummary = (&f).into();
    assert_eq!(s.malpedia_name, "win.emotet");
    assert_eq!(s.common_name, "Emotet");
}

#[test]
fn sample_equality() {
    let a = MalpediaSample::new("h", "active", "1");
    let b = MalpediaSample::new("h", "active", "1");
    let c = MalpediaSample::new("h", "active", "2");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn family_round_trip_json_full() {
    let mut f = MalpediaFamily::new("win.emotet", "Emotet");
    f.description = "desc".into();
    f.urls.push("https://example.com".into());
    f.alt_names.push("Heodo".into());
    f.actors.push("Mummy Spider".into());
    f.samples.push(MalpediaSample::new("aa", "active", "1"));
    let json = serde_json::to_string(&f).unwrap();
    let d: MalpediaFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(d.urls, vec!["https://example.com".to_string()]);
    assert_eq!(d.alt_names, vec!["Heodo".to_string()]);
    assert_eq!(d.actors, vec!["Mummy Spider".to_string()]);
    assert_eq!(d.samples.len(), 1);
}

// ---------------------------------------------------------------------------
// matcher
// ---------------------------------------------------------------------------

fn make_family(name: &str, common: &str) -> MalpediaFamily {
    MalpediaFamily::new(name, common)
}

#[test]
fn matcher_empty() {
    let m = FamilyMatcher::new(vec![]);
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert!(m.by_name("anything").is_empty());
    assert!(m.by_sha256("00").is_empty());
}

#[test]
fn matcher_by_name_normalizations() {
    let mut f = make_family("win.emotet", "Emotet");
    f.alt_names.push("Heodo".into());
    let m = FamilyMatcher::new(vec![f]);
    assert_eq!(m.by_name("Emotet").len(), 1);
    assert_eq!(m.by_name("emotet").len(), 1);
    assert_eq!(m.by_name("  EMOTET  ").len(), 1);
    assert_eq!(m.by_name("Heodo").len(), 1);
    assert_eq!(m.by_name("heodo").len(), 1);
    assert_eq!(m.by_name("win.emotet").len(), 1);
    assert_eq!(m.by_name("win emotet").len(), 1);
    assert_eq!(m.by_name("win_emotet").len(), 1);
    assert!(m.by_name("trickbot").is_empty());
}

#[test]
fn matcher_by_sha256_multi_family() {
    let mut f1 = make_family("win.a", "A");
    f1.samples.push(MalpediaSample::new("HASH", "active", "1"));
    let mut f2 = make_family("win.b", "B");
    f2.samples.push(MalpediaSample::new("hash", "active", "1"));
    let m = FamilyMatcher::new(vec![f1, f2]);
    assert_eq!(m.by_sha256("hash").len(), 2);
    assert_eq!(m.by_sha256("HASH").len(), 2);
}

#[test]
fn matcher_len_and_clone() {
    let m = FamilyMatcher::new(vec![make_family("a", "A"), make_family("b", "B")]);
    assert_eq!(m.len(), 2);
    assert!(!m.is_empty());
    let cloned = m;
    assert_eq!(cloned.len(), 2);
}

// ---------------------------------------------------------------------------
// navigator
// ---------------------------------------------------------------------------

#[test]
fn navigator_empty_families() {
    let s = to_attack_navigator(&[]).unwrap();
    assert!(s.contains("\"techniques\""));
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["techniques"].as_array().unwrap().len(), 0);
    assert_eq!(v["domain"], "enterprise-attack");
}

#[test]
fn navigator_one_per_family() {
    let fams = vec![make_family("win.a", "A"), make_family("win.b", "B")];
    let s = to_attack_navigator(&fams).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["techniques"].as_array().unwrap().len(), 2);
    assert!(s.contains("T1059"));
}

// ---------------------------------------------------------------------------
// cache
// ---------------------------------------------------------------------------

fn cache_mem() -> MalpediaCache {
    MalpediaCache::open_sqlite(":memory:").unwrap()
}

#[test]
fn cache_get_missing_family_returns_none() {
    let c = cache_mem();
    assert!(c.get_family("missing").unwrap().is_none());
}

#[test]
fn cache_family_upsert() {
    let c = cache_mem();
    let mut f = MalpediaFamily::new("win.x", "Old");
    c.put_family(&f).unwrap();
    f.common_name = "New".into();
    c.put_family(&f).unwrap();
    let got = c.get_family("win.x").unwrap().unwrap();
    assert_eq!(got.common_name, "New");
    assert_eq!(c.list_families().unwrap().len(), 1);
}

#[test]
fn cache_actor_upsert() {
    let c = cache_mem();
    let mut a = MalpediaActor::new("Lazarus", "KP");
    c.put_actor(&a).unwrap();
    a.country = "XX".into();
    c.put_actor(&a).unwrap();
    let got = c.get_actor("Lazarus").unwrap().unwrap();
    assert_eq!(got.country, "XX");
    assert_eq!(c.list_actors().unwrap().len(), 1);
}

#[test]
fn cache_list_empty() {
    let c = cache_mem();
    assert!(c.list_families().unwrap().is_empty());
    assert!(c.list_actors().unwrap().is_empty());
}

#[test]
fn cache_open_invalid_path_errors() {
    // A path under a non-existent directory should fail
    let res = MalpediaCache::open_sqlite("Z:/nonexistent/dir/does/not/exist/db.sqlite");
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

fn mkfam(name: &str, n: usize, active: bool) -> MalpediaFamily {
    let mut f = MalpediaFamily::new(name, name);
    for i in 0..n {
        f.samples.push(MalpediaSample::new(
            format!("{name}_{i}"),
            if active { "active" } else { "deprecated" },
            "1",
        ));
    }
    f
}

#[test]
fn stats_empty_attribution_coverage() {
    let s = DatabaseStats::compute(&[], &[]);
    assert!((s.attribution_coverage() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn stats_top5_only() {
    let fams: Vec<_> = (0..10).map(|i| mkfam(&format!("win.f{i}"), i + 1, true)).collect();
    let s = DatabaseStats::compute(&fams, &[]);
    assert_eq!(s.top_families_by_sample_count.len(), 5);
    // Sort is descending by sample count
    assert!(s.top_families_by_sample_count[0].1 >= s.top_families_by_sample_count[4].1);
}

#[test]
fn stats_display_contains_pct() {
    let s = DatabaseStats::compute(&[mkfam("win.x", 1, true)], &[]);
    let out = s.to_string();
    assert!(out.contains("100%") || out.contains("100 %"));
}

#[test]
fn stats_distribution_empty_mode() {
    let d = FamilyDistribution::new("x");
    assert!(d.mode().is_none());
    assert_eq!(d.total(), 0);
    assert!(d.sorted_buckets().is_empty());
}

#[test]
fn stats_platform_distribution_unknown_segment() {
    let f = MalpediaFamily::new("noseparator", "X");
    let d = platform_distribution(&[f]);
    // No '.' means split().next() returns the whole string
    assert!(d.buckets.contains_key("noseparator"));
}

#[test]
fn stats_actor_country_distribution_empty_string() {
    let a = MalpediaActor::new("Anon", "");
    let d = actor_country_distribution(&[a]);
    assert_eq!(d.buckets.get(""), Some(&1));
}

#[test]
fn stats_timeline_duration_zero() {
    let f = mkfam("win.x", 0, true);
    let e = TimelineEntry::new(&f, Some(2020), Some(2020));
    assert_eq!(e.duration_years(), Some(0));
}

#[test]
fn stats_timeline_duration_inverted_returns_none() {
    let f = mkfam("win.x", 0, true);
    let e = TimelineEntry::new(&f, Some(2025), Some(2020));
    assert!(e.duration_years().is_none());
}

#[test]
fn stats_avg_samples_single_family() {
    let s = DatabaseStats::compute(&[mkfam("win.x", 7, true)], &[]);
    assert!((s.avg_samples_per_family - 7.0).abs() < 1e-10);
}

// ---------------------------------------------------------------------------
// sample_search
// ---------------------------------------------------------------------------

#[test]
fn sampledb_empty_helpers() {
    let db = SampleDatabase::new();
    assert_eq!(db.total_samples(), 0);
    assert_eq!(db.total_families(), 0);
    assert!(db.non_empty_families().is_empty());
    assert!(db.search_by_hash_prefix("").is_empty());
}

#[test]
fn sampledb_index_overwrites_same_hash() {
    let mut db = SampleDatabase::new();
    let mut f1 = MalpediaFamily::new("win.a", "A");
    f1.samples.push(MalpediaSample::new("AAA", "active", "1"));
    let mut f2 = MalpediaFamily::new("win.b", "B");
    f2.samples.push(MalpediaSample::new("aaa", "active", "1"));
    db.index_family(&f1);
    db.index_family(&f2);
    // Same hash -> later wins in exact_index
    let m = db.lookup_exact("aaa").unwrap();
    assert_eq!(m.family_name, "win.b");
    // Total unique by hash is 1
    assert_eq!(db.total_samples(), 1);
    // Two families indexed
    assert_eq!(db.total_families(), 2);
}

#[test]
fn sampledb_prefix_empty_matches_all() {
    let mut db = SampleDatabase::new();
    let mut f = MalpediaFamily::new("win.x", "X");
    f.samples.push(MalpediaSample::new("aaa", "active", "1"));
    f.samples.push(MalpediaSample::new("bbb", "active", "1"));
    db.index_family(&f);
    let r = db.search_by_hash_prefix("");
    assert_eq!(r.len(), 2);
}

#[test]
fn cluster_report_active_fraction_zero_samples() {
    let r = ClusterReport::from_families("c".into(), &[]);
    assert!((r.active_fraction - 0.0).abs() < f64::EPSILON);
    assert!(!r.is_predominantly_active());
}

#[test]
fn cluster_report_half_active_not_predominant() {
    let mut f = MalpediaFamily::new("win.x", "X");
    f.samples.push(MalpediaSample::new("a", "active", "1"));
    f.samples.push(MalpediaSample::new("b", "deprecated", "1"));
    let r = ClusterReport::from_families("c".into(), &[f]);
    assert!((r.active_fraction - 0.5).abs() < 1e-10);
    assert!(!r.is_predominantly_active()); // strict >0.5
}

#[test]
fn related_search_family_of_case() {
    let mut db = SampleDatabase::new();
    let mut f = MalpediaFamily::new("win.x", "X");
    f.samples.push(MalpediaSample::new("AbCdEf", "active", "1"));
    db.index_family(&f);
    let r = RelatedSampleSearch::new(&db);
    assert_eq!(r.family_of("ABCDEF").as_deref(), Some("win.x"));
    assert_eq!(r.family_of("abcdef").as_deref(), Some("win.x"));
}

#[test]
fn sample_metadata_is_active_case() {
    let s = MalpediaSample::new("h", "ACTIVE", "1");
    let m = SampleMetadata::from_sample(&s, "fam");
    assert!(m.is_active());
}

#[test]
fn sample_match_fuzzy_confidence_bounds() {
    let s = MalpediaSample::new("h", "active", "1");
    let m = SampleMatch::fuzzy("h".into(), "fam".into(), s, 0);
    assert_eq!(m.confidence, 0);
    assert!(!m.is_exact);
}

// ---------------------------------------------------------------------------
// attribution_engine
// ---------------------------------------------------------------------------

#[test]
fn tlsh_distance_equal() {
    assert_eq!(tlsh_distance("ABCDEF", "ABCDEF"), 0);
    assert_eq!(tlsh_distance("T1ABCDEF", "ABCDEF"), 0);
    assert_eq!(tlsh_distance("t1abc", "abc"), 0);
}

#[test]
fn tlsh_distance_diff_and_length() {
    assert_eq!(tlsh_distance("ABCD", "ABCE"), 1);
    // Length-mismatch contributes
    assert_eq!(tlsh_distance("ABCD", "ABCDXY"), 2);
}

#[test]
fn tlsh_similarity_threshold_value() {
    assert_eq!(TLSH_SIMILARITY_THRESHOLD, 30);
}

#[test]
fn typed_hash_constructors() {
    let h = TypedHash::imphash("ff");
    assert_eq!(h.kind, HashKind::ImpHash);
    assert_eq!(h.value, "ff");
    assert_eq!(TypedHash::tlsh("aa").kind, HashKind::Tlsh);
    assert_eq!(TypedHash::sha256("bb").kind, HashKind::Sha256);
}

#[test]
fn attribution_sample_get_hash_and_imphash_flag() {
    let mut s = AttributionSample::new("sha");
    assert!(!s.has_imphash());
    s.add_hash(TypedHash::imphash("ABC"));
    assert!(s.has_imphash());
    assert_eq!(s.get_hash(&HashKind::ImpHash), Some("ABC"));
    assert_eq!(s.get_hash(&HashKind::Tlsh), None);
}

#[test]
fn cluster_reason_display() {
    assert_eq!(ClusterReason::SharedImpHash.to_string(), "shared-imphash");
    assert_eq!(ClusterReason::TlshSimilarity.to_string(), "tlsh-similarity");
    assert_eq!(ClusterReason::YaraMatch("r".into()).to_string(), "yara:r");
    assert_eq!(ClusterReason::SharedRichHash.to_string(), "shared-rich-hash");
    assert_eq!(ClusterReason::SharedCompileTime.to_string(), "shared-compile-time");
    assert_eq!(ClusterReason::Combined.to_string(), "combined");
}

#[test]
fn sample_cluster_basics() {
    let mut c = SampleCluster::new("id", ClusterReason::Combined);
    assert_eq!(c.size(), 0);
    assert!(c.primary_family().is_none());
    c.add_member("a");
    c.add_member("b");
    assert_eq!(c.size(), 2);
    c.candidate_families.push("win.x".into());
    assert_eq!(c.primary_family(), Some("win.x"));
}

#[test]
fn family_attribution_high_conf_and_weight() {
    let mut a = FamilyAttribution::new("win.x", 80, AttributionMethod::ExactHashMatch);
    assert!(a.is_high_confidence());
    a.add_evidence(Evidence::new(EvidenceKind::HashMatch, "x", 50));
    a.add_evidence(Evidence::new(EvidenceKind::YaraRule, "y", 25));
    assert_eq!(a.total_weight(), 75);
}

#[test]
fn family_attribution_low_conf() {
    let a = FamilyAttribution::new("win.x", 74, AttributionMethod::ManualAnalysis);
    assert!(!a.is_high_confidence());
    let a2 = FamilyAttribution::new("win.x", 75, AttributionMethod::ManualAnalysis);
    assert!(a2.is_high_confidence());
}

#[test]
fn engine_cluster_id_monotonic_and_count() {
    let mut e = AttributionEngine::new();
    assert_eq!(e.cluster_id_count(), 0);
    assert_eq!(e.next_cluster_id(), 0);
    assert_eq!(e.next_cluster_id(), 1);
    assert_eq!(e.next_cluster_id(), 2);
    assert_eq!(e.cluster_id_count(), 3);
}

#[test]
fn engine_get_sample_case_insensitive() {
    let mut e = AttributionEngine::new();
    e.add_sample(AttributionSample::new("AaBbCc"));
    assert!(e.get_sample("aabbcc").is_some());
    assert!(e.get_sample("AABBCC").is_some());
    assert!(e.get_sample("zz").is_none());
}

#[test]
fn engine_register_hash_lowercases() {
    let mut e = AttributionEngine::new();
    e.register_family_hashes("win.x", &["AABBCC".to_string()]);
    let mut sample = AttributionSample::new("aabbcc");
    let attrs = e.attribute_sample(&sample);
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].family, "win.x");
    assert_eq!(attrs[0].method, AttributionMethod::ExactHashMatch);
    // Also works with uppercase query
    sample.sha256 = "AABBCC".into();
    assert_eq!(e.attribute_sample(&sample).len(), 1);
}

#[test]
fn engine_attribute_imphash() {
    let mut e = AttributionEngine::new();
    e.register_family_imphashes("win.x", &["ABCDEF".to_string()]);
    let mut s = AttributionSample::new("zz");
    s.add_hash(TypedHash::imphash("abcdef"));
    let attrs = e.attribute_sample(&s);
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].method, AttributionMethod::ImportHashCluster);
}

#[test]
fn engine_attribute_yara_boosts_existing() {
    let mut e = AttributionEngine::new();
    e.register_family_hashes("win.x", &["aa".into()]);
    e.register_family_yara("win.x", vec!["rule_x".into()]);
    let mut s = AttributionSample::new("aa");
    s.yara_matches.push("rule_x".into());
    let attrs = e.attribute_sample(&s);
    assert_eq!(attrs.len(), 1, "yara should add evidence to existing, not duplicate");
    // exact match base is 95, +10 capped at 100
    assert_eq!(attrs[0].confidence, 100);
    assert!(attrs[0].evidence.len() >= 2);
}

#[test]
fn engine_attribute_actor_attached() {
    let mut e = AttributionEngine::new();
    e.register_family_hashes("win.x", &["aa".into()]);
    e.register_actor("win.x", "APT-Test");
    let s = AttributionSample::new("aa");
    let attrs = e.attribute_sample(&s);
    assert_eq!(attrs[0].actor.as_deref(), Some("APT-Test"));
}

#[test]
fn engine_attribute_sorted_desc() {
    let mut e = AttributionEngine::new();
    e.register_family_hashes("win.exact", &["aa".into()]);
    e.register_family_yara("win.yara_only", vec!["r".into()]);
    let mut s = AttributionSample::new("aa");
    s.yara_matches.push("r".into());
    let attrs = e.attribute_sample(&s);
    assert!(attrs.len() >= 2);
    // sorted descending by confidence
    for w in attrs.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
    assert_eq!(attrs[0].family, "win.exact");
}

#[test]
fn engine_attribute_all_skips_no_match() {
    let mut e = AttributionEngine::new();
    e.register_family_hashes("win.x", &["match".into()]);
    e.add_samples(vec![
        AttributionSample::new("match"),
        AttributionSample::new("nomatch"),
    ]);
    let all = e.attribute_all();
    assert_eq!(all.len(), 1);
    assert!(all.contains_key("match"));
}

#[test]
fn engine_cluster_by_imphash_min_size() {
    let mut e = AttributionEngine::new();
    let mut a = AttributionSample::new("a");
    a.add_hash(TypedHash::imphash("xx"));
    let mut b = AttributionSample::new("b");
    b.add_hash(TypedHash::imphash("xx"));
    let mut c = AttributionSample::new("c");
    c.add_hash(TypedHash::imphash("yy")); // singleton -> excluded by min_cluster_size=2
    e.add_samples(vec![a, b, c]);
    let clusters = e.cluster_by_imphash();
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].size(), 2);
    assert_eq!(clusters[0].cluster_reason, ClusterReason::SharedImpHash);
    assert_eq!(clusters[0].pivot_value.as_deref(), Some("xx"));
}

#[test]
fn engine_cluster_by_imphash_collects_candidate_families() {
    let mut e = AttributionEngine::new();
    let mut a = AttributionSample::new("a");
    a.add_hash(TypedHash::imphash("xx"));
    a.known_family = Some("win.f".into());
    let mut b = AttributionSample::new("b");
    b.add_hash(TypedHash::imphash("xx"));
    b.known_family = Some("win.f".into());
    e.add_samples(vec![a, b]);
    let clusters = e.cluster_by_imphash();
    assert_eq!(clusters[0].candidate_families, vec!["win.f".to_string()]);
}

#[test]
fn engine_config_disables_imphash() {
    let cfg = AttributionConfig {
        enable_imphash_clustering: false,
        ..AttributionConfig::default()
    };
    let mut e = AttributionEngine::with_config(cfg);
    e.register_family_imphashes("win.x", &["abc".into()]);
    let mut s = AttributionSample::new("z");
    s.add_hash(TypedHash::imphash("abc"));
    assert!(e.attribute_sample(&s).is_empty());
}

#[test]
fn engine_no_matches_returns_empty() {
    let e = AttributionEngine::new();
    let s = AttributionSample::new("xx");
    assert!(e.attribute_sample(&s).is_empty());
}

#[test]
fn typed_hash_eq_and_hash_consistency() {
    use std::collections::HashSet;
    let a = TypedHash::imphash("AA");
    let b = TypedHash::imphash("AA");
    let c = TypedHash::imphash("BB");
    assert_eq!(a, b);
    assert_ne!(a, c);
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}

// ---------------------------------------------------------------------------
// error
// ---------------------------------------------------------------------------

#[test]
fn error_not_found_helper() {
    let e = MalpediaError::not_found("xyz");
    let s = e.to_string();
    assert!(s.contains("xyz"));
    assert!(s.contains("not found"));
}

#[test]
fn error_http_display() {
    let e = MalpediaError::Http { status: 404, body: "missing".into() };
    let s = e.to_string();
    assert!(s.contains("404"));
    assert!(s.contains("missing"));
}

#[test]
fn error_invalid_input_display() {
    let e = MalpediaError::InvalidInput("bad".into());
    assert!(e.to_string().contains("bad"));
}

#[test]
fn error_into_tierror_preserves_not_found() {
    let e = MalpediaError::not_found("abc");
    let ti: rustre_threatintel::TiError = e.into();
    match ti {
        rustre_threatintel::TiError::NotFound(s) => assert_eq!(s, "abc"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}
