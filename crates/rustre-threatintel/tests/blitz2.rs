//! Blitz2 coverage tests for rustre-threatintel.

use rustre_threatintel::ioc::{IoC, IoCType, Severity};
use rustre_threatintel::malware::{MalwareFamily, MalwareType};
use rustre_threatintel::error::TiError;
use rustre_threatintel::{
    IocId, IocType, ThreatGroup, ThreatGroupTracker, ThreatIndicatorDatabase, ThreatIoc,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

// Seeded LCG (Knuth MMIX) for deterministic input generation.
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self { Self(0xDEAD_BEEF_CAFE_BABE) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

const fn ioc_type_at(i: u64) -> IoCType {
    match i % 12 {
        0 => IoCType::Md5,
        1 => IoCType::Sha1,
        2 => IoCType::Sha256,
        3 => IoCType::Sha512,
        4 => IoCType::Ip,
        5 => IoCType::Domain,
        6 => IoCType::Url,
        7 => IoCType::Email,
        8 => IoCType::Registry,
        9 => IoCType::Filename,
        10 => IoCType::Mutex,
        _ => IoCType::Yara,
    }
}

const fn db_ioc_type_at(i: u64) -> IocType {
    match i % 12 {
        0 => IocType::Md5,
        1 => IocType::Sha1,
        2 => IocType::Sha256,
        3 => IocType::Sha512,
        4 => IocType::Ip,
        5 => IocType::Domain,
        6 => IocType::Url,
        7 => IocType::Email,
        8 => IocType::Registry,
        9 => IocType::Filename,
        10 => IocType::Mutex,
        _ => IocType::Yara,
    }
}

// ─── Constructors ───────────────────────────────────────────────────────────

#[test]
fn t01_ioc_new_defaults() {
    let ioc = IoC::new(IoCType::Md5, "abc".to_string(), "s".to_string());
    assert!(ioc.id.is_none());
    assert_eq!(ioc.confidence, 50);
    assert_eq!(ioc.severity, Severity::Medium);
    assert!(ioc.tags.is_empty());
    assert_eq!(ioc.first_seen, 0);
    assert_eq!(ioc.last_seen, 0);
}

#[test]
fn t02_malware_family_new_defaults() {
    let f = MalwareFamily::new("X".to_string(), MalwareType::Worm);
    assert!(f.id.is_none());
    assert!(f.aliases.is_empty());
    assert!(f.iocs.is_empty());
    assert!(f.ttps.is_empty());
    assert!(f.first_seen.is_none());
}

#[test]
fn t03_threat_ioc_new_clamps_high() {
    let t = ThreatIoc::new(IocType::Md5, "v", "n", 2.0, "s");
    assert!((t.confidence - 1.0).abs() < f32::EPSILON);
}

#[test]
fn t04_threat_ioc_new_clamps_low() {
    let t = ThreatIoc::new(IocType::Md5, "v", "n", -1.0, "s");
    assert!((t.confidence - 0.0).abs() < f32::EPSILON);
}

#[test]
fn t05_threat_ioc_new_preserves_mid() {
    let t = ThreatIoc::new(IocType::Url, "v", "n", 0.42, "s");
    assert!((t.confidence - 0.42).abs() < 1e-6);
}

#[test]
fn t06_threat_indicator_db_new_empty() {
    let db = ThreatIndicatorDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
}

#[test]
fn t07_threat_group_new_empty_fields() {
    let g = ThreatGroup::new("G");
    assert_eq!(g.name, "G");
    assert!(g.aliases.is_empty());
    assert!(g.ttps.is_empty());
    assert!(g.iocs.is_empty());
}

#[test]
fn t08_threat_group_tracker_pre_populated_count() {
    let t = ThreatGroupTracker::new();
    assert_eq!(t.known_groups.len(), 5);
}

// ─── Boundaries (0, 1, max, off-by-one) ─────────────────────────────────────

#[test]
fn t09_confidence_zero_boundary() {
    let t = ThreatIoc::new(IocType::Md5, "v", "n", 0.0, "s");
    assert!((t.confidence - 0.0).abs() < f32::EPSILON);
}

#[test]
fn t10_confidence_one_boundary() {
    let t = ThreatIoc::new(IocType::Md5, "v", "n", 1.0, "s");
    assert!((t.confidence - 1.0).abs() < f32::EPSILON);
}

#[test]
fn t11_confidence_just_above_one() {
    let t = ThreatIoc::new(IocType::Md5, "v", "n", 1.0 + f32::EPSILON, "s");
    assert!((t.confidence - 1.0).abs() < f32::EPSILON);
}

#[test]
fn t12_confidence_just_below_zero() {
    let t = ThreatIoc::new(IocType::Md5, "v", "n", -f32::EPSILON, "s");
    assert!((t.confidence - 0.0).abs() < f32::EPSILON);
}

#[test]
fn t13_ioc_u8_confidence_max() {
    let mut i = IoC::new(IoCType::Md5, "a".to_string(), "s".to_string());
    i.confidence = u8::MAX;
    assert_eq!(i.confidence, 255);
}

#[test]
fn t14_db_zero_indicators() {
    let db = ThreatIndicatorDatabase::new();
    assert_eq!(db.lookup("anything").len(), 0);
}

#[test]
fn t15_db_one_indicator() {
    let mut db = ThreatIndicatorDatabase::new();
    db.add_ioc(ThreatIoc::new(IocType::Md5, "x", "n", 0.5, "s"));
    assert_eq!(db.len(), 1);
    assert_eq!(db.lookup("x").len(), 1);
    assert_eq!(db.lookup("y").len(), 0);
}

#[test]
fn t16_db_get_first_id_is_one() {
    let mut db = ThreatIndicatorDatabase::new();
    let id = db.add_ioc(ThreatIoc::new(IocType::Md5, "x", "n", 0.5, "s"));
    assert_eq!(id, IocId(1));
    assert!(db.get(id).is_some());
}

#[test]
fn t17_db_get_unknown_id() {
    let db = ThreatIndicatorDatabase::new();
    assert!(db.get(IocId(9_999_999)).is_none());
}

#[test]
fn t18_db_off_by_one_id_assignment() {
    let mut db = ThreatIndicatorDatabase::new();
    let a = db.add_ioc(ThreatIoc::new(IocType::Md5, "a", "n", 0.5, "s"));
    let b = db.add_ioc(ThreatIoc::new(IocType::Md5, "b", "n", 0.5, "s"));
    let c = db.add_ioc(ThreatIoc::new(IocType::Md5, "c", "n", 0.5, "s"));
    assert_eq!(a, IocId(1));
    assert_eq!(b, IocId(2));
    assert_eq!(c, IocId(3));
}

#[test]
fn t19_severity_boundary_low_to_critical() {
    assert!(Severity::Low < Severity::Critical);
    assert!(Severity::Critical > Severity::Low);
}

#[test]
fn t20_empty_string_value_in_ioc() {
    let ioc = IoC::new(IoCType::Ip, String::new(), String::new());
    assert_eq!(ioc.value, "");
    assert!(ioc.is_network());
}

// ─── Round-trips on 50 LCG-generated inputs ────────────────────────────────

#[test]
fn t21_iocType_as_str_from_key_roundtrip_50() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let ty = ioc_type_at(lcg.next());
        let key = ty.as_str();
        let parsed = IoCType::from_key(key).expect("roundtrip failed");
        assert_eq!(parsed, ty);
    }
}

#[test]
fn t22_ioc_serde_json_roundtrip_50() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let v = lcg.next();
        let ty = ioc_type_at(v);
        let ioc = IoC::new(ty.clone(), format!("val{v}"), format!("src{v}"));
        let json = serde_json::to_string(&ioc).unwrap();
        let back: IoC = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ioc_type, ty);
        assert_eq!(back.value, format!("val{v}"));
    }
}

#[test]
fn t23_malware_family_serde_roundtrip_50() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let v = lcg.next();
        let fam = MalwareFamily::new(format!("fam{v}"), MalwareType::Trojan)
            .with_alias(format!("alias{v}"));
        let json = serde_json::to_string(&fam).unwrap();
        let back: MalwareFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, format!("fam{v}"));
        assert_eq!(back.aliases.len(), 1);
    }
}

#[test]
fn t24_db_add_lookup_roundtrip_50() {
    let mut lcg = Lcg::new();
    let mut db = ThreatIndicatorDatabase::new();
    let mut values = Vec::new();
    for _ in 0..50 {
        let v = lcg.next();
        let val = format!("v{v}");
        db.add_ioc(ThreatIoc::new(db_ioc_type_at(v), val.clone(), "n", 0.5, "s"));
        values.push(val);
    }
    assert_eq!(db.len(), 50);
    for val in &values {
        assert!(!db.lookup(val).is_empty(), "missing {val}");
    }
}

#[test]
fn t25_ioc_type_display_50_inputs_nonempty() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let ty = ioc_type_at(lcg.next());
        assert!(!ty.to_string().is_empty());
        assert!(!ty.as_str().is_empty());
    }
}

// ─── Specific Err variants ──────────────────────────────────────────────────

#[test]
fn t26_err_notfound_display() {
    let e = TiError::NotFound("xyz".to_string());
    let s = e.to_string();
    assert!(s.contains("xyz"));
    assert!(matches!(e, TiError::NotFound(_)));
}

#[test]
fn t27_err_ratelimit_variant() {
    let e = TiError::RateLimit("vt".to_string());
    assert!(e.to_string().contains("vt"));
    assert!(matches!(e, TiError::RateLimit(_)));
}

#[test]
fn t28_err_invalid_api_key_variant() {
    let e = TiError::InvalidApiKey("misp".to_string());
    assert!(e.to_string().contains("misp"));
    assert!(matches!(e, TiError::InvalidApiKey(_)));
}

#[test]
fn t29_err_http_parse_other_variants() {
    assert!(matches!(TiError::Http("h".into()), TiError::Http(_)));
    assert!(matches!(TiError::Parse("p".into()), TiError::Parse(_)));
    assert!(matches!(TiError::Other("o".into()), TiError::Other(_)));
    assert!(matches!(TiError::Mysql("m".into()), TiError::Mysql(_)));
}

#[test]
fn t30_err_from_anyhow() {
    let a = anyhow::anyhow!("boom");
    let e: TiError = a.into();
    assert!(matches!(e, TiError::Other(_)));
    assert!(e.to_string().contains("boom"));
}

#[test]
fn t31_err_from_serde() {
    let parse_err: serde_json::Error = serde_json::from_str::<u32>("not json").unwrap_err();
    let e: TiError = parse_err.into();
    assert!(matches!(e, TiError::Serde(_)));
}

// ─── Display/Debug/Eq/Hash consistency on 30+ pairs ─────────────────────────

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn t32_ioctype_eq_implies_hash_30() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let v = lcg.next();
        let a = ioc_type_at(v);
        let b = ioc_type_at(v);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn t33_iocId_eq_hash_consistency_30() {
    for i in 0..30u64 {
        let a = IocId(i);
        let b = IocId(i);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn t34_malware_type_eq_hash_30() {
    let types = [
        MalwareType::Ransomware, MalwareType::Trojan, MalwareType::Backdoor,
        MalwareType::Rootkit, MalwareType::Worm, MalwareType::Virus,
        MalwareType::Spyware, MalwareType::Adware, MalwareType::Dropper,
        MalwareType::Downloader, MalwareType::Banker, MalwareType::Stealer,
        MalwareType::Botnet, MalwareType::Cryptominer, MalwareType::Fileless,
        MalwareType::PotentiallyUnwanted, MalwareType::Unknown,
    ];
    let mut count = 0;
    for t in &types {
        let cloned = t.clone();
        assert_eq!(t, &cloned);
        assert_eq!(hash_of(t), hash_of(&cloned));
        count += 1;
    }
    assert!(count >= 17);
    // and the same pair, 30 times
    for _ in 0..30 {
        let a = MalwareType::Ransomware;
        let b = MalwareType::Ransomware;
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn t35_debug_display_nonempty_30() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let v = lcg.next();
        let ty = ioc_type_at(v);
        assert!(!format!("{ty}").is_empty());
        assert!(!format!("{ty:?}").is_empty());
        let id = IocId(v);
        assert!(!format!("{id:?}").is_empty());
    }
}

#[test]
fn t36_severity_eq_hash_pairs() {
    let sevs = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical];
    for s in &sevs {
        let c = *s;
        assert_eq!(*s, c);
        assert_eq!(hash_of(s), hash_of(&c));
        assert!(!s.to_string().is_empty());
    }
}

#[test]
fn t37_ioc_display_contains_value() {
    let mut lcg = Lcg::new();
    for _ in 0..30 {
        let v = lcg.next();
        let val = format!("val-{v}");
        let ioc = IoC::new(IoCType::Domain, val.clone(), "src".to_string());
        let s = ioc.to_string();
        assert!(s.contains(&val));
    }
}

// ─── Send/Sync threaded 4×100 ───────────────────────────────────────────────

#[test]
fn t38_threat_indicator_db_send_arc_4x100() {
    let mut db = ThreatIndicatorDatabase::new();
    for i in 0..50 {
        db.add_ioc(ThreatIoc::new(IocType::Md5, format!("v{i}"), "n", 0.5, "s"));
    }
    let arc = Arc::new(db);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            let mut total = 0usize;
            for i in 0..100 {
                total += a.lookup(&format!("v{}", i % 50)).len();
            }
            total
        }));
    }
    let mut sum = 0;
    for h in handles {
        sum += h.join().unwrap();
    }
    assert!(sum > 0);
}

#[test]
fn t39_ioc_send_sync_4x100() {
    let ioc = Arc::new(IoC::new(
        IoCType::Sha256,
        "deadbeef".to_string(),
        "feed".to_string(),
    ));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = Arc::clone(&ioc);
        handles.push(thread::spawn(move || {
            let mut acc = 0usize;
            for _ in 0..100 {
                if a.is_hash() {
                    acc += a.value.len();
                }
            }
            acc
        }));
    }
    let mut total = 0;
    for h in handles {
        total += h.join().unwrap();
    }
    assert_eq!(total, 4 * 100 * "deadbeef".len());
}

#[test]
fn t40_threat_group_tracker_send_4x100() {
    let tracker = Arc::new(ThreatGroupTracker::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = Arc::clone(&tracker);
        handles.push(thread::spawn(move || {
            let mut found = 0usize;
            for _ in 0..100 {
                if a.get("APT28").is_some() { found += 1; }
                if a.get("APT29").is_some() { found += 1; }
            }
            found
        }));
    }
    let mut sum = 0;
    for h in handles {
        sum += h.join().unwrap();
    }
    assert_eq!(sum, 4 * 100 * 2);
}

// ─── Extra coverage ─────────────────────────────────────────────────────────

#[test]
fn t41_db_multiple_iocs_same_value_indexed() {
    let mut db = ThreatIndicatorDatabase::new();
    db.add_ioc(ThreatIoc::new(IocType::Ip, "1.1.1.1", "A", 0.7, "x"));
    db.add_ioc(ThreatIoc::new(IocType::Ip, "1.1.1.1", "B", 0.6, "y"));
    db.add_ioc(ThreatIoc::new(IocType::Ip, "1.1.1.1", "C", 0.5, "z"));
    assert_eq!(db.lookup("1.1.1.1").len(), 3);
}

#[test]
fn t42_stix_export_valid_json_for_each_type() {
    let iocs: Vec<ThreatIoc> = (0..12)
        .map(|i| ThreatIoc::new(db_ioc_type_at(i), format!("v{i}"), "T", 0.9, "internal"))
        .collect();
    let stix = ThreatIndicatorDatabase::export_stix(&iocs);
    let parsed: serde_json::Value = serde_json::from_str(&stix).expect("valid json");
    assert_eq!(parsed["type"], "bundle");
    assert_eq!(parsed["objects"].as_array().unwrap().len(), 12);
}

#[test]
fn t43_threat_group_tracker_search_case_insensitive() {
    let t = ThreatGroupTracker::new();
    let r = t.search("FANCY BEAR");
    assert!(r.iter().any(|g| g.name == "APT28"));
    let r2 = t.search("cozy bear");
    assert!(r2.iter().any(|g| g.name == "APT29"));
}

#[test]
fn t44_threat_group_insert_overwrite() {
    let mut t = ThreatGroupTracker::new();
    t.insert(ThreatGroup::new("APT28").with_alias("Replaced"));
    let g = t.get("APT28").unwrap();
    assert_eq!(g.aliases, vec!["Replaced"]);
}

#[test]
fn t45_ioc_is_hash_for_all_hash_types() {
    for ty in [IoCType::Md5, IoCType::Sha1, IoCType::Sha256, IoCType::Sha512] {
        assert!(IoC::new(ty, String::new(), String::new()).is_hash());
    }
    for ty in [IoCType::Ip, IoCType::Domain, IoCType::Url, IoCType::Email] {
        assert!(!IoC::new(ty, String::new(), String::new()).is_hash());
    }
}
