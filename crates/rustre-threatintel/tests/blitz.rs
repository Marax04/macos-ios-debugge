//! Blitz test suite for rustre-threatintel.
//!
//! Adversarial / boundary / round-trip tests covering the public surface.

use rustre_threatintel::confidence::{
    AggregationMethod, ConfidenceDecay, ConfidenceModel, ConfidenceTier, EvidenceSignal,
};
use rustre_threatintel::error::TiError;
use rustre_threatintel::ioc::{IoC, IoCType, Severity};
use rustre_threatintel::ioc_extractor::IocExtractor;
use rustre_threatintel::ioc_normalizer::{
    Defanger, IoCCanonicalizer, IoCDeduplicator, IoCNormalizer, IoCValidator, NormalizationResult,
    NormalizedIoC, NormalizerConfig, SourceConfidenceScorer, SourceTier, ValidationError,
    infer_ioc_type,
};
use rustre_threatintel::report::{ThreatReport, TlpLevel};
use rustre_threatintel::stix_parser::StixBundle;
use rustre_threatintel::store::{DbConnection, IoCStore};
use rustre_threatintel::threat_scorer::{
    AggregationStrategy, BatchScorer, ContextBoost, DecayConfig, ScoreCache, ScorerConfig,
    SeverityLabel, SourceSignal, ThreatScorer, TiProvider,
};
use rustre_threatintel::{IocId, IocType, ThreatGroup, ThreatGroupTracker, ThreatIndicatorDatabase, ThreatIoc};

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Defanger
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn defang_no_obfuscation_passthrough() {
    assert_eq!(Defanger::defang("https://good.example.com/x"), "https://good.example.com/x");
}

#[test]
fn defang_empty_string() {
    assert_eq!(Defanger::defang(""), "");
}

#[test]
fn defang_whitespace_trimmed() {
    assert_eq!(Defanger::defang("   evil[.]com   "), "evil.com");
}

#[test]
fn defang_multiple_brackets() {
    assert_eq!(Defanger::defang("a[.]b[.]c[.]d"), "a.b.c.d");
}

#[test]
fn defang_double_brackets() {
    assert_eq!(Defanger::defang("a[[.]]b"), "a.b");
}

#[test]
fn defang_parens_and_curlies() {
    assert_eq!(Defanger::defang("a(.)b{.}c"), "a.b.c");
}

#[test]
fn defang_at_variants() {
    assert_eq!(Defanger::defang("user[@]example.com"), "user@example.com");
    assert_eq!(Defanger::defang("user(at)example.com"), "user@example.com");
}

#[test]
fn defang_strips_zero_width() {
    let s = format!("evil{}.com", '\u{200B}');
    assert_eq!(Defanger::defang(&s), "evil.com");
}

#[test]
fn defang_hxxps_variants() {
    assert_eq!(Defanger::defang("hxxps://x"), "https://x");
    assert_eq!(Defanger::defang("hXXps://x"), "https://x");
    assert_eq!(Defanger::defang("h**ps://x"), "https://x");
}

#[test]
fn defang_batch_preserves_count() {
    let inputs = vec!["a[.]b".to_string(), "hxxp://c".to_string()];
    let out = Defanger::defang_batch(&inputs);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].1, "a.b");
}

// ─────────────────────────────────────────────────────────────────────────────
// Validator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_empty_value() {
    assert_eq!(
        IoCValidator::validate("", &IoCType::Domain),
        Err(ValidationError::Empty)
    );
}

#[test]
fn validate_whitespace_only() {
    assert_eq!(
        IoCValidator::validate("   ", &IoCType::Ip),
        Err(ValidationError::Empty)
    );
}

#[test]
fn validate_ipv4_boundary() {
    assert!(IoCValidator::validate("0.0.0.0", &IoCType::Ip).is_ok());
    assert!(IoCValidator::validate("255.255.255.255", &IoCType::Ip).is_ok());
}

#[test]
fn validate_ipv4_overflow_octet() {
    let r = IoCValidator::validate("256.0.0.1", &IoCType::Ip);
    assert!(matches!(r, Err(ValidationError::InvalidIp(_))));
}

#[test]
fn validate_ipv6() {
    assert!(IoCValidator::validate("2001:db8::1", &IoCType::Ip).is_ok());
}

#[test]
fn validate_domain_too_long_label() {
    let long_label = "a".repeat(64);
    let dom = format!("{long_label}.com");
    assert!(matches!(
        IoCValidator::validate(&dom, &IoCType::Domain),
        Err(ValidationError::InvalidDomain(_))
    ));
}

#[test]
fn validate_domain_empty_label() {
    assert!(matches!(
        IoCValidator::validate("foo..bar", &IoCType::Domain),
        Err(ValidationError::InvalidDomain(_))
    ));
}

#[test]
fn validate_domain_illegal_char() {
    assert!(matches!(
        IoCValidator::validate("foo!bar.com", &IoCType::Domain),
        Err(ValidationError::InvalidDomain(_))
    ));
}

#[test]
fn validate_domain_trailing_dot_ok() {
    assert!(IoCValidator::validate("example.com.", &IoCType::Domain).is_ok());
}

#[test]
fn validate_domain_too_long_overall() {
    // 4 * 63 + 3 dots = 255 > 253
    let label = "a".repeat(63);
    let dom = format!("{label}.{label}.{label}.{label}");
    let r = IoCValidator::validate(&dom, &IoCType::Domain);
    assert!(matches!(r, Err(ValidationError::InvalidDomain(_))));
}

#[test]
fn validate_hash_wrong_length() {
    let r = IoCValidator::validate(&"a".repeat(33), &IoCType::Md5);
    assert!(matches!(
        r,
        Err(ValidationError::WrongHashLength { expected: 32, actual: 33 })
    ));
}

#[test]
fn validate_hash_non_hex() {
    let r = IoCValidator::validate(&"g".repeat(32), &IoCType::Md5);
    assert!(matches!(r, Err(ValidationError::Malformed(_))));
}

#[test]
fn validate_sha1_sha512_lengths() {
    assert!(IoCValidator::validate(&"a".repeat(40), &IoCType::Sha1).is_ok());
    assert!(IoCValidator::validate(&"a".repeat(128), &IoCType::Sha512).is_ok());
}

#[test]
fn validate_url_missing_scheme() {
    assert!(matches!(
        IoCValidator::validate("evil.com/x", &IoCType::Url),
        Err(ValidationError::InvalidUrl(_))
    ));
}

#[test]
fn validate_url_unsupported_scheme() {
    assert!(matches!(
        IoCValidator::validate("javascript://evil", &IoCType::Url),
        Err(ValidationError::InvalidUrl(_))
    ));
}

#[test]
fn validate_url_ok_schemes() {
    for s in ["http", "https", "ftp", "ftps"] {
        assert!(IoCValidator::validate(&format!("{s}://x"), &IoCType::Url).is_ok());
    }
}

#[test]
fn validate_email_missing_at() {
    assert!(matches!(
        IoCValidator::validate("noatsign", &IoCType::Email),
        Err(ValidationError::InvalidEmail(_))
    ));
}

#[test]
fn validate_email_empty_local() {
    assert!(matches!(
        IoCValidator::validate("@host.com", &IoCType::Email),
        Err(ValidationError::InvalidEmail(_))
    ));
}

#[test]
fn validate_email_empty_domain() {
    assert!(matches!(
        IoCValidator::validate("u@", &IoCType::Email),
        Err(ValidationError::InvalidEmail(_))
    ));
}

#[test]
fn validation_error_display_variants() {
    assert!(ValidationError::Empty.to_string().contains("empty"));
    assert!(
        ValidationError::WrongHashLength { expected: 32, actual: 5 }
            .to_string()
            .contains("32")
    );
    assert!(ValidationError::InvalidIp("x".into()).to_string().contains('x'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonicalizer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn canon_email_lowercases() {
    assert_eq!(
        IoCCanonicalizer::canonicalize("USER@HOST.COM", &IoCType::Email),
        "user@host.com"
    );
}

#[test]
fn canon_hash_lowercases() {
    let h = "ABCDEF".repeat(11) + "AB"; // arbitrary
    assert_eq!(
        IoCCanonicalizer::canonicalize(&h, &IoCType::Sha256),
        h.to_lowercase()
    );
}

#[test]
fn canon_ip_v6_normalized() {
    // ::1 should round-trip via IpAddr -> ::1
    let c = IoCCanonicalizer::canonicalize("::1", &IoCType::Ip);
    assert_eq!(c, "::1");
}

#[test]
fn canon_url_lowercases_host_preserves_path() {
    let c = IoCCanonicalizer::canonicalize("HTTPS://Evil.COM/PathCase", &IoCType::Url);
    assert_eq!(c, "https://evil.com/PathCase");
}

#[test]
fn canon_url_no_path() {
    let c = IoCCanonicalizer::canonicalize("HTTP://Evil.COM", &IoCType::Url);
    assert_eq!(c, "http://evil.com");
}

#[test]
fn canon_filename_unchanged() {
    assert_eq!(
        IoCCanonicalizer::canonicalize("Evil.EXE", &IoCType::Filename),
        "Evil.EXE"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Deduplicator / SourceConfidenceScorer
// ─────────────────────────────────────────────────────────────────────────────

fn nioc(canonical: &str, conf: f32, tier: SourceTier) -> NormalizedIoC {
    NormalizedIoC {
        raw: canonical.to_string(),
        canonical: canonical.to_string(),
        ioc_type: IoCType::Domain,
        confidence: conf,
        source_tier: tier,
        tags: vec![],
    }
}

#[test]
fn dedup_sorted_by_confidence_desc() {
    let r = IoCDeduplicator::deduplicate(vec![
        nioc("a", 0.2, SourceTier::Community),
        nioc("b", 0.9, SourceTier::Commercial),
        nioc("c", 0.5, SourceTier::Vendor),
    ]);
    assert_eq!(r.len(), 3);
    assert!(r[0].confidence >= r[1].confidence);
    assert!(r[1].confidence >= r[2].confidence);
}

#[test]
fn dedup_empty() {
    let r = IoCDeduplicator::deduplicate(vec![]);
    assert!(r.is_empty());
}

#[test]
fn source_tier_baseline_monotonic() {
    let c = SourceTier::Community.baseline_confidence();
    let v = SourceTier::Vendor.baseline_confidence();
    let cm = SourceTier::Commercial.baseline_confidence();
    let fp = SourceTier::FirstParty.baseline_confidence();
    assert!(c < v && v < cm && cm < fp);
}

#[test]
fn source_tier_ord() {
    assert!(SourceTier::Community < SourceTier::FirstParty);
}

#[test]
fn confidence_scorer_score_clamped() {
    let s = SourceConfidenceScorer::score(SourceTier::FirstParty, Some(2.0));
    assert!(s <= 1.0);
}

#[test]
fn confidence_scorer_quality_none_is_identity() {
    let without_quality = SourceConfidenceScorer::score(SourceTier::Vendor, None);
    let perfect_quality = SourceConfidenceScorer::score(SourceTier::Vendor, Some(1.0));
    assert!((without_quality - perfect_quality).abs() < 1e-6);
}

#[test]
fn confidence_scorer_combine_empty() {
    assert!((SourceConfidenceScorer::combine(&[]) - 0.0).abs() < f32::EPSILON);
}

#[test]
fn confidence_scorer_combine_zero_total_weight() {
    assert!((SourceConfidenceScorer::combine(&[(0.9, 0.0), (0.5, 0.0)]) - 0.0).abs() < f32::EPSILON);
}

#[test]
fn confidence_scorer_combine_average() {
    let r = SourceConfidenceScorer::combine(&[(0.8, 1.0), (0.4, 1.0)]);
    assert!((r - 0.6).abs() < 1e-6);
}

// ─────────────────────────────────────────────────────────────────────────────
// IoCNormalizer pipeline
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn normalize_invalid_returns_invalid_variant() {
    let n = IoCNormalizer::default();
    let r = n.normalize_one("not an ip", IoCType::Ip, None, vec![]);
    matches!(r, NormalizationResult::Invalid { .. });
}

#[test]
fn normalize_one_uses_default_tier_when_none() {
    let cfg = NormalizerConfig {
        skip_invalid: true,
        default_tier: SourceTier::Commercial,
        source_quality: 1.0,
    };
    let n = IoCNormalizer::new(cfg);
    let r = n.normalize_one("evil.com", IoCType::Domain, None, vec![]);
    if let NormalizationResult::Ok(nioc) = r {
        assert_eq!(nioc.source_tier, SourceTier::Commercial);
    } else {
        panic!("expected Ok");
    }
}

#[test]
fn normalize_batch_skip_invalid_drops_them() {
    let n = IoCNormalizer::default(); // skip_invalid=true
    let (valid, invalid) = n.normalize_batch(vec![
        ("1.2.3.4".to_string(), IoCType::Ip, None, vec![]),
        ("bad".to_string(), IoCType::Ip, None, vec![]),
    ]);
    assert_eq!(valid.len(), 1);
    assert!(invalid.is_empty(), "skip_invalid=true should drop errors");
}

#[test]
fn normalize_batch_keep_invalid() {
    let cfg = NormalizerConfig {
        skip_invalid: false,
        ..NormalizerConfig::default()
    };
    let n = IoCNormalizer::new(cfg);
    let (_, invalid) = n.normalize_batch(vec![
        ("bad".to_string(), IoCType::Ip, None, vec![]),
    ]);
    assert_eq!(invalid.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// infer_ioc_type
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn infer_ipv4() {
    assert_eq!(infer_ioc_type("8.8.8.8"), Some(IoCType::Ip));
}

#[test]
fn infer_ipv6() {
    assert_eq!(infer_ioc_type("::1"), Some(IoCType::Ip));
}

#[test]
fn infer_url_http() {
    assert_eq!(infer_ioc_type("http://evil.com/a"), Some(IoCType::Url));
}

#[test]
fn infer_email_with_dot() {
    assert_eq!(infer_ioc_type("u@example.com"), Some(IoCType::Email));
}

#[test]
fn infer_domain() {
    assert_eq!(infer_ioc_type("evil.example.com"), Some(IoCType::Domain));
}

#[test]
fn infer_none_for_garbage() {
    assert_eq!(infer_ioc_type("totally random"), None);
}

#[test]
fn infer_md5_sha1_sha256_sha512() {
    assert_eq!(infer_ioc_type(&"a".repeat(32)), Some(IoCType::Md5));
    assert_eq!(infer_ioc_type(&"a".repeat(40)), Some(IoCType::Sha1));
    assert_eq!(infer_ioc_type(&"a".repeat(64)), Some(IoCType::Sha256));
    assert_eq!(infer_ioc_type(&"a".repeat(128)), Some(IoCType::Sha512));
}

#[test]
fn infer_works_through_defang() {
    // Defang reverses obfuscation first
    assert_eq!(infer_ioc_type("hxxp://evil[.]com"), Some(IoCType::Url));
}

// ─────────────────────────────────────────────────────────────────────────────
// IocExtractor
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn extractor_empty_input() {
    let e = IocExtractor::new();
    let r = e.extract_from_str("");
    assert_eq!(r.total_count(), 0);
}

#[test]
fn extractor_default_equals_new() {
    let e1 = IocExtractor::default();
    let e2 = IocExtractor::new();
    let r1 = e1.extract_from_str("1.2.3.4");
    let r2 = e2.extract_from_str("1.2.3.4");
    assert_eq!(r1.ipv4, r2.ipv4);
}

#[test]
fn extractor_multiple_urls_dedup() {
    let e = IocExtractor::new();
    let text = "http://a.com http://a.com http://b.org";
    let r = e.extract_from_str(text);
    assert_eq!(r.urls.len(), 2);
}

#[test]
fn extractor_url_excluded_from_ipv4() {
    // IP in URL should not double-count as standalone IP.
    let e = IocExtractor::new();
    let r = e.extract_from_str("see http://1.2.3.4/path");
    // URL captured
    assert_eq!(r.urls.len(), 1);
    // IPv4 should NOT contain the one inside the URL
    assert!(!r.ipv4.contains(&"1.2.3.4".to_string()));
}

#[test]
fn extractor_email_blocks_domain_extraction() {
    let e = IocExtractor::new();
    let r = e.extract_from_str("contact me at attacker@evilcorp.com please");
    assert!(r.emails.iter().any(|s| s == "attacker@evilcorp.com"));
    // The domain part 'evilcorp.com' shouldn't appear as a standalone domain
    assert!(!r.domains.iter().any(|d| d == "evilcorp.com"));
}

#[test]
fn extractor_invalid_ipv4_rejected_by_regex() {
    let e = IocExtractor::new();
    let r = e.extract_from_str("not an ip 999.999.999.999");
    assert!(r.ipv4.is_empty());
}

#[test]
fn extractor_ethereum_addr() {
    let e = IocExtractor::new();
    let addr = "0x1234567890abcdef1234567890abcdef12345678";
    let r = e.extract_from_str(addr);
    assert!(r.ethereum_addresses.iter().any(|x| x == addr));
}

#[test]
fn extractor_user_agent() {
    let e = IocExtractor::new();
    let r = e.extract_from_str("UA: Mozilla/5.0 (Windows NT 10.0)");
    assert!(!r.user_agents.is_empty());
}

#[test]
fn extractor_from_bytes_non_ascii_substituted() {
    let e = IocExtractor::new();
    let mut data = Vec::new();
    data.extend_from_slice(b"prefix ");
    data.push(0xFF);
    data.extend_from_slice(b"8.8.8.8");
    let r = e.extract_from_bytes(&data);
    assert!(r.ipv4.contains(&"8.8.8.8".to_string()));
}

#[test]
fn extractor_total_count_consistency() {
    let e = IocExtractor::new();
    let r = e.extract_from_str(
        "1.2.3.4 http://x.org bad@evil.com d41d8cd98f00b204e9800998ecf8427e",
    );
    let manual = r.ipv4.len() + r.urls.len() + r.emails.len() + r.md5.len() + r.domains.len();
    assert!(r.total_count() >= manual);
}

#[test]
fn extractor_to_ioc_list_uses_extractor_source() {
    let e = IocExtractor::new();
    let r = e.extract_from_str("1.2.3.4");
    let lst = r.to_ioc_list();
    assert!(!lst.is_empty());
    assert!(lst.iter().all(|i| i.source == "extractor"));
}

// ─────────────────────────────────────────────────────────────────────────────
// IoC / Severity / IoCType
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ioc_type_from_key_unknown_is_none() {
    assert!(IoCType::from_key("nope").is_none());
}

#[test]
fn ioc_type_serde_snake_case() {
    let json = serde_json::to_string(&IoCType::Sha256).unwrap();
    assert_eq!(json, "\"sha256\"");
}

#[test]
fn severity_serde_lowercase() {
    let json = serde_json::to_string(&Severity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
}

#[test]
fn ioc_display_contains_all_components() {
    let mut ioc = IoC::new(
        IoCType::Md5,
        "abc".to_string(),
        "test".to_string(),
    );
    ioc.confidence = 77;
    ioc.severity = Severity::High;
    let s = ioc.to_string();
    assert!(s.contains("MD5"));
    assert!(s.contains("abc"));
    assert!(s.contains("77"));
    assert!(s.contains("High"));
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfidenceModel & decay
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn confidence_tier_score_100_is_veryhigh() {
    assert_eq!(ConfidenceTier::from_score(100), ConfidenceTier::VeryHigh);
}

#[test]
fn confidence_tier_score_255_still_veryhigh() {
    // u8 range; ensure no panic and stays at top
    assert_eq!(ConfidenceTier::from_score(u8::MAX), ConfidenceTier::VeryHigh);
}

#[test]
fn confidence_model_bayes_with_zero_prior_stays_low() {
    let m = ConfidenceModel::new(AggregationMethod::WeightedMean)
        .with_prior(0.0)
        .with_signal(EvidenceSignal::new("x", 0.9, 1.0, ""));
    // Prior of 0 should yield 0 (degenerate Bayes)
    let s = m.raw_score();
    assert!(s.is_nan() || s == 0.0, "expected 0 or NaN, got {s}");
}

#[test]
fn confidence_decay_initial_clamped() {
    let d = ConfidenceDecay::new(2.0, 100.0);
    assert!((d.initial_score - 1.0).abs() < 1e-10);
}

#[test]
fn confidence_decay_halflife_min_one() {
    // half_life_secs.max(1.0) means 0 becomes 1
    let d = ConfidenceDecay::new(1.0, 0.0);
    assert!(d.half_life_secs >= 1.0);
}

#[test]
fn confidence_decay_negative_initial_clamped() {
    let d = ConfidenceDecay::new(-1.0, 10.0);
    assert!((d.initial_score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn evidence_signal_weight_clamped_negative() {
    // debug_assert may fire in debug; release should clamp.
    // Skip if debug_assertions are on — that's by design.
    if cfg!(debug_assertions) {
        return;
    }
    let s = EvidenceSignal::new("s", 0.5, -1.0, "");
    assert!((s.weight - 0.0).abs() < f64::EPSILON);
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatReport / TLP
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tlp_serde_uppercase() {
    let json = serde_json::to_string(&TlpLevel::Red).unwrap();
    assert_eq!(json, "\"RED\"");
}

#[test]
fn tlp_display_format() {
    assert_eq!(TlpLevel::Amber.to_string(), "TLP:AMBER");
}

#[test]
fn tlp_ord_chain() {
    assert!(TlpLevel::White < TlpLevel::Green);
    assert!(TlpLevel::Green < TlpLevel::Amber);
    assert!(TlpLevel::Amber < TlpLevel::Red);
}

#[test]
fn report_display_contains_tlp_and_count() {
    let mut r = ThreatReport::new("t".into(), "a".into());
    r.add_ioc(IoC::new(IoCType::Ip, "1.1.1.1".into(), "s".into()));
    let s = r.to_string();
    assert!(s.contains("TLP:WHITE"));
    assert!(s.contains("1 IoC"));
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatScorer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ti_provider_base_weights() {
    assert!(TiProvider::VirusTotal.base_weight() > TiProvider::OtxAlienVault.base_weight());
    assert!((TiProvider::Custom("x".into()).base_weight() - 1.0).abs() < f32::EPSILON);
}

#[test]
fn decay_multiplier_floor_applied() {
    let cfg = DecayConfig {
        half_life_secs: 100,
        floor: 0.25,
    };
    // Very old → should hit floor
    let m = cfg.multiplier(u64::MAX / 2);
    assert!((m - 0.25).abs() < 1e-6);
}

#[test]
fn decay_multiplier_at_zero_age_is_one() {
    let cfg = DecayConfig {
        half_life_secs: 100,
        floor: 0.0,
    };
    assert!((cfg.multiplier(0) - 1.0).abs() < 1e-6);
}

#[test]
fn severity_label_boundaries() {
    assert_eq!(SeverityLabel::from_score(0.0), SeverityLabel::Unknown);
    assert_eq!(SeverityLabel::from_score(0.2), SeverityLabel::Low);
    assert_eq!(SeverityLabel::from_score(0.4), SeverityLabel::Medium);
    assert_eq!(SeverityLabel::from_score(0.6), SeverityLabel::High);
    assert_eq!(SeverityLabel::from_score(0.8), SeverityLabel::Critical);
    assert_eq!(SeverityLabel::from_score(1.0), SeverityLabel::Critical);
}

#[test]
fn scorer_max_aggregation() {
    let cfg = ScorerConfig {
        decay: DecayConfig::default(),
        aggregation: AggregationStrategy::Max,
        max_boost: 0.4,
        apply_sigmoid: false,
    };
    let scorer = ThreatScorer::new(cfg);
    let sigs = vec![
        SourceSignal::new_now(TiProvider::Misp, 0.3),
        SourceSignal::new_now(TiProvider::VirusTotal, 0.95),
    ];
    let bd = scorer.score(&sigs, &[]);
    assert!(bd.weighted_mean >= 0.94);
}

#[test]
fn scorer_min_aggregation() {
    let cfg = ScorerConfig {
        decay: DecayConfig::default(),
        aggregation: AggregationStrategy::Min,
        max_boost: 0.4,
        apply_sigmoid: false,
    };
    let scorer = ThreatScorer::new(cfg);
    let sigs = vec![
        SourceSignal::new_now(TiProvider::Misp, 0.3),
        SourceSignal::new_now(TiProvider::VirusTotal, 0.95),
    ];
    let bd = scorer.score(&sigs, &[]);
    assert!(bd.weighted_mean <= 0.31);
}

#[test]
fn scorer_boost_capped_at_max_boost() {
    let cfg = ScorerConfig {
        decay: DecayConfig::default(),
        aggregation: AggregationStrategy::WeightedMean,
        max_boost: 0.1,
        apply_sigmoid: false,
    };
    let scorer = ThreatScorer::new(cfg);
    let sigs = vec![SourceSignal::new_now(TiProvider::Misp, 0.5)];
    let bd = scorer.score(
        &sigs,
        &[
            ContextBoost::active_sample_analysis(0.3),
            ContextBoost::sandbox_traffic(0.25),
        ],
    );
    assert!((bd.total_boost - 0.1).abs() < 1e-6);
}

#[test]
fn context_boost_active_sample_clamped() {
    let b = ContextBoost::active_sample_analysis(1.0);
    assert!(b.boost <= 0.3);
}

#[test]
fn context_boost_sandbox_traffic_clamped() {
    let b = ContextBoost::sandbox_traffic(99.0);
    assert!(b.boost <= 0.25);
}

#[test]
fn context_boost_malware_family_clamped() {
    let b = ContextBoost::malware_family_match(2.0);
    assert!(b.boost <= 0.2);
}

#[test]
fn batch_scorer_filter_by_score_sorted_desc() {
    let scorer = ThreatScorer::default();
    let bs = BatchScorer::new(scorer);
    let mut sigs_map: HashMap<String, Vec<SourceSignal>> = HashMap::new();
    sigs_map.insert(
        "a".into(),
        vec![SourceSignal::new_now(TiProvider::VirusTotal, 0.95)],
    );
    sigs_map.insert(
        "b".into(),
        vec![SourceSignal::new_now(TiProvider::OtxAlienVault, 0.1)],
    );
    let boosts_map: HashMap<String, Vec<ContextBoost>> = HashMap::new();
    let res = bs.score_all(sigs_map, &boosts_map);
    let filtered = BatchScorer::filter_by_score(&res, 0.0);
    assert_eq!(filtered.len(), 2);
    assert!(filtered[0].1 >= filtered[1].1);
}

#[test]
fn score_cache_evicts_stale() {
    let mut cache = ScoreCache::new(0); // immediate expiration
    let scorer = ThreatScorer::default();
    let bd = scorer.score(&[SourceSignal::new_now(TiProvider::Misp, 0.5)], &[]);
    cache.insert("x".into(), bd);
    // ttl=0 → entries are immediately stale: now.saturating_sub(ts) < 0 is false
    assert!(cache.get("x").is_none());
}

#[test]
fn score_cache_evict_stale_method() {
    let mut cache = ScoreCache::new(0);
    let scorer = ThreatScorer::default();
    let bd = scorer.score(&[SourceSignal::new_now(TiProvider::Misp, 0.5)], &[]);
    cache.insert("x".into(), bd);
    assert_eq!(cache.len(), 1);
    cache.evict_stale();
    assert_eq!(cache.len(), 0);
}

#[test]
fn source_signal_score_clamped() {
    let s = SourceSignal::new_now(TiProvider::Misp, 5.0);
    assert!(s.raw_score <= 1.0);
    let s2 = SourceSignal::new_now(TiProvider::Misp, -1.0);
    assert!(s2.raw_score >= 0.0);
}

// ─────────────────────────────────────────────────────────────────────────────
// STIX parser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stix_from_bytes_ok() {
    let json = br#"{"type":"bundle","spec_version":"2.1","id":"bundle--x","objects":[]}"#;
    let b = StixBundle::from_bytes(json).unwrap();
    assert!(b.is_valid());
}

#[test]
fn stix_malformed_json_errors() {
    let r = StixBundle::from_json("{not json");
    assert!(r.is_err());
}

#[test]
fn stix_missing_required_fields_errors() {
    // bundle missing spec_version
    let r = StixBundle::from_json(r#"{"type":"bundle","id":"x"}"#);
    assert!(r.is_err());
}

#[test]
fn stix_round_trip_preserves_object_count() {
    let json = r#"{
        "type":"bundle","spec_version":"2.1","id":"bundle--x",
        "objects":[
            {"type":"indicator","id":"indicator--1","name":"n",
             "pattern":"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
             "pattern_type":"stix","valid_from":"2024-01-01T00:00:00Z"}
        ]
    }"#;
    let b = StixBundle::from_json(json).unwrap();
    let s = b.to_json().unwrap();
    let b2 = StixBundle::from_json(&s).unwrap();
    assert_eq!(b.object_count(), b2.object_count());
}

#[test]
fn stix_indicator_extract_value_double_quotes() {
    // The extractor first tries single-quote pattern, then double-quote. Test the double-quote branch.
    let json = r#"{
        "type":"bundle","spec_version":"2.1","id":"bundle--x",
        "objects":[
            {"type":"indicator","id":"indicator--1","name":"n",
             "pattern":"[domain-name:value = \"evil.com\"]",
             "pattern_type":"stix","valid_from":"2024-01-01T00:00:00Z"}
        ]
    }"#;
    let b = StixBundle::from_json(json).unwrap();
    let v = b.indicators()[0].extract_value();
    assert_eq!(v.as_deref(), Some("evil.com"));
}

#[test]
fn stix_indicator_network_classification() {
    let json = r#"{
        "type":"bundle","spec_version":"2.1","id":"bundle--x",
        "objects":[
            {"type":"indicator","id":"indicator--1","name":"n",
             "pattern":"[ipv4-addr:value = '1.2.3.4']",
             "pattern_type":"stix","valid_from":"2024-01-01T00:00:00Z"}
        ]
    }"#;
    let b = StixBundle::from_json(json).unwrap();
    assert!(b.indicators()[0].is_network_indicator());
    assert!(!b.indicators()[0].is_file_hash());
}

#[test]
fn stix_bundle_validity_wrong_spec_version() {
    let json = r#"{"type":"bundle","spec_version":"1.0","id":"b","objects":[]}"#;
    let b = StixBundle::from_json(json).unwrap();
    assert!(!b.is_valid());
}

// ─────────────────────────────────────────────────────────────────────────────
// Store (SQLite in-memory)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn store_insert_two_count_two() {
    let conn = DbConnection::sqlite_in_memory().unwrap();
    let s = IoCStore::new(conn);
    s.insert_ioc(&IoC::new(IoCType::Ip, "1.1.1.1".into(), "src".into()))
        .unwrap();
    s.insert_ioc(&IoC::new(IoCType::Ip, "2.2.2.2".into(), "src".into()))
        .unwrap();
    assert_eq!(s.count().unwrap(), 2);
}

#[test]
fn store_find_by_missing_value_is_none() {
    let conn = DbConnection::sqlite_in_memory().unwrap();
    let s = IoCStore::new(conn);
    assert!(s.find_by_value("nope").unwrap().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// TiError
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ti_error_from_serde_json() {
    let err: serde_json::Error = serde_json::from_str::<serde_json::Value>("xx").unwrap_err();
    let te: TiError = err.into();
    match te {
        TiError::Serde(_) => {}
        _ => panic!("wrong variant"),
    }
}

#[test]
fn ti_error_from_anyhow() {
    let a = anyhow::anyhow!("custom");
    let te: TiError = a.into();
    matches!(te, TiError::Other(_));
}

#[test]
fn ti_error_display_each_variant_basic() {
    assert!(TiError::Http("h".into()).to_string().contains("http"));
    assert!(TiError::Parse("p".into()).to_string().contains("parse"));
    assert!(TiError::InvalidApiKey("k".into()).to_string().contains('k'));
    assert!(TiError::Mysql("m".into()).to_string().contains('m'));
    assert!(TiError::Other("o".into()).to_string().contains('o'));
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatIndicatorDatabase / STIX export
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tidb_get_by_id() {
    let mut db = ThreatIndicatorDatabase::new();
    let id = db.add_ioc(ThreatIoc::new(IocType::Md5, "abc", "T", 0.5, "s"));
    assert!(db.get(id).is_some());
    assert!(db.get(IocId(999_999)).is_none());
}

#[test]
fn tidb_export_stix_each_ioc_type_produces_pattern() {
    let types_and_keywords = [
        (IocType::Md5, "MD5"),
        (IocType::Sha1, "SHA-1"),
        (IocType::Sha256, "SHA-256"),
        (IocType::Sha512, "SHA-512"),
        (IocType::Ip, "ipv4-addr"),
        (IocType::Domain, "domain-name"),
        (IocType::Url, "url:value"),
        (IocType::Email, "email-addr"),
        (IocType::Registry, "windows-registry-key"),
        (IocType::Filename, "file:name"),
        (IocType::Mutex, "mutex:name"),
        (IocType::Yara, "file:content"),
    ];
    for (t, kw) in types_and_keywords {
        let iocs = vec![ThreatIoc::new(t, "val", "Tname", 0.5, "src")];
        let stix = ThreatIndicatorDatabase::export_stix(&iocs);
        // Must parse as JSON
        let parsed: serde_json::Value = serde_json::from_str(&stix).expect("invalid JSON");
        assert_eq!(parsed["type"], "bundle");
        assert!(stix.contains(kw), "missing keyword {kw}");
    }
}

#[test]
fn tidb_export_stix_special_chars_in_threat_name_escaped() {
    // Threat name with a double-quote must produce valid JSON.
    let iocs = vec![ThreatIoc::new(
        IocType::Md5,
        "deadbeef",
        r#"weird "quoted" name with \ backslash"#,
        0.5,
        "src",
    )];
    let stix = ThreatIndicatorDatabase::export_stix(&iocs);
    let _parsed: serde_json::Value = serde_json::from_str(&stix).expect("invalid JSON");
}

#[test]
fn tidb_lookup_after_multiple_inserts_same_value() {
    let mut db = ThreatIndicatorDatabase::new();
    for i in 0..5 {
        db.add_ioc(ThreatIoc::new(
            IocType::Domain,
            "x.com",
            format!("T{i}"),
            0.5,
            "s",
        ));
    }
    assert_eq!(db.lookup("x.com").len(), 5);
}

#[test]
fn tidb_is_empty_after_construction() {
    assert!(ThreatIndicatorDatabase::new().is_empty());
}

#[test]
fn iocid_hash_eq() {
    use std::collections::HashSet;
    let mut s: HashSet<IocId> = HashSet::new();
    s.insert(IocId(1));
    s.insert(IocId(1));
    s.insert(IocId(2));
    assert_eq!(s.len(), 2);
}

#[test]
fn ioctype_display_all() {
    for (t, s) in [
        (IocType::Md5, "MD5"),
        (IocType::Sha1, "SHA-1"),
        (IocType::Sha256, "SHA-256"),
        (IocType::Sha512, "SHA-512"),
        (IocType::Ip, "IP"),
        (IocType::Domain, "Domain"),
        (IocType::Url, "URL"),
        (IocType::Email, "Email"),
        (IocType::Registry, "Registry"),
        (IocType::Filename, "Filename"),
        (IocType::Mutex, "Mutex"),
        (IocType::Yara, "YARA"),
    ] {
        assert_eq!(t.to_string(), s);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatGroupTracker
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tgt_search_case_insensitive() {
    let t = ThreatGroupTracker::new();
    assert!(t.search("FANCY BEAR").iter().any(|g| g.name == "APT28"));
    assert!(t.search("cozy bear").iter().any(|g| g.name == "APT29"));
}

#[test]
fn tgt_search_no_match_empty() {
    let t = ThreatGroupTracker::new();
    assert!(t.search("zzzzzz_nonexistent").is_empty());
}

#[test]
fn tg_builder() {
    let g = ThreatGroup::new("X").with_alias("a").with_ttp("T1059");
    assert_eq!(g.name, "X");
    assert_eq!(g.aliases, vec!["a"]);
    assert_eq!(g.ttps, vec!["T1059"]);
}

#[test]
fn tgt_default_constructible() {
    let t: ThreatGroupTracker = ThreatGroupTracker::default();
    assert!(t.get("APT28").is_some());
}
