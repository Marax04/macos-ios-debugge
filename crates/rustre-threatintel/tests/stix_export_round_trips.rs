//! `ThreatIndicatorDatabase::export_stix` (lib.rs) is the producer and `StixBundle` /
//! `Indicator` (stix_parser.rs) is the consumer, in the same crate. Whatever one
//! writes, the other must be able to read back.
//!
//! The domain is enumerable and small — the twelve `IocType` variants — so it is
//! enumerated in full rather than sampled, once with an ordinary value and once
//! with a value containing a single quote, which is the delimiter the emitted
//! STIX pattern uses.

use rustre_threatintel::stix_parser::StixBundle;
use rustre_threatintel::{IocType, ThreatIndicatorDatabase, ThreatIoc};

/// Every variant, so a new one cannot be added without this test noticing.
fn all_types() -> Vec<(IocType, &'static str)> {
    vec![
        (IocType::Md5, "Md5"),
        (IocType::Sha1, "Sha1"),
        (IocType::Sha256, "Sha256"),
        (IocType::Sha512, "Sha512"),
        (IocType::Ip, "Ip"),
        (IocType::Domain, "Domain"),
        (IocType::Url, "Url"),
        (IocType::Email, "Email"),
        (IocType::Registry, "Registry"),
        (IocType::Filename, "Filename"),
        (IocType::Mutex, "Mutex"),
        (IocType::Yara, "Yara"),
    ]
}

fn round_trip(ioc_type: IocType, value: &str) -> Option<String> {
    let ioc = ThreatIoc::new(ioc_type, value, "TestThreat", 0.8, "unit-test");
    let json = ThreatIndicatorDatabase::export_stix(std::slice::from_ref(&ioc));
    let bundle = StixBundle::from_json(&json).ok()?;
    let indicators = bundle.indicators();
    assert_eq!(
        indicators.len(),
        1,
        "the exported bundle must contain exactly one indicator"
    );
    indicators[0].extract_value()
}

#[test]
fn an_ordinary_value_survives_export_and_reparse_for_every_type() {
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for (ioc_type, label) in all_types() {
        let value = "harmless-value-123";
        match round_trip(ioc_type.clone(), value) {
            Some(back) if back == value => {}
            Some(back) => divergences.push(format!("{label}: exported `{value}`, read back `{back}`")),
            None => divergences.push(format!("{label}: exported `{value}`, read back nothing")),
        }
        checked += 1;
    }

    assert_eq!(checked, 12, "anti-vacuity: every IocType variant exercised");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn a_value_containing_the_pattern_delimiter_survives_too() {
    // The emitted pattern is `[... = 'VALUE']`, so a single quote inside VALUE
    // is the delimiter itself. Registry keys, mutex names, filenames and YARA
    // rule text can all contain one.
    let mut divergences = Vec::new();

    for (ioc_type, label) in all_types() {
        for value in ["don't.exe", "a = 'b", "trailing'"] {
            match round_trip(ioc_type.clone(), value) {
                Some(back) if back == value => {}
                Some(back) => {
                    divergences.push(format!("{label}: exported `{value}`, read back `{back}`"));
                }
                None => divergences.push(format!("{label}: exported `{value}`, read back nothing")),
            }
        }
    }

    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn hash_types_are_classified_as_file_hashes_and_others_are_not() {
    let mut checked = 0usize;
    let mut hashes = 0usize;
    let mut non_hashes = 0usize;

    for (ioc_type, label) in all_types() {
        let expected_hash = matches!(
            ioc_type,
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 | IocType::Sha512
        );
        let ioc = ThreatIoc::new(ioc_type, "abc123", "TestThreat", 0.8, "unit-test");
        let json = ThreatIndicatorDatabase::export_stix(std::slice::from_ref(&ioc));
        let bundle = StixBundle::from_json(&json).expect("premise: our own export must parse");
        let indicators = bundle.indicators();

        assert_eq!(
            indicators[0].is_file_hash(),
            expected_hash,
            "{label}: is_file_hash() disagrees with the type that produced the pattern"
        );
        if expected_hash {
            hashes += 1;
        } else {
            non_hashes += 1;
        }
        checked += 1;
    }

    assert_eq!(checked, 12, "anti-vacuity: every variant exercised");
    assert_eq!(hashes, 4, "anti-vacuity: the four hash types must be present");
    assert!(non_hashes >= 4, "anti-vacuity: non-hash types must be present");
}
