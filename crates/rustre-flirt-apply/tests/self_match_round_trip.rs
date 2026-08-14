//! A signature must find the code it was generated from (T14).
//!
//! # The measurement that closed T3c
//!
//! Iteration 37 recorded a *hypothesis*: CRC-bearing signatures are rejected by
//! construction, because the generator drops masked bytes while the scanner
//! masks nothing. It was explicitly left unproven — closing it needed an
//! end-to-end generate→scan run. That run is
//! `examples/self_match_experiment.rs`, and on `libz.a` (15 objects, 132
//! patterns produced by the real harvester, 26 of them wildcarded) it measured:
//!
//! | subset | self-match |
//! |---|---|
//! | all patterns | 86/132 (65.2%) |
//! | without wildcards | 83/106 (78.3%) |
//! | with wildcards | **3/26 (11.5%)** |
//! | all, CRC field cleared | **128/132 (97.0%)** |
//! | wildcarded, CRC cleared | **22/26 (84.6%)** |
//!
//! Clearing one field recovers 42 of the 46 lost functions. The hypothesis is
//! now measured fact: the stored CRC does not equal the one the scanner
//! recomputes, so it rejects rather than confirms. It is not a wildcard-matching
//! defect — the wildcarded subset is merely where relocations, hence masked
//! bytes, hence divergent CRCs, are concentrated. The residual 4/132 that fail
//! even without a CRC are a separate, smaller defect, deliberately not
//! attributed here.
//!
//! # What these tests do and do not carry
//!
//! The percentages above need a real archive, so they live in the example, not
//! here. An earlier draft of this file tried to reproduce them hermetically by
//! hand-modelling how the generator computes its CRC. That model was wrong — it
//! ignored `crc_offset`, so the CRC window it built started in the wrong place —
//! and the tests were measuring the model rather than the crate. Recorded
//! because it is the same failure mode as the metric itself: a plausible model
//! of a component is not the component.
//!
//! What is pinned here is the mechanism the measurement rests on, using only the
//! real writer and the real scanner: **a CRC that does not reproduce turns a
//! match into a miss**. That plus the measured generator behaviour is the whole
//! argument.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

/// 32 bytes of plausible x86-64, distinctive enough not to occur by accident.
const BODY: &[u8] = &[
    0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48, 0x89, 0xC7, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48,
    0x83, 0xC4, 0x28, 0x5B, 0x5D, 0x41, 0x5C, 0x41, 0x5D, 0xC3, 0x90, 0x66, 0x0F, 0x1F, 0x44, 0x00,
];

fn pattern_over(name: &str, body: &[u8]) -> FlirtPattern {
    let mut p = FlirtPattern::new(body.iter().map(|b| PatternByte::Exact(*b)).collect());
    p.names.push(FlirtName {
        offset: 0,
        name: name.to_string(),
        is_public: true,
        is_local: false,
    });
    p
}

/// Drive the real path: write a `.sig`, load it into the real scanner, scan.
fn scan_for(pats: &[FlirtPattern], haystack: &[u8]) -> Vec<String> {
    let sig = rustre_flirt_gen::SigWriter::default().build(pats, "selftest");
    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig)
        .expect("il .sig appena scritto deve essere leggibile");
    scanner
        .scan_fast(haystack, 0)
        .into_iter()
        .map(|m| m.function_name)
        .collect()
}

#[test]
fn a_pattern_without_a_crc_finds_its_own_bytes() {
    // The baseline the whole round-trip rests on. If this ever fails, the
    // generate→scan path is broken for a reason that has nothing to do with the
    // CRC, and the libz percentages mean something else.
    let p = pattern_over("plain_fn", BODY);
    assert!(
        scan_for(std::slice::from_ref(&p), BODY)
            .iter()
            .any(|n| n == "plain_fn"),
        "senza CRC una firma deve ritrovare i byte da cui viene"
    );
}

#[test]
fn a_crc_that_does_not_reproduce_turns_a_match_into_a_miss() {
    // The mechanism behind the measurement. Same pattern, same bytes, only the
    // CRC changed to a value the scanner cannot recompute — exactly the position
    // the generator puts every relocation-bearing signature in.
    let mut p = pattern_over("crc_fn", BODY);
    p.crc16 = 0xDEAD;
    p.crc_length = 8;
    assert!(
        !scan_for(std::slice::from_ref(&p), BODY)
            .iter()
            .any(|n| n == "crc_fn"),
        "un CRC irriproducibile deve far fallire il match: se non lo fa, il CRC \
         non e' consultato affatto e la spiegazione del 65.2%→97.0% va rifatta"
    );
}

#[test]
fn the_crc_is_the_only_difference_between_the_two_outcomes() {
    // Stated as one assertion so the comparison cannot drift apart: two patterns
    // identical in every byte, differing only in the CRC field, land on opposite
    // sides of the match/miss line.
    let plain = pattern_over("twin", BODY);
    let mut crced = pattern_over("twin", BODY);
    crced.crc16 = 0xDEAD;
    crced.crc_length = 8;

    assert_eq!(
        plain.initial_bytes, crced.initial_bytes,
        "i due pattern devono differire solo per il CRC"
    );
    let found_plain = scan_for(std::slice::from_ref(&plain), BODY).len();
    let found_crced = scan_for(std::slice::from_ref(&crced), BODY).len();
    assert!(
        found_plain > found_crced,
        "atteso che il CRC riduca i match: {found_plain} vs {found_crced}"
    );
}
