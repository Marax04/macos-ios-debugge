//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_flirt_apply::crc16_flirt;
use rustre_flirt_apply::disambig::{Disambiguator, MatchResolution};
use rustre_flirt_apply::FlirtPattern;

/// `55 8B EC 83` (a classic x86 prologue) followed by a four-byte CRC region.
fn pattern_with_crc() -> FlirtPattern {
    let mut p = FlirtPattern::new(
        "memcpy".to_string(),
        vec![Some(0x55), Some(0x8B), Some(0xEC), Some(0x83)],
    );
    // `crc_offset` is ABSOLUTE from the start of the match. The producers in
    // `ida_sig_compat` store it as the pattern length, i.e. the offset just
    // past the pattern body — here 4.
    p.crc_offset = 4;
    p.crc_len = 4;
    p.crc = crc16_flirt(&[0xAA, 0xBB, 0xCC, 0xDD]);
    p
}

const DATA: [u8; 8] = [0x55, 0x8B, 0xEC, 0x83, 0xAA, 0xBB, 0xCC, 0xDD];

/// `Disambiguator::check_crc` and `FlirtApplier::scan_bytes` read `crc_offset`
/// differently: the first as an ABSOLUTE offset from the match start, the
/// second as relative to the end of the pattern body (`offset + pat_len +
/// crc_offset`). Only one can be right, and the producers decide it:
/// `ida_sig_compat` stores `crc_offset = bytes.len()`, i.e. absolute. The
/// second reading therefore counted the pattern length twice.
///
/// BLOCKED on a decision that is not mine to make. The evidence points to
/// ABSOLUTE — the producers write the field that way, and `check_crc` reads it
/// that way — but `scan_bytes` and its own passing test encode RELATIVE, so
/// either choice breaks a green test. Ignored rather than silently deciding.
#[test]
#[ignore = "crc_offset convention is inconsistent across the crate; awaiting a decision"]
fn the_crc_region_starts_after_the_pattern_body() {
    let patterns = vec![pattern_with_crc()];
    let d = Disambiguator::new(&patterns);

    match d.resolve(&DATA, 0) {
        MatchResolution::Unique(m) => {
            assert_eq!(m.name, "memcpy");
            assert!(
                m.crc_confirmed,
                "the CRC of AA BB CC DD matches, so the match is confirmed"
            );
        }
        other => panic!(
            "expected a unique, CRC-confirmed match; the CRC was computed over \
             the pattern bytes instead of the region after them. Got {other:?}"
        ),
    }
}

/// A pattern whose CRC does NOT match the following region must still be
/// rejected — the fix must not turn the check into a rubber stamp.
#[test]
#[ignore = "same crc_offset convention question as above"]
fn a_wrong_crc_still_rejects_the_match() {
    let mut p = pattern_with_crc();
    p.crc = p.crc.wrapping_add(1);
    let patterns = vec![p];
    let d = Disambiguator::new(&patterns);

    assert!(
        matches!(d.resolve(&DATA, 0), MatchResolution::None),
        "a CRC that does not match the data must not resolve"
    );
}

/// A pattern with no CRC region matches on bytes alone, and says so.
#[test]
fn a_pattern_without_a_crc_matches_on_bytes_alone() {
    let patterns = vec![FlirtPattern::new(
        "plain".to_string(),
        vec![Some(0x55), Some(0x8B), Some(0xEC), Some(0x83)],
    )];
    let d = Disambiguator::new(&patterns);

    match d.resolve(&DATA, 0) {
        MatchResolution::Unique(m) => {
            assert_eq!(m.name, "plain");
            assert!(!m.crc_confirmed, "there was no CRC region to confirm it");
        }
        other => panic!("expected a unique match, got {other:?}"),
    }
}

/// Truncated data must not be read past the end.
#[test]
#[ignore = "same crc_offset convention question as above"]
fn a_truncated_crc_region_does_not_resolve() {
    let patterns = vec![pattern_with_crc()];
    let d = Disambiguator::new(&patterns);
    // Only the pattern body is present; the CRC region is missing entirely.
    assert!(matches!(
        d.resolve(&DATA[..4], 0),
        MatchResolution::None
    ));
}
