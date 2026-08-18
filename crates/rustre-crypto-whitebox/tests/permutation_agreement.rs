//! The crate's several permutation tests must give the same answer.
//!
//! Four places decide independently whether a byte table is a permutation of
//! `0..=255`: `aes_wb_analyzer::is_permutation_bytes`,
//! `BijectionSet::is_bijection`, `lookup_table_extractor::is_permutation`
//! (private, so covered by the crate's own tests), and
//! `Rc4WhiteboxDetector::is_permutation`. They gate whether a region of a binary
//! is reported as an S-box or an RC4 S-array, so two of them disagreeing means
//! one detector claims a table the other denies — with no way to tell which is
//! right from inside either.
//!
//! Three of them tested the length; the fourth did not, and so called an empty
//! slice a permutation of 0..=255.

use rustre_crypto_whitebox::aes_wb_analyzer::is_permutation_bytes;
use rustre_crypto_whitebox::bge_attacker::LookupTable;
use rustre_crypto_whitebox::whitebox_aes_full::BijectionSet;
use rustre_crypto_whitebox::Rc4WhiteboxDetector;

/// Every externally reachable checker, so a new one can be added to the list.
fn checkers() -> Vec<(&'static str, fn(&[u8]) -> bool)> {
    vec![
        ("aes_wb_analyzer::is_permutation_bytes", is_permutation_bytes),
        ("BijectionSet::is_bijection", BijectionSet::is_bijection),
        (
            "Rc4WhiteboxDetector::is_permutation",
            Rc4WhiteboxDetector::is_permutation,
        ),
    ]
}

/// The identity table is a permutation; all checkers must say so.
#[test]
fn the_identity_table_is_accepted_by_every_checker() {
    let identity: Vec<u8> = (0..=255u8).collect();
    for (name, f) in checkers() {
        assert!(f(&identity), "{name} rejected the identity permutation");
    }
}

/// A 256-byte table with one duplicate is not a permutation.
#[test]
fn a_duplicate_is_rejected_by_every_checker() {
    let mut table: Vec<u8> = (0..=255u8).collect();
    table[1] = 0; // 0 appears twice, 1 not at all
    for (name, f) in checkers() {
        assert!(!f(&table), "{name} accepted a table with a repeated byte");
    }
}

/// A slice that is not 256 bytes long cannot be a permutation of `0..=255`.
///
/// This is where the four disagreed: "no duplicates" is trivially true of an
/// empty slice, but an empty table is not an S-box.
#[test]
fn a_wrong_length_is_rejected_by_every_checker() {
    let short: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0, 1, 2],
        (0..=127u8).collect(),
        (0..=255u8).chain(0..=0).collect(), // 257 bytes
    ];

    for case in &short {
        for (name, f) in checkers() {
            assert!(
                !f(case),
                "{name} accepted a {}-byte slice as a permutation of 0..=255",
                case.len()
            );
        }
    }
}

/// All checkers agree on every case, whatever the answer.
///
/// Stated as agreement rather than as expected values, so it keeps holding if
/// the shared definition is ever deliberately changed — what must not happen is
/// the four drifting apart.
#[test]
fn the_checkers_never_disagree() {
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![7; 256],
        (0..=255u8).collect(),
        (0..=255u8).rev().collect(),
        (0..=255u8).map(|b| b ^ 0x5A).collect(),
    ];
    // A 256-byte table missing exactly one value, for each value.
    for missing in [0u8, 1, 128, 255] {
        let mut t: Vec<u8> = (0..=255u8).collect();
        t[missing as usize] = missing.wrapping_add(1);
        cases.push(t);
    }

    let mut disagreements = 0usize;
    let mut accepted = 0usize;

    for case in &cases {
        let answers: Vec<(&str, bool)> = checkers().iter().map(|(n, f)| (*n, f(case))).collect();
        let first = answers[0].1;
        if first {
            accepted += 1;
        }
        for (name, answer) in &answers {
            if *answer != first {
                // ⚠ `disagreements` was incremented and then never read,
                // because the `panic!` on the next line ends the test. The
                // counter promised an aggregate ("how many implementations
                // disagree") and delivered "the first disagreement, then
                // stop" — so a table where three implementations disagree
                // reported the same thing as one where a single one did.
                // The increment is kept and the count is now reported in the
                // panic message, which is what the variable was for.
                disagreements += 1;
                panic!(
                    "{name} says {answer} but {} says {first} for a {}-byte table                      ({disagreements} disagreement(s) seen on this table)",
                    answers[0].0,
                    case.len()
                );
            }
        }
    }

    assert_eq!(disagreements, 0);
    // Anti-vacuity: if nothing were ever accepted, agreement would be trivial.
    assert!(
        accepted >= 3,
        "only {accepted} of {} cases were accepted by any checker — the agreement \
         would hold without the checkers doing anything",
        cases.len()
    );
}

/// A permutation composed with its inverse is the identity, for every input.
///
/// `LookupTable::invert` documents its input as "must be a bijection" and returns
/// `Option` to enforce it. Both directions are checked: a permutation inverts and
/// round-trips exactly, and a table that is not a bijection is refused rather
/// than silently producing a wrong inverse.
#[test]
fn inverting_a_permutation_round_trips() {
    // 7 is odd, so `b * 7 + 3` (mod 256) is a bijection on the byte range.
    let data: [u8; 256] = std::array::from_fn(|i| {
        u8::try_from(i).unwrap_or(u8::MAX).wrapping_mul(7).wrapping_add(3)
    });
    assert!(
        is_permutation_bytes(&data),
        "the fixture is not a permutation, so the round-trip would prove nothing"
    );

    let table = LookupTable::new(data);
    let inverse = table.invert().expect("a permutation must be invertible");

    for b in 0..=255u8 {
        assert_eq!(
            inverse.apply(table.apply(b)),
            b,
            "inverse(table({b})) is not {b} — the inversion is not a true inverse"
        );
        assert_eq!(
            table.apply(inverse.apply(b)),
            b,
            "table(inverse({b})) is not {b} — inversion fails in the other direction"
        );
    }
}

/// A table that is not a bijection cannot be inverted, and says so.
#[test]
fn a_non_bijection_refuses_to_invert() {
    // Every entry maps to 0: maximally non-injective.
    assert!(
        LookupTable::new([0u8; 256]).invert().is_none(),
        "a constant table has no inverse but one was produced"
    );

    // One collision is enough.
    let mut data: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(u8::MAX));
    data[1] = 0;
    assert!(
        LookupTable::new(data).invert().is_none(),
        "a single repeated output must make the table non-invertible"
    );

    // The identity, by contrast, does invert — otherwise the two assertions
    // above would hold for a function that always returns `None`.
    assert!(
        LookupTable::identity().invert().is_some(),
        "the identity table must be invertible"
    );
}
