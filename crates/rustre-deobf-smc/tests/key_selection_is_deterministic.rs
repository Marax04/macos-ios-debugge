//! `KeyDb` holds candidates in a `HashMap`, but every "which key wins" decision
//! ranked them by `confidence` alone — a `u8` in `[0, 100]`, so ties are the
//! norm rather than the exception.
//!
//! `sort_by` is stable and `max_by_key` returns the *last* maximum, so with ties
//! the winner was decided by `HashMap` iteration order, which Rust randomises
//! per process. For a key-recovery database that is the worst possible place for
//! it: `best()` claims to return "the most likely decryption key", and it
//! returned a **different key on each run**. Two runs over the same binary
//! disagreed, and neither could be reproduced.

use rustre_deobf_smc::key_recovery::{KeyAlgorithm, KeyCandidate, KeyDb};

/// Several candidates at the *same* confidence, so the tie-break is the only
/// thing deciding the answer.
fn tied_candidates() -> Vec<KeyCandidate> {
    vec![
        KeyCandidate::new(vec![0xAA; 16], KeyAlgorithm::Aes128, 80, 0x4000),
        KeyCandidate::new(vec![0xBB; 16], KeyAlgorithm::Aes128, 80, 0x1000),
        KeyCandidate::new(vec![0xCC; 16], KeyAlgorithm::Aes128, 80, 0x3000),
        KeyCandidate::new(vec![0xDD; 16], KeyAlgorithm::Aes128, 80, 0x2000),
    ]
}

fn db_from(order: &[usize]) -> KeyDb {
    let all = tied_candidates();
    let mut db = KeyDb::new();
    for &i in order {
        db.add(all[i].clone());
    }
    db
}

#[test]
fn the_best_key_does_not_depend_on_insertion_order() {
    // The decisive consequence: the same set of candidates, added in different
    // orders, must yield the same "most likely decryption key".
    let forward = db_from(&[0, 1, 2, 3]);
    let backward = db_from(&[3, 2, 1, 0]);
    let shuffled = db_from(&[2, 0, 3, 1]);

    let a = forward.best().expect("premise: a non-empty db has a best key");
    let b = backward.best().expect("premise: a non-empty db has a best key");
    let c = shuffled.best().expect("premise: a non-empty db has a best key");

    assert_eq!(
        a.key_bytes, b.key_bytes,
        "reversing the insertion order changed the recovered key"
    );
    assert_eq!(
        a.key_bytes, c.key_bytes,
        "shuffling the insertion order changed the recovered key"
    );

    // And it is the arithmetically determined winner: equal confidence, so the
    // lowest source address wins.
    assert_eq!(
        a.source_addr, 0x1000,
        "ties must resolve to the lowest source address, got {:#x}",
        a.source_addr
    );
}

#[test]
fn the_full_ranking_is_a_total_order() {
    let db = db_from(&[2, 0, 3, 1]);
    let sorted = db.all_sorted();

    assert_eq!(sorted.len(), 4, "premise: all four candidates are distinct entries");

    for w in sorted.windows(2) {
        let (a, b) = (w[0], w[1]);
        assert!(
            a.confidence > b.confidence
                || (a.confidence == b.confidence && a.source_addr < b.source_addr),
            "ranking is not a total order: (conf {}, {:#x}) precedes (conf {}, {:#x})",
            a.confidence, a.source_addr, b.confidence, b.source_addr
        );
    }
}

#[test]
fn a_genuinely_higher_confidence_still_wins() {
    // Premise: the tie-break has not replaced the ranking itself. The stronger
    // candidate sits at the *highest* address, so an address-only order would
    // rank it last.
    let mut db = KeyDb::new();
    for c in tied_candidates() {
        db.add(c);
    }
    db.add(KeyCandidate::new(
        vec![0xEE; 16],
        KeyAlgorithm::Aes128,
        95,
        0xF000,
    ));

    let best = db.best().expect("premise: the db is non-empty");
    assert_eq!(
        best.confidence, 95,
        "the highest-confidence key must win regardless of its address"
    );
    assert_eq!(best.source_addr, 0xF000);
}
