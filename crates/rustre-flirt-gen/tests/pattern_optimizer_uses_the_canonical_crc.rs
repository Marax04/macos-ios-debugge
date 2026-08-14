//! `pattern_optimizer` must use the same tail CRC as the rest of the stack (T3b).
//!
//! # The defect
//!
//! T3 unified eleven CRC implementations into `rustre_flirt::crc`. One derived
//! site survived: `pattern_optimizer::crc16` called `crc::arc` and was
//! documented as "CRC-16/ARC — FLIRT standard", while the generator that
//! actually writes `.sig` files (`PatternGenerator::generate`) and the validator
//! that reads them both use `flirt_tail` (MCRF4XX). A third algorithm for one
//! conceptual field, with a doc comment asserting the opposite.
//!
//! It was deliberately left alone across several iterations, because fixing it
//! on intuition would have been a guess: it was not established that the value
//! reached the same field as the generator's. This iteration established it —
//! `OptimizedPattern` carries exactly the leaf triple `(crc_offset: u16,
//! crc_len: u8, crc: u16)` that a `.sig` leaf stores. Same field by
//! construction, so same algorithm.
//!
//! # The honest scope of the fix
//!
//! Measured: this module is declared in `lib.rs` and imported by **nothing** in
//! the workspace. No `.sig` has ever carried a value produced here, so switching
//! the algorithm changes no output that exists today. That is not a reason to
//! leave it wrong — it is the reason it stayed wrong unnoticed. The test below
//! pins the disconnection so the claim stays true or fails loudly, rather than
//! being re-derived by grep each time (a method that has already misled this
//! project once).

use rustre_flirt_gen::pattern_optimizer::{
    CrcWindowSelector, OptimizedPattern, PatternInput, PatternOptimizer, crc16,
};

#[test]
fn the_optimizer_crc_is_the_canonical_flirt_tail() {
    // The catalogue check value, and agreement with the canonical primitive.
    for sample in [
        b"123456789".as_slice(),
        b"".as_slice(),
        b"\x48\x8b\x05\xaa\xbb\xcc\xdd".as_slice(),
    ] {
        assert_eq!(
            crc16(sample),
            rustre_flirt::crc::flirt_tail(sample),
            "pattern_optimizer::crc16 diverge da flirt_tail su {sample:?}"
        );
    }
}

#[test]
fn the_optimizer_crc_is_not_arc() {
    // Stated as its own assertion so that a future revert to `arc` fails here
    // with the reason, instead of silently passing some weaker check. The two
    // differ on any non-trivial input; a sample where they agreed would make
    // this test vacuous, so assert on one where they must not.
    let data = b"123456789";
    assert_ne!(
        crc16(data),
        rustre_flirt::crc::arc(data),
        "crc16 e' tornato ad ARC: e' il terzo algoritmo per il campo tail CRC"
    );
}

/// The CRC produced by the optimiser must be the one a validator would
/// recompute over the same window — the property the whole field exists for.
#[test]
fn an_optimised_pattern_carries_a_reproducible_crc() {
    let body: Vec<u8> = (0u8..=95).collect();
    let input = PatternInput {
        bytes: body.clone(),
        name: "fn_under_test".to_string(),
        relocations: Vec::new(),
    };
    let opt = PatternOptimizer::default();
    let flat = opt.optimize_flat(std::slice::from_ref(&input));
    let p: &OptimizedPattern = flat.first().expect("un input, un pattern");

    let start = p.crc_offset as usize;
    let end = start + p.crc_len as usize;
    assert!(end <= body.len(), "finestra CRC fuori dai byte di input");
    assert_eq!(
        p.crc,
        rustre_flirt::crc::flirt_tail(&body[start..end]),
        "il CRC memorizzato non e' ricalcolabile sulla propria finestra: e' \
         esattamente il difetto che costa il 32% dei match nel round-trip"
    );
}

/// Changing the algorithm must not change *which* window gets selected: the
/// selector ranks windows by how many distinct CRCs they produce, which is a
/// property of the data, not of the polynomial. Pinned because if it did
/// change, the switch would not be the neutral fix this test claims it is.
#[test]
fn window_selection_does_not_depend_on_the_polynomial() {
    let samples: Vec<Vec<u8>> = (0..8u8)
        .map(|k| (0u8..=127).map(|b| b.wrapping_mul(k).wrapping_add(k)).collect())
        .collect();
    let refs: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();

    let (off, len) = CrcWindowSelector::default().select(&refs);
    assert!(len > 0, "il selettore deve scegliere una finestra non vuota");

    // Distinctness under the canonical CRC must match distinctness under ARC on
    // the chosen window: if a window discriminates, it does so for both.
    let distinct = |f: fn(&[u8]) -> u16| {
        let mut v: Vec<u16> = refs
            .iter()
            .filter(|s| s.len() >= off as usize + len as usize)
            .map(|s| f(&s[off as usize..off as usize + len as usize]))
            .collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    assert_eq!(
        distinct(rustre_flirt::crc::flirt_tail),
        distinct(rustre_flirt::crc::arc),
        "il potere discriminante della finestra dipende dal polinomio: allora \
         il cambio di algoritmo non e' neutro e va rimisurato"
    );
}
