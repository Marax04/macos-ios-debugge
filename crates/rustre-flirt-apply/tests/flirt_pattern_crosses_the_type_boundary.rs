//! What survives when a pattern crosses between the two `FlirtPattern`s (T29/T37).
//!
//! # The duplicate, and why this one is not cosmetic
//!
//! `FlirtPattern` is declared twice, modelling the same concept with different
//! shapes:
//!
//! | | `rustre-flirt` | `rustre-flirt-apply` |
//! |---|---|---|
//! | bytes | `initial_bytes: Vec<PatternByte>` | `bytes: Vec<Option<u8>>` |
//! | CRC window start | **implicit**: after the initial bytes | `crc_offset: u16` |
//! | CRC window length | `crc_length: u8` | `crc_len: u16` |
//! | names | `names: Vec<FlirtName>` | `name` + `public_names` + `local_names` |
//!
//! Unlike the harmless cross-crate name collisions counted in
//! `duplicate_types_ranked_by_divergence.rs`, values really do cross between
//! these two: the generator builds the first, `SigWriter` serialises it,
//! `load_sig_file` reads it back as a `FlirtSignature`, and
//! `FlirtPattern::from_signature` reconstructs the second. The `.sig` file is
//! the bridge, and a bridge between two disagreeing models is where information
//! gets dropped.
//!
//! One difference is load-bearing. The generator has no `crc_offset` because it
//! always places the window immediately after the initial bytes; the apply side
//! stores that position explicitly. If the crossing does not reconstruct it, the
//! scanner hashes the wrong bytes — which is exactly the failure already
//! measured in the round-trip, where clearing the CRC field took self-match from
//! 65.2% to 97.0%.
//!
//! These tests measure what the crossing preserves. They do not merge the two
//! types; merging is a breaking change across three crates and needs its own
//! iteration. They establish which fields a merge would have to be careful
//! about, and pin the ones that already work so a merge cannot quietly break
//! them.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

const BODY: &[u8] = &[
    0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48, 0x89, 0xC7, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48,
    0x83, 0xC4, 0x28, 0x5B, 0x5D, 0x41, 0x5C, 0x41, 0x5D, 0xC3, 0x90, 0x66, 0x0F, 0x1F, 0x44, 0x00,
];

/// A generator-side pattern over the first `prefix` bytes of `BODY`, declaring a
/// CRC of `crc_length` bytes — which, on this side, means "the bytes right after
/// the prefix".
fn generator_pattern(name: &str, prefix: usize, crc_length: u8) -> FlirtPattern {
    let mut p = FlirtPattern::new(
        BODY[..prefix].iter().map(|b| PatternByte::Exact(*b)).collect(),
    );
    p.crc_length = crc_length;
    p.crc16 = rustre_flirt::crc::flirt_tail(&BODY[prefix..prefix + usize::from(crc_length)]);
    p.pattern_length = u16::try_from(BODY.len()).unwrap_or(u16::MAX);
    p.names.push(FlirtName {
        offset: 0,
        name: name.to_string(),
        is_public: true,
        is_local: false,
    });
    p
}

/// Cross the boundary along the real path: generator type → `SigWriter` → `.sig`
/// on disk → `load_sig_file` → `FlirtSignature` → `FlirtPattern::from_signature`.
///
/// Every hop is a public entry point, so this measures the crossing the stack
/// actually performs rather than a shortcut invented for the test — the mistake
/// recorded in `self_match_round_trip.rs`, where a hand-written model of the
/// generator was measured instead of the generator.
fn cross(pats: &[FlirtPattern], tag: &str) -> Vec<rustre_flirt_apply::FlirtPattern> {
    let sig = rustre_flirt_gen::SigWriter::default().build(pats, "crossing");

    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let sig_path = std::path::Path::new(&dir).join(format!("rustre_crossing_{tag}.sig"));
    std::fs::write(&sig_path, &sig).expect("scrittura del .sig temporaneo");

    let sigs = rustre_flirt_apply::load_sig_file(&sig_path).expect("il .sig deve essere leggibile");
    let _ = std::fs::remove_file(&sig_path);

    sigs.iter()
        .map(rustre_flirt_apply::FlirtPattern::from_signature)
        .collect()
}

#[test]
fn the_name_survives_the_crossing() {
    // The minimum a signature must carry. If this broke, nothing downstream
    // would mean anything.
    let crossed = cross(&[generator_pattern("crossing_fn", 16, 8)], "name");
    let p = crossed.first().expect("un pattern attraversato");
    assert_eq!(p.name, "crossing_fn");
}

/// The `.sig` container now carries wildcards, and this test records the change.
///
/// It was written to pin the opposite. `SigWriter::build` used to take the
/// prefix with `take_while(PatternByte::Exact)` and throw the rest away, so a
/// 16-byte pattern with wildcards at 3..7 crossed as a **3-byte** pattern with
/// no wildcards. Measured then: `p.bytes.len() == 3`.
///
/// Iteration 53 gave the leaf a masked tail (control byte `0x02`): the trie is
/// still keyed on concrete bytes, but everything after the key travels with a
/// mask. Measured now: the full 16 bytes cross, with the wildcards at their
/// original offsets.
///
/// The effect on the numbers this project tracks, all re-measured:
/// self-match 65.2% → **73.5%**, and on the wildcarded subset alone
/// 11.5% → **53.8%**; cross-binary false positives on a Go binary
/// 5 → **0**, at every threshold including none.
#[test]
fn the_container_now_carries_wildcards_through_the_crossing() {
    let mut src = generator_pattern("wc_fn", 16, 8);
    for i in [3usize, 4, 5, 6] {
        src.initial_bytes[i] = PatternByte::Wildcard;
    }
    let crossed = cross(std::slice::from_ref(&src), "wc");
    let p = crossed.first().expect("un pattern attraversato");

    assert_eq!(
        p.bytes.len(),
        16,
        "attesi 16 byte attraversati (prima erano 3, troncati al primo wildcard)"
    );
    let wc: Vec<usize> = p
        .bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| b.is_none())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        wc,
        vec![3, 4, 5, 6],
        "i wildcard devono sopravvivere ai loro offset originali"
    );
}

/// `crc_offset` crosses as **0**, meaning "relative to the end of the pattern" —
/// and that is only correct for one of its two consumers.
///
/// This test first asserted `crc_offset == prefix`, i.e. the absolute
/// convention. It failed, and the failure was mine, not the code's: `scan_fast`
/// reads `crc_offset` as relative (`offset + pat_len + crc_offset`), so 0 is
/// exactly right there.
///
/// But the crate already carries a `KNOWN INCONSISTENCY` note at that very site:
/// `Disambiguator::check_crc` reads the same field as **absolute** from the
/// match start, and the producers in `ida_sig_compat` write it as absolute
/// (`bytes.len()`). Two of the three say absolute; the crossing produces the
/// relative one. So a value that validates under `scan_fast` hashes the pattern's
/// own first bytes under `Disambiguator`.
///
/// Pinned as measured rather than corrected: picking a convention changes which
/// existing tests pass, each convention has its own, and that is a decision
/// about intended semantics rather than a defect with one right answer.
#[test]
fn the_crc_offset_crosses_as_relative_zero() {
    for prefix in [8usize, 16, 24] {
        let crossed = cross(
            &[generator_pattern("off_fn", prefix, 4)],
            &format!("off{prefix}"),
        );
        let p = crossed.first().expect("un pattern attraversato");
        assert_eq!(
            p.crc_offset, 0,
            "atteso 0 (convenzione relativa, quella di scan_fast) con {prefix} \
             byte iniziali: se ora arriva {prefix} qualcuno ha scelto la \
             convenzione assoluta, e va aggiornato anche scan_fast"
        );
    }
}

/// The property that actually matters: under the convention its own scanner
/// uses, the crossed window must select the bytes the generator hashed.
/// Offsets are a means; this is the end.
#[test]
fn the_crossed_window_selects_the_bytes_the_generator_hashed() {
    let prefix = 16usize;
    let len = 4u8;
    let src = generator_pattern("win_fn", prefix, len);
    // A distinct tag per call site: the tests run in parallel threads and share
    // the temp directory, so a reused name is a race, not a detail.
    let crossed = cross(std::slice::from_ref(&src), "window");
    let p = crossed.first().expect("un pattern attraversato");

    // `scan_fast`'s rule: start = match_start + pattern_len + crc_offset. Here
    // the match starts at 0 and the pattern is the full `prefix`.
    let start = prefix + usize::from(p.crc_offset);
    let end = start + usize::from(p.crc_len);
    assert!(end <= BODY.len(), "finestra fuori dal corpo della funzione");
    assert_eq!(
        rustre_flirt::crc::flirt_tail(&BODY[start..end]),
        src.crc16,
        "la finestra ricostruita seleziona byte diversi da quelli su cui il \
         generatore ha calcolato il CRC"
    );
}
