//! The matchers must agree on where a pattern matches (T5).
//!
//! # The question worth asking before choosing a winner
//!
//! T5 says to collapse four matchers and to "decide the winner with a
//! benchmark, not by eye". A benchmark ranks them by speed — but speed only
//! matters among implementations that give the *same answer*. Two matchers that
//! disagree about where a pattern occurs cannot both be right, and picking the
//! faster of a right one and a wrong one is worse than picking either.
//!
//! So this measures agreement first, on the primitive all of them express in
//! some form: given a pattern with wildcards and a buffer, at which offsets does
//! it match?
//!
//! The comparison is against `FlirtScanner`, the matcher on the shipping path —
//! not against a reference invented here. That mistake is on record: an earlier
//! test in this project hand-modelled the generator's CRC and measured the model
//! instead of the component.
//!
//! Wildcards get the attention because they are where this stack has already
//! been wrong twice: the `.sig` container discards them entirely, and a shifted
//! wildcard changes which bytes are compared without changing anything visible.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte, signature_matcher::PatternMatcher};

/// A 16-byte pattern over `0x40..0x4F`, with wildcards at `wc`.
fn pattern_with_wildcards(wc: &[usize]) -> Vec<PatternByte> {
    (0u8..16)
        .map(|i| {
            if wc.contains(&(i as usize)) {
                PatternByte::Wildcard
            } else {
                PatternByte::Exact(0x40u8.wrapping_add(i))
            }
        })
        .collect()
}

/// A haystack containing the pattern's concrete bytes at a known offset, with
/// the wildcard positions filled with bytes that differ from the original — so a
/// matcher that ignores the mask and compares exact bytes will *fail* to match,
/// and one that honours it will succeed. A haystack built from the original
/// bytes could not tell the two apart.
fn haystack_with_match_at(offset: usize, wc: &[usize]) -> Vec<u8> {
    let mut hay = vec![0u8; offset];
    for i in 0u8..16 {
        let b = if wc.contains(&(i as usize)) {
            0xFF ^ i // deliberately not the pattern's byte
        } else {
            0x40u8.wrapping_add(i)
        };
        hay.push(b);
    }
    hay.extend_from_slice(&[0u8; 24]);
    hay
}

/// Where the shipping scanner says the pattern matches.
fn scanner_offsets(bytes: &[PatternByte], hay: &[u8]) -> Vec<usize> {
    let mut p = FlirtPattern::new(bytes.to_vec());
    p.pattern_length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    p.names.push(FlirtName {
        offset: 0,
        name: "probe".to_string(),
        is_public: true,
        is_local: false,
    });

    let sig = rustre_flirt_gen::SigWriter::default().build(std::slice::from_ref(&p), "probe");
    let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
        return Vec::new();
    };
    let mut offs: Vec<usize> = scanner
        .scan_fast(hay, 0)
        .into_iter()
        .map(|m| usize::try_from(m.address).unwrap_or(usize::MAX))
        .collect();
    offs.sort_unstable();
    offs.dedup();
    offs
}

#[test]
fn an_exact_pattern_is_found_at_the_same_offset_by_both() {
    // The control. If the two disagree even here, the comparison below says
    // nothing about wildcards specifically.
    let bytes = pattern_with_wildcards(&[]);
    let hay = haystack_with_match_at(8, &[]);

    let matcher = PatternMatcher::find_all(&bytes, &hay);
    assert_eq!(matcher, vec![8], "PatternMatcher non trova il match esatto");

    let scanner = scanner_offsets(&bytes, &hay);
    assert_eq!(scanner, vec![8], "lo scanner di produzione non trova il match esatto");
}

/// The measurement that matters: with wildcards, the haystack differs from the
/// pattern's own bytes at exactly the masked positions.
#[test]
fn a_wildcarded_pattern_matches_where_the_mask_allows() {
    let wc = [3usize, 4, 5, 6];
    let bytes = pattern_with_wildcards(&wc);
    let hay = haystack_with_match_at(8, &wc);

    let matcher = PatternMatcher::find_all(&bytes, &hay);
    assert_eq!(
        matcher,
        vec![8],
        "PatternMatcher non onora la maschera: i byte mascherati differiscono \
         dall'originale, ed e' esattamente cio' che un wildcard deve permettere"
    );
}

/// Both matchers on the same input — they agree, and the agreement is
/// misleading.
///
/// I predicted the scanner would find nothing here, because the `.sig` container
/// truncates a wildcarded pattern at its first wildcard. It finds the match at
/// offset 8 anyway — on the surviving **3-byte** prefix, not on the 16-byte
/// pattern. Same offset, entirely different evidence.
///
/// So "the matchers agree" is true and worthless on this input, which is exactly
/// why the next test exists: it separates them by asking where the 3-byte prefix
/// occurs *without* the rest of the pattern.
#[test]
fn the_two_matchers_agree_but_not_for_the_same_reason() {
    let wc = [3usize, 4, 5, 6];
    let bytes = pattern_with_wildcards(&wc);
    let hay = haystack_with_match_at(8, &wc);

    assert_eq!(PatternMatcher::find_all(&bytes, &hay), vec![8]);
    assert_eq!(scanner_offsets(&bytes, &hay), vec![8]);
}

/// The false positive this test was built to expose is **gone** (iteration 53).
///
/// Written one iteration earlier, it asserted the defect: with only the 3-byte
/// prefix present and the rest of the pattern contradicted, `PatternMatcher`
/// correctly said no while the scanner — holding a 3-byte key left by the
/// container's truncation — said yes at offset 8. A false positive in five
/// lines, the same shape as the 5 measured on a Go binary cross-binary.
///
/// The leaf now carries a masked tail, so the scanner holds all 16 bytes and
/// agrees. Kept, inverted, as the regression guard: if the container ever goes
/// back to discarding wildcards, this is the cheapest place it shows up.
#[test]
fn neither_matcher_matches_on_the_prefix_alone() {
    let wc = [3usize, 4, 5, 6];
    let bytes = pattern_with_wildcards(&wc);

    // Prefix present (0x40 0x41 0x42), everything after it wrong.
    let mut hay = vec![0u8; 8];
    hay.extend_from_slice(&[0x40, 0x41, 0x42]);
    hay.extend_from_slice(&[0x00; 32]);

    assert!(
        PatternMatcher::find_all(&bytes, &hay).is_empty(),
        "PatternMatcher combacia su un buffer che contraddice il pattern: \
         starebbe ignorando i byte oltre il prefisso"
    );
    assert!(
        scanner_offsets(&bytes, &hay).is_empty(),
        "lo scanner di produzione combacia di nuovo sul solo prefisso: il \
         container avrebbe ripreso a scartare i wildcard, e con esso tornerebbero \
         i falsi positivi misurati cross-binario"
    );
}

/// A pattern that is absent must be found nowhere — the direction of error that
/// produces false positives, which this corpus has measured at 5 on a foreign
/// binary.
#[test]
fn neither_matcher_invents_a_match() {
    let bytes = pattern_with_wildcards(&[]);
    let hay = vec![0xAAu8; 64];

    assert!(
        PatternMatcher::find_all(&bytes, &hay).is_empty(),
        "PatternMatcher inventa un match"
    );
    assert!(
        scanner_offsets(&bytes, &hay).is_empty(),
        "lo scanner di produzione inventa un match"
    );
}
