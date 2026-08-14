//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.
//!
//! All three defects share a shape: a fast path disagrees with the slow path
//! that is already correct. `matches` honours nibble wildcards and `search`
//! does not; `scan` finds a match that `scan_parallel` misses. The fix in each
//! case is to make the fast path agree with the twin, not to reimplement it.

use rustre_hex_pattern::multi_pattern_scanner::MultiPatternScanner;
use rustre_hex_pattern::pattern_optimizer::PatternOptimizer;
use rustre_hex_pattern::Pattern;

// ── nibble wildcards were invisible to search() ────────────────────────────

/// `search` anchors on the first `PatternByte::Exact`. A pattern made only of
/// NIBBLE constraints ("4? 1?") has none, so it falls into the
/// "all wildcards — every position matches" branch and reports a match at every
/// offset, on data that satisfies neither nibble.
///
/// `matches(&data, 0)` on the very same input already returns false: the two
/// entry points disagree about what the pattern means.
#[test]
fn a_nibble_pattern_does_not_match_everything() {
    let p = Pattern::parse("4? 1?").unwrap();
    let data = [0x00, 0x00, 0x00, 0x00];

    assert!(
        !p.matches(&data, 0),
        "0x00 has neither high nibble 4 nor high nibble 1"
    );
    assert_eq!(
        p.search(&data),
        Vec::<usize>::new(),
        "search must agree with matches; it reported phantom hits"
    );
}

/// The same phantom matches reach `MultiPatternScanner`, which routes nibble
/// patterns to the wildcard bucket.
#[test]
fn the_scanner_reports_no_phantom_nibble_matches() {
    let mut s = MultiPatternScanner::new();
    s.add_pattern(Pattern::parse("4? 1?").unwrap());
    let r = s.scan(&[0x00, 0x00, 0x00, 0x00]);
    assert!(
        r.matches.is_empty(),
        "phantom matches: {:?}",
        r.matches.iter().map(|m| m.offset).collect::<Vec<_>>()
    );
}

/// A nibble pattern must still find what it really matches.
#[test]
fn a_nibble_pattern_still_finds_a_real_match() {
    let p = Pattern::parse("4? 1?").unwrap();
    //                       0x41 0x12 — high nibbles 4 and 1
    let data = [0x00, 0x41, 0x12, 0x00];
    assert_eq!(p.search(&data), vec![1]);
}

/// Full wildcards must keep matching every position, as before.
#[test]
fn an_all_wildcard_pattern_still_matches_everywhere() {
    let p = Pattern::parse("?? ??").unwrap();
    let data = [0x00, 0x11, 0x22, 0x33];
    assert_eq!(p.search(&data), vec![0, 1, 2]);
}

// ── the optimizer skipped past a real match ───────────────────────────────

/// With "AA BB ?? ??" the optimizer anchors on (index 1, 0xBB). Scanning
/// `11 AA BB 00 00` it tests i = 1, finds data[1] = 0xAA != 0xBB, then computes
/// a skip from a window that contains only 0x00 — a byte with no occurrence in
/// the pattern — and jumps forward by the full pattern length. Offset 1, where
/// the pattern really matches, is never tested at all.
#[test]
fn the_optimizer_finds_the_match_the_plain_search_finds() {
    let p = Pattern::parse("AA BB ?? ??").unwrap();
    let data = [0x11, 0xAA, 0xBB, 0x00, 0x00];

    assert_eq!(p.search(&data), vec![1], "the plain search is the reference");

    let op = PatternOptimizer::new().optimize(&p);
    assert!(op.matches(&data, 1), "the optimized form agrees at offset 1");
    assert_eq!(
        op.search(&data),
        vec![1],
        "but its search skipped straight past that offset"
    );
}

/// The optimizer must not start inventing matches either.
#[test]
fn the_optimizer_reports_nothing_when_there_is_nothing() {
    let p = Pattern::parse("AA BB ?? ??").unwrap();
    let data = [0x11, 0x22, 0x33, 0x44, 0x55];
    let op = PatternOptimizer::new().optimize(&p);
    assert_eq!(op.search(&data), Vec::<usize>::new());
}

// ── parallel scanning lost matches on chunk boundaries ────────────────────

/// `scan_parallel` splits the input into independent chunks. A match that
/// straddles a boundary belongs to no chunk, so it is lost: here the two bytes
/// sit at 63 and 64 with a chunk size of 64.
///
/// Adjacent chunks must overlap by `pattern_len - 1` bytes. `scan` on the same
/// data is the reference answer.
#[test]
fn a_match_across_a_chunk_boundary_is_not_lost() {
    let mut data = vec![0u8; 128];
    data[63] = 0xAA;
    data[64] = 0xBB;

    let mut s = MultiPatternScanner::new();
    s.add_pattern(Pattern::parse("AA BB").unwrap());
    let sequential = s.scan(&data);
    assert_eq!(sequential.matches.len(), 1, "the sequential scan is the reference");
    assert_eq!(sequential.matches[0].offset, 63);

    let mut s2 = MultiPatternScanner::new();
    s2.add_pattern(Pattern::parse("AA BB").unwrap());
    let parallel = s2.scan_parallel(&data, 64);
    assert_eq!(
        parallel.matches.len(),
        1,
        "the match at 63..65 straddles the boundary at 64 and was dropped"
    );
    assert_eq!(parallel.matches[0].offset, 63);
}

/// Overlapping the chunks must not produce the same match twice.
#[test]
fn a_match_inside_one_chunk_is_reported_once() {
    let mut data = vec![0u8; 128];
    data[10] = 0xAA;
    data[11] = 0xBB;

    let mut s = MultiPatternScanner::new();
    s.add_pattern(Pattern::parse("AA BB").unwrap());
    let r = s.scan_parallel(&data, 64);
    assert_eq!(r.matches.len(), 1, "duplicated by the overlap: {:?}", r.matches);
    assert_eq!(r.matches[0].offset, 10);
}
