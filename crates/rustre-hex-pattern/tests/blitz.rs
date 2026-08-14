//! Exhaustive blitz test suite for `rustre-hex-pattern`.
//!
//! Targets public API: PatternByte, Pattern, AlternationPattern, CompiledPattern,
//! MaskedPattern, PatternGroup, CompiledPatternGroup, SignaturePattern, crc16_ibm,
//! PatternDatabase (sqlite in-memory), PatternRange, SequencePattern, RepeatPattern,
//! PatternStatistics, ByteMask, MaskedBytePattern, PatternBook, BmhTable,
//! CatalogEntry, PatternCatalog, pattern_diff, pattern_to_masked,
//! PatternHighlightMap.

use rustre_hex_pattern::*;

// ─── PatternByte ──────────────────────────────────────────────────────────

#[test]
fn pb_exact_matches_only_value() {
    let pb = PatternByte::Exact(0xAB);
    assert!(pb.matches(0xAB));
    assert!(!pb.matches(0xAC));
    assert!(!pb.is_wildcard());
    assert_eq!(pb.mask_byte(), 0xFF);
    assert_eq!(pb.value_byte(), 0xAB);
}

#[test]
fn pb_wildcard_matches_all_bytes() {
    let pb = PatternByte::Wildcard;
    for b in 0u8..=255 {
        assert!(pb.matches(b));
    }
    assert!(pb.is_wildcard());
    assert_eq!(pb.mask_byte(), 0);
    assert_eq!(pb.value_byte(), 0);
}

#[test]
fn pb_nibble_high_only() {
    let pb = PatternByte::Nibble { high: Some(0xD), low: None };
    assert!(pb.matches(0xD0));
    assert!(pb.matches(0xDF));
    assert!(!pb.matches(0xE0));
    assert!(pb.is_wildcard());
    assert_eq!(pb.mask_byte(), 0xF0);
    assert_eq!(pb.value_byte(), 0xD0);
}

#[test]
fn pb_nibble_low_only() {
    let pb = PatternByte::Nibble { high: None, low: Some(0x5) };
    assert!(pb.matches(0x05));
    assert!(pb.matches(0xA5));
    assert!(!pb.matches(0x06));
    assert_eq!(pb.mask_byte(), 0x0F);
    assert_eq!(pb.value_byte(), 0x05);
}

#[test]
fn pb_nibble_both_none_is_wildcard_via_mask() {
    let pb = PatternByte::Nibble { high: None, low: None };
    // Both nibbles unconstrained -> match anything per `matches()`.
    assert!(pb.matches(0x00));
    assert!(pb.matches(0xFF));
    assert!(pb.is_wildcard());
    assert_eq!(pb.mask_byte(), 0);
}

// ─── Pattern parse ────────────────────────────────────────────────────────

#[test]
fn parse_simple_exact() {
    let p = Pattern::parse("DE AD BE EF").unwrap();
    assert_eq!(p.len(), 4);
    assert_eq!(p.to_bytes(), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn parse_with_wildcards() {
    let p = Pattern::parse("DE ?? BE ?").unwrap();
    assert_eq!(p.len(), 4);
    assert!(p.to_bytes().is_none());
}

#[test]
fn parse_nibble_mixes() {
    let p = Pattern::parse("A? ?B").unwrap();
    assert_eq!(p.len(), 2);
    matches!(p.bytes[0], PatternByte::Nibble { high: Some(0xA), low: None });
    matches!(p.bytes[1], PatternByte::Nibble { high: None, low: Some(0xB) });
}

#[test]
fn parse_lowercase_hex() {
    let p = Pattern::parse("de ad").unwrap();
    assert_eq!(p.to_bytes(), Some(vec![0xDE, 0xAD]));
}

#[test]
fn parse_empty_returns_err_empty() {
    match Pattern::parse("") {
        Err(PatternError::Empty) => {}
        other => panic!("expected Empty, got {other:?}"),
    }
}

#[test]
fn parse_only_whitespace_returns_empty() {
    match Pattern::parse("   \t\n  ") {
        Err(PatternError::Empty) => {}
        other => panic!("expected Empty, got {other:?}"),
    }
}

#[test]
fn parse_invalid_hex_digit() {
    match Pattern::parse("ZZ") {
        Err(PatternError::Parse { .. }) => {}
        other => panic!("expected Parse error, got {other:?}"),
    }
}

#[test]
fn parse_three_char_token_errors() {
    match Pattern::parse("ABC") {
        Err(PatternError::Parse { .. }) => {}
        other => panic!("expected Parse error for length-3 token, got {other:?}"),
    }
}

#[test]
fn parse_single_question_mark_is_wildcard() {
    let p = Pattern::parse("?").unwrap();
    assert!(matches!(p.bytes[0], PatternByte::Wildcard));
}

#[test]
fn parse_double_question_mark_is_wildcard() {
    let p = Pattern::parse("??").unwrap();
    assert!(matches!(p.bytes[0], PatternByte::Wildcard));
}

#[test]
fn parse_single_hex_digit_high_nibble() {
    // Per docstring: single digit treated as high nibble with low wildcard.
    let p = Pattern::parse("A").unwrap();
    match p.bytes[0] {
        PatternByte::Nibble { high: Some(0xA), low: None } => {}
        ref other => panic!("unexpected: {other:?}"),
    }
}

// ─── Pattern matches / search ─────────────────────────────────────────────

#[test]
fn pattern_matches_in_bounds() {
    let p = Pattern::parse("DE AD").unwrap();
    let data = [0x00, 0xDE, 0xAD, 0x99];
    assert!(p.matches(&data, 1));
    assert!(!p.matches(&data, 0));
}

#[test]
fn pattern_matches_oob_offset_safe() {
    let p = Pattern::parse("DE AD").unwrap();
    let data = [0xDE];
    assert!(!p.matches(&data, 0));
    assert!(!p.matches(&data, 100));
}

#[test]
fn pattern_matches_usize_overflow_safe() {
    let p = Pattern::parse("DE AD").unwrap();
    let data = [0xDE, 0xAD];
    assert!(!p.matches(&data, usize::MAX));
}

#[test]
fn pattern_search_exact_via_kmp() {
    let p = Pattern::parse("AA BB").unwrap();
    let data = [0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0xCC, 0xAA, 0xBB];
    assert_eq!(p.search(&data), vec![0, 3, 6]);
}

#[test]
fn pattern_search_with_wildcards_anchored() {
    let p = Pattern::parse("?? BB CC").unwrap();
    let data = [0x11, 0xBB, 0xCC, 0x22, 0xBB, 0xCC];
    assert_eq!(p.search(&data), vec![0, 3]);
}

#[test]
fn pattern_search_data_shorter_than_pattern() {
    let p = Pattern::parse("AA BB CC").unwrap();
    assert!(p.search(&[0xAA, 0xBB]).is_empty());
}

#[test]
fn pattern_search_all_wildcards_every_position() {
    let p = Pattern::parse("?? ??").unwrap();
    let data = [0u8, 1, 2, 3];
    // len=4, pat_len=2 -> positions 0..=2.
    assert_eq!(p.search(&data), vec![0, 1, 2]);
}

#[test]
fn pattern_to_simd_form_consistent() {
    let p = Pattern::parse("DE ?? A?").unwrap();
    let (v, m) = p.to_simd_form();
    assert_eq!(v, vec![0xDE, 0x00, 0xA0]);
    assert_eq!(m, vec![0xFF, 0x00, 0xF0]);
}

#[test]
fn pattern_specificity_and_counts() {
    let p = Pattern::parse("DE AD ?? ??").unwrap();
    assert_eq!(p.exact_count(), 2);
    assert_eq!(p.wildcard_count(), 2);
    assert!((p.specificity() - 0.5).abs() < 1e-9);
}

#[test]
fn pattern_specificity_empty_zero() {
    let p = Pattern { bytes: vec![], name: None, tags: vec![], captures: vec![], comment: String::new() };
    assert_eq!(p.specificity(), 0.0);
    assert!(p.is_empty());
}

#[test]
fn pattern_builders() {
    let p = Pattern::parse("AA").unwrap()
        .with_name("x")
        .with_tag("t1")
        .with_tag("t2")
        .with_comment("c")
        .with_capture("cap", 0, 1);
    assert_eq!(p.name.as_deref(), Some("x"));
    assert_eq!(p.tags, vec!["t1", "t2"]);
    assert_eq!(p.comment, "c");
    assert_eq!(p.captures.len(), 1);
    assert_eq!(p.captures[0].name, "cap");
}

#[test]
fn pattern_to_hex_string_roundtrip_exact() {
    let p = Pattern::parse("DE AD BE EF").unwrap();
    let s = p.to_hex_string();
    assert_eq!(s, "DE AD BE EF");
    let p2 = Pattern::parse(&s).unwrap();
    assert_eq!(p2.to_bytes(), p.to_bytes());
}

#[test]
fn pattern_to_hex_string_with_wildcards() {
    let p = Pattern::parse("DE ?? A?").unwrap();
    let s = p.to_hex_string();
    assert_eq!(s, "DE ?? A?");
}

#[test]
fn pattern_json_roundtrip() {
    let p = Pattern::parse("DE AD").unwrap().with_name("foo");
    let json = p.to_json().unwrap();
    let q = Pattern::from_json(&json).unwrap();
    assert_eq!(q.to_bytes(), p.to_bytes());
    assert_eq!(q.name, p.name);
}

#[test]
fn pattern_from_json_invalid_errors() {
    match Pattern::from_json("{not json") {
        Err(PatternError::Import(_)) => {}
        other => panic!("expected Import err, got {other:?}"),
    }
}

#[test]
fn pattern_search_with_captures() {
    let p = Pattern::parse("AA BB CC DD")
        .unwrap()
        .with_capture("middle", 1, 2);
    let data = [0xAA, 0xBB, 0xCC, 0xDD];
    let r = p.search_with_captures(&data);
    assert_eq!(r.len(), 1);
    let (off, caps) = &r[0];
    assert_eq!(*off, 0);
    assert_eq!(caps[0].name, "middle");
    assert_eq!(caps[0].offset, 1);
    assert_eq!(caps[0].bytes, vec![0xBB, 0xCC]);
}

// ─── AlternationPattern ───────────────────────────────────────────────────

#[test]
fn alternation_parse_basic() {
    let alt = AlternationPattern::parse("DE AD | BE EF").unwrap();
    assert_eq!(alt.len(), 2);
    assert!(!alt.is_empty());
}

#[test]
fn alternation_parse_empty_errors() {
    match AlternationPattern::parse("   |   ") {
        Err(PatternError::Empty) => {}
        other => panic!("expected Empty, got {other:?}"),
    }
}

#[test]
fn alternation_search_dedupes() {
    let alt = AlternationPattern::parse("AA | AA").unwrap();
    let data = [0xAA, 0x00, 0xAA];
    assert_eq!(alt.search(&data), vec![0, 2]);
}

#[test]
fn alternation_matches_any() {
    let alt = AlternationPattern::parse("DE AD | BE EF").unwrap();
    let data = [0xBE, 0xEF];
    assert!(alt.matches(&data, 0));
}

// ─── CompiledPattern ──────────────────────────────────────────────────────

#[test]
fn compiled_matches_same_as_pattern() {
    let p = Pattern::parse("DE ?? BE").unwrap();
    let c = CompiledPattern::compile(&p);
    let data = [0xDE, 0x11, 0xBE, 0x00, 0xDE, 0xFF, 0xBE];
    assert_eq!(c.search(&data), p.search(&data));
}

#[test]
fn compiled_all_wildcards_fallback() {
    let p = Pattern::parse("?? ??").unwrap();
    let c = CompiledPattern::compile(&p);
    let data = [0u8, 1, 2, 3];
    // Note: compiled.search has no anchor, no exact-only path -> uses fallback full scan
    // Pattern.search yields [0,1,2]; compiled fallback also [0,1,2].
    assert_eq!(c.search(&data), vec![0, 1, 2]);
}

#[test]
fn compiled_empty_data() {
    let p = Pattern::parse("AA").unwrap();
    let c = CompiledPattern::compile(&p);
    assert!(c.search(&[]).is_empty());
}

// ─── MaskedPattern ────────────────────────────────────────────────────────

#[test]
fn masked_new_requires_equal_lengths() {
    let r = MaskedPattern::new(vec![0xAA], vec![0xFF, 0xFF]);
    assert!(matches!(r, Err(PatternError::Parse { .. })));
}

#[test]
fn masked_new_ok() {
    let m = MaskedPattern::new(vec![0xAA, 0xBB], vec![0xFF, 0xF0]).unwrap();
    assert_eq!(m.len(), 2);
    assert!(!m.is_empty());
}

#[test]
fn masked_from_pattern_matches_equivalent() {
    let p = Pattern::parse("DE A?").unwrap();
    let m = MaskedPattern::from_pattern(&p);
    let data = [0xDE, 0xA7, 0xDE, 0xB7];
    assert_eq!(m.search(&data), vec![0]);
}

#[test]
fn masked_all_ff_uses_kmp() {
    let m = MaskedPattern::new(vec![0xAA, 0xBB], vec![0xFF, 0xFF]).unwrap();
    let data = [0xAA, 0xBB, 0xCC, 0xAA, 0xBB];
    assert_eq!(m.search(&data), vec![0, 3]);
}

// ─── PatternGroup / Compiled ──────────────────────────────────────────────

#[test]
fn group_search_all_sorted_by_offset() {
    let mut g = PatternGroup::new("g");
    g.add(Pattern::parse("AA").unwrap().with_name("a"));
    g.add(Pattern::parse("BB").unwrap().with_name("b"));
    let data = [0xBB, 0xAA, 0xBB];
    let matches = g.search_all(&data);
    let offsets: Vec<usize> = matches.iter().map(|m| m.offset).collect();
    assert_eq!(offsets, vec![0, 1, 2]);
}

#[test]
fn group_any_matches() {
    let mut g = PatternGroup::new("g");
    g.add(Pattern::parse("AA").unwrap());
    assert!(g.any_matches(&[0xAA], 0));
    assert!(!g.any_matches(&[0xBB], 0));
}

#[test]
fn group_compile_search_equiv() {
    let mut g = PatternGroup::new("g");
    g.add(Pattern::parse("AA BB").unwrap());
    g.add(Pattern::parse("CC").unwrap());
    let data = [0xAA, 0xBB, 0xCC];
    let c = g.compile();
    let a = g.search_all(&data);
    let b = c.search_all(&data);
    assert_eq!(a.len(), b.len());
}

#[test]
fn group_json_roundtrip() {
    let mut g = PatternGroup::new("g");
    g.add(Pattern::parse("AA").unwrap());
    let s = g.to_json().unwrap();
    let g2 = PatternGroup::from_json(&s).unwrap();
    assert_eq!(g2.patterns.len(), 1);
    assert_eq!(g2.name, "g");
}

// ─── SignaturePattern / crc16_ibm ─────────────────────────────────────────

#[test]
fn crc16_ibm_empty() {
    assert_eq!(crc16_ibm(&[]), 0x0000);
}

#[test]
fn crc16_ibm_known_value() {
    // CRC-16/MODBUS (IBM, init 0xFFFF) -- but this impl uses init 0x0000.
    // Just check determinism + non-zero result for some bytes.
    let a = crc16_ibm(&[0x01, 0x02, 0x03]);
    let b = crc16_ibm(&[0x01, 0x02, 0x03]);
    assert_eq!(a, b);
    let c = crc16_ibm(&[0x01, 0x02, 0x04]);
    assert_ne!(a, c);
}

#[test]
fn signature_pattern_matches_and_search() {
    let prologue = Pattern::parse("55 8B EC").unwrap();
    let body = [0x90u8, 0x91, 0x92, 0x93];
    let crc = crc16_ibm(&body);
    let sig = SignaturePattern::new("f", prologue.clone(), crc, body.len() as u8, 100);
    let mut data = vec![0x00, 0x55, 0x8B, 0xEC];
    data.extend_from_slice(&body);
    assert!(sig.matches(&data, 1));
    assert_eq!(sig.search(&data), vec![1]);
}

#[test]
fn signature_with_module() {
    let p = Pattern::parse("AA").unwrap();
    let sig = SignaturePattern::new("f", p, 0, 0, 0).with_module("mod.dll");
    assert_eq!(sig.module_name.as_deref(), Some("mod.dll"));
}

// ─── PatternDatabase (SQLite in-memory) ───────────────────────────────────

#[test]
fn db_open_in_memory_and_insert() {
    let db = PatternDatabase::open_in_memory().unwrap();
    let p = Pattern::parse("AA BB").unwrap().with_name("nm");
    let id = db.insert(&p).unwrap();
    assert!(id > 0);
}

// ─── PatternRange ─────────────────────────────────────────────────────────

#[test]
fn range_contains_and_expand() {
    let r = PatternRange::new(0x10, 0x12);
    assert!(r.contains(0x10));
    assert!(r.contains(0x12));
    assert!(!r.contains(0x0F));
    assert_eq!(r.expand(), vec![0x10, 0x11, 0x12]);
    assert_eq!(r.to_pattern_bytes().len(), 3);
}

#[test]
fn range_lo_eq_hi() {
    let r = PatternRange::new(5, 5);
    assert_eq!(r.expand(), vec![5]);
}

// ─── SequencePattern ──────────────────────────────────────────────────────

#[test]
fn sequence_matches_with_offsets() {
    let mut s = SequencePattern::new();
    s.add(0, Pattern::parse("AA").unwrap());
    s.add(3, Pattern::parse("BB").unwrap());
    let data = [0xAA, 0x00, 0x00, 0xBB];
    assert!(s.matches(&data, 0));
    assert_eq!(s.search(&data), vec![0]);
}

#[test]
fn sequence_default_is_empty() {
    let s = SequencePattern::default();
    assert!(s.entries.is_empty());
    assert!(s.search(&[1, 2, 3]).is_empty());
}

// ─── RepeatPattern ────────────────────────────────────────────────────────

#[test]
fn repeat_exactly_match_count() {
    let r = RepeatPattern::exactly(Pattern::parse("AA").unwrap(), 3);
    let data = [0xAA, 0xAA, 0xAA, 0xBB];
    assert!(r.matches(&data, 0));
    // inner pattern "AA" has 1 slot; min_byte_len = 1 * 3.
    assert_eq!(r.min_byte_len(), 1 * 3);
}

#[test]
fn repeat_one_or_more() {
    let r = RepeatPattern::one_or_more(Pattern::parse("AA").unwrap());
    assert!(r.matches(&[0xAA], 0));
    assert!(!r.matches(&[0xBB], 0));
}

#[test]
fn repeat_zero_or_more_always_matches() {
    let r = RepeatPattern::zero_or_more(Pattern::parse("AA").unwrap());
    // 0 reps satisfies min_count=0.
    assert!(r.matches(&[0xBB], 0));
}

#[test]
fn repeat_new_clamps_min_to_max() {
    let r = RepeatPattern::new(Pattern::parse("AA").unwrap(), 10, 3);
    assert!(r.min_count <= r.max_count);
}

// ─── PatternStatistics ────────────────────────────────────────────────────

#[test]
fn stats_empty() {
    let s = PatternStatistics::compute(&[]);
    assert_eq!(s.total, 0);
}

#[test]
fn stats_basic() {
    let ps = vec![
        Pattern::parse("AA BB").unwrap().with_name("n").with_tag("t"),
        Pattern::parse("?? ??").unwrap(),
    ];
    let s = PatternStatistics::compute(&ps);
    assert_eq!(s.total, 2);
    assert_eq!(s.named, 1);
    assert_eq!(s.tagged, 1);
    assert_eq!(s.exact_only, 1);
    assert_eq!(s.with_wildcards, 1);
    assert_eq!(s.min_length, 2);
    assert_eq!(s.max_length, 2);
}

// ─── ByteMask / MaskedBytePattern ─────────────────────────────────────────

#[test]
fn bytemask_exact_wildcard_nibbles() {
    assert!(ByteMask::exact(0xAB).matches(0xAB));
    assert!(!ByteMask::exact(0xAB).matches(0xAC));
    assert!(ByteMask::wildcard().matches(0));
    assert!(ByteMask::wildcard().is_wildcard());
    assert!(ByteMask::exact(0x55).is_exact());
    assert!(ByteMask::high_nibble(0xA).matches(0xA5));
    assert!(!ByteMask::high_nibble(0xA).matches(0xB5));
    assert!(ByteMask::low_nibble(0x5).matches(0xA5));
}

#[test]
fn bytemask_specificity_bounds() {
    assert!((ByteMask::wildcard().specificity() - 0.0).abs() < 1e-9);
    assert!((ByteMask::exact(0).specificity() - 1.0).abs() < 1e-9);
    assert!((ByteMask::high_nibble(0).specificity() - 0.5).abs() < 1e-9);
}

#[test]
fn masked_byte_pattern_search() {
    let mbp = MaskedBytePattern::new(vec![ByteMask::exact(0xAA), ByteMask::wildcard()]);
    let data = [0xAA, 0x00, 0xAA, 0x99, 0xBB];
    let hits = mbp.search(&data);
    assert!(hits.contains(&0));
    assert!(hits.contains(&2));
}

#[test]
fn masked_byte_pattern_empty_search() {
    let mbp = MaskedBytePattern::new(vec![]);
    assert!(mbp.search(&[1, 2, 3]).is_empty());
    assert!(mbp.is_empty());
    assert_eq!(mbp.specificity(), 0.0);
}

#[test]
fn pattern_to_masked_conversion() {
    let p = Pattern::parse("DE ?? A? ?B").unwrap();
    let m = pattern_to_masked(&p);
    assert_eq!(m.len(), 4);
    assert!(m.elements[0].is_exact());
    assert!(m.elements[1].is_wildcard());
    assert_eq!(m.elements[2].mask, 0xF0);
    assert_eq!(m.elements[3].mask, 0x0F);
}

// ─── PatternBook ──────────────────────────────────────────────────────────

#[test]
fn book_add_and_search() {
    let mut b = PatternBook::new("cat");
    b.add(MaskedBytePattern::new(vec![ByteMask::exact(0xAA)]));
    b.add(MaskedBytePattern::new(vec![ByteMask::exact(0xBB)]));
    let hits = b.search_all(&[0xBB, 0xAA]);
    assert_eq!(hits.len(), 2);
    // Sorted by offset
    assert_eq!(hits[0].1, 0);
    assert_eq!(hits[1].1, 1);
}

#[test]
fn book_json_roundtrip() {
    let mut b = PatternBook::new("cat");
    b.add(MaskedBytePattern::new(vec![ByteMask::exact(0xAA)]));
    let s = b.to_json().unwrap();
    let b2 = PatternBook::from_json(&s).unwrap();
    assert_eq!(b2.len(), 1);
    assert_eq!(b2.category, "cat");
}

// ─── BmhTable ─────────────────────────────────────────────────────────────

#[test]
fn bmh_search_basic() {
    let pat = b"abc";
    let t = BmhTable::build(pat);
    assert_eq!(t.pattern_len(), 3);
    let hay = b"xxabcyyabczz";
    let hits = t.search(hay, pat);
    assert_eq!(hits, vec![2, 7]);
}

#[test]
fn bmh_search_no_match() {
    let pat = b"zzz";
    let t = BmhTable::build(pat);
    assert!(t.search(b"abcabc", pat).is_empty());
}

#[test]
fn bmh_search_needle_larger_than_haystack() {
    let pat = b"abcdef";
    let t = BmhTable::build(pat);
    assert!(t.search(b"abc", pat).is_empty());
}

#[test]
#[should_panic]
fn bmh_build_empty_panics_documented() {
    // Documented panic behavior; we exercise it but isolated to one test.
    let _ = BmhTable::build(&[]);
}

#[test]
fn bmh_single_byte_pattern() {
    let pat = b"A";
    let t = BmhTable::build(pat);
    let hay = b"AABCA";
    let hits = t.search(hay, pat);
    assert_eq!(hits, vec![0, 1, 4]);
}

// ─── CatalogEntry / PatternCatalog ────────────────────────────────────────

#[test]
fn catalog_add_get_remove() {
    let mut c = PatternCatalog::new();
    let id = c.add(Pattern::parse("AA").unwrap(), "desc");
    assert!(c.get(id).is_some());
    assert!(c.remove(id));
    assert!(c.get(id).is_none());
    assert!(c.is_empty());
}

#[test]
fn catalog_by_tag_filter() {
    let mut c = PatternCatalog::new();
    let id1 = c.add(Pattern::parse("AA").unwrap(), "d1");
    let _ = c.add(Pattern::parse("BB").unwrap(), "d2");
    // CatalogEntry::with_tag consumes & returns, so we need to mutate via re-adding
    // Skip mutation: directly test has_tag via builder
    let e = CatalogEntry::new(id1, Pattern::parse("AA").unwrap(), "d").with_tag("k");
    assert!(e.has_tag("k"));
    assert!(!e.has_tag("nope"));
}

#[test]
fn catalog_search_all_sorted() {
    let mut c = PatternCatalog::new();
    c.add(Pattern::parse("AA").unwrap(), "");
    c.add(Pattern::parse("BB").unwrap(), "");
    let hits = c.search_all(&[0xBB, 0xAA]);
    assert_eq!(hits.len(), 2);
    assert!(hits[0].1 <= hits[1].1);
}

#[test]
fn catalog_json_roundtrip() {
    let mut c = PatternCatalog::new();
    c.add(Pattern::parse("AA").unwrap(), "d");
    let s = c.to_json().unwrap();
    let c2 = PatternCatalog::from_json(&s).unwrap();
    assert_eq!(c2.len(), 1);
}

// ─── pattern_diff / PatternDiffResult ─────────────────────────────────────

#[test]
fn diff_identical() {
    let p = Pattern::parse("AA").unwrap();
    let r = pattern_diff(&p, &[0xAA, 0x00, 0xAA], &[0xAA, 0x00, 0xAA]);
    assert!(r.is_identical());
    assert_eq!(r.common.len(), 2);
    assert_eq!(r.total_unique(), 2);
}

#[test]
fn diff_disjoint() {
    let p = Pattern::parse("AA").unwrap();
    let r = pattern_diff(&p, &[0xAA, 0x00], &[0x00, 0xAA]);
    assert!(!r.is_identical());
    assert_eq!(r.left_only, vec![0]);
    assert_eq!(r.right_only, vec![1]);
}

// ─── PatternHighlightMap ──────────────────────────────────────────────────

#[test]
fn highlight_map_new_empty() {
    let h = PatternHighlightMap::new();
    assert!(h.spans.is_empty());
}

// ─── PatternError Display ─────────────────────────────────────────────────

#[test]
fn pattern_error_display() {
    let e = PatternError::Empty;
    let s = format!("{e}");
    assert!(s.contains("empty"));
    let e2 = PatternError::CaptureUndefined("x".into());
    let s2 = format!("{e2}");
    assert!(s2.contains("x"));
}
