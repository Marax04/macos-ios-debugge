//! Deep adversarial tests for rustre-hex-pattern (Y070).
#![allow(clippy::needless_range_loop)]

use rustre_hex_pattern::{
    AlternationPattern, CompiledPattern, MaskedPattern, Pattern, PatternByte, PatternDatabase,
    PatternError, PatternExporter, PatternGroup, RegexPattern, SignaturePattern, crc16_ibm,
};
use std::sync::Arc;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(n: usize, g: &mut impl FnMut() -> u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let v = g();
        for i in 0..8 {
            if out.len() == n {
                break;
            }
            out.push((v >> (i * 8)) as u8);
        }
    }
    out
}

// 1
#[test]
fn pb_exact_roundtrip() {
    for v in 0u16..=255 {
        let pb = PatternByte::Exact(v as u8);
        assert!(pb.matches(v as u8));
        assert_eq!(pb.mask_byte(), 0xFF);
        assert_eq!(pb.value_byte(), v as u8);
        assert!(!pb.is_wildcard());
    }
}

// 2
#[test]
fn pb_wildcard_matches_all() {
    let pb = PatternByte::Wildcard;
    for v in 0u16..=255 {
        assert!(pb.matches(v as u8));
    }
    assert_eq!(pb.mask_byte(), 0x00);
    assert!(pb.is_wildcard());
}

// 3
#[test]
fn pb_nibble_high_only() {
    for hi in 0u8..=0xF {
        let pb = PatternByte::Nibble { high: Some(hi), low: None };
        for v in 0u16..=255 {
            let b = v as u8;
            assert_eq!(pb.matches(b), (b >> 4) == hi);
        }
        assert_eq!(pb.mask_byte(), 0xF0);
        assert!(pb.is_wildcard());
    }
}

// 4
#[test]
fn pb_nibble_low_only() {
    for lo in 0u8..=0xF {
        let pb = PatternByte::Nibble { high: None, low: Some(lo) };
        for v in 0u16..=255 {
            let b = v as u8;
            assert_eq!(pb.matches(b), (b & 0x0F) == lo);
        }
        assert_eq!(pb.mask_byte(), 0x0F);
    }
}

// 5
#[test]
fn pb_nibble_both_some_acts_like_exact() {
    let pb = PatternByte::Nibble { high: Some(0xA), low: Some(0xB) };
    assert!(pb.matches(0xAB));
    assert!(!pb.matches(0xAC));
    assert_eq!(pb.mask_byte(), 0xFF);
    assert!(!pb.is_wildcard());
}

// 6
#[test]
fn pb_nibble_both_none_is_full_wildcard_semantics() {
    let pb = PatternByte::Nibble { high: None, low: None };
    for v in 0u16..=255 {
        assert!(pb.matches(v as u8));
    }
    assert_eq!(pb.mask_byte(), 0x00);
}

// 7
#[test]
fn parse_empty_err() {
    assert!(matches!(Pattern::parse(""), Err(PatternError::Empty)));
    assert!(matches!(Pattern::parse("   "), Err(PatternError::Empty)));
}

// 8
#[test]
fn parse_all_two_digit_bytes() {
    for v in 0u16..=255 {
        let s = format!("{:02X}", v);
        let p = Pattern::parse(&s).unwrap();
        assert_eq!(p.bytes[0], PatternByte::Exact(v as u8));
    }
}

// 9
#[test]
fn parse_double_question() {
    let p = Pattern::parse("??").unwrap();
    assert_eq!(p.bytes[0], PatternByte::Wildcard);
}

// 10
#[test]
fn parse_single_question() {
    let p = Pattern::parse("?").unwrap();
    assert_eq!(p.bytes[0], PatternByte::Wildcard);
}

// 11
#[test]
fn parse_single_hex_digit_is_high_nibble() {
    // Doc: single hex digit "A" → high nibble Some(0xA), low None
    let p = Pattern::parse("A").unwrap();
    assert_eq!(p.bytes[0], PatternByte::Nibble { high: Some(0xA), low: None });
}

// 12
#[test]
fn parse_invalid_chars() {
    for s in ["GG", "ZZ", "1G", "G1", "###", "0xDE", "DEAD"] {
        assert!(Pattern::parse(s).is_err(), "should err: {s}");
    }
}

// 13
#[test]
fn parse_token_too_long() {
    assert!(Pattern::parse("DEAD").is_err());
}

// 14
#[test]
fn parse_lowercase_hex() {
    let p = Pattern::parse("de ad be ef").unwrap();
    assert_eq!(p.bytes, vec![
        PatternByte::Exact(0xDE),
        PatternByte::Exact(0xAD),
        PatternByte::Exact(0xBE),
        PatternByte::Exact(0xEF),
    ]);
}

// 15
#[test]
fn parse_multiwhitespace() {
    let p = Pattern::parse("  DE\tAD\n BE  EF  ").unwrap();
    assert_eq!(p.bytes.len(), 4);
}

// 16
#[test]
fn pattern_matches_offset_overflow() {
    let p = Pattern::parse("DE AD").unwrap();
    assert!(!p.matches(&[0xDE, 0xAD], usize::MAX));
    assert!(!p.matches(&[0xDE, 0xAD], usize::MAX - 1));
}

// 17
#[test]
fn pattern_matches_oob() {
    let p = Pattern::parse("DE AD").unwrap();
    assert!(!p.matches(&[0xDE], 0));
    assert!(!p.matches(&[], 0));
    assert!(!p.matches(&[0xDE, 0xAD], 1));
}

// 18
#[test]
fn pattern_search_empty_pattern_path() {
    // can't construct an empty pattern via parse; create manually
    let p = Pattern {
        bytes: vec![],
        name: None,
        tags: vec![],
        captures: vec![],
        comment: String::new(),
    };
    assert_eq!(p.search(&[0u8; 10]), Vec::<usize>::new());
    assert!(p.is_empty());
    assert_eq!(p.len(), 0);
}

// 19
#[test]
fn pattern_search_data_shorter_than_pattern() {
    let p = Pattern::parse("DE AD BE EF").unwrap();
    assert!(p.search(&[0xDE, 0xAD]).is_empty());
}

// 20
#[test]
fn pattern_search_all_wildcards_returns_all_positions() {
    let p = Pattern::parse("? ?").unwrap();
    let data = [1u8, 2, 3, 4, 5];
    let res = p.search(&data);
    assert_eq!(res, vec![0, 1, 2, 3]);
}

// 21
#[test]
fn pattern_search_anchored_consistency_with_brute() {
    let mut g = lcg();
    let data = rand_bytes(2048, &mut g);
    let p = Pattern::parse("?? DE ?? AD").unwrap();
    let res = p.search(&data);
    let mut brute = Vec::new();
    for i in 0..=data.len().saturating_sub(4) {
        if p.matches(&data, i) {
            brute.push(i);
        }
    }
    assert_eq!(res, brute);
}

// 22
#[test]
fn pattern_search_exact_consistency() {
    let mut g = lcg();
    let mut data = rand_bytes(1024, &mut g);
    // Plant the pattern
    let target = [0xDEu8, 0xAD, 0xBE, 0xEF];
    data[100..104].copy_from_slice(&target);
    data[500..504].copy_from_slice(&target);
    let p = Pattern::parse("DE AD BE EF").unwrap();
    let res = p.search(&data);
    assert!(res.contains(&100));
    assert!(res.contains(&500));
}

// 23
#[test]
fn to_bytes_only_when_no_wildcards() {
    assert!(Pattern::parse("DE AD").unwrap().to_bytes().is_some());
    assert!(Pattern::parse("DE ?").unwrap().to_bytes().is_none());
    assert!(Pattern::parse("D?").unwrap().to_bytes().is_none());
}

// 24
#[test]
fn to_hex_string_roundtrip_no_wildcards() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() % 10) + 1) as usize;
        let bytes = rand_bytes(n, &mut g);
        let s: String = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        let p = Pattern::parse(&s).unwrap();
        let s2 = p.to_hex_string();
        let p2 = Pattern::parse(&s2).unwrap();
        assert_eq!(p.bytes, p2.bytes);
    }
}

// 25
#[test]
fn to_hex_string_wildcard_token() {
    let p = Pattern::parse("? ??").unwrap();
    let s = p.to_hex_string();
    assert!(s.contains("??"));
}

// 26
#[test]
fn specificity_bounds() {
    let empty = Pattern { bytes: vec![], name: None, tags: vec![], captures: vec![], comment: String::new() };
    assert_eq!(empty.specificity(), 0.0);
    let full = Pattern::parse("AA BB CC DD").unwrap();
    assert!((full.specificity() - 1.0).abs() < 1e-12);
    let wc = Pattern::parse("? ? ? ?").unwrap();
    assert_eq!(wc.specificity(), 0.0);
}

// 27
#[test]
fn exact_wildcard_counts() {
    let p = Pattern::parse("DE ? AD ??").unwrap();
    assert_eq!(p.exact_count(), 2);
    assert_eq!(p.wildcard_count(), 2);
}

// 28
#[test]
fn json_roundtrip_pattern() {
    let p = Pattern::parse("DE ? AD")
        .unwrap()
        .with_name("foo")
        .with_tag("a")
        .with_tag("b")
        .with_comment("hi");
    let j = p.to_json().unwrap();
    let p2 = Pattern::from_json(&j).unwrap();
    assert_eq!(p2.bytes, p.bytes);
    assert_eq!(p2.name.as_deref(), Some("foo"));
    assert_eq!(p2.tags, vec!["a", "b"]);
    assert_eq!(p2.comment, "hi");
}

// 29
#[test]
fn json_invalid_err() {
    assert!(matches!(Pattern::from_json("not json"), Err(PatternError::Import(_))));
}

// 30
#[test]
fn captures_extract() {
    let p = Pattern::parse("DE AD BE EF").unwrap().with_capture("hdr", 0, 2);
    let data = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];
    let m = p.search_with_captures(&data);
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].1[0].bytes, vec![0xDE, 0xAD]);
    assert_eq!(m[0].1[0].offset, 0);
    assert_eq!(m[1].1[0].offset, 4);
}

// 31
#[test]
fn captures_clipped_at_end() {
    // capture extends beyond data; should clip not panic
    let p = Pattern::parse("DE AD").unwrap().with_capture("x", 0, 10);
    let data = [0xDE, 0xAD];
    let m = p.search_with_captures(&data);
    assert_eq!(m.len(), 1);
    assert!(m[0].1[0].bytes.len() <= 2);
}

// 32
#[test]
fn alternation_parse_empty_err() {
    assert!(matches!(AlternationPattern::parse(""), Err(PatternError::Empty)));
    assert!(matches!(AlternationPattern::parse("|||"), Err(PatternError::Empty)));
}

// 33
#[test]
fn alternation_search_dedups_and_sorts() {
    let a = AlternationPattern::parse("AA | AA").unwrap();
    let data = [0xAA, 0x00, 0xAA];
    let r = a.search(&data);
    assert_eq!(r, vec![0, 2]);
}

// 34
#[test]
fn alternation_matches_any() {
    let a = AlternationPattern::parse("DE AD | BE EF").unwrap();
    assert!(a.matches(&[0xDE, 0xAD], 0));
    assert!(a.matches(&[0xBE, 0xEF], 0));
    assert!(!a.matches(&[0x00, 0x00], 0));
}

// 35
#[test]
fn compiled_matches_equals_pattern_matches() {
    let mut g = lcg();
    let data = rand_bytes(1024, &mut g);
    let p = Pattern::parse("DE ?? AD ?F").unwrap();
    let cp = CompiledPattern::compile(&p);
    for i in 0..data.len().saturating_sub(4) {
        assert_eq!(p.matches(&data, i), cp.matches(&data, i), "mismatch at {i}");
    }
}

// 36
#[test]
fn compiled_search_equals_pattern_search() {
    let mut g = lcg();
    let data = rand_bytes(2048, &mut g);
    for spec in ["DE AD", "?? DE", "DE ?? AD", "AA BB CC"] {
        let p = Pattern::parse(spec).unwrap();
        let cp = CompiledPattern::compile(&p);
        assert_eq!(p.search(&data), cp.search(&data), "spec {spec}");
    }
}

// 37
#[test]
fn compiled_offset_overflow() {
    let p = Pattern::parse("DE AD").unwrap();
    let cp = CompiledPattern::compile(&p);
    assert!(!cp.matches(&[0xDE, 0xAD], usize::MAX));
}

// 38
#[test]
fn compiled_all_wildcards_search() {
    let p = Pattern::parse("? ? ?").unwrap();
    let cp = CompiledPattern::compile(&p);
    let data = [1u8, 2, 3, 4, 5];
    assert_eq!(cp.search(&data), vec![0, 1, 2]);
}

// 39
#[test]
fn masked_length_mismatch_err() {
    let r = MaskedPattern::new(vec![0, 1, 2], vec![0xFF]);
    assert!(matches!(r, Err(PatternError::Parse { .. })));
}

// 40
#[test]
fn masked_matches_oob_safe() {
    let m = MaskedPattern::new(vec![0xDE, 0xAD], vec![0xFF, 0xFF]).unwrap();
    assert!(!m.matches(&[0xDE], 0));
    assert!(!m.matches(&[0xDE, 0xAD], usize::MAX));
}

// 41
#[test]
fn masked_from_pattern_consistency() {
    let mut g = lcg();
    let data = rand_bytes(512, &mut g);
    for spec in ["DE AD", "DE ?? AD", "?F D?", "AA BB CC DD"] {
        let p = Pattern::parse(spec).unwrap();
        let m = MaskedPattern::from_pattern(&p);
        for i in 0..data.len().saturating_sub(p.len()) {
            assert_eq!(p.matches(&data, i), m.matches(&data, i));
        }
    }
}

// 42
#[test]
fn pattern_group_search_all_sorted_by_offset() {
    let mut g = PatternGroup::new("g");
    g.add(Pattern::parse("AA").unwrap().with_name("a"));
    g.add(Pattern::parse("BB").unwrap().with_name("b"));
    let data = [0xAA, 0xBB, 0xCC, 0xAA, 0xBB];
    let res = g.search_all(&data);
    let offsets: Vec<usize> = res.iter().map(|m| m.offset).collect();
    let mut sorted = offsets.clone();
    sorted.sort();
    assert_eq!(offsets, sorted);
    assert_eq!(res.len(), 4);
}

// 43
#[test]
fn pattern_group_json_roundtrip() {
    let mut g = PatternGroup::new("group1");
    g.add(Pattern::parse("DE AD").unwrap().with_name("p1"));
    g.add(Pattern::parse("BE EF").unwrap().with_name("p2"));
    let j = g.to_json().unwrap();
    let g2 = PatternGroup::from_json(&j).unwrap();
    assert_eq!(g2.name, "group1");
    assert_eq!(g2.patterns.len(), 2);
}

// 44
#[test]
fn pattern_group_compile_matches() {
    let mut grp = PatternGroup::new("g");
    grp.add(Pattern::parse("DE AD").unwrap());
    grp.add(Pattern::parse("BE EF").unwrap());
    let cg = grp.compile();
    let data = [0xDE, 0xAD, 0xBE, 0xEF];
    let a = grp.search_all(&data);
    let b = cg.search_all(&data);
    assert_eq!(a.len(), b.len());
}

// 45
#[test]
fn crc16_ibm_known_vectors() {
    // CRC-16/IBM (a.k.a CRC-16/ARC) of "123456789" is 0xBB3D
    assert_eq!(crc16_ibm(b"123456789"), 0xBB3D);
    assert_eq!(crc16_ibm(&[]), 0x0000);
}

// 46
#[test]
fn crc16_ibm_determinism() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() % 64) as usize;
        let v = rand_bytes(n, &mut g);
        assert_eq!(crc16_ibm(&v), crc16_ibm(&v));
    }
}

// 47
#[test]
fn signature_pattern_matches_when_crc_ok() {
    let body = [0x10u8, 0x20, 0x30, 0x40];
    let crc = crc16_ibm(&body);
    let mut data = vec![0xDEu8, 0xAD];
    data.extend_from_slice(&body);
    let sig = SignaturePattern::new("f", Pattern::parse("DE AD").unwrap(), crc, 4, 4);
    assert!(sig.matches(&data, 0));
    let r = sig.search(&data);
    assert_eq!(r, vec![0]);
}

// 48
#[test]
fn signature_pattern_rejects_wrong_crc() {
    let mut data = vec![0xDEu8, 0xAD, 0x10, 0x20, 0x30, 0x40];
    let sig = SignaturePattern::new("f", Pattern::parse("DE AD").unwrap(), 0x0000, 4, 4);
    assert!(!sig.matches(&data, 0));
    data.truncate(3);
    // Not enough data for crc bytes:
    let sig2 = SignaturePattern::new("f", Pattern::parse("DE AD").unwrap(), 0x0000, 4, 4);
    assert!(!sig2.matches(&data, 0));
}

// 49
#[test]
fn exporter_ida_pat_roundtrip() {
    // Names must be non-ambiguous (not just hex digits) since the .pat format
    // separates hex bytes and the name only by whitespace.
    let pats = vec![
        Pattern::parse("DE AD").unwrap().with_name("alpha_fn"),
        Pattern::parse("BE ?? EF").unwrap().with_name("beta_fn"),
    ];
    let s = PatternExporter::export_ida_pat(&pats);
    let pats2 = PatternExporter::import_ida_pat(&s).unwrap();
    assert_eq!(pats2.len(), 2);
    assert_eq!(pats2[0].name.as_deref(), Some("alpha_fn"));
    assert_eq!(pats2[1].name.as_deref(), Some("beta_fn"));
}

// 50
#[test]
fn exporter_ida_pat_skip_comments_blanks() {
    let s = "# a comment\n\nDE AD foo\n   \n# trailing";
    let pats = PatternExporter::import_ida_pat(s).unwrap();
    assert_eq!(pats.len(), 1);
    assert_eq!(pats[0].name.as_deref(), Some("foo"));
}

// 51
#[test]
fn exporter_json_roundtrip() {
    let pats = vec![Pattern::parse("DE AD").unwrap()];
    let j = PatternExporter::export_json(&pats).unwrap();
    let pats2 = PatternExporter::import_json(&j).unwrap();
    assert_eq!(pats2.len(), 1);
}

// 52
#[test]
fn db_in_memory_insert_search_delete() {
    let db = PatternDatabase::open_in_memory().unwrap();
    assert_eq!(db.count().unwrap(), 0);
    let p = Pattern::parse("DE AD").unwrap().with_name("alpha").with_tag("t1");
    let id = db.insert(&p).unwrap();
    assert_eq!(db.count().unwrap(), 1);
    let by_name = db.search_by_name("alp").unwrap();
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].bytes, p.bytes);
    let by_tag = db.search_by_tag("t1").unwrap();
    assert_eq!(by_tag.len(), 1);
    db.delete(id).unwrap();
    assert_eq!(db.count().unwrap(), 0);
}

// 53
#[test]
fn db_like_wildcards_escaped() {
    let db = PatternDatabase::open_in_memory().unwrap();
    db.insert(&Pattern::parse("DE AD").unwrap().with_name("foo")).unwrap();
    db.insert(&Pattern::parse("DE AD").unwrap().with_name("100%bar")).unwrap();
    // Query containing '%' must match literally, not as wildcard
    let r = db.search_by_name("100%").unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name.as_deref(), Some("100%bar"));
    // Underscore should also be escaped
    let r2 = db.search_by_name("_").unwrap();
    assert_eq!(r2.len(), 0);
}

// 54
#[test]
fn fuzz_parse_never_panics() {
    let mut g = lcg();
    let tokens = ["DE", "??", "?", "0?", "?F", "AA", "FF", "GG", "DEAD", "1"];
    for _ in 0..200 {
        let n = ((g() % 8) + 1) as usize;
        let mut s = String::new();
        for _ in 0..n {
            let i = (g() as usize) % tokens.len();
            s.push_str(tokens[i]);
            s.push(' ');
        }
        let _ = Pattern::parse(&s); // Ok or Err, never panic
    }
}

// 55
#[test]
fn fuzz_search_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() % 256) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let p = Pattern::parse("DE ?? AD").unwrap();
        let _ = p.search(&data);
        let cp = CompiledPattern::compile(&p);
        let _ = cp.search(&data);
        let mp = MaskedPattern::from_pattern(&p);
        let _ = mp.search(&data);
    }
}

// 56
#[test]
fn send_sync_threaded_pattern_search() {
    let p = Arc::new(Pattern::parse("DE AD BE EF").unwrap());
    let mut g = lcg();
    let mut data = rand_bytes(4096, &mut g);
    data[1024..1028].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let data = Arc::new(data);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let pc = Arc::clone(&p);
        let dc = Arc::clone(&data);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = pc.search(&dc);
                assert!(r.contains(&1024));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// 57
#[test]
fn send_sync_threaded_compiled() {
    let p = Pattern::parse("DE ?? BE EF").unwrap();
    let cp = Arc::new(CompiledPattern::compile(&p));
    let data = Arc::new(vec![0xDEu8, 0x00, 0xBE, 0xEF, 0xFF, 0xDE, 0x99, 0xBE, 0xEF]);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let cpc = Arc::clone(&cp);
        let dc = Arc::clone(&data);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = cpc.search(&dc);
                assert_eq!(r, vec![0, 5]);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// 58
#[test]
fn alternation_with_name() {
    let a = AlternationPattern::parse("AA | BB").unwrap().with_name("xx");
    assert_eq!(a.name.as_deref(), Some("xx"));
    assert_eq!(a.len(), 2);
    assert!(!a.is_empty());
}

// 59
#[test]
fn regex_pattern_basic_or_err() {
    // The result depends on rustre-hex; either Ok(Vec) or Err(Regex). Must not panic.
    let r = RegexPattern::new("DE").with_name("n");
    let _ = r.search(b"\xDE\xAD"); // either Ok or Err
    assert_eq!(r.name.as_deref(), Some("n"));
}

// 60
#[test]
fn pattern_group_any_matches() {
    let mut g = PatternGroup::new("g");
    g.add(Pattern::parse("DE AD").unwrap());
    g.add(Pattern::parse("BE EF").unwrap());
    assert!(g.any_matches(&[0xDE, 0xAD], 0));
    assert!(g.any_matches(&[0xBE, 0xEF], 0));
    assert!(!g.any_matches(&[0x00, 0x00], 0));
}

// 61
#[test]
fn to_simd_form_consistent() {
    let p = Pattern::parse("DE ?? AD ?F D?").unwrap();
    let (v, m) = p.to_simd_form();
    assert_eq!(v.len(), 5);
    assert_eq!(m.len(), 5);
    assert_eq!(m[0], 0xFF); // exact
    assert_eq!(m[1], 0x00); // wildcard
    assert_eq!(m[2], 0xFF); // exact
    assert_eq!(m[3], 0x0F); // low nibble
    assert_eq!(m[4], 0xF0); // high nibble
}
