//! Exhaustive blitz tests for rustre-flirt public API in lib.rs.

use rustre_core::address::Address;
use rustre_flirt::*;

// ── crc16_flirt ─────────────────────────────────────────────────────────────

#[test]
fn crc16_flirt_empty_is_initial() {
    // MCRF4XX (init 0xFFFF, NO final XOR): empty input yields the init value.
    // See .claude/TODO.md T1 — flair's crc16.cpp may special-case len == 0.
    assert_eq!(crc16_flirt(&[]), 0xFFFF);
}

#[test]
fn crc16_flirt_deterministic() {
    let a = crc16_flirt(&[1, 2, 3, 4]);
    let b = crc16_flirt(&[1, 2, 3, 4]);
    assert_eq!(a, b);
}

#[test]
fn crc16_flirt_different_inputs() {
    assert_ne!(crc16_flirt(&[1, 2, 3]), crc16_flirt(&[3, 2, 1]));
}

#[test]
fn crc16_ibm_empty_zero() {
    assert_eq!(crc16_ibm(&[]), 0);
}

#[test]
fn crc16_ibm_distinct_from_flirt() {
    let data = b"hello world";
    assert_ne!(crc16_ibm(data), crc16_flirt(data));
}

// ── PatternByte / FlirtPattern ──────────────────────────────────────────────

#[test]
fn flirt_pattern_new_defaults() {
    let p = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
    assert_eq!(p.initial_bytes.len(), 1);
    assert_eq!(p.crc16, 0);
    assert_eq!(p.crc_length, 0);
    assert!(p.names.is_empty());
    assert!(p.tail_bytes.is_empty());
}

#[test]
fn matches_initial_exact() {
    let p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x8B),
        PatternByte::Exact(0xEC),
    ]);
    assert!(p.matches_initial(&[0x55, 0x8B, 0xEC, 0xFF]));
}

#[test]
fn matches_initial_wildcard() {
    let p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Wildcard,
        PatternByte::Exact(0xEC),
    ]);
    assert!(p.matches_initial(&[0x55, 0x99, 0xEC]));
    assert!(!p.matches_initial(&[0x55, 0x99, 0xED]));
}

#[test]
fn matches_initial_too_short() {
    let p = FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Exact(0x8B)]);
    assert!(!p.matches_initial(&[0x55]));
}

#[test]
fn matches_initial_empty_pattern_matches_empty_buf() {
    let p = FlirtPattern::new(vec![]);
    assert!(p.matches_initial(&[]));
    assert!(p.matches_initial(&[1, 2, 3]));
}

#[test]
fn matches_tail_all_pass() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0)]);
    p.tail_bytes
        .push(TailByte { offset: 2, value: 0xAA });
    p.tail_bytes
        .push(TailByte { offset: 4, value: 0xBB });
    assert!(p.matches_tail(&[0, 0, 0xAA, 0, 0xBB]));
}

#[test]
fn matches_tail_offset_out_of_range() {
    let mut p = FlirtPattern::new(vec![]);
    p.tail_bytes.push(TailByte { offset: 10, value: 1 });
    assert!(!p.matches_tail(&[1, 2, 3]));
}

#[test]
fn matches_tail_empty_is_true() {
    let p = FlirtPattern::new(vec![]);
    assert!(p.matches_tail(&[]));
    assert!(p.matches_tail(&[1, 2]));
}

#[test]
fn matches_crc16_zero_length_always_true() {
    let p = FlirtPattern::new(vec![PatternByte::Exact(0)]);
    assert!(p.matches_crc16(&[0]));
    assert!(p.matches_crc16(&[]));
}

#[test]
fn matches_crc16_correct() {
    let initial = vec![PatternByte::Exact(0x90)];
    let extra = [1u8, 2, 3, 4];
    let crc = crc16_flirt(&extra);
    let mut p = FlirtPattern::new(initial);
    p.crc_length = 4;
    p.crc16 = crc;
    let buf = [0x90, 1, 2, 3, 4];
    assert!(p.matches_crc16(&buf));
}

#[test]
fn matches_crc16_wrong() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x90)]);
    p.crc_length = 4;
    p.crc16 = 0x1234;
    assert!(!p.matches_crc16(&[0x90, 1, 2, 3, 4]));
}

#[test]
fn matches_crc16_buf_too_short() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0)]);
    p.crc_length = 10;
    p.crc16 = 0;
    assert!(!p.matches_crc16(&[0, 1, 2]));
}

#[test]
fn matches_all_combines() {
    let initial = vec![PatternByte::Exact(0xAA), PatternByte::Exact(0xBB)];
    let extra = [0x11u8, 0x22];
    let crc = crc16_flirt(&extra);
    let mut p = FlirtPattern::new(initial);
    p.crc_length = 2;
    p.crc16 = crc;
    p.tail_bytes.push(TailByte { offset: 5, value: 0x99 });
    let buf = [0xAA, 0xBB, 0x11, 0x22, 0x00, 0x99];
    assert!(p.matches_all(&buf));

    let bad = [0xAA, 0xBB, 0x11, 0x22, 0x00, 0x00];
    assert!(!p.matches_all(&bad));
}

#[test]
fn primary_name_picks_public_offset_zero() {
    let mut p = FlirtPattern::new(vec![]);
    p.names.push(FlirtName {
        name: "_start".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    p.names.push(FlirtName {
        name: "other".into(),
        offset: 4,
        is_public: true,
        is_local: false,
    });
    assert_eq!(p.primary_name(), Some("_start"));
}

#[test]
fn primary_name_falls_back_to_a_local_name_at_zero() {
    // POLICY CHANGE (2026-07-29): this used to assert `None`, i.e. only a
    // *public* name at offset 0 counted. That rule discarded 25 965 of the
    // 67 168 rust-stdlib patterns (38.7%) — every one carrying exactly one
    // name, at offset 0, marked local (destructors, trait thunks). A static
    // function's name is still the right name for its code, so refusing it
    // threw away over a third of the database.
    let mut p = FlirtPattern::new(vec![]);
    p.names.push(FlirtName {
        name: "x".into(),
        offset: 0,
        is_public: false,
        is_local: true,
    });
    assert_eq!(p.primary_name(), Some("x"));
}

#[test]
fn all_names_iterates_all() {
    let mut p = FlirtPattern::new(vec![]);
    p.names.push(FlirtName {
        name: "a".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    p.names.push(FlirtName {
        name: "b".into(),
        offset: 2,
        is_public: false,
        is_local: true,
    });
    let v: Vec<&str> = p.all_names().collect();
    assert_eq!(v, vec!["a", "b"]);
}

#[test]
fn pattern_hex_renders_wildcards() {
    let p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Wildcard,
        PatternByte::Exact(0x0F),
    ]);
    assert_eq!(p.pattern_hex(), "55 .. 0F");
}

#[test]
fn pattern_hex_empty() {
    let p = FlirtPattern::new(vec![]);
    assert_eq!(p.pattern_hex(), "");
}

#[test]
fn wildcard_ratio_calc() {
    let p = FlirtPattern::new(vec![
        PatternByte::Exact(0),
        PatternByte::Wildcard,
        PatternByte::Wildcard,
        PatternByte::Exact(0),
    ]);
    assert!((p.wildcard_ratio() - 0.5).abs() < 1e-6);
}

#[test]
fn wildcard_ratio_empty_zero() {
    let p = FlirtPattern::new(vec![]);
    assert_eq!(p.wildcard_ratio(), 0.0);
}

#[test]
fn wildcard_ratio_all_wildcards() {
    let p = FlirtPattern::new(vec![PatternByte::Wildcard, PatternByte::Wildcard]);
    assert_eq!(p.wildcard_ratio(), 1.0);
}

// ── FlirtArch round trip ─────────────────────────────────────────────────────

#[test]
fn flirt_arch_roundtrip_known() {
    for v in [0u8, 8, 19, 128, 132, 255] {
        let a = FlirtArch::from_u8(v);
        assert_eq!(a.to_u8(), v, "arch {v}");
    }
}

#[test]
fn flirt_arch_unknown_value() {
    assert_eq!(FlirtArch::from_u8(99), FlirtArch::Unknown);
    assert_eq!(FlirtArch::from_u8(200), FlirtArch::Unknown);
}

// ── FlirtFileType bitflags ──────────────────────────────────────────────────

#[test]
fn file_type_bits_roundtrip() {
    let ft = FlirtFileType::from_u32(0xDEAD_BEEF);
    assert_eq!(ft.bits(), 0xDEAD_BEEF);
}

#[test]
fn file_type_contains() {
    let ft = FlirtFileType(FlirtFileType::ELF.bits() | FlirtFileType::PE.bits());
    assert!(ft.contains(FlirtFileType::ELF));
    assert!(ft.contains(FlirtFileType::PE));
    assert!(!ft.contains(FlirtFileType::COFF));
}

// ── parse_sig_header ─────────────────────────────────────────────────────────

#[test]
fn parse_sig_header_too_short() {
    let err = parse_sig_header(&[0u8; 5]).unwrap_err();
    assert!(matches!(err, FlirtError::ParseError(_)));
}

#[test]
fn parse_sig_header_invalid_magic() {
    let mut data = vec![0u8; 64];
    data[0] = 0xFF;
    let err = parse_sig_header(&data).unwrap_err();
    assert!(matches!(err, FlirtError::InvalidSigMagic));
}

#[test]
fn parse_sig_header_unsupported_version() {
    let mut data = vec![0u8; 64];
    // Use legacy "0x54 0x4A" magic with version 3 (< 5)
    data[0] = 0x54;
    data[1] = 0x4A;
    data[2] = 3;
    let err = parse_sig_header(&data).unwrap_err();
    assert!(matches!(err, FlirtError::UnsupportedVersion(3)));
}

#[test]
fn parse_sig_header_valid_v9_min() {
    // This test used to hand-build the header field by field, placing
    // `alt_ctype_crc` and `n_functions` *after* the library name. That is not
    // the IDASGN layout — the published one has `library_name_len` at 34,
    // `alt_ctype_crc` at 35, `n_functions` at 37, `pattern_size` at 41 and only
    // the name variable-length, at 43. Because the test wrote the same wrong
    // layout the parser read, it passed, and certified the defect (T37,
    // iteration 43; same shape as the eleven tests that certified the header
    // layout before T27).
    //
    // It now builds the header with the canonical codec, so it cannot agree
    // with a parser that has drifted: the bytes come from the one place that
    // owns the offsets.
    let mut h = rustre_flirt::sig_header::SigFileHeader::default();
    h.version = 9;
    h.arch = FlirtArch::X64.to_u8();
    h.n_functions = 7;
    let data = h.encode();

    let (hdr, off) = parse_sig_header(&data).expect("should parse");
    assert_eq!(hdr.version, 9);
    assert_eq!(hdr.arch, FlirtArch::X64);
    assert_eq!(hdr.library_name, "");
    assert_eq!(hdr.n_functions, 7);
    assert_eq!(
        off,
        h.len_bytes(),
        "l'offset restituito deve essere la lunghezza reale dell'header: se \
         diverge, tutto cio' che segue viene letto disallineato"
    );
}

#[test]
fn parse_sig_header_lib_name_truncated() {
    let mut data = Vec::new();
    data.extend_from_slice(b"IDASGN");
    data.push(9);
    data.push(0);
    // After IDASGN(6) + version(1) + arch(1) = 8 bytes, we need ctype to end at index 34.
    // Bytes from index 8 to 33 inclusive: 26 bytes of zero header fields.
    data.extend_from_slice(&[0u8; 26]);
    // Now data.len() == 34; push lib_name_len = 50, but no name bytes follow.
    data.push(50);
    let err = parse_sig_header(&data).unwrap_err();
    assert!(matches!(err, FlirtError::ParseError(_)));
}

// ── SigPattern ──────────────────────────────────────────────────────────────

#[test]
fn sig_pattern_new_default_empty() {
    let p = SigPattern::new();
    assert!(p.bytes.is_empty());
    let d = SigPattern::default();
    assert!(d.bytes.is_empty());
}

#[test]
fn sig_pattern_matches_basic() {
    let mut p = SigPattern::new();
    p.bytes.push(SigPatternByte::Exact(1));
    p.bytes.push(SigPatternByte::Wildcard);
    p.bytes.push(SigPatternByte::Exact(3));
    assert!(p.matches(&[1, 99, 3, 4]));
    assert!(!p.matches(&[1, 99, 4]));
    assert!(!p.matches(&[1, 99]));
}

// ── FlirtDatabase ───────────────────────────────────────────────────────────

#[test]
fn database_empty() {
    let db = FlirtDatabase::new();
    assert_eq!(db.total_patterns(), 0);
    assert!(db.candidate_modules(&[1, 2, 3, 4]).is_empty());
}

#[test]
fn database_add_and_lookup() {
    let mut db = FlirtDatabase::new();
    let pat = FlirtPattern::new(vec![
        PatternByte::Exact(0xDE),
        PatternByte::Exact(0xAD),
        PatternByte::Exact(0xBE),
        PatternByte::Exact(0xEF),
        PatternByte::Exact(0x99),
    ]);
    let m = SigModule {
        library_name: "lib".into(),
        arch: FlirtArch::X64,
        file_types: FlirtFileType::ELF,
        patterns: vec![pat],
    };
    db.add_module(m);
    assert_eq!(db.total_patterns(), 1);

    let hits = db.candidate_modules(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], (0, 0));

    assert!(db.candidate_modules(&[0, 0, 0, 0]).is_empty());
}

#[test]
fn database_candidate_short_buf() {
    let db = FlirtDatabase::new();
    assert!(db.candidate_modules(&[1, 2, 3]).is_empty());
}

#[test]
fn database_pattern_with_early_wildcard_not_indexed() {
    let mut db = FlirtDatabase::new();
    // Wildcard within first 4 bytes -> shouldn't get indexed by 4-byte prefix.
    let pat = FlirtPattern::new(vec![
        PatternByte::Exact(0x11),
        PatternByte::Wildcard,
        PatternByte::Exact(0x33),
        PatternByte::Exact(0x44),
    ]);
    let m = SigModule {
        library_name: "lib".into(),
        arch: FlirtArch::X86,
        file_types: FlirtFileType::PE,
        patterns: vec![pat],
    };
    db.add_module(m);
    // Should NOT be indexed since prefix wasn't fully exact.
    assert!(db.candidate_modules(&[0x11, 0x22, 0x33, 0x44]).is_empty());
}

// ── FlirtLibrary serialize/deserialize round-trip ────────────────────────────

fn sample_pattern() -> FlirtPattern {
    let extra = [0xAB, 0xCD];
    let mut p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x8B),
        PatternByte::Wildcard,
        PatternByte::Exact(0xEC),
    ]);
    p.crc16 = crc16_flirt(&extra);
    p.crc_length = 2;
    p.pattern_length = 16;
    p.names.push(FlirtName {
        name: "foo".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    p.names.push(FlirtName {
        name: "bar".into(),
        offset: 4,
        is_public: false,
        is_local: true,
    });
    p.tail_bytes.push(TailByte { offset: 8, value: 0x90 });
    p.referenced_names.push(ReferencedName {
        offset: 12,
        name: "extern_sym".into(),
    });
    p
}

#[test]
fn library_new_defaults() {
    let lib = FlirtLibrary::new("test", FlirtArch::X64, FlirtOs::Linux);
    assert_eq!(lib.name, "test");
    assert_eq!(lib.version, 1);
    assert_eq!(lib.arch, FlirtArch::X64);
    assert_eq!(lib.os, FlirtOs::Linux);
    assert_eq!(lib.pattern_count(), 0);
}

#[test]
fn library_add_pattern_increments() {
    let mut lib = FlirtLibrary::new("t", FlirtArch::X86, FlirtOs::Windows);
    lib.add_pattern(sample_pattern());
    lib.add_pattern(sample_pattern());
    assert_eq!(lib.pattern_count(), 2);
}

#[test]
fn library_serialize_starts_with_header() {
    let lib = FlirtLibrary::new("L", FlirtArch::X64, FlirtOs::Linux);
    let s = lib.serialize();
    assert!(s.starts_with("FLIRT 1"));
    assert!(s.contains("name L"));
    assert!(s.contains("arch x86_64"));
    assert!(s.contains("os linux"));
    assert!(s.contains("---"));
}

#[test]
fn library_deserialize_empty_body() {
    let lib = FlirtLibrary::new("X", FlirtArch::Arm64, FlirtOs::Android);
    let s = lib.serialize();
    let out = FlirtLibrary::deserialize(&s).expect("deserialize");
    assert_eq!(out.name, "X");
    assert_eq!(out.arch, FlirtArch::Arm64);
    assert_eq!(out.os, FlirtOs::Android);
    assert_eq!(out.pattern_count(), 0);
}

fn deser_err(s: &str) -> FlirtError {
    match FlirtLibrary::deserialize(s) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    }
}

#[test]
fn library_deserialize_bad_header() {
    assert!(matches!(
        deser_err("not a flirt file"),
        FlirtError::ParseError(_)
    ));
}

#[test]
fn library_deserialize_empty() {
    assert!(matches!(deser_err(""), FlirtError::ParseError(_)));
}

#[test]
fn library_deserialize_wrong_version() {
    let s = "FLIRT 2\nname x\narch x86\nos linux\ndesc d\n---\n";
    assert!(matches!(deser_err(s), FlirtError::UnsupportedVersion(2)));
}

#[test]
fn library_deserialize_missing_sep() {
    let s = "FLIRT 1\nname x\narch x86\nos linux\ndesc d\n";
    assert!(matches!(deser_err(s), FlirtError::ParseError(_)));
}

#[test]
fn library_roundtrip_with_patterns() {
    let mut lib = FlirtLibrary::new("rt", FlirtArch::X64, FlirtOs::Linux);
    lib.description = "test lib".into();
    lib.add_pattern(sample_pattern());

    let s = lib.serialize();
    let out = FlirtLibrary::deserialize(&s).expect("deserialize");
    assert_eq!(out.name, "rt");
    assert_eq!(out.description, "test lib");
    assert_eq!(out.pattern_count(), 1);

    let p = &out.patterns[0];
    assert_eq!(p.initial_bytes.len(), 4);
    assert_eq!(p.crc_length, 2);
    assert_eq!(p.pattern_length, 16);
    assert_eq!(p.names.len(), 2);
    assert_eq!(p.tail_bytes.len(), 1);
    assert_eq!(p.tail_bytes[0].offset, 8);
    assert_eq!(p.tail_bytes[0].value, 0x90);
    assert_eq!(p.referenced_names.len(), 1);
    assert_eq!(p.referenced_names[0].name, "extern_sym");
    // Primary name preserved
    assert_eq!(p.primary_name(), Some("foo"));
    // Local flag preserved on second name
    let bar = p.names.iter().find(|n| n.name == "bar").expect("bar");
    assert!(bar.is_local);
    assert!(!bar.is_public);
}

// ── FlirtTrie ────────────────────────────────────────────────────────────────

#[test]
fn trie_empty() {
    let t = FlirtTrie::new();
    assert_eq!(t.total_patterns(), 0);
    assert!(t.find_candidates(&[1, 2, 3]).is_empty());
    let d = FlirtTrie::default();
    assert_eq!(d.total_patterns(), 0);
}

#[test]
fn trie_finds_matching_pattern() {
    let mut lib = FlirtLibrary::new("l", FlirtArch::X86, FlirtOs::Linux);
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x8B),
    ]));
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0xC3),
    ]));
    let trie = FlirtTrie::build(&lib);
    assert_eq!(trie.total_patterns(), 2);

    let c = trie.find_candidates(&[0x55, 0x8B, 0xEC]);
    assert!(c.contains(&0));

    let c2 = trie.find_candidates(&[0xC3, 0, 0]);
    assert!(c2.contains(&1));
}

#[test]
fn trie_wildcard_matches_anything() {
    let mut lib = FlirtLibrary::new("l", FlirtArch::X86, FlirtOs::Linux);
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0x90),
        PatternByte::Wildcard,
        PatternByte::Exact(0xC3),
    ]));
    let trie = FlirtTrie::build(&lib);
    let c = trie.find_candidates(&[0x90, 0xFF, 0xC3]);
    assert!(c.contains(&0));
    let c2 = trie.find_candidates(&[0x90, 0x00, 0xC3]);
    assert!(c2.contains(&0));
}

#[test]
fn trie_no_false_positive() {
    let mut lib = FlirtLibrary::new("l", FlirtArch::X86, FlirtOs::Linux);
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0xAA),
        PatternByte::Exact(0xBB),
    ]));
    let trie = FlirtTrie::build(&lib);
    let c = trie.find_candidates(&[0xAA, 0xCC]);
    assert!(!c.contains(&0));
}

// ── FlirtMatcher ─────────────────────────────────────────────────────────────

#[test]
fn matcher_empty_defaults() {
    let m = FlirtMatcher::new();
    assert_eq!(m.library_count(), 0);
    assert_eq!(m.pattern_count(), 0);
    assert_eq!(m.min_bytes_needed(), 1);
    let d = FlirtMatcher::default();
    assert_eq!(d.library_count(), 0);
}

fn build_matcher_with_one() -> FlirtMatcher {
    let mut lib = FlirtLibrary::new("libc", FlirtArch::X64, FlirtOs::Linux);
    let extra = [0x11u8, 0x22, 0x33];
    let mut p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x48),
        PatternByte::Exact(0x89),
        PatternByte::Exact(0xE5),
    ]);
    p.crc_length = 3;
    p.crc16 = crc16_flirt(&extra);
    p.names.push(FlirtName {
        name: "main".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    lib.add_pattern(p);
    let mut m = FlirtMatcher::new();
    m.add_library(lib);
    m
}

#[test]
fn matcher_counts() {
    let m = build_matcher_with_one();
    assert_eq!(m.library_count(), 1);
    assert_eq!(m.pattern_count(), 1);
    assert_eq!(m.min_bytes_needed(), 4);
}

#[test]
fn matcher_match_function_hit() {
    let m = build_matcher_with_one();
    let buf = [0x55, 0x48, 0x89, 0xE5, 0x11, 0x22, 0x33];
    let res = m.match_function(Address(0x1000), &buf);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name, "main");
    assert_eq!(res[0].address, Address(0x1000));
    assert_eq!(res[0].library, "libc");
    assert!(res[0].is_public);
    assert!((res[0].confidence - 1.0).abs() < 1e-6);
}

#[test]
fn matcher_match_function_miss() {
    let m = build_matcher_with_one();
    let buf = [0x55, 0x48, 0x89, 0xE5, 0x11, 0x22, 0x99]; // bad CRC tail
    assert!(m.match_function(Address(0x1000), &buf).is_empty());
}

#[test]
fn matcher_best_match_some() {
    let m = build_matcher_with_one();
    let buf = [0x55, 0x48, 0x89, 0xE5, 0x11, 0x22, 0x33];
    let best = m.best_match(Address(0x2000), &buf);
    assert!(best.is_some());
    assert_eq!(best.unwrap().name, "main");
}

#[test]
fn matcher_best_match_none() {
    let m = build_matcher_with_one();
    let buf = [0, 0, 0, 0];
    assert!(m.best_match(Address(0), &buf).is_none());
}

#[test]
fn matcher_match_all_filters_addresses_below_base() {
    let m = build_matcher_with_one();
    let buf = [0x55, 0x48, 0x89, 0xE5, 0x11, 0x22, 0x33];
    // fn_start below base -> skipped
    let r = m.match_all(Address(0x1000), &buf, &[Address(0x500)]);
    assert!(r.is_empty());
    // fn_start past buf end -> skipped
    let r = m.match_all(Address(0x1000), &buf, &[Address(0x1000 + 1000)]);
    assert!(r.is_empty());
    // valid
    let r = m.match_all(Address(0x1000), &buf, &[Address(0x1000)]);
    assert_eq!(r.len(), 1);
}

#[test]
fn matcher_no_crc_gives_lower_confidence() {
    let mut lib = FlirtLibrary::new("l", FlirtArch::X86, FlirtOs::Linux);
    let mut p = FlirtPattern::new(vec![
        PatternByte::Exact(0xC3),
    ]);
    p.names.push(FlirtName {
        name: "ret".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    lib.add_pattern(p);
    let mut m = FlirtMatcher::new();
    m.add_library(lib);
    let r = m.match_function(Address(0), &[0xC3, 0]);
    assert_eq!(r.len(), 1);
    assert!((r[0].confidence - 0.9).abs() < 1e-6);
}

// ── FlirtSigSerializer ──────────────────────────────────────────────────────

#[test]
fn sig_serializer_header_starts_with_magic() {
    let lib = FlirtLibrary::new("z", FlirtArch::X64, FlirtOs::Linux);
    let out = FlirtSigSerializer::write_header(&lib);
    assert!(out.starts_with(b"IDASGN"));
    assert_eq!(out[6], 9); // version
    assert_eq!(out[7], FlirtArch::X64.to_u8());
}

// ── FlirtError display ──────────────────────────────────────────────────────

#[test]
fn flirt_error_display() {
    let e = FlirtError::InvalidPattern("x".into());
    assert!(e.to_string().contains("invalid pattern"));
    let e = FlirtError::UnsupportedVersion(7);
    assert!(e.to_string().contains('7'));
    let e = FlirtError::IndexOutOfRange(42);
    assert!(e.to_string().contains("42"));
    let e = FlirtError::InvalidSigMagic;
    assert_eq!(e.to_string(), "invalid sig magic");
}
