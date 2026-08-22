//! Deep adversarial blitz tests for rustre-flirt (lib.rs public surface).

use rustre_core::address::Address;
use rustre_flirt::*;
use std::sync::Arc;

// Seeded LCG for deterministic fuzz inputs.
fn lcg_seq(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push((s >> 32) as u8);
    }
    out
}

// ── crc16_flirt round-trip / boundary ────────────────────────────────────────

#[test]
fn crc16_flirt_boundaries() {
    // MCRF4XX: no final XOR, so empty input returns the init value (see TODO T1).
    assert_eq!(crc16_flirt(&[]), 0xFFFF);
    let a = crc16_flirt(&[0]);
    let b = crc16_flirt(&[0xFF]);
    assert_ne!(a, b);
    // 1-byte CRC differs over all 256 values
    let mut seen = std::collections::HashSet::new();
    for v in 0..=255u8 {
        seen.insert(crc16_flirt(&[v]));
    }
    assert!(seen.len() > 200);
}

#[test]
fn crc16_flirt_fuzz_never_panics() {
    for seed in 0..50u64 {
        let buf = lcg_seq(seed.wrapping_add(0xDEAD_BEEF_CAFE_BABE), 32 + (seed as usize % 256));
        let c = crc16_flirt(&buf);
        // sanity: a second computation matches
        assert_eq!(c, crc16_flirt(&buf));
    }
}

#[test]
fn crc16_ibm_fuzz() {
    for seed in 0..50u64 {
        let buf = lcg_seq(seed.wrapping_mul(7) ^ 0xCAFE, 17 + seed as usize % 100);
        assert_eq!(crc16_ibm(&buf), crc16_ibm(&buf));
    }
    assert_eq!(crc16_ibm(&[]), 0);
}

// ── PatternByte / FlirtPattern ──────────────────────────────────────────────

#[test]
fn pattern_byte_eq() {
    assert_eq!(PatternByte::Exact(5), PatternByte::Exact(5));
    assert_ne!(PatternByte::Exact(5), PatternByte::Exact(6));
    assert_ne!(PatternByte::Exact(5), PatternByte::Wildcard);
    assert_eq!(PatternByte::Wildcard, PatternByte::Wildcard);
}

#[test]
fn flirt_pattern_new_minimal() {
    let p = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
    assert!(p.matches_initial(&[0x55]));
    assert!(!p.matches_initial(&[0x56]));
    assert!(!p.matches_initial(&[])); // too short
    assert!(p.matches_crc16(&[])); // crc_length=0 => true
    assert!(p.matches_tail(&[])); // no tail
    assert_eq!(p.primary_name(), None);
}

#[test]
fn flirt_pattern_wildcard_ratio() {
    let p = FlirtPattern::new(vec![]);
    assert_eq!(p.wildcard_ratio(), 0.0);
    let p2 = FlirtPattern::new(vec![PatternByte::Wildcard, PatternByte::Exact(1)]);
    assert!((p2.wildcard_ratio() - 0.5).abs() < 1e-6);
    let p3 = FlirtPattern::new(vec![PatternByte::Wildcard, PatternByte::Wildcard]);
    assert!((p3.wildcard_ratio() - 1.0).abs() < 1e-6);
}

#[test]
fn flirt_pattern_hex_render() {
    let p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Wildcard,
        PatternByte::Exact(0xEC),
    ]);
    assert_eq!(p.pattern_hex(), "55 .. EC");
}

#[test]
fn flirt_pattern_matches_initial_fuzz() {
    let p = FlirtPattern::new(vec![
        PatternByte::Exact(0xAA),
        PatternByte::Wildcard,
        PatternByte::Exact(0xCC),
    ]);
    for seed in 0..40u64 {
        let buf = lcg_seq(seed ^ 0x1234, 8);
        let expected = buf.len() >= 3 && buf[0] == 0xAA && buf[2] == 0xCC;
        assert_eq!(p.matches_initial(&buf), expected, "seed={seed}");
    }
    // Forced positive
    assert!(p.matches_initial(&[0xAA, 0x99, 0xCC, 0xFF]));
}

#[test]
fn flirt_pattern_crc_check() {
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let crc = crc16_flirt(&data[2..6]);
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x01), PatternByte::Exact(0x02)]);
    p.crc_length = 4;
    p.crc16 = crc;
    assert!(p.matches_crc16(&data));
    // truncated buffer
    assert!(!p.matches_crc16(&data[..3]));
    // wrong crc
    p.crc16 ^= 0xFFFF;
    assert!(!p.matches_crc16(&data));
}

#[test]
fn flirt_pattern_tail_check() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
    p.tail_bytes = vec![TailByte { offset: 4, value: 0xAB }];
    assert!(p.matches_tail(&[0, 0, 0, 0, 0xAB]));
    assert!(!p.matches_tail(&[0, 0, 0, 0, 0xAC]));
    assert!(!p.matches_tail(&[0, 0, 0])); // out of range
}

#[test]
fn flirt_pattern_primary_and_all_names() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(1)]);
    p.names.push(FlirtName {
        name: "local".into(),
        offset: 4,
        is_public: false,
        is_local: true,
    });
    p.names.push(FlirtName {
        name: "pub_name".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    assert_eq!(p.primary_name(), Some("pub_name"));
    assert_eq!(p.all_names().count(), 2);
}

#[test]
fn flirt_pattern_matches_all_combo() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Exact(0x8B)]);
    let data = [0x55, 0x8B, 0xEC, 0xC3, 0xAA];
    p.crc_length = 2;
    p.crc16 = crc16_flirt(&data[2..4]);
    p.tail_bytes = vec![TailByte { offset: 4, value: 0xAA }];
    assert!(p.matches_all(&data));
    let mut bad = data;
    bad[4] = 0xBB;
    assert!(!p.matches_all(&bad));
}

// ── FlirtArch ──────────────────────────────────────────────────────────────

#[test]
fn flirt_arch_from_u8_known() {
    assert_eq!(FlirtArch::from_u8(0), FlirtArch::X86);
    assert_eq!(FlirtArch::from_u8(132), FlirtArch::X64);
    assert_eq!(FlirtArch::from_u8(19), FlirtArch::Arm);
    assert_eq!(FlirtArch::from_u8(128), FlirtArch::Arm64);
    assert_eq!(FlirtArch::from_u8(254), FlirtArch::Unknown);
    assert_eq!(FlirtArch::from_u8(99), FlirtArch::Unknown);
}

#[test]
fn flirt_arch_to_u8_round_trip() {
    for v in [0u8, 1, 8, 18, 19, 50, 128, 129, 130, 131, 132] {
        let a = FlirtArch::from_u8(v);
        if a != FlirtArch::Unknown {
            assert_eq!(a.to_u8(), v);
        }
    }
}

// ── FlirtFileType bitflags ─────────────────────────────────────────────────

#[test]
fn flirt_file_type_bits_contains() {
    let ft = FlirtFileType::from_u32(
        FlirtFileType::ELF.bits() | FlirtFileType::PE.bits(),
    );
    assert!(ft.contains(FlirtFileType::ELF));
    assert!(ft.contains(FlirtFileType::PE));
    assert!(!ft.contains(FlirtFileType::COFF));
    assert_eq!(ft.bits(), 0x0004_0000 | 0x0000_0800);
}

// ── parse_sig_header ───────────────────────────────────────────────────────

#[test]
fn parse_sig_header_too_short() {
    assert!(matches!(
        parse_sig_header(&[]),
        Err(FlirtError::ParseError(_))
    ));
    assert!(matches!(
        parse_sig_header(&[0u8; 10]),
        Err(FlirtError::ParseError(_))
    ));
}

#[test]
fn parse_sig_header_bad_magic() {
    let buf = vec![0u8; 64];
    assert!(matches!(
        parse_sig_header(&buf),
        Err(FlirtError::InvalidSigMagic)
    ));
}

#[test]
fn parse_sig_header_unsupported_version() {
    let mut buf = vec![0u8; 64];
    buf[0] = 0x54;
    buf[1] = 0x4A;
    buf[2] = 99; // bogus version
    assert!(matches!(
        parse_sig_header(&buf),
        Err(FlirtError::UnsupportedVersion(99))
    ));
}

#[test]
fn parse_sig_header_minimal_v6() {
    // Build a minimal header for v6 with "TJ" magic.
    let mut buf = vec![0u8; 64];
    buf[0] = 0x54;
    buf[1] = 0x4A;
    buf[2] = 6;
    buf[3] = 0; // arch X86
    // file types LE at offset 4..8
    buf[4..8].copy_from_slice(&FlirtFileType::PE.bits().to_le_bytes());
    // library name length at offset 30
    buf[30] = 3;
    buf[31] = b'l';
    buf[32] = b'i';
    buf[33] = b'b';
    let (hdr, off) = parse_sig_header(&buf).expect("should parse");
    assert_eq!(hdr.version, 6);
    assert_eq!(hdr.arch, FlirtArch::X86);
    assert_eq!(hdr.library_name, "lib");
    assert!(off >= 34);
}

#[test]
fn parse_sig_header_idasgn_magic() {
    let mut buf = vec![0u8; 64];
    buf[..6].copy_from_slice(b"IDASGN");
    buf[6] = 8;
    buf[7] = 132; // X64 arch byte
    buf[7 + 1..7 + 5].copy_from_slice(&FlirtFileType::ELF.bits().to_le_bytes());
    buf[7 + 27] = 0;
    let (hdr, _) = parse_sig_header(&buf).expect("parse");
    assert_eq!(hdr.version, 8);
    assert_eq!(hdr.arch, FlirtArch::X64);
}

#[test]
fn parse_sig_header_fuzz_no_panic() {
    for seed in 0..50u64 {
        let buf = lcg_seq(seed ^ 0xBEEF, 40);
        let _ = parse_sig_header(&buf);
    }
}

#[test]
fn parse_sig_header_truncated_lib_name() {
    let mut buf = vec![0u8; 31];
    buf[0] = 0x54;
    buf[1] = 0x4A;
    buf[2] = 7;
    buf[30] = 200; // claim 200 bytes of lib name but buf is too short
    assert!(matches!(
        parse_sig_header(&buf),
        Err(FlirtError::ParseError(_))
    ));
}

// ── SigPattern matches ─────────────────────────────────────────────────────

#[test]
fn sig_pattern_matches_basic() {
    let mut p = SigPattern::new();
    p.bytes.push(SigPatternByte::Exact(0xAA));
    p.bytes.push(SigPatternByte::Wildcard);
    p.bytes.push(SigPatternByte::Exact(0xCC));
    assert!(p.matches(&[0xAA, 0xBB, 0xCC, 0x00]));
    assert!(!p.matches(&[0xAA, 0xBB, 0xCD]));
    assert!(!p.matches(&[0xAA, 0xBB])); // too short
}

#[test]
fn sig_pattern_default_empty_matches_anything() {
    let p = SigPattern::default();
    assert!(p.matches(&[]));
    assert!(p.matches(&[1, 2, 3]));
}

// ── FlirtSigFile::parse ────────────────────────────────────────────────────

#[test]
fn flirt_sig_file_parse_minimal() {
    let mut buf = vec![0u8; 80];
    buf[0] = 0x54;
    buf[1] = 0x4A;
    buf[2] = 9;
    buf[30] = 0;
    let f = FlirtSigFile::parse(&buf).expect("ok");
    assert_eq!(f.header.version, 9);
}

#[test]
fn flirt_sig_file_parse_fuzz() {
    for seed in 0..40u64 {
        let buf = lcg_seq(seed ^ 0xABCD, 100);
        let _ = FlirtSigFile::parse(&buf);
    }
}

// ── FlirtDatabase ──────────────────────────────────────────────────────────

#[test]
fn flirt_database_empty() {
    let db = FlirtDatabase::new();
    assert_eq!(db.total_patterns(), 0);
    assert!(db.candidate_modules(&[1, 2, 3, 4]).is_empty());
    assert!(db.candidate_modules(&[1, 2]).is_empty()); // short
}

#[test]
fn flirt_database_add_and_query() {
    let mut db = FlirtDatabase::new();
    let mut m = SigModule {
        library_name: "x".into(),
        arch: FlirtArch::X64,
        file_types: FlirtFileType::ELF,
        patterns: Vec::new(),
    };
    m.patterns.push(FlirtPattern::new(vec![
        PatternByte::Exact(0xDE),
        PatternByte::Exact(0xAD),
        PatternByte::Exact(0xBE),
        PatternByte::Exact(0xEF),
    ]));
    // Wildcard at front → not indexed.
    m.patterns.push(FlirtPattern::new(vec![
        PatternByte::Wildcard,
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x66),
        PatternByte::Exact(0x77),
    ]));
    db.add_module(m);
    assert_eq!(db.total_patterns(), 2);
    let c = db.candidate_modules(&[0xDE, 0xAD, 0xBE, 0xEF, 0]);
    assert_eq!(c.len(), 1);
    let none = db.candidate_modules(&[0, 0, 0, 0]);
    assert!(none.is_empty());
}

// ── FlirtLibrary serialize/deserialize round-trip ──────────────────────────

fn make_library() -> FlirtLibrary {
    let mut lib = FlirtLibrary::new("libc", FlirtArch::X64, FlirtOs::Linux);
    lib.description = "test".into();
    let mut p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Wildcard,
        PatternByte::Exact(0xC3),
    ]);
    p.crc16 = 0xABCD;
    p.crc_length = 4;
    p.pattern_length = 32;
    p.names.push(FlirtName {
        name: "foo".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    p.tail_bytes.push(TailByte { offset: 7, value: 0x90 });
    p.referenced_names.push(ReferencedName {
        offset: 5,
        name: "bar".into(),
    });
    lib.add_pattern(p);
    lib
}

#[test]
fn flirt_library_round_trip() {
    let lib = make_library();
    let s = lib.serialize();
    let back = FlirtLibrary::deserialize(&s).expect("ok");
    assert_eq!(back.name, "libc");
    assert_eq!(back.arch, FlirtArch::X64);
    assert_eq!(back.os, FlirtOs::Linux);
    assert_eq!(back.description, "test");
    assert_eq!(back.patterns.len(), 1);
    let p = &back.patterns[0];
    assert_eq!(p.crc16, 0xABCD);
    assert_eq!(p.crc_length, 4);
    assert_eq!(p.pattern_length, 32);
    assert_eq!(p.names.len(), 1);
    assert_eq!(p.names[0].name, "foo");
    assert!(p.names[0].is_public);
    assert_eq!(p.tail_bytes.len(), 1);
    assert_eq!(p.tail_bytes[0].offset, 7);
    assert_eq!(p.tail_bytes[0].value, 0x90);
    assert_eq!(p.referenced_names.len(), 1);
    assert_eq!(p.referenced_names[0].name, "bar");
}

#[test]
fn flirt_library_deserialize_empty_err() {
    assert!(FlirtLibrary::deserialize("").is_err());
}

#[test]
fn flirt_library_deserialize_bad_version() {
    let s = "FLIRT 99\nname x\narch x86\nos linux\ndesc d\n---\n";
    assert!(matches!(
        FlirtLibrary::deserialize(s),
        Err(FlirtError::UnsupportedVersion(99))
    ));
}

#[test]
fn flirt_library_deserialize_missing_separator() {
    let s = "FLIRT 1\nname x\narch x86\nos linux\ndesc d\n";
    assert!(FlirtLibrary::deserialize(s).is_err());
}

#[test]
fn flirt_library_pattern_count_grows() {
    let mut lib = FlirtLibrary::new("z", FlirtArch::X86, FlirtOs::Windows);
    assert_eq!(lib.pattern_count(), 0);
    for _ in 0..5 {
        lib.add_pattern(FlirtPattern::new(vec![PatternByte::Exact(1)]));
    }
    assert_eq!(lib.pattern_count(), 5);
}

// ── FlirtTrie ──────────────────────────────────────────────────────────────

#[test]
fn flirt_trie_empty() {
    let t = FlirtTrie::new();
    assert_eq!(t.total_patterns(), 0);
    assert!(t.find_candidates(&[1, 2, 3]).is_empty());
}

#[test]
fn flirt_trie_find_candidates() {
    let mut lib = FlirtLibrary::new("x", FlirtArch::X64, FlirtOs::Unknown);
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x8B),
    ]));
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Wildcard,
    ]));
    lib.add_pattern(FlirtPattern::new(vec![
        PatternByte::Exact(0x90),
        PatternByte::Exact(0x90),
    ]));
    let trie = FlirtTrie::build(&lib);
    assert_eq!(trie.total_patterns(), 3);
    let c = trie.find_candidates(&[0x55, 0x8B, 0xEC]);
    // Both 0x55 patterns are candidates.
    assert_eq!(c.len(), 2);
    let c2 = trie.find_candidates(&[0x90, 0x90, 0x90]);
    assert_eq!(c2, vec![2]);
    let c3 = trie.find_candidates(&[0x11, 0x22, 0x33]);
    assert!(c3.is_empty());
}

// ── FlirtMatcher / FlirtMatch ──────────────────────────────────────────────

#[test]
fn flirt_matcher_empty() {
    let m = FlirtMatcher::new();
    assert_eq!(m.library_count(), 0);
    assert_eq!(m.pattern_count(), 0);
    assert_eq!(m.min_bytes_needed(), 1);
    assert!(m
        .match_function(Address::from(0x1000u64), &[0x55, 0x8B, 0xEC])
        .is_empty());
}

#[test]
fn flirt_matcher_add_and_match() {
    let mut lib = FlirtLibrary::new("L", FlirtArch::X64, FlirtOs::Unknown);
    let mut p = FlirtPattern::new(vec![
        PatternByte::Exact(0x55),
        PatternByte::Exact(0x8B),
        PatternByte::Exact(0xEC),
    ]);
    p.names.push(FlirtName {
        name: "winproc".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    lib.add_pattern(p);

    let mut m = FlirtMatcher::new();
    m.add_library(lib);
    assert_eq!(m.library_count(), 1);
    assert_eq!(m.pattern_count(), 1);
    assert_eq!(m.min_bytes_needed(), 3);

    let r = m.match_function(Address::from(0x1000u64), &[0x55, 0x8B, 0xEC, 0xC3]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "winproc");
    assert!(r[0].is_public);

    // No match
    let none = m.match_function(Address::from(0x2000u64), &[0xAA, 0xBB, 0xCC]);
    assert!(none.is_empty());
}

#[test]
fn flirt_matcher_best_match() {
    let m = builtin_matcher();
    // memset MSVC pattern: mov rax,rcx; test r8,r8; je
    let bytes = [0x48, 0x89, 0xC8, 0x4D, 0x85, 0xC0, 0x74, 0x10, 0x00, 0x00];
    let best = m.best_match(Address::from(0x1000u64), &bytes);
    assert!(best.is_some());
}

#[test]
fn flirt_matcher_match_all_skips_below_base() {
    let m = builtin_matcher();
    let base = Address::from(0x2000u64);
    let bytes = vec![0u8; 64];
    // include a fn_addr below base – should be skipped
    let starts = vec![Address::from(0x1000u64), Address::from(0x2000u64)];
    let r = m.match_all(base, &bytes, &starts);
    assert!(r.is_empty());
}

// ── builtin_crt_library_x64 / builtin_matcher ──────────────────────────────

#[test]
fn builtin_crt_library_has_patterns() {
    let lib = builtin_crt_library_x64();
    assert!(lib.pattern_count() >= 20);
    assert_eq!(lib.arch, FlirtArch::X64);
    let names: std::collections::HashSet<_> = lib
        .patterns
        .iter()
        .filter_map(|p| p.primary_name())
        .collect();
    for needed in [
        "memcpy", "memset", "memmove", "memcmp", "malloc", "free", "calloc", "realloc",
        "strlen", "strcmp", "strcpy", "strncpy", "strcat", "strncmp", "sprintf", "printf",
        "puts", "fopen", "fclose", "fread", "fwrite", "exit",
    ] {
        assert!(names.contains(needed), "missing {needed}");
    }
}

// ── FlirtSigSerializer ─────────────────────────────────────────────────────

#[test]
fn flirt_sig_serializer_header_basic() {
    let lib = builtin_crt_library_x64();
    let hdr = FlirtSigSerializer::write_header(&lib);
    assert!(hdr.starts_with(b"IDASGN"));
    assert_eq!(hdr[6], 9);
    // The CRC helper is deterministic.
    let c1 = FlirtSigSerializer::header_crc16(&hdr);
    let c2 = FlirtSigSerializer::header_crc16(&hdr);
    assert_eq!(c1, c2);
}

// ── PatternStats ───────────────────────────────────────────────────────────

#[test]
fn pattern_stats_empty_lib() {
    let lib = FlirtLibrary::new("e", FlirtArch::X86, FlirtOs::Unknown);
    let s = PatternStats::from_library(&lib);
    assert_eq!(s.total, 0);
    assert_eq!(s.with_crc, 0);
    assert_eq!(s.unnamed, 0);
    assert_eq!(s.with_tail, 0);
}

#[test]
fn pattern_stats_builtin() {
    let lib = builtin_crt_library_x64();
    let s = PatternStats::from_library(&lib);
    assert_eq!(s.total, lib.pattern_count());
    assert!((0.0..=1.0).contains(&s.avg_wildcard_ratio));
}

// ── FlirtSig / SimpleFlirtDatabase ─────────────────────────────────────────

#[test]
fn flirt_sig_from_hex_pattern_round_trip() {
    let sig = FlirtSig::from_hex_pattern("memcpy", "55 ?? 8B EC ??").unwrap();
    let s = sig.to_hex_pattern();
    assert_eq!(s, "55 ?? 8B EC ??");
    assert_eq!(sig.pattern_len(), 5);
    assert_eq!(sig.exact_byte_count(), 3);
    assert!(sig.matches(&[0x55, 0xAA, 0x8B, 0xEC, 0xFF]));
    assert!(!sig.matches(&[0x55, 0xAA, 0x8B, 0xED, 0xFF]));
}

#[test]
fn flirt_sig_from_hex_pattern_errors() {
    assert!(matches!(
        FlirtSig::from_hex_pattern("x", ""),
        Err(FlirtError::InvalidPattern(_))
    ));
    assert!(matches!(
        FlirtSig::from_hex_pattern("x", "GG"),
        Err(FlirtError::InvalidPattern(_))
    ));
}

#[test]
fn flirt_sig_match_at_offset_bounds() {
    let sig = FlirtSig::from_hex_pattern("x", "AA BB").unwrap();
    assert!(!sig.match_at_offset(&[0xAA], 0)); // too short
    assert!(sig.match_at_offset(&[0x00, 0xAA, 0xBB], 1));
    assert!(!sig.match_at_offset(&[0x00, 0xAA, 0xBB], 2)); // off+pat>data
}

#[test]
fn flirt_sig_display() {
    let sig = FlirtSig::from_hex_pattern("foo", "01 02").unwrap();
    let s = format!("{sig}");
    assert!(s.contains("foo"));
    assert!(s.contains("01 02"));
}

#[test]
fn flirt_sig_empty_pattern_never_matches() {
    let sig = FlirtSig::new("x", vec![], vec![]);
    assert!(!sig.matches(&[1, 2, 3]));
}

#[test]
#[should_panic]
fn flirt_sig_mismatched_mask_should_panic() {
    let _ = FlirtSig::new("x", vec![1, 2], vec![1]);
}

#[test]
fn simple_flirt_db_empty() {
    let db = SimpleFlirtDatabase::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
    assert!(db.query(&[1, 2, 3]).is_none());
    assert!(db.scan(&[1, 2, 3]).is_none());
}

#[test]
fn simple_flirt_db_parse_pat_text_ignores_comments_and_terminator() {
    let txt = "\
; comment line
55 8B EC C3 ABCD 4 32 foo@0+pub
---
55 90 90 90 9999 0 32 ignored
";
    let db = SimpleFlirtDatabase::parse_pat_text(txt);
    assert_eq!(db.len(), 1);
    assert_eq!(db.sigs[0].name, "foo");
}

#[test]
fn simple_flirt_db_query_and_scan() {
    let txt = "55 8B EC 0000 0 32 myfn@0\n";
    let db = SimpleFlirtDatabase::parse_pat_text(txt);
    assert_eq!(db.len(), 1);
    assert!(db.query(&[0x55, 0x8B, 0xEC, 0xFF]).is_some());
    let (off, _) = db.scan(&[0x00, 0x00, 0x55, 0x8B, 0xEC, 0x00]).unwrap();
    assert_eq!(off, 2);
}

#[test]
fn simple_flirt_db_query_all() {
    let txt = "55 8B EC 0000 0 32 a@0\n55 .. EC 0000 0 32 b@0\n";
    let db = SimpleFlirtDatabase::parse_pat_text(txt);
    let r = db.query_all(&[0x55, 0x8B, 0xEC, 0x00]);
    assert_eq!(r.len(), 2);
}

#[test]
fn simple_flirt_db_parse_fuzz_no_panic() {
    for seed in 0..40u64 {
        let buf = lcg_seq(seed ^ 0xFEED, 200);
        let s = String::from_utf8_lossy(&buf).to_string();
        let _ = SimpleFlirtDatabase::parse_pat_text(&s);
    }
}

// ── FlirtSignatureBuilder ──────────────────────────────────────────────────

#[test]
fn flirt_signature_builder_basic() {
    let p = FlirtSignatureBuilder::new("memcpy")
        .bytes(&[0x48, 0x89])
        .wildcard(3)
        .bytes(&[0xC3])
        .crc(2, 3)
        .tail_byte(10, 0xAB)
        .reference(7, "memmove")
        .build();
    assert_eq!(p.primary_name(), Some("memcpy"));
    assert_eq!(p.initial_bytes.len(), 6);
    assert_eq!(p.crc_length, 3);
    assert_eq!(p.tail_bytes.len(), 1);
    assert_eq!(p.referenced_names.len(), 1);
    assert_eq!(p.pattern_length, 6);
}

#[test]
fn flirt_signature_builder_no_crc_yields_zero() {
    let p = FlirtSignatureBuilder::new("x").bytes(&[0x01, 0x02]).build();
    assert_eq!(p.crc16, 0);
    assert_eq!(p.crc_length, 0);
}

// ── FlirtSignatureCompressor / Decompressor ─────────────────────────────────

#[test]
fn compressor_round_trip() {
    let patterns = vec![
        FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Exact(0x8B)]),
        FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Exact(0x89)]),
        FlirtPattern::new(vec![PatternByte::Wildcard, PatternByte::Exact(0xC3)]),
    ];
    let trie = FlirtSignatureCompressor::build_trie(&patterns);
    let dec = FlirtSignatureDecompressor::decompress(&trie);
    assert_eq!(dec.len(), patterns.len());
    for (idx, bytes) in &dec {
        assert_eq!(bytes, &patterns[*idx].initial_bytes);
    }
}

#[test]
fn compressor_trie_match() {
    let patterns = vec![
        FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Exact(0x8B)]),
        FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Exact(0x89)]),
    ];
    let trie = FlirtSignatureCompressor::build_trie(&patterns);
    let r = FlirtSignatureCompressor::trie_match(&trie, &[0x55, 0x8B, 0xEC], &patterns);
    assert_eq!(r.len(), 1);
}

// ── FlirtLibrarySet ────────────────────────────────────────────────────────

#[test]
fn library_set_stats() {
    let mut set = FlirtLibrarySet::new();
    assert!(set.is_empty());
    set.add_library("L1".into(), make_library());
    set.add_library("L2".into(), make_library());
    let stats = set.stats();
    assert_eq!(stats.libraries, 2);
    assert_eq!(stats.total_sigs, 2);
    assert_eq!(stats.with_crc, 2);
    assert_eq!(stats.with_tail, 2);
    assert_eq!(set.len(), 2);
}

#[test]
fn library_set_match_all() {
    let mut lib = FlirtLibrary::new("Z", FlirtArch::X64, FlirtOs::Unknown);
    lib.add_pattern(FlirtPattern::new(vec![PatternByte::Exact(0x55)]));
    let mut set = FlirtLibrarySet::new();
    set.add_library("Z".into(), lib);
    let r = set.match_all(&[0x55, 0xFF]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].library_name, "Z");
    assert_eq!(r[0].pattern_index, 0);

    let none = set.match_all(&[0x90]);
    assert!(none.is_empty());
}

// ── FlirtPatternExporter ──────────────────────────────────────────────────

#[test]
fn pattern_exporter_named_and_unnamed() {
    let mut p = FlirtPattern::new(vec![PatternByte::Exact(0x55), PatternByte::Wildcard]);
    p.crc16 = 0xABCD;
    p.crc_length = 4;
    p.pattern_length = 32;
    p.names.push(FlirtName {
        name: "foo".into(),
        offset: 0,
        is_public: true,
        is_local: false,
    });
    let line = FlirtPatternExporter::to_pat_line(&p);
    assert!(line.starts_with("55 .."));
    assert!(line.contains("ABCD"));
    assert!(line.contains("foo@0+pub"));

    let p2 = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
    let line2 = FlirtPatternExporter::to_pat_line(&p2);
    assert!(line2.contains("(unnamed)"));
}

#[test]
fn pattern_exporter_full_file_ends_with_terminator() {
    let lib = builtin_crt_library_x64();
    let file = FlirtPatternExporter::to_pat_file(&lib.patterns);
    assert!(file.trim_end().ends_with("---"));
    // each line maps to one pattern
    let line_count = file.lines().filter(|l| !l.is_empty() && *l != "---").count();
    assert_eq!(line_count, lib.patterns.len());
}

// ── Crc16Cache ─────────────────────────────────────────────────────────────

#[test]
fn crc16_cache_hits_and_misses() {
    let mut c = Crc16Cache::new();
    let data = b"hello world";
    let a = c.compute(data);
    let b = c.compute(data);
    assert_eq!(a, b);
    assert_eq!(c.hits(), 1);
    assert_eq!(c.misses(), 1);
    assert_eq!(c.total(), 2);
    assert_eq!(c.cache_size(), 1);
    c.clear();
    assert_eq!(c.cache_size(), 0);
    assert_eq!(c.total(), 0);
}

// ── FlirtMatchContext ──────────────────────────────────────────────────────

#[test]
fn flirt_match_context_counters() {
    let mut ctx = FlirtMatchContext::new();
    ctx.record_scan();
    ctx.record_scan();
    ctx.record_match();
    ctx.record_false_positive();
    assert_eq!(ctx.scanned_functions, 2);
    assert_eq!(ctx.matched_functions, 1);
    assert_eq!(ctx.false_positives_rejected, 1);
}

// ── FlirtApplier integration ───────────────────────────────────────────────

struct TestView<'a> {
    base: u64,
    data: &'a [u8],
}
impl FlirtByteView for TestView<'_> {
    fn read_bytes(&self, address: Address, len: usize) -> Option<&[u8]> {
        let abs: u64 = address.into();
        if abs < self.base {
            return None;
        }
        let off = (abs - self.base) as usize;
        if off >= self.data.len() {
            return None;
        }
        let end = (off + len).min(self.data.len());
        Some(&self.data[off..end])
    }
}

struct TestSymTab {
    fns: Vec<Address>,
    names: std::collections::HashMap<u64, String>,
}
impl FlirtSymbolTable for TestSymTab {
    fn function_addresses(&self) -> Vec<Address> {
        self.fns.clone()
    }
    fn name_at(&self, address: Address) -> Option<&str> {
        self.names.get(&u64::from(address)).map(String::as_str)
    }
    fn rename(&mut self, address: Address, new_name: &str) {
        self.names.insert(u64::from(address), new_name.to_string());
    }
}

#[test]
fn flirt_applier_renames_unknown() {
    let applier = FlirtApplier::with_builtin_sigs();
    // memset MSVC pattern bytes followed by filler
    let mut data = vec![0x48, 0x89, 0xC8, 0x4D, 0x85, 0xC0, 0x74, 0x10];
    data.extend(std::iter::repeat_n(0x90, 64));
    let view = TestView { base: 0x1000, data: &data };
    let mut syms = TestSymTab {
        fns: vec![Address::from(0x1000u64)],
        names: std::collections::HashMap::new(),
    };
    let res = applier.apply_to_view(&view, &mut syms);
    assert_eq!(res.functions_examined, 1);
    assert!(res.functions_renamed >= 1);
    assert!(syms.names.contains_key(&0x1000));
}

#[test]
fn flirt_applier_skips_user_named() {
    let applier = FlirtApplier::with_builtin_sigs();
    let mut data = vec![0x48, 0x89, 0xC8, 0x4D, 0x85, 0xC0, 0x74, 0x10];
    data.extend(std::iter::repeat_n(0x90, 64));
    let view = TestView { base: 0x1000, data: &data };
    let mut syms = TestSymTab {
        fns: vec![Address::from(0x1000u64)],
        names: {
            let mut m = std::collections::HashMap::new();
            m.insert(0x1000u64, "my_custom_name".into());
            m
        },
    };
    let res = applier.apply_to_view(&view, &mut syms);
    assert_eq!(res.functions_examined, 1);
    // Should not rename user-named symbols.
    assert_eq!(syms.names.get(&0x1000).map(String::as_str), Some("my_custom_name"));
    assert_eq!(res.functions_renamed, 0);
}

// ── Send/Sync threaded stress ──────────────────────────────────────────────

#[test]
fn matcher_send_sync_stress() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlirtMatcher>();
    assert_send_sync::<FlirtLibrary>();
    assert_send_sync::<FlirtPattern>();
    assert_send_sync::<FlirtSig>();

    let m = Arc::new(builtin_matcher());
    let mut handles = Vec::new();
    for tid in 0..4 {
        let m = m.clone();
        handles.push(std::thread::spawn(move || {
            let bytes = [0x48u8, 0x89, 0xC8, 0x4D, 0x85, 0xC0, 0x74, 0x10, 0, 0];
            for i in 0..100u64 {
                let addr = Address::from(0x1000u64 + tid * 0x100 + i);
                let r = m.match_function(addr, &bytes);
                // memset MSVC should be among matches
                assert!(!r.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── FlirtError variants smoke ──────────────────────────────────────────────

#[test]
fn flirt_error_display_variants() {
    let e1 = FlirtError::InvalidPattern("x".into());
    let e2 = FlirtError::ParseError("y".into());
    let e3 = FlirtError::UnsupportedVersion(7);
    let e4 = FlirtError::Io("z".into());
    let e5 = FlirtError::InvalidSigMagic;
    let e6 = FlirtError::SigHeaderCrcMismatch;
    let e7 = FlirtError::IndexOutOfRange(99);
    let e8 = FlirtError::Database("d".into());
    for e in [&e1, &e2, &e3, &e4, &e5, &e6, &e7, &e8] {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}
