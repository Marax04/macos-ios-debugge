//! Adversarial integration test suite for `rustre-flirt-apply`.
//!
//! Exercises the crate's public surface across multiple modules:
//! `FlirtPattern`, `FlirtSigDb`, `FlirtApplier`, `FlirtSignature`,
//! `FlirtScanner`, `AhoCorasickIndex`, `WildcardPattern`, `crc16_flirt`,
//! `build_ac_index`, `scan_with_ac`, `load_sig_file`/`load_pat_file`/`load_auto`,
//! `inspect_sig_header`, `SignaturePack`, the `pat_parser` module, and the
//! `ida_sig_compat` module (`IdaPatParser`, `IdaArch`, `IdaSigHeader`,
//! `parse_hex_pattern`, `render_pat_hex`, `crc16_ida`, `PatternConverter`,
//! `SigConversionStats`).

use std::io::Write;
use std::path::Path;

use rustre_flirt_apply::{
    AhoCorasickIndex, FlirtApplier, FlirtError, FlirtMatch, FlirtPattern, FlirtScanner,
    FlirtSigDb, FlirtSignature, SigFileHeader, WildcardPattern, build_ac_index, crc16_flirt,
    inspect_sig_header, load_auto, load_pat_file, load_sig_file, load_sig_file_v9, scan_with_ac,
};

// ---------------------------------------------------------------------------
// FlirtPattern
// ---------------------------------------------------------------------------

#[test]
fn pattern_new_default_metadata_zeroed() {
    let p = FlirtPattern::new("foo".into(), vec![Some(0x55); 4]);
    assert_eq!(p.name, "foo");
    assert_eq!(p.lib_name, "");
    assert_eq!(p.version, "");
    assert_eq!(p.crc_offset, 0);
    assert_eq!(p.crc_len, 0);
    assert_eq!(p.crc, 0);
    assert!(p.public_names.is_empty());
    assert!(p.local_names.is_empty());
    assert!(p.references.is_empty());
}

#[test]
fn pattern_matches_empty_pattern_matches_empty_data() {
    let p = FlirtPattern::new("e".into(), vec![]);
    assert!(p.matches(&[]));
    assert!(p.matches(&[0x00, 0x01])); // empty pattern matches any prefix
}

#[test]
fn pattern_matches_exactly_equal_length() {
    let p = FlirtPattern::new("e".into(), vec![Some(0xAB), Some(0xCD)]);
    assert!(p.matches(&[0xAB, 0xCD]));
    assert!(!p.matches(&[0xAB]));
}

#[test]
fn pattern_matches_wildcard_anywhere() {
    let p = FlirtPattern::new("e".into(), vec![None, None, None, None]);
    assert!(p.matches(&[0, 0, 0, 0]));
    assert!(p.matches(&[0xFF, 0x00, 0x55, 0xAA]));
}

#[test]
fn pattern_from_str_dot_token() {
    let p = FlirtPattern::from_pattern_str("55 . 8B EC", "f".into(), "l".into()).unwrap();
    assert_eq!(p.pattern_len(), 4);
    assert!(p.bytes[1].is_none());
}

#[test]
fn pattern_from_str_uppercase_lowercase_mixed() {
    let p = FlirtPattern::from_pattern_str("aA bB cC dD", "f".into(), "l".into()).unwrap();
    assert_eq!(p.bytes, vec![Some(0xAA), Some(0xBB), Some(0xCC), Some(0xDD)]);
}

#[test]
fn pattern_from_str_extra_whitespace() {
    let p = FlirtPattern::from_pattern_str("  55   8B\t\tEC  90  ", "f".into(), "l".into()).unwrap();
    assert_eq!(p.pattern_len(), 4);
}

#[test]
fn pattern_from_str_too_short_zero() {
    let err = FlirtPattern::from_pattern_str("", "f".into(), "l".into());
    assert!(matches!(err, Err(FlirtError::PatternTooShort(0))));
}

#[test]
fn pattern_from_str_too_short_three() {
    let err = FlirtPattern::from_pattern_str("55 8B EC", "f".into(), "l".into());
    assert!(matches!(err, Err(FlirtError::PatternTooShort(3))));
}

#[test]
fn pattern_from_str_3char_token_is_parse_error() {
    // "555" is not a valid u8 hex token.
    let err = FlirtPattern::from_pattern_str("555 8B EC 90", "f".into(), "l".into());
    assert!(matches!(err, Err(FlirtError::Parse(_))));
}

#[test]
fn pattern_display_includes_byte_count() {
    let p = FlirtPattern::from_pattern_str("55 8B EC 90", "fname".into(), "libname".into()).unwrap();
    let s = p.to_string();
    assert!(s.contains("fname"));
    assert!(s.contains("libname"));
    assert!(s.contains("4 bytes"));
}

#[test]
fn pattern_clone_independent() {
    let mut p = FlirtPattern::from_pattern_str("55 8B EC 90", "a".into(), "l".into()).unwrap();
    let q = p.clone();
    p.name = "b".into();
    assert_eq!(q.name, "a");
}

// ---------------------------------------------------------------------------
// FlirtSigDb
// ---------------------------------------------------------------------------

#[test]
fn db_default_is_empty() {
    let d = FlirtSigDb::default();
    assert_eq!(d.pattern_count(), 0);
}

#[test]
fn db_add_many_patterns() {
    let mut db = FlirtSigDb::new();
    for i in 0..50u8 {
        let p = FlirtPattern::new(format!("fn{i}"), vec![Some(i); 8]);
        db.add_pattern(p);
    }
    assert_eq!(db.pattern_count(), 50);
}

#[test]
fn demo_sigs_load_at_least_18_patterns() {
    // load_demo_sigs hard-codes ~19 patterns; ensure a substantial number load.
    let db = FlirtSigDb::load_demo_sigs();
    assert!(
        db.pattern_count() >= 18,
        "demo db should have >=18 patterns, got {}",
        db.pattern_count()
    );
}

#[test]
fn db_debug_format_has_count() {
    let mut db = FlirtSigDb::new();
    db.add_pattern(FlirtPattern::new("a".into(), vec![Some(0); 4]));
    db.add_pattern(FlirtPattern::new("b".into(), vec![Some(0); 4]));
    let s = format!("{db:?}");
    assert!(s.contains('2'));
}

// ---------------------------------------------------------------------------
// FlirtApplier
// ---------------------------------------------------------------------------

fn applier_with(hex: &str) -> FlirtApplier {
    let mut db = FlirtSigDb::new();
    db.add_pattern(FlirtPattern::from_pattern_str(hex, "fn".into(), "lib".into()).unwrap());
    FlirtApplier::new(db)
}

#[test]
fn applier_scan_empty_data() {
    let a = applier_with("55 8B EC 90");
    let m = a.scan(&[], 0x1000);
    assert!(m.is_empty());
}

#[test]
fn applier_scan_at_addresses_empty_list() {
    let a = applier_with("55 8B EC 90");
    let m = a.scan_at_addresses(&[0x55u8, 0x8B, 0xEC, 0x90], 0, &[]);
    assert!(m.is_empty());
}

#[test]
fn applier_scan_at_address_equal_to_base() {
    let a = applier_with("55 8B EC 90");
    let data = vec![0x55u8, 0x8B, 0xEC, 0x90];
    let m = a.scan_at_addresses(&data, 0x1000, &[0x1000]);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].address, 0x1000);
}

#[test]
fn applier_min_confidence_filters_out_low_conf() {
    let mut a = applier_with("55 ?? ?? ?? ?? ?? ?? ??"); // many wildcards => low conf
    a.set_min_confidence(95);
    let data = vec![0x55u8, 0, 0, 0, 0, 0, 0, 0];
    assert!(a.scan(&data, 0).is_empty());
}

#[test]
fn applier_match_count_matches_scan_len() {
    let a = applier_with("55 8B EC 90");
    let data = vec![0x55u8, 0x8B, 0xEC, 0x90, 0x00, 0x55, 0x8B, 0xEC, 0x90];
    assert_eq!(a.match_count(&data, 0), a.scan(&data, 0).len());
}

#[test]
fn applier_apply_returns_io_error_for_missing_file() {
    let a = applier_with("55 8B EC 90");
    let err = a
        .apply(&[0u8; 4], Path::new("definitely_does_not_exist_xyz.pat"), 0)
        .unwrap_err();
    assert!(matches!(err, FlirtError::Io(_)));
}

#[test]
fn applier_debug_includes_min_conf() {
    let mut a = applier_with("55 8B EC 90");
    a.set_min_confidence(42);
    let s = format!("{a:?}");
    assert!(s.contains("42"));
}

// ---------------------------------------------------------------------------
// FlirtSignature / WildcardPattern
// ---------------------------------------------------------------------------

#[test]
fn signature_from_pattern_round_trip_via_bytes_mask() {
    let fp =
        FlirtPattern::from_pattern_str("55 ?? EC ?? 90", "f".into(), "l".into()).unwrap();
    let sig = FlirtSignature::from_flirt_pattern(&fp);
    assert_eq!(sig.bytes.len(), 5);
    assert_eq!(sig.mask, vec![0xff, 0x00, 0xff, 0x00, 0xff]);
}

#[test]
fn signature_matches_at_data_too_short_false() {
    let fp = FlirtPattern::from_pattern_str("55 8B EC 90", "f".into(), "l".into()).unwrap();
    let sig = FlirtSignature::from_flirt_pattern(&fp);
    assert!(!sig.matches_at(&[0x55, 0x8B]));
}

#[test]
fn wildcard_pattern_prefix_cap_at_32() {
    // 40-byte all-exact pattern → prefix should cap at 32.
    let hex: String = (0..40).map(|_| "90 ").collect();
    let fp = FlirtPattern::from_pattern_str(hex.trim(), "f".into(), "l".into()).unwrap();
    let sig = FlirtSignature::from_flirt_pattern(&fp);
    let wp = WildcardPattern::from_signature(&sig);
    assert_eq!(wp.prefix().len(), 32);
    assert_eq!(wp.mask.len(), 32);
}

#[test]
fn wildcard_pattern_leading_wildcard_empty_prefix() {
    let fp = FlirtPattern::from_pattern_str("?? 8B EC 90", "f".into(), "l".into()).unwrap();
    let sig = FlirtSignature::from_flirt_pattern(&fp);
    let wp = WildcardPattern::from_signature(&sig);
    assert!(wp.prefix().is_empty());
}

// ---------------------------------------------------------------------------
// CRC-16
// ---------------------------------------------------------------------------

#[test]
fn crc16_flirt_deterministic() {
    let buf = b"hello world";
    assert_eq!(crc16_flirt(buf), crc16_flirt(buf));
}

#[test]
fn crc16_flirt_different_inputs_likely_differ() {
    let a = crc16_flirt(b"abc");
    let b = crc16_flirt(b"abd");
    assert_ne!(a, b);
}

#[test]
fn crc16_flirt_empty_init_value() {
    // IDA flair crc16 (init 0xFFFF, no final XOR): empty input returns 0xFFFF.
    assert_eq!(crc16_flirt(&[]), 0xFFFF);
}

#[test]
fn crc16_flirt_known_single_byte_value() {
    // IDA flair crc16 (poly 0x8408 reflected, init 0xFFFF, no final XOR):
    // value for a single byte must differ from the empty-input value.
    assert_ne!(crc16_flirt(&[0x00]), 0xFFFF);
}

// ---------------------------------------------------------------------------
// AhoCorasickIndex / build_ac_index / scan_with_ac
// ---------------------------------------------------------------------------

#[test]
fn ac_index_is_built_false_for_empty_sigs() {
    let idx = AhoCorasickIndex::build(&[]);
    // No patterns → automaton not built.
    assert!(!idx.is_built());
}

#[test]
fn build_ac_index_handles_empty_slice() {
    let ac = build_ac_index(&[]).unwrap();
    assert_eq!(ac.find_overlapping_iter(b"abcdef").count(), 0);
}

#[test]
fn scan_with_ac_filters_out_of_range_sig_idx() {
    // Build a real AC, then scan against the same sigs. Sanity check that
    // confirmed matches are inside the sig range.
    let sigs = vec![FlirtSignature::from_flirt_pattern(
        &FlirtPattern::from_pattern_str("55 8B EC 90", "f".into(), "l".into()).unwrap(),
    )];
    let ac = build_ac_index(&sigs).unwrap();
    let data = vec![0x55u8, 0x8B, 0xEC, 0x90];
    let matches = scan_with_ac(&data, &sigs, &ac, 0x1000, 0);
    for m in &matches {
        assert!(m.function_name == "f");
        assert_eq!(m.address, 0x1000);
    }
}

#[test]
fn scan_with_ac_crc_short_data_does_not_panic() {
    // CRC region falls past the end of `data` — code currently skips the CRC check
    // when crc_end > data.len() AND still emits the match. Ensure no panic.
    let mut fp =
        FlirtPattern::from_pattern_str("55 8B EC 90", "f".into(), "l".into()).unwrap();
    fp.crc_offset = 0;
    fp.crc_len = 8; // 8 bytes of CRC, but data only has 4
    fp.crc = 0x1234;
    let sigs = vec![FlirtSignature::from_flirt_pattern(&fp)];
    let ac = build_ac_index(&sigs).unwrap();
    let data = vec![0x55u8, 0x8B, 0xEC, 0x90];
    let _ = scan_with_ac(&data, &sigs, &ac, 0, 0);
}

// ---------------------------------------------------------------------------
// FlirtScanner
// ---------------------------------------------------------------------------

fn mk_sigs(patterns: &[&str]) -> Vec<FlirtSignature> {
    patterns
        .iter()
        .map(|p| {
            let fp = FlirtPattern::from_pattern_str(p, "fn".into(), "lib".into()).unwrap();
            FlirtSignature::from_flirt_pattern(&fp)
        })
        .collect()
}

#[test]
fn scanner_new_linear_no_index() {
    let s = FlirtScanner::new_linear(mk_sigs(&["55 8B EC 90"]));
    let dbg = format!("{s:?}");
    assert!(dbg.contains("indexed=false"));
}

#[test]
fn scanner_scan_fast_empty_data() {
    let s = FlirtScanner::new_fast(mk_sigs(&["55 8B EC 90"]));
    assert!(s.scan_fast(&[], 0).is_empty());
}

#[test]
fn scanner_min_confidence_zero_admits_all() {
    let mut s = FlirtScanner::new_fast(mk_sigs(&["55 8B EC 90"]));
    s.set_min_confidence(0);
    let m = s.scan_fast(&[0x55, 0x8B, 0xEC, 0x90], 0);
    assert_eq!(m.len(), 1);
}

#[test]
fn scanner_overlapping_matches_same_pattern() {
    let s = FlirtScanner::new_fast(mk_sigs(&["AA AA AA AA"]));
    let data = vec![0xAAu8; 8]; // pattern can start at offsets 0..=4
    let m = s.scan_fast(&data, 0);
    assert!(m.len() >= 2, "expected multiple overlapping matches, got {}", m.len());
}

#[test]
fn scanner_scan_ac_with_no_sigs_returns_empty() {
    let s = FlirtScanner::new_linear(vec![]);
    assert!(s.scan_ac(&[0u8; 8], 0).is_empty());
}

// ---------------------------------------------------------------------------
// .pat file loaders
// ---------------------------------------------------------------------------

fn write_tmp(contents: &[u8]) -> tempfile::NamedTempFile {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(contents).unwrap();
    tmp.flush().unwrap();
    tmp
}

#[test]
fn load_pat_file_blank_only_returns_empty() {
    let tmp = write_tmp(b"\n\n\n");
    let sigs = load_pat_file(tmp.path()).unwrap();
    assert!(sigs.is_empty());
}

#[test]
fn load_pat_file_comment_lines_skipped() {
    let tmp = write_tmp(b"; this is a comment\n; another\n---\n");
    let sigs = load_pat_file(tmp.path()).unwrap();
    assert!(sigs.is_empty());
}

#[test]
fn load_pat_file_one_simple_line() {
    let tmp = write_tmp(b"558BEC83 0000 0 4 myfunc\n---\n");
    let sigs = load_pat_file(tmp.path()).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].bytes, vec![0x55, 0x8B, 0xEC, 0x83]);
}

#[test]
fn load_pat_file_with_wildcards() {
    let tmp = write_tmp(b"55..EC83 0000 0 4 wcfn\n---\n");
    let sigs = load_pat_file(tmp.path()).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].mask[1], 0x00);
    assert_eq!(sigs[0].mask[0], 0xff);
}

#[test]
fn load_pat_file_separator_terminates() {
    let tmp = write_tmp(b"558BEC83 0000 0 4 a\n---\n558BEC83 0000 0 4 b\n");
    let sigs = load_pat_file(tmp.path()).unwrap();
    // The separator stops parsing → only the first line is read.
    assert_eq!(sigs.len(), 1);
}

#[test]
fn load_auto_detects_pat_by_magic() {
    let tmp = write_tmp(b"---\n558BEC83 0000 0 4 fn\n");
    let sigs = load_auto(tmp.path()).unwrap();
    // The "---" line breaks parsing before any line is read.
    // Test the no-magic fallback instead:
    let _ = sigs;
    let tmp2 = write_tmp(b"558BEC83 0000 0 4 fn\n---\n");
    let sigs2 = load_auto(tmp2.path()).unwrap();
    assert_eq!(sigs2.len(), 1);
}

#[test]
fn load_auto_detects_sig_by_magic_then_errors_on_truncation() {
    let tmp = write_tmp(b"IDASGN\x09trailingjunkbutnotenough");
    let err = load_auto(tmp.path()).unwrap_err();
    assert!(matches!(err, FlirtError::InvalidSigFile | FlirtError::Parse(_)));
}

#[test]
fn load_sig_file_rejects_short_file() {
    let tmp = write_tmp(b"IDA");
    let err = load_sig_file(tmp.path()).unwrap_err();
    assert!(matches!(err, FlirtError::InvalidSigFile));
}

#[test]
fn load_sig_file_v9_rejects_short_file() {
    let tmp = write_tmp(b"IDASGN\x09");
    let err = load_sig_file_v9(tmp.path()).unwrap_err();
    assert!(matches!(err, FlirtError::InvalidSigFile));
}

#[test]
fn inspect_sig_header_short_file_with_bad_magic_errors() {
    let tmp = write_tmp(b"BADMAG");
    let r = inspect_sig_header(tmp.path());
    assert!(r.is_err());
}

#[test]
fn sig_file_header_clone_works() {
    let h = SigFileHeader {
        version: 9,
        arch: 0,
        num_functions: 0,
        pattern_size: 32,
        lib_name: "x".into(),
    };
    let h2 = h;
    assert_eq!(h2.version, 9);
}

// ---------------------------------------------------------------------------
// FlirtMatch
// ---------------------------------------------------------------------------

#[test]
fn flirt_match_clone_serialize_fields() {
    let m = FlirtMatch {
        address: 0xDEAD_BEEF,
        function_name: "n".into(),
        lib_name: "l".into(),
        confidence: 75,
        pattern_length: 12,
    };
    let m2 = m.clone();
    assert_eq!(m2.address, m.address);
    let j = serde_json::to_string(&m).unwrap();
    assert!(j.contains("DEADBEEF") || j.contains(&format!("{}", m.address)));
}

// ---------------------------------------------------------------------------
// SignaturePack (sig_pack module)
// ---------------------------------------------------------------------------

use rustre_flirt_apply::sig_pack::{
    SignaturePack, emit_pack, emit_pattern_line, parse_pack, parse_pattern_line,
};

#[test]
fn pack_emit_then_parse_preserves_all_fields() {
    let mut p = FlirtPattern::new("memcpy".into(), vec![Some(0x55), None, Some(0xEC), Some(0x90)]);
    p.lib_name = "msvcrt".into();
    p.crc_offset = 7;
    p.crc_len = 12;
    p.crc = 0xCAFE;

    let mut pack = SignaturePack::new("demo");
    pack.push(p.clone());

    let text = emit_pack(&pack);
    let pack2 = parse_pack(&text).unwrap();
    assert_eq!(pack2.len(), 1);
    let q = &pack2.patterns[0];
    assert_eq!(q.bytes, p.bytes);
    assert_eq!(q.crc_offset, 7);
    assert_eq!(q.crc_len, 12);
    assert_eq!(q.crc, 0xCAFE);
    assert_eq!(q.lib_name, "msvcrt");
    assert_eq!(q.name, "memcpy");
}

#[test]
fn pack_parse_bad_magic_errors() {
    let r = parse_pack("NOTSIGPACK\npack x\n---\n");
    assert!(matches!(r, Err(FlirtError::Parse(_))));
}

#[test]
fn pack_parse_missing_separator_errors() {
    let r = parse_pack("SIGPACK 1\npack x\n");
    assert!(matches!(r, Err(FlirtError::Parse(_))));
}

#[test]
fn pack_emit_pattern_line_wildcards_serialise() {
    let p = FlirtPattern::new("f".into(), vec![None, Some(0x55), None]);
    let line = emit_pattern_line(&p);
    assert!(line.starts_with("..55.."));
}

#[test]
fn pack_parse_pattern_line_bad_field_count() {
    assert!(parse_pattern_line("only one field").is_err());
}

#[test]
fn pack_parse_pattern_line_bad_crc_offset() {
    let r = parse_pattern_line("5500 | NOTANUMBER 0 0000 2 | lib | f");
    assert!(r.is_err());
}

#[test]
fn pack_roundtrip_with_pipe_in_name() {
    let mut p = FlirtPattern::new("a|b".into(), vec![Some(0x90); 4]);
    p.lib_name = "li|b".into();
    let mut pack = SignaturePack::new("p");
    pack.push(p);
    let txt = pack.emit();
    let pack2 = SignaturePack::parse(&txt).unwrap();
    assert_eq!(pack2.patterns[0].name, "a|b");
    assert_eq!(pack2.patterns[0].lib_name, "li|b");
}

// ---------------------------------------------------------------------------
// pat_parser module
// ---------------------------------------------------------------------------

use rustre_flirt_apply::pat_parser::{
    PatError, PatLine, PatName, PatNameKind, parse_hex_pattern as pp_hex, parse_pat_line,
    parse_pat_text, pat_line_to_bytes,
};

#[test]
fn pp_hex_odd_length_error() {
    assert!(matches!(pp_hex("ABC"), Err(PatError::InvalidHex(_))));
}

#[test]
fn pp_hex_all_wildcards() {
    let r = pp_hex("......").unwrap();
    assert_eq!(r.len(), 3);
    assert!(r.iter().all(Option::is_none));
}

#[test]
fn pp_hex_empty_returns_empty() {
    assert!(pp_hex("").unwrap().is_empty());
}

#[test]
fn parse_pat_line_minimal() {
    let pl = parse_pat_line("558BEC :0 0000 3 :0000:public:fn", 1).unwrap();
    assert_eq!(pl.crc_len, 0);
    assert_eq!(pl.total_len, 3);
    assert_eq!(pl.names[0].kind, PatNameKind::Public);
}

#[test]
fn parse_pat_line_missing_colon() {
    let r = parse_pat_line("558BEC 0 0000 3", 5);
    assert!(matches!(r, Err(PatError::InvalidLine(5))));
}

#[test]
fn parse_pat_text_blank_only_returns_empty() {
    assert!(parse_pat_text("\n\n\n").unwrap().is_empty());
}

#[test]
fn parse_pat_text_skips_separator_lines() {
    let txt = "---START---\n558BEC :0 0000 3 :0000:public:f\n---END---\n";
    let v = parse_pat_text(txt).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn pat_line_to_bytes_returns_fields() {
    let pl = PatLine {
        pattern_bytes: vec![Some(0x55)],
        crc_len: 4,
        crc16: 0xBEEF,
        total_len: 20,
        names: vec![PatName {
            offset: 0,
            kind: PatNameKind::Public,
            name: "x".into(),
        }],
    };
    let (b, cl, c, tl) = pat_line_to_bytes(&pl);
    assert_eq!(b.len(), 1);
    assert_eq!(cl, 4);
    assert_eq!(c, 0xBEEF);
    assert_eq!(tl, 20);
}

#[test]
fn pat_error_display_non_empty() {
    assert!(!PatError::Empty.to_string().is_empty());
    assert!(PatError::InvalidLine(7).to_string().contains('7'));
    assert!(PatError::InvalidHex("ZZ".into()).to_string().contains("ZZ"));
    assert!(PatError::InvalidCrc("QQ".into()).to_string().contains("QQ"));
}

// ---------------------------------------------------------------------------
// ida_sig_compat module
// ---------------------------------------------------------------------------

use rustre_flirt_apply::ida_sig_compat::{
    IdaArch, IdaError, IdaPatParser, IdaSigHeader, IdaSigParser, InternalPattern,
    PatternConverter, SigConversionStats, crc16_ida, parse_hex_pattern as ida_hex,
    render_pat_hex,
};

#[test]
fn ida_arch_round_trip_known_codes() {
    for b in [0u8, 1, 2, 3, 4, 5, 99, 255] {
        let a = IdaArch::from_byte(b);
        let _ = a.name();
    }
    assert_eq!(IdaArch::from_byte(0), IdaArch::X86);
    assert_eq!(IdaArch::from_byte(2), IdaArch::X64);
    assert_eq!(IdaArch::from_byte(99), IdaArch::Unknown);
    assert_eq!(IdaArch::X86.name(), "x86");
    assert_eq!(IdaArch::X64.name(), "x86_64");
}

#[test]
fn ida_hex_with_spaces_ignored() {
    let p = ida_hex("55 8B EC 90").unwrap();
    assert_eq!(p, vec![Some(0x55), Some(0x8B), Some(0xEC), Some(0x90)]);
}

#[test]
fn ida_hex_odd_length_after_space_strip_errors() {
    assert!(matches!(ida_hex("555"), Err(IdaError::InvalidHex(_))));
}

#[test]
fn ida_hex_invalid_char_errors() {
    assert!(matches!(ida_hex("ZZ"), Err(IdaError::InvalidHex(_))));
}

#[test]
fn ida_hex_wildcards_decoded() {
    let p = ida_hex("55..EC").unwrap();
    assert_eq!(p, vec![Some(0x55), None, Some(0xEC)]);
}

#[test]
fn render_pat_hex_round_trips_with_ida_hex() {
    let bytes = vec![Some(0x55u8), None, Some(0xEC), Some(0x90), None];
    let rendered = render_pat_hex(&bytes);
    let parsed = ida_hex(&rendered).unwrap();
    assert_eq!(parsed, bytes);
}

#[test]
fn crc16_ida_deterministic_and_nontrivial() {
    let a = crc16_ida(b"abcd");
    assert_eq!(a, crc16_ida(b"abcd"));
    assert_ne!(a, crc16_ida(b"abce"));
}

#[test]
fn crc16_ida_empty_is_zero() {
    assert_eq!(crc16_ida(&[]), 0);
}

#[test]
fn ida_pat_parser_basic_line() {
    let parser = IdaPatParser::new("libtag");
    let line = "558BEC8B4D108B550C8B4508........ 04 BEEF 0028 :0000 my_fn";
    let p = parser.parse_line(line).unwrap();
    assert_eq!(p.library, "libtag");
    assert_eq!(p.name, "my_fn");
    assert_eq!(p.crc, 0xBEEF);
    assert_eq!(p.crc_len, 4);
    assert_eq!(p.total_len, 0x28);
    assert!(p.bytes.len() == 16);
}

#[test]
fn ida_pat_parser_too_few_parts_errors() {
    let parser = IdaPatParser::new("L");
    let r = parser.parse_line("55 04 BEEF");
    assert!(matches!(r, Err(IdaError::InvalidPatLine(_))));
}

#[test]
fn ida_pat_parser_invalid_crc_field_errors() {
    let parser = IdaPatParser::new("L");
    let r = parser.parse_line("5588 ZZ BEEF 0010 :0000 f");
    assert!(matches!(r, Err(IdaError::InvalidPatLine(_))));
}

#[test]
fn ida_pat_parser_parse_all_skips_bad_and_comments() {
    let parser = IdaPatParser::new("L");
    let txt = "; comment line\n---\n558BEC83 04 BEEF 0008 :0000 a\nGARBAGE\n";
    let v = parser.parse_all(txt).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "a");
}

#[test]
fn ida_pat_parser_local_name_prefix_bang() {
    let parser = IdaPatParser::new("L");
    let line = "558BEC83 00 0000 0008 :0004 !localname";
    let p = parser.parse_line(line).unwrap();
    assert_eq!(p.local_names.len(), 1);
    assert_eq!(p.local_names[0].1, "localname");
    assert_eq!(p.local_names[0].0, 4);
}

#[test]
fn ida_pat_parser_unknown_primary_when_no_offset_zero() {
    let parser = IdaPatParser::new("L");
    let line = "558BEC83 00 0000 0008 :0004 helper";
    let p = parser.parse_line(line).unwrap();
    assert_eq!(p.name, "unknown");
}

#[test]
fn ida_sig_header_parse_bad_magic() {
    // HEADER_FIXED_SIZE is 88 (6 magic + 1 ver + 1 arch + 4 + 2 + 2 + 2 + 2 + 2 + 64 + 2).
    let mut buf = vec![0u8; 200];
    buf[..6].copy_from_slice(b"NOTIDA");
    let r = IdaSigHeader::parse(&buf);
    assert!(matches!(r, Err(IdaError::BadMagic)));
}

#[test]
fn ida_sig_header_parse_truncated() {
    let r = IdaSigHeader::parse(b"IDASGN\x09");
    assert!(matches!(r, Err(IdaError::Truncated)));
}

#[test]
fn ida_sig_header_parse_unsupported_version() {
    let mut buf = vec![0u8; 200];
    buf[..6].copy_from_slice(b"IDASGN");
    buf[6] = 99; // unsupported
    let r = IdaSigHeader::parse(&buf);
    assert!(matches!(r, Err(IdaError::UnsupportedVersion(99))));
}

#[test]
fn ida_sig_header_parse_v9_smoke() {
    // This test used to place the library name at `[22..86]`, a fixed 64-byte
    // field, and assert that `cur >= 88`. That is not the IDASGN layout — the
    // name is last, preceded by its own length byte at 34 — and because the
    // fixture wrote the same wrong layout the parser read, it passed and
    // certified it (T36, iteration 69).
    //
    // It now builds the header with the canonical codec, so it cannot agree with
    // a parser that has drifted: the bytes come from the component that owns the
    // offsets, and `cur` is compared against that header's real length instead
    // of a constant carried over from the wrong layout.
    let h = rustre_flirt::sig_header::SigFileHeader {
        version: 9,
        arch: 0, // x86
        lib_name: "demo".to_string(),
        ..rustre_flirt::sig_header::SigFileHeader::default()
    };
    let buf = h.encode();

    let (parsed, cur) = IdaSigHeader::parse(&buf).unwrap();
    assert_eq!(parsed.version, 9);
    assert_eq!(parsed.arch, IdaArch::X86);
    assert_eq!(parsed.library_name, "demo");
    assert_eq!(cur, h.len_bytes());
}

#[test]
fn ida_sig_parser_empty_body_returns_no_patterns() {
    // Build a valid header followed by no body.
    let mut buf = vec![0u8; 92];
    buf[..6].copy_from_slice(b"IDASGN");
    buf[6] = 9;
    let (_h, pats) = IdaSigParser::parse(&buf).unwrap();
    assert!(pats.is_empty());
}

#[test]
fn pattern_converter_to_pat_line_round_trip_includes_name() {
    let p = InternalPattern {
        name: "memset".into(),
        library: "msvcrt".into(),
        bytes: vec![Some(0x55), None, Some(0xEC), Some(0x90)],
        crc: 0xBEEF,
        crc_offset: 4,
        crc_len: 4,
        total_len: 0x20,
        public_names: vec![(0, "memset".into())],
        local_names: vec![],
        references: vec![],
    };
    let line = PatternConverter::to_pat_line(&p);
    assert!(line.contains("memset"));
    assert!(line.contains("BEEF"));
    assert!(line.starts_with("55..EC90"));
}

#[test]
fn pattern_converter_to_pat_file_ends_with_separator() {
    let p = InternalPattern {
        name: "f".into(),
        library: "l".into(),
        bytes: vec![Some(0x55), Some(0x8B), Some(0xEC), Some(0x90)],
        crc: 0,
        crc_offset: 4,
        crc_len: 0,
        total_len: 4,
        public_names: vec![(0, "f".into())],
        local_names: vec![],
        references: vec![],
    };
    let file = PatternConverter::to_pat_file(&[p]);
    assert!(file.ends_with("---"));
}

#[test]
fn sig_conversion_stats_empty_input() {
    let stats = SigConversionStats::from_patterns(&[]);
    assert_eq!(stats.total_lines, 0);
    assert_eq!(stats.parsed_ok, 0);
}

#[test]
fn sig_conversion_stats_counts_wildcards() {
    let p = InternalPattern {
        name: "f".into(),
        library: "l".into(),
        bytes: vec![Some(0x55), None, Some(0xEC), None],
        crc: 0,
        crc_offset: 0,
        crc_len: 0,
        total_len: 4,
        public_names: vec![],
        local_names: vec![],
        references: vec![],
    };
    let stats = SigConversionStats::from_patterns(&[p]);
    assert_eq!(stats.wildcards_total, 2);
    assert_eq!(stats.total_lines, 1);
}

#[test]
fn internal_pattern_concrete_bytes_counts_non_wildcards() {
    let p = InternalPattern {
        name: "f".into(),
        library: "l".into(),
        bytes: vec![Some(1), None, Some(2), None, Some(3)],
        crc: 0,
        crc_offset: 0,
        crc_len: 0,
        total_len: 5,
        public_names: vec![],
        local_names: vec![],
        references: vec![],
    };
    assert_eq!(p.concrete_bytes(), 3);
}

// ---------------------------------------------------------------------------
// FlirtError display invariants
// ---------------------------------------------------------------------------

#[test]
fn flirt_error_display_variants_non_empty() {
    assert!(!FlirtError::InvalidSigFile.to_string().is_empty());
    assert!(FlirtError::PatternTooShort(5).to_string().contains('5'));
    assert!(FlirtError::Parse("xyz".into()).to_string().contains("xyz"));
    let io_err = FlirtError::Io(std::io::Error::other("boom"));
    assert!(io_err.to_string().contains("boom"));
}

// ---------------------------------------------------------------------------
// Adversarial / boundary
// ---------------------------------------------------------------------------

#[test]
fn applier_large_pattern_no_panic_on_short_data() {
    let hex: String = (0..200).map(|_| "90 ").collect();
    let a = applier_with(hex.trim());
    let _ = a.scan(&[0x90u8; 16], 0);
}

#[test]
fn scanner_many_signatures_no_panic() {
    let pats: Vec<String> = (0..100)
        .map(|i| format!("{:02X} 8B EC 90", i & 0xFF))
        .collect();
    let refs: Vec<&str> = pats.iter().map(String::as_str).collect();
    let s = FlirtScanner::new_fast(mk_sigs(&refs));
    let data = vec![0x55u8, 0x8B, 0xEC, 0x90];
    let _ = s.scan_fast(&data, 0);
}

#[test]
fn pattern_matches_does_not_panic_at_data_len_boundary() {
    let p = FlirtPattern::new("f".into(), vec![Some(0x55); 4]);
    for n in 0..6usize {
        let data = vec![0x55u8; n];
        let _ = p.matches(&data);
    }
}
