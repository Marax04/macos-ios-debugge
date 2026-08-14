//! Deep adversarial test suite for `rustre-flirt-apply`.
//!
//! Targets the public surface of `lib.rs`: `FlirtPattern`, `FlirtError`, `FlirtMatch`,
//! `FlirtSigDb`, `FlirtApplier`, `FlirtSignature`, `WildcardPattern`, `AhoCorasickIndex`,
//! `FlirtScanner`, `crc16_flirt`, `load_sig_file`{,_v9}, `inspect_sig_header`,
//! `load_pat_file`, `load_auto`, `build_ac_index`, `scan_with_ac`.

use std::io::Write;
use std::path::Path;

use rustre_flirt_apply::{
    build_ac_index, crc16_flirt, inspect_sig_header, load_auto, load_pat_file, load_sig_file,
    load_sig_file_v9, scan_with_ac, AhoCorasickIndex, FlirtApplier, FlirtError, FlirtMatch,
    FlirtPattern, FlirtScanner, FlirtSigDb, FlirtSignature, SigFileHeader, WildcardPattern,
};

// ---- Seeded LCG ------------------------------------------------------------
struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    const fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

// =====================================================================
// FlirtPattern
// =====================================================================

#[test]
fn pattern_new_initial_state() {
    let p = FlirtPattern::new("x".into(), vec![Some(1), None, Some(2)]);
    assert_eq!(p.name, "x");
    assert_eq!(p.pattern_len(), 3);
    assert_eq!(p.crc_offset, 0);
    assert_eq!(p.crc_len, 0);
    assert_eq!(p.crc, 0);
    assert!(p.public_names.is_empty());
    assert!(p.local_names.is_empty());
    assert!(p.references.is_empty());
}

#[test]
fn pattern_matches_data_shorter_than_pattern() {
    let p = FlirtPattern::new("p".into(), vec![Some(0x55); 10]);
    assert!(!p.matches(&[]));
    assert!(!p.matches(&[0x55; 9]));
    assert!(p.matches(&[0x55; 10]));
    assert!(p.matches(&[0x55; 20]));
}

#[test]
fn pattern_matches_all_wildcards_accepts_any_bytes() {
    let p = FlirtPattern::new("p".into(), vec![None; 5]);
    let mut g = Lcg::new();
    for _ in 0..50 {
        let data = g.next_bytes(8);
        assert!(p.matches(&data));
    }
}

#[test]
fn pattern_from_str_short_boundary_3_bytes_errors() {
    // 3 bytes is below the 4-byte minimum.
    let r = FlirtPattern::from_pattern_str("AA BB CC", "n".into(), "l".into());
    assert!(matches!(r, Err(FlirtError::PatternTooShort(3))));
}

#[test]
fn pattern_from_str_boundary_4_bytes_ok() {
    let r = FlirtPattern::from_pattern_str("AA BB CC DD", "n".into(), "l".into()).unwrap();
    assert_eq!(r.pattern_len(), 4);
}

#[test]
fn pattern_from_str_zero_tokens_errors() {
    let r = FlirtPattern::from_pattern_str("", "n".into(), "l".into());
    assert!(matches!(r, Err(FlirtError::PatternTooShort(0))));
}

#[test]
fn pattern_from_str_only_wildcards_returns_pattern() {
    let r = FlirtPattern::from_pattern_str(".. .. .. ..", "n".into(), "l".into()).unwrap();
    assert_eq!(r.pattern_len(), 4);
    assert!(r.bytes.iter().all(Option::is_none));
}

#[test]
fn pattern_from_str_three_token_styles_for_wildcard() {
    let a = FlirtPattern::from_pattern_str("?? ?? ?? ??", "n".into(), "l".into()).unwrap();
    let b = FlirtPattern::from_pattern_str(".. .. .. ..", "n".into(), "l".into()).unwrap();
    let c = FlirtPattern::from_pattern_str(".  .  .  .", "n".into(), "l".into()).unwrap();
    for p in [a, b, c] {
        assert_eq!(p.pattern_len(), 4);
        assert!(p.bytes.iter().all(Option::is_none));
    }
}

#[test]
fn pattern_from_str_three_char_token_errors() {
    let r = FlirtPattern::from_pattern_str("AAA BB CC DD", "n".into(), "l".into());
    assert!(matches!(r, Err(FlirtError::Parse(_))));
}

#[test]
fn pattern_from_str_invalid_hex_chars_errors() {
    let r = FlirtPattern::from_pattern_str("GG HH II JJ", "n".into(), "l".into());
    assert!(matches!(r, Err(FlirtError::Parse(_))));
}

#[test]
fn pattern_clone_preserves_fields() {
    let p = FlirtPattern::from_pattern_str("55 8B EC 90", "n".into(), "lib".into()).unwrap();
    let q = p.clone();
    assert_eq!(p.bytes, q.bytes);
    assert_eq!(p.name, q.name);
    assert_eq!(p.lib_name, q.lib_name);
    assert_eq!(p.pattern_len(), q.pattern_len());
}

#[test]
fn pattern_display_includes_length_and_libname() {
    let p =
        FlirtPattern::from_pattern_str("55 8B EC 90 41", "fname".into(), "libxyz".into()).unwrap();
    let s = format!("{p}");
    assert!(s.contains("fname"));
    assert!(s.contains("libxyz"));
    assert!(s.contains("5 bytes"));
}

#[test]
fn pattern_round_trip_str_to_struct_50_inputs() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = 4 + (g.next_u8() as usize % 12);
        let mut s = String::new();
        let mut expected: Vec<Option<u8>> = Vec::new();
        for i in 0..n {
            if i > 0 {
                s.push(' ');
            }
            if g.next_u8().is_multiple_of(4) {
                s.push_str("??");
                expected.push(None);
            } else {
                let b = g.next_u8();
                s.push_str(&format!("{b:02X}"));
                expected.push(Some(b));
            }
        }
        let p = FlirtPattern::from_pattern_str(&s, "f".into(), "l".into()).unwrap();
        assert_eq!(p.bytes, expected);
    }
}

// =====================================================================
// FlirtError
// =====================================================================

#[test]
fn error_display_strings_nonempty() {
    let a = FlirtError::InvalidSigFile.to_string();
    let b = FlirtError::PatternTooShort(7).to_string();
    let c = FlirtError::Parse("oops".into()).to_string();
    assert!(!a.is_empty());
    assert!(b.contains('7'));
    assert!(c.contains("oops"));
}

#[test]
fn error_from_io_conversion() {
    let io_err = std::io::Error::other("boom");
    let e: FlirtError = io_err.into();
    assert!(matches!(e, FlirtError::Io(_)));
}

// =====================================================================
// FlirtMatch
// =====================================================================

#[test]
fn flirt_match_display_components_present() {
    let m = FlirtMatch {
        address: 0xCAFE_BABE,
        function_name: "fn".into(),
        lib_name: "lib".into(),
        confidence: 88,
        pattern_length: 4,
    };
    let s = m.to_string();
    assert!(s.contains("0xcafebabe"));
    assert!(s.contains("88%"));
}

#[test]
fn flirt_match_clone_eq_fields() {
    let m = FlirtMatch {
        address: 1,
        function_name: "a".into(),
        lib_name: "b".into(),
        confidence: 50,
        pattern_length: 8,
    };
    let n = m.clone();
    assert_eq!(m.address, n.address);
    assert_eq!(m.function_name, n.function_name);
    assert_eq!(m.confidence, n.confidence);
}

// =====================================================================
// FlirtSigDb
// =====================================================================

#[test]
fn sigdb_default_and_new_equal() {
    let a = FlirtSigDb::new();
    let b = FlirtSigDb::default();
    assert_eq!(a.pattern_count(), b.pattern_count());
}

#[test]
fn sigdb_load_demo_sigs_has_expected_count() {
    let db = FlirtSigDb::load_demo_sigs();
    // 18 demo signatures added in source.
    assert!(db.pattern_count() >= 15);
}

#[test]
fn sigdb_debug_shows_count() {
    let mut db = FlirtSigDb::new();
    for _ in 0..3 {
        db.add_pattern(FlirtPattern::new("a".into(), vec![Some(0x55); 4]));
    }
    let s = format!("{db:?}");
    assert!(s.contains('3'));
}

// =====================================================================
// FlirtApplier
// =====================================================================

fn applier_with(hex: &str) -> FlirtApplier {
    let mut db = FlirtSigDb::new();
    db.add_pattern(FlirtPattern::from_pattern_str(hex, "fn".into(), "lib".into()).unwrap());
    FlirtApplier::new(db)
}

#[test]
fn applier_scan_empty_data() {
    let a = applier_with("55 8B EC 90");
    assert!(a.scan(&[], 0x1000).is_empty());
    assert_eq!(a.match_count(&[], 0x1000), 0);
}

#[test]
fn applier_scan_at_addresses_with_base_offset() {
    let a = applier_with("55 8B EC 90");
    let data = vec![0xAA, 0xBB, 0x55, 0x8B, 0xEC, 0x90];
    let m = a.scan_at_addresses(&data, 0x1000, &[0x1002]);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].address, 0x1002);
}

#[test]
fn applier_scan_at_addresses_empty_func_list() {
    let a = applier_with("55 8B EC 90");
    let data = vec![0x55, 0x8B, 0xEC, 0x90];
    assert!(a.scan_at_addresses(&data, 0, &[]).is_empty());
}

#[test]
fn applier_set_min_confidence_blocks_low_quality() {
    let mut a = applier_with("55 8B EC 90"); // 4 bytes
    a.set_min_confidence(101);
    let data = vec![0x55, 0x8B, 0xEC, 0x90];
    assert!(a.scan(&data, 0).is_empty());
}

#[test]
fn applier_fuzz_random_data_never_panics() {
    let db = FlirtSigDb::load_demo_sigs();
    let a = FlirtApplier::new(db);
    let mut g = Lcg::new();
    for _ in 0..30 {
        let n = (g.next_u8() as usize % 256) + 1;
        let data = g.next_bytes(n);
        let _ = a.scan(&data, 0x4000_0000);
        let _ = a.match_count(&data, 0x4000_0000);
    }
}

#[test]
fn applier_apply_invalid_pat_file_errors() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "GG bad content").unwrap();
    let applier = FlirtApplier::new(FlirtSigDb::new());
    let r = applier.apply(&[0u8; 4], tmp.path(), 0);
    assert!(matches!(r, Err(FlirtError::Parse(_))));
}

#[test]
fn applier_scan_at_address_exactly_at_data_end_no_match() {
    let a = applier_with("55 8B EC 90");
    let data = vec![0x55, 0x8B, 0xEC, 0x90];
    // address that maps exactly to data.len() -> out of range
    let m = a.scan_at_addresses(&data, 0x1000, &[0x1004]);
    assert!(m.is_empty());
}

// =====================================================================
// FlirtSignature
// =====================================================================

#[test]
fn signature_from_pattern_round_trip_masks() {
    let fp = FlirtPattern::from_pattern_str("AA BB ?? DD ?? FF", "f".into(), "l".into()).unwrap();
    let sig = FlirtSignature::from_flirt_pattern(&fp);
    assert_eq!(sig.bytes.len(), 6);
    assert_eq!(sig.mask, vec![0xff, 0xff, 0x00, 0xff, 0x00, 0xff]);
    assert_eq!(sig.bytes[2], 0x00);
}

#[test]
fn signature_matches_at_data_too_short() {
    let sig = FlirtSignature {
        bytes: vec![0x55, 0x8B, 0xEC],
        mask: vec![0xff, 0xff, 0xff],
        name: "f".into(),
        lib_name: "l".into(),
        crc_offset: 0,
        crc_len: 0,
        crc: 0,
    };
    assert!(!sig.matches_at(&[0x55, 0x8B]));
    assert!(!sig.matches_at(&[]));
}

#[test]
fn signature_fuzz_matches_at_no_panic() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next_u8() as usize % 8) + 1;
        let bytes: Vec<u8> = g.next_bytes(len);
        let mask: Vec<u8> = (0..len).map(|i| if i % 2 == 0 { 0xff } else { 0x00 }).collect();
        let sig = FlirtSignature {
            bytes,
            mask,
            name: "f".into(),
            lib_name: "l".into(),
            crc_offset: 0,
            crc_len: 0,
            crc: 0,
        };
        let data = g.next_bytes(16);
        let _ = sig.matches_at(&data);
    }
}

// =====================================================================
// WildcardPattern
// =====================================================================

#[test]
fn wildcard_pattern_empty_sig_yields_empty_prefix() {
    let sig = FlirtSignature {
        bytes: vec![],
        mask: vec![],
        name: "f".into(),
        lib_name: "l".into(),
        crc_offset: 0,
        crc_len: 0,
        crc: 0,
    };
    let wp = WildcardPattern::from_signature(&sig);
    assert!(wp.prefix().is_empty());
}

#[test]
fn wildcard_pattern_caps_at_32() {
    let bytes = vec![0xAA; 64];
    let mask = vec![0xff; 64];
    let sig = FlirtSignature {
        bytes,
        mask,
        name: "f".into(),
        lib_name: "l".into(),
        crc_offset: 0,
        crc_len: 0,
        crc: 0,
    };
    let wp = WildcardPattern::from_signature(&sig);
    assert!(wp.prefix().len() <= 32);
}

// =====================================================================
// AhoCorasickIndex
// =====================================================================

#[test]
fn ac_index_empty_sigs_not_built() {
    let idx = AhoCorasickIndex::build(&[]);
    assert!(!idx.is_built());
    let results = idx.search(&[1u8, 2, 3, 4], &[]);
    assert!(results.is_empty());
}

#[test]
fn ac_index_search_returns_offsets_in_data_bounds() {
    let fp = FlirtPattern::from_pattern_str("55 8B EC 83", "f".into(), "l".into()).unwrap();
    let sigs = vec![FlirtSignature::from_flirt_pattern(&fp)];
    let idx = AhoCorasickIndex::build(&sigs);
    let data = vec![0u8, 0x55, 0x8B, 0xEC, 0x83, 0u8];
    let cands = idx.search(&data, &sigs);
    for (off, sidx) in &cands {
        assert!(*off < data.len());
        assert!(*sidx < sigs.len());
    }
}

// =====================================================================
// crc16_flirt
// =====================================================================

#[test]
fn crc16_empty_is_ffff() {
    // IDA flair crc16 (init 0xFFFF, no final XOR): empty input returns 0xFFFF.
    assert_eq!(crc16_flirt(&[]), 0xFFFF);
}

#[test]
fn crc16_deterministic_50_inputs() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = (g.next_u8() as usize % 64) + 1;
        let data = g.next_bytes(n);
        let c1 = crc16_flirt(&data);
        let c2 = crc16_flirt(&data);
        assert_eq!(c1, c2);
    }
}

#[test]
fn crc16_different_data_different_crc_typically() {
    let mut g = Lcg::new();
    let mut differences = 0;
    let base = g.next_bytes(16);
    let base_crc = crc16_flirt(&base);
    for _ in 0..20 {
        let other = g.next_bytes(16);
        if crc16_flirt(&other) != base_crc {
            differences += 1;
        }
    }
    assert!(differences > 10);
}

#[test]
fn crc16_single_byte_changes_crc() {
    let a = crc16_flirt(&[0x00]);
    let b = crc16_flirt(&[0x01]);
    assert_ne!(a, b);
}

// =====================================================================
// FlirtScanner
// =====================================================================

fn sigs_from(patterns: &[&str]) -> Vec<FlirtSignature> {
    patterns
        .iter()
        .map(|p| {
            let fp = FlirtPattern::from_pattern_str(p, "fn".into(), "lib".into()).unwrap();
            FlirtSignature::from_flirt_pattern(&fp)
        })
        .collect()
}

#[test]
fn scanner_linear_no_index() {
    let s = FlirtScanner::new_linear(sigs_from(&["55 8B EC 83"]));
    let dbg = format!("{s:?}");
    assert!(dbg.contains("indexed=false"));
}

#[test]
fn scanner_fast_with_index_finds_match() {
    let s = FlirtScanner::new_fast(sigs_from(&["55 8B EC 83 EC 10"]));
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
    let m = s.scan_fast(&data, 0x2000);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].address, 0x2000);
}

#[test]
fn scanner_min_confidence_filter() {
    let mut s = FlirtScanner::new_fast(sigs_from(&["55 8B EC 83 EC 10"]));
    s.set_min_confidence(101);
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
    assert!(s.scan_fast(&data, 0).is_empty());
}

#[test]
fn scanner_scan_ac_finds_match() {
    let s = FlirtScanner::new_linear(sigs_from(&["55 8B EC 83 EC 10"]));
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
    let m = s.scan_ac(&data, 0x100);
    assert!(!m.is_empty());
    assert_eq!(m[0].address, 0x100);
}

#[test]
fn scanner_fuzz_random_data_no_panic() {
    let s = FlirtScanner::new_fast(sigs_from(&["55 8B EC 83 EC 10", "AA BB CC DD"]));
    let mut g = Lcg::new();
    for _ in 0..20 {
        let n = (g.next_u8() as usize % 200) + 1;
        let data = g.next_bytes(n);
        let _ = s.scan_fast(&data, 0);
        let _ = s.scan_ac(&data, 0);
    }
}

// =====================================================================
// build_ac_index / scan_with_ac
// =====================================================================

#[test]
fn build_ac_index_with_empty_sigs() {
    let sigs: Vec<FlirtSignature> = vec![];
    let ac = build_ac_index(&sigs).unwrap();
    assert_eq!(ac.find_overlapping_iter(&[1u8, 2, 3]).count(), 0);
}

#[test]
fn scan_with_ac_min_conf_threshold() {
    let sigs = sigs_from(&["55 8B EC 83"]);
    let ac = build_ac_index(&sigs).unwrap();
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
    let m = scan_with_ac(&data, &sigs, &ac, 0, 0);
    assert_eq!(m.len(), 1);
    let m2 = scan_with_ac(&data, &sigs, &ac, 0, 101);
    assert!(m2.is_empty());
}

#[test]
fn scan_with_ac_crc_pass() {
    let mut sigs = sigs_from(&["55 8B EC 83"]);
    let middle = [0xAA, 0xBB, 0xCC, 0xDD];
    sigs[0].crc_offset = 0;
    sigs[0].crc_len = 4;
    sigs[0].crc = crc16_flirt(&middle);
    let ac = build_ac_index(&sigs).unwrap();
    let mut data = vec![0x55u8, 0x8B, 0xEC, 0x83];
    data.extend_from_slice(&middle);
    let m = scan_with_ac(&data, &sigs, &ac, 0, 0);
    assert_eq!(m.len(), 1);
}

#[test]
fn scan_with_ac_crc_fail() {
    let mut sigs = sigs_from(&["55 8B EC 83"]);
    sigs[0].crc_offset = 0;
    sigs[0].crc_len = 4;
    sigs[0].crc = 0xDEAD;
    let ac = build_ac_index(&sigs).unwrap();
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xAA, 0xBB, 0xCC, 0xDD];
    let m = scan_with_ac(&data, &sigs, &ac, 0, 0);
    assert!(m.is_empty());
}

#[test]
fn scan_with_ac_crc_oob_skipped() {
    let mut sigs = sigs_from(&["55 8B EC 83"]);
    sigs[0].crc_offset = 0;
    sigs[0].crc_len = 4;
    sigs[0].crc = 0;
    let ac = build_ac_index(&sigs).unwrap();
    // Only the pattern body — no room for CRC region.
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
    let m = scan_with_ac(&data, &sigs, &ac, 0, 0);
    assert!(m.is_empty());
}

// =====================================================================
// load_pat_file / load_auto / load_sig_file{,_v9} / inspect_sig_header
// =====================================================================

#[test]
fn load_pat_file_skips_blank_and_comments() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp).unwrap();
    writeln!(tmp, "; this is a comment").unwrap();
    writeln!(tmp, "558BEC83 0000 0 4 fn_a").unwrap();
    writeln!(tmp, "---").unwrap();
    writeln!(tmp, "FFFFFFFF 0000 0 4 should_not_appear").unwrap();
    let sigs = load_pat_file(tmp.path()).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].name, "fn_a");
}

#[test]
fn load_pat_file_with_wildcards() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "55....EC83 0000 0 4 wfn").unwrap();
    writeln!(tmp, "---").unwrap();
    let sigs = load_pat_file(tmp.path()).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].mask[1], 0x00);
    assert_eq!(sigs[0].mask[2], 0x00);
    assert_eq!(sigs[0].mask[0], 0xff);
}

#[test]
fn load_auto_detects_pat() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "558BEC83 0000 0 4 fn_x").unwrap();
    writeln!(tmp, "---").unwrap();
    let sigs = load_auto(tmp.path()).unwrap();
    assert_eq!(sigs.len(), 1);
}

#[test]
fn load_auto_detects_sig_magic_invalid_then_errors() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"IDASGNxyzzzz").unwrap();
    let r = load_auto(tmp.path());
    assert!(r.is_err());
}

#[test]
fn load_sig_file_unsupported_version_errors() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    let mut bytes = vec![0u8; 200];
    bytes[..6].copy_from_slice(b"IDASGN");
    bytes[6] = 1; // unsupported version < 5
    tmp.write_all(&bytes).unwrap();
    let r = load_sig_file(tmp.path());
    assert!(matches!(r, Err(FlirtError::Parse(_))));
}

#[test]
fn load_sig_file_nonexistent_is_io_err() {
    let r = load_sig_file(Path::new("definitely_does_not_exist_12345.sig"));
    assert!(matches!(r, Err(FlirtError::Io(_))));
}

#[test]
fn load_sig_file_v9_nonexistent_is_io_err() {
    let r = load_sig_file_v9(Path::new("definitely_does_not_exist_12345.sig"));
    assert!(matches!(r, Err(FlirtError::Io(_))));
}

#[test]
fn inspect_sig_header_nonexistent_is_io_err() {
    let r = inspect_sig_header(Path::new("definitely_does_not_exist_12345.sig"));
    assert!(matches!(r, Err(FlirtError::Io(_))));
}

#[test]
fn sig_file_header_debug_contains_lib_name() {
    let hdr = SigFileHeader {
        version: 9,
        arch: 75,
        num_functions: 17,
        pattern_size: 32,
        lib_name: "foo_lib".into(),
    };
    let s = format!("{hdr:?}");
    assert!(s.contains("foo_lib"));
    assert!(s.contains("17"));
}

// =====================================================================
// Fuzz: parsers should never panic
// =====================================================================

#[test]
fn fuzz_pattern_from_str_50_random_inputs() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let n = (g.next_u8() as usize % 32) + 1;
        let bytes = g.next_bytes(n);
        let s: String = bytes
            .iter()
            .map(|b| format!("{b:02X} "))
            .collect();
        // Either Ok or specific Err — never panic.
        let _ = FlirtPattern::from_pattern_str(&s, "n".into(), "l".into());
    }
}

#[test]
fn fuzz_load_pat_random_garbage_returns_result() {
    let mut g = Lcg::new();
    for _ in 0..10 {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let n = (g.next_u8() as usize % 200) + 1;
        let bytes = g.next_bytes(n);
        tmp.write_all(&bytes).unwrap();
        // Result OK or Err, no panic.
        let _ = load_pat_file(tmp.path());
        let _ = load_auto(tmp.path());
    }
}

// =====================================================================
// Send/Sync threaded stress
// =====================================================================

#[test]
fn applier_send_sync_threaded_stress() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlirtApplier>();
    assert_send_sync::<FlirtScanner>();
    assert_send_sync::<FlirtSignature>();
    assert_send_sync::<FlirtPattern>();

    use std::sync::Arc;
    use std::thread;

    let db = FlirtSigDb::load_demo_sigs();
    let applier = Arc::new(FlirtApplier::new(db));
    let data = Arc::new({
        let mut g = Lcg::new();
        g.next_bytes(2048)
    });

    let mut handles = Vec::new();
    for _ in 0..4 {
        let a = Arc::clone(&applier);
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = a.scan(&d, 0x4000_0000);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn scanner_threaded_stress() {
    use std::sync::Arc;
    use std::thread;

    let scanner = Arc::new(FlirtScanner::new_fast(sigs_from(&[
        "55 8B EC 83 EC 10",
        "AA BB CC DD EE FF",
        "90 90 90 90 90",
    ])));
    let mut g = Lcg::new();
    let data = Arc::new(g.next_bytes(4096));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&scanner);
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = s.scan_fast(&d, 0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// =====================================================================
// Integer overflow / boundary CRC offsets
// =====================================================================

#[test]
fn scan_with_max_crc_offset_no_overflow() {
    let mut db = FlirtSigDb::new();
    let mut p = FlirtPattern::from_pattern_str("55 8B EC 83", "f".into(), "l".into()).unwrap();
    p.crc_offset = u16::MAX;
    p.crc_len = u16::MAX;
    p.crc = 0xBEEF;
    db.add_pattern(p);
    let a = FlirtApplier::new(db);
    let data = vec![0x55u8, 0x8B, 0xEC, 0x83];
    // CRC region OOB — must not panic, must return empty.
    let m = a.scan(&data, 0);
    assert!(m.is_empty());
}

#[test]
fn scan_at_addresses_addr_equal_to_base() {
    let a = applier_with("55 8B EC 90");
    let data = vec![0x55, 0x8B, 0xEC, 0x90, 0x00];
    let m = a.scan_at_addresses(&data, 0x1000, &[0x1000]);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].address, 0x1000);
}
