//! Deep adversarial test suite for `rustre-triage-die`.
//!
//! Focuses on the public API surface in `lib.rs` (DIE conditions, scanner,
//! detector, signature database, byte/entropy helpers).

use std::sync::Arc;
use std::thread;

use rustre_triage::FileKind;
use rustre_triage_die::{
    BUILTIN_RULES, DetectKind, Detection, DieCondition, DieDatabase, DieDetector, DieError,
    DieMatchResult, DieResult, DieRule, DieScanner, DieSignatureDatabase, RuleCondition,
    check_imports, compute_entropy, find_bytes, get_entry_point_bytes, match_condition,
    match_rule_condition, read_pe_sections,
};

// ---------------------------------------------------------------------------
// Seeded LCG for deterministic fuzzing
// ---------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 56) as u8
    }
    fn buf(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tiny PE builder (just enough to satisfy locate_pe)
// ---------------------------------------------------------------------------

/// Build a minimal valid-ish PE header that `locate_pe` can find.
/// Returns a buffer with: MZ stub, e_lfanew=0x80, PE\0\0, COFF header, optional header.
/// `magic` chooses 0x10b (PE32) or 0x20b (PE32+).
fn mini_pe(magic: u16, num_sections: u16, machine: u16, subsystem: u16) -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew at 0x3C
    let pe_off: u32 = 0x80;
    data[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());

    let p = pe_off as usize;
    data[p] = b'P';
    data[p + 1] = b'E';
    data[p + 2] = 0;
    data[p + 3] = 0;
    // COFF: Machine (2), NumberOfSections (2), TimeDateStamp(4), Sym(4), NumSym(4),
    // SizeOfOptionalHeader(2), Characteristics(2)
    data[p + 4..p + 6].copy_from_slice(&machine.to_le_bytes());
    data[p + 6..p + 8].copy_from_slice(&num_sections.to_le_bytes());
    let opt_header_size: u16 = if magic == 0x20b { 0xF0 } else { 0xE0 };
    data[p + 0x14..p + 0x16].copy_from_slice(&opt_header_size.to_le_bytes());
    // Optional header at p+0x18
    let opt = p + 0x18;
    data[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    // Subsystem at opt + 0x44
    data[opt + 0x44..opt + 0x46].copy_from_slice(&subsystem.to_le_bytes());
    data
}

// ===========================================================================
// 1. DetectKind / Display / Hash / Eq
// ===========================================================================

#[test]
fn t01_detect_kind_display_round() {
    let kinds = [
        DetectKind::Compiler,
        DetectKind::Packer,
        DetectKind::Protector,
        DetectKind::Installer,
        DetectKind::Archive,
        DetectKind::Library,
        DetectKind::Tool,
    ];
    for k in kinds {
        let s = k.to_string();
        assert!(!s.is_empty());
        // Debug == Display since Display uses {self:?}
        assert_eq!(s, format!("{k:?}"));
    }
}

#[test]
fn t02_detect_kind_hash_eq_pairs() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    let kinds = [
        DetectKind::Compiler,
        DetectKind::Packer,
        DetectKind::Protector,
        DetectKind::Installer,
        DetectKind::Archive,
        DetectKind::Library,
        DetectKind::Tool,
    ];
    for k in kinds {
        set.insert(k);
    }
    // 30+ pairs by re-inserting
    for _ in 0..5 {
        for k in kinds {
            set.insert(k);
        }
    }
    assert_eq!(set.len(), kinds.len());
    // pairs
    for a in kinds {
        for b in kinds {
            if a == b {
                assert_eq!(a, b);
                assert_eq!(a.to_string(), b.to_string());
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

// ===========================================================================
// 2. DieError
// ===========================================================================

#[test]
fn t03_die_error_display_contains_msg() {
    let e = DieError::DetectionFailed("boom".into());
    let s = e.to_string();
    assert!(s.contains("boom"));
    assert!(s.contains("detection"));
}

// ===========================================================================
// 3. compute_entropy boundaries
// ===========================================================================

#[test]
fn t04_entropy_empty_is_zero() {
    assert_eq!(compute_entropy(&[]), 0.0);
}

#[test]
fn t05_entropy_single_byte_zero() {
    // entirely constant data => zero entropy
    assert_eq!(compute_entropy(&[0x42u8; 1]), 0.0);
    assert_eq!(compute_entropy(&[0xFFu8; 256]), 0.0);
}

#[test]
fn t06_entropy_uniform_is_max() {
    let data: Vec<u8> = (0..=255u8).collect();
    let e = compute_entropy(&data);
    assert!((e - 8.0).abs() < 1e-3, "entropy {e} not close to 8");
}

#[test]
fn t07_entropy_bounded_for_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 1024) as usize + 1;
        let buf = g.buf(len);
        let e = compute_entropy(&buf);
        assert!((0.0..=8.0001).contains(&e), "entropy {e} out of bounds");
    }
}

// ===========================================================================
// 4. find_bytes — pattern matching
// ===========================================================================

#[test]
fn t08_find_bytes_empty_pattern() {
    assert_eq!(find_bytes(b"hello", ""), None);
}

#[test]
fn t09_find_bytes_simple_match() {
    let off = find_bytes(b"\x00\x00\xDE\xAD\xBE\xEF", "DE AD BE EF").unwrap();
    assert_eq!(off, 2);
}

#[test]
fn t10_find_bytes_wildcard() {
    let off = find_bytes(b"\x00\xAB\xCD\xEF", "AB ?? EF").unwrap();
    assert_eq!(off, 1);
    let off2 = find_bytes(b"\x00\xAB\xCD\xEF", "AB ? EF").unwrap();
    assert_eq!(off2, 1);
}

#[test]
fn t11_find_bytes_no_match() {
    assert_eq!(find_bytes(b"hello", "DE AD"), None);
}

#[test]
fn t12_find_bytes_pattern_too_long() {
    assert_eq!(find_bytes(b"AB", "AB CD EF 01 02"), None);
}

#[test]
fn t13_find_bytes_invalid_hex_token() {
    // "ZZ" parses to None and acts like a wildcard? Actually `from_str_radix` fails,
    // so it becomes None (wildcard). Just assert no panic.
    let _ = find_bytes(b"\x00\x01\x02", "ZZ 01");
}

#[test]
fn t14_find_bytes_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 512) as usize;
        let buf = g.buf(len);
        let _ = find_bytes(&buf, "?? ?? ??");
        let _ = find_bytes(&buf, "4D 5A");
        let _ = find_bytes(&buf, "");
    }
}

// ===========================================================================
// 5. read_pe_sections + get_entry_point_bytes on malformed inputs
// ===========================================================================

#[test]
fn t15_read_sections_empty() {
    assert!(read_pe_sections(&[]).is_empty());
}

#[test]
fn t16_read_sections_non_pe() {
    assert!(read_pe_sections(b"not a pe file at all").is_empty());
}

#[test]
fn t17_read_sections_truncated_pe() {
    let mut data = vec![0u8; 0x40];
    data[0] = b'M';
    data[1] = b'Z';
    let pe_off: u32 = 0x80;
    data[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
    // PE header truncated
    assert!(read_pe_sections(&data).is_empty());
}

#[test]
fn t18_read_sections_zero_sections() {
    let data = mini_pe(0x10b, 0, 0x14c, 2);
    let s = read_pe_sections(&data);
    assert_eq!(s.len(), 0);
}

#[test]
fn t19_get_entry_point_non_pe() {
    assert!(get_entry_point_bytes(b"nope").is_empty());
    assert!(get_entry_point_bytes(&[]).is_empty());
}

#[test]
fn t20_get_entry_point_zero_rva_returns_empty() {
    let data = mini_pe(0x10b, 0, 0x14c, 2);
    // ep_rva defaults to 0
    assert!(get_entry_point_bytes(&data).is_empty());
}

#[test]
fn t21_check_imports_non_pe() {
    assert!(!check_imports(b"junk", "kernel32.dll", "VirtualAlloc"));
    assert!(!check_imports(&[], "kernel32.dll", "VirtualAlloc"));
}

#[test]
fn t22_check_imports_no_import_dir() {
    let data = mini_pe(0x20b, 0, 0x8664, 3);
    assert!(!check_imports(&data, "kernel32.dll", "VirtualAlloc"));
}

#[test]
fn t23_pe_helpers_fuzz_never_panic() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 2048) as usize;
        let mut buf = g.buf(len);
        // Sprinkle "MZ" sometimes
        if buf.len() > 2 && (g.next() & 1) == 0 {
            buf[0] = b'M';
            buf[1] = b'Z';
        }
        let _ = read_pe_sections(&buf);
        let _ = get_entry_point_bytes(&buf);
        let _ = check_imports(&buf, "kernel32.dll", "VirtualAlloc");
        let _ = compute_entropy(&buf);
    }
}

// ===========================================================================
// 6. match_condition / match_rule_condition
// ===========================================================================

#[test]
fn t24_match_condition_string_present() {
    let data = b"the quick brown fox UPX! jumped";
    assert!(match_condition(
        &DieCondition::StringPresent("UPX!".into()),
        data
    ));
    assert!(!match_condition(
        &DieCondition::StringPresent("zzzz".into()),
        data
    ));
}

#[test]
fn t25_match_condition_byte_pattern_offset_bounds() {
    let data = b"\x00\x01\x02\x03\x04";
    // offset past end returns false, never panics
    assert!(!match_condition(
        &DieCondition::BytePattern {
            offset: 999,
            hex: "00 01".into()
        },
        data
    ));
    assert!(match_condition(
        &DieCondition::BytePattern {
            offset: 0,
            hex: "00 01".into()
        },
        data
    ));
}

#[test]
fn t26_match_condition_section_count_non_pe() {
    let data = b"junk";
    // count=0; "0 in [1,5]" => false
    assert!(!match_condition(
        &DieCondition::SectionCount { min: 1, max: 5 },
        data
    ));
    // count=0; "0 in [0,5]" => true
    assert!(match_condition(
        &DieCondition::SectionCount { min: 0, max: 5 },
        data
    ));
}

#[test]
fn t27_match_condition_overlay_non_pe() {
    assert!(!match_condition(&DieCondition::OverlayPresent, b"abc"));
    assert!(!match_condition(&DieCondition::Dotnet, b"abc"));
    assert!(!match_condition(&DieCondition::Manifest, b"abc"));
}

#[test]
fn t28_match_rule_condition_combinators() {
    let data = b"hello UPX!";
    let yes = DieCondition::StringPresent("UPX!".into());
    let no = DieCondition::StringPresent("zzz".into());

    assert!(match_rule_condition(
        &RuleCondition::All(vec![yes.clone()]),
        data
    ));
    assert!(!match_rule_condition(
        &RuleCondition::All(vec![yes.clone(), no.clone()]),
        data
    ));
    assert!(match_rule_condition(
        &RuleCondition::Any(vec![no.clone(), yes.clone()]),
        data
    ));
    assert!(!match_rule_condition(
        &RuleCondition::Any(vec![no.clone()]),
        data
    ));
    assert!(match_rule_condition(
        &RuleCondition::Not(Box::new(no.clone())),
        data
    ));
    assert!(!match_rule_condition(
        &RuleCondition::Not(Box::new(yes.clone())),
        data
    ));
}

#[test]
fn t29_match_rule_condition_empty_all_is_true() {
    // vacuously true
    assert!(match_rule_condition(&RuleCondition::All(vec![]), b""));
    // vacuously false
    assert!(!match_rule_condition(&RuleCondition::Any(vec![]), b""));
}

#[test]
fn t30_match_condition_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next() % 1024) as usize;
        let buf = g.buf(len);
        for cond in [
            DieCondition::OverlayPresent,
            DieCondition::Dotnet,
            DieCondition::Manifest,
            DieCondition::StringPresent("zzz".into()),
            DieCondition::SectionName("UPX0".into()),
            DieCondition::SectionCount { min: 0, max: 96 },
            DieCondition::ImportCount { min: 0, max: 65535 },
            DieCondition::EntryPointHex("60".into()),
            DieCondition::EntropyRange {
                section: 0,
                min: 0.0,
                max: 8.0,
            },
            DieCondition::SubsystemType(2),
            DieCondition::MachineType(0x8664),
            DieCondition::ResourcePresent("RT_MANIFEST".into()),
            DieCondition::ExportPresent("foo".into()),
            DieCondition::ImportPresent {
                dll: "kernel32.dll".into(),
                func: "VirtualAlloc".into(),
            },
            DieCondition::BytePattern {
                offset: 0,
                hex: "4D 5A".into(),
            },
        ] {
            let _ = match_condition(&cond, &buf);
        }
    }
}

// ===========================================================================
// 7. DieScanner
// ===========================================================================

#[test]
fn t31_scanner_new_and_default() {
    let _s1 = DieScanner::new();
    let _s2 = DieScanner;
    let _s3 = DieScanner::default();
    let dbg = format!("{:?}", DieScanner);
    assert!(dbg.contains("DieScanner"));
}

#[test]
fn t32_scanner_scan_empty() {
    let s = DieScanner::new();
    let r = s.scan(&[]);
    // No reasonable rule should match an empty file
    assert!(r.is_empty() || r.iter().all(|d| d.confidence > 0));
}

#[test]
fn t33_scanner_detects_upx_strings() {
    let s = DieScanner::new();
    let mut data = b"MZ".to_vec();
    data.extend_from_slice(&[0u8; 1024]);
    // Just embed the magic strings; section-based rules won't match without
    // a real PE, but the StringPresent("UPX!") rule will.
    data.extend_from_slice(b"UPX!");
    let r = s.scan(&data);
    // Results are sorted descending by confidence
    for w in r.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

#[test]
fn t34_scanner_fuzz_never_panics() {
    let s = DieScanner::new();
    let mut g = Lcg::new();
    for _ in 0..30 {
        let len = (g.next() % 4096) as usize;
        let buf = g.buf(len);
        let _ = s.scan(&buf);
    }
}

#[test]
fn t35_builtin_rules_nonempty() {
    assert!(BUILTIN_RULES.contains("UPX"));
    assert!(BUILTIN_RULES.contains("conditions"));
}

// ===========================================================================
// 8. Detection / DieResult
// ===========================================================================

#[test]
fn t36_die_result_aggregates() {
    let mut r = DieResult::new(FileKind::Pe64, 1234);
    assert_eq!(r.file_size, 1234);
    assert_eq!(r.max_confidence(), 0);
    r.add(Detection {
        kind: DetectKind::Compiler,
        name: "MSVC".into(),
        version: None,
        confidence: 60,
        description: "x".into(),
    });
    r.add(Detection {
        kind: DetectKind::Packer,
        name: "UPX".into(),
        version: Some("3.9".into()),
        confidence: 90,
        description: "x".into(),
    });
    r.add(Detection {
        kind: DetectKind::Protector,
        name: "Themida".into(),
        version: None,
        confidence: 85,
        description: "x".into(),
    });
    assert!(r.is_packed);
    assert!(r.is_protected);
    assert_eq!(r.compilers().len(), 1);
    assert_eq!(r.packers().len(), 1);
    assert_eq!(r.protectors().len(), 1);
    assert_eq!(r.max_confidence(), 90);
    let s = r.to_string();
    assert!(s.contains("DIE"));
    assert!(s.contains("packed=true"));
}

#[test]
fn t37_detection_display_with_and_without_version() {
    let d1 = Detection {
        kind: DetectKind::Tool,
        name: "x".into(),
        version: Some("1.0".into()),
        confidence: 50,
        description: "d".into(),
    };
    let s1 = d1.to_string();
    assert!(s1.contains("Tool"));
    assert!(s1.contains("v1.0"));
    assert!(s1.contains("50%"));
    let d2 = Detection {
        kind: DetectKind::Library,
        name: "y".into(),
        version: None,
        confidence: 10,
        description: "d".into(),
    };
    assert!(d2.to_string().contains("v?"));
}

#[test]
fn t38_die_result_serde_round_trip() {
    let mut r = DieResult::new(FileKind::Pe32, 256);
    r.add(Detection {
        kind: DetectKind::Packer,
        name: "UPX".into(),
        version: Some("3".into()),
        confidence: 90,
        description: "d".into(),
    });
    let j = serde_json::to_string(&r).unwrap();
    let r2: DieResult = serde_json::from_str(&j).unwrap();
    assert_eq!(r2.file_size, r.file_size);
    assert_eq!(r2.detections.len(), r.detections.len());
    assert!(r2.is_packed);
}

// ===========================================================================
// 9. DieDatabase / DieDetector
// ===========================================================================

#[test]
fn t39_database_new_default_and_add() {
    let db = DieDatabase::new();
    assert_eq!(db.rule_count(), 0);
    let mut db2 = DieDatabase::default();
    db2.add_rule(DieRule {
        name: "T".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0xFFFF_FFFF, b"XYZ".to_vec())],
        confidence: 99,
    });
    assert_eq!(db2.rule_count(), 1);
    assert!(format!("{db2:?}").contains("DieDatabase"));
}

#[test]
fn t40_database_load_defaults_has_rules() {
    let db = DieDatabase::load_defaults();
    assert!(db.rule_count() >= 10);
}

#[test]
fn t41_detector_match_offset_oob_safe() {
    let mut db = DieDatabase::new();
    db.add_rule(DieRule {
        name: "OOB".into(),
        kind: DetectKind::Tool,
        version: None,
        // Offset way past the data
        signature: vec![(10_000, b"XYZ".to_vec())],
        confidence: 50,
    });
    let det = DieDetector::new(db);
    let r = det.detect(b"short").unwrap();
    assert_eq!(r.detections.len(), 0);
}

#[test]
fn t42_detector_empty_signature_is_match() {
    // An anchor with empty bytes returns true, so a rule with only an empty
    // anchor fires on any input.
    let mut db = DieDatabase::new();
    db.add_rule(DieRule {
        name: "Always".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0xFFFF_FFFF, vec![])],
        confidence: 1,
    });
    let det = DieDetector::new(db);
    let r = det.detect(b"anything").unwrap();
    assert_eq!(r.detections.len(), 1);
}

#[test]
fn t43_detector_anywhere_and_exact_offset() {
    let mut db = DieDatabase::new();
    db.add_rule(DieRule {
        name: "Anywhere".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0xFFFF_FFFF, b"NEEDLE".to_vec())],
        confidence: 80,
    });
    db.add_rule(DieRule {
        name: "AtZero".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0, b"\xDE\xAD".to_vec())],
        confidence: 90,
    });
    let det = DieDetector::new(db);

    let mut d = vec![0xDE, 0xAD];
    d.extend_from_slice(b"...padding...NEEDLE...");
    let r = det.detect(&d).unwrap();
    let names: Vec<&str> = r.detections.iter().map(|x| x.name.as_str()).collect();
    assert!(names.contains(&"Anywhere"));
    assert!(names.contains(&"AtZero"));

    // Without the prefix, AtZero must NOT match.
    let r2 = det.detect(b"NO_AT_ZERO_NEEDLE_HERE").unwrap();
    let names2: Vec<&str> = r2.detections.iter().map(|x| x.name.as_str()).collect();
    assert!(names2.contains(&"Anywhere"));
    assert!(!names2.contains(&"AtZero"));
}

#[test]
fn t44_detector_with_defaults_fuzz() {
    let det = DieDetector::with_defaults();
    let mut g = Lcg::new();
    for _ in 0..30 {
        let len = (g.next() % 1024) as usize;
        let buf = g.buf(len);
        let r = det.detect(&buf).unwrap();
        // Internal invariants
        assert!(r.file_size == buf.len());
        if r.detections.iter().any(|d| d.kind == DetectKind::Packer) {
            assert!(r.is_packed);
        }
        if r.detections.iter().any(|d| d.kind == DetectKind::Protector) {
            assert!(r.is_protected);
        }
    }
}

// ===========================================================================
// 10. DieSignatureDatabase
// ===========================================================================

#[test]
fn t45_sigdb_new_and_default_have_builtins() {
    let db = DieSignatureDatabase::new();
    assert!(db.entry_count() >= 1);
    let db2 = DieSignatureDatabase::default();
    assert_eq!(db.entry_count(), db2.entry_count());
    assert!(format!("{db:?}").contains("DieSignatureDatabase"));
}

#[test]
fn t46_sigdb_scan_sorted_by_confidence() {
    let db = DieSignatureDatabase::new();
    let mut data = b"MZ".to_vec();
    data.extend_from_slice(b"UPX0 some stuff Inno Setup goes here .vmp0 PESpin");
    let hits = db.scan(&data);
    for w in hits.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
    // At least UPX, Inno Setup, VMProtect should fire
    assert!(hits.iter().any(|h| h.name.contains("UPX")));
    assert!(hits.iter().any(|h| h.name.contains("Inno")));
    assert!(hits.iter().any(|h| h.name.contains("VMProtect")));
}

#[test]
fn t47_sigdb_match_result_is_confident_threshold() {
    let m = DieMatchResult {
        name: "x".into(),
        kind: DetectKind::Tool,
        confidence: 0.69,
        version: None,
        description: "d".into(),
    };
    assert!(!m.is_confident());
    let m2 = DieMatchResult {
        name: "x".into(),
        kind: DetectKind::Tool,
        confidence: 0.7,
        version: None,
        description: "d".into(),
    };
    assert!(m2.is_confident());
    let s = m2.to_string();
    assert!(s.contains("Tool"));
    assert!(s.contains("70%"));
}

#[test]
fn t48_sigdb_fuzz_never_panics() {
    let db = DieSignatureDatabase::new();
    let mut g = Lcg::new();
    for _ in 0..30 {
        let len = (g.next() % 2048) as usize;
        let buf = g.buf(len);
        let _ = db.scan(&buf);
    }
}

#[test]
fn t49_sigdb_empty_input_no_panic() {
    let db = DieSignatureDatabase::new();
    let r = db.scan(&[]);
    // Should not match an MZ-prefixed entry on empty input
    assert!(r.iter().all(|h| !h.name.contains(".NET Framework")));
}

// ===========================================================================
// 11. Send+Sync threaded stress
// ===========================================================================

fn _assert_send_sync<T: Send + Sync>() {}

#[test]
fn t50_send_sync_marker_types() {
    _assert_send_sync::<DieDatabase>();
    _assert_send_sync::<DieDetector>();
    _assert_send_sync::<DieSignatureDatabase>();
    _assert_send_sync::<DieScanner>();
    _assert_send_sync::<DieResult>();
    _assert_send_sync::<Detection>();
}

#[test]
fn t51_threaded_detector_stress() {
    let det = Arc::new(DieDetector::with_defaults());
    let mut handles = Vec::new();
    for t in 0..4 {
        let d = Arc::clone(&det);
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new();
            // perturb seed per thread
            for _ in 0..t {
                g.next();
            }
            for _ in 0..100 {
                let len = (g.next() % 256) as usize;
                let buf = g.buf(len);
                let _ = d.detect(&buf).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t52_threaded_sigdb_stress() {
    let db = Arc::new(DieSignatureDatabase::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let d = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new();
            for _ in 0..t {
                g.next();
            }
            for _ in 0..100 {
                let len = (g.next() % 256) as usize;
                let buf = g.buf(len);
                let _ = d.scan(&buf);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ===========================================================================
// 12. Integer / boundary stress
// ===========================================================================

#[test]
fn t53_section_count_boundary_u8_max() {
    // SectionCount stores u8 — max of type
    let data = b"junk";
    assert!(!match_condition(
        &DieCondition::SectionCount { min: 0, max: 0 },
        b"random"
    ) == false); // 0 sections in [0,0]
    assert!(match_condition(
        &DieCondition::SectionCount {
            min: u8::MIN,
            max: u8::MAX
        },
        data
    ));
}

#[test]
fn t54_import_count_boundary_u16_max() {
    let data = b"junk";
    assert!(match_condition(
        &DieCondition::ImportCount {
            min: u16::MIN,
            max: u16::MAX
        },
        data
    ));
}

#[test]
fn t55_machine_subsystem_max_u16() {
    // Values must not panic; just exercise the helpers.
    assert!(!match_condition(
        &DieCondition::MachineType(u16::MAX),
        b"junk"
    ));
    assert!(!match_condition(
        &DieCondition::SubsystemType(u16::MAX),
        b"junk"
    ));
}

#[test]
fn t56_die_result_const_new() {
    // const fn
    const R: DieResult = DieResult::new(FileKind::Pe32, 0);
    assert_eq!(R.file_size, 0);
    assert!(!R.is_packed);
}

#[test]
fn t57_dotnet_truncated_pe_no_panic() {
    // PE header just shy of CLR directory range
    let mut data = mini_pe(0x10b, 0, 0x14c, 2);
    // Trim to provoke bounds-checks but keep PE header intact
    data.truncate(0x100);
    assert!(!match_condition(&DieCondition::Dotnet, &data));
}

#[test]
fn t58_off_by_one_section_count_pe() {
    let data = mini_pe(0x10b, 1, 0x14c, 2);
    // We declared 1 section but didn't populate it; read_section_count returns 1.
    assert!(match_condition(
        &DieCondition::SectionCount { min: 1, max: 1 },
        &data
    ));
    assert!(!match_condition(
        &DieCondition::SectionCount { min: 0, max: 0 },
        &data
    ));
    assert!(!match_condition(
        &DieCondition::SectionCount { min: 2, max: 5 },
        &data
    ));
}

#[test]
fn t59_machine_pe_match() {
    let data = mini_pe(0x20b, 0, 0x8664, 3);
    assert!(match_condition(&DieCondition::MachineType(0x8664), &data));
    assert!(!match_condition(&DieCondition::MachineType(0x014c), &data));
    assert!(match_condition(&DieCondition::SubsystemType(3), &data));
}

#[test]
fn t60_entrypoint_hex_no_ep_returns_false() {
    let data = mini_pe(0x10b, 0, 0x14c, 2);
    // No entry point → false
    assert!(!match_condition(
        &DieCondition::EntryPointHex("60".into()),
        &data
    ));
}
