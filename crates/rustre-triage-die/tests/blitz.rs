//! Blitz integration tests for rustre-triage-die.
//!
//! Exercises public surface across modules to surface bugs.

use rustre_triage_die::*;

// ---------------------------------------------------------------------------
// Synthetic PE builder — minimal valid PE32+ file with named sections.
// ---------------------------------------------------------------------------

/// Construct a minimal PE32+ image with the given section names.
/// Returns raw bytes long enough that section table fits.
fn make_pe(section_names: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    // MZ header
    data[0] = b'M';
    data[1] = b'Z';
    let pe_off: u32 = 0x80;
    data[0x3c..0x40].copy_from_slice(&pe_off.to_le_bytes());

    let pe = pe_off as usize;
    data[pe..pe + 4].copy_from_slice(b"PE\0\0");
    // Machine = x86-64 (0x8664)
    data[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    // NumberOfSections
    let nsec = section_names.len() as u16;
    data[pe + 6..pe + 8].copy_from_slice(&nsec.to_le_bytes());
    // SizeOfOptionalHeader = 0xF0 (PE32+)
    let opt_size: u16 = 0xF0;
    data[pe + 0x14..pe + 0x16].copy_from_slice(&opt_size.to_le_bytes());

    // Optional header magic = 0x020b (PE32+)
    let opt_off = pe + 0x18;
    data[opt_off..opt_off + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    // Subsystem = 3 (Console) at opt_off + 0x44
    data[opt_off + 0x44..opt_off + 0x46].copy_from_slice(&3u16.to_le_bytes());

    // Section table at opt_off + opt_size
    let sec_tbl = opt_off + opt_size as usize;
    for (i, name) in section_names.iter().enumerate() {
        let s = sec_tbl + i * 40;
        let nb = name.as_bytes();
        let take = nb.len().min(8);
        data[s..s + take].copy_from_slice(&nb[..take]);
        // virtual_size = 0x100 at s+8
        data[s + 8..s + 12].copy_from_slice(&0x100u32.to_le_bytes());
        // virtual_addr = 0x1000 at s+12
        data[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // raw_size 0, raw_off 0
    }
    data
}

// ---------------------------------------------------------------------------
// compute_entropy
// ---------------------------------------------------------------------------

#[test]
fn entropy_zero_for_empty() {
    assert_eq!(compute_entropy(&[]), 0.0);
}

#[test]
fn entropy_zero_for_constant() {
    let d = vec![0x42u8; 4096];
    assert!(compute_entropy(&d) < 0.01);
}

#[test]
fn entropy_max_for_uniform_distribution() {
    // All 256 byte values once each
    let d: Vec<u8> = (0..=255u8).collect();
    let e = compute_entropy(&d);
    assert!((e - 8.0).abs() < 0.01, "expected ~8.0, got {e}");
}

#[test]
fn entropy_two_symbols_half_each() {
    let mut d = vec![0u8; 1024];
    for (i, b) in d.iter_mut().enumerate() {
        *b = if i % 2 == 0 { 0 } else { 1 };
    }
    let e = compute_entropy(&d);
    assert!((e - 1.0).abs() < 0.01);
}

#[test]
fn entropy_single_byte_input() {
    // A single byte: only one symbol; p=1.0 → entropy 0
    assert_eq!(compute_entropy(&[0xAA]), 0.0);
}

// ---------------------------------------------------------------------------
// find_bytes
// ---------------------------------------------------------------------------

#[test]
fn find_bytes_basic() {
    let data = b"\x00\x11\x22\x33";
    assert_eq!(find_bytes(data, "22 33"), Some(2));
}

#[test]
fn find_bytes_first_byte() {
    let data = b"\xAB\xCD";
    assert_eq!(find_bytes(data, "AB"), Some(0));
}

#[test]
fn find_bytes_wildcard_question() {
    let data = b"\x10\x20\x30";
    assert_eq!(find_bytes(data, "10 ? 30"), Some(0));
}

#[test]
fn find_bytes_pattern_longer_than_data() {
    let data = b"\x01";
    assert_eq!(find_bytes(data, "01 02 03"), None);
}

#[test]
fn find_bytes_empty_string_returns_none() {
    assert_eq!(find_bytes(b"abc", ""), None);
}

#[test]
fn find_bytes_invalid_hex_token_treated_as_unparseable() {
    // ZZ won't parse as hex u8 — the token becomes None (wildcard).
    // This means it matches anything: pattern "ZZ" length 1 matches at offset 0.
    let data = b"\xAB";
    // Just exercise — behavior may be wildcard-like.
    let _ = find_bytes(data, "ZZ");
}

#[test]
fn find_bytes_all_wildcards_matches_at_zero() {
    let data = b"\x00\x01\x02";
    assert_eq!(find_bytes(data, "?? ?? ??"), Some(0));
}

// ---------------------------------------------------------------------------
// read_pe_sections / get_entry_point_bytes
// ---------------------------------------------------------------------------

#[test]
fn read_pe_sections_returns_empty_on_garbage() {
    assert!(read_pe_sections(&[0xFFu8; 32]).is_empty());
}

#[test]
fn read_pe_sections_truncated() {
    // Just an MZ + e_lfanew pointing past end
    let mut d = vec![0u8; 0x40];
    d[0] = b'M';
    d[1] = b'Z';
    d[0x3c..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(read_pe_sections(&d).is_empty());
}

#[test]
fn read_pe_sections_synthetic_pe() {
    let d = make_pe(&[".text", ".data", "UPX0"]);
    let sections = read_pe_sections(&d);
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[0].0, ".text");
    assert_eq!(sections[2].0, "UPX0");
}

#[test]
fn entry_point_empty_for_non_pe() {
    assert!(get_entry_point_bytes(&[0u8; 200]).is_empty());
}

#[test]
fn entry_point_empty_for_pe_with_zero_ep() {
    let d = make_pe(&[".text"]);
    // No EP set → returns empty
    assert!(get_entry_point_bytes(&d).is_empty());
}

// ---------------------------------------------------------------------------
// check_imports for non-PE
// ---------------------------------------------------------------------------

#[test]
fn check_imports_non_pe_false() {
    assert!(!check_imports(&[0u8; 128], "kernel32.dll", "VirtualAlloc"));
}

#[test]
fn check_imports_empty_data() {
    assert!(!check_imports(&[], "any.dll", "any"));
}

// ---------------------------------------------------------------------------
// DieCondition / match_condition
// ---------------------------------------------------------------------------

#[test]
fn match_condition_section_name_synthetic_pe() {
    let d = make_pe(&[".themida"]);
    assert!(match_condition(
        &DieCondition::SectionName(".themida".into()),
        &d
    ));
}

#[test]
fn match_condition_section_name_absent() {
    let d = make_pe(&[".text"]);
    assert!(!match_condition(&DieCondition::SectionName("UPX0".into()), &d));
}

#[test]
fn match_condition_section_count_in_range() {
    let d = make_pe(&[".a", ".b", ".c"]);
    assert!(match_condition(
        &DieCondition::SectionCount { min: 2, max: 4 },
        &d
    ));
}

#[test]
fn match_condition_section_count_out_of_range() {
    let d = make_pe(&[".a", ".b", ".c"]);
    assert!(!match_condition(
        &DieCondition::SectionCount { min: 5, max: 10 },
        &d
    ));
}

#[test]
fn match_condition_subsystem_matches() {
    let d = make_pe(&[".text"]);
    assert!(match_condition(&DieCondition::SubsystemType(3), &d));
}

#[test]
fn match_condition_machine_matches() {
    let d = make_pe(&[".text"]);
    assert!(match_condition(&DieCondition::MachineType(0x8664), &d));
}

#[test]
fn match_condition_machine_mismatch() {
    let d = make_pe(&[".text"]);
    assert!(!match_condition(&DieCondition::MachineType(0x014c), &d));
}

#[test]
fn match_condition_string_present_true_and_false() {
    let data = b"foo BARBAZ baz";
    assert!(match_condition(
        &DieCondition::StringPresent("BARBAZ".into()),
        data
    ));
    assert!(!match_condition(
        &DieCondition::StringPresent("ZZZZ".into()),
        data
    ));
}

#[test]
fn match_condition_byte_pattern_at_offset() {
    let data = b"\xAA\xBB\x60\xBE\xFF";
    let cond = DieCondition::BytePattern {
        offset: 2,
        hex: "60 BE".into(),
    };
    assert!(match_condition(&cond, data));
}

#[test]
fn match_condition_byte_pattern_offset_oob() {
    let data = b"\xAA";
    let cond = DieCondition::BytePattern {
        offset: 9999,
        hex: "AA".into(),
    };
    assert!(!match_condition(&cond, data));
}

#[test]
fn match_condition_dotnet_false_for_non_pe() {
    assert!(!match_condition(&DieCondition::Dotnet, &[0u8; 64]));
}

#[test]
fn match_condition_manifest_byte_marker() {
    // The 0x18 0x00 0x00 0x80 sequence marks RT_MANIFEST id.
    let mut d = vec![0xFFu8; 64];
    d.extend_from_slice(b"\x18\x00\x00\x80");
    assert!(match_condition(&DieCondition::Manifest, &d));
}

#[test]
fn match_condition_overlay_present_false_for_non_pe() {
    assert!(!match_condition(&DieCondition::OverlayPresent, &[0u8; 128]));
}

#[test]
fn match_condition_entry_point_hex_no_ep() {
    // Non-PE, no entry point
    assert!(!match_condition(
        &DieCondition::EntryPointHex("60".into()),
        &[0u8; 64]
    ));
}

#[test]
fn match_condition_entropy_range_no_sections() {
    assert!(!match_condition(
        &DieCondition::EntropyRange {
            section: 0,
            min: 0.0,
            max: 8.0,
        },
        &[0u8; 64]
    ));
}

// ---------------------------------------------------------------------------
// RuleCondition combinators
// ---------------------------------------------------------------------------

#[test]
fn rule_condition_all_empty_is_true() {
    // vacuous truth
    assert!(match_rule_condition(&RuleCondition::All(vec![]), b""));
}

#[test]
fn rule_condition_any_empty_is_false() {
    assert!(!match_rule_condition(&RuleCondition::Any(vec![]), b""));
}

#[test]
fn rule_condition_not_inverts() {
    let data = b"hello";
    let rc = RuleCondition::Not(Box::new(DieCondition::StringPresent("hello".into())));
    assert!(!match_rule_condition(&rc, data));
    let rc2 = RuleCondition::Not(Box::new(DieCondition::StringPresent("missing".into())));
    assert!(match_rule_condition(&rc2, data));
}

// ---------------------------------------------------------------------------
// DieScanner / BUILTIN_RULES
// ---------------------------------------------------------------------------

#[test]
fn die_scanner_new_and_default() {
    let _a = DieScanner::new();
    let _b = DieScanner::default();
}

#[test]
fn die_scanner_returns_sorted_by_confidence() {
    let data = b"MZNullsoft Inno Setup Borland clang MinGW";
    let dets = DieScanner.scan(data);
    for w in dets.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

#[test]
fn die_scanner_no_detections_on_zeros() {
    let dets = DieScanner.scan(&[0u8; 256]);
    assert!(dets.is_empty());
}

#[test]
fn builtin_rules_yaml_non_empty() {
    assert!(!BUILTIN_RULES.is_empty());
    assert!(BUILTIN_RULES.contains("UPX"));
}

// ---------------------------------------------------------------------------
// DetectKind / Detection / DieResult
// ---------------------------------------------------------------------------

#[test]
fn detect_kind_display_all_variants() {
    for k in [
        DetectKind::Compiler,
        DetectKind::Packer,
        DetectKind::Protector,
        DetectKind::Installer,
        DetectKind::Archive,
        DetectKind::Library,
        DetectKind::Tool,
    ] {
        let s = k.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn detect_kind_equality_and_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(DetectKind::Packer);
    s.insert(DetectKind::Packer);
    s.insert(DetectKind::Tool);
    assert_eq!(s.len(), 2);
}

#[test]
fn detection_display_no_version_uses_qmark() {
    let d = Detection {
        kind: DetectKind::Tool,
        name: "x".into(),
        version: None,
        confidence: 10,
        description: String::new(),
    };
    assert!(d.to_string().contains("v?"));
}

#[test]
fn die_result_aggregate_flags() {
    use rustre_triage::FileKind;
    let mut r = DieResult::new(FileKind::Pe64, 100);
    assert!(!r.is_packed && !r.is_protected);
    r.add(Detection {
        kind: DetectKind::Packer,
        name: "p".into(),
        version: None,
        confidence: 1,
        description: String::new(),
    });
    r.add(Detection {
        kind: DetectKind::Protector,
        name: "q".into(),
        version: None,
        confidence: 2,
        description: String::new(),
    });
    assert!(r.is_packed && r.is_protected);
    assert_eq!(r.detections.len(), 2);
    assert_eq!(r.packers().len(), 1);
    assert_eq!(r.protectors().len(), 1);
    assert_eq!(r.compilers().len(), 0);
    assert_eq!(r.max_confidence(), 2);
}

#[test]
fn die_result_max_confidence_empty() {
    use rustre_triage::FileKind;
    let r = DieResult::new(FileKind::Unknown, 0);
    assert_eq!(r.max_confidence(), 0);
}

// ---------------------------------------------------------------------------
// DieDatabase / DieDetector
// ---------------------------------------------------------------------------

#[test]
fn die_database_default_empty() {
    assert_eq!(DieDatabase::default().rule_count(), 0);
}

#[test]
fn die_database_load_defaults_has_rules() {
    let db = DieDatabase::load_defaults();
    assert!(db.rule_count() > 5);
}

#[test]
fn die_detector_with_defaults_no_match_for_plain_zero() {
    let det = DieDetector::with_defaults();
    let res = det.detect(&[0u8; 64]).unwrap();
    // None of the default signatures (MZ, MinGW, UPX0, etc.) appear in zeros
    assert!(res.detections.is_empty());
}

#[test]
fn die_detector_detects_borland() {
    let det = DieDetector::with_defaults();
    let res = det.detect(b"random Borland random").unwrap();
    assert!(res.compilers().iter().any(|d| d.name == "Delphi"));
}

#[test]
fn die_detector_offset_exact_match() {
    let mut db = DieDatabase::new();
    db.add_rule(DieRule {
        name: "X".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0, b"ZZ".to_vec())],
        confidence: 50,
    });
    let det = DieDetector::new(db);
    let r = det.detect(b"ZZdata").unwrap();
    assert_eq!(r.detections.len(), 1);
}

#[test]
fn die_detector_anywhere_special_offset() {
    let mut db = DieDatabase::new();
    db.add_rule(DieRule {
        name: "any".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0xFFFF_FFFF, b"NEEDLE".to_vec())],
        confidence: 50,
    });
    let det = DieDetector::new(db);
    let r = det.detect(b"haystack NEEDLE tail").unwrap();
    assert_eq!(r.detections.len(), 1);
}

#[test]
fn die_detector_empty_bytes_rule_always_matches() {
    let mut db = DieDatabase::new();
    db.add_rule(DieRule {
        name: "empty".into(),
        kind: DetectKind::Tool,
        version: None,
        signature: vec![(0, vec![])],
        confidence: 1,
    });
    let det = DieDetector::new(db);
    let r = det.detect(b"whatever").unwrap();
    assert_eq!(r.detections.len(), 1);
}

#[test]
fn die_detector_debug_format() {
    let det = DieDetector::with_defaults();
    let s = format!("{:?}", det);
    assert!(s.contains("DieDetector"));
}

// ---------------------------------------------------------------------------
// DieSignatureDatabase / DieMatchResult
// ---------------------------------------------------------------------------

#[test]
fn die_signature_db_builtin_count_positive() {
    let db = DieSignatureDatabase::new();
    assert!(db.entry_count() > 0);
}

#[test]
fn die_signature_db_default_works() {
    let db = DieSignatureDatabase::default();
    assert!(db.entry_count() > 0);
}

#[test]
fn die_signature_db_scan_detects_upx() {
    let db = DieSignatureDatabase::new();
    let res = db.scan(b"random UPX0 mid bytes");
    assert!(res.iter().any(|m| m.name.contains("UPX")));
}

#[test]
fn die_signature_db_scan_no_match_on_zeros() {
    let db = DieSignatureDatabase::new();
    let res = db.scan(&[0u8; 512]);
    assert!(res.is_empty());
}

#[test]
fn die_signature_db_scan_sorted() {
    let db = DieSignatureDatabase::new();
    let res = db.scan(b"MZ UPX0 .vmp0 .themida MinGW Borland Nullsoft Inno Setup clang");
    for w in res.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

#[test]
fn die_signature_db_detects_vmprotect_either_section() {
    let db = DieSignatureDatabase::new();
    let r0 = db.scan(b"x .vmp0 y");
    assert!(r0.iter().any(|m| m.name.contains("VMProtect")));
    let r1 = db.scan(b"x .vmp1 y");
    assert!(r1.iter().any(|m| m.name.contains("VMProtect")));
}

#[test]
fn die_match_result_is_confident_threshold() {
    let m = DieMatchResult {
        name: "x".into(),
        kind: DetectKind::Tool,
        confidence: 0.69,
        version: None,
        description: String::new(),
    };
    assert!(!m.is_confident());
    let m2 = DieMatchResult { confidence: 0.7, ..m };
    assert!(m2.is_confident());
}

#[test]
fn die_match_result_display_percent() {
    let m = DieMatchResult {
        name: "Foo".into(),
        kind: DetectKind::Packer,
        confidence: 0.95,
        version: Some("1.0".into()),
        description: String::new(),
    };
    let s = m.to_string();
    assert!(s.contains("95"));
    assert!(s.contains("Foo"));
}

#[test]
fn die_signature_db_debug() {
    let db = DieSignatureDatabase::new();
    assert!(format!("{:?}", db).contains("DieSignatureDatabase"));
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn die_condition_serde_each_variant() {
    let conds = vec![
        DieCondition::SectionName(".text".into()),
        DieCondition::SectionCount { min: 1, max: 9 },
        DieCondition::BytePattern { offset: 0, hex: "AA".into() },
        DieCondition::EntryPointHex("60".into()),
        DieCondition::EntropyRange { section: 0, min: 0.0, max: 8.0 },
        DieCondition::ImportPresent { dll: "a".into(), func: "b".into() },
        DieCondition::ImportCount { min: 0, max: 10 },
        DieCondition::ExportPresent("foo".into()),
        DieCondition::SubsystemType(2),
        DieCondition::StringPresent("X".into()),
        DieCondition::MachineType(0x8664),
        DieCondition::OverlayPresent,
        DieCondition::ResourcePresent("RT_MANIFEST".into()),
        DieCondition::Dotnet,
        DieCondition::Manifest,
    ];
    for c in conds {
        let j = serde_json::to_string(&c).unwrap();
        let _back: DieCondition = serde_json::from_str(&j).unwrap();
    }
}

#[test]
fn rule_condition_all_serde() {
    let rc = RuleCondition::All(vec![DieCondition::Dotnet, DieCondition::Manifest]);
    let j = serde_json::to_string(&rc).unwrap();
    let back: RuleCondition = serde_json::from_str(&j).unwrap();
    matches!(back, RuleCondition::All(_));
}

#[test]
fn detect_kind_serde() {
    for k in [DetectKind::Compiler, DetectKind::Packer, DetectKind::Tool] {
        let j = serde_json::to_string(&k).unwrap();
        let back: DetectKind = serde_json::from_str(&j).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn detection_serde_round_trip() {
    let d = Detection {
        kind: DetectKind::Packer,
        name: "UPX".into(),
        version: Some("3.x".into()),
        confidence: 95,
        description: "x".into(),
    };
    let j = serde_json::to_string(&d).unwrap();
    let back: Detection = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, "UPX");
    assert_eq!(back.confidence, 95);
}

// ---------------------------------------------------------------------------
// DieError
// ---------------------------------------------------------------------------

#[test]
fn die_error_display_contains_message() {
    let e = DieError::DetectionFailed("kaboom".into());
    assert!(e.to_string().contains("kaboom"));
}

// ---------------------------------------------------------------------------
// Send/Sync invariants
// ---------------------------------------------------------------------------

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DieScanner>();
    assert_send_sync::<DieDatabase>();
    assert_send_sync::<DieDetector>();
    assert_send_sync::<DieSignatureDatabase>();
    assert_send_sync::<DieCondition>();
    assert_send_sync::<RuleCondition>();
    assert_send_sync::<Detection>();
    assert_send_sync::<DetectKind>();
    assert_send_sync::<DieResult>();
    assert_send_sync::<DieError>();
}

// ---------------------------------------------------------------------------
// Exercise submodule entry points (currently dead-code-ish but public)
// ---------------------------------------------------------------------------

#[test]
fn submodule_compiler_detector_free_fn() {
    let _ = rustre_triage_die::compiler_detector::detect(&[0u8; 64]);
}

#[test]
fn submodule_detector_engine_free_fns() {
    let report = rustre_triage_die::detector_engine::scan_bytes(&[0u8; 64]);
    let _ = rustre_triage_die::detector_engine::format_report(&report);
}

#[test]
fn submodule_die_extended_detect() {
    let _ = rustre_triage_die::die_extended::DieExtended::detect(&[0u8; 64]);
}

#[test]
fn submodule_die_extended_detect_versions() {
    let v = rustre_triage_die::die_extended::detect_versions(b"some clang 14.0.0 binary");
    // Just ensure it runs; output shape varies.
    let _ = v;
}

#[test]
fn submodule_die_scanner_scanner_new_scan() {
    let s = rustre_triage_die::die_scanner::DieScanner::new();
    let _ = s.scan(&[0u8; 64]);
}

#[test]
fn submodule_die_signature_db_scan() {
    let db = rustre_triage_die::die_signature_db::DieSignatureDatabase::new();
    let _ = db.scan(&[0u8; 64], &[]);
}

#[test]
fn submodule_die_signature_db_hex_pattern() {
    use rustre_triage_die::die_signature_db::{find_hex_pattern, match_hex_pattern, parse_hex_pattern};
    let (bytes, mask) = parse_hex_pattern("AA ?? BB");
    assert_eq!(bytes.len(), mask.len());
    assert!(match_hex_pattern("AA BB", b"\xAA\xBB"));
    assert_eq!(find_hex_pattern("BB", b"\xAA\xBB\xCC"), Some(1));
}

#[test]
fn submodule_heuristic_detector_analyze() {
    let d = rustre_triage_die::heuristic_detector::HeuristicDetector::new();
    let _ = d.analyze(&[0u8; 64]);
}

#[test]
fn submodule_packer_detector_compute_entropy() {
    assert_eq!(rustre_triage_die::packer_detector::compute_entropy(&[]), 0.0);
}

#[test]
fn submodule_packer_detector_new_detect() {
    let d = rustre_triage_die::packer_detector::PackerDetector::new();
    let _ = d.detect(&[0u8; 64]);
}

#[test]
fn submodule_packer_detector_full_analysis() {
    let _ = rustre_triage_die::packer_detector::full_analysis(&[0u8; 64]);
}

#[test]
fn submodule_packer_signature_db_match_bytes() {
    let _ = rustre_triage_die::packer_signature_db::match_bytes(&[0u8; 64]);
}

#[test]
fn submodule_overlay_analyzer_analyze() {
    let _ = rustre_triage_die::overlay_analyzer::analyze_overlay(&[0u8; 64]);
}

#[test]
fn submodule_rule_db_extended_scan() {
    let _ = rustre_triage_die::rule_db_extended::ExtendedRuleDb::scan(&[0u8; 64]);
}

#[test]
fn submodule_scanner_with_defaults_scan() {
    let s = rustre_triage_die::scanner::DieScanner::with_defaults();
    // Some Scanner API — exercise debug at minimum
    let _ = format!("{:?}", s);
}

#[test]
fn submodule_signature_db_with_defaults() {
    let db = rustre_triage_die::signature_db::SignatureDb::with_defaults();
    let _ = db.scan(&[0u8; 64]);
}

#[test]
fn submodule_die_script_engine_new() {
    let _ = rustre_triage_die::die_script_engine::DieScriptEngine::new();
    let _ = rustre_triage_die::die_script_engine::DieScriptEngine::with_defaults();
}
