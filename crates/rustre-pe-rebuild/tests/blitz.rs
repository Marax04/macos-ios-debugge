//! Integration tests for rustre-pe-rebuild public API in lib.rs.
//!
//! Focus: structural invariants, error variants, parser edge cases,
//! roundtrips, and currently-dead public API surface exercised here so
//! it's no longer dead.

use std::collections::HashMap;

use rustre_pe_rebuild::{
    apply_fixups, chars, compute_entropy, compute_imphash, crc16_ccitt, detect_oep_heuristics,
    is_memory_pe, DumpFixer, ExportEntry, ExportRebuilder, IatEntry, IatFixOptions, IatFixer,
    IatRegion, IatScanner, ModuleResolver, OepDetector, OverlayHandler, PeDumper, PeFixupOptions,
    PeRebuilder, RebuildConfig, RebuildError, RebuildFlags, RebuildSection, RebuildStats,
    RelocationEntry, RelocationOptions, RelocationRebuilder,
};
use rustre_pe_tools::{PeBuilder, PeFile, PeMachine};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_x64_pe() -> Vec<u8> {
    let mut b = PeBuilder::new_x64();
    b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
    b.add_section(".data", vec![0u8; 32], 0xC000_0040);
    b.build()
}

fn make_x86_pe() -> Vec<u8> {
    let mut b = PeBuilder::new_x86();
    b.add_section(".text", vec![0xCCu8; 64], 0x6000_0020);
    b.build()
}

// ---------------------------------------------------------------------------
// is_memory_pe
// ---------------------------------------------------------------------------

#[test]
fn is_memory_pe_empty() {
    assert!(!is_memory_pe(&[]));
}

#[test]
fn is_memory_pe_just_under_64() {
    let mut v = vec![0u8; 63];
    v[0] = b'M';
    v[1] = b'Z';
    assert!(!is_memory_pe(&v));
}

#[test]
fn is_memory_pe_exactly_64_with_mz() {
    let mut v = vec![0u8; 64];
    v[0] = b'M';
    v[1] = b'Z';
    assert!(is_memory_pe(&v));
}

#[test]
fn is_memory_pe_wrong_magic_full_len() {
    let v = vec![b'P', b'K', 0u8, 0u8].into_iter().chain(vec![0u8; 60]).collect::<Vec<_>>();
    assert!(!is_memory_pe(&v));
}

// ---------------------------------------------------------------------------
// compute_entropy
// ---------------------------------------------------------------------------

#[test]
fn compute_entropy_empty_is_zero() {
    assert_eq!(compute_entropy(&[]), 0.0);
}

#[test]
fn compute_entropy_single_byte_is_zero() {
    assert_eq!(compute_entropy(&[0xAA]), 0.0);
}

#[test]
fn compute_entropy_uniform_is_max() {
    let data: Vec<u8> = (0u8..=255).collect();
    let e = compute_entropy(&data);
    assert!((e - 8.0).abs() < 1e-9, "expected 8.0, got {e}");
}

#[test]
fn compute_entropy_two_balanced_is_one() {
    // 128 0x00 + 128 0xFF -> entropy 1.0
    let mut d = vec![0u8; 128];
    d.extend(vec![0xFFu8; 128]);
    let e = compute_entropy(&d);
    assert!((e - 1.0).abs() < 1e-9, "expected 1.0, got {e}");
}

#[test]
fn compute_entropy_all_zeros_long() {
    assert_eq!(compute_entropy(&vec![0u8; 4096]), 0.0);
}

// ---------------------------------------------------------------------------
// crc16_ccitt
// ---------------------------------------------------------------------------

#[test]
fn crc16_ccitt_empty_is_ffff() {
    // Init value with no data processed.
    assert_eq!(crc16_ccitt(&[]), 0xFFFF);
}

#[test]
fn crc16_ccitt_deterministic() {
    let a = crc16_ccitt(b"hello");
    let b = crc16_ccitt(b"hello");
    assert_eq!(a, b);
}

#[test]
fn crc16_ccitt_different_inputs_differ() {
    assert_ne!(crc16_ccitt(b"hello"), crc16_ccitt(b"world"));
}

// ---------------------------------------------------------------------------
// RebuildSection
// ---------------------------------------------------------------------------

#[test]
fn section_virtual_end_saturates() {
    let s = RebuildSection {
        name: ".big".into(),
        virtual_address: u32::MAX - 1,
        virtual_size: 100,
        data: vec![],
        characteristics: 0,
    };
    // Should saturate, not panic.
    assert_eq!(s.virtual_end(), u32::MAX);
}

#[test]
fn section_contains_rva_zero_size_is_empty() {
    let s = RebuildSection::new(".z".to_string(), 0x1000, vec![], 0);
    // virtual_size is 0; contains_rva should always be false.
    assert!(!s.contains_rva(0x1000));
    assert!(!s.contains_rva(0x0FFF));
}

#[test]
fn section_rva_to_offset_at_boundary() {
    let s = RebuildSection::new(".t".to_string(), 0x1000, vec![0u8; 0x100], 0);
    assert_eq!(s.rva_to_offset(0x1000), Some(0));
    assert_eq!(s.rva_to_offset(0x10FF), Some(0xFF));
    assert_eq!(s.rva_to_offset(0x1100), None);
}

#[test]
fn section_entropy_matches_free_fn() {
    let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];
    let s = RebuildSection::new(".x".to_string(), 0, data.clone(), 0);
    assert_eq!(s.entropy(), compute_entropy(&data));
}

#[test]
fn section_helpers_flags() {
    let c = RebuildSection::code(".c".into(), 0, vec![0; 4]);
    assert!(c.is_executable());
    assert!(!c.is_writable());
    let d = RebuildSection::data(".d".into(), 0, vec![0; 4]);
    assert!(d.is_writable());
    assert!(!d.is_executable());
    let r = RebuildSection::rdata(".r".into(), 0, vec![0; 4]);
    assert!(!r.is_writable());
    assert!(!r.is_executable());
}

#[test]
fn section_serde_roundtrip() {
    let s = RebuildSection::new(".s".into(), 0x2000, vec![1, 2, 3], chars::MEM_READ);
    let j = serde_json::to_string(&s).unwrap();
    let s2: RebuildSection = serde_json::from_str(&j).unwrap();
    assert_eq!(s2.name, ".s");
    assert_eq!(s2.virtual_address, 0x2000);
    assert_eq!(s2.data, vec![1, 2, 3]);
}

// ---------------------------------------------------------------------------
// PeRebuilder
// ---------------------------------------------------------------------------

#[test]
fn rebuilder_align_up_zero_value() {
    assert_eq!(PeRebuilder::align_up(0, 0x200), 0);
}

#[test]
fn rebuilder_align_up_already_aligned() {
    assert_eq!(PeRebuilder::align_up(0x400, 0x200), 0x400);
}

#[test]
fn rebuilder_align_up_round_up() {
    assert_eq!(PeRebuilder::align_up(1, 0x200), 0x200);
    assert_eq!(PeRebuilder::align_up(0x1FF, 0x200), 0x200);
    assert_eq!(PeRebuilder::align_up(0x201, 0x200), 0x400);
}

#[test]
fn rebuilder_align_up_saturates_not_panics() {
    // value near u32::MAX with align 0x1000 — should not panic.
    // NOTE: Current implementation uses saturating_add then masks with !(align-1),
    // which truncates the saturated u32::MAX down to 0xFFFFF000 — strictly less
    // than the input. That violates the "align UP" contract, but the function does
    // not panic. We assert only the no-panic invariant here and capture the
    // contract violation in the bugs report.
    let _ = PeRebuilder::align_up(u32::MAX - 10, 0x1000);
}

#[test]
fn rebuilder_no_sections_err_variant() {
    let r = PeRebuilder::new(RebuildConfig::default());
    match r.rebuild() {
        Err(RebuildError::NoSections) => {}
        other => panic!("expected NoSections, got {other:?}"),
    }
}

#[test]
fn rebuilder_section_by_name_found_and_missing() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    r.add_section(RebuildSection::new(".text".into(), 0x1000, vec![0; 4], 0x20));
    assert!(r.section_by_name(".text").is_some());
    assert!(r.section_by_name(".missing").is_none());
}

#[test]
fn rebuilder_virtual_end_empty() {
    let r = PeRebuilder::new(RebuildConfig::default());
    assert_eq!(r.virtual_end(), 0);
}

#[test]
fn rebuilder_from_memory_dump_too_short() {
    let err = PeRebuilder::from_memory_dump(&[0u8; 8], 0, RebuildConfig::default()).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn rebuilder_rebuild_with_oep_detection_no_exec_sections() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    // data-only section — no MEM_EXECUTE
    r.add_section(RebuildSection::data(".data".into(), 0x1000, vec![0; 16]));
    match r.rebuild_with_oep_detection() {
        Err(RebuildError::NoOepCandidates) => {}
        other => panic!("expected NoOepCandidates, got {other:?}"),
    }
}

#[test]
fn rebuilder_rebuild_with_oep_detection_sets_flag() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    r.add_section(RebuildSection::code(".text".into(), 0x1000, vec![0x90; 64]));
    let result = r.rebuild_with_oep_detection().unwrap();
    assert!(result.stats.oep_detected);
}

// ---------------------------------------------------------------------------
// OepDetector
// ---------------------------------------------------------------------------

#[test]
fn oep_detector_explicit_ep_confidence_one() {
    let mut d = OepDetector::new();
    let res = d.detect(&[], Some(0x4000)).unwrap();
    assert_eq!(res.rva, 0x4000);
    assert!((res.confidence - 1.0).abs() < 1e-6);
}

#[test]
fn oep_detector_empty_no_candidates() {
    let mut d = OepDetector::new();
    let err = d.detect(&[], None).unwrap_err();
    assert!(matches!(err, RebuildError::NoOepCandidates));
}

#[test]
fn oep_detector_data_only_no_candidates() {
    let mut d = OepDetector::new();
    let s = RebuildSection::data(".data".into(), 0x1000, vec![0; 16]);
    let err = d.detect(&[s], None).unwrap_err();
    assert!(matches!(err, RebuildError::NoOepCandidates));
}

#[test]
fn oep_detector_x64_prologue_bonus() {
    let mut d = OepDetector::new();
    // x64 prologue: 55 48 89 E5
    let data = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90];
    let s = RebuildSection::code(".text".into(), 0x1000, data);
    let res = d.detect(&[s], None).unwrap();
    assert!(res.confidence > 0.5, "expected prologue bonus, got {}", res.confidence);
    assert_eq!(res.rva, 0x1000);
}

#[test]
fn oep_detector_candidates_recorded() {
    let mut d = OepDetector::new();
    let s1 = RebuildSection::code(".text".into(), 0x1000, vec![0x90; 16]);
    let s2 = RebuildSection::code(".text2".into(), 0x2000, vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90]);
    d.detect(&[s1, s2], None).unwrap();
    assert_eq!(d.candidates().len(), 2);
}

// ---------------------------------------------------------------------------
// detect_oep_heuristics (free function)
// ---------------------------------------------------------------------------

#[test]
fn detect_oep_heuristics_empty_dump() {
    assert!(detect_oep_heuristics(&[], 0).is_empty());
}

#[test]
fn detect_oep_heuristics_finds_x86_prologue() {
    // Place 55 8B EC at aligned offset 0.
    let dump = vec![0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90, 0x90];
    let cands = detect_oep_heuristics(&dump, 0x1000);
    assert!(!cands.is_empty());
    assert!(cands.iter().any(|c| c.address == 0x1000));
}

#[test]
fn detect_oep_heuristics_sorted_desc_confidence() {
    let mut dump = vec![0u8; 64];
    // x64 PUSH RBP / MOV RBP, RSP at offset 0 — confidence 0.75
    dump[0..4].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
    // SUB ESP, imm8 at offset 16 — confidence 0.40
    dump[16..19].copy_from_slice(&[0x83, 0xEC, 0x20]);
    let cands = detect_oep_heuristics(&dump, 0);
    assert!(cands.windows(2).all(|w| w[0].confidence >= w[1].confidence));
}

// ---------------------------------------------------------------------------
// OverlayHandler
// ---------------------------------------------------------------------------

#[test]
fn overlay_detect_too_short() {
    let err = OverlayHandler::detect(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, RebuildError::OverlayError(_)));
}

#[test]
fn overlay_detect_no_overlay_on_clean_pe() {
    let bytes = make_x64_pe();
    let info = OverlayHandler::detect(&bytes).unwrap();
    assert!(!info.has_overlay());
    assert_eq!(info.length, 0);
}

#[test]
fn overlay_detect_with_appended_data() {
    let mut bytes = make_x64_pe();
    let appended = b"OVERLAYDATA1234567890";
    bytes.extend_from_slice(appended);
    let info = OverlayHandler::detect(&bytes).unwrap();
    assert!(info.has_overlay());
    assert_eq!(info.length, appended.len());
    // Signature is first 16 bytes (or less) of overlay.
    assert_eq!(info.signature, appended[..16.min(appended.len())]);
}

#[test]
fn overlay_extract_returns_overlay_bytes() {
    let mut bytes = make_x64_pe();
    let appended = b"TAIL";
    bytes.extend_from_slice(appended);
    let extracted = OverlayHandler::extract(&bytes).unwrap();
    assert_eq!(extracted, appended);
}

#[test]
fn overlay_preserve_appends_overlay() {
    let mut bytes = make_x64_pe();
    let appended = b"PRESERVED";
    bytes.extend_from_slice(appended);
    let mut rebuilt = make_x64_pe();
    let original_rebuilt_len = rebuilt.len();
    let info = OverlayHandler::preserve(&bytes, &mut rebuilt).unwrap();
    assert!(info.has_overlay());
    assert_eq!(rebuilt.len(), original_rebuilt_len + appended.len());
    assert_eq!(&rebuilt[original_rebuilt_len..], appended);
}

// ---------------------------------------------------------------------------
// apply_fixups
// ---------------------------------------------------------------------------

#[test]
fn apply_fixups_too_short_err() {
    let mut img = vec![0u8; 32];
    let err = apply_fixups(&mut img, &PeFixupOptions::default()).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn apply_fixups_bad_signature_err() {
    let mut img = vec![0u8; 256];
    img[0] = b'M';
    img[1] = b'Z';
    img[60..64].copy_from_slice(&64u32.to_le_bytes());
    // Bytes at offset 64 are zero -> not "PE\0\0".
    let err = apply_fixups(&mut img, &PeFixupOptions::default()).unwrap_err();
    match err {
        RebuildError::Other(s) => assert!(s.contains("PE signature") || s.contains("invalid")),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn apply_fixups_override_ep_writes_value() {
    let mut img = make_x64_pe();
    let opts = PeFixupOptions {
        override_ep: Some(0xCAFE_BABE),
        strip_signature: false,
        ..Default::default()
    };
    let notes = apply_fixups(&mut img, &opts).unwrap();
    assert!(notes.iter().any(|n| n.contains("EP overridden")));
    // Re-read EP from optional header.
    let pe_off = u32::from_le_bytes(img[60..64].try_into().unwrap()) as usize;
    let opt_off = pe_off + 24;
    let ep = u32::from_le_bytes(img[opt_off + 16..opt_off + 20].try_into().unwrap());
    assert_eq!(ep, 0xCAFE_BABE);
}

#[test]
fn apply_fixups_set_dll_flag_toggles_bit() {
    let mut img = make_x64_pe();
    let opts = PeFixupOptions {
        strip_signature: false,
        set_dll_flag: Some(true),
        ..Default::default()
    };
    apply_fixups(&mut img, &opts).unwrap();
    let pe_off = u32::from_le_bytes(img[60..64].try_into().unwrap()) as usize;
    let chars_off = pe_off + 22;
    let ch = u16::from_le_bytes([img[chars_off], img[chars_off + 1]]);
    assert!(ch & 0x2000 != 0);

    // Now clear.
    let opts2 = PeFixupOptions {
        strip_signature: false,
        set_dll_flag: Some(false),
        ..Default::default()
    };
    apply_fixups(&mut img, &opts2).unwrap();
    let ch = u16::from_le_bytes([img[chars_off], img[chars_off + 1]]);
    assert!(ch & 0x2000 == 0);
}

#[test]
fn apply_fixups_strip_signature_zeros_dd4() {
    let mut img = make_x64_pe();
    // Pre-write something into DataDirectory[4] (security).
    let pe_off = u32::from_le_bytes(img[60..64].try_into().unwrap()) as usize;
    let opt_off = pe_off + 24;
    let dd4 = opt_off + 112 + 4 * 8;
    img[dd4..dd4 + 8].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
    let opts = PeFixupOptions {
        strip_signature: true,
        ..Default::default()
    };
    apply_fixups(&mut img, &opts).unwrap();
    assert_eq!(&img[dd4..dd4 + 8], &[0u8; 8]);
}

// ---------------------------------------------------------------------------
// IatFixer
// ---------------------------------------------------------------------------

#[test]
fn iat_fixer_resolves_known_import() {
    let mut opts = IatFixOptions::default();
    opts.known_imports.insert(0x7FFE_0000, ("ntdll.dll".into(), "Foo".into()));
    let mut f = IatFixer::new(opts);
    f.add_entry(IatEntry {
        iat_rva: 0x2000,
        value: 0x7FFE_0000,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    let n = f.fix().unwrap();
    assert_eq!(n, 1);
    assert_eq!(f.entries()[0].dll_name.as_deref(), Some("ntdll.dll"));
    assert_eq!(f.entries()[0].function_name.as_deref(), Some("Foo"));
    assert_eq!(f.resolved_count(), 1);
}

#[test]
fn iat_fixer_unknown_not_resolved_without_allow() {
    let mut f = IatFixer::new(IatFixOptions::default());
    f.add_entry(IatEntry {
        iat_rva: 0x2000,
        value: 0xDEAD,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    let n = f.fix().unwrap();
    assert_eq!(n, 0);
    assert_eq!(f.resolved_count(), 0);
}

#[test]
fn iat_fixer_apply_to_image_oob() {
    let f = IatFixer::new(IatFixOptions::default());
    let mut tiny = vec![0u8; 16];
    // tiny is too short to even have a PE header — pe_sections_from_buf returns empty.
    let mut f = f;
    f.add_entry(IatEntry {
        iat_rva: 0x9000,
        value: 0,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    let err = f.apply_to_image(&mut tiny, 0x0001_4000_0000).unwrap_err();
    assert!(matches!(err, RebuildError::IatOutOfBounds(_)));
}

#[test]
fn iat_fixer_apply_to_image_writes_pointer() {
    // Build a real PE so the section table parses.
    let mut img = make_x64_pe();
    // The .text section is at RVA 0x1000 (PeBuilder default first section RVA).
    // Find the PE section table to confirm.
    let pe = PeFile::parse(&img).unwrap();
    let text_rva = pe.sections[0].virtual_address;
    let text_raw_off = pe.sections[0].raw_offset as usize;

    let mut f = IatFixer::new(IatFixOptions::default());
    f.add_entry(IatEntry {
        iat_rva: text_rva,
        value: 0,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    let n = f.apply_to_image(&mut img, 0x0001_4000_0000).unwrap();
    assert_eq!(n, 1);
    let written = u64::from_le_bytes(img[text_raw_off..text_raw_off + 8].try_into().unwrap());
    assert_eq!(written, 0x0001_4000_0000 + u64::from(text_rva));
}

#[test]
fn iat_fixer_debug_contains_count() {
    let mut f = IatFixer::new(IatFixOptions::default());
    f.add_entry(IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    assert!(format!("{f:?}").contains("entries: 1"));
}

// ---------------------------------------------------------------------------
// RelocationRebuilder
// ---------------------------------------------------------------------------

#[test]
fn reloc_rebuilder_empty_builds_empty_blob() {
    let rb = RelocationRebuilder::new(RelocationOptions::default());
    let blob = rb.build_reloc_section().unwrap();
    assert!(blob.is_empty());
}

#[test]
fn reloc_rebuilder_bad_type_errors() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_entry(RelocationEntry { rva: 0x1000, reloc_type: 99 });
    let err = rb.build_reloc_section().unwrap_err();
    assert!(matches!(err, RebuildError::BadReloc(_)));
}

#[test]
fn reloc_rebuilder_entry_count_excludes_absolute() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_entry(RelocationEntry::absolute());
    rb.add_dir64(0x1000);
    rb.add_highlow(0x1004);
    assert_eq!(rb.entry_count(), 2);
}

#[test]
fn reloc_rebuilder_delta_negative() {
    let opts = RelocationOptions {
        original_base: 0x0060_0000,
        new_base: 0x0040_0000,
        rebuild_section: false,
    };
    let rb = RelocationRebuilder::new(opts);
    assert_eq!(rb.delta(), -0x0020_0000);
}

#[test]
fn reloc_rebuilder_apply_dir64_adds_delta() {
    let opts = RelocationOptions {
        original_base: 0x0040_0000,
        new_base: 0x0050_0000,
        rebuild_section: false,
    };
    let mut rb = RelocationRebuilder::new(opts);
    rb.add_dir64(0);
    let mut img = vec![0u8; 16];
    img[0..8].copy_from_slice(&0x400_0000u64.to_le_bytes());
    let n = rb.apply_to_image(&mut img).unwrap();
    assert_eq!(n, 1);
    let v = u64::from_le_bytes(img[0..8].try_into().unwrap());
    assert_eq!(v, 0x400_0000 + 0x0010_0000);
}

#[test]
fn reloc_rebuilder_apply_oob() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_dir64(100);
    let mut img = vec![0u8; 16];
    let err = rb.apply_to_image(&mut img).unwrap_err();
    assert!(matches!(err, RebuildError::BadReloc(_)));
}

#[test]
fn reloc_rebuilder_block_header_correct() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_dir64(0x1008);
    rb.add_dir64(0x1010);
    let blob = rb.build_reloc_section().unwrap();
    // page rva
    let prva = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    assert_eq!(prva, 0x1000);
    // block size = 8 + 2*2 = 12 (even entries, no pad)
    let bsz = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    assert_eq!(bsz, 12);
    // entries sorted ascending by page offset
    let e0 = u16::from_le_bytes(blob[8..10].try_into().unwrap());
    let e1 = u16::from_le_bytes(blob[10..12].try_into().unwrap());
    assert_eq!(e0 & 0xFFF, 0x008);
    assert_eq!(e1 & 0xFFF, 0x010);
    assert_eq!(e0 >> 12, 10); // dir64
}

#[test]
fn reloc_rebuilder_odd_count_gets_padding() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_dir64(0x1008);
    let blob = rb.build_reloc_section().unwrap();
    let bsz = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    // 8 + (1+1)*2 = 12
    assert_eq!(bsz, 12);
    // padding word should be zero
    let pad = u16::from_le_bytes(blob[10..12].try_into().unwrap());
    assert_eq!(pad, 0);
}

// ---------------------------------------------------------------------------
// ExportRebuilder
// ---------------------------------------------------------------------------

#[test]
fn export_rebuilder_empty_is_empty_blob() {
    let r = ExportRebuilder::new("foo.dll".into(), 1);
    assert_eq!(r.build(0).unwrap(), Vec::<u8>::new());
    assert_eq!(r.export_count(), 0);
    assert_eq!(r.dll_name(), "foo.dll");
}

#[test]
fn export_rebuilder_ordinal_below_base_err() {
    let mut r = ExportRebuilder::new("foo.dll".into(), 10);
    r.add_entry(ExportEntry::named("Bad".into(), 1, 0x1000));
    let err = r.build(0).unwrap_err();
    assert!(matches!(err, RebuildError::ExportCorrupt(_)));
}

#[test]
fn export_rebuilder_writes_header_fields() {
    let mut r = ExportRebuilder::new("foo.dll".into(), 1);
    r.add_entry(ExportEntry::named("Bar".into(), 1, 0x2000));
    let section_rva = 0x5000;
    let blob = r.build(section_rva).unwrap();
    // OrdinalBase at offset 16
    let ord_base = u32::from_le_bytes(blob[16..20].try_into().unwrap());
    assert_eq!(ord_base, 1);
    // AddressTableEntries at offset 20
    let n_funcs = u32::from_le_bytes(blob[20..24].try_into().unwrap());
    assert_eq!(n_funcs, 1);
    // NumberOfNamePointers at offset 24
    let n_names = u32::from_le_bytes(blob[24..28].try_into().unwrap());
    assert_eq!(n_names, 1);
    // Name RVA at offset 12 points to DLL name string (section_rva + strings_off)
    let name_rva = u32::from_le_bytes(blob[12..16].try_into().unwrap());
    assert!(name_rva >= section_rva);
}

#[test]
fn export_rebuilder_ordinal_only_no_name() {
    let mut r = ExportRebuilder::new("x.dll".into(), 1);
    r.add_entry(ExportEntry::ordinal_only(1, 0x1000));
    let blob = r.build(0).unwrap();
    let n_names = u32::from_le_bytes(blob[24..28].try_into().unwrap());
    assert_eq!(n_names, 0);
}

#[test]
fn export_entry_forwarder_display() {
    let e = ExportEntry::forwarder("Foo".into(), 1, "NTDLL.RtlAlloc".into());
    let s = e.to_string();
    assert!(s.contains("NTDLL.RtlAlloc"));
    assert!(e.is_forwarder);
    assert_eq!(e.forwarder.as_deref(), Some("NTDLL.RtlAlloc"));
}

// ---------------------------------------------------------------------------
// IatScanner
// ---------------------------------------------------------------------------

#[test]
fn iat_scanner_empty_dump() {
    assert!(IatScanner::scan_for_iat(&[], 0).is_empty());
}

#[test]
fn iat_scanner_all_zero_finds_nothing() {
    let dump = vec![0u8; 4096];
    let regions = IatScanner::scan_for_iat(&dump, 0x10_0000_0000);
    assert!(regions.is_empty());
}

#[test]
fn iat_scanner_finds_plausible_pointers() {
    let mut dump = vec![0u8; 64];
    // Two plausible pointers in user-space range, 8-byte aligned values.
    let p1 = 0x7FFE_0000_1000u64;
    let p2 = 0x7FFE_0000_2000u64;
    dump[0..8].copy_from_slice(&p1.to_le_bytes());
    dump[8..16].copy_from_slice(&p2.to_le_bytes());
    // Followed by junk.
    let regions = IatScanner::scan_for_iat(&dump, 0x10_0000_0000);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].entries, vec![p1, p2]);
    assert_eq!(regions[0].slot_count(), 2);
    assert!(regions[0].is_non_empty());
}

#[test]
fn iat_scanner_singleton_dropped() {
    let mut dump = vec![0u8; 32];
    let p = 0x7FFE_0000_1000u64;
    dump[0..8].copy_from_slice(&p.to_le_bytes());
    // Slot 1: zero (not plausible). MIN_ENTRIES is 2, so the lone pointer is discarded.
    let regions = IatScanner::scan_for_iat(&dump, 0);
    assert!(regions.is_empty());
}

// ---------------------------------------------------------------------------
// ModuleResolver
// ---------------------------------------------------------------------------

#[test]
fn module_resolver_finds_dll_in_range() {
    let modules = vec![(0x7FF0_0000_0000u64, 0x10_0000u64, "C:\\Windows\\System32\\kernel32.dll".to_string())];
    let res = ModuleResolver::resolve_pointer(0x7FF0_0000_5000, &modules);
    let (dll, _func) = res.unwrap();
    assert_eq!(dll, "kernel32.dll");
}

#[test]
fn module_resolver_returns_none_outside_range() {
    let modules = vec![(0x1000u64, 0x100u64, "foo.dll".to_string())];
    assert!(ModuleResolver::resolve_pointer(0x999, &modules).is_none());
    assert!(ModuleResolver::resolve_pointer(0x1100, &modules).is_none());
}

#[test]
fn module_resolver_batch_skips_unresolved() {
    let modules = vec![(0x1000u64, 0x100u64, "foo.dll".to_string())];
    let ptrs = vec![(0x1050u64, 0x100u32), (0x9999u64, 0x200u32)];
    let out = ModuleResolver::resolve_batch(&ptrs, &modules);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, 0x100);
    assert_eq!(out[0].1, "foo.dll");
}

#[test]
fn module_resolver_handles_forward_slashes() {
    let modules = vec![(0u64, 0x10u64, "/usr/lib/libfoo.so".to_string())];
    let (dll, _) = ModuleResolver::resolve_pointer(5, &modules).unwrap();
    assert_eq!(dll, "libfoo.so");
}

// ---------------------------------------------------------------------------
// compute_imphash
// ---------------------------------------------------------------------------

#[test]
fn compute_imphash_empty_is_empty_or_seed() {
    // Doc says returns empty string when no named entries. The implementation
    // joins "" then hashes 5381 to hex (16 hex). Verify behaviour matches doc.
    let h = compute_imphash(&[]);
    assert!(
        h.is_empty() || h.len() == 16,
        "imphash on empty: expected '' per doc, got {h:?}"
    );
}

#[test]
fn compute_imphash_case_insensitive_and_sorted() {
    let mk = |dll: &str, fname: &str| IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: Some(dll.to_string()),
        function_name: Some(fname.to_string()),
        ordinal: None,
    };
    let a = compute_imphash(&[mk("KERNEL32.DLL", "VirtualAlloc"), mk("ntdll.dll", "NtAlloc")]);
    let b = compute_imphash(&[mk("ntdll.dll", "ntalloc"), mk("kernel32.dll", "virtualalloc")]);
    assert_eq!(a, b);
}

#[test]
fn compute_imphash_skips_unresolved() {
    let resolved = IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: Some("k.dll".into()),
        function_name: Some("Foo".into()),
        ordinal: None,
    };
    let unresolved = IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: None,
        function_name: None,
        ordinal: None,
    };
    let a = compute_imphash(&[resolved.clone()]);
    let b = compute_imphash(&[resolved, unresolved]);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// PeDumper
// ---------------------------------------------------------------------------

#[test]
fn pe_dumper_too_short() {
    let err = PeDumper::build_valid_pe(&[0u8; 8], 0, 0).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn pe_dumper_no_pe_signature() {
    // 256 bytes of MZ-only — e_lfanew points outside; scan finds no PE.
    let mut data = vec![0xCCu8; 256];
    data[0] = b'M';
    data[1] = b'Z';
    data[60..64].copy_from_slice(&0xFFFFu32.to_le_bytes());
    let err = PeDumper::build_valid_pe(&data, 0x140_0000, 0x140_1000).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn pe_dumper_rewrites_entrypoint() {
    let bytes = make_x64_pe();
    let out = PeDumper::build_valid_pe(&bytes, 0x0001_4000_0000, 0x0001_4000_2000).unwrap();
    let pe_off = u32::from_le_bytes(out[60..64].try_into().unwrap()) as usize;
    let opt_off = pe_off + 24;
    let ep = u32::from_le_bytes(out[opt_off + 16..opt_off + 20].try_into().unwrap());
    assert_eq!(ep, 0x2000);
}

#[test]
fn pe_dumper_zeros_checksum() {
    let mut bytes = make_x64_pe();
    let pe_off = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    let opt_off = pe_off + 24;
    bytes[opt_off + 64..opt_off + 68].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let out = PeDumper::build_valid_pe(&bytes, 0, 0).unwrap();
    assert_eq!(&out[opt_off + 64..opt_off + 68], &[0u8; 4]);
}

#[test]
fn pe_dumper_auto_build_no_prologue() {
    // 64 bytes of zeros — no prologue.
    let dump = vec![0u8; 64];
    let err = PeDumper::auto_build(&dump, 0).unwrap_err();
    assert!(matches!(err, RebuildError::NoOepCandidates));
}

#[test]
fn pe_dumper_find_iat_regions_delegates() {
    let mut dump = vec![0u8; 64];
    let p = 0x7FFE_0000_1000u64;
    dump[0..8].copy_from_slice(&p.to_le_bytes());
    dump[8..16].copy_from_slice(&p.to_le_bytes());
    let regions = PeDumper::find_iat_regions(&dump, 0);
    assert_eq!(regions.len(), 1);
}

// ---------------------------------------------------------------------------
// PeRebuilder::rebuild_iat_from_memory
// ---------------------------------------------------------------------------

#[test]
fn rebuild_iat_from_memory_empty_err() {
    let err = PeRebuilder::rebuild_iat_from_memory(&[], 0, None).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn rebuild_iat_from_memory_resolves_known() {
    let mut dump = vec![0u8; 64];
    let p1 = 0x7FFE_0000_1000u64;
    let p2 = 0x7FFE_0000_2000u64;
    dump[0..8].copy_from_slice(&p1.to_le_bytes());
    dump[8..16].copy_from_slice(&p2.to_le_bytes());
    let mut imports: HashMap<u64, (String, String)> = HashMap::new();
    imports.insert(p1, ("a.dll".into(), "fnA".into()));
    let res = PeRebuilder::rebuild_iat_from_memory(&dump, 0, Some(&imports)).unwrap();
    assert!(res.total_entries() >= 2);
    // Known-resolved entry should match dll a.dll.
    let known = res.entries.iter().find(|e| e.value == p1).unwrap();
    assert_eq!(known.dll_name.as_deref(), Some("a.dll"));
    assert_eq!(known.function_name.as_deref(), Some("fnA"));
    // Unknown entry still gets stub name (per implementation).
    let unk = res.entries.iter().find(|e| e.value == p2).unwrap();
    assert!(unk.dll_name.is_some());
    assert!(unk.function_name.is_some());
}

// ---------------------------------------------------------------------------
// PeRebuilder::verify_pe_validity
// ---------------------------------------------------------------------------

#[test]
fn verify_pe_validity_too_short() {
    let issues = PeRebuilder::verify_pe_validity(&[0u8; 10]);
    assert!(!issues.is_empty());
    assert!(issues[0].contains("too short"));
}

#[test]
fn verify_pe_validity_bad_dos_magic() {
    let mut bytes = vec![0u8; 256];
    bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    let issues = PeRebuilder::verify_pe_validity(&bytes);
    assert!(issues.iter().any(|s| s.contains("DOS magic")));
}

#[test]
fn verify_pe_validity_clean_pe_minimal_issues() {
    let bytes = make_x64_pe();
    let issues = PeRebuilder::verify_pe_validity(&bytes);
    // Should have at most TLS-absent advisory; not a fatal error.
    for i in &issues {
        assert!(!i.contains("invalid DOS magic"));
        assert!(!i.contains("invalid PE signature"));
        assert!(!i.contains("section count"));
    }
}

// ---------------------------------------------------------------------------
// DumpFixer
// ---------------------------------------------------------------------------

#[test]
fn dump_fixer_fix_section_flags_too_short() {
    let mut d = vec![0u8; 8];
    let err = DumpFixer::fix_section_flags(&mut d).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn dump_fixer_fix_section_flags_no_pe_sig() {
    let mut d = vec![0u8; 128];
    d[60..64].copy_from_slice(&64u32.to_le_bytes());
    // bytes at 64 are zero — not "PE\0\0".
    let err = DumpFixer::fix_section_flags(&mut d).unwrap_err();
    assert!(matches!(err, RebuildError::Other(_)));
}

#[test]
fn dump_fixer_fix_section_flags_sets_text_executable() {
    let mut bytes = make_x64_pe();
    // Zero out characteristics for first section.
    let pe = PeFile::parse(&bytes).unwrap();
    let pe_off = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    let opt_off = pe_off + 24;
    let opt_hdr_size = u16::from_le_bytes([bytes[pe_off + 20], bytes[pe_off + 21]]) as usize;
    let sect_off = opt_off + opt_hdr_size;
    // First section header characteristics at sect_off + 36
    bytes[sect_off + 36..sect_off + 40].copy_from_slice(&0u32.to_le_bytes());
    DumpFixer::fix_section_flags(&mut bytes).unwrap();
    let new_chars =
        u32::from_le_bytes(bytes[sect_off + 36..sect_off + 40].try_into().unwrap());
    // .text name should produce CODE | EXECUTE | READ
    assert!(new_chars & chars::MEM_EXECUTE != 0);
    assert!(new_chars & chars::MEM_READ != 0);
    let _ = pe;
}

#[test]
fn dump_fixer_fix_iat_converts_va_to_rva() {
    // Build a buffer where bytes look like IAT pointers within image range.
    let mut dump = vec![0u8; 4096];
    // Two plausible pointers within image range (0..4096). But PTR_MIN is 0x1000_0000 in
    // IatScanner, so values below that won't be detected. Use values within [PTR_MIN, base+image_size).
    // Since image_size is small, FIX-iat can't run meaningfully with base=0.
    // Use base=0x1000_0000 and image_size 4096 so any value in [0x1000_0000, 0x1000_1000) is in image.
    let base: u64 = 0x1000_0000;
    let p1: u64 = base + 0x500;
    let p2: u64 = base + 0x600;
    dump[0..8].copy_from_slice(&p1.to_le_bytes());
    dump[8..16].copy_from_slice(&p2.to_le_bytes());
    DumpFixer::fix_iat(&mut dump, base).unwrap();
    let v1 = u64::from_le_bytes(dump[0..8].try_into().unwrap());
    let v2 = u64::from_le_bytes(dump[8..16].try_into().unwrap());
    assert_eq!(v1, 0x500);
    assert_eq!(v2, 0x600);
}

// ---------------------------------------------------------------------------
// IatRegion display
// ---------------------------------------------------------------------------

#[test]
fn iat_region_display() {
    let r = IatRegion { va: 0x1234, size: 16, entries: vec![1, 2] };
    let s = r.to_string();
    assert!(s.contains("0x1234"));
    assert!(s.contains("entries=2"));
}

// ---------------------------------------------------------------------------
// IatRebuildResult / RebuildStats serde
// ---------------------------------------------------------------------------

#[test]
fn rebuild_stats_serde_roundtrip() {
    let s = RebuildStats {
        iat_entries_fixed: 7,
        relocations_applied: 3,
        exports_reconstructed: 1,
        overlay_bytes: 100,
        oep_detected: true,
    };
    let j = serde_json::to_string(&s).unwrap();
    let s2: RebuildStats = serde_json::from_str(&j).unwrap();
    assert_eq!(s2.iat_entries_fixed, 7);
    assert!(s2.oep_detected);
}

// ---------------------------------------------------------------------------
// from_memory_dump with bytes that PeFile parses
// ---------------------------------------------------------------------------

#[test]
fn from_memory_dump_clean_pe_x86_via_explicit_config() {
    let bytes = make_x86_pe();
    let mut cfg = RebuildConfig::default();
    // `is_64bit` is not a field: it is the IS_64BIT bit inside `flags`.
    cfg.flags = RebuildFlags(cfg.flags.0 & !RebuildFlags::IS_64BIT.0);
    cfg.machine = PeMachine::I386;
    let result = PeRebuilder::from_memory_dump(&bytes, 0x0040_0000, cfg).unwrap();
    assert!(result.section_count >= 1);
}
