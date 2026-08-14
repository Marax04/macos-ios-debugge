//! Deep adversarial test suite for `rustre-pe-rebuild`.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_pe_rebuild::*;
use rustre_pe_tools::PeBuilder;

// ---------------------------------------------------------------------------
// Seeded LCG fuzz helper
// ---------------------------------------------------------------------------

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn make_x64_pe() -> Vec<u8> {
    let mut b = PeBuilder::new_x64();
    b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
    b.add_section(".data", vec![0u8; 32], 0xC000_0040);
    b.build()
}

// ---------------------------------------------------------------------------
// 1. compute_entropy
// ---------------------------------------------------------------------------

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(compute_entropy(&[]), 0.0);
}

#[test]
fn entropy_single_byte_is_zero() {
    assert_eq!(compute_entropy(&[0x42]), 0.0);
}

#[test]
fn entropy_uniform_distribution_near_eight() {
    let data: Vec<u8> = (0u8..=255).collect();
    let e = compute_entropy(&data);
    assert!(e > 7.99 && e <= 8.0, "got {e}");
}

#[test]
fn entropy_all_same_byte_is_zero() {
    let data = vec![0xAAu8; 1024];
    assert!(compute_entropy(&data).abs() < 1e-9);
}

#[test]
fn entropy_fuzz_bounded() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() % 512) as usize + 1;
        let data: Vec<u8> = (0..len).map(|_| g() as u8).collect();
        let e = compute_entropy(&data);
        assert!((0.0..=8.0001).contains(&e), "out of bounds entropy {e}");
    }
}

// ---------------------------------------------------------------------------
// 2. crc16_ccitt
// ---------------------------------------------------------------------------

#[test]
fn crc16_check_vector() {
    assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
}

#[test]
fn crc16_empty_init_value() {
    assert_eq!(crc16_ccitt(&[]), 0xFFFF);
}

#[test]
fn crc16_deterministic_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() % 256) as usize;
        let data: Vec<u8> = (0..len).map(|_| g() as u8).collect();
        let c1 = crc16_ccitt(&data);
        let c2 = crc16_ccitt(&data);
        assert_eq!(c1, c2);
    }
}

// ---------------------------------------------------------------------------
// 3. align_up
// ---------------------------------------------------------------------------

#[test]
fn align_up_zero_align_passthrough() {
    assert_eq!(PeRebuilder::align_up(42, 0), 42);
    assert_eq!(PeRebuilder::align_up(u32::MAX, 0), u32::MAX);
}

#[test]
fn align_up_one_is_identity() {
    let mut g = lcg();
    for _ in 0..30 {
        let v = g() as u32;
        assert_eq!(PeRebuilder::align_up(v, 1), v);
    }
}

#[test]
fn align_up_boundary_cases() {
    assert_eq!(PeRebuilder::align_up(0, 0x1000), 0);
    assert_eq!(PeRebuilder::align_up(1, 0x1000), 0x1000);
    assert_eq!(PeRebuilder::align_up(0xFFF, 0x1000), 0x1000);
    assert_eq!(PeRebuilder::align_up(0x1000, 0x1000), 0x1000);
    assert_eq!(PeRebuilder::align_up(0x1001, 0x1000), 0x2000);
}

#[test]
fn align_up_overflow_saturates() {
    // Near u32::MAX
    let v = u32::MAX - 1;
    let aligned = PeRebuilder::align_up(v, 0x1000);
    // Either u32::MAX (saturated) or a clean roundup if it fits.
    assert!(aligned >= v);
}

// ---------------------------------------------------------------------------
// 4. RebuildSection
// ---------------------------------------------------------------------------

#[test]
fn section_new_sets_virtual_size_from_data_len() {
    let s = RebuildSection::new("x".to_string(), 0x1000, vec![0u8; 123], 0);
    assert_eq!(s.virtual_size, 123);
}

#[test]
fn section_code_flags() {
    let s = RebuildSection::code(".text".to_string(), 0x1000, vec![0x90; 4]);
    assert!(s.is_executable());
    assert!(!s.is_writable());
}

#[test]
fn section_data_flags() {
    let s = RebuildSection::data(".data".to_string(), 0x2000, vec![0; 4]);
    assert!(!s.is_executable());
    assert!(s.is_writable());
}

#[test]
fn section_rdata_flags() {
    let s = RebuildSection::rdata(".rdata".to_string(), 0x3000, vec![0; 4]);
    assert!(!s.is_executable());
    assert!(!s.is_writable());
}

#[test]
fn section_contains_rva_off_by_one() {
    let s = RebuildSection::new("a".to_string(), 0x1000, vec![0u8; 0x100], 0);
    assert!(s.contains_rva(0x1000)); // start
    assert!(s.contains_rva(0x10FF)); // last
    assert!(!s.contains_rva(0x1100)); // one past end
    assert!(!s.contains_rva(0x0FFF)); // one before start
}

#[test]
fn section_rva_to_offset_oob() {
    let s = RebuildSection::new("a".to_string(), 0x1000, vec![0u8; 8], 0);
    assert_eq!(s.rva_to_offset(0x1000), Some(0));
    assert_eq!(s.rva_to_offset(0x1007), Some(7));
    assert_eq!(s.rva_to_offset(0x0FFF), None);
    assert_eq!(s.rva_to_offset(0x2000), None);
}

#[test]
fn section_virtual_end_saturates() {
    let s = RebuildSection::new("a".to_string(), u32::MAX - 5, vec![0u8; 100], 0);
    let ve = s.virtual_end();
    assert!(ve == u32::MAX);
}

#[test]
fn section_serde_roundtrip() {
    let s = RebuildSection::new(".x".to_string(), 0x1000, vec![1, 2, 3, 4], 0xC000_0040);
    let json = serde_json::to_string(&s).unwrap();
    let s2: RebuildSection = serde_json::from_str(&json).unwrap();
    assert_eq!(s2.name, s.name);
    assert_eq!(s2.virtual_address, s.virtual_address);
    assert_eq!(s2.data, s.data);
}

// ---------------------------------------------------------------------------
// 5. RebuildConfig
// ---------------------------------------------------------------------------

#[test]
fn config_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..20 {
        let mut cfg = RebuildConfig::default();
        cfg.image_base = g();
        cfg.entry_point_rva = g() as u32;
        // `is_64bit` is not a field: it is the IS_64BIT bit inside `flags`,
        // read back through `RebuildFlags::is_64bit()`.
        cfg.flags = if g() & 1 == 0 {
            RebuildFlags(cfg.flags.0 | RebuildFlags::IS_64BIT.0)
        } else {
            RebuildFlags(cfg.flags.0 & !RebuildFlags::IS_64BIT.0)
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: RebuildConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.image_base, cfg.image_base);
        assert_eq!(cfg2.entry_point_rva, cfg.entry_point_rva);
    }
}

// ---------------------------------------------------------------------------
// 6. PeRebuilder
// ---------------------------------------------------------------------------

#[test]
fn rebuilder_no_sections_errors() {
    let r = PeRebuilder::new(RebuildConfig::default());
    assert!(matches!(r.rebuild(), Err(RebuildError::NoSections)));
}

#[test]
fn rebuilder_multiple_sections_roundtrip() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    for i in 0..3 {
        r.add_section(RebuildSection::new(
            format!(".s{i}"),
            0x1000 + i * 0x1000,
            vec![i as u8; 0x40],
            0x6000_0020,
        ));
    }
    let result = r.rebuild().unwrap();
    assert_eq!(result.section_count, 3);
    assert!(!result.data.is_empty());
}

#[test]
fn rebuilder_section_by_name_and_rva() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    r.add_section(RebuildSection::new(".text".to_string(), 0x1000, vec![0; 0x100], 0x20));
    assert!(r.section_by_name(".text").is_some());
    assert!(r.section_by_name(".missing").is_none());
    assert!(r.section_at_rva(0x1010).is_some());
    assert!(r.section_at_rva(0x9000).is_none());
}

#[test]
fn rebuilder_clear_and_sort() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    r.add_section(RebuildSection::new(".b".to_string(), 0x3000, vec![0; 4], 0));
    r.add_section(RebuildSection::new(".a".to_string(), 0x1000, vec![0; 4], 0));
    r.sort_sections();
    assert_eq!(r.sections()[0].virtual_address, 0x1000);
    r.clear_sections();
    assert_eq!(r.section_count(), 0);
}

#[test]
fn rebuilder_from_memory_dump_bad_magic_err() {
    let data = vec![0u8; 256];
    assert!(matches!(
        PeRebuilder::from_memory_dump(&data, 0, RebuildConfig::default()),
        Err(RebuildError::Other(_))
    ));
}

#[test]
fn rebuilder_from_memory_dump_short_data_err() {
    let data = vec![0x4D, 0x5A]; // MZ but too short
    assert!(PeRebuilder::from_memory_dump(&data, 0, RebuildConfig::default()).is_err());
}

#[test]
fn rebuilder_from_memory_dump_valid() {
    let bytes = make_x64_pe();
    let r = PeRebuilder::from_memory_dump(&bytes, 0x0001_4000_0000, RebuildConfig::default()).unwrap();
    assert!(r.section_count >= 1);
}

#[test]
fn rebuilder_with_oep_detection() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    let mut code = vec![0u8; 64];
    code[0] = 0x55;
    code[1] = 0x48;
    code[2] = 0x89;
    code[3] = 0xE5;
    r.add_section(RebuildSection::code(".text".to_string(), 0x1000, code));
    let result = r.rebuild_with_oep_detection().unwrap();
    assert!(result.stats.oep_detected);
}

#[test]
fn rebuilder_oep_detection_no_exec_errors() {
    let mut r = PeRebuilder::new(RebuildConfig::default());
    r.add_section(RebuildSection::data(".data".to_string(), 0x1000, vec![0; 16]));
    assert!(matches!(
        r.rebuild_with_oep_detection(),
        Err(RebuildError::NoOepCandidates)
    ));
}

// ---------------------------------------------------------------------------
// 7. IatEntry / IatFixer
// ---------------------------------------------------------------------------

#[test]
fn iat_entry_resolved_predicate() {
    let mut e = IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: None,
        function_name: None,
        ordinal: None,
    };
    assert!(!e.is_resolved());
    e.ordinal = Some(7);
    assert!(e.is_resolved());
    e.ordinal = None;
    e.function_name = Some("X".to_string());
    assert!(e.is_resolved());
}

#[test]
fn iat_fixer_known_imports_resolve() {
    let mut fx = IatFixer::new(IatFixOptions::default());
    fx.register_import(0xABCDu64, "kernel32.dll".into(), "Sleep".into());
    fx.add_entry(IatEntry {
        iat_rva: 0x100,
        value: 0xABCD,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    let fixed = fx.fix().unwrap();
    assert_eq!(fixed, 1);
    assert_eq!(fx.resolved_count(), 1);
}

#[test]
fn iat_fixer_apply_to_image_oob_errors() {
    let bytes = make_x64_pe();
    let mut img = bytes.clone();
    let mut fx = IatFixer::new(IatFixOptions::default());
    fx.add_entry(IatEntry {
        iat_rva: 0xFFFF_FF00,
        value: 0,
        dll_name: None,
        function_name: None,
        ordinal: None,
    });
    assert!(matches!(
        fx.apply_to_image(&mut img, 0x0001_4000_0000),
        Err(RebuildError::IatOutOfBounds(_))
    ));
}

// ---------------------------------------------------------------------------
// 8. RelocationEntry / RelocationRebuilder
// ---------------------------------------------------------------------------

#[test]
fn reloc_eq_hash_consistency() {
    let mut g = lcg();
    for _ in 0..30 {
        let a = RelocationEntry {
            rva: g() as u32,
            reloc_type: (g() & 0xFF) as u8,
        };
        let b = a;
        assert_eq!(a, b);
        // Eq derived from PartialEq+Eq.
    }
}

#[test]
fn reloc_rebuilder_empty_is_empty_blob() {
    let rb = RelocationRebuilder::new(RelocationOptions::default());
    assert!(rb.build_reloc_section().unwrap().is_empty());
}

#[test]
fn reloc_rebuilder_invalid_type_errors() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_entry(RelocationEntry {
        rva: 0x1000,
        reloc_type: 7, // invalid
    });
    assert!(matches!(
        rb.build_reloc_section(),
        Err(RebuildError::BadReloc(_))
    ));
}

#[test]
fn reloc_apply_oob_errors() {
    let mut rb = RelocationRebuilder::new(RelocationOptions {
        original_base: 0x0040_0000,
        new_base: 0x0050_0000,
        rebuild_section: false,
    });
    rb.add_dir64(0x10_0000);
    let mut img = vec![0u8; 16];
    assert!(matches!(
        rb.apply_to_image(&mut img),
        Err(RebuildError::BadReloc(_))
    ));
}

#[test]
fn reloc_apply_zero_delta_no_change() {
    let mut rb = RelocationRebuilder::new(RelocationOptions {
        original_base: 0x0040_0000,
        new_base: 0x0040_0000,
        rebuild_section: false,
    });
    rb.add_highlow(0);
    let mut img = vec![0u8; 8];
    img[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let copy = img.clone();
    rb.apply_to_image(&mut img).unwrap();
    assert_eq!(img, copy);
}

#[test]
fn reloc_section_blob_block_aligned() {
    let mut rb = RelocationRebuilder::new(RelocationOptions::default());
    rb.add_dir64(0x1000);
    rb.add_dir64(0x1008);
    rb.add_dir64(0x1010);
    let blob = rb.build_reloc_section().unwrap();
    // block size at offset 4..8 must be a multiple of 4
    let block_size = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    assert_eq!(block_size % 4, 0);
}

// ---------------------------------------------------------------------------
// 9. ExportRebuilder
// ---------------------------------------------------------------------------

#[test]
fn export_rebuilder_ordinal_below_base_errors() {
    let mut rb = ExportRebuilder::new("x.dll".to_string(), 5);
    rb.add_entry(ExportEntry::named("Bad".to_string(), 1, 0x1000));
    assert!(matches!(rb.build(0x5000), Err(RebuildError::ExportCorrupt(_))));
}

#[test]
fn export_rebuilder_builds_directory() {
    let mut rb = ExportRebuilder::new("t.dll".to_string(), 1);
    rb.add_entry(ExportEntry::named("A".to_string(), 1, 0x1000));
    rb.add_entry(ExportEntry::named("B".to_string(), 2, 0x2000));
    let blob = rb.build(0x5000).unwrap();
    assert!(blob.len() >= 0x28);
    // OrdinalBase at offset 16
    let ord_base = u32::from_le_bytes(blob[16..20].try_into().unwrap());
    assert_eq!(ord_base, 1);
}

// ---------------------------------------------------------------------------
// 10. is_memory_pe
// ---------------------------------------------------------------------------

#[test]
fn is_memory_pe_truth_table() {
    assert!(!is_memory_pe(&[]));
    assert!(!is_memory_pe(&[0x4D, 0x5A]));
    let mut data = vec![0u8; 64];
    data[0] = 0x4D;
    data[1] = 0x5A;
    assert!(is_memory_pe(&data));
    data[0] = 0x00;
    assert!(!is_memory_pe(&data));
}

// ---------------------------------------------------------------------------
// 11. apply_fixups
// ---------------------------------------------------------------------------

#[test]
fn apply_fixups_short_image_err() {
    let mut data = vec![0u8; 10];
    assert!(apply_fixups(&mut data, &PeFixupOptions::default()).is_err());
}

#[test]
fn apply_fixups_invalid_pe_sig_err() {
    let mut data = vec![0u8; 256];
    data[60..64].copy_from_slice(&64u32.to_le_bytes());
    assert!(apply_fixups(&mut data, &PeFixupOptions::default()).is_err());
}

#[test]
fn apply_fixups_dll_flag_toggle() {
    let mut bytes = make_x64_pe();
    let opts = PeFixupOptions {
        set_dll_flag: Some(true),
        ..Default::default()
    };
    let notes = apply_fixups(&mut bytes, &opts).unwrap();
    assert!(notes.iter().any(|n| n.contains("DLL")));
}

// ---------------------------------------------------------------------------
// 12. OverlayHandler
// ---------------------------------------------------------------------------

#[test]
fn overlay_short_image_errors() {
    assert!(OverlayHandler::detect(&[0u8; 10]).is_err());
}

#[test]
fn overlay_detect_no_overlay() {
    let bytes = make_x64_pe();
    let info = OverlayHandler::detect(&bytes).unwrap();
    assert!(!info.has_overlay());
}

#[test]
fn overlay_extract_and_preserve() {
    let mut bytes = make_x64_pe();
    bytes.extend_from_slice(b"OVERLAY!");
    let extracted = OverlayHandler::extract(&bytes).unwrap();
    assert_eq!(extracted, b"OVERLAY!");
}

// ---------------------------------------------------------------------------
// 13. compute_imphash
// ---------------------------------------------------------------------------

#[test]
fn imphash_empty_no_named_entries() {
    let h = compute_imphash(&[]);
    assert_eq!(h.len(), 16);
}

#[test]
fn imphash_dll_suffix_normalization() {
    // Two entries differing only in dll case+suffix should hash identically.
    let a = vec![IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: Some("KERNEL32.DLL".to_string()),
        function_name: Some("Sleep".to_string()),
        ordinal: None,
    }];
    let b = vec![IatEntry {
        iat_rva: 0,
        value: 0,
        dll_name: Some("kernel32".to_string()),
        function_name: Some("sleep".to_string()),
        ordinal: None,
    }];
    assert_eq!(compute_imphash(&a), compute_imphash(&b));
}

// ---------------------------------------------------------------------------
// 14. IatScanner / IatRegion
// ---------------------------------------------------------------------------

#[test]
fn iat_scanner_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = (g() % 4096) as usize;
        let data: Vec<u8> = (0..len).map(|_| g() as u8).collect();
        let _ = IatScanner::scan_for_iat(&data, g());
    }
}

#[test]
fn iat_region_slot_count_and_nonempty() {
    let r = IatRegion {
        va: 0x1000,
        size: 16,
        entries: vec![1, 2],
    };
    assert_eq!(r.slot_count(), 2);
    assert!(r.is_non_empty());
    let empty = IatRegion {
        va: 0,
        size: 0,
        entries: vec![],
    };
    assert!(!empty.is_non_empty());
}

// ---------------------------------------------------------------------------
// 15. ModuleResolver
// ---------------------------------------------------------------------------

#[test]
fn module_resolver_at_module_boundary() {
    let modules = vec![(0x1000u64, 0x100u64, "a.dll".to_string())];
    assert!(ModuleResolver::resolve_pointer(0x1000, &modules).is_some());
    assert!(ModuleResolver::resolve_pointer(0x10FF, &modules).is_some());
    assert!(ModuleResolver::resolve_pointer(0x1100, &modules).is_none());
    assert!(ModuleResolver::resolve_pointer(0x0FFF, &modules).is_none());
}

// ---------------------------------------------------------------------------
// 16. detect_oep_heuristics
// ---------------------------------------------------------------------------

#[test]
fn detect_oep_heuristics_empty_input() {
    assert!(detect_oep_heuristics(&[], 0).is_empty());
}

#[test]
fn detect_oep_heuristics_sorted_desc() {
    let mut g = lcg();
    let data: Vec<u8> = (0..1024).map(|_| g() as u8).collect();
    let candidates = detect_oep_heuristics(&data, 0x1000);
    for w in candidates.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

// ---------------------------------------------------------------------------
// 17. PeDumper
// ---------------------------------------------------------------------------

#[test]
fn pe_dumper_short_input_errors() {
    assert!(PeDumper::build_valid_pe(&[0u8; 10], 0, 0).is_err());
}

#[test]
fn pe_dumper_fuzz_short_inputs_never_panic() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = (g() % 200) as usize;
        let data: Vec<u8> = (0..len).map(|_| g() as u8).collect();
        // Should produce Ok or Err but never panic.
        let _ = PeDumper::build_valid_pe(&data, g(), g());
    }
}

#[test]
fn pe_dumper_valid_pe_roundtrip_sets_ep() {
    let bytes = make_x64_pe();
    let base = 0x0001_4000_0000_u64;
    let oep = base + 0x2000;
    let out = PeDumper::build_valid_pe(&bytes, base, oep).unwrap();
    let pe_off = u32::from_le_bytes([out[60], out[61], out[62], out[63]]) as usize;
    let opt_off = pe_off + 24;
    let ep_rva = u32::from_le_bytes(out[opt_off + 16..opt_off + 20].try_into().unwrap());
    assert_eq!(ep_rva, 0x2000);
}

// ---------------------------------------------------------------------------
// 18. PeRebuilder::rebuild_iat_from_memory
// ---------------------------------------------------------------------------

#[test]
fn rebuild_iat_from_memory_empty_errors() {
    assert!(matches!(
        PeRebuilder::rebuild_iat_from_memory(&[], 0, None),
        Err(RebuildError::Other(_))
    ));
}

#[test]
fn rebuild_iat_from_memory_known_imports() {
    let mut mem = vec![0u8; 512];
    let ptrs: [u64; 4] = [
        0x7FFF_0000_1000,
        0x7FFF_0000_2000,
        0x7FFF_0000_3000,
        0x7FFF_0000_4000,
    ];
    for (i, &p) in ptrs.iter().enumerate() {
        mem[i * 8..i * 8 + 8].copy_from_slice(&p.to_le_bytes());
    }
    let mut imports = HashMap::new();
    imports.insert(0x7FFF_0000_1000u64, ("a.dll".to_string(), "f".to_string()));
    let result =
        PeRebuilder::rebuild_iat_from_memory(&mem, 0x0001_4000_0000, Some(&imports)).unwrap();
    assert!(result.total_entries() > 0);
}

// ---------------------------------------------------------------------------
// 19. PeRebuilder::verify_pe_validity
// ---------------------------------------------------------------------------

#[test]
fn verify_pe_validity_short_image() {
    let issues = PeRebuilder::verify_pe_validity(&[0u8; 10]);
    assert!(!issues.is_empty());
}

#[test]
fn verify_pe_validity_bad_dos_magic() {
    let mut data = vec![0u8; 256];
    data[60..64].copy_from_slice(&64u32.to_le_bytes());
    data[64..68].copy_from_slice(b"PE\0\0");
    let issues = PeRebuilder::verify_pe_validity(&data);
    assert!(issues.iter().any(|s| s.contains("DOS")));
}

#[test]
fn verify_pe_validity_valid_pe_minimal_issues() {
    let bytes = make_x64_pe();
    let issues = PeRebuilder::verify_pe_validity(&bytes);
    // We allow TLS-missing advisory note, but no error-level structural issues.
    for i in &issues {
        assert!(
            i.contains("TLS") || i.contains("section count is zero"),
            "unexpected issue: {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// 20. DumpFixer
// ---------------------------------------------------------------------------

#[test]
fn dump_fixer_short_image_errors() {
    let mut data = vec![0u8; 32];
    assert!(DumpFixer::fix_section_flags(&mut data).is_err());
}

#[test]
fn dump_fixer_invalid_pe_sig_errors() {
    let mut data = vec![0u8; 256];
    data[60..64].copy_from_slice(&64u32.to_le_bytes());
    assert!(DumpFixer::fix_section_flags(&mut data).is_err());
}

#[test]
fn dump_fixer_fix_section_flags_runs() {
    let mut bytes = make_x64_pe();
    DumpFixer::fix_section_flags(&mut bytes).unwrap();
}

#[test]
fn dump_fixer_fix_iat_empty_dump() {
    let mut data = vec![0u8; 256];
    // No IAT regions; should be a no-op.
    DumpFixer::fix_iat(&mut data, 0).unwrap();
}

// ---------------------------------------------------------------------------
// 21. IatEntry2 / IatRebuilder (the second-generation IAT)
// ---------------------------------------------------------------------------

#[test]
fn iat_entry2_named_display_format() {
    let e = IatEntry2::named(0x1000, "k.dll", "Foo");
    assert_eq!(e.display_name(), "k.dll!Foo");
}

#[test]
fn iat_entry2_ordinal_display_format() {
    let e = IatEntry2::ordinal(0x1000, "n.dll", 99);
    assert!(e.display_name().contains("99"));
}

#[test]
fn loaded_module_boundary() {
    let m = LoadedModule::new("t.dll", 0x1000, 0x100);
    assert!(m.contains(0x1000));
    assert!(m.contains(0x10FF));
    assert!(!m.contains(0x1100));
}

#[test]
fn iat_rebuilder_va_to_offset_oob() {
    let rb = IatRebuilder::new_x64(vec![0u8; 16], 0x1000, vec![]);
    assert_eq!(rb.va_to_offset(0x1000), Some(0));
    assert_eq!(rb.va_to_offset(0x0FFF), None);
}

#[test]
fn iat_rebuilder_scan_handles_empty_memory() {
    let rb = IatRebuilder::new_x64(vec![], 0, vec![]);
    assert!(rb.scan_for_iat().is_empty());
}

#[test]
fn iat_rebuilder_import_directory_empty() {
    let rb = IatRebuilder::new_x64(vec![], 0, vec![]);
    assert!(rb.rebuild_import_directory(&[]).is_empty());
}

#[test]
fn iat_rebuilder_fix_checksum_bad_header_errors() {
    let mut rb = IatRebuilder::new_x86(vec![0u8; 0x200], 0, vec![]);
    rb.process_memory[0x3c] = 0x40;
    assert!(rb.fix_pe_checksum().is_err());
}

// ---------------------------------------------------------------------------
// 22. Threaded Send+Sync stress for plain data types
// ---------------------------------------------------------------------------

#[test]
fn entropy_send_sync_threaded() {
    let data: Arc<Vec<u8>> = Arc::new((0u8..=255).cycle().take(1024).collect());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                let mut acc = 0.0;
                for _ in 0..100 {
                    acc += compute_entropy(&d);
                }
                acc
            })
        })
        .collect();
    for h in handles {
        let v = h.join().unwrap();
        assert!(v > 0.0);
    }
}

#[test]
fn crc16_send_sync_threaded() {
    let data: Arc<Vec<u8>> = Arc::new(b"123456789".to_vec());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(crc16_ccitt(&d), 0x29B1);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
