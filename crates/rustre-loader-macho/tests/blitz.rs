//! Exhaustive test suite for rustre-loader-macho.
//!
//! Goal: surface bugs in parsers, opcodes, header decoders, helpers.

use rustre_loader_macho::*;
use rustre_core::Endian;

// ─────────────────────────────────────────────────────────────────────────────
// MachoArch
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn arch_from_cputype_known() {
    assert_eq!(MachoArch::from_cputype(7), MachoArch::X86);
    assert_eq!(MachoArch::from_cputype(0x0100_0007), MachoArch::X86_64);
    assert_eq!(MachoArch::from_cputype(12), MachoArch::Arm);
    assert_eq!(MachoArch::from_cputype(0x0100_000C), MachoArch::Arm64);
    assert_eq!(MachoArch::from_cputype(0x0200_000C), MachoArch::Arm64_32);
    assert_eq!(MachoArch::from_cputype(18), MachoArch::PowerPc);
    assert_eq!(MachoArch::from_cputype(0x0100_0012), MachoArch::PowerPc64);
    assert_eq!(MachoArch::from_cputype(8), MachoArch::Mips);
    assert_eq!(MachoArch::from_cputype(14), MachoArch::Sparc);
}

#[test]
fn arch_from_cputype_unknown() {
    assert_eq!(MachoArch::from_cputype(0xDEAD_BEEF), MachoArch::Unknown(0xDEAD_BEEF));
}

#[test]
fn arch_pointer_size() {
    assert_eq!(MachoArch::X86_64.pointer_size(), 8);
    assert_eq!(MachoArch::Arm64.pointer_size(), 8);
    assert_eq!(MachoArch::PowerPc64.pointer_size(), 8);
    assert_eq!(MachoArch::X86.pointer_size(), 4);
    assert_eq!(MachoArch::Arm.pointer_size(), 4);
    assert_eq!(MachoArch::Arm64_32.pointer_size(), 4);
    assert_eq!(MachoArch::Mips.pointer_size(), 4);
    assert_eq!(MachoArch::Sparc.pointer_size(), 4);
    assert_eq!(MachoArch::PowerPc.pointer_size(), 4);
    // Unknown defaults to 8.
    assert_eq!(MachoArch::Unknown(0).pointer_size(), 8);
}

#[test]
fn arch_names() {
    assert_eq!(MachoArch::X86.name(), "x86");
    assert_eq!(MachoArch::X86_64.name(), "x86_64");
    assert_eq!(MachoArch::Arm64.name(), "arm64");
    assert_eq!(MachoArch::Arm64_32.name(), "arm64_32");
    assert_eq!(MachoArch::PowerPc.name(), "ppc");
    assert_eq!(MachoArch::PowerPc64.name(), "ppc64");
    assert_eq!(MachoArch::Mips.name(), "mips");
    assert_eq!(MachoArch::Sparc.name(), "sparc");
    assert_eq!(MachoArch::Unknown(42).name(), "unknown");
}

#[test]
fn arch_endian_and_is_64bit() {
    assert!(matches!(MachoArch::PowerPc.endian(), Endian::Big));
    assert!(matches!(MachoArch::PowerPc64.endian(), Endian::Big));
    assert!(matches!(MachoArch::Mips.endian(), Endian::Big));
    assert!(matches!(MachoArch::Sparc.endian(), Endian::Big));
    assert!(matches!(MachoArch::X86_64.endian(), Endian::Little));
    assert!(matches!(MachoArch::Arm64.endian(), Endian::Little));

    assert!(MachoArch::X86_64.is_64bit());
    assert!(MachoArch::Arm64.is_64bit());
    assert!(MachoArch::PowerPc64.is_64bit());
    assert!(!MachoArch::Arm.is_64bit());
    assert!(!MachoArch::Arm64_32.is_64bit());
    assert!(!MachoArch::X86.is_64bit());
}

#[test]
fn arch_subtype_name() {
    assert_eq!(MachoArch::subtype_name(0x0100_0007, 3), "x86_64 (all)");
    assert_eq!(MachoArch::subtype_name(0x0100_0007, 8), "x86_64h (Haswell)");
    assert_eq!(MachoArch::subtype_name(0x0100_000C, 0), "arm64 (all)");
    assert_eq!(MachoArch::subtype_name(0x0100_000C, 1), "arm64v8");
    assert_eq!(MachoArch::subtype_name(0x0100_000C, 2), "arm64e");
    assert_eq!(MachoArch::subtype_name(12, 0), "arm (all)");
    assert_eq!(MachoArch::subtype_name(12, 9), "armv7");
    assert_eq!(MachoArch::subtype_name(12, 11), "armv7s");
    assert_eq!(MachoArch::subtype_name(12, 12), "armv7k");
    assert_eq!(MachoArch::subtype_name(99, 99), "unknown subtype");
    // The function masks the subtype with 0x00FF_FFFF — high bits ignored.
    assert_eq!(MachoArch::subtype_name(0x0100_000C, 0xFF00_0000), "arm64 (all)");
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoFileType
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn filetype_from_raw() {
    assert_eq!(MachoFileType::from_filetype(0x1), MachoFileType::Object);
    assert_eq!(MachoFileType::from_filetype(0x2), MachoFileType::Execute);
    assert_eq!(MachoFileType::from_filetype(0x6), MachoFileType::Dylib);
    assert_eq!(MachoFileType::from_filetype(0xC), MachoFileType::Fileset);
    assert_eq!(MachoFileType::from_filetype(0xFF), MachoFileType::Unknown(0xFF));
}

#[test]
fn filetype_predicates() {
    assert!(MachoFileType::Execute.is_executable());
    assert!(!MachoFileType::Dylib.is_executable());
    assert!(MachoFileType::Dylib.is_library());
    assert!(MachoFileType::DylibStub.is_library());
    assert!(!MachoFileType::Bundle.is_library());
    assert!(MachoFileType::Core.is_core());
    assert!(MachoFileType::Fileset.is_fileset());
    assert!(!MachoFileType::Object.is_fileset());
}

#[test]
fn filetype_names_unique() {
    let all = [
        MachoFileType::Object, MachoFileType::Execute, MachoFileType::FvmLib,
        MachoFileType::Core, MachoFileType::Preload, MachoFileType::Dylib,
        MachoFileType::Dylinker, MachoFileType::Bundle, MachoFileType::DylibStub,
        MachoFileType::Dsym, MachoFileType::KextBundle, MachoFileType::Fileset,
    ];
    let names: Vec<&str> = all.iter().map(|f| f.name()).collect();
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(names.len(), unique.len(), "duplicate filetype names: {names:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSegment helpers
// ─────────────────────────────────────────────────────────────────────────────

fn seg(prot: u32, addr: u64, size: u64, foff: u64, fsize: u64) -> MachoSegment {
    MachoSegment {
        name: "X".into(), vm_addr: addr, vm_size: size,
        file_offset: foff, file_size: fsize,
        max_prot: prot, init_prot: prot, sections: vec![],
    }
}

#[test]
fn segment_perm_bits() {
    let s = seg(0x1 | 0x4, 0, 0, 0, 0); // R|X
    assert!(s.is_readable());
    assert!(!s.is_writable());
    assert!(s.is_executable());

    let s = seg(0x2, 0, 0, 0, 0); // W only
    assert!(!s.is_readable());
    assert!(s.is_writable());
    assert!(!s.is_executable());

    let s = seg(0, 0, 0, 0, 0);
    assert!(!s.is_readable() && !s.is_writable() && !s.is_executable());
}

#[test]
fn segment_contains_addr() {
    let s = seg(0, 0x1000, 0x100, 0, 0);
    assert!(s.contains_addr(0x1000));
    assert!(s.contains_addr(0x10FF));
    assert!(!s.contains_addr(0x1100));
    assert!(!s.contains_addr(0xFFF));
}

#[test]
fn segment_contains_addr_overflow() {
    // vm_addr + vm_size would overflow — must saturate, not panic.
    let s = seg(0, u64::MAX - 10, 100, 0, 0);
    assert!(s.contains_addr(u64::MAX - 1));
    assert!(s.contains_addr(u64::MAX - 10));
}

#[test]
fn segment_file_range_overflow() {
    let s = seg(0, 0, 0, usize::MAX as u64 - 5, 100);
    let r = s.file_range();
    // saturating_add must yield usize::MAX as end.
    assert_eq!(r.end, usize::MAX);
}

#[test]
fn segment_file_range_normal() {
    let s = seg(0, 0, 0, 100, 50);
    assert_eq!(s.file_range(), 100..150);
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoSectionType
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn section_type_decode_all() {
    assert_eq!(MachoSectionType::from_flags(0x0), MachoSectionType::Regular);
    assert_eq!(MachoSectionType::from_flags(0x1), MachoSectionType::ZeroFill);
    assert_eq!(MachoSectionType::from_flags(0x2), MachoSectionType::CStringLiterals);
    assert_eq!(MachoSectionType::from_flags(0xD), MachoSectionType::Interposing);
    assert_eq!(MachoSectionType::from_flags(0x42), MachoSectionType::Unknown(0x42));
    // High flag bits must be masked off.
    assert_eq!(MachoSectionType::from_flags(0x8000_0001), MachoSectionType::ZeroFill);
}

// ─────────────────────────────────────────────────────────────────────────────
// DiceKind
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dice_kind_round_trip() {
    for (raw, name) in [
        (1u16, "DICE_KIND_DATA"),
        (2, "DICE_KIND_JUMP_TABLE8"),
        (3, "DICE_KIND_JUMP_TABLE16"),
        (4, "DICE_KIND_JUMP_TABLE32"),
        (5, "DICE_KIND_ABS_JUMP_TABLE32"),
        (999, "DICE_KIND_UNKNOWN"),
    ] {
        assert_eq!(DiceKind::from_raw(raw).name(), name);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoHeaderFlags
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn header_flags_decode() {
    let f = MachoHeaderFlags::from_raw(0x0020_0000 | 0x0000_0080 | 0x0000_0004);
    assert!(f.is_pie);
    assert!(f.has_twolevel);
    assert!(f.dyld_link);
    assert!(!f.allow_stack_execution);
    assert_eq!(f.raw, 0x0020_0000 | 0x0000_0080 | 0x0000_0004);
}

#[test]
fn header_flags_all_zero() {
    let f = MachoHeaderFlags::from_raw(0);
    assert!(!f.is_pie && !f.has_twolevel && !f.dyld_link);
    assert!(!f.no_undefined_refs && !f.allow_stack_execution);
    assert!(!f.no_reexported_dylibs && !f.force_flat);
    assert!(!f.dead_strippable_dylib && !f.has_tlv_descriptors);
    assert!(!f.app_extension_safe);
    assert_eq!(f.raw, 0);
}

#[test]
fn header_flags_all_one() {
    let f = MachoHeaderFlags::from_raw(u32::MAX);
    assert!(f.is_pie && f.has_twolevel && f.dyld_link);
    assert!(f.no_undefined_refs && f.allow_stack_execution);
    assert!(f.no_reexported_dylibs && f.force_flat);
    assert!(f.dead_strippable_dylib && f.has_tlv_descriptors);
    assert!(f.app_extension_safe);
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoParser (top-level)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parser_too_small() {
    let err = MachoParser::parse(&[]).unwrap_err();
    matches!(err, rustre_core::CoreError::InvalidFormat { .. });

    let err = MachoParser::parse(&[0, 1, 2]).unwrap_err();
    matches!(err, rustre_core::CoreError::InvalidFormat { .. });
}

#[test]
fn parser_unknown_magic() {
    let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let err = MachoParser::parse(&bytes).unwrap_err();
    match err {
        rustre_core::CoreError::InvalidFormat { message } => {
            assert!(message.contains("Unknown Mach-O magic"), "got: {message}");
        }
        e => panic!("expected InvalidFormat, got {e:?}"),
    }
}

#[test]
fn parser_header_truncated() {
    // Valid 64-bit magic but only 16 bytes total — header is 32.
    let mut bytes = vec![0xCF, 0xFA, 0xED, 0xFE]; // MH_MAGIC_64
    bytes.extend_from_slice(&[0u8; 12]);
    let err = MachoParser::parse(&bytes).unwrap_err();
    match err {
        rustre_core::CoreError::InvalidFormat { message } => {
            assert!(message.contains("truncated"), "got: {message}");
        }
        e => panic!("expected InvalidFormat, got {e:?}"),
    }
}

// Build a minimal valid 64-bit Mach-O header (no load commands).
fn minimal_macho64(filetype: u32, flags: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes()); // magic
    b.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
    b.extend_from_slice(&3u32.to_le_bytes());           // cpusubtype
    b.extend_from_slice(&filetype.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());           // ncmds
    b.extend_from_slice(&0u32.to_le_bytes());           // sizeofcmds
    b.extend_from_slice(&flags.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());           // reserved
    b
}

#[test]
fn parser_minimal_64bit_executable() {
    let bytes = minimal_macho64(0x2, 0x0020_0000); // MH_EXECUTE | MH_PIE
    let info = MachoParser::parse(&bytes).expect("should parse");
    assert_eq!(info.arch, MachoArch::X86_64);
    assert_eq!(info.file_type, MachoFileType::Execute);
    assert!(info.is_pie);
    assert!(info.is_executable());
    assert!(!info.is_dylib());
    assert_eq!(info.cpu_subtype, 3);
    assert!(info.segments.is_empty());
    assert!(info.load_commands.is_empty());
}

#[test]
fn parser_minimal_64bit_dylib() {
    let bytes = minimal_macho64(0x6, 0);
    let info = MachoParser::parse(&bytes).unwrap();
    assert!(info.is_dylib());
    assert!(!info.is_executable());
    assert!(!info.is_pie);
}

// ─────────────────────────────────────────────────────────────────────────────
// Fat binary parsing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fat_detect() {
    assert!(FatBinaryParser::detect_fat(&[0xCA, 0xFE, 0xBA, 0xBE]));
    assert!(!FatBinaryParser::detect_fat(&[0xBE, 0xBA, 0xFE, 0xCA]));
    assert!(!FatBinaryParser::detect_fat(&[]));
    assert!(!FatBinaryParser::detect_fat(&[0xCA, 0xFE]));
}

#[test]
fn fat_list_arches_empty() {
    assert!(FatBinaryParser::list_arches(&[]).is_empty());
    // Not fat
    assert!(FatBinaryParser::list_arches(&[0, 0, 0, 0, 0, 0, 0, 1]).is_empty());
}

#[test]
fn fat_list_arches_truncated() {
    // Claim 5 arches but only enough bytes for 1.
    let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE];
    bytes.extend_from_slice(&5u32.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 20]); // exactly one arch
    let arches = FatBinaryParser::list_arches(&bytes);
    assert_eq!(arches.len(), 1, "must break out instead of OOB-reading");
}

#[test]
fn fat_extract_arch_oob() {
    let arch = FatArch { cputype: 7, cpusubtype: 3, offset: 1000, size: 100, align: 12 };
    assert!(FatBinaryParser::extract_arch(&[0u8; 10], &arch).is_empty());
}

#[test]
fn fat_extract_arch_normal() {
    let arch = FatArch { cputype: 7, cpusubtype: 3, offset: 4, size: 4, align: 0 };
    let data = vec![0, 0, 0, 0, 1, 2, 3, 4, 5];
    assert_eq!(FatBinaryParser::extract_arch(&data, &arch), vec![1, 2, 3, 4]);
}

#[test]
fn parser_parse_fat_too_small() {
    let err = MachoParser::parse_fat(&[0xCA, 0xFE]).unwrap_err();
    matches!(err, rustre_core::CoreError::InvalidFormat { .. });
}

#[test]
fn select_best_slice_prefers_x86_64() {
    let a = UniversalBinaryEntry { arch: MachoArch::Arm64, offset: 0, size: 0, align: 0, data: vec![] };
    let b = UniversalBinaryEntry { arch: MachoArch::X86_64, offset: 0, size: 0, align: 0, data: vec![] };
    let c = UniversalBinaryEntry { arch: MachoArch::PowerPc, offset: 0, size: 0, align: 0, data: vec![] };
    let entries = vec![a, b, c];
    let best = MachoParser::select_best_slice(&entries).unwrap();
    assert_eq!(best.arch, MachoArch::X86_64);
}

#[test]
fn select_best_slice_prefers_arm64_when_no_x86() {
    let entries = vec![
        UniversalBinaryEntry { arch: MachoArch::PowerPc, offset: 0, size: 0, align: 0, data: vec![] },
        UniversalBinaryEntry { arch: MachoArch::Arm64, offset: 0, size: 0, align: 0, data: vec![] },
    ];
    let best = MachoParser::select_best_slice(&entries).unwrap();
    assert_eq!(best.arch, MachoArch::Arm64);
}

#[test]
fn select_best_slice_empty() {
    assert!(MachoParser::select_best_slice(&[]).is_none());
}

#[test]
fn select_best_slice_falls_back_to_first() {
    let entries = vec![
        UniversalBinaryEntry { arch: MachoArch::Mips, offset: 0, size: 0, align: 0, data: vec![] },
        UniversalBinaryEntry { arch: MachoArch::Sparc, offset: 0, size: 0, align: 0, data: vec![] },
    ];
    let best = MachoParser::select_best_slice(&entries).unwrap();
    assert_eq!(best.arch, MachoArch::Mips);
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionStartsParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn function_starts_empty() {
    assert!(FunctionStartsParser::parse(&[], 0x1000).is_empty());
}

#[test]
fn function_starts_one_byte_uleb() {
    // Two deltas of 4 bytes each, then 0 terminator.
    let data = [0x04, 0x04, 0x00];
    let v = FunctionStartsParser::parse(&data, 0x1000);
    assert_eq!(v, vec![0x1004, 0x1008]);
}

#[test]
fn function_starts_multi_byte_uleb() {
    // 0x82 0x01 = (0x82 & 0x7F) | (0x01 << 7) = 0x80 + 2 = 130
    let data = [0x82, 0x01, 0x00];
    let v = FunctionStartsParser::parse(&data, 0);
    assert_eq!(v, vec![130]);
}

#[test]
fn function_starts_zero_terminator_first() {
    // First byte is 0 — sequence ends immediately, no addresses.
    let data = [0x00, 0x04, 0x04];
    let v = FunctionStartsParser::parse(&data, 0x1000);
    assert!(v.is_empty());
}

#[test]
fn function_starts_no_terminator() {
    // Runs to end without a zero — still terminates safely.
    let data = [0x04, 0x04];
    let v = FunctionStartsParser::parse(&data, 0x1000);
    assert_eq!(v, vec![0x1004, 0x1008]);
}

#[test]
fn function_starts_overflow_safe() {
    // Many continuation bytes — shift would overflow at 64.
    let data = vec![0xFF; 20];
    let _ = FunctionStartsParser::parse(&data, 0); // must not panic
}

// ─────────────────────────────────────────────────────────────────────────────
// DyldInfoParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn export_trie_empty() {
    assert!(DyldInfoParser::parse_exports(&[]).is_empty());
}

#[test]
fn export_trie_single_terminal() {
    // Single root terminal: terminal_size=2, flags=0, offset=0x42, child_count=0
    // ULEB encodings: 2 -> [0x02]; 0 -> [0x00]; 0x42 -> [0x42]
    // terminal block = flags(1) + offset(1) = 2 bytes
    let data = [
        0x02, // terminal_size = 2
        0x00, // flags
        0x42, // offset
        0x00, // child_count = 0
    ];
    let v = DyldInfoParser::parse_exports(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "");
    assert_eq!(v[0].offset, 0x42);
    assert_eq!(v[0].flags, 0);
}

#[test]
fn export_trie_oob_safe() {
    // Truncated input mid-node — must not panic.
    let _ = DyldInfoParser::parse_exports(&[0x80]); // bad ULEB
    let _ = DyldInfoParser::parse_exports(&[0x02, 0x00]); // claims 2-byte terminal w/o data
    let _ = DyldInfoParser::parse_exports(&[0xFF; 200]);
}

#[test]
fn bind_empty() {
    assert!(DyldInfoParser::parse_bind(&[]).is_empty());
}

#[test]
fn bind_done_first() {
    assert!(DyldInfoParser::parse_bind(&[0x00]).is_empty());
}

#[test]
fn bind_simple_sequence() {
    // SET_DYLIB_ORDINAL_IMM(imm=1) ; SET_SYMBOL_TRAILING_FLAGS_IMM(imm=0) "foo\0" ;
    // SET_SEGMENT_AND_OFFSET_ULEB(imm=0, offset=0x10) ; DO_BIND ; DONE
    let mut data = vec![0x10 | 1]; // SET_DYLIB_ORDINAL_IMM, imm=1
    data.push(0x40); // SET_SYMBOL_TRAILING_FLAGS_IMM
    data.extend_from_slice(b"foo\0");
    data.push(0x70); // SET_SEGMENT_AND_OFFSET_ULEB, seg index = 0
    data.push(0x10); // offset 0x10
    data.push(0x90); // DO_BIND
    data.push(0x00); // DONE
    let v = DyldInfoParser::parse_bind(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].library_ordinal, 1);
    assert_eq!(v[0].symbol_name, "foo");
    assert_eq!(v[0].address, 0x10);
}

#[test]
fn bind_special_imm_zero() {
    // SET_DYLIB_SPECIAL_IMM imm=0 should leave ordinal as 0 (per source).
    let data = [0x30, 0x40, 0x00, 0x70, 0, 0x90, 0x00];
    let v = DyldInfoParser::parse_bind(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].library_ordinal, 0);
}

#[test]
fn bind_special_imm_negative() {
    // SET_DYLIB_SPECIAL_IMM imm=1 should encode 0xF0 | 1 = 0xF1.
    let data = [0x30 | 1, 0x40, 0x00, 0x70, 0, 0x90, 0x00];
    let v = DyldInfoParser::parse_bind(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].library_ordinal, 0xF1);
}

#[test]
fn bind_uleb_times_skipping() {
    // count=3 skip=8, DO_BIND_ULEB_TIMES_SKIPPING_ULEB → 3 entries.
    let mut data = vec![0x10 | 1, 0x40];
    data.extend_from_slice(b"x\0");
    data.push(0x70); data.push(0);  // SET_SEG_OFF, offset 0
    data.push(0xC0); data.push(3); data.push(8); // 3 times skip=8
    let v = DyldInfoParser::parse_bind(&data);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].address, 0);
    // After each bind, advance by (skip + 8) = 16.
    assert_eq!(v[1].address, 16);
    assert_eq!(v[2].address, 32);
}

// ─────────────────────────────────────────────────────────────────────────────
// DataInCodeParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dice_empty() {
    assert!(DataInCodeParser::parse(&[]).is_empty());
    assert_eq!(DataInCodeParser::total_data_bytes(&[]), 0);
}

#[test]
fn dice_partial_entry_ignored() {
    // 7 bytes is < 8 → no entries.
    assert!(DataInCodeParser::parse(&[0u8; 7]).is_empty());
}

#[test]
fn dice_parse_one() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x1234u32.to_le_bytes()); // offset
    data.extend_from_slice(&0x10u16.to_le_bytes());   // length
    data.extend_from_slice(&1u16.to_le_bytes());      // DICE_KIND_DATA
    let v = DataInCodeParser::parse(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].offset, 0x1234);
    assert_eq!(v[0].length, 0x10);
    assert_eq!(v[0].kind, DiceKind::Data);
}

#[test]
fn dice_total_bytes() {
    let entries = vec![
        DataInCodeEntry { offset: 0, length: 10, kind: DiceKind::Data },
        DataInCodeEntry { offset: 0, length: 20, kind: DiceKind::JumpTable8 },
        DataInCodeEntry { offset: 0, length: u16::MAX, kind: DiceKind::Data },
    ];
    assert_eq!(DataInCodeParser::total_data_bytes(&entries), 10 + 20 + u64::from(u16::MAX));
}

// ─────────────────────────────────────────────────────────────────────────────
// RebaseParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rebase_empty() {
    assert!(RebaseParser::parse(&[]).is_empty());
}

#[test]
fn rebase_imm_times() {
    // SET_TYPE_IMM=1, SET_SEG_AND_OFFSET_ULEB imm=0 offset=0, DO_REBASE_IMM_TIMES count=3
    let data = [
        0x10 | 1, // SET_TYPE_IMM, pointer
        0x20, 0x00, // SET_SEGMENT_AND_OFFSET_ULEB
        0x50 | 3, // DO_REBASE_IMM_TIMES, 3
        0x00, // DONE
    ];
    let v = RebaseParser::parse(&data);
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].segment_offset, 0);
    assert_eq!(v[1].segment_offset, 8);
    assert_eq!(v[2].segment_offset, 16);
    assert_eq!(v[0].rebase_type, 1);
}

#[test]
fn rebase_uleb_times_skipping() {
    let data = [
        0x10 | 1, // SET_TYPE_IMM
        0x20, 0x00, // SET_SEG_AND_OFFSET
        0x80, 0x02, 0x04, // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB count=2 skip=4
        0x00,
    ];
    let v = RebaseParser::parse(&data);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].segment_offset, 0);
    // After first entry: += skip(4) + 8 = 12
    assert_eq!(v[1].segment_offset, 12);
}

#[test]
fn rebase_add_addr_imm_scaled() {
    let data = [
        0x10 | 1,        // SET_TYPE_IMM
        0x20, 0x00,  // SET_SEG_AND_OFFSET 0
        0x40 | 3,        // ADD_ADDR_IMM_SCALED, 3*8 = 24
        0x50 | 1,        // DO_REBASE_IMM_TIMES 1
        0x00,
    ];
    let v = RebaseParser::parse(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].segment_offset, 24);
}

// ─────────────────────────────────────────────────────────────────────────────
// ChainedFixupsParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn chained_fixups_too_small() {
    assert!(ChainedFixupsParser::parse_imports(&[]).is_empty());
    assert!(ChainedFixupsParser::parse_imports(&[0u8; 27]).is_empty());
    assert!(ChainedFixupsParser::parse_segment_starts(&[0u8; 10]).is_empty());
}

#[test]
fn chained_fixups_parse_one_import_format1() {
    // 28-byte header + 4-byte import + symbol pool
    let mut data = Vec::new();
    // header
    data.extend_from_slice(&0u32.to_le_bytes()); // fixups_version
    data.extend_from_slice(&0u32.to_le_bytes()); // starts_offset
    data.extend_from_slice(&28u32.to_le_bytes()); // imports_offset = right after header
    data.extend_from_slice(&32u32.to_le_bytes()); // symbols_offset
    data.extend_from_slice(&1u32.to_le_bytes()); // imports_count
    data.extend_from_slice(&1u32.to_le_bytes()); // imports_format = DYLD_CHAINED_IMPORT
    data.extend_from_slice(&0u32.to_le_bytes()); // symbols_format
    // import entry (4 bytes): lib_ordinal=2, weak=1, name_offset=0
    let raw: u32 = 0x02 | (1 << 8);
    data.extend_from_slice(&raw.to_le_bytes());
    // symbols
    data.extend_from_slice(b"hello\0");

    let v = ChainedFixupsParser::parse_imports(&data);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].lib_ordinal, 2);
    assert!(v[0].weak_import);
    assert_eq!(v[0].name, "hello");
    assert_eq!(v[0].addend, 0);
}

#[test]
fn chained_ptr_format_round_trip() {
    for raw in 1u32..=12 {
        let f = ChainedPtrFormat::from_raw(raw);
        assert!(!f.name().is_empty());
        assert_ne!(f, ChainedPtrFormat::Unknown(raw));
    }
    assert_eq!(ChainedPtrFormat::from_raw(0xFEED), ChainedPtrFormat::Unknown(0xFEED));
    assert_eq!(ChainedPtrFormat::Unknown(99).name(), "DYLD_CHAINED_PTR_UNKNOWN");
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeSignatureParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn code_sig_too_small() {
    let err = CodeSignatureParser::parse(&[0u8; 11]).unwrap_err();
    matches!(err, rustre_core::CoreError::InvalidFormat { .. });
}

#[test]
fn code_sig_wrong_magic() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // bad magic
    data.extend_from_slice(&[0u8; 8]);
    let err = CodeSignatureParser::parse(&data).unwrap_err();
    match err {
        rustre_core::CoreError::InvalidFormat { message } => {
            assert!(message.contains("SuperBlob"), "got: {message}");
        }
        e => panic!("expected InvalidFormat, got {e:?}"),
    }
}

#[test]
fn code_sig_empty_superblob() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xFADE_0CC0u32.to_be_bytes()); // CSMAGIC_EMBEDDED_SIGNATURE
    data.extend_from_slice(&12u32.to_be_bytes());          // length
    data.extend_from_slice(&0u32.to_be_bytes());           // count = 0
    let info = CodeSignatureParser::parse(&data).unwrap();
    assert!(info.slots.is_empty());
    assert!(info.code_directory.is_none());
    assert!(!info.has_cms);
    assert!(!info.has_requirements);
}

#[test]
fn code_sig_blobwrapper_slot() {
    // SuperBlob with 1 entry pointing to a BlobWrapper blob (CMS marker).
    let mut data = Vec::new();
    data.extend_from_slice(&0xFADE_0CC0u32.to_be_bytes()); // magic
    data.extend_from_slice(&0u32.to_be_bytes());           // length
    data.extend_from_slice(&1u32.to_be_bytes());           // count = 1
    // BlobIndex: slot_type, offset = 20
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&20u32.to_be_bytes());
    // Blob @20: magic=BLOBWRAPPER, size=8
    data.extend_from_slice(&0xFADE_0B01u32.to_be_bytes());
    data.extend_from_slice(&8u32.to_be_bytes());
    let info = CodeSignatureParser::parse(&data).unwrap();
    assert_eq!(info.slots.len(), 1);
    assert!(info.has_cms);
    assert!(!info.has_requirements);
}

#[test]
fn code_sig_entitlements_blob() {
    // SuperBlob with 1 entitlements blob containing XML
    let xml = b"<plist>x</plist>";
    let blob_size = 8 + xml.len() as u32;
    let mut data = Vec::new();
    data.extend_from_slice(&0xFADE_0CC0u32.to_be_bytes()); // magic
    data.extend_from_slice(&0u32.to_be_bytes());           // length
    data.extend_from_slice(&1u32.to_be_bytes());           // count = 1
    data.extend_from_slice(&5u32.to_be_bytes());           // slot type = CS_SLOTTYPE_ENTITLEMENTS
    data.extend_from_slice(&20u32.to_be_bytes());          // offset
    // blob @20
    data.extend_from_slice(&0xFADE_7171u32.to_be_bytes()); // CSMAGIC_ENTITLEMENTS
    data.extend_from_slice(&blob_size.to_be_bytes());
    data.extend_from_slice(xml);
    let info = CodeSignatureParser::parse(&data).unwrap();
    assert_eq!(info.entitlements_xml.as_deref(), Some("<plist>x</plist>"));
}

// ─────────────────────────────────────────────────────────────────────────────
// SwiftMetadataParser
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn swift_resolve_relative_ptr_positive() {
    assert_eq!(SwiftMetadataParser::resolve_relative_ptr(0x1000, 0x10), 0x1010);
}

#[test]
fn swift_resolve_relative_ptr_negative() {
    assert_eq!(SwiftMetadataParser::resolve_relative_ptr(0x1000, -0x10), 0x0FF0);
}

#[test]
fn swift_resolve_relative_ptr_zero() {
    assert_eq!(SwiftMetadataParser::resolve_relative_ptr(0xABCD, 0), 0xABCD);
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalyzerSymbol
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn analyzer_symbol_zero_syms() {
    assert!(AnalyzerSymbol::parse_symtab(&[], 0, 0, 0).is_empty());
}

#[test]
fn analyzer_symbol_oob_safe() {
    // Claim many symbols but provide too few bytes — must not panic.
    let data = [0u8; 32]; // room for 2 entries at most
    let v = AnalyzerSymbol::parse_symtab(&data, 0, 1000, 0);
    assert!(v.len() <= 2);
}

#[test]
fn analyzer_symbol_undefined() {
    // One nlist_64: strx=1, n_type=N_UNDF (0)|N_EXT(1)=1, n_sect=0, value=0
    let mut data = Vec::new();
    // symbol entry at offset 0
    data.extend_from_slice(&1u32.to_le_bytes()); // strx = 1
    data.push(0x01); // n_type: N_EXT only
    data.push(0);    // n_sect
    data.extend_from_slice(&0u16.to_le_bytes()); // n_desc
    data.extend_from_slice(&0u64.to_le_bytes()); // value
    // string table starts at offset 16: 0,_main,0
    data.push(0);
    data.extend_from_slice(b"main\0");
    let v = AnalyzerSymbol::parse_symtab(&data, 0, 1, 16);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "main");
    assert_eq!(v[0].kind, SymbolKind::Undefined);
    assert!(v[0].external);
    assert!(v[0].section.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoAnalyzer / MachoReport
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn analyzer_invalid_bytes_returns_partial_report() {
    let report = MachoAnalyzer::analyze(&[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(report.arch, "unknown");
    assert_eq!(report.file_type, "MH_UNKNOWN");
    assert!(report.segments.is_empty());
    assert!(report.imported_libs.is_empty());
    assert!(!report.is_pie);
    assert!(report.encryption.is_none());
}

#[test]
fn analyzer_minimal_macho() {
    let bytes = minimal_macho64(0x2, 0x0020_0000);
    let report = MachoAnalyzer::analyze(&bytes);
    assert_eq!(report.arch, "x86_64");
    assert_eq!(report.file_type, "MH_EXECUTE");
    assert!(report.is_pie);
}

#[test]
fn analyzer_is_pie_via_flag() {
    assert!(MachoAnalyzer::is_pie(&[], 0x0020_0000));
    assert!(!MachoAnalyzer::is_pie(&[], 0));
}

#[test]
fn analyzer_detect_swift_via_segment_name() {
    let segs = vec![seg(0, 0, 0, 0, 0)]; // empty
    assert!(!MachoAnalyzer::detect_swift(&segs));

    let mut s = seg(0, 0, 0, 0, 0);
    s.name = "__swift5_types".into();
    assert!(MachoAnalyzer::detect_swift(&[s]));
}

#[test]
fn analyzer_detect_swift_via_section_name() {
    let mut s = seg(0, 0, 0, 0, 0);
    s.name = "__TEXT".into();
    s.sections.push(MachoSection {
        name: "__swift5_proto".into(),
        segment: "__TEXT".into(),
        addr: 0, size: 0, offset: 0, align: 0, flags: 0,
        section_type: MachoSectionType::Regular,
    });
    assert!(MachoAnalyzer::detect_swift(&[s]));
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoInfo helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn empty_info() -> MachoInfo {
    MachoInfo {
        arch: MachoArch::X86_64,
        cpu_subtype: 3,
        file_type: MachoFileType::Execute,
        flags: 0,
        entry_points: vec![],
        segments: vec![],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        dylibs: vec![],
        rpaths: vec![],
        uuid: None,
        source_version: None,
        load_commands: vec![],
        has_code_signature: false,
        is_pie: false,
        is_fat: false,
        fat_slices: vec![],
        min_os_version: None,
        platform: None,
        function_starts: vec![],
        data_in_code: vec![],
        bind_entries: vec![],
        export_entries: vec![],
        rebase_entries: vec![],
        objc_classes: vec![],
        objc_protocols: vec![],
        objc_categories: vec![],
        swift_types: vec![],
        swift_proto_conformances: vec![],
        code_signature: None,
        chained_fixup_imports: vec![],
    }
}

#[test]
fn info_uuid_string_format() {
    let mut info = empty_info();
    info.uuid = Some([
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55,
        0x66, 0x77,
        0x88, 0x99,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ]);
    assert_eq!(
        info.uuid_string().unwrap(),
        "00112233-4455-6677-8899-AABBCCDDEEFF"
    );
}

#[test]
fn info_uuid_string_none() {
    let info = empty_info();
    assert!(info.uuid_string().is_none());
}

#[test]
fn info_text_data_segments() {
    let mut info = empty_info();
    let mut t = seg(0, 0x1000, 0x100, 0, 0x100); t.name = "__TEXT".into();
    let mut d = seg(0, 0x2000, 0x100, 0x100, 0x100); d.name = "__DATA".into();
    info.segments = vec![t, d];
    assert_eq!(info.text_segment().map(|s| s.vm_addr), Some(0x1000));
    assert_eq!(info.data_segment().map(|s| s.vm_addr), Some(0x2000));
}

#[test]
fn info_section_named() {
    let mut info = empty_info();
    let mut t = seg(0, 0, 0, 0, 0); t.name = "__TEXT".into();
    t.sections.push(MachoSection {
        name: "__text".into(), segment: "__TEXT".into(),
        addr: 0x1000, size: 0x10, offset: 0, align: 0, flags: 0,
        section_type: MachoSectionType::Regular,
    });
    info.segments.push(t);
    assert!(info.section_named("__TEXT", "__text").is_some());
    assert!(info.section_named("__TEXT", "__nope").is_none());
    assert!(info.section_named("__NOPE", "__text").is_none());
}

#[test]
fn info_find_symbol_and_symbol_at() {
    let mut info = empty_info();
    info.symbols.push(MachoSymbol {
        name: "foo".into(), value: 0x1234,
        section_index: 1, sym_type: MachoSymbolType::Section,
        is_external: true, is_debug: false, is_undefined: false,
    });
    assert!(info.find_symbol("foo").is_some());
    assert!(info.find_symbol("bar").is_none());
    assert!(info.symbol_at(0x1234).is_some());
    assert!(info.symbol_at(0).is_none());
}

#[test]
fn info_objc_class_names_sorted() {
    let mut info = empty_info();
    info.objc_classes.push(ObjcClass {
        name: "Zebra".into(), addr: 0, instance_methods: vec![],
        class_methods: vec![], protocols: vec![], ivars: vec![],
    });
    info.objc_classes.push(ObjcClass {
        name: "Apple".into(), addr: 0, instance_methods: vec![],
        class_methods: vec![], protocols: vec![], ivars: vec![],
    });
    assert_eq!(info.objc_class_names(), vec!["Apple", "Zebra"]);
}

#[test]
fn info_has_objc_and_has_swift() {
    let mut info = empty_info();
    assert!(!info.has_objc() && !info.has_swift());
    info.objc_protocols.push("NSObject".into());
    assert!(info.has_objc());
    info.swift_types.push(SwiftTypeDescriptor { addr: 1, relative_ptr: 0 });
    assert!(info.has_swift());
}

#[test]
fn info_function_count_and_lookup() {
    let mut info = empty_info();
    assert_eq!(info.function_count(), 0);
    assert!(info.function_start_at(0).is_none());
    info.function_starts = vec![0x1000, 0x2000, 0x3000];
    assert_eq!(info.function_count(), 3);
    assert_eq!(info.function_start_at(1), Some(0x2000));
    assert!(info.function_start_at(99).is_none());
}

#[test]
fn info_cpu_subtype_name_dispatch() {
    let mut info = empty_info();
    info.arch = MachoArch::Arm64;
    info.cpu_subtype = 2; // ARM64E
    assert_eq!(info.cpu_subtype_name(), "arm64e");
}

#[test]
fn info_is_signed_with_cms_default_false() {
    let info = empty_info();
    assert!(!info.is_signed_with_cms());
    assert!(info.entitlements().is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// MachoLoadCommandEnum::parse_all — adversarial inputs
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn load_commands_parse_empty() {
    let v = MachoLoadCommandEnum::parse_all(&[], 0, 0, false);
    assert!(v.is_empty());
}

#[test]
fn load_commands_short_input_no_panic() {
    let v = MachoLoadCommandEnum::parse_all(&[0u8; 4], 0, 1, false);
    assert!(v.is_empty());
}

#[test]
fn load_commands_cmdsize_too_small_stops() {
    // cmd=0, cmdsize=4 (less than minimum 8) → must break out, not infinite-loop.
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes()); // cmd
    data.extend_from_slice(&4u32.to_le_bytes()); // cmdsize = 4 < 8
    let v = MachoLoadCommandEnum::parse_all(&data, 0, 5, false);
    assert!(v.is_empty());
}

#[test]
fn load_commands_cmdsize_overruns_bytes_stops() {
    let mut data = Vec::new();
    data.extend_from_slice(&0u32.to_le_bytes()); // cmd
    data.extend_from_slice(&1000u32.to_le_bytes()); // huge cmdsize
    let v = MachoLoadCommandEnum::parse_all(&data, 0, 1, false);
    assert!(v.is_empty());
}
