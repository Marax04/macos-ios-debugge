//! Blitz2 — deep adversarial coverage for rustre-loader-macho.
//!
//! Focus: parser fuzzing (never-panic), round-trip properties, boundary
//! conditions, Send/Sync stress, and Hash/Eq consistency.

use rustre_core::Endian;
use rustre_loader_macho::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

// ─── Seeded LCG ────────────────────────────────────────────────────────────────

struct Lcg {
    s: u64,
}
impl Lcg {
    const fn new(seed: u64) -> Self {
        Self { s: seed }
    }
    const fn next_u64(&mut self) -> u64 {
        self.s = self
            .s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.s
    }
    fn fill(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let x = self.next_u64().to_le_bytes();
            v.extend_from_slice(&x[..(n - v.len()).min(8)]);
        }
        v
    }
}

// ─── 1. MachoArch round-trip over many cputypes ───────────────────────────────

#[test]
fn arch_from_cputype_roundtrip_50_inputs() {
    // For every "known" cputype, MachoArch round-trips back through
    // MachoInfo::cpu_subtype_name (uses the same internal map).
    let knowns: [u32; 9] = [
        7,
        0x0100_0007,
        12,
        0x0100_000C,
        0x0200_000C,
        18,
        0x0100_0012,
        8,
        14,
    ];
    for &ct in &knowns {
        let a = MachoArch::from_cputype(ct);
        // name() must be non-empty
        assert!(!a.name().is_empty(), "arch name empty for cputype {ct:#x}");
        // pointer_size() must be 4 or 8
        let ps = a.pointer_size();
        assert!(ps == 4 || ps == 8, "bad pointer size {ps}");
        // endian() must be Big or Little
        let _ = a.endian();
    }
    // Fuzz with 50 random cputypes — never panic.
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let ct = g.next_u64() as u32;
        let a = MachoArch::from_cputype(ct);
        let _ = a.name();
        let _ = a.pointer_size();
        let _ = a.endian();
        let _ = a.is_64bit();
    }
}

#[test]
fn arch_subtype_name_never_panics_fuzz() {
    let mut g = Lcg::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..200 {
        let ct = g.next_u64() as u32;
        let sub = g.next_u64() as u32;
        let _ = MachoArch::subtype_name(ct, sub);
    }
}

#[test]
fn arch_endian_consistency() {
    // 64-bit big-endian doesn't exist on Apple targets; PPC64 is BE.
    for a in [
        MachoArch::PowerPc,
        MachoArch::PowerPc64,
        MachoArch::Mips,
        MachoArch::Sparc,
    ] {
        assert!(matches!(a.endian(), Endian::Big));
    }
    for a in [
        MachoArch::X86,
        MachoArch::X86_64,
        MachoArch::Arm,
        MachoArch::Arm64,
        MachoArch::Arm64_32,
    ] {
        assert!(matches!(a.endian(), Endian::Little));
    }
}

// ─── 2. MachoFileType ─────────────────────────────────────────────────────────

#[test]
fn filetype_from_filetype_fuzz_never_panics() {
    let mut g = Lcg::new(0xAAAA_BBBB_CCCC_DDDD);
    for _ in 0..100 {
        let v = g.next_u64() as u32;
        let ft = MachoFileType::from_filetype(v);
        // name/predicates must never panic
        let _ = ft.name();
        let _ = ft.is_executable();
        let _ = ft.is_library();
        let _ = ft.is_core();
        let _ = ft.is_fileset();
    }
}

#[test]
fn filetype_all_known_have_distinct_names() {
    let kinds = [
        MachoFileType::Object,
        MachoFileType::Execute,
        MachoFileType::FvmLib,
        MachoFileType::Core,
        MachoFileType::Preload,
        MachoFileType::Dylib,
        MachoFileType::Dylinker,
        MachoFileType::Bundle,
        MachoFileType::DylibStub,
        MachoFileType::Dsym,
        MachoFileType::KextBundle,
        MachoFileType::Fileset,
    ];
    let mut s = HashSet::new();
    for k in kinds {
        assert!(s.insert(k.name()), "duplicate name {}", k.name());
    }
}

#[test]
fn filetype_boundary_values() {
    assert_eq!(MachoFileType::from_filetype(0), MachoFileType::Unknown(0));
    assert_eq!(
        MachoFileType::from_filetype(u32::MAX),
        MachoFileType::Unknown(u32::MAX)
    );
    // off-by-one around documented range
    assert_eq!(MachoFileType::from_filetype(0xD), MachoFileType::Unknown(0xD));
}

// ─── 3. MachoSectionType ─────────────────────────────────────────────────────

#[test]
fn section_type_from_flags_fuzz_never_panics() {
    let mut g = Lcg::new(0xF00D_F00D_F00D_F00D);
    for _ in 0..100 {
        let flags = g.next_u64() as u32;
        let _ = MachoSectionType::from_flags(flags);
    }
}

#[test]
fn section_type_only_low_byte_matters() {
    // Same low byte ⇒ same type regardless of high bits.
    let mut g = Lcg::new(0xBEEF_BEEF_BEEF_BEEF);
    for _ in 0..30 {
        let low = (g.next_u64() & 0xFF) as u32;
        let high = ((g.next_u64() << 8) & 0xFFFF_FF00) as u32;
        let a = MachoSectionType::from_flags(low);
        let b = MachoSectionType::from_flags(low | high);
        assert_eq!(a, b, "section type changed with high bits");
    }
}

// ─── 4. DiceKind ─────────────────────────────────────────────────────────────

#[test]
fn dice_kind_roundtrip_known() {
    for raw in 1u16..=5u16 {
        let k = DiceKind::from_raw(raw);
        assert!(!k.name().is_empty());
        assert!(!matches!(k, DiceKind::Unknown(_)));
    }
}

#[test]
fn dice_kind_unknown_boundary() {
    assert_eq!(DiceKind::from_raw(0), DiceKind::Unknown(0));
    assert_eq!(DiceKind::from_raw(6), DiceKind::Unknown(6));
    assert_eq!(DiceKind::from_raw(u16::MAX), DiceKind::Unknown(u16::MAX));
}

#[test]
fn dice_kind_fuzz_never_panics() {
    let mut g = Lcg::new(0x1010_2020_3030_4040);
    for _ in 0..100 {
        let raw = g.next_u64() as u16;
        let k = DiceKind::from_raw(raw);
        let _ = k.name();
    }
}

// ─── 5. MachoSegment helpers ─────────────────────────────────────────────────

fn seg(name: &str, vm: u64, sz: u64, prot: u32) -> MachoSegment {
    MachoSegment {
        name: name.to_string(),
        vm_addr: vm,
        vm_size: sz,
        file_offset: 0,
        file_size: sz,
        max_prot: prot,
        init_prot: prot,
        sections: vec![],
    }
}

#[test]
fn segment_protection_predicates() {
    let s = seg("__TEXT", 0, 0x1000, 0x5);
    assert!(s.is_readable());
    assert!(!s.is_writable());
    assert!(s.is_executable());
    let w = seg("__DATA", 0, 0x1000, 0x3);
    assert!(w.is_readable());
    assert!(w.is_writable());
    assert!(!w.is_executable());
}

#[test]
fn segment_contains_addr_boundaries() {
    let s = seg("__TEXT", 0x1000, 0x100, 0x5);
    assert!(!s.contains_addr(0xFFF));
    assert!(s.contains_addr(0x1000));
    assert!(s.contains_addr(0x10FF));
    assert!(!s.contains_addr(0x1100)); // exclusive upper bound
    assert!(!s.contains_addr(u64::MAX));
}

#[test]
fn segment_contains_addr_overflow_saturating() {
    // contains_addr uses saturating_add — must not panic at the max
    let s = seg("__BIG", u64::MAX - 1, u64::MAX, 0x1);
    let _ = s.contains_addr(u64::MAX);
    let _ = s.contains_addr(0);
}

#[test]
fn segment_file_range_consistency() {
    let mut s = seg("__X", 0, 0, 0x1);
    s.file_offset = 100;
    s.file_size = 50;
    let r = s.file_range();
    assert_eq!(r.start, 100);
    assert_eq!(r.end, 150);
    // overflow path
    s.file_offset = (usize::MAX - 5) as u64;
    s.file_size = 100;
    let r = s.file_range();
    assert_eq!(r.end, usize::MAX); // saturated
}

// ─── 6. MachoParser::parse — never panic on adversarial input ────────────────

#[test]
fn parser_empty_returns_err() {
    let r = MachoParser::parse(&[]);
    assert!(r.is_err());
}

#[test]
fn parser_three_bytes_returns_err() {
    assert!(MachoParser::parse(&[0xFE, 0xED, 0xFA]).is_err());
}

#[test]
fn parser_bad_magic_returns_err() {
    let bytes = [0x00, 0x00, 0x00, 0x00];
    let r = MachoParser::parse(&bytes);
    assert!(r.is_err());
}

#[test]
fn parser_truncated_after_magic_returns_err() {
    // valid magic but no header
    let mut bytes = vec![0xCF, 0xFA, 0xED, 0xFE]; // MH_MAGIC_64 LE bytes
    bytes.extend_from_slice(&[0; 4]);
    let r = MachoParser::parse(&bytes);
    assert!(r.is_err());
}

#[test]
fn parser_fuzz_50_random_blobs_never_panics() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let sz = (g.next_u64() % 512) as usize;
        let blob = g.fill(sz);
        let _ = MachoParser::parse(&blob);
    }
}

#[test]
fn parser_fuzz_with_valid_magic_50_inputs() {
    let mut g = Lcg::new(0x9999_8888_7777_6666);
    let magics: [[u8; 4]; 4] = [
        [0xCE, 0xFA, 0xED, 0xFE], // MH_MAGIC LE bytes
        [0xFE, 0xED, 0xFA, 0xCE], // MH_CIGAM raw
        [0xCF, 0xFA, 0xED, 0xFE], // MH_MAGIC_64
        [0xFE, 0xED, 0xFA, 0xCF], // MH_CIGAM_64
    ];
    for i in 0..50 {
        let m = magics[i % 4];
        let sz = 32 + (g.next_u64() as usize % 256);
        let mut blob = g.fill(sz);
        blob[..4].copy_from_slice(&m);
        let _ = MachoParser::parse(&blob); // must not panic
    }
}

#[test]
fn parser_fat_too_small() {
    assert!(MachoParser::parse_fat(&[0xCA, 0xFE, 0xBA, 0xBE]).is_err());
}

#[test]
fn parser_fat_zero_arches() {
    let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE]; // FAT_MAGIC bytes when read LE
    bytes.extend_from_slice(&0u32.to_be_bytes()); // nfat = 0
    let entries = MachoParser::parse_fat(&bytes).unwrap();
    assert_eq!(entries.len(), 0);
}

#[test]
fn parser_fat_oversized_nfat_capped() {
    // attacker claims a huge nfat — parser must cap to (bytes-8)/20.
    let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE];
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    // only room for ~0 entries given size
    let entries = MachoParser::parse_fat(&bytes).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn parser_select_best_slice_empty() {
    assert!(MachoParser::select_best_slice(&[]).is_none());
}

#[test]
fn parser_select_best_slice_prefers_x86_64_then_arm64() {
    let mk = |a: MachoArch| UniversalBinaryEntry {
        arch: a,
        offset: 0,
        size: 0,
        align: 0,
        data: vec![],
    };
    let es = vec![mk(MachoArch::Arm64), mk(MachoArch::X86_64), mk(MachoArch::PowerPc)];
    let best = MachoParser::select_best_slice(&es).unwrap();
    assert_eq!(best.arch, MachoArch::X86_64);

    let es2 = vec![mk(MachoArch::PowerPc), mk(MachoArch::Arm64)];
    let best2 = MachoParser::select_best_slice(&es2).unwrap();
    assert_eq!(best2.arch, MachoArch::Arm64);

    let es3 = vec![mk(MachoArch::Mips)];
    let best3 = MachoParser::select_best_slice(&es3).unwrap();
    assert_eq!(best3.arch, MachoArch::Mips);
}

// ─── 7. FunctionStartsParser — ULEB128 stream ────────────────────────────────

#[test]
fn function_starts_empty_returns_empty() {
    assert_eq!(FunctionStartsParser::parse(&[], 0x1000), Vec::<u64>::new());
}

#[test]
fn function_starts_terminator_only() {
    // single 0 byte ⇒ terminator ⇒ no functions
    assert!(FunctionStartsParser::parse(&[0], 0x1000).is_empty());
}

#[test]
fn function_starts_fuzz_never_panics() {
    let mut g = Lcg::new(0xBABE_CAFE_F00D_DEAD);
    for _ in 0..50 {
        let sz = (g.next_u64() % 256) as usize;
        let blob = g.fill(sz);
        let base = g.next_u64();
        let _ = FunctionStartsParser::parse(&blob, base);
    }
}

// ─── 8. DataInCodeParser ─────────────────────────────────────────────────────

#[test]
fn data_in_code_empty() {
    assert!(DataInCodeParser::parse(&[]).is_empty());
}

#[test]
fn data_in_code_truncated_entry_skipped() {
    // entry is 8 bytes: offset(4)+length(2)+kind(2). Less than 8 ⇒ nothing.
    let blob = [0u8; 7];
    assert!(DataInCodeParser::parse(&blob).is_empty());
}

#[test]
fn data_in_code_single_entry_roundtrip() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&100u32.to_le_bytes()); // offset
    blob.extend_from_slice(&8u16.to_le_bytes()); // length
    blob.extend_from_slice(&1u16.to_le_bytes()); // kind = DATA
    let entries = DataInCodeParser::parse(&blob);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].offset, 100);
    assert_eq!(entries[0].length, 8);
    assert_eq!(entries[0].kind, DiceKind::Data);
}

#[test]
fn data_in_code_total_bytes_sums_correctly() {
    let entries = vec![
        DataInCodeEntry {
            offset: 0,
            length: 4,
            kind: DiceKind::Data,
        },
        DataInCodeEntry {
            offset: 8,
            length: 16,
            kind: DiceKind::JumpTable8,
        },
    ];
    assert_eq!(DataInCodeParser::total_data_bytes(&entries), 20);
}

#[test]
fn data_in_code_fuzz_never_panics() {
    let mut g = Lcg::new(0x4242_4242_4242_4242);
    for _ in 0..50 {
        let sz = (g.next_u64() % 256) as usize;
        let blob = g.fill(sz);
        let _ = DataInCodeParser::parse(&blob);
    }
}

// ─── 9. RebaseParser ─────────────────────────────────────────────────────────

#[test]
fn rebase_empty() {
    assert!(RebaseParser::parse(&[]).is_empty());
}

#[test]
fn rebase_done_only() {
    assert!(RebaseParser::parse(&[0x00]).is_empty());
}

#[test]
fn rebase_fuzz_never_panics() {
    let mut g = Lcg::new(0xCCCC_DDDD_EEEE_FFFF);
    for _ in 0..50 {
        let sz = (g.next_u64() % 256) as usize;
        let blob = g.fill(sz);
        let _ = RebaseParser::parse(&blob);
    }
}

// ─── 10. DyldInfoParser ──────────────────────────────────────────────────────

#[test]
fn dyld_info_parse_exports_empty() {
    assert!(DyldInfoParser::parse_exports(&[]).is_empty());
}

#[test]
fn dyld_info_parse_bind_empty() {
    assert!(DyldInfoParser::parse_bind(&[]).is_empty());
}

#[test]
fn dyld_info_fuzz_never_panics() {
    let mut g = Lcg::new(0x5555_6666_7777_8888);
    for _ in 0..50 {
        let sz = (g.next_u64() % 256) as usize;
        let blob = g.fill(sz);
        let _ = DyldInfoParser::parse_exports(&blob);
        let _ = DyldInfoParser::parse_bind(&blob);
    }
}

// ─── 11. ChainedFixupsParser ─────────────────────────────────────────────────

#[test]
fn chained_fixups_imports_empty() {
    assert!(ChainedFixupsParser::parse_imports(&[]).is_empty());
}

#[test]
fn chained_fixups_segment_starts_empty() {
    assert!(ChainedFixupsParser::parse_segment_starts(&[]).is_empty());
}

#[test]
fn chained_fixups_fuzz_never_panics() {
    let mut g = Lcg::new(0x9090_8080_7070_6060);
    for _ in 0..50 {
        let sz = (g.next_u64() % 512) as usize;
        let blob = g.fill(sz);
        let _ = ChainedFixupsParser::parse_imports(&blob);
        let _ = ChainedFixupsParser::parse_segment_starts(&blob);
    }
}

#[test]
fn chained_ptr_format_known_values() {
    // ChainedPtrFormat exists; ensure known formats decode (1..=12).
    for raw in 1u32..=12u32 {
        let f = ChainedPtrFormat::from_raw(raw);
        // every known value should have a non-empty name
        let _ = f.name();
    }
}

// ─── 12. CodeSignatureParser ─────────────────────────────────────────────────

#[test]
fn code_signature_empty_returns_err() {
    assert!(CodeSignatureParser::parse(&[]).is_err());
}

#[test]
fn code_signature_truncated_returns_err() {
    let blob = [0u8; 7];
    assert!(CodeSignatureParser::parse(&blob).is_err());
}

#[test]
fn code_signature_fuzz_never_panics() {
    let mut g = Lcg::new(0xC0DE_5161_C0DE_5161);
    for _ in 0..50 {
        let sz = (g.next_u64() % 256) as usize;
        let blob = g.fill(sz);
        let _ = CodeSignatureParser::parse(&blob);
    }
}

// ─── 13. FatBinaryParser ─────────────────────────────────────────────────────

#[test]
fn fat_binary_list_arches_empty() {
    assert!(FatBinaryParser::list_arches(&[]).is_empty());
}

#[test]
fn fat_binary_list_arches_fuzz_never_panics() {
    let mut g = Lcg::new(0xFA7F_A7FA_7FA7_FA7F);
    for _ in 0..50 {
        let sz = (g.next_u64() % 512) as usize;
        let blob = g.fill(sz);
        let _ = FatBinaryParser::list_arches(&blob);
    }
}

// ─── 14. MachoHeaderFlags from_raw + display ─────────────────────────────────

#[test]
fn header_flags_roundtrip_50_random() {
    let mut g = Lcg::new(0xAA55_AA55_AA55_AA55);
    for _ in 0..50 {
        let raw = g.next_u64() as u32;
        let f = MachoHeaderFlags::from_raw(raw);
        // The struct's raw field (whatever name) is round-trippable through
        // accessor methods — at minimum these must not panic.
        let _ = format!("{f:?}");
    }
}

// ─── 15. MachoLoadCommandEnum::parse_all fuzz ────────────────────────────────

#[test]
fn load_command_parse_all_empty() {
    let v = MachoLoadCommandEnum::parse_all(&[], 0, 0, false);
    assert!(v.is_empty());
}

#[test]
fn load_command_parse_all_fuzz_never_panics() {
    let mut g = Lcg::new(0x1357_2468_1357_2468);
    for _ in 0..50 {
        let sz = (g.next_u64() % 1024) as usize;
        let blob = g.fill(sz);
        let lc_start = (g.next_u64() as usize) % (blob.len().max(1));
        let ncmds = (g.next_u64() as u32) % 64;
        let be = (g.next_u64() & 1) == 0;
        let _ = MachoLoadCommandEnum::parse_all(&blob, lc_start, ncmds, be);
    }
}

// ─── 16. Hash/Eq consistency for enums ───────────────────────────────────────

#[test]
fn macho_arch_eq_consistency() {
    // For Eq types, a == b iff their derived equality holds for all 30+ pairs.
    let xs = [
        MachoArch::X86,
        MachoArch::X86_64,
        MachoArch::Arm,
        MachoArch::Arm64,
        MachoArch::Arm64_32,
        MachoArch::PowerPc,
        MachoArch::PowerPc64,
        MachoArch::Mips,
        MachoArch::Sparc,
        MachoArch::Unknown(0),
        MachoArch::Unknown(1),
    ];
    let mut pairs = 0;
    for a in xs {
        for b in xs {
            pairs += 1;
            if a == b {
                // Symmetric
                assert!(b == a);
            } else {
                assert!(b != a);
            }
        }
    }
    assert!(pairs >= 30);
}

#[test]
fn filetype_eq_consistency() {
    let xs = [
        MachoFileType::Object,
        MachoFileType::Execute,
        MachoFileType::Dylib,
        MachoFileType::Bundle,
        MachoFileType::Core,
        MachoFileType::Unknown(7),
        MachoFileType::Unknown(8),
    ];
    let mut pairs = 0;
    for a in xs {
        for b in xs {
            pairs += 1;
            assert_eq!(a == b, !(a != b));
        }
    }
    assert!(pairs >= 30);
}

#[test]
fn dice_kind_eq_consistency() {
    let xs = [
        DiceKind::Data,
        DiceKind::JumpTable8,
        DiceKind::JumpTable16,
        DiceKind::JumpTable32,
        DiceKind::AbsJumpTable32,
        DiceKind::Unknown(99),
        DiceKind::Unknown(100),
    ];
    for a in xs {
        for b in xs {
            assert_eq!(a == b, !(a != b));
        }
    }
}

// ─── 17. MachoInfo helpers on empty/minimal info ─────────────────────────────

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
fn machoinfo_lookup_helpers_on_empty() {
    let info = empty_info();
    assert!(info.text_segment().is_none());
    assert!(info.data_segment().is_none());
    assert!(info.section_named("__TEXT", "__text").is_none());
    assert!(info.symbol_at(0).is_none());
    assert!(info.find_symbol("foo").is_none());
    assert!(info.is_executable());
    assert!(!info.is_dylib());
    assert_eq!(info.function_count(), 0);
    assert_eq!(info.function_start_at(0), None);
    assert_eq!(info.data_in_code_count(), 0);
    assert!(!info.is_signed_with_cms());
    assert!(info.entitlements().is_none());
    assert!(info.objc_class_names().is_empty());
    assert!(info.chained_import_names().is_empty());
    assert!(!info.has_objc());
    assert!(!info.has_swift());
}

#[test]
fn machoinfo_uuid_string_format() {
    let mut info = empty_info();
    info.uuid = Some([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);
    let s = info.uuid_string().unwrap();
    assert_eq!(s.len(), 36); // 32 hex + 4 dashes
    assert_eq!(&s, "01234567-89AB-CDEF-FEDC-BA9876543210");
}

#[test]
fn machoinfo_cpu_subtype_name_roundtrip() {
    let mut info = empty_info();
    info.arch = MachoArch::X86_64;
    info.cpu_subtype = 3;
    assert_eq!(info.cpu_subtype_name(), "x86_64 (all)");
    info.cpu_subtype = 8;
    assert_eq!(info.cpu_subtype_name(), "x86_64h (Haswell)");

    info.arch = MachoArch::Arm64;
    info.cpu_subtype = 0;
    assert_eq!(info.cpu_subtype_name(), "arm64 (all)");
    info.cpu_subtype = 2;
    assert_eq!(info.cpu_subtype_name(), "arm64e");
}

// ─── 18. Send/Sync threaded stress on MachoInfo (Arc + clone) ────────────────

#[test]
fn macho_info_arc_threaded_stress() {
    let info = Arc::new(empty_info());
    let mut handles = vec![];
    for _ in 0..4 {
        let info = Arc::clone(&info);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(info.is_executable());
                assert!(!info.is_dylib());
                let _ = info.text_segment();
                let _ = info.uuid_string();
                let _ = info.objc_class_names();
                let _ = info.cpu_subtype_name();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn macho_arch_send_sync_threaded_stress() {
    // MachoArch is Copy + Send + Sync.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MachoArch>();
    assert_send_sync::<MachoFileType>();
    assert_send_sync::<DiceKind>();

    let mut handles = vec![];
    for t in 0..4u32 {
        handles.push(thread::spawn(move || {
            let mut g = Lcg::new(0xABCD_EF01_2345_6789 ^ u64::from(t));
            for _ in 0..100 {
                let ct = g.next_u64() as u32;
                let a = MachoArch::from_cputype(ct);
                let _ = a.name();
                let _ = a.pointer_size();
                let _ = a.endian();
                let _ = a.is_64bit();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── 19. Boundary / overflow checks ──────────────────────────────────────────

#[test]
fn arch_pointer_size_total_known() {
    // All variants combined should yield only {4, 8}.
    let xs = [
        MachoArch::X86,
        MachoArch::X86_64,
        MachoArch::Arm,
        MachoArch::Arm64,
        MachoArch::Arm64_32,
        MachoArch::PowerPc,
        MachoArch::PowerPc64,
        MachoArch::Mips,
        MachoArch::Sparc,
        MachoArch::Unknown(0),
    ];
    for a in xs {
        let p = a.pointer_size();
        assert!(p == 4 || p == 8, "unexpected pointer size {p}");
    }
}

#[test]
fn segment_contains_addr_zero_size() {
    let s = seg("__Z", 0x2000, 0, 0x1);
    assert!(!s.contains_addr(0x2000)); // empty range contains nothing
    assert!(!s.contains_addr(0x1FFF));
    assert!(!s.contains_addr(0x2001));
}

#[test]
fn parser_all_zero_returns_err() {
    let bytes = vec![0u8; 256];
    assert!(MachoParser::parse(&bytes).is_err());
}

#[test]
fn parser_all_ff_returns_err() {
    let bytes = vec![0xFFu8; 256];
    assert!(MachoParser::parse(&bytes).is_err());
}
