//! Adversarial hardening tests: attacker-controlled counts must not cause
//! huge allocations (alloc-DoS) and offset arithmetic must not wrap.
//!
//! Pattern mirrors rustre-symbols-pdb/dwarf/stabs and rustre-loader-pe.

use rustre_loader_macho::macho_dyld_info::decode_chained_fixups;
use rustre_loader_macho::macho_security::CodeSigning;
use rustre_loader_macho::objc_metadata::{
    parse_ivar_list, parse_method_list, parse_property_list, parse_protocol_list_names, PtrSize,
};
use rustre_loader_macho::{AnalyzerSymbol, FatBinaryParser, MachoLoadCommandEnum};

// ---------------------------------------------------------------------------
// Class: alloc-DoS via file-derived counts
// ---------------------------------------------------------------------------

#[test]
fn objc_method_list_huge_count_no_alloc_dos() {
    // method_list_t: entsize_and_flags(u32) + count(u32) = 8 bytes, count = u32::MAX
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&24u32.to_le_bytes()); // entsize
    data[4..8].copy_from_slice(&u32::MAX.to_le_bytes()); // count
    let methods = parse_method_list(&data, 0, PtrSize::P64, false).unwrap();
    assert!(methods.is_empty() || methods.len() <= 1);
}

#[test]
fn objc_ivar_list_huge_count_no_alloc_dos() {
    let mut data = vec![0u8; 16];
    data[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let ivars = parse_ivar_list(&data, 0, PtrSize::P64).unwrap();
    assert!(ivars.is_empty());
}

#[test]
fn objc_property_list_huge_count_no_alloc_dos() {
    let mut data = vec![0u8; 16];
    data[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let props = parse_property_list(&data, 0, PtrSize::P64).unwrap();
    assert!(props.is_empty());
}

#[test]
fn objc_protocol_list_huge_count_no_alloc_dos() {
    // protocol_list_t: count is pointer-sized — u64::MAX here.
    let mut data = vec![0u8; 16];
    data[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    let names = parse_protocol_list_names(&data, 0, PtrSize::P64).unwrap();
    assert!(names.is_empty());
}

#[test]
fn security_superblob_huge_count_no_alloc_dos() {
    // SuperBlob: magic(BE) + length + count = u32::MAX
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&0xFADE_0CC0u32.to_be_bytes()); // CSMAGIC_EMBEDDED_SIGNATURE
    data[4..8].copy_from_slice(&16u32.to_be_bytes());
    data[8..12].copy_from_slice(&u32::MAX.to_be_bytes()); // count
    let cs = CodeSigning::parse(&data, 0, 16);
    assert!(cs.has_signature);
}

#[test]
fn dyld_chained_fixups_huge_imports_count_no_alloc_dos() {
    // dyld_chained_fixups_header: 7 u32 fields; imports_count = u32::MAX
    let mut data = vec![0u8; 28];
    data[16..20].copy_from_slice(&u32::MAX.to_le_bytes()); // imports_count
    data[20..24].copy_from_slice(&1u32.to_le_bytes()); // format = Import32
    let fx = decode_chained_fixups(&data).unwrap();
    assert!(fx.imports.len() <= 7); // 28 / 4
}

#[test]
fn load_commands_huge_ncmds_no_alloc_dos() {
    // ncmds = u32::MAX but only 8 bytes of data — must not preallocate 4G entries.
    let bytes = vec![0u8; 8];
    let cmds = MachoLoadCommandEnum::parse_all(&bytes, 0, u32::MAX, false);
    assert!(cmds.len() <= 1);
}

#[test]
fn fat_binary_huge_nfat_no_alloc_dos() {
    // FAT_MAGIC + nfat_arch = u32::MAX, no fat_arch records.
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    data[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    let arches = FatBinaryParser::list_arches(&data);
    assert!(arches.is_empty());
}

#[test]
fn analyzer_symtab_huge_nsyms_no_alloc_dos() {
    // nsyms = u32::MAX with a tiny buffer.
    let data = vec![0u8; 32];
    let syms = AnalyzerSymbol::parse_symtab(&data, 0, u32::MAX, 0);
    assert!(syms.len() <= 2); // 32 / 16
}

// ---------------------------------------------------------------------------
// Class: cursor/offset overflow (wrapping pos + len in release)
// ---------------------------------------------------------------------------

#[test]
fn objc_method_list_vm_off_near_usize_max_no_wrap() {
    let data = vec![0u8; 64];
    // usize::MAX - 4 + 8 wraps to 3 in release without checked_add.
    assert!(parse_method_list(&data, usize::MAX - 4, PtrSize::P64, false).is_err());
    assert!(parse_ivar_list(&data, usize::MAX - 4, PtrSize::P64).is_err());
    assert!(parse_property_list(&data, usize::MAX - 4, PtrSize::P64).is_err());
    assert!(parse_protocol_list_names(&data, usize::MAX - 4, PtrSize::P64).is_err());
}

#[test]
fn objc_category_off_near_usize_max_no_wrap() {
    let data = vec![0u8; 64];
    assert!(rustre_loader_macho::objc_metadata::parse_category(
        &data,
        usize::MAX - 8,
        PtrSize::P64
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// Class: fat binary slice extraction offset+size
// ---------------------------------------------------------------------------

#[test]
fn fat_extract_arch_offset_plus_size_overflow() {
    let data = vec![0u8; 64];
    let arch = rustre_loader_macho::FatArch {
        cputype: 0x0100_0007,
        cpusubtype: 3,
        offset: u32::MAX,
        size: u32::MAX,
        align: 14,
    };
    // Must return empty, not panic / wrap.
    assert!(FatBinaryParser::extract_arch(&data, &arch).is_empty());
}

// ---------------------------------------------------------------------------
// Fuzz-ish: random blobs through the hardened entry points never panic
// ---------------------------------------------------------------------------

#[test]
fn hardened_parsers_fuzz_never_panic() {
    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..50 {
        let len = (next() % 256) as usize;
        let blob: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
        let _ = parse_method_list(&blob, 0, PtrSize::P64, false);
        let _ = parse_ivar_list(&blob, 0, PtrSize::P32);
        let _ = parse_property_list(&blob, 0, PtrSize::P64);
        let _ = parse_protocol_list_names(&blob, 0, PtrSize::P64);
        let _ = decode_chained_fixups(&blob);
        let _ = CodeSigning::parse(&blob, 0, len as u32);
        let _ = MachoLoadCommandEnum::parse_all(&blob, 0, 1000, false);
        let _ = FatBinaryParser::list_arches(&blob);
        let _ = AnalyzerSymbol::parse_symtab(&blob, 0, 1000, 0);
    }
}
