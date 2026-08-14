//! Adversarial-input hardening tests: huge counts/sizes lifted from file
//! fields must not cause giant allocations, wraps, or panics.

use rustre_loader_pe::imports::RvaSection;

fn one_section(len: u32) -> Vec<RvaSection> {
    vec![RvaSection {
        virtual_address: 0x1000,
        virtual_size: len,
        raw_size: len,
        raw_offset: 0,
    }]
}

#[test]
fn reloc_huge_block_size_no_giant_alloc() {
    // Block header claims a ~4GB block in a 16-byte buffer.
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // page RVA
    data[4..8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes()); // block_size
    let sections = one_section(16);
    let blocks =
        rustre_loader_pe::relocations::parse_relocation_directory(&data, &sections, 0x1000, 0xFFFF_FFFF);
    // Must return promptly, with only the entries the buffer actually holds.
    for b in &blocks {
        assert!(b.entries.len() <= 8);
    }
}

#[test]
fn reloc_entry_offset_wrap_no_panic() {
    // va near u32::MAX + entry offset must not overflow-panic.
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    data[4..8].copy_from_slice(&10u32.to_le_bytes()); // 1 entry
    data[8..10].copy_from_slice(&0x3FFFu16.to_le_bytes()); // type 3, offset 0xFFF
    let sections = one_section(12);
    let _ = rustre_loader_pe::relocations::parse_relocation_directory(&data, &sections, 0x1000, 12);
}

#[test]
fn cfg_table_huge_count_no_giant_alloc() {
    let data = vec![0u8; 64];
    let sections = one_section(64);
    let entries = rustre_loader_pe::load_config::parse_cfg_function_table(
        &data,
        &sections,
        0x1000,
        u64::MAX, // count straight from file
        5,
    );
    assert!(entries.len() <= 64);
}

#[test]
fn cfg_table_huge_stride_no_overflow() {
    let data = vec![0u8; 64];
    let sections = one_section(64);
    // stride u32::MAX: i * stride would wrap in release without checked math
    let entries = rustre_loader_pe::load_config::parse_cfg_function_table(
        &data,
        &sections,
        0x1000,
        1000,
        u32::MAX,
    );
    assert!(entries.len() <= 1);
}

#[test]
fn safe_seh_huge_count_no_giant_alloc() {
    let data = vec![0u8; 64];
    let sections = one_section(64);
    let handlers = rustre_loader_pe::load_config::parse_safe_seh_handlers(
        &data,
        &sections,
        0x40_1000,
        u32::MAX,
        0x40_0000,
    );
    assert!(handlers.len() <= 16);
}

#[test]
fn debug_dir_huge_size_no_giant_alloc() {
    let data = vec![0u8; 64];
    let sections = one_section(64);
    let entries =
        rustre_loader_pe::debug_dir::parse_debug_directory(&data, &sections, 0x1000, u32::MAX);
    assert!(entries.len() <= 64 / 28);
}

#[test]
fn reconstruct_ico_huge_count_errors_cleanly() {
    // GRPICONDIR claiming 0xFFFF entries in a 6-byte buffer.
    let mut group = vec![0u8; 6];
    group[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let icon_map: std::collections::HashMap<u16, Vec<u8>> = std::collections::HashMap::new();
    let res = rustre_loader_pe::resources::reconstruct_ico(&group, &icon_map);
    assert!(res.is_err());
}
