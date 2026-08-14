//! Adversarial hardening tests for `rustre-loader-elf`.
//!
//! Covers the alloc-DoS class (attacker-controlled counts driving
//! `Vec::with_capacity`), the cursor-overflow class (`pos + len` wrapping in
//! release), and malformed-table loop termination.

use rustre_loader_elf::elf_dynamic_analysis::SysvHashTable;
use rustre_loader_elf::gnu_hash::GnuHashTable;
use rustre_loader_elf::notes::{NtFile, parse_note_section};
use rustre_loader_elf::program_headers::{Phdr32, Phdr64};
use rustre_loader_elf::symbols::{Sym32, Sym64};

// ---------------------------------------------------------------------------
// Alloc-DoS: gnu_hash with absurd bloom_size / nbuckets
// ---------------------------------------------------------------------------

#[test]
fn gnu_hash_huge_bloom_size_no_oom() {
    // bloom_size = u32::MAX words (would be 32 GiB) in a 32-byte section.
    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // nbuckets
    data[4..8].copy_from_slice(&0u32.to_le_bytes()); // symoffset
    data[8..12].copy_from_slice(&u32::MAX.to_le_bytes()); // bloom_size
    data[12..16].copy_from_slice(&6u32.to_le_bytes()); // bloom_shift
    // Must error out quickly, not allocate gigabytes.
    assert!(GnuHashTable::parse64(&data, true).is_err());
}

#[test]
fn gnu_hash_huge_nbuckets_no_oom() {
    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(&u32::MAX.to_le_bytes()); // nbuckets
    data[8..12].copy_from_slice(&0u32.to_le_bytes()); // bloom_size = 0
    assert!(GnuHashTable::parse64(&data, true).is_err());
}

// ---------------------------------------------------------------------------
// Alloc-DoS: symbol table parse with attacker-controlled count
// ---------------------------------------------------------------------------

#[test]
fn sym64_parse_table_huge_count_capped() {
    let data = vec![0u8; 48]; // room for exactly 2 Sym64
    let out = Sym64::parse_table(&data, 0, usize::MAX, true);
    assert_eq!(out.len(), 2);
}

#[test]
fn sym32_parse_table_huge_count_capped() {
    let data = vec![0u8; 32]; // room for exactly 2 Sym32
    let out = Sym32::parse_table(&data, 0, 1 << 40, true);
    assert_eq!(out.len(), 2);
}

// ---------------------------------------------------------------------------
// Cursor overflow: offset near usize::MAX must error, not wrap/panic
// ---------------------------------------------------------------------------

#[test]
fn sym_parse_offset_overflow_is_err() {
    let data = vec![0u8; 64];
    assert!(Sym32::parse(&data, usize::MAX - 4, true).is_err());
    assert!(Sym64::parse(&data, usize::MAX - 4, true).is_err());
}

#[test]
fn phdr_parse_offset_overflow_is_err() {
    let data = vec![0u8; 128];
    assert!(Phdr32::parse(&data, usize::MAX - 8, true).is_err());
    assert!(Phdr64::parse(&data, usize::MAX - 8, true).is_err());
}

#[test]
fn phdr64_parse_all_huge_phoff_no_panic() {
    let data = vec![0u8; 128];
    // e_phoff = u64::MAX saturates to usize::MAX internally; must not panic.
    let phdrs = Phdr64::parse_all(&data, u64::MAX, 56, 4, true);
    assert!(phdrs.is_empty());
}

// ---------------------------------------------------------------------------
// NT_FILE: huge count must be rejected before allocation
// ---------------------------------------------------------------------------

#[test]
fn nt_file_huge_count_rejected() {
    let mut data = vec![0u8; 64];
    data[0..8].copy_from_slice(&u64::MAX.to_le_bytes()); // count
    data[8..16].copy_from_slice(&4096u64.to_le_bytes()); // page_size
    assert!(NtFile::parse64(&data).is_err());
}

#[test]
fn nt_file_count_near_overflow_rejected() {
    let mut data = vec![0u8; 64];
    // count such that 16 + count*24 would wrap usize
    let count = (usize::MAX / 24) as u64;
    data[0..8].copy_from_slice(&count.to_le_bytes());
    assert!(NtFile::parse64(&data).is_err());
}

// ---------------------------------------------------------------------------
// SYSV hash: zero buckets and cyclic chains must terminate
// ---------------------------------------------------------------------------

#[test]
fn sysv_hash_zero_nbucket_no_div_by_zero() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&0u32.to_le_bytes()); // nbucket = 0
    data[4..8].copy_from_slice(&2u32.to_le_bytes()); // nchain
    let t = SysvHashTable::new(&data, true).expect("table");
    assert_eq!(t.lookup(b"foo"), None);
}

#[test]
fn sysv_hash_cyclic_chain_terminates() {
    // nbucket=1, nchain=3; bucket[0]=1; chain[1]=2, chain[2]=1 (cycle A->B->A)
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes()); // nbucket
    data.extend_from_slice(&3u32.to_le_bytes()); // nchain
    data.extend_from_slice(&1u32.to_le_bytes()); // bucket[0]
    data.extend_from_slice(&0u32.to_le_bytes()); // chain[0]
    data.extend_from_slice(&2u32.to_le_bytes()); // chain[1]
    data.extend_from_slice(&1u32.to_le_bytes()); // chain[2] -> back to 1
    let t = SysvHashTable::new(&data, true).expect("table");
    // Must return (None) instead of spinning forever.
    assert_eq!(t.lookup(b"anything"), None);
}

// ---------------------------------------------------------------------------
// Note section: adversarial sizes must not panic
// ---------------------------------------------------------------------------

#[test]
fn note_section_huge_sizes_no_panic() {
    let mut data = Vec::new();
    data.extend_from_slice(&u32::MAX.to_le_bytes()); // namesz
    data.extend_from_slice(&u32::MAX.to_le_bytes()); // descsz
    data.extend_from_slice(&1u32.to_le_bytes()); // type
    data.extend_from_slice(b"GNU\0");
    let _ = parse_note_section(&data); // Err or Ok — just must not panic/OOM
}
