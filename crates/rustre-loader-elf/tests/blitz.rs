//! Blitz test suite for `rustre-loader-elf` — exhaustive coverage of public
//! pure-function APIs, parsers, and adversarial inputs.

use rustre_loader_elf::{
    GnuBloomFilter, GnuHashTable, GnuBuildId, GnuNoteType, NoteType,
    ElfNoteSection, gnu_hash, gnu_hash_str, parse_note_section,
    parse_verdef, parse_verneed,
};

use rustre_loader_elf::arm_exidx::{
    ExidxEntry, decode_pop_regs_2, decode_unwind_byte, exidx_function_addresses,
    parse_arm_exidx, parse_arm_extab, prel31_to_addr, addr_to_prel31, UnwindOpcode,
};

use rustre_loader_elf::compression::{
    Chdr32, Chdr64, CompressedSectionHeader, compress_type_name, decompress_zlib,
};

use rustre_loader_elf::headers::{
    Ehdr32, Ehdr64, ElfHeader, elf_class_name, elf_data_name, elf_machine_name,
    elf_osabi_name, elf_type_name, arm_eabi_version,
};

// ============================================================================
// gnu_hash
// ============================================================================

#[test]
fn gnu_hash_empty_string_is_5381() {
    assert_eq!(gnu_hash(b""), 5381);
    assert_eq!(gnu_hash_str(""), 5381);
}

#[test]
fn gnu_hash_known_printf() {
    // GLIBC test vectors
    assert_eq!(gnu_hash_str("printf"), 0x156b_2bb8);
}

#[test]
fn gnu_hash_known_exit() {
    assert_eq!(gnu_hash_str("exit"), 0x7c96_7e3f);
}

#[test]
fn gnu_hash_single_byte_a() {
    // 5381*33 + 97 = 177676
    assert_eq!(gnu_hash(b"a"), 5381u32.wrapping_mul(33).wrapping_add(u32::from(b'a')));
}

#[test]
fn gnu_hash_long_string_no_panic() {
    let s = vec![b'X'; 4096];
    let _ = gnu_hash(&s);
}

#[test]
fn gnu_hash_collision_inequality() {
    assert_ne!(gnu_hash_str("foo"), gnu_hash_str("bar"));
    assert_ne!(gnu_hash_str("printf"), gnu_hash_str("scanf"));
}

#[test]
fn gnu_hash_byte_vs_str_parity() {
    assert_eq!(gnu_hash(b"hello"), gnu_hash_str("hello"));
}

#[test]
fn gnu_hash_wrapping_arithmetic() {
    // Construct input that forces wrapping
    let big = vec![0xFFu8; 100];
    let h = gnu_hash(&big);
    // Should not panic; value is deterministic
    assert_eq!(h, gnu_hash(&big));
}

// ============================================================================
// GnuBloomFilter
// ============================================================================

#[test]
fn bloom_filter_all_ones_always_true() {
    let f = GnuBloomFilter::new(vec![u64::MAX; 4], 6, 64);
    assert!(f.might_contain(0));
    assert!(f.might_contain(0xDEAD_BEEF));
    assert!(f.might_contain(u32::MAX));
}

#[test]
fn bloom_filter_all_zero_always_false() {
    let f = GnuBloomFilter::new(vec![0u64; 4], 6, 64);
    assert!(!f.might_contain(0));
    assert!(!f.might_contain(0xDEAD_BEEF));
    assert!(!f.might_contain(u32::MAX));
}

#[test]
fn bloom_filter_empty_assumed_present() {
    let f = GnuBloomFilter::new(vec![], 6, 64);
    assert!(f.might_contain(42));
}

#[test]
fn bloom_filter_word_bits_zero_assumed_present() {
    let f = GnuBloomFilter::new(vec![1u64], 6, 0);
    assert!(f.might_contain(42));
}

#[test]
fn bloom_filter_known_bit_positive() {
    let hash: u32 = 0xABCD_EF12;
    let shift2: u32 = 6;
    let word_bits: u32 = 64;
    let bit1 = hash & (word_bits - 1);
    let bit2 = (hash >> shift2) & (word_bits - 1);
    let word = (1u64 << bit1) | (1u64 << bit2);
    let f = GnuBloomFilter::new(vec![word], shift2, word_bits);
    assert!(f.might_contain(hash));
}

#[test]
fn bloom_fpr_zero_for_no_symbols() {
    let f = GnuBloomFilter::new(vec![0u64; 4], 6, 64);
    assert_eq!(f.false_positive_rate(0), 0.0);
}

#[test]
fn bloom_fpr_zero_for_empty_words() {
    let f = GnuBloomFilter::new(vec![], 6, 64);
    assert_eq!(f.false_positive_rate(100), 0.0);
}

#[test]
fn bloom_fpr_in_range() {
    let f = GnuBloomFilter::new(vec![0u64; 4], 6, 64);
    let r = f.false_positive_rate(50);
    assert!((0.0..=1.0).contains(&r));
}

// ============================================================================
// GnuHashTable
// ============================================================================

fn build_minimal_gnu_hash() -> Vec<u8> {
    let mut data = vec![0u8; 16 + 8 + 4];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // nbuckets
    data[4..8].copy_from_slice(&1u32.to_le_bytes()); // symoffset
    data[8..12].copy_from_slice(&1u32.to_le_bytes()); // bloom_size
    data[12..16].copy_from_slice(&6u32.to_le_bytes()); // shift2
    data[16..24].copy_from_slice(&0u64.to_le_bytes()); // bloom word
    data[24..28].copy_from_slice(&0u32.to_le_bytes()); // bucket
    data
}

#[test]
fn gnu_hash_table_too_short_errs() {
    assert!(GnuHashTable::parse64(&[], true).is_err());
    assert!(GnuHashTable::parse64(&[0u8; 4], true).is_err());
    assert!(GnuHashTable::parse64(&[0u8; 15], true).is_err());
}

#[test]
fn gnu_hash_table_minimal_ok() {
    let t = GnuHashTable::parse64(&build_minimal_gnu_hash(), true).unwrap();
    assert_eq!(t.nbuckets, 1);
    assert_eq!(t.symoffset, 1);
    assert_eq!(t.buckets.len(), 1);
}

#[test]
fn gnu_hash_table_lookup_empty_returns_none() {
    let t = GnuHashTable::parse64(&build_minimal_gnu_hash(), true).unwrap();
    assert!(t.lookup("anything").is_none());
}

#[test]
fn gnu_hash_table_nbuckets_zero_returns_none() {
    // Hand-craft a table where bloom passes but nbuckets=0
    let mut data = vec![0u8; 16 + 8];
    data[0..4].copy_from_slice(&0u32.to_le_bytes()); // nbuckets = 0
    data[8..12].copy_from_slice(&1u32.to_le_bytes()); // bloom_size = 1
    data[12..16].copy_from_slice(&6u32.to_le_bytes());
    data[16..24].copy_from_slice(&u64::MAX.to_le_bytes()); // bloom all-ones
    let t = GnuHashTable::parse64(&data, true).unwrap();
    assert!(t.lookup("foo").is_none());
}

#[test]
fn gnu_hash_table_bloom_rejects_lookup() {
    let t = GnuHashTable::parse64(&build_minimal_gnu_hash(), true).unwrap();
    // bloom = 0 → all lookups rejected
    assert!(t.lookup("printf").is_none());
}

#[test]
fn gnu_hash_table_symbol_count_matches_chain() {
    let mut data = vec![0u8; 16 + 8 + 4 + 12];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    data[8..12].copy_from_slice(&1u32.to_le_bytes());
    data[12..16].copy_from_slice(&6u32.to_le_bytes());
    let t = GnuHashTable::parse64(&data, true).unwrap();
    // 12 bytes of chain area → 3 entries
    assert_eq!(t.symbol_count(), 3);
}

#[test]
fn gnu_hash_table_scan_empty_buckets_returns_empty() {
    let t = GnuHashTable::parse64(&build_minimal_gnu_hash(), true).unwrap();
    assert!(t.scan_all_symbols().is_empty());
}

#[test]
fn gnu_hash_table_be_parse() {
    let mut data = vec![0u8; 16 + 8 + 4];
    data[0..4].copy_from_slice(&1u32.to_be_bytes());
    data[4..8].copy_from_slice(&1u32.to_be_bytes());
    data[8..12].copy_from_slice(&1u32.to_be_bytes());
    data[12..16].copy_from_slice(&6u32.to_be_bytes());
    let t = GnuHashTable::parse64(&data, false).unwrap();
    assert_eq!(t.nbuckets, 1);
    assert_eq!(t.symoffset, 1);
}

// ============================================================================
// ARM exidx PREL31
// ============================================================================

#[test]
fn prel31_zero_offset() {
    assert_eq!(prel31_to_addr(0x1000, 0), 0x1000);
}

#[test]
fn prel31_positive_offset() {
    assert_eq!(prel31_to_addr(0x1000, 0x100), 0x1100);
}

#[test]
fn prel31_negative_offset_sign_extends() {
    // bit 30 set → negative
    let word = 0x4000_0000u32; // bit 30 set
    let result = prel31_to_addr(0x1000, word);
    // signed: -0x40000000
    assert_eq!(result, 0x1000u32.wrapping_sub(0x4000_0000));
}

#[test]
fn prel31_encode_decode_roundtrip() {
    let entry = 0x10000u32;
    let target = 0x10100u32;
    let encoded = addr_to_prel31(entry, target);
    let decoded = prel31_to_addr(entry, encoded);
    assert_eq!(decoded, target);
}

#[test]
fn prel31_encode_decode_roundtrip_backwards() {
    let entry = 0x20000u32;
    let target = 0x10000u32; // negative diff
    let encoded = addr_to_prel31(entry, target);
    let decoded = prel31_to_addr(entry, encoded);
    assert_eq!(decoded, target);
}

#[test]
fn prel31_top_bit_ignored_on_decode() {
    // word's top bit (bit 31) must be masked
    let with_top = 0x8000_0000u32;
    assert_eq!(prel31_to_addr(0x1000, with_top), 0x1000);
}

// ============================================================================
// ARM exidx unwind opcodes
// ============================================================================

#[test]
fn unwind_byte_vsp_add() {
    matches!(decode_unwind_byte(0x10), UnwindOpcode::VspAdd(0x10));
    if let UnwindOpcode::VspAdd(v) = decode_unwind_byte(0x10) {
        assert_eq!(v, 0x10);
    } else {
        panic!("expected VspAdd");
    }
}

#[test]
fn unwind_byte_vsp_sub() {
    if let UnwindOpcode::VspSub(v) = decode_unwind_byte(0x40) {
        assert_eq!(v, 0);
    } else {
        panic!("expected VspSub");
    }
}

#[test]
fn unwind_byte_finish() {
    assert_eq!(decode_unwind_byte(0xB0), UnwindOpcode::Finish);
}

#[test]
fn unwind_byte_set_vsp_from_reg_valid() {
    if let UnwindOpcode::SetVspFromReg(r) = decode_unwind_byte(0x91) {
        assert_eq!(r, 1);
    } else {
        panic!("expected SetVspFromReg");
    }
}

#[test]
fn unwind_byte_reserved_regs_13_15() {
    assert!(matches!(decode_unwind_byte(0x9D), UnwindOpcode::Spare(_)));
    assert!(matches!(decode_unwind_byte(0x9F), UnwindOpcode::Spare(_)));
}

#[test]
fn unwind_byte_spare_b1_b2() {
    assert!(matches!(decode_unwind_byte(0xB1), UnwindOpcode::Spare(0xB1)));
    assert!(matches!(decode_unwind_byte(0xB2), UnwindOpcode::Spare(0xB2)));
}

#[test]
fn unwind_byte_a0_pop_regs() {
    // 0xA0: count=1, no r14 → mask = (1<<1)-1 << 4 = 0x10
    if let UnwindOpcode::PopRegs(m) = decode_unwind_byte(0xA0) {
        assert_eq!(m, 0x10);
    } else {
        panic!("expected PopRegs");
    }
}

#[test]
fn unwind_byte_a8_pop_with_r14() {
    // 0xA8: r14 set, count=1 → mask = 0x10 | (1<<14) = 0x4010
    if let UnwindOpcode::PopRegs(m) = decode_unwind_byte(0xA8) {
        assert_eq!(m, 0x4010);
    } else {
        panic!("expected PopRegs");
    }
}

#[test]
fn unwind_byte_0x80_range_is_spare_single() {
    // 0x80..=0x8F are handled separately (decode_pop_regs_2), single-byte = Spare
    assert!(matches!(decode_unwind_byte(0x85), UnwindOpcode::Spare(0x85)));
}

#[test]
fn decode_pop_regs_2_basic() {
    // hi=0x00, lo=0x01 → mask=0x001 → low bit r0 → regmask=1
    if let UnwindOpcode::PopRegs(m) = decode_pop_regs_2(0x00, 0x01) {
        assert_eq!(m & 1, 1);
    } else {
        panic!("expected PopRegs");
    }
}

// ============================================================================
// parse_arm_exidx / parse_arm_extab
// ============================================================================

#[test]
fn parse_exidx_empty() {
    let v = parse_arm_exidx(&[], 0, 0, 0);
    assert!(v.is_empty());
}

#[test]
fn parse_exidx_single_entry() {
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&0x100u32.to_le_bytes()); // word0
    data[4..8].copy_from_slice(&0x1u32.to_le_bytes()); // word1: EXIDX_CANTUNWIND? no, 1
    let v = parse_arm_exidx(&data, 0, 8, 0x10000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].entry_vaddr, 0x10000);
    assert_eq!(v[0].word0, 0x100);
}

#[test]
fn parse_exidx_oversize_clamps_to_data_len() {
    let data = vec![0u8; 8];
    let v = parse_arm_exidx(&data, 0, 1000, 0);
    assert_eq!(v.len(), 1);
}

#[test]
fn parse_exidx_offset_past_end_returns_empty() {
    let data = vec![0u8; 8];
    let v = parse_arm_exidx(&data, 100, 8, 0);
    assert!(v.is_empty());
}

#[test]
fn exidx_function_address_clears_thumb_bit() {
    let e = ExidxEntry { entry_vaddr: 0x1000, word0: 0x101, word1: 0 };
    // 0x1000 + 0x101 = 0x1101, &!1 = 0x1100
    assert_eq!(e.function_address(), 0x1100);
}

#[test]
fn exidx_is_cant_unwind() {
    let e = ExidxEntry { entry_vaddr: 0x1000, word0: 0, word1: 0x1 };
    assert!(e.is_cant_unwind());
    assert_eq!(e.extab_address(), None);
}

#[test]
fn exidx_inline_compact_flag() {
    // EXIDX_COMPACT_INLINE = bit 31
    let e = ExidxEntry { entry_vaddr: 0x1000, word0: 0, word1: 0x8000_0000 };
    assert!(e.is_inline_compact());
    assert_eq!(e.extab_address(), None);
}

#[test]
fn exidx_inline_opcode_bytes_extracted() {
    let e = ExidxEntry { entry_vaddr: 0x1000, word0: 0, word1: 0x80_AABBCC };
    let bytes = e.inline_opcode_bytes().expect("inline expected");
    assert_eq!(bytes, [0xAA, 0xBB, 0xCC]);
}

#[test]
fn exidx_compact_model_extracted() {
    // model bits [27:24]
    let e = ExidxEntry { entry_vaddr: 0x1000, word0: 0, word1: 0x82_000000 };
    assert!(e.is_inline_compact());
    // bits 27:24 = 0x2
    assert_eq!(e.compact_model(), 2);
}

#[test]
fn exidx_compact_model_non_inline_is_ff() {
    let e = ExidxEntry { entry_vaddr: 0x1000, word0: 0, word1: 0x1 };
    assert_eq!(e.compact_model(), 0xFF);
}

#[test]
fn exidx_function_addresses_sorted_dedup() {
    let entries = vec![
        ExidxEntry { entry_vaddr: 0x2000, word0: 0, word1: 0 },
        ExidxEntry { entry_vaddr: 0x1000, word0: 0, word1: 0 },
        ExidxEntry { entry_vaddr: 0x2000, word0: 0, word1: 0 }, // duplicate
    ];
    let addrs = exidx_function_addresses(&entries);
    assert_eq!(addrs, vec![0x1000, 0x2000]);
}

#[test]
fn parse_extab_empty() {
    assert!(parse_arm_extab(&[], 0, 0, 0).is_empty());
}

#[test]
fn parse_extab_compact_entry() {
    let mut data = vec![0u8; 4];
    data[0..4].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    let v = parse_arm_extab(&data, 0, 4, 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].personality_rva, None);
}

#[test]
fn parse_extab_generic_personality() {
    let mut data = vec![0u8; 4];
    // bit 31 clear → generic; header is PREL31 to personality
    data[0..4].copy_from_slice(&0x100u32.to_le_bytes());
    let v = parse_arm_extab(&data, 0, 4, 0x10000);
    assert_eq!(v.len(), 1);
    assert!(v[0].personality_rva.is_some());
}

// ============================================================================
// compression
// ============================================================================

#[test]
fn compress_type_name_known() {
    // ELFCOMPRESS_ZLIB = 1, ZSTD = 2
    assert_eq!(compress_type_name(1), "ELFCOMPRESS_ZLIB");
    assert_eq!(compress_type_name(2), "ELFCOMPRESS_ZSTD");
}

#[test]
fn compress_type_name_unknown_doesnt_panic() {
    let _ = compress_type_name(999);
}

#[test]
fn chdr32_too_short_errs() {
    assert!(Chdr32::parse(&[0u8; 4], 0, true).is_err());
}

#[test]
fn chdr64_too_short_errs() {
    assert!(Chdr64::parse(&[0u8; 4], 0, true).is_err());
}

#[test]
fn chdr32_parse_zlib_le() {
    // Chdr32: ch_type(4), ch_size(4), ch_addralign(4) = 12 bytes
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&1u32.to_le_bytes()); // ZLIB
    data[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // size
    data[8..12].copy_from_slice(&8u32.to_le_bytes());
    let h = Chdr32::parse(&data, 0, true).unwrap();
    assert_eq!(h.ch_type, 1);
    assert_eq!(h.ch_size, 0x1000);
    assert_eq!(h.ch_addralign, 8);
}

#[test]
fn chdr64_parse_zlib_le() {
    // Chdr64: ch_type(4), pad(4), ch_size(8), ch_addralign(8) = 24
    let mut data = vec![0u8; 24];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
    data[16..24].copy_from_slice(&16u64.to_le_bytes());
    let h = Chdr64::parse(&data, 0, true).unwrap();
    assert_eq!(h.ch_type, 1);
    assert_eq!(h.ch_size, 0x2000);
    assert_eq!(h.ch_addralign, 16);
}

#[test]
fn compressed_section_header_64bit_dispatch() {
    let mut data = vec![0u8; 24];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
    data[16..24].copy_from_slice(&8u64.to_le_bytes());
    let h = CompressedSectionHeader::parse(&data, 0, true, true).unwrap();
    assert!(h.is_zlib());
    assert!(!h.is_zstd());
    assert_eq!(h.type_name(), "ELFCOMPRESS_ZLIB");
}

#[test]
fn compressed_section_header_32bit_dispatch() {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&2u32.to_le_bytes()); // ZSTD
    data[4..8].copy_from_slice(&0x100u32.to_le_bytes());
    let h = CompressedSectionHeader::parse(&data, 0, false, true).unwrap();
    assert!(h.is_zstd());
    assert!(!h.is_zlib());
}

#[test]
fn decompress_zlib_invalid_returns_err() {
    let bad = vec![0xFFu8; 32];
    let result = decompress_zlib(&bad, 100);
    assert!(result.is_err());
}

#[test]
fn decompress_zlib_empty_input_errs_or_empty() {
    let result = decompress_zlib(&[], 0);
    // Either Err (no header) or Ok(empty); should not panic
    let _ = result;
}

// ============================================================================
// headers — name lookups
// ============================================================================

#[test]
fn elf_type_names() {
    assert_eq!(elf_type_name(0), "ET_NONE (None)");
    assert_eq!(elf_type_name(1), "ET_REL (Relocatable)");
    assert_eq!(elf_type_name(2), "ET_EXEC (Executable)");
    assert_eq!(elf_type_name(3), "ET_DYN (Shared object)");
    assert_eq!(elf_type_name(4), "ET_CORE (Core dump)");
    assert_eq!(elf_type_name(0xFFFE), "Processor-specific");
}

#[test]
fn elf_machine_names() {
    assert_eq!(elf_machine_name(0), "None");
    assert_eq!(elf_machine_name(3), "i386");
    assert_eq!(elf_machine_name(62), "x86-64");
    assert_eq!(elf_machine_name(183), "AArch64");
    assert_eq!(elf_machine_name(40), "ARM");
    assert_eq!(elf_machine_name(243), "RISC-V");
    assert_eq!(elf_machine_name(0xFFFF), "Unknown");
}

#[test]
fn elf_class_names() {
    assert_eq!(elf_class_name(0), "None");
    assert_eq!(elf_class_name(1), "ELF32");
    assert_eq!(elf_class_name(2), "ELF64");
    assert_eq!(elf_class_name(255), "Unknown");
}

#[test]
fn elf_data_names() {
    assert_eq!(elf_data_name(0), "None");
    assert_eq!(elf_data_name(1), "Little-endian (2's complement)");
    assert_eq!(elf_data_name(2), "Big-endian (2's complement)");
}

#[test]
fn elf_osabi_names() {
    assert_eq!(elf_osabi_name(0), "System V / None");
    assert_eq!(elf_osabi_name(3), "Linux");
    assert_eq!(elf_osabi_name(0xFE), "Unknown");
}

// ============================================================================
// Ehdr32 / Ehdr64 parse
// ============================================================================

fn build_ehdr32_le() -> Vec<u8> {
    let mut d = vec![0u8; 52];
    d[0..4].copy_from_slice(b"\x7fELF");
    d[4] = 1; // ELFCLASS32
    d[5] = 1; // ELFDATA2LSB
    d[6] = 1;
    d[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    d[18..20].copy_from_slice(&3u16.to_le_bytes()); // EM_386
    d[20..24].copy_from_slice(&1u32.to_le_bytes());
    d[24..28].copy_from_slice(&0x0804_8000_u32.to_le_bytes()); // entry
    d[28..32].copy_from_slice(&52u32.to_le_bytes());
    d[40..42].copy_from_slice(&52u16.to_le_bytes()); // ehsize
    d[42..44].copy_from_slice(&32u16.to_le_bytes());
    d[44..46].copy_from_slice(&1u16.to_le_bytes());
    d
}

#[test]
fn ehdr32_too_short() {
    assert!(Ehdr32::parse(&[0u8; 16]).is_err());
}

#[test]
fn ehdr32_bad_magic() {
    let mut d = vec![0u8; 52];
    d[0..4].copy_from_slice(b"XXXX");
    assert!(Ehdr32::parse(&d).is_err());
}

#[test]
fn ehdr32_wrong_class_errs() {
    let mut d = build_ehdr32_le();
    d[4] = 2; // ELFCLASS64
    assert!(Ehdr32::parse(&d).is_err());
}

#[test]
fn ehdr32_parse_ok() {
    let d = build_ehdr32_le();
    let h = Ehdr32::parse(&d).unwrap();
    assert_eq!(h.e_type, 2);
    assert_eq!(h.e_machine, 3);
    assert_eq!(h.e_entry, 0x0804_8000);
    assert!(h.is_little_endian());
}

fn build_ehdr64_le() -> Vec<u8> {
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(b"\x7fELF");
    d[4] = 2; // ELFCLASS64
    d[5] = 1;
    d[6] = 1;
    d[16..18].copy_from_slice(&2u16.to_le_bytes());
    d[18..20].copy_from_slice(&62u16.to_le_bytes());
    d[20..24].copy_from_slice(&1u32.to_le_bytes());
    d[24..32].copy_from_slice(&0x0040_1000_u64.to_le_bytes());
    d[32..40].copy_from_slice(&64u64.to_le_bytes());
    d[52..54].copy_from_slice(&64u16.to_le_bytes());
    d[54..56].copy_from_slice(&56u16.to_le_bytes());
    d[56..58].copy_from_slice(&1u16.to_le_bytes());
    d
}

#[test]
fn ehdr64_too_short() {
    assert!(Ehdr64::parse(&[0u8; 32]).is_err());
}

#[test]
fn ehdr64_parse_ok() {
    let d = build_ehdr64_le();
    let h = Ehdr64::parse(&d).unwrap();
    assert_eq!(h.e_machine, 62);
    assert_eq!(h.e_entry, 0x0040_1000);
    assert!(h.is_little_endian());
}

#[test]
fn ehdr_dispatch_64() {
    let d = build_ehdr64_le();
    let h = ElfHeader::parse(&d).unwrap();
    assert!(h.is_64bit());
    assert_eq!(h.machine(), 62);
    assert_eq!(h.entry_point(), 0x0040_1000);
}

#[test]
fn ehdr_dispatch_32() {
    let d = build_ehdr32_le();
    let h = ElfHeader::parse(&d).unwrap();
    assert!(!h.is_64bit());
    assert_eq!(h.machine(), 3);
}

#[test]
fn ehdr_dispatch_bad_magic() {
    let d = vec![0u8; 64];
    assert!(ElfHeader::parse(&d).is_err());
}

#[test]
fn arm_eabi_version_extracts_high_bits() {
    // EF_ARM_EABIMASK = 0xFF000000 → high byte is EABI version
    assert_eq!(arm_eabi_version(0x0500_0000), 5);
    assert_eq!(arm_eabi_version(0), 0);
}

// ============================================================================
// notes
// ============================================================================

#[test]
fn parse_note_section_empty_ok() {
    let s = parse_note_section(&[]).unwrap();
    assert!(s.notes.is_empty());
}

#[test]
fn parse_note_section_truncated_header_returns_ok_empty() {
    // < 12 bytes → no notes parsed
    let s = parse_note_section(&[0u8; 8]).unwrap();
    assert!(s.notes.is_empty());
}

#[test]
fn parse_note_section_namesz_overflow_errs() {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&100u32.to_le_bytes()); // namesz huge
    data[4..8].copy_from_slice(&0u32.to_le_bytes());
    data[8..12].copy_from_slice(&3u32.to_le_bytes());
    assert!(parse_note_section(&data).is_err());
}

#[test]
fn parse_note_section_gnu_build_id_classified() {
    // namesz=4 ("GNU\0"), descsz=4, type=3
    let mut data = vec![0u8; 12 + 4 + 4];
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    data[4..8].copy_from_slice(&4u32.to_le_bytes());
    data[8..12].copy_from_slice(&3u32.to_le_bytes());
    data[12..16].copy_from_slice(b"GNU\0");
    data[16..20].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    let s = parse_note_section(&data).unwrap();
    assert_eq!(s.notes.len(), 1);
    assert_eq!(s.notes[0].namespace, "GNU");
    assert!(matches!(s.notes[0].note_type, NoteType::Gnu(GnuNoteType::BuildId)));
    assert_eq!(s.notes[0].descriptor, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn parse_note_section_unknown_namespace() {
    let mut data = vec![0u8; 12 + 4 + 4];
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    data[4..8].copy_from_slice(&4u32.to_le_bytes());
    data[8..12].copy_from_slice(&42u32.to_le_bytes());
    data[12..16].copy_from_slice(b"FOO\0");
    let s = parse_note_section(&data).unwrap();
    assert_eq!(s.notes.len(), 1);
    assert!(matches!(s.notes[0].note_type, NoteType::Unknown { .. }));
}

#[test]
fn gnu_note_type_roundtrip() {
    for raw in [1u32, 2, 3, 4, 99, 12345] {
        let t = GnuNoteType::from_raw(raw);
        assert_eq!(t.as_raw(), raw);
    }
}

#[test]
fn gnu_build_id_as_hex_lowercase() {
    let b = GnuBuildId { bytes: vec![0xAB, 0xCD, 0xEF, 0x01] };
    let hex = b.as_hex();
    assert_eq!(hex.to_lowercase(), hex); // already lower
    assert!(hex.contains("abcdef01") || hex.contains("ABCDEF01"));
}

#[test]
fn gnu_build_id_len_and_empty() {
    let b = GnuBuildId { bytes: vec![] };
    assert_eq!(b.len(), 0);
    assert!(b.is_empty());

    let b2 = GnuBuildId { bytes: vec![1, 2, 3] };
    assert_eq!(b2.len(), 3);
    assert!(!b2.is_empty());
}

#[test]
fn elf_note_section_default_empty() {
    let s = ElfNoteSection::new();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert!(s.build_id().is_none());
    assert!(s.gnu_notes().is_empty());
    assert!(s.core_notes().is_empty());
}

// ============================================================================
// versioning
// ============================================================================

#[test]
fn parse_verneed_empty_ok() {
    let v = parse_verneed(&[], &[]).unwrap();
    assert!(v.is_empty());
}

#[test]
fn parse_verdef_empty_ok() {
    let v = parse_verdef(&[], &[]).unwrap();
    assert!(v.is_empty());
}

#[test]
fn parse_verneed_truncated_errs() {
    // < 16 bytes for header
    let v = parse_verneed(&[0u8; 4], &[]);
    assert!(v.is_err());
}

// ============================================================================
// Send/Sync sanity
// ============================================================================

#[test]
fn types_are_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<GnuHashTable>();
    check::<GnuBloomFilter>();
    check::<ExidxEntry>();
    check::<ElfNoteSection>();
}
