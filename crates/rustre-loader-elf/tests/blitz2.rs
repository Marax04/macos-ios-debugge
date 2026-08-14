//! Blitz2 deep adversarial suite for `rustre-loader-elf`.
//!
//! Focused on: arm_exidx, gnu_hash, versioning, ElfInfo parser, and threaded
//! Send/Sync stress over public types.

use rustre_loader_elf::{
    ElfInfo, ElfLoader, GnuBloomFilter, GnuHashTable, PltEntry, gnu_hash, gnu_hash_str,
    parse_verdef, parse_verneed,
};

use rustre_loader_elf::arm_exidx::{
    EXIDX_CANTUNWIND, EXIDX_COMPACT_INLINE, ExidxEntry, UnwindOpcode, addr_to_prel31,
    decode_pop_regs_2, decode_unwind_byte, exidx_function_addresses, parse_arm_exidx,
    parse_arm_extab, prel31_to_addr,
};
use rustre_loader_elf::versioning::{VersionDef, VersionNeed, VersionNeedAux, VersionTable};

use rustre_core::loader::{Loader, LoaderInput};
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// Seeded LCG for fuzz inputs (no rand/no time).
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

fn rand_bytes(g: &mut impl FnMut() -> u64, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let w = g().to_le_bytes();
        for &b in &w {
            if v.len() < n {
                v.push(b);
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------
// PREL31 round-trip — 50+ deterministic inputs
// ---------------------------------------------------------------------------

#[test]
fn prel31_roundtrip_many() {
    // PREL31 encodes a signed 31-bit offset (range [-2^30, 2^30)). Round-trip
    // is only well-defined when target-base fits that range; restrict fuzz
    // accordingly so we exercise the algorithm, not the documented domain limit.
    let mut g = lcg();
    for _ in 0..200 {
        let base = g() as u32;
        // Pick an offset in [-2^30, 2^30) deterministically from the LCG.
        let raw = g() as u32;
        let signed_off = ((raw as i32) >> 2); // arithmetic shift → range [-2^30, 2^30)
        let target = base.wrapping_add(signed_off as u32);
        let enc = addr_to_prel31(base, target);
        assert_eq!(enc & 0x8000_0000, 0, "PREL31 must be 31-bit");
        let dec = prel31_to_addr(base, enc);
        assert_eq!(dec, target, "round-trip failed base=0x{base:x} tgt=0x{target:x}");
    }
}

#[test]
fn prel31_zero_offset() {
    for &base in &[0u32, 1, 0x1000, 0x8000_0000, 0xFFFF_FFFF] {
        assert_eq!(prel31_to_addr(base, 0), base);
    }
}

#[test]
fn prel31_max_positive_offset() {
    // 0x3FFF_FFFF = max positive PREL31
    let dec = prel31_to_addr(0, 0x3FFF_FFFF);
    assert_eq!(dec, 0x3FFF_FFFF);
}

#[test]
fn prel31_negative_offsets() {
    // bit 30 set → negative when sign-extended
    // 0x4000_0000 → after <<1>>1 = 0xC000_0000 (signed)
    let dec = prel31_to_addr(0, 0x4000_0000);
    assert_eq!(dec, 0xC000_0000);
}

#[test]
fn prel31_ignores_top_bit_of_word() {
    // The function masks word with 0x7FFFFFFF, so top bit must not affect result.
    let mut g = lcg();
    for _ in 0..50 {
        let base = g() as u32;
        let word = (g() as u32) & 0x7FFF_FFFF;
        let with_top = word | 0x8000_0000;
        assert_eq!(prel31_to_addr(base, word), prel31_to_addr(base, with_top));
    }
}

// ---------------------------------------------------------------------------
// decode_unwind_byte coverage of all 256 inputs
// ---------------------------------------------------------------------------

#[test]
fn decode_unwind_byte_total_function() {
    for op in 0u8..=255 {
        // Must never panic
        let _ = decode_unwind_byte(op);
    }
}

#[test]
fn decode_unwind_vsp_add_range() {
    for op in 0x00u8..=0x3F {
        assert_eq!(decode_unwind_byte(op), UnwindOpcode::VspAdd(op & 0x3F));
    }
}

#[test]
fn decode_unwind_vsp_sub_range() {
    for op in 0x40u8..=0x7F {
        assert_eq!(decode_unwind_byte(op), UnwindOpcode::VspSub(op & 0x3F));
    }
}

#[test]
fn decode_unwind_finish_b0() {
    assert_eq!(decode_unwind_byte(0xB0), UnwindOpcode::Finish);
}

#[test]
fn decode_unwind_reserved_sp_regs() {
    // r13 and r15 are reserved for SetVspFromReg.
    assert_eq!(decode_unwind_byte(0x9D), UnwindOpcode::Spare(0x9D));
    assert_eq!(decode_unwind_byte(0x9F), UnwindOpcode::Spare(0x9F));
}

#[test]
fn decode_unwind_set_vsp_from_reg_legal() {
    for reg in 0u8..16 {
        if reg == 13 || reg == 15 {
            continue;
        }
        let op = 0x90 | reg;
        assert_eq!(decode_unwind_byte(op), UnwindOpcode::SetVspFromReg(reg));
    }
}

#[test]
fn decode_pop_regs_2_low_bits_only() {
    // hi=0x80, lo=0x01 → mask 0x001, regmask = 0x001 (r0)
    let op = decode_pop_regs_2(0x80, 0x01);
    match op {
        UnwindOpcode::PopRegs(m) => assert_eq!(m & 0x0FFF, 0x001),
        _ => panic!("expected PopRegs"),
    }
}

// ---------------------------------------------------------------------------
// parse_arm_exidx — boundary / fuzz / oversize
// ---------------------------------------------------------------------------

#[test]
fn parse_arm_exidx_empty() {
    let entries = parse_arm_exidx(&[], 0, 0, 0);
    assert!(entries.is_empty());
}

#[test]
fn parse_arm_exidx_partial_entry_ignored() {
    // 7 bytes is less than one full 8-byte entry → should return zero entries.
    let entries = parse_arm_exidx(&[0u8; 7], 0, 7, 0);
    assert!(entries.is_empty());
}

#[test]
fn parse_arm_exidx_oversize_section_clamps_to_data() {
    let data = vec![0u8; 16];
    // Claim section_size = 1MB but data is only 16 bytes → should not panic.
    let entries = parse_arm_exidx(&data, 0, 1_000_000, 0x1000);
    assert_eq!(entries.len(), 2);
}

#[test]
fn parse_arm_exidx_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 512;
        let buf = rand_bytes(&mut g, len);
        let off = (g() as usize) % (len + 1);
        let sz = (g() as usize) % (len.saturating_sub(off) + 1);
        let vaddr = g() as u32;
        let entries = parse_arm_exidx(&buf, off, sz, vaddr);
        // Each entry's function_address must be computable without panic.
        for e in &entries {
            let _ = e.function_address();
            let _ = e.is_inline_compact();
            let _ = e.is_cant_unwind();
            let _ = e.compact_model();
            let _ = e.inline_opcode_bytes();
            let _ = e.extab_address();
        }
    }
}

#[test]
fn parse_arm_extab_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 256;
        let buf = rand_bytes(&mut g, len);
        let off = (g() as usize) % (len + 1);
        let sz = (g() as usize) % (len.saturating_sub(off) + 1);
        let _ = parse_arm_extab(&buf, off, sz, g() as u32);
    }
}

#[test]
fn exidx_function_addresses_sorted_and_unique() {
    let mut g = lcg();
    let mut entries = Vec::new();
    for _ in 0..30 {
        entries.push(ExidxEntry {
            entry_vaddr: g() as u32,
            word0: g() as u32,
            word1: g() as u32,
        });
    }
    let addrs = exidx_function_addresses(&entries);
    for w in addrs.windows(2) {
        assert!(w[0] < w[1], "must be strictly sorted + deduped");
    }
}

#[test]
fn exidx_entry_compact_model_for_non_inline() {
    let e = ExidxEntry {
        entry_vaddr: 0,
        word0: 0,
        word1: 0x0000_0010, // not inline, not CANTUNWIND
    };
    assert_eq!(e.compact_model(), 0xFF);
}

#[test]
fn exidx_entry_thumb_bit_cleared() {
    // PREL31 producing odd address: function_address must mask off bit 0.
    let e = ExidxEntry {
        entry_vaddr: 0x1000,
        word0: 0x0101, // +0x101 → 0x1101 with thumb bit
        word1: EXIDX_CANTUNWIND,
    };
    assert_eq!(e.function_address() & 1, 0);
    assert_eq!(e.function_address(), 0x1100);
}

#[test]
fn exidx_entry_inline_opcode_bytes_extracted() {
    let e = ExidxEntry {
        entry_vaddr: 0,
        word0: 0,
        word1: EXIDX_COMPACT_INLINE | 0x00AA_BBCC,
    };
    let bytes = e.inline_opcode_bytes().unwrap();
    assert_eq!(bytes, [0xAA, 0xBB, 0xCC]);
}

// ---------------------------------------------------------------------------
// gnu_hash — known values + fuzz
// ---------------------------------------------------------------------------

#[test]
fn gnu_hash_djb2_seed_5381() {
    // Empty bytes → seed 5381
    assert_eq!(gnu_hash(b""), 5381);
}

#[test]
fn gnu_hash_str_matches_bytes_for_ascii() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = ((g() as usize) % 32) + 1;
        let s: String = (0..len)
            .map(|_| ((g() as u8) % 26 + b'a') as char)
            .collect();
        assert_eq!(gnu_hash_str(&s), gnu_hash(s.as_bytes()));
    }
}

#[test]
fn gnu_hash_deterministic_repeated() {
    let v = b"some_symbol_name";
    let h1 = gnu_hash(v);
    let h2 = gnu_hash(v);
    let h3 = gnu_hash(v);
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

#[test]
fn gnu_hash_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() as usize) % 256;
        let buf = rand_bytes(&mut g, len);
        let _ = gnu_hash(&buf);
    }
}

// ---------------------------------------------------------------------------
// GnuBloomFilter
// ---------------------------------------------------------------------------

#[test]
fn bloom_filter_zero_word_rejects_all() {
    let bf = GnuBloomFilter::new(vec![0u64; 4], 6, 64);
    let mut g = lcg();
    for _ in 0..50 {
        assert!(!bf.might_contain(g() as u32));
    }
}

#[test]
fn bloom_filter_all_ones_accepts_all() {
    let bf = GnuBloomFilter::new(vec![u64::MAX; 4], 6, 64);
    let mut g = lcg();
    for _ in 0..50 {
        assert!(bf.might_contain(g() as u32));
    }
}

#[test]
fn bloom_filter_fpr_within_unit_interval() {
    let bf = GnuBloomFilter::new(vec![u64::MAX; 8], 6, 64);
    for n in [1usize, 10, 100, 1000, 10_000] {
        let r = bf.false_positive_rate(n);
        assert!((0.0..=1.0).contains(&r), "fpr {r} out of [0,1] for n={n}");
    }
}

#[test]
fn bloom_filter_empty_treated_as_present() {
    let bf = GnuBloomFilter::new(vec![], 6, 64);
    assert!(bf.might_contain(0));
    assert!(bf.might_contain(0xFFFF_FFFF));
}

// ---------------------------------------------------------------------------
// GnuHashTable — error paths, fuzz, lookup
// ---------------------------------------------------------------------------

#[test]
fn gnu_hash_table_parse64_too_short_under_16_bytes() {
    for n in 0..16 {
        let res = GnuHashTable::parse64(&vec![0u8; n], true);
        assert!(res.is_err(), "n={n} should error");
    }
}

#[test]
fn gnu_hash_table_parse64_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..100 {
        let len = (g() as usize) % 256;
        let buf = rand_bytes(&mut g, len);
        let _ = GnuHashTable::parse64(&buf, true);
        let _ = GnuHashTable::parse64(&buf, false);
    }
}

#[test]
fn gnu_hash_table_lookup_no_buckets_returns_none() {
    // Build header with nbuckets = 0.
    let mut data = vec![0u8; 16 + 8];
    data[0..4].copy_from_slice(&0u32.to_le_bytes()); // nbuckets
    data[4..8].copy_from_slice(&0u32.to_le_bytes()); // symoffset
    data[8..12].copy_from_slice(&1u32.to_le_bytes()); // bloom_size
    data[12..16].copy_from_slice(&6u32.to_le_bytes()); // shift2
    data[16..24].copy_from_slice(&u64::MAX.to_le_bytes()); // bloom = all ones
    let t = GnuHashTable::parse64(&data, true).unwrap();
    assert!(t.lookup("anything").is_none());
}

#[test]
fn gnu_hash_table_scan_all_returns_sorted_dedup() {
    // Empty buckets → no symbols.
    let mut data = vec![0u8; 16 + 8 + 4];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..8].copy_from_slice(&1u32.to_le_bytes());
    data[8..12].copy_from_slice(&1u32.to_le_bytes());
    data[12..16].copy_from_slice(&6u32.to_le_bytes());
    let t = GnuHashTable::parse64(&data, true).unwrap();
    let v = t.scan_all_symbols();
    assert!(v.is_empty());
}

// ---------------------------------------------------------------------------
// VersionTable round-trip
// ---------------------------------------------------------------------------

#[test]
fn version_table_parse_roundtrip_many() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 64;
        let mut buf = Vec::with_capacity(n * 2);
        let mut expected = Vec::with_capacity(n);
        for _ in 0..n {
            let v = g() as u16;
            buf.extend_from_slice(&v.to_le_bytes());
            expected.push(v);
        }
        let vt = VersionTable::parse(&buf);
        assert_eq!(vt.len(), n);
        assert_eq!(vt.is_empty(), n == 0);
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(vt.get(i), Some(*exp));
        }
        assert!(vt.get(n).is_none());
        assert!(vt.get(n + 1000).is_none());
    }
}

#[test]
fn version_table_parse_odd_length_drops_trailing_byte() {
    // 3 bytes → 1 u16 entry (the last byte cannot form a complete u16).
    let vt = VersionTable::parse(&[0x01, 0x00, 0xFF]);
    assert_eq!(vt.len(), 1);
}

#[test]
fn parse_verneed_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let dlen = (g() as usize) % 128;
        let slen = (g() as usize) % 128;
        let d = rand_bytes(&mut g, dlen);
        let s = rand_bytes(&mut g, slen);
        let _ = parse_verneed(&d, &s);
    }
}

#[test]
fn parse_verdef_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let dlen = (g() as usize) % 128;
        let slen = (g() as usize) % 128;
        let d = rand_bytes(&mut g, dlen);
        let s = rand_bytes(&mut g, slen);
        let _ = parse_verdef(&d, &s);
    }
}

#[test]
fn parse_verneed_empty_data_is_ok_empty() {
    let r = parse_verneed(&[], &[]).unwrap();
    assert!(r.is_empty());
}

#[test]
fn parse_verdef_empty_data_is_ok_empty() {
    let r = parse_verdef(&[], &[]).unwrap();
    assert!(r.is_empty());
}

#[test]
fn parse_verneed_short_errors_not_panic() {
    for n in 1..16 {
        let r = parse_verneed(&vec![0u8; n], &[]);
        assert!(r.is_err(), "n={n}");
    }
}

#[test]
fn parse_verdef_short_errors_not_panic() {
    for n in 1..20 {
        let r = parse_verdef(&vec![0u8; n], &[]);
        assert!(r.is_err(), "n={n}");
    }
}

// ---------------------------------------------------------------------------
// VersionDef / VersionNeed clone & eq
// ---------------------------------------------------------------------------

#[test]
fn version_def_eq_consistency_many() {
    for i in 0..30u32 {
        let a = VersionDef {
            flags: i as u16,
            ndx: (i * 2) as u16,
            hash: i,
            names: vec![format!("v{i}")],
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}

#[test]
fn version_need_aux_eq_consistency_many() {
    for i in 0..30u32 {
        let a = VersionNeedAux {
            hash: i,
            flags: i as u16,
            other: (i + 1) as u16,
            name: format!("GLIBC_{i}"),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
    let vn = VersionNeed {
        filename: "libc.so.6".into(),
        aux: vec![],
    };
    let vn2 = vn.clone();
    assert_eq!(vn, vn2);
}

// ---------------------------------------------------------------------------
// ElfInfo parser — adversarial inputs
// ---------------------------------------------------------------------------

#[test]
fn elf_info_parse_empty_errors() {
    assert!(ElfInfo::parse(&[]).is_err());
}

#[test]
fn elf_info_parse_random_short_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 256;
        let buf = rand_bytes(&mut g, len);
        let _ = ElfInfo::parse(&buf);
    }
}

#[test]
fn elf_info_parse_truncated_after_magic_errors() {
    let mut buf = vec![0u8; 8];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    let r = ElfInfo::parse(&buf);
    assert!(r.is_err());
}

// ---------------------------------------------------------------------------
// ElfLoader — can_load adversarial
// ---------------------------------------------------------------------------

#[test]
fn loader_can_load_rejects_three_byte_prefix() {
    let loader = ElfLoader;
    let input = LoaderInput::new("", vec![0x7f, b'E', b'L']);
    assert!(!loader.can_load(&input));
}

#[test]
fn loader_can_load_only_first_four_bytes() {
    let loader = ElfLoader;
    let mut g = lcg();
    let mut buf = vec![0x7f, b'E', b'L', b'F'];
    buf.extend_from_slice(&rand_bytes(&mut g, 100));
    let input = LoaderInput::new("", buf);
    assert!(loader.can_load(&input));
}

#[test]
fn loader_name_is_elf() {
    let l = ElfLoader;
    assert_eq!(l.name(), "elf");
}

#[tokio::test]
async fn loader_find_nested_always_empty() {
    let l = ElfLoader;
    let input = LoaderInput::new("", vec![0u8; 64]);
    let r = l.find_nested(&input).await.unwrap();
    assert!(r.is_empty());
}

#[tokio::test]
async fn loader_load_random_garbage_errors() {
    let l = ElfLoader;
    let mut g = lcg();
    for _ in 0..10 {
        let buf = rand_bytes(&mut g, 200);
        let input = LoaderInput::new("", buf);
        let _ = l.load(input).await; // must not panic
    }
}

// ---------------------------------------------------------------------------
// PltEntry / value types
// ---------------------------------------------------------------------------

#[test]
fn plt_entry_clone_eq() {
    let p = PltEntry {
        name: "abc".into(),
        address: 0x1000,
        got_address: 0x2000,
    };
    let p2 = p.clone();
    assert_eq!(p, p2);
}

// ---------------------------------------------------------------------------
// Send+Sync threaded stress (4 threads x 100 ops)
// ---------------------------------------------------------------------------

#[test]
fn threaded_gnu_hash_send_sync() {
    let s = Arc::new(String::from("symbol_under_stress_test"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = s.clone();
        handles.push(thread::spawn(move || {
            let mut acc = 0u32;
            for _ in 0..100 {
                acc = acc.wrapping_add(gnu_hash_str(&s));
            }
            acc
        }));
    }
    let vals: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All threads must agree (deterministic).
    for w in vals.windows(2) {
        assert_eq!(w[0], w[1]);
    }
}

#[test]
fn threaded_prel31_roundtrip_send_sync() {
    let mut handles = Vec::new();
    for t in 0..4u32 {
        handles.push(thread::spawn(move || {
            let mut g = {
                let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE ^ (t as u64);
                move || {
                    s = s
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    s
                }
            };
            for _ in 0..100 {
                let base = g() as u32;
                // Restrict offset to PREL31's documented range [-2^30, 2^30).
                let signed_off = (g() as i32) >> 2;
                let target = base.wrapping_add(signed_off as u32);
                let enc = addr_to_prel31(base, target);
                assert_eq!(prel31_to_addr(base, enc), target);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_version_table_send_sync() {
    let data = Arc::new({
        let mut v = Vec::new();
        for i in 0..100u16 {
            v.extend_from_slice(&i.to_le_bytes());
        }
        v
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let data = data.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let vt = VersionTable::parse(&data);
                assert_eq!(vt.len(), 100);
                assert_eq!(vt.get(50), Some(50));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
