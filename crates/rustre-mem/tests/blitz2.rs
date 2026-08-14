//! blitz2: deep adversarial integration tests for rustre-mem.
//!
//! Focuses on well-defined public APIs of:
//!   VirtualMemoryProvider, helpers::read_*/write_*, search_bytes(_with_mask),
//!   shannon_entropy, entropy_blocks, high_entropy_spans,
//!   NullMemoryProvider, PatchedMemoryProvider, CompositeMemoryProvider,
//!   MemError variants.

use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use rustre_mem::entropy::{
    EntropyBlock, entropy_blocks, high_entropy_spans, shannon_entropy,
};
use rustre_mem::helpers::{
    read_f32_be_at, read_f32_le_at, read_f64_be_at, read_f64_le_at, read_i8_at,
    read_i16_le_at, read_i32_le_at, read_i64_le_at, read_u8_at, read_u16_be_at,
    read_u16_le_at, read_u32_be_at, read_u32_le_at, read_u64_be_at,
    read_u64_le_at, read_u128_le_at, search_bytes, search_bytes_with_mask,
    write_f32_le_at, write_f64_le_at, write_i32_le_at, write_i64_le_at,
    write_u8_at, write_u16_be_at, write_u16_le_at, write_u32_be_at,
    write_u32_le_at, write_u64_be_at, write_u64_le_at,
};
use rustre_mem::*;
use std::sync::Arc;
use std::thread;

// ───────────────────────── helpers / fixtures ──────────────────────────────

fn rw(start: u64, data: &[u8]) -> VirtualMemoryProvider {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(start),
        data.to_vec(),
        Permissions::READ | Permissions::WRITE,
    );
    p
}

fn empty(start: u64, len: usize) -> VirtualMemoryProvider {
    rw(start, &vec![0u8; len])
}

/// Seeded LCG (Knuth LCG constants) — deterministic, no_std-friendly.
struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_byte(&mut self) -> u8 {
        (self.next() >> 56) as u8
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

// ───────────────────────── VirtualMemoryProvider: round-trip ────────────────

#[test]
fn vmp_roundtrip_50_u32_values() {
    let mut p = empty(0x1000, 8 * 50);
    let mut g = Lcg::new();
    let values: Vec<u32> = (0..50).map(|_| g.next() as u32).collect();
    for (i, v) in values.iter().enumerate() {
        let addr = Address::new(0x1000 + (i as u64) * 8);
        write_u32_le_at(&mut p, addr, *v).unwrap();
    }
    for (i, v) in values.iter().enumerate() {
        let addr = Address::new(0x1000 + (i as u64) * 8);
        assert_eq!(read_u32_le_at(&p, addr), Some(*v));
    }
}

#[test]
fn vmp_roundtrip_u64_le_be_inverse() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let v = g.next();
        let mut p = empty(0, 16);
        write_u64_le_at(&mut p, Address::new(0), v).unwrap();
        assert_eq!(read_u64_le_at(&p, Address::new(0)), Some(v));
        // Now check BE round-trip in a fresh region.
        let mut p2 = empty(0, 16);
        write_u64_be_at(&mut p2, Address::new(0), v).unwrap();
        assert_eq!(read_u64_be_at(&p2, Address::new(0)), Some(v));
    }
}

#[test]
fn vmp_roundtrip_f32_f64() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let bits32 = g.next() as u32;
        let f = f32::from_bits(bits32);
        let mut p = empty(0, 8);
        write_f32_le_at(&mut p, Address::new(0), f).unwrap();
        let got = read_f32_le_at(&p, Address::new(0)).unwrap();
        // NaN bit patterns may not equal; compare bit patterns instead.
        assert_eq!(got.to_bits(), f.to_bits());
    }
    for _ in 0..30 {
        let bits64 = g.next();
        let d = f64::from_bits(bits64);
        let mut p = empty(0, 16);
        write_f64_le_at(&mut p, Address::new(0), d).unwrap();
        let got = read_f64_le_at(&p, Address::new(0)).unwrap();
        assert_eq!(got.to_bits(), d.to_bits());
    }
}

// ───────────────────────── boundaries ───────────────────────────────────────

#[test]
fn vmp_read_zero_len_returns_empty_even_when_unmapped() {
    let p = VirtualMemoryProvider::new();
    assert_eq!(p.read(Address::new(0), 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn vmp_write_zero_len_always_ok() {
    let mut p = VirtualMemoryProvider::new();
    assert!(p.write(Address::new(0xDEAD), &[]).is_ok());
}

#[test]
fn vmp_read_one_byte_at_first_byte_of_region() {
    let p = rw(0x2000, &[0x77, 0x88, 0x99]);
    assert_eq!(read_u8_at(&p, Address::new(0x2000)), Some(0x77));
}

#[test]
fn vmp_read_one_byte_at_last_byte_of_region() {
    let p = rw(0x2000, &[0x77, 0x88, 0x99]);
    assert_eq!(read_u8_at(&p, Address::new(0x2002)), Some(0x99));
}

#[test]
fn vmp_read_one_byte_just_past_region_fails() {
    let p = rw(0x2000, &[0x77, 0x88, 0x99]);
    assert!(p.read(Address::new(0x2003), 1).is_err());
}

#[test]
fn vmp_write_u8_max_value_roundtrip() {
    let mut p = empty(0, 4);
    write_u8_at(&mut p, Address::new(0), u8::MAX).unwrap();
    assert_eq!(read_u8_at(&p, Address::new(0)), Some(u8::MAX));
}

#[test]
fn vmp_write_u64_max_value_roundtrip() {
    let mut p = empty(0, 16);
    write_u64_le_at(&mut p, Address::new(0), u64::MAX).unwrap();
    assert_eq!(read_u64_le_at(&p, Address::new(0)), Some(u64::MAX));
}

#[test]
fn vmp_signed_min_max_roundtrip() {
    let mut p = empty(0, 16);
    write_i32_le_at(&mut p, Address::new(0), i32::MIN).unwrap();
    write_i32_le_at(&mut p, Address::new(4), i32::MAX).unwrap();
    assert_eq!(read_i32_le_at(&p, Address::new(0)), Some(i32::MIN));
    assert_eq!(read_i32_le_at(&p, Address::new(4)), Some(i32::MAX));
    write_i64_le_at(&mut p, Address::new(0), i64::MIN).unwrap();
    assert_eq!(read_i64_le_at(&p, Address::new(0)), Some(i64::MIN));
}

// ───────────────────────── truncated / oversized reads ─────────────────────

#[test]
fn vmp_truncated_u32_read_returns_none_via_helper() {
    // Region only 2 bytes long; read_u32 needs 4.
    let p = rw(0, &[0xAA, 0xBB]);
    assert!(read_u32_le_at(&p, Address::new(0)).is_none());
}

#[test]
fn vmp_truncated_u64_at_region_tail_returns_none() {
    let p = rw(0, &[0u8; 7]);
    assert!(read_u64_le_at(&p, Address::new(0)).is_none());
}

#[test]
fn vmp_oversized_write_at_region_end_fails() {
    let mut p = empty(0x1000, 4);
    let r = p.write(Address::new(0x1002), &[0u8; 4]);
    assert!(r.is_err());
}

#[test]
fn vmp_write_to_unmapped_address_fails() {
    let mut p = VirtualMemoryProvider::new();
    assert!(p.write(Address::new(0xCAFE_BABE), &[1, 2, 3]).is_err());
}

#[test]
fn vmp_write_to_readonly_fails() {
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0), vec![0u8; 8], Permissions::READ);
    let r = p.write(Address::new(0), &[1]);
    assert!(matches!(r, Err(MemError::PermissionDenied(_))));
}

// ───────────────────────── seeded LCG fuzz: never panic ────────────────────

#[test]
fn fuzz_helpers_random_addresses_no_panic() {
    let mut p = empty(0x4000, 256);
    let mut g = Lcg::new();
    for _ in 0..500 {
        let addr = Address::new(g.next() & 0xFFFF);
        // Each helper must return None for out-of-range; never panic.
        let _ = read_u8_at(&p, addr);
        let _ = read_u16_le_at(&p, addr);
        let _ = read_u32_le_at(&p, addr);
        let _ = read_u64_le_at(&p, addr);
        let _ = read_u128_le_at(&p, addr);
        let _ = read_i64_le_at(&p, addr);
        let _ = read_f64_le_at(&p, addr);
        // Writes: must return Err (not panic) for unmapped/unwriteable addresses.
        let _ = write_u8_at(&mut p, addr, 0);
    }
}

#[test]
fn fuzz_shannon_entropy_random_inputs_never_panic() {
    let mut g = Lcg::new();
    for size_seed in 0..100 {
        let n = (g.next() as usize) % 4096;
        let data = g.next_bytes(n);
        let e = shannon_entropy(&data);
        assert!(
            (0.0..=8.0001).contains(&e),
            "entropy out of range: {} size_seed={}",
            e,
            size_seed
        );
    }
}

#[test]
fn fuzz_search_bytes_random_pattern_never_panic() {
    let mut g = Lcg::new();
    let data = g.next_bytes(1024);
    let p = rw(0x10000, &data);
    let range = AddressRange::new(Address::new(0x10000), Address::new(0x10000 + 1024));
    for _ in 0..50 {
        let plen = 1 + (g.next() as usize) % 8;
        let pat = g.next_bytes(plen);
        let _ = search_bytes(&p, &pat, range);
        // mask same length:
        let mask = g.next_bytes(plen);
        let _ = search_bytes_with_mask(&p, &pat, &mask, range);
    }
}

// ───────────────────────── search semantics ────────────────────────────────

#[test]
fn search_bytes_finds_pattern_at_known_offset() {
    let mut data = vec![0u8; 64];
    data[20..24].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let p = rw(0x5000, &data);
    let range = AddressRange::new(Address::new(0x5000), Address::new(0x5000 + 64));
    let hits = search_bytes(&p, &[0xDE, 0xAD, 0xBE, 0xEF], range);
    assert_eq!(hits, vec![Address::new(0x5014)]);
}

#[test]
fn search_bytes_with_mask_all_wildcard_matches_every_offset() {
    let p = rw(0, &[0xAAu8; 4]);
    let range = AddressRange::new(Address::new(0), Address::new(4));
    let hits = search_bytes_with_mask(&p, &[0x00], &[0x00], range);
    assert_eq!(hits.len(), 4);
}

#[test]
fn search_bytes_empty_range_returns_empty() {
    let p = rw(0, &[0xAAu8; 8]);
    let r = AddressRange::new(Address::new(0), Address::new(0));
    assert!(search_bytes(&p, &[0xAA], r).is_empty());
}

// The panic these asserted was removed deliberately: `search_bytes` is reachable
// from unvalidated user input via the MCP tools, so panicking was a remote DoS.
// The documented contract is now "returns an empty vec" — assert that.
#[test]
fn search_bytes_with_mask_mismatched_lengths_returns_empty() {
    let p = rw(0, &[0u8; 8]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    assert!(search_bytes_with_mask(&p, &[0xAA, 0xBB], &[0xFF], r).is_empty());
}

#[test]
fn search_bytes_empty_pattern_returns_empty() {
    let p = rw(0, &[0u8; 8]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    assert!(search_bytes(&p, &[], r).is_empty());
}

// ───────────────────────── entropy boundaries ──────────────────────────────

#[test]
fn entropy_empty_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn entropy_single_byte_zero() {
    assert!((shannon_entropy(&[0xAA]) - 0.0).abs() < 1e-12);
}

#[test]
fn entropy_uniform_256_distinct_is_8() {
    let data: Vec<u8> = (0u8..=255).collect();
    assert!((shannon_entropy(&data) - 8.0).abs() < 1e-9);
}

#[test]
fn entropy_two_balanced_values_is_1() {
    let data: Vec<u8> = (0..1024).map(|i| (i % 2) as u8).collect();
    let e = shannon_entropy(&data);
    assert!((e - 1.0).abs() < 1e-9);
}

#[test]
fn entropy_blocks_skips_write_only_region() {
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0x1000), vec![0u8; 256], Permissions::WRITE);
    assert!(entropy_blocks(&p, 64).is_empty());
}

#[test]
fn entropy_blocks_partial_tail() {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(0x1000),
        vec![0u8; 300],
        Permissions::READ | Permissions::WRITE,
    );
    let blocks = entropy_blocks(&p, 256);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].size, 256);
    assert_eq!(blocks[1].size, 44);
}

#[test]
#[should_panic]
fn entropy_blocks_zero_block_size_should_panic() {
    let p = VirtualMemoryProvider::new();
    let _ = entropy_blocks(&p, 0);
}

#[test]
fn high_entropy_spans_groups_consecutive_blocks() {
    let blocks: Vec<EntropyBlock> = [7.5, 7.8, 1.0, 7.6, 7.9]
        .iter()
        .enumerate()
        .map(|(i, &e)| EntropyBlock {
            address: Address::new(i as u64 * 256),
            size: 256,
            entropy: e,
        })
        .collect();
    let spans = high_entropy_spans(&blocks, 7.0);
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].block_count, 2);
    assert_eq!(spans[1].block_count, 2);
}

// ───────────────────────── state machine: snapshot/restore ─────────────────

#[test]
fn snapshot_restore_after_writes_roundtrip() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut p = empty(0x1000, 16);
        p.write(Address::new(0x1000), &[1, 2, 3, 4]).unwrap();
        let s1 = p.snapshot().await.unwrap();
        p.write(Address::new(0x1000), &[9, 9, 9, 9]).unwrap();
        assert_eq!(p.read(Address::new(0x1000), 4).unwrap(), [9, 9, 9, 9]);
        p.restore(s1).await.unwrap();
        assert_eq!(p.read(Address::new(0x1000), 4).unwrap(), [1, 2, 3, 4]);
    });
}

#[test]
fn snapshot_invalid_id_returns_err() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut p = VirtualMemoryProvider::new();
        assert!(p.restore(SnapshotId(99_999)).await.is_err());
    });
}

#[test]
fn snapshot_ids_monotonic() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut p = empty(0, 4);
        let s1 = p.snapshot().await.unwrap();
        let s2 = p.snapshot().await.unwrap();
        let s3 = p.snapshot().await.unwrap();
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert!(p.snapshot_ids().len() >= 3);
    });
}

// ───────────────────────── MemError variants / Display ──────────────────────

#[test]
fn mem_error_not_mapped_display_nonempty() {
    let e = MemError::NotMapped(Address::new(0xDEAD));
    assert!(!e.to_string().is_empty());
}

#[test]
fn mem_error_perm_denied_display_nonempty() {
    let e = MemError::PermissionDenied(Address::new(0xCAFE));
    assert!(!e.to_string().is_empty());
}

#[test]
fn mem_error_oob_display_nonempty() {
    let e = MemError::OutOfBounds(Address::new(0), 64);
    assert!(!e.to_string().is_empty());
}

#[test]
fn mem_error_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let me = MemError::from(io);
    assert!(matches!(me, MemError::Io(_)));
}

// ───────────────────────── NullMemoryProvider ──────────────────────────────

#[test]
fn null_provider_reads_fail() {
    let p = NullMemoryProvider::new();
    assert!(p.read(Address::new(0x1000), 4).is_err());
    assert!(p.regions().is_empty());
}

#[test]
fn null_provider_writes_fail() {
    let mut p = NullMemoryProvider::new();
    assert!(p.write(Address::new(0x1000), &[1, 2]).is_err());
}

// ───────────────────────── PatchedMemoryProvider ───────────────────────────

#[test]
fn patched_provider_overlays_short_patch() {
    let mut base = empty(0x1000, 16);
    base.write(Address::new(0x1000), &[0xAAu8; 16]).unwrap();
    let mut pp = PatchedMemoryProvider::new(base);
    pp.add_patch(Address::new(0x1004), vec![0xBB, 0xBB], None);
    let data = pp.read(Address::new(0x1000), 8).unwrap();
    assert_eq!(data, [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xAA, 0xAA]);
}

#[test]
fn patched_provider_outside_patch_passthrough() {
    let mut base = empty(0x1000, 16);
    base.write(Address::new(0x1000), &[0xCCu8; 16]).unwrap();
    let mut pp = PatchedMemoryProvider::new(base);
    pp.add_patch(Address::new(0x1000), vec![0xDD], None);
    let data = pp.read(Address::new(0x1004), 4).unwrap();
    assert_eq!(data, [0xCC, 0xCC, 0xCC, 0xCC]);
}

// ───────────────────────── CompositeMemoryProvider priority ────────────────

#[test]
fn composite_higher_priority_wins() {
    let mut a = empty(0x1000, 4);
    a.write(Address::new(0x1000), &[0xAAu8; 4]).unwrap();
    let mut b = empty(0x1000, 4);
    b.write(Address::new(0x1000), &[0xBBu8; 4]).unwrap();
    let mut c = CompositeMemoryProvider::new();
    c.add_provider(Box::new(a), 10);
    c.add_provider(Box::new(b), 5);
    let data = c.read(Address::new(0x1000), 4).unwrap();
    assert_eq!(data, [0xAA, 0xAA, 0xAA, 0xAA]);
}

#[test]
fn composite_fallback_to_lower_priority() {
    let empty_a = VirtualMemoryProvider::new();
    let mut b = empty(0x1000, 4);
    b.write(Address::new(0x1000), &[0xEEu8; 4]).unwrap();
    let mut c = CompositeMemoryProvider::new();
    c.add_provider(Box::new(empty_a), 10);
    c.add_provider(Box::new(b), 5);
    let data = c.read(Address::new(0x1000), 4).unwrap();
    assert_eq!(data, [0xEE, 0xEE, 0xEE, 0xEE]);
}

// ───────────────────────── SnapshotId Eq / Hash consistency ─────────────────

#[test]
fn snapshot_id_eq_and_inequality_pairs() {
    use std::collections::HashSet;
    let mut seen: HashSet<SnapshotId> = HashSet::new();
    for i in 0..30u64 {
        let s = SnapshotId(i);
        assert_eq!(s, SnapshotId(i));
        assert_ne!(s, SnapshotId(i + 1));
        // Hash/Eq consistency: insertions of equal IDs collapse.
        seen.insert(s);
        seen.insert(SnapshotId(i));
    }
    assert_eq!(seen.len(), 30);
}

// ───────────────────────── cross-region reads ──────────────────────────────

#[test]
fn cross_region_contiguous_read_succeeds() {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(0x1000),
        vec![0xAAu8; 8],
        Permissions::READ | Permissions::WRITE,
    );
    p.map(
        Address::new(0x1008),
        vec![0xBBu8; 8],
        Permissions::READ | Permissions::WRITE,
    );
    let data = p.read(Address::new(0x1004), 8).unwrap();
    assert_eq!(data, [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
}

#[test]
fn cross_region_gap_read_fails() {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(0x1000),
        vec![0xAAu8; 8],
        Permissions::READ | Permissions::WRITE,
    );
    p.map(
        Address::new(0x2000),
        vec![0xBBu8; 8],
        Permissions::READ | Permissions::WRITE,
    );
    // Gap between 0x1008 and 0x2000.
    assert!(p.read(Address::new(0x1004), 8).is_err());
}

// ───────────────────────── Send+Sync threaded stress ───────────────────────

#[test]
fn virtual_provider_send_sync_threaded_reads() {
    let mut p = empty(0x1000, 4096);
    let mut g = Lcg::new();
    let payload = g.next_bytes(4096);
    p.write(Address::new(0x1000), &payload).unwrap();
    let arc = Arc::new(p);
    let mut handles = vec![];
    for t in 0..4 {
        let arc2 = Arc::clone(&arc);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let off = (t * 13 + (i as usize) * 7) % 4090;
                let d = arc2.read(Address::new(0x1000 + off as u64), 4).unwrap();
                assert_eq!(d.len(), 4);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ───────────────────────── stats ──────────────────────────────────────────

#[test]
fn stats_aggregate_perms() {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(0x1000),
        vec![0u8; 0x1000],
        Permissions::READ | Permissions::EXECUTE,
    );
    p.map(
        Address::new(0x3000),
        vec![0u8; 0x800],
        Permissions::READ | Permissions::WRITE,
    );
    let s = p.stats();
    assert_eq!(s.total_mapped, 0x1800);
    assert_eq!(s.readable_bytes, 0x1800);
    assert_eq!(s.executable_bytes, 0x1000);
    assert_eq!(s.writable_bytes, 0x800);
}

// ───────────────────────── integer-boundary read helpers ───────────────────

#[test]
fn read_u16_be_at_boundary_values() {
    let mut p = empty(0, 8);
    write_u16_be_at(&mut p, Address::new(0), 0x0000).unwrap();
    assert_eq!(read_u16_be_at(&p, Address::new(0)), Some(0x0000));
    write_u16_be_at(&mut p, Address::new(2), 0xFFFF).unwrap();
    assert_eq!(read_u16_be_at(&p, Address::new(2)), Some(0xFFFF));
    write_u16_le_at(&mut p, Address::new(4), 0xABCD).unwrap();
    assert_eq!(read_u16_le_at(&p, Address::new(4)), Some(0xABCD));
}

#[test]
fn read_u32_be_and_le_distinct() {
    let p = rw(0, &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(read_u32_be_at(&p, Address::new(0)), Some(0x12345678));
    assert_eq!(read_u32_le_at(&p, Address::new(0)), Some(0x78563412));
}

#[test]
fn read_i8_negative_one() {
    let p = rw(0, &[0xFF]);
    assert_eq!(read_i8_at(&p, Address::new(0)), Some(-1));
}

#[test]
fn read_f32_be_pi() {
    let v = std::f32::consts::PI;
    let p = rw(0, &v.to_be_bytes());
    let got = read_f32_be_at(&p, Address::new(0)).unwrap();
    assert!((got - v).abs() < 1e-6);
}

#[test]
fn read_f64_be_e() {
    let v = std::f64::consts::E;
    let p = rw(0, &v.to_be_bytes());
    let got = read_f64_be_at(&p, Address::new(0)).unwrap();
    assert!((got - v).abs() < 1e-15);
}

// ───────────────────────── named regions ───────────────────────────────────

#[test]
fn vmp_named_region_visible_in_regions_list() {
    let mut p = VirtualMemoryProvider::new();
    p.map_named(
        Address::new(0x4000),
        vec![0u8; 0x40],
        Permissions::READ,
        ".rodata",
    );
    let r = p.regions();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name.as_deref(), Some(".rodata"));
}

// ───────────────────────── unmap idempotence ───────────────────────────────

#[test]
fn vmp_unmap_idempotent_and_returns_false_when_missing() {
    let mut p = empty(0x1000, 4);
    assert!(p.unmap(Address::new(0x1000)));
    assert!(!p.unmap(Address::new(0x1000)));
    assert!(!p.unmap(Address::new(0xDEAD)));
}

// ───────────────────────── total_mapped_bytes ──────────────────────────────

#[test]
fn vmp_total_mapped_bytes_sum() {
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0), vec![0u8; 100], Permissions::READ);
    p.map(Address::new(0x1000), vec![0u8; 200], Permissions::READ);
    p.map(Address::new(0x2000), vec![0u8; 50], Permissions::READ);
    assert_eq!(p.total_mapped_bytes(), 350);
}

// ───────────────────────── raw_data accessor ──────────────────────────────

#[test]
fn vmp_raw_data_returns_inner_bytes() {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(0x9000),
        vec![1, 2, 3, 4, 5],
        Permissions::READ,
    );
    assert_eq!(p.raw_data(Address::new(0x9000)), Some(&[1, 2, 3, 4, 5][..]));
    assert!(p.raw_data(Address::new(0x9001)).is_none()); // base must match exactly
}
