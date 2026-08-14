//! Blitz test suite for rustre-mem — exhaustive coverage of public APIs.

use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use rustre_mem::*;

fn rw(start: u64, data: &[u8]) -> VirtualMemoryProvider {
    let mut p = VirtualMemoryProvider::new();
    p.map(
        Address::new(start),
        data.to_vec(),
        Permissions::READ | Permissions::WRITE,
    );
    p
}

// ───────────────────────── VirtualMemoryProvider ─────────────────────────

#[test]
fn vmp_default_is_empty() {
    let p = VirtualMemoryProvider::default();
    assert!(p.regions().is_empty());
    assert_eq!(p.total_mapped_bytes(), 0);
}

#[test]
fn vmp_read_zero_len_unmapped_ok() {
    // Per source: read of len==0 returns Ok(vec![]) without checking mapping.
    let p = VirtualMemoryProvider::new();
    assert_eq!(p.read(Address::new(0xDEAD), 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn vmp_write_empty_ok() {
    let mut p = VirtualMemoryProvider::new();
    assert!(p.write(Address::new(0xDEAD), &[]).is_ok());
}

#[test]
fn vmp_map_replaces_existing_at_same_start() {
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0x1000), vec![0xAA; 16], Permissions::READ | Permissions::WRITE);
    p.map(Address::new(0x1000), vec![0xBB; 8], Permissions::READ | Permissions::WRITE);
    let data = p.read(Address::new(0x1000), 8).unwrap();
    assert_eq!(data, [0xBBu8; 8]);
    // Reading the original 16 bytes should now fail (new region only 8).
    assert!(p.read(Address::new(0x1000), 16).is_err());
}

#[test]
fn vmp_unmap_returns_false_for_missing() {
    let mut p = VirtualMemoryProvider::new();
    assert!(!p.unmap(Address::new(0x9999)));
}

#[test]
fn vmp_is_mapped_at_last_byte() {
    let p = rw(0x1000, &[0u8; 16]);
    assert!(p.is_mapped(Address::new(0x100F)));
    assert!(!p.is_mapped(Address::new(0x1010)));
}

#[test]
fn vmp_raw_data_none_for_inner_addr() {
    let p = rw(0x1000, &[0u8; 16]);
    // raw_data only returns Some for the START address.
    assert!(p.raw_data(Address::new(0x1004)).is_none());
    assert!(p.raw_data(Address::new(0x1000)).is_some());
}

#[test]
fn vmp_read_partial_crossing_into_unmapped_fails() {
    let p = rw(0x1000, &[0xCCu8; 16]);
    // Try to read past end into unmapped territory.
    assert!(p.read(Address::new(0x1008), 16).is_err());
}

#[test]
fn vmp_write_below_base_fails() {
    let mut p = rw(0x1000, &[0u8; 16]);
    assert!(p.write(Address::new(0x0FFF), &[0xAA]).is_err());
}

#[test]
fn vmp_cross_region_write() {
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0x1000), vec![0u8; 4], Permissions::READ | Permissions::WRITE);
    p.map(Address::new(0x1004), vec![0u8; 4], Permissions::READ | Permissions::WRITE);
    p.write(Address::new(0x1002), &[1, 2, 3, 4]).unwrap();
    assert_eq!(p.read(Address::new(0x1000), 8).unwrap(), [0, 0, 1, 2, 3, 4, 0, 0]);
}

#[test]
fn vmp_cross_region_write_permission_check_partial() {
    // First region writable, second is read-only — write spanning both must fail
    // atomically (no partial write).
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0x1000), vec![0xAAu8; 4], Permissions::READ | Permissions::WRITE);
    p.map(Address::new(0x1004), vec![0xAAu8; 4], Permissions::READ);
    let err = p.write(Address::new(0x1002), &[1, 2, 3, 4]).unwrap_err();
    assert!(matches!(err, MemError::PermissionDenied(_)));
    // First region should be unchanged.
    let r = p.read(Address::new(0x1000), 4).unwrap();
    assert_eq!(r, [0xAA, 0xAA, 0xAA, 0xAA]);
}

#[test]
fn vmp_stats_empty() {
    let p = VirtualMemoryProvider::new();
    let s = p.stats();
    assert_eq!(s.total_mapped, 0);
    assert_eq!(s.readable_bytes, 0);
    assert_eq!(s.writable_bytes, 0);
    assert_eq!(s.executable_bytes, 0);
}

#[test]
fn vmp_is_not_live() {
    let p = VirtualMemoryProvider::new();
    assert!(!p.is_live());
}

// Cross-thread Send + Sync check.
#[test]
fn vmp_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VirtualMemoryProvider>();
}

// ───────────────────────── Helpers ─────────────────────────

#[test]
fn helper_read_u128_le() {
    let val: u128 = 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0;
    let p = rw(0, &val.to_le_bytes());
    assert_eq!(rustre_mem::helpers::read_u128_le_at(&p, Address::new(0)), Some(val));
}

#[test]
fn helper_read_u128_truncated() {
    // Only 8 bytes mapped, asking for 16 should fail.
    let p = rw(0, &[0u8; 8]);
    assert!(rustre_mem::helpers::read_u128_le_at(&p, Address::new(0)).is_none());
}

#[test]
fn helper_read_f32_be() {
    let val = 2.5f32;
    let p = rw(0, &val.to_be_bytes());
    let got = rustre_mem::helpers::read_f32_be_at(&p, Address::new(0)).unwrap();
    assert!((got - val).abs() < 1e-6);
}

#[test]
fn helper_read_f64_be() {
    let val = std::f64::consts::PI;
    let p = rw(0, &val.to_be_bytes());
    let got = rustre_mem::helpers::read_f64_be_at(&p, Address::new(0)).unwrap();
    assert!((got - val).abs() < 1e-12);
}

#[test]
fn helper_search_bytes_no_mask() {
    let p = rw(0, &[0x00, 0xDE, 0xAD, 0x00, 0xDE, 0xAD, 0x00, 0x00]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    let hits = rustre_mem::helpers::search_bytes(&p, &[0xDE, 0xAD], r);
    assert_eq!(hits, [Address::new(1), Address::new(4)]);
}

// These two used to assert a panic. The panic was deliberately removed because
// `search_bytes` is reachable from unvalidated user input through the MCP tools,
// which made it a remote DoS. The documented contract is now explicit —
// "Returns an empty vec if `pattern` or `mask` is empty, or if their lengths
// differ" — so the tests assert that contract instead of the abandoned one.
#[test]
fn helper_search_bytes_empty_pattern_returns_empty() {
    let p = rw(0, &[0u8; 8]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    assert!(rustre_mem::helpers::search_bytes(&p, &[], r).is_empty());
}

#[test]
fn helper_search_with_mask_length_mismatch_returns_empty() {
    let p = rw(0, &[0u8; 8]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    assert!(
        rustre_mem::helpers::search_bytes_with_mask(&p, &[0xDE, 0xAD], &[0xFF], r).is_empty()
    );
}

#[test]
fn helper_write_u16_be() {
    let mut p = rw(0, &[0u8; 4]);
    rustre_mem::helpers::write_u16_be_at(&mut p, Address::new(0), 0x1234).unwrap();
    let raw = p.read(Address::new(0), 2).unwrap();
    assert_eq!(raw, [0x12, 0x34]);
}

#[test]
fn helper_write_u32_be_roundtrip() {
    let mut p = rw(0, &[0u8; 4]);
    rustre_mem::helpers::write_u32_be_at(&mut p, Address::new(0), 0xDEAD_BEEF).unwrap();
    assert_eq!(rustre_mem::helpers::read_u32_be_at(&p, Address::new(0)), Some(0xDEAD_BEEF));
}

// ───────────────────────── Entropy ─────────────────────────

#[test]
fn entropy_block_classification_zero() {
    let b = EntropyBlock { address: Address::new(0), size: 1, entropy: 0.0 };
    assert_eq!(b.classification(), "zero");
}

#[test]
fn entropy_block_classification_low() {
    let b = EntropyBlock { address: Address::new(0), size: 1, entropy: 2.0 };
    assert!(b.classification().contains("low"));
}

#[test]
fn entropy_block_classification_medium() {
    let b = EntropyBlock { address: Address::new(0), size: 1, entropy: 5.0 };
    assert!(b.classification().contains("medium"));
}

#[test]
fn entropy_block_classification_high() {
    let b = EntropyBlock { address: Address::new(0), size: 1, entropy: 7.5 };
    let c = b.classification();
    assert!(c.contains("high") || c.contains("max"), "got {c}");
}

#[test]
#[should_panic(expected = "block_size must be > 0")]
fn entropy_blocks_zero_block_size_panics() {
    let p = VirtualMemoryProvider::new();
    let _ = rustre_mem::entropy::entropy_blocks(&p, 0);
}

#[test]
fn entropy_high_spans_consecutive() {
    let blocks: Vec<EntropyBlock> = (0..3)
        .map(|i| EntropyBlock {
            address: Address::new(i * 100),
            size: 100,
            entropy: 7.9,
        })
        .collect();
    let spans = rustre_mem::entropy::high_entropy_spans(&blocks, 7.0);
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].block_count, 3);
    assert!(!spans[0].is_empty());
}

#[test]
fn entropy_value_in_range() {
    for size in [1, 16, 256, 1024] {
        let data: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
        let e = shannon_entropy(&data);
        assert!((0.0..=8.0).contains(&e), "entropy {e} out of range for size {size}");
    }
}

// ───────────────────────── NullMemoryProvider ─────────────────────────

#[test]
fn null_provider_write_fails() {
    let mut p = NullMemoryProvider::new();
    assert!(p.write(Address::new(0), &[0]).is_err());
}

#[test]
fn null_provider_stats_zero() {
    let p = NullMemoryProvider::new();
    let s = p.stats();
    assert_eq!(s.total_mapped, 0);
}

// ───────────────────────── PatchedMemoryProvider ─────────────────────────

#[test]
fn patched_remove_patch() {
    let base = rw(0x1000, &[0xAAu8; 16]);
    let mut p = PatchedMemoryProvider::new(base);
    p.add_patch(Address::new(0x1000), vec![0xBB, 0xBB], None);
    assert_eq!(p.patch_count(), 1);
    assert!(p.remove_patch_at(Address::new(0x1000)));
    assert_eq!(p.patch_count(), 0);
    let d = p.read(Address::new(0x1000), 2).unwrap();
    assert_eq!(d, [0xAA, 0xAA]);
}

#[test]
fn patched_remove_missing_patch_returns_false() {
    let base = rw(0x1000, &[0xAAu8; 16]);
    let mut p = PatchedMemoryProvider::new(base);
    assert!(!p.remove_patch_at(Address::new(0x9999)));
}

#[test]
fn patched_clear_all_patches() {
    let base = rw(0x1000, &[0xAAu8; 16]);
    let mut p = PatchedMemoryProvider::new(base);
    p.add_patch(Address::new(0x1000), vec![0xBB], None);
    p.add_patch(Address::new(0x1004), vec![0xCC], None);
    p.clear_patches();
    assert_eq!(p.patch_count(), 0);
}

#[test]
fn patched_read_original_bypasses_patch() {
    let base = rw(0x1000, &[0xAAu8; 16]);
    let mut p = PatchedMemoryProvider::new(base);
    p.add_patch(Address::new(0x1000), vec![0xBB, 0xBB], None);
    let orig = p.read_original(Address::new(0x1000), 2).unwrap();
    assert_eq!(orig, [0xAA, 0xAA]);
}

#[test]
fn patched_covers_check() {
    let patch = Patch { addr: Address::new(0x1000), data: vec![0u8; 4], description: None };
    assert_eq!(patch.end_addr(), Address::new(0x1004));
    assert!(patch.covers(Address::new(0x1000)));
    assert!(patch.covers(Address::new(0x1003)));
    assert!(!patch.covers(Address::new(0x1004)));
    assert!(!patch.covers(Address::new(0x0FFF)));
}

// ───────────────────────── MemError ─────────────────────────

#[test]
fn memerror_variants_have_messages() {
    let errs = [
        MemError::NotMapped(Address::new(0xDEAD)),
        MemError::PermissionDenied(Address::new(0xBEEF)),
        MemError::OutOfBounds(Address::new(0xCAFE), 16),
        MemError::Unsupported,
        MemError::Io("test".into()),
        MemError::Other("test".into()),
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn memerror_eq_consistency() {
    assert_eq!(
        MemError::NotMapped(Address::new(0x1000)),
        MemError::NotMapped(Address::new(0x1000))
    );
    assert_ne!(
        MemError::NotMapped(Address::new(0x1000)),
        MemError::NotMapped(Address::new(0x2000))
    );
}

#[test]
fn memerror_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let m: MemError = io.into();
    assert!(matches!(m, MemError::Io(_)));
}

// ───────────────────────── SnapshotId ─────────────────────────

#[test]
fn snapshot_id_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(SnapshotId(1));
    s.insert(SnapshotId(1));
    s.insert(SnapshotId(2));
    assert_eq!(s.len(), 2);
}

// ───────────────────────── Snapshot / Restore ─────────────────────────

#[tokio::test]
async fn snapshot_unsupported_for_null() {
    let mut p = NullMemoryProvider::new();
    let r = p.snapshot().await;
    assert!(matches!(r, Err(MemError::Unsupported)));
}

#[tokio::test]
async fn vmp_snapshot_ids_grow() {
    let mut p = rw(0x1000, &[0u8; 16]);
    let _ = p.snapshot().await.unwrap();
    let _ = p.snapshot().await.unwrap();
    assert_eq!(p.snapshot_ids().len(), 2);
}

// ───────────────────────── Composite ─────────────────────────

#[test]
fn composite_no_providers_read_fails() {
    let c = CompositeMemoryProvider::new();
    assert!(c.read(Address::new(0x1000), 4).is_err());
}

#[test]
fn composite_priority_order() {
    let mut high = VirtualMemoryProvider::new();
    high.map(Address::new(0x1000), vec![0x11; 4], Permissions::READ | Permissions::WRITE);
    let mut low = VirtualMemoryProvider::new();
    low.map(Address::new(0x1000), vec![0x22; 4], Permissions::READ | Permissions::WRITE);
    // Add low priority first to ensure ordering by priority value (higher wins).
    let mut c = CompositeMemoryProvider::new();
    c.add_provider(Box::new(low), 1);
    c.add_provider(Box::new(high), 100);
    let d = c.read(Address::new(0x1000), 4).unwrap();
    assert_eq!(d, [0x11; 4]);
}

// ───────────────────────── Region / RegionSet ─────────────────────────

#[test]
fn region_kind_short_tags_unique_for_distinct_kinds() {
    let kinds = [
        RegionKind::Code, RegionKind::Data, RegionKind::ReadOnlyData,
        RegionKind::Bss, RegionKind::Heap, RegionKind::Stack,
        RegionKind::Guard, RegionKind::Unknown,
    ];
    use std::collections::HashSet;
    let tags: HashSet<&'static str> = kinds.iter().map(|k| k.short_tag()).collect();
    assert_eq!(tags.len(), kinds.len());
}

#[test]
fn region_kind_display_matches_tag() {
    let k = RegionKind::Code;
    assert_eq!(format!("{}", k), k.short_tag());
}

#[test]
fn page_align_up_down() {
    assert_eq!(page_align_up(Address::new(0x1001), 0x1000), Address::new(0x2000));
    assert_eq!(page_align_down(Address::new(0x1FFF), 0x1000), Address::new(0x1000));
    assert_eq!(page_align_up(Address::new(0x1000), 0x1000), Address::new(0x1000));
}

#[test]
#[should_panic]
fn page_align_non_pow2_panics() {
    let _ = page_align_up(Address::new(100), 1000);
}

#[test]
fn page_index_and_containing() {
    assert_eq!(page_index(Address::new(0x2345), 0x1000), 2);
    let range = page_containing(Address::new(0x2345), 0x1000);
    assert_eq!(range.start, Address::new(0x2000));
    assert_eq!(range.end, Address::new(0x3000));
}

#[test]
fn page_range_indices_single_page() {
    let r = AddressRange::new(Address::new(0x100), Address::new(0x200));
    let (a, b) = page_range_indices(&r, 0x1000);
    assert_eq!(a, 0);
    assert_eq!(b, 0);
}

#[test]
fn page_range_indices_multi_page() {
    let r = AddressRange::new(Address::new(0x100), Address::new(0x3001));
    let (a, b) = page_range_indices(&r, 0x1000);
    assert_eq!(a, 0);
    assert_eq!(b, 3);
}

#[test]
fn region_set_gaps() {
    let mut rs = RegionSet::new();
    rs.insert(ExtendedRegion::new(
        AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        Permissions::READ,
    ));
    rs.insert(ExtendedRegion::new(
        AddressRange::new(Address::new(0x3000), Address::new(0x4000)),
        Permissions::READ,
    ));
    let gaps = rs.gaps();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].start, Address::new(0x2000));
    assert_eq!(gaps[0].end, Address::new(0x3000));
}

#[test]
fn region_set_merge_adjacent() {
    let mut rs = RegionSet::new();
    let r1 = ExtendedRegion::new(
        AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        Permissions::READ,
    );
    let r2 = ExtendedRegion::new(
        AddressRange::new(Address::new(0x2000), Address::new(0x3000)),
        Permissions::READ,
    );
    rs.insert(r1);
    rs.insert(r2);
    rs.merge_adjacent();
    assert_eq!(rs.len(), 1);
    let merged: Vec<_> = rs.iter().collect();
    assert_eq!(merged[0].range.start, Address::new(0x1000));
    assert_eq!(merged[0].range.end, Address::new(0x3000));
}

#[test]
fn region_set_filter_by_perms_kind() {
    let mut rs = RegionSet::new();
    rs.insert(ExtendedRegion::new(
        AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        Permissions::READ | Permissions::EXECUTE,
    ));
    rs.insert(ExtendedRegion::new(
        AddressRange::new(Address::new(0x3000), Address::new(0x4000)),
        Permissions::READ | Permissions::WRITE,
    ));
    assert_eq!(rs.executable_regions().len(), 1);
    assert_eq!(rs.writable_regions().len(), 1);
    assert_eq!(rs.readable_regions().len(), 2);
    assert_eq!(rs.total_bytes(), 0x2000);
}

#[test]
fn region_set_remove_at() {
    let mut rs = RegionSet::new();
    rs.insert(ExtendedRegion::new(
        AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        Permissions::READ,
    ));
    assert!(rs.remove_at(Address::new(0x1000)));
    assert!(!rs.remove_at(Address::new(0x1000)));
    assert!(rs.is_empty());
}

// ───────────────────────── Arena ─────────────────────────

#[test]
fn arena_basic_alloc() {
    let mut a = MemoryArena::new(1024, Address::new(0x1000));
    assert_eq!(a.capacity(), 1024);
    assert_eq!(a.used(), 0);
    assert_eq!(a.available(), 1024);
    let alloc = a.alloc_zeroed(64, 8).unwrap();
    assert_eq!(alloc.offset, 0);
    assert_eq!(alloc.size, 64);
    assert_eq!(a.used(), 64);
}

#[test]
fn arena_alignment_padding() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    a.alloc_zeroed(5, 1).unwrap(); // cursor now at 5
    let next = a.alloc_zeroed(8, 8).unwrap();
    assert_eq!(next.offset, 8); // padded from 5 → 8
}

#[test]
fn arena_invalid_alignment() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    let e = a.alloc_zeroed(8, 3).unwrap_err();
    assert!(matches!(e, ArenaError::InvalidAlignment { align: 3 }));
}

#[test]
fn arena_zero_alignment() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    let e = a.alloc_zeroed(8, 0).unwrap_err();
    assert!(matches!(e, ArenaError::InvalidAlignment { align: 0 }));
}

#[test]
fn arena_out_of_memory() {
    let mut a = MemoryArena::new(16, Address::new(0));
    let e = a.alloc_zeroed(32, 1).unwrap_err();
    assert!(matches!(e, ArenaError::OutOfMemory { .. }));
}

#[test]
fn arena_mark_pop_restores_cursor() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    a.alloc_zeroed(64, 1).unwrap();
    let mark = a.save_mark();
    a.alloc_zeroed(128, 1).unwrap();
    assert_eq!(a.used(), 192);
    a.pop_mark(mark).unwrap();
    assert_eq!(a.used(), 64);
    assert_eq!(a.stats().live_allocations, 1);
}

#[test]
fn arena_pop_mark_after_reset_fails() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    a.alloc_zeroed(64, 1).unwrap();
    let mark = a.save_mark();
    a.reset();
    let e = a.pop_mark(mark).unwrap_err();
    assert!(matches!(e, ArenaError::OutOfBounds { .. }));
}

#[test]
fn arena_reset_clears_state() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    a.alloc_zeroed(64, 1).unwrap();
    a.reset();
    assert_eq!(a.used(), 0);
    assert_eq!(a.stats().live_allocations, 0);
}

#[test]
fn arena_canary_detects_corruption() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    a.set_canary_enabled(true);
    let alloc = a.alloc_zeroed(32, 1).unwrap();
    assert!(a.check_canaries().is_ok());
    // Corrupt the canary by writing past the allocation.
    a.write_at(Address::new(alloc.offset as u64 + 32), &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    let err = a.check_canaries().unwrap_err();
    assert!(matches!(err, ArenaError::CanaryCorrupted { .. }));
}

#[test]
fn arena_canary_disabled_check_is_ok() {
    let a = MemoryArena::new(1024, Address::new(0));
    assert!(a.check_canaries().is_ok());
}

#[test]
fn arena_alloc_fill_byte_pattern() {
    let mut a = MemoryArena::new(64, Address::new(0x4000));
    let alloc = a.alloc_fill(16, 1, 0xAB, Some("test".into())).unwrap();
    let data = a.read_at(Address::new(0x4000 + alloc.offset as u64), 16).unwrap();
    assert_eq!(data, vec![0xABu8; 16]);
    assert_eq!(alloc.tag.as_deref(), Some("test"));
}

#[test]
fn arena_alloc_bytes_writes_data() {
    let mut a = MemoryArena::new(64, Address::new(0));
    let alloc = a.alloc_bytes(&[1, 2, 3, 4], 1).unwrap();
    let data = a.read_at(Address::new(alloc.offset as u64), 4).unwrap();
    assert_eq!(data, [1, 2, 3, 4]);
}

#[test]
fn arena_read_oob() {
    let a = MemoryArena::new(64, Address::new(0x1000));
    // Read below base.
    assert!(a.read_at(Address::new(0x0FFF), 4).is_err());
    // Read past end.
    assert!(a.read_at(Address::new(0x1040), 4).is_err());
}

#[test]
fn arena_write_oob() {
    let mut a = MemoryArena::new(64, Address::new(0x1000));
    assert!(a.write_at(Address::new(0x0FFF), &[0]).is_err());
    assert!(a.write_at(Address::new(0x103F), &[0, 0, 0, 0]).is_err());
}

#[test]
fn arena_alloc_address_offset() {
    let alloc = ArenaAlloc { offset: 16, size: 8, align: 8, tag: None };
    assert_eq!(alloc.address(Address::new(0x1000)), Address::new(0x1010));
    assert_eq!(alloc.end_offset(), 24);
}

#[test]
fn arena_stats_tracks_alignment_waste() {
    let mut a = MemoryArena::new(1024, Address::new(0));
    a.alloc_zeroed(5, 1).unwrap();
    a.alloc_zeroed(8, 8).unwrap(); // wastes 3 bytes padding
    assert_eq!(a.stats().alignment_waste, 3);
}

// ───────────────────────── MemoryProvider find_bytes ─────────────────────

#[test]
fn provider_find_bytes_empty_pattern() {
    let p = rw(0, &[0u8; 16]);
    assert!(p.find_bytes(&[], Address::new(0)).is_none());
}

#[test]
fn provider_find_bytes_skips_unreadable() {
    let mut p = VirtualMemoryProvider::new();
    p.map(Address::new(0x1000), vec![0xAA; 8], Permissions::WRITE);
    p.map(Address::new(0x2000), vec![0xAA; 8], Permissions::READ);
    let found = p.find_bytes(&[0xAA, 0xAA], Address::new(0));
    assert_eq!(found, Some(Address::new(0x2000)));
}

#[test]
fn provider_find_bytes_with_start_filter() {
    let mut data = vec![0u8; 64];
    data[8] = 0xDE; data[9] = 0xAD;
    data[40] = 0xDE; data[41] = 0xAD;
    let p = rw(0x1000, &data);
    // Start after first occurrence.
    let found = p.find_bytes(&[0xDE, 0xAD], Address::new(0x1010));
    assert_eq!(found, Some(Address::new(0x1028)));
}

// ───────────────────────── read_cstring ─────────────────────────

#[test]
fn read_cstring_basic() {
    let mut bytes = b"hello".to_vec();
    bytes.push(0);
    bytes.extend_from_slice(b"world");
    let p = rw(0, &bytes);
    let s = read_cstring(&p, Address::new(0), 32).unwrap();
    assert_eq!(s, "hello");
}

#[test]
fn read_cstring_no_terminator_within_max_len() {
    let p = rw(0, b"abcdef");
    let s = read_cstring(&p, Address::new(0), 4).unwrap();
    assert_eq!(s, "abcd");
}

#[test]
fn read_cstring_invalid_utf8() {
    let p = rw(0, &[0xFF, 0xFE, 0xFD, 0]);
    assert!(read_cstring(&p, Address::new(0), 16).is_err());
}

#[test]
fn read_cstring_unmapped_stops_gracefully() {
    let p = rw(0, b"hi");
    // max_len 32 but only 2 bytes mapped — should return "hi" (no NUL, stops on unmapped).
    let s = read_cstring(&p, Address::new(0), 32).unwrap();
    assert_eq!(s, "hi");
}

// ───────────────────────── module-level free fn find_bytes ─────────────

#[test]
fn module_find_bytes_wildcard_mask() {
    let p = rw(0, &[0xDE, 0xAA, 0xDE, 0xBB, 0xDE, 0xCC, 0, 0]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    let hits = rustre_mem::find_bytes(&p, &[0xDE, 0x00], Some(&[0xFF, 0x00]), r);
    assert_eq!(hits.len(), 3);
}

#[test]
fn module_find_bytes_no_mask() {
    let p = rw(0, &[0xAA, 0xBB, 0xAA, 0xBB, 0xAA]);
    let r = AddressRange::new(Address::new(0), Address::new(5));
    let hits = rustre_mem::find_bytes(&p, &[0xAA, 0xBB], None, r);
    assert_eq!(hits, [Address::new(0), Address::new(2)]);
}

#[test]
fn module_find_bytes_empty_pattern() {
    let p = rw(0, &[0u8; 8]);
    let r = AddressRange::new(Address::new(0), Address::new(8));
    let hits = rustre_mem::find_bytes(&p, &[], None, r);
    assert!(hits.is_empty());
}

// ───────────────────────── ReadOnlyWrapper ─────────────────────────

#[test]
fn readonly_wrapper_allows_read() {
    let inner = rw(0x1000, &[0xAA; 8]);
    let mut w = ReadOnlyWrapper(inner);
    assert_eq!(w.read(Address::new(0x1000), 4).unwrap(), [0xAA; 4]);
    assert!(matches!(w.write(Address::new(0x1000), &[0]), Err(MemError::PermissionDenied(_))));
}

// ───────────────────────── diff_providers ─────────────────────────

#[test]
fn diff_providers_unmapped_returns_no_diff() {
    let a = VirtualMemoryProvider::new();
    let b = VirtualMemoryProvider::new();
    let diffs = diff_providers(
        &a,
        &b,
        AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
    );
    // Both unmapped — implementation will likely return empty.
    assert!(diffs.is_empty());
}

#[test]
fn diff_span_methods() {
    let span = DiffSpan {
        range: AddressRange::new(Address::new(0x100), Address::new(0x110)),
        old_bytes: vec![0u8; 16],
        new_bytes: vec![0xFFu8; 16],
    };
    assert_eq!(span.len(), 16);
}
