//! Adversarial blitz tests for rustre-core public surface.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use rustre_core::*;
use rustre_core::endian::EndianRead;

/// Seeded LCG fuzz helper.
fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ───────────────────────── Address ─────────────────────────

#[test]
fn address_wrapping_add_sub() {
    assert_eq!((Address::new(u64::MAX) + 1).as_u64(), 0);
    assert_eq!((Address::new(0) - 1).as_u64(), u64::MAX);
}

#[test]
fn address_offset_positive_negative() {
    let a = Address::new(0x1000);
    assert_eq!(a.offset(0).as_u64(), 0x1000);
    assert_eq!(a.offset(i64::MAX).as_u64(),
               0x1000u64.wrapping_add(i64::MAX as u64));
    assert_eq!(a.offset(-1).as_u64(), 0x0FFF);
    // Most-negative i64 should not panic.
    let _ = a.offset(i64::MIN);
}

#[test]
fn address_align_up_idempotent() {
    let mut g = make_lcg();
    for _ in 0..60 {
        let v = g();
        let a = Address::new(v);
        let aligned = a.align_up(0x10);
        assert!(aligned.as_u64().is_multiple_of(0x10) || aligned.as_u64() < v);
        // align_up(align_up(x)) == align_up(x)
        assert_eq!(aligned.align_up(0x10), aligned);
    }
}

#[test]
fn address_align_down_lt_align_up() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let v = g() & 0x0000_0000_FFFF_FFFF; // avoid overflow at top
        let a = Address::new(v);
        let down = a.align_down(0x10);
        let up = a.align_up(0x10);
        assert!(down.as_u64() <= a.as_u64());
        assert!(up.as_u64() >= a.as_u64());
        assert!(up.as_u64() - down.as_u64() <= 0x10);
    }
}

#[test]
fn address_is_aligned_small_align() {
    assert!(Address::new(0).is_aligned(0));
    assert!(Address::new(123).is_aligned(1));
    assert!(Address::new(8).is_aligned(8));
    assert!(!Address::new(9).is_aligned(8));
}

#[test]
fn address_checked_boundaries() {
    assert_eq!(Address::new(u64::MAX).checked_add(0), Some(Address::new(u64::MAX)));
    assert_eq!(Address::new(u64::MAX).checked_add(1), None);
    assert_eq!(Address::new(0).checked_sub(0), Some(Address::new(0)));
    assert_eq!(Address::new(0).checked_sub(1), None);
}

#[test]
fn address_distance_to_invariant() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let a = Address::new(g());
        let b = Address::new(g());
        if let Some(d) = a.distance_to(b) {
            assert_eq!(a.as_u64() + d, b.as_u64());
        } else {
            assert!(b.as_u64() < a.as_u64());
        }
    }
}

#[test]
fn address_as_u32_clamps() {
    assert_eq!(Address::new(u64::MAX).as_u32(), u32::MAX);
    assert_eq!(Address::new(0x1234).as_u32(), 0x1234);
}

// ───────────────────────── AddressRange ─────────────────────────

#[test]
fn range_overlap_symmetry_fuzz() {
    let mut g = make_lcg();
    for _ in 0..60 {
        let s1 = g() & 0xFFFF;
        let e1 = s1.saturating_add(g() & 0xFFF);
        let s2 = g() & 0xFFFF;
        let e2 = s2.saturating_add(g() & 0xFFF);
        let a = AddressRange::new(Address::new(s1), Address::new(e1));
        let b = AddressRange::new(Address::new(s2), Address::new(e2));
        assert_eq!(a.overlaps(&b), b.overlaps(&a));
        assert_eq!(a.intersects(&b), a.overlaps(&b));
    }
}

#[test]
fn range_split_at_inverse_merge() {
    let r = AddressRange::new(Address::new(0x100), Address::new(0x500));
    let (l, rg) = r.split_at(Address::new(0x200)).unwrap();
    assert_eq!(l.merge(&rg), r);
}

#[test]
fn range_intersection_subset_of_both() {
    let mut g = make_lcg();
    for _ in 0..60 {
        let s1 = g() & 0xFFFF;
        let e1 = s1.saturating_add((g() & 0xFFF) + 1);
        let s2 = g() & 0xFFFF;
        let e2 = s2.saturating_add((g() & 0xFFF) + 1);
        let a = AddressRange::new(Address::new(s1), Address::new(e1));
        let b = AddressRange::new(Address::new(s2), Address::new(e2));
        if let Some(i) = a.intersection(&b) {
            assert!(a.contains_range(&i));
            assert!(b.contains_range(&i));
        } else {
            assert!(!a.overlaps(&b));
        }
    }
}

#[test]
fn range_empty_contains_nothing() {
    let r = AddressRange::new(Address::new(0x1000), Address::new(0x1000));
    assert!(r.is_empty());
    assert!(!r.contains(Address::new(0x1000)));
    assert!(!r.contains(Address::new(0)));
}

#[test]
fn range_iter_step_zero_treated_as_one() {
    let r = AddressRange::new(Address::new(0), Address::new(3));
    let collected: Vec<u64> = r.iter_step(0).map(Address::as_u64).collect();
    assert_eq!(collected, vec![0, 1, 2]);
}

#[test]
fn range_from_len_overflow_wraps() {
    let r = AddressRange::from_len(Address::new(u64::MAX - 2), 10);
    // wraps: end < start so empty
    assert!(r.is_empty());
}

// ───────────────────────── SegmentMapping round-trip ─────────────────────────

#[test]
fn segment_mapping_roundtrip_fuzz() {
    let seg = SegmentMapping::new(
        AddressRange::new(Address::new(0x4000), Address::new(0x5000)),
        FileOffsetRange::new(FileOffset::new(0x100), FileOffset::new(0x1100)),
    );
    let mut g = make_lcg();
    for _ in 0..50 {
        let off = g() % 0x1000;
        let va = Address::new(0x4000 + off);
        let fo = seg.va_to_file_offset(va).unwrap();
        let back = seg.file_offset_to_va(fo).unwrap();
        assert_eq!(back, va);
    }
}

// ───────────────────────── RVA ─────────────────────────

#[test]
fn rva_arith_wrapping() {
    let r = RVA::new(u32::MAX) + 1;
    assert_eq!(r.as_u32(), 0);
    let r2 = RVA::new(0) - 1;
    assert_eq!(r2.as_u32(), u32::MAX);
}

#[test]
fn rva_resolve_zero_base() {
    let r = RVA::new(0x100);
    assert_eq!(r.resolve(Address::new(0)).as_u64(), 0x100);
}

// ───────────────────────── Endian ─────────────────────────

#[test]
fn endian_flip_involution() {
    assert_eq!(Endian::Little.flip().flip(), Endian::Little);
    assert_eq!(Endian::Big.flip().flip(), Endian::Big);
    assert!(Endian::Little.is_little());
    assert!(Endian::Big.is_big());
}

#[test]
fn swap_helpers_involution_fuzz() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let v = g();
        assert_eq!(swap_endian_u64(swap_endian_u64(v)), v);
        assert_eq!(swap_endian_u32(swap_endian_u32(v as u32)), v as u32);
        assert_eq!(swap_endian_u16(swap_endian_u16(v as u16)), v as u16);
    }
}

#[test]
fn endian_buf_write_read_roundtrip() {
    for endian in [Endian::Little, Endian::Big] {
        let mut buf = EndianBuf::new(endian);
        buf.write_u8(0xAB);
        buf.write_u16(0x1234);
        buf.write_u32(0xDEAD_BEEF);
        buf.write_u64(0x0123_4567_89AB_CDEF);
        assert_eq!(buf.read_u8(0), Some(0xAB));
        assert_eq!(buf.read_u16(1), Some(0x1234));
        assert_eq!(buf.read_u32(3), Some(0xDEAD_BEEF));
        assert_eq!(buf.read_u64(7), Some(0x0123_4567_89AB_CDEF));
    }
}

#[test]
fn endian_buf_read_out_of_bounds() {
    let buf = EndianBuf::from_vec(vec![1, 2, 3], Endian::Little);
    assert_eq!(buf.read_u32(0), None);
    assert_eq!(buf.read_u8(100), None);
    assert_eq!(buf.read_u64(0), None);
}

#[test]
fn slice_endian_read_truncated() {
    let data: &[u8] = &[0x01, 0x02];
    assert!(data.read_u32(0, Endian::Little).is_none());
    assert!(data.read_u64(0, Endian::Big).is_none());
    assert_eq!(data.read_u16(0, Endian::Little), Some(0x0201));
    assert_eq!(data.read_u16(0, Endian::Big), Some(0x0102));
}

#[test]
fn slice_endian_read_ptr_sizes() {
    let data: &[u8] = &[0u8; 16];
    assert_eq!(data.read_ptr(0, Endian::Little, 2), Some(0));
    assert_eq!(data.read_ptr(0, Endian::Little, 4), Some(0));
    assert_eq!(data.read_ptr(0, Endian::Little, 8), Some(0));
    // invalid pointer width
    assert_eq!(data.read_ptr(0, Endian::Little, 3), None);
    assert_eq!(data.read_ptr(0, Endian::Little, 7), None);
}

#[test]
fn uleb128_roundtrip_fuzz() {
    let mut g = make_lcg();
    for v in [0u64, 1, 0x7F, 0x80, 0x3FFF, 0x4000, u64::MAX, u64::MAX - 1] {
        let enc = encode_uleb128(v);
        let (dec, n) = decode_uleb128(&enc, 0).unwrap();
        assert_eq!(dec, v);
        assert_eq!(n, enc.len());
    }
    for _ in 0..40 {
        let v = g();
        let enc = encode_uleb128(v);
        let (dec, _) = decode_uleb128(&enc, 0).unwrap();
        assert_eq!(dec, v);
    }
}

#[test]
fn sleb128_roundtrip_fuzz() {
    let mut g = make_lcg();
    for v in [0i64, 1, -1, 63, -64, i64::MAX, i64::MIN, i64::MIN + 1] {
        let enc = encode_sleb128(v);
        let (dec, n) = decode_sleb128(&enc, 0).unwrap();
        assert_eq!(dec, v);
        assert_eq!(n, enc.len());
    }
    for _ in 0..40 {
        let v = g() as i64;
        let enc = encode_sleb128(v);
        let (dec, _) = decode_sleb128(&enc, 0).unwrap();
        assert_eq!(dec, v);
    }
}

#[test]
fn uleb128_decode_truncated_returns_none() {
    // continuation bit set but no following byte
    assert!(decode_uleb128(&[0x80], 0).is_none());
    assert!(decode_uleb128(&[], 0).is_none());
    // offset past end
    assert!(decode_uleb128(&[0x01], 5).is_none());
}

#[test]
fn uleb128_decode_overflow_returns_none() {
    // 11+ bytes all with continuation set => shift overflow
    let bad = [0xFFu8; 12];
    assert!(decode_uleb128(&bad, 0).is_none());
}

#[test]
fn sleb128_decode_truncated_returns_none() {
    assert!(decode_sleb128(&[0x80], 0).is_none());
    assert!(decode_sleb128(&[], 0).is_none());
}

// ───────────────────────── IDs ─────────────────────────

#[test]
fn id_zero_is_invalid_nonzero_valid() {
    assert!(!FunctionId::INVALID.is_valid());
    assert_eq!(FunctionId::new(0), None);
    assert!(FunctionId::new(1).unwrap().is_valid());
    assert_eq!(FunctionId::from_raw(42).into_raw(), 42);
}

#[test]
fn id_allocator_monotonic() {
    let a = IdAllocator::<FunctionId>::new();
    let mut prev: u64 = 0;
    for _ in 0..100 {
        let id: FunctionId = a.next();
        let raw = id.into_raw();
        assert!(raw > prev);
        prev = raw;
    }
    assert_eq!(a.allocated_count(), 100);
}

#[test]
fn id_allocator_shared_counter() {
    let a: IdAllocator<FunctionId> = IdAllocator::new();
    let b = a.clone_shared();
    let _ = a.next();
    let _ = b.next();
    assert_eq!(a.allocated_count(), 2);
    assert_eq!(b.allocated_count(), 2);
}

#[test]
fn id_pool_reclaim_lifo() {
    let mut pool = IdPool::<FunctionId>::new();
    let x = pool.alloc();
    let y = pool.alloc();
    pool.reclaim(x);
    pool.reclaim(y);
    assert_eq!(pool.alloc(), y);
    assert_eq!(pool.alloc(), x);
}

#[test]
fn id_map_operations() {
    let mut m: IdMap<FunctionId, &'static str> = IdMap::new();
    let id = FunctionId::from_raw(7);
    assert!(m.is_empty());
    m.insert(id, "f");
    assert!(m.contains_key(id));
    assert_eq!(m.get(id), Some(&"f"));
    assert_eq!(m.remove(id), Some("f"));
    assert!(m.is_empty());
}

#[test]
fn id_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut s: HashSet<FunctionId> = HashSet::new();
    for i in 1..=30u64 {
        assert!(s.insert(FunctionId::from_raw(i)));
        assert!(!s.insert(FunctionId::from_raw(i)));
    }
    assert_eq!(s.len(), 30);
}

#[test]
fn id_allocator_thread_safe_stress() {
    use std::sync::Arc;
    use std::thread;
    let a: Arc<IdAllocator<FunctionId>> = Arc::new(IdAllocator::new());
    let mut handles = vec![];
    for _ in 0..4 {
        let a = a.clone();
        handles.push(thread::spawn(move || {
            let mut out = Vec::new();
            for _ in 0..100 {
                out.push(a.next().into_raw());
            }
            out
        }));
    }
    let mut all = Vec::new();
    for h in handles {
        all.extend(h.join().unwrap());
    }
    all.sort_unstable();
    let unique_len = {
        let mut copy = all.clone();
        copy.dedup();
        copy.len()
    };
    assert_eq!(unique_len, 400);
}

// ───────────────────────── Permissions ─────────────────────────

#[test]
fn permissions_rwx_string_roundtrip() {
    for bits in 0u8..=7 {
        let p = Permissions::from_bits_truncate(bits);
        let s = p.as_rwx_string();
        let back = Permissions::from_rwx_string(&s).unwrap();
        assert_eq!(p, back, "bits={bits} s={s}");
    }
}

#[test]
fn permissions_from_rwx_invalid() {
    assert!(Permissions::from_rwx_string("").is_none());
    assert!(Permissions::from_rwx_string("rw").is_none());
    assert!(Permissions::from_rwx_string("rwxa").is_none());
    assert!(Permissions::from_rwx_string("zwx").is_none());
    assert!(Permissions::from_rwx_string("rzx").is_none());
    assert!(Permissions::from_rwx_string("rwz").is_none());
}

#[test]
fn permissions_with_without() {
    let p = Permissions::READ.with(Permissions::WRITE);
    assert!(p.is_readable() && p.is_writable());
    let q = p.without(Permissions::WRITE);
    assert!(!q.is_writable());
    assert!(q.is_readable());
}

#[test]
fn permissions_combo_constants() {
    assert_eq!(Permissions::RW, Permissions::READ | Permissions::WRITE);
    assert_eq!(Permissions::RX, Permissions::READ | Permissions::EXECUTE);
    assert_eq!(
        Permissions::RWX,
        Permissions::READ | Permissions::WRITE | Permissions::EXECUTE
    );
}

#[test]
fn permission_policy_allow_deny() {
    let mut pol = PermissionPolicy::new();
    pol.add_rule(PermissionRule::deny(Permissions::EXECUTE));
    assert!(pol.is_denied(Permissions::EXECUTE));
    assert!(pol.is_allowed(Permissions::READ));
}

#[test]
fn permissions_serde_roundtrip() {
    let p = Permissions::RWX;
    let s = serde_json::to_string(&p).unwrap();
    let back: Permissions = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

// ───────────────────────── Patches / Comments / Bookmarks ─────────────────────────

#[test]
fn patch_kind_label_and_reversible() {
    assert_eq!(PatchKind::Nop.label(), "nop");
    assert_eq!(PatchKind::RawBytes.label(), "raw");
    assert!(PatchKind::Nop.is_reversible());
    assert!(PatchKind::Custom("x".into()).is_reversible());
}

#[test]
fn patch_contains_and_overlap() {
    let p = Patch::new(0x1000, vec![0; 4], vec![0x90; 4], PatchKind::Nop);
    assert_eq!(p.len(), 4);
    assert!(p.contains(0x1000));
    assert!(p.contains(0x1003));
    assert!(!p.contains(0x1004));
    assert!(p.overlaps(0x0FFE, 0x1002));
    assert!(!p.overlaps(0x2000, 0x3000));
}

#[test]
fn patch_set_insert_remove_many() {
    let mut ps = PatchSet::new();
    let mut ids = Vec::new();
    for i in 0..20u64 {
        let id = ps.insert(Patch::new(
            0x1000 + i,
            vec![0x00],
            vec![0x90],
            PatchKind::Nop,
        ));
        ids.push(id);
    }
    assert_eq!(ps.len(), 20);
    for id in ids {
        assert!(ps.remove(id).is_some());
    }
    assert_eq!(ps.len(), 0);
}

#[test]
fn comment_store_multiple_per_address() {
    let mut cs = CommentStore::new();
    let id1 = cs.add_text(0x100u64, "first");
    let id2 = cs.add_text(0x100u64, "second");
    assert_ne!(id1, id2);
    assert_eq!(cs.at(0x100).len(), 2);
    cs.remove(id1);
    assert_eq!(cs.at(0x100).len(), 1);
}

#[test]
fn bookmark_set_with_color_roundtrip() {
    let mut bs = BookmarkSet::new();
    let id = bs.insert(Bookmark::new(0xC0DE_u64, "x").with_color(BookmarkColor::Red));
    assert_eq!(bs.len(), 1);
    let found = bs.at(0xC0DE);
    assert_eq!(found[0].1.label, "x");
    bs.remove(id);
    assert!(bs.is_empty());
}

// ───────────────────────── Errors ─────────────────────────

#[test]
fn core_error_is_io_and_transient() {
    assert!(CoreError::io("x").is_io());
    assert!(!CoreError::io("x").is_transient());
    assert!(CoreError::Timeout { millis: 10 }.is_transient());
    assert!(CoreError::Cancelled { reason: "user".into() }.is_transient());
}

#[test]
fn result_attach_context() {
    use rustre_core::errors::ResultExt;
    let r: rustre_core::errors::Result<i32> = Err(CoreError::io("x"));
    let e = r.attach_context("loading").unwrap_err();
    assert_eq!(e.context, "loading");
}

#[test]
fn core_error_display_nonempty() {
    let s = CoreError::Truncated { expected: 10, got: 3 }.to_string();
    assert!(s.contains("10"));
    assert!(s.contains('3'));
}

// ───────────────────────── Mode / DisasmStyle ─────────────────────────

#[test]
fn mode_pointer_sizes_consistent() {
    assert_eq!(Mode::X86_64.pointer_size(), 8);
    assert_eq!(Mode::Aarch64.pointer_size(), 8);
    assert_eq!(Mode::Arm32.pointer_size(), 4);
    assert_eq!(Mode::X86_32.pointer_size(), 4);
    assert_eq!(Mode::X86_16.pointer_size(), 2);
}

#[test]
fn mode_display_distinct() {
    use std::collections::HashSet;
    let names: HashSet<String> = [
        Mode::X86_16, Mode::X86_32, Mode::X86_64,
        Mode::Arm32, Mode::Thumb, Mode::Aarch64,
    ].iter().map(std::string::ToString::to_string).collect();
    assert_eq!(names.len(), 6);
}

#[test]
fn disasm_style_variants() {
    let intel = DisasmStyle::default();
    let att = DisasmStyle::at_t();
    assert_eq!(intel.syntax_flavor, SyntaxFlavor::Intel);
    assert_eq!(att.syntax_flavor, SyntaxFlavor::AtT);
    assert_eq!(intel.mnemonic_case, MnemonicCase::Lower);
}

// ───────────────────────── FileOffset ─────────────────────────

#[test]
fn file_offset_checked_add_overflow() {
    assert_eq!(FileOffset::new(u64::MAX).checked_add(1), None);
    assert_eq!(FileOffset::new(10).checked_add(5).unwrap().as_u64(), 15);
}

#[test]
fn file_offset_range_contains_boundaries() {
    let r = FileOffsetRange::new(FileOffset::new(10), FileOffset::new(20));
    assert!(r.contains(FileOffset::new(10)));
    assert!(!r.contains(FileOffset::new(20)));
    assert!(!r.contains(FileOffset::new(9)));
    assert_eq!(r.len(), 10);
}

// ───────────────────────── AddressSpace ─────────────────────────

#[test]
fn address_space_lookup_after_many_inserts() {
    let mut sp: AddressSpace<u32> = AddressSpace::new();
    for i in 0..30u32 {
        sp.insert(
            AddressRange::new(
                Address::new(u64::from(i) * 0x100),
                Address::new(u64::from(i) * 0x100 + 0x100),
            ),
            i,
        );
    }
    assert_eq!(sp.len(), 30);
    let found = sp.find(Address::new(0x1500)).unwrap();
    assert_eq!(found.meta, 0x15);
    assert!(sp.find(Address::new(0x10_0000)).is_none());
}

#[test]
fn address_space_remove_returns_correct_entry() {
    let mut sp: AddressSpace<&'static str> = AddressSpace::new();
    sp.insert(
        AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        "first",
    );
    sp.insert(
        AddressRange::new(Address::new(0x2000), Address::new(0x3000)),
        "second",
    );
    let removed = sp.remove_containing(Address::new(0x2500)).unwrap();
    assert_eq!(removed.meta, "second");
    assert_eq!(sp.len(), 1);
}
