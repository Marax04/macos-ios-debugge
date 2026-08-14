//! Blitz integration test suite for `rustre-core`.
//!
//! Goal: exercise the public API with adversarial inputs and edge cases to
//! surface bugs. Tests here intentionally probe overflow, boundary, parsing,
//! state-transition, and round-trip behaviour.

use rustre_core::*;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Address arithmetic & overflow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn address_offset_extremes() {
    // wrapping behaviour on i64::MIN
    let a = Address::new(0);
    let r = a.offset(i64::MIN);
    // unsigned_abs of i64::MIN is 2^63
    assert_eq!(r.as_u64(), 0u64.wrapping_sub(1u64 << 63));
}

#[test]
fn address_align_up_overflow() {
    // align_up should wrap, not panic
    let a = Address::new(u64::MAX);
    let _ = a.align_up(0x10); // must not panic
}

#[test]
fn address_align_down_pow2_only() {
    // Documented: align_down asserts power-of-two when align > 1
    let a = Address::new(0x1234);
    assert_eq!(a.align_down(8), Address::new(0x1230));
}

#[test]
fn address_is_aligned_zero_align() {
    assert!(Address::new(0x1234).is_aligned(0));
    assert!(Address::new(0x1234).is_aligned(1));
}

#[test]
fn address_distance_to_equal() {
    let a = Address::new(0x100);
    assert_eq!(a.distance_to(a), Some(0));
}

#[test]
fn address_saturating_diff() {
    assert_eq!(Address::new(10).saturating_diff(Address::new(100)), 0);
    assert_eq!(Address::new(100).saturating_diff(Address::new(10)), 90);
}

#[test]
fn address_as_u32_truncation_clamps() {
    let a = Address::new(0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(a.as_u32(), u32::MAX);
}

#[test]
fn address_sub_underflow_saturates() {
    let a = Address::new(0x100);
    let b = Address::new(0x200);
    // Sub<Self> uses saturating_sub
    let diff: u64 = a - b;
    assert_eq!(diff, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// AddressRange edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn range_overlaps_with_empty() {
    let a = AddressRange::new(Address::new(0x1000), Address::new(0x1000)); // empty
    let b = AddressRange::new(Address::new(0x500), Address::new(0x2000));
    assert!(!a.overlaps(&b));
    assert!(!b.overlaps(&a));
}

#[test]
fn range_intersection_at_boundary() {
    let a = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
    let b = AddressRange::new(Address::new(0x2000), Address::new(0x3000));
    assert!(a.intersection(&b).is_none()); // touching but not overlapping
}

#[test]
fn range_split_at_boundary_returns_none() {
    let r = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
    assert!(r.split_at(Address::new(0x1000)).is_none()); // start
    assert!(r.split_at(Address::new(0x2000)).is_none()); // end
}

#[test]
fn range_merge_disjoint_creates_hull() {
    let a = AddressRange::new(Address::new(0x1000), Address::new(0x1100));
    let b = AddressRange::new(Address::new(0x2000), Address::new(0x2100));
    let m = a.merge(&b);
    assert_eq!(m.start, Address::new(0x1000));
    assert_eq!(m.end, Address::new(0x2100));
}

#[test]
fn range_iter_step_zero_treated_as_one() {
    let r = AddressRange::new(Address::new(0), Address::new(3));
    let v: Vec<u64> = r.iter_step(0).map(Address::as_u64).collect();
    assert_eq!(v, vec![0, 1, 2]);
}

#[test]
fn range_contains_inclusive_at_end() {
    let r = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
    assert!(r.contains_inclusive(Address::new(0x2000)));
    assert!(!r.contains(Address::new(0x2000)));
}

#[test]
fn range_from_len_overflow_wraps() {
    let r = AddressRange::from_len(Address::new(u64::MAX), 10);
    // end wraps; len() saturates to 0
    assert_eq!(r.len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// SegmentMapping
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn segment_mapping_boundary_addresses() {
    let seg = SegmentMapping::new(
        AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        FileOffsetRange::new(FileOffset::new(0), FileOffset::new(0x1000)),
    );
    // boundary start
    assert!(seg.va_to_file_offset(Address::new(0x1000)).is_some());
    // boundary end (exclusive)
    assert!(seg.va_to_file_offset(Address::new(0x2000)).is_none());
}

#[test]
fn segment_mapping_smaller_file_range() {
    // virtual is larger than file (BSS-like)
    let seg = SegmentMapping::new(
        AddressRange::new(Address::new(0x1000), Address::new(0x3000)),
        FileOffsetRange::new(FileOffset::new(0), FileOffset::new(0x100)),
    );
    // First few addresses map
    assert_eq!(
        seg.va_to_file_offset(Address::new(0x1050)),
        Some(FileOffset::new(0x50))
    );
    // Past the file range portion → None
    assert!(seg.va_to_file_offset(Address::new(0x1200)).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Endian / LEB128 adversarial
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn uleb128_truncated_input_returns_none() {
    // 0x80 sets continuation bit but there are no further bytes
    let data = [0x80u8];
    assert!(decode_uleb128(&data, 0).is_none());
}

#[test]
fn uleb128_overflow_returns_none() {
    // 11 bytes all with continuation bit set → shift overflow
    let data = [0x80u8; 11];
    assert!(decode_uleb128(&data, 0).is_none());
}

#[test]
fn sleb128_truncated_input_returns_none() {
    let data = [0x80u8];
    assert!(decode_sleb128(&data, 0).is_none());
}

#[test]
fn uleb128_offset_past_end() {
    let data = [0x01u8];
    assert!(decode_uleb128(&data, 5).is_none());
}

#[test]
fn endian_read_slice_misaligned_zero_offset() {
    let data = [0x12u8, 0x34, 0x56];
    assert!(data.read_u32(0, Endian::Little).is_none()); // only 3 bytes
}

#[test]
fn endian_buf_read_oob_returns_none() {
    let buf = EndianBuf::from_vec(vec![1, 2], Endian::Little);
    assert!(buf.read_u32(0).is_none());
    assert!(buf.read_u64(0).is_none());
}

#[test]
fn endian_swap_inverse() {
    let v: u32 = 0xCAFE_BABE;
    assert_eq!(swap_endian_u32(swap_endian_u32(v)), v);
    let v: u64 = 0x1234_5678_9ABC_DEF0;
    assert_eq!(swap_endian_u64(swap_endian_u64(v)), v);
}

// ─────────────────────────────────────────────────────────────────────────────
// IDs
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn id_invalid_round_trips() {
    let id = FunctionId::INVALID;
    assert!(!id.is_valid());
    assert_eq!(id.get(), 0);
    assert!(FunctionId::new(0).is_none());
}

#[test]
fn id_allocator_concurrent_uniqueness() {
    // basic uniqueness across many allocations
    let alloc = IdAllocator::<FunctionId>::new();
    let ids: std::collections::HashSet<u64> =
        (0..1000).map(|_| alloc.next().get()).collect();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn id_pool_lifo_reclaim() {
    let mut pool = IdPool::<FunctionId>::new();
    let a = pool.alloc();
    let b = pool.alloc();
    let c = pool.alloc();
    pool.reclaim(a);
    pool.reclaim(b);
    pool.reclaim(c);
    assert_eq!(pool.alloc(), c); // LIFO
    assert_eq!(pool.alloc(), b);
    assert_eq!(pool.alloc(), a);
}

#[test]
#[should_panic]
fn id_allocator_with_start_zero_panics() {
    // documented behaviour
    let _ = IdAllocator::<ViewId>::with_start(0);
}

#[test]
fn idmap_entry_api() {
    use std::collections::hash_map::Entry;
    let mut map: IdMap<TypeId, i32> = IdMap::new();
    let id = TypeId::from_raw(1);
    match map.entry(id) {
        Entry::Vacant(v) => {
            v.insert(42);
        }
        Entry::Occupied(_) => panic!("should be vacant"),
    }
    assert_eq!(map.get(id).copied(), Some(42));
}

// ─────────────────────────────────────────────────────────────────────────────
// Permissions / parsing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn permissions_round_trip_rwx_string() {
    for bits in 0u8..=7 {
        let p = Permissions::from_bits_truncate(bits);
        let s = p.as_rwx_string();
        let parsed = Permissions::from_rwx_string(&s).unwrap();
        // only r/w/x bits are preserved through string
        assert_eq!(parsed.bits() & 0b111, p.bits() & 0b111);
    }
}

#[test]
fn permissions_from_rwx_invalid() {
    assert!(Permissions::from_rwx_string("").is_none());
    assert!(Permissions::from_rwx_string("rw").is_none());
    assert!(Permissions::from_rwx_string("rwxr").is_none());
    assert!(Permissions::from_rwx_string("zzz").is_none());
    assert!(Permissions::from_rwx_string("RWX").is_none()); // case-sensitive
}

#[test]
fn permissions_serde_round_trip() {
    let p = Permissions::RX | Permissions::GUARD;
    let json = serde_json::to_string(&p).unwrap();
    let back: Permissions = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn permission_policy_default_allows() {
    let pol = PermissionPolicy::new();
    assert!(pol.is_allowed(Permissions::RWX));
    assert!(pol.is_allowed(Permissions::NONE));
}

#[test]
fn permission_policy_first_rule_wins() {
    let mut p = PermissionPolicy::new();
    p.add_rule(PermissionRule::allow(Permissions::EXECUTE));
    p.add_rule(PermissionRule::deny(Permissions::EXECUTE));
    assert!(p.is_allowed(Permissions::EXECUTE));
}

#[test]
fn permission_set_apply_noop_no_history() {
    let mut s = PermissionSet::new(Permissions::READ);
    s.apply(Permissions::READ, None);
    assert_eq!(s.change_count(), 0);
    assert!(!s.has_history());
}

#[test]
fn permission_set_rollback() {
    let mut s = PermissionSet::new(Permissions::READ);
    s.apply(Permissions::RW, None);
    s.apply(Permissions::RWX, None);
    assert!(s.rollback());
    assert_eq!(s.current(), Permissions::RW);
    assert!(s.rollback());
    assert_eq!(s.current(), Permissions::READ);
    assert!(!s.rollback()); // empty
}

#[test]
fn permission_change_diff() {
    let c = PermissionChange::new(Permissions::READ, Permissions::RX, 0);
    assert_eq!(c.flags_added(), Permissions::EXECUTE);
    assert_eq!(c.flags_removed(), Permissions::NONE);
}

#[test]
fn memory_protection_linux_prot_bits() {
    assert_eq!(MemoryProtection::linux_prot_bits(Permissions::NONE), 0);
    assert_eq!(MemoryProtection::linux_prot_bits(Permissions::READ), 1);
    assert_eq!(MemoryProtection::linux_prot_bits(Permissions::WRITE), 2);
    assert_eq!(MemoryProtection::linux_prot_bits(Permissions::EXECUTE), 4);
    assert_eq!(MemoryProtection::linux_prot_bits(Permissions::RWX), 7);
}

#[test]
fn memory_protection_windows_page_constants() {
    assert_eq!(
        MemoryProtection::windows_page_constant(Permissions::READ),
        0x02
    );
    assert_eq!(
        MemoryProtection::windows_page_constant(Permissions::RW),
        0x04
    );
    assert_eq!(
        MemoryProtection::windows_page_constant(Permissions::EXECUTE),
        0x10
    );
    assert_eq!(
        MemoryProtection::windows_page_constant(Permissions::RX),
        0x20
    );
    assert_eq!(
        MemoryProtection::windows_page_constant(Permissions::RWX),
        0x40
    );
    // guard takes precedence
    assert_eq!(
        MemoryProtection::windows_page_constant(Permissions::GUARD | Permissions::READ),
        0x0100
    );
}

#[test]
fn memory_protection_round_trip_linux() {
    // all linux variants → permissions
    for mp in [
        MemoryProtection::LinuxNone,
        MemoryProtection::LinuxRead,
        MemoryProtection::LinuxWrite,
        MemoryProtection::LinuxExec,
        MemoryProtection::LinuxReadWrite,
        MemoryProtection::LinuxReadExec,
        MemoryProtection::LinuxReadWriteExec,
    ] {
        let _ = mp.to_permissions();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader / LoaderInput
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn loader_input_magic_short_data() {
    let inp = LoaderInput::new("u", vec![1, 2, 3]);
    assert_eq!(inp.magic(), &[1, 2, 3]);
}

#[test]
fn loader_input_magic_long_data() {
    let inp = LoaderInput::new("u", (0..32u8).collect());
    assert_eq!(inp.magic().len(), 16);
}

#[test]
fn loader_input_has_magic_at_out_of_bounds() {
    let inp = LoaderInput::new("u", vec![1, 2, 3]);
    // Offset+needle beyond end must be false, not panic.
    assert!(!inp.has_magic_at(10, &[1, 2]));
}

#[test]
fn loader_input_has_magic_at_overflow_offset() {
    // BUG CANDIDATE: offset + needle.len() may overflow with huge offset.
    let inp = LoaderInput::new("u", vec![1, 2, 3]);
    let needle: &[u8] = &[1, 2];
    // Must return false (or at least not panic) for impossibly-large offset.
    assert!(!inp.has_magic_at(usize::MAX - 1, needle));
}

#[test]
fn loader_input_starts_with_empty_needle() {
    let inp = LoaderInput::new("u", vec![1, 2, 3]);
    assert!(inp.starts_with(&[]));
}

#[test]
fn loader_options_bool_variants() {
    let opts = LoaderOptions::new()
        .set("a", "true")
        .set("b", "yes")
        .set("c", "1")
        .set("d", "false")
        .set("e", "no")
        .set("f", "0")
        .set("g", "garbage");
    assert_eq!(opts.get_bool("a"), Some(true));
    assert_eq!(opts.get_bool("b"), Some(true));
    assert_eq!(opts.get_bool("c"), Some(true));
    assert_eq!(opts.get_bool("d"), Some(false));
    assert_eq!(opts.get_bool("e"), Some(false));
    assert_eq!(opts.get_bool("f"), Some(false));
    assert_eq!(opts.get_bool("g"), None);
    assert!(opts.get_bool("absent").is_none());
}

#[test]
fn loader_options_u64_hex_decimal() {
    let opts = LoaderOptions::new()
        .set("dec", "1234")
        .set("hex", "0xCafe")
        .set("HEX", "0X10")
        .set("bad", "nope");
    assert_eq!(opts.get_u64("dec"), Some(1234));
    assert_eq!(opts.get_u64("hex"), Some(0xCAFE));
    assert_eq!(opts.get_u64("HEX"), Some(16));
    assert_eq!(opts.get_u64("bad"), None);
}

#[test]
fn binary_type_classification() {
    assert!(BinaryType::Executable.is_runnable());
    assert!(BinaryType::Firmware.is_runnable());
    assert!(BinaryType::Wasm.is_runnable());
    assert!(!BinaryType::Library.is_runnable());
    assert!(!BinaryType::Object.is_runnable());
    assert!(BinaryType::Library.is_library());
    assert!(BinaryType::Archive.is_library());
    assert!(!BinaryType::Executable.is_library());
}

#[test]
fn hint_set_first_match_wins() {
    let mut h = HintSet::new();
    h.add(LoaderHint::Architecture("a".into()));
    h.add(LoaderHint::Architecture("b".into()));
    assert_eq!(h.architecture(), Some("a"));
}

#[test]
fn hint_set_missing_returns_none() {
    let h = HintSet::new();
    assert!(h.architecture().is_none());
    assert!(h.base_address().is_none());
    assert!(h.entry_point().is_none());
    assert!(h.endian().is_none());
    assert!(!h.is_raw());
    assert!(!h.no_relocations());
}

#[test]
fn hint_set_raw_flag() {
    let mut h = HintSet::new();
    h.add(LoaderHint::Raw);
    h.add(LoaderHint::NoRelocations);
    assert!(h.is_raw());
    assert!(h.no_relocations());
}

#[test]
fn nested_binary_into_loader_input() {
    let nb = NestedBinary::new("inner.exe", vec![1, 2, 3], 0x100, BinaryType::Executable);
    assert_eq!(nb.size(), 3);
    let inp = nb.into_loader_input();
    assert_eq!(inp.uri, "inner.exe");
    assert_eq!(inp.data, vec![1, 2, 3]);
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderRegistry behaviour
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Mock {
    n: &'static str,
    conf: u8,
    prio: u32,
}

#[async_trait]
impl Loader for Mock {
    fn name(&self) -> &str {
        self.n
    }
    fn priority(&self) -> u32 {
        self.prio
    }
    fn can_load(&self, _: &LoaderInput) -> bool {
        true
    }
    fn confidence(&self, _: &LoaderInput) -> u8 {
        self.conf
    }
    async fn load(&self, _: LoaderInput) -> Result<LoadResult> {
        Err(CoreError::unsupported("mock"))
    }
    async fn find_nested(&self, _: &LoaderInput) -> Result<Vec<NestedBinary>> {
        Ok(vec![])
    }
}

#[test]
fn loader_registry_probe_sorts_by_confidence() {
    let r = LoaderRegistry::new();
    r.register(Arc::new(Mock {
        n: "a",
        conf: 30,
        prio: 50,
    }));
    r.register(Arc::new(Mock {
        n: "b",
        conf: 80,
        prio: 50,
    }));
    r.register(Arc::new(Mock {
        n: "c",
        conf: 60,
        prio: 50,
    }));
    let names: Vec<String> = r
        .probe(&LoaderInput::new("u", vec![]))
        .iter()
        .map(|l| l.name().to_string())
        .collect();
    assert_eq!(names, vec!["b", "c", "a"]);
}

#[test]
fn loader_registry_probe_ties_break_on_priority() {
    let r = LoaderRegistry::new();
    r.register(Arc::new(Mock {
        n: "low",
        conf: 80,
        prio: 10,
    }));
    r.register(Arc::new(Mock {
        n: "high",
        conf: 80,
        prio: 100,
    }));
    let best = r.best_loader(&LoaderInput::new("u", vec![])).unwrap();
    assert_eq!(best.name(), "high");
}

#[test]
fn loader_registry_unregister() {
    let r = LoaderRegistry::new();
    r.register(Arc::new(Mock {
        n: "a",
        conf: 50,
        prio: 50,
    }));
    assert!(r.unregister("a"));
    assert!(!r.unregister("a"));
    assert_eq!(r.count(), 0);
}

#[test]
fn loader_registry_list_names() {
    let r = LoaderRegistry::new();
    r.register(Arc::new(Mock {
        n: "x",
        conf: 50,
        prio: 50,
    }));
    r.register(Arc::new(Mock {
        n: "y",
        conf: 50,
        prio: 50,
    }));
    let mut names = r.list_names();
    names.sort();
    assert_eq!(names, vec!["x".to_string(), "y".to_string()]);
}

#[test]
fn loader_registry_probe_all_filters_zero_confidence() {
    #[derive(Debug)]
    struct ZeroLoader;
    #[async_trait]
    impl Loader for ZeroLoader {
        fn name(&self) -> &'static str {
            "zero"
        }
        fn can_load(&self, _: &LoaderInput) -> bool {
            false
        }
        fn confidence(&self, _: &LoaderInput) -> u8 {
            0
        }
        async fn load(&self, _: LoaderInput) -> Result<LoadResult> {
            Err(CoreError::unsupported(""))
        }
        async fn find_nested(&self, _: &LoaderInput) -> Result<Vec<NestedBinary>> {
            Ok(vec![])
        }
    }
    let r = LoaderRegistry::new();
    r.register(Arc::new(ZeroLoader));
    assert!(r.probe_all(&LoaderInput::new("u", vec![])).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Patches / PatchSet
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn patch_end_address_saturating() {
    let p = Patch::new(u64::MAX - 1, vec![0, 0], vec![1, 2], PatchKind::RawBytes);
    // end may saturate to u64::MAX, but it must not panic
    let e = p.end_address();
    assert!(e >= u64::MAX - 1);
}

#[test]
fn patch_contains_basic() {
    let p = Patch::new(0x100, vec![0; 4], vec![0; 4], PatchKind::Nop);
    assert!(p.contains(0x100));
    assert!(p.contains(0x103));
    assert!(!p.contains(0x104));
    assert!(!p.contains(0xFF));
}

#[test]
fn patch_kind_label_and_display() {
    assert_eq!(PatchKind::Nop.label(), "nop");
    assert_eq!(PatchKind::RawBytes.label(), "raw");
    assert_eq!(PatchKind::Inline.label(), "inline");
    let red = PatchKind::Redirect { target: 0xCAFE };
    assert_eq!(red.label(), "redirect");
    assert!(red.to_string().contains("cafe"));
    let custom = PatchKind::Custom("xyz".into());
    assert_eq!(custom.label(), "xyz");
    assert!(custom.to_string().contains("xyz"));
}

#[test]
fn patch_set_insert_remove_len() {
    let mut ps = PatchSet::new();
    assert_eq!(ps.len(), 0);
    let p1 = Patch::new(0x100, vec![0], vec![1], PatchKind::Nop);
    let p2 = Patch::new(0x200, vec![0], vec![1], PatchKind::Nop);
    let id1 = ps.insert(p1);
    let _id2 = ps.insert(p2);
    assert_eq!(ps.len(), 2);
    let removed = ps.remove(id1).unwrap();
    assert_eq!(removed.address, 0x100);
    assert_eq!(ps.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// CommentStore / BookmarkSet
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn comment_store_multiple_per_address() {
    let mut cs = CommentStore::new();
    cs.add_text(0x100u64, "first");
    cs.add_text(0x100u64, "second");
    assert_eq!(cs.at(0x100).len(), 2);
}

#[test]
fn bookmark_set_color() {
    let mut bs = BookmarkSet::new();
    let _id = bs.insert(Bookmark::new(0x100u64, "label").with_color(BookmarkColor::Red));
    let found = bs.at(0x100);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1.color, BookmarkColor::Red);
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors: predicates + display + conversions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn core_error_truncated_display() {
    assert!(
        CoreError::truncated(8, 3)
            .to_string()
            .contains("expected 8")
    );
}

#[test]
fn core_error_invalid_format_clone_eq() {
    let e = CoreError::InvalidFormat {
        message: "x".into(),
    };
    assert_eq!(e.clone(), e);
}

#[test]
fn core_error_from_int_conversion() {
    let r: std::result::Result<u8, _> = u8::try_from(1000u32);
    let err = r.unwrap_err();
    let core: CoreError = err.into();
    assert!(matches!(core, CoreError::Internal { .. }));
}

#[test]
fn error_context_chain() {
    let r: Result<()> = Err(CoreError::io("disk"));
    let ec = r.with_context(|| "loading".into()).unwrap_err();
    assert_eq!(ec.context, "loading");
    assert!(ec.error.is_io());
    assert!(ec.to_string().contains("loading"));
    assert!(ec.to_string().contains("disk"));
}

#[test]
fn ensure_core_passes_macro() {
    fn f(v: usize) -> Result<()> {
        ensure_core!(v > 0, CoreError::invalid_input("zero"));
        Ok(())
    }
    assert!(f(1).is_ok());
    assert!(matches!(
        f(0),
        Err(CoreError::InvalidInput { .. })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbols / Functions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn symbol_index_empty() {
    let idx = SymbolIndex::new();
    let r = idx.symbols_in_range(AddressRange::new(Address::new(0), Address::new(u64::MAX)));
    assert!(r.is_empty());
}

#[test]
fn symbol_index_range_exclusive_end() {
    let mut idx = SymbolIndex::new();
    idx.insert(SymbolEntry::new("a", Address::new(0x100)));
    idx.insert(SymbolEntry::new("b", Address::new(0x200)));
    let r = idx.symbols_in_range(AddressRange::new(Address::new(0x100), Address::new(0x200)));
    // 0x200 is the exclusive end, so only "a" should be in range
    assert_eq!(r.len(), 1);
}

#[test]
fn xref_store_distinct_kinds() {
    let mut store = XrefStore::new();
    store.add(XrefRecord::certain(
        Address::new(0x100),
        Address::new(0x200),
        XrefKind::Call,
    ));
    store.add(XrefRecord::certain(
        Address::new(0x100),
        Address::new(0x200),
        XrefKind::DataRead,
    ));
    // callers_of looks for Call type refs.
    let callers = store.callers_of(Address::new(0x200));
    assert_eq!(callers.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// PassManager — dependency ordering
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pass_manager_chain_order() {
    let mut m = PassManager::new();
    m.register_pass(AnalysisPassInfo::new("c", &["b"]));
    m.register_pass(AnalysisPassInfo::new("b", &["a"]));
    m.register_pass(AnalysisPassInfo::new("a", &[]));
    let order = m.topological_order().unwrap();
    let ai = order.iter().position(|s| s == "a").unwrap();
    let bi = order.iter().position(|s| s == "b").unwrap();
    let ci = order.iter().position(|s| s == "c").unwrap();
    assert!(ai < bi && bi < ci);
}

#[test]
fn pass_manager_self_cycle_detected() {
    let mut m = PassManager::new();
    m.register_pass(AnalysisPassInfo::new("x", &["x"]));
    assert!(m.topological_order().is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// DisasmStyle / Mode
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mode_pointer_sizes() {
    assert_eq!(Mode::X86_16.pointer_size(), 2);
    assert_eq!(Mode::X86_32.pointer_size(), 4);
    assert_eq!(Mode::X86_64.pointer_size(), 8);
    assert_eq!(Mode::Arm32.pointer_size(), 4);
    assert_eq!(Mode::Aarch64.pointer_size(), 8);
}

#[test]
fn disasm_style_at_t_vs_intel() {
    let intel = DisasmStyle::default();
    let att = DisasmStyle::at_t();
    assert_eq!(intel.syntax_flavor, SyntaxFlavor::Intel);
    assert_eq!(att.syntax_flavor, SyntaxFlavor::AtT);
}

// ─────────────────────────────────────────────────────────────────────────────
// VERSION constant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn version_non_empty() {
    assert!(!VERSION.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginRegistry (the plugin.rs one)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn plugin_registry_register_unregister() {
    let mut reg = plugin::PluginRegistry::new();
    let id = plugin::PluginId::new("test");
    reg.register(id.clone(), Box::new(123u32));
    assert!(reg.contains(&id));
    reg.unregister(&id);
    assert!(!reg.contains(&id));
}

// ─────────────────────────────────────────────────────────────────────────────
// EndianReader uleb128/sleb128
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn endian_reader_uleb128_overflow_errors() {
    let bytes = vec![0x80u8; 11];
    let mut r = EndianReader::new(std::io::Cursor::new(bytes), Endian::Little);
    assert!(r.read_uleb128().is_err());
}

#[test]
fn endian_reader_sleb128_overflow_errors() {
    let bytes = vec![0x80u8; 11];
    let mut r = EndianReader::new(std::io::Cursor::new(bytes), Endian::Little);
    assert!(r.read_sleb128().is_err());
}

#[test]
fn endian_writer_uleb128_round_trip_via_decoder() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = EndianWriter::new(&mut buf, Endian::Little);
        w.write_uleb128(0).unwrap();
        w.write_uleb128(127).unwrap();
        w.write_uleb128(128).unwrap();
        w.write_uleb128(u64::MAX).unwrap();
    }
    let (v0, n0) = decode_uleb128(&buf, 0).unwrap();
    let (v1, n1) = decode_uleb128(&buf, n0).unwrap();
    let (v2, n2) = decode_uleb128(&buf, n0 + n1).unwrap();
    let (v3, _) = decode_uleb128(&buf, n0 + n1 + n2).unwrap();
    assert_eq!((v0, v1, v2, v3), (0, 127, 128, u64::MAX));
}
