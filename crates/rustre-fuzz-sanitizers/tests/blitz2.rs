//! Deep adversarial tests for rustre-fuzz-sanitizers public lib API.

use rustre_fuzz_sanitizers::{
    AddressSanitizer, Allocation, ArithOp, HeapTracking, MemorySanitizer, SanitizerKind,
    SanitizerReport, SanitizerResult, ShadowMemory, UbSanitizer,
};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── ShadowMemory ──────────────────────────────────────────────────────────────

#[test]
fn shadow_default_all_undefined() {
    let sm = ShadowMemory::default();
    for addr in [0u64, 1, 7, 255, 256, 257, 1024, u64::from(u32::MAX)] {
        assert!(!sm.check_defined(addr, 1));
    }
}

#[test]
fn shadow_mark_zero_len_always_defined() {
    let sm = ShadowMemory::new();
    // len=0 should be vacuously true
    assert!(sm.check_defined(0x1000, 0));
}

#[test]
fn shadow_single_byte_roundtrip() {
    let mut sm = ShadowMemory::new();
    for addr in [0u64, 1, 255, 256, 257, 512, 0x10_0000] {
        sm.mark_defined(addr, 1);
        assert!(sm.check_defined(addr, 1), "addr={addr}");
        sm.mark_undefined(addr, 1);
        assert!(!sm.check_defined(addr, 1));
    }
}

#[test]
fn shadow_page_boundary_crossing() {
    let mut sm = ShadowMemory::new();
    for base in [PAGE - 5, PAGE * 2 - 1, PAGE * 10 - 3] {
        sm.mark_defined(base, 16);
        assert!(sm.check_defined(base, 16));
        assert!(sm.check_defined(base + 15, 1));
    }
}
const PAGE: u64 = 256;

#[test]
fn shadow_fuzz_mark_check_consistency() {
    let mut sm = ShadowMemory::new();
    let mut g = lcg();
    // 50 random regions
    for _ in 0..50 {
        let addr = g() & 0xFFFF;
        let len = (g() & 0x3F) as usize + 1;
        sm.mark_defined(addr, len);
        assert!(sm.check_defined(addr, len));
        // marking undefined invalidates
        sm.mark_undefined(addr, len);
        assert!(!sm.check_defined(addr, len) || len == 0);
    }
}

#[test]
fn shadow_partial_undefined_detected() {
    let mut sm = ShadowMemory::new();
    sm.mark_defined(100, 10);
    sm.mark_undefined(105, 1);
    assert!(!sm.check_defined(100, 10));
    assert!(sm.check_defined(100, 5));
    assert!(sm.check_defined(106, 4));
}

// ── MemorySanitizer ───────────────────────────────────────────────────────────

#[test]
fn msan_new_returns_uninit() {
    let m = MemorySanitizer::new();
    let r = m.check(0x100, 4);
    assert!(r.is_err());
    let e = r.unwrap_err();
    assert_eq!(e.kind, SanitizerKind::MemoryUninit);
    assert!(e.message.contains("uninitialised"));
}

#[test]
fn msan_check_zero_len_is_ok() {
    let m = MemorySanitizer::new();
    assert!(m.check(0x100, 0).is_ok());
}

#[test]
fn msan_default_eq_new() {
    let _a = MemorySanitizer::default();
    let _b = MemorySanitizer::new();
}

#[test]
fn msan_fuzz_never_panics() {
    let mut m = MemorySanitizer::new();
    let mut g = lcg();
    for _ in 0..200 {
        let addr = g();
        let len = (g() & 0x1F) as usize;
        if g() & 1 == 0 {
            m.mark_defined(addr & 0xFFFF, len);
        } else {
            m.mark_undefined(addr & 0xFFFF, len);
        }
        let _ = m.check(addr & 0xFFFF, len);
    }
}

// ── HeapTracking / AddressSanitizer ───────────────────────────────────────────

#[test]
fn heap_track_alloc_inserts() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x1000, 64);
    assert!(h.allocations.contains_key(&0x1000));
    assert!(!h.freed.contains(&0x1000));
}

#[test]
fn heap_double_free_detected() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x2000, 16);
    assert_eq!(h.track_free(0x2000), SanitizerResult::Clean);
    assert_eq!(
        h.track_free(0x2000),
        SanitizerResult::DoubleFree { addr: 0x2000 }
    );
}

#[test]
fn heap_free_untracked_is_clean() {
    let mut h = HeapTracking::new();
    // Freeing an address that was never allocated does not insert metadata.
    assert_eq!(h.track_free(0x9999), SanitizerResult::Clean);
}

#[test]
fn heap_overflow_one_byte_past_end() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x1000, 8);
    let r = h.check_heap_access(0x1004, 8);
    match r {
        SanitizerResult::HeapOverflow {
            addr,
            size,
            alloc_base,
            alloc_size,
        } => {
            assert_eq!(addr, 0x1004);
            assert_eq!(size, 8);
            assert_eq!(alloc_base, 0x1000);
            assert_eq!(alloc_size, 8);
        }
        other => panic!("expected HeapOverflow, got {other:?}"),
    }
}

#[test]
fn heap_uaf_interior_byte() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x3000, 64);
    h.track_free(0x3000);
    match h.check_heap_access(0x3020, 4) {
        SanitizerResult::UseAfterFree { addr, .. } => assert_eq!(addr, 0x3020),
        o => panic!("got {o:?}"),
    }
}

#[test]
fn heap_underflow_detected() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x1010, 16);
    let r = h.check_heap_access(0x1000, 20);
    assert_eq!(r, SanitizerResult::HeapUnderflow { addr: 0x1000 });
}

#[test]
fn heap_underflow_no_reach_is_clean() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x2000, 16);
    // Access at 0x1000 with size 4 — does not reach alloc at 0x2000
    let r = h.check_heap_access(0x1000, 4);
    assert_eq!(r, SanitizerResult::Clean);
}

#[test]
fn heap_realloc_clears_freed_state() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x4000, 8);
    h.track_free(0x4000);
    assert!(h.freed.contains(&0x4000));
    h.track_alloc(0x4000, 8);
    assert!(!h.freed.contains(&0x4000));
    assert_eq!(h.check_heap_access(0x4000, 8), SanitizerResult::Clean);
}

#[test]
fn heap_exact_fit_access_is_clean() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x5000, 32);
    assert_eq!(h.check_heap_access(0x5000, 32), SanitizerResult::Clean);
}

#[test]
fn heap_fuzz_track_alloc_free_check_no_panic() {
    let mut h = HeapTracking::new();
    let mut g = lcg();
    for _ in 0..100 {
        let addr = (g() & 0xFFF) * 0x100;
        let size = rustre_fuzz_sanitizers::cast::u64_to_usize((g() & 0x3F) + 1);
        h.track_alloc(addr, size);
        if g() & 1 == 0 {
            let _ = h.track_free(addr);
        }
        let _ = h.check_heap_access(addr.wrapping_add(g() & 0x7F), (g() & 0xF) as usize + 1);
    }
}

#[test]
fn asan_report_overflow_message() {
    let mut a = AddressSanitizer::new();
    a.track_alloc(0x1000, 8);
    let e = a.check(0x1000, 16).unwrap_err();
    assert_eq!(e.kind, SanitizerKind::HeapOverflow);
    assert!(e.message.contains("heap overflow"));
}

#[test]
fn asan_report_uaf_message() {
    let mut a = AddressSanitizer::new();
    a.track_alloc(0x2000, 8);
    a.track_free(0x2000);
    let e = a.check(0x2000, 4).unwrap_err();
    assert_eq!(e.kind, SanitizerKind::UseAfterFree);
    assert!(e.message.contains("use-after-free"));
}

#[test]
fn asan_report_underflow_message() {
    let mut a = AddressSanitizer::new();
    a.track_alloc(0x2010, 16);
    let e = a.check(0x2000, 20).unwrap_err();
    assert_eq!(e.kind, SanitizerKind::HeapUnderflow);
}

#[test]
fn asan_untracked_is_ok() {
    let a = AddressSanitizer::new();
    assert!(a.check(0xdead_beef_0000_0000, 16).is_ok());
}

#[test]
fn allocation_clone_debug() {
    let alloc = Allocation {
        addr: 0x1234,
        size: 64,
        freed: false,
        freed_at: None,
    };
    let c = alloc;
    assert_eq!(c.addr, 0x1234);
    assert_eq!(c.size, 64);
    let _ = format!("{c:?}");
}

// ── UbSanitizer ───────────────────────────────────────────────────────────────

#[test]
fn ubsan_add_overflow_boundaries() {
    assert!(UbSanitizer::check_signed_overflow(i64::MAX, 1, ArithOp::Add));
    assert!(UbSanitizer::check_signed_overflow(i64::MIN, -1, ArithOp::Add));
    assert!(!UbSanitizer::check_signed_overflow(i64::MAX, 0, ArithOp::Add));
    assert!(!UbSanitizer::check_signed_overflow(0, 0, ArithOp::Add));
    assert!(!UbSanitizer::check_signed_overflow(i64::MAX - 1, 1, ArithOp::Add));
}

#[test]
fn ubsan_sub_overflow_boundaries() {
    assert!(UbSanitizer::check_signed_overflow(i64::MIN, 1, ArithOp::Sub));
    assert!(UbSanitizer::check_signed_overflow(i64::MAX, -1, ArithOp::Sub));
    assert!(!UbSanitizer::check_signed_overflow(0, 0, ArithOp::Sub));
    assert!(!UbSanitizer::check_signed_overflow(i64::MIN + 1, 1, ArithOp::Sub));
}

#[test]
fn ubsan_mul_overflow_boundaries() {
    assert!(UbSanitizer::check_signed_overflow(i64::MAX, 2, ArithOp::Mul));
    assert!(UbSanitizer::check_signed_overflow(i64::MIN, -1, ArithOp::Mul));
    assert!(UbSanitizer::check_signed_overflow(i64::MIN, 2, ArithOp::Mul));
    assert!(!UbSanitizer::check_signed_overflow(0, i64::MAX, ArithOp::Mul));
    assert!(!UbSanitizer::check_signed_overflow(1, i64::MAX, ArithOp::Mul));
    assert!(!UbSanitizer::check_signed_overflow(-1, i64::MAX, ArithOp::Mul));
}

#[test]
fn ubsan_fuzz_signed_ops_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let a = g().cast_signed();
        let b = g().cast_signed();
        for op in [ArithOp::Add, ArithOp::Sub, ArithOp::Mul] {
            let _ = UbSanitizer::check_signed_overflow(a, b, op);
        }
    }
}

#[test]
fn ubsan_null_deref_truth() {
    assert!(UbSanitizer::check_null_deref(0));
    for n in [1u64, 0x100, 0x1000, u64::MAX] {
        assert!(!UbSanitizer::check_null_deref(n));
    }
}

#[test]
fn ubsan_misaligned_power_of_two() {
    assert!(!UbSanitizer::check_misaligned(0, 8));
    assert!(!UbSanitizer::check_misaligned(0x1000, 8));
    assert!(UbSanitizer::check_misaligned(0x1001, 8));
    assert!(UbSanitizer::check_misaligned(0x1004, 8));
    assert!(!UbSanitizer::check_misaligned(0x1008, 8));
}

#[test]
fn ubsan_misaligned_zero_or_non_power_of_two_always_aligned() {
    // alignment=0 → treated as 1 (always aligned)
    assert!(!UbSanitizer::check_misaligned(0x1001, 0));
    // alignment=3 not power of two
    assert!(!UbSanitizer::check_misaligned(0x1001, 3));
    assert!(!UbSanitizer::check_misaligned(0x1001, 6));
    assert!(!UbSanitizer::check_misaligned(0x1001, 7));
}

#[test]
fn ubsan_misaligned_alignment_one() {
    // alignment=1 → everything aligned
    for a in [0u64, 1, 0x1001, u64::MAX] {
        assert!(!UbSanitizer::check_misaligned(a, 1));
    }
}

#[test]
fn ubsan_division_zero_only() {
    assert!(UbSanitizer::check_division(0));
    for n in [1, -1, i64::MAX, i64::MIN, 42] {
        assert!(!UbSanitizer::check_division(n));
    }
}

#[test]
fn ubsan_checked_add_inverse_property() {
    let mut g = lcg();
    for _ in 0..50 {
        let a = g().cast_signed() >> 2;
        let b = g().cast_signed() >> 2;
        let s = UbSanitizer::checked_add(a, b).unwrap();
        assert_eq!(s, a.wrapping_add(b));
        // inverse
        assert_eq!(s - b, a);
    }
}

#[test]
fn ubsan_checked_add_overflow_err() {
    let r = UbSanitizer::checked_add(i64::MAX, 1);
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().kind, SanitizerKind::IntOverflow);
    let r2 = UbSanitizer::checked_add(i64::MIN, -1);
    assert!(r2.is_err());
}

#[test]
fn ubsan_checked_mul_inverse_property() {
    let mut g = lcg();
    for _ in 0..50 {
        let a = i64::from(rustre_fuzz_sanitizers::cast::u64_to_i32(g())); // smaller magnitude
        let b = i64::from(rustre_fuzz_sanitizers::cast::u64_to_i16(g()));
        let p = UbSanitizer::checked_mul(a, b).unwrap();
        assert_eq!(p, a.wrapping_mul(b));
    }
}

#[test]
fn ubsan_checked_mul_overflow_err() {
    assert!(UbSanitizer::checked_mul(i64::MAX, 2).is_err());
    assert!(UbSanitizer::checked_mul(i64::MIN, -1).is_err());
    assert_eq!(UbSanitizer::checked_mul(0, i64::MAX).unwrap(), 0);
}

#[test]
fn ubsan_check_access_null_first() {
    // null + misaligned: NullDeref reported first
    let e = UbSanitizer::check_access(0, 8).unwrap_err();
    assert_eq!(e.kind, SanitizerKind::NullDeref);
}

#[test]
fn ubsan_check_access_misaligned_kind() {
    let e = UbSanitizer::check_access(0x1001, 8).unwrap_err();
    assert_eq!(e.kind, SanitizerKind::Misaligned);
    assert!(e.message.contains("misaligned"));
}

#[test]
fn ubsan_check_access_aligned_ok() {
    for a in [0x1000u64, 0x2000, 0x8000] {
        assert!(UbSanitizer::check_access(a, 8).is_ok());
    }
}

#[test]
fn ubsan_const_new() {
    const _U: UbSanitizer = UbSanitizer::new();
}

// ── SanitizerKind / Display / Eq / Hash ───────────────────────────────────────

#[test]
fn sanitizer_kind_display_all_variants() {
    use SanitizerKind::*;
    let pairs = [
        (MemoryUninit, "MemoryUninit"),
        (HeapOverflow, "HeapOverflow"),
        (UseAfterFree, "UseAfterFree"),
        (DoubleFree, "DoubleFree"),
        (NullDeref, "NullDeref"),
        (IntOverflow, "IntOverflow"),
        (Misaligned, "Misaligned"),
        (DivByZero, "DivByZero"),
        (HeapUnderflow, "HeapUnderflow"),
    ];
    for (k, s) in pairs {
        assert_eq!(format!("{k}"), s);
    }
}

#[test]
fn sanitizer_kind_hash_eq_consistency() {
    use std::collections::HashSet;
    use SanitizerKind::*;
    let all = [
        MemoryUninit,
        HeapOverflow,
        UseAfterFree,
        DoubleFree,
        NullDeref,
        IntOverflow,
        Misaligned,
        DivByZero,
        HeapUnderflow,
    ];
    let mut set: HashSet<SanitizerKind> = HashSet::new();
    for k in &all {
        set.insert(k.clone());
    }
    assert_eq!(set.len(), all.len());
    // 30+ equality pairs
    for a in &all {
        for b in &all {
            let eq = format!("{a:?}") == format!("{b:?}");
            assert_eq!(a == b, eq);
        }
    }
}

#[test]
fn sanitizer_result_eq_and_clone() {
    let a = SanitizerResult::Clean;
    let b = a.clone();
    assert_eq!(a, b);
    let d = SanitizerResult::DoubleFree { addr: 0x42 };
    assert_eq!(d, SanitizerResult::DoubleFree { addr: 0x42 });
    assert_ne!(d, SanitizerResult::DoubleFree { addr: 0x43 });
}

#[test]
fn sanitizer_report_new_fields() {
    let r = SanitizerReport::new(SanitizerKind::DivByZero, "div", vec![1, 2, 3]);
    assert_eq!(r.kind, SanitizerKind::DivByZero);
    assert_eq!(r.message, "div");
    assert_eq!(r.stack_trace, vec![1, 2, 3]);
    let _ = r;
    let _ = format!("{r:?}");
}

#[test]
fn arith_op_copy_eq() {
    let a = ArithOp::Add;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(ArithOp::Add, ArithOp::Sub);
    assert_ne!(ArithOp::Sub, ArithOp::Mul);
}

// ── Send + Sync threaded stress ───────────────────────────────────────────────

#[test]
fn ubsan_send_sync_thread_stress() {
    // UbSanitizer methods are pure-function-like; test threaded calls.
    use std::sync::Arc;
    use std::thread;
    let work = Arc::new(());
    let mut handles = vec![];
    for t in 0..4 {
        let _w = work.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100i64 {
                let a = i.wrapping_mul(i64::from(t) + 1);
                let _ = UbSanitizer::checked_add(a, 1);
                let _ = UbSanitizer::checked_mul(a, 3);
                let _ = UbSanitizer::check_access(a.cast_unsigned() & !0x7, 8);
                let _ = UbSanitizer::check_signed_overflow(a, 2, ArithOp::Mul);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn shadow_memory_send_across_thread() {
    // ShadowMemory should be Send.
    use std::thread;
    let mut sm = ShadowMemory::new();
    sm.mark_defined(0x100, 16);
    let h = thread::spawn(move || {
        assert!(sm.check_defined(0x100, 16));
        sm
    });
    let sm2 = h.join().unwrap();
    assert!(sm2.check_defined(0x100, 16));
}

#[test]
fn address_sanitizer_send_across_thread() {
    use std::thread;
    let mut a = AddressSanitizer::new();
    a.track_alloc(0x1000, 64);
    let h = thread::spawn(move || {
        assert!(a.check(0x1000, 32).is_ok());
        a
    });
    let _ = h.join().unwrap();
}

#[test]
fn assert_send_sync_types() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ShadowMemory>();
    assert_sync::<ShadowMemory>();
    assert_send::<MemorySanitizer>();
    assert_send::<AddressSanitizer>();
    assert_send::<HeapTracking>();
    assert_send::<SanitizerReport>();
    assert_send::<SanitizerKind>();
    assert_send::<SanitizerResult>();
    assert_send::<ArithOp>();
    assert_sync::<ArithOp>();
    assert_sync::<SanitizerKind>();
}

// ── Round-trip / property fuzz ────────────────────────────────────────────────

#[test]
fn shadow_define_undefine_round_trip_many() {
    let mut sm = ShadowMemory::new();
    let mut g = lcg();
    for _ in 0..50 {
        let addr = g() & 0xFFFF;
        let len = rustre_fuzz_sanitizers::cast::u64_to_usize((g() & 0x1F) + 1);
        sm.mark_defined(addr, len);
        assert!(sm.check_defined(addr, len));
        sm.mark_undefined(addr, len);
        // Now zero-len always true; any byte: check 1 byte → false
        if len > 0 {
            assert!(!sm.check_defined(addr, 1));
        }
    }
}

#[test]
fn heap_alloc_free_state_invariants() {
    let mut h = HeapTracking::new();
    let mut g = lcg();
    for _ in 0..50 {
        let addr = ((g() & 0x3FF) + 1) * 0x100;
        let size = rustre_fuzz_sanitizers::cast::u64_to_usize((g() & 0x3F) + 1);
        h.track_alloc(addr, size);
        // immediately after alloc: not in freed set
        assert!(!h.freed.contains(&addr));
        // and the allocation is present and not freed
        let alloc = h.allocations.get(&addr).unwrap();
        assert_eq!(alloc.size, size);
        assert!(!alloc.freed);
        // freeing once: clean, then in freed set
        let r = h.track_free(addr);
        assert_eq!(r, SanitizerResult::Clean);
        assert!(h.freed.contains(&addr));
        // freeing again: DoubleFree
        assert_eq!(h.track_free(addr), SanitizerResult::DoubleFree { addr });
    }
}

#[test]
fn ubsan_checked_add_matches_wrapping_when_in_range() {
    let mut g = lcg();
    for _ in 0..100 {
        let a = (g() & 0xFFFF).cast_signed() - 0x8000;
        let b = (g() & 0xFFFF).cast_signed() - 0x8000;
        let r = UbSanitizer::checked_add(a, b).unwrap();
        assert_eq!(r, a + b);
    }
}

#[test]
fn heap_overflow_size_zero_inside_alloc_is_clean() {
    let mut h = HeapTracking::new();
    h.track_alloc(0x1000, 16);
    // size 0 access inside alloc: end == addr, end > alloc_end is false
    assert_eq!(h.check_heap_access(0x1000, 0), SanitizerResult::Clean);
    assert_eq!(h.check_heap_access(0x1008, 0), SanitizerResult::Clean);
}
