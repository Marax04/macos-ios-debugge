//! Blitz2 deep+adversarial suite for rustre-analysis-vsa.
//!
//! Targets soundness invariants of the abstract domain and engine:
//! join/meet idempotence/commutativity, contains-after-op preservation,
//! widening termination, memory model strong/weak update, address
//! classifier boundaries, register-state lattice laws, hash/eq consistency,
//! Send+Sync threaded stress, and seeded-LCG fuzz of all arithmetic.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

use rustre_analysis_vsa::{
    is_definitely_null, may_be_out_of_bounds, vs_offset, vs_scale, vs_widen,
    AddressClass, AddressClassifier, MemoryAbstraction, MemoryModel, RegisterState,
    StridedInterval, ValueSet, VsaAnalyzer, VsaBlock, VsaCfg, VsaError, VsaInstr, VsaState,
};

// ─────────────────────────── LCG fuzzer ─────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ─────────────────────────── ValueSet laws ──────────────────────────────────

#[test]
fn vs_join_is_commutative_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..200 {
        let a = ValueSet::interval(g.next() % 1000, g.next() % 1000 + 1000);
        let b = ValueSet::interval(g.next() % 1000, g.next() % 1000 + 1000);
        assert_eq!(a.join(&b), b.join(&a));
    }
}

#[test]
fn vs_join_is_idempotent_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let lo = g.next() % 10_000;
        let hi = lo + g.next() % 10_000;
        let v = ValueSet::interval(lo, hi);
        assert_eq!(v.join(&v), v);
    }
}

#[test]
fn vs_meet_is_commutative_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let a = ValueSet::interval(g.next() % 500, g.next() % 500 + 500);
        let b = ValueSet::interval(g.next() % 500, g.next() % 500 + 500);
        assert_eq!(a.meet(&b), b.meet(&a));
    }
}

#[test]
fn vs_join_absorbs_meet_partially() {
    // For lattice elements: a.join(a.meet(b)) == a
    let mut g = Lcg::new();
    for _ in 0..50 {
        let a = ValueSet::Concrete(vec![g.next() % 100, g.next() % 100, g.next() % 100]);
        let b = ValueSet::Concrete(vec![g.next() % 100, g.next() % 100]);
        let m = a.meet(&b);
        // a.join(m) must be >= a in the lattice; for Concrete sets it should equal a (modulo dedup/sort).
        let j = a.join(&m);
        // Every value of `a` must still be contained in j.
        if let ValueSet::Concrete(va) = &a {
            for v in va {
                assert!(j.contains(*v), "a={a:?}, m={m:?}, j={j:?}, v={v}");
            }
        }
    }
}

#[test]
fn vs_top_is_top_for_all_ops() {
    let t = ValueSet::top();
    let s = ValueSet::singleton(7);
    assert!(t.add(&s).is_top());
    assert!(s.add(&t).is_top());
    assert!(t.sub(&s).is_top());
    assert_eq!(t.join(&s), ValueSet::top());
    assert_eq!(t.meet(&s), s);
}

#[test]
fn vs_bottom_absorbs_meet_and_arithmetic() {
    let b = ValueSet::bottom();
    let s = ValueSet::singleton(3);
    assert!(b.meet(&s).is_bottom());
    assert!(s.meet(&b).is_bottom());
    assert!(b.add(&s).is_bottom());
    assert!(s.add(&b).is_bottom());
    assert!(b.sub(&s).is_bottom());
    assert!(s.sub(&b).is_bottom());
    assert_eq!(b.join(&s), s);
}

#[test]
fn vs_add_contains_sum_fuzz() {
    // For concrete pairs, add must contain the wrapping sum.
    let mut g = Lcg::new();
    for _ in 0..200 {
        let x = g.next();
        let y = g.next();
        let a = ValueSet::singleton(x);
        let b = ValueSet::singleton(y);
        let s = a.add(&b);
        assert!(s.contains(x.wrapping_add(y)));
    }
}

#[test]
fn vs_sub_contains_diff_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..200 {
        let x = g.next();
        let y = g.next();
        let s = ValueSet::singleton(x).sub(&ValueSet::singleton(y));
        assert!(s.contains(x.wrapping_sub(y)));
    }
}

#[test]
fn vs_singleton_arithmetic_inverse() {
    // (a + b) - b == a for singletons via Concrete path.
    let mut g = Lcg::new();
    for _ in 0..100 {
        let a = g.next() % 1_000_000;
        let b = g.next() % 1_000_000;
        let sum = ValueSet::singleton(a).add(&ValueSet::singleton(b));
        let recovered = sum.sub(&ValueSet::singleton(b));
        assert!(recovered.contains(a));
    }
}

#[test]
fn vs_bitwise_and_singletons_concrete() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let x = g.next();
        let y = g.next();
        let r = ValueSet::singleton(x).bitwise_and(&ValueSet::singleton(y));
        assert!(r.contains(x & y));
    }
}

#[test]
fn vs_bitwise_or_singletons_concrete() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let x = g.next();
        let y = g.next();
        let r = ValueSet::singleton(x).bitwise_or(&ValueSet::singleton(y));
        assert!(r.contains(x | y));
    }
}

#[test]
fn vs_concretize_singleton_limit() {
    let v = ValueSet::singleton(99);
    assert_eq!(v.concretize(0), Some(vec![99]));
}

#[test]
fn vs_concretize_top_is_none() {
    assert!(ValueSet::top().concretize(1_000_000).is_none());
}

#[test]
fn vs_concretize_bottom_is_empty() {
    assert_eq!(ValueSet::bottom().concretize(10), Some(vec![]));
}

#[test]
fn vs_concretize_range_count_correct() {
    let v = ValueSet::strided(0, 20, 2);
    let vals = v.concretize(100).expect("fits");
    assert_eq!(vals, vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]);
}

#[test]
fn vs_concretize_range_over_limit_none() {
    let v = ValueSet::interval(0, 1_000_000);
    assert!(v.concretize(100).is_none());
}

#[test]
fn vs_boundary_max_u64_singleton() {
    let v = ValueSet::singleton(u64::MAX);
    assert!(v.contains(u64::MAX));
    assert!(!v.contains(0));
}

#[test]
fn vs_boundary_zero_singleton() {
    let v = ValueSet::singleton(0);
    assert!(v.contains(0));
    assert!(!v.contains(1));
}

#[test]
fn vs_leq_self_reflexive_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let v = ValueSet::interval(g.next() % 1000, g.next() % 1000 + 1000);
        assert!(v.leq(&v));
    }
}

#[test]
fn vs_leq_bottom_is_least() {
    let mut g = Lcg::new();
    let b = ValueSet::bottom();
    for _ in 0..50 {
        let v = ValueSet::singleton(g.next());
        assert!(b.leq(&v));
    }
}

#[test]
fn vs_display_never_panics_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let v = match g.next() % 4 {
            0 => ValueSet::bottom(),
            1 => ValueSet::top(),
            2 => ValueSet::singleton(g.next()),
            _ => ValueSet::interval(g.next() % 1000, g.next() % 1000 + 1000),
        };
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

#[test]
fn vs_widen_terminates_increasing_chain() {
    // Chain: [0,1], [0,2], [0,3], ... after some steps widen should jump hi to u64::MAX.
    let mut prev = ValueSet::interval(0, 1);
    for i in 2..50 {
        let next = ValueSet::interval(0, i);
        prev = prev.widen(&next);
        if prev.is_top() {
            return;
        }
        if let ValueSet::Range { hi, .. } = &prev
            && *hi == u64::MAX {
                return;
            }
    }
    panic!("widen did not reach extreme: {prev:?}");
}

// ─────────────────────────── StridedInterval laws ───────────────────────────

#[test]
fn si_top_bottom_predicates() {
    assert!(StridedInterval::TOP.is_top());
    assert!(StridedInterval::BOTTOM.is_bottom());
    assert!(!StridedInterval::TOP.is_bottom());
    assert!(!StridedInterval::BOTTOM.is_top());
}

#[test]
fn si_singleton_contains_only_value() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let v = g.next();
        let s = StridedInterval::singleton(v);
        assert!(s.contains(v));
        assert!(s.is_singleton());
    }
}

#[test]
fn si_new_normalizes_lo_gt_hi_to_bottom() {
    let si = StridedInterval::new(10, 5, 1);
    assert!(si.is_bottom());
}

#[test]
fn si_new_clamps_hi_to_reachable() {
    // lo=0, hi=10, stride=3 -> hi should be 9 (0,3,6,9).
    let si = StridedInterval::new(0, 10, 3);
    assert!(!si.is_bottom());
    assert!(si.contains(0));
    assert!(si.contains(3));
    assert!(si.contains(6));
    assert!(si.contains(9));
    assert!(!si.contains(10));
}

#[test]
fn si_contains_respects_stride() {
    let si = StridedInterval::new(0, 100, 5);
    for k in 0..=20u64 {
        assert!(si.contains(k * 5));
    }
    assert!(!si.contains(1));
    assert!(!si.contains(7));
}

#[test]
fn si_join_with_bottom_is_identity_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..40 {
        let a = g.next() % 1000;
        let si = StridedInterval::interval(a, a + 100);
        assert_eq!(si.join(&StridedInterval::BOTTOM), si);
        assert_eq!(StridedInterval::BOTTOM.join(&si), si);
    }
}

#[test]
fn si_meet_disjoint_is_bottom() {
    let a = StridedInterval::interval(0, 10);
    let b = StridedInterval::interval(20, 30);
    assert!(a.meet(&b).is_bottom());
}

#[test]
fn si_meet_self_is_self_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let lo = g.next() % 1000;
        let hi = lo + 1 + g.next() % 100;
        let si = StridedInterval::interval(lo, hi);
        assert_eq!(si.meet(&si), si);
    }
}

#[test]
fn si_add_singletons_contains_sum_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let x = g.next() / 2;
        let y = g.next() / 2;
        let r = StridedInterval::singleton(x).add(&StridedInterval::singleton(y));
        assert!(r.contains(x.wrapping_add(y)));
    }
}

#[test]
fn si_sub_singletons_contains_diff_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..100 {
        let x = g.next();
        let y = g.next();
        let r = StridedInterval::singleton(x).sub(&StridedInterval::singleton(y));
        assert!(r.contains(x.wrapping_sub(y)));
    }
}

#[test]
fn si_concretize_singleton() {
    assert_eq!(StridedInterval::singleton(42).concretize(10), Some(vec![42]));
}

#[test]
fn si_concretize_top_none() {
    assert!(StridedInterval::TOP.concretize(1_000_000).is_none());
}

#[test]
fn si_concretize_bottom_empty() {
    assert_eq!(StridedInterval::BOTTOM.concretize(10), Some(vec![]));
}

#[test]
fn si_widen_grows_to_extreme() {
    // After enough widening steps, hi must blow to (near) u64::MAX. The
    // constructor snaps hi down by stride, so we check it's within one stride
    // of u64::MAX rather than exactly equal.
    let mut prev = StridedInterval::interval(5, 10);
    for i in 1..40 {
        let next = StridedInterval::interval(5, 10 + i);
        prev = prev.widen(&next);
    }
    assert!(
        prev.is_top() || u64::MAX - prev.hi < prev.stride,
        "widen did not approach u64::MAX: {prev:?}"
    );
}

#[test]
fn si_display_never_panics_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let si = match g.next() % 4 {
            0 => StridedInterval::BOTTOM,
            1 => StridedInterval::TOP,
            2 => StridedInterval::singleton(g.next()),
            _ => StridedInterval::new(g.next() % 100, g.next() % 100 + 100, 1 + g.next() % 8),
        };
        let _ = format!("{si}");
    }
}

#[test]
fn si_hash_eq_consistency_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..40 {
        let lo = g.next() % 1000;
        let hi = lo + g.next() % 100;
        let stride = 1 + g.next() % 8;
        let a = StridedInterval::new(lo, hi, stride);
        let b = StridedInterval::new(lo, hi, stride);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn si_is_definitely_null_only_for_zero_singleton() {
    assert!(is_definitely_null(&StridedInterval::singleton(0)));
    assert!(!is_definitely_null(&StridedInterval::singleton(1)));
    assert!(!is_definitely_null(&StridedInterval::interval(0, 10)));
    assert!(!is_definitely_null(&StridedInterval::BOTTOM));
}

#[test]
fn si_may_be_out_of_bounds_cases() {
    let bounds = (10u64, 20u64);
    assert!(!may_be_out_of_bounds(
        &StridedInterval::interval(10, 19),
        bounds
    ));
    assert!(may_be_out_of_bounds(
        &StridedInterval::interval(5, 15),
        bounds
    ));
    assert!(may_be_out_of_bounds(
        &StridedInterval::interval(15, 25),
        bounds
    ));
    assert!(may_be_out_of_bounds(&StridedInterval::TOP, bounds));
    assert!(!may_be_out_of_bounds(&StridedInterval::BOTTOM, bounds));
}

// ─────────────────────────── VsaState laws ──────────────────────────────────

#[test]
fn vsa_state_get_unknown_is_bottom() {
    let s = VsaState::new();
    assert!(s.get("never_set").is_bottom());
}

#[test]
fn vsa_state_set_then_get() {
    let mut s = VsaState::new();
    s.set("r0", ValueSet::singleton(7));
    assert_eq!(s.get("r0"), ValueSet::singleton(7));
}

#[test]
fn vsa_state_join_is_pointwise_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..40 {
        let mut a = VsaState::new();
        let mut b = VsaState::new();
        a.set("r0", ValueSet::singleton(g.next() % 100));
        b.set("r0", ValueSet::singleton(g.next() % 100));
        b.set("r1", ValueSet::singleton(g.next() % 100));
        let j = a.join(&b);
        assert!(a.leq(&j));
        assert!(b.leq(&j));
    }
}

// ─────────────────────────── MemoryModel ─────────────────────────────────────

#[test]
fn memory_model_strong_update_on_singleton() {
    let mut m = MemoryModel::default();
    m.store(&ValueSet::singleton(0x1000), ValueSet::singleton(42));
    let v = m.load(&ValueSet::singleton(0x1000));
    assert!(v.contains(42));
}

#[test]
fn memory_model_overwrite_strong_update() {
    let mut m = MemoryModel::default();
    m.store(&ValueSet::singleton(0x1000), ValueSet::singleton(1));
    m.store(&ValueSet::singleton(0x1000), ValueSet::singleton(2));
    let v = m.load(&ValueSet::singleton(0x1000));
    // After strong update, should contain 2 (1 has been overwritten).
    assert!(v.contains(2));
}

#[test]
fn memory_model_load_unknown_is_top() {
    let m = MemoryModel::default();
    let v = m.load(&ValueSet::singleton(0xDEAD));
    assert!(v.is_top());
}

// ─────────────────────────── MemoryAbstraction ──────────────────────────────

#[test]
fn mem_abs_strong_update_singleton_overwrites() {
    let mut m = MemoryAbstraction::new();
    m.store(StridedInterval::singleton(0x100), StridedInterval::singleton(1));
    m.store(StridedInterval::singleton(0x100), StridedInterval::singleton(2));
    let v = m.load(&StridedInterval::singleton(0x100));
    assert_eq!(v, StridedInterval::singleton(2));
    assert_eq!(m.cell_count(), 1);
}

#[test]
fn mem_abs_load_disjoint_is_bottom() {
    let mut m = MemoryAbstraction::new();
    m.store(StridedInterval::singleton(0x100), StridedInterval::singleton(7));
    let v = m.load(&StridedInterval::singleton(0x200));
    assert!(v.is_bottom());
}

#[test]
fn mem_abs_bottom_addr_no_effect() {
    let mut m = MemoryAbstraction::new();
    m.store(StridedInterval::BOTTOM, StridedInterval::singleton(7));
    assert_eq!(m.cell_count(), 0);
    let v = m.load(&StridedInterval::BOTTOM);
    assert!(v.is_bottom());
}

#[test]
fn mem_abs_weak_update_joins() {
    let mut m = MemoryAbstraction::new();
    // First, plant a singleton cell at 0x100 with value 5.
    m.store(StridedInterval::singleton(0x100), StridedInterval::singleton(5));
    // Now weak-update a range that aliases it.
    m.store(StridedInterval::interval(0x100, 0x108), StridedInterval::singleton(9));
    let v = m.load(&StridedInterval::singleton(0x100));
    // Must contain both 5 and 9 due to weak update join.
    assert!(v.contains(5));
    assert!(v.contains(9));
}

// ─────────────────────────── AddressClassifier ──────────────────────────────

#[test]
fn classifier_unknown_when_no_ranges() {
    let c = AddressClassifier::new();
    assert_eq!(c.classify_addr(0x1234), AddressClass::Unknown);
}

#[test]
fn classifier_code_takes_priority_over_stack() {
    let mut c = AddressClassifier::new();
    c.code_range = Some((0x400000, 0x500000));
    c.stack_range = Some((0x400000, 0x500000));
    assert_eq!(c.classify_addr(0x401000), AddressClass::Code);
}

#[test]
fn classifier_boundary_inclusive_lo_exclusive_hi() {
    let mut c = AddressClassifier::new();
    c.global_range = Some((0x1000, 0x2000));
    assert_eq!(c.classify_addr(0x1000), AddressClass::Global);
    assert_eq!(c.classify_addr(0x1FFF), AddressClass::Global);
    assert_eq!(c.classify_addr(0x2000), AddressClass::Unknown);
    assert_eq!(c.classify_addr(0xFFF), AddressClass::Unknown);
}

#[test]
fn classifier_heap_hints_match() {
    let mut c = AddressClassifier::new();
    c.heap_hints.insert(0xCAFE);
    assert_eq!(c.classify_addr(0xCAFE), AddressClass::Heap);
    assert_eq!(c.classify_addr(0xCAFF), AddressClass::Unknown);
}

#[test]
fn classifier_classify_valueset_top_returns_unknown() {
    let c = AddressClassifier::new();
    let s = c.classify(&ValueSet::top());
    assert!(s.contains(&AddressClass::Unknown));
}

// ─────────────────────────── RegisterState laws ─────────────────────────────

#[test]
fn reg_state_get_unknown_is_bottom() {
    let s = RegisterState::default();
    assert!(s.get("rax").is_bottom());
}

#[test]
fn reg_state_join_idempotent_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..40 {
        let mut s = RegisterState::default();
        s.set("r", StridedInterval::singleton(g.next() % 1000));
        let j = s.join(&s);
        assert_eq!(j, s);
    }
}

#[test]
fn reg_state_widen_terminates() {
    let mut prev = RegisterState::default();
    prev.set("i", StridedInterval::singleton(0));
    for k in 1..30u64 {
        let mut next = RegisterState::default();
        next.set("i", StridedInterval::interval(0, k));
        prev = prev.widen(&next);
    }
    let v = prev.get("i");
    assert!(v.hi == u64::MAX || v.is_top());
}

// ─────────────────────────── jumptable scale/offset/widen ───────────────────

#[test]
fn vs_scale_by_zero_is_singleton_zero() {
    let r = vs_scale(&ValueSet::interval(1, 10), 0);
    assert!(r.contains(0));
}

#[test]
fn vs_scale_singleton_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let x = g.next() % 1_000_000;
        let f = g.next() % 1000;
        let r = vs_scale(&ValueSet::singleton(x), f);
        assert!(r.contains(x.wrapping_mul(f)));
    }
}

#[test]
fn vs_offset_singleton_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let x = g.next();
        let d = g.next();
        let r = vs_offset(&ValueSet::singleton(x), d);
        assert!(r.contains(x.wrapping_add(d)));
    }
}

#[test]
fn vs_scale_preserves_bottom_and_top() {
    assert!(vs_scale(&ValueSet::bottom(), 4).is_bottom());
    assert!(vs_scale(&ValueSet::top(), 4).is_top());
}

#[test]
fn vs_offset_preserves_bottom_and_top() {
    assert!(vs_offset(&ValueSet::bottom(), 4).is_bottom());
    assert!(vs_offset(&ValueSet::top(), 4).is_top());
}

#[test]
fn vs_widen_bottom_identity() {
    let v = ValueSet::singleton(5);
    assert_eq!(vs_widen(&ValueSet::bottom(), &v), v);
    assert_eq!(vs_widen(&v, &ValueSet::bottom()), v);
}

#[test]
fn vs_widen_top_absorbs() {
    assert!(vs_widen(&ValueSet::top(), &ValueSet::singleton(0)).is_top());
    assert!(vs_widen(&ValueSet::singleton(0), &ValueSet::top()).is_top());
}

// ─────────────────────────── VsaAnalyzer / VsaCfg ───────────────────────────

#[test]
fn analyzer_empty_program_errors() {
    let cfg = VsaCfg::new(vec![], vec![], 0);
    let a = VsaAnalyzer::new(VsaState::new());
    match a.run(&cfg) {
        Err(VsaError::EmptyProgram) => {}
        other => panic!("expected EmptyProgram, got {other:?}"),
    }
}

#[test]
fn analyzer_const_assignment_single_block() {
    let block = VsaBlock {
        id: 0,
        instrs: vec![VsaInstr::Const {
            dst: "r0".into(),
            value: 42,
        }],
    };
    let cfg = VsaCfg::new(vec![block], vec![vec![]], 0);
    let a = VsaAnalyzer::new(VsaState::new());
    let states = a.run(&cfg).expect("converges");
    assert_eq!(states.len(), 1);
}

#[test]
fn analyzer_diamond_join_fuzz() {
    // entry -> b1 -> exit
    //        \-> b2 -/
    // b1 sets r=1, b2 sets r=2; at exit, r should be the join.
    let blocks = vec![
        VsaBlock { id: 0, instrs: vec![] },
        VsaBlock {
            id: 1,
            instrs: vec![VsaInstr::Const {
                dst: "r".into(),
                value: 1,
            }],
        },
        VsaBlock {
            id: 2,
            instrs: vec![VsaInstr::Const {
                dst: "r".into(),
                value: 2,
            }],
        },
        VsaBlock { id: 3, instrs: vec![] },
    ];
    let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
    let cfg = VsaCfg::new(blocks, succs, 0);
    let a = VsaAnalyzer::new(VsaState::new());
    let states = a.run(&cfg).expect("converges");
    let exit = &states[3];
    let r = exit.get("r");
    assert!(r.contains(1));
    assert!(r.contains(2));
}

#[test]
fn analyzer_loop_terminates_with_widening() {
    // Simple loop: entry -> head -> head
    let blocks = vec![
        VsaBlock {
            id: 0,
            instrs: vec![VsaInstr::Const {
                dst: "i".into(),
                value: 0,
            }],
        },
        VsaBlock {
            id: 1,
            instrs: vec![
                VsaInstr::Const {
                    dst: "one".into(),
                    value: 1,
                },
                VsaInstr::Add {
                    dst: "i".into(),
                    lhs: "i".into(),
                    rhs: "one".into(),
                },
            ],
        },
    ];
    let succs = vec![vec![1], vec![1]];
    let cfg = VsaCfg::new(blocks, succs, 0);
    let a = VsaAnalyzer::new(VsaState::new());
    let _ = a.run(&cfg).expect("must terminate via widening");
}

// ─────────────────────────── Send + Sync threaded stress ────────────────────

#[test]
fn valueset_is_send_sync_threaded_stress() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ValueSet>();
    assert_send_sync::<StridedInterval>();

    let base = Arc::new(ValueSet::interval(0, 1000));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let b = Arc::clone(&base);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE ^ t.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut local = (*b).clone();
            for _ in 0..100 {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let v = ValueSet::singleton(s % 10_000);
                local = local.join(&v);
            }
            local
        }));
    }
    for h in handles {
        let r = h.join().expect("thread");
        // Result must at least contain the original interval values.
        assert!(r.contains(0));
        assert!(r.contains(1000));
    }
}

#[test]
fn stridedinterval_threaded_arithmetic_stress() {
    let mut handles = Vec::new();
    for t in 0..4u64 {
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xCAFE_BABE_DEAD_BEEF ^ t.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for _ in 0..100 {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let a = StridedInterval::singleton(s & 0xFFFF);
                let b = StridedInterval::singleton((s >> 16) & 0xFFFF);
                let sum = a.add(&b);
                assert!(sum.contains((s & 0xFFFF).wrapping_add((s >> 16) & 0xFFFF)));
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}

// ─────────────────────────── Hash/Eq consistency batch ──────────────────────

#[test]
fn si_hash_eq_pairs_30() {
    let mut g = Lcg::new();
    let mut seen: HashSet<StridedInterval> = HashSet::new();
    for _ in 0..30 {
        let lo = g.next() % 100;
        let hi = lo + g.next() % 100;
        let stride = 1 + g.next() % 4;
        let a = StridedInterval::new(lo, hi, stride);
        let b = StridedInterval::new(lo, hi, stride);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        seen.insert(a);
    }
    assert!(!seen.is_empty());
}

// ─────────────────────────── ValueSet serde round-trip ──────────────────────

#[test]
fn valueset_serde_roundtrip_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let v = match g.next() % 4 {
            0 => ValueSet::bottom(),
            1 => ValueSet::top(),
            2 => ValueSet::singleton(g.next()),
            _ => ValueSet::strided(g.next() % 100, g.next() % 100 + 100, 1 + g.next() % 8),
        };
        let s = serde_json::to_string(&v).expect("serialize");
        let back: ValueSet = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }
}

#[test]
fn stridedinterval_serde_roundtrip_fuzz() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let si = match g.next() % 4 {
            0 => StridedInterval::BOTTOM,
            1 => StridedInterval::TOP,
            2 => StridedInterval::singleton(g.next()),
            _ => StridedInterval::new(g.next() % 100, g.next() % 100 + 100, 1 + g.next() % 8),
        };
        let s = serde_json::to_string(&si).expect("serialize");
        let back: StridedInterval = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(si, back);
    }
}
