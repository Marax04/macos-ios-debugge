//! Blitz test suite for rustre-analysis-vsa.
//!
//! Exercises ValueSet, StridedInterval, VsaState, MemoryModel, MemoryAbstraction,
//! VsaAnalyzer, AddressClassifier, IndirectCallResolver, RegisterState, jumptable APIs.

use rustre_analysis_vsa::{
    AddressClass, AddressClassifier, IndirectCallResolution, IndirectCallResolver, MemoryAbstraction,
    MemoryModel, RegisterState, StridedInterval, ValueSet, ValueSetResult, VsaAnalyzer, VsaBlock,
    VsaCfg, VsaError, VsaInstr, VsaState, bound_jump_table, is_definitely_null,
    may_be_out_of_bounds, resolve_indirect_targets, resolve_switch, vs_offset, vs_scale, vs_widen,
    TableImage, JumpTableBounds,
};
use rustre_core::endian::Endian;

// ──────────────────────── ValueSet construction ─────────────────────────

#[test]
fn vs_singleton_is_concrete_one() {
    let v = ValueSet::singleton(42);
    assert!(v.contains(42));
    assert!(!v.contains(43));
    assert_eq!(v.concretize(10), Some(vec![42]));
}

#[test]
fn vs_top_bottom_predicates() {
    assert!(ValueSet::top().is_top());
    assert!(ValueSet::bottom().is_bottom());
    assert!(!ValueSet::top().is_bottom());
    assert!(!ValueSet::bottom().is_top());
    assert!(!ValueSet::singleton(0).is_top());
    assert!(!ValueSet::singleton(0).is_bottom());
}

#[test]
fn vs_interval_collapses_singleton() {
    let v = ValueSet::interval(5, 5);
    assert_eq!(v, ValueSet::singleton(5));
}

#[test]
fn vs_interval_range() {
    let v = ValueSet::interval(0, 10);
    assert!(v.contains(0));
    assert!(v.contains(10));
    assert!(v.contains(5));
    assert!(!v.contains(11));
}

#[test]
fn vs_strided_normalizes_zero_stride() {
    // stride 0 should become 1.
    let v = ValueSet::strided(0, 4, 0);
    assert!(v.contains(0));
    assert!(v.contains(4));
}

#[test]
fn vs_strided_collapses_singleton() {
    let v = ValueSet::strided(7, 7, 3);
    assert_eq!(v, ValueSet::singleton(7));
}

// ──────────────────────── ValueSet join/meet ────────────────────────────

#[test]
fn vs_join_bottom_identity() {
    let v = ValueSet::singleton(3);
    assert_eq!(v.join(&ValueSet::bottom()), v);
    assert_eq!(ValueSet::bottom().join(&v), v);
}

#[test]
fn vs_join_top_absorbs() {
    let v = ValueSet::singleton(3);
    assert_eq!(v.join(&ValueSet::top()), ValueSet::top());
}

#[test]
fn vs_join_concrete_concrete() {
    let a = ValueSet::Concrete(vec![1, 2]);
    let b = ValueSet::Concrete(vec![3, 4]);
    let j = a.join(&b);
    assert!(j.contains(1) && j.contains(2) && j.contains(3) && j.contains(4));
}

#[test]
fn vs_join_concrete_promotes_to_range_over_max() {
    let big: Vec<u64> = (0..40).collect();
    let small: Vec<u64> = (40..50).collect();
    let a = ValueSet::Concrete(big);
    let b = ValueSet::Concrete(small);
    let j = a.join(&b);
    matches!(j, ValueSet::Range { .. });
}

#[test]
fn vs_meet_disjoint_concrete_is_bottom() {
    let a = ValueSet::Concrete(vec![1, 2]);
    let b = ValueSet::Concrete(vec![3, 4]);
    assert!(a.meet(&b).is_bottom());
}

#[test]
fn vs_meet_overlap_concrete() {
    let a = ValueSet::Concrete(vec![1, 2, 3]);
    let b = ValueSet::Concrete(vec![2, 3, 4]);
    let m = a.meet(&b);
    assert!(m.contains(2));
    assert!(m.contains(3));
    assert!(!m.contains(1));
}

#[test]
fn vs_meet_with_top_returns_self() {
    let a = ValueSet::singleton(5);
    assert_eq!(a.meet(&ValueSet::top()), a);
}

#[test]
fn vs_meet_with_bottom_is_bottom() {
    let a = ValueSet::singleton(5);
    assert!(a.meet(&ValueSet::bottom()).is_bottom());
}

#[test]
fn vs_leq_basic() {
    assert!(ValueSet::bottom().leq(&ValueSet::singleton(1)));
    assert!(ValueSet::singleton(1).leq(&ValueSet::top()));
    assert!(!ValueSet::top().leq(&ValueSet::singleton(1)));
}

// ──────────────────────── ValueSet arithmetic ───────────────────────────

#[test]
fn vs_add_concrete() {
    let a = ValueSet::Concrete(vec![1, 2]);
    let b = ValueSet::Concrete(vec![10, 20]);
    let r = a.add(&b);
    // 11, 21, 12, 22
    assert!(r.contains(11) && r.contains(12) && r.contains(21) && r.contains(22));
}

#[test]
fn vs_add_bottom_is_bottom() {
    assert!(ValueSet::bottom().add(&ValueSet::singleton(1)).is_bottom());
    assert!(ValueSet::singleton(1).add(&ValueSet::bottom()).is_bottom());
}

#[test]
fn vs_add_top_is_top() {
    assert!(ValueSet::top().add(&ValueSet::singleton(1)).is_top());
}

#[test]
fn vs_sub_concrete() {
    let a = ValueSet::singleton(10);
    let b = ValueSet::singleton(3);
    assert_eq!(a.sub(&b), ValueSet::singleton(7));
}

#[test]
fn vs_sub_wrapping() {
    let a = ValueSet::singleton(0);
    let b = ValueSet::singleton(1);
    assert_eq!(a.sub(&b), ValueSet::singleton(u64::MAX));
}

#[test]
fn vs_bitwise_and_concrete() {
    let a = ValueSet::Concrete(vec![0xff]);
    let b = ValueSet::Concrete(vec![0x0f]);
    assert_eq!(a.bitwise_and(&b), ValueSet::Concrete(vec![0x0f]));
}

#[test]
fn vs_bitwise_or_concrete() {
    let a = ValueSet::Concrete(vec![0xf0]);
    let b = ValueSet::Concrete(vec![0x0f]);
    assert_eq!(a.bitwise_or(&b), ValueSet::Concrete(vec![0xff]));
}

#[test]
fn vs_bitwise_and_top_is_top() {
    assert!(ValueSet::top().bitwise_and(&ValueSet::singleton(1)).is_top());
}

// ──────────────────────── ValueSet widen / concretize ───────────────────

#[test]
fn vs_widen_unstable_upper() {
    let prev = ValueSet::interval(0, 4);
    let next = ValueSet::interval(0, 8);
    let w = prev.widen(&next);
    if let ValueSet::Range { hi, .. } = w {
        assert_eq!(hi, u64::MAX);
    } else if !w.is_top() {
        panic!("expected widened range or top, got {:?}", w);
    }
}

#[test]
fn vs_widen_stable() {
    let prev = ValueSet::interval(0, 4);
    let next = ValueSet::interval(0, 4);
    let w = prev.widen(&next);
    assert!(w.contains(0) && w.contains(4));
}

#[test]
fn vs_concretize_range_within_limit() {
    let v = ValueSet::strided(0, 8, 2);
    assert_eq!(v.concretize(16), Some(vec![0, 2, 4, 6, 8]));
}

#[test]
fn vs_concretize_top_is_none() {
    assert_eq!(ValueSet::top().concretize(1000), None);
}

#[test]
fn vs_concretize_bottom_is_empty() {
    assert_eq!(ValueSet::bottom().concretize(10), Some(vec![]));
}

#[test]
fn vs_concretize_over_limit_is_none() {
    let v = ValueSet::interval(0, 100);
    assert_eq!(v.concretize(5), None);
}

// ──────────────────────── Display ───────────────────────────────────────

#[test]
fn vs_display_top_bottom() {
    assert_eq!(format!("{}", ValueSet::top()), "\u{22a4}");
    assert_eq!(format!("{}", ValueSet::bottom()), "\u{22a5}");
}

#[test]
fn vs_display_concrete_and_range() {
    let s = format!("{}", ValueSet::singleton(0x10));
    assert!(s.contains("0x10"));
    let r = format!("{}", ValueSet::strided(0, 10, 2));
    assert!(r.contains("/2"));
}

// ──────────────────────── VsaState ──────────────────────────────────────

#[test]
fn state_get_missing_is_bottom() {
    let s = VsaState::new();
    assert!(s.get("nope").is_bottom());
}

#[test]
fn state_set_get_roundtrip() {
    let mut s = VsaState::new();
    s.set("x", ValueSet::singleton(7));
    assert_eq!(s.get("x"), ValueSet::singleton(7));
}

#[test]
fn state_join_pointwise() {
    let mut a = VsaState::new();
    a.set("x", ValueSet::singleton(1));
    let mut b = VsaState::new();
    b.set("x", ValueSet::singleton(2));
    let j = a.join(&b);
    let v = j.get("x");
    assert!(v.contains(1) && v.contains(2));
}

#[test]
fn state_leq_reflexive() {
    let mut a = VsaState::new();
    a.set("x", ValueSet::singleton(1));
    assert!(a.leq(&a));
}

// ──────────────────────── MemoryModel ───────────────────────────────────

#[test]
fn mm_strong_update_singleton() {
    let mut mm = MemoryModel::default();
    mm.store(&ValueSet::singleton(0x1000), ValueSet::singleton(7));
    let v = mm.load(&ValueSet::singleton(0x1000));
    assert!(v.contains(7));
}

#[test]
fn mm_load_unknown_is_top() {
    let mm = MemoryModel::default();
    assert!(mm.load(&ValueSet::singleton(0x9999)).is_top());
}

#[test]
fn mm_strong_update_overwrites() {
    let mut mm = MemoryModel::default();
    mm.store(&ValueSet::singleton(0x10), ValueSet::singleton(1));
    mm.store(&ValueSet::singleton(0x10), ValueSet::singleton(2));
    let v = mm.load(&ValueSet::singleton(0x10));
    assert_eq!(v, ValueSet::singleton(2));
}

// ──────────────────────── VsaCfg / VsaAnalyzer ──────────────────────────

#[test]
fn cfg_predecessors_filled() {
    let blocks = vec![
        VsaBlock { id: 0, instrs: vec![] },
        VsaBlock { id: 1, instrs: vec![] },
    ];
    let cfg = VsaCfg::new(blocks, vec![vec![1], vec![]], 0);
    assert_eq!(cfg.predecessors[1], vec![0]);
    assert!(cfg.predecessors[0].is_empty());
}

#[test]
fn analyzer_empty_program_err() {
    let cfg = VsaCfg::new(vec![], vec![], 0);
    let a = VsaAnalyzer::new(VsaState::new());
    assert!(matches!(a.run(&cfg), Err(VsaError::EmptyProgram)));
}

#[test]
fn analyzer_const_propagation() {
    let blocks = vec![VsaBlock {
        id: 0,
        instrs: vec![VsaInstr::Const { dst: "x".into(), value: 42 }],
    }];
    let cfg = VsaCfg::new(blocks, vec![vec![]], 0);
    let a = VsaAnalyzer::new(VsaState::new());
    let states = a.run(&cfg).unwrap();
    assert_eq!(states.len(), 1);
}

#[test]
fn analyzer_copy_then_add() {
    let blocks = vec![VsaBlock {
        id: 0,
        instrs: vec![
            VsaInstr::Const { dst: "a".into(), value: 3 },
            VsaInstr::Const { dst: "b".into(), value: 4 },
            VsaInstr::Add { dst: "c".into(), lhs: "a".into(), rhs: "b".into() },
        ],
    }];
    let cfg = VsaCfg::new(blocks, vec![vec![]], 0);
    let mut mem = MemoryModel::default();
    let s = VsaAnalyzer::transfer(&cfg.blocks[0], &VsaState::new(), &mut mem);
    assert_eq!(s.get("c"), ValueSet::singleton(7));
}

#[test]
fn analyzer_two_block_join() {
    let blocks = vec![
        VsaBlock { id: 0, instrs: vec![VsaInstr::Const { dst: "x".into(), value: 1 }] },
        VsaBlock { id: 1, instrs: vec![] },
    ];
    let cfg = VsaCfg::new(blocks, vec![vec![1], vec![]], 0);
    let a = VsaAnalyzer::new(VsaState::new());
    let states = a.run(&cfg).unwrap();
    // Block 1 should have received x = 1 from block 0.
    assert!(states[1].get("x").contains(1));
}

#[test]
fn analyzer_phi_joins() {
    let mut mem = MemoryModel::default();
    let mut s = VsaState::new();
    s.set("a", ValueSet::singleton(1));
    s.set("b", ValueSet::singleton(2));
    let block = VsaBlock {
        id: 0,
        instrs: vec![VsaInstr::Phi { dst: "p".into(), srcs: vec!["a".into(), "b".into()] }],
    };
    let s2 = VsaAnalyzer::transfer(&block, &s, &mut mem);
    let p = s2.get("p");
    assert!(p.contains(1) && p.contains(2));
}

#[test]
fn analyzer_indirect_call_is_noop_on_state() {
    let mut mem = MemoryModel::default();
    let s0 = VsaState::new();
    let block = VsaBlock {
        id: 0,
        instrs: vec![VsaInstr::IndirectCall { target: "t".into() }],
    };
    let s = VsaAnalyzer::transfer(&block, &s0, &mut mem);
    assert!(s.get("t").is_bottom());
}

// ──────────────────────── AddressClassifier ─────────────────────────────

#[test]
fn classifier_unknown_by_default() {
    let c = AddressClassifier::new();
    assert_eq!(c.classify_addr(0x1234), AddressClass::Unknown);
}

#[test]
fn classifier_code_range() {
    let mut c = AddressClassifier::new();
    c.code_range = Some((0x1000, 0x2000));
    assert_eq!(c.classify_addr(0x1000), AddressClass::Code);
    assert_eq!(c.classify_addr(0x1FFF), AddressClass::Code);
    assert_eq!(c.classify_addr(0x2000), AddressClass::Unknown);
}

#[test]
fn classifier_heap_hint() {
    let mut c = AddressClassifier::new();
    c.heap_hints.insert(0xABCD);
    assert_eq!(c.classify_addr(0xABCD), AddressClass::Heap);
}

#[test]
fn classifier_classify_vs_top_is_unknown() {
    let c = AddressClassifier::new();
    let set = c.classify(&ValueSet::top());
    assert!(set.contains(&AddressClass::Unknown));
}

// ──────────────────────── IndirectCallResolver ──────────────────────────

#[test]
fn resolver_finds_code_targets() {
    let mut c = AddressClassifier::new();
    c.code_range = Some((0x1000, 0x2000));
    let mut s = VsaState::new();
    s.set("t", ValueSet::Concrete(vec![0x1100, 0x1200, 0x9999]));
    let states = vec![s];
    let resolver = IndirectCallResolver::new(&states, &c);
    let blocks = vec![VsaBlock {
        id: 0,
        instrs: vec![VsaInstr::IndirectCall { target: "t".into() }],
    }];
    let cfg = VsaCfg::new(blocks, vec![vec![]], 0);
    let resolutions = resolver.resolve(&cfg);
    assert_eq!(resolutions.len(), 1);
    let r = &resolutions[0];
    assert!(r.resolved_targets.contains(&0x1100));
    assert!(r.resolved_targets.contains(&0x1200));
    assert!(!r.resolved_targets.contains(&0x9999));
}

#[test]
fn resolver_top_is_imprecise() {
    let c = AddressClassifier::new();
    let mut s = VsaState::new();
    s.set("t", ValueSet::top());
    let states = vec![s];
    let resolver = IndirectCallResolver::new(&states, &c);
    let blocks = vec![VsaBlock {
        id: 0,
        instrs: vec![VsaInstr::IndirectCall { target: "t".into() }],
    }];
    let cfg = VsaCfg::new(blocks, vec![vec![]], 0);
    let r = resolver.resolve(&cfg);
    assert!(r[0].is_imprecise);
    assert!(r[0].resolved_targets.is_empty());
}

// ──────────────────────── StridedInterval ───────────────────────────────

#[test]
fn si_bottom_top_predicates() {
    assert!(StridedInterval::BOTTOM.is_bottom());
    assert!(StridedInterval::TOP.is_top());
    assert!(!StridedInterval::TOP.is_bottom());
    assert!(!StridedInterval::BOTTOM.is_top());
}

#[test]
fn si_new_lo_gt_hi_is_bottom() {
    assert!(StridedInterval::new(10, 5, 1).is_bottom());
}

#[test]
fn si_new_snaps_hi_down() {
    // [0,9]/3 should snap hi to 9 (reachable: 0,3,6,9)
    let s = StridedInterval::new(0, 9, 3);
    assert_eq!(s.hi, 9);
    // [0,10]/3 should snap to 9
    let s = StridedInterval::new(0, 10, 3);
    assert_eq!(s.hi, 9);
}

#[test]
fn si_singleton_predicate() {
    let s = StridedInterval::singleton(7);
    assert!(s.is_singleton());
    assert!(s.contains(7));
    assert!(!s.contains(8));
}

#[test]
fn si_contains_stride() {
    let s = StridedInterval::new(0, 10, 2);
    assert!(s.contains(0));
    assert!(s.contains(2));
    assert!(!s.contains(3));
    assert!(s.contains(10));
    assert!(!s.contains(11));
}

#[test]
fn si_join_bottom_identity() {
    let s = StridedInterval::singleton(3);
    assert_eq!(s.join(&StridedInterval::BOTTOM), s);
    assert_eq!(StridedInterval::BOTTOM.join(&s), s);
}

#[test]
fn si_join_extends_bounds() {
    let a = StridedInterval::interval(0, 4);
    let b = StridedInterval::interval(8, 12);
    let j = a.join(&b);
    assert!(j.lo == 0);
    assert!(j.hi == 12);
}

#[test]
fn si_meet_disjoint_is_bottom() {
    let a = StridedInterval::interval(0, 4);
    let b = StridedInterval::interval(10, 14);
    assert!(a.meet(&b).is_bottom());
}

#[test]
fn si_meet_overlap() {
    let a = StridedInterval::interval(0, 10);
    let b = StridedInterval::interval(5, 15);
    let m = a.meet(&b);
    assert!(!m.is_bottom());
    assert!(m.contains(5));
    assert!(m.contains(10));
}

#[test]
fn si_add_basic() {
    let a = StridedInterval::singleton(3);
    let b = StridedInterval::singleton(4);
    let r = a.add(&b);
    assert_eq!(r, StridedInterval::singleton(7));
}

#[test]
fn si_sub_basic() {
    let a = StridedInterval::singleton(10);
    let b = StridedInterval::singleton(3);
    assert_eq!(a.sub(&b), StridedInterval::singleton(7));
}

#[test]
fn si_widen_unstable_upper() {
    let a = StridedInterval::interval(0, 4);
    let b = StridedInterval::interval(0, 8);
    let w = a.widen(&b);
    assert!(w.hi == u64::MAX || w.is_top());
}

#[test]
fn si_concretize_singleton() {
    let s = StridedInterval::singleton(5);
    assert_eq!(s.concretize(10), Some(vec![5]));
}

#[test]
fn si_concretize_stride() {
    let s = StridedInterval::new(0, 8, 2);
    assert_eq!(s.concretize(10), Some(vec![0, 2, 4, 6, 8]));
}

#[test]
fn si_concretize_top_is_none() {
    assert_eq!(StridedInterval::TOP.concretize(10), None);
}

#[test]
fn si_concretize_bottom_is_empty() {
    assert_eq!(StridedInterval::BOTTOM.concretize(10), Some(vec![]));
}

#[test]
fn si_concretize_over_limit() {
    let s = StridedInterval::interval(0, 100);
    assert_eq!(s.concretize(10), None);
}

#[test]
fn si_bitwise_and_singletons() {
    let a = StridedInterval::singleton(0xff);
    let b = StridedInterval::singleton(0x0f);
    assert_eq!(a.bitwise_and(&b), StridedInterval::singleton(0x0f));
}

#[test]
fn si_bitwise_or_singletons() {
    let a = StridedInterval::singleton(0xf0);
    let b = StridedInterval::singleton(0x0f);
    assert_eq!(a.bitwise_or(&b), StridedInterval::singleton(0xff));
}

#[test]
fn si_display_singleton() {
    let s = format!("{}", StridedInterval::singleton(0x10));
    assert!(s.contains("0x10"));
}

// ──────────────────────── null / OOB helpers ────────────────────────────

#[test]
fn null_helpers() {
    assert!(is_definitely_null(&StridedInterval::singleton(0)));
    assert!(!is_definitely_null(&StridedInterval::singleton(1)));
    assert!(!is_definitely_null(&StridedInterval::BOTTOM));
    assert!(!is_definitely_null(&StridedInterval::interval(0, 4)));
}

#[test]
fn oob_helpers() {
    let s = StridedInterval::interval(10, 20);
    // bounds [base=10, limit=21) is in range
    assert!(!may_be_out_of_bounds(&s, (10, 21)));
    // bounds [11,21) — lo=10 < 11, OOB
    assert!(may_be_out_of_bounds(&s, (11, 21)));
    // bounds [10,20) — hi=20 >= 20, OOB
    assert!(may_be_out_of_bounds(&s, (10, 20)));
    // Top always OOB
    assert!(may_be_out_of_bounds(&StridedInterval::TOP, (0, 100)));
    // Bottom never OOB
    assert!(!may_be_out_of_bounds(&StridedInterval::BOTTOM, (0, 100)));
}

// ──────────────────────── MemoryAbstraction ─────────────────────────────

#[test]
fn ma_empty_load_is_bottom() {
    let ma = MemoryAbstraction::new();
    assert!(ma.load(&StridedInterval::singleton(0x100)).is_bottom());
}

#[test]
fn ma_strong_update() {
    let mut ma = MemoryAbstraction::new();
    ma.store(StridedInterval::singleton(0x100), StridedInterval::singleton(42));
    assert_eq!(ma.load(&StridedInterval::singleton(0x100)), StridedInterval::singleton(42));
}

#[test]
fn ma_strong_update_overwrites() {
    let mut ma = MemoryAbstraction::new();
    ma.store(StridedInterval::singleton(0x100), StridedInterval::singleton(1));
    ma.store(StridedInterval::singleton(0x100), StridedInterval::singleton(2));
    assert_eq!(ma.load(&StridedInterval::singleton(0x100)), StridedInterval::singleton(2));
}

#[test]
fn ma_bottom_addr_no_op() {
    let mut ma = MemoryAbstraction::new();
    ma.store(StridedInterval::BOTTOM, StridedInterval::singleton(1));
    assert_eq!(ma.cell_count(), 0);
}

#[test]
fn ma_bottom_addr_load_is_bottom() {
    let mut ma = MemoryAbstraction::new();
    ma.store(StridedInterval::singleton(0x100), StridedInterval::singleton(1));
    assert!(ma.load(&StridedInterval::BOTTOM).is_bottom());
}

// ──────────────────────── RegisterState ─────────────────────────────────

#[test]
fn rs_get_missing_is_bottom() {
    let r = RegisterState::default();
    assert!(r.get("rax").is_bottom());
}

#[test]
fn rs_set_get() {
    let mut r = RegisterState::default();
    r.set("rax", StridedInterval::singleton(7));
    assert_eq!(r.get("rax"), StridedInterval::singleton(7));
}

#[test]
fn rs_join_pointwise() {
    let mut a = RegisterState::default();
    a.set("rax", StridedInterval::singleton(1));
    let mut b = RegisterState::default();
    b.set("rax", StridedInterval::singleton(2));
    let j = a.join(&b);
    let v = j.get("rax");
    assert!(v.contains(1));
    assert!(v.contains(2));
}

#[test]
fn rs_leq_reflexive_on_empty() {
    let r = RegisterState::default();
    assert!(r.leq(&r));
}

// ──────────────────────── ValueSetResult ────────────────────────────────

#[test]
fn vsr_reg_at_oob_is_none() {
    let r = ValueSetResult::default();
    assert!(r.reg_at(0, "rax").is_none());
}

#[test]
fn vsr_is_null_at_present_register() {
    let mut rs = RegisterState::default();
    rs.set("rax", StridedInterval::singleton(0));
    let r = ValueSetResult {
        register_states: vec![rs],
        ..Default::default()
    };
    assert!(r.is_null_at(0, "rax"));
    assert!(!r.is_null_at(0, "rbx"));
}

#[test]
fn vsr_may_oob_at() {
    let mut rs = RegisterState::default();
    rs.set("rax", StridedInterval::interval(0, 100));
    let r = ValueSetResult {
        register_states: vec![rs],
        ..Default::default()
    };
    assert!(r.may_oob_at(0, "rax", (10, 50)));
}

// ──────────────────────── jumptable re-exports ──────────────────────────

#[test]
fn jt_scale_via_reexport() {
    let v = ValueSet::strided(0, 3, 1);
    let s = vs_scale(&v, 4);
    assert_eq!(s.concretize(16), Some(vec![0, 4, 8, 12]));
}

#[test]
fn jt_offset_via_reexport() {
    let v = ValueSet::singleton(0);
    let o = vs_offset(&v, 0x1000);
    assert_eq!(o, ValueSet::singleton(0x1000));
}

#[test]
fn jt_widen_via_reexport() {
    let prev = ValueSet::interval(0, 4);
    let next = ValueSet::interval(0, 8);
    let w = vs_widen(&prev, &next);
    assert!(matches!(w, ValueSet::Range { hi, .. } if hi == u64::MAX) || w.is_top());
}

#[test]
fn jt_bound_jump_table_basic() {
    let idx = ValueSet::interval(0, 7);
    let b = bound_jump_table(&idx, 4).unwrap();
    assert_eq!(b.entry_count, 8);
    assert_eq!(b.byte_span, 32);
}

#[test]
fn jt_bound_top_none() {
    assert!(bound_jump_table(&ValueSet::Top, 4).is_none());
    assert!(bound_jump_table(&ValueSet::Bottom, 4).is_none());
}

#[test]
fn jt_table_image_le_read() {
    let bytes = [0x10, 0x00, 0x00, 0x00];
    let img = TableImage::new(0x4000, &bytes, Endian::Little);
    assert_eq!(img.read(0x4000, 4), Some(0x10));
    assert_eq!(img.read(0x3FFF, 4), None);
    assert_eq!(img.read(0x4001, 4), None); // OOB read
}

#[test]
fn jt_resolve_switch_end_to_end() {
    let mut data = Vec::new();
    for t in [0x1100u32, 0x1200, 0x1300] {
        data.extend_from_slice(&t.to_le_bytes());
    }
    let img = TableImage::new(0x4000, &data, Endian::Little);
    let idx = ValueSet::interval(0, 2);
    let targets = resolve_switch(&idx, 0x4000, 4, &img, 16);
    assert_eq!(targets, vec![0x1100, 0x1200, 0x1300]);
}

#[test]
fn jt_resolve_indirect_top_is_empty() {
    let img = TableImage::new(0x4000, &[], Endian::Little);
    assert!(resolve_indirect_targets(&ValueSet::Top, &img, 4, 16).is_empty());
}

#[test]
fn jt_bounds_struct_fields() {
    let b = JumpTableBounds {
        min_index: 0,
        max_index: 7,
        entry_count: 8,
        byte_span: 32,
    };
    assert_eq!(b.byte_span, 32);
}

// ──────────────────────── Serde round-trips ─────────────────────────────

#[test]
fn vs_serde_roundtrip_concrete() {
    let v = ValueSet::Concrete(vec![1, 2, 3]);
    let s = serde_json::to_string(&v).unwrap();
    let back: ValueSet = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}

#[test]
fn vs_serde_roundtrip_range() {
    let v = ValueSet::Range { lo: 0, hi: 100, stride: 4 };
    let s = serde_json::to_string(&v).unwrap();
    let back: ValueSet = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}

#[test]
fn si_serde_roundtrip() {
    let s = StridedInterval::new(0, 16, 4);
    let txt = serde_json::to_string(&s).unwrap();
    let back: StridedInterval = serde_json::from_str(&txt).unwrap();
    assert_eq!(back, s);
}

// ──────────────────────── Resolution shape ──────────────────────────────

#[test]
fn resolution_serializes() {
    let r = IndirectCallResolution {
        block_id: 3,
        target_var: "foo".into(),
        resolved_targets: vec![0x1, 0x2],
        is_imprecise: false,
    };
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.contains("\"block_id\":3"));
}

// ──────────────────────── End-to-end small VSA ──────────────────────────

#[test]
fn end_to_end_loop_converges() {
    // Block 0: x = 0
    // Block 1: x = x + 1; loop back to 1
    // Block 2: exit
    let blocks = vec![
        VsaBlock {
            id: 0,
            instrs: vec![VsaInstr::Const { dst: "x".into(), value: 0 }],
        },
        VsaBlock {
            id: 1,
            instrs: vec![
                VsaInstr::Const { dst: "one".into(), value: 1 },
                VsaInstr::Add { dst: "x".into(), lhs: "x".into(), rhs: "one".into() },
            ],
        },
        VsaBlock { id: 2, instrs: vec![] },
    ];
    let cfg = VsaCfg::new(blocks, vec![vec![1], vec![1, 2], vec![]], 0);
    let a = VsaAnalyzer::new(VsaState::new());
    let res = a.run(&cfg);
    // Should not return EmptyProgram. Either converges or hits NoConvergence
    // — this is a real-world stress test of widening, so flag if no convergence.
    match res {
        Ok(_) => {}
        Err(VsaError::NoConvergence) => panic!("VSA failed to converge on simple counter loop"),
        Err(e) => panic!("unexpected error: {:?}", e),
    }
}
