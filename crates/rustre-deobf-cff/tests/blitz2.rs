//! Deep adversarial coverage for `rustre-deobf-cff` public API.

use rustre_core::address::Address;
use rustre_deobf_cff::{
    BlockMapping, CffCandidate, CffDeflattener, CffDeobfuscationPass, CffDetector,
    CffDispatcher, CffDispatcherDetector, CffPattern, CffRecoverer, CffVerifier,
    CfgEdge, ConstLattice, EdgeType, RecoveredEdgeType,
    SimpleBb, SimpleCfg, StateGraph, StateTransitionAnalyzer, StateVariable,
};
use rustre_deobf_cff::ollvm::{
    OllvmDetector, OllvmPatch, StateAssignment, StateVarTracker, SubDispatcherMap,
};

// ---------- LCG fuzz seed ----------
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn bb(addr: u64, succ: usize, pred: usize, instr: usize) -> SimpleBb {
    SimpleBb {
        address: Address::new(addr),
        successor_count: succ,
        predecessor_count: pred,
        instr_count: instr,
        ends_with_indirect_jump: false,
        ends_with_conditional: false,
        sets_register: None,
        state_const: None,
    }
}

fn make_cff(body: usize) -> SimpleCfg {
    let mut blocks = vec![bb(0x1000, 1, 0, 3)];
    let mut disp = bb(0x1010, body, 1 + body, 4);
    disp.ends_with_conditional = true;
    blocks.push(disp);
    for i in 0..body {
        let mut b = bb(0x1020 + (i as u64) * 0x10, 1, 1, 5);
        b.sets_register = Some("eax".into());
        b.state_const = Some(0x100 + i as u64);
        blocks.push(b);
    }
    let mut edges = vec![(0, 1, EdgeType::Unconditional)];
    for i in 0..body {
        edges.push((1, 2 + i, EdgeType::TrueBranch));
        edges.push((2 + i, 1, EdgeType::Unconditional));
    }
    SimpleCfg { blocks, edges }
}

// =======================================================================
// 1-5: BlockMapping basics + round-trip
// =======================================================================

#[test]
fn t01_blockmapping_empty_defaults() {
    let m = BlockMapping::new();
    assert_eq!(m.block_count(), 0);
    assert!(!m.is_complete());
    assert!(m.block_for_state(0).is_none());
    assert!(m.states_for_block(Address::new(0)).is_empty());
}

#[test]
fn t02_blockmapping_default_eq_new() {
    let a = BlockMapping::default();
    let b = BlockMapping::new();
    assert_eq!(a.block_count(), b.block_count());
}

#[test]
fn t03_blockmapping_insert_roundtrip_50() {
    let mut g = lcg();
    let mut m = BlockMapping::new();
    let mut pairs = vec![];
    for _ in 0..50 {
        let s = g();
        let addr = Address::new(g() & 0xFFFF_FFFF);
        m.insert(s, addr);
        pairs.push((s, addr));
    }
    for (s, addr) in &pairs {
        // Last write wins (HashMap semantics) — find what was actually mapped.
        let got = m.block_for_state(*s).unwrap();
        let states = m.states_for_block(got);
        assert!(states.contains(s), "state {} should map back to its block", s);
        let _ = addr;
    }
    assert!(m.is_complete());
}

#[test]
fn t04_blockmapping_multiple_states_one_block() {
    let mut m = BlockMapping::new();
    let a = Address::new(0x4000);
    m.insert(1, a);
    m.insert(2, a);
    m.insert(3, a);
    assert_eq!(m.block_count(), 1);
    let mut s = m.states_for_block(a).to_vec();
    s.sort();
    assert_eq!(s, vec![1, 2, 3]);
}

#[test]
fn t05_blockmapping_is_complete_when_dangling() {
    let mut m = BlockMapping::new();
    // Manually insert into state_to_block-only would require mutation;
    // is_complete must return true on a normally built mapping.
    m.insert(0xAA, Address::new(0x100));
    assert!(m.is_complete());
}

// =======================================================================
// 6-10: CffDetector
// =======================================================================

#[test]
fn t06_detector_default_params() {
    let d = CffDetector::default();
    assert_eq!(d.min_block_count, 5);
    assert!((d.min_confidence - 0.6).abs() < 1e-6);
    assert_eq!(d.max_dispatcher_preds, 50);
}

#[test]
fn t07_detector_builder_overrides() {
    let d = CffDetector::new().with_min_blocks(10).with_min_confidence(0.9);
    assert_eq!(d.min_block_count, 10);
    assert!((d.min_confidence - 0.9).abs() < 1e-6);
}

#[test]
fn t08_detector_rejects_small_cfg() {
    let d = CffDetector::new();
    let cfg = SimpleCfg { blocks: vec![bb(0, 0, 0, 1)], edges: vec![] };
    assert!(d.detect(&cfg, Address::new(0)).is_none());
}

#[test]
fn t09_detector_finds_cff() {
    let d = CffDetector::new();
    let cfg = make_cff(6);
    let cand = d.detect(&cfg, Address::new(0x1000)).expect("should detect");
    assert_eq!(cand.dispatcher_address, Address::new(0x1010));
    assert!(cand.confidence >= 0.6);
    assert_eq!(cand.block_count, cfg.blocks.len());
}

#[test]
fn t10_detector_max_disp_preds_rejects_huge() {
    let d = CffDetector::new();
    // Construct CFG with dispatcher having >50 preds.
    let cfg = make_cff(60);
    // The dispatcher would have 1 + 60 = 61 preds → above threshold.
    assert!(d.detect(&cfg, Address::new(0x1000)).is_none());
}

// =======================================================================
// 11-15: find_dispatcher / compute_confidence boundaries
// =======================================================================

#[test]
fn t11_find_dispatcher_empty() {
    let d = CffDetector::new();
    let cfg = SimpleCfg { blocks: vec![], edges: vec![] };
    assert!(d.find_dispatcher(&cfg).is_none());
}

#[test]
fn t12_find_dispatcher_needs_two_preds() {
    let d = CffDetector::new();
    let cfg = SimpleCfg {
        blocks: vec![bb(0, 1, 0, 1), bb(0x10, 0, 1, 1)],
        edges: vec![(0, 1, EdgeType::Unconditional)],
    };
    assert!(d.find_dispatcher(&cfg).is_none());
}

#[test]
fn t13_compute_confidence_bounds() {
    let d = CffDetector::new();
    let cfg = make_cff(6);
    let (idx, _) = d.find_dispatcher(&cfg).unwrap();
    let c = d.compute_confidence(&cfg, idx);
    assert!((0.0..=1.0).contains(&c));
}

#[test]
fn t14_compute_confidence_oob_idx() {
    let d = CffDetector::new();
    let cfg = make_cff(6);
    assert_eq!(d.compute_confidence(&cfg, 999), 0.0);
}

#[test]
fn t15_compute_confidence_tiny_cfg() {
    let d = CffDetector::new();
    let cfg = SimpleCfg { blocks: vec![bb(0, 0, 0, 1)], edges: vec![] };
    assert_eq!(d.compute_confidence(&cfg, 0), 0.0);
}

// =======================================================================
// 16-20: identify_state_variable, pattern classification
// =======================================================================

#[test]
fn t16_identify_state_var_register() {
    let d = CffDetector::new();
    let cfg = make_cff(5);
    let (idx, _) = d.find_dispatcher(&cfg).unwrap();
    let sv = d.identify_state_variable(&cfg, idx);
    assert_eq!(sv, StateVariable::Register("eax".into()));
}

#[test]
fn t17_identify_state_var_unknown_when_no_writes() {
    let d = CffDetector::new();
    let mut cfg = make_cff(5);
    for b in &mut cfg.blocks {
        b.sets_register = None;
    }
    let (idx, _) = d.find_dispatcher(&cfg).unwrap();
    assert_eq!(d.identify_state_variable(&cfg, idx), StateVariable::Unknown);
}

#[test]
fn t18_pattern_jumptable_via_indirect() {
    let d = CffDetector::new();
    let mut cfg = make_cff(6);
    cfg.blocks[1].ends_with_indirect_jump = true;
    let cand = d.detect(&cfg, Address::new(0x1000)).unwrap();
    assert_eq!(cand.pattern, CffPattern::JumpTable);
}

#[test]
fn t19_statevariable_display_all_variants() {
    assert_eq!(format!("{}", StateVariable::Register("rcx".into())), "reg:rcx");
    assert_eq!(format!("{}", StateVariable::StackSlot(-8)), "stack[-8]");
    // Address Display formats with the crate's specific style (hex prefix only).
    assert_eq!(format!("{}", StateVariable::GlobalMemory(Address::new(0xABC))), "mem:0xABC");
    assert_eq!(format!("{}", StateVariable::Unknown), "<unknown>");
}

#[test]
fn t20_cffpattern_display_all() {
    for (p, s) in [
        (CffPattern::Dispatcher, "Dispatcher"),
        (CffPattern::JumpTable, "JumpTable"),
        (CffPattern::LinearSearch, "LinearSearch"),
        (CffPattern::NestedDispatch, "NestedDispatch"),
        (CffPattern::Unknown, "Unknown"),
    ] {
        assert_eq!(format!("{}", p), s);
    }
}

// =======================================================================
// 21-25: Recoverer / RecoveredCfg
// =======================================================================

#[test]
fn t21_recoverer_full_pipeline() {
    let d = CffDetector::new();
    let r = CffRecoverer::new();
    let cfg = make_cff(6);
    let cand = d.detect(&cfg, Address::new(0x1000)).unwrap();
    let rec = r.recover(&cand, &cfg);
    assert_eq!(rec.function_start, Address::new(0x1000));
    assert_eq!(rec.dispatcher_address, Address::new(0x1010));
    assert!(rec.block_count() >= 1);
    // Recovered edges should not include the dispatcher as source.
    for e in &rec.edges {
        assert_ne!(e.from_block, rec.dispatcher_address);
    }
}

#[test]
fn t22_recoverer_default_params() {
    let r = CffRecoverer::default();
    assert_eq!(r.max_state_trace_depth, 32);
    assert!(r.enable_symbolic_eval);
}

#[test]
fn t23_recovered_cfg_succ_pred() {
    let d = CffDetector::new();
    let r = CffRecoverer::new();
    let cfg = make_cff(6);
    let cand = d.detect(&cfg, Address::new(0x1000)).unwrap();
    let rec = r.recover(&cand, &cfg);
    assert!(rec.is_entry(Address::new(0x1000)));
    let _succs: Vec<_> = rec.successors(Address::new(0x1020));
    let _preds: Vec<_> = rec.predecessors(Address::new(0x1020));
    assert_eq!(rec.edge_count(), rec.edges.len());
}

#[test]
fn t24_recoverer_no_dispatcher_returns_empty_edges() {
    let r = CffRecoverer::new();
    let cfg = SimpleCfg {
        blocks: vec![bb(0, 0, 0, 1)],
        edges: vec![],
    };
    let cand = CffCandidate {
        function_start: Address::new(0),
        dispatcher_address: Address::new(0xDEAD), // not in cfg
        state_variable: StateVariable::Unknown,
        block_count: 1,
        confidence: 0.7,
        pattern: CffPattern::Unknown,
    };
    let mapping = r.build_block_mapping(&cand, &cfg);
    assert_eq!(mapping.block_count(), 0);
    let edges = r.reconstruct_edges(&cand, &mapping, &cfg);
    assert!(edges.is_empty());
}

#[test]
fn t25_trace_state_max_depth() {
    let r = CffRecoverer::new();
    let mapping = BlockMapping::new();
    // No mapping → None even at depth 32.
    assert!(r.trace_state(0xDEAD, &mapping).is_none());
}

// =======================================================================
// 26-30: scan_block_state_const — x86 byte parser
// =======================================================================

#[test]
fn t26_scan_mov_r32_imm32() {
    // MOV EAX, 0xCAFEBABE → B8 BE BA FE CA
    let bytes = [0xB8, 0xBE, 0xBA, 0xFE, 0xCA];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), Some(0xCAFEBABE));
}

#[test]
fn t27_scan_mov_r64_imm64_rexw() {
    // 48 B8 .. — MOV RAX, 0x1122334455667788
    let bytes = [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    assert_eq!(
        CffRecoverer::scan_block_state_const(&bytes),
        Some(0x1122334455667788)
    );
}

#[test]
fn t28_scan_mov_rm32_imm32_c7_form() {
    // C7 C0 imm32 → MOV EAX, imm32
    let bytes = [0xC7, 0xC0, 0xEF, 0xBE, 0xAD, 0xDE];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), Some(0xDEADBEEF));
}

#[test]
fn t29_scan_empty_and_truncated() {
    assert!(CffRecoverer::scan_block_state_const(&[]).is_none());
    assert!(CffRecoverer::scan_block_state_const(&[0xB8, 0x01]).is_none());
}

#[test]
fn t30_scan_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() % 64) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (g() & 0xFF) as u8;
        }
        let _ = CffRecoverer::scan_block_state_const(&buf);
    }
}

// =======================================================================
// 31-35: ConstLattice meet algebra
// =======================================================================

#[test]
fn t31_lattice_top_identity() {
    for v in [0u64, 1, u64::MAX, 42] {
        assert_eq!(ConstLattice::Top.meet(ConstLattice::Const(v)), ConstLattice::Const(v));
        assert_eq!(ConstLattice::Const(v).meet(ConstLattice::Top), ConstLattice::Const(v));
    }
    assert_eq!(ConstLattice::Top.meet(ConstLattice::Top), ConstLattice::Top);
    assert_eq!(ConstLattice::Top.meet(ConstLattice::Bottom), ConstLattice::Bottom);
}

#[test]
fn t32_lattice_const_equal() {
    assert_eq!(ConstLattice::Const(7).meet(ConstLattice::Const(7)), ConstLattice::Const(7));
}

#[test]
fn t33_lattice_const_unequal_to_bottom() {
    assert_eq!(ConstLattice::Const(1).meet(ConstLattice::Const(2)), ConstLattice::Bottom);
}

#[test]
fn t34_lattice_bottom_absorbing() {
    assert_eq!(ConstLattice::Bottom.meet(ConstLattice::Const(5)), ConstLattice::Bottom);
    assert_eq!(ConstLattice::Const(5).meet(ConstLattice::Bottom), ConstLattice::Bottom);
    assert_eq!(ConstLattice::Bottom.meet(ConstLattice::Bottom), ConstLattice::Bottom);
}

#[test]
fn t35_lattice_as_const() {
    assert_eq!(ConstLattice::Const(99).as_const(), Some(99));
    assert_eq!(ConstLattice::Top.as_const(), None);
    assert_eq!(ConstLattice::Bottom.as_const(), None);
}

// =======================================================================
// 36-40: Verifier + Pass + Dispatcher detection
// =======================================================================

#[test]
fn t36_verifier_clean_on_recovered() {
    let pass = CffDeobfuscationPass::new();
    let cfg = make_cff(6);
    let rec = pass.run_on_function(&cfg, Address::new(0x1000)).expect("recoverable");
    let v = CffVerifier::new();
    let res = v.verify(&rec);
    assert_eq!(res.block_count, rec.block_count());
    // Dispatcher must not appear in recovered.blocks.
    assert!(!rec.blocks.contains(&rec.dispatcher_address));
    assert!(res.is_valid);
}

#[test]
fn t37_pass_rejects_non_cff_linear() {
    let pass = CffDeobfuscationPass::new();
    let cfg = SimpleCfg {
        blocks: (0..4).map(|i| bb(0x2000 + i * 0x10, if i < 3 {1} else {0}, if i > 0 {1} else {0}, 3)).collect(),
        edges: vec![
            (0, 1, EdgeType::Unconditional),
            (1, 2, EdgeType::Unconditional),
            (2, 3, EdgeType::Unconditional),
        ],
    };
    assert!(pass.run_on_function(&cfg, Address::new(0x2000)).is_none());
}

#[test]
fn t38_dispatcher_detector_min_handlers() {
    assert_eq!(CffDispatcherDetector::MIN_HANDLER_COUNT, 5);
    // Empty code: no detections.
    assert!(CffDispatcherDetector::detect(&[], 0).is_empty());
}

#[test]
fn t39_dispatcher_detector_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() % 256) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (g() & 0xFF) as u8;
        }
        let _ = CffDispatcherDetector::detect(&buf, g());
    }
}

#[test]
fn t40_dispatcher_detector_recognises_pattern_a() {
    // 5 consecutive `83 3D <disp32> <imm8> JZ <rel8>` pairs.
    let mut code = vec![];
    for i in 0..5u8 {
        code.extend_from_slice(&[0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, i, 0x74, 0x02]);
    }
    let res = CffDispatcherDetector::detect(&code, 0x4000);
    assert!(!res.is_empty(), "should detect at least one dispatcher");
    assert!(res[0].handler_count >= CffDispatcherDetector::MIN_HANDLER_COUNT);
}

// =======================================================================
// 41-46: StateGraph + Deflattener + StateTransitionAnalyzer
// =======================================================================

#[test]
fn t41_stategraph_basic() {
    let mut g = StateGraph::new();
    assert!(g.is_empty());
    g.add_edge(0, 1, None);
    g.add_edge(0, 2, Some(true));
    g.add_edge(1, 3, Some(false));
    assert_eq!(g.state_count(), 2);
    assert_eq!(g.transitions(0).len(), 2);
    let tgts = g.all_targets();
    assert!(tgts.contains(&1) && tgts.contains(&2) && tgts.contains(&3));
}

#[test]
fn t42_deflattener_sorted_output() {
    let mut g = StateGraph::new();
    g.add_edge(3, 9, None);
    g.add_edge(1, 7, None);
    g.add_edge(1, 2, None);
    let disp = CffDispatcher { addr: 0, state_var_addr: 0, handler_count: 5 };
    let edges = CffDeflattener::deflaten(&disp, &g);
    assert_eq!(edges.len(), 3);
    // Sorted ascending by (from, to).
    for w in edges.windows(2) {
        let cmp = (w[0].from_state, w[0].to_state) <= (w[1].from_state, w[1].to_state);
        assert!(cmp);
    }
}

#[test]
fn t43_deflattener_cfgedge_eq() {
    let e1 = CfgEdge { from_state: 1, to_state: 2, condition: Some(true) };
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn t44_estimate_cff_confidence_empty() {
    assert_eq!(CffDeflattener::estimate_cff_confidence(&[]), 0.0);
}

#[test]
fn t45_estimate_cff_confidence_in_range_fuzz() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = ((g() % 512) + 1) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (g() & 0xFF) as u8;
        }
        let s = CffDeflattener::estimate_cff_confidence(&buf);
        assert!((0.0..=1.0).contains(&s));
    }
}

#[test]
fn t46_state_transition_analyzer_empty_code() {
    let disp = CffDispatcher { addr: 0, state_var_addr: 0x9000, handler_count: 5 };
    let g = StateTransitionAnalyzer::analyze(&disp, &[]);
    assert!(g.is_empty());
}

// =======================================================================
// 47-52: SimpleCfg + OLLVM helpers
// =======================================================================

#[test]
fn t47_simplecfg_recompute_predecessor_counts() {
    let mut cfg = make_cff(5);
    for b in &mut cfg.blocks {
        b.predecessor_count = 0;
    }
    cfg.recompute_predecessor_counts();
    // Dispatcher (index 1) should have 6 preds: entry + 5 body.
    assert_eq!(cfg.blocks[1].predecessor_count, 6);
    // Body blocks have 1 pred (from dispatcher).
    for i in 2..cfg.blocks.len() {
        assert_eq!(cfg.blocks[i].predecessor_count, 1);
    }
}

#[test]
fn t48_state_var_tracker_basic() {
    let mut t = StateVarTracker::new();
    assert!(t.is_empty());
    t.record(Address::new(0x100), 42, false);
    t.record(Address::new(0x200), 42, true);
    let blocks = t.blocks_for_state(42);
    assert_eq!(blocks.len(), 2);
    assert_eq!(t.writer_count(), 2);
    let mut states = t.all_states();
    states.sort();
    assert_eq!(states, vec![42]);
}

#[test]
fn t49_state_var_tracker_merge() {
    let mut a = StateVarTracker::new();
    a.record(Address::new(0x100), 1, false);
    let mut b = StateVarTracker::new();
    b.record(Address::new(0x200), 2, false);
    a.merge(b);
    assert!(!a.blocks_for_state(1).is_empty());
    assert!(!a.blocks_for_state(2).is_empty());
}

#[test]
fn t50_state_var_tracker_to_block_mapping() {
    let mut t = StateVarTracker::new();
    t.record(Address::new(0x100), 7, false);
    t.record(Address::new(0x200), 9, false);
    let m = t.to_block_mapping();
    assert_eq!(m.block_for_state(7), Some(Address::new(0x100)));
    assert_eq!(m.block_for_state(9), Some(Address::new(0x200)));
}

#[test]
fn t51_subdispatcher_map() {
    let mut m = SubDispatcherMap::new();
    assert_eq!(m.sub_count(), 0);
    m.add(Address::new(0x1000), Address::new(0x2000));
    m.add(Address::new(0x1000), Address::new(0x3000));
    assert_eq!(m.sub_count(), 2);
    assert!(m.is_sub_dispatcher(Address::new(0x2000)));
    assert_eq!(m.parent_of(Address::new(0x2000)), Some(Address::new(0x1000)));
    assert!(m.parent_of(Address::new(0xDEAD)).is_none());
}

#[test]
fn t52_ollvm_patch_constructors() {
    let p1 = OllvmPatch::nop_out(Address::new(0x100), 4, "test nop");
    let _ = p1;
    let p2 = OllvmPatch::make_unconditional(Address::new(0x200), Address::new(0x300));
    let _ = p2;
}

// =======================================================================
// 53-56: Send/Sync + thread stress + StateAssignment
// =======================================================================

#[test]
fn t53_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BlockMapping>();
    assert_send_sync::<CffDetector>();
    assert_send_sync::<CffRecoverer>();
    assert_send_sync::<CffDeobfuscationPass>();
    assert_send_sync::<StateVarTracker>();
    assert_send_sync::<SubDispatcherMap>();
    assert_send_sync::<SimpleCfg>();
    assert_send_sync::<StateGraph>();
}

#[test]
fn t54_threaded_pass_stress() {
    use std::sync::Arc;
    use std::thread;
    let cfg = Arc::new(make_cff(6));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let cfg = Arc::clone(&cfg);
            thread::spawn(move || {
                let pass = CffDeobfuscationPass::new();
                for _ in 0..100 {
                    let r = pass.run_on_function(&cfg, Address::new(0x1000));
                    assert!(r.is_some());
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t55_state_assignment_can_be_built() {
    let a = StateAssignment { block: Address::new(0x100), value: 0xAB, is_conditional: false };
    assert_eq!(a.value, 0xAB);
    assert!(!a.is_conditional);
}

#[test]
fn t56_serde_roundtrip_statevariable() {
    for sv in [
        StateVariable::Register("rdi".into()),
        StateVariable::StackSlot(-16),
        StateVariable::GlobalMemory(Address::new(0xCAFE)),
        StateVariable::Unknown,
    ] {
        let j = serde_json::to_string(&sv).unwrap();
        let back: StateVariable = serde_json::from_str(&j).unwrap();
        assert_eq!(back, sv);
    }
}

// =======================================================================
// 57-60: dataflow + edge boundaries
// =======================================================================

#[test]
fn t57_propagate_dataflow_with_seeded_constants() {
    let cfg = make_cff(5);
    let mut t = StateVarTracker::new();
    let lattice = t.propagate_dataflow(&cfg, Address::new(0x1010));
    assert_eq!(lattice.len(), cfg.blocks.len());
    // Body blocks have state_const set in make_cff → must be Const(_).
    for i in 0..5 {
        let addr = 0x1020 + (i as u64) * 0x10;
        match lattice.get(&addr) {
            Some(ConstLattice::Const(v)) => assert_eq!(*v, 0x100 + i),
            other => panic!("expected Const for block {:#x}, got {:?}", addr, other),
        }
    }
}

#[test]
fn t58_recover_with_dataflow_smoke() {
    let cfg = make_cff(6);
    let d = CffDetector::new();
    let cand = d.detect(&cfg, Address::new(0x1000)).unwrap();
    let r = CffRecoverer::new();
    let rec = r.recover_with_dataflow(&cand, &cfg);
    assert_eq!(rec.dispatcher_address, Address::new(0x1010));
    assert!(!rec.blocks.contains(&rec.dispatcher_address));
}

#[test]
fn t59_fold_state_expr_direct_and_truncated() {
    let mut m = BlockMapping::new();
    m.insert(0xCAFE, Address::new(0x100));
    // Direct match
    assert_eq!(CffRecoverer::fold_state_expr(0xCAFE, &m), Some(0xCAFE));
    // Truncated 64-bit → 32-bit match
    assert_eq!(
        CffRecoverer::fold_state_expr(0x1_0000_0000 | 0xCAFE, &m),
        Some(0xCAFE)
    );
    // Unknown
    assert!(CffRecoverer::fold_state_expr(0xDEAD, &m).is_none());
}

#[test]
fn t60_pass_run_on_binary_aggregates() {
    let pass = CffDeobfuscationPass::new();
    let cfgs = vec![
        (Address::new(0x1000), make_cff(6)),
        (Address::new(0x9000), make_cff(7)),
    ];
    let res = pass.run_on_binary(cfgs);
    assert_eq!(res.candidates_found, 2);
    assert_eq!(res.candidates_recovered, 2);
    assert_eq!(res.recovered.len(), 2);
}

// =======================================================================
// 61-65: more boundary/fuzz coverage
// =======================================================================

#[test]
fn t61_build_block_mapping_uses_state_const() {
    let cfg = make_cff(5);
    let d = CffDetector::new();
    let cand = d.detect(&cfg, Address::new(0x1000)).unwrap();
    let r = CffRecoverer::new();
    let m = r.build_block_mapping(&cand, &cfg);
    // body blocks have state_const = 0x100 + i.
    for i in 0..5 {
        assert_eq!(m.block_for_state(0x100 + i), Some(Address::new(0x1020 + i * 0x10)));
    }
}

#[test]
fn t62_recoverer_without_symbolic_uses_sequential_seeds() {
    let mut cfg = make_cff(4);
    for b in &mut cfg.blocks {
        b.state_const = None;
    }
    let d = CffDetector::new();
    let cand = d.detect(&cfg, Address::new(0x1000)).unwrap();
    let mut r = CffRecoverer::new();
    r.enable_symbolic_eval = false;
    let m = r.build_block_mapping(&cand, &cfg);
    // Sequential seeds 0..4 should exist.
    let states: std::collections::HashSet<u64> = m.state_to_block.keys().copied().collect();
    assert!(states.contains(&0));
    assert!(states.contains(&1));
}

#[test]
fn t63_ollvm_detector_default_min_back_edges() {
    let d = OllvmDetector::default();
    assert_eq!(d.min_back_edges, 2);
    let d2 = OllvmDetector::new().with_min_back_edges(7);
    assert_eq!(d2.min_back_edges, 7);
}

#[test]
fn t64_ollvm_detector_smoke() {
    let cfg = make_cff(6);
    let d = OllvmDetector::new();
    // Detect may succeed or fail depending on score; ensure no panic and reasonable type.
    let _ = d.detect(&cfg, Address::new(0x1000));
}

#[test]
fn t65_state_transition_analyzer_fuzz() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = ((g() % 256) + 16) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (g() & 0xFF) as u8;
        }
        let disp = CffDispatcher {
            addr: (g() % len as u64),
            state_var_addr: g(),
            handler_count: 5,
        };
        let graph = StateTransitionAnalyzer::analyze(&disp, &buf);
        // Must not panic; state_count is finite.
        let _ = graph.state_count();
    }
}
