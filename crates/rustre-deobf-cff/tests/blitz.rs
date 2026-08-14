//! Comprehensive integration tests for the public API of `rustre-deobf-cff`.

use rustre_core::address::Address;
use rustre_deobf_cff::{
    BlockMapping, CffCandidate, CffDeflattener, CffDeobfuscationPass, CffDetector,
    CffDispatcher, CffDispatcherDetector, CffPattern, CffRecoverer, CffVerifier,
    CffVerifyResult, CfgEdge, ConstLattice, DeobfResult, EdgeType, RecoveredCfg,
    RecoveredEdge, RecoveredEdgeType, SimpleBb, SimpleCfg, StateGraph,
    StateTransitionAnalyzer, StateVariable,
};

// ---------- helpers ----------
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

/// Builds a CFG: 0=entry, 1=dispatcher (high pred), 2..=N body blocks.
fn make_cff_cfg(body_count: usize) -> SimpleCfg {
    let mut blocks = vec![bb(0x1000, 1, 0, 3)];
    let mut disp = bb(0x1010, body_count, 1 + body_count, 4);
    disp.ends_with_conditional = true;
    blocks.push(disp);
    for i in 0..body_count {
        let mut b = bb(0x1020 + (i as u64) * 0x10, 1, 1, 5);
        b.sets_register = Some("eax".into());
        blocks.push(b);
    }
    let mut edges = vec![(0, 1, EdgeType::Unconditional)];
    for i in 0..body_count {
        edges.push((1, 2 + i, EdgeType::Unconditional));
        edges.push((2 + i, 1, EdgeType::Unconditional));
    }
    SimpleCfg { blocks, edges }
}

// ---------- StateVariable ----------
#[test]
fn statevar_display_register() {
    assert_eq!(StateVariable::Register("eax".into()).to_string(), "reg:eax");
}
#[test]
fn statevar_display_stack() {
    assert_eq!(StateVariable::StackSlot(-8).to_string(), "stack[-8]");
}
#[test]
fn statevar_display_global() {
    let s = StateVariable::GlobalMemory(Address::new(0x4000)).to_string();
    assert!(s.starts_with("mem:"));
}
#[test]
fn statevar_display_unknown() {
    assert_eq!(StateVariable::Unknown.to_string(), "<unknown>");
}
#[test]
fn statevar_eq() {
    assert_eq!(StateVariable::StackSlot(4), StateVariable::StackSlot(4));
    assert_ne!(StateVariable::StackSlot(4), StateVariable::StackSlot(5));
}
#[test]
fn statevar_serde_roundtrip() {
    let v = StateVariable::Register("rdi".into());
    let s = serde_json::to_string(&v).unwrap();
    let back: StateVariable = serde_json::from_str(&s).unwrap();
    assert_eq!(v, back);
}

// ---------- CffPattern ----------
#[test]
fn cffpattern_display_all() {
    assert_eq!(CffPattern::Dispatcher.to_string(), "Dispatcher");
    assert_eq!(CffPattern::JumpTable.to_string(), "JumpTable");
    assert_eq!(CffPattern::LinearSearch.to_string(), "LinearSearch");
    assert_eq!(CffPattern::NestedDispatch.to_string(), "NestedDispatch");
    assert_eq!(CffPattern::Unknown.to_string(), "Unknown");
}
#[test]
fn cffpattern_copy_eq() {
    let p = CffPattern::JumpTable;
    let q = p;
    assert_eq!(p, q);
}

// ---------- BlockMapping ----------
#[test]
fn blockmapping_default_empty() {
    let m = BlockMapping::default();
    assert_eq!(m.block_count(), 0);
    assert!(!m.is_complete());
}
#[test]
fn blockmapping_new_equals_default() {
    let a = BlockMapping::new();
    let b = BlockMapping::default();
    assert_eq!(a.block_count(), b.block_count());
}
#[test]
fn blockmapping_insert_and_lookup() {
    let mut m = BlockMapping::new();
    m.insert(0xAA, Address::new(0x100));
    m.insert(0xBB, Address::new(0x100));
    assert_eq!(m.block_for_state(0xAA), Some(Address::new(0x100)));
    assert_eq!(m.block_for_state(0xCC), None);
    let states = m.states_for_block(Address::new(0x100));
    assert_eq!(states.len(), 2);
    assert_eq!(m.block_count(), 1);
}
#[test]
fn blockmapping_states_for_unknown() {
    let m = BlockMapping::new();
    assert_eq!(m.states_for_block(Address::new(0x999)), &[] as &[u64]);
}
#[test]
fn blockmapping_is_complete() {
    let mut m = BlockMapping::new();
    m.insert(1, Address::new(0x200));
    assert!(m.is_complete());
}

// ---------- SimpleCfg ----------
#[test]
fn simplecfg_recompute_preds() {
    let mut cfg = make_cff_cfg(3);
    for b in &mut cfg.blocks {
        b.predecessor_count = 0;
    }
    cfg.recompute_predecessor_counts();
    // dispatcher (idx 1) gets entry + 3 body back-edges = 4
    assert_eq!(cfg.blocks[1].predecessor_count, 4);
    assert_eq!(cfg.blocks[0].predecessor_count, 0);
}

// ---------- CffDetector ----------
#[test]
fn detector_default_params() {
    let d = CffDetector::default();
    assert_eq!(d.min_block_count, 5);
    assert!((d.min_confidence - 0.6).abs() < 1e-6);
    assert_eq!(d.max_dispatcher_preds, 50);
}
#[test]
fn detector_builder_methods() {
    let d = CffDetector::new().with_min_blocks(10).with_min_confidence(0.9);
    assert_eq!(d.min_block_count, 10);
    assert!((d.min_confidence - 0.9).abs() < 1e-6);
}
#[test]
fn detector_too_few_blocks_returns_none() {
    let d = CffDetector::new();
    let cfg = make_cff_cfg(1); // total = 3 blocks
    assert!(d.detect(&cfg, Address::new(0x1000)).is_none());
}
#[test]
fn detector_empty_cfg_find_dispatcher_none() {
    let cfg = SimpleCfg { blocks: vec![], edges: vec![] };
    assert!(CffDetector::new().find_dispatcher(&cfg).is_none());
}
#[test]
fn detector_finds_dispatcher_for_cff_shape() {
    let d = CffDetector::new();
    let cfg = make_cff_cfg(6); // 8 total blocks
    let (idx, conf) = d.find_dispatcher(&cfg).expect("dispatcher found");
    assert_eq!(idx, 1);
    assert!(conf > 0.0);
}
#[test]
fn detector_detect_succeeds_on_cff_shape() {
    let d = CffDetector::new().with_min_confidence(0.0);
    let cfg = make_cff_cfg(6);
    let cand = d.detect(&cfg, Address::new(0x1000)).expect("detected");
    assert_eq!(cand.function_start, Address::new(0x1000));
    assert_eq!(cand.dispatcher_address, Address::new(0x1010));
    assert_eq!(cand.block_count, 8);
}
#[test]
fn detector_too_many_preds_rejected() {
    let d = CffDetector::new();
    // 60 body blocks → dispatcher has 61 preds, above max_dispatcher_preds 50.
    let cfg = make_cff_cfg(60);
    assert!(d.find_dispatcher(&cfg).is_none());
}
#[test]
fn detector_compute_confidence_oob_zero() {
    let d = CffDetector::new();
    let cfg = make_cff_cfg(3);
    assert_eq!(d.compute_confidence(&cfg, 999), 0.0);
}
#[test]
fn detector_compute_confidence_in_unit_range() {
    let d = CffDetector::new();
    let cfg = make_cff_cfg(6);
    let c = d.compute_confidence(&cfg, 1);
    assert!((0.0..=1.0).contains(&c));
}
#[test]
fn detector_identify_state_register_eax() {
    let d = CffDetector::new();
    let cfg = make_cff_cfg(4);
    match d.identify_state_variable(&cfg, 1) {
        StateVariable::Register(r) => assert_eq!(r, "eax"),
        v => panic!("expected register eax, got {v:?}"),
    }
}
#[test]
fn detector_identify_state_unknown_when_no_register() {
    let d = CffDetector::new();
    let mut cfg = make_cff_cfg(4);
    for b in &mut cfg.blocks {
        b.sets_register = None;
    }
    assert!(matches!(d.identify_state_variable(&cfg, 1), StateVariable::Unknown));
}

// ---------- CffRecoverer ----------
#[test]
fn recoverer_default_params() {
    let r = CffRecoverer::default();
    assert_eq!(r.max_state_trace_depth, 32);
    assert!(r.enable_symbolic_eval);
}
#[test]
fn recoverer_build_mapping_uses_state_const() {
    let r = CffRecoverer::new();
    let mut cfg = make_cff_cfg(3);
    for (i, b) in cfg.blocks.iter_mut().enumerate().skip(2) {
        b.state_const = Some(100 + i as u64);
    }
    let cand = CffCandidate {
        function_start: Address::new(0x1000),
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Register("eax".into()),
        block_count: cfg.blocks.len(),
        confidence: 1.0,
        pattern: CffPattern::Dispatcher,
    };
    let m = r.build_block_mapping(&cand, &cfg);
    assert!(m.block_for_state(102).is_some());
    assert!(m.block_for_state(103).is_some());
    assert!(m.block_for_state(104).is_some());
}
#[test]
fn recoverer_build_mapping_address_fallback() {
    let r = CffRecoverer::new();
    let cfg = make_cff_cfg(3);
    let cand = CffCandidate {
        function_start: Address::new(0x1000),
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        block_count: cfg.blocks.len(),
        confidence: 1.0,
        pattern: CffPattern::Dispatcher,
    };
    let m = r.build_block_mapping(&cand, &cfg);
    assert_eq!(m.block_for_state(0x1020), Some(Address::new(0x1020)));
}
#[test]
fn recoverer_build_mapping_missing_dispatcher_empty() {
    let r = CffRecoverer::new();
    let cfg = make_cff_cfg(3);
    let cand = CffCandidate {
        function_start: Address::new(0x1000),
        dispatcher_address: Address::new(0xDEAD), // not in cfg
        state_variable: StateVariable::Unknown,
        block_count: 0,
        confidence: 1.0,
        pattern: CffPattern::Unknown,
    };
    let m = r.build_block_mapping(&cand, &cfg);
    assert_eq!(m.block_count(), 0);
}
#[test]
fn recoverer_trace_state_direct_hit() {
    let r = CffRecoverer::new();
    let mut m = BlockMapping::new();
    m.insert(42, Address::new(0x500));
    assert_eq!(r.trace_state(42, &m), Some(Address::new(0x500)));
}
#[test]
fn recoverer_trace_state_miss() {
    let r = CffRecoverer::new();
    let m = BlockMapping::new();
    assert_eq!(r.trace_state(7, &m), None);
}
#[test]
fn recoverer_fold_state_truncates_high_bits() {
    let mut m = BlockMapping::new();
    m.insert(0x1234_5678, Address::new(0x800));
    let folded = CffRecoverer::fold_state_expr(0xDEAD_0000_1234_5678, &m);
    assert_eq!(folded, Some(0x1234_5678));
}
#[test]
fn recoverer_fold_state_identity() {
    let mut m = BlockMapping::new();
    m.insert(7, Address::new(0x800));
    assert_eq!(CffRecoverer::fold_state_expr(7, &m), Some(7));
}
#[test]
fn recoverer_fold_state_none_when_unknown() {
    let m = BlockMapping::new();
    assert_eq!(CffRecoverer::fold_state_expr(123, &m), None);
}
#[test]
fn recoverer_recover_full_pipeline() {
    let r = CffRecoverer::new();
    let cfg = make_cff_cfg(4);
    let cand = CffCandidate {
        function_start: Address::new(0x1000),
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Register("eax".into()),
        block_count: cfg.blocks.len(),
        confidence: 0.9,
        pattern: CffPattern::Dispatcher,
    };
    let rec = r.recover(&cand, &cfg);
    assert_eq!(rec.function_start, Address::new(0x1000));
    assert_eq!(rec.dispatcher_address, Address::new(0x1010));
    // Dispatcher excluded from blocks.
    assert!(!rec.blocks.contains(&Address::new(0x1010)));
    assert_eq!(rec.block_count(), cfg.blocks.len() - 1);
}

// ---------- RecoveredCfg helpers ----------
#[test]
fn recoveredcfg_successors_predecessors_entry() {
    let cand = CffCandidate {
        function_start: Address::new(0x1000),
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        block_count: 0,
        confidence: 0.0,
        pattern: CffPattern::Unknown,
    };
    let rec = RecoveredCfg {
        function_start: Address::new(0x1000),
        blocks: vec![Address::new(0x1000), Address::new(0x2000)],
        edges: vec![RecoveredEdge {
            from_block: Address::new(0x1000),
            to_block: Address::new(0x2000),
            edge_type: RecoveredEdgeType::Unconditional,
            state_value: None,
        }],
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        original_candidate: cand,
    };
    assert_eq!(rec.successors(Address::new(0x1000)), vec![Address::new(0x2000)]);
    assert_eq!(rec.predecessors(Address::new(0x2000)), vec![Address::new(0x1000)]);
    assert!(rec.is_entry(Address::new(0x1000)));
    assert!(!rec.is_entry(Address::new(0x2000)));
    assert_eq!(rec.block_count(), 2);
    assert_eq!(rec.edge_count(), 1);
}

// ---------- scan_block_state_const ----------
#[test]
fn scan_state_const_empty() {
    assert_eq!(CffRecoverer::scan_block_state_const(&[]), None);
}
#[test]
fn scan_state_const_mov_r32_imm32() {
    // B8 78 56 34 12  → MOV EAX, 0x12345678
    let bytes = [0xB8u8, 0x78, 0x56, 0x34, 0x12];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), Some(0x12345678));
}
#[test]
fn scan_state_const_mov_r64_imm64() {
    // 48 B8 + 8 bytes → MOV RAX, imm64
    let bytes = [0x48u8, 0xB8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    assert_eq!(
        CffRecoverer::scan_block_state_const(&bytes),
        Some(0x8877665544332211)
    );
}
#[test]
fn scan_state_const_mov_rm32_imm32() {
    // C7 C0 78 56 34 12 → MOV EAX, 0x12345678
    let bytes = [0xC7u8, 0xC0, 0x78, 0x56, 0x34, 0x12];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), Some(0x12345678));
}
#[test]
fn scan_state_const_returns_last() {
    // Two MOVs, then JMP.
    let bytes = [
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
        0xEB, 0x00, // jmp
    ];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), Some(2));
}
#[test]
fn scan_state_const_stops_at_jmp() {
    let bytes = [
        0xB8, 0x99, 0x00, 0x00, 0x00, // mov eax, 0x99
        0xEB, 0x00, // jmp short
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax, 0x77 (after jmp, ignored)
    ];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), Some(0x99));
}
#[test]
fn scan_state_const_no_match() {
    let bytes = [0x90u8, 0x90, 0x90];
    assert_eq!(CffRecoverer::scan_block_state_const(&bytes), None);
}

// ---------- ConstLattice ----------
#[test]
fn constlattice_meet_top_identity() {
    assert_eq!(ConstLattice::Top.meet(ConstLattice::Const(5)), ConstLattice::Const(5));
    assert_eq!(ConstLattice::Const(5).meet(ConstLattice::Top), ConstLattice::Const(5));
}
#[test]
fn constlattice_meet_equal_consts() {
    assert_eq!(
        ConstLattice::Const(3).meet(ConstLattice::Const(3)),
        ConstLattice::Const(3)
    );
}
#[test]
fn constlattice_meet_different_consts_bottom() {
    assert_eq!(
        ConstLattice::Const(3).meet(ConstLattice::Const(4)),
        ConstLattice::Bottom
    );
}
#[test]
fn constlattice_meet_with_bottom() {
    assert_eq!(
        ConstLattice::Const(1).meet(ConstLattice::Bottom),
        ConstLattice::Bottom
    );
}
#[test]
fn constlattice_as_const() {
    assert_eq!(ConstLattice::Const(9).as_const(), Some(9));
    assert_eq!(ConstLattice::Top.as_const(), None);
    assert_eq!(ConstLattice::Bottom.as_const(), None);
}

// ---------- CffVerifier ----------
#[test]
fn verifier_clean_on_empty_recovered() {
    let cand = CffCandidate {
        function_start: Address::new(0),
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        block_count: 0,
        confidence: 0.0,
        pattern: CffPattern::Unknown,
    };
    let rec = RecoveredCfg {
        function_start: Address::new(0),
        blocks: vec![Address::new(0x100)],
        edges: vec![],
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        original_candidate: cand,
    };
    let res = CffVerifier::new().verify(&rec);
    assert!(res.is_clean());
    assert_eq!(res.dangling_edges, 0);
    assert_eq!(res.total_edges, 0);
    assert_eq!(res.block_count, 1);
}
#[test]
fn verifier_detects_dangling_edge() {
    let cand = CffCandidate {
        function_start: Address::new(0),
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        block_count: 0,
        confidence: 0.0,
        pattern: CffPattern::Unknown,
    };
    let rec = RecoveredCfg {
        function_start: Address::new(0),
        blocks: vec![Address::new(0x100)],
        edges: vec![RecoveredEdge {
            from_block: Address::new(0x100),
            to_block: Address::new(0xDEAD), // missing
            edge_type: RecoveredEdgeType::Unconditional,
            state_value: None,
        }],
        dispatcher_address: Address::new(0x1010),
        state_variable: StateVariable::Unknown,
        original_candidate: cand,
    };
    let res = CffVerifier::new().verify(&rec);
    assert!(!res.is_valid);
    assert!(res.dangling_edges >= 1);
    assert!(!res.is_clean());
}
#[test]
fn verifier_detects_dispatcher_in_blocks() {
    let cand = CffCandidate {
        function_start: Address::new(0),
        dispatcher_address: Address::new(0x500),
        state_variable: StateVariable::Unknown,
        block_count: 0,
        confidence: 0.0,
        pattern: CffPattern::Unknown,
    };
    let rec = RecoveredCfg {
        function_start: Address::new(0),
        blocks: vec![Address::new(0x500)], // dispatcher present!
        edges: vec![],
        dispatcher_address: Address::new(0x500),
        state_variable: StateVariable::Unknown,
        original_candidate: cand,
    };
    let res = CffVerifier::new().verify(&rec);
    assert!(!res.is_valid);
}
#[test]
fn verifyresult_is_clean_false_with_multi_dispatch() {
    let res = CffVerifyResult {
        is_valid: true,
        total_edges: 0,
        dangling_edges: 0,
        multi_dispatch_blocks: 1,
        block_count: 0,
        diagnostics: vec![],
    };
    assert!(!res.is_clean());
}

// ---------- CffDeobfuscationPass ----------
#[test]
fn pass_default_constructible() {
    let p = CffDeobfuscationPass::default();
    assert_eq!(p.detector.min_block_count, 5);
}
#[test]
fn pass_run_on_function_rejects_small() {
    let p = CffDeobfuscationPass::new();
    let cfg = make_cff_cfg(2);
    assert!(p.run_on_function(&cfg, Address::new(0x1000)).is_none());
}
#[test]
fn pass_run_on_binary_empty() {
    let p = CffDeobfuscationPass::new();
    let res = p.run_on_binary(vec![]);
    assert_eq!(res.candidates_found, 0);
    assert_eq!(res.candidates_recovered, 0);
    assert!(res.recovered.is_empty());
    assert!(res.failed.is_empty());
}
#[test]
fn deobf_result_default() {
    let r = DeobfResult::default();
    assert_eq!(r.candidates_found, 0);
}

// ---------- CffDispatcherDetector ----------
#[test]
fn dispatcher_detector_min_handlers_constant() {
    assert_eq!(CffDispatcherDetector::MIN_HANDLER_COUNT, 5);
}
#[test]
fn dispatcher_detector_empty_no_matches() {
    assert!(CffDispatcherDetector::detect(&[], 0).is_empty());
}
#[test]
fn dispatcher_detector_no_pattern() {
    let code = vec![0x90u8; 64];
    assert!(CffDispatcherDetector::detect(&code, 0x1000).is_empty());
}
#[test]
fn dispatcher_detector_matches_5_cmp_branch_pairs() {
    // Build 5 × (83 3D <disp32:0> <imm8:0> <jcc:0x74> <rel8:0x00>) = 9 bytes each.
    let mut code = Vec::new();
    for _ in 0..5 {
        code.extend_from_slice(&[0x83, 0x3D, 0, 0, 0, 0, 0, 0x74, 0]);
    }
    let r = CffDispatcherDetector::detect(&code, 0x1000);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].handler_count, 5);
    assert_eq!(r[0].addr, 0x1000);
}
#[test]
fn cff_dispatcher_eq() {
    let a = CffDispatcher { addr: 1, state_var_addr: 2, handler_count: 5 };
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------- StateGraph ----------
#[test]
fn stategraph_new_empty() {
    let g = StateGraph::new();
    assert!(g.is_empty());
    assert_eq!(g.state_count(), 0);
}
#[test]
fn stategraph_add_and_query() {
    let mut g = StateGraph::new();
    g.add_edge(1, 2, None);
    g.add_edge(1, 3, Some(true));
    assert_eq!(g.transitions(1).len(), 2);
    assert_eq!(g.transitions(99), &[] as &[(u32, Option<bool>)]);
    assert_eq!(g.state_count(), 1);
    assert!(!g.is_empty());
}
#[test]
fn stategraph_all_targets() {
    let mut g = StateGraph::new();
    g.add_edge(1, 2, None);
    g.add_edge(1, 3, None);
    g.add_edge(2, 3, None);
    let t = g.all_targets();
    assert!(t.contains(&2));
    assert!(t.contains(&3));
    assert_eq!(t.len(), 2);
}

// ---------- StateTransitionAnalyzer & CffDeflattener ----------
#[test]
fn analyzer_on_empty_code_empty_graph() {
    let d = CffDispatcher { addr: 0, state_var_addr: 0, handler_count: 5 };
    let g = StateTransitionAnalyzer::analyze(&d, &[]);
    assert!(g.is_empty());
}
#[test]
fn deflattener_empty_graph_empty_edges() {
    let d = CffDispatcher { addr: 0, state_var_addr: 0, handler_count: 5 };
    let g = StateGraph::new();
    assert!(CffDeflattener::deflaten(&d, &g).is_empty());
}
#[test]
fn deflattener_sorted_output() {
    let d = CffDispatcher { addr: 0, state_var_addr: 0, handler_count: 5 };
    let mut g = StateGraph::new();
    g.add_edge(5, 9, None);
    g.add_edge(2, 8, None);
    g.add_edge(2, 3, None);
    let edges = CffDeflattener::deflaten(&d, &g);
    assert_eq!(edges.len(), 3);
    assert!(edges[0].from_state <= edges[1].from_state);
    assert!(edges[1].from_state <= edges[2].from_state);
}
#[test]
fn cfg_edge_equality() {
    let a = CfgEdge { from_state: 1, to_state: 2, condition: Some(true) };
    let b = CfgEdge { from_state: 1, to_state: 2, condition: Some(true) };
    assert_eq!(a, b);
}
#[test]
fn estimate_confidence_empty_zero() {
    assert_eq!(CffDeflattener::estimate_cff_confidence(&[]), 0.0);
}
#[test]
fn estimate_confidence_in_unit_range() {
    let code = vec![0x90u8; 256];
    let s = CffDeflattener::estimate_cff_confidence(&code);
    assert!((0.0..=1.0).contains(&s));
}

// ---------- RecoveredEdgeType / EdgeType ----------
#[test]
fn recovered_edge_type_eq() {
    assert_eq!(RecoveredEdgeType::TrueBranch, RecoveredEdgeType::TrueBranch);
    assert_ne!(RecoveredEdgeType::TrueBranch, RecoveredEdgeType::FalseBranch);
}
#[test]
fn edge_type_copy() {
    let e = EdgeType::TrueBranch;
    let f = e;
    assert_eq!(e, f);
}

// ---------- Send/Sync bounds ----------
#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CffDetector>();
    assert_send_sync::<CffRecoverer>();
    assert_send_sync::<CffDeobfuscationPass>();
    assert_send_sync::<BlockMapping>();
    assert_send_sync::<RecoveredCfg>();
    assert_send_sync::<StateVariable>();
    assert_send_sync::<CffPattern>();
    assert_send_sync::<StateGraph>();
    assert_send_sync::<CffDispatcher>();
}
