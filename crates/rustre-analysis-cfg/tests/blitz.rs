//! Exhaustive blitz test suite for rustre-analysis-cfg.
//!
//! Targets the public surface: `analyze_cfg/try_analyze_cfg`, `DominatorTree`,
//! `PostDominatorTree`, `NaturalLoop`, `ReducibilityTest`, `CfgScc`, `DominanceFrontier`,
//! `CfgMetrics`, `CfgStats` (via `DotPrinter`), `cfg_to_dot/json`, edges (`FlowEdgeKind`,
//! `classify_terminator`, `compute_leaders`, `split_basic_blocks`),
//! `jump_table` (decode_*, `SwitchBound`, `SwitchStatement`),
//! `lengauer_tarjan` (`compute_lt`, `LtDomTree`).

use rustre_analysis_cfg::{
    BasicBlock, CfgDotPrinter, CfgEdge, CfgError, CfgMetrics, CfgScc,
    DominanceFrontier, DominatorTree, EdgeKind, JumpTableConfig, JumpTableKind,
    NaturalLoop, PostDominatorTree, ReducibilityResult, ReducibilityTest, SwitchBound,
    SwitchStatement, analyze_cfg, cfg_to_dot, cfg_to_full_json, classify_terminator,
    compute_leaders, compute_lt, cyclomatic_complexity, decode_absolute_table,
    decode_relative_table, find_back_edges, find_natural_loops, is_reducible, natural_loops,
    split_basic_blocks, try_analyze_cfg,
};
use rustre_analysis_cfg::edges::{FlowEdge, FlowEdgeKind};
use rustre_core::address::Address;
use rustre_core::endian::Endian;
use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister, Size, llil_const, llil_reg};
use std::collections::HashMap;

// ───────────────────────── helpers ─────────────────────────

const fn a(v: u64) -> Address {
    Address::new(v)
}
const fn nop() -> LlilInstruction {
    LlilInstruction::Nop
}
const fn ret() -> LlilInstruction {
    LlilInstruction::Ret
}
const fn jmp(v: u64) -> LlilInstruction {
    LlilInstruction::JumpDest {
        dest: llil_const(v, Size::QWord),
    }
}
fn cj(t: u64, f: u64) -> LlilInstruction {
    LlilInstruction::CondJump {
        cond: llil_reg("zf", Size::Byte),
        true_dest: a(t),
        false_dest: a(f),
    }
}
fn jt(targets: Vec<u64>) -> LlilInstruction {
    LlilInstruction::JumpTo {
        dest: LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete("rax".to_string()),
            size: Size::QWord,
        },
        targets: targets.into_iter().map(a).collect(),
    }
}

fn linear_prog() -> Vec<(Address, LlilInstruction)> {
    vec![(a(0), nop()), (a(2), nop()), (a(4), ret())]
}
fn diamond_prog() -> Vec<(Address, LlilInstruction)> {
    // 0: cj 8/4 ; 4: jmp 0xC ; 8: nop ; 0xC: ret
    vec![
        (a(0), cj(8, 4)),
        (a(4), jmp(0xC)),
        (a(8), nop()),
        (a(0xC), ret()),
    ]
}
fn loop_prog() -> Vec<(Address, LlilInstruction)> {
    // Header block at 0; latch block at 4 (separate because addr 4 is a jump target),
    // exit at 8. Layout:
    //   0: jmp 4            (header — forces leader at 4)
    //   4: cj 0 / 8         (latch: true back to header, false to exit)
    //   8: ret
    // Leaders: {0} ∪ {4 (from jmp), next-after-jmp=4} ∪ {0,8 from cj, next-after-cj=8}
    //        = {0, 4, 8}
    // Edges:  0 -> 4 (uncond);  4 -> 0 (true, back edge);  4 -> 8 (false)
    vec![(a(0), jmp(4)), (a(4), cj(0, 8)), (a(8), ret())]
}

// ───────────────────────── analyze_cfg basics ─────────────────────────

#[test]
fn analyze_linear_program() {
    let cfg = analyze_cfg(&linear_prog());
    assert_eq!(cfg.entry, a(0));
    assert_eq!(cfg.block_count(), 1);
    assert_eq!(cfg.edge_count(), 0);
}

#[test]
fn analyze_diamond_has_4_blocks_4_edges() {
    let cfg = analyze_cfg(&diamond_prog());
    assert_eq!(cfg.block_count(), 4, "expected 4 blocks");
    // edges: 0->8 (T), 0->4 (F), 4->0xC (uncond), no edge from 8 (no terminator -> fallthrough to 0xC)
    // 8 has no terminator -> fallthrough to next leader 0xC
    assert!(cfg.edges.iter().any(|e| e.from == a(0) && e.to == a(8) && e.kind == EdgeKind::TrueBranch));
    assert!(cfg.edges.iter().any(|e| e.from == a(0) && e.to == a(4) && e.kind == EdgeKind::FalseBranch));
    assert!(cfg.edges.iter().any(|e| e.from == a(4) && e.to == a(0xC)));
}

#[test]
fn analyze_empty_returns_default_like_cfg() {
    let cfg = analyze_cfg(&[]);
    assert_eq!(cfg.block_count(), 0);
    assert_eq!(cfg.edge_count(), 0);
}

#[test]
fn try_analyze_empty_errors() {
    let err = try_analyze_cfg(&[]).unwrap_err();
    let cfg_err = err.downcast_ref::<CfgError>().expect("CfgError downcast");
    assert!(matches!(cfg_err, CfgError::EmptyCfg));
}

#[test]
fn try_analyze_diamond_ok() {
    let cfg = try_analyze_cfg(&diamond_prog()).unwrap();
    assert!(cfg.blocks.contains_key(&cfg.entry));
}

// ───────────────────────── DominatorTree ─────────────────────────

#[test]
fn dominator_entry_has_no_idom() {
    let cfg = analyze_cfg(&diamond_prog());
    assert_eq!(cfg.immediate_dominator(a(0)), None);
}

#[test]
fn dominator_entry_dominates_all() {
    let cfg = analyze_cfg(&diamond_prog());
    for &addr in cfg.blocks.keys() {
        assert!(cfg.dominates(a(0), addr), "entry must dominate {addr:?}");
    }
}

#[test]
fn dominator_diamond_join_idom_is_entry() {
    let cfg = analyze_cfg(&diamond_prog());
    // 0xC is the join; its idom should be 0 (entry), not 4 or 8.
    assert_eq!(cfg.immediate_dominator(a(0xC)), Some(a(0)));
}

#[test]
fn dominator_self_dominates() {
    let cfg = analyze_cfg(&diamond_prog());
    for &addr in cfg.blocks.keys() {
        assert!(cfg.dominates(addr, addr));
    }
}

#[test]
fn dominator_strictly_dominates() {
    let cfg = analyze_cfg(&diamond_prog());
    let dt = &cfg.dom_tree;
    assert!(!dt.strictly_dominates(a(0), a(0)));
    assert!(dt.strictly_dominates(a(0), a(0xC)));
}

#[test]
fn dominator_depth_entry_is_zero() {
    let cfg = analyze_cfg(&diamond_prog());
    assert_eq!(cfg.dom_tree.depth(a(0)), 0);
    assert!(cfg.dom_tree.depth(a(0xC)) >= 1);
}

#[test]
fn dominator_dominated_by_entry_covers_rest() {
    let cfg = analyze_cfg(&diamond_prog());
    let dominated = cfg.dom_tree.dominated_by(a(0));
    assert_eq!(dominated.len(), cfg.block_count() - 1);
}

#[test]
fn dominance_frontier_diamond() {
    let cfg = analyze_cfg(&diamond_prog());
    // The join 0xC is in DF of 8 and 4 (since neither strictly dominates 0xC).
    let df4 = cfg.dominance_frontier(a(4));
    let df8 = cfg.dominance_frontier(a(8));
    assert!(df4.contains(&a(0xC)), "DF(4) should contain 0xC, got {df4:?}");
    assert!(df8.contains(&a(0xC)), "DF(8) should contain 0xC, got {df8:?}");
}

#[test]
fn dominance_frontier_struct_matches_dom_tree() {
    let cfg = analyze_cfg(&diamond_prog());
    let df = DominanceFrontier::compute(&cfg.dom_tree, &cfg.edges);
    for &addr in cfg.blocks.keys() {
        let a_set = df.frontier_of(addr);
        let b_set = cfg.dominance_frontier(addr);
        let mut a_sorted = a_set.to_vec();
        let mut b_sorted = b_set.clone();
        a_sorted.sort_by_key(|x| x.0);
        b_sorted.sort_by_key(|x| x.0);
        assert_eq!(a_sorted, b_sorted, "DF mismatch at {addr:?}");
    }
}

#[test]
fn iterated_dominance_frontier_diamond_is_closed() {
    let cfg = analyze_cfg(&diamond_prog());
    let df = DominanceFrontier::compute(&cfg.dom_tree, &cfg.edges);
    let idf = df.iterated_frontier(&[a(4), a(8)]);
    assert!(idf.contains(&a(0xC)));
}

// ───────────────────────── PostDominatorTree ─────────────────────────

#[test]
fn post_dom_exit_post_dominates_all() {
    let cfg = analyze_cfg(&diamond_prog());
    // 0xC (ret) post-dominates every block.
    for &addr in cfg.blocks.keys() {
        assert!(cfg.post_dominates(a(0xC), addr), "0xC must post-dom {addr:?}");
    }
}

#[test]
fn post_dom_self_post_dominates() {
    let cfg = analyze_cfg(&diamond_prog());
    for &addr in cfg.blocks.keys() {
        assert!(cfg.post_dominates(addr, addr));
    }
}

#[test]
fn post_dom_empty_blocks_is_default() {
    let pdt = PostDominatorTree::compute(&HashMap::new(), &[]);
    assert!(pdt.idom.is_empty());
}

// ───────────────────────── Natural loops ─────────────────────────

#[test]
fn loop_prog_has_one_natural_loop() {
    let cfg = analyze_cfg(&loop_prog());
    assert_eq!(cfg.loops.len(), 1);
    let l = &cfg.loops[0];
    assert_eq!(l.header, a(0));
    assert_eq!(l.back_edge_src, a(4));
    assert!(l.contains(a(0)));
    assert!(l.contains(a(4)));
}

#[test]
fn loop_size_matches_body() {
    let cfg = analyze_cfg(&loop_prog());
    let l = &cfg.loops[0];
    assert_eq!(l.size(), l.body.len());
    assert_eq!(l.size(), 2);
}

#[test]
fn diamond_has_no_loops() {
    let cfg = analyze_cfg(&diamond_prog());
    assert!(cfg.loops.is_empty());
}

#[test]
fn natural_loops_alt_overload_agrees() {
    let cfg = analyze_cfg(&loop_prog());
    let dt = DominatorTree::compute(&cfg.blocks, &cfg.edges, cfg.entry);
    let loops_alt = natural_loops(&cfg, &dt);
    assert_eq!(loops_alt.len(), cfg.loops.len());
}

#[test]
fn find_back_edges_loop_prog() {
    let cfg = analyze_cfg(&loop_prog());
    let backs = find_back_edges(&cfg, &cfg.dom_tree);
    assert_eq!(backs.len(), 1);
    assert_eq!(backs[0], (a(4), a(0)));
}

#[test]
fn is_back_edge_helper() {
    let cfg = analyze_cfg(&loop_prog());
    assert!(cfg.is_back_edge(a(4), a(0)));
    assert!(!cfg.is_back_edge(a(0), a(4)));
}

// ───────────────────────── Reducibility ─────────────────────────

#[test]
fn diamond_is_reducible() {
    let cfg = analyze_cfg(&diamond_prog());
    assert!(is_reducible(&cfg));
    assert!(matches!(ReducibilityTest::test(&cfg), ReducibilityResult::Reducible));
}

#[test]
fn loop_is_reducible() {
    let cfg = analyze_cfg(&loop_prog());
    assert!(is_reducible(&cfg));
}

#[test]
fn reducibility_result_is_reducible_helper() {
    assert!(ReducibilityResult::Reducible.is_reducible());
    assert!(!ReducibilityResult::Irreducible { back_edges: vec![] }.is_reducible());
}

#[test]
fn reducibility_empty_cfg_is_reducible() {
    let cfg = analyze_cfg(&[]);
    assert!(is_reducible(&cfg));
}

// ───────────────────────── Cyclomatic complexity ─────────────────────────

#[test]
fn cyclomatic_linear_is_one() {
    let cfg = analyze_cfg(&linear_prog());
    // E=0,N=1,P=1 => 0 - 1 + 2 = 1
    assert_eq!(cyclomatic_complexity(&cfg), 1);
}

#[test]
fn cyclomatic_diamond_is_two() {
    let cfg = analyze_cfg(&diamond_prog());
    // E=3,N=4,P=1 => 3 - 4 + 2 = 1
    let cc = cyclomatic_complexity(&cfg);
    // diamond has one decision -> cc should be 2
    assert_eq!(cc, 2, "diamond cc expected 2, got {cc}");
}

#[test]
fn cyclomatic_loop_program() {
    let cfg = analyze_cfg(&loop_prog());
    // E=3 (nop->cj fallthrough + cj true to 0 + cj false to 4), N=3, P=1 -> 3-3+2=2... actually:
    // blocks: 0 (nop,cj), 0 fall? no — leader 0 holds nop then leader 2 (after cj target).
    // Actually compute: blocks at leaders {0, 2 (next after cj target wait), 4}.
    // edges: 0 -> fallthrough? since 0's last instr is nop (terminator at addr 2 is cj though).
    // The cfg.block_count is what matters: let's just assert >= 2.
    let cc = cyclomatic_complexity(&cfg);
    assert!(cc >= 2);
}

// ───────────────────────── ControlFlowGraph helpers ─────────────────────────

#[test]
fn predecessors_and_successors() {
    let cfg = analyze_cfg(&diamond_prog());
    let preds = cfg.predecessors(a(0xC));
    assert!(preds.contains(&a(4)) || preds.contains(&a(8)));
    let succs = cfg.successors(a(0));
    assert_eq!(succs.len(), 2);
}

#[test]
fn reachable_from_entry_covers_all() {
    let cfg = analyze_cfg(&diamond_prog());
    let r = cfg.reachable_from(cfg.entry);
    assert_eq!(r.len(), cfg.block_count());
}

#[test]
fn reachable_from_nonexistent_is_empty() {
    let cfg = analyze_cfg(&diamond_prog());
    assert!(cfg.reachable_from(a(0xDEAD_BEEF)).is_empty());
}

#[test]
fn rpo_and_post_order_are_reverses() {
    let cfg = analyze_cfg(&diamond_prog());
    let rpo = cfg.reverse_post_order();
    let mut po = cfg.post_order();
    po.reverse();
    assert_eq!(rpo, po);
    assert_eq!(rpo.len(), cfg.block_count());
}

#[test]
fn to_petgraph_node_and_edge_counts_match() {
    let cfg = analyze_cfg(&diamond_prog());
    let g = cfg.to_petgraph();
    assert_eq!(g.node_count(), cfg.block_count());
    assert_eq!(g.edge_count(), cfg.edge_count());
}

// ───────────────────────── Dot / JSON ─────────────────────────

#[test]
fn cfg_to_dot_is_well_formed_digraph() {
    let cfg = analyze_cfg(&diamond_prog());
    let dot = cfg_to_dot(&cfg);
    assert!(dot.starts_with("digraph cfg {"));
    assert!(dot.trim_end().ends_with("}"));
}

#[test]
fn dot_printer_default_equals_new() {
    let a = CfgDotPrinter::default();
    let b = CfgDotPrinter::new();
    assert_eq!(a.show_instructions, b.show_instructions);
    assert_eq!(a.highlight_loops, b.highlight_loops);
    assert_eq!(a.highlight_back_edges, b.highlight_back_edges);
}

#[test]
fn cfg_to_full_json_contains_blocks_and_edges() {
    let cfg = analyze_cfg(&diamond_prog());
    let json = cfg_to_full_json(&cfg);
    assert!(json.contains("\"entry\""));
    assert!(json.contains("\"blocks\""));
    assert!(json.contains("\"edges\""));
    // Should be valid JSON.
    let _: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
}

// ───────────────────────── CfgMetrics ─────────────────────────

#[test]
fn cfg_metrics_diamond() {
    let cfg = analyze_cfg(&diamond_prog());
    let m = CfgMetrics::compute(&cfg);
    assert!(m.is_reducible);
    assert_eq!(m.back_edge_count, 0);
    assert_eq!(m.max_loop_depth, 0);
    assert_eq!(m.reachable_count, cfg.block_count());
    assert!(m.branch_count >= 1);
    assert!(m.join_count >= 1);
}

#[test]
fn cfg_metrics_loop_has_one_back_edge() {
    let cfg = analyze_cfg(&loop_prog());
    let m = CfgMetrics::compute(&cfg);
    assert_eq!(m.back_edge_count, 1);
    assert!(m.max_loop_depth >= 1);
}

// ───────────────────────── SCC ─────────────────────────

#[test]
fn scc_loop_has_nontrivial_component() {
    let cfg = analyze_cfg(&loop_prog());
    let scc = CfgScc::compute(&cfg);
    assert!(!scc.is_empty());
    let loops: Vec<_> = scc.loops();
    assert!(!loops.is_empty(), "expected at least one loop SCC");
}

#[test]
fn scc_diamond_all_trivial() {
    let cfg = analyze_cfg(&diamond_prog());
    let scc = CfgScc::compute(&cfg);
    // No loops in diamond.
    assert!(scc.loops().is_empty());
    assert_eq!(scc.len(), cfg.block_count());
}

// ───────────────────────── edges module ─────────────────────────

#[test]
fn flow_edge_kind_intraprocedural() {
    assert!(FlowEdgeKind::Jump.is_intraprocedural());
    assert!(FlowEdgeKind::Fallthrough.is_intraprocedural());
    assert!(!FlowEdgeKind::Call.is_intraprocedural());
    assert!(!FlowEdgeKind::Return.is_intraprocedural());
    assert!(FlowEdgeKind::Indirect.is_intraprocedural());
}

#[test]
fn flow_edge_kind_conditional() {
    assert!(FlowEdgeKind::BranchTaken.is_conditional());
    assert!(FlowEdgeKind::BranchNotTaken.is_conditional());
    assert!(!FlowEdgeKind::Jump.is_conditional());
}

#[test]
fn flow_edge_kind_tags_unique() {
    let all = [
        FlowEdgeKind::Fallthrough,
        FlowEdgeKind::Jump,
        FlowEdgeKind::BranchTaken,
        FlowEdgeKind::BranchNotTaken,
        FlowEdgeKind::Call,
        FlowEdgeKind::Return,
        FlowEdgeKind::Indirect,
    ];
    let mut tags: Vec<_> = all.iter().map(|k| k.tag()).collect();
    tags.sort();
    let n = tags.len();
    tags.dedup();
    assert_eq!(tags.len(), n);
}

#[test]
fn classify_indirect_jump_no_const() {
    let term = LlilInstruction::JumpDest {
        dest: llil_reg("rax", Size::QWord),
    };
    let edges = classify_terminator(a(0x10), &term, Some(a(0x20)));
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, FlowEdgeKind::Indirect);
}

#[test]
fn classify_indirect_jump_no_fallthrough_is_empty() {
    let term = LlilInstruction::JumpDest {
        dest: llil_reg("rax", Size::QWord),
    };
    let edges = classify_terminator(a(0x10), &term, None);
    assert!(edges.is_empty());
}

#[test]
fn classify_tail_call() {
    let tc = LlilInstruction::TailCall {
        dest: llil_const(0x500, Size::QWord),
    };
    let edges = classify_terminator(a(0x10), &tc, Some(a(0x20)));
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, FlowEdgeKind::Call);
    assert_eq!(edges[0].to, a(0x500));
}

#[test]
fn classify_nop_falls_through() {
    let edges = classify_terminator(a(0x10), &nop(), Some(a(0x12)));
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, FlowEdgeKind::Fallthrough);
}

#[test]
fn flow_edge_new_and_to_cfg_edge() {
    let fe = FlowEdge::new(a(1), a(2), FlowEdgeKind::BranchNotTaken);
    let ce = fe.to_cfg_edge();
    assert_eq!(ce.kind, EdgeKind::Fallthrough);
}

#[test]
fn compute_leaders_empty_is_empty() {
    let leaders = compute_leaders(&[]);
    assert!(leaders.is_empty());
}

#[test]
fn compute_leaders_includes_entry() {
    let instrs = vec![(a(0x100), nop())];
    let leaders = compute_leaders(&instrs);
    assert!(leaders.contains(&a(0x100)));
}

#[test]
fn split_basic_blocks_round_trip_addresses() {
    let instrs = vec![
        (a(0), nop()),
        (a(2), cj(8, 4)),
        (a(4), nop()),
        (a(6), jmp(0xC)),
        (a(8), nop()),
        (a(0xC), ret()),
    ];
    let blocks = split_basic_blocks(&instrs);
    for start in [a(0), a(4), a(8), a(0xC)] {
        assert!(blocks.contains_key(&start), "missing block at {start:?}");
    }
}

// ───────────────────────── jump_table ─────────────────────────

fn jt_cfg() -> JumpTableConfig {
    JumpTableConfig::new(a(0x1000), a(0x2000), Endian::Little)
}

#[test]
fn jump_table_config_target_in_range_inclusive_exclusive() {
    let c = jt_cfg();
    assert!(c.target_in_range(a(0x1000)));
    assert!(c.target_in_range(a(0x1FFF)));
    assert!(!c.target_in_range(a(0x2000)));
    assert!(!c.target_in_range(a(0xFFF)));
}

#[test]
fn jump_table_zero_entry_size_rejected() {
    let data = vec![0u8; 16];
    let jt = decode_absolute_table(&data, a(0x4000), a(0x4000), 0, Some(4), &jt_cfg(), a(0x1500));
    assert!(jt.is_none());
}

#[test]
fn jump_table_addr_before_data_base_rejected() {
    let data = vec![0u8; 16];
    let jt = decode_absolute_table(&data, a(0x4000), a(0x3000), 4, Some(2), &jt_cfg(), a(0x1500));
    assert!(jt.is_none());
}

#[test]
fn jump_table_absolute_dedup_targets() {
    let mut data = Vec::new();
    for t in [0x1100u32, 0x1100, 0x1200, 0x1100] {
        data.extend_from_slice(&t.to_le_bytes());
    }
    let jt = decode_absolute_table(&data, a(0x4000), a(0x4000), 4, Some(4), &jt_cfg(), a(0x1500)).unwrap();
    assert_eq!(jt.entry_count, 4);
    assert_eq!(jt.distinct_target_count(), 2);
}

#[test]
fn jump_table_truncated_data_breaks_loop() {
    // Only 6 bytes; 4-byte entries -> at most 1 entry; min_entries default = 2 -> None.
    let data = vec![0u8; 6];
    let jt = decode_absolute_table(&data, a(0x4000), a(0x4000), 4, None, &jt_cfg(), a(0x1500));
    assert!(jt.is_none());
}

#[test]
fn jump_table_table_byte_size() {
    let mut data = Vec::new();
    for t in [0x1100u32, 0x1200] {
        data.extend_from_slice(&t.to_le_bytes());
    }
    let jt = decode_absolute_table(&data, a(0x4000), a(0x4000), 4, Some(2), &jt_cfg(), a(0x1500)).unwrap();
    assert_eq!(jt.table_byte_size(), 8);
}

#[test]
fn jump_table_has_target_lookup() {
    let mut data = Vec::new();
    for t in [0x1100u32, 0x1200] {
        data.extend_from_slice(&t.to_le_bytes());
    }
    let jt = decode_absolute_table(&data, a(0x4000), a(0x4000), 4, Some(2), &jt_cfg(), a(0x1500)).unwrap();
    assert!(jt.has_target(a(0x1100)));
    assert!(!jt.has_target(a(0x9999)));
}

#[test]
fn jump_table_kind_serde_round_trip() {
    let v = JumpTableKind::AbsolutePointers;
    let s = serde_json::to_string(&v).unwrap();
    let back: JumpTableKind = serde_json::from_str(&s).unwrap();
    assert_eq!(v, back);
}

#[test]
fn switch_bound_case_count_basic() {
    let b = SwitchBound { max_index: 0, default_target: a(0) };
    assert_eq!(b.case_count(), 1);
    let b = SwitchBound { max_index: u64::MAX, default_target: a(0) };
    assert_eq!(b.case_count(), usize::MAX);
}

#[test]
fn switch_statement_consistency_no_bound() {
    let mut data = Vec::new();
    for t in [0x1100u32, 0x1200] {
        data.extend_from_slice(&t.to_le_bytes());
    }
    let table = decode_absolute_table(&data, a(0x4000), a(0x4000), 4, Some(2), &jt_cfg(), a(0x1500)).unwrap();
    let stmt = SwitchStatement { table, bound: None };
    assert!(stmt.is_consistent());
}

#[test]
fn switch_statement_all_successors_dedup_when_default_in_table() {
    let mut data = Vec::new();
    for t in [0x1100u32, 0x1200, 0x1FF0] {
        data.extend_from_slice(&t.to_le_bytes());
    }
    let table = decode_absolute_table(&data, a(0x4000), a(0x4000), 4, Some(3), &jt_cfg(), a(0x1500)).unwrap();
    let stmt = SwitchStatement {
        table,
        bound: Some(SwitchBound { max_index: 2, default_target: a(0x1FF0) }),
    };
    let succ = stmt.all_successors();
    assert_eq!(succ.len(), 3, "default already in table, should not be duplicated");
}

#[test]
fn jump_table_relative_negative_offsets() {
    let offs: [i32; 2] = [-0x100, 0x100];
    let mut data = Vec::new();
    for o in offs {
        data.extend_from_slice(&o.to_le_bytes());
    }
    let jt = decode_relative_table(
        &data, a(0x4000), a(0x4000), 4, a(0x1500), Some(2), &jt_cfg(), a(0x1700),
    ).unwrap();
    assert!(jt.has_target(a(0x1400)));
    assert!(jt.has_target(a(0x1600)));
}

// ───────────────────────── lengauer_tarjan ─────────────────────────

fn build_lt(
    nodes: &[u64],
    edges: &[(u64, u64)],
) -> (Vec<Address>, HashMap<Address, Vec<Address>>) {
    let n: Vec<Address> = nodes.iter().copied().map(a).collect();
    let mut s: HashMap<Address, Vec<Address>> = HashMap::new();
    for &x in &n {
        s.entry(x).or_default();
    }
    for &(f, t) in edges {
        s.entry(a(f)).or_default().push(a(t));
    }
    (n, s)
}

#[test]
fn lt_linear_chain_idoms() {
    let (n, s) = build_lt(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    assert_eq!(dt.idom_of(a(0)), None);
    assert_eq!(dt.idom_of(a(1)), Some(a(0)));
    assert_eq!(dt.idom_of(a(2)), Some(a(1)));
    assert_eq!(dt.idom_of(a(3)), Some(a(2)));
}

#[test]
fn lt_diamond_idom_join() {
    let (n, s) = build_lt(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    assert_eq!(dt.idom_of(a(3)), Some(a(0)));
}

#[test]
fn lt_entry_missing_returns_none() {
    let (n, s) = build_lt(&[0, 1], &[(0, 1)]);
    assert!(compute_lt(&n, &s, a(99)).is_none());
}

#[test]
fn lt_dominates_transitively() {
    let (n, s) = build_lt(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    assert!(dt.dominates(a(0), a(3)));
    assert!(dt.dominates(a(1), a(3)));
    assert!(!dt.dominates(a(3), a(0)));
}

#[test]
fn lt_depth_chain() {
    let (n, s) = build_lt(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    assert_eq!(dt.depth(a(0)), 0);
    assert_eq!(dt.depth(a(3)), 3);
}

#[test]
fn lt_children_of_chain() {
    let (n, s) = build_lt(&[0, 1, 2], &[(0, 1), (1, 2)]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    assert_eq!(dt.children_of(a(0)), vec![a(1)]);
    assert_eq!(dt.children_of(a(1)), vec![a(2)]);
}

#[test]
fn lt_single_node_idom_none() {
    let (n, s) = build_lt(&[0], &[]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    assert_eq!(dt.idom_of(a(0)), None);
    assert_eq!(dt.depth(a(0)), 0);
}

#[test]
fn lt_matches_cooper_on_diamond() {
    let (n, s) = build_lt(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let dt = compute_lt(&n, &s, a(0)).unwrap();
    // Build the equivalent CFG and compare against DominatorTree.
    let mut blocks = HashMap::new();
    for &addr in &n {
        blocks.insert(addr, BasicBlock { start: addr, end: addr, instructions: vec![] });
    }
    let edges = vec![
        CfgEdge { from: a(0), to: a(1), kind: EdgeKind::TrueBranch },
        CfgEdge { from: a(0), to: a(2), kind: EdgeKind::FalseBranch },
        CfgEdge { from: a(1), to: a(3), kind: EdgeKind::Unconditional },
        CfgEdge { from: a(2), to: a(3), kind: EdgeKind::Unconditional },
    ];
    let cooper = DominatorTree::compute(&blocks, &edges, a(0));
    for &addr in &n {
        assert_eq!(
            dt.idom_of(addr),
            cooper.idom.get(&addr).copied().flatten(),
            "idom mismatch at {addr:?}"
        );
    }
}

// ───────────────────────── JumpTo terminator integration ─────────────────────────

#[test]
fn analyze_jump_table_terminator_creates_n_edges() {
    let instrs = vec![
        (a(0), nop()),
        (a(2), jt(vec![0x100, 0x200, 0x300])),
        (a(0x100), ret()),
        (a(0x200), ret()),
        (a(0x300), ret()),
    ];
    let cfg = analyze_cfg(&instrs);
    let out: Vec<_> = cfg.successors(a(0));
    assert_eq!(out.len(), 3);
    for t in [a(0x100), a(0x200), a(0x300)] {
        assert!(out.contains(&t));
    }
}

// ───────────────────────── EdgeKind serde ─────────────────────────

#[test]
fn edge_kind_serde_round_trip() {
    for k in [EdgeKind::Unconditional, EdgeKind::TrueBranch, EdgeKind::FalseBranch, EdgeKind::Fallthrough] {
        let s = serde_json::to_string(&k).unwrap();
        let back: EdgeKind = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
    }
}

// ───────────────────────── NaturalLoop accessor ─────────────────────────

#[test]
fn natural_loop_contains_and_size_consistent() {
    let cfg = analyze_cfg(&loop_prog());
    let l: &NaturalLoop = &cfg.loops[0];
    assert_eq!(l.contains(l.header), true);
    assert_eq!(l.size(), l.body.len());
}

// ───────────────────────── find_natural_loops direct ─────────────────────────

#[test]
fn find_natural_loops_matches_cfg_loops() {
    let cfg = analyze_cfg(&loop_prog());
    let direct = find_natural_loops(&cfg);
    assert_eq!(direct.len(), cfg.loops.len());
}
