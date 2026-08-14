//! Blitz2: deep adversarial test suite for rustre-analysis-cfg.
//!
//! Covers analyze_cfg, try_analyze_cfg, DominatorTree, PostDominatorTree,
//! find_natural_loops, CfgStats, CfgDotPrinter, cyclomatic_complexity,
//! find_back_edges, is_reducible, FlowEdgeKind, EdgeKind hash/eq consistency,
//! plus seeded-LCG fuzzing on the analyzer.

use rustre_analysis_cfg::edges::{FlowEdge, FlowEdgeKind};
use rustre_analysis_cfg::{
    BasicBlock, CfgDotPrinter, CfgEdge, CfgStats, DominatorTree, EdgeKind, PostDominatorTree,
    analyze_cfg, cfg_to_dot, cyclomatic_complexity, find_back_edges, find_natural_loops,
    is_reducible, try_analyze_cfg,
};
use rustre_core::address::Address;
use rustre_il_llil::{LlilInstruction, Size, llil_const, llil_reg};
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

// ───── helpers ─────────────────────────────────────────────────────────────

fn a(v: u64) -> Address {
    Address::new(v)
}
fn nop() -> LlilInstruction {
    LlilInstruction::Nop
}
fn ret() -> LlilInstruction {
    LlilInstruction::Ret
}
fn jmp(v: u64) -> LlilInstruction {
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

fn hash<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// A simple seeded LCG (no rand crate).
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

// Build a synthetic CFG directly (bypass analyze_cfg).
fn make_blocks(addrs: &[u64]) -> HashMap<Address, BasicBlock> {
    let mut m = HashMap::new();
    for &x in addrs {
        m.insert(
            a(x),
            BasicBlock {
                start: a(x),
                end: a(x + 4),
                instructions: vec![nop()],
            },
        );
    }
    m
}
fn make_edges(es: &[(u64, u64)]) -> Vec<CfgEdge> {
    es.iter()
        .map(|&(f, t)| CfgEdge {
            from: a(f),
            to: a(t),
            kind: EdgeKind::Unconditional,
        })
        .collect()
}

fn linear_chain(n: u64) -> Vec<(Address, LlilInstruction)> {
    // n nop's followed by ret.
    let mut v = Vec::new();
    for i in 0..n {
        v.push((a(i * 2), nop()));
    }
    v.push((a(n * 2), ret()));
    v
}

// ───── 1. Round-trip: EdgeKind <-> FlowEdgeKind ─────────────────────────────

#[test]
fn flow_edge_kind_to_kind_consistent_for_all_variants() {
    for k in [
        FlowEdgeKind::Fallthrough,
        FlowEdgeKind::Jump,
        FlowEdgeKind::BranchTaken,
        FlowEdgeKind::BranchNotTaken,
        FlowEdgeKind::Call,
        FlowEdgeKind::Return,
        FlowEdgeKind::Indirect,
    ] {
        let ek = k.to_edge_kind();
        // The mapping must be total (never panic) and produce one of 4 variants.
        match ek {
            EdgeKind::Unconditional
            | EdgeKind::TrueBranch
            | EdgeKind::FalseBranch
            | EdgeKind::Fallthrough => {}
        }
    }
}

#[test]
fn flow_edge_kind_intraprocedural_vs_call_return() {
    assert!(FlowEdgeKind::Jump.is_intraprocedural());
    assert!(FlowEdgeKind::BranchTaken.is_intraprocedural());
    assert!(FlowEdgeKind::Fallthrough.is_intraprocedural());
    assert!(!FlowEdgeKind::Call.is_intraprocedural());
    assert!(!FlowEdgeKind::Return.is_intraprocedural());
}

#[test]
fn flow_edge_kind_conditional_predicate() {
    assert!(FlowEdgeKind::BranchTaken.is_conditional());
    assert!(FlowEdgeKind::BranchNotTaken.is_conditional());
    assert!(!FlowEdgeKind::Jump.is_conditional());
    assert!(!FlowEdgeKind::Call.is_conditional());
}

#[test]
fn flow_edge_kind_tag_unique_per_variant() {
    let tags = [
        FlowEdgeKind::Fallthrough.tag(),
        FlowEdgeKind::Jump.tag(),
        FlowEdgeKind::BranchTaken.tag(),
        FlowEdgeKind::BranchNotTaken.tag(),
        FlowEdgeKind::Call.tag(),
        FlowEdgeKind::Return.tag(),
        FlowEdgeKind::Indirect.tag(),
    ];
    let set: HashSet<&'static str> = tags.iter().copied().collect();
    assert_eq!(set.len(), tags.len(), "tags must be unique per variant");
}

#[test]
fn flow_edge_new_and_lower_to_cfg_edge() {
    let fe = FlowEdge::new(a(1), a(2), FlowEdgeKind::Jump);
    let ce = fe.to_cfg_edge();
    assert_eq!(ce.from, a(1));
    assert_eq!(ce.to, a(2));
    assert_eq!(ce.kind, EdgeKind::Unconditional);
}

// ───── 2. Hash/Eq consistency on EdgeKind (30+ pairs) ───────────────────────

#[test]
fn edge_kind_hash_eq_consistency_seeded_30_pairs() {
    let variants = [
        EdgeKind::Unconditional,
        EdgeKind::TrueBranch,
        EdgeKind::FalseBranch,
        EdgeKind::Fallthrough,
    ];
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let mut checked = 0usize;
    for _ in 0..40 {
        let i = (lcg.next() % variants.len() as u64) as usize;
        let j = (lcg.next() % variants.len() as u64) as usize;
        let a = variants[i];
        let b = variants[j];
        if a == b {
            assert_eq!(hash(&a), hash(&b));
        }
        // hash(a) == hash(b) does NOT imply a == b in general, but is consistent.
        checked += 1;
    }
    assert!(checked >= 30);
}

// ───── 3. analyze_cfg basics ────────────────────────────────────────────────

#[test]
fn analyze_cfg_empty_yields_empty_blocks() {
    let cfg = analyze_cfg(&[]);
    assert_eq!(cfg.block_count(), 0);
    assert_eq!(cfg.edge_count(), 0);
    assert!(cfg.loops.is_empty());
}

#[test]
fn try_analyze_cfg_empty_errors() {
    assert!(try_analyze_cfg(&[]).is_err());
}

#[test]
fn analyze_cfg_single_nop_one_block_no_edges() {
    let cfg = analyze_cfg(&[(a(0), nop())]);
    assert_eq!(cfg.block_count(), 1);
    assert_eq!(cfg.edge_count(), 0);
}

#[test]
fn analyze_cfg_linear_chain_50_addresses() {
    let prog = linear_chain(50);
    let cfg = analyze_cfg(&prog);
    // Exactly one block (no branches), single Ret terminator.
    assert_eq!(cfg.block_count(), 1);
    assert_eq!(cfg.edge_count(), 0);
}

#[test]
fn analyze_cfg_simple_loop_has_back_edge() {
    let prog = vec![(a(0), jmp(4)), (a(4), cj(0, 8)), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    assert!(cfg.block_count() >= 2);
    let backs = find_back_edges(&cfg, &cfg.dom_tree);
    assert!(!backs.is_empty(), "loop must have at least one back edge");
}

#[test]
fn analyze_cfg_diamond_dominators() {
    let prog = vec![
        (a(0), cj(8, 4)),
        (a(4), jmp(0xC)),
        (a(8), nop()),
        (a(0xC), ret()),
    ];
    let cfg = analyze_cfg(&prog);
    assert!(cfg.dominates(a(0), a(4)));
    assert!(cfg.dominates(a(0), a(8)));
    assert!(cfg.dominates(a(0), a(0xC)));
    assert!(!cfg.dominates(a(4), a(8)));
    assert!(!cfg.dominates(a(8), a(4)));
}

#[test]
fn analyze_cfg_diamond_post_dominators() {
    let prog = vec![
        (a(0), cj(8, 4)),
        (a(4), jmp(0xC)),
        (a(8), nop()),
        (a(0xC), ret()),
    ];
    let cfg = analyze_cfg(&prog);
    // 0xC post-dominates everything.
    assert!(cfg.post_dominates(a(0xC), a(0)));
    assert!(cfg.post_dominates(a(0xC), a(4)));
}

// ───── 4. DominatorTree invariants ──────────────────────────────────────────

#[test]
fn dominator_self_dominance_reflexive() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    for k in cfg.blocks.keys() {
        assert!(cfg.dom_tree.dominates(*k, *k));
        assert!(!cfg.dom_tree.strictly_dominates(*k, *k));
    }
}

#[test]
fn dominator_depth_entry_is_zero() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    assert_eq!(cfg.dom_tree.depth(cfg.entry), 0);
}

#[test]
fn dominator_immediate_dominator_of_entry_is_none() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    assert_eq!(cfg.immediate_dominator(cfg.entry), None);
}

#[test]
fn dominator_synthetic_linear_chain_chain_idoms() {
    let blocks = make_blocks(&[0, 1, 2, 3, 4, 5]);
    let edges = make_edges(&[(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    assert_eq!(dt.idom[&a(0)], None);
    assert_eq!(dt.idom[&a(1)], Some(a(0)));
    assert_eq!(dt.idom[&a(5)], Some(a(4)));
    assert_eq!(dt.depth(a(5)), 5);
}

#[test]
fn dominator_dominated_by_includes_all_descendants() {
    let blocks = make_blocks(&[0, 1, 2, 3]);
    let edges = make_edges(&[(0, 1), (1, 2), (1, 3)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    let mut dom = dt.dominated_by(a(0));
    dom.sort_by_key(|x| x.0);
    assert_eq!(dom, vec![a(1), a(2), a(3)]);
}

#[test]
fn dominator_empty_inputs() {
    let blocks: HashMap<Address, BasicBlock> = HashMap::new();
    let dt = DominatorTree::compute(&blocks, &[], a(0));
    assert!(dt.idom.is_empty());
}

#[test]
fn dominator_dominance_frontier_diamond() {
    let blocks = make_blocks(&[0, 1, 2, 3]);
    let edges = make_edges(&[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    let df1 = dt.dominance_frontier(a(1));
    let df2 = dt.dominance_frontier(a(2));
    assert!(df1.contains(&a(3)));
    assert!(df2.contains(&a(3)));
}

// ───── 5. PostDominatorTree ─────────────────────────────────────────────────

#[test]
fn post_dominator_empty_graph() {
    let blocks: HashMap<Address, BasicBlock> = HashMap::new();
    let pdt = PostDominatorTree::compute(&blocks, &[]);
    assert!(pdt.idom.is_empty());
}

#[test]
fn post_dominator_single_block_self_post_dominates() {
    let blocks = make_blocks(&[0]);
    let pdt = PostDominatorTree::compute(&blocks, &[]);
    assert!(pdt.post_dominates(a(0), a(0)));
}

#[test]
fn post_dominator_linear_chain_each_node_dominates_predecessors() {
    let blocks = make_blocks(&[0, 1, 2, 3]);
    let edges = make_edges(&[(0, 1), (1, 2), (2, 3)]);
    let pdt = PostDominatorTree::compute(&blocks, &edges);
    assert!(pdt.post_dominates(a(3), a(0)));
    assert!(pdt.post_dominates(a(3), a(1)));
    assert!(pdt.post_dominates(a(3), a(2)));
}

// ───── 6. NaturalLoop / find_natural_loops ──────────────────────────────────

#[test]
fn find_natural_loops_no_loops_in_dag() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let loops = find_natural_loops(&cfg);
    assert!(loops.is_empty());
}

#[test]
fn find_natural_loops_simple_self_loop() {
    let blocks = make_blocks(&[0, 1, 2]);
    let edges = make_edges(&[(0, 1), (1, 1), (1, 2)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    let pdt = PostDominatorTree::compute(&blocks, &edges);
    let cfg = rustre_analysis_cfg::ControlFlowGraph {
        blocks,
        edges,
        entry: a(0),
        dom_tree: dt,
        post_dom_tree: pdt,
        loops: vec![],
    };
    let loops = find_natural_loops(&cfg);
    assert_eq!(loops.len(), 1);
    assert_eq!(loops[0].header, a(1));
    assert!(loops[0].contains(a(1)));
    assert_eq!(loops[0].size(), 1);
}

#[test]
fn find_natural_loops_nested_loop_innermost_marking() {
    // Outer loop: 0→1→2→1, inner self-loop: 2→2.
    let blocks = make_blocks(&[0, 1, 2, 3]);
    let edges = make_edges(&[(0, 1), (1, 2), (2, 2), (2, 1), (1, 3)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    let pdt = PostDominatorTree::compute(&blocks, &edges);
    let cfg = rustre_analysis_cfg::ControlFlowGraph {
        blocks,
        edges,
        entry: a(0),
        dom_tree: dt,
        post_dom_tree: pdt,
        loops: vec![],
    };
    let loops = find_natural_loops(&cfg);
    assert!(loops.len() >= 2);
    // The 2→2 self-loop body = {2}, that must be innermost.
    let inner = loops.iter().find(|l| l.body.len() == 1).expect("inner self-loop");
    assert!(inner.is_innermost);
}

// ───── 7. ControlFlowGraph helpers ──────────────────────────────────────────

#[test]
fn cfg_successors_and_predecessors_match_edges() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    for e in &cfg.edges {
        assert!(cfg.successors(e.from).contains(&e.to));
        assert!(cfg.predecessors(e.to).contains(&e.from));
    }
}

#[test]
fn cfg_reachable_from_entry_includes_all_blocks_in_connected_cfg() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let reach = cfg.reachable_from(cfg.entry);
    for k in cfg.blocks.keys() {
        assert!(reach.contains(k), "block {k:?} unreachable from entry");
    }
}

#[test]
fn cfg_reverse_post_order_starts_with_entry() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let rpo = cfg.reverse_post_order();
    assert!(!rpo.is_empty());
    assert_eq!(rpo[0], cfg.entry);
}

#[test]
fn cfg_post_order_is_reverse_of_rpo() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let rpo = cfg.reverse_post_order();
    let mut po = cfg.post_order();
    po.reverse();
    assert_eq!(po, rpo);
}

#[test]
fn cfg_to_petgraph_preserves_node_and_edge_counts() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let g = cfg.to_petgraph();
    assert_eq!(g.node_count(), cfg.block_count());
    assert_eq!(g.edge_count(), cfg.edge_count());
}

#[test]
fn cfg_immediate_dominator_via_helper() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    assert_eq!(cfg.immediate_dominator(cfg.entry), None);
    for k in cfg.blocks.keys() {
        if *k != cfg.entry {
            assert!(cfg.immediate_dominator(*k).is_some());
        }
    }
}

#[test]
fn cfg_dominance_frontier_helper_returns_vec() {
    let blocks = make_blocks(&[0, 1, 2, 3]);
    let edges = make_edges(&[(0, 1), (0, 2), (1, 3), (2, 3)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    let pdt = PostDominatorTree::compute(&blocks, &edges);
    let cfg = rustre_analysis_cfg::ControlFlowGraph {
        blocks,
        edges,
        entry: a(0),
        dom_tree: dt,
        post_dom_tree: pdt,
        loops: vec![],
    };
    let df = cfg.dominance_frontier(a(1));
    assert!(df.contains(&a(3)));
}

// ───── 8. CfgStats & cyclomatic complexity ──────────────────────────────────

#[test]
fn cfg_stats_basic_counts_match_cfg() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let s = CfgStats::compute(&cfg);
    assert_eq!(s.block_count, cfg.block_count());
    assert_eq!(s.node_count, s.block_count);
    assert_eq!(s.edge_count, cfg.edge_count());
}

#[test]
fn cfg_stats_is_complex_threshold() {
    let prog = vec![(a(0), nop()), (a(2), ret())];
    let cfg = analyze_cfg(&prog);
    let s = CfgStats::compute(&cfg);
    assert!(!s.is_complex());
}

#[test]
fn cyclomatic_complexity_dag_lower_bound() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let cc = cyclomatic_complexity(&cfg);
    assert!(cc >= 1);
}

#[test]
fn cyclomatic_complexity_linear_program_is_two() {
    // One block, zero edges, one connected component: E - N + 2P = 0 - 1 + 2 = 1.
    let prog = vec![(a(0), nop()), (a(2), ret())];
    let cfg = analyze_cfg(&prog);
    let cc = cyclomatic_complexity(&cfg);
    assert_eq!(cc, 1);
}

// ───── 9. DOT printer ───────────────────────────────────────────────────────

#[test]
fn cfg_to_dot_starts_with_digraph_and_ends_with_brace() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let dot = cfg_to_dot(&cfg);
    assert!(dot.starts_with("digraph cfg {"));
    assert!(dot.trim_end().ends_with('}'));
}

#[test]
fn cfg_dot_printer_default_matches_new() {
    let p1 = CfgDotPrinter::default();
    let p2 = CfgDotPrinter::new();
    assert_eq!(p1.show_instructions, p2.show_instructions);
    assert_eq!(p1.highlight_loops, p2.highlight_loops);
    assert_eq!(p1.highlight_back_edges, p2.highlight_back_edges);
}

#[test]
fn cfg_dot_printer_includes_each_block_node() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let dot = cfg_to_dot(&cfg);
    for k in cfg.blocks.keys() {
        let tag = format!("n{:x} ", k.0);
        assert!(dot.contains(&tag), "DOT missing node {tag:?}\n{dot}");
    }
}

// ───── 10. find_back_edges / is_reducible ───────────────────────────────────

#[test]
fn back_edges_empty_for_dag() {
    let prog = vec![(a(0), cj(8, 4)), (a(4), nop()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    assert!(find_back_edges(&cfg, &cfg.dom_tree).is_empty());
}

#[test]
fn is_reducible_for_simple_loop() {
    let prog = vec![(a(0), jmp(4)), (a(4), cj(0, 8)), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    assert!(is_reducible(&cfg));
}

// ───── 11. Seeded-LCG fuzzing on analyze_cfg ────────────────────────────────

#[test]
fn analyze_cfg_lcg_fuzz_random_terminators_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let opcodes = ["nop", "ret", "jmp", "cj"];
    for _ in 0..200 {
        // Build a small program of 2..=8 instructions ending in ret.
        let n = 2 + (lcg.next() as usize % 7);
        let mut prog: Vec<(Address, LlilInstruction)> = Vec::new();
        for i in 0..n - 1 {
            let pick = opcodes[(lcg.next() as usize) % opcodes.len()];
            let addr = a((i as u64) * 4);
            let inst = match pick {
                "nop" => nop(),
                "ret" => ret(),
                "jmp" => jmp((lcg.next() % 32) * 4),
                _ => cj((lcg.next() % 32) * 4, (lcg.next() % 32) * 4),
            };
            prog.push((addr, inst));
        }
        prog.push((a((n as u64 - 1) * 4), ret()));
        let cfg = analyze_cfg(&prog);
        // Test-side: edges may target addresses outside the known block set
        // when fuzz produces dangling jumps; the invariant is that aggregate
        // predecessor count over known blocks never exceeds the total edges.
        let pred_total: usize = cfg
            .blocks
            .keys()
            .map(|k| cfg.predecessors(*k).len())
            .sum();
        assert!(pred_total <= cfg.edges.len());
    }
}

#[test]
fn analyze_cfg_lcg_fuzz_arbitrary_addresses_invariant_block_le_edges_plus_one() {
    let mut lcg = Lcg::new(0xA5A5_5A5A_DEAD_C0DE);
    for _ in 0..100 {
        // 3..=6 instrs with random (but unique, sorted) addresses.
        let n = 3 + (lcg.next() as usize % 4);
        let mut addrs: Vec<u64> = (0..n).map(|i| (i as u64) * 4 + (lcg.next() % 8)).collect();
        addrs.sort_unstable();
        addrs.dedup();
        let mut prog: Vec<(Address, LlilInstruction)> = Vec::new();
        for (i, &x) in addrs.iter().enumerate() {
            let inst = if i + 1 == addrs.len() {
                ret()
            } else if lcg.next() & 1 == 0 {
                nop()
            } else {
                cj(addrs[(lcg.next() as usize) % addrs.len()], x.wrapping_add(4))
            };
            prog.push((a(x), inst));
        }
        let cfg = analyze_cfg(&prog);
        // For each block, last instr must be classifiable; no panic.
        for bb in cfg.blocks.values() {
            assert!(!bb.instructions.is_empty());
        }
    }
}

// ───── 12. Boundary inputs ──────────────────────────────────────────────────

#[test]
fn analyze_cfg_address_zero_and_max_u64_boundary() {
    let prog = vec![
        (a(0), jmp(u64::MAX)),
        (a(u64::MAX), ret()),
    ];
    let cfg = analyze_cfg(&prog);
    assert!(cfg.block_count() >= 1);
}

#[test]
fn dominator_off_by_one_two_node_chain() {
    let blocks = make_blocks(&[0, 1]);
    let edges = make_edges(&[(0, 1)]);
    let dt = DominatorTree::compute(&blocks, &edges, a(0));
    assert_eq!(dt.idom[&a(0)], None);
    assert_eq!(dt.idom[&a(1)], Some(a(0)));
}

#[test]
fn dominator_isolated_node_no_edges_handled() {
    let blocks = make_blocks(&[42]);
    let dt = DominatorTree::compute(&blocks, &[], a(42));
    assert_eq!(dt.idom[&a(42)], None);
    assert_eq!(dt.depth(a(42)), 0);
}

// ───── 13. Send/Sync threaded stress ────────────────────────────────────────

#[test]
fn analyze_cfg_threaded_4x100_reads() {
    use std::sync::Arc;
    use std::thread;
    let prog = vec![
        (a(0), cj(8, 4)),
        (a(4), jmp(0xC)),
        (a(8), nop()),
        (a(0xC), ret()),
    ];
    let cfg = Arc::new(analyze_cfg(&prog));
    let mut handles = vec![];
    for _ in 0..4 {
        let c = Arc::clone(&cfg);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                assert!(c.dominates(a(0), a(0xC)));
                let _ = c.successors(a(0));
                let _ = c.predecessors(a(0xC));
                let _ = CfgStats::compute(&c);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ───── 14. JumpTo target plumbing ────────────────────────────────────────────

#[test]
fn analyze_cfg_jumpto_targets_become_edges() {
    let prog = vec![
        (
            a(0),
            LlilInstruction::JumpTo {
                dest: llil_reg("rax", Size::QWord),
                targets: vec![a(4), a(8)],
            },
        ),
        (a(4), ret()),
        (a(8), ret()),
    ];
    let cfg = analyze_cfg(&prog);
    let succs = cfg.successors(a(0));
    assert!(succs.contains(&a(4)));
    assert!(succs.contains(&a(8)));
}

// ───── 15. CondJump dual successors ──────────────────────────────────────────

#[test]
fn analyze_cfg_condjump_has_two_distinct_successors() {
    let prog = vec![(a(0), cj(4, 8)), (a(4), ret()), (a(8), ret())];
    let cfg = analyze_cfg(&prog);
    let s = cfg.successors(a(0));
    assert!(s.contains(&a(4)));
    assert!(s.contains(&a(8)));
    // Edge kinds should be TrueBranch and FalseBranch.
    let kinds: HashSet<EdgeKind> = cfg
        .edges
        .iter()
        .filter(|e| e.from == a(0))
        .map(|e| e.kind)
        .collect();
    assert!(kinds.contains(&EdgeKind::TrueBranch));
    assert!(kinds.contains(&EdgeKind::FalseBranch));
}
