//! Exhaustive blitz tests for the public API of `rustre-decompiler-cfs`.
//!
//! Focus: edge cases, boundary conditions, adversarial inputs, round-trips,
//! and exercising public surface that the internal tests skip.

use rustre_decompiler_cfs::{
    BasicBlock, BlockId, BreakContinueRecovery, Cfg, CfgAnalysis, CfsAlgorithm, CfsPipeline,
    CfsValidator, ControlFlowStructurer, CriticalEdgeSplitter, DomTree, Dominators,
    EmptyBlockEliminator, FlattenPass, GotoEliminator, GotoEliminatorPass, GotoMinimizer,
    IrreducibleLoopHandler, LoopAnalysis, LoopDetector, LoopKind, LoopShape, NaturalLoop,
    PhoenixAlgorithm, PostDomTree, Region, RegionTree, SailrAlgorithm, Statement, StructuralAnalysis, StructuralRegionType, StructuredAst,
    StructuredNode, StructuringQualityMetrics, StructuringStrategy, SwitchAnalysis,
    SwitchCase, SwitchRecovery, TarjanScc, branch_condition, identifier_tokens,
    scc_groups,
};
use std::collections::HashMap;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn bb(id: u32, stmts: Vec<Statement>, succs: Vec<u32>) -> BasicBlock {
    BasicBlock {
        id: BlockId::new(id),
        stmts,
        successors: succs.into_iter().map(BlockId::new).collect(),
    }
}
fn br(c: &str) -> Statement {
    Statement::Branch(c.to_string())
}
fn raw(s: &str) -> Statement {
    Statement::Raw(s.to_string())
}
fn assign(l: &str, r: &str) -> Statement {
    Statement::Assign { lhs: l.to_string(), rhs: r.to_string() }
}
fn ret(v: Option<&str>) -> Statement {
    Statement::Return(v.map(str::to_string))
}

// ═══ BlockId ════════════════════════════════════════════════════════════════

#[test]
fn blockid_display_zero() {
    assert_eq!(BlockId::new(0).to_string(), "bb0");
}

#[test]
fn blockid_display_max() {
    assert_eq!(BlockId::new(u32::MAX).to_string(), format!("bb{}", u32::MAX));
}

#[test]
fn blockid_ord_is_numeric() {
    let mut v = vec![BlockId::new(5), BlockId::new(2), BlockId::new(10)];
    v.sort();
    assert_eq!(v, vec![BlockId::new(2), BlockId::new(5), BlockId::new(10)]);
}

#[test]
fn blockid_hash_equality() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(BlockId::new(7));
    assert!(s.contains(&BlockId::new(7)));
    assert!(!s.contains(&BlockId::new(8)));
}

#[test]
fn blockid_const_new() {
    const X: BlockId = BlockId::new(42);
    assert_eq!(X.0, 42);
}

// ═══ Statement / BasicBlock ════════════════════════════════════════════════

#[test]
fn basic_block_builder_pattern() {
    let b = BasicBlock::new(BlockId::new(1))
        .with_stmts(vec![raw("nop")])
        .with_successors(vec![BlockId::new(2)]);
    assert_eq!(b.id, BlockId::new(1));
    assert_eq!(b.stmts.len(), 1);
    assert_eq!(b.successors, vec![BlockId::new(2)]);
}

#[test]
fn basic_block_new_is_empty() {
    let b = BasicBlock::new(BlockId::new(0));
    assert!(b.stmts.is_empty());
    assert!(b.successors.is_empty());
}

#[test]
fn statement_equality() {
    assert_eq!(raw("a"), raw("a"));
    assert_ne!(raw("a"), raw("b"));
    assert_ne!(br("x"), raw("x"));
}

// ═══ StructureError variants ════════════════════════════════════════════════

#[test]
fn empty_cfg_error_message() {
    let err = ControlFlowStructurer::new(vec![]).structure(BlockId::new(0));
    let s = format!("{}", err.unwrap_err());
    assert!(s.contains("empty"));
}

#[test]
fn entry_not_found_error_message() {
    let blocks = vec![bb(0, vec![], vec![])];
    let err = ControlFlowStructurer::new(blocks).structure(BlockId::new(99));
    let s = format!("{}", err.unwrap_err());
    assert!(s.contains("bb99"));
}

// ═══ StructuredNode::flatten / goto_count / node_count ══════════════════════

#[test]
fn flatten_empty_sequence_stays_empty() {
    let n = StructuredNode::Sequence(vec![]);
    let f = n.flatten();
    assert!(matches!(f, StructuredNode::Sequence(ref v) if v.is_empty()));
}

#[test]
fn flatten_nested_single_chain() {
    let inner = StructuredNode::Return(Some("0".into()));
    let nested = StructuredNode::Sequence(vec![StructuredNode::Sequence(vec![
        StructuredNode::Sequence(vec![inner.clone()]),
    ])]);
    assert_eq!(nested.flatten(), inner);
}

#[test]
fn node_count_leaf_is_one() {
    assert_eq!(StructuredNode::Break.node_count(), 1);
    assert_eq!(StructuredNode::Continue.node_count(), 1);
    assert_eq!(StructuredNode::Return(None).node_count(), 1);
    assert_eq!(StructuredNode::Goto(BlockId::new(0)).node_count(), 1);
}

#[test]
fn goto_count_in_switch() {
    let n = StructuredNode::Switch {
        expr: "x".into(),
        cases: vec![
            SwitchCase { value: Some(1), body: Box::new(StructuredNode::Goto(BlockId::new(5))) },
            SwitchCase { value: None, body: Box::new(StructuredNode::Goto(BlockId::new(6))) },
        ],
    };
    assert_eq!(n.goto_count(), 2);
}

#[test]
fn goto_count_in_loop() {
    let n = StructuredNode::Loop {
        kind: LoopKind::While,
        condition: "c".into(),
        body: Box::new(StructuredNode::Goto(BlockId::new(0))),
    };
    assert_eq!(n.goto_count(), 1);
}

// ═══ Serialization round-trips ══════════════════════════════════════════════

#[test]
fn roundtrip_block_id() {
    let id = BlockId::new(123);
    let j = serde_json::to_string(&id).unwrap();
    let d: BlockId = serde_json::from_str(&j).unwrap();
    assert_eq!(id, d);
}

#[test]
fn roundtrip_statement_all_variants() {
    let stmts = vec![
        raw("x"),
        assign("a", "b"),
        ret(Some("0")),
        ret(None),
        br("cond"),
    ];
    let j = serde_json::to_string(&stmts).unwrap();
    let d: Vec<Statement> = serde_json::from_str(&j).unwrap();
    assert_eq!(stmts, d);
}

#[test]
fn roundtrip_complex_structured_node() {
    let n = StructuredNode::IfElse {
        condition: "a > 0".into(),
        then_branch: Box::new(StructuredNode::Loop {
            kind: LoopKind::DoWhile,
            condition: "c".into(),
            body: Box::new(StructuredNode::Break),
        }),
        else_branch: Box::new(StructuredNode::Return(Some("1".into()))),
    };
    let j = serde_json::to_string(&n).unwrap();
    let d: StructuredNode = serde_json::from_str(&j).unwrap();
    assert_eq!(n, d);
}

// ═══ ControlFlowStructurer adversarial inputs ═══════════════════════════════

#[test]
fn structurer_unreachable_block_does_not_panic() {
    // Block 99 isolated; entry is 0 → 1.
    let blocks = vec![
        bb(0, vec![raw("a")], vec![1]),
        bb(1, vec![ret(None)], vec![]),
        bb(99, vec![raw("dead")], vec![]),
    ];
    let ast = ControlFlowStructurer::new(blocks).structure(BlockId::new(0)).unwrap();
    assert_eq!(ast.entry, BlockId::new(0));
}

#[test]
fn structurer_dangling_successor_is_ignored() {
    let blocks = vec![bb(0, vec![raw("a")], vec![77])];
    // Edge target 77 doesn't exist; build should still succeed (filtered).
    let res = ControlFlowStructurer::new(blocks).structure(BlockId::new(0));
    assert!(res.is_ok());
}

#[test]
fn structurer_deep_chain_no_stack_overflow() {
    // 200 block linear chain.
    let mut blocks: Vec<BasicBlock> = (0..199_u32)
        .map(|i| bb(i, vec![raw(&format!("s{i}"))], vec![i + 1]))
        .collect();
    blocks.push(bb(199, vec![ret(None)], vec![]));
    let ast = ControlFlowStructurer::new(blocks).structure(BlockId::new(0)).unwrap();
    assert_eq!(ast.goto_count, 0);
}

#[test]
fn structurer_parallel_edges_collapse_in_cfg() {
    // Same successor listed twice should not double-count predecessors in Cfg.
    let blocks = vec![bb(0, vec![br("c")], vec![1, 1]), bb(1, vec![ret(None)], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    assert_eq!(cfg.predecessors(BlockId::new(1)).len(), 1);
}

// ═══ Cfg ═════════════════════════════════════════════════════════════════════

#[test]
fn cfg_empty() {
    let cfg = Cfg::from_blocks(&[]);
    assert!(cfg.is_empty());
    assert_eq!(cfg.len(), 0);
    assert!(!cfg.contains(BlockId::new(0)));
}

#[test]
fn cfg_block_lookup() {
    let blocks = vec![bb(5, vec![raw("x")], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    assert!(cfg.contains(BlockId::new(5)));
    let b = cfg.block(BlockId::new(5)).unwrap();
    assert_eq!(b.id, BlockId::new(5));
    assert!(cfg.block(BlockId::new(99)).is_none());
}

#[test]
fn cfg_block_ids_sorted() {
    let blocks = vec![bb(3, vec![], vec![]), bb(1, vec![], vec![]), bb(2, vec![], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    let ids = cfg.block_ids();
    assert_eq!(ids, vec![BlockId::new(1), BlockId::new(2), BlockId::new(3)]);
}

#[test]
fn cfg_dfs_from_isolated_entry() {
    let blocks = vec![bb(0, vec![], vec![]), bb(1, vec![], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    let dfs = cfg.dfs_preorder(BlockId::new(0));
    assert_eq!(dfs, vec![BlockId::new(0)]);
}

#[test]
fn cfg_rpo_includes_only_reachable() {
    let blocks = vec![bb(0, vec![], vec![1]), bb(1, vec![], vec![]), bb(2, vec![], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    let rpo = cfg.reverse_postorder(BlockId::new(0));
    assert!(!rpo.contains(&BlockId::new(2)));
    assert!(rpo.contains(&BlockId::new(0)));
}

#[test]
fn cfg_reachable_self_loop() {
    let blocks = vec![bb(0, vec![], vec![0])];
    let cfg = Cfg::from_blocks(&blocks);
    let r = cfg.reachable(BlockId::new(0));
    assert_eq!(r.len(), 1);
}

// ═══ TarjanScc / scc_groups ═════════════════════════════════════════════════

#[test]
fn tarjan_self_loop_is_scc() {
    let blocks = vec![bb(0, vec![], vec![0])];
    let cfg = Cfg::from_blocks(&blocks);
    let sccs = TarjanScc::run(&cfg);
    assert_eq!(sccs.len(), 1);
    assert_eq!(sccs[0], vec![BlockId::new(0)]);
}

#[test]
fn tarjan_empty_graph() {
    let cfg = Cfg::from_blocks(&[]);
    let sccs = TarjanScc::run(&cfg);
    assert!(sccs.is_empty());
}

#[test]
fn scc_groups_works_on_legacy_cfggraph() {
    // scc_groups operates on the legacy petgraph CfgGraph (internal),
    // exposed only through this function. Build a structurer to get into the
    // path that uses it.
    let blocks = vec![bb(0, vec![ret(None)], vec![])];
    // Just smoke-test that the symbol can be invoked via building structurer.
    let _ = ControlFlowStructurer::new(blocks).structure(BlockId::new(0));
    // Use scc_groups via a fresh internal graph (it needs CfgGraph which is
    // pub). Construct one through the public Result API path.
    // We can't easily build CfgGraph from outside, so just ensure scc_groups
    // is a callable item with the right signature by reference.
    // Use `scc_groups` via a function pointer to verify its public signature.
    let f: fn(&_) -> Vec<Vec<_>> = scc_groups;
    let _ = f;
}

// ═══ Dominators ══════════════════════════════════════════════════════════════

#[test]
fn dominators_entry_dominates_itself() {
    let blocks = vec![bb(0, vec![ret(None)], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    let d = Dominators::compute(&cfg, BlockId::new(0));
    assert!(d.dominates(BlockId::new(0), BlockId::new(0)));
    assert_eq!(d.idom(BlockId::new(0)), Some(BlockId::new(0)));
}

#[test]
fn dominators_not_dominates_unrelated() {
    let blocks = vec![bb(0, vec![], vec![1, 2]), bb(1, vec![], vec![]), bb(2, vec![], vec![])];
    let cfg = Cfg::from_blocks(&blocks);
    let d = Dominators::compute(&cfg, BlockId::new(0));
    assert!(!d.dominates(BlockId::new(1), BlockId::new(2)));
    assert!(!d.dominates(BlockId::new(2), BlockId::new(1)));
}

// ═══ LoopAnalysis ════════════════════════════════════════════════════════════

#[test]
fn loop_analysis_no_loops() {
    let blocks = vec![bb(0, vec![], vec![1]), bb(1, vec![ret(None)], vec![])];
    let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    assert_eq!(la.loop_count(), 0);
    assert!(!la.is_header(BlockId::new(0)));
}

#[test]
fn loop_analysis_self_loop_shape() {
    let blocks = vec![bb(0, vec![], vec![0])];
    let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    assert_eq!(la.count_shape(LoopShape::SelfLoop), 1);
    assert!(la.is_header(BlockId::new(0)));
}

#[test]
fn loop_analysis_innermost_header_of_outer_block() {
    let blocks = vec![
        bb(0, vec![], vec![1]),
        bb(1, vec![br("c")], vec![2, 3]),
        bb(2, vec![], vec![1]),
        bb(3, vec![ret(None)], vec![]),
    ];
    let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    // Block 0 is outside any loop.
    assert!(la.innermost_header(BlockId::new(0)).is_none());
    // Block 1 is in a loop with header 1.
    assert_eq!(la.innermost_header(BlockId::new(1)), Some(BlockId::new(1)));
}

#[test]
fn loop_analysis_exits_unique_and_sorted() {
    let blocks = vec![
        bb(0, vec![], vec![1]),
        bb(1, vec![br("c")], vec![2, 5]),
        bb(2, vec![br("d")], vec![1, 5]), // second exit to same target
        bb(5, vec![ret(None)], vec![]),
    ];
    let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    let l = &la.loops()[0];
    // Should be deduped.
    let count_5 = l.exits.iter().filter(|&&e| e == BlockId::new(5)).count();
    assert_eq!(count_5, 1);
}

#[test]
fn detected_loop_contains_and_size() {
    let blocks = vec![
        bb(0, vec![], vec![1]),
        bb(1, vec![br("c")], vec![2, 3]),
        bb(2, vec![], vec![1]),
        bb(3, vec![ret(None)], vec![]),
    ];
    let la = LoopAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    let l = &la.loops()[0];
    assert!(l.contains(l.header));
    assert!(l.size() >= 2);
}

// ═══ Condition algebra ══════════════════════════════════════════════════════

use rustre_decompiler_cfs::Condition;

#[test]
fn condition_true_false_negate() {
    assert_eq!(Condition::True.negate(), Condition::False);
    assert_eq!(Condition::False.negate(), Condition::True);
}

#[test]
fn condition_to_c_constants() {
    assert_eq!(Condition::True.to_c(), "true");
    assert_eq!(Condition::False.to_c(), "false");
}

#[test]
fn condition_atom_count_zero_for_constants() {
    assert_eq!(Condition::True.atom_count(), 0);
    assert_eq!(Condition::False.atom_count(), 0);
}

#[test]
fn condition_demorgan_or() {
    // !(a || b) = !a && !b
    let c = Condition::atom("a").or(Condition::atom("b")).negate();
    assert_eq!(c.to_c(), "!(a) && !(b)");
}

#[test]
fn condition_roundtrip_serde() {
    let c = Condition::atom("x").and(Condition::atom("y").or(Condition::atom("z")));
    let j = serde_json::to_string(&c).unwrap();
    let d: Condition = serde_json::from_str(&j).unwrap();
    assert_eq!(c, d);
}

#[test]
fn condition_and_with_true_absorbs() {
    let c = Condition::atom("x").and(Condition::True);
    assert_eq!(c, Condition::atom("x"));
}

#[test]
fn condition_or_with_false_absorbs() {
    let c = Condition::atom("x").or(Condition::False);
    assert_eq!(c, Condition::atom("x"));
}

// ═══ branch_condition / identifier_tokens ═══════════════════════════════════

#[test]
fn branch_condition_returns_last_branch() {
    let b = BasicBlock {
        id: BlockId::new(0),
        stmts: vec![br("first"), raw("x"), br("last")],
        successors: vec![],
    };
    assert_eq!(branch_condition(&b), Some("last".to_string()));
}

#[test]
fn branch_condition_none_when_no_branch() {
    let b = BasicBlock { id: BlockId::new(0), stmts: vec![raw("x")], successors: vec![] };
    assert_eq!(branch_condition(&b), None);
}

#[test]
fn identifier_tokens_skips_numerics() {
    let t = identifier_tokens("foo == 42 + bar");
    assert!(t.contains(&"foo".to_string()));
    assert!(t.contains(&"bar".to_string()));
    assert!(!t.contains(&"42".to_string()));
}

#[test]
fn identifier_tokens_empty_input() {
    assert!(identifier_tokens("").is_empty());
}

#[test]
fn identifier_tokens_underscore_allowed() {
    let t = identifier_tokens("my_var");
    assert_eq!(t, vec!["my_var".to_string()]);
}

#[test]
fn identifier_tokens_pure_numeric_only() {
    assert!(identifier_tokens("123 456").is_empty());
}

// ═══ SwitchAnalysis ══════════════════════════════════════════════════════════

#[test]
fn switch_analysis_jump_table_synthesised_discriminant() {
    // No branch stmt → default discriminant.
    let blocks = vec![
        bb(0, vec![], vec![1, 2, 3]),
        bb(1, vec![ret(None)], vec![]),
        bb(2, vec![ret(None)], vec![]),
        bb(3, vec![ret(None)], vec![]),
    ];
    let sa = SwitchAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    assert_eq!(sa.count(), 1);
    assert_eq!(sa.switches()[0].discriminant, "switch_var");
}

#[test]
fn switch_analysis_no_switch_for_two_successors() {
    let blocks = vec![
        bb(0, vec![br("x")], vec![1, 2]),
        bb(1, vec![ret(None)], vec![]),
        bb(2, vec![ret(None)], vec![]),
    ];
    let sa = SwitchAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    // Just an if, not a switch.
    assert!(sa.switches().iter().all(|s| !s.jump_table));
}

#[test]
fn switch_analysis_cmp_chain_with_hex() {
    let blocks = vec![
        bb(0, vec![br("flags == 0x10")], vec![10, 1]),
        bb(1, vec![br("flags == 0x20")], vec![11, 2]),
        bb(10, vec![ret(None)], vec![]),
        bb(11, vec![ret(None)], vec![]),
        bb(2, vec![ret(None)], vec![]),
    ];
    let sa = SwitchAnalysis::analyze(&Cfg::from_blocks(&blocks), BlockId::new(0));
    let sw = sa.switches().iter().find(|s| !s.jump_table).expect("cmp chain");
    assert_eq!(sw.discriminant, "flags");
    // Cases 0x10 and 0x20 → 16 and 32.
    let values: Vec<i64> = sw.cases.iter().filter_map(|c| c.value).collect();
    assert!(values.contains(&16));
    assert!(values.contains(&32));
}

// ═══ CriticalEdgeSplitter ════════════════════════════════════════════════════

#[test]
fn critical_edge_splitter_splits() {
    // 0 → {1, 2}, 1 → 3, 2 → 3.  Edges (0,1) and (0,2) only have 1 pred at the
    // dest each so NOT critical. But edges to a block with 2 preds (i.e. 3)
    // from a multi-succ block would be critical. Construct that: 0 → {3, x}
    // where 3 has multiple preds.
    let mut blocks = vec![
        bb(0, vec![br("c")], vec![3, 4]),
        bb(1, vec![], vec![3]),
        bb(3, vec![ret(None)], vec![]),
        bb(4, vec![ret(None)], vec![]),
    ];
    let mut pred_count: HashMap<BlockId, usize> = HashMap::new();
    pred_count.insert(BlockId::new(3), 2); // 0 and 1 point at it
    pred_count.insert(BlockId::new(4), 1);
    let mut splitter = CriticalEdgeSplitter::new(100);
    let new = splitter.split(&mut blocks, &pred_count);
    assert!(splitter.splits() >= 1);
    assert!(!new.is_empty());
    // The first new block id should be 100.
    assert_eq!(new[0].id, BlockId::new(100));
}

#[test]
fn critical_edge_splitter_skips_single_succ() {
    let mut blocks = vec![bb(0, vec![], vec![1]), bb(1, vec![ret(None)], vec![])];
    let mut pc: HashMap<BlockId, usize> = HashMap::new();
    pc.insert(BlockId::new(1), 1);
    let mut s = CriticalEdgeSplitter::new(50);
    let new = s.split(&mut blocks, &pc);
    assert!(new.is_empty());
    assert_eq!(s.splits(), 0);
}

// ═══ EmptyBlockEliminator ═══════════════════════════════════════════════════

#[test]
fn empty_block_eliminator_chain() {
    // 0 (empty) → 1 (empty) → 2 (real)
    let blocks = vec![
        bb(0, vec![], vec![1]),
        bb(1, vec![], vec![2]),
        bb(2, vec![ret(None)], vec![]),
    ];
    let mut e = EmptyBlockEliminator::new();
    let result = e.eliminate(blocks);
    // Both 0 and 1 should be removed.
    assert!(!result.iter().any(|b| b.id == BlockId::new(0)));
    assert!(!result.iter().any(|b| b.id == BlockId::new(1)));
    assert_eq!(e.eliminated(), 2);
}

#[test]
fn empty_block_eliminator_cycle_does_not_hang() {
    // Two empty blocks pointing at each other; should not infinite-loop.
    let blocks = vec![
        bb(0, vec![], vec![1]),
        bb(1, vec![], vec![0]),
        bb(2, vec![ret(None)], vec![]),
    ];
    let mut e = EmptyBlockEliminator::new();
    let _ = e.eliminate(blocks);
}

#[test]
fn empty_block_eliminator_preserves_non_empty() {
    let blocks = vec![bb(0, vec![raw("x")], vec![1]), bb(1, vec![ret(None)], vec![])];
    let mut e = EmptyBlockEliminator::new();
    let r = e.eliminate(blocks);
    assert_eq!(r.len(), 2);
    assert_eq!(e.eliminated(), 0);
}

// ═══ IrreducibleLoopHandler ═════════════════════════════════════════════════

#[test]
fn irreducible_no_back_edges() {
    assert!(!IrreducibleLoopHandler::is_irreducible(&[]));
}

#[test]
fn irreducible_handle_increments() {
    let mut h = IrreducibleLoopHandler::new();
    h.handle(&mut vec![], &[BlockId::new(0), BlockId::new(1)]);
    assert_eq!(h.splits(), 2);
}

// ═══ LoopDetector & NaturalLoop ═════════════════════════════════════════════

#[test]
fn loop_detector_loop_for_header_finds_match() {
    let mut ld = LoopDetector::new();
    ld.add_back_edge(BlockId::new(3), BlockId::new(1));
    let l = ld.loop_for_header(BlockId::new(1)).unwrap();
    assert_eq!(l.header, BlockId::new(1));
    assert_eq!(l.latch, BlockId::new(3));
    assert!(ld.loop_for_header(BlockId::new(99)).is_none());
}

#[test]
fn natural_loop_size() {
    let nl = NaturalLoop {
        header: BlockId::new(0),
        latch: BlockId::new(1),
        body: vec![BlockId::new(0), BlockId::new(1)],
    };
    assert_eq!(nl.size(), 2);
}

// ═══ GotoEliminator ═════════════════════════════════════════════════════════

#[test]
fn goto_eliminator_non_header_returns_none() {
    let mut ge = GotoEliminator::new();
    let ld = LoopDetector::new();
    assert!(ge.try_eliminate(BlockId::new(0), &ld).is_none());
    assert_eq!(ge.break_continue_recovered(), 0);
}

#[test]
fn goto_eliminator_second_pass_drops_trivial_fallthrough() {
    // Sequence [BasicBlock(0), Goto(1), BasicBlock(1)] → the goto is redundant.
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock { id: BlockId::new(0), stmts: vec![] },
            StructuredNode::Goto(BlockId::new(1)),
            StructuredNode::BasicBlock { id: BlockId::new(1), stmts: vec![] },
        ]),
        goto_count: 1,
        loop_count: 0,
    };
    let mut ge = GotoEliminator::new();
    let result = ge.second_pass(ast, &LoopDetector::new());
    assert_eq!(result.goto_count, 0);
    assert_eq!(ge.gotos_eliminated(), 1);
}

#[test]
fn goto_eliminator_second_pass_converts_to_continue() {
    let mut ld = LoopDetector::new();
    ld.add_back_edge(BlockId::new(5), BlockId::new(2));
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::Goto(BlockId::new(2)),
        goto_count: 1,
        loop_count: 1,
    };
    let mut ge = GotoEliminator::new();
    let r = ge.second_pass(ast, &ld);
    assert!(matches!(r.root, StructuredNode::Continue));
    assert_eq!(ge.break_continue_recovered(), 1);
}

#[test]
fn goto_to_structured_break_collects() {
    let mut ld = LoopDetector::new();
    ld.add_back_edge(BlockId::new(1), BlockId::new(0));
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::Sequence(vec![
            StructuredNode::Goto(BlockId::new(99)), // outside any loop → break candidate
        ]),
        goto_count: 1,
        loop_count: 1,
    };
    let reps = GotoEliminator::goto_to_structured_break(&ast, &ld);
    assert_eq!(reps.len(), 1);
    assert_eq!(reps[0].goto_target, BlockId::new(99));
    assert!(matches!(reps[0].replacement, StructuredNode::Break));
}

// ═══ GotoMinimizer ══════════════════════════════════════════════════════════

#[test]
fn goto_minimizer_targets_deduped_and_sorted() {
    let root = StructuredNode::Sequence(vec![
        StructuredNode::Goto(BlockId::new(3)),
        StructuredNode::Goto(BlockId::new(1)),
        StructuredNode::Goto(BlockId::new(3)),
    ]);
    let r = GotoMinimizer::new().report(&root, &[]);
    assert_eq!(r.targets, vec![BlockId::new(1), BlockId::new(3)]);
}

#[test]
fn goto_minimizer_empty_report() {
    let root = StructuredNode::Break;
    let r = GotoMinimizer::new().report(&root, &[]);
    assert_eq!(r.total, 0);
    assert_eq!(r.forward, 0);
    assert_eq!(r.backward, 0);
    assert!(r.targets.is_empty());
}

// ═══ DomTree / PostDomTree (legacy) ══════════════════════════════════════════

#[test]
fn dom_tree_self_dominates() {
    let dt = DomTree::new();
    assert!(dt.dominates(BlockId::new(0), BlockId::new(0)));
}

#[test]
fn dom_tree_path_root_only() {
    let dt = DomTree::new();
    let p = dt.dominance_path(BlockId::new(7));
    assert_eq!(p, vec![BlockId::new(7)]);
}

#[test]
fn dom_tree_children_empty_for_unknown() {
    let dt = DomTree::new();
    assert!(dt.children(BlockId::new(99)).is_empty());
}

#[test]
fn postdomtree_self_pdom() {
    let pdt = PostDomTree::new();
    assert!(pdt.post_dominates(BlockId::new(0), BlockId::new(0)));
}

#[test]
fn postdomtree_no_pdom() {
    let pdt = PostDomTree::new();
    assert!(!pdt.post_dominates(BlockId::new(0), BlockId::new(1)));
}

// ═══ RegionTree / Region ═════════════════════════════════════════════════════

#[test]
fn region_tree_set_and_get_root() {
    let mut rt = RegionTree::new();
    assert!(rt.root().is_none());
    rt.set_root(Region::Block(BlockId::new(0)));
    assert!(rt.root().is_some());
}

#[test]
fn region_depth_block_is_zero() {
    assert_eq!(Region::Block(BlockId::new(0)).depth(), 0);
    assert_eq!(Region::SelfLoop(BlockId::new(0)).depth(), 0);
    assert_eq!(Region::Sequence(vec![BlockId::new(0)]).depth(), 0);
}

#[test]
fn region_is_loop_variants() {
    assert!(Region::While { header: BlockId::new(0), body: Box::new(Region::Block(BlockId::new(1))) }.is_loop());
    assert!(Region::For { header: BlockId::new(0), body: Box::new(Region::Block(BlockId::new(1))) }.is_loop());
    assert!(Region::DoWhile { body: Box::new(Region::Block(BlockId::new(1))), latch: BlockId::new(0) }.is_loop());
    assert!(!Region::Sequence(vec![]).is_loop());
    assert!(!Region::IfThen { cond: BlockId::new(0), then_region: Box::new(Region::Block(BlockId::new(1))) }.is_loop());
}

#[test]
fn region_block_ids_switch_collects_all() {
    let r = Region::Switch {
        header: BlockId::new(0),
        cases: vec![
            (Some(1), Box::new(Region::Block(BlockId::new(1)))),
            (None, Box::new(Region::Block(BlockId::new(2)))),
        ],
    };
    let ids = r.block_ids();
    assert!(ids.contains(&BlockId::new(0)));
    assert!(ids.contains(&BlockId::new(1)));
    assert!(ids.contains(&BlockId::new(2)));
}

#[test]
fn region_block_ids_dowhile() {
    let r = Region::DoWhile {
        body: Box::new(Region::Block(BlockId::new(1))),
        latch: BlockId::new(2),
    };
    let ids = r.block_ids();
    assert!(ids.contains(&BlockId::new(1)));
    assert!(ids.contains(&BlockId::new(2)));
}

// ═══ SwitchRecovery (legacy) ════════════════════════════════════════════════

#[test]
fn switch_recovery_zero_successors() {
    let mut sr = SwitchRecovery::new();
    let b = BasicBlock { id: BlockId::new(0), stmts: vec![], successors: vec![] };
    assert!(sr.recover_from_block(&b).is_none());
    assert_eq!(sr.recovered_count(), 0);
}

#[test]
fn switch_recovery_many_successors() {
    let mut sr = SwitchRecovery::new();
    let b = BasicBlock {
        id: BlockId::new(0),
        stmts: vec![],
        successors: (1..6).map(BlockId::new).collect(),
    };
    let r = sr.recover_from_block(&b).unwrap();
    if let Region::Switch { cases, .. } = r {
        assert_eq!(cases.len(), 5);
    } else {
        panic!("expected Switch");
    }
}

// ═══ BreakContinueRecovery ═══════════════════════════════════════════════════

#[test]
fn break_continue_recovery_independent_counters() {
    let mut bcr = BreakContinueRecovery::new();
    bcr.recover_break(BlockId::new(0), BlockId::new(1));
    bcr.recover_break(BlockId::new(0), BlockId::new(1));
    bcr.recover_continue(BlockId::new(0), BlockId::new(1));
    assert_eq!(bcr.breaks(), 2);
    assert_eq!(bcr.continues(), 1);
}

// ═══ PhoenixAlgorithm / SailrAlgorithm ══════════════════════════════════════

#[test]
fn phoenix_empty_blocks_emits_synth() {
    let mut p = PhoenixAlgorithm::new();
    let ast = p.structure(vec![], BlockId::new(0));
    // Falls into the error branch — should produce a single-node fallback.
    assert_eq!(ast.entry, BlockId::new(0));
    assert_eq!(p.gotos_emitted(), 1);
}

#[test]
fn sailr_simple_back_edge_counted() {
    let mut s = SailrAlgorithm::new();
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![], vec![0]),
        bb(2, vec![ret(None)], vec![]),
    ];
    let _ = s.structure(blocks, BlockId::new(0));
    assert!(s.loops_recovered() >= 1);
}

// ═══ StructuralAnalysis ══════════════════════════════════════════════════════

#[test]
fn structural_analysis_improper_for_many_succs() {
    let sa = StructuralAnalysis::new();
    let blocks = vec![BasicBlock {
        id: BlockId::new(0),
        stmts: vec![],
        successors: (1..5).map(BlockId::new).collect(),
    }];
    let r = sa.analyse(&blocks);
    assert_eq!(r[0].region_type, StructuralRegionType::Improper);
}

#[test]
fn structural_analysis_empty_blocks() {
    let r = StructuralAnalysis::new().analyse(&[]);
    assert!(r.is_empty());
}

// ═══ CfsValidator ═══════════════════════════════════════════════════════════

#[test]
fn cfs_validator_detects_missing_block() {
    let validator = CfsValidator::new();
    let blocks = vec![
        bb(0, vec![ret(None)], vec![]),
        bb(1, vec![ret(None)], vec![]),
    ];
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::BasicBlock { id: BlockId::new(0), stmts: vec![] },
        goto_count: 0,
        loop_count: 0,
    };
    let r = validator.validate(&ast, &blocks);
    assert!(r.is_err());
    let msg = r.unwrap_err();
    // Validator uses Debug formatting for the BlockId list.
    assert!(msg.contains("missing"));
    assert!(msg.contains('1'));
}

#[test]
fn cfs_validator_goto_target_counts_as_present() {
    let validator = CfsValidator::new();
    let blocks = vec![bb(0, vec![], vec![]), bb(1, vec![], vec![])];
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::Sequence(vec![
            StructuredNode::BasicBlock { id: BlockId::new(0), stmts: vec![] },
            StructuredNode::Goto(BlockId::new(1)),
        ]),
        goto_count: 1,
        loop_count: 0,
    };
    // Per implementation, goto targets are inserted into the ast block set.
    assert!(validator.validate(&ast, &blocks).is_ok());
}

// ═══ CfgAnalysis end-to-end ═════════════════════════════════════════════════

#[test]
fn cfg_analysis_irreducible_detected() {
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![], vec![2]),
        bb(2, vec![], vec![1]),
    ];
    let a = CfgAnalysis::run(&blocks, BlockId::new(0)).unwrap();
    assert!(a.has_irreducible());
}

#[test]
fn cfg_analysis_structure_returns_report() {
    let blocks = vec![bb(0, vec![ret(None)], vec![])];
    let a = CfgAnalysis::run(&blocks, BlockId::new(0)).unwrap();
    let (_ast, report) = a.structure(&blocks).unwrap();
    assert_eq!(report.total, 0);
}

// ═══ CfsAlgorithm Display ════════════════════════════════════════════════════

#[test]
fn cfs_algorithm_structural_display() {
    assert_eq!(CfsAlgorithm::Structural.to_string(), "Structural");
}

#[test]
fn cfs_algorithm_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(CfsAlgorithm::Dream);
    s.insert(CfsAlgorithm::Dream);
    assert_eq!(s.len(), 1);
}

// ═══ StructuringQualityMetrics ══════════════════════════════════════════════

#[test]
fn metrics_default() {
    let m = StructuringQualityMetrics::default();
    assert_eq!(m.score(), 0);
}

#[test]
fn metrics_roundtrip_serde() {
    let m = StructuringQualityMetrics {
        goto_count: 3,
        max_nesting_depth: 4,
        switch_count: 1,
        loop_count: 2,
        unreachable_blocks: 0,
    };
    let j = serde_json::to_string(&m).unwrap();
    let d: StructuringQualityMetrics = serde_json::from_str(&j).unwrap();
    assert_eq!(m, d);
}

// ═══ StructuringStrategy ═════════════════════════════════════════════════════

#[test]
fn strategy_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(StructuringStrategy::Hybrid);
    s.insert(StructuringStrategy::Hybrid);
    assert_eq!(s.len(), 1);
}

#[test]
fn strategy_boundary_100_is_phoenix() {
    // The doc comment says ≤ 100 → Phoenix; verify exactly at boundary.
    assert_eq!(StructuringStrategy::choose_strategy(100), StructuringStrategy::Phoenix);
    assert_eq!(StructuringStrategy::choose_strategy(101), StructuringStrategy::Hybrid);
}

// ═══ CfsPipeline ═════════════════════════════════════════════════════════════

#[test]
fn pipeline_empty_runs() {
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::Return(None),
        goto_count: 0,
        loop_count: 0,
    };
    let mut p = CfsPipeline::new();
    assert_eq!(p.pass_count(), 0);
    let (out, m) = p.run(ast);
    assert_eq!(out.goto_count, 0);
    assert_eq!(m.goto_count, 0);
}

#[test]
fn pipeline_flatten_pass() {
    let ast = StructuredAst {
        entry: BlockId::new(0),
        root: StructuredNode::Sequence(vec![StructuredNode::Sequence(vec![
            StructuredNode::Return(None),
        ])]),
        goto_count: 0,
        loop_count: 0,
    };
    let mut p = CfsPipeline::new();
    p.add_pass(Box::new(FlattenPass));
    assert_eq!(p.pass_count(), 1);
    let (out, _) = p.run(ast);
    assert!(matches!(out.root, StructuredNode::Return(None)));
}

#[test]
fn pipeline_default_for_has_passes() {
    let p = CfsPipeline::default_for(LoopDetector::new());
    assert_eq!(p.pass_count(), 3);
}

#[test]
fn pipeline_goto_eliminator_pass_counter_starts_zero() {
    let p = GotoEliminatorPass::new(LoopDetector::new());
    assert_eq!(p.gotos_eliminated(), 0);
    assert_eq!(p.break_continue_recovered(), 0);
}
