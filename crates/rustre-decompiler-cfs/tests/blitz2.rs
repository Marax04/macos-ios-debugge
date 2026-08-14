//! Deep adversarial blitz tests for rustre-decompiler-cfs.
//!
//! Targets the public surface of the lib.rs module: control flow structuring,
//! dominators, SCC, loop analysis, switch recovery, condition algebra,
//! validators and auxiliary helpers.

use std::collections::HashMap;

use rustre_decompiler_cfs::{
    BasicBlock, BlockId, BreakContinueRecovery, Cfg, CfsAlgorithm, CfsValidator, Condition,
    ControlFlowStructurer, CriticalEdgeSplitter, DetectedLoop, DomTree, Dominators,
    EmptyBlockEliminator, GotoEliminator, IrreducibleLoopHandler, LoopAnalysis, LoopDetector,
    LoopKind, LoopShape, NaturalLoop, PhoenixAlgorithm, PostDomTree, RecoveredCase,
    RecoveredSwitch, Region, RegionTree, SailrAlgorithm, Statement, StructuralAnalysis,
    StructuralRegionType, StructureError, StructuredAst, StructuredNode, SwitchAnalysis,
    SwitchCase, SwitchRecovery, TarjanScc, branch_condition, identifier_tokens, scc_groups,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn bb(id: u32, stmts: Vec<Statement>, succs: Vec<u32>) -> BasicBlock {
    BasicBlock {
        id: BlockId::new(id),
        stmts,
        successors: succs.into_iter().map(BlockId::new).collect(),
    }
}

fn raw(s: &str) -> Statement {
    Statement::Raw(s.to_string())
}
fn br(s: &str) -> Statement {
    Statement::Branch(s.to_string())
}
fn asg(l: &str, r: &str) -> Statement {
    Statement::Assign {
        lhs: l.to_string(),
        rhs: r.to_string(),
    }
}
const fn ret() -> Statement {
    Statement::Return(None)
}

struct Lcg {
    state: u64,
}
impl Lcg {
    const fn new() -> Self {
        Self {
            state: 0xDEAD_BEEF_CAFE_BABE,
        }
    }
    const fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockId / Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t01_blockid_display_and_ord() {
    let a = BlockId::new(0);
    let b = BlockId::new(1);
    assert_eq!(format!("{a}"), "bb0");
    assert_eq!(format!("{b}"), "bb1");
    assert!(a < b);
    assert_eq!(BlockId::new(42), BlockId::new(42));
}

#[test]
fn t02_blockid_hash_eq_30_pairs() {
    use std::collections::HashMap as HM;
    let mut map: HM<BlockId, u32> = HM::new();
    for i in 0..30u32 {
        map.insert(BlockId::new(i), i);
    }
    for i in 0..30u32 {
        assert_eq!(map.get(&BlockId::new(i)), Some(&i));
    }
    // Hash consistency: equal values have equal lookups
    for i in 0..30u32 {
        let a = BlockId::new(i);
        let b = BlockId::new(i);
        assert_eq!(a, b);
        assert_eq!(map.get(&a), map.get(&b));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlFlowStructurer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t03_empty_cfg_errors() {
    let r = ControlFlowStructurer::new(vec![]).structure(BlockId::new(0));
    assert!(matches!(r, Err(StructureError::EmptyCfg)));
}

#[test]
fn t04_entry_not_found_errors() {
    let blocks = vec![bb(0, vec![ret()], vec![])];
    let r = ControlFlowStructurer::new(blocks).structure(BlockId::new(42));
    assert!(matches!(r, Err(StructureError::EntryNotFound(_))));
}

#[test]
fn t05_single_block_ok() {
    let ast = ControlFlowStructurer::new(vec![bb(0, vec![ret()], vec![])])
        .structure(BlockId::new(0))
        .unwrap();
    assert_eq!(ast.entry, BlockId::new(0));
    assert_eq!(ast.goto_count, 0);
}

#[test]
fn t06_linear_chain_50_blocks_no_goto() {
    let mut blocks: Vec<BasicBlock> = (0u32..49)
        .map(|i| bb(i, vec![raw("x")], vec![i + 1]))
        .collect();
    blocks.push(bb(49, vec![ret()], vec![]));
    let ast = ControlFlowStructurer::new(blocks)
        .structure(BlockId::new(0))
        .unwrap();
    assert_eq!(ast.goto_count, 0);
}

#[test]
fn t07_simple_if_no_goto() {
    let blocks = vec![
        bb(0, vec![br("a")], vec![1, 2]),
        bb(1, vec![raw("x")], vec![2]),
        bb(2, vec![ret()], vec![]),
    ];
    let ast = ControlFlowStructurer::new(blocks)
        .structure(BlockId::new(0))
        .unwrap();
    assert_eq!(ast.goto_count, 0);
}

#[test]
fn t08_if_else_no_goto() {
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![raw("a")], vec![3]),
        bb(2, vec![raw("b")], vec![3]),
        bb(3, vec![ret()], vec![]),
    ];
    let ast = ControlFlowStructurer::new(blocks)
        .structure(BlockId::new(0))
        .unwrap();
    assert_eq!(ast.goto_count, 0);
}

#[test]
fn t09_while_loop_detected() {
    let blocks = vec![
        bb(0, vec![asg("i", "0")], vec![1]),
        bb(1, vec![br("i<10")], vec![2, 3]),
        bb(2, vec![asg("i", "i+1")], vec![1]),
        bb(3, vec![ret()], vec![]),
    ];
    let ast = ControlFlowStructurer::new(blocks)
        .structure(BlockId::new(0))
        .unwrap();
    assert!(ast.loop_count >= 1);
}

#[test]
fn t10_self_loop() {
    let ast = ControlFlowStructurer::new(vec![bb(0, vec![raw("x")], vec![0])])
        .structure(BlockId::new(0))
        .unwrap();
    assert!(ast.loop_count >= 1);
}

#[test]
fn t11_lcg_random_cfgs_never_panic() {
    let mut lcg = Lcg::new();
    for _trial in 0..50 {
        let n = (lcg.next() % 8) as u32 + 1;
        let mut blocks = Vec::new();
        for i in 0..n {
            let succ_count = (lcg.next() % 3) as usize;
            let mut succs = Vec::new();
            for _ in 0..succ_count {
                succs.push(u32::try_from(lcg.next() % u64::from(n)).unwrap_or(0));
            }
            blocks.push(bb(i, vec![raw("op")], succs));
        }
        // Should never panic. Returns Ok or Err.
        let _ = ControlFlowStructurer::new(blocks).structure(BlockId::new(0));
    }
}

#[test]
fn t12_serialization_roundtrip_ast() {
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![ret()], vec![]),
        bb(2, vec![ret()], vec![]),
    ];
    let ast = ControlFlowStructurer::new(blocks)
        .structure(BlockId::new(0))
        .unwrap();
    let json = serde_json::to_string(&ast.root).unwrap();
    let decoded: StructuredNode = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, ast.root);
}

#[test]
fn t13_node_count_invariants() {
    let leaf = StructuredNode::BasicBlock {
        id: BlockId::new(0),
        stmts: vec![],
    };
    assert_eq!(leaf.node_count(), 1);
    let seq = StructuredNode::Sequence(vec![leaf.clone(), leaf.clone(), leaf]);
    assert_eq!(seq.node_count(), 4);
}

#[test]
fn t14_goto_count_invariants() {
    let g = StructuredNode::Goto(BlockId::new(7));
    assert_eq!(g.goto_count(), 1);
    let s = StructuredNode::Sequence(vec![g.clone(), g.clone(), g]);
    assert_eq!(s.goto_count(), 3);
    assert_eq!(StructuredNode::Break.goto_count(), 0);
    assert_eq!(StructuredNode::Continue.goto_count(), 0);
    assert_eq!(StructuredNode::Return(None).goto_count(), 0);
}

#[test]
fn t15_flatten_singleton() {
    let leaf = StructuredNode::BasicBlock {
        id: BlockId::new(0),
        stmts: vec![],
    };
    let wrap = StructuredNode::Sequence(vec![StructuredNode::Sequence(vec![leaf.clone()])]);
    assert_eq!(wrap.flatten(), leaf);
}

// ─────────────────────────────────────────────────────────────────────────────
// CfsAlgorithm Display / FromStr-ish
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t16_cfs_algorithm_display_all_variants() {
    assert_eq!(CfsAlgorithm::Dream.to_string(), "DREAM");
    assert_eq!(CfsAlgorithm::Phoenix.to_string(), "Phoenix");
    assert_eq!(CfsAlgorithm::Sailr.to_string(), "SAILR");
    assert_eq!(CfsAlgorithm::Structural.to_string(), "Structural");
}

#[test]
fn t17_cfs_algorithm_serde_roundtrip() {
    for a in [
        CfsAlgorithm::Dream,
        CfsAlgorithm::Phoenix,
        CfsAlgorithm::Sailr,
        CfsAlgorithm::Structural,
    ] {
        let j = serde_json::to_string(&a).unwrap();
        let b: CfsAlgorithm = serde_json::from_str(&j).unwrap();
        assert_eq!(a, b);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Region
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t18_region_block_ids() {
    let r = Region::Sequence((0u32..10).map(BlockId::new).collect());
    assert_eq!(r.block_ids().len(), 10);
}

#[test]
fn t19_region_is_loop_variants() {
    assert!(Region::SelfLoop(BlockId::new(0)).is_loop());
    assert!(
        Region::While {
            header: BlockId::new(0),
            body: Box::new(Region::Block(BlockId::new(1)))
        }
        .is_loop()
    );
    assert!(
        Region::DoWhile {
            body: Box::new(Region::Block(BlockId::new(0))),
            latch: BlockId::new(1)
        }
        .is_loop()
    );
    assert!(
        Region::For {
            header: BlockId::new(0),
            body: Box::new(Region::Block(BlockId::new(1)))
        }
        .is_loop()
    );
    assert!(!Region::Block(BlockId::new(0)).is_loop());
    assert!(!Region::Sequence(vec![]).is_loop());
}

#[test]
fn t20_region_depth_zero_for_leaves() {
    assert_eq!(Region::Block(BlockId::new(0)).depth(), 0);
    assert_eq!(Region::Sequence(vec![]).depth(), 0);
    assert_eq!(Region::SelfLoop(BlockId::new(0)).depth(), 0);
}

#[test]
fn t21_region_depth_nested_growth() {
    let mut r = Region::Block(BlockId::new(0));
    for _ in 0..5 {
        r = Region::IfThen {
            cond: BlockId::new(0),
            then_region: Box::new(r),
        };
    }
    assert_eq!(r.depth(), 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionTree
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t22_region_tree_basic() {
    let mut rt = RegionTree::new();
    assert!(rt.root().is_none());
    let r = Region::Block(BlockId::new(7));
    let idx = rt.add_region(r.clone());
    assert_eq!(rt.region_count(), 1);
    assert_eq!(rt.region_for_block(BlockId::new(7)), Some(idx));
    rt.set_root(r.clone());
    assert_eq!(rt.root(), Some(&r));
}

// ─────────────────────────────────────────────────────────────────────────────
// DomTree / PostDomTree
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t23_dom_tree_path_and_dominates() {
    let mut d = DomTree::new();
    // 0 dominates 1 dominates 2
    d.set_idom(BlockId::new(1), BlockId::new(0));
    d.set_idom(BlockId::new(2), BlockId::new(1));
    let path = d.dominance_path(BlockId::new(2));
    assert!(path.contains(&BlockId::new(0)));
    assert!(d.dominates(BlockId::new(0), BlockId::new(2)));
    assert!(!d.dominates(BlockId::new(2), BlockId::new(0)));
    assert_eq!(d.idom(BlockId::new(1)), Some(BlockId::new(0)));
    assert_eq!(d.children(BlockId::new(0)).len(), 1);
}

#[test]
fn t24_post_dom_tree() {
    let mut p = PostDomTree::new();
    p.set_ipost_dom(BlockId::new(0), BlockId::new(2));
    p.set_ipost_dom(BlockId::new(1), BlockId::new(2));
    p.set_ipost_dom(BlockId::new(2), BlockId::new(2));
    assert!(p.post_dominates(BlockId::new(2), BlockId::new(0)));
    assert!(p.post_dominates(BlockId::new(2), BlockId::new(1)));
    assert!(!p.post_dominates(BlockId::new(0), BlockId::new(1)));
    assert_eq!(p.ipost_dom(BlockId::new(0)), Some(BlockId::new(2)));
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopDetector / NaturalLoop
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t25_loop_detector_state_machine() {
    let mut ld = LoopDetector::new();
    assert_eq!(ld.back_edge_count(), 0);
    assert!(!ld.is_loop_header(BlockId::new(0)));
    ld.add_back_edge(BlockId::new(3), BlockId::new(1));
    assert_eq!(ld.back_edge_count(), 1);
    assert!(ld.is_loop_header(BlockId::new(1)));
    assert!(ld.loop_for_header(BlockId::new(1)).is_some());
    assert!(ld.loop_for_header(BlockId::new(99)).is_none());
    assert_eq!(ld.loops().len(), 1);
}

#[test]
fn t26_natural_loop_contains_size() {
    let nl = NaturalLoop {
        header: BlockId::new(0),
        latch: BlockId::new(3),
        body: vec![BlockId::new(0), BlockId::new(1), BlockId::new(2), BlockId::new(3)],
    };
    assert_eq!(nl.size(), 4);
    assert!(nl.contains(BlockId::new(2)));
    assert!(!nl.contains(BlockId::new(99)));
}

// ─────────────────────────────────────────────────────────────────────────────
// GotoEliminator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t27_goto_eliminator_continues_for_header() {
    let mut ld = LoopDetector::new();
    ld.add_back_edge(BlockId::new(2), BlockId::new(0));
    let mut ge = GotoEliminator::new();
    let s = ge.try_eliminate(BlockId::new(0), &ld);
    assert!(s.unwrap().contains("continue"));
    assert_eq!(ge.break_continue_recovered(), 1);
    // Non-header: returns None.
    assert!(ge.try_eliminate(BlockId::new(99), &ld).is_none());
    assert_eq!(ge.gotos_eliminated(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// SwitchRecovery
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t28_switch_recovery_boundary() {
    let mut sr = SwitchRecovery::new();
    // 2 successors → None
    let b2 = BasicBlock {
        id: BlockId::new(0),
        stmts: vec![],
        successors: vec![BlockId::new(1), BlockId::new(2)],
    };
    assert!(sr.recover_from_block(&b2).is_none());
    // 3 successors → Some
    let b3 = BasicBlock {
        id: BlockId::new(0),
        stmts: vec![],
        successors: vec![BlockId::new(1), BlockId::new(2), BlockId::new(3)],
    };
    assert!(sr.recover_from_block(&b3).is_some());
    assert_eq!(sr.recovered_count(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// CriticalEdgeSplitter
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t29_critical_edge_splitter_saturates() {
    let mut s = CriticalEdgeSplitter::new(u32::MAX);
    // Saturating add should not panic.
    let mut blocks = vec![bb(0, vec![br("c")], vec![1, 2]), bb(1, vec![ret()], vec![]), bb(2, vec![ret()], vec![])];
    let mut pred: HashMap<BlockId, usize> = HashMap::new();
    pred.insert(BlockId::new(1), 2);
    pred.insert(BlockId::new(2), 2);
    let _ = s.split(&mut blocks, &pred);
    // Did not panic.
    assert!(s.splits() <= 2);
}

#[test]
fn t30_critical_edge_splitter_no_split_for_single_succ() {
    let mut s = CriticalEdgeSplitter::new(100);
    let mut blocks = vec![bb(0, vec![raw("a")], vec![1]), bb(1, vec![ret()], vec![])];
    let pred: HashMap<BlockId, usize> = HashMap::new();
    let added = s.split(&mut blocks, &pred);
    assert!(added.is_empty());
    assert_eq!(s.splits(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// EmptyBlockEliminator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t31_empty_block_eliminator_redirect() {
    let mut e = EmptyBlockEliminator::new();
    let blocks = vec![
        bb(0, vec![raw("a")], vec![1]),
        bb(1, vec![], vec![2]),
        bb(2, vec![ret()], vec![]),
    ];
    let out = e.eliminate(blocks);
    assert!(!out.iter().any(|b| b.id == BlockId::new(1)));
    assert_eq!(e.eliminated(), 1);
    // 0 now points to 2 directly.
    let b0 = out.iter().find(|b| b.id == BlockId::new(0)).unwrap();
    assert_eq!(b0.successors, vec![BlockId::new(2)]);
}

#[test]
fn t32_empty_block_eliminator_handles_cycle() {
    let mut e = EmptyBlockEliminator::new();
    // Two empties pointing at each other → must not infinite loop.
    let blocks = vec![
        bb(0, vec![], vec![1]),
        bb(1, vec![], vec![0]),
        bb(2, vec![ret()], vec![]),
    ];
    let _ = e.eliminate(blocks);
}

// ─────────────────────────────────────────────────────────────────────────────
// IrreducibleLoopHandler
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t33_irreducible_detection_states() {
    // Two distinct headers.
    let irr = vec![
        (BlockId::new(2), BlockId::new(0)),
        (BlockId::new(3), BlockId::new(1)),
    ];
    assert!(IrreducibleLoopHandler::is_irreducible(&irr));
    let red = vec![
        (BlockId::new(2), BlockId::new(0)),
        (BlockId::new(3), BlockId::new(0)),
    ];
    assert!(!IrreducibleLoopHandler::is_irreducible(&red));
    let empty: Vec<(BlockId, BlockId)> = vec![];
    assert!(!IrreducibleLoopHandler::is_irreducible(&empty));
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakContinueRecovery
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t34_break_continue_state() {
    let mut bcr = BreakContinueRecovery::new();
    assert_eq!(bcr.breaks(), 0);
    assert_eq!(bcr.continues(), 0);
    for _ in 0..7 {
        bcr.recover_break(BlockId::new(0), BlockId::new(1));
    }
    for _ in 0..5 {
        bcr.recover_continue(BlockId::new(0), BlockId::new(1));
    }
    assert_eq!(bcr.breaks(), 7);
    assert_eq!(bcr.continues(), 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// PhoenixAlgorithm / SailrAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t35_phoenix_handles_simple() {
    let mut p = PhoenixAlgorithm::new();
    let ast = p.structure(vec![bb(0, vec![ret()], vec![])], BlockId::new(0));
    assert_eq!(ast.entry, BlockId::new(0));
    assert_eq!(p.node_splits(), 0);
}

#[test]
fn t36_phoenix_missing_entry_falls_back() {
    let mut p = PhoenixAlgorithm::new();
    // Empty CFG triggers EmptyCfg error → fallback branch.
    let ast = p.structure(vec![], BlockId::new(0));
    assert_eq!(ast.entry, BlockId::new(0));
    assert_eq!(ast.goto_count, 1);
    assert!(p.gotos_emitted() >= 1);
}

#[test]
fn t37_sailr_detects_back_edges() {
    let mut s = SailrAlgorithm::new();
    // 0 → 1 → 0 (back-edge)
    let blocks = vec![bb(0, vec![raw("a")], vec![1]), bb(1, vec![br("c")], vec![0, 2]), bb(2, vec![ret()], vec![])];
    let _ast = s.structure(blocks, BlockId::new(0));
    // Should at least try detection.
    assert!(s.loops_recovered() >= 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// CfsValidator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t38_validator_detects_missing_block() {
    let v = CfsValidator::new();
    let blocks = vec![
        bb(0, vec![ret()], vec![]),
        bb(1, vec![ret()], vec![]),
    ];
    let ast = StructuredAst {
        root: StructuredNode::BasicBlock {
            id: BlockId::new(0),
            stmts: vec![],
        },
        entry: BlockId::new(0),
        goto_count: 0,
        loop_count: 0,
    };
    assert!(v.validate(&ast, &blocks).is_err());
}

#[test]
fn t39_validator_accepts_full_coverage() {
    let v = CfsValidator::new();
    let blocks = vec![bb(0, vec![ret()], vec![])];
    let ast = StructuredAst {
        root: StructuredNode::BasicBlock {
            id: BlockId::new(0),
            stmts: vec![],
        },
        entry: BlockId::new(0),
        goto_count: 0,
        loop_count: 0,
    };
    assert!(v.validate(&ast, &blocks).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuralAnalysis
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t40_structural_analysis_classifies() {
    let sa = StructuralAnalysis::new();
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![ret()], vec![]),
        bb(2, vec![ret()], vec![]),
        bb(3, vec![raw("a")], vec![1, 2, 3, 0]),
    ];
    let regions = sa.analyse(&blocks);
    assert_eq!(regions.len(), 4);
    assert_eq!(regions[0].region_type, StructuralRegionType::IfThen);
    assert_eq!(regions[1].region_type, StructuralRegionType::Block);
    assert_eq!(regions[3].region_type, StructuralRegionType::Improper);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cfg / TarjanScc / Dominators / LoopAnalysis
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t41_cfg_basic_properties() {
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![raw("a")], vec![3]),
        bb(2, vec![raw("b")], vec![3]),
        bb(3, vec![ret()], vec![]),
    ];
    let cfg = Cfg::from_blocks(&blocks);
    assert_eq!(cfg.len(), 4);
    assert!(!cfg.is_empty());
    assert!(cfg.contains(BlockId::new(2)));
    assert!(!cfg.contains(BlockId::new(99)));
    assert_eq!(cfg.successors(BlockId::new(0)).len(), 2);
    assert_eq!(cfg.predecessors(BlockId::new(3)).len(), 2);
    assert_eq!(cfg.block_ids().len(), 4);
    let rpo = cfg.reverse_postorder(BlockId::new(0));
    assert_eq!(rpo.len(), 4);
    assert_eq!(rpo[0], BlockId::new(0));
    let dfs = cfg.dfs_preorder(BlockId::new(0));
    assert_eq!(dfs.len(), 4);
    let r = cfg.reachable(BlockId::new(0));
    assert_eq!(r.len(), 4);
}

#[test]
fn t42_cfg_dedup_parallel_edges() {
    // Block 0 lists 1 twice.
    let blocks = vec![
        bb(0, vec![raw("a")], vec![1, 1, 1]),
        bb(1, vec![ret()], vec![]),
    ];
    let cfg = Cfg::from_blocks(&blocks);
    assert_eq!(cfg.successors(BlockId::new(0)).len(), 1);
    assert_eq!(cfg.predecessors(BlockId::new(1)).len(), 1);
}

#[test]
fn t43_cfg_drops_dangling_edges() {
    // Block 0 points to nonexistent 42.
    let blocks = vec![bb(0, vec![raw("a")], vec![42])];
    let cfg = Cfg::from_blocks(&blocks);
    assert_eq!(cfg.successors(BlockId::new(0)).len(), 0);
}

#[test]
fn t44_tarjan_scc_self_loop() {
    let blocks = vec![bb(0, vec![raw("a")], vec![0])];
    let cfg = Cfg::from_blocks(&blocks);
    let sccs = TarjanScc::run(&cfg);
    assert_eq!(sccs.len(), 1);
    assert_eq!(sccs[0], vec![BlockId::new(0)]);
}

#[test]
fn t45_tarjan_scc_two_node_cycle() {
    let blocks = vec![
        bb(0, vec![raw("a")], vec![1]),
        bb(1, vec![raw("b")], vec![0]),
    ];
    let cfg = Cfg::from_blocks(&blocks);
    let sccs = TarjanScc::run(&cfg);
    // One SCC of size 2.
    assert!(sccs.iter().any(|c| c.len() == 2));
}

#[test]
fn t46_dominators_entry_dominates_all() {
    let blocks = vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![raw("a")], vec![3]),
        bb(2, vec![raw("b")], vec![3]),
        bb(3, vec![ret()], vec![]),
    ];
    let cfg = Cfg::from_blocks(&blocks);
    let d = Dominators::compute(&cfg, BlockId::new(0));
    for n in 0..4u32 {
        assert!(d.dominates(BlockId::new(0), BlockId::new(n)));
    }
    assert_eq!(d.idom(BlockId::new(0)), Some(BlockId::new(0)));
}

#[test]
fn t47_loop_analysis_natural() {
    let blocks = vec![
        bb(0, vec![raw("a")], vec![1]),
        bb(1, vec![br("c")], vec![2, 3]),
        bb(2, vec![raw("b")], vec![1]),
        bb(3, vec![ret()], vec![]),
    ];
    let cfg = Cfg::from_blocks(&blocks);
    let la = LoopAnalysis::analyze(&cfg, BlockId::new(0));
    assert!(la.loop_count() >= 1);
    assert!(la.is_header(BlockId::new(1)));
    assert!(la.loop_for(BlockId::new(1)).is_some());
    assert_eq!(la.count_shape(LoopShape::Natural), 1);
}

#[test]
fn t48_loop_analysis_self_loop_shape() {
    let blocks = vec![bb(0, vec![raw("x")], vec![0])];
    let cfg = Cfg::from_blocks(&blocks);
    let la = LoopAnalysis::analyze(&cfg, BlockId::new(0));
    assert_eq!(la.count_shape(LoopShape::SelfLoop), 1);
    let l = la.loop_for(BlockId::new(0)).unwrap();
    assert_eq!(l.shape, LoopShape::SelfLoop);
}

#[test]
fn t49_detected_loop_methods() {
    let l = DetectedLoop {
        header: BlockId::new(0),
        latches: vec![BlockId::new(2)],
        body: vec![BlockId::new(0), BlockId::new(1), BlockId::new(2)],
        shape: LoopShape::Natural,
        kind: LoopKind::While,
        exits: vec![BlockId::new(3)],
    };
    assert_eq!(l.size(), 3);
    assert!(l.contains(BlockId::new(1)));
    assert!(!l.contains(BlockId::new(99)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition algebra
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t50_condition_negate_involution() {
    let a = Condition::atom("x");
    let na = a.clone().negate();
    let nna = na.negate();
    assert_eq!(nna, a);
    // True/False
    assert_eq!(Condition::True.negate(), Condition::False);
    assert_eq!(Condition::False.negate(), Condition::True);
}

#[test]
fn t51_condition_and_or_constant_absorption() {
    let x = Condition::atom("x");
    assert_eq!(Condition::True.and(x.clone()), x);
    assert_eq!(x.clone().and(Condition::True), x);
    assert_eq!(Condition::False.and(x.clone()), Condition::False);
    assert_eq!(Condition::False.or(x.clone()), x);
    assert_eq!(Condition::True.or(x), Condition::True);
}

#[test]
fn t52_condition_to_c_render() {
    let cond = Condition::atom("a").and(Condition::atom("b"));
    let s = cond.to_c();
    assert!(s.contains("a && b"));
    let nested = Condition::atom("a").or(Condition::atom("b").and(Condition::atom("c")));
    let s2 = nested.to_c();
    assert!(s2.contains("||"));
    assert!(s2.contains("&&"));
}

#[test]
fn t53_condition_atom_count() {
    let c = Condition::atom("a").and(Condition::atom("b")).or(Condition::atom("c"));
    assert_eq!(c.atom_count(), 3);
    assert_eq!(Condition::True.atom_count(), 0);
    assert_eq!(Condition::False.atom_count(), 0);
    assert_eq!(Condition::atom("x").negate().atom_count(), 1);
}

#[test]
fn t54_condition_de_morgan_via_negate() {
    let a = Condition::atom("a");
    let b = Condition::atom("b");
    let and_neg = Condition::And(Box::new(a), Box::new(b)).negate();
    // Should become Or(neg a, neg b).
    match and_neg {
        Condition::Or(_, _) => {}
        other => panic!("expected Or, got {other:?}"),
    }
}

#[test]
fn t55_condition_serde_roundtrip() {
    let c = Condition::atom("foo").and(Condition::atom("bar").negate());
    let j = serde_json::to_string(&c).unwrap();
    let d: Condition = serde_json::from_str(&j).unwrap();
    assert_eq!(c, d);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: branch_condition / identifier_tokens
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t56_branch_condition_extract() {
    let b = bb(0, vec![raw("a"), br("x > 0")], vec![]);
    assert_eq!(branch_condition(&b), Some("x > 0".to_string()));
    let none = bb(1, vec![raw("nop")], vec![]);
    assert_eq!(branch_condition(&none), None);
}

#[test]
fn t57_identifier_tokens_filters_numbers() {
    let toks = identifier_tokens("i < 10 && j > 0");
    assert!(toks.contains(&"i".to_string()));
    assert!(toks.contains(&"j".to_string()));
    assert!(!toks.iter().any(|t| t == "10"));
    assert!(!toks.iter().any(|t| t == "0"));
}

#[test]
fn t58_identifier_tokens_underscore_alnum() {
    let toks = identifier_tokens("_foo + bar_42 - x");
    assert!(toks.contains(&"_foo".to_string()));
    assert!(toks.contains(&"bar_42".to_string()));
    assert!(toks.contains(&"x".to_string()));
}

#[test]
fn t59_identifier_tokens_empty() {
    assert!(identifier_tokens("").is_empty());
    assert!(identifier_tokens("12345").is_empty());
    assert!(identifier_tokens("+-*/").is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// SwitchAnalysis
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t60_switch_analysis_jump_table() {
    let blocks = vec![
        bb(0, vec![br("x")], vec![1, 2, 3, 4]),
        bb(1, vec![ret()], vec![]),
        bb(2, vec![ret()], vec![]),
        bb(3, vec![ret()], vec![]),
        bb(4, vec![ret()], vec![]),
    ];
    let cfg = Cfg::from_blocks(&blocks);
    let sa = SwitchAnalysis::analyze(&cfg, BlockId::new(0));
    // At least one switch recovered.
    // (we don't have a public accessor; just confirm no panic). Use Debug.
    let dbg = format!("{sa:?}");
    assert!(dbg.contains("SwitchAnalysis"));
}

#[test]
fn t61_recovered_switch_methods() {
    let sw = RecoveredSwitch {
        head: BlockId::new(0),
        discriminant: "x".to_string(),
        cases: vec![
            RecoveredCase {
                value: Some(0),
                target: BlockId::new(1),
            },
            RecoveredCase {
                value: Some(1),
                target: BlockId::new(2),
            },
            RecoveredCase {
                value: None,
                target: BlockId::new(3),
            },
        ],
        jump_table: true,
    };
    assert_eq!(sw.case_count(), 2);
    assert!(sw.has_default());
}

#[test]
fn t62_recovered_switch_no_default() {
    let sw = RecoveredSwitch {
        head: BlockId::new(0),
        discriminant: "x".to_string(),
        cases: vec![RecoveredCase {
            value: Some(0),
            target: BlockId::new(1),
        }],
        jump_table: false,
    };
    assert_eq!(sw.case_count(), 1);
    assert!(!sw.has_default());
}

// ─────────────────────────────────────────────────────────────────────────────
// scc_groups re-export check
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t63_scc_groups_smoke() {
    // Build a graph and call scc_groups via the public API.  We do not have
    // direct access to CfgGraph::build (the constructor is private), but
    // ControlFlowStructurer paths exercise it. Instead, exercise scc_groups
    // indirectly: the function exists, and a no-op CFG should at least not
    // panic in the structurer path.
    let blocks = vec![bb(0, vec![ret()], vec![])];
    let _ = ControlFlowStructurer::new(blocks).structure(BlockId::new(0));
    // Ensure symbol is reachable.
    let _ = scc_groups as fn(_) -> _;
}

// ─────────────────────────────────────────────────────────────────────────────
// Statement equality / serialization
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t64_statement_eq_and_serde() {
    let s = Statement::Assign {
        lhs: "x".to_string(),
        rhs: "1".to_string(),
    };
    let j = serde_json::to_string(&s).unwrap();
    let d: Statement = serde_json::from_str(&j).unwrap();
    assert_eq!(s, d);
    assert_ne!(Statement::Return(None), Statement::Return(Some("0".into())));
}

#[test]
fn t65_switch_case_serde() {
    let c = SwitchCase {
        value: Some(42),
        body: Box::new(StructuredNode::Break),
    };
    let j = serde_json::to_string(&c).unwrap();
    let d: SwitchCase = serde_json::from_str(&j).unwrap();
    assert_eq!(c, d);
}

// ─────────────────────────────────────────────────────────────────────────────
// Boundary / overflow / Send+Sync
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t66_blockid_boundaries() {
    let zero = BlockId::new(0);
    let max = BlockId::new(u32::MAX);
    assert_eq!(format!("{zero}"), "bb0");
    assert_eq!(format!("{max}"), format!("bb{}", u32::MAX));
    assert!(zero < max);
}

#[test]
fn t67_send_sync_basic_types() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BlockId>();
    assert_send_sync::<BasicBlock>();
    assert_send_sync::<Statement>();
    assert_send_sync::<StructuredAst>();
    assert_send_sync::<Region>();
    assert_send_sync::<LoopKind>();
    assert_send_sync::<Condition>();
    assert_send_sync::<Cfg>();
}

#[test]
fn t68_threaded_loop_analysis_stress() {
    use std::sync::Arc;
    use std::thread;
    let blocks = vec![
        bb(0, vec![raw("a")], vec![1]),
        bb(1, vec![br("c")], vec![2, 3]),
        bb(2, vec![raw("b")], vec![1]),
        bb(3, vec![ret()], vec![]),
    ];
    let cfg = Arc::new(Cfg::from_blocks(&blocks));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&cfg);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let la = LoopAnalysis::analyze(&c, BlockId::new(0));
                assert!(la.loop_count() >= 1);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t69_threaded_structure_stress() {
    use std::sync::Arc;
    use std::thread;
    let blocks = Arc::new(vec![
        bb(0, vec![br("c")], vec![1, 2]),
        bb(1, vec![ret()], vec![]),
        bb(2, vec![ret()], vec![]),
    ]);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let bs = Arc::clone(&blocks);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let ast = ControlFlowStructurer::new((*bs).clone())
                    .structure(BlockId::new(0))
                    .unwrap();
                assert_eq!(ast.goto_count, 0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LCG fuzz on the various components
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t70_fuzz_cfg_construction() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let n = u32::try_from((lcg.next() % 10) + 1).unwrap_or(1);
        let mut bs = Vec::new();
        for i in 0..n {
            let sc = (lcg.next() % 4) as usize;
            let mut succs = Vec::new();
            for _ in 0..sc {
                succs.push(u32::try_from(lcg.next() & 0xFFFF_FFFF).unwrap_or(0) % n);
            }
            bs.push(bb(i, vec![raw("op")], succs));
        }
        let cfg = Cfg::from_blocks(&bs);
        assert_eq!(u32::try_from(cfg.len()).unwrap_or(u32::MAX), n);
        let _ = cfg.dfs_preorder(BlockId::new(0));
        let _ = cfg.reverse_postorder(BlockId::new(0));
        let _ = TarjanScc::run(&cfg);
        let _ = Dominators::compute(&cfg, BlockId::new(0));
    }
}

#[test]
fn t71_fuzz_switch_recovery() {
    let mut lcg = Lcg::new();
    let mut sr = SwitchRecovery::new();
    for _ in 0..50 {
        let sc = (lcg.next() % 6) as usize;
        let succs: Vec<BlockId> = (0..sc).map(|i| BlockId::new(u32::try_from(i).unwrap_or(u32::MAX))).collect();
        let b = BasicBlock {
            id: BlockId::new(0),
            stmts: vec![],
            successors: succs,
        };
        let _ = sr.recover_from_block(&b);
    }
}

#[test]
fn t72_fuzz_condition_algebra() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let a = Condition::atom(format!("x{}", lcg.next() % 100));
        let b = Condition::atom(format!("y{}", lcg.next() % 100));
        let combined = match lcg.next() % 4 {
            0 => a.clone().and(b.clone()),
            1 => a.clone().or(b.clone()),
            2 => a.clone().negate(),
            _ => b.clone().negate(),
        };
        // Idempotent: double-negation
        let _ = combined.clone().negate().negate();
        // to_c never panics
        let _ = combined.to_c();
        let _ = combined.atom_count();
    }
}
