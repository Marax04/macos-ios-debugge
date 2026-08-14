//! Exhaustive blitz tests for rustre-analysis-dataflow public API in lib.rs.

use std::collections::{HashMap, HashSet};

use rustre_analysis_dataflow::{
    AvailableExpressions, BitSetLattice, Cfg, CfgNode, ChainBuilder, DataFlowAnalysis,
    DataFlowError, DefPoint, DefUseChain, Definition, Direction, FunctionId,
    InterproceduralDataFlow, Lattice, LatticeValue, LiveVariableAnalysis, MustSet, PhiNode,
    ReachingDefinitions, SsaVar, Statement, UseDefChain, UsePoint, VeryBusyExpressions,
    WorklistAlgorithm, compute_dominance_frontiers, compute_dominators, compute_liveness,
    compute_reaching_defs, insert_phi_nodes, linear_cfg, postorder, propagate_constants,
};

// ───────────────────────── BitSetLattice ─────────────────────────

#[test]
fn bitset_default_is_bottom() {
    let d: BitSetLattice<u32> = BitSetLattice::default();
    assert_eq!(d, BitSetLattice::<u32>::bottom());
    assert!(!d.is_top);
    assert!(d.set.is_empty());
}

#[test]
fn bitset_top_contains_anything() {
    let t: BitSetLattice<u32> = BitSetLattice::top();
    assert!(t.contains(&12345));
    assert!(t.contains(&0));
}

#[test]
fn bitset_top_meet_other_returns_other() {
    let t: BitSetLattice<u32> = BitSetLattice::top();
    let a: BitSetLattice<u32> = BitSetLattice::new([1u32, 2].into_iter().collect());
    let m = t.meet(&a);
    assert_eq!(m, a);
}

#[test]
fn bitset_leq_reflexive() {
    let a: BitSetLattice<u32> = BitSetLattice::new([1, 2, 3].into_iter().collect());
    assert!(a.leq(&a));
}

#[test]
fn bitset_top_join_top_is_top() {
    let t1: BitSetLattice<u32> = BitSetLattice::top();
    let t2: BitSetLattice<u32> = BitSetLattice::top();
    assert!(t1.join(&t2).is_top);
}

#[test]
fn bitset_empty_join_is_bottom() {
    let b1: BitSetLattice<u32> = BitSetLattice::bottom();
    let b2: BitSetLattice<u32> = BitSetLattice::bottom();
    assert_eq!(b1.join(&b2), BitSetLattice::bottom());
}

// ───────────────────────── MustSet ─────────────────────────

#[test]
fn mustset_top_join_x_yields_x() {
    let t = MustSet::top_with(["a".to_string()].into_iter().collect());
    let x = MustSet::new(["b".to_string()].into_iter().collect());
    let j = t.join(&x);
    assert_eq!(j, x);
}

#[test]
fn mustset_meet_top_is_top() {
    let t = MustSet::top_with(HashSet::new());
    let x = MustSet::new(["a".into()].into_iter().collect());
    let m = t.meet(&x);
    assert!(m.is_top);
}

#[test]
fn mustset_bottom_is_empty() {
    let b = MustSet::bottom();
    assert!(b.set.is_empty());
    assert!(!b.is_top);
}

#[test]
fn mustset_join_two_concrete_sets_is_intersection() {
    let a = MustSet::new(["x".into(), "y".into()].into_iter().collect());
    let b = MustSet::new(["y".into(), "z".into()].into_iter().collect());
    let j = a.join(&b);
    assert!(j.set.contains("y"));
    assert_eq!(j.set.len(), 1);
}

// ───────────────────────── Cfg ─────────────────────────

#[test]
fn cfg_predecessors_diamond() {
    let nodes: Vec<CfgNode<Statement>> = (0..4)
        .map(|i| CfgNode { id: i, stmts: vec![] })
        .collect();
    let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
    let cfg = Cfg::new(nodes, succs, 0, 3);
    assert_eq!(cfg.predecessors[3].len(), 2);
    assert!(cfg.predecessors[3].contains(&1));
    assert!(cfg.predecessors[3].contains(&2));
}

#[test]
fn cfg_node_count() {
    let cfg: Cfg<Statement> = Cfg::new(
        (0..5).map(|i| CfgNode { id: i, stmts: vec![] }).collect(),
        vec![vec![]; 5],
        0,
        4,
    );
    assert_eq!(cfg.node_count(), 5);
}

#[test]
fn cfg_out_of_range_successor_ignored() {
    // successor referencing nonexistent node must not panic, must not be in preds.
    let nodes = vec![CfgNode::<Statement> { id: 0, stmts: vec![] }];
    let succs = vec![vec![999]];
    let cfg = Cfg::new(nodes, succs, 0, 0);
    assert_eq!(cfg.predecessors.len(), 1);
    assert!(cfg.predecessors[0].is_empty());
}

// ───────────────────────── Direction ─────────────────────────

#[test]
fn direction_eq() {
    assert_eq!(Direction::Forward, Direction::Forward);
    assert_ne!(Direction::Forward, Direction::Backward);
}

// ───────────────────────── Statement ─────────────────────────

#[test]
fn statement_new_and_with_expr() {
    let s = Statement::new(7, Some("x"), vec!["a", "b"]).with_expr("a+b");
    assert_eq!(s.id, 7);
    assert_eq!(s.def, Some("x".to_string()));
    assert_eq!(s.uses, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(s.expr, Some("a+b".to_string()));
}

#[test]
fn statement_no_def() {
    let s = Statement::new(0, None, vec!["x"]);
    assert!(s.def.is_none());
    assert!(s.expr.is_none());
}

// ───────────────────────── WorklistAlgorithm errors ─────────────────────────

#[test]
fn worklist_empty_cfg_returns_empty_cfg_err() {
    let cfg: Cfg<Statement> = Cfg::new(vec![], vec![], 0, 0);
    let err = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap_err();
    assert!(matches!(err, DataFlowError::EmptyCfg));
}

#[test]
fn dataflow_error_display() {
    let e = DataFlowError::NodeNotFound(42);
    assert!(format!("{e}").contains("42"));
    let e2 = DataFlowError::NoConvergence(10);
    assert!(format!("{e2}").contains("10"));
    let e3 = DataFlowError::EmptyCfg;
    assert!(format!("{e3}").to_lowercase().contains("empty"));
}

// ───────────────────────── LVA ─────────────────────────

#[test]
fn lva_kill_then_use() {
    // bb0: def x, use a; bb1: use x. x is live between, a never live after bb0.
    let s0 = Statement::new(0, Some("x"), vec!["a"]);
    let s1 = Statement::new(1, None, vec!["x"]);
    let cfg = linear_cfg(vec![s0, s1]);
    let r = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
    assert!(r.in_facts[0].contains(&"a".to_string()));
    assert!(r.in_facts[1].contains(&"x".to_string()));
    assert!(!r.in_facts[0].contains(&"x".to_string()));
}

#[test]
fn lva_no_uses_no_liveness() {
    let s = Statement::new(0, Some("x"), vec![]);
    let cfg = linear_cfg(vec![s]);
    let r = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
    assert!(r.in_facts[0].set.is_empty());
}

#[test]
fn lva_direction_is_backward() {
    let a = LiveVariableAnalysis;
    assert_eq!(a.direction(), Direction::Backward);
}

// ───────────────────────── RD ─────────────────────────

#[test]
fn rd_direction_forward() {
    let a = ReachingDefinitions;
    assert_eq!(a.direction(), Direction::Forward);
}

#[test]
fn rd_single_def_reaches_exit() {
    let s = Statement::new(0, Some("x"), vec![]);
    let cfg = linear_cfg(vec![s]);
    let r = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    assert_eq!(r.out_facts[0].set.len(), 1);
    let def = r.out_facts[0].set.iter().next().unwrap();
    assert_eq!(def.variable, "x");
    assert_eq!(def.stmt_id, 0);
}

#[test]
fn rd_diamond_both_defs_reach_merge() {
    let s_entry = Statement::new(0, None, vec![]);
    let s_left = Statement::new(1, Some("x"), vec![]);
    let s_right = Statement::new(2, Some("x"), vec![]);
    let s_merge = Statement::new(3, None, vec!["x"]);
    let nodes = vec![
        CfgNode { id: 0, stmts: vec![s_entry] },
        CfgNode { id: 1, stmts: vec![s_left] },
        CfgNode { id: 2, stmts: vec![s_right] },
        CfgNode { id: 3, stmts: vec![s_merge] },
    ];
    let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
    let cfg = Cfg::new(nodes, succs, 0, 3);
    let r = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    let in3 = &r.in_facts[3].set;
    assert!(in3.iter().any(|d| d.stmt_id == 1));
    assert!(in3.iter().any(|d| d.stmt_id == 2));
}

// ───────────────────────── AvailableExpressions ─────────────────────────

#[test]
fn ae_universe_constructor() {
    let u: HashSet<String> = ["a+b".into()].into_iter().collect();
    let ae = AvailableExpressions::new(u.clone());
    assert_eq!(ae.universe, u);
    assert_eq!(ae.direction(), Direction::Forward);
}

#[test]
fn ae_kill_on_redef() {
    let universe: HashSet<String> = ["a+b".into()].into_iter().collect();
    let analysis = AvailableExpressions::new(universe);
    let s0 = Statement::new(0, Some("t"), vec!["a", "b"]).with_expr("a+b");
    let s1 = Statement::new(1, Some("a"), vec![]); // kills any expr containing "a"
    let cfg = linear_cfg(vec![s0, s1]);
    let r = WorklistAlgorithm::run(&analysis, &cfg).unwrap();
    assert!(r.out_facts[0].set.contains("a+b"));
    assert!(!r.out_facts[1].set.contains("a+b"));
}

// ───────────────────────── VeryBusyExpressions ─────────────────────────

#[test]
fn vbe_diamond_busy_at_entry() {
    let universe: HashSet<String> = ["a+b".into()].into_iter().collect();
    let analysis = VeryBusyExpressions::new(universe);
    let s_l = Statement::new(0, None, vec!["a", "b"]).with_expr("a+b");
    let s_r = Statement::new(1, None, vec!["a", "b"]).with_expr("a+b");
    let nodes = vec![
        CfgNode { id: 0, stmts: vec![] },
        CfgNode { id: 1, stmts: vec![s_l] },
        CfgNode { id: 2, stmts: vec![s_r] },
        CfgNode { id: 3, stmts: vec![] },
    ];
    let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
    let cfg = Cfg::new(nodes, succs, 0, 3);
    let r = WorklistAlgorithm::run(&analysis, &cfg).unwrap();
    assert!(r.in_facts[0].set.contains("a+b"));
}

#[test]
fn vbe_direction_backward() {
    let analysis = VeryBusyExpressions::new(HashSet::new());
    assert_eq!(analysis.direction(), Direction::Backward);
}

// ───────────────────────── DefUseChain / UseDefChain ─────────────────────────

#[test]
fn du_chain_empty_uses_returns_empty_set() {
    let du = DefUseChain::new();
    let dp = DefPoint { variable: "x".into(), stmt_id: 0, node_id: 0 };
    assert!(du.uses_of(&dp).is_empty());
}

#[test]
fn ud_chain_empty_defs_returns_empty_set() {
    let ud = UseDefChain::new();
    let up = UsePoint { variable: "y".into(), stmt_id: 0, node_id: 0 };
    assert!(ud.defs_of(&up).is_empty());
}

#[test]
fn du_chain_add_and_query() {
    let mut du = DefUseChain::new();
    let d = DefPoint { variable: "x".into(), stmt_id: 0, node_id: 0 };
    let u = UsePoint { variable: "x".into(), stmt_id: 1, node_id: 1 };
    du.add_edge(d.clone(), u.clone());
    assert!(du.uses_of(&d).contains(&u));
}

#[test]
fn ud_chain_add_and_query() {
    let mut ud = UseDefChain::new();
    let d = DefPoint { variable: "x".into(), stmt_id: 0, node_id: 0 };
    let u = UsePoint { variable: "x".into(), stmt_id: 1, node_id: 1 };
    ud.add_edge(u.clone(), d.clone());
    assert!(ud.defs_of(&u).contains(&d));
}

#[test]
fn chain_builder_produces_def_use_edges() {
    let s0 = Statement::new(0, Some("x"), vec![]);
    let s1 = Statement::new(1, None, vec!["x"]);
    let cfg = linear_cfg(vec![s0, s1]);
    let rd = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    let (du, ud) = ChainBuilder::build(&cfg, &rd);
    let d = DefPoint { variable: "x".into(), stmt_id: 0, node_id: 0 };
    let u = UsePoint { variable: "x".into(), stmt_id: 1, node_id: 1 };
    assert!(du.uses_of(&d).contains(&u));
    assert!(ud.defs_of(&u).contains(&d));
}

// ───────────────────────── Interprocedural ─────────────────────────

#[test]
fn idf_default_empty() {
    let idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::default();
    assert!(idf.cfgs.is_empty());
    assert!(idf.summaries.is_empty());
}

#[test]
fn idf_set_get_summary() {
    let mut idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::new();
    let fid = FunctionId(7);
    let fact: BitSetLattice<Definition> = BitSetLattice::new(
        [Definition { variable: "x".into(), stmt_id: 0 }].into_iter().collect(),
    );
    idf.set_summary(&fid, fact.clone());
    assert_eq!(idf.get_summary(&fid), Some(&fact));
}

#[test]
fn idf_missing_summary_is_none() {
    let idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::new();
    assert!(idf.get_summary(&FunctionId(0)).is_none());
}

// ───────────────────────── linear_cfg ─────────────────────────

#[test]
fn linear_cfg_empty_input() {
    let cfg = linear_cfg(vec![]);
    assert_eq!(cfg.node_count(), 0);
}

#[test]
fn linear_cfg_single_node_self_is_entry_and_exit() {
    let s = Statement::new(0, Some("a"), vec![]);
    let cfg = linear_cfg(vec![s]);
    assert_eq!(cfg.entry, 0);
    assert_eq!(cfg.exit, 0);
    assert_eq!(cfg.successors[0], Vec::<usize>::new());
}

#[test]
fn linear_cfg_three_nodes_chained() {
    let cfg = linear_cfg(vec![
        Statement::new(0, None, vec![]),
        Statement::new(1, None, vec![]),
        Statement::new(2, None, vec![]),
    ]);
    assert_eq!(cfg.successors[0], vec![1]);
    assert_eq!(cfg.successors[1], vec![2]);
    assert!(cfg.successors[2].is_empty());
    assert_eq!(cfg.exit, 2);
}

// ───────────────────────── compute_liveness ─────────────────────────

#[test]
fn liveness_returns_sorted_unique() {
    let cfg = vec![(0u32, vec![], vec![3u32, 1, 2, 1], vec![])];
    let res = compute_liveness(&cfg);
    let li = &res[&0].0;
    assert_eq!(li, &vec![1u32, 2, 3]);
}

#[test]
fn liveness_kill_overrides_gen_NOT_but_gen_takes_precedence() {
    // gen={5}, kill={5} — gen∪(out\kill), gen wins because added after filter.
    let cfg = vec![(0u32, vec![], vec![5u32], vec![5u32])];
    let res = compute_liveness(&cfg);
    assert!(res[&0].0.contains(&5));
}

#[test]
fn liveness_unreachable_successor_ignored() {
    // bb0's successor 999 doesn't exist; should not panic.
    let cfg = vec![(0u32, vec![999u32], vec![1u32], vec![])];
    let res = compute_liveness(&cfg);
    assert!(res[&0].0.contains(&1));
}

// ───────────────────────── compute_reaching_defs ─────────────────────────

#[test]
fn rd_empty_input() {
    let res = compute_reaching_defs(&[]);
    assert!(res.is_empty());
}

#[test]
fn rd_diamond_merge_both_defs() {
    let cfg = vec![
        (0u32, vec![1u32, 2u32], vec![], vec![]),
        (1u32, vec![3u32], vec![10u32], vec![]),
        (2u32, vec![3u32], vec![20u32], vec![]),
        (3u32, vec![], vec![], vec![]),
    ];
    let res = compute_reaching_defs(&cfg);
    assert!(res[&3].0.contains(&10));
    assert!(res[&3].0.contains(&20));
}

#[test]
fn rd_kill_along_linear_chain() {
    let cfg = vec![
        (0u32, vec![1u32], vec![100u32], vec![]),
        (1u32, vec![2u32], vec![101u32], vec![100u32]),
        (2u32, vec![], vec![], vec![]),
    ];
    let res = compute_reaching_defs(&cfg);
    assert!(!res[&2].0.contains(&100));
    assert!(res[&2].0.contains(&101));
}

// ───────────────────────── LatticeValue / propagate_constants ─────────────────────────

#[test]
fn lattice_value_is_const_and_as_const() {
    assert!(LatticeValue::Const(3).is_const());
    assert!(!LatticeValue::Top.is_const());
    assert!(!LatticeValue::Bottom.is_const());
    assert_eq!(LatticeValue::Const(9).as_const(), Some(9));
    assert_eq!(LatticeValue::Top.as_const(), None);
    assert_eq!(LatticeValue::Bottom.as_const(), None);
}

#[test]
fn lattice_meet_top_x_is_x() {
    assert_eq!(
        LatticeValue::meet(&LatticeValue::Top, &LatticeValue::Top),
        LatticeValue::Top
    );
    assert_eq!(
        LatticeValue::meet(&LatticeValue::Const(5), &LatticeValue::Top),
        LatticeValue::Const(5)
    );
}

#[test]
fn lattice_meet_bottom_absorbing() {
    assert_eq!(
        LatticeValue::meet(&LatticeValue::Bottom, &LatticeValue::Const(1)),
        LatticeValue::Bottom
    );
}

#[test]
fn propagate_constants_conflict_yields_bottom() {
    let res = propagate_constants(&[(1u32, 1i64), (1, 2)], &[]);
    assert_eq!(res[&1], LatticeValue::Bottom);
}

#[test]
fn propagate_constants_consistent_yields_const() {
    let res = propagate_constants(&[(1u32, 42), (1, 42)], &[]);
    assert_eq!(res[&1], LatticeValue::Const(42));
}

#[test]
fn propagate_constants_use_only_is_bottom() {
    let res = propagate_constants(&[], &[(0u32, 7u32)]);
    assert_eq!(res[&7], LatticeValue::Bottom);
}

#[test]
fn propagate_constants_empty_input() {
    let res = propagate_constants(&[], &[]);
    assert!(res.is_empty());
}

// ───────────────────────── compute_dominators ─────────────────────────

#[test]
fn dominators_zero_nodes_returns_empty() {
    let idom = compute_dominators(0, &[], 0);
    assert!(idom.is_empty());
}

#[test]
fn dominators_linear_chain() {
    let succs = vec![vec![1], vec![2], vec![3], vec![]];
    let idom = compute_dominators(4, &succs, 0);
    assert_eq!(idom, vec![0, 0, 1, 2]);
}

#[test]
fn dominators_diamond() {
    let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
    let idom = compute_dominators(4, &succs, 0);
    assert_eq!(idom[0], 0);
    assert_eq!(idom[3], 0);
}

#[test]
fn dominators_unreachable_self_loop() {
    // node 1 unreachable from entry 0.
    let succs = vec![vec![], vec![]];
    let idom = compute_dominators(2, &succs, 0);
    assert_eq!(idom[0], 0);
    assert_eq!(idom[1], 1); // sentinel
}

// ───────────────────────── postorder ─────────────────────────

#[test]
fn postorder_linear() {
    let po = postorder(3, &[vec![1usize], vec![2], vec![]], 0);
    assert_eq!(po, vec![2, 1, 0]);
}

#[test]
fn postorder_entry_oob_returns_empty() {
    let po = postorder(0, &[], 0);
    assert!(po.is_empty());
}

#[test]
fn postorder_with_back_edge_terminates() {
    // 0→1→0 — DFS must terminate, both nodes visited once.
    let po = postorder(2, &[vec![1usize], vec![0]], 0);
    assert_eq!(po.len(), 2);
}

// ───────────────────────── dominance frontiers ─────────────────────────

#[test]
fn dom_frontier_diamond() {
    let succs = vec![vec![1usize, 2], vec![3], vec![3], vec![]];
    let idom = compute_dominators(4, &succs, 0);
    let df = compute_dominance_frontiers(4, &succs, &idom);
    assert_eq!(df[1], vec![3]);
    assert_eq!(df[2], vec![3]);
    assert!(df[0].is_empty());
    assert!(df[3].is_empty());
}

#[test]
fn dom_frontier_linear_all_empty() {
    let succs = vec![vec![1usize], vec![2], vec![3], vec![]];
    let idom = compute_dominators(4, &succs, 0);
    let df = compute_dominance_frontiers(4, &succs, &idom);
    for d in &df {
        assert!(d.is_empty());
    }
}

// ───────────────────────── insert_phi_nodes ─────────────────────────

#[test]
fn phi_diamond_inserts_at_join() {
    let cfg = vec![
        (0u32, vec![1u32, 2u32]),
        (1, vec![3]),
        (2, vec![3]),
        (3, vec![]),
    ];
    let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
    defs.insert(99, vec![1, 2]);
    let phi = insert_phi_nodes(&cfg, &defs);
    assert!(phi.get(&3).is_some_and(|v| v.contains(&99)));
}

#[test]
fn phi_empty_input() {
    let phi = insert_phi_nodes(&[], &HashMap::new());
    assert!(phi.is_empty());
}

#[test]
fn phi_linear_no_phis() {
    let cfg = vec![(0u32, vec![1u32]), (1, vec![2]), (2, vec![])];
    let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
    defs.insert(1, vec![0]);
    let phi = insert_phi_nodes(&cfg, &defs);
    assert!(phi.is_empty());
}

// ───────────────────────── SsaVar / PhiNode equality ─────────────────────────

#[test]
fn ssavar_eq_and_hash() {
    let a = SsaVar { original_id: 1, version: 0 };
    let b = SsaVar { original_id: 1, version: 0 };
    let c = SsaVar { original_id: 1, version: 1 };
    assert_eq!(a, b);
    assert_ne!(a, c);
    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

#[test]
fn phinode_eq() {
    let p1 = PhiNode { var_id: 1, sources: vec![(0, 1), (2, 3)] };
    let p2 = PhiNode { var_id: 1, sources: vec![(0, 1), (2, 3)] };
    assert_eq!(p1, p2);
}

// ───────────────────────── FunctionId ─────────────────────────

#[test]
fn function_id_copy_and_eq() {
    let a = FunctionId(7);
    let b = a; // Copy
    assert_eq!(a, b);
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}
