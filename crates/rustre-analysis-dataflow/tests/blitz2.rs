//! Adversarial / deep tests for rustre-analysis-dataflow.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rustre_analysis_dataflow::{
    AvailableExpressions, BitSetLattice, Cfg, CfgNode, ChainBuilder, DataFlowAnalysis,
    DataFlowError, DefPoint, DefUseChain, Definition, Direction, FunctionId,
    InterproceduralDataFlow, Lattice, LatticeValue, LiveVariableAnalysis, MustSet, PhiNode,
    ReachingDefinitions, SsaVar, Statement, UseDefChain, UsePoint, VeryBusyExpressions,
    WorklistAlgorithm, compute_dominance_frontiers, compute_dominators, compute_liveness,
    compute_reaching_defs, insert_phi_nodes, linear_cfg, postorder, propagate_constants,
};

// ─────────────────────────────────────────────────────────────────────────────
// Seeded LCG
// ─────────────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn range(&mut self, n: u32) -> u32 {
        (self.next() >> 32) as u32 % n.max(1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lattice properties — BitSetLattice
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_bitset_join_commutative_50() {
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        let b: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert_eq!(a.join(&b), b.join(&a));
    }
}

#[test]
fn test_bitset_join_associative_50() {
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(6)).map(|_| rng.range(12)).collect());
        let b: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(6)).map(|_| rng.range(12)).collect());
        let c: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(6)).map(|_| rng.range(12)).collect());
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }
}

#[test]
fn test_bitset_join_idempotent_50() {
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert_eq!(a.join(&a), a);
    }
}

#[test]
fn test_bitset_meet_commutative_50() {
    let mut rng = Lcg::new();
    for _ in 0..50 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        let b: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert_eq!(a.meet(&b), b.meet(&a));
    }
}

#[test]
fn test_bitset_bottom_join_identity() {
    let bot: BitSetLattice<u32> = BitSetLattice::bottom();
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert_eq!(bot.join(&a), a);
        assert_eq!(a.join(&bot), a);
    }
}

#[test]
fn test_bitset_top_join_absorbing() {
    let top: BitSetLattice<u32> = BitSetLattice::top();
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert!(top.join(&a).is_top);
        assert!(a.join(&top).is_top);
    }
}

#[test]
fn test_bitset_top_meet_identity() {
    let top: BitSetLattice<u32> = BitSetLattice::top();
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert_eq!(top.meet(&a), a);
        assert_eq!(a.meet(&top), a);
    }
}

#[test]
fn test_bitset_leq_reflexive_30() {
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a: BitSetLattice<u32> = BitSetLattice::new((0..rng.range(8)).map(|_| rng.range(20)).collect());
        assert!(a.leq(&a));
    }
}

#[test]
fn test_bitset_leq_consistent_with_subset() {
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a: HashSet<u32> = (0..rng.range(6)).map(|_| rng.range(10)).collect();
        let mut b = a.clone();
        b.insert(rng.range(10));
        b.insert(rng.range(10));
        let la = BitSetLattice::new(a);
        let lb = BitSetLattice::new(b);
        assert!(la.leq(&lb));
    }
}

#[test]
fn test_bitset_contains() {
    let a: BitSetLattice<u32> = BitSetLattice::new([1, 2, 3].into());
    assert!(a.contains(&1));
    assert!(!a.contains(&99));
    let top: BitSetLattice<u32> = BitSetLattice::top();
    assert!(top.contains(&12345));
}

#[test]
fn test_bitset_default_is_bottom() {
    let d: BitSetLattice<u32> = BitSetLattice::default();
    let b: BitSetLattice<u32> = BitSetLattice::bottom();
    assert_eq!(d, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// MustSet properties
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_mustset_join_is_intersection() {
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let sa: HashSet<String> = (0..rng.range(6)).map(|_| format!("v{}", rng.range(8))).collect();
        let sb: HashSet<String> = (0..rng.range(6)).map(|_| format!("v{}", rng.range(8))).collect();
        let a = MustSet::new(sa.clone());
        let b = MustSet::new(sb.clone());
        let j = a.join(&b);
        let expected: HashSet<String> = sa.intersection(&sb).cloned().collect();
        assert_eq!(j.set, expected);
    }
}

#[test]
fn test_mustset_meet_is_union() {
    let a = MustSet::new(["x".into(), "y".into()].into());
    let b = MustSet::new(["y".into(), "z".into()].into());
    let m = a.meet(&b);
    assert!(m.set.contains("x") && m.set.contains("y") && m.set.contains("z"));
}

#[test]
fn test_mustset_top_join_identity() {
    let top = MustSet::top();
    let a = MustSet::new(["x".into()].into());
    assert_eq!(top.join(&a), a);
    assert_eq!(a.join(&top), a);
}

#[test]
fn test_mustset_top_meet_absorbing() {
    let top = MustSet::top();
    let a = MustSet::new(["x".into()].into());
    assert!(top.meet(&a).is_top);
    assert!(a.meet(&top).is_top);
}

#[test]
fn test_mustset_bottom_meet_identity_via_union() {
    // meet on MustSet is union; bottom = empty set so meet returns the other.
    let bot = MustSet::bottom();
    let a = MustSet::new(["x".into()].into());
    assert_eq!(bot.meet(&a).set, a.set);
}

// ─────────────────────────────────────────────────────────────────────────────
// LatticeValue (constant propagation)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lattice_value_meet_commutative_30() {
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a = match rng.range(3) {
            0 => LatticeValue::Top,
            1 => LatticeValue::Const(rng.range(5) as i64),
            _ => LatticeValue::Bottom,
        };
        let b = match rng.range(3) {
            0 => LatticeValue::Top,
            1 => LatticeValue::Const(rng.range(5) as i64),
            _ => LatticeValue::Bottom,
        };
        assert_eq!(LatticeValue::meet(&a, &b), LatticeValue::meet(&b, &a));
    }
}

#[test]
fn test_lattice_value_meet_associative_30() {
    let vals = [
        LatticeValue::Top,
        LatticeValue::Const(1),
        LatticeValue::Const(2),
        LatticeValue::Bottom,
    ];
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let a = &vals[rng.range(4) as usize];
        let b = &vals[rng.range(4) as usize];
        let c = &vals[rng.range(4) as usize];
        let ab_c = LatticeValue::meet(&LatticeValue::meet(a, b), c);
        let a_bc = LatticeValue::meet(a, &LatticeValue::meet(b, c));
        assert_eq!(ab_c, a_bc);
    }
}

#[test]
fn test_lattice_value_meet_top_identity() {
    for v in [
        LatticeValue::Top,
        LatticeValue::Const(0),
        LatticeValue::Const(-1),
        LatticeValue::Bottom,
    ] {
        assert_eq!(LatticeValue::meet(&LatticeValue::Top, &v), v.clone());
        assert_eq!(LatticeValue::meet(&v, &LatticeValue::Top), v);
    }
}

#[test]
fn test_lattice_value_meet_bottom_absorbing() {
    for v in [
        LatticeValue::Top,
        LatticeValue::Const(7),
        LatticeValue::Bottom,
    ] {
        assert_eq!(LatticeValue::meet(&LatticeValue::Bottom, &v), LatticeValue::Bottom);
        assert_eq!(LatticeValue::meet(&v, &LatticeValue::Bottom), LatticeValue::Bottom);
    }
}

#[test]
fn test_lattice_value_meet_const_boundary() {
    assert_eq!(
        LatticeValue::meet(&LatticeValue::Const(i64::MAX), &LatticeValue::Const(i64::MAX)),
        LatticeValue::Const(i64::MAX)
    );
    assert_eq!(
        LatticeValue::meet(&LatticeValue::Const(i64::MIN), &LatticeValue::Const(i64::MAX)),
        LatticeValue::Bottom
    );
    assert_eq!(
        LatticeValue::meet(&LatticeValue::Const(0), &LatticeValue::Const(0)),
        LatticeValue::Const(0)
    );
}

#[test]
fn test_lattice_value_is_const_and_as_const() {
    assert!(LatticeValue::Const(42).is_const());
    assert!(!LatticeValue::Top.is_const());
    assert!(!LatticeValue::Bottom.is_const());
    assert_eq!(LatticeValue::Const(42).as_const(), Some(42));
    assert_eq!(LatticeValue::Top.as_const(), None);
    assert_eq!(LatticeValue::Bottom.as_const(), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG construction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cfg_new_predecessors_derived() {
    let nodes = vec![
        CfgNode { id: 0, stmts: vec![] },
        CfgNode { id: 1, stmts: vec![] },
        CfgNode { id: 2, stmts: vec![] },
    ];
    let succs = vec![vec![1, 2], vec![2], vec![]];
    let cfg: Cfg<Statement> = Cfg::new(nodes, succs, 0, 2);
    assert_eq!(cfg.node_count(), 3);
    assert!(cfg.predecessors[1].contains(&0));
    assert!(cfg.predecessors[2].contains(&0));
    assert!(cfg.predecessors[2].contains(&1));
}

#[test]
fn test_cfg_new_ignores_out_of_range_successors() {
    let nodes = vec![
        CfgNode { id: 0, stmts: vec![] },
        CfgNode { id: 1, stmts: vec![] },
    ];
    // Successor 99 is out of range — must not panic, not appear in predecessors.
    let succs = vec![vec![1, 99], vec![]];
    let cfg: Cfg<Statement> = Cfg::new(nodes, succs, 0, 1);
    assert_eq!(cfg.predecessors[1], vec![0]);
}

#[test]
fn test_linear_cfg_correct_structure() {
    let stmts: Vec<Statement> = (0..5).map(|i| Statement::new(i, Some("v"), vec![])).collect();
    let cfg = linear_cfg(stmts);
    assert_eq!(cfg.node_count(), 5);
    assert_eq!(cfg.entry, 0);
    assert_eq!(cfg.exit, 4);
    assert_eq!(cfg.successors[0], vec![1]);
    assert_eq!(cfg.successors[4], Vec::<usize>::new());
}

#[test]
fn test_linear_cfg_empty() {
    let cfg = linear_cfg(vec![]);
    assert_eq!(cfg.node_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// WorklistAlgorithm — error paths and properties
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_worklist_empty_cfg_returns_empty_err() {
    let cfg: Cfg<Statement> = Cfg::new(vec![], vec![], 0, 0);
    let r = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg);
    assert!(matches!(r, Err(DataFlowError::EmptyCfg)));
}

#[test]
fn test_worklist_single_node_converges() {
    let s = Statement::new(0, Some("x"), vec!["y"]);
    let cfg = linear_cfg(vec![s]);
    let r = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
    assert_eq!(r.in_facts.len(), 1);
    assert_eq!(r.out_facts.len(), 1);
}

#[test]
fn test_worklist_rd_iterations_recorded() {
    let s = Statement::new(0, Some("x"), vec![]);
    let cfg = linear_cfg(vec![s]);
    let r = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    assert!(r.iterations > 0);
}

#[test]
fn test_worklist_rd_idempotent_when_rerun() {
    let stmts: Vec<Statement> = (0..6)
        .map(|i| Statement::new(i, Some(&format!("v{i}")), vec![]))
        .collect();
    let cfg = linear_cfg(stmts);
    let a = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    let b = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    for i in 0..cfg.node_count() {
        assert_eq!(a.in_facts[i], b.in_facts[i]);
        assert_eq!(a.out_facts[i], b.out_facts[i]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Direction enum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_direction_eq() {
    assert_eq!(Direction::Forward, Direction::Forward);
    assert_ne!(Direction::Forward, Direction::Backward);
}

#[test]
fn test_lva_is_backward() {
    assert_eq!(LiveVariableAnalysis.direction(), Direction::Backward);
}

#[test]
fn test_rd_is_forward() {
    assert_eq!(ReachingDefinitions.direction(), Direction::Forward);
}

#[test]
fn test_ae_is_forward() {
    let ae = AvailableExpressions::new(HashSet::new());
    assert_eq!(ae.direction(), Direction::Forward);
}

#[test]
fn test_vbe_is_backward() {
    let vbe = VeryBusyExpressions::new(HashSet::new());
    assert_eq!(vbe.direction(), Direction::Backward);
}

// ─────────────────────────────────────────────────────────────────────────────
// Statement
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_statement_new_then_expr() {
    let s = Statement::new(7, Some("x"), vec!["a", "b"]).with_expr("a+b");
    assert_eq!(s.id, 7);
    assert_eq!(s.def, Some("x".to_string()));
    assert_eq!(s.uses, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(s.expr, Some("a+b".to_string()));
}

#[test]
fn test_statement_hash_eq_consistency_30() {
    let mut rng = Lcg::new();
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for _ in 0..30 {
        let id = rng.range(10) as usize;
        let s1 = Statement::new(id, Some("x"), vec!["a"]);
        let s2 = Statement::new(id, Some("x"), vec!["a"]);
        assert_eq!(s1, s2);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        s1.hash(&mut h1);
        s2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Definition hash/eq
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_definition_hash_eq_30() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let v = format!("v{}", rng.range(5));
        let id = rng.range(20) as usize;
        let d1 = Definition { variable: v.clone(), stmt_id: id };
        let d2 = Definition { variable: v, stmt_id: id };
        assert_eq!(d1, d2);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        d1.hash(&mut h1);
        d2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiveVariableAnalysis — adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lva_def_kills_then_use_revives() {
    // stmt0: x = ... (def x, no use)
    // stmt1: y = x  (def y, use x)
    // x must be live-in at stmt1, NOT live-in at stmt0 (no use before stmt0).
    let s0 = Statement::new(0, Some("x"), vec![]);
    let s1 = Statement::new(1, Some("y"), vec!["x"]);
    let cfg = linear_cfg(vec![s0, s1]);
    let r = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
    assert!(!r.in_facts[0].contains(&"x".to_string()));
    assert!(r.in_facts[1].contains(&"x".to_string()));
}

#[test]
fn test_lva_with_random_cfgs_no_panic() {
    let mut rng = Lcg::new();
    for _ in 0..20 {
        let n = (rng.range(6) + 2) as usize;
        let mut nodes = Vec::with_capacity(n);
        for i in 0..n {
            let def = if rng.range(2) == 0 { Some(format!("v{}", rng.range(4))) } else { None };
            let uses: Vec<String> = (0..rng.range(3)).map(|_| format!("v{}", rng.range(4))).collect();
            let stmt = Statement {
                id: i,
                def,
                uses,
                expr: None,
            };
            nodes.push(CfgNode { id: i, stmts: vec![stmt] });
        }
        let succs: Vec<Vec<usize>> = (0..n)
            .map(|i| if i + 1 < n { vec![i + 1] } else { vec![] })
            .collect();
        let cfg = Cfg::new(nodes, succs, 0, n - 1);
        let _ = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReachingDefinitions — adversarial
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_rd_branch_merge() {
    let s0 = Statement::new(0, Some("x"), vec![]);
    let s1 = Statement::new(1, Some("x"), vec![]);
    let s2 = Statement::new(2, Some("x"), vec![]);
    let s3 = Statement::new(3, None, vec!["x"]);
    let nodes = vec![
        CfgNode { id: 0, stmts: vec![s0] },
        CfgNode { id: 1, stmts: vec![s1] },
        CfgNode { id: 2, stmts: vec![s2] },
        CfgNode { id: 3, stmts: vec![s3] },
    ];
    let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
    let cfg = Cfg::new(nodes, succs, 0, 3);
    let r = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    // Defs from both branches reach node 3.
    let defs: HashSet<usize> = r.in_facts[3].set.iter().map(|d| d.stmt_id).collect();
    assert!(defs.contains(&1));
    assert!(defs.contains(&2));
    // The pre-branch def of x (stmt 0) is killed by branches.
    assert!(!defs.contains(&0));
}

// ─────────────────────────────────────────────────────────────────────────────
// AvailableExpressions / VeryBusyExpressions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ae_kills_when_operand_redefined() {
    let universe: HashSet<String> = ["a+b".into()].into();
    let ae = AvailableExpressions::new(universe);
    let s0 = Statement::new(0, Some("t"), vec!["a", "b"]).with_expr("a+b");
    let s1 = Statement::new(1, Some("a"), vec![]);
    let cfg = linear_cfg(vec![s0, s1]);
    let r = WorklistAlgorithm::run(&ae, &cfg).unwrap();
    assert!(r.out_facts[0].set.contains("a+b"));
    assert!(!r.out_facts[1].set.contains("a+b"));
}

#[test]
fn test_vbe_runs_no_panic() {
    let universe: HashSet<String> = ["a+b".into()].into();
    let vbe = VeryBusyExpressions::new(universe);
    let s0 = Statement::new(0, None, vec!["a", "b"]).with_expr("a+b");
    let cfg = linear_cfg(vec![s0]);
    let _ = WorklistAlgorithm::run(&vbe, &cfg).unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain Builder
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_chain_builder_uses_of_unknown_def_is_empty() {
    let du = DefUseChain::new();
    let dp = DefPoint { variable: "ghost".into(), stmt_id: 0, node_id: 0 };
    assert!(du.uses_of(&dp).is_empty());
}

#[test]
fn test_chain_builder_defs_of_unknown_use_is_empty() {
    let ud = UseDefChain::new();
    let up = UsePoint { variable: "ghost".into(), stmt_id: 0, node_id: 0 };
    assert!(ud.defs_of(&up).is_empty());
}

#[test]
fn test_chain_builder_add_edges() {
    let mut du = DefUseChain::new();
    let dp = DefPoint { variable: "x".into(), stmt_id: 0, node_id: 0 };
    let up = UsePoint { variable: "x".into(), stmt_id: 1, node_id: 0 };
    du.add_edge(dp.clone(), up.clone());
    assert!(du.uses_of(&dp).contains(&up));
}

#[test]
fn test_chain_builder_real_chain() {
    let s0 = Statement::new(0, Some("x"), vec![]);
    let s1 = Statement::new(1, Some("y"), vec!["x"]);
    let s2 = Statement::new(2, None, vec!["y", "x"]);
    let cfg = linear_cfg(vec![s0, s1, s2]);
    let rd = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
    let (du, ud) = ChainBuilder::build(&cfg, &rd);
    let any_x_def: bool = du.chains.keys().any(|k| k.variable == "x");
    assert!(any_x_def);
    let any_x_use: bool = ud.chains.keys().any(|k| k.variable == "x");
    assert!(any_x_use);
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_liveness / compute_reaching_defs (tuple API)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_compute_liveness_empty() {
    let r = compute_liveness(&[]);
    assert!(r.is_empty());
}

#[test]
fn test_compute_liveness_sorted_dedup_output() {
    // Gen vars given as unsorted with duplicates allowed in input format.
    let cfg = vec![(0u32, vec![], vec![5u32, 1u32, 3u32], vec![])];
    let r = compute_liveness(&cfg);
    let li = &r[&0].0;
    let mut sorted = li.clone();
    sorted.sort();
    assert_eq!(*li, sorted);
}

#[test]
fn test_compute_liveness_no_panic_random_20() {
    let mut rng = Lcg::new();
    for _ in 0..20 {
        let n = (rng.range(6) + 1) as u32;
        let cfg: Vec<_> = (0..n)
            .map(|i| {
                let succs: Vec<u32> = (0..rng.range(2))
                    .map(|_| rng.range(n))
                    .collect();
                let gens: Vec<u32> = (0..rng.range(3)).map(|_| rng.range(10)).collect();
                let kill: Vec<u32> = (0..rng.range(2)).map(|_| rng.range(10)).collect();
                (i, succs, gens, kill)
            })
            .collect();
        let _ = compute_liveness(&cfg);
    }
}

#[test]
fn test_compute_reaching_defs_empty() {
    let r = compute_reaching_defs(&[]);
    assert!(r.is_empty());
}

#[test]
fn test_compute_reaching_defs_sorted_output() {
    let cfg = vec![(0u32, vec![], vec![9u32, 1u32, 5u32], vec![])];
    let r = compute_reaching_defs(&cfg);
    let ro = &r[&0].1;
    let mut sorted = ro.clone();
    sorted.sort();
    assert_eq!(*ro, sorted);
}

#[test]
fn test_compute_reaching_defs_random_20() {
    let mut rng = Lcg::new();
    for _ in 0..20 {
        let n = (rng.range(5) + 1) as u32;
        let cfg: Vec<_> = (0..n)
            .map(|i| {
                let succs: Vec<u32> = (0..rng.range(2)).map(|_| rng.range(n)).collect();
                let gens: Vec<u32> = (0..rng.range(3)).map(|_| rng.range(10)).collect();
                let kill: Vec<u32> = (0..rng.range(2)).map(|_| rng.range(10)).collect();
                (i, succs, gens, kill)
            })
            .collect();
        let _ = compute_reaching_defs(&cfg);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominators / dominance frontier / postorder
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_compute_dominators_empty() {
    let idom = compute_dominators(0, &[], 0);
    assert!(idom.is_empty());
}

#[test]
fn test_compute_dominators_self_loop_only() {
    let succs = vec![vec![0usize]];
    let idom = compute_dominators(1, &succs, 0);
    assert_eq!(idom[0], 0);
}

#[test]
fn test_compute_dominators_unreachable_self_idom() {
    // Node 2 unreachable from 0.
    let succs = vec![vec![1usize], vec![], vec![]];
    let idom = compute_dominators(3, &succs, 0);
    assert_eq!(idom[2], 2);
}

#[test]
fn test_compute_dominators_linear_random_chains() {
    let mut rng = Lcg::new();
    for _ in 0..10 {
        let n = (rng.range(8) + 2) as usize;
        let succs: Vec<Vec<usize>> = (0..n)
            .map(|i| if i + 1 < n { vec![i + 1] } else { vec![] })
            .collect();
        let idom = compute_dominators(n, &succs, 0);
        for i in 1..n {
            assert_eq!(idom[i], i - 1);
        }
    }
}

#[test]
fn test_postorder_unreachable_omitted() {
    let succs = vec![vec![1usize], vec![], vec![]];
    let po = postorder(3, &succs, 0);
    assert!(!po.contains(&2));
}

#[test]
fn test_postorder_empty() {
    let po = postorder(0, &[], 0);
    assert!(po.is_empty());
}

#[test]
fn test_dom_frontier_loop() {
    // 0→1, 1→{2,1} self-loop.
    let succs = vec![vec![1usize], vec![1, 2], vec![]];
    let idom = compute_dominators(3, &succs, 0);
    let df = compute_dominance_frontiers(3, &succs, &idom);
    // node 1's self-loop puts 1 in DF[1].
    assert!(df[1].contains(&1));
}

// ─────────────────────────────────────────────────────────────────────────────
// propagate_constants — fuzzed
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_propagate_constants_boundary_values() {
    let assignments = [(0u32, i64::MAX), (1u32, i64::MIN), (2u32, 0)];
    let uses: &[(u32, u32)] = &[];
    let r = propagate_constants(&assignments, uses);
    assert_eq!(r[&0], LatticeValue::Const(i64::MAX));
    assert_eq!(r[&1], LatticeValue::Const(i64::MIN));
    assert_eq!(r[&2], LatticeValue::Const(0));
}

#[test]
fn test_propagate_constants_empty_returns_empty() {
    let r = propagate_constants(&[], &[]);
    assert!(r.is_empty());
}

#[test]
fn test_propagate_constants_no_panic_fuzz() {
    let mut rng = Lcg::new();
    for _ in 0..30 {
        let n_assign = (rng.range(10)) as usize;
        let assignments: Vec<(u32, i64)> = (0..n_assign)
            .map(|_| (rng.range(8), rng.next() as i64))
            .collect();
        let uses: Vec<(u32, u32)> = (0..rng.range(10))
            .map(|_| (rng.range(20), rng.range(8)))
            .collect();
        let _ = propagate_constants(&assignments, &uses);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// insert_phi_nodes — adversarial
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_insert_phi_nodes_empty_cfg() {
    let r = insert_phi_nodes(&[], &HashMap::new());
    assert!(r.is_empty());
}

#[test]
fn test_insert_phi_nodes_no_defs() {
    let cfg = vec![(0u32, vec![1u32]), (1u32, vec![])];
    let r = insert_phi_nodes(&cfg, &HashMap::new());
    assert!(r.is_empty());
}

#[test]
fn test_insert_phi_nodes_diamond_phi_at_join() {
    let cfg = vec![
        (0u32, vec![1u32, 2u32]),
        (1u32, vec![3u32]),
        (2u32, vec![3u32]),
        (3u32, vec![]),
    ];
    let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
    defs.insert(7u32, vec![1u32, 2u32]);
    let phi = insert_phi_nodes(&cfg, &defs);
    assert!(phi.get(&3u32).is_some_and(|v| v.contains(&7u32)));
}

#[test]
fn test_insert_phi_nodes_no_join_linear() {
    let cfg = vec![(0u32, vec![1u32]), (1u32, vec![2u32]), (2u32, vec![])];
    let mut defs: HashMap<u32, Vec<u32>> = HashMap::new();
    defs.insert(1u32, vec![0u32]);
    let phi = insert_phi_nodes(&cfg, &defs);
    assert!(phi.is_empty() || phi.values().all(Vec::is_empty));
}

// ─────────────────────────────────────────────────────────────────────────────
// Interprocedural skeleton
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_interproc_default_and_new_equivalent() {
    let a: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::new();
    let b: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::default();
    assert!(a.cfgs.is_empty() && b.cfgs.is_empty());
    assert!(a.summaries.is_empty() && b.summaries.is_empty());
}

#[test]
fn test_interproc_get_summary_returns_none_initially() {
    let idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::new();
    assert!(idf.get_summary(&FunctionId(1)).is_none());
}

#[test]
fn test_interproc_set_then_get() {
    let mut idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::new();
    let fid = FunctionId(99);
    idf.set_summary(&fid, BitSetLattice::bottom());
    assert!(idf.get_summary(&fid).is_some());
}

#[test]
fn test_interproc_compute_no_op_when_unregistered() {
    let mut idf: InterproceduralDataFlow<Statement, BitSetLattice<Definition>> =
        InterproceduralDataFlow::new();
    idf.compute_summaries(&ReachingDefinitions, &[FunctionId(42)])
        .unwrap();
    assert!(idf.get_summary(&FunctionId(42)).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// SsaVar / PhiNode hash / eq
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ssa_var_hash_eq() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let a = SsaVar { original_id: 5, version: 2 };
    let b = SsaVar { original_id: 5, version: 2 };
    assert_eq!(a, b);
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    a.hash(&mut h1);
    b.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn test_phi_node_eq() {
    let a = PhiNode { var_id: 1, sources: vec![(0, 0), (1, 1)] };
    let b = PhiNode { var_id: 1, sources: vec![(0, 0), (1, 1)] };
    assert_eq!(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// Send/Sync threaded stress on common analyses
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_threaded_run_lva() {
    let s0 = Statement::new(0, Some("x"), vec!["y"]);
    let s1 = Statement::new(1, None, vec!["x"]);
    let cfg = Arc::new(linear_cfg(vec![s0, s1]));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let cfg = Arc::clone(&cfg);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = WorklistAlgorithm::run(&LiveVariableAnalysis, &cfg).unwrap();
                assert_eq!(r.in_facts.len(), 2);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_threaded_run_rd() {
    let s0 = Statement::new(0, Some("x"), vec![]);
    let s1 = Statement::new(1, Some("y"), vec!["x"]);
    let cfg = Arc::new(linear_cfg(vec![s0, s1]));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let cfg = Arc::clone(&cfg);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = WorklistAlgorithm::run(&ReachingDefinitions, &cfg).unwrap();
                assert_eq!(r.out_facts.len(), 2);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_threaded_compute_dominators() {
    let succs = Arc::new(vec![vec![1usize, 2], vec![3], vec![3], vec![]]);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let succs = Arc::clone(&succs);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let idom = compute_dominators(4, &succs, 0);
                assert_eq!(idom[3], 0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
