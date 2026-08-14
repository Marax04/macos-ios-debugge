//! Differential/oracle test for `available_expressions::compute_available`.
//!
//! Oracle definition (paths, not dataflow): an expression `e` is AVAILABLE at
//! the entry of block `B` iff on EVERY execution path entry → B, `e` has been
//! computed and none of its operand variables has been redefined since that
//! computation.
//!
//! Brute force: explore the state space of (block, concrete availability set)
//! reachable from the entry by following CFG edges and simulating each block's
//! statements one at a time. Cycles are handled by memoizing visited states —
//! this is exhaustive path enumeration (finite because the availability set
//! lattice is finite), NOT a worklist over dataflow equations. avail_in(B) is
//! the intersection of the availability sets of all states arriving at B.

use std::collections::{BTreeSet, HashSet};

use rustre_analysis_dataflow::available_expressions::{
    compute_available, AvailBlock, AvailStmt, AvailableExpressions, BinOpKind, Expr, ExprId,
    ExprKind, VarId,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const NUM_VARS: u32 = 3;

/// Build the expression universe: all `va OP vb` pairs over NUM_VARS.
fn universe() -> Vec<Expr> {
    let mut v = Vec::new();
    let mut id = 0u32;
    for a in 0..NUM_VARS {
        for b in 0..NUM_VARS {
            v.push(Expr::new(
                ExprId::new(id),
                ExprKind::BinOp {
                    op: BinOpKind::Add,
                    lhs: VarId::new(a),
                    rhs: VarId::new(b),
                },
            ));
            id += 1;
        }
    }
    v
}

fn expr_operands(u: &[Expr], e: ExprId) -> Vec<VarId> {
    match u.iter().find(|x| x.id == e).map(|x| &x.kind) {
        Some(ExprKind::BinOp { lhs, rhs, .. }) => vec![*lhs, *rhs],
        _ => vec![],
    }
}

/// Oracle: simulate one statement on a concrete availability set.
/// Definitionally: redefining `v` invalidates every expression mentioning `v`;
/// computing `e` makes `e` available unless this same statement destroys one of
/// its operands.
fn step(u: &[Expr], set: &mut BTreeSet<u32>, s: &AvailStmt) {
    if let Some(def) = s.def {
        let dead: Vec<u32> = set
            .iter()
            .copied()
            .filter(|&id| expr_operands(u, ExprId::new(id)).contains(&def))
            .collect();
        for d in dead {
            set.remove(&d);
        }
    }
    if let Some(e) = s.expr_id {
        let ops = expr_operands(u, e);
        let clobbered = s.def.is_some_and(|d| ops.contains(&d));
        if !clobbered {
            set.insert(e.0);
        }
    }
}

/// Exhaustive path exploration → avail_in for every reachable block.
/// `None` = block unreachable from entry.
fn oracle(
    u: &[Expr],
    blocks: &[AvailBlock],
    entry: usize,
) -> Vec<Option<BTreeSet<u32>>> {
    let n = blocks.len();
    let mut acc: Vec<Option<BTreeSet<u32>>> = vec![None; n];
    let mut seen: HashSet<(usize, BTreeSet<u32>)> = HashSet::new();
    let mut work: Vec<(usize, BTreeSet<u32>)> = vec![(entry, BTreeSet::new())];
    while let Some((b, set)) = work.pop() {
        if !seen.insert((b, set.clone())) {
            continue;
        }
        acc[b] = Some(match acc[b].take() {
            None => set.clone(),
            Some(prev) => prev.intersection(&set).copied().collect(),
        });
        let mut out = set;
        for s in &blocks[b].stmts {
            step(u, &mut out, s);
        }
        for &succ in &blocks[b].succs {
            if succ < n {
                work.push((succ, out.clone()));
            }
        }
    }
    acc
}

fn random_case(rng: &mut Rng, u: &[Expr]) -> Vec<AvailBlock> {
    let n = 1 + rng.below(5) as usize;
    (0..n)
        .map(|i| {
            let k = rng.below(3) as usize;
            let mut succs: Vec<usize> = Vec::new();
            for _ in 0..k {
                let t = rng.below(n as u64) as usize; // allows self-loops/back edges
                if !succs.contains(&t) {
                    succs.push(t);
                }
            }
            let ns = rng.below(4) as usize;
            let stmts = (0..ns)
                .map(|_| {
                    let def = VarId::new(rng.below(u64::from(NUM_VARS)) as u32);
                    match rng.below(4) {
                        0 => AvailStmt::define(def),
                        1 => AvailStmt::read_only(vec![def]),
                        _ => {
                            let e = u[rng.below(u.len() as u64) as usize].id;
                            AvailStmt::assign(def, e, expr_operands(u, e))
                        }
                    }
                })
                .collect();
            AvailBlock {
                id: i,
                stmts,
                succs,
            }
        })
        .collect()
}

#[test]
fn available_expressions_differential_oracle() {
    let u = universe();
    let analysis = AvailableExpressions::new(u.clone());
    let mut rng = Rng(0x00AE_A11E_0001_BEEFu64);
    for case in 0..1500u32 {
        let blocks = random_case(&mut rng, &u);
        let n = blocks.len();
        let entry = 0usize;
        let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
        for b in &blocks {
            for &s in &b.succs {
                if s < n {
                    preds[s].push(b.id);
                }
            }
        }
        let got = compute_available(&blocks, entry, &preds, &analysis);
        let want = oracle(&u, &blocks, entry);

        // determinism: identical input must give identical output.
        let got2 = compute_available(&blocks, entry, &preds, &analysis);
        for b in 0..n {
            assert_eq!(
                got.in_sets[b].available, got2.in_sets[b].available,
                "case {case}: nondeterministic avail_in at bb{b}"
            );
        }

        for b in 0..n {
            let Some(expect) = &want[b] else { continue }; // unreachable block
            for e in &u {
                assert_eq!(
                    got.in_sets[b].contains(e.id),
                    expect.contains(&e.id.0),
                    "case {case}: avail_in mismatch bb={b} expr={:?}\nblocks={blocks:?}",
                    e.id
                );
            }
        }
    }
}
