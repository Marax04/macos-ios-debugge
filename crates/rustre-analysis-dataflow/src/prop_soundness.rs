//! Property-based / randomized soundness tests for the dataflow analyses.
//!
//! Uses a small self-contained xorshift PRNG (no external dev-dependencies)
//! to generate bounded random programs/CFGs, and cross-checks the analyses
//! against brute-force reference semantics:
//!
//! * `constant_propagator` — lattice laws (meet commutative / associative /
//!   idempotent / monotone), transfer monotonicity, fixpoint stability under
//!   one more transfer application, and soundness against concrete path
//!   execution ("a `Const(c)` claim is never contradicted by any execution").
//! * `available_expressions` — join laws, fixpoint stability, and soundness
//!   against brute-force path enumeration ("claimed available ⇒ computed and
//!   not killed on every path").
//! * `ssa_optimizer` — semantic preservation: a random SSA function is
//!   interpreted before and after the full `SsaOptimizer` pipeline and must
//!   return the same value.
//!
//! Failing cases found by these tests were minimized into deterministic
//! regression tests in the respective modules' own `tests` sections.

#![cfg(test)]

// ─────────────────────────────────────────────────────────────────────────────
// xorshift64* PRNG — deterministic, dependency-free
// ─────────────────────────────────────────────────────────────────────────────

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    pub fn small_i64(&mut self) -> i64 {
        (self.next_u64() % 21) as i64 - 10
    }
}

/// Random DAG-plus-optional-back-edges CFG skeleton: returns succs per block.
/// Every block `i > 0` gets at least one predecessor among `0..i`, so all
/// blocks are reachable from block 0 (the entry).
fn random_cfg(rng: &mut Rng, n: usize, allow_back_edges: bool) -> Vec<Vec<usize>> {
    let mut succs: Vec<Vec<usize>> = vec![vec![]; n];
    for j in 1..n {
        let p = rng.below(j);
        succs[p].push(j);
    }
    // Extra forward edges.
    for i in 0..n {
        if i + 1 < n && rng.chance(35) {
            let j = i + 1 + rng.below(n - i - 1);
            if !succs[i].contains(&j) && succs[i].len() < 2 {
                succs[i].push(j);
            }
        }
    }
    // Occasional back edge (including possibly to the entry block).
    if allow_back_edges && n > 1 && rng.chance(50) {
        let i = 1 + rng.below(n - 1);
        let j = rng.below(i + 1); // j <= i  → back edge (or self loop)
        if !succs[i].contains(&j) && succs[i].len() < 2 {
            succs[i].push(j);
        }
    }
    succs
}

fn preds_of(succs: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut preds = vec![vec![]; succs.len()];
    for (i, ss) in succs.iter().enumerate() {
        for &s in ss {
            preds[s].push(i);
        }
    }
    preds
}

/// Enumerate execution paths (block-id sequences starting at `entry`).
/// Back edges are unrolled: total path length is capped, and the number of
/// collected paths is bounded. Every returned path is a valid execution
/// prefix, so analysis claims may be checked at every position along it.
fn enumerate_paths(succs: &[Vec<usize>], entry: usize, max_len: usize, max_paths: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut stack = vec![vec![entry]];
    while let Some(path) = stack.pop() {
        if out.len() >= max_paths {
            break;
        }
        let last = *path.last().unwrap();
        let ss = &succs[last];
        if ss.is_empty() || path.len() >= max_len {
            out.push(path);
        } else {
            for &s in ss {
                let mut p = path.clone();
                p.push(s);
                stack.push(p);
            }
        }
    }
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 1: constant_propagator
// ═════════════════════════════════════════════════════════════════════════════

mod const_prop {
    use super::{enumerate_paths, preds_of, random_cfg, Rng};
    use crate::constant_propagator::{
        propagate_constants, BinOpKind, ConstLattice, ConstantPropagator, PropBlock, PropExpr,
        PropState, PropStmt, UnaryOpKind, VarId,
    };
    use std::collections::HashMap;

    const NVARS: u32 = 4;

    fn lattice_samples() -> Vec<ConstLattice> {
        vec![
            ConstLattice::Top,
            ConstLattice::Bottom,
            ConstLattice::Const(-3),
            ConstLattice::Const(0),
            ConstLattice::Const(7),
        ]
    }

    /// Partial order: Bottom ≤ Const(c) ≤ Top; Const(a) ≤ Const(b) iff a == b.
    fn leq(a: &ConstLattice, b: &ConstLattice) -> bool {
        match (a, b) {
            (ConstLattice::Bottom, _) | (_, ConstLattice::Top) => true,
            (ConstLattice::Const(x), ConstLattice::Const(y)) => x == y,
            _ => false,
        }
    }

    #[test]
    fn meet_is_commutative_associative_idempotent_and_a_lower_bound() {
        let s = lattice_samples();
        for a in &s {
            assert_eq!(ConstLattice::meet(a, a), *a, "idempotence");
            for b in &s {
                let ab = ConstLattice::meet(a, b);
                assert_eq!(ab, ConstLattice::meet(b, a), "commutativity");
                assert!(leq(&ab, a) && leq(&ab, b), "meet must be a lower bound");
                for c in &s {
                    assert_eq!(
                        ConstLattice::meet(&ab, c),
                        ConstLattice::meet(a, &ConstLattice::meet(b, c)),
                        "associativity"
                    );
                }
            }
        }
    }

    #[test]
    fn meet_is_monotone() {
        let s = lattice_samples();
        for a in &s {
            for a2 in &s {
                if !leq(a, a2) {
                    continue;
                }
                for b in &s {
                    assert!(
                        leq(&ConstLattice::meet(a, b), &ConstLattice::meet(a2, b)),
                        "meet monotone in first arg: {a:?} <= {a2:?} with {b:?}"
                    );
                }
            }
        }
    }

    fn random_expr(rng: &mut Rng, depth: usize) -> PropExpr {
        if depth == 0 || rng.chance(40) {
            return match rng.below(3) {
                0 => PropExpr::Literal(rng.small_i64()),
                1 => PropExpr::Var(VarId::new(rng.below(NVARS as usize) as u32)),
                _ => PropExpr::Unknown,
            };
        }
        if rng.chance(25) {
            let op = [UnaryOpKind::Neg, UnaryOpKind::Not, UnaryOpKind::Abs][rng.below(3)];
            return PropExpr::UnaryOp(op, Box::new(random_expr(rng, depth - 1)));
        }
        let op = [
            BinOpKind::Add,
            BinOpKind::Sub,
            BinOpKind::Mul,
            BinOpKind::Div,
            BinOpKind::And,
            BinOpKind::Or,
            BinOpKind::Xor,
            BinOpKind::Shl,
            BinOpKind::Shr,
        ][rng.below(9)];
        PropExpr::BinOp(
            op,
            Box::new(random_expr(rng, depth - 1)),
            Box::new(random_expr(rng, depth - 1)),
        )
    }

    /// Random program. The entry block initializes every variable (either to
    /// a literal or to `Unknown`) so no reachable use ever observes an
    /// uninitialized variable — the propagator's Top-by-absence convention is
    /// only sound under that assumption.
    fn random_program(rng: &mut Rng, back_edges: bool) -> (Vec<PropBlock>, Vec<Vec<usize>>) {
        let n = 2 + rng.below(5);
        let succs = random_cfg(rng, n, back_edges);
        let preds = preds_of(&succs);
        let mut blocks = Vec::new();
        for id in 0..n {
            let mut stmts = Vec::new();
            if id == 0 {
                for v in 0..NVARS {
                    let init = if rng.chance(60) {
                        PropExpr::Literal(rng.small_i64())
                    } else {
                        PropExpr::Unknown
                    };
                    stmts.push(PropStmt::assign(VarId::new(v), init));
                }
            }
            for _ in 0..rng.below(4) {
                let def = VarId::new(rng.below(NVARS as usize) as u32);
                stmts.push(PropStmt::assign(def, random_expr(rng, 2)));
            }
            blocks.push(PropBlock {
                id,
                stmts,
                succs: succs[id].clone(),
            });
        }
        (blocks, preds)
    }

    /// Concrete evaluation matching the folder's semantics on the defined
    /// cases; on cases where the analysis answers Bottom (div-by-zero,
    /// out-of-range shift) any value works, so we pick 0.
    fn eval_concrete(expr: &PropExpr, env: &HashMap<u32, i64>, rng: &mut Rng) -> i64 {
        match expr {
            PropExpr::Literal(v) => *v,
            PropExpr::Var(v) => *env.get(&v.0).unwrap_or(&0),
            PropExpr::Unknown => rng.small_i64(),
            PropExpr::Phi(_) => 0, // not generated
            PropExpr::UnaryOp(op, e) => {
                let v = eval_concrete(e, env, rng);
                match op {
                    UnaryOpKind::Neg => v.wrapping_neg(),
                    UnaryOpKind::Not => !v,
                    UnaryOpKind::Abs => v.wrapping_abs(),
                }
            }
            PropExpr::BinOp(op, l, r) => {
                let a = eval_concrete(l, env, rng);
                let b = eval_concrete(r, env, rng);
                match op {
                    BinOpKind::Add => a.wrapping_add(b),
                    BinOpKind::Sub => a.wrapping_sub(b),
                    BinOpKind::Mul => a.wrapping_mul(b),
                    BinOpKind::Div => {
                        if b == 0 {
                            0
                        } else {
                            a.wrapping_div(b)
                        }
                    }
                    BinOpKind::And => a & b,
                    BinOpKind::Or => a | b,
                    BinOpKind::Xor => a ^ b,
                    BinOpKind::Shl => {
                        if (0..64).contains(&b) {
                            a.wrapping_shl(b as u32)
                        } else {
                            0
                        }
                    }
                    BinOpKind::Shr => {
                        if (0..64).contains(&b) {
                            a.wrapping_shr(b as u32)
                        } else {
                            0
                        }
                    }
                }
            }
        }
    }

    fn check_claims(state_claims: &[(VarId, i64)], env: &HashMap<u32, i64>, ctx: &str) {
        for (var, c) in state_claims {
            if let Some(actual) = env.get(&var.0) {
                assert_eq!(
                    actual, c,
                    "{ctx}: analysis claims {var:?} == {c} but concrete value is {actual}"
                );
            }
        }
    }

    /// Soundness: on every enumerated execution prefix, every `Const` claim
    /// of the analysis matches the concrete value.
    #[test]
    fn propagation_never_contradicts_concrete_execution() {
        for seed in 1..=120u64 {
            let mut rng = Rng::new(seed * 0x9E37_79B9);
            let back_edges = seed % 2 == 0;
            let (blocks, preds) = random_program(&mut rng, back_edges);
            let prop = ConstantPropagator::new();
            let result = propagate_constants(&blocks, 0, &preds, &prop);
            let succs: Vec<Vec<usize>> = blocks.iter().map(|b| b.succs.clone()).collect();
            let paths = enumerate_paths(&succs, 0, 16, 128);

            for trial in 0..3u64 {
                for path in &paths {
                    let mut exec_rng = Rng::new(seed ^ (trial.wrapping_mul(0xABCD_EF01) | 1));
                    // Arbitrary initial values (entry re-assigns everything).
                    let mut env: HashMap<u32, i64> =
                        (0..NVARS).map(|v| (v, exec_rng.small_i64())).collect();
                    for &bid in path {
                        check_claims(
                            &result.constants_in(bid),
                            &env,
                            &format!("seed {seed} path {path:?} entry of block {bid}"),
                        );
                        for stmt in &blocks[bid].stmts {
                            if let Some(def) = stmt.def {
                                let v = eval_concrete(&stmt.rhs, &env, &mut exec_rng);
                                env.insert(def.0, v);
                            }
                        }
                        check_claims(
                            &result.constants_out(bid),
                            &env,
                            &format!("seed {seed} path {path:?} exit of block {bid}"),
                        );
                    }
                }
            }
        }
    }

    fn state_semantically_eq(a: &PropState, b: &PropState) -> bool {
        let keys: std::collections::HashSet<VarId> = a
            .values
            .keys()
            .chain(b.values.keys())
            .copied()
            .collect();
        keys.iter().all(|&k| a.get(k) == b.get(k))
    }

    /// Fixpoint stability: recomputing any block's in-state from its
    /// predecessors and applying the transfer function once more must not
    /// change the recorded out-state.
    #[test]
    fn fixpoint_is_stable_under_one_more_transfer() {
        for seed in 200..=280u64 {
            let mut rng = Rng::new(seed * 0x517C_C1B7);
            let (blocks, preds) = random_program(&mut rng, true);
            let prop = ConstantPropagator::new();
            let result = propagate_constants(&blocks, 0, &preds, &prop);
            assert!(result.iterations <= prop.max_iterations, "must converge");
            for (bid, block) in blocks.iter().enumerate() {
                let mut new_in = PropState::new();
                for &p in &preds[bid] {
                    new_in.join_from(&result.out_states[p]);
                }
                if bid == 0 {
                    // Entry boundary: initial values are arbitrary.
                    for v in new_in.values.values_mut() {
                        *v = ConstLattice::Bottom;
                    }
                }
                let new_out = prop.transfer(block, &new_in);
                assert!(
                    state_semantically_eq(&new_out, &result.out_states[bid]),
                    "seed {seed}: block {bid} out-state not a fixpoint:\n{new_out:?}\nvs\n{:?}",
                    result.out_states[bid]
                );
            }
        }
    }

    /// Transfer monotonicity: lowering the in-state can only lower the
    /// out-state.
    #[test]
    fn transfer_is_monotone() {
        for seed in 300..=380u64 {
            let mut rng = Rng::new(seed | 1);
            let (blocks, _) = random_program(&mut rng, false);
            // Random "higher" state s_hi, then lower some entries → s_lo.
            let mut s_hi = PropState::new();
            let mut s_lo = PropState::new();
            for v in 0..NVARS {
                let hi = match rng.below(3) {
                    0 => ConstLattice::Top,
                    1 => ConstLattice::Const(rng.small_i64()),
                    _ => ConstLattice::Bottom,
                };
                let lo = if rng.chance(50) {
                    hi.clone()
                } else {
                    match &hi {
                        ConstLattice::Top => {
                            if rng.chance(50) {
                                ConstLattice::Const(rng.small_i64())
                            } else {
                                ConstLattice::Bottom
                            }
                        }
                        ConstLattice::Const(_) | ConstLattice::Bottom => ConstLattice::Bottom,
                    }
                };
                s_hi.set(VarId::new(v), hi);
                s_lo.set(VarId::new(v), lo);
            }
            let prop = ConstantPropagator::new();
            for block in &blocks {
                let out_hi = prop.transfer(block, &s_hi);
                let out_lo = prop.transfer(block, &s_lo);
                for v in 0..NVARS {
                    let var = VarId::new(v);
                    assert!(
                        leq(out_lo.get(var), out_hi.get(var)),
                        "seed {seed}: transfer not monotone for {var:?}: lo {:?} hi {:?}",
                        out_lo.get(var),
                        out_hi.get(var)
                    );
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 2: available_expressions
// ═════════════════════════════════════════════════════════════════════════════

mod avail_exprs {
    use super::{enumerate_paths, preds_of, random_cfg, Rng};
    use crate::available_expressions::{
        compute_available, AvailBlock, AvailStmt, AvailableExpressions, BinOpKind, Expr, ExprId,
        ExprSet, ExpressionUniverse, VarId,
    };
    use std::collections::HashSet;

    const NVARS: u32 = 4;

    fn random_universe(rng: &mut Rng) -> Vec<Expr> {
        let mut u = ExpressionUniverse::new();
        let ops = [
            BinOpKind::Add,
            BinOpKind::Sub,
            BinOpKind::Mul,
            BinOpKind::Xor,
        ];
        for _ in 0..(3 + rng.below(4)) {
            let l = VarId::new(rng.below(NVARS as usize) as u32);
            let r = VarId::new(rng.below(NVARS as usize) as u32);
            u.bin_op(ops[rng.below(ops.len())], l, r);
        }
        u.into_exprs()
    }

    fn random_program(
        rng: &mut Rng,
        universe: &[Expr],
        back_edges: bool,
    ) -> (Vec<AvailBlock>, Vec<Vec<usize>>) {
        let n = 2 + rng.below(5);
        let succs = random_cfg(rng, n, back_edges);
        let preds = preds_of(&succs);
        let mut blocks = Vec::new();
        for id in 0..n {
            let mut stmts = Vec::new();
            for _ in 0..rng.below(4) {
                match rng.below(3) {
                    0 => {
                        // Compute a random universe expression into a random
                        // def (which may alias one of its operands).
                        let e = &universe[rng.below(universe.len())];
                        let def = VarId::new(rng.below(NVARS as usize) as u32);
                        let uses: Vec<VarId> = e.uses.iter().copied().collect();
                        stmts.push(AvailStmt::assign(def, e.id, uses));
                    }
                    1 => stmts.push(AvailStmt::define(VarId::new(
                        rng.below(NVARS as usize) as u32,
                    ))),
                    _ => stmts.push(AvailStmt::read_only(vec![VarId::new(
                        rng.below(NVARS as usize) as u32,
                    )])),
                }
            }
            blocks.push(AvailBlock {
                id,
                stmts,
                succs: succs[id].clone(),
            });
        }
        (blocks, preds)
    }

    /// Reference semantics along one concrete path: an expression is
    /// available if it was computed and no operand redefined since. Note the
    /// order: the computation reads its operands *before* the definition
    /// takes effect, so gen happens first and the kill (of exprs using the
    /// def) wins.
    fn reference_avail_along_path(
        blocks: &[AvailBlock],
        universe: &[Expr],
        path: &[usize],
    ) -> Vec<HashSet<ExprId>> {
        let mut avail: HashSet<ExprId> = HashSet::new();
        let mut at_entry = Vec::with_capacity(path.len());
        for &bid in path {
            at_entry.push(avail.clone());
            for stmt in &blocks[bid].stmts {
                if let Some(eid) = stmt.expr_id {
                    avail.insert(eid);
                }
                if let Some(def) = stmt.def {
                    avail.retain(|id| {
                        universe
                            .iter()
                            .find(|e| e.id == *id)
                            .is_none_or(|e| !e.uses_var(def))
                    });
                }
            }
        }
        at_entry
    }

    /// Soundness (must-analysis): if the analysis claims expression `e` is
    /// available at entry to block `b`, then on EVERY path from entry to `b`,
    /// `e` was computed and not subsequently killed.
    #[test]
    fn claimed_available_holds_on_every_path() {
        for seed in 1..=150u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xD134_2543_DE82_EF95));
            let universe = random_universe(&mut rng);
            let analysis = AvailableExpressions::new(universe.clone());
            let (blocks, preds) = random_program(&mut rng, &universe, seed % 2 == 0);
            let result = compute_available(&blocks, 0, &preds, &analysis);
            let succs: Vec<Vec<usize>> = blocks.iter().map(|b| b.succs.clone()).collect();
            let paths = enumerate_paths(&succs, 0, 16, 128);

            for path in &paths {
                let ref_entry = reference_avail_along_path(&blocks, &universe, path);
                for (pos, &bid) in path.iter().enumerate() {
                    let claimed = result.available_at_entry(bid);
                    for eid in &claimed {
                        assert!(
                            ref_entry[pos].contains(eid),
                            "seed {seed}: expr {eid:?} claimed available at entry of block \
                             {bid}, but path {path:?} (position {pos}) does not provide it"
                        );
                    }
                }
            }
        }
    }

    /// Fixpoint stability: recompute each in-set from predecessor out-sets
    /// and apply the transfer once more — the out-set must not change.
    #[test]
    fn fixpoint_is_stable_under_one_more_transfer() {
        for seed in 400..=470u64 {
            let mut rng = Rng::new(seed | 1);
            let universe = random_universe(&mut rng);
            let analysis = AvailableExpressions::new(universe.clone());
            let (blocks, preds) = random_program(&mut rng, &universe, true);
            let result = compute_available(&blocks, 0, &preds, &analysis);
            for (bid, block) in blocks.iter().enumerate() {
                let new_in = if bid == 0 {
                    AvailableExpressions::boundary()
                } else if preds[bid].is_empty() {
                    analysis.initial()
                } else {
                    let mut acc = result.out_sets[preds[bid][0]].clone();
                    for &p in &preds[bid][1..] {
                        acc = acc.join(&result.out_sets[p]);
                    }
                    acc
                };
                let new_out = analysis.transfer(block, &new_in);
                assert_eq!(
                    new_out.available, result.out_sets[bid].available,
                    "seed {seed}: block {bid} out-set is not a fixpoint"
                );
            }
        }
    }

    /// Join laws on concrete (non-lazy) sets: commutative, associative,
    /// idempotent, and a lower bound (⊆ both operands).
    #[test]
    fn join_is_commutative_associative_idempotent() {
        let mut rng = Rng::new(0xFEED_FACE);
        let universe: Vec<ExprId> = (0..8).map(ExprId::new).collect();
        let rand_set = |rng: &mut Rng| -> ExprSet {
            if rng.chance(20) {
                ExprSet::bottom()
            } else {
                let mut s = ExprSet::bottom();
                for &e in &universe {
                    if rng.chance(50) {
                        s.add(e);
                    }
                }
                if rng.chance(15) {
                    // A "reduced top" is representationally allowed too.
                    s.is_top = true;
                }
                s
            }
        };
        for _ in 0..300 {
            let a = rand_set(&mut rng);
            let b = rand_set(&mut rng);
            let c = rand_set(&mut rng);
            let ab = a.join(&b);
            let ba = b.join(&a);
            assert_eq!(ab.available, ba.available, "join commutative");
            assert_eq!(
                a.join(&a).available,
                a.available,
                "join idempotent"
            );
            assert_eq!(
                ab.join(&c).available,
                a.join(&b.join(&c)).available,
                "join associative"
            );
            assert!(
                ab.available.is_subset(&a.available) || a.is_top && !b.is_top,
                "join is a lower bound"
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 3: ssa_optimizer — semantic preservation under the full pipeline
// ═════════════════════════════════════════════════════════════════════════════

mod ssa_opt {
    use super::Rng;
    use crate::ssa_optimizer::{
        ConstVal, SsaBlock, SsaExpr, SsaFunction, SsaInstr, SsaOptimizer, SsaRef, SsaTerm,
    };
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Val {
        I(i64),
        B(bool),
    }

    // Payloads are carried only for their Debug rendering in test failures.
    #[allow(dead_code)]
    #[derive(Debug)]
    enum ExecErr {
        UndefinedVar(SsaRef),
        TypeError,
        NoBlock(u32),
        StepLimit,
    }

    fn get(env: &HashMap<SsaRef, Val>, r: &SsaRef) -> Result<Val, ExecErr> {
        env.get(r).copied().ok_or_else(|| ExecErr::UndefinedVar(r.clone()))
    }

    fn get_i(env: &HashMap<SsaRef, Val>, r: &SsaRef) -> Result<i64, ExecErr> {
        match get(env, r)? {
            Val::I(v) => Ok(v),
            Val::B(_) => Err(ExecErr::TypeError),
        }
    }

    fn eval(
        expr: &SsaExpr,
        env: &HashMap<SsaRef, Val>,
        prev_block: Option<u32>,
    ) -> Result<Val, ExecErr> {
        Ok(match expr {
            SsaExpr::Const(ConstVal::Int(v)) => Val::I(*v),
            SsaExpr::Const(ConstVal::Bool(b)) => Val::B(*b),
            SsaExpr::Const(ConstVal::Unknown) => Val::I(0),
            SsaExpr::Var(v) => get(env, v)?,
            SsaExpr::Add(l, r) => Val::I(get_i(env, l)?.wrapping_add(get_i(env, r)?)),
            SsaExpr::Sub(l, r) => Val::I(get_i(env, l)?.wrapping_sub(get_i(env, r)?)),
            SsaExpr::Mul(l, r) => Val::I(get_i(env, l)?.wrapping_mul(get_i(env, r)?)),
            SsaExpr::And(l, r) => Val::I(get_i(env, l)? & get_i(env, r)?),
            SsaExpr::Or(l, r) => Val::I(get_i(env, l)? | get_i(env, r)?),
            SsaExpr::Xor(l, r) => Val::I(get_i(env, l)? ^ get_i(env, r)?),
            SsaExpr::Neg(v) => Val::I(get_i(env, v)?.wrapping_neg()),
            SsaExpr::Not(v) => Val::I(!get_i(env, v)?),
            SsaExpr::CmpEq(l, r) => Val::B(get_i(env, l)? == get_i(env, r)?),
            SsaExpr::CmpLt(l, r) => Val::B(get_i(env, l)? < get_i(env, r)?),
            SsaExpr::Phi(srcs) => {
                let prev = prev_block.ok_or(ExecErr::TypeError)?;
                let (_, src) = srcs
                    .iter()
                    .find(|(p, _)| *p == prev)
                    .ok_or(ExecErr::TypeError)?;
                get(env, src)?
            }
            SsaExpr::Call { .. } => return Err(ExecErr::TypeError), // not generated
        })
    }

    /// Concrete interpreter. Returns the value of the executed `return`,
    /// `Ok(None)` for bare `return` / `Unreachable` termination.
    fn interpret(func: &SsaFunction, step_limit: usize) -> Result<Option<Val>, ExecErr> {
        let mut env: HashMap<SsaRef, Val> = HashMap::new();
        let mut cur = func.entry;
        let mut prev: Option<u32> = None;
        for _ in 0..step_limit {
            let block = func.block(cur).ok_or(ExecErr::NoBlock(cur))?;
            // Phis evaluate against the state at block entry (parallel
            // semantics); since generated phi sources are never defined by
            // other phis in the same block, sequential evaluation is fine.
            for instr in &block.instrs {
                let v = eval(&instr.expr, &env, prev)?;
                if let Some(def) = &instr.def {
                    env.insert(def.clone(), v);
                }
            }
            match &block.term {
                SsaTerm::Return(None) | SsaTerm::Unreachable => return Ok(None),
                SsaTerm::Return(Some(r)) => return Ok(Some(get(&env, r)?)),
                SsaTerm::Jump(t) => {
                    prev = Some(cur);
                    cur = *t;
                }
                SsaTerm::Branch(c, t, f) => {
                    let taken = match get(&env, c)? {
                        Val::B(b) => b,
                        Val::I(v) => v != 0,
                    };
                    prev = Some(cur);
                    cur = if taken { *t } else { *f };
                }
            }
        }
        Err(ExecErr::StepLimit)
    }

    /// Structured random SSA program generator: an entry block, a diamond
    /// (branch on a comparison — sometimes constant-foldable), phi joins,
    /// and optionally a bounded counting loop. Each generated variable is
    /// defined before use on every path, calls and same-block phi chains are
    /// never generated, and the result is valid SSA (unique defs).
    fn random_ssa(rng: &mut Rng) -> SsaFunction {
        let r = |n: u32| SsaRef::new("v", n);
        let mut next = 0u32;
        let mut fresh = || {
            next += 1;
            next - 1
        };
        let mut int_vars: Vec<u32> = Vec::new();

        let mut entry = SsaBlock::new(0);
        for _ in 0..(2 + rng.below(3)) {
            let d = fresh();
            entry
                .instrs
                .push(SsaInstr::assign(r(d), SsaExpr::Const(ConstVal::Int(rng.small_i64()))));
            int_vars.push(d);
        }
        let rand_int_expr = |rng: &mut Rng, vars: &[u32]| -> SsaExpr {
            let a = r(vars[rng.below(vars.len())]);
            let b = r(vars[rng.below(vars.len())]);
            match rng.below(7) {
                0 => SsaExpr::Add(a, b),
                1 => SsaExpr::Sub(a, b),
                2 => SsaExpr::Mul(a, b),
                3 => SsaExpr::And(a, b),
                4 => SsaExpr::Or(a, b),
                5 => SsaExpr::Xor(a, b),
                _ => SsaExpr::Neg(a),
            }
        };
        for _ in 0..rng.below(3) {
            let d = fresh();
            let e = rand_int_expr(rng, &int_vars);
            entry.instrs.push(SsaInstr::assign(r(d), e));
            int_vars.push(d);
        }
        // Branch condition: comparison of two int vars (often both constants,
        // so SCCP + BranchElimination fire).
        let cond = fresh();
        let ca = r(int_vars[rng.below(int_vars.len())]);
        let cb = r(int_vars[rng.below(int_vars.len())]);
        let cmp = if rng.chance(50) {
            SsaExpr::CmpLt(ca, cb)
        } else {
            SsaExpr::CmpEq(ca, cb)
        };
        entry.instrs.push(SsaInstr::assign(r(cond), cmp));
        entry.term = SsaTerm::Branch(r(cond), 1, 2);

        // Two arms. With some probability both arms compute the *same*
        // expression (textually identical) — this stresses GVN.
        let shared = if rng.chance(60) {
            Some(rand_int_expr(rng, &int_vars))
        } else {
            None
        };
        let mut arm_defs = Vec::new();
        let mut arms = Vec::new();
        for arm_id in [1u32, 2u32] {
            let mut b = SsaBlock::new(arm_id);
            let d = fresh();
            let e = shared.clone().unwrap_or_else(|| rand_int_expr(rng, &int_vars));
            b.instrs.push(SsaInstr::assign(r(d), e));
            if rng.chance(50) {
                let d2 = fresh();
                let mut vars2 = int_vars.clone();
                vars2.push(d);
                let e2 = rand_int_expr(rng, &vars2);
                b.instrs.push(SsaInstr::assign(r(d2), e2));
                arm_defs.push((arm_id, d2));
            } else {
                arm_defs.push((arm_id, d));
            }
            b.term = SsaTerm::Jump(3);
            arms.push(b);
        }

        // Join block with a phi over the two arm results.
        let mut join = SsaBlock::new(3);
        let phi_def = fresh();
        join.instrs.push(SsaInstr::assign(
            r(phi_def),
            SsaExpr::Phi(arm_defs.iter().map(|&(p, v)| (p, r(v))).collect()),
        ));
        let mut all_vars = int_vars.clone();
        all_vars.push(phi_def);
        for _ in 0..rng.below(3) {
            let d = fresh();
            let e = rand_int_expr(rng, &all_vars);
            join.instrs.push(SsaInstr::assign(r(d), e));
            all_vars.push(d);
        }

        // Optional bounded loop: join → header(4) with counter phi → body(5)
        // → header; exit(6) returns.
        if rng.chance(40) {
            let init = fresh();
            join.instrs
                .push(SsaInstr::assign(r(init), SsaExpr::Const(ConstVal::Int(0))));
            let limit = fresh();
            join.instrs.push(SsaInstr::assign(
                r(limit),
                SsaExpr::Const(ConstVal::Int(1 + rng.below(4) as i64)),
            ));
            let one = fresh();
            join.instrs
                .push(SsaInstr::assign(r(one), SsaExpr::Const(ConstVal::Int(1))));
            join.term = SsaTerm::Jump(4);

            let mut header = SsaBlock::new(4);
            let i_phi = fresh();
            let i_next = fresh(); // defined in the loop body
            let cond2 = fresh();
            header.instrs.push(SsaInstr::assign(
                r(i_phi),
                SsaExpr::Phi(vec![(3, r(init)), (5, r(i_next))]),
            ));
            header
                .instrs
                .push(SsaInstr::assign(r(cond2), SsaExpr::CmpLt(r(i_phi), r(limit))));
            header.term = SsaTerm::Branch(r(cond2), 5, 6);

            let mut body = SsaBlock::new(5);
            body.instrs
                .push(SsaInstr::assign(r(i_next), SsaExpr::Add(r(i_phi), r(one))));
            body.term = SsaTerm::Jump(4);

            let mut exit = SsaBlock::new(6);
            let ret = fresh();
            exit.instrs.push(SsaInstr::assign(
                r(ret),
                SsaExpr::Add(r(phi_def), r(i_phi)),
            ));
            exit.term = SsaTerm::Return(Some(r(ret)));

            SsaFunction {
                name: "rand".into(),
                blocks: vec![entry, arms.remove(0), arms.remove(0), join, header, body, exit],
                entry: 0,
            }
        } else {
            let ret = *all_vars.last().unwrap();
            join.term = SsaTerm::Return(Some(r(ret)));
            SsaFunction {
                name: "rand".into(),
                blocks: vec![entry, arms.remove(0), arms.remove(0), join],
                entry: 0,
            }
        }
    }

    /// Semantic preservation: the full optimizer pipeline must not change
    /// the function's return value.
    #[test]
    fn optimizer_preserves_semantics() {
        for seed in 1..=400u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xA24B_AED4_963E_E407));
            let func = random_ssa(&mut rng);
            let before = interpret(&func, 10_000)
                .unwrap_or_else(|e| panic!("seed {seed}: generated program invalid: {e:?}"));

            let mut opt_func = func.clone();
            let mut opt = SsaOptimizer::default();
            opt.optimize(&mut opt_func);

            let after = interpret(&opt_func, 10_000).unwrap_or_else(|e| {
                panic!(
                    "seed {seed}: optimized program failed ({e:?})\nORIGINAL:\n{func:#?}\nOPTIMIZED:\n{opt_func:#?}"
                )
            });
            assert_eq!(
                before, after,
                "seed {seed}: optimizer changed semantics\nORIGINAL:\n{func:#?}\nOPTIMIZED:\n{opt_func:#?}"
            );
        }
    }
}
