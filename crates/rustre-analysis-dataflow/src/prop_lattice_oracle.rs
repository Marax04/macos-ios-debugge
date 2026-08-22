//! Randomized LATTICE/ORACLE property tests for the interval lattice
//! (`value_range`), both constant-propagation implementations
//! (`constant_propagation` SCCP and `constant_propagator`), the
//! `ssa_optimizer` SCCP folder, and the `available_expressions` must-analysis.
//!
//! Concretization convention for `ValueRange` is `ValueRange::contains`
//! (dense interval; stride is advisory metadata and is not part of the
//! concretization).  All tests are deterministic (fixed xorshift seeds) so
//! any failure message with a seed reproduces exactly.
#![cfg(test)]

use crate::prop_soundness::Rng;

// ─────────────────────────────────────────────────────────────────────────────
// 1. ValueRange interval lattice
// ─────────────────────────────────────────────────────────────────────────────

mod value_range_props {
    use super::Rng;
    use crate::value_range::ValueRange;

    fn random_range(rng: &mut Rng) -> ValueRange {
        match rng.below(6) {
            0 => ValueRange::top(),
            1 => ValueRange::bottom(),
            2 => ValueRange::constant(rng.small_i64() * 3),
            3 => {
                let a = rng.small_i64() * 5;
                let b = rng.small_i64() * 5;
                ValueRange::interval(a.min(b), a.max(b))
            }
            4 => {
                let a = rng.small_i64() * 4;
                let b = a + (rng.below(40) as i64);
                ValueRange::strided(a, b, (rng.below(4) + 1) as u64)
            }
            _ => {
                // Half-open ranges.
                let a = rng.small_i64() * 7;
                let mut r = ValueRange::top();
                if rng.chance(50) {
                    r.min = Some(a);
                } else {
                    r.max = Some(a);
                }
                r
            }
        }
    }

    /// Sample points to check membership against (covers both bounds of both
    /// operands plus random probes).
    fn sample_points(rng: &mut Rng, a: &ValueRange, b: &ValueRange) -> Vec<i64> {
        let mut pts = Vec::with_capacity(16);
        for r in [a, b] {
            if let Some(lo) = r.min {
                pts.push(lo);
                pts.push(lo + 1);
            }
            if let Some(hi) = r.max {
                pts.push(hi);
                pts.push(hi - 1);
            }
        }
        for _ in 0..8 {
            pts.push(rng.small_i64() * 11);
        }
        pts
    }

    #[test]
    fn join_commutative_and_sound_2000_pairs() {
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let a = random_range(&mut rng);
            let b = random_range(&mut rng);
            let j1 = a.join(&b);
            let j2 = b.join(&a);
            assert_eq!(j1, j2, "seed {seed}: join not commutative: {a} vs {b}");
            for v in sample_points(&mut rng, &a, &b) {
                if a.contains(v) || b.contains(v) {
                    assert!(
                        j1.contains(v),
                        "seed {seed}: join unsound: {v} in operand ({a} / {b}) but not in join {j1}"
                    );
                }
            }
        }
    }

    #[test]
    fn meet_is_lower_bound_2000_pairs() {
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x517C_C1B7_2722_0A95));
            let a = random_range(&mut rng);
            let b = random_range(&mut rng);
            let m = a.meet(&b);
            for v in sample_points(&mut rng, &a, &b) {
                if m.contains(v) {
                    assert!(
                        a.contains(v) && b.contains(v),
                        "seed {seed}: meet not a lower bound: {v} in meet {m} but not in both {a} / {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn widen_over_approximates_join_2000_pairs() {
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xABCD_EF01_2345_6789) | 1);
            let a = random_range(&mut rng);
            let b = random_range(&mut rng);
            let w = a.widen(&b);
            for v in sample_points(&mut rng, &a, &b) {
                if a.contains(v) || b.contains(v) {
                    assert!(
                        w.contains(v),
                        "seed {seed}: widen unsound: {v} in operand ({a} / {b}) but not in widen {w}"
                    );
                }
            }
        }
    }

    #[test]
    fn widen_terminates_in_bounded_steps() {
        // Each bound can only move Some -> None, so any widening chain must
        // stabilize within a handful of steps regardless of the inputs fed in.
        for seed in 1..=500u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x2545_F491) | 1);
            let mut x = random_range(&mut rng);
            let mut changes = 0usize;
            for step in 0..16 {
                let b = random_range(&mut rng);
                let next = x.widen(&b.join(&x));
                if (next.min, next.max) != (x.min, x.max) {
                    changes += 1;
                }
                x = next;
                assert!(
                    changes <= 2,
                    "seed {seed}: widening chain still changing at step {step} ({changes} changes)"
                );
            }
        }
    }

    #[test]
    fn arithmetic_transfer_sound_vs_concrete_sampling() {
        // Build ranges around known concrete inhabitants, then check the
        // abstract op contains the concrete result.  Values kept small so no
        // saturation/overflow ambiguity arises.
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xD134_2543_DE82_EF95) | 1);
            let x = rng.small_i64();
            let y = rng.small_i64();
            let slack_a = rng.below(5) as i64;
            let slack_b = rng.below(5) as i64;
            let a = ValueRange::interval(x - slack_a, x + (rng.below(5) as i64));
            let b = ValueRange::interval(y - slack_b, y + (rng.below(5) as i64));
            assert!(a.contains(x) && b.contains(y), "seed {seed}: bad generator");

            assert!(a.add(&b).contains(x + y), "seed {seed}: add unsound: {x}+{y} not in {a}.add({b})");
            assert!(a.sub(&b).contains(x - y), "seed {seed}: sub unsound: {x}-{y} not in {}", a.sub(&b));
            assert!(a.mul(&b).contains(x * y), "seed {seed}: mul unsound: {x}*{y} not in {}", a.mul(&b));
            assert!(a.negate().contains(-x), "seed {seed}: negate unsound");
            let c = rng.small_i64();
            assert!(a.add_constant(c).contains(x + c), "seed {seed}: add_constant unsound");
            assert!(a.mul_constant(c).contains(x * c), "seed {seed}: mul_constant unsound (c={c})");
            // Branch-constraint restriction: if x survives the constraint the
            // restricted range must still contain it.
            let lo = rng.small_i64();
            if x >= lo {
                assert!(a.restrict_lower(lo).contains(x), "seed {seed}: restrict_lower unsound");
            }
            let hi = rng.small_i64();
            if x <= hi {
                assert!(a.restrict_upper(hi).contains(x), "seed {seed}: restrict_upper unsound");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Flat constant lattices — laws for BOTH implementations
// ─────────────────────────────────────────────────────────────────────────────

mod flat_lattice_laws {
    use super::Rng;
    use crate::constant_propagation::LatticeVal;
    use crate::constant_propagator::ConstLattice;
    use crate::ssa_optimizer::{ConstVal, ScccLat};

    fn random_latticeval(rng: &mut Rng) -> LatticeVal {
        match rng.below(4) {
            0 => LatticeVal::Undefined,
            1 => LatticeVal::Overdefined,
            _ => LatticeVal::Constant(rng.small_i64()),
        }
    }

    fn random_constlattice(rng: &mut Rng) -> ConstLattice {
        match rng.below(4) {
            0 => ConstLattice::Top,
            1 => ConstLattice::Bottom,
            _ => ConstLattice::Const(rng.small_i64()),
        }
    }

    #[test]
    fn latticeval_join_laws() {
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) | 1);
            let c = rng.small_i64();
            let d = rng.small_i64();
            // join(c, c) = c
            assert_eq!(
                LatticeVal::Constant(c).join(&LatticeVal::Constant(c)),
                LatticeVal::Constant(c)
            );
            // join(c1, c2) = Top for c1 != c2
            if c != d {
                assert_eq!(
                    LatticeVal::Constant(c).join(&LatticeVal::Constant(d)),
                    LatticeVal::Overdefined,
                    "seed {seed}"
                );
            }
            // Bottom (Undefined) identity, Top (Overdefined) absorbing.
            let x = random_latticeval(&mut rng);
            assert_eq!(LatticeVal::Undefined.join(&x), x, "seed {seed}");
            assert_eq!(x.join(&LatticeVal::Undefined), x, "seed {seed}");
            assert_eq!(x.join(&LatticeVal::Overdefined), LatticeVal::Overdefined);
            // Commutativity + idempotence + associativity.
            let y = random_latticeval(&mut rng);
            let z = random_latticeval(&mut rng);
            assert_eq!(x.join(&y), y.join(&x), "seed {seed}");
            assert_eq!(x.join(&x), x, "seed {seed}");
            assert_eq!(x.join(&y).join(&z), x.join(&y.join(&z)), "seed {seed}");
            // join is an upper bound w.r.t. leq.
            assert!(x.leq(&x.join(&y)) && y.leq(&x.join(&y)), "seed {seed}");
        }
    }

    #[test]
    fn constlattice_meet_laws() {
        // Note: constant_propagator's `meet` IS the flat-lattice merge (its
        // Top plays the role of "no info yet", Bottom of "conflicting").
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x94D0_49BB_1331_11EB) | 1);
            let c = rng.small_i64();
            let d = rng.small_i64();
            assert_eq!(
                ConstLattice::meet(&ConstLattice::Const(c), &ConstLattice::Const(c)),
                ConstLattice::Const(c)
            );
            if c != d {
                assert_eq!(
                    ConstLattice::meet(&ConstLattice::Const(c), &ConstLattice::Const(d)),
                    ConstLattice::Bottom,
                    "seed {seed}"
                );
            }
            let x = random_constlattice(&mut rng);
            let y = random_constlattice(&mut rng);
            let z = random_constlattice(&mut rng);
            assert_eq!(ConstLattice::meet(&ConstLattice::Top, &x), x, "seed {seed}");
            assert_eq!(ConstLattice::meet(&x, &ConstLattice::Top), x, "seed {seed}");
            assert_eq!(ConstLattice::meet(&x, &ConstLattice::Bottom), ConstLattice::Bottom);
            assert_eq!(ConstLattice::meet(&x, &y), ConstLattice::meet(&y, &x), "seed {seed}");
            assert_eq!(ConstLattice::meet(&x, &x), x, "seed {seed}");
            assert_eq!(
                ConstLattice::meet(&ConstLattice::meet(&x, &y), &z),
                ConstLattice::meet(&x, &ConstLattice::meet(&y, &z)),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn sccc_lat_meet_laws_via_public_behavior() {
        // ScccLat::meet is private; its laws are exercised indirectly through
        // ssa_optimizer SCCP in the differential test below.  Here just pin
        // the ConstVal equality semantics it relies on.
        assert_eq!(ConstVal::Int(3), ConstVal::Int(3));
        assert_ne!(ConstVal::Int(3), ConstVal::Int(4));
        assert_ne!(ConstVal::Int(1), ConstVal::Bool(true));
        let _ = ScccLat::Top; // type is public; keep the import honest
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Differential oracle: both constant propagators + ssa_optimizer SCCP
//    vs a concrete interpreter on random straight-line programs
// ─────────────────────────────────────────────────────────────────────────────

mod const_prop_differential {
    use super::Rng;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::constant_propagation::{
        sparse_conditional_constant_propagation, BinOp, FoldExpr, SccpInstruction,
    };
    use crate::constant_propagator::{
        propagate_constants, BinOpKind, ConstLattice, ConstantPropagator, PropBlock, PropExpr,
        PropStmt, VarId,
    };
    use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};
    use crate::ssa_optimizer::{
        ConstVal, SparseConditionalConst, SsaBlock, SsaExpr, SsaInstr, SsaRef, SsaTerm,
        SsaFunction as OptFunc,
    };

    /// One statement of the abstract random program: var[i] = lhs op rhs,
    /// where operands are either literals or earlier vars.
    #[derive(Clone, Copy, Debug)]
    enum Operand {
        Lit(i64),
        V(usize),
    }
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Op {
        Add,
        Sub,
        Mul,
        Div,
        And,
        Or,
        Xor,
        Shl,
        Shr,
    }
    #[derive(Clone, Copy, Debug)]
    struct Stmt {
        op: Op,
        lhs: Operand,
        rhs: Operand,
    }

    fn random_program(rng: &mut Rng, len: usize) -> Vec<Stmt> {
        let ops = [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::And, Op::Or, Op::Xor, Op::Shl, Op::Shr];
        (0..len)
            .map(|i| {
                let pick = |rng: &mut Rng| {
                    if i > 0 && rng.chance(60) {
                        Operand::V(rng.below(i))
                    } else {
                        Operand::Lit(rng.small_i64())
                    }
                };
                let op = ops[rng.below(ops.len())];
                let lhs = pick(rng);
                // Keep shifts well-defined and identical in every impl.
                let rhs = if matches!(op, Op::Shl | Op::Shr) {
                    Operand::Lit(rng.below(8) as i64)
                } else {
                    pick(rng)
                };
                Stmt { op, lhs, rhs }
            })
            .collect()
    }

    /// Concrete interpreter with i64 wrapping (machine) semantics.
    /// Returns `None` for a var poisoned by division by zero.
    fn concrete_eval(prog: &[Stmt]) -> Vec<Option<i64>> {
        let mut vals: Vec<Option<i64>> = Vec::with_capacity(prog.len());
        for s in prog {
            let read = |o: Operand, vals: &Vec<Option<i64>>| match o {
                Operand::Lit(c) => Some(c),
                Operand::V(i) => vals[i],
            };
            let v = match (read(s.lhs, &vals), read(s.rhs, &vals)) {
                (Some(a), Some(b)) => match s.op {
                    Op::Add => Some(a.wrapping_add(b)),
                    Op::Sub => Some(a.wrapping_sub(b)),
                    Op::Mul => Some(a.wrapping_mul(b)),
                    Op::Div => (b != 0).then(|| a.wrapping_div(b)),
                    Op::And => Some(a & b),
                    Op::Or => Some(a | b),
                    Op::Xor => Some(a ^ b),
                    Op::Shl => Some(a.wrapping_shl(b as u32)),
                    Op::Shr => Some(a.wrapping_shr(b as u32)),
                },
                _ => None,
            };
            vals.push(v);
        }
        vals
    }

    /// `precise[i]`: `v_i` is defined, comfortably inside i64 (so checked and
    /// wrapping semantics coincide), and all its transitive var operands are
    /// precise too — on these, every impl must find the exact constant.
    fn precise_mask(prog: &[Stmt], vals: &[Option<i64>]) -> Vec<bool> {
        let mut precise = vec![false; prog.len()];
        for (i, s) in prog.iter().enumerate() {
            let ok_operand = |o: Operand, precise: &Vec<bool>| match o {
                Operand::Lit(_) => true,
                Operand::V(j) => precise[j],
            };
            precise[i] = vals[i].is_some_and(|x| x.abs() < i64::MAX / 4)
                && ok_operand(s.lhs, &precise)
                && ok_operand(s.rhs, &precise);
        }
        precise
    }

    fn run_propagator(prog: &[Stmt]) -> Vec<ConstLattice> {
        let to_expr = |o: Operand| match o {
            Operand::Lit(c) => PropExpr::Literal(c),
            Operand::V(i) => PropExpr::Var(VarId::new(i as u32)),
        };
        let kind = |op: Op| match op {
            Op::Add => BinOpKind::Add,
            Op::Sub => BinOpKind::Sub,
            Op::Mul => BinOpKind::Mul,
            Op::Div => BinOpKind::Div,
            Op::And => BinOpKind::And,
            Op::Or => BinOpKind::Or,
            Op::Xor => BinOpKind::Xor,
            Op::Shl => BinOpKind::Shl,
            Op::Shr => BinOpKind::Shr,
        };
        let stmts = prog
            .iter()
            .enumerate()
            .map(|(i, s)| {
                PropStmt::assign(
                    VarId::new(i as u32),
                    PropExpr::BinOp(kind(s.op), Box::new(to_expr(s.lhs)), Box::new(to_expr(s.rhs))),
                )
            })
            .collect();
        let blocks = vec![PropBlock { id: 0, stmts, succs: vec![] }];
        let result = propagate_constants(&blocks, 0, &[vec![]], &ConstantPropagator::new());
        (0..prog.len())
            .map(|i| result.value_out(0, VarId::new(i as u32)))
            .collect()
    }

    fn sv(i: usize) -> SsaVar {
        SsaVar::new(Var::new(format!("v{i}")), 0)
    }

    fn run_sccp(prog: &[Stmt]) -> Vec<Option<i64>> {
        let to_expr = |o: Operand| match o {
            Operand::Lit(c) => FoldExpr::Imm(c),
            Operand::V(i) => FoldExpr::Var(sv(i)),
        };
        let bop = |op: Op| match op {
            Op::Add => BinOp::Add,
            Op::Sub => BinOp::Sub,
            Op::Mul => BinOp::Mul,
            Op::Div => BinOp::Div,
            Op::And => BinOp::And,
            Op::Or => BinOp::Or,
            Op::Xor => BinOp::Xor,
            Op::Shl => BinOp::Shl,
            Op::Shr => BinOp::Shr,
        };
        let cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
        let mut instrs = Vec::new();
        let mut sccp = Vec::new();
        for (i, s) in prog.iter().enumerate() {
            let mut instr = Instruction::new(i, Some(Var::new(format!("v{i}"))), vec![]);
            instr.ssa_def = Some(sv(i));
            let mut uses = Vec::new();
            for o in [s.lhs, s.rhs] {
                if let Operand::V(j) = o {
                    uses.push(sv(j));
                }
            }
            instr.ssa_uses = uses;
            sccp.push(SccpInstruction {
                base: instr.clone(),
                expr: Some(FoldExpr::Binop {
                    op: bop(s.op),
                    lhs: Box::new(to_expr(s.lhs)),
                    rhs: Box::new(to_expr(s.rhs)),
                }),
                is_branch: false,
                branch_cond: None,
                branch_targets: None,
            });
            instrs.push(instr);
        }
        let func = SsaFunction::new(cfg, &[instrs]);
        let result = sparse_conditional_constant_propagation(&func, &[sccp]);
        (0..prog.len()).map(|i| result.constant_of(&sv(i))).collect()
    }

    fn run_ssa_opt(prog: &[Stmt]) -> Vec<Option<i64>> {
        // ssa_optimizer's SCCP only folds Add/Sub/Mul (plus compares); other
        // ops are conservatively Bottom.  Feed it the whole program anyway:
        // soundness must hold regardless.
        let r = |i: usize| SsaRef::new(format!("v{i}"), 0);
        let mut block = SsaBlock::new(0);
        let mut lit_counter = prog.len();
        for (i, s) in prog.iter().enumerate() {
            // Materialize literal operands as extra defs (the IR's binops take
            // refs, not immediates).
            let mut operand = |o: Operand, block: &mut SsaBlock| match o {
                Operand::V(j) => r(j),
                Operand::Lit(c) => {
                    let name = SsaRef::new(format!("lit{lit_counter}"), 0);
                    lit_counter += 1;
                    block
                        .instrs
                        .push(SsaInstr::assign(name.clone(), SsaExpr::Const(ConstVal::Int(c))));
                    name
                }
            };
            let l = operand(s.lhs, &mut block);
            let rr = operand(s.rhs, &mut block);
            let expr = match s.op {
                Op::Add => SsaExpr::Add(l, rr),
                Op::Sub => SsaExpr::Sub(l, rr),
                Op::Mul => SsaExpr::Mul(l, rr),
                // Not foldable by this impl; still legal IR (opaque call).
                _ => SsaExpr::Call { name: "opaque".into(), args: vec![l, rr] },
            };
            block.instrs.push(SsaInstr::assign(r(i), expr));
        }
        block.term = SsaTerm::Return(None);
        let mut func = OptFunc { name: "t".into(), blocks: vec![block], entry: 0 };
        let consts = SparseConditionalConst::default().run(&mut func);
        (0..prog.len())
            .map(|i| match consts.get(&r(i)) {
                Some(ConstVal::Int(c)) => Some(*c),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn straight_line_differential_2000_programs() {
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x2B99_2DDF_A232_49D6) | 1);
            let len = 1 + rng.below(8);
            let prog = random_program(&mut rng, len);
            let oracle = concrete_eval(&prog);
            let precise = precise_mask(&prog, &oracle);
            let ssa_opt_foldable: Vec<bool> = prog
                .iter()
                .map(|s| matches!(s.op, Op::Add | Op::Sub | Op::Mul))
                .collect();

            let prop = run_propagator(&prog);
            let sccp = run_sccp(&prog);
            let opt = run_ssa_opt(&prog);

            for i in 0..prog.len() {
                // SOUNDNESS: any reported constant must equal the concrete value.
                if let ConstLattice::Const(c) = prop[i] {
                    assert_eq!(
                        Some(c), oracle[i],
                        "seed {seed}: constant_propagator wrong at v{i}: {prog:?}"
                    );
                }
                if let Some(c) = sccp[i] {
                    assert_eq!(
                        Some(c), oracle[i],
                        "seed {seed}: constant_propagation (SCCP) wrong at v{i}: {prog:?}"
                    );
                }
                if let Some(c) = opt[i] {
                    assert_eq!(
                        Some(c), oracle[i],
                        "seed {seed}: ssa_optimizer SCCP wrong at v{i}: {prog:?}"
                    );
                }
                // CROSS-IMPL: two impls both claiming a constant must agree.
                if let (ConstLattice::Const(a), Some(b)) = (&prop[i], sccp[i]) {
                    assert_eq!(*a, b, "seed {seed}: impls diverge at v{i}: {prog:?}");
                }
                // PRECISION (differential): on defined, overflow-free values
                // both main impls must actually find the constant — a Bottom
                // here would be a silent divergence.
                if precise[i] {
                    assert_eq!(
                        prop[i].as_const(),
                        oracle[i],
                        "seed {seed}: constant_propagator lost a foldable constant at v{i}: {prog:?}"
                    );
                    assert_eq!(
                        sccp[i], oracle[i],
                        "seed {seed}: SCCP lost a foldable constant at v{i}: {prog:?}"
                    );
                    // ssa_optimizer folds only Add/Sub/Mul chains whose
                    // operands it also folded.
                    let operands_folded = [prog[i].lhs, prog[i].rhs].iter().all(|o| match o {
                        Operand::Lit(_) => true,
                        Operand::V(j) => opt[*j].is_some(),
                    });
                    if ssa_opt_foldable[i] && operands_folded {
                        assert_eq!(
                            opt[i], oracle[i],
                            "seed {seed}: ssa_optimizer lost a foldable constant at v{i}: {prog:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn diamond_merge_differential_500_programs() {
        // b0 -> {b1, b2} -> b3.  Each arm assigns v0 a constant; the merged
        // value must be sound in both impls vs both concrete executions.
        for seed in 1..=500u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x9E6C_63D0_876A_368B) | 1);
            let c1 = rng.small_i64();
            let c2 = if rng.chance(40) { c1 } else { rng.small_i64() };

            // constant_propagator version.
            let blocks = vec![
                PropBlock { id: 0, stmts: vec![], succs: vec![1, 2] },
                PropBlock {
                    id: 1,
                    stmts: vec![PropStmt::assign(VarId::new(0), PropExpr::Literal(c1))],
                    succs: vec![3],
                },
                PropBlock {
                    id: 2,
                    stmts: vec![PropStmt::assign(VarId::new(0), PropExpr::Literal(c2))],
                    succs: vec![3],
                },
                PropBlock { id: 3, stmts: vec![], succs: vec![] },
            ];
            let preds = vec![vec![], vec![0], vec![0], vec![1, 2]];
            let res = propagate_constants(&blocks, 0, &preds, &ConstantPropagator::new());
            match res.value_in(3, VarId::new(0)) {
                ConstLattice::Const(c) => {
                    assert!(
                        c == c1 && c == c2,
                        "seed {seed}: propagator claims Const({c}) at merge of {c1}/{c2}"
                    );
                }
                _ => assert_ne!(c1, c2, "seed {seed}: propagator lost equal-arm constant {c1}"),
            }

            // SCCP version with a φ at the merge block.
            use crate::ssa::PhiNode;
            let cfg = Cfg::new(
                4,
                vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]],
                BBId(0),
                BBId(3),
            );
            let mk = |idx: usize, name: &str| {
                let mut i = Instruction::new(idx, Some(Var::new(name)), vec![]);
                i.ssa_def = Some(SsaVar::new(Var::new(name), 0));
                i
            };
            // Block 0 needs at least one instruction: SCCP only enqueues a
            // block's CFG successors after processing its last instruction.
            let i0 = mk(0, "d0");
            let i1 = mk(1, "a1");
            let i2 = mk(2, "a2");
            let mut phi = PhiNode::new(Var::new("x"), 2);
            phi.result = Some(SsaVar::new(Var::new("x"), 0));
            phi.args = vec![
                Some(SsaVar::new(Var::new("a1"), 0)),
                Some(SsaVar::new(Var::new("a2"), 0)),
            ];
            let mut func = SsaFunction::new(
                cfg,
                &[vec![i0.clone()], vec![i1.clone()], vec![i2.clone()], vec![]],
            );
            func.blocks[3].phis.push(phi);
            let mk_sccp = |base: Instruction, c: i64| SccpInstruction {
                base,
                expr: Some(FoldExpr::Imm(c)),
                is_branch: false,
                branch_cond: None,
                branch_targets: None,
            };
            let sccp_instrs = vec![
                vec![mk_sccp(i0, 0)],
                vec![mk_sccp(i1, c1)],
                vec![mk_sccp(i2, c2)],
                vec![],
            ];
            let result = sparse_conditional_constant_propagation(&func, &sccp_instrs);
            if let Some(c) = result.constant_of(&SsaVar::new(Var::new("x"), 0)) {
                assert!(
                    c == c1 && c == c2,
                    "seed {seed}: SCCP claims φ = Const({c}) at merge of {c1}/{c2}"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Available expressions — must-analysis vs path-enumeration oracle
// ─────────────────────────────────────────────────────────────────────────────

mod available_expressions_oracle {
    use super::Rng;
    use crate::available_expressions::{
        compute_available, AvailBlock, AvailStmt, AvailableExpressions, BinOpKind, Expr, ExprId,
        ExprKind, VarId,
    };
    use std::collections::HashSet;

    /// Simulate the per-statement gen/kill semantics along one concrete path.
    /// Semantics (the ground truth of the analysis' statement model): a
    /// definition of `v` kills every expression using `v`; a statement that
    /// computes `e` makes it available afterwards, unless `e` uses the very
    /// variable the same statement just redefined.
    fn simulate_path(
        path: &[usize],
        blocks: &[AvailBlock],
        universe: &[Expr],
    ) -> HashSet<ExprId> {
        let mut avail: HashSet<ExprId> = HashSet::new();
        for &bid in path {
            for stmt in &blocks[bid].stmts {
                if let Some(def) = stmt.def {
                    avail.retain(|id| {
                        !universe.iter().any(|e| e.id == *id && e.uses_var(def))
                    });
                }
                if let Some(eid) = stmt.expr_id {
                    let self_ref = stmt.def.is_some_and(|def| {
                        universe.iter().any(|e| e.id == eid && e.uses_var(def))
                    });
                    if !self_ref {
                        avail.insert(eid);
                    }
                }
            }
        }
        avail
    }

    /// All entry→target paths in a DAG, where the path lists the blocks
    /// *before* target (i.e. the state on entry to target).
    fn enumerate_paths(
        succs: &[Vec<usize>],
        entry: usize,
        target: usize,
        prefix: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if entry == target {
            out.push(prefix.clone());
            return;
        }
        prefix.push(entry);
        for &s in &succs[entry] {
            enumerate_paths(succs, s, target, prefix, out);
        }
        prefix.pop();
    }

    #[test]
    fn must_analysis_sound_vs_path_enumeration_300_cfgs() {
        for seed in 1..=300u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xC2B2_AE3D_27D4_EB4F) | 1);
            let n_vars = 2 + rng.below(4);
            // Universe of binop expressions over the vars.
            let n_exprs = 2 + rng.below(5);
            let ops = [BinOpKind::Add, BinOpKind::Sub, BinOpKind::Mul, BinOpKind::Xor];
            let universe: Vec<Expr> = (0..n_exprs)
                .map(|i| {
                    Expr::new(
                        ExprId::new(i as u32),
                        ExprKind::BinOp {
                            op: ops[rng.below(ops.len())],
                            lhs: VarId::new(rng.below(n_vars) as u32),
                            rhs: VarId::new(rng.below(n_vars) as u32),
                        },
                    )
                })
                .collect();

            // Random DAG: block j>0 gets a predecessor among 0..j (all
            // reachable), plus occasional extra forward edges.
            let n = 3 + rng.below(4);
            let mut succs: Vec<Vec<usize>> = vec![vec![]; n];
            for j in 1..n {
                let p = rng.below(j);
                succs[p].push(j);
                if rng.chance(35) {
                    let p2 = rng.below(j);
                    if !succs[p2].contains(&j) {
                        succs[p2].push(j);
                    }
                }
            }
            let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
            for (b, ss) in succs.iter().enumerate() {
                for &s in ss {
                    preds[s].push(b);
                }
            }

            let blocks: Vec<AvailBlock> = (0..n)
                .map(|id| {
                    let n_stmts = rng.below(4);
                    let stmts = (0..n_stmts)
                        .map(|_| match rng.below(3) {
                            0 => AvailStmt::define(VarId::new(rng.below(n_vars) as u32)),
                            1 => {
                                let e = rng.below(n_exprs);
                                AvailStmt::assign(
                                    VarId::new(rng.below(n_vars) as u32),
                                    ExprId::new(e as u32),
                                    vec![],
                                )
                            }
                            _ => AvailStmt::read_only(vec![VarId::new(rng.below(n_vars) as u32)]),
                        })
                        .collect();
                    AvailBlock { id, stmts, succs: succs[id].clone() }
                })
                .collect();

            let analysis = AvailableExpressions::new(universe.clone());
            let result = compute_available(&blocks, 0, &preds, &analysis);

            for target in 0..n {
                let mut paths = Vec::new();
                enumerate_paths(&succs, 0, target, &mut Vec::new(), &mut paths);
                if paths.is_empty() {
                    continue; // unreachable — no claim to check
                }
                // Oracle: available on entry iff available along EVERY path.
                let mut oracle: Option<HashSet<ExprId>> = None;
                for p in &paths {
                    let s = simulate_path(p, &blocks, &universe);
                    oracle = Some(match oracle {
                        None => s,
                        Some(acc) => acc.intersection(&s).copied().collect(),
                    });
                }
                let oracle = oracle.unwrap();
                let reported = &result.in_sets[target].available;
                for id in reported {
                    assert!(
                        oracle.contains(id),
                        "seed {seed}: block {target}: expression {id} reported available \
                         but NOT available on every path; paths={paths:?}"
                    );
                }
            }
        }
    }
}
