//! Property-based / randomized soundness tests for the analyses NOT covered by
//! [`crate::prop_soundness`].
//!
//! Self-contained (a small xorshift PRNG, no external dev-deps). Each analysis
//! is cross-checked against an *independent* reference:
//!
//! * `constant_propagation` (Wegman-Zadeck SCCP over `crate::ssa`) — every
//!   `Constant(c)` claim is checked against brute-force concrete execution of
//!   random SSA programs (straight-line + diamonds with phis), over many random
//!   inputs. A claimed constant that any concrete run contradicts is a bug.
//! * `value_range` — the abstract interval/range domain must *contain every
//!   concrete value*: for random small ranges we enumerate all members and
//!   assert `add`/`sub`/`mul`/`negate`/`join`/`meet` over-approximate soundly.
//!   The whole-function `analyze_value_ranges` is checked under copy/blend
//!   semantics.
//! * `live_ranges` — a variable reported *dead* (not live-out) must genuinely
//!   have no downstream use, cross-checked against an independent DFS-reachability
//!   reference on random CFGs.
//! * `pointer_analysis` (Andersen) & `alias_analysis` — the worklist solver's
//!   points-to result is compared against a naive least-fixpoint reference;
//!   may-alias soundness (`must ⇒ may`, no genuinely-aliasing pair dropped,
//!   `NoAlias ⇒ genuinely disjoint`) is asserted.

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
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    /// Small signed value in `-10..=10`.
    pub fn small_i64(&mut self) -> i64 {
        (self.next_u64() % 21) as i64 - 10
    }
}

/// Random DAG-plus-optional-back-edges CFG skeleton: returns succs per block.
/// Every block `i > 0` gets a predecessor `< i` so all blocks are reachable.
fn random_cfg(rng: &mut Rng, n: usize, allow_back_edges: bool) -> Vec<Vec<usize>> {
    let mut succs: Vec<Vec<usize>> = vec![vec![]; n];
    for j in 1..n {
        let p = rng.below(j);
        succs[p].push(j);
    }
    for i in 0..n {
        if i + 1 < n && rng.chance(35) {
            let j = i + 1 + rng.below(n - i - 1);
            if !succs[i].contains(&j) && succs[i].len() < 2 {
                succs[i].push(j);
            }
        }
    }
    if allow_back_edges && n > 1 && rng.chance(50) {
        let i = 1 + rng.below(n - 1);
        let j = rng.below(i + 1);
        if !succs[i].contains(&j) && succs[i].len() < 2 {
            succs[i].push(j);
        }
    }
    succs
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 1: value_range — abstract domain soundness (contains every concrete value)
// ═════════════════════════════════════════════════════════════════════════════

mod value_range_soundness {
    use super::Rng;
    use crate::value_range::ValueRange;

    /// A random *dense* (stride-1) bounded range over small ints so we can
    /// enumerate every member and so arithmetic never saturates.
    fn rand_range(rng: &mut Rng) -> ValueRange {
        let a = rng.small_i64();
        let b = rng.small_i64();
        ValueRange::interval(a, b) // interval() normalizes lo<=hi
    }

    fn members(r: &ValueRange) -> Vec<i64> {
        let lo = r.min.unwrap();
        let hi = r.max.unwrap();
        (lo..=hi).collect()
    }

    /// Soundness: every concrete result of an operation lies in the abstract
    /// result. This is the defining property of a sound abstract domain.
    #[test]
    fn arithmetic_and_lattice_ops_over_approximate() {
        for seed in 1..=2000u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let a = rand_range(&mut rng);
            let b = rand_range(&mut rng);
            let ma = members(&a);
            let mb = members(&b);

            let add = a.add(&b);
            let sub = a.sub(&b);
            let mul = a.mul(&b);
            let neg = a.negate();
            let join = a.join(&b);
            let meet = a.meet(&b);

            for &x in &ma {
                assert!(neg.contains(-x), "seed {seed}: negate dropped {}", -x);
                assert!(join.contains(x), "seed {seed}: join dropped lhs {x}");
                for &y in &mb {
                    assert!(add.contains(x + y), "seed {seed}: {x}+{y} not in {add}");
                    assert!(sub.contains(x - y), "seed {seed}: {x}-{y} not in {sub}");
                    assert!(mul.contains(x * y), "seed {seed}: {x}*{y} not in {mul}");
                }
            }
            for &y in &mb {
                assert!(join.contains(y), "seed {seed}: join dropped rhs {y}");
            }
            // meet is a lower bound: everything it contains is in BOTH, and
            // every value in both a and b is retained.
            if !meet.is_bottom() {
                for m in members(&meet) {
                    assert!(
                        a.contains(m) && b.contains(m),
                        "seed {seed}: meet {meet} contains {m} not in both operands"
                    );
                }
            }
            for &x in &ma {
                if b.contains(x) {
                    assert!(
                        meet.contains(x),
                        "seed {seed}: meet dropped shared value {x} (a={a}, b={b})"
                    );
                }
            }
        }
    }

    /// `restrict_lower`/`restrict_upper` must keep exactly the members that
    /// satisfy the added bound (they are meets with a half-line — must be exact,
    /// never drop a satisfying value).
    #[test]
    fn restrict_keeps_satisfying_members() {
        for seed in 1..=1500u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xD134_2543_DE82_EF95) | 1);
            let r = rand_range(&mut rng);
            let bound = rng.small_i64();
            let lo_restricted = r.restrict_lower(bound);
            let hi_restricted = r.restrict_upper(bound);
            for x in members(&r) {
                if x >= bound && !lo_restricted.is_bottom() {
                    assert!(
                        lo_restricted.contains(x),
                        "seed {seed}: restrict_lower({bound}) dropped {x}"
                    );
                }
                if x <= bound && !hi_restricted.is_bottom() {
                    assert!(
                        hi_restricted.contains(x),
                        "seed {seed}: restrict_upper({bound}) dropped {x}"
                    );
                }
            }
        }
    }

    /// Whole-function analysis soundness under copy/blend semantics: a def with
    /// one use is a copy; a def with several uses evaluates to the value of one
    /// of its operands (a "blend"/select); a def with no uses is unconstrained
    /// (the analysis returns ⊤, which contains everything). Under those
    /// semantics the computed range must contain the concrete value.
    #[test]
    fn analyze_value_ranges_contains_concrete_under_blend_semantics() {
        use crate::cfg_dom::{BBId, Cfg};
        use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};
        use crate::value_range::analyze_value_ranges;
        use std::collections::HashMap;

        for seed in 1..=400u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
            let n_instr = 3 + rng.below(8);
            let mut instrs: Vec<Instruction> = Vec::new();
            let sv = |i: usize| SsaVar::new(Var::new(format!("v{i}")), 0);
            // Track which defs are "seeded" (no uses -> top -> arbitrary conc).
            for i in 0..n_instr {
                let uses: Vec<SsaVar> = if i == 0 || rng.chance(25) {
                    vec![] // seed: analyzer -> top
                } else {
                    let k = 1 + rng.below(3.min(i));
                    (0..k).map(|_| sv(rng.below(i))).collect()
                };
                let mut ins = Instruction::new(i, Some(Var::new(format!("v{i}"))), vec![]);
                ins.ssa_def = Some(sv(i));
                ins.ssa_uses = uses;
                instrs.push(ins);
            }
            let cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
            let func = SsaFunction::new(cfg, &[instrs.clone()]);
            let ranges = analyze_value_ranges(&func);

            // Multiple concrete runs; each run picks blend choices + seeds.
            for trial in 0..6u64 {
                let mut cr = Rng::new(seed ^ (trial.wrapping_mul(0x1000_0001) | 1));
                let mut env: HashMap<usize, i64> = HashMap::new();
                for (i, ins) in instrs.iter().enumerate() {
                    let val = if ins.ssa_uses.is_empty() {
                        cr.small_i64() // seed: any value (analyzer says top)
                    } else {
                        // blend: value of one operand.
                        let pick = &ins.ssa_uses[cr.below(ins.ssa_uses.len())];
                        let idx: usize = pick.base.0[1..].parse().unwrap();
                        env[&idx]
                    };
                    env.insert(i, val);
                }
                for (i, val) in &env {
                    if let Some(r) = ranges.get(&sv(*i)) {
                        assert!(
                            r.contains(*val),
                            "seed {seed} trial {trial}: v{i}={val} not in computed range {r}"
                        );
                    }
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 2: live_ranges — a "dead" variable must be genuinely dead
// ═════════════════════════════════════════════════════════════════════════════

mod liveness_soundness {
    use super::{random_cfg, Rng};
    use crate::cfg_dom::{BBId, Cfg};
    use crate::live_ranges::compute_live_ranges;
    use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};
    use std::collections::{HashMap, HashSet};

    const NVARS: usize = 4;

    fn base(i: usize) -> Var {
        Var::new(format!("x{i}"))
    }

    /// A program: per-block list of (uses, def) pairs over base vars.
    struct Prog {
        succs: Vec<Vec<usize>>,
        blocks: Vec<Vec<(Vec<usize>, Option<usize>)>>,
    }

    fn random_prog(rng: &mut Rng) -> Prog {
        let n = 2 + rng.below(5);
        let bk = rng.chance(50);
        let succs = random_cfg(rng, n, bk);
        let mut blocks = Vec::new();
        for _ in 0..n {
            let mut instrs = Vec::new();
            for _ in 0..rng.below(4) {
                let nu = rng.below(3);
                let uses: Vec<usize> = (0..nu).map(|_| rng.below(NVARS)).collect();
                let def = if rng.chance(70) { Some(rng.below(NVARS)) } else { None };
                instrs.push((uses, def));
            }
            blocks.push(instrs);
        }
        Prog { succs, blocks }
    }

    fn to_ssa(prog: &Prog) -> SsaFunction {
        let n = prog.blocks.len();
        let succs: Vec<Vec<BBId>> = prog
            .succs
            .iter()
            .map(|s| s.iter().map(|&b| BBId(b)).collect())
            .collect();
        let exit = BBId(n - 1);
        let cfg = Cfg::new(n, succs, BBId(0), exit);
        let per_block: Vec<Vec<Instruction>> = prog
            .blocks
            .iter()
            .enumerate()
            .map(|(bi, instrs)| {
                instrs
                    .iter()
                    .enumerate()
                    .map(|(ii, (uses, def))| {
                        let mut ins = Instruction::new(bi * 100 + ii, None, vec![]);
                        ins.ssa_uses = uses.iter().map(|&u| SsaVar::new(base(u), 0)).collect();
                        ins.ssa_def = def.map(|d| SsaVar::new(base(d), 0));
                        ins
                    })
                    .collect()
            })
            .collect();
        SsaFunction::new(cfg, &per_block)
    }

    /// Independent reference: is base var `v` genuinely live at the *entry* of
    /// block `b`? DFS forward reachability of a use before a redefinition,
    /// tracking visited blocks so cycles terminate (liveness is a "may"/exists
    /// property, so once a block is visited without killing `v`, revisiting adds
    /// nothing).
    fn ref_live_in(prog: &Prog, v: usize, b: usize, visited: &mut HashSet<usize>) -> bool {
        if !visited.insert(b) {
            return false;
        }
        for (uses, def) in &prog.blocks[b] {
            if uses.contains(&v) {
                return true; // upward-exposed use
            }
            if *def == Some(v) {
                return false; // killed before any use on this block
            }
        }
        // Fell through the block without use or kill: continue into successors.
        for &s in &prog.succs[b] {
            if ref_live_in(prog, v, s, visited) {
                return true;
            }
        }
        false
    }

    fn ref_live_out(prog: &Prog, v: usize, b: usize) -> bool {
        for &s in &prog.succs[b] {
            let mut visited = HashSet::new();
            if ref_live_in(prog, v, s, &mut visited) {
                return true;
            }
        }
        false
    }

    #[test]
    fn reported_dead_variable_is_genuinely_dead() {
        for seed in 1..=1500u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xC2B2_AE3D_27D4_EB4F) | 1);
            let prog = random_prog(&mut rng);
            let func = to_ssa(&prog);
            let lr = compute_live_ranges(&func);

            for b in 0..prog.blocks.len() {
                let out: HashSet<usize> = lr.live_out[b]
                    .iter()
                    .map(|v| v.0[1..].parse::<usize>().unwrap())
                    .collect();
                let inn: HashSet<usize> = lr.live_in[b]
                    .iter()
                    .map(|v| v.0[1..].parse::<usize>().unwrap())
                    .collect();
                for v in 0..NVARS {
                    let ref_out = ref_live_out(&prog, v, b);
                    let ref_in = {
                        let mut vis = HashSet::new();
                        ref_live_in(&prog, v, b, &mut vis)
                    };
                    // Soundness: a variable the analysis calls dead must truly
                    // have no downstream use.
                    if !out.contains(&v) {
                        assert!(
                            !ref_out,
                            "seed {seed}: x{v} reported DEAD at exit of block {b} but is \
                             genuinely live (a downstream use is reachable)"
                        );
                    }
                    if !inn.contains(&v) {
                        assert!(
                            !ref_in,
                            "seed {seed}: x{v} reported DEAD at entry of block {b} but is \
                             genuinely live"
                        );
                    }
                    // Exactness (precision): this is an exact analysis, so the
                    // converse should hold too.
                    assert_eq!(
                        out.contains(&v),
                        ref_out,
                        "seed {seed}: live_out mismatch for x{v} at block {b}"
                    );
                    assert_eq!(
                        inn.contains(&v),
                        ref_in,
                        "seed {seed}: live_in mismatch for x{v} at block {b}"
                    );
                }
            }
            let _ = HashMap::<usize, usize>::new();
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 3: pointer_analysis (Andersen) — solver vs naive least fixpoint
// ═════════════════════════════════════════════════════════════════════════════

mod andersen_soundness {
    use super::Rng;
    use crate::pointer_analysis::{
        query_alias, AliasResult, AndersenPointerAnalysis, Constraint, VarId,
    };
    use std::collections::{HashMap, HashSet};

    fn random_constraints(rng: &mut Rng, nvars: u32) -> Vec<Constraint> {
        let n = 2 + rng.below(10);
        let mut cs = Vec::new();
        let rv = |rng: &mut Rng| VarId::new(rng.below(nvars as usize) as u32);
        // Always seed a few AddressOf so points-to sets are non-trivial.
        for _ in 0..(1 + rng.below(3)) {
            cs.push(Constraint::AddressOf { lhs: rv(rng), rhs: rv(rng) });
        }
        for _ in 0..n {
            let lhs = rv(rng);
            let rhs = rv(rng);
            cs.push(match rng.below(4) {
                0 => Constraint::AddressOf { lhs, rhs },
                1 => Constraint::Assign { lhs, rhs },
                2 => Constraint::Load { lhs, rhs },
                _ => Constraint::Store { lhs, rhs },
            });
        }
        cs
    }

    /// Naive least-fixpoint reference Andersen solver.
    fn reference_solve(cs: &[Constraint], nvars: u32) -> HashMap<u32, HashSet<u32>> {
        let mut pts: HashMap<u32, HashSet<u32>> = (0..nvars).map(|v| (v, HashSet::new())).collect();
        loop {
            let mut changed = false;
            let add = |pts: &mut HashMap<u32, HashSet<u32>>, v: u32, t: u32, ch: &mut bool| {
                if pts.entry(v).or_default().insert(t) {
                    *ch = true;
                }
            };
            for c in cs {
                match *c {
                    Constraint::AddressOf { lhs, rhs } => add(&mut pts, lhs.0, rhs.0, &mut changed),
                    Constraint::Assign { lhs, rhs } => {
                        let src: Vec<u32> = pts[&rhs.0].iter().copied().collect();
                        for t in src {
                            add(&mut pts, lhs.0, t, &mut changed);
                        }
                    }
                    Constraint::Load { lhs, rhs } => {
                        let rs: Vec<u32> = pts[&rhs.0].iter().copied().collect();
                        for r in rs {
                            let inner: Vec<u32> =
                                pts.get(&r).into_iter().flatten().copied().collect();
                            for t in inner {
                                add(&mut pts, lhs.0, t, &mut changed);
                            }
                        }
                    }
                    Constraint::Store { lhs, rhs } => {
                        let ls: Vec<u32> = pts[&lhs.0].iter().copied().collect();
                        let src: Vec<u32> = pts[&rhs.0].iter().copied().collect();
                        for r in ls {
                            for &t in &src {
                                add(&mut pts, r, t, &mut changed);
                            }
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        pts
    }

    #[test]
    fn worklist_solver_matches_naive_fixpoint() {
        let nvars = 6u32;
        for seed in 1..=1500u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
            let cs = random_constraints(&mut rng, nvars);
            let reference = reference_solve(&cs, nvars);

            let mut a = AndersenPointerAnalysis::new();
            a.add_all(cs.iter().copied());
            let pts = a.analyze();

            for v in 0..nvars {
                let got: HashSet<u32> = pts.pts(VarId::new(v)).iter().map(|x| x.0).collect();
                let want = &reference[&v];
                // Soundness: solver must not MISS any points-to fact.
                assert!(
                    want.is_subset(&got),
                    "seed {seed}: v{v} solver pts {got:?} misses reference {want:?}"
                );
                // Precision: Andersen is exact for these constraints.
                assert_eq!(
                    &got, want,
                    "seed {seed}: v{v} solver pts {got:?} != reference {want:?}"
                );
            }

            // Alias-query soundness against the reference points-to sets.
            for p in 0..nvars {
                for q in 0..nvars {
                    let inter_ref = !reference[&p].is_disjoint(&reference[&q]);
                    match query_alias(&pts, VarId::new(p), VarId::new(q)) {
                        AliasResult::NoAlias => assert!(
                            !inter_ref,
                            "seed {seed}: NoAlias(v{p},v{q}) but they genuinely share an object"
                        ),
                        AliasResult::MustAlias => assert!(
                            inter_ref,
                            "seed {seed}: MustAlias(v{p},v{q}) but points-to sets are disjoint"
                        ),
                        AliasResult::MayAlias => {}
                    }
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 4: alias_analysis — Anderson copy/addressof fragment soundness
// ═════════════════════════════════════════════════════════════════════════════

mod alias_analysis_soundness {
    use super::Rng;
    use crate::alias_analysis::{AliasAnalysis, ObjId, PtrVar};
    use std::collections::{HashMap, HashSet};

    /// Build a random analysis using only `AddressOf` + Copy constraints (the
    /// fragment whose ground truth is a simple copy-closure), and record the
    /// same constraints for the reference solver.
    struct Built {
        aa: AliasAnalysis,
        addr: Vec<(u32, u32)>, // (var, obj)
        copies: Vec<(u32, u32)>, // (dest, src)
        vars: Vec<u32>,
    }

    fn build(rng: &mut Rng) -> Built {
        let mut aa = AliasAnalysis::new();
        let nvars = 3 + rng.below(5);
        let nobjs = 2 + rng.below(4);
        let vars: Vec<PtrVar> = (0..nvars).map(|_| aa.fresh_var()).collect();
        let objs: Vec<ObjId> = (0..nobjs).map(|_| aa.fresh_obj()).collect();
        let mut addr = Vec::new();
        let mut copies = Vec::new();
        for _ in 0..(1 + rng.below(nvars)) {
            let v = vars[rng.below(vars.len())];
            let o = objs[rng.below(objs.len())];
            aa.address_of(v, o);
            addr.push((v.0, o.0));
        }
        for _ in 0..rng.below(nvars + 2) {
            let d = vars[rng.below(vars.len())];
            let s = vars[rng.below(vars.len())];
            aa.copy(d, s);
            copies.push((d.0, s.0));
        }
        aa.solve();
        Built {
            aa,
            addr,
            copies,
            vars: vars.iter().map(|v| v.0).collect(),
        }
    }

    fn reference_pts(b: &Built) -> HashMap<u32, HashSet<u32>> {
        let mut pts: HashMap<u32, HashSet<u32>> = HashMap::new();
        for &(v, o) in &b.addr {
            pts.entry(v).or_default().insert(o);
        }
        loop {
            let mut changed = false;
            for &(d, s) in &b.copies {
                let src: Vec<u32> = pts.get(&s).into_iter().flatten().copied().collect();
                let dst = pts.entry(d).or_default();
                for o in src {
                    if dst.insert(o) {
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        pts
    }

    #[test]
    fn may_and_must_alias_are_sound() {
        for seed in 1..=1500u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let b = build(&mut rng);
            let reference = reference_pts(&b);
            let empty = HashSet::new();

            for &p in &b.vars {
                let got = b.aa.points_to(PtrVar(p));
                let got_u: HashSet<u32> = got.iter().map(|o| o.0).collect();
                let want = reference.get(&p).unwrap_or(&empty);
                assert_eq!(
                    &got_u, want,
                    "seed {seed}: P{p} points-to {got_u:?} != reference {want:?}"
                );
            }

            for &p in &b.vars {
                for &q in &b.vars {
                    let rp = reference.get(&p).unwrap_or(&empty);
                    let rq = reference.get(&q).unwrap_or(&empty);
                    let genuinely_alias = p == q || !rp.is_disjoint(rq);
                    let may = b.aa.may_alias(PtrVar(p), PtrVar(q));
                    let must = b.aa.must_alias(PtrVar(p), PtrVar(q));

                    // must ⇒ may
                    if must {
                        assert!(may, "seed {seed}: must_alias(P{p},P{q}) but not may_alias");
                    }
                    // No genuinely-aliasing pair is dropped by may-alias.
                    assert_eq!(
                        may, genuinely_alias,
                        "seed {seed}: may_alias(P{p},P{q})={may} but genuine={genuinely_alias}"
                    );
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Part 5: constant_propagation (SCCP) — constant claims vs concrete execution
// ═════════════════════════════════════════════════════════════════════════════

mod sccp_soundness {
    use super::Rng;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::constant_propagation::{
        sparse_conditional_constant_propagation, BinOp, FoldExpr, SccpInstruction, UnOp,
    };
    use crate::ssa::{Instruction, PhiNode, SsaFunction, SsaVar, Var};
    use std::collections::HashMap;

    fn sv(name: &str) -> SsaVar {
        SsaVar::new(Var::new(name), 0)
    }

    /// Build a foldable expression over already-defined variable names.
    fn rand_expr(rng: &mut Rng, vars: &[String], depth: usize) -> FoldExpr {
        if depth == 0 || vars.is_empty() || rng.chance(45) {
            return if rng.chance(50) || vars.is_empty() {
                FoldExpr::Imm(rng.small_i64())
            } else {
                FoldExpr::Var(sv(&vars[rng.below(vars.len())]))
            };
        }
        if rng.chance(25) {
            let op = if rng.chance(50) { UnOp::Neg } else { UnOp::Not };
            return FoldExpr::Unop {
                op,
                operand: Box::new(rand_expr(rng, vars, depth - 1)),
            };
        }
        // Total binops only (no Div/Shl/Shr → no Overdefined escape hatch).
        let op = [
            BinOp::Add,
            BinOp::Sub,
            BinOp::Mul,
            BinOp::And,
            BinOp::Or,
            BinOp::Xor,
        ][rng.below(6)];
        FoldExpr::Binop {
            op,
            lhs: Box::new(rand_expr(rng, vars, depth - 1)),
            rhs: Box::new(rand_expr(rng, vars, depth - 1)),
        }
    }

    /// Concrete evaluation matching `fold`'s integer semantics exactly.
    fn eval(e: &FoldExpr, env: &HashMap<String, i64>) -> i64 {
        match e {
            FoldExpr::Imm(c) => *c,
            FoldExpr::Var(v) => env[&v.base.0],
            FoldExpr::Unop { op, operand } => {
                let v = eval(operand, env);
                match op {
                    UnOp::Neg => v.wrapping_neg(),
                    UnOp::Not => !v,
                }
            }
            FoldExpr::Binop { op, lhs, rhs } => {
                let a = eval(lhs, env);
                let b = eval(rhs, env);
                match op {
                    BinOp::Add => a.wrapping_add(b),
                    BinOp::Sub => a.wrapping_sub(b),
                    BinOp::Mul => a.wrapping_mul(b),
                    BinOp::And => a & b,
                    BinOp::Or => a | b,
                    BinOp::Xor => a ^ b,
                    // These comparison/other ops are used only for the branch
                    // condition; folded to 0/1 like `fold`.
                    BinOp::Eq | BinOp::CmpEq => i64::from(a == b),
                    BinOp::Ne => i64::from(a != b),
                    BinOp::Lt | BinOp::CmpLt => i64::from(a < b),
                    BinOp::Le => i64::from(a <= b),
                    // Not generated for value exprs.
                    BinOp::Div | BinOp::Shl | BinOp::Shr => 0,
                }
            }
        }
    }

    struct Gen {
        func: SsaFunction,
        sccp: Vec<Vec<SccpInstruction>>,
        // (block, list of (var name, expr or None-for-input))
        blocks: Vec<Vec<(String, Option<FoldExpr>)>>,
        // Diamond metadata: (cond expr, phi var, arm-t var, arm-f var) if present.
        diamond: Option<(FoldExpr, String, String, String)>,
        join_exprs: Vec<(String, Option<FoldExpr>)>,
    }

    fn mk_instr(name: &str, uses: Vec<String>) -> Instruction {
        let mut ins = Instruction::new(0, Some(Var::new(name)), vec![]);
        ins.ssa_def = Some(sv(name));
        ins.ssa_uses = uses.into_iter().map(|u| sv(&u)).collect();
        ins
    }

    fn uses_of(e: &FoldExpr, out: &mut Vec<String>) {
        match e {
            FoldExpr::Imm(_) => {}
            FoldExpr::Var(v) => out.push(v.base.0.clone()),
            FoldExpr::Unop { operand, .. } => uses_of(operand, out),
            FoldExpr::Binop { lhs, rhs, .. } => {
                uses_of(lhs, out);
                uses_of(rhs, out);
            }
        }
    }

    fn sccp_of(base: Instruction, expr: Option<FoldExpr>) -> SccpInstruction {
        SccpInstruction {
            base,
            expr,
            is_branch: false,
            branch_cond: None,
            branch_targets: None,
        }
    }

    fn gen_program(rng: &mut Rng) -> Gen {
        let mut names: Vec<String> = Vec::new();
        let mut entry_instrs: Vec<Instruction> = Vec::new();
        let mut entry_sccp: Vec<SccpInstruction> = Vec::new();
        let mut entry_defs: Vec<(String, Option<FoldExpr>)> = Vec::new();
        let mut counter = 0usize;
        let mut fresh = || {
            let n = format!("v{counter}");
            counter += 1;
            n
        };

        // Entry defs: mix of inputs (expr=None → Overdefined) and folds.
        for _ in 0..(2 + rng.below(4)) {
            let name = fresh();
            if names.is_empty() || rng.chance(40) {
                // input
                let ins = mk_instr(&name, vec![]);
                entry_instrs.push(ins.clone());
                entry_sccp.push(sccp_of(ins, None));
                entry_defs.push((name.clone(), None));
            } else {
                let e = rand_expr(rng, &names, 2);
                let mut u = Vec::new();
                uses_of(&e, &mut u);
                let ins = mk_instr(&name, u);
                entry_instrs.push(ins.clone());
                entry_sccp.push(sccp_of(ins, Some(e.clone())));
                entry_defs.push((name.clone(), Some(e)));
            }
            names.push(name);
        }

        let make_diamond = rng.chance(60) && names.len() >= 1;
        if !make_diamond {
            // Straight-line single block.
            let cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
            let func = SsaFunction::new(cfg, &[entry_instrs]);
            return Gen {
                func,
                sccp: vec![entry_sccp],
                blocks: vec![entry_defs],
                diamond: None,
                join_exprs: Vec::new(),
            };
        }

        // Diamond: entry (0) -> 1, 2 -> 3 (join).
        let cond = {
            // Comparison so it can be a boolean; often constant-foldable.
            let a = sv(&names[rng.below(names.len())]);
            let b = sv(&names[rng.below(names.len())]);
            if rng.chance(50) {
                FoldExpr::Binop { op: BinOp::CmpLt, lhs: Box::new(FoldExpr::Var(a)), rhs: Box::new(FoldExpr::Var(b)) }
            } else {
                FoldExpr::Binop { op: BinOp::CmpEq, lhs: Box::new(FoldExpr::Var(a)), rhs: Box::new(FoldExpr::Var(b)) }
            }
        };
        let _cond_name = fresh();
        let mut cond_uses = Vec::new();
        uses_of(&cond, &mut cond_uses);
        let mut cond_instr = Instruction::new(0, None, vec![]);
        cond_instr.ssa_uses = cond_uses.iter().map(|u| sv(u)).collect();
        entry_instrs.push(cond_instr.clone());
        entry_sccp.push(SccpInstruction {
            base: cond_instr,
            expr: None,
            is_branch: true,
            branch_cond: Some(cond.clone()),
            branch_targets: Some((BBId(1), BBId(2))),
        });

        // Arms each define a variable.
        let arm_t = fresh();
        let et = rand_expr(rng, &names, 2);
        let mut ut = Vec::new();
        uses_of(&et, &mut ut);
        let it = mk_instr(&arm_t, ut);
        let arm_f = fresh();
        let ef = rand_expr(rng, &names, 2);
        let mut uf = Vec::new();
        uses_of(&ef, &mut uf);
        let iff = mk_instr(&arm_f, uf);

        // Join: phi p = φ(arm_t from 1, arm_f from 2), then some folds using p.
        let phi_name = fresh();
        let mut phi = PhiNode::new(Var::new(&phi_name), 2);
        phi.result = Some(sv(&phi_name));
        phi.args = vec![Some(sv(&arm_t)), Some(sv(&arm_f))];
        let mut join_names = names.clone();
        join_names.push(phi_name.clone());
        let mut join_instrs: Vec<Instruction> = Vec::new();
        let mut join_sccp: Vec<SccpInstruction> = Vec::new();
        let mut join_defs: Vec<(String, Option<FoldExpr>)> = Vec::new();
        for _ in 0..rng.below(3) {
            let name = fresh();
            let e = rand_expr(rng, &join_names, 2);
            let mut u = Vec::new();
            uses_of(&e, &mut u);
            let ins = mk_instr(&name, u);
            join_instrs.push(ins.clone());
            join_sccp.push(sccp_of(ins, Some(e.clone())));
            join_defs.push((name.clone(), Some(e)));
            join_names.push(name);
        }

        let succs = vec![
            vec![BBId(1), BBId(2)],
            vec![BBId(3)],
            vec![BBId(3)],
            vec![],
        ];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let per_block = vec![
            entry_instrs,
            vec![it.clone()],
            vec![iff.clone()],
            join_instrs,
        ];
        let mut func = SsaFunction::new(cfg, &per_block);
        func.blocks[3].phis.push(phi);

        let sccp = vec![
            entry_sccp,
            vec![sccp_of(it, Some(et.clone()))],
            vec![sccp_of(iff, Some(ef.clone()))],
            join_sccp,
        ];

        Gen {
            func,
            sccp,
            blocks: vec![entry_defs],
            diamond: Some((cond, phi_name, arm_t, arm_f)),
            join_exprs: join_defs,
        }
    }

    #[test]
    fn sccp_constants_never_contradict_concrete_execution() {
        for seed in 1..=800u64 {
            let mut rng = Rng::new(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
            let g = gen_program(&mut rng);
            let result = sparse_conditional_constant_propagation(&g.func, &g.sccp);

            for trial in 0..8u64 {
                let mut cr = Rng::new(seed ^ (trial.wrapping_mul(0xBEEF_0001) | 1));
                let mut env: HashMap<String, i64> = HashMap::new();

                // Entry block defs.
                for (name, expr) in &g.blocks[0] {
                    let val = match expr {
                        None => cr.small_i64(),
                        Some(e) => eval(e, &env),
                    };
                    env.insert(name.clone(), val);
                }

                if let Some((cond, phi_name, arm_t, arm_f)) = &g.diamond {
                    let taken = eval(cond, &env) != 0;
                    let (arm_name, arm_expr) = if taken {
                        (arm_t, /* placeholder */ ())
                    } else {
                        (arm_f, ())
                    };
                    let _ = arm_expr;
                    // Recompute the arm value from its expr. We stored exprs in
                    // sccp; re-eval by pulling from the SccpInstruction.
                    // Simpler: evaluate via the phi source. The arm's def value
                    // is needed. We recorded the arm exprs inside sccp blocks 1/2.
                    let arm_block = if taken { 1 } else { 2 };
                    let arm_e = g.sccp[arm_block][0].expr.clone().unwrap();
                    let arm_val = eval(&arm_e, &env);
                    env.insert(arm_name.clone(), arm_val);
                    // phi result = taken arm's value.
                    env.insert(phi_name.clone(), arm_val);
                    // Join defs.
                    for (name, expr) in &g.join_exprs {
                        let val = eval(expr.as_ref().unwrap(), &env);
                        env.insert(name.clone(), val);
                    }
                }

                for (name, val) in &env {
                    if let Some(c) = result.constant_of(&sv(name)) {
                        assert_eq!(
                            c, *val,
                            "seed {seed} trial {trial}: SCCP claims {name}=={c} but concrete={val}"
                        );
                    }
                }
            }
        }
    }
}
