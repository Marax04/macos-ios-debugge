//! Differential/oracle test for the two independent liveness implementations:
//!
//! 1. `rustre_analysis_dataflow::compute_liveness` — the crate-root,
//!    MCP-facing API on the `(bb_id, succs, gen, kill)` tuple model.
//! 2. `live_ranges::compute_live_ranges` — the module-level implementation
//!    on the `SsaFunction` model.
//!
//! Both are cross-checked against a brute-force path-enumeration oracle:
//! a variable `v` is live-in at block `B` iff there exists a CFG path
//! `B = n0 → n1 → … → nk` such that `v` is upward-exposed-used (gen) in
//! `nk` and not defined (kill) in any of `n0 … n(k-1)`. Computed by plain
//! BFS over the small graphs — no dataflow equations involved.
//!
//! ~800 random CFGs of 2-8 nodes with random per-block instruction lists
//! (def/use sequences), from which gen/kill are derived in the test itself.

use std::collections::HashSet;

use rustre_analysis_dataflow::cfg_dom::{BBId, Cfg};
use rustre_analysis_dataflow::compute_liveness;
use rustre_analysis_dataflow::live_ranges::compute_live_ranges;
use rustre_analysis_dataflow::ssa::{Instruction, SsaFunction, SsaVar, Var};

// ── deterministic PRNG (xorshift64*) — no external deps ─────────────────────

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

/// One block's instruction list: (optional def, uses) in program order.
type BlockInstrs = Vec<(Option<u32>, Vec<u32>)>;

/// Derive (gen_set, kill) sets from an instruction sequence, the classic way:
/// gen = upward-exposed uses, kill = all defs.
fn gen_kill(instrs: &BlockInstrs) -> (HashSet<u32>, HashSet<u32>) {
    let mut gen_set = HashSet::new();
    let mut kill = HashSet::new();
    for (def, uses) in instrs {
        for &u in uses {
            if !kill.contains(&u) {
                gen_set.insert(u);
            }
        }
        if let Some(d) = def {
            kill.insert(*d);
        }
    }
    (gen_set, kill)
}

/// Brute-force oracle: BFS from `b`; `v` is live-in at `b` iff some node
/// reachable without passing through a killing node gens `v`.
fn oracle_live_in(
    succs: &[Vec<usize>],
    gens: &[HashSet<u32>],
    kills: &[HashSet<u32>],
    b: usize,
    v: u32,
) -> bool {
    let mut visited = vec![false; succs.len()];
    let mut stack = vec![b];
    while let Some(n) = stack.pop() {
        if visited[n] {
            continue;
        }
        visited[n] = true;
        if gens[n].contains(&v) {
            return true;
        }
        if kills[n].contains(&v) {
            continue; // def blocks liveness from below
        }
        for &s in &succs[n] {
            stack.push(s);
        }
    }
    false
}

fn oracle_live_out(
    succs: &[Vec<usize>],
    gens: &[HashSet<u32>],
    kills: &[HashSet<u32>],
    b: usize,
    v: u32,
) -> bool {
    succs[b]
        .iter()
        .any(|&s| oracle_live_in(succs, gens, kills, s, v))
}

const NUM_VARS: u32 = 5;

fn random_case(rng: &mut Rng) -> (Vec<Vec<usize>>, Vec<BlockInstrs>) {
    let n = 2 + rng.below(7) as usize; // 2-8 nodes
    let mut succs: Vec<Vec<usize>> = Vec::with_capacity(n);
    for _ in 0..n {
        let k = rng.below(3) as usize; // 0-2 successors (incl. self/back edges)
        let mut s: Vec<usize> = Vec::new();
        for _ in 0..k {
            let t = rng.below(n as u64) as usize;
            if !s.contains(&t) {
                s.push(t);
            }
        }
        succs.push(s);
    }
    let mut blocks: Vec<BlockInstrs> = Vec::with_capacity(n);
    for _ in 0..n {
        let ni = rng.below(4) as usize; // 0-3 instructions
        let mut instrs: BlockInstrs = Vec::new();
        for id in 0..ni {
            let def = if rng.below(2) == 0 {
                Some(rng.below(u64::from(NUM_VARS)) as u32)
            } else {
                None
            };
            let nu = rng.below(3) as usize;
            let uses: Vec<u32> = (0..nu)
                .map(|_| rng.below(u64::from(NUM_VARS)) as u32)
                .collect();
            let _ = id;
            instrs.push((def, uses));
        }
        blocks.push(instrs);
    }
    (succs, blocks)
}

fn build_ssa_function(succs: &[Vec<usize>], blocks: &[BlockInstrs]) -> SsaFunction {
    let n = succs.len();
    let cfg_succs: Vec<Vec<BBId>> = succs
        .iter()
        .map(|s| s.iter().map(|&t| BBId(t)).collect())
        .collect();
    let cfg = Cfg::new(n, cfg_succs, BBId(0), BBId(n - 1));
    let mut id = 0usize;
    let instrs_per_block: Vec<Vec<Instruction>> = blocks
        .iter()
        .map(|b| {
            b.iter()
                .map(|(def, uses)| {
                    let vname = |v: u32| Var::new(format!("v{v}"));
                    let mut instr =
                        Instruction::new(id, def.map(vname), uses.iter().map(|&u| vname(u)).collect());
                    // live_ranges::compute_gen_kill reads only the ssa_* fields.
                    instr.ssa_def = def.map(|d| SsaVar::new(vname(d), 0));
                    instr.ssa_uses = uses.iter().map(|&u| SsaVar::new(vname(u), 0)).collect();
                    id += 1;
                    instr
                })
                .collect()
        })
        .collect();
    SsaFunction::new(cfg, &instrs_per_block)
}

#[test]
fn liveness_differential_oracle_800_random_cfgs() {
    let mut rng = Rng(0x5EED_CAFE_F00D_1234);
    for case in 0..800u32 {
        let (succs, blocks) = random_case(&mut rng);
        let n = succs.len();
        let per_block: Vec<(HashSet<u32>, HashSet<u32>)> = blocks.iter().map(gen_kill).collect();
        let gens: Vec<HashSet<u32>> = per_block.iter().map(|(g, _)| g.clone()).collect();
        let kills: Vec<HashSet<u32>> = per_block.iter().map(|(_, k)| k.clone()).collect();

        // ── implementation 1: crate-root compute_liveness ────────────────
        let cfg_nodes: Vec<(u32, Vec<u32>, Vec<u32>, Vec<u32>)> = (0..n)
            .map(|i| {
                let mut g: Vec<u32> = gens[i].iter().copied().collect();
                let mut k: Vec<u32> = kills[i].iter().copied().collect();
                g.sort_unstable();
                k.sort_unstable();
                (
                    i as u32,
                    succs[i].iter().map(|&s| s as u32).collect(),
                    g,
                    k,
                )
            })
            .collect();
        let result = compute_liveness(&cfg_nodes);

        // ── implementation 2: live_ranges::compute_live_ranges ───────────
        let func = build_ssa_function(&succs, &blocks);
        let ranges = compute_live_ranges(&func);

        // ── oracle comparison, every (block, var) pair ────────────────────
        for b in 0..n {
            let (li, lo) = result
                .get(&(b as u32))
                .unwrap_or_else(|| panic!("case {case}: missing bb {b}"));
            for v in 0..NUM_VARS {
                let want_in = oracle_live_in(&succs, &gens, &kills, b, v);
                let want_out = oracle_live_out(&succs, &gens, &kills, b, v);

                assert_eq!(
                    li.contains(&v),
                    want_in,
                    "case {case}: compute_liveness live_in mismatch bb={b} v={v}\nsuccs={succs:?}\nblocks={blocks:?}"
                );
                assert_eq!(
                    lo.contains(&v),
                    want_out,
                    "case {case}: compute_liveness live_out mismatch bb={b} v={v}\nsuccs={succs:?}\nblocks={blocks:?}"
                );

                let var = Var::new(format!("v{v}"));
                assert_eq!(
                    ranges.live_in[b].contains(&var),
                    want_in,
                    "case {case}: compute_live_ranges live_in mismatch bb={b} v={v}\nsuccs={succs:?}\nblocks={blocks:?}"
                );
                assert_eq!(
                    ranges.live_out[b].contains(&var),
                    want_out,
                    "case {case}: compute_live_ranges live_out mismatch bb={b} v={v}\nsuccs={succs:?}\nblocks={blocks:?}"
                );
            }
        }
    }
}
