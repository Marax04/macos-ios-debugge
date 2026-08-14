//! Differential/oracle test for the four independent reaching-definitions
//! implementations in this crate:
//!
//! 1. `rustre_analysis_dataflow::compute_reaching_defs` — the crate-root,
//!    MCP-facing API on the `(bb_id, succs, gen_defs, kill_defs)` tuple model
//!    with opaque `u32` def ids.
//! 2. `reaching_defs::reaching_definitions` — the `cfg_dom::Cfg` +
//!    `NonSsaInstruction`/`DefId` model (gen/kill derived internally).
//! 3. `reaching_definitions::ReachingDefs::compute` — the `BasicBlockInfo`
//!    model with named `Var`s and caller-supplied gen/kill_vars.
//! 4. `def_use_analysis::ReachingDefs::compute` — the `Program`/`Block` model
//!    with `all_defs: ProgramPoint → def_id` and caller-supplied kill sets.
//!
//! All are cross-checked against a brute-force path-enumeration oracle:
//! a definition `d` of variable `v` in block `B` reaches the ENTRY of block
//! `C` iff `d` is the last def of `v` in `B` (survives `B`) and there is a
//! CFG path `B → n1 → … → C` such that none of `n1 … n(k-1)` (the interior
//! nodes) redefines `v`. Computed by plain BFS — no dataflow equations.
//! `d` reaches the EXIT of `C` iff (`C == B` and `d` survives `B`) or
//! (`d` reaches entry of `C` and `C` does not define `v`).
//!
//! ~800 random CFGs of 2-8 nodes, all nodes forced reachable from the entry
//! (implementations legitimately disagree on unreachable regions: the
//! RPO-based fixpoint in `def_use_analysis` never visits them, while the
//! all-blocks worklists do), with random per-block def/use instruction lists.

use std::collections::{HashMap, HashSet};

use rustre_analysis_dataflow::cfg_dom::{BBId, Cfg};
use rustre_analysis_dataflow::compute_reaching_defs;
use rustre_analysis_dataflow::def_use_analysis::{
    Block, Instruction as DuInstruction, Program, ProgramPoint,
    ReachingDefs as DuReachingDefs,
};
use rustre_analysis_dataflow::reaching_definitions::{
    BasicBlockInfo, Def as RdDef, ReachingDefs as BbReachingDefs, Var as RdVar,
};
use rustre_analysis_dataflow::reaching_defs::{reaching_definitions, DefId, NonSsaInstruction};

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

const NUM_VARS: u32 = 4;

/// One block's instruction list: (optional defined var, used vars) in order.
type BlockInstrs = Vec<(Option<u32>, Vec<u32>)>;

/// A single definition site with a globally unique id.
#[derive(Debug, Clone, Copy)]
struct DefSite {
    gid: u32,     // global def id
    var: u32,     // variable defined
    block: usize, // defining block
    instr: usize, // instruction index within block
    survives: bool, // last def of `var` in `block` (reaches the block's exit)
}

fn reachable_from(succs: &[Vec<usize>], start: usize) -> Vec<bool> {
    let mut seen = vec![false; succs.len()];
    let mut stack = vec![start];
    while let Some(n) = stack.pop() {
        if seen[n] {
            continue;
        }
        seen[n] = true;
        for &s in &succs[n] {
            stack.push(s);
        }
    }
    seen
}

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
    // Force every node reachable from node 0 (the entry): unreachable-region
    // semantics differ between the implementations by design.
    loop {
        let seen = reachable_from(&succs, 0);
        let Some(orphan) = seen.iter().position(|&v| !v) else { break };
        let reachable: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|&(_, &v)| v)
            .map(|(i, _)| i)
            .collect();
        let from = reachable[rng.below(reachable.len() as u64) as usize];
        if !succs[from].contains(&orphan) {
            succs[from].push(orphan);
        }
    }
    let mut blocks: Vec<BlockInstrs> = Vec::with_capacity(n);
    for _ in 0..n {
        let ni = rng.below(4) as usize; // 0-3 instructions
        let mut instrs: BlockInstrs = Vec::new();
        for _ in 0..ni {
            let def = if rng.below(2) == 0 {
                Some(rng.below(u64::from(NUM_VARS)) as u32)
            } else {
                None
            };
            let nu = rng.below(3) as usize;
            let uses: Vec<u32> = (0..nu)
                .map(|_| rng.below(u64::from(NUM_VARS)) as u32)
                .collect();
            instrs.push((def, uses));
        }
        blocks.push(instrs);
    }
    (succs, blocks)
}

/// Enumerate all def sites with global ids and survives flags.
fn def_sites(blocks: &[BlockInstrs]) -> Vec<DefSite> {
    let mut sites = Vec::new();
    let mut gid = 0u32;
    for (b, instrs) in blocks.iter().enumerate() {
        for (i, (def, _)) in instrs.iter().enumerate() {
            if let Some(v) = def {
                sites.push(DefSite {
                    gid,
                    var: *v,
                    block: b,
                    instr: i,
                    survives: false, // fixed up below
                });
                gid += 1;
            }
        }
    }
    // survives = last def of its var within its block.
    for idx in 0..sites.len() {
        let s = sites[idx];
        sites[idx].survives = !sites
            .iter()
            .any(|o| o.block == s.block && o.var == s.var && o.instr > s.instr);
    }
    sites
}

/// Which vars does block `b` define (any def at all)?
fn block_defines(blocks: &[BlockInstrs], b: usize, v: u32) -> bool {
    blocks[b].iter().any(|(d, _)| *d == Some(v))
}

/// Oracle: does def `d` reach the ENTRY of block `c`?
/// BFS forward from B's successors through blocks that do not redefine v.
fn oracle_reaches_entry(succs: &[Vec<usize>], blocks: &[BlockInstrs], d: &DefSite, c: usize) -> bool {
    if !d.survives {
        return false;
    }
    let mut visited = vec![false; succs.len()];
    let mut stack: Vec<usize> = succs[d.block].clone();
    while let Some(n) = stack.pop() {
        if visited[n] {
            continue;
        }
        visited[n] = true;
        if n == c {
            return true;
        }
        if block_defines(blocks, n, d.var) {
            continue; // redefinition blocks propagation past n's entry
        }
        for &s in &succs[n] {
            stack.push(s);
        }
    }
    false
}

fn oracle_reaches_exit(succs: &[Vec<usize>], blocks: &[BlockInstrs], d: &DefSite, c: usize) -> bool {
    if c == d.block {
        return d.survives;
    }
    oracle_reaches_entry(succs, blocks, d, c) && !block_defines(blocks, c, d.var)
}

// ── bridges ──────────────────────────────────────────────────────────────────

/// Impl 1: crate-root `compute_reaching_defs` on opaque u32 def ids.
/// gen = surviving defs of the block; kill = every def id of every var the
/// block defines (own defs re-added via gen, the classic formulation).
fn run_lib(succs: &[Vec<usize>], sites: &[DefSite], n: usize) -> HashMap<u32, (Vec<u32>, Vec<u32>)> {
    let nodes: Vec<(u32, Vec<u32>, Vec<u32>, Vec<u32>)> = (0..n)
        .map(|b| {
            let gen_defs: Vec<u32> = sites
                .iter()
                .filter(|s| s.block == b && s.survives)
                .map(|s| s.gid)
                .collect();
            let defined_vars: HashSet<u32> = sites
                .iter()
                .filter(|s| s.block == b)
                .map(|s| s.var)
                .collect();
            let kill_defs: Vec<u32> = sites
                .iter()
                .filter(|s| defined_vars.contains(&s.var))
                .map(|s| s.gid)
                .collect();
            (
                b as u32,
                succs[b].iter().map(|&s| s as u32).collect(),
                gen_defs,
                kill_defs,
            )
        })
        .collect();
    compute_reaching_defs(&nodes)
}

/// Impl 2: `reaching_defs::reaching_definitions` on Cfg + NonSsaInstruction.
fn run_reaching_defs(
    succs: &[Vec<usize>],
    blocks: &[BlockInstrs],
    sites: &[DefSite],
) -> rustre_analysis_dataflow::reaching_defs::ReachingDefs {
    let n = succs.len();
    let cfg_succs: Vec<Vec<BBId>> = succs
        .iter()
        .map(|s| s.iter().map(|&t| BBId(t)).collect())
        .collect();
    let cfg = Cfg::new(n, cfg_succs, BBId(0), BBId(n - 1));
    let mut id = 0usize;
    let ns_blocks: Vec<Vec<NonSsaInstruction>> = blocks
        .iter()
        .enumerate()
        .map(|(b, instrs)| {
            instrs
                .iter()
                .enumerate()
                .map(|(i, (def, uses))| {
                    let def_id = def.map(|v| {
                        let site = sites
                            .iter()
                            .find(|s| s.block == b && s.instr == i)
                            .expect("site exists");
                        DefId::new(v, site.gid)
                    });
                    let instr = NonSsaInstruction::new(id, def_id, uses.clone());
                    id += 1;
                    instr
                })
                .collect()
        })
        .collect();
    reaching_definitions(&cfg, &ns_blocks)
}

/// Impl 3: `reaching_definitions::ReachingDefs::compute` on BasicBlockInfo.
fn run_bb_info(
    succs: &[Vec<usize>],
    blocks: &[BlockInstrs],
    sites: &[DefSite],
) -> BbReachingDefs {
    let n = succs.len();
    let mut preds: Vec<Vec<u64>> = vec![Vec::new(); n];
    for (b, ss) in succs.iter().enumerate() {
        for &s in ss {
            preds[s].push(b as u64);
        }
    }
    let bb_blocks: Vec<BasicBlockInfo> = (0..n)
        .map(|b| {
            let mut info = BasicBlockInfo::new(b as u64);
            info.successors = succs[b].iter().map(|&s| s as u64).collect();
            info.predecessors = preds[b].clone();
            for s in sites.iter().filter(|s| s.block == b) {
                let d = RdDef {
                    var: RdVar::new(format!("v{}", s.var)),
                    block_id: b as u64,
                    instr_idx: s.instr,
                };
                if s.survives {
                    info.r#gen.insert(d.clone());
                }
                info.kill_vars.insert(RdVar::new(format!("v{}", s.var)));
                info.defs.push(d);
            }
            for (i, (_, uses)) in blocks[b].iter().enumerate() {
                for &u in uses {
                    info.uses.push(rustre_analysis_dataflow::reaching_definitions::Use {
                        var: RdVar::new(format!("v{u}")),
                        block_id: b as u64,
                        instr_idx: i,
                    });
                }
            }
            info
        })
        .collect();
    BbReachingDefs::compute(&bb_blocks, 0, 1_000_000).expect("fixpoint")
}

/// Impl 4: `def_use_analysis::ReachingDefs::compute` on Program.
fn run_def_use(
    succs: &[Vec<usize>],
    blocks: &[BlockInstrs],
    sites: &[DefSite],
) -> DuReachingDefs {
    let n = succs.len();
    let mut program = Program::new(0);
    for (b, instrs) in blocks.iter().enumerate() {
        let du_instrs: Vec<DuInstruction> = instrs
            .iter()
            .map(|(def, uses)| {
                let def_name = def.map(|v| format!("v{v}"));
                let use_names: Vec<String> = uses.iter().map(|u| format!("v{u}")).collect();
                DuInstruction {
                    def: def_name,
                    uses: use_names,
                }
            })
            .collect();
        program.add_block(Block::new(b, du_instrs));
    }
    for (b, ss) in succs.iter().enumerate() {
        for &s in ss {
            program.add_edge(b, s);
        }
    }
    let all_defs: HashMap<ProgramPoint, usize> = sites
        .iter()
        .map(|s| (ProgramPoint::new(s.block, s.instr), s.gid as usize))
        .collect();
    // kill[B] = every def id of every var B defines (own surviving defs are
    // re-added by gen inside the analysis).
    let mut kill_sets: HashMap<usize, HashSet<usize>> = HashMap::new();
    for b in 0..n {
        let defined_vars: HashSet<u32> = sites
            .iter()
            .filter(|s| s.block == b)
            .map(|s| s.var)
            .collect();
        let kills: HashSet<usize> = sites
            .iter()
            .filter(|s| defined_vars.contains(&s.var))
            .map(|s| s.gid as usize)
            .collect();
        kill_sets.insert(b, kills);
    }
    DuReachingDefs::compute(&program, &all_defs, &kill_sets)
}

// ── the differential test ────────────────────────────────────────────────────

#[test]
fn reaching_defs_differential_oracle_800_random_cfgs() {
    let mut rng = Rng(0xDEF5_012A_CAFE_0BAC);
    for case in 0..800u32 {
        let (succs, blocks) = random_case(&mut rng);
        let n = succs.len();
        let sites = def_sites(&blocks);

        let lib_result = run_lib(&succs, &sites, n);
        let rd_result = run_reaching_defs(&succs, &blocks, &sites);
        let bb_result = run_bb_info(&succs, &blocks, &sites);
        let du_result = run_def_use(&succs, &blocks, &sites);

        for c in 0..n {
            let (lib_in, lib_out) = lib_result
                .get(&(c as u32))
                .unwrap_or_else(|| panic!("case {case}: lib missing bb {c}"));
            for d in &sites {
                let want_in = oracle_reaches_entry(&succs, &blocks, d, c);
                let want_out = oracle_reaches_exit(&succs, &blocks, d, c);
                let ctx = || {
                    format!(
                        "case {case}: bb={c} def gid={} v{} @ ({},{}) survives={}\nsuccs={succs:?}\nblocks={blocks:?}",
                        d.gid, d.var, d.block, d.instr, d.survives
                    )
                };

                // 1. crate-root compute_reaching_defs
                assert_eq!(lib_in.contains(&d.gid), want_in, "compute_reaching_defs IN {}", ctx());
                assert_eq!(lib_out.contains(&d.gid), want_out, "compute_reaching_defs OUT {}", ctx());

                // 2. reaching_defs::reaching_definitions
                let def_id = DefId::new(d.var, d.gid);
                assert_eq!(
                    rd_result.reaches_entry(def_id, BBId(c)),
                    want_in,
                    "reaching_definitions(non-SSA) IN {}",
                    ctx()
                );
                assert_eq!(
                    rd_result.reaches_exit(def_id, BBId(c)),
                    want_out,
                    "reaching_definitions(non-SSA) OUT {}",
                    ctx()
                );

                // 3. reaching_definitions::ReachingDefs (BasicBlockInfo)
                let bb_def = RdDef {
                    var: RdVar::new(format!("v{}", d.var)),
                    block_id: d.block as u64,
                    instr_idx: d.instr,
                };
                assert_eq!(
                    bb_result.reach_in.get(&(c as u64)).is_some_and(|s| s.contains(&bb_def)),
                    want_in,
                    "BasicBlockInfo ReachingDefs IN {}",
                    ctx()
                );
                assert_eq!(
                    bb_result.reach_out.get(&(c as u64)).is_some_and(|s| s.contains(&bb_def)),
                    want_out,
                    "BasicBlockInfo ReachingDefs OUT {}",
                    ctx()
                );

                // 4. def_use_analysis::ReachingDefs
                assert_eq!(
                    du_result.in_defs.get(&c).is_some_and(|s| s.contains(&(d.gid as usize))),
                    want_in,
                    "def_use_analysis ReachingDefs IN {}",
                    ctx()
                );
                assert_eq!(
                    du_result.out_defs.get(&c).is_some_and(|s| s.contains(&(d.gid as usize))),
                    want_out,
                    "def_use_analysis ReachingDefs OUT {}",
                    ctx()
                );
            }
        }
    }
}
