//! `live_ranges` — live variable analysis and interference graph construction.
//!
//! Classic backward data-flow analysis:
//!
//! ```text
//! LiveIn[B]  = Use[B]  ∪ (LiveOut[B] − Def[B])
//! LiveOut[B] = ∪ { LiveIn[S] | S ∈ succ(B) }
//! ```
//!
//! Audit note (dataflow-crate iteration 5): grepped the whole workspace for
//! `rustre_analysis_dataflow::` usage — nothing outside this crate calls into
//! this module. Note the crate-root `compute_liveness`/`LivenessCfgNode` API
//! (in `lib.rs`, wired into `rustre-mcp-tools`) is a separate, self-contained
//! implementation that does NOT call into this module — don't confuse the
//! two. Only this module's own unit tests exercise it — treat it as orphaned
//! library code until a real consumer shows up.
//!
//! The interference graph is then derived from the live ranges: two variables
//! interfere if they are simultaneously live at any program point.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::cfg_dom::BBId;
use crate::ssa::{SsaFunction, Var};

// ── GenKill ───────────────────────────────────────────────────────────────────

/// The Gen (upward-exposed uses) and Kill (definitions) sets for one block.
#[derive(Debug, Clone, Default)]
struct GenKill {
    gen_set: HashSet<Var>,
    kill: HashSet<Var>,
}

fn compute_gen_kill(func: &SsaFunction) -> Vec<GenKill> {
    let n = func.blocks.len();
    let mut result: Vec<GenKill> = (0..n).map(|_| GenKill::default()).collect();

    for (bb_idx, block) in func.blocks.iter().enumerate() {
        let gk = &mut result[bb_idx];

        // φ-nodes: the result variable is a definition (kill).
        for phi in &block.phis {
            if let Some(ref sv) = phi.result {
                gk.kill.insert(sv.base.clone());
            }
        }

        // Process instructions in program order.
        for instr in &block.instrs {
            // Uses that are not already killed by a prior def in this block.
            for sv in &instr.ssa_uses {
                let base = sv.base.clone();
                if !gk.kill.contains(&base) {
                    gk.gen_set.insert(base);
                }
            }
            // Definition kills the variable.
            if let Some(ref sv) = instr.ssa_def {
                gk.kill.insert(sv.base.clone());
            }
        }
    }

    result
}

// ── LiveRanges ────────────────────────────────────────────────────────────────

/// Per-block live sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRanges {
    pub live_in: Vec<HashSet<Var>>,
    pub live_out: Vec<HashSet<Var>>,
}

impl LiveRanges {
    /// True when `var` is live at the *entry* of `bb`.
    #[must_use]
    pub fn is_live_at_entry(&self, var: &Var, bb: BBId) -> bool {
        self.live_in[bb.0].contains(var)
    }

    /// True when `var` is live at the *exit* of `bb`.
    #[must_use]
    pub fn is_live_at_exit(&self, var: &Var, bb: BBId) -> bool {
        self.live_out[bb.0].contains(var)
    }

    /// True when `var` is live at any point inside `bb` (heuristic: live-in or live-out).
    #[must_use]
    pub fn is_live_at(&self, var: &Var, bb: BBId) -> bool {
        self.is_live_at_entry(var, bb) || self.is_live_at_exit(var, bb)
    }

    /// True when `a` and `b` are simultaneously live in at least one block.
    #[must_use]
    pub fn interferes(&self, a: &Var, b: &Var) -> bool {
        for (live_in, live_out) in self.live_in.iter().zip(self.live_out.iter()) {
            if (live_in.contains(a) && live_in.contains(b))
                || (live_out.contains(a) && live_out.contains(b))
            {
                return true;
            }
        }
        false
    }

    /// Collect all variables that are live at any block entry.
    #[must_use]
    pub fn all_live_vars(&self) -> HashSet<Var> {
        let mut all = HashSet::new();
        for s in &self.live_in {
            all.extend(s.iter().cloned());
        }
        for s in &self.live_out {
            all.extend(s.iter().cloned());
        }
        all
    }

    /// Build the interference graph from the live ranges.
    #[must_use]
    pub fn build_interference_graph(&self) -> InterferenceGraph {
        let mut graph = InterferenceGraph::new();

        for live_set in self.live_in.iter().chain(self.live_out.iter()) {
            let vars: Vec<&Var> = live_set.iter().collect();
            for i in 0..vars.len() {
                // Register every live variable as a node, even when it has no
                // interference edges (e.g. it is the only variable live at a
                // given program point).
                graph.add_node(vars[i].clone());
                for j in (i + 1)..vars.len() {
                    graph.add_edge(vars[i].clone(), vars[j].clone());
                }
            }
        }

        graph
    }
}

// ── compute_live_ranges ───────────────────────────────────────────────────────

/// Run the backward live-variable analysis to convergence.
#[must_use]
pub fn compute_live_ranges(func: &SsaFunction) -> LiveRanges {
    let n = func.blocks.len();
    let cfg = &func.cfg;
    let gk = compute_gen_kill(func);

    let mut live_in: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<Var>> = vec![HashSet::new(); n];

    // Worklist: start with all blocks.
    let mut worklist: VecDeque<BBId> = (0..n).map(BBId).collect();
    let mut in_wl: Vec<bool> = vec![true; n];

    while let Some(bb) = worklist.pop_front() {
        // `cfg` and `func.blocks` are both public fields, so a caller-built
        // `SsaFunction` can have a `cfg.succ`/`cfg.pred` shorter than
        // `func.blocks.len()`, or containing `BBId`s `>= n`. Bounds-check
        // every index derived from CFG data so such malformed input is
        // silently ignored instead of panicking (see `value_range::dfs_topo`
        // for the same pattern).
        if bb.0 >= n {
            continue;
        }
        in_wl[bb.0] = false;

        // LiveOut[B] = ∪ { LiveIn[S] | S ∈ succ(B) }  ∪  { φ-args of S that come
        //                                                 from THIS edge }
        //
        // A φ argument is used at the END of the predecessor it comes from, not
        // at the entry of the block holding the φ. `compute_gen_kill` records a
        // φ only as a KILL of its result, so without the second term the
        // incoming values were never counted as live anywhere — a variable
        // whose only remaining use is a φ argument looked DEAD, and a caller
        // acting on that (DCE, register allocation via
        // `build_interference_graph`) would delete or clobber it.
        //
        // Attributing them per EDGE rather than adding them to the φ-block's
        // Gen set keeps the result precise: a value flowing in only from
        // predecessor P does not become live along the edge from Q, which is
        // what the cheaper conservative fix would have claimed.
        let mut new_out: HashSet<Var> = cfg
            .succ
            .get(bb.0)
            .into_iter()
            .flatten()
            .filter(|s| s.0 < n)
            .flat_map(|&s| live_in[s.0].iter().cloned())
            .collect();
        for &succ in cfg.succ.get(bb.0).into_iter().flatten().filter(|s| s.0 < n) {
            // `PhiNode.args` holds one entry per predecessor, in the order of
            // that successor's own predecessor list — so find where this block
            // sits in it.
            let Some(idx) = cfg
                .pred
                .get(succ.0)
                .and_then(|ps| ps.iter().position(|p| *p == bb))
            else {
                continue;
            };
            for phi in &func.blocks[succ.0].phis {
                if let Some(Some(arg)) = phi.args.get(idx) {
                    new_out.insert(arg.base.clone());
                }
            }
        }

        // LiveIn[B] = Gen[B] ∪ (LiveOut[B] − Kill[B])
        let new_in: HashSet<Var> = gk[bb.0]
            .gen_set
            .iter()
            .chain(new_out.iter().filter(|v| !gk[bb.0].kill.contains(*v)))
            .cloned()
            .collect();

        let changed = new_in != live_in[bb.0] || new_out != live_out[bb.0];
        live_in[bb.0] = new_in;
        live_out[bb.0] = new_out;

        if changed {
            // Re-add predecessors to the worklist.
            for &pred in cfg.pred.get(bb.0).into_iter().flatten() {
                if pred.0 < n && !in_wl[pred.0] {
                    in_wl[pred.0] = true;
                    worklist.push_back(pred);
                }
            }
        }
    }

    LiveRanges { live_in, live_out }
}

// ── InterferenceGraph ─────────────────────────────────────────────────────────

/// Undirected interference graph: each node is a variable; edges connect
/// variables that are simultaneously live.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterferenceGraph {
    /// `adj[v]` = set of variables that interfere with `v`.
    pub adj: HashMap<Var, HashSet<Var>>,
}

impl InterferenceGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure `v` is present as a node, even if it has no interference edges.
    pub fn add_node(&mut self, v: Var) {
        self.adj.entry(v).or_default();
    }

    /// Add an undirected interference edge between `a` and `b`.
    pub fn add_edge(&mut self, a: Var, b: Var) {
        if a == b {
            return;
        }
        self.adj.entry(a.clone()).or_default().insert(b.clone());
        self.adj.entry(b).or_default().insert(a);
    }

    /// True when `a` and `b` interfere.
    #[must_use]
    pub fn interferes(&self, a: &Var, b: &Var) -> bool {
        self.adj.get(a).is_some_and(|s| s.contains(b))
    }

    /// Number of nodes in the interference graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.adj.len()
    }

    /// Degree of a node (number of interfering variables).
    #[must_use]
    pub fn degree(&self, v: &Var) -> usize {
        self.adj.get(v).map_or(0, HashSet::len)
    }

    /// Return all variables that interfere with `v`.
    #[must_use]
    pub fn neighbors(&self, v: &Var) -> &HashSet<Var> {
        static EMPTY: std::sync::OnceLock<HashSet<Var>> = std::sync::OnceLock::new();
        self.adj
            .get(v)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Simple greedy graph colouring for register allocation hints.
    /// Returns `var → colour` where colour is a non-negative integer
    /// representing a physical register class.
    #[must_use]
    pub fn greedy_color(&self) -> HashMap<Var, usize> {
        let mut colour: HashMap<Var, usize> = HashMap::new();
        // Process nodes in decreasing degree order (heuristic). `self.adj`
        // is a `std::collections::HashMap` (randomly-seeded per-process), so
        // nodes with equal degree would otherwise be processed in a
        // different, run-dependent order — and greedy colouring is
        // order-sensitive, so the *specific* colour assigned to a node could
        // then vary from run to run on identical input (still a valid
        // colouring, but not a reproducible one). Break ties on the variable
        // name for full determinism.
        let mut nodes: Vec<&Var> = self.adj.keys().collect();
        nodes.sort_by(|a, b| self.degree(b).cmp(&self.degree(a)).then_with(|| a.0.cmp(&b.0)));

        for v in nodes {
            let neighbour_colours: HashSet<usize> = self
                .neighbors(v)
                .iter()
                .filter_map(|u| colour.get(u))
                .copied()
                .collect();
            let c = (0..=neighbour_colours.len()).find(|c| !neighbour_colours.contains(c)).unwrap_or(0);
            colour.insert(v.clone(), c);
        }

        colour
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::ssa::{Instruction, SsaFunction, Var};

    fn v(s: &str) -> Var {
        Var::new(s)
    }

    use crate::test_util::sv;

    /// Build a simple SSA function: two blocks.
    /// Block 0: `x_0` = ..., `y_0` = ...
    /// Block 1: ... = `x_0` (use of x; y dies here)
    fn make_two_block_func() -> SsaFunction {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));

        let mut i0 = Instruction::new(0, Some(v("x")), vec![]);
        i0.ssa_def = Some(sv("x", 0));
        let mut i1 = Instruction::new(1, Some(v("y")), vec![]);
        i1.ssa_def = Some(sv("y", 0));

        let mut i2 = Instruction::new(2, None, vec![v("x")]);
        i2.ssa_uses = vec![sv("x", 0)];

        SsaFunction::new(cfg, &vec![vec![i0, i1], vec![i2]])
    }

    /// A value whose ONLY remaining use is a φ argument must stay live on the
    /// edge it flows along — and must NOT be live on the other edge.
    ///
    /// `compute_gen_kill` records a φ solely as a KILL of its result, so before
    /// this the incoming φ arguments were never counted as uses anywhere: a
    /// variable used only by a φ looked DEAD. Anything acting on that answer —
    /// dead-code elimination, or register allocation via
    /// `build_interference_graph` — would delete or clobber a value the φ still
    /// needs. Silent miscompilation, never a crash.
    ///
    /// The diamond below is the minimal shape that also catches an
    /// OVER-approximate fix: adding φ args to the φ-block's Gen set would make
    /// `a` live out of block 2 as well, which is wrong — `a` only ever flows
    /// along the 1→3 edge.
    ///
    ///   0: `a_0` = …, `b_0` = …
    ///    ├─1─┐            (nothing; carries `a_0` through)
    ///    └─2─┘            (nothing; carries `b_0` through)
    ///        3: `r_0` = `φ(a_0` from 1, `b_0` from 2)
    #[test]
    fn phi_arguments_are_live_on_their_own_incoming_edge() {
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));

        let mut d_a = Instruction::new(0, Some(v("a")), vec![]);
        d_a.ssa_def = Some(sv("a", 0));
        let mut d_b = Instruction::new(1, Some(v("b")), vec![]);
        d_b.ssa_def = Some(sv("b", 0));

        let mut func = SsaFunction::new(cfg, &vec![vec![d_a, d_b], vec![], vec![], vec![]]);

        // r = φ(a from pred 1, b from pred 2). `args` is indexed by the
        // successor's own predecessor order, which for block 3 is [1, 2].
        let mut phi = crate::ssa::PhiNode::new(v("r"), 2);
        phi.result = Some(sv("r", 0));
        phi.args = vec![Some(sv("a", 0)), Some(sv("b", 0))];
        func.blocks[3].phis.push(phi);

        let lr = compute_live_ranges(&func);

        // Each argument is live out of the predecessor it comes from…
        assert!(
            lr.is_live_at_exit(&v("a"), BBId(1)),
            "`a` is the φ argument on the 1→3 edge, so it must be live out of block 1"
        );
        assert!(
            lr.is_live_at_exit(&v("b"), BBId(2)),
            "`b` is the φ argument on the 2→3 edge, so it must be live out of block 2"
        );
        // …and NOT out of the other one. This is what distinguishes the precise,
        // per-edge fix from the cheaper conservative one.
        assert!(
            !lr.is_live_at_exit(&v("a"), BBId(2)),
            "`a` never flows along the 2→3 edge — an over-approximate fix would              wrongly report it live here"
        );
        assert!(
            !lr.is_live_at_exit(&v("b"), BBId(1)),
            "`b` never flows along the 1→3 edge"
        );
        // Both must survive from their definition in block 0.
        assert!(lr.is_live_at_exit(&v("a"), BBId(0)));
        assert!(lr.is_live_at_exit(&v("b"), BBId(0)));
    }

    #[test]
    fn test_live_in_contains_x_at_block1() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // x is used in block 1, so it should be live-in at block 1.
        assert!(lr.is_live_at_entry(&v("x"), BBId(1)));
    }

    #[test]
    fn test_live_out_contains_x_at_block0() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // x is live-out of block 0 because it is used in block 1.
        assert!(lr.is_live_at_exit(&v("x"), BBId(0)));
    }

    #[test]
    fn test_y_not_live_at_block1() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // y is never used, so it should not be live at block 1.
        assert!(!lr.is_live_at_entry(&v("y"), BBId(1)));
    }

    #[test]
    fn test_interference_x_y_in_block0() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // x and y are both defined in block 0 and x is live-out;
        // they may or may not interfere depending on precise liveness.
        // Just verify the function doesn't panic.
        let _ = lr.interferes(&v("x"), &v("y"));
    }

    #[test]
    fn test_build_interference_graph() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        let ig = lr.build_interference_graph();
        // Graph should have at least node for x.
        assert!(ig.node_count() >= 1);
    }

    #[test]
    fn test_interference_graph_edge() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("a"), v("b"));
        assert!(ig.interferes(&v("a"), &v("b")));
        assert!(ig.interferes(&v("b"), &v("a")));
    }

    #[test]
    fn test_interference_graph_self_edge_ignored() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("a"), v("a"));
        assert!(!ig.interferes(&v("a"), &v("a")));
    }

    #[test]
    fn test_greedy_color_two_interfering() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("x"), v("y"));
        let color = ig.greedy_color();
        assert_ne!(color[&v("x")], color[&v("y")]);
    }

    #[test]
    fn test_greedy_color_triangle() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("a"), v("b"));
        ig.add_edge(v("b"), v("c"));
        ig.add_edge(v("a"), v("c"));
        let color = ig.greedy_color();
        assert_ne!(color[&v("a")], color[&v("b")]);
        assert_ne!(color[&v("b")], color[&v("c")]);
        assert_ne!(color[&v("a")], color[&v("c")]);
    }

    #[test]
    fn test_degree() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("x"), v("y"));
        ig.add_edge(v("x"), v("z"));
        assert_eq!(ig.degree(&v("x")), 2);
    }

    #[test]
    fn test_all_live_vars() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        let all = lr.all_live_vars();
        assert!(all.contains(&v("x")));
    }

    #[test]
    fn test_live_ranges_empty_function() {
        let succs: Vec<Vec<BBId>> = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let func = SsaFunction::new(cfg, &vec![vec![]]);
        let lr = compute_live_ranges(&func);
        assert!(lr.live_in[0].is_empty());
        assert!(lr.live_out[0].is_empty());
    }

    /// Regression test: a caller-built `SsaFunction` can have `cfg.succ`/
    /// `cfg.pred` referencing `BBId`s `>= func.blocks.len()` (both are public
    /// fields). This must not panic; out-of-range edges are silently ignored.
    #[test]
    fn test_out_of_range_cfg_edges_does_not_panic() {
        // Only one real block (id 0), but its successor list dangles a
        // reference to a nonexistent block 5, and predecessors likewise.
        let succs: Vec<Vec<BBId>> = vec![vec![BBId(5)]];
        let mut cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        cfg.pred = vec![vec![BBId(7)]];
        let func = SsaFunction::new(cfg, &vec![vec![]]);
        let lr = compute_live_ranges(&func);
        assert_eq!(lr.live_in.len(), 1);
        assert_eq!(lr.live_out.len(), 1);
    }

    #[test]
    fn test_is_live_at_heuristic() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // x is live at entry or exit of block 0.
        assert!(lr.is_live_at(&v("x"), BBId(0)));
    }

    #[test]
    fn test_interference_graph_node_count_after_live() {
        let mut ig = InterferenceGraph::new();
        ig.add_node(v("a"));
        ig.add_node(v("b"));
        ig.add_node(v("c"));
        assert_eq!(ig.node_count(), 3);
    }

    #[test]
    fn test_neighbors_empty_for_isolated_node() {
        let mut ig = InterferenceGraph::new();
        ig.add_node(v("z"));
        let nb = ig.neighbors(&v("z"));
        assert!(nb.is_empty());
    }

    #[test]
    fn test_greedy_color_no_edges_all_same() {
        let mut ig = InterferenceGraph::new();
        ig.add_node(v("a"));
        ig.add_node(v("b"));
        let color = ig.greedy_color();
        // No edges: all can share colour 0.
        assert_eq!(color[&v("a")], 0);
        assert_eq!(color[&v("b")], 0);
    }

    #[test]
    fn test_live_out_empty_at_exit_block() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // Block 1 is the exit; nothing is live-out there.
        assert!(lr.live_out[1].is_empty());
    }
}

// ── LiveInterval — compact [def, last_use] interval ──────────────────────────

/// A live interval for a single variable: the range of program points
/// `[start, end]` at which the variable must be kept in a register.
///
/// Program points are encoded as `(block_id * 2, instr_index * 2 + 1)`
/// to allow half-open intervals; for simplicity here we use instruction
/// indices within a linearised block sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveInterval {
    pub var: Var,
    /// First definition point (inclusive).
    pub start: usize,
    /// Last use point (inclusive).
    pub end: usize,
}

impl LiveInterval {
    #[must_use]
    pub const fn new(var: Var, start: usize, end: usize) -> Self {
        Self { var, start, end }
    }

    /// Length in abstract time units.
    #[must_use]
    pub const fn length(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether this interval overlaps with `other`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

/// Compute a linear-scan ordering from live ranges: for each variable, find
/// the earliest definition and latest use across all blocks, treating block
/// indices as time points.
#[must_use]
pub fn compute_live_intervals(func: &SsaFunction, lr: &LiveRanges) -> Vec<LiveInterval> {
    let n = func.blocks.len();
    let mut intervals: HashMap<Var, (usize, usize)> = HashMap::new();

    // Lay the blocks out on ONE strictly increasing timeline, giving each block
    // as many slots as it actually needs: entry, one per instruction, exit.
    //
    // The previous scheme reserved exactly two slots per block (`bb * 2` entry,
    // `bb * 2 + 1` exit) but numbered instructions `bb * 2 + 1 + ii`, so any
    // block with two or more instructions overran into the NEXT block's slots.
    // The numbering was therefore not injective, and it broke in both
    // directions: unrelated variables in different blocks collided (false
    // interference, wasted registers), and — worse — a block's own exit slot
    // sat BEFORE its later instructions, so a value live out of the block
    // looked dead before them and its real interference was MISSED, which lets
    // a register allocator clobber a live value.
    //
    // `du_chains.rs::LinearScan::build` already lays out slots this way.
    let mut base = vec![0usize; n];
    let mut cursor = 0usize;
    for bb in 0..n {
        base[bb] = cursor;
        // entry + instructions + exit
        cursor += 2 + func.blocks[bb].instrs.len();
    }
    let entry_t = |bb: usize| base[bb];
    let exit_t = |bb: usize| base[bb] + 1 + func.blocks[bb].instrs.len();

    for bb in 0..n {
        let block = &func.blocks[bb];
        // Phi results are defined at the block entry.
        let ent = entry_t(bb);
        for phi in &block.phis {
            if let Some(ref sv) = phi.result {
                let e = intervals.entry(sv.base.clone()).or_insert((ent, ent));
                e.0 = e.0.min(ent);
                e.1 = e.1.max(ent);
            }
        }
        for (ii, instr) in block.instrs.iter().enumerate() {
            let t = base[bb] + 1 + ii;
            if let Some(ref sv) = instr.ssa_def {
                let e = intervals.entry(sv.base.clone()).or_insert((t, t));
                e.0 = e.0.min(t);
                e.1 = e.1.max(t);
            }
        }
        // Live-in at block entry → interval starts at entry of this block.
        for var in &lr.live_in[bb] {
            let e = intervals.entry(var.clone()).or_insert((ent, ent));
            e.0 = e.0.min(ent);
        }
        // Live-out at block exit → interval extends to exit of this block.
        let ex = exit_t(bb);
        for var in &lr.live_out[bb] {
            let e = intervals.entry(var.clone()).or_insert((ex, ex));
            e.1 = e.1.max(ex);
        }
    }

    intervals
        .into_iter()
        .map(|(var, (start, end))| LiveInterval::new(var, start, end))
        .collect()
}

// ── LiveRanges extended methods ───────────────────────────────────────────────

impl LiveRanges {
    /// Number of variables live at the entry of block `bb`.
    #[must_use]
    pub fn live_in_count(&self, bb: BBId) -> usize {
        self.live_in.get(bb.0).map_or(0, HashSet::len)
    }

    /// Number of variables live at the exit of block `bb`.
    #[must_use]
    pub fn live_out_count(&self, bb: BBId) -> usize {
        self.live_out.get(bb.0).map_or(0, HashSet::len)
    }

    /// Maximum number of variables simultaneously live across all blocks.
    #[must_use]
    pub fn max_live(&self) -> usize {
        self.live_in
            .iter()
            .map(HashSet::len)
            .chain(self.live_out.iter().map(HashSet::len))
            .max()
            .unwrap_or(0)
    }

    /// Variables live-in at some block but not defined in any predecessor
    /// (i.e. function parameters / globals).
    #[must_use]
    pub fn globally_live_vars(&self) -> HashSet<Var> {
        // Approximate: variables live-in at the entry block (block 0).
        self.live_in.first().cloned().unwrap_or_default()
    }
}

// ── Extended live-range tests ─────────────────────────────────────────────────

#[cfg(test)]
mod live_range_extended_tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::ssa::{Instruction, SsaFunction, Var};

    fn v(s: &str) -> Var {
        Var::new(s)
    }
    use crate::test_util::sv;

    fn make_two_block_func() -> SsaFunction {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let mut i0 = Instruction::new(0, Some(v("x")), vec![]);
        i0.ssa_def = Some(sv("x", 0));
        let mut i2 = Instruction::new(2, None, vec![v("x")]);
        i2.ssa_uses = vec![sv("x", 0)];
        SsaFunction::new(cfg, &vec![vec![i0], vec![i2]])
    }

    #[test]
    fn live_interval_overlaps() {
        let a = LiveInterval::new(v("x"), 0, 5);
        let b = LiveInterval::new(v("y"), 3, 8);
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
    }

    #[test]
    fn live_interval_no_overlap() {
        let a = LiveInterval::new(v("x"), 0, 2);
        let b = LiveInterval::new(v("y"), 5, 9);
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn live_interval_length() {
        let a = LiveInterval::new(v("x"), 3, 7);
        assert_eq!(a.length(), 4);
    }

    #[test]
    fn compute_intervals_nonempty() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        let intervals = compute_live_intervals(&func, &lr);
        assert!(!intervals.is_empty());
    }

    #[test]
    fn max_live_at_least_one() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        assert!(lr.max_live() >= 1);
    }

    #[test]
    fn live_in_count_block0() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // Block 0 might have no live-in (nothing defined before it).
        let _ = lr.live_in_count(BBId(0));
    }

    #[test]
    fn live_out_count_block0_has_x() {
        let func = make_two_block_func();
        let lr = compute_live_ranges(&func);
        // x is defined in block 0 and used in block 1 → live-out.
        assert!(lr.live_out_count(BBId(0)) >= 1);
    }

    #[test]
    fn greedy_color_complete_graph_3() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("a"), v("b"));
        ig.add_edge(v("b"), v("c"));
        ig.add_edge(v("a"), v("c"));
        let color = ig.greedy_color();
        // 3 colours needed for a triangle.
        let colors: HashSet<usize> = color.values().copied().collect();
        assert!(colors.len() >= 3);
    }

    #[test]
    fn interference_graph_neighbors_correct() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("x"), v("y"));
        ig.add_edge(v("x"), v("z"));
        let nb = ig.neighbors(&v("x"));
        assert!(nb.contains(&v("y")));
        assert!(nb.contains(&v("z")));
    }

    #[test]
    fn greedy_color_deterministic_across_repeated_runs() {
        // Several nodes with equal degree (isolated pairs) that previously
        // could be coloured differently depending on the arbitrary
        // `HashMap` iteration order of `self.adj`. Run several times and
        // require bit-for-bit identical results.
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("m"), v("n"));
        ig.add_edge(v("a"), v("b"));
        ig.add_edge(v("y"), v("z"));
        ig.add_edge(v("c"), v("d"));
        let first = ig.greedy_color();
        for _ in 0..20 {
            assert_eq!(ig.greedy_color(), first, "greedy_color must be deterministic");
        }
    }

    #[test]
    fn interference_undirected() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v("a"), v("b"));
        assert!(ig.interferes(&v("a"), &v("b")));
        assert!(ig.interferes(&v("b"), &v("a")));
    }
}
