//! `reaching_defs` — reaching definitions analysis for non-SSA functions.
//!
//! # Relationship to [`crate::reaching_definitions`]
//! This module targets the project's shared non-SSA CFG IR (`cfg_dom::Cfg` +
//! `NonSsaInstruction` with numeric `DefId`/`var_id` identifiers).  It is the
//! low-level layer used by analyses that consume the standard CFG types.
//!
//! [`crate::reaching_definitions`] is a higher-level, self-contained module
//! built on its own `BasicBlockInfo`/`u64`-keyed IR and bundles several
//! additional analyses (live variables, available expressions, constant
//! propagation, copy propagation).  The two modules are intentionally kept
//! separate because they serve different abstraction layers.
//!
//! Classic forward may-analysis:
//! ```text
//! RDin[B]  = ∪ { RDout[P] | P ∈ pred(B) }
//! RDout[B] = Gen[B] ∪ (RDin[B] − Kill[B])
//! ```
//!
//! Gen[B]  = set of definitions in B that reach B's exit.
//! Kill[B] = all other definitions of the same variable(s) defined in B.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::cfg_dom::{BBId, Cfg};

// ── DefId ─────────────────────────────────────────────────────────────────────

/// Uniquely identifies one definition of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefId {
    /// The variable being defined.
    pub var_id: u32,
    /// The definition's unique serial number within the function.
    pub serial: u32,
}

impl DefId {
    #[must_use]
    pub const fn new(var_id: u32, serial: u32) -> Self {
        Self { var_id, serial }
    }
}

// ── NonSsaInstruction ─────────────────────────────────────────────────────────

/// A non-SSA instruction: may define one variable (by `var_id`) and use
/// several (by `var_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonSsaInstruction {
    pub id: usize,
    /// Variable id defined by this instruction, if any.
    pub def: Option<DefId>,
    /// Variable ids used by this instruction.
    pub uses: Vec<u32>,
}

impl NonSsaInstruction {
    #[must_use]
    pub const fn new(id: usize, def: Option<DefId>, uses: Vec<u32>) -> Self {
        Self { id, def, uses }
    }
}

// ── GenKill sets ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct GenKill {
    gen_set: HashSet<DefId>,
    kill: HashSet<DefId>,
}

/// Compute per-block Gen and Kill sets from all block instructions.
///
/// Requires the full list of definitions for each variable (to compute Kill).
fn compute_gen_kill(
    n: usize,
    blocks: &[Vec<NonSsaInstruction>],
    all_defs: &HashMap<u32, Vec<DefId>>,
) -> Vec<GenKill> {
    let mut result: Vec<GenKill> = (0..n).map(|_| GenKill::default()).collect();

    // `blocks` is caller-supplied and may be shorter or longer than the CFG
    // (`n`); only process indices that exist in both to avoid an
    // out-of-bounds panic on malformed/untrusted input.
    for (bb, instrs) in blocks.iter().enumerate().take(n) {
        let gk = &mut result[bb];
        for instr in instrs {
            if let Some(d) = instr.def {
                // Kill: all other definitions of the same variable.
                if let Some(all) = all_defs.get(&d.var_id) {
                    for &other in all {
                        if other != d {
                            gk.kill.insert(other);
                        }
                    }
                }
                // Remove from gen anything this def kills (overrides earlier defs
                // of the same variable in this block).
                if let Some(all) = all_defs.get(&d.var_id) {
                    for &other in all {
                        gk.gen_set.remove(&other);
                    }
                }
                // Gen: this definition reaches the end of the block.
                gk.gen_set.insert(d);
            }
        }
    }

    result
}

// ── ReachingDefs ─────────────────────────────────────────────────────────────

/// Result of the reaching-definitions analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachingDefs {
    /// Set of definitions that reach the *entry* of each block.
    pub rd_in: Vec<HashSet<DefId>>,
    /// Set of definitions that reach the *exit* of each block.
    pub rd_out: Vec<HashSet<DefId>>,
}

impl ReachingDefs {
    /// True when `def` reaches the entry of `bb`.
    ///
    /// Returns `false` (rather than panicking) if `bb` is out of range.
    #[must_use]
    pub fn reaches_entry(&self, def: DefId, bb: BBId) -> bool {
        self.rd_in.get(bb.0).is_some_and(|s| s.contains(&def))
    }

    /// True when `def` reaches the exit of `bb`.
    ///
    /// Returns `false` (rather than panicking) if `bb` is out of range.
    #[must_use]
    pub fn reaches_exit(&self, def: DefId, bb: BBId) -> bool {
        self.rd_out.get(bb.0).is_some_and(|s| s.contains(&def))
    }

    /// Return all definitions of variable `var_id` that reach the entry of `bb`.
    ///
    /// Returns an empty vector (rather than panicking) if `bb` is out of range.
    #[must_use]
    pub fn reaching_defs_at(&self, bb: BBId, var_id: u32) -> Vec<DefId> {
        self.rd_in
            .get(bb.0)
            .map(|s| s.iter().filter(|d| d.var_id == var_id).copied().collect())
            .unwrap_or_default()
    }

    /// Return the number of distinct definitions reaching entry of `bb` for `var_id`.
    ///
    /// Returns `0` (rather than panicking) if `bb` is out of range.
    #[must_use]
    pub fn def_count_at(&self, bb: BBId, var_id: u32) -> usize {
        self.rd_in
            .get(bb.0)
            .map(|s| s.iter().filter(|d| d.var_id == var_id).count())
            .unwrap_or(0)
    }

    /// Return all definitions (across all variables) reaching the entry of `bb`.
    ///
    /// Returns an empty vector (rather than panicking) if `bb` is out of range.
    #[must_use]
    pub fn all_reaching_at(&self, bb: BBId) -> Vec<DefId> {
        self.rd_in.get(bb.0).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }
}

// ── reaching_definitions ─────────────────────────────────────────────────────

/// Run the reaching-definitions analysis on a non-SSA function.
#[must_use]
pub fn reaching_definitions(cfg: &Cfg, blocks: &[Vec<NonSsaInstruction>]) -> ReachingDefs {
    let n = cfg.len();

    // Collect all definition sites per variable.
    let mut all_defs: HashMap<u32, Vec<DefId>> = HashMap::new();
    for block in blocks {
        for instr in block {
            if let Some(d) = instr.def {
                all_defs.entry(d.var_id).or_default().push(d);
            }
        }
    }

    let gk = compute_gen_kill(n, blocks, &all_defs);

    let mut rd_in: Vec<HashSet<DefId>> = vec![HashSet::new(); n];
    let mut rd_out: Vec<HashSet<DefId>> = vec![HashSet::new(); n];

    // Initialise RDout[entry] = Gen[entry]. `entry` comes from the caller-
    // supplied `cfg` and is bounds-checked rather than indexed directly, so a
    // malformed CFG with an out-of-range entry cannot panic here.
    let entry = cfg.entry;
    if let Some(entry_gen) = gk.get(entry.0).map(|g| g.gen_set.clone())
        && let Some(out) = rd_out.get_mut(entry.0)
    {
        *out = entry_gen;
    }

    let mut worklist: VecDeque<BBId> = (0..n).map(BBId).collect();
    let mut in_wl: Vec<bool> = vec![true; n];

    while let Some(bb) = worklist.pop_front() {
        // `bb.0` always comes from `0..n`, but `cfg.pred`/`cfg.succ`/`gk`/
        // `rd_in`/`rd_out` are indexed off it below. `Cfg`'s fields are
        // public, so a caller-built `Cfg` can have `pred`/`succ` shorter
        // than `n` (== `cfg.succ.len()` at construction time via `Cfg::new`,
        // but nothing stops direct field mutation afterwards) or containing
        // out-of-range `BBId`s. Bounds-check every derived index so such
        // malformed input is silently ignored instead of panicking (same
        // pattern as `live_ranges::compute_live_ranges`).
        if bb.0 >= n {
            continue;
        }
        in_wl[bb.0] = false;

        // RDin[B] = ∪ { RDout[P] | P ∈ pred(B) }
        let new_in: HashSet<DefId> = cfg
            .pred
            .get(bb.0)
            .into_iter()
            .flatten()
            .filter_map(|&p| rd_out.get(p.0))
            .flat_map(|s| s.iter().copied())
            .collect();

        // RDout[B] = Gen[B] ∪ (RDin[B] − Kill[B])
        let new_out: HashSet<DefId> = gk[bb.0]
            .gen_set
            .iter()
            .chain(new_in.iter().filter(|d| !gk[bb.0].kill.contains(d)))
            .copied()
            .collect();

        let changed = new_in != rd_in[bb.0] || new_out != rd_out[bb.0];
        rd_in[bb.0] = new_in;
        rd_out[bb.0] = new_out;

        if changed {
            for &succ in cfg.succ.get(bb.0).into_iter().flatten() {
                if succ.0 < n && !in_wl[succ.0] {
                    in_wl[succ.0] = true;
                    worklist.push_back(succ);
                }
            }
        }
    }

    ReachingDefs { rd_in, rd_out }
}

// ── Use-def chain from reaching definitions ────────────────────────────────────

/// A use-def pair derived from the reaching-definitions result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UseDefPair {
    pub use_instr_id: usize,
    pub use_var_id: u32,
    pub reaching_def: DefId,
}

/// Build use-def pairs by matching each variable use in `bb` against the
/// reaching definitions at `bb`'s entry.
#[must_use]
pub fn build_use_def_pairs(
    blocks: &[Vec<NonSsaInstruction>],
    rd: &ReachingDefs,
) -> Vec<UseDefPair> {
    let mut pairs = Vec::new();

    for (bb_idx, block) in blocks.iter().enumerate() {
        // `rd` may have been computed from a CFG shorter than `blocks` (or
        // vice versa) if the caller passes mismatched inputs; fall back to
        // an empty reaching set rather than panicking on an out-of-range index.
        let mut live: HashSet<DefId> = rd.rd_in.get(bb_idx).cloned().unwrap_or_default();

        for instr in block {
            // For each use, find which defs reach this instruction.
            for &var_id in &instr.uses {
                for &def in live.iter().filter(|d| d.var_id == var_id) {
                    pairs.push(UseDefPair {
                        use_instr_id: instr.id,
                        use_var_id: var_id,
                        reaching_def: def,
                    });
                }
            }
            // Apply this instruction's definition.
            if let Some(d) = instr.def {
                // Remove all earlier defs of the same variable.
                live.retain(|existing| existing.var_id != d.var_id);
                live.insert(d);
            }
        }
    }

    pairs
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};

    fn d(var: u32, serial: u32) -> DefId {
        DefId::new(var, serial)
    }

    fn instr(id: usize, def: Option<DefId>, uses: Vec<u32>) -> NonSsaInstruction {
        NonSsaInstruction::new(id, def, uses)
    }

    /// Linear CFG: 0 → 1 → 2 → 3.
    fn linear_cfg(n: usize) -> Cfg {
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        Cfg::new(n, succs, BBId(0), BBId(n - 1))
    }

    #[test]
    fn test_basic_reaching_def() {
        // Block 0: x=d(0,0)
        // Block 1: uses x
        let cfg = linear_cfg(2);
        let blocks = vec![
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, None, vec![0])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        // d(0,0) should reach the entry of block 1.
        assert!(rd.reaches_entry(d(0, 0), BBId(1)));
    }

    #[test]
    fn test_kill_removes_earlier_def() {
        // Block 0: x=d(0,0)
        // Block 1: x=d(0,1) (kills d(0,0))
        // Block 2: uses x
        let cfg = linear_cfg(3);
        let blocks = vec![
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, Some(d(0, 1)), vec![])],
            vec![instr(2, None, vec![0])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        // d(0,0) should NOT reach block 2.
        assert!(!rd.reaches_entry(d(0, 0), BBId(2)));
        // d(0,1) SHOULD reach block 2.
        assert!(rd.reaches_entry(d(0, 1), BBId(2)));
    }

    #[test]
    fn test_two_defs_reach_join() {
        // Block 0 → block 1, block 0 → block 2, both define x; block 3 uses x.
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let blocks = vec![
            vec![],
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, Some(d(0, 1)), vec![])],
            vec![instr(2, None, vec![0])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        // Both d(0,0) and d(0,1) should reach block 3.
        assert!(rd.reaches_entry(d(0, 0), BBId(3)));
        assert!(rd.reaches_entry(d(0, 1), BBId(3)));
    }

    #[test]
    fn test_def_count_at() {
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let blocks = vec![
            vec![],
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, Some(d(0, 1)), vec![])],
            vec![],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        assert_eq!(rd.def_count_at(BBId(3), 0), 2);
    }

    /// A `blocks` slice shorter than the CFG (fewer basic blocks supplied
    /// than `cfg.len()` claims) must not panic — it should just treat the
    /// missing blocks as empty rather than indexing out of bounds.
    #[test]
    fn test_blocks_shorter_than_cfg_does_not_panic() {
        let succs = vec![vec![BBId(1)], vec![BBId(2)], vec![]];
        let cfg = Cfg::new(3, succs, BBId(0), BBId(2));
        // Only 1 block supplied even though the CFG has 3.
        let blocks = vec![vec![instr(0, Some(d(0, 0)), vec![])]];
        let rd = reaching_definitions(&cfg, &blocks);
        assert_eq!(rd.rd_in.len(), 3);
        assert_eq!(rd.rd_out.len(), 3);
    }

    /// A `blocks` slice longer than the CFG must not panic either.
    #[test]
    fn test_blocks_longer_than_cfg_does_not_panic() {
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let blocks = vec![
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, Some(d(1, 0)), vec![])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        assert_eq!(rd.rd_in.len(), 1);
        // build_use_def_pairs iterates over `blocks` (longer than `rd`) and
        // must not panic when it reaches the out-of-range index.
        let _ = build_use_def_pairs(&blocks, &rd);
    }

    /// A directly-constructed `Cfg` (bypassing `Cfg::new`) with `pred`/`succ`
    /// shorter than `entry`/`exit` imply must not panic.
    #[test]
    fn test_malformed_cfg_out_of_range_entry_does_not_panic() {
        let cfg = Cfg {
            pred: vec![vec![]],
            succ: vec![vec![]],
            entry: BBId(5), // out of range: cfg.len() == 1
            exit: BBId(0),
        };
        let blocks = vec![vec![instr(0, Some(d(0, 0)), vec![])]];
        let rd = reaching_definitions(&cfg, &blocks);
        assert_eq!(rd.rd_in.len(), 1);
    }

    #[test]
    fn test_use_def_pairs() {
        let cfg = linear_cfg(2);
        let blocks = vec![
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, None, vec![0])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        let pairs = build_use_def_pairs(&blocks, &rd);
        assert!(!pairs.is_empty());
        assert!(
            pairs
                .iter()
                .any(|p| p.use_instr_id == 1 && p.reaching_def == d(0, 0))
        );
    }

    #[test]
    fn test_empty_blocks() {
        let cfg = linear_cfg(2);
        let blocks: Vec<Vec<NonSsaInstruction>> = vec![vec![], vec![]];
        let rd = reaching_definitions(&cfg, &blocks);
        assert!(rd.rd_in[0].is_empty());
        assert!(rd.rd_out[0].is_empty());
    }

    #[test]
    fn test_reaches_exit() {
        let cfg = linear_cfg(2);
        let blocks = vec![vec![instr(0, Some(d(0, 0)), vec![])], vec![]];
        let rd = reaching_definitions(&cfg, &blocks);
        assert!(rd.reaches_exit(d(0, 0), BBId(0)));
    }

    #[test]
    fn test_reaching_defs_at_returns_correct_var() {
        let cfg = linear_cfg(2);
        let blocks = vec![
            vec![
                instr(0, Some(d(0, 0)), vec![]), // var 0
                instr(1, Some(d(1, 0)), vec![]), // var 1
            ],
            vec![],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        let var0_defs = rd.reaching_defs_at(BBId(1), 0);
        assert_eq!(var0_defs.len(), 1);
        assert_eq!(var0_defs[0], d(0, 0));
    }

    #[test]
    fn test_out_of_range_bb_does_not_panic() {
        // Regression test: reaches_entry/reaches_exit/reaching_defs_at/
        // def_count_at/all_reaching_at used to index rd_in/rd_out directly
        // with `bb.0`, panicking on an out-of-range BBId. They must instead
        // report an empty/false result for adversarial indices.
        let cfg = linear_cfg(2);
        let blocks = vec![
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, None, vec![0])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        let bogus = BBId(9999);
        assert!(!rd.reaches_entry(d(0, 0), bogus));
        assert!(!rd.reaches_exit(d(0, 0), bogus));
        assert!(rd.reaching_defs_at(bogus, 0).is_empty());
        assert_eq!(rd.def_count_at(bogus, 0), 0);
        assert!(rd.all_reaching_at(bogus).is_empty());
    }

    #[test]
    fn test_def_id_equality() {
        let a = DefId::new(1, 0);
        let b = DefId::new(1, 0);
        let c = DefId::new(1, 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_rd_diamond_merge() {
        // 0→{1,2}→3. Each path defines var 0 differently; both should reach block 3.
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let blocks = vec![
            vec![],
            vec![instr(0, Some(d(0, 10)), vec![])],
            vec![instr(1, Some(d(0, 11)), vec![])],
            vec![],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        let defs_at_3 = rd.reaching_defs_at(BBId(3), 0);
        assert_eq!(
            defs_at_3.len(),
            2,
            "both defs of var 0 should reach block 3"
        );
    }

    #[test]
    fn test_rd_empty_blocks() {
        let cfg = linear_cfg(3);
        let blocks = vec![vec![], vec![], vec![]];
        let rd = reaching_definitions(&cfg, &blocks);
        for i in 0..3 {
            assert!(rd.rd_in[i].is_empty());
            assert!(rd.rd_out[i].is_empty());
        }
    }

    #[test]
    fn test_all_reaching_at_block1() {
        let cfg = linear_cfg(2);
        let blocks = vec![
            vec![
                instr(0, Some(d(0, 0)), vec![]),
                instr(1, Some(d(1, 0)), vec![]),
            ],
            vec![],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        let all = rd.all_reaching_at(BBId(1));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_killed_does_not_reach_successor() {
        // Block 0 defines var 0 twice; only second def should reach exit.
        let cfg = linear_cfg(1);
        let blocks = vec![vec![
            instr(0, Some(d(0, 0)), vec![]),
            instr(1, Some(d(0, 1)), vec![]),
        ]];
        let rd = reaching_definitions(&cfg, &blocks);
        // At exit of block 0, only serial 1 should survive.
        // Assert directly on rd_out[0] (the exit set) rather than
        // reaching_defs_at which reads rd_in (the entry set).
        let exit_defs = &rd.rd_out[0];
        // Serial 1 reaches; serial 0 is killed.
        assert!(exit_defs.iter().any(|d| d.serial == 1));
        assert!(!exit_defs.iter().any(|d| d.serial == 0));
    }
}

// ── ReachingDefs extended API ─────────────────────────────────────────────────

impl ReachingDefs {
    /// Return all variables (`var_ids`) whose definitions reach block `bb`.
    #[must_use]
    pub fn vars_reaching(&self, bb: BBId) -> HashSet<u32> {
        self.rd_in
            .get(bb.0)
            .map(|s| s.iter().map(|d| d.var_id).collect())
            .unwrap_or_default()
    }

    /// Whether any definition of `var_id` reaches the *exit* of block `bb`.
    #[must_use]
    pub fn var_reaches_exit(&self, var_id: u32, bb: BBId) -> bool {
        self.rd_out
            .get(bb.0)
            .is_some_and(|s| s.iter().any(|d| d.var_id == var_id))
    }

    /// Count the total number of definition-reachability pairs across all blocks.
    #[must_use]
    pub fn total_reach_pairs(&self) -> usize {
        self.rd_in.iter().map(HashSet::len).sum::<usize>()
            + self.rd_out.iter().map(HashSet::len).sum::<usize>()
    }

    /// All blocks at whose entry `def` is live.
    #[must_use]
    pub fn blocks_where_reachable(&self, def: DefId) -> Vec<BBId> {
        self.rd_in
            .iter()
            .enumerate()
            .filter(|(_, s)| s.contains(&def))
            .map(|(i, _)| BBId(i))
            .collect()
    }
}

// ── DefId helpers ─────────────────────────────────────────────────────────────

impl DefId {
    /// Whether this definition is for variable `var_id`.
    #[must_use]
    pub const fn is_for_var(&self, var_id: u32) -> bool {
        self.var_id == var_id
    }
}

// ── UseDefChain — map each use to the definitions reaching it ─────────────────

/// For each instruction that uses a variable, records the set of definitions
/// that reach that use point.
#[derive(Debug, Clone, Default)]
pub struct UseDefChain {
    /// Maps `(block_id, instr_id, operand_var_id)` → reaching defs.
    pub chains: HashMap<(usize, usize, u32), Vec<DefId>>,
}

impl UseDefChain {
    /// Build use-def chains from reaching definitions and the block instructions.
    #[must_use]
    pub fn build(rd: &ReachingDefs, blocks: &[Vec<NonSsaInstruction>]) -> Self {
        let mut chains: HashMap<(usize, usize, u32), Vec<DefId>> = HashMap::new();
        let n = blocks.len();
        debug_assert!(
            rd.rd_in.len() <= n,
            "reaching-defs IN map cannot have more entries than blocks"
        );

        for (bb_idx, block) in blocks.iter().enumerate() {
            // Process instructions in order, tracking the current reaching set.
            let mut current: HashSet<DefId> = rd.rd_in.get(bb_idx).cloned().unwrap_or_default();

            for instr in block {
                // Record reaching defs for each use in this instruction.
                for &use_var in &instr.uses {
                    let reaching: Vec<DefId> = current
                        .iter()
                        .filter(|d| d.var_id == use_var)
                        .copied()
                        .collect();
                    if !reaching.is_empty() {
                        chains.insert((bb_idx, instr.id, use_var), reaching);
                    }
                }
                // Apply the transfer function for this instruction.
                if let Some(def) = instr.def {
                    current.retain(|d| d.var_id != def.var_id);
                    current.insert(def);
                }
            }
        }

        Self { chains }
    }

    /// Return the definitions reaching use `(block, instr_id, var_id)`.
    #[must_use]
    pub fn defs_at_use(&self, block: usize, instr_id: usize, var_id: u32) -> &[DefId] {
        self.chains
            .get(&(block, instr_id, var_id))
            .map_or(&[], Vec::as_slice)
    }

    /// Total number of use-def chain entries.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.chains.len()
    }
}

// ── Extended reaching-defs tests ──────────────────────────────────────────────

#[cfg(test)]
mod reaching_extended_tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};

    fn d(var: u32, ser: u32) -> DefId {
        DefId::new(var, ser)
    }
    fn instr(id: usize, def: Option<DefId>, uses: Vec<u32>) -> NonSsaInstruction {
        NonSsaInstruction::new(id, def, uses)
    }

    #[test]
    fn vars_reaching_block1() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let blocks = vec![vec![instr(0, Some(d(5, 0)), vec![])], vec![]];
        let rd = reaching_definitions(&cfg, &blocks);
        let vars = rd.vars_reaching(BBId(1));
        assert!(vars.contains(&5));
    }

    #[test]
    fn var_reaches_exit() {
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let blocks = vec![vec![instr(0, Some(d(0, 0)), vec![])]];
        let rd = reaching_definitions(&cfg, &blocks);
        assert!(rd.var_reaches_exit(0, BBId(0)));
        assert!(!rd.var_reaches_exit(99, BBId(0)));
    }

    #[test]
    fn total_reach_pairs_positive() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let blocks = vec![vec![instr(0, Some(d(1, 0)), vec![])], vec![]];
        let rd = reaching_definitions(&cfg, &blocks);
        assert!(rd.total_reach_pairs() > 0);
    }

    #[test]
    fn blocks_where_reachable() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let blocks = vec![vec![instr(0, Some(d(0, 0)), vec![])], vec![]];
        let rd = reaching_definitions(&cfg, &blocks);
        let blocks_reach = rd.blocks_where_reachable(d(0, 0));
        assert!(blocks_reach.contains(&BBId(1)));
    }

    #[test]
    fn use_def_chain_build() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let blocks = vec![
            vec![instr(0, Some(d(0, 0)), vec![])],
            vec![instr(1, None, vec![0])],
        ];
        let rd = reaching_definitions(&cfg, &blocks);
        let udc = UseDefChain::build(&rd, &blocks);
        let defs = udc.defs_at_use(1, 1, 0);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0], d(0, 0));
    }

    #[test]
    fn use_def_chain_no_def_for_undefined_var() {
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let blocks = vec![vec![instr(0, None, vec![99])]];
        let rd = reaching_definitions(&cfg, &blocks);
        let udc = UseDefChain::build(&rd, &blocks);
        let defs = udc.defs_at_use(0, 0, 99);
        assert!(defs.is_empty());
    }

    #[test]
    fn def_id_is_for_var() {
        let d0 = d(3, 7);
        assert!(d0.is_for_var(3));
        assert!(!d0.is_for_var(4));
    }
}
