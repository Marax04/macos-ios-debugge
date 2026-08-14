//! `def_use` — def-use and use-def chain construction for SSA functions.
//!
//! # Relationship to [`crate::def_use_analysis`]
//! This module operates directly on [`crate::ssa::SsaFunction`] (SSA IR with
//! versioned [`crate::ssa::SsaVar`] operands).  It is the *SSA-aware* layer.
//! [`crate::def_use_analysis`] operates on its own standalone `Program`/`Block`
//! IR and builds a complete def-use pipeline including its own SSA construction
//! and reaching-definitions sub-analysis.  The two modules serve different callers
//! and are intentionally kept separate.
//!
//! In SSA form every variable has exactly one definition, making def-use chains
//! trivial: each def maps to all its uses.  Use-def chains are also trivial: each
//! use maps back to its unique reaching definition.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ssa::{SsaFunction, SsaVar};

// ── DefSite / UseSite ─────────────────────────────────────────────────────────

/// The unique definition point of an SSA variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefSite {
    pub var: SsaVar,
    /// Block that contains the definition.
    pub block: usize,
    /// Index within the block's instruction list (-1 for a φ-node definition).
    pub instr_idx: i32,
}

impl DefSite {
    #[must_use]
    pub const fn phi(var: SsaVar, block: usize) -> Self {
        Self {
            var,
            block,
            instr_idx: -1,
        }
    }

    #[must_use]
    pub fn instr(var: SsaVar, block: usize, idx: usize) -> Self {
        Self {
            var,
            block,
            instr_idx: i32::try_from(idx).unwrap_or(i32::MAX),
        }
    }

    /// True when this definition comes from a φ-node.
    #[must_use]
    pub const fn is_phi(&self) -> bool {
        self.instr_idx < 0
    }
}

/// One use point of an SSA variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UseSite {
    pub var: SsaVar,
    pub block: usize,
    /// Instruction index within the block.
    pub instr_idx: usize,
    /// Index within the instruction's use list.
    pub operand_idx: usize,
}

// ── DefUseChains ──────────────────────────────────────────────────────────────

/// Complete def-use and use-def chain structure for an SSA function.
#[derive(Debug, Clone, Default)]
pub struct DefUseChains {
    /// Maps each definition to all its use sites.
    pub def_to_uses: HashMap<DefSite, Vec<UseSite>>,
    /// Maps each use site to its unique definition.
    pub use_to_def: HashMap<UseSite, DefSite>,
}

impl DefUseChains {
    /// Build def-use chains from an SSA function.
    #[must_use]
    pub fn build(func: &SsaFunction) -> Self {
        let mut chains = Self::default();

        // ── Collect all definitions ────────────────────────────────────────
        // φ-node definitions.
        for (bb_idx, block) in func.blocks.iter().enumerate() {
            for phi in &block.phis {
                if let Some(ref ssa_def) = phi.result {
                    let def = DefSite::phi(ssa_def.clone(), bb_idx);
                    chains.def_to_uses.entry(def).or_default();
                }
            }
            // Instruction definitions.
            for (i, instr) in block.instrs.iter().enumerate() {
                if let Some(ref ssa_def) = instr.ssa_def {
                    let def = DefSite::instr(ssa_def.clone(), bb_idx, i);
                    chains.def_to_uses.entry(def).or_default();
                }
            }
        }

        // ── Collect all uses and link to definitions ───────────────────────
        // Build a var → def-site lookup for fast resolution.
        let def_map: HashMap<SsaVar, DefSite> = chains
            .def_to_uses
            .keys()
            .map(|d| (d.var.clone(), d.clone()))
            .collect();

        for (bb_idx, block) in func.blocks.iter().enumerate() {
            // φ-node argument uses.
            for phi in &block.phis {
                for (pred_idx, arg) in phi.args.iter().enumerate() {
                    if let Some(sv) = arg
                        && let Some(def) = def_map.get(sv) {
                            let use_site = UseSite {
                                var: sv.clone(),
                                block: bb_idx,
                                instr_idx: 0,
                                operand_idx: pred_idx,
                            };
                            chains
                                .def_to_uses
                                .entry(def.clone())
                                .or_default()
                                .push(use_site.clone());
                            chains.use_to_def.insert(use_site, def.clone());
                        }
                }
            }

            // Instruction uses.
            for (instr_idx, instr) in block.instrs.iter().enumerate() {
                for (op_idx, sv) in instr.ssa_uses.iter().enumerate() {
                    if let Some(def) = def_map.get(sv) {
                        let use_site = UseSite {
                            var: sv.clone(),
                            block: bb_idx,
                            instr_idx,
                            operand_idx: op_idx,
                        };
                        chains
                            .def_to_uses
                            .entry(def.clone())
                            .or_default()
                            .push(use_site.clone());
                        chains.use_to_def.insert(use_site, def.clone());
                    }
                }
            }
        }

        chains
    }

    /// Return all use sites for a definition.
    #[must_use]
    pub fn uses_of(&self, def: &DefSite) -> &[UseSite] {
        self.def_to_uses.get(def).map_or(&[], Vec::as_slice)
    }

    /// Return the definition for a use site (always `Some` in proper SSA form).
    #[must_use]
    pub fn def_of(&self, use_site: &UseSite) -> Option<&DefSite> {
        self.use_to_def.get(use_site)
    }

    /// True when `def` is a definition THIS CHAIN KNOWS and it has zero uses
    /// (dead definition — candidate for DCE).
    ///
    /// The membership check is the point. `uses_of` returns an empty slice
    /// both for a definition that is genuinely unused and for a `DefSite` the
    /// chain never saw, so testing only `uses_of(def).is_empty()` reported
    /// **any unknown definition as dead** — and this predicate's stated
    /// purpose is to authorise deleting code. A caller running DCE against a
    /// chain built from a different function, or from a stale snapshot, would
    /// have been told to remove live definitions.
    ///
    /// `build` inserts an entry for EVERY definition it sees (with an empty
    /// use list when there are none), so requiring membership costs no real
    /// dead definitions. The sibling `DuChains::is_dead` in `du_chains.rs`
    /// already does exactly this via its `def_site` map — the two
    /// implementations of one idea disagreed, and this is the one that was
    /// wrong.
    #[must_use]
    pub fn is_dead(&self, def: &DefSite) -> bool {
        self.def_to_uses.contains_key(def) && self.uses_of(def).is_empty()
    }

    /// Whether this chain contains `def` at all.
    ///
    /// Lets a caller tell "no uses" from "never seen" — see [`Self::is_dead`].
    #[must_use]
    pub fn knows_def(&self, def: &DefSite) -> bool {
        self.def_to_uses.contains_key(def)
    }

    /// Return all definitions that have exactly one use (candidates for inlining).
    #[must_use]
    pub fn single_use_defs(&self) -> Vec<&DefSite> {
        self.def_to_uses
            .iter()
            .filter(|(_, uses)| uses.len() == 1)
            .map(|(def, _)| def)
            .collect()
    }

    /// Return all dead definitions.
    #[must_use]
    pub fn dead_defs(&self) -> Vec<&DefSite> {
        self.def_to_uses
            .iter()
            .filter(|(_, uses)| uses.is_empty())
            .map(|(def, _)| def)
            .collect()
    }

    /// Count total use-sites registered.
    #[must_use]
    pub fn total_uses(&self) -> usize {
        self.use_to_def.len()
    }

    /// Count total definitions registered.
    #[must_use]
    pub fn total_defs(&self) -> usize {
        self.def_to_uses.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_dom::BBId;
    use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};

    fn make_ssa_var(name: &str, ver: u32) -> SsaVar {
        SsaVar::new(Var::new(name), ver)
    }

    fn make_ssa_func_with_one_def_one_use() -> SsaFunction {
        // Block 0: x_0 = ...
        // Block 1: ... = x_0 (use)
        use crate::cfg_dom::Cfg;
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));

        let x0 = make_ssa_var("x", 0);

        let def_instr = {
            let mut i = Instruction::new(0, Some(Var::new("x")), vec![]);
            i.ssa_def = Some(x0.clone());
            i
        };
        let use_instr = {
            let mut i = Instruction::new(1, None, vec![Var::new("x")]);
            i.ssa_uses = vec![x0];
            i
        };

        SsaFunction::new(cfg, &vec![vec![def_instr], vec![use_instr]])
    }

    #[test]
    fn test_build_chains_one_def_one_use() {
        let func = make_ssa_func_with_one_def_one_use();
        let chains = DefUseChains::build(&func);
        assert_eq!(chains.total_defs(), 1);
        assert_eq!(chains.total_uses(), 1);
    }

    #[test]
    fn test_uses_of_def() {
        let func = make_ssa_func_with_one_def_one_use();
        let chains = DefUseChains::build(&func);

        let def = DefSite::instr(make_ssa_var("x", 0), 0, 0);
        let uses = chains.uses_of(&def);
        assert_eq!(uses.len(), 1);
    }

    #[test]
    fn test_def_of_use() {
        let func = make_ssa_func_with_one_def_one_use();
        let chains = DefUseChains::build(&func);

        let use_site = UseSite {
            var: make_ssa_var("x", 0),
            block: 1,
            instr_idx: 0,
            operand_idx: 0,
        };
        assert!(chains.def_of(&use_site).is_some());
    }

    #[test]
    fn test_is_dead_no_uses() {
        use crate::cfg_dom::Cfg;
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let mut def_instr = Instruction::new(0, Some(Var::new("y")), vec![]);
        def_instr.ssa_def = Some(make_ssa_var("y", 0));
        let func = SsaFunction::new(cfg, &vec![vec![def_instr]]);
        let chains = DefUseChains::build(&func);
        let def = DefSite::instr(make_ssa_var("y", 0), 0, 0);
        assert!(chains.is_dead(&def));
    }

    #[test]
    fn test_single_use_defs() {
        let func = make_ssa_func_with_one_def_one_use();
        let chains = DefUseChains::build(&func);
        let single = chains.single_use_defs();
        assert_eq!(single.len(), 1);
    }

    #[test]
    fn test_dead_defs_returns_empty_when_all_used() {
        let func = make_ssa_func_with_one_def_one_use();
        let chains = DefUseChains::build(&func);
        // The one def IS used, so dead_defs should be empty.
        let dead = chains.dead_defs();
        assert!(dead.is_empty());
    }

    #[test]
    fn test_def_site_is_phi() {
        let d = DefSite::phi(make_ssa_var("a", 0), 1);
        assert!(d.is_phi());
        let d2 = DefSite::instr(make_ssa_var("a", 0), 1, 0);
        assert!(!d2.is_phi());
    }

    #[test]
    fn test_multiple_uses_of_same_def() {
        use crate::cfg_dom::Cfg;
        use crate::ssa::SsaFunction;
        // x_0 defined in block 0, used twice in block 1.
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let x0 = make_ssa_var("x", 0);
        let mut def_instr = Instruction::new(0, Some(Var::new("x")), vec![]);
        def_instr.ssa_def = Some(x0.clone());
        let mut use_instr = Instruction::new(1, None, vec![Var::new("x"), Var::new("x")]);
        use_instr.ssa_uses = vec![x0.clone(), x0.clone()];
        let func = SsaFunction::new(cfg, &vec![vec![def_instr], vec![use_instr]]);
        let chains = DefUseChains::build(&func);
        let def = DefSite::instr(x0, 0, 0);
        assert_eq!(chains.uses_of(&def).len(), 2);
        assert!(!chains.is_dead(&def));
    }

    #[test]
    fn test_dead_def_when_no_uses() {
        use crate::cfg_dom::Cfg;
        use crate::ssa::SsaFunction;
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let mut instr = Instruction::new(0, Some(Var::new("z")), vec![]);
        instr.ssa_def = Some(make_ssa_var("z", 1));
        let func = SsaFunction::new(cfg, &vec![vec![instr]]);
        let chains = DefUseChains::build(&func);
        let dead = chains.dead_defs();
        assert_eq!(dead.len(), 1);
        assert!(!dead[0].is_phi());
    }

    #[test]
    fn test_use_site_properties() {
        let us = UseSite {
            var: make_ssa_var("a", 2),
            block: 3,
            instr_idx: 5,
            operand_idx: 1,
        };
        assert_eq!(us.block, 3);
        assert_eq!(us.instr_idx, 5);
        assert_eq!(us.operand_idx, 1);
    }
}

// ── WebDecomposition ─────────────────────────────────────────────────────────

/// A *web* is a maximal connected component of the def-use graph restricted to
/// one base variable.  Webs are used in copy-propagation and interference-graph
/// construction.
#[derive(Debug, Clone, Default)]
pub struct WebDecomposition {
    /// Maps each `DefSite` to a web index.
    pub def_to_web: HashMap<DefSite, usize>,
    /// Maps each `UseSite` to a web index.
    pub use_to_web: HashMap<UseSite, usize>,
    /// Number of distinct webs.
    pub web_count: usize,
}

impl WebDecomposition {
    /// Compute web decomposition from def-use chains using union-find.
    #[must_use]
    pub fn compute(chains: &DefUseChains) -> Self {
        fn find(parent: &mut Vec<usize>, x: usize) -> usize {
            if parent[x] != x {
                parent[x] = find(parent, parent[x]);
            }
            parent[x]
        }

        fn union(parent: &mut Vec<usize>, x: usize, y: usize) {
            let rx = find(parent, x);
            let ry = find(parent, y);
            if rx != ry {
                parent[rx] = ry;
            }
        }

        // Assign each definition a unique index.
        //
        // `chains.def_to_uses` is a `std::collections::HashMap` (randomly
        // seeded per-process), so iterating its keys directly would make the
        // union-find processing order vary from run to run on identical
        // input. Since web ids are assigned in first-encountered order over
        // `defs`, that would make the web id assigned to a given definition
        // nondeterministic across runs (the partition itself would still be
        // correct, but which numeric id represents which class would not
        // be reproducible). Sort by a stable key first so id assignment is
        // deterministic.
        let mut defs: Vec<&DefSite> = chains.def_to_uses.keys().collect();
        defs.sort_unstable_by(|a, b| {
            (a.block, a.instr_idx, &a.var.base.0, a.var.version).cmp(&(
                b.block,
                b.instr_idx,
                &b.var.base.0,
                b.var.version,
            ))
        });
        let def_to_idx: HashMap<*const DefSite, usize> = defs
            .iter()
            .enumerate()
            .map(|(i, d)| (std::ptr::from_ref(*d), i))
            .collect();
        let n = defs.len();
        let mut parent: Vec<usize> = (0..n).collect();

        // For each variable base, union all defs of that variable together
        // if they share a use (i.e. the use of one flows into the other's
        // block via a phi-node).  Simplified: union all defs of same base var.
        let mut base_to_def_indices: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, def) in defs.iter().enumerate() {
            base_to_def_indices
                .entry(def.var.base.0.clone())
                .or_default()
                .push(i);
        }

        for indices in base_to_def_indices.values() {
            for w in indices.windows(2) {
                union(&mut parent, w[0], w[1]);
            }
        }

        // Sanity check: every definition we just iterated over must have a
        // unique index in `def_to_idx`. This guards against accidental
        // duplicate keys in the chain map.
        debug_assert_eq!(
            def_to_idx.len(),
            n,
            "def_to_idx should contain exactly one entry per def"
        );
        for (i, def) in defs.iter().enumerate() {
            debug_assert_eq!(
                def_to_idx.get(&std::ptr::from_ref(*def)).copied(),
                Some(i),
                "def_to_idx must map each def to its enumeration index"
            );
        }

        // Assign final web ids.
        let mut root_to_web: HashMap<usize, usize> = HashMap::new();
        let mut web_count = 0;
        let mut def_to_web: HashMap<DefSite, usize> = HashMap::new();

        for (i, def) in defs.iter().enumerate() {
            let root = find(&mut parent, i);
            let web_id = *root_to_web.entry(root).or_insert_with(|| {
                let id = web_count;
                web_count += 1;
                id
            });
            def_to_web.insert((*def).clone(), web_id);
        }

        // Map uses to webs through their definitions.
        let mut use_to_web: HashMap<UseSite, usize> = HashMap::new();
        for (use_site, def_site) in &chains.use_to_def {
            if let Some(&web_id) = def_to_web.get(def_site) {
                use_to_web.insert(use_site.clone(), web_id);
            }
        }

        Self {
            def_to_web,
            use_to_web,
            web_count,
        }
    }

    /// Return all definition sites belonging to web `id`.
    #[must_use]
    pub fn defs_in_web(&self, id: usize) -> Vec<&DefSite> {
        self.def_to_web
            .iter()
            .filter(|&(_, &w)| w == id)
            .map(|(d, _)| d)
            .collect()
    }

    /// Return all use sites belonging to web `id`.
    #[must_use]
    pub fn uses_in_web(&self, id: usize) -> Vec<&UseSite> {
        self.use_to_web
            .iter()
            .filter(|&(_, &w)| w == id)
            .map(|(u, _)| u)
            .collect()
    }
}

// ── CopyPropagation helper ────────────────────────────────────────────────────

/// Candidate for copy-propagation: an instruction of the form `x = y` where
/// `y` has exactly one definition and `x` has exactly one use.
#[derive(Debug, Clone)]
pub struct CopyPropCandidate {
    pub def: DefSite,
    pub use_site: UseSite,
    pub src_var: SsaVar,
    pub dst_var: SsaVar,
}

impl DefUseChains {
    /// Find all copy-propagation candidates: single-use defs of the form
    /// `dst = src` where the use site is in the same block or a dominated block.
    #[must_use]
    pub fn copy_prop_candidates(&self) -> Vec<CopyPropCandidate> {
        let mut candidates = Vec::new();
        for (def, uses) in &self.def_to_uses {
            if uses.len() != 1 {
                continue;
            }
            let use_site = &uses[0];
            candidates.push(CopyPropCandidate {
                def: def.clone(),
                use_site: use_site.clone(),
                src_var: def.var.clone(),
                dst_var: use_site.var.clone(),
            });
        }
        candidates
    }

    /// Number of definitions with more than N uses (highly-used defs).
    #[must_use]
    pub fn hot_defs(&self, min_uses: usize) -> Vec<(&DefSite, usize)> {
        self.def_to_uses
            .iter()
            .filter(|(_, uses)| uses.len() >= min_uses)
            .map(|(def, uses)| (def, uses.len()))
            .collect()
    }

    /// Summary: total defs, uses, dead defs, and single-use defs.
    #[must_use]
    pub fn summary(&self) -> DefUseSummary {
        DefUseSummary {
            total_defs: self.total_defs(),
            total_uses: self.total_uses(),
            dead_defs: self.dead_defs().len(),
            single_use_defs: self.single_use_defs().len(),
            phi_defs: self.def_to_uses.keys().filter(|d| d.is_phi()).count(),
        }
    }
}

/// Summary statistics for def-use chains.
#[derive(Debug, Clone)]
pub struct DefUseSummary {
    pub total_defs: usize,
    pub total_uses: usize,
    pub dead_defs: usize,
    pub single_use_defs: usize,
    pub phi_defs: usize,
}

// ── Extended tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod def_use_extended_tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};

    use crate::test_util::sv;

    fn make_linear_ssa(defs: Vec<(&str, u32)>) -> SsaFunction {
        let n = defs.len() + 1;
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        let cfg = Cfg::new(n, succs, BBId(0), BBId(n - 1));
        let mut block_instrs: Vec<Vec<Instruction>> = vec![vec![]; n];
        for (i, &(name, ver)) in defs.iter().enumerate() {
            let mut instr = Instruction::new(i, Some(Var::new(name)), vec![]);
            instr.ssa_def = Some(sv(name, ver));
            block_instrs[i].push(instr);
        }
        SsaFunction::new(cfg, &block_instrs)
    }

    #[test]
    fn web_decomp_single_var_one_web() {
        let func = make_linear_ssa(vec![("x", 0), ("x", 1)]);
        let chains = DefUseChains::build(&func);
        let webs = WebDecomposition::compute(&chains);
        // Both defs of x form one web.
        assert_eq!(webs.web_count, 1);
    }

    #[test]
    fn web_decomp_two_vars_two_webs() {
        let func = make_linear_ssa(vec![("x", 0), ("y", 0)]);
        let chains = DefUseChains::build(&func);
        let webs = WebDecomposition::compute(&chains);
        assert_eq!(webs.web_count, 2);
    }

    #[test]
    fn web_decomp_defs_in_web() {
        let func = make_linear_ssa(vec![("x", 0), ("x", 1)]);
        let chains = DefUseChains::build(&func);
        let webs = WebDecomposition::compute(&chains);
        let w0 = webs.defs_in_web(0);
        assert!(!w0.is_empty());
    }

    #[test]
    fn web_decomp_is_deterministic_across_runs() {
        // `WebDecomposition::compute` used to iterate `def_to_uses.keys()`
        // (a `HashMap`) directly to assign web ids, so the id assigned to a
        // given definition could vary run-to-run depending on the map's
        // random iteration order even though the underlying partition into
        // webs was always correct. Verify that repeated computation from the
        // same chains yields the exact same def -> web id mapping.
        let func = make_linear_ssa(vec![("x", 0), ("x", 1), ("y", 0), ("z", 0), ("z", 1)]);
        let chains = DefUseChains::build(&func);

        let first = WebDecomposition::compute(&chains);
        for _ in 0..20 {
            let again = WebDecomposition::compute(&chains);
            assert_eq!(again.web_count, first.web_count);
            assert_eq!(again.def_to_web, first.def_to_web);
        }
    }

    #[test]
    fn copy_prop_candidates_single_use() {
        let n = 2;
        let succs: Vec<Vec<BBId>> = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(n, succs, BBId(0), BBId(1));
        let x0 = sv("x", 0);
        let mut def_instr = Instruction::new(0, Some(Var::new("x")), vec![]);
        def_instr.ssa_def = Some(x0.clone());
        let mut use_instr = Instruction::new(1, None, vec![Var::new("x")]);
        use_instr.ssa_uses = vec![x0];
        let func = SsaFunction::new(cfg, &vec![vec![def_instr], vec![use_instr]]);
        let chains = DefUseChains::build(&func);
        let candidates = chains.copy_prop_candidates();
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn hot_defs_filter() {
        let n = 2;
        let succs: Vec<Vec<BBId>> = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(n, succs, BBId(0), BBId(1));
        let x0 = sv("x", 0);
        let mut def_instr = Instruction::new(0, Some(Var::new("x")), vec![]);
        def_instr.ssa_def = Some(x0.clone());
        let mut use_instr = Instruction::new(1, None, vec![Var::new("x"), Var::new("x")]);
        use_instr.ssa_uses = vec![x0.clone(), x0];
        let func = SsaFunction::new(cfg, &vec![vec![def_instr], vec![use_instr]]);
        let chains = DefUseChains::build(&func);
        let hot = chains.hot_defs(2);
        assert_eq!(hot.len(), 1);
    }

    #[test]
    fn summary_is_consistent() {
        let func = make_linear_ssa(vec![("x", 0)]);
        let chains = DefUseChains::build(&func);
        let s = chains.summary();
        assert_eq!(s.total_defs, chains.total_defs());
        assert_eq!(s.total_uses, chains.total_uses());
    }

    #[test]
    fn dead_def_summary_matches_dead_defs_len() {
        let func = make_linear_ssa(vec![("x", 0), ("y", 1)]);
        let chains = DefUseChains::build(&func);
        let s = chains.summary();
        assert_eq!(s.dead_defs, chains.dead_defs().len());
    }

    #[test]
    fn def_site_instr_is_not_phi() {
        let d = DefSite::instr(sv("x", 0), 0, 0);
        assert!(!d.is_phi());
        assert_eq!(d.instr_idx, 0);
    }

    #[test]
    fn def_site_phi_has_negative_idx() {
        let d = DefSite::phi(sv("x", 0), 2);
        assert!(d.is_phi());
        assert!(d.instr_idx < 0);
    }

    #[test]
    fn uses_in_web_matches_def_uses() {
        // x_0 defined in block 0, used once in block 1 -> web should contain
        // both the def's use-site and be non-empty.
        let n = 2;
        let succs: Vec<Vec<BBId>> = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(n, succs, BBId(0), BBId(1));
        let x0 = sv("x", 0);
        let mut def_instr = Instruction::new(0, Some(Var::new("x")), vec![]);
        def_instr.ssa_def = Some(x0.clone());
        let mut use_instr = Instruction::new(1, None, vec![Var::new("x")]);
        use_instr.ssa_uses = vec![x0];
        let func = SsaFunction::new(cfg, &vec![vec![def_instr], vec![use_instr]]);
        let chains = DefUseChains::build(&func);
        let webs = WebDecomposition::compute(&chains);
        assert_eq!(webs.web_count, 1);
        let uses = webs.uses_in_web(0);
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].block, 1);
        // A non-existent web id must yield an empty result, not panic.
        assert!(webs.uses_in_web(99).is_empty());
    }

    #[test]
    fn summary_phi_defs_counts_only_phis() {
        // Block 0 has a phi def of `p` and block 1 has a normal instr def of `q`.
        let succs: Vec<Vec<BBId>> = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        use crate::ssa::PhiNode;
        let mut func = SsaFunction::new(cfg, &vec![vec![]]);
        let phi_result = sv("p", 0);
        let mut phi = PhiNode::new(Var::new("p"), 0);
        phi.result = Some(phi_result);
        func.blocks[0].phis.push(phi);
        let mut instr = Instruction::new(0, Some(Var::new("q")), vec![]);
        instr.ssa_def = Some(sv("q", 0));
        func.blocks[0].instrs.push(instr);

        let chains = DefUseChains::build(&func);
        let s = chains.summary();
        assert_eq!(s.phi_defs, 1);
        assert_eq!(s.total_defs, 2);
    }

    #[test]
    fn chains_total_empty_function() {
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let func = SsaFunction::new(cfg, &vec![vec![]]);
        let chains = DefUseChains::build(&func);
        assert_eq!(chains.total_defs(), 0);
        assert_eq!(chains.total_uses(), 0);
    }
}

#[cfg(test)]
mod dead_definition_soundness {
    use super::*;
    use crate::ssa::{SsaVar, Var};

    /// A definition this chain never saw must NOT be reported as dead.
    ///
    /// `uses_of` returns an empty slice both for a genuinely unused definition
    /// and for a `DefSite` the chain never contained, so `is_dead` used to
    /// answer `true` for ANY unknown definition — and its documented purpose
    /// is to authorise dead-code elimination. Running DCE against a chain
    /// built from a different function, or a stale one, would have removed
    /// live definitions.
    #[test]
    fn an_unknown_definition_is_not_dead() {
        let chains = DefUseChains::default();
        let stranger = DefSite::instr(SsaVar::new(Var::new("never_seen"), 7), 3, 4);

        assert!(!chains.knows_def(&stranger), "the fixture must not contain it");
        assert!(
            !chains.is_dead(&stranger),
            "a definition the chain never saw is unknown, not dead"
        );
    }

    /// Positive control: a definition the chain DOES contain, with no uses, is
    /// still reported as dead. Without this, returning `false` unconditionally
    /// would also satisfy the test above and silently disable DCE.
    #[test]
    fn a_known_unused_definition_is_still_dead() {
        let mut chains = DefUseChains::default();
        let unused = DefSite::instr(SsaVar::new(Var::new("x"), 0), 0, 0);
        let used = DefSite::instr(SsaVar::new(Var::new("y"), 0), 0, 1);

        // `build` inserts an entry for every definition it sees, empty when
        // the definition has no uses; mirror that here.
        chains.def_to_uses.entry(unused.clone()).or_default();
        chains
            .def_to_uses
            .entry(used.clone())
            .or_default()
            .push(UseSite {
                var: SsaVar::new(Var::new("y"), 0),
                block: 0,
                instr_idx: 2,
                operand_idx: 0,
            });

        assert!(chains.knows_def(&unused));
        assert!(chains.is_dead(&unused), "a known definition with no uses is dead");
        assert!(!chains.is_dead(&used), "a definition with a use is not dead");
    }
}
