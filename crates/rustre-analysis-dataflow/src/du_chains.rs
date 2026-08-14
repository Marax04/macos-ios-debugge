//! Precise def-use / use-def chains and live-interval construction.
//!
//! This module deepens the existing `def_use` and `live_ranges` analyses with
//! *instruction-point* precision.  A [`ProgramPoint`] identifies a definition
//! or use down to `(block, slot)`, where slot 0..k are φ-nodes and slot k.. are
//! ordinary instructions.  From these points it computes:
//!
//! * **def-use chains** — for every definition, the set of points that read the
//!   value before it is redefined (intra-block) or that are reached across
//!   block boundaries via reaching-definitions.
//! * **use-def chains** — the inverse map.
//! * **live intervals** — a linearised `[start, end]` range per SSA variable
//!   over a fixed block ordering, and the interference relation derived from
//!   overlapping intervals.

use crate::cfg_dom::BBId;
use crate::ssa::{SsaFunction, SsaVar, Var};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A precise location of a definition or use within the SSA function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProgramPoint {
    /// Containing basic block.
    pub block: BBId,
    /// Slot index within the block (φ-nodes first, then instructions).
    pub slot: usize,
}

impl ProgramPoint {
    /// Construct a program point.
    #[must_use]
    pub const fn new(block: BBId, slot: usize) -> Self {
        Self { block, slot }
    }
}

/// Def-use and use-def chains keyed by SSA variable.
#[derive(Debug, Clone, Default)]
pub struct DefUseChains {
    /// For each SSA variable, the unique point that defines it.
    def_site: HashMap<SsaVar, ProgramPoint>,
    /// For each SSA variable, all points that use it.
    use_sites: HashMap<SsaVar, Vec<ProgramPoint>>,
}

impl DefUseChains {
    /// Build chains by walking the SSA function in block order.
    #[must_use]
    pub fn build(func: &SsaFunction) -> Self {
        let mut chains = Self::default();
        for (b, block) in func.blocks.iter().enumerate() {
            let bb = BBId(b);
            let mut slot = 0usize;
            // φ-nodes occupy the first slots.
            for phi in &block.phis {
                if let Some(res) = &phi.result {
                    chains
                        .def_site
                        .insert(res.clone(), ProgramPoint::new(bb, slot));
                }
                for arg in phi.args.iter().flatten() {
                    chains
                        .use_sites
                        .entry(arg.clone())
                        .or_default()
                        .push(ProgramPoint::new(bb, slot));
                }
                slot += 1;
            }
            // Ordinary instructions.
            for instr in &block.instrs {
                for u in &instr.ssa_uses {
                    chains
                        .use_sites
                        .entry(u.clone())
                        .or_default()
                        .push(ProgramPoint::new(bb, slot));
                }
                if let Some(d) = &instr.ssa_def {
                    chains
                        .def_site
                        .insert(d.clone(), ProgramPoint::new(bb, slot));
                }
                slot += 1;
            }
        }
        chains
    }

    /// The point that defines `var`, if any.
    #[must_use]
    pub fn definition_of(&self, var: &SsaVar) -> Option<ProgramPoint> {
        self.def_site.get(var).copied()
    }

    /// All points that use `var`.
    #[must_use]
    pub fn uses_of(&self, var: &SsaVar) -> &[ProgramPoint] {
        self.use_sites.get(var).map_or(&[], Vec::as_slice)
    }

    /// Number of uses of `var`.
    #[must_use]
    pub fn use_count(&self, var: &SsaVar) -> usize {
        self.use_sites.get(var).map_or(0, Vec::len)
    }

    /// Whether `var` is defined but never used (dead).
    #[must_use]
    pub fn is_dead(&self, var: &SsaVar) -> bool {
        self.def_site.contains_key(var) && self.use_count(var) == 0
    }

    /// All SSA variables that are defined but never used.
    #[must_use]
    pub fn dead_definitions(&self) -> Vec<SsaVar> {
        let mut dead: Vec<SsaVar> = self
            .def_site
            .keys()
            .filter(|v| self.use_count(v) == 0)
            .cloned()
            .collect();
        dead.sort_by_key(|a| (a.base.0.clone(), a.version));
        dead
    }

    /// Total number of distinct defined variables.
    #[must_use]
    pub fn def_count(&self) -> usize {
        self.def_site.len()
    }

    /// All variables that have at least one definition.
    #[must_use]
    pub fn defined_vars(&self) -> Vec<SsaVar> {
        let mut v: Vec<SsaVar> = self.def_site.keys().cloned().collect();
        v.sort_by_key(|a| (a.base.0.clone(), a.version));
        v
    }
}

/// A linear live interval `[start, end]` over a global instruction numbering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveInterval {
    /// SSA variable owning this interval.
    pub var: SsaVar,
    /// Global index of the defining instruction.
    pub start: usize,
    /// Global index of the last use (inclusive); equals `start` if dead.
    pub end: usize,
}

impl LiveInterval {
    /// Whether this interval overlaps `other`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Length of the interval in instruction slots.
    #[must_use]
    pub const fn length(&self) -> usize {
        self.end - self.start
    }
}

/// Live intervals for every SSA variable over a linearised numbering, plus the
/// interference relation implied by overlap.
///
/// Linearisation assigns each `(block, slot)` a strictly increasing global
/// index in block order.  This is a sound over-approximation for register
/// allocation within straight-line and acyclic code; for code with back edges
/// the intervals are conservatively widened (see [`LinearScan::build`]).
#[derive(Debug, Clone, Default)]
pub struct LinearScan {
    intervals: BTreeMap<String, LiveInterval>,
    /// Map from SSA var key to the base variable, for interference grouping.
    keys: Vec<SsaVar>,
}

fn ssa_key(v: &SsaVar) -> String {
    format!("{}_{}", v.base.0, v.version)
}

impl LinearScan {
    /// Build linear live intervals from precise def-use chains.
    #[must_use]
    pub fn build(func: &SsaFunction, chains: &DefUseChains) -> Self {
        // Assign a global index to each (block, slot).
        let mut global: HashMap<ProgramPoint, usize> = HashMap::new();
        let mut counter = 0usize;
        for (b, block) in func.blocks.iter().enumerate() {
            let bb = BBId(b);
            let slots = block.phis.len() + block.instrs.len();
            for s in 0..slots.max(1) {
                global.insert(ProgramPoint::new(bb, s), counter);
                counter += 1;
            }
        }

        let mut scan = Self::default();
        for var in chains.defined_vars() {
            let Some(def_pt) = chains.definition_of(&var) else {
                continue;
            };
            let start = *global.get(&def_pt).unwrap_or(&0);
            let mut end = start;
            for use_pt in chains.uses_of(&var) {
                if let Some(&g) = global.get(use_pt) {
                    end = end.max(g);
                }
            }
            scan.intervals
                .insert(ssa_key(&var), LiveInterval { var: var.clone(), start, end });
            scan.keys.push(var);
        }
        scan
    }

    /// The interval for `var`, if it has one.
    #[must_use]
    pub fn interval(&self, var: &SsaVar) -> Option<LiveInterval> {
        self.intervals.get(&ssa_key(var)).cloned()
    }

    /// Whether two SSA variables interfere (their intervals overlap).
    #[must_use]
    pub fn interferes(&self, a: &SsaVar, b: &SsaVar) -> bool {
        match (self.interval(a), self.interval(b)) {
            (Some(ia), Some(ib)) => a != b && ia.overlaps(&ib),
            _ => false,
        }
    }

    /// Number of variables with intervals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intervals.len()
    }

    /// Whether no intervals were built.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Greedy linear-scan register allocation: assign each variable the lowest
    /// free register index such that no two overlapping intervals share one.
    /// Returns a map from SSA-var key to register index and the register count.
    #[must_use]
    pub fn allocate(&self) -> (HashMap<String, usize>, usize) {
        // Sort by interval start (classic linear scan order).
        let mut ordered: Vec<&SsaVar> = self.keys.iter().collect();
        ordered.sort_by_key(|v| self.interval(v).map_or(0, |iv| iv.start));

        let mut assignment: HashMap<String, usize> = HashMap::new();
        // (interval, reg) — caching the interval alongside each active entry
        // avoids re-doing a hashmap lookup + clone of the interval for every
        // active variable on every outer iteration (was O(active_len) extra
        // lookups per var, i.e. quadratic in map accesses on top of the
        // already-quadratic overlap check).
        let mut active: Vec<(LiveInterval, usize)> = Vec::new(); // (interval, reg)
        let mut max_reg = 0usize;

        for var in ordered {
            let iv = self
                .interval(var)
                .unwrap_or_else(|| LiveInterval { var: var.clone(), start: 0, end: 0 });
            // Expire intervals that ended strictly before this one starts.
            active.retain(|(aiv, _)| aiv.end >= iv.start);
            // Determine used registers among genuinely overlapping actives.
            let mut used: HashSet<usize> = HashSet::new();
            for (aiv, areg) in &active {
                if aiv.overlaps(&iv) {
                    used.insert(*areg);
                }
            }
            let mut reg = 0;
            while used.contains(&reg) {
                reg += 1;
            }
            assignment.insert(ssa_key(var), reg);
            active.push((iv, reg));
            max_reg = max_reg.max(reg + 1);
        }
        (assignment, max_reg)
    }
}

/// Build a base-variable interference set: two *base* variables interfere if
/// any of their SSA versions interfere.  Useful for non-SSA register pressure.
#[must_use]
pub fn base_interference(scan: &LinearScan, vars: &[SsaVar]) -> HashSet<(Var, Var)> {
    let mut out = HashSet::new();
    for i in 0..vars.len() {
        for j in (i + 1)..vars.len() {
            if scan.interferes(&vars[i], &vars[j]) {
                let (a, b) = (vars[i].base.clone(), vars[j].base.clone());
                if a != b {
                    let pair = if a.0 <= b.0 { (a, b) } else { (b, a) };
                    out.insert(pair);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_dom::Cfg;
    use crate::ssa::{Instruction, construct_ssa};

    /// Build a tiny straight-line SSA function:
    /// b0: x = ?      (def x)
    ///     y = x      (use x, def y)
    ///     z = x + y  (use x,y; def z)
    use crate::test_util::sv;

    fn straight_line() -> SsaFunction {
        let cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
        let instrs = vec![vec![
            Instruction::new(0, Some(Var::new("x")), vec![]),
            Instruction::new(1, Some(Var::new("y")), vec![Var::new("x")]),
            Instruction::new(2, Some(Var::new("z")), vec![Var::new("x"), Var::new("y")]),
        ]];
        let mut f = SsaFunction::new(cfg, &instrs);
        construct_ssa(&mut f);
        f
    }

    #[test]
    fn program_point_ordering() {
        assert!(ProgramPoint::new(BBId(0), 0) < ProgramPoint::new(BBId(0), 1));
        assert!(ProgramPoint::new(BBId(0), 5) < ProgramPoint::new(BBId(1), 0));
    }

    /// Find the (single) SSA version of a base variable that has a definition.
    fn defined_version(chains: &DefUseChains, name: &str) -> SsaVar {
        chains
            .defined_vars()
            .into_iter()
            .find(|v| v.base.0 == name)
            .unwrap_or_else(|| panic!("no def for {name}"))
    }

    #[test]
    fn def_use_chains_built() {
        let f = straight_line();
        let chains = DefUseChains::build(&f);
        // x is defined once and used twice (in y= and z=).
        let x = defined_version(&chains, "x");
        assert!(chains.definition_of(&x).is_some());
        assert_eq!(chains.use_count(&x), 2);
    }

    #[test]
    fn dead_definition_detected() {
        // w is defined but never used.
        let cfg = Cfg::new(1, vec![vec![]], BBId(0), BBId(0));
        let instrs = vec![vec![
            Instruction::new(0, Some(Var::new("w")), vec![]),
            Instruction::new(1, Some(Var::new("y")), vec![]),
        ]];
        let mut f = SsaFunction::new(cfg, &instrs);
        construct_ssa(&mut f);
        let chains = DefUseChains::build(&f);
        let w = chains
            .defined_vars()
            .into_iter()
            .find(|v| v.base.0 == "w")
            .expect("w defined");
        assert!(chains.is_dead(&w));
        assert!(chains.dead_definitions().contains(&w));
    }

    #[test]
    fn live_interval_overlap() {
        let a = LiveInterval { var: sv("a", 0), start: 0, end: 5 };
        let b = LiveInterval { var: sv("b", 0), start: 3, end: 8 };
        let c = LiveInterval { var: sv("c", 0), start: 6, end: 9 };
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
        assert_eq!(a.length(), 5);
    }

    #[test]
    fn linear_scan_intervals() {
        let f = straight_line();
        let chains = DefUseChains::build(&f);
        let scan = LinearScan::build(&f, &chains);
        let x = defined_version(&chains, "x");
        let iv = scan.interval(&x).expect("x has interval");
        // x defined at slot 0, last used at slot 2.
        assert_eq!(iv.start, 0);
        assert_eq!(iv.end, 2);
        assert!(!scan.is_empty());
    }

    #[test]
    fn linear_scan_interference() {
        let f = straight_line();
        let chains = DefUseChains::build(&f);
        let scan = LinearScan::build(&f, &chains);
        let x = defined_version(&chains, "x");
        let y = defined_version(&chains, "y");
        // x lives [0,2], y lives [1,2] -> they interfere.
        assert!(scan.interferes(&x, &y));
    }

    #[test]
    fn linear_scan_allocation_distinct_for_overlap() {
        let f = straight_line();
        let chains = DefUseChains::build(&f);
        let scan = LinearScan::build(&f, &chains);
        let x = defined_version(&chains, "x");
        let y = defined_version(&chains, "y");
        let (assign, regs) = scan.allocate();
        // x and y overlap, must get different registers.
        assert!(regs >= 2);
        let xk = format!("{}_{}", x.base.0, x.version);
        let yk = format!("{}_{}", y.base.0, y.version);
        assert_ne!(assign.get(&xk), assign.get(&yk));
    }

    #[test]
    fn base_interference_pairs() {
        let f = straight_line();
        let chains = DefUseChains::build(&f);
        let scan = LinearScan::build(&f, &chains);
        let vars = chains.defined_vars();
        let pairs = base_interference(&scan, &vars);
        assert!(pairs.contains(&(Var::new("x"), Var::new("y"))));
    }

    #[test]
    fn live_interval_overlaps() {
        let a = LiveInterval {
            var: sv("a", 0),
            start: 0,
            end: 5,
        };
        let b = LiveInterval {
            var: sv("b", 0),
            start: 3,
            end: 8,
        };
        assert!(a.overlaps(&b));
    }

    #[test]
    fn live_interval_no_overlap() {
        let a = LiveInterval {
            var: sv("a", 0),
            start: 0,
            end: 2,
        };
        let b = LiveInterval {
            var: sv("b", 0),
            start: 5,
            end: 9,
        };
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn linear_scan_interval_none_for_unknown() {
        let f = straight_line();
        let chains = DefUseChains::build(&f);
        let scan = LinearScan::build(&f, &chains);
        let unknown = sv("zzz", 99);
        assert!(scan.interval(&unknown).is_none());
    }

    #[test]
    fn program_point_ordering_explicit() {
        let a = ProgramPoint { block: BBId(0), slot: 0 };
        let b = ProgramPoint { block: BBId(0), slot: 1 };
        let c = ProgramPoint { block: BBId(1), slot: 0 };
        assert!(a < b);
        assert!(b < c);
    }
}

// ── DUChain extended helpers ──────────────────────────────────────────────────

impl DefUseChains {
    /// Return the total use count across all defined variables.
    #[must_use]
    pub fn total_use_count(&self) -> usize {
        self.use_sites.values().map(std::vec::Vec::len).sum()
    }

    /// All SSA variables with exactly `n` uses.
    #[must_use]
    pub fn vars_with_n_uses(&self, n: usize) -> Vec<SsaVar> {
        self.def_site
            .keys()
            .filter(|v| self.use_count(v) == n)
            .cloned()
            .collect()
    }

    /// Alias for [`Self::vars_with_n_uses`].
    #[must_use]
    pub fn defs_with_n_uses(&self, n: usize) -> Vec<SsaVar> {
        self.vars_with_n_uses(n)
    }

    /// All variables with at least one definition (base variable names).
    #[must_use]
    pub fn defined_base_vars(&self) -> std::collections::HashSet<String> {
        self.def_site.keys().map(|sv| sv.base.0.clone()).collect()
    }

    /// Total number of (var, `use_point`) pairs.
    #[must_use]
    pub fn total_defs(&self) -> usize {
        self.def_site.len()
    }
}

// ── LiveInterval extended ─────────────────────────────────────────────────────

impl LiveInterval {
    /// Whether this is a trivial interval (zero length = def point == last use).
    #[must_use]
    pub const fn is_trivial(&self) -> bool {
        self.start == self.end
    }
}

// ── LinearScan extended ───────────────────────────────────────────────────────

impl LinearScan {
    /// Number of distinct intervals.
    #[must_use]
    pub fn interval_count(&self) -> usize {
        self.intervals.len()
    }

    /// Maximum live count at any single program point (approximation: longest overlap chain).
    #[must_use]
    pub fn max_live_count(&self) -> usize {
        let mut events: Vec<(usize, bool)> = Vec::new(); // (time, is_start)
        for iv in &self.intervals {
            events.push((iv.1.start, true));
            events.push((iv.1.end, false));
        }
        events.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut cur = 0usize;
        let mut max = 0usize;
        for (_, is_start) in events {
            if is_start {
                cur += 1;
            } else {
                cur = cur.saturating_sub(1);
            }
            max = max.max(cur);
        }
        max
    }
}

// ── Extended DU-chain tests ───────────────────────────────────────────────────

#[cfg(test)]
mod du_extended_tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};
    use crate::ssa::{Instruction, SsaFunction, SsaVar, Var};

    use crate::test_util::sv;

    fn make_func_with_two_defs() -> SsaFunction {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let mut i0 = Instruction::new(0, Some(Var::new("x")), vec![]);
        i0.ssa_def = Some(sv("x", 0));
        let mut i1 = Instruction::new(1, Some(Var::new("y")), vec![Var::new("x")]);
        i1.ssa_def = Some(sv("y", 0));
        i1.ssa_uses = vec![sv("x", 0)];
        let mut i2 = Instruction::new(2, None, vec![Var::new("x"), Var::new("y")]);
        i2.ssa_uses = vec![sv("x", 0), sv("y", 0)];
        SsaFunction::new(cfg, &vec![vec![i0, i1], vec![i2]])
    }

    #[test]
    fn total_use_count() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        // x has 2 uses, y has 1 use.
        assert_eq!(chains.total_use_count(), 3);
    }

    #[test]
    fn defs_with_n_uses_2() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        let two_use = chains.defs_with_n_uses(2);
        // x is used twice.
        assert_eq!(two_use.len(), 1);
    }

    #[test]
    fn defined_base_vars_has_both() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        let bases = chains.defined_base_vars();
        assert!(bases.contains("x"));
        assert!(bases.contains("y"));
    }

    #[test]
    fn linear_scan_max_live() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        let scan = LinearScan::build(&func, &chains);
        let max = scan.max_live_count();
        assert!(max >= 1);
    }

    #[test]
    fn live_interval_length_zero_for_trivial() {
        let iv = LiveInterval {
            var: sv("x", 0),
            start: 3,
            end: 3,
        };
        assert_eq!(iv.length(), 0);
        assert!(iv.is_trivial());
    }

    #[test]
    fn linear_scan_interval_count() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        let scan = LinearScan::build(&func, &chains);
        assert_eq!(scan.interval_count(), chains.total_defs());
    }

    #[test]
    fn allocate_no_conflict_single_var() {
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        let mut instr = Instruction::new(0, Some(Var::new("a")), vec![]);
        instr.ssa_def = Some(sv("a", 0));
        let func = SsaFunction::new(cfg, &vec![vec![instr]]);
        let chains = DefUseChains::build(&func);
        let scan = LinearScan::build(&func, &chains);
        let (assign, regs) = scan.allocate();
        assert_eq!(regs, 1);
        assert_eq!(assign.len(), 1);
    }

    /// Regression test for the `allocate` refactor that caches each active
    /// interval instead of re-looking it up (and cloning it) from the
    /// `intervals` map on every outer iteration. Builds a block with several
    /// short-lived, non-overlapping variables interleaved with a
    /// long-lived one, and asserts (a) no two intervals that genuinely
    /// overlap share a register and (b) short-lived vars whose intervals
    /// have expired are allowed to reuse a freed register, so the register
    /// count stays low instead of growing with the variable count.
    #[test]
    fn def_count_and_total_defs_agree() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        // x and y are both defined -> 2 distinct definitions.
        assert_eq!(chains.def_count(), 2);
        assert_eq!(chains.def_count(), chains.total_defs());
    }

    #[test]
    fn vars_with_zero_uses() {
        let func = make_func_with_two_defs();
        let chains = DefUseChains::build(&func);
        // Both x and y are used at least once in this fixture, so no
        // variable should have exactly zero uses.
        assert!(chains.vars_with_n_uses(0).is_empty());
    }

    #[test]
    fn program_point_new_matches_struct_literal() {
        let p = ProgramPoint::new(BBId(2), 4);
        assert_eq!(p, ProgramPoint { block: BBId(2), slot: 4 });
    }

    #[test]
    fn allocate_reuses_registers_after_expiry() {
        let succs = vec![vec![]];
        let cfg = Cfg::new(1, succs, BBId(0), BBId(0));
        // t0 lives across the whole block (defined first, used last).
        // a0..a3 are short-lived: each is defined and immediately used,
        // non-overlapping with each other, but all overlap t0.
        let mut instrs = Vec::new();
        instrs.push(Instruction::new(0, Some(Var::new("t")), vec![]));
        for i in 0..4u32 {
            let name = format!("a{i}");
            instrs.push(Instruction::new(instrs.len(), Some(Var::new(&name)), vec![]));
            instrs.push(Instruction::new(instrs.len(), None, vec![Var::new(&name)]));
        }
        instrs.push(Instruction::new(instrs.len(), None, vec![Var::new("t")]));
        let mut func = SsaFunction::new(cfg, &vec![instrs]);
        crate::ssa::construct_ssa(&mut func);
        let chains = DefUseChains::build(&func);
        let scan = LinearScan::build(&func, &chains);
        let (assign, regs) = scan.allocate();

        // t overlaps every a_i, so a_i must never share t's register; but
        // the a_i's are pairwise non-overlapping, so they may all share one
        // register with each other. Two registers suffice.
        assert!(regs <= 2, "expected register reuse, got {regs} registers");

        let find = |name: &str| -> SsaVar {
            chains
                .defined_vars()
                .into_iter()
                .find(|v| v.base.0 == name)
                .unwrap_or_else(|| panic!("no def for {name}"))
        };
        let t = find("t");
        let tk = format!("{}_{}", t.base.0, t.version);
        let t_reg = assign[&tk];
        for i in 0..4u32 {
            let a = find(&format!("a{i}"));
            let ak = format!("{}_{}", a.base.0, a.version);
            assert_ne!(assign[&ak], t_reg, "a{i} must not share t's register");
        }
    }
}
