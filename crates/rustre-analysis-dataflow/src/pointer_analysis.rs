//! Andersen-style pointer analysis with constraint graph, worklist solver,
//! and points-to sets.
//!
//! This module provides two flavours of pointer analysis:
//! * **Andersen** (`AndersenPointerAnalysis`) — subset-based, flow- and
//!   context-insensitive, field-insensitive.  More precise than Steensgaard.
//! * **Steensgaard** (`SteensgaardAnalysis`) — unification-based, near-linear
//!   complexity, less precise.
//!
//! Audit note (dataflow-crate iteration 5): grepped the whole workspace for
//! `rustre_analysis_dataflow::` usage — nothing outside this crate calls into
//! this module. (Other crates such as `rustre-analysis-vsa` and
//! `rustre-decompiler-type` have their own, unrelated `PointerAnalysis`-named
//! types; they do not depend on this one.) Only this module's own unit tests
//! exercise it — treat it as orphaned library code until a real consumer
//! shows up.
//!
//! Implements the classical Andersen field-insensitive, flow-insensitive
//! pointer analysis algorithm:
//!
//! * **AddressOf** (`p = &v`): add `v` to pts(p).
//! * **Assign** (`p = q`): pts(p) ⊇ pts(q).
//! * **Load** (`p = *q`): for each `r ∈ pts(q)`, pts(p) ⊇ pts(r).
//! * **Store** (`*p = q`): for each `r ∈ pts(p)`, pts(r) ⊇ pts(q).
//!
//! The worklist-based solver iterates until no new edges are added to the
//! constraint graph's inclusion edges (i.e. a fixpoint is reached).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Variable identifier
// ─────────────────────────────────────────────────────────────────────────────

/// Identifier for a pointer variable (or memory location) in the analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarId(pub u32);

impl VarId {
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }
}

impl fmt::Display for VarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraints
// ─────────────────────────────────────────────────────────────────────────────

/// The four fundamental pointer constraint kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Constraint {
    /// `lhs = &rhs`  → add `rhs` to pts(lhs).
    AddressOf { lhs: VarId, rhs: VarId },
    /// `lhs = rhs`   → pts(lhs) ⊇ pts(rhs).
    Assign { lhs: VarId, rhs: VarId },
    /// `lhs = *rhs`  → pts(lhs) ⊇ pts(r) for each r ∈ pts(rhs).
    Load { lhs: VarId, rhs: VarId },
    /// `*lhs = rhs`  → pts(r) ⊇ pts(rhs) for each r ∈ pts(lhs).
    Store { lhs: VarId, rhs: VarId },
}

impl Constraint {
    /// Returns the left-hand side variable.
    #[must_use]
    pub const fn lhs(self) -> VarId {
        match self {
            Self::AddressOf { lhs, .. }
            | Self::Assign { lhs, .. }
            | Self::Load { lhs, .. }
            | Self::Store { lhs, .. } => lhs,
        }
    }

    /// Returns the right-hand side variable.
    #[must_use]
    pub const fn rhs(self) -> VarId {
        match self {
            Self::AddressOf { rhs, .. }
            | Self::Assign { rhs, .. }
            | Self::Load { rhs, .. }
            | Self::Store { rhs, .. } => rhs,
        }
    }

    /// Short display tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::AddressOf { .. } => "addr_of",
            Self::Assign { .. } => "assign",
            Self::Load { .. } => "load",
            Self::Store { .. } => "store",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintGraph
// ─────────────────────────────────────────────────────────────────────────────

/// The constraint graph used by the Andersen solver.
///
/// Nodes are `VarId`s.  Inclusion edges (`p ⊇ q`) represent the subset
/// relation: when pts(q) changes, pts(p) may need to grow too.
#[derive(Debug, Default)]
pub struct ConstraintGraph {
    /// Address-of seeds: `pts_seeds[v]` = variables whose address v holds.
    pts_seeds: HashMap<VarId, HashSet<VarId>>,
    /// Inclusion edges: when pts(src) changes, re-process dst.
    inclusion_edges: HashMap<VarId, HashSet<VarId>>,
    /// Load constraints: `loads[rhs] = {lhs}` → pts(lhs) ⊇ pts(pt) for pt ∈ pts(rhs).
    loads: HashMap<VarId, HashSet<VarId>>,
    /// Store constraints: `stores[lhs] = {rhs}` → for pt ∈ pts(lhs), pts(pt) ⊇ pts(rhs).
    stores: HashMap<VarId, HashSet<VarId>>,
    /// All variables seen in any constraint.
    variables: HashSet<VarId>,
}

impl ConstraintGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single constraint to the graph.
    pub fn add_constraint(&mut self, c: Constraint) {
        let lhs = c.lhs();
        let rhs = c.rhs();
        self.variables.insert(lhs);
        self.variables.insert(rhs);
        match c {
            Constraint::AddressOf { lhs, rhs } => {
                self.pts_seeds.entry(lhs).or_default().insert(rhs);
            }
            Constraint::Assign { lhs, rhs } => {
                // lhs ⊇ rhs: edge from rhs → lhs.
                self.inclusion_edges.entry(rhs).or_default().insert(lhs);
            }
            Constraint::Load { lhs, rhs } => {
                self.loads.entry(rhs).or_default().insert(lhs);
            }
            Constraint::Store { lhs, rhs } => {
                self.stores.entry(lhs).or_default().insert(rhs);
            }
        }
    }

    /// Add a batch of constraints.
    pub fn add_constraints(&mut self, cs: impl IntoIterator<Item = Constraint>) {
        for c in cs {
            self.add_constraint(c);
        }
    }

    /// Number of unique variables.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    /// Number of inclusion (copy/assign) edges.
    #[must_use]
    pub fn inclusion_edge_count(&self) -> usize {
        self.inclusion_edges.values().map(std::collections::HashSet::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToSets
// ─────────────────────────────────────────────────────────────────────────────

/// The result of the pointer analysis: per-variable points-to sets.
#[derive(Debug, Default, Clone)]
pub struct PointsToSets {
    sets: HashMap<VarId, HashSet<VarId>>,
}

impl PointsToSets {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the points-to set for `v`.
    #[must_use]
    pub fn pts(&self, v: VarId) -> &HashSet<VarId> {
        static EMPTY: std::sync::OnceLock<HashSet<VarId>> = std::sync::OnceLock::new();
        self.sets
            .get(&v)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Return the points-to set for `v` (mutable access).
    pub fn pts_mut(&mut self, v: VarId) -> &mut HashSet<VarId> {
        self.sets.entry(v).or_default()
    }

    /// Add `target` to pts(v). Returns `true` if a new element was added.
    pub fn add(&mut self, v: VarId, target: VarId) -> bool {
        self.sets.entry(v).or_default().insert(target)
    }

    /// Extend pts(dst) with all elements of pts(src). Returns `true` if any new element was added.
    pub fn propagate(&mut self, src: VarId, dst: VarId) -> bool {
        let src_set: Vec<VarId> = self.pts(src).iter().copied().collect();
        let mut changed = false;
        for v in src_set {
            changed |= self.add(dst, v);
        }
        changed
    }

    /// Number of variables with non-empty points-to sets.
    #[must_use]
    pub fn non_empty_count(&self) -> usize {
        self.sets.values().filter(|s| !s.is_empty()).count()
    }

    /// Total number of (variable, target) pairs across all sets.
    #[must_use]
    pub fn total_facts(&self) -> usize {
        self.sets.values().map(std::collections::HashSet::len).sum()
    }

    /// Returns `true` if `target ∈ pts(v)`.
    #[must_use]
    pub fn contains(&self, v: VarId, target: VarId) -> bool {
        self.sets.get(&v).is_some_and(|s| s.contains(&target))
    }

    /// Merge all points-to facts from `other` into `self`.
    pub fn merge_from(&mut self, other: &Self) {
        for (&v, set) in &other.sets {
            let dst = self.sets.entry(v).or_default();
            for &t in set {
                dst.insert(t);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorklistSolver
// ─────────────────────────────────────────────────────────────────────────────

/// Andersen-style worklist solver.
///
/// Runs the standard Andersen algorithm:
/// 1. Seed all pts sets from `AddressOf` constraints.
/// 2. Propagate through copy edges.
/// 3. For Load/Store constraints, dynamically add new copy edges when pts sets change.
///
/// Terminates when no more pts facts can be added.
pub struct WorklistSolver;

impl WorklistSolver {
    /// Solve the constraint graph and return the computed points-to sets.
    #[must_use]
    pub fn solve(graph: &ConstraintGraph) -> PointsToSets {
        let mut pts = PointsToSets::new();
        let mut worklist: VecDeque<VarId> = VecDeque::new();
        let mut in_worklist: HashSet<VarId> = HashSet::new();

        // Dynamic copy (inclusion) edges `src → dst`, meaning pts(dst) ⊇ pts(src).
        // Seeded from the static `inclusion_edges` (Assign/Copy constraints) and
        // then *grown* as Load/Store constraints discover new pointees.
        //
        // This is the crucial correctness point: a Load `lhs = *p` or Store
        // `*p = rhs` must install a persistent edge for each `r ∈ pts(p)` — not
        // merely propagate once — because pts(r)'s source (the load's `r`, or a
        // store's `rhs`) can keep growing *after* the constraint was first
        // visited. A one-shot propagation silently drops those later facts,
        // under-approximating the (may-)points-to solution. See the
        // `store_rhs_growth_after_visit_is_not_dropped` regression test.
        let mut edges: HashMap<VarId, HashSet<VarId>> = HashMap::new();
        for (&src, dsts) in &graph.inclusion_edges {
            edges.entry(src).or_default().extend(dsts.iter().copied());
        }

        let push = |v: VarId, wl: &mut VecDeque<VarId>, inwl: &mut HashSet<VarId>| {
            if inwl.insert(v) {
                wl.push_back(v);
            }
        };

        // Step 1: Seed from AddressOf.
        for (&lhs, seeds) in &graph.pts_seeds {
            for &target in seeds {
                pts.add(lhs, target);
            }
        }
        for &v in graph.pts_seeds.keys() {
            push(v, &mut worklist, &mut in_worklist);
        }
        // Ensure all variables with load/store/copy constraints are processed.
        for &v in &graph.variables {
            push(v, &mut worklist, &mut in_worklist);
        }

        // Step 2: Iterate worklist to a fixpoint.
        while let Some(v) = worklist.pop_front() {
            in_worklist.remove(&v);

            let pointed_to: Vec<VarId> = pts.pts(v).iter().copied().collect();

            // Load: lhs = *v → install edge pt → lhs for each pt ∈ pts(v).
            if let Some(lhs_set) = graph.loads.get(&v) {
                let lhs_vars: Vec<VarId> = lhs_set.iter().copied().collect();
                for &lhs in &lhs_vars {
                    for &pt in &pointed_to {
                        if edges.entry(pt).or_default().insert(lhs) {
                            // New edge: propagate current pts(pt) into lhs and
                            // re-examine pt so future growth flows through.
                            push(pt, &mut worklist, &mut in_worklist);
                        }
                    }
                }
            }

            // Store: *v = rhs → install edge rhs → pt for each pt ∈ pts(v).
            if let Some(rhs_set) = graph.stores.get(&v) {
                let rhs_vars: Vec<VarId> = rhs_set.iter().copied().collect();
                for &rhs in &rhs_vars {
                    for &pt in &pointed_to {
                        if edges.entry(rhs).or_default().insert(pt) {
                            push(rhs, &mut worklist, &mut in_worklist);
                        }
                    }
                }
            }

            // Copy / Assign (and dynamically-added Load/Store edges): propagate
            // pts(v) to every inclusion successor.
            if let Some(succs) = edges.get(&v) {
                let succs: Vec<VarId> = succs.iter().copied().collect();
                for succ in succs {
                    if pts.propagate(v, succ) {
                        push(succ, &mut worklist, &mut in_worklist);
                    }
                }
            }
        }

        pts
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AndersenPointerAnalysis — high-level API
// ─────────────────────────────────────────────────────────────────────────────

/// High-level Andersen pointer analysis wrapper.
pub struct AndersenPointerAnalysis {
    pub graph: ConstraintGraph,
}

impl AndersenPointerAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: ConstraintGraph::new(),
        }
    }

    /// Add a constraint.
    pub fn add(&mut self, c: Constraint) {
        self.graph.add_constraint(c);
    }

    /// Add multiple constraints.
    pub fn add_all(&mut self, cs: impl IntoIterator<Item = Constraint>) {
        self.graph.add_constraints(cs);
    }

    /// Run the analysis and return the points-to sets.
    #[must_use]
    pub fn analyze(&self) -> PointsToSets {
        WorklistSolver::solve(&self.graph)
    }

    /// Convenience: check whether `p` may point to `q` after analysis.
    #[must_use]
    pub fn may_point_to(&self, p: VarId, q: VarId) -> bool {
        let pts = self.analyze();
        pts.contains(p, q)
    }

    /// Return the number of variables tracked.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.graph.variable_count()
    }
}

impl Default for AndersenPointerAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AndersenPointerAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndersenPointerAnalysis")
            .field("variables", &self.graph.variable_count())
            .field("inclusion_edges", &self.graph.inclusion_edge_count())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Alias query helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Alias relationship between two variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasResult {
    /// The two variables definitely do not alias.
    NoAlias,
    /// The two variables may alias (conservative).
    MayAlias,
    /// The two variables must alias (both point to exactly one location and it's the same one).
    MustAlias,
}

/// Query alias relationship given pre-computed points-to sets.
#[must_use]
pub fn query_alias(pts: &PointsToSets, p: VarId, q: VarId) -> AliasResult {
    let pp = pts.pts(p);
    let qq = pts.pts(q);
    let inter: HashSet<_> = pp.intersection(qq).collect();
    if inter.is_empty() {
        AliasResult::NoAlias
    } else if pp.len() == 1 && qq.len() == 1 && pp == qq {
        AliasResult::MustAlias
    } else {
        AliasResult::MayAlias
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u32) -> VarId {
        VarId::new(n)
    }

    /// Regression (found by `prop_soundness_ext`, minimized from seed 35): the
    /// worklist solver used to propagate Store/Load constraints *once* instead
    /// of installing a persistent inclusion edge. When the store's `rhs`
    /// points-to set grew *after* the store had already been visited, the new
    /// facts were silently dropped — an unsound (under-approximating) result.
    ///
    /// Here `*p = q` is processed while `pts(q)` is still empty; `q` only gains
    /// `a` afterwards via `q = r`. A sound solver must still flow `a` into
    /// `pts(x)` (the pointee of `p`).
    #[test]
    fn store_rhs_growth_after_visit_is_not_dropped() {
        // p=0, q=1, x=2, r=4, obj a=3.
        let mut g = ConstraintGraph::new();
        g.add_constraint(Constraint::AddressOf { lhs: v(0), rhs: v(2) }); // p = &x
        g.add_constraint(Constraint::Store { lhs: v(0), rhs: v(1) }); // *p = q
        g.add_constraint(Constraint::AddressOf { lhs: v(4), rhs: v(3) }); // r = &a
        g.add_constraint(Constraint::Assign { lhs: v(1), rhs: v(4) }); // q = r
        let pts = WorklistSolver::solve(&g);
        assert!(
            pts.contains(v(2), v(3)),
            "pts(x) must contain a: *p=q with p→x and q→a implies x→a; got {:?}",
            pts.pts(v(2))
        );
    }

    // ── VarId ─────────────────────────────────────────────────────────────────

    #[test]
    fn var_id_display() {
        assert_eq!(v(5).to_string(), "v5");
    }

    #[test]
    fn var_id_equality() {
        assert_eq!(v(1), v(1));
        assert_ne!(v(1), v(2));
    }

    // ── Constraint ────────────────────────────────────────────────────────────

    #[test]
    fn constraint_addr_of_lhs_rhs() {
        let c = Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        };
        assert_eq!(c.lhs(), v(1));
        assert_eq!(c.rhs(), v(2));
        assert_eq!(c.tag(), "addr_of");
    }

    #[test]
    fn constraint_assign_tag() {
        let c = Constraint::Assign {
            lhs: v(1),
            rhs: v(2),
        };
        assert_eq!(c.tag(), "assign");
    }

    #[test]
    fn constraint_load_tag() {
        let c = Constraint::Load {
            lhs: v(1),
            rhs: v(2),
        };
        assert_eq!(c.tag(), "load");
    }

    #[test]
    fn constraint_store_tag() {
        let c = Constraint::Store {
            lhs: v(1),
            rhs: v(2),
        };
        assert_eq!(c.tag(), "store");
    }

    // ── ConstraintGraph ───────────────────────────────────────────────────────

    #[test]
    fn constraint_graph_variable_count() {
        let mut cg = ConstraintGraph::new();
        cg.add_constraint(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        });
        cg.add_constraint(Constraint::Assign {
            lhs: v(2),
            rhs: v(3),
        });
        assert_eq!(cg.variable_count(), 3);
    }

    #[test]
    fn constraint_graph_inclusion_edges() {
        let mut cg = ConstraintGraph::new();
        cg.add_constraint(Constraint::Assign {
            lhs: v(2),
            rhs: v(1),
        });
        cg.add_constraint(Constraint::Assign {
            lhs: v(3),
            rhs: v(1),
        });
        assert_eq!(cg.inclusion_edge_count(), 2);
    }

    // ── PointsToSets ──────────────────────────────────────────────────────────

    #[test]
    fn pts_add_and_contains() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(2));
        assert!(pts.contains(v(1), v(2)));
        assert!(!pts.contains(v(1), v(3)));
    }

    #[test]
    fn pts_empty_for_unknown_var() {
        let pts = PointsToSets::new();
        assert!(pts.pts(v(99)).is_empty());
    }

    #[test]
    fn pts_propagate_returns_true_on_change() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(10));
        pts.add(v(1), v(11));
        let changed = pts.propagate(v(1), v(2));
        assert!(changed);
        assert!(pts.contains(v(2), v(10)));
        assert!(pts.contains(v(2), v(11)));
    }

    #[test]
    fn pts_propagate_no_change_idempotent() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(5));
        pts.add(v(2), v(5)); // already contains 5
        let changed = pts.propagate(v(1), v(2));
        assert!(!changed);
    }

    #[test]
    fn pts_non_empty_count() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(10));
        pts.add(v(2), v(20));
        assert_eq!(pts.non_empty_count(), 2);
    }

    #[test]
    fn pts_total_facts() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(10));
        pts.add(v(1), v(11));
        pts.add(v(2), v(20));
        assert_eq!(pts.total_facts(), 3);
    }

    #[test]
    fn pts_merge_from() {
        let mut a = PointsToSets::new();
        a.add(v(1), v(10));
        let mut b = PointsToSets::new();
        b.add(v(1), v(11));
        b.add(v(2), v(20));
        a.merge_from(&b);
        assert!(a.contains(v(1), v(10)));
        assert!(a.contains(v(1), v(11)));
        assert!(a.contains(v(2), v(20)));
    }

    // ── AddressOf constraint ──────────────────────────────────────────────────

    /// p = &x → pts(p) = {x}
    #[test]
    fn address_of_seeds_pts() {
        let mut analysis = AndersenPointerAnalysis::new();
        analysis.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        });
        let pts = analysis.analyze();
        assert!(pts.contains(v(1), v(2)));
    }

    /// p = &x; q = &x → both point to x
    #[test]
    fn two_address_of_same_target() {
        let mut analysis = AndersenPointerAnalysis::new();
        analysis.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(3),
        });
        analysis.add(Constraint::AddressOf {
            lhs: v(2),
            rhs: v(3),
        });
        let pts = analysis.analyze();
        assert!(pts.contains(v(1), v(3)));
        assert!(pts.contains(v(2), v(3)));
    }

    // ── Assign constraint ─────────────────────────────────────────────────────

    /// p = &x; q = p → pts(q) ⊇ pts(p) = {x}
    #[test]
    fn assign_propagates_pts() {
        let mut analysis = AndersenPointerAnalysis::new();
        analysis.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(10),
        });
        analysis.add(Constraint::Assign {
            lhs: v(2),
            rhs: v(1),
        });
        let pts = analysis.analyze();
        assert!(pts.contains(v(2), v(10)));
    }

    /// Assign chain: p → q → r
    #[test]
    fn assign_chain() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(100),
        });
        a.add(Constraint::Assign {
            lhs: v(2),
            rhs: v(1),
        });
        a.add(Constraint::Assign {
            lhs: v(3),
            rhs: v(2),
        });
        let pts = a.analyze();
        assert!(pts.contains(v(3), v(100)));
    }

    // ── Load constraint ───────────────────────────────────────────────────────

    /// p = &x; q = *p → q should point to whatever x points to.
    /// Here x points to nothing; pts(q) should be empty after load.
    #[test]
    fn load_simple_empty_deref() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(10),
        }); // v1 → {v10}
        a.add(Constraint::Load {
            lhs: v(2),
            rhs: v(1),
        }); // v2 = *v1 = *{v10} = pts(v10) = {}
        let pts = a.analyze();
        // v10 has no pts, so v2 stays empty.
        assert!(pts.pts(v(2)).is_empty());
    }

    /// p = &x; x = &y; q = *p → q should point to y.
    #[test]
    fn load_indirect() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        }); // v1 → {v2}
        a.add(Constraint::AddressOf {
            lhs: v(2),
            rhs: v(3),
        }); // v2 → {v3}
        a.add(Constraint::Load {
            lhs: v(4),
            rhs: v(1),
        }); // v4 = *v1 → pts(v2) = {v3}
        let pts = a.analyze();
        assert!(pts.contains(v(4), v(3)));
    }

    // ── Store constraint ──────────────────────────────────────────────────────

    /// p = &x; q = &y; *p = q → x should point to y.
    #[test]
    fn store_simple() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(10),
        }); // v1 → {v10}
        a.add(Constraint::AddressOf {
            lhs: v(2),
            rhs: v(20),
        }); // v2 → {v20}
        a.add(Constraint::Store {
            lhs: v(1),
            rhs: v(2),
        }); // *v1 = v2 → pts(v10) ⊇ pts(v2) = {v20}
        let pts = a.analyze();
        assert!(pts.contains(v(10), v(20)));
    }

    /// Chain: p = &a; a = &b; q = *p; *q = &c → b should point to c.
    #[test]
    fn store_through_load() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        }); // v1 → {v2}
        a.add(Constraint::AddressOf {
            lhs: v(2),
            rhs: v(3),
        }); // v2 → {v3}
        a.add(Constraint::AddressOf {
            lhs: v(5),
            rhs: v(6),
        }); // v5 → {v6}
        a.add(Constraint::Load {
            lhs: v(4),
            rhs: v(1),
        }); // v4 = *v1 → pts(v2) = {v3}
        a.add(Constraint::Store {
            lhs: v(4),
            rhs: v(5),
        }); // *v4 = v5 → pts(v3) ⊇ pts(v5) = {v6}
        let pts = a.analyze();
        assert!(pts.contains(v(3), v(6)));
    }

    // ── Alias queries ─────────────────────────────────────────────────────────

    #[test]
    fn alias_no_alias() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(10));
        pts.add(v(2), v(20));
        assert_eq!(query_alias(&pts, v(1), v(2)), AliasResult::NoAlias);
    }

    #[test]
    fn alias_may_alias() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(10));
        pts.add(v(1), v(11));
        pts.add(v(2), v(10));
        pts.add(v(2), v(12));
        assert_eq!(query_alias(&pts, v(1), v(2)), AliasResult::MayAlias);
    }

    #[test]
    fn alias_must_alias() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(10));
        pts.add(v(2), v(10));
        assert_eq!(query_alias(&pts, v(1), v(2)), AliasResult::MustAlias);
    }

    // ── AndersenPointerAnalysis ───────────────────────────────────────────────

    #[test]
    fn andersen_variable_count() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        });
        a.add(Constraint::Assign {
            lhs: v(3),
            rhs: v(1),
        });
        assert_eq!(a.variable_count(), 3);
    }

    #[test]
    fn andersen_may_point_to_true() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(5),
        });
        assert!(a.may_point_to(v(1), v(5)));
    }

    #[test]
    fn andersen_may_point_to_false() {
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(5),
        });
        assert!(!a.may_point_to(v(1), v(9)));
    }

    #[test]
    fn andersen_add_all() {
        let mut a = AndersenPointerAnalysis::new();
        a.add_all([
            Constraint::AddressOf {
                lhs: v(1),
                rhs: v(2),
            },
            Constraint::Assign {
                lhs: v(3),
                rhs: v(1),
            },
        ]);
        let pts = a.analyze();
        assert!(pts.contains(v(3), v(2)));
    }

    #[test]
    fn andersen_empty_graph() {
        let a = AndersenPointerAnalysis::new();
        let pts = a.analyze();
        assert_eq!(pts.total_facts(), 0);
    }

    // ── Complex scenarios ─────────────────────────────────────────────────────

    /// Linked-list pattern: node1.next = &node2; p = &node1; q = *p.next
    #[test]
    fn linked_list_one_hop() {
        // v1 = &node1; v2 = &node2; node1.next = v2 (store: *v1 = v2)
        // then: q = *v1 should get pts(node1) ⊇ pts(v2) = {node2}
        let mut a = AndersenPointerAnalysis::new();
        // p points to node1
        a.add(Constraint::AddressOf {
            lhs: v(100),
            rhs: v(1),
        }); // p → {node1}
        // node1 points to node2
        a.add(Constraint::AddressOf {
            lhs: v(200),
            rhs: v(2),
        }); // v200 → {node2}
        a.add(Constraint::Store {
            lhs: v(100),
            rhs: v(200),
        }); // *p = v200 → node1 ⊇ {node2}
        // q = *p
        a.add(Constraint::Load {
            lhs: v(300),
            rhs: v(100),
        }); // q = *p → pts(node1) = {node2}
        let pts = a.analyze();
        assert!(pts.contains(v(1), v(2)), "node1 should point to node2");
        assert!(pts.contains(v(300), v(2)), "q should reach node2 via *p");
    }

    #[test]
    fn multiple_targets_merged() {
        // p = &x or p = &y (two assignments)
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(10),
        });
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(11),
        });
        let pts = a.analyze();
        assert!(pts.contains(v(1), v(10)));
        assert!(pts.contains(v(1), v(11)));
    }

    // ── Additional Andersen tests ─────────────────────────────────────────────

    #[test]
    fn assign_does_not_add_to_rhs() {
        // q = p should NOT add anything to pts(p).
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(5),
        }); // p → {5}
        a.add(Constraint::Assign {
            lhs: v(2),
            rhs: v(1),
        }); // q = p
        let pts = a.analyze();
        // pts(p) = {5} (unchanged)
        assert!(pts.contains(v(1), v(5)));
        // pts(p) should NOT contain v(2) or anything extra from the assign.
        assert!(!pts.contains(v(1), v(2)));
    }

    #[test]
    fn store_with_two_pointees() {
        // p = &a; p = &b; *p = q where q → {z}
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(10),
        });
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(11),
        });
        a.add(Constraint::AddressOf {
            lhs: v(2),
            rhs: v(99),
        }); // q → {99}
        a.add(Constraint::Store {
            lhs: v(1),
            rhs: v(2),
        }); // *p = q
        let pts = a.analyze();
        // Both v10 and v11 should now point to 99.
        assert!(pts.contains(v(10), v(99)));
        assert!(pts.contains(v(11), v(99)));
    }

    #[test]
    fn load_transitive_three_hops() {
        // p → a → b → c; q = *p; r = *q → r should point to b.
        let mut a = AndersenPointerAnalysis::new();
        a.add(Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        }); // p → {a=v2}
        a.add(Constraint::AddressOf {
            lhs: v(2),
            rhs: v(3),
        }); // a → {b=v3}
        a.add(Constraint::AddressOf {
            lhs: v(3),
            rhs: v(4),
        }); // b → {c=v4}
        a.add(Constraint::Load {
            lhs: v(10),
            rhs: v(1),
        }); // q = *p → pts(v2) = {v3}
        a.add(Constraint::Load {
            lhs: v(11),
            rhs: v(10),
        }); // r = *q → pts(v3) = {v4}
        let pts = a.analyze();
        assert!(pts.contains(v(10), v(3)));
        assert!(pts.contains(v(11), v(4)));
    }

    #[test]
    fn worklist_solver_terminates_on_large_graph() {
        // 100-node chain: v0 → &v1, v1 = v0, v2 = v1, ...
        let mut cg = ConstraintGraph::new();
        cg.add_constraint(Constraint::AddressOf {
            lhs: VarId(0),
            rhs: VarId(100),
        });
        for i in 0u32..99 {
            cg.add_constraint(Constraint::Assign {
                lhs: VarId(i + 1),
                rhs: VarId(i),
            });
        }
        let pts = WorklistSolver::solve(&cg);
        // v99 should eventually propagate to the end.
        assert!(pts.contains(VarId(99), VarId(100)));
    }

    #[test]
    fn constraint_graph_loads_registered() {
        let mut cg = ConstraintGraph::new();
        cg.add_constraint(Constraint::Load {
            lhs: v(1),
            rhs: v(2),
        });
        assert!(cg.loads.contains_key(&v(2)));
    }

    #[test]
    fn constraint_graph_stores_registered() {
        let mut cg = ConstraintGraph::new();
        cg.add_constraint(Constraint::Store {
            lhs: v(1),
            rhs: v(2),
        });
        assert!(cg.stores.contains_key(&v(1)));
    }

    #[test]
    fn pts_add_duplicate_returns_false() {
        let mut pts = PointsToSets::new();
        pts.add(v(1), v(5));
        let changed = pts.add(v(1), v(5));
        assert!(!changed, "adding duplicate should not indicate change");
    }

    #[test]
    fn alias_no_alias_empty_sets() {
        let pts = PointsToSets::new();
        // Both have empty sets → no alias.
        assert_eq!(query_alias(&pts, v(1), v(2)), AliasResult::NoAlias);
    }

    #[test]
    fn andersen_debug_format() {
        let a = AndersenPointerAnalysis::new();
        let s = format!("{a:?}");
        assert!(s.contains("AndersenPointerAnalysis"));
    }

    #[test]
    fn constraint_equality() {
        let c1 = Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        };
        let c2 = Constraint::AddressOf {
            lhs: v(1),
            rhs: v(2),
        };
        assert_eq!(c1, c2);
    }

    #[test]
    fn var_id_ord() {
        assert!(v(1) < v(2));
        assert!(v(0) < v(100));
    }

    #[test]
    fn constraint_graph_add_all() {
        let mut cg = ConstraintGraph::new();
        cg.add_constraints([
            Constraint::AddressOf {
                lhs: v(1),
                rhs: v(10),
            },
            Constraint::Assign {
                lhs: v(2),
                rhs: v(1),
            },
            Constraint::Load {
                lhs: v(3),
                rhs: v(2),
            },
            Constraint::Store {
                lhs: v(4),
                rhs: v(5),
            },
        ]);
        assert_eq!(cg.variable_count(), 6); // v1, v2, v3, v4, v5, v10
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintExtractor — extract Andersen constraints from IR effects
// ─────────────────────────────────────────────────────────────────────────────

/// Maps IR variable names to `VarId`s and extracts pointer constraints.
pub struct ConstraintExtractor {
    name_to_id: HashMap<String, VarId>,
    next_id: u32,
    pub constraints: Vec<Constraint>,
}

impl ConstraintExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            name_to_id: HashMap::new(),
            next_id: 1,
            constraints: Vec::new(),
        }
    }

    /// Intern a variable name → `VarId`.
    ///
    /// # Panics
    /// Panics if more than `u32::MAX` unique variable names are interned.
    pub fn var(&mut self, name: &str) -> VarId {
        if let Some(&id) = self.name_to_id.get(name) {
            return id;
        }
        let id = VarId(self.next_id);
        self.next_id = self.next_id.checked_add(1).expect("VarId counter overflow");
        self.name_to_id.insert(name.to_string(), id);
        id
    }

    /// Add `p = &q`.
    pub fn add_address_of(&mut self, p: &str, q: &str) {
        let lhs = self.var(p);
        let rhs = self.var(q);
        self.constraints.push(Constraint::AddressOf { lhs, rhs });
    }

    /// Add `p = q`.
    pub fn add_assign(&mut self, p: &str, q: &str) {
        let lhs = self.var(p);
        let rhs = self.var(q);
        self.constraints.push(Constraint::Assign { lhs, rhs });
    }

    /// Add `p = *q`.
    pub fn add_load(&mut self, p: &str, q: &str) {
        let lhs = self.var(p);
        let rhs = self.var(q);
        self.constraints.push(Constraint::Load { lhs, rhs });
    }

    /// Add `*p = q`.
    pub fn add_store(&mut self, p: &str, q: &str) {
        let lhs = self.var(p);
        let rhs = self.var(q);
        self.constraints.push(Constraint::Store { lhs, rhs });
    }

    /// Build a `ConstraintGraph` from the collected constraints.
    #[must_use]
    pub fn build_graph(&self) -> ConstraintGraph {
        let mut cg = ConstraintGraph::new();
        cg.add_constraints(self.constraints.iter().copied());
        cg
    }

    /// Run the full analysis.
    #[must_use]
    pub fn analyze(&self) -> PointsToSets {
        WorklistSolver::solve(&self.build_graph())
    }

    /// Lookup the `VarId` for a name, if it exists.
    #[must_use]
    pub fn id_of(&self, name: &str) -> Option<VarId> {
        self.name_to_id.get(name).copied()
    }

    /// Total number of interned variables.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.name_to_id.len()
    }
}

impl Default for ConstraintExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MayAliasSet — coarse alias class partitioning
// ─────────────────────────────────────────────────────────────────────────────

/// Groups variables into may-alias equivalence classes.
///
/// Two variables are in the same class if their points-to sets overlap.
pub struct MayAliasSet {
    /// Map from variable to class id.
    class_of: HashMap<VarId, usize>,
    /// Number of alias classes.
    class_count: usize,
}

impl MayAliasSet {
    /// Compute may-alias classes from a `PointsToSets`.
    ///
    /// Uses a union-find approach: merge two variables' classes whenever their
    /// points-to sets share a common target.
    #[must_use]
    pub fn compute(pts: &PointsToSets) -> Self {
        // `pts.sets` is a `std::collections::HashMap` (randomly-seeded
        // per-process), so iterating its keys directly would make the
        // union-find processing order — and hence which `VarId` becomes the
        // representative of each class — vary from run to run on identical
        // input. The resulting partition (which vars share a class) would
        // still be correct, but the assigned class ids would not be
        // reproducible across runs, which is undesirable for deterministic
        // builds/tests. Sort by `VarId` first so processing order (and thus
        // class-id assignment) is fully deterministic.
        let mut vars: Vec<VarId> = pts.sets.keys().copied().collect();
        vars.sort_unstable();
        let n = vars.len();
        let mut parent: Vec<usize> = (0..n).collect();

        let var_idx: HashMap<VarId, usize> =
            vars.iter().enumerate().map(|(i, &v)| (v, i)).collect();
        debug_assert_eq!(
            var_idx.len(),
            n,
            "var_idx must contain one entry per pointer variable"
        );

        // Group by shared targets using a target → first-var map.
        let mut target_to_rep: HashMap<VarId, usize> = HashMap::new();
        for (i, &v) in vars.iter().enumerate() {
            for &t in pts.pts(v) {
                if let Some(&rep) = target_to_rep.get(&t) {
                    // Union i and rep.
                    let ri = Self::find(&mut parent, i);
                    let rr = Self::find(&mut parent, rep);
                    if ri != rr {
                        parent[ri] = rr;
                    }
                } else {
                    target_to_rep.insert(t, i);
                }
            }
        }

        // Canonicalise
        let mut class_map: HashMap<usize, usize> = HashMap::new();
        let mut next_class = 0usize;
        let mut class_of = HashMap::new();
        for (i, &v) in vars.iter().enumerate() {
            let root = Self::find(&mut parent, i);
            let cls = *class_map.entry(root).or_insert_with(|| {
                let c = next_class;
                next_class += 1;
                c
            });
            class_of.insert(v, cls);
        }

        Self {
            class_of,
            class_count: next_class,
        }
    }

    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]]; // path compression
            x = parent[x];
        }
        x
    }

    /// Returns `true` if `p` and `q` are in the same alias class.
    #[must_use]
    pub fn may_alias(&self, p: VarId, q: VarId) -> bool {
        match (self.class_of.get(&p), self.class_of.get(&q)) {
            (Some(&a), Some(&b)) => a == b,
            _ => false,
        }
    }

    /// The alias class id for `v`, if `v` is tracked.
    #[must_use]
    pub fn class_of(&self, v: VarId) -> Option<usize> {
        self.class_of.get(&v).copied()
    }

    /// Total number of alias classes.
    #[must_use]
    pub const fn class_count(&self) -> usize {
        self.class_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the new utilities
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── ConstraintExtractor ───────────────────────────────────────────────────

    #[test]
    fn extractor_address_of() {
        let mut e = ConstraintExtractor::new();
        e.add_address_of("p", "x");
        let pts = e.analyze();
        let pid = e.id_of("p").unwrap();
        let xid = e.id_of("x").unwrap();
        assert!(pts.contains(pid, xid));
    }

    #[test]
    fn extractor_assign_propagates() {
        let mut e = ConstraintExtractor::new();
        e.add_address_of("p", "x");
        e.add_assign("q", "p");
        let pts = e.analyze();
        let qid = e.id_of("q").unwrap();
        let xid = e.id_of("x").unwrap();
        assert!(pts.contains(qid, xid));
    }

    #[test]
    fn extractor_load() {
        let mut e = ConstraintExtractor::new();
        e.add_address_of("p", "a");
        e.add_address_of("a", "b");
        e.add_load("q", "p"); // q = *p → pts(a) = {b}
        let pts = e.analyze();
        let qid = e.id_of("q").unwrap();
        let bid = e.id_of("b").unwrap();
        assert!(pts.contains(qid, bid));
    }

    #[test]
    fn extractor_store() {
        let mut e = ConstraintExtractor::new();
        e.add_address_of("p", "mem");
        e.add_address_of("q", "val");
        e.add_store("p", "q"); // *p = q → pts(mem) ⊇ pts(q) = {val}
        let pts = e.analyze();
        let memid = e.id_of("mem").unwrap();
        let valid = e.id_of("val").unwrap();
        assert!(pts.contains(memid, valid));
    }

    #[test]
    fn extractor_variable_count() {
        let mut e = ConstraintExtractor::new();
        e.add_address_of("a", "b");
        e.add_assign("c", "a");
        assert_eq!(e.variable_count(), 3);
    }

    #[test]
    fn extractor_intern_idempotent() {
        let mut e = ConstraintExtractor::new();
        let id1 = e.var("x");
        let id2 = e.var("x");
        assert_eq!(id1, id2);
    }

    // ── MayAliasSet ───────────────────────────────────────────────────────────

    #[test]
    fn may_alias_same_target() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(2), VarId(10));
        let mas = MayAliasSet::compute(&pts);
        assert!(mas.may_alias(VarId(1), VarId(2)));
    }

    #[test]
    fn may_alias_different_targets() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(2), VarId(20));
        let mas = MayAliasSet::compute(&pts);
        assert!(!mas.may_alias(VarId(1), VarId(2)));
    }

    #[test]
    fn may_alias_class_count() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(2), VarId(20));
        let mas = MayAliasSet::compute(&pts);
        assert_eq!(mas.class_count(), 2);
    }

    #[test]
    fn may_alias_three_variables_same_class() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(2), VarId(10));
        pts.add(VarId(3), VarId(10));
        let mas = MayAliasSet::compute(&pts);
        assert_eq!(mas.class_count(), 1);
        assert!(mas.may_alias(VarId(1), VarId(3)));
    }

    #[test]
    fn may_alias_class_ids_deterministic_across_repeated_runs() {
        // `pts.sets` is a std `HashMap`; before the fix, class-id assignment
        // depended on its arbitrary (per-process-random) iteration order.
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(100));
        pts.add(VarId(2), VarId(100));
        pts.add(VarId(3), VarId(200));
        pts.add(VarId(4), VarId(300));
        let first = MayAliasSet::compute(&pts);
        for _ in 0..20 {
            let again = MayAliasSet::compute(&pts);
            assert_eq!(again.class_of(VarId(1)), first.class_of(VarId(1)));
            assert_eq!(again.class_of(VarId(2)), first.class_of(VarId(2)));
            assert_eq!(again.class_of(VarId(3)), first.class_of(VarId(3)));
            assert_eq!(again.class_of(VarId(4)), first.class_of(VarId(4)));
        }
    }

    #[test]
    fn may_alias_unknown_variable() {
        let pts = PointsToSets::new();
        let mas = MayAliasSet::compute(&pts);
        assert!(!mas.may_alias(VarId(99), VarId(100)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToSetPrinter — render points-to sets as human-readable text
// ─────────────────────────────────────────────────────────────────────────────

/// Render a `PointsToSets` as a human-readable multi-line string.
#[must_use]
pub fn print_points_to(pts: &PointsToSets) -> String {
    use std::fmt::Write as _;
    let mut vars: Vec<VarId> = pts.sets.keys().copied().collect();
    vars.sort();
    let mut out = String::new();
    for v in vars {
        let mut targets: Vec<VarId> = pts.pts(v).iter().copied().collect();
        targets.sort();
        let targets_str: Vec<String> = targets.iter().map(|t| format!("v{}", t.0)).collect();
        let _ = writeln!(out, "pts(v{}) = {{{}}}", v.0, targets_str.join(", "));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintStats — statistics about a constraint set
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a set of Andersen constraints.
#[derive(Debug, Default, Clone)]
pub struct ConstraintStats {
    pub address_of_count: usize,
    pub assign_count: usize,
    pub load_count: usize,
    pub store_count: usize,
}

impl ConstraintStats {
    /// Compute statistics from a slice of constraints.
    #[must_use]
    pub fn compute(constraints: &[Constraint]) -> Self {
        let mut s = Self::default();
        for c in constraints {
            match c {
                Constraint::AddressOf { .. } => s.address_of_count += 1,
                Constraint::Assign { .. } => s.assign_count += 1,
                Constraint::Load { .. } => s.load_count += 1,
                Constraint::Store { .. } => s.store_count += 1,
            }
        }
        s
    }

    /// Total number of constraints.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.address_of_count + self.assign_count + self.load_count + self.store_count
    }

    /// Fraction of Load constraints (0.0–1.0).
    #[must_use]
    pub fn load_fraction(&self) -> f64 {
        if self.total() == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.load_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total()).unwrap_or(u32::MAX))
    }

    /// Fraction of Store constraints (0.0–1.0).
    #[must_use]
    pub fn store_fraction(&self) -> f64 {
        if self.total() == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.store_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total()).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SteensgaardPointerAnalysis — simplified unification-based pointer analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified Steensgaard-style unification-based pointer analysis.
///
/// Less precise than Andersen (union-find unification) but much faster.
/// All pointer targets that flow into the same variable are merged into a
/// single abstract location.
pub struct SteensgaardAnalysis {
    parent: HashMap<VarId, VarId>,
    pts: HashMap<VarId, VarId>, // representative → abstract location
}

impl SteensgaardAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: HashMap::new(),
            pts: HashMap::new(),
        }
    }

    fn find(&mut self, v: VarId) -> VarId {
        // Iterative path-halving to avoid stack overflow on deeply chained inputs.
        if let std::collections::hash_map::Entry::Vacant(e) = self.parent.entry(v) {
            e.insert(v);
            return v;
        }
        // First pass: walk to root.
        let mut cur = v;
        loop {
            let p = *self.parent.get(&cur).unwrap_or(&cur);
            if p == cur {
                break;
            }
            cur = p;
        }
        let root = cur;
        // Second pass: path compression — point all nodes directly to root.
        let mut cur = v;
        while cur != root {
            let p = *self.parent.get(&cur).unwrap_or(&cur);
            self.parent.insert(cur, root);
            cur = p;
        }
        root
    }

    fn union(&mut self, a: VarId, b: VarId) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }

    /// Process constraints and compute unification-based points-to sets.
    pub fn solve(&mut self, constraints: &[Constraint]) {
        for &c in constraints {
            match c {
                Constraint::AddressOf { lhs, rhs } => {
                    // lhs → rhs: set the pts representative of find(lhs) to find(rhs).
                    let l = self.find(lhs);
                    let r = self.find(rhs);
                    self.pts.insert(l, r);
                }
                Constraint::Assign { lhs, rhs } => {
                    // lhs = rhs: unify their abstract locations.
                    let l = self.find(lhs);
                    let r = self.find(rhs);
                    if let (Some(&pt_l), Some(&pt_r)) = (self.pts.get(&l), self.pts.get(&r)) {
                        self.union(pt_l, pt_r);
                    }
                    self.union(l, r);
                }
                Constraint::Load { lhs, rhs } => {
                    // lhs = *rhs: unify pts(find(rhs)) and find(lhs).
                    let l = self.find(lhs);
                    let r = self.find(rhs);
                    if let Some(&pt_r) = self.pts.get(&r) {
                        self.union(l, pt_r);
                    }
                }
                Constraint::Store { lhs, rhs } => {
                    // *lhs = rhs: unify pts(find(lhs)) and find(rhs).
                    let l = self.find(lhs);
                    let r = self.find(rhs);
                    if let Some(&pt_l) = self.pts.get(&l) {
                        self.union(pt_l, r);
                    }
                }
            }
        }
    }

    /// Check whether `p` may point to `q`.
    #[must_use]
    pub fn may_point_to(&mut self, p: VarId, q: VarId) -> bool {
        let rp = self.find(p);
        let rq = self.find(q);
        match self.pts.get(&rp) {
            Some(&loc) => self.find(loc) == rq,
            None => false,
        }
    }
}

impl Default for SteensgaardAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn print_points_to_format() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(1), VarId(11));
        let s = print_points_to(&pts);
        assert!(s.contains("v1"));
        assert!(s.contains("v10"));
        assert!(s.contains("v11"));
    }

    #[test]
    fn constraint_stats_compute() {
        let cs = vec![
            Constraint::AddressOf {
                lhs: VarId(1),
                rhs: VarId(2),
            },
            Constraint::Assign {
                lhs: VarId(3),
                rhs: VarId(1),
            },
            Constraint::Load {
                lhs: VarId(4),
                rhs: VarId(3),
            },
            Constraint::Load {
                lhs: VarId(5),
                rhs: VarId(3),
            },
            Constraint::Store {
                lhs: VarId(1),
                rhs: VarId(4),
            },
        ];
        let stats = ConstraintStats::compute(&cs);
        assert_eq!(stats.address_of_count, 1);
        assert_eq!(stats.assign_count, 1);
        assert_eq!(stats.load_count, 2);
        assert_eq!(stats.store_count, 1);
        assert_eq!(stats.total(), 5);
    }

    #[test]
    fn constraint_stats_fractions() {
        let cs = vec![
            Constraint::Load {
                lhs: VarId(1),
                rhs: VarId(2),
            },
            Constraint::Load {
                lhs: VarId(3),
                rhs: VarId(4),
            },
            Constraint::Store {
                lhs: VarId(5),
                rhs: VarId(6),
            },
            Constraint::Store {
                lhs: VarId(7),
                rhs: VarId(8),
            },
        ];
        let stats = ConstraintStats::compute(&cs);
        assert!((stats.load_fraction() - 0.5).abs() < 1e-9);
        assert!((stats.store_fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn steensgaard_address_of() {
        let mut s = SteensgaardAnalysis::new();
        s.solve(&[Constraint::AddressOf {
            lhs: VarId(1),
            rhs: VarId(2),
        }]);
        assert!(s.may_point_to(VarId(1), VarId(2)));
    }

    #[test]
    fn steensgaard_assign_propagates() {
        let mut s = SteensgaardAnalysis::new();
        s.solve(&[
            Constraint::AddressOf {
                lhs: VarId(1),
                rhs: VarId(10),
            },
            Constraint::Assign {
                lhs: VarId(2),
                rhs: VarId(1),
            },
        ]);
        // After unification, v2 should also (via unification) point to the same location as v1.
        // In Steensgaard, v1 and v2 are unified so both point to v10.
        assert!(s.may_point_to(VarId(2), VarId(10)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToGraph — render points-to sets as a DOT graph for visualisation
// ─────────────────────────────────────────────────────────────────────────────

/// Renders a `PointsToSets` as a Graphviz DOT digraph string.
#[must_use]
pub fn points_to_dot(pts: &PointsToSets, title: &str) -> String {
    use std::fmt::Write as _;
    let mut out = format!("digraph {title} {{\n  rankdir=LR;\n");
    let mut vars: Vec<VarId> = pts.sets.keys().copied().collect();
    vars.sort();
    for v in &vars {
        let _ = writeln!(out, "  v{} [label=\"v{}\"];", v.0, v.0);
    }
    for v in &vars {
        let mut targets: Vec<VarId> = pts.pts(*v).iter().copied().collect();
        targets.sort();
        for t in targets {
            let _ = writeln!(out, "  v{} -> v{};", v.0, t.0);
        }
    }
    out.push_str("}\n");
    out
}

/// Statistics about the points-to graph topology.
#[derive(Debug, Clone)]
pub struct PointsToGraphStats {
    /// Number of pointer variables (nodes with a non-empty pts set).
    pub pointer_vars: usize,
    /// Number of abstract locations (variables that appear as targets).
    pub abstract_locations: usize,
    /// Total directed edges in the points-to graph.
    pub edges: usize,
    /// Maximum points-to set size.
    pub max_pts_size: usize,
    /// Average points-to set size (over non-empty sets).
    pub avg_pts_size: f64,
}

impl PointsToGraphStats {
    #[must_use]
    pub fn compute(pts: &PointsToSets) -> Self {
        let pointer_vars = pts.non_empty_count();
        let total_edges = pts.total_facts();
        let abstract_locations: std::collections::HashSet<VarId> =
            pts.sets.values().flat_map(|s| s.iter().copied()).collect();
        let max_pts = pts.sets.values().map(std::collections::HashSet::len).max().unwrap_or(0);
        let avg_pts = if pointer_vars == 0 {
            0.0
        } else {
            f64::from(u32::try_from(total_edges).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(pointer_vars).unwrap_or(u32::MAX))
        };
        Self {
            pointer_vars,
            abstract_locations: abstract_locations.len(),
            edges: total_edges,
            max_pts_size: max_pts,
            avg_pts_size: avg_pts,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for graph utilities
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod graph_util_tests {
    use super::*;

    #[test]
    fn points_to_dot_empty() {
        let pts = PointsToSets::new();
        let dot = points_to_dot(&pts, "G");
        assert!(dot.contains("digraph G"));
    }

    #[test]
    fn points_to_dot_has_edge() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        let dot = points_to_dot(&pts, "G");
        assert!(dot.contains("v1 -> v10"));
    }

    #[test]
    fn points_to_graph_stats_empty() {
        let pts = PointsToSets::new();
        let s = PointsToGraphStats::compute(&pts);
        assert_eq!(s.pointer_vars, 0);
        assert_eq!(s.edges, 0);
        assert_eq!(s.max_pts_size, 0);
    }

    #[test]
    fn points_to_graph_stats_non_empty() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(1), VarId(11));
        pts.add(VarId(2), VarId(10));
        let s = PointsToGraphStats::compute(&pts);
        assert_eq!(s.pointer_vars, 2);
        assert_eq!(s.abstract_locations, 2);
        assert_eq!(s.edges, 3);
        assert_eq!(s.max_pts_size, 2);
    }

    #[test]
    fn points_to_graph_avg_pts() {
        let mut pts = PointsToSets::new();
        pts.add(VarId(1), VarId(10));
        pts.add(VarId(1), VarId(11));
        pts.add(VarId(2), VarId(12));
        let s = PointsToGraphStats::compute(&pts);
        // v1 has 2 targets, v2 has 1 → avg = 1.5
        assert!((s.avg_pts_size - 1.5).abs() < 1e-9);
    }
}
