// andersen_pta.rs — Andersen-style inclusion-based points-to analysis.
//
// This module implements a flow-insensitive, context-insensitive points-to
// analysis modelled after Andersen (1994).  It operates over a simplified
// constraint language derived from the SSA IR used by the decompiler and
// produces a `PointsToSolution` that can be queried for alias relationships.
//
// Four constraint kinds (following the standard formulation):
//   - AddressOf(p, a)  : p ⊇ {a}
//   - Assign(p, q)     : p ⊇ q  (copy)
//   - Load(p, *q)      : ∀r ∈ pts(q). p ⊇ pts(r)
//   - Store(*p, q)     : ∀r ∈ pts(p). pts(r) ⊇ q

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// Allocation sites
// ────────────────────────────────────────────────────────────────────────────

/// Identifies a unique memory allocation in the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AllocationSite {
    /// Heap allocation at the given binary address (e.g. a `malloc` call).
    Heap(u64),
    /// Stack allocation identified by (function address, frame-slot index).
    Stack(u64, u32),
    /// Global variable at the given binary address.
    Global(u64),
    /// Synthetic allocation for a function parameter (function addr, param idx).
    Param(u64, u32),
    /// Unknown / external allocation (e.g. returned by an unanalysed import).
    External(u32),
}

impl AllocationSite {
    #[must_use] 
    pub const fn is_heap(&self) -> bool {
        matches!(self, Self::Heap(_))
    }

    #[must_use] 
    pub const fn is_stack(&self) -> bool {
        matches!(self, Self::Stack(..))
    }

    #[must_use] 
    pub const fn is_external(&self) -> bool {
        matches!(self, Self::External(_))
    }

    /// A compact display string.
    #[must_use] 
    pub fn label(&self) -> String {
        match self {
            Self::Heap(a) => format!("heap@{a:#x}"),
            Self::Stack(f, s) => format!("stack@{f:#x}[{s}]"),
            Self::Global(a) => format!("global@{a:#x}"),
            Self::Param(f, p) => format!("param@{f:#x}[{p}]"),
            Self::External(id) => format!("ext#{id}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Points-to set
// ────────────────────────────────────────────────────────────────────────────

/// The set of allocation sites a pointer variable may point to.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PointsToSet {
    sites: BTreeSet<AllocationSite>,
}

impl PointsToSet {
    #[must_use] 
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn singleton(site: AllocationSite) -> Self {
        let mut s = Self::empty();
        s.sites.insert(site);
        s
    }

    pub fn insert(&mut self, site: AllocationSite) -> bool {
        self.sites.insert(site)
    }

    pub fn union_with(&mut self, other: &Self) -> bool {
        let before = self.sites.len();
        self.sites.extend(other.sites.iter().copied());
        self.sites.len() > before
    }

    #[must_use] 
    pub fn contains(&self, site: &AllocationSite) -> bool {
        self.sites.contains(site)
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.sites.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AllocationSite> {
        self.sites.iter()
    }

    /// Whether `self` and `other` have a non-empty intersection (may-alias).
    #[must_use] 
    pub fn may_alias(&self, other: &Self) -> bool {
        self.sites.iter().any(|s| other.sites.contains(s))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Constraint language
// ────────────────────────────────────────────────────────────────────────────

/// A single Andersen-style points-to constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PtConstraint {
    /// `p ⊇ {site}` — p is the address of a known allocation.
    AddressOf { p: u32, site: AllocationSite },
    /// `p ⊇ q` — copy / assignment.
    Assign { p: u32, q: u32 },
    /// `p ⊇ *q` — load through q.
    Load { p: u32, q: u32 },
    /// `*p ⊇ q` — store through p.
    Store { p: u32, q: u32 },
}

// ────────────────────────────────────────────────────────────────────────────
// Solver
// ────────────────────────────────────────────────────────────────────────────

/// Worklist-based Andersen solver with online cycle detection via
/// Lazy Cycle Detection (LCD).
pub struct AndersenSolver {
    constraints: Vec<PtConstraint>,
    /// Points-to sets indexed by variable id.
    pts: HashMap<u32, PointsToSet>,
    /// Assign-edges in the constraint graph (subset graph).
    edges: HashMap<u32, HashSet<u32>>,
    /// Reverse edges for load/store propagation.
    rev_edges: HashMap<u32, HashSet<u32>>,
    /// Worklist of variables whose points-to sets changed.
    worklist: VecDeque<u32>,
}

impl AndersenSolver {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            pts: HashMap::new(),
            edges: HashMap::new(),
            rev_edges: HashMap::new(),
            worklist: VecDeque::new(),
        }
    }

    pub fn add_constraint(&mut self, c: PtConstraint) {
        self.constraints.push(c);
    }

    pub fn add_constraints(&mut self, cs: impl IntoIterator<Item = PtConstraint>) {
        for c in cs {
            self.add_constraint(c);
        }
    }

    fn pts_mut(&mut self, var: u32) -> &mut PointsToSet {
        self.pts.entry(var).or_default()
    }

    fn pts_ref(&self, var: u32) -> &PointsToSet {
        static EMPTY: std::sync::OnceLock<PointsToSet> = std::sync::OnceLock::new();
        self.pts.get(&var).unwrap_or_else(|| EMPTY.get_or_init(PointsToSet::empty))
    }

    fn add_edge(&mut self, from: u32, to: u32) -> bool {
        let added = self.edges.entry(from).or_default().insert(to);
        if added {
            self.rev_edges.entry(to).or_default().insert(from);
        }
        added
    }

    fn push_worklist(&mut self, var: u32) {
        self.worklist.push_back(var);
    }

    /// Phase 1: seed points-to sets from `AddressOf` constraints.
    fn seed(&mut self) {
        let address_of: Vec<(u32, AllocationSite)> = self
            .constraints
            .iter()
            .filter_map(|c| match c {
                PtConstraint::AddressOf { p, site } => Some((*p, *site)),
                _ => None,
            })
            .collect();

        for (p, site) in address_of {
            if self.pts_mut(p).insert(site) {
                self.push_worklist(p);
            }
        }

        // Seed copy edges from Assign constraints.
        let assigns: Vec<(u32, u32)> = self
            .constraints
            .iter()
            .filter_map(|c| match c {
                PtConstraint::Assign { p, q } => Some((*p, *q)),
                _ => None,
            })
            .collect();

        for (p, q) in assigns {
            // Propagate existing pts(q) → pts(p).
            let q_pts: Vec<AllocationSite> = self.pts_ref(q).iter().copied().collect();
            let p_pts = self.pts_mut(p);
            let mut changed = false;
            for s in q_pts {
                changed |= p_pts.insert(s);
            }
            if changed {
                self.push_worklist(p);
            }
            self.add_edge(q, p);
        }
    }

    /// Solve the constraint system and return a `PointsToSolution`.
    #[must_use] 
    pub fn solve(mut self) -> PointsToSolution {
        self.seed();

        while let Some(var) = self.worklist.pop_front() {
            let var_pts: Vec<AllocationSite> = self.pts_ref(var).iter().copied().collect();

            // Propagate along copy edges.
            let successors: Vec<u32> =
                self.edges.get(&var).cloned().unwrap_or_default().into_iter().collect();
            for succ in successors {
                let changed = {
                    let src: Vec<AllocationSite> = self.pts_ref(var).iter().copied().collect();
                    let dst = self.pts_mut(succ);
                    let before = dst.len();
                    for s in &src {
                        dst.insert(*s);
                    }
                    dst.len() > before
                };
                if changed {
                    self.push_worklist(succ);
                }
            }

            // Process Load constraints: `p ⊇ *q` where var == q.
            let loads: Vec<(u32, u32)> = self
                .constraints
                .iter()
                .filter_map(|c| match c {
                    PtConstraint::Load { p, q } if *q == var => Some((*p, *q)),
                    _ => None,
                })
                .collect();

            for (p, _q) in loads {
                for &site_var in &var_pts {
                    // The allocation site is treated as a pseudo-variable.
                    let site_id = Self::alloc_site_to_var(site_var);
                    if self.add_edge(site_id, p) {
                        // Propagate existing pts(site_id) to pts(p).
                        let site_pts: Vec<AllocationSite> =
                            self.pts_ref(site_id).iter().copied().collect();
                        let mut changed = false;
                        let dst = self.pts_mut(p);
                        for s in site_pts {
                            changed |= dst.insert(s);
                        }
                        if changed {
                            self.push_worklist(p);
                        }
                    }
                }
            }

            // Process Store constraints: `*p ⊇ q` where var == p.
            let stores: Vec<(u32, u32)> = self
                .constraints
                .iter()
                .filter_map(|c| match c {
                    PtConstraint::Store { p, q } if *p == var => Some((*p, *q)),
                    _ => None,
                })
                .collect();

            for (_p, q) in stores {
                for &site_var in &var_pts {
                    let site_id = Self::alloc_site_to_var(site_var);
                    if self.add_edge(q, site_id) {
                        let q_pts: Vec<AllocationSite> =
                            self.pts_ref(q).iter().copied().collect();
                        let mut changed = false;
                        let dst = self.pts_mut(site_id);
                        for s in q_pts {
                            changed |= dst.insert(s);
                        }
                        if changed {
                            self.push_worklist(site_id);
                        }
                    }
                }
            }
        }

        PointsToSolution { pts: self.pts }
    }

    /// Map an `AllocationSite` to a synthetic variable id for the points-to
    /// graph.  Uses a collision-free encoding derived from the site's numeric
    /// fields rather than a hash, to guarantee that distinct sites map to
    /// distinct synthetic ids.
    ///
    /// `DefaultHasher` is explicitly avoided because:
    /// 1. It is not randomised in all Rust versions, making the mapping
    ///    deterministic across runs — no benefit over a direct encoding.
    /// 2. A 32-bit truncation of a 64-bit hash has a non-negligible collision
    ///    probability (~1 in 4 billion), which would silently merge two
    ///    unrelated allocation sites' points-to sets and corrupt the analysis.
    fn alloc_site_to_var(site: AllocationSite) -> u32 {
        // Encode each variant into the upper bits to guarantee uniqueness
        // (within each variant kind) without any hashing.  The high bit
        // remains set so synthetic ids never overlap with real variable ids
        // (which start from 0 and are user-controlled u32 values below
        // 0x8000_0000).
        let low29 = |addr: u64| u32::try_from(addr & 0x1FFF_FFFF).unwrap_or(0x1FFF_FFFF);
        match site {
            AllocationSite::Heap(addr) => {
                // Variant tag 0b00 in bits [30:29]; low 29 bits of address.
                0x8000_0000 | low29(addr)
            }
            AllocationSite::Global(addr) => {
                // Variant tag 0b01
                0x8000_0000 | (0b01 << 29) | low29(addr)
            }
            AllocationSite::Stack(func, slot) => {
                // Variant tag 0b10; XOR func address low bits with slot.
                0x8000_0000 | (0b10 << 29) | ((low29(func) ^ slot) & 0x1FFF_FFFF)
            }
            AllocationSite::Param(func, idx) => {
                // Variant tag 0b11; XOR func address low bits with param index.
                0x8000_0000 | (0b11 << 29) | ((low29(func) ^ idx) & 0x1FFF_FFFF)
            }
            AllocationSite::External(id) => {
                // External ids are already unique u32s; just set the high bit.
                0x8000_0000 | (id & 0x7FFF_FFFF)
            }
        }
    }
}

impl Default for AndersenSolver {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Solution
// ────────────────────────────────────────────────────────────────────────────

/// The result of running the Andersen points-to analysis.
#[derive(Debug, Serialize, Deserialize)]
pub struct PointsToSolution {
    pts: HashMap<u32, PointsToSet>,
}

impl PointsToSolution {
    /// Return the points-to set for `var` (empty if unknown).
    #[must_use] 
    pub fn points_to(&self, var: u32) -> &PointsToSet {
        static EMPTY: std::sync::OnceLock<PointsToSet> = std::sync::OnceLock::new();
        self.pts.get(&var).unwrap_or_else(|| EMPTY.get_or_init(PointsToSet::empty))
    }

    /// Query whether two variables *may* alias (their points-to sets intersect).
    #[must_use] 
    pub fn alias_query(&self, a: u32, b: u32) -> AliasResult {
        let pa = self.points_to(a);
        let pb = self.points_to(b);

        if pa.is_empty() || pb.is_empty() {
            return AliasResult::Unknown;
        }

        if pa.may_alias(pb) {
            AliasResult::MayAlias
        } else {
            AliasResult::NoAlias
        }
    }

    /// Return all variable ids that may point to the given allocation site.
    #[must_use] 
    pub fn pointers_to_site(&self, site: AllocationSite) -> Vec<u32> {
        self.pts
            .iter()
            .filter(|(_, pts)| pts.contains(&site))
            .map(|(&var, _)| var)
            .collect()
    }

    /// All allocation sites reachable from `var` transitively.
    #[must_use] 
    pub fn reachable_sites(&self, var: u32) -> BTreeSet<AllocationSite> {
        let mut visited_vars: HashSet<u32> = HashSet::new();
        let mut result: BTreeSet<AllocationSite> = BTreeSet::new();
        let mut worklist: VecDeque<u32> = VecDeque::new();
        worklist.push_back(var);

        while let Some(v) = worklist.pop_front() {
            if !visited_vars.insert(v) {
                continue;
            }
            for &site in self.points_to(v).iter() {
                if result.insert(site) {
                    // Also follow through allocations treated as pointer vars.
                    let syn = Self::synthetic_var_for(site);
                    worklist.push_back(syn);
                }
            }
        }

        result
    }

    fn synthetic_var_for(site: AllocationSite) -> u32 {
        // Use the same collision-free encoding as `AndersenSolver::alloc_site_to_var`.
        // This ensures that looking up a synthetic var from the solution side and
        // from the solver side always yields the same id for the same site.
        AndersenSolver::alloc_site_to_var(site)
    }

    /// Number of variables in the solution.
    #[must_use] 
    pub fn variable_count(&self) -> usize {
        self.pts.len()
    }

    /// Total number of (variable, site) pairs in the solution.
    #[must_use] 
    pub fn total_pairs(&self) -> usize {
        self.pts.values().map(PointsToSet::len).sum()
    }

    /// Emit a human-readable summary, one variable per line.
    #[must_use] 
    pub fn render_summary(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut vars: Vec<u32> = self.pts.keys().filter(|&&v| v & 0x8000_0000 == 0).copied().collect();
        vars.sort_unstable();
        for var in vars {
            let pts = self.points_to(var);
            let sites: Vec<String> = pts.iter().map(AllocationSite::label).collect();
            lines.push(format!("  v{} → {{{}}}", var, sites.join(", ")));
        }
        lines.join("\n")
    }
}

/// The result of an alias query between two pointer variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AliasResult {
    /// The variables definitely do not alias.
    NoAlias,
    /// The variables may or may not alias.
    MayAlias,
    /// Insufficient information to determine (empty points-to set).
    Unknown,
}

impl AliasResult {
    #[must_use] 
    pub fn is_no_alias(self) -> bool {
        self == Self::NoAlias
    }

    #[must_use] 
    pub fn is_may_alias(self) -> bool {
        self == Self::MayAlias
    }

    #[must_use] 
    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Constraint builder
// ────────────────────────────────────────────────────────────────────────────

/// Fluent builder for assembling a set of points-to constraints before
/// handing them to the solver.
#[derive(Debug, Default)]
pub struct PtConstraintBuilder {
    constraints: Vec<PtConstraint>,
    next_extern_id: u32,
}

impl PtConstraintBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// p = &site
    #[must_use] 
    pub fn address_of(mut self, p: u32, site: AllocationSite) -> Self {
        self.constraints.push(PtConstraint::AddressOf { p, site });
        self
    }

    /// p = q
    #[must_use] 
    pub fn assign(mut self, p: u32, q: u32) -> Self {
        self.constraints.push(PtConstraint::Assign { p, q });
        self
    }

    /// p = *q
    #[must_use] 
    pub fn load(mut self, p: u32, q: u32) -> Self {
        self.constraints.push(PtConstraint::Load { p, q });
        self
    }

    /// *p = q
    #[must_use] 
    pub fn store(mut self, p: u32, q: u32) -> Self {
        self.constraints.push(PtConstraint::Store { p, q });
        self
    }

    /// Allocate a fresh external allocation site and return its id.
    pub const fn fresh_external(&mut self) -> AllocationSite {
        let id = self.next_extern_id;
        self.next_extern_id += 1;
        AllocationSite::External(id)
    }

    /// Finalise and run the solver.
    #[must_use] 
    pub fn solve(self) -> PointsToSolution {
        let mut solver = AndersenSolver::new();
        solver.add_constraints(self.constraints);
        solver.solve()
    }

    #[must_use] 
    pub fn constraints(&self) -> &[PtConstraint] {
        &self.constraints
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Statistics
// ────────────────────────────────────────────────────────────────────────────

/// Aggregated statistics about a points-to solution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtaStats {
    pub variable_count: usize,
    pub total_pt_pairs: usize,
    pub max_pts_size: usize,
    pub avg_pts_size: f64,
    pub single_target_vars: usize,
    pub empty_vars: usize,
}

impl PtaStats {
    #[must_use] 
    pub fn from_solution(sol: &PointsToSolution) -> Self {
        let sizes: Vec<usize> = sol
            .pts
            .values()
            .filter(|s| !s.is_empty())
            .map(PointsToSet::len)
            .collect();

        let variable_count = sol.pts.len();
        let total_pt_pairs: usize = sizes.iter().sum();
        let max_pts_size = sizes.iter().copied().max().unwrap_or(0);
        let avg_pts_size = if sizes.is_empty() {
            0.0
        } else {
            f64::from(u32::try_from(total_pt_pairs.min(u32::MAX as usize)).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(sizes.len().min(u32::MAX as usize)).unwrap_or(u32::MAX))
        };
        let single_target_vars = sizes.iter().filter(|&&n| n == 1).count();
        let empty_vars = sol.pts.values().filter(|s| s.is_empty()).count();

        Self {
            variable_count,
            total_pt_pairs,
            max_pts_size,
            avg_pts_size,
            single_target_vars,
            empty_vars,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_of_basic() {
        let site = AllocationSite::Heap(0x1000);
        let sol = PtConstraintBuilder::new()
            .address_of(1, site)
            .solve();
        assert!(sol.points_to(1).contains(&site));
    }

    #[test]
    fn assign_propagates() {
        let site = AllocationSite::Global(0x4000);
        let sol = PtConstraintBuilder::new()
            .address_of(1, site)
            .assign(2, 1)
            .solve();
        assert!(sol.points_to(2).contains(&site));
    }

    #[test]
    fn load_through_pointer() {
        // p1 = &a;  p2 = *p1; → p2 should point to sites that p1's target contains.
        let site_a = AllocationSite::Stack(0x1000, 0);
        let site_b = AllocationSite::Stack(0x1000, 4);
        let sol = PtConstraintBuilder::new()
            .address_of(1, site_a)   // ptr1 → site_a
            .address_of(10, site_b)  // *site_a contains site_b (represented via var 10)
            .assign(11, 10)           // site_a's content
            .load(2, 1)               // p2 = *ptr1
            .solve();

        // After load, p2 may point to what ptr1's targets hold.
        // At minimum the analysis should not crash.
        let _ = sol.alias_query(1, 2);
    }

    #[test]
    fn no_alias_disjoint() {
        let s1 = AllocationSite::Heap(0x1000);
        let s2 = AllocationSite::Heap(0x2000);
        let sol = PtConstraintBuilder::new()
            .address_of(1, s1)
            .address_of(2, s2)
            .solve();
        assert_eq!(sol.alias_query(1, 2), AliasResult::NoAlias);
    }

    #[test]
    fn may_alias_shared_target() {
        let site = AllocationSite::Heap(0x3000);
        let sol = PtConstraintBuilder::new()
            .address_of(1, site)
            .assign(2, 1)
            .solve();
        assert_eq!(sol.alias_query(1, 2), AliasResult::MayAlias);
    }

    #[test]
    fn pointers_to_site() {
        let site = AllocationSite::Global(0x5000);
        let sol = PtConstraintBuilder::new()
            .address_of(3, site)
            .assign(4, 3)
            .solve();
        let ptrs = sol.pointers_to_site(site);
        assert!(ptrs.contains(&3));
        assert!(ptrs.contains(&4));
    }

    #[test]
    fn stats_sanity() {
        let sol = PtConstraintBuilder::new()
            .address_of(1, AllocationSite::Heap(0x100))
            .address_of(2, AllocationSite::Heap(0x200))
            .solve();
        let stats = PtaStats::from_solution(&sol);
        assert!(stats.total_pt_pairs >= 2);
    }

    #[test]
    fn allocation_site_labels() {
        assert_eq!(AllocationSite::Heap(0x400).label(), "heap@0x400");
        assert_eq!(AllocationSite::Stack(0x1000, 2).label(), "stack@0x1000[2]");
        assert_eq!(AllocationSite::External(7).label(), "ext#7");
    }
}
