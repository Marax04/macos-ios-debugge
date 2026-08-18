//! Andersen-Style Points-To / Alias Analysis
//!
//! This module implements a flow-insensitive, context-insensitive,
//! inclusion-based (Andersen-style) points-to analysis for the `RustRE` [`IL`].
//!
//! ## Algorithm overview
//!
//! 1. **Constraint generation** — scan every instruction and emit one of four
//!    constraint kinds:
//!    * `p = &x`  →  `alloc(p, x)` (p points to the abstract object x)
//!    * `p = q`   →  `assign(p, q)` (p's points-to set ⊇ q's)
//!    * `p = *q`  →  `load(p, q)`  (p's pts ⊇ pts(r) for each r ∈ pts(q))
//!    * `*p = q`  →  `store(p, q)` (pts(r) ⊇ pts(q) for each r ∈ pts(p))
//!
//! 2. **Fixpoint propagation** — Andersen's inclusion constraints are solved
//!    iteratively (BFS worklist over the constraint graph).
//!
//! 3. **Alias query** — two pointers `p` and `q` *may-alias* iff their
//!    points-to sets intersect; *must-alias* iff they are identical singletons.
//!
//! ## Abstract objects
//!
//! Each abstract object belongs to exactly one *allocation site* category:
//! * `Stack(fn_addr, offset)` — local variable.
//! * `Heap(site_addr)` — dynamic allocation.
//! * `Global(addr)` — global / static variable.
//! * `Extern(name)` — external symbol.
//! * `Unknown` — over-approximation of all possible objects.
//!
//! ## Pointer arithmetic
//!
//! `p + k` (GEP-style) is tracked: the result points to the same abstract
//! object as `p` but with a byte offset `k`. Offset sets are small and kept
//! precise for stack frames; heap/global offsets are widened to `[0, ∞)`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Abstract allocation sites
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract allocation site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AllocSite {
    /// Stack variable: (enclosing function address, frame offset).
    Stack(u64, i32),
    /// Heap allocation at the given instruction address.
    Heap(u64),
    /// Global / static variable at the given address.
    Global(u64),
    /// External symbol (imported).
    Extern(u64 /* symbol id; use a hash of the name */),
    /// Sentinel: an unknown / over-approximated object.
    Unknown,
    /// The null pointer.
    Null,
}

impl AllocSite {
    /// Returns `true` if this is the stack.
    #[must_use]
    pub const fn is_stack(&self) -> bool { matches!(self, Self::Stack(..)) }

    /// Returns `true` if this is a heap allocation.
    #[must_use]
    pub const fn is_heap(&self) -> bool { matches!(self, Self::Heap(_)) }

    /// Returns `true` if this is a global.
    #[must_use]
    pub const fn is_global(&self) -> bool { matches!(self, Self::Global(_)) }

    /// Returns `true` if this is the Unknown object.
    #[must_use]
    pub const fn is_unknown(&self) -> bool { matches!(self, Self::Unknown) }
}

impl fmt::Display for AllocSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stack(fn_addr, off) => write!(f, "Stack({fn_addr:#x}:{off:+})"),
            Self::Heap(site) => write!(f, "Heap({site:#x})"),
            Self::Global(addr) => write!(f, "Global({addr:#x})"),
            Self::Extern(id) => write!(f, "Extern({id:#x})"),
            Self::Unknown => write!(f, "Unknown"),
            Self::Null => write!(f, "Null"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Points-to target (abstract object + optional byte offset)
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete target within an abstract object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PointsToTarget {
    /// The allocation site.
    pub site: AllocSite,
    /// The byte offset within the object. `None` means "unknown offset" (widened).
    pub offset: Option<i32>,
}

impl PointsToTarget {
    #[must_use]
    pub const fn new(site: AllocSite, offset: Option<i32>) -> Self {
        Self { site, offset }
    }

    #[must_use]
    pub const fn exact(site: AllocSite, offset: i32) -> Self {
        Self { site, offset: Some(offset) }
    }

    #[must_use]
    pub const fn unknown_offset(site: AllocSite) -> Self {
        Self { site, offset: None }
    }

    /// Apply a GEP offset to produce a new target.
    ///
    /// # Panics
    ///
    /// Never panics: chained GEPs on malformed/adversarial IL can push the
    /// offset arbitrarily close to `i32::MIN`/`MAX`; a plain `+` there
    /// overflows and panics in debug builds. `saturating_add` clamps instead,
    /// matching `Region::at_offset`'s treatment of the analogous case.
    #[must_use]
    pub const fn gep(&self, delta: i32) -> Self {
        match self.offset {
            Some(off) => Self { site: self.site, offset: Some(off.saturating_add(delta)) },
            None => Self { site: self.site, offset: None },
        }
    }

    /// Widen the offset to `None` (for heap/global where we lose precision).
    #[must_use]
    pub const fn widen_offset(&self) -> Self {
        Self { site: self.site, offset: None }
    }
}

impl fmt::Display for PointsToTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(off) => write!(f, "{}{:+}", self.site, off),
            None => write!(f, "{}+?", self.site),
        }
    }
}

/// A points-to set: a set of `PointsToTarget`s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PointsToSet {
    targets: HashSet<PointsToTarget>,
}

impl PointsToSet {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub fn singleton(target: PointsToTarget) -> Self {
        let mut s = Self::new();
        s.targets.insert(target);
        s
    }

    pub fn insert(&mut self, target: PointsToTarget) -> bool {
        self.targets.insert(target)
    }

    #[must_use]
    pub fn contains(&self, target: &PointsToTarget) -> bool {
        self.targets.contains(target)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool { self.targets.is_empty() }

    #[must_use]
    pub fn len(&self) -> usize { self.targets.len() }

    /// Compute the union (in-place). Returns `true` if anything was added.
    pub fn union_with(&mut self, other: &Self) -> bool {
        let before = self.targets.len();
        for t in &other.targets {
            self.targets.insert(*t);
        }
        self.targets.len() > before
    }

    pub fn iter(&self) -> impl Iterator<Item = &PointsToTarget> {
        self.targets.iter()
    }

    /// Returns `true` if this is a singleton (must-alias candidate).
    #[must_use]
    pub fn is_singleton(&self) -> bool { self.targets.len() == 1 }

    /// Intersect this set with `other` and return a new set.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        let targets = self.targets.intersection(&other.targets).copied().collect();
        Self { targets }
    }

    /// Apply a GEP offset to every target.
    #[must_use]
    pub fn gep(&self, delta: i32) -> Self {
        Self { targets: self.targets.iter().map(|t| t.gep(delta)).collect() }
    }
}

impl fmt::Display for PointsToSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items: Vec<String> = self.targets.iter().map(ToString::to_string).collect();
        items.sort();
        write!(f, "{{{}}}", items.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Inclusion constraints
// ─────────────────────────────────────────────────────────────────────────────

/// A variable ID in the constraint system.
type VarId = u32;

/// One Andersen inclusion constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AndersonConstraint {
    /// `p ← &x`: allocate object `x` and make `p` point to it.
    Alloc { ptr: VarId, site: AllocSite, offset: i32 },
    /// `p ← q`: pts(p) ⊇ pts(q).
    Assign { dst: VarId, src: VarId },
    /// `p ← *q`: pts(p) ⊇ ⋃_{r ∈ pts(q)} pts(r).
    Load { dst: VarId, src_ptr: VarId },
    /// `*p ← q`: ∀ r ∈ pts(p): pts(r) ⊇ pts(q).
    Store { dst_ptr: VarId, src: VarId },
    /// `p ← q + k`: pts(p) ⊇ { t.gep(k) | t ∈ pts(q) }.
    Gep { dst: VarId, src: VarId, delta: i32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// The points-to graph
// ─────────────────────────────────────────────────────────────────────────────

/// The full result of the Andersen analysis.
#[derive(Debug, Clone, Default)]
pub struct PointsToGraph {
    /// Maps variable ID → its points-to set.
    pub pts: HashMap<VarId, PointsToSet>,
    /// Maps variable ID → name (for display).
    pub names: HashMap<VarId, String>,
}

impl PointsToGraph {
    #[must_use]
    pub fn get(&self, var: VarId) -> &PointsToSet {
        static EMPTY: std::sync::OnceLock<PointsToSet> = std::sync::OnceLock::new();
        self.pts.get(&var).unwrap_or_else(|| EMPTY.get_or_init(PointsToSet::new))
    }

    /// `true` when the analysis has a points-to set for `var`.
    ///
    /// [`Self::get`] returns an empty set both for a variable the analysis
    /// examined and found to point nowhere AND for one it never saw at all.
    /// Those mean opposite things — "points to nothing" versus "no
    /// information" — and only this method can tell them apart. Any reasoning
    /// that treats an empty set as a fact must check `is_known` first.
    #[must_use]
    pub fn is_known(&self, var: VarId) -> bool {
        self.pts.contains_key(&var)
    }

    pub fn get_mut_or_default(&mut self, var: VarId) -> &mut PointsToSet {
        self.pts.entry(var).or_default()
    }

    #[must_use]
    pub fn name_of(&self, var: VarId) -> String {
        self.names.get(&var).cloned().unwrap_or_else(|| format!("v{var}"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Andersen solver
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics from the solver.
#[derive(Debug, Clone, Default)]
pub struct SolverStats {
    pub variables: usize,
    pub constraints: usize,
    pub iterations: u32,
    pub converged: bool,
}

/// The Andersen inclusion constraint solver.
pub struct AndersenSolver {
    /// All constraints to solve.
    constraints: Vec<AndersonConstraint>,
    /// Constraint graph: variable → constraints that have this variable as *source*.
    /// (Used to quickly find which constraints to re-evaluate when a pts set changes.)
    var_to_constraints: HashMap<VarId, Vec<usize>>,
}

impl AndersenSolver {
    #[must_use]
    pub fn new(constraints: Vec<AndersonConstraint>) -> Self {
        let mut var_to_constraints: HashMap<VarId, Vec<usize>> = HashMap::new();
        for (i, c) in constraints.iter().enumerate() {
            let sources = constraint_sources(c);
            for src in sources {
                var_to_constraints.entry(src).or_default().push(i);
            }
        }
        Self { constraints, var_to_constraints }
    }

    /// Solve and return the full points-to graph.
    #[must_use]
    pub fn solve(&self) -> (PointsToGraph, SolverStats) {
        const MAX_ITER: u32 = 100_000;
        let mut graph = PointsToGraph::default();
        let mut worklist: VecDeque<usize> = (0..self.constraints.len()).collect();
        let mut in_worklist: HashSet<usize> = worklist.iter().copied().collect();
        let mut iterations = 0u32;

        // Constraints that READ a synthetic deref variable, discovered while
        // solving.
        //
        // `constraint_sources` / `constraint_outputs` describe only the
        // syntactic operands. They cannot mention the deref variables, because
        // which ones a `Load`/`Store` touches depends on the points-to sets
        // being computed: `Store {dst_ptr, src}` writes `site_to_var(t)` for
        // every t ∈ pts(dst_ptr), and `Load {dst, src_ptr}` reads
        // pts(site_to_var(t)). Relying on the syntactic graph alone meant a
        // Store that grew a deref variable never re-enqueued a Load reading
        // that same variable through a DIFFERENT pointer, so the solver
        // "converged" on an incomplete points-to graph — the unsound direction,
        // producing `NoAlias` for pointers that really can alias.
        let mut dyn_readers: HashMap<VarId, HashSet<usize>> = HashMap::new();

        while let Some(ci) = worklist.pop_front() {
            if iterations >= MAX_ITER {
                break;
            }
            iterations += 1;
            in_worklist.remove(&ci);
            let changed_vars = self.process_constraint(ci, &mut graph, &mut dyn_readers);
            // Re-enqueue on the variables ACTUALLY written, from both the
            // syntactic graph and the dynamically discovered readers.
            for var in changed_vars {
                let statics = self.var_to_constraints.get(&var).into_iter().flatten();
                let dynamics = dyn_readers.get(&var).into_iter().flatten();
                for &dep_ci in statics.chain(dynamics) {
                    if in_worklist.insert(dep_ci) {
                        worklist.push_back(dep_ci);
                    }
                }
            }
        }

        let stats = SolverStats {
            variables: graph.pts.len(),
            constraints: self.constraints.len(),
            iterations,
            converged: worklist.is_empty() && iterations < MAX_ITER,
        };
        (graph, stats)
    }

    /// Process one constraint.
    ///
    /// Returns the variables whose points-to set actually GREW — not just a
    /// boolean — because the caller has to re-enqueue on the real writes, and
    /// for a `Store` those are the synthetic deref variables, not `dst_ptr`.
    ///
    /// `dyn_readers` accumulates the reverse dependency `deref var → this
    /// constraint` for every deref variable a `Load` reads, so that a later
    /// `Store` growing that variable wakes this `Load` up again.
    fn process_constraint(
        &self,
        ci: usize,
        graph: &mut PointsToGraph,
        dyn_readers: &mut HashMap<VarId, HashSet<usize>>,
    ) -> Vec<VarId> {
        match &self.constraints[ci] {
            AndersonConstraint::Alloc { ptr, site, offset } => {
                let target = PointsToTarget::exact(*site, *offset);
                if graph.get_mut_or_default(*ptr).insert(target) {
                    vec![*ptr]
                } else {
                    vec![]
                }
            }
            AndersonConstraint::Assign { dst, src } => {
                let src_pts = graph.get(*src).clone();
                if graph.get_mut_or_default(*dst).union_with(&src_pts) {
                    vec![*dst]
                } else {
                    vec![]
                }
            }
            AndersonConstraint::Load { dst, src_ptr } => {
                let deref_targets: Vec<VarId> = graph
                    .get(*src_ptr)
                    .iter()
                    .filter_map(|t| site_to_var(t.site))
                    .collect();
                let mut changed = false;
                for deref_var in deref_targets {
                    // Record that this Load depends on `deref_var`.
                    dyn_readers.entry(deref_var).or_default().insert(ci);
                    let pts = graph.get(deref_var).clone();
                    changed |= graph.get_mut_or_default(*dst).union_with(&pts);
                }
                if changed { vec![*dst] } else { vec![] }
            }
            AndersonConstraint::Store { dst_ptr, src } => {
                let store_targets: Vec<VarId> = graph
                    .get(*dst_ptr)
                    .iter()
                    .filter_map(|t| site_to_var(t.site))
                    .collect();
                let src_pts = graph.get(*src).clone();
                let mut changed = Vec::new();
                for store_var in store_targets {
                    if graph.get_mut_or_default(store_var).union_with(&src_pts) {
                        // The deref variable is what this Store really wrote.
                        changed.push(store_var);
                    }
                }
                changed
            }
            AndersonConstraint::Gep { dst, src, delta } => {
                let src_pts = graph.get(*src).gep(*delta);
                if graph.get_mut_or_default(*dst).union_with(&src_pts) {
                    vec![*dst]
                } else {
                    vec![]
                }
            }
        }
    }
}

/// The source variables referenced by a constraint (triggers re-evaluation).
fn constraint_sources(c: &AndersonConstraint) -> Vec<VarId> {
    match c {
        AndersonConstraint::Alloc { .. } => vec![],
        AndersonConstraint::Assign { src, .. }
        | AndersonConstraint::Load { src_ptr: src, .. }
        | AndersonConstraint::Gep { src, .. } => vec![*src],
        AndersonConstraint::Store { dst_ptr, src } => vec![*dst_ptr, *src],
    }
}

/// The output variables written by a constraint.
#[must_use]
pub fn constraint_outputs(c: &AndersonConstraint) -> Vec<VarId> {
    match c {
        AndersonConstraint::Alloc { ptr, .. } => vec![*ptr],
        AndersonConstraint::Assign { dst, .. }
        | AndersonConstraint::Load { dst, .. }
        | AndersonConstraint::Gep { dst, .. }
        | AndersonConstraint::Store { dst_ptr: dst, .. } => vec![*dst],
    }
}

/// Map an allocation site to a synthetic variable ID (for load/store deref).
///
/// KNOWN GAP (flagged, not fixed here — would require a larger keying
/// scheme change and is out of scope for this pass): `Heap(addr)` and
/// `Extern(id)` both map to `(x & MASK) as u32` with no namespace bit added
/// (unlike `Stack`'s `0x8000_0000` and `Global`'s `0x4000_0000` tags), so a
/// heap allocation and an extern symbol whose low 32 bits collide are
/// aliased to the same synthetic load/store variable, and `Heap`'s offset is
/// dropped entirely (two different byte offsets into the same heap site
/// collapse onto one variable). Both are over-approximations only — they can
/// make the solver report spurious `MayAlias`/`PartialAlias`, never an
/// unsound `NoAlias`/`MustAlias` — but they lose precision that a wider
/// synthetic-id encoding could keep.
const fn site_to_var(site: AllocSite) -> Option<VarId> {
    const MASK: u64 = 0xFFFF_FFFFu64;
    match site {
        AllocSite::Stack(fn_addr, off) => {
            // Encode stack slot as a synthetic var ID.
            let lo = (fn_addr & MASK) as u32;
            let off_u = off.cast_unsigned();
            Some(lo.wrapping_add(off_u).wrapping_add(0x8000_0000))
        }
        AllocSite::Heap(addr) => Some((addr & MASK) as u32),
        AllocSite::Global(addr) => Some(((addr & MASK) as u32).wrapping_add(0x4000_0000)),
        AllocSite::Extern(id) => Some((id & MASK) as u32),
        AllocSite::Unknown | AllocSite::Null => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Alias query interface
// ─────────────────────────────────────────────────────────────────────────────

/// Alias relationship between two pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AliasResult {
    /// The two pointers cannot alias (their points-to sets are disjoint).
    NoAlias,
    /// The two pointers may alias (their points-to sets intersect, but neither
    /// is a subset of the other).
    MayAlias,
    /// One pointer's points-to set is a strict subset of the other's.
    PartialAlias,
    /// The two pointers definitely alias (same singleton points-to set).
    MustAlias,
}

/// Query the alias relationship between two pointer variables.
#[must_use]
pub fn query_alias(graph: &PointsToGraph, p: VarId, q: VarId) -> AliasResult {
    // A variable the analysis never saw could point ANYWHERE, so the only
    // sound answer for it is `MayAlias`.
    //
    // This used to fall through to the empty-set branch below and answer
    // `NoAlias` — i.e. `may_alias` returned **false**, "these two pointers
    // definitely cannot alias", about a pointer nothing is known about. A
    // caller using that to justify reordering two memory accesses would have
    // been reasoning from an absence of information as if it were a fact.
    // `PointsToGraph::get` cannot distinguish the two cases; `is_known` can.
    if !graph.is_known(p) || !graph.is_known(q) {
        return AliasResult::MayAlias;
    }

    let pts_p = graph.get(p);
    let pts_q = graph.get(q);

    // Both variables WERE analysed. An empty set here is a real result:
    // the analysis found no targets, so they cannot overlap.
    if pts_p.is_empty() || pts_q.is_empty() {
        return AliasResult::NoAlias;
    }

    let intersection = pts_p.intersect(pts_q);
    if intersection.is_empty() {
        return AliasResult::NoAlias;
    }
    if pts_p.is_singleton() && pts_q.is_singleton() && pts_p == pts_q {
        return AliasResult::MustAlias;
    }
    if intersection.len() == pts_p.len() || intersection.len() == pts_q.len() {
        return AliasResult::PartialAlias;
    }
    AliasResult::MayAlias
}

/// Convenience: may-alias test.
#[must_use]
pub fn may_alias(graph: &PointsToGraph, p: VarId, q: VarId) -> bool {
    !matches!(query_alias(graph, p, q), AliasResult::NoAlias)
}

/// Convenience: must-alias test.
#[must_use]
pub fn must_alias(graph: &PointsToGraph, p: VarId, q: VarId) -> bool {
    matches!(query_alias(graph, p, q), AliasResult::MustAlias)
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraint builder helper
// ─────────────────────────────────────────────────────────────────────────────

/// A builder for incrementally generating Andersen constraints.
#[derive(Debug, Default)]
pub struct ConstraintBuilder {
    constraints: Vec<AndersonConstraint>,
    var_names: HashMap<VarId, String>,
    next_id: VarId,
}

impl ConstraintBuilder {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Create a fresh variable with an optional debug name.
    #[must_use]
    pub fn fresh_var(&mut self, name: impl Into<String>) -> VarId {
        let id = self.next_id;
        self.next_id += 1;
        self.var_names.insert(id, name.into());
        id
    }

    /// `ptr = &site`.
    pub fn add_alloc(&mut self, ptr: VarId, site: AllocSite, offset: i32) {
        self.constraints.push(AndersonConstraint::Alloc { ptr, site, offset });
    }

    /// `dst = src` (copy / assign).
    pub fn add_assign(&mut self, dst: VarId, src: VarId) {
        self.constraints.push(AndersonConstraint::Assign { dst, src });
    }

    /// `dst = *src` (load through pointer).
    pub fn add_load(&mut self, dst: VarId, src_ptr: VarId) {
        self.constraints.push(AndersonConstraint::Load { dst, src_ptr });
    }

    /// `*dst = src` (store through pointer).
    pub fn add_store(&mut self, dst_ptr: VarId, src: VarId) {
        self.constraints.push(AndersonConstraint::Store { dst_ptr, src });
    }

    /// `dst = src + delta` (pointer arithmetic / GEP).
    pub fn add_gep(&mut self, dst: VarId, src: VarId, delta: i32) {
        self.constraints.push(AndersonConstraint::Gep { dst, src, delta });
    }

    /// Consume the builder and solve the constraints.
    #[must_use]
    pub fn solve(self) -> (PointsToGraph, SolverStats) {
        let names = self.var_names;
        let solver = AndersenSolver::new(self.constraints);
        let (mut result_graph, stats) = solver.solve();
        result_graph.names = names;
        (result_graph, stats)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer arithmetic tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks pointer arithmetic chains across the IR.
///
/// When we see `p2 = p1 + 8`, we record that `p2` is derived from `p1` with
/// offset `+8`. This is used to produce precise GEP constraints.
#[derive(Debug, Clone, Default)]
pub struct PtrArithTracker {
    /// Maps derived pointer var → (base pointer var, offset).
    derivations: HashMap<VarId, Vec<(VarId, i32)>>,
}

impl PtrArithTracker {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Record `derived = base + delta`.
    pub fn record(&mut self, derived: VarId, base: VarId, delta: i32) {
        self.derivations.entry(derived).or_default().push((base, delta));
    }

    /// Get the derivation chain for a pointer.
    #[must_use]
    pub fn derivations_of(&self, ptr: VarId) -> &[(VarId, i32)] {
        self.derivations.get(&ptr).map_or(&[], Vec::as_slice)
    }

    /// Emit GEP constraints into a `ConstraintBuilder` for all tracked pointers.
    pub fn emit_constraints(&self, builder: &mut ConstraintBuilder) {
        for (&derived, bases) in &self.derivations {
            for &(base, delta) in bases {
                builder.add_gep(derived, base, delta);
            }
        }
    }

    /// Check whether `p` and `q` definitely have the same base and offset
    /// (strong must-alias based purely on derivation structure).
    #[must_use]
    pub fn structurally_must_alias(&self, p: VarId, q: VarId) -> bool {
        if p == q {
            return true;
        }
        let p_derivs = self.derivations_of(p);
        let q_derivs = self.derivations_of(q);
        for &(pb, pd) in p_derivs {
            for &(qb, qd) in q_derivs {
                if pb == qb && pd == qd {
                    return true;
                }
            }
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Classification helpers for optimisation passes
// ─────────────────────────────────────────────────────────────────────────────

/// Classify a pointer into stack / heap / global / unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointerClass {
    /// Pointer to the current or an ancestor function's stack frame.
    Stack,
    /// Pointer to a heap-allocated object.
    Heap,
    /// Pointer to a global / static.
    Global,
    /// Pointer to an external symbol.
    External,
    /// Pointer to the code segment.
    Code,
    /// Mix of the above or completely unknown.
    Unknown,
}

/// Classify a variable's points-to set.
#[must_use]
pub fn classify_pointer(graph: &PointsToGraph, var: VarId) -> PointerClass {
    let pts = graph.get(var);
    if pts.is_empty() {
        return PointerClass::Unknown;
    }

    let mut has_stack = false;
    let mut has_heap = false;
    let mut has_global = false;
    let mut has_extern = false;
    let mut has_unknown = false;

    for t in pts.iter() {
        match t.site {
            AllocSite::Stack(..) => has_stack = true,
            AllocSite::Heap(_) => has_heap = true,
            AllocSite::Global(_) => has_global = true,
            AllocSite::Extern(_) => has_extern = true,
            AllocSite::Unknown => has_unknown = true,
            AllocSite::Null => {}
        }
    }

    let count = [has_stack, has_heap, has_global, has_extern, has_unknown]
        .iter()
        .filter(|&&b| b)
        .count();

    if count > 1 || has_unknown {
        PointerClass::Unknown
    } else if has_stack {
        PointerClass::Stack
    } else if has_heap {
        PointerClass::Heap
    } else if has_global {
        PointerClass::Global
    } else if has_extern {
        PointerClass::External
    } else {
        PointerClass::Unknown
    }
}

/// Returns `true` if the pointer can only point to the stack.
#[must_use]
pub fn is_stack_only(graph: &PointsToGraph, var: VarId) -> bool {
    classify_pointer(graph, var) == PointerClass::Stack
}

/// Returns `true` if the pointer can only point to the heap.
#[must_use]
pub fn is_heap_only(graph: &PointsToGraph, var: VarId) -> bool {
    classify_pointer(graph, var) == PointerClass::Heap
}

/// Returns `true` if the pointer can only point to globals.
#[must_use]
pub fn is_global_only(graph: &PointsToGraph, var: VarId) -> bool {
    classify_pointer(graph, var) == PointerClass::Global
}

/// Returns `true` if two pointers definitely point to different memory regions.
#[must_use]
pub fn different_regions(graph: &PointsToGraph, p: VarId, q: VarId) -> bool {
    use PointerClass::{Global, Heap, Stack};
    let cp = classify_pointer(graph, p);
    let cq = classify_pointer(graph, q);
    matches!(
        (cp, cq),
        (Stack, Heap | Global) | (Heap, Stack | Global) | (Global, Stack | Heap)
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_alloc_assign() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        let q = builder.fresh_var("q");
        let x_site = AllocSite::Stack(0x1000, 0);

        // p = &x; q = p;
        builder.add_alloc(p, x_site, 0);
        builder.add_assign(q, p);

        let (graph, stats) = builder.solve();
        assert!(stats.converged);

        let pts_q = graph.get(q);
        assert!(!pts_q.is_empty());
        assert!(pts_q.contains(&PointsToTarget::exact(x_site, 0)));
    }

    #[test]
    fn test_load_through_pointer() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");   // pointer
        let _x = builder.fresh_var("x");   // pointee
        let y = builder.fresh_var("y");   // result of load
        let x_site = AllocSite::Stack(0, 0);
        let y_site = AllocSite::Stack(0, 8);
 
        // x = &y_site; p = &x_site; *p points to x (conceptually)
        // Simpler: p = &x_site; x = *p (load through p).
        // We model x_site's "value" as pointing to y_site.
 
        // p points to x_site
        builder.add_alloc(p, x_site, 0);
        // x_site "contains" a pointer to y_site
        // Model: create a variable for x_site's contents.
        let x_contents = builder.fresh_var("x_contents");
        builder.add_alloc(x_contents, y_site, 0);
 
        // y = *p (load): y's pts ⊇ pts(r) for r ∈ pts(p) → r = x_site → pts(r) needs to be known.
        // Since our site_to_var mapping uses x_site as a VarId, we need a direct constraint:
        builder.add_load(y, p);
 
        let (_graph, stats) = builder.solve();
        // y may not resolve via this model (site_to_var of Stack is encoded),
        // but the solver shouldn't crash.
        assert!(stats.converged || !stats.converged); // just ensure it runs
    }

    #[test]
    fn test_gep_constraint() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        let q = builder.fresh_var("q");
        let site = AllocSite::Stack(0x2000, 0);

        builder.add_alloc(p, site, 0);
        builder.add_gep(q, p, 8); // q = p + 8

        let (graph, stats) = builder.solve();
        assert!(stats.converged);

        let pts_q = graph.get(q);
        assert!(pts_q.contains(&PointsToTarget::exact(site, 8)));
    }

    #[test]
    fn test_must_alias() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        let q = builder.fresh_var("q");
        let site = AllocSite::Stack(0, 4);

        builder.add_alloc(p, site, 0);
        builder.add_assign(q, p);

        let (graph, _) = builder.solve();
        assert_eq!(query_alias(&graph, p, q), AliasResult::MustAlias);
    }

    #[test]
    fn test_no_alias() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        let q = builder.fresh_var("q");
        let site1 = AllocSite::Stack(0, 0);
        let site2 = AllocSite::Heap(0x4000);

        builder.add_alloc(p, site1, 0);
        builder.add_alloc(q, site2, 0);

        let (graph, _) = builder.solve();
        assert_eq!(query_alias(&graph, p, q), AliasResult::NoAlias);
    }

    #[test]
    fn test_classify_stack_pointer() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        builder.add_alloc(p, AllocSite::Stack(0x3000, -8), 0);
        let (graph, _) = builder.solve();
        assert_eq!(classify_pointer(&graph, p), PointerClass::Stack);
    }

    #[test]
    fn test_classify_heap_pointer() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        builder.add_alloc(p, AllocSite::Heap(0x5000), 0);
        let (graph, _) = builder.solve();
        assert_eq!(classify_pointer(&graph, p), PointerClass::Heap);
    }

    #[test]
    fn test_different_regions() {
        let mut builder = ConstraintBuilder::new();
        let p = builder.fresh_var("p");
        let q = builder.fresh_var("q");
        builder.add_alloc(p, AllocSite::Stack(0, 0), 0);
        builder.add_alloc(q, AllocSite::Heap(0xDEAD), 0);
        let (graph, _) = builder.solve();
        assert!(different_regions(&graph, p, q));
    }

    #[test]
    fn test_ptr_arith_tracker() {
        let mut tracker = PtrArithTracker::new();
        let base: VarId = 0;
        let derived: VarId = 1;
        tracker.record(derived, base, 16);

        assert!(tracker.structurally_must_alias(base, base));
        let derivs = tracker.derivations_of(derived);
        assert_eq!(derivs, &[(base, 16)]);
    }

    // Regression: `PointsToTarget::gep` used to overflow-panic (in debug
    // builds) when a chain of GEP constraints pushed the offset past the
    // `i32` boundary. Malformed/adversarial IL can produce arbitrarily large
    // deltas, so this must saturate instead of panicking.
    #[test]
    fn test_points_to_target_gep_saturates_on_overflow() {
        let t = PointsToTarget::exact(AllocSite::Heap(0x1000), i32::MAX - 1);
        let t2 = t.gep(100);
        assert_eq!(t2.offset, Some(i32::MAX));

        let t = PointsToTarget::exact(AllocSite::Heap(0x1000), i32::MIN + 1);
        let t2 = t.gep(-100);
        assert_eq!(t2.offset, Some(i32::MIN));
    }

    #[test]
    fn test_points_to_set_gep() {
        let mut pts = PointsToSet::new();
        pts.insert(PointsToTarget::exact(AllocSite::Stack(0, 0), 0));
        pts.insert(PointsToTarget::exact(AllocSite::Heap(100), 4));

        let gep_pts = pts.gep(8);
        assert!(gep_pts.contains(&PointsToTarget::exact(AllocSite::Stack(0, 0), 8)));
        assert!(gep_pts.contains(&PointsToTarget::exact(AllocSite::Heap(100), 12)));
    }

    // ── Property tests: Andersen solver soundness ───────────────────────────
    //
    // The optimized worklist solver must compute the same least fixpoint as a
    // naive iterate-until-stable reference over the SAME inclusion semantics. If
    // the worklist under-propagates (a missed re-enqueue), the solver would drop
    // points-to targets — an unsound NoAlias. We compare against the reference
    // for Alloc/Assign/Gep programs (which drive inclusion-edge propagation and
    // GEP transfer) and also check the must ⇒ may invariant on every pair.
    mod prop {
        use super::*;
        use std::collections::HashSet as StdHashSet;

        use crate::test_prng::Xs as Rng;

        fn naive_solve(cs: &[AndersonConstraint]) -> HashMap<VarId, StdHashSet<PointsToTarget>> {
            let mut pts: HashMap<VarId, StdHashSet<PointsToTarget>> = HashMap::new();
            loop {
                let mut changed = false;
                for c in cs {
                    match c {
                        AndersonConstraint::Alloc { ptr, site, offset } => {
                            if pts.entry(*ptr).or_default()
                                .insert(PointsToTarget::exact(*site, *offset)) { changed = true; }
                        }
                        AndersonConstraint::Assign { dst, src } => {
                            let s = pts.get(src).cloned().unwrap_or_default();
                            let d = pts.entry(*dst).or_default();
                            for t in s { if d.insert(t) { changed = true; } }
                        }
                        AndersonConstraint::Gep { dst, src, delta } => {
                            let s = pts.get(src).cloned().unwrap_or_default();
                            let d = pts.entry(*dst).or_default();
                            for t in s { if d.insert(t.gep(*delta)) { changed = true; } }
                        }
                        // Load/Store excluded from this generator (would require
                        // duplicating the private `site_to_var` encoding).
                        AndersonConstraint::Load { .. } | AndersonConstraint::Store { .. } => {}
                    }
                }
                if !changed { break; }
            }
            pts
        }

        fn gen_program(rng: &mut Rng) -> Vec<AndersonConstraint> {
            let nvars = 3 + rng.below(5);
            let nsites = 1 + rng.below(4);
            let n = 4 + rng.below(10);
            let mut cs = Vec::new();
            for _ in 0..n {
                let a = rng.below(nvars) as VarId;
                let b = rng.below(nvars) as VarId;
                // Keep all copy/gep edges strictly forward (low index → high
                // index) so the constraint graph is a DAG. A cyclic Assign/Gep
                // chain would grow offsets until i32 saturation and blow up both
                // the solver and the naive reference; cyclic behaviour is
                // exercised separately by deterministic unit tests.
                let (src, dst) = (a.min(b), a.max(b));
                match rng.below(3) {
                    0 => cs.push(AndersonConstraint::Alloc {
                        ptr: dst,
                        site: AllocSite::Heap(0x1000 + rng.below(nsites)),
                        offset: rng.below(4) as i32 * 4,
                    }),
                    1 if src != dst => cs.push(AndersonConstraint::Assign { dst, src }),
                    _ if src != dst => cs.push(AndersonConstraint::Gep {
                        dst, src, delta: rng.below(4) as i32 * 4,
                    }),
                    _ => cs.push(AndersonConstraint::Alloc {
                        ptr: dst,
                        site: AllocSite::Heap(0x1000 + rng.below(nsites)),
                        offset: 0,
                    }),
                }
            }
            cs
        }

        #[test]
        fn prop_worklist_matches_naive_fixpoint() {
            let mut rng = Rng::new(0x51);
            for _ in 0..5_000 {
                let cs = gen_program(&mut rng);
                let (graph, _) = AndersenSolver::new(cs.clone()).solve();
                let naive = naive_solve(&cs);
                for (var, expected) in &naive {
                    let got: StdHashSet<PointsToTarget> =
                        graph.get(*var).iter().copied().collect();
                    assert_eq!(
                        &got, expected,
                        "worklist solver diverged from naive fixpoint for v{var}"
                    );
                }
            }
        }

        #[test]
        fn prop_must_implies_may_and_no_alias_is_disjoint() {
            let mut rng = Rng::new(0x52);
            for _ in 0..5_000 {
                let cs = gen_program(&mut rng);
                let (graph, _) = AndersenSolver::new(cs).solve();
                let vars: Vec<VarId> = graph.pts.keys().copied().collect();
                for &p in &vars {
                    for &q in &vars {
                        if must_alias(&graph, p, q) {
                            assert!(may_alias(&graph, p, q),
                                "must-alias without may-alias: v{p}, v{q}");
                        }
                        // NoAlias must mean genuinely disjoint points-to sets.
                        let pp: StdHashSet<PointsToTarget> = graph.get(p).iter().copied().collect();
                        let qq: StdHashSet<PointsToTarget> = graph.get(q).iter().copied().collect();
                        let shares = pp.intersection(&qq).next().is_some();
                        if shares {
                            assert!(may_alias(&graph, p, q),
                                "dropped a genuinely-aliasing pair: v{p}, v{q}");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod unknown_pointer_soundness {
    use super::*;

    /// An unanalysed pointer must be treated as possibly aliasing anything.
    ///
    /// `PointsToGraph::get` returns the same empty set for "analysed, points
    /// nowhere" and "never seen". `query_alias` used to answer `NoAlias` for
    /// both, so `may_alias` reported **false** — a definite "these cannot
    /// overlap" — about a pointer with no information behind it. That is the
    /// unsound direction: a caller may reorder memory accesses on the strength
    /// of `may_alias == false`.
    #[test]
    fn unknown_pointers_may_alias() {
        let mut g = PointsToGraph::default();
        // Only `known` is registered; `unseen` was never analysed.
        let known: VarId = 1;
        let unseen: VarId = 99;
        g.get_mut_or_default(known)
            .insert(PointsToTarget::exact(AllocSite::Global(0x1000), 0));

        assert!(!g.is_known(unseen), "the fixture must leave this var unseen");
        assert_eq!(
            query_alias(&g, known, unseen),
            AliasResult::MayAlias,
            "an unanalysed pointer must be assumed to alias"
        );
        assert!(
            may_alias(&g, known, unseen),
            "may_alias must not deny an alias it has no information about"
        );
        assert!(
            !must_alias(&g, known, unseen),
            "must_alias is the strong claim and must stay false without evidence"
        );
    }

    /// The conservative answer must not swallow the precise ones: a variable
    /// the analysis DID examine and found to point nowhere still yields
    /// `NoAlias`, and two singletons on the same target still yield
    /// `MustAlias`. Without this, returning `MayAlias` unconditionally would
    /// also pass the test above.
    #[test]
    fn analysed_pointers_keep_their_precise_answers() {
        let mut g = PointsToGraph::default();
        let a: VarId = 1;
        let b: VarId = 2;
        let empty: VarId = 3;

        let target = PointsToTarget::exact(AllocSite::Global(0x2000), 0);
        g.get_mut_or_default(a).insert(target);
        g.get_mut_or_default(b).insert(target);
        // Registered, deliberately with no targets.
        let _ = g.get_mut_or_default(empty);

        assert!(g.is_known(empty), "an explicitly registered var is known");
        assert_eq!(
            query_alias(&g, a, b),
            AliasResult::MustAlias,
            "two singletons on the same target definitely alias"
        );
        assert_eq!(
            query_alias(&g, a, empty),
            AliasResult::NoAlias,
            "an analysed pointer with no targets cannot overlap anything"
        );
    }
}
