//! `pointer_analysis` — Andersen-style points-to analysis for the decompiler.
//!
//! Implements a flow-insensitive, inclusion-based points-to analysis modelled
//! on Andersen's algorithm.  Each variable is assigned a [`PointsToSet`] that
//! grows monotonically as constraints are solved by the [`WorklistSolver`].
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`PointerAnalysis`] | High-level facade — run analysis, query results |
//! | [`PointsToSet`] | Set of abstract locations a pointer may reference |
//! | [`ConstraintKind`] | Address-of / Assign / Load / Store constraints |
//! | [`ConstraintGraph`] | Stores all generated constraints |
//! | [`WorklistSolver`] | Iterative worklist-based constraint solver |
//! | [`PointerType`] | Inferred pointer type for a variable |
//! | [`NullabilityAnalysis`] | Tracks variables that may or must be null |

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// AbstractLocation
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract memory location used as a points-to target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbstractLocation {
    /// A named variable (stack or global).
    Variable(String),
    /// A heap object allocated at a specific call site.
    HeapObj(String),
    /// A function parameter.
    Param(String, u32),
    /// A return value from a call site.
    RetVal(String),
    /// The NULL location (a special sentinel).
    Null,
    /// An unknown / escaped location.
    Unknown,
}

impl AbstractLocation {
    /// Returns `true` if this is the null location.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns `true` if this is an unknown/escaped location.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl fmt::Display for AbstractLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Variable(n) => write!(f, "&{n}"),
            Self::HeapObj(site) => write!(f, "heap@{site}"),
            Self::Param(func, idx) => write!(f, "param({func}[{idx}])"),
            Self::RetVal(site) => write!(f, "ret@{site}"),
            Self::Null => write!(f, "null"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToSet
// ─────────────────────────────────────────────────────────────────────────────

/// The set of abstract locations a pointer variable may point to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PointsToSet {
    /// The abstract locations this variable may reference.
    locations: HashSet<AbstractLocation>,
}

impl PointsToSet {
    /// Create an empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a set containing a single location.
    #[must_use]
    pub fn singleton(loc: AbstractLocation) -> Self {
        let mut s = Self::empty();
        s.insert(loc);
        s
    }

    /// Insert a location into the set.
    ///
    /// Returns `true` if the set changed (location was not already present).
    pub fn insert(&mut self, loc: AbstractLocation) -> bool {
        self.locations.insert(loc)
    }

    /// Insert all locations from `other` into `self`.
    ///
    /// Returns `true` if `self` changed.
    pub fn union_with(&mut self, other: &Self) -> bool {
        let before = self.locations.len();
        for loc in &other.locations {
            self.locations.insert(loc.clone());
        }
        self.locations.len() > before
    }

    /// Returns `true` if the set contains `loc`.
    #[must_use]
    pub fn contains(&self, loc: &AbstractLocation) -> bool {
        self.locations.contains(loc)
    }

    /// Returns `true` if the set contains the null location.
    #[must_use]
    pub fn may_be_null(&self) -> bool {
        self.locations.contains(&AbstractLocation::Null)
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Number of locations in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Returns all locations as a sorted vec (for deterministic output).
    #[must_use]
    pub fn to_sorted_vec(&self) -> Vec<String> {
        let mut v: Vec<String> = self.locations.iter().map(std::string::ToString::to_string).collect();
        v.sort();
        v
    }
}

impl fmt::Display for PointsToSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let items = self.to_sorted_vec();
        write!(f, "{{{}}}", items.join(", "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintKind
// ─────────────────────────────────────────────────────────────────────────────

/// The four constraint types in Andersen's analysis.
///
/// Written in set-constraint notation where `pt(x)` means "the set of
/// locations that variable `x` may point to".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstraintKind {
    /// `pt(dst) ⊇ {src}`  (address-of: `dst = &src`).
    Address {
        /// Destination pointer variable.
        dst: String,
        /// Abstract location whose address is taken.
        src: AbstractLocation,
    },
    /// `pt(dst) ⊇ pt(src)` (copy: `dst = src`).
    Assign { dst: String, src: String },
    /// `pt(dst) ⊇ ∪{pt(l) | l ∈ pt(src)}` (load: `dst = *src`).
    Load { dst: String, src: String },
    /// `∀ l ∈ pt(dst): pt(l) ⊇ pt(src)` (store: `*dst = src`).
    Store { dst: String, src: String },
}

impl ConstraintKind {
    /// Human-readable constraint string.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Address { dst, src } => format!("pt({dst}) ⊇ {{{src}}}"),
            Self::Assign { dst, src } => format!("pt({dst}) ⊇ pt({src})"),
            Self::Load { dst, src } => format!("pt({dst}) ⊇ ∪pt(pt({src}))"),
            Self::Store { dst, src } => format!("∀l∈pt({dst}): pt(l) ⊇ pt({src})"),
        }
    }
}

impl fmt::Display for ConstraintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Accumulates all pointer constraints for a function or program.
#[derive(Debug, Default, Clone)]
pub struct ConstraintGraph {
    constraints: Vec<ConstraintKind>,
}

impl ConstraintGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address-of constraint: `dst = &src`.
    pub fn address_of(&mut self, dst: impl Into<String>, src: AbstractLocation) {
        self.constraints.push(ConstraintKind::Address {
            dst: dst.into(),
            src,
        });
    }

    /// Add an assignment constraint: `dst = src`.
    pub fn assign(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.constraints.push(ConstraintKind::Assign {
            dst: dst.into(),
            src: src.into(),
        });
    }

    /// Add a load constraint: `dst = *src`.
    pub fn load(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.constraints.push(ConstraintKind::Load {
            dst: dst.into(),
            src: src.into(),
        });
    }

    /// Add a store constraint: `*dst = src`.
    pub fn store(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.constraints.push(ConstraintKind::Store {
            dst: dst.into(),
            src: src.into(),
        });
    }

    /// All constraints.
    #[must_use]
    pub fn constraints(&self) -> &[ConstraintKind] {
        &self.constraints
    }

    /// Number of constraints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Returns `true` if no constraints have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    /// All unique variable names mentioned in the constraints.
    #[must_use]
    pub fn variables(&self) -> HashSet<String> {
        let mut vars = HashSet::new();
        for c in &self.constraints {
            match c {
                ConstraintKind::Address { dst, .. } => {
                    vars.insert(dst.clone());
                }
                ConstraintKind::Assign { dst, src }
                | ConstraintKind::Load { dst, src }
                | ConstraintKind::Store { dst, src } => {
                    vars.insert(dst.clone());
                    vars.insert(src.clone());
                }
            }
        }
        vars
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorklistSolver
// ─────────────────────────────────────────────────────────────────────────────

/// Iterative worklist solver for Andersen-style pointer constraints.
///
/// Initialises the points-to sets from address-of constraints, then
/// repeatedly propagates assignments, loads, and stores until a fixed
/// point is reached.
#[derive(Debug, Default)]
pub struct WorklistSolver {
    /// Current points-to sets for all variables.
    points_to: HashMap<String, PointsToSet>,
    /// Number of solver iterations performed.
    iterations: u32,
}

impl WorklistSolver {
    /// Create an empty solver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Solve all constraints in `graph` and populate the internal points-to map.
    pub fn solve(&mut self, graph: &ConstraintGraph) {
        // Initialise variables.
        for var in graph.variables() {
            self.points_to.entry(var).or_default();
        }

        // Phase 1: process address-of constraints.
        for c in graph.constraints() {
            if let ConstraintKind::Address { dst, src } = c {
                self.points_to
                    .entry(dst.clone())
                    .or_default()
                    .insert(src.clone());
            }
        }

        // Phase 2: worklist iteration.
        let mut worklist: VecDeque<String> = self.points_to.keys().cloned().collect();
        let mut changed = true;

        while changed {
            changed = false;
            self.iterations += 1;

            let vars: Vec<String> = std::mem::take(&mut worklist).into_iter().collect();
            for var in &vars {
                for c in graph.constraints() {
                    match c {
                        ConstraintKind::Assign { dst, src } => {
                            if src == var {
                                let src_pts = self.points_to.get(src).cloned().unwrap_or_default();
                                let dst_pts = self.points_to.entry(dst.clone()).or_default();
                                if dst_pts.union_with(&src_pts) {
                                    changed = true;
                                    worklist.push_back(dst.clone());
                                }
                            }
                        }
                        ConstraintKind::Load { dst, src } => {
                            let src_pts = self.points_to.get(src).cloned().unwrap_or_default();
                            let triggers = src == var
                                || src_pts.locations.iter().any(|loc| {
                                    matches!(loc, AbstractLocation::Variable(lname) if lname == var)
                                });
                            if triggers {
                                // dst gets the union of pt(l) for all l in pt(src).
                                let mut union = PointsToSet::empty();
                                for loc in &src_pts.locations {
                                    if let AbstractLocation::Variable(lname) = loc
                                        && let Some(lpts) = self.points_to.get(lname) {
                                            union.union_with(lpts);
                                        }
                                }
                                let dst_pts = self.points_to.entry(dst.clone()).or_default();
                                if dst_pts.union_with(&union) {
                                    changed = true;
                                    worklist.push_back(dst.clone());
                                }
                            }
                        }
                        ConstraintKind::Store { dst, src } => {
                            if src == var || dst == var {
                                let src_pts = self.points_to.get(src).cloned().unwrap_or_default();
                                let dst_pts = self.points_to.get(dst).cloned().unwrap_or_default();
                                // For each location l in pt(dst), add pt(src) to pt(l).
                                let mut updated_locs = Vec::new();
                                for loc in &dst_pts.locations {
                                    if let AbstractLocation::Variable(lname) = loc {
                                        updated_locs.push(lname.clone());
                                    }
                                }
                                for lname in updated_locs {
                                    let lpts = self.points_to.entry(lname.clone()).or_default();
                                    if lpts.union_with(&src_pts) {
                                        changed = true;
                                        worklist.push_back(lname);
                                    }
                                }
                            }
                        }
                        ConstraintKind::Address { .. } => {} // already handled
                    }
                }
            }
        }
    }

    /// Return the points-to set for `var`, or empty if not known.
    #[must_use]
    pub fn points_to(&self, var: &str) -> &PointsToSet {
        // `HashSet::new` is not const so we cannot build a `static EMPTY` —
        // use a `OnceLock` to lazily initialise it the first time we need one.
        use std::sync::OnceLock;
        static EMPTY: OnceLock<PointsToSet> = OnceLock::new();
        let empty = EMPTY.get_or_init(|| PointsToSet {
            locations: HashSet::new(),
        });
        self.points_to.get(var).unwrap_or(empty)
    }

    /// Number of iterations needed to reach a fixed point.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// All computed points-to sets.
    #[must_use]
    pub const fn all_sets(&self) -> &HashMap<String, PointsToSet> {
        &self.points_to
    }

    /// Whether variable `a` may alias variable `b` (their sets intersect).
    #[must_use]
    pub fn may_alias(&self, a: &str, b: &str) -> bool {
        let pa = self.points_to(a);
        let pb = self.points_to(b);
        // May-alias if their points-to sets are non-empty and share at least one location.
        if pa.is_empty() || pb.is_empty() {
            return false;
        }
        pa.locations.iter().any(|l| pb.locations.contains(l))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerType
// ─────────────────────────────────────────────────────────────────────────────

/// An inferred pointer type for a decompiler variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointerType {
    /// A stack-allocated variable pointer.
    StackPointer { var_name: String },
    /// A heap-allocated object pointer.
    HeapPointer { alloc_site: String },
    /// A function pointer.
    FunctionPointer,
    /// A definitely null pointer.
    Null,
    /// May be null (nullable pointer).
    Nullable,
    /// Definitely non-null.
    NonNull,
    /// Unknown pointer type.
    Unknown,
}

impl PointerType {
    /// Returns `true` if the pointer may be null.
    #[must_use]
    pub const fn may_be_null(&self) -> bool {
        matches!(self, Self::Null | Self::Nullable)
    }

    /// A short string label for the type.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::StackPointer { .. } => "stack_ptr",
            Self::HeapPointer { .. } => "heap_ptr",
            Self::FunctionPointer => "fn_ptr",
            Self::Null => "null",
            Self::Nullable => "nullable",
            Self::NonNull => "non_null",
            Self::Unknown => "unknown_ptr",
        }
    }
}

impl fmt::Display for PointerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackPointer { var_name } => write!(f, "stack_ptr({var_name})"),
            Self::HeapPointer { alloc_site } => write!(f, "heap_ptr@{alloc_site}"),
            other => write!(f, "{}", other.label()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NullabilityAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks nullability information for pointer variables.
#[derive(Debug, Default, Clone)]
pub struct NullabilityAnalysis {
    /// Variables that definitely cannot be null.
    non_null: HashSet<String>,
    /// Variables that may be null.
    nullable: HashSet<String>,
    /// Variables that are definitely null at the point of analysis.
    definitely_null: HashSet<String>,
}

impl NullabilityAnalysis {
    /// Create an empty analysis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `var` as definitely non-null.
    pub fn set_non_null(&mut self, var: impl Into<String>) {
        let var = var.into();
        self.nullable.remove(&var);
        self.definitely_null.remove(&var);
        self.non_null.insert(var);
    }

    /// Mark `var` as possibly null (nullable).
    pub fn set_nullable(&mut self, var: impl Into<String>) {
        let var = var.into();
        self.non_null.remove(&var);
        self.nullable.insert(var);
    }

    /// Mark `var` as definitely null.
    pub fn set_null(&mut self, var: impl Into<String>) {
        let var = var.into();
        self.non_null.remove(&var);
        self.nullable.remove(&var);
        self.definitely_null.insert(var);
    }

    /// Determine nullability from the points-to set.
    pub fn infer_from_pts(&mut self, var: &str, pts: &PointsToSet) {
        if pts.is_empty() {
            // No location known — be conservative.
            self.set_nullable(var);
            return;
        }
        let only_null = pts.locations.iter().all(AbstractLocation::is_null);
        let has_null = pts.may_be_null();
        let has_non_null = pts.locations.iter().any(|l| !l.is_null());

        if only_null {
            self.set_null(var);
        } else if has_null && has_non_null {
            self.set_nullable(var);
        } else if !has_null {
            self.set_non_null(var);
        } else {
            self.set_nullable(var);
        }
    }

    /// Check whether `var` may be null.
    #[must_use]
    pub fn may_be_null(&self, var: &str) -> bool {
        self.nullable.contains(var) || self.definitely_null.contains(var)
    }

    /// Check whether `var` is definitely non-null.
    #[must_use]
    pub fn is_non_null(&self, var: &str) -> bool {
        self.non_null.contains(var)
    }

    /// Check whether `var` is definitely null.
    #[must_use]
    pub fn is_null(&self, var: &str) -> bool {
        self.definitely_null.contains(var)
    }

    /// Infer nullability for every variable in the solver's points-to map.
    pub fn infer_all(&mut self, solver: &WorklistSolver) {
        for (var, pts) in solver.all_sets() {
            self.infer_from_pts(var, pts);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// High-level façade for running Andersen-style pointer analysis and
/// querying its results.
///
/// # Usage
///
/// ```ignore
/// let mut pa = PointerAnalysis::new();
/// pa.add_address_of("p", AbstractLocation::Variable("x".into()));
/// pa.add_assign("q", "p");
/// pa.solve();
/// let pts = pa.points_to("q");
/// ```
#[derive(Debug, Default)]
pub struct PointerAnalysis {
    graph: ConstraintGraph,
    solver: WorklistSolver,
    nullability: NullabilityAnalysis,
    solved: bool,
}

impl PointerAnalysis {
    /// Create an empty analysis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address-of constraint: `dst = &location`.
    pub fn add_address_of(&mut self, dst: impl Into<String>, location: AbstractLocation) {
        self.graph.address_of(dst, location);
        self.solved = false;
    }

    /// Add an assignment constraint: `dst = src`.
    pub fn add_assign(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.graph.assign(dst, src);
        self.solved = false;
    }

    /// Add a load constraint: `dst = *src`.
    pub fn add_load(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.graph.load(dst, src);
        self.solved = false;
    }

    /// Add a store constraint: `*dst = src`.
    pub fn add_store(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.graph.store(dst, src);
        self.solved = false;
    }

    /// Solve the constraint graph (runs [`WorklistSolver`]).
    pub fn solve(&mut self) {
        self.solver.solve(&self.graph);
        self.nullability.infer_all(&self.solver);
        self.solved = true;
    }

    /// Return the points-to set for `var`.
    ///
    /// If [`solve`] has not been called yet, this returns an empty set.
    #[must_use]
    pub fn points_to(&self, var: &str) -> &PointsToSet {
        self.solver.points_to(var)
    }

    /// Whether two variables may alias.
    #[must_use]
    pub fn may_alias(&self, a: &str, b: &str) -> bool {
        self.solver.may_alias(a, b)
    }

    /// Whether `var` may be null.
    #[must_use]
    pub fn may_be_null(&self, var: &str) -> bool {
        if !self.solved {
            return true; // conservative
        }
        self.nullability.may_be_null(var)
    }

    /// Whether `var` is definitely non-null.
    #[must_use]
    pub fn is_non_null(&self, var: &str) -> bool {
        if !self.solved {
            return false;
        }
        self.nullability.is_non_null(var)
    }

    /// Infer a [`PointerType`] for `var`.
    #[must_use]
    pub fn infer_pointer_type(&self, var: &str) -> PointerType {
        if !self.solved {
            return PointerType::Unknown;
        }
        let pts = self.points_to(var);
        if pts.is_empty() {
            return PointerType::Unknown;
        }

        // Check for heap pointer.
        let heap_sites: Vec<String> = pts
            .locations
            .iter()
            .filter_map(|l| {
                if let AbstractLocation::HeapObj(site) = l {
                    Some(site.clone())
                } else {
                    None
                }
            })
            .collect();
        if !heap_sites.is_empty() && !pts.may_be_null() {
            return PointerType::HeapPointer {
                alloc_site: heap_sites[0].clone(),
            };
        }

        // Check for stack pointer.
        let stack_vars: Vec<String> = pts
            .locations
            .iter()
            .filter_map(|l| {
                if let AbstractLocation::Variable(n) = l {
                    Some(n.clone())
                } else {
                    None
                }
            })
            .collect();
        if !stack_vars.is_empty() && !pts.may_be_null() {
            return PointerType::StackPointer {
                var_name: stack_vars[0].clone(),
            };
        }

        if pts.len() == 1 && pts.may_be_null() {
            return PointerType::Null;
        }
        if pts.may_be_null() {
            return PointerType::Nullable;
        }
        PointerType::NonNull
    }

    /// Number of constraints.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.graph.len()
    }

    /// Number of solver iterations.
    #[must_use]
    pub const fn solver_iterations(&self) -> u32 {
        self.solver.iterations()
    }

    /// All variables in the analysis.
    #[must_use]
    pub fn variables(&self) -> HashSet<String> {
        self.graph.variables()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AbstractLocation ──────────────────────────────────────────────────────

    #[test]
    fn test_abs_loc_display() {
        assert_eq!(AbstractLocation::Variable("x".into()).to_string(), "&x");
        assert_eq!(
            AbstractLocation::HeapObj("malloc_1".into()).to_string(),
            "heap@malloc_1"
        );
        assert_eq!(AbstractLocation::Null.to_string(), "null");
        assert_eq!(AbstractLocation::Unknown.to_string(), "?");
    }

    #[test]
    fn test_abs_loc_is_null() {
        assert!(AbstractLocation::Null.is_null());
        assert!(!AbstractLocation::Variable("x".into()).is_null());
    }

    // ── PointsToSet ───────────────────────────────────────────────────────────

    #[test]
    fn test_pts_empty() {
        let pts = PointsToSet::empty();
        assert!(pts.is_empty());
        assert_eq!(pts.len(), 0);
        assert!(!pts.may_be_null());
    }

    #[test]
    fn test_pts_singleton() {
        let pts = PointsToSet::singleton(AbstractLocation::Variable("y".into()));
        assert_eq!(pts.len(), 1);
        assert!(pts.contains(&AbstractLocation::Variable("y".into())));
    }

    #[test]
    fn test_pts_insert_dedup() {
        let mut pts = PointsToSet::empty();
        assert!(pts.insert(AbstractLocation::Variable("x".into())));
        assert!(!pts.insert(AbstractLocation::Variable("x".into()))); // already present
        assert_eq!(pts.len(), 1);
    }

    #[test]
    fn test_pts_union_with() {
        let mut a = PointsToSet::singleton(AbstractLocation::Variable("x".into()));
        let b = PointsToSet::singleton(AbstractLocation::Variable("y".into()));
        assert!(a.union_with(&b));
        assert_eq!(a.len(), 2);
        assert!(!a.union_with(&b)); // no change
    }

    #[test]
    fn test_pts_may_be_null() {
        let mut pts = PointsToSet::empty();
        assert!(!pts.may_be_null());
        pts.insert(AbstractLocation::Null);
        assert!(pts.may_be_null());
    }

    #[test]
    fn test_pts_display() {
        let pts = PointsToSet::singleton(AbstractLocation::Null);
        assert!(pts.to_string().contains("null"));
    }

    // ── ConstraintKind ────────────────────────────────────────────────────────

    #[test]
    fn test_constraint_address_display() {
        let c = ConstraintKind::Address {
            dst: "p".into(),
            src: AbstractLocation::Variable("x".into()),
        };
        let s = c.display();
        assert!(s.contains("pt(p)"));
        assert!(s.contains("&x"));
    }

    #[test]
    fn test_constraint_assign_display() {
        let c = ConstraintKind::Assign {
            dst: "q".into(),
            src: "p".into(),
        };
        assert!(c.display().contains("pt(q)"));
        assert!(c.display().contains("pt(p)"));
    }

    #[test]
    fn test_constraint_load_display() {
        let c = ConstraintKind::Load {
            dst: "a".into(),
            src: "b".into(),
        };
        let s = c.display();
        assert!(s.contains("pt(a)"));
        assert!(s.contains("pt(b)"));
    }

    #[test]
    fn test_constraint_store_display() {
        let c = ConstraintKind::Store {
            dst: "p".into(),
            src: "q".into(),
        };
        assert!(c.display().contains("pt(p)"));
    }

    // ── ConstraintGraph ───────────────────────────────────────────────────────

    #[test]
    fn test_graph_empty() {
        let g = ConstraintGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.len(), 0);
    }

    #[test]
    fn test_graph_add_constraints() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        g.assign("q", "p");
        g.load("r", "q");
        g.store("p", "r");
        assert_eq!(g.len(), 4);
    }

    #[test]
    fn test_graph_variables() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        g.assign("q", "p");
        let vars = g.variables();
        assert!(vars.contains("p"));
        assert!(vars.contains("q"));
    }

    // ── WorklistSolver ────────────────────────────────────────────────────────

    #[test]
    fn test_solver_simple_address_of() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        let mut solver = WorklistSolver::new();
        solver.solve(&g);
        let pts = solver.points_to("p");
        assert!(pts.contains(&AbstractLocation::Variable("x".into())));
    }

    #[test]
    fn test_solver_assign_propagates() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        g.assign("q", "p");
        let mut solver = WorklistSolver::new();
        solver.solve(&g);
        let pts = solver.points_to("q");
        assert!(pts.contains(&AbstractLocation::Variable("x".into())));
    }

    #[test]
    fn test_solver_load_propagates() {
        // p = &x; q = *p  =>  q should point to whatever p points to
        // Actually load: q gets union of pt(l) for l in pt(p).
        // pt(p) = {&x}, so for l = &x we need pt(x). pt(x) = {} initially.
        // So q's set stays empty unless x itself points to something.
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        g.address_of("x", AbstractLocation::Variable("y".into()));
        g.load("q", "p");
        let mut solver = WorklistSolver::new();
        solver.solve(&g);
        // q = *p, p -> {&x}, x -> {&y}, so q -> {&y}
        let pts = solver.points_to("q");
        assert!(pts.contains(&AbstractLocation::Variable("y".into())));
    }

    #[test]
    fn test_solver_may_alias_true() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        g.assign("q", "p");
        let mut solver = WorklistSolver::new();
        solver.solve(&g);
        assert!(solver.may_alias("p", "q")); // both point to x
    }

    #[test]
    fn test_solver_may_alias_false() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        g.address_of("q", AbstractLocation::Variable("y".into()));
        let mut solver = WorklistSolver::new();
        solver.solve(&g);
        assert!(!solver.may_alias("p", "q")); // distinct sets
    }

    #[test]
    fn test_solver_iterations_positive_after_solve() {
        let mut g = ConstraintGraph::new();
        g.address_of("p", AbstractLocation::Variable("x".into()));
        let mut solver = WorklistSolver::new();
        solver.solve(&g);
        assert!(solver.iterations() > 0);
    }

    // ── PointerType ───────────────────────────────────────────────────────────

    #[test]
    fn test_pointer_type_may_be_null() {
        assert!(PointerType::Null.may_be_null());
        assert!(PointerType::Nullable.may_be_null());
        assert!(!PointerType::NonNull.may_be_null());
    }

    #[test]
    fn test_pointer_type_display() {
        assert!(
            PointerType::StackPointer {
                var_name: "x".into()
            }
            .to_string()
            .contains('x')
        );
        assert!(
            PointerType::HeapPointer {
                alloc_site: "site1".into()
            }
            .to_string()
            .contains("site1")
        );
    }

    // ── NullabilityAnalysis ───────────────────────────────────────────────────

    #[test]
    fn test_nullability_set_non_null() {
        let mut na = NullabilityAnalysis::new();
        na.set_non_null("p");
        assert!(na.is_non_null("p"));
        assert!(!na.may_be_null("p"));
    }

    #[test]
    fn test_nullability_set_nullable() {
        let mut na = NullabilityAnalysis::new();
        na.set_nullable("p");
        assert!(na.may_be_null("p"));
        assert!(!na.is_non_null("p"));
    }

    #[test]
    fn test_nullability_set_null() {
        let mut na = NullabilityAnalysis::new();
        na.set_null("p");
        assert!(na.is_null("p"));
        assert!(na.may_be_null("p"));
    }

    #[test]
    fn test_nullability_infer_from_pts_non_null() {
        let mut na = NullabilityAnalysis::new();
        let pts = PointsToSet::singleton(AbstractLocation::Variable("x".into()));
        na.infer_from_pts("p", &pts);
        assert!(na.is_non_null("p"));
    }

    #[test]
    fn test_nullability_infer_from_pts_nullable() {
        let mut na = NullabilityAnalysis::new();
        let mut pts = PointsToSet::singleton(AbstractLocation::Variable("x".into()));
        pts.insert(AbstractLocation::Null);
        na.infer_from_pts("p", &pts);
        assert!(na.may_be_null("p"));
    }

    #[test]
    fn test_nullability_infer_from_pts_definitely_null() {
        let mut na = NullabilityAnalysis::new();
        let pts = PointsToSet::singleton(AbstractLocation::Null);
        na.infer_from_pts("p", &pts);
        assert!(na.is_null("p"));
    }

    // ── PointerAnalysis ───────────────────────────────────────────────────────

    #[test]
    fn test_pointer_analysis_basic() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::Variable("x".into()));
        pa.solve();
        let pts = pa.points_to("p");
        assert!(!pts.is_empty());
        assert!(pts.contains(&AbstractLocation::Variable("x".into())));
    }

    #[test]
    fn test_pointer_analysis_assign_chain() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::Variable("x".into()));
        pa.add_assign("q", "p");
        pa.add_assign("r", "q");
        pa.solve();
        assert!(pa.may_alias("p", "r"));
    }

    #[test]
    fn test_pointer_analysis_non_null_after_address_of() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::Variable("x".into()));
        pa.solve();
        assert!(pa.is_non_null("p"));
        assert!(!pa.may_be_null("p"));
    }

    #[test]
    fn test_pointer_analysis_infer_stack_pointer() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::Variable("x".into()));
        pa.solve();
        let pt = pa.infer_pointer_type("p");
        assert!(matches!(pt, PointerType::StackPointer { .. }));
    }

    #[test]
    fn test_pointer_analysis_infer_heap_pointer() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::HeapObj("malloc_1".into()));
        pa.solve();
        let pt = pa.infer_pointer_type("p");
        assert!(matches!(pt, PointerType::HeapPointer { .. }));
    }

    #[test]
    fn test_pointer_analysis_constraint_count() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::Variable("x".into()));
        pa.add_assign("q", "p");
        assert_eq!(pa.constraint_count(), 2);
    }

    #[test]
    fn test_pointer_analysis_unsolved_unknown() {
        let mut pa = PointerAnalysis::new();
        pa.add_address_of("p", AbstractLocation::Variable("x".into()));
        // Do NOT call solve()
        assert_eq!(pa.infer_pointer_type("p"), PointerType::Unknown);
        assert!(pa.may_be_null("p")); // conservative
    }
}
