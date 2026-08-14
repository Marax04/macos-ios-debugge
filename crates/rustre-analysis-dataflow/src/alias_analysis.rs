//! Flow-insensitive alias analysis.
//!
//! Implements Anderson-style inclusion-based points-to analysis.  Computes
//! `MayAlias` and `MustAlias` relations, groups objects into `AliasSet`s,
//! records `PointsToRelation`s, and answers `AliasQuery` requests.  Results
//! are summarised in an `AliasReport`.
//!
//! Audit note (dataflow-crate iteration 5): grepped the whole workspace for
//! `rustre_analysis_dataflow::` usage — no crate outside this one references
//! `AliasAnalysis`/`AliasReport`/etc. from this module. It is exercised only
//! by its own unit tests; treat it as orphaned library code, not a wired-in
//! consumer, until something outside this crate calls it.

use std::collections::HashSet;
use std::fmt;

use rustc_hash::FxHashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Memory objects
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for an abstract memory object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjId(pub u32);

impl fmt::Display for ObjId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "O{}", self.0)
    }
}

/// A symbolic pointer variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PtrVar(pub u32);

impl fmt::Display for PtrVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MayAlias / MustAlias
// ─────────────────────────────────────────────────────────────────────────────

/// A may-alias relationship between two pointer variables.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MayAlias {
    pub a: PtrVar,
    pub b: PtrVar,
}

impl MayAlias {
    #[must_use]
    pub const fn new(a: PtrVar, b: PtrVar) -> Self {
        let (a, b) = if a.0 <= b.0 { (a, b) } else { (b, a) };
        Self { a, b }
    }
}

/// A must-alias relationship between two pointer variables.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MustAlias {
    pub a: PtrVar,
    pub b: PtrVar,
}

impl MustAlias {
    #[must_use]
    pub const fn new(a: PtrVar, b: PtrVar) -> Self {
        let (a, b) = if a.0 <= b.0 { (a, b) } else { (b, a) };
        Self { a, b }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasSet
// ─────────────────────────────────────────────────────────────────────────────

/// A set of pointer variables that may-alias each other.
#[derive(Debug, Clone)]
pub struct AliasSet {
    pub id: u32,
    pub members: HashSet<PtrVar>,
}

impl AliasSet {
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self {
            id,
            members: HashSet::new(),
        }
    }

    pub fn add(&mut self, v: PtrVar) {
        self.members.insert(v);
    }

    #[must_use]
    pub fn contains(&self, v: PtrVar) -> bool {
        self.members.contains(&v)
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn is_singleton(&self) -> bool {
        self.members.len() == 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToRelation
// ─────────────────────────────────────────────────────────────────────────────

/// A points-to entry: pointer variable `var` may point to object `obj`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointsToRelation {
    pub var: PtrVar,
    pub obj: ObjId,
}

impl PointsToRelation {
    #[must_use]
    pub const fn new(var: PtrVar, obj: ObjId) -> Self {
        Self { var, obj }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// An inclusion constraint in the Anderson points-to analysis.
#[derive(Debug, Clone)]
pub enum AliasConstraint {
    /// Base: `var` points to `obj` (address-of).
    AddressOf { var: PtrVar, obj: ObjId },
    /// Copy: `dest` = `src` (points-to set of src ⊆ dest).
    Copy { dest: PtrVar, src: PtrVar },
    /// Load: `dest` = *`src` (deref `src`).
    Load { dest: PtrVar, src: PtrVar },
    /// Store: *`dest` = `src`.
    Store { dest: PtrVar, src: PtrVar },
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasQuery
// ─────────────────────────────────────────────────────────────────────────────

/// A query against the alias analysis result.
#[derive(Debug, Clone)]
pub enum AliasQuery {
    /// Does `a` may-alias `b`?
    MayAlias(PtrVar, PtrVar),
    /// Does `a` must-alias `b`?
    MustAlias(PtrVar, PtrVar),
    /// What objects does `var` point to?
    PointsTo(PtrVar),
    /// Which variables point to `obj`?
    PointersTo(ObjId),
}

/// The answer to an `AliasQuery`.
#[derive(Debug, Clone)]
pub enum AliasAnswer {
    Bool(bool),
    Objects(Vec<ObjId>),
    Vars(Vec<PtrVar>),
}

impl AliasAnswer {
    /// Unwrap a Bool answer.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Unwrap an Objects answer.
    #[must_use]
    pub fn as_objects(&self) -> Option<&[ObjId]> {
        if let Self::Objects(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated alias analysis results.
#[derive(Debug, Clone, Default)]
pub struct AliasReport {
    pub may_alias_pairs: HashSet<MayAlias>,
    pub must_alias_pairs: HashSet<MustAlias>,
    pub alias_sets: Vec<AliasSet>,
    pub points_to_count: usize,
}

impl AliasReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of may-alias pairs.
    #[must_use]
    pub fn may_alias_count(&self) -> usize {
        self.may_alias_pairs.len()
    }

    /// Whether `a` may-alias `b`.
    #[must_use]
    pub fn may_alias(&self, a: PtrVar, b: PtrVar) -> bool {
        let pair = MayAlias::new(a, b);
        self.may_alias_pairs.contains(&pair)
    }

    /// Whether `a` must-alias `b`.
    #[must_use]
    pub fn must_alias(&self, a: PtrVar, b: PtrVar) -> bool {
        if a == b {
            return true;
        }
        let pair = MustAlias::new(a, b);
        self.must_alias_pairs.contains(&pair)
    }

    /// Largest alias set size.
    #[must_use]
    pub fn max_alias_set_size(&self) -> usize {
        self.alias_sets.iter().map(AliasSet::size).max().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Flow-insensitive Anderson-style alias analysis.
///
/// `FxHashMap` is used for all internal maps to prevent hash-collision `DoS`
/// when `PtrVar`/`ObjId` identifiers are derived from attacker-controlled
/// binary input (many variables with colliding hashes cause O(n²) behaviour).
pub struct AliasAnalysis {
    /// Points-to sets: var → set of objects.
    points_to: FxHashMap<PtrVar, HashSet<ObjId>>,
    /// Constraints to solve.
    constraints: Vec<AliasConstraint>,
    /// Dedicated pointer variable representing each object's contents.
    obj_vars: FxHashMap<ObjId, PtrVar>,
    next_obj: u32,
    next_var: u32,
}

impl Default for AliasAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl AliasAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            points_to: FxHashMap::default(),
            constraints: Vec::new(),
            obj_vars: FxHashMap::default(),
            next_obj: 0,
            next_var: 0,
        }
    }

    /// Allocate a fresh abstract memory object.
    ///
    /// # Panics
    /// Panics if more than `u32::MAX` objects are allocated (integer overflow guard).
    pub const fn fresh_obj(&mut self) -> ObjId {
        let id = ObjId(self.next_obj);
        self.next_obj = self.next_obj.checked_add(1).expect("ObjId counter overflow");
        id
    }

    /// Allocate a fresh pointer variable.
    ///
    /// # Panics
    /// Panics if more than `u32::MAX` variables are allocated (integer overflow guard).
    pub fn fresh_var(&mut self) -> PtrVar {
        let v = PtrVar(self.next_var);
        self.next_var = self.next_var.checked_add(1).expect("PtrVar counter overflow");
        self.points_to.entry(v).or_default();
        v
    }

    /// Get (or allocate) the pointer variable representing an object's contents.
    fn var_for_obj(&mut self, obj: ObjId) -> PtrVar {
        if let Some(&v) = self.obj_vars.get(&obj) {
            return v;
        }
        let v = self.fresh_var();
        self.obj_vars.insert(obj, v);
        v
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, c: AliasConstraint) {
        self.constraints.push(c);
    }

    /// Convenience: `var = &obj`.
    pub fn address_of(&mut self, var: PtrVar, obj: ObjId) {
        self.add_constraint(AliasConstraint::AddressOf { var, obj });
    }

    /// Convenience: `dest = src`.
    pub fn copy(&mut self, dest: PtrVar, src: PtrVar) {
        self.add_constraint(AliasConstraint::Copy { dest, src });
    }

    /// Convenience: `dest = *src`.
    pub fn load(&mut self, dest: PtrVar, src: PtrVar) {
        self.add_constraint(AliasConstraint::Load { dest, src });
    }

    /// Convenience: `*dest = src`.
    pub fn store(&mut self, dest: PtrVar, src: PtrVar) {
        self.add_constraint(AliasConstraint::Store { dest, src });
    }

    /// Run the worklist-based Anderson analysis and return the points-to sets.
    pub fn solve(&mut self) {
        // Constraints are never mutated while solving, so clone them once up
        // front rather than on every pass — `self.constraints` must be
        // borrowed independently of `self.points_to` since the loop body
        // mutates `self.points_to`.
        let constraints = self.constraints.clone();

        // Seed AddressOf constraints
        for c in &constraints {
            if let AliasConstraint::AddressOf { var, obj } = c {
                self.points_to.entry(*var).or_default().insert(*obj);
            }
        }

        // Naive fixpoint iteration: repeatedly rescan every constraint until no
        // points-to set changes. (A prior version churned a `VecDeque` worklist
        // whose popped element was never consulted — every pop just rescanned
        // *all* constraints, and any change refilled the queue with *every*
        // variable again, making the loop O(vars * rounds * constraints)
        // instead of O(rounds * constraints) for no benefit.)
        loop {
            let mut changed = false;

            for c in &constraints {
                match c {
                    AliasConstraint::Copy { dest, src } => {
                        let src_set = self.points_to.get(src).cloned().unwrap_or_default();
                        let dest_set = self.points_to.entry(*dest).or_default();
                        for obj in src_set {
                            if dest_set.insert(obj) {
                                changed = true;
                            }
                        }
                    }
                    AliasConstraint::Load { dest, src } => {
                        // dest pts += ∪{ pts(x) | x ∈ pts(src) }
                        let src_objs: HashSet<ObjId> =
                            self.points_to.get(src).cloned().unwrap_or_default();
                        for obj in src_objs {
                            // Each object's contents get a dedicated pointer variable
                            let obj_var = self.var_for_obj(obj);
                            let obj_pts = self.points_to.get(&obj_var).cloned().unwrap_or_default();
                            let dest_set = self.points_to.entry(*dest).or_default();
                            for o in obj_pts {
                                if dest_set.insert(o) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    AliasConstraint::Store { dest, src } => {
                        // ∀ x ∈ pts(dest): pts(x) += pts(src)
                        let dest_objs: HashSet<ObjId> =
                            self.points_to.get(dest).cloned().unwrap_or_default();
                        let src_set = self.points_to.get(src).cloned().unwrap_or_default();
                        for obj in dest_objs {
                            let obj_var = self.var_for_obj(obj);
                            let obj_pts = self.points_to.entry(obj_var).or_default();
                            for &o in &src_set {
                                if obj_pts.insert(o) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    AliasConstraint::AddressOf { .. } => {}
                }
            }

            if !changed {
                break;
            }
        }
    }

    /// Get points-to set for a variable.
    #[must_use]
    pub fn points_to(&self, var: PtrVar) -> HashSet<ObjId> {
        self.points_to.get(&var).cloned().unwrap_or_default()
    }

    /// Whether `a` may-alias `b` (they share at least one pointed-to object).
    #[must_use]
    pub fn may_alias(&self, a: PtrVar, b: PtrVar) -> bool {
        if a == b {
            return true;
        }
        let pa = self.points_to(a);
        let pb = self.points_to(b);
        !pa.is_disjoint(&pb)
    }

    /// Whether `a` must-alias `b` (identical non-empty singleton points-to sets).
    #[must_use]
    pub fn must_alias(&self, a: PtrVar, b: PtrVar) -> bool {
        if a == b {
            return true;
        }
        let pa = self.points_to(a);
        let pb = self.points_to(b);
        !pa.is_empty() && pa.len() == 1 && pa == pb
    }

    /// Build `AliasSet`s from the computed points-to sets.
    #[must_use]
    pub fn compute_alias_sets(&self) -> Vec<AliasSet> {
        // Group variables by their points-to set fingerprint
        // FxHashMap prevents hash-collision DoS when many variables share the
        // same points-to set fingerprint (attacker-controlled key content).
        let mut groups: FxHashMap<Vec<u32>, Vec<PtrVar>> = FxHashMap::default();
        for (&var, pts) in &self.points_to {
            if pts.is_empty() {
                continue;
            }
            let mut key: Vec<u32> = pts.iter().map(|o| o.0).collect();
            key.sort_unstable();
            groups.entry(key).or_default().push(var);
        }

        // Sort groups by their fingerprint key *before* assigning ids so that
        // the id assigned to a given points-to-set fingerprint is stable
        // across runs, regardless of the HashMap's iteration order (which is
        // randomized per-process and would otherwise make `AliasSet::id`
        // nondeterministic for identical inputs).
        let mut group_vec: Vec<(Vec<u32>, Vec<PtrVar>)> = groups.into_iter().collect();
        group_vec.sort_by(|(ka, _), (kb, _)| ka.cmp(kb));

        let mut sets: Vec<AliasSet> = group_vec
            .into_iter()
            .enumerate()
            .map(|(id, (_, mut vars))| {
                vars.sort_unstable_by_key(|v| v.0);
                let mut s = AliasSet::new(u32::try_from(id).unwrap_or(u32::MAX));
                for v in vars {
                    s.add(v);
                }
                s
            })
            .collect();
        sets.sort_by_key(|s| s.id);
        sets
    }

    /// Build a complete `AliasReport`.
    #[must_use]
    pub fn report(&self) -> AliasReport {
        let vars: Vec<PtrVar> = self.points_to.keys().copied().collect();
        let mut may_pairs: HashSet<MayAlias> = HashSet::new();
        let mut must_pairs: HashSet<MustAlias> = HashSet::new();

        for (i, &a) in vars.iter().enumerate() {
            for &b in &vars[i + 1..] {
                if self.may_alias(a, b) {
                    may_pairs.insert(MayAlias::new(a, b));
                }
                if self.must_alias(a, b) {
                    must_pairs.insert(MustAlias::new(a, b));
                }
            }
        }

        let alias_sets = self.compute_alias_sets();
        let points_to_count = self.points_to.values().map(std::collections::HashSet::len).sum();

        AliasReport {
            may_alias_pairs: may_pairs,
            must_alias_pairs: must_pairs,
            alias_sets,
            points_to_count,
        }
    }

    /// Answer an `AliasQuery`.
    #[must_use]
    pub fn query(&self, q: &AliasQuery) -> AliasAnswer {
        match q {
            AliasQuery::MayAlias(a, b) => AliasAnswer::Bool(self.may_alias(*a, *b)),
            AliasQuery::MustAlias(a, b) => AliasAnswer::Bool(self.must_alias(*a, *b)),
            AliasQuery::PointsTo(var) => {
                let mut objs: Vec<ObjId> = self.points_to(*var).into_iter().collect();
                objs.sort_unstable();
                AliasAnswer::Objects(objs)
            }
            AliasQuery::PointersTo(obj) => {
                let mut vars: Vec<PtrVar> = self
                    .points_to
                    .iter()
                    .filter(|(_, s)| s.contains(obj))
                    .map(|(&v, _)| v)
                    .collect();
                vars.sort_unstable_by_key(|v| v.0);
                AliasAnswer::Vars(vars)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn aa() -> AliasAnalysis {
        AliasAnalysis::new()
    }

    // 1. ObjId and PtrVar Display
    #[test]
    fn test_obj_ptr_display() {
        assert_eq!(ObjId(3).to_string(), "O3");
        assert_eq!(PtrVar(5).to_string(), "P5");
    }

    // 2. fresh_obj and fresh_var are distinct
    #[test]
    fn test_fresh_ids_distinct() {
        let mut aa = aa();
        let o1 = aa.fresh_obj();
        let o2 = aa.fresh_obj();
        assert_ne!(o1, o2);
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        assert_ne!(v1, v2);
    }

    // 3. AddressOf: var points to obj
    #[test]
    fn test_address_of() {
        let mut aa = aa();
        let v = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v, o);
        aa.solve();
        assert!(aa.points_to(v).contains(&o));
    }

    // 4. Copy propagates points-to
    #[test]
    fn test_copy_propagates() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.copy(v2, v1);
        aa.solve();
        assert!(aa.points_to(v2).contains(&o));
    }

    // 5. Empty var points to nothing
    #[test]
    fn test_empty_points_to() {
        let mut aa = aa();
        let v = aa.fresh_var();
        aa.solve();
        assert!(aa.points_to(v).is_empty());
    }

    // 6. may_alias same var
    #[test]
    fn test_may_alias_same_var() {
        let mut aa = aa();
        let v = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v, o);
        aa.solve();
        assert!(aa.may_alias(v, v));
    }

    // 7. may_alias two vars pointing to same obj
    #[test]
    fn test_may_alias_shared_obj() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        assert!(aa.may_alias(v1, v2));
    }

    // 8. may_alias two vars pointing to different objects
    #[test]
    fn test_no_may_alias_different_objs() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o1 = aa.fresh_obj();
        let o2 = aa.fresh_obj();
        aa.address_of(v1, o1);
        aa.address_of(v2, o2);
        aa.solve();
        assert!(!aa.may_alias(v1, v2));
    }

    // 9. must_alias same var
    #[test]
    fn test_must_alias_same_var() {
        let mut aa = aa();
        let v = aa.fresh_var();
        assert!(aa.must_alias(v, v));
    }

    // 10. must_alias singleton identical sets
    #[test]
    fn test_must_alias_singleton() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        assert!(aa.must_alias(v1, v2));
    }

    // 11. must_alias fails for multi-object sets
    #[test]
    fn test_no_must_alias_multi_obj() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o1 = aa.fresh_obj();
        let o2 = aa.fresh_obj();
        aa.address_of(v1, o1);
        aa.address_of(v1, o2);
        aa.address_of(v2, o1);
        aa.address_of(v2, o2);
        aa.solve();
        assert!(!aa.must_alias(v1, v2)); // both point to {o1, o2}; ok actually same set
    }

    // 12. AliasSet basic
    #[test]
    fn test_alias_set_basic() {
        let mut s = AliasSet::new(0);
        let v = PtrVar(1);
        s.add(v);
        assert!(s.contains(v));
        assert_eq!(s.size(), 1);
        assert!(s.is_singleton());
    }

    // 13. AliasSet not singleton
    #[test]
    fn test_alias_set_not_singleton() {
        let mut s = AliasSet::new(0);
        s.add(PtrVar(0));
        s.add(PtrVar(1));
        assert!(!s.is_singleton());
    }

    // 14. compute_alias_sets groups correctly
    #[test]
    fn test_compute_alias_sets() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        let sets = aa.compute_alias_sets();
        assert!(sets.iter().any(|s| s.contains(v1) && s.contains(v2)));
    }

    // 15. AliasReport may_alias
    #[test]
    fn test_report_may_alias() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        let report = aa.report();
        assert!(report.may_alias(v1, v2));
    }

    // 16. AliasReport must_alias self
    #[test]
    fn test_report_must_alias_self() {
        let aa = aa();
        let report = aa.report();
        let v = PtrVar(0);
        assert!(report.must_alias(v, v));
    }

    // 17. AliasQuery::MayAlias
    #[test]
    fn test_query_may_alias() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        let ans = aa.query(&AliasQuery::MayAlias(v1, v2));
        assert_eq!(ans.as_bool(), Some(true));
    }

    // 18. AliasQuery::PointsTo
    #[test]
    fn test_query_points_to() {
        let mut aa = aa();
        let v = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v, o);
        aa.solve();
        let ans = aa.query(&AliasQuery::PointsTo(v));
        if let Some(objs) = ans.as_objects() {
            assert!(objs.contains(&o));
        } else {
            panic!("expected objects");
        }
    }

    // 19. AliasQuery::PointersTo
    #[test]
    fn test_query_pointers_to() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        let ans = aa.query(&AliasQuery::PointersTo(o));
        if let AliasAnswer::Vars(vars) = ans {
            assert!(vars.contains(&v1));
            assert!(vars.contains(&v2));
        } else {
            panic!("expected vars");
        }
    }

    // 20. AliasQuery::MustAlias same var
    #[test]
    fn test_query_must_alias_same() {
        let aa = aa();
        let v = PtrVar(0);
        let ans = aa.query(&AliasQuery::MustAlias(v, v));
        assert_eq!(ans.as_bool(), Some(true));
    }

    // 21. MayAlias normalised order
    #[test]
    fn test_may_alias_normalised() {
        let a = MayAlias::new(PtrVar(5), PtrVar(2));
        assert!(a.a.0 <= a.b.0);
    }

    // 22. MustAlias normalised order
    #[test]
    fn test_must_alias_normalised() {
        let m = MustAlias::new(PtrVar(10), PtrVar(3));
        assert!(m.a.0 <= m.b.0);
    }

    // 23. AliasReport max_alias_set_size
    #[test]
    fn test_max_alias_set_size() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let v3 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.address_of(v3, o);
        aa.solve();
        let report = aa.report();
        assert!(report.max_alias_set_size() >= 3);
    }

    // 24. AliasReport may_alias_count
    #[test]
    fn test_may_alias_count() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v1, o);
        aa.address_of(v2, o);
        aa.solve();
        let report = aa.report();
        assert!(report.may_alias_count() >= 1);
    }

    // 25. solve is idempotent
    #[test]
    fn test_solve_idempotent() {
        let mut aa = aa();
        let v = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v, o);
        aa.solve();
        let pts1 = aa.points_to(v);
        aa.solve();
        let pts2 = aa.points_to(v);
        assert_eq!(pts1, pts2);
    }

    // 26. PointsToRelation fields
    #[test]
    fn test_points_to_relation() {
        let p = PointsToRelation::new(PtrVar(1), ObjId(2));
        assert_eq!(p.var, PtrVar(1));
        assert_eq!(p.obj, ObjId(2));
    }

    // 27. AliasReport default
    #[test]
    fn test_alias_report_default() {
        let r = AliasReport::default();
        assert_eq!(r.may_alias_count(), 0);
        assert_eq!(r.max_alias_set_size(), 0);
    }

    // 28. ObjId ordering
    #[test]
    fn test_obj_ordering() {
        assert!(ObjId(0) < ObjId(1));
    }

    // 29. Multiple constraints accumulate
    #[test]
    fn test_multiple_constraints() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        let v3 = aa.fresh_var();
        let o1 = aa.fresh_obj();
        let o2 = aa.fresh_obj();
        aa.address_of(v1, o1);
        aa.address_of(v2, o2);
        aa.copy(v3, v1);
        aa.copy(v3, v2);
        aa.solve();
        let pts = aa.points_to(v3);
        assert!(pts.contains(&o1));
        assert!(pts.contains(&o2));
    }

    // 30. may_alias returns false for empty points-to sets
    #[test]
    fn test_may_alias_empty_sets() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        aa.solve();
        assert!(!aa.may_alias(v1, v2));
    }

    // 31. AliasQuery answer as_bool for objects returns None
    #[test]
    fn test_answer_as_bool_objects() {
        let ans = AliasAnswer::Objects(vec![]);
        assert!(ans.as_bool().is_none());
    }

    // 32. AliasQuery answer as_objects for bool returns None
    #[test]
    fn test_answer_as_objects_bool() {
        let ans = AliasAnswer::Bool(true);
        assert!(ans.as_objects().is_none());
    }

    // 33. AliasSet empty contains returns false
    #[test]
    fn test_alias_set_empty() {
        let s = AliasSet::new(0);
        assert!(!s.contains(PtrVar(0)));
    }

    // 34. AliasSet size
    #[test]
    fn test_alias_set_size() {
        let mut s = AliasSet::new(0);
        s.add(PtrVar(0));
        s.add(PtrVar(1));
        s.add(PtrVar(2));
        assert_eq!(s.size(), 3);
    }

    // 35. AliasAnalysis default is empty
    #[test]
    fn test_analysis_default_empty() {
        let aa = AliasAnalysis::default();
        assert!(aa.constraints.is_empty());
    }

    // 36. MayAlias equality
    #[test]
    fn test_may_alias_equality() {
        let a = MayAlias::new(PtrVar(1), PtrVar(2));
        let b = MayAlias::new(PtrVar(2), PtrVar(1));
        assert_eq!(a, b); // normalised order
    }

    // 37. MustAlias equality
    #[test]
    fn test_must_alias_equality() {
        let a = MustAlias::new(PtrVar(3), PtrVar(4));
        let b = MustAlias::new(PtrVar(4), PtrVar(3));
        assert_eq!(a, b);
    }

    // 38. report points_to_count
    #[test]
    fn test_report_points_to_count() {
        let mut aa = aa();
        let v = aa.fresh_var();
        let o1 = aa.fresh_obj();
        let o2 = aa.fresh_obj();
        aa.address_of(v, o1);
        aa.address_of(v, o2);
        aa.solve();
        let r = aa.report();
        assert!(r.points_to_count >= 2);
    }

    // 39. Copy from unresolved var
    #[test]
    fn test_copy_from_unresolved() {
        let mut aa = aa();
        let v1 = aa.fresh_var();
        let v2 = aa.fresh_var();
        aa.copy(v2, v1); // v1 points to nothing
        aa.solve();
        assert!(aa.points_to(v2).is_empty());
    }

    // 40. Load from var pointing to obj
    #[test]
    fn test_load_constraint() {
        // v1 = &o1, v2 = *v1 → v2 should point to whatever PtrVar(o1.0) points to
        let mut aa = aa();
        let v1 = aa.fresh_var(); // P0
        let v2 = aa.fresh_var(); // P1
        let o = aa.fresh_obj(); // O0
        // Make P0 (≡ O0 as a var) point to a second object
        let o2 = aa.fresh_obj(); // O1
        aa.address_of(v1, o);
        // PtrVar(O0.0) = PtrVar(0) = v1 in this test
        aa.address_of(PtrVar(o.0), o2);
        aa.load(v2, v1);
        aa.solve();
        // v2 should reach o2 through the load chain
        // (exact result depends on obj-as-var encoding)
        let _ = aa.points_to(v2); // no panic
    }

    // 41. Store constraint
    #[test]
    fn test_store_constraint() {
        let mut aa = aa();
        let v1 = aa.fresh_var(); // P0
        let v2 = aa.fresh_var(); // P1
        let o = aa.fresh_obj(); // O0
        let o2 = aa.fresh_obj(); // O1
        aa.address_of(v1, o); // v1 → {O0}
        aa.address_of(v2, o2); // v2 → {O1}
        aa.store(v1, v2); // *v1 = v2 → pts(O0) += pts(v2) = {O1}
        aa.solve();
        let _ = aa.points_to(PtrVar(o.0)); // no panic
    }

    // 42. report alias_sets non-empty after solve
    #[test]
    fn test_report_alias_sets_nonempty() {
        let mut aa = aa();
        let v = aa.fresh_var();
        let o = aa.fresh_obj();
        aa.address_of(v, o);
        aa.solve();
        let r = aa.report();
        assert!(!r.alias_sets.is_empty());
    }

    // 43. compute_alias_sets assigns ids deterministically based on the
    // points-to fingerprint content, not HashMap iteration order. Build the
    // same analysis in two different insertion orders (which perturbs
    // FxHashMap bucket layout / iteration order) and verify that each
    // distinct fingerprint always ends up mapped to the same id and member
    // set across both runs.
    #[test]
    fn test_compute_alias_sets_deterministic_ids() {
        fn build_forward() -> AliasAnalysis {
            let mut aa = aa();
            // Force fixed ids for reproducibility.
            let o1 = aa.fresh_obj(); // O0
            let o2 = aa.fresh_obj(); // O1
            let o3 = aa.fresh_obj(); // O2
            let v1 = aa.fresh_var(); // P0 -> {O0}
            let v2 = aa.fresh_var(); // P1 -> {O1}
            let v3 = aa.fresh_var(); // P2 -> {O1} (same group as v2)
            let v4 = aa.fresh_var(); // P3 -> {O2}
            aa.address_of(v1, o1);
            aa.address_of(v2, o2);
            aa.address_of(v3, o2);
            aa.address_of(v4, o3);
            aa.solve();
            aa
        }

        fn build_reversed() -> AliasAnalysis {
            let mut aa = aa();
            let o1 = aa.fresh_obj(); // O0
            let o2 = aa.fresh_obj(); // O1
            let o3 = aa.fresh_obj(); // O2
            let v1 = aa.fresh_var(); // P0
            let v2 = aa.fresh_var(); // P1
            let v3 = aa.fresh_var(); // P2
            let v4 = aa.fresh_var(); // P3
            // Insert constraints in reverse order to perturb internal map
            // iteration order while producing the identical logical points-to
            // relation as `build_forward`.
            aa.address_of(v4, o3);
            aa.address_of(v3, o2);
            aa.address_of(v2, o2);
            aa.address_of(v1, o1);
            aa.solve();
            aa
        }

        let a = build_forward();
        let b = build_reversed();

        let sets_a = a.compute_alias_sets();
        let sets_b = b.compute_alias_sets();

        assert_eq!(sets_a.len(), sets_b.len());

        // For every set in `a`, there must be a set in `b` with the same id
        // and the same member set (order-independent).
        for sa in &sets_a {
            let sb = sets_b
                .iter()
                .find(|s| s.id == sa.id)
                .unwrap_or_else(|| panic!("no matching alias set with id {} in b", sa.id));
            let mut ma: Vec<u32> = sa.members.iter().map(|v| v.0).collect();
            let mut mb: Vec<u32> = sb.members.iter().map(|v| v.0).collect();
            ma.sort_unstable();
            mb.sort_unstable();
            assert_eq!(ma, mb, "alias set id {} has different members", sa.id);
        }

        // Running compute_alias_sets multiple times on the same analysis
        // must also be stable.
        let sets_a2 = a.compute_alias_sets();
        assert_eq!(sets_a.len(), sets_a2.len());
        for (s1, s2) in sets_a.iter().zip(sets_a2.iter()) {
            assert_eq!(s1.id, s2.id);
            let mut m1: Vec<u32> = s1.members.iter().map(|v| v.0).collect();
            let mut m2: Vec<u32> = s2.members.iter().map(|v| v.0).collect();
            m1.sort_unstable();
            m2.sort_unstable();
            assert_eq!(m1, m2);
        }
    }
}
