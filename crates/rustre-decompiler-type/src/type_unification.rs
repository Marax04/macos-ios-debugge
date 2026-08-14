//! Type unification algorithm.
//!
//! Implements a union-find based constraint solver for decompiler type
//! inference.  The solver:
//! 1. Collects equality, subtype, and structural constraints.
//! 2. Unifies equivalent type variables using union-find with path compression.
//! 3. Resolves the final type assignment, applying widening on integer conflicts
//!    and `Unknown` on irreconcilable conflicts.
//! 4. Supports overload resolution for function calls by ranking candidates.

use std::collections::HashMap;

use crate::{DecompType, FunctionType, TypeError};
use rustre_decompiler_expr::IntWidth;

// ─────────────────────────────────────────────────────────────────────────────
// Type variable
// ─────────────────────────────────────────────────────────────────────────────

/// A unique identifier for a type variable in the constraint system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeVar(pub String);

impl TypeVar {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    #[must_use] 
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TypeVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraints
// ─────────────────────────────────────────────────────────────────────────────

/// A constraint in the type unification system.
#[derive(Debug, Clone)]
pub enum UnifyConstraint {
    /// Two type variables must be the same type.
    Equal(TypeVar, TypeVar),
    /// A type variable must be exactly this concrete type.
    Concrete(TypeVar, DecompType),
    /// `a` must be assignable to `b` (subtype or same).
    Subtype { sub: TypeVar, sup: TypeVar },
    /// The result of dereferencing `ptr` is `pointee`.
    Deref { ptr: TypeVar, pointee: TypeVar },
    /// The return type of calling `func_var` is `ret`.
    ReturnType { func_var: TypeVar, ret: TypeVar },
    /// The `n`-th argument of `func_var` has type `arg_ty`.
    Argument { func_var: TypeVar, index: usize, arg_ty: TypeVar },
}

// ─────────────────────────────────────────────────────────────────────────────
// Union-Find
// ─────────────────────────────────────────────────────────────────────────────

/// Union-find structure over type variable names with path compression and
/// union-by-rank.
#[derive(Debug, Default)]
pub struct UnionFind {
    parent: HashMap<String, String>,
    rank: HashMap<String, u32>,
    /// Concrete types pinned to representative nodes.
    pinned: HashMap<String, DecompType>,
    /// Pending type conflicts discovered during union (`winner_rep`, `loser_ty`, `winner_ty`).
    /// These are drained by `ConstraintSolver` to record `ConflictRecord`s.
    pub pending_conflicts: Vec<(String, DecompType, DecompType)>,
}

impl UnionFind {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn make_node(&mut self, key: &str) {
        if !self.parent.contains_key(key) {
            self.parent.insert(key.to_string(), key.to_string());
            self.rank.insert(key.to_string(), 0);
        }
    }

    /// Find the representative of `key` with path compression.
    pub fn find(&mut self, key: &str) -> String {
        self.make_node(key);
        let parent = self.parent[key].clone();
        if parent == key {
            return key.to_string();
        }
        let root = self.find(&parent);
        self.parent.insert(key.to_string(), root.clone());
        root
    }

    /// Union the sets containing `a` and `b`.  Returns `true` if a merge was
    /// performed (i.e. they were in different sets).
    pub fn union(&mut self, a: &str, b: &str) -> bool {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return false;
        }
        let rank_a = self.rank.get(&ra).copied().unwrap_or(0);
        let rank_b = self.rank.get(&rb).copied().unwrap_or(0);

        // Merge smaller rank into larger rank.
        let (winner, loser) = if rank_a >= rank_b { (&ra, &rb) } else { (&rb, &ra) };
        self.parent.insert(loser.clone(), winner.clone());

        // If a concrete type was pinned to `loser`, migrate it.
        // If the winner already has a different pinned type, record a conflict
        // so the ConstraintSolver can apply conflict_resolution.
        if let Some(loser_ty) = self.pinned.remove(loser) {
            if let Some(winner_ty) = self.pinned.get(winner) {
                if *winner_ty != loser_ty {
                    self.pending_conflicts.push((
                        winner.clone(),
                        loser_ty,
                        winner_ty.clone(),
                    ));
                }
                // Keep winner's existing type; conflict will be resolved by solver.
            } else {
                self.pinned.insert(winner.clone(), loser_ty);
            }
        }

        if rank_a == rank_b {
            *self.rank.entry(winner.clone()).or_insert(0) += 1;
        }
        true
    }

    /// Pin a concrete type to a variable's representative.
    pub fn pin_type(&mut self, var: &str, ty: DecompType) {
        let rep = self.find(var);
        self.pinned.insert(rep, ty);
    }

    /// Retrieve the pinned type for the representative of `var`.
    #[must_use]
    pub fn pinned_type(&mut self, var: &str) -> Option<DecompType> {
        let rep = self.find(var);
        self.pinned.get(&rep).cloned()
    }

    /// Return all (representative, type) pairs.
    pub fn all_pinned(&self) -> impl Iterator<Item = (&str, &DecompType)> {
        self.pinned.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of distinct components.
    #[must_use]
    pub fn component_count(&self) -> usize {
        let mut roots: std::collections::HashSet<String> = std::collections::HashSet::new();
        for key in self.parent.keys() {
            // Cannot call `find` (needs &mut) so approximate with a direct lookup.
            let root = &self.parent[key];
            roots.insert(root.clone());
        }
        roots.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraint solver
// ─────────────────────────────────────────────────────────────────────────────

/// Solves a set of `UnifyConstraint`s and returns the inferred types for all
/// type variables.
#[derive(Debug, Default)]
pub struct ConstraintSolver {
    uf: UnionFind,
    constraints: Vec<UnifyConstraint>,
    /// Conflict log (variables where two incompatible concrete types were seen).
    pub conflicts: Vec<ConflictRecord>,
}

/// A conflict record for reporting.
#[derive(Debug, Clone)]
pub struct ConflictRecord {
    pub var: String,
    pub type_a: DecompType,
    pub type_b: DecompType,
    pub resolution: DecompType,
}

impl ConstraintSolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint to the system.
    pub fn add(&mut self, c: UnifyConstraint) {
        self.constraints.push(c);
    }

    /// Add a batch of constraints.
    pub fn add_all(&mut self, cs: impl IntoIterator<Item = UnifyConstraint>) {
        for c in cs {
            self.add(c);
        }
    }

    /// Solve all constraints.  Returns the final type assignment.
    pub fn solve(&mut self) -> HashMap<String, DecompType> {
        // Phase 1: process Equal/Concrete constraints to build union-find.
        for c in self.constraints.clone() {
            self.process_constraint(&c);
        }

        // Phase 1b: drain any type conflicts discovered during union() merges.
        let union_conflicts: Vec<_> = self.uf.pending_conflicts.drain(..).collect();
        for (winner_rep, loser_ty, winner_ty) in union_conflicts {
            let resolved = self.resolve_conflict(&winner_rep, &loser_ty, &winner_ty);
            self.uf.pin_type(&winner_rep, resolved);
        }

        // Phase 1c: re-process Subtype constraints now that all Concrete constraints
        // have been applied (fixes order-dependent propagation dropping constraints).
        let subtype_cs: Vec<_> = self
            .constraints
            .iter()
            .filter(|c| matches!(c, UnifyConstraint::Subtype { .. }))
            .cloned()
            .collect();
        for c in subtype_cs {
            self.process_constraint(&c);
        }

        // Phase 2: resolve deref constraints.
        let deref_cs: Vec<_> = self
            .constraints
            .iter()
            .filter_map(|c| {
                if let UnifyConstraint::Deref { ptr, pointee } = c {
                    Some((ptr.0.clone(), pointee.0.clone()))
                } else {
                    None
                }
            })
            .collect();

        for (ptr, pointee) in deref_cs {
            if let Some(ty) = self.uf.pinned_type(&ptr)
                && let DecompType::Ptr(inner) = ty {
                    self.uf.pin_type(&pointee, *inner);
                }
        }

        // Phase 3: build output map — for every var return the pinned type of
        // its representative, or Unknown.
        let vars: Vec<String> = self.uf.parent.keys().cloned().collect();
        let mut result = HashMap::new();
        for var in vars {
            let ty = self
                .uf
                .pinned_type(&var)
                .unwrap_or(DecompType::Unknown);
            result.insert(var, ty);
        }
        result
    }

    fn process_constraint(&mut self, c: &UnifyConstraint) {
        match c {
            UnifyConstraint::Equal(a, b) => {
                self.uf.union(&a.0, &b.0);
            }
            UnifyConstraint::Concrete(var, ty) => {
                let rep = self.uf.find(&var.0);
                if let Some(existing) = self.uf.pinned_type(&var.0) {
                    if existing != *ty {
                        let resolved = self.resolve_conflict(&rep, &existing, ty);
                        self.uf.pin_type(&rep, resolved);
                    }
                } else {
                    self.uf.pin_type(&var.0, ty.clone());
                }
            }
            UnifyConstraint::Subtype { sub, sup } => {
                // Propagate concrete type from sup to sub if known.
                if let Some(ty) = self.uf.pinned_type(&sup.0) {
                    self.uf.pin_type(&sub.0, ty);
                }
            }
            _ => {}
        }
    }

    /// Resolve a conflict between two concrete types for the same variable.
    fn resolve_conflict(
        &mut self,
        var: &str,
        a: &DecompType,
        b: &DecompType,
    ) -> DecompType {
        let resolution = conflict_resolution(a, b);
        self.conflicts.push(ConflictRecord {
            var: var.to_string(),
            type_a: a.clone(),
            type_b: b.clone(),
            resolution: resolution.clone(),
        });
        resolution
    }

    /// Return the number of constraints registered.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }
}

/// Resolve a type conflict between two incompatible types.
///
/// Rules:
/// * Two integer types → widen.
/// * `Unknown` + anything → keep the concrete type.
/// * Pointer + integer of same width → keep the pointer.
/// * Irreconcilable → `Unknown`.
fn conflict_resolution(a: &DecompType, b: &DecompType) -> DecompType {
    match (a, b) {
        (DecompType::Unknown, t) | (t, DecompType::Unknown) => t.clone(),
        (DecompType::Int(wa), DecompType::Int(wb)) => {
            let bits = wa.bits().max(wb.bits());
            let signed = wa.is_signed() && wb.is_signed();
            DecompType::Int(make_int_width(bits, signed))
        }
        (DecompType::Ptr(_), DecompType::Int(w)) if w.bits() >= 64 => a.clone(),
        (DecompType::Int(w), DecompType::Ptr(_)) if w.bits() >= 64 => b.clone(),
        (DecompType::Float32, DecompType::Int(_)) | (DecompType::Int(_), DecompType::Float32) => {
            DecompType::Float32
        }
        (DecompType::Float64, DecompType::Int(_)) | (DecompType::Int(_), DecompType::Float64) => {
            DecompType::Float64
        }
        _ => DecompType::Unknown,
    }
}

const fn make_int_width(bits: u32, signed: bool) -> IntWidth {
    match (bits, signed) {
        (8, true) => IntWidth::I8,
        (8, false) => IntWidth::U8,
        (16, true) => IntWidth::I16,
        (16, false) => IntWidth::U16,
        (32, true) => IntWidth::I32,
        (32, false) => IntWidth::U32,
        (_, true) => IntWidth::I64,
        (_, false) => IntWidth::U64,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Overload resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Result of overload resolution.
#[derive(Debug, Clone)]
pub struct OverloadResolutionResult {
    /// Index of the selected overload.
    pub selected: usize,
    /// Confidence score (0–100).
    pub score: u32,
    /// Why this overload was selected.
    pub reason: String,
}

/// Selects the best-matching overload from a list of `FunctionType` candidates
/// given the inferred argument types at the call site.
///
/// Scoring:
/// * Exact type match for each argument: +10.
/// * Compatible (widening) match: +5.
/// * Unknown argument type: +1 (neutral, does not penalise).
/// * Type mismatch: 0 (candidate eliminated if too many mismatches).
#[must_use]
pub fn resolve_overload(
    candidates: &[FunctionType],
    arg_types: &[Option<DecompType>],
) -> Option<OverloadResolutionResult> {
    if candidates.is_empty() {
        return None;
    }

    let mut best_score = i32::MIN;
    let mut best_idx = 0;
    let mut best_reason = String::new();

    for (i, func) in candidates.iter().enumerate() {
        let mut score = 0i32;
        let mut reasons = Vec::new();
        let mut hard_mismatch = 0usize;

        for (j, (_, param_ty)) in func.parameters.iter().enumerate() {
            match arg_types.get(j).and_then(|t| t.as_ref()) {
                None => {
                    // Unknown: neutral.
                    score += 1;
                }
                Some(arg_ty) => {
                    if arg_ty == param_ty {
                        score += 10;
                        reasons.push(format!("arg{j}: exact"));
                    } else if is_compatible(arg_ty, param_ty) {
                        score += 5;
                        reasons.push(format!("arg{j}: compatible"));
                    } else {
                        hard_mismatch += 1;
                        score -= 5;
                    }
                }
            }
        }

        // Arity penalty: too many arguments.
        if arg_types.len() > func.parameters.len() && !func.is_variadic {
            score -= 20;
        }

        if score > best_score && hard_mismatch < 3 {
            best_score = score;
            best_idx = i;
            best_reason = reasons.join(", ");
        }
    }

    let confidence = (best_score.max(0).cast_unsigned() * 5).min(100);
    Some(OverloadResolutionResult {
        selected: best_idx,
        score: confidence,
        reason: best_reason,
    })
}

/// Check whether `arg_ty` is compatible with `param_ty` for function argument
/// passing (includes widening conversions).
fn is_compatible(arg: &DecompType, param: &DecompType) -> bool {
    if arg == param {
        return true;
    }
    match (arg, param) {
        (DecompType::Int(a), DecompType::Int(b)) => a.bits() <= b.bits(),
        (DecompType::Unknown, _) | (_, DecompType::Unknown) |
(DecompType::Ptr(_) | DecompType::CStr, DecompType::Ptr(_)) |
(DecompType::Ptr(_), DecompType::CStr) |
(DecompType::Float32, DecompType::Float64) => true,
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level unification API
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience: unify two `DecompType` values and return the result.
///
/// # Errors
/// Returns `TypeError::Mismatch` when the types are irreconcilable and both
/// are concrete (non-Unknown) and non-integer.
pub fn unify_types(a: &DecompType, b: &DecompType) -> Result<DecompType, TypeError> {
    if a == b {
        return Ok(a.clone());
    }
    let resolved = conflict_resolution(a, b);
    if resolved == DecompType::Unknown && *a != DecompType::Unknown && *b != DecompType::Unknown {
        Err(TypeError::Mismatch {
            expected: a.c_name(),
            got: b.c_name(),
        })
    } else {
        Ok(resolved)
    }
}

/// Unify a list of types (join / meet).  All types must be mutually
/// compatible.
///
/// Returns the widest common type, or `Unknown` when the types diverge
/// irreconcilably.
#[must_use]
pub fn unify_all(types: &[DecompType]) -> DecompType {
    types
        .iter()
        .fold(DecompType::Unknown, |acc, t| conflict_resolution(&acc, t))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CallingConvention;

    fn i32() -> DecompType { DecompType::Int(IntWidth::I32) }
    fn i64() -> DecompType { DecompType::Int(IntWidth::I64) }
    fn u32() -> DecompType { DecompType::Int(IntWidth::U32) }
    fn ptr() -> DecompType { DecompType::Ptr(Box::new(DecompType::Void)) }

    // ── UnionFind ─────────────────────────────────────────────────────────────

    #[test]
    fn test_union_find_basic() {
        let mut uf = UnionFind::new();
        uf.union("x", "y");
        assert_eq!(uf.find("x"), uf.find("y"));
    }

    #[test]
    fn test_union_find_pin_type() {
        let mut uf = UnionFind::new();
        uf.pin_type("a", i32());
        assert_eq!(uf.pinned_type("a"), Some(i32()));
    }

    #[test]
    fn test_union_find_pin_migrates_on_union() {
        let mut uf = UnionFind::new();
        uf.pin_type("a", i32());
        uf.union("a", "b");
        // After union, `b` should resolve to the same concrete type as `a`.
        let rep_b = uf.find("b");
        let rep_a = uf.find("a");
        assert_eq!(rep_a, rep_b);
    }

    #[test]
    fn test_union_find_path_compression() {
        let mut uf = UnionFind::new();
        uf.union("a", "b");
        uf.union("b", "c");
        uf.union("c", "d");
        let root_a = uf.find("a");
        let root_d = uf.find("d");
        assert_eq!(root_a, root_d);
    }

    // ── ConstraintSolver ──────────────────────────────────────────────────────

    #[test]
    fn test_solver_equal_propagates() {
        let mut solver = ConstraintSolver::new();
        solver.add(UnifyConstraint::Concrete(TypeVar::new("x"), i32()));
        solver.add(UnifyConstraint::Equal(TypeVar::new("x"), TypeVar::new("y")));
        let result = solver.solve();
        assert_eq!(result.get("x"), result.get("y"));
    }

    #[test]
    fn test_solver_concrete_pinned() {
        let mut solver = ConstraintSolver::new();
        solver.add(UnifyConstraint::Concrete(TypeVar::new("z"), ptr()));
        let result = solver.solve();
        assert_eq!(result.get("z"), Some(&ptr()));
    }

    #[test]
    fn test_solver_conflict_widens() {
        let mut solver = ConstraintSolver::new();
        solver.add(UnifyConstraint::Concrete(TypeVar::new("v"), i32()));
        solver.add(UnifyConstraint::Concrete(TypeVar::new("v"), i64()));
        let result = solver.solve();
        // Should widen to i64.
        assert_eq!(result.get("v"), Some(&i64()));
        assert_eq!(solver.conflicts.len(), 1);
    }

    #[test]
    fn test_solver_deref_propagation() {
        let mut solver = ConstraintSolver::new();
        solver.add(UnifyConstraint::Concrete(
            TypeVar::new("p"),
            DecompType::Ptr(Box::new(i32())),
        ));
        solver.add(UnifyConstraint::Deref {
            ptr: TypeVar::new("p"),
            pointee: TypeVar::new("deref_p"),
        });
        let result = solver.solve();
        assert_eq!(result.get("deref_p"), Some(&i32()));
    }

    // ── conflict_resolution ───────────────────────────────────────────────────

    #[test]
    fn test_conflict_unknown_prefers_concrete() {
        let r = conflict_resolution(&DecompType::Unknown, &i32());
        assert_eq!(r, i32());
    }

    #[test]
    fn test_conflict_int_int_widens() {
        let r = conflict_resolution(&DecompType::Int(IntWidth::I16), &i32());
        assert_eq!(r, i32());
    }

    #[test]
    fn test_conflict_ptr_i64() {
        let r = conflict_resolution(&ptr(), &i64());
        assert!(matches!(r, DecompType::Ptr(_)));
    }

    // ── unify_types ───────────────────────────────────────────────────────────

    #[test]
    fn test_unify_same() {
        assert_eq!(unify_types(&i32(), &i32()).unwrap(), i32());
    }

    #[test]
    fn test_unify_unknown() {
        assert_eq!(unify_types(&DecompType::Unknown, &i32()).unwrap(), i32());
    }

    #[test]
    fn test_unify_mismatch_error() {
        let result = unify_types(&ptr(), &DecompType::Float32);
        assert!(result.is_err());
    }

    // ── unify_all ─────────────────────────────────────────────────────────────

    #[test]
    fn test_unify_all_same() {
        let r = unify_all(&[i32(), i32(), i32()]);
        assert_eq!(r, i32());
    }

    #[test]
    fn test_unify_all_widening() {
        let r = unify_all(&[
            DecompType::Int(IntWidth::I8),
            DecompType::Int(IntWidth::I16),
            i32(),
        ]);
        assert_eq!(r, i32());
    }

    // ── Overload resolution ───────────────────────────────────────────────────

    #[test]
    fn test_overload_exact_match() {
        let mut f1 = FunctionType::new("foo", DecompType::Void);
        f1.add_param("x", i32());
        let mut f2 = FunctionType::new("foo", DecompType::Void);
        f2.add_param("x", i64());
        let candidates = vec![f1, f2];
        let arg_types = vec![Some(i32())];
        let result = resolve_overload(&candidates, &arg_types).unwrap();
        assert_eq!(result.selected, 0); // i32 exact match wins over i64.
    }

    #[test]
    fn test_overload_compatible_match() {
        let mut f = FunctionType::new("bar", DecompType::Void);
        f.add_param("x", i64());
        let candidates = vec![f];
        let arg_types = vec![Some(i32())];  // i32 compatible with i64
        let result = resolve_overload(&candidates, &arg_types).unwrap();
        assert_eq!(result.selected, 0);
    }

    #[test]
    fn test_overload_empty_candidates() {
        let result = resolve_overload(&[], &[Some(i32())]);
        assert!(result.is_none());
    }

    #[test]
    fn test_overload_unknown_arg_neutral() {
        let mut f = FunctionType::new("baz", DecompType::Void);
        f.add_param("x", i32());
        let candidates = vec![f];
        let arg_types = vec![None];
        let result = resolve_overload(&candidates, &arg_types).unwrap();
        assert!(result.score < 50); // neutral score, not high confidence.
    }
}
