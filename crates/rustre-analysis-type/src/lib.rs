//! `rustre-analysis-type`
//!
//! Type recovery and propagation for the `RustRE` Suite.
//!
//! Recovers C-like types from stripped binaries by collecting constraints
//! inferred from instruction operands and unifying them via a union-find
//! algorithm. The `TypePropagator` then walks the call graph, propagating
//! argument and return-value types across function boundaries.

pub mod constraints;
pub mod inference;
pub mod lattice;
pub mod primitive_types;
pub mod propagation;

/// Shared test-only PRNG for the crate's randomized property tests.
///
/// One definition instead of the per-module copies the test modules used to
/// carry (free `xorshift` ×2, raw-tuple `XorShift64` ×2, one closure form).
/// Identical algorithm, no seed guard — exactly like every former copy, so no
/// test's random sequence changes. (`property_tests::Rng` is xorshift64* — a
/// different algorithm — and stays separate.)
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// xorshift64 PRNG with a fixed seed for reproducible property tests.
    pub(crate) struct XorShift64(pub(crate) u64);
    impl XorShift64 {
        pub(crate) fn next(&mut self) -> u64 {
            xorshift(&mut self.0)
        }
    }
}
pub mod struct_builder;
pub mod struct_layout_recovery;
pub mod type_inference_engine;
pub mod type_inference_full;
pub mod type_propagation;
pub mod vtable;
#[cfg(test)]
mod property_tests;
pub mod cpp_type_recovery;
pub mod interprocedural;
mod mingw_runtime_sigs;
pub mod builtin_catalog;

pub use builtin_catalog::{list_builtin_types, lookup_builtin_type, BuiltinField, TypeRecord};
pub use lattice::{RefinementCell, TypeClass, TypeLevel};

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TypeError {
    #[error("type conflict: cannot unify {0} with {1}")]
    UnificationConflict(String, String),
    #[error("variable {0} not found in environment")]
    UnknownVariable(String),
    #[error("cyclic type constraint detected for variable {0}")]
    CyclicConstraint(String),
}

// ────────────────────────────────────────────────────────────────────────────
// TypeFact — the abstract type domain
// ────────────────────────────────────────────────────────────────────────────

/// A recovered / inferred type fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeFact {
    Sized(usize),
    Pointer(Box<Self>),
    Array {
        element: Box<Self>,
        length: Option<usize>,
    },
    Struct {
        fields: Vec<(usize, Self)>,
    },
    SignedInt(usize),
    UnsignedInt(usize),
    Float(usize),
    Bool,
    Char,
    Unknown,
}

impl fmt::Display for TypeFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sized(n) => write!(f, "sized({n})"),
            Self::Pointer(inner) => write!(f, "*{inner}"),
            Self::Array { element, length } => match length {
                Some(n) => write!(f, "[{element}; {n}]"),
                None => write!(f, "[{element}]"),
            },
            Self::Struct { fields } => {
                write!(f, "struct{{")?;
                for (i, (off, ty)) in fields.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "+{off}: {ty}")?;
                }
                write!(f, "}}")
            }
            Self::SignedInt(n) => write!(f, "i{}", n * 8),
            Self::UnsignedInt(n) => write!(f, "u{}", n * 8),
            Self::Float(n) => write!(f, "f{}", n * 8),
            Self::Bool => write!(f, "bool"),
            Self::Char => write!(f, "char"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

impl TypeFact {
    /// Return the byte size of this type if statically known.
    #[must_use]
    pub fn byte_size(&self) -> Option<usize> {
        match self {
            Self::Sized(n)
            | Self::SignedInt(n)
            | Self::UnsignedInt(n)
            | Self::Float(n) => Some(*n),
            Self::Bool | Self::Char => Some(1),
            Self::Array {
                element,
                length: Some(n),
            } => element.byte_size().and_then(|s| s.checked_mul(*n)),
            _ => None,
        }
    }

    /// Returns `true` if this type is more specific than `Unknown`.
    #[must_use]
    pub fn is_known(&self) -> bool {
        *self != Self::Unknown
    }

    /// Combine two type facts toward the most-specific refinement consistent
    /// with both — the "meet" on a lattice where `Unknown` is the top and
    /// concrete types live below.
    ///
    /// Historical name `join` is preserved for API compatibility, but the
    /// semantics is "most specific": e.g. `Sized(4) ⊓ SignedInt(4) =
    /// SignedInt(4)` because `SignedInt(4)` refines `Sized(4)` (both are size
    /// 4, the signed-int facet is strictly more informative). The previous
    /// implementation widened to `Unknown` on every mismatch, throwing away
    /// information that the constraint solver had already proved.
    ///
    /// The relation is commutative and idempotent (`x.join(&x) == x`).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        // `Unknown` is the lattice top — everything refines it.
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => return t.clone(),
            _ => {}
        }
        // `Sized(n)` is the parent of any concrete type whose `byte_size()`
        // is `n` — refine downward when possible.
        if let Self::Sized(n) = self && other.byte_size() == Some(*n) {
            return other.clone();
        }
        if let Self::Sized(n) = other && self.byte_size() == Some(*n) {
            return self.clone();
        }
        match (self, other) {
            (Self::Sized(a), Self::Sized(b)) if a == b => Self::Sized(*a),
            (Self::SignedInt(a), Self::SignedInt(b)) if a == b => Self::SignedInt(*a),
            (Self::UnsignedInt(a), Self::UnsignedInt(b)) if a == b => {
                Self::UnsignedInt(*a)
            }
            (Self::Float(a), Self::Float(b)) if a == b => Self::Float(*a),
            (Self::Pointer(a), Self::Pointer(b)) => Self::Pointer(Box::new(a.join(b))),
            _ => Self::Unknown,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TypeVariable
// ────────────────────────────────────────────────────────────────────────────

/// A type inference variable, identified by an integer id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeVar(pub u32);

impl fmt::Display for TypeVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "τ{}", self.0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ────────────────────────────────────────────────────────────────────────────

/// A constraint inferred from an instruction or ABI rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeConstraint {
    HasType(TypeVar, TypeFact),
    Equal(TypeVar, TypeVar),
    Deref {
        ptr: TypeVar,
        pointee: TypeVar,
    },
    Add {
        lhs: TypeVar,
        rhs: TypeVar,
        result: TypeVar,
    },
    Sub {
        lhs: TypeVar,
        rhs: TypeVar,
        result: TypeVar,
    },
    Bitwise {
        lhs: TypeVar,
        rhs: TypeVar,
        result: TypeVar,
    },
    IsCondition(TypeVar),
    ReturnOf {
        var: TypeVar,
        function: String,
    },
    ArgumentOf {
        var: TypeVar,
        function: String,
        index: usize,
    },
}

/// Collect every `TypeVar` mentioned by a constraint, so the solver can size
/// its `UnionFind` to cover them all (even when the constraint references a
/// `TypeVar` that was constructed directly rather than through `fresh()`).
fn constraint_vars(c: &TypeConstraint) -> Vec<TypeVar> {
    match c {
        TypeConstraint::HasType(v, _)
        | TypeConstraint::IsCondition(v)
        | TypeConstraint::ReturnOf { var: v, .. }
        | TypeConstraint::ArgumentOf { var: v, .. } => vec![*v],
        TypeConstraint::Equal(a, b) => vec![*a, *b],
        TypeConstraint::Deref { ptr, pointee } => vec![*ptr, *pointee],
        TypeConstraint::Add { lhs, rhs, result }
        | TypeConstraint::Sub { lhs, rhs, result }
        | TypeConstraint::Bitwise { lhs, rhs, result } => vec![*lhs, *rhs, *result],
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Union-Find for type variables
// ────────────────────────────────────────────────────────────────────────────

struct UnionFind {
    parent: Vec<u32>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(size: usize) -> Self {
        assert!(
            u32::try_from(size).is_ok(),
            "UnionFind: size {size} exceeds u32::MAX — cannot index with u32 type-var ids"
        );
        Self {
            parent: (0..u32::try_from(size).expect("size fits in u32")).collect(),
            rank: vec![0; size],
        }
    }

    /// Find with path compression. Implemented iteratively so that a long
    /// `parent` chain (which the public `add_constraint` API can produce
    /// adversarially) does not overflow the call stack — the recursive form
    /// blew up on linear chains of ~100k variables, a realistic size for
    /// stripped binaries.
    fn find(&mut self, x: u32) -> u32 {
        // First pass: walk to the root without touching the array.
        let mut root = x;
        while self.parent[root as usize] != root {
            root = self.parent[root as usize];
        }
        // Second pass: path compression — point every node on the path
        // directly at the root, keeping the inverse-Ackermann amortised cost.
        let mut cur = x;
        while self.parent[cur as usize] != root {
            let next = self.parent[cur as usize];
            self.parent[cur as usize] = root;
            cur = next;
        }
        root
    }

    fn union(&mut self, x: u32, y: u32) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return;
        }
        match self.rank[rx as usize].cmp(&self.rank[ry as usize]) {
            std::cmp::Ordering::Less => self.parent[rx as usize] = ry,
            std::cmp::Ordering::Greater => self.parent[ry as usize] = rx,
            std::cmp::Ordering::Equal => {
                self.parent[ry as usize] = rx;
                self.rank[rx as usize] += 1;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TypeInferenceEngine
// ────────────────────────────────────────────────────────────────────────────

/// Collects `TypeConstraint`s, unifies type variables, and assigns concrete
/// `TypeFact`s to each variable.
pub struct TypeInferenceEngine {
    constraints: Vec<TypeConstraint>,
    next_var: u32,
    name_to_var: HashMap<String, TypeVar>,
}

impl TypeInferenceEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            next_var: 0,
            name_to_var: HashMap::new(),
        }
    }

    /// Allocate a fresh type variable.
    pub const fn fresh(&mut self) -> TypeVar {
        let v = TypeVar(self.next_var);
        self.next_var += 1;
        v
    }

    /// Get or create the type variable for a named program variable.
    pub fn var_for(&mut self, name: &str) -> TypeVar {
        if let Some(&v) = self.name_to_var.get(name) {
            return v;
        }
        let v = self.fresh();
        self.name_to_var.insert(name.to_string(), v);
        v
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
    }

    /// Run unification over all collected constraints and return the assignment
    /// of `TypeFact` to each type variable id (indexed by `TypeVar.0`).
    ///
    /// # Errors
    ///
    /// Currently infallible but returns `Result` for forward compatibility.
    ///
    /// # Panics
    ///
    /// Panics if the number of type variables overflows `u32`.
    pub fn solve(&mut self) -> Result<HashMap<u32, TypeFact>, TypeError> {
        self.solve_checked().map(|(assignment, _)| assignment)
    }

    /// Like [`solve`](Self::solve), but also reports whether the capped
    /// Deref fixpoint pass actually converged. `false` means the pass cap
    /// was hit while facts were still changing (e.g. a Deref cycle, whose
    /// pointer type would deepen forever) — the assignment is still valid
    /// and deterministic, but truncated at the cap depth. The plain
    /// `solve()` used to swallow this silently.
    ///
    /// # Errors
    ///
    /// Same as [`solve`](Self::solve).
    ///
    /// # Panics
    ///
    /// Same as [`solve`](Self::solve).
    pub fn solve_checked(&mut self) -> Result<(HashMap<u32, TypeFact>, bool), TypeError> {
        // Compute the actual maximum variable id seen — `add_constraint` is
        // public and can carry `TypeVar`s the caller constructed directly
        // (e.g. via `TypeVar(99)`), past `self.next_var`. Sizing UnionFind
        // only to `next_var` would panic with out-of-bounds in find/union.
        let mut max_id = self.next_var;
        for c in &self.constraints {
            for &v in &constraint_vars(c) {
                if v.0 >= max_id {
                    max_id = v.0.saturating_add(1);
                }
            }
        }
        let n = max_id as usize;
        let mut uf = UnionFind::new(n);

        // Single pass: build union-find; record raw HasType facts and
        // IsCondition variables for canonical-order processing afterwards.
        // `TypeFact::join` is commutative but NOT associative (a conflict
        // widens to `Unknown`, the lattice top, which a *later* fact would
        // refine again), so folding facts in constraint order made the result
        // depend on the order constraints were added.
        let mut raw_facts: Vec<(u32, TypeFact)> = Vec::new();
        let mut cond_vars: Vec<u32> = Vec::new();
        for c in &self.constraints {
            match c {
                TypeConstraint::Equal(a, b) => {
                    uf.union(a.0, b.0);
                }
                TypeConstraint::HasType(v, t) => raw_facts.push((v.0, t.clone())),
                TypeConstraint::IsCondition(v) => cond_vars.push(v.0),
                // Deref constraints are handled exclusively by the dedicated
                // snapshot-based pass below, after all Equal constraints have
                // been resolved — deriving pointer types here, mid-unification
                // and in constraint order, made the result order-dependent.
                TypeConstraint::Deref { .. } => {}
                TypeConstraint::Add { lhs, rhs, result }
                | TypeConstraint::Sub { lhs, rhs, result }
                | TypeConstraint::Bitwise { lhs, rhs, result } => {
                    uf.union(lhs.0, result.0);
                    uf.union(rhs.0, result.0);
                }
                TypeConstraint::ReturnOf { .. } | TypeConstraint::ArgumentOf { .. } => {}
            }
        }

        // Group facts by their final canonical root and fold each group in a
        // canonical (sorted) order, making the result a function of the fact
        // *multiset* rather than of insertion order.
        let mut by_root: std::collections::BTreeMap<u32, Vec<TypeFact>> =
            std::collections::BTreeMap::new();
        for (var_id, fact) in raw_facts {
            by_root.entry(uf.find(var_id)).or_default().push(fact);
        }
        let mut canonical_hints: HashMap<u32, TypeFact> = HashMap::new();
        for (root, mut facts) in by_root {
            facts.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
            let mut acc = TypeFact::Unknown;
            for f in &facts {
                acc = acc.join(f);
            }
            canonical_hints.insert(root, acc);
        }
        // Weak Bool hints: only applied to classes with no concrete fact.
        for v in cond_vars {
            let root = uf.find(v);
            let hint = canonical_hints.entry(root).or_insert(TypeFact::Unknown);
            if *hint == TypeFact::Unknown {
                *hint = TypeFact::Bool;
            }
        }

        // Second pass over Deref constraints: now that all Equal constraints
        // have been resolved and canonical_hints is fully populated, re-derive
        // pointer types.  If a Deref appeared before its pointee's HasType
        // constraint in the first pass, the pointer inner type was recorded as
        // Unknown; this second pass corrects that.
        // Iterate to a fixed point: chained Derefs (p → a, a → b) need the
        // inner pointer type derived before the outer one, and constraint
        // order is arbitrary — a single pass would make the result depend on
        // the order constraints were added. Each pass can resolve at least one
        // link of the longest chain, so `deref_count` passes suffice; the
        // `changed` flag exits early (and guards against join-driven cycles).
        let deref_count = self
            .constraints
            .iter()
            .filter(|c| matches!(c, TypeConstraint::Deref { .. }))
            .count();
        // Each pass reads only the previous pass's snapshot (Jacobi-style), so
        // the outcome depends only on the *set* of constraints, never on the
        // order they were added — Gauss-Seidel style in-place updates would
        // make chained/cyclic Deref results order-dependent. Deref *cycles*
        // have no finite fixed point (the pointer type would deepen forever),
        // so passes are capped: acyclic chains of realistic length converge
        // fully, cycles stop at a deterministic depth.
        let pass_cap = deref_count.min(64);
        // Converged unless the cap is exhausted while a further pass would
        // still change something (verified by the probe pass below).
        let mut converged = true;
        let mut broke_early = pass_cap == 0;
        for _ in 0..pass_cap {
            let snapshot = canonical_hints.clone();
            // Collect this pass's contributions per root, then fold each
            // group in sorted order (join is not associative — see above).
            let mut contribs: std::collections::BTreeMap<u32, Vec<TypeFact>> =
                std::collections::BTreeMap::new();
            for c in &self.constraints {
                if let TypeConstraint::Deref { ptr, pointee } = c {
                    let ptr_root = uf.find(ptr.0);
                    let pointee_root = uf.find(pointee.0);
                    let inner = snapshot
                        .get(&pointee_root)
                        .cloned()
                        .unwrap_or(TypeFact::Unknown);
                    contribs
                        .entry(ptr_root)
                        .or_default()
                        .push(TypeFact::Pointer(Box::new(inner)));
                }
            }
            let mut changed = false;
            for (root, mut facts) in contribs {
                facts.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
                let existing = canonical_hints.entry(root).or_insert(TypeFact::Unknown);
                let mut acc = existing.clone();
                for f in &facts {
                    acc = acc.join(f);
                }
                if acc != *existing {
                    *existing = acc;
                    changed = true;
                }
            }
            if !changed {
                broke_early = true;
                break;
            }
        }
        // Probe pass: if every allotted pass still changed something, check
        // (without mutating) whether one more pass would change anything.
        // A chain of exactly `deref_count` links legitimately changes on its
        // final pass yet is fully converged — only a still-changing probe
        // marks non-convergence. This keeps `solve()` output bit-identical.
        if !broke_early {
            'probe: for c in &self.constraints {
                if let TypeConstraint::Deref { ptr, pointee } = c {
                    let ptr_root = uf.find(ptr.0);
                    let pointee_root = uf.find(pointee.0);
                    let inner = canonical_hints
                        .get(&pointee_root)
                        .cloned()
                        .unwrap_or(TypeFact::Unknown);
                    let contrib = TypeFact::Pointer(Box::new(inner));
                    let existing = canonical_hints
                        .get(&ptr_root)
                        .cloned()
                        .unwrap_or(TypeFact::Unknown);
                    if existing.join(&contrib) != existing {
                        converged = false;
                        break 'probe;
                    }
                }
            }
        }

        // Final assignment: every variable gets the hint of its canonical root.
        let mut assignment: HashMap<u32, TypeFact> = HashMap::new();
        for i in 0..u32::try_from(n).expect("n fits in u32 (validated by UnionFind::new)") {
            let root = uf.find(i);
            let fact = canonical_hints
                .get(&root)
                .cloned()
                .unwrap_or(TypeFact::Unknown);
            assignment.insert(i, fact);
        }

        Ok((assignment, converged))
    }

    /// Resolve the type fact for a named variable after solving.
    ///
    /// # Errors
    ///
    /// Returns `TypeError::UnknownVariable` if the variable was never registered.
    pub fn type_of(
        &self,
        name: &str,
        assignment: &HashMap<u32, TypeFact>,
    ) -> Result<TypeFact, TypeError> {
        let v = self
            .name_to_var
            .get(name)
            .copied()
            .ok_or_else(|| TypeError::UnknownVariable(name.to_string()))?;
        Ok(assignment.get(&v.0).cloned().unwrap_or(TypeFact::Unknown))
    }

    /// Return all (`variable_name`, `TypeFact`) pairs.
    pub fn all_types<'a>(
        &'a self,
        assignment: &'a HashMap<u32, TypeFact>,
    ) -> impl Iterator<Item = (&'a str, &'a TypeFact)> {
        self.name_to_var
            .iter()
            .filter_map(|(name, var)| assignment.get(&var.0).map(|t| (name.as_str(), t)))
    }
}

impl Default for TypeInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TypeEnvironment
// ────────────────────────────────────────────────────────────────────────────

/// The fully-resolved type environment for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeEnvironment {
    pub types: HashMap<String, TypeFact>,
    pub arg_types: Vec<TypeFact>,
    pub return_type: TypeFact,
}

impl Default for TypeEnvironment {
    fn default() -> Self {
        Self {
            types: HashMap::new(),
            arg_types: Vec::new(),
            return_type: TypeFact::Unknown,
        }
    }
}

impl TypeEnvironment {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: impl Into<String>, fact: TypeFact) {
        self.types.insert(name.into(), fact);
    }

    #[must_use]
    pub fn get(&self, name: &str) -> &TypeFact {
        self.types.get(name).unwrap_or(&TypeFact::Unknown)
    }

    /// Merge another environment in, widening on conflict.
    pub fn merge(&mut self, other: &Self) {
        for (name, fact) in &other.types {
            let existing = self.types.entry(name.clone()).or_insert(TypeFact::Unknown);
            *existing = existing.join(fact);
        }
        let max_args = self.arg_types.len().max(other.arg_types.len());
        self.arg_types.resize(max_args, TypeFact::Unknown);
        for (i, t) in other.arg_types.iter().enumerate() {
            self.arg_types[i] = self.arg_types[i].join(t);
        }
        self.return_type = self.return_type.join(&other.return_type);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// CallGraph for type propagation
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub name: String,
    pub callees: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: HashMap<String, CallGraphNode>,
}

impl CallGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&mut self, name: impl Into<String>) {
        let n = name.into();
        self.nodes
            .entry(n.clone())
            .or_insert_with(|| CallGraphNode {
                name: n,
                callees: Vec::new(),
            });
    }

    pub fn add_call(&mut self, from_fn: &str, to_fn: &str) {
        if let Some(node) = self.nodes.get_mut(from_fn) && !node.callees.contains(&to_fn.to_string()) {
            node.callees.push(to_fn.to_string());
        }
    }

    /// Topological order (callee before caller) for bottom-up propagation.
    #[must_use]
    pub fn topological_order(&self) -> Vec<String> {
        let mut visited: HashSet<&str> = HashSet::new();
        let mut order: Vec<String> = Vec::new();
        // Sort the roots so the returned order is deterministic regardless of
        // HashMap iteration order (which is randomized per-process).
        let mut roots: Vec<&String> = self.nodes.keys().collect();
        roots.sort();
        for name in roots {
            if visited.contains(name.as_str()) {
                continue;
            }
            // Iterative post-order DFS with an explicit stack to avoid
            // overflowing the call stack on deep call chains.
            let mut stack: Vec<(&str, usize)> = vec![(name.as_str(), 0)];
            visited.insert(name.as_str());
            while let Some((current, idx)) = stack.pop() {
                let callees: &[String] = self
                    .nodes
                    .get(current)
                    .map_or_else(|| [].as_slice(), |node| node.callees.as_slice());
                if let Some(callee) = callees.get(idx) {
                    stack.push((current, idx + 1));
                    if visited.insert(callee.as_str()) {
                        stack.push((callee.as_str(), 0));
                    }
                } else {
                    order.push(current.to_string());
                }
            }
        }
        order
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TypePropagator
// ────────────────────────────────────────────────────────────────────────────

/// Propagates type environments across function boundaries.
///
/// The `environments` map is protected by a [`parking_lot::RwLock`] so that
/// concurrent per-function constraint solving (when the IL lifting layer is
/// wired in) can read each function's environment in parallel while the
/// propagator holds a write lock only when merging new facts.
pub struct TypePropagator {
    pub call_graph: CallGraph,
    pub environments: parking_lot::RwLock<HashMap<String, TypeEnvironment>>,
}

impl TypePropagator {
    #[must_use]
    pub fn new(call_graph: CallGraph) -> Self {
        Self {
            call_graph,
            environments: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn set_initial_env(&mut self, function: &str, env: TypeEnvironment) {
        self.environments.write().insert(function.to_string(), env);
    }

    /// Propagate types bottom-up across the call graph until a fixed point.
    pub fn propagate(&mut self) {
        let order = self.call_graph.topological_order();

        let mut changed = true;
        let mut iters = 0;
        while changed && iters < 100 {
            changed = false;
            iters += 1;

            for caller_name in &order {
                let Some(node) = self.call_graph.nodes.get(caller_name.as_str()) else {
                    continue;
                };

                for callee_name in &node.callees {
                    // Only the callee's return type is read below — clone just
                    // that instead of the whole TypeEnvironment.
                    let dst_rt = {
                        let envs = self.environments.read();
                        match envs.get(callee_name.as_str()) {
                            Some(e) => e.return_type.clone(),
                            None => continue,
                        }
                    };

                    if dst_rt.is_known() {
                        // Clone the env to avoid holding the write lock during computation.
                        let mut src_env = self.environments.read()
                            .get(caller_name.as_str()).cloned().unwrap_or_default();

                        let existing = src_env.get(callee_name.as_str()).clone();
                        let new_rt = existing.join(&dst_rt);
                        let rt_changed = new_rt != existing;
                        if rt_changed {
                            src_env.set(callee_name.clone(), new_rt);
                        }
                        // Propagate callee's return type into caller's return-type slot.
                        let new_caller_rt = src_env.return_type.join(&dst_rt);
                        let caller_rt_changed = new_caller_rt != src_env.return_type;
                        if caller_rt_changed {
                            src_env.return_type = new_caller_rt;
                        }
                        if rt_changed || caller_rt_changed {
                            self.environments.write().insert(caller_name.clone(), src_env);
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn env_for(&self, function: &str) -> Option<TypeEnvironment> {
        self.environments.read().get(function).cloned()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Instruction model for constraint collection
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TypedInstr {
    pub kind: InstrKind,
}

#[derive(Debug, Clone)]
pub enum InstrKind {
    Assign {
        dst: String,
        src: String,
    },
    Const {
        dst: String,
        bytes: usize,
        signed: bool,
    },
    Load {
        dst: String,
        ptr: String,
    },
    Store {
        ptr: String,
        src: String,
    },
    Add {
        dst: String,
        lhs: String,
        rhs: String,
    },
    Sub {
        dst: String,
        lhs: String,
        rhs: String,
    },
    Branch {
        cond: String,
    },
    Call {
        dst: Option<String>,
        function: String,
        args: Vec<String>,
    },
    Return {
        val: Option<String>,
    },
}

/// Collect constraints from a slice of `TypedInstr`s.
pub fn collect_constraints(engine: &mut TypeInferenceEngine, instrs: &[TypedInstr]) {
    for instr in instrs {
        match &instr.kind {
            InstrKind::Assign { dst, src } => {
                let dv = engine.var_for(dst);
                let sv = engine.var_for(src);
                engine.add_constraint(TypeConstraint::Equal(dv, sv));
            }
            InstrKind::Const { dst, bytes, signed } => {
                let dv = engine.var_for(dst);
                let fact = if *signed {
                    TypeFact::SignedInt(*bytes)
                } else {
                    TypeFact::UnsignedInt(*bytes)
                };
                engine.add_constraint(TypeConstraint::HasType(dv, fact));
            }
            InstrKind::Load { dst, ptr } => {
                let dv = engine.var_for(dst);
                let pv = engine.var_for(ptr);
                engine.add_constraint(TypeConstraint::Deref {
                    ptr: pv,
                    pointee: dv,
                });
            }
            InstrKind::Store { ptr, src } => {
                let sv = engine.var_for(src);
                let pv = engine.var_for(ptr);
                engine.add_constraint(TypeConstraint::Deref {
                    ptr: pv,
                    pointee: sv,
                });
            }
            InstrKind::Add { dst, lhs, rhs } => {
                let dv = engine.var_for(dst);
                let lv = engine.var_for(lhs);
                let rv = engine.var_for(rhs);
                engine.add_constraint(TypeConstraint::Add {
                    lhs: lv,
                    rhs: rv,
                    result: dv,
                });
            }
            InstrKind::Sub { dst, lhs, rhs } => {
                let dv = engine.var_for(dst);
                let lv = engine.var_for(lhs);
                let rv = engine.var_for(rhs);
                engine.add_constraint(TypeConstraint::Sub {
                    lhs: lv,
                    rhs: rv,
                    result: dv,
                });
            }
            InstrKind::Branch { cond } => {
                let cv = engine.var_for(cond);
                engine.add_constraint(TypeConstraint::IsCondition(cv));
            }
            InstrKind::Call {
                dst,
                function,
                args,
            } => {
                if let Some(dst_name) = dst {
                    let dv = engine.var_for(dst_name);
                    engine.add_constraint(TypeConstraint::ReturnOf {
                        var: dv,
                        function: function.clone(),
                    });
                }
                for (i, arg) in args.iter().enumerate() {
                    let av = engine.var_for(arg);
                    engine.add_constraint(TypeConstraint::ArgumentOf {
                        var: av,
                        function: function.clone(),
                        index: i,
                    });
                }
            }
            InstrKind::Return { val } => {
                if let Some(name) = val {
                    let _ = engine.var_for(name);
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// StructRecovery
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldAccess {
    pub base: String,
    pub offset: usize,
    pub access_size: usize,
}

pub struct StructRecovery;

impl StructRecovery {
    /// Given all observed field accesses, produce `TypeFact::Struct` candidates.
    #[must_use]
    pub fn recover(accesses: &[FieldAccess]) -> HashMap<String, TypeFact> {
        let mut by_base: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        for fa in accesses {
            by_base
                .entry(fa.base.clone())
                .or_default()
                .push((fa.offset, fa.access_size));
        }

        let mut result = HashMap::new();
        for (base, mut fields) in by_base {
            fields.sort_by_key(|(off, _)| *off);
            fields.dedup();
            let type_fields: Vec<(usize, TypeFact)> = fields
                .into_iter()
                .map(|(off, size)| (off, TypeFact::Sized(size)))
                .collect();
            result.insert(
                base,
                TypeFact::Struct {
                    fields: type_fields,
                },
            );
        }
        result
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Level 7 — Library Function Signatures  (§6.6 level 7)
//
// This section implements type recovery from known library function signatures.
// Two sources are supported:
//
//  1. The Windows API type database (`WinApiTypeDb`) — 25 hand-coded signatures
//     covering the most common Win32 / CRT functions.
//  2. `LibraryTypeImporter` — looks up a function name+DLL pair and propagates
//     the resulting argument / return-value types to every call-site.
//
// Additionally, `ArrayDetector` provides a heuristic array-access analysis that
// complements level 5 (array inference) by working directly over a flat
// instruction stream rather than a structured CFG.
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Shared primitive type aliases used in signatures
// ────────────────────────────────────────────────────────────────────────────

/// Convenience aliases for `WinAPI` primitive sizes (bytes).
pub mod win_types {
    /// `DWORD` — 32-bit unsigned integer (4 bytes).
    pub const DWORD: usize = 4;
    /// `BOOL`  — 32-bit integer used as a boolean (4 bytes, Win32 convention).
    pub const BOOL: usize = 4;
    /// `HANDLE` — opaque pointer-sized value (8 bytes on 64-bit).
    pub const HANDLE: usize = 8;
    /// `SIZE_T` — pointer-sized unsigned integer (8 bytes on 64-bit).
    pub const SIZE_T: usize = 8;
    /// `OVERLAPPED` stub size (32 bytes on 64-bit).
    pub const OVERLAPPED: usize = 32;
    /// `FILE` opaque struct placeholder (8-byte pointer).
    pub const FILE_PTR: usize = 8;
}

// ────────────────────────────────────────────────────────────────────────────
// FunctionSignature — a single library function's ABI record
// ────────────────────────────────────────────────────────────────────────────

/// The calling-convention of a library function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    /// Microsoft x64 (first four args in RCX/RDX/R8/R9, rest on stack).
    MicrosoftX64,
    /// System V AMD64 (first six args in registers).
    SysVAmd64,
    /// 32-bit `__stdcall`.
    StdCall32,
    /// 32-bit `__cdecl`.
    CDecl32,
    /// Variadic function (`printf`, etc.).  The fixed-prefix ABI matches the
    /// parent convention.
    Variadic,
}

/// A named parameter with its type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamInfo {
    /// Human-readable parameter name (for display / annotation).
    pub name: String,
    /// The inferred type of this parameter.
    pub ty: TypeFact,
}

impl ParamInfo {
    fn new(name: impl Into<String>, ty: TypeFact) -> Self {
        Self {
            name: name.into(),
            ty,
        }
    }
}

/// A complete function-level signature recovered from a library database or
/// FLIRT match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Canonical function name (e.g. `"CreateFileA"`, `"memcpy"`).
    pub name: String,
    /// DLL or library that exports this function (lower-case, e.g. `"kernel32.dll"`).
    pub dll: String,
    /// Ordered list of parameters.
    pub params: Vec<ParamInfo>,
    /// Return type.
    pub return_type: TypeFact,
    /// Calling convention.
    pub calling_convention: CallingConvention,
    /// `true` if the function is variadic (extra arguments beyond `params`).
    pub is_variadic: bool,
}

impl FunctionSignature {
    /// Create a non-variadic signature.
    fn new(
        name: impl Into<String>,
        dll: impl Into<String>,
        params: Vec<ParamInfo>,
        return_type: TypeFact,
        calling_convention: CallingConvention,
    ) -> Self {
        Self {
            name: name.into(),
            dll: dll.into(),
            params,
            return_type,
            calling_convention,
            is_variadic: false,
        }
    }

    /// Create a variadic signature.
    fn new_variadic(
        name: impl Into<String>,
        dll: impl Into<String>,
        params: Vec<ParamInfo>,
        return_type: TypeFact,
        calling_convention: CallingConvention,
    ) -> Self {
        Self {
            name: name.into(),
            dll: dll.into(),
            params,
            return_type,
            calling_convention,
            is_variadic: true,
        }
    }

    /// Number of fixed (non-variadic) parameters.
    #[must_use]
    pub const fn arity(&self) -> usize {
        self.params.len()
    }

    /// Look up the type of the parameter at position `idx` (0-based).
    #[must_use]
    pub fn param_type(&self, idx: usize) -> Option<&TypeFact> {
        self.params.get(idx).map(|p| &p.ty)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Type helpers — shortcuts for constructing common TypeFacts
// ────────────────────────────────────────────────────────────────────────────

/// Helper: `*const void` / `*mut void` — untyped pointer.
#[inline]
fn ptr_void() -> TypeFact {
    TypeFact::Pointer(Box::new(TypeFact::Unknown))
}

/// Helper: `*const char` — pointer to a narrow string.
#[inline]
fn ptr_char() -> TypeFact {
    TypeFact::Pointer(Box::new(TypeFact::Char))
}

/// Helper: `*mut char` — mutable pointer to a narrow string.
#[inline]
fn ptr_mut_char() -> TypeFact {
    TypeFact::Pointer(Box::new(TypeFact::Char))
}

/// Helper: `DWORD` / `BOOL` — 32-bit unsigned integer.
#[inline]
const fn u32_fact() -> TypeFact {
    TypeFact::UnsignedInt(4)
}

/// Helper: `HANDLE` — 64-bit pointer-sized opaque value.
#[inline]
const fn handle_fact() -> TypeFact {
    TypeFact::UnsignedInt(win_types::HANDLE)
}

/// Helper: `SIZE_T` — 64-bit unsigned integer.
#[inline]
const fn size_t_fact() -> TypeFact {
    TypeFact::UnsignedInt(win_types::SIZE_T)
}

/// Helper: `*mut DWORD` — pointer to a 32-bit unsigned integer.
#[inline]
fn ptr_u32() -> TypeFact {
    TypeFact::Pointer(Box::new(TypeFact::UnsignedInt(4)))
}

/// Helper: `*mut OVERLAPPED` — pointer to the Win32 OVERLAPPED struct.
#[inline]
fn ptr_overlapped() -> TypeFact {
    // Represent OVERLAPPED as a sized struct; callers may refine further.
    TypeFact::Pointer(Box::new(TypeFact::Sized(win_types::OVERLAPPED)))
}

/// Helper: `*mut FILE` — pointer to a C stdio FILE structure.
#[inline]
fn ptr_file() -> TypeFact {
    TypeFact::Pointer(Box::new(TypeFact::Sized(win_types::FILE_PTR)))
}

/// Helper: `BOOL` as a return value (4-byte signed, Win32 convention).
#[inline]
const fn bool_ret() -> TypeFact {
    TypeFact::SignedInt(win_types::BOOL)
}

/// Helper: `int` — 32-bit signed integer.
#[inline]
const fn int_fact() -> TypeFact {
    TypeFact::SignedInt(4)
}

/// Helper: `void` return — represented as Unknown (no meaningful type).
#[inline]
const fn void_fact() -> TypeFact {
    TypeFact::Unknown
}

// ────────────────────────────────────────────────────────────────────────────
// WinApiTypeDb — static database of 25 common WinAPI / CRT signatures
// ────────────────────────────────────────────────────────────────────────────

/// A static database of well-known Windows API and C runtime function
/// signatures.  Used by [`LibraryTypeImporter`] to resolve names found in a
/// binary's import table or matched by FLIRT.
///
/// The database covers 25 functions:
/// `CreateFile`, `ReadFile`, `WriteFile`, `VirtualAlloc`, `VirtualFree`,
/// `VirtualProtect`, `CreateThread`, `WaitForSingleObject`, `CloseHandle`,
/// `GetProcAddress`, `LoadLibraryA`, `HeapAlloc`, `HeapFree`,
/// `memcpy`, `memset`, `malloc`, `free`, `strlen`, `strcpy`, `strcmp`,
/// `printf`, `fopen`, `fread`, `fwrite`, `fclose`.
pub struct WinApiTypeDb;

impl WinApiTypeDb {
    /// Look up a function signature by (case-insensitive) name and DLL.
    ///
    /// Returns `None` if the combination is not in the database.
    #[must_use]
    pub fn lookup(func_name: &str, dll: &str) -> Option<FunctionSignature> {
        let key = func_name.to_ascii_lowercase();
        let dll_key = dll.to_ascii_lowercase();
        Self::all_signatures().into_iter().find(|sig| {
            sig.name.to_ascii_lowercase() == key && sig.dll.to_ascii_lowercase() == dll_key
        })
    }

    /// Look up by function name alone (useful when DLL is unknown).
    ///
    /// Returns the first matching signature if the name is unambiguous across
    /// the supported database.
    #[must_use]
    pub fn lookup_by_name(func_name: &str) -> Option<FunctionSignature> {
        let key = func_name.to_ascii_lowercase();
        Self::all_signatures()
            .into_iter()
            .find(|sig| sig.name.to_ascii_lowercase() == key)
    }

    /// Return all 25 built-in signatures.
    #[must_use]
    pub fn all_signatures() -> Vec<FunctionSignature> {
        let mut sigs = Self::file_memory_signatures();
        sigs.extend(Self::process_signatures());
        sigs.extend(Self::crt_memory_string_signatures());
        sigs.extend(Self::crt_io_signatures());
        sigs
    }

    /// Win32 file-I/O and virtual-memory signatures.
    #[must_use]
    fn file_memory_signatures() -> Vec<FunctionSignature> {
        vec![
            // ── File I/O ────────────────────────────────────────────────────
            // CreateFile(lpFileName, dwAccess, dwShare, lpSecurity,
            //            dwCreationDisp, dwFlagsAttr, hTemplateFile) -> HANDLE
            FunctionSignature::new(
                "CreateFileA",
                "kernel32.dll",
                vec![
                    ParamInfo::new("lpFileName", ptr_char()),
                    ParamInfo::new("dwDesiredAccess", u32_fact()),
                    ParamInfo::new("dwShareMode", u32_fact()),
                    ParamInfo::new("lpSecurityAttributes", ptr_void()),
                    ParamInfo::new("dwCreationDisposition", u32_fact()),
                    ParamInfo::new("dwFlagsAndAttributes", u32_fact()),
                    ParamInfo::new("hTemplateFile", handle_fact()),
                ],
                handle_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // ReadFile(hFile, lpBuffer, nBytesToRead, lpNumberOfBytesRead,
            //          lpOverlapped) -> BOOL
            FunctionSignature::new(
                "ReadFile",
                "kernel32.dll",
                vec![
                    ParamInfo::new("hFile", handle_fact()),
                    ParamInfo::new("lpBuffer", ptr_void()),
                    ParamInfo::new("nNumberOfBytesToRead", u32_fact()),
                    ParamInfo::new("lpNumberOfBytesRead", ptr_u32()),
                    ParamInfo::new("lpOverlapped", ptr_overlapped()),
                ],
                bool_ret(),
                CallingConvention::MicrosoftX64,
            ),
            // WriteFile(hFile, lpBuffer, nBytesToWrite, lpNumberOfBytesWritten,
            //           lpOverlapped) -> BOOL
            FunctionSignature::new(
                "WriteFile",
                "kernel32.dll",
                vec![
                    ParamInfo::new("hFile", handle_fact()),
                    ParamInfo::new("lpBuffer", TypeFact::Pointer(Box::new(TypeFact::Unknown))),
                    ParamInfo::new("nNumberOfBytesToWrite", u32_fact()),
                    ParamInfo::new("lpNumberOfBytesWritten", ptr_u32()),
                    ParamInfo::new("lpOverlapped", ptr_overlapped()),
                ],
                bool_ret(),
                CallingConvention::MicrosoftX64,
            ),
            // ── Virtual memory ──────────────────────────────────────────────
            // VirtualAlloc(lpAddress, dwSize, flAllocType, flProtect) -> *mut void
            FunctionSignature::new(
                "VirtualAlloc",
                "kernel32.dll",
                vec![
                    ParamInfo::new("lpAddress", ptr_void()),
                    ParamInfo::new("dwSize", size_t_fact()),
                    ParamInfo::new("flAllocationType", u32_fact()),
                    ParamInfo::new("flProtect", u32_fact()),
                ],
                ptr_void(),
                CallingConvention::MicrosoftX64,
            ),
            // VirtualFree(lpAddress, dwSize, dwFreeType) -> BOOL
            FunctionSignature::new(
                "VirtualFree",
                "kernel32.dll",
                vec![
                    ParamInfo::new("lpAddress", ptr_void()),
                    ParamInfo::new("dwSize", size_t_fact()),
                    ParamInfo::new("dwFreeType", u32_fact()),
                ],
                bool_ret(),
                CallingConvention::MicrosoftX64,
            ),
            // VirtualProtect(lpAddress, dwSize, flNewProtect, lpOldProtect) -> BOOL
            FunctionSignature::new(
                "VirtualProtect",
                "kernel32.dll",
                vec![
                    ParamInfo::new("lpAddress", ptr_void()),
                    ParamInfo::new("dwSize", size_t_fact()),
                    ParamInfo::new("flNewProtect", u32_fact()),
                    ParamInfo::new("lpOldProtect", ptr_u32()),
                ],
                bool_ret(),
                CallingConvention::MicrosoftX64,
            ),
        ]
    }

    /// Win32 thread, library-loading, and heap signatures.
    #[must_use]
    fn process_signatures() -> Vec<FunctionSignature> {
        vec![
            // ── Threads ─────────────────────────────────────────────────────
            // CreateThread(lpAttr, dwStackSize, lpStartAddr, lpParam,
            //              dwCreationFlags, lpThreadId) -> HANDLE
            FunctionSignature::new(
                "CreateThread",
                "kernel32.dll",
                vec![
                    ParamInfo::new("lpThreadAttributes", ptr_void()),
                    ParamInfo::new("dwStackSize", size_t_fact()),
                    ParamInfo::new("lpStartAddress", ptr_void()),
                    ParamInfo::new("lpParameter", ptr_void()),
                    ParamInfo::new("dwCreationFlags", u32_fact()),
                    ParamInfo::new("lpThreadId", ptr_u32()),
                ],
                handle_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // WaitForSingleObject(hHandle, dwMilliseconds) -> DWORD
            FunctionSignature::new(
                "WaitForSingleObject",
                "kernel32.dll",
                vec![
                    ParamInfo::new("hHandle", handle_fact()),
                    ParamInfo::new("dwMilliseconds", u32_fact()),
                ],
                u32_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // CloseHandle(hObject) -> BOOL
            FunctionSignature::new(
                "CloseHandle",
                "kernel32.dll",
                vec![ParamInfo::new("hObject", handle_fact())],
                bool_ret(),
                CallingConvention::MicrosoftX64,
            ),
            // ── Library loading ─────────────────────────────────────────────
            // GetProcAddress(hModule, lpProcName) -> *mut void
            FunctionSignature::new(
                "GetProcAddress",
                "kernel32.dll",
                vec![
                    ParamInfo::new("hModule", handle_fact()),
                    ParamInfo::new("lpProcName", ptr_char()),
                ],
                ptr_void(),
                CallingConvention::MicrosoftX64,
            ),
            // LoadLibraryA(lpLibFileName) -> HANDLE
            FunctionSignature::new(
                "LoadLibraryA",
                "kernel32.dll",
                vec![ParamInfo::new("lpLibFileName", ptr_char())],
                handle_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // ── Heap allocation ─────────────────────────────────────────────
            // HeapAlloc(hHeap, dwFlags, dwBytes) -> *mut void
            FunctionSignature::new(
                "HeapAlloc",
                "kernel32.dll",
                vec![
                    ParamInfo::new("hHeap", handle_fact()),
                    ParamInfo::new("dwFlags", u32_fact()),
                    ParamInfo::new("dwBytes", size_t_fact()),
                ],
                ptr_void(),
                CallingConvention::MicrosoftX64,
            ),
            // HeapFree(hHeap, dwFlags, lpMem) -> BOOL
            FunctionSignature::new(
                "HeapFree",
                "kernel32.dll",
                vec![
                    ParamInfo::new("hHeap", handle_fact()),
                    ParamInfo::new("dwFlags", u32_fact()),
                    ParamInfo::new("lpMem", ptr_void()),
                ],
                bool_ret(),
                CallingConvention::MicrosoftX64,
            ),
        ]
    }

    /// C-runtime memory and string signatures.
    #[must_use]
    fn crt_memory_string_signatures() -> Vec<FunctionSignature> {
        vec![
            // ── C runtime — memory ──────────────────────────────────────────
            // memcpy(dst, src, count) -> *mut void
            FunctionSignature::new(
                "memcpy",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("dst", ptr_void()),
                    ParamInfo::new("src", TypeFact::Pointer(Box::new(TypeFact::Unknown))),
                    ParamInfo::new("count", size_t_fact()),
                ],
                ptr_void(),
                CallingConvention::MicrosoftX64,
            ),
            // memset(dst, c, count) -> *mut void
            FunctionSignature::new(
                "memset",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("dst", ptr_void()),
                    ParamInfo::new("c", int_fact()),
                    ParamInfo::new("count", size_t_fact()),
                ],
                ptr_void(),
                CallingConvention::MicrosoftX64,
            ),
            // malloc(size) -> *mut void
            FunctionSignature::new(
                "malloc",
                "msvcrt.dll",
                vec![ParamInfo::new("size", size_t_fact())],
                ptr_void(),
                CallingConvention::MicrosoftX64,
            ),
            // free(ptr) -> void
            FunctionSignature::new(
                "free",
                "msvcrt.dll",
                vec![ParamInfo::new("ptr", ptr_void())],
                void_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // ── C runtime — strings ─────────────────────────────────────────
            // strlen(s) -> SIZE_T
            FunctionSignature::new(
                "strlen",
                "msvcrt.dll",
                vec![ParamInfo::new("s", ptr_char())],
                size_t_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // strcpy(dst, src) -> *mut char
            FunctionSignature::new(
                "strcpy",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("dst", ptr_mut_char()),
                    ParamInfo::new("src", ptr_char()),
                ],
                ptr_mut_char(),
                CallingConvention::MicrosoftX64,
            ),
            // strcmp(s1, s2) -> int
            FunctionSignature::new(
                "strcmp",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("s1", ptr_char()),
                    ParamInfo::new("s2", ptr_char()),
                ],
                int_fact(),
                CallingConvention::MicrosoftX64,
            ),
        ]
    }

    /// C-runtime I/O signatures.
    #[must_use]
    fn crt_io_signatures() -> Vec<FunctionSignature> {
        vec![
            // ── C runtime — I/O ─────────────────────────────────────────────
            // printf(fmt, ...) -> int
            FunctionSignature::new_variadic(
                "printf",
                "msvcrt.dll",
                vec![ParamInfo::new("fmt", ptr_char())],
                int_fact(),
                CallingConvention::Variadic,
            ),
            // fopen(filename, mode) -> *mut FILE
            FunctionSignature::new(
                "fopen",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("filename", ptr_char()),
                    ParamInfo::new("mode", ptr_char()),
                ],
                ptr_file(),
                CallingConvention::MicrosoftX64,
            ),
            // fread(buf, size, count, stream) -> SIZE_T
            FunctionSignature::new(
                "fread",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("buf", ptr_void()),
                    ParamInfo::new("size", size_t_fact()),
                    ParamInfo::new("count", size_t_fact()),
                    ParamInfo::new("stream", ptr_file()),
                ],
                size_t_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // fwrite(buf, size, count, stream) -> SIZE_T
            FunctionSignature::new(
                "fwrite",
                "msvcrt.dll",
                vec![
                    ParamInfo::new("buf", TypeFact::Pointer(Box::new(TypeFact::Unknown))),
                    ParamInfo::new("size", size_t_fact()),
                    ParamInfo::new("count", size_t_fact()),
                    ParamInfo::new("stream", ptr_file()),
                ],
                size_t_fact(),
                CallingConvention::MicrosoftX64,
            ),
            // fclose(stream) -> int
            FunctionSignature::new(
                "fclose",
                "msvcrt.dll",
                vec![ParamInfo::new("stream", ptr_file())],
                int_fact(),
                CallingConvention::MicrosoftX64,
            ),
        ]
    }
}

// ────────────────────────────────────────────────────────────────────────────
// LibraryTypeImporter — import-table driven propagation  (§6.6 level 7)
// ────────────────────────────────────────────────────────────────────────────

/// Imports type information from a known library signature and propagates it
/// to every call-site address that calls the function.
///
/// Workflow:
/// ```text
/// 1. Binary loader identifies imported symbol → (dll, name, call-site addresses).
/// 2. LibraryTypeImporter::from_import_name looks up the signature.
/// 3. LibraryTypeImporter::propagate_to_callers emits TypeFacts for each site.
/// 4. The TypeInferenceEngine absorbs those facts via HasType constraints.
/// ```
pub struct LibraryTypeImporter;

/// A single type-propagation event produced when a caller inherits type
/// information from a resolved library signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropagatedTypeFact {
    /// Virtual address of the call-site instruction.
    pub call_site: u64,
    /// Parameter index this fact applies to, or `None` for the return value.
    pub param_index: Option<usize>,
    /// The recovered type fact.
    pub fact: TypeFact,
    /// Source annotation: which function signature was the origin.
    pub source_function: String,
}

impl LibraryTypeImporter {
    /// Look up a function signature given its import-table name and DLL.
    ///
    /// Tries [`WinApiTypeDb`] first; returns `None` if the function is not in
    /// the built-in database.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustre_analysis_type::LibraryTypeImporter;
    ///
    /// let sig = LibraryTypeImporter::from_import_name("ReadFile", "kernel32.dll");
    /// assert!(sig.is_some());
    /// assert_eq!(sig.unwrap().arity(), 5);
    /// ```
    #[must_use]
    pub fn from_import_name(func_name: &str, dll: &str) -> Option<FunctionSignature> {
        // Direct database lookup (both by full name+dll and name-only fallback).
        if let Some(sig) = WinApiTypeDb::lookup(func_name, dll) {
            return Some(sig);
        }
        // Name-only fallback for cases where the DLL is not yet known.
        WinApiTypeDb::lookup_by_name(func_name)
    }

    /// Given a resolved signature and a list of call-site virtual addresses,
    /// emit a [`PropagatedTypeFact`] for every parameter and for the return
    /// value at every site.
    ///
    /// The resulting `Vec` is intended to be fed into
    /// [`TypeInferenceEngine::add_constraint`] as `HasType` constraints after
    /// the caller maps addresses to [`TypeVar`]s.
    ///
    /// # Arguments
    ///
    /// * `sig`     — The resolved function signature.
    /// * `callers` — Virtual addresses of all call instructions that target
    ///   this import.
    ///
    /// # Returns
    ///
    /// A flat `Vec` of [`PropagatedTypeFact`]s, one per (call-site × slot)
    /// pair.  For a function with `k` parameters called at `n` sites this
    /// produces `n * (k + 1)` entries (k params + 1 return value per site).
    #[must_use]
    pub fn propagate_to_callers(
        sig: &FunctionSignature,
        callers: &[u64],
    ) -> Vec<PropagatedTypeFact> {
        // Guard against overflow: callers.len() * (params + 1) can wrap on
        // 32-bit targets when both values are attacker-controlled (import table).
        // Fall back to an unpreallocated Vec rather than panicking or allocating
        // a gigantic buffer.
        let capacity = callers
            .len()
            .checked_mul(sig.params.len().saturating_add(1))
            .unwrap_or(0);
        let mut facts = Vec::with_capacity(capacity);

        for &call_site in callers {
            // Return-value fact.
            if sig.return_type.is_known() {
                facts.push(PropagatedTypeFact {
                    call_site,
                    param_index: None,
                    fact: sig.return_type.clone(),
                    source_function: sig.name.clone(),
                });
            }

            // Per-parameter facts.
            for (idx, param) in sig.params.iter().enumerate() {
                if param.ty.is_known() {
                    facts.push(PropagatedTypeFact {
                        call_site,
                        param_index: Some(idx),
                        fact: param.ty.clone(),
                        source_function: sig.name.clone(),
                    });
                }
            }
        }

        facts
    }

    /// Ingest a full import table (list of `(func_name, dll, call_sites)`) and
    /// return all propagated type facts in one call.
    ///
    /// Entries whose names are not in the database are silently skipped.
    #[must_use]
    pub fn propagate_import_table(imports: &[(&str, &str, Vec<u64>)]) -> Vec<PropagatedTypeFact> {
        let mut all = Vec::new();
        for (func_name, dll, call_sites) in imports {
            if let Some(sig) = Self::from_import_name(func_name, dll) {
                let mut facts = Self::propagate_to_callers(&sig, call_sites);
                all.append(&mut facts);
            }
        }
        all
    }

    /// Apply propagated facts to a [`TypeInferenceEngine`] given a mapping
    /// from call-site address to the variable names for its arguments and
    /// return value.
    ///
    /// `var_map` maps `(call_site, param_index_or_none)` to variable names
    /// that can be resolved via [`TypeInferenceEngine::var_for`].
    pub fn apply_to_engine(
        engine: &mut TypeInferenceEngine,
        facts: &[PropagatedTypeFact],
        var_map: &HashMap<(u64, Option<usize>), String>,
    ) {
        for fact in facts {
            let key = (fact.call_site, fact.param_index);
            if let Some(var_name) = var_map.get(&key) {
                let tv = engine.var_for(var_name);
                engine.add_constraint(TypeConstraint::HasType(tv, fact.fact.clone()));
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// InstructionRef — lightweight reference used by ArrayDetector
// ────────────────────────────────────────────────────────────────────────────

/// A lightweight, analysis-side view of one instruction, used by
/// [`ArrayDetector`].  The full IR is not required; only the fields that
/// reveal array-like access patterns are needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionRef {
    /// Virtual address of this instruction.
    pub address: u64,
    /// The instruction kind relevant to array detection.
    pub kind: InstrRefKind,
}

/// Instruction kinds that [`ArrayDetector`] understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstrRefKind {
    /// A memory load whose effective address is `base + index * scale + disp`.
    IndexedLoad {
        /// Base register / variable name.
        base: String,
        /// Index register / variable name (None if absent).
        index: Option<String>,
        /// Stride in bytes (element size).
        scale: usize,
        /// Constant displacement added to the base.
        displacement: i64,
        /// Destination variable name.
        dst: String,
    },
    /// A memory store whose effective address is `base + index * scale + disp`.
    IndexedStore {
        /// Base register / variable name.
        base: String,
        /// Index register / variable name (None if absent).
        index: Option<String>,
        /// Stride in bytes (element size).
        scale: usize,
        /// Constant displacement.
        displacement: i64,
        /// Source value variable name.
        src: String,
    },
    /// A simple add of a constant stride to a pointer register.  This is the
    /// loop-increment pattern: `ptr += stride`.
    PtrIncrement {
        /// Pointer variable being incremented.
        ptr: String,
        /// The constant added per iteration.
        stride: usize,
    },
    /// Comparison of an index variable against a bound.
    BoundCheck {
        /// Index variable name.
        index: String,
        /// Comparison bound (may be upper or lower).
        bound: i64,
    },
    /// Any other instruction kind — ignored by the array detector.
    Other,
}

// ────────────────────────────────────────────────────────────────────────────
// ArrayAccessPattern — result of ArrayDetector
// ────────────────────────────────────────────────────────────────────────────

/// Describes a single array access pattern recovered from a sequence of
/// instructions.
///
/// The pattern is identified by observing that the same base pointer is
/// accessed with multiple different index/displacement values, all with the
/// same element stride.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrayAccessPattern {
    /// Virtual address of the base pointer (the array start).
    pub base_ptr: u64,
    /// Stride between consecutive elements, in bytes.
    pub stride: usize,
    /// Smallest index value observed.
    pub min_index: i64,
    /// Largest index value observed.
    pub max_index: i64,
    /// Name of the base variable as seen in the instruction stream.
    pub base_var: String,
    /// Number of distinct accesses that contributed to this pattern.
    pub access_count: usize,
    /// `true` if any store was observed (i.e. array is written, not just read).
    pub has_write: bool,
}

impl ArrayAccessPattern {
    /// Inferred minimum number of elements in the array.
    ///
    /// Computed as `max_index + 1` (assuming 0-based indexing).  This is a
    /// lower bound; the actual allocation may be larger.
    #[must_use]
    pub fn min_element_count(&self) -> usize {
        usize::try_from(self.max_index).map_or(0, |i| i.saturating_add(1))
    }

    /// Inferred element type — a [`TypeFact::Sized`] with the stride as size.
    #[must_use]
    pub const fn element_type(&self) -> TypeFact {
        TypeFact::Sized(self.stride)
    }

    /// Produce an [`TypeFact::Array`] with the inferred element type and,
    /// if a definite upper bound was observable, a concrete length.
    ///
    /// `bound_hint` may optionally supply an externally-known length (e.g. from
    /// an adjacent `BoundCheck` instruction).
    #[must_use]
    pub fn to_array_type(&self, bound_hint: Option<usize>) -> TypeFact {
        let length = bound_hint.or_else(|| {
            usize::try_from(self.max_index)
                .ok()
                .map(|i| i.saturating_add(1))
        });
        TypeFact::Array {
            element: Box::new(self.element_type()),
            length,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ArrayDetector — heuristic array-access analysis
// ────────────────────────────────────────────────────────────────────────────

/// Analyses a flat instruction stream for array-access patterns.
///
/// The algorithm is intentionally conservative: it groups accesses by
/// `(base_var, stride)` and only emits an [`ArrayAccessPattern`] when at
/// least two distinct index values have been observed for the same group
/// (i.e. there is evidence of repeated access with a consistent stride).
///
/// This complements level-5 array inference (which works on a structured CFG)
/// by handling the common case of short, inlined loops that have been partially
/// or fully unrolled by the compiler.
pub struct ArrayDetector;

// Internal accumulator for a (base, stride) group.
#[derive(Debug, Default)]
struct AccessGroup {
    base_var: String,
    stride: usize,
    base_addr: u64,
    indices: Vec<i64>,
    access_count: usize,
    has_write: bool,
}

impl AccessGroup {
    fn record(&mut self, index: i64, is_write: bool, addr: u64) {
        if self.base_addr == 0 {
            self.base_addr = addr;
        }
        self.indices.push(index);
        self.access_count += 1;
        if is_write {
            self.has_write = true;
        }
    }

    fn to_pattern(&self) -> Option<ArrayAccessPattern> {
        // Need at least 2 distinct indices to be confident.
        let mut uniq = self.indices.clone();
        uniq.sort_unstable();
        uniq.dedup();
        if uniq.len() < 2 {
            return None;
        }
        let min_index = *uniq.first().unwrap();
        let max_index = *uniq.last().unwrap();
        Some(ArrayAccessPattern {
            base_ptr: self.base_addr,
            stride: self.stride,
            min_index,
            max_index,
            base_var: self.base_var.clone(),
            access_count: self.access_count,
            has_write: self.has_write,
        })
    }
}

impl ArrayDetector {
    /// Analyse `instrs` and return all detected array access patterns.
    ///
    /// Each entry in the returned `Vec` corresponds to a distinct
    /// `(base_variable, stride)` pair for which at least two different index
    /// values were observed.
    ///
    /// The detection logic:
    ///
    /// 1. `IndexedLoad` / `IndexedStore` instructions contribute directly:
    ///    the displacement is used as the index (in units of `scale` bytes).
    /// 2. `PtrIncrement` increments the tracked "current offset" for a base
    ///    pointer, allowing loop-body accesses without an explicit index
    ///    register to be attributed to the correct group.
    /// 3. `BoundCheck` instructions are noted but do not form groups
    ///    themselves; their bounds may be passed as hints to
    ///    [`ArrayAccessPattern::to_array_type`].
    ///
    /// Unknown instruction kinds are skipped.
    #[must_use]
    pub fn detect(instrs: &[InstructionRef]) -> Vec<ArrayAccessPattern> {
        // Map from (base_var, stride) -> accumulator.
        let mut groups: HashMap<(String, usize), AccessGroup> = HashMap::new();
        // Track current pointer offsets for PtrIncrement patterns.
        let mut ptr_offsets: HashMap<String, i64> = HashMap::new();

        for instr in instrs {
            match &instr.kind {
                InstrRefKind::IndexedLoad {
                    base,
                    index: _,
                    scale,
                    displacement,
                    ..
                } => {
                    let key = (base.clone(), *scale);
                    let g = groups.entry(key).or_insert_with(|| AccessGroup {
                        base_var: base.clone(),
                        stride: *scale,
                        ..Default::default()
                    });
                    // Normalise displacement to element-index units.
                    let idx = if *scale > 0 {
                        displacement / i64::try_from(*scale).unwrap_or(i64::MAX)
                    } else {
                        *displacement
                    };
                    g.record(idx, false, instr.address);
                }
                InstrRefKind::IndexedStore {
                    base,
                    index: _,
                    scale,
                    displacement,
                    ..
                } => {
                    let key = (base.clone(), *scale);
                    let g = groups.entry(key).or_insert_with(|| AccessGroup {
                        base_var: base.clone(),
                        stride: *scale,
                        ..Default::default()
                    });
                    let idx = if *scale > 0 {
                        displacement / i64::try_from(*scale).unwrap_or(i64::MAX)
                    } else {
                        *displacement
                    };
                    g.record(idx, true, instr.address);
                }
                InstrRefKind::PtrIncrement { ptr, stride } => {
                    let offset = ptr_offsets.entry(ptr.clone()).or_insert(0);
                    *offset += i64::try_from(*stride).unwrap_or(i64::MAX);
                    // Record the incremented offset as an access for this base.
                    let key = (ptr.clone(), *stride);
                    let g = groups.entry(key).or_insert_with(|| AccessGroup {
                        base_var: ptr.clone(),
                        stride: *stride,
                        ..Default::default()
                    });
                    g.record(*offset, false, instr.address);
                }
                InstrRefKind::BoundCheck { .. } | InstrRefKind::Other => {}
            }
        }

        // Materialise patterns from groups with sufficient evidence.
        // Sort so the output order (and any downstream "last fact wins"
        // collection keyed by base_var) is deterministic — `groups` is a
        // HashMap whose iteration order is randomized per-process.
        let mut patterns: Vec<ArrayAccessPattern> = groups
            .values()
            .filter_map(AccessGroup::to_pattern)
            .collect();
        patterns.sort_by(|a, b| {
            a.base_var
                .cmp(&b.base_var)
                .then(a.stride.cmp(&b.stride))
        });
        patterns
    }

    /// Convenience: detect patterns and immediately convert them to
    /// [`TypeFact::Array`] entries, keyed by base variable name.
    #[must_use]
    pub fn detect_as_facts(instrs: &[InstructionRef]) -> HashMap<String, TypeFact> {
        Self::detect(instrs)
            .into_iter()
            .map(|pat| {
                let tf = pat.to_array_type(None);
                (pat.base_var, tf)
            })
            .collect()
    }

    /// Detect patterns and feed the resulting array types into a
    /// [`TypeInferenceEngine`] as `HasType` constraints.
    pub fn apply_to_engine(engine: &mut TypeInferenceEngine, instrs: &[InstructionRef]) {
        for (var_name, fact) in Self::detect_as_facts(instrs) {
            let tv = engine.var_for(&var_name);
            engine.add_constraint(TypeConstraint::HasType(tv, fact));
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TypeRecoveryPass — AnalysisPass implementation
// ────────────────────────────────────────────────────────────────────────────

use anyhow::Context as _;
use rustre_analysis::{AnalysisConfig, AnalysisError, AnalysisKind, AnalysisPass, AnalysisResult};
use rustre_core::binary_view::BinaryView;

/// An [`AnalysisPass`] that runs type inference and propagation over all
/// functions discovered in the binary view.
///
/// For each function the pass collects type constraints from the instruction
/// stream, solves them via union-find unification, and propagates the resulting
/// environments across the call graph using [`TypePropagator`].
pub struct TypeRecoveryPass;

impl TypeRecoveryPass {
    /// Create a new `TypeRecoveryPass`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for TypeRecoveryPass {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TypeRecoveryPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeRecoveryPass").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for TypeRecoveryPass {
    fn name(&self) -> &'static str {
        "type_recovery"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::TypeRecovery
    }

    fn description(&self) -> &'static str {
        "Constraint-based type recovery and inter-procedural type propagation"
    }

    async fn run(
        &self,
        view: &BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        Self::run_inner(view)
            .map_err(|e| AnalysisError::Failed(format!("{e:#}")))
    }
}

impl TypeRecoveryPass {
    fn run_inner(view: &BinaryView) -> anyhow::Result<AnalysisResult> {
        use rustre_core::address::Address as CoreAddress;

        let start = std::time::Instant::now();

        // Snapshot the function table: (entry, name, exclusive end, calling convention).
        let funcs: Vec<(u64, String, Option<u64>, Option<String>)> = {
            let table = view.functions.read();
            let mut v: Vec<_> = table
                .iter_functions()
                .map(|f| {
                    (
                        f.address.as_u64(),
                        f.name.clone(),
                        f.end_address.map(|e| e.as_u64()),
                        f.calling_convention.clone(),
                    )
                })
                .collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v
        };
        let functions_found = funcs.len();

        let lib_db = interprocedural::LibrarySignatureDb::new();

        // ── 1. Interprocedural call graph (real edges from the xref index) ──
        let mut ipa_cg = interprocedural::CallGraph::new();
        let mut library_count = 0usize;
        for (addr, name, _, _) in &funcs {
            let lib_sig = lib_db.lookup(name);
            if lib_sig.is_some() {
                library_count += 1;
            }
            ipa_cg.add_function(interprocedural::FuncInfo {
                id: *addr,
                name: name.clone(),
                num_params: lib_sig.map_or(0, |s| s.param_types.len()),
                is_library: lib_sig.is_some(),
            });
        }

        // Map a call-site address back to its containing function entry.
        let starts: Vec<u64> = funcs.iter().map(|f| f.0).collect();
        let containing = |site: u64| -> Option<u64> {
            match starts.binary_search(&site) {
                Ok(i) => Some(starts[i]),
                Err(0) => None,
                Err(i) => {
                    let (fstart, _, fend, _) = &funcs[i - 1];
                    match fend {
                        Some(end) if site >= *end => None,
                        _ => Some(*fstart),
                    }
                }
            }
        };

        // (caller entry, callee entry, call-site address)
        let mut edges: Vec<(u64, u64, u64)> = Vec::new();
        {
            let xrefs = view.xrefs.read();
            for (addr, _, _, _) in &funcs {
                for site in xrefs.callers_of(CoreAddress::new(*addr)) {
                    if let Some(caller) = containing(site.as_u64()) {
                        edges.push((caller, *addr, site.as_u64()));
                    }
                }
            }
        }
        edges.sort_unstable();
        edges.dedup();

        for &(caller, callee, site) in &edges {
            ipa_cg.add_edge(interprocedural::CallEdge {
                caller,
                callee,
                call_site: site,
                arg_types: Vec::new(),
                return_use: interprocedural::ReturnUse::Discarded,
            });
        }

        // ── 2. Run interprocedural type analysis to convergence ──
        let mut ipa =
            interprocedural::IpaTypeAnalysis::new(interprocedural::IpaContext::new(ipa_cg));
        let ipa_result = ipa.run();
        let ipa_stats = interprocedural::IpaStats::compute(&ipa_result);
        let annotations = interprocedural::TypeAnnotationApplicator::new(&ipa_result)
            .collect_annotations();

        // ── 3. Var-level bridge: propagation::TypePropagator moves published
        //       library return types onto per-call-site variables ──
        let mut prop_cg = propagation::CallGraph::new();
        for (addr, name, _, _) in &funcs {
            if let Some(sig) = lib_db.lookup(name) {
                prop_cg.add_known_sig(
                    *addr,
                    propagation::FunctionSig {
                        name: name.clone(),
                        arg_types: sig
                            .param_types
                            .iter()
                            .map(interprocedural::IpaType::to_type_fact)
                            .collect(),
                        ret_type: sig.return_type.to_type_fact(),
                    },
                );
            }
        }

        // Per caller: synthesise the call-site view and run the solution
        // propagator; collect the return-value types it recovers.
        let mut call_ret_types: HashMap<u64, Vec<TypeFact>> = HashMap::new();
        for (addr, name, _, _) in &funcs {
            let my_edges: Vec<&(u64, u64, u64)> =
                edges.iter().filter(|e| e.0 == *addr).collect();
            if my_edges.is_empty() {
                continue;
            }
            let mut mf = propagation::MlilFunction::new(*addr, name.clone());
            for (i, &&(caller, callee, _site)) in my_edges.iter().enumerate() {
                mf.add_call_site(propagation::CallSite {
                    caller,
                    callee: constraints::Address(callee),
                    arg_vars: Vec::new(),
                    ret_var: Some(constraints::VarRef::new(
                        *addr,
                        u32::try_from(i).unwrap_or(u32::MAX),
                    )),
                });
            }
            let mut sp = propagation::TypeSolutionPropagator::new();
            let solution = constraints::TypeSolution::new();
            let store = constraints::TypeStore::new();
            let typed = sp.run(&mf, &prop_cg, &solution, &store);
            let mut rets: Vec<(constraints::VarRef, TypeFact)> = typed
                .into_iter()
                .filter(|(_, t)| t.is_known())
                .collect();
            rets.sort_by_key(|(v, _)| (v.function, v.index));
            let rets: Vec<TypeFact> = rets.into_iter().map(|(_, t)| t).collect();
            if !rets.is_empty() {
                call_ret_types.insert(*addr, rets);
            }
        }
        let call_vars_typed: usize = call_ret_types.values().map(Vec::len).sum();

        // ── 4. Env-level propagation across the call graph, seeded from the
        //       IPA summaries and the var-level bridge results ──
        let mut call_graph = CallGraph::new();
        for (addr, _, _, _) in &funcs {
            call_graph.add_function(format!("{addr:#x}"));
        }
        for &(caller, callee, _) in &edges {
            call_graph.add_call(&format!("{caller:#x}"), &format!("{callee:#x}"));
        }

        let mut propagator = TypePropagator::new(call_graph);
        for (addr, _, _, _) in &funcs {
            let mut env = TypeEnvironment::new();
            if let Some(summary) = ipa_result.summaries.get(addr) {
                env.return_type = summary.return_type.to_type_fact();
                env.arg_types = summary
                    .param_types
                    .iter()
                    .map(interprocedural::IpaType::to_type_fact)
                    .collect();
            }
            if let Some(rets) = call_ret_types.get(addr) {
                for (i, t) in rets.iter().enumerate() {
                    env.set(format!("call_ret_{i}"), t.clone());
                }
            }
            propagator.set_initial_env(&format!("{addr:#x}"), env);
        }
        propagator.propagate();

        let resolved_envs = funcs
            .iter()
            .filter(|(addr, _, _, _)| {
                propagator.env_for(&format!("{addr:#x}")).is_some_and(|e| {
                    e.return_type.is_known()
                        || e.arg_types.iter().any(TypeFact::is_known)
                        || e.types.values().any(TypeFact::is_known)
                })
            })
            .count();

        // ── 5. Signatures: published library prototypes win over inference ──
        let mut published_sigs = 0usize;
        for (addr, name, _, cc) in &funcs {
            let env = propagator
                .env_for(&format!("{addr:#x}"))
                .unwrap_or_default();
            let sig =
                infer_function_signature_named(*addr, Some(name), cc.as_deref(), &env, &lib_db);
            // A published prototype always yields "high" confidence and the
            // published arity — count only signatures that actually came from
            // the library database.
            if lib_db.contains(name)
                && sig.confidence == "high"
                && sig.args.len() == lib_db.lookup(name).map_or(0, |s| s.param_types.len())
            {
                published_sigs += 1;
            }
        }

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // Lightweight constraint-solve probe to validate the engine pipeline.
        let mut probe = TypeInferenceEngine::new();
        probe
            .solve()
            .with_context(|| "type inference engine failed during TypeRecoveryPass probe")?;

        let warnings = vec![
            format!(
                "ipa: {} functions ({library_count} library-annotated), {} call edges, {} iterations, converged={}",
                ipa_stats.total_functions,
                edges.len(),
                ipa_result.iterations,
                ipa_result.converged,
            ),
            format!(
                "ipa: {}/{} functions with known return type, {} annotations collected",
                ipa_stats.functions_with_known_return,
                ipa_stats.total_functions,
                annotations.len(),
            ),
            format!(
                "propagation: {call_vars_typed} call-site vars typed from library prototypes, \
                 {resolved_envs} environments resolved, {published_sigs} published signatures applied",
            ),
        ];

        Ok(AnalysisResult {
            kind: AnalysisKind::TypeRecovery,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms,
            warnings,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// InferredSignature — combined calling-convention + type result
// ────────────────────────────────────────────────────────────────────────────

/// One recovered argument within an [`InferredSignature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredArg {
    /// Positional name (`arg0`, `arg1`, …) assigned during inference.
    pub name: String,
    /// Human-readable type string derived from the recovered [`TypeFact`].
    pub ty: String,
}

/// The fully inferred signature for a single function.
///
/// Confidence rules:
/// * `"high"`   — calling convention is known **and** every argument has a
///   concrete (non-`Unknown`) type.
/// * `"medium"` — calling convention is known, but at least one argument type
///   is `Unknown`.
/// * `"low"`    — calling convention is unknown, regardless of argument types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredSignature {
    /// Human-readable calling-convention name (e.g. `"fastcall (x86)"`), or
    /// `"unknown"` when no convention was identified.
    pub calling_convention: String,
    /// Human-readable return type (see [`TypeFact::display_name`]).
    pub return_type: String,
    /// Recovered argument list in call order.
    pub args: Vec<InferredArg>,
    /// Confidence level: `"high"`, `"medium"`, or `"low"`.
    pub confidence: String,
}

impl TypeFact {
    /// Return a compact, human-readable name for this type.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::Unknown => "?".to_string(),
            Self::Bool => "bool".to_string(),
            Self::Char => "char".to_string(),
            Self::Sized(n) => format!("sized({n})"),
            Self::SignedInt(n) => format!("i{}", n * 8),
            Self::UnsignedInt(n) => format!("u{}", n * 8),
            Self::Float(n) => format!("f{}", n * 8),
            Self::Pointer(inner) => format!("*{}", inner.display_name()),
            Self::Array { element, length: Some(n) } => {
                format!("[{}; {n}]", element.display_name())
            }
            Self::Array { element, length: None } => format!("[{}]", element.display_name()),
            Self::Struct { fields } => {
                let mut s = "struct{".to_string();
                for (i, (off, ty)) in fields.iter().enumerate() {
                    if i > 0 { s.push_str(", "); }
                    s.push('+');
                    s.push_str(&off.to_string());
                    s.push_str(": ");
                    s.push_str(&ty.display_name());
                }
                s.push('}');
                s
            }
        }
    }
}

/// Infer the complete function signature for the function at `addr`.
///
/// # Parameters
///
/// * `addr`        — Virtual address of the function (used only for future
///   look-up; not interpreted here).
/// * `calling_conv` — The calling-convention name as returned by
///   [`CallingConventionDetector`] / [`CallingConventionPattern::name`], or
///   `None` when no convention could be detected.
/// * `env`         — The [`TypeEnvironment`] produced by the type-inference
///   engine for this function.  `env.arg_types` provides per-argument types
///   and `env.return_type` provides the return type.
///
/// # Returns
///
/// An [`InferredSignature`] with confidence set according to the rules
/// documented on that struct.
#[must_use]
pub fn infer_function_signature(
    _addr: u64,
    calling_conv: Option<&str>,
    env: &TypeEnvironment,
) -> InferredSignature {
    let cc_name = calling_conv.map_or_else(|| "unknown".to_string(), std::string::ToString::to_string);

    let return_type = env.return_type.display_name();

    let args: Vec<InferredArg> = env
        .arg_types
        .iter()
        .enumerate()
        .map(|(i, ty)| InferredArg {
            name: format!("arg{i}"),
            ty: ty.display_name(),
        })
        .collect();

    let cc_known = calling_conv.is_some();
    let all_args_typed = args.iter().all(|a| a.ty != "?");

    let confidence = if cc_known && all_args_typed {
        "high"
    } else if cc_known {
        "medium"
    } else {
        "low"
    }
    .to_string();

    InferredSignature {
        calling_convention: cc_name,
        return_type,
        args,
        confidence,
    }
}

/// Like [`infer_function_signature`], but consults a
/// [`interprocedural::LibrarySignatureDb`] first when the function's `name`
/// is available.
///
/// When the name matches a published library prototype, the published
/// signature is authoritative: its arity and concrete types always win over
/// the inferred environment (inference may only fill in parameters the
/// prototype leaves opaque, never change the count or override a concrete
/// published type). Confidence is `"high"` for a published prototype.
///
/// When the name is absent or unknown to the database, this delegates to
/// [`infer_function_signature`] unchanged.
#[must_use]
pub fn infer_function_signature_named(
    addr: u64,
    name: Option<&str>,
    calling_conv: Option<&str>,
    env: &TypeEnvironment,
    lib_db: &interprocedural::LibrarySignatureDb,
) -> InferredSignature {
    let Some(sig) = name.and_then(|n| lib_db.lookup(n)) else {
        return infer_function_signature(addr, calling_conv, env);
    };

    let mut args: Vec<InferredArg> = sig
        .param_types
        .iter()
        .enumerate()
        .map(|(i, ty)| InferredArg {
            name: format!("arg{i}"),
            ty: ty.to_type_fact().display_name(),
        })
        .collect();
    // Inference may refine parameters the prototype leaves opaque, but the
    // published arity and concrete published types always win.
    for (i, arg) in args.iter_mut().enumerate() {
        if arg.ty == "?"
            && let Some(t) = env.arg_types.get(i)
            && t.is_known()
        {
            arg.ty = t.display_name();
        }
    }

    let return_type = match &sig.return_type {
        interprocedural::IpaType::Void => "void".to_string(),
        t => t.to_type_fact().display_name(),
    };

    InferredSignature {
        calling_convention: calling_conv
            .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string),
        return_type,
        args,
        confidence: "high".to_string(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_fact_display() {
        assert_eq!(TypeFact::SignedInt(4).to_string(), "i32");
        assert_eq!(TypeFact::UnsignedInt(8).to_string(), "u64");
        assert_eq!(TypeFact::Float(4).to_string(), "f32");
        assert_eq!(TypeFact::Bool.to_string(), "bool");
        assert_eq!(TypeFact::Unknown.to_string(), "?");
    }

    #[test]
    fn test_type_fact_byte_size() {
        assert_eq!(TypeFact::SignedInt(4).byte_size(), Some(4));
        assert_eq!(TypeFact::Bool.byte_size(), Some(1));
        assert_eq!(TypeFact::Unknown.byte_size(), None);
    }

    #[test]
    fn test_type_fact_join_same() {
        assert_eq!(
            TypeFact::SignedInt(4).join(&TypeFact::SignedInt(4)),
            TypeFact::SignedInt(4)
        );
    }

    #[test]
    fn test_type_fact_join_conflict_widens() {
        assert_eq!(
            TypeFact::SignedInt(4).join(&TypeFact::UnsignedInt(4)),
            TypeFact::Unknown
        );
    }

    #[test]
    fn test_type_fact_join_unknown_identity() {
        assert_eq!(
            TypeFact::Unknown.join(&TypeFact::Float(8)),
            TypeFact::Float(8)
        );
    }

    #[test]
    fn test_type_fact_pointer_join() {
        let p1 = TypeFact::Pointer(Box::new(TypeFact::SignedInt(4)));
        let p2 = TypeFact::Pointer(Box::new(TypeFact::Unknown));
        let joined = p1.join(&p2);
        assert!(matches!(joined, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_type_fact_is_known() {
        assert!(!TypeFact::Unknown.is_known());
        assert!(TypeFact::Bool.is_known());
    }

    #[test]
    fn test_engine_has_type_constraint() {
        let mut engine = TypeInferenceEngine::new();
        let v = engine.var_for("x");
        engine.add_constraint(TypeConstraint::HasType(v, TypeFact::SignedInt(4)));
        let assignment = engine.solve().unwrap();
        assert_eq!(
            engine.type_of("x", &assignment).unwrap(),
            TypeFact::SignedInt(4)
        );
    }

    #[test]
    fn test_engine_equal_propagates() {
        let mut engine = TypeInferenceEngine::new();
        let x = engine.var_for("x");
        let y = engine.var_for("y");
        engine.add_constraint(TypeConstraint::HasType(x, TypeFact::UnsignedInt(8)));
        engine.add_constraint(TypeConstraint::Equal(x, y));
        let assignment = engine.solve().unwrap();
        assert_eq!(
            engine.type_of("y", &assignment).unwrap(),
            TypeFact::UnsignedInt(8)
        );
    }

    #[test]
    fn test_engine_bool_from_condition() {
        let mut engine = TypeInferenceEngine::new();
        let c = engine.var_for("cond");
        engine.add_constraint(TypeConstraint::IsCondition(c));
        let assignment = engine.solve().unwrap();
        assert_eq!(engine.type_of("cond", &assignment).unwrap(), TypeFact::Bool);
    }

    #[test]
    fn test_engine_deref_constraint() {
        let mut engine = TypeInferenceEngine::new();
        let ptr = engine.var_for("p");
        let pointee = engine.var_for("val");
        engine.add_constraint(TypeConstraint::HasType(pointee, TypeFact::SignedInt(4)));
        engine.add_constraint(TypeConstraint::Deref { ptr, pointee });
        let assignment = engine.solve().unwrap();
        let ptr_type = engine.type_of("p", &assignment).unwrap();
        assert!(matches!(ptr_type, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_engine_unknown_variable_error() {
        let engine = TypeInferenceEngine::new();
        let assignment = HashMap::new();
        let err = engine.type_of("not_here", &assignment);
        assert!(matches!(err, Err(TypeError::UnknownVariable(_))));
    }

    #[test]
    fn test_engine_all_types_iteration() {
        let mut engine = TypeInferenceEngine::new();
        let a = engine.var_for("a");
        let b = engine.var_for("b");
        engine.add_constraint(TypeConstraint::HasType(a, TypeFact::Float(4)));
        engine.add_constraint(TypeConstraint::HasType(b, TypeFact::Bool));
        let assignment = engine.solve().unwrap();
        let collected: HashMap<_, _> = engine.all_types(&assignment).collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_collect_constraints_const() {
        let mut engine = TypeInferenceEngine::new();
        let instrs = vec![TypedInstr {
            kind: InstrKind::Const {
                dst: "x".into(),
                bytes: 4,
                signed: true,
            },
        }];
        collect_constraints(&mut engine, &instrs);
        let assignment = engine.solve().unwrap();
        assert_eq!(
            engine.type_of("x", &assignment).unwrap(),
            TypeFact::SignedInt(4)
        );
    }

    #[test]
    fn test_collect_constraints_assign_propagates() {
        let mut engine = TypeInferenceEngine::new();
        let instrs = vec![
            TypedInstr {
                kind: InstrKind::Const {
                    dst: "x".into(),
                    bytes: 8,
                    signed: false,
                },
            },
            TypedInstr {
                kind: InstrKind::Assign {
                    dst: "y".into(),
                    src: "x".into(),
                },
            },
        ];
        collect_constraints(&mut engine, &instrs);
        let assignment = engine.solve().unwrap();
        assert_eq!(
            engine.type_of("y", &assignment).unwrap(),
            TypeFact::UnsignedInt(8)
        );
    }

    #[test]
    fn test_collect_constraints_branch_bool() {
        let mut engine = TypeInferenceEngine::new();
        let instrs = vec![TypedInstr {
            kind: InstrKind::Branch {
                cond: "flag".into(),
            },
        }];
        collect_constraints(&mut engine, &instrs);
        let assignment = engine.solve().unwrap();
        assert_eq!(engine.type_of("flag", &assignment).unwrap(), TypeFact::Bool);
    }

    #[test]
    fn test_collect_constraints_add_unifies() {
        let mut engine = TypeInferenceEngine::new();
        let instrs = vec![
            TypedInstr {
                kind: InstrKind::Const {
                    dst: "a".into(),
                    bytes: 4,
                    signed: true,
                },
            },
            TypedInstr {
                kind: InstrKind::Add {
                    dst: "c".into(),
                    lhs: "a".into(),
                    rhs: "b".into(),
                },
            },
        ];
        collect_constraints(&mut engine, &instrs);
        let assignment = engine.solve().unwrap();
        assert_eq!(
            engine.type_of("c", &assignment).unwrap(),
            TypeFact::SignedInt(4)
        );
    }

    #[test]
    fn test_type_env_set_get() {
        let mut env = TypeEnvironment::new();
        env.set("x", TypeFact::SignedInt(4));
        assert_eq!(env.get("x"), &TypeFact::SignedInt(4));
        assert_eq!(env.get("missing"), &TypeFact::Unknown);
    }

    #[test]
    fn test_type_env_merge_widens_on_conflict() {
        let mut a = TypeEnvironment::new();
        a.set("x", TypeFact::SignedInt(4));
        let mut b = TypeEnvironment::new();
        b.set("x", TypeFact::UnsignedInt(4));
        a.merge(&b);
        assert_eq!(a.get("x"), &TypeFact::Unknown);
    }

    #[test]
    fn test_type_env_merge_agrees() {
        let mut a = TypeEnvironment::new();
        a.set("x", TypeFact::Float(8));
        let mut b = TypeEnvironment::new();
        b.set("x", TypeFact::Float(8));
        a.merge(&b);
        assert_eq!(a.get("x"), &TypeFact::Float(8));
    }

    #[test]
    fn test_struct_recovery_basic() {
        let accesses = vec![
            FieldAccess {
                base: "p".into(),
                offset: 0,
                access_size: 4,
            },
            FieldAccess {
                base: "p".into(),
                offset: 4,
                access_size: 8,
            },
        ];
        let result = StructRecovery::recover(&accesses);
        match result.get("p").unwrap() {
            TypeFact::Struct { fields } => {
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0], (0, TypeFact::Sized(4)));
                assert_eq!(fields[1], (4, TypeFact::Sized(8)));
            }
            _ => panic!("expected Struct"),
        }
    }

    #[test]
    fn test_struct_recovery_dedup() {
        let accesses = vec![
            FieldAccess {
                base: "q".into(),
                offset: 0,
                access_size: 4,
            },
            FieldAccess {
                base: "q".into(),
                offset: 0,
                access_size: 4,
            },
        ];
        let result = StructRecovery::recover(&accesses);
        match result.get("q").unwrap() {
            TypeFact::Struct { fields } => assert_eq!(fields.len(), 1),
            _ => panic!("expected Struct"),
        }
    }

    #[test]
    fn test_propagator_propagates_return_type() {
        let mut cg = CallGraph::new();
        cg.add_function("main");
        cg.add_function("helper");
        cg.add_call("main", "helper");

        let mut helper_env = TypeEnvironment::new();
        helper_env.return_type = TypeFact::SignedInt(4);
        let main_env = TypeEnvironment::new();

        let mut prop = TypePropagator::new(cg);
        prop.set_initial_env("helper", helper_env);
        prop.set_initial_env("main", main_env);
        prop.propagate();

        let main_result = prop.env_for("main").unwrap();
        assert_eq!(main_result.return_type, TypeFact::SignedInt(4));
    }

    #[test]
    fn test_call_graph_topological_order() {
        let mut cg = CallGraph::new();
        cg.add_function("a");
        cg.add_function("b");
        cg.add_function("c");
        cg.add_call("a", "b");
        cg.add_call("b", "c");
        let order = cg.topological_order();
        let pos_a = order.iter().position(|s| s == "a").unwrap();
        let pos_b = order.iter().position(|s| s == "b").unwrap();
        let pos_c = order.iter().position(|s| s == "c").unwrap();
        assert!(pos_c < pos_b);
        assert!(pos_b < pos_a);
    }

    // ── Level 7: WinApiTypeDb ────────────────────────────────────────────────

    #[test]
    fn test_winapi_db_all_signatures_count() {
        let sigs = WinApiTypeDb::all_signatures();
        assert_eq!(sigs.len(), 25, "expected exactly 25 built-in signatures");
    }

    #[test]
    fn test_winapi_db_lookup_createfile() {
        let sig = WinApiTypeDb::lookup("CreateFileA", "kernel32.dll");
        assert!(sig.is_some(), "CreateFileA must be in the database");
        let sig = sig.unwrap();
        assert_eq!(sig.arity(), 7);
        assert_eq!(sig.return_type, handle_fact());
    }

    #[test]
    fn test_winapi_db_lookup_case_insensitive() {
        let sig = WinApiTypeDb::lookup("createfilea", "KERNEL32.DLL");
        assert!(sig.is_some(), "lookup must be case-insensitive");
    }

    #[test]
    fn test_winapi_db_lookup_readfile_params() {
        let sig = WinApiTypeDb::lookup("ReadFile", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 5);
        // hFile is a HANDLE (8-byte unsigned)
        assert_eq!(sig.param_type(0), Some(&handle_fact()));
        // lpBuffer is a void pointer
        assert_eq!(sig.param_type(1), Some(&ptr_void()));
    }

    #[test]
    fn test_winapi_db_lookup_writefile_returns_bool() {
        let sig = WinApiTypeDb::lookup("WriteFile", "kernel32.dll").unwrap();
        assert_eq!(sig.return_type, bool_ret());
    }

    #[test]
    fn test_winapi_db_lookup_virtualalloc_returns_ptr() {
        let sig = WinApiTypeDb::lookup("VirtualAlloc", "kernel32.dll").unwrap();
        assert!(matches!(sig.return_type, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_winapi_db_lookup_virtualfree_params() {
        let sig = WinApiTypeDb::lookup("VirtualFree", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 3);
        assert_eq!(sig.param_type(1), Some(&size_t_fact()));
    }

    #[test]
    fn test_winapi_db_lookup_virtualprotect_params() {
        let sig = WinApiTypeDb::lookup("VirtualProtect", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 4);
        // lpOldProtect is *mut DWORD
        assert_eq!(sig.param_type(3), Some(&ptr_u32()));
    }

    #[test]
    fn test_winapi_db_lookup_createthread_params() {
        let sig = WinApiTypeDb::lookup("CreateThread", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 6);
        assert_eq!(sig.return_type, handle_fact());
    }

    #[test]
    fn test_winapi_db_lookup_waitforsingleobject() {
        let sig = WinApiTypeDb::lookup("WaitForSingleObject", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 2);
        assert_eq!(sig.return_type, u32_fact());
    }

    #[test]
    fn test_winapi_db_lookup_closehandle() {
        let sig = WinApiTypeDb::lookup("CloseHandle", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 1);
        assert_eq!(sig.param_type(0), Some(&handle_fact()));
    }

    #[test]
    fn test_winapi_db_lookup_getprocaddress() {
        let sig = WinApiTypeDb::lookup("GetProcAddress", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 2);
        assert!(matches!(sig.return_type, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_winapi_db_lookup_loadlibrarya() {
        let sig = WinApiTypeDb::lookup("LoadLibraryA", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 1);
        assert_eq!(sig.param_type(0), Some(&ptr_char()));
    }

    #[test]
    fn test_winapi_db_lookup_heapalloc() {
        let sig = WinApiTypeDb::lookup("HeapAlloc", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 3);
        assert!(matches!(sig.return_type, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_winapi_db_lookup_heapfree() {
        let sig = WinApiTypeDb::lookup("HeapFree", "kernel32.dll").unwrap();
        assert_eq!(sig.arity(), 3);
        assert_eq!(sig.return_type, bool_ret());
    }

    #[test]
    fn test_winapi_db_lookup_memcpy() {
        let sig = WinApiTypeDb::lookup("memcpy", "msvcrt.dll").unwrap();
        assert_eq!(sig.arity(), 3);
        assert_eq!(sig.param_type(2), Some(&size_t_fact()));
    }

    #[test]
    fn test_winapi_db_lookup_memset() {
        let sig = WinApiTypeDb::lookup("memset", "msvcrt.dll").unwrap();
        assert_eq!(sig.param_type(1), Some(&int_fact()));
    }

    #[test]
    fn test_winapi_db_lookup_malloc_free() {
        let malloc = WinApiTypeDb::lookup("malloc", "msvcrt.dll").unwrap();
        assert_eq!(malloc.arity(), 1);
        let free = WinApiTypeDb::lookup("free", "msvcrt.dll").unwrap();
        assert_eq!(free.arity(), 1);
        assert_eq!(free.return_type, void_fact());
    }

    #[test]
    fn test_winapi_db_lookup_strlen() {
        let sig = WinApiTypeDb::lookup("strlen", "msvcrt.dll").unwrap();
        assert_eq!(sig.return_type, size_t_fact());
    }

    #[test]
    fn test_winapi_db_lookup_strcpy_strcmp() {
        let strcpy = WinApiTypeDb::lookup("strcpy", "msvcrt.dll").unwrap();
        assert_eq!(strcpy.arity(), 2);
        let strcmp = WinApiTypeDb::lookup("strcmp", "msvcrt.dll").unwrap();
        assert_eq!(strcmp.return_type, int_fact());
    }

    #[test]
    fn test_winapi_db_lookup_printf_variadic() {
        let sig = WinApiTypeDb::lookup("printf", "msvcrt.dll").unwrap();
        assert!(sig.is_variadic);
        assert_eq!(sig.calling_convention, CallingConvention::Variadic);
    }

    #[test]
    fn test_winapi_db_lookup_fopen() {
        let sig = WinApiTypeDb::lookup("fopen", "msvcrt.dll").unwrap();
        assert_eq!(sig.arity(), 2);
        assert!(matches!(sig.return_type, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_winapi_db_lookup_fread_fwrite() {
        let fread = WinApiTypeDb::lookup("fread", "msvcrt.dll").unwrap();
        assert_eq!(fread.arity(), 4);
        let fwrite = WinApiTypeDb::lookup("fwrite", "msvcrt.dll").unwrap();
        assert_eq!(fwrite.arity(), 4);
    }

    #[test]
    fn test_winapi_db_lookup_fclose() {
        let sig = WinApiTypeDb::lookup("fclose", "msvcrt.dll").unwrap();
        assert_eq!(sig.return_type, int_fact());
    }

    #[test]
    fn test_winapi_db_lookup_unknown_returns_none() {
        assert!(WinApiTypeDb::lookup("ExoticApi", "exotic.dll").is_none());
    }

    #[test]
    fn test_winapi_db_lookup_by_name_only() {
        let sig = WinApiTypeDb::lookup_by_name("CloseHandle");
        assert!(sig.is_some());
    }

    // ── Level 7: LibraryTypeImporter ─────────────────────────────────────────

    #[test]
    fn test_library_importer_from_import_name_found() {
        let sig = LibraryTypeImporter::from_import_name("ReadFile", "kernel32.dll");
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().name, "ReadFile");
    }

    #[test]
    fn test_library_importer_from_import_name_not_found() {
        let sig = LibraryTypeImporter::from_import_name("UnknownFunc", "unknown.dll");
        assert!(sig.is_none());
    }

    #[test]
    fn test_library_importer_propagate_to_callers_basic() {
        let sig = WinApiTypeDb::lookup("CloseHandle", "kernel32.dll").unwrap();
        let callers = vec![0x1000_u64, 0x2000_u64];
        let facts = LibraryTypeImporter::propagate_to_callers(&sig, &callers);
        // 1 param + 1 return = 2 facts × 2 call sites = 4
        assert_eq!(facts.len(), 4);
    }

    #[test]
    fn test_library_importer_propagate_return_value_present() {
        let sig = WinApiTypeDb::lookup("malloc", "msvcrt.dll").unwrap();
        let callers = vec![0xDEAD_u64];
        let facts = LibraryTypeImporter::propagate_to_callers(&sig, &callers);
        let ret_facts: Vec<_> = facts.iter().filter(|f| f.param_index.is_none()).collect();
        assert_eq!(ret_facts.len(), 1);
        assert!(matches!(ret_facts[0].fact, TypeFact::Pointer(_)));
    }

    #[test]
    fn test_library_importer_propagate_param_indices() {
        let sig = WinApiTypeDb::lookup("memcpy", "msvcrt.dll").unwrap();
        let callers = vec![0xBEEF_u64];
        let facts = LibraryTypeImporter::propagate_to_callers(&sig, &callers);
        let param_indices: HashSet<usize> = facts.iter().filter_map(|f| f.param_index).collect();
        assert!(param_indices.contains(&0));
        assert!(param_indices.contains(&1));
        assert!(param_indices.contains(&2));
    }

    #[test]
    fn test_library_importer_propagate_empty_callers() {
        let sig = WinApiTypeDb::lookup("strlen", "msvcrt.dll").unwrap();
        let facts = LibraryTypeImporter::propagate_to_callers(&sig, &[]);
        assert!(facts.is_empty());
    }

    #[test]
    fn test_library_importer_apply_to_engine() {
        let sig = WinApiTypeDb::lookup("CloseHandle", "kernel32.dll").unwrap();
        let callers = vec![0x4000_u64];
        let facts = LibraryTypeImporter::propagate_to_callers(&sig, &callers);

        let mut var_map: HashMap<(u64, Option<usize>), String> = HashMap::new();
        var_map.insert((0x4000, Some(0)), "arg0".to_string());
        var_map.insert((0x4000, None), "ret_val".to_string());

        let mut engine = TypeInferenceEngine::new();
        LibraryTypeImporter::apply_to_engine(&mut engine, &facts, &var_map);

        let assignment = engine.solve().unwrap();
        // arg0 should be a HANDLE (8-byte unsigned)
        assert_eq!(engine.type_of("arg0", &assignment).unwrap(), handle_fact());
        // ret_val should be BOOL (4-byte signed)
        assert_eq!(engine.type_of("ret_val", &assignment).unwrap(), bool_ret());
    }

    #[test]
    fn test_library_importer_import_table() {
        let imports = vec![
            ("strlen", "msvcrt.dll", vec![0x100_u64, 0x200_u64]),
            ("CloseHandle", "kernel32.dll", vec![0x300_u64]),
        ];
        let facts = LibraryTypeImporter::propagate_import_table(&imports);
        // strlen: 1 param + 1 return × 2 sites = 4
        // CloseHandle: 1 param + 1 return × 1 site = 2
        assert_eq!(facts.len(), 6);
    }

    // ── Level 7: ArrayDetector ───────────────────────────────────────────────

    #[test]
    fn test_array_detector_indexed_loads() {
        let instrs = vec![
            InstructionRef {
                address: 0x1000,
                kind: InstrRefKind::IndexedLoad {
                    base: "arr".into(),
                    index: None,
                    scale: 4,
                    displacement: 0,
                    dst: "v0".into(),
                },
            },
            InstructionRef {
                address: 0x1004,
                kind: InstrRefKind::IndexedLoad {
                    base: "arr".into(),
                    index: None,
                    scale: 4,
                    displacement: 4,
                    dst: "v1".into(),
                },
            },
            InstructionRef {
                address: 0x1008,
                kind: InstrRefKind::IndexedLoad {
                    base: "arr".into(),
                    index: None,
                    scale: 4,
                    displacement: 8,
                    dst: "v2".into(),
                },
            },
        ];
        let patterns = ArrayDetector::detect(&instrs);
        assert_eq!(patterns.len(), 1);
        let pat = &patterns[0];
        assert_eq!(pat.base_var, "arr");
        assert_eq!(pat.stride, 4);
        assert_eq!(pat.min_index, 0);
        assert_eq!(pat.max_index, 2);
        assert_eq!(pat.access_count, 3);
        assert!(!pat.has_write);
    }

    #[test]
    fn test_array_detector_indexed_stores() {
        let instrs = vec![
            InstructionRef {
                address: 0x2000,
                kind: InstrRefKind::IndexedStore {
                    base: "buf".into(),
                    index: None,
                    scale: 1,
                    displacement: 0,
                    src: "c0".into(),
                },
            },
            InstructionRef {
                address: 0x2001,
                kind: InstrRefKind::IndexedStore {
                    base: "buf".into(),
                    index: None,
                    scale: 1,
                    displacement: 1,
                    src: "c1".into(),
                },
            },
        ];
        let patterns = ArrayDetector::detect(&instrs);
        assert_eq!(patterns.len(), 1);
        assert!(patterns[0].has_write);
        assert_eq!(patterns[0].stride, 1);
    }

    #[test]
    fn test_array_detector_ptr_increment() {
        let instrs = vec![
            InstructionRef {
                address: 0x3000,
                kind: InstrRefKind::PtrIncrement {
                    ptr: "p".into(),
                    stride: 8,
                },
            },
            InstructionRef {
                address: 0x3008,
                kind: InstrRefKind::PtrIncrement {
                    ptr: "p".into(),
                    stride: 8,
                },
            },
            InstructionRef {
                address: 0x3010,
                kind: InstrRefKind::PtrIncrement {
                    ptr: "p".into(),
                    stride: 8,
                },
            },
        ];
        let patterns = ArrayDetector::detect(&instrs);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].stride, 8);
    }

    #[test]
    fn test_array_detector_single_access_no_pattern() {
        // Only one access — not enough evidence for an array.
        let instrs = vec![InstructionRef {
            address: 0x4000,
            kind: InstrRefKind::IndexedLoad {
                base: "x".into(),
                index: None,
                scale: 4,
                displacement: 0,
                dst: "v".into(),
            },
        }];
        let patterns = ArrayDetector::detect(&instrs);
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_array_detector_min_element_count() {
        let pat = ArrayAccessPattern {
            base_ptr: 0x5000,
            stride: 4,
            min_index: 0,
            max_index: 9,
            base_var: "arr".into(),
            access_count: 10,
            has_write: false,
        };
        assert_eq!(pat.min_element_count(), 10);
    }

    #[test]
    fn test_array_detector_to_array_type_with_bound() {
        let pat = ArrayAccessPattern {
            base_ptr: 0x6000,
            stride: 8,
            min_index: 0,
            max_index: 3,
            base_var: "tbl".into(),
            access_count: 4,
            has_write: false,
        };
        let tf = pat.to_array_type(Some(16));
        match tf {
            TypeFact::Array {
                element,
                length: Some(16),
            } => {
                assert_eq!(*element, TypeFact::Sized(8));
            }
            _ => panic!("expected Array with length 16, got {tf:?}"),
        }
    }

    #[test]
    fn test_array_detector_to_array_type_inferred_length() {
        let pat = ArrayAccessPattern {
            base_ptr: 0x7000,
            stride: 2,
            min_index: 0,
            max_index: 4,
            base_var: "words".into(),
            access_count: 5,
            has_write: true,
        };
        let tf = pat.to_array_type(None);
        match tf {
            TypeFact::Array {
                element,
                length: Some(5),
            } => {
                assert_eq!(*element, TypeFact::Sized(2));
            }
            _ => panic!("expected Array{{Sized(2); 5}}, got {tf:?}"),
        }
    }

    #[test]
    fn test_array_detector_detect_as_facts() {
        let instrs = vec![
            InstructionRef {
                address: 0x8000,
                kind: InstrRefKind::IndexedLoad {
                    base: "data".into(),
                    index: None,
                    scale: 4,
                    displacement: 0,
                    dst: "r0".into(),
                },
            },
            InstructionRef {
                address: 0x8004,
                kind: InstrRefKind::IndexedLoad {
                    base: "data".into(),
                    index: None,
                    scale: 4,
                    displacement: 4,
                    dst: "r1".into(),
                },
            },
        ];
        let facts = ArrayDetector::detect_as_facts(&instrs);
        assert!(facts.contains_key("data"));
        assert!(matches!(facts["data"], TypeFact::Array { .. }));
    }

    #[test]
    fn test_array_detector_apply_to_engine() {
        let instrs = vec![
            InstructionRef {
                address: 0x9000,
                kind: InstrRefKind::IndexedLoad {
                    base: "vec".into(),
                    index: None,
                    scale: 8,
                    displacement: 0,
                    dst: "e0".into(),
                },
            },
            InstructionRef {
                address: 0x9008,
                kind: InstrRefKind::IndexedLoad {
                    base: "vec".into(),
                    index: None,
                    scale: 8,
                    displacement: 8,
                    dst: "e1".into(),
                },
            },
        ];
        let mut engine = TypeInferenceEngine::new();
        ArrayDetector::apply_to_engine(&mut engine, &instrs);
        let assignment = engine.solve().unwrap();
        let fact = engine.type_of("vec", &assignment).unwrap();
        assert!(matches!(fact, TypeFact::Array { .. }));
    }

    // ── TypeLevel::LibrarySignature ──────────────────────────────────────────

    #[test]
    fn test_type_level_library_signature_specificity() {
        use crate::lattice::TypeLevel;
        // LibrarySignature (rank 4) is more specific than Concrete (rank 3).
        assert!(
            TypeLevel::LibrarySignature.specificity()
                > TypeLevel::Concrete(TypeFact::SignedInt(4)).specificity()
        );
    }

    #[test]
    fn test_type_level_library_signature_meet() {
        use crate::lattice::TypeLevel;
        // LibrarySignature meets anything less specific -> LibrarySignature.
        let concrete = TypeLevel::Concrete(TypeFact::UnsignedInt(8));
        assert_eq!(
            TypeLevel::LibrarySignature.meet(&concrete),
            TypeLevel::LibrarySignature
        );
        assert_eq!(
            concrete.meet(&TypeLevel::LibrarySignature),
            TypeLevel::LibrarySignature
        );
    }

    #[test]
    fn test_type_level_library_signature_join_with_concrete() {
        use crate::lattice::TypeLevel;
        let concrete = TypeLevel::Concrete(TypeFact::UnsignedInt(8));
        // Joining LibrarySignature with Concrete widens to Concrete.
        let joined = TypeLevel::LibrarySignature.join(&concrete);
        assert!(matches!(joined, TypeLevel::Concrete(_)));
    }

    #[test]
    fn test_type_level_library_signature_to_fact_is_unknown() {
        use crate::lattice::TypeLevel;
        // to_fact() returns Unknown for LibrarySignature (callers use the DB).
        assert_eq!(TypeLevel::LibrarySignature.to_fact(), TypeFact::Unknown);
    }

    #[test]
    fn test_type_level_library_signature_refines_concrete() {
        use crate::lattice::TypeLevel;
        assert!(TypeLevel::LibrarySignature.refines(&TypeLevel::Concrete(TypeFact::Bool)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enterprise battery — union-find algebraic invariants, lattice properties,
// deep-chain stress, defensive solving, fuzz robustness.
//
// The type-inference engine is the foundation of recovered-type quality; a
// wrong `find()` collapses incompatible types, a wrong `join()` either widens
// to Unknown (losing the signal) or under-narrows (producing unsound types).
// This battery enforces:
//
//   * Union-find: `find(union(a,b)) == find(a) == find(b)` and the relation
//     is reflexive/symmetric/transitive over random sequences.
//   * Path compression flattens chains in one `find` pass (perf regression
//     guard) without changing the equivalence classes.
//   * `TypeFact::join` is commutative, idempotent, and *monotonically
//     informative* (the result is more specific than or equal to its inputs).
//   * `solve()` does not panic when constraints reference `TypeVar`s past
//     `next_var` (regression target for the OOB fix).
//   * 100k-variable linear-chain unification terminates without stack
//     overflow (regression target for the recursive-find fix).
//   * Fuzz: 5000 random constraint sets must solve without panicking.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod enterprise_battery {
    use super::*;
    use std::collections::BTreeMap;

    /// Deterministic LCG.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn range(&mut self, hi: u32) -> u32 {
            if hi == 0 {
                0
            } else {
                (self.next() >> 33) as u32 % hi
            }
        }
    }

    // ── Union-Find invariants ─────────────────────────────────────────────

    /// After `union(a, b)`, `find(a) == find(b)`; transitivity through any
    /// chain holds; and roots remain stable across repeated `find` calls.
    #[test]
    fn union_find_satisfies_equivalence_relation_axioms() {
        fn naive_find(classes: &[usize], mut x: usize) -> usize {
            while classes[x] != x {
                x = classes[x];
            }
            x
        }
        fn to_u32(v: usize) -> u32 {
            u32::try_from(v).expect("test value fits in u32")
        }
        let mut rng = Lcg(0x4242_4242_dead_beef);
        for _ in 0..200 {
            let n = 1 + usize::try_from(rng.next() % 200).expect("fits");
            let mut uf = UnionFind::new(n);
            // Reference equivalence relation, computed naïvely.
            let mut classes: Vec<usize> = (0..n).collect();
            for _ in 0..(n * 2) {
                let a = rng.range(to_u32(n)) as usize;
                let b = rng.range(to_u32(n)) as usize;
                uf.union(to_u32(a), to_u32(b));
                // Naïve reference: union by rewriting class label.
                let ra = naive_find(&classes, a);
                let rb = naive_find(&classes, b);
                if ra != rb {
                    classes[ra] = rb;
                }
            }
            // Property: every pair the reference puts in the same class
            // must have the same `find` root.
            for x in 0..n {
                for y in 0..n {
                    let rx = naive_find(&classes, x);
                    let ry = naive_find(&classes, y);
                    let in_same = rx == ry;
                    let uf_same = uf.find(to_u32(x)) == uf.find(to_u32(y));
                    assert_eq!(
                        in_same, uf_same,
                        "disagreement on ({x},{y}): naive={in_same} uf={uf_same}"
                    );
                }
            }
        }
    }

    /// `find` must be idempotent: two consecutive calls return the same root.
    #[test]
    fn union_find_idempotent() {
        let mut uf = UnionFind::new(20);
        for i in 1..20 {
            uf.union(0, i);
        }
        for i in 0..20 {
            let r1 = uf.find(i);
            let r2 = uf.find(i);
            assert_eq!(r1, r2);
        }
    }

    // ── Deep-chain stress (recursive-find regression target) ──────────────

    /// 100 000 unions forming a linear `parent` chain MUST not stack-overflow
    /// under `find` — would have killed the recursive implementation.
    #[test]
    fn union_find_handles_100k_linear_chain() {
        const N: u32 = 100_000;
        let mut uf = UnionFind::new(N as usize);
        // Build a chain: 0 — 1 — 2 — … — N-1 by unioning each with the next.
        // After the unions every node must share one root.
        for i in 1..N {
            uf.union(i - 1, i);
        }
        let r0 = uf.find(0);
        for i in (0..N).step_by(7919) {
            // 7919 is prime — exercises arbitrary positions.
            assert_eq!(uf.find(i), r0);
        }
    }

    // ── `TypeFact::join` lattice properties ───────────────────────────────

    #[test]
    fn join_is_commutative_idempotent_and_top_absorbs() {
        let cases = [
            TypeFact::Unknown,
            TypeFact::Sized(4),
            TypeFact::SignedInt(4),
            TypeFact::UnsignedInt(4),
            TypeFact::Float(4),
            TypeFact::Bool,
            TypeFact::Char,
            TypeFact::Pointer(Box::new(TypeFact::Sized(8))),
        ];
        for a in &cases {
            // Idempotent.
            assert_eq!(a.join(a), *a, "join({a:?}, {a:?}) != {a:?}");
            // Unknown is the top of the lattice — joining with it returns `a`.
            assert_eq!(a.join(&TypeFact::Unknown), *a);
            assert_eq!(TypeFact::Unknown.join(a), *a);
            for b in &cases {
                // Commutative.
                assert_eq!(a.join(b), b.join(a), "non-commutative join: {a:?} vs {b:?}");
            }
        }
    }

    /// `join` must NEVER produce a strictly less-informative result than
    /// either input. In particular, `Sized(n) ⊓ SignedInt(n)` must refine
    /// to `SignedInt(n)`, not widen to `Unknown` (the old bug).
    #[test]
    fn join_refines_sized_against_typed_same_size() {
        let pairs: &[(TypeFact, TypeFact, TypeFact)] = &[
            (
                TypeFact::Sized(4),
                TypeFact::SignedInt(4),
                TypeFact::SignedInt(4),
            ),
            (
                TypeFact::Sized(8),
                TypeFact::UnsignedInt(8),
                TypeFact::UnsignedInt(8),
            ),
            (TypeFact::Sized(4), TypeFact::Float(4), TypeFact::Float(4)),
            (TypeFact::Sized(1), TypeFact::Bool, TypeFact::Bool),
            (TypeFact::Sized(1), TypeFact::Char, TypeFact::Char),
        ];
        for (a, b, want) in pairs {
            let got = a.join(b);
            assert_eq!(&got, want, "join({a:?}, {b:?}) = {got:?}, want {want:?}");
            // Symmetry: same result the other way around.
            let got = b.join(a);
            assert_eq!(&got, want);
        }
    }

    /// Mismatched concrete types still widen to `Unknown` — that part of the
    /// semantics is unchanged and must remain.
    #[test]
    fn join_widens_to_unknown_on_incompatible_concrete_types() {
        let pairs = [
            (TypeFact::SignedInt(4), TypeFact::Float(4)),
            (TypeFact::SignedInt(4), TypeFact::SignedInt(8)),
            (TypeFact::Bool, TypeFact::Char),
        ];
        for (a, b) in &pairs {
            assert_eq!(
                a.join(b),
                TypeFact::Unknown,
                "expected widening on {a:?} vs {b:?}"
            );
        }
    }

    // ── Solver: defensive sizing (out-of-bounds TypeVar regression) ───────

    /// `add_constraint` is public, so a caller can hand the engine constraints
    /// referencing `TypeVar`s that were never produced by `fresh()`. The
    /// previous solver would index `parent[v]` past the array bound and panic;
    /// the new solver must size to the max id observed.
    #[test]
    fn solve_does_not_panic_on_unallocated_typevars() {
        let mut engine = TypeInferenceEngine::new();
        // Engine has produced no fresh variables — but the constraint cites τ7 and τ12.
        engine.add_constraint(TypeConstraint::Equal(TypeVar(7), TypeVar(12)));
        engine.add_constraint(TypeConstraint::HasType(TypeVar(12), TypeFact::SignedInt(4)));
        let solution = engine.solve().expect("solve must not panic");
        // Both must now have the typed answer.
        assert_eq!(solution.get(&7), Some(&TypeFact::SignedInt(4)));
        assert_eq!(solution.get(&12), Some(&TypeFact::SignedInt(4)));
    }

    /// End-to-end: chain `Equal` constraints + a single `HasType` and verify
    /// the type propagates to every member of the equivalence class.
    #[test]
    fn solve_propagates_typed_hint_across_chain_of_equals() {
        let mut engine = TypeInferenceEngine::new();
        let vars: Vec<TypeVar> = (0..50).map(|_| engine.fresh()).collect();
        for w in vars.windows(2) {
            engine.add_constraint(TypeConstraint::Equal(w[0], w[1]));
        }
        engine.add_constraint(TypeConstraint::HasType(vars[25], TypeFact::SignedInt(8)));
        let sol = engine.solve().unwrap();
        for v in &vars {
            assert_eq!(
                sol.get(&v.0),
                Some(&TypeFact::SignedInt(8)),
                "chain member {v} did not pick up the propagated type"
            );
        }
    }

    /// The Sized-refinement property survives the solver: a constraint
    /// `HasType(v, Sized(4))` followed by `HasType(v, SignedInt(4))` must
    /// land on `SignedInt(4)`, not `Unknown`.
    #[test]
    fn solve_refines_sized_to_more_specific_via_hastype() {
        let mut engine = TypeInferenceEngine::new();
        let v = engine.fresh();
        engine.add_constraint(TypeConstraint::HasType(v, TypeFact::Sized(4)));
        engine.add_constraint(TypeConstraint::HasType(v, TypeFact::SignedInt(4)));
        let sol = engine.solve().unwrap();
        assert_eq!(sol.get(&v.0), Some(&TypeFact::SignedInt(4)));
    }

    // ── Fuzz robustness ───────────────────────────────────────────────────

    /// Random constraint sets — mix of `Equal`, `HasType`, `Deref`, arithmetic —
    /// over both freshly-allocated and directly-constructed `TypeVar`s must
    /// never crash the solver.
    #[test]
    fn fuzz_solver_never_panics_on_random_constraint_sets() {
        let mut rng = Lcg(0xfeed_face_bead_beef);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut first_fail: Option<u64> = None;
        for i in 0..5_000u64 {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut engine = TypeInferenceEngine::new();
                let nvar = 1 + rng.range(40);
                for _ in 0..nvar {
                    let _ = engine.fresh();
                }
                let nconstr = rng.range(60);
                for _ in 0..nconstr {
                    // Mix valid (in-range) and adversarial (out-of-range) ids.
                    let a = TypeVar(rng.range(nvar * 2));
                    let b = TypeVar(rng.range(nvar * 2));
                    let c = TypeVar(rng.range(nvar * 2));
                    match rng.next() % 7 {
                        0 => engine.add_constraint(TypeConstraint::Equal(a, b)),
                        1 => {
                            let t = match rng.next() % 6 {
                                0 => TypeFact::Sized(1usize << rng.range(4)),
                                1 => TypeFact::SignedInt(1usize << rng.range(4)),
                                2 => TypeFact::UnsignedInt(1usize << rng.range(4)),
                                3 => TypeFact::Bool,
                                4 => TypeFact::Char,
                                _ => TypeFact::Pointer(Box::new(TypeFact::Sized(8))),
                            };
                            engine.add_constraint(TypeConstraint::HasType(a, t));
                        }
                        2 => engine.add_constraint(TypeConstraint::Deref { ptr: a, pointee: b }),
                        3 => engine.add_constraint(TypeConstraint::Add {
                            lhs: a,
                            rhs: b,
                            result: c,
                        }),
                        4 => engine.add_constraint(TypeConstraint::Sub {
                            lhs: a,
                            rhs: b,
                            result: c,
                        }),
                        5 => engine.add_constraint(TypeConstraint::Bitwise {
                            lhs: a,
                            rhs: b,
                            result: c,
                        }),
                        _ => engine.add_constraint(TypeConstraint::IsCondition(a)),
                    }
                }
                let _ = engine.solve();
            }));
            if r.is_err() {
                first_fail = Some(i);
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(
            first_fail.is_none(),
            "solver panicked at iter {first_fail:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // infer_function_signature tests
    // ─────────────────────────────────────────────────────────────────────────

    /// Synthetic __fastcall function with two typed args (ecx=i32, edx=*char)
    /// and a known return type (u32). Confidence must be "high".
    #[test]
    fn infer_fastcall_high_confidence() {
        let mut env = TypeEnvironment::new();
        env.arg_types = vec![TypeFact::SignedInt(4), TypeFact::Pointer(Box::new(TypeFact::Char))];
        env.return_type = TypeFact::UnsignedInt(4);

        let sig = infer_function_signature(0x1000, Some("fastcall (x86)"), &env);
        assert_eq!(sig.calling_convention, "fastcall (x86)");
        assert_eq!(sig.confidence, "high");
        assert_eq!(sig.args.len(), 2);
        assert_eq!(sig.args[0].ty, "i32");
        assert_eq!(sig.args[1].ty, "*char");
        assert_eq!(sig.return_type, "u32");
    }

    /// Known calling convention but some args unknown → medium confidence.
    #[test]
    fn infer_fastcall_medium_confidence() {
        let mut env = TypeEnvironment::new();
        env.arg_types = vec![TypeFact::SignedInt(4), TypeFact::Unknown];
        env.return_type = TypeFact::Unknown;

        let sig = infer_function_signature(0x2000, Some("fastcall (x86)"), &env);
        assert_eq!(sig.calling_convention, "fastcall (x86)");
        assert_eq!(sig.confidence, "medium");
    }

    /// No calling convention known → low confidence.
    #[test]
    fn infer_no_cc_low_confidence() {
        let env = TypeEnvironment::new();
        let sig = infer_function_signature(0x3000, None, &env);
        assert_eq!(sig.confidence, "low");
    }

    /// Determinism: identical constraint sets must produce identical type
    /// assignments — the solver must not depend on `HashMap` iteration order
    /// for its observable output.
    #[test]
    fn solve_is_deterministic_across_runs() {
        fn build_and_solve() -> BTreeMap<u32, TypeFact> {
            let mut engine = TypeInferenceEngine::new();
            let vars: Vec<TypeVar> = (0..20).map(|_| engine.fresh()).collect();
            for w in vars.windows(2) {
                engine.add_constraint(TypeConstraint::Equal(w[0], w[1]));
            }
            engine.add_constraint(TypeConstraint::HasType(vars[10], TypeFact::SignedInt(4)));
            engine.solve().unwrap().into_iter().collect()
        }
        let s1 = build_and_solve();
        let s2 = build_and_solve();
        assert_eq!(s1, s2, "solver output must be deterministic");
    }

    /// Regression: `CallGraph::topological_order` iterated `nodes.keys()`
    /// (randomized HashMap order), so the returned order — and everything
    /// downstream that consumed it — differed between runs. It must now be
    /// deterministic AND still place every callee before its caller.
    #[test]
    fn topological_order_is_deterministic_and_callee_first() {
        fn build() -> CallGraph {
            let mut cg = CallGraph::new();
            for f in ["main", "alpha", "beta", "gamma", "delta", "leaf"] {
                cg.add_function(f);
            }
            cg.add_call("main", "alpha");
            cg.add_call("main", "beta");
            cg.add_call("alpha", "gamma");
            cg.add_call("beta", "gamma");
            cg.add_call("gamma", "leaf");
            cg.add_call("delta", "leaf");
            cg
        }
        let orders: Vec<Vec<String>> = (0..20).map(|_| build().topological_order()).collect();
        for o in &orders[1..] {
            assert_eq!(o, &orders[0], "topological order must be deterministic");
        }
        let pos = |name: &str| orders[0].iter().position(|n| n == name).unwrap();
        for (caller, callee) in [
            ("main", "alpha"),
            ("main", "beta"),
            ("alpha", "gamma"),
            ("beta", "gamma"),
            ("gamma", "leaf"),
            ("delta", "leaf"),
        ] {
            assert!(
                pos(callee) < pos(caller),
                "{callee} must precede its caller {caller}"
            );
        }
    }

    /// Regression: `ArrayDetector::detect` returned `groups.values()` in
    /// randomized HashMap order, making the pattern list (and the winning
    /// entry of `detect_as_facts` for a base observed at two strides)
    /// nondeterministic. The output must be sorted by (base_var, stride).
    #[test]
    fn array_detector_output_order_is_deterministic_and_sorted() {
        fn instrs() -> Vec<InstructionRef> {
            let mut v = Vec::new();
            for (base, scale) in [("rbx", 8), ("rax", 4), ("rax", 8), ("rcx", 2)] {
                for d in 0..3_i64 {
                    v.push(InstructionRef {
                        address: 0x1000 + d as u64,
                        kind: InstrRefKind::IndexedLoad {
                            base: base.to_string(),
                            index: None,
                            scale,
                            displacement: d * i64::try_from(scale).unwrap(),
                            dst: "t".to_string(),
                        },
                    });
                }
            }
            v
        }
        let first = ArrayDetector::detect(&instrs());
        let keys: Vec<(String, usize)> = first
            .iter()
            .map(|p| (p.base_var.clone(), p.stride))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("rax".to_string(), 4),
                ("rax".to_string(), 8),
                ("rbx".to_string(), 8),
                ("rcx".to_string(), 2)
            ]
        );
        for _ in 0..10 {
            assert_eq!(ArrayDetector::detect(&instrs()), first);
        }
    }

    /// Property: `TypeInferenceEngine::solve` is order-independent — feeding
    /// the same constraint set in permuted order yields the same assignment.
    #[test]
    fn solve_is_constraint_order_independent() {
        let mut rng = Lcg(0x5EED_1234);
        for _ in 0..50 {
            // Random constraint pool over 12 variables.
            let mut constraints: Vec<TypeConstraint> = Vec::new();
            for _ in 0..15 {
                let a = TypeVar(rng.range(12));
                let b = TypeVar(rng.range(12));
                match rng.range(3) {
                    0 => constraints.push(TypeConstraint::Equal(a, b)),
                    1 => constraints.push(TypeConstraint::HasType(
                        a,
                        TypeFact::SignedInt(4 << (rng.range(2))),
                    )),
                    _ => constraints.push(TypeConstraint::Deref { ptr: a, pointee: b }),
                }
            }
            let solve_with = |cs: &[TypeConstraint]| -> BTreeMap<u32, TypeFact> {
                let mut e = TypeInferenceEngine::new();
                for _ in 0..12 {
                    e.fresh();
                }
                for c in cs {
                    e.add_constraint(c.clone());
                }
                e.solve().unwrap().into_iter().collect()
            };
            let base = solve_with(&constraints);
            // A few pseudo-random permutations (rotation + swap shuffle).
            for _ in 0..4 {
                let mut permuted = constraints.clone();
                let rot = rng.range(permuted.len() as u32) as usize;
                permuted.rotate_left(rot);
                for i in (1..permuted.len()).rev() {
                    let j = rng.range((i + 1) as u32) as usize;
                    permuted.swap(i, j);
                }
                assert_eq!(
                    solve_with(&permuted),
                    base,
                    "solve must be independent of constraint order"
                );
            }
        }
    }

    /// `solve_checked` must report convergence for ordinary (acyclic) Deref
    /// chains — including one whose length exactly equals the pass budget —
    /// and its assignment must match plain `solve()` exactly.
    #[test]
    fn solve_checked_reports_convergence_on_acyclic_derefs() {
        let mut engine = TypeInferenceEngine::new();
        let p = engine.fresh();
        let x = engine.fresh();
        engine.add_constraint(TypeConstraint::Deref { ptr: p, pointee: x });
        engine.add_constraint(TypeConstraint::HasType(x, TypeFact::SignedInt(4)));
        let (assignment, converged) = engine.solve_checked().unwrap();
        assert!(converged, "acyclic single deref must converge");
        assert_eq!(
            assignment.get(&p.0),
            Some(&TypeFact::Pointer(Box::new(TypeFact::SignedInt(4))))
        );

        // Backward compatibility: solve() gives the identical assignment.
        let mut engine2 = TypeInferenceEngine::new();
        let p2 = engine2.fresh();
        let x2 = engine2.fresh();
        engine2.add_constraint(TypeConstraint::Deref { ptr: p2, pointee: x2 });
        engine2.add_constraint(TypeConstraint::HasType(x2, TypeFact::SignedInt(4)));
        assert_eq!(engine2.solve().unwrap(), assignment);
    }

    /// A self-referential Deref cycle has no finite fixed point: the pointer
    /// type deepens on every pass until the cap stops it. `solve()` used to
    /// exit this silently; `solve_checked` must report `converged == false`.
    #[test]
    fn solve_checked_flags_nonconvergent_deref_cycle() {
        let mut engine = TypeInferenceEngine::new();
        let v = engine.fresh();
        engine.add_constraint(TypeConstraint::Deref { ptr: v, pointee: v });
        let (assignment, converged) = engine.solve_checked().unwrap();
        assert!(!converged, "deref cycle must be flagged as non-convergent");
        // Assignment is still produced and deterministic (truncated at cap).
        assert!(assignment.contains_key(&v.0));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPA wiring tests — prove interprocedural.rs and propagation.rs are live in
// the TypeRecoveryPass and infer_function_signature paths.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod ipa_wiring_tests {
    use super::*;
    use std::sync::Arc;

    use rustre_core::{
        address::{Address, AddressRange},
        arch::{Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo},
        binary_view::{BinaryView, FunctionDef, Memory, Segment, Xref, XrefKind},
        endian::Endian,
        errors::CoreError,
        ids::ViewId,
        permissions::Permissions,
    };

    #[derive(Debug)]
    struct DummyArch;

    impl Architecture for DummyArch {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(&self, address: Address, _bytes: &[u8]) -> Result<Instruction, CoreError> {
            Ok(Instruction::new(address, 1, "nop", vec![0x90]))
        }
        fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
            Vec::new()
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            Vec::new()
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            Vec::new()
        }
    }

    fn make_view() -> BinaryView {
        let mut mem = Memory::new();
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x1000), Address::new(0x3000)),
            permissions: Permissions::READ | Permissions::EXECUTE,
            data: vec![0x90; 0x2000],
        });
        BinaryView::new(
            ViewId::new(1).expect("non-zero view id"),
            "test://ipa-wiring".into(),
            Arc::new(DummyArch),
            Endian::Little,
            64,
            vec![Address::new(0x1000)],
            mem,
        )
    }

    /// End-to-end: the pass builds a real interprocedural call graph from the
    /// xref index, runs IPA to convergence, bridges library prototypes through
    /// propagation.rs, and reports nonzero real numbers.
    #[test]
    fn test_type_recovery_pass_produces_real_ipa_results() {
        let view = make_view();
        {
            let mut funcs = view.functions.write();
            funcs.add_function(
                FunctionDef::new(Address::new(0x1000), "main").with_end(Address::new(0x1100)),
            );
            funcs.add_function(
                FunctionDef::new(Address::new(0x1100), "helper").with_end(Address::new(0x1200)),
            );
            funcs.add_function(FunctionDef::new(Address::new(0x2000), "malloc"));
        }
        {
            let mut xrefs = view.xrefs.write();
            // call site inside main -> malloc, and main -> helper
            xrefs.add_xref(Xref::new(
                Address::new(0x1050),
                Address::new(0x2000),
                XrefKind::CodeCall,
            ));
            xrefs.add_xref(Xref::new(
                Address::new(0x1080),
                Address::new(0x1100),
                XrefKind::CodeCall,
            ));
        }

        let result = TypeRecoveryPass::run_inner(&view).expect("pass must succeed");
        assert_eq!(result.functions_found, 3);
        let all = result.warnings.join("\n");
        // Real interprocedural call graph, converged fixpoint.
        assert!(all.contains("3 functions (1 library-annotated)"), "{all}");
        assert!(all.contains("2 call edges"), "{all}");
        assert!(all.contains("converged=true"), "{all}");
        // malloc has a published prototype, so its return type is known.
        assert!(all.contains("1/3 functions with known return type"), "{all}");
        // 3 FunctionReturn + 1 malloc param annotation.
        assert!(all.contains("4 annotations collected"), "{all}");
        // propagation.rs moved malloc return type onto the call-site var in
        // main, and env-level propagation resolved malloc + main envs.
        assert!(all.contains("1 call-site vars typed"), "{all}");
        assert!(all.contains("2 environments resolved"), "{all}");
        assert!(all.contains("1 published signatures applied"), "{all}");
    }

    /// With no functions the pass still succeeds and reports zeros honestly.
    #[test]
    fn test_type_recovery_pass_empty_view() {
        let view = make_view();
        let result = TypeRecoveryPass::run_inner(&view).expect("pass must succeed");
        assert_eq!(result.functions_found, 0);
        let all = result.warnings.join("\n");
        assert!(all.contains("0 functions (0 library-annotated)"), "{all}");
        assert!(all.contains("converged=true"), "{all}");
    }

    /// Published prototypes are authoritative: inferred arity never overrides.
    #[test]
    fn test_infer_signature_published_prototype_wins() {
        let lib_db = interprocedural::LibrarySignatureDb::new();

        // Inference claims 5 int args and an int return, all bogus.
        let mut env = TypeEnvironment::new();
        env.arg_types = vec![TypeFact::SignedInt(4); 5];
        env.return_type = TypeFact::SignedInt(4);

        let sig =
            infer_function_signature_named(0x2000, Some("memcpy"), Some("sysv64"), &env, &lib_db);
        // Published arity (3) wins over inferred arity (5).
        assert_eq!(sig.args.len(), 3, "published arity must win: {sig:?}");
        // Published concrete types win over inferred ones.
        assert_eq!(sig.args[0].ty, "*?"); // void*
        assert_eq!(sig.args[2].ty, "u64"); // size_t
        assert_eq!(sig.return_type, "*?"); // returns void*
        assert_eq!(sig.confidence, "high");

        // Void return is spelled "void", not "?".
        let free_sig = infer_function_signature_named(0x2100, Some("free"), None, &env, &lib_db);
        assert_eq!(free_sig.return_type, "void");
        assert_eq!(free_sig.args.len(), 1);
    }

    /// Unknown names fall back to plain inference unchanged.
    #[test]
    fn test_infer_signature_unknown_name_falls_back() {
        let lib_db = interprocedural::LibrarySignatureDb::new();
        let mut env = TypeEnvironment::new();
        env.arg_types = vec![TypeFact::UnsignedInt(8), TypeFact::Bool];
        env.return_type = TypeFact::Float(8);

        let named =
            infer_function_signature_named(0x3000, Some("sub_3000"), Some("ms64"), &env, &lib_db);
        let plain = infer_function_signature(0x3000, Some("ms64"), &env);
        assert_eq!(named, plain);
        let anon = infer_function_signature_named(0x3000, None, Some("ms64"), &env, &lib_db);
        assert_eq!(anon, plain);
    }

    /// The propagation.rs bridge in the pass mirrors this shape: a library
    /// return type crosses a call edge and then an SSA assignment.
    #[test]
    fn test_propagation_moves_library_type_across_call_and_assignment() {
        use crate::constraints::{Address as CAddr, VarRef};
        use crate::propagation::{
            CallGraph as PropCallGraph, CallSite, FunctionSig, MlilFunction,
            TypePropagator as VarPropagator,
        };

        let mut func = MlilFunction::new(0x1000, "main");
        let ret = VarRef::new(0x1000, 0);
        let alias = VarRef::new(0x1000, 1);
        func.add_call_site(CallSite {
            caller: 0x1000,
            callee: CAddr(0x2000),
            arg_vars: vec![],
            ret_var: Some(ret),
        });
        func.add_assignment(alias, ret); // alias = malloc(...)

        let mut cg = PropCallGraph::new();
        cg.add_known_sig(
            0x2000,
            FunctionSig {
                name: "malloc".into(),
                arg_types: vec![TypeFact::UnsignedInt(8)],
                ret_type: TypeFact::Pointer(Box::new(TypeFact::Unknown)),
            },
        );

        let mut types = crate::propagation::TypeMap::new();
        let mut prop = VarPropagator::new();
        prop.load_function(&func);
        prop.seed(&types);
        prop.propagate_through_calls(&func, &cg, &mut types);

        assert!(matches!(types[&ret], TypeFact::Pointer(_)));
        assert!(
            matches!(types[&alias], TypeFact::Pointer(_)),
            "type must cross the assignment edge: {types:?}"
        );
    }
}
