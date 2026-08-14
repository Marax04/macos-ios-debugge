//! `constraints` — rich type-constraint system for the type-recovery engine.
//!
//! Each `TypeFact` is a single, atomic piece of evidence about a variable's
//! type collected from instruction analysis. The `TypeConstraintSolver` gathers
//! all facts, unifies them via union-find, and produces a `TypeSolution` that
//! assigns a concrete type to every variable in scope.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::TypeFact;

// ── Primitive identifiers ─────────────────────────────────────────────────────

/// Opaque identifier for a program address (RVA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub u64);

/// Identifies a type node inside the `TypeStore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeId(pub u32);

/// A reference to a typed variable, identified by a `(function_id, local_index)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VarRef {
    pub function: u64,
    pub index: u32,
}

impl VarRef {
    #[must_use]
    pub const fn new(function: u64, index: u32) -> Self {
        Self { function, index }
    }
}

// ── FunctionSignature ─────────────────────────────────────────────────────────

/// A resolved function signature from a library database or import table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: TypeId,
    pub parameters: Vec<TypeId>,
    pub is_variadic: bool,
}

// ── TypeFact ──────────────────────────────────────────────────────────────────

/// One atomic piece of evidence about a variable's type, extracted from a
/// single instruction or ABI rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintFact {
    /// Variable occupies exactly `size` bytes (from a memory-access width).
    HasSize { var: VarRef, size: u8 },

    /// Variable is a signed integer (from SAR / IDIV / IMUL / MOVSX).
    IsSigned { var: VarRef },

    /// Variable is an unsigned integer (from SHR / DIV / MUL / MOVZX).
    IsUnsigned { var: VarRef },

    /// Variable is a floating-point value (from x87 / SSE operations).
    IsFloat { var: VarRef },

    /// Variable is a pointer; `pointee_size` is the size of what it points to
    /// if already known from a dereference instruction.
    IsPointer {
        var: VarRef,
        pointee_size: Option<u8>,
    },

    /// Variable is an array of `elem_size`-byte elements with an optional bound.
    IsArray {
        var: VarRef,
        elem_size: u8,
        bound: Option<usize>,
    },

    /// Variable is (or points to) a struct with a field at `field_offset` bytes.
    IsStruct {
        var: VarRef,
        field_offset: u64,
        field_size: u8,
    },

    /// A specific field of a named struct type is accessed at `offset`.
    HasFieldAtOffset {
        struct_type: TypeId,
        offset: u64,
        size: u8,
        name: Option<String>,
    },

    /// Variable is a virtual-table pointer (loaded from `[ptr+0]` then indirect call).
    IsVtablePtr { var: VarRef },

    /// The `arg_idx`-th argument to `func` has type `type_id`.
    CallArgType {
        func: Address,
        arg_idx: u8,
        type_id: TypeId,
    },

    /// The return value of `func` has type `type_id`.
    CallReturnType { func: Address, type_id: TypeId },

    /// `func` is a known library function with a full signature.
    LibraryFunction {
        func: Address,
        signature: FunctionSignature,
    },

    /// Two variables have the same type (assignment or phi-node merge).
    SameType { a: VarRef, b: VarRef },
}

// ── TypeStore ─────────────────────────────────────────────────────────────────

/// A simple type registry that maps `TypeId → TypeFact`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeStore {
    entries: Vec<TypeFact>,
}

impl TypeStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new `TypeId` for `fact` and return it.
    pub fn intern(&mut self, fact: TypeFact) -> TypeId {
        let id = TypeId(u32::try_from(self.entries.len()).unwrap_or(u32::MAX));
        self.entries.push(fact);
        id
    }

    /// Retrieve the `TypeFact` for a `TypeId`.
    #[must_use]
    pub fn get(&self, id: TypeId) -> Option<&TypeFact> {
        self.entries.get(id.0 as usize)
    }

    /// Update an existing entry.
    pub fn set(&mut self, id: TypeId, fact: TypeFact) {
        if let Some(slot) = self.entries.get_mut(id.0 as usize) {
            *slot = fact;
        }
    }

    /// Number of stored types.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Union-Find ────────────────────────────────────────────────────────────────

/// Weighted-union / path-compression union-find over `VarRef` nodes.
#[derive(Debug, Clone)]
pub struct UnionFind {
    /// `parent[i]` = parent index in the tree; root satisfies `parent[i] == i`.
    parent: Vec<u32>,
    rank: Vec<u8>,
    /// Maps `VarRef` to a dense integer index.
    index: HashMap<VarRef, u32>,
    /// Reverse map: index → `VarRef`.
    vars: Vec<VarRef>,
}

impl UnionFind {
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: Vec::new(),
            rank: Vec::new(),
            index: HashMap::new(),
            vars: Vec::new(),
        }
    }

    /// Register a variable and return its internal index.
    pub fn register(&mut self, var: VarRef) -> u32 {
        if let Some(&idx) = self.index.get(&var) {
            return idx;
        }
        let idx = u32::try_from(self.vars.len()).unwrap_or(u32::MAX);
        self.vars.push(var);
        self.parent.push(idx);
        self.rank.push(0);
        self.index.insert(var, idx);
        idx
    }

    /// Path-compressing find. Returns the canonical root index.
    pub fn find(&mut self, idx: u32) -> u32 {
        let i = idx as usize;
        if self.parent[i] != idx {
            let root = self.find(self.parent[i]);
            self.parent[i] = root;
        }
        self.parent[i]
    }

    /// Union-by-rank of two nodes (by internal index).
    pub fn union_idx(&mut self, x: u32, y: u32) {
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

    /// Union two `VarRef`s (registering them if necessary).
    pub fn union(&mut self, a: VarRef, b: VarRef) {
        let ia = self.register(a);
        let ib = self.register(b);
        self.union_idx(ia, ib);
    }

    /// Find the canonical root for a `VarRef`.
    pub fn find_var(&mut self, var: VarRef) -> u32 {
        let idx = self.register(var);
        self.find(idx)
    }

    /// True if `a` and `b` are in the same equivalence class.
    pub fn same_class(&mut self, a: VarRef, b: VarRef) -> bool {
        let ra = self.find_var(a);
        let rb = self.find_var(b);
        ra == rb
    }
}

impl Default for UnionFind {
    fn default() -> Self {
        Self::new()
    }
}

// ── TypeSolution ──────────────────────────────────────────────────────────────

/// The solved assignment: `VarRef → TypeFact`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeSolution {
    assignments: HashMap<VarRef, TypeFact>,
    /// Variables whose type could not be resolved.
    pub unknowns: Vec<VarRef>,
}

impl TypeSolution {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the resolved type for a variable.
    #[must_use]
    pub fn type_of(&self, var: VarRef) -> TypeFact {
        self.assignments
            .get(&var)
            .cloned()
            .unwrap_or(TypeFact::Unknown)
    }

    /// Insert / override the type for a variable.
    pub fn set(&mut self, var: VarRef, fact: TypeFact) {
        if fact == TypeFact::Unknown {
            self.unknowns.push(var);
        }
        self.assignments.insert(var, fact);
    }

    /// Number of resolved variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    /// True when no variables are assigned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Iterate all `(VarRef, TypeFact)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (VarRef, &TypeFact)> {
        self.assignments.iter().map(|(&v, t)| (v, t))
    }
}

// ── TypeConstraintSolver ──────────────────────────────────────────────────────

/// Gathers `ConstraintFact`s, unifies variables, and produces a `TypeSolution`.
pub struct TypeConstraintSolver {
    facts: Vec<ConstraintFact>,
    union_find: UnionFind,
    pub type_store: TypeStore,
    /// Per-root accumulated type hint (`root_idx` → `TypeFact`).
    hints: HashMap<u32, TypeFact>,
}

impl TypeConstraintSolver {
    /// Create a fresh solver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            facts: Vec::new(),
            union_find: UnionFind::new(),
            type_store: TypeStore::new(),
            hints: HashMap::new(),
        }
    }

    /// Add a single `ConstraintFact` to the solver.
    pub fn add_fact(&mut self, fact: ConstraintFact) {
        self.facts.push(fact);
    }

    /// Add multiple facts at once.
    pub fn add_facts(&mut self, facts: impl IntoIterator<Item = ConstraintFact>) {
        self.facts.extend(facts);
    }

    /// Merge the types of two `TypeId`s in the store.
    pub fn merge_types(&mut self, a: TypeId, b: TypeId) -> TypeId {
        let fa = self.type_store.get(a).cloned().unwrap_or(TypeFact::Unknown);
        let fb = self.type_store.get(b).cloned().unwrap_or(TypeFact::Unknown);
        let merged = fa.join(&fb);
        self.type_store.intern(merged)
    }

    /// Run the constraint solver and produce a `TypeSolution`.
    ///
    /// Algorithm:
    ///  1. Pre-register all variables from `SameType` facts (union-find init).
    ///  2. Process all facts that unify variables.
    ///  3. Accumulate per-root type hints from singleton facts.
    ///  4. Propagate hints to all variables that share a root.
    pub fn solve(&mut self) -> TypeSolution {
        // ── Phase 1: pre-register variables ───────────────────────────────────
        // Walk all facts to register every VarRef so union-find indices are stable.
        for fact in &self.facts.clone() {
            self.register_vars_from_fact(fact);
        }

        // ── Phase 2: unify variables ──────────────────────────────────────────
        for fact in &self.facts.clone() {
            if let ConstraintFact::SameType { a, b } = fact {
                self.union_find.union(*a, *b);
            }
        }

        // ── Phase 3: accumulate hints ─────────────────────────────────────────
        for fact in &self.facts.clone() {
            self.apply_hint(fact);
        }

        // ── Phase 4: build solution ───────────────────────────────────────────
        let mut solution = TypeSolution::new();
        let all_vars: Vec<VarRef> = self.union_find.vars.clone();
        for var in all_vars {
            let root = self.union_find.find_var(var);
            let tf = self.hints.get(&root).cloned().unwrap_or(TypeFact::Unknown);
            solution.set(var, tf);
        }
        solution
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn register_vars_from_fact(&mut self, fact: &ConstraintFact) {
        match fact {
            ConstraintFact::HasSize { var, .. }
            | ConstraintFact::IsSigned { var }
            | ConstraintFact::IsUnsigned { var }
            | ConstraintFact::IsFloat { var }
            | ConstraintFact::IsPointer { var, .. }
            | ConstraintFact::IsArray { var, .. }
            | ConstraintFact::IsStruct { var, .. }
            | ConstraintFact::IsVtablePtr { var } => {
                self.union_find.register(*var);
            }
            ConstraintFact::SameType { a, b } => {
                self.union_find.register(*a);
                self.union_find.register(*b);
            }
            ConstraintFact::HasFieldAtOffset { .. }
            | ConstraintFact::CallArgType { .. }
            | ConstraintFact::CallReturnType { .. }
            | ConstraintFact::LibraryFunction { .. } => {}
        }
    }

    fn apply_hint(&mut self, fact: &ConstraintFact) {
        match fact {
            ConstraintFact::HasSize { var, size } => {
                let root = self.union_find.find_var(*var);
                let existing = self.hints.entry(root).or_insert(TypeFact::Unknown);
                let size = *size as usize;
                // Re-size signedness/kind hints in place so a defaulted size
                // (e.g. SignedInt(4) from IsSigned alone) is not joined into
                // Unknown when the proven size arrives later.
                *existing = match *existing {
                    TypeFact::SignedInt(_) => TypeFact::SignedInt(size),
                    TypeFact::UnsignedInt(_) => TypeFact::UnsignedInt(size),
                    TypeFact::Float(_) => TypeFact::Float(size),
                    // A pointer hint is structural evidence and outranks a bare
                    // width: keep it. Joining would collapse to `Unknown`
                    // (pointers have no `byte_size`), which made the solved
                    // type depend on the order `HasSize` / `IsPointer` were
                    // inserted. Property test: `prop_solve_is_permutation_independent`.
                    TypeFact::Pointer(_) => existing.clone(),
                    _ => existing.join(&TypeFact::Sized(size)),
                };
            }
            ConstraintFact::IsSigned { var } => {
                let root = self.union_find.find_var(*var);
                // Upgrade: if already sized, make it SignedInt; else mark signed
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                if let TypeFact::Sized(n) | TypeFact::UnsignedInt(n) = *entry {
                    *entry = TypeFact::SignedInt(n);
                } else if *entry == TypeFact::Unknown {
                    *entry = TypeFact::SignedInt(4); // default i32
                }
            }
            ConstraintFact::IsUnsigned { var } => {
                let root = self.union_find.find_var(*var);
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                if let TypeFact::Sized(n) | TypeFact::SignedInt(n) = *entry {
                    *entry = TypeFact::UnsignedInt(n);
                } else if *entry == TypeFact::Unknown {
                    *entry = TypeFact::UnsignedInt(4); // default u32
                }
            }
            ConstraintFact::IsFloat { var } => {
                let root = self.union_find.find_var(*var);
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                if let TypeFact::Sized(n) = *entry {
                    *entry = TypeFact::Float(n);
                } else if *entry == TypeFact::Unknown {
                    *entry = TypeFact::Float(8); // default double
                }
            }
            ConstraintFact::IsPointer { var, pointee_size } => {
                let root = self.union_find.find_var(*var);
                let inner = pointee_size
                    .map_or(TypeFact::Unknown, |s| TypeFact::Sized(s as usize));
                let ptr_fact = TypeFact::Pointer(Box::new(inner));
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                // If the accumulated hint is incompatible with "is a pointer"
                // (e.g. a defaulted `SignedInt(4)` guessed by `IsSigned`, or a
                // bare `Sized(n)`), the join collapses to `Unknown` and the
                // pointer evidence is lost — but only when `IsPointer` happens
                // to arrive *second*. Structural pointer evidence outranks a
                // width/signedness guess, so keep the pointer either way; this
                // makes the result independent of insertion order.
                let joined = entry.join(&ptr_fact);
                *entry = if joined.is_known() { joined } else { ptr_fact };
            }
            ConstraintFact::IsArray {
                var,
                elem_size,
                bound,
            } => {
                let root = self.union_find.find_var(*var);
                let elem = TypeFact::Sized(*elem_size as usize);
                let arr = TypeFact::Array {
                    element: Box::new(elem),
                    length: *bound,
                };
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                *entry = entry.join(&arr);
            }
            ConstraintFact::IsStruct {
                var,
                field_offset,
                field_size,
            } => {
                let root = self.union_find.find_var(*var);
                let field = TypeFact::Struct {
                    fields: vec![(
                        usize::try_from(*field_offset).unwrap_or(usize::MAX),
                        TypeFact::Sized(*field_size as usize),
                    )],
                };
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                *entry = entry.join(&field);
            }
            ConstraintFact::IsVtablePtr { var } => {
                // A vtable pointer is a pointer to a pointer (the vptr field).
                let root = self.union_find.find_var(*var);
                let vptr =
                    TypeFact::Pointer(Box::new(TypeFact::Pointer(Box::new(TypeFact::Unknown))));
                let entry = self.hints.entry(root).or_insert(TypeFact::Unknown);
                *entry = entry.join(&vptr);
            }
            // Facts that do not directly constrain a VarRef hint:
            ConstraintFact::HasFieldAtOffset { .. }
            | ConstraintFact::CallArgType { .. }
            | ConstraintFact::CallReturnType { .. }
            | ConstraintFact::LibraryFunction { .. }
            | ConstraintFact::SameType { .. } => {}
        }
    }
}

impl Default for TypeConstraintSolver {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var(function: u64, index: u32) -> VarRef {
        VarRef::new(function, index)
    }

    /// Regression: `IsPointer` used to be silently discarded when it arrived
    /// *after* a signedness or width hint, because the join of `SignedInt(4)`
    /// (or `Sized(n)`) with `Pointer(_)` collapses to `Unknown`. The solved
    /// type therefore depended on constraint insertion order.
    ///
    /// Minimised from `property_tests::prop_solve_is_permutation_independent`
    /// (seed `0xC0FF_EE0A`).
    #[test]
    fn regression_pointer_hint_survives_regardless_of_insertion_order() {
        let v = var(0, 0);
        let ptr = ConstraintFact::IsPointer {
            var: v,
            pointee_size: None,
        };
        for other in [
            ConstraintFact::IsSigned { var: v },
            ConstraintFact::IsUnsigned { var: v },
            ConstraintFact::HasSize { var: v, size: 8 },
            ConstraintFact::HasSize { var: v, size: 4 },
        ] {
            let mut forward = TypeConstraintSolver::new();
            forward.add_facts([other.clone(), ptr.clone()]);
            let mut backward = TypeConstraintSolver::new();
            backward.add_facts([ptr.clone(), other.clone()]);
            let (f, b) = (forward.solve().type_of(v), backward.solve().type_of(v));
            assert_eq!(f, b, "order-dependent result for {other:?}");
            assert!(
                matches!(f, TypeFact::Pointer(_)),
                "pointer evidence lost for {other:?}: got {f:?}"
            );
        }
    }

    #[test]
    fn test_solver_has_size_produces_sized() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::HasSize { var: v, size: 4 });
        let sol = solver.solve();
        assert_eq!(sol.type_of(v), TypeFact::Sized(4));
    }

    #[test]
    fn test_solver_is_signed_upgrades_sized() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::HasSize { var: v, size: 4 });
        solver.add_fact(ConstraintFact::IsSigned { var: v });
        let sol = solver.solve();
        assert_eq!(sol.type_of(v), TypeFact::SignedInt(4));
    }

    #[test]
    fn test_solver_is_unsigned_upgrades_sized() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::HasSize { var: v, size: 2 });
        solver.add_fact(ConstraintFact::IsUnsigned { var: v });
        let sol = solver.solve();
        assert_eq!(sol.type_of(v), TypeFact::UnsignedInt(2));
    }

    #[test]
    fn test_solver_is_float() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::HasSize { var: v, size: 8 });
        solver.add_fact(ConstraintFact::IsFloat { var: v });
        let sol = solver.solve();
        assert_eq!(sol.type_of(v), TypeFact::Float(8));
    }

    #[test]
    fn test_solver_is_pointer() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::IsPointer {
            var: v,
            pointee_size: Some(4),
        });
        let sol = solver.solve();
        assert!(matches!(sol.type_of(v), TypeFact::Pointer(_)));
    }

    #[test]
    fn test_solver_same_type_propagates() {
        let mut solver = TypeConstraintSolver::new();
        let a = var(1, 0);
        let b = var(1, 1);
        solver.add_fact(ConstraintFact::HasSize { var: a, size: 8 });
        solver.add_fact(ConstraintFact::IsSigned { var: a });
        solver.add_fact(ConstraintFact::SameType { a, b });
        let sol = solver.solve();
        assert_eq!(sol.type_of(b), TypeFact::SignedInt(8));
    }

    #[test]
    fn test_solver_unknown_var_returns_unknown() {
        let _solver = TypeConstraintSolver::new();
        let sol = TypeSolution::new();
        assert_eq!(sol.type_of(var(99, 99)), TypeFact::Unknown);
    }

    #[test]
    fn test_type_store_intern_and_get() {
        let mut store = TypeStore::new();
        let id = store.intern(TypeFact::SignedInt(4));
        assert_eq!(store.get(id), Some(&TypeFact::SignedInt(4)));
    }

    #[test]
    fn test_merge_types() {
        let mut solver = TypeConstraintSolver::new();
        let a = solver.type_store.intern(TypeFact::Unknown);
        let b = solver.type_store.intern(TypeFact::Float(8));
        let merged = solver.merge_types(a, b);
        assert_eq!(solver.type_store.get(merged), Some(&TypeFact::Float(8)));
    }

    #[test]
    fn test_union_find_same_class() {
        let mut uf = UnionFind::new();
        let a = var(1, 0);
        let b = var(1, 1);
        let c = var(1, 2);
        uf.union(a, b);
        assert!(uf.same_class(a, b));
        assert!(!uf.same_class(a, c));
    }

    #[test]
    fn test_vtable_ptr_hint() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::IsVtablePtr { var: v });
        let sol = solver.solve();
        assert!(matches!(sol.type_of(v), TypeFact::Pointer(_)));
    }

    #[test]
    fn test_is_array_fact() {
        let mut solver = TypeConstraintSolver::new();
        let v = var(1, 0);
        solver.add_fact(ConstraintFact::IsArray {
            var: v,
            elem_size: 4,
            bound: Some(10),
        });
        let sol = solver.solve();
        assert!(matches!(sol.type_of(v), TypeFact::Array { .. }));
    }
}
