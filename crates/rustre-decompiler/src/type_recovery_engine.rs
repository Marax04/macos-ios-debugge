//! Type recovery engine — infers high-level types from MLIL/HLIL data-flow
//! patterns, calling conventions, and API signatures.
//!
//! The engine builds a constraint graph, solves it with a union-find lattice,
//! and emits `RecoveredType` annotations for each variable.
//!
//! # ⚠ Implementazione LEGACY, senza chiamanti
//!
//! Questo modulo NON e' l'API canonica: l'implementazione usata dalla pipeline
//! e' [`rustre_decompiler_type::type_recovery_engine`], ri-esportata qui sotto
//! come [`canonical`]. La differenza NON e' cosmetica — questo file espone
//! `RecoveredType` / `TypeVarId` / `recover_types`, mentre il crate dedicato
//! espone `ConstrainedType` / `TypeSolver` e produce `DecompType`, popolando un
//! [`rustre_decompiler_type::TypeEnvironment`] tramite
//! [`canonical::TypeRecoveryEngine::run`].
//!
//! Sostituirlo ORA richiederebbe tradurre due lattici di tipi distinti su
//! codice che non ha alcun chiamante: rischio alto, guadagno zero. Il merge
//! vero si fa DOPO la promozione del gate `RUSTRE_TYPE_ENV` (vedi
//! `lib.rs::build_type_env_from_vars`). RIPARARE, NON CANCELLARE.

/// API canonica del recupero tipi, nel crate dedicato `rustre-decompiler-type`.
///
/// Preferire questa a quanto definito nel resto del modulo: e' quella che la
/// pipeline istanzia realmente.
pub use rustre_decompiler_type::type_recovery_engine as canonical;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredType
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered type for a variable or expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecoveredType {
    /// Primitive integer.
    Int { width: u8, signed: bool },
    /// Floating-point value.
    Float { width: u8 },
    /// Pointer to another type.
    Pointer { pointee: Box<Self>, const_: bool },
    /// Fixed-size array.
    Array { elem: Box<Self>, count: usize },
    /// Struct with named fields (`field_name` → type).
    Struct { name: String, fields: Vec<(String, Self)> },
    /// C-style void (function return only).
    Void,
    /// Boolean (i1).
    Bool,
    /// Function pointer.
    FunctionPtr {
        return_type: Box<Self>,
        params: Vec<Self>,
    },
    /// Type is not yet determined (under-constrained).
    Unknown,
    /// Type is contradictory (over-constrained / conflict).
    Conflict,
}

impl RecoveredType {
    /// Return the bit-width of this type, or `None` for compound types.
    #[must_use]
    pub const fn bit_width(&self) -> Option<u32> {
        match self {
            Self::Int { width, .. } | Self::Float { width } => Some(*width as u32),
            Self::Pointer { .. } => Some(64), // target-dependent; assume 64-bit
            Self::Bool => Some(1),
            Self::Void => Some(0),
            _ => None,
        }
    }

    /// Return `true` if this is a pointer type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }

    /// Return `true` if this is an integer type.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(self, Self::Int { .. })
    }

    /// Return `true` if the type has been resolved (not Unknown/Conflict).
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        !matches!(self, Self::Unknown | Self::Conflict)
    }

    /// Attempt to widen this type to accommodate `other` (lattice join).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => t.clone(),
            (Self::Int { width: w1, signed: s1 }, Self::Int { width: w2, signed: s2 }) => {
                Self::Int { width: (*w1).max(*w2), signed: *s1 || *s2 }
            }
            _ => Self::Conflict,
        }
    }
}

impl fmt::Display for RecoveredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int { width, signed } => {
                write!(f, "{}{}", if *signed { "i" } else { "u" }, width)
            }
            Self::Float { width } => write!(f, "f{width}"),
            Self::Pointer { pointee, const_ } => {
                if *const_ {
                    write!(f, "const {pointee}*")
                } else {
                    write!(f, "{pointee}*")
                }
            }
            Self::Array { elem, count } => write!(f, "{elem}[{count}]"),
            Self::Struct { name, .. } => write!(f, "struct {name}"),
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::FunctionPtr { return_type, params } => {
                let param_str = params
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "({return_type})({param_str})")
            }
            Self::Unknown => write!(f, "?"),
            Self::Conflict => write!(f, "/*!*/"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// The unique identifier for a type variable in the constraint graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeVarId(pub u32);

impl fmt::Display for TypeVarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tv{}", self.0)
    }
}

/// A constraint between type variables or between a variable and a known type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeConstraint {
    /// `var == known_type` — direct assignment.
    Eq(TypeVarId, RecoveredType),
    /// `lhs == rhs` — two type variables must be the same.
    VarEq(TypeVarId, TypeVarId),
    /// `var` is a subtype of `bound` (width / signedness).
    SubWidth { var: TypeVarId, min_width: u8, signed: bool },
    /// `var` must be a pointer (pointee type unknown).
    IsPointer(TypeVarId),
    /// `var` is the pointee of `ptr_var`.
    Pointee { ptr_var: TypeVarId, pointee_var: TypeVarId },
    /// `var` must be an integer of any width.
    IsInteger(TypeVarId),
    /// `var` must be a floating-point type.
    IsFloat(TypeVarId),
    /// `result_var == lhs_var + rhs_var` — used for pointer arithmetic.
    Add { result_var: TypeVarId, lhs_var: TypeVarId, rhs_var: TypeVarId },
    /// `var` must satisfy the bit-mask pattern (all-zeros upper bits → narrow).
    BitMask { var: TypeVarId, mask: u64 },
}

impl TypeConstraint {
    /// Return the primary type variable referenced by this constraint.
    #[must_use]
    pub const fn primary_var(&self) -> TypeVarId {
        match self {
            Self::Eq(v, _)
            | Self::VarEq(v, _)
            | Self::SubWidth { var: v, .. }
            | Self::IsPointer(v)
            | Self::Pointee { ptr_var: v, .. }
            | Self::IsInteger(v)
            | Self::IsFloat(v)
            | Self::Add { result_var: v, .. }
            | Self::BitMask { var: v, .. } => *v,
        }
    }

    /// If this constraint relates two type variables (i.e. is an edge in the
    /// constraint graph), return that pair. Otherwise `None`.
    #[must_use]
    pub const fn endpoints(&self) -> Option<(TypeVarId, TypeVarId)> {
        match self {
            Self::VarEq(a, b) => Some((*a, *b)),
            Self::Pointee { ptr_var, pointee_var } => Some((*ptr_var, *pointee_var)),
            Self::Add { result_var, lhs_var, .. } => Some((*result_var, *lhs_var)),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Union-Find for type variable merging
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct UnionFind {
    parent: Vec<u32>,
    rank: Vec<u32>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..u32::try_from(n).unwrap_or(u32::MAX)).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: u32) -> u32 {
        if self.parent[x as usize] != x {
            let root = self.find(self.parent[x as usize]);
            self.parent[x as usize] = root;
        }
        self.parent[x as usize]
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

// ─────────────────────────────────────────────────────────────────────────────
// TypeRecoveryEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Inference result for a single type variable.
#[derive(Debug, Clone)]
pub struct InferredType {
    pub var: TypeVarId,
    pub ty: RecoveredType,
    pub confidence: u8,
    pub source: String,
}

/// Type recovery engine — collects constraints and solves them.
#[derive(Debug)]
pub struct TypeRecoveryEngine {
    /// Next type variable ID to assign.
    next_id: u32,
    /// All registered constraints.
    constraints: Vec<TypeConstraint>,
    /// Explicit ground-truth types (from API knowledge / debug info).
    ground_truth: HashMap<TypeVarId, RecoveredType>,
    /// Variable name → type variable mapping.
    var_names: HashMap<String, TypeVarId>,
    /// Solved types (populated after `solve()`).
    solutions: HashMap<TypeVarId, RecoveredType>,
    /// Whether the engine has been solved.
    solved: bool,
}

impl TypeRecoveryEngine {
    /// Create a new engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: 0,
            constraints: Vec::new(),
            ground_truth: HashMap::new(),
            var_names: HashMap::new(),
            solutions: HashMap::new(),
            solved: false,
        }
    }

    /// Allocate a fresh type variable.
    pub const fn fresh_var(&mut self) -> TypeVarId {
        let id = TypeVarId(self.next_id);
        self.next_id += 1;
        self.solved = false;
        id
    }

    /// Allocate a named type variable (or return existing one with that name).
    pub fn named_var(&mut self, name: impl Into<String>) -> TypeVarId {
        let name = name.into();
        if let Some(&id) = self.var_names.get(&name) {
            return id;
        }
        let id = self.fresh_var();
        self.var_names.insert(name, id);
        id
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
        self.solved = false;
    }

    /// Add a ground-truth type for a variable (from API knowledge or debug info).
    pub fn set_ground_truth(&mut self, var: TypeVarId, ty: RecoveredType) {
        self.ground_truth.insert(var, ty);
        self.solved = false;
    }

    /// Return the number of constraints registered.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// Solve all constraints and populate `solutions`.
    pub fn solve(&mut self) {
        let n = self.next_id as usize;
        if n == 0 {
            self.solved = true;
            return;
        }

        let mut uf = UnionFind::new(n);

        // Phase 1: merge VarEq constraints.
        for c in &self.constraints {
            if let TypeConstraint::VarEq(a, b) = c {
                uf.union(a.0, b.0);
            }
        }

        // Phase 2: collect known types per equivalence class.
        let mut class_types: HashMap<u32, RecoveredType> = HashMap::new();

        // Start with ground truth.
        for (&var, ty) in &self.ground_truth {
            let root = uf.find(var.0);
            let entry = class_types.entry(root).or_insert(RecoveredType::Unknown);
            *entry = entry.join(ty);
        }

        // Phases 3-7 merged into a single pass over the constraint list.
        // Eq and SubWidth joins are applied immediately (join is commutative,
        // so their relative order does not matter). The conditional hints
        // (IsPointer / IsInteger / IsFloat) only fire when a class is still
        // Unknown, so they are buffered and applied after all joins, in the
        // original phase order, to keep results identical.
        let mut pointer_hints: Vec<u32> = Vec::new();
        let mut integer_hints: Vec<u32> = Vec::new();
        let mut float_hints: Vec<u32> = Vec::new();

        for c in &self.constraints {
            match c {
                TypeConstraint::Eq(var, ty) => {
                    let root = uf.find(var.0);
                    let entry = class_types.entry(root).or_insert(RecoveredType::Unknown);
                    *entry = entry.join(ty);
                }
                TypeConstraint::SubWidth { var, min_width, signed } => {
                    let root = uf.find(var.0);
                    let entry = class_types.entry(root).or_insert(RecoveredType::Unknown);
                    *entry = entry.join(&RecoveredType::Int { width: *min_width, signed: *signed });
                }
                TypeConstraint::IsPointer(var) => pointer_hints.push(uf.find(var.0)),
                TypeConstraint::IsInteger(var) => integer_hints.push(uf.find(var.0)),
                TypeConstraint::IsFloat(var) => float_hints.push(uf.find(var.0)),
                _ => {}
            }
        }

        // Apply buffered hints in the original phase order (pointer, integer, float).
        for root in pointer_hints {
            let entry = class_types.entry(root).or_insert(RecoveredType::Unknown);
            if *entry == RecoveredType::Unknown {
                *entry = RecoveredType::Pointer {
                    pointee: Box::new(RecoveredType::Unknown),
                    const_: false,
                };
            }
        }
        for root in integer_hints {
            let entry = class_types.entry(root).or_insert(RecoveredType::Unknown);
            if *entry == RecoveredType::Unknown {
                *entry = RecoveredType::Int { width: 64, signed: false };
            }
        }
        for root in float_hints {
            let entry = class_types.entry(root).or_insert(RecoveredType::Unknown);
            if *entry == RecoveredType::Unknown {
                *entry = RecoveredType::Float { width: 64 };
            }
        }

        // Build final solutions: each variable → class representative type.
        self.solutions.clear();
        for i in 0..n {
            let root = uf.find(u32::try_from(i).unwrap_or(u32::MAX));
            let ty = class_types
                .get(&root)
                .cloned()
                .unwrap_or(RecoveredType::Unknown);
            self.solutions.insert(TypeVarId(u32::try_from(i).unwrap_or(u32::MAX)), ty);
        }

        self.solved = true;
    }

    /// Return the inferred type for a type variable.
    /// Calls `solve()` if not already solved.
    pub fn type_of(&mut self, var: TypeVarId) -> RecoveredType {
        if !self.solved {
            self.solve();
        }
        self.solutions
            .get(&var)
            .cloned()
            .unwrap_or(RecoveredType::Unknown)
    }

    /// Return the type of a named variable.
    pub fn type_of_named(&mut self, name: &str) -> Option<RecoveredType> {
        let var = *self.var_names.get(name)?;
        Some(self.type_of(var))
    }

    /// Return all inferred types as a sorted list.
    pub fn all_inferred(&mut self) -> Vec<InferredType> {
        if !self.solved {
            self.solve();
        }
        let name_map: HashMap<TypeVarId, &str> = self
            .var_names
            .iter()
            .map(|(n, &v)| (v, n.as_str()))
            .collect();

        let mut out: Vec<InferredType> = self
            .solutions
            .iter()
            .map(|(&var, ty)| {
                let source = name_map
                    .get(&var).map_or_else(|| var.to_string(), std::string::ToString::to_string);
                let confidence = match ty {
                    RecoveredType::Unknown => 0,
                    RecoveredType::Conflict => 10,
                    _ => {
                        if self.ground_truth.contains_key(&var) {
                            100
                        } else {
                            70
                        }
                    }
                };
                InferredType { var, ty: ty.clone(), confidence, source }
            })
            .collect();
        out.sort_by_key(|i| i.var.0);
        out
    }

    /// Return the number of variables with fully resolved types.
    pub fn resolved_count(&mut self) -> usize {
        if !self.solved { self.solve(); }
        self.solutions.values().filter(|t| t.is_resolved()).count()
    }

    /// Return the set of `TypeVarId`s that participate in at least one
    /// constraint with the given variable.
    ///
    /// Implemented as a BFS over the constraint graph (treating each
    /// [`TypeConstraint::VarEq`] / [`TypeConstraint::Pointee`] / [`TypeConstraint::Add`]
    /// as an undirected edge between its operands), up to `max_depth` hops.
    #[must_use]
    pub fn reachable_vars(&self, start: TypeVarId, max_depth: usize) -> HashSet<TypeVarId> {
        // Build the adjacency map once, then BFS over it (avoids rescanning
        // the whole constraint list for every dequeued node).
        let mut adjacency: HashMap<TypeVarId, Vec<TypeVarId>> = HashMap::new();
        for c in &self.constraints {
            if let Some((a, b)) = c.endpoints() {
                adjacency.entry(a).or_default().push(b);
                adjacency.entry(b).or_default().push(a);
            }
        }

        let mut visited: HashSet<TypeVarId> = HashSet::new();
        let mut queue: VecDeque<(TypeVarId, usize)> = VecDeque::new();
        visited.insert(start);
        queue.push_back((start, 0));

        while let Some((cur, depth)) = queue.pop_front() {
            if depth >= max_depth { continue; }
            if let Some(neighbours) = adjacency.get(&cur) {
                for &n in neighbours {
                    if visited.insert(n) {
                        queue.push_back((n, depth + 1));
                    }
                }
            }
        }
        visited
    }

    /// Reset the engine to its initial state.
    pub fn reset(&mut self) {
        self.next_id = 0;
        self.constraints.clear();
        self.ground_truth.clear();
        self.var_names.clear();
        self.solutions.clear();
        self.solved = false;
    }
}

impl Default for TypeRecoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// recover_types — high-level convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience wrapper: add all `constraints` to a fresh engine, solve, and
/// return the inferred types for all type variables.
#[must_use]
pub fn recover_types(constraints: Vec<TypeConstraint>) -> Vec<InferredType> {
    let mut engine = TypeRecoveryEngine::new();
    // Allocate variables referenced in constraints.
    let mut max_id = 0u32;
    for c in &constraints {
        let v = c.primary_var();
        if v.0 >= max_id {
            max_id = v.0 + 1;
        }
        // Also check secondary vars for VarEq / Pointee / Add.
        match c {
            TypeConstraint::VarEq(_, b) => { if b.0 >= max_id { max_id = b.0 + 1; } }
            TypeConstraint::Pointee { pointee_var, .. } => { if pointee_var.0 >= max_id { max_id = pointee_var.0 + 1; } }
            TypeConstraint::Add { lhs_var, rhs_var, .. } => {
                if lhs_var.0 >= max_id { max_id = lhs_var.0 + 1; }
                if rhs_var.0 >= max_id { max_id = rhs_var.0 + 1; }
            }
            _ => {}
        }
    }
    engine.next_id = max_id;
    for c in constraints {
        engine.add_constraint(c);
    }
    engine.all_inferred()
}

// ─────────────────────────────────────────────────────────────────────────────
// Known API type database
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight database of well-known API function signatures for seeding
/// the type recovery engine.
#[derive(Debug, Default)]
pub struct ApiTypeDatabase {
    /// Maps function name → (`return_type`, `param_types`).
    entries: HashMap<String, (RecoveredType, Vec<RecoveredType>)>,
}

impl ApiTypeDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a database pre-loaded with common C standard library signatures.
    #[must_use]
    pub fn with_libc() -> Self {
        let mut db = Self::new();
        let void_ptr = RecoveredType::Pointer { pointee: Box::new(RecoveredType::Void), const_: false };
        let char_ptr = RecoveredType::Pointer { pointee: Box::new(RecoveredType::Int { width: 8, signed: true }), const_: false };
        let u64_t = RecoveredType::Int { width: 64, signed: false };
        let i32_t = RecoveredType::Int { width: 32, signed: true };
        let u32_t = RecoveredType::Int { width: 32, signed: false };

        db.insert("malloc", (void_ptr.clone(), vec![u64_t.clone()]));
        db.insert("free", (RecoveredType::Void, vec![void_ptr.clone()]));
        db.insert("memcpy", (void_ptr.clone(), vec![void_ptr.clone(), void_ptr.clone(), u64_t.clone()]));
        db.insert("memset", (void_ptr.clone(), vec![void_ptr, i32_t.clone(), u64_t.clone()]));
        db.insert("strlen", (u64_t, vec![char_ptr.clone()]));
        db.insert("strcmp", (i32_t.clone(), vec![char_ptr.clone(), char_ptr.clone()]));
        db.insert("strcpy", (char_ptr.clone(), vec![char_ptr.clone(), char_ptr.clone()]));
        db.insert("printf", (i32_t, vec![char_ptr]));
        db.insert("exit", (RecoveredType::Void, vec![u32_t]));
        db
    }

    /// Insert an API entry.
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        sig: (RecoveredType, Vec<RecoveredType>),
    ) {
        self.entries.insert(name.into(), sig);
    }

    /// Look up a function's return type.
    #[must_use]
    pub fn return_type(&self, name: &str) -> Option<&RecoveredType> {
        self.entries.get(name).map(|(r, _)| r)
    }

    /// Look up a function's parameter types.
    #[must_use]
    pub fn param_types(&self, name: &str) -> Option<&[RecoveredType]> {
        self.entries.get(name).map(|(_, p)| p.as_slice())
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Seed constraints into `engine` for a call to `func_name` with the given
    /// argument and return type variables.
    pub fn seed_call(
        &self,
        engine: &mut TypeRecoveryEngine,
        func_name: &str,
        arg_vars: &[TypeVarId],
        ret_var: Option<TypeVarId>,
    ) {
        if let Some((ret_ty, param_tys)) = self.entries.get(func_name) {
            if let Some(rv) = ret_var {
                engine.add_constraint(TypeConstraint::Eq(rv, ret_ty.clone()));
            }
            for (i, &av) in arg_vars.iter().enumerate() {
                if let Some(pt) = param_tys.get(i) {
                    engine.add_constraint(TypeConstraint::Eq(av, pt.clone()));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Heap-base detection helper
// ─────────────────────────────────────────────────────────────────────────────

/// Scan `instructions` for CALL instructions targeting known allocators.
///
/// Returns the (`instruction_index`, `dst_register`) of each matching call
/// (`malloc` / `calloc` / `realloc` / `operator new`).  The returned register
/// is the one that holds the freshly allocated pointer immediately after the
/// call (`rax` on `x86_64` / `x0` on `aarch64`).  Struct-recovery uses this
/// to treat a heap allocation result as a distinct base for field-access
/// grouping, mirroring stack frames.
#[must_use]
pub fn detect_heap_bases(instructions: &[rustre_core::arch::Instruction]) -> Vec<(usize, &'static str)> {
    let names = ["malloc", "calloc", "realloc", "operator new", "_Znwm", "_Znam"];
    let mut out = Vec::new();
    for (idx, ins) in instructions.iter().enumerate() {
        if ins.mnemonic.to_lowercase() != "call" {
            continue;
        }
        let ops = ins.operands.to_lowercase();
        if names.iter().any(|n| ops.contains(n)) {
            // x86_64 returns in rax; that's the only arch supported by the
            // surface lifter at present.
            out.push((idx, "rax"));
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_eq_constraint() {
        let mut eng = TypeRecoveryEngine::new();
        let v = eng.fresh_var();
        eng.add_constraint(TypeConstraint::Eq(v, RecoveredType::Int { width: 32, signed: false }));
        let ty = eng.type_of(v);
        assert_eq!(ty, RecoveredType::Int { width: 32, signed: false });
    }

    #[test]
    fn var_eq_propagates() {
        let mut eng = TypeRecoveryEngine::new();
        let a = eng.fresh_var();
        let b = eng.fresh_var();
        eng.add_constraint(TypeConstraint::VarEq(a, b));
        eng.add_constraint(TypeConstraint::Eq(b, RecoveredType::Bool));
        assert_eq!(eng.type_of(a), RecoveredType::Bool);
    }

    #[test]
    fn join_integers_widens() {
        let t1 = RecoveredType::Int { width: 16, signed: false };
        let t2 = RecoveredType::Int { width: 32, signed: true };
        let joined = t1.join(&t2);
        assert_eq!(joined, RecoveredType::Int { width: 32, signed: true });
    }

    #[test]
    fn unknown_joined_is_other() {
        let t = RecoveredType::Bool;
        assert_eq!(RecoveredType::Unknown.join(&t), t);
    }

    #[test]
    fn api_db_libc() {
        let db = ApiTypeDatabase::with_libc();
        assert!(db.return_type("malloc").is_some());
        assert_eq!(db.param_types("strlen").unwrap().len(), 1);
    }

    #[test]
    fn recover_types_convenience() {
        let constraints = vec![
            TypeConstraint::Eq(TypeVarId(0), RecoveredType::Int { width: 64, signed: false }),
        ];
        let result = recover_types(constraints);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ty, RecoveredType::Int { width: 64, signed: false });
    }

    #[test]
    fn type_display() {
        let t = RecoveredType::Pointer {
            pointee: Box::new(RecoveredType::Int { width: 8, signed: true }),
            const_: true,
        };
        assert_eq!(t.to_string(), "const i8*");
    }
}
