//! `type_propagation` — Type propagation across function boundaries.
//!
//! Provides a type constraint system, interprocedural type propagation,
//! return/parameter type inference, global type inference, pointer chains,
//! and type equivalence classes.

use std::collections::HashMap;
pub use std::collections::{HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypePropError {
    UnknownFunction(u64),
    TypeConflict {
        var: String,
        type_a: String,
        type_b: String,
    },
    CyclicConstraint(String),
    InsufficientInformation(String),
}

impl fmt::Display for TypePropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFunction(a) => write!(f, "unknown function at {a:#x}"),
            Self::TypeConflict {
                var,
                type_a,
                type_b,
            } => {
                write!(f, "type conflict for '{var}': {type_a} vs {type_b}")
            }
            Self::CyclicConstraint(msg) => write!(f, "cyclic constraint: {msg}"),
            Self::InsufficientInformation(msg) => write!(f, "insufficient info: {msg}"),
        }
    }
}

impl std::error::Error for TypePropError {}

// ─── ReType ──────────────────────────────────────────────────────────────────

/// Recovered type representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReType {
    Unknown,
    Void,
    Bool,
    Int(IntSize),
    UInt(IntSize),
    Float(FloatSize),
    Pointer(Box<Self>),
    Array {
        element: Box<Self>,
        size: Option<usize>,
    },
    Struct(String),
    Enum(String),
    Function {
        params: Vec<Self>,
        ret: Box<Self>,
    },
    Char,
    WChar,
    /// Meets-all: the top of the lattice.
    Top,
    /// Joins-all: the bottom of the lattice (conflict).
    Bottom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntSize {
    I8,
    I16,
    I32,
    I64,
    ISize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FloatSize {
    F32,
    F64,
    F80,
}

impl ReType {
    #[must_use] 
    pub fn ptr(inner: Self) -> Self {
        Self::Pointer(Box::new(inner))
    }

    #[must_use] 
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    #[must_use] 
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Int(_) | Self::UInt(_) | Self::Char | Self::WChar
        )
    }

    #[must_use] 
    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }

    /// Least-upper-bound (meet) in the type lattice.
    #[must_use] 
    pub fn meet(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => t.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Pointer(_), Self::Pointer(_)) => {
                Self::ptr(Self::Unknown) // conservative
            }
            _ => Self::Bottom,
        }
    }

    #[must_use] 
    pub const fn byte_size(&self) -> Option<usize> {
        match self {
            Self::Bool | Self::Int(IntSize::I8) | Self::UInt(IntSize::I8) | Self::Char => {
                Some(1)
            }
            Self::Int(IntSize::I16) | Self::UInt(IntSize::I16) | Self::WChar => Some(2),
            Self::Int(IntSize::I32)
            | Self::UInt(IntSize::I32)
            | Self::Float(FloatSize::F32) => Some(4),
            Self::Int(IntSize::I64)
            | Self::UInt(IntSize::I64)
            | Self::Float(FloatSize::F64)
            // pointers assume a 64-bit target
            | Self::Pointer(_) => Some(8),
            Self::Float(FloatSize::F80) => Some(10),
            _ => None,
        }
    }
}

impl fmt::Display for ReType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "?"),
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::Int(IntSize::I8) => write!(f, "int8"),
            Self::Int(IntSize::I16) => write!(f, "int16"),
            Self::Int(IntSize::I32) => write!(f, "int32"),
            Self::Int(IntSize::I64) => write!(f, "int64"),
            Self::Int(IntSize::ISize) => write!(f, "intptr"),
            Self::UInt(IntSize::I8) => write!(f, "uint8"),
            Self::UInt(IntSize::I16) => write!(f, "uint16"),
            Self::UInt(IntSize::I32) => write!(f, "uint32"),
            Self::UInt(IntSize::I64) => write!(f, "uint64"),
            Self::UInt(IntSize::ISize) => write!(f, "uintptr"),
            Self::Float(FloatSize::F32) => write!(f, "float"),
            Self::Float(FloatSize::F64) => write!(f, "double"),
            Self::Float(FloatSize::F80) => write!(f, "long double"),
            Self::Char => write!(f, "char"),
            Self::WChar => write!(f, "wchar_t"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::Array { element, size } => match size {
                Some(n) => write!(f, "{element}[{n}]"),
                None => write!(f, "{element}[]"),
            },
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::Enum(name) => write!(f, "enum {name}"),
            Self::Function { params, ret } => {
                let param_str: Vec<_> = params.iter().map(std::string::ToString::to_string).collect();
                write!(f, "{}({})", ret, param_str.join(", "))
            }
            Self::Top => write!(f, "⊤"),
            Self::Bottom => write!(f, "⊥"),
        }
    }
}

// ─── TypeConstraint ──────────────────────────────────────────────────────────

/// A type constraint between two type variables or a variable and a known type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeConstraint {
    /// var must equal type.
    Equals { var: String, ty: ReType },
    /// `var_a` must equal `var_b`.
    SameAs { var_a: String, var_b: String },
    /// var must be a sub-type of ty.
    SubTypeOf { var: String, ty: ReType },
    /// var must be a pointer to `target_var`.
    PtrTo { var: String, target_var: String },
    /// var is the return type of a function call.
    ReturnOf { var: String, fn_addr: u64 },
    /// var is the n-th parameter type of a function call.
    ParamOf {
        var: String,
        fn_addr: u64,
        param_idx: usize,
    },
}

// ─── TypeConstraintSystem ─────────────────────────────────────────────────────

/// Collects and solves type constraints.
///
/// SUPERSEDED by `rustre_analysis_typerecov::type_unifier::TypeUnifier`, which is a
/// true union-find solver with a 10-variant constraint vocabulary, lattice refinement
/// and typed conflict errors. This system only ever implemented `Equals`/`SameAs`;
/// `SubTypeOf`/`PtrTo`/`ReturnOf`/`ParamOf` were declared but inert (silently ignored
/// by a `_ => {}` arm), so callers got a plausible-looking but information-free answer.
/// They now fail loudly via [`TypePropError::InsufficientInformation`] instead. The two
/// solvers do not share a type universe (`String`/[`ReType`] here vs `TypeVar(u32)`/
/// `RecoveredType` there), so no re-export/alias is possible; new code should use
/// `TypeUnifier` directly rather than adding constraints here.
#[derive(Debug, Default)]
pub struct TypeConstraintSystem {
    constraints: Vec<TypeConstraint>,
    /// Maps type-variable name → solved type.
    solution: HashMap<String, ReType>,
}

impl TypeConstraintSystem {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint.
    pub fn add(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
    }

    /// Solve constraints via simple unification.
    ///
    /// # Errors
    ///
    /// Returns a [`TypePropError`] if two constraints are contradictory and
    /// cannot be unified.
    pub fn solve(&mut self) -> Result<(), TypePropError> {
        let mut changed = true;
        let mut iters = 0;
        // `constraints` is never mutated during solving — only `solution` is.
        // Move it out for the duration of the fixpoint instead of cloning the
        // whole Vec on every iteration, and restore it before returning.
        let constraints = std::mem::take(&mut self.constraints);
        let mut result: Result<(), TypePropError> = Ok(());
        'solve: while changed && iters < 1000 {
            changed = false;
            iters += 1;
            for c in &constraints {
                match c {
                    TypeConstraint::Equals { var, ty } => {
                        let entry = self.solution.entry(var.clone()).or_insert(ReType::Unknown);
                        let new_ty = entry.meet(ty);
                        if *entry != new_ty {
                            *entry = new_ty;
                            changed = true;
                        }
                    }
                    TypeConstraint::SameAs { var_a, var_b } => {
                        let ty_a = self.solution.get(var_a).cloned().unwrap_or(ReType::Unknown);
                        let ty_b = self.solution.get(var_b).cloned().unwrap_or(ReType::Unknown);
                        let unified = ty_a.meet(&ty_b);
                        let ea = self
                            .solution
                            .entry(var_a.clone())
                            .or_insert(ReType::Unknown);
                        if *ea != unified {
                            *ea = unified.clone();
                            changed = true;
                        }
                        let eb = self
                            .solution
                            .entry(var_b.clone())
                            .or_insert(ReType::Unknown);
                        if *eb != unified {
                            *eb = unified;
                            changed = true;
                        }
                    }
                    // Never implemented here. Silently ignoring them made an
                    // unsolved constraint indistinguishable from a solved one;
                    // use `TypeUnifier` (typerecov) for these.
                    TypeConstraint::SubTypeOf { var, .. } => {
                        result = Err(TypePropError::InsufficientInformation(format!(
                            "SubTypeOf on '{var}' is not supported by TypeConstraintSystem; use TypeUnifier"
                        )));
                        break 'solve;
                    }
                    TypeConstraint::PtrTo { var, .. } => {
                        result = Err(TypePropError::InsufficientInformation(format!(
                            "PtrTo on '{var}' is not supported by TypeConstraintSystem; use TypeUnifier"
                        )));
                        break 'solve;
                    }
                    TypeConstraint::ReturnOf { var, .. } => {
                        result = Err(TypePropError::InsufficientInformation(format!(
                            "ReturnOf on '{var}' is not supported by TypeConstraintSystem; use TypeUnifier"
                        )));
                        break 'solve;
                    }
                    TypeConstraint::ParamOf { var, .. } => {
                        result = Err(TypePropError::InsufficientInformation(format!(
                            "ParamOf on '{var}' is not supported by TypeConstraintSystem; use TypeUnifier"
                        )));
                        break 'solve;
                    }
                }
            }
        }
        self.constraints = constraints;
        result
    }

    /// Get the solved type for a variable.
    #[must_use] 
    pub fn get(&self, var: &str) -> ReType {
        self.solution.get(var).cloned().unwrap_or(ReType::Unknown)
    }

    /// Number of constraints.
    #[must_use] 
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// All solved type assignments.
    #[must_use] 
    pub const fn all_solutions(&self) -> &HashMap<String, ReType> {
        &self.solution
    }
}

// ─── FunctionTypeSig ─────────────────────────────────────────────────────────

/// Recovered function type signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTypeSig {
    pub address: u64,
    pub name: Option<String>,
    pub params: Vec<ReType>,
    pub return_type: ReType,
    pub is_variadic: bool,
    pub confidence: f64,
}

impl FunctionTypeSig {
    #[must_use] 
    pub const fn new(address: u64, params: Vec<ReType>, return_type: ReType) -> Self {
        Self {
            address,
            name: None,
            params,
            return_type,
            is_variadic: false,
            confidence: 0.5,
        }
    }
}

// ─── ReturnTypeInference ─────────────────────────────────────────────────────

/// Infers a function's return type from its return sites.
pub struct ReturnTypeInference;

impl ReturnTypeInference {
    /// Infer return type from a list of types observed at return sites.
    #[must_use] 
    pub fn infer(return_site_types: &[ReType]) -> ReType {
        if return_site_types.is_empty() {
            return ReType::Void;
        }
        let mut result = return_site_types[0].clone();
        for ty in return_site_types.iter().skip(1) {
            result = result.meet(ty);
            if result == ReType::Bottom {
                return ReType::Unknown;
            }
        }
        result
    }
}

// ─── ParameterTypeInference ───────────────────────────────────────────────────

/// Infers parameter types from call sites.
pub struct ParameterTypeInference;

impl ParameterTypeInference {
    /// Infer parameter types from multiple call sites.
    /// `call_sites`: each is a vec of argument types at one call site.
    #[must_use] 
    pub fn infer(call_sites: &[Vec<ReType>]) -> Vec<ReType> {
        if call_sites.is_empty() {
            return Vec::new();
        }
        let max_params = call_sites.iter().map(std::vec::Vec::len).max().unwrap_or(0);
        let mut params = Vec::with_capacity(max_params);
        for i in 0..max_params {
            let types_at_i: Vec<&ReType> = call_sites.iter().filter_map(|cs| cs.get(i)).collect();
            let mut inferred = types_at_i
                .first()
                .copied()
                .cloned()
                .unwrap_or(ReType::Unknown);
            for ty in types_at_i.iter().skip(1) {
                inferred = inferred.meet(ty);
            }
            params.push(inferred);
        }
        params
    }
}

// ─── GlobalTypeInference ─────────────────────────────────────────────────────

/// Infers types of global variables from how they are accessed.
#[derive(Debug, Default)]
pub struct GlobalTypeInference {
    /// Global address → list of inferred types from accesses.
    evidence: HashMap<u64, Vec<ReType>>,
}

impl GlobalTypeInference {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a type observation for a global.
    pub fn observe(&mut self, global_addr: u64, ty: ReType) {
        self.evidence.entry(global_addr).or_default().push(ty);
    }

    /// Infer the final type for a global.
    #[must_use] 
    pub fn infer(&self, global_addr: u64) -> ReType {
        let Some(tys) = self.evidence.get(&global_addr) else {
            return ReType::Unknown;
        };
        ReturnTypeInference::infer(tys)
    }

    /// Infer types for all observed globals.
    #[must_use] 
    pub fn infer_all(&self) -> HashMap<u64, ReType> {
        self.evidence
            .keys()
            .map(|&addr| (addr, self.infer(addr)))
            .collect()
    }
}

// ─── PointerTypeChain ─────────────────────────────────────────────────────────

/// Tracks pointer dereference chains to infer nested pointer types.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PointerTypeChain {
    /// Maps each variable/address to its inferred type after dereferencing.
    pub chain: HashMap<String, ReType>,
    /// Dereference relationships: a → *a.
    pub deref: HashMap<String, String>,
}

impl PointerTypeChain {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `ptr` dereferences to `target`.
    pub fn add_deref(&mut self, ptr: impl Into<String>, target: impl Into<String>) {
        self.deref.insert(ptr.into(), target.into());
    }

    /// Set the known type of a variable.
    pub fn set_type(&mut self, var: impl Into<String>, ty: ReType) {
        self.chain.insert(var.into(), ty);
    }

    /// Propagate types through the dereference chain.
    ///
    /// A dereference *cycle* (e.g. `a → b`, `b → a`) would otherwise grow
    /// `Ptr(Ptr(…))` forever and never reach a fixed point, so the loop is
    /// capped at `deref.len()` passes — an acyclic chain of length `k` needs
    /// at most `k` passes to converge. Edges are processed in sorted order so
    /// the (capped) result is deterministic.
    pub fn propagate(&mut self) {
        let mut edges: Vec<(String, String)> = self
            .deref
            .iter()
            .map(|(p, t)| (p.clone(), t.clone()))
            .collect();
        edges.sort();
        let max_passes = edges.len();
        let mut changed = true;
        let mut passes = 0;
        while changed && passes < max_passes {
            changed = false;
            passes += 1;
            for (ptr, target) in &edges {
                if let Some(target_ty) = self.chain.get(target).cloned() {
                    let ptr_ty = ReType::ptr(target_ty);
                    let entry = self.chain.entry(ptr.clone()).or_insert(ReType::Unknown);
                    if *entry != ptr_ty {
                        *entry = ptr_ty;
                        changed = true;
                    }
                }
            }
        }
    }

    /// Get the type of a variable (resolved through chain).
    #[must_use] 
    pub fn get(&self, var: &str) -> ReType {
        self.chain.get(var).cloned().unwrap_or(ReType::Unknown)
    }
}

// ─── TypeEquivalenceClass ─────────────────────────────────────────────────────

/// Union-Find based type equivalence class tracking.
#[derive(Debug, Default)]
pub struct TypeEquivalenceClass {
    parent: HashMap<String, String>,
    rank: HashMap<String, usize>,
    /// Type assigned to the canonical representative.
    types: HashMap<String, ReType>,
}

impl TypeEquivalenceClass {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Find the canonical representative of a variable's class.
    pub fn find(&mut self, x: &str) -> String {
        if !self.parent.contains_key(x) {
            self.parent.insert(x.to_string(), x.to_string());
            self.rank.insert(x.to_string(), 0);
        }
        let parent = self.parent[x].clone();
        if parent == x {
            return x.to_string();
        }
        let root = self.find(&parent);
        self.parent.insert(x.to_string(), root.clone());
        root
    }

    /// Union two variables into the same equivalence class.
    pub fn union(&mut self, x: &str, y: &str) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return;
        }
        let rank_x = self.rank.get(&rx).copied().unwrap_or(0);
        let rank_y = self.rank.get(&ry).copied().unwrap_or(0);
        let (root, child) = if rank_x >= rank_y {
            (rx, ry)
        } else {
            (ry, rx)
        };
        self.parent.insert(child, root.clone());
        if rank_x == rank_y {
            *self.rank.entry(root).or_insert(0) += 1;
        }
    }

    /// Assign a type to a variable's equivalence class.
    pub fn assign_type(&mut self, x: &str, ty: ReType) {
        let root = self.find(x);
        self.types.insert(root, ty);
    }

    /// Get the type for a variable's equivalence class.
    pub fn get_type(&mut self, x: &str) -> ReType {
        let root = self.find(x);
        self.types.get(&root).cloned().unwrap_or(ReType::Unknown)
    }

    /// Check if two variables are in the same equivalence class.
    pub fn same_class(&mut self, x: &str, y: &str) -> bool {
        self.find(x) == self.find(y)
    }
}

// ─── InterproceduralTypes ─────────────────────────────────────────────────────

/// Tracks interprocedural type information across a call graph.
#[derive(Debug, Default)]
pub struct InterproceduralTypes {
    pub function_sigs: HashMap<u64, FunctionTypeSig>,
    /// Call edges: `caller_addr` → vec of `(callee_addr, argument types)`.
    ///
    /// The argument types are the ones observed AT THE CALL SITE. They are
    /// what interprocedural propagation is about; the caller's own parameter
    /// types are unrelated information (see [`Self::propagate`]). An edge
    /// added through [`Self::add_call`] carries no argument types and so
    /// propagates nothing.
    call_graph: HashMap<u64, Vec<(u64, Vec<ReType>)>>,
}

impl InterproceduralTypes {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a known function signature.
    pub fn register_sig(&mut self, sig: FunctionTypeSig) {
        self.function_sigs.insert(sig.address, sig);
    }

    /// Add a call edge with no argument type information.
    ///
    /// Such an edge contributes nothing to [`Self::propagate`] — there is no
    /// argument type to propagate. Use [`Self::add_call_with_args`] to record
    /// the types observed at the call site.
    pub fn add_call(&mut self, from_fn: u64, to_fn: u64) {
        self.call_graph
            .entry(from_fn)
            .or_default()
            .push((to_fn, Vec::new()));
    }

    /// Add a call edge carrying the argument types observed at the call site.
    pub fn add_call_with_args(&mut self, from_fn: u64, to_fn: u64, arg_types: Vec<ReType>) {
        self.call_graph
            .entry(from_fn)
            .or_default()
            .push((to_fn, arg_types));
    }

    /// Get the signature for a function.
    #[must_use] 
    pub fn sig(&self, addr: u64) -> Option<&FunctionTypeSig> {
        self.function_sigs.get(&addr)
    }

    /// Propagate types along call edges.
    ///
    /// When a caller passes a typed argument to a callee with `Unknown` param
    /// type, the callee's param type is updated.
    ///
    /// The types propagated are the ones recorded AT THE CALL SITE via
    /// [`Self::add_call_with_args`]. This used to copy the CALLER'S OWN
    /// parameter types positionally into the callee's slots, which is
    /// unrelated information: `main(int argc, char **argv)` calling
    /// `f(double, size_t)` typed `f` as `(int, char**)` — confidently, and
    /// wrongly. Edges with no recorded arguments now propagate nothing, which
    /// is the honest answer when the call site's types are unknown.
    pub fn propagate(&mut self) -> usize {
        let mut updates = 0;
        // Iterate callers in sorted address order: the first caller to reach a
        // callee with an Unknown param wins, so hash-order iteration would make
        // the winner (and thus the propagated types) nondeterministic.
        let mut call_graph_clone: Vec<(u64, Vec<(u64, Vec<ReType>)>)> = self
            .call_graph
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        call_graph_clone.sort_by_key(|(addr, _)| *addr);
        for (_caller_addr, callees) in &call_graph_clone {
            for (callee_addr, arg_types) in callees {
                if arg_types.is_empty() {
                    continue;
                }
                if let Some(dst) = self.function_sigs.get_mut(callee_addr) {
                    for (i, arg_ty) in arg_types.iter().enumerate() {
                        if i < dst.params.len()
                            && dst.params[i] == ReType::Unknown
                            && *arg_ty != ReType::Unknown
                        {
                            dst.params[i] = arg_ty.clone();
                            updates += 1;
                        }
                    }
                }
            }
        }
        updates
    }

    /// Number of registered function signatures.
    #[must_use] 
    pub fn sig_count(&self) -> usize {
        self.function_sigs.len()
    }
}

// ─── TypePropagator ──────────────────────────────────────────────────────────

/// Orchestrates all type propagation passes.
pub struct TypePropagator {
    pub constraints: TypeConstraintSystem,
    pub interprocedural: InterproceduralTypes,
    pub global_types: GlobalTypeInference,
    pub pointer_chain: PointerTypeChain,
    pub equivalences: TypeEquivalenceClass,
}

impl TypePropagator {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            constraints: TypeConstraintSystem::new(),
            interprocedural: InterproceduralTypes::new(),
            global_types: GlobalTypeInference::new(),
            pointer_chain: PointerTypeChain::new(),
            equivalences: TypeEquivalenceClass::new(),
        }
    }

    /// Run all propagation passes.
    ///
    /// # Errors
    ///
    /// Returns a [`TypePropError`] if constraint solving fails due to
    /// contradictory type constraints.
    pub fn run(&mut self) -> Result<usize, TypePropError> {
        self.constraints.solve()?;
        let updates = self.interprocedural.propagate();
        self.pointer_chain.propagate();
        Ok(updates)
    }

    /// Query the best-known type for a variable.
    pub fn query_type(&mut self, var: &str) -> ReType {
        let from_constraints = self.constraints.get(var);
        if !from_constraints.is_unknown() {
            return from_constraints;
        }
        self.equivalences.get_type(var)
    }
}

impl Default for TypePropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retype_display_int32() {
        assert_eq!(ReType::Int(IntSize::I32).to_string(), "int32");
    }

    #[test]
    fn retype_display_pointer() {
        let ty = ReType::ptr(ReType::Char);
        assert_eq!(ty.to_string(), "char*");
    }

    #[test]
    fn retype_is_pointer() {
        assert!(ReType::ptr(ReType::Void).is_pointer());
        assert!(!ReType::Int(IntSize::I32).is_pointer());
    }

    #[test]
    fn retype_is_integer() {
        assert!(ReType::Int(IntSize::I64).is_integer());
        assert!(!ReType::Float(FloatSize::F32).is_integer());
    }

    #[test]
    fn retype_meet_same() {
        let a = ReType::Int(IntSize::I32);
        assert_eq!(a.meet(&a), a);
    }

    #[test]
    fn retype_meet_unknown() {
        let a = ReType::Unknown;
        let b = ReType::Int(IntSize::I32);
        assert_eq!(a.meet(&b), b);
    }

    #[test]
    fn retype_meet_conflict() {
        let a = ReType::Int(IntSize::I32);
        let b = ReType::Float(FloatSize::F32);
        assert_eq!(a.meet(&b), ReType::Bottom);
    }

    #[test]
    fn retype_byte_size() {
        assert_eq!(ReType::Int(IntSize::I32).byte_size(), Some(4));
        assert_eq!(ReType::Float(FloatSize::F64).byte_size(), Some(8));
        assert_eq!(ReType::Bool.byte_size(), Some(1));
    }

    #[test]
    fn constraint_system_equals() {
        let mut cs = TypeConstraintSystem::new();
        cs.add(TypeConstraint::Equals {
            var: "x".into(),
            ty: ReType::Int(IntSize::I32),
        });
        cs.solve().unwrap();
        assert_eq!(cs.get("x"), ReType::Int(IntSize::I32));
    }

    #[test]
    fn constraint_system_same_as() {
        let mut cs = TypeConstraintSystem::new();
        cs.add(TypeConstraint::Equals {
            var: "a".into(),
            ty: ReType::UInt(IntSize::I64),
        });
        cs.add(TypeConstraint::SameAs {
            var_a: "a".into(),
            var_b: "b".into(),
        });
        cs.solve().unwrap();
        assert_eq!(cs.get("b"), ReType::UInt(IntSize::I64));
    }

    /// Negative test: the four never-implemented constraint kinds must fail
    /// loudly rather than be silently dropped (see TypeUnifier in typerecov).
    #[test]
    fn constraint_system_rejects_unimplemented_kinds() {
        for c in [
            TypeConstraint::SubTypeOf {
                var: "x".into(),
                ty: ReType::UInt(IntSize::I64),
            },
            TypeConstraint::PtrTo {
                var: "x".into(),
                target_var: "y".into(),
            },
            TypeConstraint::ReturnOf {
                var: "x".into(),
                fn_addr: 0x1000,
            },
            TypeConstraint::ParamOf {
                var: "x".into(),
                fn_addr: 0x1000,
                param_idx: 0,
            },
        ] {
            let mut cs = TypeConstraintSystem::new();
            cs.add(c);
            let err = cs.solve().expect_err("must not silently succeed");
            assert!(matches!(err, TypePropError::InsufficientInformation(_)));
            // and it must not have invented a solution
            assert_eq!(cs.get("x"), ReType::Unknown);
        }
    }

    /// Positive control: the two implemented kinds still solve.
    #[test]
    fn constraint_system_supported_kinds_still_solve() {
        let mut cs = TypeConstraintSystem::new();
        cs.add(TypeConstraint::Equals {
            var: "a".into(),
            ty: ReType::UInt(IntSize::I32),
        });
        cs.add(TypeConstraint::SameAs {
            var_a: "a".into(),
            var_b: "b".into(),
        });
        assert!(cs.solve().is_ok());
        assert_eq!(cs.get("b"), ReType::UInt(IntSize::I32));
    }

    #[test]
    fn constraint_system_unknown_var() {
        let cs = TypeConstraintSystem::new();
        assert_eq!(cs.get("nonexistent"), ReType::Unknown);
    }

    #[test]
    fn constraint_count() {
        let mut cs = TypeConstraintSystem::new();
        cs.add(TypeConstraint::Equals {
            var: "x".into(),
            ty: ReType::Bool,
        });
        assert_eq!(cs.constraint_count(), 1);
    }

    #[test]
    fn return_type_inference_void() {
        assert_eq!(ReturnTypeInference::infer(&[]), ReType::Void);
    }

    #[test]
    fn return_type_inference_consistent() {
        let tys = vec![ReType::Int(IntSize::I32), ReType::Int(IntSize::I32)];
        assert_eq!(ReturnTypeInference::infer(&tys), ReType::Int(IntSize::I32));
    }

    #[test]
    fn return_type_inference_conflicting() {
        let tys = vec![ReType::Int(IntSize::I32), ReType::Float(FloatSize::F32)];
        // Conflict → Unknown.
        assert_eq!(ReturnTypeInference::infer(&tys), ReType::Unknown);
    }

    #[test]
    fn parameter_type_inference_single_call() {
        let calls = vec![vec![ReType::Char, ReType::Int(IntSize::I32)]];
        let params = ParameterTypeInference::infer(&calls);
        assert_eq!(params[0], ReType::Char);
        assert_eq!(params[1], ReType::Int(IntSize::I32));
    }

    #[test]
    fn parameter_type_inference_multiple_calls() {
        let calls = vec![
            vec![ReType::Int(IntSize::I32)],
            vec![ReType::Int(IntSize::I32)],
        ];
        let params = ParameterTypeInference::infer(&calls);
        assert_eq!(params[0], ReType::Int(IntSize::I32));
    }

    #[test]
    fn global_type_inference_observe_and_infer() {
        let mut gi = GlobalTypeInference::new();
        gi.observe(0x1000, ReType::Int(IntSize::I32));
        gi.observe(0x1000, ReType::Int(IntSize::I32));
        assert_eq!(gi.infer(0x1000), ReType::Int(IntSize::I32));
    }

    #[test]
    fn global_type_inference_unknown() {
        let gi = GlobalTypeInference::new();
        assert_eq!(gi.infer(0xDEAD), ReType::Unknown);
    }

    #[test]
    fn pointer_chain_propagate() {
        let mut chain = PointerTypeChain::new();
        chain.set_type("target", ReType::Int(IntSize::I32));
        chain.add_deref("ptr", "target");
        chain.propagate();
        assert_eq!(chain.get("ptr"), ReType::ptr(ReType::Int(IntSize::I32)));
    }

    #[test]
    fn pointer_chain_no_deref() {
        let chain = PointerTypeChain::new();
        assert_eq!(chain.get("unknown_var"), ReType::Unknown);
    }

    #[test]
    fn equivalence_class_union_find() {
        let mut ec = TypeEquivalenceClass::new();
        ec.union("a", "b");
        assert!(ec.same_class("a", "b"));
        assert!(!ec.same_class("a", "c"));
    }

    #[test]
    fn equivalence_class_assign_and_get() {
        let mut ec = TypeEquivalenceClass::new();
        ec.assign_type("x", ReType::Int(IntSize::I64));
        assert_eq!(ec.get_type("x"), ReType::Int(IntSize::I64));
    }

    #[test]
    fn equivalence_class_shared_type() {
        let mut ec = TypeEquivalenceClass::new();
        ec.union("a", "b");
        ec.assign_type("a", ReType::Bool);
        assert_eq!(ec.get_type("b"), ReType::Bool);
    }

    #[test]
    fn interprocedural_register_sig() {
        let mut ipt = InterproceduralTypes::new();
        let sig = FunctionTypeSig::new(0x1000, vec![ReType::Int(IntSize::I32)], ReType::Void);
        ipt.register_sig(sig);
        assert!(ipt.sig(0x1000).is_some());
        assert_eq!(ipt.sig_count(), 1);
    }

    #[test]
    fn type_propagator_run() {
        let mut tp = TypePropagator::new();
        tp.constraints.add(TypeConstraint::Equals {
            var: "result".into(),
            ty: ReType::Int(IntSize::I32),
        });
        tp.run().unwrap();
        assert_eq!(tp.query_type("result"), ReType::Int(IntSize::I32));
    }

    #[test]
    fn type_error_display() {
        let e = TypePropError::UnknownFunction(0x4000);
        assert!(e.to_string().contains("0x4000"));
    }

    #[test]
    fn retype_display_function() {
        let ty = ReType::Function {
            params: vec![ReType::Int(IntSize::I32)],
            ret: Box::new(ReType::Void),
        };
        assert!(ty.to_string().contains("void"));
    }

    /// Regression: `PointerTypeChain::propagate` looped forever on a
    /// dereference cycle (`a → b`, `b → a`), growing `Ptr(Ptr(…))` without
    /// bound. It must now terminate.
    #[test]
    fn pointer_chain_propagate_terminates_on_deref_cycle() {
        let mut pc = PointerTypeChain::new();
        pc.add_deref("a", "b");
        pc.add_deref("b", "a");
        pc.set_type("a", ReType::Int(IntSize::I32));
        pc.propagate(); // must return, not hang
        assert!(pc.get("b").is_pointer());
    }

    /// Acyclic chains still converge fully under the new iteration cap.
    #[test]
    fn pointer_chain_propagate_converges_on_long_chain() {
        let mut pc = PointerTypeChain::new();
        // p0 → p1 → … → p9, p9 has a concrete type.
        for i in 0..9 {
            pc.add_deref(format!("p{i}"), format!("p{}", i + 1));
        }
        pc.set_type("p9", ReType::Char);
        pc.propagate();
        // p0 must have picked up a 9-deep pointer type.
        let mut expected = ReType::Char;
        for _ in 0..9 {
            expected = ReType::ptr(expected);
        }
        assert_eq!(pc.get("p0"), expected);
    }

    /// Regression: `InterproceduralTypes::propagate` iterated the call graph
    /// in HashMap order, so when two callers raced to fill a callee's Unknown
    /// param, the winner was nondeterministic. The lowest caller address must
    /// now win, consistently.
    #[test]
    fn interprocedural_propagate_is_deterministic() {
        fn build() -> InterproceduralTypes {
            let mut it = InterproceduralTypes::new();
            it.register_sig(FunctionTypeSig::new(
                0x100,
                vec![ReType::Int(IntSize::I32)],
                ReType::Void,
            ));
            it.register_sig(FunctionTypeSig::new(
                0x200,
                vec![ReType::ptr(ReType::Char)],
                ReType::Void,
            ));
            it.register_sig(FunctionTypeSig::new(
                0x300,
                vec![ReType::Unknown],
                ReType::Void,
            ));
            // Two call sites racing to fill 0x300's Unknown param, each
            // passing a different argument type. (These are the CALL-SITE
            // argument types; the test used to rely on `propagate` copying the
            // callers' own parameter types, which is the defect it now guards
            // against — its subject, deterministic resolution of the race, is
            // unchanged.)
            it.add_call_with_args(0x100, 0x300, vec![ReType::Int(IntSize::I32)]);
            it.add_call_with_args(0x200, 0x300, vec![ReType::ptr(ReType::Char)]);
            it
        }
        for _ in 0..20 {
            let mut it = build();
            it.propagate();
            assert_eq!(
                it.sig(0x300).unwrap().params[0],
                ReType::Int(IntSize::I32),
                "lowest-address caller must win deterministically"
            );
        }
    }

    /// Property: `TypeConstraintSystem::solve` is independent of the order in
    /// which constraints were added (meet is commutative/associative and the
    /// solver runs to a fixed point).
    #[test]
    fn constraint_solve_is_order_independent() {
        let pool = vec![
            TypeConstraint::Equals {
                var: "a".into(),
                ty: ReType::Int(IntSize::I32),
            },
            TypeConstraint::SameAs {
                var_a: "a".into(),
                var_b: "b".into(),
            },
            TypeConstraint::SameAs {
                var_a: "b".into(),
                var_b: "c".into(),
            },
            TypeConstraint::Equals {
                var: "d".into(),
                ty: ReType::ptr(ReType::Char),
            },
            TypeConstraint::SameAs {
                var_a: "d".into(),
                var_b: "e".into(),
            },
            TypeConstraint::Equals {
                var: "c".into(),
                ty: ReType::Int(IntSize::I32),
            },
        ];
        let solve = |cs: &[TypeConstraint]| {
            let mut sys = TypeConstraintSystem::new();
            for c in cs {
                sys.add(c.clone());
            }
            sys.solve().unwrap();
            ["a", "b", "c", "d", "e"]
                .iter()
                .map(|v| sys.get(v))
                .collect::<Vec<_>>()
        };
        let base = solve(&pool);
        // All rotations plus reversed order.
        for r in 0..pool.len() {
            let mut p = pool.clone();
            p.rotate_left(r);
            assert_eq!(solve(&p), base, "rotation {r} changed the solution");
            p.reverse();
            assert_eq!(solve(&p), base, "reversed rotation {r} changed the solution");
        }
    }
}
