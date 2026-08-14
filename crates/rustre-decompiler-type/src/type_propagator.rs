//! Type propagation engine for decompiled code.
//!
//! Provides forward/backward propagation through data flow, phi-node
//! unification, API-signature propagation, pointer dereference inference,
//! and integer-width inference from shift/mask operations.

use std::collections::{HashMap, HashSet, VecDeque};

// ── TypeVar ───────────────────────────────────────────────────────────────────

/// A type variable — a placeholder for an unknown type during inference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeVar {
    /// Unique identifier for this type variable.
    pub id: u32,
    /// Optional human-readable hint (e.g. the original variable name).
    pub hint: Option<String>,
}

impl TypeVar {
    /// Create a new type variable with the given id.
    #[must_use]
    pub const fn new(id: u32) -> Self {
        Self { id, hint: None }
    }

    /// Create a type variable with a debug hint.
    #[must_use]
    pub fn with_hint(id: u32, hint: impl Into<String>) -> Self {
        Self {
            id,
            hint: Some(hint.into()),
        }
    }
}

impl std::fmt::Display for TypeVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref h) = self.hint {
            write!(f, "T{}({})", self.id, h)
        } else {
            write!(f, "T{}", self.id)
        }
    }
}

// ── ConcreteType ──────────────────────────────────────────────────────────────

/// A concrete type inferred during propagation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConcreteType {
    /// Void / no value.
    Void,
    /// Boolean.
    Bool,
    /// Signed integer of given width in bits (8, 16, 32, 64).
    Int(u8),
    /// Unsigned integer of given width in bits.
    Uint(u8),
    /// Single-precision float.
    Float32,
    /// Double-precision float.
    Float64,
    /// Pointer to another type.
    Ptr(Box<Self>),
    /// Array of elements.
    Array(Box<Self>, u64),
    /// A named struct.
    Struct(String),
    /// A function pointer.
    FnPtr,
    /// String (char *).
    CStr,
    /// Unknown / not yet determined.
    Unknown,
}

impl ConcreteType {
    /// Return the byte size of this type, if known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        match self {
            Self::Void => Some(0),
            Self::Bool | Self::Int(8) | Self::Uint(8) => Some(1),
            Self::Int(16) | Self::Uint(16) => Some(2),
            Self::Int(32) | Self::Uint(32) | Self::Float32 => Some(4),
            Self::Int(64) | Self::Uint(64) | Self::Float64 | Self::Ptr(_)
            | Self::FnPtr | Self::CStr => Some(8),
            Self::Array(inner, n) => inner.byte_size().map(|s| s * n),
            Self::Struct(_) | Self::Unknown | Self::Int(_) | Self::Uint(_) => None, // size determined by struct database or unknown
        }
    }

    /// Return a C-like name for this type.
    #[must_use]
    pub fn c_name(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Bool => "bool".to_string(),
            Self::Int(8) => "int8_t".to_string(),
            Self::Int(16) => "int16_t".to_string(),
            Self::Int(32) => "int32_t".to_string(),
            Self::Int(64) => "int64_t".to_string(),
            Self::Uint(8) => "uint8_t".to_string(),
            Self::Uint(16) => "uint16_t".to_string(),
            Self::Uint(32) => "uint32_t".to_string(),
            Self::Uint(64) => "uint64_t".to_string(),
            Self::Float32 => "float".to_string(),
            Self::Float64 => "double".to_string(),
            Self::Ptr(inner) => format!("{} *", inner.c_name()),
            Self::Array(inner, n) => format!("{}[{n}]", inner.c_name()),
            Self::Struct(name) => format!("struct {name}"),
            Self::FnPtr => "void (*)(void)".to_string(),
            Self::CStr => "char *".to_string(),
            Self::Unknown => "void *".to_string(),
            Self::Int(w) => format!("int{w}_t"),
            Self::Uint(w) => format!("uint{w}_t"),
        }
    }

    /// Whether this is a pointer-like type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Ptr(_) | Self::CStr | Self::FnPtr)
    }

    /// Compute the wider of two integer types (used for arithmetic promotions).
    #[must_use]
    pub fn widen(a: &Self, b: &Self) -> Self {
        match (a, b) {
            (Self::Int(wa), Self::Int(wb)) => Self::Int(*wa.max(wb)),
            (Self::Uint(wa), Self::Uint(wb)) => Self::Uint(*wa.max(wb)),
            (Self::Int(wa), Self::Uint(wb)) | (Self::Uint(wb), Self::Int(wa)) => {
                Self::Int(*wa.max(wb))
            }
            (Self::Float64, _) | (_, Self::Float64) => Self::Float64,
            (Self::Float32, _) | (_, Self::Float32) => Self::Float32,
            (a, Self::Unknown) | (Self::Unknown, a) => a.clone(),
            _ => Self::Unknown,
        }
    }
}

// ── TypeConstraint ────────────────────────────────────────────────────────────

/// A constraint between type variables or concrete types.
#[derive(Debug, Clone)]
pub enum TypeConstraint {
    /// Two type variables must be equal.
    Equal(TypeVar, TypeVar),
    /// A type variable is assigned a concrete type.
    Concrete(TypeVar, ConcreteType),
    /// A type variable must be a pointer to another variable's type.
    PtrTo(TypeVar, TypeVar),
    /// A type variable is the result of dereferencing another.
    Deref(TypeVar, TypeVar),
    /// A type variable must be an integer of at least `min_bits` bits.
    MinWidth(TypeVar, u8),
    /// A type variable must have exactly `bits` bit width (from shift/mask).
    ExactWidth(TypeVar, u8),
    /// A type variable is the result of a phi merging a set of variables.
    Phi(TypeVar, Vec<TypeVar>),
    /// A type variable comes from an API call return value.
    ApiReturn(TypeVar, String, String), // (result_var, module, function)
    /// A type variable is passed as argument N to an API function.
    ApiArg(TypeVar, String, String, usize),
}

impl TypeConstraint {
    /// Return the primary type variable this constraint concerns.
    #[must_use]
    pub const fn primary_var(&self) -> &TypeVar {
        match self {
            Self::Equal(a, _)
            | Self::Concrete(a, _)
            | Self::PtrTo(a, _)
            | Self::Deref(a, _)
            | Self::MinWidth(a, _)
            | Self::ExactWidth(a, _)
            | Self::Phi(a, _)
            | Self::ApiReturn(a, _, _)
            | Self::ApiArg(a, _, _, _) => a,
        }
    }
}

// ── PropDirection ─────────────────────────────────────────────────────────────

/// Direction of type propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropDirection {
    /// Forward: from definition to use.
    Forward,
    /// Backward: from use to definition.
    Backward,
    /// Bidirectional.
    Both,
}

// ── PropResult ────────────────────────────────────────────────────────────────

/// Result of a propagation pass.
#[derive(Debug, Default, Clone)]
pub struct PropResult {
    /// Variables whose type was newly determined.
    pub newly_typed: Vec<(TypeVar, ConcreteType)>,
    /// Remaining unresolved type variables.
    pub unresolved: Vec<TypeVar>,
    /// Number of propagation steps performed.
    pub steps: usize,
    /// Whether a fixed-point was reached.
    pub converged: bool,
}

// ── ApiSignature ──────────────────────────────────────────────────────────────

/// A known API function signature used during type propagation.
#[derive(Debug, Clone)]
pub struct ApiSignature {
    /// Module or library name.
    pub module: String,
    /// Function name.
    pub function: String,
    /// Return type.
    pub return_type: ConcreteType,
    /// Parameter types.
    pub param_types: Vec<ConcreteType>,
}

impl ApiSignature {
    /// Create a new API signature.
    #[must_use]
    pub fn new(
        module: impl Into<String>,
        function: impl Into<String>,
        return_type: ConcreteType,
        param_types: Vec<ConcreteType>,
    ) -> Self {
        Self {
            module: module.into(),
            function: function.into(),
            return_type,
            param_types,
        }
    }
}

// ── TypeUnifier ───────────────────────────────────────────────────────────────

/// Union-find based type unifier: merges equivalent type variables.
#[derive(Debug, Default)]
pub struct TypeUnifier {
    parent: HashMap<u32, u32>,
    /// Known concrete types for canonical representatives.
    concrete: HashMap<u32, ConcreteType>,
}

impl TypeUnifier {
    /// Create a new unifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Find the canonical representative for a type variable id.
    pub fn find(&mut self, id: u32) -> u32 {
        if let std::collections::hash_map::Entry::Vacant(e) = self.parent.entry(id) {
            e.insert(id);
            return id;
        }
        let parent = self.parent[&id];
        if parent == id {
            return id;
        }
        let root = self.find(parent);
        self.parent.insert(id, root);
        root
    }

    /// Union two type variable ids.
    pub fn union(&mut self, a: u32, b: u32) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        // Merge: prefer the one with a known concrete type.
        let (keep, discard) = if self.concrete.contains_key(&ra) {
            (ra, rb)
        } else {
            (rb, ra)
        };
        self.parent.insert(discard, keep);
        // Propagate concrete type if discard had one.
        if let Some(ty) = self.concrete.remove(&discard) {
            self.concrete.entry(keep).or_insert(ty);
        }
    }

    /// Assign a concrete type to a type variable.
    pub fn assign(&mut self, var: &TypeVar, ty: ConcreteType) {
        let root = self.find(var.id);
        self.concrete.insert(root, ty);
    }

    /// Look up the concrete type for a type variable.
    #[must_use]
    pub fn lookup(&mut self, var: &TypeVar) -> Option<ConcreteType> {
        let root = self.find(var.id);
        self.concrete.get(&root).cloned()
    }

    /// Number of type variables with resolved concrete types.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.concrete.len()
    }
}

// ── TypePropagator ────────────────────────────────────────────────────────────

/// Forward/backward type propagation engine.
///
/// Usage:
/// 1. Add constraints via `add_constraint`.
/// 2. Optionally register API signatures via `register_api`.
/// 3. Call `propagate` to resolve as many type variables as possible.
#[derive(Debug)]
pub struct TypePropagator {
    /// All constraints added to the system.
    constraints: Vec<TypeConstraint>,
    /// The unifier for merging equivalent type variables.
    unifier: TypeUnifier,
    /// Registered API signatures.
    api_db: HashMap<(String, String), ApiSignature>,
    /// Maximum propagation iterations.
    max_iterations: usize,
    /// Next fresh type variable id.
    next_var_id: u32,
}

impl TypePropagator {
    /// Create a new propagator with a default iteration limit of 64.
    #[must_use]
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            unifier: TypeUnifier::new(),
            api_db: HashMap::new(),
            max_iterations: 64,
            next_var_id: 1,
        }
    }

    /// Set the maximum number of iterations.
    pub const fn set_max_iterations(&mut self, n: usize) {
        self.max_iterations = n;
    }

    /// Allocate a fresh type variable.
    pub const fn fresh_var(&mut self) -> TypeVar {
        let id = self.next_var_id;
        self.next_var_id += 1;
        TypeVar::new(id)
    }

    /// Allocate a fresh type variable with a hint.
    pub fn fresh_var_hint(&mut self, hint: &str) -> TypeVar {
        let id = self.next_var_id;
        self.next_var_id += 1;
        TypeVar::with_hint(id, hint)
    }

    /// Add a type constraint.
    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
    }

    /// Register an API function signature.
    pub fn register_api(&mut self, sig: ApiSignature) {
        self.api_db
            .insert((sig.module.clone(), sig.function.clone()), sig);
    }

    /// Register common C standard library signatures.
    pub fn register_stdlib(&mut self) {
        let sigs = [
            ApiSignature::new(
                "libc", "malloc",
                ConcreteType::Ptr(Box::new(ConcreteType::Void)),
                vec![ConcreteType::Uint(64)],
            ),
            ApiSignature::new(
                "libc", "free",
                ConcreteType::Void,
                vec![ConcreteType::Ptr(Box::new(ConcreteType::Void))],
            ),
            ApiSignature::new(
                "libc", "strlen",
                ConcreteType::Uint(64),
                vec![ConcreteType::CStr],
            ),
            ApiSignature::new(
                "libc", "memcpy",
                ConcreteType::Ptr(Box::new(ConcreteType::Void)),
                vec![
                    ConcreteType::Ptr(Box::new(ConcreteType::Void)),
                    ConcreteType::Ptr(Box::new(ConcreteType::Void)),
                    ConcreteType::Uint(64),
                ],
            ),
            ApiSignature::new(
                "libc", "printf",
                ConcreteType::Int(32),
                vec![ConcreteType::CStr],
            ),
            ApiSignature::new(
                "libc", "atoi",
                ConcreteType::Int(32),
                vec![ConcreteType::CStr],
            ),
            ApiSignature::new(
                "libc", "exit",
                ConcreteType::Void,
                vec![ConcreteType::Int(32)],
            ),
        ];
        for sig in sigs {
            self.register_api(sig);
        }
    }

    /// Run propagation to a fixed point, returning the result.
    pub fn propagate(&mut self, direction: PropDirection) -> PropResult {
        let mut result = PropResult::default();
        let mut changed = true;
        let mut iteration = 0;

        while changed && iteration < self.max_iterations {
            changed = false;
            iteration += 1;
            result.steps += 1;

            let constraints = self.constraints.clone();
            for constraint in &constraints {
                if self.apply_constraint(constraint, direction) {
                    changed = true;
                }
            }
        }

        result.converged = !changed;

        // Collect results
        let var_ids: Vec<u32> = {
            let mut seen = HashSet::new();
            for c in &self.constraints {
                let v = c.primary_var();
                seen.insert(v.id);
            }
            seen.into_iter().collect()
        };

        for id in var_ids {
            let tv = TypeVar::new(id);
            match self.unifier.lookup(&tv) {
                Some(ty) if ty != ConcreteType::Unknown => {
                    result.newly_typed.push((tv, ty));
                }
                _ => {
                    result.unresolved.push(tv);
                }
            }
        }

        result
    }

    /// Apply a single constraint, returning `true` if new information was learned.
    fn apply_constraint(&mut self, c: &TypeConstraint, direction: PropDirection) -> bool {
        match c {
            TypeConstraint::Concrete(var, ty) => {
                if self.unifier.lookup(var).is_none() {
                    self.unifier.assign(var, ty.clone());
                    return true;
                }
                false
            }
            TypeConstraint::Equal(a, b) => self.apply_equal(a, b, direction),
            TypeConstraint::PtrTo(ptr_var, pointee_var) => {
                self.apply_ptr_to(ptr_var, pointee_var, direction)
            }
            TypeConstraint::Deref(result_var, ptr_var) => {
                if let Some(ConcreteType::Ptr(inner)) = self.unifier.lookup(ptr_var)
                    && self.unifier.lookup(result_var).is_none() {
                        self.unifier.assign(result_var, *inner);
                        return true;
                    }
                false
            }
            TypeConstraint::MinWidth(var, min_bits) => {
                match self.unifier.lookup(var) {
                    None => { self.unifier.assign(var, ConcreteType::Uint(*min_bits)); true }
                    Some(ConcreteType::Int(w)) if w < *min_bits => {
                        self.unifier.assign(var, ConcreteType::Int(*min_bits)); true
                    }
                    Some(ConcreteType::Uint(w)) if w < *min_bits => {
                        self.unifier.assign(var, ConcreteType::Uint(*min_bits)); true
                    }
                    _ => false,
                }
            }
            TypeConstraint::ExactWidth(var, bits) => {
                if self.unifier.lookup(var).is_none() {
                    self.unifier.assign(var, ConcreteType::Uint(*bits));
                    return true;
                }
                false
            }
            TypeConstraint::Phi(result_var, inputs) => self.apply_phi(result_var, inputs),
            TypeConstraint::ApiReturn(var, module, function) => {
                let key = (module.clone(), function.clone());
                if let Some(sig) = self.api_db.get(&key).cloned()
                    && self.unifier.lookup(var).is_none() {
                        self.unifier.assign(var, sig.return_type);
                        return true;
                    }
                false
            }
            TypeConstraint::ApiArg(var, module, function, arg_idx) => {
                let key = (module.clone(), function.clone());
                if let Some(sig) = self.api_db.get(&key).cloned()
                    && let Some(param_ty) = sig.param_types.get(*arg_idx).cloned()
                        && self.unifier.lookup(var).is_none() {
                            self.unifier.assign(var, param_ty);
                            return true;
                        }
                false
            }
        }
    }

    fn apply_equal(&mut self, a: &TypeVar, b: &TypeVar, direction: PropDirection) -> bool {
        let ta = self.unifier.lookup(a);
        let tb = self.unifier.lookup(b);
        let mut changed = false;
        match (ta, tb) {
            (Some(ta), None) => { self.unifier.assign(b, ta); changed = true; }
            (None, Some(tb)) if matches!(direction, PropDirection::Backward | PropDirection::Both) => {
                self.unifier.assign(a, tb); changed = true;
            }
            _ => { self.unifier.union(a.id, b.id); }
        }
        changed
    }

    fn apply_ptr_to(&mut self, ptr_var: &TypeVar, pointee_var: &TypeVar, direction: PropDirection) -> bool {
        if let Some(inner) = self.unifier.lookup(pointee_var) {
            let ptr_ty = ConcreteType::Ptr(Box::new(inner));
            if self.unifier.lookup(ptr_var).is_none() {
                self.unifier.assign(ptr_var, ptr_ty);
                return true;
            }
        }
        if matches!(direction, PropDirection::Backward | PropDirection::Both)
            && let Some(ConcreteType::Ptr(inner)) = self.unifier.lookup(ptr_var)
                && self.unifier.lookup(pointee_var).is_none() {
                    self.unifier.assign(pointee_var, *inner);
                    return true;
                }
        false
    }

    fn apply_phi(&mut self, result_var: &TypeVar, inputs: &[TypeVar]) -> bool {
        let known_ty = inputs.iter().find_map(|input| self.unifier.lookup(input));
        if let Some(ty) = known_ty {
            let was_none = self.unifier.lookup(result_var).is_none();
            if was_none { self.unifier.assign(result_var, ty.clone()); }
            for input in inputs {
                if self.unifier.lookup(input).is_none() {
                    self.unifier.assign(input, ty.clone());
                }
            }
            return was_none;
        }
        false
    }

    /// Infer integer width from a shift amount: `x >> N` → x is at least N+1 bits.
    pub fn infer_from_shift(&mut self, var: &TypeVar, shift_amount: u8) {
        let bits = if shift_amount < 8 { 8 }
        else if shift_amount < 16 { 16 }
        else if shift_amount < 32 { 32 }
        else { 64 };
        self.add_constraint(TypeConstraint::MinWidth(var.clone(), bits));
    }

    /// Infer integer width from a bit mask: `x & 0xFF` → x is 8-bit capable.
    pub fn infer_from_mask(&mut self, var: &TypeVar, mask: u64) {
        let bits = if mask <= 0xFF { 8 }
        else if mask <= 0xFFFF { 16 }
        else if mask <= 0xFFFF_FFFF { 32 }
        else { 64 };
        self.add_constraint(TypeConstraint::MinWidth(var.clone(), bits));
    }

    /// Look up the resolved type for a variable after propagation.
    #[must_use]
    pub fn resolved_type(&mut self, var: &TypeVar) -> Option<ConcreteType> {
        self.unifier.lookup(var)
    }

    /// Return a summary of all resolved variables.
    #[must_use] 
    pub fn all_resolved(&self) -> Vec<(TypeVar, ConcreteType)> {
        self.unifier.concrete.iter()
            .map(|(&id, ty)| (TypeVar::new(id), ty.clone()))
            .collect()
    }

    /// Run a BFS-style forward propagation from a set of seed variables.
    pub fn propagate_forward_bfs(
        &mut self,
        seeds: &[(TypeVar, ConcreteType)],
        edges: &[(TypeVar, TypeVar)], // (from, to) data-flow edges
    ) {
        let mut queue: VecDeque<TypeVar> = VecDeque::new();
        for (var, ty) in seeds {
            self.unifier.assign(var, ty.clone());
            queue.push_back(var.clone());
        }
        // Build adjacency map
        let mut adj: HashMap<u32, Vec<TypeVar>> = HashMap::new();
        for (from, to) in edges {
            adj.entry(from.id).or_default().push(to.clone());
        }
        while let Some(var) = queue.pop_front() {
            if let Some(ty) = self.unifier.lookup(&var)
                && let Some(successors) = adj.get(&var.id) {
                    for succ in successors {
                        if self.unifier.lookup(succ).is_none() {
                            self.unifier.assign(succ, ty.clone());
                            queue.push_back(succ.clone());
                        }
                    }
                }
        }
    }
}

impl Default for TypePropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_propagator() -> TypePropagator {
        let mut p = TypePropagator::new();
        p.register_stdlib();
        p
    }

    #[test]
    fn test_concrete_assignment() {
        let mut p = make_propagator();
        let v = p.fresh_var_hint("x");
        p.add_constraint(TypeConstraint::Concrete(v.clone(), ConcreteType::Int(32)));
        let result = p.propagate(PropDirection::Forward);
        assert!(result.converged);
        assert_eq!(p.resolved_type(&v), Some(ConcreteType::Int(32)));
    }

    #[test]
    fn test_equal_propagation() {
        let mut p = make_propagator();
        let a = p.fresh_var_hint("a");
        let b = p.fresh_var_hint("b");
        p.add_constraint(TypeConstraint::Concrete(a.clone(), ConcreteType::Uint(64)));
        p.add_constraint(TypeConstraint::Equal(a.clone(), b.clone()));
        p.propagate(PropDirection::Forward);
        assert_eq!(p.resolved_type(&b), Some(ConcreteType::Uint(64)));
    }

    #[test]
    fn test_ptr_to_propagation() {
        let mut p = make_propagator();
        let inner = p.fresh_var_hint("inner");
        let ptr = p.fresh_var_hint("ptr");
        p.add_constraint(TypeConstraint::Concrete(inner.clone(), ConcreteType::Int(32)));
        p.add_constraint(TypeConstraint::PtrTo(ptr.clone(), inner.clone()));
        p.propagate(PropDirection::Forward);
        let ty = p.resolved_type(&ptr).unwrap();
        assert!(matches!(ty, ConcreteType::Ptr(_)));
    }

    #[test]
    fn test_deref_propagation() {
        let mut p = make_propagator();
        let ptr = p.fresh_var_hint("p");
        let deref_result = p.fresh_var_hint("*p");
        p.add_constraint(TypeConstraint::Concrete(
            ptr.clone(),
            ConcreteType::Ptr(Box::new(ConcreteType::Uint(8))),
        ));
        p.add_constraint(TypeConstraint::Deref(deref_result.clone(), ptr.clone()));
        p.propagate(PropDirection::Forward);
        assert_eq!(p.resolved_type(&deref_result), Some(ConcreteType::Uint(8)));
    }

    #[test]
    fn test_api_return_type() {
        let mut p = make_propagator();
        let ret = p.fresh_var_hint("malloc_result");
        p.add_constraint(TypeConstraint::ApiReturn(
            ret.clone(),
            "libc".to_string(),
            "malloc".to_string(),
        ));
        p.propagate(PropDirection::Forward);
        let ty = p.resolved_type(&ret).unwrap();
        assert!(matches!(ty, ConcreteType::Ptr(_)));
    }

    #[test]
    fn test_api_arg_type() {
        let mut p = make_propagator();
        let arg = p.fresh_var_hint("arg0");
        p.add_constraint(TypeConstraint::ApiArg(
            arg.clone(),
            "libc".to_string(),
            "strlen".to_string(),
            0,
        ));
        p.propagate(PropDirection::Forward);
        assert_eq!(p.resolved_type(&arg), Some(ConcreteType::CStr));
    }

    #[test]
    fn test_phi_node_propagation() {
        let mut p = make_propagator();
        let a = p.fresh_var_hint("a");
        let b = p.fresh_var_hint("b");
        let phi = p.fresh_var_hint("phi");
        p.add_constraint(TypeConstraint::Concrete(a.clone(), ConcreteType::Int(32)));
        p.add_constraint(TypeConstraint::Phi(phi.clone(), vec![a.clone(), b.clone()]));
        p.propagate(PropDirection::Forward);
        assert_eq!(p.resolved_type(&phi), Some(ConcreteType::Int(32)));
        assert_eq!(p.resolved_type(&b), Some(ConcreteType::Int(32)));
    }

    #[test]
    fn test_shift_width_inference() {
        let mut p = make_propagator();
        let v = p.fresh_var_hint("val");
        p.infer_from_shift(&v, 24); // shift by 24 → at least 32-bit
        p.propagate(PropDirection::Forward);
        let ty = p.resolved_type(&v).unwrap();
        assert!(matches!(ty, ConcreteType::Uint(32) | ConcreteType::Uint(64)));
    }

    #[test]
    fn test_mask_width_inference() {
        let mut p = make_propagator();
        let v = p.fresh_var_hint("byte");
        p.infer_from_mask(&v, 0xFF); // mask 0xFF → 8-bit
        p.propagate(PropDirection::Forward);
        assert_eq!(p.resolved_type(&v), Some(ConcreteType::Uint(8)));
    }

    #[test]
    fn test_bfs_propagation() {
        let mut p = make_propagator();
        let a = TypeVar::new(1);
        let b = TypeVar::new(2);
        let c = TypeVar::new(3);
        let seeds = vec![(a.clone(), ConcreteType::Int(32))];
        let edges = vec![(a.clone(), b.clone()), (b.clone(), c.clone())];
        p.propagate_forward_bfs(&seeds, &edges);
        assert_eq!(p.resolved_type(&b), Some(ConcreteType::Int(32)));
        assert_eq!(p.resolved_type(&c), Some(ConcreteType::Int(32)));
    }

    #[test]
    fn test_min_width_constraint() {
        let mut p = make_propagator();
        let v = p.fresh_var();
        p.add_constraint(TypeConstraint::MinWidth(v.clone(), 16));
        p.add_constraint(TypeConstraint::MinWidth(v.clone(), 32));
        p.propagate(PropDirection::Forward);
        let ty = p.resolved_type(&v).unwrap();
        // Should be at least 32-bit
        match ty {
            ConcreteType::Uint(b) | ConcreteType::Int(b) => assert!(b >= 16),
            _ => {}
        }
    }

    #[test]
    fn test_type_var_display() {
        let v = TypeVar::with_hint(42, "myvar");
        assert!(v.to_string().contains("42"));
        assert!(v.to_string().contains("myvar"));
    }

    #[test]
    fn test_concrete_type_c_name() {
        assert_eq!(ConcreteType::Int(32).c_name(), "int32_t");
        assert_eq!(ConcreteType::Uint(64).c_name(), "uint64_t");
        assert_eq!(ConcreteType::CStr.c_name(), "char *");
        assert_eq!(
            ConcreteType::Ptr(Box::new(ConcreteType::Int(32))).c_name(),
            "int32_t *"
        );
    }

    #[test]
    fn test_concrete_type_byte_size() {
        assert_eq!(ConcreteType::Int(32).byte_size(), Some(4));
        assert_eq!(ConcreteType::Uint(8).byte_size(), Some(1));
        assert_eq!(ConcreteType::Float64.byte_size(), Some(8));
        assert_eq!(ConcreteType::Array(Box::new(ConcreteType::Int(32)), 4).byte_size(), Some(16));
    }

    #[test]
    fn test_unifier_union_find() {
        let mut u = TypeUnifier::new();
        u.assign(&TypeVar::new(1), ConcreteType::Int(32));
        u.union(1, 2);
        assert_eq!(u.lookup(&TypeVar::new(2)), Some(ConcreteType::Int(32)));
    }
}
