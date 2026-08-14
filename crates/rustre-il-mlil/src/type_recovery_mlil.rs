//! Type recovery at the MLIL level.
//!
//! Propagates type information through SSA phi nodes, narrows types from
//! comparison operations, propagates pointer types through loads, imports
//! calling-convention return types, and propagates return types.
//!
//! # Algorithm
//! Uses a standard Hindley-Milner-style union-find lattice over a finite type
//! domain.  Constraints are generated from:
//!
//! 1. **Phi nodes** — all sources and the result must share the same type.
//! 2. **Comparisons** — `x < 0` implies `x` is signed; `x < y` where `y` is
//!    unsigned implies `x` is unsigned.
//! 3. **Loads** — if `p` has type `*T` then `load(p)` has type `T`.
//! 4. **Calling conventions** — the return register has the callee's return type.
//! 5. **Stores** — if `*p = v` and `p : *T` then `v : T`.

use ahash::AHashMap as HashMap;

use crate::{MlilExpr, MlilFunction, MlilInstruction, SsaVar};

// ─────────────────────────────────────────────────────────────────────────────
// MlilType — the type lattice
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered type at the MLIL level.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[derive(Default)]
pub enum MlilType {
    /// Top of the lattice: no information.
    #[default]
    Unknown,
    /// Bottom: type conflict (multiple incompatible constraints).
    Conflict,
    /// Boolean (1-bit value from comparison).
    Bool,
    /// Signed integer of `bits` width.
    SInt(u8),
    /// Unsigned integer of `bits` width.
    UInt(u8),
    /// Floating-point of `bits` width.
    Float(u8),
    /// Pointer to an inner type.
    Ptr(Box<Self>),
    /// Array of `count` elements of inner type (count may be unknown: 0 = ∞).
    Array(Box<Self>, usize),
    /// Struct with named fields (field name → type).
    Struct(String),
    /// Function pointer with `n` parameters.
    FnPtr { n_params: usize },
    /// Void (used for call return types that are discarded).
    Void,
}

impl MlilType {
    /// Returns `true` if this is a pointer type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Ptr(_))
    }

    /// Dereference a pointer type.  Returns the pointed-to type or `Unknown`.
    #[must_use]
    pub fn deref(&self) -> Self {
        match self {
            Self::Ptr(inner) => *inner.clone(),
            _ => Self::Unknown,
        }
    }

    /// Promote to a pointer-to-self type.
    #[must_use]
    pub fn addr_of(self) -> Self {
        Self::Ptr(Box::new(self))
    }

    /// Meet in the type lattice (greatest lower bound).
    /// Returns `Conflict` if the two types are irreconcilable.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => t.clone(),
            (Self::Conflict, _) | (_, Self::Conflict) => Self::Conflict,
            (Self::Bool, Self::Bool) => Self::Bool,
            (Self::SInt(a), Self::SInt(b)) if a == b => Self::SInt(*a),
            (Self::UInt(a), Self::UInt(b)) if a == b => Self::UInt(*a),
            (Self::Float(a), Self::Float(b)) if a == b => Self::Float(*a),
            // Widen: u32 ∧ u64 = u64 (widening).
            (Self::UInt(a), Self::UInt(b)) => Self::UInt(*a.max(b)),
            (Self::SInt(a), Self::SInt(b)) => Self::SInt(*a.max(b)),
            (Self::Ptr(a), Self::Ptr(b)) => Self::Ptr(Box::new(a.meet(b))),
            (Self::Void, Self::Void) => Self::Void,
            _ => Self::Conflict,
        }
    }

    /// Width in bits (for integer/float types).
    #[must_use]
    pub const fn bits(&self) -> Option<u8> {
        match self {
            Self::SInt(b) | Self::UInt(b) | Self::Float(b) => Some(*b),
            _ => None,
        }
    }

    /// Return the default type for a given byte-size value.
    #[must_use]
    pub fn from_bytes(bytes: u64, signed: bool) -> Self {
        // Clamp to u8::MAX (255 bits) before the multiply to avoid overflow;
        // any width > 128 bits is already represented as an opaque integer.
        let bits = bytes.saturating_mul(8).min(u64::from(u8::MAX)) as u8;
        if signed {
            Self::SInt(bits)
        } else {
            Self::UInt(bits)
        }
    }
}


impl std::fmt::Display for MlilType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "?"),
            Self::Conflict => write!(f, "conflict"),
            Self::Bool => write!(f, "bool"),
            Self::SInt(b) => write!(f, "i{b}"),
            Self::UInt(b) => write!(f, "u{b}"),
            Self::Float(b) => write!(f, "f{b}"),
            Self::Ptr(t) => write!(f, "*{t}"),
            Self::Array(t, 0) => write!(f, "[]{t}"),
            Self::Array(t, n) => write!(f, "[{n}]{t}"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::FnPtr { n_params } => write!(f, "fn(*{n_params})"),
            Self::Void => write!(f, "void"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// A typing constraint between SSA variables and types.
#[derive(Debug, Clone)]
pub enum TypeConstraint {
    /// `v` must have type `t`.
    HasType(SsaVar, MlilType),
    /// `v1` and `v2` must have the same type (equality constraint).
    Equal(SsaVar, SsaVar),
    /// `result` = load of a `*T` pointer var `ptr`; result has type T.
    DerefLoad {
        ptr: SsaVar,
        result: SsaVar,
    },
    /// `value` stored through `ptr: *T`; value has type T.
    DerefStore {
        ptr: SsaVar,
        value: SsaVar,
    },
    /// `result` of comparison is `bool`.
    ComparisonResult(SsaVar),
    /// `v` is compared against zero in a signed context → `SInt`.
    SignedCompare(SsaVar),
    /// `v` is compared against zero in an unsigned context → `UInt`.
    UnsignedCompare(SsaVar),
}

// ─────────────────────────────────────────────────────────────────────────────
// CallingConventionTypes — per-function calling convention type signatures
// ─────────────────────────────────────────────────────────────────────────────

/// Type signature for a function (imported from calling convention or debug info).
#[derive(Debug, Clone)]
pub struct FnTypeSignature {
    /// Return type.
    pub return_type: MlilType,
    /// Parameter types in order.
    pub params: Vec<MlilType>,
}

impl FnTypeSignature {
    /// Create an unknown signature.
    #[must_use] 
    pub fn unknown(n_params: usize) -> Self {
        Self {
            return_type: MlilType::Unknown,
            params: vec![MlilType::Unknown; n_params],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeEnvironment — maps SSA variables to recovered types
// ─────────────────────────────────────────────────────────────────────────────

/// A mapping from SSA variable to its recovered type.
#[derive(Debug, Clone, Default)]
pub struct TypeEnvironment {
    /// The recovered type for each SSA variable.
    pub types: HashMap<SsaVar, MlilType>,
    /// Union-find parent pointers (for equality constraints).
    parent: HashMap<SsaVar, SsaVar>,
}

impl TypeEnvironment {
    /// Look up the type of `var`, defaulting to `Unknown`.
    #[must_use] 
    pub fn get(&self, var: &SsaVar) -> &MlilType {
        self.types.get(var).unwrap_or(&MlilType::Unknown)
    }

    /// Set the type of `var`, meeting with any existing type.
    pub fn set(&mut self, var: SsaVar, ty: MlilType) {
        let existing = self.types.entry(var).or_default();
        let new_ty = existing.meet(&ty);
        *existing = new_ty;
    }

    /// Find the representative of `var` in the union-find.
    ///
    /// Uses an iterative two-pass algorithm (find root, then path-compress)
    /// to avoid stack overflow on long chains produced by many `Equal`
    /// constraints from attacker-controlled input.
    pub fn find(&mut self, var: &SsaVar) -> SsaVar {
        // Pass 1: walk to root iteratively.
        let mut current = var.clone();
        loop {
            let parent = match self.parent.get(&current).cloned() {
                Some(p) if p == current => break,
                Some(p) => p,
                None => break,
            };
            current = parent;
        }
        let root = current;

        // Pass 2: path-compress — point every node on the path to root.
        let mut node = var.clone();
        loop {
            let parent = match self.parent.get(&node).cloned() {
                Some(p) if p == node => break,
                Some(p) => p,
                None => break,
            };
            if node != root {
                self.parent.insert(node.clone(), root.clone());
            }
            node = parent;
        }
        root
    }

    /// Union two variables (equality constraint).
    pub fn union(&mut self, a: &SsaVar, b: &SsaVar) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(rb.clone(), ra.clone());
            // Merge types.
            let ta = self.get(&ra).clone();
            let tb = self.get(&rb).clone();
            let merged = ta.meet(&tb);
            self.types.insert(ra, merged);
        }
    }

    /// Apply all constraints until convergence.
    pub fn solve(&mut self, constraints: &[TypeConstraint]) {
        let mut changed = true;
        while changed {
            changed = false;
            for c in constraints {
                let before = self.types.clone();
                self.apply_constraint(c);
                if self.types != before {
                    changed = true;
                }
            }
        }
    }

    fn apply_constraint(&mut self, c: &TypeConstraint) {
        match c {
            TypeConstraint::HasType(var, ty) => {
                let r = self.find(var);
                self.set(r, ty.clone());
            }
            TypeConstraint::Equal(a, b) => {
                self.union(a, b);
            }
            TypeConstraint::DerefLoad { ptr, result } => {
                let ptr_ty = self.get(ptr).clone();
                if let MlilType::Ptr(inner) = ptr_ty {
                    let r = self.find(result);
                    self.set(r, *inner);
                }
            }
            TypeConstraint::DerefStore { ptr, value } => {
                let ptr_ty = self.get(ptr).clone();
                if let MlilType::Ptr(inner) = ptr_ty {
                    let r = self.find(value);
                    self.set(r, *inner);
                }
            }
            TypeConstraint::ComparisonResult(var) => {
                let r = self.find(var);
                self.set(r, MlilType::Bool);
            }
            TypeConstraint::SignedCompare(var) => {
                let r = self.find(var);
                let cur = self.get(&r).clone();
                if cur == MlilType::Unknown {
                    self.set(r, MlilType::SInt(64));
                }
            }
            TypeConstraint::UnsignedCompare(var) => {
                let r = self.find(var);
                let cur = self.get(&r).clone();
                if cur == MlilType::Unknown {
                    self.set(r, MlilType::UInt(64));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintGenerator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates typing constraints from MLIL SSA instructions.
#[derive(Debug, Clone, Default)]
pub struct ConstraintGenerator {
    pub constraints: Vec<TypeConstraint>,
}

impl ConstraintGenerator {
    /// Generate constraints for a single SSA variable definition (`Assign`).
    pub fn visit_assign(&mut self, var: &SsaVar, src: &MlilExpr) {
        self.gen_mlil_expr_constraints(var, src);
    }

    /// Generate constraints for a phi node.
    pub fn visit_phi(&mut self, dest: &SsaVar, sources: &[SsaVar]) {
        for op in sources {
            self.constraints
                .push(TypeConstraint::Equal(dest.clone(), op.clone()));
        }
    }

    /// Generate constraints for a call return value.
    pub fn visit_call_return(&mut self, ret_var: &SsaVar, sig: &FnTypeSignature) {
        self.constraints.push(TypeConstraint::HasType(
            ret_var.clone(),
            sig.return_type.clone(),
        ));
    }

    fn gen_mlil_expr_constraints(&mut self, dest: &SsaVar, expr: &MlilExpr) {
        match expr {
            // Load: result type depends on pointer type.
            MlilExpr::Load { addr, .. } => {
                if let Some(ptr_var) = mlil_expr_to_ssa_var(addr) {
                    self.constraints.push(TypeConstraint::DerefLoad {
                        ptr: ptr_var,
                        result: dest.clone(),
                    });
                } else {
                    self.constraints.push(TypeConstraint::HasType(
                        dest.clone(),
                        MlilType::UInt(64),
                    ));
                }
            }
            // Comparisons produce booleans.
            MlilExpr::CmpEq(_, _)
            | MlilExpr::CmpNe(_, _)
            | MlilExpr::CmpSlt(_, _)
            | MlilExpr::CmpSle(_, _)
            | MlilExpr::CmpUlt(_, _)
            | MlilExpr::CmpUle(_, _) => {
                self.constraints
                    .push(TypeConstraint::ComparisonResult(dest.clone()));
                // Signed comparisons → operands are signed.
                match expr {
                    MlilExpr::CmpSlt(l, r) | MlilExpr::CmpSle(l, r) => {
                        if let Some(v) = mlil_expr_to_ssa_var(l) {
                            self.constraints.push(TypeConstraint::SignedCompare(v));
                        }
                        if let Some(v) = mlil_expr_to_ssa_var(r) {
                            self.constraints.push(TypeConstraint::SignedCompare(v));
                        }
                    }
                    MlilExpr::CmpUlt(l, r) | MlilExpr::CmpUle(l, r) => {
                        if let Some(v) = mlil_expr_to_ssa_var(l) {
                            self.constraints.push(TypeConstraint::UnsignedCompare(v));
                        }
                        if let Some(v) = mlil_expr_to_ssa_var(r) {
                            self.constraints.push(TypeConstraint::UnsignedCompare(v));
                        }
                    }
                    _ => {}
                }
            }
            // Arithmetic: result same type as operands.
            MlilExpr::Add(l, r, _)
            | MlilExpr::Sub(l, r, _)
            | MlilExpr::Mul(l, r, _) => {
                if let Some(lv) = mlil_expr_to_ssa_var(l) {
                    self.constraints.push(TypeConstraint::Equal(dest.clone(), lv));
                }
                if let Some(rv) = mlil_expr_to_ssa_var(r) {
                    self.constraints.push(TypeConstraint::Equal(dest.clone(), rv));
                }
            }
            // Constants: infer from size.
            MlilExpr::Const { size, .. } => {
                self.constraints.push(TypeConstraint::HasType(
                    dest.clone(),
                    MlilType::from_bytes(size.bytes() as u64, false),
                ));
            }
            // Variable copy: same type.
            MlilExpr::Var { var, .. } => {
                self.constraints
                    .push(TypeConstraint::Equal(dest.clone(), var.clone()));
            }
            // Stack pointer: pointer type.
            MlilExpr::StackPointer(_) => {
                self.constraints.push(TypeConstraint::HasType(
                    dest.clone(),
                    MlilType::Ptr(Box::new(MlilType::Unknown)),
                ));
            }
            // Float arithmetic: float result.
            MlilExpr::FAdd(_, _, s)
            | MlilExpr::FSub(_, _, s)
            | MlilExpr::FMul(_, _, s)
            | MlilExpr::FDiv(_, _, s) => {
                self.constraints.push(TypeConstraint::HasType(
                    dest.clone(),
                    MlilType::Float((s.bytes() * 8) as u8),
                ));
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilTypeRecovery — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level type recovery pass for MLIL SSA functions.
#[derive(Debug, Clone, Default)]
pub struct MlilTypeRecovery {
    /// Known function signatures (address → signature).
    pub fn_signatures: HashMap<u64, FnTypeSignature>,
    /// Known global variable types (address → type).
    pub global_types: HashMap<u64, MlilType>,
    /// Known struct types (name → field map).
    pub struct_types: HashMap<String, HashMap<u64, MlilType>>,
}

impl MlilTypeRecovery {
    /// Run type recovery on `func`.  Returns the recovered type environment.
    #[must_use] 
    pub fn recover(&self, func: &MlilFunction) -> TypeEnvironment {
        let mut cgen = ConstraintGenerator::default();

        // Walk all instructions and generate constraints.
        for block in &func.blocks {
            for ai in &block.instrs {
                match &ai.instr {
                    MlilInstruction::Assign { dest, src, .. } => {
                        cgen.visit_assign(dest, src);
                    }
                    MlilInstruction::Phi { dest, sources } => {
                        cgen.visit_phi(dest, sources);
                    }
                    MlilInstruction::Call { dest, args, ret_vars } => {
                        // Look up callee signature from destination expression.
                        let sig = self.lookup_sig_from_mlil(dest);
                        // Assign return types to ret_vars.
                        for (i, rv) in ret_vars.iter().enumerate() {
                            let ret_ty = sig.params.get(i).cloned().unwrap_or(MlilType::Unknown);
                            cgen.constraints.push(TypeConstraint::HasType(rv.clone(), ret_ty));
                        }
                        // Constrain call args from signature.
                        for (i, arg) in args.iter().enumerate() {
                            if let Some(v) = mlil_expr_to_ssa_var(arg) {
                                let param_ty = sig.params.get(i).cloned().unwrap_or(MlilType::Unknown);
                                if param_ty != MlilType::Unknown {
                                    cgen.constraints.push(TypeConstraint::HasType(v, param_ty));
                                }
                            }
                        }
                    }
                    MlilInstruction::Store { addr, src, .. } => {
                        if let Some(ptr_var) = mlil_expr_to_ssa_var(addr)
                            && let Some(val_var) = mlil_expr_to_ssa_var(src) {
                                cgen.constraints.push(TypeConstraint::DerefStore {
                                    ptr: ptr_var,
                                    value: val_var,
                                });
                            }
                    }
                    _ => {}
                }
            }
        }

        // Import global types as initial HasType constraints.
        for (addr, ty) in &self.global_types {
            let var = SsaVar::new(format!("global_{addr:x}"), 0);
            cgen.constraints.push(TypeConstraint::HasType(
                var,
                ty.clone().addr_of(),
            ));
        }

        // Solve constraints.
        let mut env = TypeEnvironment::default();
        env.solve(&cgen.constraints);
        env
    }

    fn lookup_sig_from_mlil(&self, dest: &MlilExpr) -> FnTypeSignature {
        if let MlilExpr::Const { value: addr, .. } = dest
            && let Some(sig) = self.fn_signatures.get(addr) {
                return sig.clone();
            }
        FnTypeSignature::unknown(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer type propagation helper
// ─────────────────────────────────────────────────────────────────────────────

/// Propagate pointer types from known allocations and global constants.
/// Returns a map from SSA variable → inferred pointer target type.
#[must_use] 
pub fn propagate_pointer_types(
    func: &MlilFunction,
    known_globals: &HashMap<u64, MlilType>,
) -> HashMap<SsaVar, MlilType> {
    let mut result: HashMap<SsaVar, MlilType> = HashMap::new();

    for block in &func.blocks {
        for ai in &block.instrs {
            if let MlilInstruction::Assign { dest, src, .. } = &ai.instr {
                match src {
                    // Global address constant → pointer to global's type.
                    MlilExpr::Const { value: addr, .. } => {
                        if let Some(ty) = known_globals.get(addr) {
                            result.insert(dest.clone(), ty.clone().addr_of());
                        }
                    }
                    // Stack pointer arithmetic → pointer to stack slot.
                    MlilExpr::Add(l, _, _) if matches!(l.as_ref(), MlilExpr::StackPointer(_)) => {
                        result.insert(
                            dest.clone(),
                            MlilType::Ptr(Box::new(MlilType::Unknown)),
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: extract SSA variable from an MLIL expression leaf
// ─────────────────────────────────────────────────────────────────────────────

fn mlil_expr_to_ssa_var(expr: &MlilExpr) -> Option<SsaVar> {
    match expr {
        MlilExpr::Var { var, .. } => Some(var.clone()),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meet_same_type() {
        let a = MlilType::UInt(32);
        assert_eq!(a.meet(&MlilType::UInt(32)), MlilType::UInt(32));
    }

    #[test]
    fn test_meet_unknown() {
        let a = MlilType::Unknown;
        let b = MlilType::SInt(64);
        assert_eq!(a.meet(&b), MlilType::SInt(64));
        assert_eq!(b.meet(&a), MlilType::SInt(64));
    }

    #[test]
    fn test_meet_conflict() {
        let a = MlilType::UInt(32);
        let b = MlilType::SInt(32);
        assert_eq!(a.meet(&b), MlilType::Conflict);
    }

    #[test]
    fn test_meet_ptr() {
        let a = MlilType::Ptr(Box::new(MlilType::UInt(32)));
        let b = MlilType::Ptr(Box::new(MlilType::UInt(32)));
        assert_eq!(a.meet(&b), MlilType::Ptr(Box::new(MlilType::UInt(32))));
    }

    #[test]
    fn test_deref_type() {
        let p = MlilType::Ptr(Box::new(MlilType::SInt(64)));
        assert_eq!(p.deref(), MlilType::SInt(64));
    }

    #[test]
    fn test_type_env_equality_constraint() {
        let mut env = TypeEnvironment::default();
        let x = SsaVar::new("x", 0);
        let y = SsaVar::new("y", 0);
        let constraints = vec![
            TypeConstraint::HasType(x.clone(), MlilType::UInt(32)),
            TypeConstraint::Equal(x.clone(), y.clone()),
        ];
        env.solve(&constraints);
        // y should have the same type as x after unification.
        let y_root = env.find(&y);
        assert_eq!(env.get(&y_root), &MlilType::UInt(32));
    }

    #[test]
    fn test_comparison_result_bool() {
        let mut env = TypeEnvironment::default();
        let cmp = SsaVar::new("cmp", 0);
        let constraints = vec![TypeConstraint::ComparisonResult(cmp.clone())];
        env.solve(&constraints);
        assert_eq!(env.get(&cmp), &MlilType::Bool);
    }

    #[test]
    fn test_signed_compare_constraint() {
        let mut env = TypeEnvironment::default();
        let x = SsaVar::new("x", 0);
        let constraints = vec![TypeConstraint::SignedCompare(x.clone())];
        env.solve(&constraints);
        assert_eq!(env.get(&x), &MlilType::SInt(64));
    }

    #[test]
    fn test_deref_load_propagation() {
        let mut env = TypeEnvironment::default();
        let ptr = SsaVar::new("ptr", 0);
        let res = SsaVar::new("res", 0);
        // ptr has type *u32.
        env.set(
            ptr.clone(),
            MlilType::Ptr(Box::new(MlilType::UInt(32))),
        );
        let constraints = vec![TypeConstraint::DerefLoad {
            ptr: ptr.clone(),
            result: res.clone(),
        }];
        env.solve(&constraints);
        assert_eq!(env.get(&res), &MlilType::UInt(32));
    }

    #[test]
    fn test_type_display() {
        assert_eq!(MlilType::UInt(32).to_string(), "u32");
        assert_eq!(MlilType::SInt(64).to_string(), "i64");
        assert_eq!(
            MlilType::Ptr(Box::new(MlilType::Float(32))).to_string(),
            "*f32"
        );
        assert_eq!(MlilType::Bool.to_string(), "bool");
    }

    #[test]
    fn test_phi_constraints() {
        let mut cgen = ConstraintGenerator::default();
        let dest = SsaVar::new("x", 2);
        let sources = vec![SsaVar::new("x", 0), SsaVar::new("x", 1)];
        cgen.visit_phi(&dest, &sources);
        assert_eq!(cgen.constraints.len(), 2);
    }

    #[test]
    fn test_from_bytes() {
        assert_eq!(MlilType::from_bytes(4, false), MlilType::UInt(32));
        assert_eq!(MlilType::from_bytes(8, true), MlilType::SInt(64));
    }
}
