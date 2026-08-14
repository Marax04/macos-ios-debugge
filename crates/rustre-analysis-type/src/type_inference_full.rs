//! Complete Hindley-Milner style type inference.
//!
//! Implements Algorithm W with full unification, generalisation/instantiation,
//! let-polymorphism, and occurs-check.  The primary types are adapted for a
//! binary-analysis context: integers, pointers, arrays, structs, and function
//! types.

use std::collections::{HashMap, HashSet};
use std::fmt;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Type variable
// ─────────────────────────────────────────────────────────────────────────────

/// A type variable used during inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TyVar(pub u32);

impl fmt::Display for TyVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "α{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mono type
// ─────────────────────────────────────────────────────────────────────────────

/// A monomorphic type in the inference system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MonoType {
    /// A type variable.
    Var(TyVar),
    /// An integer of given bit width (8/16/32/64).
    Int { bits: u32, signed: bool },
    /// A boolean.
    Bool,
    /// A floating-point type.
    Float { bits: u32 },
    /// A pointer to another type.
    Ptr(Box<Self>),
    /// A fixed-length array.
    Array {
        elem: Box<Self>,
        len: Option<u32>,
    },
    /// A struct with named fields at byte offsets.
    Struct { fields: Vec<(u32, Self)> },
    /// A function type: argument types → return type.
    Func {
        args: Vec<Self>,
        ret: Box<Self>,
    },
    /// Void / no type.
    Void,
}

impl fmt::Display for MonoType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Var(v) => write!(f, "{v}"),
            Self::Int { bits, signed } => {
                write!(f, "{}{bits}", if *signed { "i" } else { "u" })
            }
            Self::Bool => write!(f, "bool"),
            Self::Float { bits } => write!(f, "f{bits}"),
            Self::Ptr(inner) => write!(f, "*{inner}"),
            Self::Array { elem, len } => match len {
                Some(n) => write!(f, "[{elem}; {n}]"),
                None => write!(f, "[{elem}]"),
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
            Self::Func { args, ret } => {
                write!(f, "(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ") -> {ret}")
            }
            Self::Void => write!(f, "void"),
        }
    }
}

impl MonoType {
    /// Collect all free type variables in this type.
    #[must_use]
    pub fn free_vars(&self) -> HashSet<TyVar> {
        match self {
            Self::Var(v) => {
                let mut s = HashSet::new();
                s.insert(*v);
                s
            }
            Self::Ptr(inner) => inner.free_vars(),
            Self::Array { elem, .. } => elem.free_vars(),
            Self::Struct { fields } => fields.iter().flat_map(|(_, t)| t.free_vars()).collect(),
            Self::Func { args, ret } => {
                let mut s: HashSet<TyVar> = args.iter().flat_map(Self::free_vars).collect();
                s.extend(ret.free_vars());
                s
            }
            _ => HashSet::new(),
        }
    }

    /// Apply a `TypeSubstitution` to this type.
    #[must_use]
    pub fn apply(&self, subst: &TypeSubstitution) -> Self {
        match self {
            Self::Var(v) => subst.lookup(*v).unwrap_or_else(|| self.clone()),
            Self::Ptr(inner) => Self::Ptr(Box::new(inner.apply(subst))),
            Self::Array { elem, len } => Self::Array {
                elem: Box::new(elem.apply(subst)),
                len: *len,
            },
            Self::Struct { fields } => Self::Struct {
                fields: fields
                    .iter()
                    .map(|(off, t)| (*off, t.apply(subst)))
                    .collect(),
            },
            Self::Func { args, ret } => Self::Func {
                args: args.iter().map(|a| a.apply(subst)).collect(),
                ret: Box::new(ret.apply(subst)),
            },
            _ => self.clone(),
        }
    }

    /// Return true if `var` occurs anywhere in `self` (occurs-check).
    #[must_use]
    pub fn occurs(&self, var: TyVar) -> bool {
        self.free_vars().contains(&var)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolyType / TypeScheme
// ─────────────────────────────────────────────────────────────────────────────

/// A polymorphic type (type scheme): `∀ α₁…αn. τ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolyType {
    /// Universally quantified variables.
    pub quantified: Vec<TyVar>,
    /// The underlying monotype.
    pub body: MonoType,
}

impl PolyType {
    /// Create a monomorphic scheme (no quantified variables).
    #[must_use]
    pub const fn mono(ty: MonoType) -> Self {
        Self {
            quantified: Vec::new(),
            body: ty,
        }
    }

    /// Generalise `ty` over all free variables not in `env`.
    #[must_use]
    pub fn generalise(ty: MonoType, env: &TypeEnv) -> Self {
        let env_free = env.free_vars();
        let mut quantified: Vec<TyVar> = ty
            .free_vars()
            .into_iter()
            .filter(|v| !env_free.contains(v))
            .collect();
        // Sort: `free_vars` is a HashSet, so collecting directly makes the
        // quantifier order (which drives instantiation numbering, Display,
        // and PolyType equality) nondeterministic across runs.
        quantified.sort_unstable();
        Self {
            quantified,
            body: ty,
        }
    }

    /// Free variables in the scheme (not bound by quantifiers).
    #[must_use]
    pub fn free_vars(&self) -> HashSet<TyVar> {
        let bound: HashSet<TyVar> = self.quantified.iter().copied().collect();
        self.body.free_vars().difference(&bound).copied().collect()
    }

    /// Apply a substitution to the scheme body (quantified vars are left alone).
    #[must_use]
    pub fn apply(&self, subst: &TypeSubstitution) -> Self {
        // Build a restricted substitution that does not touch quantified vars.
        let mut restricted = subst.clone();
        for &v in &self.quantified {
            restricted.remove(v);
        }
        Self {
            quantified: self.quantified.clone(),
            body: self.body.apply(&restricted),
        }
    }
}

/// Alias for `PolyType` to match naming in the public API.
pub type TypeScheme = PolyType;

impl fmt::Display for PolyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.quantified.is_empty() {
            write!(f, "∀")?;
            for (i, v) in self.quantified.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{v}")?;
            }
            write!(f, ". ")?;
        }
        write!(f, "{}", self.body)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeSubstitution
// ─────────────────────────────────────────────────────────────────────────────

/// A finite map from type variables to mono-types.
#[derive(Debug, Clone, Default)]
pub struct TypeSubstitution {
    map: HashMap<TyVar, MonoType>,
}

impl TypeSubstitution {
    /// Create an empty substitution (identity).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `var` to `ty`.
    pub fn bind(&mut self, var: TyVar, ty: MonoType) {
        self.map.insert(var, ty);
    }

    /// Remove a binding.
    pub fn remove(&mut self, var: TyVar) {
        self.map.remove(&var);
    }

    /// Look up `var`.
    #[must_use]
    pub fn lookup(&self, var: TyVar) -> Option<MonoType> {
        self.map.get(&var).cloned()
    }

    /// Compose `self` with `other`: `self ∘ other`.
    /// The result maps `v` → `other(v)` applied with `self`, then adds `self`.
    #[must_use]
    pub fn compose(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for (&v, ty) in &other.map {
            result.bind(v, ty.apply(self));
        }
        for (&v, ty) in &self.map {
            result.map.entry(v).or_insert_with(|| ty.clone());
        }
        result
    }

    /// Number of bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the substitution is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeEquation
// ─────────────────────────────────────────────────────────────────────────────

/// A type equality constraint: `lhs = rhs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEquation {
    pub lhs: MonoType,
    pub rhs: MonoType,
}

impl TypeEquation {
    #[must_use]
    pub const fn new(lhs: MonoType, rhs: MonoType) -> Self {
        Self { lhs, rhs }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnificationAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from unification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UnifyError {
    #[error("cannot unify {0} with {1}")]
    Conflict(String, String),
    #[error("occurs check failed: {0} occurs in {1}")]
    OccursCheck(String, String),
    #[error("struct field count mismatch")]
    StructMismatch,
    #[error("function arity mismatch: {0} vs {1}")]
    ArityMismatch(usize, usize),
}

/// The Robinson unification algorithm.
pub struct UnificationAlgorithm;

impl UnificationAlgorithm {
    /// Unify `lhs` with `rhs` given the current substitution.
    /// Returns the updated substitution on success.
    ///
    /// # Errors
    /// Returns `UnifyError` if the types cannot be unified.
    pub fn unify(
        lhs: &MonoType,
        rhs: &MonoType,
        subst: &TypeSubstitution,
    ) -> Result<TypeSubstitution, UnifyError> {
        let lhs = lhs.apply(subst);
        let rhs = rhs.apply(subst);
        Self::unify_inner(&lhs, &rhs, subst)
    }

    /// Solve a list of equations, returning the most general unifier.
    ///
    /// # Errors
    /// Returns `UnifyError` if any equation cannot be unified.
    pub fn solve(equations: &[TypeEquation]) -> Result<TypeSubstitution, UnifyError> {
        let mut subst = TypeSubstitution::new();
        for eq in equations {
            let new_subst = Self::unify(&eq.lhs, &eq.rhs, &subst)?;
            subst = new_subst;
        }
        Ok(subst)
    }

    fn unify_inner(
        lhs: &MonoType,
        rhs: &MonoType,
        subst: &TypeSubstitution,
    ) -> Result<TypeSubstitution, UnifyError> {
        match (lhs, rhs) {
            (a, b) if a == b => Ok(subst.clone()),

            (MonoType::Var(v), ty) | (ty, MonoType::Var(v)) => {
                if let MonoType::Var(v2) = ty && v == v2 {
                    return Ok(subst.clone());
                }
                if ty.occurs(*v) {
                    return Err(UnifyError::OccursCheck(v.to_string(), ty.to_string()));
                }
                // Keep the substitution idempotent: apply the new binding to
                // the RANGE of the existing substitution before adding it.
                // Merely inserting `v → ty` leaves earlier bindings like
                // `v0 → Ptr(v)` unresolved, so `apply` on the final "MGU"
                // returned by `solve` produced types still containing solved
                // variables (chained equations were not fully resolved).
                let mut single = TypeSubstitution::new();
                single.bind(*v, ty.clone());
                let mut new_subst = TypeSubstitution::new();
                for (&k, t) in &subst.map {
                    new_subst.bind(k, t.apply(&single));
                }
                new_subst.bind(*v, ty.clone());
                Ok(new_subst)
            }

            (MonoType::Ptr(a), MonoType::Ptr(b)) => Self::unify(a, b, subst),

            (MonoType::Array { elem: ea, len: la }, MonoType::Array { elem: eb, len: lb }) => {
                if la != lb {
                    return Err(UnifyError::Conflict(lhs.to_string(), rhs.to_string()));
                }
                Self::unify(ea, eb, subst)
            }

            (MonoType::Func { args: aa, ret: ra }, MonoType::Func { args: ab, ret: rb }) => {
                if aa.len() != ab.len() {
                    return Err(UnifyError::ArityMismatch(aa.len(), ab.len()));
                }
                let mut s = subst.clone();
                for (a, b) in aa.iter().zip(ab.iter()) {
                    s = Self::unify(a, b, &s)?;
                }
                Self::unify(ra, rb, &s)
            }

            (MonoType::Struct { fields: fa }, MonoType::Struct { fields: fb }) => {
                if fa.len() != fb.len() {
                    return Err(UnifyError::StructMismatch);
                }
                let mut s = subst.clone();
                for ((oa, ta), (ob, tb)) in fa.iter().zip(fb.iter()) {
                    if oa != ob {
                        return Err(UnifyError::StructMismatch);
                    }
                    s = Self::unify(ta, tb, &s)?;
                }
                Ok(s)
            }

            _ => Err(UnifyError::Conflict(lhs.to_string(), rhs.to_string())),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeEnv
// ─────────────────────────────────────────────────────────────────────────────

/// A typing environment (Γ): maps variable names to type schemes.
#[derive(Debug, Clone, Default)]
pub struct TypeEnv {
    bindings: HashMap<String, PolyType>,
}

impl TypeEnv {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a name to a type scheme.
    pub fn insert(&mut self, name: impl Into<String>, scheme: PolyType) {
        self.bindings.insert(name.into(), scheme);
    }

    /// Look up a name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&PolyType> {
        self.bindings.get(name)
    }

    /// Free type variables across all bindings.
    #[must_use]
    pub fn free_vars(&self) -> HashSet<TyVar> {
        self.bindings.values().flat_map(PolyType::free_vars).collect()
    }

    /// Apply a substitution to all schemes in the environment.
    #[must_use]
    pub fn apply(&self, subst: &TypeSubstitution) -> Self {
        Self {
            bindings: self
                .bindings
                .iter()
                .map(|(k, s)| (k.clone(), s.apply(subst)))
                .collect(),
        }
    }

    /// Number of bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether the environment is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fresh variable generator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates fresh type variables.
#[derive(Debug, Default)]
pub struct FreshVars {
    next: u32,
}

impl FreshVars {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the next fresh `TyVar`.
    pub const fn fresh(&mut self) -> TyVar {
        let v = TyVar(self.next);
        self.next += 1;
        v
    }

    /// Return the next fresh `MonoType::Var`.
    pub const fn fresh_ty(&mut self) -> MonoType {
        MonoType::Var(self.fresh())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeInferenceFull
// ─────────────────────────────────────────────────────────────────────────────

/// Inference error.
#[derive(Debug, Error, Clone)]
pub enum InferenceError {
    #[error("unbound variable: {0}")]
    UnboundVariable(String),
    #[error("unification error: {0}")]
    Unification(#[from] UnifyError),
}

/// A simple expression language for testing the inference engine.
#[derive(Debug, Clone)]
pub enum Expr {
    Lit(Literal),
    Var(String),
    App {
        func: Box<Self>,
        arg: Box<Self>,
    },
    Abs {
        param: String,
        body: Box<Self>,
    },
    Let {
        name: String,
        def: Box<Self>,
        body: Box<Self>,
    },
    If {
        cond: Box<Self>,
        then: Box<Self>,
        else_: Box<Self>,
    },
}

/// Literal values.
#[derive(Debug, Clone)]
pub enum Literal {
    Int(i64),
    Bool(bool),
    Ptr(u64),
}

/// Full Hindley-Milner type inference engine.
pub struct TypeInferenceFull {
    pub fresh: FreshVars,
}

impl Default for TypeInferenceFull {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeInferenceFull {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fresh: FreshVars::new(),
        }
    }

    /// Infer the type of `expr` in environment `env`.
    /// Returns `(type, substitution)`.
    ///
    /// # Errors
    /// Returns `InferenceError` on type mismatch or unbound variable.
    pub fn infer(
        &mut self,
        env: &TypeEnv,
        expr: &Expr,
    ) -> Result<(MonoType, TypeSubstitution), InferenceError> {
        match expr {
            Expr::Lit(Literal::Int(_)) => Ok((
                MonoType::Int {
                    bits: 64,
                    signed: true,
                },
                TypeSubstitution::new(),
            )),
            Expr::Lit(Literal::Bool(_)) => Ok((MonoType::Bool, TypeSubstitution::new())),
            Expr::Lit(Literal::Ptr(_)) => {
                let inner = self.fresh.fresh_ty();
                Ok((MonoType::Ptr(Box::new(inner)), TypeSubstitution::new()))
            }

            Expr::Var(name) => {
                let scheme = env
                    .lookup(name)
                    .ok_or_else(|| InferenceError::UnboundVariable(name.clone()))?;
                let ty = self.instantiate(scheme);
                Ok((ty, TypeSubstitution::new()))
            }

            Expr::Abs { param, body } => {
                let param_ty = self.fresh.fresh_ty();
                let mut env2 = env.clone();
                env2.insert(param.clone(), PolyType::mono(param_ty.clone()));
                let (ret_ty, s) = self.infer(&env2, body)?;
                let func_ty = MonoType::Func {
                    args: vec![param_ty.apply(&s)],
                    ret: Box::new(ret_ty),
                };
                Ok((func_ty, s))
            }

            Expr::App { func, arg } => {
                let (func_ty, s1) = self.infer(env, func)?;
                let env2 = env.apply(&s1);
                let (arg_ty, s2) = self.infer(&env2, arg)?;
                let ret_ty = self.fresh.fresh_ty();
                let expected = MonoType::Func {
                    args: vec![arg_ty],
                    ret: Box::new(ret_ty.clone()),
                };
                let s3 = UnificationAlgorithm::unify(&func_ty.apply(&s2), &expected, &s2)?;
                let result_ty = ret_ty.apply(&s3);
                let subst = s3.compose(&s2.compose(&s1));
                Ok((result_ty, subst))
            }

            Expr::Let { name, def, body } => {
                let (def_ty, s1) = self.infer(env, def)?;
                let env2 = env.apply(&s1);
                let scheme = PolyType::generalise(def_ty, &env2);
                let mut env3 = env2;
                env3.insert(name.clone(), scheme);
                let (body_ty, s2) = self.infer(&env3, body)?;
                let subst = s2.compose(&s1);
                Ok((body_ty, subst))
            }

            Expr::If { cond, then, else_ } => {
                let (cond_ty, s1) = self.infer(env, cond)?;
                let s2 = UnificationAlgorithm::unify(&cond_ty, &MonoType::Bool, &s1)?;
                let env2 = env.apply(&s2);
                let (then_ty, s3) = self.infer(&env2, then)?;
                let env3 = env2.apply(&s3);
                let (else_ty, s4) = self.infer(&env3, else_)?;
                let s5 = UnificationAlgorithm::unify(
                    &then_ty.apply(&s4),
                    &else_ty,
                    &s4.compose(&s3.compose(&s2.compose(&s1))),
                )?;
                let result = then_ty.apply(&s5);
                Ok((result, s5))
            }
        }
    }

    /// Instantiate a type scheme: replace each quantified variable with a fresh one.
    fn instantiate(&mut self, scheme: &PolyType) -> MonoType {
        if scheme.quantified.is_empty() {
            return scheme.body.clone();
        }
        let mut mapping = TypeSubstitution::new();
        for &v in &scheme.quantified {
            mapping.bind(v, self.fresh.fresh_ty());
        }
        scheme.body.apply(&mapping)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn int64() -> MonoType {
        MonoType::Int {
            bits: 64,
            signed: true,
        }
    }
    fn bool_ty() -> MonoType {
        MonoType::Bool
    }
    fn ptr(inner: MonoType) -> MonoType {
        MonoType::Ptr(Box::new(inner))
    }
    fn func1(arg: MonoType, ret: MonoType) -> MonoType {
        MonoType::Func {
            args: vec![arg],
            ret: Box::new(ret),
        }
    }
    fn var(n: u32) -> MonoType {
        MonoType::Var(TyVar(n))
    }

    // 1. Fresh variables are distinct
    #[test]
    fn test_fresh_vars_distinct() {
        let mut fresh = FreshVars::new();
        let v1 = fresh.fresh();
        let v2 = fresh.fresh();
        assert_ne!(v1, v2);
    }

    // 2. Free vars of a var type
    #[test]
    fn test_free_vars_var() {
        let ty = var(0);
        assert!(ty.free_vars().contains(&TyVar(0)));
    }

    // 3. Free vars of a concrete type
    #[test]
    fn test_free_vars_concrete() {
        assert!(int64().free_vars().is_empty());
    }

    // 4. Free vars of a pointer type
    #[test]
    fn test_free_vars_ptr() {
        let ty = ptr(var(5));
        assert!(ty.free_vars().contains(&TyVar(5)));
    }

    // 5. Substitution lookup
    #[test]
    fn test_subst_lookup() {
        let mut s = TypeSubstitution::new();
        s.bind(TyVar(0), int64());
        assert_eq!(s.lookup(TyVar(0)), Some(int64()));
        assert_eq!(s.lookup(TyVar(1)), None);
    }

    // 6. Applying substitution to a var
    #[test]
    fn test_apply_subst_var() {
        let mut s = TypeSubstitution::new();
        s.bind(TyVar(0), int64());
        assert_eq!(var(0).apply(&s), int64());
    }

    // 7. Applying substitution does not affect non-matching var
    #[test]
    fn test_apply_subst_noop() {
        let s = TypeSubstitution::new();
        assert_eq!(var(99).apply(&s), var(99));
    }

    // 8. Substitution composition
    #[test]
    fn test_subst_compose() {
        let mut s1 = TypeSubstitution::new();
        s1.bind(TyVar(0), var(1));
        let mut s2 = TypeSubstitution::new();
        s2.bind(TyVar(1), int64());
        let composed = s2.compose(&s1);
        // var(0) should map through to int64
        assert_eq!(var(0).apply(&composed), int64());
    }

    // 9. Unify two identical types
    #[test]
    fn test_unify_identical() {
        let s = UnificationAlgorithm::unify(&int64(), &int64(), &TypeSubstitution::new());
        assert!(s.is_ok());
    }

    // 10. Unify var with concrete type
    #[test]
    fn test_unify_var_concrete() {
        let s = UnificationAlgorithm::unify(&var(0), &int64(), &TypeSubstitution::new())
            .expect("unify ok");
        assert_eq!(s.lookup(TyVar(0)), Some(int64()));
    }

    // 11. Unify concrete with var (symmetric)
    #[test]
    fn test_unify_concrete_var() {
        let s = UnificationAlgorithm::unify(&int64(), &var(0), &TypeSubstitution::new())
            .expect("symmetric ok");
        assert_eq!(s.lookup(TyVar(0)), Some(int64()));
    }

    // 12. Unify ptr types
    #[test]
    fn test_unify_ptr() {
        let s = UnificationAlgorithm::unify(&ptr(var(0)), &ptr(int64()), &TypeSubstitution::new())
            .expect("ptr unify ok");
        assert_eq!(var(0).apply(&s), int64());
    }

    // 13. Unify function types
    #[test]
    fn test_unify_func() {
        let f1 = func1(var(0), var(1));
        let f2 = func1(int64(), bool_ty());
        let s = UnificationAlgorithm::unify(&f1, &f2, &TypeSubstitution::new()).expect("func ok");
        assert_eq!(var(0).apply(&s), int64());
        assert_eq!(var(1).apply(&s), bool_ty());
    }

    // 14. Unify fails on conflict
    #[test]
    fn test_unify_conflict() {
        let r = UnificationAlgorithm::unify(&int64(), &bool_ty(), &TypeSubstitution::new());
        assert!(matches!(r, Err(UnifyError::Conflict(_, _))));
    }

    // 15. Occurs check
    #[test]
    fn test_occurs_check() {
        // var(0) = ptr(var(0)) should fail
        let r = UnificationAlgorithm::unify(&var(0), &ptr(var(0)), &TypeSubstitution::new());
        assert!(matches!(r, Err(UnifyError::OccursCheck(_, _))));
    }

    // 16. Arity mismatch
    #[test]
    fn test_arity_mismatch() {
        let f1 = MonoType::Func {
            args: vec![int64(), int64()],
            ret: Box::new(bool_ty()),
        };
        let f2 = func1(int64(), bool_ty());
        let r = UnificationAlgorithm::unify(&f1, &f2, &TypeSubstitution::new());
        assert!(matches!(r, Err(UnifyError::ArityMismatch(_, _))));
    }

    // 17. Solve empty equations
    #[test]
    fn test_solve_empty() {
        let s = UnificationAlgorithm::solve(&[]).expect("ok");
        assert!(s.is_empty());
    }

    // 18. Solve a single equation
    #[test]
    fn test_solve_single_eq() {
        let eq = TypeEquation::new(var(0), int64());
        let s = UnificationAlgorithm::solve(&[eq]).expect("ok");
        assert_eq!(var(0).apply(&s), int64());
    }

    // 19. Infer literal int
    #[test]
    fn test_infer_int_lit() {
        let mut inf = TypeInferenceFull::new();
        let env = TypeEnv::new();
        let (ty, _) = inf.infer(&env, &Expr::Lit(Literal::Int(42))).expect("ok");
        assert_eq!(ty, int64());
    }

    // 20. Infer bool literal
    #[test]
    fn test_infer_bool_lit() {
        let mut inf = TypeInferenceFull::new();
        let (ty, _) = inf
            .infer(&TypeEnv::new(), &Expr::Lit(Literal::Bool(true)))
            .expect("ok");
        assert_eq!(ty, bool_ty());
    }

    // 21. Infer var from env
    #[test]
    fn test_infer_var() {
        let mut inf = TypeInferenceFull::new();
        let mut env = TypeEnv::new();
        env.insert("x", PolyType::mono(int64()));
        let (ty, _) = inf.infer(&env, &Expr::Var("x".into())).expect("ok");
        assert_eq!(ty, int64());
    }

    // 22. Infer unbound var fails
    #[test]
    fn test_infer_unbound_var() {
        let mut inf = TypeInferenceFull::new();
        let r = inf.infer(&TypeEnv::new(), &Expr::Var("x".into()));
        assert!(matches!(r, Err(InferenceError::UnboundVariable(_))));
    }

    // 23. Infer identity function
    #[test]
    fn test_infer_identity() {
        let mut inf = TypeInferenceFull::new();
        let id = Expr::Abs {
            param: "x".into(),
            body: Box::new(Expr::Var("x".into())),
        };
        let (ty, _) = inf.infer(&TypeEnv::new(), &id).expect("ok");
        // Should be α → α for some α
        assert!(matches!(ty, MonoType::Func { .. }));
    }

    // 24. PolyType::mono has no quantified vars
    #[test]
    fn test_polytype_mono() {
        let pt = PolyType::mono(int64());
        assert!(pt.quantified.is_empty());
        assert_eq!(pt.body, int64());
    }

    // 25. PolyType free vars excludes quantified
    #[test]
    fn test_polytype_free_vars() {
        let pt = PolyType {
            quantified: vec![TyVar(0)],
            body: func1(var(0), var(1)),
        };
        let fv = pt.free_vars();
        assert!(!fv.contains(&TyVar(0)));
        assert!(fv.contains(&TyVar(1)));
    }

    // 26. PolyType generalise captures free vars
    #[test]
    fn test_generalise() {
        let env = TypeEnv::new();
        let ty = func1(var(0), var(1));
        let pt = PolyType::generalise(ty, &env);
        let quantified: HashSet<TyVar> = pt.quantified.iter().copied().collect();
        assert!(quantified.contains(&TyVar(0)));
        assert!(quantified.contains(&TyVar(1)));
    }

    // 27. TypeEnv free_vars
    #[test]
    fn test_env_free_vars() {
        let mut env = TypeEnv::new();
        env.insert("f", PolyType::mono(func1(var(0), int64())));
        assert!(env.free_vars().contains(&TyVar(0)));
    }

    // 28. TypeEnv apply substitution
    #[test]
    fn test_env_apply_subst() {
        let mut env = TypeEnv::new();
        env.insert("x", PolyType::mono(var(0)));
        let mut s = TypeSubstitution::new();
        s.bind(TyVar(0), int64());
        let env2 = env.apply(&s);
        let scheme = env2.lookup("x").expect("exists");
        assert_eq!(scheme.body, int64());
    }

    // 29. Infer let expression
    #[test]
    fn test_infer_let() {
        let mut inf = TypeInferenceFull::new();
        let expr = Expr::Let {
            name: "x".into(),
            def: Box::new(Expr::Lit(Literal::Int(1))),
            body: Box::new(Expr::Var("x".into())),
        };
        let (ty, _) = inf.infer(&TypeEnv::new(), &expr).expect("ok");
        assert_eq!(ty, int64());
    }

    // 30. Infer if expression
    #[test]
    fn test_infer_if() {
        let mut inf = TypeInferenceFull::new();
        let expr = Expr::If {
            cond: Box::new(Expr::Lit(Literal::Bool(true))),
            then: Box::new(Expr::Lit(Literal::Int(1))),
            else_: Box::new(Expr::Lit(Literal::Int(0))),
        };
        let (ty, _) = inf.infer(&TypeEnv::new(), &expr).expect("ok");
        assert_eq!(ty, int64());
    }

    // 31. MonoType Display for Int
    #[test]
    fn test_monotype_display_int() {
        assert_eq!(int64().to_string(), "i64");
        assert_eq!(
            MonoType::Int {
                bits: 32,
                signed: false
            }
            .to_string(),
            "u32"
        );
    }

    // 32. MonoType Display for Func
    #[test]
    fn test_monotype_display_func() {
        let f = func1(int64(), bool_ty());
        assert!(f.to_string().contains("->"));
    }

    // 33. Subst len and is_empty
    #[test]
    fn test_subst_len() {
        let mut s = TypeSubstitution::new();
        assert!(s.is_empty());
        s.bind(TyVar(0), int64());
        assert_eq!(s.len(), 1);
    }

    // 34. TypeEnv len and is_empty
    #[test]
    fn test_env_len() {
        let mut env = TypeEnv::new();
        assert!(env.is_empty());
        env.insert("x", PolyType::mono(int64()));
        assert_eq!(env.len(), 1);
    }

    // 35. Unify struct types
    #[test]
    fn test_unify_struct() {
        let s1 = MonoType::Struct {
            fields: vec![(0, var(0)), (8, int64())],
        };
        let s2 = MonoType::Struct {
            fields: vec![(0, bool_ty()), (8, int64())],
        };
        let subst = UnificationAlgorithm::unify(&s1, &s2, &TypeSubstitution::new()).expect("ok");
        assert_eq!(var(0).apply(&subst), bool_ty());
    }

    // 36. Unify struct field count mismatch
    #[test]
    fn test_unify_struct_mismatch() {
        let s1 = MonoType::Struct {
            fields: vec![(0, int64())],
        };
        let s2 = MonoType::Struct {
            fields: vec![(0, int64()), (8, bool_ty())],
        };
        let r = UnificationAlgorithm::unify(&s1, &s2, &TypeSubstitution::new());
        assert!(matches!(r, Err(UnifyError::StructMismatch)));
    }

    // 37. MonoType occurs check with nested ptr
    #[test]
    fn test_occurs_nested_ptr() {
        let ty = ptr(ptr(var(0)));
        assert!(ty.occurs(TyVar(0)));
        assert!(!ty.occurs(TyVar(1)));
    }

    // 38. PolyType apply does not affect quantified vars
    #[test]
    fn test_polytype_apply_quantified() {
        let pt = PolyType {
            quantified: vec![TyVar(0)],
            body: var(0),
        };
        let mut s = TypeSubstitution::new();
        s.bind(TyVar(0), int64());
        let pt2 = pt.apply(&s);
        // Body should remain var(0) because it is quantified
        assert_eq!(pt2.body, var(0));
    }

    // 39. FreshVars fresh_ty returns MonoType::Var
    #[test]
    fn test_fresh_ty() {
        let mut fresh = FreshVars::new();
        let ty = fresh.fresh_ty();
        assert!(matches!(ty, MonoType::Var(_)));
    }

    // 40. TyVar display
    #[test]
    fn test_tyvar_display() {
        assert_eq!(TyVar(3).to_string(), "α3");
    }

    // 41. Infer ptr literal
    #[test]
    fn test_infer_ptr_lit() {
        let mut inf = TypeInferenceFull::new();
        let (ty, _) = inf
            .infer(&TypeEnv::new(), &Expr::Lit(Literal::Ptr(0xdead_beef)))
            .expect("ok");
        assert!(matches!(ty, MonoType::Ptr(_)));
    }

    /// Regression: `unify_inner` inserted `v → ty` without applying the new
    /// binding to the range of the existing substitution, so `solve` on
    /// chained equations returned a non-idempotent "MGU": applying it to a
    /// variable left already-solved variables in the result.
    #[test]
    fn test_solve_chained_equations_fully_resolved() {
        // v0 = *v1, v1 = i64  ⇒  v0 must resolve to *i64 in ONE apply.
        let eqs = vec![
            TypeEquation::new(var(0), ptr(var(1))),
            TypeEquation::new(var(1), int64()),
        ];
        let s = UnificationAlgorithm::solve(&eqs).expect("ok");
        assert_eq!(var(0).apply(&s), ptr(int64()));
        // Idempotence: applying twice must equal applying once, for both orders.
        let eqs_rev = vec![
            TypeEquation::new(var(1), int64()),
            TypeEquation::new(var(0), ptr(var(1))),
        ];
        let s2 = UnificationAlgorithm::solve(&eqs_rev).expect("ok");
        assert_eq!(var(0).apply(&s2), ptr(int64()));
        for sub in [&s, &s2] {
            let once = var(0).apply(sub);
            assert_eq!(once.apply(sub), once, "substitution must be idempotent");
        }
    }

    /// Regression: deeper chain through a function type.
    #[test]
    fn test_solve_chain_through_func() {
        // v0 = fn(v1) -> v2, v1 = *v3, v2 = bool, v3 = i64
        let eqs = vec![
            TypeEquation::new(var(0), func1(var(1), var(2))),
            TypeEquation::new(var(1), ptr(var(3))),
            TypeEquation::new(var(2), bool_ty()),
            TypeEquation::new(var(3), int64()),
        ];
        let s = UnificationAlgorithm::solve(&eqs).expect("ok");
        assert_eq!(var(0).apply(&s), func1(ptr(int64()), bool_ty()));
    }

    /// Regression: `PolyType::generalise` collected quantifiers straight from
    /// a `HashSet`, so quantifier order (and thus scheme equality and
    /// instantiation numbering) was nondeterministic. Must now be sorted.
    #[test]
    fn test_generalise_quantifier_order_deterministic() {
        let env = TypeEnv::new();
        let ty = MonoType::Func {
            args: vec![var(9), var(2), var(7), var(1), var(5)],
            ret: Box::new(var(3)),
        };
        let expected: Vec<TyVar> = [1, 2, 3, 5, 7, 9].iter().map(|&i| TyVar(i)).collect();
        for _ in 0..20 {
            let pt = PolyType::generalise(ty.clone(), &env);
            assert_eq!(pt.quantified, expected, "quantifiers must be sorted");
        }
    }

    // 42. TypeEquation construction
    #[test]
    fn test_type_equation() {
        let eq = TypeEquation::new(var(0), int64());
        assert_eq!(eq.lhs, var(0));
        assert_eq!(eq.rhs, int64());
    }
}
