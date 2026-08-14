//! Type propagation for the decompiler expression tree.
//!
//! Assigns the most specific `TypeAnnotation` to each sub-expression
//! by propagating known type information from leaves to roots (bottom-up)
//! and from context to leaves (top-down).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{BinOp, Expr, IntWidth, UnOp};

// ─── TypeAnnotation ───────────────────────────────────────────────────────────

/// The inferred type of an expression node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeAnnotation {
    /// A fixed-width integer.
    Int(IntWidth),
    /// Boolean (result of a comparison or logical op).
    Bool,
    /// A pointer to something.
    Pointer { pointee: Box<Self>, bytes: u8 },
    /// Function pointer.
    FunctionPtr,
    /// Type could not be determined.
    Unknown,
    /// Multiple conflicting annotations — propagation failed here.
    Conflict(Box<Self>, Box<Self>),
}

impl TypeAnnotation {
    /// Returns `true` if the annotation is not `Unknown` or `Conflict`.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown | Self::Conflict(_, _))
    }

    /// Try to unify two annotations.  Returns `Conflict` on mismatch.
    #[must_use]
    pub fn unify(a: Self, b: Self) -> Self {
        if a == b {
            return a;
        }
        match (&a, &b) {
            (Self::Unknown, _) => b,
            (_, Self::Unknown) => a,
            (Self::Int(wa), Self::Int(wb)) => {
                // Prefer wider type.
                if wa.bits() >= wb.bits() { a } else { b }
            }
            _ => Self::Conflict(Box::new(a), Box::new(b)),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Int(w) => format!("{w}"),
            Self::Bool => "bool".to_string(),
            Self::Pointer { pointee, bytes } => {
                format!("ptr{}({})", bytes * 8, pointee.display())
            }
            Self::FunctionPtr => "fnptr".to_string(),
            Self::Unknown => "?".to_string(),
            Self::Conflict(a, b) => format!("conflict({},{})", a.display(), b.display()),
        }
    }
}

// ─── TypeEnvironment ──────────────────────────────────────────────────────────

/// Maps variable names to their known types.
#[derive(Debug, Default, Clone)]
pub struct TypeEnvironment {
    bindings: HashMap<String, TypeAnnotation>,
}

impl TypeEnvironment {
    /// Create an empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a variable to a type.
    pub fn bind(&mut self, name: impl Into<String>, ty: TypeAnnotation) {
        self.bindings.insert(name.into(), ty);
    }

    /// Look up a variable type.
    #[must_use]
    pub fn lookup(&self, name: &str) -> TypeAnnotation {
        self.bindings.get(name).cloned().unwrap_or(TypeAnnotation::Unknown)
    }

    /// Merge another environment into `self`, unifying shared bindings.
    pub fn merge_from(&mut self, other: &Self) {
        for (k, v) in &other.bindings {
            let existing = self.lookup(k);
            self.bindings.insert(k.clone(), TypeAnnotation::unify(existing, v.clone()));
        }
    }

    /// All known bindings.
    #[must_use]
    pub const fn all_bindings(&self) -> &HashMap<String, TypeAnnotation> {
        &self.bindings
    }
}

// ─── PropagationResult ───────────────────────────────────────────────────────

/// Result of running type propagation over an expression.
#[derive(Debug, Serialize, Deserialize)]
pub struct PropagationResult {
    /// Inferred type at the root of the expression.
    pub root_type: TypeAnnotation,
    /// Types inferred for each variable seen in the expression.
    pub inferred_vars: HashMap<String, TypeAnnotation>,
    /// Number of nodes that have a known type.
    pub typed_nodes: usize,
    /// Number of nodes that remain `Unknown`.
    pub unknown_nodes: usize,
    /// Number of conflict nodes.
    pub conflict_nodes: usize,
}

// ─── ExprTypePropagator ──────────────────────────────────────────────────────

/// Propagates type information through an `Expr` tree.
pub struct ExprTypePropagator {
    /// Initial type environment (variable → type bindings).
    pub env: TypeEnvironment,
    /// Pointer width in bytes (4 for 32-bit, 8 for 64-bit targets).
    pub pointer_bytes: u8,
}

impl Default for ExprTypePropagator {
    fn default() -> Self {
        Self {
            env: TypeEnvironment::new(),
            pointer_bytes: 8,
        }
    }
}

impl ExprTypePropagator {
    /// Create a propagator with an empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a pre-populated type environment.
    #[must_use]
    pub const fn with_env(env: TypeEnvironment) -> Self {
        Self { env, pointer_bytes: 8 }
    }

    /// Run propagation and return the result.
    #[must_use]
    pub fn propagate(&self, expr: &Expr) -> PropagationResult {
        let mut inferred_vars: HashMap<String, TypeAnnotation> = HashMap::new();
        let mut typed = 0usize;
        let mut unknown = 0usize;
        let mut conflicts = 0usize;

        let root_type = self.infer(expr, &mut inferred_vars, &mut typed, &mut unknown, &mut conflicts);

        PropagationResult {
            root_type,
            inferred_vars,
            typed_nodes: typed,
            unknown_nodes: unknown,
            conflict_nodes: conflicts,
        }
    }

    fn infer(
        &self,
        expr: &Expr,
        vars: &mut HashMap<String, TypeAnnotation>,
        typed: &mut usize,
        unknown: &mut usize,
        conflicts: &mut usize,
    ) -> TypeAnnotation {
        let ty = self.infer_inner(expr, vars, typed, unknown, conflicts);
        match &ty {
            TypeAnnotation::Unknown => *unknown += 1,
            TypeAnnotation::Conflict(_, _) => *conflicts += 1,
            _ => *typed += 1,
        }
        ty
    }

    fn infer_inner(
        &self,
        expr: &Expr,
        vars: &mut HashMap<String, TypeAnnotation>,
        typed: &mut usize,
        unknown: &mut usize,
        conflicts: &mut usize,
    ) -> TypeAnnotation {
        match expr {
            Expr::Const(_, w) => TypeAnnotation::Int(*w),

            Expr::Var(name) => {
                let ty = self.env.lookup(name);
                if ty.is_known() {
                    vars.insert(name.clone(), ty.clone());
                }
                ty
            }

            Expr::BinOp(op, lhs, rhs) => {
                let lt = self.infer(lhs, vars, typed, unknown, conflicts);
                let rt = self.infer(rhs, vars, typed, unknown, conflicts);
                Self::infer_binop(*op, lt, rt)
            }

            Expr::UnOp(op, inner) => {
                let inner_ty = self.infer(inner, vars, typed, unknown, conflicts);
                self.infer_unop(*op, inner_ty)
            }

            Expr::Ternary { cond, then_expr, else_expr } => {
                let _cond_ty = self.infer(cond, vars, typed, unknown, conflicts);
                let tt = self.infer(then_expr, vars, typed, unknown, conflicts);
                let et = self.infer(else_expr, vars, typed, unknown, conflicts);
                TypeAnnotation::unify(tt, et)
            }

            Expr::Call { .. } => TypeAnnotation::Unknown,

            Expr::Load { size, .. } => {
                // A load of N bytes produces an integer of N bytes.
                match *size {
                    1 => TypeAnnotation::Int(IntWidth::U8),
                    2 => TypeAnnotation::Int(IntWidth::U16),
                    4 => TypeAnnotation::Int(IntWidth::U32),
                    8 => TypeAnnotation::Int(IntWidth::U64),
                    _ => TypeAnnotation::Unknown,
                }
            }

            Expr::FieldAccess { base, .. } => {
                // Field access: infer the base type but the result type is unknown
                // without struct layout information.
                let _ = self.infer(base, vars, typed, unknown, conflicts);
                TypeAnnotation::Unknown
            }

            Expr::Index { base, index, .. } => {
                // Index access: infer both operands; result type is unknown
                // without array element type information.
                let _ = self.infer(base, vars, typed, unknown, conflicts);
                let _ = self.infer(index, vars, typed, unknown, conflicts);
                TypeAnnotation::Unknown
            }

            Expr::Phi(exprs) => {
                // A phi node's type is the unified type of all incoming values.
                exprs
                    .iter()
                    .map(|e| self.infer(e, vars, typed, unknown, conflicts))
                    .fold(TypeAnnotation::Unknown, TypeAnnotation::unify)
            }
        }
    }

    fn infer_binop(op: BinOp, lt: TypeAnnotation, rt: TypeAnnotation) -> TypeAnnotation {
        if op.is_comparison() || op.is_logical() {
            return TypeAnnotation::Bool;
        }
        TypeAnnotation::unify(lt, rt)
    }

    fn infer_unop(&self, op: UnOp, inner_ty: TypeAnnotation) -> TypeAnnotation {
        match op {
            UnOp::LNot => TypeAnnotation::Bool,
            UnOp::Cast(w) => TypeAnnotation::Int(w),
            UnOp::AddrOf => TypeAnnotation::Pointer {
                pointee: Box::new(inner_ty),
                bytes: self.pointer_bytes,
            },
            UnOp::Deref => {
                if let TypeAnnotation::Pointer { pointee, .. } = inner_ty {
                    *pointee
                } else {
                    TypeAnnotation::Unknown
                }
            }
            _ => inner_ty,
        }
    }

    /// Annotate all variable bindings discovered in `expr` back into `env`.
    pub fn update_env_from(&mut self, result: &PropagationResult) {
        for (k, v) in &result.inferred_vars {
            let existing = self.env.lookup(k);
            self.env.bind(k.clone(), TypeAnnotation::unify(existing, v.clone()));
        }
    }
}

// ─── TypePropagationPipeline ─────────────────────────────────────────────────

/// Run propagation over a list of expressions in sequence, sharing the
/// accumulated type environment across all of them.
pub struct TypePropagationPipeline {
    propagator: ExprTypePropagator,
}

impl TypePropagationPipeline {
    /// Create with an empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self { propagator: ExprTypePropagator::new() }
    }

    /// Create with a seed environment.
    #[must_use]
    pub const fn with_env(env: TypeEnvironment) -> Self {
        Self { propagator: ExprTypePropagator::with_env(env) }
    }

    /// Propagate types for `expr` and absorb the results back into the
    /// shared environment for the next call.
    pub fn process(&mut self, expr: &Expr) -> PropagationResult {
        let result = self.propagator.propagate(expr);
        self.propagator.update_env_from(&result);
        result
    }

    /// Return the accumulated type environment.
    #[must_use]
    pub const fn env(&self) -> &TypeEnvironment {
        &self.propagator.env
    }
}

impl Default for TypePropagationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntWidth;

    fn c(v: i64, w: IntWidth) -> Expr { Expr::Const(v, w) }
    fn var(name: &str) -> Expr { Expr::Var(name.to_string()) }

    #[test]
    fn const_type() {
        let p = ExprTypePropagator::new();
        let r = p.propagate(&c(42, IntWidth::I32));
        assert_eq!(r.root_type, TypeAnnotation::Int(IntWidth::I32));
    }

    #[test]
    fn var_lookup_known() {
        let mut env = TypeEnvironment::new();
        env.bind("x", TypeAnnotation::Int(IntWidth::U64));
        let p = ExprTypePropagator::with_env(env);
        let r = p.propagate(&var("x"));
        assert_eq!(r.root_type, TypeAnnotation::Int(IntWidth::U64));
    }

    #[test]
    fn var_lookup_unknown() {
        let p = ExprTypePropagator::new();
        let r = p.propagate(&var("unknown_var"));
        assert_eq!(r.root_type, TypeAnnotation::Unknown);
    }

    #[test]
    fn comparison_bool() {
        let p = ExprTypePropagator::new();
        let expr = Expr::BinOp(BinOp::Eq, Box::new(c(1, IntWidth::I32)), Box::new(c(1, IntWidth::I32)));
        let r = p.propagate(&expr);
        assert_eq!(r.root_type, TypeAnnotation::Bool);
    }

    #[test]
    fn lnot_bool() {
        let p = ExprTypePropagator::new();
        let expr = Expr::UnOp(UnOp::LNot, Box::new(var("flag")));
        let r = p.propagate(&expr);
        assert_eq!(r.root_type, TypeAnnotation::Bool);
    }

    #[test]
    fn cast_type() {
        let p = ExprTypePropagator::new();
        let expr = Expr::UnOp(UnOp::Cast(IntWidth::U8), Box::new(c(1000, IntWidth::I32)));
        let r = p.propagate(&expr);
        assert_eq!(r.root_type, TypeAnnotation::Int(IntWidth::U8));
    }

    #[test]
    fn load_4_bytes() {
        let p = ExprTypePropagator::new();
        let expr = Expr::Load { ptr: Box::new(var("ptr")), size: 4 };
        let r = p.propagate(&expr);
        assert_eq!(r.root_type, TypeAnnotation::Int(IntWidth::U32));
    }

    #[test]
    fn ternary_unify() {
        let p = ExprTypePropagator::new();
        let expr = Expr::Ternary {
            cond: Box::new(c(1, IntWidth::I32)),
            then_expr: Box::new(c(0, IntWidth::I32)),
            else_expr: Box::new(c(1, IntWidth::I32)),
        };
        let r = p.propagate(&expr);
        assert_eq!(r.root_type, TypeAnnotation::Int(IntWidth::I32));
    }

    #[test]
    fn pipeline_accumulates_env() {
        let mut pipeline = TypePropagationPipeline::new();
        let mut env_seed = TypeEnvironment::new();
        env_seed.bind("n", TypeAnnotation::Int(IntWidth::I64));
        pipeline.propagator.env = env_seed;
        let expr = Expr::BinOp(BinOp::Add, Box::new(var("n")), Box::new(c(1, IntWidth::I64)));
        let r = pipeline.process(&expr);
        assert!(r.inferred_vars.contains_key("n"));
    }

    #[test]
    fn unify_unknown() {
        let a = TypeAnnotation::Unknown;
        let b = TypeAnnotation::Int(IntWidth::I32);
        assert_eq!(TypeAnnotation::unify(a, b), TypeAnnotation::Int(IntWidth::I32));
    }

    #[test]
    fn typed_nodes_counted() {
        let p = ExprTypePropagator::new();
        let expr = Expr::BinOp(
            BinOp::Add,
            Box::new(c(1, IntWidth::I32)),
            Box::new(c(2, IntWidth::I32)),
        );
        let r = p.propagate(&expr);
        assert!(r.typed_nodes >= 3); // root + 2 leaves
    }
}
