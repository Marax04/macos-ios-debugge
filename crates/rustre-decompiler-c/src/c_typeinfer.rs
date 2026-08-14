//! C type inference and propagation pass.
//!
//! [`CTypeInferencer`] propagates types through a C AST, resolves unknown
//! types, narrows casts, and reports type errors.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::c_printer::{BinOp, CExpr, CStmt, CType, UnOp};

// ─────────────────────────────────────────────────────────────────────────────
// TypeError
// ─────────────────────────────────────────────────────────────────────────────

/// A type error found during inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeError {
    pub description: String,
    pub location: Option<String>,
    pub severity: TypeErrSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeErrSeverity {
    Warning,
    Error,
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            TypeErrSeverity::Warning => "warn",
            TypeErrSeverity::Error => "error",
        };
        if let Some(ref loc) = self.location {
            write!(f, "[{}] {}: {}", sev, loc, self.description)
        } else {
            write!(f, "[{}] {}", sev, self.description)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeEnv
// ─────────────────────────────────────────────────────────────────────────────

/// A scoped type environment mapping names to types.
#[derive(Debug, Default, Clone)]
pub struct TypeEnv {
    scopes: Vec<HashMap<String, CType>>,
}

impl TypeEnv {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
        }
    }

    pub fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    pub fn define(&mut self, name: &str, ty: CType) {
        if let Some(s) = self.scopes.last_mut() {
            s.insert(name.to_string(), ty);
        }
    }

    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&CType> {
        for scope in self.scopes.iter().rev() {
            if let Some(ty) = scope.get(name) {
                return Some(ty);
            }
        }
        None
    }

    #[must_use]
    pub const fn scope_depth(&self) -> usize {
        self.scopes.len()
    }

    #[must_use]
    pub fn names_in_current_scope(&self) -> Vec<&str> {
        self.scopes
            .last()
            .map(|s| s.keys().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Infer type of CExpr
// ─────────────────────────────────────────────────────────────────────────────

/// Infer the type of an expression given a type environment.
#[must_use]
pub fn infer_expr_type(expr: &CExpr, env: &TypeEnv) -> Option<CType> {
    match expr {
        CExpr::IntLit(_) => Some(CType::Int(32, true)),
        CExpr::UIntLit(_) => Some(CType::Int(32, false)),
        CExpr::FloatLit(_) => Some(CType::Float(64)),
        CExpr::StrLit(_) => Some(CType::Pointer(Box::new(CType::Int(8, true)))),
        CExpr::CharLit(_) => Some(CType::Int(8, true)),
        CExpr::Null => Some(CType::Pointer(Box::new(CType::Void))),
        CExpr::Ident(name) => env.lookup(name).cloned(),
        CExpr::Cast(ty, _) => Some(*ty.clone()),
        CExpr::SizeOf(_) => Some(CType::Int(64, false)),
        CExpr::UnOp(op, inner) => infer_unop_type(*op, inner, env),
        CExpr::BinOp(op, lhs, rhs) => infer_binop_type(*op, lhs, rhs, env),
        // Would need type db
        CExpr::Index(arr, _) => {
            if let Some(CType::Pointer(inner)) = infer_expr_type(arr, env) {
                Some(*inner)
            } else if let Some(CType::Array(inner, _)) = infer_expr_type(arr, env) {
                Some(*inner)
            } else {
                None
            }
        }
        // Would need function type db
        CExpr::Ternary(_, then, _) => infer_expr_type(then, env),
        _ => None,
    }
}

fn infer_unop_type(op: UnOp, inner: &CExpr, env: &TypeEnv) -> Option<CType> {
    match op {
        UnOp::Not => Some(CType::Int(32, true)),
        UnOp::AddrOf => {
            let inner_ty = infer_expr_type(inner, env)?;
            Some(CType::Pointer(Box::new(inner_ty)))
        }
        UnOp::Deref => {
            if let Some(CType::Pointer(inner_ty)) = infer_expr_type(inner, env) {
                Some(*inner_ty)
            } else {
                None
            }
        }
        _ => infer_expr_type(inner, env),
    }
}

fn infer_binop_type(op: BinOp, lhs: &CExpr, rhs: &CExpr, env: &TypeEnv) -> Option<CType> {
    match op {
        BinOp::Eq
        | BinOp::Ne
        | BinOp::Lt
        | BinOp::Le
        | BinOp::Gt
        | BinOp::Ge
        | BinOp::LogAnd
        | BinOp::LogOr => Some(CType::Int(32, true)),
        BinOp::Assign
        | BinOp::AddAssign
        | BinOp::SubAssign
        | BinOp::MulAssign
        | BinOp::DivAssign => infer_expr_type(lhs, env),
        _ => {
            let lt = infer_expr_type(lhs, env);
            let rt = infer_expr_type(rhs, env);
            // Usual arithmetic conversions (simplified)
            match (lt, rt) {
                (Some(l), Some(r)) => Some(arithmetic_promote(l, r)),
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                _ => None,
            }
        }
    }
}

fn arithmetic_promote(a: CType, b: CType) -> CType {
    // Simplified: float wins over int, larger int wins.
    match (&a, &b) {
        (CType::Float(wa), CType::Float(wb)) => CType::Float((*wa).max(*wb)),
        (CType::Float(_), _) => a,
        (_, CType::Float(_)) => b,
        (CType::Int(wa, _), CType::Int(wb, _)) => {
            let w = (*wa).max(*wb);
            CType::Int(w, false) // unsigned wins
        }
        _ => a,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CTypeInferencer
// ─────────────────────────────────────────────────────────────────────────────

/// Walks a C AST and infers / checks types.
pub struct CTypeInferencer {
    pub env: TypeEnv,
    pub errors: Vec<TypeError>,
    pub type_annotations: HashMap<usize, CType>,
    annotation_counter: usize,
}

impl CTypeInferencer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            env: TypeEnv::new(),
            errors: Vec::new(),
            type_annotations: HashMap::new(),
            annotation_counter: 0,
        }
    }

    /// Infer the type of an expression and optionally annotate it.
    #[must_use]
    pub fn infer_expr(&mut self, expr: &CExpr) -> Option<CType> {
        let ty = infer_expr_type(expr, &self.env);
        if let Some(ref t) = ty {
            let id = self.annotation_counter;
            self.annotation_counter += 1;
            self.type_annotations.insert(id, t.clone());
        }
        ty
    }

    /// Check a statement, updating the environment and collecting errors.
    pub fn check_stmt(&mut self, stmt: &CStmt) {
        match stmt {
            CStmt::Decl { ty, name, init } => {
                self.env.define(name, ty.clone());
                if let Some(init_expr) = init
                    && let Some(init_ty) = infer_expr_type(init_expr, &self.env)
                        && !types_compatible(ty, &init_ty) {
                            self.errors.push(TypeError {
                                description: format!(
                                    "type mismatch in declaration of `{name}`: expected {ty}, got {init_ty}"
                                ),
                                location: None,
                                severity: TypeErrSeverity::Warning,
                            });
                        }
            }
            CStmt::Return(Some(expr)) => {
                let _ = self.infer_expr(expr);
            }
            CStmt::If { cond, then, else_ } => {
                let _ = self.infer_expr(cond);
                self.env.push_scope();
                for s in then {
                    self.check_stmt(s);
                }
                self.env.pop_scope();
                if let Some(els) = else_ {
                    self.env.push_scope();
                    for s in els {
                        self.check_stmt(s);
                    }
                    self.env.pop_scope();
                }
            }
            CStmt::While { cond, body } | CStmt::DoWhile { cond, body } => {
                let _ = self.infer_expr(cond);
                self.env.push_scope();
                for s in body {
                    self.check_stmt(s);
                }
                self.env.pop_scope();
            }
            CStmt::For {
                cond, update, body, ..
            } => {
                if let Some(c) = cond {
                    let _ = self.infer_expr(c);
                }
                if let Some(u) = update {
                    let _ = self.infer_expr(u);
                }
                self.env.push_scope();
                for s in body {
                    self.check_stmt(s);
                }
                self.env.pop_scope();
            }
            CStmt::Expr(e) => {
                let _ = self.infer_expr(e);
            }
            _ => {}
        }
    }

    /// Check all statements in a function body.
    pub fn check_function(&mut self, params: &[(CType, String)], body: &[CStmt]) {
        self.env.push_scope();
        for (ty, name) in params {
            self.env.define(name, ty.clone());
        }
        for stmt in body {
            self.check_stmt(stmt);
        }
        self.env.pop_scope();
    }

    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.errors.len()
    }
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

impl Default for CTypeInferencer {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if two types are assignment-compatible (simplified).
#[must_use]
pub fn types_compatible(target: &CType, src: &CType) -> bool {
    if target == src {
        return true;
    }
    match (target, src) {
        // Any pointer ← NULL
        (CType::Pointer(_), CType::Pointer(inner)) if matches!(inner.as_ref(), CType::Void) => true,
        // Widening integer conversions
        (CType::Int(tw, _), CType::Int(sw, _)) => tw >= sw,
        // Int ← bool
        (CType::Int(..), CType::Bool) | (CType::Float(_), CType::Int(..)) => true,
        // Float ← int
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c_printer::{BinOp, CExpr, CStmt, CType, UnOp};

    fn empty_env() -> TypeEnv {
        TypeEnv::new()
    }

    fn env_with(vars: &[(&str, CType)]) -> TypeEnv {
        let mut e = TypeEnv::new();
        for &(name, ref ty) in vars {
            e.define(name, ty.clone());
        }
        e
    }

    // --- TypeEnv ---

    #[test]
    fn env_define_lookup() {
        let mut e = TypeEnv::new();
        e.define("x", CType::Int(32, true));
        assert_eq!(e.lookup("x"), Some(&CType::Int(32, true)));
    }

    #[test]
    fn env_shadow_in_scope() {
        let mut e = TypeEnv::new();
        e.define("x", CType::Int(32, true));
        e.push_scope();
        e.define("x", CType::Int(64, true));
        assert_eq!(e.lookup("x"), Some(&CType::Int(64, true)));
        e.pop_scope();
        assert_eq!(e.lookup("x"), Some(&CType::Int(32, true)));
    }

    #[test]
    fn env_missing_returns_none() {
        let e = TypeEnv::new();
        assert!(e.lookup("no_such").is_none());
    }

    #[test]
    fn env_scope_depth() {
        let mut e = TypeEnv::new();
        assert_eq!(e.scope_depth(), 1);
        e.push_scope();
        assert_eq!(e.scope_depth(), 2);
    }

    #[test]
    fn env_no_pop_below_root() {
        let mut e = TypeEnv::new();
        e.pop_scope(); // Should not panic
        assert_eq!(e.scope_depth(), 1);
    }

    // --- infer_expr_type ---

    #[test]
    fn infer_int_lit() {
        let e = empty_env();
        assert_eq!(
            infer_expr_type(&CExpr::IntLit(5), &e),
            Some(CType::Int(32, true))
        );
    }

    #[test]
    fn infer_uint_lit() {
        let e = empty_env();
        assert_eq!(
            infer_expr_type(&CExpr::UIntLit(5), &e),
            Some(CType::Int(32, false))
        );
    }

    #[test]
    fn infer_float_lit() {
        let e = empty_env();
        assert_eq!(
            infer_expr_type(&CExpr::FloatLit(1.0), &e),
            Some(CType::Float(64))
        );
    }

    #[test]
    fn infer_null_is_void_ptr() {
        let e = empty_env();
        let ty = infer_expr_type(&CExpr::Null, &e).unwrap();
        assert!(matches!(ty, CType::Pointer(_)));
    }

    #[test]
    fn infer_ident_from_env() {
        let e = env_with(&[("x", CType::Int(64, true))]);
        assert_eq!(
            infer_expr_type(&CExpr::Ident("x".into()), &e),
            Some(CType::Int(64, true))
        );
    }

    #[test]
    fn infer_ident_missing() {
        let e = empty_env();
        assert!(infer_expr_type(&CExpr::Ident("no".into()), &e).is_none());
    }

    #[test]
    fn infer_cast_gives_cast_type() {
        let e = empty_env();
        let expr = CExpr::Cast(Box::new(CType::Int(64, false)), Box::new(CExpr::IntLit(0)));
        assert_eq!(infer_expr_type(&expr, &e), Some(CType::Int(64, false)));
    }

    #[test]
    fn infer_sizeof_is_size_t() {
        let e = empty_env();
        let ty = infer_expr_type(&CExpr::SizeOf(Box::new(CType::Int(32, true))), &e).unwrap();
        assert_eq!(ty, CType::Int(64, false));
    }

    #[test]
    fn infer_addr_of_creates_pointer() {
        let e = env_with(&[("x", CType::Int(32, true))]);
        let expr = CExpr::UnOp(UnOp::AddrOf, Box::new(CExpr::Ident("x".into())));
        let ty = infer_expr_type(&expr, &e).unwrap();
        assert!(matches!(ty, CType::Pointer(_)));
    }

    #[test]
    fn infer_deref_pointer() {
        let e = env_with(&[("p", CType::Pointer(Box::new(CType::Int(32, true))))]);
        let expr = CExpr::UnOp(UnOp::Deref, Box::new(CExpr::Ident("p".into())));
        let ty = infer_expr_type(&expr, &e).unwrap();
        assert_eq!(ty, CType::Int(32, true));
    }

    #[test]
    fn infer_binop_eq_is_int() {
        let e = empty_env();
        let expr = CExpr::BinOp(
            BinOp::Eq,
            Box::new(CExpr::IntLit(1)),
            Box::new(CExpr::IntLit(1)),
        );
        let ty = infer_expr_type(&expr, &e).unwrap();
        assert!(matches!(ty, CType::Int(..)));
    }

    // --- types_compatible ---

    #[test]
    fn compatible_same_type() {
        assert!(types_compatible(
            &CType::Int(32, true),
            &CType::Int(32, true)
        ));
    }

    #[test]
    fn compatible_widening_int() {
        assert!(types_compatible(
            &CType::Int(64, true),
            &CType::Int(32, true)
        ));
    }

    #[test]
    fn compatible_narrowing_int_false() {
        assert!(!types_compatible(
            &CType::Int(32, true),
            &CType::Int(64, true)
        ));
    }

    #[test]
    fn compatible_float_from_int() {
        assert!(types_compatible(&CType::Float(32), &CType::Int(32, true)));
    }

    #[test]
    fn compatible_ptr_from_void_ptr() {
        let void_ptr = CType::Pointer(Box::new(CType::Void));
        let int_ptr = CType::Pointer(Box::new(CType::Int(32, true)));
        // void* → int* is compatible
        assert!(types_compatible(&int_ptr, &void_ptr));
    }

    // --- CTypeInferencer ---

    #[test]
    fn inferencer_decl_no_error() {
        let mut ti = CTypeInferencer::new();
        ti.check_stmt(&CStmt::Decl {
            ty: CType::Int(32, true),
            name: "x".into(),
            init: Some(CExpr::IntLit(5)),
        });
        assert!(!ti.has_errors());
    }

    #[test]
    fn inferencer_decl_type_mismatch_warning() {
        let mut ti = CTypeInferencer::new();
        // Assigning float literal to int var — mismatch
        ti.check_stmt(&CStmt::Decl {
            ty: CType::Int(32, true),
            name: "x".into(),
            init: Some(CExpr::FloatLit(1.0)),
        });
        assert!(ti.has_errors());
    }

    #[test]
    fn inferencer_var_available_after_decl() {
        let mut ti = CTypeInferencer::new();
        ti.check_stmt(&CStmt::Decl {
            ty: CType::Int(32, true),
            name: "i".into(),
            init: None,
        });
        assert_eq!(ti.env.lookup("i"), Some(&CType::Int(32, true)));
    }

    #[test]
    fn inferencer_check_function() {
        let mut ti = CTypeInferencer::new();
        ti.check_function(
            &[(CType::Int(32, true), "n".into())],
            &[CStmt::Return(Some(CExpr::Ident("n".into())))],
        );
        assert!(!ti.has_errors());
    }

    #[test]
    fn inferencer_scope_enters_if() {
        let mut ti = CTypeInferencer::new();
        ti.check_stmt(&CStmt::If {
            cond: CExpr::IntLit(1),
            then: vec![CStmt::Decl {
                ty: CType::Int(32, true),
                name: "inner".into(),
                init: None,
            }],
            else_: None,
        });
        // After if block, scope should be popped
        assert!(ti.env.lookup("inner").is_none());
    }
}
