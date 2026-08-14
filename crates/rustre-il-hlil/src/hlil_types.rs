//! `hlil_types.rs` — HLIL type-system infrastructure.
//!
//! This module provides a richer type-system layer on top of the primitive
//! [`HlilType`] enum defined in `lib.rs`.  The key types are:
//!
//! * [`HlilVarType`] — a rich, display-able wrapper around `HlilType` that
//!   carries optional source-level names.
//! * [`HlilFunctionType`] — the full signature of an HLIL function with
//!   named parameters.
//! * [`HlilPointerType`] — pointer metadata (pointee, width, const-ness,
//!   volatile-ness, array stride).
//! * [`HlilArrayType`] — array metadata (element type, known count,
//!   stride, raw-buffer flag).
//! * [`TypeAnnotator`] — annotates every expression in an
//!   [`HlilFunction`] with a concrete `HlilType`.
//! * [`TypeConsistencyChecker`] — validates that assignments and returns
//!   are type-consistent; collects typed errors.
//! * [`HlilTypeSystem`] — top-level registry that ties everything together;
//!   provides `intern`, `resolve`, `unify`, and `query` operations.

use std::collections::HashMap;
use std::fmt;

use crate::{HlilExpr, HlilFunction, HlilStatement, HlilType};

pub use crate::HlilVar;

// ─── HlilVarType ─────────────────────────────────────────────────────────────

/// A variable-type pair with an optional human-readable source-level name.
///
/// Used whenever we want to label a type for display in a UI or report (e.g.
/// `argc: int32_t`) without conflating that label with the underlying IR type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HlilVarType {
    pub ty: HlilType,
    /// Optional C-style identifier (field name, parameter name, …).
    pub name: Option<String>,
    /// Whether this slot is `const`-qualified.
    pub is_const: bool,
    /// Whether this slot is `volatile`-qualified.
    pub is_volatile: bool,
}

impl HlilVarType {
    /// Construct with just a type, no name.
    #[must_use]
    pub fn new(ty: HlilType) -> Self {
        Self {
            ty,
            name: None,
            is_const: false,
            is_volatile: false,
        }
    }

    /// Construct with a name.
    #[must_use]
    pub fn named(name: impl Into<String>, ty: HlilType) -> Self {
        Self {
            ty,
            name: Some(name.into()),
            is_const: false,
            is_volatile: false,
        }
    }

    /// Mark as const.
    #[must_use]
    pub fn with_const(mut self) -> Self {
        self.is_const = true;
        self
    }

    /// Mark as volatile.
    #[must_use]
    pub fn with_volatile(mut self) -> Self {
        self.is_volatile = true;
        self
    }

    /// Returns `true` if the underlying type is a pointer.
    #[must_use]
    pub fn is_pointer(&self) -> bool {
        self.ty.is_pointer()
    }

    /// Returns `true` if the underlying type is an integer.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.ty.is_integer()
    }

    /// Byte width, if statically known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u32> {
        self.ty.byte_size()
    }
}

impl fmt::Display for HlilVarType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_const {
            write!(f, "const ")?;
        }
        if self.is_volatile {
            write!(f, "volatile ")?;
        }
        write!(f, "{}", self.ty)?;
        if let Some(n) = &self.name {
            write!(f, " {n}")?;
        }
        Ok(())
    }
}

// ─── HlilPointerType ─────────────────────────────────────────────────────────

/// Pointer type metadata beyond what `HlilType::Pointer` stores.
///
/// Adds const/volatile qualifiers on the pointee, an optional array stride
/// (for pointer-as-array), and a flag marking "fat pointers" (slice-style).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlilPointerType {
    /// The type the pointer points at.
    pub pointee: HlilVarType,
    /// Width of the pointer itself in bits (32 or 64 typically).
    pub ptr_bits: u32,
    /// If `Some(n)`, treat this as `pointee[n]` — a fixed-size array pointer.
    pub array_count: Option<u64>,
    /// Stride in bytes between successive elements (default: `pointee.byte_size()`).
    pub stride: Option<u32>,
    /// True when this is a "fat pointer" carrying a length alongside the address.
    pub is_fat: bool,
}

impl HlilPointerType {
    /// Create a simple single-element pointer.
    #[must_use]
    pub fn simple(pointee: HlilType, ptr_bits: u32) -> Self {
        Self {
            pointee: HlilVarType::new(pointee),
            ptr_bits,
            array_count: None,
            stride: None,
            is_fat: false,
        }
    }

    /// Create a fixed-size array pointer.
    #[must_use]
    pub fn array_ptr(pointee: HlilType, ptr_bits: u32, count: u64) -> Self {
        Self {
            pointee: HlilVarType::new(pointee),
            ptr_bits,
            array_count: Some(count),
            stride: None,
            is_fat: false,
        }
    }

    /// Convert to an [`HlilType::Pointer`].
    #[must_use]
    pub fn to_hlil_type(&self) -> HlilType {
        HlilType::Pointer {
            pointee: Box::new(self.pointee.ty.clone()),
            bits: self.ptr_bits,
        }
    }

    /// Total size of the pointed-to region, if known.
    #[must_use]
    pub fn region_size(&self) -> Option<u64> {
        let elem_size = u64::from(self.pointee.byte_size()?);
        let stride = self.stride.map_or(elem_size, |s| u64::from(s));
        let count = u64::from(self.array_count.unwrap_or(1));
        Some(stride * count)
    }
}

impl fmt::Display for HlilPointerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} *", self.pointee.ty)?;
        if let Some(n) = self.array_count {
            write!(f, "[{n}]")?;
        }
        Ok(())
    }
}

// ─── HlilArrayType ───────────────────────────────────────────────────────────

/// Detailed array type metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlilArrayType {
    /// Element type.
    pub element: HlilVarType,
    /// Number of elements, if statically known.
    pub count: Option<u64>,
    /// Byte stride between elements (defaults to `element.byte_size()`).
    pub stride: Option<u32>,
    /// True when this array represents a raw byte buffer (e.g. `uint8_t[]`).
    pub is_raw_buffer: bool,
}

impl HlilArrayType {
    #[must_use]
    pub fn new(element: HlilType, count: Option<u64>) -> Self {
        Self {
            element: HlilVarType::new(element),
            count,
            stride: None,
            is_raw_buffer: false,
        }
    }

    /// Total byte size, if both element size and count are known.
    #[must_use]
    pub fn total_size(&self) -> Option<u64> {
        let elem = u64::from(self.element.byte_size()?);
        let stride = self.stride.map_or(elem, |s| u64::from(s));
        let count = self.count?;
        Some(stride * count)
    }

    /// Convert to an [`HlilType::Array`].
    #[must_use]
    pub fn to_hlil_type(&self) -> HlilType {
        HlilType::Array {
            elem: Box::new(self.element.ty.clone()),
            count: self.count,
        }
    }
}

impl fmt::Display for HlilArrayType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.count {
            Some(n) => write!(f, "{}[{n}]", self.element.ty),
            None => write!(f, "{}[]", self.element.ty),
        }
    }
}

// ─── HlilFunctionType ────────────────────────────────────────────────────────

/// A fully-typed function signature, including named parameters, calling
/// convention, and variadic flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlilFunctionType {
    pub name: Option<String>,
    pub return_type: HlilVarType,
    pub params: Vec<HlilVarType>,
    pub is_variadic: bool,
    pub calling_convention: Option<String>,
    /// True when the function is declared `[[noreturn]]` / `__attribute__((noreturn))`.
    pub no_return: bool,
}

impl HlilFunctionType {
    /// Construct a minimal void-return function with no parameters.
    #[must_use]
    pub fn void_fn(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            return_type: HlilVarType::new(HlilType::Void),
            params: Vec::new(),
            is_variadic: false,
            calling_convention: None,
            no_return: false,
        }
    }

    /// Add a named parameter and return `self` (builder style).
    #[must_use]
    pub fn with_param(mut self, name: impl Into<String>, ty: HlilType) -> Self {
        self.params.push(HlilVarType::named(name, ty));
        self
    }

    /// Set the return type and return `self`.
    #[must_use]
    pub fn returning(mut self, ty: HlilType) -> Self {
        self.return_type = HlilVarType::new(ty);
        self
    }

    /// Mark as variadic and return `self`.
    #[must_use]
    pub fn variadic(mut self) -> Self {
        self.is_variadic = true;
        self
    }

    /// Mark as no-return and return `self`.
    #[must_use]
    pub fn no_return(mut self) -> Self {
        self.no_return = true;
        self
    }

    /// Returns `true` when the parameter count (excluding variadic slot) equals `n`.
    #[must_use]
    pub fn arity(&self) -> usize {
        self.params.len()
    }

    /// Check if a call with `arg_count` arguments is compatible.
    #[must_use]
    pub fn call_compat(&self, arg_count: usize) -> bool {
        if self.is_variadic {
            arg_count >= self.params.len()
        } else {
            arg_count == self.params.len()
        }
    }

    /// Convert to an [`HlilType::Function`].
    #[must_use]
    pub fn to_hlil_type(&self) -> HlilType {
        HlilType::Function {
            ret: Box::new(self.return_type.ty.clone()),
            params: self.params.iter().map(|p| p.ty.clone()).collect(),
        }
    }
}

impl fmt::Display for HlilFunctionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("(anonymous)");
        let params: Vec<String> = self.params.iter().map(std::string::ToString::to_string).collect();
        let variadic_suffix = if self.is_variadic {
            if params.is_empty() {
                "...".to_string()
            } else {
                ", ...".to_string()
            }
        } else {
            String::new()
        };
        write!(
            f,
            "{} {}({}{})",
            self.return_type.ty,
            name,
            params.join(", "),
            variadic_suffix
        )
    }
}

// ─── TypeAnnotator ───────────────────────────────────────────────────────────

/// Annotates every sub-expression in an [`HlilFunction`] with a concrete
/// [`HlilType`], using a simple forward-inference algorithm.
///
/// The result is a flat map `(expression_node_id → HlilType)`.  Because HLIL
/// expression trees are not globally identified, the annotator represents
/// nodes by their pre-order traversal index within the function body.
#[derive(Debug, Default)]
pub struct TypeAnnotator {
    /// Maps pre-order node index → inferred type.
    pub annotations: HashMap<usize, HlilType>,
    /// Counter used during traversal.
    counter: usize,
}

impl TypeAnnotator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Annotate Selfns in `func` and return the populated map.
    pub fn annotate(&mut self, func: &HlilFunction) {
        self.counter = 0;
        for stmt in &func.body {
            self.annotate_stmt(stmt);
        }
    }

    fn annotate_expr(&mut self, expr: &HlilExpr) {
        let idx = self.counter;
        self.counter += 1;
        let ty = expr.expr_type().clone();
        self.annotations.insert(idx, ty);

        // Recurse into sub-expressions.
        match expr {
            HlilExpr::Deref { addr, .. } => self.annotate_expr(addr),
            HlilExpr::FieldAccess { base, .. } => self.annotate_expr(base),
            HlilExpr::Index { base, idx: i, .. } => {
                self.annotate_expr(base);
                self.annotate_expr(i);
            }
            HlilExpr::Add(a, b, _)
            | HlilExpr::Sub(a, b, _)
            | HlilExpr::Mul(a, b, _)
            | HlilExpr::Div(a, b, _)
            | HlilExpr::Mod(a, b, _)
            | HlilExpr::And(a, b, _)
            | HlilExpr::Or(a, b, _)
            | HlilExpr::Xor(a, b, _)
            | HlilExpr::Shl(a, b, _)
            | HlilExpr::Shr(a, b, _)
            | HlilExpr::CmpEq(a, b)
            | HlilExpr::CmpNe(a, b)
            | HlilExpr::CmpLt(a, b)
            | HlilExpr::CmpGt(a, b)
            | HlilExpr::CmpLe(a, b)
            | HlilExpr::CmpGe(a, b)
            | HlilExpr::LogicalAnd(a, b)
            | HlilExpr::LogicalOr(a, b) => {
                self.annotate_expr(a);
                self.annotate_expr(b);
            }
            HlilExpr::Neg(e, _)
            | HlilExpr::Not(e, _)
            | HlilExpr::LogicalNot(e)
            | HlilExpr::Cast { expr: e, .. } => self.annotate_expr(e),
            HlilExpr::Call {
                func: fn_expr,
                args,
                ..
            } => {
                self.annotate_expr(fn_expr);
                for a in args {
                    self.annotate_expr(a);
                }
            }
            HlilExpr::Ternary {
                cond, then, else_, ..
            } => {
                self.annotate_expr(cond);
                self.annotate_expr(then);
                self.annotate_expr(else_);
            }
            // Leaf nodes — already recorded above.
            _ => {}
        }
    }

    fn annotate_stmt(&mut self, stmt: &HlilStatement) {
        match stmt {
            HlilStatement::Expression(e) | HlilStatement::VarDeclare { init: Some(e), .. } => {
                self.annotate_expr(e);
            }
            HlilStatement::Assign { dest, src } => {
                self.annotate_expr(dest);
                self.annotate_expr(src);
            }
            HlilStatement::AssignUnpack { src, .. } => self.annotate_expr(src),
            HlilStatement::VarDeclare { init: None, .. }
            | HlilStatement::VarDecl { init: None, .. }
            | HlilStatement::Break
            | HlilStatement::Continue
            | HlilStatement::Goto(..)
            | HlilStatement::Label(..)
            | HlilStatement::Nop => {}
            HlilStatement::Return(vals) => {
                for v in vals {
                    self.annotate_expr(v);
                }
            }
            HlilStatement::If {
                cond,
                then_body,
                else_body,
            } => {
                self.annotate_expr(cond);
                for s in then_body {
                    self.annotate_stmt(s);
                }
                for s in else_body {
                    self.annotate_stmt(s);
                }
            }
            HlilStatement::While { cond, body } => {
                self.annotate_expr(cond);
                for s in body {
                    self.annotate_stmt(s);
                }
            }
            HlilStatement::DoWhile { body, cond } => {
                for s in body {
                    self.annotate_stmt(s);
                }
                self.annotate_expr(cond);
            }
            HlilStatement::For {
                init,
                cond,
                step,
                body,
            } => {
                if let Some(i) = init {
                    self.annotate_stmt(i);
                }
                if let Some(c) = cond {
                    self.annotate_expr(c);
                }
                if let Some(s) = step {
                    self.annotate_expr(s);
                }
                for s in body {
                    self.annotate_stmt(s);
                }
            }
            HlilStatement::Switch {
                value,
                cases,
                default,
            } => {
                self.annotate_expr(value);
                for c in cases {
                    for s in &c.body {
                        self.annotate_stmt(s);
                    }
                }
                for s in default {
                    self.annotate_stmt(s);
                }
            }
            HlilStatement::VarDecl { init: Some(e), .. }
            | HlilStatement::Expr(e) => self.annotate_expr(e),
            _ => {}
        }
    }

    /// Retrieve the annotation at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&HlilType> {
        self.annotations.get(&index)
    }

    /// Total number of annotations recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.annotations.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }
}

// ─── TypeConsistencyError ────────────────────────────────────────────────────

/// A single type-consistency violation found by [`TypeConsistencyChecker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeConsistencyError {
    pub kind: ConsistencyErrorKind,
    pub description: String,
}

impl fmt::Display for TypeConsistencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}", self.kind, self.description)
    }
}

/// The category of a consistency error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyErrorKind {
    /// Assignment target and source types differ.
    AssignTypeMismatch,
    /// Return value type does not match the declared return type.
    ReturnTypeMismatch,
    /// Operands of a binary operation have incompatible types.
    OperandTypeMismatch,
    /// A call passes too many or too few arguments.
    ArityMismatch,
    /// Attempt to dereference a non-pointer.
    DerefNonPointer,
    /// Condition of an `if`/`while` is not boolean or integer.
    NonBoolCondition,
}

// ─── TypeConsistencyChecker ──────────────────────────────────────────────────

/// Walks an [`HlilFunction`] and collects type-consistency errors.
#[derive(Debug, Default)]
pub struct TypeConsistencyChecker {
    pub errors: Vec<TypeConsistencyError>,
    /// Expected return type (set from the function prototype before checking).
    pub expected_return: Option<HlilType>,
}

impl TypeConsistencyChecker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the checker over `func`.  Returns the number of errors found.
    pub fn check(&mut self, func: &HlilFunction) -> usize {
        self.errors.clear();
        self.expected_return = Some(func.prototype.return_type.clone());
        for stmt in &func.body {
            self.check_stmt(stmt);
        }
        self.errors.len()
    }

    fn push(&mut self, kind: ConsistencyErrorKind, desc: impl Into<String>) {
        self.errors.push(TypeConsistencyError {
            kind,
            description: desc.into(),
        });
    }

    fn check_expr(&mut self, expr: &HlilExpr) {
        match expr {
            HlilExpr::Deref { addr, .. } => {
                if !addr.expr_type().is_pointer() {
                    self.push(
                        ConsistencyErrorKind::DerefNonPointer,
                        format!("dereferencing non-pointer type {}", addr.expr_type()),
                    );
                }
                self.check_expr(addr);
            }
            HlilExpr::Add(a, b, _)
            | HlilExpr::Sub(a, b, _)
            | HlilExpr::Mul(a, b, _)
            | HlilExpr::Div(a, b, _)
            | HlilExpr::Mod(a, b, _) => {
                // Allow integer ↔ pointer arithmetic for pointer math.
                let at = a.expr_type();
                let bt = b.expr_type();
                if at != bt && !at.is_pointer() && !bt.is_pointer() {
                    self.push(
                        ConsistencyErrorKind::OperandTypeMismatch,
                        format!("arithmetic type mismatch: {at} vs {bt}"),
                    );
                }
                self.check_expr(a);
                self.check_expr(b);
            }
            HlilExpr::If { .. } => {}
            _ => self.check_expr_children(expr),
        }
    }

    fn check_expr_children(&mut self, expr: &HlilExpr) {
        match expr {
            HlilExpr::FieldAccess { base, .. } => self.check_expr(base),
            HlilExpr::Index { base, idx, .. } => {
                self.check_expr(base);
                self.check_expr(idx);
            }
            HlilExpr::Neg(e, _)
            | HlilExpr::Not(e, _)
            | HlilExpr::LogicalNot(e)
            | HlilExpr::Cast { expr: e, .. } => self.check_expr(e),
            HlilExpr::Call { func, args, .. } => {
                self.check_expr(func);
                for a in args {
                    self.check_expr(a);
                }
            }
            HlilExpr::Ternary {
                cond, then, else_, ..
            } => {
                self.check_expr(cond);
                self.check_expr(then);
                self.check_expr(else_);
            }
            _ => {}
        }
    }

    fn check_stmt(&mut self, stmt: &HlilStatement) {
        match stmt {
            HlilStatement::Assign { dest, src } => {
                let dt = dest.expr_type();
                let st = src.expr_type();
                if dt != st && *dt != HlilType::Unknown && *st != HlilType::Unknown {
                    self.push(
                        ConsistencyErrorKind::AssignTypeMismatch,
                        format!("assign: lhs={dt}, rhs={st}"),
                    );
                }
                self.check_expr(dest);
                self.check_expr(src);
            }
            HlilStatement::Return(vals) => {
                if let Some(expected) = &self.expected_return.clone() {
                    if *expected == HlilType::Void && !vals.is_empty() {
                        self.push(
                            ConsistencyErrorKind::ReturnTypeMismatch,
                            "void function returns a value".to_string(),
                        );
                    } else if let Some(first) = vals.first() {
                        let actual = first.expr_type();
                        if *expected != HlilType::Unknown
                            && *actual != HlilType::Unknown
                            && expected != actual
                        {
                            self.push(
                                ConsistencyErrorKind::ReturnTypeMismatch,
                                format!("expected {expected}, got {actual}"),
                            );
                        }
                    }
                }
                for v in vals {
                    self.check_expr(v);
                }
            }
            HlilStatement::If {
                cond,
                then_body,
                else_body,
            } => {
                let ct = cond.expr_type();
                if !matches!(
                    ct,
                    HlilType::Bool | HlilType::Int { .. } | HlilType::Unknown
                ) {
                    self.push(
                        ConsistencyErrorKind::NonBoolCondition,
                        format!("if condition has type {ct}"),
                    );
                }
                self.check_expr(cond);
                for s in then_body {
                    self.check_stmt(s);
                }
                for s in else_body {
                    self.check_stmt(s);
                }
            }
            HlilStatement::While { cond, body } | HlilStatement::DoWhile { body, cond } => {
                self.check_expr(cond);
                for s in body {
                    self.check_stmt(s);
                }
            }
            HlilStatement::For {
                init,
                cond,
                step,
                body,
            } => {
                if let Some(i) = init {
                    self.check_stmt(i);
                }
                if let Some(c) = cond {
                    self.check_expr(c);
                }
                if let Some(s) = step {
                    self.check_expr(s);
                }
                for s in body {
                    self.check_stmt(s);
                }
            }
            HlilStatement::Switch {
                value,
                cases,
                default,
            } => {
                self.check_expr(value);
                for c in cases {
                    for s in &c.body {
                        self.check_stmt(s);
                    }
                }
                for s in default {
                    self.check_stmt(s);
                }
            }
            HlilStatement::Expression(e) | HlilStatement::VarDeclare { init: Some(e), .. } => {
                self.check_expr(e);
            }
            HlilStatement::Block(stmts) => {
                for s in stmts {
                    self.check_stmt(s);
                }
            }
            _ => {}
        }
    }

    /// `true` when no errors were found in the last `check` call.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.errors.is_empty()
    }
}

// ─── HlilTypeSystem ──────────────────────────────────────────────────────────

/// Top-level type registry for an HLIL module.
///
/// * **intern** – deduplicate and store named types.
/// * **resolve** – look up a named type.
/// * **unify** – compute the "least common supertype" of two types.
/// * **query** – infer the type of an expression in the context of the registry.
#[derive(Debug, Default)]
pub struct HlilTypeSystem {
    /// Named type definitions (struct, enum, typedef).
    pub named_types: HashMap<String, HlilType>,
    /// Function type registry.
    pub function_types: HashMap<String, HlilFunctionType>,
    /// Pointer metadata.
    pub pointer_metadata: HashMap<String, HlilPointerType>,
    /// Array metadata.
    pub array_metadata: HashMap<String, HlilArrayType>,
}

impl HlilTypeSystem {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a named type.  Returns `true` if it was newly inserted.
    pub fn intern(&mut self, name: impl Into<String>, ty: HlilType) -> bool {
        let key = name.into();
        if self.named_types.contains_key(&key) {
            return false;
        }
        self.named_types.insert(key, ty);
        true
    }

    /// Look up a named type.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&HlilType> {
        self.named_types.get(name)
    }

    /// Intern a function type.
    pub fn intern_fn(&mut self, ty: HlilFunctionType) -> bool {
        if let Some(name) = &ty.name {
            let key = name.clone();
            if self.function_types.contains_key(&key) {
                return false;
            }
            self.function_types.insert(key, ty);
            true
        } else {
            false
        }
    }

    /// Compute the "least common supertype" of `a` and `b`.
    ///
    /// Rules:
    /// * If `a == b`, returns `a`.
    /// * `Unknown` unifies with anything → returns the other type.
    /// * Two integers of the same width but different signedness → unsigned.
    /// * Two integers of different width → the wider one.
    /// * Pointer + integer → pointer (pointer arithmetic).
    /// * All other combinations → `Unknown`.
    #[must_use]
    pub fn unify(&self, a: &HlilType, b: &HlilType) -> HlilType {
        if a == b {
            return a.clone();
        }
        match (a, b) {
            (HlilType::Unknown, other) | (other, HlilType::Unknown) => other.clone(),
            (HlilType::Int { bits: ba, .. }, HlilType::Int { bits: bb, .. }) => HlilType::Int {
                signed: false,
                bits: (*ba).max(*bb),
            },
            (HlilType::Pointer { .. }, HlilType::Int { .. })
            | (HlilType::Int { .. }, HlilType::Pointer { .. }) => a.clone(),
            _ => HlilType::Unknown,
        }
    }

    /// Infer the type of an expression using the registry.
    #[must_use]
    pub fn query_expr(&self, expr: &HlilExpr) -> HlilType {
        match expr.expr_type() {
            HlilType::Struct { name } | HlilType::Enum { name } => {
                self.resolve(name).cloned().unwrap_or(HlilType::Unknown)
            }
            ty => ty.clone(),
        }
    }

    /// Number of named types interned.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.named_types.len()
    }

    /// Returns all interned type names.
    #[must_use]
    pub fn type_names(&self) -> Vec<&str> {
        self.named_types.keys().map(std::string::String::as_str).collect()
    }

    /// Remove a type by name and return it.
    pub fn remove(&mut self, name: &str) -> Option<HlilType> {
        self.named_types.remove(name)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HlilType, HlilVar};
    use rustre_core::address::Address;

    fn make_func() -> HlilFunction {
        HlilFunction::new(Address::new(0x1000), "test_fn")
    }

    // HlilVarType tests ─────────────────────────────────────────────────────

    #[test]
    fn vartype_new_no_name() {
        let vt = HlilVarType::new(HlilType::i32());
        assert_eq!(vt.ty, HlilType::i32());
        assert!(vt.name.is_none());
        assert!(!vt.is_const);
        assert!(!vt.is_volatile);
    }

    #[test]
    fn vartype_named() {
        let vt = HlilVarType::named("argc", HlilType::i32());
        assert_eq!(vt.name.as_deref(), Some("argc"));
        assert_eq!(vt.ty, HlilType::i32());
    }

    #[test]
    fn vartype_with_const() {
        let vt = HlilVarType::new(HlilType::u8()).with_const();
        assert!(vt.is_const);
    }

    #[test]
    fn vartype_with_volatile() {
        let vt = HlilVarType::new(HlilType::u8()).with_volatile();
        assert!(vt.is_volatile);
    }

    #[test]
    fn vartype_is_pointer() {
        let vt = HlilVarType::new(HlilType::ptr(HlilType::u8(), 64));
        assert!(vt.is_pointer());
    }

    #[test]
    fn vartype_is_integer() {
        let vt = HlilVarType::new(HlilType::i64());
        assert!(vt.is_integer());
    }

    #[test]
    fn vartype_byte_size_known() {
        let vt = HlilVarType::new(HlilType::u32());
        assert_eq!(vt.byte_size(), Some(4));
    }

    #[test]
    fn vartype_byte_size_unknown() {
        let vt = HlilVarType::new(HlilType::Unknown);
        assert!(vt.byte_size().is_none());
    }

    #[test]
    fn vartype_display_const_volatile() {
        let vt = HlilVarType::named("x", HlilType::i32())
            .with_const()
            .with_volatile();
        let s = vt.to_string();
        assert!(s.contains("const"));
        assert!(s.contains("volatile"));
        assert!(s.contains('x'));
    }

    // HlilPointerType tests ─────────────────────────────────────────────────

    #[test]
    fn ptr_type_simple() {
        let p = HlilPointerType::simple(HlilType::u8(), 64);
        assert_eq!(p.ptr_bits, 64);
        assert!(p.array_count.is_none());
        assert!(!p.is_fat);
    }

    #[test]
    fn ptr_type_array() {
        let p = HlilPointerType::array_ptr(HlilType::u32(), 64, 16);
        assert_eq!(p.array_count, Some(16));
    }

    #[test]
    fn ptr_type_region_size() {
        let p = HlilPointerType::array_ptr(HlilType::u32(), 64, 4);
        assert_eq!(p.region_size(), Some(16));
    }

    #[test]
    fn ptr_type_to_hlil_type() {
        let p = HlilPointerType::simple(HlilType::i32(), 32);
        let ty = p.to_hlil_type();
        assert!(matches!(ty, HlilType::Pointer { bits: 32, .. }));
    }

    #[test]
    fn ptr_type_display() {
        let p = HlilPointerType::simple(HlilType::u8(), 64);
        assert!(p.to_string().contains('*'));
    }

    // HlilArrayType tests ───────────────────────────────────────────────────

    #[test]
    fn array_type_total_size_known() {
        let a = HlilArrayType::new(HlilType::u32(), Some(8));
        assert_eq!(a.total_size(), Some(32));
    }

    #[test]
    fn array_type_total_size_unknown_count() {
        let a = HlilArrayType::new(HlilType::u32(), None);
        assert!(a.total_size().is_none());
    }

    #[test]
    fn array_type_to_hlil_type() {
        let a = HlilArrayType::new(HlilType::u8(), Some(10));
        let ty = a.to_hlil_type();
        assert!(matches!(
            ty,
            HlilType::Array {
                count: Some(10),
                ..
            }
        ));
    }

    #[test]
    fn array_type_display_fixed() {
        let a = HlilArrayType::new(HlilType::u8(), Some(10));
        assert!(a.to_string().contains("[10]"));
    }

    #[test]
    fn array_type_display_flexible() {
        let a = HlilArrayType::new(HlilType::u8(), None);
        assert!(a.to_string().contains("[]"));
    }

    // HlilFunctionType tests ─────────────────────────────────────────────────

    #[test]
    fn fn_type_void_fn() {
        let ft = HlilFunctionType::void_fn("main");
        assert_eq!(ft.arity(), 0);
        assert_eq!(ft.return_type.ty, HlilType::Void);
    }

    #[test]
    fn fn_type_with_params() {
        let ft = HlilFunctionType::void_fn("foo")
            .with_param("argc", HlilType::i32())
            .with_param("argv", HlilType::ptr(HlilType::ptr(HlilType::u8(), 64), 64));
        assert_eq!(ft.arity(), 2);
    }

    #[test]
    fn fn_type_call_compat_exact() {
        let ft = HlilFunctionType::void_fn("f").with_param("x", HlilType::i32());
        assert!(ft.call_compat(1));
        assert!(!ft.call_compat(0));
        assert!(!ft.call_compat(2));
    }

    #[test]
    fn fn_type_call_compat_variadic() {
        let ft = HlilFunctionType::void_fn("printf")
            .with_param("fmt", HlilType::ptr(HlilType::u8(), 64))
            .variadic();
        assert!(ft.call_compat(1));
        assert!(ft.call_compat(5));
        assert!(!ft.call_compat(0));
    }

    #[test]
    fn fn_type_no_return() {
        let ft = HlilFunctionType::void_fn("exit").no_return();
        assert!(ft.no_return);
    }

    #[test]
    fn fn_type_to_hlil_type() {
        let ft = HlilFunctionType::void_fn("f")
            .with_param("x", HlilType::i32())
            .returning(HlilType::i32());
        let ty = ft.to_hlil_type();
        assert!(matches!(ty, HlilType::Function { .. }));
    }

    #[test]
    fn fn_type_display() {
        let ft = HlilFunctionType::void_fn("greet")
            .with_param("n", HlilType::i32())
            .returning(HlilType::i32());
        let s = ft.to_string();
        assert!(s.contains("greet"));
        assert!(s.contains('n'));
    }

    // TypeAnnotator tests ───────────────────────────────────────────────────

    #[test]
    fn annotator_empty_func() {
        let func = make_func();
        let mut ann = TypeAnnotator::new();
        ann.annotate(&func);
        assert!(ann.is_empty());
    }

    #[test]
    fn annotator_counts_exprs() {
        let mut func = make_func();
        func.body.push(HlilStatement::Expression(HlilExpr::Const {
            value: 42,
            ty: HlilType::i32(),
        }));
        let mut ann = TypeAnnotator::new();
        ann.annotate(&func);
        assert!(!ann.is_empty());
    }

    #[test]
    fn annotator_nested_expr() {
        let mut func = make_func();
        let expr = HlilExpr::Add(
            Box::new(HlilExpr::Const {
                value: 1,
                ty: HlilType::i32(),
            }),
            Box::new(HlilExpr::Const {
                value: 2,
                ty: HlilType::i32(),
            }),
            HlilType::i32(),
        );
        func.body.push(HlilStatement::Expression(expr));
        let mut ann = TypeAnnotator::new();
        ann.annotate(&func);
        // Add + 2 consts = 3 nodes.
        assert_eq!(ann.len(), 3);
    }

    #[test]
    fn annotator_assign_stmt() {
        let mut func = make_func();
        let dest = HlilExpr::Var {
            var: HlilVar::new("x", HlilType::i32()),
        };
        let src = HlilExpr::Const {
            value: 0,
            ty: HlilType::i32(),
        };
        func.body.push(HlilStatement::Assign { dest, src });
        let mut ann = TypeAnnotator::new();
        ann.annotate(&func);
        assert_eq!(ann.len(), 2);
    }

    // TypeConsistencyChecker tests ──────────────────────────────────────────

    #[test]
    fn checker_empty_func_is_consistent() {
        let func = make_func();
        let mut checker = TypeConsistencyChecker::new();
        let errors = checker.check(&func);
        assert_eq!(errors, 0);
        assert!(checker.is_consistent());
    }

    #[test]
    fn checker_detects_assign_mismatch() {
        let mut func = make_func();
        let dest = HlilExpr::Var {
            var: HlilVar::new("x", HlilType::i32()),
        };
        let src = HlilExpr::Const {
            value: 0,
            ty: HlilType::u64(),
        };
        func.body.push(HlilStatement::Assign { dest, src });
        let mut checker = TypeConsistencyChecker::new();
        let errors = checker.check(&func);
        assert!(errors > 0);
    }

    #[test]
    fn checker_consistent_assignment() {
        let mut func = make_func();
        let dest = HlilExpr::Var {
            var: HlilVar::new("x", HlilType::i32()),
        };
        let src = HlilExpr::Const {
            value: 0,
            ty: HlilType::i32(),
        };
        func.body.push(HlilStatement::Assign { dest, src });
        let mut checker = TypeConsistencyChecker::new();
        let errors = checker.check(&func);
        assert_eq!(errors, 0);
    }

    #[test]
    fn checker_deref_non_pointer() {
        let mut func = make_func();
        let non_ptr = HlilExpr::Const {
            value: 0xdeadbeef,
            ty: HlilType::u32(),
        };
        let deref = HlilExpr::Deref {
            addr: Box::new(non_ptr),
            ty: HlilType::u8(),
        };
        func.body.push(HlilStatement::Expression(deref));
        let mut checker = TypeConsistencyChecker::new();
        checker.check(&func);
        let has_deref_err = checker
            .errors
            .iter()
            .any(|e| e.kind == ConsistencyErrorKind::DerefNonPointer);
        assert!(has_deref_err);
    }

    // HlilTypeSystem tests ──────────────────────────────────────────────────

    #[test]
    fn type_system_intern_and_resolve() {
        let mut ts = HlilTypeSystem::new();
        ts.intern(
            "MyStruct",
            HlilType::Struct {
                name: "MyStruct".into(),
            },
        );
        assert!(ts.resolve("MyStruct").is_some());
        assert!(ts.resolve("Missing").is_none());
    }

    #[test]
    fn type_system_intern_dedup() {
        let mut ts = HlilTypeSystem::new();
        assert!(ts.intern("Foo", HlilType::i32()));
        assert!(!ts.intern("Foo", HlilType::i32()));
        assert_eq!(ts.type_count(), 1);
    }

    #[test]
    fn type_system_remove() {
        let mut ts = HlilTypeSystem::new();
        ts.intern("Bar", HlilType::u8());
        assert!(ts.remove("Bar").is_some());
        assert!(ts.remove("Bar").is_none());
    }

    #[test]
    fn type_system_unify_equal() {
        let ts = HlilTypeSystem::new();
        let t = HlilType::i32();
        assert_eq!(ts.unify(&t, &t), t);
    }

    #[test]
    fn type_system_unify_unknown() {
        let ts = HlilTypeSystem::new();
        assert_eq!(
            ts.unify(&HlilType::Unknown, &HlilType::i32()),
            HlilType::i32()
        );
        assert_eq!(
            ts.unify(&HlilType::i32(), &HlilType::Unknown),
            HlilType::i32()
        );
    }

    #[test]
    fn type_system_unify_int_widens() {
        let ts = HlilTypeSystem::new();
        let result = ts.unify(&HlilType::i32(), &HlilType::i64());
        assert_eq!(
            result,
            HlilType::Int {
                signed: false,
                bits: 64
            }
        );
    }

    #[test]
    fn type_system_unify_incompatible() {
        let ts = HlilTypeSystem::new();
        let result = ts.unify(&HlilType::Void, &HlilType::i32());
        assert_eq!(result, HlilType::Unknown);
    }

    #[test]
    fn type_system_intern_fn() {
        let mut ts = HlilTypeSystem::new();
        let ft = HlilFunctionType::void_fn("foo");
        assert!(ts.intern_fn(ft));
        assert_eq!(ts.function_types.len(), 1);
    }

    #[test]
    fn type_system_query_expr_struct() {
        let mut ts = HlilTypeSystem::new();
        ts.intern("Point", HlilType::i32());
        let expr = HlilExpr::Var {
            var: HlilVar::new(
                "p",
                HlilType::Struct {
                    name: "Point".into(),
                },
            ),
        };
        let ty = ts.query_expr(&expr);
        assert_eq!(ty, HlilType::i32());
    }

    #[test]
    fn type_system_query_expr_plain() {
        let ts = HlilTypeSystem::new();
        let expr = HlilExpr::Const {
            value: 1,
            ty: HlilType::u8(),
        };
        assert_eq!(ts.query_expr(&expr), HlilType::u8());
    }

    #[test]
    fn type_system_type_names() {
        let mut ts = HlilTypeSystem::new();
        ts.intern("Alpha", HlilType::i32());
        ts.intern("Beta", HlilType::u8());
        let names = ts.type_names();
        assert!(names.contains(&"Alpha"));
        assert!(names.contains(&"Beta"));
    }
}
