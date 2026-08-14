//! Type propagation through the AST.
//!
//! Implements forward and backward type propagation across SSA assignments,
//! function calls (guided by signature), arithmetic operations (widening /
//! narrowing), pointer arithmetic, and struct field accesses.  A lightweight
//! SSA-based constraint system is used to unify types across phi-nodes and
//! copy edges.

use std::collections::HashMap;

use rustre_decompiler_expr::{BinOp, Expr, IntWidth, UnOp};

use crate::{CallingConvention, DecompType, FunctionType, StructType, TypeDatabase};

// ─────────────────────────────────────────────────────────────────────────────
// Type constraint kinds
// ─────────────────────────────────────────────────────────────────────────────

/// A single directional type constraint produced during propagation.
#[derive(Debug, Clone)]
pub enum TypeConstraintKind {
    /// `dst` must have the same type as `src`.
    Equals { dst: String, src: String },
    /// `dst` is the pointee of `src` (i.e. `*src`).
    Deref { dst: String, ptr: String },
    /// `dst` is a pointer to `src`.
    AddrOf { dst: String, inner: String },
    /// `dst` receives the result of widening `src` to `width`.
    Widened { dst: String, src: String, width: IntWidth },
    /// `dst` is the `offset`-th field of the struct pointed to by `base`.
    StructField { dst: String, base: String, offset: u64 },
    /// `dst` receives the return type of `callee`.
    ReturnOf { dst: String, callee: String },
    /// `dst` is the `n`-th argument of `callee`.
    Argument { dst: String, callee: String, index: usize },
    /// `dst` is the result of a comparison (always `bool` / `i32`).
    BoolResult { dst: String },
}

/// A set of constraints generated from a single analysis pass.
#[derive(Debug, Default)]
pub struct PropagationConstraints {
    pub constraints: Vec<TypeConstraintKind>,
}

impl PropagationConstraints {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, c: TypeConstraintKind) {
        self.constraints.push(c);
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.constraints.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypePropagationEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Engine that propagates type information through an SSA-like assignment list.
///
/// # Algorithm
///
/// 1. **Seed** the engine with any already-known types (parameters, global
///    symbols recovered from the binary, import signatures).
/// 2. **Forward pass**: visit each assignment in program order.  For each
///    known input type, infer the output type using the transfer functions
///    below.
/// 3. **Backward pass**: if the output type of an assignment is known but the
///    input is not, propagate backwards (e.g. if `a = b` and `a : T`, then
///    `b : T`).
/// 4. Repeat until a fixed-point is reached (bounded by `max_rounds`).
#[derive(Debug)]
pub struct TypePropagationEngine {
    /// Known types for each SSA variable / label.
    types: HashMap<String, DecompType>,
    /// Function signatures looked up during call analysis.
    db: TypeDatabase,
    /// Maximum forward/backward rounds.
    pub max_rounds: usize,
    /// Log of propagation steps (for debugging).
    log: Vec<String>,
}

impl TypePropagationEngine {
    /// Create a new engine with an empty type map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            db: TypeDatabase::new(),
            max_rounds: 20,
            log: Vec::new(),
        }
    }

    /// Attach a type database (for function signature lookup).
    #[must_use] 
    pub fn with_db(mut self, db: TypeDatabase) -> Self {
        self.db = db;
        self
    }

    /// Seed a variable with a known type.
    pub fn seed(&mut self, var: impl Into<String>, ty: DecompType) {
        self.types.insert(var.into(), ty);
    }

    /// Query the inferred type of a variable.
    #[must_use]
    pub fn get(&self, var: &str) -> Option<&DecompType> {
        self.types.get(var)
    }

    /// Return a clone of the full type map.
    #[must_use]
    pub const fn type_map(&self) -> &HashMap<String, DecompType> {
        &self.types
    }

    /// Return propagation log entries.
    #[must_use]
    pub fn log(&self) -> &[String] {
        &self.log
    }

    // ── Main propagation entry point ─────────────────────────────────────────

    /// Run forward + backward propagation on the given assignments until a
    /// fixed-point is reached.
    ///
    /// Returns the number of newly inferred types.
    pub fn propagate(&mut self, assignments: &[(String, Expr)]) -> usize {
        let mut total_new = 0;
        for _round in 0..self.max_rounds {
            let fwd = self.forward_pass(assignments);
            let bwd = self.backward_pass(assignments);
            total_new += fwd + bwd;
            if fwd == 0 && bwd == 0 {
                break;
            }
        }
        total_new
    }

    // ── Forward pass ─────────────────────────────────────────────────────────

    fn forward_pass(&mut self, assignments: &[(String, Expr)]) -> usize {
        let mut new_count = 0;
        for (dst, expr) in assignments {
            if self.types.contains_key(dst.as_str()) {
                continue; // already known
            }
            if let Some(ty) = self.infer_forward(expr) {
                self.log
                    .push(format!("[fwd] {dst} : {}", ty.c_name()));
                self.types.insert(dst.clone(), ty);
                new_count += 1;
            }
        }
        new_count
    }

    /// Infer the type of `expr` given currently-known variable types.
    fn infer_forward(&self, expr: &Expr) -> Option<DecompType> {
        match expr {
            Expr::Const(_, w) | Expr::UnOp(UnOp::Cast(w), _) => Some(DecompType::Int(*w)),
            Expr::Var(n) => self.types.get(n.as_str()).cloned(),

            Expr::BinOp(op, a, b) => self.infer_binop_forward(*op, a, b),

            Expr::UnOp(UnOp::Deref, ptr) => {
                self.infer_forward(ptr).and_then(|ty| match ty {
                    DecompType::Ptr(inner) => Some(*inner),
                    DecompType::CStr => Some(DecompType::Int(IntWidth::I8)),
                    DecompType::Array(elem, _) => Some(*elem),
                    _ => None,
                })
            }
            Expr::UnOp(UnOp::AddrOf, inner) => {
                self.infer_forward(inner)
                    .map(|t| DecompType::Ptr(Box::new(t)))
            }
            Expr::UnOp(UnOp::Neg | UnOp::Not, e) => self.infer_forward(e),
            Expr::UnOp(UnOp::LNot, _) => Some(DecompType::Int(IntWidth::I32)),

            Expr::Load { ptr, size } => {
                if let Some(ty) = self.infer_forward(ptr)
                    && let DecompType::Ptr(inner) = ty {
                        return Some(*inner);
                    }
                // Fallback: use access size.
                Some(match size {
                    1 => DecompType::Int(IntWidth::U8),
                    2 => DecompType::Int(IntWidth::U16),
                    4 => DecompType::Int(IntWidth::U32),
                    _ => DecompType::Int(IntWidth::U64),
                })
            }

            Expr::FieldAccess { base, offset } => {
                if let Some(base_ty) = self.infer_forward(base) {
                    let st = match &base_ty {
                        DecompType::Ptr(inner) => {
                            if let DecompType::Struct(st) = inner.as_ref() {
                                Some(st.as_ref())
                            } else {
                                None
                            }
                        }
                        DecompType::Struct(st) => Some(st.as_ref()),
                        _ => None,
                    };
                    if let Some(st) = st
                        && let Some(field) = st.field_exact(*offset) {
                            return Some(field.ty.clone());
                        }
                }
                None
            }

            Expr::Index { base, .. } => {
                self.infer_forward(base).and_then(|ty| match ty {
                    DecompType::Ptr(inner) => Some(*inner),
                    DecompType::Array(elem, _) => Some(*elem),
                    _ => None,
                })
            }

            Expr::Call { callee, args: _ } => {
                let callee_name = callee.as_var()?;
                self.db.get_function(callee_name).map_or_else(
                    || infer_return_type_from_name(callee_name),
                    |func| Some(func.return_type.clone()),
                )
            }

            Expr::Ternary { then_expr, else_expr, .. } => {
                self.infer_forward(then_expr)
                    .or_else(|| self.infer_forward(else_expr))
            }

            Expr::Phi(exprs) => {
                // Phi: type is the join of all incoming types.
                exprs
                    .iter()
                    .find_map(|e| self.infer_forward(e))
            }
        }
    }

    fn infer_binop_forward(&self, op: BinOp, a: &Expr, b: &Expr) -> Option<DecompType> {
        let ta = self.infer_forward(a);
        let tb = self.infer_forward(b);

        match op {
            // Comparison always yields bool/i32.
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le |
            BinOp::Gt | BinOp::Ge | BinOp::LAnd | BinOp::LOr => {
                Some(DecompType::Int(IntWidth::I32))
            }

            // Pointer arithmetic: ptr + int → ptr.
            BinOp::Add | BinOp::Sub => {
                match (&ta, &tb) {
                    (Some(DecompType::Ptr(_)), _) => ta,
                    (_, Some(DecompType::Ptr(_))) => tb,
                    (Some(DecompType::CStr), _) => ta,
                    _ => widening_join(ta.as_ref(), tb.as_ref()),
                }
            }

            // Arithmetic and bitwise: apply integer widening.
            BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::And | BinOp::Or | BinOp::Xor => widening_join(ta.as_ref(), tb.as_ref()),

            // Shifts: result type is the left operand type.
            BinOp::Shl | BinOp::Shr | BinOp::Sar => ta,
        }
    }

    // ── Backward pass ─────────────────────────────────────────────────────────

    fn backward_pass(&mut self, assignments: &[(String, Expr)]) -> usize {
        let mut new_count = 0;
        // Collect backward inferences without mutably borrowing `self` twice.
        let mut to_insert: Vec<(String, DecompType)> = Vec::new();

        for (dst, expr) in assignments {
            let dst_ty = self.types.get(dst.as_str()).cloned();
            let Some(dst_ty) = dst_ty else { continue };
            self.collect_backward_inferences(expr, &dst_ty, &mut to_insert);
        }

        for (var, ty) in to_insert {
            if !self.types.contains_key(&var) {
                self.log.push(format!("[bwd] {var} : {}", ty.c_name()));
                self.types.insert(var, ty);
                new_count += 1;
            }
        }
        new_count
    }

    fn collect_backward_inferences(
        &self,
        expr: &Expr,
        expected: &DecompType,
        out: &mut Vec<(String, DecompType)>,
    ) {
        match expr {
            Expr::Var(n) => {
                if !self.types.contains_key(n.as_str()) {
                    out.push((n.clone(), expected.clone()));
                }
            }
            // Copy: both sides have same type.
            Expr::UnOp(UnOp::Cast(_), inner) => {
                // After a cast the inner is a "narrower" version — skip backward.
                let _ = inner;
            }
            Expr::UnOp(UnOp::AddrOf, inner) => {
                // expected is a pointer → inner is the pointee.
                if let DecompType::Ptr(pointee) = expected {
                    self.collect_backward_inferences(inner, pointee, out);
                }
            }
            Expr::UnOp(UnOp::Deref, ptr) => {
                // expected is the pointee type → ptr is a pointer to it.
                let ptr_ty = DecompType::Ptr(Box::new(expected.clone()));
                self.collect_backward_inferences(ptr, &ptr_ty, out);
            }
            Expr::BinOp(op, a, b) => {
                match op {
                    BinOp::Add | BinOp::Sub => {
                        // Always propagate to left operand.
                        self.collect_backward_inferences(a, expected, out);
                        // If result is not a pointer, also propagate to right operand.
                        if !expected.is_pointer() {
                            self.collect_backward_inferences(b, expected, out);
                        }
                    }
                    BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::And | BinOp::Or |
                    BinOp::Xor | BinOp::Shl | BinOp::Shr | BinOp::Sar => {
                        self.collect_backward_inferences(a, expected, out);
                        self.collect_backward_inferences(b, expected, out);
                    }
                    _ => {}
                }
            }
            Expr::Phi(exprs) => {
                for e in exprs {
                    self.collect_backward_inferences(e, expected, out);
                }
            }
            _ => {}
        }
    }

    // ── Pointer arithmetic specialisation ────────────────────────────────────

    /// Analyse pointer arithmetic patterns and record field/element types.
    ///
    /// Call this after the main propagation loop to refine struct field types.
    pub fn propagate_pointer_arith(&mut self, assignments: &[(String, Expr)]) {
        let mut updates: Vec<(String, DecompType)> = Vec::new();
        for (dst, expr) in assignments {
            if let Expr::BinOp(BinOp::Add, base, offset) = expr
                && let Some(DecompType::Ptr(inner)) = self.infer_forward(base)
                    && let DecompType::Struct(st) = inner.as_ref()
                        && let Some(c) = offset.as_const()
                            && let Some(field) = st.field_exact(u64::try_from(c).unwrap_or(u64::MAX)) {
                                updates.push((
                                    dst.clone(),
                                    DecompType::Ptr(Box::new(field.ty.clone())),
                                ));
                            }
        }
        for (var, ty) in updates {
            self.types.entry(var).or_insert(ty);
        }
    }

    // ── Struct field access propagation ──────────────────────────────────────

    /// Propagate struct field types from a known struct definition.
    pub fn propagate_struct_fields(
        &mut self,
        struct_var: &str,
        struct_ty: &StructType,
    ) {
        let ptr_ty = DecompType::Ptr(Box::new(DecompType::Struct(Box::new(struct_ty.clone()))));
        self.types.insert(struct_var.to_string(), ptr_ty);
        for field in &struct_ty.fields {
            let field_var = format!("{struct_var}_{}", field.name);
            self.types.entry(field_var).or_insert_with(|| field.ty.clone());
        }
    }

    // ── Function call propagation ─────────────────────────────────────────────

    /// Propagate types from a known function signature to its argument
    /// variables and the result variable.
    pub fn propagate_call(
        &mut self,
        result_var: &str,
        func: &FunctionType,
        arg_vars: &[&str],
    ) {
        // Result type.
        self.types
            .entry(result_var.to_string())
            .or_insert_with(|| func.return_type.clone());

        // Argument types.
        for (i, (_, param_ty)) in func.parameters.iter().enumerate() {
            if let Some(arg_var) = arg_vars.get(i) {
                self.types
                    .entry(arg_var.to_string())
                    .or_insert_with(|| param_ty.clone());
            }
        }
    }

    // ── SSA phi-node propagation ──────────────────────────────────────────────

    /// Propagate types through SSA phi nodes by joining incoming types.
    ///
    /// If all incoming variables have the same type, the phi node adopts that
    /// type.  Otherwise the widest compatible type is used.
    pub fn propagate_phi(&mut self, phi_var: &str, incoming: &[&str]) {
        if self.types.contains_key(phi_var) {
            return;
        }
        let joined = incoming
            .iter()
            .filter_map(|v| self.types.get(*v).cloned())
            .reduce(|a, b| join_types(&a, &b));
        if let Some(ty) = joined {
            self.types.insert(phi_var.to_string(), ty);
        }
    }
}

impl Default for TypePropagationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integer widening / join helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the widened integer type from two operand types.
///
/// Rules (matching C integer promotion):
/// * If one operand is 64-bit, result is 64-bit.
/// * If one operand is unsigned and the other signed with the same width,
///   the result is unsigned (matching C's "usual arithmetic conversions").
/// * Otherwise, the wider type wins.
fn widening_join(a: Option<&DecompType>, b: Option<&DecompType>) -> Option<DecompType> {
    let (a, b) = (a?, b?);
    match (a, b) {
        (DecompType::Int(wa), DecompType::Int(wb)) => {
            let result = widen_int(*wa, *wb);
            Some(DecompType::Int(result))
        }
        (DecompType::Float32, DecompType::Float32) => Some(DecompType::Float32),
        (DecompType::Float64, _) | (_, DecompType::Float64) => Some(DecompType::Float64),
        (DecompType::Float32, DecompType::Int(_)) | (DecompType::Int(_), DecompType::Float32) => {
            Some(DecompType::Float64)
        }
        (t, _) => Some(t.clone()),
    }
}

fn widen_int(a: IntWidth, b: IntWidth) -> IntWidth {
    let bits_a = a.bits();
    let bits_b = b.bits();
    let bits = bits_a.max(bits_b);
    let signed = a.is_signed() && b.is_signed();
    match (bits, signed) {
        (8, true) => IntWidth::I8,
        (8, false) => IntWidth::U8,
        (16, true) => IntWidth::I16,
        (16, false) => IntWidth::U16,
        (32, true) => IntWidth::I32,
        (32, false) => IntWidth::U32,
        (_, true) => IntWidth::I64,
        (_, false) => IntWidth::U64,
    }
}

/// Compute the least-upper-bound (join) of two types.
///
/// Used when merging types at phi-nodes and other meet-points.
fn join_types(a: &DecompType, b: &DecompType) -> DecompType {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (DecompType::Int(wa), DecompType::Int(wb)) => DecompType::Int(widen_int(*wa, *wb)),
        (DecompType::Ptr(_), DecompType::Unknown) | (DecompType::Unknown, DecompType::Ptr(_)) => {
            a.clone()
        }
        (DecompType::Unknown, t) | (t, DecompType::Unknown) => t.clone(),
        _ => DecompType::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Callee-name heuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Infer the return type of a function from its name alone.
fn infer_return_type_from_name(name: &str) -> Option<DecompType> {
    let n = name.to_lowercase();
    // String functions → char * or size_t.
    if n.starts_with("str") && matches!(n.as_str(), "strlen" | "strnlen") {
        return Some(DecompType::Int(IntWidth::U64));
    }
    if n.starts_with("str") {
        return Some(DecompType::CStr);
    }
    // Memory allocation → void *.
    if matches!(n.as_str(), "malloc" | "calloc" | "realloc" | "new" | "heapalloc") {
        return Some(DecompType::Ptr(Box::new(DecompType::Void)));
    }
    // Boolean predicates → int.
    if n.starts_with("is") || n.starts_with("has") || n.ends_with("_ok") {
        return Some(DecompType::Int(IntWidth::I32));
    }
    // Open/fopen → FILE *.
    if n.contains("fopen") || n.contains("_open") {
        return Some(DecompType::Ptr(Box::new(DecompType::Void)));
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraint collector
// ─────────────────────────────────────────────────────────────────────────────

/// Walk an expression and collect all typing constraints it generates.
pub fn collect_constraints(
    dst: &str,
    expr: &Expr,
    out: &mut PropagationConstraints,
) {
    match expr {
        Expr::Var(src) => out.push(TypeConstraintKind::Equals {
            dst: dst.to_string(),
            src: src.clone(),
        }),

        Expr::UnOp(UnOp::Deref, ptr) => {
            let tmp = format!("{dst}__ptr");
            collect_constraints(&tmp, ptr, out);
            out.push(TypeConstraintKind::Deref {
                dst: dst.to_string(),
                ptr: tmp,
            });
        }

        Expr::UnOp(UnOp::AddrOf, inner) => {
            let tmp = format!("{dst}__inner");
            collect_constraints(&tmp, inner, out);
            out.push(TypeConstraintKind::AddrOf {
                dst: dst.to_string(),
                inner: tmp,
            });
        }

        Expr::UnOp(UnOp::Cast(w), _) => out.push(TypeConstraintKind::Widened {
            dst: dst.to_string(),
            src: format!("{dst}__cast_src"),
            width: *w,
        }),

        Expr::BinOp(op, a, _b) => {
            if op.is_comparison() {
                out.push(TypeConstraintKind::BoolResult { dst: dst.to_string() });
            }
            if let Some(src_var) = a.as_var() {
                out.push(TypeConstraintKind::Equals {
                    dst: dst.to_string(),
                    src: src_var.to_string(),
                });
            }
        }

        Expr::FieldAccess { base, offset } => {
            if let Some(base_var) = base.as_var() {
                out.push(TypeConstraintKind::StructField {
                    dst: dst.to_string(),
                    base: base_var.to_string(),
                    offset: *offset,
                });
            }
        }

        Expr::Call { callee, args } => {
            if let Some(callee_name) = callee.as_var() {
                out.push(TypeConstraintKind::ReturnOf {
                    dst: dst.to_string(),
                    callee: callee_name.to_string(),
                });
                for (i, arg) in args.iter().enumerate() {
                    if let Some(arg_var) = arg.as_var() {
                        out.push(TypeConstraintKind::Argument {
                            dst: arg_var.to_string(),
                            callee: callee_name.to_string(),
                            index: i,
                        });
                    }
                }
            }
        }

        Expr::Phi(exprs) => {
            for e in exprs {
                collect_constraints(dst, e, out);
            }
        }

        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Calling-convention aware propagation
// ─────────────────────────────────────────────────────────────────────────────

/// Annotate argument and return types according to a known calling convention.
///
/// For `SysV` x64 and MS x64 the argument registers are well-defined; this
/// helper seeds the type engine with register-variable names.
pub fn seed_calling_convention_types(
    engine: &mut TypePropagationEngine,
    func: &FunctionType,
) {
    // Register names used by SysV AMD64 and MSVC x64.
    let sysv_arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    let msvc_arg_regs = ["rcx", "rdx", "r8", "r9"];

    let arg_regs: &[&str] = match func.calling_convention {
        CallingConvention::SysV64 => &sysv_arg_regs,
        _ => &msvc_arg_regs, // MSVC x64, FastCall, and all others use MSVC registers
    };

    for (i, (param_name, param_ty)) in func.parameters.iter().enumerate() {
        // Seed by parameter name.
        engine.seed(param_name.clone(), param_ty.clone());
        // Also seed the corresponding register variable.
        if let Some(reg) = arg_regs.get(i) {
            engine.seed(format!("var_{reg}"), param_ty.clone());
        }
    }
    // Seed return register.
    let ret_reg = "rax";
    engine.seed(format!("var_{ret_reg}"), func.return_type.clone());
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructField;

    fn i32() -> DecompType { DecompType::Int(IntWidth::I32) }
    fn i64() -> DecompType { DecompType::Int(IntWidth::I64) }
    fn u32() -> DecompType { DecompType::Int(IntWidth::U32) }
    fn ptr_i32() -> DecompType { DecompType::Ptr(Box::new(DecompType::Int(IntWidth::I32))) }

    #[test]
    fn test_seed_and_get() {
        let mut eng = TypePropagationEngine::new();
        eng.seed("x", i32());
        assert_eq!(eng.get("x"), Some(&i32()));
    }

    #[test]
    fn test_forward_const() {
        let mut eng = TypePropagationEngine::new();
        let assigns = vec![(
            "a".to_string(),
            Expr::Const(42, IntWidth::I32),
        )];
        let n = eng.propagate(&assigns);
        assert!(n > 0);
        assert_eq!(eng.get("a"), Some(&i32()));
    }

    #[test]
    fn test_forward_var_copy() {
        let mut eng = TypePropagationEngine::new();
        eng.seed("x", ptr_i32());
        let assigns = vec![(
            "y".to_string(),
            Expr::Var("x".to_string()),
        )];
        eng.propagate(&assigns);
        assert_eq!(eng.get("y"), Some(&ptr_i32()));
    }

    #[test]
    fn test_forward_deref() {
        let mut eng = TypePropagationEngine::new();
        eng.seed("p", ptr_i32());
        let assigns = vec![(
            "v".to_string(),
            Expr::UnOp(UnOp::Deref, Box::new(Expr::Var("p".to_string()))),
        )];
        eng.propagate(&assigns);
        assert_eq!(eng.get("v"), Some(&i32()));
    }

    #[test]
    fn test_backward_propagation() {
        let mut eng = TypePropagationEngine::new();
        // `b` = `a`, and `b : i32` is known from elsewhere → `a : i32`.
        let assigns = vec![(
            "b".to_string(),
            Expr::Var("a".to_string()),
        )];
        eng.seed("b", i32());
        eng.propagate(&assigns);
        assert_eq!(eng.get("a"), Some(&i32()));
    }

    #[test]
    fn test_phi_join_same_type() {
        let mut eng = TypePropagationEngine::new();
        eng.seed("x", i32());
        eng.seed("y", i32());
        eng.propagate_phi("z", &["x", "y"]);
        assert_eq!(eng.get("z"), Some(&i32()));
    }

    #[test]
    fn test_phi_join_widening() {
        let mut eng = TypePropagationEngine::new();
        eng.seed("a", DecompType::Int(IntWidth::I16));
        eng.seed("b", i32());
        eng.propagate_phi("c", &["a", "b"]);
        // Result should be the wider i32.
        assert_eq!(eng.get("c"), Some(&i32()));
    }

    #[test]
    fn test_struct_field_propagation() {
        let st = StructType {
            name: "Foo".to_string(),
            fields: vec![
                StructField { offset: 0, name: "x".to_string(), ty: i32() },
                StructField { offset: 4, name: "y".to_string(), ty: u32() },
            ],
            total_size: 8,
        };
        let mut eng = TypePropagationEngine::new();
        eng.propagate_struct_fields("foo_ptr", &st);
        assert!(eng.get("foo_ptr").is_some());
        assert_eq!(eng.get("foo_ptr_x"), Some(&i32()));
        assert_eq!(eng.get("foo_ptr_y"), Some(&u32()));
    }

    #[test]
    fn test_comparison_yields_bool() {
        let mut eng = TypePropagationEngine::new();
        let assigns = vec![(
            "cmp".to_string(),
            Expr::BinOp(
                BinOp::Eq,
                Box::new(Expr::Var("x".to_string())),
                Box::new(Expr::Const(0, IntWidth::I32)),
            ),
        )];
        eng.propagate(&assigns);
        assert_eq!(eng.get("cmp"), Some(&DecompType::Int(IntWidth::I32)));
    }

    #[test]
    fn test_widen_int_promotes() {
        let result = widen_int(IntWidth::I16, IntWidth::I32);
        assert_eq!(result, IntWidth::I32);
    }

    #[test]
    fn test_collect_constraints_call() {
        let expr = Expr::Call {
            callee: Box::new(Expr::Var("malloc".to_string())),
            args: vec![Expr::Var("size".to_string())],
        };
        let mut out = PropagationConstraints::new();
        collect_constraints("ptr", &expr, &mut out);
        assert!(!out.is_empty());
        assert!(matches!(
            out.constraints[0],
            TypeConstraintKind::ReturnOf { .. }
        ));
    }

    #[test]
    fn test_pointer_arith_propagation() {
        let st = StructType {
            name: "Node".to_string(),
            fields: vec![
                StructField { offset: 0, name: "val".to_string(), ty: i32() },
                StructField { offset: 8, name: "next".to_string(), ty: ptr_i32() },
            ],
            total_size: 16,
        };
        let ptr_node = DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st))));
        let mut eng = TypePropagationEngine::new();
        eng.seed("node", ptr_node);
        let assigns = vec![(
            "field_ptr".to_string(),
            Expr::BinOp(
                BinOp::Add,
                Box::new(Expr::Var("node".to_string())),
                Box::new(Expr::Const(8, IntWidth::U64)),
            ),
        )];
        eng.propagate_pointer_arith(&assigns);
        // Should infer the type of field at offset 8.
        assert!(eng.get("field_ptr").is_some());
    }
}
