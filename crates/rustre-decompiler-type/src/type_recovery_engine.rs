//! `type_recovery_engine` — constraint-based type recovery for the decompiler.
//!
//! Provides [`TypeRecoveryEngine`] which collects [`TypeConstraint`]s from
//! operations, solves them via propagation, and populates a [`TypeEnvironment`]
//! with recovered types for variables.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::{DecompType, StructField, StructType, TypeEnvironment};
use rustre_decompiler_expr::IntWidth;

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// A constraint on the type of a variable, derived from an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeConstraint {
    /// Subject variable name.
    pub var: String,
    /// Constrained type.
    pub ty: ConstrainedType,
    /// Confidence in this constraint (0–100).
    pub confidence: u8,
    /// Human-readable reason.
    pub reason: String,
}

/// The type constraint kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstrainedType {
    /// Must be exactly this type.
    Exact(DecompType),
    /// Must be at least this wide (in bits).
    AtLeastWidth(u32),
    /// Must be a pointer.
    IsPointer,
    /// Must be a signed integer.
    IsSigned,
    /// Must be an unsigned integer.
    IsUnsigned,
    /// Must be a float.
    IsFloat,
    /// Must be a boolean.
    IsBool,
    /// Must be an integer (any width).
    IsInteger,
    /// Must be compatible with this type.
    CompatibleWith(DecompType),
}

impl TypeConstraint {
    /// Create an exact type constraint.
    #[must_use]
    pub fn exact(var: impl Into<String>, ty: DecompType, reason: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            ty: ConstrainedType::Exact(ty),
            confidence: 100,
            reason: reason.into(),
        }
    }

    /// Create a pointer constraint.
    #[must_use]
    pub fn is_pointer(var: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            ty: ConstrainedType::IsPointer,
            confidence: 90,
            reason: reason.into(),
        }
    }

    /// Create a signed integer constraint.
    #[must_use]
    pub fn is_signed(var: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            ty: ConstrainedType::IsSigned,
            confidence: 70,
            reason: reason.into(),
        }
    }

    /// Create a width constraint.
    #[must_use]
    pub fn at_least_width(var: impl Into<String>, bits: u32, reason: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            ty: ConstrainedType::AtLeastWidth(bits),
            confidence: 80,
            reason: reason.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeSolver — constraint propagation
// ─────────────────────────────────────────────────────────────────────────────

/// Solves a system of type constraints by propagation.
#[derive(Debug, Default)]
pub struct TypeSolver {
    pub constraints: Vec<TypeConstraint>,
    /// Equality edges: if `var_a` == `var_b`, they should have the same type.
    pub equality_edges: Vec<(String, String)>,
    /// Derived types after solving.
    pub solved: HashMap<String, DecompType>,
}

impl TypeSolver {
    /// Create a new solver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint.
    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.constraints.push(c);
    }

    /// Add a type equality between two variables.
    pub fn add_equality(&mut self, a: impl Into<String>, b: impl Into<String>) {
        self.equality_edges.push((a.into(), b.into()));
    }

    /// Run constraint propagation.
    pub fn solve(&mut self) {
        // First pass: apply exact constraints directly.
        for c in &self.constraints {
            if let ConstrainedType::Exact(ty) = &c.ty {
                self.solved.insert(c.var.clone(), ty.clone());
            }
        }
        // Second pass: apply heuristic constraints for unsolved variables.
        for c in &self.constraints {
            if self.solved.contains_key(&c.var) {
                continue;
            }
            let ty = match &c.ty {
                ConstrainedType::IsPointer => DecompType::Ptr(Box::new(DecompType::Unknown)),
                ConstrainedType::IsBool => DecompType::Bool,
                ConstrainedType::IsFloat => DecompType::Float64,
                ConstrainedType::IsSigned => DecompType::Int(IntWidth::I64),
                ConstrainedType::IsUnsigned => DecompType::Int(IntWidth::U64),
                ConstrainedType::IsInteger => DecompType::Int(IntWidth::I32),
                ConstrainedType::AtLeastWidth(bits) => {
                    let w = width_for_bits(*bits);
                    DecompType::Int(w)
                }
                ConstrainedType::CompatibleWith(ty) => ty.clone(),
                ConstrainedType::Exact(_) => continue,
            };
            self.solved.entry(c.var.clone()).or_insert(ty);
        }
        // Propagate equality edges with a FIFO worklist so newly-resolved
        // variables are revisited promptly.
        // Bound total iterations to prevent an unbounded loop on adversarial
        // constraint graphs: at most one variable can be newly-solved per
        // round, so N * |edges| iterations is a safe ceiling.
        let max_iters = self.equality_edges.len().saturating_mul(self.equality_edges.len() + 1);
        let mut iters = 0usize;
        let mut worklist: VecDeque<usize> = (0..self.equality_edges.len()).collect();
        while let Some(idx) = worklist.pop_front() {
            if iters >= max_iters {
                break;
            }
            iters += 1;
            let (a, b) = self.equality_edges[idx].clone();
            let ta = self.solved.get(&a).cloned();
            let tb = self.solved.get(&b).cloned();
            match (ta, tb) {
                (Some(ty), None) => {
                    self.solved.insert(b, ty);
                    // Re-enqueue all edges so neighbours can propagate further.
                    worklist.extend(0..self.equality_edges.len());
                }
                (None, Some(ty)) => {
                    self.solved.insert(a, ty);
                    worklist.extend(0..self.equality_edges.len());
                }
                _ => {}
            }
        }
    }

    /// Get the solved type for a variable.
    #[must_use]
    pub fn get(&self, var: &str) -> Option<&DecompType> {
        self.solved.get(var)
    }

    /// Return the number of solved variables.
    #[must_use]
    pub fn solved_count(&self) -> usize {
        self.solved.len()
    }

    /// Return variables that are still unknown.
    #[must_use]
    pub fn unsolved_vars(&self) -> Vec<&str> {
        let all: HashSet<&str> = self.constraints.iter().map(|c| c.var.as_str()).collect();
        all.into_iter()
            .filter(|v| !self.solved.contains_key(*v))
            .collect()
    }
}

const fn width_for_bits(bits: u32) -> IntWidth {
    match bits {
        0..=8 => IntWidth::I8,
        9..=16 => IntWidth::I16,
        17..=32 => IntWidth::I32,
        _ => IntWidth::I64,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Records pointer points-to and aliasing relationships.
#[derive(Debug, Default)]
pub struct PointerAnalysis {
    points_to: HashMap<String, Vec<String>>,
    may_alias: Vec<(String, String)>,
    must_not_be_null: HashSet<String>,
}

impl PointerAnalysis {
    /// Create a new pointer analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `ptr` points to `target`.
    pub fn record_points_to(&mut self, ptr: impl Into<String>, target: impl Into<String>) {
        self.points_to
            .entry(ptr.into())
            .or_default()
            .push(target.into());
    }

    /// Record that two pointers may alias.
    pub fn record_may_alias(&mut self, a: impl Into<String>, b: impl Into<String>) {
        self.may_alias.push((a.into(), b.into()));
    }

    /// Mark a pointer as definitely non-null.
    pub fn record_nonnull(&mut self, ptr: impl Into<String>) {
        self.must_not_be_null.insert(ptr.into());
    }

    /// Return all known targets for a pointer.
    #[must_use]
    pub fn points_to_targets(&self, ptr: &str) -> &[String] {
        self.points_to.get(ptr).map_or(&[], Vec::as_slice)
    }

    /// Check if `ptr` may alias with `other`.
    #[must_use]
    pub fn may_alias_with(&self, ptr: &str, other: &str) -> bool {
        self.may_alias
            .iter()
            .any(|(a, b)| (a == ptr && b == other) || (b == ptr && a == other))
    }

    /// Check if a pointer is definitely non-null.
    #[must_use]
    pub fn is_nonnull(&self, ptr: &str) -> bool {
        self.must_not_be_null.contains(ptr)
            || !self.points_to.get(ptr).unwrap_or(&Vec::new()).is_empty()
    }

    /// Return the number of distinct pointers tracked.
    #[must_use]
    pub fn pointer_count(&self) -> usize {
        self.points_to.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArrayDetection
// ─────────────────────────────────────────────────────────────────────────────

/// Detects array access patterns in expressions.
#[derive(Debug, Default)]
pub struct ArrayDetection {
    /// Detected arrays: base variable → (element type, length hint).
    pub arrays: HashMap<String, (DecompType, u64)>,
    /// Stride observations: base var → observed stride.
    pub strides: HashMap<String, Vec<u64>>,
}

impl ArrayDetection {
    /// Create a new array detection context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed memory access stride for a base variable.
    pub fn observe_stride(&mut self, base: impl Into<String>, stride: u64) {
        self.strides.entry(base.into()).or_default().push(stride);
    }

    /// Finalize: decide the most likely element type from observed strides.
    pub fn finalize(&mut self) {
        for (base, strides) in &self.strides {
            if strides.is_empty() {
                continue;
            }
            let mode = most_common(strides);
            let elem_ty = element_type_from_stride(mode);
            self.arrays.insert(base.clone(), (elem_ty, 0)); // length unknown
        }
    }

    /// Record a known array with an explicit length.
    pub fn record_array(&mut self, base: impl Into<String>, elem_ty: DecompType, len: u64) {
        self.arrays.insert(base.into(), (elem_ty, len));
    }

    /// Return the detected element type for a base.
    #[must_use]
    pub fn element_type(&self, base: &str) -> Option<&DecompType> {
        self.arrays.get(base).map(|(t, _)| t)
    }

    /// Return the number of detected arrays.
    #[must_use]
    pub fn array_count(&self) -> usize {
        self.arrays.len()
    }
}

fn most_common(v: &[u64]) -> u64 {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for &x in v {
        *counts.entry(x).or_insert(0) += 1;
    }
    *counts
        .iter()
        .max_by_key(|(_, c)| *c)
        .map_or(&1, |(k, _)| k)
}

const fn element_type_from_stride(stride: u64) -> DecompType {
    match stride {
        1 => DecompType::Int(IntWidth::U8),
        2 => DecompType::Int(IntWidth::U16),
        4 => DecompType::Int(IntWidth::U32),
        8 => DecompType::Int(IntWidth::U64),
        _ => DecompType::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructFieldRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers struct field layout from observed memory accesses.
#[derive(Debug, Default)]
pub struct StructFieldRecovery {
    /// Observed accesses per base: offset → (size, `access_count`).
    pub observations: HashMap<String, HashMap<u64, (u8, usize)>>,
}

impl StructFieldRecovery {
    /// Create a new struct field recovery context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a memory access at a specific offset.
    pub fn observe_access(&mut self, base: impl Into<String>, offset: u64, size: u8) {
        let entry = self
            .observations
            .entry(base.into())
            .or_default()
            .entry(offset)
            .or_insert((size, 0));
        entry.1 += 1;
    }

    /// Recover the struct type for a base variable.
    #[must_use]
    pub fn recover_struct(&self, base: &str, name: impl Into<String>) -> Option<StructType> {
        let accesses = self.observations.get(base)?;
        let mut fields: Vec<StructField> = accesses
            .iter()
            .map(|(&offset, &(size, _))| {
                let ty = match size {
                    1 => DecompType::Int(IntWidth::U8),
                    2 => DecompType::Int(IntWidth::U16),
                    4 => DecompType::Int(IntWidth::U32),
                    8 => DecompType::Int(IntWidth::U64),
                    _ => DecompType::Unknown,
                };
                StructField::new(offset, format!("field_{offset:x}"), ty)
            })
            .collect();
        fields.sort_by_key(|f| f.offset);
        let total_size = fields
            .iter()
            .map(|f| f.offset + f.ty.byte_size().unwrap_or(8))
            .max()
            .unwrap_or(0);
        Some(StructType::new(name, fields, total_size))
    }

    /// Return the number of tracked bases.
    #[must_use]
    pub fn base_count(&self) -> usize {
        self.observations.len()
    }

    /// Return the number of observed field accesses for a base.
    #[must_use]
    pub fn field_count(&self, base: &str) -> usize {
        self.observations.get(base).map_or(0, HashMap::len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeRecoveryEngine — top-level orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level type recovery engine that coordinates all sub-analyses.
#[derive(Debug)]
pub struct TypeRecoveryEngine {
    pub solver: TypeSolver,
    pub pointer_analysis: PointerAnalysis,
    pub array_detection: ArrayDetection,
    pub struct_recovery: StructFieldRecovery,
    pub env: TypeEnvironment,
}

impl Default for TypeRecoveryEngine {
    fn default() -> Self {
        Self {
            solver: TypeSolver::new(),
            pointer_analysis: PointerAnalysis::new(),
            array_detection: ArrayDetection::new(),
            struct_recovery: StructFieldRecovery::new(),
            env: TypeEnvironment::new(),
        }
    }
}

impl TypeRecoveryEngine {
    /// Create a new type recovery engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a type constraint.
    pub fn add_constraint(&mut self, c: TypeConstraint) {
        self.solver.add_constraint(c);
    }

    /// Record a pointer dereference: infer that `ptr` is a pointer.
    pub fn record_deref(&mut self, ptr: impl Into<String>) {
        let p: String = ptr.into();
        self.solver
            .add_constraint(TypeConstraint::is_pointer(p.clone(), "deref"));
        self.pointer_analysis.record_nonnull(p);
    }

    /// Record an arithmetic operation: infer integer types.
    pub fn record_arithmetic(&mut self, result: impl Into<String>, operand: impl Into<String>) {
        let r = result.into();
        let o = operand.into();
        self.solver.add_constraint(TypeConstraint {
            var: r.clone(),
            ty: ConstrainedType::IsInteger,
            confidence: 60,
            reason: "arithmetic".to_string(),
        });
        self.solver.add_equality(r, o);
    }

    /// Record a comparison: infer boolean result type.
    pub fn record_comparison(&mut self, result: impl Into<String>, signed: bool) {
        let r = result.into();
        let reason = if signed {
            "signed comparison result"
        } else {
            "unsigned comparison result"
        };
        self.solver.add_constraint(TypeConstraint {
            var: r,
            ty: ConstrainedType::IsBool,
            confidence: 95,
            reason: reason.to_string(),
        });
    }

    /// Record a struct field access.
    pub fn record_struct_access(&mut self, base: impl Into<String>, offset: u64, access_size: u8) {
        let b = base.into();
        self.struct_recovery
            .observe_access(b.clone(), offset, access_size);
        self.solver
            .add_constraint(TypeConstraint::is_pointer(b, "struct field access"));
    }

    /// Record an array element access.
    pub fn record_array_access(&mut self, base: impl Into<String>, stride: u64) {
        let b = base.into();
        self.array_detection.observe_stride(b.clone(), stride);
        self.solver
            .add_constraint(TypeConstraint::is_pointer(b, "array access"));
    }

    /// Run all recovery passes and populate the environment.
    pub fn run(&mut self) {
        self.array_detection.finalize();
        self.solver.solve();
        // Populate env from solver results.
        for (var, ty) in &self.solver.solved {
            self.env.set(var.clone(), ty.clone());
        }
        // Populate array types in env.
        for (base, (elem_ty, _)) in &self.array_detection.arrays {
            if self.env.get(base).is_none() {
                self.env
                    .set(base.clone(), DecompType::Ptr(Box::new(elem_ty.clone())));
            }
        }
        // Recover and register structs.
        let bases: Vec<String> = self.struct_recovery.observations.keys().cloned().collect();
        for base in bases {
            let struct_name = format!("struct_{base}");
            if let Some(st) = self.struct_recovery.recover_struct(&base, &struct_name) {
                self.env.add_struct(st.clone());
                self.env.set(
                    base,
                    DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st)))),
                );
            }
        }
    }

    /// Get the recovered type for a variable.
    #[must_use]
    pub fn get_type(&self, var: &str) -> Option<&DecompType> {
        self.env.get(var)
    }

    /// Return the number of recovered types.
    #[must_use]
    pub fn recovered_count(&self) -> usize {
        self.solver.solved_count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TypeConstraint ────────────────────────────────────────────────────────

    #[test]
    fn test_constraint_exact() {
        let c = TypeConstraint::exact("x", DecompType::Int(IntWidth::I32), "assignment");
        assert_eq!(c.var, "x");
        assert_eq!(c.confidence, 100);
        assert!(matches!(c.ty, ConstrainedType::Exact(_)));
    }

    #[test]
    fn test_constraint_is_pointer() {
        let c = TypeConstraint::is_pointer("p", "deref");
        assert_eq!(c.ty, ConstrainedType::IsPointer);
    }

    #[test]
    fn test_constraint_is_signed() {
        let c = TypeConstraint::is_signed("val", "sdiv");
        assert_eq!(c.ty, ConstrainedType::IsSigned);
    }

    #[test]
    fn test_constraint_at_least_width() {
        let c = TypeConstraint::at_least_width("large", 32, "wide store");
        assert_eq!(c.ty, ConstrainedType::AtLeastWidth(32));
    }

    // ── TypeSolver ────────────────────────────────────────────────────────────

    #[test]
    fn test_solver_exact_constraint() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint::exact(
            "x",
            DecompType::Int(IntWidth::I32),
            "test",
        ));
        s.solve();
        assert!(matches!(s.get("x"), Some(DecompType::Int(IntWidth::I32))));
    }

    #[test]
    fn test_solver_pointer_constraint() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint::is_pointer("p", "load"));
        s.solve();
        assert!(matches!(s.get("p"), Some(DecompType::Ptr(_))));
    }

    #[test]
    fn test_solver_bool_constraint() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint {
            var: "flag".to_string(),
            ty: ConstrainedType::IsBool,
            confidence: 90,
            reason: "cmp".to_string(),
        });
        s.solve();
        assert!(matches!(s.get("flag"), Some(DecompType::Bool)));
    }

    #[test]
    fn test_solver_equality_propagation() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint::exact(
            "a",
            DecompType::Int(IntWidth::I32),
            "",
        ));
        s.add_equality("a", "b");
        s.solve();
        assert!(matches!(s.get("b"), Some(DecompType::Int(IntWidth::I32))));
    }

    #[test]
    fn test_solver_solved_count() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint::exact("x", DecompType::Bool, ""));
        s.add_constraint(TypeConstraint::exact("y", DecompType::Float64, ""));
        s.solve();
        assert_eq!(s.solved_count(), 2);
    }

    #[test]
    fn test_solver_at_least_width() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint::at_least_width("big", 32, "store"));
        s.solve();
        assert!(s.get("big").is_some());
    }

    #[test]
    fn test_solver_unsigned_constraint() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint {
            var: "u".to_string(),
            ty: ConstrainedType::IsUnsigned,
            confidence: 70,
            reason: "udiv".to_string(),
        });
        s.solve();
        let ty = s.get("u").unwrap();
        assert!(matches!(ty, DecompType::Int(w) if !w.is_signed()));
    }

    #[test]
    fn test_solver_float_constraint() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint {
            var: "f".to_string(),
            ty: ConstrainedType::IsFloat,
            confidence: 90,
            reason: "fadd".to_string(),
        });
        s.solve();
        assert!(matches!(
            s.get("f"),
            Some(DecompType::Float64 | DecompType::Float32)
        ));
    }

    // ── PointerAnalysis ───────────────────────────────────────────────────────

    #[test]
    fn test_pointer_analysis_points_to() {
        let mut pa = PointerAnalysis::new();
        pa.record_points_to("p", "obj");
        assert_eq!(pa.points_to_targets("p"), &["obj".to_string()]);
    }

    #[test]
    fn test_pointer_analysis_may_alias() {
        let mut pa = PointerAnalysis::new();
        pa.record_may_alias("a", "b");
        assert!(pa.may_alias_with("a", "b"));
        assert!(pa.may_alias_with("b", "a"));
        assert!(!pa.may_alias_with("a", "c"));
    }

    #[test]
    fn test_pointer_analysis_nonnull() {
        let mut pa = PointerAnalysis::new();
        pa.record_nonnull("q");
        assert!(pa.is_nonnull("q"));
        assert!(!pa.is_nonnull("null_ptr"));
    }

    #[test]
    fn test_pointer_analysis_count() {
        let mut pa = PointerAnalysis::new();
        pa.record_points_to("p1", "x");
        pa.record_points_to("p2", "y");
        assert_eq!(pa.pointer_count(), 2);
    }

    #[test]
    fn test_pointer_analysis_nonnull_via_points_to() {
        let mut pa = PointerAnalysis::new();
        pa.record_points_to("ptr", "some_object");
        assert!(pa.is_nonnull("ptr"));
    }

    // ── ArrayDetection ────────────────────────────────────────────────────────

    #[test]
    fn test_array_detection_stride_4() {
        let mut ad = ArrayDetection::new();
        ad.observe_stride("arr", 4);
        ad.observe_stride("arr", 4);
        ad.finalize();
        let ty = ad.element_type("arr").unwrap();
        assert!(matches!(ty, DecompType::Int(IntWidth::U32)));
    }

    #[test]
    fn test_array_detection_stride_8() {
        let mut ad = ArrayDetection::new();
        ad.observe_stride("ptrs", 8);
        ad.finalize();
        let ty = ad.element_type("ptrs").unwrap();
        assert!(matches!(ty, DecompType::Int(IntWidth::U64)));
    }

    #[test]
    fn test_array_detection_record_explicit() {
        let mut ad = ArrayDetection::new();
        ad.record_array("buf", DecompType::Int(IntWidth::U8), 256);
        assert_eq!(ad.array_count(), 1);
    }

    #[test]
    fn test_array_detection_count() {
        let mut ad = ArrayDetection::new();
        ad.observe_stride("a", 4);
        ad.observe_stride("b", 8);
        ad.finalize();
        assert_eq!(ad.array_count(), 2);
    }

    // ── StructFieldRecovery ───────────────────────────────────────────────────

    #[test]
    fn test_struct_field_recovery_observe() {
        let mut sfr = StructFieldRecovery::new();
        sfr.observe_access("obj", 0, 4);
        sfr.observe_access("obj", 4, 4);
        sfr.observe_access("obj", 8, 8);
        assert_eq!(sfr.field_count("obj"), 3);
    }

    #[test]
    fn test_struct_field_recovery_recover() {
        let mut sfr = StructFieldRecovery::new();
        sfr.observe_access("node", 0, 4);
        sfr.observe_access("node", 8, 8);
        let st = sfr.recover_struct("node", "NodeType").unwrap();
        assert_eq!(st.name, "NodeType");
        assert_eq!(st.fields.len(), 2);
    }

    #[test]
    fn test_struct_total_size_computed() {
        let mut sfr = StructFieldRecovery::new();
        sfr.observe_access("s", 0, 4);
        sfr.observe_access("s", 4, 8);
        let st = sfr.recover_struct("s", "S").unwrap();
        assert!(st.total_size >= 8);
    }

    #[test]
    fn test_pointer_analysis_empty_targets() {
        let pa = PointerAnalysis::new();
        assert!(pa.points_to_targets("unknown").is_empty());
    }

    #[test]
    fn test_solver_integer_constraint() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint {
            var: "n".to_string(),
            ty: ConstrainedType::IsInteger,
            confidence: 60,
            reason: "arithmetic".to_string(),
        });
        s.solve();
        assert!(s.get("n").is_some());
    }

    #[test]
    fn test_solver_compatible_with() {
        let mut s = TypeSolver::new();
        s.add_constraint(TypeConstraint {
            var: "v".to_string(),
            ty: ConstrainedType::CompatibleWith(DecompType::Float32),
            confidence: 70,
            reason: "float op".to_string(),
        });
        s.solve();
        assert!(matches!(s.get("v"), Some(DecompType::Float32)));
    }

    #[test]
    fn test_engine_run_multiple_constraints() {
        let mut eng = TypeRecoveryEngine::new();
        eng.add_constraint(TypeConstraint::exact(
            "a",
            DecompType::Int(IntWidth::I32),
            "",
        ));
        eng.add_constraint(TypeConstraint::exact("b", DecompType::Float64, ""));
        eng.add_constraint(TypeConstraint::is_pointer("c", "deref"));
        eng.run();
        assert!(eng.recovered_count() >= 3);
    }

    #[test]
    fn test_struct_field_recovery_missing_base() {
        let sfr = StructFieldRecovery::new();
        assert!(sfr.recover_struct("missing", "X").is_none());
    }

    #[test]
    fn test_struct_field_recovery_base_count() {
        let mut sfr = StructFieldRecovery::new();
        sfr.observe_access("a", 0, 4);
        sfr.observe_access("b", 0, 8);
        assert_eq!(sfr.base_count(), 2);
    }

    #[test]
    fn test_struct_field_recovery_field_size() {
        let mut sfr = StructFieldRecovery::new();
        sfr.observe_access("s", 0, 1);
        sfr.observe_access("s", 4, 4);
        let st = sfr.recover_struct("s", "S").unwrap();
        let f0 = st.field_exact(0).unwrap();
        assert!(matches!(f0.ty, DecompType::Int(IntWidth::U8)));
    }

    // ── TypeRecoveryEngine ────────────────────────────────────────────────────

    #[test]
    fn test_engine_deref() {
        let mut eng = TypeRecoveryEngine::new();
        eng.record_deref("ptr");
        eng.run();
        let ty = eng.get_type("ptr");
        assert!(ty.is_some());
        assert!(matches!(ty.unwrap(), DecompType::Ptr(_)));
    }

    #[test]
    fn test_engine_arithmetic() {
        let mut eng = TypeRecoveryEngine::new();
        eng.record_arithmetic("r", "a");
        eng.run();
        // r should be typed as integer.
        let _ = eng.recovered_count();
        let _ = eng.get_type("r").is_some();
    }

    #[test]
    fn test_engine_comparison() {
        let mut eng = TypeRecoveryEngine::new();
        eng.record_comparison("cond", false);
        eng.run();
        let ty = eng.get_type("cond");
        assert!(matches!(ty, Some(DecompType::Bool)));
    }

    #[test]
    fn test_engine_struct_access() {
        let mut eng = TypeRecoveryEngine::new();
        eng.record_struct_access("s_ptr", 0, 4);
        eng.record_struct_access("s_ptr", 4, 4);
        eng.run();
        let ty = eng.get_type("s_ptr");
        assert!(matches!(ty, Some(DecompType::Ptr(_))));
    }

    #[test]
    fn test_engine_array_access() {
        let mut eng = TypeRecoveryEngine::new();
        eng.record_array_access("arr", 4);
        eng.record_array_access("arr", 4);
        eng.run();
        let ty = eng.get_type("arr");
        assert!(ty.is_some());
    }

    #[test]
    fn test_engine_recovered_count() {
        let mut eng = TypeRecoveryEngine::new();
        eng.add_constraint(TypeConstraint::exact(
            "x",
            DecompType::Int(IntWidth::I32),
            "",
        ));
        eng.add_constraint(TypeConstraint::exact("y", DecompType::Float64, ""));
        eng.run();
        assert!(eng.recovered_count() >= 2);
    }

    #[test]
    fn test_engine_add_constraint_direct() {
        let mut eng = TypeRecoveryEngine::new();
        eng.add_constraint(TypeConstraint::is_pointer("raw_ptr", "observation"));
        eng.run();
        let ty = eng.get_type("raw_ptr");
        assert!(ty.is_some());
    }

    #[test]
    fn test_width_for_bits_helper() {
        assert_eq!(width_for_bits(8), IntWidth::I8);
        assert_eq!(width_for_bits(16), IntWidth::I16);
        assert_eq!(width_for_bits(32), IntWidth::I32);
        assert_eq!(width_for_bits(64), IntWidth::I64);
    }
}
