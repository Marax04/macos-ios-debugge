//! `type_flow_lattice` — Lattice-based type propagation through IR basic blocks.
//!
//! Implements a fixed-point dataflow analysis that propagates type information
//! forward through a simplified IR representation (assignment graphs and
//! phi-nodes). The lattice has three levels:
//!
//! ```text
//!   ⊤  (Top   — no information)
//!   T  (a concrete DecompType)
//!   ⊥  (Bottom — conflicting information / Unknown)
//! ```
//!
//! Key types:
//! - [`TypeLatticeValue`] — one element of the lattice
//! - [`TypeSolution`] — result of a fixed-point solve (var → type)
//! - [`TypeConstraint`] — an equality / subtype constraint between variables
//! - [`propagate_fixed_point`] — the main solver entry-point

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{DecompType, StructType};
use rustre_decompiler_expr::IntWidth;

// ─── TypeLatticeValue ────────────────────────────────────────────────────────

/// A value in the type lattice.
///
/// Ordering: `Top ≤ Concrete(_) ≤ Bottom`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum TypeLatticeValue {
    /// No type information available yet.
    #[default]
    Top,
    /// A known concrete type.
    Concrete(DecompType),
    /// Conflicting type assignments — degenerated to Unknown.
    Bottom,
}

impl TypeLatticeValue {
    /// Meet (greatest lower bound) of two lattice values.
    ///
    /// - Top ⊓ x = x
    /// - Bottom ⊓ _ = Bottom
    /// - Concrete(T) ⊓ Concrete(T) = Concrete(T)
    /// - Concrete(T) ⊓ Concrete(U) = Bottom  (unless one is Unknown)
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Concrete(a), Self::Concrete(b)) => {
                if a == b {
                    Self::Concrete(a.clone())
                } else if *a == DecompType::Unknown {
                    Self::Concrete(b.clone())
                } else if *b == DecompType::Unknown {
                    Self::Concrete(a.clone())
                } else {
                    Self::Bottom
                }
            }
        }
    }

    /// Join (least upper bound) of two lattice values.
    ///
    /// - Top ⊔ x = Top
    /// - Bottom ⊔ x = x
    /// - Concrete(T) ⊔ Concrete(T) = Concrete(T)
    /// - Concrete(T) ⊔ Concrete(U) = Top  (widening)
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Concrete(a), Self::Concrete(b)) => {
                if a == b {
                    Self::Concrete(a.clone())
                } else {
                    Self::Top
                }
            }
        }
    }

    /// Whether this lattice value contains concrete type information.
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        matches!(self, Self::Concrete(_))
    }

    /// Extract the concrete type, if any.
    #[must_use]
    pub const fn concrete_type(&self) -> Option<&DecompType> {
        match self {
            Self::Concrete(t) => Some(t),
            _ => None,
        }
    }
}


// ─── TypeConstraint (lattice form) ───────────────────────────────────────────

/// A constraint between a destination variable and a source expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowConstraint {
    /// `dst = src` — propagate type from `src` to `dst`.
    Assign { dst: String, src: String },
    /// `dst = const` — `dst` has a known integer type.
    AssignConst { dst: String, ty: DecompType },
    /// `dst = phi(src1, src2, …)` — meet all source types.
    Phi { dst: String, sources: Vec<String> },
    /// `dst = *ptr` — dereference: dst gets pointee type of ptr.
    Deref { dst: String, ptr: String },
    /// `dst = &src` — address-of: dst gets `Ptr(typeof(src))`.
    AddrOf { dst: String, src: String },
    /// `dst = src + const_offset` — field access hint.
    FieldHint { dst: String, src: String, offset: u64 },
    /// `dst = cast(src, width)` — explicit integer cast.
    Cast { dst: String, src: String, width: IntWidth },
    /// `dst = binop(lhs, rhs)` — arithmetic: dst gets type of lhs.
    BinOp { dst: String, lhs: String, rhs: String },
}

impl FlowConstraint {
    /// Return the destination variable name.
    #[must_use]
    pub fn dst(&self) -> &str {
        match self {
            Self::Assign { dst, .. }
            | Self::AssignConst { dst, .. }
            | Self::Phi { dst, .. }
            | Self::Deref { dst, .. }
            | Self::AddrOf { dst, .. }
            | Self::FieldHint { dst, .. }
            | Self::Cast { dst, .. }
            | Self::BinOp { dst, .. } => dst,
        }
    }

    /// Collect all source variable names referenced by this constraint.
    #[must_use]
    pub fn sources(&self) -> Vec<&str> {
        match self {
            Self::AssignConst { .. } => vec![],
            Self::Phi { sources, .. } => sources.iter().map(String::as_str).collect(),
            Self::Deref { ptr, .. } => vec![ptr],
            Self::Assign { src, .. } | Self::AddrOf { src, .. } | Self::FieldHint { src, .. } | Self::Cast { src, .. } => vec![src],
            Self::BinOp { lhs, rhs, .. } => vec![lhs, rhs],
        }
    }
}

// ─── TypeSolution ─────────────────────────────────────────────────────────────

/// The result of a fixed-point type propagation solve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeSolution {
    /// Variable → resolved lattice value.
    pub values: HashMap<String, TypeLatticeValue>,
    /// Number of iterations required to reach fixed point.
    pub iterations: usize,
    /// Variables for which the solver could not determine a concrete type.
    pub unresolved: Vec<String>,
}

impl TypeSolution {
    /// Look up the resolved type for a variable.
    #[must_use]
    pub fn resolved_type(&self, var: &str) -> Option<&DecompType> {
        self.values.get(var)?.concrete_type()
    }

    /// Whether `var` has been resolved to a concrete type.
    #[must_use]
    pub fn is_resolved(&self, var: &str) -> bool {
        matches!(
            self.values.get(var),
            Some(TypeLatticeValue::Concrete(_))
        )
    }

    /// Number of variables with a concrete type.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.values
            .values()
            .filter(|v| v.is_concrete())
            .count()
    }

    /// Total number of variables tracked.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.values.len()
    }

    /// Coverage ratio: resolved / total.
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.values.is_empty() {
            return 1.0;
        }
        f64::from(u32::try_from(self.resolved_count().min(u32::MAX as usize)).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total_count().min(u32::MAX as usize)).unwrap_or(u32::MAX))
    }

    /// All resolved variable → type pairs.
    #[must_use]
    pub fn resolved_pairs(&self) -> Vec<(&String, &DecompType)> {
        self.values
            .iter()
            .filter_map(|(k, v)| v.concrete_type().map(|t| (k, t)))
            .collect()
    }
}

// ─── propagate_fixed_point ────────────────────────────────────────────────────

/// Solve a system of [`FlowConstraint`]s to a fixed point.
///
/// Seeds the lattice from `initial_types` and then iteratively applies
/// the constraints in worklist order until no more changes occur.
///
/// Returns a [`TypeSolution`] containing the final lattice state.
///
/// # Panics
///
/// Panics if the worklist is non-empty but `pop_front` returns `None`
/// (which cannot happen in practice).
#[must_use]
pub fn propagate_fixed_point<S1: ::std::hash::BuildHasher, S2: ::std::hash::BuildHasher>(
    constraints: &[FlowConstraint],
    initial_types: &HashMap<String, DecompType, S1>,
    struct_registry: &HashMap<String, StructType, S2>,
) -> TypeSolution {
    // Initialize lattice from seeds.
    let mut lattice: HashMap<String, TypeLatticeValue> = HashMap::new();
    for (var, ty) in initial_types {
        lattice.insert(var.clone(), TypeLatticeValue::Concrete(ty.clone()));
    }

    // Worklist: all variable names to process.
    let all_vars: HashSet<String> = constraints
        .iter()
        .flat_map(|c| {
            let mut v = vec![c.dst().to_string()];
            v.extend(c.sources().iter().map(std::string::ToString::to_string));
            v
        })
        .collect();

    let mut worklist: VecDeque<String> = all_vars.into_iter().collect();
    // Track which variables are already in the worklist so membership checks
    // are O(1) instead of the O(n) VecDeque::contains scan.  Without this a
    // constraint graph with N variables and M constraints causes O(N·M) work
    // per iteration, making the overall solve O(N²·M) — a DoS amplifier for
    // attacker-controlled input sizes.
    let mut in_worklist: HashSet<String> = worklist.iter().cloned().collect();
    let mut iterations = 0usize;

    while !worklist.is_empty() {
        iterations += 1;
        if iterations > 10_000 {
            // Safety valve against divergence.
            break;
        }

        let var = worklist.pop_front().unwrap();
        in_worklist.remove(&var);

        // Find all constraints that write to `var`.
        let relevant: Vec<&FlowConstraint> =
            constraints.iter().filter(|c| c.dst() == var).collect();

        for constraint in relevant {
            let new_val = evaluate_constraint(constraint, &lattice, struct_registry);
            let current = lattice.entry(var.clone()).or_insert(TypeLatticeValue::Top);
            let met = current.meet(&new_val);
            if met != *current {
                *current = met;
                // Re-add all variables that depend on `var`.
                for c in constraints {
                    if c.sources().contains(&var.as_str()) {
                        let dep = c.dst().to_string();
                        if !in_worklist.contains(&dep) {
                            in_worklist.insert(dep.clone());
                            worklist.push_back(dep);
                        }
                    }
                }
            }
        }
    }

    let unresolved: Vec<String> = lattice
        .iter()
        .filter_map(|(k, v)| {
            if v.is_concrete() {
                None
            } else {
                Some(k.clone())
            }
        })
        .collect();

    TypeSolution {
        values: lattice,
        iterations,
        unresolved,
    }
}

/// Evaluate a single `FlowConstraint` against the current lattice state.
fn evaluate_constraint<S1: ::std::hash::BuildHasher, S2: ::std::hash::BuildHasher>(
    c: &FlowConstraint,
    lattice: &HashMap<String, TypeLatticeValue, S1>,
    structs: &HashMap<String, StructType, S2>,
) -> TypeLatticeValue {
    let lookup = |var: &str| {
        lattice
            .get(var)
            .cloned()
            .unwrap_or(TypeLatticeValue::Top)
    };

    match c {
        FlowConstraint::Assign { src, .. } => lookup(src),

        FlowConstraint::AssignConst { ty, .. } => TypeLatticeValue::Concrete(ty.clone()),

        FlowConstraint::Phi { sources, .. } => {
            sources
                .iter()
                .map(|s| lookup(s))
                .fold(TypeLatticeValue::Bottom, |acc, v| acc.join(&v))
        }

        FlowConstraint::Deref { ptr, .. } => {
            match lookup(ptr) {
                TypeLatticeValue::Concrete(DecompType::Ptr(inner)) => {
                    TypeLatticeValue::Concrete(*inner)
                }
                TypeLatticeValue::Concrete(DecompType::CStr) => {
                    TypeLatticeValue::Concrete(DecompType::Int(IntWidth::U8))
                }
                TypeLatticeValue::Top => TypeLatticeValue::Top,
                TypeLatticeValue::Bottom | TypeLatticeValue::Concrete(_) => TypeLatticeValue::Bottom,
            }
        }

        FlowConstraint::AddrOf { src, .. } => {
            match lookup(src) {
                TypeLatticeValue::Concrete(t) => {
                    TypeLatticeValue::Concrete(DecompType::Ptr(Box::new(t)))
                }
                TypeLatticeValue::Top => TypeLatticeValue::Top,
                TypeLatticeValue::Bottom => TypeLatticeValue::Bottom,
            }
        }

        FlowConstraint::FieldHint { src, offset, .. } => {
            match lookup(src) {
                TypeLatticeValue::Concrete(DecompType::Ptr(inner)) => {
                    if let DecompType::Struct(st) = *inner {
                        if let Some(field) = st.field_exact(*offset) {
                            return TypeLatticeValue::Concrete(field.ty.clone());
                        }
                        // Try by name from registry
                        if let Some(reg_st) = structs.get(&st.name)
                            && let Some(field) = reg_st.field_exact(*offset) {
                                return TypeLatticeValue::Concrete(field.ty.clone());
                            }
                    }
                    TypeLatticeValue::Bottom
                }
                TypeLatticeValue::Top => TypeLatticeValue::Top,
                TypeLatticeValue::Bottom | TypeLatticeValue::Concrete(_) => TypeLatticeValue::Bottom,
            }
        }

        FlowConstraint::Cast { width, .. } => {
            TypeLatticeValue::Concrete(DecompType::Int(*width))
        }

        FlowConstraint::BinOp { lhs, rhs, .. } => {
            // Arithmetic: prefer pointer type if either operand is a pointer.
            let lhs_v = lookup(lhs);
            let rhs_v = lookup(rhs);
            match (&lhs_v, &rhs_v) {
                (TypeLatticeValue::Concrete(l), _) if l.is_pointer() => lhs_v.clone(),
                (_, TypeLatticeValue::Concrete(r)) if r.is_pointer() => rhs_v.clone(),
                _ => lhs_v.meet(&rhs_v),
            }
        }
    }
}

// ─── LatticePropagator ────────────────────────────────────────────────────────

/// A convenience wrapper around `propagate_fixed_point` that manages the
/// constraint set and struct registry incrementally.
#[derive(Debug, Default)]
pub struct LatticePropagator {
    constraints: Vec<FlowConstraint>,
    seeds: HashMap<String, DecompType>,
    struct_registry: HashMap<String, StructType>,
}

impl LatticePropagator {
    /// Create an empty propagator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a variable with a known type.
    pub fn seed(&mut self, var: impl Into<String>, ty: DecompType) {
        self.seeds.insert(var.into(), ty);
    }

    /// Add a flow constraint.
    pub fn add_constraint(&mut self, c: FlowConstraint) {
        self.constraints.push(c);
    }

    /// Register a struct type for field resolution.
    pub fn add_struct(&mut self, st: StructType) {
        self.struct_registry.insert(st.name.clone(), st);
    }

    /// Run the fixed-point solver and return the solution.
    #[must_use]
    pub fn solve(&self) -> TypeSolution {
        propagate_fixed_point(&self.constraints, &self.seeds, &self.struct_registry)
    }

    /// Number of constraints.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// Number of seeds.
    #[must_use]
    pub fn seed_count(&self) -> usize {
        self.seeds.len()
    }
}

// ─── LatticeDebugger ─────────────────────────────────────────────────────────

/// Renders the current lattice state as a human-readable table for debugging.
pub struct LatticeDebugger;

impl LatticeDebugger {
    /// Produce a formatted table from a `TypeSolution`.
    #[must_use]
    pub fn render(solution: &TypeSolution) -> String {
        let mut pairs: Vec<(&String, &TypeLatticeValue)> = solution.values.iter().collect();
        pairs.sort_by_key(|(a, _)| *a);

        let mut out = format!(
            "=== Lattice Solution (iterations={}, resolved={}/{}) ===\n",
            solution.iterations,
            solution.resolved_count(),
            solution.total_count()
        );
        writeln!(out, "{:32}  Type", "Variable").unwrap();
        out.push_str(&"-".repeat(60));
        out.push('\n');
        for (var, val) in &pairs {
            let ty_str = match val {
                TypeLatticeValue::Top => "⊤ (unresolved)".to_string(),
                TypeLatticeValue::Bottom => "⊥ (conflict)".to_string(),
                TypeLatticeValue::Concrete(t) => t.c_name(),
            };
            writeln!(out, "{var:32}  {ty_str}").unwrap();
        }
        out
    }
}

// ─── ConstraintGraphBuilder ───────────────────────────────────────────────────

/// Builds a set of `FlowConstraint`s from a simple assignment list.
#[derive(Debug, Default)]
pub struct ConstraintGraphBuilder {
    constraints: Vec<FlowConstraint>,
}

impl ConstraintGraphBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `dst = src`.
    pub fn assign(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.constraints.push(FlowConstraint::Assign {
            dst: dst.into(),
            src: src.into(),
        });
    }

    /// Add `dst = constant_of_type(ty)`.
    pub fn assign_const(&mut self, dst: impl Into<String>, ty: DecompType) {
        self.constraints.push(FlowConstraint::AssignConst {
            dst: dst.into(),
            ty,
        });
    }

    /// Add `dst = phi(sources…)`.
    pub fn phi(&mut self, dst: impl Into<String>, sources: Vec<String>) {
        self.constraints.push(FlowConstraint::Phi {
            dst: dst.into(),
            sources,
        });
    }

    /// Add `dst = *ptr`.
    pub fn deref(&mut self, dst: impl Into<String>, ptr: impl Into<String>) {
        self.constraints.push(FlowConstraint::Deref {
            dst: dst.into(),
            ptr: ptr.into(),
        });
    }

    /// Add `dst = &src`.
    pub fn addr_of(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.constraints.push(FlowConstraint::AddrOf {
            dst: dst.into(),
            src: src.into(),
        });
    }

    /// Add `dst = (width) src`.
    pub fn cast(&mut self, dst: impl Into<String>, src: impl Into<String>, width: IntWidth) {
        self.constraints.push(FlowConstraint::Cast {
            dst: dst.into(),
            src: src.into(),
            width,
        });
    }

    /// Finish building and return the constraint list.
    #[must_use]
    pub fn build(self) -> Vec<FlowConstraint> {
        self.constraints
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StructField, StructType};

    fn int32() -> DecompType {
        DecompType::Int(IntWidth::I32)
    }
    fn ptr_int32() -> DecompType {
        DecompType::Ptr(Box::new(int32()))
    }

    #[test]
    fn test_lattice_meet_top() {
        let t = TypeLatticeValue::Top;
        let c = TypeLatticeValue::Concrete(int32());
        assert_eq!(t.meet(&c), c);
        assert_eq!(c.meet(&t), c);
    }

    #[test]
    fn test_lattice_meet_same_concrete() {
        let a = TypeLatticeValue::Concrete(int32());
        let b = TypeLatticeValue::Concrete(int32());
        assert_eq!(a.meet(&b), a);
    }

    #[test]
    fn test_lattice_meet_different_concrete() {
        let a = TypeLatticeValue::Concrete(int32());
        let b = TypeLatticeValue::Concrete(DecompType::Float32);
        assert_eq!(a.meet(&b), TypeLatticeValue::Bottom);
    }

    #[test]
    fn test_lattice_meet_unknown_lhs() {
        let a = TypeLatticeValue::Concrete(DecompType::Unknown);
        let b = TypeLatticeValue::Concrete(int32());
        assert_eq!(a.meet(&b), b);
    }

    #[test]
    fn test_lattice_join() {
        let a = TypeLatticeValue::Concrete(int32());
        let b = TypeLatticeValue::Concrete(int32());
        assert_eq!(a.join(&b), a);
        let c = TypeLatticeValue::Concrete(DecompType::Float32);
        assert_eq!(a.join(&c), TypeLatticeValue::Top);
    }

    #[test]
    fn test_propagate_assign() {
        let mut seeds = HashMap::new();
        seeds.insert("x".to_string(), int32());
        let constraints = vec![FlowConstraint::Assign {
            dst: "y".to_string(),
            src: "x".to_string(),
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        assert_eq!(sol.resolved_type("y"), Some(&int32()));
    }

    #[test]
    fn test_propagate_deref() {
        let mut seeds = HashMap::new();
        seeds.insert("p".to_string(), ptr_int32());
        let constraints = vec![FlowConstraint::Deref {
            dst: "v".to_string(),
            ptr: "p".to_string(),
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        assert_eq!(sol.resolved_type("v"), Some(&int32()));
    }

    #[test]
    fn test_propagate_addr_of() {
        let mut seeds = HashMap::new();
        seeds.insert("v".to_string(), int32());
        let constraints = vec![FlowConstraint::AddrOf {
            dst: "p".to_string(),
            src: "v".to_string(),
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        assert_eq!(sol.resolved_type("p"), Some(&ptr_int32()));
    }

    #[test]
    fn test_propagate_cast() {
        let seeds = HashMap::new();
        let constraints = vec![FlowConstraint::Cast {
            dst: "c".to_string(),
            src: "x".to_string(),
            width: IntWidth::U8,
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        assert_eq!(
            sol.resolved_type("c"),
            Some(&DecompType::Int(IntWidth::U8))
        );
    }

    #[test]
    fn test_propagate_phi() {
        let mut seeds = HashMap::new();
        seeds.insert("a".to_string(), int32());
        seeds.insert("b".to_string(), int32());
        let constraints = vec![FlowConstraint::Phi {
            dst: "phi_out".to_string(),
            sources: vec!["a".to_string(), "b".to_string()],
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        assert_eq!(sol.resolved_type("phi_out"), Some(&int32()));
    }

    #[test]
    fn test_propagate_conflict_phi() {
        let mut seeds = HashMap::new();
        seeds.insert("a".to_string(), int32());
        seeds.insert("b".to_string(), DecompType::Float32);
        let constraints = vec![FlowConstraint::Phi {
            dst: "phi_out".to_string(),
            sources: vec!["a".to_string(), "b".to_string()],
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        // Should resolve to Top (join of conflicting concrete types)
        assert_eq!(
            sol.values.get("phi_out"),
            Some(&TypeLatticeValue::Top)
        );
    }

    #[test]
    fn test_solution_coverage_ratio() {
        let mut seeds = HashMap::new();
        seeds.insert("a".to_string(), int32());
        let constraints = vec![
            FlowConstraint::Assign {
                dst: "b".to_string(),
                src: "a".to_string(),
            },
            FlowConstraint::AssignConst {
                dst: "c".to_string(),
                ty: DecompType::Float32,
            },
        ];
        let sol = propagate_fixed_point(&constraints, &seeds, &HashMap::new());
        assert!(sol.coverage_ratio() > 0.0);
    }

    #[test]
    fn test_lattice_propagator_builder() {
        let mut prop = LatticePropagator::new();
        prop.seed("ptr", ptr_int32());
        prop.add_constraint(FlowConstraint::Deref {
            dst: "val".to_string(),
            ptr: "ptr".to_string(),
        });
        let sol = prop.solve();
        assert_eq!(sol.resolved_type("val"), Some(&int32()));
    }

    #[test]
    fn test_constraint_graph_builder() {
        let mut builder = ConstraintGraphBuilder::new();
        builder.assign("y", "x");
        builder.assign_const("z", int32());
        let cs = builder.build();
        assert_eq!(cs.len(), 2);
    }

    #[test]
    fn test_field_hint_constraint() {
        let st = StructType::new(
            "Foo",
            vec![StructField::new(0, "a", int32()), StructField::new(4, "b", DecompType::Float32)],
            8,
        );
        let mut seeds = HashMap::new();
        seeds.insert(
            "p".to_string(),
            DecompType::Ptr(Box::new(DecompType::Struct(Box::new(st.clone())))),
        );
        let mut structs = HashMap::new();
        structs.insert(st.name.clone(), st);

        let constraints = vec![FlowConstraint::FieldHint {
            dst: "field_b".to_string(),
            src: "p".to_string(),
            offset: 4,
        }];
        let sol = propagate_fixed_point(&constraints, &seeds, &structs);
        assert_eq!(sol.resolved_type("field_b"), Some(&DecompType::Float32));
    }
}
