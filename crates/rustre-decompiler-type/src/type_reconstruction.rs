//! Type reconstruction from IL operations via constraint solving.
//!
//! Provides [`TypeReconstructor`], [`TypeConstraint`], [`ConstraintSolver`],
//! [`ReconstructedType`], and [`PointsToGraph`].

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ─── ReconstructedType ────────────────────────────────────────────────────────

/// A type inferred during reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReconstructedType {
    /// Unknown type (not yet inferred).
    Unknown,
    /// Void (used for function returns).
    Void,
    /// Boolean.
    Bool,
    /// Signed integer of specific bit width.
    Int(u8),
    /// Unsigned integer of specific bit width.
    UInt(u8),
    /// Floating point.
    Float(u8),
    /// Pointer to another type.
    Ptr(Box<Self>),
    /// Array of element type with optional count.
    Array(Box<Self>, Option<usize>),
    /// Struct by name.
    Struct(String),
    /// Function pointer.
    FuncPtr,
    /// Char type.
    Char,
    /// Char pointer (string).
    CStr,
    /// Ambiguous — multiple conflicting constraints.
    Ambiguous,
}

impl ReconstructedType {
    #[must_use] 
    pub fn byte_size(&self) -> Option<usize> {
        match self {
            Self::Bool
            | Self::Int(8)
            | Self::UInt(8)
            | Self::Char => Some(1),
            Self::Int(16) | Self::UInt(16) => Some(2),
            Self::Int(32)
            | Self::UInt(32)
            | Self::Float(32) => Some(4),
            Self::Int(64)
            | Self::UInt(64)
            | Self::Float(64) => Some(8),
            Self::Ptr(_) | Self::FuncPtr | Self::CStr => {
                Some(8)
            }
            Self::Array(elem, Some(n)) => elem.byte_size().and_then(|s| s.checked_mul(*n)),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn is_pointer(&self) -> bool {
        matches!(
            self,
            Self::Ptr(_) | Self::CStr | Self::FuncPtr
        )
    }

    #[must_use] 
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Int(_)
                | Self::UInt(_)
                | Self::Bool
                | Self::Char
        )
    }

    #[must_use] 
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float(_))
    }

    /// True if this type is more specific than Unknown.
    #[must_use] 
    pub const fn is_known(&self) -> bool {
        !matches!(
            self,
            Self::Unknown | Self::Ambiguous
        )
    }

    #[must_use] 
    pub fn display_name(&self) -> String {
        match self {
            Self::Unknown => "?".into(),
            Self::Void => "void".into(),
            Self::Bool => "bool".into(),
            Self::Int(w) => format!("int{w}"),
            Self::UInt(w) => format!("uint{w}"),
            Self::Float(w) => format!("float{w}"),
            Self::Ptr(inner) => format!("{}*", inner.display_name()),
            Self::Array(elem, Some(n)) => format!("{}[{n}]", elem.display_name()),
            Self::Array(elem, None) => format!("{}[]", elem.display_name()),
            Self::Struct(name) => format!("struct {name}"),
            Self::FuncPtr => "fn*".into(),
            Self::Char => "char".into(),
            Self::CStr => "char*".into(),
            Self::Ambiguous => "ambiguous".into(),
        }
    }
}

impl std::fmt::Display for ReconstructedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ─── TypeConstraint ───────────────────────────────────────────────────────────

/// A constraint on a variable's type derived from an IL operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeConstraint {
    /// Must be a pointer type.
    MustBePointer,
    /// Must be an integer (any width).
    MustBeInteger,
    /// Must be a floating-point type.
    MustBeFloat,
    /// Must be at least N bytes wide.
    SizeAtLeast(u8),
    /// Must be exactly N bits wide.
    ExactWidth(u8),
    /// Must be signed.
    Signed,
    /// Must be unsigned.
    Unsigned,
    /// Used in a boolean context (if/while condition).
    BoolContext,
    /// Dereferenced at offset (implies pointer or struct).
    Dereferenced,
    /// Points to a known struct.
    PointsToStruct(String),
    /// Is the same type as another variable.
    SameAs(String),
    /// Is used as a function argument at position N.
    FuncArg(usize),
    /// Is a return value.
    ReturnValue,
    /// Used in arithmetic (add/sub/mul).
    ArithmeticUse,
    /// Used in bitwise operation.
    BitwiseUse,
    /// Null-checked (implies pointer).
    NullChecked,
}

// ─── VariableId ───────────────────────────────────────────────────────────────

pub type VariableId = String;

// ─── ConstraintSet ────────────────────────────────────────────────────────────

/// All constraints collected for a single variable.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSet {
    pub constraints: Vec<TypeConstraint>,
}

impl ConstraintSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, c: TypeConstraint) {
        if !self.constraints.contains(&c) {
            self.constraints.push(c);
        }
    }

    #[must_use] 
    pub fn has(&self, c: &TypeConstraint) -> bool {
        self.constraints.contains(c)
    }

    #[must_use] 
    pub fn min_size(&self) -> u8 {
        self.constraints
            .iter()
            .filter_map(|c| {
                if let TypeConstraint::SizeAtLeast(n) = c {
                    Some(*n)
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(0)
    }

    #[must_use] 
    pub fn exact_width(&self) -> Option<u8> {
        self.constraints.iter().find_map(|c| {
            if let TypeConstraint::ExactWidth(w) = c {
                Some(*w)
            } else {
                None
            }
        })
    }
}

// ─── ConstraintSolver ─────────────────────────────────────────────────────────

/// Resolves a set of [`TypeConstraint`]s into a [`ReconstructedType`].
///
/// `Default` is already implemented manually below; we keep it off the
/// derive list via a never-active `cfg_attr` to avoid a duplicate impl.
#[cfg_attr(any(), derive(Default))]
#[derive(Debug, Clone, Copy)]
pub struct ConstraintSolver;

impl ConstraintSolver {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Solve constraints for a single variable.
    #[must_use] 
    pub fn solve(&self, cs: &ConstraintSet) -> ReconstructedType {
        let is_ptr = cs.has(&TypeConstraint::MustBePointer)
            || cs.has(&TypeConstraint::Dereferenced)
            || cs.has(&TypeConstraint::NullChecked);
        let is_float = cs.has(&TypeConstraint::MustBeFloat);
        let is_int = cs.has(&TypeConstraint::MustBeInteger)
            || cs.has(&TypeConstraint::ArithmeticUse)
            || cs.has(&TypeConstraint::BitwiseUse);
        let signed = cs.has(&TypeConstraint::Signed);
        let unsigned = cs.has(&TypeConstraint::Unsigned);

        // Conflict: both float and integer signals → ambiguous
        if is_float && is_int {
            return ReconstructedType::Ambiguous;
        }

        if is_ptr {
            // Check if points to known struct
            if let Some(TypeConstraint::PointsToStruct(name)) = cs
                .constraints
                .iter()
                .find(|c| matches!(c, TypeConstraint::PointsToStruct(_)))
            {
                return ReconstructedType::Ptr(Box::new(ReconstructedType::Struct(name.clone())));
            }
            return ReconstructedType::Ptr(Box::new(ReconstructedType::Unknown));
        }

        if is_float {
            let width = cs.exact_width().unwrap_or(64);
            return ReconstructedType::Float(width);
        }

        if is_int || cs.has(&TypeConstraint::BoolContext) {
            if cs.has(&TypeConstraint::BoolContext) && !is_int {
                return ReconstructedType::Bool;
            }
            let width = cs.exact_width().unwrap_or_else(|| {
                let min = cs.min_size();
                if min <= 32 {
                    32
                } else {
                    64
                }
            });
            if signed && !unsigned {
                return ReconstructedType::Int(width);
            }
            if unsigned && !signed {
                return ReconstructedType::UInt(width);
            }
            return ReconstructedType::Int(width);
        }

        ReconstructedType::Unknown
    }

    /// Solve all variables at once, propagating `SameAs` constraints.
    #[must_use] 
    pub fn solve_all(
        &self,
        var_constraints: &HashMap<VariableId, ConstraintSet>,
    ) -> HashMap<VariableId, ReconstructedType> {
        let mut result: HashMap<VariableId, ReconstructedType> = HashMap::new();

        // First pass: solve each individually
        for (var, cs) in var_constraints {
            result.insert(var.clone(), self.solve(cs));
        }

        // Second pass: propagate SameAs constraints
        for (var, cs) in var_constraints {
            for c in &cs.constraints {
                if let TypeConstraint::SameAs(other) = c {
                    let my_type = result
                        .get(var)
                        .cloned()
                        .unwrap_or(ReconstructedType::Unknown);
                    let other_type = result
                        .get(other)
                        .cloned()
                        .unwrap_or(ReconstructedType::Unknown);
                    let merged = self.merge(&my_type, &other_type);
                    result.insert(var.clone(), merged.clone());
                    result.insert(other.clone(), merged);
                }
            }
        }

        result
    }

    /// Merge two types: prefer the more specific one.
    #[must_use] 
    pub fn merge(&self, a: &ReconstructedType, b: &ReconstructedType) -> ReconstructedType {
        if a == b {
            return a.clone();
        }
        match (a, b) {
            (ReconstructedType::Unknown, other) | (other, ReconstructedType::Unknown) => {
                other.clone()
            }
            (ReconstructedType::Ambiguous, _) | (_, ReconstructedType::Ambiguous) => {
                ReconstructedType::Ambiguous
            }
            _ => {
                // Conflict → ambiguous
                if a.is_pointer() && b.is_pointer() {
                    return a.clone();
                }
                if a.is_integer() && b.is_integer() {
                    // Take wider
                    return a.clone();
                }
                ReconstructedType::Ambiguous
            }
        }
    }
}

impl Default for ConstraintSolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PointsToEdge ─────────────────────────────────────────────────────────────

/// An edge in the points-to graph: pointer variable → pointee variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointsToEdge {
    pub from: VariableId,
    pub to: VariableId,
    pub offset: i64,
}

// ─── PointsToGraph ────────────────────────────────────────────────────────────

/// Points-to graph: maps pointer variables to the variables/locations they may point to.
#[derive(Debug, Default)]
pub struct PointsToGraph {
    edges: Vec<PointsToEdge>,
    /// All variables that may be pointed to by at least one pointer.
    pointees: HashSet<VariableId>,
}

impl PointsToGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a "from points to to at offset" edge.
    pub fn add_edge(&mut self, from: VariableId, to: VariableId, offset: i64) {
        let edge = PointsToEdge {
            from,
            to: to.clone(),
            offset,
        };
        if !self.edges.contains(&edge) {
            self.pointees.insert(to);
            self.edges.push(edge);
        }
    }

    /// All variables that `var` may point to.
    #[must_use] 
    pub fn points_to(&self, var: &str) -> Vec<&PointsToEdge> {
        self.edges.iter().filter(|e| e.from == var).collect()
    }

    /// All variables that may point to `var`.
    #[must_use] 
    pub fn pointed_by(&self, var: &str) -> Vec<&PointsToEdge> {
        self.edges.iter().filter(|e| e.to == var).collect()
    }

    #[must_use] 
    pub fn is_pointer(&self, var: &str) -> bool {
        self.edges.iter().any(|e| e.from == var)
    }

    #[must_use] 
    pub fn is_pointee(&self, var: &str) -> bool {
        self.pointees.contains(var)
    }

    #[must_use] 
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// All reachable pointees of `var` (transitive closure).
    #[must_use] 
    pub fn reachable(&self, var: &str) -> Vec<VariableId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(var.to_string());
        let mut result = Vec::new();
        while let Some(v) = queue.pop_front() {
            for edge in self.points_to(&v) {
                if visited.insert(edge.to.clone()) {
                    result.push(edge.to.clone());
                    queue.push_back(edge.to.clone());
                }
            }
        }
        result
    }
}

// ─── TypeReconstructor ────────────────────────────────────────────────────────

/// Infers types for IL variables from operation patterns.
#[derive(Debug, Default)]
pub struct TypeReconstructor {
    /// Variable → collected constraints.
    var_constraints: HashMap<VariableId, ConstraintSet>,
    /// Points-to graph.
    points_to: PointsToGraph,
    solver: ConstraintSolver,
}

impl TypeReconstructor {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint for a variable.
    pub fn constrain(&mut self, var: &str, c: TypeConstraint) {
        self.var_constraints
            .entry(var.to_string())
            .or_default()
            .add(c);
    }

    /// Record a pointer assignment: `ptr_var` = &`target_var`.
    pub fn record_address_of(&mut self, ptr_var: &str, target_var: &str) {
        self.constrain(ptr_var, TypeConstraint::MustBePointer);
        self.points_to
            .add_edge(ptr_var.to_string(), target_var.to_string(), 0);
    }

    /// Record a field access: `ptr_var` + `offset` being accessed.
    pub fn record_field_access(&mut self, ptr_var: &str, offset: i64, field_var: &str) {
        self.constrain(ptr_var, TypeConstraint::MustBePointer);
        self.constrain(ptr_var, TypeConstraint::Dereferenced);
        self.points_to
            .add_edge(ptr_var.to_string(), field_var.to_string(), offset);
    }

    /// Record an arithmetic use.
    pub fn record_arithmetic(&mut self, var: &str) {
        self.constrain(var, TypeConstraint::MustBeInteger);
        self.constrain(var, TypeConstraint::ArithmeticUse);
    }

    /// Record a bitwise use.
    pub fn record_bitwise(&mut self, var: &str) {
        self.constrain(var, TypeConstraint::MustBeInteger);
        self.constrain(var, TypeConstraint::BitwiseUse);
    }

    /// Record a null check (implies pointer).
    pub fn record_null_check(&mut self, var: &str) {
        self.constrain(var, TypeConstraint::MustBePointer);
        self.constrain(var, TypeConstraint::NullChecked);
    }

    /// Record a float use.
    pub fn record_float_use(&mut self, var: &str, width: u8) {
        self.constrain(var, TypeConstraint::MustBeFloat);
        self.constrain(var, TypeConstraint::ExactWidth(width));
    }

    /// Record use as a boolean condition.
    pub fn record_bool_context(&mut self, var: &str) {
        self.constrain(var, TypeConstraint::BoolContext);
    }

    /// Record a signed arithmetic use.
    pub fn record_signed(&mut self, var: &str) {
        self.constrain(var, TypeConstraint::MustBeInteger);
        self.constrain(var, TypeConstraint::Signed);
    }

    /// Record an unsigned use.
    pub fn record_unsigned(&mut self, var: &str) {
        self.constrain(var, TypeConstraint::MustBeInteger);
        self.constrain(var, TypeConstraint::Unsigned);
    }

    /// Record that two variables share the same type.
    pub fn record_same_type(&mut self, a: &str, b: &str) {
        self.constrain(a, TypeConstraint::SameAs(b.to_string()));
        self.constrain(b, TypeConstraint::SameAs(a.to_string()));
    }

    /// Solve all constraints and return the inferred type map.
    #[must_use] 
    pub fn reconstruct(&self) -> HashMap<VariableId, ReconstructedType> {
        let mut result = self.solver.solve_all(&self.var_constraints);
        // Apply points-to graph: if var is a pointer, infer its pointee type
        for (var, ty) in &mut result {
            if matches!(ty, ReconstructedType::Ptr(inner) if matches!(**inner, ReconstructedType::Unknown))
            {
                let targets = self.points_to.points_to(var);
                // If all targets agree on a struct, specialize
                if let Some(first) = targets.first()
                    && let Some(struct_name) = Self::infer_struct_from_accesses(&first.to) {
                        *ty = ReconstructedType::Ptr(Box::new(ReconstructedType::Struct(
                            struct_name,
                        )));
                    }
            }
        }
        result
    }

    const fn infer_struct_from_accesses(_var: &str) -> Option<String> {
        // Placeholder: in a real implementation, look up struct candidates from the struct recoverer.
        None
    }

    /// All known variable names.
    #[must_use] 
    pub fn variables(&self) -> Vec<&VariableId> {
        self.var_constraints.keys().collect()
    }

    /// Constraints for a specific variable.
    #[must_use] 
    pub fn constraints_for(&self, var: &str) -> Option<&ConstraintSet> {
        self.var_constraints.get(var)
    }

    #[must_use] 
    pub const fn points_to_graph(&self) -> &PointsToGraph {
        &self.points_to
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_by_default() {
        let solver = ConstraintSolver::new();
        let cs = ConstraintSet::new();
        let ty = solver.solve(&cs);
        assert_eq!(ty, ReconstructedType::Unknown);
    }

    #[test]
    fn test_integer_constraint() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBeInteger);
        cs.add(TypeConstraint::ExactWidth(32));
        let ty = solver.solve(&cs);
        assert_eq!(ty, ReconstructedType::Int(32));
    }

    #[test]
    fn test_unsigned_constraint() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBeInteger);
        cs.add(TypeConstraint::Unsigned);
        cs.add(TypeConstraint::ExactWidth(64));
        let ty = solver.solve(&cs);
        assert_eq!(ty, ReconstructedType::UInt(64));
    }

    #[test]
    fn test_float_constraint() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBeFloat);
        cs.add(TypeConstraint::ExactWidth(64));
        let ty = solver.solve(&cs);
        assert_eq!(ty, ReconstructedType::Float(64));
    }

    #[test]
    fn test_pointer_constraint() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBePointer);
        let ty = solver.solve(&cs);
        assert!(ty.is_pointer());
    }

    #[test]
    fn test_conflict_float_int() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBeFloat);
        cs.add(TypeConstraint::MustBeInteger);
        let ty = solver.solve(&cs);
        assert_eq!(ty, ReconstructedType::Ambiguous);
    }

    #[test]
    fn test_bool_context() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::BoolContext);
        let ty = solver.solve(&cs);
        assert_eq!(ty, ReconstructedType::Bool);
    }

    #[test]
    fn test_pointer_to_struct() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBePointer);
        cs.add(TypeConstraint::PointsToStruct("Node".into()));
        let ty = solver.solve(&cs);
        assert_eq!(
            ty,
            ReconstructedType::Ptr(Box::new(ReconstructedType::Struct("Node".into())))
        );
    }

    #[test]
    fn test_type_reconstructor_arithmetic() {
        let mut r = TypeReconstructor::new();
        r.record_arithmetic("x");
        let types = r.reconstruct();
        let ty = types.get("x").unwrap();
        assert!(ty.is_integer());
    }

    #[test]
    fn test_type_reconstructor_float() {
        let mut r = TypeReconstructor::new();
        r.record_float_use("f", 64);
        let types = r.reconstruct();
        assert_eq!(types.get("f").unwrap(), &ReconstructedType::Float(64));
    }

    #[test]
    fn test_type_reconstructor_null_check() {
        let mut r = TypeReconstructor::new();
        r.record_null_check("ptr");
        let types = r.reconstruct();
        assert!(types.get("ptr").unwrap().is_pointer());
    }

    #[test]
    fn test_type_reconstructor_address_of() {
        let mut r = TypeReconstructor::new();
        r.record_address_of("p", "x");
        let types = r.reconstruct();
        assert!(types.get("p").unwrap().is_pointer());
    }

    #[test]
    fn test_points_to_graph_basic() {
        let mut g = PointsToGraph::new();
        g.add_edge("p".into(), "x".into(), 0);
        assert!(g.is_pointer("p"));
        assert!(g.is_pointee("x"));
    }

    #[test]
    fn test_points_to_transitive() {
        let mut g = PointsToGraph::new();
        g.add_edge("p".into(), "q".into(), 0);
        g.add_edge("q".into(), "r".into(), 0);
        let reachable = g.reachable("p");
        assert!(reachable.contains(&"q".to_string()));
        assert!(reachable.contains(&"r".to_string()));
    }

    #[test]
    fn test_points_to_pointed_by() {
        let mut g = PointsToGraph::new();
        g.add_edge("p".into(), "x".into(), 0);
        g.add_edge("q".into(), "x".into(), 0);
        assert_eq!(g.pointed_by("x").len(), 2);
    }

    #[test]
    fn test_solve_all_same_as() {
        let solver = ConstraintSolver::new();
        let mut vars: HashMap<VariableId, ConstraintSet> = HashMap::new();
        let mut cs_a = ConstraintSet::new();
        cs_a.add(TypeConstraint::MustBeInteger);
        cs_a.add(TypeConstraint::ExactWidth(32));
        cs_a.add(TypeConstraint::SameAs("b".into()));
        let cs_b = ConstraintSet::new();
        vars.insert("a".into(), cs_a);
        vars.insert("b".into(), cs_b);
        let result = solver.solve_all(&vars);
        // b should inherit a's type
        assert_eq!(result.get("b").unwrap(), &ReconstructedType::Int(32));
    }

    #[test]
    fn test_merge_unknown_with_known() {
        let solver = ConstraintSolver::new();
        let a = ReconstructedType::Unknown;
        let b = ReconstructedType::Int(32);
        assert_eq!(solver.merge(&a, &b), ReconstructedType::Int(32));
    }

    #[test]
    fn test_merge_same_types() {
        let solver = ConstraintSolver::new();
        let a = ReconstructedType::Int(32);
        let b = ReconstructedType::Int(32);
        assert_eq!(solver.merge(&a, &b), ReconstructedType::Int(32));
    }

    #[test]
    fn test_type_display() {
        assert_eq!(ReconstructedType::Int(32).to_string(), "int32");
        assert_eq!(ReconstructedType::UInt(64).to_string(), "uint64");
        assert_eq!(
            ReconstructedType::Ptr(Box::new(ReconstructedType::Int(32))).to_string(),
            "int32*"
        );
        assert_eq!(
            ReconstructedType::Struct("Node".into()).to_string(),
            "struct Node"
        );
        assert_eq!(ReconstructedType::Unknown.to_string(), "?");
    }

    #[test]
    fn test_reconstructed_type_is_pointer() {
        assert!(ReconstructedType::Ptr(Box::new(ReconstructedType::Unknown)).is_pointer());
        assert!(ReconstructedType::CStr.is_pointer());
        assert!(!ReconstructedType::Int(32).is_pointer());
    }

    #[test]
    fn test_reconstructed_type_byte_size() {
        assert_eq!(ReconstructedType::Int(32).byte_size(), Some(4));
        assert_eq!(ReconstructedType::Float(64).byte_size(), Some(8));
        assert_eq!(ReconstructedType::Bool.byte_size(), Some(1));
        assert_eq!(
            ReconstructedType::Ptr(Box::new(ReconstructedType::Unknown)).byte_size(),
            Some(8)
        );
    }

    #[test]
    fn test_constraint_set_min_size() {
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::SizeAtLeast(4));
        cs.add(TypeConstraint::SizeAtLeast(8));
        assert_eq!(cs.min_size(), 8);
    }

    #[test]
    fn test_constraint_set_exact_width() {
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::ExactWidth(64));
        assert_eq!(cs.exact_width(), Some(64));
    }

    #[test]
    fn test_type_reconstructor_variables() {
        let mut r = TypeReconstructor::new();
        r.record_arithmetic("a");
        r.record_float_use("b", 32);
        let vars = r.variables();
        assert!(vars.contains(&&"a".to_string()));
        assert!(vars.contains(&&"b".to_string()));
    }

    #[test]
    fn test_constraint_has() {
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBePointer);
        assert!(cs.has(&TypeConstraint::MustBePointer));
        assert!(!cs.has(&TypeConstraint::MustBeFloat));
    }

    #[test]
    fn test_type_reconstructor_bitwise() {
        let mut r = TypeReconstructor::new();
        r.record_bitwise("flags");
        let types = r.reconstruct();
        assert!(types.get("flags").unwrap().is_integer());
    }

    #[test]
    fn test_type_reconstructor_signed() {
        let mut r = TypeReconstructor::new();
        r.record_signed("count");
        let types = r.reconstruct();
        if let ReconstructedType::Int(_) = types.get("count").unwrap() {
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_type_reconstructor_unsigned() {
        let mut r = TypeReconstructor::new();
        r.record_unsigned("size");
        let types = r.reconstruct();
        if let ReconstructedType::UInt(_) = types.get("size").unwrap() {
        } else {
            panic!("expected UInt");
        }
    }

    #[test]
    fn test_points_to_edge_count() {
        let mut g = PointsToGraph::new();
        g.add_edge("p".into(), "x".into(), 0);
        g.add_edge("p".into(), "y".into(), 8);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_points_to_graph_no_self_loop_duplicate() {
        let mut g = PointsToGraph::new();
        g.add_edge("p".into(), "x".into(), 0);
        g.add_edge("p".into(), "x".into(), 0); // duplicate
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_reconstructed_type_is_float() {
        assert!(ReconstructedType::Float(32).is_float());
        assert!(!ReconstructedType::Int(32).is_float());
    }

    #[test]
    fn test_reconstructed_type_is_known() {
        assert!(ReconstructedType::Int(32).is_known());
        assert!(!ReconstructedType::Unknown.is_known());
        assert!(!ReconstructedType::Ambiguous.is_known());
    }

    #[test]
    fn test_reconstructed_type_array_size() {
        let ty = ReconstructedType::Array(Box::new(ReconstructedType::Int(32)), Some(4));
        assert_eq!(ty.byte_size(), Some(16));
    }

    #[test]
    fn test_constraint_solver_no_constraints() {
        let solver = ConstraintSolver::new();
        let cs = ConstraintSet::new();
        assert_eq!(solver.solve(&cs), ReconstructedType::Unknown);
    }

    #[test]
    fn test_reconstruct_empty_gives_empty_map() {
        let r = TypeReconstructor::new();
        let types = r.reconstruct();
        assert!(types.is_empty());
    }

    #[test]
    fn test_type_display_cstr() {
        assert_eq!(ReconstructedType::CStr.to_string(), "char*");
    }

    #[test]
    fn test_type_display_func_ptr() {
        assert_eq!(ReconstructedType::FuncPtr.to_string(), "fn*");
    }

    #[test]
    fn test_constraint_set_no_exact_width() {
        let cs = ConstraintSet::new();
        assert_eq!(cs.exact_width(), None);
    }

    #[test]
    fn test_solver_signed_over_unsigned() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBeInteger);
        cs.add(TypeConstraint::Signed);
        cs.add(TypeConstraint::Unsigned); // conflict → stays signed (signed wins)
        let ty = solver.solve(&cs);
        // Both signed+unsigned → defaults to Int
        assert!(ty.is_integer());
    }

    #[test]
    fn test_points_to_graph_not_pointer_for_unknown() {
        let g = PointsToGraph::new();
        assert!(!g.is_pointer("nobody"));
    }

    #[test]
    fn test_points_to_graph_not_pointee_for_unknown() {
        let g = PointsToGraph::new();
        assert!(!g.is_pointee("nobody"));
    }

    #[test]
    fn test_reconstructed_type_char() {
        let ty = ReconstructedType::Char;
        assert_eq!(ty.byte_size(), Some(1));
        assert!(ty.is_integer());
    }

    #[test]
    fn test_reconstructed_type_void() {
        let ty = ReconstructedType::Void;
        assert_eq!(ty.to_string(), "void");
        // Void is more specific than Unknown/Ambiguous, so is_known() is true.
        // (The previous assertion contradicted its own comment.)
        assert!(ty.is_known());
    }

    #[test]
    fn test_constraint_set_duplicate_not_added() {
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBePointer);
        cs.add(TypeConstraint::MustBePointer);
        assert_eq!(cs.constraints.len(), 1);
    }

    #[test]
    fn test_merge_both_ambiguous() {
        let solver = ConstraintSolver::new();
        let a = ReconstructedType::Ambiguous;
        let b = ReconstructedType::Int(32);
        let result = solver.merge(&a, &b);
        assert_eq!(result, ReconstructedType::Ambiguous);
    }

    #[test]
    fn test_type_reconstructor_func_arg() {
        let mut r = TypeReconstructor::new();
        r.constrain("arg0", TypeConstraint::FuncArg(0));
        r.constrain("arg0", TypeConstraint::MustBeInteger);
        let types = r.reconstruct();
        assert!(types.get("arg0").unwrap().is_integer());
    }

    #[test]
    fn test_reconstructed_type_array_no_size() {
        let ty = ReconstructedType::Array(Box::new(ReconstructedType::Int(8)), None);
        assert_eq!(ty.byte_size(), None);
        assert_eq!(ty.to_string(), "int8[]");
    }

    #[test]
    fn test_void_is_known() {
        // Void is a valid, known type
        assert!(ReconstructedType::Void.is_known());
    }

    #[test]
    fn test_bool_is_integer() {
        assert!(ReconstructedType::Bool.is_integer());
    }

    #[test]
    fn test_constraint_return_value() {
        let mut r = TypeReconstructor::new();
        r.constrain("ret", TypeConstraint::ReturnValue);
        r.constrain("ret", TypeConstraint::MustBeInteger);
        let types = r.reconstruct();
        assert!(types.get("ret").unwrap().is_integer());
    }

    #[test]
    fn test_solver_size_at_least_promotes_width() {
        let solver = ConstraintSolver::new();
        let mut cs = ConstraintSet::new();
        cs.add(TypeConstraint::MustBeInteger);
        cs.add(TypeConstraint::SizeAtLeast(4));
        let ty = solver.solve(&cs);
        // min_size=4 bytes → 32-bit int
        if let ReconstructedType::Int(w) = ty {
            assert!(w >= 32);
        } else {
            panic!("expected Int");
        }
    }
}
