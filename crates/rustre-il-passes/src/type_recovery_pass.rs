//! Type recovery IR pass for `rustre-il-passes`.
//!
//! # Overview
//!
//! Type recovery is a two-phase fixed-point analysis that infers C-like type
//! information for every register and temporary seen in an LLIL function:
//!
//! ## Phase 1 —" Constraint Collection
//!
//! [`TypeConstraintCollector`] walks each [`LlilInstruction`] in the function
//! and emits a [`TypeConstraint`] for every register whose type can be narrowed:
//!
//! * A `SetReg { size: DWord }` implies the destination holds a 32-bit value.
//! * A register used as a `Load` address is annotated as a pointer.
//! * A register used in a `Store` address is annotated as a pointer.
//! * A register used as a `CondJump` condition is annotated as a 1-bit bool.
//! * A register assigned the result of a float op is annotated as `float32`
//!   or `float64`.
//!
//! ## Phase 2 —" Solving
//!
//! [`TypeSolver`] unifies all constraints using a worklist algorithm on the
//! type lattice:
//!
//! ```text
//! Unknown  âŠ'  Integral{N}  âŠ'  SignedInt{N}  âŠ'  Conflict
//!                          âŠ'  UnsignedInt{N} âŠ'  Conflict
//! Unknown  âŠ'  Float32                        âŠ'  Conflict
//! Unknown  âŠ'  Pointer(—¦)                     âŠ'  Conflict
//! ```
//!
//! When two incompatible constraints are joined (e.g. `Float32` with
//! `SignedInt{32}`), the result is [`PropagatedType::Conflict`].
//!
//! ## Phase 3 —" Annotation
//!
//! [`TypeAnnotator`] stores the solved types in a [`TypePassResult`] keyed by
//! register name.  The result is consumed by later passes (struct-layout
//! recovery, call-convention analysis, pseudocode generation).
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut pass = TypeRecoveryPass::new_64();
//! let result = pass.run(&func);
//! for reg in result.pointers() {
//!     println!("{reg} is a pointer");
//! }
//! ```
//!
//! [`TypeRecoveryPass`] is a two-phase analysis:
//!
//! 1. **Collection** —" [`TypeConstraintCollector`] walks every LLIL instruction
//!    and infers type constraints (e.g. "register `rax` holds a pointer because
//!    it is used as a load address").
//! 2. **Solving** —" [`TypeSolver`] unifies the constraints into concrete
//!    [`PropagatedType`]s using a union-find lattice.
//! 3. **Annotation** —" [`TypeAnnotator`] stores the resolved types back into a
//!    [`TypePassResult`] keyed by variable name.

use std::collections::HashMap;

pub use std::collections::{HashSet, VecDeque};
use std::fmt;

use rustre_core::address::Address;
use rustre_il_llil::{
    LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size,
};

// ---------------------------------------------------------------------------
// Type width constants
// ---------------------------------------------------------------------------

/// Bit-widths used throughout the type system.
pub mod widths {
    pub const W1: u32 = 1;
    pub const W8: u32 = 8;
    pub const W16: u32 = 16;
    pub const W32: u32 = 32;
    pub const W64: u32 = 64;
    pub const W128: u32 = 128;
}

/// Well-known type strings emitted in decompiler output.
pub mod type_names {
    pub const BOOL: &str = "_Bool";
    pub const INT8: &str = "int8_t";
    pub const INT16: &str = "int16_t";
    pub const INT32: &str = "int32_t";
    pub const INT64: &str = "int64_t";
    pub const UINT8: &str = "uint8_t";
    pub const UINT16: &str = "uint16_t";
    pub const UINT32: &str = "uint32_t";
    pub const UINT64: &str = "uint64_t";
    pub const FLOAT: &str = "float";
    pub const DOUBLE: &str = "double";
    pub const VOIDPTR: &str = "void *";
}

/// System V AMD64 ABI integer argument register names.
pub const SYSV_ARGS: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

/// Microsoft x64 ABI integer argument register names.
pub const MS_X64_ARGS: &[&str] = &["rcx", "rdx", "r8", "r9"];

/// x86-64 callee-saved register names (System V ABI).
pub const CALLEE_SAVED_SYSV: &[&str] = &["rbx", "rbp", "r12", "r13", "r14", "r15"];

/// x86-64 caller-saved register names (System V ABI).
pub const CALLER_SAVED_SYSV: &[&str] =
    &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

// ---------------------------------------------------------------------------
// TypeConstraintBuilder —" fluent builder for test use
// ---------------------------------------------------------------------------

/// A fluent builder for constructing [`TypeConstraint`] lists in tests.
#[derive(Debug, Default)]
pub struct TypeConstraintBuilder {
    constraints: Vec<TypeConstraint>,
}

impl TypeConstraintBuilder {
    /// Add a constraint.
    #[must_use]
    pub fn add(mut self, var: &str, ty: PropagatedType, addr: u64) -> Self {
        self.constraints
            .push(TypeConstraint::new(var, ty, Address(addr)));
        self
    }

    /// Build the constraint list.
    #[must_use]
    pub fn build(self) -> Vec<TypeConstraint> {
        self.constraints
    }
}

// ---------------------------------------------------------------------------
// AnnotationMerger —" merges TypePassResults from multiple analyses
// ---------------------------------------------------------------------------

/// Merges the type facts from multiple [`TypePassResult`]s into one.
///
/// Uses the lattice join to combine facts from different analyses;
/// conflicts are recorded as [`PropagatedType::Conflict`].
#[derive(Debug, Default)]
pub struct AnnotationMerger;

impl AnnotationMerger {
    /// Merge `results` into a single [`TypePassResult`].
    #[must_use] 
    pub fn merge(results: &[TypePassResult]) -> TypePassResult {
        let mut merged = TypePassResult::new(Address(0));
        for r in results {
            for (var, ty) in &r.types {
                let current = merged.get_type(var).clone();
                let joined = current.join(ty);
                merged.set_type(var.clone(), joined);
            }
        }
        merged
    }
}

// ---------------------------------------------------------------------------
// TypeExporter —" serialises a TypePassResult to CSV
// ---------------------------------------------------------------------------

/// Exports recovered type information to a CSV summary.
#[derive(Debug, Default)]
pub struct TypeExporter;

impl TypeExporter {
    /// Produce a CSV string: `variable,type\n` for each entry.
    #[must_use] 
    pub fn to_csv(result: &TypePassResult) -> String {
        let mut out = String::from("variable,type\n");
        let mut rows: Vec<(String, String)> = result
            .types
            .iter()
            .map(|(k, v)| (k.clone(), format!("{v}")))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        for (var, ty) in rows {
            use std::fmt::Write as _;
            let _ = writeln!(out, "{var},{ty}");
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ADDITIONAL CONSTANTS
// ---------------------------------------------------------------------------

/// Default confidence threshold for type assertions.
pub const DEFAULT_CONFIDENCE: f64 = 0.75;

/// Maximum number of inferred constraints per variable before capping.
pub const MAX_CONSTRAINTS_PER_VAR: usize = 1024;

/// Minimum access count before a pointer conclusion is accepted.
pub const MIN_POINTER_EVIDENCE: usize = 1;

/// Minimum access count before a float conclusion is accepted.
pub const MIN_FLOAT_EVIDENCE: usize = 2;

// ---------------------------------------------------------------------------
// TypeStatistics —" aggregate statistics over collected constraints
// ---------------------------------------------------------------------------

/// Statistics about a type recovery run.
#[derive(Debug, Clone, Default)]
pub struct TypeStatistics {
    pub total_constraints: usize,
    pub pointer_constraints: usize,
    pub float_constraints: usize,
    pub integral_constraints: usize,
    pub bool_constraints: usize,
}

impl TypeStatistics {
    /// Build from a constraint list.
    #[must_use] 
    pub fn from_constraints(constraints: &[TypeConstraint]) -> Self {
        let mut s = Self {
            total_constraints: constraints.len(),
            ..Self::default()
        };
        for c in constraints {
            match &c.ty {
                PropagatedType::Pointer(_) => s.pointer_constraints += 1,
                PropagatedType::Float32 | PropagatedType::Float64 => s.float_constraints += 1,
                PropagatedType::UnsignedInt { bits: 1 } => s.bool_constraints += 1,
                PropagatedType::Integral { .. }
                | PropagatedType::SignedInt { .. }
                | PropagatedType::UnsignedInt { .. } => s.integral_constraints += 1,
                _ => {}
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// PropagatedType
// ---------------------------------------------------------------------------

/// A recovered / inferred type for a variable or memory location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PropagatedType {
    /// Width in bits is known but sign/semantics are not.
    Integral { bits: u32 },
    /// Signed integer of a known width.
    SignedInt { bits: u32 },
    /// Unsigned integer of a known width.
    UnsignedInt { bits: u32 },
    /// Single-precision float.
    Float32,
    /// Double-precision float.
    Float64,
    /// Pointer to another type.
    Pointer(Box<Self>),
    /// Type is completely unknown.
    Unknown,
    /// A conflict was detected (two incompatible constraints).
    Conflict,
}

impl PropagatedType {
    /// Return the byte width if known.
    #[must_use]
    pub fn byte_width(&self) -> Option<u32> {
        match self {
            Self::Integral { bits } | Self::SignedInt { bits } | Self::UnsignedInt { bits } => {
                Some(bits / 8)
            }
            Self::Float32 => Some(4),
            Self::Float64 | Self::Pointer(_) => Some(8), // assume 64-bit pointers for Pointer
            Self::Unknown | Self::Conflict => None,
        }
    }

    /// Whether this type is an integer kind.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Integral { .. } | Self::SignedInt { .. } | Self::UnsignedInt { .. }
        )
    }

    /// Whether this type is a pointer.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// Return the join of `self` and `other` in the type lattice.
    /// Unknown âŠ' any concrete âŠ' Conflict.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unknown, t) | (t, Self::Unknown) => t.clone(),
            (Self::Conflict, _) | (_, Self::Conflict) => Self::Conflict,
            (a, b) if a == b => a.clone(),
            // Compatible integer widths: signed beats unsigned.
            (Self::Integral { bits: b1 }, Self::SignedInt { bits: b2 })
            | (Self::SignedInt { bits: b1 }, Self::Integral { bits: b2 })
                if b1 == b2 =>
            {
                Self::SignedInt { bits: *b1 }
            }
            (Self::Integral { bits: b1 }, Self::UnsignedInt { bits: b2 })
            | (Self::UnsignedInt { bits: b1 }, Self::Integral { bits: b2 })
                if b1 == b2 =>
            {
                Self::UnsignedInt { bits: *b1 }
            }
            _ => Self::Conflict,
        }
    }
}

impl fmt::Display for PropagatedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integral { bits } => write!(f, "i{bits}"),
            Self::SignedInt { bits } => write!(f, "s{bits}"),
            Self::UnsignedInt { bits } => write!(f, "u{bits}"),
            Self::Float32 => write!(f, "f32"),
            Self::Float64 => write!(f, "f64"),
            Self::Pointer(inner) => write!(f, "*{inner}"),
            Self::Unknown => write!(f, "?"),
            Self::Conflict => write!(f, "CONFLICT"),
        }
    }
}

// ---------------------------------------------------------------------------
// TypeConstraint
// ---------------------------------------------------------------------------

/// A single type constraint relating a variable to a type.
#[derive(Debug, Clone)]
pub struct TypeConstraint {
    /// The variable (register name) being constrained.
    pub variable: String,
    /// The asserted type.
    pub ty: PropagatedType,
    /// Source instruction address for debugging.
    pub source: Address,
}

impl TypeConstraint {
    #[must_use]
    pub fn new(variable: impl Into<String>, ty: PropagatedType, source: Address) -> Self {
        Self {
            variable: variable.into(),
            ty,
            source,
        }
    }
}

// ---------------------------------------------------------------------------
// TypeConstraintCollector
// ---------------------------------------------------------------------------

/// Walks LLIL instructions and emits [`TypeConstraint`]s.
#[derive(Debug, Default)]
pub struct TypeConstraintCollector {
    /// All constraints collected so far.
    pub constraints: Vec<TypeConstraint>,
    /// Pointer size in bits (32 or 64).
    pub pointer_bits: u32,
}

impl TypeConstraintCollector {
    /// Create a collector for 64-bit pointer targets.
    #[must_use]
    pub fn new_64() -> Self {
        Self {
            pointer_bits: 64,
            ..Default::default()
        }
    }

    /// Create a collector for 32-bit pointer targets.
    #[must_use]
    pub fn new_32() -> Self {
        Self {
            pointer_bits: 32,
            ..Default::default()
        }
    }

    /// Collect constraints from a single LLIL function.
    pub fn collect(&mut self, func: &LlilFunction) {
        for annotated in &func.instructions {
            self.visit_instr(annotated);
        }
    }

    fn visit_instr(&mut self, annotated: &LlilAnnotatedInstr) {
        let addr = annotated.address;
        match &annotated.instr {
            LlilInstruction::SetReg {
                dest,
                size,
                value: src,
            } => {
                let name = reg_name(dest);
                // The destination holds a value of the given width.
                self.add(name.clone(), type_from_size(*size), addr);
                // If the source is a load (address-of), the register is a pointer.
                if let LlilExpr::Load { addr: ptr_expr, .. } = src {
                    self.mark_pointer(&reg_name_of_expr(ptr_expr.as_ref()), addr);
                }
                // Float sources narrow the type.
                if is_float_expr(src) {
                    let float_ty = if size.bytes() == 4 {
                        PropagatedType::Float32
                    } else {
                        PropagatedType::Float64
                    };
                    self.add(name, float_ty, addr);
                }
            }

            LlilInstruction::Store {
                addr: ptr_expr,
                size,
                value: src,
            } => {
                self.mark_pointer(&reg_name_of_expr(ptr_expr), addr);
                // Source is written through a pointer â†' source is an integral.
                if let Some(name) = as_reg_name(src) {
                    self.add(name, type_from_size(*size), addr);
                }
            }

            LlilInstruction::Load {
                dest,
                size,
                addr: ptr_expr,
            } => {
                let dest_name = reg_name(dest);
                self.add(dest_name, type_from_size(*size), addr);
                self.mark_pointer(&reg_name_of_expr(ptr_expr), addr);
            }

            LlilInstruction::CondJump { cond, .. } => {
                // The condition variable is boolean (1-bit unsigned).
                if let Some(name) = as_reg_name(cond) {
                    self.add(name, PropagatedType::UnsignedInt { bits: 1 }, addr);
                }
            }

            // Arithmetic instructions: propagate size constraints to operands.
            _ => {}
        }
    }

    fn add(&mut self, variable: String, ty: PropagatedType, source: Address) {
        if !variable.is_empty() {
            self.constraints
                .push(TypeConstraint::new(variable, ty, source));
        }
    }

    fn mark_pointer(&mut self, name: &str, source: Address) {
        if !name.is_empty() {
            self.constraints.push(TypeConstraint::new(
                name,
                PropagatedType::Pointer(Box::new(PropagatedType::Unknown)),
                source,
            ));
        }
    }
}

fn reg_name(reg: &LlilRegister) -> String {
    match reg {
        LlilRegister::Concrete(n) => n.clone(),
        LlilRegister::Temporary(n) => format!("tmp{n}"),
    }
}

fn reg_name_of_expr(expr: &LlilExpr) -> String {
    match expr {
        LlilExpr::RegisterRef { reg, .. } => reg_name(reg),
        _ => String::new(),
    }
}

fn as_reg_name(expr: &LlilExpr) -> Option<String> {
    match expr {
        LlilExpr::RegisterRef { reg, .. } => Some(reg_name(reg)),
        _ => None,
    }
}

fn type_from_size(size: Size) -> PropagatedType {
    PropagatedType::Integral {
        bits: u32::try_from(size.bytes() * 8).unwrap_or(0),
    }
}

const fn is_float_expr(expr: &LlilExpr) -> bool {
    matches!(
        expr,
        LlilExpr::FAdd(..)
            | LlilExpr::FSub(..)
            | LlilExpr::FMul(..)
            | LlilExpr::FDiv(..)
            | LlilExpr::FNeg(..)
            | LlilExpr::IntToFloat { .. }
            | LlilExpr::FloatToInt { .. }
    )
}

// ---------------------------------------------------------------------------
// TypeSolver
// ---------------------------------------------------------------------------

/// Unifies collected constraints into a type map using a simple worklist.
#[derive(Debug, Default)]
pub struct TypeSolver {
    /// Current best type for each variable.
    types: HashMap<String, PropagatedType>,
}

impl TypeSolver {
    /// Solve `constraints`, returning the final type map.
    pub fn solve(&mut self, constraints: &[TypeConstraint]) -> HashMap<String, PropagatedType> {
        // Initialise all variables to Unknown.
        for c in constraints {
            self.types
                .entry(c.variable.clone())
                .or_insert(PropagatedType::Unknown);
        }
        // Iteratively join constraints until convergence.
        let mut changed = true;
        while changed {
            changed = false;
            for c in constraints {
                let current = self
                    .types
                    .get(&c.variable)
                    .cloned()
                    .unwrap_or(PropagatedType::Unknown);
                let joined = current.join(&c.ty);
                if joined
                    != *self
                        .types
                        .get(&c.variable)
                        .unwrap_or(&PropagatedType::Unknown)
                {
                    self.types.insert(c.variable.clone(), joined);
                    changed = true;
                }
            }
        }
        self.types.clone()
    }
}

// ---------------------------------------------------------------------------
// TypeAnnotator
// ---------------------------------------------------------------------------

/// Stores solved types into a [`TypePassResult`].
#[derive(Debug, Default)]
pub struct TypeAnnotator;

impl TypeAnnotator {
    /// Annotate `func`'s variables using the solved `types` map and return a
    /// [`TypePassResult`].
    #[must_use] 
    pub fn annotate(
        &self,
        func: &LlilFunction,
        types: &HashMap<String, PropagatedType>,
    ) -> TypePassResult {
        let mut result = TypePassResult::new(func.address);
        for (var, ty) in types {
            result.set_type(var.clone(), ty.clone());
        }
        result
    }
}

// ---------------------------------------------------------------------------
// TypePassResult
// ---------------------------------------------------------------------------

/// The output of the type recovery pass for one function.
#[derive(Debug, Clone, Default)]
pub struct TypePassResult {
    /// Function entry address.
    pub function_address: Address,
    /// Variable â†' inferred type.
    types: HashMap<String, PropagatedType>,
    /// Warnings generated during recovery.
    pub warnings: Vec<String>,
}

impl TypePassResult {
    /// Create an empty result for the function at `addr`.
    #[must_use]
    pub fn new(addr: Address) -> Self {
        Self {
            function_address: addr,
            ..Default::default()
        }
    }

    /// Store a type for `variable`.
    pub fn set_type(&mut self, variable: String, ty: PropagatedType) {
        self.types.insert(variable, ty);
    }

    /// Look up the inferred type for `variable`.
    #[must_use]
    pub fn get_type(&self, variable: &str) -> &PropagatedType {
        self.types.get(variable).unwrap_or(&PropagatedType::Unknown)
    }

    /// Number of variables with inferred types.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.types.len()
    }

    /// Returns all variables whose type is [`PropagatedType::Conflict`].
    #[must_use]
    pub fn conflicts(&self) -> Vec<&str> {
        self.types
            .iter()
            .filter(|(_, t)| matches!(t, PropagatedType::Conflict))
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Returns all pointer-typed variables.
    #[must_use]
    pub fn pointers(&self) -> Vec<&str> {
        self.types
            .iter()
            .filter(|(_, t)| t.is_pointer())
            .map(|(k, _)| k.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TypeRecoveryPass
// ---------------------------------------------------------------------------

/// The top-level type recovery pass.
///
/// Usage:
/// ```rust,ignore
/// let mut pass = TypeRecoveryPass::new_64();
/// let result = pass.run(&func);
/// ```
#[derive(Debug)]
pub struct TypeRecoveryPass {
    collector: TypeConstraintCollector,
    solver: TypeSolver,
    annotator: TypeAnnotator,
    /// The most recent pass result.
    pub last_result: Option<TypePassResult>,
}

impl TypeRecoveryPass {
    /// Create a 64-bit type recovery pass.
    #[must_use]
    pub fn new_64() -> Self {
        Self {
            collector: TypeConstraintCollector::new_64(),
            solver: TypeSolver::default(),
            annotator: TypeAnnotator,
            last_result: None,
        }
    }

    /// Create a 32-bit type recovery pass.
    #[must_use]
    pub fn new_32() -> Self {
        Self {
            collector: TypeConstraintCollector::new_32(),
            solver: TypeSolver::default(),
            annotator: TypeAnnotator,
            last_result: None,
        }
    }

    /// Run the pass on `func` and return the annotated result.
    pub fn run(&mut self, func: &LlilFunction) -> TypePassResult {
        self.collector.constraints.clear();
        self.collector.collect(func);
        let types = self.solver.solve(&self.collector.constraints);
        let result = self.annotator.annotate(func, &types);
        self.last_result = Some(result.clone());
        result
    }

    /// Number of constraints collected in the last run.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.collector.constraints.len()
    }
}

// ---------------------------------------------------------------------------
// MultiPassTypeRecovery —" inter-procedural type propagation skeleton
// ---------------------------------------------------------------------------

/// Runs type recovery on multiple functions and merges insights.
#[derive(Debug, Default)]
pub struct MultiPassTypeRecovery {
    /// Per-function results.
    pub results: std::collections::HashMap<u64, TypePassResult>,
    /// Cross-function pointer propagations.
    pub propagated: usize,
}

impl MultiPassTypeRecovery {
    /// Run recovery on a set of functions and merge pointer type evidence.
    pub fn run_all(&mut self, funcs: &[rustre_il_llil::LlilFunction]) {
        let mut pass = TypeRecoveryPass::new_64();
        for func in funcs {
            let result = pass.run(func);
            self.results.insert(func.address.0, result);
        }
        self.propagate_pointers();
    }

    fn propagate_pointers(&mut self) {
        // Simplified: mark all pointer variables across all functions.
        for result in self.results.values_mut() {
            // Count how many pointer variables were found in each function.
            let ptr_count = result.pointers().len();
            self.propagated += ptr_count;
        }
    }

    /// Total functions analyzed.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.results.len()
    }
}

// ---------------------------------------------------------------------------
// TypeConstraintFilter —" filters constraints by confidence
// ---------------------------------------------------------------------------

/// Filters a set of constraints to keep only those with a minimum confidence.
#[derive(Debug, Default)]
pub struct TypeConstraintFilter {
    min_occurrences: usize,
}

impl TypeConstraintFilter {
    /// Create a filter that requires `min_occurrences` identical constraints
    /// before accepting them.
    #[must_use]
    pub const fn new(min_occurrences: usize) -> Self {
        Self { min_occurrences }
    }

    /// Filter `constraints` by occurrence count.
    #[must_use] 
    pub fn filter(&self, constraints: &[TypeConstraint]) -> Vec<TypeConstraint> {
        let mut counts: std::collections::HashMap<(&str, String), usize> =
            std::collections::HashMap::new();
        for c in constraints {
            *counts
                .entry((c.variable.as_str(), format!("{:?}", c.ty)))
                .or_insert(0) += 1;
        }
        constraints
            .iter()
            .filter(|c| {
                let key = (c.variable.as_str(), format!("{:?}", c.ty));
                counts.get(&key).copied().unwrap_or(0) >= self.min_occurrences
            })
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TypeMap —" flat lookup table for the decompiler
// ---------------------------------------------------------------------------

/// A flat, name-keyed lookup table for decompiler type annotations.
#[derive(Debug, Clone, Default)]
pub struct TypeMap {
    map: std::collections::HashMap<String, PropagatedType>,
}

impl TypeMap {
    /// Create from a [`TypePassResult`].
    #[must_use]
    pub fn from_result(result: &TypePassResult) -> Self {
        let mut tm = Self::default();
        for (k, v) in &result.types {
            tm.map.insert(k.clone(), v.clone());
        }
        tm
    }

    /// Insert a type.
    pub fn insert(&mut self, name: impl Into<String>, ty: PropagatedType) {
        self.map.insert(name.into(), ty);
    }

    /// Look up a type.
    #[must_use]
    pub fn get(&self, name: &str) -> &PropagatedType {
        self.map.get(name).unwrap_or(&PropagatedType::Unknown)
    }

    /// All variable names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// TypeConstraintPrinter —" human-readable constraint output
// ---------------------------------------------------------------------------

/// Pretty-prints a set of type constraints for debugging.
#[derive(Debug, Default)]
pub struct TypeConstraintPrinter;

impl TypeConstraintPrinter {
    /// Return a human-readable string for `constraints`.
    #[must_use] 
    pub fn print(constraints: &[TypeConstraint]) -> String {
        let mut out = String::new();
        for (i, c) in constraints.iter().enumerate() {
            use std::fmt::Write as _;
            let _ = writeln!(out, "[{i:3}] {} : {} (@ {:#x})", c.variable, c.ty, c.source.0);
        }
        out
    }

    /// Print only the constraints for `variable`.
    #[must_use] 
    pub fn print_var<'a>(
        variable: &str,
        constraints: &'a [TypeConstraint],
    ) -> Vec<&'a TypeConstraint> {
        constraints
            .iter()
            .filter(|c| c.variable == variable)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TypeLattice —" explicit lattice operations exposed as a utility
// ---------------------------------------------------------------------------

/// Wraps lattice operations for use by callers who want explicit control.
#[derive(Debug, Default)]
pub struct TypeLattice;

impl TypeLattice {
    /// Check whether `a âŠ' b` (a is less than or equal to b in the lattice).
    #[must_use]
    pub fn leq(a: &PropagatedType, b: &PropagatedType) -> bool {
        match (a, b) {
            (PropagatedType::Unknown, _) | (_, PropagatedType::Conflict) => true,
            (x, y) => x == y,
        }
    }

    /// Compute the least upper bound (join) of a collection of types.
    #[must_use] 
    pub fn lub(types: &[PropagatedType]) -> PropagatedType {
        types
            .iter()
            .fold(PropagatedType::Unknown, |acc, t| acc.join(t))
    }

    /// Is `ty` a "bottom" (most general) type?
    #[must_use]
    pub const fn is_bottom(ty: &PropagatedType) -> bool {
        matches!(ty, PropagatedType::Unknown)
    }

    /// Is `ty` a "top" (fully constrained / conflicted) type?
    #[must_use]
    pub const fn is_top(ty: &PropagatedType) -> bool {
        matches!(ty, PropagatedType::Conflict)
    }
}

// ---------------------------------------------------------------------------
// CallConventionTypeHints —" inject calling-convention argument types
// ---------------------------------------------------------------------------

/// Provides type hints based on well-known calling conventions.
#[derive(Debug, Default)]
pub struct CallConventionTypeHints;

impl CallConventionTypeHints {
    /// Return the argument registers for System V AMD64 ABI.
    #[must_use]
    pub fn sysv_amd64_args() -> Vec<(&'static str, PropagatedType)> {
        vec![
            ("rdi", PropagatedType::Integral { bits: 64 }),
            ("rsi", PropagatedType::Integral { bits: 64 }),
            ("rdx", PropagatedType::Integral { bits: 64 }),
            ("rcx", PropagatedType::Integral { bits: 64 }),
            ("r8", PropagatedType::Integral { bits: 64 }),
            ("r9", PropagatedType::Integral { bits: 64 }),
        ]
    }

    /// Return the argument registers for Microsoft x64 ABI.
    #[must_use]
    pub fn ms_x64_args() -> Vec<(&'static str, PropagatedType)> {
        vec![
            ("rcx", PropagatedType::Integral { bits: 64 }),
            ("rdx", PropagatedType::Integral { bits: 64 }),
            ("r8", PropagatedType::Integral { bits: 64 }),
            ("r9", PropagatedType::Integral { bits: 64 }),
        ]
    }

    /// Inject hints into a [`TypeMap`] for the given ABI.
    pub fn inject_sysv(map: &mut TypeMap) {
        for (reg, ty) in Self::sysv_amd64_args() {
            map.insert(reg, ty);
        }
    }
}

// ---------------------------------------------------------------------------
// TypeSummary —" high-level summary of recovery results
// ---------------------------------------------------------------------------

/// Produces a human-readable summary of a [`TypePassResult`].
#[derive(Debug, Clone, Default)]
pub struct TypeSummary {
    pub total_vars: usize,
    pub known_vars: usize,
    pub pointer_vars: usize,
    pub float_vars: usize,
    pub conflict_vars: usize,
}

impl TypeSummary {
    /// Build a summary from `result`.
    #[must_use]
    pub fn from_result(result: &TypePassResult) -> Self {
        Self {
            total_vars: result.variable_count(),
            pointer_vars: result.pointers().len(),
            conflict_vars: result.conflicts().len(),
            ..Self::default()
        }
    }

    /// Fraction of variables with non-Unknown types.
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.total_vars == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.known_vars).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_vars).unwrap_or(u32::MAX))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_il_llil::{
        LlilAnnotatedInstr, LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size,
    };

    fn make_func(instrs: Vec<(u64, LlilInstruction)>) -> LlilFunction {
        let instructions = instrs
            .into_iter()
            .map(|(a, i)| LlilAnnotatedInstr {
                address: Address(a),
                instr: i,
                size: 1,
                length: 1,
            })
            .collect();
        LlilFunction {
            address: Address(0),
            name: Some("t".into()),
            instructions,
            blocks: vec![],
            ..LlilFunction::default()
        }
    }

    fn reg_expr(name: &str, size: Size) -> LlilExpr {
        LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(name.into()),
            size,
        }
    }

    // --- PropagatedType tests ---

    #[test]
    fn prop_type_join_unknown_with_known() {
        let t = PropagatedType::Unknown.join(&PropagatedType::SignedInt { bits: 32 });
        assert_eq!(t, PropagatedType::SignedInt { bits: 32 });
    }

    #[test]
    fn prop_type_join_same() {
        let t =
            PropagatedType::SignedInt { bits: 32 }.join(&PropagatedType::SignedInt { bits: 32 });
        assert_eq!(t, PropagatedType::SignedInt { bits: 32 });
    }

    #[test]
    fn prop_type_join_incompatible_conflict() {
        let t = PropagatedType::Float32.join(&PropagatedType::SignedInt { bits: 32 });
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn prop_type_join_integral_with_signed() {
        let t = PropagatedType::Integral { bits: 32 }.join(&PropagatedType::SignedInt { bits: 32 });
        assert_eq!(t, PropagatedType::SignedInt { bits: 32 });
    }

    #[test]
    fn prop_type_join_integral_with_unsigned() {
        let t =
            PropagatedType::Integral { bits: 64 }.join(&PropagatedType::UnsignedInt { bits: 64 });
        assert_eq!(t, PropagatedType::UnsignedInt { bits: 64 });
    }

    #[test]
    fn prop_type_join_conflict_absorbs() {
        let t = PropagatedType::Conflict.join(&PropagatedType::Float32);
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn prop_type_is_integer() {
        assert!(PropagatedType::SignedInt { bits: 32 }.is_integer());
        assert!(!PropagatedType::Pointer(Box::new(PropagatedType::Unknown)).is_integer());
    }

    #[test]
    fn prop_type_is_pointer() {
        assert!(PropagatedType::Pointer(Box::new(PropagatedType::Unknown)).is_pointer());
        assert!(!PropagatedType::Float32.is_pointer());
    }

    #[test]
    fn prop_type_byte_width() {
        assert_eq!(PropagatedType::SignedInt { bits: 32 }.byte_width(), Some(4));
        assert_eq!(PropagatedType::Float64.byte_width(), Some(8));
        assert_eq!(PropagatedType::Unknown.byte_width(), None);
    }

    #[test]
    fn prop_type_display() {
        assert_eq!(format!("{}", PropagatedType::SignedInt { bits: 32 }), "s32");
        assert_eq!(format!("{}", PropagatedType::Unknown), "?");
        assert_eq!(format!("{}", PropagatedType::Conflict), "CONFLICT");
    }

    // --- TypeConstraintCollector tests ---

    #[test]
    fn collector_setreg_adds_width_constraint() {
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: LlilExpr::Const {
                    value: 0,
                    size: Size::QWord,
                },
            },
        )]);
        let mut col = TypeConstraintCollector::new_64();
        col.collect(&func);
        let has_rax = col.constraints.iter().any(|c| c.variable == "rax");
        assert!(has_rax);
    }

    #[test]
    fn collector_store_marks_pointer() {
        let func = make_func(vec![(
            0,
            LlilInstruction::Store {
                addr: reg_expr("rbx", Size::QWord),
                size: Size::DWord,
                value: LlilExpr::Const {
                    value: 0,
                    size: Size::DWord,
                },
            },
        )]);
        let mut col = TypeConstraintCollector::new_64();
        col.collect(&func);
        let ptr = col
            .constraints
            .iter()
            .find(|c| c.variable == "rbx" && c.ty.is_pointer());
        assert!(ptr.is_some());
    }

    #[test]
    fn collector_load_marks_pointer_and_dest() {
        let func = make_func(vec![(
            0,
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rcx".into()),
                size: Size::DWord,
                addr: reg_expr("rdx", Size::QWord),
            },
        )]);
        let mut col = TypeConstraintCollector::new_64();
        col.collect(&func);
        let ptr = col
            .constraints
            .iter()
            .any(|c| c.variable == "rdx" && c.ty.is_pointer());
        let dst = col.constraints.iter().any(|c| c.variable == "rcx");
        assert!(ptr);
        assert!(dst);
    }

    #[test]
    fn collector_condjump_marks_bool() {
        let func = make_func(vec![(
            0,
            LlilInstruction::CondJump {
                cond: reg_expr("rax", Size::Byte),
                true_dest: Address(0x100),
                false_dest: Address(0x200),
            },
        )]);
        let mut col = TypeConstraintCollector::new_64();
        col.collect(&func);
        let bool_c = col.constraints.iter().find(|c| {
            c.variable == "rax" && matches!(c.ty, PropagatedType::UnsignedInt { bits: 1 })
        });
        assert!(bool_c.is_some());
    }

    // --- TypeSolver tests ---

    #[test]
    fn solver_unknown_initially() {
        let mut solver = TypeSolver::default();
        let constraints = vec![TypeConstraint::new(
            "x",
            PropagatedType::Unknown,
            Address(0),
        )];
        let types = solver.solve(&constraints);
        assert_eq!(types["x"], PropagatedType::Unknown);
    }

    #[test]
    fn solver_concrete_type() {
        let mut solver = TypeSolver::default();
        let constraints = vec![TypeConstraint::new(
            "x",
            PropagatedType::SignedInt { bits: 32 },
            Address(0),
        )];
        let types = solver.solve(&constraints);
        assert_eq!(types["x"], PropagatedType::SignedInt { bits: 32 });
    }

    #[test]
    fn solver_joins_compatible() {
        let mut solver = TypeSolver::default();
        let constraints = vec![
            TypeConstraint::new("x", PropagatedType::Integral { bits: 32 }, Address(0)),
            TypeConstraint::new("x", PropagatedType::SignedInt { bits: 32 }, Address(1)),
        ];
        let types = solver.solve(&constraints);
        assert_eq!(types["x"], PropagatedType::SignedInt { bits: 32 });
    }

    #[test]
    fn solver_produces_conflict() {
        let mut solver = TypeSolver::default();
        let constraints = vec![
            TypeConstraint::new("x", PropagatedType::Float32, Address(0)),
            TypeConstraint::new("x", PropagatedType::SignedInt { bits: 32 }, Address(1)),
        ];
        let types = solver.solve(&constraints);
        assert_eq!(types["x"], PropagatedType::Conflict);
    }

    // --- TypePassResult tests ---

    #[test]
    fn pass_result_get_set() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type("rax".into(), PropagatedType::SignedInt { bits: 64 });
        assert_eq!(r.get_type("rax"), &PropagatedType::SignedInt { bits: 64 });
        assert_eq!(r.get_type("rbx"), &PropagatedType::Unknown);
    }

    #[test]
    fn pass_result_conflicts_list() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type("x".into(), PropagatedType::Conflict);
        r.set_type("y".into(), PropagatedType::Float32);
        assert_eq!(r.conflicts().len(), 1);
    }

    #[test]
    fn pass_result_pointers_list() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type(
            "ptr".into(),
            PropagatedType::Pointer(Box::new(PropagatedType::Unknown)),
        );
        r.set_type("val".into(), PropagatedType::SignedInt { bits: 32 });
        assert_eq!(r.pointers().len(), 1);
    }

    #[test]
    fn pass_result_variable_count() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type("a".into(), PropagatedType::Float64);
        r.set_type("b".into(), PropagatedType::Float32);
        assert_eq!(r.variable_count(), 2);
    }

    // --- TypeRecoveryPass end-to-end tests ---

    #[test]
    fn pass_run_empty_function() {
        let func = make_func(vec![]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        assert_eq!(result.variable_count(), 0);
    }

    #[test]
    fn pass_run_setreg_infers_width() {
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::DWord,
                value: LlilExpr::Const {
                    value: 0,
                    size: Size::DWord,
                },
            },
        )]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        let ty = result.get_type("rax");
        assert!(ty.is_integer() || matches!(ty, PropagatedType::Integral { .. }));
    }

    #[test]
    fn pass_run_load_infers_pointer() {
        let func = make_func(vec![(
            0,
            LlilInstruction::Load {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                addr: reg_expr("rbx", Size::QWord),
            },
        )]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        assert!(result.get_type("rbx").is_pointer());
    }

    #[test]
    fn pass_run_store_infers_pointer() {
        let func = make_func(vec![(
            0,
            LlilInstruction::Store {
                addr: reg_expr("rdi", Size::QWord),
                size: Size::DWord,
                value: LlilExpr::Const {
                    value: 0,
                    size: Size::DWord,
                },
            },
        )]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        assert!(result.get_type("rdi").is_pointer());
    }

    #[test]
    fn pass_constraint_count_after_run() {
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: LlilExpr::Const {
                    value: 0,
                    size: Size::QWord,
                },
            },
        )]);
        let mut pass = TypeRecoveryPass::new_64();
        pass.run(&func);
        assert!(pass.constraint_count() > 0);
    }

    #[test]
    fn pass_last_result_populated() {
        let func = make_func(vec![]);
        let mut pass = TypeRecoveryPass::new_64();
        pass.run(&func);
        assert!(pass.last_result.is_some());
    }

    #[test]
    fn type_from_size_byte() {
        assert_eq!(
            type_from_size(Size::Byte),
            PropagatedType::Integral { bits: 8 }
        );
    }

    #[test]
    fn type_from_size_qword() {
        assert_eq!(
            type_from_size(Size::QWord),
            PropagatedType::Integral { bits: 64 }
        );
    }

    #[test]
    fn prop_type_pointer_display() {
        let ty = PropagatedType::Pointer(Box::new(PropagatedType::SignedInt { bits: 32 }));
        assert!(format!("{ty}").contains('*'));
    }

    // --- Additional PropagatedType lattice tests ---

    #[test]
    fn join_unknown_with_float32() {
        let t = PropagatedType::Unknown.join(&PropagatedType::Float32);
        assert_eq!(t, PropagatedType::Float32);
    }

    #[test]
    fn join_float32_with_float64_conflict() {
        let t = PropagatedType::Float32.join(&PropagatedType::Float64);
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn join_conflict_with_unknown_is_conflict() {
        let t = PropagatedType::Conflict.join(&PropagatedType::Unknown);
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn join_signed_with_unsigned_conflict() {
        let t =
            PropagatedType::SignedInt { bits: 32 }.join(&PropagatedType::UnsignedInt { bits: 32 });
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn join_integral_different_widths_conflict() {
        let t = PropagatedType::Integral { bits: 32 }.join(&PropagatedType::Integral { bits: 64 });
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn join_pointer_with_int_conflict() {
        let ptr = PropagatedType::Pointer(Box::new(PropagatedType::Unknown));
        let t = ptr.join(&PropagatedType::SignedInt { bits: 64 });
        assert_eq!(t, PropagatedType::Conflict);
    }

    #[test]
    fn byte_width_float32() {
        assert_eq!(PropagatedType::Float32.byte_width(), Some(4));
    }

    #[test]
    fn byte_width_signed_8() {
        assert_eq!(PropagatedType::SignedInt { bits: 8 }.byte_width(), Some(1));
    }

    #[test]
    fn byte_width_conflict_none() {
        assert_eq!(PropagatedType::Conflict.byte_width(), None);
    }

    // --- TypeConstraint helpers ---

    #[test]
    fn type_constraint_new() {
        let c = TypeConstraint::new("rax", PropagatedType::Unknown, Address(0));
        assert_eq!(c.variable, "rax");
    }

    // --- Multiple constraint merging ---

    #[test]
    fn solver_multiple_vars_independent() {
        let mut solver = TypeSolver::default();
        let constraints = vec![
            TypeConstraint::new("a", PropagatedType::SignedInt { bits: 32 }, Address(0)),
            TypeConstraint::new("b", PropagatedType::Float64, Address(0)),
        ];
        let types = solver.solve(&constraints);
        assert_eq!(types["a"], PropagatedType::SignedInt { bits: 32 });
        assert_eq!(types["b"], PropagatedType::Float64);
    }

    #[test]
    fn solver_three_constraints_converge() {
        let mut solver = TypeSolver::default();
        let constraints = vec![
            TypeConstraint::new("x", PropagatedType::Integral { bits: 64 }, Address(0)),
            TypeConstraint::new("x", PropagatedType::Integral { bits: 64 }, Address(1)),
            TypeConstraint::new("x", PropagatedType::UnsignedInt { bits: 64 }, Address(2)),
        ];
        let types = solver.solve(&constraints);
        assert_eq!(types["x"], PropagatedType::UnsignedInt { bits: 64 });
    }

    // --- TypeAnnotator ---

    #[test]
    fn annotator_empty_types() {
        let ann = TypeAnnotator;
        let func = make_func(vec![]);
        let result = ann.annotate(&func, &std::collections::HashMap::new());
        assert_eq!(result.variable_count(), 0);
    }

    #[test]
    fn annotator_single_type() {
        let ann = TypeAnnotator;
        let func = make_func(vec![]);
        let mut types = std::collections::HashMap::new();
        types.insert(
            "rdi".into(),
            PropagatedType::Pointer(Box::new(PropagatedType::Unknown)),
        );
        let result = ann.annotate(&func, &types);
        assert!(result.get_type("rdi").is_pointer());
    }

    // --- TypeRecoveryPass 32-bit ---

    #[test]
    fn pass_32bit_creates() {
        let mut pass = TypeRecoveryPass::new_32();
        assert_eq!(pass.collector.pointer_bits, 32);
        let func = make_func(vec![]);
        let result = pass.run(&func);
        assert_eq!(result.variable_count(), 0);
    }

    // --- Warnings initially empty ---

    #[test]
    fn pass_result_warnings_empty() {
        let r = TypePassResult::new(Address(0));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn pass_result_function_address() {
        let r = TypePassResult::new(Address(0x1000));
        assert_eq!(r.function_address, Address(0x1000));
    }

    // --- Float detection ---

    #[test]
    fn is_float_expr_fadd() {
        let e = LlilExpr::FAdd(
            Box::new(LlilExpr::Const {
                value: 0,
                size: Size::DWord,
            }),
            Box::new(LlilExpr::Const {
                value: 0,
                size: Size::DWord,
            }),
            Size::DWord,
        );
        assert!(is_float_expr(&e));
    }

    #[test]
    fn is_float_expr_non_float() {
        let e = LlilExpr::Const {
            value: 0,
            size: Size::DWord,
        };
        assert!(!is_float_expr(&e));
    }

    #[test]
    fn reg_name_concrete() {
        assert_eq!(reg_name(&LlilRegister::Concrete("rsp".into())), "rsp");
    }

    #[test]
    fn reg_name_temporary() {
        assert_eq!(reg_name(&LlilRegister::Temporary(3)), "tmp3");
    }

    #[test]
    fn type_from_size_word() {
        assert_eq!(
            type_from_size(Size::Word),
            PropagatedType::Integral { bits: 16 }
        );
    }

    #[test]
    fn type_from_size_dword() {
        assert_eq!(
            type_from_size(Size::DWord),
            PropagatedType::Integral { bits: 32 }
        );
    }

    // --- MultiPassTypeRecovery ---

    #[test]
    fn multi_pass_empty() {
        let mut mp = MultiPassTypeRecovery::default();
        mp.run_all(&[]);
        assert_eq!(mp.function_count(), 0);
    }

    #[test]
    fn multi_pass_single_func() {
        let func = make_func(vec![(
            0,
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
                value: LlilExpr::Const {
                    value: 0,
                    size: Size::QWord,
                },
            },
        )]);
        let mut mp = MultiPassTypeRecovery::default();
        mp.run_all(&[func]);
        assert_eq!(mp.function_count(), 1);
    }

    // --- TypeConstraintFilter ---

    #[test]
    fn filter_min_one_passes_all() {
        let f = TypeConstraintFilter::new(1);
        let c = vec![TypeConstraint::new(
            "x",
            PropagatedType::Unknown,
            Address(0),
        )];
        assert_eq!(f.filter(&c).len(), 1);
    }

    #[test]
    fn filter_min_two_removes_singles() {
        let f = TypeConstraintFilter::new(2);
        let c = vec![TypeConstraint::new(
            "x",
            PropagatedType::Unknown,
            Address(0),
        )];
        assert_eq!(f.filter(&c).len(), 0);
    }

    #[test]
    fn filter_keeps_repeated() {
        let f = TypeConstraintFilter::new(2);
        let c = vec![
            TypeConstraint::new("x", PropagatedType::Float32, Address(0)),
            TypeConstraint::new("x", PropagatedType::Float32, Address(1)),
        ];
        assert_eq!(f.filter(&c).len(), 2);
    }

    // --- TypeMap ---

    #[test]
    fn type_map_insert_get() {
        let mut m = TypeMap::default();
        m.insert("rax", PropagatedType::SignedInt { bits: 64 });
        assert_eq!(m.get("rax"), &PropagatedType::SignedInt { bits: 64 });
    }

    #[test]
    fn type_map_default_unknown() {
        let m = TypeMap::default();
        assert_eq!(m.get("missing"), &PropagatedType::Unknown);
    }

    #[test]
    fn type_map_names() {
        let mut m = TypeMap::default();
        m.insert("a", PropagatedType::Float32);
        m.insert("b", PropagatedType::Float64);
        
        assert_eq!(m.names().count(), 2);
    }

    #[test]
    fn type_map_from_result() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type(
            "ptr".into(),
            PropagatedType::Pointer(Box::new(PropagatedType::Unknown)),
        );
        let m = TypeMap::from_result(&r);
        assert!(m.get("ptr").is_pointer());
    }

    // --- PropagatedType symmetric join ---

    #[test]
    fn join_symmetric_float32() {
        let a = PropagatedType::Float32;
        let b = PropagatedType::Float32;
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn join_symmetric_signed_int() {
        let a = PropagatedType::SignedInt { bits: 32 };
        let b = PropagatedType::UnsignedInt { bits: 32 };
        assert_eq!(a.join(&b), b.join(&a));
    }

    // --- TypeRecoveryPass: multiple SetReg ---

    #[test]
    fn pass_two_setregs_different_vars() {
        let func = make_func(vec![
            (
                0,
                LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                    value: LlilExpr::Const {
                        value: 0,
                        size: Size::QWord,
                    },
                },
            ),
            (
                1,
                LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("rbx".into()),
                    size: Size::DWord,
                    value: LlilExpr::Const {
                        value: 0,
                        size: Size::DWord,
                    },
                },
            ),
        ]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        assert!(result.variable_count() >= 2);
    }

    #[test]
    fn pass_nop_no_constraints() {
        let func = make_func(vec![(0, LlilInstruction::Nop)]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        assert_eq!(result.variable_count(), 0);
    }

    #[test]
    fn pass_ret_no_constraints() {
        let func = make_func(vec![(0, LlilInstruction::Ret)]);
        let mut pass = TypeRecoveryPass::new_64();
        let result = pass.run(&func);
        assert_eq!(result.variable_count(), 0);
    }

    // --- TypeConstraintPrinter tests ---

    #[test]
    fn printer_empty_constraints() {
        let s = TypeConstraintPrinter::print(&[]);
        assert!(s.is_empty());
    }

    #[test]
    fn printer_single_constraint() {
        let c = vec![TypeConstraint::new(
            "rax",
            PropagatedType::Float32,
            Address(0x100),
        )];
        let s = TypeConstraintPrinter::print(&c);
        assert!(s.contains("rax"));
        assert!(s.contains("f32"));
    }

    #[test]
    fn printer_print_var() {
        let c = vec![
            TypeConstraint::new("rax", PropagatedType::Float32, Address(0)),
            TypeConstraint::new("rbx", PropagatedType::Float64, Address(0)),
        ];
        let found = TypeConstraintPrinter::print_var("rax", &c);
        assert_eq!(found.len(), 1);
    }

    // --- TypeLattice tests ---

    #[test]
    fn lattice_leq_unknown_any() {
        assert!(TypeLattice::leq(
            &PropagatedType::Unknown,
            &PropagatedType::Float32
        ));
    }

    #[test]
    fn lattice_leq_any_conflict() {
        assert!(TypeLattice::leq(
            &PropagatedType::Float32,
            &PropagatedType::Conflict
        ));
    }

    #[test]
    fn lattice_leq_reflexive() {
        let t = PropagatedType::SignedInt { bits: 32 };
        assert!(TypeLattice::leq(&t, &t));
    }

    #[test]
    fn lattice_lub_empty() {
        let t = TypeLattice::lub(&[]);
        assert_eq!(t, PropagatedType::Unknown);
    }

    #[test]
    fn lattice_lub_single() {
        let t = TypeLattice::lub(&[PropagatedType::Float32]);
        assert_eq!(t, PropagatedType::Float32);
    }

    #[test]
    fn lattice_is_bottom_unknown() {
        assert!(TypeLattice::is_bottom(&PropagatedType::Unknown));
        assert!(!TypeLattice::is_bottom(&PropagatedType::Float32));
    }

    #[test]
    fn lattice_is_top_conflict() {
        assert!(TypeLattice::is_top(&PropagatedType::Conflict));
        assert!(!TypeLattice::is_top(&PropagatedType::Unknown));
    }

    // --- CallConventionTypeHints tests ---

    #[test]
    fn sysv_amd64_args_count() {
        let args = CallConventionTypeHints::sysv_amd64_args();
        assert_eq!(args.len(), 6);
    }

    #[test]
    fn ms_x64_args_count() {
        let args = CallConventionTypeHints::ms_x64_args();
        assert_eq!(args.len(), 4);
    }

    #[test]
    fn inject_sysv_populates_map() {
        let mut m = TypeMap::default();
        CallConventionTypeHints::inject_sysv(&mut m);
        assert!(m.get("rdi").is_integer());
    }

    // --- TypeSummary tests ---

    #[test]
    fn type_summary_empty() {
        let r = TypePassResult::new(Address(0));
        let s = TypeSummary::from_result(&r);
        assert_eq!(s.total_vars, 0);
        assert_eq!(s.coverage(), 0.0);
    }

    #[test]
    fn type_summary_pointer_counted() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type(
            "p".into(),
            PropagatedType::Pointer(Box::new(PropagatedType::Unknown)),
        );
        let s = TypeSummary::from_result(&r);
        assert_eq!(s.pointer_vars, 1);
    }

    #[test]
    fn type_summary_conflict_counted() {
        let mut r = TypePassResult::new(Address(0));
        r.set_type("x".into(), PropagatedType::Conflict);
        let s = TypeSummary::from_result(&r);
        assert_eq!(s.conflict_vars, 1);
    }
}
