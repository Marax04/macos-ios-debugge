//! Type constraint generation.
//!
//! Walks an abstract IL representation and emits [`TypeConstraint`]s that
//! capture the type relationships implied by each operation.  A downstream
//! unifier ([`crate::type_unifier`]) then solves the constraint system.
//!
//! # Key types
//! - [`ConstraintKind`]           — the shape of a single constraint.
//! - [`TypeConstraint`]           — one constraint with provenance.
//! - [`TypeConstraintGenerator`]  — the main constraint-emission engine.

use std::collections::HashMap;

use crate::{RecoveredType, TypeVar};

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintKind
// ─────────────────────────────────────────────────────────────────────────────

/// The structural form of a type constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintKind {
    /// `lhs = rhs` — the two type variables must unify to the same type.
    Equal { lhs: TypeVar, rhs: TypeVar },
    /// `lhs` is a pointer to the type of `pointee`.
    IsPointerTo { ptr: TypeVar, pointee: TypeVar },
    /// `var` has a concrete type.
    HasType { var: TypeVar, ty: RecoveredType },
    /// `var` is an integer of at least `min_width` bytes.
    IsInteger { var: TypeVar, min_width: u8, signed: Option<bool> },
    /// `var` is a floating-point value.
    IsFloat { var: TypeVar, width: u8 },
    /// `var` is the result of adding an offset to `base` (pointer arithmetic).
    PointerArithmetic { result: TypeVar, base: TypeVar, offset: TypeVar },
    /// `var` is a struct field access at byte `offset` from `base`.
    FieldAccess { struct_var: TypeVar, field_var: TypeVar, byte_offset: u32 },
    /// `callee` is a function accepting `param_count` parameters.
    IsCallable { callee: TypeVar, param_count: usize },
    /// `var` is the return type of the function `func`.
    IsReturnOf { var: TypeVar, func: TypeVar },
    /// `arr` is an array with element type `elem` and at least `min_count` elements.
    IsArray { arr: TypeVar, elem: TypeVar, min_count: usize },
}

impl std::fmt::Display for ConstraintKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Equal { lhs, rhs } => write!(f, "{lhs} = {rhs}"),
            Self::IsPointerTo { ptr, pointee } => write!(f, "{ptr} = *{pointee}"),
            Self::HasType { var, ty } => write!(f, "{var} : {}", ty.display_name()),
            Self::IsInteger { var, min_width, signed } => {
                let s = match signed {
                    Some(true) => "signed",
                    Some(false) => "unsigned",
                    None => "int",
                };
                write!(f, "{var} : {s}≥{min_width}B")
            }
            Self::IsFloat { var, width } => write!(f, "{var} : f{}", width * 8),
            Self::PointerArithmetic { result, base, offset } => {
                write!(f, "{result} = {base}[{offset}]")
            }
            Self::FieldAccess { struct_var, field_var, byte_offset } => {
                write!(f, "{struct_var}.+{byte_offset} : {field_var}")
            }
            Self::IsCallable { callee, param_count } => {
                write!(f, "{callee} : fn({param_count})")
            }
            Self::IsReturnOf { var, func } => write!(f, "{var} = ret({func})"),
            Self::IsArray { arr, elem, min_count } => {
                write!(f, "{arr} : [{elem}; ≥{min_count}]")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Provenance
// ─────────────────────────────────────────────────────────────────────────────

/// Source location / instruction that caused a constraint to be emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Address of the instruction.
    pub address: u64,
    /// Human-readable description.
    pub note: String,
}

impl Provenance {
    #[must_use]
    pub fn new(address: u64, note: impl Into<String>) -> Self {
        Self {
            address,
            note: note.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraint
// ─────────────────────────────────────────────────────────────────────────────

/// A single type constraint with provenance information.
#[derive(Debug, Clone)]
pub struct TypeConstraint {
    /// The unique constraint id (assigned by the generator).
    pub id: u32,
    /// The structural form of the constraint.
    pub kind: ConstraintKind,
    /// Where this constraint came from.
    pub provenance: Provenance,
    /// Confidence weight (higher = more trustworthy).
    pub confidence: f32,
}

impl TypeConstraint {
    /// Create a high-confidence constraint (confidence = 1.0).
    #[must_use]
    pub const fn certain(id: u32, kind: ConstraintKind, prov: Provenance) -> Self {
        Self {
            id,
            kind,
            provenance: prov,
            confidence: 1.0,
        }
    }

    /// Create a heuristic constraint with given confidence.
    #[must_use]
    pub const fn heuristic(id: u32, kind: ConstraintKind, prov: Provenance, confidence: f32) -> Self {
        Self {
            id,
            kind,
            provenance: prov,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract IL for constraint generation (no dependency on a concrete IL crate)
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract IL value referenced in constraint generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IlValue {
    /// A temporary or register identified by an opaque id.
    Temp(u32),
    /// A function parameter at the given index.
    Param(u32),
    /// The return value of the current function.
    RetVal,
    /// A literal integer constant.
    Const(i64),
    /// A global variable at a given address.
    Global(u64),
}

/// An abstract IL instruction for constraint generation.
#[derive(Debug, Clone)]
pub enum IlInstr {
    /// `dst = src` — copy / move.
    Assign { dst: IlValue, src: IlValue, addr: u64 },
    /// `dst = *ptr` — load from memory.
    Load { dst: IlValue, ptr: IlValue, size_bytes: u8, addr: u64 },
    /// `*ptr = src` — store to memory.
    Store { ptr: IlValue, src: IlValue, size_bytes: u8, addr: u64 },
    /// `dst = base + offset * scale` — address calculation.
    AddressOf { dst: IlValue, base: IlValue, offset: IlValue, scale: u32, addr: u64 },
    /// `dst = callee(args...)` — call instruction.
    Call { dst: Option<IlValue>, callee: IlValue, args: Vec<IlValue>, addr: u64 },
    /// `dst = lhs op rhs` — binary arithmetic.
    BinOp { dst: IlValue, lhs: IlValue, rhs: IlValue, op: AbstractBinOp, addr: u64 },
    /// `dst = cast(src)` — type-cast with explicit width.
    Cast { dst: IlValue, src: IlValue, to_width: u8, signed: bool, addr: u64 },
    /// Return `val`.
    Return { val: Option<IlValue>, addr: u64 },
}

/// Abstract binary operation categories for constraint purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstractBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Cmp,
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeConstraintGenerator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates type constraints by walking an abstract IL instruction stream.
///
/// The generator assigns a fresh [`TypeVar`] to each distinct [`IlValue`]
/// it encounters and emits [`TypeConstraint`]s for each instruction.
#[derive(Debug, Clone)]
pub struct TypeConstraintGenerator {
    /// Next type-variable id to assign.
    next_var: u32,
    /// Next constraint id to assign.
    next_cid: u32,
    /// Mapping from IL value to its type variable.
    var_map: HashMap<IlValue, TypeVar>,
    /// Emitted constraints.
    constraints: Vec<TypeConstraint>,
    /// Pointer width of the target (4 or 8 bytes).
    pub pointer_width: u8,
}

impl TypeConstraintGenerator {
    /// Create a new generator for the given pointer width.
    #[must_use]
    pub fn new(pointer_width: u8) -> Self {
        Self {
            next_var: 0,
            next_cid: 0,
            var_map: HashMap::new(),
            constraints: Vec::new(),
            pointer_width,
        }
    }

    /// Create a generator for 64-bit targets.
    #[must_use]
    pub fn new_64bit() -> Self {
        Self::new(8)
    }

    /// Create a generator for 32-bit targets.
    #[must_use]
    pub fn new_32bit() -> Self {
        Self::new(4)
    }

    /// Allocate or retrieve the type variable for `value`.
    ///
    /// # Panics
    /// Panics if the `TypeVar` id space (`u32`) is exhausted (more than
    /// `u32::MAX` distinct variables allocated).
    pub fn type_var_of(&mut self, value: &IlValue) -> TypeVar {
        if let IlValue::Const(c) = value {
            // Constants get a fresh variable each time but are immediately
            // constrained to their value.
            let v = TypeVar::new(self.next_var);
            self.next_var = self.next_var
                .checked_add(1)
                .expect("TypeVar id space exhausted (u32 overflow in next_var)");
            // Infer integer width from magnitude.
            let min_width = const_min_width(*c);
            // Only a NEGATIVE literal is evidence of signedness. A non-negative
            // one fits both a signed and an unsigned type, so it says nothing
            // — `Some(false)` asserted "definitely unsigned", and a variable
            // assigned both `-1` and `5` (ordinary signed code) then raised a
            // `SignednessConflict` that failed the whole unification, taking
            // every unrelated type in the function down with it.
            let signed = if *c < 0 { Some(true) } else { None };
            self.push(TypeConstraint::certain(
                self.next_cid,
                ConstraintKind::IsInteger { var: v, min_width, signed },
                Provenance::new(0, format!("literal {c}")),
            ));
            return v;
        }
        if let Some(&existing) = self.var_map.get(value) {
            return existing;
        }
        let v = TypeVar::new(self.next_var);
        self.next_var = self.next_var
            .checked_add(1)
            .expect("TypeVar id space exhausted (u32 overflow in next_var)");
        self.var_map.insert(value.clone(), v);
        v
    }

    fn push(&mut self, c: TypeConstraint) {
        self.next_cid = self.next_cid
            .checked_add(1)
            .expect("constraint id space exhausted (u32 overflow in next_cid)");
        self.constraints.push(c);
    }

    fn emit(&mut self, kind: ConstraintKind, addr: u64) {
        let id = self.next_cid;
        self.push(TypeConstraint::certain(
            id,
            kind,
            Provenance::new(addr, String::new()),
        ));
    }

    fn emit_heuristic(&mut self, kind: ConstraintKind, addr: u64, confidence: f32) {
        let id = self.next_cid;
        self.push(TypeConstraint::heuristic(
            id,
            kind,
            Provenance::new(addr, String::new()),
            confidence,
        ));
    }

    /// Process one IL instruction and emit constraints.
    pub fn process(&mut self, instr: &IlInstr) {
        match instr {
            IlInstr::Assign { dst, src, addr } => {
                let dst_v = self.type_var_of(dst);
                let src_v = self.type_var_of(src);
                self.emit(ConstraintKind::Equal { lhs: dst_v, rhs: src_v }, *addr);
            }

            IlInstr::Load { dst, ptr, size_bytes, addr } => {
                let dst_v = self.type_var_of(dst);
                let ptr_v = self.type_var_of(ptr);
                self.emit_memory_access(ptr_v, dst_v, *size_bytes, *addr);
            }

            IlInstr::Store { ptr, src, size_bytes, addr } => {
                let src_v = self.type_var_of(src);
                let ptr_v = self.type_var_of(ptr);
                self.emit_memory_access(ptr_v, src_v, *size_bytes, *addr);
            }

            IlInstr::AddressOf { dst, base, offset, scale: _, addr } => {
                let dst_v = self.type_var_of(dst);
                let base_v = self.type_var_of(base);
                let offset_v = self.type_var_of(offset);
                self.emit(
                    ConstraintKind::PointerArithmetic {
                        result: dst_v,
                        base: base_v,
                        offset: offset_v,
                    },
                    *addr,
                );
                self.emit(
                    ConstraintKind::IsInteger {
                        var: dst_v,
                        min_width: self.pointer_width,
                        signed: Some(false),
                    },
                    *addr,
                );
            }

            IlInstr::Call { dst, callee, args, addr } => {
                let callee_v = self.type_var_of(callee);
                let param_count = args.len();
                self.emit(ConstraintKind::IsCallable { callee: callee_v, param_count }, *addr);

                if let Some(ret_val) = dst {
                    let ret_v = self.type_var_of(ret_val);
                    self.emit(ConstraintKind::IsReturnOf { var: ret_v, func: callee_v }, *addr);
                }

                // Each argument generates a parameter constraint (heuristic).
                for (i, arg) in args.iter().enumerate() {
                    let _arg_v = self.type_var_of(arg);
                    // In a full system we'd emit a HasParam constraint here.
                    // For now we note the index in a note.
                    let _ = i; // suppress unused warning
                }
            }

            IlInstr::BinOp { dst, lhs, rhs, op, addr } => {
                let dst_v = self.type_var_of(dst);
                let lhs_v = self.type_var_of(lhs);
                let rhs_v = self.type_var_of(rhs);
                self.process_binop(dst_v, lhs_v, rhs_v, *op, *addr);
            }

            IlInstr::Cast { dst, src: _, to_width, signed, addr } => {
                let dst_v = self.type_var_of(dst);
                self.emit(
                    ConstraintKind::IsInteger { var: dst_v, min_width: *to_width, signed: Some(*signed) },
                    *addr,
                );
            }

            IlInstr::Return { val, addr } => {
                if let Some(v) = val {
                    let _v_var = self.type_var_of(v);
                    // Return type is unified with the function's declared return type
                    // in a full pipeline; here we just ensure the var is registered.
                    let _ = *addr;
                }
            }
        }
    }

    /// Emit the standard pointer + width + value-width triple shared by
    /// `Load` and `Store` instructions.
    fn emit_memory_access(
        &mut self,
        ptr_v: TypeVar,
        value_v: TypeVar,
        size_bytes: u8,
        addr: u64,
    ) {
        // `ptr` must be a pointer to `value`'s type.
        self.emit(
            ConstraintKind::IsPointerTo { ptr: ptr_v, pointee: value_v },
            addr,
        );
        // ptr must be a pointer-width integer (used as an address).
        self.emit(
            ConstraintKind::IsInteger {
                var: ptr_v,
                min_width: self.pointer_width,
                signed: Some(false),
            },
            addr,
        );
        // value has integer type of the access size.
        self.emit(
            ConstraintKind::IsInteger {
                var: value_v,
                min_width: size_bytes,
                signed: None,
            },
            addr,
        );
    }

    fn process_binop(
        &mut self,
        dst_v: TypeVar,
        lhs_v: TypeVar,
        rhs_v: TypeVar,
        op: AbstractBinOp,
        addr: u64,
    ) {
        match op {
            AbstractBinOp::Add | AbstractBinOp::Sub => {
                // Could be pointer arithmetic or integer arithmetic.
                self.emit_heuristic(
                    ConstraintKind::PointerArithmetic {
                        result: dst_v,
                        base: lhs_v,
                        offset: rhs_v,
                    },
                    addr,
                    0.4,
                );
                self.emit_heuristic(
                    ConstraintKind::Equal { lhs: dst_v, rhs: lhs_v },
                    addr,
                    0.6,
                );
            }
            AbstractBinOp::Mul | AbstractBinOp::Div | AbstractBinOp::Mod => {
                self.emit(
                    ConstraintKind::IsInteger {
                        var: dst_v,
                        min_width: 1,
                        signed: None,
                    },
                    addr,
                );
                self.emit(ConstraintKind::Equal { lhs: lhs_v, rhs: dst_v }, addr);
                self.emit(ConstraintKind::Equal { lhs: rhs_v, rhs: dst_v }, addr);
            }
            AbstractBinOp::And | AbstractBinOp::Or | AbstractBinOp::Xor => {
                self.emit(ConstraintKind::Equal { lhs: dst_v, rhs: lhs_v }, addr);
                self.emit(ConstraintKind::Equal { lhs: lhs_v, rhs: rhs_v }, addr);
            }
            AbstractBinOp::Shl | AbstractBinOp::Shr => {
                self.emit(
                    ConstraintKind::IsInteger { var: rhs_v, min_width: 1, signed: Some(false) },
                    addr,
                );
                self.emit(ConstraintKind::Equal { lhs: dst_v, rhs: lhs_v }, addr);
            }
            AbstractBinOp::Cmp => {
                // Comparison result is a boolean (1-byte int).
                self.emit(
                    ConstraintKind::IsInteger { var: dst_v, min_width: 1, signed: Some(false) },
                    addr,
                );
                self.emit(ConstraintKind::Equal { lhs: lhs_v, rhs: rhs_v }, addr);
            }
        }
    }

    /// Process a sequence of IL instructions.
    pub fn process_all(&mut self, instrs: &[IlInstr]) {
        for instr in instrs {
            self.process(instr);
        }
    }

    /// Consume the generator and return the emitted constraints.
    #[must_use]
    pub fn into_constraints(self) -> Vec<TypeConstraint> {
        self.constraints
    }

    /// Borrow the emitted constraints without consuming.
    #[must_use]
    pub fn constraints(&self) -> &[TypeConstraint] {
        &self.constraints
    }

    /// Number of distinct type variables allocated.
    #[must_use]
    pub const fn type_var_count(&self) -> u32 {
        self.next_var
    }

    /// Look up the type variable for an existing IL value (read-only).
    #[must_use]
    pub fn lookup(&self, value: &IlValue) -> Option<TypeVar> {
        self.var_map.get(value).copied()
    }
}

fn const_min_width(c: i64) -> u8 {
    if c >= i64::from(i8::MIN) && c <= i64::from(u8::MAX) {
        1
    } else if c >= i64::from(i16::MIN) && c <= i64::from(u16::MAX) {
        2
    } else if c >= i64::from(i32::MIN) && c <= i64::from(u32::MAX) {
        4
    } else {
        8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintSet — collection helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A filtered view of a constraint set.
#[derive(Debug, Clone, Default)]
pub struct ConstraintSet {
    pub constraints: Vec<TypeConstraint>,
}

impl ConstraintSet {
    /// Create from a raw constraint list.
    #[must_use]
    pub const fn new(constraints: Vec<TypeConstraint>) -> Self {
        Self { constraints }
    }

    /// Retain only constraints with confidence >= `threshold`.
    #[must_use]
    pub fn filter_by_confidence(mut self, threshold: f32) -> Self {
        self.constraints.retain(|c| c.confidence >= threshold);
        self
    }

    /// Return all equality constraints.
    #[must_use]
    pub fn equalities(&self) -> Vec<&TypeConstraint> {
        self.constraints
            .iter()
            .filter(|c| matches!(c.kind, ConstraintKind::Equal { .. }))
            .collect()
    }

    /// Return all pointer constraints.
    #[must_use]
    pub fn pointer_constraints(&self) -> Vec<&TypeConstraint> {
        self.constraints
            .iter()
            .filter(|c| matches!(c.kind, ConstraintKind::IsPointerTo { .. }))
            .collect()
    }

    /// Return all field-access constraints.
    #[must_use]
    pub fn field_accesses(&self) -> Vec<&TypeConstraint> {
        self.constraints
            .iter()
            .filter(|c| matches!(c.kind, ConstraintKind::FieldAccess { .. }))
            .collect()
    }

    /// Number of constraints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u32) -> IlValue {
        IlValue::Temp(n)
    }

    #[test]
    fn test_assign_emits_equality() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        tcg.process(&IlInstr::Assign { dst: t(0), src: t(1), addr: 0x1000 });
        let cs = tcg.into_constraints();
        assert!(cs.iter().any(|c| matches!(c.kind, ConstraintKind::Equal { .. })));
    }

    #[test]
    fn test_load_emits_pointer_constraint() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        tcg.process(&IlInstr::Load { dst: t(0), ptr: t(1), size_bytes: 8, addr: 0x1000 });
        let cs = tcg.into_constraints();
        assert!(cs
            .iter()
            .any(|c| matches!(c.kind, ConstraintKind::IsPointerTo { .. })));
    }

    #[test]
    fn test_store_emits_pointer_constraint() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        tcg.process(&IlInstr::Store { ptr: t(0), src: t(1), size_bytes: 4, addr: 0x2000 });
        let cs = tcg.into_constraints();
        assert!(cs
            .iter()
            .any(|c| matches!(c.kind, ConstraintKind::IsPointerTo { .. })));
    }

    #[test]
    fn test_call_emits_callable_constraint() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        tcg.process(&IlInstr::Call {
            dst: Some(t(0)),
            callee: t(1),
            args: vec![t(2), t(3)],
            addr: 0x3000,
        });
        let cs = tcg.into_constraints();
        assert!(cs.iter().any(|c| matches!(
            c.kind,
            ConstraintKind::IsCallable { param_count: 2, .. }
        )));
        assert!(cs
            .iter()
            .any(|c| matches!(c.kind, ConstraintKind::IsReturnOf { .. })));
    }

    #[test]
    fn test_cast_emits_integer_constraint() {
        let mut tcg = TypeConstraintGenerator::new_32bit();
        tcg.process(&IlInstr::Cast {
            dst: t(0),
            src: t(1),
            to_width: 4,
            signed: true,
            addr: 0x4000,
        });
        let cs = tcg.into_constraints();
        assert!(cs.iter().any(|c| matches!(
            c.kind,
            ConstraintKind::IsInteger { min_width: 4, signed: Some(true), .. }
        )));
    }

    #[test]
    fn test_type_var_reuse() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        let v1a = tcg.type_var_of(&t(5));
        let v1b = tcg.type_var_of(&t(5));
        assert_eq!(v1a, v1b, "same IL value must map to same type var");
    }

    #[test]
    fn test_constraint_set_filter() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        tcg.process(&IlInstr::BinOp {
            dst: t(0),
            lhs: t(1),
            rhs: t(2),
            op: AbstractBinOp::Add,
            addr: 0,
        });
        let cs = ConstraintSet::new(tcg.into_constraints());
        let high = cs.filter_by_confidence(0.9);
        // Only high-confidence constraints should remain.
        for c in &high.constraints {
            assert!(c.confidence >= 0.9);
        }
    }

    #[test]
    fn test_process_all() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        let instrs = vec![
            IlInstr::Assign { dst: t(0), src: IlValue::Const(42), addr: 0 },
            IlInstr::Assign { dst: t(1), src: t(0), addr: 4 },
        ];
        tcg.process_all(&instrs);
        assert!(!tcg.constraints().is_empty());
        assert!(tcg.type_var_count() >= 2);
    }

    /// End-to-end property: for random small access-pattern programs, the
    /// generated constraints solved in the emitted order and in a random
    /// permutation must recover identical types for every variable.
    #[test]
    fn prop_generated_constraints_solve_order_independent() {
        use crate::type_unifier::{TypeUnifier, UnificationResult};
        use crate::TypeVar;

        use crate::test_prng::xorshift as xs;
        fn rv(s: &mut u64) -> IlValue {
            match xs(s) % 3 {
                0 => IlValue::Temp((xs(s) % 5) as u32),
                1 => IlValue::Param((xs(s) % 3) as u32),
                _ => IlValue::Global(0x4000 + (xs(s) % 3) * 8),
            }
        }
        fn random_program(s: &mut u64) -> Vec<IlInstr> {
            let n = 3 + (xs(s) % 6) as usize;
            (0..n)
                .map(|i| {
                    let addr = 0x1000 + i as u64 * 4;
                    match xs(s) % 6 {
                        0 => IlInstr::Assign { dst: rv(s), src: rv(s), addr },
                        1 => IlInstr::Load {
                            dst: rv(s),
                            ptr: rv(s),
                            size_bytes: [1u8, 2, 4, 8][(xs(s) % 4) as usize],
                            addr,
                        },
                        2 => IlInstr::Store {
                            ptr: rv(s),
                            src: rv(s),
                            size_bytes: [1u8, 2, 4, 8][(xs(s) % 4) as usize],
                            addr,
                        },
                        3 => IlInstr::AddressOf {
                            dst: rv(s),
                            base: rv(s),
                            offset: rv(s),
                            scale: 1 + (xs(s) % 8) as u32,
                            addr,
                        },
                        4 => IlInstr::BinOp {
                            dst: rv(s),
                            lhs: rv(s),
                            rhs: rv(s),
                            op: [
                                AbstractBinOp::Add,
                                AbstractBinOp::Mul,
                                AbstractBinOp::Xor,
                                AbstractBinOp::Shl,
                                AbstractBinOp::Cmp,
                            ][(xs(s) % 5) as usize],
                            addr,
                        },
                        _ => IlInstr::Call {
                            dst: Some(rv(s)),
                            callee: rv(s),
                            args: vec![rv(s)],
                            addr,
                        },
                    }
                })
                .collect()
        }
        fn normalize(t: &RecoveredType, res: &UnificationResult, depth: u8) -> RecoveredType {
            if depth == 0 {
                return RecoveredType::Unknown;
            }
            match t {
                RecoveredType::Var(v) => {
                    let inner = res.get(*v);
                    if matches!(inner, RecoveredType::Var(w) if w == v) {
                        RecoveredType::Unknown
                    } else {
                        normalize(inner, res, depth - 1)
                    }
                }
                RecoveredType::Pointer(inner) => {
                    RecoveredType::Pointer(Box::new(normalize(inner, res, depth - 1)))
                }
                other => other.clone(),
            }
        }

        let mut s = 0xfeed_face_1234_5678u64;
        for iter in 0..300 {
            let prog = random_program(&mut s);
            let mut tcg = TypeConstraintGenerator::new_64bit();
            tcg.process_all(&prog);
            let nvars = tcg.type_var_count();
            let cs = tcg.into_constraints();

            let mut permuted = cs.clone();
            for i in (1..permuted.len()).rev() {
                let j = (xs(&mut s) % (i as u64 + 1)) as usize;
                permuted.swap(i, j);
            }

            let r1 = TypeUnifier::new(nvars).solve(&cs);
            let r2 = TypeUnifier::new(nvars).solve(&permuted);
            match (&r1, &r2) {
                (Ok(a), Ok(b)) => {
                    for v in 0..nvars {
                        let ta = normalize(a.get(TypeVar::new(v)), a, 8);
                        let tb = normalize(b.get(TypeVar::new(v)), b, 8);
                        assert_eq!(
                            ta, tb,
                            "iter {iter}: var {v} recovered differently under permutation\nprogram: {prog:?}"
                        );
                    }
                }
                (Err(_), Err(_)) => {}
                _ => panic!(
                    "iter {iter}: Ok/Err depends on constraint order: {r1:?} vs {r2:?}\nprogram: {prog:?}"
                ),
            }
        }
    }

    #[test]
    fn test_cmp_emits_integer_dst() {
        let mut tcg = TypeConstraintGenerator::new_64bit();
        tcg.process(&IlInstr::BinOp {
            dst: t(0),
            lhs: t(1),
            rhs: t(2),
            op: AbstractBinOp::Cmp,
            addr: 0,
        });
        let cs = tcg.into_constraints();
        assert!(cs.iter().any(|c| matches!(
            c.kind,
            ConstraintKind::IsInteger { min_width: 1, .. }
        )));
    }
}
