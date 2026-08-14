//! CIL evaluation-stack type simulator and verifier.
//!
//! Simulates the .NET evaluation stack through a CIL method body to detect
//! stack underflows, overflows, and branch-imbalances (mismatched stack heights
//! at join points).  This is the subset of ECMA-335 §III.1.8 that is needed
//! for de-obfuscation and decompilation.
//!
//! Types: [`StackType`], [`StackState`], [`StackError`], [`JoinPoint`],
//! [`StackVerifier`], [`VerifyResult`].

use std::collections::{BTreeMap, HashMap};
use std::fmt;

// ─── StackType ────────────────────────────────────────────────────────────────

/// The abstract type of a slot on the CIL evaluation stack (ECMA §I.12.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StackType {
    /// `int32` — 32-bit integer (also covers bool, char, i8, i16, u8, u16).
    Int32,
    /// `int64`.
    Int64,
    /// `native int` (pointer-sized integer, `nint` / `nuint`).
    NativeInt,
    /// `F` — floating-point (f32 or f64).
    Float,
    /// `O` — object reference (managed pointer to heap object).
    Object,
    /// `&` — managed pointer (byref).
    ManagedPointer,
    /// `*` — unmanaged pointer.
    UnmanagedPointer,
    /// Value type on the stack — carries the type name for tracking.
    ValueType(String),
    /// Transient pointer (result of `ldflda`, `ldsflda`, etc.).
    TransientPointer,
    /// Unknown / could not determine (conservative fallback).
    Unknown,
}

impl StackType {
    /// True if this type can be used as a boolean test (brtrue / brfalse).
    #[must_use]
    pub const fn is_bool_compatible(&self) -> bool {
        matches!(self, Self::Int32 | Self::Int64 | Self::NativeInt |
                       Self::Object | Self::ManagedPointer | Self::UnmanagedPointer)
    }

    /// True if this type is an integer type.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(self, Self::Int32 | Self::Int64 | Self::NativeInt)
    }

    /// True if this type is a pointer of any kind.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::ManagedPointer | Self::UnmanagedPointer |
                       Self::TransientPointer | Self::Object)
    }

    /// Widen to a common type for arithmetic (ECMA §III.1.5 binary operations).
    #[must_use]
    pub const fn binary_numeric_result(lhs: &Self, rhs: &Self) -> Self {
        match (lhs, rhs) {
            (Self::Int32, Self::Int32) => Self::Int32,
            (Self::Float, Self::Float) => Self::Float,
            (Self::NativeInt, _) | (_, Self::NativeInt) => Self::NativeInt,
            (Self::Int64 | _, Self::Int64) | (Self::Int64, _) => Self::Int64,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for StackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int32 => write!(f, "int32"),
            Self::Int64 => write!(f, "int64"),
            Self::NativeInt => write!(f, "native_int"),
            Self::Float => write!(f, "F"),
            Self::Object => write!(f, "O"),
            Self::ManagedPointer => write!(f, "&"),
            Self::UnmanagedPointer => write!(f, "*"),
            Self::ValueType(n) => write!(f, "valuetype({n})"),
            Self::TransientPointer => write!(f, "transient*"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─── StackState ───────────────────────────────────────────────────────────────

/// The evaluation stack at a particular point in the method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StackState {
    slots: Vec<StackType>,
}

impl StackState {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub const fn with_types(types: Vec<StackType>) -> Self {
        Self { slots: types }
    }

    /// Push a type onto the stack.
    pub fn push(&mut self, ty: StackType) {
        self.slots.push(ty);
    }

    /// Pop a type from the stack.
    ///
    /// # Errors
    /// Returns `StackError::Underflow` if the stack is empty.
    pub fn pop(&mut self) -> Result<StackType, StackError> {
        self.slots.pop().ok_or(StackError::Underflow { offset: 0 })
    }

    /// Peek at the top-of-stack without consuming.
    #[must_use]
    pub fn peek(&self) -> Option<&StackType> {
        self.slots.last()
    }

    /// Stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.slots.len()
    }

    /// True if the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Merge another stack state into this one (join point).
    /// Types are merged conservatively; mismatched depths produce `None`.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Option<Self> {
        if self.slots.len() != other.slots.len() {
            return None;
        }
        let merged = self.slots.iter().zip(&other.slots)
            .map(|(a, b)| merge_types(a, b))
            .collect();
        Some(Self { slots: merged })
    }

    /// Compare depths — compatible if depths match.
    #[must_use]
    pub const fn depth_compatible(&self, other: &Self) -> bool {
        self.slots.len() == other.slots.len()
    }
}

fn merge_types(a: &StackType, b: &StackType) -> StackType {
    if a == b { return a.clone(); }
    match (a, b) {
        (StackType::Int32, StackType::NativeInt) | (StackType::NativeInt, StackType::Int32) =>
            StackType::NativeInt,
        (StackType::Object, _) | (_, StackType::Object) => StackType::Object,
        _ => StackType::Unknown,
    }
}

impl fmt::Display for StackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, ty) in self.slots.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{ty}")?;
        }
        write!(f, "]")
    }
}

// ─── StackError ───────────────────────────────────────────────────────────────

/// An error detected during stack simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackError {
    /// Attempted to pop from an empty stack.
    Underflow { offset: u32 },
    /// Stack exceeded the method's declared maximum stack size.
    Overflow { offset: u32, depth: usize, max: usize },
    /// Two branches reach the same join point with different stack depths.
    ImbalancedBranch {
        join_point: u32,
        depth_a: usize,
        depth_b: usize,
    },
    /// Two branches push incompatible types at the same stack slot.
    TypeMismatch {
        offset: u32,
        slot: usize,
        expected: StackType,
        got: StackType,
    },
    /// Stack not empty on method return path.
    NonEmptyReturn { offset: u32, depth: usize },
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Underflow { offset } =>
                write!(f, "stack underflow at IL_{offset:#x}"),
            Self::Overflow { offset, depth, max } =>
                write!(f, "stack overflow at IL_{offset:#x}: depth={depth} max={max}"),
            Self::ImbalancedBranch { join_point, depth_a, depth_b } =>
                write!(f, "imbalanced branch at IL_{join_point:#x}: {depth_a} vs {depth_b}"),
            Self::TypeMismatch { offset, slot, expected, got } =>
                write!(f, "type mismatch at IL_{offset:#x} slot[{slot}]: expected {expected}, got {got}"),
            Self::NonEmptyReturn { offset, depth } =>
                write!(f, "non-empty stack at ret IL_{offset:#x}: depth={depth}"),
        }
    }
}

// ─── JoinPoint ────────────────────────────────────────────────────────────────

/// A branch join point: a CIL offset that may be reached from multiple paths.
#[derive(Debug, Clone)]
pub struct JoinPoint {
    /// The CIL offset of the join point.
    pub offset: u32,
    /// The stack state expected when entering this block (from first arrival).
    pub expected_state: StackState,
    /// Number of times this join point has been visited.
    pub visit_count: usize,
}

impl JoinPoint {
    #[must_use]
    pub const fn new(offset: u32, state: StackState) -> Self {
        Self { offset, expected_state: state, visit_count: 1 }
    }
}

// ─── VerifyResult ─────────────────────────────────────────────────────────────

/// The result of running the stack verifier over a method.
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// All errors found during verification.
    pub errors: Vec<StackError>,
    /// Stack state at each CIL offset (final state after the instruction).
    pub states: BTreeMap<u32, StackState>,
    /// All detected join points.
    pub join_points: Vec<JoinPoint>,
}

impl VerifyResult {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Number of distinct stack depths encountered.
    #[must_use]
    pub fn unique_depths(&self) -> Vec<usize> {
        let mut depths: Vec<usize> = self.states.values().map(StackState::depth).collect();
        depths.sort_unstable();
        depths.dedup();
        depths
    }
}

// ─── StackEffect ─────────────────────────────────────────────────────────────

/// The stack effect of a CIL opcode: how many slots it pops and what it pushes.
#[derive(Debug, Clone)]
pub struct StackEffect {
    /// Number of slots popped.
    pub pop: usize,
    /// Types pushed (empty = nothing pushed).
    pub push: Vec<StackType>,
}

impl StackEffect {
    #[must_use]
    pub const fn new(pop: usize, push: Vec<StackType>) -> Self {
        Self { pop, push }
    }

    #[must_use]
    pub const fn nop() -> Self {
        Self { pop: 0, push: Vec::new() }
    }
}

/// Approximate stack effect for a CIL mnemonic.
///
/// This is intentionally conservative: unknown instructions return `Unknown`
/// pushes so the verifier can still track depth even for opcodes not listed.
#[must_use]
pub fn stack_effect_of(mnemonic: &str) -> StackEffect {
    match mnemonic {
        // ── Constants ──────────────────────────────────────────────────────
        "ldc.i8" => StackEffect::new(0, vec![StackType::Int64]),
        "ldc.r4" | "ldc.r8" => StackEffect::new(0, vec![StackType::Float]),
        "ldnull" | "ldstr" | "newobj" => StackEffect::new(0, vec![StackType::Object]),
        // ── Load argument / local ──────────────────────────────────────────
        "ldarga.s" | "ldarga" | "ldloca.s" | "ldloca" =>
            StackEffect::new(0, vec![StackType::ManagedPointer]),

        // ── Store argument / local ─────────────────────────────────────────
        "starg.s" | "starg" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3"
        | "stloc.s" | "stloc" | "pop" | "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s" | "initobj" | "throw" | "rethrow" => StackEffect::new(1, vec![]),

        // ── Arithmetic ────────────────────────────────────────────────────
        "add" | "sub" | "mul" | "div" | "rem" | "and" | "or" | "xor"
        | "shl" | "shr" | "shr.un"
        | "add.ovf" | "add.ovf.un" | "sub.ovf" | "sub.ovf.un"
        | "mul.ovf" | "mul.ovf.un" | "div.un" | "rem.un" =>
            StackEffect::new(2, vec![StackType::Unknown]),
        "neg" | "not" | "ldobj" | "ldfld" | "ldsfld" | "refanytype" | "refanyval" => StackEffect::new(1, vec![StackType::Unknown]),

        // ── Comparisons ───────────────────────────────────────────────────
        "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" | "ldelem.i1" | "ldelem.i2" | "ldelem.i4" | "ldelem.u1" | "ldelem.u2" | "ldelem.u4" =>
            StackEffect::new(2, vec![StackType::Int32]),

        // ── Conversions ───────────────────────────────────────────────────
        "conv.i" | "conv.u" | "ldind.i" | "ldind.u" | "ldlen" => StackEffect::new(1, vec![StackType::NativeInt]),
        "conv.i1" | "conv.i2" | "conv.i4" | "conv.u1" | "conv.u2" | "conv.u4"
        | "conv.ovf.i1" | "conv.ovf.i2" | "conv.ovf.i4"
        | "conv.ovf.u1" | "conv.ovf.u2" | "conv.ovf.u4"
        | "conv.ovf.i1.un" | "conv.ovf.i2.un" | "conv.ovf.i4.un"
        | "conv.ovf.u1.un" | "conv.ovf.u2.un" | "conv.ovf.u4.un" | "ldind.i1" | "ldind.i2" | "ldind.i4" | "ldind.u1" | "ldind.u2" | "ldind.u4" =>
            StackEffect::new(1, vec![StackType::Int32]),
        "conv.i8" | "conv.u8" | "conv.ovf.i8" | "conv.ovf.u8"
        | "conv.ovf.i8.un" | "conv.ovf.u8.un" | "ldind.i8" | "ldind.u8" =>
            StackEffect::new(1, vec![StackType::Int64]),
        "conv.r4" | "conv.r8" | "conv.r.un" | "ldind.r4" | "ldind.r8" =>
            StackEffect::new(1, vec![StackType::Float]),

        // ── Stack manipulation ────────────────────────────────────────────
        "dup" => StackEffect::new(1, vec![StackType::Unknown, StackType::Unknown]),
        "nop" | "break" | "br" | "br.s" | "leave" | "leave.s" | "ret" | "endfinally" | "endfilter" => StackEffect::nop(),

        // ── Branches ─────────────────────────────────────────────────────
        "beq" | "beq.s" | "bge" | "bge.s" | "bge.un" | "bge.un.s"
        | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s"
        | "ble" | "ble.s" | "ble.un" | "ble.un.s"
        | "blt" | "blt.s" | "blt.un" | "blt.un.s"
        | "bne.un" | "bne.un.s" | "stobj" | "stind.i" | "stind.i1" | "stind.i2" | "stind.i4" | "stind.i8"
        | "stind.r4" | "stind.r8" | "stind.ref" | "stfld" | "stsfld" => StackEffect::new(2, vec![]),

        // ── Object model ─────────────────────────────────────────────────
        // pops n args, simplified
        "ldind.ref" | "ldelem.ref" | "newarr" | "isinst" | "castclass" | "box" | "unbox.any" | "unbox" => StackEffect::new(1, vec![StackType::Object]),
        "ldflda" | "ldsflda" => StackEffect::new(1, vec![StackType::TransientPointer]),
        "ldelema" => StackEffect::new(2, vec![StackType::ManagedPointer]),
        "ldelem.i" | "ldelem.u" => StackEffect::new(2, vec![StackType::NativeInt]),
        "ldelem.i8" | "ldelem.u8" => StackEffect::new(2, vec![StackType::Int64]),
        "ldelem.r4" | "ldelem.r8" => StackEffect::new(2, vec![StackType::Float]),
        "stelem.i" | "stelem.i1" | "stelem.i2" | "stelem.i4" | "stelem.i8"
        | "stelem.r4" | "stelem.r8" | "stelem.ref" | "stelem" => StackEffect::new(3, vec![]),
        // ── Method calls ─────────────────────────────────────────────────
        // ── Misc ──────────────────────────────────────────────────────────
        "ldc.i4" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2" | "ldc.i4.3"
        | "ldc.i4.4" | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8"
        | "ldc.i4.m1" | "ldc.i4.s" | "sizeof" => StackEffect::new(0, vec![StackType::Int32]),
        "localloc" => StackEffect::new(1, vec![StackType::UnmanagedPointer]),
        "mkrefany" => StackEffect::new(1, vec![StackType::ValueType("TypedReference".into())]),
        _ => StackEffect::new(0, vec![StackType::Unknown]),
    }
}

// ─── StackVerifier ────────────────────────────────────────────────────────────

/// Simulates the CIL evaluation stack and collects errors.
pub struct StackVerifier {
    max_stack: usize,
    /// Per-offset join state: expected `StackState` when first arrived.
    join_states: HashMap<u32, StackState>,
}

impl StackVerifier {
    #[must_use]
    pub fn new(max_stack: usize) -> Self {
        Self { max_stack, join_states: HashMap::new() }
    }

    /// Simulate the method. `instructions` must be sorted by offset.
    ///
    /// Returns a `VerifyResult` with any detected errors and per-offset states.
    #[must_use]
    pub fn verify(&mut self, instructions: &[crate::cil_control_flow::CilInstruction]) -> VerifyResult {
        let mut result = VerifyResult::default();
        if instructions.is_empty() { return result; }

        // Worklist: (offset_index, stack_state_on_entry).
        let mut worklist: Vec<(usize, StackState)> = vec![(0, StackState::new())];
        let mut visited: HashMap<usize, StackState> = HashMap::new();

        // Build offset → index map.
        let offset_map: HashMap<u32, usize> = instructions.iter()
            .enumerate()
            .map(|(i, insn)| (insn.offset, i))
            .collect();

        while let Some((idx, state_in)) = worklist.pop() {
            if idx >= instructions.len() { continue; }
            let insn = &instructions[idx];

            // Join-point check.
            if let Some(prev) = visited.get(&idx) {
                if !prev.depth_compatible(&state_in) {
                    result.errors.push(StackError::ImbalancedBranch {
                        join_point: insn.offset,
                        depth_a: prev.depth(),
                        depth_b: state_in.depth(),
                    });
                    continue;
                }
                // Already visited at this depth, skip.
                continue;
            }
            visited.insert(idx, state_in.clone());

            let mut state = state_in.clone();

            // Apply the instruction's stack effect.
            let effect = stack_effect_of(&insn.mnemonic);

            // Pop.
            for _ in 0..effect.pop {
                if state.pop().is_ok() {} else {
                    result.errors.push(StackError::Underflow { offset: insn.offset });
                    break;
                }
            }

            // Push.
            for ty in &effect.push {
                state.push(ty.clone());
                if state.depth() > self.max_stack {
                    result.errors.push(StackError::Overflow {
                        offset: insn.offset,
                        depth: state.depth(),
                        max: self.max_stack,
                    });
                    break;
                }
            }

            result.states.insert(insn.offset, state.clone());

            // Schedule successors.
            if insn.is_terminator {
                // ret: stack should be empty (simplified: depth 0 or 1 for non-void).
                continue;
            }

            // Branch targets.
            for &tgt in &insn.branch_targets {
                if let Some(&ti) = offset_map.get(&tgt)
                    && !visited.contains_key(&ti) {
                        worklist.push((ti, state.clone()));
                    }
            }

            // Fallthrough.
            if insn.is_unconditional_branch { continue; }
            let next = idx + 1;
            if next < instructions.len() && !visited.contains_key(&next) {
                worklist.push((next, state.clone()));
            }
        }

        // Populate join points.
        for (offset, state) in &self.join_states {
            result.join_points.push(JoinPoint::new(*offset, state.clone()));
        }

        result
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cil_control_flow::CilInstruction;

    fn insn_simple(off: u32, mnem: &str) -> CilInstruction {
        let mut i = CilInstruction::new(off, mnem, 1);
        if mnem == "ret" { i.is_terminator = true; }
        i
    }

    #[test]
    fn stack_type_display() {
        assert_eq!(StackType::Int32.to_string(), "int32");
        assert_eq!(StackType::Object.to_string(), "O");
        assert_eq!(StackType::ValueType("Foo".into()).to_string(), "valuetype(Foo)");
    }

    #[test]
    fn stack_type_bool_compat() {
        assert!(StackType::Int32.is_bool_compatible());
        assert!(StackType::Object.is_bool_compatible());
        assert!(!StackType::Float.is_bool_compatible());
    }

    #[test]
    fn stack_type_binary_numeric() {
        assert_eq!(StackType::binary_numeric_result(&StackType::Int32, &StackType::Int32), StackType::Int32);
        assert_eq!(StackType::binary_numeric_result(&StackType::Int64, &StackType::Int64), StackType::Int64);
        assert_eq!(StackType::binary_numeric_result(&StackType::Int32, &StackType::NativeInt), StackType::NativeInt);
    }

    #[test]
    fn stack_state_push_pop() {
        let mut s = StackState::new();
        s.push(StackType::Int32);
        s.push(StackType::Int64);
        assert_eq!(s.depth(), 2);
        assert_eq!(s.pop().unwrap(), StackType::Int64);
        assert_eq!(s.depth(), 1);
    }

    #[test]
    fn stack_state_underflow() {
        let mut s = StackState::new();
        assert!(s.pop().is_err());
    }

    #[test]
    fn stack_state_merge_same() {
        let s1 = StackState::with_types(vec![StackType::Int32]);
        let s2 = StackState::with_types(vec![StackType::Int32]);
        let m = s1.merge(&s2).unwrap();
        assert_eq!(m.depth(), 1);
        assert_eq!(m.peek(), Some(&StackType::Int32));
    }

    #[test]
    fn stack_state_merge_depth_mismatch() {
        let s1 = StackState::with_types(vec![StackType::Int32]);
        let s2 = StackState::new();
        assert!(s1.merge(&s2).is_none());
    }

    #[test]
    fn stack_effect_nop() {
        let e = stack_effect_of("nop");
        assert_eq!(e.pop, 0);
        assert!(e.push.is_empty());
    }

    #[test]
    fn stack_effect_ldc_i4() {
        let e = stack_effect_of("ldc.i4.0");
        assert_eq!(e.pop, 0);
        assert_eq!(e.push, vec![StackType::Int32]);
    }

    #[test]
    fn stack_effect_add() {
        let e = stack_effect_of("add");
        assert_eq!(e.pop, 2);
        assert_eq!(e.push.len(), 1);
    }

    #[test]
    fn stack_effect_dup() {
        let e = stack_effect_of("dup");
        assert_eq!(e.pop, 1);
        assert_eq!(e.push.len(), 2);
    }

    #[test]
    fn verify_simple_method() {
        // ldc.i4.0, ret
        let insns = vec![
            insn_simple(0, "ldc.i4.0"),
            insn_simple(1, "ret"),
        ];
        let mut v = StackVerifier::new(8);
        let result = v.verify(&insns);
        assert!(result.is_valid());
        assert_eq!(result.states[&0].depth(), 1);
    }

    #[test]
    fn verify_underflow_detected() {
        let insns = vec![
            insn_simple(0, "pop"), // pop on empty stack
            insn_simple(1, "ret"),
        ];
        let mut v = StackVerifier::new(8);
        let result = v.verify(&insns);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| matches!(e, StackError::Underflow { .. })));
    }

    #[test]
    fn stack_error_display() {
        let e = StackError::Underflow { offset: 0x10 };
        assert!(e.to_string().contains("underflow"));
        let e2 = StackError::ImbalancedBranch { join_point: 5, depth_a: 1, depth_b: 0 };
        assert!(e2.to_string().contains("imbalanced"));
    }

    #[test]
    fn stack_state_display() {
        let s = StackState::with_types(vec![StackType::Int32, StackType::Object]);
        let d = s.to_string();
        assert!(d.contains("int32"));
        assert!(d.contains('O'));
    }

    #[test]
    fn verify_result_unique_depths() {
        let mut r = VerifyResult::default();
        r.states.insert(0, StackState::with_types(vec![StackType::Int32]));
        r.states.insert(1, StackState::new());
        let depths = r.unique_depths();
        assert!(depths.contains(&0));
        assert!(depths.contains(&1));
    }
}
