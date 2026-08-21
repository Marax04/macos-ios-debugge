//! CIL evaluation stack tracker.
//!
//! Simulates push/pop for every CIL opcode to track the type state of the
//! evaluation stack at each instruction offset.  Used by the decompiler and
//! verifier to infer expression types and detect ill-formed method bodies.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{CilDecodeError, CilInstr};

// ── StackType ─────────────────────────────────────────────────────────────────

/// CLR-level stack type as specified by ECMA-335 §III.1.8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackType {
    /// Native integer / managed pointer.
    NativeInt,
    /// 32-bit integer (covers bool, char, i8, u8, i16, u16, i32, u32).
    Int32,
    /// 64-bit integer.
    Int64,
    /// 32-bit float.
    Float32,
    /// 64-bit float (all floats are widened to F on the stack).
    Float64,
    /// Managed object reference.
    ObjectRef,
    /// Managed pointer (`&T`).
    ManagedPtr,
    /// Unmanaged pointer (`*T`).
    UnmanagedPtr,
    /// Value type (struct) with a metadata token.
    ValueType(u32),
    /// Unknown / not yet determined.
    Unknown,
}

impl fmt::Display for StackType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeInt => write!(f, "I"),
            Self::Int32 => write!(f, "I4"),
            Self::Int64 => write!(f, "I8"),
            Self::Float32 => write!(f, "F4"),
            Self::Float64 => write!(f, "F8"),
            Self::ObjectRef => write!(f, "O"),
            Self::ManagedPtr => write!(f, "&"),
            Self::UnmanagedPtr => write!(f, "*"),
            Self::ValueType(tok) => write!(f, "VT({tok:#010x})"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

impl StackType {
    /// Returns `true` if this type is a numeric integer on the stack.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(self, Self::Int32 | Self::Int64 | Self::NativeInt)
    }

    /// Returns `true` if this type is a floating-point value on the stack.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float32 | Self::Float64)
    }

    /// Returns `true` if this type is a reference (object or pointer).
    #[must_use]
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::ObjectRef | Self::ManagedPtr | Self::UnmanagedPtr)
    }
}

// ── StackSlot ─────────────────────────────────────────────────────────────────

/// A single slot on the CIL evaluation stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSlot {
    /// The CLR-level type of this slot.
    pub ty: StackType,
    /// Optional metadata token associated with this slot (e.g., for `ldtoken`).
    pub token: Option<u32>,
    /// Instruction offset that pushed this value onto the stack.
    pub pushed_at: u32,
}

impl StackSlot {
    /// Create a new slot.
    #[must_use]
    pub const fn new(ty: StackType, pushed_at: u32) -> Self {
        Self {
            ty,
            token: None,
            pushed_at,
        }
    }

    /// Create a slot with an associated metadata token.
    #[must_use]
    pub const fn with_token(ty: StackType, token: u32, pushed_at: u32) -> Self {
        Self {
            ty,
            token: Some(token),
            pushed_at,
        }
    }
}

impl fmt::Display for StackSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@+{}", self.ty, self.pushed_at)
    }
}

// ── CilStack ──────────────────────────────────────────────────────────────────

/// The CIL evaluation stack at a single point in a method body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CilStack {
    slots: Vec<StackSlot>,
}

impl CilStack {
    /// Create an empty stack.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Push a slot onto the stack.
    pub fn push(&mut self, slot: StackSlot) {
        self.slots.push(slot);
    }

    /// Pop and return the top slot, or `None` if the stack is empty.
    pub fn pop(&mut self) -> Option<StackSlot> {
        self.slots.pop()
    }

    /// Peek at the top slot without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&StackSlot> {
        self.slots.last()
    }

    /// Current stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.slots.len()
    }

    /// Returns `true` if the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Return a clone of all slots from bottom to top.
    #[must_use]
    pub fn as_slice(&self) -> &[StackSlot] {
        &self.slots
    }

    /// Duplicate the top element (implements `dup`).
    ///
    /// # Errors
    /// Returns `StackError::Underflow` if the stack is empty.
    pub fn dup(&mut self, offset: u32) -> Result<(), StackError> {
        let top = self.peek().ok_or(StackError::Underflow)?.clone();
        self.push(StackSlot::new(top.ty, offset));
        Ok(())
    }

    /// Check that the stack has at least `n` items.
    ///
    /// # Errors
    /// Returns `StackError::Underflow` if there are fewer than `n` items.
    pub const fn require(&self, n: usize) -> Result<(), StackError> {
        if self.slots.len() < n {
            Err(StackError::Underflow)
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for CilStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stack[")?;
        for (i, slot) in self.slots.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{slot}")?;
        }
        write!(f, "]")
    }
}

// ── StackError ────────────────────────────────────────────────────────────────

/// Errors produced by the stack tracker.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum StackError {
    #[error("stack underflow at offset {0:#010x}")]
    UnderflowAt(u32),
    #[error("stack underflow")]
    Underflow,
    #[error("type mismatch: expected {expected}, got {got} at offset {offset:#010x}")]
    TypeMismatch {
        expected: String,
        got: String,
        offset: u32,
    },
    #[error("max stack exceeded: depth {depth} > max {max_stack}")]
    MaxStackExceeded { depth: usize, max_stack: u16 },
    #[error("decode error: {0}")]
    Decode(String),
    #[error("stack not empty at return: depth {0}")]
    NonEmptyAtReturn(usize),
}

impl From<CilDecodeError> for StackError {
    fn from(e: CilDecodeError) -> Self {
        Self::Decode(e.to_string())
    }
}

// ── Stack effect helper ───────────────────────────────────────────────────────

/// Describes what a single CIL opcode does to the evaluation stack.
#[derive(Debug, Clone)]
pub struct StackEffect {
    /// Number of slots popped.
    pub pops: u8,
    /// Slots pushed (in order from bottom to top).
    pub pushes: Vec<StackType>,
}

impl StackEffect {
    const fn none() -> Self {
        Self {
            pops: 0,
            pushes: vec![],
        }
    }
    const fn pop1() -> Self {
        Self {
            pops: 1,
            pushes: vec![],
        }
    }
    const fn pop2() -> Self {
        Self {
            pops: 2,
            pushes: vec![],
        }
    }
    fn push1(ty: StackType) -> Self {
        Self {
            pops: 0,
            pushes: vec![ty],
        }
    }
    fn pop1_push1(ty: StackType) -> Self {
        Self {
            pops: 1,
            pushes: vec![ty],
        }
    }
    fn pop2_push1(ty: StackType) -> Self {
        Self {
            pops: 2,
            pushes: vec![ty],
        }
    }
}

/// Compute the stack effect of a decoded CIL instruction.
#[must_use]
pub fn stack_effect_of(instr: &CilInstr) -> StackEffect {
    match instr.mnemonic.as_str() {
        // --- no effect ---
        // --- load argument / local → push I4/O ---
        "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3" | "ldarg.s" | "ldarg" | "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldloc" => {
            StackEffect::push1(StackType::Unknown)
        }
        // --- store argument / local → pop 1 ---
        "starg.s" | "starg" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s"
        | "stloc" | "pop" | "ret" | "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s" | "switch" | "stsfld" | "throw" | "initobj" => StackEffect::pop1(),

        // --- load address → push managed ptr ---
        "ldarga.s" | "ldarga" | "ldloca.s" | "ldloca" => {
            StackEffect::push1(StackType::ManagedPtr)
        }

        // --- constants → push I4 ---
        "ldnull" | "newobj" | "ldstr" => StackEffect::push1(StackType::ObjectRef),
        "ldc.i4.m1" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2" | "ldc.i4.3" | "ldc.i4.4"
        | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8" | "ldc.i4.s" | "ldc.i4" => {
            StackEffect::push1(StackType::Int32)
        }
        "ldc.i8" => StackEffect::push1(StackType::Int64),
        "ldc.r4" => StackEffect::push1(StackType::Float32),
        "ldc.r8" => StackEffect::push1(StackType::Float64),

        // --- dup / pop ---
        "dup" => StackEffect {
            pops: 0,
            pushes: vec![StackType::Unknown, StackType::Unknown],
        },
        // --- call / newobj / ret ---
        "call" | "callvirt" | "calli" => StackEffect {
            pops: 0, // variable; simplified
            pushes: vec![StackType::Unknown],
        },
        // --- branches --- consume 0–2 stack items, push nothing ---
        "beq" | "beq.s" | "bge" | "bge.s" | "bgt" | "bgt.s" | "ble" | "ble.s" | "blt"
        | "blt.s" | "bne.un" | "bne.un.s" | "bge.un" | "bge.un.s" | "bgt.un" | "bgt.un.s"
        | "ble.un" | "ble.un.s" | "blt.un" | "blt.un.s" | "stind.ref" | "stind.i1" | "stind.i2" | "stind.i4" | "stind.i8" | "stind.r4"
        | "stind.r8" | "stind.i" | "stfld" | "stobj" | "cpobj" => StackEffect::pop2(),
        // --- indirect loads --- pop ptr, push value ---
        "ldind.i1" | "ldind.u1" | "ldind.i2" | "ldind.u2" | "ldind.i4" | "ldind.u4" | "conv.i1" | "conv.i2" | "conv.i4" | "conv.u1" | "conv.u2" | "conv.u4"
        | "conv.ovf.i1" | "conv.ovf.i2" | "conv.ovf.i4" | "conv.ovf.u1" | "conv.ovf.u2"
        | "conv.ovf.u4" | "conv.ovf.i1.un" | "conv.ovf.i2.un" | "conv.ovf.i4.un"
        | "conv.ovf.u1.un" | "conv.ovf.u2.un" | "conv.ovf.u4.un" => {
            StackEffect::pop1_push1(StackType::Int32)
        }
        "ldind.i8" | "ldind.u8" | "conv.i8" | "conv.u8" | "conv.ovf.i8" | "conv.ovf.u8" | "conv.ovf.i8.un"
        | "conv.ovf.u8.un" => StackEffect::pop1_push1(StackType::Int64),
        "ldind.i" | "conv.i" | "conv.u" | "conv.ovf.i" | "conv.ovf.u" | "conv.ovf.i.un"
        | "conv.ovf.u.un" | "ldvirtftn" | "ldlen" | "localloc" => StackEffect::pop1_push1(StackType::NativeInt),
        "ldind.r4" | "conv.r4" => StackEffect::pop1_push1(StackType::Float32),
        "ldind.r8" | "conv.r8" | "conv.r.un" | "ckfinite" => StackEffect::pop1_push1(StackType::Float64),
        "ldind.ref" | "box" | "isinst" | "castclass" | "newarr" => StackEffect::pop1_push1(StackType::ObjectRef),

        // --- indirect stores --- pop value + ptr ---
        // --- arithmetic / logic --- pop2 push1 ---
        "add" | "sub" | "mul" | "div" | "div.un" | "rem" | "rem.un" | "and" | "or" | "xor"
        | "shl" | "shr" | "shr.un" | "ldelem" | "ldelem.i1" | "ldelem.u1" | "ldelem.i2" | "ldelem.u2" | "ldelem.i4"
        | "ldelem.u4" | "ldelem.i8" | "ldelem.i" | "ldelem.r4" | "ldelem.r8"
        | "ldelem.ref" => StackEffect::pop2_push1(StackType::Unknown),
        "neg" | "not" | "ldfld" | "ldsfld" | "ldobj" | "unbox" | "unbox.any" => StackEffect::pop1_push1(StackType::Unknown),

        // --- conversions --- pop1 push1 ---
        // --- object model ---
        "ldflda" | "ldsflda" => StackEffect::pop1_push1(StackType::ManagedPtr),
        "ldtoken" | "ldftn" | "arglist" => StackEffect::push1(StackType::NativeInt),
        "ldelema" => StackEffect::pop2_push1(StackType::ManagedPtr),
        "stelem" | "stelem.i" | "stelem.i1" | "stelem.i2" | "stelem.i4" | "stelem.i8"
        | "stelem.r4" | "stelem.r8" | "stelem.ref" | "cpblk" | "initblk" => StackEffect {
            pops: 3,
            pushes: vec![],
        },

        // --- exception handling ---
        // --- overflow arithmetic ---
        "add.ovf" | "add.ovf.un" | "sub.ovf" | "sub.ovf.un" | "mul.ovf" | "mul.ovf.un" => {
            StackEffect::pop2_push1(StackType::Unknown)
        }

        // --- comparison ---
        "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" => {
            StackEffect::pop2_push1(StackType::Int32)
        }

        // --- misc ---
        "sizeof" => StackEffect::push1(StackType::Int32),
        "refanyval" | "mkrefany" | "refanytype" => {
            StackEffect::pop1_push1(StackType::Unknown)
        }
        "constrained" | "volatile" | "unaligned" | "tail" | "readonly" | "no" => {
            StackEffect::none()
        }

        _ => StackEffect::none(),
    }
}

// ── StackVerifier ─────────────────────────────────────────────────────────────

/// Tracks the stack state at every instruction offset and validates it.
pub struct StackVerifier {
    /// Max stack depth declared in the fat method header.
    pub max_stack: u16,
    /// Recorded stack state at each byte offset.
    pub states: HashMap<u32, CilStack>,
    /// Errors found during verification.
    pub errors: Vec<StackError>,
}

impl StackVerifier {
    /// Create a new verifier for a method with the given max-stack value.
    #[must_use]
    pub fn new(max_stack: u16) -> Self {
        Self {
            max_stack,
            states: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Run the verifier over raw CIL bytecode.
    ///
    /// Simulates the stack state linearly through the code.  Branch merging
    /// is not implemented (i.e., this is a linear-pass approximation).
    ///
    /// # Errors
    /// Returns all accumulated errors in `self.errors` after the pass.
    pub fn verify(&mut self, code: &[u8]) {
        let mut stack = CilStack::new();
        let mut offset = 0u32;

        while (offset as usize) < code.len() {
            let remaining = &code[offset as usize..];
            let (instr, size) = match CilInstr::decode(remaining) {
                Ok(pair) => pair,
                Err(e) => {
                    self.errors.push(StackError::Decode(e.to_string()));
                    break;
                }
            };

            self.states.insert(offset, stack.clone());

            let effect = stack_effect_of(&instr);

            // Pop
            for _ in 0..effect.pops {
                if stack.pop().is_none() {
                    self.errors.push(StackError::UnderflowAt(offset));
                }
            }

            // Push
            for pushed_ty in effect.pushes {
                stack.push(StackSlot::new(pushed_ty, offset));
            }

            // Handle dup explicitly
            if instr.mnemonic == "dup" {
                // stack_effect_of already returned Unknown×2, but we need to
                // preserve the original type.  Correct the last two slots.
                if let Some(third_from_top) = {
                    let depth = stack.depth();
                    if depth >= 2 {
                        stack.as_slice().get(depth - 2).cloned()
                    } else {
                        None
                    }
                } {
                    // Replace top with a copy of the element below it.
                    if let Some(top) = stack.slots.last_mut() {
                        top.ty = third_from_top.ty;
                    }
                }
            }

            // Depth check
            if stack.depth() > self.max_stack as usize {
                self.errors.push(StackError::MaxStackExceeded {
                    depth: stack.depth(),
                    max_stack: self.max_stack,
                });
            }

            // `size` is one decoded instruction length; the CIL encoding caps it far
            // below `u32::MAX`, and a malformed value saturates instead of wrapping.
            offset = offset.saturating_add(u32::try_from(size).unwrap_or(u32::MAX));
            // Record post-execution state so max_observed_depth includes the
            // depth reached after the last push (the final state would otherwise
            // be missed because `states` is keyed by pre-execution offsets).
            self.states.insert(offset, stack.clone());
        }
    }

    /// Returns `true` if no errors were detected.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Stack state at the given byte offset (or `None` if not visited).
    #[must_use]
    pub fn state_at(&self, offset: u32) -> Option<&CilStack> {
        self.states.get(&offset)
    }

    /// Maximum stack depth actually observed.
    #[must_use]
    pub fn max_observed_depth(&self) -> usize {
        self.states.values().map(CilStack::depth).max().unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_push_pop() {
        let mut s = CilStack::new();
        s.push(StackSlot::new(StackType::Int32, 0));
        assert_eq!(s.depth(), 1);
        let slot = s.pop().unwrap();
        assert_eq!(slot.ty, StackType::Int32);
        assert!(s.is_empty());
    }

    #[test]
    fn test_stack_dup() {
        let mut s = CilStack::new();
        s.push(StackSlot::new(StackType::Int64, 0));
        assert!(s.dup(4).is_ok());
        assert_eq!(s.depth(), 2);
    }

    #[test]
    fn test_stack_dup_empty_underflow() {
        let mut s = CilStack::new();
        assert!(s.dup(0).is_err());
    }

    #[test]
    fn test_stack_type_integer() {
        assert!(StackType::Int32.is_integer());
        assert!(StackType::NativeInt.is_integer());
        assert!(!StackType::Float64.is_integer());
    }

    #[test]
    fn test_stack_type_reference() {
        assert!(StackType::ObjectRef.is_reference());
        assert!(StackType::ManagedPtr.is_reference());
        assert!(!StackType::Int32.is_reference());
    }

    #[test]
    fn test_stack_effect_nop() {
        let (instr, _) = CilInstr::decode(&[0x00]).unwrap(); // nop
        let eff = stack_effect_of(&instr);
        assert_eq!(eff.pops, 0);
        assert!(eff.pushes.is_empty());
    }

    #[test]
    fn test_stack_effect_ldc_i4_0() {
        let (instr, _) = CilInstr::decode(&[0x16]).unwrap(); // ldc.i4.0
        let eff = stack_effect_of(&instr);
        assert_eq!(eff.pops, 0);
        assert_eq!(eff.pushes.len(), 1);
        assert_eq!(eff.pushes[0], StackType::Int32);
    }

    #[test]
    fn test_stack_effect_add_pops_two() {
        let (instr, _) = CilInstr::decode(&[0x58]).unwrap(); // add
        let eff = stack_effect_of(&instr);
        assert_eq!(eff.pops, 2);
        assert_eq!(eff.pushes.len(), 1);
    }

    #[test]
    fn test_stack_effect_ret_pops_one() {
        let (instr, _) = CilInstr::decode(&[0x2a]).unwrap(); // ret
        let eff = stack_effect_of(&instr);
        assert_eq!(eff.pops, 1);
        assert!(eff.pushes.is_empty());
    }

    #[test]
    fn test_verifier_simple_program() {
        // ldc.i4.1  ldc.i4.2  add  ret
        let code = [0x17u8, 0x18, 0x58, 0x2a];
        let mut v = StackVerifier::new(8);
        v.verify(&code);
        assert!(v.is_valid(), "errors: {:?}", v.errors);
    }

    #[test]
    fn test_verifier_tracks_states() {
        let code = [0x17u8, 0x2a]; // ldc.i4.1  ret
        let mut v = StackVerifier::new(8);
        v.verify(&code);
        assert!(v.state_at(0).is_some());
        assert!(v.state_at(1).is_some());
    }

    #[test]
    fn test_verifier_max_depth() {
        // Push four I4 constants onto the stack.
        let code = [0x17u8, 0x18, 0x19, 0x1a]; // 1,2,3,4
        let mut v = StackVerifier::new(8);
        v.verify(&code);
        assert_eq!(v.max_observed_depth(), 4);
    }

    #[test]
    fn test_verifier_underflow_detected() {
        // pop on empty stack: ldc.i4.0  pop  pop
        let code = [0x16u8, 0x26, 0x26];
        let mut v = StackVerifier::new(8);
        v.verify(&code);
        assert!(!v.is_valid());
        assert!(v.errors.iter().any(|e| matches!(e, StackError::UnderflowAt(_))));
    }

    #[test]
    fn test_slot_display() {
        let slot = StackSlot::new(StackType::Int32, 8);
        let s = slot.to_string();
        assert!(s.contains("I4"));
    }

    #[test]
    fn test_cil_stack_display() {
        let mut s = CilStack::new();
        s.push(StackSlot::new(StackType::Int32, 0));
        s.push(StackSlot::new(StackType::ObjectRef, 1));
        let repr = s.to_string();
        assert!(repr.contains("I4"));
        assert!(repr.contains('O'));
    }
}
