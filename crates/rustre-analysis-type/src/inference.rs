//! `inference` — multi-level type inference engine.
//!
//! Six progressively finer inference levels are applied to recover types from
//! stripped binary analysis:
//!
//! | Level | Evidence                           | Conclusion              |
//! |-------|------------------------------------|-------------------------|
//! | 1     | Memory-access width                | Integer size            |
//! | 2     | SAR/IDIV/IMUL vs SHR/DIV/MOVZX    | Signedness              |
//! | 3     | LOAD/STORE dereference / LEA       | Pointer                 |
//! | 4     | Multiple ptr+n field accesses      | Struct                  |
//! | 5     | base + index * elem_size pattern   | Array                   |
//! | 6     | [ptr+0] indirect call              | VTable pointer (C++ oo) |

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    TypeFact,
    constraints::{Address, ConstraintFact, VarRef},
};

// ── Instruction model ─────────────────────────────────────────────────────────

/// High-level mnemonic categories that carry type evidence.
/// We do not model the full ISA — only the semantically-relevant subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Mnemonic {
    // Arithmetic
    Add,
    Sub,
    Mul,  // unsigned multiply
    IMul, // signed multiply
    Div,  // unsigned divide
    IDiv, // signed divide
    // Shifts
    Shl,
    Shr, // logical (unsigned) shift right
    Sar, // arithmetic (signed) shift right
    // Sign/zero extension
    Movsx,
    Movzx,
    // Floating point
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    Cvtsi2ss,
    Cvtsi2sd,
    // Memory
    Load,
    Store,
    Lea,
    // Calls
    Call,
    IndirectCall,
    // Comparison / branch (used to mark boolean results)
    Cmp,
    Test,
    Jcc,
}

/// A single abstract instruction operand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operand {
    Var(VarRef),
    Immediate(i64),
    /// Memory reference: `base + scale*index + disp`.
    MemRef {
        base: Option<VarRef>,
        index: Option<VarRef>,
        scale: u8,
        disp: i64,
    },
    /// Indirect through a variable (e.g. `[rax+0]`).
    Deref {
        ptr: VarRef,
        offset: i64,
        access_size: u8,
    },
}

/// One abstract lifted instruction carrying type evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedInstruction {
    pub mnemonic: Mnemonic,
    pub dst: Option<Operand>,
    pub src1: Option<Operand>,
    pub src2: Option<Operand>,
    /// Native byte width of the operation (0 = unknown).
    pub width: u8,
    /// Address of this instruction in the binary.
    pub address: Address,
}

// ── Level 1: Size inference ───────────────────────────────────────────────────

/// Extract `HasSize` facts from instruction operand widths.
///
/// Rules:
/// - Any `Load` or `Store` of width W → `HasSize{var, W}` for the value operand.
/// - Any arithmetic instruction of width W → `HasSize` for destination.
pub fn infer_sizes(instr: &TypedInstruction) -> Vec<ConstraintFact> {
    let mut facts = Vec::new();

    if instr.width == 0 {
        return facts;
    }
    let sz = instr.width;

    let dest_var: Option<VarRef> = instr.dst.as_ref().and_then(operand_var);

    match instr.mnemonic {
        Mnemonic::Load => {
            if let Some(v) = dest_var {
                facts.push(ConstraintFact::HasSize { var: v, size: sz });
            }
            // The address operand is a pointer; its pointee has size `sz`.
            if let Some(Operand::Deref { ptr, .. }) = &instr.src1 {
                facts.push(ConstraintFact::IsPointer {
                    var: *ptr,
                    pointee_size: Some(sz),
                });
            }
        }
        Mnemonic::Store => {
            if let Some(Operand::Deref { ptr, .. }) = &instr.dst {
                facts.push(ConstraintFact::IsPointer {
                    var: *ptr,
                    pointee_size: Some(sz),
                });
            }
            if let Some(v) = instr.src1.as_ref().and_then(operand_var) {
                facts.push(ConstraintFact::HasSize { var: v, size: sz });
            }
        }
        Mnemonic::Add
        | Mnemonic::Sub
        | Mnemonic::Mul
        | Mnemonic::IMul
        | Mnemonic::Div
        | Mnemonic::IDiv
        | Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar => {
            if let Some(v) = dest_var {
                facts.push(ConstraintFact::HasSize { var: v, size: sz });
            }
        }
        Mnemonic::Movsx
        | Mnemonic::Movzx
        | Mnemonic::Fadd
        | Mnemonic::Fsub
        | Mnemonic::Fmul
        | Mnemonic::Fdiv
        | Mnemonic::Cvtsi2ss
        | Mnemonic::Cvtsi2sd
        | Mnemonic::Lea
        | Mnemonic::Call
        | Mnemonic::IndirectCall
        | Mnemonic::Cmp
        | Mnemonic::Test
        | Mnemonic::Jcc => {}
    }

    facts
}

// ── Level 2: Sign inference ───────────────────────────────────────────────────

/// Extract `IsSigned` / `IsUnsigned` facts from the instruction mnemonic.
///
/// | Mnemonic          | Conclusion                   |
/// |-------------------|------------------------------|
/// | SAR               | result & first operand signed |
/// | IDIV, IMUL        | all integer operands signed   |
/// | SHR, DIV, MUL     | all integer operands unsigned |
/// | MOVSX             | source operand is signed      |
/// | MOVZX             | source operand is unsigned    |
pub fn infer_signedness(instr: &TypedInstruction) -> Vec<ConstraintFact> {
    let mut facts = Vec::new();
    let dst = instr.dst.as_ref().and_then(operand_var);
    let src1 = instr.src1.as_ref().and_then(operand_var);

    match instr.mnemonic {
        Mnemonic::Sar | Mnemonic::IDiv | Mnemonic::IMul => {
            if let Some(v) = dst {
                facts.push(ConstraintFact::IsSigned { var: v });
            }
            if let Some(v) = src1 {
                facts.push(ConstraintFact::IsSigned { var: v });
            }
            if let Some(v) = instr.src2.as_ref().and_then(operand_var) {
                facts.push(ConstraintFact::IsSigned { var: v });
            }
        }
        Mnemonic::Shr | Mnemonic::Div | Mnemonic::Mul => {
            if let Some(v) = dst {
                facts.push(ConstraintFact::IsUnsigned { var: v });
            }
            if let Some(v) = src1 {
                facts.push(ConstraintFact::IsUnsigned { var: v });
            }
        }
        Mnemonic::Movsx => {
            // MOVSX sign-extends: the source is signed.
            if let Some(v) = src1 {
                facts.push(ConstraintFact::IsSigned { var: v });
            }
        }
        Mnemonic::Movzx => {
            // MOVZX zero-extends: the source is unsigned.
            if let Some(v) = src1 {
                facts.push(ConstraintFact::IsUnsigned { var: v });
            }
        }
        Mnemonic::Add
        | Mnemonic::Sub
        | Mnemonic::Shl
        | Mnemonic::Fadd
        | Mnemonic::Fsub
        | Mnemonic::Fmul
        | Mnemonic::Fdiv
        | Mnemonic::Cvtsi2ss
        | Mnemonic::Cvtsi2sd
        | Mnemonic::Load
        | Mnemonic::Store
        | Mnemonic::Lea
        | Mnemonic::Call
        | Mnemonic::IndirectCall
        | Mnemonic::Cmp
        | Mnemonic::Test
        | Mnemonic::Jcc => {}
    }

    facts
}

// ── Level 3: Pointer inference ────────────────────────────────────────────────

/// Extract `IsPointer` facts.
///
/// A variable is a pointer when:
/// - It appears as the `ptr` in a `Deref` operand (LOAD or STORE).
/// - It is the destination of a `Lea` instruction.
pub fn infer_pointers(instr: &TypedInstruction) -> Vec<ConstraintFact> {
    let mut facts = Vec::new();

    match instr.mnemonic {
        Mnemonic::Lea => {
            if let Some(v) = instr.dst.as_ref().and_then(operand_var) {
                facts.push(ConstraintFact::IsPointer {
                    var: v,
                    pointee_size: None,
                });
            }
        }
        Mnemonic::Load | Mnemonic::Store => {
            // Already handled in `infer_sizes`; here we handle ptr-only case.
            let deref_op = if instr.mnemonic == Mnemonic::Load {
                instr.src1.as_ref()
            } else {
                instr.dst.as_ref()
            };
            if let Some(Operand::Deref {
                ptr, access_size, ..
            }) = deref_op
            {
                facts.push(ConstraintFact::IsPointer {
                    var: *ptr,
                    pointee_size: Some(*access_size),
                });
            }
        }
        _ => {}
    }

    facts
}

// ── Level 4: Struct inference ─────────────────────────────────────────────────

/// Records observed field accesses on a base pointer variable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructAccessCollector {
    /// `base_var → list of (offset, size)` accesses.
    accesses: HashMap<VarRef, Vec<(u64, u8)>>,
}

impl StructAccessCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a memory access at `base + offset` of `size` bytes.
    pub fn record(&mut self, base: VarRef, offset: u64, size: u8) {
        self.accesses.entry(base).or_default().push((offset, size));
    }

    /// Scan an instruction for field-access patterns and record them.
    pub fn observe(&mut self, instr: &TypedInstruction) {
        let access_op = match instr.mnemonic {
            Mnemonic::Load => instr.src1.as_ref(),
            Mnemonic::Store => instr.dst.as_ref(),
            _ => return,
        };
        if let Some(Operand::Deref { ptr, offset, access_size, }) = access_op && *offset > 0 {
            // Non-zero offset: strong struct evidence.
            self.record(*ptr, u64::try_from(*offset).unwrap_or(0), *access_size);
        }
    }

    /// Emit `IsStruct` facts for every variable that has been accessed at
    /// more than one distinct offset (i.e. struct-like usage).
    #[must_use]
    pub fn emit_facts(&self) -> Vec<ConstraintFact> {
        let mut facts = Vec::new();
        // Sort variables: `self.accesses` is a HashMap, and iterating it
        // directly makes the emitted fact order depend on hash-iteration
        // order (nondeterministic across runs/platforms).
        let mut vars: Vec<&VarRef> = self.accesses.keys().collect();
        vars.sort_unstable();
        for &var in vars {
            let offsets = &self.accesses[&var];
            let mut distinct: Vec<(u64, u8)> = offsets.clone();
            distinct.sort_unstable();
            distinct.dedup();
            if distinct.len() >= 2 {
                for (offset, size) in distinct {
                    facts.push(ConstraintFact::IsStruct {
                        var,
                        field_offset: offset,
                        field_size: size,
                    });
                }
            }
        }
        facts
    }
}

// ── Level 5: Array inference ──────────────────────────────────────────────────

/// Detects the `base + index * elem_size` address-computation pattern.
/// When an instruction computes an effective address of this form, we emit an
/// `IsArray` fact for the base variable.
#[must_use]
pub fn infer_array(instr: &TypedInstruction) -> Option<ConstraintFact> {
    // Look for: LEA dst, [base + index*scale + disp]
    if instr.mnemonic != Mnemonic::Lea {
        return None;
    }
    if let Some(Operand::MemRef { base: Some(base), scale, .. }) = &instr.src1 && *scale > 1 {
        return Some(ConstraintFact::IsArray {
            var: *base,
            elem_size: *scale,
            bound: None,
        });
    }
    None
}

// ── Level 6: VTable pointer inference ────────────────────────────────────────

/// Detects the C++ vtable dispatch pattern:
/// 1. Load the vtable pointer from `[object_ptr + 0]`.
/// 2. Load the method pointer from `[vtable_ptr + slot * 8]`.
/// 3. Indirect call through the method pointer.
///
/// The `VtablePatternDetector` is a small state machine that tracks these three
/// steps across consecutive instructions on the same basic-block path.
#[derive(Debug, Clone, Default)]
pub struct VtablePatternDetector {
    /// Candidate state: (`object_var`, `vtable_load_result_var`).
    state: Option<(VarRef, VarRef)>,
    /// Whether the step-2 load through the vtable register was observed.
    slot_loaded: bool,
    pub emitted: Vec<ConstraintFact>,
}

impl VtablePatternDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next instruction.  If the three-step pattern is completed, an
    /// `IsVtablePtr` fact is emitted into `self.emitted`.
    pub fn observe(&mut self, instr: &TypedInstruction) {
        match instr.mnemonic {
            Mnemonic::Load => {
                // Step 1: load from [object_ptr + 0]
                // Step 2: load from [vtable_var + slot*8]
                if let Some((_, vtbl_var)) = self.state && let Some(Operand::Deref { ptr, .. }) = &instr.src1 && *ptr == vtbl_var {
                    // Still in the pattern; record that the slot load occurred.
                    self.slot_loaded = true;
                } else if let ( Some(Operand::Deref { ptr: obj, offset: 0, .. }), Some(dst_op), ) = (&instr.src1, &instr.dst) && let Some(dst_var) = operand_var(dst_op) {
                    // Record candidate: object → vtable_var
                    self.state = Some((*obj, dst_var));
                    self.slot_loaded = false;
                }
            }
            Mnemonic::IndirectCall => {
                // Step 3: indirect call — if we have a pending vtable state, emit.
                if let Some((obj_var, _)) = self.state.take() && std::mem::take(&mut self.slot_loaded) {
                    self.emitted
                        .push(ConstraintFact::IsVtablePtr { var: obj_var });
                }
            }
            _ => {}
        }
    }

    /// Drain emitted facts.
    pub fn drain_facts(&mut self) -> Vec<ConstraintFact> {
        std::mem::take(&mut self.emitted)
    }
}

// ── Unified inference pipeline ────────────────────────────────────────────────

/// Run all six inference levels on a sequence of instructions and collect all
/// `ConstraintFact`s produced.
#[must_use]
pub fn run_inference_pipeline(instrs: &[TypedInstruction]) -> Vec<ConstraintFact> {
    let mut facts: Vec<ConstraintFact> = Vec::new();
    let mut struct_collector = StructAccessCollector::new();
    let mut vtable_detector = VtablePatternDetector::new();

    for instr in instrs {
        // Level 1 – sizes
        facts.extend(infer_sizes(instr));
        // Level 2 – signedness
        facts.extend(infer_signedness(instr));
        // Level 3 – pointers
        facts.extend(infer_pointers(instr));
        // Level 4 – struct accesses (collected; emitted after loop)
        struct_collector.observe(instr);
        // Level 5 – array
        if let Some(f) = infer_array(instr) {
            facts.push(f);
        }
        // Level 6 – vtable
        vtable_detector.observe(instr);
        facts.extend(vtable_detector.drain_facts());
    }

    // Emit struct facts from accumulated accesses.
    facts.extend(struct_collector.emit_facts());

    facts
}

// ── TypeHintSummary ───────────────────────────────────────────────────────────

/// A summarized type annotation for a single variable, combining all evidence
/// gathered by the inference pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeHintSummary {
    pub var: VarRef,
    pub best_guess: TypeFact,
    pub confidence: u8, // 0..100
}

/// Collapse all facts about each variable into a `TypeHintSummary`.
#[must_use]
pub fn summarize_hints(facts: &[ConstraintFact]) -> Vec<TypeHintSummary> {
    // Accumulate per-variable best-guess using `TypeFact::join`.
    let mut map: HashMap<VarRef, (TypeFact, u8)> = HashMap::new();

    for fact in facts {
        let (var, tf, conf) = match fact {
            ConstraintFact::HasSize { var, size } => (*var, TypeFact::Sized(*size as usize), 30u8),
            ConstraintFact::IsSigned { var } => (*var, TypeFact::SignedInt(4), 40),
            ConstraintFact::IsUnsigned { var } => (*var, TypeFact::UnsignedInt(4), 40),
            ConstraintFact::IsFloat { var } => (*var, TypeFact::Float(8), 60),
            ConstraintFact::IsPointer { var, pointee_size } => {
                let inner = pointee_size
                    .map_or(TypeFact::Unknown, |s| TypeFact::Sized(s as usize));
                (*var, TypeFact::Pointer(Box::new(inner)), 70)
            }
            ConstraintFact::IsArray {
                var,
                elem_size,
                bound,
            } => (
                *var,
                TypeFact::Array {
                    element: Box::new(TypeFact::Sized(*elem_size as usize)),
                    length: *bound,
                },
                65,
            ),
            ConstraintFact::IsStruct {
                var,
                field_offset,
                field_size,
            } => (
                *var,
                TypeFact::Struct {
                    fields: vec![(
                        usize::try_from(*field_offset).unwrap_or(usize::MAX),
                        TypeFact::Sized(*field_size as usize),
                    )],
                },
                55,
            ),
            ConstraintFact::IsVtablePtr { var } => (
                *var,
                TypeFact::Pointer(Box::new(TypeFact::Pointer(Box::new(TypeFact::Unknown)))),
                80,
            ),
            _ => continue,
        };

        let entry = map.entry(var).or_insert((TypeFact::Unknown, 0));
        entry.0 = entry.0.join(&tf);
        entry.1 = entry.1.max(conf);
    }

    // Sort by variable: `map` is a HashMap and `into_iter` yields
    // hash-iteration order, which would make the summary order
    // nondeterministic across runs/platforms.
    let mut out: Vec<TypeHintSummary> = map
        .into_iter()
        .map(|(v, (tf, conf))| TypeHintSummary {
            var: v,
            best_guess: tf,
            confidence: conf,
        })
        .collect();
    out.sort_unstable_by_key(|h| h.var);
    out
}

// ── helpers ───────────────────────────────────────────────────────────────────

const fn operand_var(op: &Operand) -> Option<VarRef> {
    if let Operand::Var(v) = op {
        Some(*v)
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::VarRef;

    fn make_var(i: u32) -> VarRef {
        VarRef::new(0, i)
    }

    fn load_instr(dst: VarRef, ptr: VarRef, offset: i64, width: u8) -> TypedInstruction {
        TypedInstruction {
            mnemonic: Mnemonic::Load,
            dst: Some(Operand::Var(dst)),
            src1: Some(Operand::Deref {
                ptr,
                offset,
                access_size: width,
            }),
            src2: None,
            width,
            address: Address(0),
        }
    }

    fn store_instr(ptr: VarRef, offset: i64, src: VarRef, width: u8) -> TypedInstruction {
        TypedInstruction {
            mnemonic: Mnemonic::Store,
            dst: Some(Operand::Deref {
                ptr,
                offset,
                access_size: width,
            }),
            src1: Some(Operand::Var(src)),
            src2: None,
            width,
            address: Address(0),
        }
    }

    fn arith_instr(mnemonic: Mnemonic, dst: VarRef, src1: VarRef, width: u8) -> TypedInstruction {
        TypedInstruction {
            mnemonic,
            dst: Some(Operand::Var(dst)),
            src1: Some(Operand::Var(src1)),
            src2: None,
            width,
            address: Address(0),
        }
    }

    #[test]
    fn test_level1_load_emits_has_size() {
        let v_dst = make_var(0);
        let v_ptr = make_var(1);
        let instr = load_instr(v_dst, v_ptr, 0, 4);
        let facts = infer_sizes(&instr);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, ConstraintFact::HasSize { var, size: 4 } if *var == v_dst))
        );
    }

    #[test]
    fn test_level1_load_emits_is_pointer() {
        let v_dst = make_var(0);
        let v_ptr = make_var(1);
        let instr = load_instr(v_dst, v_ptr, 0, 8);
        let facts = infer_sizes(&instr);
        assert!(facts.iter().any(|f| matches!(f, ConstraintFact::IsPointer { var, pointee_size: Some(8) } if *var == v_ptr)));
    }

    #[test]
    fn test_level2_sar_emits_signed() {
        let v_dst = make_var(0);
        let v_src = make_var(1);
        let instr = arith_instr(Mnemonic::Sar, v_dst, v_src, 4);
        let facts = infer_signedness(&instr);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, ConstraintFact::IsSigned { var } if *var == v_dst))
        );
    }

    #[test]
    fn test_level2_shr_emits_unsigned() {
        let v_dst = make_var(0);
        let v_src = make_var(1);
        let instr = arith_instr(Mnemonic::Shr, v_dst, v_src, 4);
        let facts = infer_signedness(&instr);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, ConstraintFact::IsUnsigned { var } if *var == v_dst))
        );
    }

    #[test]
    fn test_level2_movsx_source_signed() {
        let v_dst = make_var(0);
        let v_src = make_var(1);
        let instr = arith_instr(Mnemonic::Movsx, v_dst, v_src, 1);
        let facts = infer_signedness(&instr);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, ConstraintFact::IsSigned { var } if *var == v_src))
        );
    }

    #[test]
    fn test_level3_lea_emits_pointer() {
        let v_dst = make_var(0);
        let instr = TypedInstruction {
            mnemonic: Mnemonic::Lea,
            dst: Some(Operand::Var(v_dst)),
            src1: None,
            src2: None,
            width: 8,
            address: Address(0),
        };
        let facts = infer_pointers(&instr);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, ConstraintFact::IsPointer { var, .. } if *var == v_dst))
        );
    }

    #[test]
    fn test_level4_struct_multi_offset() {
        let base = make_var(0);
        let val = make_var(1);
        let mut col = StructAccessCollector::new();
        col.observe(&load_instr(val, base, 0, 4));
        col.observe(&load_instr(val, base, 8, 8));
        col.observe(&load_instr(val, base, 16, 4));
        let facts = col.emit_facts();
        // Should have IsStruct facts for the non-zero offsets (8 and 16).
        
        assert!(facts
            .iter().any(|f| matches!(f, ConstraintFact::IsStruct { .. })));
    }

    #[test]
    fn test_level5_lea_array() {
        let base = make_var(0);
        let dst = make_var(1);
        let instr = TypedInstruction {
            mnemonic: Mnemonic::Lea,
            dst: Some(Operand::Var(dst)),
            src1: Some(Operand::MemRef {
                base: Some(base),
                index: None,
                scale: 4,
                disp: 0,
            }),
            src2: None,
            width: 8,
            address: Address(0),
        };
        let f = infer_array(&instr);
        assert!(matches!(
            f,
            Some(ConstraintFact::IsArray { elem_size: 4, .. })
        ));
    }

    #[test]
    fn test_level6_vtable_detection() {
        let obj = make_var(0);
        let vtbl = make_var(1);
        let method = make_var(2);

        let mut det = VtablePatternDetector::new();

        // Step 1: load vtable ptr from [obj+0]
        det.observe(&load_instr(vtbl, obj, 0, 8));
        // Step 2: load method from [vtbl+offset]
        det.observe(&load_instr(method, vtbl, 16, 8));
        // Step 3: indirect call
        let call_instr = TypedInstruction {
            mnemonic: Mnemonic::IndirectCall,
            dst: None,
            src1: Some(Operand::Var(method)),
            src2: None,
            width: 0,
            address: Address(0x1000),
        };
        det.observe(&call_instr);

        assert!(!det.emitted.is_empty());
        assert!(
            det.emitted
                .iter()
                .any(|f| matches!(f, ConstraintFact::IsVtablePtr { var } if *var == obj))
        );
    }

    #[test]
    fn test_pipeline_runs_on_empty() {
        let facts = run_inference_pipeline(&[]);
        assert!(facts.is_empty());
    }

    #[test]
    fn test_pipeline_store_and_load() {
        let ptr = make_var(0);
        let val = make_var(1);
        let instrs = vec![store_instr(ptr, 0, val, 4), load_instr(val, ptr, 0, 4)];
        let facts = run_inference_pipeline(&instrs);
        assert!(!facts.is_empty());
    }

    #[test]
    fn test_summarize_hints_non_empty() {
        let v = make_var(0);
        let facts = vec![
            ConstraintFact::HasSize { var: v, size: 4 },
            ConstraintFact::IsSigned { var: v },
        ];
        let hints = summarize_hints(&facts);
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_summarize_hints_float_confidence() {
        let v = make_var(0);
        let facts = vec![ConstraintFact::IsFloat { var: v }];
        let hints = summarize_hints(&facts);
        let h = hints.iter().find(|h| h.var == v).unwrap();
        assert!(h.confidence >= 60);
    }
}
