//! .NET Common Intermediate Language (CIL/MSIL) LLIL lifter.
//!
//! CIL is a stack-based bytecode used by the .NET runtime (CLR).  This lifter
//! models the evaluation stack with virtual registers `s_0`, `s_1`, etc., local
//! variables as `local_<idx>`, and method arguments as `arg_<idx>`.
//!
//! # Stack discipline
//!
//! CIL is purely stack-based.  Each instruction that *produces* a value writes
//! to `s_<depth>` and increments the depth counter.  Instructions that *consume*
//! values read from the current top before decrementing.
//!
//! Because `lift` operates on a single instruction at a time (stateless API)
//! the lifter cannot maintain true inter-instruction stack state.  Instead,
//! each instruction is lifted as if the stack depth before it is **0**, and
//! `s_0` represents the top-of-stack at entry.  A higher-level analysis pass can
//! assign concrete SSA names by tracking depth across a basic block.
//!
//! # Operand extraction
//!
//! CIL operands (local indices, argument indices, branch targets, integer
//! constants) are carried in the instruction's raw `operands` string field as
//! well as the structured `operand_list`.  Both sources are tried; the raw text
//! is the primary source because the structured list may be empty for
//! architectures whose disassembler does not populate it.
//!
//! # Supported opcodes
//!
//! The following CIL opcode groups are handled:
//!
//! * **Control flow**: `nop`, `ret`, `br`/`br.s`, `brfalse`/`brtrue`,
//!   comparison branches (`beq`, `bne.un`, `blt`, `bgt`, `ble`, `bge` + `.s`/`.un` variants)
//! * **Stack manipulation**: `dup`, `pop`
//! * **Argument load/store**: `ldarg.*`, `starg.*`
//! * **Local load/store**: `ldloc.*`, `stloc.*`
//! * **Integer/float constants**: `ldc.i4.*`, `ldc.i8`, `ldc.r4`, `ldc.r8`, `ldnull`
//! * **Arithmetic**: `add`, `sub`, `mul`, `div`, `rem` (+ overflow and unsigned variants)
//! * **Bitwise**: `and`, `or`, `xor`, `not`, `neg`
//! * **Shifts**: `shl`, `shr`, `shr.un`
//! * **Comparison**: `ceq`, `clt`, `cgt` (+ unsigned variants)
//! * **Memory**: `ldind.*`, `stind.*`, `ldobj`, `stobj`, `ldfld`, `stfld`,
//!   `ldsfld`, `stsfld`, `initobj`
//! * **Calls**: `call`, `callvirt`, `calli`, `newobj`, `newarr`
//! * **Misc**: `ldlen`, `throw`, `conv.*`

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Helper: virtual register names
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Return the name of the virtual stack register at position `depth`.
#[inline]
fn stack_reg(depth: usize) -> String {
    format!("s_{depth}")
}

/// Return the name of the virtual local-variable register for index `idx`.
#[inline]
fn local_reg(idx: u64) -> String {
    format!("local_{idx}")
}

/// Return the name of the virtual argument register for index `idx`.
#[inline]
fn arg_reg(idx: u64) -> String {
    format!("arg_{idx}")
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Operand extraction helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parse the raw operand string into whitespace-separated tokens, stripping
/// any CIL comment markers (`//`) and type-reference brackets (`[assembly]`).
fn raw_tokens(instr: &Instruction) -> Vec<String> {
    // Strip C#-style inline comments.
    let raw = instr.operands.split("//").next().unwrap_or("").trim();
    if raw.is_empty() {
        return instr.operand_list.iter().map(|o| format!("{o}")).collect::<Vec<_>>();
    }
    raw.split_whitespace()
        .map(|s| s.trim_matches(',').to_string())
        .collect()
}

/// Try to extract the first numeric token from the operand string as a `u64`.
/// Accepts decimal (including negative) and `0x`/`0X`-prefixed hex.
fn first_u64(instr: &Instruction) -> Option<u64> {
    let toks = raw_tokens(instr);
    parse_u64(toks.first()?)
}

/// Parse a string token as a `u64` (decimal, hex, or negative decimal).
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).ok())
}

/// Extract a branch target from the operand string.
///
/// CIL disassemblers typically format branch targets as absolute IL offsets or
/// labels like `IL_0042`.  We parse them into a `u64` best-effort.
fn branch_target_expr(instr: &Instruction) -> IrExpr {
    let toks = raw_tokens(instr);
    for tok in &toks {
        // Handle label form `IL_NNNN`.
        let candidate = tok.to_ascii_uppercase().strip_prefix("IL_").map_or_else(|| parse_u64(tok), |rest| u64::from_str_radix(rest, 16).ok());
        if let Some(v) = candidate {
            return IrExpr::Const(v);
        }
    }
    // Fallthrough: use address + size as a placeholder.
    IrExpr::Const(instr.address.0.wrapping_add(instr.size as u64))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// CilLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A mnemonic-driven LLIL lifter for .NET Common Intermediate Language (CIL).
///
/// ## Stack modelling
///
/// The CIL evaluation stack is modelled with virtual registers named `s_0`,
/// `s_1`, etc.  A per-instruction depth counter (starting at 0) tracks which
/// virtual register is the current top-of-stack:
///
/// * **Push** (producers): write result to `s_<depth>` then depth++
/// * **Pop** (consumers): depth-- then read from `s_<depth>`
/// * **Binary ops**: pop two, push one â€” net depth change of -1
///
/// Local variables map to `local_<idx>`, method arguments to `arg_<idx>`.
///
/// ## Memory operations
///
/// Field accesses (`ldfld`/`stfld`) and indirect loads/stores (`ldind`/`stind`)
/// produce [`Effect::MemRead`] / [`Effect::MemWrite`] with the stack-top value
/// as the base address, matching the CIL specification.
///
/// ## Limitations
///
/// * Floating-point values are treated as 4-byte or 8-byte integer slots.
/// * SIMD and advanced generics opcodes are folded into [`Effect::Intrinsic`].
/// * Metadata tokens (type/method/field references) in the operand string are
///   treated as opaque strings and are not resolved to symbol names.
#[derive(Debug, Clone)]
pub struct CilLifter;

impl CilLifter {
    /// Create a new `CilLifter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // â”€â”€ Instruction helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Build a binary operation effect: pop two, push one.
    ///
    /// * Input operands: `s_0` (top) and `s_1` (second)
    /// * Output: `s_0 = op(s_1, s_0)`
    fn bin_op(constructor: fn(Box<IrExpr>, Box<IrExpr>) -> IrExpr) -> Vec<Effect> {
        // CIL binary: stack[sp-2] op stack[sp-1] â†’ result pushed back.
        // In our flat model the two inputs are s_0 (top) and s_1 (second).
        let lhs = IrExpr::Reg(stack_reg(1));
        let rhs = IrExpr::Reg(stack_reg(0));
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: constructor(Box::new(lhs), Box::new(rhs)),
        }]
    }

    /// Build a binary intrinsic effect (for ops without a direct `IrExpr` node).
    fn bin_intrinsic(name: &str) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![IrExpr::Reg(stack_reg(1)), IrExpr::Reg(stack_reg(0))],
        }]
    }

    /// Push a constant value onto the stack (writes to `s_0`).
    fn push_const(value: u64) -> Vec<Effect> {
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Const(value),
        }]
    }

    /// Push a register value onto the stack (writes to `s_0`).
    fn push_reg(src: &str) -> Vec<Effect> {
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Reg(src.to_string()),
        }]
    }

    /// Pop the stack top into a named register.
    fn pop_to_reg(dest: &str) -> Vec<Effect> {
        vec![Effect::RegWrite {
            reg: dest.to_string(),
            value: IrExpr::Reg(stack_reg(0)),
        }]
    }

    // â”€â”€ Per-opcode lifting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    const fn lift_nop() -> Vec<Effect> {
        vec![]
    }

    // --- ldarg / starg ---

    fn lift_ldarg(idx: u64) -> Vec<Effect> {
        Self::push_reg(&arg_reg(idx))
    }

    fn lift_starg(idx: u64) -> Vec<Effect> {
        Self::pop_to_reg(&arg_reg(idx))
    }

    // --- ldloc / stloc ---

    fn lift_ldloc(idx: u64) -> Vec<Effect> {
        Self::push_reg(&local_reg(idx))
    }

    fn lift_stloc(idx: u64) -> Vec<Effect> {
        Self::pop_to_reg(&local_reg(idx))
    }

    // --- ldc.i4 variants ---

    fn lift_ldc_i4(value: i32) -> Vec<Effect> {
        Self::push_const(i64::from(value).cast_unsigned())
    }

    // --- arithmetic ---

    /// Mark the checked (`.ovf`) arithmetic forms so they stay distinguishable
    /// from the unchecked ones.
    ///
    /// `add`, `add.ovf` and `add.ovf.un` shared one handler. The `.ovf` forms
    /// THROW `OverflowException` instead of wrapping, and `.un` decides whether
    /// the overflow test is signed or unsigned — three behaviours, one lift.
    ///
    /// The two-step question, and the answer that decided the treatment:
    /// 1. *Is the fact expressible?* No. This IR has no exception EDGE — even
    ///    the unconditional `throw` is lifted as an opaque intrinsic
    ///    (`lift_throw`), so a CONDITIONAL throw certainly cannot be a real
    ///    control-flow fact here.
    /// 2. *Does the distinction survive?* It did not — and that is the part
    ///    that was fixable.
    ///
    /// So the value stays the wrapping approximation (the RESULT BITS are the
    /// same when no overflow occurs, which is the non-trapping path) and a
    /// mnemonic-named intrinsic records that this form can trap. Same
    /// convention as ARM's `ADC` and PowerPC's `ADDE`.
    ///
    /// Worth noting: the previous iteration assumed this case "deserved more
    /// than a marker" because an exception edge should be modelled. Checking
    /// the IR showed it cannot be — the assumption was wrong, and checking it
    /// was the difference between a correct fix and a stalled one.
    fn with_overflow_marker(mut effects: Vec<Effect>, mnem: &str) -> Vec<Effect> {
        effects.insert(
            0,
            Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            },
        );
        effects
    }

    fn lift_add() -> Vec<Effect> {
        Self::bin_op(IrExpr::Add)
    }

    fn lift_sub() -> Vec<Effect> {
        Self::bin_op(IrExpr::Sub)
    }

    fn lift_mul() -> Vec<Effect> {
        Self::bin_op(IrExpr::Mul)
    }

    fn lift_div(unsigned: bool) -> Vec<Effect> {
        let name = if unsigned { "div.un" } else { "div" };
        Self::bin_intrinsic(name)
    }

    fn lift_rem(unsigned: bool) -> Vec<Effect> {
        let name = if unsigned { "rem.un" } else { "rem" };
        Self::bin_intrinsic(name)
    }

    fn lift_neg() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "neg".to_string(),
            args: vec![IrExpr::Reg(stack_reg(0))],
        }]
    }

    // --- bitwise ---

    fn lift_and() -> Vec<Effect> {
        Self::bin_op(IrExpr::And)
    }

    fn lift_or() -> Vec<Effect> {
        Self::bin_op(IrExpr::Or)
    }

    fn lift_xor() -> Vec<Effect> {
        Self::bin_op(IrExpr::Xor)
    }

    fn lift_not() -> Vec<Effect> {
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Not(Box::new(IrExpr::Reg(stack_reg(0)))),
        }]
    }

    fn lift_shl() -> Vec<Effect> {
        Self::bin_op(IrExpr::Shl)
    }

    /// `shr` is CIL's ARITHMETIC shift; `shr.un` is the logical one.
    ///
    /// This took the flag as `_unsigned` — ignored — and its own comment stated
    /// the fact and then the defect in one breath: "CIL shr is arithmetic
    /// shift; shr.un is logical. Both map to Shr." So `shr` was wrong for every
    /// negative value and the two opcodes were indistinguishable, while
    /// `IrExpr::Sar` existed and `lift_div`/`lift_rem` two functions above were
    /// already consuming their own flag correctly.
    fn lift_shr(unsigned: bool) -> Vec<Effect> {
        Self::bin_op(if unsigned { IrExpr::Shr } else { IrExpr::Sar })
    }

    // --- stack manipulation ---

    /// dup: duplicate the top of the stack (`s_1` = `s_0`).
    fn lift_dup() -> Vec<Effect> {
        vec![Effect::RegWrite {
            reg: stack_reg(1),
            value: IrExpr::Reg(stack_reg(0)),
        }]
    }

    /// pop: discard the top of the stack (modelled as writing Undef).
    fn lift_pop() -> Vec<Effect> {
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::Undef,
        }]
    }

    // --- indirect load (ldind) ---

    /// `LDIND.*` is a TYPED indirect load, and the type is part of the opcode.
    /// A single `lift_ldind(size)` flattened FOUR distinct facts:
    ///
    /// 1. **signedness** — `.i1` sign-extends into the int32 stack slot, `.u1`
    ///    zero-extends. Sixth occurrence of that class in this crate.
    /// 2. **float vs integer** — `.r4`/`.r8` push a FLOAT; sign extension is not
    ///    merely unnecessary there, it is meaningless.
    /// 3. **object reference** — `.ref` pushes a GC-tracked reference, which is
    ///    neither an integer nor a float.
    /// 4. **native int** — `.i` is platform-dependent; the code models it as 8
    ///    bytes, an honest approximation, but on a 32-bit target it is 4.
    ///
    /// Found by the lesson from the previous iteration: a shared arm is a place
    /// where SEVERAL facts were assumed equal, so check them all rather than
    /// only the one being hunted. Here the signedness was the one I came for and
    /// the smallest of the four.
    ///
    /// Since every `LDIND` variant carries a type, the mnemonic is recorded on
    /// all of them — uniform, and nothing downstream has to infer the type from
    /// a size alone.
    fn lift_ldind_typed(size: u8, mnem: &str) -> Vec<Effect> {
        let mut out = Self::lift_ldind(size);
        out.push(Effect::Intrinsic {
            name: mnem.to_string(),
            args: vec![IrExpr::Reg(stack_reg(0))],
        });
        out
    }

    fn lift_ldind(size: u8) -> Vec<Effect> {
        // addr = s_0; dest = s_0 (address is consumed, value is pushed back).
        vec![Effect::MemRead {
            addr: IrExpr::Reg(stack_reg(0)),
            dest: stack_reg(0),
            size,
        }]
    }

    // --- indirect store (stind) ---

    fn lift_stind(size: u8) -> Vec<Effect> {
        // value = s_0 (top), addr = s_1.
        vec![Effect::MemWrite {
            addr: IrExpr::Reg(stack_reg(1)),
            value: IrExpr::Reg(stack_reg(0)),
            size,
        }]
    }

    // --- ldobj / stobj ---

    fn lift_ldobj() -> Vec<Effect> {
        // Same as ldind but size is opaque (type token).  Use 8 as a placeholder.
        Self::lift_ldind(8)
    }

    fn lift_stobj() -> Vec<Effect> {
        Self::lift_stind(8)
    }

    // --- field access ---

    /// ldfld: pop object ref, push field value.
    fn lift_ldfld() -> Vec<Effect> {
        // We model the field access as a MemRead from s_0 (object ref),
        // putting the result back in s_0.
        vec![Effect::MemRead {
            addr: IrExpr::Reg(stack_reg(0)),
            dest: stack_reg(0),
            size: 8,
        }]
    }

    /// stfld: pop value (`s_0`), pop object ref (`s_1`), write field.
    fn lift_stfld() -> Vec<Effect> {
        vec![Effect::MemWrite {
            addr: IrExpr::Reg(stack_reg(1)),
            value: IrExpr::Reg(stack_reg(0)),
            size: 8,
        }]
    }

    /// ldsfld: push static field value (address is a constant â€” treat as Undef).
    fn lift_ldsfld() -> Vec<Effect> {
        vec![Effect::MemRead {
            addr: IrExpr::Undef,
            dest: stack_reg(0),
            size: 8,
        }]
    }

    /// stsfld: pop value (`s_0`), write to static field.
    fn lift_stsfld() -> Vec<Effect> {
        vec![Effect::MemWrite {
            addr: IrExpr::Undef,
            value: IrExpr::Reg(stack_reg(0)),
            size: 8,
        }]
    }

    // --- initobj: zero-initialise a value type at address on stack ---

    fn lift_initobj() -> Vec<Effect> {
        vec![Effect::MemWrite {
            addr: IrExpr::Reg(stack_reg(0)),
            value: IrExpr::Const(0),
            size: 8,
        }]
    }

    // --- call / ret ---

    fn lift_call(instr: &Instruction) -> Vec<Effect> {
        // The branch target is the method reference; model it as a constant.
        let target = branch_target_expr(instr);
        vec![Effect::Call { target }]
    }

    fn lift_ret() -> Vec<Effect> {
        // The return value (if any) is on the stack; we model it as s_0.
        vec![Effect::Return {
            value: Some(IrExpr::Reg(stack_reg(0))),
        }]
    }

    // --- branches ---

    fn lift_br(instr: &Instruction) -> Vec<Effect> {
        vec![Effect::Branch {
            target: branch_target_expr(instr),
            condition: None,
        }]
    }

    fn lift_brfalse(instr: &Instruction) -> Vec<Effect> {
        // Branch if s_0 == 0.
        vec![Effect::Branch {
            target: branch_target_expr(instr),
            condition: Some(IrExpr::CmpEqZero(Box::new(IrExpr::Reg(stack_reg(0))))),
        }]
    }

    fn lift_brtrue(instr: &Instruction) -> Vec<Effect> {
        // Branch if s_0 != 0.
        vec![Effect::Branch {
            target: branch_target_expr(instr),
            condition: Some(IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(
                IrExpr::Reg(stack_reg(0)),
            ))))),
        }]
    }

    /// Generic conditional branch comparing two stack values.
    ///
    /// Equality (`beq`) uses `CmpEqZero(Sub(s_1, s_0))`.  Ordered comparisons
    /// (`blt`, `bgt`, etc.) cannot be represented exactly with the available
    /// `IrExpr` nodes, so they are encoded as `CmpEqZero(Undef)` with an
    /// [`Effect::Intrinsic`] carrying the comparison name and both operands
    /// preceding the branch.  The branch condition is therefore always present
    /// but callers must consult the preceding intrinsic for full semantics.
    fn lift_beq(instr: &Instruction) -> Vec<Effect> {
        let diff = IrExpr::Sub(
            Box::new(IrExpr::Reg(stack_reg(1))),
            Box::new(IrExpr::Reg(stack_reg(0))),
        );
        vec![Effect::Branch {
            target: branch_target_expr(instr),
            condition: Some(IrExpr::CmpEqZero(Box::new(diff))),
        }]
    }

    fn lift_bne(instr: &Instruction) -> Vec<Effect> {
        let diff = IrExpr::Sub(
            Box::new(IrExpr::Reg(stack_reg(1))),
            Box::new(IrExpr::Reg(stack_reg(0))),
        );
        vec![Effect::Branch {
            target: branch_target_expr(instr),
            condition: Some(IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(diff))))),
        }]
    }

    /// Ordered comparison branch: emit an intrinsic side-effect that computes
    /// the comparison result into a temporary `cmp_tmp` register, then branch
    /// conditionally on that register being non-zero.
    fn lift_bcmp(instr: &Instruction, cmp_name: &str) -> Vec<Effect> {
        // Step 1: compute the comparison into a scratch register.
        let cmp_effect = Effect::Intrinsic {
            name: cmp_name.to_string(),
            args: vec![IrExpr::Reg(stack_reg(1)), IrExpr::Reg(stack_reg(0))],
        };
        // Step 2: branch if the comparison scratch register is non-zero.
        // We model the scratch as `s_0` reused (the comparison result).
        let branch_effect = Effect::Branch {
            target: branch_target_expr(instr),
            condition: Some(IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(
                IrExpr::Reg("cmp_tmp".to_string()),
            ))))),
        };
        vec![cmp_effect, branch_effect]
    }

    // --- comparison (push 0 or 1) ---

    fn lift_ceq() -> Vec<Effect> {
        let diff = IrExpr::Sub(
            Box::new(IrExpr::Reg(stack_reg(1))),
            Box::new(IrExpr::Reg(stack_reg(0))),
        );
        vec![Effect::RegWrite {
            reg: stack_reg(0),
            value: IrExpr::CmpEqZero(Box::new(diff)),
        }]
    }

    fn lift_clt(unsigned: bool) -> Vec<Effect> {
        let name = if unsigned { "clt.un" } else { "clt" };
        Self::bin_intrinsic(name)
    }

    fn lift_cgt(unsigned: bool) -> Vec<Effect> {
        let name = if unsigned { "cgt.un" } else { "cgt" };
        Self::bin_intrinsic(name)
    }

    // --- type conversion ---

    fn lift_conv(type_name: &str) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: format!("conv.{type_name}"),
            args: vec![IrExpr::Reg(stack_reg(0))],
        }]
    }

    // --- object creation ---

    fn lift_newobj(instr: &Instruction) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "newobj".to_string(),
            args: vec![branch_target_expr(instr)],
        }]
    }

    fn lift_newarr(instr: &Instruction) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "newarr".to_string(),
            args: vec![
                branch_target_expr(instr),
                IrExpr::Reg(stack_reg(0)), // num elements
            ],
        }]
    }

    fn lift_ldlen() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "ldlen".to_string(),
            args: vec![IrExpr::Reg(stack_reg(0))],
        }]
    }

    fn lift_throw() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "throw".to_string(),
            args: vec![IrExpr::Reg(stack_reg(0))],
        }]
    }

    // â”€â”€ Main dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn mnemonic_to_effects_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();

            match mnem {
            // â”€â”€ No-op â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "nop" => Some(Self::lift_nop()),

            // â”€â”€ Argument load â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldarg.0" => Some(Self::lift_ldarg(0)),
            "ldarg.1" => Some(Self::lift_ldarg(1)),
            "ldarg.2" => Some(Self::lift_ldarg(2)),
            "ldarg.3" => Some(Self::lift_ldarg(3)),
            "ldarg.s" | "ldarg" => {
                let idx = first_u64(instr).unwrap_or(0);
                Some(Self::lift_ldarg(idx))
            }

            // â”€â”€ Argument store â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "starg.s" | "starg" => {
                let idx = first_u64(instr).unwrap_or(0);
                Some(Self::lift_starg(idx))
            }

            // â”€â”€ Local variable load â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldloc.0" => Some(Self::lift_ldloc(0)),
            "ldloc.1" => Some(Self::lift_ldloc(1)),
            "ldloc.2" => Some(Self::lift_ldloc(2)),
            "ldloc.3" => Some(Self::lift_ldloc(3)),
            "ldloc.s" | "ldloc" => {
                let idx = first_u64(instr).unwrap_or(0);
                Some(Self::lift_ldloc(idx))
            }

            // â”€â”€ Local variable store â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "stloc.0" => Some(Self::lift_stloc(0)),
            "stloc.1" => Some(Self::lift_stloc(1)),
            "stloc.2" => Some(Self::lift_stloc(2)),
            "stloc.3" => Some(Self::lift_stloc(3)),
            "stloc.s" | "stloc" => {
                let idx = first_u64(instr).unwrap_or(0);
                Some(Self::lift_stloc(idx))
            }

            // â”€â”€ Integer constants (i4) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldc.i4.m1" | "ldc.i4.-1" => Some(Self::lift_ldc_i4(-1)),
            "ldc.i4.0" => Some(Self::lift_ldc_i4(0)),
            "ldc.i4.1" => Some(Self::lift_ldc_i4(1)),
            "ldc.i4.2" => Some(Self::lift_ldc_i4(2)),
            "ldc.i4.3" => Some(Self::lift_ldc_i4(3)),
            "ldc.i4.4" => Some(Self::lift_ldc_i4(4)),
            "ldc.i4.5" => Some(Self::lift_ldc_i4(5)),
            "ldc.i4.6" => Some(Self::lift_ldc_i4(6)),
            "ldc.i4.7" => Some(Self::lift_ldc_i4(7)),
            "ldc.i4.8" => Some(Self::lift_ldc_i4(8)),
            "ldc.i4.s" | "ldc.i4" => {
                let v = first_u64(instr).map_or(0i32, |u| i32::try_from(u).unwrap_or(i32::MAX));
                Some(Self::lift_ldc_i4(v))
            }

            // â”€â”€ Integer constants (i8) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldc.i8" | "ldc.r8" => {
                let v = first_u64(instr).unwrap_or(0);
                Some(Self::push_const(v))
            }

            // â”€â”€ Floating-point constants (treat as bit-identical integer) â”€â”€â”€â”€
            "ldc.r4" => {
                // Stored as 32-bit float; reinterpret bits as u64.
                let v = first_u64(instr).unwrap_or(0);
                Some(Self::push_const(v & 0xFFFF_FFFF))
            }
            // â”€â”€ Null constant â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldnull" => Some(Self::push_const(0)),

            // â”€â”€ Stack manipulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "dup" => Some(Self::lift_dup()),
            "pop" => Some(Self::lift_pop()),

            // â”€â”€ Arithmetic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "add" => Some(Self::lift_add()),
            "add.ovf" | "add.ovf.un" => {
                Some(Self::with_overflow_marker(Self::lift_add(), &mnem))
            }
                _ => None,
            }
    }
    fn mnemonic_to_effects_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();

            match mnem {
            "sub" => Some(Self::lift_sub()),
            "sub.ovf" | "sub.ovf.un" => {
                Some(Self::with_overflow_marker(Self::lift_sub(), &mnem))
            }
            "mul" => Some(Self::lift_mul()),
            "mul.ovf" | "mul.ovf.un" => {
                Some(Self::with_overflow_marker(Self::lift_mul(), &mnem))
            }
            "div" => Some(Self::lift_div(false)),
            "div.un" => Some(Self::lift_div(true)),
            "rem" => Some(Self::lift_rem(false)),
            "rem.un" => Some(Self::lift_rem(true)),
            "neg" => Some(Self::lift_neg()),

            // â”€â”€ Bitwise â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "and" => Some(Self::lift_and()),
            "or" => Some(Self::lift_or()),
            "xor" => Some(Self::lift_xor()),
            "not" => Some(Self::lift_not()),

            // â”€â”€ Shifts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "shl" => Some(Self::lift_shl()),
            "shr" => Some(Self::lift_shr(false)),
            "shr.un" => Some(Self::lift_shr(true)),

            // â”€â”€ Comparison (push 0 or 1) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ceq" => Some(Self::lift_ceq()),
            "clt" => Some(Self::lift_clt(false)),
            "clt.un" => Some(Self::lift_clt(true)),
            "cgt" => Some(Self::lift_cgt(false)),
            "cgt.un" => Some(Self::lift_cgt(true)),

            // â”€â”€ Unconditional branch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "br" | "br.s" => Some(Self::lift_br(instr)),

            // â”€â”€ Conditional branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "brfalse" | "brfalse.s" | "brzero" => Some(Self::lift_brfalse(instr)),
            "brtrue" | "brtrue.s" | "brinst" => Some(Self::lift_brtrue(instr)),
            "beq" | "beq.s" => Some(Self::lift_beq(instr)),
            "bne.un" | "bne.un.s" => Some(Self::lift_bne(instr)),
            "blt" | "blt.s" => Some(Self::lift_bcmp(instr, "blt")),
            "blt.un" | "blt.un.s" => Some(Self::lift_bcmp(instr, "blt.un")),
            "bgt" | "bgt.s" => Some(Self::lift_bcmp(instr, "bgt")),
            "bgt.un" | "bgt.un.s" => Some(Self::lift_bcmp(instr, "bgt.un")),
            "ble" | "ble.s" => Some(Self::lift_bcmp(instr, "ble")),
            "ble.un" | "ble.un.s" => Some(Self::lift_bcmp(instr, "ble.un")),
            "bge" | "bge.s" => Some(Self::lift_bcmp(instr, "bge")),
            "bge.un" | "bge.un.s" => Some(Self::lift_bcmp(instr, "bge.un")),

            // â”€â”€ Indirect loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldind.i1" | "ldind.u1" => Some(Self::lift_ldind_typed(1, mnem)),
            "ldind.i2" | "ldind.u2" => Some(Self::lift_ldind_typed(2, mnem)),
                _ => None,
            }
    }
    fn mnemonic_to_effects_c(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();

            match mnem {
            "ldind.i4" | "ldind.u4" | "ldind.r4" => Some(Self::lift_ldind_typed(4, mnem)),
            "ldind.i8" | "ldind.u8" | "ldind.i" | "ldind.r8" | "ldind.ref" => {
                Some(Self::lift_ldind_typed(8, mnem))
            }
            // native int (platform-dependent; model as 8)
            // â”€â”€ Indirect stores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "stind.i1" => Some(Self::lift_stind(1)),
            "stind.i2" => Some(Self::lift_stind(2)),
            "stind.i4" | "stind.r4" => Some(Self::lift_stind(4)),
            "stind.i8" | "stind.i" | "stind.r8" | "stind.ref" => Some(Self::lift_stind(8)),
            // â”€â”€ Object loads/stores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldobj" => Some(Self::lift_ldobj()),
            "stobj" => Some(Self::lift_stobj()),

            // â”€â”€ Field access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldfld" => Some(Self::lift_ldfld()),
            "stfld" => Some(Self::lift_stfld()),
            "ldsfld" => Some(Self::lift_ldsfld()),
            "stsfld" => Some(Self::lift_stsfld()),
            "ldflda" => {
                // Load field address: conceptually the object ref + offset â†’ pointer.
                // Model as Intrinsic since we don't know the field offset statically.
                Some(vec![Effect::Intrinsic {
                    name: "ldflda".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }])
            }
            "ldsflda" => {
                Some(vec![Effect::Intrinsic {
                    name: "ldsflda".to_string(),
                    args: vec![],
                }])
            }

            // â”€â”€ Initialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "initobj" => Some(Self::lift_initobj()),

            // â”€â”€ Calls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "call" | "callvirt" | "calli" | "tail.call" => Some(Self::lift_call(instr)),

            // â”€â”€ Return â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ret" => Some(Self::lift_ret()),

            // â”€â”€ Object creation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "newobj" => Some(Self::lift_newobj(instr)),
            "newarr" => Some(Self::lift_newarr(instr)),
            "ldlen" => Some(Self::lift_ldlen()),

            // â”€â”€ Exception handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "throw" => Some(Self::lift_throw()),
            "rethrow" => Some(vec![Effect::Intrinsic {
                name: "rethrow".to_string(),
                args: vec![],
            }]),
            "endfinally" | "endfilter" => Some(vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }]),
            "leave" | "leave.s" => {
                // Leave a protected region; unconditional branch out of try/catch.
                Some(vec![Effect::Branch {
                    target: branch_target_expr(instr),
                    condition: None,
                }])
            }

            // â”€â”€ Type conversion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "conv.i1" => Some(Self::lift_conv("i1")),
            "conv.i2" => Some(Self::lift_conv("i2")),
            "conv.i4" => Some(Self::lift_conv("i4")),
            "conv.i8" => Some(Self::lift_conv("i8")),
            "conv.u1" => Some(Self::lift_conv("u1")),
            "conv.u2" => Some(Self::lift_conv("u2")),
            "conv.u4" => Some(Self::lift_conv("u4")),
            "conv.u8" => Some(Self::lift_conv("u8")),
            "conv.i" => Some(Self::lift_conv("i")),
            "conv.u" => Some(Self::lift_conv("u")),
                _ => None,
            }
    }
    fn mnemonic_to_effects_d_a_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();

                    match mnem {
            "conv.r4" => Some(Self::lift_conv("r4")),
            "conv.r8" => Some(Self::lift_conv("r8")),
            "conv.r.un" => Some(Self::lift_conv("r.un")),
            "conv.ovf.i1" | "conv.ovf.i1.un" => Some(Self::lift_conv("ovf.i1")),
            "conv.ovf.i2" | "conv.ovf.i2.un" => Some(Self::lift_conv("ovf.i2")),
            "conv.ovf.i4" | "conv.ovf.i4.un" => Some(Self::lift_conv("ovf.i4")),
            "conv.ovf.i8" | "conv.ovf.i8.un" => Some(Self::lift_conv("ovf.i8")),
            "conv.ovf.u1" | "conv.ovf.u1.un" => Some(Self::lift_conv("ovf.u1")),
            "conv.ovf.u2" | "conv.ovf.u2.un" => Some(Self::lift_conv("ovf.u2")),
            "conv.ovf.u4" | "conv.ovf.u4.un" => Some(Self::lift_conv("ovf.u4")),
            "conv.ovf.u8" | "conv.ovf.u8.un" => Some(Self::lift_conv("ovf.u8")),
            "ldelem.i1" | "ldelem.u1" => {
                // array ref = s_1, index = s_0
                Some(vec![Effect::Intrinsic {
                    name: "ldelem".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(1)), IrExpr::Reg(stack_reg(0))],
                }])
            }
            "ldelem.i2" | "ldelem.u2" | "ldelem.i4" | "ldelem.u4" | "ldelem.i8" | "ldelem.i"
            | "ldelem.r4" | "ldelem.r8" | "ldelem.ref" | "ldelem" => {
                Some(vec![Effect::Intrinsic {
                    name: "ldelem".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(1)), IrExpr::Reg(stack_reg(0))],
                }])
            }
            "stelem.i1" | "stelem.i2" | "stelem.i4" | "stelem.i8" | "stelem.r4" | "stelem.r8"
            | "stelem.ref" | "stelem" | "stelem.i" => {
                // array = s_2, index = s_1, value = s_0
                Some(vec![Effect::Intrinsic {
                    name: "stelem".to_string(),
                    args: vec![
                        IrExpr::Reg(stack_reg(2)),
                        IrExpr::Reg(stack_reg(1)),
                        IrExpr::Reg(stack_reg(0)),
                    ],
                }])
            }
            "ldelema" => {
                Some(vec![Effect::Intrinsic {
                    name: "ldelema".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(1)), IrExpr::Reg(stack_reg(0))],
                }])
            }
            "box" => {
                Some(vec![Effect::Intrinsic {
                    name: "box".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }])
            }
            "unbox" | "unbox.any" => {
                Some(vec![Effect::Intrinsic {
                    name: "unbox".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }])
            }
            "castclass" => {
                Some(vec![Effect::Intrinsic {
                    name: "castclass".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }])
            }
            "isinst" => {
                Some(vec![Effect::Intrinsic {
                    name: "isinst".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }])
            }
            "ldvirtftn" => {
                Some(vec![Effect::Intrinsic {
                    name: "ldvirtftn".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }])
            }
            "ldftn" => {
                Some(vec![Effect::Intrinsic {
                    name: "ldftn".to_string(),
                    args: vec![branch_target_expr(instr)],
                }])
            }
            "ldtoken" => {
                Some(vec![Effect::Intrinsic {
                    name: "ldtoken".to_string(),
                    args: vec![branch_target_expr(instr)],
                }])
            }
                        _ => None,
                    }
    }

    fn mnemonic_to_effects_d_a_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let _mnem = mnem.trim();

                    None
    }

    fn mnemonic_to_effects_d_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let _mnem = mnem.trim();

        let __s0 = Self::mnemonic_to_effects_d_a_a(instr);
        if __s0.is_some() { return __s0; }
        Self::mnemonic_to_effects_d_a_b(instr)
    }

    fn mnemonic_to_effects_d_b(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();

                match mnem {
            "ldstr" => {
                // Push a reference to a string constant.
                vec![Effect::Intrinsic {
                    name: "ldstr".to_string(),
                    args: vec![branch_target_expr(instr)],
                }]
            }
            "volatile." | "unaligned." | "tail." | "constrained." | "readonly." => {
                // Instruction prefixes â€” no semantic effect at LLIL.
                Self::lift_nop()
            }
            "ckfinite" => {
                vec![Effect::Intrinsic {
                    name: "ckfinite".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }]
            }
            "localloc" => {
                vec![Effect::Intrinsic {
                    name: "localloc".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }]
            }
            "cpobj" => {
                vec![Effect::Intrinsic {
                    name: "cpobj".to_string(),
                    args: vec![IrExpr::Reg(stack_reg(1)), IrExpr::Reg(stack_reg(0))],
                }]
            }
            "cpblk" => {
                vec![Effect::Intrinsic {
                    name: "cpblk".to_string(),
                    args: vec![
                        IrExpr::Reg(stack_reg(2)),
                        IrExpr::Reg(stack_reg(1)),
                        IrExpr::Reg(stack_reg(0)),
                    ],
                }]
            }
            "initblk" => {
                vec![Effect::Intrinsic {
                    name: "initblk".to_string(),
                    args: vec![
                        IrExpr::Reg(stack_reg(2)),
                        IrExpr::Reg(stack_reg(1)),
                        IrExpr::Reg(stack_reg(0)),
                    ],
                }]
            }
            "sizeof" => {
                vec![Effect::Intrinsic {
                    name: "sizeof".to_string(),
                    args: vec![branch_target_expr(instr)],
                }]
            }
            "refanytype" | "refanyval" | "mkrefany" => {
                vec![Effect::Intrinsic {
                    name: mnem.to_string(),
                    args: vec![IrExpr::Reg(stack_reg(0))],
                }]
            }
            "arglist" => {
                vec![Effect::Intrinsic {
                    name: "arglist".to_string(),
                    args: vec![],
                }]
            }
            "jmp" => {
                // Tail-call jump to a method.
                Self::lift_call(instr)
            }
            _ => {
                vec![Effect::Intrinsic {
                    name: format!("__cil_unimpl_{mnem}"),
                    args: vec![],
                }]
            }
                }
    }

    fn mnemonic_to_effects_d(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let _mnem = mnem.trim();

        let __s0 = Self::mnemonic_to_effects_d_a(instr);
        if let Some(v) = __s0 { return v; }
        Self::mnemonic_to_effects_d_b(instr)
    }

    fn mnemonic_to_effects(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let _mnem = mnem.trim();

        let __r0 = Self::mnemonic_to_effects_a(instr);
        if let Some(v) = __r0 { return v; }
        let __r1 = Self::mnemonic_to_effects_b(instr);
        if let Some(v) = __r1 { return v; }
        let __r2 = Self::mnemonic_to_effects_c(instr);
        if let Some(v) = __r2 { return v; }
        Self::mnemonic_to_effects_d(instr)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Default
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl Default for CilLifter {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ArchLifter implementation
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl fmt::Display for CilLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CilLifter(.NET CIL/MSIL LLIL)")
    }
}

impl ArchLifter for CilLifter {
    fn arch_name(&self) -> &'static str {
        "cil"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        ".NET Common Intermediate Language (CIL/MSIL) LLIL lifter"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let effects = Self::mnemonic_to_effects(instr);
        let ir_text = if effects.is_empty() {
            "nop".to_string()
        } else {
            effects
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        };
        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::Instruction;

    /// Build a minimal `Instruction` with the given mnemonic and optional
    /// operand string.  The structured `operand_list` is left empty.
    fn make_instr(mnemonic: &str, operands: &str) -> Instruction {
        let mut instr = Instruction::new(Address(0x0000_1000), 1, mnemonic.to_string(), vec![0x00]);
        instr.operands = operands.to_string();
        instr
    }

    /// Convenience: lift a single instruction with a fresh `CilLifter`.
    fn lift(mnemonic: &str, operands: &str) -> LiftedInstr {
        let lifter = CilLifter::new();
        let instr = make_instr(mnemonic, operands);
        lifter.lift(&instr).expect("lift should succeed")
    }

    // â”€â”€ Test 1: ldc.i4.1 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldc_i4_1_pushes_const_1() {
        let li = lift("ldc.i4.1", "");
        assert_eq!(li.effects.len(), 1, "expected exactly one effect");
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0", "should write to stack top");
                assert_eq!(*value, IrExpr::Const(1), "should push constant 1");
            }
            other => panic!("unexpected effect: {other:?}"),
        }
        assert!(!li.ir_text.is_empty());
    }

    // â”€â”€ Test 2: ldc.i4.m1 (push -1) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldc_i4_m1_pushes_minus_one() {
        let li = lift("ldc.i4.m1", "");
        match &li.effects[0] {
            Effect::RegWrite { value, .. } => {
                // -1 as u64 = 0xFFFF_FFFF_FFFF_FFFF
                assert_eq!(*value, IrExpr::Const((-1i64) as u64));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 3: ldc.i4.s with explicit operand â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldc_i4_s_with_operand() {
        let li = lift("ldc.i4.s", "42");
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert_eq!(*value, IrExpr::Const(42));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 4: add â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_add_pops_two_pushes_one() {
        let li = lift("add", "");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0", "result goes to stack top");
                match value {
                    IrExpr::Add(lhs, rhs) => {
                        assert_eq!(**lhs, IrExpr::Reg("s_1".to_string()));
                        assert_eq!(**rhs, IrExpr::Reg("s_0".to_string()));
                    }
                    other => panic!("expected Add, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    /// `LDIND.*` is a TYPED load and one handler flattened four facts:
    /// signedness (`.i1` vs `.u1`), float vs integer (`.r4`/`.r8`), object
    /// reference (`.ref`), and native int (`.i`). All of them must survive.
    ///
    /// Asserting all four — not just the signedness I came looking for — is the
    /// point: a shared arm assumes several things equal.
    #[test]
    fn ldind_variants_are_all_distinguishable() {
        let r = |m: &str| format!("{:?}", lift(m, "").effects);
        // signedness
        assert_ne!(r("ldind.i1"), r("ldind.u1"), "signed and unsigned differ");
        // float vs integer, at the same size
        assert_ne!(r("ldind.i4"), r("ldind.r4"), "a float load is not an int load");
        // object reference vs integer, at the same size
        assert_ne!(r("ldind.i8"), r("ldind.ref"), "a reference is not an integer");
        // native int vs fixed 64-bit
        assert_ne!(r("ldind.i"), r("ldind.i8"), "native int is platform-dependent");
    }

    // â”€â”€ Test 5: add.ovf must be DISTINGUISHABLE from add â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// This test used to be called `test_add_ovf_same_as_add` and asserted
    /// `assert_eq!` — the NAME asserted the defect. `ADD.OVF` throws
    /// `OverflowException` where `ADD` wraps, so lifting them identically makes
    /// a checked add read as an unchecked one.
    ///
    /// Ninth test in this session whose name froze the under-modelling it
    /// should have caught. **When a fix breaks a test, read the test name
    /// first: it often states the assumption that IS the bug.**
    #[test]
    fn add_ovf_is_distinguishable_from_add() {
        let li_add = lift("add", "");
        let li_ovf = lift("add.ovf", "");
        assert_ne!(
            li_add.effects, li_ovf.effects,
            "ADD.OVF can trap; ADD cannot — they must not lift identically"
        );
        assert_ne!(
            lift("add.ovf", "").effects,
            lift("add.ovf.un", "").effects,
            "the signed and unsigned overflow checks are different instructions"
        );
    }

    // â”€â”€ Test 6: sub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sub_effect() {
        let li = lift("sub", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Sub(lhs, rhs),
                ..
            } => {
                assert_eq!(**lhs, IrExpr::Reg("s_1".to_string()));
                assert_eq!(**rhs, IrExpr::Reg("s_0".to_string()));
            }
            other => panic!("expected Sub RegWrite, got {other:?}"),
        }
    }

    // â”€â”€ Test 7: mul â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_mul_effect() {
        let li = lift("mul", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Mul(..),
                ..
            } => {}
            other => panic!("expected Mul RegWrite, got {other:?}"),
        }
    }

    // â”€â”€ Test 8: ldloc.0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldloc_0_reads_local_0() {
        let li = lift("ldloc.0", "");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert_eq!(*value, IrExpr::Reg("local_0".to_string()));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 9: ldloc.s N reads local_N â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldloc_s_reads_local_n() {
        let li = lift("ldloc.s", "7");
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert_eq!(*value, IrExpr::Reg("local_7".to_string()));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 10: stloc.0 writes to local_0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_stloc_0_writes_local_0() {
        let li = lift("stloc.0", "");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "local_0");
                assert_eq!(*value, IrExpr::Reg("s_0".to_string()));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 11: ldarg.0 reads arg_0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldarg_0_reads_arg_0() {
        let li = lift("ldarg.0", "");
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                assert_eq!(*value, IrExpr::Reg("arg_0".to_string()));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 12: br (unconditional branch) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_br_unconditional_branch() {
        // Use a decimal IL offset as the operand.
        let li = lift("br", "0x2000");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::Branch { target, condition } => {
                assert_eq!(*target, IrExpr::Const(0x2000));
                assert!(condition.is_none(), "br must be unconditional");
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 13: br.s (short form) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_br_s_unconditional() {
        let li = lift("br.s", "IL_0042");
        match &li.effects[0] {
            Effect::Branch { target, condition } => {
                assert_eq!(*target, IrExpr::Const(0x0042));
                assert!(condition.is_none());
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 14: brfalse (conditional branch on zero) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_brfalse_branch_on_zero() {
        let li = lift("brfalse", "0x3000");
        match &li.effects[0] {
            Effect::Branch { target, condition } => {
                assert_eq!(*target, IrExpr::Const(0x3000));
                assert!(condition.is_some(), "brfalse must be conditional");
                // Condition should be CmpEqZero(s_0).
                match condition.as_ref().unwrap() {
                    IrExpr::CmpEqZero(inner) => {
                        assert_eq!(**inner, IrExpr::Reg("s_0".to_string()));
                    }
                    other => panic!("expected CmpEqZero, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 15: brtrue (conditional branch on non-zero) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_brtrue_branch_on_nonzero() {
        let li = lift("brtrue", "0x4000");
        match &li.effects[0] {
            Effect::Branch { condition, .. } => {
                assert!(condition.is_some());
                match condition.as_ref().unwrap() {
                    IrExpr::Not(inner) => {
                        matches!(**inner, IrExpr::CmpEqZero(_));
                    }
                    other => panic!("expected Not(CmpEqZero(_)), got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 16: ret â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ret_returns_with_stack_value() {
        let li = lift("ret", "");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::Return { value } => {
                assert!(
                    value.is_some(),
                    "ret should carry the stack top as return value"
                );
                assert_eq!(value.as_ref().unwrap(), &IrExpr::Reg("s_0".to_string()));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
        assert!(li.is_terminator(), "ret must be a terminator");
    }

    // â”€â”€ Test 17: nop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_nop_has_no_effects() {
        let li = lift("nop", "");
        assert!(li.effects.is_empty(), "nop should produce no effects");
        assert_eq!(li.ir_text, "nop");
    }

    // â”€â”€ Test 18: dup duplicates stack top â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_dup_duplicates_stack_top() {
        let li = lift("dup", "");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_1");
                assert_eq!(*value, IrExpr::Reg("s_0".to_string()));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 19: and / or / xor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_bitwise_and() {
        let li = lift("and", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::And(..),
                ..
            } => {}
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn test_bitwise_or() {
        let li = lift("or", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Or(..),
                ..
            } => {}
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn test_bitwise_xor() {
        let li = lift("xor", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Xor(..),
                ..
            } => {}
            other => panic!("expected Xor, got {other:?}"),
        }
    }

    // â”€â”€ Test 20: not â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_not_inverts_top() {
        let li = lift("not", "");
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                match value {
                    IrExpr::Not(inner) => {
                        assert_eq!(**inner, IrExpr::Reg("s_0".to_string()));
                    }
                    other => panic!("expected Not, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 21: shl / shr â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_shl() {
        let li = lift("shl", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Shl(..),
                ..
            } => {}
            other => panic!("expected Shl, got {other:?}"),
        }
    }

    /// `shr` is CIL's ARITHMETIC shift and `shr.un` the logical one.
    ///
    /// This test asserted `IrExpr::Shr` for `shr` — the logical node — and no
    /// test covered `shr.un` at all, so nothing compared the two. It pinned the
    /// defect the lifter's own comment described.
    #[test]
    fn test_shr() {
        let li = lift("shr", "");
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Sar(..),
                ..
            } => {}
            other => panic!("shr is arithmetic; expected Sar, got {other:?}"),
        }

        let un = lift("shr.un", "");
        match &un.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Shr(..),
                ..
            } => {}
            other => panic!("shr.un is logical; expected Shr, got {other:?}"),
        }
        assert_ne!(
            format!("{:?}", li.effects),
            format!("{:?}", un.effects),
            "shr and shr.un must not lift identically"
        );
    }

    // â”€â”€ Test 22: div is an intrinsic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_div_is_intrinsic() {
        let li = lift("div", "");
        match &li.effects[0] {
            Effect::Intrinsic { name, args } => {
                assert_eq!(name, "div");
                assert_eq!(args.len(), 2);
            }
            other => panic!("expected Intrinsic, got {other:?}"),
        }
    }

    // â”€â”€ Test 23: ceq produces CmpEqZero â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ceq_compares_stack_top_two() {
        let li = lift("ceq", "");
        match &li.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "s_0");
                match value {
                    IrExpr::CmpEqZero(inner) => match inner.as_ref() {
                        IrExpr::Sub(lhs, rhs) => {
                            assert_eq!(**lhs, IrExpr::Reg("s_1".to_string()));
                            assert_eq!(**rhs, IrExpr::Reg("s_0".to_string()));
                        }
                        other => panic!("expected Sub inside CmpEqZero, got {other:?}"),
                    },
                    other => panic!("expected CmpEqZero, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // â”€â”€ Test 24: ldind.i4 is MemRead â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldind_i4_mem_read() {
        let li = lift("ldind.i4", "");
        match &li.effects[0] {
            Effect::MemRead { addr, dest, size } => {
                assert_eq!(*addr, IrExpr::Reg("s_0".to_string()));
                assert_eq!(dest, "s_0");
                assert_eq!(*size, 4);
            }
            other => panic!("expected MemRead, got {other:?}"),
        }
    }

    // â”€â”€ Test 25: stind.i4 is MemWrite â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_stind_i4_mem_write() {
        let li = lift("stind.i4", "");
        match &li.effects[0] {
            Effect::MemWrite { addr, value, size } => {
                assert_eq!(*addr, IrExpr::Reg("s_1".to_string()));
                assert_eq!(*value, IrExpr::Reg("s_0".to_string()));
                assert_eq!(*size, 4);
            }
            other => panic!("expected MemWrite, got {other:?}"),
        }
    }

    // â”€â”€ Test 26: call emits Call effect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_call_emits_call_effect() {
        let li = lift("call", "0x5000");
        match &li.effects[0] {
            Effect::Call { target } => {
                assert_eq!(*target, IrExpr::Const(0x5000));
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    // â”€â”€ Test 27: beq uses CmpEqZero(Sub) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_beq_condition() {
        let li = lift("beq", "0x6000");
        match &li.effects[0] {
            Effect::Branch { target, condition } => {
                assert_eq!(*target, IrExpr::Const(0x6000));
                let cond = condition.as_ref().expect("beq must have condition");
                assert!(matches!(cond, IrExpr::CmpEqZero(_)));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Test 28: ldc.i8 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldc_i8() {
        let li = lift("ldc.i8", "0xDEADBEEFCAFEBABE");
        match &li.effects[0] {
            Effect::RegWrite { value, .. } => {
                assert_eq!(*value, IrExpr::Const(0xDEAD_BEEF_CAFE_BABE));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Test 29: initobj zeroes memory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_initobj_zero_write() {
        let li = lift("initobj", "SomeType");
        match &li.effects[0] {
            Effect::MemWrite { addr, value, .. } => {
                assert_eq!(*addr, IrExpr::Reg("s_0".to_string()));
                assert_eq!(*value, IrExpr::Const(0));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Test 30: throw is Intrinsic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_throw_is_intrinsic() {
        let li = lift("throw", "");
        match &li.effects[0] {
            Effect::Intrinsic { name, args } => {
                assert_eq!(name, "throw");
                assert_eq!(args.len(), 1);
                assert_eq!(args[0], IrExpr::Reg("s_0".to_string()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Test 31: conv.i4 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_conv_i4() {
        let li = lift("conv.i4", "");
        match &li.effects[0] {
            Effect::Intrinsic { name, args } => {
                assert_eq!(name, "conv.i4");
                assert_eq!(args.len(), 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Test 32: unknown opcode â†’ __cil_unimpl_ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_unknown_opcode_intrinsic() {
        let li = lift("some.exotic.opcode", "");
        match &li.effects[0] {
            Effect::Intrinsic { name, .. } => {
                assert!(name.starts_with("__cil_unimpl_"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Test 33: arch_name and lift_level â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_arch_metadata() {
        let lifter = CilLifter::new();
        assert_eq!(lifter.arch_name(), "cil");
        assert_eq!(lifter.lift_level(), LiftLevel::Llil);
    }

    // â”€â”€ Test 34: ir_text is non-empty for instructions with effects â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ir_text_populated() {
        let li = lift("ldloc.3", "");
        assert!(!li.ir_text.is_empty());
        assert!(li.ir_text.contains("s_0"));
    }

    // â”€â”€ Test 35: ldnull pushes 0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldnull_pushes_zero() {
        let li = lift("ldnull", "");
        match &li.effects[0] {
            Effect::RegWrite { value, .. } => {
                assert_eq!(*value, IrExpr::Const(0));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
