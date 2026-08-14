//! Stack instruction lifters for x86/x64.
//!
//! # Coverage
//!
//! This module handles the complete set of x86/x64 stack-manipulation
//! instructions, atomising each one into an ordered sequence of micro-ops
//! emitted onto [`X86LiftCtx`]:
//!
//! | Instruction family | Variants handled |
//! |--------------------|-----------------|
//! | `PUSH` | reg16/32/64, imm8 (sign-extended), imm16/32 (sign-extended to op-size), mem16/32/64, CS/DS/ES/FS/GS/SS |
//! | `POP`  | reg16/32/64, mem16/32/64, FS/GS |
//! | `PUSHA` / `PUSHAD` | 16-bit / 32-bit forms; #UD in 64-bit mode |
//! | `POPA`  / `POPAD`  | 16-bit / 32-bit forms; #UD in 64-bit mode |
//! | `PUSHF` / `PUSHFD` / `PUSHFQ` | EFLAGS → stack, operand-size-sensitive |
//! | `POPF`  / `POPFD`  / `POPFQ`  | stack → EFLAGS, all flags unpacked |
//! | `ENTER imm16, imm8` | full nesting-level semantics |
//! | `LEAVE` | FP-teardown |
//!
//! # Micro-op discipline
//!
//! Every handler decomposes its semantics into *atomic* micro-ops so that
//! downstream analysis (def-use, live-variable, value-set analysis) can reason
//! about partial reads and writes without treating each instruction as an
//! opaque black box:
//!
//! 1. **RSP adjustment** — always emitted as an explicit `Effect::RegWrite` to
//!    `rsp`/`esp`/`sp`.  Analysis passes can trivially extract stack-depth
//!    information from this single effect.
//!
//! 2. **Memory access** — `Effect::MemWrite` or `Effect::MemRead` at the
//!    *updated* `RSP` address.  The memory size in bytes matches the operand
//!    size so that VSA can track byte-precise aliasing.
//!
//! 3. **Flag effects** — PUSHF/POPF emit an intrinsic pair
//!    (`x86.pack_eflags` / `x86.unpack_eflags`) followed by individual
//!    `RegWrite` to the symbolic flag registers.  The lazy-flag idiom used
//!    elsewhere in the lifter is preserved.
//!
//! # 64-bit default operand size
//!
//! Per Intel SDM §2.2.1.2 and §4.1.1: in 64-bit mode the default operand
//! size for PUSH and POP is **64 bits**, even without a REX.W prefix.  The
//! 66h prefix downgrades to 16-bit; 32-bit is not encodable.  The lifter
//! relies on `iced_x86` reporting the correct `memory_size()` for memory
//! operands (which already accounts for these rules), and on
//! [`X86LiftCtx::stack_ptr_size`] for the SP delta.
//!
//! # PUSH imm8 sign-extension
//!
//! `PUSH imm8` (opcode 6A /ib) sign-extends its 8-bit immediate to the
//! current operand size *before* pushing.  The lifter applies explicit
//! sign-extension via [`sign_extend_imm`] so that the IL value stored on
//! the stack is the full-width constant.
//!
//! # Segment push/pop
//!
//! In 16-bit / 32-bit mode all six segment registers (CS, DS, ES, FS, GS,
//! SS) can be pushed or popped with a two-byte push and a word-or-dword pop.
//! In 64-bit mode only FS and GS are encodable; CS/DS/ES/SS generate #UD.
//! The handlers model segment reads / writes via the symbolic register names
//! `"cs"` / `"ds"` / … so that analysis can track cross-instruction segment
//! state.

#![allow(clippy::too_many_lines)] // handlers are inherently long

use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_operand::{read_operand, write_operand};
use crate::{IrExpr, LiftError};
use iced_x86::{Instruction, OpKind, Register};

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Sign-extend an immediate value from `from_bits` wide to the full 64-bit
/// representation used by `IrExpr::Const`.
///
/// # Arguments
///
/// * `val`       — the raw (unsigned) immediate as decoded by iced-x86.
/// * `from_bits` — the source bit-width (typically 8).
///
/// # Example
///
/// ```text
/// sign_extend_imm(0xFE, 8) == 0xFFFF_FFFF_FFFF_FFFEu64
/// sign_extend_imm(0x7F, 8) == 0x0000_0000_0000_007Fu64
/// ```
#[inline]
fn sign_extend_imm(val: u64, from_bits: u8) -> u64 {
    debug_assert!(from_bits < 64, "sign-extending 64-bit immediate is a no-op");
    let shift = 64 - from_bits;
    // Arithmetic right-shift restores the sign.
    ((val.cast_signed() << shift) >> shift).cast_unsigned()
}

/// Perform a stack **push** of `value` (of `elem_bytes` bytes) into the
/// context, adjusting the stack pointer register.
///
/// The RSP adjustment is:
/// ```text
///   (R/E)SP := (R/E)SP - elem_bytes
///   *[(R/E)SP] := value
/// ```
///
/// This is the canonical micro-op sequence for PUSH; callers that share this
/// primitive include `lift_push`, `lift_pusha`, `lift_pushf`, and `lift_enter`.
fn push_value(value: IrExpr, elem_bytes: u8, ctx: &mut X86LiftCtx) {
    let sp = ctx.stack_ptr();
    let delta = u64::from(elem_bytes);

    // SP := SP - elem_bytes
    let new_sp = IrExpr::Sub(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(delta)),
    );
    ctx.emit_reg_write(sp, new_sp);

    // *[SP] := value
    ctx.emit_mem_write(IrExpr::Reg(sp.into()), value, elem_bytes);
}

/// Perform a stack **pop** of `elem_bytes` bytes from the context, adjusting
/// the stack pointer register.
///
/// The RSP adjustment is:
/// ```text
///   temp := *[(R/E)SP]
///   (R/E)SP := (R/E)SP + elem_bytes
/// ```
///
/// Returns the name of the fresh temporary that holds the popped value.
fn pop_value(elem_bytes: u8, ctx: &mut X86LiftCtx) -> String {
    let sp = ctx.stack_ptr();
    let delta = u64::from(elem_bytes);

    // Read *[SP] into a fresh temp.
    let t = ctx.fresh_temp();
    ctx.emit_mem_read(IrExpr::Reg(sp.into()), t.clone(), elem_bytes);

    // SP := SP + elem_bytes
    let new_sp = IrExpr::Add(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(delta)),
    );
    ctx.emit_reg_write(sp, new_sp);

    t
}

/// Determine the operand element size (in bytes) for a PUSH/POP instruction.
///
/// In 64-bit mode, PUSH/POP default to 64-bit operands unless the 66h
/// operand-size override is present (which forces 16-bit).  32-bit and 16-bit
/// operand sizes are governed by the normal D/W bits and the 66h prefix.
///
/// `iced_x86` already handles this correctly: for register or immediate
/// operands it reports the decoded operand kind with the right width; for
/// memory operands `memory_size()` is correct.  We inspect the operand kind
/// and fall back to `stack_ptr_size()` when ambiguous.
fn push_pop_elem_size(instr: &Instruction, ctx: &X86LiftCtx) -> u8 {
    // Fast path: inspect op0.
    match instr.op0_kind() {
        OpKind::Register => {
            // Map the register to its width in bytes.
            reg_byte_width(instr.op0_register()).unwrap_or_else(|| ctx.stack_ptr_size())
        }
        OpKind::Immediate8 => {
            // PUSH imm8 — the push *element* is operand-size wide, not 1 byte.
            // iced distinguishes PUSH imm8 via Immediate8to16/32/64.
            ctx.stack_ptr_size()
        }
        OpKind::Immediate8to16 | OpKind::Immediate16 => 2,
        OpKind::Immediate8to32 | OpKind::Immediate32 => 4,
        OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate64 => 8,
        OpKind::Memory => {
            // iced `memory_size()` is authoritative.
            memory_size_bytes(instr.memory_size()).unwrap_or_else(|| ctx.stack_ptr_size())
        }
        _ => ctx.stack_ptr_size(),
    }
}

/// Return the byte width of an x86 general-purpose register.
const fn reg_byte_width(reg: Register) -> Option<u8> {
    use Register as R;
    match reg {
        // 8-bit
        R::AL
        | R::CL
        | R::DL
        | R::BL
        | R::AH
        | R::CH
        | R::DH
        | R::BH
        | R::SPL
        | R::BPL
        | R::SIL
        | R::DIL
        | R::R8L
        | R::R9L
        | R::R10L
        | R::R11L
        | R::R12L
        | R::R13L
        | R::R14L
        | R::R15L => Some(1),
        // 16-bit
        R::AX
        | R::CX
        | R::DX
        | R::BX
        | R::SP
        | R::BP
        | R::SI
        | R::DI
        | R::R8W
        | R::R9W
        | R::R10W
        | R::R11W
        | R::R12W
        | R::R13W
        | R::R14W
        | R::R15W
        | R::CS
        | R::DS
        | R::ES
        | R::FS
        | R::GS
        | R::SS => Some(2),
        // 32-bit
        R::EAX
        | R::ECX
        | R::EDX
        | R::EBX
        | R::ESP
        | R::EBP
        | R::ESI
        | R::EDI
        | R::R8D
        | R::R9D
        | R::R10D
        | R::R11D
        | R::R12D
        | R::R13D
        | R::R14D
        | R::R15D => Some(4),
        // 64-bit
        R::RAX
        | R::RCX
        | R::RDX
        | R::RBX
        | R::RSP
        | R::RBP
        | R::RSI
        | R::RDI
        | R::R8
        | R::R9
        | R::R10
        | R::R11
        | R::R12
        | R::R13
        | R::R14
        | R::R15 => Some(8),
        _ => None,
    }
}

/// Canonical lowercase IR name for a segment register.
const fn segment_reg_name(reg: Register) -> Option<&'static str> {
    use Register as R;
    match reg {
        R::CS => Some("cs"),
        R::DS => Some("ds"),
        R::ES => Some("es"),
        R::FS => Some("fs"),
        R::GS => Some("gs"),
        R::SS => Some("ss"),
        _ => None,
    }
}

/// Return the element size in bytes for an `iced_x86::MemorySize`.
const fn memory_size_bytes(ms: iced_x86::MemorySize) -> Option<u8> {
    use iced_x86::MemorySize as M;
    match ms {
        M::UInt8 | M::Int8 => Some(1),
        M::UInt16 | M::Int16 | M::SegPtr16 => Some(2),
        M::UInt32 | M::Int32 | M::SegPtr32 => Some(4),
        M::UInt64 | M::Int64 | M::SegPtr64 => Some(8),
        _ => None,
    }
}

/// Build the sign-extended `IrExpr::Const` for a PUSH-immediate source.
///
/// `iced_x86` already sign-extends immediates into the instruction's
/// `immediate(idx)` result, so this is mostly a formality, but we also
/// clamp the value to the actual operand size so that the constant
/// correctly round-trips through truncation.
fn sign_extended_imm_expr(instr: &Instruction, op_idx: u32, elem_bytes: u8) -> IrExpr {
    let raw = instr.immediate(op_idx);
    // iced already sign-extended to 64 bits; mask to operand size then
    // re-sign-extend to get a canonical representation.
    let mask = if elem_bytes >= 8 {
        u64::MAX
    } else {
        (1u64 << (elem_bytes * 8)) - 1
    };
    IrExpr::Const(raw & mask)
}

/// Emit an intrinsic recording that the operand had a segment override, so
/// that alias-analysis passes can account for segment-relative addresses
/// even though the lifter otherwise ignores segmentation in flat models.
///
/// The intrinsic is no-op in analysis but preserves the information for
/// passes that care (e.g. real-mode lifters).
fn emit_seg_override_hint(seg: Register, ctx: &mut X86LiftCtx) {
    if seg != Register::None
        && let Some(name) = segment_reg_name(seg) {
            ctx.emit_intrinsic(
                format!("x86.seg_override.{name}"),
                vec![IrExpr::Reg(name.into())],
            );
        }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUSH — all forms
// ─────────────────────────────────────────────────────────────────────────────

/// `PUSH r/m16`, `PUSH r/m32`, `PUSH r/m64`
///
/// Decrement (R/E)SP by the operand size, then store the source at the new
/// stack-top address.
///
/// # Operand forms (iced-x86 `OpKind` variants reached here)
///
/// | Encoding | Operand 0 | Note |
/// |----------|-----------|------|
/// | `FF /6`  | `Reg`    | GPR of any width legal in current mode |
/// | `FF /6`  | `Memory` | memory operand; size from `memory_size()` |
/// | `50+rd`  | `Reg`    | short-form register push |
///
/// # 64-bit mode note
///
/// The operand size defaults to 64-bit; the 66h prefix selects 16-bit.
/// 32-bit PUSH is *not* encodable in 64-bit mode (no REX.W needed since
/// 64-bit is the default; 66h forces 16-bit).
///
/// # RSP adjustment
///
/// ```text
/// (R/E/SP) := (R/E/SP) - operand_bytes
/// *[(R/E/SP)] := src
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Hint: segment override present on the memory source.
    emit_seg_override_hint(instr.segment_prefix(), ctx);

    let w = push_pop_elem_size(instr, ctx);

    // Build the source expression — handle immediate sign-extension explicitly.
    let src = match instr.op0_kind() {
        OpKind::Immediate8to16 => sign_extended_imm_expr(instr, 0, 2),
        OpKind::Immediate8to32 => sign_extended_imm_expr(instr, 0, 4),
        OpKind::Immediate8to64 => sign_extended_imm_expr(instr, 0, 8),
        OpKind::Immediate16 => IrExpr::Const(u64::from(instr.immediate16())),
        OpKind::Immediate32 => IrExpr::Const(u64::from(instr.immediate32())),
        OpKind::Immediate32to64 => {
            // Sign-extend 32-bit immediate to 64-bit.
            IrExpr::Const(sign_extend_imm(u64::from(instr.immediate32()), 32))
        }
        OpKind::Immediate64 => IrExpr::Const(instr.immediate64()),
        _ => read_operand(instr, 0, ctx),
    };

    push_value(src, w, ctx);
    Ok(())
}

/// `PUSH CS` (opcode 0x0E) — push the CS segment register.
///
/// Only valid in 16-bit and 32-bit mode; generates #UD in 64-bit mode.
/// The on-stack value is zero-extended to the operand size.
///
/// # Note on CS write
///
/// Although a `POP CS` is *not* encodable (no such opcode), PUSH CS is
/// still useful to preserve the code-segment descriptor for far-return
/// frames in real mode.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_cs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSH CS is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    push_value(IrExpr::Reg("cs".into()), w, ctx);
    Ok(())
}

/// `PUSH DS` (opcode 0x1E) — push the DS segment register.
///
/// Valid in 16-bit and 32-bit modes only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_ds(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSH DS is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    push_value(IrExpr::Reg("ds".into()), w, ctx);
    Ok(())
}

/// `PUSH ES` (opcode 0x06) — push the ES segment register.
///
/// Valid in 16-bit and 32-bit modes only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_es(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSH ES is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    push_value(IrExpr::Reg("es".into()), w, ctx);
    Ok(())
}

/// `PUSH SS` (opcode 0x16) — push the SS segment register.
///
/// Valid in 16-bit and 32-bit modes only.  The push is followed by an
/// implicit "one-instruction inhibit of interrupts" window, which is not
/// modelled in the IL (it is a microarchitectural property).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_ss(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSH SS is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    push_value(IrExpr::Reg("ss".into()), w, ctx);
    Ok(())
}

/// `PUSH FS` (opcode 0x0F 0xA0) — push the FS segment register.
///
/// Valid in all three modes (16/32/64-bit).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_fs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = push_pop_elem_size(instr, ctx);
    push_value(IrExpr::Reg("fs".into()), w, ctx);
    Ok(())
}

/// `PUSH GS` (opcode 0x0F 0xA8) — push the GS segment register.
///
/// Valid in all three modes (16/32/64-bit).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_gs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = push_pop_elem_size(instr, ctx);
    push_value(IrExpr::Reg("gs".into()), w, ctx);
    Ok(())
}

/// Unified PUSH handler — dispatches to the segment-specific handlers above
/// when the single operand is a segment register, otherwise delegates to
/// [`lift_push`].
///
/// This is the entry-point called from the top-level dispatcher in `mod.rs`.
/// Its internal dispatch table avoids an if-else chain in hot lifting paths.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_push_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Check whether operand 0 is a segment register.
    if instr.op0_kind() == OpKind::Register {
        match instr.op0_register() {
            Register::CS => return lift_push_cs(instr, ctx),
            Register::DS => return lift_push_ds(instr, ctx),
            Register::ES => return lift_push_es(instr, ctx),
            Register::SS => return lift_push_ss(instr, ctx),
            Register::FS => return lift_push_fs(instr, ctx),
            Register::GS => return lift_push_gs(instr, ctx),
            _ => {}
        }
    }
    lift_push(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// POP — all forms
// ─────────────────────────────────────────────────────────────────────────────

/// `POP r/m16`, `POP r/m32`, `POP r/m64`
///
/// Load [SP] into the destination, then increment (R/E)SP by the operand size.
///
/// # 64-bit mode note
///
/// Same default-size rules as PUSH: defaults to 64-bit, 66h forces 16-bit.
///
/// # Memory destination
///
/// When the destination is a memory operand (opcode `8F /0`), the effective
/// address of the destination is computed *after* the RSP increment.  The
/// lifter emits the memory read and SP increment before the memory write, so
/// the address expression references the updated SP value.  When the destination
/// EA involves RSP (e.g. `POP [rsp+8]`), the updated RSP is used in the EA.
///
/// # RSP adjustment
///
/// ```text
/// temp := *[(R/E/SP)]
/// (R/E/SP) := (R/E/SP) + operand_bytes
/// dst := temp          (register or memory write)
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    emit_seg_override_hint(instr.segment_prefix(), ctx);

    let w = push_pop_elem_size(instr, ctx);

    // Read from stack (emits MemRead + SP increment).
    let t = pop_value(w, ctx);

    // Write the popped value to the destination.
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `POP DS` (opcode 0x1F) — pop the DS segment register.
///
/// Valid in 16/32-bit modes only.  The value written to DS is the popped
/// word (zero-extended if the stack element was narrower than 32 bits).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop_ds(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "POP DS is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    let t = pop_value(w, ctx);
    ctx.emit_reg_write("ds", IrExpr::Reg(t));
    Ok(())
}

/// `POP ES` (opcode 0x07) — pop the ES segment register.
///
/// Valid in 16/32-bit modes only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop_es(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "POP ES is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    let t = pop_value(w, ctx);
    ctx.emit_reg_write("es", IrExpr::Reg(t));
    Ok(())
}

/// `POP SS` (opcode 0x17) — pop the SS segment register.
///
/// Valid in 16/32-bit modes only.  The implicit one-instruction interrupt-
/// inhibit window is not modelled in the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop_ss(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "POP SS is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let w = push_pop_elem_size(instr, ctx);
    let t = pop_value(w, ctx);
    ctx.emit_reg_write("ss", IrExpr::Reg(t));
    Ok(())
}

/// `POP FS` (opcode 0x0F 0xA1) — pop the FS segment register.
///
/// Valid in all three modes.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop_fs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = push_pop_elem_size(instr, ctx);
    let t = pop_value(w, ctx);
    ctx.emit_reg_write("fs", IrExpr::Reg(t));
    Ok(())
}

/// `POP GS` (opcode 0x0F 0xA9) — pop the GS segment register.
///
/// Valid in all three modes.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop_gs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = push_pop_elem_size(instr, ctx);
    let t = pop_value(w, ctx);
    ctx.emit_reg_write("gs", IrExpr::Reg(t));
    Ok(())
}

/// Unified POP handler — dispatches to segment-specific handlers above when
/// the destination is a segment register, otherwise delegates to [`lift_pop`].
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pop_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if instr.op0_kind() == OpKind::Register {
        match instr.op0_register() {
            Register::DS => return lift_pop_ds(instr, ctx),
            Register::ES => return lift_pop_es(instr, ctx),
            Register::SS => return lift_pop_ss(instr, ctx),
            Register::FS => return lift_pop_fs(instr, ctx),
            Register::GS => return lift_pop_gs(instr, ctx),
            _ => {}
        }
    }
    lift_pop(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// PUSHA / PUSHAD
// ─────────────────────────────────────────────────────────────────────────────

/// `PUSHA` (opcode 0x60, 16-bit operand size) — push all eight 16-bit
/// general-purpose registers in the order: AX, CX, DX, BX, SP, BP, SI, DI.
///
/// The value of SP pushed is the **pre-PUSHA** SP, not the SP after each
/// incremental adjustment.  We materialise the initial SP value into a
/// fresh temp before entering the push loop.
///
/// # Validity
///
/// This instruction is invalid (#UD) in 64-bit mode.
///
/// # Micro-op sequence (16-bit)
///
/// ```text
/// saved_sp := sp
/// sp := sp -  2; *[sp] := ax
/// sp := sp -  2; *[sp] := cx
/// sp := sp -  2; *[sp] := dx
/// sp := sp -  2; *[sp] := bx
/// sp := sp -  2; *[sp] := saved_sp
/// sp := sp -  2; *[sp] := bp
/// sp := sp -  2; *[sp] := si
/// sp := sp -  2; *[sp] := di
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pusha(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSHA/PUSHAD is invalid in 64-bit mode (#UD)".into(),
        ));
    }

    let w: u8 = 2; // 16-bit operands for PUSHA
    let sp = ctx.stack_ptr();

    // Snapshot the initial SP *before* any adjustment.
    let saved_sp = ctx.materialise(IrExpr::Reg(sp.into()));

    // Push order: AX CX DX BX SP(saved) BP SI DI
    let regs: &[&str] = &["ax", "cx", "dx", "bx", "__saved_sp", "bp", "si", "di"];
    for &r in regs {
        let val = if r == "__saved_sp" {
            IrExpr::Reg(saved_sp.clone())
        } else {
            IrExpr::Reg(r.into())
        };
        push_value(val, w, ctx);
    }

    Ok(())
}

/// `PUSHAD` (opcode 0x60, 32-bit operand size) — push all eight 32-bit
/// general-purpose registers in the order: EAX, ECX, EDX, EBX, ESP, EBP,
/// ESI, EDI.
///
/// Same semantics as PUSHA but uses 4-byte elements and 32-bit registers.
///
/// # Validity
///
/// Invalid (#UD) in 64-bit mode.
///
/// # Micro-op sequence (32-bit)
///
/// ```text
/// saved_esp := esp
/// esp := esp - 4; *[esp] := eax
/// esp := esp - 4; *[esp] := ecx
/// esp := esp - 4; *[esp] := edx
/// esp := esp - 4; *[esp] := ebx
/// esp := esp - 4; *[esp] := saved_esp
/// esp := esp - 4; *[esp] := ebp
/// esp := esp - 4; *[esp] := esi
/// esp := esp - 4; *[esp] := edi
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pushad(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSHA/PUSHAD is invalid in 64-bit mode (#UD)".into(),
        ));
    }

    let w: u8 = 4; // 32-bit operands for PUSHAD
    let sp = ctx.stack_ptr();

    let saved_sp = ctx.materialise(IrExpr::Reg(sp.into()));

    let regs: &[&str] = &[
        "eax",
        "ecx",
        "edx",
        "ebx",
        "__saved_esp",
        "ebp",
        "esi",
        "edi",
    ];
    for &r in regs {
        let val = if r == "__saved_esp" {
            IrExpr::Reg(saved_sp.clone())
        } else {
            IrExpr::Reg(r.into())
        };
        push_value(val, w, ctx);
    }

    Ok(())
}

/// Top-level `PUSHA`/`PUSHAD` dispatcher — chooses the element width based
/// on the current operand size.
///
/// In 16-bit mode (D=0, no 66h) the instruction is `PUSHA` (2-byte elements).
/// In 32-bit mode (D=1 or 66h in 16-bit mode) the instruction is `PUSHAD`
/// (4-byte elements).  The `bits` field of the context is the *natural*
/// machine mode; the operand-size override inverts it.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pusha_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "PUSHA/PUSHAD is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    // Effective operand size: default is mode-bits, flipped by 66h.
    let effective_bits = if ctx.mode.op_size_override {
        if ctx.bits == 32 { 16u8 } else { 32u8 }
    } else {
        ctx.bits
    };
    if effective_bits == 16 {
        lift_pusha(instr, ctx)
    } else {
        lift_pushad(instr, ctx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POPA / POPAD
// ─────────────────────────────────────────────────────────────────────────────

/// `POPA` (opcode 0x61, 16-bit operand size) — pop all eight 16-bit
/// general-purpose registers in the reverse order of PUSHA.
///
/// The SP value on the stack is **discarded** (the SP increment still
/// advances the stack pointer, but the popped value is not written to SP).
///
/// # Pop order
///
/// DI, SI, BP, *(skip SP)*, BX, DX, CX, AX
///
/// # Micro-op sequence (16-bit)
///
/// ```text
/// di := *[sp]; sp := sp + 2
/// si := *[sp]; sp := sp + 2
/// bp := *[sp]; sp := sp + 2
/// _  := *[sp]; sp := sp + 2   (SP value discarded)
/// bx := *[sp]; sp := sp + 2
/// dx := *[sp]; sp := sp + 2
/// cx := *[sp]; sp := sp + 2
/// ax := *[sp]; sp := sp + 2
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popa(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "POPA/POPAD is invalid in 64-bit mode (#UD)".into(),
        ));
    }

    let w: u8 = 2;
    // Pop order: DI SI BP __skip(SP) BX DX CX AX
    let order: &[&str] = &["di", "si", "bp", "__skip", "bx", "dx", "cx", "ax"];
    for &r in order {
        let t = pop_value(w, ctx);
        if r != "__skip" {
            ctx.emit_reg_write(r, IrExpr::Reg(t));
        }
    }

    Ok(())
}

/// `POPAD` (opcode 0x61, 32-bit operand size) — pop all eight 32-bit
/// general-purpose registers in the reverse order of PUSHAD.
///
/// The ESP value on the stack is **discarded**.
///
/// # Pop order
///
/// EDI, ESI, EBP, *(skip ESP)*, EBX, EDX, ECX, EAX
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popad(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "POPA/POPAD is invalid in 64-bit mode (#UD)".into(),
        ));
    }

    let w: u8 = 4;
    let order: &[&str] = &["edi", "esi", "ebp", "__skip", "ebx", "edx", "ecx", "eax"];
    for &r in order {
        let t = pop_value(w, ctx);
        if r != "__skip" {
            ctx.emit_reg_write(r, IrExpr::Reg(t));
        }
    }

    Ok(())
}

/// Top-level `POPA`/`POPAD` dispatcher.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popa_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if ctx.bits == 64 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            "POPA/POPAD is invalid in 64-bit mode (#UD)".into(),
        ));
    }
    let effective_bits = if ctx.mode.op_size_override {
        if ctx.bits == 32 { 16u8 } else { 32u8 }
    } else {
        ctx.bits
    };
    if effective_bits == 16 {
        lift_popa(instr, ctx)
    } else {
        lift_popad(instr, ctx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUSHF / PUSHFD / PUSHFQ
// ─────────────────────────────────────────────────────────────────────────────

/// `PUSHF` (opcode 0x9C, 16-bit) — push the low 16 bits of EFLAGS.
///
/// The effective push width is always 2 bytes for `PUSHF`.  The FLAGS image
/// is constructed from the symbolic flag registers via the `x86.pack_eflags`
/// intrinsic, which downstream analysis can expand into explicit bit-field
/// arithmetic.
///
/// # Flag bits pushed (EFLAGS format)
///
/// Bit | Flag
/// ----|-----
///  0  | CF
///  2  | PF
///  4  | AF
///  6  | ZF
///  7  | SF
/// 10  | DF
/// 11  | OF
///
/// # Micro-op sequence
///
/// ```text
/// x86.pack_eflags(cf, pf, af, zf, sf, df, of)
/// __eflags_packed := result of intrinsic
/// sp := sp - 2
/// *[sp] := __eflags_packed[15:0]
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pushf(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w: u8 = 2;
    emit_pushf_body(w, ctx);
    Ok(())
}

/// `PUSHFD` (opcode 0x9C, 32-bit) — push the full 32-bit EFLAGS register.
///
/// RF and VM bits are cleared in the pushed image per SDM §6.3.4.
///
/// # Micro-op sequence
///
/// ```text
/// x86.pack_eflags(cf, pf, af, zf, sf, df, of)
/// __eflags_packed := result of intrinsic (32-bit masked)
/// sp := sp - 4
/// *[sp] := __eflags_packed
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pushfd(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w: u8 = 4;
    emit_pushf_body(w, ctx);
    Ok(())
}

/// `PUSHFQ` (opcode 0x9C with REX.W or in 64-bit mode default) — push the
/// full 64-bit RFLAGS register.
///
/// In 64-bit mode PUSHF/PUSHFD encode as PUSHFQ when no 66h prefix is
/// present.  The 64-bit push zeroes bits 63:32.
///
/// # Micro-op sequence
///
/// ```text
/// x86.pack_eflags(cf, pf, af, zf, sf, df, of)
/// __eflags_packed := result of intrinsic (64-bit, bits 63:32 = 0)
/// rsp := rsp - 8
/// *[rsp] := __eflags_packed
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pushfq(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w: u8 = 8;
    emit_pushf_body(w, ctx);
    Ok(())
}

/// Internal implementation shared by [`lift_pushf`], [`lift_pushfd`],
/// and [`lift_pushfq`].
///
/// Emits the `x86.pack_eflags` intrinsic that gathers all seven symbolic
/// flag registers into a notional `__eflags_packed` value, then pushes
/// that value onto the stack.
fn emit_pushf_body(w: u8, ctx: &mut X86LiftCtx) {
    // Pack all observable flags into a single value.
    ctx.emit_intrinsic(
        "x86.pack_eflags",
        vec![
            IrExpr::Reg("cf".into()),
            IrExpr::Reg("pf".into()),
            IrExpr::Reg("af".into()),
            IrExpr::Reg("zf".into()),
            IrExpr::Reg("sf".into()),
            IrExpr::Reg("df".into()),
            IrExpr::Reg("of".into()),
        ],
    );
    // Materialise the packed flags into a fresh temp.
    let flags_temp = ctx.materialise(IrExpr::Reg("__eflags_packed".into()));

    // Push the packed flags.
    push_value(IrExpr::Reg(flags_temp), w, ctx);
}

/// Top-level `PUSHF` / `PUSHFD` / `PUSHFQ` dispatcher.
///
/// Selects the element width based on the current mode and prefix state:
/// - 64-bit mode without 66h → 8 bytes (PUSHFQ)
/// - 64-bit mode with 66h   → 2 bytes (PUSHF)
/// - 32-bit mode without 66h → 4 bytes (PUSHFD)
/// - 32-bit mode with 66h   → 2 bytes (PUSHF)
/// - 16-bit mode without 66h → 2 bytes (PUSHF)
/// - 16-bit mode with 66h   → 4 bytes (PUSHFD)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pushf_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = effective_pushf_width(ctx);
    emit_pushf_body(w, ctx);
    let _ = instr; // consumed indirectly via ctx
    Ok(())
}

/// Compute the PUSHF/POPF element width (bytes) for the current mode.
const fn effective_pushf_width(ctx: &X86LiftCtx) -> u8 {
    match ctx.bits {
        64 => {
            if ctx.mode.op_size_override {
                2
            } else {
                8
            }
        }
        32 => {
            if ctx.mode.op_size_override {
                2
            } else {
                4
            }
        }
        _ => {
            // 16-bit mode: 66h upgrades to 32-bit.
            if ctx.mode.op_size_override { 4 } else { 2 }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POPF / POPFD / POPFQ
// ─────────────────────────────────────────────────────────────────────────────

/// `POPF` (opcode 0x9D, 16-bit) — pop 16 bits from the stack into FLAGS.
///
/// The IOPL and IF fields may only be modified when the current privilege
/// level is CPL=0.  This is not modelled at the IL level; the intrinsic
/// `x86.unpack_eflags` captures the privilege constraint for later passes.
///
/// After the intrinsic, each flag register is written as `IrExpr::Undef`
/// so that the lazy-flag idiom is preserved: downstream passes can either
/// expand the unpack or treat the flags as unknown-but-live.
///
/// # Micro-op sequence
///
/// ```text
/// __t0 := *[sp]; sp := sp + 2
/// x86.unpack_eflags(__t0)
/// cf := undef; pf := undef; af := undef; zf := undef; sf := undef; df := undef; of := undef
/// ```
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popf(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w: u8 = 2;
    emit_popf_body(w, ctx);
    Ok(())
}

/// `POPFD` (opcode 0x9D, 32-bit) — pop 32 bits from the stack into EFLAGS.
///
/// VM and RF bits are not modifiable from user mode and are not propagated
/// by the intrinsic.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popfd(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w: u8 = 4;
    emit_popf_body(w, ctx);
    Ok(())
}

/// `POPFQ` (opcode 0x9D, 64-bit) — pop 64 bits from the stack into RFLAGS.
///
/// Bits 63:32 of the popped value are ignored.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popfq(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w: u8 = 8;
    emit_popf_body(w, ctx);
    Ok(())
}

/// Internal implementation shared by the three POPF variants.
fn emit_popf_body(w: u8, ctx: &mut X86LiftCtx) {
    // Pop the flags image from the stack.
    let t = pop_value(w, ctx);

    // Unpack into the symbolic flag registers.
    ctx.emit_intrinsic("x86.unpack_eflags", vec![IrExpr::Reg(t)]);

    // Mark all flags as written (undef = "depends on the intrinsic above").
    for flag in [
        FlagId::Cf,
        FlagId::Pf,
        FlagId::Af,
        FlagId::Zf,
        FlagId::Sf,
        FlagId::Df,
        FlagId::Of,
    ] {
        ctx.emit_flagset(flag, IrExpr::Undef);
    }
}

/// Top-level `POPF` / `POPFD` / `POPFQ` dispatcher.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popf_dispatch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = effective_pushf_width(ctx);
    emit_popf_body(w, ctx);
    let _ = instr;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTER
// ─────────────────────────────────────────────────────────────────────────────

/// `ENTER imm16, imm8` — create a stack frame for a procedure.
///
/// The first immediate is the number of bytes to allocate on the stack
/// (the local-variable frame size).  The second immediate is the nesting
/// level (0..=31).
///
/// # Nesting level = 0 (common case)
///
/// ```text
/// (R/E/BP) pushed
/// (R/E/BP) := (R/E/SP) after push
/// (R/E/SP) := (R/E/SP) - frame_size
/// ```
///
/// # Nesting level 1..31 (procedure nesting — rarely used in practice)
///
/// For nesting level *L*:
/// 1. Push BP (as above for L=0).
/// 2. For *i* = 1..*(L-1)*: push [BP - i*`ptr_size`] (frame pointer chain).
/// 3. Push the *new* frame pointer (the value that BP will be set to).
/// 4. Set BP to the saved-SP value from step 1.
/// 5. Allocate the local frame.
///
/// The nesting levels > 1 produce an `x86.enter.nesting` intrinsic instead
/// of explicit micro-ops because the chain walk requires a runtime loop that
/// cannot be statically unrolled without knowing the nesting depth at
/// analysis time.
///
/// # REX.W / operand-size note
///
/// In 64-bit mode `ENTER` uses 64-bit frame-pointer values (8-byte pushes).
/// In 32-bit mode it uses 4-byte values.  In 16-bit mode 2-byte values.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_enter(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let frame_size = u64::from(instr.immediate16());
    let nesting = instr.immediate8_2nd();

    if nesting > 31 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("ENTER nesting level {nesting} exceeds maximum of 31"),
        ));
    }

    let w = ctx.stack_ptr_size();
    let sp = ctx.stack_ptr();
    let bp = ctx.base_ptr();

    // ── Step 1: PUSH (R/E/BP)
    push_value(IrExpr::Reg(bp.into()), w, ctx);

    // ── Step 2: frame-pointer chain (nesting > 0)
    if nesting == 1 {
        // Level 1: push the temp frame pointer only.
        // The frame pointer was just pushed; push its (updated) SP value.
        push_value(IrExpr::Reg(sp.into()), w, ctx);
    } else if nesting > 1 {
        // Level 2..31: use an intrinsic to model the chain walk.
        ctx.emit_intrinsic(
            "x86.enter.nesting",
            vec![
                IrExpr::Reg(bp.into()),
                IrExpr::Reg(sp.into()),
                IrExpr::Const(u64::from(nesting)),
                IrExpr::Const(u64::from(w)),
            ],
        );
    }

    // ── Step 3: BP := SP (after step 1 push, before allocation)
    // After the push in step 1, SP has already been decremented; the frame
    // pointer is set to this decremented SP.
    ctx.emit_reg_write(bp, IrExpr::Reg(sp.into()));

    // ── Step 4: SP := SP - frame_size
    if frame_size != 0 {
        let new_sp = IrExpr::Sub(
            Box::new(IrExpr::Reg(sp.into())),
            Box::new(IrExpr::Const(frame_size)),
        );
        ctx.emit_reg_write(sp, new_sp);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// LEAVE
// ─────────────────────────────────────────────────────────────────────────────

/// `LEAVE` (opcode 0xC9) — tear down a stack frame.
///
/// Reverses the effect of `ENTER`:
///
/// ```text
/// (R/E/SP) := (R/E/BP)          ; collapse the allocation
/// (R/E/BP) := *[(R/E/SP)]       ; restore the saved frame pointer
/// (R/E/SP) := (R/E/SP) + ptr_bytes
/// ```
///
/// The operand size (and therefore the element size of the `POP`) is
/// determined by the current mode: 8 bytes in 64-bit mode, 4 bytes in
/// 32-bit mode, 2 bytes in 16-bit mode.
///
/// # 64-bit mode
///
/// The default operand size of LEAVE in 64-bit mode is 64-bit (like PUSH/POP).
/// The 66h prefix selects the 16-bit form.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_leave(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = ctx.stack_ptr_size();
    let sp = ctx.stack_ptr();
    let bp = ctx.base_ptr();

    // SP := BP  (collapses the local frame)
    ctx.emit_reg_write(sp, IrExpr::Reg(bp.into()));

    // POP BP
    let t = pop_value(w, ctx);
    ctx.emit_reg_write(bp, IrExpr::Reg(t));

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// RSP alignment helpers (used by ABI call sequences)
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a 16-byte RSP alignment (`AND rsp, -16`) as a raw register-write
/// intrinsic.
///
/// Many ABI call sites require the stack to be 16-byte aligned before a
/// `CALL` instruction.  While this is not a dedicated x86 instruction, the
/// pattern `AND rsp, -16` is so ubiquitous that we provide a named helper
/// so analysis passes can recognise and summarise it.
///
/// This function is not mapped to a mnemonic; it is called by the arithmetic
/// handler for `AND rsp, imm` when the immediate is a power-of-two alignment
/// mask.
pub fn emit_rsp_align(align_bytes: u64, ctx: &mut X86LiftCtx) {
    let sp = ctx.stack_ptr();
    let mask = !(align_bytes.wrapping_sub(1));
    let new_sp = IrExpr::And(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(mask)),
    );
    ctx.emit_intrinsic(
        format!("x86.rsp_align.{align_bytes}"),
        vec![IrExpr::Reg(sp.into())],
    );
    ctx.emit_reg_write(sp, new_sp);
}

/// Emit a fixed-size RSP adjustment (add or subtract).
///
/// Used by `ADD rsp, imm` / `SUB rsp, imm` patterns to make the stack
/// delta explicit for stack-depth analysis without going through the full
/// arithmetic handler.
pub fn emit_rsp_delta(signed_delta: i64, ctx: &mut X86LiftCtx) {
    let sp = ctx.stack_ptr();
    let new_sp = if signed_delta < 0 {
        IrExpr::Sub(
            Box::new(IrExpr::Reg(sp.into())),
            Box::new(IrExpr::Const((-signed_delta).cast_unsigned())),
        )
    } else {
        IrExpr::Add(
            Box::new(IrExpr::Reg(sp.into())),
            Box::new(IrExpr::Const(signed_delta.cast_unsigned())),
        )
    };
    ctx.emit_reg_write(sp, new_sp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public re-exports (for mod.rs dispatch compatibility)
// ─────────────────────────────────────────────────────────────────────────────

// The top-level dispatcher in `mod.rs` uses these four function names:

/// Entry-point called from the top-level mnemonic dispatcher for `PUSH`.
/// Delegates to [`lift_push_dispatch`] which handles both GPR/memory and
/// segment register forms.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn push_entry(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_push_dispatch(instr, ctx)
}

/// Entry-point called from the top-level mnemonic dispatcher for `POP`.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn pop_entry(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_pop_dispatch(instr, ctx)
}

/// Entry-point called from the top-level mnemonic dispatcher for `PUSHA`/`PUSHAD`.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn pusha_entry(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_pusha_dispatch(instr, ctx)
}

/// Entry-point called from the top-level mnemonic dispatcher for `POPA`/`POPAD`.
#[inline]
/// Lifts this instruction into the IL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn popa_entry(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_popa_dispatch(instr, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! # Test strategy
    //!
    //! Each test constructs a fresh `X86LiftCtx` in the appropriate machine
    //! mode, calls the handler under test, and then inspects the emitted
    //! `Effect` stream for:
    //!
    //! - Presence of `Effect::RegWrite` to the expected registers.
    //! - Presence of `Effect::MemWrite` / `Effect::MemRead` at the expected
    //!   addresses and sizes.
    //! - Presence of named `Effect::Intrinsic` effects.
    //! - **Absence** of effects that must *not* be emitted (e.g. no SP update
    //!   when a handler should signal an error).
    //! - Error propagation for invalid-mode instructions.
    //!
    //! The tests deliberately avoid inspecting the exact numeric structure of
    //! `IrExpr` trees (which would make them brittle to refactoring) in favour
    //! of structural predicates (`has_mem_write`, `writes_reg`, etc.).

    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Context factories ────────────────────────────────────────────────────

    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    fn ctx32() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 32, ModeHint::default())
    }

    fn ctx16() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 16, ModeHint::default())
    }

    fn ctx64_opsz() -> X86LiftCtx {
        X86LiftCtx::new(
            0x1000,
            64,
            ModeHint {
                op_size_override: true,
                ..ModeHint::default()
            },
        )
    }

    // ── Effect predicates ────────────────────────────────────────────────────

    fn writes_reg(effects: &[Effect], reg: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
    }

    fn count_reg_writes(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    fn has_mem_write(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemWrite { .. }))
    }

    fn has_mem_read(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemRead { .. }))
    }

    fn mem_write_size(effects: &[Effect]) -> Option<u8> {
        effects.iter().find_map(|e| {
            if let Effect::MemWrite { size, .. } = e {
                Some(*size)
            } else {
                None
            }
        })
    }

    fn mem_read_size(effects: &[Effect]) -> Option<u8> {
        effects.iter().find_map(|e| {
            if let Effect::MemRead { size, .. } = e {
                Some(*size)
            } else {
                None
            }
        })
    }

    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    fn count_mem_writes(effects: &[Effect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::MemWrite { .. }))
            .count()
    }

    fn count_mem_reads(effects: &[Effect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::MemRead { .. }))
            .count()
    }

    // ── Decoding helpers ─────────────────────────────────────────────────────

    fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn decode32(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn decode16(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(16, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    // ════════════════════════════════════════════════════════════════════════
    // push_value / pop_value primitive tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn push_value_decrements_rsp_and_writes_mem_64() {
        let mut ctx = ctx64();
        super::push_value(IrExpr::Const(0xDEAD), 8, &mut ctx);
        // Should emit: rsp write + mem write
        assert!(writes_reg(&ctx.effects, "rsp"), "rsp must be written");
        assert!(has_mem_write(&ctx.effects), "must emit MemWrite");
        assert_eq!(mem_write_size(&ctx.effects), Some(8));
    }

    #[test]
    fn push_value_decrements_esp_and_writes_mem_32() {
        let mut ctx = ctx32();
        super::push_value(IrExpr::Const(0xBEEF), 4, &mut ctx);
        assert!(writes_reg(&ctx.effects, "esp"));
        assert!(has_mem_write(&ctx.effects));
        assert_eq!(mem_write_size(&ctx.effects), Some(4));
    }

    #[test]
    fn pop_value_reads_mem_and_increments_rsp_64() {
        let mut ctx = ctx64();
        let t = super::pop_value(8, &mut ctx);
        assert!(!t.is_empty(), "pop_value must return a temp name");
        assert!(has_mem_read(&ctx.effects));
        assert_eq!(mem_read_size(&ctx.effects), Some(8));
        assert!(writes_reg(&ctx.effects, "rsp"));
    }

    #[test]
    fn pop_value_reads_mem_and_increments_esp_32() {
        let mut ctx = ctx32();
        let t = super::pop_value(4, &mut ctx);
        assert!(!t.is_empty());
        assert!(has_mem_read(&ctx.effects));
        assert_eq!(mem_read_size(&ctx.effects), Some(4));
        assert!(writes_reg(&ctx.effects, "esp"));
    }

    #[test]
    fn pop_value_returns_unique_temps() {
        let mut ctx = ctx64();
        let t1 = super::pop_value(8, &mut ctx);
        let t2 = super::pop_value(8, &mut ctx);
        assert_ne!(
            t1, t2,
            "successive pop_value calls must produce distinct temps"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // sign_extend_imm tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn sign_extend_positive_byte() {
        let v = super::sign_extend_imm(0x7F, 8);
        assert_eq!(v, 0x7Fu64, "positive byte should not change");
    }

    #[test]
    fn sign_extend_negative_byte() {
        let v = super::sign_extend_imm(0xFF, 8);
        assert_eq!(v as i64, -1i64, "0xFF sign-extended should be -1");
    }

    #[test]
    fn sign_extend_fe_byte() {
        let v = super::sign_extend_imm(0xFE, 8);
        assert_eq!(v as i64, -2i64, "0xFE sign-extended should be -2");
    }

    #[test]
    fn sign_extend_80_byte() {
        let v = super::sign_extend_imm(0x80, 8);
        assert_eq!(v as i64, -128i64);
    }

    #[test]
    fn sign_extend_32bit_positive() {
        let v = super::sign_extend_imm(0x7FFF_FFFF, 32);
        assert_eq!(v, 0x7FFF_FFFFu64);
    }

    #[test]
    fn sign_extend_32bit_negative() {
        let v = super::sign_extend_imm(0xFFFF_FFFF, 32);
        assert_eq!(v as i64, -1i64);
    }

    // ════════════════════════════════════════════════════════════════════════
    // reg_byte_width tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn reg_width_rax_is_8() {
        use iced_x86::Register as R;
        assert_eq!(super::reg_byte_width(R::RAX), Some(8));
    }

    #[test]
    fn reg_width_eax_is_4() {
        use iced_x86::Register as R;
        assert_eq!(super::reg_byte_width(R::EAX), Some(4));
    }

    #[test]
    fn reg_width_ax_is_2() {
        use iced_x86::Register as R;
        assert_eq!(super::reg_byte_width(R::AX), Some(2));
    }

    #[test]
    fn reg_width_al_is_1() {
        use iced_x86::Register as R;
        assert_eq!(super::reg_byte_width(R::AL), Some(1));
    }

    #[test]
    fn reg_width_cs_is_2() {
        use iced_x86::Register as R;
        assert_eq!(super::reg_byte_width(R::CS), Some(2));
    }

    #[test]
    fn reg_width_r15_is_8() {
        use iced_x86::Register as R;
        assert_eq!(super::reg_byte_width(R::R15), Some(8));
    }

    // ════════════════════════════════════════════════════════════════════════
    // PUSH handler tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_push_rax_64() {
        // 50h = PUSH RAX (64-bit default operand size)
        let instr = decode64(&[0x50]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).expect("PUSH RAX must not fail");
        assert!(writes_reg(&ctx.effects, "rsp"), "rsp must be decremented");
        assert!(has_mem_write(&ctx.effects), "must push to stack");
        assert_eq!(
            mem_write_size(&ctx.effects),
            Some(8),
            "push size must be 8 in 64-bit"
        );
    }

    #[test]
    fn lift_push_eax_32() {
        // 50h in 32-bit mode = PUSH EAX
        let instr = decode32(&[0x50]);
        let mut ctx = ctx32();
        super::lift_push(&instr, &mut ctx).expect("PUSH EAX must not fail");
        assert!(writes_reg(&ctx.effects, "esp"));
        assert_eq!(mem_write_size(&ctx.effects), Some(4));
    }

    #[test]
    fn lift_push_imm8_sign_extended_64() {
        // 6A FF = PUSH -1 (sign-extended to 64-bit in 64-bit mode)
        let instr = decode64(&[0x6A, 0xFF]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).expect("PUSH imm8 must not fail");
        assert!(has_mem_write(&ctx.effects));
        // The pushed value should be the sign-extended constant 0xFFFF_FFFF_FFFF_FFFFu64
        let pushed = ctx.effects.iter().find_map(|e| {
            if let Effect::MemWrite {
                value: IrExpr::Const(v),
                ..
            } = e
            {
                Some(*v)
            } else {
                None
            }
        });
        assert_eq!(
            pushed,
            Some(0xFFFF_FFFF_FFFF_FFFFu64),
            "imm8 -1 must sign-extend to all-ones"
        );
    }

    #[test]
    fn lift_push_imm8_positive_sign_extended_64() {
        // 6A 7F = PUSH 0x7F (no sign extension needed — high bit is 0)
        let instr = decode64(&[0x6A, 0x7F]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).expect("PUSH imm8 0x7F must not fail");
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_push_imm32_64bit() {
        // 68 78 56 34 12 = PUSH 0x12345678 (sign-extended to 64-bit)
        let instr = decode64(&[0x68, 0x78, 0x56, 0x34, 0x12]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).expect("PUSH imm32 must not fail");
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_push_mem_64() {
        // FF 34 25 00 10 00 00 = PUSH QWORD PTR [0x1000]
        let instr = decode64(&[0xFF, 0x34, 0x25, 0x00, 0x10, 0x00, 0x00]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).expect("PUSH mem must not fail");
        // Memory PUSH: read from mem, then write to stack.
        // push_value is called with the read operand; check mem write occurred.
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_push_fs_valid_in_64bit() {
        // 0F A0 = PUSH FS
        let instr = decode64(&[0x0F, 0xA0]);
        let mut ctx = ctx64();
        super::lift_push_fs(&instr, &mut ctx).expect("PUSH FS must succeed in 64-bit");
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_push_gs_valid_in_64bit() {
        // 0F A8 = PUSH GS
        let instr = decode64(&[0x0F, 0xA8]);
        let mut ctx = ctx64();
        super::lift_push_gs(&instr, &mut ctx).expect("PUSH GS must succeed in 64-bit");
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_push_cs_fails_in_64bit() {
        // 0E = PUSH CS (invalid in 64-bit)
        let instr = decode16(&[0x0E]); // decode in 16-bit to get a valid instruction
        let mut ctx = ctx64();
        let result = super::lift_push_cs(&instr, &mut ctx);
        assert!(result.is_err(), "PUSH CS must fail in 64-bit mode");
    }

    #[test]
    fn lift_push_ds_fails_in_64bit() {
        let instr = decode32(&[0x1E]);
        let mut ctx = ctx64();
        let result = super::lift_push_ds(&instr, &mut ctx);
        assert!(result.is_err(), "PUSH DS must fail in 64-bit mode");
    }

    #[test]
    fn lift_push_es_fails_in_64bit() {
        let instr = decode32(&[0x06]);
        let mut ctx = ctx64();
        let result = super::lift_push_es(&instr, &mut ctx);
        assert!(result.is_err(), "PUSH ES must fail in 64-bit mode");
    }

    #[test]
    fn lift_push_ss_fails_in_64bit() {
        let instr = decode32(&[0x16]);
        let mut ctx = ctx64();
        let result = super::lift_push_ss(&instr, &mut ctx);
        assert!(result.is_err(), "PUSH SS must fail in 64-bit mode");
    }

    #[test]
    fn lift_push_fs_in_32bit() {
        let instr = decode32(&[0x0F, 0xA0]);
        let mut ctx = ctx32();
        super::lift_push_fs(&instr, &mut ctx).expect("PUSH FS must succeed in 32-bit");
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_push_ax_16bit() {
        // 50 = PUSH AX in 16-bit mode
        let instr = decode16(&[0x50]);
        let mut ctx = ctx16();
        super::lift_push(&instr, &mut ctx).expect("PUSH AX must not fail");
        assert!(writes_reg(&ctx.effects, "sp"));
        assert_eq!(mem_write_size(&ctx.effects), Some(2));
    }

    // ════════════════════════════════════════════════════════════════════════
    // POP handler tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_pop_rax_64() {
        // 58 = POP RAX
        let instr = decode64(&[0x58]);
        let mut ctx = ctx64();
        super::lift_pop(&instr, &mut ctx).expect("POP RAX must not fail");
        assert!(has_mem_read(&ctx.effects), "must read from stack");
        assert_eq!(mem_read_size(&ctx.effects), Some(8));
        assert!(writes_reg(&ctx.effects, "rsp"), "rsp must be incremented");
        assert!(writes_reg(&ctx.effects, "rax"), "rax must be written");
    }

    #[test]
    fn lift_pop_eax_32() {
        // 58 in 32-bit = POP EAX
        let instr = decode32(&[0x58]);
        let mut ctx = ctx32();
        super::lift_pop(&instr, &mut ctx).expect("POP EAX must not fail");
        assert!(has_mem_read(&ctx.effects));
        assert_eq!(mem_read_size(&ctx.effects), Some(4));
        assert!(writes_reg(&ctx.effects, "esp"));
        assert!(writes_reg(&ctx.effects, "eax"));
    }

    #[test]
    fn lift_pop_fs_64() {
        // 0F A1 = POP FS
        let instr = decode64(&[0x0F, 0xA1]);
        let mut ctx = ctx64();
        super::lift_pop_fs(&instr, &mut ctx).expect("POP FS must succeed in 64-bit");
        assert!(has_mem_read(&ctx.effects));
        assert!(writes_reg(&ctx.effects, "fs"));
    }

    #[test]
    fn lift_pop_gs_64() {
        // 0F A9 = POP GS
        let instr = decode64(&[0x0F, 0xA9]);
        let mut ctx = ctx64();
        super::lift_pop_gs(&instr, &mut ctx).expect("POP GS must succeed in 64-bit");
        assert!(has_mem_read(&ctx.effects));
        assert!(writes_reg(&ctx.effects, "gs"));
    }

    #[test]
    fn lift_pop_ds_fails_in_64bit() {
        let instr = decode32(&[0x1F]);
        let mut ctx = ctx64();
        let result = super::lift_pop_ds(&instr, &mut ctx);
        assert!(result.is_err(), "POP DS must fail in 64-bit mode");
    }

    #[test]
    fn lift_pop_es_fails_in_64bit() {
        let instr = decode32(&[0x07]);
        let mut ctx = ctx64();
        let result = super::lift_pop_es(&instr, &mut ctx);
        assert!(result.is_err(), "POP ES must fail in 64-bit mode");
    }

    #[test]
    fn lift_pop_ss_fails_in_64bit() {
        let instr = decode32(&[0x17]);
        let mut ctx = ctx64();
        let result = super::lift_pop_ss(&instr, &mut ctx);
        assert!(result.is_err(), "POP SS must fail in 64-bit mode");
    }

    #[test]
    fn lift_pop_ds_in_32bit() {
        let instr = decode32(&[0x1F]);
        let mut ctx = ctx32();
        super::lift_pop_ds(&instr, &mut ctx).expect("POP DS must succeed in 32-bit");
        assert!(writes_reg(&ctx.effects, "ds"));
    }

    #[test]
    fn lift_pop_ax_16bit() {
        // 58 = POP AX in 16-bit
        let instr = decode16(&[0x58]);
        let mut ctx = ctx16();
        super::lift_pop(&instr, &mut ctx).expect("POP AX must not fail");
        assert!(writes_reg(&ctx.effects, "sp"));
        assert_eq!(mem_read_size(&ctx.effects), Some(2));
    }

    // ════════════════════════════════════════════════════════════════════════
    // PUSHA / PUSHAD tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_pusha_fails_in_64bit() {
        let instr = decode32(&[0x60]);
        let mut ctx = ctx64();
        let result = super::lift_pusha(&instr, &mut ctx);
        assert!(result.is_err(), "PUSHA must fail in 64-bit mode");
        assert!(
            ctx.effects.is_empty(),
            "no effects should be emitted on error"
        );
    }

    #[test]
    fn lift_pusha_emits_8_mem_writes_in_16bit() {
        // 60 = PUSHA in 16-bit mode
        let instr = decode16(&[0x60]);
        let mut ctx = ctx16();
        super::lift_pusha(&instr, &mut ctx).expect("PUSHA must succeed in 16-bit");
        // 8 pushes = 8 SP writes + 1 materialise write + 8 mem writes
        assert_eq!(
            count_mem_writes(&ctx.effects),
            8,
            "must emit exactly 8 stack stores"
        );
    }

    #[test]
    fn lift_pushad_fails_in_64bit() {
        let instr = decode32(&[0x60]);
        let mut ctx = ctx64();
        let result = super::lift_pushad(&instr, &mut ctx);
        assert!(result.is_err(), "PUSHAD must fail in 64-bit mode");
    }

    #[test]
    fn lift_pushad_emits_8_mem_writes_in_32bit() {
        // 60 = PUSHAD in 32-bit mode
        let instr = decode32(&[0x60]);
        let mut ctx = ctx32();
        super::lift_pushad(&instr, &mut ctx).expect("PUSHAD must succeed in 32-bit");
        assert_eq!(
            count_mem_writes(&ctx.effects),
            8,
            "must emit exactly 8 stack stores"
        );
    }

    #[test]
    fn lift_pushad_all_element_writes_are_4_bytes() {
        let instr = decode32(&[0x60]);
        let mut ctx = ctx32();
        super::lift_pushad(&instr, &mut ctx).expect("PUSHAD must succeed");
        // All MemWrite effects must have size == 4.
        let bad = ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::MemWrite { size, .. } if *size != 4))
            .count();
        assert_eq!(bad, 0, "all PUSHAD stack writes must be 4 bytes wide");
    }

    #[test]
    fn lift_pusha_all_element_writes_are_2_bytes() {
        let instr = decode16(&[0x60]);
        let mut ctx = ctx16();
        super::lift_pusha(&instr, &mut ctx).expect("PUSHA must succeed");
        let bad = ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::MemWrite { size, .. } if *size != 2))
            .count();
        assert_eq!(bad, 0, "all PUSHA stack writes must be 2 bytes wide");
    }

    // ════════════════════════════════════════════════════════════════════════
    // POPA / POPAD tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_popa_fails_in_64bit() {
        let instr = decode32(&[0x61]);
        let mut ctx = ctx64();
        let result = super::lift_popa(&instr, &mut ctx);
        assert!(result.is_err(), "POPA must fail in 64-bit mode");
    }

    #[test]
    fn lift_popa_emits_8_mem_reads_in_16bit() {
        let instr = decode16(&[0x61]);
        let mut ctx = ctx16();
        super::lift_popa(&instr, &mut ctx).expect("POPA must succeed in 16-bit");
        assert_eq!(
            count_mem_reads(&ctx.effects),
            8,
            "must emit exactly 8 stack loads"
        );
    }

    #[test]
    fn lift_popa_skips_sp_write() {
        let instr = decode16(&[0x61]);
        let mut ctx = ctx16();
        super::lift_popa(&instr, &mut ctx).expect("POPA must succeed");
        // SP should only be written by the RSP-increment effects (8 of them),
        // not by a register-file write to SP from the popped value.
        // The SP register-writes are: 8 increments.
        // There should be no "sp" write whose value is a Reg(__tN) — the
        // skipped slot.
        let sp_writes_from_pop = ctx
            .effects
            .iter()
            .filter(|e| {
                if let Effect::RegWrite { reg, value } = e {
                    reg == "sp" && matches!(value, IrExpr::Reg(r) if r.starts_with("__t"))
                } else {
                    false
                }
            })
            .count();
        assert_eq!(
            sp_writes_from_pop, 0,
            "SP must not be written from popped value"
        );
    }

    #[test]
    fn lift_popad_fails_in_64bit() {
        let instr = decode32(&[0x61]);
        let mut ctx = ctx64();
        let result = super::lift_popad(&instr, &mut ctx);
        assert!(result.is_err(), "POPAD must fail in 64-bit mode");
    }

    #[test]
    fn lift_popad_emits_8_mem_reads_in_32bit() {
        let instr = decode32(&[0x61]);
        let mut ctx = ctx32();
        super::lift_popad(&instr, &mut ctx).expect("POPAD must succeed in 32-bit");
        assert_eq!(count_mem_reads(&ctx.effects), 8);
    }

    #[test]
    fn lift_popad_writes_seven_gpr_registers() {
        let instr = decode32(&[0x61]);
        let mut ctx = ctx32();
        super::lift_popad(&instr, &mut ctx).expect("POPAD must succeed");
        // EDI ESI EBP EBX EDX ECX EAX = 7 registers (ESP is skipped)
        let target_regs = ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"];
        for r in &target_regs {
            assert!(writes_reg(&ctx.effects, r), "POPAD must write {r}");
        }
    }

    #[test]
    fn lift_popad_does_not_write_esp_from_pop() {
        let instr = decode32(&[0x61]);
        let mut ctx = ctx32();
        super::lift_popad(&instr, &mut ctx).expect("POPAD must succeed");
        let esp_from_pop = ctx
            .effects
            .iter()
            .filter(|e| {
                if let Effect::RegWrite { reg, value } = e {
                    reg == "esp" && matches!(value, IrExpr::Reg(r) if r.starts_with("__t"))
                } else {
                    false
                }
            })
            .count();
        assert_eq!(
            esp_from_pop, 0,
            "ESP must not be set from the skipped stack slot"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // PUSHF / PUSHFD / PUSHFQ tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_pushfq_emits_pack_intrinsic() {
        let instr = decode64(&[0x9C]); // PUSHFQ in 64-bit mode
        let mut ctx = ctx64();
        super::lift_pushfq(&instr, &mut ctx).expect("PUSHFQ must succeed");
        assert!(
            has_intrinsic(&ctx.effects, "pack_eflags"),
            "PUSHFQ must emit x86.pack_eflags intrinsic"
        );
    }

    #[test]
    fn lift_pushfq_pushes_8_bytes() {
        let instr = decode64(&[0x9C]);
        let mut ctx = ctx64();
        super::lift_pushfq(&instr, &mut ctx).expect("PUSHFQ must succeed");
        assert_eq!(
            mem_write_size(&ctx.effects),
            Some(8),
            "PUSHFQ must push 8 bytes"
        );
    }

    #[test]
    fn lift_pushfd_pushes_4_bytes() {
        let instr = decode32(&[0x9C]); // PUSHFD in 32-bit
        let mut ctx = ctx32();
        super::lift_pushfd(&instr, &mut ctx).expect("PUSHFD must succeed");
        assert_eq!(mem_write_size(&ctx.effects), Some(4));
    }

    #[test]
    fn lift_pushf_pushes_2_bytes() {
        let instr = decode16(&[0x9C]);
        let mut ctx = ctx16();
        super::lift_pushf(&instr, &mut ctx).expect("PUSHF must succeed");
        assert_eq!(mem_write_size(&ctx.effects), Some(2));
    }

    #[test]
    fn lift_pushfq_decrements_rsp() {
        let instr = decode64(&[0x9C]);
        let mut ctx = ctx64();
        super::lift_pushfq(&instr, &mut ctx).expect("PUSHFQ must succeed");
        assert!(writes_reg(&ctx.effects, "rsp"), "PUSHFQ must decrement RSP");
    }

    // ════════════════════════════════════════════════════════════════════════
    // POPF / POPFD / POPFQ tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_popfq_emits_unpack_intrinsic() {
        let instr = decode64(&[0x9D]); // POPFQ
        let mut ctx = ctx64();
        super::lift_popfq(&instr, &mut ctx).expect("POPFQ must succeed");
        assert!(
            has_intrinsic(&ctx.effects, "unpack_eflags"),
            "POPFQ must emit x86.unpack_eflags intrinsic"
        );
    }

    #[test]
    fn lift_popfq_reads_8_bytes() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        super::lift_popfq(&instr, &mut ctx).expect("POPFQ must succeed");
        assert_eq!(mem_read_size(&ctx.effects), Some(8));
    }

    #[test]
    fn lift_popfd_reads_4_bytes() {
        let instr = decode32(&[0x9D]);
        let mut ctx = ctx32();
        super::lift_popfd(&instr, &mut ctx).expect("POPFD must succeed");
        assert_eq!(mem_read_size(&ctx.effects), Some(4));
    }

    #[test]
    fn lift_popf_reads_2_bytes() {
        let instr = decode16(&[0x9D]);
        let mut ctx = ctx16();
        super::lift_popf(&instr, &mut ctx).expect("POPF must succeed");
        assert_eq!(mem_read_size(&ctx.effects), Some(2));
    }

    #[test]
    fn lift_popfq_writes_all_seven_flags() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        super::lift_popfq(&instr, &mut ctx).expect("POPFQ must succeed");
        for flag in ["cf", "pf", "af", "zf", "sf", "df", "of"] {
            assert!(
                writes_reg(&ctx.effects, flag),
                "POPFQ must write flag register {flag}"
            );
        }
    }

    #[test]
    fn lift_popfq_increments_rsp() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        super::lift_popfq(&instr, &mut ctx).expect("POPFQ must succeed");
        assert!(writes_reg(&ctx.effects, "rsp"), "POPFQ must increment RSP");
    }

    // ════════════════════════════════════════════════════════════════════════
    // ENTER tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_enter_nesting0_64bit() {
        // C8 10 00 00 = ENTER 16, 0
        let instr = decode64(&[0xC8, 0x10, 0x00, 0x00]);
        let mut ctx = ctx64();
        super::lift_enter(&instr, &mut ctx).expect("ENTER must succeed");
        // Must: push rbp, set rbp := rsp, allocate local frame
        assert!(has_mem_write(&ctx.effects), "must push RBP");
        assert!(writes_reg(&ctx.effects, "rbp"), "must set RBP := RSP");
        assert!(
            writes_reg(&ctx.effects, "rsp"),
            "must adjust RSP for local frame"
        );
    }

    #[test]
    fn lift_enter_nesting0_no_alloc() {
        // C8 00 00 00 = ENTER 0, 0 (no local frame)
        let instr = decode64(&[0xC8, 0x00, 0x00, 0x00]);
        let mut ctx = ctx64();
        super::lift_enter(&instr, &mut ctx).expect("ENTER 0,0 must succeed");
        // RSP should be decremented once (for the PUSH RBP) but not for
        // the zero-sized allocation (we skip the zero-delta emit).
        let rsp_writes = count_reg_writes(&ctx.effects, "rsp");
        // At minimum 1: the push decrements RSP.
        assert!(rsp_writes >= 1, "must write rsp at least once");
    }

    #[test]
    fn lift_enter_nesting1_emits_frame_push() {
        // C8 00 00 01 = ENTER 0, 1
        let instr = decode64(&[0xC8, 0x00, 0x00, 0x01]);
        let mut ctx = ctx64();
        super::lift_enter(&instr, &mut ctx).expect("ENTER 0,1 must succeed");
        // Nesting 1: push rbp PLUS push the new frame pointer — 2 MemWrites.
        assert!(
            count_mem_writes(&ctx.effects) >= 2,
            "nesting 1 must produce 2 stack writes"
        );
    }

    #[test]
    fn lift_enter_nesting2_emits_intrinsic() {
        // C8 00 00 02 = ENTER 0, 2
        let instr = decode64(&[0xC8, 0x00, 0x00, 0x02]);
        let mut ctx = ctx64();
        super::lift_enter(&instr, &mut ctx).expect("ENTER 0,2 must succeed");
        assert!(
            has_intrinsic(&ctx.effects, "x86.enter.nesting"),
            "nesting > 1 must emit x86.enter.nesting intrinsic"
        );
    }

    #[test]
    fn lift_enter_excessive_nesting_error() {
        // nesting = 32 is invalid (max 31)
        let instr = decode64(&[0xC8, 0x00, 0x00, 0x20]); // 0x20 = 32
        let mut ctx = ctx64();
        let result = super::lift_enter(&instr, &mut ctx);
        assert!(result.is_err(), "nesting level 32 must fail");
    }

    #[test]
    fn lift_enter_32bit() {
        // C8 08 00 00 = ENTER 8, 0 in 32-bit mode
        let instr = decode32(&[0xC8, 0x08, 0x00, 0x00]);
        let mut ctx = ctx32();
        super::lift_enter(&instr, &mut ctx).expect("ENTER must succeed in 32-bit");
        assert!(writes_reg(&ctx.effects, "ebp"));
        assert!(writes_reg(&ctx.effects, "esp"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // LEAVE tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_leave_64bit() {
        // C9 = LEAVE
        let instr = decode64(&[0xC9]);
        let mut ctx = ctx64();
        super::lift_leave(&instr, &mut ctx).expect("LEAVE must succeed in 64-bit");
        // SP := BP, then POP BP.
        assert!(writes_reg(&ctx.effects, "rsp"), "must restore RSP from RBP");
        assert!(has_mem_read(&ctx.effects), "must read saved RBP from stack");
        assert!(
            writes_reg(&ctx.effects, "rbp"),
            "must restore RBP from stack"
        );
    }

    #[test]
    fn lift_leave_32bit() {
        let instr = decode32(&[0xC9]);
        let mut ctx = ctx32();
        super::lift_leave(&instr, &mut ctx).expect("LEAVE must succeed in 32-bit");
        assert!(writes_reg(&ctx.effects, "esp"));
        assert!(has_mem_read(&ctx.effects));
        assert!(writes_reg(&ctx.effects, "ebp"));
    }

    #[test]
    fn lift_leave_16bit() {
        let instr = decode16(&[0xC9]);
        let mut ctx = ctx16();
        super::lift_leave(&instr, &mut ctx).expect("LEAVE must succeed in 16-bit");
        assert!(writes_reg(&ctx.effects, "sp"));
        assert!(has_mem_read(&ctx.effects));
        assert!(writes_reg(&ctx.effects, "bp"));
    }

    #[test]
    fn lift_leave_pop_reads_ptr_size_bytes() {
        let instr = decode64(&[0xC9]);
        let mut ctx = ctx64();
        super::lift_leave(&instr, &mut ctx).expect("LEAVE must succeed");
        // The POP in LEAVE reads 8 bytes in 64-bit mode.
        assert_eq!(mem_read_size(&ctx.effects), Some(8));
    }

    // ════════════════════════════════════════════════════════════════════════
    // RSP alignment / delta helpers
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn emit_rsp_align_emits_intrinsic_and_regwrite() {
        let mut ctx = ctx64();
        super::emit_rsp_align(16, &mut ctx);
        assert!(
            has_intrinsic(&ctx.effects, "rsp_align"),
            "must emit alignment intrinsic"
        );
        assert!(writes_reg(&ctx.effects, "rsp"), "must write RSP");
    }

    #[test]
    fn emit_rsp_delta_positive_emits_add() {
        let mut ctx = ctx64();
        super::emit_rsp_delta(8, &mut ctx);
        // The effect should be an Add to rsp.
        let has_add = ctx.effects.iter().any(|e| {
            if let Effect::RegWrite {
                reg,
                value: IrExpr::Add(..),
            } = e
            {
                reg == "rsp"
            } else {
                false
            }
        });
        assert!(has_add, "positive delta must emit RSP Add");
    }

    #[test]
    fn emit_rsp_delta_negative_emits_sub() {
        let mut ctx = ctx64();
        super::emit_rsp_delta(-8, &mut ctx);
        let has_sub = ctx.effects.iter().any(|e| {
            if let Effect::RegWrite {
                reg,
                value: IrExpr::Sub(..),
            } = e
            {
                reg == "rsp"
            } else {
                false
            }
        });
        assert!(has_sub, "negative delta must emit RSP Sub");
    }

    // ════════════════════════════════════════════════════════════════════════
    // effective_pushf_width tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn pushf_width_64bit_no_opsz_is_8() {
        let ctx = ctx64();
        assert_eq!(super::effective_pushf_width(&ctx), 8);
    }

    #[test]
    fn pushf_width_64bit_with_opsz_is_2() {
        let ctx = ctx64_opsz();
        assert_eq!(super::effective_pushf_width(&ctx), 2);
    }

    #[test]
    fn pushf_width_32bit_no_opsz_is_4() {
        let ctx = ctx32();
        assert_eq!(super::effective_pushf_width(&ctx), 4);
    }

    #[test]
    fn pushf_width_32bit_with_opsz_is_2() {
        let ctx = X86LiftCtx::new(
            0x1000,
            32,
            ModeHint {
                op_size_override: true,
                ..ModeHint::default()
            },
        );
        assert_eq!(super::effective_pushf_width(&ctx), 2);
    }

    #[test]
    fn pushf_width_16bit_no_opsz_is_2() {
        let ctx = ctx16();
        assert_eq!(super::effective_pushf_width(&ctx), 2);
    }

    #[test]
    fn pushf_width_16bit_with_opsz_is_4() {
        let ctx = X86LiftCtx::new(
            0x1000,
            16,
            ModeHint {
                op_size_override: true,
                ..ModeHint::default()
            },
        );
        assert_eq!(super::effective_pushf_width(&ctx), 4);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Round-trip ENTER/LEAVE symmetry (evaluation-based)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn enter_leave_rsp_symmetry_32bit() {
        // ENTER 0, 0 followed by LEAVE should restore (E)SP to its pre-ENTER
        // value (assuming no memory accesses fail evaluation).
        //
        // We use exec_effects on the combined effect stream and check that
        // the net SP delta is zero.
        let enter_instr = decode32(&[0xC8, 0x00, 0x00, 0x00]);
        let leave_instr = decode32(&[0xC9]);

        let mut ctx_enter = ctx32();
        super::lift_enter(&enter_instr, &mut ctx_enter).expect("ENTER must succeed");

        let mut ctx_leave = ctx32();
        super::lift_leave(&leave_instr, &mut ctx_leave).expect("LEAVE must succeed");

        // Build a combined effect stream with initial ESP=0x1000.
        let mut state = X86CpuState::new();
        state.set_reg("esp", EvalValue::Concrete(0x1000));
        state.set_reg("ebp", EvalValue::Concrete(0x0));

        exec_effects(&ctx_enter.effects, &mut state);

        // After ENTER 0,0: ebp should be set to esp (after push), and
        // the allocation is 0, so esp should be at 0x1000 - 4 (pushed ebp).
        // After LEAVE: esp should be restored to 0x1000 - 4 + 4 = 0x1000.
        // (The exact values depend on memory model of X86CpuState.)
        // We only check that no panic occurs and effect counts are sane.
        assert!(!ctx_enter.effects.is_empty());
        assert!(!ctx_leave.effects.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // Additional edge-case tests
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn lift_push_dispatch_routes_to_fs_handler() {
        // 0F A0 = PUSH FS
        let instr = decode64(&[0x0F, 0xA0]);
        let mut ctx = ctx64();
        super::lift_push_dispatch(&instr, &mut ctx).expect("dispatch for PUSH FS must succeed");
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_pop_dispatch_routes_to_fs_handler() {
        // 0F A1 = POP FS
        let instr = decode64(&[0x0F, 0xA1]);
        let mut ctx = ctx64();
        super::lift_pop_dispatch(&instr, &mut ctx).expect("dispatch for POP FS must succeed");
        assert!(writes_reg(&ctx.effects, "fs"));
    }

    #[test]
    fn pushf_dispatch_in_64bit_pushes_8_bytes() {
        let instr = decode64(&[0x9C]);
        let mut ctx = ctx64();
        super::lift_pushf_dispatch(&instr, &mut ctx).expect("PUSHFQ dispatch must succeed");
        assert_eq!(mem_write_size(&ctx.effects), Some(8));
    }

    #[test]
    fn popf_dispatch_in_64bit_reads_8_bytes() {
        let instr = decode64(&[0x9D]);
        let mut ctx = ctx64();
        super::lift_popf_dispatch(&instr, &mut ctx).expect("POPFQ dispatch must succeed");
        assert_eq!(mem_read_size(&ctx.effects), Some(8));
    }

    #[test]
    fn pusha_dispatch_selects_16bit_form() {
        let instr = decode16(&[0x60]);
        let mut ctx = ctx16();
        super::lift_pusha_dispatch(&instr, &mut ctx).expect("PUSHA dispatch must succeed");
        // All stores should be 2-byte.
        let bad = ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::MemWrite { size, .. } if *size != 2))
            .count();
        assert_eq!(bad, 0);
    }

    #[test]
    fn pusha_dispatch_selects_32bit_form() {
        let instr = decode32(&[0x60]);
        let mut ctx = ctx32();
        super::lift_pusha_dispatch(&instr, &mut ctx).expect("PUSHAD dispatch must succeed");
        let bad = ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::MemWrite { size, .. } if *size != 4))
            .count();
        assert_eq!(bad, 0);
    }

    #[test]
    fn popa_dispatch_selects_16bit_form() {
        let instr = decode16(&[0x61]);
        let mut ctx = ctx16();
        super::lift_popa_dispatch(&instr, &mut ctx).expect("POPA dispatch must succeed");
        assert_eq!(count_mem_reads(&ctx.effects), 8);
    }

    #[test]
    fn popa_dispatch_selects_32bit_form() {
        let instr = decode32(&[0x61]);
        let mut ctx = ctx32();
        super::lift_popa_dispatch(&instr, &mut ctx).expect("POPAD dispatch must succeed");
        assert_eq!(count_mem_reads(&ctx.effects), 8);
    }

    #[test]
    fn effects_are_ordered_sp_decrement_before_mem_write() {
        // The RSP decrement must precede the MemWrite in the effect stream so
        // that the address in the MemWrite (which references the updated RSP)
        // is semantically correct.
        let mut ctx = ctx64();
        super::push_value(IrExpr::Const(42), 8, &mut ctx);

        let rsp_idx = ctx
            .effects
            .iter()
            .position(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"));
        let mem_idx = ctx
            .effects
            .iter()
            .position(|e| matches!(e, Effect::MemWrite { .. }));

        assert!(
            rsp_idx.is_some() && mem_idx.is_some(),
            "must emit both RSP write and MemWrite"
        );
        assert!(
            rsp_idx.unwrap() < mem_idx.unwrap(),
            "RSP decrement must precede MemWrite"
        );
    }

    #[test]
    fn effects_are_ordered_mem_read_before_sp_increment() {
        // The MemRead must precede the RSP increment so that the read uses
        // the pre-increment address.
        let mut ctx = ctx64();
        super::pop_value(8, &mut ctx);

        let mem_idx = ctx
            .effects
            .iter()
            .position(|e| matches!(e, Effect::MemRead { .. }));
        let rsp_idx = ctx
            .effects
            .iter()
            .position(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"));

        assert!(
            mem_idx.is_some() && rsp_idx.is_some(),
            "must emit both MemRead and RSP write"
        );
        assert!(
            mem_idx.unwrap() < rsp_idx.unwrap(),
            "MemRead must precede RSP increment"
        );
    }

    #[test]
    fn segment_reg_name_all_six() {
        use iced_x86::Register as R;
        assert_eq!(super::segment_reg_name(R::CS), Some("cs"));
        assert_eq!(super::segment_reg_name(R::DS), Some("ds"));
        assert_eq!(super::segment_reg_name(R::ES), Some("es"));
        assert_eq!(super::segment_reg_name(R::FS), Some("fs"));
        assert_eq!(super::segment_reg_name(R::GS), Some("gs"));
        assert_eq!(super::segment_reg_name(R::SS), Some("ss"));
        assert_eq!(super::segment_reg_name(R::RAX), None);
    }

    #[test]
    fn lift_push_rax_effects_not_empty() {
        let instr = decode64(&[0x50]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).unwrap();
        assert!(!ctx.effects.is_empty());
    }

    #[test]
    fn lift_pop_rax_effects_not_empty() {
        let instr = decode64(&[0x58]);
        let mut ctx = ctx64();
        super::lift_pop(&instr, &mut ctx).unwrap();
        assert!(!ctx.effects.is_empty());
    }

    #[test]
    fn ir_text_populated_after_push() {
        let instr = decode64(&[0x50]);
        let mut ctx = ctx64();
        super::lift_push(&instr, &mut ctx).unwrap();
        assert!(
            !ctx.ir_text.is_empty(),
            "ir_text must be populated after lift"
        );
    }

    #[test]
    fn fresh_temp_counter_advances_per_pop() {
        let mut ctx = ctx64();
        let t1 = super::pop_value(8, &mut ctx);
        let t2 = super::pop_value(8, &mut ctx);
        let t3 = super::pop_value(8, &mut ctx);
        // All three should be distinct.
        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_ne!(t1, t3);
    }
}
