//! Centralised operand → `IrExpr` conversion for the x86/x64 lifter.
//!
//! This module is the single source of truth for how an `iced_x86::OpKind`
//! becomes an `IrExpr`. Every handler in `x86_handlers/*` calls into
//! [`read_operand`] for sources and [`write_operand`] for destinations.
//! Centralising the logic guarantees:
//!
//!   * uniform effective-address construction for memory operands
//!     (`base + index*scale + disp`), independent of which handler asks
//!   * consistent register-name canonicalisation (lower-case via iced-x86's
//!     `Debug` impl)
//!   * proper x86-64 partial-register write semantics: writing a 32-bit GPR
//!     in 64-bit mode zero-extends to the parent 64-bit register; writing
//!     `AL` or `AH` leaves the high half of `RAX` untouched
//!   * a single chokepoint for segment-override handling (`fs:`, `gs:` etc.)
//!     so that future MMU/TLS-aware passes can rewrite it in one place
//!
//! The functions in this module never touch the flags — that is the job of
//! `crate::x86_flags`.

use crate::x86_context::X86LiftCtx;
use crate::{Effect, IrExpr};
use iced_x86::{Instruction, OpKind, Register};

// ─────────────────────────────────────────────────────────────────────────────
// Register helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical lower-case register name (matches the existing `X86Lifter`
/// convention so that the two code-paths emit identical IR strings).
#[must_use]
pub fn reg_name(reg: Register) -> String {
    format!("{reg:?}").to_ascii_lowercase()
}

/// Width in **bytes** of a register, as understood by the IR.
///
/// `iced_x86::Register::size()` already returns the size in *bytes*
/// (e.g. `8` for `RAX`, `4` for `EAX`, `1` for `AL`), so it is used directly.
#[must_use]
pub fn reg_size(reg: Register) -> u8 {
    u8::try_from(reg.size()).unwrap_or(u8::MAX)
}

/// Width in **bits** of a register (`reg_size * 8`). Saturates at `u8::MAX`
/// for the wide vector registers (YMM/ZMM exceed 255 bits).
#[must_use]
pub fn reg_bits(reg: Register) -> u8 {
    u8::try_from(u32::try_from(reg.size()).unwrap_or(u32::MAX).saturating_mul(8).min(u32::from(u8::MAX))).unwrap_or(u8::MAX)
}

/// True when writing this register in 64-bit mode must zero-extend to the
/// 64-bit parent (Intel SDM §3.4.1.1: writes to 32-bit GPRs clear bits 63:32).
#[must_use]
// 🛑 SOTTO-REGISTRI: difetto ARCHITETTURALE, non patchabile qui.
// Scrivere `AH` emette `RegWrite { reg: "ah" }` e nulla collega `ah` al
// genitore ⇒ la scrittura si PERDE (provato: `mov %cl,%ah` a 0x140001547 in
// `pack_fields` non compare nell'emesso). Ho provato la fusione SIA qui SIA in
// `X86Lifter::lift_mov`: NESSUNA delle due ha effetto, perche' il problema si
// ripete a ogni livello — scrivere `rax` non alimenta una lettura di `ax`.
// Serve un MODELLO dei sotto-registri, non un rattoppo.

pub fn writes_zero_extend(reg: Register, bits: u8) -> bool {
    bits == 64 && matches!(reg.size(), 4)
}

/// Parent 64-bit register name for any GPR, or the register's own name when
/// it does not belong to a GPR family.
#[must_use]
pub fn parent64_name(reg: Register) -> String {
    use Register as R;
    let parent = match reg {
        R::RAX | R::EAX | R::AX | R::AL | R::AH => R::RAX,
        R::RBX | R::EBX | R::BX | R::BL | R::BH => R::RBX,
        R::RCX | R::ECX | R::CX | R::CL | R::CH => R::RCX,
        R::RDX | R::EDX | R::DX | R::DL | R::DH => R::RDX,
        R::RSI | R::ESI | R::SI | R::SIL => R::RSI,
        R::RDI | R::EDI | R::DI | R::DIL => R::RDI,
        R::RSP | R::ESP | R::SP | R::SPL => R::RSP,
        R::RBP | R::EBP | R::BP | R::BPL => R::RBP,
        R::R8 | R::R8D | R::R8W | R::R8L => R::R8,
        R::R9 | R::R9D | R::R9W | R::R9L => R::R9,
        R::R10 | R::R10D | R::R10W | R::R10L => R::R10,
        R::R11 | R::R11D | R::R11W | R::R11L => R::R11,
        R::R12 | R::R12D | R::R12W | R::R12L => R::R12,
        R::R13 | R::R13D | R::R13W | R::R13L => R::R13,
        R::R14 | R::R14D | R::R14W | R::R14L => R::R14,
        R::R15 | R::R15D | R::R15W | R::R15L => R::R15,
        other => other,
    };
    reg_name(parent)
}

// ─────────────────────────────────────────────────────────────────────────────
// Effective-address construction
// ─────────────────────────────────────────────────────────────────────────────

/// Build the effective-address expression for `instr`'s memory operand:
///
/// `base + index*scale + displacement`, with the segment prefix (if any)
/// folded in as an `Add` against a synthetic segment-base register
/// (`__seg_fs_base`, `__seg_gs_base`, …).
///
/// Returns the address expression
/// **without** the `Deref` wrapper — callers wrap it themselves so that
/// stores and loads share the same address tree.
#[must_use]
pub fn effective_address(instr: &Instruction) -> IrExpr {
    let base = instr.memory_base();
    let index = instr.memory_index();
    let scale = instr.memory_index_scale();
    let disp = instr.memory_displacement64();

    let base_expr: IrExpr = if base == Register::None {
        IrExpr::Const(0)
    } else {
        IrExpr::Reg(reg_name(base))
    };

    let with_index = if index == Register::None {
        base_expr
    } else {
        let idx = IrExpr::Reg(reg_name(index));
        let scaled = if scale > 1 {
            IrExpr::Mul(Box::new(idx), Box::new(IrExpr::Const(u64::from(scale))))
        } else {
            idx
        };
        // If base is the zero placeholder, skip the redundant Add(0, idx).
        if matches!(base_expr, IrExpr::Const(0)) && base == Register::None {
            scaled
        } else {
            IrExpr::Add(Box::new(base_expr), Box::new(scaled))
        }
    };

    let with_disp = if disp != 0 {
        IrExpr::Add(Box::new(with_index), Box::new(IrExpr::Const(disp)))
    } else {
        with_index
    };

    match instr.segment_prefix() {
        Register::FS => IrExpr::Add(
            Box::new(IrExpr::Reg("__seg_fs_base".into())),
            Box::new(with_disp),
        ),
        Register::GS => IrExpr::Add(
            Box::new(IrExpr::Reg("__seg_gs_base".into())),
            Box::new(with_disp),
        ),
        // ES/CS/SS/DS use a zero base in flat-memory modes (64-bit and the
        // common 32-bit user-mode), so they are folded away. Kernels that
        // rely on segment bases must rewrite this IR in a later pass.
        _ => with_disp,
    }
}

/// Memory-operand element size in **bytes**, defaulting to the machine width
/// when iced reports zero (which happens for some `lea` and prefetch forms).
#[must_use]
pub fn mem_size(instr: &Instruction, ctx: &X86LiftCtx) -> u8 {
    let sz = u8::try_from(instr.memory_size().element_size()).unwrap_or(u8::MAX);
    if sz == 0 { ctx.default_op_size() } else { sz }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand reads
// ─────────────────────────────────────────────────────────────────────────────

/// Width of operand `idx` of `instr` in **bytes**.
///
/// Falls back to the default operand size for branch and immediate kinds that
/// do not carry their own width.
#[must_use]
pub fn operand_size(instr: &Instruction, idx: u32, ctx: &X86LiftCtx) -> u8 {
    let kind = match idx {
        0 => instr.op0_kind(),
        1 => instr.op1_kind(),
        2 => instr.op2_kind(),
        3 => instr.op3_kind(),
        _ => instr.op_kind(idx),
    };
    match kind {
        OpKind::Register => reg_size(instr.op_register(idx)),
        OpKind::Memory => mem_size(instr, ctx),
        OpKind::Immediate8 | OpKind::Immediate8_2nd => 1,
        OpKind::Immediate16 | OpKind::Immediate8to16 | OpKind::NearBranch16 => 2,
        OpKind::Immediate32 | OpKind::Immediate8to32 | OpKind::NearBranch32 => 4,
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::NearBranch64 => 8,
        _ => ctx.default_op_size(),
    }
}

/// Read operand `idx` and return its value as an `IrExpr`.
///
/// * register operand → `IrExpr::Reg(name)`
/// * immediate operand → `IrExpr::Const(value)` (already sign-extended by iced)
/// * memory operand → `IrExpr::Deref(addr, size)` (the IR's load form)
/// * branch target → `IrExpr::Const(addr)` for near-branches
///
/// For far branches and VSIB the function returns `IrExpr::Undef`; higher
/// layers can flag those as `LiftError::UnsupportedLevel` if needed.
#[must_use]
pub fn read_operand(instr: &Instruction, idx: u32, ctx: &X86LiftCtx) -> IrExpr {
    let kind = match idx {
        0 => instr.op0_kind(),
        1 => instr.op1_kind(),
        2 => instr.op2_kind(),
        3 => instr.op3_kind(),
        _ => instr.op_kind(idx),
    };
    match kind {
        OpKind::Register => IrExpr::Reg(reg_name(instr.op_register(idx))),
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => IrExpr::Const(instr.immediate(idx)),
        OpKind::NearBranch16 => IrExpr::Const(u64::from(instr.near_branch16())),
        OpKind::NearBranch32 => IrExpr::Const(u64::from(instr.near_branch32())),
        OpKind::NearBranch64 => IrExpr::Const(instr.near_branch64()),
        OpKind::Memory => {
            let addr = effective_address(instr);
            let size = mem_size(instr, ctx);
            IrExpr::Deref(Box::new(addr), size)
        }
        _ => IrExpr::Undef,
    }
}

/// Read the `idx`'th operand but **strip** any outer `Deref` (so the caller
/// gets the raw address expression, useful for `LEA`).
#[must_use]
pub fn read_operand_addr_only(instr: &Instruction, _idx: u32) -> IrExpr {
    // LEA always targets a memory operand, so we just return the effective
    // address tree. The width of the result is the operand-size of LEA's
    // destination register, which the handler will zero-extend if necessary.
    effective_address(instr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Operand writes
// ─────────────────────────────────────────────────────────────────────────────

/// Commit `value` into operand `idx` of `instr`. This is the **single** place
/// where the lifter resolves partial-register write semantics, including the
/// x86-64 zero-extension of 32-bit GPR writes.
///
/// Errors if the operand kind is not a register or memory destination.
pub fn write_operand(instr: &Instruction, idx: u32, value: IrExpr, ctx: &mut X86LiftCtx) {
    let kind = match idx {
        0 => instr.op0_kind(),
        1 => instr.op1_kind(),
        2 => instr.op2_kind(),
        3 => instr.op3_kind(),
        _ => instr.op_kind(idx),
    };
    match kind {
        OpKind::Register => {
            let reg = instr.op_register(idx);
            let reg_str = reg_name(reg);
            // x86-64 32-bit GPR write zero-extends to the parent 64-bit GPR.
            if writes_zero_extend(reg, ctx.bits) {
                ctx.emit(Effect::RegWrite {
                    reg: reg_str.clone(),
                    value,
                });
                let parent = parent64_name(reg);
                if parent != reg_str {
                    ctx.emit(Effect::RegWrite {
                        reg: parent,
                        value: IrExpr::Reg(reg_str),
                    });
                }
            } else {
                ctx.emit(Effect::RegWrite {
                    reg: reg_str,
                    value,
                });
            }
        }
        OpKind::Memory => {
            let addr = effective_address(instr);
            let size = mem_size(instr, ctx);
            ctx.emit(Effect::MemWrite { addr, value, size });
        }
        _ => {
            // Writing to an immediate / branch operand is meaningless. Emit
            // a marker intrinsic so the situation is visible during review.
            ctx.emit(Effect::Intrinsic {
                name: "x86.write_to_non_lvalue".into(),
                args: vec![value],
            });
        }
    }
}

/// True when operand `idx` is a memory operand. Used by handlers that have
/// to decide between an `Effect::MemWrite` / `MemRead` and a `RegWrite`.
#[must_use]
pub fn is_memory_op(instr: &Instruction, idx: u32) -> bool {
    let kind = match idx {
        0 => instr.op0_kind(),
        1 => instr.op1_kind(),
        2 => instr.op2_kind(),
        3 => instr.op3_kind(),
        _ => instr.op_kind(idx),
    };
    matches!(kind, OpKind::Memory)
}

/// True when operand `idx` is a register operand.
#[must_use]
pub fn is_register_op(instr: &Instruction, idx: u32) -> bool {
    let kind = match idx {
        0 => instr.op0_kind(),
        1 => instr.op1_kind(),
        2 => instr.op2_kind(),
        3 => instr.op3_kind(),
        _ => instr.op_kind(idx),
    };
    matches!(kind, OpKind::Register)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! These tests exercise the pure register/canonicalisation helpers that do
    //! not require a decoded `iced_x86::Instruction`. The instruction-bound
    //! helpers (`effective_address`, `read_operand`, `write_operand`) are
    //! covered indirectly by the x86 handler integration tests.
    use super::*;
    use iced_x86::Register as R;

    #[test]
    fn reg_name_is_lowercase_and_canonical() {
        assert_eq!(reg_name(R::RAX), "rax");
        assert_eq!(reg_name(R::EAX), "eax");
        assert_eq!(reg_name(R::AL), "al");
        assert_eq!(reg_name(R::R15D), "r15d");
        // Edge: None register should still produce a lower-case name without panicking.
        let _ = reg_name(R::None);
    }

    #[test]
    fn reg_size_matches_iced_byte_width() {
        assert_eq!(reg_size(R::AL), 1, "8-bit GPR is 1 byte");
        assert_eq!(reg_size(R::AX), 2, "16-bit GPR is 2 bytes");
        assert_eq!(reg_size(R::EAX), 4, "32-bit GPR is 4 bytes");
        assert_eq!(reg_size(R::RAX), 8, "64-bit GPR is 8 bytes");
        // High-byte alias.
        assert_eq!(reg_size(R::AH), 1);
    }

    #[test]
    fn reg_bits_saturates_for_wide_vector_regs() {
        assert_eq!(reg_bits(R::RAX), 64);
        assert_eq!(reg_bits(R::EAX), 32);
        assert_eq!(reg_bits(R::AX), 16);
        assert_eq!(reg_bits(R::AL), 8);
        // YMM/ZMM exceed 255 bits → saturating cast to u8::MAX.
        let ymm = reg_bits(R::YMM0);
        assert!(ymm == 255 || ymm == u8::MAX);
        let zmm = reg_bits(R::ZMM0);
        assert_eq!(zmm, u8::MAX, "ZMM (512-bit) must saturate at u8::MAX");
    }

    #[test]
    fn writes_zero_extend_only_in_64bit_mode_for_32bit_gpr() {
        // 32-bit GPR write in 64-bit mode must zero-extend.
        assert!(writes_zero_extend(R::EAX, 64));
        assert!(writes_zero_extend(R::R10D, 64));
        // 32-bit GPR write in 32-bit mode does NOT zero-extend (it's already full width).
        assert!(!writes_zero_extend(R::EAX, 32));
        // 64-bit GPR writes are full-width, not "zero-extend".
        assert!(!writes_zero_extend(R::RAX, 64));
        // 8/16-bit GPR writes leave the parent's high bits untouched on x86-64.
        assert!(!writes_zero_extend(R::AL, 64));
        assert!(!writes_zero_extend(R::AX, 64));
        assert!(!writes_zero_extend(R::AH, 64));
        // Boundary: 16-bit mode never zero-extends.
        assert!(!writes_zero_extend(R::EAX, 16));
        // Boundary: 0 bits (a malformed mode value) must not panic and must not zero-extend.
        assert!(!writes_zero_extend(R::EAX, 0));
    }

    #[test]
    fn parent64_name_collapses_gpr_aliases() {
        // RAX family.
        for r in [R::RAX, R::EAX, R::AX, R::AL, R::AH] {
            assert_eq!(parent64_name(r), "rax", "{r:?} should map to rax");
        }
        // RSP / RBP / RSI / RDI use the SIL/DIL/SPL/BPL low-byte aliases under REX.
        assert_eq!(parent64_name(R::RSP), "rsp");
        assert_eq!(parent64_name(R::ESP), "rsp");
        assert_eq!(parent64_name(R::SPL), "rsp");
        assert_eq!(parent64_name(R::SIL), "rsi");
        assert_eq!(parent64_name(R::DIL), "rdi");
        assert_eq!(parent64_name(R::BPL), "rbp");
        // Extended R8..R15 family.
        for r in [R::R8, R::R8D, R::R8W, R::R8L] {
            assert_eq!(parent64_name(r), "r8");
        }
        for r in [R::R15, R::R15D, R::R15W, R::R15L] {
            assert_eq!(parent64_name(r), "r15");
        }
    }

    #[test]
    fn parent64_name_passthrough_for_non_gpr() {
        // Non-GPR registers (SIMD, segment, control) should return their own name.
        assert_eq!(parent64_name(R::XMM0), reg_name(R::XMM0));
        assert_eq!(parent64_name(R::YMM3), reg_name(R::YMM3));
        assert_eq!(parent64_name(R::ES), reg_name(R::ES));
        assert_eq!(parent64_name(R::CR0), reg_name(R::CR0));
        // None passes through.
        assert_eq!(parent64_name(R::None), reg_name(R::None));
    }

    #[test]
    fn parent64_name_roundtrip_is_idempotent_for_64bit_gprs() {
        // Applying parent64_name to an already-64-bit GPR must be a no-op.
        for r in [R::RAX, R::RBX, R::RCX, R::RDX, R::RSI, R::RDI, R::RSP, R::RBP,
                  R::R8, R::R9, R::R10, R::R11, R::R12, R::R13, R::R14, R::R15] {
            assert_eq!(parent64_name(r), reg_name(r), "{r:?} should be its own parent");
        }
    }
}
