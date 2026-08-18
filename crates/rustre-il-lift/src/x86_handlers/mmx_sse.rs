//! MMX / SSE / SSE2 / SSE3 / SSSE3 / SSE4.1 / SSE4.2 instruction handlers.
//!
//! ## Architecture
//!
//! Every handler follows the intrinsic-dispatch pattern established by the
//! existing stub: read operands → emit a named `Effect::Intrinsic` that
//! encodes the operation, lane type and width → materialise an opaque result
//! temp → commit to destination.  This keeps the IL compact while preserving
//! enough information for decompiler passes to recognise common patterns
//! (vectorised memcpy, AES-NI, CRC32, string search, etc.).
//!
//! ## Register naming conventions
//!
//! | Family | Width | IR name |
//! |--------|-------|---------|
//! | MMX    | 64-bit  | `mm0`–`mm7` |
//! | SSE    | 128-bit | `xmm0`–`xmm15` |
//! | AVX    | 256-bit | `ymm0`–`ymm15` (handled in `avx.rs`) |
//!
//! ## Intrinsic name schema
//!
//! ```text
//! x86.<extension>.<mnemonic_lower>
//! ```
//!
//! For example `ADDPS` → `"x86.sse.addps"`, `PADDB` → `"x86.mmx.paddb"`,
//! `PCMPESTRI` → `"x86.sse4_2.pcmpestri"`.
//!
//! ## μOp discipline
//!
//! 1. Read all source operands as `IrExpr` (no side-effects yet).
//! 2. Emit `Effect::Intrinsic { name, args }`.
//! 3. Allocate a fresh temp with `ctx.fresh_temp()` and emit
//!    `Effect::RegWrite { reg: temp, value: IrExpr::Undef }` — the intrinsic
//!    "returns" into that temp by convention.
//! 4. Write the temp into the destination operand via `write_operand`.
//!
//! Scalar flag-setting instructions (COMISS, UCOMISS, etc.) additionally emit
//! `emit_flagset` calls to mark ZF/PF/CF as updated.


use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_operand::{read_operand, write_operand};
use crate::{IrExpr, LiftError};
use iced_x86::{Instruction, Mnemonic};

// =============================================================================
// Internal helper primitives
// =============================================================================

/// Emit a 2-operand SIMD intrinsic `name(dst, src)`, materialise the result
/// into a fresh temp, and commit back into operand 0.
#[inline]
fn binop_intr(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic(name, vec![dst, src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    
}

/// Emit a 3-operand SIMD intrinsic `name(a, b, c)`, materialise and commit.
/// Used for `CMPPS xmm, xmm, imm8`, `SHUFPS`, `PALIGNR`, etc.
#[inline]
fn triop_intr(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let c = read_operand(instr, 2, ctx);
    ctx.emit_intrinsic(name, vec![a, b, c]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    
}

/// Emit a unary SIMD intrinsic `name(src)`, materialise the result and commit.
/// Used for `SQRTPS`, `RSQRTPS`, `RCPPS`, `PABSB`, etc.
#[inline]
fn unop_intr(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic(name, vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    
}

/// Emit a 4-operand SIMD intrinsic (blend-with-mask, DPPS, etc.).
#[inline]
pub fn quadop_intr(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let op0 = read_operand(instr, 0, ctx);
    let op1 = read_operand(instr, 1, ctx);
    let op2 = read_operand(instr, 2, ctx);
    let op3 = if instr.op_count() >= 4 {
        read_operand(instr, 3, ctx)
    } else {
        IrExpr::Const(0)
    };
    ctx.emit_intrinsic(name, vec![op0, op1, op2, op3]);
    let tmp = ctx.fresh_temp();
    ctx.emit_reg_write(tmp.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(tmp), ctx);
    
}

/// Dispatch based on `op_count`: 2-operand → `binop_intr`, 3-operand → `triop_intr`.
#[inline]
fn auto_intr(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    if instr.op_count() >= 3 {
        triop_intr(instr, ctx, name);
    } else {
        binop_intr(instr, ctx, name);
    }
}

/// Emit a flag-setting compare intrinsic that updates ZF/PF/CF in EFLAGS and
/// clears OF/SF/AF to 0 (per Intel SDM for COMISS/UCOMISS/COMISD/UCOMISD).
#[inline]
fn scalar_cmp_flags(instr: &Instruction, ctx: &mut X86LiftCtx, name: &str) {
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic(name, vec![a, b]);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Pf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    ctx.emit_flagset(FlagId::Sf, IrExpr::Const(0));
    ctx.emit_flagset(FlagId::Af, IrExpr::Const(0));
}

// =============================================================================
// ── Section 1: Move instructions ─────────────────────────────────────────────
// =============================================================================

/// Aligned and unaligned vector move variants.
///
/// Covers:
/// - `MOVAPS`  — move 128-bit aligned packed single
/// - `MOVAPD`  — move 128-bit aligned packed double
/// - `MOVUPS`  — move 128-bit unaligned packed single
/// - `MOVUPD`  — move 128-bit unaligned packed double
/// - `MOVDQA`  — move 128-bit aligned packed integer
/// - `MOVDQU`  — move 128-bit unaligned packed integer
/// - `MOVQ`    — move 64-bit (scalar or MMX)
/// - `MOVD`    — move 32-bit (GPR ↔ XMM/MMX)
/// - `MOVSS`   — move scalar single-precision float
/// - `MOVSD`   — move scalar double-precision float (XMM form)
/// - `MOVLPS`/`MOVHPS` — load/store low/high 64-bit of XMM
/// - `MOVLHPS`/`MOVHLPS` — move between XMM halves
/// - `MOVNTDQ`/`MOVNTPD`/`MOVNTPS` — non-temporal (streaming) store
/// - `MOVNTDQA` — non-temporal aligned load (SSE4.1)
/// - `LDDQU`   — load 128-bit unaligned (SSE3)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sse_mov(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    match instr.mnemonic() {
        // Non-temporal stores: emit an intrinsic to preserve the NT hint,
        // then perform the move so dataflow sees the store.
        M::Movntdq | M::Movntpd | M::Movntps => {
            let name = match instr.mnemonic() {
                M::Movntdq => "x86.sse2.movntdq",
                M::Movntpd => "x86.sse2.movntpd",
                M::Movntps => "x86.sse.movntps",
                _ => "x86.sse.movnt",
            };
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic(name, vec![src.clone()]);
            write_operand(instr, 0, src, ctx);
        }
        // Non-temporal aligned load (SSE4.1)
        M::Movntdqa => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse4_1.movntdqa", vec![src.clone()]);
            write_operand(instr, 0, src, ctx);
        }
        // LDDQU: unaligned 128-bit load with cache hint (SSE3)
        M::Lddqu => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse3.lddqu", vec![src.clone()]);
            write_operand(instr, 0, src, ctx);
        }
        // MOVLPS/MOVHPS: 64-bit partial XMM loads/stores
        M::Movlps => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse.movlps", vec![src.clone()]);
            write_operand(instr, 0, src, ctx);
        }
        M::Movhps => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse.movhps", vec![src.clone()]);
            write_operand(instr, 0, src, ctx);
        }
        // MOVLHPS: move low 64 bits of src to high 64 bits of dst
        M::Movlhps => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse.movlhps", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        // MOVHLPS: move high 64 bits of src to low 64 bits of dst
        M::Movhlps => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse.movhlps", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        // MOVMSKPS/MOVMSKPD: extract sign bits of each lane into a GPR
        M::Movmskps => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse.movmskps", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        M::Movmskpd => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse2.movmskpd", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        // MOVDDUP (SSE3): broadcast low 64 bits of src into both halves of dst
        M::Movddup => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse3.movddup", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        // MOVSHDUP (SSE3): duplicate odd (high) single-precision elements
        M::Movshdup => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse3.movshdup", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        // MOVSLDUP (SSE3): duplicate even (low) single-precision elements
        M::Movsldup => {
            let src = read_operand(instr, 1, ctx);
            ctx.emit_intrinsic("x86.sse3.movsldup", vec![src]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        // Plain moves: direct copy.
        _ => {
            let src = read_operand(instr, 1, ctx);
            write_operand(instr, 0, src, ctx);
        }
    }
    Ok(())
}

// =============================================================================
// ── Section 2: SSE floating-point arithmetic ──────────────────────────────────
// =============================================================================

/// SSE/SSE2 floating-point arithmetic.
///
/// Covers (packed and scalar forms):
/// - `ADDPS`/`ADDPD`/`ADDSS`/`ADDSD`
/// - `SUBPS`/`SUBPD`/`SUBSS`/`SUBSD`
/// - `MULPS`/`MULPD`/`MULSS`/`MULSD`
/// - `DIVPS`/`DIVPD`/`DIVSS`/`DIVSD`
/// - `SQRTPS`/`SQRTPD`/`SQRTSS`/`SQRTSD`
/// - `RSQRTPS`/`RSQRTSS` — reciprocal square-root approximation
/// - `RCPPS`/`RCPSS`     — reciprocal approximation
/// - `MINPS`/`MINPD`/`MINSS`/`MINSD`
/// - `MAXPS`/`MAXPD`/`MAXSS`/`MAXSD`
/// - `ADDSUBPS`/`ADDSUBPD` — alternating add/subtract (SSE3)
/// - `HADDPS`/`HADDPD`     — horizontal add (SSE3)
/// - `HSUBPS`/`HSUBPD`     — horizontal subtract (SSE3)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sse_arith(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Addps => "x86.sse.addps",
        M::Addpd => "x86.sse2.addpd",
        M::Addss => "x86.sse.addss",
        M::Addsd => "x86.sse2.addsd",
        M::Subps => "x86.sse.subps",
        M::Subpd => "x86.sse2.subpd",
        M::Subss => "x86.sse.subss",
        M::Subsd => "x86.sse2.subsd",
        M::Mulps => "x86.sse.mulps",
        M::Mulpd => "x86.sse2.mulpd",
        M::Mulss => "x86.sse.mulss",
        M::Mulsd => "x86.sse2.mulsd",
        M::Divps => "x86.sse.divps",
        M::Divpd => "x86.sse2.divpd",
        M::Divss => "x86.sse.divss",
        M::Divsd => "x86.sse2.divsd",
        M::Sqrtps => "x86.sse.sqrtps",
        M::Sqrtpd => "x86.sse2.sqrtpd",
        M::Sqrtss => "x86.sse.sqrtss",
        M::Sqrtsd => "x86.sse2.sqrtsd",
        M::Rsqrtps => "x86.sse.rsqrtps",
        M::Rsqrtss => "x86.sse.rsqrtss",
        M::Rcpps => "x86.sse.rcpps",
        M::Rcpss => "x86.sse.rcpss",
        M::Minps => "x86.sse.minps",
        M::Minpd => "x86.sse2.minpd",
        M::Minss => "x86.sse.minss",
        M::Minsd => "x86.sse2.minsd",
        M::Maxps => "x86.sse.maxps",
        M::Maxpd => "x86.sse2.maxpd",
        M::Maxss => "x86.sse.maxss",
        M::Maxsd => "x86.sse2.maxsd",
        // SSE3
        M::Addsubps => "x86.sse3.addsubps",
        M::Addsubpd => "x86.sse3.addsubpd",
        M::Haddps => "x86.sse3.haddps",
        M::Haddpd => "x86.sse3.haddpd",
        M::Hsubps => "x86.sse3.hsubps",
        M::Hsubpd => "x86.sse3.hsubpd",
        _ => "x86.sse.arith_unknown",
    };
    // SQRT/RSQRT/RCP are 1-source (dst, src) — no in-place accumulate
    match instr.mnemonic() {
        M::Sqrtps
        | M::Sqrtpd
        | M::Sqrtss
        | M::Sqrtsd
        | M::Rsqrtps
        | M::Rsqrtss
        | M::Rcpps
        | M::Rcpss => {
            unop_intr(instr, ctx, name);
            Ok(())
        },
        _ => {
            binop_intr(instr, ctx, name);
            Ok(())
        },
    }
}

// =============================================================================
// ── Section 3: SSE logical operations ────────────────────────────────────────
// =============================================================================

/// Bitwise logical operations on packed floating-point vectors.
///
/// - `ANDPS`/`ANDPD`   — bitwise AND
/// - `ANDNPS`/`ANDNPD` — bitwise AND-NOT (dst = ~src0 & src1)
/// - `ORPS`/`ORPD`     — bitwise OR
/// - `XORPS`/`XORPD`   — bitwise XOR
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sse_logic(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Andps => "x86.sse.andps",
        M::Andpd => "x86.sse2.andpd",
        M::Andnps => "x86.sse.andnps",
        M::Andnpd => "x86.sse2.andnpd",
        M::Orps => "x86.sse.orps",
        M::Orpd => "x86.sse2.orpd",
        M::Xorps => "x86.sse.xorps",
        M::Xorpd => "x86.sse2.xorpd",
        _ => "x86.sse.logic_unknown",
    };
    binop_intr(instr, ctx, name);
    Ok(())
}

// =============================================================================
// ── Section 4: SSE compare ───────────────────────────────────────────────────
// =============================================================================

/// SSE floating-point compare variants.
///
/// Scalar flag-updating forms (`COMISS`, `UCOMISS`, `COMISD`, `UCOMISD`)
/// write ZF/PF/CF in EFLAGS and zero OF/SF/AF.
///
/// Vector/scalar mask forms (`CMPPS`, `CMPPD`, `CMPSS`, `CMPSD`) carry an
/// imm8 predicate (0=EQ, 1=LT, 2=LE, 3=UNORD, 4=NEQ, 5=NLT, 6=NLE, 7=ORD)
/// and produce an all-0 / all-1 lane mask result in the destination register.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sse_cmp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    match instr.mnemonic() {
        // ── Scalar EFLAGS-setting compare ───────────────────────────────
        M::Comiss => {
            scalar_cmp_flags(instr, ctx, "x86.sse.comiss");
        }
        M::Ucomiss => {
            scalar_cmp_flags(instr, ctx, "x86.sse.ucomiss");
        }
        M::Comisd => {
            scalar_cmp_flags(instr, ctx, "x86.sse2.comisd");
        }
        M::Ucomisd => {
            scalar_cmp_flags(instr, ctx, "x86.sse2.ucomisd");
        }
        // ── Predicated vector/scalar compare ────────────────────────────
        M::Cmpps => {
            triop_intr(instr, ctx, "x86.sse.cmpps");
        }
        M::Cmppd => {
            triop_intr(instr, ctx, "x86.sse2.cmppd");
        }
        M::Cmpss => {
            triop_intr(instr, ctx, "x86.sse.cmpss");
        }
        // CMPSD (XMM scalar form): the mnemonic is shared with the string op;
        // the dispatcher already guards with `is_sse_scalar_form`.
        M::Cmpsd => {
            triop_intr(instr, ctx, "x86.sse2.cmpsd");
        }
        _ => {
            let name = format!("x86.sse.{:?}", instr.mnemonic()).to_ascii_lowercase();
            auto_intr(instr, ctx, &name);
        }
    }
    Ok(())
}

// =============================================================================
// ── Section 5: SSE shuffle / unpack / blend ───────────────────────────────────
// =============================================================================

/// SSE shuffle, unpack and permute operations.
///
/// - `SHUFPS` / `SHUFPD`         — shuffle lanes using imm8 control
/// - `UNPCKLPS`/`UNPCKHPS`       — interleave low/high single lanes
/// - `UNPCKLPD`/`UNPCKHPD`       — interleave low/high double lanes
/// - `PSHUFB`  (SSSE3)           — byte shuffle using lane mask
/// - `PSHUFD`                    — shuffle 32-bit dwords
/// - `PSHUFHW`/`PSHUFLW`         — shuffle high/low 16-bit words
/// - `PUNPCKLBW`/`PUNPCKHBW`     — interleave bytes
/// - `PUNPCKLWD`/`PUNPCKHWD`     — interleave words
/// - `PUNPCKLDQ`/`PUNPCKHDQ`     — interleave dwords
/// - `PUNPCKLQDQ`/`PUNPCKHQDQ`   — interleave qwords (SSE2)
/// - `PALIGNR`  (SSSE3)          — concatenate and shift right by imm8 bytes
/// - `EXTRACTPS`                 — extract single-precision float lane
/// - `INSERTPS`                  — insert single-precision float lane
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sse_shuffle(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Shufps => "x86.sse.shufps",
        M::Shufpd => "x86.sse2.shufpd",
        M::Unpcklps => "x86.sse.unpcklps",
        M::Unpckhps => "x86.sse.unpckhps",
        M::Unpcklpd => "x86.sse2.unpcklpd",
        M::Unpckhpd => "x86.sse2.unpckhpd",
        M::Pshufb => "x86.ssse3.pshufb",
        M::Pshufd => "x86.sse2.pshufd",
        M::Pshufhw => "x86.sse2.pshufhw",
        M::Pshuflw => "x86.sse2.pshuflw",
        M::Punpcklbw => "x86.sse2.punpcklbw",
        M::Punpckhbw => "x86.sse2.punpckhbw",
        M::Punpcklwd => "x86.sse2.punpcklwd",
        M::Punpckhwd => "x86.sse2.punpckhwd",
        M::Punpckldq => "x86.sse2.punpckldq",
        M::Punpckhdq => "x86.sse2.punpckhdq",
        M::Punpcklqdq => "x86.sse2.punpcklqdq",
        M::Punpckhqdq => "x86.sse2.punpckhqdq",
        M::Palignr => "x86.ssse3.palignr",
        M::Extractps => "x86.sse4_1.extractps",
        M::Insertps => "x86.sse4_1.insertps",
        _ => {
            let s = format!("x86.sse.{:?}", instr.mnemonic()).to_ascii_lowercase();
            auto_intr(instr, ctx, &s);
            return Ok(());
        }
    };
    auto_intr(instr, ctx, name);
    Ok(())
}

// =============================================================================
// ── Section 6: MMX integer arithmetic ────────────────────────────────────────
// =============================================================================

/// MMX integer arithmetic: PADDB/W/D/Q with normal, unsigned-saturating and
/// signed-saturating variants; PSUBB/W/D/Q likewise.
///
/// Normal wrapping add/sub:
/// - `PADDB` / `PADDW` / `PADDD` / `PADDQ`
/// - `PSUBB` / `PSUBW` / `PSUBD` / `PSUBQ`
///
/// Unsigned saturation (clamp to [0, `MAX_UINT`]):
/// - `PADDUSB` / `PADDUSW`
/// - `PSUBUSB` / `PSUBUSW`
///
/// Signed saturation (clamp to [`MIN_INT`, `MAX_INT`]):
/// - `PADDSB` / `PADDSW`
/// - `PSUBSB` / `PSUBSW`
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mmx_add_sub(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Paddb => "x86.mmx.paddb",
        M::Paddw => "x86.mmx.paddw",
        M::Paddd => "x86.mmx.paddd",
        M::Paddq => "x86.sse2.paddq",
        M::Paddsb => "x86.mmx.paddsb",
        M::Paddsw => "x86.mmx.paddsw",
        M::Paddusb => "x86.mmx.paddusb",
        M::Paddusw => "x86.mmx.paddusw",
        M::Psubb => "x86.mmx.psubb",
        M::Psubw => "x86.mmx.psubw",
        M::Psubd => "x86.mmx.psubd",
        M::Psubq => "x86.sse2.psubq",
        M::Psubsb => "x86.mmx.psubsb",
        M::Psubsw => "x86.mmx.psubsw",
        M::Psubusb => "x86.mmx.psubusb",
        M::Psubusw => "x86.mmx.psubusw",
        _ => "x86.mmx.add_sub_unknown",
    };
    binop_intr(instr, ctx, name);
    Ok(())
}

/// MMX / SSE2 integer SIMD: general dispatcher for all integer vector ops.
///
/// Covers:
/// - Wrapping add/sub (all widths)
/// - Saturating add/sub (signed and unsigned)
/// - Multiply variants: `PMULLW`, `PMULHW`, `PMULHUW`, `PMULUDQ` (SSE2), `PMULLD` (SSE4.1)
/// - Multiply-accumulate: `PMADDWD`, `PMADDUBSW` (SSSE3)
/// - Pack: `PACKUSWB`, `PACKSSWB`, `PACKSSDW`
/// - Compare: `PCMPEQB/W/D/Q`, `PCMPGTB/W/D/Q`
/// - Bitwise: `PAND`, `PANDN`, `POR`, `PXOR`
/// - Shifts: `PSLLW/D/Q`, `PSRLW/D/Q`, `PSRAW/D`
/// - Misc: `PAVGB/W`, `PMINSB/SD/UW/UD`, `PMAXSB/SD/UW/UD`, `PSADBW`, `MPSADBW`
/// - SSE4.1: `PMULDQ`, `PHMINPOSUW`, `PTEST`, `PCMPEQQ`
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
const fn simd_int_intr_name_a(m: Mnemonic) -> Option<&'static str> {
    use Mnemonic as M;
    match m {
        M::Paddb => Some("x86.mmx.paddb"),
        M::Paddw => Some("x86.mmx.paddw"),
        M::Paddd => Some("x86.mmx.paddd"),
        M::Paddq => Some("x86.sse2.paddq"),
        M::Paddsb => Some("x86.mmx.paddsb"),
        M::Paddsw => Some("x86.mmx.paddsw"),
        M::Paddusb => Some("x86.mmx.paddusb"),
        M::Paddusw => Some("x86.mmx.paddusw"),
        M::Psubb => Some("x86.mmx.psubb"),
        M::Psubw => Some("x86.mmx.psubw"),
        M::Psubd => Some("x86.mmx.psubd"),
        M::Psubq => Some("x86.sse2.psubq"),
        M::Psubsb => Some("x86.mmx.psubsb"),
        M::Psubsw => Some("x86.mmx.psubsw"),
        M::Psubusb => Some("x86.mmx.psubusb"),
        M::Psubusw => Some("x86.mmx.psubusw"),
        M::Pmullw => Some("x86.mmx.pmullw"),
        M::Pmulhw => Some("x86.mmx.pmulhw"),
        M::Pmulhuw => Some("x86.mmx.pmulhuw"),
        M::Pmuludq => Some("x86.sse2.pmuludq"),
        M::Pmulld => Some("x86.sse4_1.pmulld"),
        M::Pmuldq => Some("x86.sse4_1.pmuldq"),
        M::Pmulhrsw => Some("x86.ssse3.pmulhrsw"),
        M::Pmaddwd => Some("x86.mmx.pmaddwd"),
        M::Pmaddubsw => Some("x86.ssse3.pmaddubsw"),
        M::Packuswb => Some("x86.mmx.packuswb"),
        M::Packsswb => Some("x86.mmx.packsswb"),
        M::Packssdw => Some("x86.mmx.packssdw"),
        M::Pcmpeqb => Some("x86.mmx.pcmpeqb"),
        M::Pcmpeqw => Some("x86.mmx.pcmpeqw"),
        M::Pcmpeqd => Some("x86.mmx.pcmpeqd"),
        M::Pcmpeqq => Some("x86.sse4_1.pcmpeqq"),
        M::Pcmpgtb => Some("x86.mmx.pcmpgtb"),
        M::Pcmpgtw => Some("x86.mmx.pcmpgtw"),
        M::Pcmpgtd => Some("x86.mmx.pcmpgtd"),
        M::Pcmpgtq => Some("x86.sse4_2.pcmpgtq"),
        M::Pand => Some("x86.mmx.pand"),
        M::Pandn => Some("x86.mmx.pandn"),
        M::Por => Some("x86.mmx.por"),
        M::Pxor => Some("x86.mmx.pxor"),
        M::Psllw => Some("x86.mmx.psllw"),
        M::Pslld => Some("x86.mmx.pslld"),
        M::Psllq => Some("x86.mmx.psllq"),
        _ => None,
    }
}

const fn simd_int_intr_name_b(m: Mnemonic) -> Option<&'static str> {
    use Mnemonic as M;
    match m {
        M::Pxor => Some("x86.mmx.pxor"),
        M::Psllw => Some("x86.mmx.psllw"),
        M::Pslld => Some("x86.mmx.pslld"),
        M::Psllq => Some("x86.mmx.psllq"),
        M::Psrlw => Some("x86.mmx.psrlw"),
        M::Psrld => Some("x86.mmx.psrld"),
        M::Psrlq => Some("x86.mmx.psrlq"),
        M::Psraw => Some("x86.mmx.psraw"),
        M::Psrad => Some("x86.mmx.psrad"),
        M::Pavgb => Some("x86.sse.pavgb"),
        M::Pavgw => Some("x86.sse.pavgw"),
        M::Pminsb => Some("x86.sse4_1.pminsb"),
        M::Pminsd => Some("x86.sse4_1.pminsd"),
        M::Pminuw => Some("x86.sse.pminuw"),
        M::Pminud => Some("x86.sse4_1.pminud"),
        M::Pmaxsb => Some("x86.sse4_1.pmaxsb"),
        M::Pmaxsd => Some("x86.sse4_1.pmaxsd"),
        M::Pmaxuw => Some("x86.sse.pmaxuw"),
        M::Pmaxud => Some("x86.sse4_1.pmaxud"),
        M::Pminsw => Some("x86.sse.pminsw"),
        M::Pmaxsw => Some("x86.sse.pmaxsw"),
        M::Psadbw => Some("x86.sse.psadbw"),
        M::Mpsadbw => Some("x86.sse4_1.mpsadbw"),
        M::Ptest => Some("x86.sse4_1.ptest"),
        M::Pabsb => Some("x86.ssse3.pabsb"),
        M::Pabsw => Some("x86.ssse3.pabsw"),
        M::Pabsd => Some("x86.ssse3.pabsd"),
        M::Phaddw => Some("x86.ssse3.phaddw"),
        M::Phaddd => Some("x86.ssse3.phaddd"),
        M::Phaddsw => Some("x86.ssse3.phaddsw"),
        M::Phsubw => Some("x86.ssse3.phsubw"),
        M::Phsubd => Some("x86.ssse3.phsubd"),
        M::Phsubsw => Some("x86.ssse3.phsubsw"),
        M::Phminposuw => Some("x86.sse4_1.phminposuw"),
        M::Pmovmskb => Some("x86.sse2.pmovmskb"),
        _ => None,
    }
}

/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_simd_int(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = if let Some(n) = simd_int_intr_name_a(instr.mnemonic())
        .or_else(|| simd_int_intr_name_b(instr.mnemonic()))
    {
        n
    } else {
        let s = format!("x86.sse.{:?}", instr.mnemonic()).to_ascii_lowercase();
        auto_intr(instr, ctx, &s);
        return Ok(());
    };
    // PTEST writes EFLAGS (ZF and CF) instead of producing a vector result.
    if instr.mnemonic() == M::Ptest {
        let a = read_operand(instr, 0, ctx);
        let b = read_operand(instr, 1, ctx);
        ctx.emit_intrinsic(name, vec![a, b]);
        ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
        ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Sf, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Af, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Pf, IrExpr::Const(0));
        return Ok(());
    }
    // PMOVMSKB writes into a GPR (not an XMM destination).
    if instr.mnemonic() == M::Pmovmskb {
        let src = read_operand(instr, 1, ctx);
        ctx.emit_intrinsic(name, vec![src]);
        let t = ctx.fresh_temp();
        ctx.emit_reg_write(t.clone(), IrExpr::Undef);
        write_operand(instr, 0, IrExpr::Reg(t), ctx);
        return Ok(());
    }
    auto_intr(instr, ctx, name);
    Ok(())
}

// =============================================================================
// ── Section 7: MMX moves, EMMS, MOVD/MOVQ GPR forms ─────────────────────────
// =============================================================================

/// MMX MOVQ and MOVD between MMX/XMM registers and general-purpose registers,
/// and the `EMMS` instruction that resets the x87 FP tag register.
///
/// - `MOVD mm, r/m32`  — load 32-bit integer into MMX low dword (zero-ext)
/// - `MOVD r/m32, mm`  — store MMX low dword into register or memory
/// - `MOVQ mm, mm/m64` — copy 64-bit MMX value
/// - `EMMS`            — empty MMX state (sets FP tag word to 0xFFFF)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mmx_movq_emms(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    if instr.mnemonic() == M::Emms {
        // EMMS resets the x87 FP tag register to 0xFFFF (all empty).
        // We model this as writing 0xFFFF into the architectural pseudo-reg
        // "fptag", and emit an intrinsic so analysis passes can see it.
        ctx.emit_intrinsic("x86.mmx.emms", vec![]);
        ctx.emit_reg_write("fptag", IrExpr::Const(0xFFFF));
    } else {
        // MOVD / MOVQ â€” plain copy; the operand resolver handles the
        // register-class difference (MMX, XMM, GPR, memory).
        let src = read_operand(instr, 1, ctx);
        write_operand(instr, 0, src, ctx);
    }
    Ok(())
}

// =============================================================================
// ── Section 8: SSE conversion instructions ───────────────────────────────────
// =============================================================================

/// Type-conversion instructions between integer, single-precision and
/// double-precision representations.
///
/// | Mnemonic       | Semantics |
/// |----------------|-----------|
/// | `CVTSI2SS`     | int32/64 → scalar f32 |
/// | `CVTSI2SD`     | int32/64 → scalar f64 |
/// | `CVTSS2SI`     | scalar f32 → int32/64 (round) |
/// | `CVTSD2SI`     | scalar f64 → int32/64 (round) |
/// | `CVTTSS2SI`    | scalar f32 → int32/64 (truncate) |
/// | `CVTTSD2SI`    | scalar f64 → int32/64 (truncate) |
/// | `CVTSS2SD`     | scalar f32 → scalar f64 |
/// | `CVTSD2SS`     | scalar f64 → scalar f32 |
/// | `CVTPS2PD`     | packed f32×2 → packed f64×2 |
/// | `CVTPD2PS`     | packed f64×2 → packed f32×4 (upper zeroed) |
/// | `CVTDQ2PS`     | packed int32×4 → packed f32×4 |
/// | `CVTDQ2PD`     | packed int32×2 → packed f64×2 |
/// | `CVTPS2DQ`     | packed f32×4 → packed int32×4 (round) |
/// | `CVTPD2DQ`     | packed f64×2 → packed int32×2 (round) |
/// | `CVTTPS2DQ`    | packed f32×4 → packed int32×4 (truncate) |
/// | `CVTTPD2DQ`    | packed f64×2 → packed int32×2 (truncate) |
/// | `CVTPS2PI`     | packed f32×2 → packed int32 in MM (round) |
/// | `CVTPD2PI`     | packed f64×2 → packed int32 in MM (round) |
/// | `CVTPI2PS`     | packed int32 in MM → packed f32×2 |
/// | `CVTPI2PD`     | packed int32 in MM → packed f64×2 |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sse_cvt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Cvtsi2ss => "x86.sse.cvtsi2ss",
        M::Cvtsi2sd => "x86.sse2.cvtsi2sd",
        M::Cvtss2si => "x86.sse.cvtss2si",
        M::Cvtsd2si => "x86.sse2.cvtsd2si",
        M::Cvttss2si => "x86.sse.cvttss2si",
        M::Cvttsd2si => "x86.sse2.cvttsd2si",
        M::Cvtss2sd => "x86.sse2.cvtss2sd",
        M::Cvtsd2ss => "x86.sse2.cvtsd2ss",
        M::Cvtps2pd => "x86.sse2.cvtps2pd",
        M::Cvtpd2ps => "x86.sse2.cvtpd2ps",
        M::Cvtdq2ps => "x86.sse2.cvtdq2ps",
        M::Cvtdq2pd => "x86.sse2.cvtdq2pd",
        M::Cvtps2dq => "x86.sse2.cvtps2dq",
        M::Cvtpd2dq => "x86.sse2.cvtpd2dq",
        M::Cvttps2dq => "x86.sse2.cvttps2dq",
        M::Cvttpd2dq => "x86.sse2.cvttpd2dq",
        M::Cvtps2pi => "x86.sse.cvtps2pi",
        M::Cvtpd2pi => "x86.sse2.cvtpd2pi",
        M::Cvtpi2ps => "x86.sse.cvtpi2ps",
        M::Cvtpi2pd => "x86.sse2.cvtpi2pd",
        _ => {
            let s = format!("x86.sse.{:?}", instr.mnemonic()).to_ascii_lowercase();
            return {
                binop_intr(instr, ctx, &s);
                Ok(())
            };
        }
    };
    binop_intr(instr, ctx, name);
    Ok(())
}

// =============================================================================
// ── Section 9: MXCSR, prefetch, fence ────────────────────────────────────────
// =============================================================================

/// Load / store the MXCSR control/status register.
///
/// - `LDMXCSR m32` — load MXCSR from memory
/// - `STMXCSR m32` — store MXCSR to memory
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mxcsr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    match instr.mnemonic() {
        M::Ldmxcsr => {
            let src = read_operand(instr, 0, ctx);
            ctx.emit_intrinsic("x86.sse.ldmxcsr", vec![src.clone()]);
            ctx.emit_reg_write("mxcsr", src);
        }
        M::Stmxcsr => {
            ctx.emit_intrinsic("x86.sse.stmxcsr", vec![IrExpr::Reg("mxcsr".into())]);
            write_operand(instr, 0, IrExpr::Reg("mxcsr".into()), ctx);
        }
        _ => {
            ctx.emit_intrinsic("x86.sse.mxcsr_unknown", vec![]);
        }
    }
    Ok(())
}

/// Prefetch hints and memory-barrier fences.
///
/// Prefetch:
/// - `PREFETCHNTA` — non-temporal prefetch into all cache levels
/// - `PREFETCHT0`  — prefetch into L1/L2/L3
/// - `PREFETCHT1`  — prefetch into L2/L3
/// - `PREFETCHT2`  — prefetch into L3
///
/// Fences:
/// - `SFENCE` — store fence (all stores ordered before this point)
/// - `LFENCE` — load fence
/// - `MFENCE` — full memory fence
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetch_fence(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    match instr.mnemonic() {
        M::Prefetchnta => {
            let addr = read_operand(instr, 0, ctx);
            ctx.emit_intrinsic("x86.sse.prefetchnta", vec![addr]);
        }
        M::Prefetcht0 => {
            let addr = read_operand(instr, 0, ctx);
            ctx.emit_intrinsic("x86.sse.prefetcht0", vec![addr]);
        }
        M::Prefetcht1 => {
            let addr = read_operand(instr, 0, ctx);
            ctx.emit_intrinsic("x86.sse.prefetcht1", vec![addr]);
        }
        M::Prefetcht2 => {
            let addr = read_operand(instr, 0, ctx);
            ctx.emit_intrinsic("x86.sse.prefetcht2", vec![addr]);
        }
        M::Sfence => {
            ctx.emit_intrinsic("x86.sse.sfence", vec![]);
        }
        M::Lfence => {
            ctx.emit_intrinsic("x86.sse2.lfence", vec![]);
        }
        M::Mfence => {
            ctx.emit_intrinsic("x86.sse2.mfence", vec![]);
        }
        _ => {
            ctx.emit_intrinsic("x86.sse.fence_unknown", vec![]);
        }
    }
    Ok(())
}

// =============================================================================
// ── Section 10: SSE4.2 string compare ────────────────────────────────────────
// =============================================================================

/// SSE4.2 string/text processing instructions.
///
/// All four variants take an `imm8` control byte that encodes:
/// - bits [1:0]: source data element size (00=uint8, 01=uint16, 10=int8, 11=int16)
/// - bits [3:2]: aggregation operation (00=EqualAny, 01=Ranges, 10=EqualEach, 11=EqualOrdered)
/// - bit  [4]:   polarity (0=positive, 1=negative)
/// - bit  [5]:   output selection (for xSTRI: 0=least-significant, 1=most-significant)
/// - bit  [6]:   only for xSTRM: result type (0=mask, 1=bit-mask)
///
/// - `PCMPESTRI` — explicit-length string compare, return index in ECX
/// - `PCMPESTRM` — explicit-length string compare, return mask in XMM0
/// - `PCMPISTRI` — implicit-length (null-terminated) string compare, index in ECX
/// - `PCMPISTRM` — implicit-length string compare, mask in XMM0
///
/// These instructions set CF/ZF/SF/OF/AF/PF as comparison side-effects.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pcmpstr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let (name, explicit) = match instr.mnemonic() {
        M::Pcmpestri => ("x86.sse4_2.pcmpestri", true),
        M::Pcmpestrm => ("x86.sse4_2.pcmpestrm", true),
        M::Pcmpistri => ("x86.sse4_2.pcmpistri", false),
        M::Pcmpistrm => ("x86.sse4_2.pcmpistrm", false),
        _ => {
            ctx.emit_intrinsic("x86.sse4_2.pcmpstr_unknown", vec![]);
            return Ok(());
        }
    };
    let a = read_operand(instr, 0, ctx);
    let b = read_operand(instr, 1, ctx);
    let imm = read_operand(instr, 2, ctx);
    let mut args = vec![a, b, imm];
    if explicit {
        // Explicit-length forms also implicitly read EAX (length of src1)
        // and EDX (length of src2).
        args.push(IrExpr::Reg("eax".into()));
        args.push(IrExpr::Reg("edx".into()));
    }
    ctx.emit_intrinsic(name, args);
    // Result: index or mask in ECX / XMM0 respectively; flags are clobbered.
    match instr.mnemonic() {
        M::Pcmpestri | M::Pcmpistri => {
            ctx.emit_reg_write("ecx", IrExpr::Undef);
        }
        M::Pcmpestrm | M::Pcmpistrm => {
            ctx.emit_reg_write("xmm0", IrExpr::Undef);
        }
        _ => {}
    }
    // All flags defined by the imm8 control
    for f in [
        FlagId::Cf,
        FlagId::Zf,
        FlagId::Sf,
        FlagId::Of,
        FlagId::Af,
        FlagId::Pf,
    ] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    Ok(())
}

// =============================================================================
// ── Section 11: SSE4.2 CRC32 ─────────────────────────────────────────────────
// =============================================================================

/// `CRC32 r32/64, r/m8/16/32/64` — accumulate CRC-32C (Castagnoli) checksum.
///
/// The source can be 8, 16, 32 or 64 bits; the destination is always a
/// 32-bit (or 64-bit when REX.W) GPR.  Flags are not modified.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_crc32(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.sse4_2.crc32", vec![dst, src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// =============================================================================
// ── Section 12: SSE4.1 blend, dot-product, round ─────────────────────────────
// =============================================================================

/// SSE4.1 blend (lane-select) instructions.
///
/// - `BLENDPS xmm, xmm, imm8`   — select f32 lanes by imm8 bitmask
/// - `BLENDPD xmm, xmm, imm8`   — select f64 lanes by imm8 bitmask
/// - `BLENDVPS xmm, xmm, xmm0`  — select f32 lanes by XMM0 sign bits
/// - `BLENDVPD xmm, xmm, xmm0`  — select f64 lanes by XMM0 sign bits
/// - `PBLENDW xmm, xmm, imm8`   — select 16-bit word lanes by imm8 bitmask
/// - `PBLENDVB xmm, xmm, xmm0`  — select bytes by XMM0 high bits
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_blend(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Blendps => "x86.sse4_1.blendps",
        M::Blendpd => "x86.sse4_1.blendpd",
        M::Blendvps => "x86.sse4_1.blendvps",
        M::Blendvpd => "x86.sse4_1.blendvpd",
        M::Pblendw => "x86.sse4_1.pblendw",
        M::Pblendvb => "x86.sse4_1.pblendvb",
        _ => "x86.sse4_1.blend_unknown",
    };
    // Variable-blend forms implicitly read XMM0 as the selector.
    match instr.mnemonic() {
        M::Blendvps | M::Blendvpd | M::Pblendvb => {
            let a = read_operand(instr, 0, ctx);
            let b = read_operand(instr, 1, ctx);
            let sel = IrExpr::Reg("xmm0".into());
            ctx.emit_intrinsic(name, vec![a, b, sel]);
            let t = ctx.fresh_temp();
            ctx.emit_reg_write(t.clone(), IrExpr::Undef);
            write_operand(instr, 0, IrExpr::Reg(t), ctx);
        }
        _ => {
            triop_intr(instr, ctx, name);
        }
    }
    Ok(())
}

/// SSE4.1 dot-product instructions.
///
/// - `DPPS xmm, xmm, imm8`  — dot-product of f32×4 with imm8 selecting
///   which lanes contribute to the sum and which result lanes receive it
/// - `DPPD xmm, xmm, imm8`  — dot-product of f64×2
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_dp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Dpps => "x86.sse4_1.dpps",
        M::Dppd => "x86.sse4_1.dppd",
        _ => "x86.sse4_1.dp_unknown",
    };
    triop_intr(instr, ctx, name);
    Ok(())
}

/// SSE4.1 rounding instructions.
///
/// - `ROUNDPS xmm, xmm, imm8`  — round all f32 lanes per imm8 mode
/// - `ROUNDPD xmm, xmm, imm8`  — round all f64 lanes
/// - `ROUNDSS xmm, xmm, imm8`  — round scalar f32
/// - `ROUNDSD xmm, xmm, imm8`  — round scalar f64
///
/// `imm8` bits [1:0]: 00=nearest, 01=down, 10=up, 11=truncate; bit 2=MXCSR.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_round(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Roundps => "x86.sse4_1.roundps",
        M::Roundpd => "x86.sse4_1.roundpd",
        M::Roundss => "x86.sse4_1.roundss",
        M::Roundsd => "x86.sse4_1.roundsd",
        _ => "x86.sse4_1.round_unknown",
    };
    triop_intr(instr, ctx, name);
    Ok(())
}

// =============================================================================
// ── Section 13: SSE4.1 sign-/zero-extend move (PMOVSX / PMOVZX) ──────────────
// =============================================================================

/// SSE4.1 packed sign-extend moves.
///
/// Each instruction reads a narrow source, sign-extends each element to the
/// wider lane type, and writes the result to an XMM destination.
///
/// - `PMOVSXBW`  — i8×8  → i16×8
/// - `PMOVSXBD`  — i8×4  → i32×4
/// - `PMOVSXBQ`  — i8×2  → i64×2
/// - `PMOVSXWD`  — i16×4 → i32×4
/// - `PMOVSXWQ`  — i16×2 → i64×2
/// - `PMOVSXDQ`  — i32×2 → i64×2
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pmovsx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Pmovsxbw => "x86.sse4_1.pmovsxbw",
        M::Pmovsxbd => "x86.sse4_1.pmovsxbd",
        M::Pmovsxbq => "x86.sse4_1.pmovsxbq",
        M::Pmovsxwd => "x86.sse4_1.pmovsxwd",
        M::Pmovsxwq => "x86.sse4_1.pmovsxwq",
        M::Pmovsxdq => "x86.sse4_1.pmovsxdq",
        _ => "x86.sse4_1.pmovsx_unknown",
    };
    unop_intr(instr, ctx, name);
    Ok(())
}

/// SSE4.1 packed zero-extend moves.
///
/// Identical semantics to PMOVSX but zero-extends instead of sign-extends.
///
/// - `PMOVZXBW`  — u8×8  → u16×8
/// - `PMOVZXBD`  — u8×4  → u32×4
/// - `PMOVZXBQ`  — u8×2  → u64×2
/// - `PMOVZXWD`  — u16×4 → u32×4
/// - `PMOVZXWQ`  — u16×2 → u64×2
/// - `PMOVZXDQ`  — u32×2 → u64×2
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pmovzx(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    let name: &str = match instr.mnemonic() {
        M::Pmovzxbw => "x86.sse4_1.pmovzxbw",
        M::Pmovzxbd => "x86.sse4_1.pmovzxbd",
        M::Pmovzxbq => "x86.sse4_1.pmovzxbq",
        M::Pmovzxwd => "x86.sse4_1.pmovzxwd",
        M::Pmovzxwq => "x86.sse4_1.pmovzxwq",
        M::Pmovzxdq => "x86.sse4_1.pmovzxdq",
        _ => "x86.sse4_1.pmovzx_unknown",
    };
    unop_intr(instr, ctx, name);
    Ok(())
}

// =============================================================================
// ── Section 14: Catch-all for remaining SSE2/SSE3/SSSE3/SSE4 integer ops ──────
// =============================================================================

/// Dispatcher for any remaining SIMD integer instructions not covered by a
/// more specific handler above.  Generates an intrinsic name from the mnemonic.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_simd_misc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let name = format!("x86.sse.{:?}", instr.mnemonic()).to_ascii_lowercase();
    auto_intr(instr, ctx, &name);
    Ok(())
}

// =============================================================================
// ── Section 15: Top-level public API re-exports (used by mod.rs dispatch) ────
// =============================================================================

// The following public entry-points were already established in the original
// stub and are kept for backward-compatibility with the dispatcher in mod.rs.
// Each now delegates to the richer implementation above.

// Move — aligned/unaligned/non-temporal/partial (all SSE move variants).
// Already defined above as `lift_sse_mov`.

// Floating-point arithmetic (add/sub/mul/div/sqrt/rsqrt/rcp/min/max/hadd/hsub/addsub).
// Already defined above as `lift_sse_arith`.

// Bitwise logical (and/andn/or/xor for ps/pd).
// Already defined above as `lift_sse_logic`.

// Predicated and scalar flag-setting compare.
// Already defined above as `lift_sse_cmp`.

// Lane shuffle/unpack/permute/blend.
// Already defined above as `lift_sse_shuffle`.

// Integer SIMD bulk dispatcher.
// Already defined above as `lift_simd_int`.

// =============================================================================
// ── Section 16: Tests ─────────────────────────────────────────────────────────
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Test infrastructure ───────────────────────────────────────────────────

    fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    fn has_reg_write(effects: &[Effect], reg: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
    }

    fn intrinsic_count(effects: &[Effect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Intrinsic { .. }))
            .count()
    }

    // ── Smoke tests: context mechanics ───────────────────────────────────────

    #[test]
    fn ctx_emits_correctly() {
        let mut ctx = ctx64();
        ctx.emit(Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(1),
        });
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn fresh_temps_are_unique() {
        let mut ctx = ctx64();
        let t1 = ctx.fresh_temp();
        let t2 = ctx.fresh_temp();
        assert_ne!(t1, t2);
        let t3 = ctx.fresh_temp();
        assert_ne!(t2, t3);
    }

    #[test]
    fn materialise_returns_unique_temp() {
        let mut ctx = ctx64();
        let t = ctx.materialise(IrExpr::Const(7));
        assert!(!t.is_empty());
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn intrinsic_does_not_panic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("test.handler_smoke", vec![]);
        assert!(has_intrinsic(&ctx.effects, "test.handler_smoke"));
    }

    #[test]
    fn eval_constant_through_effects() {
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(0x42),
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rax", 0x42);
    }

    #[test]
    fn unknown_propagates_in_eval() {
        let effects = vec![Effect::RegWrite {
            reg: "rbx".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg("rax".into())),
                Box::new(IrExpr::Const(1)),
            ),
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        assert_eq!(s.get_reg("rbx"), EvalValue::Unknown);
    }

    #[test]
    fn mem_write_stored_and_readable() {
        let effects = vec![Effect::MemWrite {
            addr: IrExpr::Const(0x5000),
            value: IrExpr::Const(0xdead_beef),
            size: 4,
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        assert_eq!(s.read_mem(0x5000, 4), EvalValue::Concrete(0xdead_beef));
    }

    // ── binop_intr / unop_intr / triop_intr helper tests ─────────────────────

    #[test]
    fn binop_intr_emits_intrinsic_and_regwrite() {
        let mut ctx = ctx64();
        // ADDPS xmm0, xmm1  →  66 0F 58 C1
        let instr = decode64(&[0x0F, 0x58, 0xC1]);
        let _ = binop_intr(&instr, &mut ctx, "x86.sse.addps");
        assert!(has_intrinsic(&ctx.effects, "x86.sse.addps"));
        // At least one RegWrite (the temp + the dst commit)
        assert!(
            ctx.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { .. }))
        );
    }

    #[test]
    fn unop_intr_emits_intrinsic() {
        let mut ctx = ctx64();
        // SQRTPS xmm0, xmm1  →  0F 51 C1
        let instr = decode64(&[0x0F, 0x51, 0xC1]);
        let _ = unop_intr(&instr, &mut ctx, "x86.sse.sqrtps");
        assert!(has_intrinsic(&ctx.effects, "x86.sse.sqrtps"));
    }

    // ── lift_sse_arith tests ──────────────────────────────────────────────────

    #[test]
    fn addps_emits_correct_intrinsic() {
        // ADDPS xmm0, xmm1  →  0F 58 C1
        let instr = decode64(&[0x0F, 0x58, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "addps"));
    }

    #[test]
    fn addpd_emits_sse2_intrinsic() {
        // ADDPD xmm0, xmm1  →  66 0F 58 C1
        let instr = decode64(&[0x66, 0x0F, 0x58, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "addpd"));
    }

    #[test]
    fn subps_emits_correct_intrinsic() {
        // SUBPS xmm0, xmm1  →  0F 5C C1
        let instr = decode64(&[0x0F, 0x5C, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "subps"));
    }

    #[test]
    fn mulps_emits_correct_intrinsic() {
        // MULPS xmm0, xmm1  →  0F 59 C1
        let instr = decode64(&[0x0F, 0x59, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "mulps"));
    }

    #[test]
    fn divps_emits_correct_intrinsic() {
        // DIVPS xmm0, xmm1  →  0F 5E C1
        let instr = decode64(&[0x0F, 0x5E, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "divps"));
    }

    #[test]
    fn sqrtps_emits_correct_intrinsic() {
        // SQRTPS xmm0, xmm1  →  0F 51 C1
        let instr = decode64(&[0x0F, 0x51, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "sqrtps"));
    }

    #[test]
    fn minps_emits_correct_intrinsic() {
        // MINPS xmm0, xmm1  →  0F 5D C1
        let instr = decode64(&[0x0F, 0x5D, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "minps"));
    }

    #[test]
    fn maxps_emits_correct_intrinsic() {
        // MAXPS xmm0, xmm1  →  0F 5F C1
        let instr = decode64(&[0x0F, 0x5F, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_arith(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "maxps"));
    }

    // ── lift_sse_logic tests ──────────────────────────────────────────────────

    #[test]
    fn andps_emits_correct_intrinsic() {
        // ANDPS xmm0, xmm1  →  0F 54 C1
        let instr = decode64(&[0x0F, 0x54, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_logic(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "andps"));
    }

    #[test]
    fn orps_emits_correct_intrinsic() {
        // ORPS xmm0, xmm1  →  0F 56 C1
        let instr = decode64(&[0x0F, 0x56, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_logic(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "orps"));
    }

    #[test]
    fn xorps_emits_correct_intrinsic() {
        // XORPS xmm0, xmm0  →  0F 57 C0
        let instr = decode64(&[0x0F, 0x57, 0xC0]);
        let mut ctx = ctx64();
        lift_sse_logic(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "xorps"));
    }

    #[test]
    fn andpd_emits_sse2_intrinsic() {
        // ANDPD xmm0, xmm1  →  66 0F 54 C1
        let instr = decode64(&[0x66, 0x0F, 0x54, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_logic(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "andpd"));
    }

    // ── lift_sse_cmp tests ────────────────────────────────────────────────────

    #[test]
    fn comiss_sets_flags() {
        // COMISS xmm0, xmm1  →  0F 2F C1
        let instr = decode64(&[0x0F, 0x2F, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_cmp(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "comiss"));
        assert!(has_reg_write(&ctx.effects, "zf"));
        assert!(has_reg_write(&ctx.effects, "pf"));
        assert!(has_reg_write(&ctx.effects, "cf"));
        assert!(has_reg_write(&ctx.effects, "of"));
        assert!(has_reg_write(&ctx.effects, "sf"));
        assert!(has_reg_write(&ctx.effects, "af"));
    }

    #[test]
    fn ucomiss_sets_flags() {
        // UCOMISS xmm0, xmm1  →  0F 2E C1
        let instr = decode64(&[0x0F, 0x2E, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_cmp(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "ucomiss"));
    }

    #[test]
    fn cmpps_produces_mask_result() {
        // CMPPS xmm0, xmm1, 0 (EQ)  →  0F C2 C1 00
        let instr = decode64(&[0x0F, 0xC2, 0xC1, 0x00]);
        let mut ctx = ctx64();
        lift_sse_cmp(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "cmpps"));
    }

    // ── lift_sse_shuffle tests ────────────────────────────────────────────────

    #[test]
    fn shufps_emits_triop_intrinsic() {
        // SHUFPS xmm0, xmm1, 0xE4  →  0F C6 C1 E4
        let instr = decode64(&[0x0F, 0xC6, 0xC1, 0xE4]);
        let mut ctx = ctx64();
        lift_sse_shuffle(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "shufps"));
    }

    #[test]
    fn pshufd_emits_triop_intrinsic() {
        // PSHUFD xmm0, xmm1, 0x4E  →  66 0F 70 C1 4E
        let instr = decode64(&[0x66, 0x0F, 0x70, 0xC1, 0x4E]);
        let mut ctx = ctx64();
        lift_sse_shuffle(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pshufd"));
    }

    #[test]
    fn punpcklbw_emits_correct_intrinsic() {
        // PUNPCKLBW xmm0, xmm1  →  66 0F 60 C1
        let instr = decode64(&[0x66, 0x0F, 0x60, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_shuffle(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "punpcklbw"));
    }

    // ── lift_simd_int tests ───────────────────────────────────────────────────

    #[test]
    fn paddb_emits_mmx_intrinsic() {
        // PADDB xmm0, xmm1  →  66 0F FC C1
        let instr = decode64(&[0x66, 0x0F, 0xFC, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "paddb"));
    }

    #[test]
    fn paddw_emits_mmx_intrinsic() {
        // PADDW xmm0, xmm1  →  66 0F FD C1
        let instr = decode64(&[0x66, 0x0F, 0xFD, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "paddw"));
    }

    #[test]
    fn paddd_emits_mmx_intrinsic() {
        // PADDD xmm0, xmm1  →  66 0F FE C1
        let instr = decode64(&[0x66, 0x0F, 0xFE, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "paddd"));
    }

    #[test]
    fn paddq_emits_sse2_intrinsic() {
        // PADDQ xmm0, xmm1  →  66 0F D4 C1
        let instr = decode64(&[0x66, 0x0F, 0xD4, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "paddq"));
    }

    #[test]
    fn psubb_emits_mmx_intrinsic() {
        // PSUBB xmm0, xmm1  →  66 0F F8 C1
        let instr = decode64(&[0x66, 0x0F, 0xF8, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "psubb"));
    }

    #[test]
    fn pmullw_emits_intrinsic() {
        // PMULLW xmm0, xmm1  →  66 0F D5 C1
        let instr = decode64(&[0x66, 0x0F, 0xD5, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pmullw"));
    }

    #[test]
    fn pmuludq_emits_sse2_intrinsic() {
        // PMULUDQ xmm0, xmm1  →  66 0F F4 C1
        let instr = decode64(&[0x66, 0x0F, 0xF4, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pmuludq"));
    }

    #[test]
    fn pxor_emits_intrinsic() {
        // PXOR xmm0, xmm1  →  66 0F EF C1
        let instr = decode64(&[0x66, 0x0F, 0xEF, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pxor"));
    }

    #[test]
    fn pand_emits_intrinsic() {
        // PAND xmm0, xmm1  →  66 0F DB C1
        let instr = decode64(&[0x66, 0x0F, 0xDB, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pand"));
    }

    #[test]
    fn por_emits_intrinsic() {
        // POR xmm0, xmm1  →  66 0F EB C1
        let instr = decode64(&[0x66, 0x0F, 0xEB, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "por"));
    }

    #[test]
    fn pcmpeqb_emits_intrinsic() {
        // PCMPEQB xmm0, xmm1  →  66 0F 74 C1
        let instr = decode64(&[0x66, 0x0F, 0x74, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pcmpeqb"));
    }

    #[test]
    fn pcmpgtb_emits_intrinsic() {
        // PCMPGTB xmm0, xmm1  →  66 0F 64 C1
        let instr = decode64(&[0x66, 0x0F, 0x64, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pcmpgtb"));
    }

    #[test]
    fn ptest_sets_flags() {
        // PTEST xmm0, xmm1  →  66 0F 38 17 C1
        let instr = decode64(&[0x66, 0x0F, 0x38, 0x17, 0xC1]);
        let mut ctx = ctx64();
        lift_simd_int(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "ptest"));
        assert!(has_reg_write(&ctx.effects, "zf"));
        assert!(has_reg_write(&ctx.effects, "cf"));
    }

    // ── lift_sse_mov tests ────────────────────────────────────────────────────

    #[test]
    fn movaps_is_plain_copy() {
        // MOVAPS xmm0, xmm1  →  0F 28 C1
        let instr = decode64(&[0x0F, 0x28, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_mov(&instr, &mut ctx).unwrap();
        // Plain copy: no Intrinsic, just a RegWrite to xmm0
        assert_eq!(intrinsic_count(&ctx.effects), 0);
        assert!(has_reg_write(&ctx.effects, "xmm0"));
    }

    #[test]
    fn movddup_emits_sse3_intrinsic() {
        // MOVDDUP xmm0, xmm1  →  F2 0F 12 C1
        let instr = decode64(&[0xF2, 0x0F, 0x12, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_mov(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "movddup"));
    }

    #[test]
    fn movshdup_emits_sse3_intrinsic() {
        // MOVSHDUP xmm0, xmm1  →  F3 0F 16 C1
        let instr = decode64(&[0xF3, 0x0F, 0x16, 0xC1]);
        let mut ctx = ctx64();
        lift_sse_mov(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "movshdup"));
    }

    // ── lift_blend tests ──────────────────────────────────────────────────────

    #[test]
    fn blendps_emits_sse4_intrinsic() {
        // BLENDPS xmm0, xmm1, 0x0F  →  66 0F 3A 0C C1 0F
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x0C, 0xC1, 0x0F]);
        let mut ctx = ctx64();
        lift_blend(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "blendps"));
    }

    #[test]
    fn blendvps_reads_xmm0_selector() {
        // BLENDVPS xmm0, xmm1, xmm0  →  66 0F 38 14 C1
        let instr = decode64(&[0x66, 0x0F, 0x38, 0x14, 0xC1]);
        let mut ctx = ctx64();
        lift_blend(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "blendvps"));
        // The intrinsic args should include a Reg("xmm0") for the selector.
        let found = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { args, .. } = e {
                args.iter()
                    .any(|a| matches!(a, IrExpr::Reg(r) if r == "xmm0"))
            } else {
                false
            }
        });
        assert!(found, "selector xmm0 not found in intrinsic args");
    }

    // ── lift_dp tests ─────────────────────────────────────────────────────────

    #[test]
    fn dpps_emits_sse4_intrinsic() {
        // DPPS xmm0, xmm1, 0xFF  →  66 0F 3A 40 C1 FF
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x40, 0xC1, 0xFF]);
        let mut ctx = ctx64();
        lift_dp(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "dpps"));
    }

    #[test]
    fn dppd_emits_sse4_intrinsic() {
        // DPPD xmm0, xmm1, 0x31  →  66 0F 3A 41 C1 31
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x41, 0xC1, 0x31]);
        let mut ctx = ctx64();
        lift_dp(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "dppd"));
    }

    // ── lift_round tests ──────────────────────────────────────────────────────

    #[test]
    fn roundps_emits_sse4_intrinsic() {
        // ROUNDPS xmm0, xmm1, 0x00  →  66 0F 3A 08 C1 00
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x08, 0xC1, 0x00]);
        let mut ctx = ctx64();
        lift_round(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "roundps"));
    }

    #[test]
    fn roundsd_emits_sse4_intrinsic() {
        // ROUNDSD xmm0, xmm1, 0x01  →  66 0F 3A 0B C1 01
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x0B, 0xC1, 0x01]);
        let mut ctx = ctx64();
        lift_round(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "roundsd"));
    }

    // ── lift_pmovsx / lift_pmovzx tests ──────────────────────────────────────

    #[test]
    fn pmovsxbw_emits_correct_intrinsic() {
        // PMOVSXBW xmm0, xmm1  →  66 0F 38 20 C1
        let instr = decode64(&[0x66, 0x0F, 0x38, 0x20, 0xC1]);
        let mut ctx = ctx64();
        lift_pmovsx(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pmovsxbw"));
    }

    #[test]
    fn pmovzxbq_emits_correct_intrinsic() {
        // PMOVZXBQ xmm0, xmm1  →  66 0F 38 32 C1
        let instr = decode64(&[0x66, 0x0F, 0x38, 0x32, 0xC1]);
        let mut ctx = ctx64();
        lift_pmovzx(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pmovzxbq"));
    }

    // ── lift_crc32 tests ──────────────────────────────────────────────────────

    #[test]
    fn crc32_emits_sse42_intrinsic() {
        // CRC32 eax, cl  →  F2 0F 38 F0 C1
        let instr = decode64(&[0xF2, 0x0F, 0x38, 0xF0, 0xC1]);
        let mut ctx = ctx64();
        lift_crc32(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "crc32"));
    }

    // ── lift_mmx_movq_emms tests ──────────────────────────────────────────────

    #[test]
    fn emms_resets_fptag() {
        // EMMS  →  0F 77
        let instr = decode64(&[0x0F, 0x77]);
        let mut ctx = ctx64();
        lift_mmx_movq_emms(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "emms"));
        assert!(has_reg_write(&ctx.effects, "fptag"));
    }

    // ── lift_pcmpstr tests ────────────────────────────────────────────────────

    #[test]
    fn pcmpistri_emits_sse42_intrinsic_and_ecx() {
        // PCMPISTRI xmm0, xmm1, 0x00  →  66 0F 3A 63 C1 00
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x63, 0xC1, 0x00]);
        let mut ctx = ctx64();
        lift_pcmpstr(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pcmpistri"));
        assert!(has_reg_write(&ctx.effects, "ecx"));
        // All flags clobbered
        assert!(has_reg_write(&ctx.effects, "zf"));
        assert!(has_reg_write(&ctx.effects, "cf"));
    }

    #[test]
    fn pcmpistrm_emits_sse42_intrinsic_and_xmm0() {
        // PCMPISTRM xmm0, xmm1, 0x00  →  66 0F 3A 62 C1 00
        let instr = decode64(&[0x66, 0x0F, 0x3A, 0x62, 0xC1, 0x00]);
        let mut ctx = ctx64();
        lift_pcmpstr(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pcmpistrm"));
        assert!(has_reg_write(&ctx.effects, "xmm0"));
    }

    // ── lift_mxcsr tests ──────────────────────────────────────────────────────

    #[test]
    fn ldmxcsr_writes_mxcsr_reg() {
        // LDMXCSR [rsp]  →  0F AE 14 24
        let instr = decode64(&[0x0F, 0xAE, 0x14, 0x24]);
        let mut ctx = ctx64();
        lift_mxcsr(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "ldmxcsr"));
        assert!(has_reg_write(&ctx.effects, "mxcsr"));
    }

    // ── Multiple-effects sanity: no handler leaves ctx empty ─────────────────

    #[test]
    fn all_handlers_produce_at_least_one_effect() {
        type HandlerCase<'a> = (
            &'a [u8],
            fn(&iced_x86::Instruction, &mut X86LiftCtx) -> Result<(), LiftError>,
        );
        let cases: &[HandlerCase<'_>] = &[
            // addps xmm0,xmm1
            (&[0x0F, 0x58, 0xC1], lift_sse_arith),
            // andps xmm0,xmm1
            (&[0x0F, 0x54, 0xC1], lift_sse_logic),
            // comiss xmm0,xmm1
            (&[0x0F, 0x2F, 0xC1], lift_sse_cmp),
            // shufps xmm0,xmm1,0
            (&[0x0F, 0xC6, 0xC1, 0x00], lift_sse_shuffle),
            // paddb xmm0,xmm1
            (&[0x66, 0x0F, 0xFC, 0xC1], lift_simd_int),
            // movaps xmm0,xmm1
            (&[0x0F, 0x28, 0xC1], lift_sse_mov),
        ];
        for (bytes, handler) in cases {
            let instr = decode64(bytes);
            let mut ctx = ctx64();
            let _ = handler(&instr, &mut ctx);
            assert!(
                !ctx.is_empty(),
                "handler produced no effects for bytes {bytes:?}"
            );
        }
    }
}
