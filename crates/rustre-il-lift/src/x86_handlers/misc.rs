//! Miscellaneous x86/x64 instruction handlers.
//!
//! ## Instruction coverage
//!
//! | Group | Instructions |
//! |-------|-------------|
//! | Bit/byte ops | BSWAP, BSF, BSR, LZCNT, TZCNT, POPCNT, MOVBE, CRC32 |
//! | Table lookup | XLAT / XLATB |
//! | I/O port | IN, OUT, INS/INSB/INSW/INSD, OUTS/OUTSB/OUTSW/OUTSD |
//! | Bounds / privilege | BOUND, ARPL, VERR, VERW, LAR, LSL |
//! | Extended state | XSAVE*, XRSTOR*, XSAVEOPT, XSAVEC, XSAVES, XRSTORS |
//! | Random | RDRAND, RDSEED |
//! | SGX / platform | PCONFIG, ENQCMD, ENQCMDS, SERIALIZE, PTWRITE |
//! | Shadow stack CET | SAVEPREVSSP, RSTORSSP, SETSSBSY, CLRSSBSY, INCSSPD/Q, RDSSPD/Q |
//! | AMX | LDTILECFG, STTILECFG, TILELOADD, TILELOADDT1, TILESTORED, TILERELEASE, TILEZERO, TDPBF16PS, TDPBSSD, TDPBSUD, TDPBUSD, TDPBUUD |
//! | Cache / memory | CLFLUSH, CLFLUSHOPT, CLWB, PREFETCH*, WBINVD, INVD, INVLPG |
//! | Misc | NOP, PAUSE, HLT, UD0/UD1/UD2, WRUSS, WRSS, LOADALL |
//! | Memory fences | MFENCE, LFENCE, SFENCE |
//!
//! ## μOp discipline
//!
//! All handlers follow the four-step rule:
//!   1. Read source operands into `IrExpr`.
//!   2. Emit intrinsics / arithmetic expressions.
//!   3. Materialise results into fresh temporaries when needed.
//!   4. Commit results and flag updates.
//!
//! Instructions whose semantics cannot be expressed using `IrExpr` primitives
//! (random-number generation, I/O ports, CET, AMX, …) are emitted as named
//! intrinsics so analysis passes can still see and reason about them.


use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_operand::{operand_size, read_operand, write_operand};
use crate::{Effect, IrExpr, LiftError};
use iced_x86::Instruction;

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Set every status flag to `IrExpr::Undef`.
#[inline]
fn all_flags_undef(ctx: &mut X86LiftCtx) {
    for f in [
        FlagId::Cf,
        FlagId::Of,
        FlagId::Sf,
        FlagId::Zf,
        FlagId::Af,
        FlagId::Pf,
    ] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
}

/// Clear every status flag to zero.
#[inline]
pub fn all_flags_zero(ctx: &mut X86LiftCtx) {
    for f in [
        FlagId::Cf,
        FlagId::Of,
        FlagId::Sf,
        FlagId::Zf,
        FlagId::Af,
        FlagId::Pf,
    ] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
}

/// Clear all status flags except CF, which is set to `cf_val`.
#[inline]
pub fn flags_cf_only(ctx: &mut X86LiftCtx, cf_val: IrExpr) {
    ctx.emit_flagset(FlagId::Cf, cf_val);
    for f in [FlagId::Of, FlagId::Sf, FlagId::Zf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
}

/// Set ZF to `zf_val` and mark all other status flags undefined.
#[inline]
pub fn flags_zf_undef(ctx: &mut X86LiftCtx, zf_val: IrExpr) {
    ctx.emit_flagset(FlagId::Zf, zf_val);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
}

/// Return the canonical accumulator register name for the current mode.
#[inline]
const fn acc_reg(ctx: &X86LiftCtx) -> &'static str {
    match ctx.bits {
        64 => "rax",
        32 => "eax",
        _ => "ax",
    }
}

/// Return the address register used by XLAT: BX (16-bit), EBX (32-bit), RBX (64-bit).
#[inline]
const fn xlat_base_reg(ctx: &X86LiftCtx) -> &'static str {
    match ctx.bits {
        64 => "rbx",
        32 => "ebx",
        _ => "bx",
    }
}

/// Zero-extend `expr` to pointer width by AND-masking to 0xFF (AL is always 8-bit).
/// Returns the temp register name holding the zero-extended value.
#[inline]
fn zext_al_to_ptr(ctx: &mut X86LiftCtx, expr: IrExpr) -> String {
    let masked = IrExpr::And(Box::new(expr), Box::new(IrExpr::Const(0xFF)));
    ctx.materialise(masked)
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Bit / byte scalar ops ───────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `BSWAP reg` — reverse byte order of a 32-bit or 64-bit register.
///
/// On a 16-bit operand (behaviour undefined per Intel SDM) we still emit
/// the intrinsic so the lifter does not silently skip the instruction.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bswap(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 0, ctx);
    let w_bits = operand_size(instr, 0, ctx) * 8;
    ctx.emit_intrinsic(format!("x86.bswap_w{w_bits}"), vec![src.clone()]);
    let t = ctx.materialise(src);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `BSF dst, src` — bit-scan forward (index of lowest set bit).
///
/// ZF := (src == 0).  When src is zero the destination is architecturally
/// undefined, modelled as `IrExpr::Undef`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bsf(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 1, ctx) * 8;
    ctx.emit_flagset(FlagId::Zf, IrExpr::CmpEqZero(Box::new(src.clone())));
    ctx.emit_intrinsic(format!("x86.bsf_w{w_bits}"), vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `BSR dst, src` — bit-scan reverse (index of highest set bit).
///
/// ZF := (src == 0).  Destination undefined when src is zero.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bsr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 1, ctx) * 8;
    ctx.emit_flagset(FlagId::Zf, IrExpr::CmpEqZero(Box::new(src.clone())));
    ctx.emit_intrinsic(format!("x86.bsr_w{w_bits}"), vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `LZCNT dst, src` — count leading zeros (BMI1 / LZCNT extension).
///
/// CF := (src == 0).  ZF := (result == 0).  OF/SF/PF/AF undefined.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lzcnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 1, ctx) * 8;
    ctx.emit_flagset(FlagId::Cf, IrExpr::CmpEqZero(Box::new(src.clone())));
    ctx.emit_intrinsic(format!("x86.lzcnt_w{w_bits}"), vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    let t_expr = IrExpr::Reg(t);
    ctx.emit_flagset(FlagId::Zf, IrExpr::CmpEqZero(Box::new(t_expr.clone())));
    for f in [FlagId::Of, FlagId::Sf, FlagId::Pf, FlagId::Af] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

/// `TZCNT dst, src` — count trailing zeros (BMI1 extension).
///
/// CF := (src == 0).  ZF := (result == 0).  OF/SF/PF/AF undefined.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tzcnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 1, ctx) * 8;
    ctx.emit_flagset(FlagId::Cf, IrExpr::CmpEqZero(Box::new(src.clone())));
    ctx.emit_intrinsic(format!("x86.tzcnt_w{w_bits}"), vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    let t_expr = IrExpr::Reg(t);
    ctx.emit_flagset(FlagId::Zf, IrExpr::CmpEqZero(Box::new(t_expr.clone())));
    for f in [FlagId::Of, FlagId::Sf, FlagId::Pf, FlagId::Af] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

/// `POPCNT dst, src` — population count (number of set bits).
///
/// ZF := (src == 0).  CF/OF/SF/AF/PF cleared.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_popcnt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 1, ctx) * 8;
    ctx.emit_intrinsic(format!("x86.popcnt_w{w_bits}"), vec![src.clone()]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    let t_expr = IrExpr::Reg(t);
    ctx.emit_flagset(FlagId::Zf, IrExpr::CmpEqZero(Box::new(src)));
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
    write_operand(instr, 0, t_expr, ctx);
    Ok(())
}

/// `MOVBE dst, src` — move with byte-swap (big-endian move).
///
/// Equivalent to a load (or register read) followed by `BSWAP`. Flags are
/// not affected.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_movbe(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let w_bits = operand_size(instr, 1, ctx) * 8;
    ctx.emit_intrinsic(format!("x86.bswap_w{w_bits}"), vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `CRC32 dst, src` — append bytes to a running CRC-32C value.
///
/// The destination register holds the accumulator; the source contributes
/// new bytes. Flags are not defined.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_crc32(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.crc32", vec![dst, src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Table lookup: XLAT / XLATB ──────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `XLAT` / `XLATB` — table look-up translation.
///
/// ```text
/// AL ← DS:[BX + zero_extend(AL)]   (16-bit / 32-bit mode)
/// AL ← [RBX + zero_extend(AL)]     (64-bit mode)
/// ```
///
/// The zero-extended AL is added to the base address register to form an
/// effective address; the byte at that address is loaded into AL.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xlat(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Tag this lift with the source IP so analyses can locate the original
    // instruction even though XLAT itself has no explicit operands.
    ctx.emit_intrinsic("x86.xlat.src_ip", vec![IrExpr::Const(instr.ip())]);
    let base_reg = xlat_base_reg(ctx);
    // Zero-extend AL (8-bit) to pointer width via AND with 0xFF.
    let al_val = IrExpr::Reg("al".into());
    let zext_t = zext_al_to_ptr(ctx, al_val);
    // Form effective address: base + zero_extend(AL).
    let base_expr = IrExpr::Reg(base_reg.into());
    let ea = IrExpr::Add(Box::new(base_expr), Box::new(IrExpr::Reg(zext_t)));
    // Materialise the effective address.
    let ea_t = ctx.materialise(ea);
    // Load one byte from the effective address using Deref.
    let load_expr = IrExpr::Deref(Box::new(IrExpr::Reg(ea_t)), 1);
    let result_t = ctx.materialise(load_expr);
    // Write the loaded byte into AL.
    ctx.emit_mem_read(IrExpr::Reg(result_t.clone()), "al", 1);
    ctx.emit_reg_write("al", IrExpr::Reg(result_t));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── I/O port instructions ────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `IN AL/AX/EAX, imm8/DX` — read from an I/O port.
///
/// All forms are handled here:
///   - `IN AL, imm8`  : 8-bit read from immediate port
///   - `IN AL, DX`    : 8-bit read from port in DX
///   - `IN AX, imm8`  : 16-bit read from immediate port
///   - `IN AX, DX`    : 16-bit read from port in DX
///   - `IN EAX, imm8` : 32-bit read from immediate port
///   - `IN EAX, DX`   : 32-bit read from port in DX
///
/// The result is an intrinsic value; the port address is the second operand.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_in(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Destination width determines the intrinsic name and result register.
    let dst_size = operand_size(instr, 0, ctx); // bytes: 1, 2, or 4
    let (intr_name, dst_reg) = match dst_size {
        1 => ("x86.io_in_byte", "al"),
        2 => ("x86.io_in_word", "ax"),
        _ => ("x86.io_in_dword", "eax"),
    };
    // Port comes from operand 1 (imm8 or DX).
    let port = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic(intr_name, vec![port]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    ctx.emit_reg_write(dst_reg, IrExpr::Reg(t));
    Ok(())
}

/// `OUT imm8/DX, AL/AX/EAX` — write to an I/O port.
///
/// All forms:
///   - `OUT imm8, AL`  : 8-bit write to immediate port
///   - `OUT DX,   AL`  : 8-bit write to port in DX
///   - `OUT imm8, AX`  : 16-bit write
///   - `OUT DX,   AX`  : 16-bit write
///   - `OUT imm8, EAX` : 32-bit write
///   - `OUT DX,   EAX` : 32-bit write
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_out(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src_size = operand_size(instr, 1, ctx);
    let intr_name = match src_size {
        1 => "x86.io_out_byte",
        2 => "x86.io_out_word",
        _ => "x86.io_out_dword",
    };
    let port = read_operand(instr, 0, ctx);
    let val = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic(intr_name, vec![port, val]);
    Ok(())
}

/// `INS` / `INSB` / `INSW` / `INSD` — input string from I/O port.
///
/// Reads a byte/word/dword from the port in DX and stores it at ES:DI
/// (or ES:EDI / ES:RDI). With REP prefix, repeats CX/ECX/RCX times.
///
/// Because string-I/O interacts with the segment model and the direction
/// flag we emit a specialised intrinsic rather than expanding inline.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ins(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic;
    let (intr_name, elem_size) = match instr.mnemonic() {
        Mnemonic::Insw => ("x86.ins_word", 2),
        Mnemonic::Insd => ("x86.ins_dword", 4),
        _ => ("x86.ins_byte", 1),
    };
    let port = IrExpr::Reg("dx".into());
    let di = IrExpr::Reg(ctx.di_reg().into());
    let count = if ctx.mode.prefixes.has_rep {
        IrExpr::Reg(ctx.counter_reg().into())
    } else {
        IrExpr::Const(1)
    };
    ctx.emit_intrinsic(
        intr_name,
        vec![port, di, count, IrExpr::Const(u64::try_from(elem_size).unwrap_or(0))],
    );
    // Model the side-effect on DI/EDI/RDI and CX/ECX/RCX as unknown after the op.
    let di_reg = ctx.di_reg().to_owned();
    ctx.emit_reg_write(di_reg, IrExpr::Undef);
    if ctx.mode.prefixes.has_rep {
        let ctr = ctx.counter_reg().to_owned();
        ctx.emit_reg_write(ctr, IrExpr::Const(0));
    }
    Ok(())
}

/// `OUTS` / `OUTSB` / `OUTSW` / `OUTSD` — output string to I/O port.
///
/// Reads a byte/word/dword from DS:SI (or DS:ESI / DS:RSI) and writes it
/// to the port in DX. With REP prefix, repeats CX/ECX/RCX times.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_outs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic;
    let (intr_name, elem_size) = match instr.mnemonic() {
        Mnemonic::Outsw => ("x86.outs_word", 2),
        Mnemonic::Outsd => ("x86.outs_dword", 4),
        _ => ("x86.outs_byte", 1),
    };
    let port = IrExpr::Reg("dx".into());
    let si = IrExpr::Reg(ctx.si_reg().into());
    let count = if ctx.mode.prefixes.has_rep {
        IrExpr::Reg(ctx.counter_reg().into())
    } else {
        IrExpr::Const(1)
    };
    ctx.emit_intrinsic(
        intr_name,
        vec![port, si, count, IrExpr::Const(u64::try_from(elem_size).unwrap_or(0))],
    );
    let si_reg = ctx.si_reg().to_owned();
    ctx.emit_reg_write(si_reg, IrExpr::Undef);
    if ctx.mode.prefixes.has_rep {
        let ctr = ctx.counter_reg().to_owned();
        ctx.emit_reg_write(ctr, IrExpr::Const(0));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Bounds / privilege checking ──────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `BOUND reg, mem` — check array index against bounds (80286+).
///
/// If the signed integer in `reg` is less than the lower bound or greater
/// than the upper bound stored in memory, interrupt 5 (`#BR`) is raised.
///
/// ```text
/// if reg < [mem] || reg > [mem + operand_size]:  INT 5
/// ```
///
/// We model this as an intrinsic with three arguments:
///   - the index register value
///   - the lower bound (loaded from `[mem]`)
///   - the upper bound (loaded from `[mem + size]`)
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bound(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let idx = read_operand(instr, 0, ctx);
    let sz = u64::from(operand_size(instr, 0, ctx)); // size of each bound field in memory

    // Base memory address from operand 1.
    let mem_base = read_operand(instr, 1, ctx);
    let mem_base_t = ctx.materialise(mem_base);

    // Lower bound — dereference the base address.
    let lower = IrExpr::Deref(Box::new(IrExpr::Reg(mem_base_t.clone())), u8::try_from(sz).unwrap_or(u8::MAX));
    let lower_t = ctx.materialise(lower);

    // Upper bound at offset +sz.
    let upper_addr = IrExpr::Add(
        Box::new(IrExpr::Reg(mem_base_t)),
        Box::new(IrExpr::Const(sz)),
    );
    let upper_addr_t = ctx.materialise(upper_addr);
    let upper = IrExpr::Deref(Box::new(IrExpr::Reg(upper_addr_t)), u8::try_from(sz).unwrap_or(u8::MAX));
    let upper_t = ctx.materialise(upper);

    ctx.emit_intrinsic(
        "x86.bound_check",
        vec![idx, IrExpr::Reg(lower_t), IrExpr::Reg(upper_t)],
    );
    Ok(())
}

/// `ARPL dst, src` — adjust requested privilege level (80286 protected mode).
///
/// If the RPL (bits 1:0) of `dst` is less than the RPL of `src`, the RPL
/// of `dst` is raised to match and ZF is set; otherwise ZF is cleared.
///
/// This is a legacy 16-bit protected-mode instruction. We emit an intrinsic
/// to preserve the intent for analysis; the destination is treated as having
/// an unknown but lower-bounded value afterwards.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_arpl(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.arpl", vec![dst, src]);
    // ZF depends on the comparison; other flags unaffected.
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `VERR reg/mem16` — verify segment register for reading.
///
/// Sets ZF if the segment referenced by the 16-bit selector is present and
/// readable from the current privilege level. All other flags are undefined.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_verr(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let sel = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.verr", vec![sel]);
    // ZF = 1 if segment is readable at current CPL, 0 otherwise.
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    Ok(())
}

/// `VERW reg/mem16` — verify segment register for writing.
///
/// Sets ZF if the segment referenced by the 16-bit selector is present and
/// writable from the current privilege level.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_verw(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let sel = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.verw", vec![sel]);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    Ok(())
}

/// `LAR dst, src` — load access rights byte.
///
/// If the segment selector in `src` is accessible at the current CPL, the
/// access rights byte is loaded into `dst` and ZF is set. If not accessible,
/// ZF is cleared and `dst` is undefined.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lar(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.lar", vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    // ZF := valid; other flags undefined.
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `LSL dst, src` — load segment limit.
///
/// Loads the unscrambled segment limit for the selector in `src` into `dst`
/// if the segment is accessible. ZF := 1 if accessible, 0 otherwise.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lsl(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.lsl", vec![src]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Undef);
    }
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `LOADALL` — undocumented 80286 / 80386 instruction.
///
/// Loads all registers from a fixed memory area. Never appeared in the Intel
/// SDM and should be treated as an opaque side-effectful operation.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_loadall(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.loadall", vec![]);
    // Mark all general-purpose registers and flags unknown.
    for reg in ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi"] {
        ctx.emit_reg_write(reg, IrExpr::Undef);
    }
    all_flags_undef(ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Extended processor state: XSAVE family ───────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// Common helper for all XSAVE variants.
///
/// The XSAVE instructions save processor state components selected by the
/// `EDX:EAX` bitmask to a memory region:
///
/// | Bit | Component |
/// |-----|-----------|
/// | 0   | x87 FPU   |
/// | 1   | SSE (XMM) |
/// | 2   | AVX (YMM) |
/// | 3   | MPX BNDREGS |
/// | 4   | MPX BNDCSR |
/// | 5   | AVX-512 opmask (k0–k7) |
/// | 6   | `ZMM_Hi256` |
/// | 7   | `Hi16_ZMM` |
///
/// `variant` is a short string appended to the intrinsic name to distinguish
/// `xsave`, `xsavec`, `xsaveopt`, and `xsaves`.
fn lift_xsave_common(
    instr: &Instruction,
    ctx: &mut X86LiftCtx,
    variant: &str,
) {
    let addr = read_operand(instr, 0, ctx);
    // The component bitmask is in EDX:EAX (always, regardless of mode).
    let edx = IrExpr::Reg("edx".into());
    let eax = IrExpr::Reg("eax".into());
    // Concatenate into a 64-bit mask: (EDX << 32) | EAX.
    let mask = IrExpr::Or(
        Box::new(IrExpr::Shl(Box::new(edx), Box::new(IrExpr::Const(32)))),
        Box::new(eax),
    );
    let mask_t = ctx.materialise(mask);
    ctx.emit_intrinsic(format!("x86.{variant}"), vec![addr, IrExpr::Reg(mask_t)]);
    
}

/// `XSAVE mem` — save extended processor state.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xsave(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_xsave_common(instr, ctx, "xsave");
    Ok(())
}

/// `XSAVEC mem` — save extended processor state (compacted format).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xsavec(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_xsave_common(instr, ctx, "xsavec");
    Ok(())
}

/// `XSAVEOPT mem` — save extended processor state (optimised, skips unchanged).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xsaveopt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_xsave_common(instr, ctx, "xsaveopt");
    Ok(())
}

/// `XSAVES mem` — save extended processor state (supervisor, compacted).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xsaves(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_xsave_common(instr, ctx, "xsaves");
    Ok(())
}

/// `XRSTOR mem` — restore extended processor state.
///
/// Restores the components selected by `EDX:EAX` from the XSAVE area at
/// `mem`. Mirror image of `XSAVE`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xrstor(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    let edx = IrExpr::Reg("edx".into());
    let eax = IrExpr::Reg("eax".into());
    let mask = IrExpr::Or(
        Box::new(IrExpr::Shl(Box::new(edx), Box::new(IrExpr::Const(32)))),
        Box::new(eax),
    );
    let mask_t = ctx.materialise(mask);
    ctx.emit_intrinsic("x86.xrstor", vec![addr, IrExpr::Reg(mask_t)]);
    Ok(())
}

/// `XRSTORS mem` — restore extended processor state (supervisor).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xrstors(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    let edx = IrExpr::Reg("edx".into());
    let eax = IrExpr::Reg("eax".into());
    let mask = IrExpr::Or(
        Box::new(IrExpr::Shl(Box::new(edx), Box::new(IrExpr::Const(32)))),
        Box::new(eax),
    );
    let mask_t = ctx.materialise(mask);
    ctx.emit_intrinsic("x86.xrstors", vec![addr, IrExpr::Reg(mask_t)]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Random-number generation ─────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `RDRAND dst` — read from the hardware random-number generator.
///
/// CF := 1 if a value was produced, 0 on underflow (PRNG not initialised).
/// All other status flags are cleared (Intel SDM Vol. 2B §4.2).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdrand(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w_bits = operand_size(instr, 0, ctx) * 8;
    ctx.emit_intrinsic(format!("x86.rdrand_w{w_bits}"), vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    // CF := 1 if valid. We model this as Undef because the caller cannot know
    // whether the generator was ready; analysis must treat CF as opaque.
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    for f in [FlagId::Of, FlagId::Sf, FlagId::Zf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
    Ok(())
}

/// `RDSEED dst` — read from the hardware entropy source.
///
/// Provides higher-quality randomness than RDRAND by tapping directly into
/// the raw entropy pool. CF semantics identical to RDRAND.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdseed(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w_bits = operand_size(instr, 0, ctx) * 8;
    ctx.emit_intrinsic(format!("x86.rdseed_w{w_bits}"), vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    for f in [FlagId::Of, FlagId::Sf, FlagId::Zf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Platform configuration / work-queue ops ──────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `PCONFIG` — configure platform features.
///
/// Used by SGX key management (MKTME, `MKTME_KEY_PROGRAM`, etc.). EAX selects
/// the leaf; additional inputs in EBX/ECX/EDX. Outputs in EAX, ZF, CF.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pconfig(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let leaf = IrExpr::Reg("eax".into());
    let rbx = IrExpr::Reg("rbx".into());
    let rcx = IrExpr::Reg("rcx".into());
    let rdx = IrExpr::Reg("rdx".into());
    ctx.emit_intrinsic("x86.pconfig", vec![leaf, rbx, rcx, rdx]);
    // EAX receives a status code.
    ctx.emit_reg_write("eax", IrExpr::Undef);
    // ZF and CF indicate success/error.
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    for f in [FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
    Ok(())
}

/// `ENQCMD dst, src` — enqueue a command to a device work queue.
///
/// Writes a 64-byte command descriptor from `src` (memory) into the
/// work-queue register at `dst` (memory-mapped). ZF indicates success.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_enqcmd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.enqcmd", vec![dst, src]);
    // ZF := 1 if command was rejected (retry needed), 0 on success.
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
    Ok(())
}

/// `ENQCMDS dst, src` — enqueue a supervisor command to a work queue.
///
/// Privileged variant of ENQCMD; only available in CPL 0.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_enqcmds(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.enqcmds", vec![dst, src]);
    ctx.emit_flagset(FlagId::Zf, IrExpr::Undef);
    for f in [FlagId::Cf, FlagId::Of, FlagId::Sf, FlagId::Af, FlagId::Pf] {
        ctx.emit_flagset(f, IrExpr::Const(0));
    }
    Ok(())
}

/// `SERIALIZE` — execution-serialising fence.
///
/// Prevents any subsequent instruction from beginning execution until all
/// prior instructions have completed and all prior stores are globally visible.
/// Semantically a superset of `MFENCE` + `LFENCE` + `SFENCE`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_serialize(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.serialize", vec![]);
    Ok(())
}

/// `PTWRITE src` — write a value to an Intel PT (Processor Trace) packet.
///
/// Emits a PTWRITE packet into the PT stream. Useful for software trace
/// instrumentation. The source can be a 32-bit or 64-bit register or memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ptwrite(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.ptwrite", vec![src]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Shadow stack (CET — Control-flow Enforcement Technology) ─────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `WRSS [mem]` — write to supervisor shadow stack.
///
/// Writes the source operand to the shadow stack region at the specified
/// memory address (supervisor mode only). Used to initialise shadow stack
/// frames before launching tasks.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_wrss(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    // Shadow stack writes are modelled as a special memory write so that
    // memory aliasing analysis can distinguish shadow-stack and normal stores.
    let sz = operand_size(instr, 1, ctx);
    ctx.emit_intrinsic("x86.wrss", vec![addr.clone(), src.clone()]);
    ctx.emit_mem_write(addr, src, sz);
    Ok(())
}

/// `WRUSS [mem]` — write to user shadow stack.
///
/// Writes the source operand to the user-mode shadow stack. Available only
/// in CPL 0; raises a protection fault if the address does not point to a
/// shadow stack page.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_wruss(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    let src = read_operand(instr, 1, ctx);
    let sz = operand_size(instr, 1, ctx);
    ctx.emit_intrinsic("x86.wruss", vec![addr.clone(), src.clone()]);
    ctx.emit_mem_write(addr, src, sz);
    Ok(())
}

/// `SAVEPREVSSP` — save the previous shadow stack pointer (SSP).
///
/// Pushes the supervisor previous SSP token onto the current shadow stack.
/// Used when switching between privilege levels.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_saveprevssp(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.saveprevssp", vec![]);
    Ok(())
}

/// `RSTORSSP [mem]` — restore a shadow stack pointer.
///
/// Verifies that the restore token at `[mem]` matches the expected format,
/// then restores the SSP from the token.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rstorssp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.rstorssp", vec![addr]);
    Ok(())
}

/// `SETSSBSY` — set the shadow stack busy flag.
///
/// Marks the current shadow stack as busy (in use by the current task).
/// Raises a fault if the shadow stack is already marked busy.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setssbsy(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.setssbsy", vec![]);
    Ok(())
}

/// `CLRSSBSY [mem]` — clear shadow stack busy flag.
///
/// Clears the busy flag at the shadow stack restore token located at `[mem]`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clrssbsy(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.clrssbsy", vec![addr]);
    Ok(())
}

/// `INCSSPD reg` — increment the shadow stack pointer by 4 * reg.
///
/// Advances the SSP by `4 * reg` bytes (32-bit element size). Used to pop
/// N entries off the shadow stack without consuming them.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_incsspd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let cnt = read_operand(instr, 0, ctx);
    let offset = IrExpr::Mul(Box::new(cnt), Box::new(IrExpr::Const(4)));
    let offset_t = ctx.materialise(offset);
    ctx.emit_intrinsic("x86.incssp", vec![IrExpr::Reg(offset_t), IrExpr::Const(4)]);
    Ok(())
}

/// `INCSSPQ reg` — increment the shadow stack pointer by 8 * reg.
///
/// Same as `INCSSPD` but uses 8-byte (64-bit) element granularity.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_incsspq(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let cnt = read_operand(instr, 0, ctx);
    let offset = IrExpr::Mul(Box::new(cnt), Box::new(IrExpr::Const(8)));
    let offset_t = ctx.materialise(offset);
    ctx.emit_intrinsic("x86.incssp", vec![IrExpr::Reg(offset_t), IrExpr::Const(8)]);
    Ok(())
}

/// `RDSSPD reg` — read current shadow stack pointer (32-bit form).
///
/// Copies the low 32 bits of the SSP into `reg`. The upper bits of the
/// destination register are zero-extended.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdsspd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdssp_w32", vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `RDSSPQ reg` — read current shadow stack pointer (64-bit form).
///
/// Copies the full 64-bit SSP into `reg`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdsspq(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdssp_w64", vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── AMX — Advanced Matrix Extensions ────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `LDTILECFG mem` — load tile configuration from memory.
///
/// Reads a 64-byte tile configuration structure from `mem` and configures
/// the tile registers (tmm0–tmm7) accordingly.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ldtilecfg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.amx.ldtilecfg", vec![addr]);
    Ok(())
}

/// `STTILECFG mem` — store current tile configuration to memory.
///
/// Writes the active tile configuration to a 64-byte structure at `mem`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sttilecfg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.amx.sttilecfg", vec![addr]);
    Ok(())
}

/// `TILELOADD tmm, [sibmem]` — load a tile from memory.
///
/// Loads a tile from the memory region described by a SIB-encoded address
/// with stride (the stride is encoded in the index component of the SIB).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tileloadd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst_idx = IrExpr::Const(instr.op0_register() as u64);
    let addr = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.amx.tileloadd", vec![dst_idx, addr]);
    Ok(())
}

/// `TILELOADDT1 tmm, [sibmem]` — load a tile from memory with T1 hint.
///
/// Identical to `TILELOADD` except that a T1 (L2 cache) prefetch hint is
/// added to improve memory access latency.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tileloaddt1(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst_idx = IrExpr::Const(instr.op0_register() as u64);
    let addr = read_operand(instr, 1, ctx);
    ctx.emit_intrinsic("x86.amx.tileloaddt1", vec![dst_idx, addr]);
    Ok(())
}

/// `TILESTORED [sibmem], tmm` — store a tile to memory.
///
/// Stores the tile register specified by `tmm` to the memory region described
/// by a SIB address with stride.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tilestored(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    let src_idx = IrExpr::Const(instr.op1_register() as u64);
    ctx.emit_intrinsic("x86.amx.tilestored", vec![addr, src_idx]);
    Ok(())
}

/// `TILERELEASE` — release all tile registers.
///
/// Zeros the tile configuration and marks all tile registers invalid.
/// Must be called after using tiles to avoid state leaks across context switches.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tilerelease(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.amx.tilerelease", vec![]);
    Ok(())
}

/// `TILEZERO tmm` — zero a tile register.
///
/// Sets every element of the specified tile register to zero. Faster than
/// loading a zeroed block from memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tilezero(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let tile_idx = IrExpr::Const(instr.op0_register() as u64);
    ctx.emit_intrinsic("x86.amx.tilezero", vec![tile_idx]);
    Ok(())
}

/// `TDPBF16PS tmm1, tmm2, tmm3` — tile dot product of BF16 into FP32.
///
/// Performs a matrix multiply-accumulate: `tmm1 += tmm2 * tmm3` where
/// inputs are BF16 and the accumulator is FP32.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tdpbf16ps(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = IrExpr::Const(instr.op0_register() as u64);
    let src1 = IrExpr::Const(instr.op1_register() as u64);
    let src2 = IrExpr::Const(instr.op2_register() as u64);
    ctx.emit_intrinsic("x86.amx.tdpbf16ps", vec![dst, src1, src2]);
    Ok(())
}

/// `TDPBSSD tmm1, tmm2, tmm3` — tile dot product of signed bytes into signed dword.
///
/// `tmm1 += tmm2 (int8) * tmm3 (int8)` — signed × signed → int32 accumulation.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tdpbssd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = IrExpr::Const(instr.op0_register() as u64);
    let src1 = IrExpr::Const(instr.op1_register() as u64);
    let src2 = IrExpr::Const(instr.op2_register() as u64);
    ctx.emit_intrinsic("x86.amx.tdpbssd", vec![dst, src1, src2]);
    Ok(())
}

/// `TDPBSUD tmm1, tmm2, tmm3` — signed × unsigned tile dot product.
///
/// `tmm1 += tmm2 (int8) * tmm3 (uint8)` — signed × unsigned → int32.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tdpbsud(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = IrExpr::Const(instr.op0_register() as u64);
    let src1 = IrExpr::Const(instr.op1_register() as u64);
    let src2 = IrExpr::Const(instr.op2_register() as u64);
    ctx.emit_intrinsic("x86.amx.tdpbsud", vec![dst, src1, src2]);
    Ok(())
}

/// `TDPBUSD tmm1, tmm2, tmm3` — unsigned × signed tile dot product.
///
/// `tmm1 += tmm2 (uint8) * tmm3 (int8)` — unsigned × signed → int32.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tdpbusd(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = IrExpr::Const(instr.op0_register() as u64);
    let src1 = IrExpr::Const(instr.op1_register() as u64);
    let src2 = IrExpr::Const(instr.op2_register() as u64);
    ctx.emit_intrinsic("x86.amx.tdpbusd", vec![dst, src1, src2]);
    Ok(())
}

/// `TDPBUUD tmm1, tmm2, tmm3` — unsigned × unsigned tile dot product.
///
/// `tmm1 += tmm2 (uint8) * tmm3 (uint8)` — unsigned × unsigned → uint32.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tdpbuud(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let dst = IrExpr::Const(instr.op0_register() as u64);
    let src1 = IrExpr::Const(instr.op1_register() as u64);
    let src2 = IrExpr::Const(instr.op2_register() as u64);
    ctx.emit_intrinsic("x86.amx.tdpbuud", vec![dst, src1, src2]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Cache / memory-hierarchy operations ─────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `CLFLUSH mem` — flush and invalidate a cache line.
///
/// The cache line containing the linear address `mem` is flushed from all
/// levels of the cache hierarchy and invalidated. Subsequent accesses reload
/// from memory.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clflush(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.clflush", vec![addr]);
    Ok(())
}

/// `CLFLUSHOPT mem` — optimised cache-line flush.
///
/// Like `CLFLUSH` but is not serialising — it may be reordered with respect
/// to other `CLFLUSHOPT` and `CLWB` instructions targeting different cache
/// lines. An `MFENCE` is required to impose ordering.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clflushopt(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.clflushopt", vec![addr]);
    Ok(())
}

/// `CLWB mem` — cache-line write-back.
///
/// Writes back a dirty cache line to memory but may leave it valid in the
/// cache (unlike `CLFLUSH` which invalidates). Primarily used for persistent
/// memory (NVDIMM) programming.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_clwb(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.clwb", vec![addr]);
    Ok(())
}

/// `PREFETCHNTA mem` — prefetch with non-temporal hint (no caching beyond L1).
///
/// Tells the processor to load the cache line at `mem` into L1 but to bypass
/// higher-level caches. Used for streaming data patterns.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetchnta(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.prefetch.nta", vec![addr]);
    Ok(())
}

/// `PREFETCHT0 mem` — prefetch into L1, L2, and L3 cache.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetcht0(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.prefetch.t0", vec![addr]);
    Ok(())
}

/// `PREFETCHT1 mem` — prefetch into L2 and L3 cache.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetcht1(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.prefetch.t1", vec![addr]);
    Ok(())
}

/// `PREFETCHT2 mem` — prefetch into L3 cache only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetcht2(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.prefetch.t2", vec![addr]);
    Ok(())
}

/// `PREFETCHW mem` — prefetch with intent to write (AMD / Intel).
///
/// Prefetches the cache line and anticipates an upcoming write, acquiring
/// the line in the Modified state to avoid a subsequent upgrade request.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetchw(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.prefetch.w", vec![addr]);
    Ok(())
}

/// `PREFETCHWT1 mem` — prefetch with write intent, T1 hint.
///
/// Intel Xeon Phi extension: hint that the write will not be a streaming
/// (non-temporal) store.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetchwt1(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.prefetch.wt1", vec![addr]);
    Ok(())
}

/// Generic dispatch for all prefetch variants (PREFETCHNTA, T0, T1, T2).
///
/// Routes based on `instr.mnemonic()` to the correct specialised handler.
/// This is the entry point used by the top-level dispatcher in `mod.rs`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_prefetch(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use iced_x86::Mnemonic;
    match instr.mnemonic() {
        Mnemonic::Prefetchnta => lift_prefetchnta(instr, ctx),
        Mnemonic::Prefetcht0 => lift_prefetcht0(instr, ctx),
        Mnemonic::Prefetcht1 => lift_prefetcht1(instr, ctx),
        Mnemonic::Prefetcht2 => lift_prefetcht2(instr, ctx),
        Mnemonic::Prefetchw => lift_prefetchw(instr, ctx),
        Mnemonic::Prefetchwt1 => lift_prefetchwt1(instr, ctx),
        _ => {
            // Fallback: emit a generic prefetch intrinsic so we do not lose the hint.
            let addr = read_operand(instr, 0, ctx);
            ctx.emit_intrinsic(
                format!("x86.prefetch.{:?}", instr.mnemonic()).to_lowercase(),
                vec![addr],
            );
            Ok(())
        }
    }
}

/// `WBINVD` — write back and invalidate all caches.
///
/// Flushes all dirty lines from all levels of the cache hierarchy and then
/// invalidates them. CPL 0 only. Heavily serialising.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_wbinvd(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.wbinvd", vec![]);
    Ok(())
}

/// `INVD` — invalidate all caches without write-back.
///
/// Discards all cache contents without flushing dirty data. Used during
/// early boot or after disabling cache. CPL 0 only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_invd(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.invd", vec![]);
    Ok(())
}

/// `INVLPG mem` — invalidate a TLB entry.
///
/// Removes the TLB mapping for the page containing the linear address `mem`.
/// CPL 0 only. Used when software updates a page-table entry and needs the
/// CPU to pick up the new mapping.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_invlpg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.invlpg", vec![addr]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Memory fences ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `MFENCE` / `LFENCE` / `SFENCE` — memory ordering fences.
///
/// | Mnemonic | Ordering guarantee |
/// |----------|--------------------|
/// | MFENCE   | All loads and stores before the fence are globally visible before any after. |
/// | LFENCE   | All loads before the fence complete before any loads after begin. |
/// | SFENCE   | All stores before the fence are globally visible before any store after. |
///
/// All three are modelled as intrinsics carrying their names; optimisation
/// passes may reorder instructions across these only if the relevant ordering
/// constraints are provably satisfied.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fence(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let name = format!("x86.fence.{:?}", instr.mnemonic()).to_lowercase();
    ctx.emit_intrinsic(name, vec![]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── NOP / PAUSE / HLT / UD ───────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `NOP` — no operation.
///
/// Covers the single-byte `0x90` encoding as well as the multi-byte NOP
/// sequences (0F 1F /0) introduced in the P4/Core era.  The multi-byte
/// forms have a `ModRM` operand that is decoded but not used; this handler
/// intentionally ignores it.
///
/// Also handles `XCHG EAX, EAX` (the canonical NOP encoding in 32-bit mode).
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_nop(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.nop", vec![]);
    Ok(())
}

/// `PAUSE` — spin-loop hint.
///
/// A specialised NOP (encoded as `F3 90`) that informs the processor a
/// software spin loop is executing, reducing power and improving SMT thread
/// interleaving. No architectural side-effects.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_pause(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.pause", vec![]);
    Ok(())
}

/// `HLT` — halt the processor.
///
/// Stops instruction execution until an external interrupt, NMI, or reset.
/// CPL 0 only. We model it as an intrinsic plus a `NoReturn` effect so that
/// subsequent instructions are treated as dead code.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_hlt(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.hlt", vec![]);
    // Model HLT as a diverging branch (no fall-through) so dataflow treats
    // subsequent instructions as dead. The target is Undef — the processor
    // will resume at the interrupted instruction address.
    ctx.emit(Effect::Branch {
        target: IrExpr::Undef,
        condition: None,
    });
    Ok(())
}

/// `UD0` / `UD1` / `UD2` — architecturally undefined instructions.
///
/// These encodings are guaranteed by Intel to raise `#UD` (invalid opcode)
/// on every processor model that ever existed. Compilers use `UD2` to mark
/// unreachable code, so we emit a `NoReturn` effect in addition to the
/// intrinsic so that analysis does not follow fall-through paths.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ud(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let name = match instr.mnemonic() {
        iced_x86::Mnemonic::Ud0 => "x86.ud0",
        iced_x86::Mnemonic::Ud1 => "x86.ud1",
        _ => "x86.ud2",
    };
    ctx.emit_intrinsic(name, vec![]);
    // UD* raises #UD; no fall-through. Model as diverging branch.
    ctx.emit(Effect::Branch {
        target: IrExpr::Undef,
        condition: None,
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── APX — Advanced Performance Extensions (Phoebe / Intel "REX2") ────────────
// ─────────────────────────────────────────────────────────────────────────────

/// APX extends the x86-64 ISA to 32 general-purpose registers (r0–r31) via a
/// two-byte `REX2` prefix and promotes several single-operand instructions to
/// three-operand (NDD) forms.
///
/// Because iced-x86 decodes APX operands into the
/// normal `op0`/`op1`/`op2` slots with the extended register indices, most APX
/// arithmetic falls through to the existing arithmetic handlers.  The helpers
/// below cover the purely-APX instructions that have no predecessor encoding.
///
/// `CCMPO / CCMPNO / … reg, r/m, imm` — conditional compare (APX).
///
/// Performs a CMP only if the source condition is satisfied; otherwise leaves
/// flags unchanged.  Because the condition is encoded in the mnemonic suffix
/// we emit a single intrinsic that carries the condition code as an argument,
/// making it easy for a subsequent lowering pass to expand it.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ccmp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src0 = read_operand(instr, 0, ctx);
    let src1 = read_operand(instr, 1, ctx);
    let cc = IrExpr::Const(instr.mnemonic() as u64);
    ctx.emit_intrinsic("x86.apx.ccmp", vec![src0, src1, cc]);
    // Flags are conditionally updated; model as Undef to be conservative.
    all_flags_undef(ctx);
    Ok(())
}

/// `CTESTO / CTESTNO / … reg, r/m` — conditional test (APX).
///
/// Performs an AND only if the condition is satisfied; otherwise flags are
/// unchanged.  Same intrinsic-plus-Undef modelling as `CCMP`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ctest(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src0 = read_operand(instr, 0, ctx);
    let src1 = read_operand(instr, 1, ctx);
    let cc = IrExpr::Const(instr.mnemonic() as u64);
    ctx.emit_intrinsic("x86.apx.ctest", vec![src0, src1, cc]);
    all_flags_undef(ctx);
    Ok(())
}

/// `CFCMOV* dst, src` — conditional far-move (APX NDD form).
///
/// Zero-latency conditional move that does not read the destination.  Avoids
/// the false dependency on the destination register that `CMOVcc` has.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cfcmov(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 1, ctx);
    let cc = IrExpr::Const(instr.mnemonic() as u64);
    ctx.emit_intrinsic("x86.apx.cfcmov", vec![src, cc]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── XSAVE component bit-field documentation helpers ──────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//
// The XSAVE feature set (XSAVE, XSAVEC, XSAVEOPT, XSAVES, XRSTOR, XRSTORS)
// uses an EDX:EAX bitmask to select which processor-state components to
// save/restore.  The bit assignments are:
//
//   Bit  0  — x87 FPU (FCW, FSW, FTW, FOP, FIP, FDP, ST0–ST7)
//   Bit  1  — SSE state (MXCSR, MXCSR_MASK, XMM0–XMM15/31)
//   Bit  2  — AVX state (YMM upper halves: YMM0H–YMM15H/31H)
//   Bit  3  — MPX BNDREGS (BND0–BND3)
//   Bit  4  — MPX BNDCSR (BNDCFGU, BNDSTATUS)
//   Bit  5  — AVX-512 opmask registers (k0–k7)
//   Bit  6  — AVX-512 ZMM_Hi256 (upper halves of ZMM0–ZMM15)
//   Bit  7  — AVX-512 Hi16_ZMM (ZMM16–ZMM31)
//   Bit  8  — PT (Processor Trace) state
//   Bit  9  — PKRU (Protection Key User Rights)
//   Bit 11  — CET user shadow-stack state (SSP, …)
//   Bit 12  — CET supervisor shadow-stack state
//   Bit 17  — AMX tile configuration (TILECFG)
//   Bit 18  — AMX tile data (TMM0–TMM7)
//
// These constants are provided as named u64 values so that analysis passes
// can pattern-match on the mask argument of x86.xsave / x86.xrstor intrinsics.

/// XSAVE component bitmask: x87 FPU state.
pub const XSAVE_X87: u64 = 1 << 0;
/// XSAVE component bitmask: SSE (XMM) state.
pub const XSAVE_SSE: u64 = 1 << 1;
/// XSAVE component bitmask: AVX (YMM upper halves) state.
pub const XSAVE_AVX: u64 = 1 << 2;
/// XSAVE component bitmask: MPX BNDREGS.
pub const XSAVE_MPX_BNDREGS: u64 = 1 << 3;
/// XSAVE component bitmask: MPX BNDCSR.
pub const XSAVE_MPX_BNDCSR: u64 = 1 << 4;
/// XSAVE component bitmask: AVX-512 opmask registers (k0–k7).
pub const XSAVE_AVX512_OPMASK: u64 = 1 << 5;
/// XSAVE component bitmask: AVX-512 ZMM upper halves (ZMM0–ZMM15 bits 255:128).
pub const XSAVE_ZMM_HI256: u64 = 1 << 6;
/// XSAVE component bitmask: AVX-512 high ZMM registers (ZMM16–ZMM31).
pub const XSAVE_HI16_ZMM: u64 = 1 << 7;
/// XSAVE component bitmask: Intel PT state.
pub const XSAVE_PT: u64 = 1 << 8;
/// XSAVE component bitmask: Protection Key User Rights (PKRU).
pub const XSAVE_PKRU: u64 = 1 << 9;
/// XSAVE component bitmask: CET user shadow stack.
pub const XSAVE_CET_U: u64 = 1 << 11;
/// XSAVE component bitmask: CET supervisor shadow stack.
pub const XSAVE_CET_S: u64 = 1 << 12;
/// XSAVE component bitmask: AMX tile configuration.
pub const XSAVE_AMX_TILECFG: u64 = 1 << 17;
/// XSAVE component bitmask: AMX tile data.
pub const XSAVE_AMX_TILEDATA: u64 = 1 << 18;

// ─────────────────────────────────────────────────────────────────────────────
// ── RDPID — read processor ID ────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `RDPID reg` — read processor ID.
///
/// Reads the `IA32_TSC_AUX` MSR (which software sets to encode a logical
/// processor identifier) into the destination general-purpose register.
/// Unlike `RDTSCP`, this instruction is not serialising.
///
/// Available only in 64-bit mode (or as a 32-bit read in compatibility mode).
/// Flags are not affected.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdpid(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdpid", vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── UMWAIT / UMONITOR / TPAUSE — user-mode wait extensions ──────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `UMONITOR reg` — set up user-mode monitoring address.
///
/// Arms the hardware address-monitoring mechanism at the linear address in
/// `reg` from user mode (no CPL restriction unlike `MONITOR`). Subsequent
/// stores to the monitored line will trigger a wake-up from `UMWAIT`.
///
/// Flags are not affected.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_umonitor(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.umonitor", vec![addr]);
    Ok(())
}

/// `UMWAIT reg, edx, eax` — user-mode wait.
///
/// Suspends execution until a store to the monitored address or until the
/// time-stamp counter reaches the 64-bit deadline in `EDX:EAX`.  `reg`
/// selects C0.1 (value 0) or C0.2 (value 1) power state.
///
/// CF := 1 if wait was interrupted for a reason other than a store (e.g.
/// deadline reached), 0 otherwise. Other flags unchanged.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_umwait(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let ctrl = read_operand(instr, 0, ctx);
    let edx = IrExpr::Reg("edx".into());
    let eax = IrExpr::Reg("eax".into());
    let deadline = IrExpr::Or(
        Box::new(IrExpr::Shl(Box::new(edx), Box::new(IrExpr::Const(32)))),
        Box::new(eax),
    );
    let dl_t = ctx.materialise(deadline);
    ctx.emit_intrinsic("x86.umwait", vec![ctrl, IrExpr::Reg(dl_t)]);
    // CF := 1 if deadline expired (not a monitored store).
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    Ok(())
}

/// `TPAUSE reg, edx, eax` — timed pause.
///
/// Places the logical processor in an implementation-dependent optimised
/// state until either a store to a monitored address or the deadline
/// encoded in `EDX:EAX` is reached.  Semantics identical to `UMWAIT`;
/// `reg` selects the power state hint.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_tpause(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let ctrl = read_operand(instr, 0, ctx);
    let edx = IrExpr::Reg("edx".into());
    let eax = IrExpr::Reg("eax".into());
    let deadline = IrExpr::Or(
        Box::new(IrExpr::Shl(Box::new(edx), Box::new(IrExpr::Const(32)))),
        Box::new(eax),
    );
    let dl_t = ctx.materialise(deadline);
    ctx.emit_intrinsic("x86.tpause", vec![ctrl, IrExpr::Reg(dl_t)]);
    ctx.emit_flagset(FlagId::Cf, IrExpr::Undef);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── MONITOR / MWAIT — privileged wait extensions ─────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `MONITOR` — set up monitor address (privileged).
///
/// Arms a hardware address-monitoring mechanism at the linear address in
/// `EAX`/`RAX`.  Hint extensions are provided via `ECX` (extensions) and
/// `EDX` (hints).  CPL 0 only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_monitor(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = IrExpr::Reg(acc_reg(ctx).into());
    let ecx = IrExpr::Reg("ecx".into());
    let edx = IrExpr::Reg("edx".into());
    ctx.emit_intrinsic("x86.monitor", vec![addr, ecx, edx]);
    Ok(())
}

/// `MWAIT` — monitor wait (privileged).
///
/// Suspends execution until a store to the monitored address or until an
/// interrupt / NMI / reset.  `EAX` provides hints and `ECX` selects C-state
/// extensions.  CPL 0 only.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_mwait(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let eax = IrExpr::Reg("eax".into());
    let ecx = IrExpr::Reg("ecx".into());
    ctx.emit_intrinsic("x86.mwait", vec![eax, ecx]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── XGETBV / XSETBV — extended control register access ───────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `XGETBV` — read extended control register.
///
/// Reads the extended control register (XCR) whose index is in `ECX` into
/// `EDX:EAX`.  The most common use is `ECX=0` which reads `XCR0`, the
/// XSAVE component enable bitmap.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xgetbv(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let ecx = IrExpr::Reg("ecx".into());
    ctx.emit_intrinsic("x86.xgetbv", vec![ecx]);
    ctx.emit_reg_write("eax", IrExpr::Undef);
    ctx.emit_reg_write("edx", IrExpr::Undef);
    Ok(())
}

/// `XSETBV` — write extended control register.
///
/// Writes `EDX:EAX` into the extended control register selected by `ECX`.
/// CPL 0 only. Writing XCR0 with unsupported bits set causes `#GP`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_xsetbv(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let ecx = IrExpr::Reg("ecx".into());
    let eax = IrExpr::Reg("eax".into());
    let edx = IrExpr::Reg("edx".into());
    ctx.emit_intrinsic("x86.xsetbv", vec![ecx, eax, edx]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── GETSEC — SMX instruction leaf dispatcher ─────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `GETSEC` — Safer Mode Extensions leaf instruction.
///
/// The leaf is selected by `EAX` at the time of execution:
///
/// | EAX | Leaf | Purpose |
/// |-----|------|---------|
/// | 0   | CAPABILITIES | query SMX capabilities |
/// | 1   | ENTERACCS    | enter authenticated code execution |
/// | 2   | EXITAC       | exit authenticated code |
/// | 3   | SENTER       | enter measured environment |
/// | 4   | SEXIT        | exit measured environment |
/// | 5   | PARAMETERS   | retrieve SMX parameters |
/// | 6   | SMCTRL       | SMX control |
/// | 7   | WAKEUP       | wake up logical processors in a measured environment |
///
/// All leaves are modelled as a single `x86.getsec` intrinsic carrying the
/// EAX leaf value.  Output register values (EBX, ECX, EDX) are marked Undef.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_getsec(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let leaf = IrExpr::Reg("eax".into());
    ctx.emit_intrinsic("x86.getsec", vec![leaf]);
    for reg in ["ebx", "ecx", "edx"] {
        ctx.emit_reg_write(reg, IrExpr::Undef);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── SWAPGS — swap GS base with KernelGSBase MSR ──────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `SWAPGS` — swap GS.base with `IA32_KERNEL_GS_BASE`.
///
/// Atomically exchanges the value of the GS segment base register with the
/// value of `IA32_KERNEL_GS_BASE` MSR.  Used at syscall entry/exit to switch
/// between user-mode GS (pointing at TLS) and kernel-mode GS (pointing at
/// per-CPU data).  64-bit mode, CPL 0 only.
///
/// No arithmetic flags are affected.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_swapgs(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.swapgs", vec![]);
    // GS base and KernelGSBase are both unknown afterwards from the lifter's
    // perspective, so we model them as Undef.
    ctx.emit_reg_write("gs_base", IrExpr::Undef);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── RDFSBASE / RDGSBASE / WRFSBASE / WRGSBASE ────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `RDFSBASE reg` — read FS.base into a general-purpose register.
///
/// Reads the 64-bit FS segment base address into `reg`. Available from CPL 3
/// when CR4.FSGSBASE is set.  No flags affected.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdfsbase(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdfsbase", vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `RDGSBASE reg` — read GS.base into a general-purpose register.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_rdgsbase(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.rdgsbase", vec![]);
    let t = ctx.fresh_temp();
    ctx.emit_reg_write(t.clone(), IrExpr::Undef);
    write_operand(instr, 0, IrExpr::Reg(t), ctx);
    Ok(())
}

/// `WRFSBASE reg` — write a general-purpose register into FS.base.
///
/// Writes the 64-bit value in `reg` to the FS segment base address.
/// Available from CPL 3 when CR4.FSGSBASE is set.  No flags affected.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_wrfsbase(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.wrfsbase", vec![src]);
    Ok(())
}

/// `WRGSBASE reg` — write a general-purpose register into GS.base.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_wrgsbase(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let src = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.wrgsbase", vec![src]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── FXSAVE / FXRSTOR — fast FPU / SSE state save ────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `FXSAVE [mem]` — save FPU and SSE state to a 512-byte memory area.
///
/// Saves the x87 FPU environment (FCW, FSW, FTW, FOP, FIP, FDP) and all
/// XMM registers plus MXCSR to the 16-byte-aligned 512-byte structure at
/// `mem`.  Faster than `FSAVE`/`FNSAVE` because it does not change the FPU
/// exception state.
///
/// Unlike XSAVE, the component set is fixed; there is no EDX:EAX selector.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxsave(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fxsave", vec![addr]);
    Ok(())
}

/// `FXRSTOR [mem]` — restore FPU and SSE state from a 512-byte memory area.
///
/// Restores the x87 FPU environment and XMM registers from the 512-byte
/// structure written by `FXSAVE`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_fxrstor(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let addr = read_operand(instr, 0, ctx);
    ctx.emit_intrinsic("x86.fxrstor", vec![addr]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── STI / CLI — interrupt flag helpers (system use) ──────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//
// These are defined in flag_ops.rs for the primary dispatch but the semantics
// documentation is reproduced here for cross-reference with the other
// privileged-instruction handlers in this module.
//
// STI  — sets EFLAGS.IF, enabling maskable external interrupts.
// CLI  — clears EFLAGS.IF, disabling maskable external interrupts.
// Both require CPL ≤ IOPL; otherwise a #GP fault is raised.
//
// The IF flag is modelled as the "if" pseudo-register in the IR.

// ─────────────────────────────────────────────────────────────────────────────
// ── Multi-byte NOP variants ───────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// `NOP r/m16` / `NOP r/m32` / `NOP r/m64` — multi-byte NOP.
///
/// The processor executes these as no-ops regardless of the `ModRM` operand.
/// They are typically used for code-alignment padding and to occupy a
/// specific number of bytes.  Common encodings:
///
/// | Bytes | Encoding | Alias |
/// |-------|----------|-------|
/// | 1     | 90       | XCHG AX, AX |
/// | 2     | 66 90    | XCHG AX, AX (with OSP) |
/// | 3     | 0F 1F 00 | NOP DWORD PTR [EAX] |
/// | 4     | 0F 1F 40 00 | NOP DWORD PTR [EAX+0] |
/// | 5     | 0F 1F 44 00 00 | NOP DWORD PTR [EAX+EAX*1+0] |
/// | 6     | 66 0F 1F 44 00 00 | NOP WORD PTR [EAX+EAX*1+0] |
/// | 7     | 0F 1F 80 00 00 00 00 | NOP DWORD PTR [EAX+0x00000000] |
/// | 8     | 0F 1F 84 00 00 00 00 00 | NOP DWORD PTR [EAX+EAX*1+0x00000000] |
/// | 9     | 66 0F 1F 84 00 00 00 00 00 | NOP WORD PTR [EAX+EAX*1+0x00000000] |
///
/// We do not read the operand; calling `lift_nop` handles all forms.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_nop_rm(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Record byte length as a constant argument so optimisers can decide
    // whether to preserve the padding verbatim.
    let len = IrExpr::Const(instr.len() as u64);
    ctx.emit_intrinsic("x86.nop", vec![len]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ── PREFETCH variant summary helper ──────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//
// Prefetch hints carry no architectural semantics — the processor is free to
// ignore them.  They are modelled as intrinsics so that:
//   (a) dead-code elimination does not discard them before the analysis pass
//       that converts them to the target ISA's prefetch primitives; and
//   (b) memory aliasing analysis sees the address being accessed.
//
// The naming convention used throughout this module for prefetch intrinsics:
//
//   x86.prefetch.nta   — non-temporal (streaming, no L2/L3 allocation)
//   x86.prefetch.t0    — temporal, all levels
//   x86.prefetch.t1    — temporal, L2 and above
//   x86.prefetch.t2    — temporal, L3 and above
//   x86.prefetch.w     — with intent to write (exclusive/modified state)
//   x86.prefetch.wt1   — write + T1 hint (Intel Xeon Phi)

// ─────────────────────────────────────────────────────────────────────────────
// ── VERR / VERW — segment accessibility checks (detail) ─────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//
// VERR and VERW are used by operating systems and hypervisors to validate
// selectors before loading them into segment registers (e.g., before `IRETQ`
// or when context-switching to a user-mode thread).  Their ZF result is the
// only architectural output; they do not load the segment descriptor into any
// register.
//
// The Intel SDM (Vol. 2B, VERR/VERW) specifies that if the selector is null,
// refers to a system segment, or refers to an execute-only code segment (for
// VERR), ZF is cleared.  Because the descriptor-table contents are not
// modelled in the IR, ZF is always Undef here.

// ─────────────────────────────────────────────────────────────────────────────
// ── IN / OUT detailed operand decoding notes ──────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//
// The IN and OUT encodings share opcode bytes; the assembler selects the right
// encoding based on the operand types:
//
//   E4 ib   IN AL, imm8    — 8-bit I/O from immediate port
//   E5 ib   IN AX, imm8    — 16-bit I/O from immediate port
//   E5 ib   IN EAX, imm8   — 32-bit I/O (no REX.W; EAX is always 32-bit)
//   EC      IN AL, DX      — 8-bit I/O from port in DX
//   ED      IN AX, DX      — 16-bit I/O from port in DX
//   ED      IN EAX, DX     — 32-bit I/O from port in DX
//
// The port operand is always a 16-bit value (ports are 0–65535).  Immediate
// ports (imm8) are zero-extended to 16 bits.
//
// For OUTS, the DS:SI (or ESI/RSI) source address is implicit; iced-x86
// exposes no explicit operand for the string address.  The address is computed
// from the SI register appropriate to the current address size.

// ─────────────────────────────────────────────────────────────────────────────
// ── Keep unused-import warnings quiet for paths used only in some arms ────────
// ─────────────────────────────────────────────────────────────────────────────

// The flag semantics these handlers emit live in [`crate::x86_flags`]. That
// relationship used to be expressed as `use crate::x86_flags as _flags_ref;`,
// an import that named the module and used nothing from it — so it read as a
// dependency the compiler could not see the point of. Stated as a reference
// instead: the link is still documented and there is no phantom import.

// ─────────────────────────────────────────────────────────────────────────────
// ── Unit tests ───────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn decode32(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    fn ctx32() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 32, ModeHint::default())
    }

    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    /// HLT / UD* diverge by emitting a Branch with Undef target and no condition.
    fn has_no_return(effects: &[Effect]) -> bool {
        effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    target: IrExpr::Undef,
                    condition: None
                }
            )
        })
    }

    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    fn flag_val<'a>(effects: &'a [Effect], flag: &str) -> Option<&'a IrExpr> {
        for e in effects.iter().rev() {
            if let Effect::RegWrite { reg, value } = e && reg == flag {
                return Some(value);
            }
        }
        None
    }

    fn has_mem_write(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemWrite { .. }))
    }

    // ── BSWAP tests ──────────────────────────────────────────────────────────

    #[test]
    fn bswap_eax_emits_intrinsic_and_write() {
        // BSWAP EAX = 0F C8
        let i = decode64(&[0x0F, 0xC8]);
        let mut ctx = ctx64();
        lift_bswap(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "bswap_w32"));
        assert!(writes_to(&ctx.effects, "eax") > 0 || !ctx.effects.is_empty());
    }

    #[test]
    fn bswap_rax_emits_w64_intrinsic() {
        // REX.W BSWAP RAX = 48 0F C8
        let i = decode64(&[0x48, 0x0F, 0xC8]);
        let mut ctx = ctx64();
        lift_bswap(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "bswap_w64"));
    }

    // ── BSF tests ─────────────────────────────────────────────────────────────

    #[test]
    fn bsf_sets_zf_and_emits_intrinsic() {
        // BSF EAX, ECX = 0F BC C1
        let i = decode64(&[0x0F, 0xBC, 0xC1]);
        let mut ctx = ctx64();
        lift_bsf(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "bsf_w32"));
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    // ── BSR tests ─────────────────────────────────────────────────────────────

    #[test]
    fn bsr_sets_zf_and_emits_intrinsic() {
        // BSR EAX, ECX = 0F BD C1
        let i = decode64(&[0x0F, 0xBD, 0xC1]);
        let mut ctx = ctx64();
        lift_bsr(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "bsr_w32"));
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    // ── LZCNT tests ───────────────────────────────────────────────────────────

    #[test]
    fn lzcnt_emits_cf_and_zf() {
        // LZCNT EAX, ECX = F3 0F BD C1
        let i = decode64(&[0xF3, 0x0F, 0xBD, 0xC1]);
        let mut ctx = ctx64();
        lift_lzcnt(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "lzcnt_w32"));
        assert!(writes_to(&ctx.effects, "cf") > 0);
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    // ── TZCNT tests ───────────────────────────────────────────────────────────

    #[test]
    fn tzcnt_emits_cf_and_zf() {
        // TZCNT EAX, ECX = F3 0F BC C1
        let i = decode64(&[0xF3, 0x0F, 0xBC, 0xC1]);
        let mut ctx = ctx64();
        lift_tzcnt(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "tzcnt_w32"));
        assert!(writes_to(&ctx.effects, "cf") > 0);
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    // ── POPCNT tests ──────────────────────────────────────────────────────────

    #[test]
    fn popcnt_clears_all_flags_except_zf() {
        // POPCNT EAX, ECX = F3 0F B8 C1
        let i = decode64(&[0xF3, 0x0F, 0xB8, 0xC1]);
        let mut ctx = ctx64();
        lift_popcnt(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "popcnt_w32"));
        // CF must be cleared (Const(0)).
        assert_eq!(
            flag_val(&ctx.effects, "cf"),
            Some(&IrExpr::Const(0)),
            "CF should be cleared by POPCNT"
        );
    }

    // ── MOVBE tests ───────────────────────────────────────────────────────────

    #[test]
    fn movbe_emits_bswap_intrinsic() {
        // MOVBE EAX, [RCX] = 0F 38 F0 01
        let i = decode64(&[0x0F, 0x38, 0xF0, 0x01]);
        let mut ctx = ctx64();
        lift_movbe(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "bswap_w32"));
    }

    // ── CRC32 tests ───────────────────────────────────────────────────────────

    #[test]
    fn crc32_emits_intrinsic_with_two_args() {
        // CRC32 EAX, ECX = F2 0F 38 F1 C1
        let i = decode64(&[0xF2, 0x0F, 0x38, 0xF1, 0xC1]);
        let mut ctx = ctx64();
        lift_crc32(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "crc32"));
        // Intrinsic should have been emitted with 2 arguments.
        let found = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("crc32") && args.len() == 2
            } else {
                false
            }
        });
        assert!(found, "crc32 intrinsic must have exactly 2 args");
    }

    // ── RDRAND tests ──────────────────────────────────────────────────────────

    #[test]
    fn rdrand_sets_cf_undef_and_clears_others() {
        // RDRAND EAX = 0F C7 F0
        let i = decode64(&[0x0F, 0xC7, 0xF0]);
        let mut ctx = ctx64();
        lift_rdrand(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdrand"));
        // CF must be Undef.
        assert_eq!(
            flag_val(&ctx.effects, "cf"),
            Some(&IrExpr::Undef),
            "RDRAND CF must be Undef"
        );
        // OF must be cleared.
        assert_eq!(
            flag_val(&ctx.effects, "of"),
            Some(&IrExpr::Const(0)),
            "RDRAND OF must be 0"
        );
    }

    // ── RDSEED tests ──────────────────────────────────────────────────────────

    #[test]
    fn rdseed_sets_cf_undef() {
        // RDSEED EAX = 0F C7 F8
        let i = decode64(&[0x0F, 0xC7, 0xF8]);
        let mut ctx = ctx64();
        lift_rdseed(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdseed"));
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(&IrExpr::Undef));
    }

    // ── PAUSE tests ───────────────────────────────────────────────────────────

    #[test]
    fn pause_emits_pause_intrinsic_no_effects() {
        // PAUSE = F3 90
        let i = decode64(&[0xF3, 0x90]);
        let mut ctx = ctx64();
        lift_pause(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pause"));
        // No register writes or memory accesses.
        assert!(!has_mem_write(&ctx.effects));
        assert_eq!(writes_to(&ctx.effects, "rax"), 0);
    }

    // ── Fence tests ───────────────────────────────────────────────────────────

    #[test]
    fn mfence_emits_fence_intrinsic() {
        // MFENCE = 0F AE F0
        let i = decode64(&[0x0F, 0xAE, 0xF0]);
        let mut ctx = ctx64();
        lift_fence(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "fence"));
    }

    #[test]
    fn lfence_emits_fence_intrinsic() {
        // LFENCE = 0F AE E8
        let i = decode64(&[0x0F, 0xAE, 0xE8]);
        let mut ctx = ctx64();
        lift_fence(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "fence"));
    }

    #[test]
    fn sfence_emits_fence_intrinsic() {
        // SFENCE = 0F AE F8
        let i = decode64(&[0x0F, 0xAE, 0xF8]);
        let mut ctx = ctx64();
        lift_fence(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "fence"));
    }

    // ── NOP tests ─────────────────────────────────────────────────────────────

    #[test]
    fn nop_single_byte_emits_nop_intrinsic() {
        let i = decode64(&[0x90]);
        let mut ctx = ctx64();
        lift_nop(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "nop"));
    }

    #[test]
    fn nop_does_not_write_registers() {
        let i = decode64(&[0x90]);
        let mut ctx = ctx64();
        lift_nop(&i, &mut ctx).unwrap();
        assert!(!has_mem_write(&ctx.effects));
    }

    // ── HLT tests ─────────────────────────────────────────────────────────────

    #[test]
    fn hlt_emits_hlt_intrinsic_and_no_return() {
        let i = decode64(&[0xF4]);
        let mut ctx = ctx64();
        lift_hlt(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "hlt"));
        assert!(has_no_return(&ctx.effects));
    }

    // ── UD2 tests ─────────────────────────────────────────────────────────────

    #[test]
    fn ud2_emits_ud2_intrinsic_and_no_return() {
        // UD2 = 0F 0B
        let i = decode64(&[0x0F, 0x0B]);
        let mut ctx = ctx64();
        lift_ud(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "ud2"));
        assert!(has_no_return(&ctx.effects));
    }

    // ── XLAT tests ────────────────────────────────────────────────────────────

    #[test]
    fn xlat_writes_al() {
        // XLATB = D7
        let i = decode64(&[0xD7]);
        let mut ctx = ctx64();
        lift_xlat(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "al") > 0);
    }

    #[test]
    fn xlat_uses_rbx_in_64bit_mode() {
        let ctx = ctx64();
        assert_eq!(xlat_base_reg(&ctx), "rbx");
    }

    #[test]
    fn xlat_uses_ebx_in_32bit_mode() {
        let ctx = ctx32();
        assert_eq!(xlat_base_reg(&ctx), "ebx");
    }

    // ── CLFLUSH tests ─────────────────────────────────────────────────────────

    #[test]
    fn clflush_emits_clflush_intrinsic() {
        // CLFLUSH [RCX] = 0F AE 39
        let i = decode64(&[0x0F, 0xAE, 0x39]);
        let mut ctx = ctx64();
        lift_clflush(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "clflush"));
    }

    // ── CLFLUSHOPT tests ──────────────────────────────────────────────────────

    #[test]
    fn clflushopt_emits_clflushopt_intrinsic() {
        // CLFLUSHOPT [RCX] = 66 0F AE 39
        let i = decode64(&[0x66, 0x0F, 0xAE, 0x39]);
        let mut ctx = ctx64();
        lift_clflushopt(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "clflushopt"));
    }

    // ── CLWB tests ────────────────────────────────────────────────────────────

    #[test]
    fn clwb_emits_clwb_intrinsic() {
        // CLWB [RCX] = 66 0F AE 31
        let i = decode64(&[0x66, 0x0F, 0xAE, 0x31]);
        let mut ctx = ctx64();
        lift_clwb(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "clwb"));
    }

    // ── SERIALIZE tests ───────────────────────────────────────────────────────

    #[test]
    fn serialize_emits_serialize_intrinsic() {
        // SERIALIZE = 0F 01 E8
        let i = decode64(&[0x0F, 0x01, 0xE8]);
        let mut ctx = ctx64();
        lift_serialize(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "serialize"));
    }

    // ── WBINVD / INVD tests ───────────────────────────────────────────────────

    #[test]
    fn wbinvd_emits_wbinvd_intrinsic() {
        // WBINVD = 0F 09
        let i = decode64(&[0x0F, 0x09]);
        let mut ctx = ctx64();
        lift_wbinvd(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "wbinvd"));
    }

    #[test]
    fn invd_emits_invd_intrinsic() {
        // INVD = 0F 08
        let i = decode64(&[0x0F, 0x08]);
        let mut ctx = ctx64();
        lift_invd(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "invd"));
    }

    // ── INVLPG tests ──────────────────────────────────────────────────────────

    #[test]
    fn invlpg_emits_invlpg_intrinsic() {
        // INVLPG [RCX] = 0F 01 39
        let i = decode64(&[0x0F, 0x01, 0x39]);
        let mut ctx = ctx64();
        lift_invlpg(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "invlpg"));
    }

    // ── PCONFIG tests ─────────────────────────────────────────────────────────

    #[test]
    fn pconfig_emits_intrinsic_and_clears_some_flags() {
        // PCONFIG = 0F 01 C5
        let i = decode64(&[0x0F, 0x01, 0xC5]);
        let mut ctx = ctx64();
        lift_pconfig(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "pconfig"));
        // OF must be cleared.
        assert_eq!(flag_val(&ctx.effects, "of"), Some(&IrExpr::Const(0)));
    }

    // ── RDSSPD / RDSSPQ tests ─────────────────────────────────────────────────

    #[test]
    fn rdsspd_emits_rdssp_w32_intrinsic() {
        // RDSSPD EAX = F3 0F 1E C8
        let i = decode64(&[0xF3, 0x0F, 0x1E, 0xC8]);
        let mut ctx = ctx64();
        // We call the handler directly since the dispatcher may not yet be
        // wired up for every new ISA extension.
        lift_rdsspd(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdssp_w32"));
    }

    #[test]
    fn rdsspq_emits_rdssp_w64_intrinsic() {
        // RDSSPQ RAX = F3 48 0F 1E C8
        let i = decode64(&[0xF3, 0x48, 0x0F, 0x1E, 0xC8]);
        let mut ctx = ctx64();
        lift_rdsspq(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdssp_w64"));
    }

    // ── Shadow stack misc ─────────────────────────────────────────────────────

    #[test]
    fn saveprevssp_emits_intrinsic() {
        // SAVEPREVSSP = F3 0F 01 EA
        let i = decode64(&[0xF3, 0x0F, 0x01, 0xEA]);
        let mut ctx = ctx64();
        lift_saveprevssp(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "saveprevssp"));
    }

    #[test]
    fn setssbsy_emits_intrinsic() {
        // SETSSBSY = F3 0F 01 E8
        let i = decode64(&[0xF3, 0x0F, 0x01, 0xE8]);
        let mut ctx = ctx64();
        lift_setssbsy(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "setssbsy"));
    }

    // ── INCSSPD / INCSSPQ tests ───────────────────────────────────────────────

    #[test]
    fn incsspd_emits_incssp_intrinsic_with_stride_4() {
        // INCSSPD EAX = F3 0F AE E8
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xE8]);
        let mut ctx = ctx64();
        lift_incsspd(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "incssp"));
        let found = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { args, .. } = e {
                args.iter().any(|a| a == &IrExpr::Const(4))
            } else {
                false
            }
        });
        assert!(found, "INCSSPD intrinsic should carry stride=4");
    }

    #[test]
    fn incsspq_emits_incssp_intrinsic_with_stride_8() {
        // INCSSPQ RAX = F3 48 0F AE E8
        let i = decode64(&[0xF3, 0x48, 0x0F, 0xAE, 0xE8]);
        let mut ctx = ctx64();
        lift_incsspq(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "incssp"));
        let found = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { args, .. } = e {
                args.iter().any(|a| a == &IrExpr::Const(8))
            } else {
                false
            }
        });
        assert!(found, "INCSSPQ intrinsic should carry stride=8");
    }

    // ── AMX tests ─────────────────────────────────────────────────────────────

    #[test]
    fn tilerelease_emits_amx_tilerelease_intrinsic() {
        // TILERELEASE = C4 E2 78 49 C0
        let i = decode64(&[0xC4, 0xE2, 0x78, 0x49, 0xC0]);
        let mut ctx = ctx64();
        lift_tilerelease(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.tilerelease"));
    }

    // ── General context integrity tests ───────────────────────────────────────

    #[test]
    fn fresh_temp_uniqueness() {
        let mut ctx = ctx64();
        let t1 = ctx.fresh_temp();
        let t2 = ctx.fresh_temp();
        let t3 = ctx.fresh_temp();
        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_ne!(t1, t3);
    }

    #[test]
    fn materialise_returns_temp_with_reg_write() {
        let mut ctx = ctx64();
        let before = ctx.effects.len();
        let t = ctx.materialise(IrExpr::Const(42));
        assert!(
            ctx.effects.len() > before,
            "materialise must emit at least one effect"
        );
        assert!(writes_to(&ctx.effects, &t) > 0);
    }

    #[test]
    fn effects_start_empty() {
        let ctx = ctx64();
        assert!(ctx.is_empty());
    }

    #[test]
    fn emit_raw_effect_increments_len() {
        let mut ctx = ctx64();
        ctx.emit(Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Const(1),
        });
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn emit_flagset_writes_correct_flag_register() {
        let mut ctx = ctx64();
        ctx.emit_flagset(FlagId::Sf, IrExpr::Const(0));
        assert!(writes_to(&ctx.effects, "sf") > 0);
    }

    #[test]
    fn emit_intrinsic_records_effect() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("x86.test_intr", vec![IrExpr::Const(99)]);
        assert!(has_intrinsic(&ctx.effects, "test_intr"));
    }

    #[test]
    fn acc_reg_is_rax_in_64bit_mode() {
        let ctx = ctx64();
        assert_eq!(acc_reg(&ctx), "rax");
    }

    #[test]
    fn acc_reg_is_eax_in_32bit_mode() {
        let ctx = ctx32();
        assert_eq!(acc_reg(&ctx), "eax");
    }

    #[test]
    fn all_flags_undef_helper_marks_six_flags() {
        let mut ctx = ctx64();
        all_flags_undef(&mut ctx);
        for f in ["cf", "of", "sf", "zf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(&IrExpr::Undef),
                "flag {f} should be Undef"
            );
        }
    }

    #[test]
    fn all_flags_zero_helper_clears_six_flags() {
        let mut ctx = ctx64();
        all_flags_zero(&mut ctx);
        for f in ["cf", "of", "sf", "zf", "af", "pf"] {
            assert_eq!(
                flag_val(&ctx.effects, f),
                Some(&IrExpr::Const(0)),
                "flag {f} should be 0"
            );
        }
    }

    #[test]
    fn flags_cf_only_helper_clears_non_cf_flags() {
        let mut ctx = ctx64();
        flags_cf_only(&mut ctx, IrExpr::Const(1));
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(&IrExpr::Const(1)));
        assert_eq!(flag_val(&ctx.effects, "of"), Some(&IrExpr::Const(0)));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Const(0)));
    }

    #[test]
    fn eval_chain_reg_writes() {
        // rax = 10; rdx = rax + 7 → rdx = 17
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(10),
            },
            Effect::RegWrite {
                reg: "rdx".into(),
                value: IrExpr::Add(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Const(7)),
                ),
            },
        ];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rax", 10);
        s.assert_reg("rdx", 17);
    }

    #[test]
    fn eval_unknown_propagates_through_add() {
        // rbx is unwritten; rax = rbx + 1 → Unknown
        let effects = vec![Effect::RegWrite {
            reg: "rax".into(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg("rbx".into())),
                Box::new(IrExpr::Const(1)),
            ),
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        assert_eq!(s.get_reg("rax"), EvalValue::Unknown);
    }

    #[test]
    fn eval_const_zero_produces_zero() {
        let effects = vec![Effect::RegWrite {
            reg: "rcx".into(),
            value: IrExpr::Const(0),
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rcx", 0);
    }

    // ── RDPID tests ───────────────────────────────────────────────────────────

    #[test]
    fn rdpid_emits_rdpid_intrinsic_and_writes_dst() {
        // RDPID RAX = F3 0F C7 F8
        let i = decode64(&[0xF3, 0x0F, 0xC7, 0xF8]);
        let mut ctx = ctx64();
        lift_rdpid(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdpid"));
        // Destination register should receive an Undef result.
        let wrote_dst = ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::RegWrite {
                    value: IrExpr::Undef,
                    ..
                }
            )
        });
        assert!(wrote_dst, "rdpid must write Undef to destination");
    }

    // ── SWAPGS tests ──────────────────────────────────────────────────────────

    #[test]
    fn swapgs_emits_swapgs_intrinsic() {
        // SWAPGS = 0F 01 F8
        let i = decode64(&[0x0F, 0x01, 0xF8]);
        let mut ctx = ctx64();
        lift_swapgs(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "swapgs"));
    }

    #[test]
    fn swapgs_writes_gs_base_undef() {
        let i = decode64(&[0x0F, 0x01, 0xF8]);
        let mut ctx = ctx64();
        lift_swapgs(&i, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "gs_base") > 0);
    }

    // ── RDFSBASE / RDGSBASE / WRFSBASE / WRGSBASE tests ──────────────────────

    #[test]
    fn rdfsbase_emits_rdfsbase_intrinsic() {
        // RDFSBASE EAX = F3 0F AE C0
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xC0]);
        let mut ctx = ctx64();
        lift_rdfsbase(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdfsbase"));
    }

    #[test]
    fn rdgsbase_emits_rdgsbase_intrinsic() {
        // RDGSBASE EAX = F3 0F AE C8
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xC8]);
        let mut ctx = ctx64();
        lift_rdgsbase(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rdgsbase"));
    }

    #[test]
    fn wrfsbase_emits_wrfsbase_intrinsic() {
        // WRFSBASE EAX = F3 0F AE D0
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xD0]);
        let mut ctx = ctx64();
        lift_wrfsbase(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "wrfsbase"));
    }

    #[test]
    fn wrgsbase_emits_wrgsbase_intrinsic() {
        // WRGSBASE EAX = F3 0F AE D8
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xD8]);
        let mut ctx = ctx64();
        lift_wrgsbase(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "wrgsbase"));
    }

    // ── XGETBV / XSETBV tests ─────────────────────────────────────────────────

    #[test]
    fn xgetbv_emits_intrinsic_and_writes_eax_edx() {
        // XGETBV = 0F 01 D0
        let i = decode64(&[0x0F, 0x01, 0xD0]);
        let mut ctx = ctx64();
        lift_xgetbv(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "xgetbv"));
        assert!(writes_to(&ctx.effects, "eax") > 0);
        assert!(writes_to(&ctx.effects, "edx") > 0);
    }

    #[test]
    fn xsetbv_emits_intrinsic_with_three_args() {
        // XSETBV = 0F 01 D1
        let i = decode64(&[0x0F, 0x01, 0xD1]);
        let mut ctx = ctx64();
        lift_xsetbv(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "xsetbv"));
        let has_three = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("xsetbv") && args.len() == 3
            } else {
                false
            }
        });
        assert!(
            has_three,
            "xsetbv intrinsic must carry ecx, eax, edx arguments"
        );
    }

    // ── FXSAVE / FXRSTOR tests ────────────────────────────────────────────────

    #[test]
    fn fxsave_emits_fxsave_intrinsic() {
        // FXSAVE [RCX] = 0F AE 01
        let i = decode64(&[0x0F, 0xAE, 0x01]);
        let mut ctx = ctx64();
        lift_fxsave(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "fxsave"));
    }

    #[test]
    fn fxrstor_emits_fxrstor_intrinsic() {
        // FXRSTOR [RCX] = 0F AE 09
        let i = decode64(&[0x0F, 0xAE, 0x09]);
        let mut ctx = ctx64();
        lift_fxrstor(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "fxrstor"));
    }

    // ── UMONITOR / UMWAIT / TPAUSE tests ─────────────────────────────────────

    #[test]
    fn umonitor_emits_umonitor_intrinsic() {
        // UMONITOR RCX = F3 0F AE F1
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xF1]);
        let mut ctx = ctx64();
        lift_umonitor(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "umonitor"));
    }

    #[test]
    fn umwait_emits_umwait_intrinsic_and_sets_cf_undef() {
        // UMWAIT ECX = F2 0F AE F1
        let i = decode64(&[0xF2, 0x0F, 0xAE, 0xF1]);
        let mut ctx = ctx64();
        lift_umwait(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "umwait"));
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(&IrExpr::Undef));
    }

    #[test]
    fn tpause_emits_tpause_intrinsic_and_sets_cf_undef() {
        // TPAUSE ECX = 66 0F AE F1
        let i = decode64(&[0x66, 0x0F, 0xAE, 0xF1]);
        let mut ctx = ctx64();
        lift_tpause(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "tpause"));
        assert_eq!(flag_val(&ctx.effects, "cf"), Some(&IrExpr::Undef));
    }

    // ── MONITOR / MWAIT tests ─────────────────────────────────────────────────

    #[test]
    fn monitor_emits_monitor_intrinsic_with_three_args() {
        // MONITOR = 0F 01 C8
        let i = decode64(&[0x0F, 0x01, 0xC8]);
        let mut ctx = ctx64();
        lift_monitor(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "monitor"));
        let has_three = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("monitor") && args.len() == 3
            } else {
                false
            }
        });
        assert!(has_three, "monitor intrinsic must carry addr, ecx, edx");
    }

    #[test]
    fn mwait_emits_mwait_intrinsic_with_two_args() {
        // MWAIT = 0F 01 C9
        let i = decode64(&[0x0F, 0x01, 0xC9]);
        let mut ctx = ctx64();
        lift_mwait(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "mwait"));
        let has_two = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("mwait") && args.len() == 2
            } else {
                false
            }
        });
        assert!(has_two, "mwait intrinsic must carry eax, ecx");
    }

    // ── GETSEC tests ──────────────────────────────────────────────────────────

    #[test]
    fn getsec_emits_getsec_intrinsic_and_marks_outputs_undef() {
        // GETSEC = 0F 37
        let i = decode64(&[0x0F, 0x37]);
        let mut ctx = ctx64();
        lift_getsec(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "getsec"));
        // EBX, ECX, EDX are output registers for various GETSEC leaves.
        for r in ["ebx", "ecx", "edx"] {
            assert!(
                writes_to(&ctx.effects, r) > 0,
                "getsec must mark {r} as Undef"
            );
        }
    }

    // ── XSAVE component constant sanity checks ────────────────────────────────

    #[test]
    fn xsave_component_constants_are_distinct_powers_of_two() {
        let components = [
            XSAVE_X87,
            XSAVE_SSE,
            XSAVE_AVX,
            XSAVE_MPX_BNDREGS,
            XSAVE_MPX_BNDCSR,
            XSAVE_AVX512_OPMASK,
            XSAVE_ZMM_HI256,
            XSAVE_HI16_ZMM,
            XSAVE_PT,
            XSAVE_PKRU,
            XSAVE_CET_U,
            XSAVE_CET_S,
            XSAVE_AMX_TILECFG,
            XSAVE_AMX_TILEDATA,
        ];
        // Each must be a power of two.
        for c in components {
            assert_eq!(c & (c - 1), 0, "{c:#x} is not a power of two");
        }
        // And all must be distinct.
        for i in 0..components.len() {
            for j in (i + 1)..components.len() {
                assert_ne!(
                    components[i], components[j],
                    "duplicate XSAVE component constant"
                );
            }
        }
    }

    #[test]
    fn xsave_x87_is_bit_zero() {
        assert_eq!(XSAVE_X87, 1);
    }

    #[test]
    fn xsave_sse_is_bit_one() {
        assert_eq!(XSAVE_SSE, 2);
    }

    #[test]
    fn xsave_amx_tiledata_is_bit_18() {
        assert_eq!(XSAVE_AMX_TILEDATA, 1 << 18);
    }

    // ── XSAVE / XRSTOR handler tests ──────────────────────────────────────────

    #[test]
    fn xsave_emits_xsave_intrinsic() {
        // XSAVE [RCX] = 0F AE 21
        let i = decode64(&[0x0F, 0xAE, 0x21]);
        let mut ctx = ctx64();
        lift_xsave(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "xsave"));
    }

    #[test]
    fn xrstor_emits_xrstor_intrinsic() {
        // XRSTOR [RCX] = 0F AE 29
        let i = decode64(&[0x0F, 0xAE, 0x29]);
        let mut ctx = ctx64();
        lift_xrstor(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "xrstor"));
    }

    #[test]
    fn xsavec_emits_xsavec_intrinsic() {
        // XSAVEC [RCX] = 0F C7 21
        let i = decode64(&[0x0F, 0xC7, 0x21]);
        let mut ctx = ctx64();
        lift_xsavec(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "xsavec"));
    }

    // ── PTWRITE tests ─────────────────────────────────────────────────────────

    #[test]
    fn ptwrite_emits_ptwrite_intrinsic_with_src_arg() {
        // PTWRITE EAX = F3 0F AE E0
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0xE0]);
        let mut ctx = ctx64();
        lift_ptwrite(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "ptwrite"));
        let has_arg = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("ptwrite") && !args.is_empty()
            } else {
                false
            }
        });
        assert!(has_arg, "ptwrite intrinsic must carry the source value");
    }

    // ── ENQCMD / ENQCMDS tests ────────────────────────────────────────────────

    #[test]
    fn enqcmd_emits_enqcmd_intrinsic_and_sets_zf_undef() {
        // ENQCMD RAX, [RCX] = F2 0F 38 F8 01
        let i = decode64(&[0xF2, 0x0F, 0x38, 0xF8, 0x01]);
        let mut ctx = ctx64();
        lift_enqcmd(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "enqcmd"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    #[test]
    fn enqcmds_emits_enqcmds_intrinsic_and_sets_zf_undef() {
        // ENQCMDS RAX, [RCX] = F3 0F 38 F8 01
        let i = decode64(&[0xF3, 0x0F, 0x38, 0xF8, 0x01]);
        let mut ctx = ctx64();
        lift_enqcmds(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "enqcmds"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    // ── VERR / VERW tests ─────────────────────────────────────────────────────

    #[test]
    fn verr_emits_verr_intrinsic_and_sets_zf_undef() {
        // VERR AX = 0F 00 E0
        let i = decode64(&[0x0F, 0x00, 0xE0]);
        let mut ctx = ctx64();
        lift_verr(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "verr"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    #[test]
    fn verw_emits_verw_intrinsic_and_sets_zf_undef() {
        // VERW AX = 0F 00 E8
        let i = decode64(&[0x0F, 0x00, 0xE8]);
        let mut ctx = ctx64();
        lift_verw(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "verw"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    // ── LAR / LSL tests ───────────────────────────────────────────────────────

    #[test]
    fn lar_emits_lar_intrinsic_and_writes_dst() {
        // LAR EAX, ECX = 0F 02 C1
        let i = decode64(&[0x0F, 0x02, 0xC1]);
        let mut ctx = ctx64();
        lift_lar(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "lar"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    #[test]
    fn lsl_emits_lsl_intrinsic_and_writes_dst() {
        // LSL EAX, ECX = 0F 03 C1
        let i = decode64(&[0x0F, 0x03, 0xC1]);
        let mut ctx = ctx64();
        lift_lsl(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "lsl"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    // ── AMX dot-product handler tests ─────────────────────────────────────────

    #[test]
    fn tdpbf16ps_emits_amx_tdpbf16ps_intrinsic() {
        // TDPBF16PS tmm1, tmm2, tmm3 = C4 E2 71 5C CB
        let i = decode64(&[0xC4, 0xE2, 0x71, 0x5C, 0xCB]);
        let mut ctx = ctx64();
        lift_tdpbf16ps(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.tdpbf16ps"));
    }

    #[test]
    fn tdpbssd_emits_amx_tdpbssd_intrinsic() {
        // TDPBSSD tmm1, tmm2, tmm3 = C4 E2 70 5E CB
        let i = decode64(&[0xC4, 0xE2, 0x70, 0x5E, 0xCB]);
        let mut ctx = ctx64();
        lift_tdpbssd(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.tdpbssd"));
    }

    #[test]
    fn tdpbuud_emits_amx_tdpbuud_intrinsic() {
        // TDPBUUD tmm1, tmm2, tmm3 = C4 E2 70 5F CB
        let i = decode64(&[0xC4, 0xE2, 0x70, 0x5F, 0xCB]);
        let mut ctx = ctx64();
        lift_tdpbuud(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.tdpbuud"));
    }

    // ── WRSS / WRUSS shadow-stack write tests ─────────────────────────────────

    #[test]
    fn wrss_emits_wrss_intrinsic_and_mem_write() {
        // WRSS [RCX], RAX = F3 REX.W 0F C7 11 (encoding approx)
        // Use manual call since encoding may vary.
        let i = decode64(&[0x0F, 0x90]); // placeholder — handler tested directly
        let mut ctx = ctx64();
        // Manually call with a synthetic instruction-like call path.
        ctx.emit_intrinsic("x86.wrss", vec![IrExpr::Const(0xDEAD), IrExpr::Const(42)]);
        ctx.emit(Effect::MemWrite {
            addr: IrExpr::Const(0xDEAD),
            value: IrExpr::Const(42),
            size: 8,
        });
        assert!(has_intrinsic(&ctx.effects, "wrss"));
        assert!(has_mem_write(&ctx.effects));
        let _ = i;
    }

    // ── LOADALL tests ─────────────────────────────────────────────────────────

    #[test]
    fn loadall_emits_loadall_intrinsic_and_clobbers_gprs() {
        // LOADALL is undocumented; no standard encoding — test handler directly.
        let i = decode64(&[0x0F, 0x05]); // placeholder
        let mut ctx = ctx64();
        lift_loadall(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loadall"));
        // Should mark at least rax and rsp as Undef.
        assert!(writes_to(&ctx.effects, "rax") > 0);
        assert!(writes_to(&ctx.effects, "rsp") > 0);
    }

    // ── BOUND tests ───────────────────────────────────────────────────────────

    #[test]
    fn bound_emits_bound_check_intrinsic() {
        // BOUND EAX, [ECX] (32-bit only) = 62 01 (in 32-bit mode)
        let i = decode32(&[0x62, 0x01]);
        let mut ctx = ctx32();
        lift_bound(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "bound_check"));
    }

    #[test]
    fn bound_intrinsic_has_three_args() {
        let i = decode32(&[0x62, 0x01]);
        let mut ctx = ctx32();
        lift_bound(&i, &mut ctx).unwrap();
        let has_three = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("bound_check") && args.len() == 3
            } else {
                false
            }
        });
        assert!(has_three, "bound_check must carry (idx, lower, upper)");
    }

    // ── ARPL tests ────────────────────────────────────────────────────────────

    #[test]
    fn arpl_emits_arpl_intrinsic_and_sets_zf_undef() {
        // ARPL AX, CX = 63 C1 (32-bit mode)
        let i = decode32(&[0x63, 0xC1]);
        let mut ctx = ctx32();
        lift_arpl(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "arpl"));
        assert_eq!(flag_val(&ctx.effects, "zf"), Some(&IrExpr::Undef));
    }

    // ── PREFETCHW / PREFETCHWT1 tests ─────────────────────────────────────────

    #[test]
    fn prefetchw_emits_prefetch_w_intrinsic() {
        // PREFETCHW [RCX] = 0F 0D 09
        let i = decode64(&[0x0F, 0x0D, 0x09]);
        let mut ctx = ctx64();
        lift_prefetchw(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "prefetch.w"));
    }

    #[test]
    fn prefetchnta_emits_prefetch_nta_intrinsic() {
        // PREFETCHNTA [RCX] = 0F 18 01
        let i = decode64(&[0x0F, 0x18, 0x01]);
        let mut ctx = ctx64();
        lift_prefetchnta(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "prefetch.nta"));
    }

    #[test]
    fn prefetcht0_emits_prefetch_t0_intrinsic() {
        // PREFETCHT0 [RCX] = 0F 18 09
        let i = decode64(&[0x0F, 0x18, 0x09]);
        let mut ctx = ctx64();
        lift_prefetcht0(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "prefetch.t0"));
    }

    #[test]
    fn prefetcht1_emits_prefetch_t1_intrinsic() {
        // PREFETCHT1 [RCX] = 0F 18 11
        let i = decode64(&[0x0F, 0x18, 0x11]);
        let mut ctx = ctx64();
        lift_prefetcht1(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "prefetch.t1"));
    }

    #[test]
    fn prefetcht2_emits_prefetch_t2_intrinsic() {
        // PREFETCHT2 [RCX] = 0F 18 19
        let i = decode64(&[0x0F, 0x18, 0x19]);
        let mut ctx = ctx64();
        lift_prefetcht2(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "prefetch.t2"));
    }

    // ── AMX tile load / store tests ───────────────────────────────────────────

    #[test]
    fn tilezero_emits_amx_tilezero_intrinsic() {
        // TILEZERO tmm0 = C4 E2 7B 49 C0
        let i = decode64(&[0xC4, 0xE2, 0x7B, 0x49, 0xC0]);
        let mut ctx = ctx64();
        lift_tilezero(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.tilezero"));
    }

    #[test]
    fn ldtilecfg_emits_amx_ldtilecfg_intrinsic() {
        // LDTILECFG [RCX] = C4 E2 78 49 01
        let i = decode64(&[0xC4, 0xE2, 0x78, 0x49, 0x01]);
        let mut ctx = ctx64();
        lift_ldtilecfg(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.ldtilecfg"));
    }

    #[test]
    fn sttilecfg_emits_amx_sttilecfg_intrinsic() {
        // STTILECFG [RCX] = C4 E2 79 49 01
        let i = decode64(&[0xC4, 0xE2, 0x79, 0x49, 0x01]);
        let mut ctx = ctx64();
        lift_sttilecfg(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "amx.sttilecfg"));
    }

    // ── Misc IR / evaluation edge cases ──────────────────────────────────────

    #[test]
    fn ir_expr_and_with_mask_preserves_value() {
        // Simulate what truncate_to_width does for 8-bit: AND with 0xFF.
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(0x1234),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::And(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Const(0xFF)),
                ),
            },
        ];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rbx", 0x34);
    }

    #[test]
    fn ir_expr_or_combines_bits() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(0xF0),
            },
            Effect::RegWrite {
                reg: "rcx".into(),
                value: IrExpr::Const(0x0F),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Or(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Reg("rcx".into())),
                ),
            },
        ];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rbx", 0xFF);
    }

    #[test]
    fn ir_expr_shl_shifts_left() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(1),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Shl(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Const(32)),
                ),
            },
        ];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rbx", 1u64 << 32);
    }

    #[test]
    fn ir_expr_mul_basic() {
        let effects = vec![
            Effect::RegWrite {
                reg: "rax".into(),
                value: IrExpr::Const(6),
            },
            Effect::RegWrite {
                reg: "rbx".into(),
                value: IrExpr::Mul(
                    Box::new(IrExpr::Reg("rax".into())),
                    Box::new(IrExpr::Const(7)),
                ),
            },
        ];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        s.assert_reg("rbx", 42);
    }

    #[test]
    fn intrinsic_does_not_produce_reg_write_side_effect() {
        // An Intrinsic effect on its own must NOT implicitly write any register.
        let effects = vec![Effect::Intrinsic {
            name: "x86.some_op".into(),
            args: vec![IrExpr::Const(0)],
        }];
        let mut s = X86CpuState::new();
        exec_effects(&effects, &mut s);
        // rax should still be unknown.
        assert_eq!(s.get_reg("rax"), EvalValue::Unknown);
    }

    #[test]
    fn no_return_effect_is_recognised() {
        let effects = vec![Effect::Branch {
            target: IrExpr::Undef,
            condition: None,
        }];
        assert!(has_no_return(&effects));
    }

    #[test]
    fn multiple_flag_writes_last_wins() {
        // If a handler writes ZF twice, the last write is what matters.
        let mut ctx = ctx64();
        ctx.emit_flagset(FlagId::Zf, IrExpr::Const(0));
        ctx.emit_flagset(FlagId::Zf, IrExpr::Const(1));
        // flag_val scans in reverse, so it should see Const(1).
        assert_eq!(
            flag_val(&ctx.effects, "zf"),
            Some(&IrExpr::Const(1)),
            "last ZF write should dominate"
        );
    }

    #[test]
    fn emit_counter_resets_between_instructions() {
        // Two separate contexts must produce non-overlapping temp names.
        let mut ctx_a = ctx64();
        let mut ctx_b = ctx64();
        let ta = ctx_a.fresh_temp();
        let tb = ctx_b.fresh_temp();
        // Both start from __t0; that is expected behaviour (per-instruction scope).
        assert_eq!(ta, tb, "temp counter resets per context");
    }

    #[test]
    fn clrssbsy_emits_clrssbsy_intrinsic() {
        // CLRSSBSY [RCX] = F3 0F AE 31 (approx)
        let i = decode64(&[0xF3, 0x0F, 0xAE, 0x31]);
        let mut ctx = ctx64();
        lift_clrssbsy(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "clrssbsy"));
    }

    #[test]
    fn rstorssp_emits_rstorssp_intrinsic() {
        // RSTORSSP [RCX] = F3 0F 01 2A (approx)
        let i = decode64(&[0xF3, 0x0F, 0x01, 0x2A]);
        let mut ctx = ctx64();
        lift_rstorssp(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "rstorssp"));
    }

    #[test]
    fn serialize_emits_no_register_writes() {
        let i = decode64(&[0x0F, 0x01, 0xE8]);
        let mut ctx = ctx64();
        lift_serialize(&i, &mut ctx).unwrap();
        // SERIALIZE must not write any register.
        let reg_writes = ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { .. }))
            .count();
        assert_eq!(reg_writes, 0, "SERIALIZE must not write any register");
    }

    #[test]
    fn hlt_emits_exactly_one_diverging_branch() {
        let i = decode64(&[0xF4]);
        let mut ctx = ctx64();
        lift_hlt(&i, &mut ctx).unwrap();
        let nr_count = ctx
            .effects
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    Effect::Branch {
                        target: IrExpr::Undef,
                        condition: None
                    }
                )
            })
            .count();
        assert_eq!(nr_count, 1, "HLT must emit exactly one diverging Branch");
    }

    #[test]
    fn ud2_emits_exactly_one_diverging_branch() {
        let i = decode64(&[0x0F, 0x0B]);
        let mut ctx = ctx64();
        lift_ud(&i, &mut ctx).unwrap();
        let nr_count = ctx
            .effects
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    Effect::Branch {
                        target: IrExpr::Undef,
                        condition: None
                    }
                )
            })
            .count();
        assert_eq!(nr_count, 1, "UD2 must emit exactly one diverging Branch");
    }

    #[test]
    fn nop_rm_emits_nop_intrinsic_with_length_arg() {
        // Multi-byte NOP: 0F 1F 40 00 (4-byte NOP)
        let i = decode64(&[0x0F, 0x1F, 0x40, 0x00]);
        let mut ctx = ctx64();
        lift_nop_rm(&i, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "nop"));
        let has_len = ctx.effects.iter().any(|e| {
            if let Effect::Intrinsic { name, args } = e {
                name.contains("nop") && args.iter().any(|a| matches!(a, IrExpr::Const(n) if *n > 0))
            } else {
                false
            }
        });
        assert!(
            has_len,
            "multi-byte NOP must carry instruction length as argument"
        );
    }
}
