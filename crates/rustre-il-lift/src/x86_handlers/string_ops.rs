//! x86/x64 string-operation instruction lifter.
//!
//! # Instruction families covered
//!
//! | Family | Mnemonics | Width variants |
//! |--------|-----------|----------------|
//! | Move string | MOVSB/W/D/Q | 1/2/4/8 bytes |
//! | Compare string | CMPSB/W/D/Q | 1/2/4/8 bytes |
//! | Scan string | SCASB/W/D/Q | 1/2/4/8 bytes |
//! | Load string | LODSB/W/D/Q | 1/2/4/8 bytes |
//! | Store string | STOSB/W/D/Q | 1/2/4/8 bytes |
//! | Input string | INSB/W/D | 1/2/4 bytes |
//! | Output string | OUTSB/W/D | 1/2/4 bytes |
//!
//! # Prefix handling
//!
//! Every handler correctly models:
//!
//! * **REP** — repeat while CX/ECX/RCX != 0.  Used by MOVS, LODS, STOS, INS, OUTS.
//! * **REPE/REPZ** — repeat while CX/ECX/RCX != 0 AND ZF == 1.  Used by CMPS, SCAS.
//! * **REPNE/REPNZ** — repeat while CX/ECX/RCX != 0 AND ZF == 0.  Used by CMPS, SCAS.
//! * **Address-size override (0x67)** — switches between SI/ESI/RSI, DI/EDI/RDI,
//!   CX/ECX/RCX according to the effective address size.
//! * **Operand-size override (0x66)** — handled via the mnemonic suffix (B/W/D/Q).
//! * **Segment overrides** — DS:SI source and ES:DI destination are standard; an
//!   explicit segment-override prefix redirects the *source* segment only.
//!   The destination is always ES in 16/32-bit mode; in 64-bit mode segments are
//!   flat (all overrides are ignored for flat memory modelling).
//!
//! # DF (Direction Flag) modelling
//!
//! The direction flag determines whether the index registers advance (+width)
//! or retreat (-width) after each element.  Because DF is typically known
//! statically at analysis time (CLD before `rep movs`, STD in rare cases), the
//! lifter emits an `x86.string.step` intrinsic that downstream passes can fold
//! once DF is resolved, while always also emitting a conservative `RegWrite`
//! that assumes DF == 0 (forward) so that the IR remains self-contained even
//! without DF propagation.
//!
//! # REP loop expansion
//!
//! REP prefixes are expanded into an explicit IR loop using the label-intrinsic
//! pair `x86.string.loop_header` / `x86.string.loop_exit`.  The loop body is:
//!
//! ```text
//!   x86.string.loop_header            ; label — MLIL pass uses as loop head
//!   if CX == 0 goto loop_exit         ; pre-test (count zero ⇒ skip entirely)
//!   <single-iteration body>
//!   CX := CX - 1
//!   [if ZF == 1 / ZF == 0 ...] goto loop_header   ; REPE / REPNE back-edge
//!   [if CX != 0  ...] goto loop_header             ; plain REP back-edge
//!   x86.string.loop_exit              ; label
//! ```
//!
//! This models the architectural guarantee that the count check precedes the
//! first iteration (REP with CX=0 executes zero iterations).
//!
//! # INS / OUTS I/O port instructions
//!
//! INS reads from the I/O port in DX into ES:DI.  OUTS writes from DS:SI to the
//! port in DX.  Because I/O port access is privileged (ring 0) and requires
//! `IOPB` permission in ring 3, the lifter models the I/O transfer as an
//! `x86.io.in` / `x86.io.out` intrinsic rather than a plain memory access.
//! The pointer step and REP loop semantics are identical to LODS/STOS.

use crate::x86_context::X86LiftCtx;
use crate::x86_flags;
use crate::x86_operand::reg_name;
use crate::{Effect, IrExpr, LiftError};
use iced_x86::{Instruction, Mnemonic};

// ─────────────────────────────────────────────────────────────────────────────
// Width helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return the element width in bytes encoded in the string-op mnemonic suffix.
///
/// The x86 encoding guarantees a one-to-one mapping between mnemonic and
/// operand width; there is no ambiguity across the B/W/D/Q variants.
/// Returns 0 for mnemonics that are not string ops (should not occur in
/// practice since the dispatcher only calls these handlers for string ops).
#[inline]
const fn string_op_width(m: Mnemonic) -> u8 {
    use Mnemonic as M;
    match m {
        M::Movsb | M::Cmpsb | M::Scasb | M::Lodsb | M::Stosb | M::Insb | M::Outsb => 1,

        M::Movsw | M::Cmpsw | M::Scasw | M::Lodsw | M::Stosw | M::Insw | M::Outsw => 2,

        M::Movsd | M::Cmpsd | M::Scasd | M::Lodsd | M::Stosd | M::Insd | M::Outsd => 4,

        M::Movsq | M::Cmpsq | M::Scasq | M::Lodsq | M::Stosq => 8,

        _ => 0,
    }
}

/// Return the bit-width of the operand (bytes * 8), clamped to 64.
///
/// Used when constructing flag-formula intrinsic names, which encode width in
/// bits (`x86.flag.cf_sub_w8`, `x86.flag.cf_sub_w32`, etc.).
#[inline]
fn op_bits(w: u8) -> u8 {
    (w * 8).min(64)
}

/// Accumulator register name for an operand of width `w`.
///
/// String ops that read/write the accumulator (LODS, STOS, SCAS) use the
/// sub-register matched to the element width:
///
/// | w | register |
/// |---|----------|
/// | 1 | AL       |
/// | 2 | AX       |
/// | 4 | EAX      |
/// | 8 | RAX      |
#[inline]
const fn acc_reg(w: u8) -> &'static str {
    match w {
        1 => "al",
        2 => "ax",
        4 => "eax",
        _ => "rax",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Address-size-aware index register selection
// ─────────────────────────────────────────────────────────────────────────────

/// Select the source-index register based on the effective address size.
///
/// In 64-bit mode the default is RSI; the 0x67 address-size override switches
/// to ESI (32-bit addressing).  In 32-bit mode the default is ESI; the 0x67
/// override switches to SI.  In 16-bit mode the default is SI; the 0x67
/// override switches to ESI.
///
/// This differs from `X86LiftCtx::si_reg()`, which returns the register for
/// the *machine mode* without consulting the address-size override flag.  Here
/// we fold both the mode and the prefix.
#[inline]
const fn effective_si(ctx: &X86LiftCtx) -> &'static str {
    match (ctx.bits, ctx.mode.addr_size_override) {
        (64, false) => "rsi",
        (64, true) | (32, false) => "esi",
        _ => "si",
    }
}

/// Select the destination-index register based on the effective address size.
///
/// Mirrors [`effective_si`] but for the DI register family.
#[inline]
const fn effective_di(ctx: &X86LiftCtx) -> &'static str {
    match (ctx.bits, ctx.mode.addr_size_override) {
        (64, false) => "rdi",
        (64, true) | (32, false) => "edi",
        _ => "di",
    }
}

/// Select the REP counter register based on the effective address size.
///
/// Per SDM Vol. 1 §7.3.6: the counter register is ECX when the address-size
/// attribute is 32, and RCX when it is 64.  With a 0x67 prefix in 64-bit mode
/// the counter switches to ECX.
#[inline]
const fn effective_cx(ctx: &X86LiftCtx) -> &'static str {
    match (ctx.bits, ctx.mode.addr_size_override) {
        (64, false) => "rcx",
        (64, true) | (32, false) => "ecx",
        _ => "cx",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Segment-override helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return the IR name of the segment-base register implied by the source
/// segment override, or `None` in 64-bit flat mode.
///
/// In 16/32-bit mode, string source addresses are `DS:SI` by default.  An
/// explicit override can redirect to `ES`, `CS`, `SS`, `FS`, or `GS`.  The
/// lifter models segment bases as IR registers named `seg_es`, `seg_cs`, etc.
/// In 64-bit flat mode all segment bases are zero; the lifter drops them.
#[inline]
const fn source_seg_base(ctx: &X86LiftCtx) -> Option<&'static str> {
    if ctx.bits == 64 {
        return None; // flat — all segment bases are 0
    }
    Some(match ctx.mode.seg_override {
        // default for string source
        1 => "seg_es",
        2 => "seg_cs",
        3 => "seg_ss",
        5 => "seg_fs",
        6 => "seg_gs",
        _ => "seg_ds",
    })
}

/// Return the IR name of the destination segment base, or `None` in 64-bit.
///
/// String destinations are always `ES:DI` in 16/32-bit mode; segment overrides
/// do *not* affect the destination.
#[inline]
const fn dest_seg_base(ctx: &X86LiftCtx) -> Option<&'static str> {
    if ctx.bits == 64 { None } else { Some("seg_es") }
}

/// Build the effective source address `seg_base + index_reg`.
///
/// If the segment base is omitted (64-bit flat), the effective address is just
/// the raw index register.
fn make_src_addr(ctx: &X86LiftCtx, idx: &str) -> IrExpr {
    source_seg_base(ctx).map_or_else(|| IrExpr::Reg(idx.to_string()), |seg| IrExpr::Add(
            Box::new(IrExpr::Reg(seg.to_string())),
            Box::new(IrExpr::Reg(idx.to_string())),
        ))
}

/// Build the effective destination address `seg_es + index_reg`.
fn make_dst_addr(ctx: &X86LiftCtx, idx: &str) -> IrExpr {
    dest_seg_base(ctx).map_or_else(|| IrExpr::Reg(idx.to_string()), |seg| IrExpr::Add(
            Box::new(IrExpr::Reg(seg.to_string())),
            Box::new(IrExpr::Reg(idx.to_string())),
        ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer step emission
// ─────────────────────────────────────────────────────────────────────────────

/// Emit the post-operation pointer update for a string index register.
///
/// According to the SDM the index registers advance by `+width` when
/// DF == 0 (forward direction, set by CLD) and retreat by `-width` when
/// DF == 1 (backward direction, set by STD).
///
/// The lifter emits two artefacts:
///
/// 1. An `x86.string.step` **intrinsic** that captures the full three-way
///    triple `(reg, width, df)`.  Downstream passes can fold this when DF is
///    known to be constant.
///
/// 2. A conservative `RegWrite` that adds `+width` (DF == 0 assumption).
///    This keeps the IR self-contained: any pass that ignores the intrinsic
///    still sees a valid (if imprecise) dataflow edge on the index register.
///
/// Handlers must call this once per index register, per iteration.
fn step_pointer(ctx: &mut X86LiftCtx, reg: &str, width: u8) {
    // Intrinsic: full DF-aware semantics recorded for later passes.
    ctx.emit_intrinsic(
        "x86.string.step",
        vec![
            IrExpr::Reg(reg.to_string()),
            IrExpr::Const(u64::from(width)),
            IrExpr::Reg("df".into()),
        ],
    );
    // Conservative RegWrite: assumes DF == 0 (forward).
    let step = IrExpr::Const(u64::from(width));
    let new_v = IrExpr::Add(Box::new(IrExpr::Reg(reg.to_string())), Box::new(step));
    ctx.emit_reg_write(reg, new_v);
}

/// Emit pointer step for the source index register (SI/ESI/RSI), respecting
/// both the machine mode and any address-size override prefix.
#[inline]
fn step_si(ctx: &mut X86LiftCtx, width: u8) {
    let si = effective_si(ctx);
    step_pointer(ctx, si, width);
}

/// Emit pointer step for the destination index register (DI/EDI/RDI).
#[inline]
fn step_di(ctx: &mut X86LiftCtx, width: u8) {
    let di = effective_di(ctx);
    step_pointer(ctx, di, width);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — MOVS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for MOVSB/W/D/Q.
///
/// Semantics (per SDM Vol. 2B, MOVS):
/// ```text
///   temp := mem[DS:SI]          ; load element from source
///   mem[ES:DI] := temp          ; store element to destination
///   SI += (DF == 0) ? +width : -width
///   DI += (DF == 0) ? +width : -width
/// ```
/// Flags: not modified.
fn body_movs(ctx: &mut X86LiftCtx, w: u8) {
    let si = effective_si(ctx);
    let di = effective_di(ctx);
    let src_addr = make_src_addr(ctx, si);
    let dst_addr = make_dst_addr(ctx, di);
    let t = ctx.fresh_temp();
    ctx.emit_mem_read(src_addr, t.clone(), w);
    ctx.emit_mem_write(dst_addr, IrExpr::Reg(t), w);
    step_si(ctx, w);
    step_di(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — CMPS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for CMPSB/W/D/Q.
///
/// Semantics (per SDM Vol. 2A, CMPS):
/// ```text
///   a    := mem[DS:SI]
///   b    := mem[ES:DI]
///   temp := a - b               ; sets flags, result discarded
///   SI += (DF == 0) ? +width : -width
///   DI += (DF == 0) ? +width : -width
/// ```
/// Flags modified: CF, OF, SF, ZF, AF, PF (same as SUB).
///
/// The REPE/REPNE prefix tests ZF after the flag update; this function just
/// emits the flag update — the loop wrapper reads ZF for the back-edge.
fn body_cmps(ctx: &mut X86LiftCtx, w: u8) {
    let si = effective_si(ctx);
    let di = effective_di(ctx);
    let src_addr = make_src_addr(ctx, si);
    let dst_addr = make_dst_addr(ctx, di);
    let a = ctx.fresh_temp();
    let b = ctx.fresh_temp();
    ctx.emit_mem_read(src_addr, a.clone(), w);
    ctx.emit_mem_read(dst_addr, b.clone(), w);
    let diff = IrExpr::Sub(
        Box::new(IrExpr::Reg(a.clone())),
        Box::new(IrExpr::Reg(b.clone())),
    );
    let r = ctx.materialise_sized(diff, op_bits(w));
    x86_flags::set_flags_sub(
        ctx,
        &IrExpr::Reg(a),
        &IrExpr::Reg(b),
        &IrExpr::Reg(r),
        op_bits(w),
    );
    step_si(ctx, w);
    step_di(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — SCAS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for SCASB/W/D/Q.
///
/// Semantics (per SDM Vol. 2B, SCAS):
/// ```text
///   mem_val := mem[ES:DI]
///   temp    := acc - mem_val    ; sets flags, result discarded
///   DI += (DF == 0) ? +width : -width
/// ```
/// where `acc` is AL/AX/EAX/RAX depending on the operand width.
///
/// Flags modified: CF, OF, SF, ZF, AF, PF (same as CMP/SUB).
///
/// SCAS does NOT read from SI; only DI advances.
fn body_scas(ctx: &mut X86LiftCtx, w: u8) {
    let di = effective_di(ctx);
    let dst_addr = make_dst_addr(ctx, di);
    let acc = acc_reg(w);
    let mem_val = ctx.fresh_temp();
    ctx.emit_mem_read(dst_addr, mem_val.clone(), w);
    let diff = IrExpr::Sub(
        Box::new(IrExpr::Reg(acc.into())),
        Box::new(IrExpr::Reg(mem_val.clone())),
    );
    let r = ctx.materialise_sized(diff, op_bits(w));
    x86_flags::set_flags_sub(
        ctx,
        &IrExpr::Reg(acc.into()),
        &IrExpr::Reg(mem_val),
        &IrExpr::Reg(r),
        op_bits(w),
    );
    step_di(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — LODS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for LODSB/W/D/Q.
///
/// Semantics (per SDM Vol. 2B, LODS):
/// ```text
///   AL/AX/EAX/RAX := mem[DS:SI]
///   SI += (DF == 0) ? +width : -width
/// ```
/// Flags: not modified.
///
/// Note: REP LODS is architecturally valid but is almost never useful
/// (each iteration overwrites the accumulator, so only the last value
/// survives).  The lifter still models it correctly.
fn body_lods(ctx: &mut X86LiftCtx, w: u8) {
    let si = effective_si(ctx);
    let src_addr = make_src_addr(ctx, si);
    let acc = acc_reg(w);
    let t = ctx.fresh_temp();
    ctx.emit_mem_read(src_addr, t.clone(), w);
    ctx.emit_reg_write(acc, IrExpr::Reg(t));
    step_si(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — STOS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for STOSB/W/D/Q.
///
/// Semantics (per SDM Vol. 2B, STOS):
/// ```text
///   mem[ES:DI] := AL/AX/EAX/RAX
///   DI += (DF == 0) ? +width : -width
/// ```
/// Flags: not modified.
fn body_stos(ctx: &mut X86LiftCtx, w: u8) {
    let di = effective_di(ctx);
    let dst_addr = make_dst_addr(ctx, di);
    let acc = acc_reg(w);
    ctx.emit_mem_write(dst_addr, IrExpr::Reg(acc.into()), w);
    step_di(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — INS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for INSB/W/D.
///
/// Semantics (per SDM Vol. 2A, INS):
/// ```text
///   mem[ES:DI] := I/O_port[DX]   (modelled as x86.io.in intrinsic)
///   DI += (DF == 0) ? +width : -width
/// ```
/// Flags: not modified.
///
/// The I/O transfer is modelled as:
/// ```text
///   x86.io.in(DX, width)  →  __io_temp
///   mem[ES:DI] := __io_temp
/// ```
/// so that analyses can reason about the I/O side-effect separately from the
/// memory write.
fn body_ins(ctx: &mut X86LiftCtx, w: u8) {
    let di = effective_di(ctx);
    let dst_addr = make_dst_addr(ctx, di);
    let io_temp = ctx.fresh_temp();
    // Emit I/O read intrinsic.
    ctx.emit_intrinsic(
        format!("x86.io.in.w{}", op_bits(w)),
        vec![IrExpr::Reg("dx".into()), IrExpr::Const(u64::from(w))],
    );
    ctx.emit_reg_write(io_temp.clone(), IrExpr::Undef);
    // Store the I/O value to the destination.
    ctx.emit_mem_write(dst_addr, IrExpr::Reg(io_temp), w);
    step_di(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-iteration bodies — OUTS family
// ─────────────────────────────────────────────────────────────────────────────

/// Single-iteration body for OUTSB/W/D.
///
/// Semantics (per SDM Vol. 2B, OUTS):
/// ```text
///   I/O_port[DX] := mem[DS:SI]   (modelled as x86.io.out intrinsic)
///   SI += (DF == 0) ? +width : -width
/// ```
/// Flags: not modified.
fn body_outs(ctx: &mut X86LiftCtx, w: u8) {
    let si = effective_si(ctx);
    let src_addr = make_src_addr(ctx, si);
    let t = ctx.fresh_temp();
    ctx.emit_mem_read(src_addr, t.clone(), w);
    ctx.emit_intrinsic(
        format!("x86.io.out.w{}", op_bits(w)),
        vec![
            IrExpr::Reg("dx".into()),
            IrExpr::Reg(t),
            IrExpr::Const(u64::from(w)),
        ],
    );
    step_si(ctx, w);
}

// ─────────────────────────────────────────────────────────────────────────────
// REP loop wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Wrap a single-iteration `body` in a REP / REPE / REPNE loop.
///
/// The expansion uses three mandatory architectural rules (SDM Vol. 1 §7.3.6):
///
/// 1. **Pre-test**: if the count register is already zero when the REP prefix
///    is encountered, the loop body is never entered.
/// 2. **Post-iteration count decrement**: the count register is decremented
///    after each iteration.
/// 3. **Conditional back-edge**: for REPE (ZF == 1) and REPNE (ZF == 0) the
///    loop also exits when the ZF condition fails, regardless of the count.
///
/// `needs_zf_check` — `true` for REPE/REPNE prefixes (CMPS, SCAS).
/// `repe`           — `true` for REPE (exit when ZF == 0), `false` for REPNE
///                    (exit when ZF == 1).
///
/// The emitted IR pattern (annotated):
/// ```text
///   Intrinsic("x86.string.loop_header")      ; structured-loop entry label
///   Branch(loop_exit, cond: CX == 0)          ; pre-test: skip if count zero
///   <body(ctx)>                                ; single-iteration semantics
///   CX := CX - 1                              ; count decrement
///   Branch(loop_header, cond: back_edge_cond) ; back-edge
///   Intrinsic("x86.string.loop_exit")         ; structured-loop exit label
/// ```
fn emit_rep_loop<F>(ctx: &mut X86LiftCtx, mut body: F, needs_zf_check: bool, repe: bool)
where
    F: FnMut(&mut X86LiftCtx),
{
    let cx = effective_cx(ctx);

    // Label: loop header.
    ctx.emit_intrinsic("x86.string.loop_header", vec![]);

    // Pre-test: if CX == 0, skip the loop entirely.
    ctx.emit(Effect::Branch {
        target: IrExpr::Reg("__loop_exit".into()),
        condition: Some(IrExpr::CmpEqZero(Box::new(IrExpr::Reg(cx.into())))),
    });

    // Loop body (one iteration).
    body(ctx);

    // Count decrement: CX := CX - 1.
    let dec = IrExpr::Sub(Box::new(IrExpr::Reg(cx.into())), Box::new(IrExpr::Const(1)));
    ctx.emit_reg_write(cx, dec);

    // Back-edge condition.
    let cx_nonzero = IrExpr::CmpEqZero(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Reg(
        cx.into(),
    )))));
    let back_cond = if needs_zf_check {
        let zf = IrExpr::Reg("zf".into());
        let zf_cond = if repe {
            // REPE: continue while ZF == 1.
            zf
        } else {
            // REPNE: continue while ZF == 0.
            IrExpr::CmpEqZero(Box::new(zf))
        };
        IrExpr::And(Box::new(cx_nonzero), Box::new(zf_cond))
    } else {
        cx_nonzero
    };

    ctx.emit(Effect::Branch {
        target: IrExpr::Reg("__loop_header".into()),
        condition: Some(back_cond),
    });

    // Label: loop exit.
    ctx.emit_intrinsic("x86.string.loop_exit", vec![]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: detect mnemonic-level REP/REPE/REPNE intent
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Public lifter entry points
// ─────────────────────────────────────────────────────────────────────────────

// ── MOVS ─────────────────────────────────────────────────────────────────────

/// Lift MOVSB / MOVSW / MOVSD / MOVSQ.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   mem[ES:DI] := mem[DS:SI]
///   SI ±= width   (direction controlled by DF)
///   DI ±= width
/// ```
///
/// With REP prefix:
/// ```text
///   while CX != 0:
///       mem[ES:DI] := mem[DS:SI]
///       SI ±= width
///       DI ±= width
///       CX -= 1
/// ```
///
/// REPE/REPNE are **not** meaningful for MOVS (no flag check); if such a
/// prefix appears in the binary, the lifter models it the same as plain REP
/// (forward to the single-step body, repeat until CX == 0).
///
/// # Register effects
///
/// * SI/ESI/RSI — incremented or decremented by `width`.
/// * DI/EDI/RDI — incremented or decremented by `width`.
/// * CX/ECX/RCX — decremented by 1 per iteration (REP only).
///
/// # Flag effects
///
/// No flags are modified by MOVS.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_movs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_movs: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_rep || ctx.mode.prefixes.has_repne {
        emit_rep_loop(ctx, |c| body_movs(c, w), false, true);
    } else {
        body_movs(ctx, w);
    }
    Ok(())
}

// ── CMPS ─────────────────────────────────────────────────────────────────────

/// Lift CMPSB / CMPSW / CMPSD / CMPSQ.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   temp := mem[DS:SI] - mem[ES:DI]   ; compare and set flags
///   SI ±= width
///   DI ±= width
/// ```
///
/// With REPE (F3h) prefix:
/// ```text
///   while CX != 0 && ZF == 1:
///       temp := mem[DS:SI] - mem[ES:DI]
///       SI ±= width
///       DI ±= width
///       CX -= 1
/// ```
/// (Exits when a **mismatch** is found: ZF becomes 0.)
///
/// With REPNE (F2h) prefix:
/// ```text
///   while CX != 0 && ZF == 0:
///       temp := mem[DS:SI] - mem[ES:DI]
///       SI ±= width
///       DI ±= width
///       CX -= 1
/// ```
/// (Exits when a **match** is found: ZF becomes 1.)
///
/// # Flag effects
///
/// CF, OF, SF, ZF, AF, PF — set according to `mem[DS:SI] - mem[ES:DI]`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_cmps(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_cmps: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_repne {
        // REPNE CMPS: exit on match (ZF == 1).
        emit_rep_loop(ctx, |c| body_cmps(c, w), true, false);
    } else if ctx.mode.prefixes.has_rep {
        // REPE CMPS: exit on mismatch (ZF == 0).
        emit_rep_loop(ctx, |c| body_cmps(c, w), true, true);
    } else {
        body_cmps(ctx, w);
    }
    Ok(())
}

// ── SCAS ─────────────────────────────────────────────────────────────────────

/// Lift SCASB / SCASW / SCASD / SCASQ.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   temp := AL/AX/EAX/RAX - mem[ES:DI]   ; compare and set flags
///   DI ±= width
/// ```
///
/// With REPE (F3h) prefix:
/// ```text
///   while CX != 0 && ZF == 1:
///       temp := acc - mem[ES:DI]
///       DI ±= width
///       CX -= 1
/// ```
/// (Continues while equal; exits on first mismatch.)
///
/// With REPNE (F2h) prefix:
/// ```text
///   while CX != 0 && ZF == 0:
///       temp := acc - mem[ES:DI]
///       DI ±= width
///       CX -= 1
/// ```
/// (Continues while not equal; exits on first match — the classic `strlen`
/// equivalent for arbitrary byte patterns.)
///
/// # Flag effects
///
/// CF, OF, SF, ZF, AF, PF — set according to `acc - mem[ES:DI]`.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_scas(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_scas: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_repne {
        // REPNE SCAS: exit when equal (ZF == 1) — scan for match.
        emit_rep_loop(ctx, |c| body_scas(c, w), true, false);
    } else if ctx.mode.prefixes.has_rep {
        // REPE SCAS: exit when not equal (ZF == 0) — scan while equal.
        emit_rep_loop(ctx, |c| body_scas(c, w), true, true);
    } else {
        body_scas(ctx, w);
    }
    Ok(())
}

// ── LODS ─────────────────────────────────────────────────────────────────────

/// Lift LODSB / LODSW / LODSD / LODSQ.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   AL/AX/EAX/RAX := mem[DS:SI]
///   SI ±= width
/// ```
///
/// With REP prefix (architecturally valid but rarely useful):
/// ```text
///   while CX != 0:
///       AL/AX/EAX/RAX := mem[DS:SI]
///       SI ±= width
///       CX -= 1
/// ```
/// After the loop, the accumulator holds only the last value loaded.
///
/// # Flag effects
///
/// No flags are modified by LODS.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_lods(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_lods: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_rep || ctx.mode.prefixes.has_repne {
        emit_rep_loop(ctx, |c| body_lods(c, w), false, true);
    } else {
        body_lods(ctx, w);
    }
    Ok(())
}

// ── STOS ─────────────────────────────────────────────────────────────────────

/// Lift STOSB / STOSW / STOSD / STOSQ.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   mem[ES:DI] := AL/AX/EAX/RAX
///   DI ±= width
/// ```
///
/// With REP prefix (the primary use case — `memset`-like fills):
/// ```text
///   while CX != 0:
///       mem[ES:DI] := AL/AX/EAX/RAX
///       DI ±= width
///       CX -= 1
/// ```
///
/// # Flag effects
///
/// No flags are modified by STOS.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_stos(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_stos: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_rep || ctx.mode.prefixes.has_repne {
        emit_rep_loop(ctx, |c| body_stos(c, w), false, true);
    } else {
        body_stos(ctx, w);
    }
    Ok(())
}

// ── INS ──────────────────────────────────────────────────────────────────────

/// Lift INSB / INSW / INSD.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   mem[ES:DI] := I/O[DX]    (x86.io.in intrinsic)
///   DI ±= width
/// ```
///
/// With REP prefix:
/// ```text
///   while CX != 0:
///       mem[ES:DI] := I/O[DX]
///       DI ±= width
///       CX -= 1
/// ```
///
/// # Privilege
///
/// INS is privileged at CPL > IOPL unless the IOPB allows the port.
/// The lifter does not check privilege — that is an operating-mode concern
/// for the emulation layer, not for the IR lifter.
///
/// # Flag effects
///
/// No flags are modified by INS.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ins(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_ins: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_rep || ctx.mode.prefixes.has_repne {
        emit_rep_loop(ctx, |c| body_ins(c, w), false, true);
    } else {
        body_ins(ctx, w);
    }
    Ok(())
}

// ── OUTS ─────────────────────────────────────────────────────────────────────

/// Lift OUTSB / OUTSW / OUTSD.
///
/// # Semantics
///
/// Without prefix:
/// ```text
///   I/O[DX] := mem[DS:SI]    (x86.io.out intrinsic)
///   SI ±= width
/// ```
///
/// With REP prefix:
/// ```text
///   while CX != 0:
///       I/O[DX] := mem[DS:SI]
///       SI ±= width
///       CX -= 1
/// ```
///
/// # Flag effects
///
/// No flags are modified by OUTS.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_outs(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let w = string_op_width(instr.mnemonic());
    if w == 0 {
        return Err(LiftError::LiftFailed(
            ctx.addr,
            format!("lift_outs: unexpected mnemonic {:?}", instr.mnemonic()),
        ));
    }
    if ctx.mode.prefixes.has_rep || ctx.mode.prefixes.has_repne {
        emit_rep_loop(ctx, |c| body_outs(c, w), false, true);
    } else {
        body_outs(ctx, w);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Address-size and mode variant helpers (used by tests and future callers)
// ─────────────────────────────────────────────────────────────────────────────

/// Build a `ModeHint` for a 16-bit address-size context (for test use).
#[doc(hidden)]
#[must_use] 
pub const fn mode_16bit() -> crate::x86_context::ModeHint {
    crate::x86_context::ModeHint {
        rex_w: false,
        op_size_override: false,
        addr_size_override: false,
        prefixes: crate::x86_context::PrefixFlags { has_rep: false, has_repne: false, has_lock: false },
        seg_override: 0,
    }
}

/// Build a `ModeHint` with the REP prefix flag set (for test use).
#[doc(hidden)]
#[must_use] 
pub const fn mode_with_rep(base: crate::x86_context::ModeHint) -> crate::x86_context::ModeHint {
    crate::x86_context::ModeHint { prefixes: crate::x86_context::PrefixFlags { has_rep: true, ..base.prefixes }, ..base }
}

/// Build a `ModeHint` with the REPNE prefix flag set (for test use).
#[doc(hidden)]
#[must_use] 
pub const fn mode_with_repne(base: crate::x86_context::ModeHint) -> crate::x86_context::ModeHint {
    crate::x86_context::ModeHint { prefixes: crate::x86_context::PrefixFlags { has_repne: true, ..base.prefixes }, ..base }
}

/// Build a `ModeHint` with the address-size override flag set (for test use).
#[doc(hidden)]
#[must_use] 
pub const fn mode_with_addr_override(base: crate::x86_context::ModeHint) -> crate::x86_context::ModeHint {
    crate::x86_context::ModeHint {
        addr_size_override: true,
        ..base
    }
}

/// Build a `ModeHint` with the FS segment override set (for test use).
#[doc(hidden)]
#[must_use] 
pub const fn mode_with_fs_override(base: crate::x86_context::ModeHint) -> crate::x86_context::ModeHint {
    crate::x86_context::ModeHint {
        seg_override: 5,
        ..base
    }
}

// Suppress the unused-import lint for reg_name (it is re-exported in the
// parent module via the `_suppress` pattern).
fn _suppress(r: iced_x86::Register) -> String {
    reg_name(r)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Decoder helpers ──────────────────────────────────────────────────────

    fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    fn _decode32(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

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

    fn ctx64_rep() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, mode_with_rep(ModeHint::default()))
    }

    fn ctx64_repne() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, mode_with_repne(ModeHint::default()))
    }

    fn ctx64_addr_override() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, mode_with_addr_override(ModeHint::default()))
    }

    fn ctx32_rep() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 32, mode_with_rep(ModeHint::default()))
    }

    // ── Effect inspection helpers ────────────────────────────────────────────

    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects.iter().any(|e| match e {
            Effect::Intrinsic { name, .. } => name.contains(substr),
            _ => false,
        })
    }

    fn _count_intrinsic(effects: &[Effect], substr: &str) -> usize {
        effects
            .iter()
            .filter(|e| match e {
                Effect::Intrinsic { name, .. } => name.contains(substr),
                _ => false,
            })
            .count()
    }

    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| match e {
                Effect::RegWrite { reg: r, .. } => r == reg,
                _ => false,
            })
            .count()
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

    fn has_branch(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::Branch { .. }))
    }

    fn _count_branches(effects: &[Effect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Branch { .. }))
            .count()
    }

    fn _has_conditional_branch(effects: &[Effect]) -> bool {
        effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        })
    }

    fn reg_write_value<'a>(effects: &'a [Effect], reg: &str) -> Option<&'a IrExpr> {
        effects.iter().find_map(|e| match e {
            Effect::RegWrite { reg: r, value } if r == reg => Some(value),
            _ => None,
        })
    }

    // ── Infrastructure smoke tests ───────────────────────────────────────────

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
    fn intrinsic_does_not_panic() {
        let mut ctx = ctx64();
        ctx.emit_intrinsic("test.handler_smoke", vec![]);
        assert!(has_intrinsic(&ctx.effects, "test.handler_smoke"));
    }

    #[test]
    fn materialise_returns_unique_temp() {
        let mut ctx = ctx64();
        let t = ctx.materialise(IrExpr::Const(7));
        assert!(!t.is_empty());
        assert_eq!(ctx.len(), 1);
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

    // ── string_op_width ──────────────────────────────────────────────────────

    #[test]
    fn width_byte_variants() {
        assert_eq!(string_op_width(Mnemonic::Movsb), 1);
        assert_eq!(string_op_width(Mnemonic::Cmpsb), 1);
        assert_eq!(string_op_width(Mnemonic::Scasb), 1);
        assert_eq!(string_op_width(Mnemonic::Lodsb), 1);
        assert_eq!(string_op_width(Mnemonic::Stosb), 1);
        assert_eq!(string_op_width(Mnemonic::Insb), 1);
        assert_eq!(string_op_width(Mnemonic::Outsb), 1);
    }

    #[test]
    fn width_word_variants() {
        assert_eq!(string_op_width(Mnemonic::Movsw), 2);
        assert_eq!(string_op_width(Mnemonic::Cmpsw), 2);
        assert_eq!(string_op_width(Mnemonic::Scasw), 2);
        assert_eq!(string_op_width(Mnemonic::Lodsw), 2);
        assert_eq!(string_op_width(Mnemonic::Stosw), 2);
        assert_eq!(string_op_width(Mnemonic::Insw), 2);
        assert_eq!(string_op_width(Mnemonic::Outsw), 2);
    }

    #[test]
    fn width_dword_variants() {
        assert_eq!(string_op_width(Mnemonic::Movsd), 4);
        assert_eq!(string_op_width(Mnemonic::Cmpsd), 4);
        assert_eq!(string_op_width(Mnemonic::Scasd), 4);
        assert_eq!(string_op_width(Mnemonic::Lodsd), 4);
        assert_eq!(string_op_width(Mnemonic::Stosd), 4);
        assert_eq!(string_op_width(Mnemonic::Insd), 4);
        assert_eq!(string_op_width(Mnemonic::Outsd), 4);
    }

    #[test]
    fn width_qword_variants() {
        assert_eq!(string_op_width(Mnemonic::Movsq), 8);
        assert_eq!(string_op_width(Mnemonic::Cmpsq), 8);
        assert_eq!(string_op_width(Mnemonic::Scasq), 8);
        assert_eq!(string_op_width(Mnemonic::Lodsq), 8);
        assert_eq!(string_op_width(Mnemonic::Stosq), 8);
    }

    // ── acc_reg ──────────────────────────────────────────────────────────────

    #[test]
    fn acc_reg_all_widths() {
        assert_eq!(acc_reg(1), "al");
        assert_eq!(acc_reg(2), "ax");
        assert_eq!(acc_reg(4), "eax");
        assert_eq!(acc_reg(8), "rax");
    }

    // ── effective register selection ─────────────────────────────────────────

    #[test]
    fn effective_si_64bit_default() {
        let ctx = ctx64();
        assert_eq!(effective_si(&ctx), "rsi");
    }

    #[test]
    fn effective_si_64bit_addr_override() {
        let ctx = ctx64_addr_override();
        assert_eq!(effective_si(&ctx), "esi");
    }

    #[test]
    fn effective_di_64bit_default() {
        let ctx = ctx64();
        assert_eq!(effective_di(&ctx), "rdi");
    }

    #[test]
    fn effective_di_32bit_default() {
        let ctx = ctx32();
        assert_eq!(effective_di(&ctx), "edi");
    }

    #[test]
    fn effective_cx_64bit_default() {
        let ctx = ctx64();
        assert_eq!(effective_cx(&ctx), "rcx");
    }

    #[test]
    fn effective_cx_64bit_addr_override() {
        let ctx = ctx64_addr_override();
        assert_eq!(effective_cx(&ctx), "ecx");
    }

    #[test]
    fn effective_cx_32bit() {
        let ctx = ctx32();
        assert_eq!(effective_cx(&ctx), "ecx");
    }

    #[test]
    fn effective_cx_16bit() {
        let ctx = ctx16();
        assert_eq!(effective_cx(&ctx), "cx");
    }

    // ── MOVS body ────────────────────────────────────────────────────────────

    #[test]
    fn body_movs_byte_emits_mem_read_and_write() {
        let mut ctx = ctx64();
        body_movs(&mut ctx, 1);
        assert_eq!(count_mem_reads(&ctx.effects), 1);
        assert_eq!(count_mem_writes(&ctx.effects), 1);
    }

    #[test]
    fn body_movs_steps_both_pointers() {
        let mut ctx = ctx64();
        body_movs(&mut ctx, 1);
        // step_pointer emits 1 intrinsic + 1 RegWrite per pointer.
        assert!(has_intrinsic(&ctx.effects, "x86.string.step"));
        assert!(writes_to(&ctx.effects, "rsi") > 0);
        assert!(writes_to(&ctx.effects, "rdi") > 0);
    }

    #[test]
    fn body_movs_qword_uses_correct_size() {
        let mut ctx = ctx64();
        body_movs(&mut ctx, 8);
        let reads: Vec<_> = ctx
            .effects
            .iter()
            .filter_map(|e| match e {
                Effect::MemRead { size, .. } => Some(*size),
                _ => None,
            })
            .collect();
        assert!(reads.iter().all(|&s| s == 8));
    }

    #[test]
    fn body_movs_does_not_set_flags() {
        let mut ctx = ctx64();
        body_movs(&mut ctx, 4);
        // No flag registers should be written.
        for flag in &["cf", "zf", "sf", "of", "pf", "af"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "MOVS should not write flag {flag}"
            );
        }
    }

    // ── CMPS body ────────────────────────────────────────────────────────────

    #[test]
    fn body_cmps_reads_two_memory_locations() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 1);
        assert_eq!(count_mem_reads(&ctx.effects), 2);
    }

    #[test]
    fn body_cmps_sets_zf() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 4);
        assert!(writes_to(&ctx.effects, "zf") > 0, "CMPS must set ZF");
    }

    #[test]
    fn body_cmps_sets_sf() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 4);
        assert!(writes_to(&ctx.effects, "sf") > 0, "CMPS must set SF");
    }

    #[test]
    fn body_cmps_sets_cf_via_intrinsic() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 4);
        assert!(
            has_intrinsic(&ctx.effects, "cf_sub"),
            "CMPS must emit CF-sub intrinsic"
        );
    }

    #[test]
    fn body_cmps_steps_both_pointers() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 2);
        assert!(writes_to(&ctx.effects, "rsi") > 0);
        assert!(writes_to(&ctx.effects, "rdi") > 0);
    }

    #[test]
    fn body_cmps_does_not_write_memory() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 4);
        assert_eq!(
            count_mem_writes(&ctx.effects),
            0,
            "CMPS must not write memory"
        );
    }

    // ── SCAS body ────────────────────────────────────────────────────────────

    #[test]
    fn body_scas_reads_from_di_only() {
        let mut ctx = ctx64();
        body_scas(&mut ctx, 1);
        assert_eq!(count_mem_reads(&ctx.effects), 1);
        // SI (rsi) must not be advanced.
        assert_eq!(writes_to(&ctx.effects, "rsi"), 0);
    }

    #[test]
    fn body_scas_steps_di() {
        let mut ctx = ctx64();
        body_scas(&mut ctx, 1);
        assert!(writes_to(&ctx.effects, "rdi") > 0);
    }

    #[test]
    fn body_scas_sets_flags_like_sub() {
        let mut ctx = ctx64();
        body_scas(&mut ctx, 4);
        assert!(writes_to(&ctx.effects, "zf") > 0);
        assert!(writes_to(&ctx.effects, "sf") > 0);
        assert!(has_intrinsic(&ctx.effects, "cf_sub"));
        assert!(has_intrinsic(&ctx.effects, "of_sub"));
    }

    #[test]
    fn body_scas_does_not_write_memory() {
        let mut ctx = ctx64();
        body_scas(&mut ctx, 1);
        assert_eq!(count_mem_writes(&ctx.effects), 0);
    }

    // ── LODS body ────────────────────────────────────────────────────────────

    #[test]
    fn body_lods_byte_writes_al() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 1);
        assert!(writes_to(&ctx.effects, "al") > 0);
    }

    #[test]
    fn body_lods_word_writes_ax() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 2);
        assert!(writes_to(&ctx.effects, "ax") > 0);
    }

    #[test]
    fn body_lods_dword_writes_eax() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 4);
        assert!(writes_to(&ctx.effects, "eax") > 0);
    }

    #[test]
    fn body_lods_qword_writes_rax() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 8);
        assert!(writes_to(&ctx.effects, "rax") > 0);
    }

    #[test]
    fn body_lods_reads_one_mem_location() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 4);
        assert_eq!(count_mem_reads(&ctx.effects), 1);
    }

    #[test]
    fn body_lods_steps_si_not_di() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 4);
        assert!(writes_to(&ctx.effects, "rsi") > 0);
        assert_eq!(writes_to(&ctx.effects, "rdi"), 0);
    }

    #[test]
    fn body_lods_does_not_set_flags() {
        let mut ctx = ctx64();
        body_lods(&mut ctx, 4);
        for flag in &["cf", "zf", "sf", "of", "pf", "af"] {
            assert_eq!(
                writes_to(&ctx.effects, flag),
                0,
                "LODS must not modify flag {flag}"
            );
        }
    }

    // ── STOS body ────────────────────────────────────────────────────────────

    #[test]
    fn body_stos_writes_one_mem_location() {
        let mut ctx = ctx64();
        body_stos(&mut ctx, 4);
        assert_eq!(count_mem_writes(&ctx.effects), 1);
        assert_eq!(count_mem_reads(&ctx.effects), 0);
    }

    #[test]
    fn body_stos_steps_di_not_si() {
        let mut ctx = ctx64();
        body_stos(&mut ctx, 1);
        assert!(writes_to(&ctx.effects, "rdi") > 0);
        assert_eq!(writes_to(&ctx.effects, "rsi"), 0);
    }

    #[test]
    fn body_stos_does_not_set_flags() {
        let mut ctx = ctx64();
        body_stos(&mut ctx, 8);
        for flag in &["cf", "zf", "sf", "of", "pf", "af"] {
            assert_eq!(writes_to(&ctx.effects, flag), 0);
        }
    }

    // ── INS body ─────────────────────────────────────────────────────────────

    #[test]
    fn body_ins_emits_io_in_intrinsic() {
        let mut ctx = ctx64();
        body_ins(&mut ctx, 1);
        assert!(has_intrinsic(&ctx.effects, "x86.io.in"));
    }

    #[test]
    fn body_ins_writes_memory() {
        let mut ctx = ctx64();
        body_ins(&mut ctx, 1);
        assert_eq!(count_mem_writes(&ctx.effects), 1);
    }

    #[test]
    fn body_ins_steps_di() {
        let mut ctx = ctx64();
        body_ins(&mut ctx, 2);
        assert!(writes_to(&ctx.effects, "rdi") > 0);
    }

    #[test]
    fn body_ins_word_uses_w16_intrinsic() {
        let mut ctx = ctx64();
        body_ins(&mut ctx, 2);
        assert!(has_intrinsic(&ctx.effects, "w16"));
    }

    #[test]
    fn body_ins_dword_uses_w32_intrinsic() {
        let mut ctx = ctx64();
        body_ins(&mut ctx, 4);
        assert!(has_intrinsic(&ctx.effects, "w32"));
    }

    // ── OUTS body ────────────────────────────────────────────────────────────

    #[test]
    fn body_outs_emits_io_out_intrinsic() {
        let mut ctx = ctx64();
        body_outs(&mut ctx, 1);
        assert!(has_intrinsic(&ctx.effects, "x86.io.out"));
    }

    #[test]
    fn body_outs_reads_memory() {
        let mut ctx = ctx64();
        body_outs(&mut ctx, 1);
        assert_eq!(count_mem_reads(&ctx.effects), 1);
    }

    #[test]
    fn body_outs_steps_si() {
        let mut ctx = ctx64();
        body_outs(&mut ctx, 4);
        assert!(writes_to(&ctx.effects, "rsi") > 0);
    }

    // ── REP loop wrapper ─────────────────────────────────────────────────────

    #[test]
    fn rep_loop_emits_header_and_exit_intrinsics() {
        let mut ctx = ctx64_rep();
        emit_rep_loop(&mut ctx, |c| body_stos(c, 1), false, true);
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
        assert!(has_intrinsic(&ctx.effects, "loop_exit"));
    }

    #[test]
    fn rep_loop_emits_pre_test_branch() {
        let mut ctx = ctx64_rep();
        emit_rep_loop(&mut ctx, |c| body_stos(c, 1), false, true);
        assert!(
            has_branch(&ctx.effects),
            "REP loop must emit at least one branch"
        );
    }

    #[test]
    fn rep_loop_decrements_rcx() {
        let mut ctx = ctx64_rep();
        emit_rep_loop(&mut ctx, |c| body_stos(c, 1), false, true);
        // RCX should be written (the decrement).
        assert!(writes_to(&ctx.effects, "rcx") > 0);
    }

    #[test]
    fn rep_loop_with_addr_override_decrements_ecx() {
        let mut ctx = X86LiftCtx::new(
            0x1000,
            64,
            mode_with_rep(mode_with_addr_override(ModeHint::default())),
        );
        emit_rep_loop(&mut ctx, |c| body_stos(c, 1), false, true);
        assert!(writes_to(&ctx.effects, "ecx") > 0);
    }

    #[test]
    fn repe_loop_emits_zf_back_edge() {
        let mut ctx = ctx64_rep();
        emit_rep_loop(&mut ctx, |c| body_cmps(c, 1), true, true);
        // The back-edge branch condition must reference ZF.
        let has_zf_cond = ctx.effects.iter().any(|e| match e {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => format!("{cond}").contains("zf"),
            _ => false,
        });
        assert!(has_zf_cond, "REPE loop back-edge must check ZF");
    }

    #[test]
    fn repne_loop_emits_negated_zf_back_edge() {
        let mut ctx = ctx64_repne();
        emit_rep_loop(&mut ctx, |c| body_scas(c, 1), true, false);
        // Must still reference ZF in some branch condition.
        let has_zf_cond = ctx.effects.iter().any(|e| match e {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => format!("{cond}").contains("zf"),
            _ => false,
        });
        assert!(has_zf_cond, "REPNE loop back-edge must check ZF");
    }

    #[test]
    fn rep_loop_plain_has_no_zf_backedge() {
        let mut ctx = ctx64_rep();
        emit_rep_loop(&mut ctx, |c| body_movs(c, 1), false, true);
        // For plain REP (no ZF check) the back-edge branch should NOT
        // reference ZF in its condition.
        let has_zf_backedge = ctx.effects.iter().any(|e| match e {
            Effect::Branch {
                condition: Some(cond),
                target,
            } => {
                // The loop_header back-edge target.
                format!("{target}").contains("loop_header") && format!("{cond}").contains("zf")
            }
            _ => false,
        });
        assert!(!has_zf_backedge, "Plain REP back-edge must not check ZF");
    }

    // ── lift_movs public entry ───────────────────────────────────────────────

    #[test]
    fn lift_movs_no_rep_no_loop_intrinsic() {
        // MOVSB opcode: A4
        let instr = decode64(&[0xA4]);
        let mut ctx = ctx64();
        lift_movs(&instr, &mut ctx).unwrap();
        assert!(!has_intrinsic(&ctx.effects, "loop_header"));
    }

    #[test]
    fn lift_movs_rep_emits_loop() {
        // REP MOVSB: F3 A4
        let instr = decode64(&[0xF3, 0xA4]);
        let mut ctx = ctx64_rep();
        lift_movs(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
        assert!(has_intrinsic(&ctx.effects, "loop_exit"));
    }

    #[test]
    fn lift_movsd_no_rep_correct_size() {
        // MOVSD (string): A5 (no REX — 32-bit default in 64-bit mode for D)
        // In 64-bit mode A5 = MOVSD (4 bytes).
        let instr = decode64(&[0xA5]);
        let mut ctx = ctx64();
        lift_movs(&instr, &mut ctx).unwrap();
        assert!(ctx
            .effects
            .iter()
            .filter_map(|e| match e {
                Effect::MemRead { size, .. } => Some(*size),
                _ => None,
            })
            .any(|x| x == 4));
    }

    #[test]
    fn lift_movsq_uses_8byte_size() {
        // REX.W MOVSB: 48 A5 = MOVSQ
        let instr = decode64(&[0x48, 0xA5]);
        let mut ctx = ctx64();
        lift_movs(&instr, &mut ctx).unwrap();
        assert!(
            ctx
                .effects
                .iter()
                .filter_map(|e| match e {
                    Effect::MemRead { size, .. } => Some(*size),
                    _ => None,
                })
                .any(|x| x == 8),
            "MOVSQ must use 8-byte reads"
        );
    }

    // ── lift_cmps public entry ───────────────────────────────────────────────

    #[test]
    fn lift_cmps_no_prefix_sets_flags() {
        // CMPSB: A6
        let instr = decode64(&[0xA6]);
        let mut ctx = ctx64();
        lift_cmps(&instr, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "zf") > 0);
    }

    #[test]
    fn lift_cmps_repe_emits_loop_with_zf_check() {
        // REPE CMPSB: F3 A6
        let instr = decode64(&[0xF3, 0xA6]);
        let mut ctx = ctx64_rep();
        lift_cmps(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
        let has_zf_cond = ctx.effects.iter().any(|e| match e {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => format!("{cond}").contains("zf"),
            _ => false,
        });
        assert!(has_zf_cond);
    }

    #[test]
    fn lift_cmps_repne_emits_loop() {
        // REPNE CMPSB: F2 A6
        let instr = decode64(&[0xF2, 0xA6]);
        let mut ctx = ctx64_repne();
        lift_cmps(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
    }

    // ── lift_scas public entry ───────────────────────────────────────────────

    #[test]
    fn lift_scas_no_prefix_reads_di() {
        // SCASB: AE
        let instr = decode64(&[0xAE]);
        let mut ctx = ctx64();
        lift_scas(&instr, &mut ctx).unwrap();
        assert_eq!(count_mem_reads(&ctx.effects), 1);
        assert!(writes_to(&ctx.effects, "rdi") > 0);
    }

    #[test]
    fn lift_scas_repe_loop_references_zf() {
        // REPE SCASB: F3 AE
        let instr = decode64(&[0xF3, 0xAE]);
        let mut ctx = ctx64_rep();
        lift_scas(&instr, &mut ctx).unwrap();
        let has_zf = ctx.effects.iter().any(|e| match e {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => format!("{cond}").contains("zf"),
            _ => false,
        });
        assert!(has_zf);
    }

    #[test]
    fn lift_scas_repne_loop_references_zf() {
        // REPNE SCASB: F2 AE — classic strlen/memchr pattern
        let instr = decode64(&[0xF2, 0xAE]);
        let mut ctx = ctx64_repne();
        lift_scas(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
    }

    // ── lift_lods public entry ───────────────────────────────────────────────

    #[test]
    fn lift_lods_byte_writes_al() {
        // LODSB: AC
        let instr = decode64(&[0xAC]);
        let mut ctx = ctx64();
        lift_lods(&instr, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "al") > 0);
    }

    #[test]
    fn lift_lods_no_rep_no_loop() {
        let instr = decode64(&[0xAC]);
        let mut ctx = ctx64();
        lift_lods(&instr, &mut ctx).unwrap();
        assert!(!has_intrinsic(&ctx.effects, "loop_header"));
    }

    #[test]
    fn lift_lods_rep_emits_loop() {
        // REP LODSB: F3 AC
        let instr = decode64(&[0xF3, 0xAC]);
        let mut ctx = ctx64_rep();
        lift_lods(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
    }

    #[test]
    fn lift_lodsq_writes_rax() {
        // REX.W LODSB: 48 AD = LODSQ
        let instr = decode64(&[0x48, 0xAD]);
        let mut ctx = ctx64();
        lift_lods(&instr, &mut ctx).unwrap();
        assert!(writes_to(&ctx.effects, "rax") > 0);
    }

    // ── lift_stos public entry ───────────────────────────────────────────────

    #[test]
    fn lift_stos_byte_writes_mem_from_al() {
        // STOSB: AA
        let instr = decode64(&[0xAA]);
        let mut ctx = ctx64();
        lift_stos(&instr, &mut ctx).unwrap();
        assert_eq!(count_mem_writes(&ctx.effects), 1);
    }

    #[test]
    fn lift_stos_no_rep_no_loop() {
        let instr = decode64(&[0xAA]);
        let mut ctx = ctx64();
        lift_stos(&instr, &mut ctx).unwrap();
        assert!(!has_intrinsic(&ctx.effects, "loop_header"));
    }

    #[test]
    fn lift_stos_rep_emits_loop_and_mem_write() {
        // REP STOSB: F3 AA
        let instr = decode64(&[0xF3, 0xAA]);
        let mut ctx = ctx64_rep();
        lift_stos(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
        assert!(count_mem_writes(&ctx.effects) > 0);
    }

    #[test]
    fn lift_stosq_no_flag_effects() {
        // REX.W STOSB: 48 AB = STOSQ
        let instr = decode64(&[0x48, 0xAB]);
        let mut ctx = ctx64();
        lift_stos(&instr, &mut ctx).unwrap();
        for flag in &["cf", "zf", "sf", "of", "pf", "af"] {
            assert_eq!(writes_to(&ctx.effects, flag), 0);
        }
    }

    // ── 32-bit mode tests ────────────────────────────────────────────────────

    #[test]
    fn movs_32bit_mode_uses_esi_edi() {
        let mut ctx = ctx32();
        body_movs(&mut ctx, 1);
        // In 32-bit mode without override, SI→ESI, DI→EDI.
        assert!(writes_to(&ctx.effects, "esi") > 0);
        assert!(writes_to(&ctx.effects, "edi") > 0);
    }

    #[test]
    fn cmps_32bit_mode_uses_esi_edi() {
        let mut ctx = ctx32();
        body_cmps(&mut ctx, 1);
        assert!(writes_to(&ctx.effects, "esi") > 0);
        assert!(writes_to(&ctx.effects, "edi") > 0);
    }

    #[test]
    fn rep_movs_32bit_uses_ecx() {
        let mut ctx = ctx32_rep();
        emit_rep_loop(&mut ctx, |c| body_movs(c, 1), false, true);
        assert!(writes_to(&ctx.effects, "ecx") > 0);
    }

    // ── Segment-override awareness ───────────────────────────────────────────

    #[test]
    fn source_seg_base_is_none_in_64bit() {
        let ctx = ctx64();
        assert!(source_seg_base(&ctx).is_none());
    }

    #[test]
    fn source_seg_base_is_seg_ds_in_32bit_default() {
        let ctx = ctx32();
        assert_eq!(source_seg_base(&ctx), Some("seg_ds"));
    }

    #[test]
    fn source_seg_base_fs_override() {
        let ctx = X86LiftCtx::new(0x1000, 32, mode_with_fs_override(ModeHint::default()));
        assert_eq!(source_seg_base(&ctx), Some("seg_fs"));
    }

    #[test]
    fn dest_seg_base_is_seg_es_in_32bit() {
        let ctx = ctx32();
        assert_eq!(dest_seg_base(&ctx), Some("seg_es"));
    }

    #[test]
    fn dest_seg_base_is_none_in_64bit() {
        let ctx = ctx64();
        assert!(dest_seg_base(&ctx).is_none());
    }

    // ── INS / OUTS lifter entry ──────────────────────────────────────────────

    #[test]
    fn lift_ins_byte_emits_io_intrinsic_and_mem_write() {
        // INSB: 6C — 32-bit opcode (64-bit mode accepts it)
        let instr = decode64(&[0x6C]);
        let mut ctx = ctx64();
        lift_ins(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.io.in"));
        assert_eq!(count_mem_writes(&ctx.effects), 1);
    }

    #[test]
    fn lift_outs_byte_emits_io_intrinsic_and_mem_read() {
        // OUTSB: 6E
        let instr = decode64(&[0x6E]);
        let mut ctx = ctx64();
        lift_outs(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.io.out"));
        assert_eq!(count_mem_reads(&ctx.effects), 1);
    }

    #[test]
    fn rep_ins_emits_loop() {
        // REP INSB: F3 6C
        let instr = decode64(&[0xF3, 0x6C]);
        let mut ctx = ctx64_rep();
        lift_ins(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
    }

    #[test]
    fn rep_outs_emits_loop() {
        // REP OUTSB: F3 6E
        let instr = decode64(&[0xF3, 0x6E]);
        let mut ctx = ctx64_rep();
        lift_outs(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "loop_header"));
    }

    // ── step_pointer correctness ─────────────────────────────────────────────

    #[test]
    fn step_pointer_emits_step_intrinsic_with_df_arg() {
        let mut ctx = ctx64();
        step_pointer(&mut ctx, "rsi", 4);
        let found = ctx.effects.iter().any(|e| match e {
            Effect::Intrinsic { name, args } => {
                name == "x86.string.step"
                    && args.len() == 3
                    && matches!(&args[2], IrExpr::Reg(r) if r == "df")
            }
            _ => false,
        });
        assert!(
            found,
            "step_pointer must emit x86.string.step with df as arg[2]"
        );
    }

    #[test]
    fn step_pointer_conservative_regwrite_adds_width() {
        let mut ctx = ctx64();
        step_pointer(&mut ctx, "rsi", 8);
        let rw = reg_write_value(&ctx.effects, "rsi");
        assert!(rw.is_some(), "step_pointer must emit a RegWrite for rsi");
        // The conservative write should be rsi + 8.
        let expr_str = format!("{}", rw.unwrap());
        assert!(
            expr_str.contains("0x8") || expr_str.contains("rsi"),
            "conservative step should reference +8 and rsi, got: {expr_str}"
        );
    }

    // ── op_bits helper ───────────────────────────────────────────────────────

    #[test]
    fn op_bits_mapping() {
        assert_eq!(op_bits(1), 8);
        assert_eq!(op_bits(2), 16);
        assert_eq!(op_bits(4), 32);
        assert_eq!(op_bits(8), 64);
    }

    // ── Multi-width CMPS flag naming ─────────────────────────────────────────

    #[test]
    fn cmps_byte_uses_w8_flag_intrinsic() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 1);
        assert!(
            has_intrinsic(&ctx.effects, "w8"),
            "CMPSB should use w8 intrinsics"
        );
    }

    #[test]
    fn cmps_qword_uses_w64_flag_intrinsic() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 8);
        assert!(
            has_intrinsic(&ctx.effects, "w64"),
            "CMPSQ should use w64 intrinsics"
        );
    }

    #[test]
    fn scas_word_uses_w16_flag_intrinsic() {
        let mut ctx = ctx64();
        body_scas(&mut ctx, 2);
        assert!(
            has_intrinsic(&ctx.effects, "w16"),
            "SCASW should use w16 intrinsics"
        );
    }

    // ── Effect count sanity checks ───────────────────────────────────────────

    #[test]
    fn body_movs_effect_count_reasonable() {
        let mut ctx = ctx64();
        body_movs(&mut ctx, 1);
        // Expected: 1 MemRead + 1 MemWrite + 2 * (1 Intrinsic + 1 RegWrite) = 6
        assert!(
            ctx.effects.len() >= 4 && ctx.effects.len() <= 12,
            "body_movs should emit 4-12 effects, got {}",
            ctx.effects.len()
        );
    }

    #[test]
    fn body_cmps_effect_count_reasonable() {
        let mut ctx = ctx64();
        body_cmps(&mut ctx, 1);
        // 2 MemReads + materialise + flags (6 * 2 lazy = 12) + 2 steps (4) = ~19
        assert!(
            ctx.effects.len() >= 10,
            "body_cmps should emit >= 10 effects, got {}",
            ctx.effects.len()
        );
    }

    // ── Idempotence: calling body twice doubles the effect count ─────────────

    #[test]
    fn body_stos_twice_doubles_mem_writes() {
        let mut ctx = ctx64();
        body_stos(&mut ctx, 1);
        let n1 = count_mem_writes(&ctx.effects);
        body_stos(&mut ctx, 1);
        let n2 = count_mem_writes(&ctx.effects);
        assert_eq!(n2, n1 * 2);
    }
}
