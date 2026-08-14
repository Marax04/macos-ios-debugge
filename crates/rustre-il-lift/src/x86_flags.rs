//! Flag-formula helpers for the x86/x64 lifter.
//!
//! ## Strategy
//!
//! `IrExpr` carries direct primitives for the three flags whose closed-form
//! is cheap and useful to downstream VSA: **ZF** (`CmpEqZero`), **PF**
//! (`Parity`) and **SF** (high-bit extraction). The remaining three flags —
//! **CF**, **OF**, **AF** — would require either an extended `IrExpr` with
//! width-aware unsigned/signed comparisons, or an inlined 10-node expression
//! tree per arithmetic instruction (the latter is what slows Capstone's
//! optional flag computation and what we want to avoid).
//!
//! The crate's `IrExpr` is closed, so the lifter takes the third route: it
//! emits an **`Effect::Intrinsic`** describing the formula (its name encodes
//! the operation and operand width) immediately followed by a `RegWrite` of
//! `IrExpr::Undef` into the flag register. MLIL passes can pattern-match
//! this idiom and either:
//!
//!   * expand the intrinsic into an explicit bitwise computation when a
//!     downstream `Jcc` actually reads the flag, or
//!   * eliminate both effects as dead code when no reader exists.
//!
//! This is the lazy-flag evaluation described in the architectural spec
//! and matches what Binary Ninja and Ghidra do in practice.
//!
//! ## Intrinsic naming
//!
//! ```text
//!   x86.flag.cf_add_w<W>      args = [a, b]
//!   x86.flag.cf_sub_w<W>      args = [a, b]
//!   x86.flag.cf_adc_w<W>      args = [a, b, cf_in]
//!   x86.flag.cf_sbb_w<W>      args = [a, b, cf_in]
//!   x86.flag.of_add_w<W>      args = [a, b, result]
//!   x86.flag.of_sub_w<W>      args = [a, b, result]
//!   x86.flag.af_add           args = [a, b]
//!   x86.flag.af_sub           args = [a, b]
//!   x86.flag.cf_shl_w<W>      args = [val, cnt]
//!   x86.flag.cf_shr_w<W>      args = [val, cnt]
//!   x86.flag.cf_sar_w<W>      args = [val, cnt]
//!   x86.flag.of_shl1_w<W>     args = [val]
//!   x86.flag.of_shr1_w<W>     args = [val]
//! ```
//!
//! Width is in **bits** to disambiguate signed-vs-unsigned semantics.

use crate::x86_context::{FlagId, X86LiftCtx};
use crate::{Effect, IrExpr};

// ─────────────────────────────────────────────────────────────────────────────
// Closed-form helpers (no intrinsic needed)
// ─────────────────────────────────────────────────────────────────────────────

/// ZF = (result == 0).
#[must_use]
pub fn zf_of(result: &IrExpr) -> IrExpr {
    IrExpr::CmpEqZero(Box::new(result.clone()))
}

/// SF = (high bit of result) — for an operand `bits` wide.
///
/// Formula: `(result >> (bits-1)) & 1`. We emit the `Shr` form alone (the
/// `& 1` is implied for 1-bit values in the IR; the parity/zero primitives
/// follow the same convention).
#[must_use]
pub fn sf_of(result: &IrExpr, bits: u8) -> IrExpr {
    let shift = u64::from(bits.saturating_sub(1));
    IrExpr::And(
        Box::new(IrExpr::Shr(
            Box::new(result.clone()),
            Box::new(IrExpr::Const(shift)),
        )),
        Box::new(IrExpr::Const(1)),
    )
}

/// PF = even parity of the low byte of the result.
#[must_use]
pub fn pf_of(result: &IrExpr) -> IrExpr {
    IrExpr::Parity(Box::new(result.clone()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Intrinsic-backed helpers
// ─────────────────────────────────────────────────────────────────────────────

fn intrinsic(ctx: &mut X86LiftCtx, name: &str, args: Vec<IrExpr>) {
    ctx.emit(Effect::Intrinsic {
        name: name.to_string(),
        args,
    });
}

fn flag_undef(ctx: &mut X86LiftCtx, flag: FlagId) {
    ctx.emit_flagset(flag, IrExpr::Undef);
}

// ─────────────────────────────────────────────────────────────────────────────
// Composite flag setters
// ─────────────────────────────────────────────────────────────────────────────

/// Emit the six EFLAGS updates produced by ADD `a + b = result`, with all
/// operands `bits` wide.
///
/// The handler is expected to have materialised `result` into a temporary
/// register (so that ZF/SF/PF reference the temp rather than re-evaluating
/// the addition).
pub fn set_flags_add(ctx: &mut X86LiftCtx, a: &IrExpr, b: &IrExpr, result: &IrExpr, bits: u8) {
    // CF and AF and OF: lazy intrinsics.
    intrinsic(
        ctx,
        &format!("x86.flag.cf_add_w{bits}"),
        vec![a.clone(), b.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, "x86.flag.af_add", vec![a.clone(), b.clone()]);
    flag_undef(ctx, FlagId::Af);
    intrinsic(
        ctx,
        &format!("x86.flag.of_add_w{bits}"),
        vec![a.clone(), b.clone(), result.clone()],
    );
    flag_undef(ctx, FlagId::Of);

    // ZF / SF / PF: closed form on the result temp.
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Emit the six EFLAGS updates produced by SUB / CMP `a - b = result`.
pub fn set_flags_sub(ctx: &mut X86LiftCtx, a: &IrExpr, b: &IrExpr, result: &IrExpr, bits: u8) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_sub_w{bits}"),
        vec![a.clone(), b.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, "x86.flag.af_sub", vec![a.clone(), b.clone()]);
    flag_undef(ctx, FlagId::Af);
    intrinsic(
        ctx,
        &format!("x86.flag.of_sub_w{bits}"),
        vec![a.clone(), b.clone(), result.clone()],
    );
    flag_undef(ctx, FlagId::Of);

    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Emit flag updates for ADC: same as ADD but the CF formula folds the
/// incoming carry.
pub fn set_flags_adc(
    ctx: &mut X86LiftCtx,
    a: &IrExpr,
    b: &IrExpr,
    cf_in: &IrExpr,
    result: &IrExpr,
    bits: u8,
) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_adc_w{bits}"),
        vec![a.clone(), b.clone(), cf_in.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, "x86.flag.af_add", vec![a.clone(), b.clone()]);
    flag_undef(ctx, FlagId::Af);
    intrinsic(
        ctx,
        &format!("x86.flag.of_add_w{bits}"),
        vec![a.clone(), b.clone(), result.clone()],
    );
    flag_undef(ctx, FlagId::Of);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Emit flag updates for SBB: same as SUB but the CF formula folds the
/// incoming borrow.
pub fn set_flags_sbb(
    ctx: &mut X86LiftCtx,
    a: &IrExpr,
    b: &IrExpr,
    cf_in: &IrExpr,
    result: &IrExpr,
    bits: u8,
) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_sbb_w{bits}"),
        vec![a.clone(), b.clone(), cf_in.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, "x86.flag.af_sub", vec![a.clone(), b.clone()]);
    flag_undef(ctx, FlagId::Af);
    intrinsic(
        ctx,
        &format!("x86.flag.of_sub_w{bits}"),
        vec![a.clone(), b.clone(), result.clone()],
    );
    flag_undef(ctx, FlagId::Of);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Emit the flag updates for INC: like ADD by 1 **but CF is not modified**.
pub fn set_flags_inc(ctx: &mut X86LiftCtx, a: &IrExpr, result: &IrExpr, bits: u8) {
    // CF preserved — no emission.
    intrinsic(ctx, "x86.flag.af_add", vec![a.clone(), IrExpr::Const(1)]);
    flag_undef(ctx, FlagId::Af);
    intrinsic(
        ctx,
        &format!("x86.flag.of_add_w{bits}"),
        vec![a.clone(), IrExpr::Const(1), result.clone()],
    );
    flag_undef(ctx, FlagId::Of);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Emit the flag updates for DEC: like SUB by 1 but CF is preserved.
pub fn set_flags_dec(ctx: &mut X86LiftCtx, a: &IrExpr, result: &IrExpr, bits: u8) {
    intrinsic(ctx, "x86.flag.af_sub", vec![a.clone(), IrExpr::Const(1)]);
    flag_undef(ctx, FlagId::Af);
    intrinsic(
        ctx,
        &format!("x86.flag.of_sub_w{bits}"),
        vec![a.clone(), IrExpr::Const(1), result.clone()],
    );
    flag_undef(ctx, FlagId::Of);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Emit the flag updates for NEG: like `0 - a`.
pub fn set_flags_neg(ctx: &mut X86LiftCtx, a: &IrExpr, result: &IrExpr, bits: u8) {
    set_flags_sub(ctx, &IrExpr::Const(0), a, result, bits);
}

/// Logical-op flag pattern (AND / OR / XOR / TEST):
/// CF := 0, OF := 0, AF := undefined, ZF/SF/PF computed on `result`.
pub fn set_flags_logic(ctx: &mut X86LiftCtx, result: &IrExpr, bits: u8) {
    ctx.emit_flagset(FlagId::Cf, IrExpr::Const(0));
    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    // AF is architecturally undefined after logical ops.
    intrinsic(ctx, "x86.flag.af_undef", vec![]);
    flag_undef(ctx, FlagId::Af);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// MUL / IMUL flag pattern (one-operand form):
/// CF and OF are set when the upper half is non-zero, the rest are undefined.
///
/// Takes the two **multiplicands** `a` and `b`, not a pre-computed half: the
/// upper half of a `bits`-wide multiply is not representable in a `bits`-wide
/// `IrExpr`, so the evaluator forms the full `2*bits` product itself. Passing
/// an already-truncated low half here would make CF/OF stuck-at-zero.
pub fn set_flags_mul(ctx: &mut X86LiftCtx, a: &IrExpr, b: &IrExpr, bits: u8) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_mul_w{bits}"),
        vec![a.clone(), b.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(
        ctx,
        &format!("x86.flag.of_mul_w{bits}"),
        vec![a.clone(), b.clone()],
    );
    flag_undef(ctx, FlagId::Of);
    // SF, ZF, AF, PF undefined per SDM.
    for f in [FlagId::Sf, FlagId::Zf, FlagId::Af, FlagId::Pf] {
        flag_undef(ctx, f);
    }
}

/// Shift-flag pattern:
/// CF := bit shifted out, OF := defined only for count==1, ZF/SF/PF on result.
pub fn set_flags_shift_left(
    ctx: &mut X86LiftCtx,
    val: &IrExpr,
    cnt: &IrExpr,
    result: &IrExpr,
    bits: u8,
) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_shl_w{bits}"),
        vec![val.clone(), cnt.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, &format!("x86.flag.of_shl1_w{bits}"), vec![val.clone()]);
    flag_undef(ctx, FlagId::Of);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

pub fn set_flags_shift_right(
    ctx: &mut X86LiftCtx,
    val: &IrExpr,
    cnt: &IrExpr,
    result: &IrExpr,
    bits: u8,
) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_shr_w{bits}"),
        vec![val.clone(), cnt.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, &format!("x86.flag.of_shr1_w{bits}"), vec![val.clone()]);
    flag_undef(ctx, FlagId::Of);
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

pub fn set_flags_shift_arith_right(
    ctx: &mut X86LiftCtx,
    val: &IrExpr,
    cnt: &IrExpr,
    result: &IrExpr,
    bits: u8,
) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_sar_w{bits}"),
        vec![val.clone(), cnt.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    // OF = 0 for SAR by 1.
    ctx.emit_flagset(FlagId::Of, IrExpr::Const(0));
    ctx.emit_flagset(FlagId::Zf, zf_of(result));
    ctx.emit_flagset(FlagId::Sf, sf_of(result, bits));
    ctx.emit_flagset(FlagId::Pf, pf_of(result));
}

/// Rotate flag pattern: CF := last bit rotated, OF := defined only for cnt==1.
pub fn set_flags_rotate_left(ctx: &mut X86LiftCtx, val: &IrExpr, cnt: &IrExpr, bits: u8) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_rol_w{bits}"),
        vec![val.clone(), cnt.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, &format!("x86.flag.of_rol1_w{bits}"), vec![val.clone()]);
    flag_undef(ctx, FlagId::Of);
}

pub fn set_flags_rotate_right(ctx: &mut X86LiftCtx, val: &IrExpr, cnt: &IrExpr, bits: u8) {
    intrinsic(
        ctx,
        &format!("x86.flag.cf_ror_w{bits}"),
        vec![val.clone(), cnt.clone()],
    );
    flag_undef(ctx, FlagId::Cf);
    intrinsic(ctx, &format!("x86.flag.of_ror1_w{bits}"), vec![val.clone()]);
    flag_undef(ctx, FlagId::Of);
}

// ─────────────────────────────────────────────────────────────────────────────
// Jcc condition expressions
// ─────────────────────────────────────────────────────────────────────────────

/// Build the boolean expression read by a Jcc / `SETcc` / `CMOVcc` for the given
/// condition code.
///
/// Returns `IrExpr::Undef` for unknown codes (no Jcc has more
/// than the 16 standard codes, so the fallback is never reached in practice).
#[must_use]
pub fn cond_expr(cc: ConditionCode) -> IrExpr {
    use ConditionCode as C;
    let cf = || IrExpr::Reg("cf".into());
    let zf = || IrExpr::Reg("zf".into());
    let sf = || IrExpr::Reg("sf".into());
    let of = || IrExpr::Reg("of".into());
    let pf = || IrExpr::Reg("pf".into());
    // Logical (not bitwise) negation of a 0/1 flag: `flag == 0`. Using
    // `IrExpr::Not` here would bit-flip a boolean (`!1 == 0xFFFF…FE`), which
    // reads as "true" under the evaluator's non-zero test and breaks the
    // negated condition codes (JNE, JAE, JNS, …).
    let not = |e: IrExpr| IrExpr::CmpEqZero(Box::new(e));
    let or = |l: IrExpr, r: IrExpr| IrExpr::Or(Box::new(l), Box::new(r));
    let and = |l: IrExpr, r: IrExpr| IrExpr::And(Box::new(l), Box::new(r));
    let xor = |l: IrExpr, r: IrExpr| IrExpr::Xor(Box::new(l), Box::new(r));

    match cc {
        C::O => of(),
        C::No => not(of()),
        C::B => cf(),
        C::Ae => not(cf()),
        C::E => zf(),
        C::Ne => not(zf()),
        C::Be => or(cf(), zf()),
        C::A => and(not(cf()), not(zf())),
        C::S => sf(),
        C::Ns => not(sf()),
        C::P => pf(),
        C::Np => not(pf()),
        C::L => xor(sf(), of()),
        C::Ge => not(xor(sf(), of())),
        C::Le => or(zf(), xor(sf(), of())),
        C::G => and(not(zf()), not(xor(sf(), of()))),
    }
}

/// 16 standard x86 condition codes (same encoding as the low nibble of the
/// Jcc / `SETcc` / `CMOVcc` opcode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionCode {
    /// JO  / SETO  / CMOVO
    O,
    /// JNO / SETNO / CMOVNO
    No,
    /// JB / JC / JNAE
    B,
    /// JAE / JNB / JNC
    Ae,
    /// JE / JZ
    E,
    /// JNE / JNZ
    Ne,
    /// JBE / JNA
    Be,
    /// JA / JNBE
    A,
    /// JS
    S,
    /// JNS
    Ns,
    /// JP / JPE
    P,
    /// JNP / JPO
    Np,
    /// JL / JNGE
    L,
    /// JGE / JNL
    Ge,
    /// JLE / JNG
    Le,
    /// JG / JNLE
    G,
}

impl ConditionCode {
    /// Map an iced-x86 `ConditionCode` (or equivalent) to ours. We mirror the
    /// iced enum manually because we don't want to leak iced as a public dep.
    #[must_use]
    pub const fn from_iced(cc: iced_x86::ConditionCode) -> Option<Self> {
        use iced_x86::ConditionCode as IC;
        Some(match cc {
            IC::o => Self::O,
            IC::no => Self::No,
            IC::b => Self::B,
            IC::ae => Self::Ae,
            IC::e => Self::E,
            IC::ne => Self::Ne,
            IC::be => Self::Be,
            IC::a => Self::A,
            IC::s => Self::S,
            IC::ns => Self::Ns,
            IC::p => Self::P,
            IC::np => Self::Np,
            IC::l => Self::L,
            IC::ge => Self::Ge,
            IC::le => Self::Le,
            IC::g => Self::G,
            IC::None => return None,
        })
    }
}
