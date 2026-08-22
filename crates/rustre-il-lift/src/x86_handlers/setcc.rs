//!`SETcc`c instruction handlers —  x86/x64 conditional byte-set operations.
//!
//! # Instruction family overview
//!
//! `SETcc` writes the value `1` (condition true) or `0` (condition false) to an
//! 8-bit destination operand (register or memory). The destination is always
//! exactly one byte regardless of the current operand-size prefix; a REX.W
//! prefix has no effect on the output width. The destination register is
//! zero-extended to the full register width on write (partial-register
//! semantics apply only to AH/BH/CH/DH which cannot be REX-encoded targets).
//!
//! # All 16 condition codes and their EFLAGS inputs
//!
//! | Mnemonic | Alias(es)     | Condition expression       | Flags read    |
//! |----------|---------------|----------------------------|---------------|
//! | SETO     | —"             | OF = 1                     | OF            |
//! | SETNO    | —"             | OF = 0                     | OF            |
//! | SETB     | SETC, SETNAE  | CF = 1                     | CF            |
//! | SETAE    | SETNB, SETNC  | CF = 0                     | CF            |
//! | SETE     | SETZ          | ZF = 1                     | ZF            |
//! | SETNE    | SETNZ         | ZF = 0                     | ZF            |
//! | SETBE    | SETNA         | CF = 1 OR ZF = 1           | CF, ZF        |
//! | SETA     | SETNBE        | CF = 0 AND ZF = 0          | CF, ZF        |
//! | SETS     | —"             | SF = 1                     | SF            |
//! | SETNS    | —"             | SF = 0                     | SF            |
//! | SETP     | SETPE         | PF = 1                     | PF            |
//! | SETNP    | SETPO         | PF = 0                     | PF            |
//! | SETL     | SETNGE        | SF â‰  OF                    | SF, OF        |
//! | SETGE    | SETNL         | SF = OF                    | SF, OF        |
//! | SETLE    | SETNG         | ZF = 1 OR SF â‰  OF          | ZF, SF, OF    |
//! | SETG     | SETNLE        | ZF = 0 AND SF = OF         | ZF, SF, OF    |
//!
//! # Encodings
//!
//! All `SETcc` instructions share a common two-byte opcode pattern:
//! `0F 9x /0` where `x` is the condition nibble (matching the low nibble of
//! the Jcc opcode family). The `/0` `ModRM` field selects the destination:
//!
//! - `mod=11` (reg field): 8-bit GPR destination (AL, CL, DL, BL, SPL, BPL,
//!   SIL, DIL with REX prefix; AH, CH, DH, BH without REX)
//! - `modâ‰ 11` (memory): 8-bit memory destination with any addressing mode
//!
//! REX prefix effects:
//! - REX.R: extends the `ModRM` reg field to access R8B—"R15B
//! - REX.X: extends the SIB index field
//! - REX.B: extends the `ModRM` r/m field or SIB base
//! - REX.W: present but ignored for `SETcc` (output is always 8-bit)
//!
//! # IR emission strategy
//!
//! Since `IrExpr` has no ternary/select primitive, we materialise the boolean
//! condition expression (which evaluates to 0 or 1 in the IR evaluator) and
//! write it directly to the destination. The `x86.setcc.<cc>` intrinsic is
//! emitted first so that dataflow analyses can observe the semantic intent;
//! the explicit `RegWrite`/`MemWrite` follows immediately as the concrete
//! effect. The condition expression tree precisely encodes the EFLAGS inputs
//! so that flag-liveness analysis can determine which flags are consumed.
//!
//! # EFLAGS
//!
//! `SETcc` reads flags but never writes them. No EFLAGS output effects are
//! emitted.

use crate::IrExpr;
use crate::LiftError;
use crate::x86_context::{FlagId, X86LiftCtx};
use crate::x86_flags::{ConditionCode, cond_expr};
use crate::x86_operand::{effective_address, reg_name};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Internal helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Map an iced-x86 `Mnemonic` for a `SETcc` instruction to the matching
/// `ConditionCode`. Returns `None` for any mnemonic that is not a `SETcc`.
///
/// This explicit match is preferred over `instr.condition_code()` when the
/// caller already knows the mnemonic: it avoids the extra virtual dispatch and
/// produces a compile-time-verifiable exhaustive table. Aliases are folded to
/// their canonical form (SETC â†' B, SETNC â†' Ae, SETZ â†' E, SETNZ â†' Ne).
#[must_use]
const fn cc_from_mnemonic(m: Mnemonic) -> Option<ConditionCode> {
    use ConditionCode as C;
    use Mnemonic as M;
    Some(match m {
        M::Seto                    => C::O,
        M::Setno                   => C::No,
        M::Setb  /* SETC/SETNAE */ => C::B,
        M::Setae /* SETNB/SETNC */ => C::Ae,
        M::Sete  /* SETZ        */ => C::E,
        M::Setne /* SETNZ       */ => C::Ne,
        M::Setbe /* SETNA       */ => C::Be,
        M::Seta  /* SETNBE      */ => C::A,
        M::Sets                    => C::S,
        M::Setns                   => C::Ns,
        M::Setp  /* SETPE       */ => C::P,
        M::Setnp /* SETPO       */ => C::Np,
        M::Setl  /* SETNGE      */ => C::L,
        M::Setge /* SETNL       */ => C::Ge,
        M::Setle /* SETNG       */ => C::Le,
        M::Setg  /* SETNLE      */ => C::G,
        _ => return None,
    })
}

/// Return the human-readable name string for a condition code. Used in
/// intrinsic names and IR text generation.
#[must_use]
const fn cc_name(cc: ConditionCode) -> &'static str {
    use ConditionCode as C;
    match cc {
        C::O => "o",
        C::No => "no",
        C::B => "b",
        C::Ae => "ae",
        C::E => "e",
        C::Ne => "ne",
        C::Be => "be",
        C::A => "a",
        C::S => "s",
        C::Ns => "ns",
        C::P => "p",
        C::Np => "np",
        C::L => "l",
        C::Ge => "ge",
        C::Le => "le",
        C::G => "g",
    }
}

/// Return a short English description of the condition for doc-comments and
/// IR annotation strings.
#[must_use]
const fn cc_description(cc: ConditionCode) -> &'static str {
    use ConditionCode as C;
    match cc {
        C::O => "overflow (OF=1)",
        C::No => "no overflow (OF=0)",
        C::B => "below / carry (CF=1)",
        C::Ae => "above or equal / no carry (CF=0)",
        C::E => "equal / zero (ZF=1)",
        C::Ne => "not equal / not zero (ZF=0)",
        C::Be => "below or equal (CF=1 OR ZF=1)",
        C::A => "above (CF=0 AND ZF=0)",
        C::S => "sign (SF=1)",
        C::Ns => "no sign (SF=0)",
        C::P => "parity even (PF=1)",
        C::Np => "parity odd (PF=0)",
        C::L => "less (SF!=OF)",
        C::Ge => "greater or equal (SF=OF)",
        C::Le => "less or equal (ZF=1 OR SF!=OF)",
        C::G => "greater (ZF=0 AND SF=OF)",
    }
}

/// Return the set of `FlagId`s that are _read_ by a given condition code.
/// Used by flag-liveness and dead-flag-write analyses to build precise
/// use-def chains through `SETcc` instructions.
#[must_use]
pub const fn cc_flags_read(cc: ConditionCode) -> &'static [FlagId] {
    use ConditionCode as C;
    use FlagId as F;
    match cc {
        C::O | C::No => &[F::Of],
        C::B | C::Ae => &[F::Cf],
        C::E | C::Ne => &[F::Zf],
        C::Be | C::A => &[F::Cf, F::Zf],
        C::S | C::Ns => &[F::Sf],
        C::P | C::Np => &[F::Pf],
        C::L | C::Ge => &[F::Sf, F::Of],
        C::Le | C::G => &[F::Zf, F::Sf, F::Of],
    }
}

/// Emit an `x86.setcc.<cc>` intrinsic followed by the 8-bit byte-set write to
/// a register destination.
///
/// The `reg` parameter is the iced-x86 `Register` decoded from the `ModRM`
/// byte. In 64-bit mode without a REX prefix the high-byte registers
/// (AH=0x24, BH=0x27, CH=0x25, DH=0x26) are accessible; with any REX prefix
/// they are replaced by the low-byte registers of RSP/RBP/RSI/RDI.
///
/// The IR emits a single `RegWrite` of the boolean condition expression.
/// Because 8-bit registers in 64-bit mode are partial-register writes, the
/// parent 64-bit register is NOT touched; only the byte register name is
/// written, which matches Binary Ninja's LLIL convention.
fn emit_setcc_reg(cc: ConditionCode, cond: IrExpr, reg: Register, ctx: &mut X86LiftCtx) {
    let name = cc_name(cc);
    let desc = cc_description(cc);
    // Intrinsic carries the condition expression for semantic analyses that
    // do not want to reconstruct it from the RegWrite tree.
    ctx.emit_intrinsic(
        format!("x86.setcc.{name}"),
        vec![cond.clone(), IrExpr::Reg(reg_name(reg))],
    );
    // Concrete effect: write the 0/1 boolean to the 8-bit register.
    let dest_name = reg_name(reg);
    ctx.emit_reg_write(dest_name, cond);
    // Append a textual annotation to ir_text for disassembly display.
    let _ = desc; // used via format in the intrinsic name already
}

/// Emit an `x86.setcc.<cc>` intrinsic followed by the 8-bit byte-set write to
/// a memory destination.
///
/// The effective address is computed from `instr`'s memory operand fields
/// (base + index*scale + displacement + optional segment base). The write
/// size is always 1 byte.
fn emit_setcc_mem(cc: ConditionCode, cond: IrExpr, addr: IrExpr, ctx: &mut X86LiftCtx) {
    let name = cc_name(cc);
    // Intrinsic carries both the condition and the address for pointer
    // analyses that track memory-destination SETcc patterns.
    ctx.emit_intrinsic(
        format!("x86.setcc.{name}"),
        vec![cond.clone(), addr.clone()],
    );
    // Concrete effect: 1-byte memory write.
    ctx.emit_mem_write(addr, cond, 1);
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Public entry points —" individual condition-code handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
//
// Each `lift_set<cc>` function handles exactly one condition code. The generic
// `lift_setcc` dispatcher calls into these after resolving the mnemonic.
// Having named functions per condition also allows future call-graph analyses
// to trivially identify SETcc sites by function name.

/// SETO —" Set byte if overflow.
///
/// Condition: OF = 1.
/// Writes 1 to destination if the Overflow Flag is set, 0 otherwise.
/// Typical use: capture signed-overflow status after ADD/SUB/IMUL.
///
/// Encoding: `0F 90 /0` (rm8).
/// Flags read: OF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_seto(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::O)
}

/// SETNO —" Set byte if no overflow.
///
/// Condition: OF = 0.
/// Writes 1 to destination if the Overflow Flag is clear, 0 otherwise.
///
/// Encoding: `0F 91 /0` (rm8).
/// Flags read: OF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setno(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::No)
}

/// SETB —" Set byte if below (unsigned less-than).
///
/// Condition: CF = 1.
/// Aliases: SETC (set if carry), SETNAE (set if not above or equal).
/// Writes 1 to destination if the Carry Flag is set, 0 otherwise.
/// Typical use: capture borrow/carry after unsigned subtraction or comparison.
///
/// Encoding: `0F 92 /0` (rm8).
/// Flags read: CF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setb(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::B)
}

/// SETAE —" Set byte if above or equal (unsigned â‰¥).
///
/// Condition: CF = 0.
/// Aliases: SETNB (set if not below), SETNC (set if no carry).
/// Writes 1 to destination if the Carry Flag is clear, 0 otherwise.
///
/// Encoding: `0F 93 /0` (rm8).
/// Flags read: CF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setae(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Ae)
}

/// SETE —" Set byte if equal / zero.
///
/// Condition: ZF = 1.
/// Alias: SETZ (set if zero).
/// Writes 1 to destination if the Zero Flag is set, 0 otherwise.
/// Typical use: capture equality test result after CMP/TEST.
///
/// Encoding: `0F 94 /0` (rm8).
/// Flags read: ZF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sete(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::E)
}

/// SETNE —" Set byte if not equal / not zero.
///
/// Condition: ZF = 0.
/// Alias: SETNZ (set if not zero).
/// Writes 1 to destination if the Zero Flag is clear, 0 otherwise.
///
/// Encoding: `0F 95 /0` (rm8).
/// Flags read: ZF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setne(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Ne)
}

/// SETBE —" Set byte if below or equal (unsigned â‰¤).
///
/// Condition: CF = 1 OR ZF = 1.
/// Alias: SETNA (set if not above).
/// Writes 1 to destination if either the Carry Flag or Zero Flag is set.
/// This is the compound unsigned â‰¤ condition: below (CF) or equal (ZF).
///
/// Encoding: `0F 96 /0` (rm8).
/// Flags read: CF, ZF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setbe(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Be)
}

/// SETA —" Set byte if above (unsigned >).
///
/// Condition: CF = 0 AND ZF = 0.
/// Alias: SETNBE (set if not below or equal).
/// Writes 1 to destination only when neither CF nor ZF is set.
/// This is the strict unsigned greater-than condition.
///
/// Encoding: `0F 97 /0` (rm8).
/// Flags read: CF, ZF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_seta(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::A)
}

/// SETS —" Set byte if sign.
///
/// Condition: SF = 1.
/// Writes 1 to destination if the Sign Flag is set (result was negative).
///
/// Encoding: `0F 98 /0` (rm8).
/// Flags read: SF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_sets(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::S)
}

/// SETNS —" Set byte if no sign.
///
/// Condition: SF = 0.
/// Writes 1 to destination if the Sign Flag is clear (result was non-negative).
///
/// Encoding: `0F 99 /0` (rm8).
/// Flags read: SF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setns(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Ns)
}

/// SETP —" Set byte if parity even.
///
/// Condition: PF = 1.
/// Alias: SETPE (set if parity even).
/// Writes 1 to destination if the Parity Flag is set (even number of 1-bits
/// in the low byte of the most recent result).
///
/// Encoding: `0F 9A /0` (rm8).
/// Flags read: PF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::P)
}

/// SETNP —" Set byte if parity odd.
///
/// Condition: PF = 0.
/// Alias: SETPO (set if parity odd).
/// Writes 1 to destination if the Parity Flag is clear (odd number of 1-bits
/// in the low byte of the most recent result).
///
/// Encoding: `0F 9B /0` (rm8).
/// Flags read: PF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setnp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Np)
}

/// SETL —" Set byte if less (signed <).
///
/// Condition: SF â‰  OF (i.e. SF XOR OF = 1).
/// Alias: SETNGE (set if not greater or equal).
/// Writes 1 to destination when the signed less-than relationship holds.
/// The XOR of SF and OF captures both the "positive overflow" case (SF=0,OF=1)
/// and the "negative overflow" case (SF=1,OF=0).
///
/// Encoding: `0F 9C /0` (rm8).
/// Flags read: SF, OF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setl(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::L)
}

/// SETGE —" Set byte if greater or equal (signed â‰¥).
///
/// Condition: SF = OF (i.e. SF XOR OF = 0).
/// Alias: SETNL (set if not less).
/// Writes 1 to destination when the signed greater-or-equal relationship holds.
///
/// Encoding: `0F 9D /0` (rm8).
/// Flags read: SF, OF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setge(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Ge)
}

/// SETLE —" Set byte if less or equal (signed â‰¤).
///
/// Condition: ZF = 1 OR SF â‰  OF.
/// Alias: SETNG (set if not greater).
/// Writes 1 to destination when either the result was zero (ZF) or the signed
/// less-than relationship holds (`SFÃ¢`‰ OF). This is the compound signed â‰¤ test.
///
/// Encoding: `0F 9E /0` (rm8).
/// Flags read: ZF, SF, OF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setle(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::Le)
}

/// SETG —" Set byte if greater (signed >).
///
/// Condition: ZF = 0 AND SF = OF.
/// Alias: SETNLE (set if not less or equal).
/// Writes 1 to destination only when the result was non-zero and the signed
/// greater-than relationship holds. This is the strict signed greater-than test.
///
/// Encoding: `0F 9F /0` (rm8).
/// Flags read: ZF, SF, OF. Flags written: none.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setg(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    lift_setcc_inner(instr, ctx, ConditionCode::G)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Core dispatcher —" called from mod.rs
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Unified `SETcc` dispatcher. Called from `lift_instruction` for all 16 `SETcc`
/// mnemonics (including aliases encoded as distinct iced-x86 mnemonics).
///
/// This function:
/// 1. Resolves the condition code from `instr.mnemonic()`.
/// 2. Builds the boolean condition expression using `cond_expr`.
/// 3. Dispatches to `lift_setcc_inner` which handles both register and memory
///    destination forms.
///
/// Alias handling: iced-x86 presents SETB/SETC/SETNAE as the single mnemonic
/// `Mnemonic::Setb`; all three assemble to the same opcode `0F 92`. Similarly
/// for the other alias groups. The `cc_from_mnemonic` table folds them.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_setcc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let cc = cc_from_mnemonic(instr.mnemonic())
        .or_else(|| ConditionCode::from_iced(instr.condition_code()))
        .ok_or_else(|| {
            LiftError::LiftFailed(
                ctx.addr,
                format!("unrecognised SETcc mnemonic: {:?}", instr.mnemonic()),
            )
        })?;
    lift_setcc_inner(instr, ctx, cc)
}

/// Inner implementation shared by all per-cc entry points and the dispatcher.
///
/// Handles the two destination forms:
///
/// **Register form** (`mod=11` in ModRM):
/// The condition expression is written directly to the 8-bit register named by
/// the `ModRM` reg field. In 64-bit mode with no REX prefix, AH/BH/CH/DH are
/// accessible; with any REX prefix, SPL/BPL/SIL/DIL replace them (iced-x86
/// already resolves this in `instr.op0_register()`).
///
/// **Memory form** (`modâ‰ 11` in ModRM):
/// The effective address is built from the memory operand fields
/// (base + index*scale + displacement), and the condition expression is stored
/// as a 1-byte memory write. Segment overrides (FS:, GS:, etc.) are folded
/// into the address via `effective_address()`.
///
/// REX.W is ignored —" output is always 8 bits.
/// LOCK prefix is invalid for `SETcc` (no lock bus cycle); we emit it as an
/// intrinsic annotation but do not enforce the fault (that is the job of the
/// emulator/validator layer above the lifter).
fn lift_setcc_inner(
    instr: &Instruction,
    ctx: &mut X86LiftCtx,
    cc: ConditionCode,
) -> Result<(), LiftError> {
    // Note any unusual prefixes.
    if ctx.mode.prefixes.has_lock {
        // LOCK + SETcc is undefined behaviour / #UD on real hardware.
        // We emit a warning intrinsic and continue lifting so that the
        // surrounding disassembly block is not truncated.
        ctx.emit_intrinsic("x86.setcc.lock_prefix_warning".to_string(), vec![]);
    }
    if ctx.mode.prefixes.has_rep || ctx.mode.prefixes.has_repne {
        // REP/REPE/REPNE are also invalid with SETcc, but some obfuscators
        // emit them as dead prefixes. Record but ignore.
        ctx.emit_intrinsic("x86.setcc.rep_prefix_warning".to_string(), vec![]);
    }

    // Build the condition expression. This is always a closed-form IrExpr
    // tree referencing the live flag registers (cf/zf/sf/of/pf).
    let cond = cond_expr(cc);

    // Dispatch on destination operand kind.
    match instr.op0_kind() {
        OpKind::Register => {
            let reg = instr.op0_register();
            emit_setcc_reg(cc, cond, reg, ctx);
        }
        OpKind::Memory => {
            let addr = effective_address(instr);
            emit_setcc_mem(cc, cond, addr, ctx);
        }
        other => {
            // SETcc only has rm8 operand forms; any other OpKind indicates a
            // decode error or a truncated/corrupt instruction stream.
            return Err(LiftError::LiftFailed(
                ctx.addr,
                format!(
                    "SETcc has unexpected operand kind {other:?} (expected Register or Memory)"
                ),
            ));
        }
    }
    Ok(())
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Explicit per-register helpers (used by peephole optimiser)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
//
// These functions emit a SETcc to a *known* register without going through the
// instruction decoder. The x86 optimiser and calling-convention recovery pass
// call these when they rebuild boolean expressions from longer sequences
// (e.g. a CMOV chain that can be sunk to a SETcc).

/// Emit SETO to an explicit 8-bit register without decoding an instruction.
pub fn emit_seto_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::O);
    emit_setcc_reg(ConditionCode::O, cond, reg, ctx);
}

/// Emit SETNO to an explicit 8-bit register.
pub fn emit_setno_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::No);
    emit_setcc_reg(ConditionCode::No, cond, reg, ctx);
}

/// Emit SETB (SETC) to an explicit 8-bit register.
pub fn emit_setb_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::B);
    emit_setcc_reg(ConditionCode::B, cond, reg, ctx);
}

/// Emit SETAE (SETNC) to an explicit 8-bit register.
pub fn emit_setae_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ae);
    emit_setcc_reg(ConditionCode::Ae, cond, reg, ctx);
}

/// Emit SETE (SETZ) to an explicit 8-bit register.
pub fn emit_sete_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::E);
    emit_setcc_reg(ConditionCode::E, cond, reg, ctx);
}

/// Emit SETNE (SETNZ) to an explicit 8-bit register.
pub fn emit_setne_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ne);
    emit_setcc_reg(ConditionCode::Ne, cond, reg, ctx);
}

/// Emit SETBE (SETNA) to an explicit 8-bit register.
pub fn emit_setbe_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Be);
    emit_setcc_reg(ConditionCode::Be, cond, reg, ctx);
}

/// Emit SETA (SETNBE) to an explicit 8-bit register.
pub fn emit_seta_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::A);
    emit_setcc_reg(ConditionCode::A, cond, reg, ctx);
}

/// Emit SETS to an explicit 8-bit register.
pub fn emit_sets_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::S);
    emit_setcc_reg(ConditionCode::S, cond, reg, ctx);
}

/// Emit SETNS to an explicit 8-bit register.
pub fn emit_setns_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ns);
    emit_setcc_reg(ConditionCode::Ns, cond, reg, ctx);
}

/// Emit SETP (SETPE) to an explicit 8-bit register.
pub fn emit_setp_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::P);
    emit_setcc_reg(ConditionCode::P, cond, reg, ctx);
}

/// Emit SETNP (SETPO) to an explicit 8-bit register.
pub fn emit_setnp_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Np);
    emit_setcc_reg(ConditionCode::Np, cond, reg, ctx);
}

/// Emit SETL (SETNGE) to an explicit 8-bit register.
pub fn emit_setl_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::L);
    emit_setcc_reg(ConditionCode::L, cond, reg, ctx);
}

/// Emit SETGE (SETNL) to an explicit 8-bit register.
pub fn emit_setge_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ge);
    emit_setcc_reg(ConditionCode::Ge, cond, reg, ctx);
}

/// Emit SETLE (SETNG) to an explicit 8-bit register.
pub fn emit_setle_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Le);
    emit_setcc_reg(ConditionCode::Le, cond, reg, ctx);
}

/// Emit SETG (SETNLE) to an explicit 8-bit register.
pub fn emit_setg_reg(reg: Register, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::G);
    emit_setcc_reg(ConditionCode::G, cond, reg, ctx);
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Explicit per-memory helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Emit SETE (SETZ) to an explicit memory address expression.
///
/// Used by the optimiser when folding `CMP + JE + MOV 0/1` sequences into
/// a single SETcc-like effect in the IR.
pub fn emit_sete_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::E);
    emit_setcc_mem(ConditionCode::E, cond, addr, ctx);
}

/// Emit SETNE (SETNZ) to an explicit memory address expression.
pub fn emit_setne_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ne);
    emit_setcc_mem(ConditionCode::Ne, cond, addr, ctx);
}

/// Emit SETB (SETC) to an explicit memory address expression.
pub fn emit_setb_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::B);
    emit_setcc_mem(ConditionCode::B, cond, addr, ctx);
}

/// Emit SETAE (SETNC) to an explicit memory address expression.
pub fn emit_setae_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ae);
    emit_setcc_mem(ConditionCode::Ae, cond, addr, ctx);
}

/// Emit SETBE to an explicit memory address expression.
pub fn emit_setbe_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Be);
    emit_setcc_mem(ConditionCode::Be, cond, addr, ctx);
}

/// Emit SETA to an explicit memory address expression.
pub fn emit_seta_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::A);
    emit_setcc_mem(ConditionCode::A, cond, addr, ctx);
}

/// Emit SETL to an explicit memory address expression.
pub fn emit_setl_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::L);
    emit_setcc_mem(ConditionCode::L, cond, addr, ctx);
}

/// Emit SETGE to an explicit memory address expression.
pub fn emit_setge_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Ge);
    emit_setcc_mem(ConditionCode::Ge, cond, addr, ctx);
}

/// Emit SETLE to an explicit memory address expression.
pub fn emit_setle_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::Le);
    emit_setcc_mem(ConditionCode::Le, cond, addr, ctx);
}

/// Emit SETG to an explicit memory address expression.
pub fn emit_setg_mem(addr: IrExpr, ctx: &mut X86LiftCtx) {
    let cond = cond_expr(ConditionCode::G);
    emit_setcc_mem(ConditionCode::G, cond, addr, ctx);
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Flag-read metadata table
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Returns a static description of the EFLAGS semantics for a `SETcc` condition.
///
/// This is used by the dead-flag-write analysis (`x86_analysis::dead_flag_writes`)
/// to mark flag register writes as live when they feed a downstream `SETcc`, and
/// by the pretty-printer to annotate IR output with flag-use information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetccFlagSemantics {
    /// Condition code this describes.
    pub cc: ConditionCode,
    /// Human-readable condition description.
    pub description: &'static str,
    /// Flags that must be live before this instruction executes.
    pub flags_read: &'static [FlagId],
    /// x86 opcode byte (low byte; high byte is always 0x0F).
    pub opcode_low: u8,
    /// Canonical mnemonic string.
    pub mnemonic: &'static str,
    /// Alias mnemonics (empty slice if none).
    pub aliases: &'static [&'static str],
}

/// Complete static table of all 16 `SETcc` variants with their metadata.
///
/// Entries are ordered by opcode (0x90—"0x9F) to allow O(1) lookup by
/// `opcode_low - 0x90` when decoding from raw bytes.
pub static SETCC_TABLE: &[SetccFlagSemantics] = &[
    SetccFlagSemantics {
        cc: ConditionCode::O,
        description: "Set if overflow (OF=1)",
        flags_read: &[FlagId::Of],
        opcode_low: 0x90,
        mnemonic: "seto",
        aliases: &[],
    },
    SetccFlagSemantics {
        cc: ConditionCode::No,
        description: "Set if no overflow (OF=0)",
        flags_read: &[FlagId::Of],
        opcode_low: 0x91,
        mnemonic: "setno",
        aliases: &[],
    },
    SetccFlagSemantics {
        cc: ConditionCode::B,
        description: "Set if below / carry (CF=1)",
        flags_read: &[FlagId::Cf],
        opcode_low: 0x92,
        mnemonic: "setb",
        aliases: &["setc", "setnae"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Ae,
        description: "Set if above or equal / no carry (CF=0)",
        flags_read: &[FlagId::Cf],
        opcode_low: 0x93,
        mnemonic: "setae",
        aliases: &["setnb", "setnc"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::E,
        description: "Set if equal / zero (ZF=1)",
        flags_read: &[FlagId::Zf],
        opcode_low: 0x94,
        mnemonic: "sete",
        aliases: &["setz"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Ne,
        description: "Set if not equal / not zero (ZF=0)",
        flags_read: &[FlagId::Zf],
        opcode_low: 0x95,
        mnemonic: "setne",
        aliases: &["setnz"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Be,
        description: "Set if below or equal (CF=1 OR ZF=1)",
        flags_read: &[FlagId::Cf, FlagId::Zf],
        opcode_low: 0x96,
        mnemonic: "setbe",
        aliases: &["setna"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::A,
        description: "Set if above (CF=0 AND ZF=0)",
        flags_read: &[FlagId::Cf, FlagId::Zf],
        opcode_low: 0x97,
        mnemonic: "seta",
        aliases: &["setnbe"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::S,
        description: "Set if sign (SF=1)",
        flags_read: &[FlagId::Sf],
        opcode_low: 0x98,
        mnemonic: "sets",
        aliases: &[],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Ns,
        description: "Set if no sign (SF=0)",
        flags_read: &[FlagId::Sf],
        opcode_low: 0x99,
        mnemonic: "setns",
        aliases: &[],
    },
    SetccFlagSemantics {
        cc: ConditionCode::P,
        description: "Set if parity even (PF=1)",
        flags_read: &[FlagId::Pf],
        opcode_low: 0x9A,
        mnemonic: "setp",
        aliases: &["setpe"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Np,
        description: "Set if parity odd (PF=0)",
        flags_read: &[FlagId::Pf],
        opcode_low: 0x9B,
        mnemonic: "setnp",
        aliases: &["setpo"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::L,
        description: "Set if less / not greater or equal (SF!=OF)",
        flags_read: &[FlagId::Sf, FlagId::Of],
        opcode_low: 0x9C,
        mnemonic: "setl",
        aliases: &["setnge"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Ge,
        description: "Set if greater or equal / not less (SF=OF)",
        flags_read: &[FlagId::Sf, FlagId::Of],
        opcode_low: 0x9D,
        mnemonic: "setge",
        aliases: &["setnl"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::Le,
        description: "Set if less or equal (ZF=1 OR SF!=OF)",
        flags_read: &[FlagId::Zf, FlagId::Sf, FlagId::Of],
        opcode_low: 0x9E,
        mnemonic: "setle",
        aliases: &["setng"],
    },
    SetccFlagSemantics {
        cc: ConditionCode::G,
        description: "Set if greater (ZF=0 AND SF=OF)",
        flags_read: &[FlagId::Zf, FlagId::Sf, FlagId::Of],
        opcode_low: 0x9F,
        mnemonic: "setg",
        aliases: &["setnle"],
    },
];

/// Look up the flag semantics entry for a given condition code.
/// Returns the entry from `SETCC_TABLE` in O(1) using the opcode-index encoding.
#[must_use]
pub fn setcc_semantics(cc: ConditionCode) -> &'static SetccFlagSemantics {
    use ConditionCode as C;
    let idx: usize = match cc {
        C::O => 0,
        C::No => 1,
        C::B => 2,
        C::Ae => 3,
        C::E => 4,
        C::Ne => 5,
        C::Be => 6,
        C::A => 7,
        C::S => 8,
        C::Ns => 9,
        C::P => 10,
        C::Np => 11,
        C::L => 12,
        C::Ge => 13,
        C::Le => 14,
        C::G => 15,
    };
    &SETCC_TABLE[idx]
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Condition-expression construction helpers (public, used by CMOVcc module)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Build the `IrExpr` for "OF = 1" (SETO / CMOVO condition).
#[must_use]
pub fn cond_o() -> IrExpr {
    IrExpr::Reg("of".into())
}

/// Build the `IrExpr` for "OF = 0" (SETNO / CMOVNO condition).
#[must_use]
pub fn cond_no() -> IrExpr {
    IrExpr::CmpEqZero(Box::new(IrExpr::Reg("of".into())))
}

/// Build the `IrExpr` for "CF = 1" (SETB / SETC / SETNAE condition).
#[must_use]
pub fn cond_b() -> IrExpr {
    IrExpr::Reg("cf".into())
}

/// Build the `IrExpr` for "CF = 0" (SETAE / SETNB / SETNC condition).
#[must_use]
pub fn cond_ae() -> IrExpr {
    IrExpr::CmpEqZero(Box::new(IrExpr::Reg("cf".into())))
}

/// Build the `IrExpr` for "ZF = 1" (SETE / SETZ condition).
#[must_use]
pub fn cond_e() -> IrExpr {
    IrExpr::Reg("zf".into())
}

/// Build the `IrExpr` for "ZF = 0" (SETNE / SETNZ condition).
#[must_use]
pub fn cond_ne() -> IrExpr {
    IrExpr::CmpEqZero(Box::new(IrExpr::Reg("zf".into())))
}

/// Build the `IrExpr` for "CF = 1 OR ZF = 1" (SETBE / SETNA condition).
#[must_use]
pub fn cond_be() -> IrExpr {
    IrExpr::Or(
        Box::new(IrExpr::Reg("cf".into())),
        Box::new(IrExpr::Reg("zf".into())),
    )
}

/// Build the `IrExpr` for "CF = 0 AND ZF = 0" (SETA / SETNBE condition).
#[must_use]
pub fn cond_a() -> IrExpr {
    IrExpr::And(
        Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Reg("cf".into())))),
        Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Reg("zf".into())))),
    )
}

/// Build the `IrExpr` for "SF = 1" (SETS condition).
#[must_use]
pub fn cond_s() -> IrExpr {
    IrExpr::Reg("sf".into())
}

/// Build the `IrExpr` for "SF = 0" (SETNS condition).
#[must_use]
pub fn cond_ns() -> IrExpr {
    IrExpr::CmpEqZero(Box::new(IrExpr::Reg("sf".into())))
}

/// Build the `IrExpr` for "PF = 1" (SETP / SETPE condition).
#[must_use]
pub fn cond_p() -> IrExpr {
    IrExpr::Reg("pf".into())
}

/// Build the `IrExpr` for "PF = 0" (SETNP / SETPO condition).
#[must_use]
pub fn cond_np() -> IrExpr {
    IrExpr::CmpEqZero(Box::new(IrExpr::Reg("pf".into())))
}

/// Build the `IrExpr` for "SF XOR OF" (SETL / SETNGE condition).
#[must_use]
pub fn cond_l() -> IrExpr {
    IrExpr::Xor(
        Box::new(IrExpr::Reg("sf".into())),
        Box::new(IrExpr::Reg("of".into())),
    )
}

/// Build the `IrExpr` for "NOT (SF XOR OF)" (SETGE / SETNL condition).
#[must_use]
pub fn cond_ge() -> IrExpr {
    IrExpr::CmpEqZero(Box::new(IrExpr::Xor(
        Box::new(IrExpr::Reg("sf".into())),
        Box::new(IrExpr::Reg("of".into())),
    )))
}

/// Build the `IrExpr` for "ZF = 1 OR (SF XOR OF)" (SETLE / SETNG condition).
#[must_use]
pub fn cond_le() -> IrExpr {
    IrExpr::Or(
        Box::new(IrExpr::Reg("zf".into())),
        Box::new(IrExpr::Xor(
            Box::new(IrExpr::Reg("sf".into())),
            Box::new(IrExpr::Reg("of".into())),
        )),
    )
}

/// Build the `IrExpr` for "ZF = 0 AND NOT (SF XOR OF)" (SETG / SETNLE condition).
#[must_use]
pub fn cond_g() -> IrExpr {
    IrExpr::And(
        Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Reg("zf".into())))),
        Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Xor(
            Box::new(IrExpr::Reg("sf".into())),
            Box::new(IrExpr::Reg("of".into())),
        )))),
    )
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_context::{FlagId, ModeHint, X86LiftCtx};
    use crate::x86_eval::{EvalValue, X86CpuState, exec_effects};
    use crate::{Effect, IrExpr};
    use iced_x86::{Decoder, DecoderOptions};

    // â"€â"€â"€ Decode helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

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

    // â"€â"€â"€ Effect inspection helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn _reg_writes(effects: &[Effect]) -> Vec<(&str, &IrExpr)> {
        effects
            .iter()
            .filter_map(|e| {
                if let Effect::RegWrite { reg, value } = e {
                    Some((reg.as_str(), value))
                } else {
                    None
                }
            })
            .collect()
    }

    fn writes_to(effects: &[Effect], reg: &str) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { reg: r, .. } if r == reg))
            .count()
    }

    fn has_mem_write(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::MemWrite { .. }))
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

    fn has_intrinsic(effects: &[Effect], substr: &str) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name.contains(substr)))
    }

    fn _intrinsic_names(effects: &[Effect]) -> Vec<&str> {
        effects
            .iter()
            .filter_map(|e| {
                if let Effect::Intrinsic { name, .. } = e {
                    Some(name.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    fn effect_count(effects: &[Effect]) -> usize {
        effects.len()
    }

    /// Evaluate the written value of the first `RegWrite` to `reg`.
    fn _eval_reg_write(effects: &[Effect], reg: &str) -> Option<EvalValue> {
        let mut s = X86CpuState::new();
        exec_effects(effects, &mut s);
        Some(s.get_reg(reg))
    }

    // â"€â"€â"€ Condition expression evaluation helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Set up a CPU state with specific flag values and evaluate a condition
    /// expression.
    fn eval_cond(cond: &IrExpr, cf: u64, zf: u64, sf: u64, of: u64, pf: u64) -> EvalValue {
        use crate::x86_eval::eval_expr;
        let mut s = X86CpuState::new();
        s.set_reg("cf", EvalValue::Concrete(cf));
        s.set_reg("zf", EvalValue::Concrete(zf));
        s.set_reg("sf", EvalValue::Concrete(sf));
        s.set_reg("of", EvalValue::Concrete(of));
        s.set_reg("pf", EvalValue::Concrete(pf));
        eval_expr(cond, &s)
    }

    fn is_one(v: EvalValue) -> bool {
        v == EvalValue::Concrete(1)
    }
    fn is_zero(v: EvalValue) -> bool {
        v == EvalValue::Concrete(0)
    }

    // â"€â"€â"€ Table completeness test â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn setcc_table_has_16_entries() {
        assert_eq!(SETCC_TABLE.len(), 16);
    }

    #[test]
    fn setcc_table_opcodes_are_sequential() {
        for (i, entry) in SETCC_TABLE.iter().enumerate() {
            assert_eq!(
                entry.opcode_low,
                0x90 + i as u8,
                "entry {} has wrong opcode",
                i
            );
        }
    }

    #[test]
    fn setcc_semantics_lookup_all_codes() {
        use ConditionCode as C;
        let all = [
            C::O,
            C::No,
            C::B,
            C::Ae,
            C::E,
            C::Ne,
            C::Be,
            C::A,
            C::S,
            C::Ns,
            C::P,
            C::Np,
            C::L,
            C::Ge,
            C::Le,
            C::G,
        ];
        for cc in all {
            let sem = setcc_semantics(cc);
            assert_eq!(sem.cc, cc);
            assert!(!sem.flags_read.is_empty());
        }
    }

    // â"€â"€â"€ cc_flags_read completeness â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cc_flags_read_seto_is_of() {
        assert_eq!(cc_flags_read(ConditionCode::O), &[FlagId::Of]);
    }

    #[test]
    fn cc_flags_read_setb_is_cf() {
        assert_eq!(cc_flags_read(ConditionCode::B), &[FlagId::Cf]);
    }

    #[test]
    fn cc_flags_read_sete_is_zf() {
        assert_eq!(cc_flags_read(ConditionCode::E), &[FlagId::Zf]);
    }

    #[test]
    fn cc_flags_read_setbe_is_cf_zf() {
        assert_eq!(cc_flags_read(ConditionCode::Be), &[FlagId::Cf, FlagId::Zf]);
    }

    #[test]
    fn cc_flags_read_setle_is_zf_sf_of() {
        assert_eq!(
            cc_flags_read(ConditionCode::Le),
            &[FlagId::Zf, FlagId::Sf, FlagId::Of]
        );
    }

    // â"€â"€â"€ Condition expression correctness â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cond_o_true_when_of_set() {
        assert!(is_one(eval_cond(&cond_o(), 0, 0, 0, 1, 0)));
        assert!(is_zero(eval_cond(&cond_o(), 0, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_no_true_when_of_clear() {
        assert!(is_one(eval_cond(&cond_no(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_no(), 0, 0, 0, 1, 0)));
    }

    #[test]
    fn cond_b_true_when_cf_set() {
        assert!(is_one(eval_cond(&cond_b(), 1, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_b(), 0, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_ae_true_when_cf_clear() {
        assert!(is_one(eval_cond(&cond_ae(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_ae(), 1, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_e_true_when_zf_set() {
        assert!(is_one(eval_cond(&cond_e(), 0, 1, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_e(), 0, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_ne_true_when_zf_clear() {
        assert!(is_one(eval_cond(&cond_ne(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_ne(), 0, 1, 0, 0, 0)));
    }

    #[test]
    fn cond_be_true_when_cf_or_zf() {
        // CF=1, ZF=0 â†' true
        assert!(is_one(eval_cond(&cond_be(), 1, 0, 0, 0, 0)));
        // CF=0, ZF=1 â†' true
        assert!(is_one(eval_cond(&cond_be(), 0, 1, 0, 0, 0)));
        // CF=1, ZF=1 â†' true
        assert!(is_one(eval_cond(&cond_be(), 1, 1, 0, 0, 0)));
        // CF=0, ZF=0 â†' false
        assert!(is_zero(eval_cond(&cond_be(), 0, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_a_true_when_cf_and_zf_both_clear() {
        assert!(is_one(eval_cond(&cond_a(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_a(), 1, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_a(), 0, 1, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_a(), 1, 1, 0, 0, 0)));
    }

    #[test]
    fn cond_s_true_when_sf_set() {
        assert!(is_one(eval_cond(&cond_s(), 0, 0, 1, 0, 0)));
        assert!(is_zero(eval_cond(&cond_s(), 0, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_ns_true_when_sf_clear() {
        assert!(is_one(eval_cond(&cond_ns(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_ns(), 0, 0, 1, 0, 0)));
    }

    #[test]
    fn cond_p_true_when_pf_set() {
        assert!(is_one(eval_cond(&cond_p(), 0, 0, 0, 0, 1)));
        assert!(is_zero(eval_cond(&cond_p(), 0, 0, 0, 0, 0)));
    }

    #[test]
    fn cond_np_true_when_pf_clear() {
        assert!(is_one(eval_cond(&cond_np(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_np(), 0, 0, 0, 0, 1)));
    }

    #[test]
    fn cond_l_true_when_sf_ne_of() {
        // SF=1, OF=0 â†' true
        assert!(is_one(eval_cond(&cond_l(), 0, 0, 1, 0, 0)));
        // SF=0, OF=1 â†' true
        assert!(is_one(eval_cond(&cond_l(), 0, 0, 0, 1, 0)));
        // SF=0, OF=0 â†' false
        assert!(is_zero(eval_cond(&cond_l(), 0, 0, 0, 0, 0)));
        // SF=1, OF=1 â†' false
        assert!(is_zero(eval_cond(&cond_l(), 0, 0, 1, 1, 0)));
    }

    #[test]
    fn cond_ge_true_when_sf_eq_of() {
        assert!(is_one(eval_cond(&cond_ge(), 0, 0, 0, 0, 0)));
        assert!(is_one(eval_cond(&cond_ge(), 0, 0, 1, 1, 0)));
        assert!(is_zero(eval_cond(&cond_ge(), 0, 0, 1, 0, 0)));
        assert!(is_zero(eval_cond(&cond_ge(), 0, 0, 0, 1, 0)));
    }

    #[test]
    fn cond_le_true_when_zf_set_or_sf_ne_of() {
        // ZF=1 alone â†' true
        assert!(is_one(eval_cond(&cond_le(), 0, 1, 0, 0, 0)));
        // SF!=OF â†' true
        assert!(is_one(eval_cond(&cond_le(), 0, 0, 1, 0, 0)));
        // Both â†' true
        assert!(is_one(eval_cond(&cond_le(), 0, 1, 1, 0, 0)));
        // Neither â†' false
        assert!(is_zero(eval_cond(&cond_le(), 0, 0, 0, 0, 0)));
        assert!(is_zero(eval_cond(&cond_le(), 0, 0, 1, 1, 0)));
    }

    #[test]
    fn cond_g_true_when_zf_clear_and_sf_eq_of() {
        // ZF=0, SF=OF=0 â†' true
        assert!(is_one(eval_cond(&cond_g(), 0, 0, 0, 0, 0)));
        // ZF=0, SF=OF=1 â†' true
        assert!(is_one(eval_cond(&cond_g(), 0, 0, 1, 1, 0)));
        // ZF=1 â†' false (even if SF=OF)
        assert!(is_zero(eval_cond(&cond_g(), 0, 1, 0, 0, 0)));
        // SF!=OF â†' false
        assert!(is_zero(eval_cond(&cond_g(), 0, 0, 1, 0, 0)));
    }

    // â"€â"€â"€ Instruction decode and lift: register destination â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// SETE AL —" `0F 94 C0`
    #[test]
    fn lift_sete_al_reg_form_emits_reg_write() {
        // SETE AL
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "al"), 1);
    }

    #[test]
    fn lift_sete_al_emits_setcc_intrinsic() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.e"));
    }

    /// SETNE BL —" `0F 95 C3`
    #[test]
    fn lift_setne_bl_emits_bl_write() {
        let instr = decode64(&[0x0F, 0x95, 0xC3]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "bl"), 1);
    }

    /// SETB CL —" `0F 92 C1`
    #[test]
    fn lift_setb_cl_emits_cl_write() {
        let instr = decode64(&[0x0F, 0x92, 0xC1]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "cl"), 1);
    }

    /// SETAE DL —" `0F 93 C2`
    #[test]
    fn lift_setae_dl_emits_dl_write() {
        let instr = decode64(&[0x0F, 0x93, 0xC2]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "dl"), 1);
    }

    /// SETO AL —" `0F 90 C0`
    #[test]
    fn lift_seto_al_emits_reg_write_and_intrinsic() {
        let instr = decode64(&[0x0F, 0x90, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "al"), 1);
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.o"));
    }

    /// SETNO AL —" `0F 91 C0`
    #[test]
    fn lift_setno_al_emits_intrinsic_no() {
        let instr = decode64(&[0x0F, 0x91, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.no"));
    }

    /// SETS AL —" `0F 98 C0`
    #[test]
    fn lift_sets_al_emits_intrinsic_s() {
        let instr = decode64(&[0x0F, 0x98, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.s"));
    }

    /// SETNS AL —" `0F 99 C0`
    #[test]
    fn lift_setns_al_emits_intrinsic_ns() {
        let instr = decode64(&[0x0F, 0x99, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.ns"));
    }

    /// SETP AL —" `0F 9A C0`
    #[test]
    fn lift_setp_al_emits_intrinsic_p() {
        let instr = decode64(&[0x0F, 0x9A, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.p"));
    }

    /// SETNP AL —" `0F 9B C0`
    #[test]
    fn lift_setnp_al_emits_intrinsic_np() {
        let instr = decode64(&[0x0F, 0x9B, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.np"));
    }

    /// SETL AL —" `0F 9C C0`
    #[test]
    fn lift_setl_al_emits_intrinsic_l() {
        let instr = decode64(&[0x0F, 0x9C, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.l"));
    }

    /// SETGE AL —" `0F 9D C0`
    #[test]
    fn lift_setge_al_emits_intrinsic_ge() {
        let instr = decode64(&[0x0F, 0x9D, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.ge"));
    }

    /// SETLE AL —" `0F 9E C0`
    #[test]
    fn lift_setle_al_emits_intrinsic_le() {
        let instr = decode64(&[0x0F, 0x9E, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.le"));
    }

    /// SETG AL —" `0F 9F C0`
    #[test]
    fn lift_setg_al_emits_intrinsic_g() {
        let instr = decode64(&[0x0F, 0x9F, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.g"));
    }

    /// SETBE AL —" `0F 96 C0`
    #[test]
    fn lift_setbe_al_emits_intrinsic_be() {
        let instr = decode64(&[0x0F, 0x96, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.be"));
    }

    /// SETA AL —" `0F 97 C0`
    #[test]
    fn lift_seta_al_emits_intrinsic_a() {
        let instr = decode64(&[0x0F, 0x97, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_intrinsic(&ctx.effects, "x86.setcc.a"));
    }

    // â"€â"€â"€ Memory destination form â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// SETE [RCX] —" `0F 94 01`
    #[test]
    fn lift_sete_mem_emits_mem_write() {
        let instr = decode64(&[0x0F, 0x94, 0x01]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_sete_mem_write_size_is_one_byte() {
        let instr = decode64(&[0x0F, 0x94, 0x01]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(mem_write_size(&ctx.effects), Some(1));
    }

    #[test]
    fn lift_setne_mem_emits_mem_write() {
        // SETNE [RCX]
        let instr = decode64(&[0x0F, 0x95, 0x01]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_mem_write(&ctx.effects));
    }

    #[test]
    fn lift_setl_mem_emits_mem_write() {
        // SETL [RCX]
        let instr = decode64(&[0x0F, 0x9C, 0x01]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_mem_write(&ctx.effects));
    }

    // â"€â"€â"€ 32-bit mode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn lift_sete_al_32bit_mode_emits_reg_write() {
        let instr = decode32(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx32();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "al"), 1);
    }

    #[test]
    fn lift_setb_mem_32bit_mode_emits_mem_write() {
        // SETB [ECX]
        let instr = decode32(&[0x0F, 0x92, 0x01]);
        let mut ctx = ctx32();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(has_mem_write(&ctx.effects));
        assert_eq!(mem_write_size(&ctx.effects), Some(1));
    }

    // â"€â"€â"€ Effect count sanity checks â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn lift_sete_reg_produces_exactly_two_effects() {
        // Intrinsic + RegWrite
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(effect_count(&ctx.effects), 2);
    }

    #[test]
    fn lift_sete_mem_produces_exactly_two_effects() {
        // Intrinsic + MemWrite
        let instr = decode64(&[0x0F, 0x94, 0x01]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(effect_count(&ctx.effects), 2);
    }

    // â"€â"€â"€ No flag writes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn no_flag_writes(effects: &[Effect]) -> bool {
        let flags = ["cf", "zf", "sf", "of", "pf", "af", "df"];
        !effects.iter().any(|e| {
            if let Effect::RegWrite { reg, .. } = e {
                flags.contains(&reg.as_str())
            } else {
                false
            }
        })
    }

    #[test]
    fn lift_sete_does_not_write_any_flags() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(no_flag_writes(&ctx.effects));
    }

    #[test]
    fn lift_setg_does_not_write_any_flags() {
        let instr = decode64(&[0x0F, 0x9F, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(no_flag_writes(&ctx.effects));
    }

    #[test]
    fn lift_setle_does_not_write_any_flags() {
        let instr = decode64(&[0x0F, 0x9E, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(no_flag_writes(&ctx.effects));
    }

    // â"€â"€â"€ Per-emit helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn emit_sete_reg_al_writes_al() {
        let mut ctx = ctx64();
        emit_sete_reg(Register::AL, &mut ctx);
        assert_eq!(writes_to(&ctx.effects, "al"), 1);
    }

    #[test]
    fn emit_setne_reg_bl_writes_bl() {
        let mut ctx = ctx64();
        emit_setne_reg(Register::BL, &mut ctx);
        assert_eq!(writes_to(&ctx.effects, "bl"), 1);
    }

    #[test]
    fn emit_setb_reg_cl_writes_cl() {
        let mut ctx = ctx64();
        emit_setb_reg(Register::CL, &mut ctx);
        assert_eq!(writes_to(&ctx.effects, "cl"), 1);
    }

    #[test]
    fn emit_setl_reg_dl_writes_dl() {
        let mut ctx = ctx64();
        emit_setl_reg(Register::DL, &mut ctx);
        assert_eq!(writes_to(&ctx.effects, "dl"), 1);
    }

    #[test]
    fn emit_setg_reg_al_writes_al() {
        let mut ctx = ctx64();
        emit_setg_reg(Register::AL, &mut ctx);
        assert_eq!(writes_to(&ctx.effects, "al"), 1);
    }

    #[test]
    fn emit_sete_mem_writes_memory() {
        let mut ctx = ctx64();
        emit_sete_mem(IrExpr::Const(0xDEAD_BEEF), &mut ctx);
        assert!(has_mem_write(&ctx.effects));
        assert_eq!(mem_write_size(&ctx.effects), Some(1));
    }

    #[test]
    fn emit_setl_mem_writes_memory() {
        let mut ctx = ctx64();
        emit_setl_mem(IrExpr::Reg("rax".into()), &mut ctx);
        assert!(has_mem_write(&ctx.effects));
    }

    // â"€â"€â"€ cc_name / cc_description coverage â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cc_name_all_variants_are_nonempty() {
        use ConditionCode as C;
        let all = [
            C::O,
            C::No,
            C::B,
            C::Ae,
            C::E,
            C::Ne,
            C::Be,
            C::A,
            C::S,
            C::Ns,
            C::P,
            C::Np,
            C::L,
            C::Ge,
            C::Le,
            C::G,
        ];
        for cc in all {
            assert!(!cc_name(cc).is_empty(), "cc_name empty for {cc:?}");
            assert!(
                !cc_description(cc).is_empty(),
                "cc_description empty for {cc:?}"
            );
        }
    }

    // â"€â"€â"€ cc_from_mnemonic round-trip â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cc_from_mnemonic_sete_returns_e() {
        assert_eq!(cc_from_mnemonic(Mnemonic::Sete), Some(ConditionCode::E));
    }

    #[test]
    fn cc_from_mnemonic_setne_returns_ne() {
        assert_eq!(cc_from_mnemonic(Mnemonic::Setne), Some(ConditionCode::Ne));
    }

    #[test]
    fn cc_from_mnemonic_setb_returns_b() {
        assert_eq!(cc_from_mnemonic(Mnemonic::Setb), Some(ConditionCode::B));
    }

    #[test]
    fn cc_from_mnemonic_setl_returns_l() {
        assert_eq!(cc_from_mnemonic(Mnemonic::Setl), Some(ConditionCode::L));
    }

    #[test]
    fn cc_from_mnemonic_setg_returns_g() {
        assert_eq!(cc_from_mnemonic(Mnemonic::Setg), Some(ConditionCode::G));
    }

    #[test]
    fn cc_from_mnemonic_nop_returns_none() {
        assert_eq!(cc_from_mnemonic(Mnemonic::Nop), None);
    }

    // â"€â"€â"€ ctx state tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn ctx_effects_empty_initially() {
        let ctx = ctx64();
        assert!(ctx.is_empty());
    }

    #[test]
    fn ctx_ir_text_updated_after_lift() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(!ctx.ir_text.is_empty());
    }

    #[test]
    fn ctx_fresh_temp_unique_across_calls() {
        let mut ctx = ctx64();
        let t1 = ctx.fresh_temp();
        let t2 = ctx.fresh_temp();
        assert_ne!(t1, t2);
    }

    // â"€â"€â"€ Eval integration: SETE reads ZF â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn lift_sete_al_evaluates_to_1_when_zf_set() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("zf", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_sete_al_evaluates_to_0_when_zf_clear() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("zf", EvalValue::Concrete(0));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0);
    }

    #[test]
    fn lift_setne_al_evaluates_to_0_when_zf_set() {
        let instr = decode64(&[0x0F, 0x95, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("zf", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0);
    }

    #[test]
    fn lift_setb_al_evaluates_to_1_when_cf_set() {
        let instr = decode64(&[0x0F, 0x92, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("cf", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_setl_al_evaluates_to_1_when_sf_ne_of() {
        // SF=1, OF=0 â†' SETL should write 1
        let instr = decode64(&[0x0F, 0x9C, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("sf", EvalValue::Concrete(1));
        s.set_reg("of", EvalValue::Concrete(0));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_setge_al_evaluates_to_1_when_sf_eq_of() {
        // SF=1, OF=1 â†' SETGE should write 1
        let instr = decode64(&[0x0F, 0x9D, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("sf", EvalValue::Concrete(1));
        s.set_reg("of", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_setle_al_evaluates_to_1_when_zf_set() {
        // ZF=1 alone satisfies SETLE
        let instr = decode64(&[0x0F, 0x9E, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("zf", EvalValue::Concrete(1));
        s.set_reg("sf", EvalValue::Concrete(0));
        s.set_reg("of", EvalValue::Concrete(0));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_setg_al_evaluates_to_0_when_zf_set() {
        // ZF=1 â†' SETG must write 0 even if SF=OF
        let instr = decode64(&[0x0F, 0x9F, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("zf", EvalValue::Concrete(1));
        s.set_reg("sf", EvalValue::Concrete(1));
        s.set_reg("of", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0);
    }

    #[test]
    fn lift_seto_al_evaluates_to_1_when_of_set() {
        let instr = decode64(&[0x0F, 0x90, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("of", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_sets_al_evaluates_to_1_when_sf_set() {
        let instr = decode64(&[0x0F, 0x98, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("sf", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_setp_al_evaluates_to_1_when_pf_set() {
        let instr = decode64(&[0x0F, 0x9A, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("pf", EvalValue::Concrete(1));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    // â"€â"€â"€ REX prefix: R8B destination â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// SETE R8B —" `41 0F 94 C0` (REX.B = 1, `ModRM` mod=11 reg=0 rm=0 â†' R8B)
    #[test]
    fn lift_sete_r8b_with_rex_prefix_emits_r8b_write() {
        let instr = decode64(&[0x41, 0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert_eq!(writes_to(&ctx.effects, "r8l"), 1);
    }

    // â"€â"€â"€ SETBE / SETA compound condition eval â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn lift_setbe_al_true_when_only_cf_set() {
        let instr = decode64(&[0x0F, 0x96, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("cf", EvalValue::Concrete(1));
        s.set_reg("zf", EvalValue::Concrete(0));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 1);
    }

    #[test]
    fn lift_seta_al_false_when_cf_set() {
        let instr = decode64(&[0x0F, 0x97, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();

        let mut s = X86CpuState::new();
        s.set_reg("cf", EvalValue::Concrete(1));
        s.set_reg("zf", EvalValue::Concrete(0));
        exec_effects(&ctx.effects, &mut s);
        s.assert_reg("al", 0);
    }

    // â"€â"€â"€ ir_text contains condition name â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn ir_text_contains_setcc_name_for_sete() {
        let instr = decode64(&[0x0F, 0x94, 0xC0]);
        let mut ctx = ctx64();
        lift_setcc(&instr, &mut ctx).unwrap();
        assert!(ctx.ir_text.contains("setcc"));
    }

    // â"€â"€â"€ Alias table entries have non-empty alias lists â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn setcc_table_aliases_for_setb() {
        let sem = setcc_semantics(ConditionCode::B);
        assert!(sem.aliases.contains(&"setc"));
        assert!(sem.aliases.contains(&"setnae"));
    }

    #[test]
    fn setcc_table_aliases_for_sete() {
        let sem = setcc_semantics(ConditionCode::E);
        assert!(sem.aliases.contains(&"setz"));
    }

    #[test]
    fn setcc_table_no_aliases_for_seto() {
        let sem = setcc_semantics(ConditionCode::O);
        assert!(sem.aliases.is_empty());
    }
}
