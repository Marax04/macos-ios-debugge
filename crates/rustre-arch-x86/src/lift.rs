//! x86 / x86-64 â†' LLIL instruction lifter.
//!
//! This module translates instructions decoded by `iced-x86` into the
//! architecture-independent Low-Level IL (`LLIL`) defined in the
//! `rustre-il-llil` crate. The entry point is [`X86Lifter::lift`], which
//! consumes a decoded [`iced_x86::Instruction`] together with its address and
//! byte length and yields a sequence of [`LlilAnnotatedInstr`].
//!
//! # Design
//!
//! Lifting is organised around *category handlers*. The top-level
//! [`X86Lifter::lift_into`] dispatches on [`iced_x86::Mnemonic`] /
//! [`iced_x86::Code`] to a handler for each instruction family (data movement,
//! arithmetic, logic, shifts, control flow, string operations, conditional
//! moves, system, flag manipulation, and a subset of SSE/MMX moves).
//!
//! Operands are mapped to [`LlilExpr`] trees via [`X86Lifter::read_operand`]
//! and written back via [`X86Lifter::write_operand`], with memory operands
//! modelled explicitly through [`LlilExpr::Load`] / [`LlilInstruction::Store`]
//! using a full `base + index*scale + disp` (and RIP-relative) address
//! computation. Flag effects are emitted as discrete
//! [`LlilInstruction::SetFlag`] instructions so that data-flow analysis can see
//! exactly which flags an instruction defines.
//!
//! All temporaries are allocated through a monotonically increasing counter so
//! that a single machine instruction that needs scratch values (for example a
//! `cmpxchg` or a flag-affecting arithmetic op) produces well-formed,
//! non-aliasing temporaries.

use iced_x86::{
    // ⚠ `OpAccess` NON e' importato di proposito: i 18 usi nel file sono tutti
    // qualificati (`iced_x86::OpAccess::…`), quindi l'import restava morto e
    // produceva un warning permanente — ed e' cosi' che un warning VERO passa
    // inosservato (#391, stessa lezione del `#[test]` duplicato).
    Code, ConditionCode, Instruction as IcedInstruction, Mnemonic, OpKind, Register,
};
use rustre_core::address::Address;
use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilInstruction, LlilRegister, Size};

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Flag name constants
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Carry flag.
pub const FLAG_CF: &str = "cf";
/// Parity flag.
pub const FLAG_PF: &str = "pf";
/// Auxiliary (half-carry) flag.
pub const FLAG_AF: &str = "af";
/// Zero flag.
pub const FLAG_ZF: &str = "zf";
/// Sign flag.
pub const FLAG_SF: &str = "sf";
/// Overflow flag.
pub const FLAG_OF: &str = "of";
/// Direction flag.
pub const FLAG_DF: &str = "df";

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Register-name mapping
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Map an iced-x86 [`Register`] to its lower-case architectural name.
///
/// iced's `Debug` representation uses the canonical upper-case mnemonics
/// (`RAX`, `R8D`, `XMM0`, —¦); lower-casing yields the names used throughout the
/// `rustre` register tables.
#[must_use]
pub fn reg_name(reg: Register) -> String {
    // `to_ascii_lowercase()` on a `String` always allocates a second buffer;
    // `make_ascii_lowercase()` lowercases the `format!` buffer in place, so
    // this hot path (called per register operand) does one allocation
    // instead of two.
    let mut s = format!("{reg:?}");
    s.make_ascii_lowercase();
    s
}

/// 64-bit parent of an 8- or 16-bit GPR view, with the WIDTH of that view.
///
/// Unlike the 32-bit case, a narrow write does NOT clear the upper bits: `mov
/// $1, %cl` leaves bits 8..63 of RCX untouched. So these views cannot be
/// modelled by zero-extension — the write must be a read-modify-write that
/// preserves the rest of the parent, and the read must mask.
///
/// `spl`/`bpl`/`sp`/`bp` are ABSENT on purpose: the stack and frame pointers
/// are modelled separately and rewriting them would perturb frame recovery,
/// exactly as for [`gpr32_parent`].
///
/// `ah`/`ch`/`dh`/`bh` are ABSENT too: they alias bits 8..15, not the low
/// bits, so the same mask/shift shape does not describe them. Modelling them
/// wrongly would be worse than leaving them separate.
#[must_use]
pub fn gpr_narrow_parent(name: &str) -> Option<(&'static str, u32)> {
    Some(match name {
        // 8-bit low views.
        "al" => ("rax", 8),
        "cl" => ("rcx", 8),
        "dl" => ("rdx", 8),
        "bl" => ("rbx", 8),
        "sil" => ("rsi", 8),
        "dil" => ("rdi", 8),
        "r8b" => ("r8", 8),
        "r9b" => ("r9", 8),
        "r10b" => ("r10", 8),
        "r11b" => ("r11", 8),
        "r12b" => ("r12", 8),
        "r13b" => ("r13", 8),
        "r14b" => ("r14", 8),
        "r15b" => ("r15", 8),
        // ⚠ `iced_x86` spells the low byte of r8-r15 as `r8l`..`r15l`, NOT
        // `r8b`..`r15b`. Listing only the `b` form made the 8-bit aliasing miss
        // those registers ENTIRELY and in silence: measured, 844 of the 846
        // remaining `var_r*` locals read-but-never-written were exactly this
        // spelling. Both forms are accepted so the table cannot be defeated by
        // whichever name the disassembler happens to print.
        "r8l" => ("r8", 8),
        "r9l" => ("r9", 8),
        "r10l" => ("r10", 8),
        "r11l" => ("r11", 8),
        "r12l" => ("r12", 8),
        "r13l" => ("r13", 8),
        "r14l" => ("r14", 8),
        "r15l" => ("r15", 8),
        // 16-bit views.
        "ax" => ("rax", 16),
        "cx" => ("rcx", 16),
        "dx" => ("rdx", 16),
        "bx" => ("rbx", 16),
        "si" => ("rsi", 16),
        "di" => ("rdi", 16),
        "r8w" => ("r8", 16),
        "r9w" => ("r9", 16),
        "r10w" => ("r10", 16),
        "r11w" => ("r11", 16),
        "r12w" => ("r12", 16),
        "r13w" => ("r13", 16),
        "r14w" => ("r14", 16),
        "r15w" => ("r15", 16),
        _ => return None,
    })
}

/// Genitore a 64 bit di una vista «byte ALTO» (`ah`/`ch`/`dh`/`bh`).
///
/// Sono ESCLUSI da [`gpr_narrow_parent`] perche' aliasano i bit **8..15**, non
/// quelli bassi: la forma maschera/shift di quella tabella non li descrive.
/// Qui si modellano con lo SHIFT esplicito:
///   lettura   `(parent >> 8) & 0xFF`
///   scrittura `(parent & ~0xFF00) | ((value & 0xFF) << 8)`
/// Senza questo, `mov %cl, %ah` scrive un nome che nessuno legge e la
/// scrittura si PERDE — misurato su `pack_fields` (0x140001547), che percio'
/// restituisce solo il byte basso.
#[must_use]
pub fn gpr_high_byte_parent(name: &str) -> Option<&'static str> {
    Some(match name {
        "ah" => "rax",
        "ch" => "rcx",
        "dh" => "rdx",
        "bh" => "rbx",
        _ => return None,
    })
}

/// Gate OPT-IN per il modello dei byte alti: cambia l'IL, quindi va misurato.
fn high_byte_alias_enabled() -> bool {
    !matches!(std::env::var("RUSTRE_HIGHBYTE").as_deref(), Ok("0") | Ok("false"))
}

/// The 8/16-bit views of `rbp`, kept OUT of [`gpr_narrow_parent`] because "the
/// frame is modelled separately".
///
/// That exclusion costs fidelity when `rbp` is NOT a frame pointer, which is
/// common: `sample10_cs/sub_140004c40` does `mov %rax, %rbp` and then
/// `cmp %bpl, (%rbp)`, so `%bpl` is plainly the low byte of a general-purpose
/// `%rbp`. Leaving it out made it a register of its own that nothing writes, and
/// the emitted C read `*(__int64 *)fp - var_bpl` — TWO NAMES for one register,
/// one of them never defined. Measured: 81 such locals (`var_bpl` 69, `var_bp` 12).
///
/// ⚠ `spl`/`sp` stay out deliberately: stack-pointer tracking depends on clean
/// `sp` arithmetic, and a read-modify-write of `rsp` through its low byte would
/// disturb it. `rbp` carries no such invariant.
fn gpr_frame_narrow_parent(name: &str) -> Option<(&'static str, u32)> {
    match name {
        "bpl" => Some(("rbp", 8)),
        "bp" => Some(("rbp", 16)),
        _ => None,
    }
}

/// Default ON since the measured promotion. On the 12-binary corpus: locals read
/// but never written 1641/53511 -> 1560/53419, exactly the 81 predicted; path A
/// BYTE-IDENTICAL; `char rsp_frame[` still emitted, so frame recovery did NOT
/// regress — the blanket exclusion was more conservative than necessary;
/// distinct call targets unchanged (6585, none lost); arity 122/135; brace
/// balance 0; fixed-list recompilability 1199/1200 (same single pre-existing
/// failure). Read by hand: `*(__int64 *)fp - var_bpl` became
/// `*(__int64 *)v1 - (v1 & 255)` — one register on both sides, masked to its low
/// byte, which is exactly `cmp %bpl, (%rbp)`.
///
/// Set `RUSTRE_X86_BP_NARROW_ALIAS=0` to fall back.
fn frame_narrow_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("RUSTRE_X86_BP_NARROW_ALIAS").as_deref(),
            Ok("0") | Ok("false")
        )
    })
}

/// [`gpr_narrow_parent`] plus the gated `rbp` low views.
///
/// Used on BOTH the read and the write side: aliasing only one of them would
/// send a write to a separate `bpl` register while reads took `rbp`, breaking
/// the def-use link the alias exists to preserve.
fn narrow_parent_aliased(name: &str) -> Option<(&'static str, u32)> {
    gpr_narrow_parent(name).or_else(|| {
        if frame_narrow_alias_enabled() {
            gpr_frame_narrow_parent(name)
        } else {
            None
        }
    })
}

/// Whether 8/16-bit GPR views are aliased onto their 64-bit parents.
///
/// DEFAULT ON since 2026-07-29, measured on the 12-binary corpus: the HLIL path
/// `B` went from 8973 to 5964 locals read-but-never-written (denominator 57326),
/// i.e. the numerator fell by a third, while path `A` stayed BYTE-IDENTICAL
/// (0 differing `sub_*.c`) and recompilability on the FIXED 1200-file list was
/// 1199/1200 both with the gate off and on — the single failure is the
/// pre-existing `sqrt` arity bug, present in both.
///
/// Enabling it was blocked for several iterations by 6 `'v1' undeclared` files
/// in `sample4_go`. That turned out NOT to be a defect of the aliasing at all
/// but of `inline_hlil_single_use_temps`, which lost a substitution when two
/// inlines touched; the aliasing merely produced the chain that exposed it.
///
/// Set `RUSTRE_X86_GPR8_16_ALIAS=0` (or `false`) to turn it back off.
fn gpr_narrow_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("RUSTRE_X86_GPR8_16_ALIAS").as_deref(),
            Ok("0") | Ok("false")
        )
    })
}

/// 64-bit parent of a 32-bit general-purpose register name, or `None` when
/// `name` is not a 32-bit GPR.
///
/// `esp`/`ebp` are deliberately ABSENT: the stack and frame pointers are the
/// base of the great majority of local-variable accesses, and rewriting them
/// would perturb frame reconstruction, which is a separate analysis. Excluding
/// them costs nothing here — 32-bit writes to them are vanishingly rare in
/// 64-bit code.
#[must_use]
pub fn gpr32_parent(name: &str) -> Option<&'static str> {
    Some(match name {
        "eax" => "rax",
        "ecx" => "rcx",
        "edx" => "rdx",
        "ebx" => "rbx",
        "esi" => "rsi",
        "edi" => "rdi",
        "r8d" => "r8",
        "r9d" => "r9",
        "r10d" => "r10",
        "r11d" => "r11",
        "r12d" => "r12",
        "r13d" => "r13",
        "r14d" => "r14",
        "r15d" => "r15",
        _ => return None,
    })
}

/// Whether 32-bit GPRs are aliased onto their 64-bit parents.
///
/// **On by default**; set `RUSTRE_X86_GPR32_ALIAS=0` to disable.
///
/// A 32-bit GPR is not a location of its own: writing `eax` zero-extends into
/// `rax`, and reading it reads `rax`'s low half. Modelling them as separate
/// registers made the decompiler emit locals that are read but never written —
/// the data flow existed in the binary but not in the output.
///
/// Measured over the whole corpus before flipping (two fresh trees, `env -u`
/// vs `=1`): locals read-but-never-written dropped 13933 → 10246 (−26%), calls
/// to real functions stayed at 65819, braces stayed balanced, and
/// recompilability of the 6728 changed files went UP, 6713 → 6720. Every one of
/// those 6728 files is a `.hlil.c`: path A came out byte-identical, so this
/// cannot disturb it. Cost: +14 gotos.
///
/// The crate's own tests pass in BOTH modes: the assertions that named a 32-bit
/// destination go through [`has_setreg_to`] / [`is_dest`] /
/// [`intrinsic_name`] / [`operand_spelling`], which accept the parent only when
/// the alias is on and never blur one register into another.
///
/// Read once — the lifter calls it per operand.
/// Whether an instruction's IMPLICIT accumulator operand is read through the
/// same alias tables as the explicit ones.
///
/// Default ON since it was measured. `cmpxchg` built its accumulator read by
/// hand, so `eax` was a register distinct from `rax` and every read of it
/// dangled — the function could load `rax` and still emit `uint32_t v9` READ
/// AND NEVER WRITTEN.
///
/// Measured on the corpus (gate ON vs OFF, same fresh driver): B's
/// read-never-written locals **1361/53181 -> 1140/52960** (2.56% -> 2.15%), of
/// which the `vN` class **1296 -> 1075**; emitted lines went DOWN (876804 ->
/// 876583) because the phantom locals disappear; path B arity **127/135 with
/// OVER still 1**; fixed-list recompilability **1199/1200** (that one failure
/// predates this); path A output byte-identical; distinct call targets and
/// brace balance unchanged. Hand-checked `sample10_cs/sub_14006c020` (4 ×
/// `lock cmpxchg`, `rax` loaded at 0x14006c057): the undefined `v9` is gone and
/// the SIGNATURE is unchanged, so nothing was invented to make it disappear.
///
/// The candidate count was 300 (the residuals living in the 259 functions that
/// contain a `cmpxchg`); 221 of them really did depend on this alias.
///
/// Opt out with `RUSTRE_X86_IMPLICIT_ACC_ALIAS=0`. ⚠ Same shape as the other
/// gates here, so an EMPTY value reads as ON — build a control group with
/// `env -u`, never `VAR=`.
fn implicit_acc_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("RUSTRE_X86_IMPLICIT_ACC_ALIAS").as_deref(),
            Ok("0") | Ok("false")
        )
    })
}

/// Whether `DIV`/`IDIV` read their implicit dividend halves (`eax`/`edx` and
/// the narrower views) through the alias tables.
///
/// Default ON since it was measured, with its own gate (separate from
/// `implicit_acc_alias_enabled`) so the two effects could be told apart. Same
/// defect, different instruction: the general path built BOTH halves by hand.
///
/// Measured ON vs OFF **with the same binary** — the only comparison that
/// isolates this change, since concurrent agents rebuild the shared crates:
/// read-never-written locals **1140/52960 -> 1100/52920** (2.15% -> 2.08%),
/// emitted lines DOWN (876583 -> 876543), 76 files changed, path A output
/// identical, distinct call targets unchanged, brace balance 0, path B arity
/// **127/135 with OVER still 1**, fixed-list recompilability **1199/1200** on
/// both sides (that one failure predates this).
///
/// Hand-checked with the residual predicate (not `grep`, which counts LINES):
/// `sample10_cs/sub_1400167c0` and `sub_1400169a0` each go from `['v5']` to no
/// undefined locals with the SIGNATURE UNCHANGED, and each really does contain
/// a `div`/`idiv` — so nothing was invented to make the residual disappear.
///
/// Opt out with `RUSTRE_X86_DIV_ACC_ALIAS=0`. ⚠ An EMPTY value reads as ON:
/// build a control group with `env -u`, never `VAR=`.
fn div_acc_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("RUSTRE_X86_DIV_ACC_ALIAS").as_deref(),
            Ok("0") | Ok("false")
        )
    })
}

/// `CWD`/`CDQ` read the accumulator through its PARENT register.
///
/// Same defect class as `cdqe`, `cmpxchg` and `div`: `lift_sign_extend_dx`
/// hand-built the accumulator read as `RegisterRef { Concrete("eax") }`, which
/// bypasses the alias tables, so at 32 bits `eax` was a register nothing ever
/// wrote. Its sibling `lift_sign_extend_acc` (`cbw`/`cwde`/`cdqe`) was already
/// fixed; this branch was left behind.
///
/// Found from DATA, not a hunch: a mnemonic histogram over the 984 functions
/// with residual locals against a sampled CONTROL GROUP of 1016 clean ones put
/// `cltd` (AT&T for `cdq`) at **6.2% vs 0.0%** — the only mnemonic whose
/// control frequency is zero. Without the control group `jmp` looks like a
/// signal at 76.7% and is noise (68.2% in clean functions too).
///
/// Unlike the `mul`/`imul` bypass — rejected because 50 of its 52 sites are
/// 64-bit, where the fix is a no-op — the WIDTH here is chosen by the mnemonic
/// itself: `cdq` is always `DWord`/`eax`, so every observed site is one the fix
/// actually changes.
///
/// **Measured and promoted to default ON.** At equal binary, against a baseline
/// with both gates off: residual read-never-written locals in path B go
/// **1100/52920 (2.08%) -> 1043/52863 (1.97%)**, i.e. **-57** in 57 fewer files,
/// with emitted lines DOWN (876543 -> 876486), brace balance 0, path A output
/// byte-identical, and fixed-list recompilability 1199/1200 on both sides (that
/// one failure predates this).
///
/// Hand-checked with the residual predicate, never `grep` (which counts LINES):
/// of the **57 healed functions, 57 really do contain a `cltd`/`cdq`** in their
/// disassembly and **0 changed signature** — so none was healed for an unrelated
/// reason and none bought its gain with an invented parameter.
///
/// Opt out with `RUSTRE_X86_CDQ_ACC_ALIAS=0`. ⚠ An EMPTY value reads as ON:
/// build a control group with `env -u`, never `VAR=`.
fn cdq_acc_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("RUSTRE_X86_CDQ_ACC_ALIAS").as_deref(),
            Ok("0") | Ok("false")
        )
    })
}

/// One-operand `MUL`/`IMUL` read the accumulator through its PARENT register.
///
/// Same bypass, carried on the `cdq` cycle because on its own it was not worth
/// one: of 52 functions with a one-operand `mul`/`imul`, **50 are 64-bit** where
/// `acc_pair` already yields `rax` and the change is inert — only 2 are 32-bit.
/// Kept on a SEPARATE gate from `cdq` so the measurement can attribute the gain.
///
/// The two-and three-operand forms already go through `read_operand` and are
/// correct. Only the READS are rewritten: the high half is written, never read.
///
/// **Measured: worth ZERO on the numerator, so it stays default OFF.** Carried
/// on the `cdq` cycle and measured on its own tree: residuals stay at 1043 and
/// only 22 locals leave the denominator (52863 -> 52841). The width analysis
/// predicted exactly this, which is why the two gates were kept separate — on a
/// single gate `mul` would have taken credit for `cdq`'s -57.
///
/// Kept, not deleted: the bypass is a real defect, just a rare one. Turn it on
/// with `RUSTRE_X86_MUL_ACC_ALIAS=1` (a non-empty value is required here).
fn mul_acc_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("RUSTRE_X86_MUL_ACC_ALIAS").is_ok_and(|v| v != "0" && v != "false"))
}

fn gpr32_alias_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // ⚠ An EMPTY value must NOT disable: `VAR= cmd` is the usual shell idiom
    // for "unset this", so honouring it as an opt-out would make the opt-out
    // depend on shell quoting. Only an explicit "0"/"false" disables.
    // (The mirror-image mistake — treating `Ok("")` as ENABLED — once ran a
    // supposed control group with the feature ON and produced a zero-diff that
    // was mistaken for "this code is dead".)
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("RUSTRE_X86_GPR32_ALIAS").as_deref(),
            Ok("0") | Ok("false")
        )
    })
}

/// Rewrite a narrow (8/16-bit) register write as a read-modify-write of its
/// 64-bit parent.
///
/// `mov $1, %cl` is `rcx = (rcx & ~0xFF) | (value & 0xFF)`: the upper bits
/// SURVIVE. Writing `rcx = zx(value)` instead — the 32-bit rule — would clear
/// them and silently corrupt the value, which is why this is a separate
/// transform and not a widening of [`widen_gpr32_write`].
fn widen_gpr_narrow_write(instr: LlilInstruction) -> LlilInstruction {
    let LlilInstruction::SetReg { dest, size, value } = instr else {
        return instr;
    };
    let LlilRegister::Concrete(ref name) = dest else {
        return LlilInstruction::SetReg { dest, size, value };
    };
    let expect = match size {
        Size::Byte => 8u32,
        Size::Word => 16,
        _ => return LlilInstruction::SetReg { dest, size, value },
    };
    // Byte ALTO: stessa idea, ma con lo shift di 8.
    if expect == 8
        && high_byte_alias_enabled()
        && let Some(parent) = gpr_high_byte_parent(name)
    {
        let q = Size::QWord;
        let parent_ref = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(parent.to_string()),
            size: q,
        };
        let keep = LlilExpr::And(
            Box::new(parent_ref),
            Box::new(LlilExpr::Const { value: !0xFF00u64, size: q }),
            q,
        );
        let put = LlilExpr::ShlT(
            Box::new(LlilExpr::And(
                Box::new(LlilExpr::ZeroExtend { expr: Box::new(value), from: size, to: q }),
                Box::new(LlilExpr::Const { value: 0xFF, size: q }),
                q,
            )),
            Box::new(LlilExpr::Const { value: 8, size: q }),
            q,
        );
        return LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(parent.to_string()),
            size: q,
            value: LlilExpr::Or(Box::new(keep), Box::new(put), q),
        };
    }
    let Some((parent, width)) = narrow_parent_aliased(name).filter(|(_, w)| *w == expect) else {
        return LlilInstruction::SetReg { dest, size, value };
    };
    let mask: u64 = if width == 8 { 0xFF } else { 0xFFFF };
    let q = Size::QWord;
    let parent_ref = LlilExpr::RegisterRef {
        reg: LlilRegister::Concrete(parent.to_string()),
        size: q,
    };
    // (parent & !mask) | (value & mask)
    let keep = LlilExpr::And(
        Box::new(parent_ref),
        Box::new(LlilExpr::Const { value: !mask, size: q }),
        q,
    );
    let put = LlilExpr::And(
        Box::new(LlilExpr::ZeroExtend { expr: Box::new(value), from: size, to: q }),
        Box::new(LlilExpr::Const { value: mask, size: q }),
        q,
    );
    LlilInstruction::SetReg {
        dest: LlilRegister::Concrete(parent.to_string()),
        size: q,
        value: LlilExpr::Or(Box::new(keep), Box::new(put), q),
    }
}

/// Redirect a 32-bit register write onto its 64-bit parent, materialising the
/// zero-extension x86-64 performs.
///
/// This is the WRITE half of the aliasing; [`gpr32_alias_enabled`] gates it and
/// the read half lives in the register-operand path. Both are required: doing
/// only reads would read a parent nothing ever writes, and doing only writes
/// would lose every use.
fn widen_gpr32_write(instr: LlilInstruction) -> LlilInstruction {
    let LlilInstruction::SetReg { dest, size, value } = instr else {
        return instr;
    };
    let LlilRegister::Concrete(ref name) = dest else {
        return LlilInstruction::SetReg { dest, size, value };
    };
    let Some(parent) = (size == Size::DWord).then(|| gpr32_parent(name)).flatten() else {
        return LlilInstruction::SetReg { dest, size, value };
    };
    LlilInstruction::SetReg {
        dest: LlilRegister::Concrete(parent.to_string()),
        size: Size::QWord,
        value: LlilExpr::ZeroExtend {
            expr: Box::new(value),
            from: Size::DWord,
            to: Size::QWord,
        },
    }
}

/// Convert a byte count into the LLIL [`Size`]. `Size` now has exact
/// variants for 256-bit (YMM, `Size::YWord`) and 512-bit (ZMM,
/// `Size::ZWord`) widths, so AVX2/AVX-512 operands map exactly instead of
/// saturating to `Size::OWord` (128-bit) as before. Anything wider than
/// 512 bits still saturates to `Size::ZWord`.
#[must_use]
pub fn size_from_bytes(bytes: usize) -> Size {
    match bytes {
        0 | 1 => Size::Byte,
        2 => Size::Word,
        3 | 4 => Size::DWord,
        5..=8 => Size::QWord,
        9..=16 => Size::OWord,
        17..=32 => Size::YWord,
        _ => Size::ZWord,
    }
}

/// Size of an iced register as an LLIL [`Size`].
#[must_use]
pub fn reg_size(reg: Register) -> Size {
    size_from_bytes(reg.size())
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// X86Lifter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Stateful lifter for a single architecture bitness.
///
/// The lifter is cheap to construct and holds only the pointer width (for stack
/// modelling and address computations) plus a temporary-register counter. A
/// fresh lifter should be used per function if globally-unique temporaries are
/// desired; reusing one across a whole function also works because the counter
/// only ever increases.
#[derive(Debug, Clone)]
pub struct X86Lifter {
    bits: u32,
    temp_counter: u32,
}

impl X86Lifter {
    /// Create a lifter for the given bitness (16, 32, or 64).
    #[must_use]
    pub fn new(bits: u32) -> Self {
        Self {
            bits,
            temp_counter: 0,
        }
    }

    /// Create a lifter whose temporaries start at `base` instead of 0.
    ///
    /// Perche' esiste (#4400): `disassemble_and_lift` costruisce un lifter NUOVO per
    /// ogni istruzione, quindi il contatore riparte da 0 e il nome del temporaneo —
    /// `format!("tmp{n}")` in `rustre-il-llil` — **collide fra istruzioni diverse**.
    /// Provato con `tests/sonda4400_tmp_collision.rs`: `cmp $1,%r10d` produce
    /// `Temporary(0)` e il successivo `sbb $-1,%eax` produce di nuovo `Temporary(0)`
    /// (per il proprio `cf_in`), cosi' che a valle diventano **una sola variabile** e
    /// l'`sbb` legge la sottrazione del `cmp` al posto del carry.
    ///
    /// Filando `base` fra un'istruzione e la successiva (con [`Self::temp_count`]) i
    /// temporanei restano unici sull'intera funzione.
    #[must_use]
    pub fn with_temp_base(bits: u32, base: u32) -> Self {
        Self {
            bits,
            temp_counter: base,
        }
    }

    /// Create a 64-bit lifter.
    #[must_use]
    pub fn new_64() -> Self {
        Self::new(64)
    }

    /// Create a 32-bit lifter.
    #[must_use]
    pub fn new_32() -> Self {
        Self::new(32)
    }

    /// Create a 16-bit lifter.
    #[must_use]
    pub fn new_16() -> Self {
        Self::new(16)
    }

    /// The configured bitness.
    #[must_use]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// The pointer / native operand width as an LLIL [`Size`].
    #[must_use]
    pub fn ptr_size(&self) -> Size {
        match self.bits {
            16 => Size::Word,
            32 => Size::DWord,
            _ => Size::QWord,
        }
    }

    /// Pointer width in bytes.
    #[must_use]
    pub fn ptr_bytes(&self) -> u64 {
        match self.bits {
            16 => 2,
            32 => 4,
            _ => 8,
        }
    }

    /// The architectural stack-pointer register name for this bitness.
    #[must_use]
    pub fn sp_name(&self) -> &'static str {
        match self.bits {
            16 => "sp",
            32 => "esp",
            _ => "rsp",
        }
    }

    /// The architectural instruction-pointer register name for this bitness.
    #[must_use]
    pub fn ip_name(&self) -> &'static str {
        match self.bits {
            16 => "ip",
            32 => "eip",
            _ => "rip",
        }
    }

    /// Allocate a fresh temporary register.
    fn new_temp(&mut self) -> LlilRegister {
        let id = self.temp_counter;
        self.temp_counter = self.temp_counter.wrapping_add(1);
        LlilRegister::Temporary(id)
    }

    /// Number of temporaries allocated so far.
    #[must_use]
    pub fn temp_count(&self) -> u32 {
        self.temp_counter
    }

    // â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    // Public entry points
    // â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Lift a single decoded instruction into a vector of annotated LLIL
    /// instructions.
    #[must_use]
    pub fn lift(
        &mut self,
        iced: &IcedInstruction,
        address: Address,
        size: usize,
    ) -> Vec<LlilAnnotatedInstr> {
        let mut out = Vec::new();
        self.lift_into(iced, address, size, &mut out);
        out
    }

    /// Lift a single instruction, appending the produced LLIL to `out`.
    ///
    /// Every emitted [`LlilInstruction`] is wrapped in an
    /// [`LlilAnnotatedInstr`] carrying the same `address` / `size` as the
    /// originating machine instruction so the consumer can correlate IL back to
    /// machine code.
    pub fn lift_into(
        &mut self,
        iced: &IcedInstruction,
        address: Address,
        size: usize,
        out: &mut Vec<LlilAnnotatedInstr>,
    ) {
        let mut ctx = EmitCtx { address, size, out };
        self.dispatch(iced, &mut ctx);
    }

    // â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    // Dispatch
    // â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn dispatch(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        use Mnemonic as M;
        let m = iced.mnemonic();
        match m {
            // â"€â"€ Data movement â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Mov => self.lift_mov(iced, ctx),
            M::Movzx => self.lift_movzx(iced, ctx),
            M::Movsx | M::Movsxd => self.lift_movsx(iced, ctx),
            M::Lea => self.lift_lea(iced, ctx),
            M::Xchg => self.lift_xchg(iced, ctx),
            M::Cmpxchg => self.lift_cmpxchg(iced, ctx),
            // APX CMPccXADD: conditional atomic compare-and-add,
            // `reg1, reg2, [mem]` — see `lift_cmpccxadd` for full semantics.
            M::Cmpbexadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::be),
            M::Cmpbxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::b),
            M::Cmplexadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::le),
            M::Cmplxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::l),
            M::Cmpnbexadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::a),
            M::Cmpnbxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::ae),
            M::Cmpnlexadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::g),
            M::Cmpnlxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::ge),
            M::Cmpnoxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::no),
            M::Cmpnpxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::np),
            M::Cmpnsxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::ns),
            M::Cmpnzxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::ne),
            M::Cmpoxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::o),
            M::Cmppxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::p),
            M::Cmpsxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::s),
            M::Cmpzxadd => self.lift_cmpccxadd(iced, ctx, ConditionCode::e),
            // RAO-INT: unconditional atomic memory RMW, `[mem] op= src`,
            // no register/flag writeback (Aadd/Aand/Aor/Axor).
            M::Aadd => self.lift_atomic_memop(iced, ctx, |a, b, sz| LlilExpr::AddT(Box::new(a), Box::new(b), sz)),
            M::Aand => self.lift_atomic_memop(iced, ctx, |a, b, sz| LlilExpr::And(Box::new(a), Box::new(b), sz)),
            M::Aor => self.lift_atomic_memop(iced, ctx, |a, b, sz| LlilExpr::Or(Box::new(a), Box::new(b), sz)),
            M::Axor => self.lift_atomic_memop(iced, ctx, |a, b, sz| LlilExpr::Xor(Box::new(a), Box::new(b), sz)),
            M::Push => self.lift_push(iced, ctx),
            M::Pop => self.lift_pop(iced, ctx),
            M::Pushfq | M::Pushfd | M::Pushf => self.lift_pushf(iced, ctx),
            M::Popfq | M::Popfd | M::Popf => self.lift_popf(iced, ctx),
            // A `REP`-prefixed string op transfers CX elements, not one; lifting
            // only the single element silently loses the whole block transfer.
            M::Movsb | M::Movsw | M::Movsq => {
                if iced.has_rep_prefix() {
                    self.lift_rep_movs(iced, ctx);
                } else {
                    self.lift_movs(iced, ctx);
                }
            }
            M::Movsd if is_string_op(iced) => {
                if iced.has_rep_prefix() {
                    self.lift_rep_movs(iced, ctx);
                } else {
                    self.lift_movs(iced, ctx);
                }
            }

            // â"€â"€ Arithmetic â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Add => self.lift_add_sub(iced, ctx, false, false),
            M::Sub => self.lift_add_sub(iced, ctx, true, false),
            M::Adc => self.lift_add_sub(iced, ctx, false, true),
            M::Sbb => self.lift_add_sub(iced, ctx, true, true),
            M::Cmp => self.lift_cmp(iced, ctx),
            M::Inc => self.lift_inc_dec(iced, ctx, false),
            M::Dec => self.lift_inc_dec(iced, ctx, true),
            M::Neg => self.lift_neg(iced, ctx),
            M::Mul => self.lift_mul(iced, ctx),
            M::Imul => self.lift_imul(iced, ctx),
            M::Div => self.lift_div(iced, ctx, false),
            M::Idiv => self.lift_div(iced, ctx, true),
            M::Cbw | M::Cwde | M::Cdqe => self.lift_sign_extend_acc(iced, ctx),
            M::Cwd | M::Cdq | M::Cqo => self.lift_sign_extend_dx(iced, ctx),

            // â"€â"€ Logical â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::And => self.lift_logic(iced, ctx, LogicOp::And),
            M::Or => self.lift_logic(iced, ctx, LogicOp::Or),
            M::Xor => self.lift_logic(iced, ctx, LogicOp::Xor),
            M::Not => self.lift_not(iced, ctx),
            M::Test => self.lift_test(iced, ctx),

            // â"€â"€ Shifts / rotates â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Shl | M::Sal => self.lift_shift(iced, ctx, ShiftOp::Shl),
            M::Shr => self.lift_shift(iced, ctx, ShiftOp::Shr),
            M::Sar => self.lift_shift(iced, ctx, ShiftOp::Sar),
            M::Rol => self.lift_rotate(iced, ctx, RotateOp::Rol),
            M::Ror => self.lift_rotate(iced, ctx, RotateOp::Ror),
            M::Rcl => self.lift_rotate(iced, ctx, RotateOp::Rcl),
            M::Rcr => self.lift_rotate(iced, ctx, RotateOp::Rcr),
            M::Shld => self.lift_double_shift(iced, ctx, true),
            M::Shrd => self.lift_double_shift(iced, ctx, false),

            // â"€â"€ Control flow â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Jmp => self.lift_jmp(iced, ctx),
            M::Call => self.lift_call(iced, ctx),
            M::Ret | M::Retf => self.lift_ret(iced, ctx),
            M::Leave => self.lift_leave(iced, ctx),
            M::Enter => self.lift_enter(iced, ctx),
            M::Loop | M::Loope | M::Loopne => self.lift_loop(iced, ctx),
            M::Jcxz | M::Jecxz | M::Jrcxz => self.lift_jcxz(iced, ctx),

            // â"€â"€ String ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Stosb | M::Stosw | M::Stosd | M::Stosq => {
                if iced.has_rep_prefix() {
                    self.lift_rep_stos(iced, ctx);
                } else {
                    self.lift_stos(iced, ctx);
                }
            }
            M::Lodsb | M::Lodsw | M::Lodsd | M::Lodsq => self.lift_lods(iced, ctx),
            M::Scasb | M::Scasw | M::Scasd | M::Scasq => self.lift_scas(iced, ctx),
            M::Cmpsb | M::Cmpsw | M::Cmpsq => self.lift_cmps(iced, ctx),
            M::Cmpsd if is_string_op(iced) => self.lift_cmps(iced, ctx),

            // â"€â"€ Flag manipulation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Clc => self.emit_set_flag_const(ctx, FLAG_CF, 0),
            M::Stc => self.emit_set_flag_const(ctx, FLAG_CF, 1),
            M::Cmc => self.lift_cmc(ctx),
            M::Cld => self.emit_set_flag_const(ctx, FLAG_DF, 0),
            M::Std => self.emit_set_flag_const(ctx, FLAG_DF, 1),
            M::Lahf => self.lift_lahf(ctx),
            M::Sahf => self.lift_sahf(ctx),

            // â"€â"€ System / misc â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Nop | M::Fnop | M::Pause | M::Wait => ctx.emit(LlilInstruction::Nop),
            // `CPUID` writes EAX, EBX, ECX and EDX (the leaf result), reading
            // the leaf/subleaf from EAX and ECX. Modelled as a bare intrinsic,
            // the IL wrote none of them and a decompiler believed all four kept
            // their old values — through an instruction that appears in
            // essentially every real binary.
            M::Cpuid => {
                // The leaf/subleaf inputs go through `read_reg_by_name`, like
                // every other implicit-accumulator read (cdqe, cmpxchg, div,
                // cdq). Spelling `RegisterRef("eax")` by hand bypassed the
                // GPR32 alias, so under it `eax` was a name nothing ever
                // defines — read-never-written, 11 residual locals across 7
                // binaries and four source languages.
                //
                // The inputs are MATERIALISED first: CPUID writes all four
                // registers simultaneously from the ORIGINAL eax/ecx, but the
                // four SetRegs below are sequential, so the write to eax would
                // otherwise poison the leaf read of the three that follow.
                let leaf = self.materialise_temp(
                    Self::read_reg_by_name("eax", Size::DWord),
                    Size::DWord,
                    ctx,
                );
                let subleaf = self.materialise_temp(
                    Self::read_reg_by_name("ecx", Size::DWord),
                    Size::DWord,
                    ctx,
                );
                let args = vec![leaf, subleaf];
                for out in ["eax", "ebx", "ecx", "edx"] {
                    ctx.emit(LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete(out.to_string()),
                        size: Size::DWord,
                        value: LlilExpr::Intrinsic {
                            name: format!("cpuid_{out}"),
                            args: args.clone(),
                            result_size: Size::DWord,
                        },
                    });
                }
            }
            M::Rdtsc => self.lift_rdtsc(ctx),
            // `RDPMC` and `XGETBV` write the EDX:EAX pair (performance
            // counter / extended control register). Same shape as RDTSC.
            M::Rdpmc => self.lift_edx_eax_pair(ctx, "rdpmc"),
            M::Xgetbv => self.lift_edx_eax_pair(ctx, "xgetbv"),
            M::Rdpru => self.lift_rdpru(ctx),
            // XSUSLDTRK/XRESLDTRK (TSX suspend/resume load address tracking)
            // — effect-only, no register/memory result.
            M::Xsusldtrk => self.lift_intrinsic_no_result(iced, ctx, "xsusldtrk"),
            M::Xresldtrk => self.lift_intrinsic_no_result(iced, ctx, "xresldtrk"),
            M::Rdtscp => self.lift_rdtscp(ctx),
            // `SYSCALL` CLOBBERS RCX and R11: the CPU puts the return address
            // in RCX and the saved RFLAGS in R11. The `SysCall` node alone left
            // both looking untouched, so a decompiler believed values held in
            // them survived the call — exactly the registers a syscall stub
            // uses around it. `SYSENTER` does not clobber them, so the two are
            // no longer collapsed into one arm.
            M::Syscall => {
                ctx.emit(LlilInstruction::SysCall);
                for (reg, what) in [("rcx", "return_address"), ("r11", "saved_rflags")] {
                    ctx.emit(LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete(reg.to_string()),
                        size: Size::QWord,
                        value: LlilExpr::Intrinsic {
                            name: format!("syscall_{what}"),
                            args: vec![],
                            result_size: Size::QWord,
                        },
                    });
                }
            }
            M::Sysenter => ctx.emit(LlilInstruction::SysCall),
            M::Sysret | M::Sysexit => ctx.emit(LlilInstruction::Ret),
            M::Int3 => ctx.emit(LlilInstruction::Breakpoint),
            M::Int => self.lift_int(iced, ctx),
            M::Int1 => ctx.emit(LlilInstruction::Trap { code: 1 }),
            M::Into => ctx.emit(LlilInstruction::Trap { code: 4 }),
            M::Ud0 | M::Ud1 | M::Ud2 => ctx.emit(LlilInstruction::Trap { code: 6 }),
            M::Hlt => self.lift_intrinsic_no_result(iced, ctx, "hlt"),
            M::Rdrand | M::Rdseed => self.lift_rdrand(iced, ctx),

            // ── SALC (undocumented 8086-era, opcode D6) ─────────────────────
            // "Set AL from Carry": `AL = CF ? 0xFF : 0x00`. It WRITES A
            // REGISTER and must not be lumped in with the effect-only legacy
            // tail below — it is essentially a byte-wide SBB AL,AL.
            // Affects no flags.
            M::Salc => {
                let value = LlilExpr::CondExpr {
                    cond: Box::new(Self::cond_expr(ConditionCode::b)),
                    true_val: Box::new(LlilExpr::Const { value: 0xFF, size: Size::Byte }),
                    false_val: Box::new(LlilExpr::Const { value: 0, size: Size::Byte }),
                    size: Size::Byte,
                };
                ctx.emit(LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete(reg_name(Register::AL)),
                    size: Size::Byte,
                    value,
                });
            }

            // ── FRED (Flexible Return and Event Delivery) ───────────────────
            // ERETS/ERETU return from an event to supervisor/user context —
            // control transfers, so they get IRET's treatment rather than being
            // modelled as inert intrinsics.
            // FRED event returns. Like IRET/RSM/SKINIT they RESTORE a saved
            // context and do not fall through — the decoder reports
            // `flow_control = Return` for both. The intrinsic is kept for the
            // unmodelled state effects; the `Ret` carries the control-flow fact
            // so a CFG stops here instead of merging the next block in.
            M::Erets => {
                self.lift_fpu_generic(iced, ctx, "erets");
                ctx.emit(LlilInstruction::Ret);
            }
            M::Eretu => {
                self.lift_fpu_generic(iced, ctx, "eretu");
                ctx.emit(LlilInstruction::Ret);
            }

            // ── AMD LWP (Lightweight Profiling) ─────────────────────────────
            // LLWPCB/SLWPCB load/store the LWP control-block pointer; LWPINS
            // inserts a profiling record and LWPVAL a value sample. LWPINS is
            // documented to set CF on a ring-buffer overflow, but the exact
            // condition is not confirmed from an authoritative source here, so
            // these are left at effect/intrinsic granularity rather than
            // fabricating a carry rule. See the SEV-SNP note above for the
            // standard this repo holds flag semantics to.
            M::Llwpcb => self.lift_fpu_generic(iced, ctx, "llwpcb"),
            M::Slwpcb => self.lift_fpu_generic(iced, ctx, "slwpcb"),
            M::Lwpins => self.lift_fpu_generic(iced, ctx, "lwpins"),
            M::Lwpval => self.lift_fpu_generic(iced, ctx, "lwpval"),

            // ── Misc system / one-off ───────────────────────────────────────
            // VMFUNC: dispatch a VM function selected by EAX. PCOMMIT:
            // deprecated persistent-memory commit. CL1INVMB / PBNDKB / GETSECQ
            // / CCS_HASH: cache-line invalidate-mem-barrier, platform key
            // bundling, GETSEC quote, VIA PadLock hash — all zero-explicit-
            // operand, effect-only, same shape as the VMX/TDX ops above.
            M::Vmfunc => self.lift_intrinsic_no_result(iced, ctx, "vmfunc"),
            M::Pcommit => self.lift_intrinsic_no_result(iced, ctx, "pcommit"),
            M::Cl1invmb => self.lift_intrinsic_no_result(iced, ctx, "cl1invmb"),
            M::Pbndkb => self.lift_intrinsic_writing_reported_regs(iced, ctx, "pbndkb"),
            M::Getsecq => self.lift_intrinsic_no_result(iced, ctx, "getsecq"),
            M::Ccs_hash => self.lift_intrinsic_writing_reported_regs(iced, ctx, "ccs_hash"),
            // JMPE: transfer to IA-64 mode (Itanium) — a control transfer.
            M::Jmpe => self.lift_fpu_generic(iced, ctx, "jmpe"),

            // ── KNC / Xeon Phi misc ─────────────────────────────────────────
            // CLEVICT0/DELAY/RDUDBG/WRUDBG are effect-only. TZCNTI writes a
            // register destination, so it uses the writeback path.
            M::Clevict0 => self.lift_intrinsic_no_result(iced, ctx, "clevict0"),
            M::Delay => self.lift_intrinsic_no_result(iced, ctx, "delay"),
            M::Rdudbg => self.lift_intrinsic_no_result(iced, ctx, "rdudbg"),
            M::Wrudbg => self.lift_intrinsic_no_result(iced, ctx, "wrudbg"),
            M::Tzcnti => self.lift_fpu_generic(iced, ctx, "tzcnti"),
            // JKNZD/JKZD branch on a mask register being (non-)zero. They are
            // CONTROL TRANSFERS, not inert intrinsics — but iced reports no
            // condition_code() for them, so the structural Jcc path in
            // `dispatch_fallback` does not pick them up either. Route them
            // through the same generic transfer handling as JMPE above rather
            // than silently dropping the branch.
            M::Jknzd => self.lift_fpu_generic(iced, ctx, "jknzd"),
            M::Jkzd => self.lift_fpu_generic(iced, ctx, "jkzd"),

            // ── x87 legacy / 8087-80287-era, effect-only ────────────────────
            // FENI/FDISI (+ their FN no-wait forms) enabled/disabled the 8087
            // interrupt mask; FSETPM/FRSTPM were 80287 protected-mode
            // transitions; FNSTDW/FNSTSG store the 80287 data/segment
            // registers; FTSTP/FRINT2/FRICHOP are undocumented Cyrix-era x87.
            // All are NOPs on any modern CPU.
            M::Feni | M::Fneni => self.lift_intrinsic_no_result(iced, ctx, "feni"),
            M::Fdisi | M::Fndisi => self.lift_intrinsic_no_result(iced, ctx, "fdisi"),
            M::Fsetpm | M::Fnsetpm => self.lift_intrinsic_no_result(iced, ctx, "fsetpm"),
            M::Frstpm => self.lift_intrinsic_no_result(iced, ctx, "frstpm"),
            M::Fnstdw => self.lift_fpu_generic(iced, ctx, "fnstdw"),
            M::Fnstsg => self.lift_fpu_generic(iced, ctx, "fnstsg"),
            M::Ftstp => self.lift_fpu_generic(iced, ctx, "ftstp"),
            M::Frint2 => self.lift_fpu_generic(iced, ctx, "frint2"),
            M::Frichop => self.lift_fpu_generic(iced, ctx, "frichop"),

            // ── Cyrix / pre-2000 undocumented, effect-only ──────────────────
            // IBTS (insert bit string, withdrawn 386 opcode), SMINT (Cyrix SMM
            // entry), RDM (return from SMM), RSDC/SVTS (save/restore segment
            // descriptor / task state), BB0_RESET/BB1_RESET (branch-buffer
            // reset), CPU_READ/CPU_WRITE (Cyrix config access), ALTINST
            // (alternate instruction set enable), STOREALL, UNDOC.
            M::Ibts => self.lift_fpu_generic(iced, ctx, "ibts"),
            M::Smint => self.lift_intrinsic_no_result(iced, ctx, "smint"),
            M::Rdm => self.lift_intrinsic_no_result(iced, ctx, "rdm"),
            M::Rsdc => self.lift_fpu_generic(iced, ctx, "rsdc"),
            M::Svts => self.lift_fpu_generic(iced, ctx, "svts"),
            M::Bb0_reset => self.lift_intrinsic_no_result(iced, ctx, "bb0_reset"),
            M::Bb1_reset => self.lift_intrinsic_no_result(iced, ctx, "bb1_reset"),
            M::Cpu_read => self.lift_intrinsic_no_result(iced, ctx, "cpu_read"),
            M::Cpu_write => self.lift_intrinsic_no_result(iced, ctx, "cpu_write"),
            M::Altinst => self.lift_intrinsic_no_result(iced, ctx, "altinst"),
            M::Storeall => self.lift_intrinsic_no_result(iced, ctx, "storeall"),
            M::Undoc => self.lift_intrinsic_no_result(iced, ctx, "undoc"),

            // ── AMD SEV-SNP RMP management ──────────────────────────────────
            // NOT effect-only despite having no explicit operands — see
            // `lift_snp_rmp` for the AMD-documented flag split (only PVALIDATE
            // writes CF; RMPQUERY also returns RDX/RCX).
            M::Pvalidate => self.lift_snp_rmp(ctx, "pvalidate", true, &[]),
            M::Psmash => self.lift_snp_rmp(ctx, "psmash", false, &[]),
            M::Rmpupdate => self.lift_snp_rmp(ctx, "rmpupdate", false, &[]),
            M::Rmpquery => self.lift_snp_rmp(
                ctx,
                "rmpquery",
                false,
                // RDX[63:8] = target VMPL permission mask, RCX[0] = page size.
                &[(Register::RDX, Size::QWord), (Register::RCX, Size::QWord)],
            ),

            // ── UINTR (user interrupts) ─────────────────────────────────────
            // CLUI/STUI clear/set the user-interrupt flag (UIF); neither reads
            // nor writes rFLAGS, so they are genuinely effect-only.
            M::Clui => self.lift_intrinsic_no_result(iced, ctx, "clui"),
            M::Stui => self.lift_intrinsic_no_result(iced, ctx, "stui"),
            // TESTUI is NOT effect-only — it reports UIF *through the flags*:
            //   `CF := UIF; ZF := AF := OF := PF := SF := 0`
            // (Intel SDM). Modelling it as a bare intrinsic would silently drop
            // the only thing it computes, so CF is read from a `uif` intrinsic
            // and the remaining five flags are cleared, exactly as specified.
            M::Testui => {
                self.emit_set_flag(
                    ctx,
                    FLAG_CF,
                    LlilExpr::Intrinsic {
                        name: "uif".to_string(),
                        args: vec![],
                        result_size: Size::Byte,
                    },
                );
                for flag in [FLAG_ZF, FLAG_OF, FLAG_AF, FLAG_PF, FLAG_SF] {
                    self.emit_set_flag_const(ctx, flag, 0);
                }
            }
            // UIRET returns from a user-interrupt handler — a control transfer,
            // so it gets the same treatment as IRET above rather than being
            // modelled as an inert intrinsic.
            // User-interrupt return — same shape as IRET: does not fall through.
            M::Uiret => {
                self.lift_fpu_generic(iced, ctx, "uiret");
                ctx.emit(LlilInstruction::Ret);
            }

            // ── VMX (Intel virtualization) ──────────────────────────────
            // All effect-only privileged mode transitions / VMCS management
            // except VMREAD, which writes its GPR/memory destination from
            // the addressed VMCS field.
            M::Vmcall => self.lift_intrinsic_no_result(iced, ctx, "vmcall"),
            M::Vmlaunch => self.lift_intrinsic_no_result(iced, ctx, "vmlaunch"),
            M::Vmresume => self.lift_intrinsic_no_result(iced, ctx, "vmresume"),
            M::Vmxoff => self.lift_intrinsic_no_result(iced, ctx, "vmxoff"),
            // TDX (Trust Domain Extensions): TDCALL (guest->TDX-module
            // call), SEAMCALL/SEAMOPS (host->SEAM-module call/query),
            // SEAMRET (return from SEAM) — all zero-explicit-operand,
            // effect-only, same shape as the VMX ops above.
            M::Tdcall => self.lift_intrinsic_no_result(iced, ctx, "tdcall"),
            M::Seamcall => self.lift_intrinsic_no_result(iced, ctx, "seamcall"),
            M::Seamops => self.lift_intrinsic_writing_reported_regs(iced, ctx, "seamops"),
            M::Seamret => self.lift_intrinsic_no_result(iced, ctx, "seamret"),
            M::Vmptrld => self.lift_fpu_generic(iced, ctx, "vmptrld"),
            M::Vmptrst => self.lift_fpu_generic(iced, ctx, "vmptrst"),
            M::Vmclear => self.lift_fpu_generic(iced, ctx, "vmclear"),
            M::Vmxon => self.lift_fpu_generic(iced, ctx, "vmxon"),
            M::Invept => self.lift_fpu_generic(iced, ctx, "invept"),
            M::Invvpid => self.lift_fpu_generic(iced, ctx, "invvpid"),
            M::Vmwrite => self.lift_fpu_generic(iced, ctx, "vmwrite"),
            M::Vmread => self.lift_simd_write(iced, ctx, "vmread"),

            // ── AMX (tile registers) ──────────────────────────────────────
            // TMM0-7 are opaque 1024-byte 2D tile registers (row/col
            // dimensions set at runtime via `LDTILECFG`, not encoded in the
            // instruction itself) — this IR's `Size` enum tops out at
            // `ZWord` (64 bytes, AVX-512 ZMM), so it cannot represent a
            // tile register's true shape or width. Earlier session notes
            // treated this as fully blocked pending a new 2D-register IR
            // primitive; on inspection that's only true for EXACT
            // byte-for-byte tile semantics. `reg_name`/`size_from_bytes`
            // already degrade TMM operands safely (silently reported as
            // `Size::ZWord`, not a panic), so the SAME "real operand reads,
            // approximate/no exact writeback" treatment already used for
            // every other exotic multi-implicit-operand instruction in this
            // file (VMX/SEAM above, MPX, VP2INTERSECT, AVX512_4FMAPS, …)
            // applies here too — real coverage today, exact tile semantics
            // remains a genuine future subsystem-design task, not a
            // blocker for closing the `Unimplemented` gap.
            M::Tileloadd | M::Tileloaddt1 => {
                self.lift_intrinsic_writing_reported_regs(iced, ctx, "tileload");
            }
            M::Tilestored => self.lift_fpu_generic(iced, ctx, "tilestore"),
            M::Tilerelease => self.lift_intrinsic_writing_reported_regs(iced, ctx, "tilerelease"),
            M::Tilezero => self.lift_intrinsic_writing_reported_regs(iced, ctx, "tilezero"),
            M::Ldtilecfg => self.lift_intrinsic_writing_reported_regs(iced, ctx, "ldtilecfg"),
            M::Sttilecfg => self.lift_fpu_generic(iced, ctx, "sttilecfg"),
            M::Tdpbf16ps
            | M::Tdpbssd
            | M::Tdpbsud
            | M::Tdpbusd
            | M::Tdpbuud
            | M::Tdpfp16ps
            | M::Tcmmimfp16ps
            | M::Tcmmrlfp16ps => self.lift_intrinsic_writing_reported_regs(iced, ctx, "tdp"),

            // ── SVM (AMD virtualization) ────────────────────────────────
            M::Vmrun => self.lift_intrinsic_no_result(iced, ctx, "vmrun"),
            M::Vmmcall => self.lift_intrinsic_no_result(iced, ctx, "vmmcall"),
            M::Vmload => self.lift_intrinsic_no_result(iced, ctx, "vmload"),
            M::Vmsave => self.lift_intrinsic_no_result(iced, ctx, "vmsave"),
            M::Stgi => self.lift_intrinsic_no_result(iced, ctx, "stgi"),
            M::Clgi => self.lift_intrinsic_no_result(iced, ctx, "clgi"),
            // SKINIT does not fall through: it jumps to the secure loader
            // entry point it just established, so execution never returns to
            // the following byte. The decoder says so (`flow_control =
            // Return`); the IL emitted only an intrinsic, so a CFG ran straight
            // past it and merged the next block into this one. Same class as
            // RSM/IRET/UIRET below — found once the sweep generated ModRM
            // rm != 0, which `0F 01 DE` needs.
            M::Skinit => {
                self.lift_intrinsic_writing_reported_regs(iced, ctx, "skinit");
                ctx.emit(LlilInstruction::Ret);
            }
            // AMD SEV-SNP #VC (VMGEXIT) handler trap — effect-only, no operands.
            M::Vmgexit => self.lift_intrinsic_no_result(iced, ctx, "vmgexit"),
            M::Invlpga => self.lift_intrinsic_no_result(iced, ctx, "invlpga"),

            // ── Misc privileged / system ────────────────────────────────
            // RSM resumes the interrupted context out of System Management
            // Mode: it does NOT fall through. `branch.rs::classify_branch`
            // already knows this (`0F AA => BranchKind::Return`, commented
            // "returns"); the lifter did not — the same fact described twice,
            // once wrongly, which is the shape behind most of this session's
            // findings. Intrinsic kept for the unmodelled state restore.
            M::Rsm => {
                self.lift_intrinsic_no_result(iced, ctx, "rsm");
                ctx.emit(LlilInstruction::Ret);
            }
            M::Wbinvd => self.lift_intrinsic_no_result(iced, ctx, "wbinvd"),
            M::Invd => self.lift_intrinsic_no_result(iced, ctx, "invd"),
            M::Getsec => self.lift_intrinsic_no_result(iced, ctx, "getsec"),

            // ── 3DNow! (legacy AMD MMX-register floating point) ─────────
            // All forms are `PFxx mm, mm/mem64` — read both operands,
            // compute via a named intrinsic, write back to the MMX
            // destination register (same writeback shape as ordinary MMX
            // arithmetic).
            M::Pfadd => self.lift_simd_write(iced, ctx, "pfadd"),
            M::Pfsub => self.lift_simd_write(iced, ctx, "pfsub"),
            M::Pfsubr => self.lift_simd_write(iced, ctx, "pfsubr"),
            M::Pfmul => self.lift_simd_write(iced, ctx, "pfmul"),
            M::Pfcmpeq => self.lift_simd_write(iced, ctx, "pfcmpeq"),
            M::Pfcmpge => self.lift_simd_write(iced, ctx, "pfcmpge"),
            M::Pfcmpgt => self.lift_simd_write(iced, ctx, "pfcmpgt"),
            M::Pfmax => self.lift_simd_write(iced, ctx, "pfmax"),
            M::Pfmin => self.lift_simd_write(iced, ctx, "pfmin"),
            M::Pfrcp => self.lift_simd_write(iced, ctx, "pfrcp"),
            M::Pfrsqrt => self.lift_simd_write(iced, ctx, "pfrsqrt"),
            M::Pf2id => self.lift_simd_write(iced, ctx, "pf2id"),
            M::Pi2fd => self.lift_simd_write(iced, ctx, "pi2fd"),
            M::Pfacc => self.lift_simd_write(iced, ctx, "pfacc"),
            M::Pfnacc => self.lift_simd_write(iced, ctx, "pfnacc"),
            M::Pfpnacc => self.lift_simd_write(iced, ctx, "pfpnacc"),
            M::Pswapd => self.lift_simd_write(iced, ctx, "pswapd"),
            M::Femms => self.lift_intrinsic_no_result(iced, ctx, "femms"),
            // Generic intrinsics that don't produce a result and don't need
            // bespoke lifting. `Rdmsr` / `Wrmsr` are intentionally NOT in
            // this list: their dedicated handlers below model the implicit
            // ECX/EDX:EAX read/write semantics.
            // NOTE: `Xgetbv` and `Rdpmc` used to be in this effect-only list,
            // contradicting the comment right above it — both WRITE EDX:EAX,
            // exactly like `Rdmsr`, and are now handled with it below. Left
            // here, the IL never wrote the pair and a decompiler believed the
            // old EDX:EAX survived.
            M::Xsetbv
            | M::Lfence
            | M::Sfence
            | M::Mfence
            | M::Prefetchnta
            | M::Prefetcht0
            | M::Prefetcht1
            | M::Prefetcht2
            | M::Clflush
            // PREFETCH (3DNow!-era AMD prefetch, distinct mnemonic id from
            // Prefetchnta/t0/t1/t2 above) and the newer Intel
            // PREFETCHIT0/IT1 (instruction-fetch prefetch hints) — same
            // effect-only cache-hint shape.
            | M::Prefetch
            | M::Prefetchit0
            | M::Prefetchit1 => {
                self.lift_intrinsic_no_result(iced, ctx, &reg_name_lower_mnemonic(m));
            }
            // ENQCMD/ENQCMDS: enqueue a 64-byte command descriptor (real
            // explicit dest-memory/src-register operands) to a
            // memory-mapped device queue, sets ZF on success — no single
            // GPR/vector result this IR can target, so read both operands
            // for visibility (same precedent as Maskmovdqu/MPX above).
            M::Enqcmd | M::Enqcmds => self.lift_fpu_generic(iced, ctx, "enqcmd"),
            // LOADIWKEY (Key Locker): loads the internal wrapping key from
            // XMM0/XMM1(+XMM2 if AESKLE) — effect-only, no GPR/vector
            // result.
            M::Loadiwkey => self.lift_intrinsic_no_result(iced, ctx, "loadiwkey"),
            // SENDUIPI: send a user-interrupt IPI to the target selected by
            // the operand — effect-only.
            M::Senduipi => self.lift_intrinsic_no_result(iced, ctx, "senduipi"),

            // â"€â"€ Bit scan / bit test (set flags) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Bsf | M::Bsr => self.lift_bit_scan(iced, ctx, m == M::Bsr),
            M::Bt | M::Bts | M::Btr | M::Btc => self.lift_bit_test(iced, ctx, m),
            M::Bswap => self.lift_bswap(iced, ctx),
            M::Popcnt => self.lift_unary_intrinsic_with_zf(iced, ctx, "popcnt"),
            M::Lzcnt | M::Tzcnt => {
                self.lift_unary_intrinsic_with_zf(iced, ctx, &reg_name_lower_mnemonic(m));
            }

            // â"€â"€ SSE / MMX data moves â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Movaps
            | M::Movups
            | M::Movapd
            | M::Movupd
            | M::Movdqa
            | M::Movdqu
            | M::Movq
            | M::Movd
            | M::Movss => {
                self.lift_vector_move(iced, ctx, m);
            }
            // `movsd` between XMM registers (scalar double) —" not the string op.
            M::Movsd => self.lift_vector_move(iced, ctx, m),

            // â"€â"€ Atomic / exchange â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Xadd => self.lift_xadd(iced, ctx),
            M::Cmpxchg8b => self.lift_cmpxchg8b(iced, ctx),
            M::Cmpxchg16b => self.lift_cmpxchg16b(iced, ctx),

            // â"€â"€ System state â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Rdmsr => self.lift_rdmsr(ctx),
            M::Wrmsr => self.lift_wrmsr(ctx),
            M::Xsave | M::Xsave64 => self.lift_xsave(iced, ctx),
            M::Xrstor | M::Xrstor64 => self.lift_xrstor(iced, ctx),
            M::Fxsave | M::Fxsave64 => self.lift_fxsave(iced, ctx),
            M::Fxrstor | M::Fxrstor64 => self.lift_fxrstor(iced, ctx),
            M::Clflushopt => self.lift_intrinsic_no_result(iced, ctx, "clflushopt"),
            M::Clwb => self.lift_intrinsic_no_result(iced, ctx, "clwb"),
            M::Cldemote => self.lift_intrinsic_no_result(iced, ctx, "cldemote"),
            M::Clac | M::Stac => self.lift_intrinsic_no_result(iced, ctx, "ac_flag_toggle"),
            // Cli/Clts: clear-interrupt-flag / clear-task-switched-flag —
            // privileged, effect-only (no GPR/vector result), same shape as
            // the already-covered `Sti`.
            M::Cli => self.lift_intrinsic_no_result(iced, ctx, "cli"),
            M::Clts => self.lift_intrinsic_no_result(iced, ctx, "clts"),
            // Clzero (AMD): zero the cache line containing [rax] —
            // effect-only memory-clearing hint, no register result.
            M::Clzero => self.lift_intrinsic_no_result(iced, ctx, "clzero"),
            // MOVDIRI writes a GPR to memory: operand 0 IS the destination,
            // so the generic SIMD writer is right for it.
            M::Movdiri => self.lift_simd_write(iced, ctx, "movdiri"),
            // MOVDIR64B is NOT the same shape, despite the neighbouring name.
            // It moves 64 bytes memory-to-memory, and its operand 0 is a
            // REGISTER HOLDING THE DESTINATION ADDRESS, not the destination
            // itself. Routing it through `lift_simd_write` therefore wrote the
            // *address register* with the moved data and modelled NO STORE at
            // all — the 64-byte write was invisible, which is why this was the
            // memory oracle's last pinned residual. Same defect shape as
            // RDPKRU: an instruction whose operand 0 is not what the helper
            // assumes.
            M::Movdir64b => {
                let asize = self.ptr_size();
                let value = LlilExpr::Intrinsic {
                    name: "movdir64b".to_string(),
                    args: vec![self.read_operand(iced, 1)],
                    result_size: Size::OWord,
                };
                ctx.emit(LlilInstruction::Store {
                    addr: LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(iced.op0_register())),
                        size: asize,
                    },
                    size: Size::OWord,
                    value,
                });
            }
            // Rdpkru: reads the Protection Key Rights register into EDX:EAX
            // (this IR only models a single result register — approximated
            // as a real write to EAX, matching the exotic-instruction
            // approximation precedent). Wrpkru: writes EAX/ECX/EDX into
            // PKRU — effect-only, no GPR result.
            // RDPKRU takes NO operands and returns the key register in
            // EDX:EAX. It was routed to the SIMD writer, which writes
            // `operand 0` — with no operands that resolved to a register
            // literally named "none", so the real EAX/EDX writes were lost AND
            // a phantom register was defined. The decoder names both.
            M::Rdpkru => self.lift_intrinsic_writing_reported_regs(iced, ctx, "rdpkru"),
            M::Wrpkru => self.lift_fpu_generic(iced, ctx, "wrpkru"),
            // SGX enclave management (privileged, effect-only) / AMD SEV-SNP
            // RMP adjust (privileged, effect-only) / TDX/CET Hreset
            // (effect-only, resets history state, no GPR result) / AES
            // key-locker (128/256-bit wide, effect-only — like AES-NI, the
            // real crypto math isn't modelled, but these also have no
            // single destination this IR can target cleanly since they
            // write multiple XMM registers at once) / Pconfig (platform
            // configuration, effect-only).
            M::Encls => self.lift_intrinsic_writing_reported_regs(iced, ctx, "encls"),
            M::Enclu => self.lift_intrinsic_writing_reported_regs(iced, ctx, "enclu"),
            M::Enclv => self.lift_intrinsic_writing_reported_regs(iced, ctx, "enclv"),
            M::Rmpadjust => self.lift_intrinsic_writing_reported_regs(iced, ctx, "rmpadjust"),
            M::Hreset => self.lift_fpu_generic(iced, ctx, "hreset"),
            M::Pconfig => self.lift_intrinsic_writing_reported_regs(iced, ctx, "pconfig"),
            // VIA/Centaur PadLock crypto extension — effect-only (multi-
            // implicit-register side effect, same approximation class as
            // AES-NI/SHA above).
            M::Ccs_encrypt => self.lift_intrinsic_writing_reported_regs(iced, ctx, "ccs_encrypt"),
            // Cyrix-era pre-Pentium legacy opcodes (undocumented/rarely
            // emulated even by modern CPUs) — effect-only, in scope per the
            // literal-100%-coverage decision but essentially never appears
            // in real binaries.
            M::Rsldt => self.lift_fpu_generic(iced, ctx, "rsldt"),
            M::Dmint => self.lift_fpu_generic(iced, ctx, "dmint"),
            M::Frinear => self.lift_fpu_generic(iced, ctx, "frinear"),
            M::Fstdw => self.lift_fpu_generic(iced, ctx, "fstdw"),
            // Key-locker AES. The NON-wide forms have an explicit xmm
            // destination in operand 0, which the effect-only helper never
            // wrote. The WIDE forms take only the key handle and operate on
            // XMM0-7 implicitly — their operand 0 is MEMORY, so writing it
            // would invent a store; they stay effect-only, which is honest
            // about what is not modelled.
            M::Aesdec128kl | M::Aesdec256kl | M::Aesenc128kl | M::Aesenc256kl => {
                self.lift_intrinsic_to_op0(iced, ctx, "aeskl");
            }
            M::Aesdecwide128kl
            | M::Aesdecwide256kl
            | M::Aesencwide128kl
            | M::Aesencwide256kl => {
                self.lift_intrinsic_writing_reported_regs(iced, ctx, "aeskl_wide");
            }
            M::Prefetchw => self.lift_intrinsic_no_result(iced, ctx, "prefetchw"),
            M::Prefetchwt1 => self.lift_intrinsic_no_result(iced, ctx, "prefetchwt1"),
            // KNC (Xeon Phi Knights Corner) MVEX prefetch hints — effect-only,
            // like the standard Prefetch* family.
            M::Vprefetch0 => self.lift_intrinsic_no_result(iced, ctx, "vprefetch0"),
            M::Vprefetch1 => self.lift_intrinsic_no_result(iced, ctx, "vprefetch1"),
            M::Vprefetch2 => self.lift_intrinsic_no_result(iced, ctx, "vprefetch2"),
            M::Vprefetche0 => self.lift_intrinsic_no_result(iced, ctx, "vprefetche0"),
            M::Vprefetche1 => self.lift_intrinsic_no_result(iced, ctx, "vprefetche1"),
            M::Vprefetche2 => self.lift_intrinsic_no_result(iced, ctx, "vprefetche2"),
            // VEX form of MASKMOVDQU — conditional byte-mask store to DS:DI,
            // effect-only (no single decoded destination, matches pass-19
            // Maskmovdqu precedent).
            M::Vmaskmovdqu => self.lift_fpu_generic(iced, ctx, "vmaskmovdqu"),
            // AVX-512 FP16 scalar complex FMA (Vfmaddcsh/Vfmulcsh) —
            // real writeback via lift_simd_write, siblings of Vfmadd132sh etc.
            M::Vfmaddcsh => self.lift_simd_write(iced, ctx, "vfmaddcsh"),
            M::Vfmulcsh => self.lift_simd_write(iced, ctx, "vfmulcsh"),
            // KNC MVEX arithmetic siblings — real writeback.
            M::Vsubrps => self.lift_simd_write(iced, ctx, "vsubrps"),
            M::Vpsubsetbd => self.lift_simd_write(iced, ctx, "vpsubsetbd"),
            M::Vgminps => self.lift_simd_write(iced, ctx, "vgminps"),
            // Cyrix XBTS / SVDC — pre-Pentium legacy, effect-only.
            M::Xbts => self.lift_fpu_generic(iced, ctx, "xbts"),
            M::Svdc => self.lift_fpu_generic(iced, ctx, "svdc"),
            // Cyrix UMOV / RSTS — legacy, effect-only.
            M::Umov => self.lift_fpu_generic(iced, ctx, "umov"),
            M::Rsts => self.lift_fpu_generic(iced, ctx, "rsts"),
            // AVX-512DQ qword absolute value — real writeback.
            M::Vpabsq => self.lift_simd_write(iced, ctx, "vpabsq"),
            // AVX-512 FP16 complex FMA / conjugate mul (packed) — real writeback.
            M::Vfmaddcph => self.lift_simd_write(iced, ctx, "vfmaddcph"),
            M::Vfcmulcph => self.lift_simd_write(iced, ctx, "vfcmulcph"),
            // AVX-NE-CONVERT: bf16→f32 broadcast even-odd converts — real writeback.
            M::Vcvtneobf162ps => self.lift_simd_write(iced, ctx, "vcvtneobf162ps"),
            // KNC MVEX arithmetic/convert siblings — real writeback.
            M::Vgmaxpd => self.lift_simd_write(iced, ctx, "vgmaxpd"),
            M::Vpmadd233d => self.lift_simd_write(iced, ctx, "vpmadd233d"),
            M::Vcvtfxpntps2dq => self.lift_simd_write(iced, ctx, "vcvtfxpntps2dq"),
            // 3DNow!/3DNow!+ siblings — real writeback into MM register.
            M::Pdistib => self.lift_simd_write(iced, ctx, "pdistib"),
            M::Pmvgezb => self.lift_simd_write(iced, ctx, "pmvgezb"),
            M::Pmvnzb => self.lift_simd_write(iced, ctx, "pmvnzb"),
            M::Pavgusb => self.lift_simd_write(iced, ctx, "pavgusb"),
            M::Pfrsqrtv => self.lift_simd_write(iced, ctx, "pfrsqrtv"),
            M::Pi2fw => self.lift_simd_write(iced, ctx, "pi2fw"),
            M::Paddsiw => self.lift_simd_write(iced, ctx, "paddsiw"),
            M::Paveb => self.lift_simd_write(iced, ctx, "paveb"),
            M::Pmachriw => self.lift_simd_write(iced, ctx, "pmachriw"),
            // AVX-512DQ qword unsigned min — sibling of already-wired Vpmaxuq.
            M::Vpminuq => self.lift_simd_write(iced, ctx, "vpminuq"),
            // AVX-512 FP16 conjugate complex FMA scalar — sibling of Vfmaddcsh.
            M::Vfcmaddcsh => self.lift_simd_write(iced, ctx, "vfcmaddcsh"),
            // KNC K-mask ortest bare form — flags-only, same pattern as Kortestb/w/d/q.
            M::Kortest => self.lift_kortest(iced, ctx),
            // VIA/Centaur PadLock Montgomery multiply — effect-only, same
            // implicit-multi-register class as Ccs_encrypt.
            M::Montmul => self.lift_intrinsic_writing_reported_regs(iced, ctx, "montmul"),
            // AVX-NE-CONVERT: bf16→f32 odd-even packed convert.
            M::Vcvtneoph2ps => self.lift_simd_write(iced, ctx, "vcvtneoph2ps"),
            // AVX-512ER extended-range exp2 — real writeback.
            // Vexp2ps is the single-precision sibling of Vexp2pd.
            M::Vexp2pd => self.lift_simd_write(iced, ctx, "vexp2pd"),
            M::Vexp2ps => self.lift_simd_write(iced, ctx, "vexp2ps"),

            // ── KNC / Xeon Phi (MVEX) vector tail ───────────────────────────
            // Direct siblings of MVEX forms already wired above (Vgmaxpd,
            // Vgminps, Vsubrps, Vpsubsetbd, Vpaddsetsd, Vpmadd233d,
            // Vcvtfxpntps2dq, Vcvtfxpntudq2ps …) — same vector writeback shape,
            // flag-neutral. Intrinsic granularity, as with the rest of the SIMD
            // surface.
            M::Vgmaxps => self.lift_simd_write(iced, ctx, "vgmaxps"),
            M::Vgminpd => self.lift_simd_write(iced, ctx, "vgminpd"),
            M::Vlog2ps => self.lift_simd_write(iced, ctx, "vlog2ps"),
            M::Vexp223ps => self.lift_simd_write(iced, ctx, "vexp223ps"),
            M::Vfixupnanpd => self.lift_simd_write(iced, ctx, "vfixupnanpd"),
            M::Vfmadd233ps => self.lift_simd_write(iced, ctx, "vfmadd233ps"),
            M::Vpmadd231d => self.lift_simd_write(iced, ctx, "vpmadd231d"),
            M::Vpmulhud => self.lift_simd_write(iced, ctx, "vpmulhud"),
            M::Vpadcd => self.lift_simd_write(iced, ctx, "vpadcd"),
            M::Vpaddsetcd => self.lift_simd_write(iced, ctx, "vpaddsetcd"),
            M::Vpsbbd => self.lift_simd_write(iced, ctx, "vpsbbd"),
            M::Vpsbbrd => self.lift_simd_write(iced, ctx, "vpsbbrd"),
            M::Vpsubrsetbd => self.lift_simd_write(iced, ctx, "vpsubrsetbd"),
            M::Vrndfxpntpd => self.lift_simd_write(iced, ctx, "vrndfxpntpd"),
            M::Vrndfxpntps => self.lift_simd_write(iced, ctx, "vrndfxpntps"),
            M::Vcvtfxpntpd2dq => self.lift_simd_write(iced, ctx, "vcvtfxpntpd2dq"),
            M::Vcvtfxpntpd2udq => self.lift_simd_write(iced, ctx, "vcvtfxpntpd2udq"),

            // ── 3DNow!+ (AMD) tail ──────────────────────────────────────────
            // Siblings of the 3DNow! forms already wired above (Pi2fw, Pavgusb,
            // Pfrsqrtv, Pmvgezb …) — write back into an MM register.
            M::Pf2iw => self.lift_simd_write(iced, ctx, "pf2iw"),
            M::Pfrcpit1 => self.lift_simd_write(iced, ctx, "pfrcpit1"),
            M::Pfrcpit2 => self.lift_simd_write(iced, ctx, "pfrcpit2"),
            M::Pfrcpv => self.lift_simd_write(iced, ctx, "pfrcpv"),
            M::Pfrsqit1 => self.lift_simd_write(iced, ctx, "pfrsqit1"),

            // ── Cyrix MMX-extension tail ────────────────────────────────────
            // Siblings of Paddsiw/Paveb/Pmachriw/Pdistib/Pmvgezb/Pmvnzb above.
            M::Pmagw => self.lift_simd_write(iced, ctx, "pmagw"),
            M::Psubsiw => self.lift_simd_write(iced, ctx, "psubsiw"),
            M::Pmvzb => self.lift_simd_write(iced, ctx, "pmvzb"),
            M::Pmvlzb => self.lift_simd_write(iced, ctx, "pmvlzb"),
            M::Pmulhriw => self.lift_simd_write(iced, ctx, "pmulhriw"),
            // AVX-512 FP16 remaining complex-arithmetic members. These complete
            // the {conj,plain} x {packed,scalar} x {fma,mul} matrix whose other
            // members are already wired above (Vfmaddcph/Vfcmulcph/Vfmaddcsh/
            // Vfmulcsh/Vfcmaddcsh) — real writeback, same shape.
            M::Vfcmaddcph => self.lift_simd_write(iced, ctx, "vfcmaddcph"),
            M::Vfmulcph => self.lift_simd_write(iced, ctx, "vfmulcph"),
            M::Vfcmulcsh => self.lift_simd_write(iced, ctx, "vfcmulcsh"),
            // AVX-NE-CONVERT broadcast forms — siblings of the already-wired
            // Vcvtneobf162ps/Vcvtneoph2ps packed converts.
            M::Vbcstnebf162ps => self.lift_simd_write(iced, ctx, "vbcstnebf162ps"),
            M::Vbcstnesh2ps => self.lift_simd_write(iced, ctx, "vbcstnesh2ps"),
            M::Vcvtneebf162ps => self.lift_simd_write(iced, ctx, "vcvtneebf162ps"),
            // KNC MVEX arithmetic siblings.
            M::Vaddnpd => self.lift_simd_write(iced, ctx, "vaddnpd"),
            M::Vpaddsetsd => self.lift_simd_write(iced, ctx, "vpaddsetsd"),
            M::Vgmaxabsps => self.lift_simd_write(iced, ctx, "vgmaxabsps"),
            M::Vcvtfxpntudq2ps => self.lift_simd_write(iced, ctx, "vcvtfxpntudq2ps"),
            M::Vpsubrd => self.lift_simd_write(iced, ctx, "vpsubrd"),
            M::Vaddsetsps => self.lift_simd_write(iced, ctx, "vaddsetsps"),
            // AVX-512DQ qword signed max — sibling of already-wired Vpmaxuq/Vpminuq.
            M::Vpmaxsq => self.lift_simd_write(iced, ctx, "vpmaxsq"),
            // KNC K-mask NOT bare form — same pattern as Kandn/Kxor/Kor bare (pass 60).
            M::Knot => self.lift_simd_write(iced, ctx, "knot"),
            // 3DNow! Pmulhrw — real writeback into MM register.
            M::Pmulhrw => self.lift_simd_write(iced, ctx, "pmulhrw"),
            // KNC MVEX prefetch NTA hint — effect-only.
            M::Vprefetchenta => self.lift_intrinsic_no_result(iced, ctx, "vprefetchenta"),
            // KNC MVEX arithmetic/convert siblings.
            M::Vsubrpd => self.lift_simd_write(iced, ctx, "vsubrpd"),
            M::Vaddnps => self.lift_simd_write(iced, ctx, "vaddnps"),
            M::Vcvtfxpntps2udq => self.lift_simd_write(iced, ctx, "vcvtfxpntps2udq"),
            M::Vcvtfxpntdq2ps => self.lift_simd_write(iced, ctx, "vcvtfxpntdq2ps"),
            M::Vfixupnanps => self.lift_simd_write(iced, ctx, "vfixupnanps"),
            // AVX-NE-CONVERT: bf16→f32 even-even packed convert.
            M::Vcvtneeph2ps => self.lift_simd_write(iced, ctx, "vcvtneeph2ps"),
            // Cyrix legacy — effect-only.
            M::Rdshr => self.lift_fpu_generic(iced, ctx, "rdshr"),
            M::Wrshr => self.lift_fpu_generic(iced, ctx, "wrshr"),
            M::Svldt => self.lift_fpu_generic(iced, ctx, "svldt"),
            M::Fstsg => self.lift_fpu_generic(iced, ctx, "fstsg"),
            M::Spflt => self.lift_fpu_generic(iced, ctx, "spflt"),
            // KNC cache-line evict hint — effect-only.
            M::Clevict1 => self.lift_intrinsic_no_result(iced, ctx, "clevict1"),

            // â"€â"€ MISC data / BCD â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Xlatb => self.lift_xlat(ctx),
            M::Aad => self.lift_bcd_intrinsic(iced, ctx, "aad"),
            M::Aam => self.lift_bcd_intrinsic(iced, ctx, "aam"),
            M::Aas => self.lift_bcd_intrinsic_noarg(ctx, "aas"),
            M::Aaa => self.lift_bcd_intrinsic_noarg(ctx, "aaa"),
            M::Daa => self.lift_bcd_intrinsic_noarg(ctx, "daa"),
            M::Das => self.lift_bcd_intrinsic_noarg(ctx, "das"),

            // â"€â"€ FPU integer operations â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Fiadd => self.lift_fpu_int_binop(iced, ctx, "fiadd"),
            M::Fisub => self.lift_fpu_int_binop(iced, ctx, "fisub"),
            M::Fisubr => self.lift_fpu_int_binop(iced, ctx, "fisubr"),
            M::Fimul => self.lift_fpu_int_binop(iced, ctx, "fimul"),
            M::Fidiv => self.lift_fpu_int_binop(iced, ctx, "fidiv"),
            M::Fidivr => self.lift_fpu_int_binop(iced, ctx, "fidivr"),
            M::Ficom => self.lift_fpu_int_compare(iced, ctx, false),
            M::Ficomp => self.lift_fpu_int_compare(iced, ctx, true),
            M::Fild => self.lift_fild(iced, ctx),
            M::Fist => self.lift_fist(iced, ctx, false),
            M::Fistp => self.lift_fist(iced, ctx, true),
            M::Fisttp => self.lift_fisttp(iced, ctx),

            // â"€â"€ FPU environment save/restore â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Fldenv => self.lift_intrinsic_mem_arg(iced, ctx, "fldenv"),
            M::Fstenv | M::Fnstenv => self.lift_intrinsic_mem_arg(iced, ctx, "fstenv"),
            M::Fsave | M::Fnsave => self.lift_intrinsic_mem_arg(iced, ctx, "fsave"),
            M::Frstor => self.lift_intrinsic_writing_reported_regs(iced, ctx, "frstor"),
            M::Fldcw => self.lift_fldcw(iced, ctx),
            M::Fstcw | M::Fnstcw => self.lift_fstcw(iced, ctx),
            M::Fstsw | M::Fnstsw => self.lift_fstsw(iced, ctx),

            // â"€â"€ FPU conditional move â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            M::Fcmovb => self.lift_fcmov(ctx, ConditionCode::b),
            M::Fcmove => self.lift_fcmov(ctx, ConditionCode::e),
            M::Fcmovbe => self.lift_fcmov(ctx, ConditionCode::be),
            M::Fcmovu => self.lift_fcmov_pf(ctx),
            M::Fcmovnb => self.lift_fcmov(ctx, ConditionCode::ae),
            M::Fcmovne => self.lift_fcmov(ctx, ConditionCode::ne),
            M::Fcmovnbe => self.lift_fcmov(ctx, ConditionCode::a),
            M::Fcmovnu => self.lift_fcmov_npf(ctx),

            // ── FPU basic arithmetic (register/memory form) ───────────────────
            M::Fadd => self.lift_fpu_write(iced, ctx, "fadd"),
            M::Faddp => self.lift_fpu_write(iced, ctx, "faddp"),
            M::Fsub => self.lift_fpu_write(iced, ctx, "fsub"),
            M::Fsubp => self.lift_fpu_write(iced, ctx, "fsubp"),
            M::Fsubr => self.lift_fpu_write(iced, ctx, "fsubr"),
            M::Fsubrp => self.lift_fpu_write(iced, ctx, "fsubrp"),
            M::Fmul => self.lift_fpu_write(iced, ctx, "fmul"),
            M::Fmulp => self.lift_fpu_write(iced, ctx, "fmulp"),
            M::Fdiv => self.lift_fpu_write(iced, ctx, "fdiv"),
            M::Fdivp => self.lift_fpu_write(iced, ctx, "fdivp"),
            M::Fdivr => self.lift_fpu_write(iced, ctx, "fdivr"),
            M::Fdivrp => self.lift_fpu_write(iced, ctx, "fdivrp"),

            // ── FPU load/store ─────────────────────────────────────────────
            // Fst/Fstp always decode an explicit ST(i)-or-memory
            // *destination* as operand 0, so route through `lift_fpu_write`
            // for real writeback (previously silently discarded via
            // `lift_fpu_generic`). Fxch swaps ST(0) and ST(i): operand 0 is
            // the ST(i) side, which does receive the old ST(0) value, so
            // `lift_fpu_write` applies there too.
            //
            // Fld is the OPPOSITE shape: its single decoded operand 0 is the
            // *source* (memory or ST(i)) being loaded — the true destination
            // is always the implicit ST(0) after the stack push, which
            // `write_operand(iced, 0, ...)` cannot express (it would
            // incorrectly write the result back into the memory/register
            // that was just read, corrupting state). Keep Fld on
            // `lift_fpu_generic` (honest discard, not a wrong write) until
            // there's a way to target "ST(0) after push" explicitly.
            M::Fld => self.lift_fpu_generic(iced, ctx, "fld"),
            // FBLD: load an 18-digit packed-BCD value from memory and push
            // it onto the x87 stack as ST(0) — same "load-shape ambiguity"
            // as FLD above (push, not a plain write to operand 0), so it
            // gets the same honest-discard `lift_fpu_generic` treatment.
            M::Fbld => self.lift_fpu_generic(iced, ctx, "fbld"),
            M::Fst => self.lift_fpu_write(iced, ctx, "fst"),
            M::Fstp => self.lift_fpu_write(iced, ctx, "fstp"),
            // FBSTP: store ST(0) as packed BCD to memory (operand 0 is
            // genuinely the destination, unlike FBLD's load/push shape) and
            // pop the x87 stack — real writeback via `lift_fpu_write`, same
            // shape as FSTP.
            M::Fbstp => self.lift_fpu_write(iced, ctx, "fbstp"),
            M::Fxch => self.lift_fpu_write(iced, ctx, "fxch"),
            M::Ffree => self.lift_fpu_generic(iced, ctx, "ffree"),
            // FSTPNCE: non-canonical-encoding alias of FSTP (store ST(0), pop) —
            // same real-writeback shape.
            M::Fstpnce => self.lift_fpu_write(iced, ctx, "fstp"),
            // FFREEP: non-canonical-encoding alias of FFREE that also pops —
            // no value computed, same honest-discard shape as FFREE.
            M::Ffreep => self.lift_fpu_generic(iced, ctx, "ffreep"),

            // ── FPU unary / transcendental ─────────────────────────────────
            // Implicit ST(0) source+dest, no decoded operand — unlike Fld,
            // there's no operand to misread as the destination, so
            // `lift_fpu_write_st0` can target ST(0) directly and unambiguously.
            M::Fchs => self.lift_fpu_write_st0(iced, ctx, "fchs"),
            M::Fabs => self.lift_fpu_write_st0(iced, ctx, "fabs"),
            M::Fsqrt => self.lift_fpu_write_st0(iced, ctx, "fsqrt"),
            M::Fsin => self.lift_fpu_write_st0(iced, ctx, "fsin"),
            M::Fcos => self.lift_fpu_write_st0(iced, ctx, "fcos"),
            M::Fsincos => self.lift_fpu_write_st0(iced, ctx, "fsincos"),
            M::Fptan => self.lift_fpu_write_st0(iced, ctx, "fptan"),
            // `FPATAN`/`FYL2X`/`FYL2XP1` compute into ST(1) and then POP, so
            // the decoder names ST(1) as the destination while the post-pop
            // view puts the result in ST(0). This IL does not model the x87
            // stack positionally, and under that model BOTH slots are
            // destroyed: ST(1)'s old value is overwritten by the computation
            // and ST(0)'s is consumed. Writing only ST(0) left a consumer free
            // to believe ST(1) survived. Neither write is invented.
            M::Fpatan => self.lift_fpu_write_st0_and_st1(iced, ctx, "fpatan"),
            M::Fyl2x => self.lift_fpu_write_st0_and_st1(iced, ctx, "fyl2x"),
            M::Fyl2xp1 => self.lift_fpu_write_st0_and_st1(iced, ctx, "fyl2xp1"),
            M::F2xm1 => self.lift_fpu_write_st0(iced, ctx, "f2xm1"),
            M::Fprem => self.lift_fpu_write_st0(iced, ctx, "fprem"),
            M::Fprem1 => self.lift_fpu_write_st0(iced, ctx, "fprem1"),
            M::Fscale => self.lift_fpu_write_st0(iced, ctx, "fscale"),
            M::Frndint => self.lift_fpu_write_st0(iced, ctx, "frndint"),
            M::Fxtract => self.lift_fpu_write_st0(iced, ctx, "fxtract"),
            // Fdecstp/Fincstp only rotate the stack TOP pointer — no value
            // is computed or written, so the no-writeback Intrinsic is
            // correct as-is (not a bug, nothing to fix).
            M::Fdecstp => self.lift_fpu_generic(iced, ctx, "fdecstp"),
            M::Fincstp => self.lift_fpu_generic(iced, ctx, "fincstp"),

            // ── FPU compare / classify ─────────────────────────────────────
            M::Fxam => self.lift_fpu_generic(iced, ctx, "fxam"),
            M::Ftst => self.lift_fpu_generic(iced, ctx, "ftst"),
            M::Fcom => self.lift_fpu_generic(iced, ctx, "fcom"),
            M::Fcomp => self.lift_fpu_generic(iced, ctx, "fcomp"),
            M::Fcompp => self.lift_fpu_generic(iced, ctx, "fcompp"),
            M::Fucom => self.lift_fpu_generic(iced, ctx, "fucom"),
            M::Fucomp => self.lift_fpu_generic(iced, ctx, "fucomp"),
            M::Fucompp => self.lift_fpu_generic(iced, ctx, "fucompp"),
            M::Fcomi => self.lift_fpu_generic(iced, ctx, "fcomi"),
            M::Fcomip => self.lift_fpu_generic(iced, ctx, "fcomip"),
            M::Fucomi => self.lift_fpu_generic(iced, ctx, "fucomi"),
            M::Fucomip => self.lift_fpu_generic(iced, ctx, "fucomip"),

            // ── FPU load-constant ───────────────────────────────────────────
            // No decoded operand; pushes a fixed constant onto ST(0) —
            // same unambiguous-destination shape as the unary/transcendental
            // group above.
            M::Fldz => self.lift_fpu_write_st0(iced, ctx, "fldz"),
            M::Fld1 => self.lift_fpu_write_st0(iced, ctx, "fld1"),
            M::Fldpi => self.lift_fpu_write_st0(iced, ctx, "fldpi"),
            M::Fldl2t => self.lift_fpu_write_st0(iced, ctx, "fldl2t"),
            M::Fldl2e => self.lift_fpu_write_st0(iced, ctx, "fldl2e"),
            M::Fldlg2 => self.lift_fpu_write_st0(iced, ctx, "fldlg2"),
            M::Fldln2 => self.lift_fpu_write_st0(iced, ctx, "fldln2"),

            // ── FPU init / clear ─────────────────────────────────────────────
            M::Finit | M::Fninit => self.lift_fpu_generic(iced, ctx, "finit"),
            M::Fclex | M::Fnclex => self.lift_fpu_generic(iced, ctx, "fclex"),

            // ── AVX / AVX2 vector moves ─────────────────────────────────────
            M::Vmovaps | M::Vmovups | M::Vmovapd | M::Vmovupd => {
                self.lift_vex_move(iced, ctx);
            }
            // AVX/AVX2/AVX-512 integer vector move — major gap found pass
            // 42: these were completely undispatched despite being some of
            // the most common instructions in real AVX-compiled code
            // (Vmovdqa32/64 and Vmovdqu8/16/32/64 are separate `Mnemonic`
            // ids for the EVEX masked-type-tagged forms, not just decode
            // variants of the bare VEX form — all real-writeback moves,
            // same shape as Vmovaps above).
            M::Vmovdqa
            | M::Vmovdqa32
            | M::Vmovdqa64
            | M::Vmovdqu
            | M::Vmovdqu8
            | M::Vmovdqu16
            | M::Vmovdqu32
            | M::Vmovdqu64 => {
                self.lift_vex_move(iced, ctx);
            }
            // AVX scalar single/double move (VMOVSS/VMOVSD) — arguably the
            // single highest-value miss in this pass: extremely common in
            // any AVX-compiled scalar floating-point code. No string-op
            // disambiguation needed here (unlike legacy `Movsd`) since
            // there's no REP-prefixed VEX string-move form.
            M::Vmovss | M::Vmovsd => self.lift_vex_move(iced, ctx),
            // AVX-512 FP16 scalar move (VMOVSH) and GPR<->XMM word move
            // (VMOVW) — same real-move shape as Vmovd/Vmovq below.
            M::Vmovsh | M::Vmovw => self.lift_vex_move(iced, ctx),

            // ── AVX / AVX2 floating-point arithmetic (3-operand VEX) ────────
            M::Vaddps | M::Vaddpd => self.lift_vex_binop(iced, ctx, VexBinOp::Add),
            M::Vsubps | M::Vsubpd => self.lift_vex_binop(iced, ctx, VexBinOp::Sub),
            M::Vmulps | M::Vmulpd => self.lift_vex_binop(iced, ctx, VexBinOp::Mul),
            M::Vdivps | M::Vdivpd => self.lift_vex_binop(iced, ctx, VexBinOp::Div),
            M::Vandps | M::Vandpd => self.lift_vex_binop(iced, ctx, VexBinOp::And),
            M::Vorps | M::Vorpd => self.lift_vex_binop(iced, ctx, VexBinOp::Or),
            M::Vxorps | M::Vxorpd => self.lift_vex_binop(iced, ctx, VexBinOp::Xor),
            M::Vandnps | M::Vandnpd => self.lift_vex_binop(iced, ctx, VexBinOp::Andn),
            // Scalar (single-element) VEX arithmetic siblings of the packed
            // forms above — same 3-operand `lift_vex_binop` shape.
            M::Vaddsd | M::Vaddss => self.lift_vex_binop(iced, ctx, VexBinOp::Add),
            M::Vsubsd | M::Vsubss => self.lift_vex_binop(iced, ctx, VexBinOp::Sub),
            M::Vmulsd | M::Vmulss => self.lift_vex_binop(iced, ctx, VexBinOp::Mul),
            M::Vdivsd | M::Vdivss => self.lift_vex_binop(iced, ctx, VexBinOp::Div),
            // AVX-512 FP16 (`ph`/`sh` suffix) arithmetic — same operand
            // shape as the already-covered ps/pd/sd/ss siblings, reusing
            // `lift_vex_binop` unchanged. This IR has no dedicated
            // half-precision lane type in its `Size` enum, same as it has
            // no dedicated float32/float64 distinction — element width is
            // carried by the destination register size + the `Intrinsic`
            // name, not the `Size` enum, so no new IR support is needed.
            M::Vaddph | M::Vaddsh => self.lift_vex_binop(iced, ctx, VexBinOp::Add),
            M::Vsubph | M::Vsubsh => self.lift_vex_binop(iced, ctx, VexBinOp::Sub),
            M::Vmulph | M::Vmulsh => self.lift_vex_binop(iced, ctx, VexBinOp::Mul),
            M::Vdivph | M::Vdivsh => self.lift_vex_binop(iced, ctx, VexBinOp::Div),
            // Alternating add/sub (odd lanes add, even lanes subtract).
            M::Vaddsubpd | M::Vaddsubps => self.lift_simd_write(iced, ctx, "addsub"),

            // ── Legacy SSE/SSE2 scalar + packed arithmetic (2-operand form:
            //    `dst = dst OP src`) — `lift_vex_binop` already falls back to
            //    the 2-operand read path when `op_count() < 3`, so the same
            //    helper covers both the AVX and legacy encodings. Scalar
            //    (SS/SD) and packed (PS/PD) forms share semantics here; exact
            //    "preserve upper lanes on scalar ops" behavior is the same
            //    simplification already applied to the AVX arms above. ──────
            M::Addps | M::Addpd | M::Addss | M::Addsd => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Add);
            }
            M::Subps | M::Subpd | M::Subss | M::Subsd => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Sub);
            }
            M::Mulps | M::Mulpd | M::Mulss | M::Mulsd => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Mul);
            }
            M::Divps | M::Divpd | M::Divss | M::Divsd => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Div);
            }
            M::Andps | M::Andpd => self.lift_vex_binop(iced, ctx, VexBinOp::And),
            M::Orps | M::Orpd => self.lift_vex_binop(iced, ctx, VexBinOp::Or),
            M::Xorps | M::Xorpd => self.lift_vex_binop(iced, ctx, VexBinOp::Xor),
            M::Andnps | M::Andnpd => self.lift_vex_binop(iced, ctx, VexBinOp::Andn),
            M::Pand => self.lift_vex_binop(iced, ctx, VexBinOp::And),
            M::Por => self.lift_vex_binop(iced, ctx, VexBinOp::Or),
            M::Pxor => self.lift_vex_binop(iced, ctx, VexBinOp::Xor),
            M::Pandn => self.lift_vex_binop(iced, ctx, VexBinOp::Andn),
            M::Paddb | M::Paddw | M::Paddd | M::Paddq => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Add);
            }
            M::Psubb | M::Psubw | M::Psubd | M::Psubq => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Sub);
            }
            M::Pshufb => self.lift_vex_pshufb(iced, ctx),

            // ── Legacy SSE scalar/packed sqrt + min/max (intrinsics — no
            //    direct LLIL expr grammar for these) ─────────────────────────
            M::Sqrtps | M::Sqrtpd | M::Sqrtss | M::Sqrtsd => {
                self.lift_simd_unary(iced, ctx, "sqrt");
            }
            M::Minps | M::Minpd | M::Minss | M::Minsd => {
                self.lift_simd_write(iced, ctx, "min");
            }
            M::Maxps | M::Maxpd | M::Maxss | M::Maxsd => {
                self.lift_simd_write(iced, ctx, "max");
            }
            M::Comiss | M::Comisd => {
                self.lift_comi(iced, ctx, "comi");
            }
            M::Ucomiss | M::Ucomisd => {
                self.lift_comi(iced, ctx, "ucomi");
            }
            M::Cvtsi2sd
            | M::Cvtsi2ss
            | M::Cvttss2si
            | M::Cvttsd2si
            | M::Cvtss2si
            | M::Cvtsd2si
            | M::Cvtps2pd
            | M::Cvtpd2ps
            | M::Cvtdq2ps
            | M::Cvtps2dq
            | M::Cvttps2dq
            | M::Cvtdq2pd
            | M::Cvtpd2dq
            | M::Cvttpd2dq
            | M::Cvtss2sd
            | M::Cvtsd2ss => {
                self.lift_simd_write(iced, ctx, "cvt");
            }
            M::Pshufd | M::Pshuflw | M::Pshufhw => self.lift_simd_write(iced, ctx, "pshuf"),
            M::Punpcklbw
            | M::Punpcklwd
            | M::Punpckldq
            | M::Punpcklqdq
            | M::Punpckhbw
            | M::Punpckhwd
            | M::Punpckhdq
            | M::Punpckhqdq
            | M::Unpcklps
            | M::Unpckhps
            | M::Unpcklpd
            | M::Unpckhpd => self.lift_simd_write(iced, ctx, "unpck"),
            M::Pcmpeqb | M::Pcmpeqw | M::Pcmpeqd => self.lift_simd_write(iced, ctx, "pcmpeq"),
            M::Pcmpgtb | M::Pcmpgtw | M::Pcmpgtd => self.lift_simd_write(iced, ctx, "pcmpgt"),
            M::Pmovmskb | M::Movmskps | M::Movmskpd => {
                self.lift_simd_write(iced, ctx, "movmsk");
            }
            M::Pminub | M::Pminsw | M::Pminsb | M::Pminud | M::Pminsd | M::Pminuw => {
                self.lift_simd_write(iced, ctx, "pmin");
            }
            M::Pmaxub | M::Pmaxsw | M::Pmaxsb | M::Pmaxud | M::Pmaxsd | M::Pmaxuw => {
                self.lift_simd_write(iced, ctx, "pmax");
            }
            M::Palignr => self.lift_simd_write(iced, ctx, "palignr"),
            M::Pinsrb | M::Pinsrw | M::Pinsrd | M::Pinsrq => {
                self.lift_simd_write(iced, ctx, "pinsr");
            }
            M::Pextrb | M::Pextrw | M::Pextrd | M::Pextrq => {
                self.lift_simd_write(iced, ctx, "pextr");
            }
            M::Pmulhw | M::Pmullw | M::Pmuludq | M::Pmuldq | M::Pmulld | M::Pmulhuw => {
                self.lift_simd_write(iced, ctx, "pmul");
            }
            // PMULHRSW (SSSE3): packed multiply-high with round-and-scale —
            // real writeback, same "intrinsic name" shape as PMUL* above.
            M::Pmulhrsw => self.lift_simd_write(iced, ctx, "pmulhrsw"),
            // PHMINPOSUW (SSE4.1): horizontal minimum of packed unsigned
            // words, result placed in lane 0 with its index in lane 1.
            M::Phminposuw => self.lift_simd_write(iced, ctx, "phminposuw"),
            // ── Packed shifts (logical left/right, arithmetic right) ─────────
            // PSLLW/D/Q, PSRLW/D/Q, PSRAW/D take either an immediate count, a
            // 64-bit MMX/GPR-low count, or a full xmm count operand
            // (iced/`read_operand` already normalizes all three forms), and
            // shift every packed lane by that count (out-of-range counts
            // zero the lane per the SDM). PSLLDQ/PSRLDQ shift the *whole*
            // register by whole bytes rather than per-lane. All are
            // real-writeback ops, so `lift_simd_write` (not
            // `lift_fpu_generic`) is correct here.
            M::Psllw | M::Pslld | M::Psllq => self.lift_simd_write(iced, ctx, "psll"),
            M::Psrlw | M::Psrld | M::Psrlq => self.lift_simd_write(iced, ctx, "psrl"),
            M::Psraw | M::Psrad => self.lift_simd_write(iced, ctx, "psra"),
            M::Pslldq => self.lift_simd_write(iced, ctx, "pslldq"),
            M::Psrldq => self.lift_simd_write(iced, ctx, "psrldq"),
            // ── Pack (saturating narrow) ───────────────────────────────────
            M::Packsswb | M::Packssdw => self.lift_simd_write(iced, ctx, "packss"),
            M::Packuswb | M::Packusdw => self.lift_simd_write(iced, ctx, "packus"),
            // ── Average / horizontal multiply-add / sum-of-abs-diff ───────
            M::Pavgb | M::Pavgw => self.lift_simd_write(iced, ctx, "pavg"),
            M::Pmaddwd | M::Pmaddubsw => self.lift_simd_write(iced, ctx, "pmadd"),
            M::Psadbw => self.lift_simd_write(iced, ctx, "psadbw"),
            // MMX 64-bit shuffle (immediate byte selects each of the four
            // 16-bit lanes, same shape as PSHUFD but on an MM register).
            M::Pshufw => self.lift_simd_write(iced, ctx, "pshuf"),
            // ── SSE packed/scalar compare-with-predicate ───────────────────
            // CMPPS/CMPPD/CMPSS and non-string CMPSD encode an imm8
            // predicate (EQ/LT/LE/UNORD/...) selecting the comparison;
            // `is_string_op` disambiguates CMPSD (SSE compare) from the
            // REP-prefixed string-compare mnemonic that shares the same
            // `Mnemonic::Cmpsd` mnemonic id.
            M::Cmpps | M::Cmppd | M::Cmpss => self.lift_simd_write(iced, ctx, "cmpp"),
            M::Cmpsd if !is_string_op(iced) => self.lift_simd_write(iced, ctx, "cmpp"),
            M::Shufps | M::Shufpd => self.lift_simd_write(iced, ctx, "shuf"),
            // SSE4.1: imm8-selected blend (mask reg/imm8), and imm8-selected
            // dot-product; SSE3: packed add/sub-alternating (addsub) and
            // horizontal add/sub (haddpd/ps, hsubpd/ps); SSE4.1: extract/
            // insert a single packed-single lane via imm8. All single-
            // destination, real-writeback via `lift_simd_write`.
            M::Blendpd | M::Blendps => self.lift_simd_write(iced, ctx, "blend"),
            M::Blendvpd | M::Blendvps => self.lift_simd_write(iced, ctx, "blendv"),
            M::Dppd | M::Dpps => self.lift_simd_write(iced, ctx, "dp"),
            M::Addsubpd | M::Addsubps => self.lift_simd_write(iced, ctx, "addsub"),
            M::Haddpd | M::Haddps => self.lift_simd_write(iced, ctx, "hadd"),
            M::Hsubpd | M::Hsubps => self.lift_simd_write(iced, ctx, "hsub"),
            M::Insertps => self.lift_simd_write(iced, ctx, "insertps"),
            // AVX (VEX-encoded) counterparts of the above — same
            // named-intrinsic writeback shape, real gap: the legacy SSE3/
            // SSE4.1 forms above were wired but their V-prefixed siblings
            // were not.
            M::Vhaddpd | M::Vhaddps => self.lift_simd_write(iced, ctx, "hadd"),
            M::Vhsubpd | M::Vhsubps => self.lift_simd_write(iced, ctx, "hsub"),
            M::Vinsertps => self.lift_simd_write(iced, ctx, "insertps"),
            M::Extractps => self.lift_simd_write(iced, ctx, "extractps"),
            // MMX<->packed-float conversions (legacy, MM0-7 <-> XMM):
            // Cvtpi2pd/ps read a packed-int MM source and write packed
            // floats to an XMM dest; Cvt(t)pd2pi/Cvt(t)ps2pi read packed
            // floats from XMM/mem and write packed ints to an MM dest.
            // Both directions have a real single destination at operand 0,
            // so `lift_simd_write` applies unmodified.
            M::Cvtpi2pd | M::Cvtpi2ps => self.lift_simd_write(iced, ctx, "cvtpi2p"),
            M::Cvtpd2pi | M::Cvttpd2pi => self.lift_simd_write(iced, ctx, "cvtpd2pi"),
            M::Cvtps2pi | M::Cvttps2pi => self.lift_simd_write(iced, ctx, "cvtps2pi"),
            // SSE4A (AMD-specific): Extrq extracts a bitfield from xmm into
            // itself; Insertq inserts a bitfield from src into dest — both
            // single-destination (operand 0).
            M::Extrq => self.lift_simd_write(iced, ctx, "extrq"),
            M::Insertq => self.lift_simd_write(iced, ctx, "insertq"),
            // Legacy MMX/SSE2 saturating packed add (real writeback).
            M::Paddsb | M::Paddsw => self.lift_simd_write(iced, ctx, "paddsat"),
            M::Paddusb | M::Paddusw => self.lift_simd_write(iced, ctx, "paddusat"),
            M::Psubsb | M::Psubsw => self.lift_simd_write(iced, ctx, "psubsat"),
            M::Psubusb | M::Psubusw => self.lift_simd_write(iced, ctx, "psubusat"),
            // MMX<->XMM low-64-bit move (real writeback, same shape as the
            // already-covered Vmovd/Vmovq via `lift_vex_move`... but these
            // are legacy non-VEX forms, so use `lift_simd_write` instead).
            M::Movdq2q | M::Movq2dq => self.lift_simd_write(iced, ctx, "movq2q"),
            // Non-temporal scalar single/double store (real memory
            // writeback, same shape as the already-covered Movntss/Movntsd
            // siblings Movntps/Movntpd/Movnti).
            M::Movntss | M::Movntsd => self.lift_vector_move(iced, ctx, iced.mnemonic()),
            // SSE4.1 sign/zero-extend (packed byte/word/dword -> wider lanes)
            M::Pmovsxbw | M::Pmovsxbd | M::Pmovsxbq | M::Pmovsxwd | M::Pmovsxwq
            | M::Pmovsxdq => self.lift_simd_write(iced, ctx, "pmovsx"),
            M::Pmovzxbw | M::Pmovzxbd | M::Pmovzxbq | M::Pmovzxwd | M::Pmovzxwq
            | M::Pmovzxdq => self.lift_simd_write(iced, ctx, "pmovzx"),
            // SSSE3: absolute value, sign (per-lane copy-negate-or-zero),
            // horizontal add/sub (each single-destination via operand 0).
            M::Pabsb | M::Pabsw | M::Pabsd => self.lift_simd_write(iced, ctx, "pabs"),
            M::Psignb | M::Psignw | M::Psignd => self.lift_simd_write(iced, ctx, "psign"),
            M::Phaddw | M::Phaddd => self.lift_simd_write(iced, ctx, "phadd"),
            M::Phaddsw => self.lift_simd_write(iced, ctx, "phaddsw"),
            M::Phsubw | M::Phsubd => self.lift_simd_write(iced, ctx, "phsub"),
            M::Phsubsw => self.lift_simd_write(iced, ctx, "phsubsw"),
            // SSE4.1/4.2 64-bit-lane compare (legacy, non-VEX forms).
            M::Pcmpeqq => self.lift_simd_write(iced, ctx, "pcmpeq"),
            M::Pcmpgtq => self.lift_simd_write(iced, ctx, "pcmpgt"),
            // SSE4.1: variable blend (xmm0-selected) / imm8-selected blend.
            M::Pblendvb => self.lift_simd_write(iced, ctx, "blendv"),
            M::Pblendw => self.lift_simd_write(iced, ctx, "blend"),
            // ── AVX (VEX-encoded) counterparts of the legacy MMX/SSE integer
            // ops above ─────────────────────────────────────────────────────
            // Systematic gap found pass 35: every legacy `P*`/`Pmovsx`/
            // `Pmovzx`/`Punpck*` integer-SIMD mnemonic above was wired, but
            // essentially none of their `V`-prefixed AVX-128/256 siblings
            // were. Same named-intrinsic writeback shape throughout — no new
            // helper logic needed, just the missing dispatch arms.
            M::Vpabsb | M::Vpabsw | M::Vpabsd => self.lift_simd_write(iced, ctx, "pabs"),
            M::Vpsignb | M::Vpsignw | M::Vpsignd => self.lift_simd_write(iced, ctx, "psign"),
            M::Vphaddw | M::Vphaddd => self.lift_simd_write(iced, ctx, "phadd"),
            M::Vphaddsw => self.lift_simd_write(iced, ctx, "phaddsw"),
            M::Vphsubw | M::Vphsubd => self.lift_simd_write(iced, ctx, "phsub"),
            M::Vphsubsw => self.lift_simd_write(iced, ctx, "phsubsw"),
            M::Vphminposuw => self.lift_simd_write(iced, ctx, "phminposuw"),
            // NOTE: Vpblendvb is already dispatched below (grouped with
            // Vblendvps/Vblendvpd as "vblendv") — do not re-add it here.
            M::Vpblendw => self.lift_simd_write(iced, ctx, "blend"),
            M::Vpshufhw | M::Vpshuflw => self.lift_simd_write(iced, ctx, "pshuf"),
            M::Vpunpckhbw
            | M::Vpunpckhwd
            | M::Vpunpckhdq
            | M::Vpunpckhqdq
            | M::Vpunpcklbw
            | M::Vpunpcklwd
            | M::Vpunpckldq
            | M::Vpunpcklqdq => self.lift_simd_write(iced, ctx, "unpck"),
            M::Vpinsrb | M::Vpinsrw | M::Vpinsrd | M::Vpinsrq => {
                self.lift_simd_write(iced, ctx, "pinsr");
            }
            M::Vpextrb | M::Vpextrw | M::Vpextrd | M::Vpextrq => {
                self.lift_simd_write(iced, ctx, "pextr");
            }
            M::Vpmulhw | M::Vpmullw | M::Vpmuludq | M::Vpmuldq | M::Vpmulld | M::Vpmulhuw => {
                self.lift_simd_write(iced, ctx, "pmul");
            }
            // AVX-512DQ packed multiply-low quadword — the dword `Vpmulld`
            // sibling above was wired, the quadword-width form wasn't.
            M::Vpmullq => self.lift_simd_write(iced, ctx, "pmul"),
            // KNC-only MVEX dword multiply-high (Knights Corner precursor
            // of AVX-512) — same 3-operand write shape as the VEX/EVEX
            // forms above, low real-world value but in scope.
            M::Vpmulhd => self.lift_simd_write(iced, ctx, "pmul"),
            // KNC-only MVEX packed-float scale — same shape as the
            // already-wired Vscalefps/pd (different mnemonic, same
            // AVX-512-scalef-precursor family).
            M::Vscaleps => self.lift_simd_write(iced, ctx, "vscalef"),
            // KNC-only MVEX 128-bit-lane permute (precursor of the
            // Vshufi32x4/Vperm* family) — same real writeback shape.
            M::Vpermf32x4 => self.lift_simd_write(iced, ctx, "vperm"),
            // KNC-only MVEX packed-dword less-than compare, writes a
            // k-register — same shape as the already-wired Kmask family.
            M::Vpcmpltd => self.lift_simd_write(iced, ctx, "vpcmp"),
            // AVX2 imm8-selected dword blend (VEX 3-operand form of the
            // legacy imm8 BLENDPS/PD idea, but integer dwords) — real,
            // fairly common instruction that was simply never wired.
            M::Vpblendd => self.lift_simd_write(iced, ctx, "blend"),
            M::Vpmulhrsw => self.lift_simd_write(iced, ctx, "pmulhrsw"),
            M::Vpsllw | M::Vpslld | M::Vpsllq => self.lift_simd_write(iced, ctx, "psll"),
            M::Vpsrlw | M::Vpsrld | M::Vpsrlq => self.lift_simd_write(iced, ctx, "psrl"),
            // Variable per-lane shift (VPSLLVD/Q/W, VPSRLVD/Q/W,
            // VPSRAVD/W/Q) — each lane shifted by an independently-supplied
            // count from the second source operand, instead of one
            // instruction-wide immediate/count. Extremely common in
            // vectorized code (e.g. per-element bit manipulation). Real
            // writeback, same named-intrinsic shape as the uniform-count
            // shifts above (this IR doesn't model true per-lane variable
            // shift, so it's approximated the same way as every other
            // packed op here — real operand reads/writeback, not exact
            // per-lane semantics).
            M::Vpsllvd | M::Vpsllvq | M::Vpsllvw => self.lift_simd_write(iced, ctx, "psllv"),
            M::Vpsrlvd | M::Vpsrlvq | M::Vpsrlvw => self.lift_simd_write(iced, ctx, "psrlv"),
            M::Vpsravd | M::Vpsravw | M::Vpsravq => self.lift_simd_write(iced, ctx, "psrav"),
            // Vpsraq (AVX-512): arithmetic shift right quadword — the
            // legacy ISA has no non-VEX PSRAQ (only 32-bit-and-narrower
            // arithmetic shifts existed pre-AVX-512), so there's no
            // "legacy sibling" precedent to follow here, just the same
            // `lift_simd_write` shape as its Vpsraw/Vpsrad neighbours.
            M::Vpsraw | M::Vpsrad | M::Vpsraq => self.lift_simd_write(iced, ctx, "psra"),
            // AVX-512VBMI2 funnel shift (concatenate two sources, shift by
            // a count, keep the middle bits) — real writeback, named
            // intrinsic (no funnel-shift primitive exists in this IR).
            M::Vpshldw | M::Vpshldd | M::Vpshldq => self.lift_simd_write(iced, ctx, "pshld"),
            M::Vpshrdw | M::Vpshrdd | M::Vpshrdq => self.lift_simd_write(iced, ctx, "pshrd"),
            // Variable-per-lane-count funnel shift siblings of the
            // immediate-count forms above.
            M::Vpshldvd | M::Vpshldvq | M::Vpshldvw => {
                self.lift_simd_write(iced, ctx, "pshldv");
            }
            M::Vpshrdvd | M::Vpshrdvq | M::Vpshrdvw => {
                self.lift_simd_write(iced, ctx, "pshrdv");
            }
            // IFMA: 52-bit-precision packed multiply, keeping the high or
            // low half of the product added into the accumulator — real
            // writeback, same shape as the VNNI dot-product family.
            M::Vpmadd52huq => self.lift_simd_write(iced, ctx, "vpmadd52h"),
            M::Vpmadd52luq => self.lift_simd_write(iced, ctx, "vpmadd52l"),
            // AVX-512BITALG packed population count / bit-mask-from-
            // bitwise-AND-then-popcount — real writeback.
            M::Vpopcntb | M::Vpopcntw | M::Vpopcntd | M::Vpopcntq => {
                self.lift_simd_write(iced, ctx, "vpopcnt");
            }
            M::Vpshufbitqmb => self.lift_simd_write(iced, ctx, "vpshufbitqmb"),
            // AVX-512CD conflict detection (find equal earlier lanes) /
            // AVX-512VBMI cross-lane multi-shift — real writeback, no
            // existing IR primitive so both stay named intrinsics.
            M::Vpconflictd | M::Vpconflictq => self.lift_simd_write(iced, ctx, "vpconflict"),
            M::Vpmultishiftqb => self.lift_simd_write(iced, ctx, "vpmultishiftqb"),
            M::Vpslldq => self.lift_simd_write(iced, ctx, "pslldq"),
            M::Vpsrldq => self.lift_simd_write(iced, ctx, "psrldq"),
            M::Vpacksswb | M::Vpackssdw => self.lift_simd_write(iced, ctx, "packss"),
            M::Vpackuswb | M::Vpackusdw => self.lift_simd_write(iced, ctx, "packus"),
            M::Vpavgb | M::Vpavgw => self.lift_simd_write(iced, ctx, "pavg"),
            M::Vpmaddwd | M::Vpmaddubsw => self.lift_simd_write(iced, ctx, "pmadd"),
            M::Vpsadbw => self.lift_simd_write(iced, ctx, "psadbw"),
            M::Vpaddsb | M::Vpaddsw => self.lift_simd_write(iced, ctx, "paddsat"),
            M::Vpaddusb | M::Vpaddusw => self.lift_simd_write(iced, ctx, "paddusat"),
            M::Vpsubsb | M::Vpsubsw => self.lift_simd_write(iced, ctx, "psubsat"),
            M::Vpsubusb | M::Vpsubusw => self.lift_simd_write(iced, ctx, "psubusat"),
            M::Vpmovsxbw | M::Vpmovsxbd | M::Vpmovsxbq | M::Vpmovsxwd | M::Vpmovsxwq
            | M::Vpmovsxdq => self.lift_simd_write(iced, ctx, "pmovsx"),
            M::Vpmovzxbw | M::Vpmovzxbd | M::Vpmovzxbq | M::Vpmovzxwd | M::Vpmovzxwq
            | M::Vpmovzxdq => self.lift_simd_write(iced, ctx, "pmovzx"),
            // AVX-512 truncating narrow-conversion (the inverse of
            // pmovsx/pmovzx above — wide lane truncated down to a narrower
            // lane, e.g. QWORD->BYTE) — same single-destination real-
            // writeback shape.
            M::Vpmovqb | M::Vpmovqw | M::Vpmovqd | M::Vpmovdb | M::Vpmovdw | M::Vpmovwb => {
                self.lift_simd_write(iced, ctx, "pmovtrunc");
            }
            // Signed- and unsigned-saturating narrow-conversion siblings of
            // the plain truncating forms above (clamp to the narrower
            // lane's representable range instead of dropping high bits) —
            // same single-destination real-writeback shape.
            M::Vpmovsdb
            | M::Vpmovsdw
            | M::Vpmovsqb
            | M::Vpmovsqd
            | M::Vpmovsqw
            | M::Vpmovswb => {
                self.lift_simd_write(iced, ctx, "pmovs");
            }
            M::Vpmovusdb
            | M::Vpmovusdw
            | M::Vpmovusqb
            | M::Vpmovusqd
            | M::Vpmovusqw
            | M::Vpmovuswb => {
                self.lift_simd_write(iced, ctx, "pmovus");
            }
            // NOTE: Vpminub/Vpminsw/Vpmaxub/Vpmaxsw are already dispatched
            // below (grouped as "vpminmax") — only the remaining width
            // variants were missing here.
            M::Vpminsb | M::Vpminud | M::Vpminsd | M::Vpminuw | M::Vpminsq => {
                self.lift_simd_write(iced, ctx, "pmin");
            }
            M::Vpmaxsb | M::Vpmaxud | M::Vpmaxsd | M::Vpmaxuw => {
                self.lift_simd_write(iced, ctx, "pmax");
            }
            // AVX-512DQ quadword-lane unsigned max — sibling of the dword
            // Vpmaxud above, same shape.
            M::Vpmaxuq => self.lift_simd_write(iced, ctx, "pmax"),
            M::Vpcmpestri | M::Vpcmpistri => {
                self.lift_string_compare_write(iced, ctx, "pcmpstri", Register::ECX, Size::DWord);
            }
            // 64-bit-index-register sibling of Vpcmpestri above.
            M::Vpcmpestri64 => {
                self.lift_string_compare_write(iced, ctx, "pcmpstri", Register::ECX, Size::DWord);
            }
            M::Vpcmpestrm | M::Vpcmpistrm => {
                self.lift_string_compare_write(iced, ctx, "pcmpstrm", Register::XMM0, Size::OWord);
            }
            // VEX 64-bit-index-register variant of Vpcmpestrm (implicit
            // ECX/EDX index registers become RCX/RDX in 64-bit mode) — same
            // implicit-XMM0-destination shape as the 32-bit form above.
            M::Vpcmpestrm64 => {
                self.lift_string_compare_write(iced, ctx, "pcmpstrm", Register::XMM0, Size::OWord);
            }
            M::Vprefetchnta => self.lift_intrinsic_no_result(iced, ctx, "prefetchnta"),
            // SSE4.1 imm8-rounding-mode round; SSE reciprocal/rsqrt
            // approximations. All real single-destination writes.
            M::Roundpd | M::Roundps | M::Roundsd | M::Roundss => {
                self.lift_simd_write(iced, ctx, "round");
            }
            M::Rcpps | M::Rcpss => self.lift_simd_write(iced, ctx, "rcp"),
            M::Vrcpps | M::Vrcpss => self.lift_simd_write(iced, ctx, "rcp"),
            M::Rsqrtps | M::Rsqrtss => self.lift_simd_write(iced, ctx, "rsqrt"),
            M::Vrsqrtps | M::Vrsqrtss => self.lift_simd_write(iced, ctx, "rsqrt"),
            M::Vrcpsh => self.lift_simd_write(iced, ctx, "rcp"),
            M::Vrsqrtsh => self.lift_simd_write(iced, ctx, "rsqrt"),
            // AVX-512ER 28-bit-precision reciprocal/rsqrt (Xeon Phi Knights
            // Landing extended-range) and their 23-bit MVEX (KNC) precursors —
            // same shape as the 14-bit-precision forms above.
            M::Vrcp28ps | M::Vrcp28pd | M::Vrcp28ss | M::Vrcp28sd | M::Vrcp23ps => {
                self.lift_simd_write(iced, ctx, "rcp28");
            }
            M::Vrsqrt28ps | M::Vrsqrt28pd | M::Vrsqrt28ss | M::Vrsqrt28sd | M::Vrsqrt23ps => {
                self.lift_simd_write(iced, ctx, "rsqrt28");
            }
            // AVX-512 14-bit-precision reciprocal/rsqrt approximations
            // (packed and scalar) — same shape as the legacy/AVX RCP/RSQRT
            // above, just a different precision-tier intrinsic name.
            M::Vrcp14ps | M::Vrcp14pd | M::Vrcp14ss | M::Vrcp14sd => {
                self.lift_simd_write(iced, ctx, "rcp14");
            }
            M::Vrsqrt14ps | M::Vrsqrt14pd | M::Vrsqrt14ss | M::Vrsqrt14sd => {
                self.lift_simd_write(iced, ctx, "rsqrt14");
            }
            // FP16 imm8-rounding-mode round (packed/scalar) — same shape
            // as the already-wired f32/f64 VROUND* forms.
            M::Vrndscaleph | M::Vrndscalesh => self.lift_simd_write(iced, ctx, "rndscale"),
            // SSE3 duplicate-move (low/odd-lane broadcast within a vector).
            M::Movddup | M::Movshdup | M::Movsldup => {
                self.lift_simd_write(iced, ctx, "movdup");
            }
            M::Vmovddup | M::Vmovshdup | M::Vmovsldup => {
                self.lift_simd_write(iced, ctx, "movdup");
            }
            // Byte-swapping move (common in real code, GPR<->GPR/mem).
            M::Movbe => self.lift_simd_write(iced, ctx, "movbe"),
            // SSE4.1 sum-of-absolute-differences with imm8-selected offsets.
            M::Mpsadbw => self.lift_simd_write(iced, ctx, "mpsadbw"),
            M::Vmpsadbw => self.lift_simd_write(iced, ctx, "mpsadbw"),
            M::Movhlps | M::Movlhps | M::Movhps | M::Movlps => {
                self.lift_simd_write(iced, ctx, "movhl");
            }
            // AVX counterparts of the above — same real-writeback shape.
            M::Vmovhlps | M::Vmovlhps | M::Vmovhps | M::Vmovlps | M::Vmovhpd | M::Vmovlpd => {
                self.lift_simd_write(iced, ctx, "movhl");
            }
            // MOVNTDQ/MOVNTPS/MOVNTPD/MOVNTI are non-temporal *stores*
            // (`dst_mem = src_reg`); LDDQU is an unaligned *load*
            // (`dst_reg = src_mem`). Both are plain data moves — reuse
            // `lift_vector_move`, which already performs the real
            // `write_operand` call (with width adjustment for MOVNTI's
            // GPR<->vector-sized cases) that `lift_fpu_generic` was
            // dropping.
            M::Movntdq | M::Movntps | M::Movntpd | M::Movnti => {
                self.lift_vector_move(iced, ctx, iced.mnemonic());
            }
            // AVX non-temporal store counterparts — same real-writeback
            // shape as the legacy forms above.
            M::Vmovntdq | M::Vmovntps | M::Vmovntpd => {
                self.lift_vector_move(iced, ctx, iced.mnemonic());
            }
            M::Lddqu | M::Vlddqu => self.lift_vector_move(iced, ctx, iced.mnemonic()),
            M::Ptest | M::Vptest => self.lift_ptest(iced, ctx),
            // VPTESTMB/W/D/Q and VPTESTNM*: packed AND-then-test-into-mask
            // (real k-register destination at operand 0, unlike PTEST/
            // VPTEST above which are flag-only) — real writeback via
            // `lift_simd_write`, not the flag-only `lift_ptest` path.
            M::Vptestmb | M::Vptestmw | M::Vptestmd | M::Vptestmq => {
                self.lift_simd_write(iced, ctx, "vptestm");
            }
            M::Vptestnmb | M::Vptestnmw | M::Vptestnmd | M::Vptestnmq => {
                self.lift_simd_write(iced, ctx, "vptestnm");
            }
            // VPMOVM2B/W/D/Q: sign-extend each k-register mask bit into a
            // full-width vector lane (real vector-register destination).
            M::Vpmovm2b | M::Vpmovm2w | M::Vpmovm2d | M::Vpmovm2q => {
                self.lift_simd_write(iced, ctx, "vpmovm2");
            }
            // VPMOVB2M/W2M/D2M/Q2M: extract each lane's sign bit into a
            // k-register mask (real mask-register destination) — the
            // inverse direction of VPMOVM2* above.
            M::Vpmovb2m | M::Vpmovw2m | M::Vpmovd2m | M::Vpmovq2m => {
                self.lift_simd_write(iced, ctx, "vpmov2m");
            }
            // VTESTPS/VTESTPD: same AND/ANDN-into-ZF/CF flag semantics as
            // PTEST/VPTEST, just testing the sign bits of packed
            // float lanes instead of the whole integer register.
            M::Vtestps | M::Vtestpd => self.lift_ptest(iced, ctx),
            M::Emms => self.lift_intrinsic_no_result(iced, ctx, "emms"),
            // Movhpd/Movlpd: move high/low packed double — same shape as
            // the already-covered single-precision Movhps/Movlps siblings.
            M::Movhpd | M::Movlpd => self.lift_simd_write(iced, ctx, "movhl"),
            // Movntq (MMX->mem non-temporal store) / Movntdqa (mem->XMM
            // non-temporal *aligned* load): same real-move shape as the
            // already-covered Movntdq/Lddqu.
            M::Movntq => self.lift_vector_move(iced, ctx, iced.mnemonic()),
            M::Movntdqa | M::Vmovntdqa => self.lift_vector_move(iced, ctx, iced.mnemonic()),
            // Maskmovdqu/Maskmovq: conditional per-byte store to [rdi] gated
            // by a mask register — no single destination operand this IR's
            // `write_operand` can target (it's a masked partial memory
            // write, not one value), so — like MPX above — this stays an
            // effect-only Intrinsic with real operand reads for visibility.
            M::Maskmovdqu | M::Maskmovq => self.lift_fpu_generic(iced, ctx, "maskmov"),
            // VMASKMOVPD/PS: AVX conditional per-lane load-or-store gated by
            // a mask register — like MASKMOVDQU above, this is a masked
            // partial read/write with no single operand this IR's
            // `write_operand` can safely target for both the load and store
            // encodings, so it stays an effect-only Intrinsic with real
            // operand reads for visibility.
            M::Vmaskmovpd | M::Vmaskmovps => self.lift_intrinsic_writing_reported_regs(iced, ctx, "maskmov"),
            // VPMASKMOVD/Q: AVX2 integer sibling of VMASKMOVPD/PS above —
            // same masked-partial-read/write shape, same treatment.
            M::Vpmaskmovd | M::Vpmaskmovq => self.lift_intrinsic_writing_reported_regs(iced, ctx, "maskmov"),
            // Legacy multi-register push/pop (invalid in 64-bit mode, real
            // in 16/32-bit) — pushes/pops 8 GPRs in one instruction; fully
            // modelling that is a bigger job than one dispatch arm, so this
            // stays an effect-only Intrinsic (matches the existing
            // approximation precedent for other exotic multi-register ops).
            M::Pusha | M::Pushad => self.lift_fpu_generic(iced, ctx, "pusha"),
            // `POPA`/`POPAD` pop SEVEN general registers off the stack (ESP's
            // slot is discarded, not loaded). Routed to the effect-only helper,
            // the IL wrote none of them and a decompiler believed all seven
            // kept their old values. Modelled with the IL's own `Pop` node, the
            // same way `lift_leave` writes `bp`.
            //
            // Pop order per the SDM: EDI, ESI, EBP, (ESP discarded), EBX, EDX,
            // ECX, EAX.
            M::Popa | M::Popad => {
                let wide = iced.mnemonic() == Mnemonic::Popad;
                let size = if wide { Size::DWord } else { Size::Word };
                let regs: [&str; 7] = if wide {
                    ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]
                } else {
                    ["di", "si", "bp", "bx", "dx", "cx", "ax"]
                };
                // The discarded ESP slot: account for it so the stack pointer
                // ends where the hardware leaves it.
                for (i, r) in regs.iter().enumerate() {
                    if i == 3 {
                        let sp = self.sp_name().to_string();
                        let asize = self.ptr_size();
                        ctx.emit(LlilInstruction::SetReg {
                            dest: LlilRegister::Concrete(sp.clone()),
                            size: asize,
                            value: LlilExpr::AddT(
                                Box::new(LlilExpr::RegisterRef {
                                    reg: LlilRegister::Concrete(sp),
                                    size: asize,
                                }),
                                Box::new(LlilExpr::Const {
                                    value: size.bytes() as u64,
                                    size: asize,
                                }),
                                asize,
                            ),
                        });
                    }
                    ctx.emit(LlilInstruction::Pop {
                        dest: LlilRegister::Concrete((*r).to_string()),
                        size,
                    });
                }
            }
            // Bound: array-bounds check against two in-memory limits, traps
            // if out of range — no register result, effect-only.
            M::Bound => self.lift_fpu_generic(iced, ctx, "bound"),
            // Arpl: adjusts the RPL field of a 16-bit selector operand and
            // sets ZF — real single-destination writeback via operand 0
            // (a GPR/mem selector, not a vector register, but
            // `write_operand` dispatches generically on `OpKind`).
            M::Arpl => self.lift_simd_write(iced, ctx, "arpl"),
            // Descriptor-table-register loads (privileged, effect-only —
            // load a memory-resident descriptor into GDTR/IDTR, no GPR
            // result) vs. Ltr/Lmsw (load a *register* operand, still no
            // useful value result to model) — all effect-only Intrinsics,
            // same pattern as the VMX/SVM/MPX groups above.
            M::Lgdt => self.lift_fpu_generic(iced, ctx, "lgdt"),
            M::Lidt => self.lift_fpu_generic(iced, ctx, "lidt"),
            M::Lldt => self.lift_fpu_generic(iced, ctx, "lldt"),
            M::Ltr => self.lift_fpu_generic(iced, ctx, "ltr"),
            M::Lmsw => self.lift_fpu_generic(iced, ctx, "lmsw"),
            // Lar/Lsl: read an access-rights byte / segment-limit from a
            // descriptor and write it to a GPR destination, plus set ZF —
            // real single-destination writeback via operand 0.
            M::Lar => self.lift_simd_write(iced, ctx, "lar"),
            M::Lsl => self.lift_simd_write(iced, ctx, "lsl"),
            // Store-side siblings of the Lgdt/Lidt/Lldt/Ltr/Lmsw group:
            // Sgdt/Sidt store a memory-resident descriptor (real write via
            // operand 0); Sldt/Str/Smsw store a *register or memory*
            // selector/machine-status value (also real writeback via
            // operand 0); Sti sets the interrupt flag — effect-only, no
            // register/memory result.
            M::Sgdt => self.lift_simd_write(iced, ctx, "sgdt"),
            M::Sidt => self.lift_simd_write(iced, ctx, "sidt"),
            M::Sldt => self.lift_simd_write(iced, ctx, "sldt"),
            M::Str => self.lift_simd_write(iced, ctx, "str"),
            M::Smsw => self.lift_simd_write(iced, ctx, "smsw"),
            M::Sti => self.lift_intrinsic_no_result(iced, ctx, "sti"),
            // Verr/Verw: verify whether a segment selector is
            // readable/writable and set ZF accordingly — flag-only, no
            // register/memory result.
            M::Verr => self.lift_intrinsic_no_result(iced, ctx, "verr"),
            M::Verw => self.lift_intrinsic_no_result(iced, ctx, "verw"),
            // Load-far-pointer: loads a GPR (operand 0, real writeback) plus
            // an implicit segment register this IR doesn't model — same
            // approximation precedent as other multi-result exotic ops.
            M::Lds => self.lift_simd_write(iced, ctx, "lds"),
            M::Les => self.lift_simd_write(iced, ctx, "les"),
            M::Lfs => self.lift_simd_write(iced, ctx, "lfs"),
            M::Lgs => self.lift_simd_write(iced, ctx, "lgs"),
            M::Lss => self.lift_simd_write(iced, ctx, "lss"),
            // Ldmxcsr: loads the MXCSR control/status register — effect-only
            // (no GPR/vector result this IR models MXCSR as).
            M::Ldmxcsr | M::Vldmxcsr => self.lift_fpu_generic(iced, ctx, "ldmxcsr"),
            // Stmxcsr: stores MXCSR to memory — real writeback (operand 0
            // is genuinely the destination, unlike Ldmxcsr's load shape).
            M::Stmxcsr | M::Vstmxcsr => self.lift_simd_write(iced, ctx, "stmxcsr"),
            // Swapgs: swaps GS base with the kernel GS base MSR —
            // effect-only (common in kernel/syscall-entry code, no GPR
            // result this IR models).
            M::Swapgs => self.lift_intrinsic_no_result(iced, ctx, "swapgs"),
            // Rdpid: reads the logical processor ID into a GPR — real
            // writeback via operand 0.
            M::Rdpid => self.lift_simd_write(iced, ctx, "rdpid"),
            // TSX (transactional memory): Xbegin/Xend/Xtest are
            // control-flow/flag-only; Xabort takes an immediate abort code
            // — all effect-only, no GPR/memory result this IR models.
            // `XBEGIN` writes EAX with the abort status when the transaction
            // aborts. Modelled as a write so the definition is visible; the
            // fallback branch target stays unmodelled (the IL has no
            // transactional-memory concept).
            M::Xbegin => {
                self.lift_fpu_generic(iced, ctx, "xbegin");
                ctx.emit(LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete("eax".to_string()),
                    size: Size::DWord,
                    value: LlilExpr::Intrinsic {
                        name: "xbegin_status".to_string(),
                        args: vec![],
                        result_size: Size::DWord,
                    },
                });
            }
            M::Xend => self.lift_intrinsic_no_result(iced, ctx, "xend"),
            M::Xabort => self.lift_fpu_generic(iced, ctx, "xabort"),
            M::Xtest => self.lift_intrinsic_no_result(iced, ctx, "xtest"),
            // Ring-0 fast syscall return — privileged control-flow,
            // effect-only.
            // SYSRET/SYSEXIT return to user mode: control does NOT continue.
            // The 32-bit forms already emit `Ret` (see `M::Sysret | M::Sysexit`
            // above); these 64-bit forms were routed to the effect-only helper
            // instead — THE SAME INSTRUCTION AT TWO WIDTHS, HANDLED IN TWO
            // PLACES, one right and one wrong. The intrinsic is kept for the
            // mode-switch effects the IR does not model; the `Ret` records the
            // control-flow fact that was missing.
            M::Sysexitq | M::Sysretq => {
                self.lift_fpu_generic(iced, ctx, "sysret");
                ctx.emit(LlilInstruction::Ret);
            }
            // Wbnoinvd: writeback-without-invalidate cache flush,
            // Serialize: forces prior instructions to complete before
            // continuing — both effect-only.
            M::Wbnoinvd => self.lift_intrinsic_no_result(iced, ctx, "wbnoinvd"),
            M::Serialize => self.lift_intrinsic_no_result(iced, ctx, "serialize"),
            // User-mode monitor/wait/pause hints — effect-only.
            M::Umonitor => self.lift_intrinsic_no_result(iced, ctx, "umonitor"),
            M::Umwait => self.lift_fpu_generic(iced, ctx, "umwait"),
            M::Tpause => self.lift_fpu_generic(iced, ctx, "tpause"),
            // VIA PadLock crypto extensions — effect-only (bulk
            // memory-to-memory crypto via implicit ESI/EDI/ECX, no single
            // destination this IR can target, matches the AES-NI/SHA
            // precedent of not hand-computing the crypto math).
            M::Xcryptcbc
            | M::Xcryptcfb
            | M::Xcryptctr
            | M::Xcryptecb
            | M::Xcryptofb => self.lift_intrinsic_writing_reported_regs(iced, ctx, "xcrypt"),
            M::Xsha1 => self.lift_intrinsic_writing_reported_regs(iced, ctx, "xsha1"),
            M::Xsha256 => self.lift_intrinsic_writing_reported_regs(iced, ctx, "xsha256"),
            M::Xsha512 | M::Xsha512_alt => {
                self.lift_intrinsic_writing_reported_regs(iced, ctx, "xsha512");
            }
            M::Xstore | M::Xstore_alt => {
                self.lift_intrinsic_writing_reported_regs(iced, ctx, "xstore");
            }
            // Extended-state save/restore family (XSAVE variants) — all
            // effect-only (bulk multi-register memory transfer, no single
            // destination this IR can target).
            M::Xsaves | M::Xsaves64 | M::Xsavec | M::Xsavec64 | M::Xsaveopt
            | M::Xsaveopt64 => self.lift_fpu_generic(iced, ctx, "xsave"),
            M::Xrstors | M::Xrstors64 => self.lift_fpu_generic(iced, ctx, "xrstors"),
            // Port I/O: effect-only (In writes AL/AX/EAX which iced does
            // decode as operand 0 — but the "value" isn't computable at
            // lift time since it depends on live hardware I/O state, so
            // this stays a documented approximation rather than a fabricated
            // writeback).
            // `IN` reads a port INTO the accumulator — operand 0 is the
            // destination, and it was never written.
            M::In => self.lift_intrinsic_to_op0(iced, ctx, "in"),
            M::Out => self.lift_fpu_generic(iced, ctx, "out"),
            // TLB/PCID invalidation — privileged, effect-only.
            M::Invlpg => self.lift_fpu_generic(iced, ctx, "invlpg"),
            M::Invpcid => self.lift_fpu_generic(iced, ctx, "invpcid"),
            // Interrupt return — privileged control-flow, effect-only (no
            // register/memory result; the crate's IR doesn't model the
            // implied stack-frame pop + mode switch precisely).
            // The intrinsic records the DATA effects we do not model; the
            // `Return` records the CONTROL-FLOW fact, which is separate and was
            // being lost. IRET does not fall through — it returns to the
            // interrupted context — so without a terminator a CFG built from
            // this IL runs straight into whatever bytes follow the handler.
            // Found by pointing `LlilVerifier` at real lifter output: `0xCF`
            // produced a block with 0 terminators.
            M::Iret | M::Iretd | M::Iretq => {
                self.lift_fpu_generic(iced, ctx, "iret");
                ctx.emit(LlilInstruction::Return { value: None });
            }
            // MONITOR/MWAIT: set up / wait on an address-monitor for the
            // CPU's power-management hardware — effect-only.
            M::Monitor | M::Monitorx => self.lift_fpu_generic(iced, ctx, "monitor"),
            M::Mwait | M::Mwaitx => self.lift_fpu_generic(iced, ctx, "mwait"),
            // Rd/Wr{fs,gs}base: read/write FSBASE/GSBASE into/from a GPR —
            // Rd* writes a real destination; Wr* is effect-only (writes an
            // internal segment-base MSR-like value this IR doesn't model
            // as a register).
            M::Rdfsbase | M::Rdgsbase => self.lift_simd_write(iced, ctx, "rdxbase"),
            M::Wrfsbase | M::Wrgsbase => self.lift_fpu_generic(iced, ctx, "wrxbase"),
            // Ptwrite: writes a value into the Processor Trace packet
            // stream — a tracing side effect, not a register/memory result.
            M::Ptwrite => self.lift_fpu_generic(iced, ctx, "ptwrite"),
            // SSE4.2 string/text compare: like Fld, the decoded operands
            // are both SOURCES (the two xmm/mem operands + imm8 control
            // byte) — the actual result is an IMPLICIT register never
            // decoded as an operand: ECX for the index forms (Pcmpestri/
            // Pcmpistri), XMM0 for the mask forms (Pcmpestrm/Pcmpistrm).
            // `write_operand(iced, 0, ...)` would incorrectly target the
            // first *source* operand, so — same fix as `lift_fpu_write_st0`
            // — target the implicit destination register directly.
            // Approximation note (matches AES-NI/SHA precedent elsewhere in
            // this file): models real operand reads + real writeback to the
            // correct register, but does not hand-compute the exact
            // aggregation-operation/polarity bit semantics from imm8.
            // The `*64` forms are the REX.W encodings of the same instructions
            // (64-bit RAX/RDX length operands); the lifted semantics and the
            // implicit result register are identical, so they share these arms.
            M::Pcmpestri | M::Pcmpistri | M::Pcmpestri64 => {
                self.lift_string_compare_write(iced, ctx, "pcmpstri", Register::ECX, Size::DWord);
            }
            M::Pcmpestrm | M::Pcmpistrm | M::Pcmpestrm64 => {
                self.lift_string_compare_write(iced, ctx, "pcmpstrm", Register::XMM0, Size::OWord);
            }

            // ── AVX broadcast / permute / blend / zero-upper ─────────────────
            M::Vbroadcastss | M::Vbroadcastsd | M::Vbroadcastf128 => {
                self.lift_simd_write(iced, ctx, "vbroadcast");
            }
            // AVX2/AVX-512 integer broadcast (scalar GPR-or-memory-or-lane
            // source replicated across every packed lane) — extremely
            // common in vectorized code (e.g. broadcasting a loop-invariant
            // constant/scalar before a packed op), was entirely
            // undispatched despite the float `Vbroadcastss`/`sd` siblings
            // above being wired. Same named-intrinsic real-writeback shape.
            M::Vpbroadcastb | M::Vpbroadcastw | M::Vpbroadcastd | M::Vpbroadcastq => {
                self.lift_simd_write(iced, ctx, "vbroadcast");
            }
            // AVX-512CD: broadcast a mask register's bits into full lanes
            // (byte-per-mask-bit / dword-per-mask-bit). Same shape.
            M::Vpbroadcastmb2q | M::Vpbroadcastmw2d => {
                self.lift_simd_write(iced, ctx, "vbroadcast");
            }
            M::Vinsertf128 | M::Vinserti128 => self.lift_simd_write(iced, ctx, "vinsert"),
            M::Vextractf128 | M::Vextracti128 => self.lift_simd_write(iced, ctx, "vextract"),
            // AVX-512 wider insert/extract width variants (32/64-bit-lane
            // and 128/256/512-bit-vector granularities) — same "vinsert"/
            // "vextract" named-intrinsic shape as the AVX-128 forms above,
            // just operating on a different lane/vector width.
            M::Vinsertf32x4
            | M::Vinsertf32x8
            | M::Vinsertf64x2
            | M::Vinsertf64x4
            | M::Vinserti32x4
            | M::Vinserti32x8
            | M::Vinserti64x2
            | M::Vinserti64x4 => self.lift_simd_write(iced, ctx, "vinsert"),
            M::Vdppd | M::Vdpps => self.lift_simd_write(iced, ctx, "dp"),
            M::Vperm2f128 | M::Vpermq | M::Vpermd | M::Vpermps | M::Vpermpd => {
                self.lift_simd_write(iced, ctx, "vperm");
            }
            // AVX2 integer sibling of Vperm2f128 above (same 2x128-bit-lane
            // permute shape, integer element type).
            M::Vperm2i128 => self.lift_simd_write(iced, ctx, "vperm"),
            // AVX-512BW word-lane full permute — sibling of the
            // dword/float Vpermd/Vpermps above, word granularity.
            // Vpermb is the AVX-512VBMI byte-granularity member of the same
            // family; real compilers emit it for byte shuffles/table lookups.
            M::Vpermw | M::Vpermb => self.lift_simd_write(iced, ctx, "vperm"),

            // ── AMD XOP vector family (Bulldozer/Piledriver, dropped in Zen) ──
            //
            // All of these are pure vector data-processing ops: they write a
            // vector destination and leave rFLAGS UNTOUCHED, like every other
            // SIMD data-processing instruction (the only x86 SIMD ops that
            // touch flags are the explicit compare-to-flags forms — COMISD/
            // UCOMISD/PTEST/VTESTP* — and none of these are that). Notably
            // VPCOM* is AMD's *mask*-producing compare: a true lane sets all
            // corresponding destination bits to 1 and a false lane to 0, rather
            // than setting flags. So `lift_simd_write` (dest write, no flag
            // emission) is the right shape for the whole family.
            //
            // Modelled at intrinsic granularity — the destination write and
            // operand reads are real, but the per-lane arithmetic is not
            // hand-expanded, matching how the rest of the SIMD surface here is
            // handled (e.g. `vperm` above).

            // Fraction extract (packed/scalar, single/double).
            M::Vfrczpd | M::Vfrczps | M::Vfrczsd | M::Vfrczss => {
                self.lift_simd_write(iced, ctx, "vfrcz");
            }
            // Bitwise conditional move — a bit-granular blend: dst = (a & sel)
            // | (b & ~sel).
            M::Vpcmov => self.lift_simd_write(iced, ctx, "vpcmov"),
            // Packed byte permute from two sources with per-byte selector
            // (supports zeroing / bit-reversal effects).
            M::Vpperm => self.lift_simd_write(iced, ctx, "vpperm"),
            // Two-source permute with selector (float/double lanes).
            M::Vpermil2pd | M::Vpermil2ps => self.lift_simd_write(iced, ctx, "vpermil2"),
            // Packed compare producing an all-ones/all-zeros lane MASK in the
            // destination (signed and unsigned, b/w/d/q lanes) — NOT flags.
            M::Vpcomb | M::Vpcomw | M::Vpcomd | M::Vpcomq => {
                self.lift_simd_write(iced, ctx, "vpcom");
            }
            M::Vpcomub | M::Vpcomuw | M::Vpcomud | M::Vpcomuq => {
                self.lift_simd_write(iced, ctx, "vpcomu");
            }
            // Packed rotate — per-lane variable rotate amount from a vector.
            M::Vprotb | M::Vprotw | M::Vprotd | M::Vprotq => {
                self.lift_simd_write(iced, ctx, "vprot");
            }
            // Packed arithmetic / logical shift — unlike SSE2, each lane may
            // shift by a different amount taken from a vector register, and a
            // negative count shifts right.
            M::Vpshab | M::Vpshaw | M::Vpshad | M::Vpshaq => {
                self.lift_simd_write(iced, ctx, "vpsha");
            }
            M::Vpshlb | M::Vpshlw | M::Vpshld | M::Vpshlq => {
                self.lift_simd_write(iced, ctx, "vpshl");
            }
            // Horizontal add — signed source, widening to larger lanes.
            M::Vphaddbw | M::Vphaddbd | M::Vphaddbq | M::Vphaddwd | M::Vphaddwq
            | M::Vphadddq => self.lift_simd_write(iced, ctx, "vphadd"),
            // Horizontal add — unsigned source, widening.
            M::Vphaddubw | M::Vphaddubd | M::Vphaddubq | M::Vphadduwd | M::Vphadduwq
            | M::Vphaddudq => self.lift_simd_write(iced, ctx, "vphaddu"),
            // Horizontal subtract, widening.
            M::Vphsubbw | M::Vphsubwd | M::Vphsubdq => {
                self.lift_simd_write(iced, ctx, "vphsub");
            }
            // Multiply-accumulate (`ss` = signed-saturating; `h`/`l` select the
            // high/low half of the qword result).
            M::Vpmacsdd | M::Vpmacsdqh | M::Vpmacsdql | M::Vpmacswd | M::Vpmacsww => {
                self.lift_simd_write(iced, ctx, "vpmacs");
            }
            M::Vpmacssdd | M::Vpmacssdqh | M::Vpmacssdql | M::Vpmacsswd | M::Vpmacssww => {
                self.lift_simd_write(iced, ctx, "vpmacss");
            }
            // Multiply-add-accumulate.
            M::Vpmadcswd => self.lift_simd_write(iced, ctx, "vpmadcswd"),
            M::Vpmadcsswd => self.lift_simd_write(iced, ctx, "vpmadcsswd"),
            M::Vpermilps | M::Vpermilpd => self.lift_simd_write(iced, ctx, "vpermil"),
            M::Vpblendvb | M::Vblendvps | M::Vblendvpd => {
                self.lift_simd_write(iced, ctx, "vblendv");
            }
            // AVX-512 mask-register-controlled blend (real k-register
            // predicate operand, distinct instruction shape from the
            // imm8/xmm0-selected VBLENDV* above but same real-writeback
            // destination-at-operand-0 pattern).
            M::Vpblendmb | M::Vpblendmw | M::Vpblendmd | M::Vpblendmq => {
                self.lift_simd_write(iced, ctx, "vpblendm");
            }
            // AVX-512 signed AND unsigned packed compare-with-predicate
            // into a k-register mask — real mask-register destination,
            // extremely common building block for masked/predicated
            // AVX-512 code. Both signed and unsigned forms were missing.
            M::Vpcmpb | M::Vpcmpw | M::Vpcmpd | M::Vpcmpq | M::Vpcmpub | M::Vpcmpuw
            | M::Vpcmpud | M::Vpcmpuq => {
                self.lift_simd_write(iced, ctx, "vpcmp");
            }
            // VZEROUPPER/VZEROALL zero the upper lanes (or the whole of)
            // every vector register — 16 of them at 64-bit. Compilers emit
            // VZEROUPPER around calls in essentially every AVX-using binary, so
            // an unmodelled clobber here is not an exotic corner: a decompiler
            // believed all sixteen registers survived it.
            M::Vzeroupper | M::Vzeroall => self.lift_intrinsic_writing_reported_regs(iced, ctx, "vzero"),
            M::Vpalignr => self.lift_simd_write(iced, ctx, "vpalignr"),
            M::Vpshufd => self.lift_simd_write(iced, ctx, "vpshufd"),
            M::Vpcmpeqb | M::Vpcmpeqw | M::Vpcmpeqd | M::Vpcmpeqq => {
                self.lift_simd_write(iced, ctx, "vpcmpeq");
            }
            M::Vpcmpgtb | M::Vpcmpgtw | M::Vpcmpgtd | M::Vpcmpgtq => {
                self.lift_simd_write(iced, ctx, "vpcmpgt");
            }
            M::Vpminub | M::Vpmaxub | M::Vpminsw | M::Vpmaxsw => {
                self.lift_simd_write(iced, ctx, "vpminmax");
            }
            M::Vpmovmskb | M::Vmovmskps | M::Vmovmskpd => {
                self.lift_simd_write(iced, ctx, "vmovmsk");
            }
            M::Vmovd | M::Vmovq => self.lift_vex_move(iced, ctx),
            M::Vsqrtps | M::Vsqrtpd => self.lift_simd_write(iced, ctx, "vsqrt"),
            M::Vsqrtss | M::Vsqrtsd => self.lift_simd_write(iced, ctx, "vsqrt"),
            M::Vroundpd | M::Vroundps | M::Vroundsd | M::Vroundss => {
                self.lift_simd_write(iced, ctx, "round");
            }
            // AVX-512 imm8-controlled round-to-scale (RNDSCALE) and
            // reduce (REDUCE, "round then subtract") — same
            // named-intrinsic writeback shape as ROUND above.
            M::Vrndscaleps | M::Vrndscalepd | M::Vrndscalesd | M::Vrndscaless => {
                self.lift_simd_write(iced, ctx, "rndscale");
            }
            M::Vreduceps | M::Vreducepd | M::Vreducesd | M::Vreducess | M::Vreduceph
            | M::Vreducesh => {
                self.lift_simd_write(iced, ctx, "reduce");
            }
            M::Vcmpps | M::Vcmppd => self.lift_simd_write(iced, ctx, "vcmp"),
            M::Vcmpsd | M::Vcmpss => self.lift_simd_write(iced, ctx, "vcmp"),
            M::Vcomisd | M::Vcomiss => self.lift_comi(iced, ctx, "comi"),
            M::Vucomisd | M::Vucomiss => self.lift_comi(iced, ctx, "ucomi"),
            M::Vcmpph | M::Vcmpsh => self.lift_simd_write(iced, ctx, "vcmp"),
            M::Vcomish => self.lift_comi(iced, ctx, "comi"),
            // AVX-512 FP16 unordered scalar compare — the `ucomi` sibling of
            // Vcomish above, matching the Vucomisd/Vucomiss pair.
            M::Vucomish => self.lift_comi(iced, ctx, "ucomi"),
            M::Vsqrtph | M::Vsqrtsh => self.lift_simd_write(iced, ctx, "vsqrt"),
            M::Vgetexpph => self.lift_simd_write(iced, ctx, "vgetexp"),
            M::Vgetmantph => self.lift_simd_write(iced, ctx, "vgetmant"),
            M::Vscalefph => self.lift_simd_write(iced, ctx, "vscalef"),
            M::Vrcpph => self.lift_simd_write(iced, ctx, "rcp"),
            M::Vrsqrtph => self.lift_simd_write(iced, ctx, "rsqrt"),
            // FP16 conversions — same shape as the already-covered Vcvt*
            // group.
            M::Vcvtph2ps
            | M::Vcvtps2ph
            | M::Vcvtph2pd
            | M::Vcvtpd2ph
            | M::Vcvtsh2ss
            | M::Vcvtss2sh
            | M::Vcvtsh2sd
            | M::Vcvtsd2sh
            | M::Vcvtdq2ph
            | M::Vcvtph2dq
            | M::Vcvtudq2ph
            | M::Vcvtph2udq => self.lift_simd_write(iced, ctx, "vcvt"),
            M::Vblendpd | M::Vblendps => self.lift_simd_write(iced, ctx, "blend"),
            M::Vshufps | M::Vshufpd => self.lift_simd_write(iced, ctx, "vshuf"),
            // AVX-512 128-bit-lane (quadword-granularity) cross-lane
            // shuffle — same imm8-selected shape as Vshufps/pd above, just
            // operating on whole 128-bit lanes instead of scalar elements.
            M::Vshufi64x2 | M::Vshufi32x4 | M::Vshuff32x4 | M::Vshuff64x2 => {
                self.lift_simd_write(iced, ctx, "vshuf");
            }
            M::Vminps | M::Vminpd => self.lift_simd_write(iced, ctx, "min"),
            M::Vmaxps | M::Vmaxpd => self.lift_simd_write(iced, ctx, "max"),
            // Scalar AVX forms (VMINSS/VMINSD/VMAXSS/VMAXSD) — same
            // named-intrinsic writeback shape as the packed forms above,
            // just operating on the low scalar lane only.
            M::Vminss | M::Vminsd => self.lift_simd_write(iced, ctx, "min"),
            M::Vmaxss | M::Vmaxsd => self.lift_simd_write(iced, ctx, "max"),
            // FP16 (AVX-512 FP16) packed/scalar min/max — same gap shape,
            // the FP16 add/sub/mul/div siblings were wired but min/max
            // weren't.
            M::Vminph | M::Vminsh => self.lift_simd_write(iced, ctx, "min"),
            M::Vmaxph | M::Vmaxsh => self.lift_simd_write(iced, ctx, "max"),
            M::Vunpcklps | M::Vunpckhps | M::Vunpcklpd | M::Vunpckhpd => {
                self.lift_simd_write(iced, ctx, "vunpck");
            }
            M::Vcvtsi2sd
            | M::Vcvtsi2ss
            | M::Vcvttss2si
            | M::Vcvttsd2si
            | M::Vcvtss2si
            | M::Vcvtsd2si
            | M::Vcvtps2pd
            | M::Vcvtpd2ps
            | M::Vcvtdq2ps
            | M::Vcvtps2dq
            | M::Vcvttps2dq
            | M::Vcvtdq2pd
            | M::Vcvtpd2dq
            | M::Vcvttpd2dq
            | M::Vcvtss2sd
            | M::Vcvtsd2ss
            // AVX-512 unsigned/qword conversion siblings of the group above
            // — same operand shape (one src, one dst, no implicit register),
            // `lift_simd_write` applies unmodified.
            | M::Vcvtpd2udq
            | M::Vcvtpd2uqq
            | M::Vcvtps2udq
            | M::Vcvtps2uqq
            | M::Vcvtsd2usi
            | M::Vcvtss2usi
            | M::Vcvttpd2udq
            | M::Vcvttpd2uqq
            | M::Vcvttps2udq
            | M::Vcvttps2uqq
            | M::Vcvttsd2usi
            | M::Vcvttss2usi
            | M::Vcvtusi2sd
            | M::Vcvtusi2ss
            | M::Vcvtudq2pd
            | M::Vcvtudq2ps
            | M::Vcvtuqq2pd
            | M::Vcvtuqq2ps
            | M::Vcvtqq2pd
            | M::Vcvtqq2ps
            | M::Vcvtpd2qq
            | M::Vcvttpd2qq
            | M::Vcvtps2qq
            | M::Vcvttps2qq => self.lift_simd_write(iced, ctx, "vcvt"),
            // FP16 unsigned/word/GPR conversion siblings, same "vcvt" shape.
            M::Vcvtph2uqq
            | M::Vcvtph2uw
            | M::Vcvtph2w
            | M::Vcvtph2qq
            | M::Vcvtph2psx
            | M::Vcvtps2phx
            | M::Vcvttph2dq
            | M::Vcvttph2qq
            | M::Vcvttph2udq
            | M::Vcvttph2uqq
            | M::Vcvttph2uw
            | M::Vcvttph2w
            | M::Vcvtuw2ph
            | M::Vcvtw2ph
            | M::Vcvtsh2si
            | M::Vcvtsh2usi
            | M::Vcvttsh2si
            | M::Vcvttsh2usi
            | M::Vcvtsi2sh
            | M::Vcvtusi2sh
            | M::Vcvtqq2ph
            | M::Vcvtuqq2ph => self.lift_simd_write(iced, ctx, "vcvt"),

            // AVX-512 broadcast width siblings of Vbroadcastss/sd/f128 —
            // same shape, `lift_simd_write` applies unmodified.
            M::Vbroadcastf32x2
            | M::Vbroadcastf32x4
            | M::Vbroadcastf32x8
            | M::Vbroadcastf64x2
            | M::Vbroadcastf64x4
            | M::Vbroadcasti128
            | M::Vbroadcasti32x2
            | M::Vbroadcasti32x4
            | M::Vbroadcasti32x8
            | M::Vbroadcasti64x2
            | M::Vbroadcasti64x4 => self.lift_simd_write(iced, ctx, "vbroadcast"),
            // AVX-512 extract width siblings of Vextractf128/Vextracti128.
            M::Vextractf32x4
            | M::Vextractf32x8
            | M::Vextractf64x2
            | M::Vextractf64x4
            | M::Vextracti32x4
            | M::Vextracti32x8
            | M::Vextracti64x2
            | M::Vextracti64x4
            | M::Vextractps => self.lift_simd_write(iced, ctx, "vextract"),
            M::Valignd | M::Valignq => self.lift_simd_write(iced, ctx, "valign"),
            M::Vdbpsadbw => self.lift_simd_write(iced, ctx, "vdbpsadbw"),
            M::Vfpclasspd
            | M::Vfpclassps
            | M::Vfpclasssd
            | M::Vfpclassss
            | M::Vfpclassph
            | M::Vfpclasssh => self.lift_simd_write(iced, ctx, "vfpclass"),
            M::Vblendmpd | M::Vblendmps => self.lift_simd_write(iced, ctx, "vblendm"),
            M::Vgetexpsd | M::Vgetexpss | M::Vgetexpsh => {
                self.lift_simd_write(iced, ctx, "vgetexp");
            }
            M::Vfixupimmsd | M::Vfixupimmss => self.lift_simd_write(iced, ctx, "vfixupimm"),

            // ── AVX-512 (EVEX): mask registers, ternary logic, compress/expand,
            //    range/fixup/scale/mantissa, gather/scatter ──────────────────
            //
            // K-mask instructions (`Kmov*`/`Kand*`/`Kor*`/`Kxor*`/`Knot*`)
            // read/write the k0-k7 mask registers via the *same* generic
            // `iced_x86::Register`-keyed path as every other register
            // operand: `reg_name`/`reg_size` format/size any `Register`
            // variant generically (`reg_size` uses `Register::size()`, and
            // `reg_name` lowercases `{reg:?}`, giving e.g. "k1"), and
            // `read_operand`/`write_operand` dispatch purely on
            // `OpKind::Register` without special-casing vector vs.
            // general-purpose vs. mask registers. So `lift_simd_write`
            // (real `write_operand` writeback) applies unmodified — no new
            // mask-register IR support is needed.
            // `Kmov`/`Kxor` are the KNC bare (unsuffixed) mask-register forms —
            // same shape as the AVX-512 width-suffixed members beside them.
            M::Kmovb | M::Kmovw | M::Kmovd | M::Kmovq | M::Kmov => {
                self.lift_simd_write(iced, ctx, "kmov")
            }
            M::Kandw | M::Kandb | M::Kandd | M::Kandq => self.lift_simd_write(iced, ctx, "kand"),
            // Bare `Kand`/`Kor` (no width suffix): Knights-Corner-era 16-bit-
            // only precursor encoding (`VEX_KNC_Kand_kr_kr`/`VEX_KNC_Kor_kr_kr`),
            // a distinct `Mnemonic` from the AVX-512 `Kandw`/`Korw` above —
            // same real-writeback shape, just the older single-width form.
            M::Kand => self.lift_simd_write(iced, ctx, "kand"),
            M::Kor => self.lift_simd_write(iced, ctx, "kor"),
            M::Korw | M::Korb | M::Kord | M::Korq => self.lift_simd_write(iced, ctx, "kor"),
            M::Kxorw | M::Kxorb | M::Kxord | M::Kxorq | M::Kxor => {
                self.lift_simd_write(iced, ctx, "kxor")
            }
            M::Knotw | M::Knotb | M::Knotd | M::Knotq => self.lift_simd_write(iced, ctx, "knot"),
            M::Vpternlogd | M::Vpternlogq => self.lift_simd_write(iced, ctx, "vpternlog"),
            M::Vcompressps | M::Vcompresspd | M::Vpcompressd | M::Vpcompressq => {
                self.lift_simd_write(iced, ctx, "vcompress");
            }
            M::Vpcompressb | M::Vpcompressw => self.lift_simd_write(iced, ctx, "vcompress"),
            M::Vexpandps | M::Vexpandpd | M::Vpexpandd | M::Vpexpandq => {
                self.lift_simd_write(iced, ctx, "vexpand");
            }
            M::Vpexpandb | M::Vpexpandw => self.lift_simd_write(iced, ctx, "vexpand"),
            // AVX-512 rotate-left/right, both immediate-count and
            // variable-per-lane-count forms — real writeback, no rotate
            // primitive in this IR so it's a named intrinsic like the
            // funnel-shift family above.
            M::Vprolq | M::Vprold => self.lift_simd_write(iced, ctx, "vprol"),
            M::Vprolvq | M::Vprolvd => self.lift_simd_write(iced, ctx, "vprolv"),
            M::Vprorq | M::Vprord => self.lift_simd_write(iced, ctx, "vpror"),
            M::Vprorvq | M::Vprorvd => self.lift_simd_write(iced, ctx, "vprorv"),
            M::Vrangeps | M::Vrangepd => self.lift_simd_write(iced, ctx, "vrange"),
            M::Vrangess | M::Vrangesd => self.lift_simd_write(iced, ctx, "vrange"),
            M::Vfixupimmps | M::Vfixupimmpd => self.lift_simd_write(iced, ctx, "vfixupimm"),
            M::Vscalefps | M::Vscalefpd => self.lift_simd_write(iced, ctx, "vscalef"),
            M::Vscalefss | M::Vscalefsd => self.lift_simd_write(iced, ctx, "vscalef"),
            M::Vscalefsh => self.lift_simd_write(iced, ctx, "vscalef"),
            M::Vgetexpps | M::Vgetexppd => self.lift_simd_write(iced, ctx, "vgetexp"),
            M::Vgetmantps | M::Vgetmantpd => self.lift_simd_write(iced, ctx, "vgetmant"),
            M::Vgetmantss | M::Vgetmantsd | M::Vgetmantsh => {
                self.lift_simd_write(iced, ctx, "vgetmant");
            }
            M::Vplzcntd | M::Vplzcntq => self.lift_simd_write(iced, ctx, "vplzcnt"),
            // Gather (VSIB) is implemented via `lift_vex_gather` below: since
            // `LlilExpr::Load`/`LlilInstruction::Store` (rustre-il-llil,
            // src/lib.rs) take exactly one `addr: Box<LlilExpr>` and this
            // IR's vector registers are modelled as single wide
            // integers/floats (no per-lane vector primitive — see
            // `apply_evex_mask`'s doc comment), there is no dedicated
            // "extract lane N of a vector register" IR node.
            // `rustre_il_llil::SimdInstruction::VecExtractI32` exists in
            // rustre-il-llil but is a *disconnected* toy interpreter type
            // (dest/src are `String`s, executed by its own `SimdState`, not
            // constructible as an `LlilExpr`) — it is not wired into this
            // file's `LlilExpr`/`EmitCtx` emission pipeline at all, so it
            // cannot be used here.
            //
            // Instead, lane extraction is done with plain integer arithmetic
            // already in the IR grammar — `Shr` + `LowPart` peel out lane
            // `i`'s bits from the full-width `RegisterRef` of the index
            // register, `SignExtend` widens it to pointer size for the
            // address computation (reusing the same base+index*scale+disp
            // shape as `mem_address`), and the per-lane result is folded
            // back into the destination with `Shl`+`Or`, gated by a
            // `CondExpr` reading either the EVEX `k`-register bit (when
            // `op_mask()` is a real k-register) or the VEX full-vector mask
            // register's per-lane MSB (sign bit), matching Intel SDM
            // semantics for merging-masking. This needs no new LLIL enum
            // variant — see `lift_vex_gather` below.
            //
            // Gap (1) — "the VEX-form side effect of clearing a mask register
            // lane after a successful gather is not modelled" — is CLOSED: the
            // mask write the ISA defines is now emitted (see
            // `write_reported_regs_except_op0`). It was found only once the
            // sweeps generated SIB addressing, which VSIB *requires*, so no
            // earlier sweep could reach these encodings at all. Remaining gap:
            // (2)
            // EVEX zeroing-masking (`{z}`) for gather is not distinguished
            // from merging (unmasked lanes always keep the prior dest value,
            // as if merging). Scatter (opposite direction, same VSIB
            // addressing) is modelled per-lane with real `Store`s in
            // `lift_evex_scatter` below.
            M::Vgatherdps | M::Vpgatherdd => {
                self.lift_vex_gather(iced, ctx, Size::DWord, Size::DWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vgatherdpd | M::Vpgatherdq => {
                self.lift_vex_gather(iced, ctx, Size::QWord, Size::DWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vgatherqps | M::Vpgatherqd => {
                self.lift_vex_gather(iced, ctx, Size::DWord, Size::QWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vgatherqpd | M::Vpgatherqq => {
                self.lift_vex_gather(iced, ctx, Size::QWord, Size::QWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vscatterdps | M::Vpscatterdd => {
                self.lift_evex_scatter(iced, ctx, Size::DWord, Size::DWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vscatterdpd | M::Vpscatterdq => {
                self.lift_evex_scatter(iced, ctx, Size::QWord, Size::DWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vscatterqps | M::Vpscatterqd => {
                self.lift_evex_scatter(iced, ctx, Size::DWord, Size::QWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            M::Vscatterqpd | M::Vpscatterqq => {
                self.lift_evex_scatter(iced, ctx, Size::QWord, Size::QWord);
                self.write_reported_regs_except_op0(iced, ctx, "vsib_mask");
            }
            // Knights-Corner-era (Xeon Phi prototype ISA, never shipped on
            // mainstream Intel silicon) unpack-load/pack-store/non-rotating
            // move variants. Real decodable `Code::` variants exist in
            // iced, but these are effectively unencounterable in any
            // present-day binary — treated as effect-only intrinsics
            // (real operand reads for visibility, no attempt to model the
            // exotic high/low-half unpack-across-cacheline-boundary
            // semantics) rather than left `Unimplemented`, per the
            // "100% dispatched" mandate.
            M::Vloadunpackhd
            | M::Vloadunpackhpd
            | M::Vloadunpackhps
            | M::Vloadunpackhq
            | M::Vloadunpackld
            | M::Vloadunpacklpd
            | M::Vloadunpacklps
            | M::Vloadunpacklq
            | M::Vpackstorehd
            | M::Vpackstorehpd
            | M::Vpackstorehps
            | M::Vpackstorehq
            | M::Vpackstoreld
            | M::Vpackstorelpd
            | M::Vpackstorelps
            | M::Vpackstorelq
            | M::Vmovnrapd
            | M::Vmovnraps
            | M::Vmovnrngoapd
            | M::Vmovnrngoaps => {
                self.lift_fpu_generic(iced, ctx, &reg_name_lower_mnemonic(m));
            }
            // Status (re-verified this pass): design above still stands and
            // was NOT implemented this session. Per-lane unrolling needs a
            // new address-expr builder that takes an explicit per-lane index
            // value instead of reading straight from `read_operand`'s
            // memory-operand path, plus wiring mask-lane extraction into
            // that builder. That's a genuine new subsystem (not a
            // lift.rs-local helper), so it's deliberately deferred again
            // rather than rushed into a partially-correct implementation.

            // ── AVX-512 K-mask register ops (beyond Kmov/Kand/Kor/Kxor/Knot
            //    above): same generic Register-keyed read/write path, so
            //    `lift_simd_write` writeback and `lift_ptest`-style flag-only
            //    testing both apply unmodified. ─────────────────────────────
            M::Kaddb | M::Kaddw | M::Kaddd | M::Kaddq => self.lift_simd_write(iced, ctx, "kadd"),
            M::Kandnb | M::Kandnw | M::Kandnd | M::Kandnq => {
                self.lift_simd_write(iced, ctx, "kandn");
            }
            // Bare `Kandn`/`Kandnr` (KNC precursor, same shape as bare
            // Kand/Kor/Kxnor above; `Kandnr` swaps operand order but is
            // still a plain 2-source-1-dest AND-NOT).
            M::Kandn | M::Kandnr => self.lift_simd_write(iced, ctx, "kandn"),
            // Bare `Kxnor` (KNC precursor, same shape as bare Kand/Kor above).
            M::Kxnor => self.lift_simd_write(iced, ctx, "kxnor"),
            M::Kxnorb | M::Kxnorw | M::Kxnord | M::Kxnorq => {
                self.lift_simd_write(iced, ctx, "kxnor");
            }
            M::Kshiftlb | M::Kshiftlw | M::Kshiftld | M::Kshiftlq => {
                self.lift_simd_write(iced, ctx, "kshiftl");
            }
            M::Kshiftrb | M::Kshiftrw | M::Kshiftrd | M::Kshiftrq => {
                self.lift_simd_write(iced, ctx, "kshiftr");
            }
            M::Kunpckbw | M::Kunpckwd | M::Kunpckdq => {
                self.lift_simd_write(iced, ctx, "kunpck");
            }
            // KTEST: TMP = SRC1 AND SRC2 -> ZF; TMP2 = SRC1 AND NOT SRC2 ->
            // CF — bit-for-bit the same AND/ANDN flag-only pattern PTEST
            // uses, just on k-registers instead of xmm/ymm, so the existing
            // helper applies unmodified.
            M::Ktestb | M::Ktestw | M::Ktestd | M::Ktestq => self.lift_ptest(iced, ctx),
            // KORTEST: TMP = SRC1 OR SRC2; ZF = (TMP == 0); CF = (TMP ==
            // all-ones) — different flag formula from PTEST/KTEST (OR, not
            // AND/ANDN, and CF compares against all-ones not zero), so it
            // gets its own small helper.
            M::Kortestb | M::Kortestw | M::Kortestd | M::Kortestq => self.lift_kortest(iced, ctx),
            // Kconcat/Kmerge/Kextract: legacy AVX-512BW/pre-AVX512F
            // mask-register composition ops with no modelled single-register
            // destination in this IR (Kconcat writes a k-register PAIR,
            // Kmerge2l1h/l composes two masks into one 2x-wide result,
            // Kextract has architecture-specific implicit operands) —
            // effect-only, matches the Vgatherpf/Vscatterpf precedent below.
            M::Kconcath | M::Kconcatl | M::Kextract | M::Kmerge2l1h | M::Kmerge2l1l => {
                self.lift_intrinsic_no_result(iced, ctx, "kmask_compose");
            }

            // ── AVX-512/KNC gather/scatter software-prefetch hints — pure
            //    cache side effects, no register/memory value is written, so
            //    these are honestly effect-only (not a discard-result bug:
            //    there is genuinely nothing to write back). ────────────────
            M::Vgatherpf0dpd
            | M::Vgatherpf0dps
            | M::Vgatherpf0qpd
            | M::Vgatherpf0qps
            | M::Vgatherpf1dpd
            | M::Vgatherpf1dps
            | M::Vgatherpf1qpd
            | M::Vgatherpf1qps
            | M::Vgatherpf0hintdpd
            | M::Vgatherpf0hintdps => self.lift_intrinsic_no_result(iced, ctx, "vgatherpf"),
            M::Vscatterpf0dpd
            | M::Vscatterpf0dps
            | M::Vscatterpf0qpd
            | M::Vscatterpf0qps
            | M::Vscatterpf1dpd
            | M::Vscatterpf1dps
            | M::Vscatterpf1qpd
            | M::Vscatterpf1qps
            | M::Vscatterpf0hintdpd
            | M::Vscatterpf0hintdps => self.lift_intrinsic_no_result(iced, ctx, "vscatterpf"),

            // ── AVX-512 VPERMI2/VPERMT2 (3-operand table-permute family) ──────
            M::Vpermi2b
            | M::Vpermi2w
            | M::Vpermi2d
            | M::Vpermi2q
            | M::Vpermi2ps
            | M::Vpermi2pd => self.lift_simd_write(iced, ctx, "vpermi2"),
            M::Vpermt2b
            | M::Vpermt2w
            | M::Vpermt2d
            | M::Vpermt2q
            | M::Vpermt2ps
            | M::Vpermt2pd => self.lift_simd_write(iced, ctx, "vpermt2"),

            // ── GFNI / VAES (VEX/EVEX-encoded, distinct Mnemonic values from
            //    the legacy SSE AES-NI/GFNI forms already dispatched above) ──
            M::Gf2p8affineqb => self.lift_simd_write(iced, ctx, "gf2p8affineqb"),
            M::Gf2p8affineinvqb => self.lift_simd_write(iced, ctx, "gf2p8affineinvqb"),
            M::Gf2p8mulb => self.lift_simd_write(iced, ctx, "gf2p8mulb"),
            // AVX/AVX-512 (VEX/EVEX-encoded) counterparts of the GFNI ops
            // above — same real-writeback shape, missing V-sibling gap.
            M::Vgf2p8affineqb => self.lift_simd_write(iced, ctx, "gf2p8affineqb"),
            M::Vgf2p8affineinvqb => self.lift_simd_write(iced, ctx, "gf2p8affineinvqb"),
            M::Vgf2p8mulb => self.lift_simd_write(iced, ctx, "gf2p8mulb"),
            M::Vaesenc => self.lift_simd_write(iced, ctx, "aesenc"),
            M::Vaesenclast => self.lift_simd_write(iced, ctx, "aesenclast"),
            M::Vaesdec => self.lift_simd_write(iced, ctx, "aesdec"),
            M::Vaesdeclast => self.lift_simd_write(iced, ctx, "aesdeclast"),
            // SM3 (hash) / SM4 (block cipher) — Chinese national cryptography
            // standards, AVX-512-adjacent extensions. Real, though niche
            // (regulatory-market use); same named-intrinsic shape as the
            // AES/SHA families above.
            M::Vsm3msg1 => self.lift_simd_write(iced, ctx, "sm3msg1"),
            M::Vsm3msg2 => self.lift_simd_write(iced, ctx, "sm3msg2"),
            M::Vsm3rnds2 => self.lift_simd_write(iced, ctx, "sm3rnds2"),
            M::Vsm4key4 => self.lift_simd_write(iced, ctx, "sm4key4"),
            M::Vsm4rnds4 => self.lift_simd_write(iced, ctx, "sm4rnds4"),
            M::Vaesimc => self.lift_simd_write(iced, ctx, "aesimc"),
            M::Vaeskeygenassist => self.lift_simd_write(iced, ctx, "aeskeygenassist"),

            // ── Cryptography / CRC / ADX ──────────────────────────────────────
            M::Crc32 => self.lift_simd_write(iced, ctx, "crc32"),
            M::Aesenc => self.lift_simd_write(iced, ctx, "aesenc"),
            M::Aesenclast => self.lift_simd_write(iced, ctx, "aesenclast"),
            M::Aesdec => self.lift_simd_write(iced, ctx, "aesdec"),
            M::Aesdeclast => self.lift_simd_write(iced, ctx, "aesdeclast"),
            M::Aesimc => self.lift_simd_write(iced, ctx, "aesimc"),
            M::Aeskeygenassist => self.lift_simd_write(iced, ctx, "aeskeygenassist"),
            M::Sha1nexte => self.lift_simd_write(iced, ctx, "sha1nexte"),
            M::Sha1msg1 => self.lift_simd_write(iced, ctx, "sha1msg1"),
            M::Sha1msg2 => self.lift_simd_write(iced, ctx, "sha1msg2"),
            M::Sha1rnds4 => self.lift_simd_write(iced, ctx, "sha1rnds4"),
            M::Sha256rnds2 => self.lift_simd_write(iced, ctx, "sha256rnds2"),
            M::Vsha512rnds2 => self.lift_simd_write(iced, ctx, "vsha512rnds2"),
            M::Vsha512msg1 => self.lift_simd_write(iced, ctx, "vsha512msg1"),
            M::Vsha512msg2 => self.lift_simd_write(iced, ctx, "vsha512msg2"),
            M::Sha256msg1 => self.lift_simd_write(iced, ctx, "sha256msg1"),
            M::Sha256msg2 => self.lift_simd_write(iced, ctx, "sha256msg2"),
            M::Pclmulqdq | M::Vpclmulqdq => self.lift_simd_write(iced, ctx, "pclmulqdq"),
            M::Adcx => self.lift_bmi_intrinsic3(iced, ctx, "adcx"),
            M::Adox => self.lift_bmi_intrinsic3(iced, ctx, "adox"),

            // ── Port-string I/O ────────────────────────────────────────────
            // INS/OUTS are string ops: they ADVANCE their index register by the
            // element size, in the direction of DF, exactly like MOVS/STOS.
            // Routing them to the effect-only helper meant `rdi`/`rsi` were
            // never written, so a decompiler believed the pointer did not move
            // — the same defect shape as the REP/DF one, in the port-I/O
            // corner nobody looks at. The port access itself stays an
            // intrinsic: this IL does not model I/O space.
            M::Insb | M::Insw | M::Insd => {
                self.lift_fpu_generic(iced, ctx, "ins");
                let elem = Self::string_elem_size(iced);
                let di = self.di_name();
                self.advance_index(&di, elem, ctx);
            }
            M::Outsb | M::Outsw | M::Outsd => {
                self.lift_fpu_generic(iced, ctx, "outs");
                let elem = Self::string_elem_size(iced);
                let si = self.si_name();
                self.advance_index(&si, elem, ctx);
            }

            // ── AVX / AVX2 integer/logical (3-operand VEX) ───────────────────
            // `Vpxor`/`Vpand`/`Vpor`/`Vpandn` also cover their EVEX
            // `Vpxord`/`Vpxorq` etc. siblings below; masking (if any) is
            // applied uniformly by `lift_vex_binop`.
            M::Vpxor | M::Vpxord | M::Vpxorq => self.lift_vex_binop(iced, ctx, VexBinOp::Xor),
            M::Vpand | M::Vpandd | M::Vpandq => self.lift_vex_binop(iced, ctx, VexBinOp::And),
            M::Vpor | M::Vpord | M::Vporq => self.lift_vex_binop(iced, ctx, VexBinOp::Or),
            M::Vpandn | M::Vpandnd | M::Vpandnq => self.lift_vex_binop(iced, ctx, VexBinOp::Andn),
            M::Vpshufb => self.lift_vex_pshufb(iced, ctx),
            M::Vpaddb | M::Vpaddw | M::Vpaddd | M::Vpaddq => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Add);
            }
            M::Vpsubb | M::Vpsubw | M::Vpsubd | M::Vpsubq => {
                self.lift_vex_binop(iced, ctx, VexBinOp::Sub);
            }

            // AVX-512 VNNI dot-product-accumulate (dst += dot(src1, src2)
            // over packed byte/word lanes, widening into dst's dword
            // lanes) — high real-world value (ubiquitous in int8 ML
            // inference kernels). Same 3-operand read-modify-write shape
            // as the FMA3 block below but no FMA-specific accumulate enum
            // models integer dot-product, so this uses the generic
            // named-intrinsic `lift_simd_write` path instead.
            M::Vpdpbusd | M::Vpdpbusds | M::Vpdpwssd | M::Vpdpwssds => {
                self.lift_simd_write(iced, ctx, "vpdp");
            }
            // VNNI-INT8 extension: remaining signed/unsigned operand-polarity
            // combinations of the same byte-lane dot-product-accumulate shape
            // (Vpdpbusd/busds above cover unsigned*signed; these cover the
            // other three polarity pairs) plus the word-lane VNNI-INT16
            // siblings of Vpdpwssd/wssds above.
            M::Vpdpbssd
            | M::Vpdpbssds
            | M::Vpdpbsud
            | M::Vpdpbsuds
            | M::Vpdpbuud
            | M::Vpdpbuuds
            | M::Vpdpwsud
            | M::Vpdpwsuds
            | M::Vpdpwusd
            | M::Vpdpwusds
            | M::Vpdpwuud
            | M::Vpdpwuuds => {
                self.lift_simd_write(iced, ctx, "vpdp");
            }
            // AVX-512 BF16: VDPBF16PS (bf16 dot-product-accumulate into
            // fp32, same shape as VNNI above) and VCVTNEPS2BF16/
            // VCVTNE2PS2BF16 (narrowing fp32->bf16 convert, single- and
            // dual-source forms) — real single-destination writeback.
            M::Vdpbf16ps => self.lift_simd_write(iced, ctx, "vdpbf16ps"),
            M::Vcvtneps2bf16 | M::Vcvtne2ps2bf16 => {
                self.lift_simd_write(iced, ctx, "vcvtneps2bf16");
            }
            // VP2INTERSECTD/Q writes TWO k-mask destinations at once. That
            // was the stated reason for leaving it effect-only: "no single
            // operand-0 target this IR's `write_operand` can model". The
            // constraint was real but is no longer — the decoder-driven helper
            // writes however many registers the ISA defines, so both k-mask
            // writes are now visible. A comment that explains WHY something is
            // unmodelled is worth re-reading whenever the capability changes.
            M::Vp2intersectd | M::Vp2intersectq => {
                self.lift_intrinsic_writing_reported_regs(iced, ctx, "vp2intersect");
            }

            // AVX512_4FMAPS/4VNNIW (Knights Mill-only, discontinued Xeon
            // Phi hardware): 4-source fused-multiply-add-accumulate and
            // 4-source dot-product-accumulate, each implicitly reading
            // FOUR consecutive source registers starting at the named
            // operand (real semantics this IR can't express exactly). Real
            // single-destination writeback via `lift_simd_write` using
            // just the explicit operands, matching the established
            // approximation precedent for exotic multi-implicit-source ops
            // elsewhere in this dispatch table.
            M::V4fmaddps | M::V4fmaddss | M::V4fnmaddps | M::V4fnmaddss => {
                self.lift_simd_write(iced, ctx, "v4fmadd");
            }
            M::Vp4dpwssd | M::Vp4dpwssds => {
                self.lift_simd_write(iced, ctx, "vp4dpwssd");
            }

            // ── FMA3 (VEX.DDS 3-operand fused multiply-add) ──────────────────
            M::Vfmadd132ps | M::Vfmadd132pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Madd);
            }
            M::Vfmadd213ps | M::Vfmadd213pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Madd);
            }
            M::Vfmadd231ps | M::Vfmadd231pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Madd);
            }
            M::Vfmsub132ps | M::Vfmsub132pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Msub);
            }
            M::Vfmsub213ps | M::Vfmsub213pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Msub);
            }
            M::Vfmsub231ps | M::Vfmsub231pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Msub);
            }
            M::Vfnmadd132ps | M::Vfnmadd132pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Nmadd);
            }
            M::Vfnmadd213ps | M::Vfnmadd213pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Nmadd);
            }
            M::Vfnmadd231ps | M::Vfnmadd231pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Nmadd);
            }
            M::Vfnmsub132ps | M::Vfnmsub132pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Nmsub);
            }
            M::Vfnmsub213ps | M::Vfnmsub213pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Nmsub);
            }
            M::Vfnmsub231ps | M::Vfnmsub231pd => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Nmsub);
            }
            // Scalar (single-element) siblings of the packed FMA3 forms
            // above — same operand shape, same `lift_fma3` helper.
            M::Vfmadd132sd | M::Vfmadd132ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Madd);
            }
            M::Vfmadd213sd | M::Vfmadd213ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Madd);
            }
            M::Vfmadd231sd | M::Vfmadd231ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Madd);
            }
            M::Vfmsub132sd | M::Vfmsub132ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Msub);
            }
            M::Vfmsub213sd | M::Vfmsub213ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Msub);
            }
            M::Vfmsub231sd | M::Vfmsub231ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Msub);
            }
            M::Vfnmadd132sd | M::Vfnmadd132ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Nmadd);
            }
            M::Vfnmadd213sd | M::Vfnmadd213ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Nmadd);
            }
            M::Vfnmadd231sd | M::Vfnmadd231ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Nmadd);
            }
            M::Vfnmsub132sd | M::Vfnmsub132ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Nmsub);
            }
            M::Vfnmsub213sd | M::Vfnmsub213ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Nmsub);
            }
            M::Vfnmsub231sd | M::Vfnmsub231ss => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Nmsub);
            }
            // AVX-512 FP16 (`ph`/`sh` suffix) FMA3 siblings — same operand
            // shape as the ps/pd/sd/ss forms above, same `lift_fma3` helper.
            M::Vfmadd132ph | M::Vfmadd132sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Madd);
            }
            M::Vfmadd213ph | M::Vfmadd213sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Madd);
            }
            M::Vfmadd231ph | M::Vfmadd231sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Madd);
            }
            M::Vfmsub132ph | M::Vfmsub132sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Msub);
            }
            M::Vfmsub213ph | M::Vfmsub213sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Msub);
            }
            M::Vfmsub231ph | M::Vfmsub231sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Msub);
            }
            M::Vfnmadd132ph | M::Vfnmadd132sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Nmadd);
            }
            M::Vfnmadd213ph | M::Vfnmadd213sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Nmadd);
            }
            M::Vfnmadd231ph | M::Vfnmadd231sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Nmadd);
            }
            M::Vfnmsub132ph | M::Vfnmsub132sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S132, FmaVariant::Nmsub);
            }
            M::Vfnmsub213ph | M::Vfnmsub213sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S213, FmaVariant::Nmsub);
            }
            M::Vfnmsub231ph | M::Vfnmsub231sh => {
                self.lift_fma3(iced, ctx, Fma3Suffix::S231, FmaVariant::Nmsub);
            }

            // ── FMA4 (AMD legacy VEX 4-operand fused multiply-add) ────────────
            // `VFMADDPD/PS/SD/SS xmm1, xmm2, xmm3, xmm4` computes
            // `xmm1 = xmm2*xmm3 + xmm4` regardless of which of the two
            // alternate encodings (src3-as-register vs. src3-as-memory) was
            // used — iced_x86 normalises operand order to match this
            // semantic (src1, src2, src3) reading order for both encodings,
            // so a flat `op(1)*op(2)+op(3)` read is correct without needing
            // to special-case the encoding the way FMA3's suffix (132/213/
            // 231) does.
            M::Vfmaddpd | M::Vfmaddps | M::Vfmaddsd | M::Vfmaddss => {
                self.lift_fma4(iced, ctx, FmaVariant::Madd);
            }
            M::Vfmsubpd | M::Vfmsubps | M::Vfmsubsd | M::Vfmsubss => {
                self.lift_fma4(iced, ctx, FmaVariant::Msub);
            }
            M::Vfnmaddpd | M::Vfnmaddps | M::Vfnmaddsd | M::Vfnmaddss => {
                self.lift_fma4(iced, ctx, FmaVariant::Nmadd);
            }
            M::Vfnmsubpd | M::Vfnmsubps | M::Vfnmsubsd | M::Vfnmsubss => {
                self.lift_fma4(iced, ctx, FmaVariant::Nmsub);
            }
            // Alternating-lane forms (odd lanes get the opposite sign) —
            // approximation note: like the rest of this file's FMA lifters,
            // this models real operand reads + real writeback via the
            // named intrinsic, but does not hand-compute the per-lane
            // add/sub alternation pattern itself (downstream consumers of
            // the `Intrinsic` node are expected to know its semantics from
            // the name).
            M::Vfmaddsubpd | M::Vfmaddsubps => {
                self.lift_fma4_named(iced, ctx, "fmaddsub");
            }
            M::Vfmsubaddpd | M::Vfmsubaddps => {
                self.lift_fma4_named(iced, ctx, "fmsubadd");
            }
            // VEX.DDS 3-operand FMA3 siblings of the fmaddsub/fmsubadd
            // alternating-lane forms above (132/213/231 suffix variants) —
            // same 3-operand shape as the plain FMA3 group, reusing
            // `lift_fma3` with the same suffix/operand semantics; the
            // "-sub"/alternating-lane behavior lives in the intrinsic name.
            M::Vfmaddsub132pd | M::Vfmaddsub132ps | M::Vfmaddsub132ph => {
                self.lift_fma3_named(iced, ctx, Fma3Suffix::S132, "fmaddsub");
            }
            M::Vfmaddsub213pd | M::Vfmaddsub213ps | M::Vfmaddsub213ph => {
                self.lift_fma3_named(iced, ctx, Fma3Suffix::S213, "fmaddsub");
            }
            M::Vfmaddsub231pd | M::Vfmaddsub231ps | M::Vfmaddsub231ph => {
                self.lift_fma3_named(iced, ctx, Fma3Suffix::S231, "fmaddsub");
            }
            M::Vfmsubadd132pd | M::Vfmsubadd132ps | M::Vfmsubadd132ph => {
                self.lift_fma3_named(iced, ctx, Fma3Suffix::S132, "fmsubadd");
            }
            M::Vfmsubadd213pd | M::Vfmsubadd213ps | M::Vfmsubadd213ph => {
                self.lift_fma3_named(iced, ctx, Fma3Suffix::S213, "fmsubadd");
            }
            M::Vfmsubadd231pd | M::Vfmsubadd231ps | M::Vfmsubadd231ph => {
                self.lift_fma3_named(iced, ctx, Fma3Suffix::S231, "fmsubadd");
            }

            // ── BMI1 / BMI2 ───────────────────────────────────────────────────
            M::Andn => self.lift_bmi_andn(iced, ctx),
            M::Bextr => self.lift_bmi_bextr(iced, ctx),
            M::Bzhi => self.lift_bmi_bzhi(iced, ctx),
            M::Blsr => self.lift_bmi_blsr(iced, ctx),
            M::Blsi => self.lift_bmi_blsi(iced, ctx),

            // ── AMD TBM (XOP) ───────────────────────────────────────────────
            // Value formulas per the AMD64 APM vol. 3 / sandpile; flag handling
            // and the CF-sense argument are documented on `lift_tbm`. The
            // `true`/`false` flag is whether the instruction is built on
            // `src + 1` (true) or `src - 1` (false) — it selects the CF sense,
            // so it must match the formula's use of `adj`.
            //
            // src + 1 family: CF = (src == all-ones)
            M::Blcfill => self.lift_tbm(iced, ctx, true, |src, adj, size| {
                // x & (x + 1)
                LlilExpr::And(Box::new(src.clone()), Box::new(adj.clone()), size)
            }),
            M::Blcs => self.lift_tbm(iced, ctx, true, |src, adj, size| {
                // x | (x + 1)
                LlilExpr::Or(Box::new(src.clone()), Box::new(adj.clone()), size)
            }),
            M::Blcmsk => self.lift_tbm(iced, ctx, true, |src, adj, size| {
                // x ^ (x + 1)
                LlilExpr::Xor(Box::new(src.clone()), Box::new(adj.clone()), size)
            }),
            M::Blci => self.lift_tbm(iced, ctx, true, |src, adj, size| {
                // x | ~(x + 1)
                LlilExpr::Or(
                    Box::new(src.clone()),
                    Box::new(LlilExpr::Not(Box::new(adj.clone()), size)),
                    size,
                )
            }),
            M::Blcic => self.lift_tbm(iced, ctx, true, |src, adj, size| {
                // ~x & (x + 1)
                LlilExpr::And(
                    Box::new(LlilExpr::Not(Box::new(src.clone()), size)),
                    Box::new(adj.clone()),
                    size,
                )
            }),
            M::T1mskc => self.lift_tbm(iced, ctx, true, |src, adj, size| {
                // ~x | (x + 1)
                LlilExpr::Or(
                    Box::new(LlilExpr::Not(Box::new(src.clone()), size)),
                    Box::new(adj.clone()),
                    size,
                )
            }),
            // src - 1 family: CF = (src == 0)
            M::Blsfill => self.lift_tbm(iced, ctx, false, |src, adj, size| {
                // x | (x - 1)
                LlilExpr::Or(Box::new(src.clone()), Box::new(adj.clone()), size)
            }),
            M::Blsic => self.lift_tbm(iced, ctx, false, |src, adj, size| {
                // ~x | (x - 1)
                LlilExpr::Or(
                    Box::new(LlilExpr::Not(Box::new(src.clone()), size)),
                    Box::new(adj.clone()),
                    size,
                )
            }),
            M::Tzmsk => self.lift_tbm(iced, ctx, false, |src, adj, size| {
                // ~x & (x - 1)
                LlilExpr::And(
                    Box::new(LlilExpr::Not(Box::new(src.clone()), size)),
                    Box::new(adj.clone()),
                    size,
                )
            }),
            M::Blsmsk => self.lift_bmi_blsmsk(iced, ctx),
            M::Pdep => self.lift_bmi_intrinsic3(iced, ctx, "pdep"),
            M::Pext => self.lift_bmi_intrinsic3(iced, ctx, "pext"),
            M::Mulx => self.lift_bmi_mulx(iced, ctx),
            M::Rorx => self.lift_bmi_rorx(iced, ctx),
            M::Shlx => self.lift_bmi_shiftx(iced, ctx, ShiftOp::Shl),
            M::Shrx => self.lift_bmi_shiftx(iced, ctx, ShiftOp::Shr),
            M::Sarx => self.lift_bmi_shiftx(iced, ctx, ShiftOp::Sar),

            // ── MPX (Memory Protection Extensions) ──────────────────────
            // All effect-only: `BND*` bound-register ops don't map onto any
            // GPR/vector register this IR models, so — like the VMX/SVM
            // privileged ops above — we read every explicit operand into an
            // `Intrinsic` for downstream visibility without attempting a
            // (nonexistent) writeback.
            M::Bndmk => self.lift_intrinsic_to_op0(iced, ctx, "bndmk"),
            M::Bndcl => self.lift_fpu_generic(iced, ctx, "bndcl"),
            M::Bndcu => self.lift_fpu_generic(iced, ctx, "bndcu"),
            M::Bndcn => self.lift_fpu_generic(iced, ctx, "bndcn"),
            // `BNDMOV bnd, bnd/m` WRITES its bound destination; only the
            // `BNDMOV m, bnd` direction is a pure store. The register-to-
            // register form surfaced solely at 16-bit — the sweep's `C0` ModRM
            // decodes to something else in the wider modes, so a whole operand
            // form was invisible until the 16-bit extension.
            M::Bndmov => self.lift_intrinsic_writing_reported_regs(iced, ctx, "bndmov"),
            M::Bndldx => self.lift_intrinsic_to_op0(iced, ctx, "bndldx"),
            M::Bndstx => self.lift_fpu_generic(iced, ctx, "bndstx"),

            // ── CET (Control-flow Enforcement Technology) ───────────────
            // `ENDBR32`/`ENDBR64` are branch-target markers — architecturally
            // a NOP unless CET is enabled, matching how this dispatcher
            // treats other CPUID-gated marker ops.
            M::Endbr32 | M::Endbr64 => ctx.emit(LlilInstruction::Nop),
            // `RDSSPD`/`RDSSPQ dst` — read the current shadow-stack pointer
            // into a GPR (a real writeback, unlike the other CET ops here).
            M::Rdsspd | M::Rdsspq => {
                let size = Self::op_size(iced, 0);
                let expr = LlilExpr::Intrinsic {
                    name: "rdssp".to_string(),
                    args: vec![],
                    result_size: size,
                };
                self.write_operand(iced, 0, expr, ctx);
            }
            // `INCSSPD`/`INCSSPQ src` — advance the shadow-stack pointer by
            // `src` (scaled) CALL-sized slots; effect-only (SSP is not a
            // modeled register).
            M::Incsspd | M::Incsspq => self.lift_fpu_generic(iced, ctx, "incssp"),
            M::Saveprevssp => self.lift_intrinsic_no_result(iced, ctx, "saveprevssp"),
            M::Rstorssp => self.lift_fpu_generic(iced, ctx, "rstorssp"),
            M::Wrssd | M::Wrssq => self.lift_fpu_generic(iced, ctx, "wrss"),
            M::Wrussd | M::Wrussq => self.lift_fpu_generic(iced, ctx, "wruss"),
            M::Setssbsy => self.lift_intrinsic_no_result(iced, ctx, "setssbsy"),
            M::Clrssbsy => self.lift_fpu_generic(iced, ctx, "clrssbsy"),

            // ── Obscure/legacy ────────────────────────────────────────────
            // `LOADALL` — undocumented 286/386 debug instruction that loads
            // the entire register file (including hidden segment-descriptor
            // state) from memory; effect-only, no explicit operands.
            M::Loadall => self.lift_intrinsic_no_result(iced, ctx, "loadall"),

            // ── AES Key Locker / MSR-list / TLB-broadcast / misc newer ──────
            // Encodekey128/256: wraps an AES key into a hardware-sealed
            // handle across several XMM outputs — effect-only from the
            // pipeline's point of view (no single scalar dest to model).
            // `ENCODEKEY128/256` write their r32 destination (operand 0)
            // with the handle-restriction result.
            M::Encodekey128 => self.lift_intrinsic_writing_reported_regs(iced, ctx, "encodekey128"),
            M::Encodekey256 => self.lift_intrinsic_writing_reported_regs(iced, ctx, "encodekey256"),
            // Rdmsrlist/Wrmsrlist: bulk MSR read/write driven by an RSI
            // list pointer + RCX count; Wrmsrns: non-serializing WRMSR.
            M::Rdmsrlist => self.lift_intrinsic_writing_reported_regs(iced, ctx, "rdmsrlist"),
            M::Wrmsrlist => self.lift_intrinsic_writing_reported_regs(iced, ctx, "wrmsrlist"),
            // ⚠ These four (`Wrmsrns`, `Invlpgb`, `Tlbsync`, `Mcommit` below)
            // are NOT candidates for delegation to
            // `system_insn_lifter::SystemInsnLifter`, despite it being a
            // mnemonic-driven entry point that is otherwise unused: it has no
            // arm for any of them, so it answers with its synthetic
            // `__sys_<m>` catch-all — a worse name, a fabricated address
            // argument, and still no register write. Measured and pinned by
            // `system_insn_lifter_has_no_arm_for_the_amd_broadcast_mnemonics`.
            M::Wrmsrns => self.lift_intrinsic_no_result(iced, ctx, "wrmsrns"),
            // Invlpgb/Tlbsync: AMD broadcast TLB invalidation + barrier.
            M::Invlpgb => self.lift_intrinsic_no_result(iced, ctx, "invlpgb"),
            M::Tlbsync => self.lift_intrinsic_no_result(iced, ctx, "tlbsync"),
            // Lkgs: load IA32_KERNEL_GS_BASE without swapgs (FRED).
            M::Lkgs => self.lift_fpu_generic(iced, ctx, "lkgs"),
            // Mcommit: commit prior stores to memory (AMD).
            M::Mcommit => self.lift_intrinsic_no_result(iced, ctx, "mcommit"),

            _ => self.dispatch_fallback(iced, ctx),
        }
    }

    /// Handle conditional families (Jcc, `SETcc`, `CMOVcc`) and anything not matched
    /// by the primary mnemonic dispatch.
    fn dispatch_fallback(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let cc = iced.condition_code();
        if cc != ConditionCode::None {
            // Distinguish SETcc / CMOVcc / Jcc by structure.
            if is_setcc(iced) {
                self.lift_setcc(iced, ctx, cc);
                return;
            }
            if is_cmovcc(iced) {
                self.lift_cmovcc(iced, ctx, cc);
                return;
            }
            // Otherwise it's a conditional branch (Jcc).
            self.lift_jcc(iced, ctx, cc);
            return;
        }
        // Unknown / not-yet-lifted instruction. This is the ONLY point in the
        // dispatcher where the lifter admits it cannot translate an
        // instruction, so it is also the only place where delegating to
        // `rustre-il-lift` can add information instead of overwriting a better
        // answer. Gated OFF by default (REGOLA #28) — see
        // `il_lift_fallback_enabled`.
        let mnem = format!("{:?}", iced.mnemonic());
        if il_lift_fallback_enabled()
            && let Some(n) = self.try_il_lift_fallback(iced, ctx)
            && n > 0
        {
            return;
        }
        // Record its mnemonic so analysis can report what was skipped (raw
        // bytes are still available via the annotated wrapper's address/size).
        ctx.emit(LlilInstruction::Unimplemented { mnemonic: mnem });
    }

    /// Delegate one instruction to `rustre-il-lift` and emit the produced
    /// effects as LLIL, returning how many LLIL instructions were emitted.
    ///
    /// The `Effect` -> `LlilInstruction` conversion is NOT written here: it is
    /// the bridge that already exists (and is already unit-tested) in
    /// `rustre_il_llil::lift_effect_to_llil_instr`.
    ///
    /// Two deliberate restrictions:
    ///
    /// * `Effect::Intrinsic` with an EMPTY argument list is skipped. That is
    ///   exactly what `rustre-il-lift`'s own `_ =>` arm produces for a
    ///   mnemonic it does not model, so accepting it would replace an honest
    ///   `Unimplemented` marker with an equally empty intrinsic and *lose* the
    ///   "this was skipped" signal while looking like progress.
    /// * Returning `Some(0)` (everything skipped) leaves the caller on the
    ///   `Unimplemented` path — the delegation only wins when it produced real
    ///   effects.
    ///
    /// Returns `None` when the instruction could not be re-encoded (iced does
    /// not retain the raw bytes, so they are reconstructed — see
    /// [`iced_encoded_bytes`]).
    fn try_il_lift_fallback(&self, iced: &IcedInstruction, ctx: &mut EmitCtx) -> Option<usize> {
        let bytes = iced_encoded_bytes(iced)?;
        let bits = u8::try_from(self.bits).unwrap_or(64);
        let lifter = rustre_il_lift::X86Lifter::new(bits);
        let effects = lifter.decode_and_lift(&bytes, iced.ip())?;
        let mut n = 0usize;
        for eff in &effects {
            if matches!(eff, rustre_il_lift::Effect::Intrinsic { args, .. } if args.is_empty()) {
                continue;
            }
            ctx.emit(rustre_il_llil::lift_effect_to_llil_instr(eff, iced.ip()));
            n += 1;
        }
        Some(n)
    }
}

/// Whether the terminal `dispatch_fallback` arm delegates to `rustre-il-lift`
/// before giving up with [`LlilInstruction::Unimplemented`].
///
/// **OPT-IN, default OFF.** REGOLA #28 requires path A (`func.pseudo_code`) to
/// stay byte-identical; with `RUSTRE_X86_IL_LIFT_FALLBACK` unset this function
/// returns `false` and not a single emitted byte can change, so the invariant
/// holds by construction rather than by measurement. The control group is
/// therefore `env -u RUSTRE_X86_IL_LIFT_FALLBACK` — note that, unlike the
/// default-ON gates in this file, an EMPTY value does NOT enable it.
///
/// Turn it on with `RUSTRE_X86_IL_LIFT_FALLBACK=1` (or `=true`).
///
/// Deliberately NOT memoised in a `OnceLock`: the delegation runs only on the
/// unimplemented-instruction path (rare), and caching would make the value
/// depend on which unit test ran first.
pub(crate) fn il_lift_fallback_enabled() -> bool {
    matches!(
        std::env::var("RUSTRE_X86_IL_LIFT_FALLBACK").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Re-encode a decoded instruction back to raw bytes.
///
/// iced-x86 does not retain the bytes an [`IcedInstruction`] was decoded from,
/// and [`EmitCtx`] carries only address/size, so byte-driven consumers such as
/// `rustre_il_lift::X86Lifter::decode_and_lift` need them reconstructed. Unlike
/// [`iced_bytes`] — which returns a zero-filled placeholder of the right length
/// — this re-encodes for real via [`iced_x86::Encoder`], so the result decodes
/// back to the same instruction (the exact encoding may differ when several
/// encodings exist).
///
/// Returns `None` when the instruction cannot be encoded (e.g.
/// `Mnemonic::INVALID`).
#[must_use]
pub fn iced_encoded_bytes(iced: &IcedInstruction) -> Option<Vec<u8>> {
    let bitness = match iced.code_size() {
        iced_x86::CodeSize::Code16 => 16,
        iced_x86::CodeSize::Code32 => 32,
        _ => 64,
    };
    let mut encoder = iced_x86::Encoder::new(bitness);
    encoder.encode(iced, iced.ip()).ok()?;
    Some(encoder.take_buffer())
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Emit context
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Per-instruction emit context: tracks the originating address/size and the
/// output buffer the handlers push into.
struct EmitCtx<'a> {
    address: Address,
    size: usize,
    out: &'a mut Vec<LlilAnnotatedInstr>,
}

impl EmitCtx<'_> {
    /// Append one LLIL instruction, tagging it with the current address/size.
    fn emit(&mut self, instr: LlilInstruction) {
        // Single choke point for the ~30 `SetReg` sites in this lifter: doing
        // the widening per-site would have to be repeated at each of them and
        // would silently miss any added later.
        let instr = if gpr32_alias_enabled() {
            widen_gpr32_write(instr)
        } else {
            instr
        };
        // 8/16 bit: transform SEPARATA perche' la regola e' diversa (i bit alti
        // sopravvivono). Gate distinto, cosi' le due si misurano da sole.
        let instr = if gpr_narrow_alias_enabled() {
            widen_gpr_narrow_write(instr)
        } else {
            instr
        };
        let len = u8::try_from(self.size).unwrap_or(u8::MAX);
        self.out.push(LlilAnnotatedInstr {
            address: self.address,
            size: self.size,
            instr,
            length: len,
        });
    }

    /// Address of the instruction immediately following the current one
    /// (the natural fall-through).
    fn fall_through(&self) -> Address {
        Address::new(self.address.0.wrapping_add(self.size as u64))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Small helper enums
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Clone, Copy)]
enum LogicOp {
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy)]
enum ShiftOp {
    Shl,
    Shr,
    Sar,
}

#[derive(Clone, Copy)]
enum RotateOp {
    Rol,
    Ror,
    Rcl,
    Rcr,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Free helper functions
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lower-case mnemonic name (for intrinsics).
fn reg_name_lower_mnemonic(m: Mnemonic) -> String {
    let mut s = format!("{m:?}");
    s.make_ascii_lowercase();
    s
}

/// Recover the raw encoded bytes of an instruction (best effort: iced does not
/// store the bytes, so we synthesise a placeholder of the right length).
///
/// Exposed publicly so downstream consumers — FLIRT, YARA, signature
/// generators, and trace replay code that wants a length-correct slot per
/// decoded instruction — can opt into the placeholder without re-implementing
/// it. The placeholder is `0u8`-filled; callers that need real encoding
/// should re-encode via `iced_x86::Encoder` against a known IP.
#[must_use]
pub fn iced_bytes(iced: &IcedInstruction) -> Vec<u8> {
    vec![0u8; iced.len()]
}

/// Returns `true` if the instruction carries a REP/REPE/REPNE prefix or is a
/// genuine string operation (used to disambiguate `movsd`/`cmpsd` between the
/// string form and the SSE scalar-double form).
fn is_string_op(iced: &IcedInstruction) -> bool {
    matches!(
        iced.code(),
        Code::Movsb_m8_m8
            | Code::Movsw_m16_m16
            | Code::Movsd_m32_m32
            | Code::Movsq_m64_m64
            | Code::Cmpsb_m8_m8
            | Code::Cmpsw_m16_m16
            | Code::Cmpsd_m32_m32
            | Code::Cmpsq_m64_m64
    )
}

/// Returns `true` if `iced` is a `SETcc` instruction (single 8-bit destination).
fn is_setcc(iced: &IcedInstruction) -> bool {
    matches!(
        iced.mnemonic(),
        Mnemonic::Seto
            | Mnemonic::Setno
            | Mnemonic::Setb
            | Mnemonic::Setae
            | Mnemonic::Sete
            | Mnemonic::Setne
            | Mnemonic::Setbe
            | Mnemonic::Seta
            | Mnemonic::Sets
            | Mnemonic::Setns
            | Mnemonic::Setp
            | Mnemonic::Setnp
            | Mnemonic::Setl
            | Mnemonic::Setge
            | Mnemonic::Setle
            | Mnemonic::Setg
    )
}

/// Returns `true` if `iced` is a `CMOVcc` instruction.
fn is_cmovcc(iced: &IcedInstruction) -> bool {
    matches!(
        iced.mnemonic(),
        Mnemonic::Cmovo
            | Mnemonic::Cmovno
            | Mnemonic::Cmovb
            | Mnemonic::Cmovae
            | Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovbe
            | Mnemonic::Cmova
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns
            | Mnemonic::Cmovp
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovl
            | Mnemonic::Cmovge
            | Mnemonic::Cmovle
            | Mnemonic::Cmovg
    )
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Operand modelling
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// Compute the LLIL [`Size`] of operand `n`.
    fn op_size(iced: &IcedInstruction, n: u32) -> Size {
        match iced.op_kind(n) {
            OpKind::Register => reg_size(iced.op_register(n)),
            OpKind::Immediate8 | OpKind::Immediate8_2nd => Size::Byte,
            OpKind::Immediate16 | OpKind::Immediate8to16 => Size::Word,
            OpKind::Immediate32 | OpKind::Immediate8to32 => Size::DWord,
            OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => Size::QWord,
            OpKind::NearBranch16 | OpKind::FarBranch16 => Size::Word,
            OpKind::NearBranch32 | OpKind::FarBranch32 => Size::DWord,
            OpKind::NearBranch64 => Size::QWord,
            // For memory operands fall back to the instruction's memory size.
            _ => size_from_bytes(iced.memory_size().size()),
        }
    }

    /// Build the address expression for the memory operand of `iced`
    /// (`base + index*scale + disp`, or a RIP-relative absolute address).
    fn mem_address(&self, iced: &IcedInstruction) -> LlilExpr {
        let asize = self.ptr_size();

        // RIP-relative memory: iced resolves the absolute target for us.
        if iced.is_ip_rel_memory_operand() {
            return LlilExpr::Const {
                value: iced.memory_displacement64(),
                size: asize,
            };
        }

        let base = iced.memory_base();
        let index = iced.memory_index();
        let scale = iced.memory_index_scale();
        let disp = iced.memory_displacement64();

        let mut acc: Option<LlilExpr> = None;

        if base != Register::None {
            // Read through the parent so a NARROW base aliases: with an
            // address-size override the base is `eax`, and hand-building the
            // read here bypasses the alias tables exactly as `cdqe`/`cmpxchg`/
            // `div`/`cdq` used to. Measured: 6 residuals, all the same
            // `mov %gs:(%eax),%rax` CRT idiom; at 64 bits this is a no-op
            // because the parent IS the register.
            acc = Some(Self::read_reg_by_name(&reg_name(base), asize));
        }

        if index != Register::None {
            let idx_reg = LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(reg_name(index)),
                size: asize,
            };
            let scaled = if scale > 1 {
                LlilExpr::MulT(
                    Box::new(idx_reg),
                    Box::new(LlilExpr::Const {
                        value: u64::from(scale),
                        size: asize,
                    }),
                    asize,
                )
            } else {
                idx_reg
            };
            acc = Some(match acc {
                Some(b) => LlilExpr::AddT(Box::new(b), Box::new(scaled), asize),
                None => scaled,
            });
        }

        if disp != 0 || acc.is_none() {
            let disp_expr = LlilExpr::Const {
                value: disp,
                size: asize,
            };
            acc = Some(match acc {
                Some(b) => LlilExpr::AddT(Box::new(b), Box::new(disp_expr), asize),
                None => disp_expr,
            });
        }

        acc.unwrap_or(LlilExpr::Const {
            value: 0,
            size: asize,
        })
    }

    /// Read operand `n` as an [`LlilExpr`] value.
    ///
    /// Register and immediate operands map directly; memory operands become an
    /// explicit [`LlilExpr::Load`] from the computed address.
    fn read_operand(&self, iced: &IcedInstruction, n: u32) -> LlilExpr {
        let size = Self::op_size(iced, n);
        match iced.op_kind(n) {
            OpKind::Register => {
                let reg = iced.op_register(n);
                if reg == Register::None {
                    LlilExpr::Undefined(size)
                } else {
                    let name = reg_name(reg);
                    // READ half of the 32-bit aliasing: the value lives in the
                    // 64-bit parent, so read that and truncate. Without the
                    // truncation the upper 32 bits would leak into a 32-bit
                    // use whenever the last write was 64-bit wide.
                    // 8/16 bit: il valore vive nei bit bassi del padre, quindi
                    // si legge il padre e si MASCHERA (non basta troncare: la
                    // larghezza dell'operando resta quella stretta).
                    if high_byte_alias_enabled()
                        && let Some(parent) = gpr_high_byte_parent(&name)
                    {
                        // `(parent >> 8) & 0xFF`
                        return LlilExpr::And(
                            Box::new(LlilExpr::Shr(
                                Box::new(LlilExpr::RegisterRef {
                                    reg: LlilRegister::Concrete(parent.to_string()),
                                    size: Size::QWord,
                                }),
                                Box::new(LlilExpr::Const { value: 8, size: Size::QWord }),
                                Size::QWord,
                            )),
                            Box::new(LlilExpr::Const { value: 0xFF, size: Size::QWord }),
                            size,
                        );
                    }
                    if let Some((parent, width)) = gpr_narrow_alias_enabled()
                        .then(|| narrow_parent_aliased(&name))
                        .flatten()
                    {
                        let mask: u64 = if width == 8 { 0xFF } else { 0xFFFF };
                        return LlilExpr::And(
                            Box::new(LlilExpr::RegisterRef {
                                reg: LlilRegister::Concrete(parent.to_string()),
                                size: Size::QWord,
                            }),
                            Box::new(LlilExpr::Const { value: mask, size: Size::QWord }),
                            size,
                        );
                    }
                    match gpr32_alias_enabled()
                        .then(|| gpr32_parent(&name))
                        .flatten()
                    {
                        Some(parent) => LlilExpr::LowPart {
                            expr: Box::new(LlilExpr::RegisterRef {
                                reg: LlilRegister::Concrete(parent.to_string()),
                                size: Size::QWord,
                            }),
                            to: Size::DWord,
                        },
                        None => LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete(name),
                            size,
                        },
                    }
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => LlilExpr::Const {
                value: iced.immediate(n),
                size,
            },
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => LlilExpr::Const {
                value: iced.near_branch_target(),
                size,
            },
            OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => {
                // A GS/FS-prefixed load is NOT a dereference of an ordinary
                // address: the segment base is supplied by the OS and is not a
                // value this function ever computes. Modelled as a plain Load,
                // the base becomes a local nothing writes (see
                // `segment_read_intrinsic`).
                if let Some(name) = Self::segment_read_intrinsic(iced.segment_prefix(), size) {
                    LlilExpr::Intrinsic {
                        name: name.to_string(),
                        args: vec![self.string_or_mem_address(iced, n)],
                        result_size: size,
                    }
                } else {
                    LlilExpr::Load {
                        addr: Box::new(self.string_or_mem_address(iced, n)),
                        size,
                    }
                }
            }
            _ => LlilExpr::Undefined(size),
        }
    }

    /// MSVC intrinsic for a `GS:`/`FS:`-prefixed read, by access width.
    ///
    /// The thread block is reached through a segment whose base the OS sets and
    /// the function never computes. Emitting `*(T *)addr` therefore leaves the
    /// base as a local that is read and never written — the exact residual this
    /// repairs — and silently drops the offset. The project already speaks
    /// these intrinsics (`__readgsqword` and friends), but only in the TEXTUAL
    /// pipeline of path A, which the HLIL path never goes through; on path B
    /// **not one of the 11144 emitted files contained one**. So this revives an
    /// existing treatment rather than inventing a new one.
    ///
    /// Gate `RUSTRE_X86_SEGMENT_INTRINSIC`, **default ON since #369**, measured:
    /// 1151 intrinsics across 783 functions, and on a 40-function sample read
    /// against the disassembly, ZERO lacked a `%gs:`/`%fs:` prefix (no ordinary
    /// load was hijacked), ZERO signatures changed, and 38/40 replaced a
    /// dereference. Fixed-list recompilability ROSE 1195/1200 -> 1199/1200: the
    /// shape it replaces (`((__int64 (*)())*(__int64 *)(uint64_t))…`) was not
    /// merely ugly, it was ill-typed.
    /// ⚠ HONEST: the residual count did NOT move (1037 before, 1037 after). The
    /// -18 predicted at #331 was computed on a tree that has since changed; this
    /// is promoted on FIDELITY and recompilability, NOT on residuals.
    /// Opt out with `RUSTRE_X86_SEGMENT_INTRINSIC=0`.
    fn segment_read_intrinsic(seg: Register, size: Size) -> Option<&'static str> {
        if !Self::segment_intrinsic_enabled() {
            return None;
        }
        Self::segment_intrinsic_name(seg, size)
    }

    /// The gate alone, split out so a test can state which branch it is in.
    ///
    /// ⚠ Memoized: within ONE process this value is fixed, so a test cannot
    /// exercise both directions here. The two-direction proof is therefore made
    /// at process level (`env -u …` vs `=1`), and what a unit test can own is
    /// the pure mapping below.
    fn segment_intrinsic_enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| {
            !matches!(
                std::env::var("RUSTRE_X86_SEGMENT_INTRINSIC").as_deref(),
                Ok("0") | Ok("false")
            )
        })
    }

    /// Pure segment/width -> intrinsic mapping, with no gate: exhaustively
    /// testable, and `None` for every non-segment register.
    fn segment_intrinsic_name(seg: Register, size: Size) -> Option<&'static str> {
        let gs = match seg {
            Register::GS => true,
            Register::FS => false,
            _ => return None,
        };
        Some(match (gs, size) {
            (true, Size::Byte) => "__readgsbyte",
            (true, Size::Word) => "__readgsword",
            (true, Size::DWord) => "__readgsdword",
            (true, _) => "__readgsqword",
            (false, Size::Byte) => "__readfsbyte",
            (false, Size::Word) => "__readfsword",
            (false, Size::DWord) => "__readfsdword",
            (false, _) => "__readfsqword",
        })
    }

    /// Address expression for either a regular memory operand or an implicit
    /// string-operation source/destination operand (`[rsi]` / `[rdi]`).
    fn string_or_mem_address(&self, iced: &IcedInstruction, n: u32) -> LlilExpr {
        let asize = self.ptr_size();
        match iced.op_kind(n) {
            OpKind::MemorySegSI | OpKind::MemorySegESI | OpKind::MemorySegRSI => {
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(self.si_name()),
                    size: asize,
                }
            }
            OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.di_name()),
                size: asize,
            },
            _ => self.mem_address(iced),
        }
    }

    /// Source-index register name for the current bitness.
    fn si_name(&self) -> String {
        match self.bits {
            16 => "si",
            32 => "esi",
            _ => "rsi",
        }
        .to_string()
    }

    /// Destination-index register name for the current bitness.
    fn di_name(&self) -> String {
        match self.bits {
            16 => "di",
            32 => "edi",
            _ => "rdi",
        }
        .to_string()
    }

    /// Whether operand `n` is a memory operand of any kind.
    fn op_is_memory(iced: &IcedInstruction, n: u32) -> bool {
        matches!(
            iced.op_kind(n),
            OpKind::Memory
                | OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI
        )
    }

    /// Write `value` to operand `n` (register â†' [`LlilInstruction::SetReg`],
    /// memory â†' [`LlilInstruction::Store`]).
    fn write_operand(&self, iced: &IcedInstruction, n: u32, value: LlilExpr, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, n);
        match iced.op_kind(n) {
            OpKind::Register => {
                let reg = iced.op_register(n);
                ctx.emit(LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete(reg_name(reg)),
                    size,
                    value,
                });
            }
            _ if Self::op_is_memory(iced, n) => {
                ctx.emit(LlilInstruction::Store {
                    addr: self.string_or_mem_address(iced, n),
                    size,
                    value,
                });
            }
            _ => {
                // Writing to an immediate / branch operand is meaningless;
                // emit nothing rather than corrupt state.
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Flag helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Build an [`LlilExpr`] that reads architectural flag `name`.
fn flag(name: &str) -> LlilExpr {
    LlilExpr::Flag(name.to_string())
}

/// `value == 0` (zero-flag definition).
fn is_zero(value: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::CmpEq(
        Box::new(value),
        Box::new(LlilExpr::Const { value: 0, size }),
    )
}

/// `value <s 0` (sign-flag definition).
fn is_negative(value: LlilExpr, size: Size) -> LlilExpr {
    LlilExpr::CmpSlt(
        Box::new(value),
        Box::new(LlilExpr::Const { value: 0, size }),
    )
}

/// Largest unsigned value representable in `size` (all bits set).
fn size_max_unsigned(size: Size) -> u64 {
    let bits = size.bits();
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

impl X86Lifter {
    /// Emit a `SetFlag flag = const` instruction.
    fn emit_set_flag_const(&mut self, ctx: &mut EmitCtx, name: &str, value: u64) {
        ctx.emit(LlilInstruction::SetFlag {
            name: name.to_string(),
            src: LlilExpr::Const {
                value,
                size: Size::Byte,
            },
        });
    }

    /// Emit `SetFlag name = src`.
    fn emit_set_flag(&mut self, ctx: &mut EmitCtx, name: &str, src: LlilExpr) {
        ctx.emit(LlilInstruction::SetFlag {
            name: name.to_string(),
            src,
        });
    }

    /// Emit the standard SF / ZF / PF flag definitions derived from `result`.
    ///
    /// `result` is cloned into each predicate; callers typically materialise the
    /// result into a temporary first so the expressions stay small.
    fn emit_sf_zf_pf(&mut self, ctx: &mut EmitCtx, result: &LlilExpr, size: Size) {
        self.emit_set_flag(ctx, FLAG_SF, is_negative(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.emit_set_flag(
            ctx,
            FLAG_PF,
            LlilExpr::Intrinsic {
                name: "parity".to_string(),
                args: vec![result.clone()],
                result_size: Size::Byte,
            },
        );
    }

    /// Materialise `expr` into a fresh temporary register and return a read of
    /// that temporary. Useful when a value feeds several flag predicates.
    fn materialise_temp(&mut self, expr: LlilExpr, size: Size, ctx: &mut EmitCtx) -> LlilExpr {
        let t = self.new_temp();
        ctx.emit(LlilInstruction::SetReg {
            dest: t.clone(),
            size,
            value: expr,
        });
        LlilExpr::RegisterRef { reg: t, size }
    }

    // â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    // Condition predicate construction
    // â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Build a boolean [`LlilExpr`] (result 0/1) for the given x86 condition
    /// code, expressed purely in terms of architectural flags.
    fn cond_expr(cc: ConditionCode) -> LlilExpr {
        let cf = || flag(FLAG_CF);
        let zf = || flag(FLAG_ZF);
        let sf = || flag(FLAG_SF);
        let of = || flag(FLAG_OF);
        let pf = || flag(FLAG_PF);
        let one = || LlilExpr::Const {
            value: 1,
            size: Size::Byte,
        };
        let is_set = |e: LlilExpr| LlilExpr::CmpEq(Box::new(e), Box::new(one()));
        let is_clr = |e: LlilExpr| {
            LlilExpr::CmpEq(
                Box::new(e),
                Box::new(LlilExpr::Const {
                    value: 0,
                    size: Size::Byte,
                }),
            )
        };
        let or = |a: LlilExpr, b: LlilExpr| LlilExpr::Or(Box::new(a), Box::new(b), Size::Byte);
        let and = |a: LlilExpr, b: LlilExpr| LlilExpr::And(Box::new(a), Box::new(b), Size::Byte);
        match cc {
            ConditionCode::None => one(),
            ConditionCode::o => is_set(of()),
            ConditionCode::no => is_clr(of()),
            ConditionCode::b => is_set(cf()),  // CF=1
            ConditionCode::ae => is_clr(cf()), // CF=0
            ConditionCode::e => is_set(zf()),  // ZF=1
            ConditionCode::ne => is_clr(zf()), // ZF=0
            ConditionCode::be => or(is_set(cf()), is_set(zf())), // CF=1 or ZF=1
            ConditionCode::a => and(is_clr(cf()), is_clr(zf())), // CF=0 and ZF=0
            ConditionCode::s => is_set(sf()),  // SF=1
            ConditionCode::ns => is_clr(sf()), // SF=0
            ConditionCode::p => is_set(pf()),  // PF=1
            ConditionCode::np => is_clr(pf()), // PF=0
            ConditionCode::l => LlilExpr::CmpNe(Box::new(sf()), Box::new(of())), // SF!=OF
            ConditionCode::ge => LlilExpr::CmpEq(Box::new(sf()), Box::new(of())), // SF=OF
            ConditionCode::le => or(
                is_set(zf()),
                LlilExpr::CmpNe(Box::new(sf()), Box::new(of())),
            ), // ZF=1 or SF!=OF
            ConditionCode::g => and(
                is_clr(zf()),
                LlilExpr::CmpEq(Box::new(sf()), Box::new(of())),
            ), // ZF=0 and SF=OF
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Data-movement handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `MOV dst, src`.
    fn lift_mov(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        if iced.op_count() < 2 {
            ctx.emit(LlilInstruction::Nop);
            return;
        }
        let src = self.read_operand(iced, 1);
        self.write_operand(iced, 0, src, ctx);
    }

    /// `MOVZX dst, src` —" zero-extend.
    fn lift_movzx(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let from = Self::op_size(iced, 1);
        let to = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let ext = LlilExpr::ZeroExtend {
            expr: Box::new(src),
            from,
            to,
        };
        self.write_operand(iced, 0, ext, ctx);
    }

    /// `MOVSX` / `MOVSXD dst, src` —" sign-extend.
    fn lift_movsx(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let from = Self::op_size(iced, 1);
        let to = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let ext = LlilExpr::SignExtend {
            expr: Box::new(src),
            from,
            to,
        };
        self.write_operand(iced, 0, ext, ctx);
    }

    /// `LEA dst, [mem]` —" compute the effective address, no memory access.
    fn lift_lea(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let addr = self.mem_address(iced);
        let dst_size = Self::op_size(iced, 0);
        // LEA may truncate the computed address to the destination width.
        let value = if dst_size.bytes() < self.ptr_size().bytes() {
            LlilExpr::LowPart {
                expr: Box::new(addr),
                to: dst_size,
            }
        } else {
            addr
        };
        self.write_operand(iced, 0, value, ctx);
    }

    /// `XCHG a, b` —" atomic exchange via a temporary.
    fn lift_xchg(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let tmp = self.materialise_temp(a, size, ctx);
        self.write_operand(iced, 0, b, ctx);
        self.write_operand(iced, 1, tmp, ctx);
    }

    /// `CMPXCHG dst, src` —" compare `acc` with `dst`; on equality store `src`
    /// into `dst`, otherwise load `dst` into `acc`. Sets ZF accordingly.
    fn lift_cmpxchg(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let acc_reg = match size {
            Size::Byte => "al",
            Size::Word => "ax",
            Size::DWord => "eax",
            _ => "rax",
        };
        // The accumulator is an IMPLICIT operand, so it never passes through
        // `read_operand` and — built by hand — never consulted the alias tables:
        // `eax` became a register of its own, distinct from `rax`. Measured on
        // the corpus: a function that loads `rax` and then `cmpxchg`es on `eax`
        // emitted `uint32_t v9` READ AND NEVER WRITTEN (e.g. `sample10_cs`
        // `sub_14006c020`, 4 × `lock cmpxchg` with `rax` defined before the
        // first one). Same defect class as `cdqe` — see `lift_sign_extend_acc`.
        let acc = if implicit_acc_alias_enabled() {
            Self::read_reg_by_name(acc_reg, size)
        } else {
            LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(acc_reg.to_string()),
                size,
            }
        };
        let dst = self.read_operand(iced, 0);
        let src = self.read_operand(iced, 1);

        // Flags: ALL set exactly as `CMP acc, dst` (SDM) — not just ZF.
        let cmp_result = self.materialise_temp(
            LlilExpr::SubT(Box::new(acc.clone()), Box::new(dst.clone()), size),
            size,
            ctx,
        );
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpUlt(Box::new(acc.clone()), Box::new(dst.clone())),
        );
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&acc, &dst, &cmp_result, true));
        self.emit_set_flag(ctx, FLAG_AF, Self::aux_flag(&acc, &dst, true));
        self.emit_sf_zf_pf(ctx, &cmp_result, size);

        let eq = LlilExpr::CmpEq(Box::new(acc.clone()), Box::new(dst.clone()));

        // BOTH writes below are CONDITIONAL on the compare, and modelling
        // "maybe write" as "always write the old value" is NOT a no-op at
        // 32 bits on x86-64: any write to a 32-bit register zero-extends into
        // the full 64-bit one. So the untaken branch destroyed the upper half.
        // Hardware-measured before the fix (`cmpxchg ecx, ebx`, not equal):
        // native left rcx = 0x123456789ABCDEF0, the IL left 0x9ABCDEF0.
        //
        // 8- and 16-bit writes preserve the surrounding bits, and a 64-bit
        // write covers the whole register, so ONLY the 32-bit case is affected
        // — which is why `cmpxchg cl, bl` and `cmpxchg rcx, rbx` always agreed
        // with the CPU. Widening the write to the 64-bit parent makes the
        // untaken branch a genuine no-op at every width.

        // dst = (acc == dst) ? src : dst
        //
        // NOTE the untaken branch must be the FULL parent register, not the
        // 32-bit read widened: `zext(low32(rcx))` is still 0x00000000_9ABCDEF0.
        // Widening only the WRITE is not enough — the first attempt at this fix
        // did exactly that and the hardware oracle stayed red with identical
        // values, which is what made the mistake obvious.
        if !self.write_cond_reg_preserving_parent(iced, 0, &eq, &src, size, ctx) {
            let new_dst = LlilExpr::CondExpr {
                cond: Box::new(eq.clone()),
                true_val: Box::new(src),
                false_val: Box::new(dst.clone()),
                size,
            };
            self.write_operand(iced, 0, new_dst, ctx);
        }

        // acc = (acc == dst) ? acc : dst
        //
        // Same hazard, mirrored: here the EQUAL branch is the one that writes
        // the accumulator its own value. The hardware oracle did not catch this
        // half on its own because the failing grid states had rax = 0, where a
        // zero-extension is invisible — absence of a red is not evidence here.
        let eq2 = eq.clone();
        let dst2 = dst.clone();
        let new_acc = LlilExpr::CondExpr {
            cond: Box::new(eq),
            true_val: Box::new(acc),
            false_val: Box::new(dst),
            size,
        };
        if size == Size::DWord {
            // Mirror of the destination fix: the EQUAL branch does not write
            // the accumulator, so it must yield the full 64-bit rax; only the
            // not-equal branch performs a 32-bit write (which zero-extends).
            let parent = Self::parent64_name(acc_reg);
            let parent_ref = LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(parent.clone()),
                size: Size::QWord,
            };
            let _ = new_acc;
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(parent.clone()),
                size: Size::QWord,
                value: LlilExpr::CondExpr {
                    cond: Box::new(eq2),
                    true_val: Box::new(parent_ref),
                    false_val: Box::new(LlilExpr::ZeroExtend {
                        expr: Box::new(dst2),
                        from: Size::DWord,
                        to: Size::QWord,
                    }),
                    size: Size::QWord,
                },
            });
        } else {
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(acc_reg.to_string()),
                size,
                value: new_acc,
            });
        }
    }

    /// 64-bit parent of a 32-bit GPR name used by the accumulator table above.
    fn parent64_name(name: &str) -> String {
        match name {
            "eax" => "rax",
            "ecx" => "rcx",
            "edx" => "rdx",
            "ebx" => "rbx",
            other => other,
        }
        .to_string()
    }

    /// When operand `idx` is a 32-bit REGISTER, emit the write at its 64-bit
    /// parent instead, zero-extending the value.
    ///
    /// Returns `true` when it handled the write. Only 32-bit register
    /// destinations are redirected: those are the sole case where writing a
    /// value back unchanged is observable (x86-64 zero-extends 32-bit writes).
    /// Memory destinations and other widths fall through to the normal path.
    ///
    /// The 32→64 mapping comes from `iced_x86::Register::full_register()` —
    /// the decoder's own table — rather than a hand-written one, so it cannot
    /// drift into being a second, disagreeing description of the register file.
    fn write_cond_reg_preserving_parent(
        &mut self,
        iced: &IcedInstruction,
        idx: u32,
        cond: &LlilExpr,
        taken_val: &LlilExpr,
        size: Size,
        ctx: &mut EmitCtx,
    ) -> bool {
        if size != Size::DWord || iced.op_kind(idx) != iced_x86::OpKind::Register {
            return false;
        }
        let reg = iced.op_register(idx);
        let parent = reg.full_register();
        if parent == reg {
            return false;
        }
        let parent_ref = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(reg_name(parent)),
            size: Size::QWord,
        };
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg_name(parent)),
            size: Size::QWord,
            value: LlilExpr::CondExpr {
                // Taken: a real 32-bit write, which zero-extends — model that
                // explicitly rather than relying on the write's width.
                cond: Box::new(cond.clone()),
                true_val: Box::new(LlilExpr::ZeroExtend {
                    expr: Box::new(taken_val.clone()),
                    from: Size::DWord,
                    to: Size::QWord,
                }),
                // Untaken: the register is not written at all, so all 64 bits
                // survive. This is the whole point of the helper.
                false_val: Box::new(parent_ref),
                size: Size::QWord,
            },
        });
        true
    }

    /// APX `CMPccXADD reg1, reg2, [mem]` —" conditional atomic
    /// compare-and-add:
    /// ```text
    /// temp = [mem]
    /// flags = CMP(reg1, temp)      // reg1 - temp, sets OF/SF/ZF/AF/CF/PF
    /// if cc(flags): [mem] = temp + reg2
    /// reg1 = temp
    /// ```
    /// `reg1` always ends up holding the pre-update memory value regardless
    /// of whether the condition was taken (matches Intel's APX spec).
    fn lift_cmpccxadd(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, cc: ConditionCode) {
        // iced encodes this form as `[mem], reg1, reg2` (operand 0 is the
        // memory operand), even though Intel's mnemonic syntax reads
        // `CMPccXADD reg1, reg2, [mem]` — do not reorder to match the
        // mnemonic text.
        let size = Self::op_size(iced, 0);
        let reg1 = self.read_operand(iced, 1);
        let reg2 = self.read_operand(iced, 2);
        let temp = self.materialise_temp(self.read_operand(iced, 0), size, ctx);

        // Flags as if `CMP reg1, temp` executed.
        let sub = self.materialise_temp(
            LlilExpr::SubT(Box::new(reg1.clone()), Box::new(temp.clone()), size),
            size,
            ctx,
        );
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpUlt(Box::new(reg1.clone()), Box::new(temp.clone())),
        );
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&reg1, &temp, &sub, true));
        self.emit_set_flag(ctx, FLAG_AF, Self::aux_flag(&reg1, &temp, true));
        self.emit_sf_zf_pf(ctx, &sub, size);

        let cond = Self::cond_expr(cc);
        let new_mem = LlilExpr::CondExpr {
            cond: Box::new(cond),
            true_val: Box::new(LlilExpr::AddT(Box::new(temp.clone()), Box::new(reg2), size)),
            false_val: Box::new(temp.clone()),
            size,
        };
        self.write_operand(iced, 0, new_mem, ctx);
        self.write_operand(iced, 1, temp, ctx);
    }

    /// RAO-INT `Aadd/Aand/Aor/Axor [mem], src` —" unconditional atomic
    /// memory read-modify-write with no register writeback and no flags
    /// affected (per Intel's RAO-INT spec, these are pure memory ops).
    fn lift_atomic_memop(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        op: impl FnOnce(LlilExpr, LlilExpr, Size) -> LlilExpr,
    ) {
        let size = Self::op_size(iced, 0);
        let dst = self.read_operand(iced, 0);
        let src = self.read_operand(iced, 1);
        let result = op(dst, src, size);
        self.write_operand(iced, 0, result, ctx);
    }

    /// `PUSH src` —" decrement SP and store.
    fn lift_push(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let push_size = if size.bytes() < self.ptr_size().bytes() {
            self.ptr_size()
        } else {
            size
        };
        let src = self.read_operand(iced, 0);
        let value = if push_size == size {
            src
        } else {
            LlilExpr::ZeroExtend {
                expr: Box::new(src),
                from: size,
                to: push_size,
            }
        };
        ctx.emit(LlilInstruction::Push {
            size: push_size,
            src: value,
        });
    }

    /// `POP dst` —" load from stack and increment SP.
    fn lift_pop(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let pop_size = if size.bytes() < self.ptr_size().bytes() {
            self.ptr_size()
        } else {
            size
        };
        if iced.op_kind(0) == OpKind::Register {
            let reg = iced.op_register(0);
            ctx.emit(LlilInstruction::Pop {
                dest: LlilRegister::Concrete(reg_name(reg)),
                size: pop_size,
            });
        } else {
            // pop into memory: model as load-from-SP then store, with SP
            // adjustment handled by the Pop pseudo on a temporary.
            let tmp = self.new_temp();
            ctx.emit(LlilInstruction::Pop {
                dest: tmp.clone(),
                size: pop_size,
            });
            self.write_operand(
                iced,
                0,
                LlilExpr::RegisterRef {
                    reg: tmp,
                    size: pop_size,
                },
                ctx,
            );
        }
    }

    /// `PUSHF`/`PUSHFD`/`PUSHFQ` —" push the flags register.
    fn lift_pushf(&mut self, _iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = self.ptr_size();
        ctx.emit(LlilInstruction::Push {
            size,
            src: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.flags_name()),
                size,
            },
        });
    }

    /// `POPF`/`POPFD`/`POPFQ` —" pop into the flags register.
    fn lift_popf(&mut self, _iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = self.ptr_size();
        ctx.emit(LlilInstruction::Pop {
            dest: LlilRegister::Concrete(self.flags_name()),
            size,
        });
    }

    /// Flags register name for the current bitness.
    fn flags_name(&self) -> String {
        match self.bits {
            16 => "flags",
            32 => "eflags",
            _ => "rflags",
        }
        .to_string()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Arithmetic handlers (with full flag computation)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `ADD`/`SUB`/`ADC`/`SBB dst, src`.
    ///
    /// `is_sub` selects subtraction semantics; `with_carry` includes the carry
    /// flag (ADC/SBB).
    fn lift_add_sub(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        is_sub: bool,
        with_carry: bool,
    ) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);

        // Carry-in for ADC/SBB, materialised once so it's read consistently
        // (pre-instruction value) everywhere it's used below.
        let cf_in = if with_carry {
            Some(self.materialise_temp(
                LlilExpr::ZeroExtend {
                    expr: Box::new(flag(FLAG_CF)),
                    from: Size::Byte,
                    to: size,
                },
                size,
                ctx,
            ))
        } else {
            None
        };

        // b' = b + carry-in, used only for the *value* computation. Flags
        // (CF/OF/AF) are derived below from the original `a`, `b`, and
        // carry-in via full-adder/full-subtractor identities, since folding
        // the carry into `b` first loses information at the b == MAX corner.
        let b_folded = match &cf_in {
            Some(cf) => LlilExpr::AddT(Box::new(b.clone()), Box::new(cf.clone()), size),
            None => b.clone(),
        };

        let result_expr = if is_sub {
            LlilExpr::SubT(Box::new(a.clone()), Box::new(b_folded.clone()), size)
        } else {
            LlilExpr::AddT(Box::new(a.clone()), Box::new(b_folded.clone()), size)
        };
        let result = self.materialise_temp(result_expr, size, ctx);

        // Carry flag (full-adder/full-subtractor form over the *original* a, b).
        let cf = if is_sub {
            // borrow = (a <u b) | (cf_in & (a == b))
            let base = LlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone()));
            match &cf_in {
                Some(cf) => {
                    let eq = LlilExpr::CmpEq(Box::new(a.clone()), Box::new(b.clone()));
                    let carry_edge = LlilExpr::And(Box::new(cf.clone()), Box::new(eq), Size::Byte);
                    LlilExpr::Or(Box::new(base), Box::new(carry_edge), Size::Byte)
                }
                None => base,
            }
        } else {
            // sum0 = a + b (no carry-in). When there's no carry-in, `result`
            // above already equals sum0 (b_folded == b), so reuse it instead
            // of emitting a redundant duplicate temp.
            let sum0 = match &cf_in {
                Some(_) => self.materialise_temp(
                    LlilExpr::AddT(Box::new(a.clone()), Box::new(b.clone()), size),
                    size,
                    ctx,
                ),
                None => result.clone(),
            };
            // overflow = (sum0 <u a) | (cf_in & (sum0 == MAX))
            let base = LlilExpr::CmpUlt(Box::new(sum0.clone()), Box::new(a.clone()));
            match &cf_in {
                Some(cf) => {
                    let max = LlilExpr::Const {
                        value: size_max_unsigned(size),
                        size,
                    };
                    let at_max = LlilExpr::CmpEq(Box::new(sum0), Box::new(max));
                    let carry_edge =
                        LlilExpr::And(Box::new(cf.clone()), Box::new(at_max), Size::Byte);
                    LlilExpr::Or(Box::new(base), Box::new(carry_edge), Size::Byte)
                }
                None => base,
            }
        };
        self.emit_set_flag(ctx, FLAG_CF, cf);

        // Overflow flag (signed), computed against the original `b`.
        let of = Self::overflow_flag(&a, &b, &result, is_sub);
        self.emit_set_flag(ctx, FLAG_OF, of);

        // Auxiliary flag (carry/borrow out of bit 3), same full-adder
        // treatment as CF but restricted to the low nibble.
        let af = Self::aux_flag_with_carry(&a, &b, cf_in.as_ref(), is_sub);
        self.emit_set_flag(ctx, FLAG_AF, af);

        // SF / ZF / PF.
        self.emit_sf_zf_pf(ctx, &result, size);

        // Write back.
        self.write_operand(iced, 0, result, ctx);
    }

    /// `CMP a, b` —" like SUB but discards the result; only flags are set.
    fn lift_cmp(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let result = self.materialise_temp(
            LlilExpr::SubT(Box::new(a.clone()), Box::new(b.clone()), size),
            size,
            ctx,
        );

        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone())),
        );
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&a, &b, &result, true));
        self.emit_set_flag(ctx, FLAG_AF, Self::aux_flag(&a, &b, true));
        self.emit_sf_zf_pf(ctx, &result, size);
    }

    /// Signed-overflow predicate for add (`is_sub == false`) or sub.
    ///
    /// add: OF = (sign(a) == sign(b)) && (sign(res) != sign(a))
    /// sub: OF = (sign(a) != sign(b)) && (sign(res) != sign(a))
    fn overflow_flag(a: &LlilExpr, b: &LlilExpr, res: &LlilExpr, is_sub: bool) -> LlilExpr {
        let size = a.result_size();
        let sa = is_negative(a.clone(), size);
        let sb = is_negative(b.clone(), size);
        let sr = is_negative(res.clone(), size);
        let same_or_diff_ab = if is_sub {
            LlilExpr::CmpNe(Box::new(sa.clone()), Box::new(sb))
        } else {
            LlilExpr::CmpEq(Box::new(sa.clone()), Box::new(sb))
        };
        let res_diff = LlilExpr::CmpNe(Box::new(sr), Box::new(sa));
        LlilExpr::And(Box::new(same_or_diff_ab), Box::new(res_diff), Size::Byte)
    }

    /// Auxiliary-carry predicate: carry/borrow out of bit 3.
    /// AF = ((a ^ b ^ res) >> 4) & 1, modelled via a low-nibble compare.
    fn aux_flag(a: &LlilExpr, b: &LlilExpr, is_sub: bool) -> LlilExpr {
        let size = a.result_size();
        let mask = LlilExpr::Const { value: 0xf, size };
        let lo_a = LlilExpr::And(Box::new(a.clone()), Box::new(mask.clone()), size);
        let lo_b = LlilExpr::And(Box::new(b.clone()), Box::new(mask), size);
        if is_sub {
            // borrow from bit 4: (a & 0xf) <u (b & 0xf)
            LlilExpr::CmpUlt(Box::new(lo_a), Box::new(lo_b))
        } else {
            // carry into bit 4: (a & 0xf) + (b & 0xf) >u 0xf
            let sum = LlilExpr::AddT(Box::new(lo_a), Box::new(lo_b), size);
            LlilExpr::CmpUgt(
                Box::new(sum),
                Box::new(LlilExpr::Const { value: 0xf, size }),
            )
        }
    }

    /// Auxiliary-carry predicate for ADC/SBB: same nibble-level full-adder
    /// carry as `aux_flag`, but additionally accounts for a carry-in.
    /// `carry-in`, `cf_in`. Falls back to `aux_flag` when `cf_in` is `None`.
    fn aux_flag_with_carry(
        a: &LlilExpr,
        b: &LlilExpr,
        cf_in: Option<&LlilExpr>,
        is_sub: bool,
    ) -> LlilExpr {
        let Some(cf_in) = cf_in else {
            return Self::aux_flag(a, b, is_sub);
        };
        let size = a.result_size();
        let mask = LlilExpr::Const { value: 0xf, size };
        let lo_a = LlilExpr::And(Box::new(a.clone()), Box::new(mask.clone()), size);
        let lo_b = LlilExpr::And(Box::new(b.clone()), Box::new(mask), size);
        if is_sub {
            // borrow = (lo_a <u lo_b) | (cf_in & (lo_a == lo_b))
            let base = LlilExpr::CmpUlt(Box::new(lo_a.clone()), Box::new(lo_b.clone()));
            let eq = LlilExpr::CmpEq(Box::new(lo_a), Box::new(lo_b));
            let carry_edge = LlilExpr::And(Box::new(cf_in.clone()), Box::new(eq), Size::Byte);
            LlilExpr::Or(Box::new(base), Box::new(carry_edge), Size::Byte)
        } else {
            // sum0 = lo_a + lo_b; carry = (sum0 >u 0xf) | (cf_in & (sum0 == 0xf))
            let sum0 = LlilExpr::AddT(Box::new(lo_a), Box::new(lo_b), size);
            let base = LlilExpr::CmpUgt(
                Box::new(sum0.clone()),
                Box::new(LlilExpr::Const { value: 0xf, size }),
            );
            let at_max = LlilExpr::CmpEq(Box::new(sum0), Box::new(LlilExpr::Const { value: 0xf, size }));
            let carry_edge = LlilExpr::And(Box::new(cf_in.clone()), Box::new(at_max), Size::Byte);
            LlilExpr::Or(Box::new(base), Box::new(carry_edge), Size::Byte)
        }
    }

    /// `INC`/`DEC dst` —" like ADD/SUB 1 but leaves CF unchanged.
    fn lift_inc_dec(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, is_dec: bool) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let one = LlilExpr::Const { value: 1, size };
        let result_expr = if is_dec {
            LlilExpr::SubT(Box::new(a.clone()), Box::new(one.clone()), size)
        } else {
            LlilExpr::AddT(Box::new(a.clone()), Box::new(one.clone()), size)
        };
        let result = self.materialise_temp(result_expr, size, ctx);

        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&a, &one, &result, is_dec));
        self.emit_set_flag(ctx, FLAG_AF, Self::aux_flag(&a, &one, is_dec));
        self.emit_sf_zf_pf(ctx, &result, size);
        self.write_operand(iced, 0, result, ctx);
    }

    /// `NEG dst` —" two's-complement negation.
    fn lift_neg(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let result = self.materialise_temp(LlilExpr::Neg(Box::new(a.clone()), size), size, ctx);

        // CF = (a != 0)
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpNe(
                Box::new(a.clone()),
                Box::new(LlilExpr::Const { value: 0, size }),
            ),
        );
        // OF set when operand is the minimum signed value (negation overflows).
        let zero = LlilExpr::Const { value: 0, size };
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&zero, &a, &result, true));
        self.emit_set_flag(ctx, FLAG_AF, Self::aux_flag(&zero, &a, true));
        self.emit_sf_zf_pf(ctx, &result, size);
        self.write_operand(iced, 0, result, ctx);
    }

    /// `MUL src` —" unsigned multiply of the accumulator by `src`.
    fn lift_mul(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 0);
        let (acc, hi) = self.acc_pair(size);
        let acc_expr = if mul_acc_alias_enabled() {
            Self::read_reg_by_name(&acc, size)
        } else {
            LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(acc.clone()),
                size,
            }
        };
        // The full unsigned product is 2×`size` wide (AMD APM vol.3 MUL:
        // "the product is stored in the double-width DX:AX / EDX:EAX /
        // RDX:RAX register pair"). Multiplying at `size` and depositing that
        // truncated value's "high half" into rdx was wrong — the high half of
        // a same-width product is always the OVERFLOW bit pattern, not the
        // real upper 64 bits. Zero-extend both operands to the double width
        // and multiply THERE, then split.
        let dbl = Self::double_size(size);
        let product = LlilExpr::MulT(
            Box::new(LlilExpr::ZeroExtend {
                expr: Box::new(acc_expr),
                from: size,
                to: dbl,
            }),
            Box::new(LlilExpr::ZeroExtend {
                expr: Box::new(src.clone()),
                from: size,
                to: dbl,
            }),
            dbl,
        );

        if size == Size::Byte {
            // AX = AL * src (already the full 16-bit product).
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("ax".to_string()),
                size: Size::Word,
                value: product,
            });
        } else {
            ctx.emit(LlilInstruction::SetRegSplit {
                high: LlilRegister::Concrete(hi),
                low: LlilRegister::Concrete(acc.clone()),
                src: product,
            });
        }
        // CF = OF = 1 iff the upper half is non-zero (i.e. the result does not
        // fit in the low half). Previously an argument-less `mul_overflow()` —
        // the same arg-less/shared-name intrinsic hazard fixed for shifts:
        // every MUL emitted an identical expression (CSE merge) and the
        // dependency on the operands was invisible. Now it carries them.
        let of = LlilExpr::Intrinsic {
            name: "mul_overflow".to_string(),
            args: vec![
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(acc),
                    size,
                },
                src,
            ],
            result_size: Size::Byte,
        };
        self.emit_set_flag(ctx, FLAG_CF, of.clone());
        self.emit_set_flag(ctx, FLAG_OF, of);
    }

    /// The width holding the full product / dividend of a MUL/DIV at `size`
    /// (one step up the size ladder: Byte→Word … QWord→OWord).
    const fn double_size(size: Size) -> Size {
        match size {
            Size::Byte => Size::Word,
            Size::Word => Size::DWord,
            Size::DWord => Size::QWord,
            _ => Size::OWord,
        }
    }

    /// `IMUL` —" handles the 1-, 2-, and 3-operand forms.
    fn lift_imul(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let count = iced.op_count();
        let size = Self::op_size(iced, 0);
        // The two multiplicands, captured for the operand-dependent overflow
        // flags below (previously `imul_overflow()` had NO args — same
        // arg-less/shared-name hazard fixed for shifts and MUL).
        let (of_a, of_b) = match count {
            1 => {
                // Single-operand: like MUL but signed — the full product is
                // DOUBLE width (see lift_mul; a same-width product's high half
                // is meaningless). Sign-extend both operands to the double
                // width and multiply there.
                let src = self.read_operand(iced, 0);
                let (acc, hi) = self.acc_pair(size);
                let acc_expr = if mul_acc_alias_enabled() {
                    Self::read_reg_by_name(&acc, size)
                } else {
                    LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(acc.clone()),
                        size,
                    }
                };
                let dbl = Self::double_size(size);
                let product = LlilExpr::MulT(
                    Box::new(LlilExpr::SignExtend {
                        expr: Box::new(acc_expr),
                        from: size,
                        to: dbl,
                    }),
                    Box::new(LlilExpr::SignExtend {
                        expr: Box::new(src.clone()),
                        from: size,
                        to: dbl,
                    }),
                    dbl,
                );
                if size == Size::Byte {
                    ctx.emit(LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("ax".to_string()),
                        size: Size::Word,
                        value: product,
                    });
                } else {
                    ctx.emit(LlilInstruction::SetRegSplit {
                        high: LlilRegister::Concrete(hi),
                        low: LlilRegister::Concrete(acc.clone()),
                        src: product,
                    });
                }
                // Also a READ (it feeds the overflow flags), so it aliases too.
                let of_acc = if mul_acc_alias_enabled() {
                    Self::read_reg_by_name(&acc, size)
                } else {
                    LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(acc),
                        size,
                    }
                };
                (of_acc, src)
            }
            2 => {
                // Two-operand IMUL keeps only the LOW half in the destination
                // (truncation to operand size is architectural), so the
                // same-width MulT is correct here.
                let a = self.read_operand(iced, 0);
                let b = self.read_operand(iced, 1);
                let result = LlilExpr::MulT(Box::new(a.clone()), Box::new(b.clone()), size);
                self.write_operand(iced, 0, result, ctx);
                (a, b)
            }
            _ => {
                // 3-operand: dst = src1 * imm
                let b = self.read_operand(iced, 1);
                let c = self.read_operand(iced, 2);
                let result = LlilExpr::MulT(Box::new(b.clone()), Box::new(c.clone()), size);
                self.write_operand(iced, 0, result, ctx);
                (b, c)
            }
        };
        let of = LlilExpr::Intrinsic {
            name: "imul_overflow".to_string(),
            args: vec![of_a, of_b],
            result_size: Size::Byte,
        };
        self.emit_set_flag(ctx, FLAG_CF, of.clone());
        self.emit_set_flag(ctx, FLAG_OF, of);
    }

    /// `DIV`/`IDIV src` —" divide the double-width accumulator by `src`,
    /// producing quotient and remainder.
    fn lift_div(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, signed: bool) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 0);
        let (acc, hi) = self.acc_pair(size);

        if size == Size::Byte {
            // AX / src â†' AL (quot), AH (rem)
            let dividend = LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("ax".to_string()),
                size: Size::Word,
            };
            // The divisor must be widened with the SIGNEDNESS OF THE DIVISION.
            // This path zero-extended unconditionally, so `idiv bl` with
            // bl = 0xFF divided by +255 instead of -1: for ax=1 the CPU yields
            // quotient -1 (al=0xFF, ah=0) and the IL yielded quotient 0 with
            // remainder 1. Hardware-confirmed. The general (16/32/64-bit) path
            // below already picks the extension by signedness — this was the
            // same operation described twice, once wrongly.
            let div_src = if signed {
                LlilExpr::SignExtend {
                    expr: Box::new(src.clone()),
                    from: Size::Byte,
                    to: Size::Word,
                }
            } else {
                LlilExpr::ZeroExtend {
                    expr: Box::new(src.clone()),
                    from: Size::Byte,
                    to: Size::Word,
                }
            };
            let (q, r) = if signed {
                (
                    LlilExpr::DivS(
                        Box::new(dividend.clone()),
                        Box::new(div_src.clone()),
                        Size::Word,
                    ),
                    LlilExpr::ModS(Box::new(dividend), Box::new(div_src), Size::Word),
                )
            } else {
                (
                    LlilExpr::DivU(
                        Box::new(dividend.clone()),
                        Box::new(div_src.clone()),
                        Size::Word,
                    ),
                    LlilExpr::ModU(Box::new(dividend), Box::new(div_src), Size::Word),
                )
            };
            // Same read-after-write hazard as the general case below: `al` and
            // `ah` ARE the two halves of `ax`, the dividend both results read,
            // so writing either one first corrupts the other's input. Stage the
            // quotient in a temporary while `ax` is still intact.
            let tmp_q = self.new_temp();
            ctx.emit(LlilInstruction::SetReg {
                dest: tmp_q.clone(),
                size: Size::Byte,
                value: LlilExpr::LowPart {
                    expr: Box::new(q),
                    to: Size::Byte,
                },
            });
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("ah".to_string()),
                size: Size::Byte,
                value: LlilExpr::LowPart {
                    expr: Box::new(r),
                    to: Size::Byte,
                },
            });
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("al".to_string()),
                size: Size::Byte,
                value: LlilExpr::RegisterRef { reg: tmp_q, size: Size::Byte },
            });
            return;
        }

        // General case: dividend = hi:lo, modelled precisely at double width:
        //   dividend = (zext(hi) << bits) | zext(lo)
        // (zero-extension of both halves is correct even for IDIV — the
        // concatenation is a pure bit-level operation; signedness only
        // matters for the division itself, at the doubled width).
        let wide = match size {
            Size::Word => Size::DWord,
            Size::DWord => Size::QWord,
            _ => Size::OWord,
        };
        let bits = match size {
            Size::Word => 16u64,
            Size::DWord => 32,
            _ => 64,
        };
        // Both halves of the dividend are IMPLICIT operands, so — built by hand
        // — they bypassed the alias tables and `eax`/`edx` became registers
        // distinct from `rax`/`rdx`. Same defect class as `cmpxchg` (see
        // `implicit_acc_alias_enabled`), which measured -221 residuals on the
        // corpus; `div`/`idiv` appear in 143 of the functions that still have
        // one.
        let (lo, hi_ref) = if div_acc_alias_enabled() {
            (
                Self::read_reg_by_name(&acc, size),
                Self::read_reg_by_name(&hi, size),
            )
        } else {
            (
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(acc.clone()),
                    size,
                },
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(hi.clone()),
                    size,
                },
            )
        };
        let dividend = LlilExpr::Or(
            Box::new(LlilExpr::ShlT(
                Box::new(LlilExpr::ZeroExtend {
                    expr: Box::new(hi_ref),
                    from: size,
                    to: wide,
                }),
                Box::new(LlilExpr::Const {
                    value: bits,
                    size: wide,
                }),
                wide,
            )),
            Box::new(LlilExpr::ZeroExtend {
                expr: Box::new(lo),
                from: size,
                to: wide,
            }),
            wide,
        );
        let wide_src = if signed {
            LlilExpr::SignExtend {
                expr: Box::new(src),
                from: size,
                to: wide,
            }
        } else {
            LlilExpr::ZeroExtend {
                expr: Box::new(src),
                from: size,
                to: wide,
            }
        };
        let (q, r) = if signed {
            (
                LlilExpr::DivS(Box::new(dividend.clone()), Box::new(wide_src.clone()), wide),
                LlilExpr::ModS(Box::new(dividend), Box::new(wide_src), wide),
            )
        } else {
            (
                LlilExpr::DivU(Box::new(dividend.clone()), Box::new(wide_src.clone()), wide),
                LlilExpr::ModU(Box::new(dividend), Box::new(wide_src), wide),
            )
        };
        // READ-AFTER-WRITE HAZARD. Both `q` and `r` read the dividend, which is
        // built from the accumulator PAIR (`acc` and `hi`). Emitting
        // `acc := q` then `hi := r` makes the remainder recompute its dividend
        // from an accumulator the first statement has ALREADY overwritten, so
        // the remainder is wrong whenever the quotient differs from the
        // original low half. Confirmed against the host CPU: `div ebx` with
        // eax=2, ebx=2 leaves edx=1 in the IL where the hardware leaves 0
        // (the IL had recomputed `1 % 2` after eax became the quotient).
        //
        // Writing `hi` first only moves the hazard, because `q` reads `hi` too.
        // So the quotient is materialised into a temporary FIRST, while both
        // halves still hold their original values.
        let tmp_q = self.new_temp();
        ctx.emit(LlilInstruction::SetReg {
            dest: tmp_q.clone(),
            size,
            value: LlilExpr::LowPart {
                expr: Box::new(q),
                to: size,
            },
        });
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(hi),
            size,
            value: LlilExpr::LowPart {
                expr: Box::new(r),
                to: size,
            },
        });
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(acc),
            size,
            value: LlilExpr::RegisterRef { reg: tmp_q, size },
        });
    }

    /// Returns `(low_acc, high_acc)` register names for the accumulator pair
    /// used by MUL/DIV at the given size.
    fn acc_pair(&self, size: Size) -> (String, String) {
        match size {
            Size::Byte => ("al".to_string(), "ah".to_string()),
            Size::Word => ("ax".to_string(), "dx".to_string()),
            Size::DWord => ("eax".to_string(), "edx".to_string()),
            _ => ("rax".to_string(), "rdx".to_string()),
        }
    }

    /// Read a register BY NAME through the same 8/16- and 32-bit aliasing that
    /// `read_operand` applies to explicit operands.
    ///
    /// Instructions with an IMPLICIT register source (`CDQE` reads `eax`, and
    /// so on) build their operand by hand, which bypassed the alias tables and
    /// left the narrow view as a register nothing ever writes.
    fn read_reg_by_name(name: &str, size: Size) -> LlilExpr {
        if high_byte_alias_enabled()
            && let Some(parent) = gpr_high_byte_parent(name)
        {
            return LlilExpr::And(
                Box::new(LlilExpr::Shr(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(parent.to_string()),
                        size: Size::QWord,
                    }),
                    Box::new(LlilExpr::Const { value: 8, size: Size::QWord }),
                    Size::QWord,
                )),
                Box::new(LlilExpr::Const { value: 0xFF, size: Size::QWord }),
                size,
            );
        }
        if let Some((parent, width)) = gpr_narrow_alias_enabled()
            .then(|| narrow_parent_aliased(name))
            .flatten()
        {
            let mask: u64 = if width == 8 { 0xFF } else { 0xFFFF };
            return LlilExpr::And(
                Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(parent.to_string()),
                    size: Size::QWord,
                }),
                Box::new(LlilExpr::Const {
                    value: mask,
                    size: Size::QWord,
                }),
                size,
            );
        }
        match gpr32_alias_enabled().then(|| gpr32_parent(name)).flatten() {
            Some(parent) => LlilExpr::LowPart {
                expr: Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(parent.to_string()),
                    size: Size::QWord,
                }),
                to: size,
            },
            None => LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(name.to_string()),
                size,
            },
        }
    }

    /// `CBW`/`CWDE`/`CDQE` —" sign-extend the accumulator in place.
    fn lift_sign_extend_acc(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let (from, to, dst) = match iced.mnemonic() {
            Mnemonic::Cbw => (Size::Byte, Size::Word, "ax"),
            Mnemonic::Cwde => (Size::Word, Size::DWord, "eax"),
            _ => (Size::DWord, Size::QWord, "rax"),
        };
        let src_reg = match from {
            Size::Byte => "al",
            Size::Word => "ax",
            _ => "eax",
        };
        // ⚠ The accumulator source is IMPLICIT, so it never passes through
        // `read_operand` and so never consulted the alias tables. Building the
        // `RegisterRef` by hand made `eax` a register of its own, distinct from
        // `rax` — and since nothing ever writes it, the HLIL emitted
        // `v8 = sub_X(); v8 = (int64_t)(int32_t)v9;` with `v9` UNDEFINED: the
        // sign extension of the call's return value was silently LOST and the
        // arithmetic after it ran on a value that does not exist. Read through
        // the same aliasing the explicit operands use.
        let src = Self::read_reg_by_name(src_reg, from);
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(dst.to_string()),
            size: to,
            value: LlilExpr::SignExtend {
                expr: Box::new(src),
                from,
                to,
            },
        });
    }

    /// `CWD`/`CDQ`/`CQO` —" sign-extend the accumulator into DX:AX / EDX:EAX /
    /// RDX:RAX.
    fn lift_sign_extend_dx(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let (size, acc, dx) = match iced.mnemonic() {
            Mnemonic::Cwd => (Size::Word, "ax", "dx"),
            Mnemonic::Cdq => (Size::DWord, "eax", "edx"),
            _ => (Size::QWord, "rax", "rdx"),
        };
        // Read through the parent so the narrow view aliases (see
        // `cdq_acc_alias_enabled`). `dx` below is a WRITE and stays as-is.
        let acc_expr = if cdq_acc_alias_enabled() {
            Self::read_reg_by_name(acc, size)
        } else {
            LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(acc.to_string()),
                size,
            }
        };
        // DX = (AX <s 0) ? -1 : 0
        let dx_val = LlilExpr::Sar(
            Box::new(acc_expr),
            Box::new(LlilExpr::Const {
                value: (size.bits() as u64) - 1,
                size,
            }),
            size,
        );
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(dx.to_string()),
            size,
            value: dx_val,
        });
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Logical handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `AND`/`OR`/`XOR dst, src`.
    fn lift_logic(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, op: LogicOp) {
        let size = Self::op_size(iced, 0);

        // Special-case the `xor reg, reg` / `sub reg, reg` zeroing idiom: when
        // both operands are the same register, XOR yields a constant zero.
        if matches!(op, LogicOp::Xor)
            && iced.op_kind(0) == OpKind::Register
            && iced.op_kind(1) == OpKind::Register
            && iced.op_register(0) == iced.op_register(1)
        {
            self.write_operand(iced, 0, LlilExpr::Const { value: 0, size }, ctx);
            self.emit_set_flag_const(ctx, FLAG_CF, 0);
            self.emit_set_flag_const(ctx, FLAG_OF, 0);
            self.emit_set_flag_const(ctx, FLAG_SF, 0);
            self.emit_set_flag_const(ctx, FLAG_ZF, 1);
            self.emit_set_flag_const(ctx, FLAG_PF, 1);
            return;
        }

        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let expr = match op {
            LogicOp::And => LlilExpr::And(Box::new(a), Box::new(b), size),
            LogicOp::Or => LlilExpr::Or(Box::new(a), Box::new(b), size),
            LogicOp::Xor => LlilExpr::Xor(Box::new(a), Box::new(b), size),
        };
        let result = self.materialise_temp(expr, size, ctx);

        // Logical ops clear CF and OF; AF is undefined (model as cleared).
        self.emit_set_flag_const(ctx, FLAG_CF, 0);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag_const(ctx, FLAG_AF, 0);
        self.emit_sf_zf_pf(ctx, &result, size);
        self.write_operand(iced, 0, result, ctx);
    }

    /// `NOT dst` —" one's-complement; no flags affected.
    fn lift_not(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        self.write_operand(iced, 0, LlilExpr::Not(Box::new(a), size), ctx);
    }

    /// `TEST a, b` —" `a & b`, discard result, set flags.
    fn lift_test(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let result = self.materialise_temp(LlilExpr::And(Box::new(a), Box::new(b), size), size, ctx);
        self.emit_set_flag_const(ctx, FLAG_CF, 0);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_sf_zf_pf(ctx, &result, size);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Shift / rotate handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// Mask a shift count the way the hardware does. AMD APM vol. 3
    /// (pub 24594 rev 3.34, Oct 2022), SAL/SHL p. 314 — and word-for-word the
    /// same on the SHR and SAR pages: "The processor masks the upper three
    /// bits of the count operand, thus restricting the count to a number
    /// between 0 and 31. When the destination is 64 bits wide, the processor
    /// masks the upper two bits of the count, providing a count in the range
    /// of 0 to 63." SHLX/SHRX/SARX state the same rule ("When the operand
    /// size is 32, bits [31:5] of shft_cnt are ignored; when the operand size
    /// is 64, bits [63:6] of shft_cnt are ignored").
    ///
    /// The mask is 5 bits for ALL sub-64-bit operand widths — an 8-bit shift
    /// by cl=0x21 really shifts by 1, and by cl=12 shifts everything out; it
    /// is NOT reduced mod the operand width. Emitting the raw count used to
    /// leave the out-of-range behaviour to whichever IL consumer evaluated
    /// the expression (interpreter, const folder, ...), each of which had its
    /// own rule and none of which matched the CPU for counts >= the width.
    fn mask_shift_count(count: LlilExpr, operand_size: Size) -> LlilExpr {
        let mask: u64 = if operand_size == Size::QWord { 0x3F } else { 0x1F };
        match count {
            LlilExpr::Const { value, size } => LlilExpr::Const { value: value & mask, size },
            other => {
                let csz = other.result_size();
                LlilExpr::And(
                    Box::new(other),
                    Box::new(LlilExpr::Const { value: mask, size: csz }),
                    csz,
                )
            }
        }
    }

    /// `SHL`/`SHR`/`SAR dst, count`.
    fn lift_shift(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, op: ShiftOp) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let count = if iced.op_count() > 1 {
            let masked = Self::mask_shift_count(self.read_operand(iced, 1), size);
            // Materialise a NON-constant masked count once: it appears in the
            // shift itself, the CF intrinsic, and every count-predicated flag
            // select — inlining the `cl & 0x3f` tree into all of them blew
            // downstream passes up quadratically (a Go corpus binary went
            // from <1 s to minutes).
            match masked {
                c @ LlilExpr::Const { .. } => c,
                other => {
                    let csz = other.result_size();
                    self.materialise_temp(other, csz, ctx)
                }
            }
        } else {
            LlilExpr::Const { value: 1, size }
        };
        // CF is a function of the shifted value and the count — capture them
        // before `expr` consumes them.
        let cf_args = vec![a.clone(), count.clone()];
        // Per-op carry name: SHL's CF is the last bit shifted out of the MSB
        // end, SHR/SAR's the last bit out of the LSB end. They are NOT the same
        // rule, so they must not share an expression.
        let cf_name = match op {
            ShiftOp::Shl => "shl_cf",
            ShiftOp::Shr => "shr_cf",
            ShiftOp::Sar => "sar_cf",
        };
        let expr = match op {
            ShiftOp::Shl => LlilExpr::ShlT(Box::new(a), Box::new(count.clone()), size),
            ShiftOp::Shr => LlilExpr::Shr(Box::new(a), Box::new(count.clone()), size),
            ShiftOp::Sar => LlilExpr::Sar(Box::new(a), Box::new(count.clone()), size),
        };
        let result = self.materialise_temp(expr, size, ctx);
        // CF holds the last bit shifted out, as a function of (value, count).
        //
        // This previously emitted `shift_carry()` — one shared name for SHL/SHR/
        // SAR, with NO ARGUMENTS — even though the comment right here said it
        // "depends on the (possibly variable) shift count". Consequences:
        // (a) the dependency on value/count was invisible to dataflow, and
        // (b) every shift in a function emitted a structurally IDENTICAL
        //     expression, so a CSE/GVN pass could merge the carry of a SHL with
        //     that of a SHR — opposite ends of the operand.
        let cf_val = LlilExpr::Intrinsic {
            name: cf_name.to_string(),
            args: cf_args,
            result_size: Size::Byte,
        };
        // APM (SAL/SHL p.314, same wording on SHR/SAR): "If the count is 0,
        // no flags are affected" — previously CF and SF/ZF/PF were written
        // unconditionally (same class as the rotate count-0 bug). A constant
        // count resolves the predicate at lift time; a variable count emits
        // the selection explicitly, keeping the OLD flag value at count 0.
        match &count {
            LlilExpr::Const { value, .. } => {
                if *value != 0 {
                    self.emit_set_flag(ctx, FLAG_CF, cf_val);
                    self.emit_sf_zf_pf(ctx, &result, size);
                }
            }
            _ => {
                let csz = count.result_size();
                let cnt_is_zero = LlilExpr::CmpEq(
                    Box::new(count.clone()),
                    Box::new(LlilExpr::Const { value: 0, size: csz }),
                );
                let keep_old = |new_val: LlilExpr, old_flag: &str| LlilExpr::CondExpr {
                    cond: Box::new(cnt_is_zero.clone()),
                    true_val: Box::new(flag(old_flag)),
                    false_val: Box::new(new_val),
                    size: Size::Byte,
                };
                self.emit_set_flag(ctx, FLAG_CF, keep_old(cf_val, FLAG_CF));
                self.emit_set_flag(
                    ctx,
                    FLAG_SF,
                    keep_old(is_negative(result.clone(), size), FLAG_SF),
                );
                self.emit_set_flag(ctx, FLAG_ZF, keep_old(is_zero(result.clone(), size), FLAG_ZF));
                self.emit_set_flag(
                    ctx,
                    FLAG_PF,
                    keep_old(
                        LlilExpr::Intrinsic {
                            name: "parity".to_string(),
                            args: vec![result.clone()],
                            result_size: Size::Byte,
                        },
                        FLAG_PF,
                    ),
                );
            }
        }
        self.write_operand(iced, 0, result, ctx);
    }

    /// `ROL`/`ROR`/`RCL`/`RCR dst, count`.
    fn lift_rotate(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, op: RotateOp) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        // The rotate count is masked exactly like a shift count (upper bits
        // dropped: 0–31, or 0–63 for 64-bit destinations) — the APM rotate
        // pages carry the same masking wording as the shift pages.
        let count = if iced.op_count() > 1 {
            let masked = Self::mask_shift_count(self.read_operand(iced, 1), size);
            // Materialise a NON-constant masked count once (see lift_shift —
            // inlining it into every flag select is quadratic downstream).
            match masked {
                c @ LlilExpr::Const { .. } => c,
                other => {
                    let csz = other.result_size();
                    self.materialise_temp(other, csz, ctx)
                }
            }
        } else {
            LlilExpr::Const { value: 1, size }
        };
        // The carry is a function of the rotated value and the count, so it must
        // be captured BEFORE `expr` consumes them.
        let cf_args = vec![a.clone(), count.clone()];
        // Per-op carry name. The four rotates do NOT share a carry rule (AMD64
        // APM vol.3): ROL sets CF to the LSB of the result, ROR to the MSB, and
        // RCL/RCR rotate the carry itself through the operand. Emitting one
        // shared `rotate_carry()` for all four claimed they were the same value.
        let cf_name = match op {
            RotateOp::Rol => "rol_cf",
            RotateOp::Ror => "ror_cf",
            RotateOp::Rcl => "rcl_cf",
            RotateOp::Rcr => "rcr_cf",
        };
        // A 1-bit ROL/ROR DEFINES OF, and the two rules are DIFFERENT (APM:
        // ROL `OF = CF-after XOR msb(result)`; ROR `OF = msb(result) XOR
        // msb-1(result)`). The RCL/RCR 1-bit OF wording has not been
        // re-verified against the APM, so those two keep the documented gap
        // rather than a guessed emission.
        let of_name = match op {
            RotateOp::Rol => Some("rol_of"),
            RotateOp::Ror => Some("ror_of"),
            RotateOp::Rcl | RotateOp::Rcr => None,
        };
        let expr = match op {
            RotateOp::Rol => {
                LlilExpr::Rol(Box::new(a.clone()), Box::new(count.clone()), size)
            }
            RotateOp::Ror => {
                LlilExpr::Ror(Box::new(a.clone()), Box::new(count.clone()), size)
            }
            // RCL/RCR rotate through carry —" modelled as an intrinsic that takes
            // the value, the count, and the incoming carry flag.
            RotateOp::Rcl => LlilExpr::Intrinsic {
                name: "rcl".to_string(),
                args: vec![a.clone(), count.clone(), flag(FLAG_CF)],
                result_size: size,
            },
            RotateOp::Rcr => LlilExpr::Intrinsic {
                name: "rcr".to_string(),
                args: vec![a.clone(), count.clone(), flag(FLAG_CF)],
                result_size: size,
            },
        };
        // Evaluate the rotate BEFORE any flag or destination write: RCL/RCR
        // consume the INCOMING carry, and the flag intrinsics reference the
        // PRE-rotate operand value. (This helper previously wrote the
        // destination first, so the CF intrinsic's arguments referenced the
        // already-rotated register — the same value/ordering class as the
        // shift lifter, which computes flags before the write.)
        let result = self.materialise_temp(expr, size, ctx);
        let cf_val = LlilExpr::Intrinsic {
            name: cf_name.to_string(),
            args: cf_args,
            result_size: Size::Byte,
        };
        let of_val = of_name.map(|n| LlilExpr::Intrinsic {
            name: n.to_string(),
            args: vec![a.clone(), count.clone()],
            result_size: Size::Byte,
        });
        // APM (ROL/ROR pages): "When the rotate count is 0, no flags are
        // affected", and OF is defined only for 1-bit rotates (undefined for
        // counts > 1 — honestly left stale, never guessed). A constant count
        // resolves the predicate at lift time; a variable count emits the
        // selection explicitly so a later `jo`/`jc` sees the dependency.
        match &count {
            LlilExpr::Const { value, .. } => {
                if *value != 0 {
                    self.emit_set_flag(ctx, FLAG_CF, cf_val);
                    if *value == 1
                        && let Some(of_val) = of_val
                    {
                        self.emit_set_flag(ctx, FLAG_OF, of_val);
                    }
                }
            }
            _ => {
                let csz = count.result_size();
                self.emit_set_flag(
                    ctx,
                    FLAG_CF,
                    LlilExpr::CondExpr {
                        cond: Box::new(LlilExpr::CmpEq(
                            Box::new(count.clone()),
                            Box::new(LlilExpr::Const { value: 0, size: csz }),
                        )),
                        true_val: Box::new(flag(FLAG_CF)),
                        false_val: Box::new(cf_val),
                        size: Size::Byte,
                    },
                );
                if let Some(of_val) = of_val {
                    self.emit_set_flag(
                        ctx,
                        FLAG_OF,
                        LlilExpr::CondExpr {
                            cond: Box::new(LlilExpr::CmpEq(
                                Box::new(count.clone()),
                                Box::new(LlilExpr::Const { value: 1, size: csz }),
                            )),
                            true_val: Box::new(of_val),
                            false_val: Box::new(flag(FLAG_OF)),
                            size: Size::Byte,
                        },
                    );
                }
            }
        }
        self.write_operand(iced, 0, result, ctx);
    }

    /// `SHLD`/`SHRD dst, src, count` —" double-precision shift.
    fn lift_double_shift(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, left: bool) {
        let size = Self::op_size(iced, 0);
        let dst = self.read_operand(iced, 0);
        let src = self.read_operand(iced, 1);
        // The shift count is masked to 0–31 (0–63 for a 64-bit destination)
        // exactly like a single shift — AMD APM SHLD/SHRD carry the same
        // masking wording. The raw count used to be passed straight into the
        // opaque intrinsic.
        let count = Self::mask_shift_count(self.read_operand(iced, 2), size);
        let name = if left { "shld" } else { "shrd" };
        let result = LlilExpr::Intrinsic {
            name: name.to_string(),
            args: vec![dst, src, count],
            result_size: size,
        };
        let result = self.materialise_temp(result, size, ctx);
        self.emit_sf_zf_pf(ctx, &result, size);
        self.write_operand(iced, 0, result, ctx);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Control-flow handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// Build the destination expression of a branch/call operand 0.
    fn branch_target(&self, iced: &IcedInstruction) -> (LlilExpr, bool) {
        match iced.op_kind(0) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => (
                LlilExpr::Const {
                    value: iced.near_branch_target(),
                    size: self.ptr_size(),
                },
                false,
            ),
            OpKind::Register => (self.read_operand(iced, 0), true),
            _ if Self::op_is_memory(iced, 0) => (self.read_operand(iced, 0), true),
            _ => (self.read_operand(iced, 0), true),
        }
    }

    /// `JMP target` (relative or indirect).
    fn lift_jmp(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let (dest, indirect) = self.branch_target(iced);
        if indirect {
            ctx.emit(LlilInstruction::JumpTo {
                dest,
                targets: vec![],
            });
        } else {
            ctx.emit(LlilInstruction::JumpDest { dest });
        }
    }

    /// `CALL target` (relative or indirect).
    fn lift_call(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let (dest, _indirect) = self.branch_target(iced);
        ctx.emit(LlilInstruction::Call(dest));
    }

    /// `RET` / `RET imm16` / `RETF`.
    fn lift_ret(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // `RET imm16` also POPS `imm16` BYTES OF ARGUMENTS (callee cleanup, the
        // stdcall convention). The immediate was being dropped — the parameter
        // was literally named `_iced` — so `ret 0x10` modelled the same stack
        // effect as a bare `ret`, and every caller-side stack-depth and
        // calling-convention inference downstream inherited the error.
        //
        // Found by grepping for parameters named `_something`: each one is a
        // documented decision to ignore an input, and where that input is the
        // instruction, every operand-derived fact is lost by construction.
        //
        // Ordering: `Ret` models the return-address pop, so the extra
        // adjustment is emitted BEFORE it (nothing after a terminator is
        // reachable). The final `rsp` is the same either way — pop-then-add and
        // add-then-pop differ only in intermediate state.
        if iced.op_count() > 0 {
            let extra = iced.immediate(0);
            if extra != 0 {
                let sp = self.sp_name().to_string();
                let asize = self.ptr_size();
                ctx.emit(LlilInstruction::SetReg {
                    dest: LlilRegister::Concrete(sp.clone()),
                    size: asize,
                    value: LlilExpr::AddT(
                        Box::new(LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete(sp),
                            size: asize,
                        }),
                        Box::new(LlilExpr::Const { value: extra, size: asize }),
                        asize,
                    ),
                });
            }
        }
        ctx.emit(LlilInstruction::Ret);
    }

    /// `LEAVE` —" `mov SP, BP; pop BP`.
    fn lift_leave(&mut self, _iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = self.ptr_size();
        let bp = match self.bits {
            16 => "bp",
            32 => "ebp",
            _ => "rbp",
        };
        // SP = BP
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(self.sp_name().to_string()),
            size,
            value: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(bp.to_string()),
                size,
            },
        });
        // pop BP
        ctx.emit(LlilInstruction::Pop {
            dest: LlilRegister::Concrete(bp.to_string()),
            size,
        });
    }

    /// `ENTER imm16, imm8` —" push BP, set up a stack frame.
    fn lift_enter(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = self.ptr_size();
        let bp = match self.bits {
            16 => "bp",
            32 => "ebp",
            _ => "rbp",
        };
        // push BP
        ctx.emit(LlilInstruction::Push {
            size,
            src: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(bp.to_string()),
                size,
            },
        });
        // BP = SP
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(bp.to_string()),
            size,
            value: LlilExpr::StackPointer(size),
        });
        // SP -= frame_size
        let frame = iced.immediate(0);
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(self.sp_name().to_string()),
            size,
            value: LlilExpr::SubT(
                Box::new(LlilExpr::StackPointer(size)),
                Box::new(LlilExpr::Const { value: frame, size }),
                size,
            ),
        });
    }

    /// `Jcc target` —" conditional branch with both static successors.
    fn lift_jcc(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, cc: ConditionCode) {
        let true_dest = Address::new(iced.near_branch_target());
        let false_dest = ctx.fall_through();
        ctx.emit(LlilInstruction::CondJump {
            cond: Self::cond_expr(cc),
            true_dest,
            false_dest,
        });
    }

    /// `LOOP`/`LOOPE`/`LOOPNE` —" decrement (E)CX and branch while non-zero.
    fn lift_loop(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = self.ptr_size();
        let cx = match self.bits {
            16 => "cx",
            32 => "ecx",
            _ => "rcx",
        };
        // CX = CX - 1
        let cx_expr = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(cx.to_string()),
            size,
        };
        let dec = LlilExpr::SubT(
            Box::new(cx_expr),
            Box::new(LlilExpr::Const { value: 1, size }),
            size,
        );
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(cx.to_string()),
            size,
            value: dec,
        });

        let cx_nonzero = LlilExpr::CmpNe(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(cx.to_string()),
                size,
            }),
            Box::new(LlilExpr::Const { value: 0, size }),
        );
        let cond = match iced.mnemonic() {
            Mnemonic::Loope => LlilExpr::And(
                Box::new(cx_nonzero),
                Box::new(LlilExpr::CmpEq(
                    Box::new(flag(FLAG_ZF)),
                    Box::new(LlilExpr::Const {
                        value: 1,
                        size: Size::Byte,
                    }),
                )),
                Size::Byte,
            ),
            Mnemonic::Loopne => LlilExpr::And(
                Box::new(cx_nonzero),
                Box::new(LlilExpr::CmpEq(
                    Box::new(flag(FLAG_ZF)),
                    Box::new(LlilExpr::Const {
                        value: 0,
                        size: Size::Byte,
                    }),
                )),
                Size::Byte,
            ),
            _ => cx_nonzero,
        };
        ctx.emit(LlilInstruction::CondJump {
            cond,
            true_dest: Address::new(iced.near_branch_target()),
            false_dest: ctx.fall_through(),
        });
    }

    /// `JCXZ`/`JECXZ`/`JRCXZ` —" branch if count register is zero.
    fn lift_jcxz(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = self.ptr_size();
        let cx = match iced.mnemonic() {
            Mnemonic::Jcxz => "cx",
            Mnemonic::Jecxz => "ecx",
            _ => "rcx",
        };
        let cond = LlilExpr::CmpEq(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(cx.to_string()),
                size,
            }),
            Box::new(LlilExpr::Const { value: 0, size }),
        );
        ctx.emit(LlilInstruction::CondJump {
            cond,
            true_dest: Address::new(iced.near_branch_target()),
            false_dest: ctx.fall_through(),
        });
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// String-operation handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// Element size of a string operation from its memory size.
    fn string_elem_size(iced: &IcedInstruction) -> Size {
        size_from_bytes(iced.memory_size().size().max(1))
    }

    /// `DF ? on_set : on_clear` — the ONE description of the direction flag
    /// every string-op lowering goes through.
    ///
    /// It exists because the crate briefly had two: the per-element path
    /// (`advance_index`) honoured DF while the `REP` path (`lift_rep_movs` /
    /// `lift_rep_stos` / `finish_rep`) ignored it entirely, so `std; rep movsb`
    /// — a real `memmove` idiom for overlapping ranges — lifted to a FORWARD
    /// copy with the pointer updates carrying the wrong sign as well. Two
    /// independently-written descriptions of one machine fact is exactly the
    /// shape that hides this class of defect, so there is now only one.
    fn df_select(&self, on_set: LlilExpr, on_clear: LlilExpr) -> LlilExpr {
        LlilExpr::CondExpr {
            cond: Box::new(LlilExpr::CmpEq(
                Box::new(flag(FLAG_DF)),
                Box::new(LlilExpr::Const {
                    value: 1,
                    size: Size::Byte,
                }),
            )),
            true_val: Box::new(on_set),
            false_val: Box::new(on_clear),
            size: self.ptr_size(),
        }
    }

    /// Advance an index register (`rsi`/`rdi`) by `+elem` or `-elem` according
    /// to the direction flag, modelled as `reg = reg + (DF ? -elem : +elem)`.
    fn advance_index(&mut self, reg: &str, elem: Size, ctx: &mut EmitCtx) {
        let asize = self.ptr_size();
        let step = elem.bytes() as u64;
        let delta = self.df_select(
            LlilExpr::Const {
                value: step.wrapping_neg(),
                size: asize,
            },
            LlilExpr::Const {
                value: step,
                size: asize,
            },
        );
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg.to_string()),
            size: asize,
            value: LlilExpr::AddT(
                Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(reg.to_string()),
                    size: asize,
                }),
                Box::new(delta),
                asize,
            ),
        });
    }

    /// Counter register name for the current bitness (`rcx`/`ecx`/`cx`).
    fn cx_name(&self) -> String {
        match self.bits {
            16 => "cx",
            32 => "ecx",
            _ => "rcx",
        }
        .to_string()
    }

    /// Byte count a `REP` string op transfers: `CX * elem`, folded to plain
    /// `CX` for byte-sized elements so the common case reads cleanly.
    fn rep_byte_count(&self, elem: Size) -> LlilExpr {
        let asize = self.ptr_size();
        let cx = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(self.cx_name()),
            size: asize,
        };
        if elem.bytes() <= 1 {
            return cx;
        }
        LlilExpr::MulT(
            Box::new(cx),
            Box::new(LlilExpr::Const {
                value: elem.bytes() as u64,
                size: asize,
            }),
            asize,
        )
    }

    /// After a `REP` string op the indices have moved by the whole transfer and
    /// the counter is drained. Modelled explicitly so code AFTER the rep reads
    /// the right `rdi`/`rsi`/`rcx`; advancing by a single element (what the
    /// non-rep path does) would leave them short by `count - 1`.
    ///
    /// The move is `DF ? reg - count : reg + count`. The direction is NOT a
    /// detail that can be defaulted away here: `std; rep movsb; cld` walks
    /// downward, and an unconditional `+ count` reports the index register
    /// `2 * count` away from where the hardware leaves it.
    fn finish_rep(&mut self, regs: &[String], count: &LlilExpr, ctx: &mut EmitCtx) {
        let asize = self.ptr_size();
        for reg in regs {
            let cur = || LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(reg.clone()),
                size: asize,
            };
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(reg.clone()),
                size: asize,
                value: self.df_select(
                    LlilExpr::SubT(Box::new(cur()), Box::new(count.clone()), asize),
                    LlilExpr::AddT(Box::new(cur()), Box::new(count.clone()), asize),
                ),
            });
        }
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(self.cx_name()),
            size: asize,
            value: LlilExpr::Const { value: 0, size: asize },
        });
    }

    /// The LOW address of a `REP` transfer that starts at `reg`.
    ///
    /// `memcpy`/`memset` describe a range by its lowest address, but a `REP`
    /// string op starts at the index register and walks in the DF direction.
    /// Going up, the low address IS the register. Going down, the range is
    /// `[reg - count + elem, reg]`, so the intrinsic must be handed
    /// `reg - count + elem` — handing it `reg` names a block that starts where
    /// the transfer ENDS and runs off the far side of it.
    fn rep_base(&self, reg: &str, count: &LlilExpr, elem: Size) -> LlilExpr {
        let asize = self.ptr_size();
        let ptr = || LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(reg.to_string()),
            size: asize,
        };
        let low = LlilExpr::AddT(
            Box::new(LlilExpr::SubT(
                Box::new(ptr()),
                Box::new(count.clone()),
                asize,
            )),
            Box::new(LlilExpr::Const {
                value: elem.bytes() as u64,
                size: asize,
            }),
            asize,
        );
        self.df_select(low, ptr())
    }

    /// `REP MOVS` —" block copy, lifted as `memcpy(rdi, rsi, rcx * elem)`.
    ///
    /// Without this the `rep` prefix was ignored and only ONE element was
    /// lifted, so `rep movsb` with `rcx = 100` decompiled to a single-byte
    /// copy — code that compiles and reads plausibly while doing the wrong
    /// thing. The intrinsic reaches the output because
    /// `LlilInstruction::Intrinsic` becomes `MlilInstruction::Call` with the
    /// name as callee, which HLIL prints as `memcpy(…)`.
    fn lift_rep_movs(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let count = self.rep_byte_count(elem);
        let (di_base, si_base) = (
            self.rep_base(&self.di_name(), &count, elem),
            self.rep_base(&self.si_name(), &count, elem),
        );
        ctx.emit(LlilInstruction::Intrinsic {
            name: "memcpy".to_string(),
            args: vec![di_base, si_base, count.clone()],
        });
        let (di, si) = (self.di_name(), self.si_name());
        self.finish_rep(&[di, si], &count, ctx);
    }

    /// `REP STOS` —" block fill, lifted as `memset(rdi, al, rcx * elem)`.
    fn lift_rep_stos(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let acc = match elem {
            Size::Byte => "al",
            Size::Word => "ax",
            Size::DWord => "eax",
            _ => "rax",
        };
        let count = self.rep_byte_count(elem);
        let di_base = self.rep_base(&self.di_name(), &count, elem);
        ctx.emit(LlilInstruction::Intrinsic {
            name: "memset".to_string(),
            args: vec![
                di_base,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(acc.to_string()),
                    size: elem,
                },
                count.clone(),
            ],
        });
        let di = self.di_name();
        self.finish_rep(&[di], &count, ctx);
    }

    /// `MOVS` —" `[rdi] = [rsi]`, then advance both indices.
    fn lift_movs(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let asize = self.ptr_size();
        let value = LlilExpr::Load {
            addr: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.si_name()),
                size: asize,
            }),
            size: elem,
        };
        ctx.emit(LlilInstruction::Store {
            addr: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.di_name()),
                size: asize,
            },
            size: elem,
            value,
        });
        let si = self.si_name();
        let di = self.di_name();
        self.advance_index(&si, elem, ctx);
        self.advance_index(&di, elem, ctx);
    }

    /// `STOS` —" `[rdi] = acc`, then advance RDI.
    fn lift_stos(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let asize = self.ptr_size();
        let acc = match elem {
            Size::Byte => "al",
            Size::Word => "ax",
            Size::DWord => "eax",
            _ => "rax",
        };
        ctx.emit(LlilInstruction::Store {
            addr: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.di_name()),
                size: asize,
            },
            size: elem,
            value: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(acc.to_string()),
                size: elem,
            },
        });
        let di = self.di_name();
        self.advance_index(&di, elem, ctx);
    }

    /// `LODS` —" `acc = [rsi]`, then advance RSI.
    fn lift_lods(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let asize = self.ptr_size();
        let acc = match elem {
            Size::Byte => "al",
            Size::Word => "ax",
            Size::DWord => "eax",
            _ => "rax",
        };
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(acc.to_string()),
            size: elem,
            value: LlilExpr::Load {
                addr: Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(self.si_name()),
                    size: asize,
                }),
                size: elem,
            },
        });
        let si = self.si_name();
        self.advance_index(&si, elem, ctx);
    }

    /// `SCAS` —" compare acc with `[rdi]`, set flags, advance RDI.
    fn lift_scas(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let asize = self.ptr_size();
        let acc = match elem {
            Size::Byte => "al",
            Size::Word => "ax",
            Size::DWord => "eax",
            _ => "rax",
        };
        let a = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(acc.to_string()),
            size: elem,
        };
        let b = LlilExpr::Load {
            addr: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.di_name()),
                size: asize,
            }),
            size: elem,
        };
        let result = self.materialise_temp(
            LlilExpr::SubT(Box::new(a.clone()), Box::new(b.clone()), elem),
            elem,
            ctx,
        );
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone())),
        );
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&a, &b, &result, true));
        self.emit_sf_zf_pf(ctx, &result, elem);
        let di = self.di_name();
        self.advance_index(&di, elem, ctx);
    }

    /// `CMPS` —" compare `[rsi]` with `[rdi]`, set flags, advance both indices.
    fn lift_cmps(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let elem = Self::string_elem_size(iced);
        let asize = self.ptr_size();
        let a = LlilExpr::Load {
            addr: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.si_name()),
                size: asize,
            }),
            size: elem,
        };
        let b = LlilExpr::Load {
            addr: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(self.di_name()),
                size: asize,
            }),
            size: elem,
        };
        let result = self.materialise_temp(
            LlilExpr::SubT(Box::new(a.clone()), Box::new(b.clone()), elem),
            elem,
            ctx,
        );
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone())),
        );
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&a, &b, &result, true));
        self.emit_sf_zf_pf(ctx, &result, elem);
        let si = self.si_name();
        let di = self.di_name();
        self.advance_index(&si, elem, ctx);
        self.advance_index(&di, elem, ctx);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Conditional move / set handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `SETcc dst` —" set the 8-bit destination to the condition result.
    fn lift_setcc(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, cc: ConditionCode) {
        let cond = Self::cond_expr(cc);
        // cond already yields 0/1 in a Byte; store it directly.
        self.write_operand(iced, 0, cond, ctx);
    }

    /// `CMOVcc dst, src` —" `dst = cond ? src : dst`.
    fn lift_cmovcc(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, cc: ConditionCode) {
        let size = Self::op_size(iced, 0);
        let cond = Self::cond_expr(cc);
        let src = self.read_operand(iced, 1);
        let dst = self.read_operand(iced, 0);
        let value = LlilExpr::CondExpr {
            cond: Box::new(cond),
            true_val: Box::new(src),
            false_val: Box::new(dst),
            size,
        };
        self.write_operand(iced, 0, value, ctx);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Flag / system / misc handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `CMC` —" complement the carry flag.
    fn lift_cmc(&mut self, ctx: &mut EmitCtx) {
        let new_cf = LlilExpr::Xor(
            Box::new(flag(FLAG_CF)),
            Box::new(LlilExpr::Const {
                value: 1,
                size: Size::Byte,
            }),
            Size::Byte,
        );
        self.emit_set_flag(ctx, FLAG_CF, new_cf);
    }

    /// `LAHF` —" load AH from the low byte of the flags.
    fn lift_lahf(&mut self, ctx: &mut EmitCtx) {
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("ah".to_string()),
            size: Size::Byte,
            value: LlilExpr::Intrinsic {
                name: "lahf".to_string(),
                args: vec![
                    flag(FLAG_SF),
                    flag(FLAG_ZF),
                    flag(FLAG_AF),
                    flag(FLAG_PF),
                    flag(FLAG_CF),
                ],
                result_size: Size::Byte,
            },
        });
    }

    /// `SAHF` —" store AH into the low flags.
    fn lift_sahf(&mut self, ctx: &mut EmitCtx) {
        let ah = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete("ah".to_string()),
            size: Size::Byte,
        };
        // Each flag = (AH >> bit) & 1, modelled per IA-32 bit layout.
        let bit = |src: &LlilExpr, n: u64| {
            LlilExpr::And(
                Box::new(LlilExpr::Shr(
                    Box::new(src.clone()),
                    Box::new(LlilExpr::Const {
                        value: n,
                        size: Size::Byte,
                    }),
                    Size::Byte,
                )),
                Box::new(LlilExpr::Const {
                    value: 1,
                    size: Size::Byte,
                }),
                Size::Byte,
            )
        };
        self.emit_set_flag(ctx, FLAG_CF, bit(&ah, 0));
        self.emit_set_flag(ctx, FLAG_PF, bit(&ah, 2));
        self.emit_set_flag(ctx, FLAG_AF, bit(&ah, 4));
        self.emit_set_flag(ctx, FLAG_ZF, bit(&ah, 6));
        self.emit_set_flag(ctx, FLAG_SF, bit(&ah, 7));
    }

    /// Emit an intrinsic instruction with no result value.
    fn lift_intrinsic_no_result(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        // An instruction WITH operands must not lose them.
        //
        // This helper used to take no `iced` at all, so it could not see the
        // operands even in principle — and 98 call sites went through it. For
        // `clflush [rbx]`, `verr [rbx]`, `fxsave [rbx]`, `cmpxchg8b [rbx]` the
        // memory operand vanished completely: neither the access nor even the
        // ADDRESS was referenced, so dead-code elimination is free to delete
        // whatever computes `rbx`.
        //
        // This is the argless-intrinsic class already recorded in memory
        // (`project-rustre-argless-intrinsic-bug-class`) reappearing in a new
        // guise: an empty `args` list silently drops operand dependencies.
        //
        // Operand-carrying forms now go through `lift_fpu_generic`, which is
        // access-aware (it asks the decoder whether a memory operand is read or
        // written). Genuinely operand-less instructions keep the previous
        // behaviour exactly.
        if iced.op_count() > 0 {
            self.lift_fpu_generic(iced, ctx, name);
            return;
        }
        ctx.emit(LlilInstruction::Intrinsic {
            name: name.to_string(),
            args: vec![],
        });
    }

    /// `RDTSC` —" EDX:EAX = timestamp counter.
    /// An instruction whose result is the `EDX:EAX` pair (`RDPMC`, `XGETBV`).
    ///
    /// Modelled as two explicit writes so the pair is visible to dependency
    /// analysis; the VALUE stays an intrinsic because the IL does not model
    /// performance counters or extended control registers.
    fn lift_edx_eax_pair(&mut self, ctx: &mut EmitCtx, name: &str) {
        for (reg, suffix) in [("eax", "lo"), ("edx", "hi")] {
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(reg.to_string()),
                size: Size::DWord,
                value: LlilExpr::Intrinsic {
                    name: format!("{name}_{suffix}"),
                    args: vec![],
                    result_size: Size::DWord,
                },
            });
        }
    }

    fn lift_rdtsc(&mut self, ctx: &mut EmitCtx) {
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("eax".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdtsc_lo".to_string(),
                args: vec![],
                result_size: Size::DWord,
            },
        });
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("edx".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdtsc_hi".to_string(),
                args: vec![],
                result_size: Size::DWord,
            },
        });
    }

    /// `RDTSCP` —" like RDTSC plus ECX = processor ID.
    fn lift_rdtscp(&mut self, ctx: &mut EmitCtx) {
        self.lift_rdtsc(ctx);
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("ecx".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdtscp_aux".to_string(),
                args: vec![],
                result_size: Size::DWord,
            },
        });
    }

    /// `RDPRU` — read the processor register selected by `ECX` into
    /// `EDX:EAX` (same fixed-register writeback shape as `RDTSC`, just a
    /// different intrinsic source).
    fn lift_rdpru(&mut self, ctx: &mut EmitCtx) {
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("eax".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdpru_lo".to_string(),
                args: vec![],
                result_size: Size::DWord,
            },
        });
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("edx".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdpru_hi".to_string(),
                args: vec![],
                result_size: Size::DWord,
            },
        });
    }

    /// `INT imm8` —" software interrupt.
    fn lift_int(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        ctx.emit(LlilInstruction::Trap {
            code: iced.immediate(0),
        });
    }

    /// `RDRAND`/`RDSEED dst` —" random into destination, sets CF=1 on success.
    fn lift_rdrand(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let name = reg_name_lower_mnemonic(iced.mnemonic());
        self.write_operand(
            iced,
            0,
            LlilExpr::Intrinsic {
                name: name.clone(),
                args: vec![],
                result_size: size,
            },
            ctx,
        );
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::Intrinsic {
                name: format!("{name}_ok"),
                args: vec![],
                result_size: Size::Byte,
            },
        );
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Stub handlers for not-yet-fully-lifted instructions
//
// These emit a single `Intrinsic` instruction tagged with the mnemonic name so
// downstream consumers can still see the effect at the right address. They are
// intentionally conservative placeholders —" semantically a no-op data-wise but
// flagged as side-effectful via the intrinsic.
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `XADD dst, src` —" atomic exchange-and-add. Stub.
    fn lift_xadd(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // XADD dst, src: tmp = dst + src; src = old dst; dst = tmp.
        // Flags exactly as ADD. (Was an effect-only intrinsic stub that
        // discarded both results.)
        let size = Self::op_size(iced, 0);
        // Materialise both originals first — the two writes below must all
        // see pre-instruction values (incl. the dst == src aliasing case).
        let a = {
            let e = self.read_operand(iced, 0);
            self.materialise_temp(e, size, ctx)
        };
        let b = {
            let e = self.read_operand(iced, 1);
            self.materialise_temp(e, size, ctx)
        };
        let result = self.materialise_temp(
            LlilExpr::AddT(Box::new(a.clone()), Box::new(b.clone()), size),
            size,
            ctx,
        );

        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::CmpUlt(Box::new(result.clone()), Box::new(a.clone())),
        );
        self.emit_set_flag(ctx, FLAG_OF, Self::overflow_flag(&a, &b, &result, false));
        self.emit_set_flag(ctx, FLAG_AF, Self::aux_flag(&a, &b, false));
        self.emit_sf_zf_pf(ctx, &result, size);

        // src gets the OLD dst, then dst gets the sum (dst write last so the
        // aliased `xadd r, r` form ends with the sum, per the SDM).
        self.write_operand(iced, 1, a, ctx);
        self.write_operand(iced, 0, result, ctx);
    }

    /// `CMPXCHG8B m64` —" atomic 8-byte compare-and-exchange. Stub.
    fn lift_cmpxchg8b(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // Delegates to the access-aware helper: this instruction HAS a
        // memory operand, and emitting `args: vec![]` dropped it
        // completely — not the access, not even the address.
        self.lift_intrinsic_writing_reported_regs(iced, ctx, "cmpxchg8b");
    }

    /// `CMPXCHG16B m128` —" atomic 16-byte compare-and-exchange. Stub.
    fn lift_cmpxchg16b(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // Delegates to the access-aware helper: this instruction HAS a
        // memory operand, and emitting `args: vec![]` dropped it
        // completely — not the access, not even the address.
        self.lift_fpu_generic(iced, ctx, "cmpxchg16b");
    }

    /// `RDMSR` — per the AMD APM vol. 3 (pub 24594 rev 3.34, "RDMSR — Read
    /// Model-Specific Register"): "Loads the contents of a 64-bit
    /// model-specific register (MSR) specified in the ECX register into
    /// registers EDX:EAX. The EDX register receives the high-order 32 bits
    /// and the EAX register receives the low order bits."
    ///
    /// Previously an effect-only stub: both writebacks were dropped, so a
    /// downstream read of EAX/EDX after RDMSR would constant-propagate the
    /// pre-RDMSR values straight across it. ECX is passed as the intrinsic
    /// argument so two RDMSRs of different MSR numbers are not CSE-mergeable
    /// (same hazard `lift_snp_rmp` documents for PVALIDATE). Same
    /// fixed-register writeback shape as `lift_rdtsc`.
    fn lift_rdmsr(&mut self, ctx: &mut EmitCtx) {
        let ecx = || LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete("ecx".to_string()),
            size: Size::DWord,
        };
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("eax".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdmsr_lo".to_string(),
                args: vec![ecx()],
                result_size: Size::DWord,
            },
        });
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("edx".to_string()),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: "rdmsr_hi".to_string(),
                args: vec![ecx()],
                result_size: Size::DWord,
            },
        });
    }

    /// `WRMSR` —" write model-specific register. Stub.
    fn lift_wrmsr(&mut self, ctx: &mut EmitCtx) {
        ctx.emit(LlilInstruction::Intrinsic {
            name: "wrmsr".to_string(),
            args: vec![],
        });
    }

    /// `XSAVE`/`XSAVE64` —" save processor extended state. Stub.
    fn lift_xsave(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // Delegates to the access-aware helper: this instruction HAS a
        // memory operand, and emitting `args: vec![]` dropped it
        // completely — not the access, not even the address.
        self.lift_fpu_generic(iced, ctx, "xsave");
    }

    /// `XRSTOR`/`XRSTOR64` —" restore processor extended state. Stub.
    fn lift_xrstor(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // Delegates to the access-aware helper: this instruction HAS a
        // memory operand, and emitting `args: vec![]` dropped it
        // completely — not the access, not even the address.
        self.lift_fpu_generic(iced, ctx, "xrstor");
    }

    /// `FXSAVE`/`FXSAVE64` —" save x87/SSE state. Stub.
    fn lift_fxsave(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // Delegates to the access-aware helper: this instruction HAS a
        // memory operand, and emitting `args: vec![]` dropped it
        // completely — not the access, not even the address.
        self.lift_fpu_generic(iced, ctx, "fxsave");
    }

    /// `FXRSTOR`/`FXRSTOR64` —" restore x87/SSE state. Stub.
    fn lift_fxrstor(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        // Delegates to the access-aware helper: this instruction HAS a
        // memory operand, and emitting `args: vec![]` dropped it
        // completely — not the access, not even the address.
        self.lift_fpu_generic(iced, ctx, "fxrstor");
    }

    /// `XLAT`/`XLATB` — per the AMD APM vol. 3 (pub 24594 rev 3.34, "XLAT —
    /// Translate Table Index"): "Uses the unsigned integer in the AL register
    /// as an offset into a table and copies the contents of the table entry
    /// at that location to the AL register. The instruction uses seg:[rBX]
    /// as the base address of the table."
    ///
    /// Previously an effect-only stub that dropped the AL writeback and the
    /// rBX/AL input dependencies. The table load itself stays an intrinsic
    /// (the segment-override case is not modelled bit-exactly), but the
    /// definition of AL and its dependence on rBX and the old AL are now
    /// recorded, so liveness/const-prop cannot carry a stale AL across it.
    fn lift_xlat(&mut self, ctx: &mut EmitCtx) {
        let (base, base_size) = match self.bits {
            64 => ("rbx", Size::QWord),
            32 => ("ebx", Size::DWord),
            _ => ("bx", Size::Word),
        };
        // `XLATB` is `AL = [RBX + AL]` — a REAL memory read from a computed
        // address, not an opaque effect. It was modelled as an intrinsic taking
        // rbx and al as arguments with NO `Load`, so the memory dependency was
        // invisible: nothing downstream knew the table was read, and the
        // memory-effect oracle flagged it as a missing load.
        //
        // The address is exactly expressible: base + zero-extended AL.
        let addr = LlilExpr::AddT(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(base.to_string()),
                size: base_size,
            }),
            Box::new(LlilExpr::ZeroExtend {
                expr: Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("al".to_string()),
                    size: Size::Byte,
                }),
                from: Size::Byte,
                to: base_size,
            }),
            base_size,
        );
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("al".to_string()),
            size: Size::Byte,
            value: LlilExpr::Load {
                addr: Box::new(addr),
                size: Size::Byte,
            },
        });
    }

    /// BCD intrinsic with one operand (AAD/AAM). Stub.
    fn lift_bcd_intrinsic(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        // The whole BCD family WRITES AX (`DAA`/`DAS` write AL; `AAA`/`AAS`/
        // `AAM`/`AAD` write AL and AH). Emitting a bare effect-only intrinsic
        // meant the IL never wrote the register at all, so a decompiler
        // believed the OLD value of AX survived and propagated a stale
        // definition downstream.
        //
        // `AAM`/`AAD` also carry an imm8 that changes the result
        // (`AAM 0x10` != `AAM 0x0A`); it was dropped because the parameter was
        // named `_iced`. These are 32-bit-only instructions, which is why the
        // 64-bit-only sweeps never saw any of this.
        let mut args = vec![LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete("ax".to_string()),
            size: Size::Word,
        }];
        for n in 0..iced.op_count() {
            args.push(self.read_operand(iced, n));
        }
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("ax".to_string()),
            size: Size::Word,
            value: LlilExpr::Intrinsic {
                name: name.to_string(),
                args,
                result_size: Size::Word,
            },
        });
    }

    /// BCD intrinsic with no operands (AAA/AAS/DAA/DAS). Stub.
    fn lift_bcd_intrinsic_noarg(&mut self, ctx: &mut EmitCtx, name: &str) {
        // Same as `lift_bcd_intrinsic` minus the immediate: AAA/AAS/DAA/DAS
        // read and write AX, so the write must be modelled or the old value
        // appears to survive.
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("ax".to_string()),
            size: Size::Word,
            value: LlilExpr::Intrinsic {
                name: name.to_string(),
                args: vec![LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("ax".to_string()),
                    size: Size::Word,
                }],
                result_size: Size::Word,
            },
        });
    }

    /// Generic FPU intrinsic: reads every explicit operand present on `iced`
    /// (register/memory/immediate — `ST(n)` decodes as a normal `Register`)
    /// and emits them as `Intrinsic` args, so downstream dataflow analysis can
    /// see which registers/memory the FPU op actually touches instead of a
    /// bare opaque name.
    fn lift_fpu_generic(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        // ACCESS-AWARE OPERANDS.
        //
        // This helper used to `read_operand` EVERY operand. For an operand the
        // ISA only WRITES — `fist [rbx]`, `fnstcw [rbx]`, `fnsave [rbx]` — that
        // produced a LOAD of a location that is never read, and NO STORE of the
        // value that is. A decompiler then sees the location as
        // read-and-never-modified: dead-store elimination is free to drop the
        // address computation, and every alias/dependency analysis gets the
        // direction of the access backwards.
        //
        // The access comes from `InstructionInfoFactory` — the decoder's own
        // instruction database — rather than a hand-maintained list of x87
        // store mnemonics, which would be a second description of the same fact
        // and would drift. Narrowed to the unambiguous case: exactly ONE memory
        // operand, which the decoder reports as write-only. Everything else
        // keeps the previous behaviour exactly.
        let mut factory = iced_x86::InstructionInfoFactory::new();
        let info = factory.info(iced);
        let mem = info.used_memory();
        // Read and write are asked SEPARATELY, because an operand can be both.
        // The first version only handled Write-only and so left `fxsave`,
        // `xsave`, `cmpxchg8b`, `rstorssp` — whose memory access iced reports as
        // ReadWrite or as several regions — with no store at all.
        let mem_writes = mem.iter().any(|m| {
            matches!(
                m.access(),
                iced_x86::OpAccess::Write
                    | iced_x86::OpAccess::CondWrite
                    | iced_x86::OpAccess::ReadWrite
                    | iced_x86::OpAccess::ReadCondWrite
            )
        });
        let mem_reads = mem.iter().any(|m| {
            matches!(
                m.access(),
                iced_x86::OpAccess::Read
                    | iced_x86::OpAccess::CondRead
                    | iced_x86::OpAccess::ReadWrite
                    | iced_x86::OpAccess::ReadCondWrite
            )
        });
        let mem_operands: Vec<u32> =
            (0..iced.op_count()).filter(|&n| Self::op_is_memory(iced, n)).collect();
        // Restricted to a SINGLE memory operand: with more than one there is no
        // unambiguous destination, and guessing is how the iteration-20
        // over-reach happened.
        let write_idx = if mem_writes && mem_operands.len() == 1 {
            Some(mem_operands[0])
        } else {
            None
        };

        // A memory operand the decoder reports NO access for supplies an
        // ADDRESS, not a value: `prefetchnta [rbx]`, `invlpg [rbx]`,
        // `bndmk bnd,[rbx]` never dereference it. Reading it would invent a
        // memory read that can fault — while passing nothing at all (the
        // previous `args: []`) would drop the dependency on `rbx` entirely.
        // Passing the ADDRESS keeps the dependency and invents no access.
        //
        // This was caught by the INVENTED-LOAD direction of the oracle, which
        // was itself missing until this iteration — and what it caught first
        // was the regression introduced by the previous iteration's own fix.
        let address_only = mem.is_empty();
        let args: Vec<LlilExpr> = (0..iced.op_count())
            // The destination operand is still READ when the access is
            // ReadWrite — dropping it there would lose a real dependency.
            .filter(|n| Some(*n) != write_idx || mem_reads)
            .map(|n| {
                if address_only && Self::op_is_memory(iced, n) {
                    self.mem_address(iced)
                } else {
                    self.read_operand(iced, n)
                }
            })
            .collect();

        if let Some(w) = write_idx {
            // The instruction produces a value into memory. Model it as a
            // STORE of the intrinsic's result, so the write is visible.
            let size = Self::op_size(iced, w);
            let value = LlilExpr::Intrinsic {
                name: name.to_string(),
                args,
                result_size: size,
            };
            self.write_operand(iced, w, value, ctx);
        } else {
            ctx.emit(LlilInstruction::Intrinsic {
                name: name.to_string(),
                args,
            });
        }
    }

    /// FPU unary/transcendental op with NO decoded operand at all (e.g.
    /// bare `FCHS`/`FABS`/`FSQRT` — `iced.op_count() == 0`) that implicitly
    /// reads and overwrites `ST(0)`. Unlike `Fld` (whose single decoded
    /// operand is a *source*, not `ST(0)`), these have no operand to
    /// misinterpret — the destination is unambiguously `ST(0)` — so we can
    /// target it directly via `reg_name(Register::ST0)` rather than routing
    /// through the operand-index-based `write_operand`.
    ///
    /// Approximation note: two-result ops (`FSINCOS` writes both `ST(1)` and
    /// `ST(0)`; `FPTAN` pushes an extra `1.0`) only get their primary
    /// `ST(0)` result modelled here, matching the existing
    /// Intrinsic-approximation precedent used elsewhere in this file for
    /// exotic multi-output instructions.
    /// x87 binary ops that write ST(1) and then pop. See the call sites for
    /// why both slots are written.
    fn lift_fpu_write_st0_and_st1(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        name: &str,
    ) {
        self.lift_fpu_write_st0(iced, ctx, name);
        let st1 = reg_name(Register::ST1);
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(st1),
            size: Size::OWord,
            value: LlilExpr::Intrinsic {
                name: format!("{name}_st1"),
                args: vec![],
                result_size: Size::OWord,
            },
        });
    }

    fn lift_fpu_write_st0(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let args: Vec<LlilExpr> = (0..iced.op_count())
            .map(|n| self.read_operand(iced, n))
            .collect();
        let value = LlilExpr::Intrinsic {
            name: name.to_string(),
            args,
            result_size: Size::OWord,
        };
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg_name(Register::ST0)),
            size: Size::OWord,
            value,
        });
    }

    /// `PCMPESTRI`/`PCMPESTRM`/`PCMPISTRI`/`PCMPISTRM` — all decoded
    /// operands are sources; the true destination is an implicit register
    /// (`ECX` for the index forms, `XMM0` for the mask forms) never
    /// represented as an operand. Same shape as `lift_fpu_write_st0`: reads
    /// every present operand into the `Intrinsic`, then writes directly to
    /// `dest_reg` via `reg_name` rather than `write_operand`'s
    /// operand-index lookup.
    fn lift_string_compare_write(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        name: &str,
        dest_reg: Register,
        dest_size: Size,
    ) {
        let args: Vec<LlilExpr> = (0..iced.op_count())
            .map(|n| self.read_operand(iced, n))
            .collect();
        let value = LlilExpr::Intrinsic {
            name: name.to_string(),
            args,
            result_size: dest_size,
        };
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg_name(dest_reg)),
            size: dest_size,
            value,
        });
    }

    /// AMD SEV-SNP RMP-management instructions (PVALIDATE / PSMASH /
    /// RMPUPDATE / RMPQUERY). These have NO explicit operands in iced's decode —
    /// they take their inputs in fixed registers — so they are easy to mistake
    /// for the effect-only privileged ops handled by `lift_intrinsic_no_result`
    /// (VMCALL, SEAMCALL, …). They are NOT: each computes a **status code into
    /// EAX** and sets flags from it, and modelling them as inert would discard
    /// everything they produce.
    ///
    /// Per the AMD64 APM vol. 3 (pub. 24594 rev 3.34), each reference page says:
    /// "Upon completion, a return code is stored in EAX. rFLAGS bits OF, ZF,
    /// AF, PF and SF are set based on this return code." The published
    /// `rFLAGS Affected` rows confirm exactly which flags move, and they are
    /// NOT uniform across the family:
    ///   - PSMASH / RMPUPDATE / RMPQUERY → `OF SF ZF AF PF` modified, **CF is
    ///     NOT touched** (row: one `M` + four `M`s).
    ///   - PVALIDATE → the same five **plus CF** (row: one `M` + five `M`s).
    ///     PVALIDATE's CF is a genuinely separate output: it reports whether
    ///     the RMP entry actually changed (`CF = 0` if the Validated bit
    ///     changed, `CF = 1` if it did not, or in a non-SNP environment).
    ///
    /// `writes_cf` therefore selects PVALIDATE's extra output.
    ///
    /// The status code and the flags derived from it are modelled as
    /// intrinsics: the manual specifies the *return codes* (SUCCESS/FAIL_INPUT/
    /// FAIL_PERMISSION/…) but not a bit-level formula mapping a code onto each
    /// flag, so inventing e.g. `ZF = (rc == 0)` would be a guess. Instead each
    /// flag reads a `<name>_<flag>` intrinsic, matching the `lift_rdrand`
    /// precedent (`CF = rdrand_ok`) — the dependency is recorded honestly
    /// without fabricating semantics the manual does not give.
    fn lift_snp_rmp(
        &mut self,
        ctx: &mut EmitCtx,
        name: &str,
        writes_cf: bool,
        extra_dests: &[(Register, Size)],
    ) {
        // PVALIDATE's inputs are fixed architectural registers (AMD SEV-SNP
        // APM): RAX = linear address of the page, ECX = page size (0 = 4KB,
        // 1 = 2MB), EDX = desired validated state (bit 0). Passing them as
        // args (rather than the arg-less form the rest of this family still
        // uses) records the real dependency, so a CSE/GVN pass sees that two
        // PVALIDATE call sites with different RAX/ECX/EDX are NOT the same
        // value — the exact hazard the shift/rotate-carry bug class was.
        // PSMASH/RMPUPDATE/RMPQUERY are deliberately left arg-less: their
        // exact operand-register roles were not independently re-verified,
        // and guessing would be worse than the documented gap.
        let pvalidate_args = || {
            vec![
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(reg_name(Register::RAX)),
                    size: Size::QWord,
                },
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(reg_name(Register::ECX)),
                    size: Size::DWord,
                },
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(reg_name(Register::EDX)),
                    size: Size::DWord,
                },
            ]
        };
        let status_args = if writes_cf { pvalidate_args() } else { vec![] };

        // EAX = status code.
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg_name(Register::EAX)),
            size: Size::DWord,
            value: LlilExpr::Intrinsic {
                name: name.to_string(),
                args: status_args.clone(),
                result_size: Size::DWord,
            },
        });
        // Any additional architectural outputs (RMPQUERY returns the permission
        // mask in RDX and the page size in RCX).
        for &(reg, size) in extra_dests {
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(reg_name(reg)),
                size,
                value: LlilExpr::Intrinsic {
                    name: format!("{name}_{}", reg_name(reg)),
                    args: vec![],
                    result_size: size,
                },
            });
        }
        // OF/SF/ZF/AF/PF from the status code — always, for all four.
        for flag in [FLAG_OF, FLAG_SF, FLAG_ZF, FLAG_AF, FLAG_PF] {
            self.emit_set_flag(
                ctx,
                flag,
                LlilExpr::Intrinsic {
                    name: format!("{name}_{flag}"),
                    args: status_args.clone(),
                    result_size: Size::Byte,
                },
            );
        }
        // CF — PVALIDATE only.
        if writes_cf {
            self.emit_set_flag(
                ctx,
                FLAG_CF,
                LlilExpr::Intrinsic {
                    name: format!("{name}_rmp_unchanged"),
                    args: status_args,
                    result_size: Size::Byte,
                },
            );
        }
    }

    /// FPU op that has an *explicit* destination operand (register or
    /// memory) in iced's decode — e.g. `FADD ST(1), ST` / `FLD m32fp` /
    /// `FCHS`-with-explicit-ST-form. Mirrors `lift_simd_write`: builds an
    /// expr-level `Intrinsic` from all present operands and writes the
    /// result to operand 0 via `write_operand`, so the computed value is no
    /// longer silently discarded the way `lift_fpu_generic` drops it.
    ///
    /// Known gap: x87's *implicit*-operand encodings (bare `FADD` meaning
    /// `ST(1) = ST(1) + ST(0); pop`, or `FLD1`/`FCHS` with no decoded
    /// register operand at all) have `op_count() == 0` and cannot be routed
    /// through `write_operand` (there is no operand-0 register/memory slot
    /// to target) — those fall back to `lift_fpu_generic`'s effect-only
    /// Intrinsic, same as before. Modelling the full x87 stack-pointer
    /// rotation for implicit forms is a separate, larger piece of work.
    fn lift_fpu_write(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        if iced.op_count() == 0 {
            self.lift_fpu_generic(iced, ctx, name);
            return;
        }
        let size = Self::op_size(iced, 0);
        let args: Vec<LlilExpr> = (0..iced.op_count())
            .map(|n| self.read_operand(iced, n))
            .collect();
        let expr = LlilExpr::Intrinsic {
            name: name.to_string(),
            args,
            result_size: size,
        };
        // A MEMORY operand 0 is a SOURCE, not the destination.
        //
        // `FADD m32fp` computes `ST(0) <- ST(0) + m32fp`: memory is read-only,
        // and the decoder agrees (`InstructionInfoFactory` reports the access as
        // `Read`). Writing the result back to operand 0 invented a store to
        // `[rbx]` that the instruction never performs — the dangerous direction
        // for a decompiler, since alias analysis then believes the location was
        // clobbered. Six mnemonics were affected: fadd/fmul/fsub/fsubr/fdiv/
        // fdivr with a memory operand.
        //
        // The REGISTER forms (`FADD ST(0), ST(i)`) genuinely do write operand 0,
        // so they keep the existing path.
        // Which it is, is decided by the DECODER, not by the operand's shape.
        // A first attempt used "operand 0 is memory ⇒ it is a source", which is
        // right for `fadd m32` and WRONG for `fst`/`fstp`/`fbstp`, whose memory
        // operand really is the destination. The ratchet in
        // `tests/memory_effects_vs_iced.rs` caught that regression on the very
        // next run — 3 new MISSING store — which is what a ratchet is for.
        let reads_only = if Self::op_is_memory(iced, 0) {
            let mut factory = iced_x86::InstructionInfoFactory::new();
            let info = factory.info(iced);
            let mem = info.used_memory();
            mem.len() == 1
                && matches!(
                    mem[0].access(),
                    iced_x86::OpAccess::Read | iced_x86::OpAccess::CondRead
                )
        } else {
            false
        };
        if reads_only {
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(reg_name(Register::ST0)),
                size: Size::OWord,
                value: expr,
            });
        } else {
            self.write_operand(iced, 0, expr, ctx);
        }
    }

    /// FPU integer binary operation (FIADD/FISUB/.../FIDIV/FIDIVR).
    fn lift_fpu_int_binop(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        // `FIADD`/`FISUB`/`FIMUL`/`FIDIV`(R) compute `ST(0) op int_memory` and
        // write the result to ST(0). Routed to the effect-only helper, the IL
        // never wrote ST(0), so the old top-of-stack appeared to survive.
        // Same shape as the `FADD m32` case fixed in iteration 20, in the
        // integer-operand corner of the same family.
        self.lift_fpu_write_st0(iced, ctx, name);
    }

    /// FPU integer compare (FICOM/FICOMP).
    fn lift_fpu_int_compare(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, pop: bool) {
        self.lift_fpu_generic(iced, ctx, if pop { "ficomp" } else { "ficom" });
    }

    /// `FILD m` —" load integer onto FPU stack.
    fn lift_fild(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        self.lift_fpu_generic(iced, ctx, "fild");
    }

    /// `FIST`/`FISTP` —" store FPU top to integer.
    fn lift_fist(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, pop: bool) {
        self.lift_fpu_generic(iced, ctx, if pop { "fistp" } else { "fist" });
    }

    /// `FISTTP` —" store FPU top to integer with truncation, pop.
    fn lift_fisttp(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        self.lift_fpu_generic(iced, ctx, "fisttp");
    }

    /// An instruction whose result lands in OPERAND 0, with the value left
    /// opaque as an intrinsic of the remaining operands.
    ///
    /// `IN al, dx` (port read), `BNDMK bnd, m`, `BNDLDX bnd, m` all have a
    /// register destination the effect-only helper never wrote, so the IL left
    /// the destination looking unchanged.
    fn lift_intrinsic_to_op0(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let size = Self::op_size(iced, 0);
        // A source memory operand the decoder reports NO access for supplies an
        // ADDRESS, not a value — `bndmk bnd,[rbx]` and `bndldx bnd,[rax+rax]`
        // never dereference it. Reading it would INVENT a load that can fault.
        // Same distinction as `lift_fpu_generic`; the memory-effect oracle's
        // INVENTED-LOAD direction caught this helper the run after it landed.
        let mut info = iced_x86::InstructionInfoFactory::new();
        let address_only = info.info(iced).used_memory().len() == 0;
        let args: Vec<LlilExpr> = (1..iced.op_count())
            .map(|n| {
                if address_only && Self::op_is_memory(iced, n) {
                    self.mem_address(iced)
                } else {
                    self.read_operand(iced, n)
                }
            })
            .collect();
        let value = LlilExpr::Intrinsic {
            name: name.to_string(),
            args,
            result_size: size,
        };
        self.write_operand(iced, 0, value, ctx);
    }

    /// Generic FPU/system intrinsic that takes a single memory operand.
    fn lift_intrinsic_mem_arg(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        self.lift_fpu_generic(iced, ctx, name);
    }

    /// `FLDCW m16` —" load FPU control word.
    fn lift_fldcw(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        self.lift_fpu_generic(iced, ctx, "fldcw");
    }

    /// `FSTCW`/`FNSTCW m16` —" store FPU control word.
    fn lift_fstcw(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        self.lift_fpu_generic(iced, ctx, "fstcw");
    }

    /// `FSTSW`/`FNSTSW` —" store FPU status word.
    fn lift_fstsw(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        self.lift_fpu_generic(iced, ctx, "fstsw");
    }

    /// FPU conditional move (`FCMOVcc ST(0), ST(i)`). The condition itself is
    /// evaluated by the caller's `cc`; the intrinsic records which flag family
    /// gated the move plus the source `ST(i)` operand.
    fn lift_fcmov(&mut self, ctx: &mut EmitCtx, cc: ConditionCode) {
        // `FCMOVcc` moves ST(i) into ST(0) when the condition holds — it WRITES
        // ST(0). A bare intrinsic left the destination unmodelled. The value
        // stays an intrinsic (the x87 stack is not modelled positionally), but
        // the WRITE is now visible to dependency analysis.
        self.write_st0_intrinsic(ctx, &format!("fcmov{cc:?}").to_ascii_lowercase());
    }

    /// Write `ST(0)` with an opaque intrinsic of the given name, reading the
    /// current ST(0) so the dependency is not lost either.
    fn write_st0_intrinsic(&mut self, ctx: &mut EmitCtx, name: &str) {
        let st0 = reg_name(Register::ST0);
        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(st0.clone()),
            size: Size::OWord,
            value: LlilExpr::Intrinsic {
                name: name.to_string(),
                args: vec![LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(st0),
                    size: Size::OWord,
                }],
                result_size: Size::OWord,
            },
        });
    }

    /// `FCMOVU` —" FPU conditional move if PF=1.
    fn lift_fcmov_pf(&mut self, ctx: &mut EmitCtx) {
        // See `lift_fcmov`: `FCMOVU` also writes ST(0).
        self.write_st0_intrinsic(ctx, "fcmovu");
    }

    /// `FCMOVNU` —" FPU conditional move if PF=0.
    fn lift_fcmov_npf(&mut self, ctx: &mut EmitCtx) {
        // See `lift_fcmov`: `FCMOVNU` also writes ST(0). Iteration 29 fixed
        // `lift_fcmov` and `lift_fcmov_pf` and missed this one, two lines
        // below its own twin — the "look for PAIRS, not bugs" criterion.
        self.write_st0_intrinsic(ctx, "fcmovnu");
    }

    /// Effect-only intrinsic that nevertheless writes registers the ISA
    /// defines implicitly: the VIA PadLock bulk-crypto family (`XCRYPT*`,
    /// `XSHA*`, `XSTORE`, `CCS_*`, `MONTMUL`) consumes ECX and advances
    /// ESI/EDI, `CMPXCHG8B` loads EDX:EAX on failure, `ENCLV` returns in
    /// EAX/EBX/ECX/EDX, `FRSTOR` restores the whole x87/MMX file, and the wide
    /// key-locker forms write ZMM0-7.
    ///
    /// None of those values are computable here — they are data-dependent, or
    /// the crypto itself. But "which architectural registers are written" IS
    /// knowable, and it is the fact dependency analysis needs: a write the IL
    /// omits makes a decompiler believe the OLD VALUE SURVIVES.
    ///
    /// The register list is taken from `InstructionInfoFactory`, never
    /// hand-written — one helper covers seven families and stays correct if a
    /// future decoder revision adds an implicit operand. Read registers become
    /// the intrinsic's arguments so the dependency on ECX/ESI/EDI is kept and
    /// two different call sites are not CSE-mergeable.
    /// Write the registers the decoder reports as written, SKIPPING operand 0.
    ///
    /// For gather and scatter the per-lane data movement is already modelled
    /// properly (real `Load`s / `Store`s and a real destination write); what was
    /// missing is the architectural side effect that the ISA defines and that
    /// real code depends on: **the mask register is zeroed as lanes complete**.
    /// A gather loop retries while the mask is non-zero, so an unmodelled mask
    /// clear leaves a decompiler believing the mask never changes.
    ///
    /// Operand 0 is skipped so the opaque intrinsic does not clobber the
    /// destination value the caller has already computed properly.
    fn write_reported_regs_except_op0(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        name: &str,
    ) {
        let dest = if iced.op_count() > 0 { iced.op0_register() } else { Register::None };
        let mut factory = iced_x86::InstructionInfoFactory::new();
        let info = factory.info(iced);
        let writes: Vec<Register> = info
            .used_registers()
            .iter()
            .filter(|u| {
                matches!(
                    u.access(),
                    iced_x86::OpAccess::Write
                        | iced_x86::OpAccess::ReadWrite
                        | iced_x86::OpAccess::CondWrite
                        | iced_x86::OpAccess::ReadCondWrite
                )
            })
            .map(iced_x86::UsedRegister::register)
            .filter(|r| *r != dest && r.full_register() != dest.full_register())
            .collect();
        for reg in writes {
            let size = size_from_bytes(reg.size());
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(reg_name(reg)),
                size,
                value: LlilExpr::Intrinsic {
                    name: format!("{name}_{}", reg_name(reg)),
                    args: vec![],
                    result_size: size,
                },
            });
        }
    }

    fn lift_intrinsic_writing_reported_regs(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        name: &str,
    ) {
        // MEMORY effects first, through the access-aware path. `FRSTOR` READS
        // its 108-byte image and `CMPXCHG8B` conditionally WRITES its operand;
        // routing them here instead of there would have traded a missing
        // register write for a missing memory access — the exact swap that
        // iterations 21 and 30 made. This helper is ADDITIVE by construction,
        // so both oracles stay satisfied.
        self.lift_fpu_generic(iced, ctx, name);

        let mut factory = iced_x86::InstructionInfoFactory::new();
        let info = factory.info(iced);

        // Registers this IL models through dedicated nodes (Push/Ret/Jump) or
        // not at all are out of scope, exactly as in the oracle.
        let in_scope = |r: Register| {
            !r.is_segment_register()
                && !format!("{r:?}").starts_with("CR")
                && !format!("{r:?}").starts_with("DR")
                && !format!("{r:?}").starts_with("TR")
                && !matches!(
                    r,
                    Register::RIP | Register::EIP | Register::RSP | Register::ESP | Register::SP
                )
        };

        let args: Vec<LlilExpr> = info
            .used_registers()
            .iter()
            .filter(|u| {
                matches!(u.access(), iced_x86::OpAccess::Read | iced_x86::OpAccess::ReadWrite | iced_x86::OpAccess::CondRead)
                    && in_scope(u.register())
            })
            .map(|u| LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(reg_name(u.register())),
                size: size_from_bytes(u.register().size()),
            })
            .collect();

        for u in info.used_registers() {
            if !matches!(
                u.access(),
                iced_x86::OpAccess::Write
                    | iced_x86::OpAccess::ReadWrite
                    | iced_x86::OpAccess::CondWrite
                    | iced_x86::OpAccess::ReadCondWrite
            ) || !in_scope(u.register())
            {
                continue;
            }
            let reg = u.register();
            let size = size_from_bytes(reg.size());
            ctx.emit(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(reg_name(reg)),
                size,
                value: LlilExpr::Intrinsic {
                    name: format!("{name}_{}", reg_name(reg)),
                    args: args.clone(),
                    result_size: size,
                },
            });
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Bit-manipulation handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `BSF`/`BSR dst, src` —" bit scan; ZF set when source is zero.
    fn lift_bit_scan(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, reverse: bool) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let name = if reverse { "bsr" } else { "bsf" };
        // ZF = (src == 0)
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(src.clone(), size));
        self.write_operand(
            iced,
            0,
            LlilExpr::Intrinsic {
                name: name.to_string(),
                args: vec![src],
                result_size: size,
            },
            ctx,
        );
    }

    /// Reduce a `BT`/`BTS`/`BTR`/`BTC` bit offset MODULO the operand size.
    ///
    /// Intel SDM vol.2, BT: "If the bit base operand specifies a register, the
    /// instruction takes the modulo 16, 32, or 64 of the bit offset operand"
    /// (AMD APM vol.3 BT is identical). So the mask is `size.bits() - 1`:
    /// 0x0F at 16 bits, 0x1F at 32, 0x3F at 64.
    ///
    /// This is deliberately NOT [`Self::mask_shift_count`]. The two rules look
    /// alike and are opposite below 32 bits: shifts mask with a FIXED 5 bits at
    /// every sub-64-bit width (APM: `shl bl, 0x21` shifts by 1, NOT by 1 mod 8),
    /// while bit-test genuinely is mod-width. Reusing the shift helper would
    /// mask `bt ax, cx` with 0x1F and leave cx = 17 testing bit 17 of a 16-bit
    /// register instead of bit 1.
    ///
    /// Only the REGISTER bit-base form is masked; with a memory bit base the
    /// offset is an unbounded signed bit-string index (which additionally needs
    /// the effective address adjusted by offset/8 — a separate, documented gap).
    fn mask_bit_offset(offset: LlilExpr, operand_size: Size) -> LlilExpr {
        let mask = (operand_size.bits() as u64).saturating_sub(1);
        match offset {
            LlilExpr::Const { value, size } => LlilExpr::Const { value: value & mask, size },
            other => {
                let csz = other.result_size();
                LlilExpr::And(
                    Box::new(other),
                    Box::new(LlilExpr::Const { value: mask, size: csz }),
                    csz,
                )
            }
        }
    }

    /// `BT`/`BTS`/`BTR`/`BTC` —" test (and optionally modify) a bit; CF gets it.
    fn lift_bit_test(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, m: Mnemonic) {
        let size = Self::op_size(iced, 0);
        let base = self.read_operand(iced, 0);
        let bit = self.read_operand(iced, 1);
        // Register bit-base: the offset is taken modulo the operand size. Left
        // raw, an out-of-range offset (`bt eax, ecx` with ecx = 32) reached the
        // IL as a shift by 32, which every consumer that zeroes out-of-range
        // shifts evaluates to CF = 0 — hardware gives CF = bit 0. A following
        // `jc` was then structured as the wrong branch.
        let bit = if iced.op_kind(0) == OpKind::Register {
            Self::mask_bit_offset(bit, size)
        } else {
            bit
        };
        // CF = (base >> bit) & 1
        let cf = LlilExpr::And(
            Box::new(LlilExpr::Shr(
                Box::new(base.clone()),
                Box::new(bit.clone()),
                size,
            )),
            Box::new(LlilExpr::Const { value: 1, size }),
            size,
        );
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::LowPart {
                expr: Box::new(cf),
                to: Size::Byte,
            },
        );

        let mask = LlilExpr::ShlT(
            Box::new(LlilExpr::Const { value: 1, size }),
            Box::new(bit),
            size,
        );
        let new_val = match m {
            Mnemonic::Bts => Some(LlilExpr::Or(Box::new(base), Box::new(mask), size)),
            Mnemonic::Btr => Some(LlilExpr::And(
                Box::new(base),
                Box::new(LlilExpr::Not(Box::new(mask), size)),
                size,
            )),
            Mnemonic::Btc => Some(LlilExpr::Xor(Box::new(base), Box::new(mask), size)),
            _ => None,
        };
        if let Some(v) = new_val {
            self.write_operand(iced, 0, v, ctx);
        }
    }

    /// `BSWAP dst` —" byte-swap.
    fn lift_bswap(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        // Concrete byte permutation (was an opaque intrinsic):
        //   result = Σ_i ((a >> 8i) & 0xFF) << 8(N-1-i)
        let n = size.bytes() as u64;
        let mut acc = LlilExpr::Const { value: 0, size };
        for i in 0..n {
            let byte_i = LlilExpr::And(
                Box::new(LlilExpr::Shr(
                    Box::new(a.clone()),
                    Box::new(LlilExpr::Const { value: 8 * i, size }),
                    size,
                )),
                Box::new(LlilExpr::Const { value: 0xFF, size }),
                size,
            );
            let placed = LlilExpr::ShlT(
                Box::new(byte_i),
                Box::new(LlilExpr::Const { value: 8 * (n - 1 - i), size }),
                size,
            );
            acc = LlilExpr::Or(Box::new(acc), Box::new(placed), size);
        }
        self.write_operand(iced, 0, acc, ctx);
    }

    /// `POPCNT`/`LZCNT`/`TZCNT dst, src` —" count bits; ZF set when src is zero.
    fn lift_unary_intrinsic_with_zf(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        name: &str,
    ) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(src.clone(), size));
        self.write_operand(
            iced,
            0,
            LlilExpr::Intrinsic {
                name: name.to_string(),
                args: vec![src],
                result_size: size,
            },
            ctx,
        );
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// SSE / MMX data-move handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// Lift a vector / scalar SSE-MMX data move (`MOVAPS`, `MOVDQA`, `MOVD`,
    /// `MOVQ`, —¦).
    ///
    /// These are modelled as straight copies (register/memory) at the operand
    /// width. `MOVD`/`MOVQ` between a GPR and a vector register involve a width
    /// mismatch, which is preserved by the per-operand sizing.
    fn lift_vector_move(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, _m: Mnemonic) {
        if iced.op_count() < 2 {
            ctx.emit(LlilInstruction::Nop);
            return;
        }
        let dst_size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let src_size = src.result_size();

        // Adjust width between GPR and vector operands when they differ.
        let value = if src_size.bytes() < dst_size.bytes() {
            LlilExpr::ZeroExtend {
                expr: Box::new(src),
                from: src_size,
                to: dst_size,
            }
        } else if src_size.bytes() > dst_size.bytes() {
            LlilExpr::LowPart {
                expr: Box::new(src),
                to: dst_size,
            }
        } else {
            src
        };
        // Applies EVEX opmask semantics when present (e.g. `VMOVAPS
        // zmm0{k1}{z}, zmm1`); a no-op for plain SSE/VEX moves, which have
        // no opmask register.
        let value = self.apply_evex_mask(iced, value, dst_size);
        self.write_operand(iced, 0, value, ctx);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// AVX / AVX2 (VEX-encoded) SIMD handlers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
//
// The VEX/EVEX operand shapes are modelled at the `LlilExpr`/`Size` level
// used throughout this file rather than through `simd_lifter.rs`'s
// `SimdILEmitter`, which targets a *different* IR
// (`rustre_il_lift::{Effect, IrExpr}`).
//
// ⚠ The reason is NOT that the two IRs are unbridgeable — an earlier version
// of this comment claimed exactly that, and it was FALSE: the converter
// `rustre_il_llil::lift_effect_to_llil_instr` (rustre-il-llil/src/lib.rs,
// `Effect` -> `LlilInstruction`) exists, is unit-tested, and is now actually
// used by the terminal arm of `dispatch_fallback` behind
// `RUSTRE_X86_IL_LIFT_FALLBACK`. Leaving the false claim in place is what kept
// this front closed session after session.
//
// The REAL limitation, and the reason the delegation is confined to the
// fallback instead of replacing these arms, is a loss of width: `IrExpr` does
// not carry a `Size`, so the bridge assumes `Size::QWord` for every operand.
// For the arms below — whose whole content is exact 128/256/512-bit operand
// sizing — that would be a fidelity REGRESSION, not a refactor.
// `Size` now has exact 256-bit (`Size::YWord`) and 512-bit
// (`Size::ZWord`) variants, so VEX.256 (YMM) and EVEX.512 (ZMM) operands are
// modelled at their full width via `op_size`/`reg_size`/`size_from_bytes`;
// VEX.128 (XMM) forms of the same mnemonics still use `Size::OWord`.

/// Binary operator for 3-operand VEX arithmetic/logic instructions
/// (`VADDPS dst, src1, src2` etc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VexBinOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Andn,
}

/// Operand-permutation suffix for FMA3 instructions (`VFMADD132xx` /
/// `VFMADD213xx` / `VFMADD231xx`). Per the Intel SDM, with iced operand
/// indices `op0` = dest (also `src1`, read before being overwritten),
/// `op1` = `src2`, `op2` = `src3`:
///
/// - `132`: `dst = op0(before) * op2 + op1`  (dst*src3 + src2)
/// - `213`: `dst = op1 * op0(before) + op2`  (src2*dst + src3)
/// - `231`: `dst = op1 * op2 + op0(before)`  (src2*src3 + dst)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fma3Suffix {
    S132,
    S213,
    S231,
}

/// Which fused multiply-add family to lift (`VFMADD`/`VFMSUB`/`VFNMADD`/
/// `VFNMSUB`), i.e. the sign applied to the product and/or the addend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FmaVariant {
    /// `+(a*b) + c`
    Madd,
    /// `+(a*b) - c`
    Msub,
    /// `-(a*b) + c`
    Nmadd,
    /// `-(a*b) - c`
    Nmsub,
}

impl X86Lifter {
    /// `VMOVAPS`/`VMOVUPS`/`VMOVAPD`/`VMOVUPD dst, src` — vector move, 2- or
    /// 3-operand VEX form (`vmovaps ymm0, ymm1` or `vmovaps ymm0, [mem]`).
    fn lift_vex_move(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        self.lift_vector_move(iced, ctx, iced.mnemonic());
    }

    /// 3-operand VEX arithmetic/logic: `dst = src1 OP src2`.
    ///
    /// Falls back to the 2-operand form (`dst = dst OP src`) when only two
    /// operands are present (some encodings / disassembly listings elide the
    /// destination-is-also-source1 operand).
    fn lift_vex_binop(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, op: VexBinOp) {
        let size = Self::op_size(iced, 0);
        // The SSE/AVX zeroing idiom, exactly as the integer path already models
        // it for `xor reg, reg` (see the `LogicOp::Xor` special case): XOR of a
        // register with ITSELF is a constant zero and has NO input dependency —
        // every x86 implementation special-cases it. Without this, `xorps
        // %xmm15,%xmm15` lifted to `var_xmm15 = var_xmm15 ^ var_xmm15`, i.e. a
        // read of an undefined local. Measured: 275 of B's 485 defective SSE
        // locals were this single idiom, 57% of the class. Go's ABI keeps X15
        // as its zero register, so it recurs in every function.
        //
        // Both the 2-operand (SSE) and 3-operand (VEX `vxorps dst, a, b`) forms
        // are covered: for VEX the SOURCES are operands 1 and 2.
        if matches!(op, VexBinOp::Xor) {
            let (i, j) = if iced.op_count() >= 3 { (1, 2) } else { (0, 1) };
            if iced.op_kind(i) == OpKind::Register
                && iced.op_kind(j) == OpKind::Register
                && iced.op_register(i) == iced.op_register(j)
            {
                let zero = LlilExpr::Const { value: 0, size };
                let zero = self.apply_evex_mask(iced, zero, size);
                self.write_operand(iced, 0, zero, ctx);
                return;
            }
        }
        let (a, b) = if iced.op_count() >= 3 {
            (self.read_operand(iced, 1), self.read_operand(iced, 2))
        } else {
            (self.read_operand(iced, 0), self.read_operand(iced, 1))
        };
        let expr = match op {
            VexBinOp::Add => LlilExpr::AddT(Box::new(a), Box::new(b), size),
            VexBinOp::Sub => LlilExpr::SubT(Box::new(a), Box::new(b), size),
            VexBinOp::Mul => LlilExpr::MulT(Box::new(a), Box::new(b), size),
            VexBinOp::Div => LlilExpr::DivU(Box::new(a), Box::new(b), size),
            VexBinOp::And => LlilExpr::And(Box::new(a), Box::new(b), size),
            VexBinOp::Or => LlilExpr::Or(Box::new(a), Box::new(b), size),
            VexBinOp::Xor => LlilExpr::Xor(Box::new(a), Box::new(b), size),
            VexBinOp::Andn => LlilExpr::And(
                Box::new(LlilExpr::Not(Box::new(a), size)),
                Box::new(b),
                size,
            ),
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }

    /// `VPSHUFB dst, src1, src2` — byte shuffle; modelled as an intrinsic
    /// since it needs per-byte selection logic outside this IR's expression
    /// grammar.
    fn lift_vex_pshufb(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let (a, b) = if iced.op_count() >= 3 {
            (self.read_operand(iced, 1), self.read_operand(iced, 2))
        } else {
            (self.read_operand(iced, 0), self.read_operand(iced, 1))
        };
        let expr = LlilExpr::Intrinsic {
            name: "pshufb".to_string(),
            args: vec![a, b],
            result_size: size,
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }

    /// Generic legacy-SSE/SSE2 handler that computes an
    /// [`LlilExpr::Intrinsic`] over *all* of the instruction's operands
    /// (mirroring the exact semantic inputs the real hardware instruction
    /// reads) and writes the result back into operand 0.
    ///
    /// This is the writeback-producing counterpart to `lift_fpu_generic`:
    /// `lift_fpu_generic` emits a statement-level `Intrinsic` with no result,
    /// which is correct for the x87 stack (where there is no explicit
    /// register operand to write) but silently drops the result for SSE
    /// instructions that *do* have an explicit destination operand — e.g.
    /// `CVTSS2SD xmm0, xmm1` has to actually write the converted value into
    /// `xmm0`. Used for shuffles/unpacks/compares/min-max/sqrt/conversions/
    /// movmsk etc. where the destination is operand 0.
    fn lift_simd_write(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let size = Self::op_size(iced, 0);
        let args: Vec<LlilExpr> = (0..iced.op_count())
            .map(|n| self.read_operand(iced, n))
            .collect();
        // ⚠ #6040, gate opt-in `RUSTRE_SIMD_MNEMONIC`: i nomi di FAMIGLIA
        // perdono quale istruzione fosse. `cvt` da solo copre **SEDICI**
        // conversioni (`:1821-1838`), fra cui `Cvtsi2sd` (intero→double) e
        // `Cvttsd2si` (double→intero troncato), che sono OPPOSTE; `movhl`
        // copre Movhps/Movlps/Movhpd/Movlpd.
        // Finche' il nome e' la famiglia, dare all'intrinseco un corpo sarebbe
        // corretto in 1 caso su 16 ⇒ codice **confidently wrong**. Col
        // mnemonico ciascuno puo' avere il corpo giusto.
        // ⚠ Tocca ENTRAMBI i path ⇒ opt-in, e #28 va riverificato.
        let name: String = if !matches!(std::env::var("RUSTRE_SIMD_MNEMONIC").as_deref(), Ok("0") | Ok("false")) {
            format!("{:?}", iced.mnemonic()).to_ascii_lowercase()
        } else {
            name.to_string()
        };
        let expr = LlilExpr::Intrinsic {
            name,
            args,
            result_size: size,
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }

    /// `SQRT{PS,PD,SS,SD} dst, src` — the destination is NOT an input here:
    /// `dst = sqrt(src)`. Routing these through `lift_simd_write`, which passes
    /// EVERY operand, emitted `sqrt(dst, src)`.
    ///
    /// That mattered more than it looks. Most emitted intrinsic names (`min`,
    /// `max`, `blend`, …) are unknown to the C compiler, so an extra argument
    /// is accepted as an implicit declaration — `min` is emitted with two
    /// arguments 17 times and compiles fine. `sqrt` instead collides with a
    /// **gcc builtin of arity 1**, so the extra argument is a hard error
    /// (`too many arguments to function 'sqrt'`) — it was the LAST fixed-list
    /// recompilability failure (#370, 2 occurrences in 2 files).
    ///
    /// ⚠ Deliberately NOT a general "drop operand 0" rule: for `ADDSD` and
    /// friends the destination really is read, and dropping it would silently
    /// change the semantics.
    fn lift_simd_unary(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let size = Self::op_size(iced, 0);
        // The source is the LAST operand: two-operand SSE (`sqrtsd dst, src`)
        // and three-operand VEX both put it there.
        let src = self.read_operand(iced, iced.op_count().saturating_sub(1));
        let expr = LlilExpr::Intrinsic {
            name: name.to_string(),
            args: vec![src],
            result_size: size,
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }

    /// `COMISS`/`COMISD`/`UCOMISS`/`UCOMISD dst, src` — scalar floating-point
    /// compare that sets `ZF`/`PF`/`CF` from the ordered/unordered relation
    /// between `dst` and `src` (mirroring integer `CMP`'s flag-only, no
    /// writeback contract) and clears `OF`/`SF`/`AF`. There's no native
    /// float-compare primitive in this IR, so — like `mul_overflow` above —
    /// the three-way relation is modelled via `Intrinsic` placeholders that
    /// downstream analyses can special-case.
    fn lift_comi(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let mk = |flag: &str| LlilExpr::Intrinsic {
            name: format!("{name}_{flag}"),
            args: vec![a.clone(), b.clone()],
            result_size: Size::Byte,
        };
        self.emit_set_flag(ctx, FLAG_ZF, mk("zf"));
        self.emit_set_flag(ctx, FLAG_PF, mk("pf"));
        self.emit_set_flag(ctx, FLAG_CF, mk("cf"));
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag_const(ctx, FLAG_SF, 0);
        self.emit_set_flag_const(ctx, FLAG_AF, 0);
    }

    /// `PTEST`/`VPTEST dst, src` — flag-only bitwise test: `ZF = ((dst & src)
    /// == 0)`, `CF = ((dst & ~src) == 0)`, no register/memory writeback
    /// (unlike `lift_comi`, which models ordered/unordered float compares —
    /// PTEST is a pure integer AND-based test with different flag
    /// semantics, so it gets its own helper rather than reusing `lift_comi`).
    fn lift_ptest(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let and_expr = LlilExpr::Intrinsic {
            name: "ptest_and".to_string(),
            args: vec![a.clone(), b.clone()],
            result_size: size,
        };
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(and_expr, size));
        let andn_expr = LlilExpr::Intrinsic {
            name: "ptest_andn".to_string(),
            args: vec![a, b],
            result_size: size,
        };
        self.emit_set_flag(ctx, FLAG_CF, is_zero(andn_expr, size));
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag_const(ctx, FLAG_SF, 0);
        self.emit_set_flag_const(ctx, FLAG_AF, 0);
        self.emit_set_flag_const(ctx, FLAG_PF, 0);
    }

    /// `KORTESTB/W/D/Q dst, src` — flag-only k-register test: `ZF = ((dst |
    /// src) == 0)`, `CF = ((dst | src) == all-ones)`, no writeback. Distinct
    /// from `lift_ptest`'s AND/ANDN formula (PTEST/KTEST), so it gets its
    /// own helper.
    fn lift_kortest(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 0);
        let b = self.read_operand(iced, 1);
        let or_expr = LlilExpr::Intrinsic {
            name: "kortest_or".to_string(),
            args: vec![a, b],
            result_size: size,
        };
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(or_expr.clone(), size));
        let all_ones = LlilExpr::Const {
            value: match size {
                Size::Byte => 0xFF,
                Size::Word => 0xFFFF,
                Size::DWord => 0xFFFF_FFFF,
                _ => u64::MAX,
            },
            size,
        };
        self.emit_set_flag(ctx, FLAG_CF, LlilExpr::CmpEq(Box::new(or_expr), Box::new(all_ones)));
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag_const(ctx, FLAG_SF, 0);
        self.emit_set_flag_const(ctx, FLAG_AF, 0);
        self.emit_set_flag_const(ctx, FLAG_PF, 0);
    }

    /// VSIB gather: `VGATHERDPS`/`VGATHERDPD`/`VGATHERQPS`/`VGATHERQPD`/
    /// `VPGATHERDD`/`VPGATHERDQ`/`VPGATHERQD`/`VPGATHERQQ`.
    ///
    /// `dest_elem`/`index_elem` are the per-lane sizes of the destination
    /// and VSIB index vector (dword/qword each); the number of lanes `N` is
    /// derived from the destination vector width (`op_size(iced, 0)`) so
    /// that mismatched index/dest widths (e.g. `VPGATHERQD`: qword index,
    /// dword dest) only consume as many index lanes as there are dest
    /// lanes, matching the SDM.
    ///
    /// For each lane `i` this emits: extract index lane `i` from the VSIB
    /// index register (`Shr` + `LowPart`), sign-extend and scale/add
    /// base+disp to build the per-lane address (mirroring `mem_address`),
    /// `Load` that address, and select it (vs. the destination's prior
    /// lane, for merging-masking) via a `CondExpr` gated on the mask lane —
    /// an EVEX `k`-register bit if `op_mask()` names a real k-register,
    /// else (VEX form) the corresponding lane's MSB in the full-vector VEX
    /// mask register operand. Lane results are folded back with `Shl`+`Or`
    /// into one `SetReg` of the whole destination register.
    fn lift_vex_gather(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        dest_elem: Size,
        index_elem: Size,
    ) {
        let dest_size = Self::op_size(iced, 0);
        let dest_reg = iced.op_register(0);
        let index_reg = iced.memory_index();
        let base_reg = iced.memory_base();
        let scale = u64::from(iced.memory_index_scale());
        let disp = iced.memory_displacement64();
        let asize = self.ptr_size();

        if index_reg == Register::None {
            // Malformed/unexpected encoding — fall back to the honest
            // effect-only path rather than emitting a bogus address.
            self.lift_fpu_generic(iced, ctx, "vgather");
            return;
        }

        let dest_elem_bits = dest_elem.bits() as u64;
        let n_lanes = dest_size.bytes() / dest_elem.bytes();
        let index_full_size = reg_size(index_reg);
        let dest_full_size = dest_size;

        // EVEX (k-register) vs VEX (full-vector-register) mask.
        let k = iced.op_mask();
        let use_evex_k = k != Register::None;
        let vex_mask_reg = if use_evex_k {
            Register::None
        } else if iced.op_count() >= 3 {
            iced.op_register(iced.op_count() - 1)
        } else {
            Register::None
        };

        let mut acc = LlilExpr::Const {
            value: 0,
            size: dest_full_size,
        };

        for lane in 0..n_lanes as u64 {
            // ── per-lane dynamic address: base + sext(index[lane])*scale + disp
            let idx_shr = LlilExpr::Shr(
                Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(reg_name(index_reg)),
                    size: index_full_size,
                }),
                Box::new(LlilExpr::Const {
                    value: lane * index_elem.bits() as u64,
                    size: index_full_size,
                }),
                index_full_size,
            );
            let idx_lane = LlilExpr::LowPart {
                expr: Box::new(idx_shr),
                to: index_elem,
            };
            let idx_ext = LlilExpr::SignExtend {
                expr: Box::new(idx_lane),
                from: index_elem,
                to: asize,
            };
            let scaled = if scale > 1 {
                LlilExpr::MulT(
                    Box::new(idx_ext),
                    Box::new(LlilExpr::Const { value: scale, size: asize }),
                    asize,
                )
            } else {
                idx_ext
            };
            let mut addr = scaled;
            if base_reg != Register::None {
                addr = LlilExpr::AddT(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(base_reg)),
                        size: asize,
                    }),
                    Box::new(addr),
                    asize,
                );
            }
            if disp != 0 {
                addr = LlilExpr::AddT(
                    Box::new(addr),
                    Box::new(LlilExpr::Const { value: disp, size: asize }),
                    asize,
                );
            }
            let load = LlilExpr::Load {
                addr: Box::new(addr),
                size: dest_elem,
            };

            // ── per-lane mask predicate
            let cond = if use_evex_k {
                let k_size = reg_size(k);
                let k_shr = LlilExpr::Shr(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(k)),
                        size: k_size,
                    }),
                    Box::new(LlilExpr::Const { value: lane, size: k_size }),
                    k_size,
                );
                let k_bit = LlilExpr::LowPart {
                    expr: Box::new(k_shr),
                    to: Size::Byte,
                };
                LlilExpr::CmpNe(
                    Box::new(LlilExpr::And(
                        Box::new(k_bit),
                        Box::new(LlilExpr::Const { value: 1, size: Size::Byte }),
                        Size::Byte,
                    )),
                    Box::new(LlilExpr::Const { value: 0, size: Size::Byte }),
                )
            } else if vex_mask_reg != Register::None {
                let m_shr = LlilExpr::Shr(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(vex_mask_reg)),
                        size: dest_full_size,
                    }),
                    Box::new(LlilExpr::Const {
                        value: lane * dest_elem_bits,
                        size: dest_full_size,
                    }),
                    dest_full_size,
                );
                let m_lane = LlilExpr::LowPart {
                    expr: Box::new(m_shr),
                    to: dest_elem,
                };
                is_negative(m_lane, dest_elem)
            } else {
                // No mask operand found (shouldn't happen for a well-formed
                // gather): treat as "always gather" rather than dropping
                // the lane silently.
                LlilExpr::Const { value: 1, size: Size::Byte }
            };

            let prior_lane = LlilExpr::LowPart {
                expr: Box::new(LlilExpr::Shr(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(dest_reg)),
                        size: dest_full_size,
                    }),
                    Box::new(LlilExpr::Const {
                        value: lane * dest_elem_bits,
                        size: dest_full_size,
                    }),
                    dest_full_size,
                )),
                to: dest_elem,
            };

            let lane_val = LlilExpr::CondExpr {
                cond: Box::new(cond),
                true_val: Box::new(load),
                false_val: Box::new(prior_lane),
                size: dest_elem,
            };

            let placed = LlilExpr::ShlT(
                Box::new(LlilExpr::ZeroExtend {
                    expr: Box::new(lane_val),
                    from: dest_elem,
                    to: dest_full_size,
                }),
                Box::new(LlilExpr::Const {
                    value: lane * dest_elem_bits,
                    size: dest_full_size,
                }),
                dest_full_size,
            );
            acc = LlilExpr::Or(Box::new(acc), Box::new(placed), dest_full_size);
        }

        ctx.emit(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete(reg_name(dest_reg)),
            size: dest_full_size,
            value: acc,
        });
    }

    /// AVX-512 scatter (`VSCATTER*`/`VPSCATTER*`): per-lane VSIB `Store`s,
    /// mirroring [`Self::lift_vex_gather`] in the opposite direction.
    ///
    /// Operand shape: op0 = VSIB memory, op1 = source vector register, with
    /// a mandatory EVEX opmask. Each selected lane stores
    /// `src[lane]` to `base + sext(index[lane])*scale + disp`. Masked-off
    /// lanes are modelled as a value-preserving store of the prior memory
    /// contents (`CondExpr(k[lane], src[lane], Load(addr))`) so memory
    /// semantics stay exact at the value level.
    fn lift_evex_scatter(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        src_elem: Size,
        index_elem: Size,
    ) {
        let src_reg = iced.op_register(1);
        let index_reg = iced.memory_index();
        let base_reg = iced.memory_base();
        let scale = u64::from(iced.memory_index_scale());
        let disp = iced.memory_displacement64();
        let asize = self.ptr_size();

        if index_reg == Register::None || src_reg == Register::None {
            // Malformed encoding — honest effect-only fallback.
            self.lift_fpu_generic(iced, ctx, "vscatter");
            return;
        }

        let src_full_size = reg_size(src_reg);
        let index_full_size = reg_size(index_reg);
        let src_elem_bits = src_elem.bits() as u64;
        // Lane count is limited by both the source vector and the index
        // vector (e.g. VSCATTERQPS: qword indices, dword elements).
        let n_lanes = (src_full_size.bytes() / src_elem.bytes())
            .min(index_full_size.bytes() / index_elem.bytes());

        let k = iced.op_mask();

        for lane in 0..n_lanes as u64 {
            // Per-lane dynamic address: base + sext(index[lane])*scale + disp.
            let idx_shr = LlilExpr::Shr(
                Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(reg_name(index_reg)),
                    size: index_full_size,
                }),
                Box::new(LlilExpr::Const {
                    value: lane * index_elem.bits() as u64,
                    size: index_full_size,
                }),
                index_full_size,
            );
            let idx_ext = LlilExpr::SignExtend {
                expr: Box::new(LlilExpr::LowPart {
                    expr: Box::new(idx_shr),
                    to: index_elem,
                }),
                from: index_elem,
                to: asize,
            };
            let scaled = if scale > 1 {
                LlilExpr::MulT(
                    Box::new(idx_ext),
                    Box::new(LlilExpr::Const { value: scale, size: asize }),
                    asize,
                )
            } else {
                idx_ext
            };
            let mut addr = scaled;
            if base_reg != Register::None {
                addr = LlilExpr::AddT(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(base_reg)),
                        size: asize,
                    }),
                    Box::new(addr),
                    asize,
                );
            }
            if disp != 0 {
                addr = LlilExpr::AddT(
                    Box::new(addr),
                    Box::new(LlilExpr::Const { value: disp, size: asize }),
                    asize,
                );
            }

            // Source lane value.
            let lane_val = LlilExpr::LowPart {
                expr: Box::new(LlilExpr::Shr(
                    Box::new(LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete(reg_name(src_reg)),
                        size: src_full_size,
                    }),
                    Box::new(LlilExpr::Const {
                        value: lane * src_elem_bits,
                        size: src_full_size,
                    }),
                    src_full_size,
                )),
                to: src_elem,
            };

            // Per-lane k-mask predicate (scatter always carries an opmask;
            // if iced reports none, store unconditionally rather than
            // dropping the lane).
            let value = if k != Register::None {
                let k_size = reg_size(k);
                let k_bit = LlilExpr::LowPart {
                    expr: Box::new(LlilExpr::Shr(
                        Box::new(LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete(reg_name(k)),
                            size: k_size,
                        }),
                        Box::new(LlilExpr::Const { value: lane, size: k_size }),
                        k_size,
                    )),
                    to: Size::Byte,
                };
                let cond = LlilExpr::CmpNe(
                    Box::new(LlilExpr::And(
                        Box::new(k_bit),
                        Box::new(LlilExpr::Const { value: 1, size: Size::Byte }),
                        Size::Byte,
                    )),
                    Box::new(LlilExpr::Const { value: 0, size: Size::Byte }),
                );
                LlilExpr::CondExpr {
                    cond: Box::new(cond),
                    true_val: Box::new(lane_val),
                    false_val: Box::new(LlilExpr::Load {
                        addr: Box::new(addr.clone()),
                        size: src_elem,
                    }),
                    size: src_elem,
                }
            } else {
                lane_val
            };

            ctx.emit(LlilInstruction::Store {
                addr,
                size: src_elem,
                value,
            });
        }
    }

    /// Infer the per-lane element size of an EVEX vector instruction from
    /// its mnemonic suffix (`…ps`/`…ss` → dword, `…pd`/`…sd` → qword,
    /// integer `…b/w/d/q`). Returns `None` when the suffix is ambiguous —
    /// callers then fall back to whole-register mask semantics.
    fn evex_elem_size(iced: &IcedInstruction) -> Option<Size> {
        let name = format!("{:?}", iced.mnemonic()).to_ascii_lowercase();
        if name.ends_with("ps") || name.ends_with("ss") {
            Some(Size::DWord)
        } else if name.ends_with("pd") || name.ends_with("sd") {
            Some(Size::QWord)
        } else if name.ends_with('b') {
            Some(Size::Byte)
        } else if name.ends_with('w') {
            Some(Size::Word)
        } else if name.ends_with('d') {
            Some(Size::DWord)
        } else if name.ends_with('q') {
            Some(Size::QWord)
        } else {
            None
        }
    }

    /// Apply EVEX opmask (`{k1}`/`{k1}{z}`) semantics to a computed vector
    /// result, if the instruction carries an opmask register
    /// ([`iced_x86::Instruction::op_mask`]).
    ///
    /// When the element size is inferable and the lane count is small enough
    /// to keep the expression tree bounded (≤ 16 lanes), masking is modelled
    /// EXACTLY per lane: each destination lane selects between the computed
    /// lane and (merging) the prior destination lane or (zeroing, `{z}`) 0,
    /// keyed on the corresponding `k`-register bit.
    ///
    /// Otherwise (unknown element size, or byte-granularity ZMM with 64
    /// lanes) the previous whole-register approximation is used: `k != 0`
    /// selects the full computed value, `k == 0` the merge/zero fallback —
    /// exact for the all-ones/all-zero mask extremes, documented
    /// approximation in between.
    fn apply_evex_mask(&mut self, iced: &IcedInstruction, computed: LlilExpr, size: Size) -> LlilExpr {
        let k = iced.op_mask();
        if k == Register::None {
            return computed;
        }
        let mask_size = reg_size(k);

        // Exact per-lane path.
        if let Some(elem) = Self::evex_elem_size(iced) {
            let n_lanes = (size.bytes() / elem.bytes()) as u64;
            if n_lanes >= 2 && n_lanes <= 16 {
                let eb = elem.bits() as u64;
                let zeroing = iced.zeroing_masking();
                let dest_before = if zeroing {
                    None
                } else {
                    Some(self.read_operand(iced, 0))
                };
                let mut acc = LlilExpr::Const { value: 0, size };
                for lane in 0..n_lanes {
                    let k_bit = LlilExpr::LowPart {
                        expr: Box::new(LlilExpr::Shr(
                            Box::new(LlilExpr::RegisterRef {
                                reg: LlilRegister::Concrete(reg_name(k)),
                                size: mask_size,
                            }),
                            Box::new(LlilExpr::Const { value: lane, size: mask_size }),
                            mask_size,
                        )),
                        to: Size::Byte,
                    };
                    let cond = LlilExpr::CmpNe(
                        Box::new(LlilExpr::And(
                            Box::new(k_bit),
                            Box::new(LlilExpr::Const { value: 1, size: Size::Byte }),
                            Size::Byte,
                        )),
                        Box::new(LlilExpr::Const { value: 0, size: Size::Byte }),
                    );
                    let lane_of = |e: &LlilExpr| LlilExpr::LowPart {
                        expr: Box::new(LlilExpr::Shr(
                            Box::new(e.clone()),
                            Box::new(LlilExpr::Const { value: lane * eb, size }),
                            size,
                        )),
                        to: elem,
                    };
                    let true_val = lane_of(&computed);
                    let false_val = match &dest_before {
                        Some(d) => lane_of(d),
                        None => LlilExpr::Const { value: 0, size: elem },
                    };
                    let sel = LlilExpr::CondExpr {
                        cond: Box::new(cond),
                        true_val: Box::new(true_val),
                        false_val: Box::new(false_val),
                        size: elem,
                    };
                    let placed = LlilExpr::ShlT(
                        Box::new(LlilExpr::ZeroExtend {
                            expr: Box::new(sel),
                            from: elem,
                            to: size,
                        }),
                        Box::new(LlilExpr::Const { value: lane * eb, size }),
                        size,
                    );
                    acc = LlilExpr::Or(Box::new(acc), Box::new(placed), size);
                }
                return acc;
            }
        }
        let mask_val = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(reg_name(k)),
            size: mask_size,
        };
        let cond = LlilExpr::CmpNe(
            Box::new(mask_val),
            Box::new(LlilExpr::Const {
                value: 0,
                size: mask_size,
            }),
        );
        let else_val = if iced.zeroing_masking() {
            LlilExpr::Const { value: 0, size }
        } else {
            // Merging-masking: unmasked lanes keep the destination's
            // previous value, so fall back to reading the (pre-write)
            // destination operand.
            self.read_operand(iced, 0)
        };
        LlilExpr::CondExpr {
            cond: Box::new(cond),
            true_val: Box::new(computed),
            false_val: Box::new(else_val),
            size,
        }
    }

    /// `VFMADD*/VFMSUB*/VFNMADD*/VFNMSUB*132/213/231PS/PD` — FMA3 fused
    /// multiply-add. Semantics (see [`Fma3Suffix`]/[`FmaVariant`] docs):
    /// `dst = ±(a*b) ± c` with `a`/`b`/`c` selected from `{dst_before, src2,
    /// src3}` according to the `132`/`213`/`231` operand permutation.
    ///
    /// There is no fused (single-rounding) multiply-add primitive in this
    /// IR, so — consistent with `PDEP`/`MULX`/`VPSHUFB` above — this is
    /// modelled as an [`LlilExpr::Intrinsic`] rather than as separate
    /// `Mul`+`Add` nodes, to avoid implying IEEE-754 double-rounding
    /// semantics that don't match real FMA hardware.
    fn lift_fma3(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        suffix: Fma3Suffix,
        variant: FmaVariant,
    ) {
        let size = Self::op_size(iced, 0);
        let dst_before = self.read_operand(iced, 0);
        let src2 = self.read_operand(iced, 1);
        let src3 = self.read_operand(iced, 2);
        let (a, b, c) = match suffix {
            Fma3Suffix::S132 => (dst_before, src3, src2),
            Fma3Suffix::S213 => (src2, dst_before, src3),
            Fma3Suffix::S231 => (src2, src3, dst_before),
        };
        let name = match variant {
            FmaVariant::Madd => "fmadd",
            FmaVariant::Msub => "fmsub",
            FmaVariant::Nmadd => "fnmadd",
            FmaVariant::Nmsub => "fnmsub",
        };
        let expr = LlilExpr::Intrinsic {
            name: name.to_string(),
            args: vec![a, b, c],
            result_size: size,
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }

    /// FMA4 (AMD legacy VEX 4-operand form): `dst, src1, src2, src3` where
    /// `dst = src1*src2 (+/-) src3` per `variant`. Unlike FMA3's 132/213/231
    /// suffix (which encodes which 3 *positions* hold dst-before/src2/src3
    /// because one operand is elided and reused as both dst and a source),
    /// FMA4 has all 4 operands explicit and in fixed semantic order — no
    /// suffix disambiguation needed.
    fn lift_fma4(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, variant: FmaVariant) {
        self.lift_fma4_named(
            iced,
            ctx,
            match variant {
                FmaVariant::Madd => "fmadd",
                FmaVariant::Msub => "fmsub",
                FmaVariant::Nmadd => "fnmadd",
                FmaVariant::Nmsub => "fnmsub",
            },
        );
    }

    /// FMA4 lift with an explicit intrinsic name — used both by
    /// `lift_fma4` (madd/msub/nmadd/nmsub) and directly for the
    /// alternating-lane `Vfmaddsubpd/ps`/`Vfmsubaddpd/ps` forms, which are
    /// also plain 4-operand FMA4 encodings but don't fit the
    /// `FmaVariant` sign enum (the sign alternates per-lane rather than
    /// being fixed for the whole instruction).
    fn lift_fma4_named(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let size = Self::op_size(iced, 0);
        let a = self.read_operand(iced, 1);
        let b = self.read_operand(iced, 2);
        let c = self.read_operand(iced, 3);
        let expr = LlilExpr::Intrinsic {
            name: name.to_string(),
            args: vec![a, b, c],
            result_size: size,
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }

    /// FMA3 lift with an explicit intrinsic name (as opposed to `lift_fma3`,
    /// which derives the name from `FmaVariant`) — used for the
    /// `fmaddsub`/`fmsubadd` alternating-lane forms, which share FMA3's
    /// 132/213/231 operand-position suffix but aren't a plain sign variant.
    fn lift_fma3_named(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        suffix: Fma3Suffix,
        name: &str,
    ) {
        let size = Self::op_size(iced, 0);
        let dst_before = self.read_operand(iced, 0);
        let src2 = self.read_operand(iced, 1);
        let src3 = self.read_operand(iced, 2);
        let (a, b, c) = match suffix {
            Fma3Suffix::S132 => (dst_before, src3, src2),
            Fma3Suffix::S213 => (src2, dst_before, src3),
            Fma3Suffix::S231 => (src2, src3, dst_before),
        };
        let expr = LlilExpr::Intrinsic {
            name: name.to_string(),
            args: vec![a, b, c],
            result_size: size,
        };
        let expr = self.apply_evex_mask(iced, expr, size);
        self.write_operand(iced, 0, expr, ctx);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BMI1 / BMI2
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

impl X86Lifter {
    /// `ANDN dst, src1, src2` — `dst = ~src1 & src2`. Sets ZF/SF from the
    /// result; clears CF/OF; AF/PF undefined (modelled as unaffected).
    fn lift_bmi_andn(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src1 = self.read_operand(iced, 1);
        let src2 = self.read_operand(iced, 2);
        let expr = LlilExpr::And(
            Box::new(LlilExpr::Not(Box::new(src1), size)),
            Box::new(src2),
            size,
        );
        let result = self.materialise_temp(expr, size, ctx);
        self.emit_set_flag_const(ctx, FLAG_CF, 0);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_SF, is_negative(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.write_operand(iced, 0, result, ctx);
    }

    /// `BEXTR dst, src, ctrl` — extract a bitfield of `src` starting at bit
    /// `ctrl[7:0]` with length `ctrl[15:8]`. `ZF` reflects the result; other
    /// flags are cleared/undefined.
    fn lift_bmi_bextr(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let ctrl = self.read_operand(iced, 2);
        let expr = LlilExpr::Intrinsic {
            name: "bextr".to_string(),
            args: vec![src, ctrl],
            result_size: size,
        };
        let result = self.materialise_temp(expr, size, ctx);
        self.emit_set_flag_const(ctx, FLAG_CF, 0);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.write_operand(iced, 0, result, ctx);
    }

    /// `BZHI dst, src, index` — zero all bits in `src` at position >= `index[7:0]`.
    fn lift_bmi_bzhi(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let index = self.read_operand(iced, 2);
        let expr = LlilExpr::Intrinsic {
            name: "bzhi".to_string(),
            args: vec![src, index],
            result_size: size,
        };
        let result = self.materialise_temp(expr, size, ctx);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.emit_set_flag(
            ctx,
            FLAG_CF,
            LlilExpr::Intrinsic {
                name: "bzhi_carry".to_string(),
                args: vec![],
                result_size: Size::Byte,
            },
        );
        self.write_operand(iced, 0, result, ctx);
    }

    /// `BLSR dst, src` — reset (clear) the lowest set bit of `src`:
    /// `dst = src & (src - 1)`. `CF = (src == 0)`, `OF = 0`, `SF`/`ZF` from
    /// result; `PF`/`AF` undefined (left unset, matching the `ANDN`/`BEXTR`
    /// precedent above).
    ///
    /// NOTE: `BLSR`'s carry sense is the OPPOSITE of `BLSI`'s and matches
    /// `BLSMSK`'s — do not "fix" it to look like `BLSI` just because the two
    /// are adjacent and otherwise identical. Both AMD (which defines BLSR via a
    /// `sub` pseudo-instruction, so CF is the SUB borrow) and the Intel SDM
    /// ("CF is set if the source is zero") agree. This was miscoded as
    /// `CF = (src != 0)` for a long time; `test_lift_blsr_cf_set_when_src_zero`
    /// guards it.
    fn lift_bmi_blsr(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let src_minus_one = LlilExpr::Sub {
            left: Box::new(src.clone()),
            right: Box::new(LlilExpr::Const { value: 1, size }),
            size,
        };
        let expr = LlilExpr::And(Box::new(src.clone()), Box::new(src_minus_one), size);
        let result = self.materialise_temp(expr, size, ctx);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_SF, is_negative(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_CF, is_zero(src, size));
        self.write_operand(iced, 0, result, ctx);
    }

    /// AMD TBM (Trailing Bit Manipulation, Bulldozer/Piledriver XOP-encoded)
    /// `dst, src` instructions. All nine share one shape: compute a value from
    /// `src` and either `src+1` or `src-1`, then set flags identically.
    ///
    /// Flags, per the AMD64 APM vol. 3 (pub. 24594) — every one of the nine
    /// reference pages carries a byte-identical `rFLAGS Affected` row
    /// (`OF=0, SF=M, ZF=M, AF=U, PF=U, CF=M`) plus a sentence stating that CF
    /// comes from the `add`/`sub` pseudo-instruction while the other arithmetic
    /// flags come from the final logical op. Hence:
    ///   - `OF = 0`; `SF`/`ZF` from the result.
    ///   - `CF` is the carry/borrow of the `src±1` step, NOT the logical op's
    ///     (real AND/OR/XOR clear CF — the manual explicitly carves CF out):
    ///       * `+1` forms → CF = (src == all-ones), i.e. the ADD carried out.
    ///       * `-1` forms → CF = (src == 0), i.e. the SUB borrowed.
    ///   - `AF`/`PF` are documented UNDEFINED and so are left unwritten. Note
    ///     this differs from the pseudo-code's `and`, which *does* define PF —
    ///     the rFLAGS table overrides the pseudo-code here.
    ///
    /// `uses_increment` selects the CF sense; `value` is the already-built
    /// result expression.
    fn lift_tbm(
        &mut self,
        iced: &IcedInstruction,
        ctx: &mut EmitCtx,
        uses_increment: bool,
        build: impl FnOnce(&LlilExpr, &LlilExpr, Size) -> LlilExpr,
    ) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        // The `src ± 1` operand shared by the value and the carry.
        let adjusted = if uses_increment {
            LlilExpr::Add {
                left: Box::new(src.clone()),
                right: Box::new(LlilExpr::Const { value: 1, size }),
                size,
            }
        } else {
            LlilExpr::Sub {
                left: Box::new(src.clone()),
                right: Box::new(LlilExpr::Const { value: 1, size }),
                size,
            }
        };
        let result = self.materialise_temp(build(&src, &adjusted, size), size, ctx);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_SF, is_negative(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        // CF from the src±1 step: ADD carries out exactly when src is all-ones;
        // SUB borrows exactly when src is zero.
        let cf = if uses_increment {
            is_zero(
                LlilExpr::Not(Box::new(src), size),
                size,
            )
        } else {
            is_zero(src, size)
        };
        self.emit_set_flag(ctx, FLAG_CF, cf);
        self.write_operand(iced, 0, result, ctx);
    }

    /// `BLSI dst, src` — isolate the lowest set bit of `src`:
    /// `dst = src & (-src)`. `CF = (src != 0)` — note this is the OPPOSITE
    /// sense to `BLSR`/`BLSMSK` (AMD defines BLSI via a `neg` pseudo-instruction,
    /// and NEG's carry is set for a non-zero operand). `OF = 0`, `SF`/`ZF` from
    /// result.
    fn lift_bmi_blsi(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let neg_src = LlilExpr::Neg(Box::new(src.clone()), size);
        let expr = LlilExpr::And(Box::new(src.clone()), Box::new(neg_src), size);
        let result = self.materialise_temp(expr, size, ctx);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_SF, is_negative(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_CF, LlilExpr::Not(Box::new(is_zero(src, size)), Size::Byte));
        self.write_operand(iced, 0, result, ctx);
    }

    /// `BLSMSK dst, src` — mask up to and including the lowest set bit of
    /// `src`: `dst = (src - 1) ^ src`. `CF = (src == 0)` — the same carry sense
    /// as `BLSR` (both are defined via a `sub` pseudo-instruction, so CF is the
    /// SUB borrow), and the *inverse* of `BLSI`'s (defined via `neg`).
    /// `OF = 0`, `SF`/`ZF` from result.
    fn lift_bmi_blsmsk(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let src_minus_one = LlilExpr::Sub {
            left: Box::new(src.clone()),
            right: Box::new(LlilExpr::Const { value: 1, size }),
            size,
        };
        let expr = LlilExpr::Xor(Box::new(src_minus_one), Box::new(src.clone()), size);
        let result = self.materialise_temp(expr, size, ctx);
        self.emit_set_flag_const(ctx, FLAG_OF, 0);
        self.emit_set_flag(ctx, FLAG_SF, is_negative(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_ZF, is_zero(result.clone(), size));
        self.emit_set_flag(ctx, FLAG_CF, is_zero(src, size));
        self.write_operand(iced, 0, result, ctx);
    }

    /// Generic 2-source, no-flags-affected BMI2 intrinsic (`PDEP`/`PEXT`):
    /// `dst = f(src1, src2)`.
    fn lift_bmi_intrinsic3(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, name: &str) {
        let size = Self::op_size(iced, 0);
        let src1 = self.read_operand(iced, 1);
        let src2 = self.read_operand(iced, 2);
        let expr = LlilExpr::Intrinsic {
            name: name.to_string(),
            args: vec![src1, src2],
            result_size: size,
        };
        self.write_operand(iced, 0, expr, ctx);
    }

    /// `MULX dst_hi, dst_lo, src` — unsigned `EDX:reg * src`, no flags
    /// affected. iced models this as `MULX dst1, dst2, src` where the
    /// implicit multiplicand is `EDX`/`RDX`.
    fn lift_bmi_mulx(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let dx_name = match size {
            Size::QWord => "rdx",
            Size::DWord => "edx",
            _ => "dx",
        };
        let a = LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(dx_name.to_string()),
            size,
        };
        let b = self.read_operand(iced, 2);
        let wide = LlilExpr::Intrinsic {
            name: "mulx".to_string(),
            args: vec![a, b],
            result_size: size,
        };
        let temp = self.materialise_temp(wide, size, ctx);
        // dst1 = high half, dst2 = low half (both modelled via the same
        // intrinsic result since exact half extraction needs double-width
        // arithmetic outside this IR's native operators).
        self.write_operand(
            iced,
            0,
            LlilExpr::Intrinsic {
                name: "mulx_hi".to_string(),
                args: vec![temp.clone()],
                result_size: size,
            },
            ctx,
        );
        self.write_operand(
            iced,
            1,
            LlilExpr::Intrinsic {
                name: "mulx_lo".to_string(),
                args: vec![temp],
                result_size: size,
            },
            ctx,
        );
    }

    /// `RORX dst, src, imm` — rotate right by immediate, no flags affected.
    fn lift_bmi_rorx(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        let imm = self.read_operand(iced, 2);
        let expr = LlilExpr::Intrinsic {
            name: "rorx".to_string(),
            args: vec![src, imm],
            result_size: size,
        };
        self.write_operand(iced, 0, expr, ctx);
    }

    /// `SHLX`/`SHRX`/`SARX dst, src, count` — shift without touching flags.
    fn lift_bmi_shiftx(&mut self, iced: &IcedInstruction, ctx: &mut EmitCtx, op: ShiftOp) {
        let size = Self::op_size(iced, 0);
        let src = self.read_operand(iced, 1);
        // Same 5-/6-bit count masking as SHL/SHR/SAR — see `mask_shift_count`
        // for the APM citation (SHLX: bits [31:5] / [63:6] of shft_cnt are
        // ignored).
        let count = Self::mask_shift_count(self.read_operand(iced, 2), size);
        let expr = match op {
            ShiftOp::Shl => LlilExpr::ShlT(Box::new(src), Box::new(count), size),
            ShiftOp::Shr => LlilExpr::Shr(Box::new(src), Box::new(count), size),
            ShiftOp::Sar => LlilExpr::Sar(Box::new(src), Box::new(count), size),
        };
        self.write_operand(iced, 0, expr, ctx);
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    /// Decode the first instruction in `bytes` (at `ip`) and lift it.
    fn lift_at(bits: u32, ip: u64, bytes: &[u8]) -> Vec<LlilAnnotatedInstr> {
        let mut dec = Decoder::with_ip(bits, bytes, ip, DecoderOptions::NONE);
        let iced = dec.decode();
        assert!(!iced.is_invalid(), "decode failed for {bytes:02x?}");
        let mut lifter = X86Lifter::new(bits);
        lifter.lift(&iced, Address::new(ip), iced.len())
    }

    fn lift64(bytes: &[u8]) -> Vec<LlilAnnotatedInstr> {
        lift_at(64, 0x1000, bytes)
    }

    /// Encode a 2-register-operand instruction from its `iced_x86::Code`
    /// variant and lift it — avoids hand-crafting EVEX/VEX byte encodings
    /// (error-prone for AVX-512 forms) for pure dispatch-coverage tests.
    fn lift64_encoded_2(code: iced_x86::Code, op0: Register, op1: Register) -> Vec<LlilAnnotatedInstr> {
        let instr = iced_x86::Instruction::with2(code, op0, op1).unwrap();
        let mut encoder = iced_x86::Encoder::new(64);
        let len = encoder.encode(&instr, 0x1000).unwrap();
        let bytes = encoder.take_buffer();
        lift_at(64, 0x1000, &bytes[..len])
    }

    /// Like `lift64`, but with `DecoderOptions::MPX` enabled — MPX `BND*`
    /// opcodes (`0F 1A`/`0F 1B`) alias the reserved-NOP encoding space, so
    /// iced only decodes them as `Bndmk`/`Bndcl`/... rather than
    /// `Reservednop` when this option is explicitly requested (mirroring
    /// how a real decoder would be configured for MPX-aware disassembly).
    fn lift64_mpx(bytes: &[u8]) -> Vec<LlilAnnotatedInstr> {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::MPX);
        let iced = dec.decode();
        assert!(!iced.is_invalid(), "decode failed for {bytes:02x?}");
        let mut lifter = X86Lifter::new(64);
        lifter.lift(&iced, Address::new(0x1000), iced.len())
    }

    fn lift32(bytes: &[u8]) -> Vec<LlilAnnotatedInstr> {
        lift_at(32, 0x1000, bytes)
    }

    /// REGRESSION: `RET imm16` pops `imm16` bytes of arguments as well as the
    /// return address (stdcall callee cleanup). The immediate used to be
    /// dropped — `lift_ret` took `_iced` — so `ret 0x10` and a bare `ret`
    /// produced identical IL and every downstream stack-depth inference was
    /// wrong by that much.
    #[test]
    fn ret_imm16_adjusts_the_stack_pointer() {
        // C2 10 00 — RET 0x10
        let ops = lift64(&[0xC2, 0x10, 0x00]);
        let rendered = ops
            .iter()
            .map(|o| format!("{:?}", o.instr))
            .collect::<Vec<_>>()
            .join("
");
        assert!(
            rendered.contains("rsp") && rendered.contains("16"),
            "ret 0x10 must adjust rsp by 16:
{rendered}"
        );
        assert!(rendered.contains("Ret"), "still a return:
{rendered}");

        // A bare RET must NOT gain a spurious adjustment.
        let plain = lift64(&[0xC3]);
        assert_eq!(plain.len(), 1, "bare ret should stay a single Ret: {plain:?}");
    }

    /// REGRESSION: `REP MOVS`/`REP STOS` must honour the direction flag.
    ///
    /// The `memcpy`/`memset` lowering that replaced the one-element-per-`rep`
    /// bug arrived with NO reference to DF at all, while the non-`rep`
    /// `advance_index` path ten lines away did honour it. With DF=1 (`std;
    /// rep movsb`, the overlapping-`memmove` idiom) that lifts a BACKWARD
    /// transfer as a forward one and moves the index registers the wrong way,
    /// leaving them `2 * count` from where the hardware puts them.
    ///
    /// Asserted on the rendered expressions rather than by counting
    /// instructions: the defect was never a missing statement, it was a
    /// present statement with an unconditional direction — a count would have
    /// been green throughout.
    #[test]
    fn rep_string_ops_honour_the_direction_flag() {
        // f3 a4 = rep movsb, f3 ab = rep stosd
        for (name, bytes) in [("rep movsb", &[0xF3u8, 0xA4][..]), ("rep stosd", &[0xF3, 0xAB][..])] {
            let ops = lift64(bytes);
            let rendered: Vec<String> = ops.iter().map(|o| format!("{:?}", o.instr)).collect();
            let all = rendered.join("
");

            // The transfer itself must select its base address on DF.
            let intrinsic = rendered
                .iter()
                .find(|r| r.contains("memcpy") || r.contains("memset"))
                .unwrap_or_else(|| panic!("{name}: no block-transfer intrinsic in {all}"));
            assert!(
                intrinsic.contains(r#"Flag("df")"#),
                "{name}: transfer ignores the direction flag: {intrinsic}"
            );

            // ...and so must the post-transfer index update. Both halves are
            // checked because fixing only the base address would still leave
            // the register wrong, and only the register would still name the
            // wrong block.
            let update = rendered
                .iter()
                .find(|r| r.contains("SetReg") && (r.contains("rdi") || r.contains("rsi")))
                .unwrap_or_else(|| panic!("{name}: no index update in {all}"));
            assert!(
                update.contains(r#"Flag("df")"#),
                "{name}: index update ignores the direction flag: {update}"
            );
            // A DF-aware update must be able to go DOWN, i.e. subtract.
            assert!(
                update.contains("SubT"),
                "{name}: index update has no decrementing branch: {update}"
            );
        }
    }

    /// Count how many `SetFlag` instructions define `flag`.
    fn count_flag_writes(ops: &[LlilAnnotatedInstr], flag: &str) -> usize {
        ops.iter()
            .filter(|o| matches!(&o.instr, LlilInstruction::SetFlag { name: f, .. } if f == flag))
            .count()
    }

    /// Debug-render the expression assigned to `flag`, so a test can assert on
    /// the flag's actual VALUE and not merely that it was written. Counting
    /// writes alone let a real inverted-carry bug in `BLSR` survive for a long
    /// time — the flag was written exactly once, just with the wrong value.
    fn flag_expr_debug(ops: &[LlilAnnotatedInstr], flag: &str) -> Option<String> {
        ops.iter().find_map(|o| match &o.instr {
            LlilInstruction::SetFlag { name: f, src } if f == flag => Some(format!("{src:?}")),
            _ => None,
        })
    }

    /// `BT`/`BTS`/`BTR`/`BTC` with a REGISTER bit-base reduce the bit offset
    /// MODULO the operand size (Intel SDM vol.2 BT: "If the bit base operand
    /// specifies a register, the instruction takes the modulo 16, 32, or 64 of
    /// the bit offset operand"; AMD APM vol.3 BT states the same). Only the
    /// MEMORY form treats the offset as an unbounded signed bit-string index.
    ///
    /// This is deliberately NOT `mask_shift_count`: shifts use a FIXED 5-bit
    /// mask at every sub-64-bit width (`shl bl, 0x21` shifts by 1, not by
    /// 1 mod 8), whereas bit-test really is mod-width — so at 16 bits BT masks
    /// with 0x0F where a shift would mask with 0x1F. Reusing the shift helper
    /// here would leave `bt ax, cx` (cx = 17) testing bit 17 of a 16-bit
    /// register instead of bit 1.
    #[test]
    fn bit_test_offset_is_masked_mod_operand_size() {
        // `bt eax, ecx` (0F A3 C8). Offset must be reduced mod 32 → `& 0x1f`.
        let ops = lift64(&[0x0F, 0xA3, 0xC8]);
        let cf = flag_expr_debug(&ops, FLAG_CF).expect("bt must define CF");
        assert!(
            cf.contains("1f") || cf.contains("31"),
            "bt r32 CF must use an offset masked & 0x1f, got: {cf}"
        );

        // `bts rax, rcx` (48 0F AB C8). 64-bit → mod 64 → `& 0x3f`, and the
        // SAME masked offset must reach the `1 << bit` mask, not just CF.
        let ops = lift64(&[0x48, 0x0F, 0xAB, 0xC8]);
        let cf = flag_expr_debug(&ops, FLAG_CF).expect("bts must define CF");
        assert!(
            cf.contains("3f") || cf.contains("63"),
            "bts r64 CF must use an offset masked & 0x3f, got: {cf}"
        );
        let wrote = ops.iter().find_map(|o| match &o.instr {
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. } if d == "rax" => {
                Some(format!("{value:?}"))
            }
            _ => None,
        });
        let wrote = wrote.expect("bts must write rax");
        assert!(
            wrote.contains("3f") || wrote.contains("63"),
            "bts r64 bit-mask must use the masked offset too, got: {wrote}"
        );

        // 16-bit is where the mod-width rule DIFFERS from the shift rule:
        // `bt ax, cx` (66 0F A3 C8) must mask & 0x0f, NOT & 0x1f.
        let ops = lift64(&[0x66, 0x0F, 0xA3, 0xC8]);
        let cf = flag_expr_debug(&ops, FLAG_CF).expect("bt r16 must define CF");
        assert!(
            cf.contains(" f,") || cf.contains("15") || cf.contains("0xf"),
            "bt r16 CF must use an offset masked & 0x0f (mod 16, NOT the \
             shift rule's 0x1f), got: {cf}"
        );
    }

    fn flags_written(ops: &[LlilAnnotatedInstr]) -> Vec<String> {
        ops.iter()
            .filter_map(|o| match &o.instr {
                LlilInstruction::SetFlag { name: flag, .. } => Some(flag.clone()),
                _ => None,
            })
            .collect()
    }

    /// Peel the zero-extension a 32-bit write carries under
    /// [`gpr32_alias_enabled`], so a test can ask about the value that was
    /// computed without restating the register model around it.
    ///
    /// With the alias off this is the identity, so assertions keep their old
    /// meaning exactly; with it on, `rax = zx(intrinsic(...))` still answers
    /// "what did this instruction compute" with `intrinsic(...)`.
    fn computed_value(value: &LlilExpr) -> &LlilExpr {
        match value {
            LlilExpr::ZeroExtend { expr, from: Size::DWord, to: Size::QWord }
                if gpr32_alias_enabled() =>
            {
                expr
            }
            other => other,
        }
    }

    /// Name of the intrinsic a write computes, looking through the
    /// alias zero-extension. `None` when the value is not an intrinsic at all —
    /// so `intrinsic_name(v) == Some("crc32")` stays a real assertion and
    /// cannot be satisfied by an unrelated shape.
    fn intrinsic_name(value: &LlilExpr) -> Option<&str> {
        match computed_value(value) {
            LlilExpr::Intrinsic { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    /// Is `e` a read of the 32-bit register `name`?
    ///
    /// Under the alias a 32-bit read becomes `LowPart(RegisterRef(parent))`;
    /// both spellings mean the same machine value. Still exact about WHICH
    /// register: a read of `ecx` is never accepted for `eax`.
    fn reads_reg32(e: &LlilExpr, name: &str) -> bool {
        match e {
            LlilExpr::RegisterRef { reg: LlilRegister::Concrete(r), .. } => r == name,
            LlilExpr::LowPart { expr, to: Size::DWord } if gpr32_alias_enabled() => {
                matches!(&**expr, LlilExpr::RegisterRef { reg: LlilRegister::Concrete(r), .. }
                    if Some(r.as_str()) == gpr32_parent(name))
            }
            _ => false,
        }
    }

    /// How the operand register `name` is SPELLED in a lifted expression under
    /// the current register model: under the GPR32 alias a 32-bit operand
    /// appears as `LowPart(<parent>)`, so its debug text names the parent.
    /// Both spellings denote the same machine value; picking the right one
    /// keeps "the flag depends on its operand" an exact assertion instead of
    /// widening it to "mentions some register".
    fn operand_spelling(name: &str) -> &str {
        match gpr32_alias_enabled().then(|| gpr32_parent(name)).flatten() {
            Some(parent) => parent,
            None => name,
        }
    }

    /// Is `dest` the destination the test means by the 32-bit name `name`?
    ///
    /// Same rule as [`has_setreg_to`], for assertions that inspect `dest`
    /// inline. Exact about identity: `is_dest(d, "ecx")` is false for a write
    /// to `rdx`, which is what the "writes ecx, not the source" tests need.
    fn is_dest(dest: &str, name: &str) -> bool {
        dest == name
            || (gpr32_alias_enabled() && Some(dest) == gpr32_parent(name))
    }

    /// Does any lifted op write `name`?
    ///
    /// These tests ask "does this instruction write its destination", and they
    /// spell the destination with the width the encoding uses (`eax`, `ecx`).
    /// Under [`gpr32_alias_enabled`] a 32-bit write deliberately lands on the
    /// 64-bit parent, so a write to `rax` IS the write to `eax` the test means —
    /// accepting the parent keeps the question the same while the register
    /// model changes underneath.
    ///
    /// The widening is applied ONLY when the alias is on, so with it off these
    /// assertions stay exactly as strict as they were. And it never blurs
    /// DIFFERENT registers: asking for `ecx` still cannot be satisfied by a
    /// write to `rdx`, which is what tests like
    /// `test_lift_pcmpistri_writes_ecx_not_source` rely on.
    fn has_setreg_to(ops: &[LlilAnnotatedInstr], name: &str) -> bool {
        let parent = gpr32_alias_enabled().then(|| gpr32_parent(name)).flatten();
        ops.iter().any(|o| {
            matches!(&o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. }
                if d == name || Some(d.as_str()) == parent)
        })
    }

    // â"€â"€ basic helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_reg_name() {
        assert_eq!(reg_name(Register::RAX), "rax");
        assert_eq!(reg_name(Register::R8D), "r8d");
        assert_eq!(reg_name(Register::XMM0), "xmm0");
        assert_eq!(reg_name(Register::AH), "ah");
    }

    #[test]
    fn test_size_from_bytes() {
        assert_eq!(size_from_bytes(1), Size::Byte);
        assert_eq!(size_from_bytes(2), Size::Word);
        assert_eq!(size_from_bytes(4), Size::DWord);
        assert_eq!(size_from_bytes(8), Size::QWord);
        assert_eq!(size_from_bytes(16), Size::OWord);
        assert_eq!(size_from_bytes(32), Size::YWord);
        assert_eq!(size_from_bytes(64), Size::ZWord);
        assert_eq!(size_from_bytes(128), Size::ZWord); // saturates above 512-bit
    }

    #[test]
    fn test_lifter_ptr_size() {
        assert_eq!(X86Lifter::new_64().ptr_size(), Size::QWord);
        assert_eq!(X86Lifter::new_32().ptr_size(), Size::DWord);
        assert_eq!(X86Lifter::new_16().ptr_size(), Size::Word);
        assert_eq!(X86Lifter::new_64().sp_name(), "rsp");
        assert_eq!(X86Lifter::new_32().sp_name(), "esp");
    }

    // â"€â"€ NOP â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_nop() {
        let ops = lift64(&[0x90]);
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0].instr, LlilInstruction::Nop));
    }

    // â"€â"€ MOV reg, reg â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_mov_reg_reg() {
        // 48 89 c3 —" mov rbx, rax
        let ops = lift64(&[0x48, 0x89, 0xc3]);
        assert_eq!(ops.len(), 1);
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, size, value: src } => {
                assert_eq!(*dest, LlilRegister::Concrete("rbx".into()));
                assert_eq!(*size, Size::QWord);
                assert_eq!(
                    *src,
                    LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rax".into()),
                        size: Size::QWord
                    }
                );
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    // â"€â"€ MOV reg, imm â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_mov_reg_imm() {
        // b8 2a 00 00 00 —" mov eax, 0x2a
        let ops = lift64(&[0xb8, 0x2a, 0x00, 0x00, 0x00]);
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, value: src, .. } => {
                let LlilRegister::Concrete(d) = dest else {
                    panic!("expected a concrete destination, got {dest:?}")
                };
                assert!(is_dest(d, "eax"), "must write eax (or its parent), got {d}");
                assert_eq!(
                    *computed_value(src),
                    LlilExpr::Const {
                        value: 0x2a,
                        size: Size::DWord
                    }
                );
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    // â"€â"€ MOV to memory: must produce Store â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_mov_mem_store() {
        // 48 89 45 f8 —" mov [rbp-8], rax
        let ops = lift64(&[0x48, 0x89, 0x45, 0xf8]);
        let store = ops
            .iter()
            .find(|o| matches!(o.instr, LlilInstruction::Store { .. }));
        assert!(
            store.is_some(),
            "mov to memory should produce a Store: {ops:?}"
        );
        if let LlilInstruction::Store { addr, size, value: src } = &store.unwrap().instr {
            assert_eq!(*size, Size::QWord);
            assert_eq!(
                *src,
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord
                }
            );
            // address must be rbp + disp (an Add)
            assert!(
                matches!(addr, LlilExpr::AddT(..)),
                "addr should be base+disp"
            );
        }
    }

    // â"€â"€ MOV from memory: must produce Load on RHS â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_mov_mem_load() {
        // 48 8b 45 f8 —" mov rax, [rbp-8]
        let ops = lift64(&[0x48, 0x8b, 0x45, 0xf8]);
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, value: src, .. } => {
                assert_eq!(*dest, LlilRegister::Concrete("rax".into()));
                assert!(matches!(src, LlilExpr::Load { .. }), "src should be a Load");
            }
            other => panic!("expected SetReg with Load, got {other:?}"),
        }
    }

    // â"€â"€ MOVZX / MOVSX â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_movzx() {
        // 48 0f b6 c3 —" movzx rax, bl
        let ops = lift64(&[0x48, 0x0f, 0xb6, 0xc3]);
        match &ops[0].instr {
            LlilInstruction::SetReg { value: src, .. } => {
                assert!(
                    matches!(src, LlilExpr::ZeroExtend { .. }),
                    "expected ZeroExtend"
                );
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_movsx() {
        // 48 0f be c3 —" movsx rax, bl
        let ops = lift64(&[0x48, 0x0f, 0xbe, 0xc3]);
        match &ops[0].instr {
            LlilInstruction::SetReg { value: src, .. } => {
                assert!(
                    matches!(src, LlilExpr::SignExtend { .. }),
                    "expected SignExtend"
                );
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_movsxd() {
        // 48 63 c3 —" movsxd rax, ebx
        let ops = lift64(&[0x48, 0x63, 0xc3]);
        match &ops[0].instr {
            LlilInstruction::SetReg { value: src, .. } => {
                assert!(matches!(
                    src,
                    LlilExpr::SignExtend {
                        from: Size::DWord,
                        to: Size::QWord,
                        ..
                    }
                ));
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    // â"€â"€ LEA: address computation, no memory access â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_lea_no_memory_access() {
        // 48 8d 44 18 04 —" lea rax, [rax+rbx+4]
        let ops = lift64(&[0x48, 0x8d, 0x44, 0x18, 0x04]);
        assert_eq!(ops.len(), 1);
        // No Load / Store should be present.
        assert!(!ops.iter().any(|o| matches!(
            o.instr,
            LlilInstruction::Load { .. } | LlilInstruction::Store { .. }
        )));
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, value: src, .. } => {
                assert_eq!(*dest, LlilRegister::Concrete("rax".into()));
                // value is an address arithmetic expression, never a Load
                assert!(!matches!(src, LlilExpr::Load { .. }));
                assert!(matches!(src, LlilExpr::AddT(..)));
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    // â"€â"€ XCHG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_xchg() {
        // 48 91 —" xchg rax, rcx
        let ops = lift64(&[0x48, 0x91]);
        // Should produce: tmp = rax; rax = rcx; rcx = tmp  â†' 3 SetReg
        let setregs = ops
            .iter()
            .filter(|o| matches!(o.instr, LlilInstruction::SetReg { .. }))
            .count();
        assert_eq!(setregs, 3, "xchg should yield 3 SetReg ops: {ops:?}");
    }

    // â"€â"€ CMPXCHG sets ZF â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_cmpxchg_sets_zf() {
        let ops = lift64(&[0x48, 0x0f, 0xb1, 0xcb]); // cmpxchg rbx, rcx
        assert!(count_flag_writes(&ops, FLAG_ZF) >= 1, "cmpxchg must set ZF");
    }

    // â"€â"€ PUSH / POP adjust stack â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_push_reg() {
        // 55 —" push rbp
        let ops = lift64(&[0x55]);
        assert_eq!(ops.len(), 1);
        match &ops[0].instr {
            LlilInstruction::Push { size, src } => {
                assert_eq!(*size, Size::QWord);
                assert_eq!(
                    *src,
                    LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("rbp".into()),
                        size: Size::QWord
                    }
                );
            }
            other => panic!("expected Push, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_pop_reg() {
        // 5d —" pop rbp
        let ops = lift64(&[0x5d]);
        assert_eq!(ops.len(), 1);
        match &ops[0].instr {
            LlilInstruction::Pop { dest, size } => {
                assert_eq!(*dest, LlilRegister::Concrete("rbp".into()));
                assert_eq!(*size, Size::QWord);
            }
            other => panic!("expected Pop, got {other:?}"),
        }
    }

    // â"€â"€ ADD: result + 6 flags + store â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_add_flags_and_store() {
        // 48 01 d8 —" add rax, rbx
        let ops = lift64(&[0x48, 0x01, 0xd8]);
        // CF, OF, AF, SF, ZF, PF
        for f in [FLAG_CF, FLAG_OF, FLAG_AF, FLAG_SF, FLAG_ZF, FLAG_PF] {
            assert_eq!(count_flag_writes(&ops, f), 1, "add must set {f}");
        }
        // final write to rax
        assert!(has_setreg_to(&ops, "rax"), "add must write rax");
        // the add expression must appear in a temporary materialisation
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::AddT(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_sub_uses_borrow_cf() {
        // 48 29 d8 —" sub rax, rbx
        let ops = lift64(&[0x48, 0x29, 0xd8]);
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
        // CF for sub is a CmpUlt(a, b)
        let cf = ops.iter().find_map(|o| match &o.instr {
            LlilInstruction::SetFlag { name: flag, src } if flag == FLAG_CF => Some(src.clone()),
            _ => None,
        });
        assert!(
            matches!(cf, Some(LlilExpr::CmpUlt(..))),
            "sub CF should be CmpUlt"
        );
    }

    #[test]
    fn test_lift_adc_folds_carry() {
        // 48 11 d8 —" adc rax, rbx
        let ops = lift64(&[0x48, 0x11, 0xd8]);
        // The right operand should include a read of the carry flag.
        assert!(
            ops.iter().any(|o| o.instr.reads_flag(FLAG_CF)),
            "adc must read CF"
        );
    }

    // â"€â"€ CMP: flags only, no register write â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_cmp_no_dest_write() {
        // 48 39 d8 —" cmp rax, rbx
        let ops = lift64(&[0x48, 0x39, 0xd8]);
        for f in [FLAG_CF, FLAG_OF, FLAG_AF, FLAG_SF, FLAG_ZF, FLAG_PF] {
            assert_eq!(count_flag_writes(&ops, f), 1, "cmp must set {f}");
        }
        // No SetReg writing rax (only the temporary result).
        assert!(!has_setreg_to(&ops, "rax"), "cmp must not write rax");
    }

    // â"€â"€ INC / DEC leave CF alone â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_inc_no_cf() {
        // 48 ff c0 —" inc rax
        let ops = lift64(&[0x48, 0xff, 0xc0]);
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 0, "inc must NOT set CF");
        assert_eq!(count_flag_writes(&ops, FLAG_OF), 1);
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        assert!(has_setreg_to(&ops, "rax"));
    }

    #[test]
    fn test_lift_dec() {
        // 48 ff c8 —" dec rax
        let ops = lift64(&[0x48, 0xff, 0xc8]);
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 0);
        assert!(has_setreg_to(&ops, "rax"));
    }

    // â"€â"€ NEG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_neg() {
        // 48 f7 d8 —" neg rax
        let ops = lift64(&[0x48, 0xf7, 0xd8]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Neg(..),
                ..
            }
        )));
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    // â"€â"€ MUL / IMUL / DIV / IDIV â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_mul_split() {
        // 48 f7 e3 —" mul rbx
        let ops = lift64(&[0x48, 0xf7, 0xe3]);
        let split = ops
            .iter()
            .find_map(|o| match &o.instr {
                LlilInstruction::SetRegSplit { src, .. } => Some(src),
                _ => None,
            })
            .expect("mul should write rdx:rax via SetRegSplit");
        // The 128-bit product must be a DOUBLE-WIDTH multiply — both operands
        // zero-extended to OWord and multiplied there — else the high half
        // deposited into rdx is meaningless (it was a truncated `.8` product).
        let dbg = format!("{split:?}");
        assert!(
            dbg.contains("ZeroExtend") && dbg.contains("OWord"),
            "mul product must be a full 128-bit (OWord) multiply, got {dbg}"
        );
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
        assert_eq!(count_flag_writes(&ops, FLAG_OF), 1);
        // CF/OF (set iff the upper half is nonzero) must DEPEND on the operands,
        // not be an argument-less placeholder that every MUL emits identically.
        let cf = flag_expr_debug(&ops, FLAG_CF).expect("mul writes CF");
        assert!(
            cf.contains("rax") && cf.contains("rbx"),
            "mul CF must depend on its operands, got {cf}"
        );
    }

    #[test]
    fn test_lift_imul_two_operand() {
        // 48 0f af c3 —" imul rax, rbx
        let ops = lift64(&[0x48, 0x0f, 0xaf, 0xc3]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value: LlilExpr::MulT(..), .. } if d == "rax")));
        // Overflow flags must depend on both multiplicands, not be an
        // argument-less placeholder shared by every IMUL.
        let cf = flag_expr_debug(&ops, FLAG_CF).expect("imul writes CF");
        assert!(cf.contains("rax") && cf.contains("rbx"), "{cf}");
    }

    #[test]
    fn test_lift_div_quotient_remainder() {
        // 48 f7 f3 —" div rbx
        let ops = lift64(&[0x48, 0xf7, 0xf3]);
        assert!(has_setreg_to(&ops, "rax"), "div writes quotient to rax");
        assert!(has_setreg_to(&ops, "rdx"), "div writes remainder to rdx");
        // Quotient/remainder computed at double width, truncated back.
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::LowPart { expr, .. },
                ..
            } if matches!(**expr, LlilExpr::DivU(.., Size::OWord))
        )));
    }

    #[test]
    fn test_lift_idiv_signed() {
        // 48 f7 fb —" idiv rbx
        let ops = lift64(&[0x48, 0xf7, 0xfb]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::LowPart { expr, .. },
                ..
            } if matches!(**expr, LlilExpr::DivS(..))
        )));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::LowPart { expr, .. },
                ..
            } if matches!(**expr, LlilExpr::ModS(..))
        )));
    }

    #[test]
    fn test_15_byte_length_limit_rejected() {
        // 15 legacy prefixes + opcode = 16 bytes: x86 caps instructions at
        // 15 bytes, the decoder must reject rather than decode/lift garbage.
        let mut bytes = vec![0x66; 15];
        bytes.push(0x90);
        assert!(
            crate::X86LiftAdapter::decode_one_iced(64, &bytes, 0x1000).is_none(),
            ">15-byte instruction must not decode"
        );
        // 14 prefixes + nop = 15 bytes: exactly at the limit, must decode.
        let mut ok = vec![0x66; 14];
        ok.push(0x90);
        assert!(crate::X86LiftAdapter::decode_one_iced(64, &ok, 0x1000).is_some());
    }

    #[test]
    fn test_lift_cdq_cqo_sign_extend_into_high() {
        // 99 — cdq: edx = sign(eax);  48 99 — cqo: rdx = sign(rax)
        for (bytes, hi) in [(vec![0x99u8], "edx"), (vec![0x48, 0x99], "rdx")] {
            let ops = lift64(&bytes);
            assert!(
                ops.iter().any(|o| matches!(
                    &o.instr,
                    LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. }
                        if is_dest(d, hi)
                )),
                "{bytes:02x?} must write {hi}"
            );
        }
    }

    #[test]
    fn test_lift_bswap_writes_dest() {
        // 48 0f c8 — bswap rax
        let ops = lift64(&[0x48, 0x0F, 0xC8]);
        assert!(has_setreg_to(&ops, "rax"), "bswap must write its operand");
    }

    #[test]
    fn test_lift_scatter_emits_stores() {
        // 62 f2 7d 09 a0 0c 07 — vpscatterdd [rdi+xmm0]{k1}, xmm1
        // 4 dword lanes → 4 real Stores (was effect-only intrinsic, no Store).
        let ops = lift64(&[0x62, 0xf2, 0x7d, 0x09, 0xa0, 0x0c, 0x07]);
        let stores = ops
            .iter()
            .filter(|o| matches!(&o.instr, LlilInstruction::Store { size: Size::DWord, .. }))
            .count();
        assert_eq!(stores, 4, "vpscatterdd xmm must emit one Store per lane");
    }

    #[test]
    fn test_evex_opmask_is_per_lane() {
        // 62 f1 74 09 58 c2 — vaddps xmm0{k1}, xmm1, xmm2
        // 4 dword lanes → the masked result must select per lane (4 CondExpr
        // keyed on distinct k1 bits), not one whole-register predicate.
        let ops = lift64(&[0x62, 0xf1, 0x74, 0x09, 0x58, 0xc2]);
        let val = ops
            .iter()
            .find_map(|o| match &o.instr {
                LlilInstruction::SetReg { value, .. } => Some(value),
                _ => None,
            })
            .expect("vaddps writes a register");
        let s = format!("{val:?}");
        let cond_count = s.matches("CondExpr").count();
        assert!(
            cond_count >= 4,
            "expected >=4 per-lane CondExpr selections, got {cond_count}"
        );
    }

    #[test]
    fn test_lift_div_dividend_includes_high_half() {
        // 48 f7 f3 — div rbx: dividend must be (zext(rdx) << 64) | zext(rax),
        // not just rax (the old lo-only approximation dropped rdx entirely).
        let ops = lift64(&[0x48, 0xf7, 0xf3]);
        let uses_rdx_in_dividend = ops.iter().any(|o| {
            if let LlilInstruction::SetReg {
                value: LlilExpr::LowPart { expr, .. },
                ..
            } = &o.instr
            {
                if let LlilExpr::DivU(dividend, _, Size::OWord) = &**expr {
                    let s = format!("{dividend:?}");
                    return s.contains("rdx") && s.contains("rax") && s.contains("ShlT");
                }
            }
            false
        });
        assert!(
            uses_rdx_in_dividend,
            "DIV dividend must concatenate rdx:rax at double width"
        );
    }

    // â"€â"€ XOR reg,reg zeroing idiom â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// `xorps %xmm15,%xmm15` azzera SENZA dipendere dall'input: il percorso
    /// intero lo modellava gia', quello SSE no, e da li' uscivano 275 letture
    /// di una locale mai definita (57% della classe SSE).
    #[test]
    fn test_lift_sse_xor_self_zeroes() {
        // 0f 57 ff  ->  xorps %xmm7, %xmm7
        let ops = lift64(&[0x0f, 0x57, 0xff]);
        let dbg: String = ops.iter().map(|o| format!("{:?}", o.instr)).collect();
        assert!(
            !dbg.contains("Xor"),
            "l'azzeramento non deve leggere il registro: {dbg}"
        );
        assert!(dbg.contains("Const"), "deve diventare una costante: {dbg}");
    }

    /// Controparte INTERA dell'idioma di azzeramento. ⚠ Questo test e' rimasto
    /// **MORTO**: aggiungendo la variante SSE, il suo `#[test]` fu inserito
    /// sopra quello esistente (`duplicated attribute`), il nuovo corpo se lo
    /// prese e questa funzione resto' senza attributo — mai eseguita, e nessuno
    /// poteva vederla fallire. Riparata a #381 rimettendo l'attributo.
    #[test]
    fn test_lift_xor_self_zeroes() {
        // 48 31 c0 —" xor rax, rax
        let ops = lift64(&[0x48, 0x31, 0xc0]);
        // dest should be set to a constant zero
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value: LlilExpr::Const { value: 0, .. }, .. } if d == "rax")));
        // ZF = 1, CF = 0
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 1, .. } } if flag == FLAG_ZF)));
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 0, .. } } if flag == FLAG_CF)));
    }

    #[test]
    fn test_lift_and_clears_cf_of() {
        // 48 21 d8 —" and rax, rbx
        let ops = lift64(&[0x48, 0x21, 0xd8]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 0, .. } } if flag == FLAG_CF)));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::And(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_or() {
        // 48 09 d8 —" or rax, rbx
        let ops = lift64(&[0x48, 0x09, 0xd8]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Or(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_not_no_flags() {
        // 48 f7 d0 —" not rax
        let ops = lift64(&[0x48, 0xf7, 0xd0]);
        assert!(flags_written(&ops).is_empty(), "not affects no flags");
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Not(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_test_flags_only() {
        // 48 85 c3 —" test rax, rbx
        let ops = lift64(&[0x48, 0x85, 0xc3]);
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        assert!(
            !has_setreg_to(&ops, "rax"),
            "test must not write a register"
        );
    }

    // â"€â"€ Shifts / rotates â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_shl() {
        // 48 c1 e0 04 —" shl rax, 4
        let ops = lift64(&[0x48, 0xc1, 0xe0, 0x04]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::ShlT(..),
                ..
            }
        )));
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    #[test]
    fn test_lift_sar() {
        // 48 c1 f8 03 —" sar rax, 3
        let ops = lift64(&[0x48, 0xc1, 0xf8, 0x03]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Sar(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_shr() {
        // 48 d1 e8 —" shr rax, 1
        let ops = lift64(&[0x48, 0xd1, 0xe8]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Shr(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_rol() {
        // 48 c1 c0 08 —" rol rax, 8
        let ops = lift64(&[0x48, 0xc1, 0xc0, 0x08]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Rol(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_ror() {
        // 48 c1 c8 08 —" ror rax, 8
        let ops = lift64(&[0x48, 0xc1, 0xc8, 0x08]);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Ror(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_rcl_intrinsic() {
        // 48 d1 d0 —" rcl rax, 1
        let ops = lift64(&[0x48, 0xd1, 0xd0]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { value: LlilExpr::Intrinsic { name, .. }, .. } if name == "rcl")));
    }

    #[test]
    fn test_lift_shld() {
        // 48 0f a4 d8 04 —" shld rax, rbx, 4
        let ops = lift64(&[0x48, 0x0f, 0xa4, 0xd8, 0x04]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { value: LlilExpr::Intrinsic { name, .. }, .. } if name == "shld")));
    }

    #[test]
    fn test_lift_shld_masks_variable_count() {
        // 48 0f a5 d8 —" shld rax, rbx, cl. The count is masked to 0–63 for a
        // 64-bit destination exactly like a single shift (AMD APM SHLD/SHRD
        // carry the same masking rule) — the raw cl used to be passed straight
        // into the opaque intrinsic.
        let ops = lift64(&[0x48, 0x0f, 0xa5, 0xd8]);
        let count_dbg = ops.iter().find_map(|o| match &o.instr {
            LlilInstruction::SetReg { value: LlilExpr::Intrinsic { name, args, .. }, .. }
                if name == "shld" => args.get(2).map(|c| format!("{c:?}")),
            _ => None,
        }).expect("shld intrinsic with 3 args");
        assert!(
            count_dbg.contains("And") && count_dbg.contains("63"),
            "shld count must be masked & 0x3f, got {count_dbg}"
        );
    }

    // â"€â"€ Control flow â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_jmp_rel() {
        // eb 05 —" jmp +5 from 0x1000 â†' 0x1007
        let ops = lift64(&[0xeb, 0x05]);
        match &ops[0].instr {
            LlilInstruction::JumpDest { dest } => {
                assert_eq!(
                    *dest,
                    LlilExpr::Const {
                        value: 0x1007,
                        size: Size::QWord
                    }
                );
            }
            other => panic!("expected Jump, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_jmp_indirect() {
        // ff e0 —" jmp rax
        let ops = lift64(&[0xff, 0xe0]);
        assert!(matches!(ops[0].instr, LlilInstruction::JumpTo { .. }));
    }

    #[test]
    fn test_lift_call_rel() {
        // e8 fb ff ff ff —" call -5 from 0x1000 â†' 0x1000
        let ops = lift64(&[0xe8, 0xfb, 0xff, 0xff, 0xff]);
        assert!(matches!(ops[0].instr, LlilInstruction::Call { .. }));
    }

    #[test]
    fn test_lift_ret() {
        let ops = lift64(&[0xc3]);
        assert!(matches!(ops[0].instr, LlilInstruction::Ret));
    }

    #[test]
    fn test_lift_jz_zf_predicate() {
        // 74 03 —" jz +3 from 0x1000 â†' 0x1005, fall-through 0x1002
        let ops = lift64(&[0x74, 0x03]);
        match &ops[0].instr {
            LlilInstruction::CondJump {
                cond,
                true_dest,
                false_dest,
            } => {
                assert_eq!(true_dest.0, 0x1005);
                assert_eq!(false_dest.0, 0x1002);
                assert!(
                    expr_reads_named_flag(cond, FLAG_ZF),
                    "jz must test ZF: {cond:?}"
                );
            }
            other => panic!("expected CondJump, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_jnz_zf_predicate() {
        // 75 03 —" jnz +3
        let ops = lift64(&[0x75, 0x03]);
        match &ops[0].instr {
            LlilInstruction::CondJump { cond, .. } => assert!(expr_reads_named_flag(cond, FLAG_ZF)),
            other => panic!("expected CondJump, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_jl_tests_sf_of() {
        // 7c 03 —" jl +3
        let ops = lift64(&[0x7c, 0x03]);
        match &ops[0].instr {
            LlilInstruction::CondJump { cond, .. } => {
                assert!(expr_reads_named_flag(cond, FLAG_SF));
                assert!(expr_reads_named_flag(cond, FLAG_OF));
            }
            other => panic!("expected CondJump, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_jbe_tests_cf_zf() {
        // 76 03 —" jbe +3
        let ops = lift64(&[0x76, 0x03]);
        match &ops[0].instr {
            LlilInstruction::CondJump { cond, .. } => {
                assert!(expr_reads_named_flag(cond, FLAG_CF));
                assert!(expr_reads_named_flag(cond, FLAG_ZF));
            }
            other => panic!("expected CondJump, got {other:?}"),
        }
    }

    #[test]
    fn test_all_jcc_lift_to_condjump() {
        // 16 short Jcc opcodes 0x70..=0x7f
        for opc in 0x70u8..=0x7f {
            let ops = lift64(&[opc, 0x02]);
            assert!(
                matches!(ops[0].instr, LlilInstruction::CondJump { .. }),
                "opcode {opc:#x} should be a CondJump"
            );
        }
    }

    #[test]
    fn test_lift_leave() {
        // c9 —" leave
        let ops = lift64(&[0xc9]);
        // SP = BP ; pop BP
        assert!(has_setreg_to(&ops, "rsp"));
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::Pop { dest: LlilRegister::Concrete(d), .. } if d == "rbp")));
    }

    #[test]
    fn test_lift_enter() {
        // c8 10 00 00 —" enter 0x10, 0
        let ops = lift64(&[0xc8, 0x10, 0x00, 0x00]);
        assert!(
            ops.iter()
                .any(|o| matches!(o.instr, LlilInstruction::Push { .. }))
        );
        assert!(has_setreg_to(&ops, "rbp"));
        assert!(has_setreg_to(&ops, "rsp"));
    }

    #[test]
    fn test_lift_loop() {
        // e2 fe —" loop -2
        let ops = lift64(&[0xe2, 0xfe]);
        assert!(has_setreg_to(&ops, "rcx"), "loop decrements rcx");
        assert!(
            ops.iter()
                .any(|o| matches!(o.instr, LlilInstruction::CondJump { .. }))
        );
    }

    // â"€â"€ SETcc / CMOVcc â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn cdqe_sign_extends_the_parent_not_a_separate_eax() {
        // 48 98 —" cdqe (sign-extend eax into rax).
        //
        // THE guarantee: the source is the SAME register family as the
        // destination. Building the implicit operand by hand made `eax` a
        // register nothing ever writes, so the HLIL emitted
        // `v8 = sub_X(); v8 = (int64_t)(int32_t)v9;` with `v9` undefined and
        // the sign extension of the call's return value silently LOST.
        let ops = lift64(&[0x48, 0x98]);
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, value, .. } => {
                assert_eq!(*dest, LlilRegister::Concrete("rax".into()));
                let text = format!("{value:?}");
                assert!(text.contains("rax"), "source is not the parent: {text}");
                assert!(
                    !text.contains("\"eax\""),
                    "source is still a separate eax: {text}"
                );
            }
            other => panic!("cdqe did not lift to SetReg: {other:?}"),
        }
    }

    /// `cmpxchg` legge il suo accumulatore come vista del PARENT, non come un
    /// registro a se'.
    ///
    /// Testo reale: `sample10_cs/sub_14006c020` fa `mov mem,%rax` a 0x14006c057
    /// e poi 4 x `lock cmpxchg %esi,mem`. Con l'accumulatore costruito a mano,
    /// `eax` era un registro che nessuno scriveva e B emetteva `uint32_t v9`
    /// **letto e mai scritto**, con 12 usi. Stessa classe del fix `cdqe`.
    ///
    /// ⚠ Il gate e' default OFF, quindi il test lo forza esplicitamente; e'
    /// anche la ragione per cui il caso a gate OFF sta in un test SEPARATO
    /// (`OnceLock` memoizza: due valori nello stesso processo non convivono).
    #[test]
    fn cmpxchg_reads_the_accumulator_through_the_parent() {
        if !implicit_acc_alias_enabled() {
            // Senza il gate questo comportamento non e' richiesto: il test
            // documenta il gate, non lo aggira.
            return;
        }
        // f0 0f b1 35 xx xx xx xx — lock cmpxchg %esi, disp32(%rip)
        let ops = lift64(&[0xf0, 0x0f, 0xb1, 0x35, 0x10, 0x00, 0x00, 0x00]);
        let text = format!("{ops:?}");
        assert!(
            text.contains("rax"),
            "l'accumulatore implicito non passa dal parent: {text}"
        );
    }

    /// NON-intervento: a 64 bit l'accumulatore E' gia' il parent, quindi non
    /// deve comparire nessuna vista ristretta.
    #[test]
    fn cmpxchg_at_64_bits_keeps_rax_itself() {
        // f0 48 0f b1 35 xx xx xx xx — lock cmpxchg %rsi, disp32(%rip)
        let ops = lift64(&[0xf0, 0x48, 0x0f, 0xb1, 0x35, 0x10, 0x00, 0x00, 0x00]);
        let text = format!("{ops:?}");
        assert!(text.contains("rax"), "manca l'accumulatore: {text}");
        assert!(
            !text.contains("\"eax\""),
            "a 64 bit non deve esistere una vista eax: {text}"
        );
    }

    /// `CDQ` (AT&T `cltd`, opcode 0x99) deve leggere l'accumulatore dal PARENT.
    ///
    /// ⚠ Il test asserisce nei DUE versi invece di auto-saltarsi quando il gate
    /// e' spento: un test che si salta «passa» senza provare nulla, e questo
    /// gate nasce di default OFF, quindi si sarebbe saltato SEMPRE.
    #[test]
    fn cdq_reads_the_accumulator_through_the_parent_when_gated() {
        let ops = lift64(&[0x99]);
        let text = format!("{ops:?}");
        if cdq_acc_alias_enabled() {
            assert!(
                text.contains("rax"),
                "col gate acceso l'accumulatore implicito deve passare dal parent: {text}"
            );
        } else {
            assert!(
                text.contains("eax"),
                "col gate spento resta la vista stretta: {text}"
            );
        }
    }

    /// `sqrtsd` scrive `dst = sqrt(src)`: la DESTINAZIONE non e' un ingresso.
    /// Prima veniva emesso `sqrt(dst, src)`, errore duro perche' `sqrt` collide
    /// con un builtin di gcc ad arita' 1.
    #[test]
    fn sqrtsd_passes_only_its_source() {
        // F2 0F 51 C1 — sqrtsd xmm0, xmm1
        let ops = lift64(&[0xF2, 0x0F, 0x51, 0xC1]);
        let text = format!("{ops:?}");
        assert!(text.contains("sqrt"), "manca l'intrinseco: {text}");
        let args = text.split("sqrt").nth(1).unwrap_or("");
        assert!(
            args.contains("xmm1"),
            "la sorgente deve essere passata: {text}"
        );
        // Un solo argomento: la destinazione NON deve comparire fra gli args.
        let fino_alla_virgola = args.split("result_size").next().unwrap_or("");
        assert!(
            !fino_alla_virgola.contains("xmm0"),
            "la destinazione NON e' un ingresso di sqrt: {text}"
        );
    }

    /// NON-intervento: per `addsd` la destinazione E' letta, quindi deve
    /// restare fra gli argomenti. Senza questo, «scarta l'operando 0» potrebbe
    /// essere generalizzato per errore, cambiando la semantica in silenzio.
    #[test]
    fn addsd_still_reads_its_destination() {
        // F2 0F 58 C1 — addsd xmm0, xmm1
        let ops = lift64(&[0xF2, 0x0F, 0x58, 0xC1]);
        let text = format!("{ops:?}");
        assert!(text.contains("xmm0"), "manca la destinazione letta: {text}");
        assert!(text.contains("xmm1"), "manca la sorgente: {text}");
    }

    /// La mappatura PURA segmento/larghezza, esaustiva e senza gate.
    ///
    /// ⚠ Il gate e' memoizzato con `OnceLock`: un processo solo NON puo' vedere
    /// entrambi i valori, quindi un test «nei due versi» sul gate sarebbe finto.
    /// Qui si asserisce cio' che e' davvero decidibile; la prova nei due versi
    /// e' di processo (`env -u` contro `=1`).
    #[test]
    fn segment_intrinsic_name_covers_both_segments_and_every_width() {
        use iced_x86::Register;
        for (seg, atteso) in [
            (Register::GS, ["__readgsbyte", "__readgsword", "__readgsdword", "__readgsqword"]),
            (Register::FS, ["__readfsbyte", "__readfsword", "__readfsdword", "__readfsqword"]),
        ] {
            for (i, size) in [Size::Byte, Size::Word, Size::DWord, Size::QWord].iter().enumerate() {
                assert_eq!(
                    X86Lifter::segment_intrinsic_name(seg, *size),
                    Some(atteso[i]),
                    "mappatura sbagliata per {seg:?}/{size:?}"
                );
            }
        }
        // Un registro NON di segmento non deve MAI produrre un intrinseco:
        // e' cio' che impedisce di dirottare i load ordinari.
        for seg in [Register::None, Register::DS, Register::ES, Register::CS, Register::SS] {
            assert_eq!(
                X86Lifter::segment_intrinsic_name(seg, Size::QWord),
                None,
                "{seg:?} non e' GS/FS e non deve diventare un intrinseco"
            );
        }
    }

    /// Il gate governa DAVVERO il sito di lift, nel ramo in cui questo processo
    /// si trova. Non si auto-salta: asserisce in entrambi i rami.
    #[test]
    fn gs_prefixed_load_follows_the_segment_gate() {
        // 65 48 8B 04 25 30 00 00 00 — mov rax, gs:[0x30]
        let ops = lift64(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00]);
        let text = format!("{ops:?}");
        if X86Lifter::segment_intrinsic_enabled() {
            assert!(
                text.contains("__readgsqword"),
                "col gate acceso il load con prefisso GS deve diventare un intrinseco: {text}"
            );
        } else {
            assert!(
                text.contains("Load"),
                "col gate spento deve restare un Load ordinario: {text}"
            );
            assert!(
                !text.contains("__readgs"),
                "col gate spento non deve comparire alcun intrinseco: {text}"
            );
        }
    }

    /// NON-intervento: `CQO` e' gia' a 64 bit, `rax` E' il parent.
    #[test]
    fn cqo_keeps_rax_itself() {
        // 48 99 — cqo
        let ops = lift64(&[0x48, 0x99]);
        let text = format!("{ops:?}");
        assert!(text.contains("rax"), "manca l'accumulatore: {text}");
        assert!(
            !text.contains("\"eax\""),
            "a 64 bit non deve esistere una vista eax: {text}"
        );
    }

    #[test]
    fn test_lift_sete() {
        // 0f 94 c0 —" sete al
        let ops = lift64(&[0x0f, 0x94, 0xc0]);
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, value: src, .. } => {
                // Con l'aliasing 8/16 bit acceso di default, scrivere `al` e' un
                // read-modify-write del PARENT `rax`: i bit alti sopravvivono.
                // L'invariante da difendere non e' il NOME del destinatario ma
                // che la scrittura raggiunga la famiglia giusta e dipenda da ZF.
                assert_eq!(*dest, LlilRegister::Concrete("rax".into()));
                assert!(
                    expr_reads_named_flag(src, FLAG_ZF),
                    "sete should depend on ZF"
                );
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_all_setcc() {
        // 0f 90..0f 9f —" setcc al
        for opc in 0x90u8..=0x9f {
            let ops = lift64(&[0x0f, opc, 0xc0]);
            assert!(
                ops.iter()
                    .any(|o| matches!(o.instr, LlilInstruction::SetReg { .. })),
                "setcc {opc:#x} should set a register"
            );
        }
    }

    #[test]
    fn test_lift_cmove() {
        // 48 0f 44 c3 —" cmove rax, rbx
        let ops = lift64(&[0x48, 0x0f, 0x44, 0xc3]);
        match &ops[0].instr {
            LlilInstruction::SetReg { dest, value: src, .. } => {
                assert_eq!(*dest, LlilRegister::Concrete("rax".into()));
                assert!(
                    matches!(src, LlilExpr::CondExpr { .. }),
                    "cmov should be a CondExpr"
                );
            }
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    // â"€â"€ Flag manipulation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_clc_stc() {
        let clc = lift64(&[0xf8]);
        assert!(clc.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 0, .. } } if flag == FLAG_CF)));
        let stc = lift64(&[0xf9]);
        assert!(stc.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 1, .. } } if flag == FLAG_CF)));
    }

    #[test]
    fn test_lift_cld_std() {
        let cld = lift64(&[0xfc]);
        assert!(cld.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 0, .. } } if flag == FLAG_DF)));
        let std = lift64(&[0xfd]);
        assert!(std.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Const { value: 1, .. } } if flag == FLAG_DF)));
    }

    #[test]
    fn test_lift_cmc() {
        let ops = lift64(&[0xf5]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetFlag { name: flag, src: LlilExpr::Xor(..) } if flag == FLAG_CF)));
    }

    #[test]
    fn test_lift_sahf() {
        let ops = lift64(&[0x9e]);
        // SAHF writes 5 arithmetic flags.
        for f in [FLAG_CF, FLAG_PF, FLAG_AF, FLAG_ZF, FLAG_SF] {
            assert_eq!(count_flag_writes(&ops, f), 1, "sahf must set {f}");
        }
    }

    // â"€â"€ System / misc â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    /// `CPUID` writes EAX, EBX, ECX and EDX. This test used to assert only that
    /// a bare `cpuid` intrinsic STATEMENT existed, which pinned the
    /// under-modelling the register-effect oracle later flagged: with no
    /// writes, a decompiler believed all four registers kept their old values.
    fn test_lift_cpuid() {
        let ops = lift64(&[0x0f, 0xa2]);
        let rendered = ops
            .iter()
            .map(|o| format!("{:?}", o.instr))
            .collect::<Vec<_>>()
            .join("
");
        for reg in ["eax", "ebx", "ecx", "edx"] {
            assert!(
                rendered.contains(&format!("cpuid_{reg}")),
                "CPUID must write {reg}:
{rendered}"
            );
        }
    }

    #[test]
    fn test_lift_rdtsc() {
        let ops = lift64(&[0x0f, 0x31]);
        assert!(has_setreg_to(&ops, "eax"));
        assert!(has_setreg_to(&ops, "edx"));
    }

    /// RDMSR (0F 32): per the AMD APM vol. 3 (pub 24594 rev 3.34, "RDMSR —
    /// Read Model-Specific Register"): "Loads the contents of a 64-bit
    /// model-specific register (MSR) specified in the ECX register into
    /// registers EDX:EAX." Lifting it as an inert intrinsic drops both
    /// writebacks, so a later read of EAX/EDX would const-propagate the
    /// pre-RDMSR value straight across the instruction. The ECX (MSR
    /// number) dependency must be recorded in the intrinsic args or two
    /// RDMSRs of different MSRs become CSE-identical values.
    #[test]
    fn test_lift_rdmsr_writes_edx_eax_from_ecx() {
        let ops = lift64(&[0x0f, 0x32]);
        assert!(has_setreg_to(&ops, "eax"), "rdmsr must define EAX");
        assert!(has_setreg_to(&ops, "edx"), "rdmsr must define EDX");
        // Every rdmsr result value must depend on ECX — asserted on the STRUCTURE,
        // not on the debug text. `contains("ecx")` was satisfied by the substring
        // appearing anywhere (an unrelated operand, a nested register, the
        // intrinsic's own name); `reads_reg32` asks the real question, "is this
        // expression a read of ECX", and stays exact about which register.
        for o in &ops {
            if let LlilInstruction::SetReg { value, .. } = &o.instr {
                let args = match computed_value(value) {
                    LlilExpr::Intrinsic { args, .. } => args,
                    other => panic!("rdmsr result must be an intrinsic: {other:?}"),
                };
                assert!(
                    args.iter().any(|a| reads_reg32(a, "ecx")),
                    "rdmsr result must take ECX as an argument: {value:?}"
                );
            }
        }
    }

    /// XLAT/XLATB (D7): per the AMD APM vol. 3 (pub 24594 rev 3.34, "XLAT —
    /// Translate Table Index"): "Uses the unsigned integer in the AL register
    /// as an offset into a table and copies the contents of the table entry
    /// at that location to the AL register. The instruction uses seg:[rBX]
    /// as the base address of the table." An inert-intrinsic lift drops the
    /// AL writeback and the rBX/AL dependencies.
    #[test]
    fn test_lift_xlat_writes_al_from_rbx_al() {
        let ops = lift64(&[0xd7]);
        // Aliasing 8/16 acceso: la definizione di AL arriva sul parent `rax`.
        assert!(has_setreg_to(&ops, "rax"), "xlat must define the AL family");
        for o in &ops {
            if let LlilInstruction::SetReg { value, .. } = &o.instr {
                let dbg = format!("{value:?}");
                assert!(dbg.contains("rbx") && dbg.contains("al"),
                    "xlat result must depend on rBX and AL: {dbg}");
            }
        }
        // 32-bit mode: table base is EBX.
        let ops32 = lift32(&[0xd7]);
        // Anche a 32 bit `al` e' aliasato: `gpr_narrow_parent` porta al parent
        // a 64 bit, che resta il portatore della famiglia AL.
        assert!(has_setreg_to(&ops32, "rax"), "xlat a 32 bit definisce la famiglia AL");
        let dbg: String = ops32.iter().map(|o| format!("{:?}", o.instr)).collect();
        assert!(dbg.contains("ebx"), "32-bit xlat table base is EBX: {dbg}");
    }

    #[test]
    fn test_lift_syscall() {
        let ops = lift64(&[0x0f, 0x05]);
        assert!(matches!(ops[0].instr, LlilInstruction::SysCall));
    }

    #[test]
    fn test_lift_int3() {
        let ops = lift64(&[0xcc]);
        assert!(matches!(ops[0].instr, LlilInstruction::Breakpoint));
    }

    #[test]
    fn test_lift_ud2() {
        let ops = lift64(&[0x0f, 0x0b]);
        assert!(matches!(ops[0].instr, LlilInstruction::Trap { .. }));
    }

    #[test]
    fn test_lift_int_imm() {
        // cd 80 —" int 0x80
        let ops = lift64(&[0xcd, 0x80]);
        assert!(matches!(ops[0].instr, LlilInstruction::Trap { code: 0x80 }));
    }

    // â"€â"€ String ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_movs() {
        // a4 —" movsb
        let ops = lift64(&[0xa4]);
        assert!(
            ops.iter()
                .any(|o| matches!(o.instr, LlilInstruction::Store { .. }))
        );
        assert!(has_setreg_to(&ops, "rsi"));
        assert!(has_setreg_to(&ops, "rdi"));
    }

    #[test]
    fn test_lift_stos() {
        // aa —" stosb
        let ops = lift64(&[0xaa]);
        assert!(
            ops.iter()
                .any(|o| matches!(o.instr, LlilInstruction::Store { .. }))
        );
        assert!(has_setreg_to(&ops, "rdi"));
    }

    #[test]
    fn test_lift_lods() {
        // ac —" lodsb
        let ops = lift64(&[0xac]);
        // `al` e' aliasato sul parent: la definizione arriva su `rax` (RMW).
        assert!(has_setreg_to(&ops, "rax"), "lodsb deve definire la famiglia AL");
        assert!(has_setreg_to(&ops, "rsi"));
    }

    #[test]
    fn test_lift_scas_sets_flags() {
        // ae —" scasb
        let ops = lift64(&[0xae]);
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        assert!(has_setreg_to(&ops, "rdi"));
    }

    #[test]
    fn test_lift_cmps_sets_flags() {
        // a6 —" cmpsb
        let ops = lift64(&[0xa6]);
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        assert!(has_setreg_to(&ops, "rsi"));
        assert!(has_setreg_to(&ops, "rdi"));
    }

    // â"€â"€ Bit ops â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_bsf_sets_zf() {
        // 48 0f bc c3 —" bsf rax, rbx
        let ops = lift64(&[0x48, 0x0f, 0xbc, 0xc3]);
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { value: LlilExpr::Intrinsic { name, .. }, .. } if name == "bsf")));
    }

    #[test]
    fn test_lift_bt_sets_cf() {
        // 48 0f a3 d8 —" bt rax, rbx
        let ops = lift64(&[0x48, 0x0f, 0xa3, 0xd8]);
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    #[test]
    fn test_lift_bts_modifies() {
        // 48 0f ab d8 —" bts rax, rbx
        let ops = lift64(&[0x48, 0x0f, 0xab, 0xd8]);
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg {
                value: LlilExpr::Or(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lift_bswap() {
        // 48 0f c8 —" bswap rax: now a concrete Or/Shl/Shr byte permutation
        // (8 lanes), no longer an opaque intrinsic.
        let ops = lift64(&[0x48, 0x0f, 0xc8]);
        let val = ops
            .iter()
            .find_map(|o| match &o.instr {
                LlilInstruction::SetReg { value, .. } => Some(value),
                _ => None,
            })
            .expect("bswap writes its operand");
        let s = format!("{val:?}");
        assert!(!s.contains("Intrinsic"), "bswap must be concrete");
        assert!(s.matches("ShlT").count() >= 8, "one placed byte per lane");
    }

    #[test]
    fn test_lift_popcnt() {
        // f3 48 0f b8 c3 —" popcnt rax, rbx
        let ops = lift64(&[0xf3, 0x48, 0x0f, 0xb8, 0xc3]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { value: LlilExpr::Intrinsic { name, .. }, .. } if name == "popcnt")));
    }

    // â"€â"€ SSE / MMX moves â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_movaps() {
        // 0f 28 c1 —" movaps xmm0, xmm1
        let ops = lift64(&[0x0f, 0x28, 0xc1]);
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. } if d == "xmm0")));
    }

    #[test]
    fn test_lift_movdqa() {
        // 66 0f 6f c1 —" movdqa xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x6f, 0xc1]);
        assert!(has_setreg_to(&ops, "xmm0"));
    }

    #[test]
    fn test_lift_movd_gpr_to_xmm() {
        // 66 0f 6e c0 —" movd xmm0, eax
        let ops = lift64(&[0x66, 0x0f, 0x6e, 0xc0]);
        assert!(has_setreg_to(&ops, "xmm0"));
    }

    #[test]
    fn test_lift_movq_xmm_store() {
        // 66 0f d6 03 —" movq [rbx], xmm0
        let ops = lift64(&[0x66, 0x0f, 0xd6, 0x03]);
        assert!(
            ops.iter()
                .any(|o| matches!(o.instr, LlilInstruction::Store { .. }))
        );
    }

    // â"€â"€ 32-bit-mode parity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_32bit_push() {
        // 55 —" push ebp (32-bit)
        let ops = lift32(&[0x55]);
        match &ops[0].instr {
            LlilInstruction::Push { size, src } => {
                assert_eq!(*size, Size::DWord);
                assert_eq!(
                    *src,
                    LlilExpr::RegisterRef {
                        reg: LlilRegister::Concrete("ebp".into()),
                        size: Size::DWord
                    }
                );
            }
            other => panic!("expected Push, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_32bit_add() {
        // 01 d8 —" add eax, ebx (32-bit)
        let ops = lift32(&[0x01, 0xd8]);
        assert!(has_setreg_to(&ops, "eax"));
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    // â"€â"€ memory addressing with index*scale+disp â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lift_mem_index_scale() {
        // 48 8b 04 cb —" mov rax, [rbx + rcx*8]
        let ops = lift64(&[0x48, 0x8b, 0x04, 0xcb]);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Load { addr, .. },
                ..
            } => {
                // address contains base + index*scale â†' an Add containing a Mul
                let s = format!("{addr}");
                assert!(s.contains('+'), "address should be additive: {s}");
                assert!(s.contains('*'), "address should contain scaling: {s}");
            }
            other => panic!("expected SetReg/Load, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_rip_relative() {
        // 48 8b 05 10 00 00 00 —" mov rax, [rip+0x10]
        let ops = lift64(&[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00]);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Load { addr, .. },
                ..
            } => {
                // RIP-relative resolves to an absolute constant
                assert!(
                    matches!(**addr, LlilExpr::Const { .. }),
                    "rip-relative should be an absolute Const: {addr:?}"
                );
            }
            other => panic!("expected SetReg/Load, got {other:?}"),
        }
    }

    // â"€â"€ Unknown instruction falls back to Unimplemented â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_fld_st0_is_implemented() {
        // d9 c0 — fld st(0). Previously fell back to `Unimplemented`; now
        // lifted as a real `fld` intrinsic. Fld's decoded operand 0 is its
        // *source* (memory or ST(i)), not its destination (always the
        // implicit ST(0) after push) — `write_operand(iced, 0, ...)` would
        // incorrectly write back into the source, so Fld intentionally
        // stays on the statement-level `lift_fpu_generic` path (honest
        // discard, not a wrong write) rather than `lift_fpu_write`.
        let ops = lift64(&[0xd9, 0xc0]);
        assert!(matches!(
            ops[0].instr,
            LlilInstruction::Intrinsic { ref name, .. } if name == "fld"
        ));
    }

    /// `dispatch_fallback` must emit `Unimplemented` (tagged with the mnemonic)
    /// for anything with no lifting arm, rather than silently emitting nothing.
    ///
    /// This test has twice been invalidated by its own example getting
    /// implemented — first `getsec` (0f 37), then `salc` (d6) — so it no longer
    /// hard-codes one. It builds the fallback case directly instead, which
    /// stays valid even at 100% mnemonic coverage: `Mnemonic::INVALID` has no
    /// dispatch arm and no condition code, so it exercises exactly the final
    /// `_ => dispatch_fallback` path and its `Unimplemented` emission.
    #[test]
    fn test_unknown_falls_back() {
        // A default-constructed instruction has mnemonic INVALID: no dispatch
        // arm, no condition code — exactly the final `_ => dispatch_fallback`
        // path.
        let iced = IcedInstruction::default();
        assert_eq!(
            iced.mnemonic(),
            Mnemonic::INVALID,
            "precondition: this test relies on a default instruction being INVALID"
        );
        let ops = lift_instr(32, &iced);

        assert_eq!(ops.len(), 1, "fallback must emit exactly one instruction");
        match &ops[0].instr {
            LlilInstruction::Unimplemented { mnemonic } => {
                assert!(
                    mnemonic.contains("INVALID"),
                    "Unimplemented must carry the mnemonic name so analysis can \
                     report what was skipped, got {mnemonic:?}"
                );
            }
            other => panic!("expected Unimplemented, got {other:?}"),
        }
    }

    /// The gate is OPT-IN and must stay OFF unless explicitly asked for.
    ///
    /// This is the REGOLA #28 guard in its cheapest form: while this returns
    /// `false` the terminal `dispatch_fallback` arm cannot emit anything it did
    /// not emit before, so path A is byte-identical *by construction* and needs
    /// no corpus diff to prove it.
    #[test]
    fn il_lift_fallback_gate_is_opt_in() {
        // Control group: the variable must be UNSET, not empty — an empty value
        // is the shell idiom for "unset", and for this OPT-IN gate it must read
        // as OFF too (the mirror-image mistake of the default-ON gates above,
        // where `VAR=` wrongly read as ON and ran a control group with the
        // feature enabled).
        unsafe { std::env::remove_var("RUSTRE_X86_IL_LIFT_FALLBACK") };
        assert!(!il_lift_fallback_enabled(), "unset must read as OFF");
        unsafe { std::env::set_var("RUSTRE_X86_IL_LIFT_FALLBACK", "") };
        assert!(!il_lift_fallback_enabled(), "empty must read as OFF");
        unsafe { std::env::set_var("RUSTRE_X86_IL_LIFT_FALLBACK", "0") };
        assert!(!il_lift_fallback_enabled(), "\"0\" must read as OFF");
        unsafe { std::env::set_var("RUSTRE_X86_IL_LIFT_FALLBACK", "1") };
        assert!(il_lift_fallback_enabled(), "\"1\" must read as ON");
        unsafe { std::env::set_var("RUSTRE_X86_IL_LIFT_FALLBACK", "true") };
        assert!(il_lift_fallback_enabled(), "\"true\" must read as ON");
        unsafe { std::env::remove_var("RUSTRE_X86_IL_LIFT_FALLBACK") };
    }

    /// The delegation is NOT dead code: given bytes `rustre-il-lift` models,
    /// `try_il_lift_fallback` really re-encodes, really lifts, and really
    /// EMITS the converted effects into the `EmitCtx` (rather than computing
    /// them and dropping them, which is what the pre-existing test-only bridge
    /// usage did).
    ///
    /// The dispatcher never routes `add rax, rbx` here — it has its own arm —
    /// so this exercises the helper directly. That is the point: it isolates
    /// "does the wiring work" from "does the wiring ever fire", which the
    /// sweep below measures separately.
    #[test]
    fn il_lift_fallback_delegation_emits_into_the_context() {
        // 48 01 d8 — ADD RAX, RBX
        let bytes = [0x48u8, 0x01, 0xd8];
        let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let iced = dec.decode();
        assert!(!iced.is_invalid());

        let lifter = X86Lifter::new(64);
        let mut out = Vec::new();
        let mut ctx = EmitCtx {
            address: Address::new(0x1000),
            size: iced.len(),
            out: &mut out,
        };
        let n = lifter
            .try_il_lift_fallback(&iced, &mut ctx)
            .expect("re-encode + delegate must succeed for ADD RAX, RBX");
        assert!(n > 0, "delegation produced no effects");
        assert_eq!(n, out.len(), "every counted effect must be EMITTED");
        assert!(
            !out.iter()
                .any(|o| matches!(o.instr, LlilInstruction::Unimplemented { .. })),
            "delegated output must not be Unimplemented"
        );
    }

    /// `iced_encoded_bytes` must round-trip, otherwise the delegation would be
    /// lifting a *different* instruction than the dispatcher was handed.
    #[test]
    fn iced_encoded_bytes_round_trips() {
        for bytes in [
            &[0x48u8, 0x01, 0xd8][..], // add rax, rbx
            &[0x0f, 0x05][..],         // syscall
            &[0x8d, 0x04, 0x18][..],   // lea eax, [rax+rbx]
        ] {
            let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
            let iced = dec.decode();
            let enc = iced_encoded_bytes(&iced).expect("must encode");
            let mut dec2 = Decoder::with_ip(64, &enc, 0x1000, DecoderOptions::NONE);
            let round = dec2.decode();
            assert_eq!(round.code(), iced.code(), "re-encode changed the opcode");
        }
        // `Mnemonic::INVALID` has no encoding — the helper must say so instead
        // of fabricating bytes.
        assert!(iced_encoded_bytes(&IcedInstruction::default()).is_none());
    }

    /// MEASURED, not assumed: how often does the delegation actually fire?
    ///
    /// Sweep of the 1-/2-/3-byte opcode space in 32- and 64-bit mode. Result at
    /// the time of writing: exactly **1 distinct mnemonic** (`Reservednop`)
    /// reaches the terminal `Unimplemented` arm, and `rustre-il-lift` adds
    /// **0** useful effects for it — the dispatcher in this file already covers
    /// everything `rustre_il_lift::X86Lifter::decode_and_lift` models
    /// (`Mov/Add/Sub/And/Or/Xor/Push/Pop/Call/Ret/Jmp/Jcc/Cmp/Test/Lea/Nop/
    /// Syscall`), so the delegate can only ever answer with its own empty
    /// `_ =>` intrinsic, which is deliberately skipped.
    ///
    /// So the gate is WIRED and MEASURED AT ZERO, and is kept OFF and
    /// documented rather than deleted (same treatment as
    /// `RUSTRE_X86_MUL_ACC_ALIAS`). A future session that widens
    /// `rustre-il-lift`'s mnemonic table can re-run this test to see the number
    /// move; until then the front is closed WITH A NUMBER.
    #[test]
    fn il_lift_fallback_delegation_measured_on_the_opcode_sweep() {
        use std::collections::BTreeMap;
        let mut unimpl: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        // Denominator. A zero numerator is only a datum if the sweep really
        // decoded something (REGOLA: uno zero da un comando fallito non e' un
        // dato) — asserted at the end.
        let mut decoded = 0usize;
        for bits in [64u32, 32] {
            for b0 in 0u16..=255 {
                for b1 in 0u16..=255 {
                    let bytes = [
                        b0 as u8, b1 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ];
                    let mut dec = Decoder::with_ip(bits, &bytes, 0x1000, DecoderOptions::NONE);
                    let iced = dec.decode();
                    if iced.is_invalid() {
                        continue;
                    }
                    decoded += 1;
                    let mut lifter = X86Lifter::new(bits);
                    let ops = lifter.lift(&iced, Address::new(0x1000), iced.len());
                    for o in &ops {
                        if let LlilInstruction::Unimplemented { mnemonic } = &o.instr {
                            unimpl
                                .entry(format!("{bits}:{mnemonic}"))
                                .or_insert_with(|| bytes[..iced.len()].to_vec());
                        }
                    }
                }
            }
        }
        // 3-byte sweep over the escape / VEX / EVEX / REX / mandatory-prefix
        // maps, where most of the not-yet-lifted mnemonics actually live.
        for bits in [64u32, 32] {
            for p in [
                0x0Fu8, 0xC4, 0xC5, 0x62, 0x66, 0xF2, 0xF3, 0x48, 0x4C, 0xD8, 0xD9, 0xDA, 0xDB,
                0xDC, 0xDD, 0xDE, 0xDF,
            ] {
                for b1 in 0u16..=255 {
                    for b2 in 0u16..=255 {
                        let bytes = [
                            p, b1 as u8, b2 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ];
                        let mut dec = Decoder::with_ip(bits, &bytes, 0x1000, DecoderOptions::NONE);
                        let iced = dec.decode();
                        if iced.is_invalid() {
                            continue;
                        }
                        decoded += 1;
                        let mut lifter = X86Lifter::new(bits);
                        let ops = lifter.lift(&iced, Address::new(0x1000), iced.len());
                        for o in &ops {
                            if let LlilInstruction::Unimplemented { mnemonic } = &o.instr {
                                unimpl
                                    .entry(format!("{bits}:{mnemonic}"))
                                    .or_insert_with(|| bytes[..iced.len()].to_vec());
                            }
                        }
                    }
                }
            }
        }
        println!("IL_LIFT_FALLBACK decoded={decoded} unimpl_distinct={}", unimpl.len());
        for (k, v) in &unimpl {
            println!("IL_LIFT_FALLBACK unimpl {k} bytes={v:02x?}");
        }
        let mut wins = 0usize;
        for (k, bytes) in &unimpl {
            let mut dec = Decoder::with_ip(
                if k.starts_with("64") { 64 } else { 32 },
                bytes,
                0x1000,
                DecoderOptions::NONE,
            );
            let iced = dec.decode();
            let enc = iced_encoded_bytes(&iced);
            let lifter = rustre_il_lift::X86Lifter::new(if k.starts_with("64") { 64 } else { 32 });
            let effs = enc
                .as_ref()
                .and_then(|b| lifter.decode_and_lift(b, iced.ip()));
            let useful = effs.as_ref().map_or(0, |v| {
                v.iter()
                    .filter(|e| {
                        !matches!(e, rustre_il_lift::Effect::Intrinsic { args, .. } if args.is_empty())
                    })
                    .count()
            });
            if useful > 0 {
                wins += 1;
                println!("IL_LIFT_FALLBACK win {k} -> {useful} effects");
            }
        }
        println!(
            "IL_LIFT_FALLBACK wins={wins}/{} (denominator: {decoded} decoded)",
            unimpl.len()
        );

        // Guard the DENOMINATOR, not the numerator: `wins` is allowed to grow
        // (that would be the front reopening, i.e. good news, and failing on
        // good news is how a metric gets ignored). What must never silently
        // happen is the sweep going vacuous and reporting a hollow zero.
        assert!(
            decoded > 10_000,
            "sweep went vacuous: only {decoded} instructions decoded"
        );
        assert!(
            !unimpl.is_empty(),
            "no instruction reached the terminal Unimplemented arm — the probe \
             no longer measures the path it claims to measure"
        );
        // Anchor the one mnemonic known to reach the fallback, so a change in
        // dispatcher coverage is visible here rather than only in the corpus.
        assert!(
            unimpl.keys().any(|k| k.contains("Reservednop")),
            "expected `Reservednop` among the fallback mnemonics, got {:?}",
            unimpl.keys().collect::<Vec<_>>()
        );
    }

    /// The plan that produced this wiring also asked to reroute the AMD
    /// broadcast/serialisation arms (`invlpgb`, `tlbsync`, `mcommit`,
    /// `wrmsrns`) through `system_insn_lifter::SystemInsnLifter`, on the
    /// premise that it would "replace result-less intrinsics with effects that
    /// really write the registers".
    ///
    /// MEASURED AND FALSE: `SystemInsnLifter::lift` has no arm for any of the
    /// four, so it answers with its synthetic `__sys_<m>` catch-all. Routing
    /// them there would rename `invlpgb` to `__sys_invlpgb`, inject a synthetic
    /// address argument, and still write no register — a naming regression sold
    /// as an integration. The arms in `dispatch` are therefore left alone, and
    /// this test pins the reason so the idea is not re-attempted from the same
    /// false premise.
    #[test]
    fn system_insn_lifter_has_no_arm_for_the_amd_broadcast_mnemonics() {
        use crate::system_insn_lifter::SystemInsnLifter;
        let sys = SystemInsnLifter::new_64();
        for m in ["invlpgb", "tlbsync", "mcommit", "wrmsrns"] {
            let effects = sys.lift(m, &[], 0x1000);
            assert_eq!(effects.len(), 1, "{m}: expected the catch-all shape");
            match &effects[0] {
                rustre_il_lift::Effect::Intrinsic { name, .. } => assert_eq!(
                    name,
                    &format!("__sys_{m}"),
                    "{m}: expected the synthetic catch-all, not a real model"
                ),
                other => panic!("{m}: unexpected effect {other:?}"),
            }
            assert!(
                !effects.iter().any(|e| matches!(
                    e,
                    rustre_il_lift::Effect::RegWrite { .. } | rustre_il_lift::Effect::MemWrite { .. }
                )),
                "{m}: the delegate writes no register/memory, so it cannot be an upgrade"
            );
        }
    }

    // â"€â"€ X86Arch::lift integration â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_arch_lift_integration() {
        let arch = crate::X86Arch::new_64bit();
        let (ops, len) = arch
            .lift(Address::new(0x1000), &[0x48, 0x01, 0xd8])
            .unwrap();
        assert_eq!(len, 3);
        assert!(!ops.is_empty());
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
    }

    /// Local helper: does an expression tree reference flag `name`?
    fn expr_reads_named_flag(e: &LlilExpr, name: &str) -> bool {
        // Reuse the public read-flag logic by wrapping in a throwaway SetReg.
        let probe = LlilInstruction::SetReg {
            dest: LlilRegister::Temporary(0),
            size: Size::Byte,
            value: e.clone(),
        };
        probe.reads_flag(name)
    }

    // ── AVX / AVX2 lift arms ─────────────────────────────────────────────

    /// Build a lifted instruction sequence directly from an `iced_x86`
    /// [`IcedInstruction`], bypassing the byte encoder/decoder (VEX raw byte
    /// sequences are fiddly to hand-encode correctly).
    fn lift_instr(bits: u32, iced: &IcedInstruction) -> Vec<LlilAnnotatedInstr> {
        let mut lifter = X86Lifter::new(bits);
        lifter.lift(iced, Address::new(0x1000), iced.len())
    }

    fn is_unimplemented(ops: &[LlilAnnotatedInstr]) -> bool {
        ops.iter()
            .any(|o| matches!(o.instr, LlilInstruction::Unimplemented { .. }))
    }

    #[test]
    fn test_lift_vmovaps_ymm() {
        let iced =
            IcedInstruction::with2(Code::VEX_Vmovaps_ymm_ymmm256, Register::YMM0, Register::YMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "ymm0"));
    }

    #[test]
    fn test_lift_vaddps_ymm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vaddps_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        match &ops[0].instr {
            LlilInstruction::SetReg {
                dest: LlilRegister::Concrete(d),
                value: LlilExpr::AddT(..),
                ..
            } => assert_eq!(d, "ymm0"),
            other => panic!("expected SetReg/AddT, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vaddpd_ymm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vaddpd_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vsubps_ymm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vsubps_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::SubT(..),
                ..
            } => {}
            other => panic!("expected SetReg/SubT, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vmulps_ymm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vmulps_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::MulT(..),
                ..
            } => {}
            other => panic!("expected SetReg/MulT, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vpxor_ymm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vpxor_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Xor(..),
                ..
            } => {}
            other => panic!("expected SetReg/Xor, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vpand_vpor_vpandn_ymm() {
        for (code, expect_not) in [
            (Code::VEX_Vpand_ymm_ymm_ymmm256, false),
            (Code::VEX_Vpor_ymm_ymm_ymmm256, false),
            (Code::VEX_Vpandn_ymm_ymm_ymmm256, true),
        ] {
            let iced = IcedInstruction::with3(code, Register::YMM0, Register::YMM1, Register::YMM2)
                .unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            if expect_not {
                match &ops[0].instr {
                    LlilInstruction::SetReg {
                        value: LlilExpr::And(a, ..),
                        ..
                    } => assert!(matches!(**a, LlilExpr::Not(..))),
                    other => panic!("expected SetReg/And(Not,_), got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn test_lift_vpshufb_ymm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vpshufb_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Intrinsic { name, .. },
                ..
            } => assert_eq!(name, "pshufb"),
            other => panic!("expected SetReg/Intrinsic(pshufb), got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vpaddb_vpsubb_ymm() {
        let add = IcedInstruction::with3(
            Code::VEX_Vpaddb_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &add);
        assert!(matches!(
            &ops[0].instr,
            LlilInstruction::SetReg {
                value: LlilExpr::AddT(..),
                ..
            }
        ));

        let sub = IcedInstruction::with3(
            Code::VEX_Vpsubb_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &sub);
        assert!(matches!(
            &ops[0].instr,
            LlilInstruction::SetReg {
                value: LlilExpr::SubT(..),
                ..
            }
        ));
    }

    // ── AVX2 YMM exact-width checks ─────────────────────────────────────

    #[test]
    fn test_lift_vmovaps_ymm_is_yword_not_saturated_oword() {
        // Regression test: before `Size::YWord` existed, YMM operands
        // saturated to `Size::OWord` (128-bit); they must now round-trip at
        // their real 256-bit width.
        let iced =
            IcedInstruction::with2(Code::VEX_Vmovaps_ymm_ymmm256, Register::YMM0, Register::YMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg { size, .. } => assert_eq!(*size, Size::YWord),
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vaddps_xmm_stays_oword() {
        // VEX.128 forms of the same mnemonics must still use `Size::OWord`
        // (128-bit), not `Size::YWord`.
        let iced = IcedInstruction::with3(
            Code::VEX_Vaddps_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg { size, .. } => assert_eq!(*size, Size::OWord),
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vaddps_ymm_is_yword() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vaddps_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg { size, .. } => assert_eq!(*size, Size::YWord),
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vpxord_vpord_vpandd_zmm_are_zword() {
        for code in [
            Code::EVEX_Vpxord_zmm_k1z_zmm_zmmm512b32,
            Code::EVEX_Vpord_zmm_k1z_zmm_zmmm512b32,
            Code::EVEX_Vpandd_zmm_k1z_zmm_zmmm512b32,
        ] {
            let iced = IcedInstruction::with3(code, Register::ZMM0, Register::ZMM1, Register::ZMM2)
                .unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            match &ops[0].instr {
                LlilInstruction::SetReg { size, .. } => assert_eq!(*size, Size::ZWord),
                other => panic!("{code:?}: expected SetReg, got {other:?}"),
            }
        }
    }

    /// Regression guard for a family of mnemonics that were missing from
    /// dispatch arms whose *sibling* members were already present — e.g. the
    /// `pmin` arm listed Vpminsb/ud/sd/uw but not Vpminsq, and the `vperm` arm
    /// listed Vpermd/w/q/ps/pd but not Vpermb. Unlike the genuinely obscure
    /// legacy tail (Cyrix, KNC), these DO appear in real compiler output, so
    /// silently falling back to `Unimplemented` was a real fidelity loss.
    #[test]
    fn test_lift_family_sibling_mnemonics_are_dispatched() {
        // (code, expected destination register) — 3-operand register forms.
        let cases: &[(Code, Register)] = &[
            // AVX-512VBMI byte-granularity permute (sibling of Vpermw/Vpermd).
            (Code::EVEX_Vpermb_zmm_k1z_zmm_zmmm512, Register::ZMM0),
            // AVX-512F qword signed min (sibling of Vpminsd/Vpminuq).
            (Code::EVEX_Vpminsq_zmm_k1z_zmm_zmmm512b64, Register::ZMM0),
            // AVX-512-FP16 complex-arithmetic members whose siblings were wired.
            (Code::EVEX_Vfcmaddcph_zmm_k1z_zmm_zmmm512b32_er, Register::ZMM0),
            (Code::EVEX_Vfmulcph_zmm_k1z_zmm_zmmm512b32_er, Register::ZMM0),
        ];
        for &(code, dst) in cases {
            let iced =
                IcedInstruction::with3(code, dst, Register::ZMM1, Register::ZMM2).unwrap();
            let ops = lift_instr(64, &iced);
            assert!(
                !is_unimplemented(&ops),
                "{code:?} fell back to Unimplemented — a sibling mnemonic is \
                 missing from its family's dispatch arm"
            );
            assert!(
                has_setreg_to(&ops, "zmm0"),
                "{code:?} must write its destination register"
            );
        }
    }

    /// `PCMPESTRI64`/`PCMPESTRM64` are the REX.W encodings of PCMPESTRI/PCMPESTRM.
    /// They were missing from the arms that already handled the non-W forms, so
    /// a single REX.W prefix silently downgraded the lift to `Unimplemented`.
    #[test]
    fn test_lift_pcmpestr64_rexw_forms_are_dispatched() {
        let cases: &[(Code, &str)] = &[
            (Code::Pcmpestri64_xmm_xmmm128_imm8, "ecx"),
            (Code::Pcmpestrm64_xmm_xmmm128_imm8, "xmm0"),
        ];
        for &(code, expected_dst) in cases {
            let iced =
                IcedInstruction::with3(code, Register::XMM1, Register::XMM2, 0u32).unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(
                has_setreg_to(&ops, expected_dst),
                "{code:?} must write its implicit result register {expected_dst}"
            );
        }
    }

    // ── AVX-512 (EVEX) masking ──────────────────────────────────────────

    #[test]
    fn test_lift_evex_vaddps_zmm_zeroing_mask() {
        let mut iced = IcedInstruction::with3(
            Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er,
            Register::ZMM0,
            Register::ZMM1,
            Register::ZMM2,
        )
        .unwrap();
        iced.set_op_mask(Register::K1);
        iced.set_zeroing_masking(true);
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value:
                    LlilExpr::CondExpr {
                        true_val,
                        false_val,
                        ..
                    },
                ..
            } => {
                let _ = (true_val, false_val);
                unreachable!("whole-register CondExpr no longer emitted");
            }
            LlilInstruction::SetReg { value, .. } => {
                // Per-lane masking: 16 dword lanes, each a CondExpr on a k1
                // bit; zeroing form selects Const 0 for masked-off lanes.
                let s = format!("{value:?}");
                assert_eq!(s.matches("CondExpr").count(), 16, "16 per-lane selects");
                assert!(s.contains("AddT"), "computed AddT must feed the lanes");
                assert!(
                    !s.contains("\"zmm0\""),
                    "zeroing form must not read the old destination"
                );
            }
            other => panic!("expected SetReg/CondExpr, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_evex_vaddps_zmm_merging_mask() {
        let mut iced = IcedInstruction::with3(
            Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er,
            Register::ZMM0,
            Register::ZMM1,
            Register::ZMM2,
        )
        .unwrap();
        iced.set_op_mask(Register::K1);
        // merging (default, not zeroing)
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value:
                    LlilExpr::CondExpr {
                        true_val,
                        false_val,
                        ..
                    },
                ..
            } => {
                let _ = (true_val, false_val);
                unreachable!("whole-register CondExpr no longer emitted");
            }
            LlilInstruction::SetReg { value, .. } => {
                // Per-lane masking, merging form: each masked-off lane reads
                // the prior destination (zmm0) instead of 0.
                let s = format!("{value:?}");
                assert_eq!(s.matches("CondExpr").count(), 16, "16 per-lane selects");
                assert!(s.contains("AddT"));
                assert!(
                    s.contains("\"zmm0\""),
                    "merging form must fall back to the old destination per lane"
                );
            }
            other => panic!("expected SetReg/CondExpr, got {other:?}"),
        }
    }

    #[test]
    fn test_lift_evex_vaddps_zmm_no_mask_is_plain() {
        // No opmask register set: masking must be a no-op.
        let iced = IcedInstruction::with3(
            Code::EVEX_Vaddps_zmm_k1z_zmm_zmmm512b32_er,
            Register::ZMM0,
            Register::ZMM1,
            Register::ZMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::AddT(..),
                ..
            } => {}
            other => panic!("expected SetReg/AddT (no masking), got {other:?}"),
        }
    }

    // ── FMA3 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_vfmadd132ps_xmm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vfmadd132ps_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Intrinsic { name, args, .. },
                size,
                ..
            } => {
                assert_eq!(name, "fmadd");
                assert_eq!(args.len(), 3);
                assert_eq!(*size, Size::OWord);
            }
            other => panic!("expected SetReg/Intrinsic(fmadd), got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vfmadd213pd_ymm_is_yword() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vfmadd213pd_ymm_ymm_ymmm256,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Intrinsic { name, .. },
                size,
                ..
            } => {
                assert_eq!(name, "fmadd");
                assert_eq!(*size, Size::YWord);
            }
            other => panic!("expected SetReg/Intrinsic(fmadd), got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vfmadd231ps_xmm() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vfmadd231ps_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Intrinsic { name, .. },
                ..
            } => assert_eq!(name, "fmadd"),
            other => panic!("expected SetReg/Intrinsic(fmadd), got {other:?}"),
        }
    }

    #[test]
    fn test_lift_vfmsub132ps_and_vfnmadd132ps_and_vfnmsub132ps() {
        for (code, expect_name) in [
            (Code::VEX_Vfmsub132ps_xmm_xmm_xmmm128, "fmsub"),
            (Code::VEX_Vfnmadd132ps_xmm_xmm_xmmm128, "fnmadd"),
            (Code::VEX_Vfnmsub132ps_xmm_xmm_xmmm128, "fnmsub"),
        ] {
            let iced =
                IcedInstruction::with3(code, Register::XMM0, Register::XMM1, Register::XMM2)
                    .unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            match &ops[0].instr {
                LlilInstruction::SetReg {
                    value: LlilExpr::Intrinsic { name, .. },
                    ..
                } => assert_eq!(name, expect_name),
                other => panic!("{code:?}: expected SetReg/Intrinsic, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_lift_vfmadd132pd_evex_zmm_is_zword() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vfmadd132pd_zmm_k1z_zmm_zmmm512b64_er,
            Register::ZMM0,
            Register::ZMM1,
            Register::ZMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        match &ops[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::Intrinsic { name, .. },
                size,
                ..
            } => {
                assert_eq!(name, "fmadd");
                assert_eq!(*size, Size::ZWord);
            }
            other => panic!("expected SetReg/Intrinsic(fmadd), got {other:?}"),
        }
    }

    // ── BMI1 / BMI2 lift arms ────────────────────────────────────────────

    #[test]
    fn test_lift_andn() {
        let iced = IcedInstruction::with3(
            Code::VEX_Andn_r32_r32_rm32,
            Register::EAX,
            Register::EBX,
            Register::ECX,
        )
        .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
    }

    #[test]
    fn test_lift_bextr() {
        let iced = IcedInstruction::with3(
            Code::VEX_Bextr_r32_rm32_r32,
            Register::EAX,
            Register::ECX,
            Register::EDX,
        )
        .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
    }

    #[test]
    fn test_lift_bzhi() {
        let iced = IcedInstruction::with3(
            Code::VEX_Bzhi_r32_rm32_r32,
            Register::EAX,
            Register::ECX,
            Register::EDX,
        )
        .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
    }

    #[test]
    fn test_lift_blsr() {
        let iced = IcedInstruction::with2(Code::VEX_Blsr_r32_rm32, Register::EAX, Register::ECX)
            .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    #[test]
    fn test_lift_blsi() {
        let iced = IcedInstruction::with2(Code::VEX_Blsi_r32_rm32, Register::EAX, Register::ECX)
            .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    #[test]
    fn test_lift_blsmsk() {
        let iced = IcedInstruction::with2(Code::VEX_Blsmsk_r32_rm32, Register::EAX, Register::ECX)
            .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
        assert_eq!(count_flag_writes(&ops, FLAG_CF), 1);
    }

    /// The three BMI1 `BLS*` instructions look interchangeable but split 2-1 on
    /// carry sense, and `BLSR` was miscoded to match `BLSI` instead of `BLSMSK`.
    ///
    /// Per the Intel SDM (and AMD, which defines each via a pseudo-instruction
    /// whose carry-out becomes CF):
    ///   - `BLSR`   (`sub`) → `CF = (src == 0)`
    ///   - `BLSMSK` (`sub`) → `CF = (src == 0)`
    ///   - `BLSI`   (`neg`) → `CF = (src != 0)`
    ///
    /// The pre-existing tests asserted only `count_flag_writes(CF) == 1`, which
    /// an inverted carry passes happily — so assert on the emitted expression.
    /// `BLSR`/`BLSMSK` must test the source for zero directly, whereas `BLSI`
    /// must wrap that test in a `Not`.
    #[test]
    fn test_lift_bls_family_carry_sense_differs() {
        let cf_of = |code| {
            let iced = IcedInstruction::with2(code, Register::EAX, Register::ECX).unwrap();
            flag_expr_debug(&lift_instr(32, &iced), FLAG_CF)
                .unwrap_or_else(|| panic!("{code:?} wrote no CF"))
        };

        let blsr = cf_of(Code::VEX_Blsr_r32_rm32);
        let blsmsk = cf_of(Code::VEX_Blsmsk_r32_rm32);
        let blsi = cf_of(Code::VEX_Blsi_r32_rm32);

        // BLSR and BLSMSK share a carry sense: CF = (src == 0).
        assert_eq!(
            blsr, blsmsk,
            "BLSR and BLSMSK must emit the same CF (both `CF = (src == 0)`), \
             got BLSR={blsr} vs BLSMSK={blsmsk}"
        );
        // BLSI is the odd one out: CF = (src != 0), i.e. the negation.
        assert_ne!(
            blsr, blsi,
            "BLSI's CF must be the INVERSE of BLSR's, but both emitted {blsr} \
             — this is the inverted-carry bug BLSR originally had"
        );
        assert!(
            blsi.contains("Not"),
            "BLSI's CF should negate the is-zero test (`CF = (src != 0)`), got {blsi}"
        );
        assert!(
            !blsr.contains("Not"),
            "BLSR's CF must NOT negate the is-zero test (`CF = (src == 0)`), got {blsr}"
        );
    }

    /// All nine AMD TBM instructions must lift to a real value + flags, not
    /// fall back to `Unimplemented`.
    #[test]
    fn test_lift_tbm_family_dispatched_with_flags() {
        let codes = [
            Code::XOP_Blcfill_r32_rm32,
            Code::XOP_Blcs_r32_rm32,
            Code::XOP_Blcmsk_r32_rm32,
            Code::XOP_Blci_r32_rm32,
            Code::XOP_Blcic_r32_rm32,
            Code::XOP_T1mskc_r32_rm32,
            Code::XOP_Blsfill_r32_rm32,
            Code::XOP_Blsic_r32_rm32,
            Code::XOP_Tzmsk_r32_rm32,
        ];
        for code in codes {
            let iced =
                IcedInstruction::with2(code, Register::EAX, Register::ECX).unwrap();
            let ops = lift_instr(32, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(has_setreg_to(&ops, "eax"), "{code:?} must write its destination");
            // OF/SF/ZF/CF are all defined; AF/PF are documented undefined and
            // so must NOT be written.
            for flag in [FLAG_OF, FLAG_SF, FLAG_ZF, FLAG_CF] {
                assert_eq!(
                    count_flag_writes(&ops, flag),
                    1,
                    "{code:?} must write {flag} exactly once"
                );
            }
        }
    }

    /// The CF sense splits the TBM family in two, mirroring the BLSR-vs-BLSI
    /// split: instructions built on `src + 1` set CF when the ADD carries out
    /// (src is all-ones), those built on `src - 1` set CF when the SUB borrows
    /// (src is zero). Getting this backwards is invisible to a write-count
    /// assertion, so compare the emitted expressions directly.
    #[test]
    fn test_lift_tbm_carry_sense_splits_by_increment_vs_decrement() {
        let cf_of = |code| {
            let iced = IcedInstruction::with2(code, Register::EAX, Register::ECX).unwrap();
            flag_expr_debug(&lift_instr(32, &iced), FLAG_CF)
                .unwrap_or_else(|| panic!("{code:?} wrote no CF"))
        };

        // `src + 1` forms test the COMPLEMENT of src for zero (src == all-ones).
        let inc_forms = [
            Code::XOP_Blcfill_r32_rm32,
            Code::XOP_Blcs_r32_rm32,
            Code::XOP_Blcmsk_r32_rm32,
            Code::XOP_Blci_r32_rm32,
            Code::XOP_Blcic_r32_rm32,
            Code::XOP_T1mskc_r32_rm32,
        ];
        // `src - 1` forms test src itself for zero.
        let dec_forms =
            [Code::XOP_Blsfill_r32_rm32, Code::XOP_Blsic_r32_rm32, Code::XOP_Tzmsk_r32_rm32];

        let inc_cf = cf_of(inc_forms[0]);
        for code in inc_forms {
            assert_eq!(cf_of(code), inc_cf, "{code:?} must share the +1 CF sense");
            assert!(
                cf_of(code).contains("Not"),
                "{code:?} is a `src + 1` form: CF must be (src == all-ones), so the \
                 is-zero test must be applied to ~src. Got {}",
                cf_of(code)
            );
        }

        let dec_cf = cf_of(dec_forms[0]);
        for code in dec_forms {
            assert_eq!(cf_of(code), dec_cf, "{code:?} must share the -1 CF sense");
        }

        assert_ne!(
            inc_cf, dec_cf,
            "the `src + 1` and `src - 1` TBM families must NOT share a CF sense"
        );
        // `src - 1` forms share BLSR's carry exactly: CF = (src == 0).
        let blsr_cf = {
            let iced =
                IcedInstruction::with2(Code::VEX_Blsr_r32_rm32, Register::EAX, Register::ECX)
                    .unwrap();
            flag_expr_debug(&lift_instr(32, &iced), FLAG_CF).unwrap()
        };
        assert_eq!(
            dec_cf, blsr_cf,
            "the `src - 1` TBM forms and BLSR are both defined via a `sub` \
             pseudo-instruction, so their CF must be identical"
        );
    }

    /// The AMD XOP vector family must lift to a real destination write — and,
    /// crucially, must NOT emit any flag writes. XOP vector ops are
    /// flag-neutral like all SIMD data-processing instructions; VPCOM in
    /// particular is AMD's *mask*-producing compare (all-ones/all-zeros per
    /// lane in the destination) and is easy to mistake for a flag-setting
    /// compare. Emitting flags here would corrupt downstream flag recovery.
    #[test]
    fn test_lift_xop_vector_family_writes_dest_and_no_flags() {
        // 4-operand XOP forms (dst, src1, src2, src3/selector).
        let four_op = [
            Code::XOP_Vpcmov_xmm_xmm_xmmm128_xmm,
            Code::XOP_Vpperm_xmm_xmm_xmmm128_xmm,
            Code::XOP_Vpmacsdd_xmm_xmm_xmmm128_xmm,
            Code::XOP_Vpmacssdd_xmm_xmm_xmmm128_xmm,
            Code::XOP_Vpmadcswd_xmm_xmm_xmmm128_xmm,
        ];
        for code in four_op {
            let iced = IcedInstruction::with4(
                code,
                Register::XMM0,
                Register::XMM1,
                Register::XMM2,
                Register::XMM3,
            )
            .unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(has_setreg_to(&ops, "xmm0"), "{code:?} must write its destination");
            assert!(
                flags_written(&ops).is_empty(),
                "{code:?} is a flag-neutral XOP vector op but wrote flags: {:?}",
                flags_written(&ops)
            );
        }

        // 3-operand XOP forms (dst, src1, src2) — per-lane variable
        // rotate/shift amounts taken from a vector register.
        let three_op = [
            Code::XOP_Vprotb_xmm_xmmm128_xmm,
            Code::XOP_Vpshab_xmm_xmmm128_xmm,
            Code::XOP_Vpshlb_xmm_xmmm128_xmm,
            Code::XOP_Vfrczps_xmm_xmmm128,
        ];
        for code in three_op {
            // Vfrczps is a 2-operand form; the rest are 3-operand.
            let iced = IcedInstruction::with3(code, Register::XMM0, Register::XMM1, Register::XMM2)
                .or_else(|_| IcedInstruction::with2(code, Register::XMM0, Register::XMM1))
                .unwrap_or_else(|e| panic!("{code:?}: could not build test instruction: {e}"));
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(has_setreg_to(&ops, "xmm0"), "{code:?} must write its destination");
            assert!(
                flags_written(&ops).is_empty(),
                "{code:?} is a flag-neutral XOP vector op but wrote flags: {:?}",
                flags_written(&ops)
            );
        }
    }

    /// `VPCOM*` compares into a destination MASK, so it must write the
    /// destination register and leave flags alone — the opposite of the
    /// `COMISD`/`UCOMISD` compare-to-flags forms handled by `lift_comi`.
    #[test]
    fn test_lift_vpcom_writes_mask_not_flags() {
        for code in [Code::XOP_Vpcomb_xmm_xmm_xmmm128_imm8, Code::XOP_Vpcomub_xmm_xmm_xmmm128_imm8]
        {
            let iced =
                IcedInstruction::with4(code, Register::XMM0, Register::XMM1, Register::XMM2, 0u32)
                    .unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(
                has_setreg_to(&ops, "xmm0"),
                "{code:?} must write its comparison mask to the destination"
            );
            assert!(
                flags_written(&ops).is_empty(),
                "{code:?} produces a lane mask, NOT flags — it must not write {:?}",
                flags_written(&ops)
            );
        }
    }

    /// `TESTUI` reports the user-interrupt flag *through rFLAGS* — its entire
    /// observable effect is `CF := UIF; ZF := AF := OF := PF := SF := 0`
    /// (Intel SDM). Lifting it as a bare effect-only intrinsic, like its
    /// siblings CLUI/STUI, would silently discard the only thing it computes.
    #[test]
    fn test_lift_testui_sets_cf_from_uif_and_clears_the_rest() {
        let iced = IcedInstruction::with(Code::Testui);
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops), "TESTUI fell back to Unimplemented");

        let cf = flag_expr_debug(&ops, FLAG_CF).expect("TESTUI must write CF");
        assert!(
            cf.contains("uif"),
            "TESTUI's CF must come from the UIF intrinsic, got {cf}"
        );
        for flag in [FLAG_ZF, FLAG_OF, FLAG_AF, FLAG_PF, FLAG_SF] {
            let e = flag_expr_debug(&ops, flag)
                .unwrap_or_else(|| panic!("TESTUI must clear {flag}"));
            assert!(
                e.contains('0'),
                "TESTUI must clear {flag} to zero, got {e}"
            );
        }
    }

    /// CLUI/STUI only toggle UIF and touch no rFLAGS — the contrast with
    /// TESTUI above is the whole point, so guard it.
    #[test]
    fn test_lift_clui_stui_are_flag_neutral() {
        for code in [Code::Clui, Code::Stui] {
            let iced = IcedInstruction::with(code);
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(
                flags_written(&ops).is_empty(),
                "{code:?} must not write flags, got {:?}",
                flags_written(&ops)
            );
        }
    }

    /// The SEV-SNP RMP instructions take no explicit operands, which makes them
    /// look like the effect-only privileged ops (VMCALL/SEAMCALL/…). They are
    /// not: each returns a status code in EAX and sets flags from it.
    ///
    /// The family is deliberately NOT uniform, per the AMD64 APM's published
    /// `rFLAGS Affected` rows: all four modify OF/SF/ZF/AF/PF, but **only
    /// PVALIDATE also writes CF** (reporting whether the RMP entry changed).
    /// Treating them uniformly — in either direction — is the mistake this
    /// guards against.
    #[test]
    fn test_lift_sev_snp_writes_eax_and_only_pvalidate_writes_cf() {
        let cases: &[(Code, bool)] = &[
            // Pvalidate has w/d/q address-size encodings; all lift identically.
            (Code::Pvalidateq, true),
            (Code::Pvalidated, true),
            (Code::Psmash, false),
            (Code::Rmpupdate, false),
            (Code::Rmpquery, false),
        ];
        for &(code, expect_cf) in cases {
            let iced = IcedInstruction::with(code);
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            assert!(
                has_setreg_to(&ops, "eax"),
                "{code:?} must write its status code to EAX"
            );
            // The five status-derived flags, for every member of the family.
            for flag in [FLAG_OF, FLAG_SF, FLAG_ZF, FLAG_AF, FLAG_PF] {
                assert_eq!(
                    count_flag_writes(&ops, flag),
                    1,
                    "{code:?} must set {flag} from its return code"
                );
            }
            assert_eq!(
                count_flag_writes(&ops, FLAG_CF),
                usize::from(expect_cf),
                "{code:?}: only PVALIDATE writes CF (it reports whether the RMP \
                 entry changed); the others leave CF untouched per the AMD APM"
            );
        }
    }

    /// PVALIDATE's status/flags must depend on its architectural inputs
    /// (RAX = address, ECX = page size, EDX = desired validated state — AMD
    /// SEV-SNP APM), not be emitted as bare argument-less intrinsics.
    ///
    /// Same hazard as the shift/rotate carry bug: an argument-less intrinsic
    /// is structurally IDENTICAL for every PVALIDATE call site in a function,
    /// so a CSE/GVN pass keyed on expression shape can merge the status of
    /// two calls that ran with different RAX/ECX/EDX — a real miscompile, not
    /// just a missing-dependency annoyance, since PVALIDATE's result
    /// genuinely differs per call. PSMASH/RMPUPDATE/RMPQUERY are deliberately
    /// left untouched here — their exact operand-register roles were not
    /// independently re-verified, so guessing would be worse than leaving the
    /// documented gap (see project memory on this bug class).
    #[test]
    fn test_lift_pvalidate_status_depends_on_its_operand_registers() {
        let iced = IcedInstruction::with(Code::Pvalidateq);
        let ops = lift_instr(64, &iced);
        let of = flag_expr_debug(&ops, FLAG_OF).unwrap_or_else(|| panic!("Pvalidateq wrote no OF"));
        assert!(
            of.contains("rax") && of.contains("ecx") && of.contains("edx"),
            "PVALIDATE's status-derived flags must depend on RAX/ECX/EDX \
             (its architectural inputs per the AMD SEV-SNP APM), got {of}"
        );
    }

    /// Shift/rotate carries must be DISTINCT expressions that depend on their
    /// operands.
    ///
    /// They used to be emitted as bare `shift_carry()` / `rotate_carry()` — one
    /// shared name each, with NO arguments. Two things were wrong with that:
    /// the dependency on (value, count) was invisible to dataflow, and every
    /// shift (or rotate) in a function produced a structurally IDENTICAL
    /// expression, so a CSE/GVN pass keyed on expression shape could merge the
    /// carry of a SHL with that of a SHR, or a ROL's with a ROR's — opposite
    /// ends of the operand. The committed snapshot showed the smoking gun:
    /// `rol eax, 3` and `ror rax, 7` both emitted `flag(cf) = rotate_carry()`.
    #[test]
    fn test_shift_rotate_carries_are_distinct_and_operand_dependent() {
        // A NONZERO immediate: a rotate by 0 (the old `Register::None` operand
        // encoded imm 0) legitimately writes no flags at all per the APM.
        let cf_of = |code| {
            let iced = IcedInstruction::with2(code, Register::EAX, 3i32).unwrap();
            flag_expr_debug(&lift_instr(64, &iced), FLAG_CF)
                .unwrap_or_else(|| panic!("{code:?} wrote no CF"))
        };

        let shl = cf_of(Code::Shl_rm32_imm8);
        let shr = cf_of(Code::Shr_rm32_imm8);
        let rol = cf_of(Code::Rol_rm32_imm8);
        let ror = cf_of(Code::Ror_rm32_imm8);

        // Each op's carry must be its own rule, never a shared placeholder.
        for (name, e) in [("shl", &shl), ("shr", &shr), ("rol", &rol), ("ror", &ror)] {
            assert!(
                !e.contains("shift_carry") && !e.contains("rotate_carry"),
                "{name}: carry must not be the old shared placeholder, got {e}"
            );
            // The carry depends on the value being shifted/rotated — an
            // argument-less intrinsic loses that dependency entirely.
            assert!(
                e.contains(operand_spelling("eax")),
                "{name}: carry must depend on its operand, got {e}"
            );
        }

        // No two of the four may collapse to the same expression.
        let all = [("shl", &shl), ("shr", &shr), ("rol", &rol), ("ror", &ror)];
        for (i, (na, a)) in all.iter().enumerate() {
            for (nb, b) in &all[i + 1..] {
                assert_ne!(
                    a, b,
                    "{na} and {nb} must not emit the same CF expression — CSE \
                     would merge two different carries into one"
                );
            }
        }
    }

    #[test]
    fn test_shift_flags_follow_apm_count_semantics() {
        let lift_imm = |code, imm: i32| {
            let iced = IcedInstruction::with2(code, Register::EAX, imm).unwrap();
            lift_instr(64, &iced)
        };
        // APM (pub 24594, SAL/SHL p.314, same wording on SHR/SAR): "If the
        // count is 0, no flags are affected."
        let z = lift_imm(Code::Shl_rm32_imm8, 0);
        for f in [FLAG_CF, FLAG_SF, FLAG_ZF, FLAG_PF] {
            assert!(flag_expr_debug(&z, f).is_none(), "shl by 0 must not write {f}");
        }
        // Masking first: 32 & 0x1F == 0 → same as 0.
        let z32 = lift_imm(Code::Shl_rm32_imm8, 32);
        assert!(flag_expr_debug(&z32, FLAG_CF).is_none(), "shl by 32 masks to 0: no flags");
        // Nonzero constant count: CF and SF/ZF/PF written as before.
        let s3 = lift_imm(Code::Shl_rm32_imm8, 3);
        for f in [FLAG_CF, FLAG_SF, FLAG_ZF, FLAG_PF] {
            assert!(flag_expr_debug(&s3, f).is_some(), "shl by 3 must write {f}");
        }
        // Variable count: every flag write predicated on the masked count,
        // keeping the OLD flag value when the count is 0.
        let iced =
            IcedInstruction::with2(Code::Shl_rm32_CL, Register::EAX, Register::CL).unwrap();
        let var = lift_instr(64, &iced);
        let cf = flag_expr_debug(&var, FLAG_CF).expect("variable shl writes CF");
        assert!(cf.contains("CondExpr") && cf.contains("shl_cf") && cf.contains("Flag(\"cf\")"), "{cf}");
        let zf = flag_expr_debug(&var, FLAG_ZF).expect("variable shl writes ZF");
        assert!(zf.contains("CondExpr") && zf.contains("Flag(\"zf\")"), "{zf}");
        let sf = flag_expr_debug(&var, FLAG_SF).expect("variable shl writes SF");
        assert!(sf.contains("CondExpr") && sf.contains("Flag(\"sf\")"), "{sf}");
        let pf = flag_expr_debug(&var, FLAG_PF).expect("variable shl writes PF");
        assert!(pf.contains("CondExpr") && pf.contains("Flag(\"pf\")"), "{pf}");
    }

    #[test]
    fn test_rotate_flags_follow_apm_count_semantics() {
        let lift_imm = |code, imm: i32| {
            let iced = IcedInstruction::with2(code, Register::EAX, imm).unwrap();
            lift_instr(64, &iced)
        };
        // APM (pub 24594, ROL/ROR pages): "When the rotate count is 0, no
        // flags are affected."
        let z = lift_imm(Code::Rol_rm32_imm8, 0);
        assert!(flag_expr_debug(&z, FLAG_CF).is_none(), "rotate by 0 must not write CF");
        assert!(flag_expr_debug(&z, FLAG_OF).is_none(), "rotate by 0 must not write OF");
        // The count is masked to 5 bits first (6 for 64-bit): 32 & 0x1F == 0.
        let z32 = lift_imm(Code::Rol_rm32_imm8, 32);
        assert!(flag_expr_debug(&z32, FLAG_CF).is_none(), "rol by 32 masks to 0: no flags");
        // A 1-bit rotate DEFINES OF, with a per-op rule (ROL: CF-after XOR
        // msb(result); ROR: msb XOR msb-1 — different rules, so the two must
        // never share an expression).
        let rol1 = lift_imm(Code::Rol_rm32_imm8, 1);
        let rol1_of = flag_expr_debug(&rol1, FLAG_OF).expect("rol-by-1 defines OF");
        assert!(rol1_of.contains("rol_of") && rol1_of.contains(operand_spelling("eax")), "{rol1_of}");
        let ror1 = lift_imm(Code::Ror_rm32_imm8, 1);
        let ror1_of = flag_expr_debug(&ror1, FLAG_OF).expect("ror-by-1 defines OF");
        assert!(ror1_of.contains("ror_of"), "{ror1_of}");
        assert_ne!(rol1_of, ror1_of);
        // Count > 1: CF is defined, OF is UNDEFINED — honestly left unwritten
        // (stale), never guessed.
        let rol3 = lift_imm(Code::Rol_rm32_imm8, 3);
        assert!(flag_expr_debug(&rol3, FLAG_CF).is_some());
        assert!(flag_expr_debug(&rol3, FLAG_OF).is_none(), "OF undefined for count > 1");
        // Variable count: the flag writes must be predicated on the masked
        // count — count==0 keeps the OLD flag value, count==1 (and only 1)
        // defines OF.
        let iced =
            IcedInstruction::with2(Code::Rol_rm32_CL, Register::EAX, Register::CL).unwrap();
        let var = lift_instr(64, &iced);
        let cf = flag_expr_debug(&var, FLAG_CF).expect("variable rol writes CF");
        assert!(cf.contains("CondExpr"), "CF must be predicated on count: {cf}");
        assert!(cf.contains("rol_cf"), "{cf}");
        assert!(cf.contains("Flag(\"cf\")"), "old CF must be kept when count==0: {cf}");
        let of = flag_expr_debug(&var, FLAG_OF).expect("variable rol writes OF");
        assert!(
            of.contains("CondExpr") && of.contains("rol_of") && of.contains("Flag(\"of\")"),
            "OF must select rol_of only when count==1: {of}"
        );
    }

    #[test]
    fn test_lift_vmaxsd_vminsd() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vmaxsd_xmm_xmm_xmmm64,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vhaddpd() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vhaddpd_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vmovddup() {
        let iced =
            IcedInstruction::with2(Code::VEX_Vmovddup_xmm_xmmm64, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vldmxcsr() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RAX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let iced = IcedInstruction::with1(Code::VEX_Vldmxcsr_m32, mem).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    // ── APX CMPccXADD / RAO-INT / AES-KL / MSR-list / misc ─────────────────

    #[test]
    fn test_lift_cmpbexadd_conditional_atomic_add() {
        // CMPBEXADD [mem], eax, ecx (VEX_Cmpbexadd_m32_r32_r32: m32, r32, r32)
        let mem = iced_x86::MemoryOperand::new(
            Register::RDX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let iced =
            IcedInstruction::with3(Code::VEX_Cmpbexadd_m32_r32_r32, mem, Register::EAX, Register::ECX)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        // Flags reflecting the CMP(reg1, temp) must be set.
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetFlag { name, .. } if name == FLAG_ZF)));
        // reg1 (EAX) always gets the pre-update memory value.
        assert!(has_setreg_to(&ops, "eax"));
        // Store back to memory is conditional on the `be` comparison.
        assert!(ops.iter().any(|o| matches!(&o.instr,
            LlilInstruction::Store { value: LlilExpr::CondExpr { .. }, .. })));
    }

    #[test]
    fn test_lift_aadd_atomic_memop_no_flags() {
        // AADD [mem], eax
        let mem = iced_x86::MemoryOperand::new(
            Register::RDX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let iced = IcedInstruction::with2(Code::Aadd_m32_r32, mem, Register::EAX).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(&o.instr, LlilInstruction::Store { .. })));
        // RAO-INT ops don't affect flags.
        assert!(!ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetFlag { .. })));
    }


    #[test]
    fn test_lift_axor_aor_aand_effect() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RDX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        for code in [Code::Aand_m64_r64, Code::Aor_m64_r64, Code::Axor_m64_r64] {
            let iced = IcedInstruction::with2(code, mem, Register::RAX).unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops));
        }
    }

    #[test]
    fn test_lift_encodekey_msrlist_invlpgb_effect_only() {
        let iced =
            IcedInstruction::with2(Code::Encodekey128_r32_r32, Register::EAX, Register::EAX)
                .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));

        let iced = IcedInstruction::with(Code::Wrmsrns);
        assert!(!is_unimplemented(&lift_instr(64, &iced)));

        let iced = IcedInstruction::with(Code::Wrmsrlist);
        assert!(!is_unimplemented(&lift_instr(64, &iced)));

        let iced = IcedInstruction::with(Code::Rdmsrlist);
        assert!(!is_unimplemented(&lift_instr(64, &iced)));

        let iced = IcedInstruction::with(Code::Tlbsync);
        assert!(!is_unimplemented(&lift_instr(64, &iced)));

        let iced =
            IcedInstruction::with1(Code::Lkgs_rm16, Register::AX).unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_cli_clts_clzero() {
        // CLI
        assert!(has_intrinsic_named(&lift64(&[0xfa]), "cli"));
        // CLTS (0F 06)
        assert!(has_intrinsic_named(&lift64(&[0x0f, 0x06]), "clts"));
        // CLZERO (0F 01 FC)
        assert!(has_intrinsic_named(&lift64(&[0x0f, 0x01, 0xfc]), "clzero"));
    }

    #[test]
    fn test_lift_rdpru() {
        // RDPRU (0F 01 FD)
        let ops = lift64(&[0x0f, 0x01, 0xfd]);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
        assert!(has_setreg_to(&ops, "edx"));
    }

    #[test]
    fn test_lift_xsusldtrk_xresldtrk() {
        // XSUSLDTRK (F2 0F 01 E8), XRESLDTRK (F2 0F 01 E9)
        assert!(has_intrinsic_named(&lift64(&[0xf2, 0x0f, 0x01, 0xe8]), "xsusldtrk"));
        assert!(has_intrinsic_named(&lift64(&[0xf2, 0x0f, 0x01, 0xe9]), "xresldtrk"));
    }

    #[test]
    fn test_lift_amx_tilezero() {
        let iced = IcedInstruction::with1(Code::VEX_Tilezero_tmm, Register::TMM0).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_amx_ldtilecfg() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RAX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let iced = IcedInstruction::with1(Code::VEX_Ldtilecfg_m512, mem).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vpcompressb() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vpcompressb_xmmm128_k1z_xmm,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpblendd() {
        let iced = IcedInstruction::with4(
            Code::VEX_Vpblendd_ymm_ymm_ymmm256_imm8,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpmullq() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpmullq_ymm_k1z_ymm_ymmm256b64,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vrangesd() {
        let iced = IcedInstruction::with4(
            Code::EVEX_Vrangesd_xmm_k1z_xmm_xmmm64_imm8_sae,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpshldvd() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpshldvd_ymm_k1z_ymm_ymmm256b32,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vrcp14ps() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vrcp14ps_ymm_k1z_ymmm256b32,
            Register::YMM0,
            Register::YMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpmadd52huq() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpmadd52huq_ymm_k1z_ymm_ymmm256b64,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vucomisd() {
        let iced = IcedInstruction::with2(
            Code::VEX_Vucomisd_xmm_xmmm64,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vprolq() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vprolq_ymm_k1z_ymmm256b64_imm8,
            Register::YMM0,
            Register::YMM1,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpexpandb() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vpexpandb_xmm_k1z_xmmm128,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpmovsdb() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vpmovsdb_xmmm32_k1z_xmm,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpsravd() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vpsravd_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpblendmd() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpblendmd_ymm_k1z_ymm_ymmm256b32,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpcmpd() {
        let iced = IcedInstruction::with4(
            Code::EVEX_Vpcmpd_kr_k1_ymm_ymmm256b32_imm8,
            Register::K0,
            Register::YMM0,
            Register::YMM1,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vrcpps() {
        let iced =
            IcedInstruction::with2(Code::VEX_Vrcpps_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vsm3msg1_vsm4key4() {
        let sm3 = IcedInstruction::with3(
            Code::VEX_Vsm3msg1_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &sm3)));
        let sm4 = IcedInstruction::with3(
            Code::VEX_Vsm4key4_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &sm4)));
    }

    #[test]
    fn test_lift_vptestmb() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vptestmb_kr_k1_xmm_xmmm128,
            Register::K0,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpmovm2b_vpmovb2m() {
        let m2v = IcedInstruction::with2(Code::EVEX_Vpmovm2b_xmm_kr, Register::XMM0, Register::K0)
            .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &m2v)));
        let v2m = IcedInstruction::with2(Code::EVEX_Vpmovb2m_kr_xmm, Register::K0, Register::XMM0)
            .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &v2m)));
    }

    #[test]
    fn test_lift_vpbroadcastb_vpbroadcastd() {
        let b = IcedInstruction::with2(Code::VEX_Vpbroadcastb_xmm_xmmm8, Register::XMM0, Register::XMM1)
            .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &b)));
        let d = IcedInstruction::with2(Code::VEX_Vpbroadcastd_xmm_xmmm32, Register::XMM0, Register::XMM1)
            .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &d)));
    }

    #[test]
    fn test_lift_vscalefsd() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vscalefsd_xmm_k1z_xmm_xmmm64_er,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpdpbusd() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpdpbusd_xmm_k1z_xmm_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vdpbf16ps() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vdpbf16ps_ymm_k1z_ymm_ymmm256b32,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vcvtneps2bf16() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vcvtneps2bf16_xmm_k1z_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vp2intersectd() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vp2intersectd_kp1_xmm_xmmm128b32,
            Register::K0,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpsraq() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpsraq_ymm_k1z_ymm_xmmm128,
            Register::YMM0,
            Register::YMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpshldd() {
        let iced = IcedInstruction::with4(
            Code::EVEX_Vpshldd_ymm_k1z_ymm_ymmm256b32_imm8,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpopcntd() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vpopcntd_ymm_k1z_ymmm256b32,
            Register::YMM0,
            Register::YMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vpconflictd() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vpconflictd_ymm_k1z_ymmm256b32,
            Register::YMM0,
            Register::YMM1,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vtestps() {
        let iced =
            IcedInstruction::with2(Code::VEX_Vtestps_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
    }

    #[test]
    fn test_lift_vpmovqb() {
        let iced =
            IcedInstruction::with2(Code::EVEX_Vpmovqb_xmmm16_k1z_xmm, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vrndscaleps_vreduceps() {
        let rnd = IcedInstruction::with3(
            Code::EVEX_Vrndscaleps_ymm_k1z_ymmm256b32_imm8,
            Register::YMM0,
            Register::YMM1,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &rnd)));
        let red = IcedInstruction::with3(
            Code::EVEX_Vreduceps_ymm_k1z_ymmm256b32_imm8,
            Register::YMM0,
            Register::YMM1,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &red)));
    }

    #[test]
    fn test_lift_vsqrtss() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vsqrtss_xmm_xmm_xmmm32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vroundss() {
        let iced = IcedInstruction::with4(
            Code::VEX_Vroundss_xmm_xmm_xmmm32_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            0u32,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &iced)));
    }

    #[test]
    fn test_lift_vmovss_vmovsd() {
        let vmovss = IcedInstruction::with3(
            Code::VEX_Vmovss_xmm_xmm_xmm,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &vmovss);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "xmm0"));

        let vmovsd = IcedInstruction::with3(
            Code::VEX_Vmovsd_xmm_xmm_xmm,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &vmovsd);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "xmm0"));
    }

    #[test]
    fn test_lift_vmovdqa32() {
        let iced =
            IcedInstruction::with2(Code::EVEX_Vmovdqa32_ymm_k1z_ymmm256, Register::YMM0, Register::YMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vmovntdq() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RAX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let iced = IcedInstruction::with2(Code::VEX_Vmovntdq_m256_ymm, mem, Register::YMM0).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vmaxph_vminph() {
        let vmax = IcedInstruction::with3(
            Code::EVEX_Vmaxph_ymm_k1z_ymm_ymmm256b16,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &vmax)));
        let vmin = IcedInstruction::with3(
            Code::EVEX_Vminph_ymm_k1z_ymm_ymmm256b16,
            Register::YMM0,
            Register::YMM1,
            Register::YMM2,
        )
        .unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &vmin)));
    }

    #[test]
    fn test_lift_vgf2p8mulb() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vgf2p8mulb_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vinsertf32x4() {
        let iced = IcedInstruction::with4(
            Code::EVEX_Vinsertf32x4_ymm_k1z_ymm_xmmm128_imm8,
            Register::YMM0,
            Register::YMM1,
            Register::XMM2,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vgetmantsd() {
        let iced = IcedInstruction::with4(
            Code::EVEX_Vgetmantsd_xmm_k1z_xmm_xmmm64_imm8_sae,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_tdx_ops() {
        // TDCALL (66 0F 01 CC), SEAMRET (66 0F 01 CD), SEAMOPS (66 0F 01 CE),
        // SEAMCALL (66 0F 01 CF).
        assert!(has_intrinsic_named(&lift64(&[0x66, 0x0f, 0x01, 0xcc]), "tdcall"));
        assert!(has_intrinsic_named(&lift64(&[0x66, 0x0f, 0x01, 0xcd]), "seamret"));
        assert!(has_intrinsic_named(&lift64(&[0x66, 0x0f, 0x01, 0xce]), "seamops"));
        assert!(has_intrinsic_named(&lift64(&[0x66, 0x0f, 0x01, 0xcf]), "seamcall"));
    }

    #[test]
    fn test_lift_fbld_fbstp() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RAX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let fbld = IcedInstruction::with1(Code::Fbld_m80bcd, mem).unwrap();
        assert!(!is_unimplemented(&lift_instr(64, &fbld)));
        let fbstp = IcedInstruction::with1(Code::Fbstp_m80bcd, mem).unwrap();
        let ops = lift_instr(64, &fbstp);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_enqcmd() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RAX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let iced = IcedInstruction::with2(Code::Enqcmd_r64_m512, Register::RCX, mem).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_loadiwkey() {
        let iced =
            IcedInstruction::with2(Code::Loadiwkey_xmm_xmm, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_senduipi() {
        let iced = IcedInstruction::with1(Code::Senduipi_r64, Register::RAX).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_prefetchit0_prefetchit1() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RIP,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        for code in [Code::Prefetchit0_m8, Code::Prefetchit1_m8] {
            let iced = IcedInstruction::with1(code, mem).unwrap();
            let ops = lift_instr(64, &iced);
            assert!(!is_unimplemented(&ops));
        }
    }

    #[test]
    fn test_lift_vpabsb() {
        let iced =
            IcedInstruction::with2(Code::VEX_Vpabsb_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vpunpckhbw() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vpunpckhbw_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vpmulhw() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vpmulhw_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vpsllw() {
        let iced = IcedInstruction::with3(
            Code::VEX_Vpsllw_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vpinsrb() {
        let iced = IcedInstruction::with4(
            Code::VEX_Vpinsrb_xmm_xmm_r32m8_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::EAX,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_pmulhrsw() {
        let iced =
            IcedInstruction::with2(Code::Pmulhrsw_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_phminposuw() {
        let iced =
            IcedInstruction::with2(Code::Phminposuw_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_pdep_pext() {
        let pdep = IcedInstruction::with3(
            Code::VEX_Pdep_r32_r32_rm32,
            Register::EAX,
            Register::EBX,
            Register::ECX,
        )
        .unwrap();
        let ops = lift_instr(32, &pdep);
        match &ops[0].instr {
            LlilInstruction::SetReg { value, .. } => {
                assert_eq!(intrinsic_name(value), Some("pdep"));
            }
            other => panic!("expected SetReg/Intrinsic(pdep), got {other:?}"),
        }

        let pext = IcedInstruction::with3(
            Code::VEX_Pext_r32_r32_rm32,
            Register::EAX,
            Register::EBX,
            Register::ECX,
        )
        .unwrap();
        let ops = lift_instr(32, &pext);
        match &ops[0].instr {
            LlilInstruction::SetReg { value, .. } => {
                assert_eq!(intrinsic_name(value), Some("pext"));
            }
            other => panic!("expected SetReg/Intrinsic(pext), got {other:?}"),
        }
    }

    #[test]
    fn test_lift_mulx() {
        let iced = IcedInstruction::with3(
            Code::VEX_Mulx_r32_r32_rm32,
            Register::EAX,
            Register::EBX,
            Register::ECX,
        )
        .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(has_setreg_to(&ops, "eax"));
        assert!(has_setreg_to(&ops, "ebx"));
    }

    #[test]
    fn test_lift_rorx() {
        let iced = IcedInstruction::with3(
            Code::VEX_Rorx_r32_rm32_imm8,
            Register::EAX,
            Register::ECX,
            4i32,
        )
        .unwrap();
        let ops = lift_instr(32, &iced);
        assert!(!is_unimplemented(&ops));
        match &ops[0].instr {
            LlilInstruction::SetReg { value, .. } => {
                assert_eq!(intrinsic_name(value), Some("rorx"));
            }
            other => panic!("expected SetReg/Intrinsic(rorx), got {other:?}"),
        }
    }

    #[test]
    fn test_lift_shlx_shrx_sarx_no_flags() {
        for code in [
            Code::VEX_Shlx_r32_rm32_r32,
            Code::VEX_Shrx_r32_rm32_r32,
            Code::VEX_Sarx_r32_rm32_r32,
        ] {
            let iced = IcedInstruction::with3(code, Register::EAX, Register::ECX, Register::EDX)
                .unwrap();
            let ops = lift_instr(32, &iced);
            assert!(!is_unimplemented(&ops), "{code:?} fell back to Unimplemented");
            // SHLX/SHRX/SARX must not touch flags.
            assert!(
                ops.iter()
                    .all(|o| !matches!(o.instr, LlilInstruction::SetFlag { .. })),
                "{code:?} should not affect flags"
            );
            assert!(has_setreg_to(&ops, "eax"));
        }
    }

    // ── legacy SSE writeback (lift_simd_write) ──────────────────────────

    #[test]
    fn test_lift_cvtss2sd_writes_dest() {
        // f3 0f 5a c1 — cvtss2sd xmm0, xmm1
        let ops = lift64(&[0xf3, 0x0f, 0x5a, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("cvt"))
            )),
            "cvtss2sd should write an Intrinsic(\"cvt\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_pshufd_writes_dest() {
        // 66 0f 70 c1 00 — pshufd xmm0, xmm1, 0
        let ops = lift64(&[0x66, 0x0f, 0x70, 0xc1, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pshuf"))
            )),
            "pshufd should write an Intrinsic(\"pshuf\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_pcmpeqb_writes_dest() {
        // 66 0f 74 c1 — pcmpeqb xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x74, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pcmpeq"))
            )),
            "pcmpeqb should write an Intrinsic(\"pcmpeq\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_minss_maxss_write_dest() {
        // f3 0f 5d c1 — minss xmm0, xmm1
        let ops = lift64(&[0xf3, 0x0f, 0x5d, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("min"))
        )));

        // f3 0f 5f c1 — maxss xmm0, xmm1
        let ops = lift64(&[0xf3, 0x0f, 0x5f, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("max"))
        )));
    }

    #[test]
    fn test_lift_pmovmskb_writes_gpr() {
        // 66 0f d7 c1 — pmovmskb eax, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xd7, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if is_dest(d, "eax") && intrinsic_name(value).is_some_and(|n| n.contains("movmsk"))
            )),
            "pmovmskb should write an Intrinsic(\"movmsk\", ..) result into eax, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_comiss_sets_flags_not_dest() {
        // 0f 2f c1 — comiss xmm0, xmm1
        let ops = lift64(&[0x0f, 0x2f, 0xc1]);
        assert!(!is_unimplemented(&ops));
        let flags = flags_written(&ops);
        assert!(flags.contains(&FLAG_ZF.to_string()));
        assert!(flags.contains(&FLAG_PF.to_string()));
        assert!(flags.contains(&FLAG_CF.to_string()));
        assert!(flags.contains(&FLAG_OF.to_string()));
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        // COMISS must not overwrite xmm0/xmm1 — it's compare-only.
        assert!(!has_setreg_to(&ops, "xmm0"));
    }

    #[test]
    fn test_lift_ucomisd_uses_distinct_intrinsic_name() {
        // 66 0f 2e c1 — ucomisd xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x2e, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetFlag { name: f, src: LlilExpr::Intrinsic { name, .. } }
                if f == FLAG_ZF && name == "ucomi_zf"
        )));
    }

    // ── MMX/SSE packed shift / pack / avg / madd / cmpp coverage pass ──

    #[test]
    fn test_lift_psllw_pslld_psllq_write_dest() {
        // 66 0f f1 c1 — psllw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xf1, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("psll"))
        )));

        // 66 0f f2 c1 — pslld xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xf2, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("psll"))
        )));

        // 66 0f f3 c1 — psllq xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xf3, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("psll"))
        )));
    }

    #[test]
    fn test_lift_psrlw_psraw_write_dest() {
        // 66 0f d1 c1 — psrlw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xd1, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("psrl"))
        )));

        // 66 0f e1 c1 — psraw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xe1, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("psra"))
        )));
    }

    #[test]
    fn test_lift_pslldq_psrldq_write_dest() {
        // 66 0f 73 f8 08 — pslldq xmm0, 8
        let ops = lift64(&[0x66, 0x0f, 0x73, 0xf8, 0x08]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "pslldq")
        )));

        // 66 0f 73 d8 08 — psrldq xmm0, 8
        let ops = lift64(&[0x66, 0x0f, 0x73, 0xd8, 0x08]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "psrldq")
        )));
    }

    #[test]
    fn test_lift_pack_instructions_write_dest() {
        // 66 0f 63 c1 — packsswb xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x63, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("packss"))
        )));

        // 66 0f 67 c1 — packuswb xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x67, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("packus"))
        )));

        // 66 0f 38 2b c1 — packusdw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x38, 0x2b, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("packus"))
        )));
    }

    #[test]
    fn test_lift_pavg_pmadd_psadbw_write_dest() {
        // 66 0f e0 c1 — pavgb xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xe0, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pavg"))
        )));

        // 66 0f f5 c1 — pmaddwd xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xf5, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pmadd"))
        )));

        // 66 0f f6 c1 — psadbw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0xf6, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("psadbw"))
        )));
    }

    #[test]
    fn test_lift_pminuw_pmaxuw_pmulld_write_dest() {
        // 66 0f 38 3a c1 — pminuw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x38, 0x3a, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pmin"))
        )));

        // 66 0f 38 40 c1 — pmulld xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x38, 0x40, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pmul"))
        )));
    }

    #[test]
    fn test_lift_cmpps_cmpsd_write_dest() {
        // 0f c2 c1 00 — cmpps xmm0, xmm1, 0 (EQ)
        let ops = lift64(&[0x0f, 0xc2, 0xc1, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if (name.contains("cmpp") || name.contains("cmps")))
        )));

        // f2 0f c2 c1 00 — cmpsd xmm0, xmm1, 0 (non-string SSE compare)
        let ops = lift64(&[0xf2, 0x0f, 0xc2, 0xc1, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if (name.contains("cmpp") || name.contains("cmps")))
        )));
    }

    // ── AVX (VEX) writeback fixes: lift_simd_write / lift_ptest ────────

    #[test]
    fn test_lift_vminps_vmaxps_write_dest() {
        // c5 f0 5d c2 — vminps xmm0, xmm1, xmm2
        let ops = lift64(&[0xc5, 0xf0, 0x5d, 0xc2]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.contains("min"))
        )));

        // c5 f0 5f c2 — vmaxps xmm0, xmm1, xmm2
        let ops = lift64(&[0xc5, 0xf0, 0x5f, 0xc2]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.contains("max"))
        )));
    }

    #[test]
    fn test_lift_vsqrtps_writes_dest() {
        // c5 f8 51 c1 — vsqrtps xmm0, xmm1
        let ops = lift64(&[0xc5, 0xf8, 0x51, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vsqrt"))
        )));
    }

    #[test]
    fn test_lift_vcmpps_writes_dest() {
        // c5 f0 c2 c2 00 — vcmpps xmm0, xmm1, xmm2, 0
        let ops = lift64(&[0xc5, 0xf0, 0xc2, 0xc2, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vcmp"))
        )));
    }

    #[test]
    fn test_lift_vshufps_writes_dest() {
        // c5 f0 c6 c2 00 — vshufps xmm0, xmm1, xmm2, 0
        let ops = lift64(&[0xc5, 0xf0, 0xc6, 0xc2, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vshuf"))
        )));
    }

    #[test]
    fn test_lift_vblendvps_writes_dest() {
        // c4 e3 69 4a c2 10 — vblendvps xmm0, xmm1, xmm2, xmm1
        let ops = lift64(&[0xc4, 0xe3, 0x69, 0x4a, 0xc2, 0x10]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vblendv"))
        )));
    }

    #[test]
    fn test_lift_vpermilps_writes_dest() {
        // c4 e2 79 0c c1 — vpermilps xmm0, xmm1, xmm1
        let ops = lift64(&[0xc4, 0xe2, 0x79, 0x0c, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vpermil"))
        )));
    }

    #[test]
    fn test_lift_movntdq_stores_to_memory() {
        // 66 0f e7 00 — movntdq [rax], xmm0
        let ops = lift64(&[0x66, 0x0f, 0xe7, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(&o.instr, LlilInstruction::Store { .. })),
            "movntdq should emit a Store to memory, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_lddqu_writes_dest() {
        // f2 0f f0 00 — lddqu xmm0, [rax]
        let ops = lift64(&[0xf2, 0x0f, 0xf0, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. } if d == "xmm0"
            )),
            "lddqu should write the loaded value into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_ptest_sets_zf_cf_not_dest() {
        // 66 0f 38 17 c1 — ptest xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x38, 0x17, 0xc1]);
        assert!(!is_unimplemented(&ops));
        let flags = flags_written(&ops);
        assert!(flags.contains(&FLAG_ZF.to_string()));
        assert!(flags.contains(&FLAG_CF.to_string()));
        assert!(flags.contains(&FLAG_OF.to_string()));
        assert_eq!(count_flag_writes(&ops, FLAG_ZF), 1);
        // PTEST must not overwrite xmm0/xmm1 — it's compare-only.
        assert!(!has_setreg_to(&ops, "xmm0"));
    }

    // ── x87 FPU explicit-operand writeback (lift_fpu_write) ─────────────

    #[test]
    fn test_lift_fadd_writes_dest() {
        // d8 c1 — fadd st(0), st(1)
        let ops = lift64(&[0xd8, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { value, .. }
                    if matches!(value, LlilExpr::Intrinsic { name, .. } if name == "fadd")
            )),
            "fadd should write an Intrinsic(\"fadd\", ..) result to its destination, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_blendpd_writes_dest() {
        // 66 0f 3a 0d c1 05 — blendpd xmm0, xmm1, 5
        let ops = lift64(&[0x66, 0x0f, 0x3a, 0x0d, 0xc1, 0x05]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("blend"))
            )),
            "blendpd should write an Intrinsic(\"blend\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_vfmadd213sd_dispatched() {
        // c4 e2 f9 a9 c2 — vfmadd213sd xmm0, xmm1, xmm2 (VEX.DDS.LIG.66.0F38.W1 A9)
        let ops = lift64(&[0xc4, 0xe2, 0xf9, 0xa9, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vaddsd_writes_dest() {
        // c5 fb 58 c1 — vaddsd xmm0, xmm1, xmm1 (VEX.LIG.F2.0F 58)
        let ops = lift64(&[0xc5, 0xfb, 0x58, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. } if d == "xmm0"
            )),
            "vaddsd should write a real result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_vcomisd_sets_flags() {
        // c5 f9 2f c1 — vcomisd xmm0, xmm1
        let ops = lift64(&[0xc5, 0xf9, 0x2f, 0xc1]);
        assert!(!is_unimplemented(&ops));
        let flags = flags_written(&ops);
        assert!(flags.contains(&FLAG_ZF.to_string()));
    }

    #[test]
    fn test_lift_vaddph_writes_dest() {
        // 62 f5 74 08 58 c2 — vaddph xmm0, xmm1, xmm2 (EVEX.128.NP.0F.W0 58)
        let ops = lift64(&[0x62, 0xf5, 0x74, 0x08, 0x58, 0xc2]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. } if d == "xmm0"
            )),
            "vaddph should write a real result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_vaddsh_dispatched() {
        // 62 f5 76 08 58 c2 — vaddsh xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf5, 0x76, 0x08, 0x58, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vsubph_dispatched() {
        // 62 f5 74 08 5c c2 — vsubph xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf5, 0x74, 0x08, 0x5c, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vmulph_dispatched() {
        // 62 f5 74 08 59 c2 — vmulph xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf5, 0x74, 0x08, 0x59, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vdivsh_dispatched() {
        // 62 f5 76 08 5e c2 — vdivsh xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf5, 0x76, 0x08, 0x5e, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vcmpph_dispatched() {
        // 62 f3 7c 08 c2 c1 01 — vcmpph k0, xmm0, xmm1, 1
        let ops = lift64(&[0x62, 0xf3, 0x7c, 0x08, 0xc2, 0xc1, 0x01]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vcomish_sets_flags() {
        // 62 f5 7c 08 2f c1 — vcomish xmm0, xmm1
        let ops = lift64(&[0x62, 0xf5, 0x7c, 0x08, 0x2f, 0xc1]);
        assert!(!is_unimplemented(&ops));
        let flags = flags_written(&ops);
        assert!(flags.contains(&FLAG_ZF.to_string()));
    }

    #[test]
    fn test_lift_vcvtph2ps_dispatched() {
        // 62 f2 7d 08 13 c1 — vcvtph2ps xmm0, xmm1
        let ops = lift64(&[0x62, 0xf2, 0x7d, 0x08, 0x13, 0xc1]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vcvtsh2ss_dispatched() {
        // 62 f6 74 08 13 c2 — vcvtsh2ss xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf6, 0x74, 0x08, 0x13, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vfmadd213ph_dispatched() {
        // 62 f6 75 08 a8 c2 — vfmadd213ph xmm0, xmm1, xmm2 (EVEX.DDS.128.66.0F38.W0 A8)
        let ops = lift64(&[0x62, 0xf6, 0x75, 0x08, 0xa8, 0xc2]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "fmadd")
            )),
            "vfmadd213ph should write an Intrinsic(\"fmadd\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_vfmadd213sh_dispatched() {
        // 62 f6 75 08 a9 c2 — vfmadd213sh xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf6, 0x75, 0x08, 0xa9, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vfnmsub231sh_dispatched() {
        // vfnmsub231sh xmm0, xmm1, xmm2 — EVEX.DDS.LIG.66.0F38.W0 BF
        // 62 f6 75 08 bf c2
        let ops = lift64(&[0x62, 0xf6, 0x75, 0x08, 0xbf, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vsqrtph_dispatched() {
        // 62 f5 7c 08 51 c1 — vsqrtph xmm0, xmm1
        let ops = lift64(&[0x62, 0xf5, 0x7c, 0x08, 0x51, 0xc1]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vfmadd132ph_dispatched() {
        // 62 f6 75 08 98 c2 — vfmadd132ph xmm0, xmm1, xmm2
        let ops = lift64(&[0x62, 0xf6, 0x75, 0x08, 0x98, 0xc2]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_rdpkru_writes_eax() {
        // 0f 01 ee — rdpkru
        let ops = lift64(&[0x0f, 0x01, 0xee]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vcvtudq2pd_dispatched() {
        let ops = lift64_encoded_2(Code::EVEX_Vcvtudq2pd_xmm_k1z_xmmm64b32, Register::XMM0, Register::XMM1);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vcvtsd2usi_dispatched() {
        let ops = lift64_encoded_2(Code::EVEX_Vcvtsd2usi_r32_xmmm64_er, Register::EAX, Register::XMM1);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vbroadcastf32x4_dispatched() {
        let mem = iced_x86::MemoryOperand::new(
            Register::RAX,
            Register::None,
            1,
            0,
            1,
            false,
            Register::None,
        );
        let instr = iced_x86::Instruction::with2(Code::EVEX_Vbroadcastf32x4_ymm_k1z_m128, Register::YMM0, mem)
            .unwrap();
        let mut encoder = iced_x86::Encoder::new(64);
        let len = encoder.encode(&instr, 0x1000).unwrap();
        let bytes = encoder.take_buffer();
        let ops = lift_at(64, 0x1000, &bytes[..len]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_valignd_dispatched() {
        let instr = iced_x86::Instruction::with4(
            Code::EVEX_Valignd_xmm_k1z_xmm_xmmm128b32_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            1i32,
        )
        .unwrap();
        let mut encoder = iced_x86::Encoder::new(64);
        let len = encoder.encode(&instr, 0x1000).unwrap();
        let bytes = encoder.take_buffer();
        let ops = lift_at(64, 0x1000, &bytes[..len]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vfpclassps_dispatched() {
        let instr = iced_x86::Instruction::with3(
            Code::EVEX_Vfpclassps_kr_k1_xmmm128b32_imm8,
            Register::K0,
            Register::XMM1,
            0i32,
        )
        .unwrap();
        let mut encoder = iced_x86::Encoder::new(64);
        let len = encoder.encode(&instr, 0x1000).unwrap();
        let bytes = encoder.take_buffer();
        let ops = lift_at(64, 0x1000, &bytes[..len]);
        assert!(!is_unimplemented(&ops));
    }

    /// Encode a 4-register-operand instruction from its `iced_x86::Code`
    /// variant and lift it — for FMA4's explicit 4-operand VEX forms.
    fn lift64_encoded_4(
        code: iced_x86::Code,
        op0: Register,
        op1: Register,
        op2: Register,
        op3: Register,
    ) -> Vec<LlilAnnotatedInstr> {
        let instr = iced_x86::Instruction::with4(code, op0, op1, op2, op3).unwrap();
        let mut encoder = iced_x86::Encoder::new(64);
        let len = encoder.encode(&instr, 0x1000).unwrap();
        let bytes = encoder.take_buffer();
        lift_at(64, 0x1000, &bytes[..len])
    }

    #[test]
    fn test_lift_vfmaddpd_fma4_writes_dest() {
        // VFMADDPD xmm0, xmm1, xmm2, xmm3 — dst = xmm1*xmm2 + xmm3
        let ops = lift64_encoded_4(
            Code::VEX_Vfmaddpd_xmm_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            Register::XMM3,
        );
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "fmadd")
            )),
            "vfmaddpd (FMA4) should write an Intrinsic(\"fmadd\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_vfnmsubss_fma4_dispatched() {
        let ops = lift64_encoded_4(
            Code::VEX_Vfnmsubss_xmm_xmm_xmm_xmmm32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            Register::XMM3,
        );
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vfmaddsubpd_fma4_dispatched() {
        let ops = lift64_encoded_4(
            Code::VEX_Vfmaddsubpd_xmm_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            Register::XMM3,
        );
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_vfmaddsub213pd_fma3_dispatched() {
        let instr = iced_x86::Instruction::with3(
            Code::VEX_Vfmaddsub213pd_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let mut encoder = iced_x86::Encoder::new(64);
        let len = encoder.encode(&instr, 0x1000).unwrap();
        let bytes = encoder.take_buffer();
        let ops = lift_at(64, 0x1000, &bytes[..len]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_clwb_dispatched() {
        // 66 0f ae 30 — clwb [rax]
        let ops = lift64(&[0x66, 0x0f, 0xae, 0x30]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_pcmpistri_writes_ecx_not_source() {
        // 66 0f 3a 63 c1 00 — pcmpistri xmm0, xmm1, 0
        let ops = lift64(&[0x66, 0x0f, 0x3a, 0x63, 0xc1, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if is_dest(d, "ecx") && intrinsic_name(value) == Some("pcmpstri")
            )),
            "pcmpistri should write to ecx (implicit dest), not the xmm0 source operand, got {ops:?}"
        );
        assert!(!has_setreg_to(&ops, "xmm0"));
    }

    #[test]
    fn test_lift_pcmpistrm_writes_xmm0() {
        // 66 0f 3a 62 c1 00 — pcmpistrm xmm0, xmm1, 0
        let ops = lift64(&[0x66, 0x0f, 0x3a, 0x62, 0xc1, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "pcmpstrm")
            )),
            "pcmpistrm should write to xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_arpl_writes_dest() {
        // 63 c1 — arpl cx, ax
        let ops = lift64(&[0x63, 0xc1]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_movntdqa_reads_and_writes() {
        // 66 0f 38 2a c1 — movntdqa xmm0, [rcx] (reg form invalid; use mem)
        let ops = lift64(&[0x66, 0x0f, 0x38, 0x2a, 0x01]);
        assert!(!is_unimplemented(&ops));
    }

    #[test]
    fn test_lift_pmovsxbw_writes_dest() {
        // 66 0f 38 20 c1 — pmovsxbw xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x38, 0x20, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("pmovsx"))
            )),
            "pmovsxbw should write an Intrinsic(\"pmovsx\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_roundps_writes_dest() {
        // 66 0f 3a 08 c1 00 — roundps xmm0, xmm1, 0
        let ops = lift64(&[0x66, 0x0f, 0x3a, 0x08, 0xc1, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("round"))
            )),
            "roundps should write an Intrinsic(\"round\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_movbe_writes_dest() {
        // 0f 38 f0 00 — movbe eax, [rax]  (encoded as movbe r32, m32)
        let ops = lift64(&[0x0f, 0x38, 0xf0, 0x00]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { value, .. }
                    if intrinsic_name(value) == Some("movbe")
            )),
            "movbe should write an Intrinsic(\"movbe\", ..) result, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_cvtpi2pd_writes_dest() {
        // 66 0f 2a c1 — cvtpi2pd xmm0, mm1
        let ops = lift64(&[0x66, 0x0f, 0x2a, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("cvtpi2p"))
            )),
            "cvtpi2pd should write an Intrinsic(\"cvtpi2p\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_haddpd_writes_dest() {
        // 66 0f 7c c1 — haddpd xmm0, xmm1
        let ops = lift64(&[0x66, 0x0f, 0x7c, 0xc1]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("hadd"))
            )),
            "haddpd should write an Intrinsic(\"hadd\", ..) result into xmm0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_fchs_writes_st0() {
        // d9 e0 — fchs (no decoded operand; implicit ST(0) src+dest)
        let ops = lift64(&[0xd9, 0xe0]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "st0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "fchs")
            )),
            "fchs should write an Intrinsic(\"fchs\", ..) result into st0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_fldz_writes_st0() {
        // d9 ee — fldz (no decoded operand; pushes constant 0.0 onto ST(0))
        let ops = lift64(&[0xd9, 0xee]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "st0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "fldz")
            )),
            "fldz should write an Intrinsic(\"fldz\", ..) result into st0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_fstp_writes_memory() {
        // dd 1c 25 00 00 00 10 — fstp qword ptr [0x10000000]
        let ops = lift64(&[0xdd, 0x1c, 0x25, 0x00, 0x00, 0x00, 0x10]);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::Store { value, .. }
                    if matches!(value, LlilExpr::Intrinsic { name, .. } if name == "fstp")
            )),
            "fstp with a memory destination should emit a Store(Intrinsic(\"fstp\", ..)), got {ops:?}"
        );
    }

    // ── Crypto / CRC / SHA (lift_simd_write writeback) ──────────────────

    #[test]
    fn test_lift_crc32_writes_dest() {
        let iced =
            IcedInstruction::with2(Code::Crc32_r32_rm32, Register::EAX, Register::EBX).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if is_dest(d, "eax") && intrinsic_name(value) == Some("crc32")
        )));
    }

    #[test]
    fn test_lift_pclmulqdq_writes_dest() {
        let iced = IcedInstruction::with3(
            Code::Pclmulqdq_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "pclmulqdq")
        )));
    }

    #[test]
    fn test_lift_vpclmulqdq_writes_dest() {
        let iced = IcedInstruction::with4(
            Code::VEX_Vpclmulqdq_xmm_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.contains("pclmulqdq"))
        )));
    }

    #[test]
    fn test_lift_aesenc_writes_dest() {
        let iced =
            IcedInstruction::with2(Code::Aesenc_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "aesenc")
        )));
    }

    #[test]
    fn test_lift_aesdeclast_writes_dest() {
        let iced = IcedInstruction::with2(
            Code::Aesdeclast_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "aesdeclast")
        )));
    }

    #[test]
    fn test_lift_aesimc_writes_dest() {
        let iced =
            IcedInstruction::with2(Code::Aesimc_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "aesimc")
        )));
    }

    #[test]
    fn test_lift_aeskeygenassist_writes_dest() {
        let iced = IcedInstruction::with3(
            Code::Aeskeygenassist_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "aeskeygenassist")
        )));
    }

    #[test]
    fn test_lift_sha1msg1_writes_dest() {
        let iced =
            IcedInstruction::with2(Code::Sha1msg1_xmm_xmmm128, Register::XMM0, Register::XMM1)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "sha1msg1")
        )));
    }

    #[test]
    fn test_lift_sha1rnds4_writes_dest() {
        let iced = IcedInstruction::with3(
            Code::Sha1rnds4_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "sha1rnds4")
        )));
    }

    #[test]
    fn test_lift_sha256rnds2_writes_dest() {
        let iced = IcedInstruction::with2(
            Code::Sha256rnds2_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "sha256rnds2")
        )));
    }

    #[test]
    fn test_lift_sha256msg2_writes_dest() {
        let iced = IcedInstruction::with2(
            Code::Sha256msg2_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "sha256msg2")
        )));
    }

    // ── AVX-512 exotic ops (lift_simd_write) ─────────────────────────────

    #[test]
    fn test_lift_vgetexpps_writes_dest() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vgetexpps_xmm_k1z_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vgetexp"))
        )));
    }

    #[test]
    fn test_lift_vplzcntd_writes_dest() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vplzcntd_xmm_k1z_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vplzcnt"))
        )));
    }

    #[test]
    fn test_lift_vscalefps_writes_dest() {
        let iced = IcedInstruction::with3(
            Code::EVEX_Vscalefps_xmm_k1z_xmm_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vscalef"))
        )));
    }

    #[test]
    fn test_lift_vrangeps_writes_dest() {
        let iced = IcedInstruction::with4(
            Code::EVEX_Vrangeps_xmm_k1z_xmm_xmmm128b32_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            0u32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vrange"))
        )));
    }

    #[test]
    fn test_lift_vexpandps_writes_dest() {
        let iced = IcedInstruction::with2(
            Code::EVEX_Vexpandps_xmm_k1z_xmmm128,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vexpand"))
        )));
    }

    // ── AVX-512 K-mask registers (lift_simd_write) ──────────────────────

    #[test]
    fn test_lift_kandw_writes_kdest() {
        // kandw k0, k1, k2 — dst = k1 & k2
        let iced =
            IcedInstruction::with3(Code::VEX_Kandw_kr_kr_kr, Register::K0, Register::K1, Register::K2)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("kand"))
            )),
            "kandw should write an Intrinsic(\"kand\", ..) result into k0, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_kxorw_writes_kdest() {
        // kxorw k0, k1, k2 — dst = k1 ^ k2
        let iced =
            IcedInstruction::with3(Code::VEX_Kxorw_kr_kr_kr, Register::K0, Register::K1, Register::K2)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("kxor"))
        )));
    }

    #[test]
    fn test_lift_knotw_writes_kdest() {
        // knotw k0, k1 — dst = !k1
        let iced = IcedInstruction::with2(Code::VEX_Knotw_kr_kr, Register::K0, Register::K1).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("knot"))
        )));
    }

    #[test]
    fn test_lift_kmovw_writes_kdest() {
        // kmovw k0, k1 — dst = k1
        let iced = IcedInstruction::with2(Code::VEX_Kmovw_kr_km16, Register::K0, Register::K1).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("kmov"))
        )));
    }

    #[test]
    fn test_lift_kaddw_writes_kdest() {
        // kaddw k0, k1, k2 — dst = k1 + k2 (mask add)
        let iced =
            IcedInstruction::with3(Code::VEX_Kaddw_kr_kr_kr, Register::K0, Register::K1, Register::K2)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("kadd"))
        )));
    }

    #[test]
    fn test_lift_kunpckwd_writes_kdest() {
        // kunpckwd k0, k1, k2
        let iced = IcedInstruction::with3(
            Code::VEX_Kunpckwd_kr_kr_kr,
            Register::K0,
            Register::K1,
            Register::K2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("kunpck"))
        )));
    }

    #[test]
    fn test_lift_kshiftlw_writes_kdest() {
        // kshiftlw k0, k1, 3
        let iced =
            IcedInstruction::with3(Code::VEX_Kshiftlw_kr_kr_imm8, Register::K0, Register::K1, 3i32)
                .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "k0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("kshiftl"))
        )));
    }

    #[test]
    fn test_lift_ktestw_flag_only_no_writeback() {
        // ktestw k0, k1 — flag-only, no register writeback
        let iced = IcedInstruction::with2(Code::VEX_Ktestw_kr_kr, Register::K0, Register::K1).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetFlag { name, .. } if name == FLAG_ZF)));
        assert!(!ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetReg { .. })));
    }

    #[test]
    fn test_lift_kortestw_flag_only_no_writeback() {
        // kortestw k0, k1 — flag-only, no register writeback
        let iced =
            IcedInstruction::with2(Code::VEX_Kortestw_kr_kr, Register::K0, Register::K1).unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetFlag { name, .. } if name == FLAG_ZF)));
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetFlag { name, .. } if name == FLAG_CF)));
        assert!(!ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetReg { .. })));
    }

    // ── AVX-512 VPERMI2/VPERMT2 (lift_simd_write) ────────────────────────

    #[test]
    fn test_lift_vpermi2d_writes_dest() {
        // vpermi2d xmm0{k1}{z}, xmm1, xmm2 (EVEX-only encoding)
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpermi2d_xmm_k1z_xmm_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vpermi2"))
        )));
    }

    #[test]
    fn test_lift_vpermt2d_writes_dest() {
        // vpermt2d xmm0{k1}{z}, xmm1, xmm2 (EVEX-only encoding)
        let iced = IcedInstruction::with3(
            Code::EVEX_Vpermt2d_xmm_k1z_xmm_xmmm128b32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vpermt2"))
        )));
    }

    // ── GFNI / VAES (lift_simd_write) ─────────────────────────────────────

    #[test]
    fn test_lift_gf2p8affineqb_writes_dest() {
        // gf2p8affineqb xmm0, xmm1, 0x1
        let iced = IcedInstruction::with3(
            Code::Gf2p8affineqb_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            1i32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "gf2p8affineqb")
        )));
    }

    #[test]
    fn test_lift_vaesenc_writes_dest() {
        // vaesenc xmm0, xmm1, xmm2 (VEX encoding — distinct Mnemonic from
        // legacy SSE Aesenc)
        let iced = IcedInstruction::with3(
            Code::VEX_Vaesenc_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.contains("aesenc"))
        )));
    }

    // ── Vpternlogd (lift_simd_write) ─────────────────────────────────────

    #[test]
    fn test_lift_vpternlogd_writes_dest() {
        // vpternlogd xmm0{k1}{z}, xmm1, xmm2, 0x0 (EVEX-only encoding)
        let iced = IcedInstruction::with4(
            Code::EVEX_Vpternlogd_xmm_k1z_xmm_xmmm128b32_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            0i32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vpternlog"))
            )),
            "vpternlogd should write an Intrinsic(\"vpternlog\", ..) result into xmm0, got {ops:?}"
        );
    }

    // ── VEX-prefixed duplicates of already-fixed legacy SSE ops
    //    (lift_simd_write) ───────────────────────────────────────────────

    #[test]
    fn test_lift_vpshufd_writes_dest() {
        // vpshufd xmm0, xmm1, 0
        let iced = IcedInstruction::with3(
            Code::VEX_Vpshufd_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            0i32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "vpshufd")
        )));
    }

    #[test]
    fn test_lift_vpalignr_writes_dest() {
        // vpalignr xmm0, xmm1, xmm2, 1
        let iced = IcedInstruction::with4(
            Code::VEX_Vpalignr_xmm_xmm_xmmm128_imm8,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            1i32,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name == "vpalignr")
        )));
    }

    #[test]
    fn test_lift_vpcmpeqb_writes_dest() {
        // vpcmpeqb xmm0, xmm1, xmm2
        let iced = IcedInstruction::with3(
            Code::VEX_Vpcmpeqb_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vpcmpeq"))
        )));
    }

    #[test]
    fn test_lift_vpminub_writes_dest() {
        // vpminub xmm0, xmm1, xmm2
        let iced = IcedInstruction::with3(
            Code::VEX_Vpminub_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if (name.contains("vpminmax") || name.contains("vpminub")))
        )));
    }

    #[test]
    fn test_lift_vpmovmskb_writes_gpr() {
        // vpmovmskb eax, xmm1
        let iced = IcedInstruction::with2(
            Code::VEX_Vpmovmskb_r32_xmm,
            Register::EAX,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(
            ops.iter().any(|o| matches!(
                &o.instr,
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if is_dest(d, "eax") && intrinsic_name(value).is_some_and(|n| n.contains("vmovmsk") || n.contains("movmsk"))
            )),
            "vpmovmskb should write an Intrinsic(\"vmovmsk\", ..) result into eax, got {ops:?}"
        );
    }

    #[test]
    fn test_lift_vunpcklps_writes_dest() {
        // vunpcklps xmm0, xmm1, xmm2
        let iced = IcedInstruction::with3(
            Code::VEX_Vunpcklps_xmm_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vunpck"))
        )));
    }

    // ── Vcvt* VEX conversions (lift_simd_write) ──────────────────────────

    #[test]
    fn test_lift_vcvtss2sd_writes_dest() {
        // vcvtss2sd xmm0, xmm1, xmm2
        let iced = IcedInstruction::with3(
            Code::VEX_Vcvtss2sd_xmm_xmm_xmmm32,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vcvt"))
        )));
    }

    #[test]
    fn test_lift_vcvtdq2ps_writes_dest() {
        // vcvtdq2ps xmm0, xmm1
        let iced = IcedInstruction::with2(
            Code::VEX_Vcvtdq2ps_xmm_xmmm128,
            Register::XMM0,
            Register::XMM1,
        )
        .unwrap();
        let ops = lift_instr(64, &iced);
        assert!(!is_unimplemented(&ops));
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                if d == "xmm0" && matches!(value, LlilExpr::Intrinsic { name, .. } if name.starts_with("vcvt"))
        )));
    }

    // ── VSIB gather ─────────────────────────────────────────────────────

    fn count_loads(ops: &[LlilAnnotatedInstr]) -> usize {
        fn walk(e: &LlilExpr, n: &mut usize) {
            if let LlilExpr::Load { addr, .. } = e {
                *n += 1;
                walk(addr, n);
                return;
            }
            match e {
                LlilExpr::CondExpr { cond, true_val, false_val, .. } => {
                    walk(cond, n);
                    walk(true_val, n);
                    walk(false_val, n);
                }
                LlilExpr::Or(a, b, _)
                | LlilExpr::AddT(a, b, _)
                | LlilExpr::MulT(a, b, _)
                | LlilExpr::Shr(a, b, _)
                | LlilExpr::ShlT(a, b, _)
                | LlilExpr::And(a, b, _) => {
                    walk(a, n);
                    walk(b, n);
                }
                LlilExpr::LowPart { expr, .. }
                | LlilExpr::ZeroExtend { expr, .. }
                | LlilExpr::SignExtend { expr, .. } => walk(expr, n),
                _ => {}
            }
        }
        let mut n = 0;
        for o in ops {
            if let LlilInstruction::SetReg { value, .. } = &o.instr {
                walk(value, &mut n);
            }
        }
        n
    }

    #[test]
    fn test_lift_vpgatherdd_vex_writes_dest_and_has_per_lane_loads() {
        // VPGATHERDD xmm0, [rax + xmm1*4], xmm2
        // C4 E2 69 90 04 88
        let ops = lift64(&[0xC4, 0xE2, 0x69, 0x90, 0x04, 0x88]);
        assert!(!is_unimplemented(&ops));
        // 4 dword lanes in a 128-bit dest -> 4 per-lane Load nodes.
        assert_eq!(count_loads(&ops), 4);
        assert!(ops.iter().any(|o| matches!(
            &o.instr,
            LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), .. } if d == "xmm0"
        )));
    }

    #[test]
    fn test_lift_vpgatherdd_vex_gates_on_mask_lane_sign_bit() {
        let ops = lift64(&[0xC4, 0xE2, 0x69, 0x90, 0x04, 0x88]);
        let value = ops
            .iter()
            .find_map(|o| match &o.instr {
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" =>
                {
                    Some(value)
                }
                _ => None,
            })
            .expect("expected SetReg xmm0");
        // The outermost fold is `Or(acc_so_far, Shl(ZeroExtend(CondExpr(...)), ...))`;
        // walk down to find at least one CondExpr whose condition is a
        // CmpSlt against 0 (the VEX mask-lane MSB test from `is_negative`).
        fn has_sign_bit_cond(e: &LlilExpr) -> bool {
            match e {
                LlilExpr::CondExpr { cond, .. } => {
                    matches!(**cond, LlilExpr::CmpSlt(_, _)) || has_sign_bit_cond(cond)
                }
                LlilExpr::Or(a, b, _) | LlilExpr::ShlT(a, b, _) => {
                    has_sign_bit_cond(a) || has_sign_bit_cond(b)
                }
                LlilExpr::ZeroExtend { expr, .. } => has_sign_bit_cond(expr),
                _ => false,
            }
        }
        assert!(has_sign_bit_cond(value));
    }

    #[test]
    fn test_lift_vgatherqpd_evex_writes_dest_and_gates_on_kmask() {
        // VGATHERQPD xmm0{k1}, [rax + xmm1*8]  (EVEX form: k-register mask,
        // no explicit mask-register operand)
        // EVEX.128.66.0F38.W1 93 /r
        // 62 F2 FD 09 93 04 C8
        let ops = lift64(&[0x62, 0xF2, 0xFD, 0x09, 0x93, 0x04, 0xC8]);
        assert!(!is_unimplemented(&ops));
        // 2 qword lanes in a 128-bit dest -> 2 per-lane Load nodes.
        assert_eq!(count_loads(&ops), 2);
        let value = ops
            .iter()
            .find_map(|o| match &o.instr {
                LlilInstruction::SetReg { dest: LlilRegister::Concrete(d), value, .. }
                    if d == "xmm0" =>
                {
                    Some(value)
                }
                _ => None,
            })
            .expect("expected SetReg xmm0");
        // EVEX form gates on a k-register bit via CmpNe(And(k_bit, 1), 0),
        // not the VEX CmpSlt sign-bit test.
        fn has_kmask_cond(e: &LlilExpr) -> bool {
            match e {
                LlilExpr::CondExpr { cond, .. } => {
                    matches!(**cond, LlilExpr::CmpNe(_, _)) || has_kmask_cond(cond)
                }
                LlilExpr::Or(a, b, _) | LlilExpr::ShlT(a, b, _) => {
                    has_kmask_cond(a) || has_kmask_cond(b)
                }
                LlilExpr::ZeroExtend { expr, .. } => has_kmask_cond(expr),
                _ => false,
            }
        }
        assert!(has_kmask_cond(value));
    }

    // ── Mnemonic dispatch coverage report ─────────────────────────────────
    //
    // iced_x86::Mnemonic (v1.21) is a plain #[repr(u16)] C-like enum with no
    // public iterator/values() API, so we can't enumerate variants at
    // runtime via reflection. Instead we statically count how many distinct
    // `M::<Variant>` identifiers are referenced anywhere in this file's
    // source (a reasonable proxy for "has a real lifting arm, not just
    // falls through to `Unimplemented`") against the known total variant
    // count of the vendored iced_x86 1.21.0 `Mnemonic` enum (1894,
    // including `INVALID`), obtained by counting `Name = N,` entries in
    // iced_x86-1.21.0/src/mnemonic.rs.
    //
    // This is an approximation, not exact ground truth: (a) an `M::<Variant>`
    // reference may appear in a comment rather than a live match arm — do NOT
    // spell such an example with a concrete alphanumeric name anywhere in this
    // file, because the scanner below would count the comment itself as a
    // covered mnemonic. That is not hypothetical: a placeholder variant name
    // written in this very comment inflated the count to 1895/1894, which is
    // what the `dispatched <= TOTAL_MNEMONIC_VARIANTS` assertion now catches.
    // And
    // (b) a single dispatch arm often lifts a *family* of related mnemonics
    // (e.g. `Vgatherdps | Vgatherdpd | ...`) with equal fidelity, so raw
    // variant-count coverage understates how much real x86 behavior is
    // covered relative to how many mnemonics are genuinely obscure/rare
    // (undocumented, vendor-specific, or FPU stack aliases that never
    // appear in compiler-generated code).
    /// Mnemonics that are deliberately NOT dispatched by an `M::` arm, with
    /// the reason. Counting these as "missing" understates real coverage and
    /// has repeatedly caused wasted effort chasing phantom gaps, so they are
    /// enumerated explicitly rather than silently ignored.
    ///
    /// Two groups:
    /// 1. **Structurally dispatched** — `dispatch_fallback` routes the whole
    ///    Jcc / SETcc / CMOVcc condition-code family via
    ///    `iced.condition_code()` + `is_setcc`/`is_cmovcc`, so these have real
    ///    lifting arms without any `M::` literal ever appearing for them.
    /// 2. **Not instructions** — iced pseudo-mnemonics for data directives and
    ///    the invalid/filler sentinels; there is nothing to lift.
    const NON_DISPATCH_MNEMONICS: &[&str] = &[
        // 1. Jcc — lifted by dispatch_fallback -> lift_jcc.
        "Ja", "Jae", "Jb", "Jbe", "Je", "Jg", "Jge", "Jl", "Jle", "Jne", "Jno", "Jnp", "Jns",
        "Jo", "Jp", "Js", //
        // 1. SETcc — lifted by dispatch_fallback -> lift_setcc.
        "Seta", "Setae", "Setb", "Setbe", "Sete", "Setg", "Setge", "Setl", "Setle", "Setne",
        "Setno", "Setnp", "Setns", "Seto", "Setp", "Sets", //
        // 1. CMOVcc — lifted by dispatch_fallback -> lift_cmovcc.
        "Cmova", "Cmovae", "Cmovb", "Cmovbe", "Cmove", "Cmovg", "Cmovge", "Cmovl", "Cmovle",
        "Cmovne", "Cmovno", "Cmovnp", "Cmovns", "Cmovo", "Cmovp", "Cmovs", //
        // 2. Not instructions: data directives / sentinels.
        "INVALID", "Db", "Dd", "Dq", "Dw", "Zero_bytes", "Reservednop",
    ];

    #[test]
    fn test_mnemonic_coverage_report() {
        const TOTAL_MNEMONIC_VARIANTS: usize = 1894;

        let src = include_str!("lift.rs");
        let mut seen = std::collections::HashSet::new();
        let mut idx = 0usize;
        while let Some(pos) = src[idx..].find("M::") {
            let start = idx + pos + 3;
            let rest = &src[start..];
            let end = start
                + rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
            if end > start {
                seen.insert(&src[start..end]);
            }
            idx = end.max(start + 1);
        }

        // The NON_DISPATCH set is by definition disjoint from the `M::` arms;
        // if one ever gains an explicit arm, the two would double-count and
        // silently inflate coverage past 100%. Catch that here.
        for m in NON_DISPATCH_MNEMONICS {
            assert!(
                !seen.contains(m),
                "`{m}` is listed in NON_DISPATCH_MNEMONICS but now also has an \
                 explicit `M::{m}` dispatch arm — remove it from that list, \
                 otherwise coverage is double-counted."
            );
        }

        let dispatched = seen.len() + NON_DISPATCH_MNEMONICS.len();

        // Coverage above 100% is arithmetically impossible, so it means the
        // scanner counted something that is not a real enum variant — almost
        // always an `M::`-prefixed name written in a comment or a string
        // literal. Without this guard the metric silently over-reports, which
        // is strictly worse than under-reporting: it manufactures false
        // confidence that there is no work left.
        assert!(
            dispatched <= TOTAL_MNEMONIC_VARIANTS,
            "counted {dispatched} covered mnemonics but the enum only has \
             {TOTAL_MNEMONIC_VARIANTS} — the `M::` scan matched a non-variant \
             (check for an `M::`-prefixed name in a comment or string literal \
             in this file), or NON_DISPATCH_MNEMONICS double-counts."
        );

        let pct = 100.0 * dispatched as f64 / TOTAL_MNEMONIC_VARIANTS as f64;
        println!(
            "mnemonic dispatch coverage: {dispatched}/{TOTAL_MNEMONIC_VARIANTS} ({pct:.1}%) = \
             {} explicit `M::` dispatch arms + {} structurally-dispatched/non-instruction \
             mnemonics (Jcc/SETcc/CMOVcc via condition_code(), data directives) — everything \
             else falls through to LlilInstruction::Unimplemented in dispatch_fallback",
            seen.len(),
            NON_DISPATCH_MNEMONICS.len(),
        );

        // Regression guard: coverage should never silently shrink. Bump this
        // floor down only if mnemonics were deliberately removed/merged.
        assert!(
            dispatched == TOTAL_MNEMONIC_VARIANTS,
            "mnemonic dispatch coverage regressed: {dispatched}/{TOTAL_MNEMONIC_VARIANTS}. \
             Coverage reached 100% on 2026-07-16 and must stay there: every iced \
             Mnemonic variant now either has an explicit `M::` dispatch arm or is \
             listed in NON_DISPATCH_MNEMONICS with a reason. A drop means a dispatch \
             arm was lost — add it back rather than lowering this bound."
        );
    }

    // ── VMX / SVM / 3DNow! / misc-system dispatch ───────────────────────

    fn has_intrinsic_named(ops: &[LlilAnnotatedInstr], name: &str) -> bool {
        ops.iter().any(|o| {
            matches!(&o.instr, LlilInstruction::Intrinsic { name: n, .. } if n == name)
        })
    }

    #[test]
    fn test_lift_vmcall_effect_only() {
        // 0F 01 C1 — VMCALL
        let ops = lift64(&[0x0f, 0x01, 0xc1]);
        assert!(has_intrinsic_named(&ops, "vmcall"));
        // Effect-only: no SetReg/Store writeback should be emitted.
        assert!(!ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetReg { .. })));
    }

    #[test]
    fn test_lift_vmxoff_effect_only() {
        // 0F 01 C4 — VMXOFF
        let ops = lift64(&[0x0f, 0x01, 0xc4]);
        assert!(has_intrinsic_named(&ops, "vmxoff"));
    }

    #[test]
    fn test_lift_vmread_writes_dest() {
        // 0F 78 D8 — VMREAD rax, rbx (dest = r/m64 = rax)
        let ops = lift64(&[0x0f, 0x78, 0xd8]);
        assert!(has_setreg_to(&ops, "rax"));
    }

    // ── MPX / CET / misc dispatch ────────────────────────────────────────

    #[test]
    fn test_lift_bndmk_writes_bound_bndcheck_effect_only() {
        // F3 0F 1B 00 — BNDMK bnd0, [rax]. BNDMK WRITES its bound register,
        // so it is a SetReg carrying the intrinsic, not a bare intrinsic
        // statement. (The `_effect_only` name pinned the under-modelling —
        // fourth instance of that pattern in this crate.)
        let ops = lift64_mpx(&[0xf3, 0x0f, 0x1b, 0x00]);
        let rendered = ops.iter().map(|o| format!("{:?}", o.instr)).collect::<Vec<_>>().join("
");
        assert!(
            rendered.contains("SetReg") && rendered.contains("bndmk"),
            "BNDMK must write its bound register:
{rendered}"
        );
        // The CHECK instructions genuinely write nothing — they only fault.
        // F3 0F 1A 00 — BNDCL bnd0, [rax]
        let ops = lift64_mpx(&[0xf3, 0x0f, 0x1a, 0x00]);
        assert!(has_intrinsic_named(&ops, "bndcl"));
        // F2 0F 1A 00 — BNDCU bnd0, [rax]
        let ops = lift64_mpx(&[0xf2, 0x0f, 0x1a, 0x00]);
        assert!(has_intrinsic_named(&ops, "bndcu"));
        // F2 0F 1B 00 — BNDCN bnd0, [rax]
        let ops = lift64_mpx(&[0xf2, 0x0f, 0x1b, 0x00]);
        assert!(has_intrinsic_named(&ops, "bndcn"));
    }

    #[test]
    fn test_lift_bndmov_bndldx_bndstx_effects() {
        // 66 0F 1A C1 — BNDMOV bnd0, bnd1
        let ops = lift64_mpx(&[0x66, 0x0f, 0x1a, 0xc1]);
        assert!(has_intrinsic_named(&ops, "bndmov"));
        // 0F 1A 04 00 — BNDLDX bnd0, [rax + rax]. LOADS into a bound
        // register, so it writes its destination.
        let ops = lift64_mpx(&[0x0f, 0x1a, 0x04, 0x00]);
        let rendered = ops.iter().map(|o| format!("{:?}", o.instr)).collect::<Vec<_>>().join("
");
        assert!(
            rendered.contains("SetReg") && rendered.contains("bndldx"),
            "BNDLDX must write its bound register:
{rendered}"
        );
        // 0F 1B 04 00 — BNDSTX [rax + rax], bnd0
        let ops = lift64_mpx(&[0x0f, 0x1b, 0x04, 0x00]);
        assert!(has_intrinsic_named(&ops, "bndstx"));
    }

    #[test]
    fn test_lift_endbr32_endbr64_marker_nop() {
        // F3 0F 1E FA — ENDBR64
        let ops = lift64(&[0xf3, 0x0f, 0x1e, 0xfa]);
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::Nop)));
        // F3 0F 1E FB — ENDBR32
        let ops = lift64(&[0xf3, 0x0f, 0x1e, 0xfb]);
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::Nop)));
    }

    #[test]
    fn test_lift_rdsspd_rdsspq_writes_dest() {
        // F3 0F 1E C8 — RDSSPD eax
        let ops = lift64(&[0xf3, 0x0f, 0x1e, 0xc8]);
        assert!(has_setreg_to(&ops, "eax"));
        // F3 48 0F 1E C8 — RDSSPQ rax
        let ops = lift64(&[0xf3, 0x48, 0x0f, 0x1e, 0xc8]);
        assert!(has_setreg_to(&ops, "rax"));
    }

    #[test]
    fn test_lift_shadow_stack_ops_effects_and_stores() {
        // F3 0F AE E8 — INCSSPD eax
        let ops = lift64(&[0xf3, 0x0f, 0xae, 0xe8]);
        assert!(has_intrinsic_named(&ops, "incssp"));
        // F3 0F 01 EA — SAVEPREVSSP
        let ops = lift64(&[0xf3, 0x0f, 0x01, 0xea]);
        assert!(has_intrinsic_named(&ops, "saveprevssp"));
        // F3 0F 01 E8 — SETSSBSY (no operand: still a bare intrinsic)
        let ops = lift64(&[0xf3, 0x0f, 0x01, 0xe8]);
        assert!(has_intrinsic_named(&ops, "setssbsy"));

        // RSTORSSP [rax] and CLRSSBSY [rax] WRITE shadow-stack memory — the
        // decoder reports the access — so the IL must contain a STORE, with the
        // intrinsic as the stored value. This test previously asserted they were
        // "effect only", pinning the same under-modelling that the WRSS/WRUSS
        // test did: SECOND instance of the rule that **a test name containing
        // the assumption (`_effect_only`) is where a defect is frozen**.
        for (label, bytes, name) in [
            ("RSTORSSP [rax]", &[0xf3u8, 0x0f, 0x01, 0x28][..], "rstorssp"),
            ("CLRSSBSY [rax]", &[0xf3, 0x0f, 0xae, 0x30][..], "clrssbsy"),
        ] {
            let ops = lift64(bytes);
            let rendered = ops
                .iter()
                .map(|o| format!("{:?}", o.instr))
                .collect::<Vec<_>>()
                .join("
");
            assert!(
                rendered.contains("Store {"),
                "{label}: writes shadow-stack memory but the IL has no Store:
{rendered}"
            );
            assert!(rendered.contains(name), "{label}: intrinsic lost:
{rendered}");
        }
    }

    /// WRSS/WRUSS WRITE their memory operand (shadow stack), so the IL must
    /// contain a STORE — not merely an effect-only intrinsic.
    ///
    /// This test previously asserted the opposite (`..._effect_only`, checking
    /// only for an `Intrinsic` STATEMENT), pinning the under-modelling that
    /// `memory_effects_vs_iced.rs` later flagged: with no store, the shadow
    /// stack looked never-written and dead-store elimination could drop the
    /// address computation. The decoder is the authority here — it reports the
    /// memory operand as `Write` — so the test was updated, not the fix
    /// reverted. The intrinsic is still present, now as the STORED VALUE, which
    /// keeps the "we do not model the exact shadow-stack semantics" honesty.
    #[test]
    fn test_lift_wrss_wruss_store_to_shadow_stack() {
        for (label, bytes, name) in [
            ("WRSSD [rax], ecx", &[0x0fu8, 0x38, 0xf6, 0x08][..], "wrss"),
            ("WRSSQ [rax], rcx", &[0x48, 0x0f, 0x38, 0xf6, 0x08][..], "wrss"),
            ("WRUSSD [rax], ecx", &[0x66, 0x0f, 0x38, 0xf5, 0x08][..], "wruss"),
            ("WRUSSQ [rax], rcx", &[0x66, 0x48, 0x0f, 0x38, 0xf5, 0x08][..], "wruss"),
        ] {
            let ops = lift64(bytes);
            let rendered = ops
                .iter()
                .map(|o| format!("{:?}", o.instr))
                .collect::<Vec<_>>()
                .join("
");
            assert!(
                rendered.contains("Store {"),
                "{label}: the memory operand is written, but no Store:
{rendered}"
            );
            assert!(
                rendered.contains(name),
                "{label}: the `{name}` intrinsic should carry the stored value:
{rendered}"
            );
        }
    }

    #[test]
    fn test_lift_stgi_clgi_svm_effect_only() {
        // 0F 01 DC — STGI
        let ops = lift64(&[0x0f, 0x01, 0xdc]);
        assert!(has_intrinsic_named(&ops, "stgi"));
        // 0F 01 DD — CLGI
        let ops = lift64(&[0x0f, 0x01, 0xdd]);
        assert!(has_intrinsic_named(&ops, "clgi"));
    }

    #[test]
    fn test_lift_vmrun_vmmcall_svm() {
        // 0F 01 D8 — VMRUN
        let ops = lift64(&[0x0f, 0x01, 0xd8]);
        assert!(has_intrinsic_named(&ops, "vmrun"));
        // 0F 01 D9 — VMMCALL
        let ops = lift64(&[0x0f, 0x01, 0xd9]);
        assert!(has_intrinsic_named(&ops, "vmmcall"));
    }

    #[test]
    fn test_lift_wbinvd_invd_rsm() {
        assert!(has_intrinsic_named(&lift64(&[0x0f, 0x09]), "wbinvd"));
        assert!(has_intrinsic_named(&lift64(&[0x0f, 0x08]), "invd"));
        assert!(has_intrinsic_named(&lift64(&[0x0f, 0xaa]), "rsm"));
    }

    #[test]
    fn test_lift_femms_effect_only() {
        // 0F 0E — FEMMS
        let ops = lift64(&[0x0f, 0x0e]);
        assert!(has_intrinsic_named(&ops, "femms"));
    }

    #[test]
    fn test_lift_pfadd_writes_mm_dest() {
        // 0F 0F C1 9E — PFADD mm0, mm1
        let ops = lift64(&[0x0f, 0x0f, 0xc1, 0x9e]);
        assert!(has_setreg_to(&ops, "mm0"));
        assert!(ops
            .iter()
            .any(|o| matches!(&o.instr, LlilInstruction::SetReg { value, .. }
                if matches!(value, LlilExpr::Intrinsic { name, .. } if name == "pfadd"))));
    }

    #[test]
    fn test_lift_pf2id_writes_mm_dest() {
        // 0F 0F C1 1D — PF2ID mm0, mm1
        let ops = lift64(&[0x0f, 0x0f, 0xc1, 0x1d]);
        assert!(has_setreg_to(&ops, "mm0"));
    }

    // ── 32-bit GPR aliasing onto the 64-bit parent ──────────────────────────
    //
    // These exercise the two pure halves directly. The end-to-end path is
    // env-gated through a process-wide `OnceLock`, so toggling it from a test
    // would race every other test in this binary; the corpus measurement is
    // what validates the wiring.

    #[test]
    fn gpr_narrow_parent_maps_low_views_but_not_high_bytes_nor_the_frame() {
        assert_eq!(gpr_narrow_parent("cl"), Some(("rcx", 8)));
        assert_eq!(gpr_narrow_parent("dil"), Some(("rdi", 8)));
        // `iced_x86` stampa il byte basso di r8-r15 come `rNl`, non `rNb`:
        // riconoscere solo la forma `b` faceva mancare quei registri in
        // silenzio (844 locali difettose misurate).
        assert_eq!(gpr_narrow_parent("r13l"), Some(("r13", 8)));
        assert_eq!(gpr_narrow_parent("r8l"), Some(("r8", 8)));
        assert_eq!(gpr_narrow_parent("r15l"), Some(("r15", 8)));
        assert_eq!(gpr_narrow_parent("r13b"), Some(("r13", 8)));
        assert_eq!(gpr_narrow_parent("r9w"), Some(("r9", 16)));
        assert_eq!(gpr_narrow_parent("ax"), Some(("rax", 16)));
        // ah/ch/dh/bh aliasano i bit 8..15, non quelli bassi: la stessa
        // maschera NON li descrive, quindi restano fuori.
        assert_eq!(gpr_narrow_parent("ah"), None);
        assert_eq!(gpr_narrow_parent("ch"), None);
        // Il frame e' modellato a parte.
        assert_eq!(gpr_narrow_parent("spl"), None);
        assert_eq!(gpr_narrow_parent("bp"), None);
        // Le viste basse di `rbp` stanno nella tabella SEPARATA, dietro gate:
        // `rbp` e' spesso general-purpose (`mov %rax,%rbp` + `cmp %bpl,(%rbp)`),
        // e lasciarle fuori creava un registro che nessuno scrive mai.
        assert_eq!(gpr_frame_narrow_parent("bpl"), Some(("rbp", 8)));
        assert_eq!(gpr_frame_narrow_parent("bp"), Some(("rbp", 16)));
        // ⚠ `spl`/`sp` restano fuori ANCHE da quella: la tracciatura dello
        // stack pointer dipende da un'aritmetica pulita di `sp`.
        assert_eq!(gpr_frame_narrow_parent("spl"), None);
        assert_eq!(gpr_frame_narrow_parent("sp"), None);
        // Larghezze non strette.
        assert_eq!(gpr_narrow_parent("ecx"), None);
        assert_eq!(gpr_narrow_parent("rcx"), None);
    }

    #[test]
    fn an_8_bit_write_preserves_the_upper_bits_of_its_parent() {
        // E' LA differenza rispetto ai 32 bit: `mov $1,%cl` NON azzera
        // rcx[8..63]. Se questa transform producesse uno zero-extend, il
        // valore verrebbe silenziosamente corrotto.
        let w = widen_gpr_narrow_write(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("cl".to_string()),
            size: Size::Byte,
            value: LlilExpr::Const { value: 1, size: Size::Byte },
        });
        let LlilInstruction::SetReg { dest, size, value } = w else { panic!("SetReg atteso") };
        assert_eq!(dest, LlilRegister::Concrete("rcx".to_string()));
        assert_eq!(size, Size::QWord);
        let txt = format!("{value}");
        assert!(txt.contains("rcx"), "i bit alti del padre devono essere LETTI: {txt}");
        assert!(!matches!(value, LlilExpr::ZeroExtend { .. }), "non e' uno zero-extend: {txt}");
    }

    #[test]
    fn a_16_bit_write_masks_to_16_bits_not_8() {
        let w = widen_gpr_narrow_write(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("r9w".to_string()),
            size: Size::Word,
            value: LlilExpr::Const { value: 7, size: Size::Word },
        });
        let LlilInstruction::SetReg { dest, value, .. } = w else { panic!("SetReg atteso") };
        assert_eq!(dest, LlilRegister::Concrete("r9".to_string()));
        let txt = format!("{value}");
        // Il Display stampa in ESADECIMALE: la maschera a 16 bit e' 0xffff,
        // e quella di conservazione dei bit alti 0xffffffffffff0000.
        assert!(txt.contains("0xffff.8"), "maschera a 16 bit attesa: {txt}");
        assert!(
            txt.contains("0xffffffffffff0000"),
            "i bit sopra il 15 devono essere PRESERVATI: {txt}"
        );
    }

    #[test]
    fn a_32_bit_write_is_left_to_the_zero_extend_rule() {
        // Guardia: questa transform non deve rubare i 32 bit, che hanno la
        // regola OPPOSTA (azzerano i bit alti).
        let orig = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("ecx".to_string()),
            size: Size::DWord,
            value: LlilExpr::Const { value: 1, size: Size::DWord },
        };
        assert_eq!(widen_gpr_narrow_write(orig.clone()), orig);
    }

    #[test]
    fn gpr32_parent_maps_the_whole_32_bit_file_but_not_sp_or_bp() {
        assert_eq!(gpr32_parent("eax"), Some("rax"));
        assert_eq!(gpr32_parent("r8d"), Some("r8"));
        assert_eq!(gpr32_parent("r15d"), Some("r15"));
        // Already 64-bit, or 8/16-bit: not this subclass.
        assert_eq!(gpr32_parent("rax"), None);
        assert_eq!(gpr32_parent("al"), None);
        assert_eq!(gpr32_parent("ax"), None);
        // Deliberately excluded — frame reconstruction owns these.
        assert_eq!(gpr32_parent("esp"), None);
        assert_eq!(gpr32_parent("ebp"), None);
    }

    #[test]
    fn a_32_bit_write_lands_on_the_parent_and_materialises_the_zero_extension() {
        let w = widen_gpr32_write(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("eax".to_string()),
            size: Size::DWord,
            value: LlilExpr::Const { value: 7, size: Size::DWord },
        });
        let LlilInstruction::SetReg { dest, size, value } = w else {
            panic!("expected SetReg");
        };
        assert_eq!(dest, LlilRegister::Concrete("rax".to_string()));
        // A later 64-bit READ of `rax` therefore sees the zero-extended value,
        // not a separate `eax` location — the defect this whole change targets.
        assert_eq!(size, Size::QWord);
        assert!(
            matches!(value, LlilExpr::ZeroExtend { from: Size::DWord, to: Size::QWord, .. }),
            "the truncation semantics must be materialised, not implied by the width"
        );
    }

    #[test]
    fn a_64_bit_write_is_left_exactly_alone() {
        let orig = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".to_string()),
            size: Size::QWord,
            value: LlilExpr::Const { value: 7, size: Size::QWord },
        };
        assert_eq!(widen_gpr32_write(orig.clone()), orig);
    }

    #[test]
    fn an_8_bit_write_is_left_alone_so_its_masking_is_not_silently_dropped() {
        let orig = LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("al".to_string()),
            size: Size::Byte,
            value: LlilExpr::Const { value: 7, size: Size::Byte },
        };
        assert_eq!(widen_gpr32_write(orig.clone()), orig);
    }
}
