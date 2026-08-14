//! PowerPC /`PowerPC64`4 LLIL lifter (`PpcLifter`).
//!
//! Mnemonic-driven lifter for 32-bit and 64-bit PowerPC (ELF ABI).
//!
//! # Register conventions (ELF ABI)
//!
//! | Reg    | Role                                  |
//! |--------|---------------------------------------|
//! | r0     | Volatile scratch / zero in some addrs |
//! | r1     | Stack pointer (sp)                    |
//! | r2     | TOC pointer (64-bit ELF)              |
//! | r3Ã¢â‚¬â€œr10 | Argument / return registers           |
//! | r3     | Primary integer return register       |
//! | r31    | Frame pointer (by convention)         |
//! | lr     | Link register (return address)        |
//! | ctr    | Count register (loop / indirect call) |
//! | xer    | Integer exception register            |
//! | cr0Ã¢â‚¬â€œcr7| Condition register fields             |
//!
//! # Rc (record) bit
//!
//! Many PowerPC instructions optionally set `cr0` when a trailing `.` is
//! appended to the mnemonic (e.g. `add.` vs `add`).  We strip the trailing
//! dot before dispatching and emit a `cr0` update effect when present.

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// PpcLifter
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Mnemonic-driven LLIL lifter for 32-bit and 64-bit PowerPC.
#[derive(Debug, Clone)]
pub struct PpcLifter {
    /// Pointer-size in bits: 32 or 64.
    pub bits: u32,
}

/// The PowerPC mnemonics that actually HAVE an `OE` (overflow-enabled) form,
/// per the ISA. Stripping a trailing `o` from anything else corrupts the
/// mnemonic.
///
/// Three real instructions end in `o` WITHOUT it being the OE suffix, and all
/// three were being mangled into unreachable match arms:
///
/// * **`eieio`** — Enforce In-order Execution of I/O, a memory barrier. Became
///   `eiei`, so the barrier lifted as an unknown intrinsic.
/// * **`bso`** — Branch if Summary Overflow. Became `bs`: a CONDITIONAL BRANCH
///   silently demoted to an unrecognised mnemonic, i.e. a lost control-flow
///   fact.
/// * **`fcmpo`** — Floating Compare Ordered. Became `fcmp`, matching neither
///   `fcmpu` nor `fcmpo`.
///
/// Found by hunting UNREACHABLE MATCH ARMS as a class: an arm whose literal the
/// normaliser can never produce is dead code that reads as coverage. The list
/// is itemised deliberately — a silent "strip if it looks like a suffix" is
/// what caused this.
const OE_CAPABLE: &[&str] = &[
    "add", "addc", "adde", "addme", "addze",
    "subf", "subfc", "subfe", "subfme", "subfze",
    "neg", "mullw", "mulld", "divw", "divwu", "divd", "divdu",
];

impl PpcLifter {
    /// Create a 32-bit PowerPC lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: 32 }
    }

    /// Create a 64-bit PowerPC lifter.
    #[must_use]
    pub const fn new_64() -> Self {
        Self { bits: 64 }
    }

    /// Pointer size in bytes.
    #[must_use]
    pub const fn ptr_size(&self) -> u8 {
        match self.bits {
            32 => 4,
            64 => 8,
            _ => u8::MAX,
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // Operand helpers
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Return the register name of the operand at `idx`, if it is a register.
    fn op_reg(instr: &Instruction, idx: usize) -> Option<String> {
        instr
            .operand_list
            .get(idx)
            .and_then(|o| o.as_register())
            .map(|r| r.name.clone())
    }

    /// Return the immediate value of the operand at `idx` (signed, sign-extended).
    fn op_imm(instr: &Instruction, idx: usize) -> Option<i64> {
        instr.operand_list.get(idx).and_then(rustre_core::Operand::as_immediate)
    }

    /// Return the label/address value of the operand at `idx`.
    fn op_label(instr: &Instruction, idx: usize) -> Option<u64> {
        instr.operand_list.get(idx).and_then(rustre_core::Operand::as_label)
    }

    /// Build an [`IrExpr`] from an operand at `idx`: register, immediate, or label.
    fn op_expr(instr: &Instruction, idx: usize) -> IrExpr {
        if let Some(r) = Self::op_reg(instr, idx) {
            return IrExpr::Reg(r);
        }
        if let Some(v) = Self::op_imm(instr, idx) {
            return IrExpr::Const(v.cast_unsigned());
        }
        if let Some(a) = Self::op_label(instr, idx) {
            return IrExpr::Const(a);
        }
        IrExpr::Undef
    }

    /// Build an effective-address expression for a `d(rA)` or `d(r0)` memory
    /// reference.
    ///
    /// PowerPC convention: when `rA` is `r0` in a load/store, the base is 0
    /// (absolute address).  The displacement is the preceding operand and the
    /// base register is the following operand.
    ///
    /// `disp_idx` is the index of the displacement operand in `operand_list`.
    /// The base register is assumed to be at `disp_idx + 1`.
    fn mem_addr(instr: &Instruction, disp_idx: usize) -> IrExpr {
        let disp = Self::op_imm(instr, disp_idx).unwrap_or(0);
        let base_reg = Self::op_reg(instr, disp_idx + 1);

        match base_reg.as_deref() {
            // r0 as base means zero in load/store EA computation.
            Some("r0") | None => IrExpr::Const(disp.cast_unsigned()),
            Some(r) => {
                if disp == 0 {
                    IrExpr::Reg(r.to_string())
                } else {
                    IrExpr::Add(
                        Box::new(IrExpr::Reg(r.to_string())),
                        Box::new(IrExpr::Const(disp.cast_unsigned())),
                    )
                }
            }
        }
    }

    /// Build an indexed effective-address expression for `rA + rB` memory
    /// references (load/store indexed forms).
    ///
    /// `ra_idx` is the index of `rA`; `rb_idx` is the index of `rB`.
    fn mem_addr_indexed(instr: &Instruction, ra_idx: usize, rhs_idx: usize) -> IrExpr {
        let ra = Self::op_reg(instr, ra_idx);
        let rb = Self::op_reg(instr, rhs_idx);

        match (ra.as_deref(), rb.as_deref()) {
            (Some("r0") | None, Some(b)) => IrExpr::Reg(b.to_string()),
            (Some(a), Some(b)) => IrExpr::Add(
                Box::new(IrExpr::Reg(a.to_string())),
                Box::new(IrExpr::Reg(b.to_string())),
            ),
            (Some(a), None) => IrExpr::Reg(a.to_string()),
            (None, None) => IrExpr::Const(0),
        }
    }

    /// Sign-extend a 16-bit immediate to 64 bits.
    fn sext16(v: i64) -> u64 {
        i64::from(i16::try_from(v).unwrap_or(i16::MAX)).cast_unsigned()
    }

    /// Zero-extend a 16-bit immediate to 64 bits.
    fn zext16(v: i64) -> u64 {
        u64::from(u16::try_from(v.unsigned_abs()).unwrap_or(u16::MAX))
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // Tokeniser helpers
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Tokenise the mnemonic and return `(base_mnem, has_rc_dot)`.
    ///
    /// Strips the trailing `.` that records the result in cr0 (the Rc bit).
    /// Also strips common suffixes used for overflow (`o`, `o.`) and carry
    /// (`c`, `e`) variants:
    ///
    /// | Suffix | Meaning                         |
    /// |--------|---------------------------------|
    /// | `.`    | Rc=1: update cr0                |
    /// | `o`    | OE=1: update xer[SO/OV]         |
    /// | `o.`   | OE=1 and Rc=1                   |
    /// Split a PowerPC mnemonic into `(base, rc, oe)`.
    ///
    /// `rc` is the `.` suffix (record into CR0); `oe` is the `o` suffix
    /// (record overflow into XER).
    ///
    /// **`oe` used to be DISCARDED**: the function stripped the trailing `o`
    /// and returned only `(base, false)`, so `addo` reached the dispatch as
    /// `add`, `nego` as `neg`, `divwo` as `divw`. Two consequences, and the
    /// second one is why this matters:
    ///
    /// 1. every `"...o"` match arm in the dispatch was UNREACHABLE — dead code
    ///    that reads as coverage;
    /// 2. the overflow fact was destroyed **by the parser**, before any
    ///    dispatch could see it, so no amount of work in the match arms could
    ///    have recovered it.
    ///
    /// This is the "information lost by the call path" shape from the RISC-V
    /// XLEN defect, one stage earlier: lost by the PARSER rather than by the
    /// dispatch signature.
    ///
    /// It also means the `o`-form arms added in an earlier iteration of this
    /// session were dead on arrival — recorded rather than quietly repaired,
    /// since a fix that never executes is not a fix.
    fn parse_mnem(raw: &str) -> (&str, bool, bool) {
        if let Some(base) = raw.strip_suffix("o.")
            && OE_CAPABLE.contains(&base)
        {
            return (base, true, true);
        }
        if let Some(base) = raw.strip_suffix('.') {
            return (base, true, false);
        }
        if let Some(base) = raw.strip_suffix('o')
            && OE_CAPABLE.contains(&base)
        {
            return (base, false, true);
        }
        (raw, false, false)
    }

    /// Produce a cr0 update effect based on a result register.
    ///
    /// `cr0` conceptually holds `{LT, GT, EQ, SO}`.  We model it as:
    ///   - cr0 = CmpEqZero(result)   [bit EQ]
    ///
    /// Full signed comparison is outside scope; emit the zero test only.
    fn cr0_update(result_reg: &str) -> Effect {
        Effect::RegWrite {
            reg: "cr0".to_string(),
            value: IrExpr::CmpEqZero(Box::new(IrExpr::Reg(result_reg.to_string()))),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // Per-instruction lifters
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// `ADDI rD, rA, SIMM` Ã¢â‚¬â€ Add Immediate.
    ///
    /// If rA = 0 this is effectively `LI rD, SIMM`.
    fn lift_addi(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_reg(instr, 1);
        let simm = Self::op_imm(instr, 2).unwrap_or(0);
        let imm_expr = IrExpr::Const(Self::sext16(simm));

        let value = match ra.as_deref() {
            Some("r0") | None => imm_expr,
            Some(r) => IrExpr::Add(Box::new(IrExpr::Reg(r.to_string())), Box::new(imm_expr)),
        };

        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `ADDIS rD, rA, SIMM` Ã¢â‚¬â€ Add Immediate Shifted (upper 16 bits).
    fn lift_addis(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_reg(instr, 1);
        let simm = Self::op_imm(instr, 2).unwrap_or(0);
        let shifted = IrExpr::Const(simm.cast_unsigned() << 16);

        let value = match ra.as_deref() {
            Some("r0") | None => shifted,
            Some(r) => IrExpr::Add(Box::new(IrExpr::Reg(r.to_string())), Box::new(shifted)),
        };

        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `ADD rD, rA, rB` (and ADDO, ADDC, ADDE variants).
    /// Mark the PowerPC add/subtract forms whose CARRY or OVERFLOW behaviour is
    /// not modelled, so they stay distinguishable from the plain form.
    ///
    /// Six mnemonics shared one handler, covering THREE different behaviours:
    ///   * `add` / `subf`      — no carry involvement;
    ///   * `addc` / `subfc`    — PRODUCE the carry (write CA);
    ///   * `adde` / `subfe`    — CONSUME the carry (`rD = rA + rB + CA`);
    /// plus the `o` variants of each, which additionally set OV.
    ///
    /// All six lifted identically, so a multi-word add — the whole reason the
    /// `e` forms exist — was indistinguishable from a plain one.
    ///
    /// This IR has no readable carry or overflow flag (checked: no lifter in
    /// the crate reads one), so the exact value is not expressible. The value
    /// therefore stays the carry-free approximation and an intrinsic named for
    /// the mnemonic is emitted alongside — the same treatment ARM's `ADC`/`SBC`
    /// received, and the same convention as MIPS `div`/`divu`.
    fn with_flag_marker(mut effects: Vec<Effect>, mnem: &str) -> Vec<Effect> {
        effects.insert(
            0,
            Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            },
        );
        effects
    }

    fn lift_add(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let value = IrExpr::Add(Box::new(ra), Box::new(rb));
        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `SUBF rD, rA, rB` Ã¢â‚¬â€ Subtract From (rD = rB - rA).
    fn lift_subf(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        // subf rD,rA,rB => rD = rB - rA
        let value = IrExpr::Sub(Box::new(rb), Box::new(ra));
        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `SUBI rD, rA, SIMM` Ã¢â‚¬â€ Subtract Immediate (pseudo: ADDI rD, rA, -SIMM).
    fn lift_subi(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let simm = Self::op_imm(instr, 2).unwrap_or(0);
        let imm_expr = IrExpr::Const(Self::sext16(-simm));
        let value = IrExpr::Add(Box::new(ra), Box::new(imm_expr));
        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `SUBIS rD, rA, SIMM` Ã¢â‚¬â€ Subtract Immediate Shifted.
    fn lift_subis(instr: &Instruction, _rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let simm = Self::op_imm(instr, 2).unwrap_or(0);
        let shifted = IrExpr::Const((-simm).cast_unsigned() << 16);
        let value = IrExpr::Add(Box::new(ra), Box::new(shifted));
        vec![Effect::RegWrite { reg: rd, value }]
    }

    /// `MULLW rD, rA, rB` / `MULLI rD, rA, SIMM` Ã¢â‚¬â€ Multiply.
    fn lift_mul(instr: &Instruction, rc: bool, is_imm: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let rb = if is_imm {
            let simm = Self::op_imm(instr, 2).unwrap_or(0);
            IrExpr::Const(Self::sext16(simm))
        } else {
            Self::op_expr(instr, 2)
        };
        let value = IrExpr::Mul(Box::new(ra), Box::new(rb));
        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `MULHW rD, rA, rB` Ã¢â‚¬â€ Multiply High Word (upper 32 bits of 64-bit product).
    fn lift_mulhw(instr: &Instruction, rc: bool, signed: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let name = if signed { "mulhw" } else { "mulhwu" };
        let mut effects = vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![ra, rb, IrExpr::Reg(rd.clone())],
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `DIVW rD, rA, rB` / `DIVWU rD, rA, rB` Ã¢â‚¬â€ Integer divide (intrinsic).
    fn lift_div(instr: &Instruction, rc: bool, signed: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let name = if signed { "divw" } else { "divwu" };
        let mut effects = vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![ra, rb, IrExpr::Reg(rd.clone())],
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `AND rA, rS, rB` / `ANDI. rA, rS, UIMM` Ã¢â‚¬â€ Bitwise AND.
    fn lift_and(instr: &Instruction, rc: bool, is_imm: bool) -> Vec<Effect> {
        // AND rA, rS, rB  (note: destination is op[0], not op[0])
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = if is_imm {
            let uimm = Self::op_imm(instr, 2).unwrap_or(0);
            IrExpr::Const(Self::zext16(uimm))
        } else {
            Self::op_expr(instr, 2)
        };
        let value = IrExpr::And(Box::new(rs), Box::new(rb));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `ANDIS. rA, rS, UIMM` Ã¢â‚¬â€ AND Immediate Shifted.
    fn lift_andis(instr: &Instruction) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let uimm = Self::op_imm(instr, 2).unwrap_or(0);
        let shifted = IrExpr::Const(uimm.cast_unsigned() << 16);
        let value = IrExpr::And(Box::new(rs), Box::new(shifted));
        // ANDIS. always sets cr0 (Rc=1 always)
        vec![
            Effect::RegWrite {
                reg: ra.clone(),
                value,
            },
            Self::cr0_update(&ra),
        ]
    }

    /// `OR rA, rS, rB` / `ORI rA, rS, UIMM` / `ORIS rA, rS, UIMM` Ã¢â‚¬â€ Bitwise OR.
    fn lift_or(instr: &Instruction, rc: bool, imm_kind: ImmKind) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = match imm_kind {
            ImmKind::None => Self::op_expr(instr, 2),
            ImmKind::ZeroExt16 => {
                let uimm = Self::op_imm(instr, 2).unwrap_or(0);
                IrExpr::Const(Self::zext16(uimm))
            }
            ImmKind::Shifted16 => {
                let uimm = Self::op_imm(instr, 2).unwrap_or(0);
                IrExpr::Const(uimm.cast_unsigned() << 16)
            }
        };
        // Optimise: OR rs, rs, rs is a no-op MR (move register)
        let value = match (&rs, &rb) {
            (IrExpr::Reg(a), IrExpr::Reg(b)) if a == b => rs.clone(),
            _ => IrExpr::Or(Box::new(rs), Box::new(rb)),
        };
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `XOR rA, rS, rB` / `XORI rA, rS, UIMM` / `XORIS rA, rS, UIMM`.
    fn lift_xor(instr: &Instruction, rc: bool, imm_kind: ImmKind) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = match imm_kind {
            ImmKind::None => Self::op_expr(instr, 2),
            ImmKind::ZeroExt16 => {
                let uimm = Self::op_imm(instr, 2).unwrap_or(0);
                IrExpr::Const(Self::zext16(uimm))
            }
            ImmKind::Shifted16 => {
                let uimm = Self::op_imm(instr, 2).unwrap_or(0);
                IrExpr::Const(uimm.cast_unsigned() << 16)
            }
        };
        let value = IrExpr::Xor(Box::new(rs), Box::new(rb));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `NAND rA, rS, rB` Ã¢â‚¬â€ NOT(rS AND rB).
    fn lift_nand(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let value = IrExpr::Not(Box::new(IrExpr::And(Box::new(rs), Box::new(rb))));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `NOR rA, rS, rB` Ã¢â‚¬â€ NOT(rS OR rB).  `NOT` pseudo is NOR rs, rs, rs.
    fn lift_nor(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let value = IrExpr::Not(Box::new(IrExpr::Or(Box::new(rs), Box::new(rb))));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `SLW rA, rS, rB` Ã¢â‚¬â€ Shift Left Word.
    fn lift_slw(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let value = IrExpr::Shl(Box::new(rs), Box::new(rb));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `SLWI rA, rS, n` Ã¢â‚¬â€ Shift Left Word Immediate (pseudo: RLWINM).
    fn lift_slwi(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let sh = Self::op_imm(instr, 2).unwrap_or(0);
        let value = IrExpr::Shl(Box::new(rs), Box::new(IrExpr::Const(sh.cast_unsigned())));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `SRW rA, rS, rB` Ã¢â‚¬â€ Shift Right Word (logical).
    fn lift_srw(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let value = IrExpr::Shr(Box::new(rs), Box::new(rb));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `SRWI rA, rS, n` Ã¢â‚¬â€ Shift Right Word Immediate (pseudo: RLWINM).
    fn lift_srwi(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let sh = Self::op_imm(instr, 2).unwrap_or(0);
        let value = IrExpr::Shr(Box::new(rs), Box::new(IrExpr::Const(sh.cast_unsigned())));
        let mut effects = vec![Effect::RegWrite {
            reg: ra.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `SRAW rA, rS, rB` Ã¢â‚¬â€ Shift Right Algebraic Word (arithmetic shift).
    fn lift_sraw(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        // Was a LOGICAL `Shr` with the note "we model arithmetic shift as
        // logical shift for now" — but `IrExpr::Sar` exists, so the sign
        // propagation SRAW is named for was simply being dropped. The intrinsic
        // wrapper kept `sraw` distinguishable from `srw`, so this was a wrong
        // VALUE inside a correctly-labelled envelope: any pass reading the
        // argument saw a logical shift.
        //
        // The 32-bit ("Word") nature of the operation is carried by the
        // intrinsic name, as before; only the shift kind changes here.
        let value = IrExpr::Sar(Box::new(rs), Box::new(rb));
        let mut effects = vec![Effect::Intrinsic {
            name: "sraw".to_string(),
            args: vec![value, IrExpr::Reg(ra.clone())],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `SRAWI rA, rS, SH` Ã¢â‚¬â€ Shift Right Algebraic Word Immediate.
    fn lift_srawi(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let sh = Self::op_imm(instr, 2).unwrap_or(0);
        // Same defect as `lift_sraw`: algebraic shift emitted as logical.
        let value = IrExpr::Sar(Box::new(rs), Box::new(IrExpr::Const(sh.cast_unsigned())));
        let mut effects = vec![Effect::Intrinsic {
            name: "srawi".to_string(),
            args: vec![value, IrExpr::Reg(ra.clone())],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `LWZ rD, d(rA)` Ã¢â‚¬â€ Load Word and Zero.
    fn lift_lwz(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemRead {
            addr,
            dest: rd,
            size: 4,
        }]
    }

    /// `LWZU rD, d(rA)` Ã¢â‚¬â€ Load Word and Zero with Update.
    fn lift_lwzu(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let Some(ra) = Self::op_reg(instr, 2) else { return Self::lift_lwz(instr) };
        let disp = Self::op_imm(instr, 1).unwrap_or(0);
        let ea = if disp == 0 {
            IrExpr::Reg(ra.clone())
        } else {
            IrExpr::Add(
                Box::new(IrExpr::Reg(ra.clone())),
                Box::new(IrExpr::Const(Self::sext16(disp))),
            )
        };
        vec![
            Effect::MemRead {
                addr: ea.clone(),
                dest: rd,
                size: 4,
            },
            Effect::RegWrite { reg: ra, value: ea },
        ]
    }

    /// `LWZX rD, rA, rB` Ã¢â‚¬â€ Load Word and Zero Indexed.
    fn lift_lwzx(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let addr = Self::mem_addr_indexed(instr, 1, 2);
        vec![Effect::MemRead {
            addr,
            dest: rd,
            size: 4,
        }]
    }

    /// `LHZ rD, d(rA)` Ã¢â‚¬â€ Load Halfword and Zero.
    fn lift_lhz(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemRead {
            addr,
            dest: rd,
            size: 2,
        }]
    }

    /// `LHA rD, d(rA)` Ã¢â‚¬â€ Load Halfword Algebraic (sign-extended).
    fn lift_lha(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let addr = Self::mem_addr(instr, 1);
        // We model sign-extension as an intrinsic since IrExpr has no sext node.
        vec![
            Effect::MemRead {
                addr,
                dest: rd.clone(),
                size: 2,
            },
            Effect::Intrinsic {
                name: "sext16".to_string(),
                args: vec![IrExpr::Reg(rd)],
            },
        ]
    }

    /// `LBZ rD, d(rA)` Ã¢â‚¬â€ Load Byte and Zero.
    fn lift_lbz(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemRead {
            addr,
            dest: rd,
            size: 1,
        }]
    }

    /// `LMW rD, d(rA)` Ã¢â‚¬â€ Load Multiple Words (rD..r31 from memory).
    fn lift_lmw(instr: &Instruction) -> Vec<Effect> {
        let Some(rd_str) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let base_addr = Self::mem_addr(instr, 1);
        let rd_n: u32 = rd_str.trim_start_matches('r').parse().unwrap_or(0);

        // PPC only has GPRs r0..r31; rd_n > 31 is invalid input from the binary.
        if rd_n > 31 {
            return Self::unknown(instr);
        }
        let count = 32 - rd_n;
        let mut effects = Vec::with_capacity(count as usize);
        for i in 0..count {
            let reg_name = format!("r{}", rd_n + i);
            let offset = u64::from(i * 4);
            let addr = if offset == 0 {
                base_addr.clone()
            } else {
                IrExpr::Add(Box::new(base_addr.clone()), Box::new(IrExpr::Const(offset)))
            };
            effects.push(Effect::MemRead {
                addr,
                dest: reg_name,
                size: 4,
            });
        }
        effects
    }

    /// `STW rS, d(rA)` Ã¢â‚¬â€ Store Word.
    fn lift_stw(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemWrite {
            addr,
            value: rs,
            size: 4,
        }]
    }

    /// `STWU rS, d(rA)` Ã¢â‚¬â€ Store Word with Update.
    /// Append the base-register write-back that the PowerPC `…u` (UPDATE)
    /// addressing forms perform: `rA <- EA`.
    ///
    /// `LHZU`, `LBZU`, `LHAU`, `LFSU`, `LFDU`, `STHU`, `STBU`, `STFSU` and
    /// `STFDU` all shared their handler with the NON-update form, so the
    /// write-back was not modelled at all — on PowerPC's standard
    /// auto-increment loop idiom, where the pointer advance IS the update.
    /// `STWU` already had its own handler doing exactly this; the other nine
    /// forms were simply never given the same treatment, and a comment on the
    /// dispatch line said `// simplified (no update)`.
    ///
    /// `disp_idx` is the operand index of the displacement, matching
    /// `mem_addr`'s convention: the base register is at `disp_idx + 1`.
    /// Per the ISA, `rA = 0` is not a base register in these forms, so there
    /// is nothing to update — the guard mirrors `mem_addr`'s own r0 handling.
    fn with_ea_update(
        mut effects: Vec<Effect>,
        instr: &Instruction,
        disp_idx: usize,
    ) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, disp_idx + 1) else { return effects };
        if ra == "r0" {
            return effects;
        }
        let ea = Self::mem_addr(instr, disp_idx);
        effects.push(Effect::RegWrite { reg: ra, value: ea });
        effects
    }

    /// `ADDE`/`SUBFE` consume the carry; `ADDC`/`SUBFC` produce it.
    ///
    /// All four shared an arm with their carry-free sibling and called
    /// `lift_add`/`lift_subf` unchanged, so `adde` produced a value IDENTICAL to
    /// `add` — the carry-in was simply dropped. Only the marker intrinsic's name
    /// differed, which is why the `assert_ne!` guarding this pair passed while
    /// the semantics had collapsed.
    ///
    /// `ADDE rD,rA,rB` is `rA + rB + CA`.
    /// `SUBFE rD,rA,rB` is `~rA + rB + CA`, i.e. `rB - rA - 1 + CA`.
    ///
    /// `xer_ca` is a modelling convention for the XER carry bit, in keeping with
    /// how this crate names flags elsewhere (`cr0` here, `cf` in the ARM and Z80
    /// lifters). The FACT that the carry participates is certain; only the
    /// spelling is a choice.
    ///
    /// The carry-OUT of `ADDC`/`SUBFC` is a separate, still-unmodelled fact:
    /// their VALUE is already correct, so that is a fidelity gap rather than a
    /// wrong answer, and it stays in the marker.
    fn with_carry_in(effects: Vec<Effect>, subtract: bool) -> Vec<Effect> {
        let ca = IrExpr::Reg("xer_ca".to_string());
        effects
            .into_iter()
            .map(|e| match e {
                Effect::RegWrite { reg, value } => Effect::RegWrite {
                    reg,
                    value: if subtract {
                        // rB - rA - 1 + CA
                        IrExpr::Add(
                            Box::new(IrExpr::Sub(
                                Box::new(value),
                                Box::new(IrExpr::Const(1)),
                            )),
                            Box::new(ca.clone()),
                        )
                    } else {
                        IrExpr::Add(Box::new(value), Box::new(ca.clone()))
                    },
                },
                other => other,
            })
            .collect()
    }

    fn lift_stwu(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        let Some(ra) = Self::op_reg(instr, 2) else { return Self::lift_stw(instr) };
        let disp = Self::op_imm(instr, 1).unwrap_or(0);
        let ea = if disp == 0 {
            IrExpr::Reg(ra.clone())
        } else {
            IrExpr::Add(
                Box::new(IrExpr::Reg(ra.clone())),
                Box::new(IrExpr::Const(Self::sext16(disp))),
            )
        };
        vec![
            Effect::MemWrite {
                addr: ea.clone(),
                value: rs,
                size: 4,
            },
            Effect::RegWrite { reg: ra, value: ea },
        ]
    }

    /// `STWX rS, rA, rB` Ã¢â‚¬â€ Store Word Indexed.
    fn lift_stwx(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        let addr = Self::mem_addr_indexed(instr, 1, 2);
        vec![Effect::MemWrite {
            addr,
            value: rs,
            size: 4,
        }]
    }

    /// `STH rS, d(rA)` Ã¢â‚¬â€ Store Halfword.
    fn lift_sth(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemWrite {
            addr,
            value: rs,
            size: 2,
        }]
    }

    /// `STB rS, d(rA)` Ã¢â‚¬â€ Store Byte.
    fn lift_stb(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemWrite {
            addr,
            value: rs,
            size: 1,
        }]
    }

    /// `STMW rS, d(rA)` Ã¢â‚¬â€ Store Multiple Words (rS..r31 to memory).
    fn lift_stmw(instr: &Instruction) -> Vec<Effect> {
        let Some(rs_str) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let base_addr = Self::mem_addr(instr, 1);
        let rs_n: u32 = rs_str.trim_start_matches('r').parse().unwrap_or(0);

        // PPC only has GPRs r0..r31; rs_n > 31 is invalid input from the binary.
        if rs_n > 31 {
            return Self::unknown(instr);
        }
        let count = 32 - rs_n;
        let mut effects = Vec::with_capacity(count as usize);
        for i in 0..count {
            let reg_name = format!("r{}", rs_n + i);
            let offset = u64::from(i * 4);
            let addr = if offset == 0 {
                base_addr.clone()
            } else {
                IrExpr::Add(Box::new(base_addr.clone()), Box::new(IrExpr::Const(offset)))
            };
            effects.push(Effect::MemWrite {
                addr,
                value: IrExpr::Reg(reg_name),
                size: 4,
            });
        }
        effects
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Branch instructions Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Compute the branch target from operand 0.
    ///
    /// If the operand is a label, use it directly.  If it is an immediate,
    /// sign-extend it as a 26-bit offset and add to the instruction address
    /// (for relative branches).
    fn branch_target(instr: &Instruction) -> IrExpr {
        // Check for a label operand (absolute target already resolved).
        if let Some(addr) = Self::op_label(instr, 0) {
            return IrExpr::Const(addr);
        }
        // Check for an immediate (relative offset).
        if let Some(imm) = Self::op_imm(instr, 0) {
            // 26-bit signed offset (LI field) Ã¢â‚¬â€ already sign-extended by disasm.
            let target = instr.address.0.cast_signed().wrapping_add(imm).cast_unsigned();
            return IrExpr::Const(target);
        }
        // Check for a register operand (indirect branch).
        if let Some(r) = Self::op_reg(instr, 0) {
            return IrExpr::Reg(r);
        }
        IrExpr::Undef
    }

    /// `B target` Ã¢â‚¬â€ Unconditional branch.
    fn lift_b(instr: &Instruction) -> Vec<Effect> {
        let target = Self::branch_target(instr);
        vec![Effect::Branch {
            target,
            condition: None,
        }]
    }

    /// `BA target` Ã¢â‚¬â€ Branch Absolute.
    fn lift_ba(instr: &Instruction) -> Vec<Effect> {
        let target = Self::op_label(instr, 0).map_or_else(
            || {
                Self::op_imm(instr, 0)
                    .map_or(IrExpr::Undef, |v| IrExpr::Const(v.cast_unsigned()))
            },
            IrExpr::Const,
        );
        vec![Effect::Branch {
            target,
            condition: None,
        }]
    }

    /// `BL target` Ã¢â‚¬â€ Branch and Link (direct call).
    fn lift_bl(instr: &Instruction) -> Vec<Effect> {
        let target = Self::branch_target(instr);
        // LR = PC + 4 (next instruction)
        let lr_val = IrExpr::Const(instr.address.0 + 4);
        vec![
            Effect::RegWrite {
                reg: "lr".to_string(),
                value: lr_val,
            },
            Effect::Call { target },
        ]
    }

    /// `BLA target` Ã¢â‚¬â€ Branch and Link Absolute.
    fn lift_bla(instr: &Instruction) -> Vec<Effect> {
        let target = Self::op_label(instr, 0).map_or_else(
            || {
                Self::op_imm(instr, 0)
                    .map_or(IrExpr::Undef, |v| IrExpr::Const(v.cast_unsigned()))
            },
            IrExpr::Const,
        );
        let lr_val = IrExpr::Const(instr.address.0 + 4);
        vec![
            Effect::RegWrite {
                reg: "lr".to_string(),
                value: lr_val,
            },
            Effect::Call { target },
        ]
    }

    /// `BLR` Ã¢â‚¬â€ Branch to Link Register (return).
    fn lift_blr() -> Vec<Effect> {
        vec![Effect::Return {
            value: Some(IrExpr::Reg("r3".to_string())),
        }]
    }

    /// `BCTR` Ã¢â‚¬â€ Branch to Count Register.
    fn lift_bctr() -> Vec<Effect> {
        vec![Effect::Branch {
            target: IrExpr::Reg("ctr".to_string()),
            condition: None,
        }]
    }

    /// `BCTRL` Ã¢â‚¬â€ Branch to Count Register and Link.
    fn lift_bctrl(instr: &Instruction) -> Vec<Effect> {
        let lr_val = IrExpr::Const(instr.address.0 + 4);
        vec![
            Effect::RegWrite {
                reg: "lr".to_string(),
                value: lr_val,
            },
            Effect::Call {
                target: IrExpr::Reg("ctr".to_string()),
            },
        ]
    }

    /// `BC BO, BI, target` Ã¢â‚¬â€ Branch Conditional.
    ///
    /// PowerPC uses a 5-bit BO field and a 5-bit BI field.
    /// Rather than fully decoding BO/BI, we produce a condition based on
    /// the BI field (which CR bit to test) and model BO conservatively.
    fn lift_bc(instr: &Instruction) -> Vec<Effect> {
        // BO = operand[0], BI = operand[1], target = operand[2]
        let bo = Self::op_imm(instr, 0).unwrap_or(0).cast_unsigned();
        let bi = Self::op_imm(instr, 1).unwrap_or(0).cast_unsigned();

        // If BO has bit 2 set (0b00100), the branch is always taken (CTR ignored).
        // If BO has bit 4 set (0b10000), condition bit is not tested.
        let branch_always = (bo & 0b10100) == 0b10100;

        let target = Self::op_label(instr, 2)
            .map(IrExpr::Const)
            .or_else(|| {
                Self::op_imm(instr, 2)
                    .map(|v| IrExpr::Const(instr.address.0.cast_signed().wrapping_add(v).cast_unsigned()))
            })
            .unwrap_or(IrExpr::Undef);

        if branch_always {
            return vec![Effect::Branch {
                target,
                condition: None,
            }];
        }

        // Map BI to a condition register field and bit.
        let cr_field = bi / 4;
        let bit_in_field = bi % 4;
        let cr_name = format!("cr{cr_field}");
        let bit_mask = IrExpr::Const(1u64 << (3 - bit_in_field)); // cr bits are big-endian

        // Test the specific CR bit: condition = (cr_field & bit_mask) != 0
        let condition = IrExpr::And(Box::new(IrExpr::Reg(cr_name)), Box::new(bit_mask));

        // If BO bit 3 is 0, branch if bit is set; if 1, branch if bit is clear.
        let cond_expr = if (bo & 0b01000) != 0 {
            // Branch if condition bit is CLEAR (zero)
            IrExpr::CmpEqZero(Box::new(condition))
        } else {
            // Branch if condition bit is SET (non-zero)
            condition
        };

        vec![Effect::Branch {
            target,
            condition: Some(cond_expr),
        }]
    }

    /// `BCL BO, BI, target` Ã¢â‚¬â€ Branch Conditional and Link.
    fn lift_bcl(instr: &Instruction) -> Vec<Effect> {
        let mut effects = Self::lift_bc(instr);
        let lr_val = IrExpr::Const(instr.address.0 + 4);
        effects.insert(
            0,
            Effect::RegWrite {
                reg: "lr".to_string(),
                value: lr_val,
            },
        );
        effects
    }

    /// `BCLR BO, BI` Ã¢â‚¬â€ Branch Conditional to Link Register.
    fn lift_bclr(instr: &Instruction) -> Vec<Effect> {
        let bo = Self::op_imm(instr, 0).unwrap_or(0).cast_unsigned();
        let bi = Self::op_imm(instr, 1).unwrap_or(0).cast_unsigned();

        let branch_always = (bo & 0b10100) == 0b10100;
        let target = IrExpr::Reg("lr".to_string());

        if branch_always {
            // BCLR with BO=20 is the same as BLR
            return vec![Effect::Return {
                value: Some(IrExpr::Reg("r3".to_string())),
            }];
        }

        let cr_field = bi / 4;
        let bit_in_field = bi % 4;
        let cr_name = format!("cr{cr_field}");
        let bit_mask = IrExpr::Const(1u64 << (3 - bit_in_field));
        let condition = IrExpr::And(Box::new(IrExpr::Reg(cr_name)), Box::new(bit_mask));
        let cond_expr = if (bo & 0b01000) != 0 {
            IrExpr::CmpEqZero(Box::new(condition))
        } else {
            condition
        };

        vec![Effect::Branch {
            target,
            condition: Some(cond_expr),
        }]
    }

    /// `BCLRL BO, BI` Ã¢â‚¬â€ Branch Conditional to Link Register and Link.
    fn lift_bclrl(instr: &Instruction) -> Vec<Effect> {
        let mut effects = Self::lift_bclr(instr);
        let lr_val = IrExpr::Const(instr.address.0 + 4);
        effects.insert(
            0,
            Effect::RegWrite {
                reg: "lr".to_string(),
                value: lr_val,
            },
        );
        effects
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ System / special-purpose instructions Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// `SC` Ã¢â‚¬â€ System Call.
    ///
    /// On Linux PowerPC the syscall number is in r0.
    fn lift_sc() -> Vec<Effect> {
        vec![Effect::Syscall {
            nr: IrExpr::Reg("r0".to_string()),
        }]
    }

    /// `NOP` Ã¢â‚¬â€ No operation.
    const fn lift_nop() -> Vec<Effect> {
        vec![]
    }

    /// `MR rA, rS` Ã¢â‚¬â€ Move Register (pseudo: OR rA, rS, rS).
    fn lift_mr(instr: &Instruction) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        vec![Effect::RegWrite { reg: ra, value: rs }]
    }

    /// `LI rD, SIMM` Ã¢â‚¬â€ Load Immediate (pseudo: ADDI rD, 0, SIMM).
    fn lift_li(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let simm = Self::op_imm(instr, 1).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Const(Self::sext16(simm)),
        }]
    }

    /// `LIS rD, SIMM` Ã¢â‚¬â€ Load Immediate Shifted (pseudo: ADDIS rD, 0, SIMM).
    fn lift_lis(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let simm = Self::op_imm(instr, 1).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Const(simm.cast_unsigned() << 16),
        }]
    }

    /// `MFLR rD` Ã¢â‚¬â€ Move From Link Register.
    fn lift_mflr(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Reg("lr".to_string()),
        }]
    }

    /// `MTLR rS` Ã¢â‚¬â€ Move To Link Register.
    fn lift_mtlr(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        vec![Effect::RegWrite {
            reg: "lr".to_string(),
            value: rs,
        }]
    }

    /// `MFCTR rD` Ã¢â‚¬â€ Move From Count Register.
    fn lift_mfctr(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Reg("ctr".to_string()),
        }]
    }

    /// `MTCTR rS` Ã¢â‚¬â€ Move To Count Register.
    fn lift_mtctr(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        vec![Effect::RegWrite {
            reg: "ctr".to_string(),
            value: rs,
        }]
    }

    /// `MFXER rD` Ã¢â‚¬â€ Move From XER.
    fn lift_mfxer(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Reg("xer".to_string()),
        }]
    }

    /// `MTXER rS` Ã¢â‚¬â€ Move To XER.
    fn lift_mtxer(instr: &Instruction) -> Vec<Effect> {
        let rs = Self::op_expr(instr, 0);
        vec![Effect::RegWrite {
            reg: "xer".to_string(),
            value: rs,
        }]
    }

    /// `MFSPR rD, SPR` Ã¢â‚¬â€ Move From Special Purpose Register.
    fn lift_mfspr(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let spr = Self::op_imm(instr, 1).unwrap_or(0);
        // Decode well-known SPR numbers.
        let src = match spr {
            1 => IrExpr::Reg("xer".to_string()),
            8 => IrExpr::Reg("lr".to_string()),
            9 => IrExpr::Reg("ctr".to_string()),
            18 => IrExpr::Reg("dsisr".to_string()),
            19 => IrExpr::Reg("dar".to_string()),
            268 => IrExpr::Reg("tb".to_string()), // time base
            269 => IrExpr::Reg("tbu".to_string()),
            _ => {
                return vec![Effect::Intrinsic {
                    name: "mfspr".to_string(),
                    args: vec![IrExpr::Const(spr.cast_unsigned()), IrExpr::Reg(rd)],
                }];
            }
        };
        vec![Effect::RegWrite {
            reg: rd,
            value: src,
        }]
    }

    /// `MTSPR SPR, rS` Ã¢â‚¬â€ Move To Special Purpose Register.
    fn lift_mtspr(instr: &Instruction) -> Vec<Effect> {
        let spr = Self::op_imm(instr, 0).unwrap_or(0);
        let rs = Self::op_expr(instr, 1);
        let dest = match spr {
            1 => "xer".to_string(),
            8 => "lr".to_string(),
            9 => "ctr".to_string(),
            _ => {
                return vec![Effect::Intrinsic {
                    name: "mtspr".to_string(),
                    args: vec![IrExpr::Const(spr.cast_unsigned()), rs],
                }];
            }
        };
        vec![Effect::RegWrite {
            reg: dest,
            value: rs,
        }]
    }

    /// `MFCR rD` Ã¢â‚¬â€ Move From Condition Register.
    fn lift_mfcr(instr: &Instruction) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        vec![Effect::Intrinsic {
            name: "mfcr".to_string(),
            args: vec![IrExpr::Reg(rd)],
        }]
    }

    /// `MTCRF FXM, rS` Ã¢â‚¬â€ Move To Condition Register Fields.
    fn lift_mtcrf(instr: &Instruction) -> Vec<Effect> {
        let fxm = Self::op_imm(instr, 0).unwrap_or(0);
        let rs = Self::op_expr(instr, 1);
        vec![Effect::Intrinsic {
            name: "mtcrf".to_string(),
            args: vec![IrExpr::Const(fxm.cast_unsigned()), rs],
        }]
    }

    /// `CMPW rA, rB` / `CMPLW rA, rB` Ã¢â‚¬â€ Compare Word (sets cr0).
    fn lift_cmpw(instr: &Instruction, is_logical: bool) -> Vec<Effect> {
        // Operands may be (crfD, rA, rB) with crfD defaulting to cr0, or (rA, rB).
        let (ra_idx, rhs_idx) = if instr.operand_list.len() >= 3 {
            (1, 2)
        } else {
            (0, 1)
        };
        let cr_idx = if instr.operand_list.len() >= 3 {
            Self::op_imm(instr, 0).unwrap_or(0)
        } else {
            0
        };
        let cr_name = format!("cr{cr_idx}");
        let ra = Self::op_expr(instr, ra_idx);
        let rb = Self::op_expr(instr, rhs_idx);
        let name = if is_logical { "cmplw" } else { "cmpw" };
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![ra, rb, IrExpr::Reg(cr_name)],
        }]
    }

    /// `CMPWI rA, SIMM` / `CMPLWI rA, UIMM` Ã¢â‚¬â€ Compare Word Immediate.
    fn lift_cmpwi(instr: &Instruction, is_logical: bool) -> Vec<Effect> {
        let (ra_idx, imm_idx) = if instr.operand_list.len() >= 3 {
            (1, 2)
        } else {
            (0, 1)
        };
        let cr_idx = if instr.operand_list.len() >= 3 {
            Self::op_imm(instr, 0).unwrap_or(0)
        } else {
            0
        };
        let cr_name = format!("cr{cr_idx}");
        let ra = Self::op_expr(instr, ra_idx);
        let imm = Self::op_imm(instr, imm_idx).unwrap_or(0);
        let imm_expr = if is_logical {
            IrExpr::Const(Self::zext16(imm))
        } else {
            IrExpr::Const(Self::sext16(imm))
        };
        let name = if is_logical { "cmplwi" } else { "cmpwi" };
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![ra, imm_expr, IrExpr::Reg(cr_name)],
        }]
    }

    /// `NEG rD, rA` Ã¢â‚¬â€ Negate (rD = -rA = ~rA + 1).
    fn lift_neg(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(rd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let ra = Self::op_expr(instr, 1);
        let value = IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(ra));
        let mut effects = vec![Effect::RegWrite {
            reg: rd.clone(),
            value,
        }];
        if rc {
            effects.push(Self::cr0_update(&rd));
        }
        effects
    }

    /// `EXTSB rA, rS` Ã¢â‚¬â€ Extend Sign Byte.
    fn lift_extsb(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let mut effects = vec![Effect::Intrinsic {
            name: "extsb".to_string(),
            args: vec![rs, IrExpr::Reg(ra.clone())],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `EXTSH rA, rS` Ã¢â‚¬â€ Extend Sign Halfword.
    fn lift_extsh(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let mut effects = vec![Effect::Intrinsic {
            name: "extsh".to_string(),
            args: vec![rs, IrExpr::Reg(ra.clone())],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `RLWINM rA, rS, SH, MB, ME` Ã¢â‚¬â€ Rotate Left Word Immediate and Mask.
    fn lift_rlwinm(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let sh = Self::op_imm(instr, 2).unwrap_or(0);
        let mb = Self::op_imm(instr, 3).unwrap_or(0);
        let me = Self::op_imm(instr, 4).unwrap_or(31);
        let mut effects = vec![Effect::Intrinsic {
            name: "rlwinm".to_string(),
            args: vec![
                rs,
                IrExpr::Const(sh.cast_unsigned()),
                IrExpr::Const(mb.cast_unsigned()),
                IrExpr::Const(me.cast_unsigned()),
                IrExpr::Reg(ra.clone()),
            ],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `RLWIMI rA, rS, SH, MB, ME` Ã¢â‚¬â€ Rotate Left Word Immediate Mask Insert.
    fn lift_rlwimi(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let sh = Self::op_imm(instr, 2).unwrap_or(0);
        let mb = Self::op_imm(instr, 3).unwrap_or(0);
        let me = Self::op_imm(instr, 4).unwrap_or(31);
        let mut effects = vec![Effect::Intrinsic {
            name: "rlwimi".to_string(),
            args: vec![
                rs,
                IrExpr::Const(sh.cast_unsigned()),
                IrExpr::Const(mb.cast_unsigned()),
                IrExpr::Const(me.cast_unsigned()),
                IrExpr::Reg(ra.clone()),
            ],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    /// `RLWNM rA, rS, rB, MB, ME` Ã¢â‚¬â€ Rotate Left Word and Mask.
    fn lift_rlwnm(instr: &Instruction, rc: bool) -> Vec<Effect> {
        let Some(ra) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let rs = Self::op_expr(instr, 1);
        let rb = Self::op_expr(instr, 2);
        let mb = Self::op_imm(instr, 3).unwrap_or(0);
        let me = Self::op_imm(instr, 4).unwrap_or(31);
        let mut effects = vec![Effect::Intrinsic {
            name: "rlwnm".to_string(),
            args: vec![
                rs,
                rb,
                IrExpr::Const(mb.cast_unsigned()),
                IrExpr::Const(me.cast_unsigned()),
                IrExpr::Reg(ra.clone()),
            ],
        }];
        if rc {
            effects.push(Self::cr0_update(&ra));
        }
        effects
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Floating-point (FPR) instructions Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Generic float load Ã¢â‚¬â€ `LFD/LFDU/LFS/LFSU`.
    fn lift_lf(instr: &Instruction, size: u8) -> Vec<Effect> {
        let Some(fd) = Self::op_reg(instr, 0) else { return Self::unknown(instr) };
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemRead {
            addr,
            dest: fd,
            size,
        }]
    }

    /// Generic float store Ã¢â‚¬â€ `STFD/STFDU/STFS/STFSU`.
    fn lift_stf(instr: &Instruction, size: u8) -> Vec<Effect> {
        let fs = Self::op_expr(instr, 0);
        let addr = Self::mem_addr(instr, 1);
        vec![Effect::MemWrite {
            addr,
            value: fs,
            size,
        }]
    }

    /// Fallback Ã¢â‚¬â€ produce an `Intrinsic` effect for unknown mnemonics.
    fn unknown(instr: &Instruction) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: instr.mnemonic.to_ascii_lowercase(),
            args: vec![],
        }]
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // Main dispatch
    // Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    fn mnemonic_to_effects_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (mnem, rc, oe) = Self::parse_mnem(&raw);

        // The `o` suffix records overflow into XER, which this IR does not
        // model. Applying the marker HERE, driven by the parsed flag, is the
        // only way it can work: the suffix never survives into `mnem`, so the
        // per-mnemonic `"...o"` arms this used to rely on were unreachable.
        let result = Self::mnemonic_to_effects_a_inner(instr, mnem, rc);
        return match result {
            Some(effects) if oe => Some(Self::with_flag_marker(effects, &raw)),
            other => other,
        };
    }

    fn mnemonic_to_effects_a_inner(
        instr: &Instruction,
        mnem: &str,
        rc: bool,
    ) -> Option<Vec<Effect>> {
            match mnem {
            // Ã¢â€â‚¬Ã¢â€â‚¬ No-ops Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "nop" | "ori"  /* ori 0,0,0 is canonical NOP */
                if instr.operand_list.is_empty()
                    || (instr.operand_list.len() == 3
                        && Self::op_imm(instr, 2) == Some(0)
                        && Self::op_reg(instr, 0).as_deref() == Some("r0")) =>
            {
                Some(Self::lift_nop())
            }
            "nop" => Some(Self::lift_nop()),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Arithmetic Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "add" => Some(Self::lift_add(instr, rc)),
            "addc" => Some(Self::with_flag_marker(Self::lift_add(instr, rc), mnem)),
            "adde" => Some(Self::with_flag_marker(
                Self::with_carry_in(Self::lift_add(instr, rc), false),
                mnem,
            )),
            "addi" | "addic" => Some(Self::lift_addi(instr, rc)),
            "addis"          => Some(Self::lift_addis(instr, rc)),
            "subf" => Some(Self::lift_subf(instr, rc)),
            "subfc" => Some(Self::with_flag_marker(Self::lift_subf(instr, rc), mnem)),
            "subfe" => Some(Self::with_flag_marker(
                Self::with_carry_in(Self::lift_subf(instr, rc), true),
                mnem,
            )),
            "subi"  => Some(Self::lift_subi(instr, rc)),
            "subis" => Some(Self::lift_subis(instr, rc)),
            "neg" => Some(Self::lift_neg(instr, rc)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Multiply Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "mullw" => Some(Self::lift_mul(instr, rc, false)),
            "mulli"            => Some(Self::lift_mul(instr, rc, true)),
            "mulhw"            => Some(Self::lift_mulhw(instr, rc, true)),
            "mulhwu"           => Some(Self::lift_mulhw(instr, rc, false)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Divide Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "divw" => Some(Self::lift_div(instr, rc, true)),
            "divwu" => Some(Self::lift_div(instr, rc, false)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Logical Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "and"          => Some(Self::lift_and(instr, rc, false)),
            "andi"         => Some(Self::lift_and(instr, true, true)),  // andi. always sets cr0
            "andis"        => Some(Self::lift_andis(instr)),
            "or"           => Some(Self::lift_or(instr, rc, ImmKind::None)),
            "ori"          => Some(Self::lift_or(instr, rc, ImmKind::ZeroExt16)),
            "oris"         => Some(Self::lift_or(instr, rc, ImmKind::Shifted16)),
            "xor"          => Some(Self::lift_xor(instr, rc, ImmKind::None)),
            "xori"         => Some(Self::lift_xor(instr, rc, ImmKind::ZeroExt16)),
            "xoris"        => Some(Self::lift_xor(instr, rc, ImmKind::Shifted16)),
            "nand"         => Some(Self::lift_nand(instr, rc)),
            "nor"          => Some(Self::lift_nor(instr, rc)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Shift Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "slw"   => Some(Self::lift_slw(instr, rc)),
            "slwi"  => Some(Self::lift_slwi(instr, rc)),
            "srw"   => Some(Self::lift_srw(instr, rc)),
            "srwi"  => Some(Self::lift_srwi(instr, rc)),
            "sraw"  => Some(Self::lift_sraw(instr, rc)),
            "srawi" => Some(Self::lift_srawi(instr, rc)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Extend Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "extsb" => Some(Self::lift_extsb(instr, rc)),
            "extsh" => Some(Self::lift_extsh(instr, rc)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Rotate / mask Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "rlwinm" => Some(Self::lift_rlwinm(instr, rc)),
            "rlwimi" => Some(Self::lift_rlwimi(instr, rc)),
            "rlwnm"  => Some(Self::lift_rlwnm(instr, rc)),

            // Ã¢â€â‚¬Ã¢â€â‚¬ Loads Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "lwz" | "lw"         => Some(Self::lift_lwz(instr)),
            // alternate mnemonic
            "lwzu"        => Some(Self::lift_lwzu(instr)),
            "lwzx"        => Some(Self::lift_lwzx(instr)),
            "lhz" => Some(Self::lift_lhz(instr)),
            "lhzu" => Some(Self::with_ea_update(Self::lift_lhz(instr), instr, 1)),
            "lha" => Some(Self::lift_lha(instr)),
            "lhau" => Some(Self::with_ea_update(Self::lift_lha(instr), instr, 1)),
            "lbz" => Some(Self::lift_lbz(instr)),
            "lbzu" => Some(Self::with_ea_update(Self::lift_lbz(instr), instr, 1)),
            "lmw"         => Some(Self::lift_lmw(instr)),
            "lfs" => Some(Self::lift_lf(instr, 4)),
            "lfsu" => Some(Self::with_ea_update(Self::lift_lf(instr, 4), instr, 1)),
            "lfd" => Some(Self::lift_lf(instr, 8)),
            "lfdu" => Some(Self::with_ea_update(Self::lift_lf(instr, 8), instr, 1)),
            // Ã¢â€â‚¬Ã¢â€â‚¬ Stores Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "stw"         => Some(Self::lift_stw(instr)),
            "stwu"        => Some(Self::lift_stwu(instr)),
            "stwx"        => Some(Self::lift_stwx(instr)),
                _ => None,
            }
    }
    fn mnemonic_to_effects_b_a_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (mnem, _rc, _oe) = Self::parse_mnem(&raw);

                    match mnem {
            "sth" => Some(Self::lift_sth(instr)),
            "sthu" => Some(Self::with_ea_update(Self::lift_sth(instr), instr, 1)),
            "stb" => Some(Self::lift_stb(instr)),
            "stbu" => Some(Self::with_ea_update(Self::lift_stb(instr), instr, 1)),
            "stmw"        => Some(Self::lift_stmw(instr)),
            "stfs" => Some(Self::lift_stf(instr, 4)),
            "stfsu" => Some(Self::with_ea_update(Self::lift_stf(instr, 4), instr, 1)),
            "stfd" => Some(Self::lift_stf(instr, 8)),
            "stfdu" => Some(Self::with_ea_update(Self::lift_stf(instr, 8), instr, 1)),
            "b"    => Some(Self::lift_b(instr)),
            "ba"   => Some(Self::lift_ba(instr)),
            "bl"   => Some(Self::lift_bl(instr)),
            "bla"  => Some(Self::lift_bla(instr)),
            "blr"   => Some(Self::lift_blr()),
            "blrl"  => {
                // blrl = BLR then link: calls through LR and sets LR = PC+4
                let lr_val = IrExpr::Const(instr.address.0 + 4);
                Some(vec![
                    Effect::RegWrite { reg: "lr".to_string(), value: lr_val },
                    Effect::Call { target: IrExpr::Reg("lr".to_string()) },
                ])
            }
            "bctr"  => Some(Self::lift_bctr()),
            "bctrl" => Some(Self::lift_bctrl(instr)),
            "bc" | "bca"  => Some(Self::lift_bc(instr)),
            "bcl" | "bcla" => Some(Self::lift_bcl(instr)),
            "bclr"        => Some(Self::lift_bclr(instr)),
            "bclrl"       => Some(Self::lift_bclrl(instr)),
            "beq" | "beqa"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::And(
                    Box::new(IrExpr::Reg("cr0".to_string())),
                    Box::new(IrExpr::Const(0x2)), // EQ bit in cr0
                )),
            }]),
            "bne" | "bnea"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::And(
                    Box::new(IrExpr::Reg("cr0".to_string())),
                    Box::new(IrExpr::Const(0x2)),
                )))),
            }]),
            "blt" | "blta"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::And(
                    Box::new(IrExpr::Reg("cr0".to_string())),
                    Box::new(IrExpr::Const(0x8)), // LT bit
                )),
            }]),
            "ble" | "blea"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Or(
                    Box::new(IrExpr::And(Box::new(IrExpr::Reg("cr0".to_string())), Box::new(IrExpr::Const(0x8)))),
                    Box::new(IrExpr::And(Box::new(IrExpr::Reg("cr0".to_string())), Box::new(IrExpr::Const(0x2)))),
                )),
            }]),
            "bgt" | "bgta"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::And(
                    Box::new(IrExpr::Reg("cr0".to_string())),
                    Box::new(IrExpr::Const(0x4)), // GT bit
                )),
            }]),
            "bge" | "bgea"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Or(
                    Box::new(IrExpr::And(Box::new(IrExpr::Reg("cr0".to_string())), Box::new(IrExpr::Const(0x4)))),
                    Box::new(IrExpr::And(Box::new(IrExpr::Reg("cr0".to_string())), Box::new(IrExpr::Const(0x2)))),
                )),
            }]),
            "bso" | "bsoa"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::And(
                    Box::new(IrExpr::Reg("cr0".to_string())),
                    Box::new(IrExpr::Const(0x1)), // SO bit
                )),
            }]),
            "bns" | "bnsa"  => Some(vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::And(
                    Box::new(IrExpr::Reg("cr0".to_string())),
                    Box::new(IrExpr::Const(0x1)),
                )))),
            }]),
            "cmpw"  | "cmp"   => Some(Self::lift_cmpw(instr, false)),
            "cmplw" | "cmpl"  => Some(Self::lift_cmpw(instr, true)),
            "cmpwi" | "cmpi"  => Some(Self::lift_cmpwi(instr, false)),
            "cmplwi" | "cmpli" => Some(Self::lift_cmpwi(instr, true)),
            "mr"  => Some(Self::lift_mr(instr)),
                        _ => None,
                    }
    }

    fn mnemonic_to_effects_b_a_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (_mnem, _rc, _oe) = Self::parse_mnem(&raw);

                    None
    }

    fn mnemonic_to_effects_b_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (_mnem, _rc, _oe) = Self::parse_mnem(&raw);

        if let Some(__s0) = Self::mnemonic_to_effects_b_a_a(instr) { return Some(__s0); }
        Self::mnemonic_to_effects_b_a_b(instr)
    }

    fn mnemonic_to_effects_b_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (mnem, _rc, _oe) = Self::parse_mnem(&raw);

                match mnem {
            "li"  => Some(Self::lift_li(instr)),
            "lis" => Some(Self::lift_lis(instr)),
            "mflr"  => Some(Self::lift_mflr(instr)),
            "mtlr"  => Some(Self::lift_mtlr(instr)),
            "mfctr" => Some(Self::lift_mfctr(instr)),
            "mtctr" => Some(Self::lift_mtctr(instr)),
            "mfxer" => Some(Self::lift_mfxer(instr)),
            "mtxer" => Some(Self::lift_mtxer(instr)),
            "mfspr" => Some(Self::lift_mfspr(instr)),
            "mtspr" => Some(Self::lift_mtspr(instr)),
            "mfcr"  => Some(Self::lift_mfcr(instr)),
            "mtcrf" => Some(Self::lift_mtcrf(instr)),
            "sc" => Some(Self::lift_sc()),
            "sync" | "isync" | "lwsync" | "eieio" | "ptesync" => Some(vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }]),
            "tw" | "twi" | "td" | "tdi" => Some(vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![Self::op_expr(instr, 0), Self::op_expr(instr, 1)],
            }]),
            "fadd" | "fadds" | "fsub" | "fsubs"
            | "fmul" | "fmuls" | "fdiv" | "fdivs"
            | "fmadd" | "fmadds" | "fmsub" | "fmsubs"
            | "fnmadd" | "fnmadds" | "fnmsub" | "fnmsubs"
            | "fabs" | "fnabs" | "fneg" | "frsp"
            | "fctiw" | "fctiwz" | "fcfid" | "fctid" | "fctidz"
            | "fcmpu" | "fcmpo"
            | "fmr" | "fsel" | "fsqrt" | "fsqrts" | "frsqrte" | "fre" => {
                let args: Vec<IrExpr> = (0..instr.operand_list.len())
                    .map(|i| Self::op_expr(instr, i))
                    .collect();
                Some(vec![Effect::Intrinsic { name: mnem.to_string(), args }])
            }
            m if m.starts_with('v') => {
                let args: Vec<IrExpr> = (0..instr.operand_list.len())
                    .map(|i| Self::op_expr(instr, i))
                    .collect();
                Some(vec![Effect::Intrinsic { name: mnem.to_string(), args }])
            }
            _ => Some(Self::unknown(instr)),
                }
    }

    fn mnemonic_to_effects_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (_mnem, _rc, _oe) = Self::parse_mnem(&raw);

        if let Some(__s0) = Self::mnemonic_to_effects_b_a(instr) { return Some(__s0); }
        Self::mnemonic_to_effects_b_b(instr)
    }

    fn mnemonic_to_effects(instr: &Instruction) -> Vec<Effect> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let (_mnem, _rc, _oe) = Self::parse_mnem(&raw);

        if let Some(__r0) = Self::mnemonic_to_effects_a(instr) { return __r0; }
        Self::mnemonic_to_effects_b(instr).unwrap_or_else(|| Self::unknown(instr))
    }
}

impl Default for PpcLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PpcLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PpcLifter({})", self.bits)
    }
}

impl ArchLifter for PpcLifter {
    fn arch_name(&self) -> &'static str {
        if self.bits == 64 { "ppc64" } else { "ppc" }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "mnemonic-driven PowerPC LLIL lifter"
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        // We handle all mnemonics Ã¢â‚¬â€ unknown ones fall back to Intrinsic.
        let _ = mnemonic;
        true
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

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Internal helpers
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Distinguishes how an immediate operand should be widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImmKind {
    /// Register operand Ã¢â‚¬â€ not an immediate.
    None,
    /// Zero-extend 16-bit immediate to word width.
    ZeroExt16,
    /// Shift left by 16 (ORIS/XORIS/ADDIS pattern).
    Shifted16,
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Tests
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::{
        address::Address,
        arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind},
    };

    fn make_reg(name: &str) -> Operand {
        Operand::Register(RegisterInfo::new(name, 0, 4, RegisterKind::General))
    }

    fn make_imm(v: i64) -> Operand {
        Operand::Immediate(v)
    }

    fn make_label(addr: u64) -> Operand {
        Operand::Label(addr)
    }

    fn make_instr(addr: u64, mnem: &str, operands: Vec<Operand>) -> Instruction {
        Instruction {
            address: Address::new(addr),
            size: 4,
            mnemonic: mnem.to_string(),
            operands: String::new(),
            operand_list: operands,
            flags: InstrFlags::NONE,
            bytes: vec![0; 4],
            comment: None,
        }
    }

    fn lifter() -> PpcLifter {
        PpcLifter::new()
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ADDI / LI Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// SRAW/SRAWI are ALGEBRAIC shifts — they propagate the sign bit.
    ///
    /// Both emitted a logical `IrExpr::Shr`, with a comment saying so ("we
    /// model arithmetic shift as logical shift for now") while `IrExpr::Sar`
    /// existed. The intrinsic wrapper kept `sraw` distinguishable from `srw`,
    /// which is why the previous sweep passed over this: the NAMES differed, so
    /// only reading the emitted VALUE showed the two computing the same thing.
    #[test]
    fn algebraic_shifts_propagate_the_sign() {
        let l = lifter();
        let render = |mnem: &str, third: Operand| {
            format!(
                "{:?}",
                l.lift(&make_instr(
                    0x1000,
                    mnem,
                    vec![make_reg("r3"), make_reg("r4"), third],
                ))
                .expect("lift")
                .effects
            )
        };

        let sraw = render("sraw", make_reg("r5"));
        let srawi = render("srawi", make_imm(3));
        assert!(sraw.contains("Sar"), "sraw must be arithmetic, got {sraw}");
        assert!(srawi.contains("Sar"), "srawi must be arithmetic, got {srawi}");

        // The logical counterpart must stay logical — otherwise this test would
        // pass just as well with every shift turned into a Sar.
        let srw = render("srw", make_reg("r5"));
        assert!(
            srw.contains("Shr") && !srw.contains("Sar"),
            "srw must stay logical, got {srw}"
        );
    }

    /// Three PowerPC mnemonics end in `o` WITHOUT it being the overflow suffix.
    /// The parser stripped it unconditionally, so their match arms were
    /// unreachable and each fell through to the unknown-mnemonic fallback:
    /// `eieio` (memory barrier), `bso` (conditional branch — a lost
    /// control-flow fact) and `fcmpo` (ordered float compare).
    #[test]
    fn mnemonics_ending_in_o_are_not_mistaken_for_overflow_forms() {
        for m in ["eieio", "bso", "fcmpo"] {
            let (base, _rc, oe) = PpcLifter::parse_mnem(m);
            assert_eq!(base, m, "{m} must not be stripped: it is not an OE form");
            assert!(!oe, "{m} does not carry the overflow suffix");
        }
        // The real overflow forms must still be recognised.
        for m in ["addo", "nego", "divwo", "mullwo"] {
            let (base, _rc, oe) = PpcLifter::parse_mnem(m);
            assert_ne!(base, m, "{m} IS an overflow form and must be stripped");
            assert!(oe, "{m} must report the overflow suffix");
        }
    }

    /// `ADD`, `ADDC` (produces carry) and `ADDE` (consumes it) are three
    /// different instructions that shared one lift.
    ///
    /// This comment used to claim "the exact values are not expressible — this
    /// IR has no carry flag". **That was false.** A carry REGISTER is exactly
    /// how every other lifter here models a flag (`cf` in ARM and Z80, `cr0` in
    /// this very file), so `ADDE`'s value was expressible all along and was
    /// simply dropped: `adde` produced a value byte-identical to `add`.
    ///
    /// It survived because the guard below compared the WHOLE rendering, and the
    /// marker intrinsics carry different names — so the assertion could never
    /// fail no matter what the writes did. The comparison now excludes the
    /// intrinsics, which is what makes it a test rather than a formality.
    ///
    /// `ADDC`/`SUBFC` produce a carry that is still unmodelled; their VALUE is
    /// correct, so that remains a fidelity gap named by the marker.
    #[test]
    fn carry_forms_are_distinguishable_from_plain_add() {
        let render = |m: &str| {
            let instr = make_instr(
                0x1000,
                m,
                vec![make_reg("r3"), make_reg("r4"), make_reg("r5")],
            );
            format!("{:?}", PpcLifter::new().lift(&instr).unwrap().effects)
        };
        // Compare only the WRITES: the marker intrinsics differ by name, so
        // comparing full renderings passes even when the semantics collapse.
        let writes = |m: &str| {
            PpcLifter::new()
                .lift(&make_instr(
                    0x1000,
                    m,
                    vec![make_reg("r3"), make_reg("r4"), make_reg("r5")],
                ))
                .unwrap()
                .effects
                .iter()
                .filter(|e| !matches!(e, Effect::Intrinsic { .. }))
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
        };

        assert_ne!(
            writes("add"),
            writes("adde"),
            "ADDE adds the carry-in; its VALUE must differ from ADD"
        );
        assert!(
            format!("{:?}", writes("adde")).contains("xer_ca"),
            "ADDE must read the carry: {:?}",
            writes("adde")
        );
        assert_ne!(
            writes("subf"),
            writes("subfe"),
            "SUBFE is ~rA + rB + CA; its VALUE must differ from SUBF"
        );

        // ADDC's value is the same as ADD's on purpose — only its carry-OUT
        // differs, and that is still unmodelled. The distinction lives in the
        // marker, so assert THAT rather than a value difference that should not
        // exist.
        assert_eq!(
            writes("add"),
            writes("addc"),
            "ADDC computes the same sum as ADD; only the carry-out differs"
        );
        let plain = render("add");
        assert_ne!(plain, render("addc"), "ADDC must still be distinguishable");
        assert!(render("adde").contains("adde"), "the carry fact must be named");

        // The `o` (overflow-recording) variants of the multiply/divide/negate
        // family were not covered when the add/subf ones were fixed.
        for (plain, ovf) in [
            ("neg", "nego"),
            ("mullw", "mullwo"),
            ("divw", "divwo"),
            ("divwu", "divwuo"),
        ] {
            assert_ne!(
                render(plain),
                render(ovf),
                "{ovf} records overflow in XER; {plain} does not"
            );
        }
    }

    /// The PowerPC `…u` forms UPDATE the base register with the effective
    /// address. Nine of them shared their handler with the non-update form, so
    /// the write-back was missing entirely; nothing in the suite covered it,
    /// which is why the fix had to be given a test rather than assumed to work.
    #[test]
    fn update_forms_write_back_the_base_register() {
        // lhzu r3, 8(r4)  =>  r3 = [r4 + 8]; r4 = r4 + 8
        let instr = make_instr(
            0x1000,
            "lhzu",
            vec![make_reg("r3"), make_imm(8), make_reg("r4")],
        );
        let effects = PpcLifter::new().lift(&instr).unwrap().effects;
        assert!(
            effects.iter().any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "r4")),
            "lhzu must write the effective address back into r4: {effects:?}"
        );

        // The NON-update form must be unchanged: no write-back.
        let plain = make_instr(
            0x1004,
            "lhz",
            vec![make_reg("r3"), make_imm(8), make_reg("r4")],
        );
        let plain_effects = PpcLifter::new().lift(&plain).unwrap().effects;
        assert!(
            !plain_effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "r4")),
            "lhz must NOT touch the base register: {plain_effects:?}"
        );
    }

    #[test]
    fn test_addi_with_base() {
        // addi r3, r1, 8   =>  r3 = r1 + 8
        let instr = make_instr(
            0x1000,
            "addi",
            vec![make_reg("r3"), make_reg("r1"), make_imm(8)],
        );
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "r3");
                match value {
                    IrExpr::Add(lhs, rhs) => {
                        assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "r1"));
                        assert!(matches!(rhs.as_ref(), IrExpr::Const(8)));
                    }
                    other => panic!("expected Add, got {other:?}"),
                }
            }
            other => panic!("expected RegWrite, got {other:?}"),
        }
    }

    #[test]
    fn test_addi_r0_base_is_li() {
        // addi r3, r0, 42  => r3 = 42  (r0 means zero)
        let instr = make_instr(
            0x1000,
            "addi",
            vec![make_reg("r3"), make_reg("r0"), make_imm(42)],
        );
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "r3");
                assert!(matches!(value, IrExpr::Const(42)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_li_pseudo() {
        // li r4, -1
        let instr = make_instr(0x1000, "li", vec![make_reg("r4"), make_imm(-1)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Const(v),
            } => {
                assert_eq!(reg, "r4");
                // -1 sign-extended from 16 bits = 0xFFFF_FFFF_FFFF_FFFF
                assert_eq!(*v, (-1i64) as u64);
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ LWZ Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_lwz() {
        // lwz r3, 4(r1)   =>  r3 = *(r1 + 4)
        let instr = make_instr(
            0x2000,
            "lwz",
            vec![make_reg("r3"), make_imm(4), make_reg("r1")],
        );
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::MemRead { addr, dest, size } => {
                assert_eq!(dest, "r3");
                assert_eq!(*size, 4u8);
                match addr {
                    IrExpr::Add(base, off) => {
                        assert!(matches!(base.as_ref(), IrExpr::Reg(r) if r == "r1"));
                        assert!(matches!(off.as_ref(), IrExpr::Const(4)));
                    }
                    other => panic!("expected Add EA, got {other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_lwz_zero_disp() {
        // lwz r5, 0(r3)  =>  r5 = *r3
        let instr = make_instr(
            0x2004,
            "lwz",
            vec![make_reg("r5"), make_imm(0), make_reg("r3")],
        );
        let lifted = lifter().lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::MemRead { addr, dest, size } => {
                assert_eq!(dest, "r5");
                assert_eq!(*size, 4);
                assert!(matches!(addr, IrExpr::Reg(r) if r == "r3"));
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ STW Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_stw() {
        // stw r3, 8(r1)   =>  *(r1 + 8) = r3
        let instr = make_instr(
            0x3000,
            "stw",
            vec![make_reg("r3"), make_imm(8), make_reg("r1")],
        );
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::MemWrite { addr, value, size } => {
                assert_eq!(*size, 4u8);
                assert!(matches!(value, IrExpr::Reg(r) if r == "r3"));
                match addr {
                    IrExpr::Add(base, off) => {
                        assert!(matches!(base.as_ref(), IrExpr::Reg(r) if r == "r1"));
                        assert!(matches!(off.as_ref(), IrExpr::Const(8)));
                    }
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ BL (call) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_bl_direct() {
        // bl 0x5000
        let instr = make_instr(0x4000, "bl", vec![make_label(0x5000)]);
        let lifted = lifter().lift(&instr).unwrap();
        // Should produce: lr = PC+4, Call { target: 0x5000 }
        assert_eq!(lifted.effects.len(), 2);
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "lr");
                assert!(matches!(value, IrExpr::Const(0x4004)));
            }
            other => panic!("{other:?}"),
        }
        match &lifted.effects[1] {
            Effect::Call { target } => {
                assert!(matches!(target, IrExpr::Const(0x5000)));
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ BLR (return) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_blr() {
        let instr = make_instr(0x5000, "blr", vec![]);
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::Return {
                value: Some(IrExpr::Reg(r)),
            } => {
                assert_eq!(r, "r3");
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SC (syscall) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_sc() {
        let instr = make_instr(0x6000, "sc", vec![]);
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::Syscall { nr: IrExpr::Reg(r) } => {
                assert_eq!(r, "r0");
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ NOP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_nop() {
        let instr = make_instr(0x7000, "nop", vec![]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(lifted.effects.is_empty());
        assert_eq!(lifted.ir_text, "nop");
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Rc-bit (record bit) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_add_dot_sets_cr0() {
        // add. r3, r4, r5
        let instr = make_instr(
            0x8000,
            "add.",
            vec![make_reg("r3"), make_reg("r4"), make_reg("r5")],
        );
        let lifted = lifter().lift(&instr).unwrap();
        // Should have RegWrite for r3 AND a cr0 update
        assert!(lifted.effects.len() >= 2);
        let has_cr0 = lifted
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "cr0"));
        assert!(has_cr0, "Expected cr0 update from add.");
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ MFLR / MTLR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_mflr() {
        let instr = make_instr(0x9000, "mflr", vec![make_reg("r3")]);
        let lifted = lifter().lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "r3");
                assert_eq!(src, "lr");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_mtlr() {
        let instr = make_instr(0x9004, "mtlr", vec![make_reg("r31")]);
        let lifted = lifter().lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "lr");
                assert_eq!(src, "r31");
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Arch name Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_arch_name() {
        assert_eq!(PpcLifter::new().arch_name(), "ppc");
        assert_eq!(PpcLifter::new_64().arch_name(), "ppc64");
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ STWU (store with update) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_stwu() {
        // stwu r1, -16(r1)  Ã¢â‚¬â€ typical prologue: allocate stack frame
        let instr = make_instr(
            0xA000,
            "stwu",
            vec![make_reg("r1"), make_imm(-16), make_reg("r1")],
        );
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(
            lifted.effects.len(),
            2,
            "stwu should produce MemWrite and RegWrite (update)"
        );
        assert!(matches!(
            &lifted.effects[0],
            Effect::MemWrite { size: 4, .. }
        ));
        assert!(matches!(&lifted.effects[1], Effect::RegWrite { reg, .. } if reg == "r1"));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ OR / MR pseudo Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_mr_pseudo() {
        // mr r4, r3  => r4 = r3
        let instr = make_instr(0xB000, "mr", vec![make_reg("r4"), make_reg("r3")]);
        let lifted = lifter().lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "r4");
                assert_eq!(src, "r3");
            }
            other => panic!("{other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Unknown mnemonic fallback Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_unknown_mnemonic() {
        let instr = make_instr(0xC000, "xyzzy_unknown", vec![]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            matches!(&lifted.effects[0], Effect::Intrinsic { name, .. } if name == "xyzzy_unknown")
        );
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 64-bit lifter Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_64bit_lifter() {
        let l = PpcLifter::new_64();
        assert_eq!(l.arch_name(), "ppc64");
        assert_eq!(l.bits, 64);
        assert_eq!(l.ptr_size(), 8);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ir_text non-empty for non-nop Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_ir_text_populated() {
        let instr = make_instr(0x1000, "li", vec![make_reg("r3"), make_imm(0)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.ir_text.is_empty());
        assert_ne!(lifted.ir_text, "nop");
    }
}
