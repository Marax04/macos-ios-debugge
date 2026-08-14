//! SPARC / SPARC64 LLIL lifter (`SparcLifter`).
//!
//! Mnemonic-driven lifter for the SPARC V8 (32-bit) and V9 (64-bit) ISA.
//!
//! # Register Windows
//!
//! SPARC uses a register-window architecture.  The 32 visible integer registers
//! are divided into four groups of eight:
//!
//! | Group  | Names       | Role                                        |
//! |--------|-------------|---------------------------------------------|
//! | global | %g0 â€“ %g7   | Always visible; %g0 is always zero          |
//! | output | %o0 â€“ %o7   | Outgoing args / return values; %o6 = %sp    |
//! | local  | %l0 â€“ %l7   | Caller-saves within the current window      |
//! | input  | %i0 â€“ %i7   | Incoming args / %i6 = %fp / %i7 = ret addr |
//!
//! On a `SAVE` instruction the register window slides: current %o becomes
//! new %i, a new set of %l registers is allocated, and %sp advances.  On
//! `RESTORE` the reverse happens.  We model `SAVE`/`RESTORE` as intrinsics.
//!
//! # Delay Slots
//!
//! Most SPARC control-flow instructions (branches and `CALL`) have a *delay
//! slot*: the instruction immediately following is always executed before the
//! branch takes effect.  This lifter records the delay-slot semantics via an
//! `Intrinsic { name: "delay_slot" }` effect appended after the branch effect,
//! matching the convention used by the MIPS lifter.
//!
//! # Condition Codes
//!
//! Conditional branches test the integer condition codes stored in the PSR
//! (processor status register): `icc_n`, `icc_z`, `icc_v`, `icc_c`.
//! We model each as a named register; the lifter emits them symbolically.

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SparcLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Mnemonic-driven LLIL lifter for SPARC V8 (32-bit) and SPARC V9 / SPARC64
/// (64-bit).
///
/// # Examples
///
/// ```
/// use rustre_il_lift::sparc_lifter::SparcLifter;
///
/// let lifter = SparcLifter::new();    // SPARC V8 / 32-bit
/// let lifter64 = SparcLifter::new_64(); // SPARC V9 / 64-bit
/// ```
#[derive(Debug, Clone)]
pub struct SparcLifter {
    /// Pointer / register size in bits: 32 or 64.
    pub bits: u32,
}

impl SparcLifter {
    /// Create a 32-bit SPARC V8 lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: 32 }
    }

    /// Create a 64-bit SPARC V9 / SPARC64 lifter.
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

    // â”€â”€ Register helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Normalise a SPARC register name.
    ///
    /// Strips a leading `%` if present, lower-cases the result, and maps known
    /// aliases:
    /// - `%o6` / `o6` â†’ `"sp"`
    /// - `%i6` / `i6` â†’ `"fp"`
    /// - `%o7` / `o7` â†’ `"o7"` (return-address register for CALL)
    /// - `%i7` / `i7` â†’ `"i7"` (return-address register for RETURN)
    /// - `%g0` / `g0` â†’ `"g0"` (always-zero, kept as a named register)
    #[must_use]
    pub fn norm_reg(raw: &str) -> String {
        let s = raw.trim().trim_start_matches('%').to_ascii_lowercase();
        match s.as_str() {
            "o6" | "sp" => "sp".to_string(),
            "i6" | "fp" => "fp".to_string(),
            _ => s,
        }
    }

    // â”€â”€ Operand helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Return the normalised register name at `idx`, if the operand is a
    /// register.
    fn op_reg(instr: &Instruction, idx: usize) -> Option<String> {
        instr
            .operand_list
            .get(idx)
            .and_then(|o| o.as_register())
            .map(|r| Self::norm_reg(&r.name))
    }

    /// Return the signed immediate value at `idx`.
    fn op_imm(instr: &Instruction, idx: usize) -> Option<i64> {
        instr.operand_list.get(idx).and_then(rustre_core::Operand::as_immediate)
    }

    /// Return the label / resolved-address value at `idx`.
    fn op_label(instr: &Instruction, idx: usize) -> Option<u64> {
        instr.operand_list.get(idx).and_then(rustre_core::Operand::as_label)
    }

    /// Build an [`IrExpr`] from the operand at `idx`: register â†’ `Reg`, immediate
    /// â†’ `Const`, label â†’ `Const`, otherwise `Undef`.
    fn op_expr(instr: &Instruction, idx: usize) -> IrExpr {
        if let Some(r) = Self::op_reg(instr, idx) {
            // %g0 is always zero; fold it immediately so later analysis is
            // simpler without requiring a constant-propagation pass.
            if r == "g0" {
                return IrExpr::Const(0);
            }
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

    /// Build the effective-address expression for a SPARC memory reference.
    ///
    /// SPARC addressing modes:
    /// - `[rs1 + rs2]`   â€“ register + register  (operands idx and idx+1)
    /// - `[rs1 + simm13]` â€“ register + signed 13-bit immediate
    /// - `[rs1]`          â€“ register only (treated as rs1 + 0)
    ///
    /// When `rs1` is `%g0` the base is folded to zero.
    fn mem_addr(instr: &Instruction, base_idx: usize) -> IrExpr {
        let base = Self::op_expr(instr, base_idx);
        // Check for a second operand (offset register or immediate).
        let offset_opt = if instr.operand_list.len() > base_idx + 1 {
            let o = Self::op_expr(instr, base_idx + 1);
            match &o {
                IrExpr::Const(0) => None,
                _ => Some(o),
            }
        } else {
            None
        };
        match (base, offset_opt) {
            (IrExpr::Const(0), None) => IrExpr::Const(0),
            (b, None) => b,
            (IrExpr::Const(0), Some(off)) => off,
            (b, Some(off)) => IrExpr::Add(Box::new(b), Box::new(off)),
        }
    }

    /// Resolve a branch / call target.
    ///
    /// Priority: Label operand â†’ Immediate (PC-relative if < 0x1000) â†’ %g0+offset.
    fn branch_target(instr: &Instruction, op_idx: usize) -> IrExpr {
        // Label takes precedence (already resolved absolute address).
        if let Some(a) = Self::op_label(instr, op_idx) {
            return IrExpr::Const(a);
        }
        if let Some(v) = Self::op_imm(instr, op_idx) {
            // SPARC branch displacements are word offsets.  If the value looks
            // like a small relative offset add it to the instruction address;
            // if it is already a plausible code address treat it as absolute.
            let target = if v.unsigned_abs() < 0x0010_0000 {
                instr.address.0.wrapping_add((v * 4).cast_unsigned())
            } else {
                v.cast_unsigned()
            };
            return IrExpr::Const(target);
        }
        // No explicit operand â€” indirect via register (e.g. JMPL %i7+8, %g0).
        Self::op_expr(instr, op_idx)
    }

    // â”€â”€ Condition-code helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Build the condition expression for integer condition-code branches.
    ///
    /// Returns `None` for `BA` (always) and a suitable `IrExpr` for every
    /// other Bicc instruction.
    fn icc_condition(mnem: &str) -> Option<IrExpr> {
        // Helper closures.
        let z = || IrExpr::Reg("icc_z".to_string());
        let n = || IrExpr::Reg("icc_n".to_string());
        let v = || IrExpr::Reg("icc_v".to_string());
        let c = || IrExpr::Reg("icc_c".to_string());
        let nz = || IrExpr::Not(Box::new(z()));
        let nn = || IrExpr::Not(Box::new(n()));
        let nv = || IrExpr::Not(Box::new(v()));
        let nc = || IrExpr::Not(Box::new(c()));

        match mnem {
            // Unconditional
            "bn" => Some(IrExpr::Const(0)), // never taken
            // Simple flag tests
            "be" | "bz" => Some(z()),
            "bne" | "bnz" => Some(nz()),
            "bneg" | "bmi" => Some(n()),
            "bpos" | "bpl" => Some(nn()),
            "bvs" => Some(v()),
            "bvc" => Some(nv()),
            "bcs" | "blu" | "bcarry" => Some(c()),
            "bcc" | "bgeu" | "bncarry" => Some(nc()),
            // Unsigned comparisons
            "bleu" =>
            // C | Z
            {
                Some(IrExpr::Or(Box::new(c()), Box::new(z())))
            }
            "bgu" =>
            // ~C & ~Z
            {
                Some(IrExpr::And(Box::new(nc()), Box::new(nz())))
            }
            // Signed comparisons
            "bl" =>
            // N xor V
            {
                Some(IrExpr::Xor(Box::new(n()), Box::new(v())))
            }
            "bge" =>
            // ~(N xor V)
            {
                Some(IrExpr::Not(Box::new(IrExpr::Xor(
                    Box::new(n()),
                    Box::new(v()),
                ))))
            }
            "ble" =>
            // Z | (N xor V)
            {
                Some(IrExpr::Or(
                    Box::new(z()),
                    Box::new(IrExpr::Xor(Box::new(n()), Box::new(v()))),
                ))
            }
            "bg" =>
            // ~Z & ~(N xor V)
            {
                Some(IrExpr::And(
                    Box::new(nz()),
                    Box::new(IrExpr::Not(Box::new(IrExpr::Xor(
                        Box::new(n()),
                        Box::new(v()),
                    )))),
                ))
            }
            _ => None,
        }
    }

    // â”€â”€ Main dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Map an instruction mnemonic + operands to a list of [`Effect`]s.
    fn mnemonic_to_effects_a_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "nop" => Some(vec![]),

            "add" | "addcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: IrExpr::Add(Box::new(rs1.clone()), Box::new(rs2_or_imm.clone())),
                    });
                }
                if mnem == "addcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![IrExpr::Add(Box::new(rs1), Box::new(rs2_or_imm))],
                    });
                }
                Some(efx)
            }
            "addx" | "addxcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                // ADDX = ADD + carry
                let sum_plus_c = IrExpr::Add(
                    Box::new(IrExpr::Add(
                        Box::new(rs1),
                        Box::new(rs2_or_imm),
                    )),
                    Box::new(IrExpr::Reg("icc_c".to_string())),
                );
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: sum_plus_c.clone(),
                    });
                }
                if mnem == "addxcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![sum_plus_c],
                    });
                }
                Some(efx)
            }
            "sub" | "subcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: IrExpr::Sub(Box::new(rs1.clone()), Box::new(rs2_or_imm.clone())),
                    });
                }
                if mnem == "subcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![IrExpr::Sub(Box::new(rs1), Box::new(rs2_or_imm))],
                    });
                }
                Some(efx)
            }
                    _ => None,
                }
    }

    fn mnemonic_to_effects_a_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "subx" | "subxcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let diff_minus_c = IrExpr::Sub(
                    Box::new(IrExpr::Sub(
                        Box::new(rs1),
                        Box::new(rs2_or_imm),
                    )),
                    Box::new(IrExpr::Reg("icc_c".to_string())),
                );
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: diff_minus_c.clone(),
                    });
                }
                if mnem == "subxcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![diff_minus_c],
                    });
                }
                Some(efx)
            }
            "umul" | "smul" | "umulcc" | "smulcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let product = IrExpr::Mul(Box::new(rs1.clone()), Box::new(rs2_or_imm.clone()));
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: product.clone(),
                    });
                }
                // The high 32 bits go into %y — and THAT is where the
                // signedness matters. `umul` and `smul` shared this arm and
                // emitted the same `mul_high_to_y`, so the upper half of a
                // signed product was indistinguishable from an unsigned one.
                //
                // The low half deliberately keeps a plain `Mul`: the low 32
                // bits of a product are identical either way, so only the high
                // half is fixed here.
                //
                // Naming pattern taken from `udiv`/`sdiv` a few arms below,
                // which already got this right.
                efx.push(Effect::Intrinsic {
                    name: if mnem.starts_with('s') {
                        "smul_high_to_y".to_string()
                    } else {
                        "umul_high_to_y".to_string()
                    },
                    args: vec![IrExpr::Mul(Box::new(rs1), Box::new(rs2_or_imm))],
                });
                if mnem == "umulcc" || mnem == "smulcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![product],
                    });
                }
                Some(efx)
            }
            "udiv" | "sdiv" | "udivcc" | "sdivcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let signed = mnem.starts_with('s');
                let mut efx = vec![Effect::Intrinsic {
                    name: if signed {
                        "sdiv".to_string()
                    } else {
                        "udiv".to_string()
                    },
                    args: vec![rs1, rs2_or_imm, IrExpr::Reg(rd)],
                }];
                if mnem == "udivcc" || mnem == "sdivcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![],
                    });
                }
                Some(efx)
            }
                    _ => None,
                }
    }

    fn mnemonic_to_effects_a_c(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "and" | "andcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: IrExpr::And(Box::new(rs1.clone()), Box::new(rs2_or_imm.clone())),
                    });
                }
                if mnem == "andcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![IrExpr::And(Box::new(rs1), Box::new(rs2_or_imm))],
                    });
                }
                Some(efx)
            }
                _ => None,
                }
    }

    fn mnemonic_to_effects_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let _mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

        if let Some(r) = Self::mnemonic_to_effects_a_a(instr) { return Some(r); }
        if let Some(r) = Self::mnemonic_to_effects_a_b(instr) { return Some(r); }
        Self::mnemonic_to_effects_a_c(instr)
    }
    fn mnemonic_to_effects_b_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "andn" | "andncc" => {
                // ANDN rd, rs1, rs2  â†’  rd = rs1 & ~rs2
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let val = IrExpr::And(
                    Box::new(rs1),
                    Box::new(IrExpr::Not(Box::new(rs2_or_imm))),
                );
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: val.clone(),
                    });
                }
                if mnem == "andncc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![val],
                    });
                }
                Some(efx)
            }
            "or" | "orcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: IrExpr::Or(Box::new(rs1.clone()), Box::new(rs2_or_imm.clone())),
                    });
                }
                if mnem == "orcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![IrExpr::Or(Box::new(rs1), Box::new(rs2_or_imm))],
                    });
                }
                Some(efx)
            }
            "orn" | "orncc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let val = IrExpr::Or(
                    Box::new(rs1),
                    Box::new(IrExpr::Not(Box::new(rs2_or_imm))),
                );
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: val.clone(),
                    });
                }
                if mnem == "orncc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![val],
                    });
                }
                Some(efx)
            }
            "xor" | "xorcc" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: IrExpr::Xor(Box::new(rs1.clone()), Box::new(rs2_or_imm.clone())),
                    });
                }
                if mnem == "xorcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![IrExpr::Xor(Box::new(rs1), Box::new(rs2_or_imm))],
                    });
                }
                Some(efx)
            }
                    _ => None,
                }
    }

    fn mnemonic_to_effects_b_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "xnor" | "xnorcc" => {
                // XNOR = ~(rs1 XOR rs2)
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                let val = IrExpr::Not(Box::new(IrExpr::Xor(
                    Box::new(rs1),
                    Box::new(rs2_or_imm),
                )));
                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd,
                        value: val.clone(),
                    });
                }
                if mnem == "xnorcc" {
                    efx.push(Effect::Intrinsic {
                        name: "set_icc".to_string(),
                        args: vec![val],
                    });
                }
                Some(efx)
            }
            "sll" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let shcnt = Self::op_expr(instr, 2);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Shl(Box::new(rs1), Box::new(shcnt)),
                }])
            }
            "srl" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let shcnt = Self::op_expr(instr, 2);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Shr(Box::new(rs1), Box::new(shcnt)),
                }])
            }
            "sra" => {
                // Arithmetic right shift; we model it as Shr with an intrinsic
                // qualifier since IrExpr::Shr is unsigned.
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let shcnt = Self::op_expr(instr, 2);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::Intrinsic {
                    name: "sra".to_string(),
                    args: vec![IrExpr::Reg(rd), rs1, shcnt],
                }])
            }
                _ => None,
                }
    }

    fn mnemonic_to_effects_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let _mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

        if let Some(r) = Self::mnemonic_to_effects_b_a(instr) { return Some(r); }
        Self::mnemonic_to_effects_b_b(instr)
    }
    fn mnemonic_to_effects_c(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

            match mnem {

            // SPARC V9 64-bit shifts.
            "sllx" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let shcnt = Self::op_expr(instr, 2);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Shl(Box::new(rs1), Box::new(shcnt)),
                }])
            }

            "srlx" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let shcnt = Self::op_expr(instr, 2);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Shr(Box::new(rs1), Box::new(shcnt)),
                }])
            }

            "srax" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let shcnt = Self::op_expr(instr, 2);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::Intrinsic {
                    name: "srax".to_string(),
                    args: vec![IrExpr::Reg(rd), rs1, shcnt],
                }])
            }

            // â”€â”€ Pseudo-instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

            // MOV rd, rs  (assembled as OR %g0, rs, rd)
            "mov" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let src = Self::op_expr(instr, 1);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: src,
                }])
            }

            // CLR rd  (assembled as OR %g0, %g0, rd)
            "clr" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Const(0),
                }])
            }

            // SETHI imm22, rd  â€” loads the upper 22 bits.
            "sethi" => {
                let imm = Self::op_imm(instr, 0).unwrap_or(0).cast_unsigned();
                let rd = Self::op_reg(instr, 1).unwrap_or_else(|| "g0".into());
                if rd == "g0" {
                    return Some(vec![]);
                } // sethi 0, %g0 = NOP
                // The hardware shifts left by 10; disassemblers often pre-shift.
                // If the value looks like it has already been shifted (>= 2^10)
                // use it directly; otherwise shift.
                let val = if imm < (1 << 10) { imm << 10 } else { imm };
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Const(val),
                }])
            }

            // CMP rs1, rs2/imm  (SUBCC %g0, â€¦; we keep a named intrinsic)
            "cmp" => {
                let rs1 = Self::op_expr(instr, 0);
                let rs2_or_imm = Self::op_expr(instr, 1);
                Some(vec![Effect::Intrinsic {
                    name: "cmp".to_string(),
                    args: vec![rs1, rs2_or_imm],
                }])
            }

            // TST rs  (ORCC %g0, rs, %g0)
            "tst" => {
                let rs = Self::op_expr(instr, 0);
                Some(vec![Effect::Intrinsic {
                    name: "tst".to_string(),
                    args: vec![rs],
                }])
            }
                _ => None,
            }
    }
    fn mnemonic_to_effects_d(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

            match mnem {

            // NOT rd  (XNOR rd, %g0, rs)
            "not" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs = Self::op_expr(instr, 0); // same operand
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Not(Box::new(rs)),
                }])
            }

            // NEG rd  (SUB %g0, rs, rd)
            "neg" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs = Self::op_expr(instr, 0);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(rs)),
                }])
            }

            // â”€â”€ Memory loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // SPARC loads: rd is always the destination; address = [rs1+rs2/simm13]
            // Operand layout from disassemblers varies; we treat:
            //   op[0] = rd, op[1] = base reg, op[2] = index/offset (optional)
            "ld" | "lduw" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                if rd == "g0" {
                    return Some(vec![Effect::MemRead {
                        addr,
                        dest: "g0".into(),
                        size: 4,
                    }]);
                }
                Some(vec![Effect::MemRead {
                    addr,
                    dest: rd,
                    size: 4,
                }])
            }

            "ldd" => {
                // Load double: loads 8 bytes into rd:rd+1.
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                Some(vec![
                    Effect::MemRead {
                        addr: addr.clone(),
                        dest: rd.clone(),
                        size: 4,
                    },
                    Effect::Intrinsic {
                        name: "ldd_high".to_string(),
                        args: vec![addr, IrExpr::Reg(rd)],
                    },
                ])
            }

            "ldx" => {
                // SPARC V9: load 64-bit.
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemRead {
                    addr,
                    dest: rd,
                    size: 8,
                }])
            }

            "ldsb" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::Intrinsic {
                    name: "ldsb".to_string(),
                    args: vec![addr, IrExpr::Reg(rd)],
                }])
            }

            "ldsh" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::Intrinsic {
                    name: "ldsh".to_string(),
                    args: vec![addr, IrExpr::Reg(rd)],
                }])
            }

            "ldub" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemRead {
                    addr,
                    dest: rd,
                    size: 1,
                }])
            }
                _ => None,
            }
    }
    fn mnemonic_to_effects_e_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "lduh" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemRead {
                    addr,
                    dest: rd,
                    size: 2,
                }])
            }
            "st" | "stw" => {
                let rs = Self::op_expr(instr, 0);
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemWrite {
                    addr,
                    value: rs,
                    size: 4,
                }])
            }
            "stx" => {
                let rs = Self::op_expr(instr, 0);
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemWrite {
                    addr,
                    value: rs,
                    size: 8,
                }])
            }
            "stb" | "stub" => {
                let rs = Self::op_expr(instr, 0);
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemWrite {
                    addr,
                    value: rs,
                    size: 1,
                }])
            }
            "sth" | "stuh" => {
                let rs = Self::op_expr(instr, 0);
                let addr = Self::mem_addr(instr, 1);
                Some(vec![Effect::MemWrite {
                    addr,
                    value: rs,
                    size: 2,
                }])
            }
            "std" => {
                // Store double: two consecutive word stores.
                let rs = Self::op_expr(instr, 0);
                let addr = Self::mem_addr(instr, 1);
                Some(vec![
                    Effect::MemWrite {
                        addr: addr.clone(),
                        value: rs.clone(),
                        size: 4,
                    },
                    Effect::Intrinsic {
                        name: "std_high".to_string(),
                        args: vec![addr, rs],
                    },
                ])
            }
            "call" => {
                let target = Self::branch_target(instr, 0);
                let ret_addr = instr.address.0 + 4;
                Some(vec![
                    // Save return address to %o7.
                    Effect::RegWrite {
                        reg: "o7".to_string(),
                        value: IrExpr::Const(ret_addr),
                    },
                    Effect::Call { target },
                    Effect::Intrinsic {
                        name: "delay_slot".to_string(),
                        args: vec![],
                    },
                ])
            }
                    _ => None,
                }
    }

    fn mnemonic_to_effects_e_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

                match mnem {
            "jmpl" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                // For JMPL the operand order is (target_expr, rd) in most
                // disassemblers, but some put rd first.  We handle both by
                // checking which operand looks like a register vs. memory expr.
                let target = Self::mem_addr(instr, 1);

                // Detect RET / RETL patterns:
                //   target is %i7+8 or %o7+8 and rd is %g0 â†’ Return
                let is_ret = rd == "g0" && {
                    // Check if the first base operand is i7 or o7.
                    let base_reg = Self::op_reg(instr, 1).or_else(|| Self::op_reg(instr, 0));
                    matches!(base_reg.as_deref(), Some("i7" | "o7"))
                };

                let mut efx = vec![];
                if rd != "g0" {
                    efx.push(Effect::RegWrite {
                        reg: rd.clone(),
                        value: IrExpr::Const(instr.address.0),
                    });
                }
                if is_ret {
                    efx.push(Effect::Return {
                        value: Some(IrExpr::Reg("o0".to_string())),
                    });
                } else if rd == "o7" || rd == "g0" {
                    // Indirect call or tail-call.
                    efx.push(Effect::Call { target });
                } else {
                    efx.push(Effect::Branch {
                        target,
                        condition: None,
                    });
                }
                efx.push(Effect::Intrinsic {
                    name: "delay_slot".to_string(),
                    args: vec![],
                });
                Some(efx)
            }
                _ => None,
                }
    }

    fn mnemonic_to_effects_e(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let _mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

        if let Some(r) = Self::mnemonic_to_effects_e_a(instr) { return Some(r); }
        Self::mnemonic_to_effects_e_b(instr)
    }
    fn mnemonic_to_effects_f(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

            match mnem {

            // â”€â”€ Control flow: RET / RETL (pseudo-mnemonics) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ret" => {
                Some(vec![
                    Effect::Return {
                        value: Some(IrExpr::Reg("o0".to_string())),
                    },
                    Effect::Intrinsic {
                        name: "delay_slot".to_string(),
                        args: vec![],
                    },
                ])
            }

            "retl" => {
                // Leaf return: uses %o7 instead of %i7.
                Some(vec![
                    Effect::Return {
                        value: Some(IrExpr::Reg("o0".to_string())),
                    },
                    Effect::Intrinsic {
                        name: "delay_slot".to_string(),
                        args: vec![],
                    },
                ])
            }

            // â”€â”€ Control flow: Branches (Bicc) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // Branch-always (BA) = unconditional jump.
            "ba" => {
                let target = Self::branch_target(instr, 0);
                Some(vec![
                    Effect::Branch {
                        target,
                        condition: None,
                    },
                    Effect::Intrinsic {
                        name: "delay_slot".to_string(),
                        args: vec![],
                    },
                ])
            }

            // Branch-never (BN) = effectively a NOP (never taken).
            "bn" => {
                Some(vec![
                    Effect::Branch {
                        target: Self::branch_target(instr, 0),
                        condition: Some(IrExpr::Const(0)),
                    },
                    Effect::Intrinsic {
                        name: "delay_slot".to_string(),
                        args: vec![],
                    },
                ])
            }

            // All other integer conditional branches.
            b if Self::icc_condition(b).is_some() => {
                let target = Self::branch_target(instr, 0);
                let cond = Self::icc_condition(b).unwrap();
                Some(vec![
                    Effect::Branch {
                        target,
                        condition: Some(cond),
                    },
                    Effect::Intrinsic {
                        name: "delay_slot".to_string(),
                        args: vec![],
                    },
                ])
            }

            // â”€â”€ Register-window operations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "save" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "sp".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                Some(vec![Effect::Intrinsic {
                    name: "save".to_string(),
                    args: vec![IrExpr::Reg(rd), rs1, rs2_or_imm],
                }])
            }

            "restore" => {
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let rs1 = Self::op_expr(instr, 1);
                let rs2_or_imm = Self::op_expr(instr, 2);
                Some(vec![Effect::Intrinsic {
                    name: "restore".to_string(),
                    args: vec![IrExpr::Reg(rd), rs1, rs2_or_imm],
                }])
            }

            // â”€â”€ Trap instructions (Ticc) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // TA 0 is a common system-call convention on Solaris.
            "ta" => {
                let nr = Self::op_expr(instr, 0);
                Some(vec![Effect::Syscall { nr }])
            }
                _ => None,
            }
    }
    fn mnemonic_to_effects_g(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

            match mnem {

            t if t.starts_with('t') && Self::icc_condition(&t[1..]).is_some() => {
                // Conditional trap: te, tne, tl, tge, â€¦ â†’ Intrinsic
                let cond_mnem = &t[1..];
                let cond = Self::icc_condition(cond_mnem).unwrap_or(IrExpr::Undef);
                Some(vec![Effect::Intrinsic {
                    name: format!("trap_{cond_mnem}"),
                    args: vec![cond, Self::op_expr(instr, 0)],
                }])
            }

            // â”€â”€ Memory barrier / serialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "stbar" => Some(vec![Effect::Intrinsic {
                name: "stbar".to_string(),
                args: vec![],
            }]),
            "membar" => {
                let mask = Self::op_expr(instr, 0);
                Some(vec![Effect::Intrinsic {
                    name: "membar".to_string(),
                    args: vec![mask],
                }])
            }
            "flush" => {
                let addr = Self::op_expr(instr, 0);
                Some(vec![Effect::Intrinsic {
                    name: "flush".to_string(),
                    args: vec![addr],
                }])
            }

            // â”€â”€ SPARC V9: MOVcc (conditional move) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // MOVcc cond, rs2_or_imm, rd  â€” rd = (cond) ? rs2 : rd (unchanged)
            m if m.starts_with("mov") && m.len() > 3 => {
                let cond_part = &m[3..];
                let cond = Self::icc_condition(cond_part)
                    .unwrap_or_else(|| IrExpr::Reg(format!("cc_{cond_part}")));
                let rd = Self::op_reg(instr, 0).unwrap_or_else(|| "g0".into());
                let src = Self::op_expr(instr, 1);
                Some(vec![Effect::Intrinsic {
                    name: format!("movcc_{cond_part}"),
                    args: vec![cond, src, IrExpr::Reg(rd)],
                }])
            }

            // â”€â”€ State register reads / writes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "rd" => {
                // RD  %reg_state, rd   â€” read state register
                let rd = Self::op_reg(instr, 1).unwrap_or_else(|| "g0".into());
                let src = Self::op_expr(instr, 0);
                if rd == "g0" {
                    return Some(vec![]);
                }
                Some(vec![Effect::RegWrite {
                    reg: rd,
                    value: src,
                }])
            }

            "wr" => {
                // WR  rs1, rs2_or_imm, %state_reg â€” write state register
                let rs1 = Self::op_expr(instr, 0);
                let rs2 = Self::op_expr(instr, 1);
                let dest = Self::op_reg(instr, 2).unwrap_or_else(|| "y".into());
                Some(vec![Effect::RegWrite {
                    reg: dest,
                    value: IrExpr::Xor(Box::new(rs1), Box::new(rs2)),
                }])
            }

            // â”€â”€ Floating-point skeleton â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // Full FP lifting is out of scope; emit named intrinsics for all
            // fp* / f* instructions.
            f if f.starts_with('f') => {
                let args: Vec<IrExpr> = (0..instr.operand_list.len())
                    .map(|i| Self::op_expr(instr, i))
                    .collect();
                Some(vec![Effect::Intrinsic {
                    name: f.to_string(),
                    args,
                }])
            }
                _ => None,
            }
    }
    fn mnemonic_to_effects_h(instr: &Instruction) -> Vec<Effect> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

        // â”€â”€ Unrecognised / privileged â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let other = mnem;
        let args: Vec<IrExpr> = (0..instr.operand_list.len())
            .map(|i| Self::op_expr(instr, i))
            .collect();
        vec![Effect::Intrinsic {
            name: other.to_string(),
            args,
        }]
    }

    fn mnemonic_to_effects(instr: &Instruction) -> Vec<Effect> {
        let raw_mnem = instr.mnemonic.to_ascii_lowercase();
        // Strip an optional trailing ",a" annul suffix (e.g. "ba,a") and a
        // trailing ",pt" / ",pn" prediction hint used in SPARC V9.
        let _mnem = raw_mnem
            .trim_end_matches(",pn")
            .trim_end_matches(",pt")
            .trim_end_matches(",a")
            .trim_end_matches(",a ")
            .trim();

        if let Some(r) = Self::mnemonic_to_effects_a(instr) { return r; }
        if let Some(r) = Self::mnemonic_to_effects_b(instr) { return r; }
        if let Some(r) = Self::mnemonic_to_effects_c(instr) { return r; }
        if let Some(r) = Self::mnemonic_to_effects_d(instr) { return r; }
        if let Some(r) = Self::mnemonic_to_effects_e(instr) { return r; }
        if let Some(r) = Self::mnemonic_to_effects_f(instr) { return r; }
        if let Some(r) = Self::mnemonic_to_effects_g(instr) { return r; }
        Self::mnemonic_to_effects_h(instr)
    }
}

// â”€â”€ Default â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl Default for SparcLifter {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€ fmt::Display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl fmt::Display for SparcLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SparcLifter({})", self.bits)
    }
}

// â”€â”€ ArchLifter implementation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl ArchLifter for SparcLifter {
    fn arch_name(&self) -> &'static str {
        if self.bits == 64 { "sparc64" } else { "sparc" }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        if self.bits == 64 {
            "SPARC V9 / SPARC64 mnemonic-driven LLIL lifter"
        } else {
            "SPARC V8 32-bit mnemonic-driven LLIL lifter"
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        let m = mnemonic.to_ascii_lowercase();
        // We handle every SPARC mnemonic via the catch-all arm, so always true.
        !m.is_empty()
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
    use rustre_core::arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind};

    // â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn reg_op(name: &str) -> Operand {
        Operand::Register(RegisterInfo::new(name, 0, 4, RegisterKind::General))
    }

    fn imm_op(v: i64) -> Operand {
        Operand::Immediate(v)
    }

    fn label_op(addr: u64) -> Operand {
        Operand::Label(addr)
    }

    fn make_instr(addr: u64, mnemonic: &str, operands: Vec<Operand>) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 4, mnemonic.to_string(), vec![0x00u8; 4]);
        i.flags = InstrFlags::NONE;
        i.operand_list = operands;
        i
    }

    fn lift(mnemonic: &str, operands: Vec<Operand>) -> Vec<Effect> {
        let lifter = SparcLifter::new();
        let instr = make_instr(0x1000, mnemonic, operands);
        lifter.lift(&instr).expect("lift failed").effects
    }

    fn lift64(mnemonic: &str, operands: Vec<Operand>) -> Vec<Effect> {
        let lifter = SparcLifter::new_64();
        let instr = make_instr(0x1000, mnemonic, operands);
        lifter.lift(&instr).expect("lift64 failed").effects
    }

    // â”€â”€ NOP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_nop_produces_no_effects() {
        let efx = lift("nop", vec![]);
        assert!(efx.is_empty(), "nop should produce no effects");
    }

    // â”€â”€ ADD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_add_register_operands() {
        // ADD %o0, %o1, %o2   â†’   o2 = o0 + o1
        let efx = lift("add", vec![reg_op("o2"), reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Add(l, r),
            } => {
                assert_eq!(reg, "o2");
                assert!(matches!(l.as_ref(), IrExpr::Reg(n) if n == "o0"));
                assert!(matches!(r.as_ref(), IrExpr::Reg(n) if n == "o1"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_add_immediate_operand() {
        // ADD %o0, 42, %o1   â†’   o1 = o0 + 0x2a
        let efx = lift("add", vec![reg_op("o1"), reg_op("o0"), imm_op(42)]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Add(l, r),
            } => {
                assert_eq!(reg, "o1");
                assert!(matches!(l.as_ref(), IrExpr::Reg(n) if n == "o0"));
                assert!(matches!(r.as_ref(), IrExpr::Const(42)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_addcc_emits_icc_update() {
        let efx = lift("addcc", vec![reg_op("o2"), reg_op("o0"), reg_op("o1")]);
        assert_eq!(
            efx.len(),
            2,
            "addcc should emit RegWrite + set_icc intrinsic"
        );
        assert!(matches!(&efx[0], Effect::RegWrite { reg, .. } if reg == "o2"));
        assert!(matches!(&efx[1], Effect::Intrinsic { name, .. } if name == "set_icc"));
    }

    #[test]
    fn test_add_to_g0_is_discarded() {
        // ADD %g0, %o0, %o1  â€” result goes to %g0, so RegWrite is suppressed.
        let efx = lift("add", vec![reg_op("g0"), reg_op("o0"), reg_op("o1")]);
        assert!(efx.is_empty(), "write to %g0 should be discarded");
    }

    // â”€â”€ SUB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sub_register_operands() {
        let efx = lift("sub", vec![reg_op("o3"), reg_op("o1"), reg_op("o2")]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Sub(l, r),
            } => {
                assert_eq!(reg, "o3");
                assert!(matches!(l.as_ref(), IrExpr::Reg(n) if n == "o1"));
                assert!(matches!(r.as_ref(), IrExpr::Reg(n) if n == "o2"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ CMP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cmp_emits_intrinsic() {
        let efx = lift("cmp", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "cmp"));
    }

    // â”€â”€ AND / OR / XOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_and_register_operands() {
        let efx = lift("and", vec![reg_op("l0"), reg_op("l1"), reg_op("l2")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::And(..) } if reg == "l0"));
    }

    #[test]
    fn test_andn_inverts_second_operand() {
        let efx = lift("andn", vec![reg_op("l0"), reg_op("l1"), reg_op("l2")]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::RegWrite {
                value: IrExpr::And(_, r),
                ..
            } => {
                assert!(matches!(r.as_ref(), IrExpr::Not(_)));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_or_register_operands() {
        let efx = lift("or", vec![reg_op("l3"), reg_op("l4"), reg_op("l5")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Or(..) } if reg == "l3"));
    }

    #[test]
    fn test_xor_register_operands() {
        let efx = lift("xor", vec![reg_op("i0"), reg_op("i1"), reg_op("i2")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Xor(..) } if reg == "i0"));
    }

    #[test]
    fn test_xnor_is_not_of_xor() {
        let efx = lift("xnor", vec![reg_op("i0"), reg_op("i1"), reg_op("i2")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(
            &efx[0],
            Effect::RegWrite {
                value: IrExpr::Not(_),
                ..
            }
        ));
    }

    // â”€â”€ Shifts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sll_left_shift() {
        let efx = lift("sll", vec![reg_op("o0"), reg_op("o1"), imm_op(3)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Shl(..) } if reg == "o0"));
    }

    #[test]
    fn test_srl_right_shift() {
        let efx = lift("srl", vec![reg_op("o0"), reg_op("o1"), imm_op(2)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Shr(..) } if reg == "o0"));
    }

    #[test]
    fn test_sra_emits_intrinsic() {
        // SRA is arithmetic right shift â€” modelled as an intrinsic.
        let efx = lift("sra", vec![reg_op("o0"), reg_op("o1"), imm_op(1)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "sra"));
    }

    // â”€â”€ SETHI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sethi_upper_22_bits() {
        // SETHI 0x12345, %l0  â€” value already pre-shifted by disassembler.
        // 0x12345 >= 1024, so it should be used as-is.
        let efx = lift("sethi", vec![imm_op(0x12345), reg_op("l0")]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Const(v),
            } => {
                assert_eq!(reg, "l0");
                assert_eq!(*v, 0x12345);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_sethi_to_g0_is_nop() {
        let efx = lift("sethi", vec![imm_op(0), reg_op("g0")]);
        assert!(efx.is_empty(), "sethi 0, %g0 should be NOP");
    }

    // â”€â”€ MOV / CLR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_mov_register() {
        let efx = lift("mov", vec![reg_op("o0"), reg_op("i0")]);
        assert_eq!(efx.len(), 1);
        assert!(
            matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Reg(src) }
            if reg == "o0" && src == "i0")
        );
    }

    #[test]
    fn test_clr_zeroes_register() {
        let efx = lift("clr", vec![reg_op("l2")]);
        assert_eq!(efx.len(), 1);
        assert!(
            matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Const(0) }
            if reg == "l2")
        );
    }

    // â”€â”€ Memory: LD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ld_simple_register_base() {
        // LD %o0, [%o1]   â†’  MemRead { addr: o1, dest: o0, size: 4 }
        let efx = lift("ld", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::MemRead { dest, size, .. } => {
                assert_eq!(dest, "o0");
                assert_eq!(*size, 4);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_ld_register_plus_offset() {
        // LD %o0, [%sp + 0x10]
        let efx = lift("ld", vec![reg_op("o0"), reg_op("sp"), imm_op(0x10)]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::MemRead {
                addr: IrExpr::Add(base, offset),
                size,
                dest,
            } => {
                assert_eq!(*size, 4);
                assert_eq!(dest, "o0");
                assert!(matches!(base.as_ref(), IrExpr::Reg(n) if n == "sp"));
                assert!(matches!(offset.as_ref(), IrExpr::Const(0x10)));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_ldub_byte_load() {
        let efx = lift("ldub", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::MemRead { size: 1, dest, .. } if dest == "o0"));
    }

    #[test]
    fn test_lduh_half_load() {
        let efx = lift("lduh", vec![reg_op("l0"), reg_op("l1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::MemRead { size: 2, dest, .. } if dest == "l0"));
    }

    #[test]
    fn test_ldsb_emits_intrinsic() {
        let efx = lift("ldsb", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "ldsb"));
    }

    // â”€â”€ Memory: ST â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_st_word_store() {
        // ST %o0, [%sp + 4]  â†’  MemWrite { addr: sp+4, value: o0, size: 4 }
        let efx = lift("st", vec![reg_op("o0"), reg_op("sp"), imm_op(4)]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::MemWrite {
                value: IrExpr::Reg(src),
                size,
                ..
            } => {
                assert_eq!(src, "o0");
                assert_eq!(*size, 4);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_stb_byte_store() {
        let efx = lift("stb", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::MemWrite { size: 1, .. }));
    }

    #[test]
    fn test_sth_half_store() {
        let efx = lift("sth", vec![reg_op("l0"), reg_op("l1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::MemWrite { size: 2, .. }));
    }

    // â”€â”€ CALL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_call_absolute_label() {
        // CALL 0x4000
        let lifter = SparcLifter::new();
        let instr = make_instr(0x1000, "call", vec![label_op(0x4000)]);
        let result = lifter.lift(&instr).expect("lift failed");
        let efx = &result.effects;

        // Effects: RegWrite{o7=0x1004}, Call{0x4000}, delay_slot
        assert_eq!(efx.len(), 3, "call should produce 3 effects");

        // %o7 gets return address (instruction address + 4).
        match &efx[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Const(v),
            } => {
                assert_eq!(reg, "o7");
                assert_eq!(*v, 0x1004);
            }
            other => panic!("expected o7 write, got: {other:?}"),
        }

        // Call target.
        match &efx[1] {
            Effect::Call {
                target: IrExpr::Const(0x4000),
            } => {}
            other => panic!("expected call to 0x4000, got: {other:?}"),
        }

        // Delay slot intrinsic.
        assert!(matches!(&efx[2], Effect::Intrinsic { name, .. } if name == "delay_slot"));
    }

    #[test]
    fn test_call_pc_relative_offset() {
        // CALL with a small immediate offset (word count).
        let lifter = SparcLifter::new();
        // offset = 10 words = 40 bytes; target = 0x1000 + 40 = 0x1028
        let instr = make_instr(0x1000, "call", vec![imm_op(10)]);
        let result = lifter.lift(&instr).expect("lift");
        let efx = &result.effects;
        match &efx[1] {
            Effect::Call {
                target: IrExpr::Const(t),
            } => {
                assert_eq!(*t, 0x1000 + 10 * 4, "PC-relative call target mismatch");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ RET â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ret_produces_return_effect() {
        let efx = lift("ret", vec![]);
        assert!(!efx.is_empty());
        assert!(matches!(&efx[0], Effect::Return { value: Some(_) }));
        // Should also have a delay_slot.
        assert!(
            efx.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "delay_slot"))
        );
    }

    #[test]
    fn test_retl_is_leaf_return() {
        let efx = lift("retl", vec![]);
        assert!(matches!(&efx[0], Effect::Return { value: Some(IrExpr::Reg(r)) } if r == "o0"));
    }

    // â”€â”€ BA (unconditional branch) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ba_unconditional_branch() {
        let lifter = SparcLifter::new();
        let instr = make_instr(0x2000, "ba", vec![label_op(0x3000)]);
        let result = lifter.lift(&instr).expect("lift");
        let efx = &result.effects;
        assert_eq!(efx.len(), 2, "ba: branch + delay_slot");
        match &efx[0] {
            Effect::Branch {
                target: IrExpr::Const(0x3000),
                condition: None,
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert!(matches!(&efx[1], Effect::Intrinsic { name, .. } if name == "delay_slot"));
    }

    #[test]
    fn test_ba_with_annul_suffix() {
        // "ba,a" should strip the annul suffix and behave like "ba".
        let lifter = SparcLifter::new();
        let instr = make_instr(0x2000, "ba,a", vec![label_op(0x3000)]);
        let result = lifter.lift(&instr).expect("lift");
        let efx = &result.effects;
        assert!(
            matches!(
                &efx[0],
                Effect::Branch {
                    condition: None,
                    ..
                }
            ),
            "ba,a should be unconditional"
        );
    }

    // â”€â”€ Conditional branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_be_zero_condition() {
        let efx = lift("be", vec![label_op(0x5000)]);
        assert_eq!(efx.len(), 2);
        match &efx[0] {
            Effect::Branch {
                condition: Some(IrExpr::Reg(r)),
                ..
            } => {
                assert_eq!(r, "icc_z");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_bne_not_zero_condition() {
        let efx = lift("bne", vec![label_op(0x5000)]);
        match &efx[0] {
            Effect::Branch {
                condition: Some(IrExpr::Not(inner)),
                ..
            } => {
                assert!(matches!(inner.as_ref(), IrExpr::Reg(r) if r == "icc_z"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_bl_signed_less_than() {
        let efx = lift("bl", vec![label_op(0x6000)]);
        match &efx[0] {
            Effect::Branch {
                condition: Some(IrExpr::Xor(n, v)),
                ..
            } => {
                assert!(matches!(n.as_ref(), IrExpr::Reg(r) if r == "icc_n"));
                assert!(matches!(v.as_ref(), IrExpr::Reg(r) if r == "icc_v"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_bge_signed_greater_equal() {
        let efx = lift("bge", vec![label_op(0x6000)]);
        // ~(N xor V)
        assert!(matches!(
            &efx[0],
            Effect::Branch {
                condition: Some(IrExpr::Not(_)),
                ..
            }
        ));
    }

    #[test]
    fn test_blu_unsigned_less_than_carry() {
        let efx = lift("blu", vec![label_op(0x7000)]);
        match &efx[0] {
            Effect::Branch {
                condition: Some(IrExpr::Reg(r)),
                ..
            } => {
                assert_eq!(r, "icc_c");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_bgeu_unsigned_greater_equal() {
        let efx = lift("bgeu", vec![label_op(0x7000)]);
        match &efx[0] {
            Effect::Branch {
                condition: Some(IrExpr::Not(inner)),
                ..
            } => {
                assert!(matches!(inner.as_ref(), IrExpr::Reg(r) if r == "icc_c"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_bn_never_branch() {
        let efx = lift("bn", vec![label_op(0x8000)]);
        match &efx[0] {
            Effect::Branch {
                condition: Some(IrExpr::Const(0)),
                ..
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ MUL / DIV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// `umul` and `smul` are WIDENING multiplies: the low 32 bits land in `rd`
    /// and the high 32 in `%y`. The high half is where the signedness shows.
    ///
    /// This test asserted `name == "mul_high_to_y"` — a name with no signedness
    /// in it — and there was no `smul` test at all, so nothing ever compared
    /// the two. They lifted identically.
    #[test]
    fn test_umul_product_and_y_intrinsic() {
        let efx = lift("umul", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        assert_eq!(efx.len(), 2);
        // The LOW half stays a plain `Mul` on purpose: the low 32 bits of a
        // product are the same signed or unsigned.
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Mul(..) } if reg == "o0"));
        assert!(
            matches!(&efx[1], Effect::Intrinsic { name, .. } if name == "umul_high_to_y"),
            "the high half must record that it is UNSIGNED, got {:?}",
            efx[1]
        );

        let signed = lift("smul", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        assert!(
            matches!(&signed[1], Effect::Intrinsic { name, .. } if name == "smul_high_to_y"),
            "the high half must record that it is SIGNED, got {:?}",
            signed[1]
        );
        assert_ne!(
            format!("{efx:?}"),
            format!("{signed:?}"),
            "umul and smul must not lift identically"
        );
    }

    #[test]
    fn test_udiv_emits_intrinsic() {
        let efx = lift("udiv", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "udiv"));
    }

    #[test]
    fn test_sdiv_emits_intrinsic() {
        let efx = lift("sdiv", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "sdiv"));
    }

    // â”€â”€ SAVE / RESTORE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_save_emits_intrinsic() {
        let efx = lift("save", vec![reg_op("sp"), reg_op("sp"), imm_op(-96)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "save"));
    }

    #[test]
    fn test_restore_emits_intrinsic() {
        let efx = lift("restore", vec![reg_op("g0"), reg_op("g0"), reg_op("g0")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "restore"));
    }

    // â”€â”€ TA / Trap â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ta_syscall() {
        let efx = lift("ta", vec![imm_op(0)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Syscall { .. }));
    }

    #[test]
    fn test_ta_syscall_nr_1() {
        let efx = lift("ta", vec![imm_op(1)]);
        assert!(matches!(
            &efx[0],
            Effect::Syscall {
                nr: IrExpr::Const(1)
            }
        ));
    }

    // â”€â”€ Memory barrier â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_stbar_intrinsic() {
        let efx = lift("stbar", vec![]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "stbar"));
    }

    #[test]
    fn test_membar_intrinsic() {
        let efx = lift("membar", vec![imm_op(0xf)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "membar"));
    }

    // â”€â”€ 64-bit SPARC V9 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sparc64_arch_name() {
        let lifter = SparcLifter::new_64();
        assert_eq!(lifter.arch_name(), "sparc64");
    }

    #[test]
    fn test_sparc32_arch_name() {
        let lifter = SparcLifter::new();
        assert_eq!(lifter.arch_name(), "sparc");
    }

    #[test]
    fn test_sparc64_ldx_8_byte_load() {
        let efx = lift64("ldx", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::MemRead { size: 8, .. }));
    }

    #[test]
    fn test_sparc64_stx_8_byte_store() {
        let efx = lift64("stx", vec![reg_op("o0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::MemWrite { size: 8, .. }));
    }

    #[test]
    fn test_sparc64_sllx() {
        let efx = lift64("sllx", vec![reg_op("o0"), reg_op("o1"), imm_op(32)]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(
            &efx[0],
            Effect::RegWrite {
                value: IrExpr::Shl(..),
                ..
            }
        ));
    }

    // â”€â”€ g0 constant folding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_g0_folded_to_zero_in_operand() {
        // OR %o0, %g0, %o1  â€” %g0 becomes Const(0).
        let efx = lift("or", vec![reg_op("o0"), reg_op("g0"), reg_op("o1")]);
        assert_eq!(efx.len(), 1);
        match &efx[0] {
            Effect::RegWrite {
                value: IrExpr::Or(l, _r),
                ..
            } => {
                assert!(matches!(l.as_ref(), IrExpr::Const(0)));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ LiftedInstr metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lifted_instr_has_correct_address() {
        let lifter = SparcLifter::new();
        let instr = make_instr(0xDEAD_0000, "nop", vec![]);
        let li = lifter.lift(&instr).expect("lift");
        assert_eq!(li.address, 0xDEAD_0000);
    }

    #[test]
    fn test_lifted_instr_level_is_llil() {
        let lifter = SparcLifter::new();
        let instr = make_instr(0, "add", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        let li = lifter.lift(&instr).expect("lift");
        assert_eq!(li.il_level, LiftLevel::Llil);
    }

    #[test]
    fn test_ir_text_non_empty_for_real_instruction() {
        let lifter = SparcLifter::new();
        let instr = make_instr(0, "add", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        let li = lifter.lift(&instr).expect("lift");
        assert!(!li.ir_text.is_empty());
    }

    #[test]
    fn test_ir_text_is_nop_for_nop() {
        let lifter = SparcLifter::new();
        let instr = make_instr(0, "nop", vec![]);
        let li = lifter.lift(&instr).expect("lift");
        assert_eq!(li.ir_text, "nop");
    }

    // â”€â”€ unknown mnemonic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_unknown_mnemonic_emits_intrinsic() {
        let efx = lift("notamnemonic", vec![]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::Intrinsic { name, .. } if name == "notamnemonic"));
    }

    // â”€â”€ jmpl ret pattern â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_jmpl_i7_plus_8_is_return() {
        // JMPL %g0, %i7  (base_idx=1 â†’ op[1] = %i7) â€” should be treated as ret.
        let lifter = SparcLifter::new();
        let instr = make_instr(0x1000, "jmpl", vec![reg_op("g0"), reg_op("i7"), imm_op(8)]);
        let result = lifter.lift(&instr).expect("lift");
        let has_return = result
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Return { .. }));
        assert!(has_return, "JMPL %i7+8, %g0 should produce a Return effect");
    }

    // â”€â”€ rd/wr state registers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_rd_y_into_register() {
        // RD %y, %o0
        let efx = lift("rd", vec![reg_op("y"), reg_op("o0")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, .. } if reg == "o0"));
    }

    #[test]
    fn test_wr_register_to_y() {
        // WR %o0, %g0, %y  â†’  y = o0 ^ g0
        let efx = lift("wr", vec![reg_op("o0"), reg_op("g0"), reg_op("y")]);
        assert_eq!(efx.len(), 1);
        assert!(matches!(&efx[0], Effect::RegWrite { reg, value: IrExpr::Xor(..) } if reg == "y"));
    }

    // â”€â”€ Addx carry-in â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_addx_includes_carry() {
        let efx = lift("addx", vec![reg_op("o0"), reg_op("o1"), reg_op("o2")]);
        assert_eq!(efx.len(), 1);
        // The value should be an Add of (Add + carry).
        match &efx[0] {
            Effect::RegWrite {
                value: IrExpr::Add(inner, carry),
                ..
            } => {
                assert!(matches!(inner.as_ref(), IrExpr::Add(..)));
                assert!(matches!(carry.as_ref(), IrExpr::Reg(r) if r == "icc_c"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // â”€â”€ Norm reg aliases â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_norm_reg_sp_aliases() {
        assert_eq!(SparcLifter::norm_reg("%o6"), "sp");
        assert_eq!(SparcLifter::norm_reg("o6"), "sp");
        assert_eq!(SparcLifter::norm_reg("%sp"), "sp");
    }

    #[test]
    fn test_norm_reg_fp_aliases() {
        assert_eq!(SparcLifter::norm_reg("%i6"), "fp");
        assert_eq!(SparcLifter::norm_reg("i6"), "fp");
        assert_eq!(SparcLifter::norm_reg("%fp"), "fp");
    }

    #[test]
    fn test_norm_reg_strips_percent() {
        assert_eq!(SparcLifter::norm_reg("%g1"), "g1");
        assert_eq!(SparcLifter::norm_reg("%l7"), "l7");
    }

    // â”€â”€ ptr_size â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ptr_size_32() {
        let l = SparcLifter::new();
        assert_eq!(l.ptr_size(), 4);
    }

    #[test]
    fn test_ptr_size_64() {
        let l = SparcLifter::new_64();
        assert_eq!(l.ptr_size(), 8);
    }
}
