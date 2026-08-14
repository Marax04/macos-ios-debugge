//! Motorola 68000 (m68k) LLIL lifter.
//!
//! Implements a mnemonic-driven LLIL lifter for the Motorola 68000 family of
//! processors, covering the core 68000 ISA as well as 68020 extensions.
//!
//! # Register file
//! - Data registers: `d0`Ã¢â‚¬â€œ`d7` (32-bit general purpose)
//! - Address registers: `a0`Ã¢â‚¬â€œ`a6`, `a7` (also aliased as `sp`)
//! - `pc` Ã¢â‚¬â€ program counter
//! - `sr` Ã¢â‚¬â€ status register (condition codes in the low byte: N, Z, V, C, X)
//!
//! # Size suffixes
//! The m68k assembler notation appends a size qualifier to most mnemonics:
//! - `.b` Ã¢â‚¬â€ byte (1 byte)
//! - `.w` Ã¢â‚¬â€ word (2 bytes) Ã¢â‚¬â€ default when omitted
//! - `.l` Ã¢â‚¬â€ longword (4 bytes)
//! - `.s` Ã¢â‚¬â€ short branch displacement (2 bytes)
//!
//! `strip_size_suffix` removes these before mnemonic matching.
//!
//! # Design notes
//! * Every instruction produces a `Vec<Effect>` through `lift_effects()`.
//! * Size information is inferred from the suffix character when available.
//! * Operand parsing follows the standard m68k addressing modes.
//! * Branch conditions model the SR flags (`zf`, `nf`, `cf`, `vf`, `xf`).

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::{Instruction, Operand};
use std::fmt;

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// M68kLifter
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// LLIL lifter for the Motorola 68000 processor family.
///
/// Supports the base 68000 ISA (used by classic Macintosh, Amiga, Atari ST,
/// Sega Genesis, and embedded systems) as well as the 68020 superset.
///
/// # Examples
///
/// ```
/// use rustre_il_lift::m68k_lifter::M68kLifter;
///
/// let lifter = M68kLifter::new();        // 68000
/// let lifter020 = M68kLifter::new_68020(); // 68020
/// ```
#[derive(Debug, Clone)]
pub struct M68kLifter {
    /// Human-readable CPU variant string (e.g. `"68000"`, `"68020"`).
    pub cpu_type: &'static str,
}

impl M68kLifter {
    /// Create a standard Motorola 68000 lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { cpu_type: "68000" }
    }

    /// Create a Motorola 68020 lifter (superset of 68000).
    #[must_use]
    pub const fn new_68020() -> Self {
        Self { cpu_type: "68020" }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Size helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Return the byte-count for the size suffix character, defaulting to 4
    /// (longword) when the suffix is unrecognised.
    ///
    /// | suffix | bytes |
    /// |--------|-------|
    /// | `b`    | 1     |
    /// | `w`    | 2     |
    /// | `l`    | 4     |
    /// | `s`    | 2     |
    #[must_use]
    pub const fn size_char_to_bytes(c: char) -> u8 {
        match c {
            'b' => 1,
            'w' | 's' => 2,
            _ => 4,
        }
    }

    /// Extract the size suffix from a mnemonic and return the corresponding byte
    /// count.  Returns `4` (longword) when no recognised suffix is present.
    #[must_use]
    pub fn infer_size(mnem: &str) -> u8 {
        match mnem.rsplit_once('.') {
            Some((_, suf)) if !suf.is_empty() => {
                Self::size_char_to_bytes(suf.chars().next().unwrap_or('l'))
            }
            _ => 4,
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Operand helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Convert a structured [`Operand`] to an [`IrExpr`], without dereferencing
    /// memory Ã¢â‚¬â€ callers must wrap in `IrExpr::Deref` when a load is required.
    fn operand_to_expr(op: &Operand) -> IrExpr {
        match op {
            Operand::Register(r) => IrExpr::Reg(r.name.clone()),
            Operand::Immediate(v) => IrExpr::Const((*v).cast_unsigned()),
            Operand::UImmediate(v) => IrExpr::Const(*v),
            Operand::Label(addr) => IrExpr::Const(*addr),
            Operand::Memory {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                // EA = base + index * scale + disp
                let mut expr: Option<IrExpr> = base.as_ref().map(|r| IrExpr::Reg(r.name.clone()));

                if let Some(idx) = index {
                    let idx_expr = if *scale > 1 {
                        IrExpr::Mul(
                            Box::new(IrExpr::Reg(idx.name.clone())),
                            Box::new(IrExpr::Const(u64::from(*scale))),
                        )
                    } else {
                        IrExpr::Reg(idx.name.clone())
                    };
                    expr = Some(match expr {
                        Some(e) => IrExpr::Add(Box::new(e), Box::new(idx_expr)),
                        None => idx_expr,
                    });
                }

                if *disp != 0 {
                    let disp_abs = IrExpr::Const((*disp).unsigned_abs());
                    expr = Some(match expr {
                        Some(e) if *disp < 0 => IrExpr::Sub(Box::new(e), Box::new(disp_abs)),
                        Some(e) => IrExpr::Add(Box::new(e), Box::new(disp_abs)),
                        None => IrExpr::Const((*disp).cast_unsigned()),
                    });
                }

                expr.unwrap_or(IrExpr::Const(0))
            }
            Operand::FpReg(n) => IrExpr::Reg(format!("fp{n}")),
            Operand::VecReg(n) => IrExpr::Reg(format!("v{n}")),
            Operand::Segment(_, inner) => Self::operand_to_expr(inner),
        }
    }

    /// Get operand `i` as an expression, or `IrExpr::Undef` when out of range.
    fn op_expr(instr: &Instruction, i: usize) -> IrExpr {
        instr
            .operand_list
            .get(i)
            .map_or(IrExpr::Undef, Self::operand_to_expr)
    }

    /// Get the effective-address expression for operand `i`, dereferencing it if
    /// it is a memory operand.  For register operands, returns the register
    /// expression directly (no dereference needed).
    fn op_load(instr: &Instruction, i: usize, size: u8) -> IrExpr {
        let Some(op) = instr.operand_list.get(i) else { return IrExpr::Undef };
        match op {
            Operand::Register(_) => Self::operand_to_expr(op),
            Operand::Immediate(v) => IrExpr::Const((*v).cast_unsigned()),
            Operand::UImmediate(v) => IrExpr::Const(*v),
            Operand::Label(a) => IrExpr::Const(*a),
            _ => {
                // Memory operand: compute EA and dereference.
                let ea = Self::operand_to_expr(op);
                IrExpr::Deref(Box::new(ea), size)
            }
        }
    }

    /// Attempt to extract a destination register name from operand `i`.
    fn dest_reg_name(instr: &Instruction, i: usize) -> Option<String> {
        instr
            .operand_list
            .get(i)
            .and_then(|op| op.as_register())
            .map(|r| r.name.clone())
    }

    /// Resolve a branch target: Label > Immediate (absolute if Ã¢â€°Â¥ 0x1000,
    /// else PC-relative from the end of the instruction).
    fn branch_target(instr: &Instruction) -> IrExpr {
        let fallthrough = instr.address.0.wrapping_add(instr.size as u64);
        if let Some(op) = instr.operand_list.first() {
            match op {
                Operand::Label(addr) => return IrExpr::Const(*addr),
                Operand::Immediate(v) => {
                    let target = if *v >= 0x1000 {
                        (*v).cast_unsigned()
                    } else {
                        fallthrough.wrapping_add((*v).cast_unsigned())
                    };
                    return IrExpr::Const(target);
                }
                Operand::UImmediate(v) => {
                    let target = if *v >= 0x1000 {
                        *v
                    } else {
                        fallthrough.wrapping_add(*v)
                    };
                    return IrExpr::Const(target);
                }
                Operand::Register(r) => return IrExpr::Reg(r.name.clone()),
                _ => {}
            }
        }
        IrExpr::Const(fallthrough)
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Main dispatch Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Produce effects for a single m68k instruction.
    fn lift_effects_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

            Some(match base {
            // NOP: matched explicitly with an empty effect list (not a fallback).
            "nop" => vec![],

            //Ã¢â€â‚¬Ã¢â€â‚¬ NOP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

            // Ã¢â€â‚¬Ã¢â€â‚¬ MOVE family Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            //
            // MOVE  <src>, <dst>  Ã¢â‚¬â€ general-purpose data move
            // MOVEA <src>, An    Ã¢â‚¬â€ move to address register (no flag update)
            // MOVEQ #imm, Dn     Ã¢â‚¬â€ move quick (8-bit sign-extended immediate)
            "move" | "movea" => Self::lift_move(instr, size),

            "moveq" => {
                // MOVEQ #imm8, Dn Ã¢â‚¬â€ sign-extend 8-bit immediate to 32 bits
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_expr(instr, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: src,
                }]
            }

            "movem" => Self::lift_movem(instr, size),

            "movep" => {
                // MOVEP Ã¢â‚¬â€ move peripheral (byte/word from/to alternate bytes)
                // Modelled as an intrinsic because the strided memory access is
                // not directly representable in our IR.
                vec![Effect::Intrinsic {
                    name: "m68k_movep".to_string(),
                    args: vec![Self::op_expr(instr, 0), Self::op_expr(instr, 1)],
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ LEA / PEA Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "lea" => {
                // LEA <ea>, An Ã¢â‚¬â€ load effective address
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "a0".to_string());
                let ea = Self::operand_to_expr(
                    instr.operand_list.first().unwrap_or(&Operand::UImmediate(0)),
                );
                vec![Effect::RegWrite {
                    reg: dst,
                    value: ea,
                }]
            }

            "pea" => {
                // PEA <ea> Ã¢â‚¬â€ push effective address on stack
                // sp = sp - 4; [sp] = ea
                let ea = Self::operand_to_expr(
                    instr.operand_list.first().unwrap_or(&Operand::UImmediate(0)),
                );
                let sp_minus_4 = IrExpr::Sub(
                    Box::new(IrExpr::Reg("a7".to_string())),
                    Box::new(IrExpr::Const(4)),
                );
                vec![
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: sp_minus_4.clone(),
                    },
                    Effect::MemWrite {
                        addr: sp_minus_4,
                        value: ea,
                        size: 4,
                    },
                ]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Arithmetic Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "add" | "adda" | "addi" | "addq" => Self::lift_add(instr, size),

            "addx" => {
                // ADDX Dx, Dy  /  ADDX -(Ax), -(Ay)  Ã¢â‚¬â€ add with extend (X flag)
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                let dst_expr = Self::op_load(instr, 1, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Add(
                        Box::new(IrExpr::Add(Box::new(dst_expr), Box::new(src))),
                        Box::new(IrExpr::Reg("xf".to_string())),
                    ),
                }]
            }

            "sub" | "suba" | "subi" | "subq" => Self::lift_sub(instr, size),

            "subx" => {
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                let dst_expr = Self::op_load(instr, 1, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(
                        Box::new(IrExpr::Sub(Box::new(dst_expr), Box::new(src))),
                        Box::new(IrExpr::Reg("xf".to_string())),
                    ),
                }]
            }
                _ => return None,
            })
    }
    fn lift_effects_b_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

                Some(match base {
            "neg" => {
                // NEG <ea> Ã¢â‚¬â€ negate (0 - ea)
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(src)),
                }]
            }
            "negx" => {
                // NEGX <ea> Ã¢â‚¬â€ negate with extend: 0 - ea - X
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(
                        Box::new(IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(src))),
                        Box::new(IrExpr::Reg("xf".to_string())),
                    ),
                }]
            }
            // MULS and MULU are WIDENING multiplies (16x16 -> 32), so the
            // signedness genuinely changes the result — unlike a same-width
            // multiply, whose low half is identical either way.
            //
            // They used to share this arm and lift to a plain `IrExpr::Mul`,
            // which destroyed the distinction AND the widening: two different
            // instructions, one confident and wrong expression.
            //
            // The IR has no widening or signed/unsigned multiply node, so the
            // operation itself cannot be spelled out — but the DISTINCTION can
            // survive, which is the part that matters. This follows the shape
            // `divs`/`divu` in the very next arm already uses correctly:
            // an intrinsic carrying the base mnemonic in its name.
            "muls" | "mulu" | "mul" => {
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let lhs = Self::op_load(instr, 1, size);
                let rhs = Self::op_load(instr, 0, size);
                vec![
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: format!("m68k_{base}"),
                        args: vec![lhs, rhs],
                    },
                ]
            }
            "divs" | "divu" | "div" => {
                // Division: model as intrinsic (quotient/remainder pair)
                vec![Effect::Intrinsic {
                    name: format!("m68k_{base}"),
                    args: vec![Self::op_load(instr, 1, size), Self::op_load(instr, 0, size)],
                }]
            }
            "and" | "andi" => {
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let lhs = Self::op_load(instr, 1, size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(lhs), Box::new(rhs)),
                }]
            }
            "or" | "ori" => {
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let lhs = Self::op_load(instr, 1, size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(lhs), Box::new(rhs)),
                }]
            }
            "eor" | "eori" => {
                let dst = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d0".to_string());
                let lhs = Self::op_load(instr, 1, size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Xor(Box::new(lhs), Box::new(rhs)),
                }]
            }
            "not" => {
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Not(Box::new(src)),
                }]
            }
            "lsl" | "asl" => {
                let dst = Self::dest_reg_name(instr, 1)
                    .or_else(|| Self::dest_reg_name(instr, 0))
                    .unwrap_or_else(|| "d0".to_string());
                let (lhs, rhs) = Self::shift_operands(instr, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shl(Box::new(lhs), Box::new(rhs)),
                }]
            }
                    _ => return None,
                })
    }

    fn lift_effects_b_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

                Some(match base {
            "lsr" | "asr" => {
                let dst = Self::dest_reg_name(instr, 1)
                    .or_else(|| Self::dest_reg_name(instr, 0))
                    .unwrap_or_else(|| "d0".to_string());
                let (lhs, rhs) = Self::shift_operands(instr, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shr(Box::new(lhs), Box::new(rhs)),
                }]
            }
            "rol" | "ror" | "roxl" | "roxr" => {
                // Rotates are not directly representable in our IR Ã¢â‚¬â€ model as intrinsics.
                let name = format!("m68k_{base}");
                let (lhs, rhs) = Self::shift_operands(instr, size);
                vec![Effect::Intrinsic {
                    name,
                    args: vec![lhs, rhs],
                }]
            }
                _ => return None,
                })
    }

    fn lift_effects_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let _size = Self::infer_size(raw_mnem);
        let _base = strip_size_suffix(raw_mnem);

        if let Some(r) = Self::lift_effects_b_a(instr) {
            return Some(r);
        }
        Self::lift_effects_b_b(instr)
    }
    fn lift_effects_c(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

            Some(match base {

            //Ã¢â€â‚¬Ã¢â€â‚¬ Bit operations Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "btst" => {
                vec![Effect::Intrinsic {
                    name: "m68k_btst".to_string(),
                    args: vec![Self::op_load(instr, 0, size), Self::op_load(instr, 1, size)],
                }]
            }
            "bset" | "bclr" | "bchg" => {
                vec![Effect::Intrinsic {
                    name: format!("m68k_{base}"),
                    args: vec![Self::op_load(instr, 0, size), Self::op_load(instr, 1, size)],
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Clear Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "clr" => {
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Const(0),
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Compare / Test Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "cmp" | "cmpa" | "cmpi" | "cmpm" => {
                // CMP sets flags only Ã¢â‚¬â€ model as intrinsic
                vec![Effect::Intrinsic {
                    name: "m68k_cmp".to_string(),
                    args: vec![Self::op_load(instr, 0, size), Self::op_load(instr, 1, size)],
                }]
            }

            "tst" => {
                vec![Effect::Intrinsic {
                    name: "m68k_tst".to_string(),
                    args: vec![Self::op_load(instr, 0, size)],
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Unconditional branches Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "bra" | "jmp" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: None,
            }],

            // Ã¢â€â‚¬Ã¢â€â‚¬ Conditional branches (Bcc) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "beq" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("zf".to_string())),
            }],
            "bne" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
            }],
            "bcs" | "blo" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("cf".to_string())),
            }],
            "bcc" | "bhs" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("cf".to_string())))),
            }],
            "bmi" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("nf".to_string())),
            }],
                _ => return None,
            })
    }
    fn lift_effects_d(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let _size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

            Some(match base {
            "bpl" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("nf".to_string())))),
            }],
            "bvs" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Reg("vf".to_string())),
            }],
            "bvc" => vec![Effect::Branch {
                target: Self::branch_target(instr),
                condition: Some(IrExpr::Not(Box::new(IrExpr::Reg("vf".to_string())))),
            }],
            "bhi" => {
                // BHI: C=0 AND Z=0
                vec![Effect::Branch {
                    target: Self::branch_target(instr),
                    condition: Some(IrExpr::And(
                        Box::new(IrExpr::Not(Box::new(IrExpr::Reg("cf".to_string())))),
                        Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                    )),
                }]
            }
            "bls" => {
                // BLS: C=1 OR Z=1
                vec![Effect::Branch {
                    target: Self::branch_target(instr),
                    condition: Some(IrExpr::Or(
                        Box::new(IrExpr::Reg("cf".to_string())),
                        Box::new(IrExpr::Reg("zf".to_string())),
                    )),
                }]
            }
            "bge" => {
                // BGE: N XOR V = 0  Ã¢â€ â€™  NOT(N XOR V)
                vec![Effect::Branch {
                    target: Self::branch_target(instr),
                    condition: Some(IrExpr::Not(Box::new(IrExpr::Xor(
                        Box::new(IrExpr::Reg("nf".to_string())),
                        Box::new(IrExpr::Reg("vf".to_string())),
                    )))),
                }]
            }
            "blt" => {
                // BLT: N XOR V = 1
                vec![Effect::Branch {
                    target: Self::branch_target(instr),
                    condition: Some(IrExpr::Xor(
                        Box::new(IrExpr::Reg("nf".to_string())),
                        Box::new(IrExpr::Reg("vf".to_string())),
                    )),
                }]
            }
            "bgt" => {
                // BGT: Z=0 AND (N XOR V)=0
                vec![Effect::Branch {
                    target: Self::branch_target(instr),
                    condition: Some(IrExpr::And(
                        Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                        Box::new(IrExpr::Not(Box::new(IrExpr::Xor(
                            Box::new(IrExpr::Reg("nf".to_string())),
                            Box::new(IrExpr::Reg("vf".to_string())),
                        )))),
                    )),
                }]
            }
            "ble" => {
                // BLE: Z=1 OR (N XOR V)=1
                vec![Effect::Branch {
                    target: Self::branch_target(instr),
                    condition: Some(IrExpr::Or(
                        Box::new(IrExpr::Reg("zf".to_string())),
                        Box::new(IrExpr::Xor(
                            Box::new(IrExpr::Reg("nf".to_string())),
                            Box::new(IrExpr::Reg("vf".to_string())),
                        )),
                    )),
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Subroutine calls / returns Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "bsr" => {
                // BSR: push PC then branch (= call in our IR)
                vec![Effect::Call {
                    target: Self::branch_target(instr),
                }]
            }

            "jsr" => {
                vec![Effect::Call {
                    target: Self::branch_target(instr),
                }]
            }
                _ => return None,
            })
    }
    fn lift_effects_e_a(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

                Some(match base {
            "rts" => vec![Effect::Return { value: None }],
            "rtr" => {
                // RTR: restore CCR from stack, then RTS
                vec![Effect::Return { value: None }]
            }
            "rte" => {
                // RTE: return from exception (restores SR and PC)
                vec![Effect::Return { value: None }]
            }
            "link" => {
                // LINK An, #disp Ã¢â‚¬â€ save An, set An = SP, allocate frame
                // sp = sp - 4; [sp] = An; An = sp; sp = sp + disp (disp is negative)
                let an = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "a6".to_string());
                let disp = Self::op_expr(instr, 1);
                let sp_after_push = IrExpr::Sub(
                    Box::new(IrExpr::Reg("a7".to_string())),
                    Box::new(IrExpr::Const(4)),
                );
                vec![
                    // [sp - 4] = An
                    Effect::MemWrite {
                        addr: sp_after_push.clone(),
                        value: IrExpr::Reg(an.clone()),
                        size: 4,
                    },
                    // sp = sp - 4
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: sp_after_push,
                    },
                    // An = sp (new frame pointer)
                    Effect::RegWrite {
                        reg: an,
                        value: IrExpr::Reg("a7".to_string()),
                    },
                    // sp = sp + disp (allocate locals)
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: IrExpr::Add(Box::new(IrExpr::Reg("a7".to_string())), Box::new(disp)),
                    },
                ]
            }
            "unlk" => {
                // UNLK An Ã¢â‚¬â€ sp = An; pop An from stack
                let an = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "a6".to_string());
                vec![
                    // sp = An
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: IrExpr::Reg(an.clone()),
                    },
                    // An = [sp]; sp = sp + 4
                    Effect::MemRead {
                        addr: IrExpr::Reg("a7".to_string()),
                        dest: an,
                        size: 4,
                    },
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: IrExpr::Add(
                            Box::new(IrExpr::Reg("a7".to_string())),
                            Box::new(IrExpr::Const(4)),
                        ),
                    },
                ]
            }
            "push" => {
                let src = Self::op_load(instr, 0, size);
                let sp_new = IrExpr::Sub(
                    Box::new(IrExpr::Reg("a7".to_string())),
                    Box::new(IrExpr::Const(u64::from(size))),
                );
                vec![
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: sp_new.clone(),
                    },
                    Effect::MemWrite {
                        addr: sp_new,
                        value: src,
                        size,
                    },
                ]
            }
                    _ => return None,
                })
    }

    fn lift_effects_e_b(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

                Some(match base {
            "pull" | "pop" => {
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let effects = vec![
                    Effect::MemRead {
                        addr: IrExpr::Reg("a7".to_string()),
                        dest: dst,
                        size,
                    },
                    Effect::RegWrite {
                        reg: "a7".to_string(),
                        value: IrExpr::Add(
                            Box::new(IrExpr::Reg("a7".to_string())),
                            Box::new(IrExpr::Const(u64::from(size))),
                        ),
                    },
                ];
                effects
            }
            "trap" => {
                // TRAP #n Ã¢â‚¬â€ invoke trap vector; d0 conventionally holds syscall nr
                vec![Effect::Syscall {
                    nr: IrExpr::Reg("d0".to_string()),
                }]
            }
            "trapv" => {
                // TRAPV Ã¢â‚¬â€ trap on overflow
                vec![Effect::Intrinsic {
                    name: "m68k_trapv".to_string(),
                    args: vec![IrExpr::Reg("vf".to_string())],
                }]
            }
            "exg" => {
                // EXG Rx, Ry Ã¢â‚¬â€ exchange two registers (atomic swap)
                let rx = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let ry = Self::dest_reg_name(instr, 1).unwrap_or_else(|| "d1".to_string());
                vec![
                    Effect::RegWrite {
                        reg: rx.clone(),
                        value: IrExpr::Reg(ry.clone()),
                    },
                    Effect::RegWrite {
                        reg: ry,
                        value: IrExpr::Reg(rx),
                    },
                ]
            }
            "swap" => {
                // SWAP Dn Ã¢â‚¬â€ exchange upper/lower 16-bit halves of Dn
                // = (Dn >> 16) | (Dn << 16)  (both masked to 32 bits)
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let src = IrExpr::Reg(dst.clone());
                let hi = IrExpr::Shr(Box::new(src.clone()), Box::new(IrExpr::Const(16)));
                let lo = IrExpr::Shl(Box::new(src), Box::new(IrExpr::Const(16)));
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(lo), Box::new(hi)),
                }]
            }
                _ => return None,
                })
    }

    fn lift_effects_e(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let _size = Self::infer_size(raw_mnem);
        let _base = strip_size_suffix(raw_mnem);

        if let Some(r) = Self::lift_effects_e_a(instr) {
            return Some(r);
        }
        Self::lift_effects_e_b(instr)
    }
    fn lift_effects_f(instr: &Instruction) -> Option<Vec<Effect>> {
        let raw_mnem = instr.mnemonic.as_str();
        let size = Self::infer_size(raw_mnem);
        let base = strip_size_suffix(raw_mnem);

            Some(match base {

            "ext" | "extb" => {
                // EXT.W Dn Ã¢â‚¬â€ sign-extend byte Ã¢â€ â€™ word (modelled as intrinsic)
                // EXT.L Dn Ã¢â‚¬â€ sign-extend word Ã¢â€ â€™ long
                // EXTB.L Dn (68020) Ã¢â‚¬â€ sign-extend byte Ã¢â€ â€™ long
                vec![Effect::Intrinsic {
                    name: format!("m68k_{base}"),
                    args: vec![Self::op_load(instr, 0, size)],
                }]
            }

            "abcd" | "sbcd" | "nbcd" => {
                // BCD arithmetic Ã¢â‚¬â€ model as intrinsics
                vec![Effect::Intrinsic {
                    name: format!("m68k_{base}"),
                    args: vec![Self::op_load(instr, 0, size), Self::op_load(instr, 1, size)],
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ DBcc (decrement and branch) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            "dbra" | "dbf" => {
                // DBcc Dn, <label> Ã¢â‚¬â€ post-decrement loop
                // Dn = Dn - 1; if Dn != -1 goto label
                let reg = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let decremented = IrExpr::Sub(
                    Box::new(IrExpr::Reg(reg.clone())),
                    Box::new(IrExpr::Const(1)),
                );
                let branch_target = Self::branch_target(instr);
                vec![
                    Effect::RegWrite {
                        reg,
                        value: decremented.clone(),
                    },
                    Effect::Branch {
                        target: branch_target,
                        condition: Some(IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(
                            IrExpr::Add(Box::new(decremented), Box::new(IrExpr::Const(1))),
                        ))))),
                    },
                ]
            }

            // Generic DBcc Ã¢â‚¬â€ decrement and branch if condition false
            s if s.starts_with("db") => {
                let reg = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let decremented = IrExpr::Sub(
                    Box::new(IrExpr::Reg(reg.clone())),
                    Box::new(IrExpr::Const(1)),
                );
                vec![
                    Effect::RegWrite {
                        reg,
                        value: decremented,
                    },
                    Effect::Branch {
                        target: Self::branch_target(instr),
                        condition: Some(IrExpr::Undef), // condition varies by Bcc type
                    },
                ]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Scc (set byte on condition) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            s if s.starts_with('s') && s.len() <= 4 => {
                // Scc <ea> Ã¢â‚¬â€ set byte to 0xFF or 0x00 based on condition
                vec![Effect::Intrinsic {
                    name: format!("m68k_{base}"),
                    args: vec![Self::op_load(instr, 0, 1)],
                }]
            }

            // Ã¢â€â‚¬Ã¢â€â‚¬ Fallback Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
            other => {
                vec![Effect::Intrinsic {
                    name: format!("m68k_{other}"),
                    args: (0..instr.operand_list.len())
                        .map(|i| Self::op_load(instr, i, size))
                        .collect(),
                }]
            }
            })
    }

    /// Dispatch, then attach the address-register updates implied by the
    /// auto-increment/decrement addressing modes.
    ///
    /// Wired at this single tail point so EVERY m68k instruction gets them
    /// rather than one handler at a time: `move`, `movem`, `addx` and the rest
    /// all share the modes, and a per-handler fix would have covered exactly the
    /// one whose output I happened to be reading.
    fn lift_effects(instr: &Instruction) -> Vec<Effect> {
        let size = Self::infer_size(instr.mnemonic.as_str());
        let (pre, post) = Self::auto_adjust_effects(instr, size);
        if pre.is_empty() && post.is_empty() {
            return Self::lift_effects_dispatch(instr);
        }
        let mut out = pre;
        out.extend(Self::lift_effects_dispatch(instr));
        out.extend(post);
        out
    }

    fn lift_effects_dispatch(instr: &Instruction) -> Vec<Effect> {
        let raw_mnem = instr.mnemonic.as_str();
        let _size = Self::infer_size(raw_mnem);
        let _base = strip_size_suffix(raw_mnem);

        if let Some(r) = Self::lift_effects_a(instr) {
            return r;
        }
        if let Some(r) = Self::lift_effects_b(instr) {
            return r;
        }
        if let Some(r) = Self::lift_effects_c(instr) {
            return r;
        }
        if let Some(r) = Self::lift_effects_d(instr) {
            return r;
        }
        if let Some(r) = Self::lift_effects_e(instr) {
            return r;
        }
        // lift_effects_f is the final fallback and always matches (its wildcard
        // arm builds a generic Intrinsic effect), so it always returns Some(_).
        Self::lift_effects_f(instr).unwrap_or_default()
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Sub-handlers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Lift a MOVE or MOVEA instruction.
    fn lift_move(instr: &Instruction, size: u8) -> Vec<Effect> {
        // MOVE <src>, <dst>
        // src is operand 0; dst is operand 1
        let src_op = instr.operand_list.first();
        let dst_op = instr.operand_list.get(1);

        let src_expr: IrExpr = match src_op {
            Some(Operand::Register(r)) => IrExpr::Reg(r.name.clone()),
            Some(Operand::Immediate(v)) => IrExpr::Const((*v).cast_unsigned()),
            Some(Operand::UImmediate(v)) => IrExpr::Const(*v),
            Some(Operand::Label(a)) => IrExpr::Const(*a),
            Some(op) => {
                let ea = Self::operand_to_expr(op);
                IrExpr::Deref(Box::new(ea), size)
            }
            None => IrExpr::Undef,
        };

        match dst_op {
            Some(Operand::Register(r)) => {
                vec![Effect::RegWrite {
                    reg: r.name.clone(),
                    value: src_expr,
                }]
            }
            Some(op) => {
                let ea = Self::operand_to_expr(op);
                vec![Effect::MemWrite {
                    addr: ea,
                    value: src_expr,
                    size,
                }]
            }
            None => {
                vec![Effect::RegWrite {
                    reg: "d0".to_string(),
                    value: src_expr,
                }]
            }
        }
    }

    /// Lift MOVEM (move multiple registers).
    ///
    /// Without disassembler-provided register lists this lifter conservatively
    /// models MOVEM as an intrinsic, capturing the base address operand.
    /// Find the register named inside an auto-increment / auto-decrement operand.
    ///
    /// Returns the lower-cased register names appearing as `-(An)` (predecrement)
    /// and `(An)+` (postincrement) in the operand text. Hand-parsed because this
    /// crate has no regex dependency and the grammar is trivial.
    fn auto_adjust_regs(operands: &str) -> (Vec<String>, Vec<String>) {
        let bytes: Vec<char> = operands.chars().collect();
        let mut pre = Vec::new();
        let mut post = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == '(' {
                // Find the matching close paren.
                if let Some(close) = (i + 1..bytes.len()).find(|&j| bytes[j] == ')') {
                    let inner: String = bytes[i + 1..close].iter().collect();
                    let name = inner.trim().to_ascii_lowercase();
                    // A register operand only; `(4,a0)` and the like are not
                    // auto-adjusting forms.
                    let simple = !name.is_empty()
                        && !name.contains(',')
                        && name.chars().all(|c| c.is_ascii_alphanumeric());
                    if simple {
                        // Predecrement: the '-' immediately precedes the '('.
                        let preceded_by_minus = bytes[..i]
                            .iter()
                            .rev()
                            .find(|c| !c.is_whitespace())
                            .is_some_and(|c| *c == '-');
                        let followed_by_plus = bytes
                            .get(close + 1)
                            .is_some_and(|c| *c == '+');
                        if preceded_by_minus {
                            pre.push(name);
                        } else if followed_by_plus {
                            post.push(name);
                        }
                    }
                    i = close + 1;
                    continue;
                }
            }
            i += 1;
        }
        (pre, post)
    }

    /// Register effects of the m68k AUTO-INCREMENT / AUTO-DECREMENT addressing
    /// modes, `(An)+` and `-(An)`.
    ///
    /// # The defect this closes
    ///
    /// `operand_to_expr` builds `base + index * scale + disp` and discards the
    /// rest of the operand with `..`. The structured `Operand::Memory` in
    /// `rustre-core` has no field for these modes at all, so `-(a7)`, `(a7)+`
    /// and a plain `(a7)` all collapsed to the identical expression
    /// `Reg("a7")`. Two separate losses followed:
    ///
    /// 1. **The address register was never updated.** After
    ///    `move.l d0, -(a7)` the IL claimed `a7` still held its old value, so
    ///    every later stack offset computed from it was wrong — the same class
    ///    as the missing register writes closed by the arch-x86 register-effect
    ///    oracle, where an unmodelled write makes a consumer believe the old
    ///    value survives.
    /// 2. **The three modes were indistinguishable.** Opaque is acceptable when
    ///    a fact cannot be expressed; opaque AND indistinguishable is not,
    ///    because nothing downstream can tell that anything was lost.
    ///
    /// The mode is absent from the structured operand but present in the operand
    /// TEXT, so it is recovered from the text — the same technique
    /// `Arm32Lifter::has_writeback` already uses for the `!` writeback suffix.
    ///
    /// Returns `(pre, post)`: predecrement effects, which the architecture
    /// applies BEFORE the access, and postincrement effects, applied AFTER. The
    /// caller must keep them on the correct side of the access; folding both
    /// into one list would be a third way to lose the distinction.
    fn auto_adjust_effects(instr: &Instruction, size: u8) -> (Vec<Effect>, Vec<Effect>) {
        let (pre_regs, post_regs) = Self::auto_adjust_regs(&instr.operands);
        let step = u64::from(size.max(1));
        let sub = |reg: String| Effect::RegWrite {
            value: IrExpr::Sub(
                Box::new(IrExpr::Reg(reg.clone())),
                Box::new(IrExpr::Const(step)),
            ),
            reg,
        };
        let add = |reg: String| Effect::RegWrite {
            value: IrExpr::Add(
                Box::new(IrExpr::Reg(reg.clone())),
                Box::new(IrExpr::Const(step)),
            ),
            reg,
        };
        (
            pre_regs.into_iter().map(sub).collect(),
            post_regs.into_iter().map(add).collect(),
        )
    }

    fn lift_movem(instr: &Instruction, size: u8) -> Vec<Effect> {
        // A fully-faithful MOVEM lift would require the register list bitmask
        // which is encoded in the instruction word itself and not always decoded
        // by generic disassemblers into our Operand model.  We fall back to an
        // intrinsic that records the base EA so analysis passes can at least
        // see that memory is accessed.
        let ea = Self::op_expr(instr, 0);
        // The register list is genuinely unavailable here, so the transfer stays
        // opaque. The ADDRESSING MODE, however, is not unavailable: name the
        // intrinsic after it so `movem.l d0-d7, -(sp)` and `movem.l (sp)+, d0-d7`
        // stop producing byte-identical IR. An opaque effect is acceptable; an
        // opaque effect that erases which direction memory was walked is not.
        let (pre, post) = Self::auto_adjust_regs(&instr.operands);
        let name = if pre.is_empty() {
            if post.is_empty() {
                "m68k_movem"
            } else {
                "m68k_movem_postinc"
            }
        } else {
            "m68k_movem_predec"
        };
        vec![Effect::Intrinsic {
            name: name.to_string(),
            args: vec![ea, IrExpr::Const(u64::from(size))],
        }]
    }

    /// Lift ADD / ADDA / ADDI / ADDQ.
    fn lift_add(instr: &Instruction, size: u8) -> Vec<Effect> {
        // ADDI / ADDQ: src (imm) is op0, dst is op1
        // ADD Dn, <ea>: src (Dn) is op0, dst (<ea>) is op1
        // ADD <ea>, Dn: src (<ea>) is op0, dst (Dn) is op1
        let dst_op = instr.operand_list.get(1);
        match dst_op {
            Some(Operand::Register(r)) => {
                let dst = r.name.clone();
                let lhs = Self::op_load(instr, 1, size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Add(Box::new(lhs), Box::new(rhs)),
                }]
            }
            Some(op) => {
                let ea = Self::operand_to_expr(op);
                let lhs = IrExpr::Deref(Box::new(ea.clone()), size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::MemWrite {
                    addr: ea,
                    value: IrExpr::Add(Box::new(lhs), Box::new(rhs)),
                    size,
                }]
            }
            None => {
                // Fallback: single-operand form (some assemblers allow ADD #n, Dn
                // where Dn is implied).
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                let base_expr = IrExpr::Reg(dst.clone());
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Add(Box::new(base_expr), Box::new(src)),
                }]
            }
        }
    }

    /// Lift SUB / SUBA / SUBI / SUBQ.
    fn lift_sub(instr: &Instruction, size: u8) -> Vec<Effect> {
        let dst_op = instr.operand_list.get(1);
        match dst_op {
            Some(Operand::Register(r)) => {
                let dst = r.name.clone();
                let lhs = Self::op_load(instr, 1, size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(lhs), Box::new(rhs)),
                }]
            }
            Some(op) => {
                let ea = Self::operand_to_expr(op);
                let lhs = IrExpr::Deref(Box::new(ea.clone()), size);
                let rhs = Self::op_load(instr, 0, size);
                vec![Effect::MemWrite {
                    addr: ea,
                    value: IrExpr::Sub(Box::new(lhs), Box::new(rhs)),
                    size,
                }]
            }
            None => {
                let dst = Self::dest_reg_name(instr, 0).unwrap_or_else(|| "d0".to_string());
                let src = Self::op_load(instr, 0, size);
                let base_expr = IrExpr::Reg(dst.clone());
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(base_expr), Box::new(src)),
                }]
            }
        }
    }

    /// Return `(lhs, rhs)` for shift/rotate instructions.
    ///
    /// Two-operand form: `ASL count, Dn` Ã¢â€ â€™ `lhs = Dn`, `rhs = count`.
    /// One-operand form (memory): shift by 1 is implied.
    fn shift_operands(instr: &Instruction, size: u8) -> (IrExpr, IrExpr) {
        if instr.operand_list.len() >= 2 {
            let rhs = Self::op_load(instr, 0, size); // shift count
            let lhs = Self::op_load(instr, 1, size); // value
            (lhs, rhs)
        } else {
            let lhs = Self::op_load(instr, 0, size);
            (lhs, IrExpr::Const(1))
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ IR text renderer Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    fn effects_to_text(effects: &[Effect]) -> String {
        if effects.is_empty() {
            return "nop".to_string();
        }
        effects
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Default
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

impl Default for M68kLifter {
    fn default() -> Self {
        Self::new()
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Debug / Display
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

impl fmt::Display for M68kLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "M68kLifter({})", self.cpu_type)
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// ArchLifter impl
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

impl ArchLifter for M68kLifter {
    fn arch_name(&self) -> &'static str {
        "m68k"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "Motorola 68000-family LLIL lifter"
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        // Accept anything Ã¢â‚¬â€ unknown mnemonics fall back to Intrinsic.
        !mnemonic.is_empty()
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let effects = Self::lift_effects(instr);
        let ir_text = Self::effects_to_text(&effects);
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
// strip_size_suffix Ã¢â‚¬â€ public helper
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Strip the m68k size qualifier from the end of a mnemonic string.
///
/// Recognised suffixes (case-insensitive): `.b`, `.w`, `.l`, `.s`.
/// If the mnemonic has no recognised suffix the original slice is returned.
///
/// # Examples
///
/// ```
/// # use rustre_il_lift::m68k_lifter::strip_size_suffix;
/// assert_eq!(strip_size_suffix("move.l"), "move");
/// // The size suffix is matched case-insensitively, but the case of the
/// // remaining mnemonic is preserved (callers normally pass lowercase).
/// assert_eq!(strip_size_suffix("MOVE.W"), "MOVE");
/// assert_eq!(strip_size_suffix("bra.s"),  "bra");
/// assert_eq!(strip_size_suffix("nop"),    "nop");
/// assert_eq!(strip_size_suffix("add.b"),  "add");
/// ```
///
/// Note: the function returns a `&str` into a lower-cased copy held by the
/// caller or a static slice when the input is already lowercase and has no
/// suffix.  In practice callers always pass `instr.mnemonic.as_str()`.
#[must_use]
pub fn strip_size_suffix(mnem: &str) -> &str {
    let lower = mnem; // callers must pass already-lowercased slices
    // Fast path: look for a dot near the end.
    if let Some(dot_pos) = lower.rfind('.') {
        let suffix = &lower[dot_pos + 1..];
        if matches!(suffix, "b" | "w" | "l" | "s" | "B" | "W" | "L" | "S") {
            return &lower[..dot_pos];
        }
    }
    lower
}

// The private lowercased variant used inside lift_effects.
// We always call instr.mnemonic.to_ascii_lowercase() before matching,
// so strip_size_suffix only needs to handle lowercase inputs in practice.

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Tests
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind};

    // Ã¢â€â‚¬Ã¢â€â‚¬ Helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// Build a minimal `RegisterInfo` suitable for test operands.
    fn reg_info(name: &str) -> RegisterInfo {
        RegisterInfo::new(name, 0, 4, RegisterKind::General)
    }

    /// Build a minimal `Instruction` with the given mnemonic and operands.
    fn make_instr(addr: u64, mnem: &str, ops: Vec<Operand>) -> Instruction {
        Instruction {
            address: Address(addr),
            size: 4,
            mnemonic: mnem.to_string(),
            operands: String::new(),
            operand_list: ops,
            flags: InstrFlags::NONE,
            bytes: vec![0u8; 4],
            comment: None,
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ strip_size_suffix Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    /// The m68k auto-increment/decrement modes update the address register, and
    /// the three modes must not collapse to identical IR.
    ///
    /// `Operand::Memory` in `rustre-core` carries no field for the mode, so
    /// `-(a7)`, `(a7)+` and `(a7)` all became the same expression `Reg("a7")`.
    /// The register update was therefore missing entirely — a consumer believed
    /// `a7` survived `move.l d0, -(a7)` unchanged — and nothing downstream could
    /// even tell a fact had been dropped.
    #[test]
    fn auto_increment_decrement_updates_the_address_register() {
        let with_text = |mnem: &str, text: &str| {
            let mut i = make_instr(0x1000, mnem, vec![]);
            i.operands = text.to_string();
            i
        };
        let lifter = M68kLifter::new();
        let render = |i: &Instruction| format!("{:?}", lifter.lift(i).unwrap().effects);

        // Predecrement must SUBTRACT the access size, and do it BEFORE the
        // access: the adjustment is the first effect emitted.
        let dec = lifter
            .lift(&with_text("move.l", "d0, -(a7)"))
            .unwrap()
            .effects;
        assert!(
            matches!(
                dec.first(),
                Some(Effect::RegWrite { reg, value: IrExpr::Sub(..) }) if reg == "a7"
            ),
            "predecrement must subtract from a7 before the access, got {dec:?}"
        );

        // Postincrement must ADD, and do it AFTER: the adjustment is last.
        let inc = lifter
            .lift(&with_text("move.l", "(a7)+, d0"))
            .unwrap()
            .effects;
        assert!(
            matches!(
                inc.last(),
                Some(Effect::RegWrite { reg, value: IrExpr::Add(..) }) if reg == "a7"
            ),
            "postincrement must add to a7 after the access, got {inc:?}"
        );

        // The step is the ACCESS SIZE, not a fixed word.
        let byte = render(&with_text("move.b", "d0, -(a7)"));
        assert!(byte.contains("Const(1)"), "move.b adjusts by 1, got {byte}");

        // A plain `(a7)` must adjust nothing, and `(4,a0)` is not an
        // auto-adjusting form at all.
        for text in ["d0, (a7)", "d0, (4,a0)"] {
            let out = render(&with_text("move.l", text));
            assert!(
                !out.contains("RegWrite { reg: \"a7\"") && !out.contains("RegWrite { reg: \"a0\""),
                "{text} must not adjust an address register, got {out}"
            );
        }

        // MOVEM stays opaque about WHICH registers move, but must no longer be
        // opaque about the direction memory is walked.
        let push = render(&with_text("movem.l", "d0-d7, -(sp)"));
        let pop = render(&with_text("movem.l", "(sp)+, d0-d7"));
        assert_ne!(push, pop, "MOVEM push and pop must be distinguishable");
        assert!(push.contains("predec"), "got {push}");
        assert!(pop.contains("postinc"), "got {pop}");
    }

    #[test]
    fn test_strip_size_suffix_basic() {
        assert_eq!(strip_size_suffix("move.l"), "move");
        assert_eq!(strip_size_suffix("add.b"), "add");
        assert_eq!(strip_size_suffix("sub.w"), "sub");
        assert_eq!(strip_size_suffix("bra.s"), "bra");
        assert_eq!(strip_size_suffix("nop"), "nop");
        assert_eq!(strip_size_suffix("rts"), "rts");
    }

    #[test]
    fn test_strip_size_suffix_no_match() {
        // Unrecognised suffix Ã¢â‚¬â€ leave unchanged
        assert_eq!(strip_size_suffix("move.x"), "move.x");
        assert_eq!(strip_size_suffix("sub"), "sub");
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ infer_size Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_infer_size() {
        assert_eq!(M68kLifter::infer_size("move.b"), 1);
        assert_eq!(M68kLifter::infer_size("move.w"), 2);
        assert_eq!(M68kLifter::infer_size("move.l"), 4);
        assert_eq!(M68kLifter::infer_size("bra.s"), 2);
        assert_eq!(M68kLifter::infer_size("nop"), 4); // default
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ NOP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_nop() {
        let lifter = M68kLifter::new();
        let instr = make_instr(0x1000, "nop", vec![]);
        let result =lifter.lift(&instr).expect("lift nop");
        assert!(result.effects.is_empty(), "NOP should produce no effects");
        assert_eq!(result.ir_text, "nop");
        assert_eq!(result.address, 0x1000);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ MOVE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_move_reg_to_reg() {
        // MOVE.L d1, d0  Ã¢â‚¬â€ copy d1 into d0
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x2000,
            "move.l",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d0")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift move");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d0");
                assert!(matches!(value, IrExpr::Reg(r) if r == "d1"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_move_imm_to_reg() {
        // MOVE.L #0x42, d0  Ã¢â‚¬â€ load immediate into d0
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x2004,
            "move.l",
            vec![Operand::Immediate(0x42), Operand::Register(reg_info("d0"))],
        );
        let result =lifter.lift(&instr).expect("lift move imm");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d0");
                assert_eq!(value, &IrExpr::Const(0x42));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_moveq() {
        // MOVEQ #-1, d7  Ã¢â‚¬â€ sign-extended quick move
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x2008,
            "moveq",
            vec![Operand::Immediate(-1), Operand::Register(reg_info("d7"))],
        );
        let result =lifter.lift(&instr).expect("lift moveq");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d7");
                assert_eq!(value, &IrExpr::Const(u64::MAX)); // -1 as u64
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ADD Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_add_reg_reg() {
        // ADD.L d1, d0  Ã¢â‚¬â€ d0 = d0 + d1
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x3000,
            "add.l",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d0")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift add");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d0");
                match value {
                    IrExpr::Add(lhs, rhs) => {
                        assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "d0"));
                        assert!(matches!(rhs.as_ref(), IrExpr::Reg(r) if r == "d1"));
                    }
                    other => panic!("expected Add, got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_addi() {
        // ADDI.L #5, d3  Ã¢â‚¬â€ d3 = d3 + 5
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x3010,
            "addi.l",
            vec![Operand::Immediate(5), Operand::Register(reg_info("d3"))],
        );
        let result =lifter.lift(&instr).expect("lift addi");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d3");
                assert!(matches!(value, IrExpr::Add(_, _)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SUB Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_sub_reg_reg() {
        // SUB.L d2, d1  Ã¢â‚¬â€ d1 = d1 - d2
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x4000,
            "sub.l",
            vec![
                Operand::Register(reg_info("d2")),
                Operand::Register(reg_info("d1")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift sub");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d1");
                assert!(matches!(value, IrExpr::Sub(_, _)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ CLR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_clr() {
        // CLR.L d5  Ã¢â‚¬â€ d5 = 0
        let lifter = M68kLifter::new();
        let instr = make_instr(0x5000, "clr.l", vec![Operand::Register(reg_info("d5"))]);
        let result =lifter.lift(&instr).expect("lift clr");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d5");
                assert_eq!(value, &IrExpr::Const(0));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ NEG Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_neg() {
        // NEG.L d0  Ã¢â‚¬â€ d0 = 0 - d0
        let lifter = M68kLifter::new();
        let instr = make_instr(0x5010, "neg.l", vec![Operand::Register(reg_info("d0"))]);
        let result =lifter.lift(&instr).expect("lift neg");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d0");
                match value {
                    IrExpr::Sub(lhs, _rhs) => {
                        assert_eq!(lhs.as_ref(), &IrExpr::Const(0));
                    }
                    other => panic!("expected Sub(0, d0), got {other:?}"),
                }
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ BRA Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_bra() {
        // BRA 0x8000  Ã¢â‚¬â€ unconditional branch
        let lifter = M68kLifter::new();
        let instr = make_instr(0x6000, "bra", vec![Operand::Label(0x8000)]);
        let result =lifter.lift(&instr).expect("lift bra");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Branch { target, condition } => {
                assert_eq!(target, &IrExpr::Const(0x8000));
                assert!(condition.is_none(), "BRA should be unconditional");
            }
            other => panic!("unexpected effect: {other:?}"),
        }
        assert!(result.is_terminator());
    }

    #[test]
    fn test_bra_short() {
        // BRA.S 0x7000
        let lifter = M68kLifter::new();
        let instr = make_instr(0x6010, "bra.s", vec![Operand::Label(0x7000)]);
        let result =lifter.lift(&instr).expect("lift bra.s");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Branch { target, condition } => {
                assert_eq!(target, &IrExpr::Const(0x7000));
                assert!(condition.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Bcc (conditional branches) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_beq() {
        let lifter = M68kLifter::new();
        let instr = make_instr(0x6020, "beq", vec![Operand::Label(0x9000)]);
        let result =lifter.lift(&instr).expect("lift beq");
        match &result.effects[0] {
            Effect::Branch {
                target,
                condition: Some(cond),
            } => {
                assert_eq!(target, &IrExpr::Const(0x9000));
                assert!(matches!(cond, IrExpr::Reg(r) if r == "zf"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_bne() {
        let lifter = M68kLifter::new();
        let instr = make_instr(0x6030, "bne", vec![Operand::Label(0x9100)]);
        let result =lifter.lift(&instr).expect("lift bne");
        match &result.effects[0] {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => {
                assert!(matches!(cond, IrExpr::Not(_)));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_blt() {
        let lifter = M68kLifter::new();
        let instr = make_instr(0x6040, "blt", vec![Operand::Label(0x9200)]);
        let result =lifter.lift(&instr).expect("lift blt");
        match &result.effects[0] {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => {
                // BLT: N XOR V
                assert!(matches!(cond, IrExpr::Xor(_, _)));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ JSR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_jsr() {
        // JSR 0xA000  Ã¢â‚¬â€ call subroutine
        let lifter = M68kLifter::new();
        let instr = make_instr(0x7000, "jsr", vec![Operand::Label(0xA000)]);
        let result =lifter.lift(&instr).expect("lift jsr");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Call { target } => {
                assert_eq!(target, &IrExpr::Const(0xA000));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_bsr() {
        // BSR 0xB000 Ã¢â‚¬â€ branch to subroutine (saves return address)
        let lifter = M68kLifter::new();
        let instr = make_instr(0x7010, "bsr", vec![Operand::Label(0xB000)]);
        let result =lifter.lift(&instr).expect("lift bsr");
        assert_eq!(result.effects.len(), 1);
        assert!(
            matches!(&result.effects[0], Effect::Call { target } if target == &IrExpr::Const(0xB000))
        );
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ RTS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_rts() {
        // RTS Ã¢â‚¬â€ return from subroutine
        let lifter = M68kLifter::new();
        let instr = make_instr(0x8000, "rts", vec![]);
        let result =lifter.lift(&instr).expect("lift rts");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Return { value } => {
                assert!(value.is_none(), "RTS has no return value in IR");
            }
            other => panic!("unexpected effect: {other:?}"),
        }
        assert!(result.is_terminator());
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ JMP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_jmp() {
        // JMP (a0) Ã¢â‚¬â€ indirect jump through address register
        let lifter = M68kLifter::new();
        let instr = make_instr(0x8010, "jmp", vec![Operand::Register(reg_info("a0"))]);
        let result =lifter.lift(&instr).expect("lift jmp");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Branch { target, condition } => {
                assert!(condition.is_none());
                assert!(matches!(target, IrExpr::Reg(r) if r == "a0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ LEA Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_lea() {
        // LEA table(a0), a1  Ã¢â‚¬â€ load effective address
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x9000,
            "lea",
            vec![
                Operand::Memory {
                    base: Some(reg_info("a0")),
                    index: None,
                    scale: 1,
                    disp: 0x10,
                    width: 4,
                },
                Operand::Register(reg_info("a1")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift lea");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "a1");
                // EA = a0 + 0x10
                assert!(matches!(value, IrExpr::Add(_, _)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ PEA Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_pea() {
        // PEA (a0) Ã¢â‚¬â€ push effective address onto stack
        let lifter = M68kLifter::new();
        let instr = make_instr(0x9010, "pea", vec![Operand::Register(reg_info("a0"))]);
        let result =lifter.lift(&instr).expect("lift pea");
        // Should have: sp update + MemWrite
        assert_eq!(result.effects.len(), 2);
        assert!(matches!(&result.effects[0], Effect::RegWrite { reg, .. } if reg == "a7"));
        assert!(matches!(&result.effects[1], Effect::MemWrite { .. }));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ TRAP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_trap() {
        // TRAP #0  Ã¢â‚¬â€ software trap / syscall
        let lifter = M68kLifter::new();
        let instr = make_instr(0xA000, "trap", vec![Operand::UImmediate(0)]);
        let result =lifter.lift(&instr).expect("lift trap");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::Syscall { nr } => {
                assert!(matches!(nr, IrExpr::Reg(r) if r == "d0"));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ EXG Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_exg() {
        // EXG d0, d1  Ã¢â‚¬â€ exchange data registers
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xB000,
            "exg",
            vec![
                Operand::Register(reg_info("d0")),
                Operand::Register(reg_info("d1")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift exg");
        assert_eq!(result.effects.len(), 2);
        // First write: d0 = d1
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d0");
                assert!(matches!(value, IrExpr::Reg(r) if r == "d1"));
            }
            other => panic!("unexpected first effect: {other:?}"),
        }
        // Second write: d1 = d0
        match &result.effects[1] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d1");
                assert!(matches!(value, IrExpr::Reg(r) if r == "d0"));
            }
            other => panic!("unexpected second effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ SWAP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_swap() {
        // SWAP d2 Ã¢â‚¬â€ swap high/low words
        let lifter = M68kLifter::new();
        let instr = make_instr(0xC000, "swap", vec![Operand::Register(reg_info("d2"))]);
        let result =lifter.lift(&instr).expect("lift swap");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d2");
                assert!(matches!(value, IrExpr::Or(_, _)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ NOT Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_not() {
        // NOT.L d3 Ã¢â‚¬â€ bitwise complement
        let lifter = M68kLifter::new();
        let instr = make_instr(0xD000, "not.l", vec![Operand::Register(reg_info("d3"))]);
        let result =lifter.lift(&instr).expect("lift not");
        assert_eq!(result.effects.len(), 1);
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d3");
                assert!(matches!(value, IrExpr::Not(_)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ AND / OR / EOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_and() {
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xE000,
            "and.l",
            vec![Operand::Immediate(0xFF), Operand::Register(reg_info("d0"))],
        );
        let result =lifter.lift(&instr).expect("lift and");
        assert!(matches!(
            &result.effects[0],
            Effect::RegWrite {
                value: IrExpr::And(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_or() {
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xE010,
            "or.l",
            vec![Operand::Immediate(0x0F), Operand::Register(reg_info("d1"))],
        );
        let result =lifter.lift(&instr).expect("lift or");
        assert!(matches!(
            &result.effects[0],
            Effect::RegWrite {
                value: IrExpr::Or(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_eor() {
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xE020,
            "eor.l",
            vec![
                Operand::Register(reg_info("d0")),
                Operand::Register(reg_info("d1")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift eor");
        assert!(matches!(
            &result.effects[0],
            Effect::RegWrite {
                value: IrExpr::Xor(_, _),
                ..
            }
        ));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ LSL / LSR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_lsl() {
        // LSL.L #2, d0  Ã¢â‚¬â€ d0 <<= 2
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xF000,
            "lsl.l",
            vec![Operand::Immediate(2), Operand::Register(reg_info("d0"))],
        );
        let result =lifter.lift(&instr).expect("lift lsl");
        match &result.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "d0");
                assert!(matches!(value, IrExpr::Shl(_, _)));
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_lsr() {
        // LSR.W d1, d2  Ã¢â‚¬â€ d2 >>= d1
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xF010,
            "lsr.w",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d2")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift lsr");
        assert!(matches!(
            &result.effects[0],
            Effect::RegWrite {
                value: IrExpr::Shr(_, _),
                ..
            }
        ));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ MULS / DIVU Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_muls() {
        // MULS.W d1, d0  Ã¢â‚¬â€ d0 = d0 * d1 (signed multiply)
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xF020,
            "muls.w",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d0")),
            ],
        );
        let result = lifter.lift(&instr).expect("lift muls");

        // This assertion used to be `IrExpr::Mul(_, _)` — it PINNED THE DEFECT.
        // Its own comment says "signed multiply" while `IrExpr::Mul` cannot
        // express signedness at all, so `muls.w` and `mulu.w` lifted to the
        // same expression. MULS/MULU widen 16x16 -> 32, where the signedness
        // really does change the result.
        let render = |m: &str| {
            format!(
                "{:?}",
                lifter
                    .lift(&make_instr(
                        0xF020,
                        m,
                        vec![
                            Operand::Register(reg_info("d1")),
                            Operand::Register(reg_info("d0")),
                        ],
                    ))
                    .expect("lift")
                    .effects
            )
        };
        assert!(
            format!("{:?}", result.effects).contains("m68k_muls"),
            "muls must keep its signedness somewhere in the IL"
        );
        assert_ne!(
            render("muls.w"),
            render("mulu.w"),
            "signed and unsigned widening multiplies must not lift identically"
        );
    }

    #[test]
    fn test_divu() {
        // DIVU.W d1, d0 Ã¢â‚¬â€ quotient+remainder in d0 (model as intrinsic)
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xF030,
            "divu.w",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d0")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift divu");
        assert!(
            matches!(&result.effects[0], Effect::Intrinsic { name, .. } if name == "m68k_divu")
        );
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ CMP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_cmp() {
        // CMP.L d1, d0 Ã¢â‚¬â€ sets flags, no register write
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xF040,
            "cmp.l",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d0")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift cmp");
        assert!(matches!(&result.effects[0], Effect::Intrinsic { name, .. } if name == "m68k_cmp"));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ LINK / UNLK Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_link() {
        // LINK a6, #-16  Ã¢â‚¬â€ standard frame prologue
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x1_0000,
            "link",
            vec![Operand::Register(reg_info("a6")), Operand::Immediate(-16)],
        );
        let result =lifter.lift(&instr).expect("lift link");
        // LINK produces 4 effects: MemWrite (push a6), sp update, a6=sp, sp+disp
        assert_eq!(result.effects.len(), 4, "LINK should emit 4 effects");
        assert!(matches!(&result.effects[0], Effect::MemWrite { .. }));
        assert!(matches!(&result.effects[1], Effect::RegWrite { reg, .. } if reg == "a7"));
        assert!(matches!(&result.effects[2], Effect::RegWrite { reg, .. } if reg == "a6"));
        assert!(matches!(&result.effects[3], Effect::RegWrite { reg, .. } if reg == "a7"));
    }

    #[test]
    fn test_unlk() {
        // UNLK a6  Ã¢â‚¬â€ standard frame epilogue
        let lifter = M68kLifter::new();
        let instr = make_instr(0x1_0010, "unlk", vec![Operand::Register(reg_info("a6"))]);
        let result =lifter.lift(&instr).expect("lift unlk");
        assert_eq!(result.effects.len(), 3);
        assert!(matches!(&result.effects[0], Effect::RegWrite { reg, .. } if reg == "a7"));
        assert!(matches!(&result.effects[1], Effect::MemRead { dest, .. } if dest == "a6"));
        assert!(matches!(&result.effects[2], Effect::RegWrite { reg, .. } if reg == "a7"));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ROL intrinsic Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_rol_intrinsic() {
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0xF050,
            "rol.l",
            vec![Operand::Immediate(1), Operand::Register(reg_info("d0"))],
        );
        let result =lifter.lift(&instr).expect("lift rol");
        assert!(matches!(&result.effects[0], Effect::Intrinsic { name, .. } if name == "m68k_rol"));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 68020 constructor Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_68020_constructor() {
        let lifter = M68kLifter::new_68020();
        assert_eq!(lifter.cpu_type, "68020");
        assert_eq!(lifter.arch_name(), "m68k");
        assert_eq!(lifter.lift_level(), LiftLevel::Llil);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ ir_text / is_terminator helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_ir_text_non_empty_for_add() {
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x1_2000,
            "add.l",
            vec![
                Operand::Register(reg_info("d1")),
                Operand::Register(reg_info("d0")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift add");
        assert!(!result.ir_text.is_empty());
        assert_ne!(result.ir_text, "nop");
    }

    #[test]
    fn test_rts_is_terminator() {
        let lifter = M68kLifter::new();
        let instr = make_instr(0x2_0000, "rts", vec![]);
        let result =lifter.lift(&instr).expect("lift rts");
        assert!(result.is_terminator());
    }

    #[test]
    fn test_move_is_not_terminator() {
        let lifter = M68kLifter::new();
        let instr = make_instr(
            0x2_0004,
            "move.l",
            vec![
                Operand::Register(reg_info("d0")),
                Operand::Register(reg_info("d1")),
            ],
        );
        let result =lifter.lift(&instr).expect("lift move");
        assert!(!result.is_terminator());
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ Unknown mnemonic fallback Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_unknown_mnemonic_fallback() {
        let lifter = M68kLifter::new();
        let instr = make_instr(0x3_0000, "fmove.x", vec![]);
        let result =lifter.lift(&instr).expect("lift unknown");
        assert_eq!(result.effects.len(), 1);
        assert!(matches!(&result.effects[0], Effect::Intrinsic { .. }));
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ lift_block delegates correctly Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    #[test]
    fn test_lift_block() {
        let lifter = M68kLifter::new();
        let instrs = vec![
            make_instr(0x4_0000, "nop", vec![]),
            make_instr(0x4_0004, "rts", vec![]),
        ];
        let results = lifter.lift_block(&instrs);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        let rts = results[1].as_ref().unwrap();
        assert!(rts.is_terminator());
    }
}
