//! eBPF LLIL lifter.
//!
//! Implements a mnemonic-driven LLIL lifter for eBPF (and classic BPF where
//! overlap exists).  The lifter is purely text-based: it consults
//! [`Instruction::mnemonic`] and [`Instruction::operand_list`] / the
//! [`Operand`] helpers, without importing any arch-specific crate.
//!
//! # eBPF register map
//!
//! | Name | Role |
//! |------|------|
//! | `r0` | Return value / scratch |
//! | `r1`â€“`r5` | Argument registers (caller-saved) |
//! | `r6`â€“`r9` | Callee-saved |
//! | `r10` / `fp` | Frame pointer (read-only) |
//! | `pc` | Implicit program counter |
//!
//! # Supported instruction groups
//!
//! * **Arithmetic** â€“ add, sub, mul, div, or, and, xor, mod, neg, lsh, rsh,
//!   arsh, mov (all with 32-bit variants and immediate variants)
//! * **Memory loads** â€“ ldxb, ldxh, ldxw, ldxdw, ldb, ldh, ldw, lddw
//! * **Memory stores** â€“ stxb, stxh, stxw, stxdw, stb, sth, stw
//! * **Jumps** â€“ ja, jeq, jne, jgt, jge, jlt, jle, jset,
//!   jsgt, jsge, jslt, jsle
//! * **Misc** â€“ call, exit, nop, le/be (endian-swap)

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// BpfLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Mnemonic-driven LLIL lifter for eBPF (and classic BPF).
///
/// Create with [`BpfLifter::new`] for the classic/base variant or
/// [`BpfLifter::new_ebpf`] for full eBPF support.  Both are currently
/// functionally identical; the `ebpf` flag is preserved for future extension
/// (e.g. BTF-aware type propagation).
#[derive(Debug, Clone)]
pub struct BpfLifter {
    /// `true` when targeting eBPF (64-bit), `false` for classic cBPF (32-bit).
    pub ebpf: bool,
}

impl BpfLifter {
    /// Create a classic BPF lifter (32-bit semantics).
    #[must_use]
    pub const fn new() -> Self {
        Self { ebpf: false }
    }

    /// Create an eBPF lifter (64-bit semantics, helper calls, maps, etc.).
    #[must_use]
    pub const fn new_ebpf() -> Self {
        Self { ebpf: true }
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Operand helpers
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Extract the register name from the operand at `idx`, if any.
    fn op_reg(instr: &Instruction, idx: usize) -> Option<String> {
        instr
            .operand_list
            .get(idx)
            .and_then(|o| o.as_register())
            .map(|r| Self::norm_reg(&r.name))
    }

    /// Extract a signed immediate from the operand at `idx`, if any.
    fn op_imm(instr: &Instruction, idx: usize) -> Option<i64> {
        instr.operand_list.get(idx).and_then(rustre_core::Operand::as_immediate)
    }

    /// Build an [`IrExpr`] from operand `idx` â€” either a register or immediate.
    fn op_expr(instr: &Instruction, idx: usize) -> IrExpr {
        if let Some(name) = Self::op_reg(instr, idx) {
            return IrExpr::Reg(name);
        }
        if let Some(v) = Self::op_imm(instr, idx) {
            return IrExpr::Const(v.cast_unsigned());
        }
        // Label operand (absolute address).
        if let Some(addr) = instr.operand_list.get(idx).and_then(rustre_core::Operand::as_label) {
            return IrExpr::Const(addr);
        }
        IrExpr::Undef
    }

    /// Normalise an eBPF register name.
    ///
    /// Accepts `r0`â€“`r10`, `fp` (alias for `r10`), and `pc`.  All other tokens
    /// are returned as-is (lower-cased).
    #[must_use]
    fn norm_reg(name: &str) -> String {
        let lower = name.trim().to_ascii_lowercase();
        match lower.as_str() {
            "fp" => "r10".to_string(),
            other => other.to_string(),
        }
    }

    /// Parse a memory-operand of the form `[reg + off]`, `[reg - off]`, or
    /// just `[reg]` from the instruction's operands.
    ///
    /// eBPF memory operands are typically encoded as:
    ///   - A `Memory` operand with `base = Some(reg)`, `disp = offset`, `width`.
    ///   - Fallback: operand 1 is a register and operand 2 is an immediate offset.
    ///
    /// Returns `(effective_address_expr, access_size_bytes)`.
    fn parse_mem_operand(instr: &Instruction, op_idx: usize) -> (IrExpr, u8) {
        use rustre_core::arch::Operand;

        if let Some(op) = instr.operand_list.get(op_idx)
            && let Operand::Memory {
                base, disp, width, ..
            } = op
            {
                let base_expr = base.as_ref().map_or(IrExpr::Const(0), |r| IrExpr::Reg(Self::norm_reg(&r.name)));
                let addr = match (*disp).cmp(&0) {
                    std::cmp::Ordering::Equal => base_expr,
                    std::cmp::Ordering::Greater => {
                        IrExpr::Add(Box::new(base_expr), Box::new(IrExpr::Const((*disp).cast_unsigned())))
                    }
                    std::cmp::Ordering::Less => IrExpr::Sub(
                        Box::new(base_expr),
                        Box::new(IrExpr::Const(disp.unsigned_abs())),
                    ),
                };
                return (addr, *width);
            }

        // Fallback: register operand + optional immediate offset
        let base = Self::op_reg(instr, op_idx)
            .map_or(IrExpr::Undef, IrExpr::Reg);
        let offset_idx = op_idx + 1;
        let addr = if let Some(off) = Self::op_imm(instr, offset_idx) {
            match off.cmp(&0) {
                std::cmp::Ordering::Equal => base,
                std::cmp::Ordering::Greater => {
                    IrExpr::Add(Box::new(base), Box::new(IrExpr::Const(off.cast_unsigned())))
                }
                std::cmp::Ordering::Less => IrExpr::Sub(
                    Box::new(base),
                    Box::new(IrExpr::Const(off.unsigned_abs())),
                ),
            }
        } else {
            base
        };
        (addr, 8)
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Branch-target resolution
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Resolve the branch target for a BPF jump instruction.
    ///
    /// BPF jump offsets are relative to the *next* instruction (PC + 1 in
    /// BPF 64-bit-word units, or next-byte-address in byte-encoded programs).
    /// We use the next byte address as the base and add the offset scaled by
    /// the standard BPF instruction size (8 bytes).
    fn branch_target(instr: &Instruction, off_operand_idx: usize) -> IrExpr {
        let next_pc = instr.address.0.saturating_add(instr.size as u64);
        // The offset may appear as the first operand (for `ja`) or after
        // the comparison operands (e.g. `jeq r1, r2, off`).
        if let Some(off) = Self::op_imm(instr, off_operand_idx) {
            // BPF offsets are in instruction-count units (8 bytes each).
            let target = if off >= 0 {
                next_pc.wrapping_add(off.cast_unsigned().wrapping_mul(8))
            } else {
                next_pc.wrapping_sub(off.unsigned_abs().wrapping_mul(8))
            };
            return IrExpr::Const(target);
        }
        // Label / absolute address operand.
        if let Some(addr) = instr
            .operand_list
            .get(off_operand_idx)
            .and_then(rustre_core::Operand::as_label)
        {
            return IrExpr::Const(addr);
        }
        // Unknown target.
        IrExpr::Const(next_pc)
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Condition expression builders
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Build the condition expression for `jeq dst, src` â€” taken when `dst == src`.
    ///
    /// Encoded as `CmpEqZero(dst - src)`.
    fn cond_eq(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::CmpEqZero(Box::new(IrExpr::Sub(Box::new(dst), Box::new(src))))
    }

    /// Build the condition expression for `jne dst, src` â€” taken when `dst != src`.
    fn cond_ne(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::Not(Box::new(Self::cond_eq(dst, src)))
    }

    /// Build the condition expression for `jgt dst, src` (unsigned `dst > src`).
    ///
    /// The doc comment here used to describe a `Sub`-as-carry-proxy wrapped in
    /// an Intrinsic "for correctness". No Intrinsic was ever emitted, and the
    /// expression reduced to `dst != src`. `IrExpr::CmpLtU` says it directly.
    fn cond_ugt(dst: IrExpr, src: IrExpr) -> IrExpr {
        // `dst >u src`  ==  `src <u dst`.
        IrExpr::CmpLtU(Box::new(src), Box::new(dst))
    }

    /// Build condition for `jge dst, src` (unsigned `dst >= src`).
    fn cond_uge(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::Not(Box::new(IrExpr::CmpLtU(Box::new(dst), Box::new(src))))
    }

    /// Build condition for `jlt dst, src` (unsigned `dst < src`).
    fn cond_ult(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::CmpLtU(Box::new(dst), Box::new(src))
    }

    /// Build condition for `jle dst, src` (unsigned `dst <= src`).
    fn cond_ule(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::Not(Box::new(IrExpr::CmpLtU(Box::new(src), Box::new(dst))))
    }

    /// Build condition for `jsgt dst, src` (signed `dst > src`).
    fn cond_sgt(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::CmpLt(Box::new(src), Box::new(dst))
    }

    /// Build condition for `jsge dst, src` (signed `dst >= src`).
    fn cond_sge(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::Not(Box::new(IrExpr::CmpLt(Box::new(dst), Box::new(src))))
    }

    /// Build condition for `jslt dst, src` (signed `dst < src`).
    fn cond_slt(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::CmpLt(Box::new(dst), Box::new(src))
    }

    /// Build condition for `jsle dst, src` (signed `dst <= src`).
    fn cond_sle(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::Not(Box::new(IrExpr::CmpLt(Box::new(src), Box::new(dst))))
    }

    /// Build condition for `jset dst, src` â€” taken when `(dst & src) != 0`.
    fn cond_set(dst: IrExpr, src: IrExpr) -> IrExpr {
        IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::And(
            Box::new(dst),
            Box::new(src),
        )))))
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Access-size helpers
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Return the access size in bytes implied by the mnemonic suffix.
    ///
    /// | Suffix | Bytes |
    /// |--------|-------|
    /// | `b`    | 1     |
    /// | `h`    | 2     |
    /// | `w`    | 4     |
    /// | `dw`   | 8     |
    fn size_from_mnem(mnem: &str) -> u8 {
        if mnem.ends_with("dw") {
            8
        } else if mnem.ends_with('w') {
            4
        } else if mnem.ends_with('h') {
            2
        } else if mnem.ends_with('b') {
            1
        } else {
            8 // default: 64-bit
        }
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Main dispatch
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Dispatch a single instruction to the appropriate lifter method.
    ///
    /// Returns the list of IR effects.  An empty list means "no observable
    /// side-effect" (nop / pure compute with result discarded).
    fn dispatch_a(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.as_str();

        // â”€â”€ ALU instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // BPF ALU mnemonics follow a <op>[32][i] pattern where:
        //   - no suffix  â†’ 64-bit register-register
        //   - 32         â†’ 32-bit (result zero-extended)
        //   - i          â†’ immediate second operand (some disassemblers use this)
        // We normalise the base and handle dst / src(reg or imm) uniformly.

        // Strip trailing `32` or `i` suffixes to get the base mnemonic.
        let base = mnem.trim_end_matches("32").trim_end_matches('i');

            match base {
            // â”€â”€ nop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "nop" => vec![],

            // â”€â”€ exit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "exit" => vec![Effect::Return {
                value: Some(IrExpr::Reg("r0".to_string())),
            }],

            // â”€â”€ call â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // BPF helper call: `call <imm>` where imm is the helper function ID.
            "call" => {
                let target = Self::op_imm(instr, 0).map_or_else(|| Self::op_expr(instr, 0), |imm| IrExpr::Const(imm.cast_unsigned()));
                // After a call, r0 receives the return value; r1â€“r5 are clobbered.
                // Emit the call effect followed by clobbers for r1â€“r5.
                let mut effects = vec![Effect::Call { target }];
                // Model r0 as the return value (set to undef after call until
                // the helper returns â€” a downstream analysis fills this in).
                effects.push(Effect::RegWrite {
                    reg: "r0".to_string(),
                    value: IrExpr::Undef,
                });
                for i in 1u8..=5 {
                    effects.push(Effect::RegWrite {
                        reg: format!("r{i}"),
                        value: IrExpr::Undef,
                    });
                }
                effects
            }

            // â”€â”€ mov â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mov" | "movi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let src = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: src,
                }]
            }

            // â”€â”€ add â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "add" | "addi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Add(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ sub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "sub" | "subi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ mul â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mul" | "muli" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Mul(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ div â€” may trap on divide-by-zero; model as Intrinsic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "div" | "divi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![
                    Effect::Intrinsic {
                        name: "bpf_div".to_string(),
                        args: vec![lhs, rhs],
                    },
                    // Pessimistically assume the dst register is written.
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Undef,
                    },
                ]
            }

            // â”€â”€ mod â€” same trap semantics as div â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mod" | "modi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![
                    Effect::Intrinsic {
                        name: "bpf_mod".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Undef,
                    },
                ]
            }
                _ => vec![],
            }
    }
    fn dispatch_b(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.as_str();

        // â”€â”€ ALU instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // BPF ALU mnemonics follow a <op>[32][i] pattern where:
        //   - no suffix  â†’ 64-bit register-register
        //   - 32         â†’ 32-bit (result zero-extended)
        //   - i          â†’ immediate second operand (some disassemblers use this)
        // We normalise the base and handle dst / src(reg or imm) uniformly.

        // Strip trailing `32` or `i` suffixes to get the base mnemonic.
        let base = mnem.trim_end_matches("32").trim_end_matches('i');

            match base {

            // â”€â”€ or â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "or" | "ori" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ and â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "and" | "andi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ xor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "xor" | "xori" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                let rhs = Self::op_expr(instr, 1);
                // xor r, r â†’ 0 (zero idiom)
                let value = if lhs == rhs {
                    IrExpr::Const(0)
                } else {
                    IrExpr::Xor(Box::new(lhs), Box::new(rhs))
                };
                vec![Effect::RegWrite { reg: dst, value }]
            }

            // â”€â”€ lsh (logical shift left) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "lsh" | "lshi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                // eBPF takes only the low 6 bits of the shift count; the value
                // came through unmasked, so a count of 64 shifted by 64 in the
                // IL and by 0 on the machine. All shifts in this lifter are the
                // 64-bit forms (there are no `*32` mnemonics here), hence 63.
                let rhs = IrExpr::And(
                    Box::new(Self::op_expr(instr, 1)),
                    Box::new(IrExpr::Const(63)),
                );
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shl(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ rsh (logical shift right) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "rsh" | "rshi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                // eBPF takes only the low 6 bits of the shift count; the value
                // came through unmasked, so a count of 64 shifted by 64 in the
                // IL and by 0 on the machine. All shifts in this lifter are the
                // 64-bit forms (there are no `*32` mnemonics here), hence 63.
                let rhs = IrExpr::And(
                    Box::new(Self::op_expr(instr, 1)),
                    Box::new(IrExpr::Const(63)),
                );
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shr(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ arsh (arithmetic shift right â€” sign-extending) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "arsh" | "arshi" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let lhs = IrExpr::Reg(dst.clone());
                // eBPF takes only the low 6 bits of the shift count; the value
                // came through unmasked, so a count of 64 shifted by 64 in the
                // IL and by 0 on the machine. All shifts in this lifter are the
                // 64-bit forms (there are no `*32` mnemonics here), hence 63.
                let rhs = IrExpr::And(
                    Box::new(Self::op_expr(instr, 1)),
                    Box::new(IrExpr::Const(63)),
                );
                // eBPF `arsh` propagates the sign bit. The comment here used to
                // claim it was "wrapped so analysis passes can distinguish it"
                // — there was no wrapper, and this emitted the very same `Shr`
                // as `rsh`, so the two lifted to byte-identical effects.
                // `IrExpr::Sar` exists; use it.
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sar(Box::new(lhs), Box::new(rhs)),
                }]
            }

            // â”€â”€ neg (two's-complement negation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "neg" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let src = IrExpr::Reg(dst.clone());
                // neg dst  â†’  dst = 0 - dst
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(src)),
                }]
            }

            // â”€â”€ endian-swap (le/be) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // `le <imm>` / `be <imm>` â€” imm âˆˆ {16, 32, 64}.
            // We model these as an Intrinsic since we have no bswap IrExpr node.
            "le" | "be" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let width = Self::op_expr(instr, 1);
                let name = format!("bpf_{mnem}");
                vec![
                    Effect::Intrinsic {
                        name,
                        args: vec![IrExpr::Reg(dst.clone()), width],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Undef,
                    },
                ]
            }

            // â”€â”€ lddw (64-bit immediate load â€” two insns wide) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // Typically decoded as a single 16-byte instruction by disassemblers.
            "lddw" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let imm = Self::op_imm(instr, 1).unwrap_or(0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Const(imm.cast_unsigned()),
                }]
            }
                _ => vec![],
            }
    }
    fn dispatch_c(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.as_str();

        // â”€â”€ ALU instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // BPF ALU mnemonics follow a <op>[32][i] pattern where:
        //   - no suffix  â†’ 64-bit register-register
        //   - 32         â†’ 32-bit (result zero-extended)
        //   - i          â†’ immediate second operand (some disassemblers use this)
        // We normalise the base and handle dst / src(reg or imm) uniformly.

        // Strip trailing `32` or `i` suffixes to get the base mnemonic.
        let base = mnem.trim_end_matches("32").trim_end_matches('i');

            match base {

            // â”€â”€ absolute loads (ldb / ldh / ldw) â€” classic BPF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // `ldw dst, [addr]` â€” load from absolute address.
            "ldb" | "ldh" | "ldw" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let (addr, _) = Self::parse_mem_operand(instr, 1);
                let size = Self::size_from_mnem(mnem);
                vec![Effect::MemRead {
                    addr,
                    dest: dst,
                    size,
                }]
            }

            // â”€â”€ indirect/extended loads (ldxb / ldxh / ldxw / ldxdw) â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // `ldxdw dst, [src + off]` â€” load from register + offset.
            "ldxb" | "ldxh" | "ldxw" | "ldxdw" => {
                let dst = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let (addr, sz_op) = Self::parse_mem_operand(instr, 1);
                let size = if sz_op != 0 {
                    sz_op
                } else {
                    Self::size_from_mnem(mnem)
                };
                vec![Effect::MemRead {
                    addr,
                    dest: dst,
                    size,
                }]
            }

            // â”€â”€ absolute stores (stb / sth / stw) â€” classic BPF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "stb" | "sth" | "stw" => {
                let (addr, _) = Self::parse_mem_operand(instr, 0);
                let value = Self::op_expr(instr, 2);
                let size = Self::size_from_mnem(mnem);
                vec![Effect::MemWrite { addr, value, size }]
            }

            // â”€â”€ indirect/extended stores (stxb / stxh / stxw / stxdw) â”€â”€â”€â”€â”€â”€â”€â”€
            // `stxdw [dst + off], src` â€” store src into [dst + off].
            "stxb" | "stxh" | "stxw" | "stxdw" => {
                let (addr, sz_op) = Self::parse_mem_operand(instr, 0);
                let value = Self::op_expr(instr, 2);
                let size = if sz_op != 0 {
                    sz_op
                } else {
                    Self::size_from_mnem(mnem)
                };
                vec![Effect::MemWrite { addr, value, size }]
            }

            // â”€â”€ ja â€” unconditional jump â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ja" => {
                let target = Self::branch_target(instr, 0);
                vec![Effect::Branch {
                    target,
                    condition: None,
                }]
            }

            // â”€â”€ jeq â€” jump if equal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jeq" | "jeqi" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_eq(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jne â€” jump if not equal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jne" | "jnei" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_ne(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jgt â€” jump if greater-than (unsigned) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jgt" | "jgti" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_ugt(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jge â€” jump if greater-or-equal (unsigned) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jge" | "jgei" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_uge(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }
                _ => vec![],
            }
    }
    fn dispatch_d(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.as_str();

        // â”€â”€ ALU instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // BPF ALU mnemonics follow a <op>[32][i] pattern where:
        //   - no suffix  â†’ 64-bit register-register
        //   - 32         â†’ 32-bit (result zero-extended)
        //   - i          â†’ immediate second operand (some disassemblers use this)
        // We normalise the base and handle dst / src(reg or imm) uniformly.

        // Strip trailing `32` or `i` suffixes to get the base mnemonic.
        let base = mnem.trim_end_matches("32").trim_end_matches('i');

            match base {

            // â”€â”€ jlt â€” jump if less-than (unsigned) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jlt" | "jlti" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_ult(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jle â€” jump if less-or-equal (unsigned) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jle" | "jlei" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_ule(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jset â€” jump if bitwise-AND is non-zero â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jset" | "jseti" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_set(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jsgt â€” jump if greater-than (signed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jsgt" | "jsgti" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_sgt(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jsge â€” jump if greater-or-equal (signed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jsge" | "jsgei" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_sge(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jslt â€” jump if less-than (signed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jslt" | "jslti" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_slt(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ jsle â€” jump if less-or-equal (signed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "jsle" | "jslei" => {
                let dst_name = Self::op_reg(instr, 0).unwrap_or_else(|| "r0".to_string());
                let dst = IrExpr::Reg(dst_name);
                let src = Self::op_expr(instr, 1);
                let target = Self::branch_target(instr, 2);
                let condition = Self::cond_sle(dst, src);
                vec![Effect::Branch {
                    target,
                    condition: Some(condition),
                }]
            }

            // â”€â”€ fallback â€” unknown mnemonic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            _ => {
                vec![Effect::Intrinsic {
                    name: format!("bpf_{}", mnem.replace([' ', '-'], "_")),
                    args: (0..instr.operand_list.len())
                        .map(|i| Self::op_expr(instr, i))
                        .collect(),
                }]
            }
            }
    }

    fn dispatch(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.as_str();

        // â”€â”€ ALU instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // BPF ALU mnemonics follow a <op>[32][i] pattern where:
        //   - no suffix  â†’ 64-bit register-register
        //   - 32         â†’ 32-bit (result zero-extended)
        //   - i          â†’ immediate second operand (some disassemblers use this)
        // We normalise the base and handle dst / src(reg or imm) uniformly.

        // Whether this is an ALU32 form. The comment above states the rule —
        // "32 -> 32-bit (result zero-extended)" — and the old code stripped the
        // suffix and then used the base for dispatch only, so the width was
        // DOCUMENTED and DISCARDED in the same breath: `add32 r1, r2` lifted
        // byte-identically to `add r1, r2`, claiming a full 64-bit add where the
        // hardware computes 32 bits and ZEROES the upper half.
        //
        // Same class as RISC-V's `addw` and MIPS's `add` vs `dadd`, both fixed
        // earlier in this session: a mnemonic suffix that announces the operand
        // width, folded into a width-agnostic handler.
        let is_alu32 = Self::is_alu32(mnem);

        // "nop" legitimately lifts to zero effects; special-cased here since
        // the dispatch_a/b/c chain below uses "non-empty result" as its
        // "handled" sentinel and would otherwise treat an empty match as
        // "try the next stage" and fall through to dispatch_d's fallback.
        if mnem == "nop" {
            return vec![];
        }

        let __r0 = Self::dispatch_a(instr);
        if !__r0.is_empty() { return Self::narrow_if_alu32(__r0, is_alu32); }
        let __r1 = Self::dispatch_b(instr);
        if !__r1.is_empty() { return Self::narrow_if_alu32(__r1, is_alu32); }
        let __r2 = Self::dispatch_c(instr);
        if !__r2.is_empty() { return Self::narrow_if_alu32(__r2, is_alu32); }
        Self::narrow_if_alu32(Self::dispatch_d(instr), is_alu32)
    }

    /// Does this mnemonic name an ALU32 (32-bit) form?
    ///
    /// BPF ALU mnemonics follow `<op>[32][i]`, so the immediate marker comes
    /// after the width marker and must be removed first.
    #[must_use]
    fn is_alu32(mnem: &str) -> bool {
        mnem.trim_end_matches('i').ends_with("32")
    }

    /// Zero-extend every register result to 32 bits, for the ALU32 forms.
    ///
    /// Applied at the single dispatch tail rather than inside each of the two
    /// dozen ALU arms: the width is a property of the INSTRUCTION, and a
    /// per-arm fix would have covered only the arm whose output I happened to
    /// read (the recurring lesson of this session).
    ///
    /// Only `RegWrite` needs masking. The `JMP32` forms (`jeq32`, `jlt32`, …)
    /// also compare at 32 bits, but they write no register, so this pass leaves
    /// them untouched — their comparison width is a SEPARATE fact and is NOT
    /// claimed to be fixed here.
    #[must_use]
    fn narrow_if_alu32(effects: Vec<Effect>, is_alu32: bool) -> Vec<Effect> {
        if !is_alu32 {
            return effects;
        }
        effects
            .into_iter()
            .map(|e| match e {
                Effect::RegWrite { reg, value } => Effect::RegWrite {
                    reg,
                    value: IrExpr::And(
                        Box::new(value),
                        Box::new(IrExpr::Const(0xFFFF_FFFF)),
                    ),
                },
                other => other,
            })
            .collect()
    }
}

impl Default for BpfLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BpfLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ebpf {
            write!(f, "BpfLifter(eBPF)")
        } else {
            write!(f, "BpfLifter(cBPF)")
        }
    }
}

impl ArchLifter for BpfLifter {
    fn arch_name(&self) -> &'static str {
        if self.ebpf { "ebpf" } else { "bpf" }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        if self.ebpf {
            "mnemonic-driven eBPF LLIL lifter"
        } else {
            "mnemonic-driven classic BPF LLIL lifter"
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        // All BPF mnemonics are handled (unknown ones fall back to Intrinsic).
        !mnemonic.is_empty()
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let effects = Self::dispatch(instr);

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
    use rustre_core::{
        address::Address,
        arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind},
    };

    // â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn make_reg(name: &str) -> RegisterInfo {
        RegisterInfo::new(name, 0, 8, RegisterKind::General)
    }

    fn reg_op(name: &str) -> Operand {
        Operand::Register(make_reg(name))
    }

    fn imm_op(v: i64) -> Operand {
        Operand::Immediate(v)
    }

    fn label_op(addr: u64) -> Operand {
        Operand::Label(addr)
    }

    fn mem_op(base: &str, offset: i64, width: u8) -> Operand {
        Operand::Memory {
            base: Some(make_reg(base)),
            index: None,
            scale: 1,
            disp: offset,
            width,
        }
    }

    fn instr(addr: u64, mnemonic: &str, ops: Vec<Operand>) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 8, mnemonic.to_string(), vec![0u8; 8]);
        i.operand_list = ops;
        i.flags = InstrFlags::NONE;
        i
    }

    fn lift(mnemonic: &str, ops: Vec<Operand>) -> LiftedInstr {
        let lifter = BpfLifter::new_ebpf();
        let i = instr(0x1000, mnemonic, ops);
        lifter.lift(&i).expect("lift should succeed")
    }

    // â”€â”€ constructors and metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn constructors() {
        let classic = BpfLifter::new();
        assert!(!classic.ebpf);
        assert_eq!(classic.arch_name(), "bpf");

        let ebpf = BpfLifter::new_ebpf();
        assert!(ebpf.ebpf);
        assert_eq!(ebpf.arch_name(), "ebpf");
    }

    #[test]
    fn lift_level_is_llil() {
        let l = BpfLifter::new_ebpf();
        assert_eq!(l.lift_level(), LiftLevel::Llil);
    }

    #[test]
    fn description_contains_ebpf() {
        let l = BpfLifter::new_ebpf();
        assert!(
            l.description().contains("eBPF")
                || l.description().contains("ebpf")
                || l.description().contains("BPF")
        );
    }

    // â”€â”€ nop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_nop() {
        let li = lift("nop", vec![]);
        assert!(li.effects.is_empty(), "nop must have no effects");
        assert_eq!(li.ir_text, "nop");
    }

    // â”€â”€ add â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_add_reg() {
        // add r1, r2  â†’  r1 = r1 + r2
        let li = lift("add", vec![reg_op("r1"), reg_op("r2")]);
        assert_eq!(li.original_mnemonic, "add");
        let wrote_r1 = li.effects.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "r1" && matches!(value, IrExpr::Add(..))
            } else {
                false
            }
        });
        assert!(
            wrote_r1,
            "add should write r1 with Add expr; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_add_imm() {
        // add r3, 10  â†’  r3 = r3 + 10
        let li = lift("add", vec![reg_op("r3"), imm_op(10)]);
        let wrote = li.effects.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "r3"
                    && matches!(value, IrExpr::Add(_, r) if matches!(r.as_ref(), IrExpr::Const(10)))
            } else {
                false
            }
        });
        assert!(
            wrote,
            "add imm should write r3 with Add(r3, 10); got: {:?}",
            li.effects
        );
    }

    /// UPDATED: this test previously asserted that `add32` produces a bare
    /// top-level `Add`, and its comment said "same as add but 32-bit suffix
    /// stripped" — writing the wrong rule down and pinning it. BPF ALU32
    /// computes in 32 bits and ZERO-EXTENDS into the 64-bit destination, so the
    /// two forms must NOT produce identical IR.
    #[test]
    fn lift_add32() {
        let li = lift("add32", vec![reg_op("r0"), reg_op("r1")]);
        let wrote = li.effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite { reg, value: IrExpr::And(inner, mask) }
                if reg == "r0"
                    && matches!(**inner, IrExpr::Add(..))
                    && matches!(**mask, IrExpr::Const(0xFFFF_FFFF))
        ));
        assert!(
            wrote,
            "add32 must add then zero-extend to 32 bits; got: {:?}",
            li.effects
        );

        // The distinction is the point: the 64-bit form must stay unmasked.
        let wide = lift("add", vec![reg_op("r0"), reg_op("r1")]);
        assert_ne!(
            format!("{:?}", wide.effects),
            format!("{:?}", li.effects),
            "add and add32 must not lift identically"
        );
        assert!(
            wide.effects.iter().any(|e| matches!(
                e,
                Effect::RegWrite { reg, value: IrExpr::Add(..) } if reg == "r0"
            )),
            "the 64-bit add must NOT be masked; got: {:?}",
            wide.effects
        );
    }

    // â”€â”€ sub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_sub_reg() {
        let li = lift("sub", vec![reg_op("r5"), reg_op("r6")]);
        let wrote = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Sub(..) } if reg == "r5"));
        assert!(
            wrote,
            "sub should produce RegWrite Sub; got: {:?}",
            li.effects
        );
    }

    // â”€â”€ mul â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_mul_reg() {
        let li = lift("mul", vec![reg_op("r2"), reg_op("r3")]);
        let wrote = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Mul(..) } if reg == "r2"));
        assert!(
            wrote,
            "mul should produce RegWrite Mul; got: {:?}",
            li.effects
        );
    }

    // â”€â”€ or / and / xor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_or() {
        let li = lift("or", vec![reg_op("r1"), reg_op("r2")]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Or(..) } if reg == "r1")
        }));
    }

    #[test]
    fn lift_and() {
        let li = lift("and", vec![reg_op("r4"), reg_op("r5")]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::And(..) } if reg == "r4")
        }));
    }

    #[test]
    fn lift_xor_different() {
        let li = lift("xor", vec![reg_op("r1"), reg_op("r2")]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Xor(..) } if reg == "r1")
        }));
    }

    #[test]
    fn lift_xor_self_is_zero() {
        // xor r1, r1  â†’  r1 = 0
        let li = lift("xor", vec![reg_op("r1"), reg_op("r1")]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(0) } if reg == "r1")
        }));
    }

    // â”€â”€ shift â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_lsh() {
        let li = lift("lsh", vec![reg_op("r0"), imm_op(3)]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Shl(..) } if reg == "r0")
        }));
    }

    /// The eight ordering jumps must be eight distinct conditions.
    ///
    /// They were not. `cond_ugt` expanded to
    /// `NOT((dst-src == 0) OR (src-dst == 0))` — both terms are the same test,
    /// so the whole thing reduced to `dst != src`. Every unsigned jump was
    /// built from it, so `jlt` came out identical to `jgt` and `jle` identical
    /// to `jge`: four instructions, two expressions, all four wrong. The signed
    /// four used the sign bit of a subtraction, which misreads every case where
    /// the subtraction overflows.
    ///
    /// The old comment asked for "an `UGT` IrExpr node" as the ideal fix.
    /// `CmpLtU` had since been added.
    #[test]
    fn ordering_jumps_are_eight_distinct_conditions() {
        let render = |m: &str| {
            format!(
                "{:?}",
                lift(m, vec![reg_op("r1"), reg_op("r2"), imm_op(8)]).effects
            )
        };
        let jumps = ["jgt", "jge", "jlt", "jle", "jsgt", "jsge", "jslt", "jsle"];
        let mut seen: Vec<(&str, String)> = Vec::new();
        for m in jumps {
            let text = render(m);
            if let Some((other, _)) = seen.iter().find(|(_, t)| *t == text) {
                panic!("{m} lifts identically to {other}:\n{text}");
            }
            seen.push((m, text));
        }

        // Unsigned jumps must use the unsigned comparison, signed ones the
        // signed comparison — the distinction the mnemonics spell out.
        for m in ["jgt", "jge", "jlt", "jle"] {
            assert!(render(m).contains("CmpLtU"), "{m} must compare unsigned");
        }
        for m in ["jsgt", "jsge", "jslt", "jsle"] {
            let t = render(m);
            assert!(
                t.contains("CmpLt(") && !t.contains("CmpLtU"),
                "{m} must compare signed, got {t}"
            );
        }
    }

    /// eBPF takes only the low 6 bits of a shift count. It came through
    /// unmasked, so a count of 64 shifted by 64 in the IL and by 0 on the
    /// machine.
    ///
    /// Both the register and immediate forms are masked here: unlike MIPS,
    /// whose `sa` field is five bits wide in the encoding and cannot overflow,
    /// eBPF's immediate is a full 32-bit field.
    #[test]
    fn shift_counts_are_masked() {
        for mnem in ["lsh", "rsh", "arsh"] {
            let t = format!("{:?}", lift(mnem, vec![reg_op("r0"), imm_op(64)]).effects);
            assert!(
                t.contains("Const(63)"),
                "{mnem} must mask its shift count, got {t}"
            );
        }
    }

    #[test]
    fn lift_rsh() {
        let li = lift("rsh", vec![reg_op("r0"), imm_op(2)]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Shr(..) } if reg == "r0")
        }));
    }

    /// `arsh` is the ARITHMETIC shift; `rsh` is logical.
    ///
    /// This test used to be a byte-for-byte copy of `lift_rsh`, asserting the
    /// same `IrExpr::Shr` — and the lifter did emit the same node for both, so
    /// the two instructions were indistinguishable. The pair of identical tests
    /// was itself the evidence, had anyone read them side by side.
    #[test]
    fn lift_arsh() {
        let li = lift("arsh", vec![reg_op("r0"), imm_op(1)]);
        assert!(
            li.effects.iter().any(|e| {
                matches!(e, Effect::RegWrite { reg, value: IrExpr::Sar(..) } if reg == "r0")
            }),
            "arsh must be an arithmetic shift, got {:?}",
            li.effects
        );
        let logical = lift("rsh", vec![reg_op("r0"), imm_op(1)]);
        assert_ne!(
            format!("{:?}", li.effects),
            format!("{:?}", logical.effects),
            "arsh and rsh must not lift identically"
        );
    }

    // â”€â”€ neg â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_neg() {
        let li = lift("neg", vec![reg_op("r1")]);
        let wrote = li.effects.iter().any(|e| {
            if let Effect::RegWrite { reg, value } = e {
                reg == "r1"
                    && matches!(
                        value,
                        IrExpr::Sub(zero, _) if matches!(zero.as_ref(), IrExpr::Const(0))
                    )
            } else {
                false
            }
        });
        assert!(
            wrote,
            "neg should write Sub(0, r1) into r1; got: {:?}",
            li.effects
        );
    }

    // â”€â”€ mov â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_mov_reg() {
        // mov r0, r1  â†’  r0 = r1
        let li = lift("mov", vec![reg_op("r0"), reg_op("r1")]);
        assert!(li.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Reg(src) } if reg == "r0" && src == "r1")
        }), "mov should write r0 = r1; got: {:?}", li.effects);
    }

    #[test]
    fn lift_mov_imm() {
        // mov r0, 42  â†’  r0 = 42
        let li = lift("mov", vec![reg_op("r0"), imm_op(42)]);
        assert!(
            li.effects.iter().any(|e| {
                matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(42) } if reg == "r0")
            }),
            "mov imm should write Const(42) to r0; got: {:?}",
            li.effects
        );
    }

    // â”€â”€ lddw â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_lddw() {
        let li = lift(
            "lddw",
            vec![reg_op("r1"), imm_op(0x0102_0304_0506_0708_u64 as i64)],
        );
        let wrote = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "r1"));
        assert!(wrote, "lddw should write r1; got: {:?}", li.effects);
    }

    // â”€â”€ memory loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_ldxw() {
        // ldxw r0, [r1 + 8]  â†’  r0 = *(r1 + 8):4
        let li = lift("ldxw", vec![reg_op("r0"), mem_op("r1", 8, 4)]);
        let mem_read = li.effects.iter().any(|e| {
            if let Effect::MemRead { dest, size, addr } = e {
                dest == "r0"
                    && *size == 4
                    && matches!(addr, IrExpr::Add(base, off)
                        if matches!(base.as_ref(), IrExpr::Reg(r) if r == "r1")
                        && matches!(off.as_ref(), IrExpr::Const(8))
                    )
            } else {
                false
            }
        });
        assert!(
            mem_read,
            "ldxw should MemRead r0 from [r1+8]:4; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_ldxdw() {
        // ldxdw r2, [r3 + 0]  â†’  r2 = *(r3):8
        let li = lift("ldxdw", vec![reg_op("r2"), mem_op("r3", 0, 8)]);
        assert!(
            li.effects
                .iter()
                .any(|e| { matches!(e, Effect::MemRead { dest, size: 8, .. } if dest == "r2") }),
            "ldxdw should MemRead 8 bytes into r2; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_ldxb() {
        let li = lift("ldxb", vec![reg_op("r0"), mem_op("r1", 4, 1)]);
        assert!(
            li.effects
                .iter()
                .any(|e| { matches!(e, Effect::MemRead { dest, size: 1, .. } if dest == "r0") })
        );
    }

    #[test]
    fn lift_ldxh() {
        let li = lift("ldxh", vec![reg_op("r0"), mem_op("r2", 2, 2)]);
        assert!(
            li.effects
                .iter()
                .any(|e| { matches!(e, Effect::MemRead { dest, size: 2, .. } if dest == "r0") })
        );
    }

    // â”€â”€ memory stores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_stxw() {
        // stxw [r1 + 0], r2  â†’  *(r1):4 = r2
        let li = lift("stxw", vec![mem_op("r1", 0, 4), reg_op("r2"), reg_op("r2")]);
        let mem_write = li.effects.iter().any(|e| {
            if let Effect::MemWrite { size, value, .. } = e {
                *size == 4 && matches!(value, IrExpr::Reg(r) if r == "r2")
            } else {
                false
            }
        });
        assert!(
            mem_write,
            "stxw should MemWrite 4 bytes from r2; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_stxdw() {
        let li = lift(
            "stxdw",
            vec![mem_op("r10", -8, 8), reg_op("r1"), reg_op("r1")],
        );
        let wrote = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::MemWrite { size: 8, .. }));
        assert!(
            wrote,
            "stxdw should MemWrite 8 bytes; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_stxb() {
        let li = lift("stxb", vec![mem_op("r1", 0, 1), reg_op("r2"), reg_op("r2")]);
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { size: 1, .. }))
        );
    }

    #[test]
    fn lift_stxh() {
        let li = lift("stxh", vec![mem_op("r1", 2, 2), reg_op("r2"), reg_op("r2")]);
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { size: 2, .. }))
        );
    }

    // â”€â”€ branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_ja_unconditional() {
        // ja +5  â†’  Branch { target = pc+1+(5*8), condition = None }
        let li = lift("ja", vec![imm_op(5)]);
        let is_uncond = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: None,
                    ..
                }
            )
        });
        assert!(
            is_uncond,
            "ja should produce unconditional Branch; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_ja_label() {
        let li = lift("ja", vec![label_op(0x2000)]);
        assert!(li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    target: IrExpr::Const(0x2000),
                    condition: None
                }
            )
        }));
    }

    #[test]
    fn lift_jeq_is_conditional() {
        // jeq r0, r1, +2
        let li = lift("jeq", vec![reg_op("r0"), reg_op("r1"), imm_op(2)]);
        let is_cond = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(
            is_cond,
            "jeq should produce conditional Branch; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_jeq_condition_is_cmpeqzero_of_sub() {
        let li = lift("jeq", vec![reg_op("r0"), reg_op("r1"), imm_op(0)]);
        let cond_ok = li.effects.iter().any(|e| {
            if let Effect::Branch {
                condition: Some(cond),
                ..
            } = e
            {
                // condition = CmpEqZero(Sub(r0, r1))
                matches!(cond, IrExpr::CmpEqZero(inner)
                    if matches!(inner.as_ref(), IrExpr::Sub(..))
                )
            } else {
                false
            }
        });
        assert!(
            cond_ok,
            "jeq condition should be CmpEqZero(Sub); got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_jne_condition_is_not_of_cmpeqzero() {
        let li = lift("jne", vec![reg_op("r0"), reg_op("r1"), imm_op(0)]);
        let cond_ok = li.effects.iter().any(|e| {
            if let Effect::Branch {
                condition: Some(cond),
                ..
            } = e
            {
                matches!(cond, IrExpr::Not(inner)
                    if matches!(inner.as_ref(), IrExpr::CmpEqZero(..))
                )
            } else {
                false
            }
        });
        assert!(
            cond_ok,
            "jne condition should be Not(CmpEqZero); got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_jgt() {
        let li = lift("jgt", vec![reg_op("r1"), reg_op("r2"), imm_op(1)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jge() {
        let li = lift("jge", vec![reg_op("r1"), reg_op("r2"), imm_op(1)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jlt() {
        let li = lift("jlt", vec![reg_op("r1"), reg_op("r2"), imm_op(1)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jle() {
        let li = lift("jle", vec![reg_op("r1"), reg_op("r2"), imm_op(1)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jset() {
        let li = lift("jset", vec![reg_op("r0"), imm_op(0x80), imm_op(3)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jsgt() {
        let li = lift("jsgt", vec![reg_op("r0"), reg_op("r1"), imm_op(0)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jsge() {
        let li = lift("jsge", vec![reg_op("r0"), imm_op(-1), imm_op(0)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jslt() {
        let li = lift("jslt", vec![reg_op("r0"), imm_op(0), imm_op(2)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    #[test]
    fn lift_jsle() {
        let li = lift("jsle", vec![reg_op("r0"), imm_op(0), imm_op(2)]);
        assert!(li.effects.iter().any(|e| matches!(
            e,
            Effect::Branch {
                condition: Some(_),
                ..
            }
        )));
    }

    // â”€â”€ call â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_call_helper() {
        // call 1  â†’  call bpf_helper(1); r0 = undef; r1-r5 = undef
        let li = lift("call", vec![imm_op(1)]);
        assert!(
            li.effects.iter().any(|e| matches!(e, Effect::Call { .. })),
            "call should emit Call effect; got: {:?}",
            li.effects
        );
        // r0 should be clobbered
        assert!(
            li.effects.iter().any(|e| {
                matches!(e, Effect::RegWrite { reg, value: IrExpr::Undef } if reg == "r0")
            }),
            "call should clobber r0; got: {:?}",
            li.effects
        );
        // r1-r5 should be clobbered
        for n in 1u8..=5 {
            let rn = format!("r{n}");
            assert!(
                li.effects.iter().any(|e| {
                    matches!(e, Effect::RegWrite { reg, value: IrExpr::Undef } if reg == &rn)
                }),
                "call should clobber {rn}; got: {:?}",
                li.effects
            );
        }
    }

    // â”€â”€ exit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_exit() {
        let li = lift("exit", vec![]);
        let is_ret = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Return { value: Some(IrExpr::Reg(r)) } if r == "r0"));
        assert!(is_ret, "exit should Return r0; got: {:?}", li.effects);
    }

    // â”€â”€ div/mod fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lift_div_emits_intrinsic() {
        let li = lift("div", vec![reg_op("r0"), reg_op("r1")]);
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "bpf_div")),
            "div should emit bpf_div intrinsic; got: {:?}",
            li.effects
        );
    }

    #[test]
    fn lift_mod_emits_intrinsic() {
        let li = lift("mod", vec![reg_op("r0"), reg_op("r1")]);
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "bpf_mod")),
            "mod should emit bpf_mod intrinsic; got: {:?}",
            li.effects
        );
    }

    // â”€â”€ register normalisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn fp_alias_normalises_to_r10() {
        assert_eq!(BpfLifter::norm_reg("fp"), "r10");
        assert_eq!(BpfLifter::norm_reg("FP"), "r10");
        assert_eq!(BpfLifter::norm_reg("r10"), "r10");
    }

    // â”€â”€ unknown instruction fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn unknown_mnemonic_fallback_is_intrinsic() {
        let li = lift("bpf_unknown_42", vec![reg_op("r0")]);
        assert!(
            li.effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { .. })),
            "unknown mnemonic should produce Intrinsic; got: {:?}",
            li.effects
        );
    }

    // â”€â”€ LiftedInstr metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lifted_address_matches_instr() {
        let lifter = BpfLifter::new_ebpf();
        let i = instr(0xdead_beef, "exit", vec![]);
        let li = lifter.lift(&i).unwrap();
        assert_eq!(li.address, 0xdead_beef);
    }

    #[test]
    fn lifted_mnemonic_preserved() {
        let lifter = BpfLifter::new_ebpf();
        let i = instr(0, "ADD32", vec![reg_op("r0"), reg_op("r1")]);
        let li = lifter.lift(&i).unwrap();
        assert_eq!(li.original_mnemonic, "ADD32");
    }

    #[test]
    fn lifted_il_level_is_llil() {
        let lifter = BpfLifter::new_ebpf();
        let i = instr(0, "nop", vec![]);
        let li = lifter.lift(&i).unwrap();
        assert_eq!(li.il_level, LiftLevel::Llil);
    }

    // â”€â”€ batch lifting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn batch_lift_returns_one_per_instr() {
        let lifter = BpfLifter::new_ebpf();
        let instrs = vec![
            instr(0x00, "nop", vec![]),
            instr(0x08, "exit", vec![]),
            instr(0x10, "add", vec![reg_op("r0"), reg_op("r1")]),
        ];
        let results = lifter.lift_block(&instrs);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn size_from_mnem_variants() {
        assert_eq!(BpfLifter::size_from_mnem("ldxb"), 1);
        assert_eq!(BpfLifter::size_from_mnem("ldxh"), 2);
        assert_eq!(BpfLifter::size_from_mnem("ldxw"), 4);
        assert_eq!(BpfLifter::size_from_mnem("ldxdw"), 8);
        assert_eq!(BpfLifter::size_from_mnem("stxdw"), 8);
        assert_eq!(BpfLifter::size_from_mnem("stxb"), 1);
    }
}
