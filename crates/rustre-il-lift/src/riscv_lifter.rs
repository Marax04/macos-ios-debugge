//! RISC-V LLIL lifter â€” supports RV32I, RV64I, RV32M, RV64M and common
//! pseudo-instructions.
//!
//! The lifter is mnemonic-driven: it parses the `mnemonic` string and the
//! comma-separated `operands` text from the [`Instruction`] struct rather than
//! decoding raw bytes, making it independent of any particular RISC-V
//! disassembler frontend.
//!
//! # Architecture overview
//!
//! RISC-V uses a simple three-operand (destination, source1, source2) or
//! two-operand (destination, immediate) encoding.  The 32-bit (RV32I) and
//! 64-bit (RV64I) integer base ISAs are handled; the M-extension (multiply /
//! divide / remainder) is partially handled with real `Mul` nodes for MUL and
//! `Intrinsic` for DIV/REM since the IR has no native division node.
//!
//! ## Register ABI names
//!
//! | x register | ABI name |
//! |-----------|----------|
//! | x0        | zero     |
//! | x1        | ra       |
//! | x2        | sp       |
//! | x3        | gp       |
//! | x4        | tp       |
//! | x5â€“x7     | t0â€“t2    |
//! | x8        | s0 / fp  |
//! | x9        | s1       |
//! | x10â€“x11   | a0â€“a1    |
//! | x12â€“x17   | a2â€“a7    |
//! | x18â€“x27   | s2â€“s11   |
//! | x28â€“x31   | t3â€“t6    |

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// RiscvLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A mnemonic-driven LLIL lifter for RISC-V (RV32I / RV64I + M-extension).
///
/// # Usage
///
/// ```no_run
/// use rustre_il_lift::riscv_lifter::RiscvLifter;
///
/// let lifter32 = RiscvLifter::new();       // RV32I
/// let lifter64 = RiscvLifter::new_rv64();  // RV64I
/// ```
#[derive(Debug, Clone)]
pub struct RiscvLifter {
    /// Pointer width in bits: 32 or 64.
    pub bits: u32,
}

impl RiscvLifter {
    /// Create a new RV32I lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: 32 }
    }

    /// Create a new RV64I lifter.
    #[must_use]
    pub const fn new_rv64() -> Self {
        Self { bits: 64 }
    }

    // â”€â”€ register helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Normalize a register name token to its ABI name.
    ///
    /// Strips optional `%` prefixes, lower-cases, and maps `xN` registers to
    /// their ABI names (e.g. `x10` â†’ `a0`).
    #[must_use]
    fn norm_reg(raw: &str) -> String {
        let s = raw.trim().trim_start_matches('%').to_ascii_lowercase();
        // Map architectural register names to ABI names.
        match s.as_str() {
            "x0" | "zero" => "zero".to_string(),
            "x1" | "ra" => "ra".to_string(),
            "x2" | "sp" => "sp".to_string(),
            "x3" | "gp" => "gp".to_string(),
            "x4" | "tp" => "tp".to_string(),
            "x5" | "t0" => "t0".to_string(),
            "x6" | "t1" => "t1".to_string(),
            "x7" | "t2" => "t2".to_string(),
            "x8" | "s0" | "fp" => "s0".to_string(),
            "x9" | "s1" => "s1".to_string(),
            "x10" | "a0" => "a0".to_string(),
            "x11" | "a1" => "a1".to_string(),
            "x12" | "a2" => "a2".to_string(),
            "x13" | "a3" => "a3".to_string(),
            "x14" | "a4" => "a4".to_string(),
            "x15" | "a5" => "a5".to_string(),
            "x16" | "a6" => "a6".to_string(),
            "x17" | "a7" => "a7".to_string(),
            "x18" | "s2" => "s2".to_string(),
            "x19" | "s3" => "s3".to_string(),
            "x20" | "s4" => "s4".to_string(),
            "x21" | "s5" => "s5".to_string(),
            "x22" | "s6" => "s6".to_string(),
            "x23" | "s7" => "s7".to_string(),
            "x24" | "s8" => "s8".to_string(),
            "x25" | "s9" => "s9".to_string(),
            "x26" | "s10" => "s10".to_string(),
            "x27" | "s11" => "s11".to_string(),
            "x28" | "t3" => "t3".to_string(),
            "x29" | "t4" => "t4".to_string(),
            "x30" | "t5" => "t5".to_string(),
            "x31" | "t6" => "t6".to_string(),
            other => other.to_string(),
        }
    }

    /// Return `true` if `name` (after normalization) is the zero register.
    fn is_zero(name: &str) -> bool {
        let n = Self::norm_reg(name);
        n == "zero" || n == "x0"
    }

    /// Build an [`IrExpr`] for a register token.
    ///
    /// If the register is `zero` / `x0` the expression is `Const(0)`.
    fn reg_expr(name: &str) -> IrExpr {
        let n = Self::norm_reg(name);
        if n == "zero" {
            IrExpr::Const(0)
        } else {
            IrExpr::Reg(n)
        }
    }

    // â”€â”€ operand parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Parse an immediate token.
    ///
    /// Accepts `#N`, `0xN`, `-N`, plain decimal, or `%lo(N)` / `%hi(N)` forms.
    /// Returns `None` for tokens that do not look like integer constants.
    fn parse_imm(tok: &str) -> Option<i64> {
        let t = tok.trim().trim_start_matches('#');

        // Handle %lo(...) / %hi(...) / %pcrel_lo(...) etc.
        if let Some(inner) = t.strip_prefix('%')
            && let Some(idx) = inner.find('(') {
                let content = &inner[idx + 1..].trim_end_matches(')');
                return Self::parse_imm(content);
            }

        // Hex
        if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            return i64::from_str_radix(hex, 16)
                .ok()
                .or_else(|| u64::from_str_radix(hex, 16).ok().map(u64::cast_signed));
        }
        // Negative hex
        if let Some(rest) = t.strip_prefix('-')
            && let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
                return i64::from_str_radix(hex, 16).ok().map(|v| -v);
            }
        // Decimal
        t.parse::<i64>().ok()
    }

    /// Parse a `base + offset` memory operand written as `offset(base)`.
    ///
    /// Returns `(base_expr, offset_expr, byte_size)` or `None` if the token
    /// does not match the `offset(base)` pattern.
    fn parse_mem_operand(tok: &str) -> Option<(IrExpr, Option<IrExpr>)> {
        // Pattern: `<offset>(<reg>)`  where <offset> may be empty.
        let t = tok.trim();
        if let Some(paren_pos) = t.rfind('(') {
            let off_str = &t[..paren_pos];
            let reg_str = t[paren_pos + 1..].trim_end_matches(')');
            let base_expr = Self::reg_expr(reg_str);
            let off_expr = if off_str.trim().is_empty() || off_str.trim() == "0" {
                None
            } else {
                Self::parse_imm(off_str).map(|v| match v.cmp(&0) {
                    std::cmp::Ordering::Equal => {
                        // Skip zero offset
                        IrExpr::Const(0)
                    }
                    std::cmp::Ordering::Less => IrExpr::Sub(
                        Box::new(IrExpr::Const(0)), // placeholder; will be overridden
                        Box::new(IrExpr::Const(v.unsigned_abs())),
                    ),
                    std::cmp::Ordering::Greater => IrExpr::Const(v.cast_unsigned()),
                })
            };
            return Some((base_expr, off_expr));
        }
        None
    }

    /// Build an effective address expression from a memory operand token.
    ///
    /// Returns `(addr_expr, size_bytes)`.
    fn mem_addr_and_size(tok: &str, default_size: u8) -> (IrExpr, u8) {
        match Self::parse_mem_operand(tok) {
            Some((base, Some(off))) => {
                // Handle negative offsets correctly
                let addr = if let IrExpr::Sub(_, rhs) = &off {
                    IrExpr::Sub(Box::new(base), rhs.clone())
                } else if off == IrExpr::Const(0) {
                    base
                } else {
                    IrExpr::Add(Box::new(base), Box::new(off))
                };
                (addr, default_size)
            }
            Some((base, None)) => (base, default_size),
            None => {
                // Fallback: treat token as a plain register
                (Self::reg_expr(tok), default_size)
            }
        }
    }

    // â”€â”€ tokeniser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Split the operand string `instr.operands` into individual tokens.
    ///
    /// Tokens are separated by commas; whitespace is trimmed.  Parenthesised
    /// memory operands like `8(sp)` are kept as a single token even if they
    /// contain a comma internally (there is no comma inside RISC-V memory refs
    /// in standard disassembly, but we handle edge cases defensively).
    fn split_operands(operands_str: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = String::new();
        let mut depth = 0usize;
        for ch in operands_str.chars() {
            match ch {
                '(' => {
                    depth += 1;
                    current.push(ch);
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                    current.push(ch);
                }
                ',' if depth == 0 => {
                    let t = current.trim().to_string();
                    if !t.is_empty() {
                        result.push(t);
                    }
                    current.clear();
                }
                _ => {
                    current.push(ch);
                }
            }
        }
        let t = current.trim().to_string();
        if !t.is_empty() {
            result.push(t);
        }
        result
    }

    /// Tokenise an instruction into `(mnemonic_lower, operand_tokens)`.
    ///
    /// Also attempts to extract operand strings from the structured
    /// `operand_list`, falling back to the text `operands` field.
    fn tokenise(instr: &Instruction) -> (String, Vec<String>) {
        let mnem = instr.mnemonic.to_ascii_lowercase();

        // Prefer the text operands field (it is always present in RISC-V output
        // from standard disassemblers like objdump / LLVM).
        let ops = if instr.operands.is_empty() {
            // Fall back to structured operand list via Display.
            instr.operand_list.iter().map(|o| format!("{o}")).collect::<Vec<_>>()
        } else {
            Self::split_operands(&instr.operands)
        };

        (mnem, ops)
    }

    // â”€â”€ per-mnemonic helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Lift arithmetic R-type: `rd = rs1 OP rs2`.
    fn lift_arith_r(ops: &[&str], make: impl Fn(IrExpr, IrExpr) -> IrExpr) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "arith_r_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            // Write to x0 is a no-op.
            return vec![];
        }
        let rs1 = Self::reg_expr(ops[1]);
        let rs2 = Self::reg_expr(ops[2]);
        vec![Effect::RegWrite {
            reg: rd,
            value: make(rs1, rs2),
        }]
    }

    /// Lift arithmetic I-type: `rd = rs1 OP imm`.
    fn lift_arith_i(ops: &[&str], make: impl Fn(IrExpr, IrExpr) -> IrExpr) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "arith_i_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs1 = Self::reg_expr(ops[1]);
        let imm_val = Self::parse_imm(ops[2]).unwrap_or(0);
        let imm = IrExpr::Const(imm_val.cast_unsigned());
        vec![Effect::RegWrite {
            reg: rd,
            value: make(rs1, imm),
        }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Integer arithmetic
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// ADD / ADDW : `rd = rs1 + rs2`
    /// Sign-extend a 32-bit result into the full register, the way RISC-V
    /// defines every `w`-suffixed operation on RV64.
    ///
    /// `ADDW`/`SUBW` compute a 32-bit sum and then SIGN-EXTEND bit 31 through
    /// bits 63..32. They shared a handler with the full-width `ADD`/`SUB`, so
    /// the low half was right and the high half was whatever the 64-bit
    /// arithmetic happened to produce — silently wrong whenever the 32-bit
    /// result is negative.
    ///
    /// Same width class as `SRAW`/`SRAIW` (iteration 54) and the same idiom:
    /// shift the value up so bit 31 lands on bit 63, then shift back
    /// arithmetically. No new node needed.
    fn sext32_result(value: IrExpr) -> IrExpr {
        IrExpr::Sar(
            Box::new(IrExpr::Shl(Box::new(value), Box::new(IrExpr::Const(32)))),
            Box::new(IrExpr::Const(32)),
        )
    }

    /// `ADDW` — 32-bit add, result sign-extended. See `sext32_result`.
    /// `ADDIW` — 32-bit add-immediate, result sign-extended. Same class as
    /// `ADDW`; it shared a handler with the full-width `ADDI`.
    /// `SLLW`/`SLLIW` — 32-bit left shift, result sign-extended.
    ///
    /// The left shift needs no pre-truncation: `sext32_result` keeps only the
    /// low 32 bits before extending, so anything shifted above bit 31 is
    /// discarded exactly as the hardware discards it.
    fn lift_sllw(ops: &[&str], imm: bool) -> Vec<Effect> {
        if imm {
            Self::lift_arith_i(ops, |a, b| {
                Self::sext32_result(IrExpr::Shl(Box::new(a), Box::new(b)))
            })
        } else {
            Self::lift_arith_r(ops, |a, b| {
                Self::sext32_result(IrExpr::Shl(
                    Box::new(a),
                    Box::new(Self::mask_shift_count(b, 31)),
                ))
            })
        }
    }

    /// `SRLW`/`SRLIW` — 32-bit LOGICAL right shift, result sign-extended.
    ///
    /// Unlike the left shift this one MUST truncate first: a right shift of the
    /// full 64-bit register would pull the upper half's bits down into the
    /// result. Mask to 32 bits, shift, then sign-extend — which is why this is
    /// not simply `sext32_result(a >> b)`.
    fn lift_srlw(ops: &[&str], imm: bool) -> Vec<Effect> {
        if imm {
            Self::lift_arith_i(ops, |a, b| {
                let low32 = IrExpr::And(Box::new(a), Box::new(IrExpr::Const(0xFFFF_FFFF)));
                Self::sext32_result(IrExpr::Shr(Box::new(low32), Box::new(b)))
            })
        } else {
            Self::lift_arith_r(ops, |a, b| {
                let low32 = IrExpr::And(Box::new(a), Box::new(IrExpr::Const(0xFFFF_FFFF)));
                Self::sext32_result(IrExpr::Shr(
                    Box::new(low32),
                    Box::new(Self::mask_shift_count(b, 31)),
                ))
            })
        }
    }

    fn lift_addiw(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| {
            Self::sext32_result(IrExpr::Add(Box::new(a), Box::new(b)))
        })
    }

    fn lift_addw(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| {
            Self::sext32_result(IrExpr::Add(Box::new(a), Box::new(b)))
        })
    }

    /// `SUBW` / `C.SUBW` — 32-bit subtract, result sign-extended.
    fn lift_subw(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| {
            Self::sext32_result(IrExpr::Sub(Box::new(a), Box::new(b)))
        })
    }

    fn lift_add(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| IrExpr::Add(Box::new(a), Box::new(b)))
    }

    /// ADDI / ADDIW : `rd = rs1 + imm`
    fn lift_addi(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "addi_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs1_raw = ops[1];
        let imm_str = ops[2];
        let imm_val = Self::parse_imm(imm_str).unwrap_or(0);

        // RISC-V pseudo: MV  rd, rs1   â‰¡  ADDI rd, rs1, 0
        if imm_val == 0 {
            return vec![Effect::RegWrite {
                reg: rd,
                value: Self::reg_expr(rs1_raw),
            }];
        }

        // RISC-V pseudo: LI rd, imm  â‰¡  ADDI rd, x0, imm
        if Self::is_zero(rs1_raw) {
            return vec![Effect::RegWrite {
                reg: rd,
                value: IrExpr::Const(imm_val.cast_unsigned()),
            }];
        }

        let rs1 = Self::reg_expr(rs1_raw);
        let imm = IrExpr::Const(imm_val.cast_unsigned());
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Add(Box::new(rs1), Box::new(imm)),
        }]
    }

    /// SUB / SUBW : `rd = rs1 - rs2`
    fn lift_sub(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| IrExpr::Sub(Box::new(a), Box::new(b)))
    }

    /// AND / ANDI : `rd = rs1 & rs2/imm`
    fn lift_and(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| IrExpr::And(Box::new(a), Box::new(b)))
    }

    fn lift_andi(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| IrExpr::And(Box::new(a), Box::new(b)))
    }

    /// OR / ORI : `rd = rs1 | rs2/imm`
    fn lift_or(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| IrExpr::Or(Box::new(a), Box::new(b)))
    }

    fn lift_ori(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| IrExpr::Or(Box::new(a), Box::new(b)))
    }

    /// XOR / XORI : `rd = rs1 ^ rs2/imm`
    fn lift_xor(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| IrExpr::Xor(Box::new(a), Box::new(b)))
    }

    fn lift_xori(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| IrExpr::Xor(Box::new(a), Box::new(b)))
    }

    /// SLL / SLLW / SLLI / SLLIW : `rd = rs1 << rs2/imm`
    /// Mask a REGISTER-supplied shift count to the bits the ISA actually reads.
    ///
    /// RISC-V takes `rs2[4:0]` on RV32 and `rs2[5:0]` on RV64 for the full-width
    /// shifts, and always `rs2[4:0]` for the 32-bit `W` forms. The count came
    /// through raw, so a register holding 64 shifted by 64 in the IL and by 0
    /// on the machine.
    ///
    /// Only the REGISTER forms need this: `slli`, `sraiw` and friends encode
    /// their `shamt` in a 5- or 6-bit field, so it cannot be out of range.
    /// Masking those would add noise, not correctness — which is why the `W`
    /// handlers apply it on the `lift_arith_r` path only.
    fn mask_shift_count(count: IrExpr, mask: u64) -> IrExpr {
        IrExpr::And(Box::new(count), Box::new(IrExpr::Const(mask)))
    }

    fn lift_sll(ops: &[&str], bits: u32) -> Vec<Effect> {
        let m = u64::from(bits) - 1;
        Self::lift_arith_r(ops, move |a, b| {
            IrExpr::Shl(Box::new(a), Box::new(Self::mask_shift_count(b, m)))
        })
    }

    fn lift_slli(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| IrExpr::Shl(Box::new(a), Box::new(b)))
    }

    /// SRL / SRLW / SRLI / SRLIW : `rd = rs1 >> rs2/imm` (logical)
    fn lift_srl(ops: &[&str], bits: u32) -> Vec<Effect> {
        let m = u64::from(bits) - 1;
        Self::lift_arith_r(ops, move |a, b| {
            IrExpr::Shr(Box::new(a), Box::new(Self::mask_shift_count(b, m)))
        })
    }

    fn lift_srli(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| IrExpr::Shr(Box::new(a), Box::new(b)))
    }

    /// SRA / SRAW / SRAI / SRAIW : arithmetic right shift.
    ///
    /// The IR has no dedicated arithmetic shift node; we reuse `Shr` and note
    /// that analysis passes should check the original mnemonic.
    /// `SRA` — shift right ARITHMETIC, full register width.
    fn lift_sra(ops: &[&str], bits: u32) -> Vec<Effect> {
        let m = u64::from(bits) - 1;
        Self::lift_arith_r(ops, move |a, b| {
            IrExpr::Sar(Box::new(a), Box::new(Self::mask_shift_count(b, m)))
        })
    }

    /// `SRAW` — the 32-BIT arithmetic shift on RV64.
    ///
    /// `Sar` reads the sign from bit 63, so applying it to a 32-bit value would
    /// fill with the wrong bit — the same width trap already corrected in the
    /// MIPS lifter. The `w` suffix in RISC-V marks exactly this: a 32-bit
    /// operation on a 64-bit machine.
    ///
    /// Expressed with existing nodes: shift the value up so its sign lands on
    /// bit 63, then shift back arithmetically by `32 + n`. RISC-V defines the
    /// result of the `w` forms to be sign-extended into the upper half, which
    /// is what this produces.
    fn lift_sraw(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| {
            IrExpr::Sar(
                Box::new(IrExpr::Shl(Box::new(a), Box::new(IrExpr::Const(32)))),
                // The count is rs2[4:0]. Mask BEFORE the +32 that lifts the
                // value into the upper half, or the mask would clip the total.
                Box::new(IrExpr::Add(
                    Box::new(Self::mask_shift_count(b, 31)),
                    Box::new(IrExpr::Const(32)),
                )),
            )
        })
    }

    /// `SRAI` — immediate form, full register width.
    fn lift_srai(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| IrExpr::Sar(Box::new(a), Box::new(b)))
    }

    /// `SRAIW` — 32-bit immediate arithmetic shift; see `lift_sraw`.
    fn lift_sraiw(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_i(ops, |a, b| {
            IrExpr::Sar(
                Box::new(IrExpr::Shl(Box::new(a), Box::new(IrExpr::Const(32)))),
                Box::new(IrExpr::Add(Box::new(b), Box::new(IrExpr::Const(32)))),
            )
        })
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Multiply / divide (M-extension)
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// MUL / MULW : `rd = rs1 * rs2`
    /// `MULW` — 32-bit multiply, result sign-extended into the upper half.
    ///
    /// It shared a handler with the full-width `MUL`, so the low 32 bits were
    /// right and bits 63..32 held whatever the 64-bit product produced — wrong
    /// for every negative 32-bit result, the same class as `ADDW`/`SUBW`.
    ///
    /// The low half needs no pre-truncation: the low 32 bits of a product
    /// depend only on the low 32 bits of the operands, so `sext32_result` on
    /// the full product is exact. (This is NOT true of the right shift, which
    /// is why `SRLW` masks first — worth stating because the two look alike.)
    fn lift_mulw(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| {
            Self::sext32_result(IrExpr::Mul(Box::new(a), Box::new(b)))
        })
    }

    fn lift_mul(ops: &[&str]) -> Vec<Effect> {
        Self::lift_arith_r(ops, |a, b| IrExpr::Mul(Box::new(a), Box::new(b)))
    }

    /// MULH / MULHU / MULHSU : upper half of multiply â€” Intrinsic.
    fn lift_mulh(mnem: &str, ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs1 = Self::reg_expr(ops[1]);
        let rs2 = Self::reg_expr(ops[2]);
        vec![Effect::Intrinsic {
            name: mnem.to_string(),
            args: vec![IrExpr::Reg(rd), rs1, rs2],
        }]
    }

    /// DIV / DIVU / DIVW / DIVUW : integer division â€” no native IR node.
    fn lift_div(mnem: &str, ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs1 = Self::reg_expr(ops[1]);
        let rs2 = Self::reg_expr(ops[2]);
        vec![Effect::Intrinsic {
            name: mnem.to_string(),
            args: vec![IrExpr::Reg(rd), rs1, rs2],
        }]
    }

    /// REM / REMU / REMW / REMUW : remainder â€” no native IR node.
    fn lift_rem(mnem: &str, ops: &[&str]) -> Vec<Effect> {
        Self::lift_div(mnem, ops)
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Set-less-than
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// SLT / SLTU / SLTI / SLTIU : `rd = (rs1 < rs2) ? 1 : 0`
    ///
    /// Represented as `CmpEqZero(Sub(rs1, rs2)) == 0` would be wrong for < ;
    /// instead we use an Intrinsic with the operands embedded for analysis
    /// passes that understand it, or emit a Sub with a note.
    /// For simplicity we emit: `rd = __slt(rs1, rs2)`.
    fn lift_slt(mnem: &str, ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let a = Self::reg_expr(ops[1]);
        let b = if mnem.ends_with('i') {
            let v = Self::parse_imm(ops[2]).unwrap_or(0);
            IrExpr::Const(v.cast_unsigned())
        } else {
            Self::reg_expr(ops[2])
        };
        // Was an opaque `Effect::Intrinsic` carrying the mnemonic. That was
        // FAITHFUL — the mnemonic kept `slt` and `sltu` distinguishable, so no
        // fact was lost — but it was not ANALYSABLE: no pass could see a
        // comparison, only an unknown intrinsic.
        //
        // (The comment that used to sit here described a sign-of-difference
        // encoding the code did not implement. A comment describing code that
        // does something else is worth deleting on sight.)
        //
        // Now that the IR distinguishes signed from unsigned less-than, emit
        // the real comparison. `sltu`/`sltiu` are the UNSIGNED forms; note that
        // `sltiu` still sign-extends its immediate before comparing unsigned,
        // which is why the immediate is built the same way for both.
        let unsigned = mnem.ends_with('u');
        let cmp = if unsigned {
            IrExpr::CmpLtU(Box::new(a), Box::new(b))
        } else {
            IrExpr::CmpLt(Box::new(a), Box::new(b))
        };
        vec![Effect::RegWrite { reg: rd, value: cmp }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Upper-immediate
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// LUI : `rd = imm << 12` (upper 20 bits)
    fn lift_lui(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "lui_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let imm_val = Self::parse_imm(ops[1]).unwrap_or(0);
        // LUI stores the immediate already shifted: rd = imm << 12
        let shifted = imm_val.cast_unsigned() << 12;
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Const(shifted),
        }]
    }

    /// AUIPC : `rd = PC + (imm << 12)`
    fn lift_auipc(ops: &[&str], pc: u64) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "auipc_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let imm_val = Self::parse_imm(ops[1]).unwrap_or(0);
        let offset = imm_val.cast_unsigned() << 12;
        let target = pc.wrapping_add(offset);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Const(target),
        }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Memory loads
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Generic load: `rd = *addr:size`
    /// RISC-V loads. `LB`/`LH`/`LW` SIGN-extend the loaded value into the
    /// destination register; `LBU`/`LHU`/`LWU` ZERO-extend it. The two forms
    /// shared this handler, which took only a size, so a loaded `0xFF` was
    /// indistinguishable between `-1` and `255` — silent wrong values, not a
    /// lost optimisation.
    ///
    /// Modelled with the `sextN` intrinsic marker already used by the PowerPC
    /// lifter for `LHA` (its comment notes `IrExpr` has no sign-extend node).
    /// Following the existing precedent keeps one convention in the crate
    /// rather than inventing a second one; the missing node is recorded as a
    /// separate item.
    fn lift_load(ops: &[&str], size: u8, signed: bool) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "load_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let (addr, sz) = Self::mem_addr_and_size(ops[1], size);
        let mut out = vec![Effect::MemRead {
            addr,
            dest: rd.clone(),
            size: sz,
        }];
        // A full-width load needs no extension at all.
        if signed && u32::from(sz) * 8 < 64 {
            out.push(Effect::Intrinsic {
                name: format!("sext{}", u32::from(sz) * 8),
                args: vec![IrExpr::Reg(rd)],
            });
        }
        out
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Memory stores
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Generic store: `*addr:size = rs2`
    fn lift_store(ops: &[&str], size: u8) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "store_bad_ops".into(),
                args: vec![],
            }];
        }
        let src_expr = Self::reg_expr(ops[0]);
        let (addr, sz) = Self::mem_addr_and_size(ops[1], size);
        vec![Effect::MemWrite {
            addr,
            value: src_expr,
            size: sz,
        }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Branches
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Resolve a branch target token.
    ///
    /// Priority: label (0x-prefixed absolute address), then PC-relative offset.
    fn branch_target(tok: &str, pc: u64, instr_size: usize) -> IrExpr {
        let t = tok.trim();
        // Try parsing as absolute address (hex or decimal that looks like a code address).
        if let Some(v) = Self::parse_imm(t) {
            let abs = v.cast_unsigned();
            // Heuristic: if > 0x1000, treat as absolute target; else as PC-relative.
            if abs >= 0x1000 || t.starts_with("0x") || t.starts_with("0X") {
                return IrExpr::Const(abs);
            }
            // PC-relative signed offset
            let next_pc = pc.wrapping_add(instr_size as u64);
            return IrExpr::Const(next_pc.wrapping_add(abs));
        }
        // Symbolic label â€” return Undef (resolved later by the pipeline).
        IrExpr::Undef
    }

    /// BEQ : `if rs1 == rs2 goto target`  â†’  `CmpEqZero(rs1 - rs2)`
    fn lift_beq(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "beq_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs1 = Self::reg_expr(ops[0]);
        let rs2 = Self::reg_expr(ops[1]);
        let target = Self::branch_target(ops[2], pc, instr_size);
        let diff = IrExpr::Sub(Box::new(rs1), Box::new(rs2));
        let cond = IrExpr::CmpEqZero(Box::new(diff));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BNE : `if rs1 != rs2 goto target`  â†’  `Not(CmpEqZero(rs1 - rs2))`
    fn lift_bne(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "bne_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs1 = Self::reg_expr(ops[0]);
        let rs2 = Self::reg_expr(ops[1]);
        let target = Self::branch_target(ops[2], pc, instr_size);
        let diff = IrExpr::Sub(Box::new(rs1), Box::new(rs2));
        let cond = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(diff))));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BLT : `if (signed)rs1 < rs2 goto target`
    fn lift_blt(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "blt_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs1 = Self::reg_expr(ops[0]);
        let rs2 = Self::reg_expr(ops[1]);
        let target = Self::branch_target(ops[2], pc, instr_size);
        // Was "(rs1 - rs2) sign bit", which is WRONG whenever the subtraction
        // overflows: for rs1 = INT64_MIN, rs2 = 1 the difference wraps to a
        // positive value and the sign bit reads 0, so the branch was lifted as
        // "not less than" when rs1 really is less. This is the exact reason
        // hardware tests SF != OF rather than SF alone. It also hard-coded a
        // shift of 63, silently assuming RV64 in a lifter that also serves RV32.
        let cond = IrExpr::CmpLt(Box::new(rs1), Box::new(rs2));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BGE : `if (signed)rs1 >= rs2 goto target`
    fn lift_bge(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "bge_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs1 = Self::reg_expr(ops[0]);
        let rs2 = Self::reg_expr(ops[1]);
        let target = Self::branch_target(ops[2], pc, instr_size);
        // rs1 >= rs2  ==  NOT(rs1 < rs2). Same overflow defect as BLT above:
        // the sign-of-difference encoding misreads the overflowing cases.
        let lt = IrExpr::CmpLt(Box::new(rs1), Box::new(rs2));
        let cond = IrExpr::CmpEqZero(Box::new(lt));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BLTU : `if (unsigned)rs1 < rs2 goto target`
    ///
    /// The old encoding was an `Intrinsic` effect naming a synthetic condition
    /// register `__bltu_cond`, justified by "the IR has no unsigned-less-than
    /// node". `IrExpr::CmpLtU` exists now, and the workaround had two defects
    /// beyond being opaque:
    ///
    /// * the register name was a FIXED string, so two `bltu` in one block
    ///   defined the same condition register and the second silently won;
    /// * an `Intrinsic` effect does not WRITE a register, so the branch read a
    ///   condition nothing in the IR ever defined.
    ///
    /// The comment also promised that "downstream passes can reconstruct the
    /// full semantics" — no pass anywhere consumes `bltu_cond`.
    fn lift_bltu(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "bltu_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs1 = Self::reg_expr(ops[0]);
        let rs2 = Self::reg_expr(ops[1]);
        let target = Self::branch_target(ops[2], pc, instr_size);
        let cond = IrExpr::CmpLtU(Box::new(rs1), Box::new(rs2));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BGEU : `if (unsigned)rs1 >= rs2 goto target`, i.e. NOT(rs1 <u rs2).
    /// Carried the same defective synthetic-register encoding as BLTU.
    fn lift_bgeu(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: "bgeu_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs1 = Self::reg_expr(ops[0]);
        let rs2 = Self::reg_expr(ops[1]);
        let target = Self::branch_target(ops[2], pc, instr_size);
        let lt = IrExpr::CmpLtU(Box::new(rs1), Box::new(rs2));
        vec![Effect::Branch {
            target,
            condition: Some(IrExpr::CmpEqZero(Box::new(lt))),
        }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Jump and link
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// JAL `rd, offset` : if rd != x0 this is a call (saves return addr in rd).
    fn lift_jal(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        // Two forms:
        //   JAL rd, offset  â€” explicit rd
        //   J   offset      â€” pseudo (rd = x0)
        let (rd, offset_str) = match ops.len() {
            0 => {
                return vec![Effect::Intrinsic {
                    name: "jal_bad_ops".into(),
                    args: vec![],
                }];
            }
            1 => ("zero", ops[0]),
            _ => (ops[0], ops[1]),
        };
        let rd_norm = Self::norm_reg(rd);
        let target = Self::branch_target(offset_str, pc, instr_size);
        let ret_addr = pc.wrapping_add(instr_size as u64);

        if rd_norm == "zero" {
            // J pseudo: unconditional branch, no return address saved.
            vec![Effect::Branch {
                target,
                condition: None,
            }]
        } else if rd_norm == "ra" {
            // Conventional call: ra = PC+4; call target
            vec![
                Effect::RegWrite {
                    reg: rd_norm,
                    value: IrExpr::Const(ret_addr),
                },
                Effect::Call { target },
            ]
        } else {
            // Unusual rd (e.g. t0): still a call semantically if branching to a
            // function.  Save return address and branch.
            vec![
                Effect::RegWrite {
                    reg: rd_norm,
                    value: IrExpr::Const(ret_addr),
                },
                Effect::Call { target },
            ]
        }
    }

    /// JALR `rd, rs1, imm` : indirect call/branch/return.
    ///
    /// - `JALR x0, 0(ra)` = RET
    /// - `JALR ra, 0(rs1)` or `JALR ra, rs1, 0` = indirect call
    /// - Anything else = indirect jump with optional link
    fn lift_jalr(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        // JALR has several textual forms depending on the disassembler:
        //  (1) jalr rd, rs1, imm   (3 operands)
        //  (2) jalr rd, imm(rs1)  (2 operands â€” memory-like syntax)
        //  (3) jalr rs1           (1 operand â€” pseudo: jalr x0, 0(rs1))
        //  (4) ret                (handled separately)
        let (rd_str, target_expr) = match ops.len() {
            0 => {
                return vec![Effect::Intrinsic {
                    name: "jalr_bad_ops".into(),
                    args: vec![],
                }];
            }
            1 => {
                // jalr rs1  â†’  jalr x0, 0(rs1)
                let t = IrExpr::Reg(Self::norm_reg(ops[0]));
                ("zero", t)
            }
            2 => {
                // jalr rd, imm(rs1)  OR  jalr rd, rs1
                let rd = ops[0];
                if ops[1].contains('(') {
                    // Memory-like syntax: imm(rs1)
                    let (base, off) =
                        Self::parse_mem_operand(ops[1]).unwrap_or((IrExpr::Undef, None));
                    let t = match off {
                        Some(o) => IrExpr::Add(Box::new(base), Box::new(o)),
                        None => base,
                    };
                    (rd, t)
                } else {
                    // jalr rd, rs1  (implicit imm=0)
                    (rd, IrExpr::Reg(Self::norm_reg(ops[1])))
                }
            }
            _ => {
                // jalr rd, rs1, imm
                let rd = ops[0];
                let rs1 = Self::reg_expr(ops[1]);
                let imm_val = Self::parse_imm(ops[2]).unwrap_or(0);
                let t = if imm_val == 0 {
                    rs1
                } else {
                    IrExpr::Add(Box::new(rs1), Box::new(IrExpr::Const(imm_val.cast_unsigned())))
                };
                (rd, t)
            }
        };

        let rd_norm = Self::norm_reg(rd_str);
        let ret_addr = pc.wrapping_add(instr_size as u64);

        // Detect RET: jalr x0, 0(ra)  or  jalr x0, ra
        let is_return = rd_norm == "zero"
            && matches!(&target_expr,
                IrExpr::Reg(r) if r == "ra"
            );

        if is_return {
            return vec![Effect::Return {
                value: Some(IrExpr::Reg("a0".to_string())),
            }];
        }

        if rd_norm == "zero" {
            // Indirect branch (tail call or computed goto)
            vec![Effect::Branch {
                target: target_expr,
                condition: None,
            }]
        } else {
            // Indirect call: save return address in rd and call.
            vec![
                Effect::RegWrite {
                    reg: rd_norm,
                    value: IrExpr::Const(ret_addr),
                },
                Effect::Call {
                    target: target_expr,
                },
            ]
        }
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Environment calls
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// ECALL â€” system call; syscall number in a7.
    fn lift_ecall() -> Vec<Effect> {
        vec![Effect::Syscall {
            nr: IrExpr::Reg("a7".to_string()),
        }]
    }

    /// EBREAK â€” debugger breakpoint intrinsic.
    fn lift_ebreak() -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: "ebreak".to_string(),
            args: vec![],
        }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Pseudo-instructions
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// RET pseudo : `jalr x0, 0(ra)` â†’ `return a0`
    fn lift_ret() -> Vec<Effect> {
        vec![Effect::Return {
            value: Some(IrExpr::Reg("a0".to_string())),
        }]
    }

    /// MV pseudo : `addi rd, rs, 0` â†’ `rd = rs`
    fn lift_mv(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "mv_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let src = Self::reg_expr(ops[1]);
        vec![Effect::RegWrite {
            reg: rd,
            value: src,
        }]
    }

    /// LI pseudo : `addi rd, x0, imm` â†’ `rd = imm`
    fn lift_li(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "li_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let imm_val = Self::parse_imm(ops[1]).unwrap_or(0);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Const(imm_val.cast_unsigned()),
        }]
    }

    /// NEG pseudo : `sub rd, x0, rs` â†’ `rd = 0 - rs`
    fn lift_neg(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "neg_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs = Self::reg_expr(ops[1]);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(rs)),
        }]
    }

    /// NOT pseudo : `xori rd, rs, -1` â†’ `rd = ~rs`
    fn lift_not(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "not_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs = Self::reg_expr(ops[1]);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Not(Box::new(rs)),
        }]
    }

    /// SEQZ pseudo : `sltiu rd, rs, 1` â†’ `rd = (rs == 0) ? 1 : 0`
    fn lift_seqz(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "seqz_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs = Self::reg_expr(ops[1]);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::CmpEqZero(Box::new(rs)),
        }]
    }

    /// SNEZ pseudo : `sltu rd, x0, rs` â†’ `rd = (rs != 0) ? 1 : 0`
    fn lift_snez(ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "snez_bad_ops".into(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        if rd == "zero" {
            return vec![];
        }
        let rs = Self::reg_expr(ops[1]);
        vec![Effect::RegWrite {
            reg: rd,
            value: IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(rs)))),
        }]
    }

    /// BEQZ pseudo : `beq rs, x0, offset`
    fn lift_beqz(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "beqz_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs = Self::reg_expr(ops[0]);
        let target = Self::branch_target(ops[1], pc, instr_size);
        let cond = IrExpr::CmpEqZero(Box::new(rs));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BNEZ pseudo : `bne rs, x0, offset`
    fn lift_bnez(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "bnez_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs = Self::reg_expr(ops[0]);
        let target = Self::branch_target(ops[1], pc, instr_size);
        let cond = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(rs))));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BLEZ pseudo : `bge x0, rs, offset`
    fn lift_blez(ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "blez_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs = Self::reg_expr(ops[0]);
        let target = Self::branch_target(ops[1], pc, instr_size);
        // These four compare against ZERO, so unlike BLT/BGE there is no
        // subtraction and the sign-bit encoding is sound — a real difference
        // from the overflow defect fixed above, not the same bug again.
        //
        // The sign bit's POSITION was wrong though: it was hard-coded to 63
        // while `RiscvLifter::new()` builds an RV32 lifter and the registry
        // maps both "riscv" and "riscv32" onto it. Reading bit 63 of a 32-bit
        // value always yields 0, so on RV32 `bgez` was always taken, `bltz`
        // never, `blez` collapsed to `== 0` and `bgtz` to `!= 0`.
        // rs <= 0  ==  rs < 0 OR rs == 0
        // rs < 0: sign bit set; rs == 0: CmpEqZero
        let sign = IrExpr::Shr(Box::new(rs.clone()), Box::new(IrExpr::Const(u64::from(bits - 1))));
        let sign_bit = IrExpr::And(Box::new(sign), Box::new(IrExpr::Const(1)));
        let is_zero = IrExpr::CmpEqZero(Box::new(rs));
        let cond = IrExpr::Or(Box::new(sign_bit), Box::new(is_zero));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BGEZ pseudo : `bge rs, x0, offset`
    fn lift_bgez(ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "bgez_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs = Self::reg_expr(ops[0]);
        let target = Self::branch_target(ops[1], pc, instr_size);
        // rs >= 0  â‰¡  sign bit == 0
        let sign = IrExpr::Shr(Box::new(rs), Box::new(IrExpr::Const(u64::from(bits - 1))));
        let cond = IrExpr::CmpEqZero(Box::new(sign));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BLTZ pseudo : `blt rs, x0, offset`
    fn lift_bltz(ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "bltz_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs = Self::reg_expr(ops[0]);
        let target = Self::branch_target(ops[1], pc, instr_size);
        // rs < 0  â‰¡  sign bit == 1
        let sign = IrExpr::Shr(Box::new(rs), Box::new(IrExpr::Const(u64::from(bits - 1))));
        let cond = IrExpr::And(Box::new(sign), Box::new(IrExpr::Const(1)));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// BGTZ pseudo : `blt x0, rs, offset`
    fn lift_bgtz(ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Vec<Effect> {
        if ops.len() < 2 {
            return vec![Effect::Intrinsic {
                name: "bgtz_bad_ops".into(),
                args: vec![],
            }];
        }
        let rs = Self::reg_expr(ops[0]);
        let target = Self::branch_target(ops[1], pc, instr_size);
        // rs > 0  â‰¡  sign bit clear AND rs != 0
        let sign = IrExpr::Shr(Box::new(rs.clone()), Box::new(IrExpr::Const(u64::from(bits - 1))));
        let sign_bit = IrExpr::And(Box::new(sign), Box::new(IrExpr::Const(1)));
        let not_negative = IrExpr::CmpEqZero(Box::new(sign_bit));
        let not_zero = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(rs))));
        let cond = IrExpr::And(Box::new(not_negative), Box::new(not_zero));
        vec![Effect::Branch {
            target,
            condition: Some(cond),
        }]
    }

    /// J / B pseudo : unconditional branch to `offset`.
    fn lift_j(ops: &[&str], pc: u64, instr_size: usize) -> Vec<Effect> {
        let target = ops
            .first()
            .map_or(IrExpr::Undef, |t| Self::branch_target(t, pc, instr_size));
        vec![Effect::Branch {
            target,
            condition: None,
        }]
    }

    /// JR pseudo : `jalr x0, 0(rs)` â†’ indirect unconditional branch.
    fn lift_jr(ops: &[&str]) -> Vec<Effect> {
        let target = ops
            .first()
            .map_or(IrExpr::Undef, |r| Self::reg_expr(r));
        vec![Effect::Branch {
            target,
            condition: None,
        }]
    }

    /// CALL pseudo : `auipc ra, %pcrel_hi(sym); jalr ra, %pcrel_lo(sym)(ra)`
    /// Simplified to a single Call effect when seen as the `call` pseudo.
    fn lift_call_pseudo(ops: &[&str]) -> Vec<Effect> {
        let target = ops
            .first()
            .and_then(|t| Self::parse_imm(t).map(|v| IrExpr::Const(v.cast_unsigned())))
            .unwrap_or(IrExpr::Undef);
        vec![Effect::Call { target }]
    }

    /// TAIL pseudo : `auipc t1, ...; jalr x0, ...(t1)` â†’ tail call.
    fn lift_tail(ops: &[&str]) -> Vec<Effect> {
        let target = ops
            .first()
            .and_then(|t| Self::parse_imm(t).map(|v| IrExpr::Const(v.cast_unsigned())))
            .unwrap_or(IrExpr::Undef);
        // Tail call: like a branch but semantically a call
        vec![Effect::Branch {
            target,
            condition: None,
        }]
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Atomic / Zifencei / Zicsr (brief handling)
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// FENCE / FENCE.I : memory barrier.
    fn lift_fence(mnem: &str) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: mnem.to_string(),
            args: vec![],
        }]
    }

    /// CSR instructions (CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI).
    fn lift_csr(mnem: &str, ops: &[&str]) -> Vec<Effect> {
        if ops.len() < 3 {
            return vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }];
        }
        let rd = Self::norm_reg(ops[0]);
        let csr_name = ops[1].trim().to_ascii_lowercase();
        let src = if mnem.ends_with('i') {
            IrExpr::Const(Self::parse_imm(ops[2]).unwrap_or(0).cast_unsigned())
        } else {
            Self::reg_expr(ops[2])
        };
        let mut effects = Vec::new();
        // Read the CSR into rd (if rd != x0)
        if rd != "zero" {
            effects.push(Effect::MemRead {
                addr: IrExpr::Reg(csr_name.clone()),
                dest: rd,
                size: 8,
            });
        }
        // Modify the CSR based on the operation type
        let csr_val = match mnem {
            "csrrs" | "csrrsi" => {
                IrExpr::Or(Box::new(IrExpr::Reg(csr_name.clone())), Box::new(src))
            }
            "csrrc" | "csrrci" => IrExpr::And(
                Box::new(IrExpr::Reg(csr_name.clone())),
                Box::new(IrExpr::Not(Box::new(src))),
            ),
            _ => src,
        };
        effects.push(Effect::MemWrite {
            addr: IrExpr::Reg(csr_name),
            value: csr_val,
            size: 8,
        });
        effects
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Main dispatch
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Dispatch a mnemonic + operands to the appropriate effect list.
    fn dispatch_a(mnem: &str, ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Option<Vec<Effect>> {
        Some(match mnem {
            // â”€â”€ NOP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "nop" => vec![],

            // â”€â”€ Pseudo: MV, LI, NEG, NOT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mv" => Self::lift_mv(ops),
            "li" => Self::lift_li(ops),
            "neg" | "negw" => Self::lift_neg(ops),
            "not" => Self::lift_not(ops),

            // â”€â”€ Pseudo: set comparisons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "seqz" => Self::lift_seqz(ops),
            "snez" => Self::lift_snez(ops),
            "sltz" => {
                // sltz rd, rs  â‰¡  slt rd, rs, x0
                if ops.len() >= 2 {
                    let augmented = [ops[0], ops[1], "zero"];
                    Self::lift_slt("slt", &augmented)
                } else {
                    vec![Effect::Intrinsic {
                        name: "sltz_bad_ops".into(),
                        args: vec![],
                    }]
                }
            }
            "sgtz" => {
                // sgtz rd, rs  â‰¡  slt rd, x0, rs
                if ops.len() >= 2 {
                    let augmented = [ops[0], "zero", ops[1]];
                    Self::lift_slt("slt", &augmented)
                } else {
                    vec![Effect::Intrinsic {
                        name: "sgtz_bad_ops".into(),
                        args: vec![],
                    }]
                }
            }

            // â”€â”€ Integer arithmetic (R-type) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "add" => Self::lift_add(ops),
            "addw" => Self::lift_addw(ops),
            "sub" => Self::lift_sub(ops),
            "subw" => Self::lift_subw(ops),
            "and" => Self::lift_and(ops),
            "or" => Self::lift_or(ops),
            "xor" => Self::lift_xor(ops),
            "sll" => Self::lift_sll(ops, bits),
            "sllw" => Self::lift_sllw(ops, false),
            "srl" => Self::lift_srl(ops, bits),
            "srlw" => Self::lift_srlw(ops, false),
            // `SRA`/`SRAI` shift at the REGISTER width, which is XLEN. On
            // RV32 that is 32 bits, and the plain `Sar` reads the sign from bit
            // 63 — so the 32-bit form is required there. The lifter knew its
            // width all along (`RiscvLifter::bits`, and `new()` builds an RV32
            // lifter); the static dispatch chain simply dropped it. Nothing had
            // to be invented here, only threaded.
            "sra" => {
                if bits == 32 { Self::lift_sraw(ops) } else { Self::lift_sra(ops, bits) }
            }
            "sraw" => Self::lift_sraw(ops),

            // â”€â”€ Integer arithmetic (I-type) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "addi" => Self::lift_addi(ops),
            "addiw" => Self::lift_addiw(ops),
            "andi" => Self::lift_andi(ops),
            "ori" => Self::lift_ori(ops),
            "xori" => Self::lift_xori(ops),
            "slli" => Self::lift_slli(ops),
            "slliw" => Self::lift_sllw(ops, true),
            "srli" => Self::lift_srli(ops),
            "srliw" => Self::lift_srlw(ops, true),
            "srai" => {
                if bits == 32 { Self::lift_sraiw(ops) } else { Self::lift_srai(ops) }
            }
            "sraiw" => Self::lift_sraiw(ops),

            // â”€â”€ Multiply (M-extension) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mul" => Self::lift_mul(ops),
            "mulw" => Self::lift_mulw(ops),
            "mulh" | "mulhu" | "mulhsu" => Self::lift_mulh(mnem, ops),
            "div" | "divu" | "divw" | "divuw" => Self::lift_div(mnem, ops),
            "rem" | "remu" | "remw" | "remuw" => Self::lift_rem(mnem, ops),

            // â”€â”€ Set-less-than â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "slt" | "sltu" | "slti" | "sltiu" => Self::lift_slt(mnem, ops),

            // â”€â”€ Upper-immediate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "lui" => Self::lift_lui(ops),
            "auipc" => Self::lift_auipc(ops, pc),

            // â”€â”€ Loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "lb" => Self::lift_load(ops, 1, true),
            "lbu" => Self::lift_load(ops, 1, false),
            "lh" => Self::lift_load(ops, 2, true),
            "lhu" => Self::lift_load(ops, 2, false),
            "lw" => Self::lift_load(ops, 4, true),
            "lwu" => Self::lift_load(ops, 4, false),
            // LD is full-width: the guard in `lift_load` skips the extension.
            "ld" => Self::lift_load(ops, 8, true),

            // â”€â”€ Stores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "sb" => Self::lift_store(ops, 1),
            "sh" => Self::lift_store(ops, 2),
            "sw" => Self::lift_store(ops, 4),
            "sd" => Self::lift_store(ops, 8),

            // â”€â”€ Branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "beq" => Self::lift_beq(ops, pc, instr_size),
            "bne" => Self::lift_bne(ops, pc, instr_size),
            "blt" => Self::lift_blt(ops, pc, instr_size),
            "bge" => Self::lift_bge(ops, pc, instr_size),
            "bltu" => Self::lift_bltu(ops, pc, instr_size),
            "bgeu" => Self::lift_bgeu(ops, pc, instr_size),

            // â”€â”€ Pseudo branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "beqz" => Self::lift_beqz(ops, pc, instr_size),
            "bnez" => Self::lift_bnez(ops, pc, instr_size),
            "blez" => Self::lift_blez(ops, pc, instr_size, bits),
                _ => return None,
            })
    }
    fn dispatch_b_a(mnem: &str, ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Option<Vec<Effect>> {
        Some(match mnem {
            "bgez" => Self::lift_bgez(ops, pc, instr_size, bits),
            "bltz" => Self::lift_bltz(ops, pc, instr_size, bits),
            "bgtz" => Self::lift_bgtz(ops, pc, instr_size, bits),
            "jal" => Self::lift_jal(ops, pc, instr_size),
            "jalr" => Self::lift_jalr(ops, pc, instr_size),
            "j" | "b" => Self::lift_j(ops, pc, instr_size),
            "jr" => Self::lift_jr(ops),
            "ret" => Self::lift_ret(),
            "call" => Self::lift_call_pseudo(ops),
            "tail" => Self::lift_tail(ops),
            "ecall" => Self::lift_ecall(),
            "ebreak" => Self::lift_ebreak(),
            "fence" | "fence.i" | "sfence.vma" => Self::lift_fence(mnem),
            "csrrw" | "csrrs" | "csrrc" | "csrrwi" | "csrrsi" | "csrrci" => {
                Self::lift_csr(mnem, ops)
            }
            "csrr" => {
                // csrr rd, csr  â‰¡  csrrs rd, csr, x0
                if ops.len() >= 2 {
                    let augmented = [ops[0], ops[1], "zero"];
                    Self::lift_csr("csrrs", &augmented)
                } else {
                    vec![Effect::Intrinsic {
                        name: "csrr_bad_ops".into(),
                        args: vec![],
                    }]
                }
            }
            "csrw" => {
                // csrw csr, rs  â‰¡  csrrw x0, csr, rs
                if ops.len() >= 2 {
                    let augmented = ["zero", ops[0], ops[1]];
                    Self::lift_csr("csrrw", &augmented)
                } else {
                    vec![Effect::Intrinsic {
                        name: "csrw_bad_ops".into(),
                        args: vec![],
                    }]
                }
            }
            "csrs" => {
                if ops.len() >= 2 {
                    let augmented = ["zero", ops[0], ops[1]];
                    Self::lift_csr("csrrs", &augmented)
                } else {
                    vec![Effect::Intrinsic {
                        name: "csrs_bad_ops".into(),
                        args: vec![],
                    }]
                }
            }
            "csrc" => {
                if ops.len() >= 2 {
                    let augmented = ["zero", ops[0], ops[1]];
                    Self::lift_csr("csrrc", &augmented)
                } else {
                    vec![Effect::Intrinsic {
                        name: "csrc_bad_ops".into(),
                        args: vec![],
                    }]
                }
            }
            m if m.starts_with("lr.") => {
                if ops.len() >= 2 {
                    let rd = Self::norm_reg(ops[0]);
                    let addr = Self::reg_expr(ops[1].trim_start_matches('(').trim_end_matches(')'));
                    let sz = if std::path::Path::new(m).extension().is_some_and(|e| e.eq_ignore_ascii_case("d")) { 8u8 } else { 4u8 };
                    if rd == "zero" {
                        return Some(vec![]);
                    }
                    vec![Effect::MemRead {
                        addr,
                        dest: rd,
                        size: sz,
                    }]
                } else {
                    vec![Effect::Intrinsic {
                        name: mnem.to_string(),
                        args: vec![],
                    }]
                }
            }
                    _ => return None,
                })
    }

    fn dispatch_b_b(mnem: &str, ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Option<Vec<Effect>> {
        Some(match mnem {
            m if m.starts_with("sc.") => {
                vec![Effect::Intrinsic {
                    name: mnem.to_string(),
                    args: vec![],
                }]
            }
            m if m.starts_with("amo") => {
                vec![Effect::Intrinsic {
                    name: mnem.to_string(),
                    args: vec![],
                }]
            }
            m if m.starts_with('f') => {
                vec![Effect::Intrinsic {
                    name: mnem.to_string(),
                    args: vec![],
                }]
            }
            "c.nop" => vec![],
            "c.mv" => Self::lift_mv(ops),
            "c.li" => Self::lift_li(ops),
            "c.lui" => Self::lift_lui(ops),
            "c.add" => Self::lift_add(ops),
            "c.addi" | "c.addi4spn" | "c.addi16sp" => Self::lift_addi(ops),
            "c.sub" => Self::lift_sub(ops),
            "c.subw" => Self::lift_subw(ops),
            "c.and" => Self::lift_and(ops),
            "c.or" => Self::lift_or(ops),
            "c.xor" => Self::lift_xor(ops),
            // C.LW sign-extends, per the RVC spec.
            "c.lw" => Self::lift_load(ops, 4, true),
            "c.ld" => Self::lift_load(ops, 8, true), // full-width, no extension
            "c.sw" => Self::lift_store(ops, 4),
            "c.sd" => Self::lift_store(ops, 8),
            "c.j" => Self::lift_j(ops, pc, instr_size),
            "c.jr" => Self::lift_jr(ops),
            "c.jalr" => Self::lift_jalr(ops, pc, instr_size),
            "c.beqz" => Self::lift_beqz(ops, pc, instr_size),
            "c.bnez" => Self::lift_bnez(ops, pc, instr_size),
            "c.ret" => Self::lift_ret(),
            "c.slli" => Self::lift_slli(ops),
            "c.srli" => Self::lift_srli(ops),
            // `srai` in dispatch_a picks `lift_sraiw` on RV32 because an
            // arithmetic shift must read the sign at the register width. The
            // COMPRESSED spelling of the same instruction bypassed that and
            // always took the 64-bit path, so on RV32 `c.srai` and `srai`
            // lifted differently — and RV32 code is overwhelmingly compressed,
            // so the wrong one is the one that actually shows up.
            //
            // `c.slli`/`c.srli` are left alone deliberately: their uncompressed
            // forms take no width selection either, so those pairs agree.
            "c.srai" => {
                if bits == 32 {
                    Self::lift_sraiw(ops)
                } else {
                    Self::lift_srai(ops)
                }
            }
            "c.andi" => Self::lift_andi(ops),
            _ => vec![Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            }],
                })
    }

    fn dispatch_b(mnem: &str, ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Vec<Effect> {
        if let Some(r) = Self::dispatch_b_a(mnem, ops, pc, instr_size, bits) {
            return r;
        }
        // dispatch_b_b is the true final fallback and always returns Some(..).
        Self::dispatch_b_b(mnem, ops, pc, instr_size, bits).unwrap_or_default()
    }

    fn dispatch(mnem: &str, ops: &[&str], pc: u64, instr_size: usize, bits: u32) -> Vec<Effect> {
        if let Some(r) = Self::dispatch_a(mnem, ops, pc, instr_size, bits) {
            return r;
        }
        Self::dispatch_b(mnem, ops, pc, instr_size, bits)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ArchLifter implementation
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl Default for RiscvLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RiscvLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RiscvLifter(rv{})", self.bits)
    }
}

impl ArchLifter for RiscvLifter {
    fn arch_name(&self) -> &'static str {
        if self.bits == 64 {
            "riscv64"
        } else {
            "riscv32"
        }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        if self.bits == 64 {
            "mnemonic-driven RV64I LLIL lifter"
        } else {
            "mnemonic-driven RV32I LLIL lifter"
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        // Accept everything â€” unknown mnemonics fall back to Intrinsic.
        let _ = mnemonic;
        true
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let (mnem, raw_ops) = Self::tokenise(instr);
        let op_refs: Vec<&str> = raw_ops.iter().map(String::as_str).collect();
        let pc = instr.address.0;
        let instr_size = instr.size;

        let effects = Self::dispatch(&mnem, &op_refs, pc, instr_size, self.bits);

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
            address: pc,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }

    fn lift_block(&self, instrs: &[Instruction]) -> Vec<Result<LiftedInstr, LiftError>> {
        instrs.iter().map(|i| self.lift(i)).collect()
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
        arch::{InstrFlags, Instruction},
    };

    // â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Build a minimal [`Instruction`] with the given mnemonic and operand text.
    fn make_instr(addr: u64, mnemonic: &str, operands: &str) -> Instruction {
        let mut i = Instruction::new(Address::new(addr), 4, mnemonic.to_string(), vec![0u8; 4]);
        i.operands = operands.to_string();
        i.flags = InstrFlags::NONE;
        i
    }

    /// Shorthand: lift a single instruction and unwrap.
    fn lift(mnemonic: &str, operands: &str) -> LiftedInstr {
        let lifter = RiscvLifter::new();
        lifter
            .lift(&make_instr(0x1000, mnemonic, operands))
            .unwrap()
    }

    /// Every RISC-V `w`-suffixed instruction computes on 32 bits and
    /// SIGN-EXTENDS the result into the upper half. The whole family shared
    /// handlers with the full-width forms, so the low half was right and the
    /// high half was whatever 64-bit arithmetic produced — wrong for every
    /// negative 32-bit result.
    #[test]
    fn w_suffix_forms_differ_from_full_width() {
        let lifter = RiscvLifter::new_rv64();
        let render = |m: &str, ops: &str| {
            format!("{:?}", lifter.lift(&make_instr(0x1000, m, ops)).unwrap().effects)
        };
        for (full, narrow, ops) in [
            ("add", "addw", "a0, a1, a2"),
            ("sub", "subw", "a0, a1, a2"),
            ("sll", "sllw", "a0, a1, a2"),
            ("srl", "srlw", "a0, a1, a2"),
            ("addi", "addiw", "a0, a1, 1"),
            ("mul", "mulw", "a0, a1, a2"),
        ] {
            assert_ne!(
                render(full, ops),
                render(narrow, ops),
                "{narrow} must sign-extend its 32-bit result; {full} must not"
            );
        }
        // The logical right shift must TRUNCATE before shifting, or the upper
        // half's bits fall into the result.
        assert!(
            render("srlw", "a0, a1, a2").contains("4294967295"),
            "srlw must mask to 32 bits before shifting"
        );
    }

    /// `SRA` shifts at XLEN. On RV32 the register is 32 bits, so the sign must
    /// be read from bit 31; on RV64 from bit 63. The lifter knew its width all
    /// along, but the static dispatch chain dropped it, so BOTH configurations
    /// emitted the same 64-bit shift.
    ///
    /// Nothing in the suite covered this — the fix left every test green — so
    /// this asserts the two configurations now DIFFER, which is the whole point.
    #[test]
    fn sra_is_width_aware_rv32_differs_from_rv64() {
        let instr = make_instr(0x1000, "sra", "a0, a1, a2");
        let rv32 = format!("{:?}", RiscvLifter::new().lift(&instr).unwrap().effects);
        let rv64 = format!("{:?}", RiscvLifter::new_rv64().lift(&instr).unwrap().effects);
        assert_ne!(
            rv32, rv64,
            "RV32 and RV64 SRA must not lift identically — RV32 needs the 32-bit form"
        );
        // RV32 reaches the 32-bit form, which shifts the sign up to bit 63 first.
        assert!(rv32.contains("Shl"), "RV32 sra must use the 32-bit form: {rv32}");
        assert!(!rv64.contains("Shl"), "RV64 sra is already full width: {rv64}");
    }

    /// Same but with a specific address.
    fn lift_at(addr: u64, mnemonic: &str, operands: &str) -> LiftedInstr {
        let lifter = RiscvLifter::new();
        lifter.lift(&make_instr(addr, mnemonic, operands)).unwrap()
    }

    // â”€â”€ lifter metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_arch_name_rv32() {
        let l = RiscvLifter::new();
        assert_eq!(l.arch_name(), "riscv32");
        assert_eq!(l.lift_level(), LiftLevel::Llil);
        assert!(l.description().contains("RV32"));
    }

    #[test]
    fn test_arch_name_rv64() {
        let l = RiscvLifter::new_rv64();
        assert_eq!(l.arch_name(), "riscv64");
        assert!(l.description().contains("RV64"));
    }

    #[test]
    fn test_supports_mnemonic() {
        let l = RiscvLifter::new();
        assert!(l.supports_mnemonic("add"));
        assert!(l.supports_mnemonic("totally_unknown_thing"));
    }

    // â”€â”€ NOP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_nop_has_no_effects() {
        let li = lift("nop", "");
        assert!(li.effects.is_empty());
        assert_eq!(li.ir_text, "nop");
        assert!(!li.is_terminator());
    }

    // â”€â”€ Arithmetic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_add_r_type() {
        let li = lift("add", "a0, a1, a2");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite { reg, value } = &li.effects[0] {
            assert_eq!(reg, "a0");
            assert!(matches!(value, IrExpr::Add(_, _)));
        } else {
            panic!("expected RegWrite, got {:?}", li.effects[0]);
        }
    }

    #[test]
    fn test_addi_immediate() {
        let li = lift("addi", "t0, t1, 8");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite { reg, value } = &li.effects[0] {
            assert_eq!(reg, "t0");
            // addi t0, t1, 8  =>  t0 = t1 + 0x8
            assert!(matches!(value, IrExpr::Add(_, _)));
        } else {
            panic!("expected RegWrite");
        }
    }

    #[test]
    fn test_addi_zero_is_mv() {
        // addi rd, rs, 0  â‰¡  mv rd, rs
        let li = lift("addi", "a0, a1, 0");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite { reg, value } = &li.effects[0] {
            assert_eq!(reg, "a0");
            // Should be a plain register copy, not an Add
            assert!(matches!(value, IrExpr::Reg(_)));
        } else {
            panic!("expected RegWrite");
        }
    }

    #[test]
    fn test_addi_x0_is_li() {
        // addi rd, x0, imm  â‰¡  li rd, imm
        let li = lift("addi", "a0, x0, 42");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite { reg, value } = &li.effects[0] {
            assert_eq!(reg, "a0");
            assert_eq!(value, &IrExpr::Const(42));
        } else {
            panic!("expected RegWrite");
        }
    }

    #[test]
    fn test_sub_r_type() {
        let li = lift("sub", "s0, s1, s2");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite { reg, value } = &li.effects[0] {
            assert_eq!(reg, "s0");
            assert!(matches!(value, IrExpr::Sub(_, _)));
        } else {
            panic!("expected RegWrite");
        }
    }

    #[test]
    fn test_and_r_type() {
        let li = lift("and", "a0, a1, a2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::And(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_or_r_type() {
        let li = lift("or", "a0, a1, a2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Or(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_xor_r_type() {
        let li = lift("xor", "a0, a1, a2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Xor(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_sll_r_type() {
        let li = lift("sll", "t0, t1, t2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Shl(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_srl_r_type() {
        let li = lift("srl", "t0, t1, t2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Shr(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_mul_m_extension() {
        let li = lift("mul", "a0, a1, a2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Mul(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_div_becomes_intrinsic() {
        let li = lift("div", "a0, a1, a2");
        assert!(matches!(&li.effects[0], Effect::Intrinsic { name, .. } if name == "div"));
    }

    // â”€â”€ Write-to-x0 is no-op â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_write_to_x0_is_nop() {
        let li = lift("add", "x0, a0, a1");
        assert!(li.effects.is_empty(), "write to x0 must produce no effect");
    }

    #[test]
    fn test_write_to_zero_abi_is_nop() {
        let li = lift("addi", "zero, a0, 1");
        assert!(li.effects.is_empty());
    }

    // â”€â”€ LUI / AUIPC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lui() {
        let li = lift("lui", "a0, 1");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite {
            reg,
            value: IrExpr::Const(v),
        } = &li.effects[0]
        {
            assert_eq!(reg, "a0");
            // lui a0, 1  =>  a0 = 1 << 12 = 0x1000
            assert_eq!(*v, 0x1000);
        } else {
            panic!("expected RegWrite Const, got {:?}", li.effects[0]);
        }
    }

    #[test]
    fn test_auipc() {
        let li = lift_at(0x2000, "auipc", "a0, 1");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite {
            reg,
            value: IrExpr::Const(v),
        } = &li.effects[0]
        {
            assert_eq!(reg, "a0");
            // auipc a0, 1  =>  a0 = PC + (1 << 12) = 0x2000 + 0x1000 = 0x3000
            assert_eq!(*v, 0x3000);
        } else {
            panic!("expected RegWrite Const, got {:?}", li.effects[0]);
        }
    }

    // â”€â”€ Memory loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lw_load() {
        let li = lift("lw", "a0, 8(sp)");
        // `LW` SIGN-extends its 32-bit result into the 64-bit destination, so
        // the lift is a load PLUS an extension marker. The old
        // `assert_eq!(li.effects.len(), 1)` pinned the ABSENCE of that
        // extension — the eighth time in this session that a test froze the
        // under-modelling it should have caught.
        assert_eq!(li.effects.len(), 2, "lw must load AND sign-extend: {:?}", li.effects);
        assert!(
            matches!(&li.effects[1], Effect::Intrinsic { name, .. } if name == "sext32"),
            "expected a sext32 marker, got {:?}",
            li.effects[1]
        );
        if let Effect::MemRead { addr, dest, size } = &li.effects[0] {
            assert_eq!(dest, "a0");
            assert_eq!(*size, 4);
            // address should be sp + 8
            assert!(matches!(addr, IrExpr::Add(_, _)));
        } else {
            panic!("expected MemRead, got {:?}", li.effects[0]);
        }
    }

    #[test]
    fn test_lb_load() {
        let li = lift("lb", "a1, 0(a0)");
        if let Effect::MemRead { size, .. } = &li.effects[0] {
            assert_eq!(*size, 1);
        } else {
            panic!("expected MemRead");
        }
    }

    #[test]
    fn test_ld_load_64() {
        let li = lift("ld", "a0, 16(sp)");
        if let Effect::MemRead { size, .. } = &li.effects[0] {
            assert_eq!(*size, 8);
        } else {
            panic!("expected MemRead");
        }
    }

    #[test]
    fn test_lw_zero_offset() {
        let li = lift("lw", "a0, 0(a1)");
        if let Effect::MemRead { addr, .. } = &li.effects[0] {
            // With zero offset the address should just be the base register.
            assert!(matches!(addr, IrExpr::Reg(r) if r == "a1"));
        } else {
            panic!("expected MemRead");
        }
    }

    // â”€â”€ Memory stores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sw_store() {
        let li = lift("sw", "a0, 8(sp)");
        assert_eq!(li.effects.len(), 1);
        if let Effect::MemWrite { addr, size, .. } = &li.effects[0] {
            assert_eq!(*size, 4);
            assert!(matches!(addr, IrExpr::Add(_, _)));
        } else {
            panic!("expected MemWrite, got {:?}", li.effects[0]);
        }
    }

    #[test]
    fn test_sb_store() {
        let li = lift("sb", "a1, 0(a0)");
        if let Effect::MemWrite { size, .. } = &li.effects[0] {
            assert_eq!(*size, 1);
        } else {
            panic!("expected MemWrite");
        }
    }

    #[test]
    fn test_sd_store_64() {
        let li = lift("sd", "a0, 24(sp)");
        if let Effect::MemWrite { size, .. } = &li.effects[0] {
            assert_eq!(*size, 8);
        } else {
            panic!("expected MemWrite");
        }
    }

    // â”€â”€ Branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_beq_conditional_branch() {
        let li = lift("beq", "a0, a1, 0x2000");
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch, "beq must produce a conditional branch");
    }

    #[test]
    fn test_bne_conditional_branch() {
        let li = lift("bne", "a0, a1, 0x3000");
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch, "bne must produce a conditional branch");
    }

    #[test]
    fn test_blt_conditional_branch() {
        let li = lift("blt", "a0, a1, 0x4000");
        assert!(li.is_terminator());
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch);
    }

    #[test]
    fn test_bge_conditional_branch() {
        let li = lift("bge", "s0, s1, 0x5000");
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch);
    }

    /// The four ordering branches must lift to REAL comparison nodes, with the
    /// signed and unsigned forms distinguishable.
    ///
    /// The pre-existing tests for these asserted only `condition: Some(_)`,
    /// which any condition satisfies — so they passed while `blt` used a
    /// sign-of-difference encoding that misreads every overflowing comparison,
    /// and while `bltu` branched on `__bltu_cond`, a register no effect ever
    /// defined and whose fixed name collided between two `bltu` in one block.
    /// Naming a mnemonic in a test is not the same as testing its meaning.
    #[test]
    fn ordering_branches_lift_to_real_comparisons() {
        fn condition_of(mnem: &str) -> IrExpr {
            let li = lift(mnem, "a0, a1, 0x2000");
            li.effects
                .iter()
                .find_map(|e| match e {
                    Effect::Branch {
                        condition: Some(c), ..
                    } => Some(c.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{mnem} produced no conditional branch"))
        }

        // Signed forms use CmpLt; unsigned forms use CmpLtU. If these two ever
        // collapse to the same node the ISA distinction is gone.
        assert!(
            matches!(condition_of("blt"), IrExpr::CmpLt(..)),
            "blt must compare signed, got {}",
            condition_of("blt")
        );
        assert!(
            matches!(condition_of("bltu"), IrExpr::CmpLtU(..)),
            "bltu must compare UNSIGNED, got {}",
            condition_of("bltu")
        );

        // The `>=` forms are the negation of the corresponding `<`, so the
        // inner node still carries the signedness.
        match condition_of("bge") {
            IrExpr::CmpEqZero(inner) => assert!(
                matches!(*inner, IrExpr::CmpLt(..)),
                "bge must negate a SIGNED compare, got {inner}"
            ),
            other => panic!("bge must be a negation, got {other}"),
        }
        match condition_of("bgeu") {
            IrExpr::CmpEqZero(inner) => assert!(
                matches!(*inner, IrExpr::CmpLtU(..)),
                "bgeu must negate an UNSIGNED compare, got {inner}"
            ),
            other => panic!("bgeu must be a negation, got {other}"),
        }

        // The defect that made the unsigned pair wrong rather than merely
        // opaque: the branch read a synthetic register nothing defined.
        for mnem in ["bltu", "bgeu"] {
            let li = lift(mnem, "a0, a1, 0x2000");
            assert!(
                !format!("{:?}", li.effects).contains("_cond"),
                "{mnem} must not branch on an undefined synthetic condition register"
            );
        }
    }

    /// The compare-against-zero branches must read the sign bit at the width
    /// the lifter was built for.
    ///
    /// The position was hard-coded to 63 while `RiscvLifter::new()` — what the
    /// registry gives you for both "riscv" and "riscv32" — is an RV32 lifter.
    /// Reading bit 63 of a 32-bit value is always 0, so on RV32 `bgez` was
    /// always taken and `bltz` never was.
    ///
    /// Every existing test for these ran through the RV32 helper and passed
    /// anyway, because none of them looked at the condition. Running in the
    /// broken configuration is not the same as testing it.
    /// A REGISTER-supplied shift count is `rs2[4:0]` on RV32, `rs2[5:0]` on
    /// RV64, and always `rs2[4:0]` for the 32-bit `W` forms. It came through
    /// raw, so a register holding 64 shifted by 64 in the IL and by 0 on the
    /// machine.
    ///
    /// The IMMEDIATE forms must stay unmasked: their `shamt` is a 5- or 6-bit
    /// field in the encoding and cannot be out of range, so a mask there would
    /// be noise. Asserted, so an over-correction fails instead of passing.
    #[test]
    fn register_shift_counts_are_masked() {
        let render = |lifter: &RiscvLifter, mnem: &str, ops: &str| {
            format!(
                "{:?}",
                lifter
                    .lift(&make_instr(0x1000, mnem, ops))
                    .expect("lift")
                    .effects
            )
        };
        let rv32 = RiscvLifter::new();
        let rv64 = RiscvLifter::new_rv64();

        // Full-width forms follow XLEN.
        for mnem in ["sll", "srl", "sra"] {
            let a = render(&rv32, mnem, "a0, a1, a2");
            assert!(
                a.contains("And(Reg(\"a2\"), Const(31))"),
                "rv32 {mnem} reads rs2[4:0], got {a}"
            );
            let b = render(&rv64, mnem, "a0, a1, a2");
            assert!(
                b.contains("And(Reg(\"a2\"), Const(63))"),
                "rv64 {mnem} reads rs2[5:0], got {b}"
            );
        }

        // The 32-bit W forms are always 5 bits, whatever XLEN is.
        for mnem in ["sllw", "srlw", "sraw"] {
            let t = render(&rv64, mnem, "a0, a1, a2");
            assert!(
                t.contains("And(Reg(\"a2\"), Const(31))"),
                "{mnem} reads rs2[4:0] regardless of XLEN, got {t}"
            );
        }

        // Immediate forms carry an encoded shamt: no mask.
        for mnem in ["slli", "srli", "srai", "slliw", "sraiw"] {
            let t = render(&rv64, mnem, "a0, a1, 3");
            // The count here is a constant; it must not be wrapped in a mask.
            assert!(
                !t.contains("And(Const(3)"),
                "{mnem} encodes its shamt and needs no mask, got {t}"
            );
        }
    }

    #[test]
    fn zero_compare_branches_use_the_right_sign_bit() {
        fn cond_text(lifter: &RiscvLifter, mnem: &str) -> String {
            let li = lifter
                .lift(&make_instr(0x1000, mnem, "a0, 0x3000"))
                .expect("lift must succeed");
            li.effects
                .iter()
                .find_map(|e| match e {
                    Effect::Branch {
                        condition: Some(c), ..
                    } => Some(format!("{c}")),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{mnem} produced no conditional branch"))
        }

        let rv32 = RiscvLifter::new();
        let rv64 = RiscvLifter::new_rv64();
        for mnem in ["blez", "bgez", "bltz", "bgtz"] {
            let c32 = cond_text(&rv32, mnem);
            let c64 = cond_text(&rv64, mnem);
            assert!(
                // Constants render in hex: 0x1f == 31, 0x3f == 63.
                c32.contains("0x1f") && !c32.contains("0x3f"),
                "{mnem} on RV32 must read the sign at bit 31, got {c32}"
            );
            assert!(
                c64.contains("0x3f"),
                "{mnem} on RV64 must read the sign at bit 63, got {c64}"
            );
            assert_ne!(
                c32, c64,
                "{mnem} must not lift identically at both widths"
            );
        }
    }

    /// A compressed instruction must lift the same as its uncompressed
    /// spelling — they are the same instruction.
    ///
    /// `c.srai` took the 64-bit arithmetic-shift path unconditionally while
    /// `srai` selected by width, so the two disagreed on RV32. Found by
    /// noticing that the dispatch chain holding the compressed forms received
    /// no width parameter at all.
    #[test]
    fn compressed_shifts_agree_with_their_uncompressed_spelling() {
        for (bits, lifter) in [(32u32, RiscvLifter::new()), (64, RiscvLifter::new_rv64())] {
            let plain = lifter
                .lift(&make_instr(0x1000, "srai", "a0, a1, 3"))
                .expect("srai must lift");
            let compressed = lifter
                .lift(&make_instr(0x1000, "c.srai", "a0, a1, 3"))
                .expect("c.srai must lift");
            assert_eq!(
                format!("{:?}", plain.effects),
                format!("{:?}", compressed.effects),
                "rv{bits}: c.srai must lift identically to srai"
            );
        }
    }

    #[test]
    fn test_beqz_pseudo() {
        let li = lift("beqz", "a0, 0x2000");
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch);
    }

    #[test]
    fn test_bnez_pseudo() {
        let li = lift("bnez", "a0, 0x3000");
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        });
        assert!(has_branch);
    }

    // â”€â”€ JAL / JALR / RET â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_jal_ra_is_call() {
        // jal ra, target  â†’  call
        let li = lift_at(0x1000, "jal", "ra, 0x4000");
        let has_call = li.effects.iter().any(|e| matches!(e, Effect::Call { .. }));
        assert!(has_call, "jal ra,target should be a call");
        // Return address should be saved in ra
        let saves_ra = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "ra"));
        assert!(saves_ra, "jal ra,target must save return address in ra");
    }

    #[test]
    fn test_jal_x0_is_branch() {
        // jal x0, offset  â†’  unconditional branch (J pseudo)
        let li = lift_at(0x1000, "jal", "x0, 0x2000");
        let has_branch = li.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: None,
                    ..
                }
            )
        });
        assert!(
            has_branch,
            "jal x0,offset should be an unconditional branch"
        );
        let has_call = li.effects.iter().any(|e| matches!(e, Effect::Call { .. }));
        assert!(!has_call, "jal x0,offset must not be a call");
    }

    #[test]
    fn test_ret_pseudo() {
        let li = lift("ret", "");
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(&li.effects[0], Effect::Return { .. }));
        assert!(li.is_terminator());
    }

    #[test]
    fn test_jalr_x0_ra_is_return() {
        // jalr x0, 0(ra)  =  ret
        let li = lift("jalr", "x0, 0(ra)");
        let has_return = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Return { .. }));
        assert!(has_return, "jalr x0, 0(ra) should be a return");
    }

    #[test]
    fn test_jalr_ra_rs1_is_call() {
        // jalr ra, 0(a5)  =  indirect call through a5
        let li = lift_at(0x2000, "jalr", "ra, 0(a5)");
        let has_call = li.effects.iter().any(|e| matches!(e, Effect::Call { .. }));
        assert!(has_call, "jalr ra, 0(a5) should be a call");
    }

    // â”€â”€ ECALL / EBREAK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ecall_is_syscall() {
        let li = lift("ecall", "");
        assert_eq!(li.effects.len(), 1);
        if let Effect::Syscall { nr } = &li.effects[0] {
            assert_eq!(nr, &IrExpr::Reg("a7".to_string()));
        } else {
            panic!("expected Syscall");
        }
    }

    #[test]
    fn test_ebreak_is_intrinsic() {
        let li = lift("ebreak", "");
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(&li.effects[0], Effect::Intrinsic { name, .. } if name == "ebreak"));
    }

    // â”€â”€ Pseudo-instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_mv_pseudo() {
        let li = lift("mv", "a0, a1");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite { reg, value } = &li.effects[0] {
            assert_eq!(reg, "a0");
            assert!(matches!(value, IrExpr::Reg(r) if r == "a1"));
        } else {
            panic!("expected RegWrite");
        }
    }

    #[test]
    fn test_li_pseudo() {
        let li = lift("li", "a0, 42");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite {
            reg,
            value: IrExpr::Const(v),
        } = &li.effects[0]
        {
            assert_eq!(reg, "a0");
            assert_eq!(*v, 42);
        } else {
            panic!("expected RegWrite Const(42)");
        }
    }

    #[test]
    fn test_neg_pseudo() {
        let li = lift("neg", "a0, a1");
        assert_eq!(li.effects.len(), 1);
        if let Effect::RegWrite {
            value: IrExpr::Sub(lhs, _),
            ..
        } = &li.effects[0]
        {
            assert_eq!(**lhs, IrExpr::Const(0));
        } else {
            panic!("expected RegWrite Sub(0, rs)");
        }
    }

    #[test]
    fn test_not_pseudo() {
        let li = lift("not", "a0, a1");
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Not(_),
                ..
            }
        ));
    }

    #[test]
    fn test_seqz_pseudo() {
        let li = lift("seqz", "a0, a1");
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::CmpEqZero(_),
                ..
            }
        ));
    }

    // â”€â”€ Unknown mnemonic â†’ Intrinsic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_unknown_mnemonic_becomes_intrinsic() {
        let li = lift("totally_unknown_riscv_op", "a0, a1, a2");
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(&li.effects[0], Effect::Intrinsic { .. }));
    }

    // â”€â”€ Register normalisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_reg_norm_x10_to_a0() {
        assert_eq!(RiscvLifter::norm_reg("x10"), "a0");
        assert_eq!(RiscvLifter::norm_reg("X10"), "a0");
    }

    #[test]
    fn test_reg_norm_fp_to_s0() {
        assert_eq!(RiscvLifter::norm_reg("fp"), "s0");
        assert_eq!(RiscvLifter::norm_reg("s0"), "s0");
        assert_eq!(RiscvLifter::norm_reg("x8"), "s0");
    }

    #[test]
    fn test_reg_norm_zero_variants() {
        assert_eq!(RiscvLifter::norm_reg("zero"), "zero");
        assert_eq!(RiscvLifter::norm_reg("x0"), "zero");
    }

    // â”€â”€ Operand parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_parse_imm_decimal() {
        assert_eq!(RiscvLifter::parse_imm("42"), Some(42));
        assert_eq!(RiscvLifter::parse_imm("-8"), Some(-8));
    }

    #[test]
    fn test_parse_imm_hex() {
        assert_eq!(RiscvLifter::parse_imm("0x1000"), Some(0x1000));
        assert_eq!(RiscvLifter::parse_imm("0xFF"), Some(0xFF));
    }

    #[test]
    fn test_parse_imm_hash_prefix() {
        assert_eq!(RiscvLifter::parse_imm("#16"), Some(16));
    }

    #[test]
    fn test_split_operands() {
        let tokens = RiscvLifter::split_operands("a0, 8(sp)");
        assert_eq!(tokens, vec!["a0", "8(sp)"]);
    }

    #[test]
    fn test_split_operands_three() {
        let tokens = RiscvLifter::split_operands("a0, a1, a2");
        assert_eq!(tokens, vec!["a0", "a1", "a2"]);
    }

    // â”€â”€ Block lifting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lift_block_multiple_instructions() {
        let lifter = RiscvLifter::new();
        let instrs = vec![
            make_instr(0x1000, "addi", "sp, sp, -16"),
            make_instr(0x1004, "sw", "ra, 12(sp)"),
            make_instr(0x1008, "lw", "a0, 0(a5)"),
            make_instr(0x100c, "lw", "ra, 12(sp)"),
            make_instr(0x1010, "addi", "sp, sp, 16"),
            make_instr(0x1014, "ret", ""),
        ];
        let results = lifter.lift_block(&instrs);
        assert_eq!(results.len(), 6);
        assert!(results.iter().all(Result::is_ok));
        let block: Vec<LiftedInstr> = results.into_iter().map(Result::unwrap).collect();
        // The ret at 0x1014 should be a terminator.
        assert!(block.last().unwrap().is_terminator());
    }

    // â”€â”€ Terminator detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_jal_is_terminator() {
        let li = lift_at(0x1000, "jal", "x0, 0x2000");
        assert!(li.is_terminator());
    }

    #[test]
    fn test_ecall_is_terminator() {
        let li = lift("ecall", "");
        assert!(li.is_terminator());
    }

    #[test]
    fn test_add_is_not_terminator() {
        let li = lift("add", "a0, a1, a2");
        assert!(!li.is_terminator());
    }

    // â”€â”€ Compressed instructions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_c_nop() {
        let li = lift("c.nop", "");
        assert!(li.effects.is_empty());
    }

    #[test]
    fn test_c_mv() {
        let li = lift("c.mv", "a0, a1");
        assert!(matches!(&li.effects[0], Effect::RegWrite { reg, .. } if reg == "a0"));
    }

    #[test]
    fn test_c_add() {
        let li = lift("c.add", "a0, a1, a2");
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Add(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_c_lw() {
        let li = lift("c.lw", "a0, 4(a1)");
        assert!(matches!(&li.effects[0], Effect::MemRead { size: 4, .. }));
    }

    #[test]
    fn test_c_sw() {
        let li = lift("c.sw", "a0, 4(a1)");
        assert!(matches!(&li.effects[0], Effect::MemWrite { size: 4, .. }));
    }

    // â”€â”€ Fence / system â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_fence_is_intrinsic() {
        let li = lift("fence", "");
        assert!(matches!(&li.effects[0], Effect::Intrinsic { name, .. } if name == "fence"));
    }

    #[test]
    fn test_fence_i_is_intrinsic() {
        let li = lift("fence.i", "");
        assert!(matches!(&li.effects[0], Effect::Intrinsic { name, .. } if name == "fence.i"));
    }

    // â”€â”€ Addressing modes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_negative_offset_load() {
        let li = lift("lw", "a0, -4(s0)");
        if let Effect::MemRead { addr, .. } = &li.effects[0] {
            // -4(s0) should produce Sub(s0, 4)
            assert!(matches!(addr, IrExpr::Sub(_, _)));
        } else {
            panic!("expected MemRead");
        }
    }

    #[test]
    fn test_rv64_lifter_ld() {
        let lifter = RiscvLifter::new_rv64();
        let instr = make_instr(0x2000, "ld", "a0, 0(a1)");
        let li = lifter.lift(&instr).unwrap();
        if let Effect::MemRead { size, .. } = &li.effects[0] {
            assert_eq!(*size, 8);
        } else {
            panic!("expected MemRead");
        }
    }

    // â”€â”€ Register-read tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_read_registers_for_add() {
        let li = lift("add", "a0, a1, a2");
        let read = li.read_registers();
        assert!(read.contains(&"a1".to_string()), "a1 should be read");
        assert!(read.contains(&"a2".to_string()), "a2 should be read");
    }

    #[test]
    fn test_written_registers_for_addi() {
        let li = lift("addi", "t0, t1, 4");
        let written = li.written_registers();
        assert!(written.contains(&"t0".to_string()), "t0 should be written");
    }

    // â”€â”€ Default / Display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_default_is_rv32() {
        let l = RiscvLifter::default();
        assert_eq!(l.bits, 32);
    }

    #[test]
    fn test_display() {
        let l32 = RiscvLifter::new();
        let l64 = RiscvLifter::new_rv64();
        assert!(format!("{l32}").contains("rv32"));
        assert!(format!("{l64}").contains("rv64"));
    }

    // â”€â”€ All basic mnemonics succeed without panic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_all_basic_mnemonics_succeed() {
        let lifter = RiscvLifter::new();
        let cases: &[(&str, &str)] = &[
            ("add", "a0, a1, a2"),
            ("sub", "a0, a1, a2"),
            ("and", "a0, a1, a2"),
            ("or", "a0, a1, a2"),
            ("xor", "a0, a1, a2"),
            ("sll", "a0, a1, a2"),
            ("srl", "a0, a1, a2"),
            ("sra", "a0, a1, a2"),
            ("mul", "a0, a1, a2"),
            ("div", "a0, a1, a2"),
            ("rem", "a0, a1, a2"),
            ("addi", "a0, a1, 4"),
            ("andi", "a0, a1, 0xff"),
            ("ori", "a0, a1, 0x1"),
            ("xori", "a0, a1, -1"),
            ("slli", "a0, a1, 2"),
            ("srli", "a0, a1, 1"),
            ("srai", "a0, a1, 1"),
            ("lui", "a0, 0x100"),
            ("auipc", "a0, 0x1"),
            ("lb", "a0, 0(a1)"),
            ("lh", "a0, 0(a1)"),
            ("lw", "a0, 0(a1)"),
            ("ld", "a0, 0(a1)"),
            ("lbu", "a0, 0(a1)"),
            ("lhu", "a0, 0(a1)"),
            ("lwu", "a0, 0(a1)"),
            ("sb", "a0, 0(a1)"),
            ("sh", "a0, 0(a1)"),
            ("sw", "a0, 0(a1)"),
            ("sd", "a0, 0(a1)"),
            ("beq", "a0, a1, 0x2000"),
            ("bne", "a0, a1, 0x2000"),
            ("blt", "a0, a1, 0x2000"),
            ("bge", "a0, a1, 0x2000"),
            ("bltu", "a0, a1, 0x2000"),
            ("bgeu", "a0, a1, 0x2000"),
            ("jal", "ra, 0x4000"),
            ("jalr", "ra, 0(a5)"),
            ("ecall", ""),
            ("ebreak", ""),
            ("nop", ""),
            ("ret", ""),
            ("mv", "a0, a1"),
            ("li", "a0, 100"),
            ("neg", "a0, a1"),
            ("not", "a0, a1"),
            ("seqz", "a0, a1"),
            ("snez", "a0, a1"),
            ("beqz", "a0, 0x3000"),
            ("bnez", "a0, 0x3000"),
            ("bgez", "a0, 0x3000"),
            ("bltz", "a0, 0x3000"),
            ("slt", "a0, a1, a2"),
            ("sltu", "a0, a1, a2"),
            ("slti", "a0, a1, 1"),
            ("sltiu", "a0, a1, 1"),
        ];
        for (mnem, ops) in cases {
            let instr = make_instr(0x1000, mnem, ops);
            let result = lifter.lift(&instr);
            assert!(result.is_ok(), "lift failed for '{mnem} {ops}'");
        }
    }
}
