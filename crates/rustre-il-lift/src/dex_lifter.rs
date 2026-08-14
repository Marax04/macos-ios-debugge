//! Android DEX (Dalvik/ART bytecode) LLIL lifter.
//!
//! # Architecture overview
//!
//! DEX is a register-based VM with up to 65536 virtual registers per method,
//! named `v0`..`v65535`.  Wide (64-bit) values occupy consecutive register
//! pairs where the lower-numbered register holds the low 32 bits.
//!
//! Method arguments occupy the *top* registers.  For a non-static method with
//! 5 total registers (`locals_size = 3`) and 2 arguments, the argument
//! registers are `v3` (this-pointer / arg0) and `v4` (arg1).
//!
//! # Operand convention used by this lifter
//!
//! Because DEX disassemblers vary in how they serialise operands, this lifter
//! treats `Instruction::operands` as the canonical source.  The raw operand
//! string is split on whitespace and commas; each token is interpreted as
//! either a register name (`v<N>`), an immediate value (decimal or hex), or a
//! method/field/string reference (kept as a string literal argument).
//!
//! # Supported opcodes
//!
//! All opcodes in the Dalvik instruction set reference are handled, either with
//! a concrete LLIL mapping or via `Effect::Intrinsic` for instructions whose
//! semantics cannot be expressed purely in LLIL (type checks, monitors, etc.).

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Helper: parse operand tokens from raw operand string
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Split the raw operand string into cleaned tokens.
///
/// Handles common disassembler formats:
/// - `v0, v1`  â†’  `["v0", "v1"]`
/// - `v0 v1`   â†’  `["v0", "v1"]`
/// - `v0, #42` â†’  `["v0", "42"]`
/// - `v0, 0x2a` â†’ `["v0", "0x2a"]`
fn operand_tokens(instr: &Instruction) -> Vec<String> {
    // Use structured operand list text if operands field is empty.
    let raw = if instr.operands.is_empty() {
        instr
            .operand_list
            .iter()
            .map(|o| format!("{o}"))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        instr.operands.clone()
    };
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim().trim_start_matches('#').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a token as a `u64`.  Accepts `0x`-prefixed hex and decimal.
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).ok())
}

/// Parse a token as a signed `i64`, returning as `u64` bit-pattern.
fn parse_i64_as_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).ok())
}

/// Return the virtual register name for token at `idx`.
///
/// Returns `"v<idx>"` as a fallback when the token is absent or malformed.
fn token_reg(tokens: &[String], idx: usize) -> String {
    tokens
        .get(idx)
        .filter(|t| t.starts_with('v') || t.starts_with('V'))
        .cloned()
        .unwrap_or_else(|| format!("v{idx}"))
}

/// Return an [`IrExpr::Reg`] for the register at token position `idx`.
fn reg_expr(tokens: &[String], idx: usize) -> IrExpr {
    IrExpr::Reg(token_reg(tokens, idx))
}

/// Return an [`IrExpr::Const`] parsed from the token at `idx`, or
/// [`IrExpr::Undef`] if the token is absent or not a number.
fn imm_expr(tokens: &[String], idx: usize) -> IrExpr {
    tokens
        .get(idx)
        .and_then(|t| parse_i64_as_u64(t))
        .map_or(IrExpr::Undef, IrExpr::Const)
}

/// Return an [`IrExpr`] that represents an immediate-or-register operand.
///
/// Tries to parse `tokens[idx]` as an immediate first; if that fails it
/// treats it as a register reference.
fn imm_or_reg(tokens: &[String], idx: usize) -> IrExpr {
    if let Some(t) = tokens.get(idx) {
        if let Some(v) = parse_i64_as_u64(t) {
            return IrExpr::Const(v);
        }
        return IrExpr::Reg(t.clone());
    }
    IrExpr::Undef
}

/// Build a virtual register name for the high half of a wide pair.
fn wide_high(base: &str) -> String {
    // e.g.  "v4" â†’ "v5"
    if let Some(n_str) = base.strip_prefix('v')
        && let Ok(n) = n_str.parse::<u32>() {
            return format!("v{}", n.saturating_add(1));
        }
    format!("{base}_hi")
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DexLifter struct
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// LLIL lifter for Android DEX (Dalvik/ART) bytecode.
///
/// Instantiate with [`DexLifter::new`].  The lifter is stateless across
/// instruction boundaries; per-method state (register count, argument layout)
/// is not tracked here â€” the caller is responsible for annotating the instruction
/// stream with that context if needed.
#[derive(Debug, Clone)]
pub struct DexLifter;

impl DexLifter {
    /// Create a new DEX lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Core dispatch
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


    // -- First-match sub-helpers --

    fn lift_mnemonic_fx_a(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "move" | "move/from16" | "move/16" => {
                // move vA, vB  â†’  vA = vB
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: src,
                }]
            }
            "move-wide" | "move-wide/from16" | "move-wide/16" => {
                // move-wide vA, vB  â†’  vA = vB (low), vA+1 = vB+1 (high)
                let dst_lo = token_reg(&toks, 0);
                let src_lo = token_reg(&toks, 1);
                let dst_hi = wide_high(&dst_lo);
                let src_hi = wide_high(&src_lo);
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg(src_lo),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg(src_hi),
                    },
                ]
            }
            "move-object" | "move-object/from16" | "move-object/16" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: src,
                }]
            }
            "move-result" | "move-result-object" => {
                // move-result vA  â†’  vA = result_reg
                let dst = token_reg(&toks, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Reg("result".to_string()),
                }]
            }
            "move-result-wide" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
            "move-exception" => {
                let dst = token_reg(&toks, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Reg("exception".to_string()),
                }]
            }
            "return-void" => vec![Effect::Return { value: None }],
            "return" | "return-object" => {
                let val = if toks.is_empty() {
                    IrExpr::Reg("v0".to_string())
                } else {
                    reg_expr(&toks, 0)
                };
                vec![Effect::Return { value: Some(val) }]
            }
            "return-wide" => {
                let val = if toks.is_empty() {
                    IrExpr::Reg("v0".to_string())
                } else {
                    reg_expr(&toks, 0)
                };
                // Represent the wide return as the low half register.
                vec![Effect::Return { value: Some(val) }]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_b(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "const/4" => {
                // const/4 vA, #+B  â€” 4-bit signed literal
                let dst = token_reg(&toks, 0);
                let val = imm_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: val,
                }]
            }
            "const/16" | "const" | "const/32" => {
                let dst = token_reg(&toks, 0);
                let val = imm_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: val,
                }]
            }
            "const/high16" => {
                // Shift the 16-bit literal into the high half of a 32-bit word.
                let dst = token_reg(&toks, 0);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                let shifted = (raw & 0xffff) << 16;
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Const(shifted),
                }]
            }
            "const-wide/16" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                // Sign-extend 16-bit â†’ 64-bit (truncate to the low 16 bits
                // first: `raw` is a u64 built from a possibly-negative i64,
                // so it's typically far outside i16's range and a direct
                // try_from would always fail).
                let extended = i64::from(raw as u16 as i16).cast_unsigned();
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(extended & 0xffff_ffff),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(extended >> 32),
                    },
                ]
            }
            "const-wide/32" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                let extended = i64::from(i32::try_from(raw).unwrap_or(i32::MAX)).cast_unsigned();
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(extended & 0xffff_ffff),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(extended >> 32),
                    },
                ]
            }
            "const-wide" | "const-wide/64" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let v = toks.get(1).and_then(|t| parse_u64(t)).unwrap_or(0);
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(v & 0xffff_ffff),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(v >> 32),
                    },
                ]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_c(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "const-wide/high16" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                let shifted: u64 = (raw & 0xffff) << 48;
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(0),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(shifted >> 32),
                    },
                ]
            }
            "const-string" | "const-string/jumbo" => {
                let dst = token_reg(&toks, 0);
                let _ = toks.get(1).cloned().unwrap_or_else(|| "\"\"".to_string());
                // Emit RegWrite with Undef (actual string object resolved at runtime)
                // plus an intrinsic that records the string reference for analysis.
                vec![
                    Effect::RegWrite {
                        reg: dst.clone(),
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: "const_string".to_string(),
                        args: vec![IrExpr::Reg(dst)],
                    },
                ]
            }
            "const-class" => {
                let dst = token_reg(&toks, 0);
                let cls = toks.get(1).cloned().unwrap_or_default();
                vec![
                    Effect::RegWrite {
                        reg: dst.clone(),
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: format!("const_class:{cls}"),
                        args: vec![IrExpr::Reg(dst), IrExpr::Undef],
                    },
                ]
            }
            "monitor-enter" => {
                let obj = reg_expr(&toks, 0);
                vec![Effect::Intrinsic {
                    name: "monitor_enter".to_string(),
                    args: vec![obj],
                }]
            }
            "monitor-exit" => {
                let obj = reg_expr(&toks, 0);
                vec![Effect::Intrinsic {
                    name: "monitor_exit".to_string(),
                    args: vec![obj],
                }]
            }
            "check-cast" => {
                let obj = reg_expr(&toks, 0);
                let _ = toks.get(1).cloned().unwrap_or_default();
                vec![Effect::Intrinsic {
                    name: "check_cast".to_string(),
                    args: vec![obj, IrExpr::Undef],
                }]
            }
            "instance-of" => {
                let dst = token_reg(&toks, 0);
                let obj = reg_expr(&toks, 1);
                let _ = toks.get(2).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: "instance_of".to_string(),
                        args: vec![obj, IrExpr::Undef],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_d(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        match mnem {
            "array-length" => {
                let dst = token_reg(&toks, 0);
                let arr = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "array_length".to_string(),
                        args: vec![arr],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "new-instance" => {
                let dst = token_reg(&toks, 0);
                let _ = toks.get(1).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: "new_instance".to_string(),
                        args: vec![IrExpr::Undef],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "new-array" => {
                let dst = token_reg(&toks, 0);
                let size = reg_expr(&toks, 1);
                let _ = toks.get(2).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: "new_array".to_string(),
                        args: vec![size, IrExpr::Undef],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "filled-new-array" | "filled-new-array/range" => {
                let arg_exprs: Vec<IrExpr> = toks
                    .iter()
                    .filter(|t| t.starts_with('v'))
                    .map(|t| IrExpr::Reg(t.clone()))
                    .collect();
                vec![Effect::Intrinsic {
                    name: "filled_new_array".to_string(),
                    args: arg_exprs,
                }]
            }
            "fill-array-data" => {
                let arr = reg_expr(&toks, 0);
                let tbl = imm_or_reg(&toks, 1);
                vec![Effect::Intrinsic {
                    name: "fill_array_data".to_string(),
                    args: vec![arr, tbl],
                }]
            }
            "throw" => {
                let exc = reg_expr(&toks, 0);
                vec![Effect::Intrinsic {
                    name: "throw".to_string(),
                    args: vec![exc],
                }]
            }
            "goto" | "goto/16" | "goto/32" => {
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                vec![Effect::Branch {
                    target,
                    condition: None,
                }]
            }
            "packed-switch" | "sparse-switch" => {
                let reg = reg_expr(&toks, 0);
                let tbl = imm_or_reg(&toks, 1);
                vec![Effect::Intrinsic {
                    name: mnem.replace('-', "_"),
                    args: vec![reg, tbl],
                }]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_e(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        match mnem {
            "cmpl-float" | "cmpg-float" | "cmpl-double" | "cmpg-double" | "cmp-long" => {
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                let op_name = mnem.replace('-', "_");
                vec![
                    Effect::Intrinsic {
                        name: op_name,
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "if-eq" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                IrExpr::CmpEqZero(Box::new(IrExpr::Xor(Box::new(a), Box::new(b))))
            }),
            "if-ne" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Xor(
                    Box::new(a),
                    Box::new(b),
                )))))
            }),
            "if-lt" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a < b  â‰¡  sign bit of (a - b) is set
                // NOT CmpEqZero(Shr(Sub(a,b), 31))
                let diff = IrExpr::Sub(Box::new(a), Box::new(b));
                IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))))
            }),
            "if-ge" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a >= b  â‰¡  CmpEqZero(Shr(Sub(a,b), 31))
                let diff = IrExpr::Sub(Box::new(a), Box::new(b));
                IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))
            }),
            "if-gt" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a > b  â‰¡  b < a  â‰¡  sign bit of (b - a) is set
                let diff = IrExpr::Sub(Box::new(b), Box::new(a));
                IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))))
            }),
            "if-le" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a <= b  â‰¡  b >= a  â‰¡  CmpEqZero(Shr(Sub(b,a), 31))
                let diff = IrExpr::Sub(Box::new(b), Box::new(a));
                IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))
            }),
            "if-eqz" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                vec![Effect::Branch {
                    target,
                    condition: Some(IrExpr::CmpEqZero(Box::new(reg))),
                }]
            }
            "if-nez" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                vec![Effect::Branch {
                    target,
                    condition: Some(IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(reg))))),
                }]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_f(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        match mnem {
            "if-ltz" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg < 0  â‰¡  sign bit of reg is set  â‰¡  reg >> 31 != 0
                let cond = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg),
                    Box::new(IrExpr::Const(31)),
                )))));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
            "if-gez" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg >= 0  â‰¡  sign bit is clear
                let cond = IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg),
                    Box::new(IrExpr::Const(31)),
                )));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
            "if-gtz" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg > 0  â‰¡  reg != 0 AND sign bit is clear
                let sign_clear = IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg.clone()),
                    Box::new(IrExpr::Const(31)),
                )));
                let not_zero = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(reg))));
                let cond = IrExpr::And(Box::new(sign_clear), Box::new(not_zero));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
            "if-lez" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg <= 0  â‰¡  reg == 0 OR sign bit set
                let is_zero = IrExpr::CmpEqZero(Box::new(reg.clone()));
                let sign_set = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg),
                    Box::new(IrExpr::Const(31)),
                )))));
                let cond = IrExpr::Or(Box::new(is_zero), Box::new(sign_set));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
            "aget" | "aget-object" => Self::aget(&toks, 4),
            "aget-wide" => Self::aget_wide(&toks),
            "aget-boolean" | "aget-byte" => Self::aget(&toks, 1),
            "aget-char" | "aget-short" => Self::aget(&toks, 2),
            "aput" | "aput-object" => Self::aput(&toks, 4),
            "aput-wide" => Self::aput_wide(&toks),
            "aput-boolean" | "aput-byte" => Self::aput(&toks, 1),
            "aput-char" | "aput-short" => Self::aput(&toks, 2),
            "iget" | "iget-object" => Self::iget(&toks, 4),
            "iget-wide" => Self::iget_wide(&toks),
            "iget-boolean" | "iget-byte" => Self::iget(&toks, 1),
            "iget-char" | "iget-short" => Self::iget(&toks, 2),
            "iput" | "iput-object" => Self::iput(&toks, 4),
            "iput-wide" => Self::iput_wide(&toks),
            "iput-boolean" | "iput-byte" => Self::iput(&toks, 1),
            "iput-char" | "iput-short" => Self::iput(&toks, 2),
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_g(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "sget" | "sget-object" => {
                let dst = token_reg(&toks, 0);
                let field_ref = toks.get(1).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: format!("sget_field:{field_ref}"),
                        args: vec![IrExpr::Reg(dst.clone())],
                    },
                    Effect::MemRead {
                        addr: IrExpr::Undef, // static field address resolved at runtime
                        dest: dst,
                        size: 4,
                    },
                ]
            }
            "sget-wide" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                vec![
                    Effect::MemRead {
                        addr: IrExpr::Undef,
                        dest: dst_lo,
                        size: 4,
                    },
                    Effect::MemRead {
                        addr: IrExpr::Undef,
                        dest: dst_hi,
                        size: 4,
                    },
                ]
            }
            "sget-boolean" | "sget-byte" => {
                let dst = token_reg(&toks, 0);
                vec![Effect::MemRead {
                    addr: IrExpr::Undef,
                    dest: dst,
                    size: 1,
                }]
            }
            "sget-char" | "sget-short" => {
                let dst = token_reg(&toks, 0);
                vec![Effect::MemRead {
                    addr: IrExpr::Undef,
                    dest: dst,
                    size: 2,
                }]
            }
            "sput" | "sput-object" => {
                let src = reg_expr(&toks, 0);
                vec![Effect::MemWrite {
                    addr: IrExpr::Undef,
                    value: src,
                    size: 4,
                }]
            }
            "sput-wide" => {
                let src_lo = reg_expr(&toks, 0);
                let src_name_hi = toks.first().map(|t| wide_high(t)).unwrap_or_default();
                vec![
                    Effect::MemWrite {
                        addr: IrExpr::Undef,
                        value: src_lo,
                        size: 4,
                    },
                    Effect::MemWrite {
                        addr: IrExpr::Undef,
                        value: IrExpr::Reg(src_name_hi),
                        size: 4,
                    },
                ]
            }
            "sput-boolean" | "sput-byte" => {
                let src = reg_expr(&toks, 0);
                vec![Effect::MemWrite {
                    addr: IrExpr::Undef,
                    value: src,
                    size: 1,
                }]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_h(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "sput-char" | "sput-short" => {
                let src = reg_expr(&toks, 0);
                vec![Effect::MemWrite {
                    addr: IrExpr::Undef,
                    value: src,
                    size: 2,
                }]
            }
            "invoke-virtual"
            | "invoke-super"
            | "invoke-direct"
            | "invoke-static"
            | "invoke-interface"
            | "invoke-virtual/range"
            | "invoke-super/range"
            | "invoke-direct/range"
            | "invoke-static/range"
            | "invoke-interface/range"
            | "invoke-polymorphic"
            | "invoke-polymorphic/range"
            | "invoke-custom"
            | "invoke-custom/range" => {
                // target is the method reference token (last non-register token or first token after regs)
                let target_tok = toks
                    .iter()
                    .find(|t| !t.starts_with('v') && !t.starts_with('{') && !t.starts_with('}'))
                    .cloned()
                    .unwrap_or_else(|| "method".to_string());
                // Collect register args
                let arg_exprs: Vec<IrExpr> = toks
                    .iter()
                    .filter(|t| t.starts_with('v'))
                    .map(|t| IrExpr::Reg(t.clone()))
                    .collect();
                let mut effects = vec![Effect::Call {
                    target: IrExpr::Const(parse_u64(&target_tok).unwrap_or(0)),
                }];
                // Record args as an intrinsic annotation
                effects.push(Effect::Intrinsic {
                    name: "invoke_args".to_string(),
                    args: arg_exprs,
                });
                effects
            }
            "add-int" => Self::binop3(&toks, IrExpr::add_fn),
            "sub-int" => Self::binop3(&toks, IrExpr::sub_fn),
            "mul-int" => Self::binop3(&toks, IrExpr::mul_fn),
            "div-int" => {
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "div_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "rem-int" => {
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "rem_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "and-int" => Self::binop3(&toks, IrExpr::and_fn),
            "or-int" => Self::binop3(&toks, IrExpr::or_fn),
            "xor-int" => Self::binop3(&toks, IrExpr::xor_fn),
            "shl-int" => Self::binop3(&toks, IrExpr::shl_fn),
            // `shr-int` is ARITHMETIC, `ushr-int` LOGICAL. They shared this arm
            // and both became a logical `Shr`, so the signed form was wrong for
            // every negative value and the two were indistinguishable. The
            // `-long` forms already keep them apart, by intrinsic name.
            "shr-int" => Self::binop3(&toks, IrExpr::sar_fn),
            "ushr-int" => Self::binop3(&toks, IrExpr::shr_fn),
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_i(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "add-long" | "sub-long" | "mul-long" | "div-long" | "rem-long" | "and-long"
            | "or-long" | "xor-long" | "shl-long" | "shr-long" | "ushr-long" => {
                let op = mnem.trim_end_matches("-long").replace('-', "_");
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let lhs_lo = reg_expr(&toks, 1);
                let rhs_lo = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: format!("{op}_long"),
                        args: vec![lhs_lo, rhs_lo],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
            "add-float" | "sub-float" | "mul-float" | "div-float" | "rem-float" | "add-double"
            | "sub-double" | "mul-double" | "div-double" | "rem-double" => {
                let op = mnem.replace('-', "_");
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: op,
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "add-int/2addr" => Self::binop2addr(&toks, IrExpr::add_fn),
            "sub-int/2addr" => Self::binop2addr(&toks, IrExpr::sub_fn),
            "mul-int/2addr" => Self::binop2addr(&toks, IrExpr::mul_fn),
            "div-int/2addr" => {
                let dst = token_reg(&toks, 0);
                let rhs = reg_expr(&toks, 1);
                let lhs = IrExpr::Reg(dst.clone());
                vec![
                    Effect::Intrinsic {
                        name: "div_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "rem-int/2addr" => {
                let dst = token_reg(&toks, 0);
                let rhs = reg_expr(&toks, 1);
                let lhs = IrExpr::Reg(dst.clone());
                vec![
                    Effect::Intrinsic {
                        name: "rem_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "and-int/2addr" => Self::binop2addr(&toks, IrExpr::and_fn),
            "or-int/2addr" => Self::binop2addr(&toks, IrExpr::or_fn),
            "xor-int/2addr" => Self::binop2addr(&toks, IrExpr::xor_fn),
            "shl-int/2addr" => Self::binop2addr(&toks, IrExpr::shl_fn),
            "shr-int/2addr" => Self::binop2addr(&toks, IrExpr::sar_fn),
            "ushr-int/2addr" => Self::binop2addr(&toks, IrExpr::shr_fn),
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_j(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "add-long/2addr" | "sub-long/2addr" | "mul-long/2addr" | "div-long/2addr"
            | "rem-long/2addr" | "and-long/2addr" | "or-long/2addr" | "xor-long/2addr"
            | "shl-long/2addr" | "shr-long/2addr" | "ushr-long/2addr" => {
                let op = mnem.trim_end_matches("/2addr").replace('-', "_");
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let rhs_lo = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: format!("{op}_2addr"),
                        args: vec![IrExpr::Reg(dst_lo.clone()), rhs_lo],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
            "add-float/2addr" | "sub-float/2addr" | "mul-float/2addr" | "div-float/2addr"
            | "rem-float/2addr" | "add-double/2addr" | "sub-double/2addr" | "mul-double/2addr"
            | "div-double/2addr" | "rem-double/2addr" => {
                let op = mnem.trim_end_matches("/2addr").replace('-', "_");
                let dst = token_reg(&toks, 0);
                let rhs = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: op,
                        args: vec![IrExpr::Reg(dst.clone()), rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "add-int/lit16" | "add-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::wrap32(IrExpr::Add(Box::new(src), Box::new(lit))),
                }]
            }
            "rsub-int" | "rsub-int/lit8" => {
                // rsub-int vA, vB, #+CC  â†’  vA = CC - vB  (reversed subtract)
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::wrap32(IrExpr::Sub(Box::new(lit), Box::new(src))),
                }]
            }
            "mul-int/lit16" | "mul-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::wrap32(IrExpr::Mul(Box::new(src), Box::new(lit))),
                }]
            }
            "div-int/lit16" | "div-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "div_int".to_string(),
                        args: vec![src, lit],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_k(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "rem-int/lit16" | "rem-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "rem_int".to_string(),
                        args: vec![src, lit],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "and-int/lit16" | "and-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(src), Box::new(lit)),
                }]
            }
            "or-int/lit16" | "or-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(src), Box::new(lit)),
                }]
            }
            "xor-int/lit16" | "xor-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Xor(Box::new(src), Box::new(lit)),
                }]
            }
            "shl-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shl(Box::new(src), Box::new(lit)),
                }]
            }
            // Third form of the same pair, after the plain and `/2addr` ones:
            // `shr-int` is ARITHMETIC, `ushr-int` LOGICAL.
            "shr-int/lit8" | "ushr-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                let value = if mnem.starts_with('u') {
                    IrExpr::Shr(Box::new(src), Box::new(lit))
                } else {
                    IrExpr::Sar(Box::new(src), Box::new(lit))
                };
                vec![Effect::RegWrite { reg: dst, value }]
            }
            "not-int" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Not(Box::new(src)),
                }]
            }
            "not-long" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let src_lo = reg_expr(&toks, 1);
                let src_name_hi = toks.get(1).map(|t| wide_high(t)).unwrap_or_default();
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Not(Box::new(src_lo)),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Not(Box::new(IrExpr::Reg(src_name_hi))),
                    },
                ]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_l(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        match mnem {
            "neg-int" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_int".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "neg-long" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_long".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
            "neg-float" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_float".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "neg-double" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_double".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
            "int-to-long" | "int-to-float" | "int-to-double" | "long-to-int" | "long-to-float"
            | "long-to-double" | "float-to-int" | "float-to-long" | "float-to-double"
            | "double-to-int" | "double-to-long" | "double-to-float" | "int-to-byte"
            | "int-to-char" | "int-to-short" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let op = mnem.replace('-', "_");
                vec![
                    Effect::Intrinsic {
                        name: op,
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            _ => vec![],
        }
    }

    fn lift_mnemonic_fx_m(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let other = mnem;
                let args: Vec<IrExpr> = toks
                    .iter()
                    .map(|t| {
                        parse_i64_as_u64(t).map_or_else(|| IrExpr::Reg(t.clone()), IrExpr::Const)
                    })
                    .collect();
                vec![Effect::Intrinsic {
                    name: other.to_string(),
                    args,
                }]
        
    }

    fn lift_mnemonic_first(instr: &Instruction) -> std::vec::Vec<Effect> {
        let __r0 = Self::lift_mnemonic_fx_a(instr);
        if !__r0.is_empty() { return __r0; }
        let __r1 = Self::lift_mnemonic_fx_b(instr);
        if !__r1.is_empty() { return __r1; }
        let __r2 = Self::lift_mnemonic_fx_c(instr);
        if !__r2.is_empty() { return __r2; }
        let __r3 = Self::lift_mnemonic_fx_d(instr);
        if !__r3.is_empty() { return __r3; }
        let __r4 = Self::lift_mnemonic_fx_e(instr);
        if !__r4.is_empty() { return __r4; }
        let __r5 = Self::lift_mnemonic_fx_f(instr);
        if !__r5.is_empty() { return __r5; }
        let __r6 = Self::lift_mnemonic_fx_g(instr);
        if !__r6.is_empty() { return __r6; }
        let __r7 = Self::lift_mnemonic_fx_h(instr);
        if !__r7.is_empty() { return __r7; }
        let __r8 = Self::lift_mnemonic_fx_i(instr);
        if !__r8.is_empty() { return __r8; }
        let __r9 = Self::lift_mnemonic_fx_j(instr);
        if !__r9.is_empty() { return __r9; }
        let __r10 = Self::lift_mnemonic_fx_k(instr);
        if !__r10.is_empty() { return __r10; }
        let __r11 = Self::lift_mnemonic_fx_l(instr);
        if !__r11.is_empty() { return __r11; }
        Self::lift_mnemonic_fx_m(instr)
    }

    // -- Second-match helpers --

    fn lift_mnemonic_a(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            // Ã¢â€�â‚¬Ã¢â€�â‚¬ nop Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ move variants Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "move" | "move/from16" | "move/16" => {
                // move vA, vB  Ã¢â€ â€™  vA = vB
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: src,
                }]
            }

            "move-wide" | "move-wide/from16" | "move-wide/16" => {
                // move-wide vA, vB  Ã¢â€ â€™  vA = vB (low), vA+1 = vB+1 (high)
                let dst_lo = token_reg(&toks, 0);
                let src_lo = token_reg(&toks, 1);
                let dst_hi = wide_high(&dst_lo);
                let src_hi = wide_high(&src_lo);
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg(src_lo),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg(src_hi),
                    },
                ]
            }

            "move-object" | "move-object/from16" | "move-object/16" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: src,
                }]
            }

            "move-result" | "move-result-object" => {
                // move-result vA  Ã¢â€ â€™  vA = result_reg
                let dst = token_reg(&toks, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Reg("result".to_string()),
                }]
            }

            "move-result-wide" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_b(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {

            "move-exception" => {
                let dst = token_reg(&toks, 0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Reg("exception".to_string()),
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ return Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "return-void" => vec![Effect::Return { value: None }],

            "return" | "return-object" => {
                let val = if toks.is_empty() {
                    IrExpr::Reg("v0".to_string())
                } else {
                    reg_expr(&toks, 0)
                };
                vec![Effect::Return { value: Some(val) }]
            }

            "return-wide" => {
                let val = if toks.is_empty() {
                    IrExpr::Reg("v0".to_string())
                } else {
                    reg_expr(&toks, 0)
                };
                // Represent the wide return as the low half register.
                vec![Effect::Return { value: Some(val) }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ const family Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "const/4" => {
                // const/4 vA, #+B  Ã¢â‚¬â€� 4-bit signed literal
                let dst = token_reg(&toks, 0);
                let val = imm_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: val,
                }]
            }

            "const/16" | "const" | "const/32" => {
                let dst = token_reg(&toks, 0);
                let val = imm_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: val,
                }]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_c(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {

            "const/high16" => {
                // Shift the 16-bit literal into the high half of a 32-bit word.
                let dst = token_reg(&toks, 0);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                let shifted = (raw & 0xffff) << 16;
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Const(shifted),
                }]
            }

            "const-wide/16" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                // Sign-extend 16-bit Ã¢â€ â€™ 64-bit
                let extended = i64::from(raw as u16 as i16).cast_unsigned();
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(extended & 0xffff_ffff),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(extended >> 32),
                    },
                ]
            }

            "const-wide/32" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                let extended = i64::from(i32::try_from(raw).unwrap_or(i32::MAX)).cast_unsigned();
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(extended & 0xffff_ffff),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(extended >> 32),
                    },
                ]
            }

            "const-wide" | "const-wide/64" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let v = toks.get(1).and_then(|t| parse_u64(t)).unwrap_or(0);
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(v & 0xffff_ffff),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(v >> 32),
                    },
                ]
            }

            "const-wide/high16" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let raw = toks.get(1).and_then(|t| parse_i64_as_u64(t)).unwrap_or(0);
                let shifted: u64 = (raw & 0xffff) << 48;
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Const(0),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Const(shifted >> 32),
                    },
                ]
            }

            "const-string" | "const-string/jumbo" => {
                let dst = token_reg(&toks, 0);
                let _ = toks.get(1).cloned().unwrap_or_else(|| "\"\"".to_string());
                // Emit RegWrite with Undef (actual string object resolved at runtime)
                // plus an intrinsic that records the string reference for analysis.
                vec![
                    Effect::RegWrite {
                        reg: dst.clone(),
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: "const_string".to_string(),
                        args: vec![IrExpr::Reg(dst)],
                    },
                ]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_d(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {

            "const-class" => {
                let dst = token_reg(&toks, 0);
                let cls = toks.get(1).cloned().unwrap_or_default();
                vec![
                    Effect::RegWrite {
                        reg: dst.clone(),
                        value: IrExpr::Undef,
                    },
                    Effect::Intrinsic {
                        name: format!("const_class:{cls}"),
                        args: vec![IrExpr::Reg(dst), IrExpr::Undef],
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ monitor Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "monitor-enter" => {
                let obj = reg_expr(&toks, 0);
                vec![Effect::Intrinsic {
                    name: "monitor_enter".to_string(),
                    args: vec![obj],
                }]
            }

            "monitor-exit" => {
                let obj = reg_expr(&toks, 0);
                vec![Effect::Intrinsic {
                    name: "monitor_exit".to_string(),
                    args: vec![obj],
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ type checks Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "check-cast" => {
                let obj = reg_expr(&toks, 0);
                let _ = toks.get(1).cloned().unwrap_or_default();
                vec![Effect::Intrinsic {
                    name: "check_cast".to_string(),
                    args: vec![obj, IrExpr::Undef],
                }]
            }

            "instance-of" => {
                let dst = token_reg(&toks, 0);
                let obj = reg_expr(&toks, 1);
                let _ = toks.get(2).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: "instance_of".to_string(),
                        args: vec![obj, IrExpr::Undef],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ array-length Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "array-length" => {
                let dst = token_reg(&toks, 0);
                let arr = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "array_length".to_string(),
                        args: vec![arr],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_e(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ new-instance Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "new-instance" => {
                let dst = token_reg(&toks, 0);
                let _ = toks.get(1).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: "new_instance".to_string(),
                        args: vec![IrExpr::Undef],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ new-array Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "new-array" => {
                let dst = token_reg(&toks, 0);
                let size = reg_expr(&toks, 1);
                let _ = toks.get(2).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: "new_array".to_string(),
                        args: vec![size, IrExpr::Undef],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ filled-new-array Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "filled-new-array" | "filled-new-array/range" => {
                let arg_exprs: Vec<IrExpr> = toks
                    .iter()
                    .filter(|t| t.starts_with('v'))
                    .map(|t| IrExpr::Reg(t.clone()))
                    .collect();
                vec![Effect::Intrinsic {
                    name: "filled_new_array".to_string(),
                    args: arg_exprs,
                }]
            }

            "fill-array-data" => {
                let arr = reg_expr(&toks, 0);
                let tbl = imm_or_reg(&toks, 1);
                vec![Effect::Intrinsic {
                    name: "fill_array_data".to_string(),
                    args: vec![arr, tbl],
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ throw Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "throw" => {
                let exc = reg_expr(&toks, 0);
                vec![Effect::Intrinsic {
                    name: "throw".to_string(),
                    args: vec![exc],
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ goto Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "goto" | "goto/16" | "goto/32" => {
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                vec![Effect::Branch {
                    target,
                    condition: None,
                }]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_f(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ switch tables Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "packed-switch" | "sparse-switch" => {
                let reg = reg_expr(&toks, 0);
                let tbl = imm_or_reg(&toks, 1);
                vec![Effect::Intrinsic {
                    name: mnem.replace('-', "_"),
                    args: vec![reg, tbl],
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ float/double comparisons Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "cmpl-float" | "cmpg-float" | "cmpl-double" | "cmpg-double" | "cmp-long" => {
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                let op_name = mnem.replace('-', "_");
                vec![
                    Effect::Intrinsic {
                        name: op_name,
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ conditional branches (two registers) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "if-eq" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                IrExpr::CmpEqZero(Box::new(IrExpr::Xor(Box::new(a), Box::new(b))))
            }),
            "if-ne" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Xor(
                    Box::new(a),
                    Box::new(b),
                )))))
            }),
            "if-lt" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a < b  Ã¢â€°Â¡  sign bit of (a - b) is set
                // NOT CmpEqZero(Shr(Sub(a,b), 31))
                let diff = IrExpr::Sub(Box::new(a), Box::new(b));
                IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))))
            }),
            "if-ge" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a >= b  Ã¢â€°Â¡  CmpEqZero(Shr(Sub(a,b), 31))
                let diff = IrExpr::Sub(Box::new(a), Box::new(b));
                IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))
            }),
                _ => vec![],
            }
    }
    fn lift_mnemonic_g(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "if-gt" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a > b  Ã¢â€°Â¡  b < a  Ã¢â€°Â¡  sign bit of (b - a) is set
                let diff = IrExpr::Sub(Box::new(b), Box::new(a));
                IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))))
            }),
            "if-le" => Self::cond_branch_rr(&toks, addr, instr.size, |a, b| {
                // a <= b  Ã¢â€°Â¡  b >= a  Ã¢â€°Â¡  CmpEqZero(Shr(Sub(b,a), 31))
                let diff = IrExpr::Sub(Box::new(b), Box::new(a));
                IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(diff),
                    Box::new(IrExpr::Const(31)),
                )))
            }),

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ conditional branches (compare with zero) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "if-eqz" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                vec![Effect::Branch {
                    target,
                    condition: Some(IrExpr::CmpEqZero(Box::new(reg))),
                }]
            }
            "if-nez" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                vec![Effect::Branch {
                    target,
                    condition: Some(IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(reg))))),
                }]
            }
            "if-ltz" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg < 0  Ã¢â€°Â¡  sign bit of reg is set  Ã¢â€°Â¡  reg >> 31 != 0
                let cond = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg),
                    Box::new(IrExpr::Const(31)),
                )))));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
            "if-gez" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg >= 0  Ã¢â€°Â¡  sign bit is clear
                let cond = IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg),
                    Box::new(IrExpr::Const(31)),
                )));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_h(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let addr = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "if-gtz" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg > 0  Ã¢â€°Â¡  reg != 0 AND sign bit is clear
                let sign_clear = IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg.clone()),
                    Box::new(IrExpr::Const(31)),
                )));
                let not_zero = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(reg))));
                let cond = IrExpr::And(Box::new(sign_clear), Box::new(not_zero));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }
            "if-lez" => {
                let reg = reg_expr(&toks, 0);
                let target = Self::branch_target_from_tokens(&toks, addr, instr.size);
                // reg <= 0  Ã¢â€°Â¡  reg == 0 OR sign bit set
                let is_zero = IrExpr::CmpEqZero(Box::new(reg.clone()));
                let sign_set = IrExpr::Not(Box::new(IrExpr::CmpEqZero(Box::new(IrExpr::Shr(
                    Box::new(reg),
                    Box::new(IrExpr::Const(31)),
                )))));
                let cond = IrExpr::Or(Box::new(is_zero), Box::new(sign_set));
                vec![Effect::Branch {
                    target,
                    condition: Some(cond),
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ array access (aget) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "aget" | "aget-object" => Self::aget(&toks, 4),
            "aget-wide" => Self::aget_wide(&toks),
            "aget-boolean" | "aget-byte" => Self::aget(&toks, 1),
            "aget-char" | "aget-short" => Self::aget(&toks, 2),
                _ => vec![],
            }
    }
    fn lift_mnemonic_i(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            // Ã¢â€�â‚¬Ã¢â€�â‚¬ array access (aput) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "aput" | "aput-object" => Self::aput(&toks, 4),
            "aput-wide" => Self::aput_wide(&toks),
            "aput-boolean" | "aput-byte" => Self::aput(&toks, 1),
            "aput-char" | "aput-short" => Self::aput(&toks, 2),
            // Ã¢â€�â‚¬Ã¢â€�â‚¬ instance field access (iget / iput) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            // iget vA, vB, field@CCCC  Ã¢â€ â€™  vA = mem[vB + field_offset]
            "iget" | "iget-object" => Self::iget(&toks, 4),
            "iget-wide" => Self::iget_wide(&toks),
                _ => vec![],
            }
    }
    fn lift_mnemonic_j(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "iget-boolean" | "iget-byte" => Self::iget(&toks, 1),
            "iget-char" | "iget-short" => Self::iget(&toks, 2),
            "iput" | "iput-object" => Self::iput(&toks, 4),
            "iput-wide" => Self::iput_wide(&toks),
            "iput-boolean" | "iput-byte" => Self::iput(&toks, 1),
            "iput-char" | "iput-short" => Self::iput(&toks, 2),
                _ => vec![],
            }
    }
    fn lift_mnemonic_k(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            // Ã¢â€�â‚¬Ã¢â€�â‚¬ static field access (sget / sput) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            // sget vA, field@BBBB  Ã¢â€ â€™  vA = [static_field_address]
            "sget" | "sget-object" => {
                let dst = token_reg(&toks, 0);
                let field_ref = toks.get(1).cloned().unwrap_or_default();
                vec![
                    Effect::Intrinsic {
                        name: format!("sget_field:{field_ref}"),
                        args: vec![IrExpr::Reg(dst.clone())],
                    },
                    Effect::MemRead {
                        addr: IrExpr::Undef, // static field address resolved at runtime
                        dest: dst,
                        size: 4,
                    },
                ]
            }
            "sget-wide" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                vec![
                    Effect::MemRead {
                        addr: IrExpr::Undef,
                        dest: dst_lo,
                        size: 4,
                    },
                    Effect::MemRead {
                        addr: IrExpr::Undef,
                        dest: dst_hi,
                        size: 4,
                    },
                ]
            }
            "sget-boolean" | "sget-byte" => {
                let dst = token_reg(&toks, 0);
                vec![Effect::MemRead {
                    addr: IrExpr::Undef,
                    dest: dst,
                    size: 1,
                }]
            }
            "sget-char" | "sget-short" => {
                let dst = token_reg(&toks, 0);
                vec![Effect::MemRead {
                    addr: IrExpr::Undef,
                    dest: dst,
                    size: 2,
                }]
            }

            "sput" | "sput-object" => {
                let src = reg_expr(&toks, 0);
                vec![Effect::MemWrite {
                    addr: IrExpr::Undef,
                    value: src,
                    size: 4,
                }]
            }
            "sput-wide" => {
                let src_lo = reg_expr(&toks, 0);
                let src_name_hi = toks.first().map(|t| wide_high(t)).unwrap_or_default();
                vec![
                    Effect::MemWrite {
                        addr: IrExpr::Undef,
                        value: src_lo,
                        size: 4,
                    },
                    Effect::MemWrite {
                        addr: IrExpr::Undef,
                        value: IrExpr::Reg(src_name_hi),
                        size: 4,
                    },
                ]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_l(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "sput-boolean" | "sput-byte" => {
                let src = reg_expr(&toks, 0);
                vec![Effect::MemWrite {
                    addr: IrExpr::Undef,
                    value: src,
                    size: 1,
                }]
            }
            "sput-char" | "sput-short" => {
                let src = reg_expr(&toks, 0);
                vec![Effect::MemWrite {
                    addr: IrExpr::Undef,
                    value: src,
                    size: 2,
                }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ invoke Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "invoke-virtual"
            | "invoke-super"
            | "invoke-direct"
            | "invoke-static"
            | "invoke-interface"
            | "invoke-virtual/range"
            | "invoke-super/range"
            | "invoke-direct/range"
            | "invoke-static/range"
            | "invoke-interface/range"
            | "invoke-polymorphic"
            | "invoke-polymorphic/range"
            | "invoke-custom"
            | "invoke-custom/range" => {
                // target is the method reference token (last non-register token or first token after regs)
                let target_tok = toks
                    .iter()
                    .find(|t| !t.starts_with('v') && !t.starts_with('{') && !t.starts_with('}'))
                    .cloned()
                    .unwrap_or_else(|| "method".to_string());
                // Collect register args
                let arg_exprs: Vec<IrExpr> = toks
                    .iter()
                    .filter(|t| t.starts_with('v'))
                    .map(|t| IrExpr::Reg(t.clone()))
                    .collect();
                let mut effects = vec![Effect::Call {
                    target: IrExpr::Const(parse_u64(&target_tok).unwrap_or(0)),
                }];
                // Record args as an intrinsic annotation
                effects.push(Effect::Intrinsic {
                    name: "invoke_args".to_string(),
                    args: arg_exprs,
                });
                effects
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ integer arithmetic (3-register) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-int" => Self::binop3(&toks, IrExpr::add_fn),
            "sub-int" => Self::binop3(&toks, IrExpr::sub_fn),
            "mul-int" => Self::binop3(&toks, IrExpr::mul_fn),
                _ => vec![],
            }
    }
    fn lift_mnemonic_m(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "div-int" => {
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "div_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "rem-int" => {
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "rem_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "and-int" => Self::binop3(&toks, IrExpr::and_fn),
            "or-int" => Self::binop3(&toks, IrExpr::or_fn),
            "xor-int" => Self::binop3(&toks, IrExpr::xor_fn),
            "shl-int" => Self::binop3(&toks, IrExpr::shl_fn),
                _ => vec![],
            }
    }
    fn lift_mnemonic_n(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            // `shr-int` is ARITHMETIC, `ushr-int` LOGICAL. They shared this arm
            // and both became a logical `Shr`, so the signed form was wrong for
            // every negative value and the two were indistinguishable. The
            // `-long` forms already keep them apart, by intrinsic name.
            "shr-int" => Self::binop3(&toks, IrExpr::sar_fn),
            "ushr-int" => Self::binop3(&toks, IrExpr::shr_fn),
            // logical right shift

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ long (wide) arithmetic Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-long" | "sub-long" | "mul-long" | "div-long" | "rem-long" | "and-long"
            | "or-long" | "xor-long" | "shl-long" | "shr-long" | "ushr-long" => {
                let op = mnem.trim_end_matches("-long").replace('-', "_");
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let lhs_lo = reg_expr(&toks, 1);
                let rhs_lo = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: format!("{op}_long"),
                        args: vec![lhs_lo, rhs_lo],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ float / double arithmetic Ã¢â€ â€™ intrinsics Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-float" | "sub-float" | "mul-float" | "div-float" | "rem-float" | "add-double"
            | "sub-double" | "mul-double" | "div-double" | "rem-double" => {
                let op = mnem.replace('-', "_");
                let dst = token_reg(&toks, 0);
                let lhs = reg_expr(&toks, 1);
                let rhs = reg_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: op,
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ 2-address forms (vA op= vB) Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-int/2addr" => Self::binop2addr(&toks, IrExpr::add_fn),
            "sub-int/2addr" => Self::binop2addr(&toks, IrExpr::sub_fn),
            "mul-int/2addr" => Self::binop2addr(&toks, IrExpr::mul_fn),
                _ => vec![],
            }
    }
    fn lift_mnemonic_o(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "div-int/2addr" => {
                let dst = token_reg(&toks, 0);
                let rhs = reg_expr(&toks, 1);
                let lhs = IrExpr::Reg(dst.clone());
                vec![
                    Effect::Intrinsic {
                        name: "div_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "rem-int/2addr" => {
                let dst = token_reg(&toks, 0);
                let rhs = reg_expr(&toks, 1);
                let lhs = IrExpr::Reg(dst.clone());
                vec![
                    Effect::Intrinsic {
                        name: "rem_int".to_string(),
                        args: vec![lhs, rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "and-int/2addr" => Self::binop2addr(&toks, IrExpr::and_fn),
            "or-int/2addr" => Self::binop2addr(&toks, IrExpr::or_fn),
            "xor-int/2addr" => Self::binop2addr(&toks, IrExpr::xor_fn),
            "shl-int/2addr" => Self::binop2addr(&toks, IrExpr::shl_fn),
                _ => vec![],
            }
    }
    fn lift_mnemonic_p(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "shr-int/2addr" => Self::binop2addr(&toks, IrExpr::sar_fn),
            "ushr-int/2addr" => Self::binop2addr(&toks, IrExpr::shr_fn),
            // Ã¢â€�â‚¬Ã¢â€�â‚¬ 2-address long Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-long/2addr" | "sub-long/2addr" | "mul-long/2addr" | "div-long/2addr"
            | "rem-long/2addr" | "and-long/2addr" | "or-long/2addr" | "xor-long/2addr"
            | "shl-long/2addr" | "shr-long/2addr" | "ushr-long/2addr" => {
                let op = mnem.trim_end_matches("/2addr").replace('-', "_");
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let rhs_lo = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: format!("{op}_2addr"),
                        args: vec![IrExpr::Reg(dst_lo.clone()), rhs_lo],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ 2-address float / double Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-float/2addr" | "sub-float/2addr" | "mul-float/2addr" | "div-float/2addr"
            | "rem-float/2addr" | "add-double/2addr" | "sub-double/2addr" | "mul-double/2addr"
            | "div-double/2addr" | "rem-double/2addr" => {
                let op = mnem.trim_end_matches("/2addr").replace('-', "_");
                let dst = token_reg(&toks, 0);
                let rhs = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: op,
                        args: vec![IrExpr::Reg(dst.clone()), rhs],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ lit16 / lit8 forms Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "add-int/lit16" | "add-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::wrap32(IrExpr::Add(Box::new(src), Box::new(lit))),
                }]
            }
            "rsub-int" | "rsub-int/lit8" => {
                // rsub-int vA, vB, #+CC  Ã¢â€ â€™  vA = CC - vB  (reversed subtract)
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::wrap32(IrExpr::Sub(Box::new(lit), Box::new(src))),
                }]
            }
            "mul-int/lit16" | "mul-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::wrap32(IrExpr::Mul(Box::new(src), Box::new(lit))),
                }]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_q(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "div-int/lit16" | "div-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "div_int".to_string(),
                        args: vec![src, lit],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "rem-int/lit16" | "rem-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![
                    Effect::Intrinsic {
                        name: "rem_int".to_string(),
                        args: vec![src, lit],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "and-int/lit16" | "and-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(src), Box::new(lit)),
                }]
            }
            "or-int/lit16" | "or-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(src), Box::new(lit)),
                }]
            }
            "xor-int/lit16" | "xor-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Xor(Box::new(src), Box::new(lit)),
                }]
            }
            "shl-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Shl(Box::new(src), Box::new(lit)),
                }]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_r(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            // Third form of the same pair, after the plain and `/2addr` ones:
            // `shr-int` is ARITHMETIC, `ushr-int` LOGICAL.
            "shr-int/lit8" | "ushr-int/lit8" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let lit = imm_expr(&toks, 2);
                let value = if mnem.starts_with('u') {
                    IrExpr::Shr(Box::new(src), Box::new(lit))
                } else {
                    IrExpr::Sar(Box::new(src), Box::new(lit))
                };
                vec![Effect::RegWrite { reg: dst, value }]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ unary ops Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "not-int" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Not(Box::new(src)),
                }]
            }
            "not-long" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let src_lo = reg_expr(&toks, 1);
                let src_name_hi = toks.get(1).map(|t| wide_high(t)).unwrap_or_default();
                vec![
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Not(Box::new(src_lo)),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Not(Box::new(IrExpr::Reg(src_name_hi))),
                    },
                ]
            }
            "neg-int" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_int".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
            "neg-long" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_long".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }
            "neg-float" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_float".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }
                _ => vec![],
            }
    }
    fn lift_mnemonic_s(instr: &Instruction) -> std::vec::Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let mnem = mnem.trim();
        let toks = operand_tokens(instr);
        let _ = instr.address.0;

        let _effects = Self::lift_mnemonic_first(instr);

            match mnem {
            "neg-double" => {
                let dst_lo = token_reg(&toks, 0);
                let dst_hi = wide_high(&dst_lo);
                let src = reg_expr(&toks, 1);
                vec![
                    Effect::Intrinsic {
                        name: "neg_double".to_string(),
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst_lo,
                        value: IrExpr::Reg("result_lo".to_string()),
                    },
                    Effect::RegWrite {
                        reg: dst_hi,
                        value: IrExpr::Reg("result_hi".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ type conversion intrinsics Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            "int-to-long" | "int-to-float" | "int-to-double" | "long-to-int" | "long-to-float"
            | "long-to-double" | "float-to-int" | "float-to-long" | "float-to-double"
            | "double-to-int" | "double-to-long" | "double-to-float" | "int-to-byte"
            | "int-to-char" | "int-to-short" => {
                let dst = token_reg(&toks, 0);
                let src = reg_expr(&toks, 1);
                let op = mnem.replace('-', "_");
                vec![
                    Effect::Intrinsic {
                        name: op,
                        args: vec![src],
                    },
                    Effect::RegWrite {
                        reg: dst,
                        value: IrExpr::Reg("result".to_string()),
                    },
                ]
            }

            // Ã¢â€�â‚¬Ã¢â€�â‚¬ catch-all: unknown opcode Ã¢â€ â€™ Intrinsic stub Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬Ã¢â€�â‚¬
            other => {
                let args: Vec<IrExpr> = toks
                    .iter()
                    .map(|t| {
                        parse_i64_as_u64(t).map_or_else(|| IrExpr::Reg(t.clone()), IrExpr::Const)
                    })
                    .collect();
                vec![Effect::Intrinsic {
                    name: other.to_string(),
                    args,
                }]
            }
            }
    }

    fn lift_mnemonic(instr: &Instruction) -> std::vec::Vec<Effect> {
        // "nop" legitimately lifts to zero effects; special-cased here since
        // the lift_mnemonic_a..s chain below uses "non-empty result" as its
        // "handled" sentinel and would otherwise fall through to a wrong
        // catch-all fallback for a mnemonic whose real effects list is empty.
        if instr.mnemonic.eq_ignore_ascii_case("nop") {
            return vec![];
        }
        let __r0 = Self::lift_mnemonic_a(instr);
        if !__r0.is_empty() { return __r0; }
        let __r1 = Self::lift_mnemonic_b(instr);
        if !__r1.is_empty() { return __r1; }
        let __r2 = Self::lift_mnemonic_c(instr);
        if !__r2.is_empty() { return __r2; }
        let __r3 = Self::lift_mnemonic_d(instr);
        if !__r3.is_empty() { return __r3; }
        let __r4 = Self::lift_mnemonic_e(instr);
        if !__r4.is_empty() { return __r4; }
        let __r5 = Self::lift_mnemonic_f(instr);
        if !__r5.is_empty() { return __r5; }
        let __r6 = Self::lift_mnemonic_g(instr);
        if !__r6.is_empty() { return __r6; }
        let __r7 = Self::lift_mnemonic_h(instr);
        if !__r7.is_empty() { return __r7; }
        let __r8 = Self::lift_mnemonic_i(instr);
        if !__r8.is_empty() { return __r8; }
        let __r9 = Self::lift_mnemonic_j(instr);
        if !__r9.is_empty() { return __r9; }
        let __r10 = Self::lift_mnemonic_k(instr);
        if !__r10.is_empty() { return __r10; }
        let __r11 = Self::lift_mnemonic_l(instr);
        if !__r11.is_empty() { return __r11; }
        let __r12 = Self::lift_mnemonic_m(instr);
        if !__r12.is_empty() { return __r12; }
        let __r13 = Self::lift_mnemonic_n(instr);
        if !__r13.is_empty() { return __r13; }
        let __r14 = Self::lift_mnemonic_o(instr);
        if !__r14.is_empty() { return __r14; }
        let __r15 = Self::lift_mnemonic_p(instr);
        if !__r15.is_empty() { return __r15; }
        let __r16 = Self::lift_mnemonic_q(instr);
        if !__r16.is_empty() { return __r16; }
        let __r17 = Self::lift_mnemonic_r(instr);
        if !__r17.is_empty() { return __r17; }
        Self::lift_mnemonic_s(instr)
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Static helpers for repeated patterns
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Resolve a branch target from the token list.
    ///
    /// Prefers the last numeric token (offset or absolute target);
    /// falls back to the next instruction address on failure.
    fn branch_target_from_tokens(toks: &[String], base_addr: u64, instr_size: usize) -> IrExpr {
        let next = base_addr.saturating_add(instr_size as u64);
        // The target is typically the last token.
        for t in toks.iter().rev() {
            if let Some(v) = parse_i64_as_u64(t) {
                // Heuristic: if the value fits in 16 bits, treat it as a
                // code-unit offset (Ã—2 for byte offset) from the instruction.
                // Larger values are treated as absolute addresses.
                if v <= 0xffff {
                    let offset = i16::try_from(v).unwrap_or(i16::MAX);
                    // Use wrapping arithmetic in u64 space to avoid casting
                    // base_addr to i64 (which would corrupt addresses > i64::MAX).
                    let target = if offset >= 0 {
                        base_addr.wrapping_add(i64::from(offset * 2).cast_unsigned())
                    } else {
                        // offset is negative; abs fits in i64 since offset >= i16::MIN.
                        base_addr.wrapping_sub(i64::from((-offset) * 2).cast_unsigned())
                    };
                    return IrExpr::Const(target);
                }
                return IrExpr::Const(v);
            }
        }
        IrExpr::Const(next)
    }

    /// Conditional branch comparing two registers.
    fn cond_branch_rr<F>(
        toks: &[String],
        addr: u64,
        instr_size: usize,
        cond_builder: F,
    ) -> Vec<Effect>
    where
        F: FnOnce(IrExpr, IrExpr) -> IrExpr,
    {
        let lhs = reg_expr(toks, 0);
        let rhs = reg_expr(toks, 1);
        let target = Self::branch_target_from_tokens(toks, addr, instr_size);
        let condition = cond_builder(lhs, rhs);
        vec![Effect::Branch {
            target,
            condition: Some(condition),
        }]
    }

    /// aget vA, vB, vC  â†’  vA = mem[vB + vC * `element_size`] : size
    fn aget(toks: &[String], size: u8) -> Vec<Effect> {
        let dst = token_reg(toks, 0);
        let arr = reg_expr(toks, 1);
        let idx = reg_expr(toks, 2);
        let scale = u64::from(size);
        let addr = IrExpr::Add(
            Box::new(arr),
            Box::new(IrExpr::Mul(Box::new(idx), Box::new(IrExpr::Const(scale)))),
        );
        vec![Effect::MemRead {
            addr,
            dest: dst,
            size,
        }]
    }

    /// aget-wide vA, vB, vC  â†’  reads 8 bytes into vA (lo) and vA+1 (hi)
    fn aget_wide(toks: &[String]) -> Vec<Effect> {
        let dst_lo = token_reg(toks, 0);
        let dst_hi = wide_high(&dst_lo);
        let arr = reg_expr(toks, 1);
        let idx = reg_expr(toks, 2);
        let addr_lo = IrExpr::Add(
            Box::new(arr.clone()),
            Box::new(IrExpr::Mul(
                Box::new(idx.clone()),
                Box::new(IrExpr::Const(8)),
            )),
        );
        let addr_hi = IrExpr::Add(
            Box::new(arr),
            Box::new(IrExpr::Add(
                Box::new(IrExpr::Mul(Box::new(idx), Box::new(IrExpr::Const(8)))),
                Box::new(IrExpr::Const(4)),
            )),
        );
        vec![
            Effect::MemRead {
                addr: addr_lo,
                dest: dst_lo,
                size: 4,
            },
            Effect::MemRead {
                addr: addr_hi,
                dest: dst_hi,
                size: 4,
            },
        ]
    }

    /// aput vA, vB, vC  â†’  mem[vB + vC * size] = vA
    fn aput(toks: &[String], size: u8) -> Vec<Effect> {
        let src = reg_expr(toks, 0);
        let arr = reg_expr(toks, 1);
        let idx = reg_expr(toks, 2);
        let scale = u64::from(size);
        let addr = IrExpr::Add(
            Box::new(arr),
            Box::new(IrExpr::Mul(Box::new(idx), Box::new(IrExpr::Const(scale)))),
        );
        vec![Effect::MemWrite {
            addr,
            value: src,
            size,
        }]
    }

    /// aput-wide vA, vB, vC
    fn aput_wide(toks: &[String]) -> Vec<Effect> {
        let src_lo = reg_expr(toks, 0);
        let src_hi_name = toks.first().map(|t| wide_high(t)).unwrap_or_default();
        let arr = reg_expr(toks, 1);
        let idx = reg_expr(toks, 2);
        let addr_lo = IrExpr::Add(
            Box::new(arr.clone()),
            Box::new(IrExpr::Mul(
                Box::new(idx.clone()),
                Box::new(IrExpr::Const(8)),
            )),
        );
        let addr_hi = IrExpr::Add(
            Box::new(arr),
            Box::new(IrExpr::Add(
                Box::new(IrExpr::Mul(Box::new(idx), Box::new(IrExpr::Const(8)))),
                Box::new(IrExpr::Const(4)),
            )),
        );
        vec![
            Effect::MemWrite {
                addr: addr_lo,
                value: src_lo,
                size: 4,
            },
            Effect::MemWrite {
                addr: addr_hi,
                value: IrExpr::Reg(src_hi_name),
                size: 4,
            },
        ]
    }

    /// iget vA, vB, field  â†’  vA = mem[vB + `field_offset`] : size
    fn iget(toks: &[String], size: u8) -> Vec<Effect> {
        let dst = token_reg(toks, 0);
        let obj = reg_expr(toks, 1);
        // field offset is unknown at lift time; use Undef as placeholder offset
        let addr = IrExpr::Add(Box::new(obj), Box::new(IrExpr::Undef));
        vec![Effect::MemRead {
            addr,
            dest: dst,
            size,
        }]
    }

    fn iget_wide(toks: &[String]) -> Vec<Effect> {
        let dst_lo = token_reg(toks, 0);
        let dst_hi = wide_high(&dst_lo);
        let obj = reg_expr(toks, 1);
        let addr_lo = IrExpr::Add(Box::new(obj.clone()), Box::new(IrExpr::Undef));
        let addr_hi = IrExpr::Add(
            Box::new(obj),
            Box::new(IrExpr::Add(
                Box::new(IrExpr::Undef),
                Box::new(IrExpr::Const(4)),
            )),
        );
        vec![
            Effect::MemRead {
                addr: addr_lo,
                dest: dst_lo,
                size: 4,
            },
            Effect::MemRead {
                addr: addr_hi,
                dest: dst_hi,
                size: 4,
            },
        ]
    }

    /// iput vA, vB, field  â†’  mem[vB + `field_offset`] = vA : size
    fn iput(toks: &[String], size: u8) -> Vec<Effect> {
        let src = reg_expr(toks, 0);
        let obj = reg_expr(toks, 1);
        let addr = IrExpr::Add(Box::new(obj), Box::new(IrExpr::Undef));
        vec![Effect::MemWrite {
            addr,
            value: src,
            size,
        }]
    }

    fn iput_wide(toks: &[String]) -> Vec<Effect> {
        let src_lo = reg_expr(toks, 0);
        let src_hi_name = toks.first().map(|t| wide_high(t)).unwrap_or_default();
        let obj = reg_expr(toks, 1);
        let addr_lo = IrExpr::Add(Box::new(obj.clone()), Box::new(IrExpr::Undef));
        let addr_hi = IrExpr::Add(
            Box::new(obj),
            Box::new(IrExpr::Add(
                Box::new(IrExpr::Undef),
                Box::new(IrExpr::Const(4)),
            )),
        );
        vec![
            Effect::MemWrite {
                addr: addr_lo,
                value: src_lo,
                size: 4,
            },
            Effect::MemWrite {
                addr: addr_hi,
                value: IrExpr::Reg(src_hi_name),
                size: 4,
            },
        ]
    }

    /// 3-register binary op: vA = vB op vC
    fn binop3<F>(toks: &[String], op: F) -> Vec<Effect>
    where
        F: FnOnce(IrExpr, IrExpr) -> IrExpr,
    {
        let dst = token_reg(toks, 0);
        let lhs = reg_expr(toks, 1);
        let rhs = reg_expr(toks, 2);
        vec![Effect::RegWrite {
            reg: dst,
            value: op(lhs, rhs),
        }]
    }

    /// 2-address binary op: vA op= vB  (vA = vA op vB)
    fn binop2addr<F>(toks: &[String], op: F) -> Vec<Effect>
    where
        F: FnOnce(IrExpr, IrExpr) -> IrExpr,
    {
        let dst = token_reg(toks, 0);
        let lhs = IrExpr::Reg(dst.clone());
        let rhs = reg_expr(toks, 1);
        vec![Effect::RegWrite {
            reg: dst,
            value: op(lhs, rhs),
        }]
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IrExpr builder helpers used as function pointers in binop3 / binop2addr
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl IrExpr {
    /// Dalvik `v` registers hold 32 bits and the `-int` operations are 32-bit
    /// two's complement — they WRAP. This IR is untyped, so without an explicit
    /// mask the carry out of bit 31 survives and `add-int` of two large values
    /// reads as a 33-bit sum.
    ///
    /// These four helpers are used by the `-int` forms ONLY; the `-long` family
    /// goes through intrinsics, so masking here cannot narrow a 64-bit result by
    /// mistake. `and`/`or`/`xor` and the right shifts keep their bare
    /// constructors: they cannot widen their inputs, so a mask would be noise.
    ///
    /// Same class as the WASM `i32` wrap and BPF's `add32`.
    fn wrap32(e: Self) -> Self {
        Self::And(Box::new(e), Box::new(Self::Const(0xFFFF_FFFF)))
    }

    fn add_fn(a: Self, b: Self) -> Self {
        Self::wrap32(Self::Add(Box::new(a), Box::new(b)))
    }
    fn sub_fn(a: Self, b: Self) -> Self {
        Self::wrap32(Self::Sub(Box::new(a), Box::new(b)))
    }
    fn mul_fn(a: Self, b: Self) -> Self {
        Self::wrap32(Self::Mul(Box::new(a), Box::new(b)))
    }
    fn and_fn(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }
    fn or_fn(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }
    fn xor_fn(a: Self, b: Self) -> Self {
        Self::Xor(Box::new(a), Box::new(b))
    }
    fn shl_fn(a: Self, b: Self) -> Self {
        Self::wrap32(Self::Shl(Box::new(a), Box::new(b)))
    }
    fn shr_fn(a: Self, b: Self) -> Self {
        Self::Shr(Box::new(a), Box::new(b))
    }

    /// Dalvik's `shr-int` is the ARITHMETIC shift; `ushr-int` is the logical
    /// one — the `u` prefix is the whole difference between the two opcodes.
    fn sar_fn(a: Self, b: Self) -> Self {
        Self::Sar(Box::new(a), Box::new(b))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ArchLifter impl
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl Default for DexLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DexLifter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DexLifter(dex/LLIL)")
    }
}

impl ArchLifter for DexLifter {
    fn arch_name(&self) -> &'static str {
        "dex"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "Android DEX (Dalvik/ART) LLIL lifter â€” register-based VM with 65536 virtual registers"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let effects = Self::lift_mnemonic(instr);

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

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        // The DEX ISA is fixed; we accept every mnemonic and produce at least
        // an Intrinsic stub for unknown ones.
        let _ = mnemonic;
        true
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::{InstrFlags, Instruction};

    /// Build a minimal [`Instruction`] with the given mnemonic and operand string.
    fn make_instr(addr: u64, mnem: &str, operands: &str) -> Instruction {
        Instruction {
            address: Address(addr),
            size: 2,
            mnemonic: mnem.to_string(),
            operands: operands.to_string(),
            operand_list: vec![],
            flags: InstrFlags::NONE,
            bytes: vec![],
            comment: None,
        }
    }

    /// Dalvik's `shr-int` is the ARITHMETIC shift and `ushr-int` the logical
    /// one — the `u` is the entire difference between the two opcodes. All four
    /// sites (plain and `/2addr`, across both dispatch paths) shared an arm and
    /// emitted a logical `Shr`.
    ///
    /// Nothing covered this: the earlier sweep for signed/unsigned pairs used a
    /// mnemonic pattern without `-`, so every hyphenated Dalvik opcode was
    /// invisible to it. A probe that cannot express the ISA's naming finds
    /// nothing and looks clean.
    #[test]
    fn arithmetic_and_logical_shifts_differ() {
        let l = DexLifter::new();
        let render = |m: &str, ops: &str| {
            format!(
                "{:?}",
                l.lift(&make_instr(0x100, m, ops)).expect("lift").effects
            )
        };
        for (signed, unsigned, ops) in [
            ("shr-int", "ushr-int", "v0, v1, v2"),
            ("shr-int/2addr", "ushr-int/2addr", "v0, v1"),
        ] {
            let a = render(signed, ops);
            let u = render(unsigned, ops);
            assert!(a.contains("Sar"), "{signed} must be arithmetic, got {a}");
            assert!(
                u.contains("Shr") && !u.contains("Sar"),
                "{unsigned} must stay logical, got {u}"
            );
            assert_ne!(a, u, "{signed} and {unsigned} must not lift identically");
        }
    }

    /// Build an instruction that represents a branch with a given size.
    fn make_branch_instr(addr: u64, mnem: &str, operands: &str, size: usize) -> Instruction {
        Instruction {
            address: Address(addr),
            size,
            mnemonic: mnem.to_string(),
            operands: operands.to_string(),
            operand_list: vec![],
            flags: InstrFlags::BRANCH,
            bytes: vec![],
            comment: None,
        }
    }

    fn lifter() -> DexLifter {
        DexLifter::new()
    }

    // â”€â”€ Test 1: const/4 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_const4_positive() {
        let instr = make_instr(0x100, "const/4", "v0, 7");
        let li = lifter().lift(&instr).expect("lift failed");
        assert_eq!(li.address, 0x100);
        assert_eq!(li.original_mnemonic, "const/4");
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Const(v),
            } => {
                assert_eq!(reg, "v0");
                assert_eq!(*v, 7);
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn test_const4_negative() {
        // Negative literal: const/4 v2, -1  (sign-extended)
        let instr = make_instr(0x102, "const/4", "v2, -1");
        let li = lifter().lift(&instr).expect("lift failed");
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Const(v),
            } => {
                assert_eq!(reg, "v2");
                // -1 as u64 is 0xffffffffffffffff
                assert_eq!(*v, u64::MAX);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_const16() {
        let instr = make_instr(0x200, "const/16", "v3, 1000");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(&li.effects[0],
            Effect::RegWrite { reg, value: IrExpr::Const(1000) } if reg == "v3"));
    }

    #[test]
    fn test_const_high16() {
        // const/high16 v0, 0x1234  â†’  v0 = 0x12340000
        let instr = make_instr(0x300, "const/high16", "v0, 0x1234");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Const(v),
            } => {
                assert_eq!(reg, "v0");
                assert_eq!(*v, 0x1234_0000);
            }
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 2: add-int â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Dalvik `v` registers hold 32 bits and the `-int` operations are 32-bit
    /// two's complement — they WRAP. This IR is untyped, so without a mask the
    /// carry out of bit 31 survived and `add-int` read as a 33-bit sum.
    ///
    /// Only ops whose result can EXCEED 32 bits are masked. `and`/`or`/`xor`
    /// and the right shifts are asserted UNMASKED, so a later over-correction
    /// fails rather than passes — and the `-long` family must stay untouched.
    #[test]
    fn int_arithmetic_wraps_at_32_bits() {
        let l = DexLifter::new();
        let r = |m: &str, ops: &str| {
            format!("{:?}", l.lift(&make_instr(0x100, m, ops)).unwrap().effects)
        };
        const MASK: &str = "Const(4294967295)";

        for m in ["add-int", "sub-int", "mul-int", "shl-int"] {
            let t = r(m, "v0, v1, v2");
            assert!(t.contains(MASK), "{m} must wrap at 32 bits: {t}");
        }
        for m in ["add-int/2addr", "sub-int/2addr", "mul-int/2addr", "shl-int/2addr"] {
            let t = r(m, "v0, v1");
            assert!(t.contains(MASK), "{m} must wrap at 32 bits: {t}");
        }
        for m in ["add-int/lit8", "rsub-int/lit8", "mul-int/lit8"] {
            let t = r(m, "v0, v1, 5");
            assert!(t.contains(MASK), "{m} must wrap at 32 bits: {t}");
        }

        // These cannot widen their inputs; a mask would be noise.
        for m in ["and-int", "or-int", "xor-int", "shr-int", "ushr-int"] {
            let t = r(m, "v0, v1, v2");
            assert!(!t.contains(MASK), "{m} cannot exceed 32 bits: {t}");
        }

        // The 64-bit family goes through intrinsics and must not be narrowed.
        let long = r("add-long", "v0, v2, v4");
        assert!(!long.contains(MASK), "add-long must not be masked to 32: {long}");
    }

    #[test]
    fn test_add_int_3reg() {
        // add-int v0, v1, v2  â†’  v0 = v1 + v2
        let instr = make_instr(0x400, "add-int", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                // `-int` ops wrap at 32 bits, so the value is masked. These
                // tests asserted the BARE node, pinning the unwrapped form.
                value: IrExpr::And(inner, _),
            } => {
                let (lhs, rhs) = match inner.as_ref() {
                    IrExpr::Add(l, r) => (l, r),
                    other => panic!("expected a wrapped Add, got {other:?}"),
                };
                assert_eq!(reg, "v0");
                assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "v1"));
                assert!(matches!(rhs.as_ref(), IrExpr::Reg(r) if r == "v2"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_add_int_2addr() {
        // add-int/2addr v0, v1  â†’  v0 = v0 + v1
        let instr = make_instr(0x402, "add-int/2addr", "v0, v1");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                // `-int` ops wrap at 32 bits, so the value is masked. These
                // tests asserted the BARE node, pinning the unwrapped form.
                value: IrExpr::And(inner, _),
            } => {
                let (lhs, rhs) = match inner.as_ref() {
                    IrExpr::Add(l, r) => (l, r),
                    other => panic!("expected a wrapped Add, got {other:?}"),
                };
                assert_eq!(reg, "v0");
                assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "v0"));
                assert!(matches!(rhs.as_ref(), IrExpr::Reg(r) if r == "v1"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_add_int_lit8() {
        // add-int/lit8 v0, v1, 5  â†’  v0 = v1 + 5
        let instr = make_instr(0x410, "add-int/lit8", "v0, v1, 5");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                // `-int` ops wrap at 32 bits, so the value is masked. These
                // tests asserted the BARE node, pinning the unwrapped form.
                value: IrExpr::And(inner, _),
            } => {
                let (lhs, rhs) = match inner.as_ref() {
                    IrExpr::Add(l, r) => (l, r),
                    other => panic!("expected a wrapped Add, got {other:?}"),
                };
                assert_eq!(reg, "v0");
                assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "v1"));
                assert!(matches!(rhs.as_ref(), IrExpr::Const(5)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_sub_int() {
        let instr = make_instr(0x500, "sub-int", "v5, v6, v7");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                // `-int` ops wrap at 32 bits, so the value is masked. These
                // tests asserted the BARE node, pinning the unwrapped form.
                value: IrExpr::And(inner, _),
            } => {
                let (lhs, rhs) = match inner.as_ref() {
                    IrExpr::Sub(l, r) => (l, r),
                    other => panic!("expected a wrapped Sub, got {other:?}"),
                };
                assert_eq!(reg, "v5");
                assert!(matches!(lhs.as_ref(), IrExpr::Reg(r) if r == "v6"));
                assert!(matches!(rhs.as_ref(), IrExpr::Reg(r) if r == "v7"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_and_int() {
        let instr = make_instr(0x600, "and-int", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::And(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_or_int_lit16() {
        let instr = make_instr(0x610, "or-int/lit16", "v0, v1, 0xff");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Or(_lhs, rhs),
            } => {
                assert_eq!(reg, "v0");
                assert!(matches!(rhs.as_ref(), IrExpr::Const(0xff)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_xor_int() {
        let instr = make_instr(0x700, "xor-int", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::Xor(_, _),
                ..
            }
        ));
    }

    #[test]
    fn test_not_int() {
        let instr = make_instr(0x800, "not-int", "v0, v1");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Not(src),
            } => {
                assert_eq!(reg, "v0");
                assert!(matches!(src.as_ref(), IrExpr::Reg(r) if r == "v1"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_rsub_int() {
        // rsub-int v0, v1, 10  â†’  v0 = 10 - v1
        let instr = make_instr(0x900, "rsub-int", "v0, v1, 10");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                // `-int` ops wrap at 32 bits, so the value is masked. These
                // tests asserted the BARE node, pinning the unwrapped form.
                value: IrExpr::And(inner, _),
            } => {
                let (lhs, rhs) = match inner.as_ref() {
                    IrExpr::Sub(l, r) => (l, r),
                    other => panic!("expected a wrapped Sub, got {other:?}"),
                };
                assert_eq!(reg, "v0");
                assert!(matches!(lhs.as_ref(), IrExpr::Const(10)));
                assert!(matches!(rhs.as_ref(), IrExpr::Reg(r) if r == "v1"));
            }
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 3: goto â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_goto_unconditional() {
        // goto +8  â€” target = addr + offset*2 = 0x100 + 8*2 = 0x110
        let instr = make_branch_instr(0x100, "goto", "8", 2);
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::Branch {
                target: IrExpr::Const(t),
                condition: None,
            } => {
                assert_eq!(*t, 0x110, "expected 0x110, got {t:#x}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_goto16() {
        let instr = make_branch_instr(0x200, "goto/16", "0x10", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: None, ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_goto32_absolute() {
        // Large value â†’ treated as absolute address
        let instr = make_branch_instr(0x200, "goto/32", "0x10000", 6);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                target: IrExpr::Const(t),
                condition: None,
            } => {
                assert_eq!(*t, 0x10000);
            }
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 4: if-eq / if-ne / if-eqz â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_if_eq() {
        // if-eq v0, v1, +4  â†’ conditional branch when v0 == v1
        let instr = make_branch_instr(0x300, "if-eq", "v0, v1, 4", 4);
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => {
                // condition should be CmpEqZero(Xor(v0, v1))
                assert!(
                    matches!(cond, IrExpr::CmpEqZero(_)),
                    "expected CmpEqZero, got {cond:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_if_ne() {
        let instr = make_branch_instr(0x310, "if-ne", "v0, v1, 4", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(cond),
                ..
            } => {
                assert!(matches!(cond, IrExpr::Not(_)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_if_eqz() {
        let instr = make_branch_instr(0x320, "if-eqz", "v5, 10", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(IrExpr::CmpEqZero(inner)),
                ..
            } => {
                assert!(matches!(inner.as_ref(), IrExpr::Reg(r) if r == "v5"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_if_nez() {
        let instr = make_branch_instr(0x330, "if-nez", "v3, 6", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(IrExpr::Not(inner)),
                ..
            } => {
                assert!(matches!(inner.as_ref(), IrExpr::CmpEqZero(_)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_if_ltz() {
        let instr = make_branch_instr(0x340, "if-ltz", "v1, 2", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(IrExpr::Not(_)),
                ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_if_gez() {
        let instr = make_branch_instr(0x350, "if-gez", "v1, 2", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(IrExpr::CmpEqZero(_)),
                ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 5: invoke-virtual â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_invoke_virtual() {
        // invoke-virtual {v0, v1}, Ljava/lang/Object;->toString()Ljava/lang/String;
        let instr = make_instr(
            0x500,
            "invoke-virtual",
            "v0, v1, Ljava/lang/Object;->toString()Ljava/lang/String;",
        );
        let li = lifter().lift(&instr).unwrap();
        // Should have a Call effect followed by an invoke_args intrinsic
        let has_call = li.effects.iter().any(|e| matches!(e, Effect::Call { .. }));
        let has_args = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "invoke_args"));
        assert!(has_call, "expected Call effect");
        assert!(has_args, "expected invoke_args intrinsic");
    }

    #[test]
    fn test_invoke_static() {
        let instr = make_instr(0x600, "invoke-static", "v0, android/util/Log;->d");
        let li = lifter().lift(&instr).unwrap();
        assert!(li.effects.iter().any(|e| matches!(e, Effect::Call { .. })));
    }

    #[test]
    fn test_invoke_virtual_range() {
        let instr = make_instr(
            0x700,
            "invoke-virtual/range",
            "v0 .. v3, Ljava/io/InputStream;->read",
        );
        let li = lifter().lift(&instr).unwrap();
        assert!(li.effects.iter().any(|e| matches!(e, Effect::Call { .. })));
    }

    // â”€â”€ Test 6: move variants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_move() {
        let instr = make_instr(0x800, "move", "v2, v0");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "v2");
                assert_eq!(src, "v0");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_move_from16() {
        let instr = make_instr(0x802, "move/from16", "v10, v256");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "v10");
                assert_eq!(src, "v256");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_move_result() {
        let instr = make_instr(0x900, "move-result", "v0");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "v0");
                assert_eq!(src, "result");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_move_exception() {
        let instr = make_instr(0xa00, "move-exception", "v1");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } => {
                assert_eq!(reg, "v1");
                assert_eq!(src, "exception");
            }
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 7: return variants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_return_void() {
        let instr = make_instr(0xb00, "return-void", "");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(&li.effects[0], Effect::Return { value: None }));
    }

    #[test]
    fn test_return_reg() {
        let instr = make_instr(0xb02, "return", "v0");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Return {
                value: Some(IrExpr::Reg(r)),
            } => assert_eq!(r, "v0"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_return_object() {
        let instr = make_instr(0xb04, "return-object", "v3");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Return {
                value: Some(IrExpr::Reg(r)),
            } => assert_eq!(r, "v3"),
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 8: aget / aput â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_aget_int() {
        // aget v0, v1, v2  â†’  v0 = mem[v1 + v2 * 4] : 4
        let instr = make_instr(0xc00, "aget", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 1);
        match &li.effects[0] {
            Effect::MemRead {
                dest,
                size: 4,
                addr: IrExpr::Add(base, offset),
            } => {
                assert_eq!(dest, "v0");
                assert!(matches!(base.as_ref(), IrExpr::Reg(r) if r == "v1"));
                // offset is Mul(v2, 4)
                assert!(matches!(offset.as_ref(), IrExpr::Mul(_, _)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_aget_boolean() {
        let instr = make_instr(0xc10, "aget-boolean", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(&li.effects[0], Effect::MemRead { size: 1, .. }));
    }

    #[test]
    fn test_aput_int() {
        // aput v0, v1, v2  â†’  mem[v1 + v2 * 4] = v0
        let instr = make_instr(0xc20, "aput", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(&li.effects[0], Effect::MemWrite { size: 4, .. }));
    }

    // â”€â”€ Test 9: iget / iput â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_iget() {
        let instr = make_instr(0xd00, "iget", "v0, v1, Lcom/example/Foo;->bar:I");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::MemRead { dest, size: 4, .. } => assert_eq!(dest, "v0"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_iput() {
        let instr = make_instr(0xd10, "iput", "v5, v1, Lcom/example/Foo;->count:I");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(&li.effects[0], Effect::MemWrite { size: 4, .. }));
    }

    // â”€â”€ Test 10: sget / sput â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_sget() {
        let instr = make_instr(0xe00, "sget", "v0, Lcom/example/Foo;->COUNTER:I");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[1] {
            Effect::MemRead { dest, size: 4, .. } => assert_eq!(dest, "v0"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_sput() {
        let instr = make_instr(0xe10, "sput", "v2, Lcom/example/Foo;->COUNTER:I");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(&li.effects[0], Effect::MemWrite { size: 4, .. }));
    }

    // â”€â”€ Test 11: monitor / throw / new-instance â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_monitor_enter() {
        let instr = make_instr(0xf00, "monitor-enter", "v0");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Intrinsic { name, args } => {
                assert_eq!(name, "monitor_enter");
                assert!(matches!(&args[0], IrExpr::Reg(r) if r == "v0"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_throw() {
        let instr = make_instr(0xf10, "throw", "v1");
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Intrinsic { name, args } => {
                assert_eq!(name, "throw");
                assert!(matches!(&args[0], IrExpr::Reg(r) if r == "v1"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_new_instance() {
        let instr = make_instr(0xf20, "new-instance", "v0, Ljava/lang/StringBuilder;");
        let li = lifter().lift(&instr).unwrap();
        // Should have Intrinsic + RegWrite
        let has_intrinsic = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "new_instance"));
        let has_write = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "v0"));
        assert!(has_intrinsic);
        assert!(has_write);
    }

    // â”€â”€ Test 12: nop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_nop() {
        let instr = make_instr(0x1000, "nop", "");
        let li = lifter().lift(&instr).unwrap();
        assert!(li.effects.is_empty());
        assert_eq!(li.ir_text, "nop");
    }

    // â”€â”€ Test 13: wide const â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_const_wide16() {
        // const-wide/16 v0, -1  â†’  v0 = 0xffffffff, v1 = 0xffffffff (sign-extended)
        let instr = make_instr(0x1100, "const-wide/16", "v0, -1");
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 2, "expected two RegWrite for lo+hi");
        match (&li.effects[0], &li.effects[1]) {
            (
                Effect::RegWrite {
                    reg: lo_reg,
                    value: IrExpr::Const(lo_val),
                },
                Effect::RegWrite {
                    reg: hi_reg,
                    value: IrExpr::Const(hi_val),
                },
            ) => {
                assert_eq!(lo_reg, "v0");
                assert_eq!(hi_reg, "v1");
                // -1 sign-extended â†’ 0xffffffffffffffff
                let extended = (-1i16 as i64) as u64;
                assert_eq!(*lo_val, extended & 0xffff_ffff);
                assert_eq!(*hi_val, extended >> 32);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_const_wide() {
        let instr = make_instr(0x1200, "const-wide", "v2, 0x100000000");
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 2);
        match (&li.effects[0], &li.effects[1]) {
            (
                Effect::RegWrite {
                    value: IrExpr::Const(lo),
                    ..
                },
                Effect::RegWrite {
                    value: IrExpr::Const(hi),
                    ..
                },
            ) => {
                assert_eq!(*lo, 0); // low 32 bits
                assert_eq!(*hi, 1); // high 32 bits
            }
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 14: move-wide â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_move_wide() {
        // move-wide v0, v2  â†’  v0 = v2, v1 = v3
        let instr = make_instr(0x1300, "move-wide", "v0, v2");
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 2);
        match (&li.effects[0], &li.effects[1]) {
            (
                Effect::RegWrite {
                    reg: lo_dst,
                    value: IrExpr::Reg(lo_src),
                },
                Effect::RegWrite {
                    reg: hi_dst,
                    value: IrExpr::Reg(hi_src),
                },
            ) => {
                assert_eq!(lo_dst, "v0");
                assert_eq!(lo_src, "v2");
                assert_eq!(hi_dst, "v1");
                assert_eq!(hi_src, "v3");
            }
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 15: shl/shr int â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_shl_int() {
        let instr = make_instr(0x1400, "shl-int", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        assert!(matches!(
            &li.effects[0],
            Effect::RegWrite {
                value: IrExpr::And(..),
                ..
            }
        ));
    }

    #[test]
    fn test_shr_int_lit8() {
        let instr = make_instr(0x1402, "shr-int/lit8", "v0, v1, 3");
        let li = lifter().lift(&instr).unwrap();
        // Asserted `IrExpr::Shr` — the LOGICAL node — for Dalvik's arithmetic
        // shift, and no test covered `ushr-int/lit8`. Third form of the pair,
        // after the plain and `/2addr` ones.
        match &li.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Sar(_lhs, rhs),
                ..
            } => {
                assert!(matches!(rhs.as_ref(), IrExpr::Const(3)));
            }
            other => panic!("shr-int/lit8 is arithmetic; got {other:?}"),
        }

        let un = lifter()
            .lift(&make_instr(0x1402, "ushr-int/lit8", "v0, v1, 3"))
            .unwrap();
        match &un.effects[0] {
            Effect::RegWrite {
                value: IrExpr::Shr(..),
                ..
            } => {}
            other => panic!("ushr-int/lit8 is logical; got {other:?}"),
        }
        assert_ne!(
            format!("{:?}", li.effects),
            format!("{:?}", un.effects),
            "the two lit8 shifts must not lift identically"
        );
    }

    // â”€â”€ Test 16: cmp-long / cmpl-float â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cmp_long() {
        let instr = make_instr(0x1500, "cmp-long", "v0, v1, v3");
        let li = lifter().lift(&instr).unwrap();
        let has_intrinsic = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "cmp_long"));
        assert!(has_intrinsic);
    }

    #[test]
    fn test_cmpl_float() {
        let instr = make_instr(0x1510, "cmpl-float", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        let has_intrinsic = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "cmpl_float"));
        assert!(has_intrinsic);
    }

    // â”€â”€ Test 17: neg-int / neg-long â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_neg_int() {
        let instr = make_instr(0x1600, "neg-int", "v0, v1");
        let li = lifter().lift(&instr).unwrap();
        let has_neg = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "neg_int"));
        assert!(has_neg);
    }

    // â”€â”€ Test 18: LiftedInstr helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lifted_instr_is_terminator_return() {
        let instr = make_instr(0x2000, "return-void", "");
        let li = lifter().lift(&instr).unwrap();
        assert!(li.is_terminator());
        assert!(li.has_side_effects());
    }

    #[test]
    fn test_lifted_instr_is_terminator_goto() {
        let instr = make_branch_instr(0x2010, "goto", "5", 2);
        let li = lifter().lift(&instr).unwrap();
        assert!(li.is_terminator());
    }

    #[test]
    fn test_lifted_instr_not_terminator_move() {
        let instr = make_instr(0x2020, "move", "v0, v1");
        let li = lifter().lift(&instr).unwrap();
        assert!(!li.is_terminator());
    }

    #[test]
    fn test_written_registers() {
        let instr = make_instr(0x2030, "add-int", "v5, v6, v7");
        let li = lifter().lift(&instr).unwrap();
        let written = li.written_registers();
        assert!(written.contains(&"v5".to_string()));
    }

    #[test]
    fn test_read_registers_add() {
        let instr = make_instr(0x2040, "add-int", "v0, v1, v2");
        let li = lifter().lift(&instr).unwrap();
        let read = li.read_registers();
        assert!(read.contains(&"v1".to_string()));
        assert!(read.contains(&"v2".to_string()));
    }

    // â”€â”€ Test 19: unknown opcode fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_unknown_opcode_produces_intrinsic() {
        let instr = make_instr(0x3000, "some-future-opcode", "v0, v1");
        let li = lifter().lift(&instr).unwrap();
        assert_eq!(li.effects.len(), 1);
        assert!(matches!(&li.effects[0],
            Effect::Intrinsic { name, .. } if name == "some-future-opcode"));
    }

    // â”€â”€ Test 20: lifter metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lifter_metadata() {
        let l = DexLifter::new();
        assert_eq!(l.arch_name(), "dex");
        assert_eq!(l.lift_level(), LiftLevel::Llil);
        assert!(l.supports_mnemonic("invoke-virtual"));
        assert!(l.supports_mnemonic("anything"));
        assert!(!l.description().is_empty());
    }

    // â”€â”€ Test 21: wide_high helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_wide_high_naming() {
        assert_eq!(wide_high("v0"), "v1");
        assert_eq!(wide_high("v99"), "v100");
        assert_eq!(wide_high("v65534"), "v65535");
    }

    // â”€â”€ Test 22: if-lt / if-le â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_if_lt() {
        let instr = make_branch_instr(0x4000, "if-lt", "v0, v1, 4", 4);
        let li = lifter().lift(&instr).unwrap();
        // Condition should be non-trivial (not None)
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(_), ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_if_le() {
        let instr = make_branch_instr(0x4010, "if-le", "v0, v1, 4", 4);
        let li = lifter().lift(&instr).unwrap();
        match &li.effects[0] {
            Effect::Branch {
                condition: Some(_), ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    // â”€â”€ Test 23: aget-wide â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_aget_wide() {
        let instr = make_instr(0x5000, "aget-wide", "v0, v2, v4");
        let li = lifter().lift(&instr).unwrap();
        // Two MemRead effects for lo and hi halves
        
        assert_eq!(li
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::MemRead { .. })).count(), 2, "expected 2 MemRead for aget-wide");
    }

    // â”€â”€ Test 24: int-to-long conversion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_int_to_long() {
        let instr = make_instr(0x6000, "int-to-long", "v0, v1");
        let li = lifter().lift(&instr).unwrap();
        let has_conv = li
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "int_to_long"));
        assert!(has_conv);
    }
}
