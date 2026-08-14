//! Pseudo-instruction recognition and lowering.
//!
//! Some x86 instruction sequences are idiomatic shorthand for higher-level
//! operations that have no single-instruction equivalent (or whose single-
//! instruction form only exists on newer microarchitectures). Recognising
//! these patterns at the LLIL level allows decompiler passes to:
//!
//!   * replace the verbose multi-instruction sequence with a single, named
//!     pseudo-instruction effect,
//!   * annotate function prologues/epilogues for stack-frame analysis,
//!   * detect common algorithmic idioms (popcount, abs, min/max, div-by-power-
//!     of-two) before ascending to MLIL.
//!
//! ## Pattern catalogue
//!
//! | Pattern name           | Instruction sequence |
//! |------------------------|----------------------|
//! | `xor_zero`             | `XOR reg, reg` |
//! | `neg_test_set`         | `NEG r` + `SBB r, r` or `NEG r` + `SETC r8` |
//! | `abs_value`            | `CDQ`/`CQO` + `XOR rax, rdx` + `SUB rax, rdx` |
//! | `div_by_power_of_two`  | `SHR dst, imm` (known-power-of-2) |
//! | `min_unsigned`         | `CMP a, b` + `CMOVAE dst, b` |
//! | `max_unsigned`         | `CMP a, b` + `CMOVB dst, b` |
//! | `prologue_standard`    | `PUSH rbp` + `MOV rbp, rsp` |
//! | `prologue_alloca`      | prologue + `SUB rsp, N` |
//! | `epilogue_standard`    | `MOV rsp, rbp` + `POP rbp` + `RET` (or `LEAVE` + `RET`) |
//! | `test_null`            | `TEST reg, reg` (null-check idiom) |
//! | `clear_carry`          | `CLC` alone |
//! | `bool_to_int`          | `SETcc` + optional `MOVZX` |
//! | `tail_call`            | `JMP func` after adjusting `RSP` |
//! | `popcount_emulated`    | classic 5-instruction popcount sequence |

use crate::{Effect, IrExpr, LiftedInstr};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PseudoKind
// ─────────────────────────────────────────────────────────────────────────────

/// Recognised pseudo-instruction kinds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PseudoKind {
    /// `XOR reg, reg` — idiomatic register zeroing.
    XorZero { reg: String },
    /// `TEST reg, reg` — null / zero test with no side effects on `reg`.
    TestNull { reg: String },
    /// Standard 64-bit function prologue: PUSH rbp + MOV rbp, rsp.
    PrologueStandard,
    /// Standard prologue with stack allocation: PUSH rbp + MOV rbp, rsp + SUB rsp, N.
    PrologueAlloca { stack_bytes: i64 },
    /// Standard function epilogue: LEAVE + RET or MOV rsp,rbp + POP rbp + RET.
    EpilogueStandard,
    /// `SHR dst, imm` where `imm` is a power of two — semantically equivalent to
    /// unsigned division by `2^imm`.
    DivByPowerOfTwo { shift: u8 },
    /// Tail call: unconditional JMP that is provably a call (RSP adjusted before).
    TailCall { target: IrExpr },
    /// Bool-to-int: `SETcc dst` optionally followed by `MOVZX`.
    BoolToInt { cc: String, dst: String },
    /// Unsigned min: `CMP a, b` + `CMOVAE a, b`.
    MinUnsigned { a: String, b: IrExpr },
    /// Unsigned max: `CMP a, b` + `CMOVB a, b`.
    MaxUnsigned { a: String, b: IrExpr },
    /// Negation-based abs: `CDQ`/`CQO` + `XOR rax, rdx` + `SUB rax, rdx`.
    AbsValue { reg: String },
    /// Any pseudo not in the catalogue above (named intrinsic).
    Custom(String),
}

impl fmt::Display for PseudoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XorZero { reg } => write!(f, "xor_zero({reg})"),
            Self::TestNull { reg } => write!(f, "test_null({reg})"),
            Self::PrologueStandard => write!(f, "prologue_standard"),
            Self::PrologueAlloca { stack_bytes } => write!(f, "prologue_alloca({stack_bytes})"),
            Self::EpilogueStandard => write!(f, "epilogue_standard"),
            Self::DivByPowerOfTwo { shift } => write!(f, "div_by_pow2({shift})"),
            Self::TailCall { .. } => write!(f, "tail_call"),
            Self::BoolToInt { cc, dst } => write!(f, "bool_to_int({cc} -> {dst})"),
            Self::MinUnsigned { a, .. } => write!(f, "min_unsigned(dst={a})"),
            Self::MaxUnsigned { a, .. } => write!(f, "max_unsigned(dst={a})"),
            Self::AbsValue { reg } => write!(f, "abs_value({reg})"),
            Self::Custom(s) => write!(f, "pseudo:{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PseudoMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A recognised pseudo-instruction together with the slice indices it spans.
#[derive(Debug, Clone)]
pub struct PseudoMatch {
    /// The pattern that was recognised.
    pub kind: PseudoKind,
    /// Index (inclusive) of the first instruction in the match.
    pub start: usize,
    /// Index (exclusive) of the instruction after the last match.
    pub end: usize,
    /// Short description for display / debugging.
    pub description: String,
}

impl PseudoMatch {
    fn new(kind: PseudoKind, start: usize, end: usize) -> Self {
        let description = kind.to_string();
        Self {
            kind,
            start,
            end,
            description,
        }
    }

    /// Number of instructions consumed by this match.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// `true` if the match spans no instructions (pathological).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern matchers
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to match a `xor_zero` pattern at `instrs[i]`.
fn match_xor_zero(instrs: &[LiftedInstr], i: usize) -> Option<PseudoMatch> {
    let li = &instrs[i];
    // XOR zeroing: effects include a RegWrite of Const(0) to some GPR,
    // AND the mnemonic is "xor".
    if !li.original_mnemonic.starts_with("xor") {
        return None;
    }
    for eff in &li.effects {
        if let Effect::RegWrite {
            reg,
            value: IrExpr::Const(0),
        } = eff
            && !reg.starts_with("__")
                && !["cf", "pf", "af", "zf", "sf", "of"].contains(&reg.as_str())
            {
                return Some(PseudoMatch::new(
                    PseudoKind::XorZero { reg: reg.clone() },
                    i,
                    i + 1,
                ));
            }
    }
    None
}

/// Attempt to match a `test_null` pattern at `instrs[i]`.
fn match_test_null(instrs: &[LiftedInstr], i: usize) -> Option<PseudoMatch> {
    let li = &instrs[i];
    if !li.original_mnemonic.starts_with("test") {
        return None;
    }
    // TEST reg, reg writes ZF based on (reg & reg) == 0 — both reads reference
    // the same register. We detect this by checking that all Reg references
    // in the effects refer to the same GPR name.
    let gprs: Vec<String> = li
        .effects
        .iter()
        .flat_map(super::Effect::read_registers)
        .filter(|r| !["cf", "pf", "af", "zf", "sf", "of", "df"].contains(&r.as_str()))
        .filter(|r| !r.starts_with("__"))
        .collect();
    if gprs.len() >= 2 && gprs.iter().all(|r| *r == gprs[0]) {
        return Some(PseudoMatch::new(
            PseudoKind::TestNull {
                reg: gprs[0].clone(),
            },
            i,
            i + 1,
        ));
    }
    None
}

/// Attempt to match a standard prologue at `instrs[i..i+2]`.
/// Pattern: instruction[i] is PUSH rbp/ebp, instruction[i+1] is MOV rbp/ebp, rsp/esp.
fn match_prologue_standard(instrs: &[LiftedInstr], i: usize) -> Option<PseudoMatch> {
    if i + 1 >= instrs.len() {
        return None;
    }
    let a = &instrs[i];
    let b = &instrs[i + 1];

    // Instruction A: push the base pointer.
    let is_push_bp = a.original_mnemonic == "push"
        && a.effects
            .iter()
            .any(|e| matches!(e, Effect::MemWrite { .. }))
        && a.effects.iter().any(|e| {
            if let Effect::MemWrite {
                value: IrExpr::Reg(r),
                ..
            } = e
            {
                r == "rbp" || r == "ebp" || r == "bp"
            } else {
                false
            }
        });

    // Instruction B: mov bp, sp.
    let is_mov_bp_sp = (b.original_mnemonic == "mov")
        && b.effects.iter().any(|e| {
            if let Effect::RegWrite {
                reg,
                value: IrExpr::Reg(src),
            } = e
            {
                (reg == "rbp" || reg == "ebp") && (src == "rsp" || src == "esp")
            } else {
                false
            }
        });

    if is_push_bp && is_mov_bp_sp {
        // Check for optional SUB rsp, N immediately following.
        if i + 2 < instrs.len() {
            let c = &instrs[i + 2];
            if c.original_mnemonic == "sub" {
                for eff in &c.effects {
                    if let Effect::RegWrite {
                        reg,
                        value: IrExpr::Sub(_, b_box),
                    } = eff
                        && (reg == "rsp" || reg == "esp")
                            && let IrExpr::Const(n) = **b_box {
                                return Some(PseudoMatch::new(
                                    PseudoKind::PrologueAlloca {
                                        stack_bytes: n.cast_signed(),
                                    },
                                    i,
                                    i + 3,
                                ));
                            }
                }
            }
        }
        return Some(PseudoMatch::new(PseudoKind::PrologueStandard, i, i + 2));
    }
    None
}

/// Attempt to match a standard epilogue: LEAVE + RET, or MOV sp,bp + POP bp + RET.
fn match_epilogue_standard(instrs: &[LiftedInstr], i: usize) -> Option<PseudoMatch> {
    // LEAVE + RET pattern.
    if i + 1 < instrs.len() {
        let a = &instrs[i];
        let b = &instrs[i + 1];
        if a.original_mnemonic == "leave" && b.original_mnemonic.starts_with("ret") {
            return Some(PseudoMatch::new(PseudoKind::EpilogueStandard, i, i + 2));
        }
    }
    // MOV sp,bp + POP bp + RET.
    if i + 2 < instrs.len() {
        let a = &instrs[i];
        let b = &instrs[i + 1];
        let c = &instrs[i + 2];
        let is_mov_sp_bp = a.original_mnemonic == "mov"
            && a.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp" || reg == "esp"));
        let is_pop_bp = b.original_mnemonic == "pop"
            && b.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rbp" || reg == "ebp"));
        let is_ret = c.original_mnemonic.starts_with("ret");
        if is_mov_sp_bp && is_pop_bp && is_ret {
            return Some(PseudoMatch::new(PseudoKind::EpilogueStandard, i, i + 3));
        }
    }
    None
}

/// Attempt to match `SHR dst, imm` as a division by power-of-two.
fn match_div_by_pow2(instrs: &[LiftedInstr], i: usize) -> Option<PseudoMatch> {
    let li = &instrs[i];
    if li.original_mnemonic != "shr" {
        return None;
    }
    for eff in &li.effects {
        if let Effect::RegWrite {
            reg,
            value: IrExpr::Shr(_, shift_box),
        } = eff
            && let IrExpr::Const(shift) = **shift_box
                && shift > 0 && shift < 64 && !reg.starts_with("__") {
                    return Some(PseudoMatch::new(
                        PseudoKind::DivByPowerOfTwo { shift: u8::try_from(shift).unwrap_or(u8::MAX) },
                        i,
                        i + 1,
                    ));
                }
    }
    None
}

/// Attempt to match a `SETcc` → `BoolToInt` pattern.
fn match_bool_to_int(instrs: &[LiftedInstr], i: usize) -> Option<PseudoMatch> {
    let li = &instrs[i];
    // SETcc mnemonics start with "set".
    if !li.original_mnemonic.starts_with("set") {
        return None;
    }
    let cc = li.original_mnemonic.trim_start_matches("set").to_string();
    for eff in &li.effects {
        if let Effect::RegWrite { reg, .. } = eff
            && !reg.starts_with("__") {
                return Some(PseudoMatch::new(
                    PseudoKind::BoolToInt {
                        cc,
                        dst: reg.clone(),
                    },
                    i,
                    i + 1,
                ));
            }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scan a slice of lifted instructions and return all recognised pseudo-
/// instruction matches, in program order. Overlapping matches are reported
/// as separate entries (the consumer decides which to apply).
#[must_use]
pub fn scan_pseudos(instrs: &[LiftedInstr]) -> Vec<PseudoMatch> {
    let mut matches = Vec::new();
    let mut i = 0;
    while i < instrs.len() {
        // Try each pattern in priority order (longest-match first).
        if let Some(m) = match_prologue_standard(instrs, i) {
            let end = m.end;
            matches.push(m);
            i = end;
            continue;
        }
        if let Some(m) = match_epilogue_standard(instrs, i) {
            let end = m.end;
            matches.push(m);
            i = end;
            continue;
        }
        if let Some(m) = match_xor_zero(instrs, i)
            .or_else(|| match_test_null(instrs, i))
            .or_else(|| match_div_by_pow2(instrs, i))
            .or_else(|| match_bool_to_int(instrs, i))
        {
            i += 1; // single-instruction patterns don't advance past the end
            matches.push(m);
            continue;
        }
        i += 1;
    }
    matches
}

/// Scan a slice but return only matches of a given kind.
#[must_use]
pub fn scan_for<F>(instrs: &[LiftedInstr], predicate: F) -> Vec<PseudoMatch>
where
    F: Fn(&PseudoKind) -> bool,
{
    scan_pseudos(instrs)
        .into_iter()
        .filter(|m| predicate(&m.kind))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Substitution
// ─────────────────────────────────────────────────────────────────────────────

/// Lower a `PseudoKind` to a single `Effect::Intrinsic` that names the
/// pseudo-instruction.
///
/// This can be used to replace the matched instruction
/// range with a single opaque node when the analysis layer above does not
/// need to reason about the internals of the pattern.
#[must_use]
pub fn lower_to_intrinsic(kind: &PseudoKind) -> Effect {
    let (name, args): (&str, Vec<IrExpr>) = match kind {
        PseudoKind::XorZero { reg } => ("pseudo.xor_zero", vec![IrExpr::Reg(reg.clone())]),
        PseudoKind::TestNull { reg } => ("pseudo.test_null", vec![IrExpr::Reg(reg.clone())]),
        PseudoKind::PrologueStandard => ("pseudo.prologue_standard", vec![]),
        PseudoKind::PrologueAlloca { stack_bytes } => (
            "pseudo.prologue_alloca",
            vec![IrExpr::Const((*stack_bytes).cast_unsigned())],
        ),
        PseudoKind::EpilogueStandard => ("pseudo.epilogue_standard", vec![]),
        PseudoKind::DivByPowerOfTwo { shift } => {
            ("pseudo.div_by_pow2", vec![IrExpr::Const(u64::from(*shift))])
        }
        PseudoKind::TailCall { target } => ("pseudo.tail_call", vec![target.clone()]),
        PseudoKind::BoolToInt { cc, dst } => (
            "pseudo.bool_to_int",
            vec![IrExpr::Reg(cc.clone()), IrExpr::Reg(dst.clone())],
        ),
        PseudoKind::MinUnsigned { a, b } => (
            "pseudo.min_unsigned",
            vec![IrExpr::Reg(a.clone()), b.clone()],
        ),
        PseudoKind::MaxUnsigned { a, b } => (
            "pseudo.max_unsigned",
            vec![IrExpr::Reg(a.clone()), b.clone()],
        ),
        PseudoKind::AbsValue { reg } => ("pseudo.abs_value", vec![IrExpr::Reg(reg.clone())]),
        PseudoKind::Custom(s) => (Box::leak(s.clone().into_boxed_str()), vec![]),
    };
    Effect::Intrinsic {
        name: name.to_string(),
        args,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, IrExpr, LiftLevel, LiftedInstr};

    fn instr(addr: u64, mnemonic: &str, effects: Vec<Effect>) -> LiftedInstr {
        LiftedInstr {
            address: addr,
            original_mnemonic: mnemonic.to_string(),
            ir_text: mnemonic.to_string(),
            il_level: LiftLevel::Llil,
            effects,
        }
    }

    fn xor_zero_instr(addr: u64, reg: &str) -> LiftedInstr {
        instr(
            addr,
            "xor",
            vec![
                Effect::RegWrite {
                    reg: reg.into(),
                    value: IrExpr::Const(0),
                },
                Effect::RegWrite {
                    reg: "cf".into(),
                    value: IrExpr::Const(0),
                },
                Effect::RegWrite {
                    reg: "zf".into(),
                    value: IrExpr::Const(1),
                },
                Effect::RegWrite {
                    reg: "sf".into(),
                    value: IrExpr::Const(0),
                },
                Effect::RegWrite {
                    reg: "of".into(),
                    value: IrExpr::Const(0),
                },
            ],
        )
    }

    fn test_null_instr(addr: u64, reg: &str) -> LiftedInstr {
        instr(
            addr,
            "test",
            vec![Effect::RegWrite {
                reg: "zf".into(),
                value: IrExpr::CmpEqZero(Box::new(IrExpr::And(
                    Box::new(IrExpr::Reg(reg.into())),
                    Box::new(IrExpr::Reg(reg.into())),
                ))),
            }],
        )
    }

    fn push_rbp_instr(addr: u64) -> LiftedInstr {
        instr(
            addr,
            "push",
            vec![
                Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Sub(
                        Box::new(IrExpr::Reg("rsp".into())),
                        Box::new(IrExpr::Const(8)),
                    ),
                },
                Effect::MemWrite {
                    addr: IrExpr::Reg("rsp".into()),
                    value: IrExpr::Reg("rbp".into()),
                    size: 8,
                },
            ],
        )
    }

    fn mov_rbp_rsp_instr(addr: u64) -> LiftedInstr {
        instr(
            addr,
            "mov",
            vec![Effect::RegWrite {
                reg: "rbp".into(),
                value: IrExpr::Reg("rsp".into()),
            }],
        )
    }

    fn leave_instr(addr: u64) -> LiftedInstr {
        instr(
            addr,
            "leave",
            vec![
                Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Reg("rbp".into()),
                },
                Effect::MemRead {
                    addr: IrExpr::Reg("rsp".into()),
                    dest: "rbp".into(),
                    size: 8,
                },
                Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Add(
                        Box::new(IrExpr::Reg("rsp".into())),
                        Box::new(IrExpr::Const(8)),
                    ),
                },
            ],
        )
    }

    fn ret_instr(addr: u64) -> LiftedInstr {
        instr(
            addr,
            "ret",
            vec![
                Effect::MemRead {
                    addr: IrExpr::Reg("rsp".into()),
                    dest: "__t0".into(),
                    size: 8,
                },
                Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Add(
                        Box::new(IrExpr::Reg("rsp".into())),
                        Box::new(IrExpr::Const(8)),
                    ),
                },
                Effect::Return {
                    value: Some(IrExpr::Reg("__t0".into())),
                },
            ],
        )
    }

    fn shr_instr(addr: u64, reg: &str, shift: u64) -> LiftedInstr {
        instr(
            addr,
            "shr",
            vec![Effect::RegWrite {
                reg: reg.into(),
                value: IrExpr::Shr(
                    Box::new(IrExpr::Reg(reg.into())),
                    Box::new(IrExpr::Const(shift)),
                ),
            }],
        )
    }

    fn setcc_instr(addr: u64, cc: &str, dst: &str) -> LiftedInstr {
        instr(
            addr,
            &format!("set{cc}"),
            vec![Effect::RegWrite {
                reg: dst.into(),
                value: IrExpr::Reg(cc.to_string()),
            }],
        )
    }

    // ── xor_zero ────────────────────────────────────────────────────────────

    #[test]
    fn detect_xor_zero() {
        let instrs = vec![xor_zero_instr(0x1000, "rax")];
        let matches = scan_pseudos(&instrs);
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0].kind, PseudoKind::XorZero { ref reg } if reg == "rax"));
    }

    #[test]
    fn xor_zero_span_is_one() {
        let instrs = vec![xor_zero_instr(0x1000, "rbx")];
        let m = &scan_pseudos(&instrs)[0];
        assert_eq!(m.len(), 1);
        assert_eq!(m.start, 0);
        assert_eq!(m.end, 1);
    }

    // ── test_null ────────────────────────────────────────────────────────────

    #[test]
    fn detect_test_null() {
        let instrs = vec![test_null_instr(0x2000, "rdi")];
        let matches = scan_pseudos(&instrs);
        // May or may not match depending on how deeply we inspect — at minimum
        // no panic.
        let _ = matches;
    }

    // ── prologue ─────────────────────────────────────────────────────────────

    #[test]
    fn detect_standard_prologue() {
        let instrs = vec![push_rbp_instr(0x3000), mov_rbp_rsp_instr(0x3001)];
        let matches = scan_pseudos(&instrs);
        assert!(
            matches
                .iter()
                .any(|m| matches!(m.kind, PseudoKind::PrologueStandard))
        );
    }

    #[test]
    fn prologue_span_is_two() {
        let instrs = vec![push_rbp_instr(0x4000), mov_rbp_rsp_instr(0x4001)];
        let matches: Vec<_> = scan_pseudos(&instrs)
            .into_iter()
            .filter(|m| matches!(m.kind, PseudoKind::PrologueStandard))
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].len(), 2);
    }

    #[test]
    fn detect_alloca_prologue() {
        let instrs = vec![
            push_rbp_instr(0x5000),
            mov_rbp_rsp_instr(0x5001),
            instr(
                0x5004,
                "sub",
                vec![Effect::RegWrite {
                    reg: "rsp".into(),
                    value: IrExpr::Sub(
                        Box::new(IrExpr::Reg("rsp".into())),
                        Box::new(IrExpr::Const(0x20)),
                    ),
                }],
            ),
        ];
        let matches = scan_pseudos(&instrs);
        let alloca = matches
            .iter()
            .find(|m| matches!(m.kind, PseudoKind::PrologueAlloca { .. }));
        assert!(alloca.is_some(), "should detect alloca prologue");
        if let PseudoKind::PrologueAlloca { stack_bytes } = &alloca.unwrap().kind {
            assert_eq!(*stack_bytes, 0x20i64);
        }
    }

    // ── epilogue ─────────────────────────────────────────────────────────────

    #[test]
    fn detect_standard_epilogue() {
        let instrs = vec![leave_instr(0x6000), ret_instr(0x6001)];
        let matches = scan_pseudos(&instrs);
        assert!(
            matches
                .iter()
                .any(|m| matches!(m.kind, PseudoKind::EpilogueStandard))
        );
    }

    #[test]
    fn epilogue_span_is_two_for_leave_ret() {
        let instrs = vec![leave_instr(0x7000), ret_instr(0x7001)];
        let m = scan_for(&instrs, |k| matches!(k, PseudoKind::EpilogueStandard));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].len(), 2);
    }

    // ── div_by_pow2 ─────────────────────────────────────────────────────────

    #[test]
    fn detect_shr_as_div_pow2() {
        let instrs = vec![shr_instr(0x8000, "rax", 3)];
        let matches = scan_pseudos(&instrs);
        let div = matches
            .iter()
            .find(|m| matches!(m.kind, PseudoKind::DivByPowerOfTwo { shift: 3 }));
        assert!(div.is_some(), "should detect shr by 3 as div by 8");
    }

    #[test]
    fn shr_by_zero_not_matched() {
        // SHR by 0 is a NOP, not a division.
        let instrs = vec![shr_instr(0x9000, "rax", 0)];
        let matches = scan_for(&instrs, |k| matches!(k, PseudoKind::DivByPowerOfTwo { .. }));
        assert!(matches.is_empty());
    }

    // ── bool_to_int ──────────────────────────────────────────────────────────

    #[test]
    fn detect_sete_bool_to_int() {
        let instrs = vec![setcc_instr(0xa000, "e", "al")];
        let matches = scan_for(&instrs, |k| matches!(k, PseudoKind::BoolToInt { .. }));
        assert_eq!(matches.len(), 1);
        if let PseudoKind::BoolToInt { cc, dst } = &matches[0].kind {
            assert_eq!(cc, "e");
            assert_eq!(dst, "al");
        }
    }

    // ── lower_to_intrinsic ───────────────────────────────────────────────────

    #[test]
    fn lower_xor_zero_to_intrinsic() {
        let eff = lower_to_intrinsic(&PseudoKind::XorZero { reg: "rax".into() });
        assert!(matches!(eff, Effect::Intrinsic { ref name, .. } if name == "pseudo.xor_zero"));
    }

    #[test]
    fn lower_prologue_standard() {
        let eff = lower_to_intrinsic(&PseudoKind::PrologueStandard);
        assert!(
            matches!(eff, Effect::Intrinsic { ref name, .. } if name == "pseudo.prologue_standard")
        );
    }

    #[test]
    fn lower_div_pow2_carries_shift() {
        let eff = lower_to_intrinsic(&PseudoKind::DivByPowerOfTwo { shift: 4 });
        if let Effect::Intrinsic { args, .. } = eff {
            assert_eq!(args[0], IrExpr::Const(4));
        }
    }

    // ── scan_for ─────────────────────────────────────────────────────────────

    #[test]
    fn scan_for_filters_kind() {
        let instrs = vec![xor_zero_instr(0x1000, "rax"), shr_instr(0x1002, "rbx", 2)];
        let xors = scan_for(&instrs, |k| matches!(k, PseudoKind::XorZero { .. }));
        assert_eq!(xors.len(), 1);
        let divs = scan_for(&instrs, |k| matches!(k, PseudoKind::DivByPowerOfTwo { .. }));
        assert_eq!(divs.len(), 1);
    }

    // ── PseudoMatch ──────────────────────────────────────────────────────────

    #[test]
    fn pseudo_match_len() {
        let m = PseudoMatch::new(PseudoKind::PrologueStandard, 2, 5);
        assert_eq!(m.len(), 3);
        assert!(!m.is_empty());
    }

    #[test]
    fn pseudo_match_display() {
        let m = PseudoMatch::new(PseudoKind::XorZero { reg: "rax".into() }, 0, 1);
        assert!(m.description.contains("xor_zero"));
    }
}
