//! ARM32 / Thumb LLIL lifter (`Arm32Lifter`).
//!
//! Implements a mnemonic-driven low-level IL lifter for the ARM32 and Thumb
//! instruction sets.  The lifter operates solely on the mnemonic string and
//! the structured operand list carried by [`Instruction`]; it does not depend
//! on any `rustre-arch-*` crate.
//!
//! # Architecture coverage
//!
//! | Category                     | Mnemonics (base, after suffix strip)           |
//! |------------------------------|------------------------------------------------|
//! | Arithmetic                   | ADD, ADC, SUB, SBC, RSB, RSC, MUL, MLA, MLS   |
//! | Bitwise                      | AND, ORR, EOR, BIC, MVN                        |
//! | Data movement                | MOV, MOVW, MOVT                                |
//! | Shifts                       | LSL, LSR, ASR, ROR                             |
//! | Load / store (single)        | LDR, LDRB, LDRH, LDRSB, LDRSH                 |
//! | Load / store (single)        | STR, STRB, STRH                                |
//! | Load / store (multiple)      | LDM, LDMIA, LDMFD, STM, STMIA, STMFD          |
//! | Stack                        | PUSH, POP                                      |
//! | Branches                     | B, BX, BL, BLX                                 |
//! | Compare / test (flag-only)   | CMP, CMN, TST, TEQ                             |
//! | System call                  | SVC / SWI                                      |
//! | No-operation                 | NOP                                            |
//! | IT block                     | IT, ITT, ITE, ITTTT, etc.                      |
//! | Unknown                      | â†’ `Intrinsic` fallback                         |

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Register name constants
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Canonical ARM32 register names (r0â€“r15 plus aliases).
const REG_SP: &str = "sp";
const REG_LR: &str = "lr";
const REG_PC: &str = "pc";

// ARM32 condition code suffixes (two-letter codes).
const CONDITION_SUFFIXES: &[&str] = &[
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "hs", "lo",
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Arm32Lifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Mnemonic-driven LLIL lifter for the ARM32 and Thumb instruction sets.
///
/// Use [`Arm32Lifter::new`] for ARM32 (A32 encoding) and
/// [`Arm32Lifter::new_thumb`] for Thumb/Thumb-2 (T16/T32 encoding).
/// The two modes share the same lifting logic; `thumb` is recorded in the
/// struct so that downstream consumers can distinguish them.
#[derive(Debug, Clone)]
pub struct Arm32Lifter {
    /// `true` when this lifter is operating in Thumb / Thumb-2 mode.
    pub thumb: bool,
}

impl Arm32Lifter {
    /// Create a new ARM32 (A32) lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { thumb: false }
    }

    /// Create a new Thumb / Thumb-2 lifter.
    #[must_use]
    pub const fn new_thumb() -> Self {
        Self { thumb: true }
    }

    // â”€â”€ Mnemonic normalisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Strip the condition-code suffix **and** an optional 'S' flag suffix
    /// from an ARM32 mnemonic, returning the base mnemonic.
    ///
    /// Examples:
    /// - `"addeq"` â†’ `"add"`
    /// - `"movs"`  â†’ `"mov"`
    /// - `"blxne"` â†’ `"blx"`
    /// - `"ldmia"` â†’ `"ldmia"` (IA is not a condition code)
    fn strip_suffixes(mnem: &str) -> &str {
        let m = mnem;

        // "svc" (software interrupt / syscall) is an atomic mnemonic whose
        // last two letters ("vc") happen to collide with the "VC" (oVerflow
        // Clear) ARM condition code. It never takes a condition suffix in
        // this lifter, so strip it before the generic condition-code logic
        // below mistakes it for base "s" + condition "vc".
        // Mnemonics whose OWN last letters collide with a suffix. Each is a
        // complete ARM mnemonic, not `base + suffix`, and stripping mangles it
        // into something no match arm can ever see.
        //
        // Measured, not guessed — the probe that produced this list showed:
        //   teq -> "t", mls -> "ml", smlal -> "sml", umlal -> "uml"
        // so `TEQ` (flag-setting test), `MLS` (multiply-subtract) and the two
        // multiply-accumulate-long forms were all lifted as unknown mnemonics.
        //
        // `svc` was already special-cased by hand here (it collides with the
        // `VC` condition); the others are the same defect, unnoticed. The list
        // is ITEMISED for the reason PowerPC's `OE_CAPABLE` is: a heuristic
        // "strip if it looks like a suffix" is what caused all of them.
        const ATOMIC: &[&str] = &[
            "svc",   // collides with condition VC
            "teq",   // collides with condition EQ
            "mls",   // collides with condition LS
            "smmls", // collides with condition LS
            "vmls",  // collides with condition LS
            "smlal", // collides with condition AL
            "umlal", // collides with condition AL
        ];
        if ATOMIC.iter().any(|a| m.eq_ignore_ascii_case(a)) {
            return m;
        }

        // First pass: try stripping a trailing two-letter condition code.
        // We iterate from longest match to shortest to avoid partial matches.
        // Condition codes are always exactly 2 characters.  We also handle the
        // optional 'S' flag that may appear **before** the condition code.
        //
        // Possible suffix patterns (suffix follows the base mnemonic):
        //   <base>           â€” no suffix
        //   <base>S          â€” set-flags only
        //   <base><cc>       â€” condition only
        //   <base>S<cc>      â€” set-flags + condition (unusual but valid)
        //   <base><cc>S      â€” condition + set-flags (common ARM32 form)

        // Try "<base><cc>S" â†’ strip "S" then "<cc>".
        if m.ends_with('s') || m.ends_with('S') {
            let without_s = &m[..m.len() - 1];
            if without_s.len() >= 2 {
                let candidate_cc = &without_s[without_s.len() - 2..];
                if CONDITION_SUFFIXES.contains(&candidate_cc.to_ascii_lowercase().as_str()) {
                    let base = &without_s[..without_s.len() - 2];
                    if !base.is_empty() {
                        return base;
                    }
                }
            }
            // Pure "<base>S" (no condition code).
            let base = without_s;
            // Only strip trailing 'S' if the resulting string is a recognised
            // mnemonic base â€” to avoid stripping the 'S' from "lsr", "str", etc.
            // We do a conservative check: the stripped base must be at least 2
            // chars and must not itself look like a condition code.
            if base.len() >= 2 {
                let base_lower = base.to_ascii_lowercase();
                // Do not strip 'S' from well-known mnemonics that end in 's'.
                let ends_in_s_base = matches!(
                    base_lower.as_str(),
                    "lsr" | "asr" | "rors" | "bics" | "adds" | "subs"
                        | "ands" | "orrs" | "eors" | "movs" | "muls"
                );
                if !ends_in_s_base {
                    // Tentatively strip â€” the caller will decide if this is valid.
                    return base;
                }
            }
        }

        // Try "<base><cc>".
        if m.len() >= 2 {
            let candidate_cc = &m[m.len() - 2..];
            if CONDITION_SUFFIXES.contains(&candidate_cc.to_ascii_lowercase().as_str()) {
                let base = &m[..m.len() - 2];
                if !base.is_empty() {
                    return base;
                }
            }
        }

        // No recognisable suffix â†’ return the mnemonic unchanged.
        m
    }

    /// Normalise a mnemonic: lower-case and strip condition + S-flag suffixes.
    fn normalise(mnem: &str) -> String {
        let lower = mnem.to_ascii_lowercase();
        Self::strip_suffixes(&lower).to_string()
    }

    // â”€â”€ Operand helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Return the register name for operand at `idx`, if the operand is a
    /// [`Operand::Register`].
    fn op_reg(instr: &Instruction, idx: usize) -> Option<String> {
        instr
            .operand_list
            .get(idx)
            .and_then(|o| o.as_register())
            .map(|r| r.name.to_ascii_lowercase())
    }

    /// Return the immediate value for operand at `idx`.
    ///
    /// Accepts both signed [`Operand::Immediate`] and unsigned
    /// [`Operand::UImmediate`].
    fn op_imm(instr: &Instruction, idx: usize) -> Option<u64> {
        instr.operand_list.get(idx).and_then(|o| {
            use rustre_core::arch::Operand;
            match o {
                Operand::Immediate(v) => Some((*v).cast_unsigned()),
                Operand::UImmediate(v) => Some(*v),
                _ => None,
            }
        })
    }

    /// Return the label address for operand at `idx`.
    fn op_label(instr: &Instruction, idx: usize) -> Option<u64> {
        instr.operand_list.get(idx).and_then(rustre_core::Operand::as_label)
    }

    /// Build an [`IrExpr`] for the operand at `idx`.
    ///
    /// Resolution order: register â†’ immediate â†’ label â†’ `Undef`.
    fn op_expr(instr: &Instruction, idx: usize) -> IrExpr {
        use rustre_core::arch::Operand;
        instr.operand_list.get(idx).map_or(IrExpr::Undef, |op| match op {
                Operand::Register(r) => IrExpr::Reg(r.name.to_ascii_lowercase()),
                Operand::Immediate(v) => IrExpr::Const((*v).cast_unsigned()),
                Operand::UImmediate(v) => IrExpr::Const(*v),
                Operand::Label(a) => IrExpr::Const(*a),
                Operand::Memory { base, index, scale, disp, .. } => {
                    // Effective address = base + index * scale + disp
                    let mut expr: Option<IrExpr> =
                        base.as_ref().map(|r| IrExpr::Reg(r.name.to_ascii_lowercase()));
                    if let Some(idx_reg) = index {
                        let idx_expr = if *scale > 1 {
                            IrExpr::Mul(
                                Box::new(IrExpr::Reg(idx_reg.name.to_ascii_lowercase())),
                                Box::new(IrExpr::Const(u64::from(*scale))),
                            )
                        } else {
                            IrExpr::Reg(idx_reg.name.to_ascii_lowercase())
                        };
                        expr = Some(match expr {
                            Some(e) => IrExpr::Add(Box::new(e), Box::new(idx_expr)),
                            None => idx_expr,
                        });
                    }
                    if *disp != 0 {
                        let abs = disp.unsigned_abs();
                        expr = Some(match expr {
                            Some(e) if *disp < 0 => {
                                IrExpr::Sub(Box::new(e), Box::new(IrExpr::Const(abs)))
                            }
                            Some(e) => IrExpr::Add(Box::new(e), Box::new(IrExpr::Const(abs))),
                            None => IrExpr::Const((*disp).cast_unsigned()),
                        });
                    }
                    expr.unwrap_or(IrExpr::Const(0))
                }
                Operand::FpReg(n) => IrExpr::Reg(format!("s{n}")),
                Operand::VecReg(n) => IrExpr::Reg(format!("d{n}")),
                Operand::Segment(_, inner) => {
                    // Flatten segment override Ã¢â‚¬â€� shouldn't occur on ARM but
                    // handle defensively.
                    use rustre_core::arch::Operand as Op;
                    match inner.as_ref() {
                        Op::Register(r) => IrExpr::Reg(r.name.to_ascii_lowercase()),
                        Op::Immediate(v) => IrExpr::Const((*v).cast_unsigned()),
                        Op::UImmediate(v) => IrExpr::Const(*v),
                        _ => IrExpr::Undef,
                    }
                }
            })
    }

    /// Resolve the branch target.
    ///
    /// Priority: `Label` operand at `idx` â†’ `Immediate`/`UImmediate` operand â†’
    /// `Register` operand (indirect) â†’ `Undef`.
    fn branch_target(instr: &Instruction, idx: usize) -> IrExpr {
        if let Some(addr) = Self::op_label(instr, idx) {
            return IrExpr::Const(addr);
        }
        if let Some(imm) = Self::op_imm(instr, idx) {
            return IrExpr::Const(imm);
        }
        if let Some(reg) = Self::op_reg(instr, idx) {
            // Clear the Thumb bit (bit 0) that BX/BLX addresses may carry.
            return IrExpr::And(
                Box::new(IrExpr::Reg(reg)),
                Box::new(IrExpr::Const(!1u64)),
            );
        }
        IrExpr::Undef
    }

    /// Normalise an ARM32 register name.
    ///
    /// Maps `r13` â†’ `sp`, `r14` â†’ `lr`, `r15` â†’ `pc`, and lower-cases.
    fn norm_reg(name: &str) -> String {
        match name.to_ascii_lowercase().as_str() {
            "r13" => REG_SP.to_string(),
            "r14" => REG_LR.to_string(),
            "r15" => REG_PC.to_string(),
            other => other.to_string(),
        }
    }

    /// Return the `size` in bytes determined by the mnemonic variant suffix.
    ///
    /// `LDR` / `STR` â†’ 4 bytes, `LDRB` / `STRB` â†’ 1, `LDRH` / `STRH` â†’ 2.
    fn mem_size_from_mnem(base: &str) -> u8 {
        match base {
            "ldrb" | "strb" | "ldrsb" => 1,
            "ldrh" | "strh" | "ldrsh" => 2,
            _ => 4, // ldr, str, ldrd, strd default to word (4 bytes)
        }
    }

    // â”€â”€ Per-instruction lifters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Lift `MOV Rd, <op>` / `MOVW Rd, #imm16` / `MOVT Rd, #imm16`.
    fn lift_mov(instr: &Instruction, base: &str) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        match base {
            "movt" => {
                // MOVT: insert `imm16` into the top 16 bits of Rd without
                // touching the bottom 16 bits.
                // Rd = (Rd & 0x0000_ffff) | (imm << 16)
                let imm = Self::op_imm(instr, 1).unwrap_or(0);
                let hi = IrExpr::Const((imm & 0xffff) << 16);
                let mask = IrExpr::Const(0x0000_ffff);
                let lo = IrExpr::And(Box::new(IrExpr::Reg(dst.clone())), Box::new(mask));
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Or(Box::new(lo), Box::new(hi)),
                }]
            }
            "movw" => {
                // MOVW: zero-extend 16-bit immediate into Rd.
                let imm = Self::op_imm(instr, 1).unwrap_or(0);
                vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::Const(imm & 0xffff),
                }]
            }
            _ => {
                let src = Self::op_expr(instr, 1);
                vec![Effect::RegWrite { reg: dst, value: src }]
            }
        }
    }

    /// Lift `MVN Rd, <op>` â€” bitwise NOT.
    fn lift_mvn(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let src = Self::op_expr(instr, 1);
        vec![Effect::RegWrite {
            reg: dst,
            value: IrExpr::Not(Box::new(src)),
        }]
    }

    /// Lift two-operand arithmetic: `ADD / SUB / AND / ORR / EOR / ADC / SBC / RSB / RSC`.
    ///
    /// ARM32 encoding: `<op> Rd, Rn, <op2>`.
    /// Mark a carry-CONSUMING arithmetic instruction so the fact survives.
    ///
    /// `ADC` is `Rd = Rn + Op2 + carry` and `SBC` is `Rd = Rn - Op2 - ~carry`.
    /// Both shared a handler with the carry-free `ADD`/`SUB`, so `add` and
    /// `adc` produced IDENTICAL IL — the results differ by one whenever the
    /// carry is set, which is exactly what a multi-word add does (`ADDS` then
    /// `ADC` is how ARM32 adds 64-bit values).
    ///
    /// This IR has NO readable carry flag — no lifter in the crate reads one —
    /// so unlike the `ROR` case the exact value is genuinely not expressible.
    /// The value therefore stays the carry-free approximation, but an intrinsic
    /// named for the mnemonic is emitted alongside it so nothing downstream can
    /// mistake `adc` for `add`. Same convention the MIPS lifter uses for
    /// `div`/`divu` and the Z80 lifter for its rotates: **opaque is acceptable,
    /// opaque-and-indistinguishable is not.**
    /// Fold the carry into a value-producing effect.
    ///
    /// `ADC`, `SBC` and `RSC` all shared their carry-free sibling's lift, so
    /// `adc` produced a value byte-identical to `add`: the carry-in was simply
    /// dropped. Only the marker intrinsic's name differed, which is why the
    /// guard comparing whole renderings never caught it — the same shape as the
    /// PowerPC `ADDE` defect, one architecture over.
    ///
    /// `ADC  Rd, Rn, Op2` is `Rn + Op2 + C`.
    /// `SBC  Rd, Rn, Op2` is `Rn - Op2 - NOT(C)`, i.e. `Rn - Op2 - 1 + C`.
    /// `RSC  Rd, Rn, Op2` is the same with the operands reversed.
    ///
    /// No name had to be invented here: `cf` is already the carry this very file
    /// reads when it builds condition codes.
    fn with_carry_in(effects: Vec<Effect>, borrow: bool) -> Vec<Effect> {
        let cf = IrExpr::Reg("cf".to_string());
        effects
            .into_iter()
            .map(|e| match e {
                Effect::RegWrite { reg, value } => Effect::RegWrite {
                    reg,
                    value: if borrow {
                        IrExpr::Add(
                            Box::new(IrExpr::Sub(Box::new(value), Box::new(IrExpr::Const(1)))),
                            Box::new(cf.clone()),
                        )
                    } else {
                        IrExpr::Add(Box::new(value), Box::new(cf.clone()))
                    },
                },
                other => other,
            })
            .collect()
    }

    fn with_carry_marker(mut effects: Vec<Effect>, mnem: &str) -> Vec<Effect> {
        effects.insert(
            0,
            Effect::Intrinsic {
                name: mnem.to_string(),
                args: vec![],
            },
        );
        effects
    }

    fn lift_alu3(
        instr: &Instruction,
        op: fn(Box<IrExpr>, Box<IrExpr>) -> IrExpr,
    ) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        // Two-operand form: `ADD Rd, Rn, Op2`
        let lhs = Self::op_expr(instr, 1);
        let rhs = Self::op_expr(instr, 2);
        // Simplify add-with-zero (common for MOV aliases).
        let value = if matches!((&lhs, &rhs), (IrExpr::Const(0), _)) {
            rhs
        } else if matches!((&lhs, &rhs), (_, IrExpr::Const(0))) {
            lhs
        } else {
            op(Box::new(lhs), Box::new(rhs))
        };
        vec![Effect::RegWrite { reg: dst, value }]
    }

    /// Lift `RSB / RSC Rd, Rn, Op2` â†’ `Rd = Op2 - Rn`.
    fn lift_rsb(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let lhs = Self::op_expr(instr, 2); // reversed
        let rhs = Self::op_expr(instr, 1);
        vec![Effect::RegWrite {
            reg: dst,
            value: IrExpr::Sub(Box::new(lhs), Box::new(rhs)),
        }]
    }

    /// Lift `BIC Rd, Rn, Op2` â†’ `Rd = Rn & ~Op2`.
    fn lift_bic(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let lhs = Self::op_expr(instr, 1);
        let rhs = Self::op_expr(instr, 2);
        vec![Effect::RegWrite {
            reg: dst,
            value: IrExpr::And(Box::new(lhs), Box::new(IrExpr::Not(Box::new(rhs)))),
        }]
    }

    /// Lift `MUL Rd, Rm, Rs` â†’ `Rd = Rm * Rs`.
    fn lift_mul(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let lhs = Self::op_expr(instr, 1);
        let rhs = Self::op_expr(instr, 2);
        vec![Effect::RegWrite {
            reg: dst,
            value: IrExpr::Mul(Box::new(lhs), Box::new(rhs)),
        }]
    }

    /// Lift `MLA Rd, Rm, Rs, Ra` â†’ `Rd = Rm * Rs + Ra`.
    fn lift_mla(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let rm = Self::op_expr(instr, 1);
        let rs = Self::op_expr(instr, 2);
        let ra = Self::op_expr(instr, 3);
        let product = IrExpr::Mul(Box::new(rm), Box::new(rs));
        vec![Effect::RegWrite {
            reg: dst,
            value: IrExpr::Add(Box::new(product), Box::new(ra)),
        }]
    }

    /// Lift `MLS Rd, Rm, Rs, Ra` â†’ `Rd = Ra - Rm * Rs`.
    fn lift_mls(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let rm = Self::op_expr(instr, 1);
        let rs = Self::op_expr(instr, 2);
        let ra = Self::op_expr(instr, 3);
        let product = IrExpr::Mul(Box::new(rm), Box::new(rs));
        vec![Effect::RegWrite {
            reg: dst,
            value: IrExpr::Sub(Box::new(ra), Box::new(product)),
        }]
    }

    /// Lift shift instructions: `LSL / LSR / ASR / ROR Rd, Rm, <amount>`.
    ///
    /// `is_left` controls the direction; both ASR and LSR are mapped to `Shr`
    /// (logical right shift) since `IrExpr` does not distinguish arithmetic
    /// from logical shift at the LLIL level.
    /// Lift `ROR Rd, Rs, #n` — rotate right, EXACTLY.
    ///
    /// This used to call `lift_shift`, with the comment "represent as a
    /// right-shift (approximate)". A rotate is not a shift: the bits that leave
    /// the right come back at the left. `ROR r0, r0, #8` on `0x000000FF` yields
    /// `0xFF000000`; the shift yields `0`. Silently wrong VALUES.
    ///
    /// No new IR node was needed — unlike the arithmetic shift and the unsigned
    /// compare, a rotate IS expressible with the nodes that already exist:
    /// `((x >> n) | (x << (32 - n))) & 0xFFFF_FFFF`. **A comment claiming an
    /// approximation is worth testing against the IR's actual expressiveness;
    /// sometimes the fact was always sayable.**
    ///
    /// The mask keeps the result inside ARM32's 32-bit register width, since
    /// the left half of the rotate would otherwise leave bits above bit 31.
    fn lift_ror(instr: &Instruction) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let src = Self::op_expr(instr, 1);
        let amount = Self::op_expr(instr, 2);
        let right = IrExpr::Shr(Box::new(src.clone()), Box::new(amount.clone()));
        let left = IrExpr::Shl(
            Box::new(src),
            Box::new(IrExpr::Sub(Box::new(IrExpr::Const(32)), Box::new(amount))),
        );
        let value = IrExpr::And(
            Box::new(IrExpr::Or(Box::new(right), Box::new(left))),
            Box::new(IrExpr::Const(0xFFFF_FFFF)),
        );
        vec![Effect::RegWrite { reg: dst, value }]
    }

    fn lift_shift(instr: &Instruction, is_left: bool) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let src = Self::op_expr(instr, 1);
        let amount = Self::op_expr(instr, 2);
        let value = if is_left {
            IrExpr::Shl(Box::new(src), Box::new(amount))
        } else {
            IrExpr::Shr(Box::new(src), Box::new(amount))
        };
        vec![Effect::RegWrite { reg: dst, value }]
    }

    /// `LDRSB`/`LDRSH` SIGN-extend the loaded value into the 32-bit register;
    /// `LDRB`/`LDRH` ZERO-extend it. They shared `lift_ldr`, which takes only a
    /// size, so a loaded `0xFF` was indistinguishable between `-1` and `255`.
    ///
    /// **Fifth architecture with this defect** after RISC-V, WASM and MIPS (twice).
    /// The doc comment on `lift_ldr` even lists `LDR{B,H,SB,SH}` together, so the
    /// distinction was written down and then not made.
    ///
    /// Uses the `sextN` marker convention shared with the PowerPC, RISC-V, WASM
    /// and MIPS lifters. ARM32 registers are 32 bits and these loads are 8 or 16,
    /// so the load is always narrower than the register — the width-relative
    /// condition that mattered on MIPS is unconditionally true here, and saying
    /// so is why no gate appears below.
    ///
    /// A `pc` destination turns the load into an indirect branch; in that case
    /// `lift_ldr` returns a `Branch` and there is no register to extend, so the
    /// marker is only appended to a real `MemRead`.
    fn lift_ldr_signed(instr: &Instruction, size: u8) -> Vec<Effect> {
        let mut out = Self::lift_ldr(instr, size);
        if let Some(Effect::MemRead { dest, .. }) = out.first() {
            let reg = dest.clone();
            out.push(Effect::Intrinsic {
                name: format!("sext{}", u32::from(size) * 8),
                args: vec![IrExpr::Reg(reg)],
            });
        }
        out
    }

    /// Lift `LDR{B,H,SB,SH} Rd, <addr>`.
    /// Resolve an ARM single/double-transfer memory operand into the ADDRESS
    /// actually accessed plus the base-register writeback the addressing mode
    /// implies.
    ///
    /// # The defect this closes
    ///
    /// ARM has three indexing modes and they differ in BOTH facts:
    ///
    /// | form                | address  | base afterwards |
    /// |---------------------|----------|-----------------|
    /// | `ldr r0, [r1, #4]`  | `r1 + 4` | unchanged       |
    /// | `ldr r0, [r1, #4]!` | `r1 + 4` | `r1 + 4`        |
    /// | `ldr r0, [r1], #4`  | **`r1`** | `r1 + 4`        |
    ///
    /// `lift_ldr`/`lift_str`/`ldrd`/`strd` emitted `base + disp` unconditionally
    /// and NO writeback at all, so the pre-indexed forms silently lost the
    /// pointer advance — the idiom at the heart of every `while (*p++)` loop —
    /// and the post-indexed forms read from the wrong address on top of that.
    ///
    /// This is the PAIR signal for the third iteration running: `lift_ldm` and
    /// `lift_stm`, in this same file, already consult `has_writeback`. Two
    /// implementations of one fact, one of them right.
    ///
    /// The mode is not representable in `rustre_core::arch::Operand::Memory`
    /// (it has base/index/scale/disp/width and nothing else), so it is recovered
    /// from the operand TEXT, as `has_writeback` already does for `!`.
    fn indexed_addr_and_writeback(
        instr: &Instruction,
        idx: usize,
    ) -> (IrExpr, Option<Effect>) {
        use rustre_core::arch::Operand;
        let plain = Self::op_expr(instr, idx);
        let Some(Operand::Memory { base, disp, .. }) = instr.operand_list.get(idx) else {
            return (plain, None);
        };
        let Some(base_reg) = base.as_ref().map(|r| Self::norm_reg(&r.name)) else {
            return (plain, None);
        };
        let text = instr.operands.as_str();
        // Post-indexed puts the offset OUTSIDE the brackets: `[r1], #4`.
        let post = text
            .find(']')
            .is_some_and(|i| text[i + 1..].trim_start().starts_with(','));
        let pre = !post && text.trim_end().ends_with("]!");
        if !pre && !post {
            return (plain, None);
        }
        // The offset lives in `disp` when the decoder filled it in; for the
        // post-indexed form some disassemblers leave it in the text only.
        let step = if *disp != 0 {
            *disp
        } else {
            Self::trailing_offset(text).unwrap_or(0)
        };
        let advanced = if step < 0 {
            IrExpr::Sub(
                Box::new(IrExpr::Reg(base_reg.clone())),
                Box::new(IrExpr::Const(step.unsigned_abs())),
            )
        } else if step > 0 {
            IrExpr::Add(
                Box::new(IrExpr::Reg(base_reg.clone())),
                Box::new(IrExpr::Const(step.cast_unsigned())),
            )
        } else {
            IrExpr::Reg(base_reg.clone())
        };
        let wb = Some(Effect::RegWrite {
            reg: base_reg.clone(),
            value: advanced,
        });
        // Post-indexed accesses the UNMODIFIED base; pre-indexed accesses the
        // updated address, which is what `plain` already computes.
        let addr = if post {
            IrExpr::Reg(base_reg)
        } else {
            plain
        };
        (addr, wb)
    }

    /// Parse a `#N` immediate appearing after the closing bracket, for
    /// post-indexed operands whose displacement the decoder left in the text.
    fn trailing_offset(text: &str) -> Option<i64> {
        let after = &text[text.find(']')? + 1..];
        let tok = after.trim_start().strip_prefix(',')?.trim();
        let num = tok.strip_prefix('#').unwrap_or(tok);
        let (neg, digits) = match num.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, num),
        };
        let digits: String = digits.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let v: i64 = digits.parse().ok()?;
        Some(if neg { -v } else { v })
    }

    fn lift_ldr(instr: &Instruction, size: u8) -> Vec<Effect> {
        let dst = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        // Operand 1 is the memory address (may be a Memory operand or a label).
        let mut writeback = None;
        let addr = instr.operand_list.get(1).map_or(IrExpr::Undef, |op| {
                use rustre_core::arch::Operand;
                match op {
                    Operand::Label(a) => IrExpr::Const(*a),
                    _ => {
                        let (a, wb) = Self::indexed_addr_and_writeback(instr, 1);
                        writeback = wb;
                        a
                    }
                }
            });

        // If destination is pc, this is a branch (indirect).
        if dst == REG_PC {
            return vec![Effect::Branch {
                target: IrExpr::Deref(Box::new(addr), size),
                condition: None,
            }];
        }

        let mut out = vec![Effect::MemRead { addr, dest: dst, size }];
        out.extend(writeback);
        out
    }

    /// Lift `STR{B,H} Rd, <addr>`.
    fn lift_str(instr: &Instruction, size: u8) -> Vec<Effect> {
        let src = Self::op_expr(instr, 0);
        let (addr, writeback) = Self::indexed_addr_and_writeback(instr, 1);
        let mut out = vec![Effect::MemWrite { addr, value: src, size }];
        out.extend(writeback);
        out
    }

    /// Lift `PUSH {reglist}`.
    ///
    /// Emits one `MemWrite` per register in the list (high register first,
    /// matching ARM's STMDB semantics), then adjusts SP.
    fn lift_push(instr: &Instruction) -> Vec<Effect> {
        let regs = Self::collect_reglist(instr);
        if regs.is_empty() {
            return Self::fallback(instr);
        }
        let n = regs.len() as u64;
        let mut effects: Vec<Effect> = Vec::with_capacity(regs.len() + 1);

        // PUSH is STMDB SP!, reglist â€” stores in descending order.
        // SP is decremented *before* each store.
        // We emit: sp = sp - n*4, then store each reg at sp+offset.
        effects.push(Effect::RegWrite {
            reg: REG_SP.to_string(),
            value: IrExpr::Sub(
                Box::new(IrExpr::Reg(REG_SP.to_string())),
                Box::new(IrExpr::Const(n * 4)),
            ),
        });
        for (i, reg) in regs.iter().enumerate() {
            let offset = IrExpr::Const(i as u64 * 4);
            let addr = IrExpr::Add(
                Box::new(IrExpr::Reg(REG_SP.to_string())),
                Box::new(offset),
            );
            effects.push(Effect::MemWrite {
                addr,
                value: IrExpr::Reg(reg.clone()),
                size: 4,
            });
        }
        effects
    }

    /// Lift `POP {reglist}`.
    ///
    /// Emits one `MemRead` per register, adjusts SP.  If `pc` is in the list,
    /// also emits a [`Effect::Return`].
    fn lift_pop(instr: &Instruction) -> Vec<Effect> {
        let regs = Self::collect_reglist(instr);
        if regs.is_empty() {
            return Self::fallback(instr);
        }
        let n = regs.len() as u64;
        let has_pc = regs.iter().any(|r| r == REG_PC || r == "r15");
        let mut effects: Vec<Effect> = Vec::with_capacity(regs.len() + 2);

        // Emit loads.
        for (i, reg) in regs.iter().enumerate() {
            if reg == REG_PC || reg == "r15" {
                continue; // handled separately as Return
            }
            let offset = IrExpr::Const(i as u64 * 4);
            let addr = IrExpr::Add(
                Box::new(IrExpr::Reg(REG_SP.to_string())),
                Box::new(offset),
            );
            effects.push(Effect::MemRead {
                addr,
                dest: reg.clone(),
                size: 4,
            });
        }

        // Advance SP.
        effects.push(Effect::RegWrite {
            reg: REG_SP.to_string(),
            value: IrExpr::Add(
                Box::new(IrExpr::Reg(REG_SP.to_string())),
                Box::new(IrExpr::Const(n * 4)),
            ),
        });

        // If PC is in the list, emit a return.
        if has_pc {
            effects.push(Effect::Return {
                value: Some(IrExpr::Reg("r0".to_string())),
            });
        }

        effects
    }

    /// Does this LDM/STM write the base register back?
    ///
    /// ARM spells it with a trailing `!` on the base operand (`LDMIA r0!,
    /// {r1-r3}`). WITHOUT the `!` the base is left untouched — `LDMIA sp,
    /// {…}` reading a frame without advancing it is ordinary code.
    ///
    /// Both `lift_ldm` and `lift_stm` used to push the write-back
    /// UNCONDITIONALLY, so every non-`!` form got an INVENTED register write:
    /// a false definition that kills whatever the base register held. That is
    /// the mirror of the PowerPC defect fixed in the previous iteration, where
    /// a real write-back was MISSING.
    ///
    /// `lift_ldm`'s own doc comment already claimed this was conditional
    /// ("if writeback is implied (by recognising the `!` convention…)") — the
    /// third time in this session that a comment described behaviour the code
    /// did not implement.
    ///
    /// The marker is looked for in both the raw operand text and the base
    /// operand's rendering, because different disassembler front-ends put it
    /// in one or the other.
    /// Resolve the ADDRESSING MODE of a block transfer into the offset of the
    /// first transferred register and the base writeback delta, in bytes.
    ///
    /// # The defect this exists to fix
    ///
    /// `lift_stm` treated every mode as increment-after, while the dispatch arm
    /// unioned `"stm" | "stmia" | "stmfd" | "stmdb"`. `STMDB`/`STMFD` DECREMENT
    /// BEFORE storing, so `stmdb sp!, {r4, r5, lr}` -- the standard ARM function
    /// prologue, on the hot path of essentially every ARM binary -- was emitted
    /// with stores at `sp+0, sp+4, sp+8` and a writeback of `sp+12`, when the
    /// architecture writes them at `sp-12, sp-8, sp-4` and leaves `sp-12`. Every
    /// address and the sign of the writeback were wrong.
    ///
    /// The correct model was already in this file: `lift_push`, which is exactly
    /// `STMDB SP!`, decrements first. Two implementations of one fact, one right
    /// -- so the fix is to make the general path agree with the special case.
    ///
    /// The `LDM` arm next to it (`"ldm" | "ldmia" | "ldmfd"`) groups only
    /// increment-after forms and was therefore correct; that correct grouping
    /// beside the wrong one is what made the defect visible.
    ///
    /// All four architectural modes are resolved, including the stack aliases,
    /// whose meaning DIFFERS between load and store (`FD` is `IA` for `LDM` but
    /// `DB` for `STM`) -- which is precisely why one shared handler cannot infer
    /// the direction from the suffix alone.
    fn block_transfer_offsets(base: &str, n: u64, is_load: bool) -> (i64, i64) {
        let bytes = (n * 4) as i64;
        let suffix = base
            .strip_prefix(if is_load { "ldm" } else { "stm" })
            .unwrap_or("");
        // Stack aliases map to different arithmetic modes for loads and stores.
        let mode = match suffix {
            "fd" => {
                if is_load {
                    "ia"
                } else {
                    "db"
                }
            }
            "ea" => {
                if is_load {
                    "db"
                } else {
                    "ia"
                }
            }
            "fa" => {
                if is_load {
                    "da"
                } else {
                    "ib"
                }
            }
            "ed" => {
                if is_load {
                    "ib"
                } else {
                    "da"
                }
            }
            // A bare `ldm`/`stm` defaults to increment-after.
            "" => "ia",
            other => other,
        };
        match mode {
            "ib" => (4, bytes),
            "da" => (-(bytes - 4), -bytes),
            "db" => (-bytes, -bytes),
            // "ia" and anything unrecognised: the architectural default.
            _ => (0, bytes),
        }
    }

    /// Build `base + delta` for a signed byte delta, folding a zero delta away.
    fn base_plus(base_reg: &str, delta: i64) -> IrExpr {
        let b = IrExpr::Reg(base_reg.to_string());
        match delta.cmp(&0) {
            core::cmp::Ordering::Equal => b,
            core::cmp::Ordering::Greater => {
                IrExpr::Add(Box::new(b), Box::new(IrExpr::Const(delta as u64)))
            }
            core::cmp::Ordering::Less => {
                IrExpr::Sub(Box::new(b), Box::new(IrExpr::Const(delta.unsigned_abs())))
            }
        }
    }

    fn has_writeback(instr: &Instruction) -> bool {
        if instr.operands.contains('!') {
            return true;
        }
        instr
            .operand_list
            .first()
            .is_some_and(|op| format!("{op:?}").contains('!'))
    }

    /// Lift `LDM{IA,FD} Rn{!}, {reglist}`.
    ///
    /// Emits `MemRead` for each register; if writeback is implied (by
    /// recognising the `!` convention in the operand string, or by the IA
    /// variant), advances the base register.
    fn lift_ldm(instr: &Instruction, base: &str) -> Vec<Effect> {
        let base_reg = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let regs = Self::collect_reglist_skip_base(instr);
        let has_pc = regs.iter().any(|r| r == REG_PC || r == "r15");
        let n = regs.len() as u64;
        let mut effects: Vec<Effect> = Vec::with_capacity(regs.len() + 2);

        let (first, wb) = Self::block_transfer_offsets(base, n, true);
        for (i, reg) in regs.iter().enumerate() {
            if reg == REG_PC || reg == "r15" {
                continue;
            }
            let addr = Self::base_plus(&base_reg, first + (i as i64) * 4);
            effects.push(Effect::MemRead {
                addr,
                dest: reg.clone(),
                size: 4,
            });
        }

        // Writeback, ONLY for the `!` form — see `has_writeback`.
        if Self::has_writeback(instr) {
            effects.push(Effect::RegWrite {
                reg: base_reg.clone(),
                value: Self::base_plus(&base_reg, wb),
            });
        }

        if has_pc {
            effects.push(Effect::Return {
                value: Some(IrExpr::Reg("r0".to_string())),
            });
        }

        effects
    }

    /// Lift `STM{IA,FD} Rn{!}, {reglist}`.
    fn lift_stm(instr: &Instruction, base: &str) -> Vec<Effect> {
        let base_reg = match Self::op_reg(instr, 0) {
            Some(r) => Self::norm_reg(&r),
            None => return Self::fallback(instr),
        };
        let regs = Self::collect_reglist_skip_base(instr);
        let n = regs.len() as u64;
        let (first, wb) = Self::block_transfer_offsets(base, n, false);
        let mut effects: Vec<Effect> = Vec::with_capacity(regs.len() + 1);

        for (i, reg) in regs.iter().enumerate() {
            let addr = Self::base_plus(&base_reg, first + (i as i64) * 4);
            effects.push(Effect::MemWrite {
                addr,
                value: IrExpr::Reg(reg.clone()),
                size: 4,
            });
        }

        // Writeback, ONLY for the `!` form — same reasoning as `lift_ldm`.
        if Self::has_writeback(instr) {
            effects.push(Effect::RegWrite {
                reg: base_reg.clone(),
                value: Self::base_plus(&base_reg, wb),
            });
        }

        effects
    }

    /// Lift `B{<cc>} <target>` â€” unconditional or conditional branch.
    ///
    /// The condition expression is derived from the original mnemonic's suffix.
    fn lift_b(instr: &Instruction) -> Vec<Effect> {
        let target = Self::branch_target(instr, 0);
        let condition = Self::condition_from_mnem(&instr.mnemonic.to_ascii_lowercase());
        vec![Effect::Branch { target, condition }]
    }

    /// Lift `BX <Rm>` â€” branch and exchange (may switch ARM/Thumb mode).
    fn lift_bx(instr: &Instruction) -> Vec<Effect> {
        let target = Self::branch_target(instr, 0);
        // BX LR is effectively a return.
        if let Some(reg) = Self::op_reg(instr, 0)
            && Self::norm_reg(&reg) == REG_LR {
                return vec![Effect::Return {
                    value: Some(IrExpr::Reg("r0".to_string())),
                }];
            }
        let condition = Self::condition_from_mnem(&instr.mnemonic.to_ascii_lowercase());
        vec![Effect::Branch { target, condition }]
    }

    /// Lift `BL <target>` â€” branch with link (call).
    ///
    /// Sets `lr = next_pc`, then calls target.
    fn lift_bl(instr: &Instruction) -> Vec<Effect> {
        let next_pc = instr.address.0 + instr.size as u64;
        let target = Self::branch_target(instr, 0);
        vec![
            Effect::RegWrite {
                reg: REG_LR.to_string(),
                value: IrExpr::Const(next_pc),
            },
            Effect::Call { target },
        ]
    }

    /// Lift `BLX <target>` â€” branch with link and exchange.
    ///
    /// Like BL but may switch ARM/Thumb mode.
    fn lift_blx(instr: &Instruction) -> Vec<Effect> {
        let next_pc = instr.address.0 + instr.size as u64;
        let target = Self::branch_target(instr, 0);
        vec![
            Effect::RegWrite {
                reg: REG_LR.to_string(),
                value: IrExpr::Const(next_pc),
            },
            Effect::Call { target },
        ]
    }

    /// Lift `SVC #imm` (Linux ARM32: syscall number in r7).
    fn lift_svc(_instr: &Instruction) -> Vec<Effect> {
        vec![Effect::Syscall {
            nr: IrExpr::Reg("r7".to_string()),
        }]
    }

    /// Lift `CMP / CMN / TST / TEQ Rn, Op2` â€” flag-only operations.
    ///
    /// These instructions update flags but produce no register output that
    /// is preserved across basic blocks.  We emit a `zf`/`nf` update via
    /// an Intrinsic to represent the flag side-effect without inventing a
    /// register destination.
    fn lift_cmp_family(instr: &Instruction, base: &str) -> Vec<Effect> {
        let a = Self::op_expr(instr, 0);
        let b = Self::op_expr(instr, 1);
        let name = base.to_string();
        vec![Effect::Intrinsic {
            name,
            args: vec![a, b],
        }]
    }

    /// Produce a fallback `Intrinsic` for an unrecognised mnemonic.
    fn fallback(instr: &Instruction) -> Vec<Effect> {
        let mnem = instr.mnemonic.to_ascii_lowercase();
        let args: Vec<IrExpr> = instr
            .operand_list
            .iter()
            .enumerate()
            .map(|(i, _)| Self::op_expr(instr, i))
            .collect();
        vec![Effect::Intrinsic { name: mnem, args }]
    }

    // â”€â”€ Register-list helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Collect all register-name operands from `instr` into a sorted list.
    ///
    /// ARM32 `PUSH` / `POP` / `LDM` / `STM` encode their register lists as
    /// individual [`Operand::Register`] entries in `operand_list`; the first
    /// operand of `LDM`/`STM` is the base register which is skipped here for
    /// PUSH/POP (no explicit base), but for LDM/STM callers handle the base
    /// register separately and pass `skip_first=true`.
    fn collect_reglist(instr: &Instruction) -> Vec<String> {
        use rustre_core::arch::Operand;
        instr
            .operand_list
            .iter()
            .filter_map(|op| {
                if let Operand::Register(r) = op {
                    Some(Self::norm_reg(&r.name))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collect only the register-list operands for LDM/STM, skipping the base.
    fn collect_reglist_skip_base(instr: &Instruction) -> Vec<String> {
        use rustre_core::arch::Operand;
        instr
            .operand_list
            .iter()
            .skip(1) // skip base register
            .filter_map(|op| {
                if let Operand::Register(r) = op {
                    Some(Self::norm_reg(&r.name))
                } else {
                    None
                }
            })
            .collect()
    }

    // â”€â”€ Condition-code extraction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Extract the condition-code suffix from a mnemonic and return the
    /// corresponding [`IrExpr`], or `None` for unconditional branches.
    ///
    /// ARM32 condition codes use the `cpsr` flags `N`, `Z`, `C`, `V`.
    /// We model these as the virtual flag registers `nf`, `zf`, `cf`, `vf`.
    fn condition_from_mnem(mnem: &str) -> Option<IrExpr> {
        // Extract the last two (or one) characters as a potential condition code.
        let cc = if mnem.len() >= 2 {
            // Try two-char suffix first.
            let suffix2 = &mnem[mnem.len() - 2..];
            match suffix2 {
                "eq" => return Some(IrExpr::Reg("zf".to_string())),
                "ne" => return Some(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                "cs" | "hs" => return Some(IrExpr::Reg("cf".to_string())),
                "cc" | "lo" => return Some(IrExpr::Not(Box::new(IrExpr::Reg("cf".to_string())))),
                "mi" => return Some(IrExpr::Reg("nf".to_string())),
                "pl" => return Some(IrExpr::Not(Box::new(IrExpr::Reg("nf".to_string())))),
                "vs" => return Some(IrExpr::Reg("vf".to_string())),
                "vc" => return Some(IrExpr::Not(Box::new(IrExpr::Reg("vf".to_string())))),
                "hi" => {
                    return Some(IrExpr::And(
                        Box::new(IrExpr::Reg("cf".to_string())),
                        Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                    ))
                }
                "ls" => {
                    return Some(IrExpr::Or(
                        Box::new(IrExpr::Not(Box::new(IrExpr::Reg("cf".to_string())))),
                        Box::new(IrExpr::Reg("zf".to_string())),
                    ))
                }
                "ge" => {
                    return Some(IrExpr::Not(Box::new(IrExpr::Xor(
                        Box::new(IrExpr::Reg("nf".to_string())),
                        Box::new(IrExpr::Reg("vf".to_string())),
                    ))))
                }
                "lt" => {
                    return Some(IrExpr::Xor(
                        Box::new(IrExpr::Reg("nf".to_string())),
                        Box::new(IrExpr::Reg("vf".to_string())),
                    ))
                }
                "gt" => {
                    return Some(IrExpr::And(
                        Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".to_string())))),
                        Box::new(IrExpr::Not(Box::new(IrExpr::Xor(
                            Box::new(IrExpr::Reg("nf".to_string())),
                            Box::new(IrExpr::Reg("vf".to_string())),
                        )))),
                    ))
                }
                "le" => {
                    return Some(IrExpr::Or(
                        Box::new(IrExpr::Reg("zf".to_string())),
                        Box::new(IrExpr::Xor(
                            Box::new(IrExpr::Reg("nf".to_string())),
                            Box::new(IrExpr::Reg("vf".to_string())),
                        )),
                    ))
                }
                "al" => return None, // unconditional
                _ => {}
            }
            suffix2
        } else {
            ""
        };
        let _ = cc;
        None // default: unconditional
    }

    // â”€â”€ Main dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Map a normalised mnemonic to a list of [`Effect`]s.
    fn dispatch_a(instr: &Instruction, base: &str) -> Option<Vec<Effect>> {
            match base {
            // â”€â”€ NOP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "nop" => Some(vec![]),

            // â”€â”€ Data movement â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mov" | "movs" | "movw" | "movt" => Some(Self::lift_mov(instr, base)),
            "mvn" | "mvns" => Some(Self::lift_mvn(instr)),

            // â”€â”€ Arithmetic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "add" | "adds" => Some(Self::lift_alu3(instr, IrExpr::Add)),
            "adc" | "adcs" => Some(Self::with_carry_marker(
                Self::with_carry_in(Self::lift_alu3(instr, IrExpr::Add), false),
                "adc",
            )),
            "sub" | "subs" => Some(Self::lift_alu3(instr, IrExpr::Sub)),
            "sbc" | "sbcs" => Some(Self::with_carry_marker(
                Self::with_carry_in(Self::lift_alu3(instr, IrExpr::Sub), true),
                "sbc",
            )),
            "rsb" | "rsbs" => Some(Self::lift_rsb(instr)),
            // RSC shared RSB's arm outright — no carry AND no marker, so the two
            // were indistinguishable rather than merely imprecise.
            "rsc" | "rscs" => Some(Self::with_carry_marker(
                Self::with_carry_in(Self::lift_rsb(instr), true),
                "rsc",
            )),

            // â”€â”€ Bitwise â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "and" | "ands" => Some(Self::lift_alu3(instr, IrExpr::And)),
            "orr" | "orrs" => Some(Self::lift_alu3(instr, IrExpr::Or)),
            "eor" | "eors" => Some(Self::lift_alu3(instr, IrExpr::Xor)),
            "bic" | "bics" => Some(Self::lift_bic(instr)),

            // â”€â”€ Multiply â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "mul" | "muls" => Some(Self::lift_mul(instr)),
            "mla" | "mlas" => Some(Self::lift_mla(instr)),
            "mls" => Some(Self::lift_mls(instr)),

            // â”€â”€ Shifts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "lsl" | "lsls" => Some(Self::lift_shift(instr, true)),
            "lsr" | "lsrs" | "asr" | "asrs" => Some(Self::lift_shift(instr, false)),
            "ror" | "rors" => Some(Self::lift_ror(instr)),

            // â”€â”€ Memory loads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "ldr" => Some(Self::lift_ldr(instr, 4)),
            "ldrb" => Some(Self::lift_ldr(instr, 1)),
            "ldrsb" => Some(Self::lift_ldr_signed(instr, 1)),
            "ldrh" => Some(Self::lift_ldr(instr, 2)),
            "ldrsh" => Some(Self::lift_ldr_signed(instr, 2)),

            // â”€â”€ Memory stores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            "str" => Some(Self::lift_str(instr, 4)),
            "strb" => Some(Self::lift_str(instr, 1)),
            "strh" => Some(Self::lift_str(instr, 2)),
                _ => None,
            }
    }
    fn dispatch_b_a(instr: &Instruction, base: &str) -> Option<Vec<Effect>> {
                match base {
            "ldm" | "ldmia" | "ldmib" | "ldmda" | "ldmdb" | "ldmfd" | "ldmfa" | "ldmea"
            | "ldmed" => Some(Self::lift_ldm(instr, base)),
            "stm" | "stmia" | "stmib" | "stmda" | "stmdb" | "stmfd" | "stmfa" | "stmea"
            | "stmed" => Some(Self::lift_stm(instr, base)),
            "push" => Some(Self::lift_push(instr)),
            "pop" => Some(Self::lift_pop(instr)),
            "b" => Some(Self::lift_b(instr)),
            "bx" => Some(Self::lift_bx(instr)),
            "bl" => Some(Self::lift_bl(instr)),
            "blx" => Some(Self::lift_blx(instr)),
            "cmp" | "cmn" | "tst" | "teq" => Some(Self::lift_cmp_family(instr, base)),
            "svc" | "swi" => Some(Self::lift_svc(instr)),
            it if it.starts_with("it") => {
                Some(vec![Effect::Intrinsic {
                    name: it.to_string(),
                    args: vec![],
                }])
            }
            "dsb" | "dmb" | "isb" | "wfi" | "wfe" | "sev" | "yield" | "hint" => {
                Some(vec![Effect::Intrinsic {
                    name: base.to_string(),
                    args: vec![],
                }])
            }
            "clz" => {
                let dst = Self::op_reg(instr, 0).map_or_else(|| "r0".to_string(), |r| Self::norm_reg(&r));
                let src = Self::op_expr(instr, 1);
                Some(vec![Effect::Intrinsic {
                    name: "clz".to_string(),
                    args: vec![IrExpr::Reg(dst), src],
                }])
            }
            "uxtb" => {
                let dst = Self::op_reg(instr, 0).map_or_else(|| "r0".to_string(), |r| Self::norm_reg(&r));
                let src = Self::op_expr(instr, 1);
                Some(vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(src), Box::new(IrExpr::Const(0xff))),
                }])
            }
            "uxth" => {
                let dst = Self::op_reg(instr, 0).map_or_else(|| "r0".to_string(), |r| Self::norm_reg(&r));
                let src = Self::op_expr(instr, 1);
                Some(vec![Effect::RegWrite {
                    reg: dst,
                    value: IrExpr::And(Box::new(src), Box::new(IrExpr::Const(0xffff))),
                }])
            }
            "sxtb" | "sxth" => {
                let dst = Self::op_reg(instr, 0).map_or_else(|| "r0".to_string(), |r| Self::norm_reg(&r));
                let src = Self::op_expr(instr, 1);
                let mask = if base == "sxtb" { 0xff } else { 0xffff };
                Some(vec![Effect::Intrinsic {
                    name: base.to_string(),
                    args: vec![
                        IrExpr::Reg(dst),
                        IrExpr::And(Box::new(src), Box::new(IrExpr::Const(mask))),
                    ],
                }])
            }
            "rev" | "rev16" | "revsh" => {
                let dst = Self::op_reg(instr, 0).map_or_else(|| "r0".to_string(), |r| Self::norm_reg(&r));
                let src = Self::op_expr(instr, 1);
                Some(vec![Effect::Intrinsic {
                    name: base.to_string(),
                    args: vec![IrExpr::Reg(dst), src],
                }])
            }
            "ldrex" | "ldrexb" | "ldrexh" | "ldrexd" => {
                let size = Self::mem_size_from_mnem(base.trim_start_matches("ldrex"));
                Some(Self::lift_ldr(instr, if size == 0 { 4 } else { size }))
            }
            "strex" | "strexb" | "strexh" | "strexd" => {
                // STREX Rd, Rt, [Rn] â€” Rt is the value, Rn is the address.
                let src = Self::op_expr(instr, 1);
                let addr = Self::op_expr(instr, 2);
                Some(vec![Effect::MemWrite { addr, value: src, size: 4 }])
            }
                    _ => None,
                }
    }

    fn dispatch_b_b(instr: &Instruction, base: &str) -> Option<Vec<Effect>> {
                match base {
            "ldrd" => {
                let dst0 = Self::op_reg(instr, 0).map_or_else(|| "r0".to_string(), |r| Self::norm_reg(&r));
                let dst1 = Self::op_reg(instr, 1).map_or_else(|| "r1".to_string(), |r| Self::norm_reg(&r));
                let (addr, writeback) = Self::indexed_addr_and_writeback(instr, 2);
                let mut out = vec![
                    Effect::MemRead {
                        addr: addr.clone(),
                        dest: dst0,
                        size: 4,
                    },
                    Effect::MemRead {
                        addr: IrExpr::Add(Box::new(addr), Box::new(IrExpr::Const(4))),
                        dest: dst1,
                        size: 4,
                    },
                ];
                out.extend(writeback);
                Some(out)
            }
            "strd" => {
                let src0 = Self::op_expr(instr, 0);
                let src1 = Self::op_expr(instr, 1);
                let addr = Self::op_expr(instr, 2);
                Some(vec![
                    Effect::MemWrite {
                        addr: addr.clone(),
                        value: src0,
                        size: 4,
                    },
                    Effect::MemWrite {
                        addr: IrExpr::Add(Box::new(addr), Box::new(IrExpr::Const(4))),
                        value: src1,
                        size: 4,
                    },
                ])
            }
            _ => Some(Self::fallback(instr)),
                }
    }

    fn dispatch_b(instr: &Instruction, base: &str) -> Vec<Effect> {
        let __s0 = Self::dispatch_b_a(instr, base);
        if let Some(v) = __s0 { return v; }
        Self::dispatch_b_b(instr, base).unwrap_or_default()
    }

    /// Does this mnemonic carry a condition suffix or the flag-setting `S`?
    ///
    /// `normalise` strips BOTH before dispatch, so `addeq` reaches the match as
    /// `add` and `adds` as `add`. Two facts died there:
    ///
    /// * **the condition** — `ADDEQ` executes only when Z is set, and the IL
    ///   claimed the add always happens. On ARM32, whose signature feature is
    ///   predication, that is wrong code on a very common pattern, not a corner
    ///   case;
    /// * **the `S` flag** — `ADDS` updates the condition flags and `ADD` does
    ///   not.
    ///
    /// It also means every `"...s"` entry in the match arms (`"adds"`,
    /// `"adcs"`, `"subs"`, `"lsrs"`…) is UNREACHABLE — dead code that reads as
    /// coverage. Second lifter with this shape after PowerPC's `o` suffix.
    ///
    /// This IR has no conditional-write effect (only `Effect::Branch` carries a
    /// condition), so a predicated data instruction cannot be expressed
    /// exactly. The fixable half is making the fact SURVIVE: a marker naming
    /// the full mnemonic, the same convention used for PowerPC's overflow forms
    /// and ARM's own `ADC`.
    fn suffix_marker(raw: &str, base: &str) -> Option<Effect> {
        if raw == base {
            return None;
        }
        Some(Effect::Intrinsic { name: raw.to_string(), args: vec![] })
    }

    fn dispatch(instr: &Instruction, base: &str) -> Vec<Effect> {
        let raw = instr.mnemonic.to_ascii_lowercase();
        let mut effects = {
            let __r0 = Self::dispatch_a(instr, base);
            if let Some(v) = __r0 { v } else { Self::dispatch_b(instr, base) }
        };
        // Branches already model their own condition (`condition_from_mnem`),
        // so marking them again would be noise; everything else loses the fact.
        if !effects.iter().any(|e| matches!(e, Effect::Branch { .. }))
            && let Some(marker) = Self::suffix_marker(&raw, base)
        {
            // ARM's defining feature is PREDICATION, and it was being thrown
            // away: `ADDEQ r0, r1, r2` produced an UNCONDITIONAL
            // `RegWrite { r0, r1 + r2 }` next to a marker naming the suffix.
            // The marker kept the fact readable, but every dataflow pass saw an
            // unconditional definition of r0 — confidently wrong rather than
            // merely opaque.
            //
            // `IrExpr::IfThenElse` exists and `condition_from_mnem` already
            // builds the condition for branches, so nothing had to be invented:
            //   r0 = if <cond> { r1 + r2 } else { r0 }
            // which is the same shape as a conditional move.
            //
            // The condition is derived from the SUFFIX, never from the raw
            // mnemonic: `teq` ends in "eq" and `svc` in "vc", and reading those
            // as conditions is exactly the collision the ATOMIC list in
            // `strip_suffixes` guards. Because `base` is the already-stripped
            // mnemonic, an atomic like `teq` has `raw == base` and never
            // reaches here at all.
            if let Some(suffix) = raw.strip_prefix(base)
                && let Some(cond) = Self::condition_from_mnem(suffix)
            {
                for e in &mut effects {
                    if let Effect::RegWrite { reg, value } = e {
                        *value = IrExpr::IfThenElse(
                            Box::new(cond.clone()),
                            Box::new(value.clone()),
                            Box::new(IrExpr::Reg(reg.clone())),
                        );
                    }
                }
            }
            effects.insert(0, marker);
        }
        effects
    }
}

impl Default for Arm32Lifter {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ArchLifter implementation
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

impl ArchLifter for Arm32Lifter {
    fn arch_name(&self) -> &'static str {
        if self.thumb { "thumb" } else { "arm32" }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        if self.thumb {
            "mnemonic-driven Thumb/Thumb-2 LLIL lifter"
        } else {
            "mnemonic-driven ARM32 LLIL lifter"
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        let base = Self::normalise(mnemonic);
        !matches!(base.as_str(), "" | "undefined")
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let base = Self::normalise(&instr.mnemonic);
        let effects = Self::dispatch(instr, &base);

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
    use rustre_core::arch::{InstrFlags, Instruction, Operand, RegisterInfo, RegisterKind};
    use rustre_core::Address;

    fn make_reg(name: &str) -> RegisterInfo {
        RegisterInfo::new(name, 0, 4, RegisterKind::General)
    }

    fn make_instr(addr: u64, mnemonic: &str) -> Instruction {
        Instruction {
            address: Address::new(addr),
            size: 4,
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            operand_list: Vec::new(),
            flags: InstrFlags::NONE,
            bytes: vec![0; 4],
            comment: None,
        }
    }

    fn with_ops(mut instr: Instruction, ops: Vec<Operand>) -> Instruction {
        instr.operand_list = ops;
        instr
    }

    fn reg_op(name: &str) -> Operand {
        Operand::Register(make_reg(name))
    }

    fn imm_op(v: u64) -> Operand {
        Operand::UImmediate(v)
    }

    fn label_op(v: u64) -> Operand {
        Operand::Label(v)
    }

    fn mem_op(base: &str, disp: i64) -> Operand {
        Operand::Memory {
            base: Some(make_reg(base)),
            index: None,
            scale: 1,
            disp,
            width: 4,
        }
    }

    fn lifter() -> Arm32Lifter {
        Arm32Lifter::new()
    }

    // â”€â”€ strip_suffixes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// `LDRSB`/`LDRSH` sign-extend; `LDRB`/`LDRH` zero-extend. They shared a
    /// handler taking only a size, so the two lifted identically.
    ///
    /// Fifth architecture with this defect. The doc comment on `lift_ldr` lists
    /// `LDR{B,H,SB,SH}` together — the distinction was written down and then not
    /// made, which is the same comment-versus-code gap seen a dozen times here.
        /// ARM's defining feature is PREDICATION, and it was being discarded.
    ///
    /// `ADDEQ r0, r1, r2` lifted to an UNCONDITIONAL `RegWrite` beside a marker
    /// naming the suffix. The marker kept the fact readable, so this was not an
    /// opacity problem — every dataflow pass saw an unconditional definition of
    /// `r0`, which is confidently wrong. `IrExpr::IfThenElse` already existed
    /// and `condition_from_mnem` already built the condition for branches.
    ///
    /// The untaken arm must be the destination's OLD value, not a zero or an
    /// `Undef` — the same lesson as the CMPXCHG upper-half fix.
    #[test]
    fn predicated_writes_are_conditional() {
        let l = lifter();
        let dataproc = |m: &str| {
            let i = with_ops(
                make_instr(0x1000, m),
                vec![reg_op("r0"), reg_op("r1"), reg_op("r2")],
            );
            format!("{:?}", l.lift(&i).unwrap().effects)
        };

        let cond = dataproc("addeq");
        assert!(
            cond.contains("IfThenElse(Reg(\"zf\")") && cond.contains("Reg(\"r0\"))"),
            "addeq must write conditionally, keeping r0 on the untaken arm: {cond}"
        );

        // The unconditional form must NOT grow a condition.
        let plain = dataproc("add");
        assert!(
            !plain.contains("IfThenElse"),
            "add is unconditional: {plain}"
        );

        // `S` sets flags, it is not a condition — it must not become one.
        let flags = dataproc("adds");
        assert!(
            !flags.contains("IfThenElse"),
            "adds is flag-setting, not predicated: {flags}"
        );

        // The condition comes from the SUFFIX, never the raw mnemonic: `teq`
        // ends in "eq" and `svc` in "vc". Those are atomic in `strip_suffixes`,
        // so `raw == base` and they never reach the predication path.
        for atomic in ["teq", "svc"] {
            let t = dataproc(atomic);
            assert!(
                !t.contains("IfThenElse"),
                "{atomic} is not predicated; its tail only looks like a condition: {t}"
            );
        }

        // SCOPE, recorded rather than silently skipped: a predicated LOAD or
        // STORE is NOT modelled. `Effect::MemRead`/`MemWrite` have no slot for
        // a condition, and wrapping the stored VALUE would not help — the
        // access itself would still happen. That needs a conditional-effect
        // concept the IR does not have; the marker keeps the fact readable.
        let ld = {
            let i = with_ops(make_instr(0x1000, "ldreq"), vec![reg_op("r0"), mem_op("r1", 4)]);
            format!("{:?}", l.lift(&i).unwrap().effects)
        };
        assert!(
            ld.contains("ldreq"),
            "a predicated load must at least keep its condition named: {ld}"
        );
    }

#[test]
    fn signed_and_unsigned_loads_differ() {
        let ops = || {
            vec![
                Operand::Register(make_reg("r0")),
                Operand::Memory {
                    base: Some(make_reg("r1")),
                    index: None,
                    scale: 1,
                    disp: 8,
                    width: 1,
                },
            ]
        };
        let render = |m: &str| {
            format!(
                "{:?}",
                Arm32Lifter::new()
                    .lift(&with_ops(make_instr(0x1000, m), ops()))
                    .unwrap()
                    .effects
            )
        };
        assert_ne!(render("ldrb"), render("ldrsb"), "LDRB and LDRSB must differ");
        assert_ne!(render("ldrh"), render("ldrsh"), "LDRH and LDRSH must differ");
        assert!(render("ldrsb").contains("sext8"), "LDRSB must sign-extend");
        assert!(!render("ldrb").contains("sext"), "LDRB must not sign-extend");
    }

    /// Four ARM mnemonics END with the letters of a condition code without
    /// carrying one, and `strip_suffixes` mangled every one of them into
    /// something no match arm can see: `teq`→`t`, `mls`→`ml`, `smlal`→`sml`,
    /// `umlal`→`uml`. `svc` had already been special-cased by hand; the rest
    /// were the same defect, unnoticed.
    ///
    /// The opposite direction is asserted too: real suffixed forms must STILL
    /// be stripped, or the guard would trade one defect for another.
    #[test]
    fn mnemonics_colliding_with_suffixes_are_not_mangled() {
        for m in ["teq", "mls", "smlal", "umlal", "svc"] {
            assert_eq!(
                Arm32Lifter::strip_suffixes(m),
                m,
                "{m} is a complete mnemonic, not base+suffix"
            );
        }
        for (input, base) in [("addeq", "add"), ("movne", "mov"), ("adds", "add"), ("bics", "bic")] {
            assert_eq!(
                Arm32Lifter::strip_suffixes(input),
                base,
                "{input} really does carry a suffix"
            );
        }
        // Measured behaviour worth pinning: `lsrs` is left UNCHANGED by the
        // existing guard, so its match arm IS reachable. An earlier note in
        // this session claimed every `...s` arm was dead code — that was too
        // broad, and this assertion records the correction.
        assert_eq!(Arm32Lifter::strip_suffixes("lsrs"), "lsrs");
    }

    /// `normalise` strips the condition suffix and the flag-setting `S` before
    /// dispatch, so `ADDEQ` and `ADDS` both reached the match as `add` and
    /// lifted IDENTICALLY to an unconditional, non-flag-setting add. On ARM32,
    /// where predication is the ISA's signature feature, that is wrong on a
    /// very common pattern.
    #[test]
    fn condition_and_s_suffix_survive_normalisation() {
        let ops = || {
            vec![
                Operand::Register(make_reg("r0")),
                Operand::Register(make_reg("r1")),
                Operand::Register(make_reg("r2")),
            ]
        };
        let render = |m: &str| {
            format!(
                "{:?}",
                Arm32Lifter::new()
                    .lift(&with_ops(make_instr(0x1000, m), ops()))
                    .unwrap()
                    .effects
            )
        };
        let plain = render("add");
        assert_ne!(plain, render("addeq"), "ADDEQ is conditional; ADD is not");
        assert_ne!(plain, render("adds"), "ADDS sets the flags; ADD does not");
        assert!(render("addeq").contains("addeq"), "the condition must be named");
    }

    /// `ADC` adds the carry, `ADD` does not — `ADDS`+`ADC` is how ARM32 adds a
    /// 64-bit value. They shared a handler and lifted IDENTICALLY, so nothing
    /// downstream could tell a multi-word add from a plain one. The exact value
    /// is not expressible (this IR has no readable carry flag), but the
    /// DISTINCTION must survive.
    #[test]
    fn adc_is_distinguishable_from_add() {
        let ops = || {
            vec![
                Operand::Register(make_reg("r0")),
                Operand::Register(make_reg("r1")),
                Operand::Register(make_reg("r2")),
            ]
        };
        let render = |m: &str| {
            format!(
                "{:?}",
                Arm32Lifter::new()
                    .lift(&with_ops(make_instr(0x1000, m), ops()))
                    .unwrap()
                    .effects
            )
        };
        // Compare only the WRITES. The marker intrinsics carry different names,
        // so comparing whole renderings is satisfied by the name alone — this
        // assertion passed for months while `adc` produced a value identical to
        // `add`, the carry-in silently dropped.
        let writes = |m: &str| {
            Arm32Lifter::new()
                .lift(&with_ops(make_instr(0x1000, m), ops()))
                .unwrap()
                .effects
                .iter()
                .filter(|e| !matches!(e, Effect::Intrinsic { .. }))
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
        };

        for (plain, carry) in [("add", "adc"), ("sub", "sbc"), ("rsb", "rsc")] {
            assert_ne!(
                writes(plain),
                writes(carry),
                "{carry} folds in the carry; its VALUE must differ from {plain}"
            );
            assert!(
                format!("{:?}", writes(carry)).contains("cf"),
                "{carry} must read the carry flag: {:?}",
                writes(carry)
            );
        }

        // RSC used to share RSB's arm outright, so it had no marker either.
        assert!(render("rsc").contains("rsc"), "RSC must be named, not folded into RSB");
        assert!(render("adc").contains("adc"), "the carry fact must be named");
    }

    /// `LDM`/`STM` write the base register back ONLY in the `!` form. Both
    /// lifters used to do it unconditionally, inventing a definition of the
    /// base register for every non-`!` form. Nothing in the suite covered it —
    /// the fix stayed green — so this test exists to make the fix mean
    /// something, and it checks BOTH directions.
    #[test]
    fn ldm_stm_write_back_only_with_the_bang_suffix() {
        let base_written = |instr: &Instruction| -> bool {
            Arm32Lifter::new()
                .lift(instr)
                .is_ok_and(|l| {
                    l.effects
                        .iter()
                        .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "r0"))
                })
        };

        let ops = || {
            vec![
                Operand::Register(make_reg("r0")),
                Operand::Register(make_reg("r1")),
                Operand::Register(make_reg("r2")),
            ]
        };

        let plain = with_ops(make_instr(0x1000, "ldmia"), ops());
        assert!(
            !base_written(&plain),
            "LDMIA without `!` must NOT write the base register"
        );

        let mut bang = with_ops(make_instr(0x1004, "ldmia"), ops());
        bang.operands = "r0!, {r1, r2}".to_string();
        assert!(
            base_written(&bang),
            "LDMIA with `!` MUST write the base register back"
        );
    }

    #[test]
    fn test_strip_eq_suffix() {
        assert_eq!(Arm32Lifter::strip_suffixes("addeq"), "add");
    }

    #[test]
    fn test_strip_ne_suffix() {
        assert_eq!(Arm32Lifter::strip_suffixes("movne"), "mov");
    }

    #[test]
    fn test_strip_s_flag() {
        // "movs" â†’ strip trailing 's' â†’ "mov"
        // Note: our heuristic only strips 's' when the result isn't a
        // recognised 's'-terminal mnemonic.
        let base = Arm32Lifter::normalise("movs");
        assert_eq!(base, "mov");
    }

    #[test]
    fn test_no_suffix_unchanged() {
        assert_eq!(Arm32Lifter::strip_suffixes("ldr"), "ldr");
        assert_eq!(Arm32Lifter::strip_suffixes("str"), "str");
        assert_eq!(Arm32Lifter::strip_suffixes("nop"), "nop");
    }

    #[test]
    fn test_strip_blxne() {
        assert_eq!(Arm32Lifter::normalise("blxne"), "blx");
    }

    // â”€â”€ MOV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_mov_reg() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x1000, "mov"),
            vec![reg_op("r0"), reg_op("r1")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "r0");
                assert!(matches!(value, IrExpr::Reg(r) if r == "r1"));
            }
            _ => panic!("Expected RegWrite"),
        }
    }

    #[test]
    fn test_mov_imm() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x1000, "mov"),
            vec![reg_op("r2"), imm_op(42)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value } => {
                assert_eq!(reg, "r2");
                assert!(matches!(value, IrExpr::Const(42)));
            }
            _ => panic!("Expected RegWrite"),
        }
    }

    #[test]
    fn test_movw() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x1000, "movw"),
            vec![reg_op("r3"), imm_op(0xabcd)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::RegWrite { value: IrExpr::Const(v), .. } => {
                assert_eq!(*v, 0xabcd);
            }
            _ => panic!("Expected RegWrite with Const"),
        }
    }

    #[test]
    fn test_movt() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x1000, "movt"),
            vec![reg_op("r4"), imm_op(0x1234)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        // Result should be Or(And(r4, 0xffff), 0x1234_0000)
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value: IrExpr::Or(_, hi) } => {
                assert_eq!(reg, "r4");
                assert!(matches!(hi.as_ref(), IrExpr::Const(0x1234_0000)));
            }
            _ => panic!("Expected RegWrite Or"),
        }
    }

    // â”€â”€ LDR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ldr_mem() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x2000, "ldr"),
            vec![reg_op("r0"), mem_op("r1", 8)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::MemRead { dest, size, .. } => {
                assert_eq!(dest, "r0");
                assert_eq!(*size, 4);
            }
            _ => panic!("Expected MemRead"),
        }
    }

    #[test]
    fn test_ldrb() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x2004, "ldrb"),
            vec![reg_op("r5"), mem_op("r6", 0)],
        );
        let lifted = l.lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::MemRead { size, .. } => assert_eq!(*size, 1),
            _ => panic!("Expected MemRead"),
        }
    }

    #[test]
    fn test_ldrh() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x2008, "ldrh"),
            vec![reg_op("r7"), mem_op("r8", 0)],
        );
        let lifted = l.lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::MemRead { size, .. } => assert_eq!(*size, 2),
            _ => panic!("Expected MemRead"),
        }
    }

    // â”€â”€ STR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_str_mem() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x3000, "str"),
            vec![reg_op("r0"), mem_op("sp", -4)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::MemWrite { size, .. } => assert_eq!(*size, 4),
            _ => panic!("Expected MemWrite"),
        }
    }

    // â”€â”€ BL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_bl() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x4000, "bl"),
            vec![label_op(0x8000)],
        );
        let lifted = l.lift(&instr).unwrap();
        // BL should emit lr = next_pc and Call
        assert!(lifted.effects.len() >= 2);
        let has_lr = lifted.effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite { reg, .. } if reg == "lr"
        ));
        let has_call = lifted.effects.iter().any(|e| matches!(
            e,
            Effect::Call { target: IrExpr::Const(0x8000) }
        ));
        assert!(has_lr, "BL should set lr");
        assert!(has_call, "BL should emit Call to 0x8000");
    }

    #[test]
    fn test_bl_sets_next_pc_in_lr() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x4000, "bl"),
            vec![label_op(0x9000)],
        );
        let lifted = l.lift(&instr).unwrap();
        let lr_val = lifted.effects.iter().find_map(|e| {
            if let Effect::RegWrite { reg, value: IrExpr::Const(v) } = e {
                if reg == "lr" { Some(*v) } else { None }
            } else {
                None
            }
        });
        // next_pc = 0x4000 + 4 = 0x4004
        assert_eq!(lr_val, Some(0x4004));
    }

    // â”€â”€ POP (return) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_pop_with_pc() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x5000, "pop"),
            vec![reg_op("r4"), reg_op("r5"), reg_op("pc")],
        );
        let lifted = l.lift(&instr).unwrap();
        let has_return = lifted.effects.iter().any(|e| matches!(e, Effect::Return { .. }));
        assert!(has_return, "POP {{r4,r5,pc}} should emit Return");
    }

    #[test]
    fn test_pop_without_pc() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x5000, "pop"),
            vec![reg_op("r4"), reg_op("r5")],
        );
        let lifted = l.lift(&instr).unwrap();
        let has_return = lifted.effects.iter().any(|e| matches!(e, Effect::Return { .. }));
        assert!(!has_return, "POP without pc should not emit Return");
        // Should have MemRead for r4, r5 and sp adjustment.
        let reads: usize = lifted.effects.iter().filter(|e| matches!(e, Effect::MemRead { .. })).count();
        assert_eq!(reads, 2);
    }

    // â”€â”€ SVC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_svc() {
        let l = lifter();
        let instr = make_instr(0x6000, "svc");
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::Syscall { nr: IrExpr::Reg(r) } => {
                assert_eq!(r, "r7");
            }
            _ => panic!("Expected Syscall with r7"),
        }
    }

    #[test]
    fn test_swi() {
        // SWI is an alias for SVC on older ARM.
        let l = lifter();
        let instr = make_instr(0x6004, "swi");
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(&lifted.effects[0], Effect::Syscall { .. }));
    }

    // â”€â”€ Branches â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_b_unconditional() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x7000, "b"),
            vec![label_op(0x7100)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.effects.len(), 1);
        match &lifted.effects[0] {
            Effect::Branch { condition: None, target: IrExpr::Const(0x7100) } => {}
            _ => panic!("Expected unconditional Branch to 0x7100"),
        }
    }

    #[test]
    fn test_beq() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x7004, "beq"),
            vec![label_op(0x7200)],
        );
        let lifted = l.lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::Branch { condition: Some(IrExpr::Reg(r)), .. } => {
                assert_eq!(r, "zf");
            }
            _ => panic!("Expected conditional Branch on zf"),
        }
    }

    #[test]
    fn test_bne() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x7008, "bne"),
            vec![label_op(0x7300)],
        );
        let lifted = l.lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::Branch { condition: Some(IrExpr::Not(inner)), .. } => {
                assert!(matches!(inner.as_ref(), IrExpr::Reg(r) if r == "zf"));
            }
            _ => panic!("Expected Branch with NOT(zf)"),
        }
    }

    #[test]
    fn test_bx_lr_is_return() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x8000, "bx"),
            vec![reg_op("lr")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(
            lifted.effects.iter().any(|e| matches!(e, Effect::Return { .. })),
            "BX LR should be a Return"
        );
    }

    // â”€â”€ Arithmetic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_add() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x9000, "add"),
            vec![reg_op("r0"), reg_op("r1"), reg_op("r2")],
        );
        let lifted = l.lift(&instr).unwrap();
        match &lifted.effects[0] {
            Effect::RegWrite { reg, value: IrExpr::Add(..) } => {
                assert_eq!(reg, "r0");
            }
            _ => panic!("Expected RegWrite Add"),
        }
    }

    #[test]
    fn test_sub() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x9004, "sub"),
            vec![reg_op("r0"), reg_op("r1"), reg_op("r2")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(
            &lifted.effects[0],
            Effect::RegWrite { value: IrExpr::Sub(..), .. }
        ));
    }

    #[test]
    fn test_and() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x9008, "and"),
            vec![reg_op("r0"), reg_op("r1"), imm_op(0xff)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(
            &lifted.effects[0],
            Effect::RegWrite { value: IrExpr::And(..), .. }
        ));
    }

    #[test]
    fn test_orr() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x900c, "orr"),
            vec![reg_op("r0"), reg_op("r1"), reg_op("r2")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(
            &lifted.effects[0],
            Effect::RegWrite { value: IrExpr::Or(..), .. }
        ));
    }

    #[test]
    fn test_eor() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x9010, "eor"),
            vec![reg_op("r0"), reg_op("r1"), reg_op("r2")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(
            &lifted.effects[0],
            Effect::RegWrite { value: IrExpr::Xor(..), .. }
        ));
    }

    #[test]
    fn test_mul() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0x9014, "mul"),
            vec![reg_op("r0"), reg_op("r1"), reg_op("r2")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(
            &lifted.effects[0],
            Effect::RegWrite { value: IrExpr::Mul(..), .. }
        ));
    }

    // â”€â”€ NOP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_nop() {
        let l = lifter();
        let lifted = l.lift(&make_instr(0xa000, "nop")).unwrap();
        assert!(lifted.effects.is_empty());
        assert_eq!(lifted.ir_text, "nop");
    }

    // â”€â”€ Condition-code stripping in condition_from_mnem â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_condition_ge() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0xb000, "bge"),
            vec![label_op(0xb100)],
        );
        let lifted = l.lift(&instr).unwrap();
        // GE = NOT(NF XOR VF)
        match &lifted.effects[0] {
            Effect::Branch { condition: Some(IrExpr::Not(inner)), .. } => {
                assert!(matches!(inner.as_ref(), IrExpr::Xor(..)));
            }
            _ => panic!("Expected Branch with NOT(XOR) condition for GE"),
        }
    }

    #[test]
    fn test_condition_lt() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0xb004, "blt"),
            vec![label_op(0xb200)],
        );
        let lifted = l.lift(&instr).unwrap();
        // LT = NF XOR VF
        match &lifted.effects[0] {
            Effect::Branch { condition: Some(IrExpr::Xor(a, b)), .. } => {
                assert!(matches!(a.as_ref(), IrExpr::Reg(r) if r == "nf"));
                assert!(matches!(b.as_ref(), IrExpr::Reg(r) if r == "vf"));
            }
            _ => panic!("Expected Branch with XOR(nf,vf) condition for LT"),
        }
    }

    // â”€â”€ Thumb lifter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_thumb_arch_name() {
        let l = Arm32Lifter::new_thumb();
        assert_eq!(l.arch_name(), "thumb");
    }

    #[test]
    fn test_arm32_arch_name() {
        let l = Arm32Lifter::new();
        assert_eq!(l.arch_name(), "arm32");
    }

    // â”€â”€ PUSH / POP SP adjustment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// `STMDB`/`STMFD` decrement BEFORE storing. They shared a handler with
    /// `STMIA`, so the standard prologue `stmdb sp!, {r4, r5, lr}` stored at
    /// `sp+0/+4/+8` and wrote back `sp+12` instead of storing at `sp-12/-8/-4`
    /// and leaving `sp-12`. `lift_push` -- the same instruction under its alias
    /// -- already modelled this correctly: two implementations, one right.
    #[test]
    fn block_transfers_respect_the_addressing_mode_direction() {
        // The pure mode arithmetic, for a three-register list (12 bytes).
        // (first transferred offset, writeback delta)
        for (mnem, is_load, want) in [
            ("stmia", false, (0i64, 12i64)),
            ("stmib", false, (4, 12)),
            ("stmda", false, (-8, -12)),
            ("stmdb", false, (-12, -12)),
            // Stack aliases mean DIFFERENT modes for loads and stores: FD is
            // DB for a store but IA for a load. One shared handler cannot infer
            // the direction from the suffix, which is the root of the defect.
            ("stmfd", false, (-12, -12)),
            ("stmea", false, (0, 12)),
            ("ldmia", true, (0, 12)),
            ("ldmfd", true, (0, 12)),
            ("ldmdb", true, (-12, -12)),
            ("ldmea", true, (-12, -12)),
        ] {
            let got = Arm32Lifter::block_transfer_offsets(mnem, 3, is_load);
            assert_eq!(got, want, "{mnem}: wrong addressing-mode arithmetic");
        }

        // And end-to-end through the real dispatch path: the prologue must
        // touch addresses BELOW sp, never above it.
        let lifter = Arm32Lifter::new();
        let mut instr = with_ops(
            make_instr(0x1000, "stmdb"),
            vec![reg_op("sp"), reg_op("r4"), reg_op("r5"), reg_op("lr")],
        );
        instr.operands = "sp!, {r4, r5, lr}".to_string();
        let text = format!("{:?}", lifter.lift(&instr).unwrap().effects);
        assert!(
            text.contains("Sub"),
            "STMDB must address below the base, got {text}"
        );
        assert!(
            !text.contains("Add"),
            "STMDB must not address above the base, got {text}"
        );
    }

    /// ARM's three indexing modes differ in the ADDRESS accessed and in whether
    /// the base advances. All three produced the same effect before: `base+disp`
    /// with no writeback, so `ldr r0, [r1, #4]!` lost the pointer advance and
    /// `ldr r0, [r1], #4` also read from the wrong address.
    ///
    /// `lift_ldm`/`lift_stm` in this same file already consulted
    /// `has_writeback` — two implementations of one fact, one right.
    #[test]
    fn indexed_addressing_modes_differ_in_address_and_writeback() {
        let mem = |base: &str, disp: i64| Operand::Memory {
            base: Some(make_reg(base)),
            index: None,
            scale: 1,
            disp,
            width: 4,
        };
        let build = |text: &str| {
            let mut i = with_ops(
                make_instr(0x1000, "ldr"),
                vec![reg_op("r0"), mem("r1", 4)],
            );
            i.operands = text.to_string();
            i
        };
        let lifter = Arm32Lifter::new();
        let eff = |text: &str| lifter.lift(&build(text)).unwrap().effects;

        // Plain offset: address is r1+4, base unchanged.
        let plain = eff("r0, [r1, #4]");
        assert_eq!(plain.len(), 1, "offset form must not write back: {plain:?}");
        assert!(matches!(plain[0], Effect::MemRead { .. }));

        // Pre-indexed: address is r1+4 AND base becomes r1+4.
        let pre = eff("r0, [r1, #4]!");
        assert!(
            matches!(
                pre.last(),
                Some(Effect::RegWrite { reg, value: IrExpr::Add(..) }) if reg == "r1"
            ),
            "pre-indexed must advance r1: {pre:?}"
        );
        let pre_addr = match &pre[0] {
            Effect::MemRead { addr, .. } => format!("{addr:?}"),
            other => panic!("expected a load, got {other:?}"),
        };
        assert!(pre_addr.contains("Add"), "pre-indexed reads r1+4: {pre_addr}");

        // Post-indexed: address is the UNMODIFIED r1, and base still advances.
        let post = eff("r0, [r1], #4");
        assert!(
            matches!(
                post.last(),
                Some(Effect::RegWrite { reg, value: IrExpr::Add(..) }) if reg == "r1"
            ),
            "post-indexed must advance r1: {post:?}"
        );
        let post_addr = match &post[0] {
            Effect::MemRead { addr, .. } => format!("{addr:?}"),
            other => panic!("expected a load, got {other:?}"),
        };
        assert!(
            !post_addr.contains("Add"),
            "post-indexed reads the UNMODIFIED base, got {post_addr}"
        );

        // All three must be distinguishable from one another.
        let renders = [
            format!("{plain:?}"),
            format!("{pre:?}"),
            format!("{post:?}"),
        ];
        assert_ne!(renders[0], renders[1]);
        assert_ne!(renders[1], renders[2]);
        assert_ne!(renders[0], renders[2]);

        // Stores share the modes and the same helper.
        let mut st = with_ops(
            make_instr(0x1004, "str"),
            vec![reg_op("r0"), mem("r1", 8)],
        );
        st.operands = "r0, [r1, #8]!".to_string();
        let se = lifter.lift(&st).unwrap().effects;
        assert!(
            matches!(
                se.last(),
                Some(Effect::RegWrite { reg, value: IrExpr::Add(..) }) if reg == "r1"
            ),
            "pre-indexed STR must advance r1: {se:?}"
        );
    }

    #[test]
    fn test_push_adjusts_sp() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0xc000, "push"),
            vec![reg_op("r4"), reg_op("r5"), reg_op("lr")],
        );
        let lifted = l.lift(&instr).unwrap();
        let sp_write = lifted.effects.iter().find(|e| {
            matches!(e, Effect::RegWrite { reg, .. } if reg == "sp")
        });
        assert!(sp_write.is_some(), "PUSH should adjust SP");
    }

    // â”€â”€ CMP / TST â†’ Intrinsic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cmp_emits_intrinsic() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0xd000, "cmp"),
            vec![reg_op("r0"), reg_op("r1")],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(&lifted.effects[0], Effect::Intrinsic { name, .. } if name == "cmp"));
    }

    #[test]
    fn test_tst_emits_intrinsic() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0xd004, "tst"),
            vec![reg_op("r2"), imm_op(0x0f)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(matches!(&lifted.effects[0], Effect::Intrinsic { name, .. } if name == "tst"));
    }

    // â”€â”€ ir_text sanity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ir_text_non_empty_for_ldr() {
        let l = lifter();
        let instr = with_ops(
            make_instr(0xe000, "ldr"),
            vec![reg_op("r0"), mem_op("r1", 0)],
        );
        let lifted = l.lift(&instr).unwrap();
        assert!(!lifted.ir_text.is_empty());
        assert_ne!(lifted.ir_text, "nop");
    }

    #[test]
    fn test_lifted_instr_address_preserved() {
        let l = lifter();
        let instr = make_instr(0x1234_5678, "nop");
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.address, 0x1234_5678);
    }

    #[test]
    fn test_original_mnemonic_preserved() {
        let l = lifter();
        let instr = make_instr(0x1000, "ADDEQ");
        let lifted = l.lift(&instr).unwrap();
        assert_eq!(lifted.original_mnemonic, "ADDEQ");
    }
}


