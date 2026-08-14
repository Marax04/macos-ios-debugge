//! Flag semantics lifter.
//!
//! Provides [`FlagSemanticsLifter`], [`FlagUpdate`], [`FlagExpr`], and
//! [`lift_flags_for_insn()`] for converting the implicit flag side-effects of
//! an instruction into explicit IR expressions that downstream passes can
//! reason about.

use std::collections::HashMap;
use std::fmt;

use crate::{Effect, IrExpr, LiftedInstr};

// ─────────────────────────────────────────────────────────────────────────────
// FlagId
// ─────────────────────────────────────────────────────────────────────────────

/// Names of x86 condition flags produced by arithmetic and logical operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlagId {
    /// Carry flag.
    CF,
    /// Overflow flag.
    OF,
    /// Sign flag.
    SF,
    /// Zero flag.
    ZF,
    /// Parity flag.
    PF,
    /// Auxiliary carry flag.
    AF,
    /// Direction flag.
    DF,
    /// Trap flag.
    TF,
    /// Interrupt enable flag.
    IF,
    /// Any architecture-specific flag identified by name.
    Named(String),
}

impl FlagId {
    #[must_use] 
    pub const fn name(&self) -> &str {
        match self {
            Self::CF => "cf",
            Self::OF => "of",
            Self::SF => "sf",
            Self::ZF => "zf",
            Self::PF => "pf",
            Self::AF => "af",
            Self::DF => "df",
            Self::TF => "tf",
            Self::IF => "if",
            Self::Named(n) => n.as_str(),
        }
    }

    #[must_use] 
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "cf" => Self::CF,
            "of" => Self::OF,
            "sf" => Self::SF,
            "zf" => Self::ZF,
            "pf" => Self::PF,
            "af" => Self::AF,
            "df" => Self::DF,
            "tf" => Self::TF,
            "if" => Self::IF,
            other => Self::Named(other.to_string()),
        }
    }
}

impl fmt::Display for FlagId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlagExpr
// ─────────────────────────────────────────────────────────────────────────────

/// An expression that computes a flag value from the result of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagExpr {
    /// The flag is always set to a constant (0 or 1).
    Const(u8),
    /// The flag is undefined / unspecified after this instruction.
    Undefined,
    /// The flag inherits its previous value (unchanged).
    Preserved,
    /// The flag is set to 1 when the result equals zero.
    ResultEqualsZero,
    /// The flag is set to the sign bit (bit `width - 1`) of the result.
    ResultSignBit { width: u8 },
    /// The flag is set to the even parity of the low 8 bits of the result.
    ResultParity,
    /// Carry out of bit `bit_pos` of the result.
    CarryOut { bit_pos: u8 },
    /// Overflow when adding two signed `width`-bit values.
    AddOverflow { width: u8 },
    /// Overflow when subtracting two signed `width`-bit values.
    SubOverflow { width: u8 },
    /// Borrow from subtraction.
    BorrowOut { width: u8 },
    /// Half-carry from bit 3 (used by x86 AF).
    AuxiliaryCarry,
    /// Arbitrary IR expression.
    Expr(IrExpr),
}

impl fmt::Display for FlagExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "{v}"),
            Self::Undefined => write!(f, "?"),
            Self::Preserved => write!(f, "="),
            Self::ResultEqualsZero => write!(f, "(res==0)"),
            Self::ResultSignBit { width } => write!(f, "(res[{width}])"),
            Self::ResultParity => write!(f, "parity(res)"),
            Self::CarryOut { bit_pos } => write!(f, "carry({bit_pos})"),
            Self::AddOverflow { width } => write!(f, "add_of{width}"),
            Self::SubOverflow { width } => write!(f, "sub_of{width}"),
            Self::BorrowOut { width } => write!(f, "borrow{width}"),
            Self::AuxiliaryCarry => write!(f, "af_carry"),
            Self::Expr(e) => write!(f, "{e}"),
        }
    }
}

impl FlagExpr {
    /// Convert to an [`IrExpr`] for embedding into the IL stream.
    #[must_use] 
    pub fn to_ir_expr(&self, result_reg: &str) -> IrExpr {
        match self {
            Self::Const(v) => IrExpr::Const(u64::from(*v)),
            Self::Undefined | Self::Preserved | Self::AddOverflow { .. } | Self::SubOverflow { .. } | Self::BorrowOut { .. } | Self::AuxiliaryCarry => IrExpr::Undef,
            Self::ResultEqualsZero => {
                IrExpr::CmpEqZero(Box::new(IrExpr::Reg(result_reg.to_string())))
            }
            Self::ResultSignBit { width } => {
                IrExpr::Shr(
                    Box::new(IrExpr::Reg(result_reg.to_string())),
                    Box::new(IrExpr::Const(u64::from(*width) - 1)),
                )
            }
            Self::ResultParity => {
                IrExpr::Parity(Box::new(IrExpr::Reg(result_reg.to_string())))
            }
            Self::CarryOut { bit_pos } => {
                IrExpr::Shr(
                    Box::new(IrExpr::Reg(result_reg.to_string())),
                    Box::new(IrExpr::Const(u64::from(*bit_pos))),
                )
            }
            Self::Expr(e) => e.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlagUpdate
// ─────────────────────────────────────────────────────────────────────────────

/// The complete set of flag side-effects for a single instruction.
#[derive(Debug, Clone)]
pub struct FlagUpdate {
    /// The mnemonic this update was derived from.
    pub mnemonic: String,
    /// The destination register whose value is used as `result` in expressions.
    pub result_reg: String,
    /// Operand width in bits.
    pub width: u8,
    /// Per-flag expressions.
    pub flags: HashMap<FlagId, FlagExpr>,
}

impl FlagUpdate {
    pub fn new(mnemonic: impl Into<String>, result_reg: impl Into<String>, width: u8) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            result_reg: result_reg.into(),
            width,
            flags: HashMap::new(),
        }
    }

    #[must_use] 
    pub fn set(mut self, flag: FlagId, expr: FlagExpr) -> Self {
        self.flags.insert(flag, expr);
        self
    }

    /// Convert the update to a list of [`Effect::RegWrite`] entries for each
    /// affected flag.
    #[must_use] 
    pub fn to_effects(&self) -> Vec<Effect> {
        let mut out = Vec::with_capacity(self.flags.len());
        for (flag, expr) in &self.flags {
            if matches!(expr, FlagExpr::Preserved) {
                continue;
            }
            out.push(Effect::RegWrite {
                reg: flag.name().to_string(),
                value: expr.to_ir_expr(&self.result_reg),
            });
        }
        out
    }

    /// Returns `true` if this update modifies at least one flag.
    #[must_use] 
    pub fn modifies_any_flag(&self) -> bool {
        self.flags.values().any(|e| !matches!(e, FlagExpr::Preserved))
    }

    /// The set of flags that this update explicitly modifies.
    #[must_use] 
    pub fn modified_flags(&self) -> Vec<FlagId> {
        self.flags
            .iter()
            .filter(|(_, e)| !matches!(e, FlagExpr::Preserved | FlagExpr::Undefined))
            .map(|(f, _)| f.clone())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlagSemanticsLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Derives flag update specifications from instruction mnemonics.
///
/// The lifter encodes the x86 ISM flag semantics for the most common
/// instruction classes and falls back to `Undefined` for unknown instructions.
#[derive(Debug, Default)]
pub struct FlagSemanticsLifter {
    /// Custom overrides: mnemonic → `FlagUpdate` builder.
    overrides: HashMap<String, FlagUpdate>,
}

impl FlagSemanticsLifter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a custom [`FlagUpdate`] for a specific mnemonic.
    pub fn add_override(&mut self, update: FlagUpdate) {
        self.overrides.insert(update.mnemonic.clone(), update);
    }

    /// Derive a [`FlagUpdate`] from the given mnemonic, result register, and
    /// operand width.
    #[must_use] 
    pub fn derive(&self, mnemonic: &str, result_reg: &str, width: u8) -> FlagUpdate {
        // Check overrides first.
        if let Some(ov) = self.overrides.get(mnemonic) {
            return ov.clone();
        }
        Self::builtin(mnemonic, result_reg, width)
    }

    /// Built-in flag semantics for common x86 instructions.
    fn builtin(mnemonic: &str, result_reg: &str, width: u8) -> FlagUpdate {
        let m = mnemonic.to_ascii_lowercase();
        let base = FlagUpdate::new(&m, result_reg, width);
        match m.as_str() {
            // ADD / ADC
            "add" | "adc" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::CF, FlagExpr::CarryOut { bit_pos: width })
                .set(FlagId::OF, FlagExpr::AddOverflow { width })
                .set(FlagId::AF, FlagExpr::AuxiliaryCarry),

            // SUB / SBB / CMP
            "sub" | "sbb" | "cmp" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::CF, FlagExpr::BorrowOut { width })
                .set(FlagId::OF, FlagExpr::SubOverflow { width })
                .set(FlagId::AF, FlagExpr::AuxiliaryCarry),

            // AND / OR / XOR / TEST — OF and CF cleared
            "and" | "or" | "xor" | "test" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::CF, FlagExpr::Const(0))
                .set(FlagId::OF, FlagExpr::Const(0))
                .set(FlagId::AF, FlagExpr::Undefined),

            // INC / DEC — CF not affected
            "inc" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::OF, FlagExpr::AddOverflow { width })
                .set(FlagId::AF, FlagExpr::AuxiliaryCarry)
                .set(FlagId::CF, FlagExpr::Preserved),

            "dec" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::OF, FlagExpr::SubOverflow { width })
                .set(FlagId::AF, FlagExpr::AuxiliaryCarry)
                .set(FlagId::CF, FlagExpr::Preserved),

            // NEG
            "neg" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::CF, FlagExpr::Expr(IrExpr::Not(Box::new(
                    IrExpr::CmpEqZero(Box::new(IrExpr::Reg(result_reg.to_string()))),
                ))))
                .set(FlagId::OF, FlagExpr::SubOverflow { width })
                .set(FlagId::AF, FlagExpr::AuxiliaryCarry),

            // SHL / SHR / SAR / SAL
            "shl" | "sal" | "shr" | "sar" => base
                .set(FlagId::ZF, FlagExpr::ResultEqualsZero)
                .set(FlagId::SF, FlagExpr::ResultSignBit { width })
                .set(FlagId::PF, FlagExpr::ResultParity)
                .set(FlagId::CF, FlagExpr::Undefined)
                .set(FlagId::OF, FlagExpr::Undefined)
                .set(FlagId::AF, FlagExpr::Undefined),

            // IMUL / MUL
            "imul" | "mul" => base
                .set(FlagId::CF, FlagExpr::Undefined)
                .set(FlagId::OF, FlagExpr::Undefined)
                .set(FlagId::ZF, FlagExpr::Undefined)
                .set(FlagId::SF, FlagExpr::Undefined)
                .set(FlagId::PF, FlagExpr::Undefined)
                .set(FlagId::AF, FlagExpr::Undefined),

            // MOV / MOVZX / MOVSX / LEA / PUSH / POP — no flag changes
            "mov" | "movzx" | "movsx" | "movsxd" | "lea" | "push" | "pop" | "nop" => {
                FlagUpdate::new(&m, result_reg, width)
            }

            // CLC / STC — explicit CF manipulation
            "clc" => base.set(FlagId::CF, FlagExpr::Const(0)),
            "stc" => base.set(FlagId::CF, FlagExpr::Const(1)),
            "cmc" => base.set(FlagId::CF, FlagExpr::Expr(IrExpr::Not(Box::new(
                IrExpr::Reg("cf".to_string()),
            )))),

            // CLD / STD — DF manipulation
            "cld" => base.set(FlagId::DF, FlagExpr::Const(0)),
            "std" => base.set(FlagId::DF, FlagExpr::Const(1)),

            // SAHF LOADS the low flag byte FROM AH: it WRITES CF, PF, AF, ZF
            // and SF. It was grouped with the no-flag-change bucket below, so
            // the IL claimed `sahf` left the flags untouched — the classic
            // stale-definition defect: a write that is not modelled makes every
            // consumer believe the OLD value survives.
            //
            // (The two comments around this arm had drifted apart: one said
            // "LAHF / SAHF", the next said "RET / CALL / JMP — no flag
            // changes", while a single arm covered all six.)
            //
            // The bit positions are the architectural layout of the flags byte,
            // and `FlagExpr::Expr` can express them exactly with existing nodes.
            "sahf" => {
                let ah_bit = |n: u64| {
                    FlagExpr::Expr(IrExpr::And(
                        Box::new(IrExpr::Shr(
                            Box::new(IrExpr::Reg("ah".to_string())),
                            Box::new(IrExpr::Const(n)),
                        )),
                        Box::new(IrExpr::Const(1)),
                    ))
                };
                FlagUpdate::new(&m, result_reg, width)
                    .set(FlagId::CF, ah_bit(0))
                    .set(FlagId::PF, ah_bit(2))
                    .set(FlagId::AF, ah_bit(4))
                    .set(FlagId::ZF, ah_bit(6))
                    .set(FlagId::SF, ah_bit(7))
            }

            // LAHF reads the flags into AH and changes none of them; RET / CALL
            // / JMP touch no flags either.
            "lahf" | "ret" | "retn" | "call" | "jmp" => FlagUpdate::new(&m, result_reg, width),

            // Unknown — all flags undefined.
            _ => {
                let mut fu = FlagUpdate::new(&m, result_reg, width);
                for flag in &[
                    FlagId::CF, FlagId::OF, FlagId::SF,
                    FlagId::ZF, FlagId::PF, FlagId::AF,
                ] {
                    fu.flags.insert(flag.clone(), FlagExpr::Undefined);
                }
                fu
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// lift_flags_for_insn
// ─────────────────────────────────────────────────────────────────────────────

/// Primary entry point: derive flag semantics for a [`LiftedInstr`] and
/// return the corresponding [`FlagUpdate`].
///
/// The result register is taken from the first `RegWrite` effect in `instr`
/// or defaults to `"rax"`.
#[must_use] 
pub fn lift_flags_for_insn(
    lifter: &FlagSemanticsLifter,
    instr: &LiftedInstr,
    width: u8,
) -> FlagUpdate {
    let result_reg = instr
        .effects
        .iter()
        .find_map(|e| {
            if let Effect::RegWrite { reg, .. } = e {
                Some(reg.as_str())
            } else {
                None
            }
        })
        .unwrap_or("rax");

    lifter.derive(&instr.original_mnemonic, result_reg, width)
}

/// Augment a [`LiftedInstr`] with additional [`Effect::RegWrite`] entries for
/// every flag that the instruction modifies.
pub fn inject_flag_effects(instr: &mut LiftedInstr, update: &FlagUpdate) {
    for effect in update.to_effects() {
        instr.effects.push(effect);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LiftLevel};

    fn dummy_instr(mnemonic: &str, effects: Vec<Effect>) -> LiftedInstr {
        LiftedInstr {
            address: 0x1000,
            original_mnemonic: mnemonic.to_string(),
            ir_text: mnemonic.to_string(),
            il_level: LiftLevel::Llil,
            effects,
        }
    }

    #[test]
    fn add_sets_zf_sf_pf_cf_of_af() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("add", "rax", 64);
        assert!(update.flags.contains_key(&FlagId::ZF));
        assert!(update.flags.contains_key(&FlagId::SF));
        assert!(update.flags.contains_key(&FlagId::PF));
        assert!(update.flags.contains_key(&FlagId::CF));
        assert!(update.flags.contains_key(&FlagId::OF));
        assert!(update.flags.contains_key(&FlagId::AF));
    }

    #[test]
    fn mov_has_no_flag_effects() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("mov", "rax", 64);
        assert!(!update.modifies_any_flag());
    }

    #[test]
    fn and_clears_cf_and_of() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("and", "rax", 32);
        assert_eq!(update.flags[&FlagId::CF], FlagExpr::Const(0));
        assert_eq!(update.flags[&FlagId::OF], FlagExpr::Const(0));
    }

    #[test]
    fn inc_preserves_cf() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("inc", "eax", 32);
        assert_eq!(update.flags[&FlagId::CF], FlagExpr::Preserved);
    }

    #[test]
    fn to_effects_excludes_preserved() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("inc", "eax", 32);
        let effects = update.to_effects();
        // CF is preserved so should not appear in effects.
        assert!(!effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, .. } if reg == "cf")
        }));
    }

    #[test]
    fn clc_sets_cf_to_zero() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("clc", "rflags", 64);
        assert_eq!(update.flags[&FlagId::CF], FlagExpr::Const(0));
    }

    #[test]
    fn stc_sets_cf_to_one() {
        let lifter = FlagSemanticsLifter::new();
        let update = lifter.derive("stc", "rflags", 64);
        assert_eq!(update.flags[&FlagId::CF], FlagExpr::Const(1));
    }

    #[test]
    fn custom_override_takes_precedence() {
        let mut lifter = FlagSemanticsLifter::new();
        let custom = FlagUpdate::new("add", "rax", 64)
            .set(FlagId::ZF, FlagExpr::Const(0));
        lifter.add_override(custom);
        let update = lifter.derive("add", "rax", 64);
        assert_eq!(update.flags[&FlagId::ZF], FlagExpr::Const(0));
    }

    #[test]
    fn lift_flags_for_insn_uses_result_reg() {
        let lifter = FlagSemanticsLifter::new();
        let instr = dummy_instr("add", vec![
            Effect::RegWrite {
                reg: "rbx".to_string(),
                value: IrExpr::Const(0),
            }
        ]);
        let update = lift_flags_for_insn(&lifter, &instr, 64);
        assert_eq!(update.result_reg, "rbx");
    }

    #[test]
    fn inject_flag_effects_adds_writes() {
        let lifter = FlagSemanticsLifter::new();
        let mut instr = dummy_instr("add", vec![]);
        let update = lifter.derive("add", "rax", 64);
        inject_flag_effects(&mut instr, &update);
        let regs: Vec<_> = instr.effects.iter().filter_map(|e| {
            if let Effect::RegWrite { reg, .. } = e { Some(reg.as_str()) } else { None }
        }).collect();
        assert!(regs.contains(&"zf"));
    }

    #[test]
    fn flag_id_round_trip() {
        let id = FlagId::parse("of");
        assert_eq!(id, FlagId::OF);
        assert_eq!(id.name(), "of");
    }

    #[test]
    fn result_equals_zero_expr() {
        let expr = FlagExpr::ResultEqualsZero.to_ir_expr("rax");
        assert!(matches!(expr, IrExpr::CmpEqZero(_)));
    }
}
