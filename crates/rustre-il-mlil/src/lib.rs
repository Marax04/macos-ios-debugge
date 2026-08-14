//! `rustre-il-mlil`
//!
//! Medium-Level Intermediate Language (MLIL) in Static Single Assignment (SSA) form.
//!
//! MLIL is the SSA-form of LLIL. It replaces registers and temporaries with SSA
//! variables (name + version), inserts PHI nodes at dominance-frontier join points,
//! and enables precise data-flow analysis across a function's control-flow graph.

pub mod calling_convention_db;
pub mod mlil_verification;
pub mod phi_placement;
pub mod mlil_analysis;
pub mod mlil_call_analysis;
pub mod mlil_optimizer;
pub mod mlil_ssa;
pub mod ssa_reconstruction;
pub mod type_recovery_mlil;
pub mod mlil_ssa_builder;
pub mod mlil_alias_analysis;
pub mod mlil_dead_store_eliminator;

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use rustre_core::address::Address;
use rustre_il_llil::{LlilExpr, LlilInstruction};
use std::fmt;

// Re-export Size from LLIL so callers can refer to `rustre_il_mlil::Size`.
pub use rustre_il_llil::Size;

// ─── SsaVar ───────────────────────────────────────────────────────────────────

/// An SSA variable: a (name, version) pair.
///
/// Each definition of a source-level register or temporary gets a unique version
/// number, so every variable is defined exactly once in SSA form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

impl SsaVar {
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }

    /// Creates an SSA variable at version 0 (the initial / pre-function value).
    pub fn initial(name: impl Into<String>) -> Self {
        Self::new(name, 0)
    }

    /// Returns a copy of this variable incremented to `version + 1`.
    #[must_use]
    pub fn next_version(&self) -> Self {
        Self {
            name: self.name.clone(),
            version: self.version.saturating_add(1),
        }
    }
}

impl fmt::Display for SsaVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.version)
    }
}

// ─── MlilExpr ────────────────────────────────────────────────────────────────

/// An expression node in MLIL. All registers and temporaries are replaced by
/// [`SsaVar`] references. Every variant carries a [`Size`] annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlilExpr {
    Const {
        value: u64,
        size: Size,
    },
    Var {
        var: SsaVar,
        size: Size,
    },
    Load {
        addr: Box<Self>,
        size: Size,
    },
    Add(Box<Self>, Box<Self>, Size),
    Sub(Box<Self>, Box<Self>, Size),
    Mul(Box<Self>, Box<Self>, Size),
    DivU(Box<Self>, Box<Self>, Size),
    DivS(Box<Self>, Box<Self>, Size),
    And(Box<Self>, Box<Self>, Size),
    Or(Box<Self>, Box<Self>, Size),
    Xor(Box<Self>, Box<Self>, Size),
    Shl(Box<Self>, Box<Self>, Size),
    Shr(Box<Self>, Box<Self>, Size),
    Sar(Box<Self>, Box<Self>, Size),
    Neg(Box<Self>, Size),
    Not(Box<Self>, Size),
    ZeroExtend {
        expr: Box<Self>,
        from: Size,
        to: Size,
    },
    SignExtend {
        expr: Box<Self>,
        from: Size,
        to: Size,
    },
    CmpEq(Box<Self>, Box<Self>),
    CmpNe(Box<Self>, Box<Self>),
    CmpSlt(Box<Self>, Box<Self>),
    CmpUlt(Box<Self>, Box<Self>),
    CmpSle(Box<Self>, Box<Self>),
    CmpUle(Box<Self>, Box<Self>),
    FAdd(Box<Self>, Box<Self>, Size),
    FSub(Box<Self>, Box<Self>, Size),
    FMul(Box<Self>, Box<Self>, Size),
    FDiv(Box<Self>, Box<Self>, Size),
    FNeg(Box<Self>, Size),
    IntToFloat {
        expr: Box<Self>,
        to: Size,
    },
    FloatToInt {
        expr: Box<Self>,
        to: Size,
    },
    Select {
        cond: Box<Self>,
        true_val: Box<Self>,
        false_val: Box<Self>,
        size: Size,
    },
    Undefined(Size),
    StackPointer(Size),
    Flag {
        name: String,
    },
    Call {
        dest: Box<Self>,
        args: Vec<Self>,
        return_size: Size,
    },
}

impl MlilExpr {
    /// Returns the result size of this expression.
    #[must_use]
    pub const fn result_size(&self) -> Size {
        match self {
            Self::Const { size, .. }
            | Self::Var { size, .. }
            | Self::Load { size, .. } => *size,
            Self::Add(_, _, s)
            | Self::Sub(_, _, s)
            | Self::Mul(_, _, s)
            | Self::DivU(_, _, s)
            | Self::DivS(_, _, s)
            | Self::And(_, _, s)
            | Self::Or(_, _, s)
            | Self::Xor(_, _, s)
            | Self::Shl(_, _, s)
            | Self::Shr(_, _, s)
            | Self::Sar(_, _, s)
            | Self::Neg(_, s)
            | Self::Not(_, s)
            | Self::FAdd(_, _, s)
            | Self::FSub(_, _, s)
            | Self::FMul(_, _, s)
            | Self::FDiv(_, _, s)
            | Self::FNeg(_, s)
            | Self::Undefined(s)
            | Self::StackPointer(s) => *s,
            Self::IntToFloat { to, .. }
            | Self::FloatToInt { to, .. }
            | Self::Select { size: to, .. } => *to,
            Self::ZeroExtend { to, .. } | Self::SignExtend { to, .. } => *to,
            Self::CmpEq(..)
            | Self::CmpNe(..)
            | Self::CmpSlt(..)
            | Self::CmpUlt(..)
            | Self::CmpSle(..)
            | Self::CmpUle(..)
            | Self::Flag { .. } => Size::Byte,
            Self::Call { return_size, .. } => *return_size,
        }
    }

    /// If this expression is a constant, returns its value.
    #[must_use]
    pub const fn is_const(&self) -> Option<u64> {
        match self {
            Self::Const { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Returns `true` if this expression (or any sub-expression) references `var`.
    #[must_use]
    pub fn uses_var(&self, var: &SsaVar) -> bool {
        match self {
            Self::Var { var: v, .. } => v == var,
            Self::Const { .. }
            | Self::Undefined(_)
            | Self::StackPointer(_)
            | Self::Flag { .. } => false,
            Self::Load { addr, .. } => addr.uses_var(var),
            Self::Neg(e, _) | Self::Not(e, _) | Self::FNeg(e, _) => e.uses_var(var),
            Self::ZeroExtend { expr, .. }
            | Self::SignExtend { expr, .. }
            | Self::IntToFloat { expr, .. }
            | Self::FloatToInt { expr, .. } => expr.uses_var(var),
            Self::Select { cond, true_val, false_val, .. } => {
                cond.uses_var(var) || true_val.uses_var(var) || false_val.uses_var(var)
            }
            Self::Add(l, r, _)
            | Self::Sub(l, r, _)
            | Self::Mul(l, r, _)
            | Self::DivU(l, r, _)
            | Self::DivS(l, r, _)
            | Self::And(l, r, _)
            | Self::Or(l, r, _)
            | Self::Xor(l, r, _)
            | Self::Shl(l, r, _)
            | Self::Shr(l, r, _)
            | Self::Sar(l, r, _)
            | Self::FAdd(l, r, _)
            | Self::FSub(l, r, _)
            | Self::FMul(l, r, _)
            | Self::FDiv(l, r, _)
            | Self::CmpEq(l, r)
            | Self::CmpNe(l, r)
            | Self::CmpSlt(l, r)
            | Self::CmpUlt(l, r)
            | Self::CmpSle(l, r)
            | Self::CmpUle(l, r) => l.uses_var(var) || r.uses_var(var),
            Self::Call { dest, args, .. } => {
                dest.uses_var(var) || args.iter().any(|a| a.uses_var(var))
            }
        }
    }
}

impl fmt::Display for MlilExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const { value, .. } => write!(f, "0x{value:x}"),
            Self::Var { var, .. } => write!(f, "{var}"),
            Self::Load { addr, size } => write!(f, "[{addr}].{size}"),
            Self::Add(l, r, _) => write!(f, "({l} + {r})"),
            Self::Sub(l, r, _) => write!(f, "({l} - {r})"),
            Self::Mul(l, r, _) => write!(f, "({l} * {r})"),
            Self::DivU(l, r, _) => write!(f, "({l} /u {r})"),
            Self::DivS(l, r, _) => write!(f, "({l} /s {r})"),
            Self::And(l, r, _) => write!(f, "({l} & {r})"),
            Self::Or(l, r, _) => write!(f, "({l} | {r})"),
            Self::Xor(l, r, _) => write!(f, "({l} ^ {r})"),
            Self::Shl(l, r, _) => write!(f, "({l} << {r})"),
            Self::Shr(l, r, _) => write!(f, "({l} >> {r})"),
            Self::Sar(l, r, _) => write!(f, "({l} sar {r})"),
            Self::Neg(e, _) => write!(f, "(-{e})"),
            Self::Not(e, _) => write!(f, "(!{e})"),
            Self::ZeroExtend { expr, from, to } => write!(f, "zext({expr}, {from}->{to})"),
            Self::SignExtend { expr, from, to } => write!(f, "sext({expr}, {from}->{to})"),
            Self::CmpEq(l, r) => write!(f, "({l} == {r})"),
            Self::CmpNe(l, r) => write!(f, "({l} != {r})"),
            Self::CmpSlt(l, r) => write!(f, "({l} s< {r})"),
            Self::CmpUlt(l, r) => write!(f, "({l} u< {r})"),
            Self::CmpSle(l, r) => write!(f, "({l} s<= {r})"),
            Self::CmpUle(l, r) => write!(f, "({l} u<= {r})"),
            Self::FAdd(l, r, _) => write!(f, "({l} f+ {r})"),
            Self::FSub(l, r, _) => write!(f, "({l} f- {r})"),
            Self::FMul(l, r, _) => write!(f, "({l} f* {r})"),
            Self::FDiv(l, r, _) => write!(f, "({l} f/ {r})"),
            Self::FNeg(e, _) => write!(f, "(f-{e})"),
            Self::IntToFloat { expr, to } => write!(f, "int_to_float({expr}, {to})"),
            Self::FloatToInt { expr, to } => write!(f, "float_to_int({expr}, {to})"),
            Self::Select { cond, true_val, false_val, .. } => {
                write!(f, "select({cond}, {true_val}, {false_val})")
            }
            Self::Undefined(s) => write!(f, "undef.{s}"),
            Self::StackPointer(s) => write!(f, "sp.{s}"),
            Self::Flag { name } => write!(f, "flag:{name}"),
            Self::Call { dest, args, .. } => {
                write!(f, "call({dest}")?;
                for a in args {
                    write!(f, ", {a}")?;
                }
                write!(f, ")")
            }
        }
    }
}

// ─── MlilInstruction ─────────────────────────────────────────────────────────

/// A single MLIL instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlilInstruction {
    Nop,
    Assign {
        dest: SsaVar,
        size: Size,
        src: MlilExpr,
    },
    Store {
        addr: MlilExpr,
        size: Size,
        src: MlilExpr,
    },
    Jump {
        dest: MlilExpr,
    },
    /// Multi-way jump (switch / jump table): the computed `dest` expression
    /// selects one of `targets`. Preserves the FULL target list so the CFG
    /// keeps one successor edge per case — collapsing to `Jump(first)` would
    /// silently delete every other switch arm as dead code.
    JumpTable {
        dest: MlilExpr,
        targets: Vec<Address>,
    },
    CondJump {
        cond: MlilExpr,
        true_dest: Address,
        false_dest: Address,
    },
    Call {
        dest: MlilExpr,
        args: Vec<MlilExpr>,
        ret_vars: Vec<SsaVar>,
    },
    TailCall {
        dest: MlilExpr,
        args: Vec<MlilExpr>,
    },
    Ret {
        values: Vec<MlilExpr>,
    },
    /// SSA PHI node: `dest = φ(sources…)`.
    Phi {
        dest: SsaVar,
        sources: Vec<SsaVar>,
    },
    Trap {
        code: u64,
    },
    SysCall {
        args: Vec<MlilExpr>,
        ret_vars: Vec<SsaVar>,
    },
    Undefined,
}

/// Whether a call records the ABI return register in `ret_vars` (default ON).
///
/// MEASURED on the 12-binary corpus before promotion: locals read but never
/// written 2710/53363 -> 2291/54161, path A byte-identical, distinct call
/// targets 6583 -> 6585 (none lost), arity 122/135 unchanged, brace balance 0,
/// fixed-list recompilability 1199/1200 (same single failure as the baseline).
/// Set `RUSTRE_CALL_RET_VAR=0` to fall back to the old behaviour.
///
/// Two companion repairs were REQUIRED to reach that: `fold_loaded_fnptr_into_call`
/// (decompiler) keeps a loaded callee in call position so it is still named
/// `sub_X`, and the HLIL call lift types the return variable as a 64-bit int
/// instead of `Unknown` (which printed as the non-C word `unknown`).
fn call_ret_var_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !matches!(std::env::var("RUSTRE_CALL_RET_VAR").as_deref(), Ok("0") | Ok("false")))
}

impl MlilInstruction {
    /// Returns `true` if this instruction ends a basic block.
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        matches!(
            self,
            Self::Jump { .. }
                | Self::JumpTable { .. }
                | Self::CondJump { .. }
                | Self::Ret { .. }
                | Self::TailCall { .. }
                | Self::Trap { .. }
        )
    }

    /// Returns `true` if this is a PHI node.
    #[must_use]
    pub const fn is_phi(&self) -> bool {
        matches!(self, Self::Phi { .. })
    }

    /// Returns the SSA variable defined by this instruction, if any.
    #[must_use]
    pub fn defined_var(&self) -> Option<&SsaVar> {
        match self {
            Self::Assign { dest, .. } | Self::Phi { dest, .. } => Some(dest),
            Self::Call { ret_vars, .. } | Self::SysCall { ret_vars, .. } => {
                ret_vars.first()
            }
            _ => None,
        }
    }

    /// Returns `true` if any operand expression references `v`.
    #[must_use]
    pub fn uses_var(&self, v: &SsaVar) -> bool {
        match self {
            Self::Nop | Self::Undefined | Self::Trap { .. } => {
                false
            }
            Self::Assign { src, .. } => src.uses_var(v),
            Self::Store { addr, src, .. } => addr.uses_var(v) || src.uses_var(v),
            Self::Jump { dest } | Self::JumpTable { dest, .. } => dest.uses_var(v),
            Self::CondJump { cond, .. } => cond.uses_var(v),
            Self::Call { dest, args, .. } | Self::TailCall { dest, args } => {
                dest.uses_var(v) || args.iter().any(|a| a.uses_var(v))
            }
            Self::Ret { values } => values.iter().any(|e| e.uses_var(v)),
            Self::Phi { sources, .. } => sources.contains(v),
            Self::SysCall { args, .. } => args.iter().any(|a| a.uses_var(v)),
        }
    }

    /// Lift an [`LlilInstruction`] to one or more pre-SSA MLIL instructions.
    ///
    /// Unlike [`Self::lift_llil`], this models the stack-pointer adjustment
    /// for `Push`/`Pop` (`sp = sp - size` before a push store, `sp = sp +
    /// size` after a pop load), so distinct stack slots get distinct `sp`
    /// SSA versions instead of all aliasing a bare `StackPointer` address.
    /// Prefer this entry point when lifting whole instruction streams.
    pub fn lift_llil_multi(instr: LlilInstruction) -> Vec<Self> {
        let sp_var = || SsaVar::initial("sp");
        let sp = || MlilExpr::Var {
            var: sp_var(),
            size: Size::QWord,
        };
        let size_const = |size: Size| MlilExpr::Const {
            value: size.bytes() as u64,
            size: Size::QWord,
        };
        match instr {
            LlilInstruction::Push { size, src } => vec![
                // sp = sp - size
                Self::Assign {
                    dest: sp_var(),
                    size: Size::QWord,
                    src: MlilExpr::Sub(
                        Box::new(sp()),
                        Box::new(size_const(size)),
                        Size::QWord,
                    ),
                },
                // [sp] = src
                Self::Store {
                    addr: sp(),
                    size,
                    src: lift_llil_expr(src),
                },
            ],
            LlilInstruction::Pop { dest, size } => vec![
                // dest = [sp]
                Self::Assign {
                    // ⚠ `dest` is an LlilRegister whose Display is ALREADY the
                    // register name: `format!("r{dest}")` yielded `rrbx` for `rbx`,
                    // a variable no push ever wrote. That broke the save/restore
                    // pairing — the push read `rbx`, the pop wrote `rrbx` — and is
                    // why the corpus carried 31998 `var_rr*` locals that are read
                    // and never written. (`r{id}` is right for `LlilExpr::Register`,
                    // where `id` is a NUMBER; the spelling was copied to a name.)
                    dest: SsaVar::initial(dest.name()),
                    size,
                    src: MlilExpr::Load {
                        addr: Box::new(sp()),
                        size,
                    },
                },
                // sp = sp + size
                Self::Assign {
                    dest: sp_var(),
                    size: Size::QWord,
                    src: MlilExpr::Add(
                        Box::new(sp()),
                        Box::new(size_const(size)),
                        Size::QWord,
                    ),
                },
            ],
            other => vec![Self::lift_llil(other)],
        }
    }

    /// Lift an [`LlilInstruction`] to a best-effort pre-SSA MLIL instruction.
    ///
    /// NOTE: `Push`/`Pop` here read/write at a bare `StackPointer` address
    /// with no stack-pointer adjustment, so all stack slots alias each
    /// other. Use [`Self::lift_llil_multi`] when that matters.
    pub fn lift_llil(instr: LlilInstruction) -> Self {
        match instr {
            LlilInstruction::Nop
            | LlilInstruction::Breakpoint
            | LlilInstruction::Undefined
            | LlilInstruction::Unimplemented { .. }
            | LlilInstruction::UnimplementedRaw { .. } => Self::Nop,

            // MLIL has a first-class SysCall — do NOT fold it into Nop:
            // syscalls carry side effects and register clobbers, and losing
            // them erases the crate's core analysis signal.
            LlilInstruction::SysCall => Self::SysCall {
                args: vec![],
                ret_vars: vec![],
            },

            // Best-effort single-instruction form: a hi:lo pair write can't
            // be represented as one Assign, so keep the LOW half (the half
            // virtually all consumers read, e.g. the mul result) rather than
            // dropping BOTH definitions to Nop. Use [`Self::lift_llil_multi`]
            // to get both halves as two Assigns.
            LlilInstruction::SetRegSplit { high: _, low, src } => {
                let lifted = lift_llil_expr(src);
                let full = lifted.result_size();
                let half = half_size(full);
                Self::Assign {
                    dest: SsaVar::initial(low.name()),
                    size: half,
                    src: MlilExpr::ZeroExtend {
                        expr: Box::new(lifted),
                        from: full,
                        to: half,
                    },
                }
            }

            LlilInstruction::SetFlag { name, src } => Self::Assign {
                dest: SsaVar::initial(format!("flag_{name}")),
                size: Size::Byte,
                src: lift_llil_expr(src),
            },
            LlilInstruction::Push { size, src } => Self::Store {
                addr: MlilExpr::StackPointer(size),
                size,
                src: lift_llil_expr(src),
            },
            LlilInstruction::Pop { dest, size } => Self::Assign {
                dest: SsaVar::initial(dest.name()),
                size,
                src: MlilExpr::Load {
                    addr: Box::new(MlilExpr::StackPointer(size)),
                    size,
                },
            },
            LlilInstruction::Trap { code } => Self::Trap { code },
            // Best-effort: conditionality is lost here (MLIL has no
            // conditional-call form); preserving the call target/effect is
            // still strictly better than silently dropping it to `Nop`.
            LlilInstruction::CondCall { dest, .. } => Self::Call {
                dest: lift_llil_expr(dest),
                args: vec![],
                ret_vars: vec![],
            },

            // `SetRegister` is the register-BY-ID variant (`dest: u32`), unlike
            // the sibling arms whose `dest` is a `Register` with a `.name()`.
            // Rendered as `r{id}` to match `LlilInstruction`'s own Display.
            LlilInstruction::SetRegister { dest, value, size } => Self::Assign {
                dest: SsaVar::initial(format!("r{dest}")),
                size,
                src: lift_llil_expr(value),
            },
            LlilInstruction::ConditionalJump {
                cond,
                true_target,
                false_target,
            } => Self::CondJump {
                cond: lift_llil_expr(cond),
                true_dest: true_target,
                false_dest: false_target,
            },

            LlilInstruction::SetReg { dest, value, .. } => Self::Assign {
                dest: SsaVar::initial(dest.name()),
                size: Size::QWord,
                src: lift_llil_expr(value),
            },
            LlilInstruction::Load { dest, addr, size } => Self::Assign {
                dest: SsaVar::initial(dest.name()),
                size,
                src: MlilExpr::Load {
                    addr: Box::new(lift_llil_expr(addr)),
                    size,
                },
            },
            LlilInstruction::Store { addr, value, size } => Self::Store {
                addr: lift_llil_expr(addr),
                size,
                src: lift_llil_expr(value),
            },
            LlilInstruction::Jump(dest) | LlilInstruction::JumpDest { dest } => {
                if let LlilExpr::Const { .. } = &dest {
                    // Direct jump — use Jump with a Const expr.
                    Self::Jump {
                        dest: lift_llil_expr(dest),
                    }
                } else {
                    Self::Jump {
                        dest: lift_llil_expr(dest),
                    }
                }
            }
            LlilInstruction::JumpTo { dest, targets } => {
                if targets.is_empty() {
                    Self::Jump {
                        dest: lift_llil_expr(dest),
                    }
                } else {
                    // Preserve the full jump-table edge set — collapsing to the
                    // first target erases every switch case but case 0.
                    Self::JumpTable {
                        dest: lift_llil_expr(dest),
                        targets,
                    }
                }
            }
            LlilInstruction::Call(dest) | LlilInstruction::CallDest { dest } => {
                // A call DEFINES the ABI return register. Leaving `ret_vars`
                // empty made the HLIL lifter emit the call as a bare statement
                // (`sub_X();`) while the following read of `rax` stayed orphaned,
                // so the value showed up as a local that is read and never
                // written. Verified against the disassembly: in
                // `sample10_cs/sub_140003350` the body is `call 0x14004E8B0` +
                // `test %eax,%eax`, emitted as `sub_14004E8B0();` followed by
                // `if ((uint32_t)v2 != 0)` with `v2` undefined. Measured: 776 of
                // B's 2079 defective `vN` (37%) have a call right before the
                // first read.
                //
                // ⚠ These are NOT missing parameters. Promoting them to
                // parameters — the shape the "read before written" heuristic
                // suggests — would invent PHANTOM arguments that compile clean
                // and are silently wrong, and the arity oracle cannot see it
                // because these functions are absent from `prototypes.json`.
                // Recording the return register is the faithful fix: the call
                // really does define it.
                Self::Call {
                    dest: lift_llil_expr(dest),
                    args: vec![],
                    ret_vars: if call_ret_var_enabled() {
                        vec![SsaVar::initial("rax")]
                    } else {
                        vec![]
                    },
                }
            }
            LlilInstruction::TailCall { dest } => Self::TailCall {
                dest: lift_llil_expr(dest),
                args: vec![],
            },
            LlilInstruction::Ret => Self::Ret { values: vec![] },
            LlilInstruction::CondJump {
                cond,
                true_dest,
                false_dest,
            } => Self::CondJump {
                cond: lift_llil_expr(cond),
                true_dest,
                false_dest,
            },
            LlilInstruction::Intrinsic { name, args } => Self::Call {
                dest: MlilExpr::Var {
                    var: SsaVar::initial(name),
                    size: Size::QWord,
                },
                args: args.into_iter().map(lift_llil_expr).collect(),
                ret_vars: vec![],
            },
            LlilInstruction::Return { value } => Self::Ret {
                values: value.into_iter().map(lift_llil_expr).collect(),
            },
        }
    }
}

impl fmt::Display for MlilInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nop => write!(f, "nop"),
            Self::Assign { dest, size, src } => {
                write!(f, "{dest}.{size} = {src}")
            }
            Self::Store { addr, size, src } => {
                write!(f, "[{addr}].{size} = {src}")
            }
            Self::Jump { dest } => write!(f, "jump {dest}"),
            Self::JumpTable { dest, targets } => {
                let tgts: Vec<String> = targets.iter().map(ToString::to_string).collect();
                write!(f, "jump {dest} [{}]", tgts.join(", "))
            }
            Self::CondJump {
                cond,
                true_dest,
                false_dest,
            } => {
                write!(f, "if ({cond}) goto {true_dest} else goto {false_dest}")
            }
            Self::Call {
                dest,
                args,
                ret_vars,
            } => {
                let rets: Vec<String> = ret_vars.iter().map(ToString::to_string).collect();
                let arg_strs: Vec<String> = args.iter().map(ToString::to_string).collect();
                if rets.is_empty() {
                    write!(f, "call {dest}({})", arg_strs.join(", "))
                } else {
                    write!(
                        f,
                        "{} = call {dest}({})",
                        rets.join(", "),
                        arg_strs.join(", ")
                    )
                }
            }
            Self::TailCall { dest, args } => {
                let arg_strs: Vec<String> = args.iter().map(ToString::to_string).collect();
                write!(f, "tailcall {dest}({})", arg_strs.join(", "))
            }
            Self::Ret { values } => {
                let val_strs: Vec<String> = values.iter().map(ToString::to_string).collect();
                write!(f, "return {}", val_strs.join(", "))
            }
            Self::Phi { dest, sources } => {
                let src_strs: Vec<String> = sources.iter().map(ToString::to_string).collect();
                write!(f, "{dest} = φ({})", src_strs.join(", "))
            }
            Self::Trap { code } => write!(f, "trap 0x{code:x}"),
            Self::SysCall { args, ret_vars } => {
                let rets: Vec<String> = ret_vars.iter().map(ToString::to_string).collect();
                let arg_strs: Vec<String> = args.iter().map(ToString::to_string).collect();
                if rets.is_empty() {
                    write!(f, "syscall({})", arg_strs.join(", "))
                } else {
                    write!(f, "{} = syscall({})", rets.join(", "), arg_strs.join(", "))
                }
            }
            Self::Undefined => write!(f, "undefined"),
        }
    }
}

// ─── MlilAnnotatedInstr ──────────────────────────────────────────────────────

/// An MLIL instruction annotated with the address it was lifted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlilAnnotatedInstr {
    pub address: Address,
    pub instr: MlilInstruction,
}

// ─── MlilBasicBlock ──────────────────────────────────────────────────────────

/// A basic block in the MLIL CFG.
///
/// PHI nodes, if any, always appear first; the block's terminator is last.
#[derive(Debug, Clone)]
pub struct MlilBasicBlock {
    pub id: u32,
    pub start: Address,
    pub end: Address,
    pub instrs: Vec<MlilAnnotatedInstr>,
    pub predecessors: Vec<u32>,
    pub successors: Vec<u32>,
}

impl MlilBasicBlock {
    /// Iterates over only the PHI instructions in this block.
    pub fn phis(&self) -> impl Iterator<Item = &MlilAnnotatedInstr> {
        self.instrs.iter().take_while(|ai| ai.instr.is_phi())
    }

    /// Iterates over all non-PHI instructions in this block.
    pub fn non_phi_instrs(&self) -> impl Iterator<Item = &MlilAnnotatedInstr> {
        self.instrs.iter().skip_while(|ai| ai.instr.is_phi())
    }

    /// Returns the terminator instruction of this block, if it has one.
    #[must_use]
    pub fn terminator(&self) -> Option<&MlilAnnotatedInstr> {
        self.instrs.last().filter(|ai| ai.instr.is_terminator())
    }

    /// Collects all SSA variables *defined* in this block.
    #[must_use]
    pub fn defined_vars(&self) -> Vec<&SsaVar> {
        self.instrs
            .iter()
            .filter_map(|ai| ai.instr.defined_var())
            .collect()
    }

    /// Collects all SSA variables *used* in this block.
    #[must_use]
    pub fn used_vars(&self) -> Vec<SsaVar> {
        let mut used = Vec::new();
        for ai in &self.instrs {
            collect_used_vars_in_instr(&ai.instr, &mut used);
        }
        used
    }
}

fn collect_used_vars_in_instr(instr: &MlilInstruction, out: &mut Vec<SsaVar>) {
    match instr {
        MlilInstruction::Nop | MlilInstruction::Undefined | MlilInstruction::Trap { .. } => {}
        MlilInstruction::Assign { src, .. } => collect_used_vars_in_expr(src, out),
        MlilInstruction::Store { addr, src, .. } => {
            collect_used_vars_in_expr(addr, out);
            collect_used_vars_in_expr(src, out);
        }
        MlilInstruction::Jump { dest } | MlilInstruction::JumpTable { dest, .. } => {
            collect_used_vars_in_expr(dest, out);
        }
        MlilInstruction::CondJump { cond, .. } => collect_used_vars_in_expr(cond, out),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            collect_used_vars_in_expr(dest, out);
            for a in args {
                collect_used_vars_in_expr(a, out);
            }
        }
        MlilInstruction::Ret { values } => {
            for v in values {
                collect_used_vars_in_expr(v, out);
            }
        }
        MlilInstruction::Phi { sources, .. } => {
            out.extend(sources.iter().cloned());
        }
        MlilInstruction::SysCall { args, .. } => {
            for a in args {
                collect_used_vars_in_expr(a, out);
            }
        }
    }
}

fn collect_used_vars_in_expr(expr: &MlilExpr, out: &mut Vec<SsaVar>) {
    match expr {
        MlilExpr::Var { var, .. } => out.push(var.clone()),
        MlilExpr::Const { .. }
        | MlilExpr::Undefined(_)
        | MlilExpr::StackPointer(_)
        | MlilExpr::Flag { .. } => {}
        MlilExpr::Load { addr, .. } => collect_used_vars_in_expr(addr, out),
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) | MlilExpr::FNeg(e, _) => collect_used_vars_in_expr(e, out),
        MlilExpr::ZeroExtend { expr, .. }
        | MlilExpr::SignExtend { expr, .. }
        | MlilExpr::IntToFloat { expr, .. }
        | MlilExpr::FloatToInt { expr, .. } => {
            collect_used_vars_in_expr(expr, out);
        }
        MlilExpr::Select { cond, true_val, false_val, .. } => {
            collect_used_vars_in_expr(cond, out);
            collect_used_vars_in_expr(true_val, out);
            collect_used_vars_in_expr(false_val, out);
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => {
            collect_used_vars_in_expr(l, out);
            collect_used_vars_in_expr(r, out);
        }
        MlilExpr::Call { dest, args, .. } => {
            collect_used_vars_in_expr(dest, out);
            for a in args {
                collect_used_vars_in_expr(a, out);
            }
        }
    }
}

// ─── MlilFunction ────────────────────────────────────────────────────────────

/// A function in MLIL/SSA form.
#[derive(Debug, Clone)]
pub struct MlilFunction {
    pub entry: Address,
    pub blocks: Vec<MlilBasicBlock>,
    pub var_versions: HashMap<String, u32>,
}

impl MlilFunction {
    #[must_use]
    pub fn new(entry: Address) -> Self {
        Self {
            entry,
            blocks: Vec::new(),
            var_versions: HashMap::new(),
        }
    }

    #[must_use]
    pub fn block_by_id(&self, id: u32) -> Option<&MlilBasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    #[must_use]
    pub fn block_at(&self, addr: Address) -> Option<&MlilBasicBlock> {
        self.blocks
            .iter()
            .find(|b| addr.as_u64() >= b.start.as_u64() && addr.as_u64() < b.end.as_u64())
    }

    /// Iterates over every annotated instruction in program order.
    pub fn all_instrs(&self) -> impl Iterator<Item = &MlilAnnotatedInstr> {
        self.blocks.iter().flat_map(|b| b.instrs.iter())
    }

    /// Finds the unique definition site of `var`, if it exists.
    #[must_use]
    pub fn find_def(&self, var: &SsaVar) -> Option<&MlilAnnotatedInstr> {
        self.all_instrs()
            .find(|ai| ai.instr.defined_var() == Some(var))
    }

    /// Returns all instruction sites that use `var`.
    #[must_use]
    pub fn find_uses(&self, var: &SsaVar) -> Vec<&MlilAnnotatedInstr> {
        self.all_instrs()
            .filter(|ai| ai.instr.uses_var(var))
            .collect()
    }

    /// Returns all SSA variables defined anywhere in the function.
    #[must_use]
    pub fn all_vars(&self) -> Vec<SsaVar> {
        self.all_instrs()
            .filter_map(|ai| ai.instr.defined_var())
            .cloned()
            .collect()
    }
}

// ─── rustre-il-lift integration ──────────────────────────────────────────────
//
// `MlilPassLifter` adapts a generic `rustre_il_lift::LiftedInstr` (which
// carries architecture-independent `Effect`s) into a sequence of pre-SSA
// `MlilInstruction`s.  This is the centralised bridge the `rustre-il-lift`
// crate was designed for, replacing ad-hoc manual translation at each call
// site.

use rustre_il_lift::{ArchLifter, Effect, IrExpr, LiftError, LiftedInstr, LiftLevel};
use rustre_core::arch::Instruction;

/// Converts a `rustre_il_lift::IrExpr` into an `MlilExpr`.
fn ir_expr_to_mlil(expr: &IrExpr) -> MlilExpr {
    match expr {
        IrExpr::Const(v) => MlilExpr::Const { value: *v, size: Size::QWord },
        IrExpr::Reg(name) => MlilExpr::Var { var: SsaVar::initial(name.clone()), size: Size::QWord },
        IrExpr::Add(l, r) => MlilExpr::Add(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Sub(l, r) => MlilExpr::Sub(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Mul(l, r) => MlilExpr::Mul(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Or(l, r)  => MlilExpr::Or(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::And(l, r) => MlilExpr::And(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Xor(l, r) => MlilExpr::Xor(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Shl(l, r) => MlilExpr::Shl(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Shr(l, r) => MlilExpr::Shr(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        // `Sar` e' lo shift ARITMETICO: propaga il segno, quindi NON `Shr`.
        IrExpr::Sar(l, r) => MlilExpr::Sar(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)), Size::QWord),
        IrExpr::Not(e)    => MlilExpr::Not(Box::new(ir_expr_to_mlil(e)), Size::QWord),
        IrExpr::Deref(e, sz) => MlilExpr::Load {
            addr: Box::new(ir_expr_to_mlil(e)),
            size: Size::try_from(*sz as usize).unwrap_or(Size::QWord),
        },
        IrExpr::CmpEqZero(e) => MlilExpr::CmpEq(
            Box::new(ir_expr_to_mlil(e)),
            Box::new(MlilExpr::Const { value: 0, size: Size::QWord }),
        ),
        IrExpr::Parity(e) => MlilExpr::Not(Box::new(ir_expr_to_mlil(e)), Size::Byte),
        IrExpr::Undef => MlilExpr::Undefined(Size::QWord),
        IrExpr::CmpEq(l, r) | IrExpr::Eq(l, r) => {
            MlilExpr::CmpEq(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r)))
        }
        IrExpr::Ne(l, r) => MlilExpr::CmpNe(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r))),
        IrExpr::CmpLt(l, r) => MlilExpr::CmpSlt(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r))),
        // `CmpLtU` e' SENZA SEGNO: qui `CmpLt` va su `CmpSlt` (con segno), quindi
        // la controparte non firmata e' `CmpUlt`. Confonderle sbaglia ogni
        // confronto con operandi che superano meta' dell'intervallo.
        IrExpr::CmpLtU(l, r) => MlilExpr::CmpUlt(Box::new(ir_expr_to_mlil(l)), Box::new(ir_expr_to_mlil(r))),
        IrExpr::CmpGt(l, r) => MlilExpr::CmpSlt(Box::new(ir_expr_to_mlil(r)), Box::new(ir_expr_to_mlil(l))),
        IrExpr::IfThenElse(cond, t, f) => {
            let lifted_t = ir_expr_to_mlil(t);
            let size = lifted_t.result_size();
            MlilExpr::Select {
                cond: Box::new(ir_expr_to_mlil(cond)),
                true_val: Box::new(lifted_t),
                false_val: Box::new(ir_expr_to_mlil(f)),
                size,
            }
        }
    }
}

/// Converts a slice of `rustre_il_lift::Effect`s to a list of `MlilInstruction`s.
#[must_use] 
pub fn effects_to_mlil(effects: &[Effect]) -> Vec<MlilInstruction> {
    effects.iter().map(|eff| match eff {
        Effect::RegWrite { reg, value } => MlilInstruction::Assign {
            dest: SsaVar::initial(reg.clone()),
            size: Size::QWord,
            src: ir_expr_to_mlil(value),
        },
        Effect::MemWrite { addr, value, size } => MlilInstruction::Store {
            addr: ir_expr_to_mlil(addr),
            size: Size::try_from(*size as usize).unwrap_or(Size::QWord),
            src: ir_expr_to_mlil(value),
        },
        Effect::MemRead { addr, dest, size } => MlilInstruction::Assign {
            dest: SsaVar::initial(dest.clone()),
            size: Size::try_from(*size as usize).unwrap_or(Size::QWord),
            src: MlilExpr::Load {
                addr: Box::new(ir_expr_to_mlil(addr)),
                size: Size::try_from(*size as usize).unwrap_or(Size::QWord),
            },
        },
        Effect::Call { target } => MlilInstruction::Call {
            dest: ir_expr_to_mlil(target),
            args: vec![],
            ret_vars: vec![],
        },
        Effect::Branch { target, condition: None } => MlilInstruction::Jump {
            dest: ir_expr_to_mlil(target),
        },
        Effect::Branch { target, condition: Some(cond) } => {
            // The true destination is encoded in the target expression when it
            // is a constant; otherwise fall back to a zero sentinel that a
            // later CFG-building pass must resolve.
            let true_addr = match target {
                IrExpr::Const(v) => Address::new(*v),
                _ => Address::new(0),
            };
            MlilInstruction::CondJump {
                cond: ir_expr_to_mlil(cond),
                true_dest: true_addr,
                false_dest: Address::new(0),
            }
        }
        Effect::Return { value } => MlilInstruction::Ret {
            values: value.as_ref().map_or_else(Vec::new, |v| vec![ir_expr_to_mlil(v)]),
        },
        Effect::Syscall { nr } => MlilInstruction::SysCall {
            args: vec![ir_expr_to_mlil(nr)],
            ret_vars: vec![],
        },
        Effect::Trap { vector } => MlilInstruction::Trap { code: u64::from(*vector) },
        Effect::ConditionalTrap { .. } | Effect::NoReturn | Effect::Intrinsic { .. } => MlilInstruction::Nop,
    }).collect()
}

/// An `ArchLifter` adapter that post-processes a `LiftedInstr` produced by an
/// architecture-specific lifter and converts its `Effect`s to `MlilInstruction`s.
///
/// This avoids duplicating effect-to-MLIL translation at every call site and
/// centralises the conversion in the crate that owns `MlilInstruction`.
#[derive(Debug)]
pub struct MlilPassLifter {
    inner: Box<dyn ArchLifter>,
}

impl MlilPassLifter {
    /// Wrap an existing `ArchLifter`.
    #[must_use] 
    pub fn new(inner: Box<dyn ArchLifter>) -> Self {
        Self { inner }
    }

    /// Lift a single instruction and convert its effects to `MlilInstruction`s.
    ///
    /// # Errors
    /// Propagates any error from the inner lifter.
    pub fn lift_to_mlil(&self, instr: &Instruction) -> Result<Vec<MlilInstruction>, LiftError> {
        let lifted = self.inner.lift(instr)?;
        Ok(effects_to_mlil(&lifted.effects))
    }
}

impl ArchLifter for MlilPassLifter {
    fn arch_name(&self) -> &str { self.inner.arch_name() }
    fn lift_level(&self) -> LiftLevel { LiftLevel::MlilSsa }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        self.inner.lift(instr)
    }

    fn description(&self) -> &'static str { "MLIL pass lifter — converts effects to MlilInstruction" }
}

// ─── LLIL-to-MLIL expression lifter ─────────────────────────────────────────

fn lift_llil_binop(
    l: LlilExpr,
    r: LlilExpr,
    s: Size,
    ctor: fn(Box<MlilExpr>, Box<MlilExpr>, Size) -> MlilExpr,
) -> MlilExpr {
    ctor(Box::new(lift_llil_expr(l)), Box::new(lift_llil_expr(r)), s)
}

/// The size of one half of a split register pair (`SetRegSplit` writes a
/// double-width value into `high:low`, each half being this size).
const fn half_size(full: Size) -> Size {
    match full {
        Size::Byte | Size::Word => Size::Byte,
        Size::DWord => Size::Word,
        Size::QWord => Size::DWord,
        Size::OWord => Size::QWord,
        Size::YWord => Size::OWord,
        Size::ZWord => Size::YWord,
    }
}

fn lift_llil_expr(expr: LlilExpr) -> MlilExpr {
    match expr {
        LlilExpr::Const { value, size } => MlilExpr::Const { value, size },
        LlilExpr::RegisterRef { reg, size } => MlilExpr::Var {
            var: SsaVar::initial(reg.name()),
            size,
        },
        LlilExpr::Register { id, size } => MlilExpr::Var {
            var: SsaVar::initial(format!("r{id}")),
            size,
        },
        LlilExpr::Load { addr, size } => MlilExpr::Load {
            addr: Box::new(lift_llil_expr(*addr)),
            size,
        },
        LlilExpr::AddT(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Add),
        LlilExpr::SubT(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Sub),
        LlilExpr::MulT(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Mul),
        LlilExpr::Add { left, right, size } => lift_llil_binop(*left, *right, size, MlilExpr::Add),
        LlilExpr::Sub { left, right, size } => lift_llil_binop(*left, *right, size, MlilExpr::Sub),
        LlilExpr::Mul { left, right, size } => lift_llil_binop(*left, *right, size, MlilExpr::Mul),
        LlilExpr::DivU(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::DivU),
        LlilExpr::DivS(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::DivS),
        LlilExpr::ModU(l, r, s) => {
            // l % r (unsigned) = l - (l /u r) * r
            let ll = lift_llil_expr(*l);
            let rr = lift_llil_expr(*r);
            let div = MlilExpr::DivU(Box::new(ll.clone()), Box::new(rr.clone()), s);
            let mul = MlilExpr::Mul(Box::new(div), Box::new(rr), s);
            MlilExpr::Sub(Box::new(ll), Box::new(mul), s)
        }
        LlilExpr::ModS(l, r, s) => {
            // l % r (signed) = l - (l /s r) * r — signed division is required
            // for negative operands (x86 idiv remainder takes the dividend's sign).
            let ll = lift_llil_expr(*l);
            let rr = lift_llil_expr(*r);
            let div = MlilExpr::DivS(Box::new(ll.clone()), Box::new(rr.clone()), s);
            let mul = MlilExpr::Mul(Box::new(div), Box::new(rr), s);
            MlilExpr::Sub(Box::new(ll), Box::new(mul), s)
        }
        LlilExpr::Neg(e, s) => MlilExpr::Neg(Box::new(lift_llil_expr(*e)), s),
        LlilExpr::And(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::And),
        LlilExpr::Or(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Or),
        LlilExpr::Xor(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Xor),
        LlilExpr::Not(e, s) => MlilExpr::Not(Box::new(lift_llil_expr(*e)), s),
        LlilExpr::ShlT(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Shl),
        LlilExpr::Shl { value, shift, size } => {
            lift_llil_binop(*value, *shift, size, MlilExpr::Shl)
        }
        LlilExpr::Shr(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Shr),
        LlilExpr::Sar(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::Sar),
        LlilExpr::Rol(l, amt, s) => {
            // Rol(x, n, s) = (x << n) | (x >> (s_bits - n))
            let lv = lift_llil_expr(*l);
            let av = lift_llil_expr(*amt);
            let bits = s.bits() as u64;
            let width_const = MlilExpr::Const { value: bits, size: s };
            let right_shift = MlilExpr::Sub(Box::new(width_const), Box::new(av.clone()), s);
            MlilExpr::Or(
                Box::new(MlilExpr::Shl(Box::new(lv.clone()), Box::new(av), s)),
                Box::new(MlilExpr::Shr(Box::new(lv), Box::new(right_shift), s)),
                s,
            )
        }
        LlilExpr::Ror(l, amt, s) => {
            // Ror(x, n, s) = (x >> n) | (x << (s_bits - n))
            let lv = lift_llil_expr(*l);
            let av = lift_llil_expr(*amt);
            let bits = s.bits() as u64;
            let width_const = MlilExpr::Const { value: bits, size: s };
            let left_shift = MlilExpr::Sub(Box::new(width_const), Box::new(av.clone()), s);
            MlilExpr::Or(
                Box::new(MlilExpr::Shr(Box::new(lv.clone()), Box::new(av), s)),
                Box::new(MlilExpr::Shl(Box::new(lv), Box::new(left_shift), s)),
                s,
            )
        }
        LlilExpr::CmpEq(l, r) | LlilExpr::FCmpEq(l, r) => {
            MlilExpr::CmpEq(Box::new(lift_llil_expr(*l)), Box::new(lift_llil_expr(*r)))
        }
        LlilExpr::CmpNe(l, r) => {
            MlilExpr::CmpNe(Box::new(lift_llil_expr(*l)), Box::new(lift_llil_expr(*r)))
        }
        LlilExpr::CmpSlt(l, r) | LlilExpr::FCmpLt(l, r) => {
            MlilExpr::CmpSlt(Box::new(lift_llil_expr(*l)), Box::new(lift_llil_expr(*r)))
        }
        LlilExpr::CmpUlt(l, r) => {
            MlilExpr::CmpUlt(Box::new(lift_llil_expr(*l)), Box::new(lift_llil_expr(*r)))
        }
        LlilExpr::CmpSle(l, r) => {
            MlilExpr::CmpSle(Box::new(lift_llil_expr(*l)), Box::new(lift_llil_expr(*r)))
        }
        LlilExpr::CmpUle(l, r) => {
            MlilExpr::CmpUle(Box::new(lift_llil_expr(*l)), Box::new(lift_llil_expr(*r)))
        }
        LlilExpr::CmpSgt(l, r) | LlilExpr::FCmpGt(l, r) => {
            MlilExpr::CmpSlt(Box::new(lift_llil_expr(*r)), Box::new(lift_llil_expr(*l)))
        }
        LlilExpr::CmpUgt(l, r) => {
            MlilExpr::CmpUlt(Box::new(lift_llil_expr(*r)), Box::new(lift_llil_expr(*l)))
        }
        LlilExpr::CmpSge(l, r) => {
            MlilExpr::CmpSle(Box::new(lift_llil_expr(*r)), Box::new(lift_llil_expr(*l)))
        }
        LlilExpr::CmpUge(l, r) => {
            MlilExpr::CmpUle(Box::new(lift_llil_expr(*r)), Box::new(lift_llil_expr(*l)))
        }
        LlilExpr::ZeroExtend { expr, from, to } => MlilExpr::ZeroExtend {
            expr: Box::new(lift_llil_expr(*expr)),
            from,
            to,
        },
        LlilExpr::SignExtend { expr, from, to } => MlilExpr::SignExtend {
            expr: Box::new(lift_llil_expr(*expr)),
            from,
            to,
        },
        LlilExpr::LowPart { expr, to } => {
            let lifted = lift_llil_expr(*expr);
            let from = lifted.result_size();
            MlilExpr::ZeroExtend {
                expr: Box::new(lifted),
                from,
                to,
            }
        }
        LlilExpr::FAdd(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::FAdd),
        LlilExpr::FSub(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::FSub),
        LlilExpr::FMul(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::FMul),
        LlilExpr::FDiv(l, r, s) => lift_llil_binop(*l, *r, s, MlilExpr::FDiv),
        LlilExpr::FNeg(e, s) => MlilExpr::FNeg(Box::new(lift_llil_expr(*e)), s),
        LlilExpr::IntToFloat { expr, to } => MlilExpr::IntToFloat {
            expr: Box::new(lift_llil_expr(*expr)),
            to,
        },
        LlilExpr::FloatToInt { expr, to } => MlilExpr::FloatToInt {
            expr: Box::new(lift_llil_expr(*expr)),
            to,
        },
        LlilExpr::StackPointer(s) => MlilExpr::StackPointer(s),
        LlilExpr::Flag(name) => MlilExpr::Flag { name },
        LlilExpr::CondExpr {
            cond,
            true_val,
            false_val,
            size: _,
        } => {
            let lifted_cond = lift_llil_expr(*cond);
            let lifted_true = lift_llil_expr(*true_val);
            let lifted_false = lift_llil_expr(*false_val);
            let size = lifted_true.result_size();
            MlilExpr::Select {
                cond: Box::new(lifted_cond),
                true_val: Box::new(lifted_true),
                false_val: Box::new(lifted_false),
                size,
            }
        }
        LlilExpr::Undefined(s) => MlilExpr::Undefined(s),
        LlilExpr::Intrinsic {
            name,
            args,
            result_size,
        } => MlilExpr::Call {
            dest: Box::new(MlilExpr::Var {
                var: SsaVar::initial(name),
                size: Size::QWord,
            }),
            args: args.into_iter().map(lift_llil_expr).collect(),
            return_size: result_size,
        },
    }
}

// ─── Additional imports for passes ───────────────────────────────────────────

// ─── MLIL constant folding ────────────────────────────────────────────────────

/// Fold constant sub-expressions in an [`MlilExpr`].
///
/// Returns the simplified expression and the count of reductions applied.
#[must_use]
pub fn fold_mlil_expr(expr: MlilExpr) -> (MlilExpr, u32) {
    /// Mask a `u64` to the low `size.bits()` bits — every arithmetic constant
    /// the folder produces is normalised through this so that the SSA invariant
    /// "the value of a `Const{size}` fits in `size`" holds across the IR.
    /// Without this the folder was producing values like `Const{u8, 0x100}`
    /// from `Add(u8, 0xFF) + 1`, silently breaking every downstream pass that
    /// trusted the size annotation.
    const fn trunc(v: u64, size: Size) -> u64 {
        let bits = size.bits();
        if bits >= 64 {
            v
        } else {
            v & ((1u64 << bits) - 1)
        }
    }
    /// Structural equality on two MLIL expressions, used by identities like
    /// `Sub(x, x) = 0` and `Xor(x, x) = 0`.
    fn same(a: &MlilExpr, b: &MlilExpr) -> bool {
        a == b
    }
    /// Sign-extend a width-`bits` value to i128 for signed arithmetic
    /// (currently unused, reserved for `Sar` once implemented in the IR).
    /// Right-shift count semantics: shifts ≥ width are saturating-zero, as
    /// in LLVM `lshr poison` / Capstone `shr ≥ width = 0`, NOT `wrapping_shl`
    /// which uses `count % width` and would return `x << 0 = x` for `count = 64`.
    const fn safe_shl(v: u64, by: u64, size: Size) -> u64 {
        if by >= size.bits() as u64 {
            0
        } else {
            trunc(v << by, size)
        }
    }
    const fn safe_shr(v: u64, by: u64, size: Size) -> u64 {
        let bits = size.bits() as u64;
        if by >= bits { 0 } else { trunc(v, size) >> by }
    }
    /// Sign-aware saturating signed-shift-right.
    fn safe_sar(v: u64, by: u64, size: Size) -> u64 {
        let bits = size.bits();
        let by = by.min(bits as u64 - 1) as u32;
        let v_trunc = trunc(v, size);
        let sign = if bits == 64 {
            v_trunc as i64
        } else {
            let shift = 64 - bits;
            ((v_trunc as i64) << shift) >> shift
        };
        trunc((sign >> by) as u64, size)
    }

    match expr {
        MlilExpr::Add(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: trunc(lv.wrapping_add(rv), s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            // Additive identities: x + 0 = x  and  0 + x = x.
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            if l2.is_const() == Some(0) {
                return (r2, c1 + c2 + 1);
            }
            (MlilExpr::Add(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Sub(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: trunc(lv.wrapping_sub(rv), s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            // x - x = 0 (only when subtrees are pure: a Load may have a side
            // effect and removing it would be unsound).
            if same(&l2, &r2) && !mlil_expr_has_side_effects(&l2) {
                return (MlilExpr::Const { value: 0, size: s }, c1 + c2 + 1);
            }
            (MlilExpr::Sub(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Mul(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            // x * 0 = 0 — but only when the other side is side-effect-free,
            // otherwise the multiplication's evaluation order would discard
            // a load/call we are required to preserve.
            if (l2.is_const() == Some(0) && !mlil_expr_has_side_effects(&r2))
                || (r2.is_const() == Some(0) && !mlil_expr_has_side_effects(&l2))
            {
                return (MlilExpr::Const { value: 0, size: s }, c1 + c2 + 1);
            }
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: trunc(lv.wrapping_mul(rv), s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            // Multiplicative identity: x * 1 = x  and  1 * x = x.
            if r2.is_const() == Some(1) {
                return (l2, c1 + c2 + 1);
            }
            if l2.is_const() == Some(1) {
                return (r2, c1 + c2 + 1);
            }
            (MlilExpr::Mul(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::And(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            // x & 0 = 0 with the same side-effect proviso as Mul.
            if (l2.is_const() == Some(0) && !mlil_expr_has_side_effects(&r2))
                || (r2.is_const() == Some(0) && !mlil_expr_has_side_effects(&l2))
            {
                return (MlilExpr::Const { value: 0, size: s }, c1 + c2 + 1);
            }
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: trunc(lv & rv, s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            // x & x = x.
            if same(&l2, &r2) && !mlil_expr_has_side_effects(&l2) {
                return (l2, c1 + c2 + 1);
            }
            // x & all_ones(size) = x.
            let all_ones = trunc(u64::MAX, s);
            if r2.is_const() == Some(all_ones) {
                return (l2, c1 + c2 + 1);
            }
            if l2.is_const() == Some(all_ones) {
                return (r2, c1 + c2 + 1);
            }
            (MlilExpr::And(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Or(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: trunc(lv | rv, s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            // x | 0 = x, x | x = x.
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            if l2.is_const() == Some(0) {
                return (r2, c1 + c2 + 1);
            }
            if same(&l2, &r2) && !mlil_expr_has_side_effects(&l2) {
                return (l2, c1 + c2 + 1);
            }
            (MlilExpr::Or(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Xor(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: trunc(lv ^ rv, s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            // x ^ 0 = x.
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            if l2.is_const() == Some(0) {
                return (r2, c1 + c2 + 1);
            }
            // x ^ x = 0 — the canonical register-zeroing idiom after copy-prop.
            if same(&l2, &r2) && !mlil_expr_has_side_effects(&l2) {
                return (MlilExpr::Const { value: 0, size: s }, c1 + c2 + 1);
            }
            (MlilExpr::Xor(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Shl(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: safe_shl(lv, rv, s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            // x << 0 = x.
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            (MlilExpr::Shl(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Shr(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: safe_shr(lv, rv, s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            (MlilExpr::Shr(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Sar(l, r, s) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: safe_sar(lv, rv, s),
                        size: s,
                    },
                    c1 + c2 + 1,
                );
            }
            if r2.is_const() == Some(0) {
                return (l2, c1 + c2 + 1);
            }
            (MlilExpr::Sar(Box::new(l2), Box::new(r2), s), c1 + c2)
        }
        MlilExpr::Neg(e, s) => {
            let (e2, c) = fold_mlil_expr(*e);
            if let Some(v) = e2.is_const() {
                return (
                    MlilExpr::Const {
                        value: trunc(v.wrapping_neg(), s),
                        size: s,
                    },
                    c + 1,
                );
            }
            // -(-x) = x.
            if let MlilExpr::Neg(inner, _) = e2 {
                return (*inner, c + 1);
            }
            (MlilExpr::Neg(Box::new(e2), s), c)
        }
        MlilExpr::Not(e, s) => {
            let (e2, c) = fold_mlil_expr(*e);
            if let Some(v) = e2.is_const() {
                return (
                    MlilExpr::Const {
                        value: trunc(!v, s),
                        size: s,
                    },
                    c + 1,
                );
            }
            // ~(~x) = x.
            if let MlilExpr::Not(inner, _) = e2 {
                return (*inner, c + 1);
            }
            (MlilExpr::Not(Box::new(e2), s), c)
        }
        MlilExpr::CmpEq(l, r) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: u64::from(lv == rv),
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            // x == x = 1.
            if same(&l2, &r2) && !mlil_expr_has_side_effects(&l2) {
                return (
                    MlilExpr::Const {
                        value: 1,
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            (MlilExpr::CmpEq(Box::new(l2), Box::new(r2)), c1 + c2)
        }
        MlilExpr::CmpNe(l, r) => {
            let (l2, c1) = fold_mlil_expr(*l);
            let (r2, c2) = fold_mlil_expr(*r);
            if let (Some(lv), Some(rv)) = (l2.is_const(), r2.is_const()) {
                return (
                    MlilExpr::Const {
                        value: u64::from(lv != rv),
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            // x != x = 0.
            if same(&l2, &r2) && !mlil_expr_has_side_effects(&l2) {
                return (
                    MlilExpr::Const {
                        value: 0,
                        size: Size::Byte,
                    },
                    c1 + c2 + 1,
                );
            }
            (MlilExpr::CmpNe(Box::new(l2), Box::new(r2)), c1 + c2)
        }
        MlilExpr::Load { addr, size } => {
            let (a2, c) = fold_mlil_expr(*addr);
            (
                MlilExpr::Load {
                    addr: Box::new(a2),
                    size,
                },
                c,
            )
        }
        other => (other, 0),
    }
}

fn fold_mlil_instr(instr: MlilInstruction) -> (MlilInstruction, u32) {
    match instr {
        MlilInstruction::Assign { dest, size, src } => {
            let (s2, c) = fold_mlil_expr(src);
            (
                MlilInstruction::Assign {
                    dest,
                    size,
                    src: s2,
                },
                c,
            )
        }
        MlilInstruction::Store { addr, size, src } => {
            let (a2, c1) = fold_mlil_expr(addr);
            let (s2, c2) = fold_mlil_expr(src);
            (
                MlilInstruction::Store {
                    addr: a2,
                    size,
                    src: s2,
                },
                c1 + c2,
            )
        }
        MlilInstruction::CondJump {
            cond,
            true_dest,
            false_dest,
        } => {
            let (c2, cnt) = fold_mlil_expr(cond);
            (
                MlilInstruction::CondJump {
                    cond: c2,
                    true_dest,
                    false_dest,
                },
                cnt,
            )
        }
        other => (other, 0),
    }
}

// ─── MLIL dead store elimination ─────────────────────────────────────────────

/// Eliminate SSA assignments whose defined variable is never used in the function.
///
/// Returns the number of dead assignments removed.
#[must_use]
pub fn eliminate_dead_stores(func: &mut MlilFunction) -> u32 {
    // Collect all used variables (globally).
    let mut used: HashSet<SsaVar> = HashSet::new();
    for ai in func.all_instrs() {
        let mut tmp = Vec::new();
        collect_used_vars_in_instr(&ai.instr, &mut tmp);
        used.extend(tmp);
    }
    let mut count = 0u32;
    for block in &mut func.blocks {
        block.instrs.retain(|ai| {
            if let MlilInstruction::Assign { dest, src, .. } = &ai.instr {
                // Keep if result is used or if src has memory side effects.
                if !used.contains(dest) && !mlil_expr_has_side_effects(src) {
                    count += 1;
                    return false;
                }
            }
            true
        });
    }
    count
}

fn mlil_expr_has_side_effects(expr: &MlilExpr) -> bool {
    match expr {
        MlilExpr::Load { .. } | MlilExpr::Call { .. } => true,
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => mlil_expr_has_side_effects(e),
        MlilExpr::ZeroExtend { expr: e, .. } | MlilExpr::SignExtend { expr: e, .. } => {
            mlil_expr_has_side_effects(e)
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => mlil_expr_has_side_effects(l) || mlil_expr_has_side_effects(r),
        _ => false,
    }
}

// ─── MLIL copy propagation ────────────────────────────────────────────────────

/// Propagate trivial SSA copies: if `v1 = v2` and `v2` is only defined once,
/// replace all uses of `v1` with `v2`.
///
/// Returns the number of substitutions performed.
#[must_use]
pub fn propagate_copies(func: &mut MlilFunction) -> u32 {
    // Find all trivial copies: assign { dest = v1, src = Var(v2) }.
    let mut copies: HashMap<SsaVar, SsaVar> = HashMap::new();
    for ai in func.all_instrs() {
        if let MlilInstruction::Assign {
            dest,
            src: MlilExpr::Var { var, .. },
            ..
        } = &ai.instr
        {
            copies.insert(dest.clone(), var.clone());
        }
    }
    if copies.is_empty() {
        return 0;
    }

    // Transitive closure of the copy chain: if `a → b` and `b → c`, then
    // `a → c`. Without this we would emit only one hop per pass, so chains
    // like `a = b; c = a; d = c` keep `d` pointing at `c` even though both
    // `c` and `a` are themselves copies of `b`. Bounded by `copies.len()` to
    // terminate even on (impossible-in-SSA but defensively-handled) cycles.
    let max_steps = copies.len();
    let keys: Vec<SsaVar> = copies.keys().cloned().collect();
    for k in keys {
        let mut cur = copies[&k].clone();
        for _ in 0..max_steps {
            match copies.get(&cur) {
                Some(next) if next != &cur => cur = next.clone(),
                _ => break,
            }
        }
        copies.insert(k, cur);
    }

    let mut count = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            count += subst_copies_in_instr(&mut ai.instr, &copies);
        }
    }
    count
}

fn subst_copies_in_expr(expr: &mut MlilExpr, copies: &HashMap<SsaVar, SsaVar>) -> u32 {
    match expr {
        MlilExpr::Var { var, .. } => {
            if let Some(replacement) = copies.get(var) {
                *var = replacement.clone();
                return 1;
            }
            0
        }
        MlilExpr::Load { addr, .. } => subst_copies_in_expr(addr, copies),
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => subst_copies_in_expr(e, copies),
        MlilExpr::ZeroExtend { expr: e, .. } | MlilExpr::SignExtend { expr: e, .. } => {
            subst_copies_in_expr(e, copies)
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => {
            subst_copies_in_expr(l, copies) + subst_copies_in_expr(r, copies)
        }
        MlilExpr::Call { dest, args, .. } => {
            subst_copies_in_expr(dest, copies)
                + args
                    .iter_mut()
                    .map(|a| subst_copies_in_expr(a, copies))
                    .sum::<u32>()
        }
        _ => 0,
    }
}

fn subst_copies_in_instr(instr: &mut MlilInstruction, copies: &HashMap<SsaVar, SsaVar>) -> u32 {
    match instr {
        MlilInstruction::Assign { src, .. } => subst_copies_in_expr(src, copies),
        MlilInstruction::Store { addr, src, .. } => {
            subst_copies_in_expr(addr, copies) + subst_copies_in_expr(src, copies)
        }
        MlilInstruction::Jump { dest } => subst_copies_in_expr(dest, copies),
        MlilInstruction::CondJump { cond, .. } => subst_copies_in_expr(cond, copies),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            subst_copies_in_expr(dest, copies)
                + args
                    .iter_mut()
                    .map(|a| subst_copies_in_expr(a, copies))
                    .sum::<u32>()
        }
        MlilInstruction::Ret { values } => values
            .iter_mut()
            .map(|v| subst_copies_in_expr(v, copies))
            .sum(),
        MlilInstruction::SysCall { args, .. } => args
            .iter_mut()
            .map(|a| subst_copies_in_expr(a, copies))
            .sum(),
        _ => 0,
    }
}

// ─── PHI node elimination ─────────────────────────────────────────────────────

/// Eliminate trivial PHI nodes that have exactly one source (not a join point).
///
/// Replaces `dest = φ(source)` with a copy `dest = source` and removes the
/// PHI node, replacing all uses of `dest` with `source`.
///
/// Returns the number of PHIs eliminated.
#[must_use]
pub fn eliminate_trivial_phis(func: &mut MlilFunction) -> u32 {
    let mut replacements: HashMap<SsaVar, SsaVar> = HashMap::new();
    // Find trivial PHIs.
    for block in &func.blocks {
        for ai in &block.instrs {
            if let MlilInstruction::Phi { dest, sources } = &ai.instr
                && sources.len() == 1 {
                    replacements.insert(dest.clone(), sources[0].clone());
                }
        }
    }
    if replacements.is_empty() {
        return 0;
    }
    // Remove trivial PHIs.
    let mut count = 0u32;
    for block in &mut func.blocks {
        block.instrs.retain(|ai| {
            if let MlilInstruction::Phi { dest, sources } = &ai.instr
                && sources.len() == 1 && replacements.contains_key(dest) {
                    count += 1;
                    return false;
                }
            true
        });
    }
    // Substitute all uses of the eliminated PHI dests.
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            subst_copies_in_instr(&mut ai.instr, &replacements);
        }
    }
    count
}

// ─── Simple type inference ────────────────────────────────────────────────────

/// Inferred type information for an SSA variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    /// Signed or unsigned integer of the given size.
    Int(Size),
    /// A pointer (address).
    Pointer,
    /// Boolean (0 or 1).
    Bool,
    /// Unknown / cannot infer.
    Unknown,
}

impl std::fmt::Display for InferredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(s) => write!(f, "int{}", s.bits()),
            Self::Pointer => write!(f, "ptr"),
            Self::Bool => write!(f, "bool"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

/// Run a simple forward type-inference pass over `func`.
///
/// Returns a map from [`SsaVar`] to [`InferredType`].
#[must_use]
pub fn infer_types(func: &MlilFunction) -> HashMap<SsaVar, InferredType> {
    let mut types: HashMap<SsaVar, InferredType> = HashMap::new();
    for ai in func.all_instrs() {
        match &ai.instr {
            MlilInstruction::Assign { dest, src, .. } => {
                let ty = infer_expr_type(src, &types);
                types.insert(dest.clone(), ty);
            }
            MlilInstruction::Phi { dest, sources } => {
                // PHI type = first non-Unknown source type.
                let ty = sources
                    .iter()
                    .filter_map(|s| types.get(s).cloned())
                    .find(|t| *t != InferredType::Unknown)
                    .unwrap_or(InferredType::Unknown);
                types.insert(dest.clone(), ty);
            }
            MlilInstruction::Call { ret_vars, .. } => {
                for rv in ret_vars {
                    types.insert(rv.clone(), InferredType::Unknown);
                }
            }
            _ => {}
        }
    }
    types
}

fn infer_expr_type(expr: &MlilExpr, types: &HashMap<SsaVar, InferredType>) -> InferredType {
    match expr {
        MlilExpr::Const { size, .. } => InferredType::Int(*size),
        MlilExpr::Var { var, size } => types.get(var).cloned().unwrap_or(InferredType::Int(*size)),
        MlilExpr::Load { size, .. } => InferredType::Int(*size),
        MlilExpr::CmpEq(..)
        | MlilExpr::CmpNe(..)
        | MlilExpr::CmpSlt(..)
        | MlilExpr::CmpUlt(..)
        | MlilExpr::CmpSle(..)
        | MlilExpr::CmpUle(..) => InferredType::Bool,
        MlilExpr::Add(_, r, _) => {
            // If right side looks like a pointer offset, the result is a pointer.
            if matches!(infer_expr_type(r, types), InferredType::Pointer) {
                InferredType::Pointer
            } else {
                InferredType::Int(expr.result_size())
            }
        }
        MlilExpr::StackPointer(_) => InferredType::Pointer,
        MlilExpr::ZeroExtend { to, .. } | MlilExpr::SignExtend { to, .. } => InferredType::Int(*to),
        MlilExpr::Call { return_size, .. } => InferredType::Int(*return_size),
        _ => InferredType::Int(expr.result_size()),
    }
}

// ─── MLIL pass manager ────────────────────────────────────────────────────────

/// Result type for MLIL passes.
pub type MlilPassResult = anyhow::Result<u32>;

/// Trait for a single MLIL optimisation or analysis pass.
pub trait MlilPass {
    /// Human-readable pass name.
    fn name(&self) -> &'static str;
    /// Run the pass; return the number of changes.
    ///
    /// # Errors
    /// Returns an error if the pass encounters an internal failure.
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult;
}

/// A pass that runs MLIL constant folding.
#[derive(Debug, Default)]
pub struct MlilConstantFoldingPass;

impl MlilPass for MlilConstantFoldingPass {
    fn name(&self) -> &'static str {
        "mlil-constant-fold"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        let mut total = 0u32;
        for block in &mut func.blocks {
            for ai in &mut block.instrs {
                let old_instr = std::mem::replace(&mut ai.instr, MlilInstruction::Nop);
                let (new_instr, cnt) = fold_mlil_instr(old_instr);
                ai.instr = new_instr;
                total += cnt;
            }
        }
        Ok(total)
    }
}

/// A pass that eliminates dead SSA assignments.
#[derive(Debug, Default)]
pub struct MlilDeadStorePass;

impl MlilPass for MlilDeadStorePass {
    fn name(&self) -> &'static str {
        "mlil-dead-store-elim"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(eliminate_dead_stores(func))
    }
}

/// A pass that eliminates trivial PHI nodes.
#[derive(Debug, Default)]
pub struct MlilPhiEliminationPass;

impl MlilPass for MlilPhiEliminationPass {
    fn name(&self) -> &'static str {
        "mlil-phi-elim"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(eliminate_trivial_phis(func))
    }
}

/// A pass that propagates trivial copies.
#[derive(Debug, Default)]
pub struct MlilCopyPropagationPass;

impl MlilPass for MlilCopyPropagationPass {
    fn name(&self) -> &'static str {
        "mlil-copy-propagation"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(propagate_copies(func))
    }
}

/// Orchestrates multiple MLIL passes.
#[derive(Default)]
pub struct MlilPassManager {
    passes: Vec<Box<dyn MlilPass>>,
}

impl MlilPassManager {
    /// Creates an empty pass manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a standard optimisation pipeline.
    #[must_use]
    pub fn standard() -> Self {
        let mut pm = Self::new();
        pm.add(MlilConstantFoldingPass);
        pm.add(MlilCopyPropagationPass);
        pm.add(MlilPhiEliminationPass);
        pm.add(MlilDeadStorePass);
        pm
    }

    /// Adds a pass to the pipeline.
    pub fn add<P: MlilPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Runs all passes once; returns the total transformation count.
    ///
    /// # Errors
    /// Returns an error if any pass fails.
    pub fn run_all(&mut self, func: &mut MlilFunction) -> anyhow::Result<u32> {
        let mut total = 0u32;
        for p in &mut self.passes {
            total += p.run(func)?;
        }
        Ok(total)
    }

    /// Returns the names of all registered passes.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&'static str> {
        self.passes.iter().map(|p| p.name()).collect()
    }
}

impl fmt::Debug for MlilPassManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlilPassManager({} passes)", self.passes.len())
    }
}

// ─── Pretty-printer ───────────────────────────────────────────────────────────

/// Render `func` as a human-readable MLIL listing.
#[must_use]
pub fn mlil_function_to_text(func: &MlilFunction) -> String {
    let mut s = format!("MLIL Function @ {:#x}\n", func.entry.as_u64());
    for block in &func.blocks {
        s.push_str(&format!(
            "  Block {} [{:#x} .. {:#x}]  preds={:?}  succs={:?}\n",
            block.id,
            block.start.as_u64(),
            block.end.as_u64(),
            block.predecessors,
            block.successors
        ));
        for ai in &block.instrs {
            s.push_str(&format!("    {:#x}:  {}\n", ai.address.as_u64(), ai.instr));
        }
    }
    s
}

/// Render `func` as a Graphviz DOT string.
#[must_use]
pub fn mlil_function_to_dot(func: &MlilFunction) -> String {
    let mut s = format!(
        "digraph \"mlil_{:#x}\" {{\n  rankdir=TB;\n",
        func.entry.as_u64()
    );
    for block in &func.blocks {
        let label_lines: Vec<String> = block
            .instrs
            .iter()
            .map(|ai| format!("{:#x}: {}", ai.address.as_u64(), ai.instr).replace('"', "\\\""))
            .collect();
        let label = label_lines.join("\\l");
        s.push_str(&format!(
            "  bb{} [label=\"BB{}\\n{}\\l\", shape=box, fontname=monospace];\n",
            block.id, block.id, label
        ));
        for &succ in &block.successors {
            s.push_str(&format!("  bb{} -> bb{};\n", block.id, succ));
        }
    }
    s.push_str("}\n");
    s
}

/// Serialise `func` to compact JSON.
///
/// # Errors
/// Returns an error if serialisation fails.
pub fn mlil_function_to_json(func: &MlilFunction) -> anyhow::Result<String> {
    use serde_json::json;
    let blocks: Vec<serde_json::Value> = func
        .blocks
        .iter()
        .map(|b| {
            let instrs: Vec<String> = b.instrs.iter().map(|i| i.instr.to_string()).collect();
            json!({
                "id": b.id,
                "start": b.start.as_u64(),
                "end": b.end.as_u64(),
                "instructions": instrs,
                "predecessors": b.predecessors,
                "successors": b.successors,
            })
        })
        .collect();
    Ok(serde_json::to_string(&json!({
        "entry": func.entry.as_u64(),
        "blocks": blocks,
    }))?)
}

// ─── Additional helpers on MlilExpr ──────────────────────────────────────────

impl MlilExpr {
    /// Count the total number of nodes in the expression tree.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Const { .. }
            | Self::Var { .. }
            | Self::Undefined(_)
            | Self::StackPointer(_)
            | Self::Flag { .. } => 1,
            Self::Load { addr, .. } => 1 + addr.node_count(),
            Self::Neg(e, _) | Self::Not(e, _) => 1 + e.node_count(),
            Self::ZeroExtend { expr, .. } | Self::SignExtend { expr, .. } => {
                1 + expr.node_count()
            }
            Self::Add(l, r, _)
            | Self::Sub(l, r, _)
            | Self::Mul(l, r, _)
            | Self::DivU(l, r, _)
            | Self::DivS(l, r, _)
            | Self::And(l, r, _)
            | Self::Or(l, r, _)
            | Self::Xor(l, r, _)
            | Self::Shl(l, r, _)
            | Self::Shr(l, r, _)
            | Self::Sar(l, r, _)
            | Self::FAdd(l, r, _)
            | Self::FSub(l, r, _)
            | Self::FMul(l, r, _)
            | Self::FDiv(l, r, _)
            | Self::CmpEq(l, r)
            | Self::CmpNe(l, r)
            | Self::CmpSlt(l, r)
            | Self::CmpUlt(l, r)
            | Self::CmpSle(l, r)
            | Self::CmpUle(l, r) => 1 + l.node_count() + r.node_count(),
            Self::FNeg(e, _) => 1 + e.node_count(),
            Self::IntToFloat { expr, .. } | Self::FloatToInt { expr, .. } => 1 + expr.node_count(),
            Self::Select { cond, true_val, false_val, .. } => {
                1 + cond.node_count() + true_val.node_count() + false_val.node_count()
            }
            Self::Call { dest, args, .. } => {
                1 + dest.node_count() + args.iter().map(Self::node_count).sum::<usize>()
            }
        }
    }

    /// Collect all SSA variable names referenced in this expression.
    #[must_use]
    pub fn vars_used(&self) -> Vec<SsaVar> {
        let mut out = Vec::new();
        collect_used_vars_in_expr(self, &mut out);
        out.sort();
        out.dedup();
        out
    }

    /// Returns `true` if this expression contains no loads or calls.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        !mlil_expr_has_side_effects(self)
    }
}

// ─── SsaMlilFunction ─────────────────────────────────────────────────────────

/// An [`MlilFunction`] that has been placed into full SSA form via
/// [`SsaBuilder`].
///
/// The inner [`MlilFunction`] has version-0 variables renamed to unique
/// per-definition versions and PHI nodes inserted at dominance-frontier join
/// points. Use [`SsaMlilFunction::into_inner`] to recover the underlying
/// function for further passes.
#[derive(Debug, Clone)]
pub struct SsaMlilFunction(pub MlilFunction);

impl SsaMlilFunction {
    /// Consume and return the inner [`MlilFunction`].
    #[must_use]
    pub fn into_inner(self) -> MlilFunction {
        self.0
    }

    /// Borrow the inner [`MlilFunction`].
    #[must_use]
    pub const fn inner(&self) -> &MlilFunction {
        &self.0
    }

    /// Mutably borrow the inner [`MlilFunction`].
    pub const fn inner_mut(&mut self) -> &mut MlilFunction {
        &mut self.0
    }
}

impl std::ops::Deref for SsaMlilFunction {
    type Target = MlilFunction;
    fn deref(&self) -> &MlilFunction {
        &self.0
    }
}

impl std::ops::DerefMut for SsaMlilFunction {
    fn deref_mut(&mut self) -> &mut MlilFunction {
        &mut self.0
    }
}

// ─── Additional helpers on MlilFunction ──────────────────────────────────────

impl MlilFunction {
    /// Returns the total number of instructions across all blocks.
    #[must_use]
    pub fn total_instr_count(&self) -> usize {
        self.blocks.iter().map(|b| b.instrs.len()).sum()
    }

    /// Returns `true` if there are no basic blocks.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Render as text listing.
    #[must_use]
    pub fn to_text(&self) -> String {
        mlil_function_to_text(self)
    }

    /// Render as DOT.
    #[must_use]
    pub fn to_dot(&self) -> String {
        mlil_function_to_dot(self)
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns an error if serialisation fails.
    pub fn to_json(&self) -> anyhow::Result<String> {
        mlil_function_to_json(self)
    }

    /// Run type inference and return the type map.
    #[must_use]
    pub fn infer_types(&self) -> HashMap<SsaVar, InferredType> {
        infer_types(self)
    }

    /// Consume this function, run full SSA construction (PHI placement +
    /// variable renaming via [`ssa::SsaBuilder`]), and return the result
    /// wrapped in [`SsaMlilFunction`].
    ///
    /// This is the primary entry-point for library callers that want SSA form.
    #[must_use]
    pub fn into_ssa(mut self) -> SsaMlilFunction {
        ssa::SsaBuilder::build(&mut self);
        SsaMlilFunction(self)
    }
}

// ─── MlilExprBuilder ─────────────────────────────────────────────────────────

/// Fluent builder for composing [`MlilExpr`] trees with less boilerplate.
///
/// # Examples
/// ```
/// use rustre_il_mlil::{MlilExprBuilder, Size};
/// let e = MlilExprBuilder::const_val(1, Size::QWord)
///     .add(MlilExprBuilder::const_val(2, Size::QWord).build(), Size::QWord);
/// ```
#[derive(Debug, Clone)]
pub struct MlilExprBuilder {
    inner: MlilExpr,
}

impl MlilExprBuilder {
    /// Wrap an existing [`MlilExpr`].
    #[must_use]
    pub const fn new(expr: MlilExpr) -> Self {
        Self { inner: expr }
    }

    /// Constant value.
    #[must_use]
    pub const fn const_val(value: u64, size: Size) -> Self {
        Self {
            inner: MlilExpr::Const { value, size },
        }
    }

    /// Variable reference.
    #[must_use]
    pub const fn var(var: SsaVar, size: Size) -> Self {
        Self {
            inner: MlilExpr::Var { var, size },
        }
    }

    /// Memory load.
    #[must_use]
    pub fn load(self, size: Size) -> Self {
        Self {
            inner: MlilExpr::Load {
                addr: Box::new(self.inner),
                size,
            },
        }
    }

    /// Add `rhs`.
    #[must_use]
    pub fn add(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Add(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Subtract `rhs`.
    #[must_use]
    pub fn sub(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Sub(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Multiply by `rhs`.
    #[must_use]
    pub fn mul(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Mul(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Unsigned divide by `rhs`.
    #[must_use]
    pub fn divu(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::DivU(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Signed divide by `rhs`.
    #[must_use]
    pub fn divs(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::DivS(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Bitwise AND with `rhs`.
    #[must_use]
    pub fn and(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::And(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Bitwise OR with `rhs`.
    #[must_use]
    pub fn or(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Or(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Bitwise XOR with `rhs`.
    #[must_use]
    pub fn xor(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Xor(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Shift left by `rhs`.
    #[must_use]
    pub fn shl(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Shl(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Logical shift right.
    #[must_use]
    pub fn shr(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Shr(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Arithmetic shift right.
    #[must_use]
    pub fn sar(self, rhs: MlilExpr, size: Size) -> Self {
        Self {
            inner: MlilExpr::Sar(Box::new(self.inner), Box::new(rhs), size),
        }
    }

    /// Negate.
    #[must_use]
    pub fn neg(self, size: Size) -> Self {
        Self {
            inner: MlilExpr::Neg(Box::new(self.inner), size),
        }
    }

    /// Bitwise NOT.
    #[must_use]
    pub fn not(self, size: Size) -> Self {
        Self {
            inner: MlilExpr::Not(Box::new(self.inner), size),
        }
    }

    /// Zero-extend to `to`.
    #[must_use]
    pub fn zero_extend(self, from: Size, to: Size) -> Self {
        Self {
            inner: MlilExpr::ZeroExtend {
                expr: Box::new(self.inner),
                from,
                to,
            },
        }
    }

    /// Sign-extend to `to`.
    #[must_use]
    pub fn sign_extend(self, from: Size, to: Size) -> Self {
        Self {
            inner: MlilExpr::SignExtend {
                expr: Box::new(self.inner),
                from,
                to,
            },
        }
    }

    /// Compare equal to `rhs`.
    #[must_use]
    pub fn cmpeq(self, rhs: MlilExpr) -> Self {
        Self {
            inner: MlilExpr::CmpEq(Box::new(self.inner), Box::new(rhs)),
        }
    }

    /// Compare not-equal to `rhs`.
    #[must_use]
    pub fn cmpne(self, rhs: MlilExpr) -> Self {
        Self {
            inner: MlilExpr::CmpNe(Box::new(self.inner), Box::new(rhs)),
        }
    }

    /// Signed less-than `rhs`.
    #[must_use]
    pub fn cmpslt(self, rhs: MlilExpr) -> Self {
        Self {
            inner: MlilExpr::CmpSlt(Box::new(self.inner), Box::new(rhs)),
        }
    }

    /// Unsigned less-than `rhs`.
    #[must_use]
    pub fn cmpult(self, rhs: MlilExpr) -> Self {
        Self {
            inner: MlilExpr::CmpUlt(Box::new(self.inner), Box::new(rhs)),
        }
    }

    /// Consume and return the built expression.
    #[must_use]
    pub fn build(self) -> MlilExpr {
        self.inner
    }
}

// ─── MlilInstrBuilder ────────────────────────────────────────────────────────

/// Fluent builder for [`MlilInstruction`].
pub struct MlilInstrBuilder;

impl MlilInstrBuilder {
    /// `dest.size = src`
    #[must_use]
    pub const fn assign(dest: SsaVar, size: Size, src: MlilExpr) -> MlilInstruction {
        MlilInstruction::Assign { dest, size, src }
    }

    /// `[addr].size = src`
    #[must_use]
    pub const fn store(addr: MlilExpr, size: Size, src: MlilExpr) -> MlilInstruction {
        MlilInstruction::Store { addr, size, src }
    }

    /// `jump dest`
    #[must_use]
    pub const fn jump(dest: MlilExpr) -> MlilInstruction {
        MlilInstruction::Jump { dest }
    }

    /// `if (cond) goto true_dest else goto false_dest`
    #[must_use]
    pub const fn cond_jump(cond: MlilExpr, true_dest: Address, false_dest: Address) -> MlilInstruction {
        MlilInstruction::CondJump {
            cond,
            true_dest,
            false_dest,
        }
    }

    /// `[rets] = call dest(args)`
    #[must_use]
    pub const fn call(dest: MlilExpr, args: Vec<MlilExpr>, ret_vars: Vec<SsaVar>) -> MlilInstruction {
        MlilInstruction::Call {
            dest,
            args,
            ret_vars,
        }
    }

    /// `return values`
    #[must_use]
    pub const fn ret(values: Vec<MlilExpr>) -> MlilInstruction {
        MlilInstruction::Ret { values }
    }

    /// `dest = φ(sources...)`
    #[must_use]
    pub const fn phi(dest: SsaVar, sources: Vec<SsaVar>) -> MlilInstruction {
        MlilInstruction::Phi { dest, sources }
    }

    /// `syscall(args)`
    #[must_use]
    pub const fn syscall(args: Vec<MlilExpr>, ret_vars: Vec<SsaVar>) -> MlilInstruction {
        MlilInstruction::SysCall { args, ret_vars }
    }
}

// ─── MlilFunctionBuilder ─────────────────────────────────────────────────────

/// Incremental builder for [`MlilFunction`].
///
/// Maintains version counters per variable name so you can call
/// [`define`] / [`bump`] instead of tracking versions manually.
pub struct MlilFunctionBuilder {
    func: MlilFunction,
    version_counters: HashMap<String, u32>,
    next_block_id: u32,
}

impl MlilFunctionBuilder {
    /// Create a new builder for a function starting at `entry`.
    #[must_use]
    pub fn new(entry: Address) -> Self {
        Self {
            func: MlilFunction::new(entry),
            version_counters: HashMap::new(),
            next_block_id: 0,
        }
    }

    /// Allocate the next block id and return it.
    #[must_use]
    pub const fn alloc_block_id(&mut self) -> u32 {
        let id = self.next_block_id;
        self.next_block_id += 1;
        id
    }

    /// Add a pre-built block.
    pub fn push_block(&mut self, block: MlilBasicBlock) {
        self.func.blocks.push(block);
    }

    /// Return (without incrementing) the next version for `name`.
    #[must_use]
    pub fn current_version(&self, name: &str) -> u32 {
        self.version_counters.get(name).copied().unwrap_or(0)
    }

    /// Define `name` at its current version and bump the counter.
    ///
    /// Returns the [`SsaVar`] for the newly defined version.
    pub fn define(&mut self, name: &str) -> SsaVar {
        let ver = self.version_counters.entry(name.to_owned()).or_insert(0);
        let v = SsaVar::new(name, *ver);
        *ver += 1;
        v
    }

    /// Read the current version of `name` as an [`SsaVar`] without incrementing.
    #[must_use]
    pub fn read(&self, name: &str) -> SsaVar {
        SsaVar::new(name, self.current_version(name).saturating_sub(1))
    }

    /// Finish and return the built [`MlilFunction`].
    #[must_use]
    pub fn finish(self) -> MlilFunction {
        self.func
    }
}

// ─── Redundant load elimination ──────────────────────────────────────────────

/// Eliminate redundant consecutive loads from the same constant address within
/// a single basic block.
///
/// If `v1 = [addr].sz` and then `v2 = [addr].sz` with no intervening store to
/// `addr`, replace the second load with a copy `v2 = v1`.
///
/// Returns the number of loads replaced.
#[must_use]
pub fn eliminate_redundant_loads(func: &mut MlilFunction) -> u32 {
    let mut total = 0u32;
    for block in &mut func.blocks {
        // Map of (addr_const, size) → last loaded SSA var.
        let mut load_cache: HashMap<(u64, Size), SsaVar> = HashMap::new();
        for ai in &mut block.instrs {
            match &ai.instr.clone() {
                MlilInstruction::Assign {
                    dest,
                    size,
                    src:
                        MlilExpr::Load {
                            addr,
                            size: load_sz,
                        },
                } if *size == *load_sz => {
                    if let MlilExpr::Const {
                        value: addr_val, ..
                    } = addr.as_ref()
                    {
                        let key = (*addr_val, *size);
                        if let Some(prev) = load_cache.get(&key).cloned() {
                            // Replace load with copy from previous.
                            ai.instr = MlilInstruction::Assign {
                                dest: dest.clone(),
                                size: *size,
                                src: MlilExpr::Var {
                                    var: prev,
                                    size: *size,
                                },
                            };
                            total += 1;
                        } else {
                            load_cache.insert(key, dest.clone());
                        }
                    }
                }
                // Any store invalidates the entire cache (conservative).
                MlilInstruction::Store { .. }
                | MlilInstruction::Call { .. }
                | MlilInstruction::SysCall { .. } => {
                    load_cache.clear();
                }
                _ => {}
            }
        }
    }
    total
}

// ─── Strength reduction ───────────────────────────────────────────────────────

/// Replace expensive operations with cheaper equivalents:
/// - `x * 2^k  →  x << k`
/// - `x / 2^k  →  x >> k`  (unsigned only)
///
/// Returns the number of replacements.
#[must_use]
pub fn strength_reduce(func: &mut MlilFunction) -> u32 {
    let mut total = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            let changed = strength_reduce_instr(&mut ai.instr);
            total += u32::from(changed);
        }
    }
    total
}

fn strength_reduce_instr(instr: &mut MlilInstruction) -> bool {
    match instr {
        MlilInstruction::Assign { src, .. } => strength_reduce_expr(src),
        MlilInstruction::Store { src, addr, .. } => {
            strength_reduce_expr(src) | strength_reduce_expr(addr)
        }
        MlilInstruction::CondJump { cond, .. } => strength_reduce_expr(cond),
        MlilInstruction::Ret { values } => values.iter_mut().any(strength_reduce_expr),
        _ => false,
    }
}

const fn is_power_of_two(v: u64) -> Option<u32> {
    if v >= 2 && v.is_power_of_two() {
        Some(v.trailing_zeros())
    } else {
        None
    }
}

fn strength_reduce_expr(expr: &mut MlilExpr) -> bool {
    match expr {
        MlilExpr::Mul(l, r, s) => {
            // Recurse first.
            let c1 = strength_reduce_expr(l);
            let c2 = strength_reduce_expr(r);
            // x * 2^k  →  x << k
            if let Some(shift) = r.is_const().and_then(is_power_of_two) {
                let lhs = std::mem::replace(l.as_mut(), MlilExpr::Undefined(*s));
                let shift_expr = MlilExpr::Const {
                    value: u64::from(shift),
                    size: *s,
                };
                *expr = MlilExpr::Shl(Box::new(lhs), Box::new(shift_expr), *s);
                return true;
            }
            if let Some(shift) = l.is_const().and_then(is_power_of_two) {
                let rhs = std::mem::replace(r.as_mut(), MlilExpr::Undefined(*s));
                let shift_expr = MlilExpr::Const {
                    value: u64::from(shift),
                    size: *s,
                };
                *expr = MlilExpr::Shl(Box::new(rhs), Box::new(shift_expr), *s);
                return true;
            }
            c1 | c2
        }
        MlilExpr::DivU(l, r, s) => {
            let c1 = strength_reduce_expr(l);
            let c2 = strength_reduce_expr(r);
            // x / 2^k  →  x >> k (unsigned)
            if let Some(shift) = r.is_const().and_then(is_power_of_two) {
                let lhs = std::mem::replace(l.as_mut(), MlilExpr::Undefined(*s));
                let shift_expr = MlilExpr::Const {
                    value: u64::from(shift),
                    size: *s,
                };
                *expr = MlilExpr::Shr(Box::new(lhs), Box::new(shift_expr), *s);
                return true;
            }
            c1 | c2
        }
        MlilExpr::Add(l, r, s)
        | MlilExpr::Sub(l, r, s)
        | MlilExpr::And(l, r, s)
        | MlilExpr::Or(l, r, s)
        | MlilExpr::Xor(l, r, s)
        | MlilExpr::Shl(l, r, s)
        | MlilExpr::Shr(l, r, s)
        | MlilExpr::Sar(l, r, s)
        | MlilExpr::DivS(l, r, s)
        | MlilExpr::FAdd(l, r, s)
        | MlilExpr::FSub(l, r, s)
        | MlilExpr::FMul(l, r, s)
        | MlilExpr::FDiv(l, r, s) => {
            let _ = s;
            strength_reduce_expr(l) | strength_reduce_expr(r)
        }
        MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => strength_reduce_expr(l) | strength_reduce_expr(r),
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => strength_reduce_expr(e),
        MlilExpr::ZeroExtend { expr: e, .. } | MlilExpr::SignExtend { expr: e, .. } => {
            strength_reduce_expr(e)
        }
        MlilExpr::Load { addr, .. } => strength_reduce_expr(addr),
        MlilExpr::Call { dest, args, .. } => {
            let c = strength_reduce_expr(dest);
            args.iter_mut()
                .fold(c, |acc, a| acc | strength_reduce_expr(a))
        }
        _ => false,
    }
}

// ─── Algebraic simplification ─────────────────────────────────────────────────

/// Algebraic identity simplifications beyond constant folding:
/// - `x + 0 → x`, `0 + x → x`
/// - `x - x → 0`
/// - `x * 1 → x`, `1 * x → x`
/// - `x & x → x`, `x | x → x`, `x ^ x → 0`
/// - `x & all_ones → x`
/// - `x | 0 → x`, `0 | x → x`
/// - `--x → x` (double negation)
/// - `!!x → x` (double bitwise not)
///
/// Returns the number of simplifications.
#[must_use]
pub fn algebraic_simplify(func: &mut MlilFunction) -> u32 {
    let mut total = 0u32;
    for block in &mut func.blocks {
        for ai in &mut block.instrs {
            total += algebraic_simplify_instr(&mut ai.instr);
        }
    }
    total
}

fn algebraic_simplify_instr(instr: &mut MlilInstruction) -> u32 {
    match instr {
        MlilInstruction::Assign { src, .. } => algebraic_simplify_expr(src),
        MlilInstruction::Store { addr, src, .. } => {
            algebraic_simplify_expr(addr) + algebraic_simplify_expr(src)
        }
        MlilInstruction::CondJump { cond, .. } => algebraic_simplify_expr(cond),
        MlilInstruction::Ret { values } => values.iter_mut().map(algebraic_simplify_expr).sum(),
        _ => 0,
    }
}

const fn all_ones_for_size(s: Size) -> u64 {
    match s {
        Size::Byte => 0xFF,
        Size::Word => 0xFFFF,
        Size::DWord => 0xFFFF_FFFF,
        Size::QWord => u64::MAX,
        _ => u64::MAX,
    }
}

fn algebraic_simplify_expr(expr: &mut MlilExpr) -> u32 {
    // Recurse first into children.
    let child_changes = match expr {
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _) => algebraic_simplify_expr(l) + algebraic_simplify_expr(r),
        MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => algebraic_simplify_expr(l) + algebraic_simplify_expr(r),
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => algebraic_simplify_expr(e),
        MlilExpr::ZeroExtend { expr: e, .. } | MlilExpr::SignExtend { expr: e, .. } => {
            algebraic_simplify_expr(e)
        }
        MlilExpr::Load { addr, .. } => algebraic_simplify_expr(addr),
        MlilExpr::Call { dest, args, .. } => {
            algebraic_simplify_expr(dest)
                + args.iter_mut().map(algebraic_simplify_expr).sum::<u32>()
        }
        _ => 0,
    };

    // Now apply identity rules at the current node.
    let simplified = match expr {
        // x + 0  or  0 + x  →  x
        MlilExpr::Add(l, r, _) => {
            if r.is_const() == Some(0) {
                Some(l.as_ref().clone())
            } else if l.is_const() == Some(0) {
                Some(r.as_ref().clone())
            } else {
                None
            }
        }
        // x - 0  →  x
        MlilExpr::Sub(l, r, _) => {
            if r.is_const() == Some(0) {
                Some(l.as_ref().clone())
            } else if l == r {
                Some(MlilExpr::Const {
                    value: 0,
                    size: l.result_size(),
                })
            } else {
                None
            }
        }
        // x * 1  or  1 * x  →  x
        MlilExpr::Mul(l, r, _) => {
            if r.is_const() == Some(1) {
                Some(l.as_ref().clone())
            } else if l.is_const() == Some(1) {
                Some(r.as_ref().clone())
            } else {
                None
            }
        }
        // x & x  →  x   |   x & all_ones  →  x   |   x & 0  →  0
        MlilExpr::And(l, r, s) => {
            if l == r || r.is_const() == Some(all_ones_for_size(*s)) {
                Some(l.as_ref().clone())
            } else if l.is_const() == Some(all_ones_for_size(*s)) {
                Some(r.as_ref().clone())
            } else {
                None
            }
        }
        // x | x  →  x   |   x | 0  →  x   |   0 | x  →  x
        MlilExpr::Or(l, r, _) => {
            if l == r || r.is_const() == Some(0) {
                Some(l.as_ref().clone())
            } else if l.is_const() == Some(0) {
                Some(r.as_ref().clone())
            } else {
                None
            }
        }
        // x ^ x  →  0   |   x ^ 0  →  x
        MlilExpr::Xor(l, r, s) => {
            if l == r {
                Some(MlilExpr::Const { value: 0, size: *s })
            } else if r.is_const() == Some(0) {
                Some(l.as_ref().clone())
            } else {
                None
            }
        }
        // -(-x)  →  x
        MlilExpr::Neg(e, _) => {
            if let MlilExpr::Neg(inner, _) = e.as_ref() {
                Some(inner.as_ref().clone())
            } else {
                None
            }
        }
        // ~(~x)  →  x
        MlilExpr::Not(e, _) => {
            if let MlilExpr::Not(inner, _) = e.as_ref() {
                Some(inner.as_ref().clone())
            } else {
                None
            }
        }
        _ => None,
    };

    if let Some(new_expr) = simplified {
        *expr = new_expr;
        return child_changes + 1;
    }
    child_changes
}

// ─── Use-def chains ───────────────────────────────────────────────────────────

/// A single use/def entry in the use-def chain.
#[derive(Debug, Clone)]
pub struct UseDefEntry {
    /// The block id containing this use/def.
    pub block_id: u32,
    /// The address of the instruction.
    pub address: Address,
    /// Whether this entry is a definition site (true) or use site (false).
    pub is_def: bool,
}

/// Build use-def chains for all SSA variables in `func`.
///
/// Returns a map from [`SsaVar`] to a list of [`UseDefEntry`] items, combining
/// both the single definition and all uses.
#[must_use]
pub fn build_use_def_chains(func: &MlilFunction) -> HashMap<SsaVar, Vec<UseDefEntry>> {
    let mut chains: HashMap<SsaVar, Vec<UseDefEntry>> = HashMap::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            // Record definition.
            if let Some(def_var) = ai.instr.defined_var() {
                chains
                    .entry(def_var.clone())
                    .or_default()
                    .push(UseDefEntry {
                        block_id: block.id,
                        address: ai.address,
                        is_def: true,
                    });
            }
            // Record uses.
            let mut used = Vec::new();
            collect_used_vars_in_instr(&ai.instr, &mut used);
            for v in used {
                chains.entry(v).or_default().push(UseDefEntry {
                    block_id: block.id,
                    address: ai.address,
                    is_def: false,
                });
            }
        }
    }
    chains
}

// ─── Live variable analysis ───────────────────────────────────────────────────

/// Per-block liveness sets.
#[derive(Debug, Clone, Default)]
pub struct BlockLiveness {
    /// Variables live at block entry.
    pub live_in: HashSet<SsaVar>,
    /// Variables live at block exit.
    pub live_out: HashSet<SsaVar>,
    /// `UEVar`: variables used before definition in this block.
    pub ue_var: HashSet<SsaVar>,
    /// `VarKill`: variables defined in this block.
    pub var_kill: HashSet<SsaVar>,
}

/// Compute liveness information for every block in `func`.
///
/// Uses a standard backward iterative data-flow analysis.
#[must_use]
pub fn compute_liveness(func: &MlilFunction) -> HashMap<u32, BlockLiveness> {
    let mut info: HashMap<u32, BlockLiveness> = HashMap::new();

    // Initialise UEVar and VarKill for each block.
    for block in &func.blocks {
        let mut binfo = BlockLiveness::default();
        for ai in &block.instrs {
            // Uses that are not already killed.
            let mut uses = Vec::new();
            collect_used_vars_in_instr(&ai.instr, &mut uses);
            for v in &uses {
                if !binfo.var_kill.contains(v) {
                    binfo.ue_var.insert(v.clone());
                }
            }
            // Def kills.
            if let Some(def) = ai.instr.defined_var() {
                binfo.var_kill.insert(def.clone());
            }
        }
        info.insert(block.id, binfo);
    }

    // Iterative backward fixpoint.
    let mut changed = true;
    while changed {
        changed = false;
        // Process blocks in reverse order for faster convergence.
        for block in func.blocks.iter().rev() {
            // live_out = union of successors' live_in.
            let mut new_out: HashSet<SsaVar> = HashSet::new();
            for &sid in &block.successors {
                if let Some(bi) = info.get(&sid) {
                    new_out.extend(bi.live_in.iter().cloned());
                }
            }
            // live_in = ue_var ∪ (live_out ∖ var_kill)
            let binfo = info.entry(block.id).or_default();
            let new_in: HashSet<SsaVar> = binfo
                .ue_var
                .iter()
                .cloned()
                .chain(
                    new_out
                        .iter()
                        .filter(|v| !binfo.var_kill.contains(*v))
                        .cloned(),
                )
                .collect();
            if new_in != binfo.live_in || new_out != binfo.live_out {
                binfo.live_in = new_in;
                binfo.live_out = new_out;
                changed = true;
            }
        }
    }
    info
}

// ─── Dominance tree ───────────────────────────────────────────────────────────

/// Computes an approximate immediate dominator for each block using the
/// Lengauer-Tarjan simplified algorithm.
///
/// Returns a map from block id to its immediate dominator block id.
/// The entry block maps to itself.
///
/// # Panics
/// Panics if the function has no blocks.
#[must_use]
pub fn compute_dominators(func: &MlilFunction) -> HashMap<u32, u32> {
    if func.blocks.is_empty() {
        return HashMap::new();
    }
    let entry_id = func.blocks[0].id;
    let mut idom: HashMap<u32, u32> = HashMap::new();
    idom.insert(entry_id, entry_id);

    // BFS ordering.
    let mut order: Vec<u32> = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: std::collections::VecDeque<u32> = std::collections::VecDeque::new();
    queue.push_back(entry_id);
    visited.insert(entry_id);
    while let Some(id) = queue.pop_front() {
        order.push(id);
        if let Some(block) = func.block_by_id(id) {
            for &succ in &block.successors {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }

    // Simple iterative dominator computation.
    let mut changed = true;
    while changed {
        changed = false;
        for &id in order.iter().skip(1) {
            let block = match func.block_by_id(id) {
                Some(b) => b,
                None => continue,
            };
            // New idom = first processed predecessor.
            let mut new_idom: Option<u32> = None;
            for &pred in &block.predecessors {
                if !idom.contains_key(&pred) {
                    continue;
                }
                new_idom = Some(match new_idom {
                    None => pred,
                    Some(d) => intersect(pred, d, &idom, &order),
                });
            }
            if let Some(d) = new_idom {
                let old = idom.entry(id).or_insert(d);
                if *old != d {
                    *old = d;
                    changed = true;
                }
            }
        }
    }
    idom
}

fn intersect(mut a: u32, mut b: u32, idom: &HashMap<u32, u32>, order: &[u32]) -> u32 {
    fn rpo_index(id: u32, order: &[u32]) -> usize {
        order.iter().position(|&x| x == id).unwrap_or(usize::MAX)
    }
    while a != b {
        while rpo_index(a, order) > rpo_index(b, order) {
            a = *idom.get(&a).unwrap_or(&a);
        }
        while rpo_index(b, order) > rpo_index(a, order) {
            b = *idom.get(&b).unwrap_or(&b);
        }
    }
    a
}

// ─── MlilVarInfo ─────────────────────────────────────────────────────────────

/// Extended information about a single SSA variable, combining type and liveness.
#[derive(Debug, Clone)]
pub struct MlilVarInfo {
    pub var: SsaVar,
    pub inferred_type: InferredType,
    pub def_block: Option<u32>,
    pub use_count: usize,
}

/// Collect [`MlilVarInfo`] for every defined variable in `func`.
#[must_use]
pub fn collect_var_info(func: &MlilFunction) -> Vec<MlilVarInfo> {
    let types = infer_types(func);
    let chains = build_use_def_chains(func);
    let mut info = Vec::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            if let Some(def) = ai.instr.defined_var() {
                let use_count = chains
                    .get(def)
                    .map_or(0, |v| v.iter().filter(|e| !e.is_def).count());
                info.push(MlilVarInfo {
                    var: def.clone(),
                    inferred_type: types.get(def).cloned().unwrap_or(InferredType::Unknown),
                    def_block: Some(block.id),
                    use_count,
                });
            }
        }
    }
    info
}

// ─── C-like pretty-printer ────────────────────────────────────────────────────

/// Render an [`MlilExpr`] as a C-like expression string.
#[must_use]
pub fn mlil_expr_to_c(expr: &MlilExpr) -> String {
    match expr {
        MlilExpr::Const { value, .. } => {
            if *value > 9 {
                format!("0x{value:x}")
            } else {
                format!("{value}")
            }
        }
        MlilExpr::Var { var, .. } => format!("{var}"),
        MlilExpr::Load { addr, size } => {
            format!("*({} *){}", c_type_for_size(*size), mlil_expr_to_c(addr))
        }
        MlilExpr::Add(l, r, _) => format!("({} + {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Sub(l, r, _) => format!("({} - {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Mul(l, r, _) => format!("({} * {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::DivU(l, r, _) => format!(
            "(unsigned)({}) / (unsigned)({})",
            mlil_expr_to_c(l),
            mlil_expr_to_c(r)
        ),
        MlilExpr::DivS(l, r, _) => format!("({}) / ({})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::And(l, r, _) => format!("({} & {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Or(l, r, _) => format!("({} | {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Xor(l, r, _) => format!("({} ^ {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Shl(l, r, _) => format!("({} << {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Shr(l, r, _) => format!("({} >> {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Sar(l, r, _) => format!("(int)({}) >> {}", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Neg(e, _) => format!("-({})", mlil_expr_to_c(e)),
        MlilExpr::Not(e, _) => format!("~({})", mlil_expr_to_c(e)),
        MlilExpr::ZeroExtend { expr, .. } => format!("(unsigned){}", mlil_expr_to_c(expr)),
        MlilExpr::SignExtend { expr, .. } => format!("(signed){}", mlil_expr_to_c(expr)),
        MlilExpr::CmpEq(l, r) => format!("({} == {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::CmpNe(l, r) => format!("({} != {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::CmpSlt(l, r) => format!("({} < {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::CmpUlt(l, r) => format!(
            "(unsigned)({}) < (unsigned)({})",
            mlil_expr_to_c(l),
            mlil_expr_to_c(r)
        ),
        MlilExpr::CmpSle(l, r) => format!("({} <= {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::CmpUle(l, r) => format!(
            "(unsigned)({}) <= (unsigned)({})",
            mlil_expr_to_c(l),
            mlil_expr_to_c(r)
        ),
        MlilExpr::FAdd(l, r, _) => format!("({} + {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::FSub(l, r, _) => format!("({} - {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::FMul(l, r, _) => format!("({} * {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::FDiv(l, r, _) => format!("({} / {})", mlil_expr_to_c(l), mlil_expr_to_c(r)),
        MlilExpr::Undefined(_) => "undefined".to_owned(),
        MlilExpr::StackPointer(_) => "sp".to_owned(),
        MlilExpr::Flag { name } => format!("flag_{name}"),
        MlilExpr::FNeg(e, _) => format!("(-{})", mlil_expr_to_c(e)),
        MlilExpr::IntToFloat { expr, .. } => format!("(float)({})", mlil_expr_to_c(expr)),
        MlilExpr::FloatToInt { expr, .. } => format!("(int)({})", mlil_expr_to_c(expr)),
        MlilExpr::Select { cond, true_val, false_val, .. } => format!(
            "({} ? {} : {})",
            mlil_expr_to_c(cond),
            mlil_expr_to_c(true_val),
            mlil_expr_to_c(false_val)
        ),
        MlilExpr::Call { dest, args, .. } => {
            let arg_strs: Vec<String> = args.iter().map(mlil_expr_to_c).collect();
            format!("{}({})", mlil_expr_to_c(dest), arg_strs.join(", "))
        }
    }
}

const fn c_type_for_size(s: Size) -> &'static str {
    match s {
        Size::Byte => "uint8_t",
        Size::Word => "uint16_t",
        Size::DWord => "uint32_t",
        Size::QWord => "uint64_t",
        _ => "uintptr_t",
    }
}

/// Render an [`MlilInstruction`] as a C-like statement string.
#[must_use]
pub fn mlil_instr_to_c(instr: &MlilInstruction) -> String {
    match instr {
        MlilInstruction::Nop => "/* nop */".to_owned(),
        MlilInstruction::Assign { dest, src, .. } => {
            format!("{dest} = {};", mlil_expr_to_c(src))
        }
        MlilInstruction::Store { addr, src, size } => {
            format!(
                "*({} *){} = {};",
                c_type_for_size(*size),
                mlil_expr_to_c(addr),
                mlil_expr_to_c(src)
            )
        }
        MlilInstruction::Jump { dest } => format!("goto {};", mlil_expr_to_c(dest)),
        MlilInstruction::JumpTable { dest, targets } => {
            let tgts: Vec<String> = targets.iter().map(|t| format!("0x{:x}", t.as_u64())).collect();
            format!(
                "switch ({}) /* targets: {} */",
                mlil_expr_to_c(dest),
                tgts.join(", ")
            )
        }
        MlilInstruction::CondJump {
            cond,
            true_dest,
            false_dest,
        } => {
            format!(
                "if ({}) goto 0x{:x}; else goto 0x{:x};",
                mlil_expr_to_c(cond),
                true_dest.as_u64(),
                false_dest.as_u64()
            )
        }
        MlilInstruction::Call {
            dest,
            args,
            ret_vars,
        } => {
            let arg_strs: Vec<String> = args.iter().map(mlil_expr_to_c).collect();
            let call_str = format!("{}({})", mlil_expr_to_c(dest), arg_strs.join(", "));
            if ret_vars.is_empty() {
                format!("{call_str};")
            } else {
                let rets: Vec<String> = ret_vars.iter().map(std::string::ToString::to_string).collect();
                format!("{} = {call_str};", rets.join(", "))
            }
        }
        MlilInstruction::TailCall { dest, args } => {
            let arg_strs: Vec<String> = args.iter().map(mlil_expr_to_c).collect();
            format!("return {}({});", mlil_expr_to_c(dest), arg_strs.join(", "))
        }
        MlilInstruction::Ret { values } => {
            let val_strs: Vec<String> = values.iter().map(mlil_expr_to_c).collect();
            format!("return {};", val_strs.join(", "))
        }
        MlilInstruction::Phi { dest, sources } => {
            let src_strs: Vec<String> = sources.iter().map(std::string::ToString::to_string).collect();
            format!("{dest} = ϕ({});", src_strs.join(", "))
        }
        MlilInstruction::Trap { code } => format!("__builtin_trap(0x{code:x});"),
        MlilInstruction::SysCall { args, ret_vars } => {
            let arg_strs: Vec<String> = args.iter().map(mlil_expr_to_c).collect();
            let syscall = format!("syscall({})", arg_strs.join(", "));
            if ret_vars.is_empty() {
                format!("{syscall};")
            } else {
                let rets: Vec<String> = ret_vars.iter().map(std::string::ToString::to_string).collect();
                format!("{} = {syscall};", rets.join(", "))
            }
        }
        MlilInstruction::Undefined => "/* undefined */".to_owned(),
    }
}

/// Render the entire function as C-like pseudocode.
#[must_use]
pub fn mlil_function_to_c(func: &MlilFunction) -> String {
    let mut out = format!("// MLIL function @ 0x{:x}\n", func.entry.as_u64());
    out.push_str("{\n");
    for block in &func.blocks {
        out.push_str(&format!(
            "  block_{}:  // [{:#x}..{:#x}]\n",
            block.id,
            block.start.as_u64(),
            block.end.as_u64()
        ));
        for ai in &block.instrs {
            out.push_str(&format!(
                "    /* 0x{:x} */ {}\n",
                ai.address.as_u64(),
                mlil_instr_to_c(&ai.instr)
            ));
        }
    }
    out.push_str("}\n");
    out
}

// ─── Generic visitor pattern ──────────────────────────────────────────────────

/// Visitor over [`MlilExpr`] nodes.
pub trait MlilExprVisitor {
    /// Called for every expression node (pre-order).
    fn visit_expr(&mut self, expr: &MlilExpr);
}

/// Visitor over [`MlilInstruction`] nodes.
pub trait MlilInstrVisitor {
    /// Called for every instruction.
    fn visit_instr(&mut self, instr: &MlilInstruction);
}

/// Walk all expression sub-nodes of `expr`, calling `visitor.visit_expr` pre-order.
pub fn walk_expr<V: MlilExprVisitor>(expr: &MlilExpr, visitor: &mut V) {
    visitor.visit_expr(expr);
    match expr {
        MlilExpr::Load { addr, .. } => walk_expr(addr, visitor),
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => walk_expr(e, visitor),
        MlilExpr::ZeroExtend { expr: e, .. } | MlilExpr::SignExtend { expr: e, .. } => {
            walk_expr(e, visitor);
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _) => {
            walk_expr(l, visitor);
            walk_expr(r, visitor);
        }
        MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => {
            walk_expr(l, visitor);
            walk_expr(r, visitor);
        }
        MlilExpr::Call { dest, args, .. } => {
            walk_expr(dest, visitor);
            for a in args {
                walk_expr(a, visitor);
            }
        }
        _ => {}
    }
}

/// Walk all instructions (and their sub-expressions) in `func`.
pub fn walk_function_instrs<V: MlilInstrVisitor>(func: &MlilFunction, visitor: &mut V) {
    for block in &func.blocks {
        for ai in &block.instrs {
            visitor.visit_instr(&ai.instr);
        }
    }
}

// ─── Const collector visitor ──────────────────────────────────────────────────

/// Collects every [`MlilExpr::Const`] value found in a function.
#[derive(Debug, Default)]
pub struct ConstCollector {
    pub constants: Vec<u64>,
}

impl MlilExprVisitor for ConstCollector {
    fn visit_expr(&mut self, expr: &MlilExpr) {
        if let MlilExpr::Const { value, .. } = expr {
            self.constants.push(*value);
        }
    }
}

/// Collect all constant values used anywhere in `func`.
#[must_use]
pub fn collect_constants(func: &MlilFunction) -> Vec<u64> {
    let mut collector = ConstCollector::default();
    for ai in func.all_instrs() {
        let exprs_in_instr = collect_exprs_in_instr(&ai.instr);
        for e in &exprs_in_instr {
            walk_expr(e, &mut collector);
        }
    }
    collector.constants.sort_unstable();
    collector.constants.dedup();
    collector.constants
}

fn collect_exprs_in_instr(instr: &MlilInstruction) -> Vec<&MlilExpr> {
    match instr {
        MlilInstruction::Assign { src, .. } => vec![src],
        MlilInstruction::Store { addr, src, .. } => vec![addr, src],
        MlilInstruction::Jump { dest } => vec![dest],
        MlilInstruction::CondJump { cond, .. } => vec![cond],
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            let mut v: Vec<&MlilExpr> = vec![dest];
            v.extend(args.iter());
            v
        }
        MlilInstruction::Ret { values } => values.iter().collect(),
        MlilInstruction::SysCall { args, .. } => args.iter().collect(),
        _ => vec![],
    }
}

// ─── Call site analysis ───────────────────────────────────────────────────────

/// Information about a single call site.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Block containing the call.
    pub block_id: u32,
    /// Address of the call instruction.
    pub address: Address,
    /// Callee expression (often a Const address).
    pub callee: MlilExpr,
    /// Number of arguments passed.
    pub arg_count: usize,
    /// Whether this is a tail call.
    pub is_tail_call: bool,
    /// Whether this is a system call.
    pub is_syscall: bool,
}

/// Collect all call sites in `func`.
#[must_use]
pub fn collect_call_sites(func: &MlilFunction) -> Vec<CallSite> {
    let mut sites = Vec::new();
    for block in &func.blocks {
        for ai in &block.instrs {
            match &ai.instr {
                MlilInstruction::Call { dest, args, .. } => {
                    sites.push(CallSite {
                        block_id: block.id,
                        address: ai.address,
                        callee: dest.clone(),
                        arg_count: args.len(),
                        is_tail_call: false,
                        is_syscall: false,
                    });
                }
                MlilInstruction::TailCall { dest, args } => {
                    sites.push(CallSite {
                        block_id: block.id,
                        address: ai.address,
                        callee: dest.clone(),
                        arg_count: args.len(),
                        is_tail_call: true,
                        is_syscall: false,
                    });
                }
                MlilInstruction::SysCall { args, .. } => {
                    sites.push(CallSite {
                        block_id: block.id,
                        address: ai.address,
                        callee: MlilExpr::Undefined(Size::QWord),
                        arg_count: args.len(),
                        is_tail_call: false,
                        is_syscall: true,
                    });
                }
                _ => {}
            }
        }
    }
    sites
}

// ─── Additional passes ────────────────────────────────────────────────────────

/// Pass that performs strength reduction on the function.
#[derive(Debug, Default)]
pub struct MlilStrengthReductionPass;

impl MlilPass for MlilStrengthReductionPass {
    fn name(&self) -> &'static str {
        "mlil-strength-reduce"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(strength_reduce(func))
    }
}

/// Pass that performs algebraic simplification.
#[derive(Debug, Default)]
pub struct MlilAlgebraicSimplifyPass;

impl MlilPass for MlilAlgebraicSimplifyPass {
    fn name(&self) -> &'static str {
        "mlil-algebraic-simplify"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(algebraic_simplify(func))
    }
}

/// Pass that eliminates redundant loads within blocks.
#[derive(Debug, Default)]
pub struct MlilRedundantLoadEliminationPass;

impl MlilPass for MlilRedundantLoadEliminationPass {
    fn name(&self) -> &'static str {
        "mlil-redundant-load-elim"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(eliminate_redundant_loads(func))
    }
}

/// Extended standard pipeline including all passes.
impl MlilPassManager {
    /// Creates the full optimisation pipeline.
    #[must_use]
    pub fn full() -> Self {
        let mut pm = Self::new();
        pm.add(MlilConstantFoldingPass);
        pm.add(MlilAlgebraicSimplifyPass);
        pm.add(MlilStrengthReductionPass);
        pm.add(MlilCopyPropagationPass);
        pm.add(MlilPhiEliminationPass);
        pm.add(MlilRedundantLoadEliminationPass);
        pm.add(MlilDeadStorePass);
        pm
    }
}

// ─── Serialization snapshots ──────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// A serializable snapshot of an MLIL basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlilBlockSnapshot {
    pub id: u32,
    pub start: u64,
    pub end: u64,
    pub instrs: Vec<String>,
    pub predecessors: Vec<u32>,
    pub successors: Vec<u32>,
}

/// A serializable snapshot of an MLIL function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlilFunctionSnapshot {
    pub entry: u64,
    pub blocks: Vec<MlilBlockSnapshot>,
}

/// Convert `func` into a serialisable snapshot.
#[must_use]
pub fn snapshot_mlil_function(func: &MlilFunction) -> MlilFunctionSnapshot {
    MlilFunctionSnapshot {
        entry: func.entry.as_u64(),
        blocks: func
            .blocks
            .iter()
            .map(|b| MlilBlockSnapshot {
                id: b.id,
                start: b.start.as_u64(),
                end: b.end.as_u64(),
                instrs: b
                    .instrs
                    .iter()
                    .map(|ai| format!("{:#x}: {}", ai.address.as_u64(), ai.instr))
                    .collect(),
                predecessors: b.predecessors.clone(),
                successors: b.successors.clone(),
            })
            .collect(),
    }
}

/// Serialise `func` to a pretty JSON string.
///
/// # Errors
/// Returns an error if serialisation fails.
pub fn mlil_function_to_json_pretty(func: &MlilFunction) -> anyhow::Result<String> {
    let snap = snapshot_mlil_function(func);
    Ok(serde_json::to_string_pretty(&snap)?)
}

// ─── MlilGlobalValueNumbering ─────────────────────────────────────────────────

/// A very simple intra-function GVN: detect identical expressions in the same
/// block and eliminate the duplicate computation.
///
/// Returns the number of substitutions.
#[must_use]
pub fn global_value_numbering(func: &mut MlilFunction) -> u32 {
    let mut total = 0u32;
    for block in &mut func.blocks {
        // Map of expression-as-string → first var that holds it.
        let mut expr_table: HashMap<String, SsaVar> = HashMap::new();
        // We build a substitution map for copy-propagation at the end.
        let mut replacements: HashMap<SsaVar, SsaVar> = HashMap::new();
        for ai in &block.instrs {
            if let MlilInstruction::Assign { dest, src, .. } = &ai.instr
                && src.is_pure() {
                    let key = src.to_string();
                    if let Some(existing) = expr_table.get(&key).cloned() {
                        // This computation was already done — record replacement.
                        replacements.insert(dest.clone(), existing);
                        total += 1;
                    } else {
                        expr_table.insert(key, dest.clone());
                    }
                }
        }
        // Apply replacements.
        if !replacements.is_empty() {
            for ai in &mut block.instrs {
                subst_copies_in_instr(&mut ai.instr, &replacements);
            }
        }
    }
    total
}

/// Pass that performs global value numbering.
#[derive(Debug, Default)]
pub struct MlilGvnPass;

impl MlilPass for MlilGvnPass {
    fn name(&self) -> &'static str {
        "mlil-gvn"
    }
    fn run(&mut self, func: &mut MlilFunction) -> MlilPassResult {
        Ok(global_value_numbering(func))
    }
}

// ─── Reaching definitions ─────────────────────────────────────────────────────

/// Per-block reaching definition sets (var name → set of defining SSA vars).
#[derive(Debug, Clone, Default)]
pub struct ReachingDefs {
    /// Definitions that reach the beginning of this block.
    pub reach_in: HashMap<String, HashSet<SsaVar>>,
    /// Definitions that exit this block.
    pub reach_out: HashMap<String, HashSet<SsaVar>>,
}

/// Compute reaching definitions for every block in `func`.
#[must_use]
pub fn compute_reaching_defs(func: &MlilFunction) -> HashMap<u32, ReachingDefs> {
    let mut info: HashMap<u32, ReachingDefs> = HashMap::new();
    for block in &func.blocks {
        info.insert(block.id, ReachingDefs::default());
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            // reach_in = union of predecessors' reach_out.
            let new_in: HashMap<String, HashSet<SsaVar>> = {
                let mut merged: HashMap<String, HashSet<SsaVar>> = HashMap::new();
                for &pred in &block.predecessors {
                    if let Some(pred_info) = info.get(&pred) {
                        for (name, defs) in &pred_info.reach_out {
                            merged
                                .entry(name.clone())
                                .or_default()
                                .extend(defs.iter().cloned());
                        }
                    }
                }
                merged
            };

            // reach_out = (reach_in \ killed) ∪ gen
            let mut new_out = new_in.clone();
            for ai in &block.instrs {
                if let Some(def) = ai.instr.defined_var() {
                    // Kill all previous defs of this base name, replace with this def.
                    let entry = new_out.entry(def.name.clone()).or_default();
                    entry.clear();
                    entry.insert(def.clone());
                }
            }

            let binfo = info.get_mut(&block.id).unwrap();
            if new_in != binfo.reach_in || new_out != binfo.reach_out {
                binfo.reach_in = new_in;
                binfo.reach_out = new_out;
                changed = true;
            }
        }
    }
    info
}

// ─── MlilStats ────────────────────────────────────────────────────────────────

/// Statistics about an MLIL function.
#[derive(Debug, Clone, Default)]
pub struct MlilStats {
    pub block_count: usize,
    pub instr_count: usize,
    pub phi_count: usize,
    pub call_count: usize,
    pub tail_call_count: usize,
    pub syscall_count: usize,
    pub store_count: usize,
    pub load_count: usize,
    pub unique_var_count: usize,
}

/// Compute statistics for `func`.
#[must_use]
pub fn compute_stats(func: &MlilFunction) -> MlilStats {
    let mut stats = MlilStats {
        block_count: func.blocks.len(),
        ..Default::default()
    };
    for ai in func.all_instrs() {
        stats.instr_count += 1;
        match &ai.instr {
            MlilInstruction::Phi { .. } => stats.phi_count += 1,
            MlilInstruction::Call { .. } => stats.call_count += 1,
            MlilInstruction::TailCall { .. } => stats.tail_call_count += 1,
            MlilInstruction::SysCall { .. } => stats.syscall_count += 1,
            MlilInstruction::Store { .. } => stats.store_count += 1,
            MlilInstruction::Assign {
                src: MlilExpr::Load { .. },
                ..
            } => stats.load_count += 1,
            _ => {}
        }
    }
    stats.unique_var_count = func.all_vars().len();
    stats
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilInstruction, LlilRegister, Size};

    #[test]
    fn test_lift_setreg() {
        let mlil = MlilInstruction::lift_llil(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: LlilExpr::Const {
                value: 42,
                size: Size::QWord,
            },
        });
        assert!(matches!(mlil, MlilInstruction::Assign { .. }));
    }

    #[test]
    fn test_lift_ret() {
        let mlil = MlilInstruction::lift_llil(LlilInstruction::Ret);
        assert_eq!(mlil, MlilInstruction::Ret { values: vec![] });
    }

    #[test]
    fn test_is_terminator() {
        assert!(MlilInstruction::Ret { values: vec![] }.is_terminator());
        assert!(
            MlilInstruction::Jump {
                dest: MlilExpr::Const {
                    value: 0,
                    size: Size::QWord
                }
            }
            .is_terminator()
        );
        assert!(!MlilInstruction::Nop.is_terminator());
    }

    #[test]
    fn test_phi_not_terminator() {
        let phi = MlilInstruction::Phi {
            dest: SsaVar::new("x", 2),
            sources: vec![SsaVar::new("x", 0), SsaVar::new("x", 1)],
        };
        assert!(!phi.is_terminator());
        assert!(phi.is_phi());
    }

    #[test]
    fn test_mlil_function_all_instrs() {
        let addr = Address::new(0x1000);
        let block = MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x2000),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Nop,
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(block);
        assert_eq!(func.all_instrs().count(), 2);
    }

    // ── SsaVar ────────────────────────────────────────────────────────────

    #[test]
    fn ssa_var_display() {
        let v = SsaVar::new("rax", 3);
        assert_eq!(v.to_string(), "rax#3");
    }

    #[test]
    fn ssa_var_initial_is_version_0() {
        let v = SsaVar::initial("rbx");
        assert_eq!(v.version, 0);
        assert_eq!(v.name, "rbx");
    }

    #[test]
    fn ssa_var_next_version() {
        let v = SsaVar::new("rcx", 1);
        let v2 = v.next_version();
        assert_eq!(v2.version, 2);
        assert_eq!(v2.name, "rcx");
    }

    #[test]
    fn ssa_var_equality_and_hash() {
        let v1 = SsaVar::new("rax", 0);
        let v2 = SsaVar::new("rax", 0);
        let v3 = SsaVar::new("rax", 1);
        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }

    // ── MlilExpr ─────────────────────────────────────────────────────────

    #[test]
    fn mlil_expr_const_result_size() {
        let e = MlilExpr::Const {
            value: 42,
            size: Size::DWord,
        };
        assert_eq!(e.result_size(), Size::DWord);
        assert_eq!(e.is_const(), Some(42));
    }

    #[test]
    fn mlil_expr_var_result_size() {
        let v = SsaVar::new("x", 0);
        let e = MlilExpr::Var {
            var: v,
            size: Size::QWord,
        };
        assert_eq!(e.result_size(), Size::QWord);
        assert_eq!(e.is_const(), None);
    }

    #[test]
    fn mlil_expr_load_result_size() {
        let addr = MlilExpr::Const {
            value: 0x1000,
            size: Size::QWord,
        };
        let e = MlilExpr::Load {
            addr: Box::new(addr),
            size: Size::DWord,
        };
        assert_eq!(e.result_size(), Size::DWord);
    }

    #[test]
    fn mlil_expr_arithmetic_result_sizes() {
        let c = MlilExpr::Const {
            value: 1,
            size: Size::QWord,
        };
        let d = MlilExpr::Const {
            value: 2,
            size: Size::QWord,
        };
        assert_eq!(
            MlilExpr::Add(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::Sub(Box::new(c.clone()), Box::new(d.clone()), Size::DWord).result_size(),
            Size::DWord
        );
        assert_eq!(
            MlilExpr::Mul(Box::new(c.clone()), Box::new(d.clone()), Size::Word).result_size(),
            Size::Word
        );
        assert_eq!(
            MlilExpr::DivU(Box::new(c.clone()), Box::new(d.clone()), Size::Byte).result_size(),
            Size::Byte
        );
        assert_eq!(
            MlilExpr::DivS(Box::new(c), Box::new(d), Size::QWord).result_size(),
            Size::QWord
        );
    }

    #[test]
    fn mlil_expr_bitwise_result_sizes() {
        let c = MlilExpr::Const {
            value: 1,
            size: Size::QWord,
        };
        let d = MlilExpr::Const {
            value: 2,
            size: Size::QWord,
        };
        assert_eq!(
            MlilExpr::And(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::Or(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::Xor(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::Shl(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::Shr(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::Sar(Box::new(c), Box::new(d), Size::QWord).result_size(),
            Size::QWord
        );
    }

    #[test]
    fn mlil_expr_cmp_always_byte() {
        let c = MlilExpr::Const {
            value: 0,
            size: Size::QWord,
        };
        let d = MlilExpr::Const {
            value: 1,
            size: Size::QWord,
        };
        assert_eq!(
            MlilExpr::CmpEq(Box::new(c.clone()), Box::new(d.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            MlilExpr::CmpNe(Box::new(c.clone()), Box::new(d.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            MlilExpr::CmpSlt(Box::new(c.clone()), Box::new(d.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            MlilExpr::CmpUlt(Box::new(c.clone()), Box::new(d.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            MlilExpr::CmpSle(Box::new(c.clone()), Box::new(d.clone())).result_size(),
            Size::Byte
        );
        assert_eq!(
            MlilExpr::CmpUle(Box::new(c), Box::new(d)).result_size(),
            Size::Byte
        );
    }

    #[test]
    fn mlil_expr_uses_var() {
        let x = SsaVar::new("x", 0);
        let y = SsaVar::new("y", 1);
        let expr = MlilExpr::Add(
            Box::new(MlilExpr::Var {
                var: x.clone(),
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 1,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        assert!(expr.uses_var(&x));
        assert!(!expr.uses_var(&y));
    }

    #[test]
    fn mlil_expr_display() {
        let e = MlilExpr::Const {
            value: 0xff,
            size: Size::Byte,
        };
        assert_eq!(e.to_string(), "0xff");
        let v = SsaVar::new("rax", 2);
        let ev = MlilExpr::Var {
            var: v,
            size: Size::QWord,
        };
        assert_eq!(ev.to_string(), "rax#2");
    }

    // ── MlilInstruction ───────────────────────────────────────────────────

    #[test]
    fn mlil_instr_defined_var_assign() {
        let v = SsaVar::new("rax", 1);
        let instr = MlilInstruction::Assign {
            dest: v.clone(),
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            },
        };
        assert_eq!(instr.defined_var(), Some(&v));
    }

    #[test]
    fn mlil_instr_defined_var_phi() {
        let v = SsaVar::new("x", 2);
        let phi = MlilInstruction::Phi {
            dest: v.clone(),
            sources: vec![SsaVar::new("x", 0), SsaVar::new("x", 1)],
        };
        assert_eq!(phi.defined_var(), Some(&v));
    }

    #[test]
    fn mlil_instr_defined_var_nop_is_none() {
        assert_eq!(MlilInstruction::Nop.defined_var(), None);
        assert_eq!(MlilInstruction::Ret { values: vec![] }.defined_var(), None);
    }

    #[test]
    fn mlil_instr_uses_var_store() {
        let v = SsaVar::new("ptr", 0);
        let instr = MlilInstruction::Store {
            addr: MlilExpr::Var {
                var: v.clone(),
                size: Size::QWord,
            },
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 42,
                size: Size::QWord,
            },
        };
        assert!(instr.uses_var(&v));
    }

    #[test]
    fn mlil_instr_uses_var_phi_sources() {
        let s0 = SsaVar::new("x", 0);
        let s1 = SsaVar::new("x", 1);
        let d = SsaVar::new("x", 2);
        let phi = MlilInstruction::Phi {
            dest: d.clone(),
            sources: vec![s0.clone(), s1.clone()],
        };
        assert!(phi.uses_var(&s0));
        assert!(phi.uses_var(&s1));
        assert!(!phi.uses_var(&d));
    }

    #[test]
    fn mlil_instr_cond_jump_is_terminator() {
        let addr = Address::new(0x1000);
        let instr = MlilInstruction::CondJump {
            cond: MlilExpr::Const {
                value: 1,
                size: Size::Byte,
            },
            true_dest: addr,
            false_dest: Address::new(0x2000),
        };
        assert!(instr.is_terminator());
        assert!(!instr.is_phi());
    }

    #[test]
    fn mlil_instr_tail_call_is_terminator() {
        let instr = MlilInstruction::TailCall {
            dest: MlilExpr::Const {
                value: 0x401000,
                size: Size::QWord,
            },
            args: vec![],
        };
        assert!(instr.is_terminator());
    }

    #[test]
    fn mlil_instr_trap_is_terminator() {
        assert!(MlilInstruction::Trap { code: 3 }.is_terminator());
    }

    #[test]
    fn mlil_instr_display_assign() {
        let v = SsaVar::new("rax", 1);
        let instr = MlilInstruction::Assign {
            dest: v,
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 0xff,
                size: Size::QWord,
            },
        };
        let s = instr.to_string();
        assert!(s.contains("rax#1"));
        assert!(s.contains("0xff"));
    }

    #[test]
    fn mlil_instr_display_phi() {
        let d = SsaVar::new("x", 2);
        let phi = MlilInstruction::Phi {
            dest: d,
            sources: vec![SsaVar::new("x", 0), SsaVar::new("x", 1)],
        };
        let s = phi.to_string();
        assert!(s.contains("x#2"));
        assert!(s.contains('φ'));
    }

    // ── MlilBasicBlock ────────────────────────────────────────────────────

    #[test]
    fn basic_block_phis_and_non_phis() {
        let addr = Address::new(0x1000);
        let phi = MlilInstruction::Phi {
            dest: SsaVar::new("x", 1),
            sources: vec![SsaVar::new("x", 0)],
        };
        let nop = MlilInstruction::Nop;
        let ret = MlilInstruction::Ret { values: vec![] };
        let block = MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: phi,
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: nop,
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: ret,
                },
            ],
            predecessors: vec![],
            successors: vec![],
        };
        assert_eq!(block.phis().count(), 1);
        assert_eq!(block.non_phi_instrs().count(), 2);
    }

    #[test]
    fn basic_block_defined_vars() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 1);
        let block = MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: v.clone(),
                    size: Size::QWord,
                    src: MlilExpr::Const {
                        value: 0,
                        size: Size::QWord,
                    },
                },
            }],
            predecessors: vec![],
            successors: vec![],
        };
        let defs = block.defined_vars();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0], &v);
    }

    // ── MlilFunction ─────────────────────────────────────────────────────

    #[test]
    fn mlil_function_find_def() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 1);
        let block = MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: v.clone(),
                    size: Size::QWord,
                    src: MlilExpr::Const {
                        value: 99,
                        size: Size::QWord,
                    },
                },
            }],
            predecessors: vec![],
            successors: vec![],
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(block);
        assert!(func.find_def(&v).is_some());
        let missing = SsaVar::new("rax", 99);
        assert!(func.find_def(&missing).is_none());
    }

    #[test]
    fn mlil_function_all_vars() {
        let addr = Address::new(0x1000);
        let v1 = SsaVar::new("rax", 1);
        let v2 = SsaVar::new("rbx", 0);
        let block = MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v1.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 1,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Assign {
                        dest: v2.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 2,
                            size: Size::QWord,
                        },
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(block);
        let vars = func.all_vars();
        assert_eq!(vars.len(), 2);
        assert!(vars.contains(&v1));
        assert!(vars.contains(&v2));
    }

    #[test]
    fn mlil_function_block_by_id_and_block_at() {
        let addr = Address::new(0x1000);
        let block = MlilBasicBlock {
            id: 7,
            start: addr,
            end: Address::new(0x1100),
            instrs: vec![],
            predecessors: vec![],
            successors: vec![],
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(block);
        assert!(func.block_by_id(7).is_some());
        assert!(func.block_by_id(99).is_none());
        assert!(func.block_at(Address::new(0x1050)).is_some());
        assert!(func.block_at(Address::new(0x2000)).is_none());
    }

    // ── Lift LLIL → MLIL coverage ─────────────────────────────────────────

    #[test]
    fn test_lift_nop_to_mlil_nop() {
        use rustre_il_llil::LlilInstruction;
        let mlil = MlilInstruction::lift_llil(LlilInstruction::Nop);
        assert_eq!(mlil, MlilInstruction::Nop);
    }

    #[test]
    fn test_lift_load_to_assign() {
        use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};
        let mlil = MlilInstruction::lift_llil(LlilInstruction::Load {
            dest: LlilRegister::Concrete("rcx".into()),
            size: Size::DWord,
            addr: LlilExpr::Const {
                value: 0x1000,
                size: Size::QWord,
            },
        });
        assert!(matches!(mlil, MlilInstruction::Assign { .. }));
    }

    #[test]
    fn test_lift_store_to_store() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let mlil = MlilInstruction::lift_llil(LlilInstruction::Store {
            addr: LlilExpr::Const {
                value: 0x2000,
                size: Size::QWord,
            },
            size: Size::QWord,
            value: LlilExpr::Const {
                value: 0,
                size: Size::QWord,
            },
        });
        assert!(matches!(mlil, MlilInstruction::Store { .. }));
    }

    #[test]
    fn test_lift_call_to_call() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let mlil = MlilInstruction::lift_llil(LlilInstruction::Call(LlilExpr::Const {
            value: 0x401000,
            size: Size::QWord,
        }));
        assert!(matches!(mlil, MlilInstruction::Call { .. }));
    }

    #[test]
    fn test_lift_tailcall_to_tailcall() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let mlil = MlilInstruction::lift_llil(LlilInstruction::TailCall {
            dest: LlilExpr::Const {
                value: 0x401000,
                size: Size::QWord,
            },
        });
        assert!(matches!(mlil, MlilInstruction::TailCall { .. }));
    }

    #[test]
    fn test_lift_jump_to_jump() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let mlil = MlilInstruction::lift_llil(LlilInstruction::Jump(LlilExpr::Const {
            value: 0x500,
            size: Size::QWord,
        }));
        assert!(matches!(mlil, MlilInstruction::Jump { .. }));
    }

    #[test]
    fn test_lift_cond_jump_to_mlil_cond_jump() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let mlil = MlilInstruction::lift_llil(LlilInstruction::CondJump {
            cond: LlilExpr::Flag("zf".to_string()),
            true_dest: Address::new(0x100),
            false_dest: Address::new(0x200),
        });
        assert!(matches!(mlil, MlilInstruction::CondJump { .. }));
    }

    // ── New tests: constant folding ───────────────────────────────────────

    #[test]
    fn mlil_fold_add_constants() {
        let expr = MlilExpr::Add(
            Box::new(MlilExpr::Const {
                value: 3,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 7,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let (folded, cnt) = fold_mlil_expr(expr);
        assert_eq!(cnt, 1);
        assert_eq!(folded.is_const(), Some(10));
    }

    #[test]
    fn mlil_fold_sub_zero() {
        let v = SsaVar::new("x", 0);
        let expr = MlilExpr::Sub(
            Box::new(MlilExpr::Var {
                var: v,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let (folded, cnt) = fold_mlil_expr(expr);
        assert!(cnt > 0);
        assert!(matches!(folded, MlilExpr::Var { .. }));
    }

    #[test]
    fn mlil_fold_mul_by_zero() {
        let v = SsaVar::new("x", 0);
        let expr = MlilExpr::Mul(
            Box::new(MlilExpr::Var {
                var: v,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let (folded, cnt) = fold_mlil_expr(expr);
        assert!(cnt > 0);
        assert_eq!(folded.is_const(), Some(0));
    }

    #[test]
    fn mlil_fold_and_zero() {
        let v = SsaVar::new("x", 0);
        let expr = MlilExpr::And(
            Box::new(MlilExpr::Var {
                var: v,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let (folded, cnt) = fold_mlil_expr(expr);
        assert!(cnt > 0);
        assert_eq!(folded.is_const(), Some(0));
    }

    // ── New tests: dead store elimination ─────────────────────────────────

    #[test]
    fn mlil_dead_store_elim_removes_unused() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("tmp", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v,
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 42,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let removed = eliminate_dead_stores(&mut func);
        assert_eq!(removed, 1);
        assert_eq!(func.blocks[0].instrs.len(), 1);
    }

    #[test]
    fn mlil_dead_store_elim_keeps_used() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 42,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret {
                        values: vec![MlilExpr::Var {
                            var: v,
                            size: Size::QWord,
                        }],
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let removed = eliminate_dead_stores(&mut func);
        assert_eq!(removed, 0);
        assert_eq!(func.blocks[0].instrs.len(), 2);
    }

    // ── New tests: trivial PHI elimination ───────────────────────────────

    #[test]
    fn mlil_trivial_phi_elim() {
        let addr = Address::new(0x1000);
        let src = SsaVar::new("x", 0);
        let dst = SsaVar::new("x", 1);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Phi {
                        dest: dst.clone(),
                        sources: vec![src],
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret {
                        values: vec![MlilExpr::Var {
                            var: dst,
                            size: Size::QWord,
                        }],
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let eliminated = eliminate_trivial_phis(&mut func);
        assert_eq!(eliminated, 1);
        // PHI removed; Ret should now reference src (x#0) via substitution.
    }

    // ── New tests: copy propagation ───────────────────────────────────────

    #[test]
    fn mlil_copy_propagation_substitutes() {
        let addr = Address::new(0x1000);
        let src = SsaVar::new("rax", 0);
        let dst = SsaVar::new("tmp", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: dst.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Var {
                            var: src,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret {
                        values: vec![MlilExpr::Var {
                            var: dst,
                            size: Size::QWord,
                        }],
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let subs = propagate_copies(&mut func);
        assert!(subs > 0);
    }

    // ── New tests: type inference ─────────────────────────────────────────

    #[test]
    fn mlil_type_inference_const_int() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: v.clone(),
                    size: Size::QWord,
                    src: MlilExpr::Const {
                        value: 42,
                        size: Size::QWord,
                    },
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let types = infer_types(&func);
        assert_eq!(types.get(&v), Some(&InferredType::Int(Size::QWord)));
    }

    #[test]
    fn mlil_type_inference_bool() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("cond", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: v.clone(),
                    size: Size::Byte,
                    src: MlilExpr::CmpEq(
                        Box::new(MlilExpr::Const {
                            value: 0,
                            size: Size::QWord,
                        }),
                        Box::new(MlilExpr::Const {
                            value: 0,
                            size: Size::QWord,
                        }),
                    ),
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let types = infer_types(&func);
        assert_eq!(types.get(&v), Some(&InferredType::Bool));
    }

    // ── New tests: pretty-printer and serialisation ───────────────────────

    #[test]
    fn mlil_to_text_contains_entry() {
        let func = MlilFunction::new(Address::new(0xDEAD));
        let text = func.to_text();
        assert!(text.to_lowercase().contains("dead") || text.contains("0xdead"));
    }

    #[test]
    fn mlil_to_dot_valid() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::Ret { values: vec![] },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let dot = func.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("bb0"));
    }

    #[test]
    fn mlil_to_json_roundtrip() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::Nop,
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let json = func.to_json().unwrap();
        assert!(json.contains("\"entry\""));
    }

    // ── New tests: pass manager ───────────────────────────────────────────

    #[test]
    fn mlil_pass_manager_standard() {
        let mut pm = MlilPassManager::standard();
        let names = pm.pass_names();
        assert!(!names.is_empty());
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::Assign {
                    dest: SsaVar::new("x", 0),
                    size: Size::QWord,
                    src: MlilExpr::Add(
                        Box::new(MlilExpr::Const {
                            value: 5,
                            size: Size::QWord,
                        }),
                        Box::new(MlilExpr::Const {
                            value: 3,
                            size: Size::QWord,
                        }),
                        Size::QWord,
                    ),
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let total = pm.run_all(&mut func).unwrap();
        // Expect at least the constant fold to fire.
        assert!(total > 0);
    }

    // ── New tests: MlilExpr helpers ───────────────────────────────────────

    #[test]
    fn mlil_expr_node_count() {
        let e = MlilExpr::Add(
            Box::new(MlilExpr::Const {
                value: 1,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 2,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        assert_eq!(e.node_count(), 3);
    }

    #[test]
    fn mlil_expr_is_pure() {
        let pure = MlilExpr::Const {
            value: 0,
            size: Size::QWord,
        };
        assert!(pure.is_pure());
        let impure = MlilExpr::Load {
            addr: Box::new(MlilExpr::Const {
                value: 0x1000,
                size: Size::QWord,
            }),
            size: Size::QWord,
        };
        assert!(!impure.is_pure());
    }

    #[test]
    fn mlil_expr_vars_used() {
        let x = SsaVar::new("x", 0);
        let y = SsaVar::new("y", 1);
        let expr = MlilExpr::Add(
            Box::new(MlilExpr::Var {
                var: x.clone(),
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Var {
                var: y.clone(),
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let vars = expr.vars_used();
        assert!(vars.contains(&x));
        assert!(vars.contains(&y));
    }

    // ── New tests: function total count / empty ────────────────────────────

    #[test]
    fn mlil_function_is_empty() {
        let func = MlilFunction::new(Address::new(0x1000));
        assert!(func.is_empty());
        assert_eq!(func.total_instr_count(), 0);
    }

    #[test]
    fn mlil_function_total_instr_count() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Nop,
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        assert_eq!(func.total_instr_count(), 2);
        assert!(!func.is_empty());
    }

    // ── New tests: InferredType display ───────────────────────────────────

    #[test]
    fn inferred_type_display() {
        assert_eq!(InferredType::Int(Size::QWord).to_string(), "int64");
        assert_eq!(InferredType::Bool.to_string(), "bool");
        assert_eq!(InferredType::Pointer.to_string(), "ptr");
        assert_eq!(InferredType::Unknown.to_string(), "?");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tests for new APIs added in the expansion
    // ─────────────────────────────────────────────────────────────────────

    // ── MlilExprBuilder ───────────────────────────────────────────────────

    #[test]
    fn expr_builder_const_val() {
        let e = MlilExprBuilder::const_val(42, Size::QWord).build();
        assert_eq!(e.is_const(), Some(42));
        assert_eq!(e.result_size(), Size::QWord);
    }

    #[test]
    fn expr_builder_var() {
        let v = SsaVar::new("rax", 1);
        let e = MlilExprBuilder::var(v.clone(), Size::QWord).build();
        assert!(e.uses_var(&v));
        assert!(e.is_const().is_none());
    }

    #[test]
    fn expr_builder_add_chain() {
        let e = MlilExprBuilder::const_val(3, Size::QWord)
            .add(
                MlilExprBuilder::const_val(7, Size::QWord).build(),
                Size::QWord,
            )
            .build();
        let (folded, cnt) = fold_mlil_expr(e);
        assert!(cnt > 0);
        assert_eq!(folded.is_const(), Some(10));
    }

    #[test]
    fn expr_builder_load() {
        let e = MlilExprBuilder::const_val(0x1000, Size::QWord)
            .load(Size::DWord)
            .build();
        assert_eq!(e.result_size(), Size::DWord);
        assert!(!e.is_pure());
    }

    #[test]
    fn expr_builder_cmpeq() {
        let e = MlilExprBuilder::const_val(1, Size::QWord)
            .cmpeq(MlilExprBuilder::const_val(1, Size::QWord).build())
            .build();
        assert_eq!(e.result_size(), Size::Byte);
    }

    #[test]
    fn expr_builder_neg_not() {
        let e = MlilExprBuilder::const_val(5, Size::QWord)
            .neg(Size::QWord)
            .build();
        let (folded, _) = fold_mlil_expr(e);
        assert_eq!(folded.is_const(), Some(5u64.wrapping_neg()));

        // NOT on a `Size::Byte` constant MUST truncate the result to 8 bits —
        // a `Const{Byte}` whose value doesn't fit in a byte is a malformed IR
        // node. With proper truncation, NOT(0xFF as u8) = 0x00, not the old
        // un-truncated 0xFFFF_FFFF_FFFF_FF00 (which broke every later pass
        // that read the size annotation).
        let e2 = MlilExprBuilder::const_val(0xFF, Size::Byte)
            .not(Size::Byte)
            .build();
        let (folded2, _) = fold_mlil_expr(e2);
        assert_eq!(folded2.is_const(), Some(0x00));
    }

    #[test]
    fn expr_builder_zero_sign_extend() {
        let e = MlilExprBuilder::const_val(0x80, Size::Byte)
            .zero_extend(Size::Byte, Size::QWord)
            .build();
        assert_eq!(e.result_size(), Size::QWord);

        let e2 = MlilExprBuilder::const_val(0x80, Size::Byte)
            .sign_extend(Size::Byte, Size::QWord)
            .build();
        assert_eq!(e2.result_size(), Size::QWord);
    }

    // ── MlilInstrBuilder ──────────────────────────────────────────────────

    #[test]
    fn instr_builder_assign() {
        let v = SsaVar::new("rax", 0);
        let instr = MlilInstrBuilder::assign(
            v.clone(),
            Size::QWord,
            MlilExpr::Const {
                value: 7,
                size: Size::QWord,
            },
        );
        assert_eq!(instr.defined_var(), Some(&v));
        assert!(!instr.is_terminator());
    }

    #[test]
    fn instr_builder_ret() {
        let instr = MlilInstrBuilder::ret(vec![]);
        assert!(instr.is_terminator());
    }

    #[test]
    fn instr_builder_phi() {
        let d = SsaVar::new("x", 2);
        let instr =
            MlilInstrBuilder::phi(d.clone(), vec![SsaVar::new("x", 0), SsaVar::new("x", 1)]);
        assert!(instr.is_phi());
        assert_eq!(instr.defined_var(), Some(&d));
    }

    #[test]
    fn instr_builder_syscall() {
        let rv = SsaVar::new("ret", 0);
        let instr = MlilInstrBuilder::syscall(
            vec![MlilExpr::Const {
                value: 60,
                size: Size::QWord,
            }],
            vec![rv.clone()],
        );
        assert!(matches!(instr, MlilInstruction::SysCall { .. }));
        assert_eq!(instr.defined_var(), Some(&rv));
    }

    // ── MlilFunctionBuilder ───────────────────────────────────────────────

    #[test]
    fn function_builder_basic() {
        let mut builder = MlilFunctionBuilder::new(Address::new(0x1000));
        let block_id = builder.alloc_block_id();
        assert_eq!(block_id, 0);
        let v = builder.define("rax");
        assert_eq!(v.name, "rax");
        assert_eq!(v.version, 0);
        let v2 = builder.define("rax");
        assert_eq!(v2.version, 1);
        let read_v = builder.read("rax");
        assert_eq!(read_v.version, 1);
        let func = builder.finish();
        assert_eq!(func.entry.as_u64(), 0x1000);
        assert!(func.blocks.is_empty());
    }

    // ── Strength reduction ────────────────────────────────────────────────

    #[test]
    fn strength_reduce_mul_pow2() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: v,
                    size: Size::QWord,
                    src: MlilExpr::Mul(
                        Box::new(MlilExpr::Var {
                            var: SsaVar::new("x", 0),
                            size: Size::QWord,
                        }),
                        Box::new(MlilExpr::Const {
                            value: 8,
                            size: Size::QWord,
                        }),
                        Size::QWord,
                    ),
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let count = strength_reduce(&mut func);
        assert_eq!(count, 1);
        // Should now be a Shl by 3.
        if let MlilInstruction::Assign {
            src: MlilExpr::Shl(_, shift, _),
            ..
        } = &func.blocks[0].instrs[0].instr
        {
            assert_eq!(shift.is_const(), Some(3));
        } else {
            panic!("Expected Shl after strength reduction");
        }
    }

    #[test]
    fn strength_reduce_divu_pow2() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: SsaVar::new("r", 0),
                    size: Size::QWord,
                    src: MlilExpr::DivU(
                        Box::new(MlilExpr::Var {
                            var: SsaVar::new("x", 0),
                            size: Size::QWord,
                        }),
                        Box::new(MlilExpr::Const {
                            value: 4,
                            size: Size::QWord,
                        }),
                        Size::QWord,
                    ),
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let count = strength_reduce(&mut func);
        assert_eq!(count, 1);
    }

    // ── Algebraic simplification ──────────────────────────────────────────

    #[test]
    fn algebraic_xor_self_zero() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("x", 0);
        let expr_v = MlilExpr::Var {
            var: v,
            size: Size::QWord,
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: SsaVar::new("r", 0),
                    size: Size::QWord,
                    src: MlilExpr::Xor(Box::new(expr_v.clone()), Box::new(expr_v), Size::QWord),
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let count = algebraic_simplify(&mut func);
        assert!(count > 0);
        if let MlilInstruction::Assign { src, .. } = &func.blocks[0].instrs[0].instr {
            assert_eq!(src.is_const(), Some(0));
        }
    }

    #[test]
    fn algebraic_add_zero() {
        let mut expr = MlilExpr::Add(
            Box::new(MlilExpr::Var {
                var: SsaVar::new("x", 0),
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let count = algebraic_simplify_expr(&mut expr);
        assert!(count > 0);
        assert!(matches!(expr, MlilExpr::Var { .. }));
    }

    #[test]
    fn algebraic_double_neg_eliminates() {
        let mut expr = MlilExpr::Neg(
            Box::new(MlilExpr::Neg(
                Box::new(MlilExpr::Var {
                    var: SsaVar::new("x", 0),
                    size: Size::QWord,
                }),
                Size::QWord,
            )),
            Size::QWord,
        );
        let count = algebraic_simplify_expr(&mut expr);
        assert!(count > 0);
        assert!(matches!(expr, MlilExpr::Var { .. }));
    }

    #[test]
    fn algebraic_or_zero() {
        let mut expr = MlilExpr::Or(
            Box::new(MlilExpr::Var {
                var: SsaVar::new("x", 0),
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let count = algebraic_simplify_expr(&mut expr);
        assert!(count > 0);
        assert!(matches!(expr, MlilExpr::Var { .. }));
    }

    // ── Redundant load elimination ────────────────────────────────────────

    #[test]
    fn redundant_load_elim_same_addr() {
        let addr = Address::new(0x1000);
        let v1 = SsaVar::new("x", 0);
        let v2 = SsaVar::new("y", 0);
        let load_addr = MlilExpr::Const {
            value: 0x2000,
            size: Size::QWord,
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1020),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v1.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Load {
                            addr: Box::new(load_addr.clone()),
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: MlilInstruction::Assign {
                        dest: v2,
                        size: Size::QWord,
                        src: MlilExpr::Load {
                            addr: Box::new(load_addr),
                            size: Size::QWord,
                        },
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let count = eliminate_redundant_loads(&mut func);
        assert_eq!(count, 1);
        // Second instr should now be a copy.
        if let MlilInstruction::Assign {
            src: MlilExpr::Var { var, .. },
            ..
        } = &func.blocks[0].instrs[1].instr
        {
            assert_eq!(var, &v1);
        } else {
            panic!("Expected copy after redundant load elimination");
        }
    }

    #[test]
    fn redundant_load_elim_store_invalidates() {
        let addr = Address::new(0x1000);
        let v1 = SsaVar::new("x", 0);
        let v2 = SsaVar::new("y", 0);
        let load_addr = MlilExpr::Const {
            value: 0x2000,
            size: Size::QWord,
        };
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1020),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v1,
                        size: Size::QWord,
                        src: MlilExpr::Load {
                            addr: Box::new(load_addr.clone()),
                            size: Size::QWord,
                        },
                    },
                },
                // Store in between — should invalidate cache.
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Store {
                        addr: MlilExpr::Const {
                            value: 0x2000,
                            size: Size::QWord,
                        },
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 99,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: MlilInstruction::Assign {
                        dest: v2,
                        size: Size::QWord,
                        src: MlilExpr::Load {
                            addr: Box::new(load_addr),
                            size: Size::QWord,
                        },
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let count = eliminate_redundant_loads(&mut func);
        // Store invalidates; second load should NOT be replaced.
        assert_eq!(count, 0);
    }

    // ── Use-def chains ────────────────────────────────────────────────────

    #[test]
    fn use_def_chains_single_def_use() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 1,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret {
                        values: vec![MlilExpr::Var {
                            var: v.clone(),
                            size: Size::QWord,
                        }],
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let chains = build_use_def_chains(&func);
        let entries = chains.get(&v).unwrap();
        let def_count = entries.iter().filter(|e| e.is_def).count();
        let use_count = entries.iter().filter(|e| !e.is_def).count();
        assert_eq!(def_count, 1);
        assert_eq!(use_count, 1);
    }

    // ── C-like pretty printer ─────────────────────────────────────────────

    #[test]
    fn mlil_expr_to_c_const() {
        let e = MlilExpr::Const {
            value: 0x10,
            size: Size::QWord,
        };
        assert_eq!(mlil_expr_to_c(&e), "0x10");
        let e2 = MlilExpr::Const {
            value: 7,
            size: Size::QWord,
        };
        assert_eq!(mlil_expr_to_c(&e2), "7");
    }

    #[test]
    fn mlil_expr_to_c_var() {
        let v = SsaVar::new("rax", 1);
        let e = MlilExpr::Var {
            var: v,
            size: Size::QWord,
        };
        assert_eq!(mlil_expr_to_c(&e), "rax#1");
    }

    #[test]
    fn mlil_expr_to_c_add() {
        let e = MlilExpr::Add(
            Box::new(MlilExpr::Const {
                value: 1,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 2,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let c = mlil_expr_to_c(&e);
        assert!(c.contains('+'));
    }

    #[test]
    fn mlil_instr_to_c_assign() {
        let v = SsaVar::new("rax", 0);
        let instr = MlilInstruction::Assign {
            dest: v,
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 42,
                size: Size::QWord,
            },
        };
        let c = mlil_instr_to_c(&instr);
        assert!(c.contains("rax#0"));
        assert!(c.contains(';'));
    }

    #[test]
    fn mlil_instr_to_c_cond_jump() {
        let instr = MlilInstruction::CondJump {
            cond: MlilExpr::Const {
                value: 1,
                size: Size::Byte,
            },
            true_dest: Address::new(0x100),
            false_dest: Address::new(0x200),
        };
        let c = mlil_instr_to_c(&instr);
        assert!(c.contains("if"));
        assert!(c.contains("goto"));
    }

    #[test]
    fn mlil_instr_to_c_trap() {
        let instr = MlilInstruction::Trap { code: 3 };
        let c = mlil_instr_to_c(&instr);
        assert!(c.contains("trap"));
    }

    #[test]
    fn mlil_function_to_c_output() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::Ret { values: vec![] },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let c = mlil_function_to_c(&func);
        assert!(c.contains("0x1000"));
        assert!(c.contains("return"));
    }

    // ── Visitor ───────────────────────────────────────────────────────────

    #[test]
    fn const_collector_finds_constants() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1010),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::Assign {
                    dest: SsaVar::new("x", 0),
                    size: Size::QWord,
                    src: MlilExpr::Add(
                        Box::new(MlilExpr::Const {
                            value: 10,
                            size: Size::QWord,
                        }),
                        Box::new(MlilExpr::Const {
                            value: 20,
                            size: Size::QWord,
                        }),
                        Size::QWord,
                    ),
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let consts = collect_constants(&func);
        assert!(consts.contains(&10));
        assert!(consts.contains(&20));
    }

    // ── Call site analysis ────────────────────────────────────────────────

    #[test]
    fn call_sites_direct_call() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Call {
                        dest: MlilExpr::Const {
                            value: 0x401000,
                            size: Size::QWord,
                        },
                        args: vec![MlilExpr::Const {
                            value: 1,
                            size: Size::QWord,
                        }],
                        ret_vars: vec![],
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let sites = collect_call_sites(&func);
        assert_eq!(sites.len(), 1);
        assert!(!sites[0].is_tail_call);
        assert!(!sites[0].is_syscall);
        assert_eq!(sites[0].arg_count, 1);
    }

    #[test]
    fn call_sites_tail_call() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::TailCall {
                    dest: MlilExpr::Const {
                        value: 0x402000,
                        size: Size::QWord,
                    },
                    args: vec![],
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let sites = collect_call_sites(&func);
        assert_eq!(sites.len(), 1);
        assert!(sites[0].is_tail_call);
    }

    #[test]
    fn call_sites_syscall() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::SysCall {
                    args: vec![MlilExpr::Const {
                        value: 60,
                        size: Size::QWord,
                    }],
                    ret_vars: vec![],
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let sites = collect_call_sites(&func);
        assert_eq!(sites.len(), 1);
        assert!(sites[0].is_syscall);
    }

    // ── Global value numbering ────────────────────────────────────────────

    #[test]
    fn gvn_eliminates_duplicate_expr() {
        let addr = Address::new(0x1000);
        let x = SsaVar::new("x", 0);
        let v1 = SsaVar::new("v1", 0);
        let v2 = SsaVar::new("v2", 0);
        let src_expr = MlilExpr::Add(
            Box::new(MlilExpr::Var {
                var: x,
                size: Size::QWord,
            }),
            Box::new(MlilExpr::Const {
                value: 1,
                size: Size::QWord,
            }),
            Size::QWord,
        );
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1020),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v1,
                        size: Size::QWord,
                        src: src_expr.clone(),
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: MlilInstruction::Assign {
                        dest: v2,
                        size: Size::QWord,
                        src: src_expr,
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let count = global_value_numbering(&mut func);
        assert_eq!(count, 1);
    }

    // ── Liveness analysis ─────────────────────────────────────────────────

    #[test]
    fn liveness_single_block() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 1,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret {
                        values: vec![MlilExpr::Var {
                            var: v.clone(),
                            size: Size::QWord,
                        }],
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let liveness = compute_liveness(&func);
        let b0 = &liveness[&0];
        // v is killed in this block.
        assert!(b0.var_kill.contains(&v));
    }

    // ── Dominator computation ─────────────────────────────────────────────

    #[test]
    fn dominators_single_block() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![],
            predecessors: vec![],
            successors: vec![],
        });
        let idom = compute_dominators(&func);
        assert_eq!(idom[&0], 0); // Entry dominates itself.
    }

    #[test]
    fn dominators_two_blocks() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![],
            predecessors: vec![],
            successors: vec![1],
        });
        func.blocks.push(MlilBasicBlock {
            id: 1,
            start: Address::new(0x1008),
            end: Address::new(0x1010),
            instrs: vec![],
            predecessors: vec![0],
            successors: vec![],
        });
        let idom = compute_dominators(&func);
        assert_eq!(idom[&0], 0);
        assert_eq!(idom[&1], 0); // Block 0 dominates block 1.
    }

    // ── Reaching definitions ──────────────────────────────────────────────

    #[test]
    fn reaching_defs_single_block() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1008),
            instrs: vec![MlilAnnotatedInstr {
                address: addr,
                instr: MlilInstruction::Assign {
                    dest: v.clone(),
                    size: Size::QWord,
                    src: MlilExpr::Const {
                        value: 42,
                        size: Size::QWord,
                    },
                },
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let rd = compute_reaching_defs(&func);
        let b0 = &rd[&0];
        assert!(
            b0.reach_out
                .get("rax")
                .is_some_and(|s| s.contains(&v))
        );
    }

    // ── VarInfo ───────────────────────────────────────────────────────────

    #[test]
    fn var_info_use_count() {
        let addr = Address::new(0x1000);
        let v = SsaVar::new("rax", 0);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: v.clone(),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 1,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret {
                        values: vec![MlilExpr::Var {
                            var: v.clone(),
                            size: Size::QWord,
                        }],
                    },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let infos = collect_var_info(&func);
        let rax_info = infos.iter().find(|i| i.var == v).unwrap();
        assert_eq!(rax_info.use_count, 1);
        assert_eq!(rax_info.def_block, Some(0));
    }

    // ── MlilStats ─────────────────────────────────────────────────────────

    #[test]
    fn mlil_stats_basic() {
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1020),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: SsaVar::new("x", 0),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 1,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Call {
                        dest: MlilExpr::Const {
                            value: 0x401000,
                            size: Size::QWord,
                        },
                        args: vec![],
                        ret_vars: vec![],
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: MlilInstruction::Phi {
                        dest: SsaVar::new("x", 1),
                        sources: vec![SsaVar::new("x", 0)],
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x100c),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let stats = compute_stats(&func);
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.instr_count, 4);
        assert_eq!(stats.phi_count, 1);
        assert_eq!(stats.call_count, 1);
    }

    // ── Snapshot serialization ────────────────────────────────────────────

    #[test]
    fn mlil_snapshot_roundtrip() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1008),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    instr: MlilInstruction::Assign {
                        dest: SsaVar::new("rax", 0),
                        size: Size::QWord,
                        src: MlilExpr::Const {
                            value: 42,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let snap = snapshot_mlil_function(&func);
        assert_eq!(snap.entry, 0x1000);
        assert_eq!(snap.blocks.len(), 1);
        assert_eq!(snap.blocks[0].instrs.len(), 2);

        let json = serde_json::to_string(&snap).unwrap();
        let snap2: MlilFunctionSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap2.entry, 0x1000);
        assert_eq!(snap2.blocks[0].id, 0);
    }

    #[test]
    fn mlil_function_to_json_pretty_output() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1004),
            instrs: vec![MlilAnnotatedInstr {
                address: Address::new(0x1000),
                instr: MlilInstruction::Nop,
            }],
            predecessors: vec![],
            successors: vec![],
        });
        let json = mlil_function_to_json_pretty(&func).unwrap();
        assert!(json.contains("\"entry\""));
        assert!(json.contains('\n')); // Pretty-printed.
    }

    // ── Full pass manager ─────────────────────────────────────────────────

    #[test]
    fn mlil_full_pass_manager() {
        let mut pm = MlilPassManager::full();
        let names = pm.pass_names();
        assert!(names.len() >= 7);
        let addr = Address::new(0x1000);
        let mut func = MlilFunction::new(addr);
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1010),
            instrs: vec![
                MlilAnnotatedInstr {
                    address: addr,
                    instr: MlilInstruction::Assign {
                        dest: SsaVar::new("x", 0),
                        size: Size::QWord,
                        src: MlilExpr::Add(
                            Box::new(MlilExpr::Const {
                                value: 5,
                                size: Size::QWord,
                            }),
                            Box::new(MlilExpr::Const {
                                value: 3,
                                size: Size::QWord,
                            }),
                            Size::QWord,
                        ),
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1004),
                    instr: MlilInstruction::Ret { values: vec![] },
                },
            ],
            predecessors: vec![],
            successors: vec![],
        });
        let total = pm.run_all(&mut func).unwrap();
        assert!(total > 0);
    }

    // ── Additional MlilExpr coverage ─────────────────────────────────────

    #[test]
    fn mlil_expr_float_ops_result_size() {
        let c = MlilExpr::Const {
            value: 0,
            size: Size::QWord,
        };
        let d = MlilExpr::Const {
            value: 0,
            size: Size::QWord,
        };
        assert_eq!(
            MlilExpr::FAdd(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::FSub(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::FMul(Box::new(c.clone()), Box::new(d.clone()), Size::QWord).result_size(),
            Size::QWord
        );
        assert_eq!(
            MlilExpr::FDiv(Box::new(c), Box::new(d), Size::QWord).result_size(),
            Size::QWord
        );
    }

    #[test]
    fn mlil_expr_stack_pointer_result_size() {
        let e = MlilExpr::StackPointer(Size::QWord);
        assert_eq!(e.result_size(), Size::QWord);
    }

    #[test]
    fn mlil_expr_undefined_result_size() {
        let e = MlilExpr::Undefined(Size::DWord);
        assert_eq!(e.result_size(), Size::DWord);
    }

    #[test]
    fn mlil_instr_syscall_display() {
        let rv = SsaVar::new("ret", 0);
        let instr = MlilInstruction::SysCall {
            args: vec![MlilExpr::Const {
                value: 60,
                size: Size::QWord,
            }],
            ret_vars: vec![rv],
        };
        let s = instr.to_string();
        assert!(s.contains("syscall"));
        assert!(s.contains("ret#0"));
    }

    #[test]
    fn mlil_instr_call_display_no_rets() {
        let instr = MlilInstruction::Call {
            dest: MlilExpr::Const {
                value: 0x401000,
                size: Size::QWord,
            },
            args: vec![],
            ret_vars: vec![],
        };
        let s = instr.to_string();
        assert!(s.contains("call"));
    }

    #[test]
    fn mlil_instr_store_display() {
        let instr = MlilInstruction::Store {
            addr: MlilExpr::Const {
                value: 0x2000,
                size: Size::QWord,
            },
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            },
        };
        let s = instr.to_string();
        assert!(s.contains('['));
        assert!(s.contains('='));
    }

    #[test]
    fn mlil_expr_vars_used_in_load() {
        let v = SsaVar::new("ptr", 0);
        let e = MlilExpr::Load {
            addr: Box::new(MlilExpr::Var {
                var: v.clone(),
                size: Size::QWord,
            }),
            size: Size::QWord,
        };
        let vars = e.vars_used();
        assert!(vars.contains(&v));
    }

    #[test]
    fn lift_llil_push_is_not_nop() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let instr = LlilInstruction::Push {
            size: Size::QWord,
            src: LlilExpr::Const { value: 42, size: Size::QWord },
        };
        let lifted = MlilInstruction::lift_llil(instr);
        assert!(!matches!(lifted, MlilInstruction::Nop));
        assert!(matches!(lifted, MlilInstruction::Store { .. }));
        if let MlilInstruction::Store { addr, .. } = &lifted {
            assert!(matches!(addr, MlilExpr::StackPointer(Size::QWord)));
        }
    }

    #[test]
    fn a_push_and_the_matching_pop_touch_the_SAME_variable() {
        use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};

        // The whole point of a save/restore pair: `push %rbx` reads rbx and
        // `pop %rbx` writes it back. If the two names disagree, the pop writes a
        // variable nothing ever read and the push's read is never defined —
        // which is exactly how 31998 `var_rr*` locals appeared corpus-wide.
        let pushed = MlilInstruction::lift_llil(LlilInstruction::Push {
            size: Size::QWord,
            src: LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
            },
        });
        let popped = MlilInstruction::lift_llil(LlilInstruction::Pop {
            dest: LlilRegister::Concrete("rbx".into()),
            size: Size::QWord,
        });

        let MlilInstruction::Store { src, .. } = &pushed else {
            panic!("push must lower to a Store, got {pushed:?}")
        };
        let MlilExpr::Var { var: read, .. } = src else {
            panic!("push must store the REGISTER's value, got {src:?}")
        };
        let MlilInstruction::Assign { dest: written, .. } = &popped else {
            panic!("pop must lower to an Assign, got {popped:?}")
        };
        assert_eq!(
            read.name, written.name,
            "push read `{}` but pop wrote `{}` — the pair no longer refers to one location",
            read.name, written.name
        );
        // And it must be the register itself, not some derived spelling.
        assert_eq!(written.name, "rbx");
    }

    #[test]
    fn lift_llil_pop_is_not_nop() {
        use rustre_il_llil::{LlilInstruction, LlilRegister};
        let instr = LlilInstruction::Pop {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
        };
        let lifted = MlilInstruction::lift_llil(instr);
        assert!(!matches!(lifted, MlilInstruction::Nop));
        assert!(matches!(lifted, MlilInstruction::Assign { .. }));
        if let MlilInstruction::Assign { src, .. } = &lifted {
            assert!(matches!(src, MlilExpr::Load { .. }));
        }
    }

    #[test]
    fn lift_llil_multi_push_pop_model_sp_adjust() {
        use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};

        // Push: sp = sp - 8, then store at sp (a Var, not a bare
        // StackPointer, so SSA renaming keeps distinct slots distinct).
        let push = MlilInstruction::lift_llil_multi(LlilInstruction::Push {
            size: Size::QWord,
            src: LlilExpr::Const { value: 42, size: Size::QWord },
        });
        assert_eq!(push.len(), 2);
        match &push[0] {
            MlilInstruction::Assign { dest, src, .. } => {
                assert_eq!(dest.name, "sp");
                assert!(matches!(src, MlilExpr::Sub(..)), "push must decrement sp");
                if let MlilExpr::Sub(l, r, _) = src {
                    assert!(matches!(**l, MlilExpr::Var { ref var, .. } if var.name == "sp"));
                    assert_eq!(r.is_const(), Some(8));
                }
            }
            other => panic!("expected sp-adjust Assign, got {other:?}"),
        }
        match &push[1] {
            MlilInstruction::Store { addr, .. } => {
                assert!(matches!(addr, MlilExpr::Var { var, .. } if var.name == "sp"));
            }
            other => panic!("expected Store at sp, got {other:?}"),
        }

        // Pop: load from sp (keyed off the sp var, NOT the operand size),
        // then sp = sp + 4.
        let pop = MlilInstruction::lift_llil_multi(LlilInstruction::Pop {
            dest: LlilRegister::Concrete("eax".into()),
            size: Size::DWord,
        });
        assert_eq!(pop.len(), 2);
        match &pop[0] {
            MlilInstruction::Assign { src, .. } => {
                if let MlilExpr::Load { addr, .. } = src {
                    assert!(matches!(**addr, MlilExpr::Var { ref var, .. } if var.name == "sp"));
                } else {
                    panic!("expected Load from sp, got {src:?}");
                }
            }
            other => panic!("expected dest Assign, got {other:?}"),
        }
        match &pop[1] {
            MlilInstruction::Assign { dest, src, .. } => {
                assert_eq!(dest.name, "sp");
                assert!(matches!(src, MlilExpr::Add(..)), "pop must increment sp");
                if let MlilExpr::Add(_, r, _) = src {
                    assert_eq!(r.is_const(), Some(4));
                }
            }
            other => panic!("expected sp-adjust Assign, got {other:?}"),
        }

        // Non-push/pop instructions delegate to the single-instruction lift.
        let nop = MlilInstruction::lift_llil_multi(LlilInstruction::Nop);
        assert_eq!(nop, vec![MlilInstruction::Nop]);
    }

    #[test]
    fn lift_llil_setflag_is_not_nop() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let instr = LlilInstruction::SetFlag {
            name: "ZF".to_string(),
            src: LlilExpr::Const { value: 1, size: Size::Byte },
        };
        let lifted = MlilInstruction::lift_llil(instr);
        assert!(!matches!(lifted, MlilInstruction::Nop));
        if let MlilInstruction::Assign { dest, size, .. } = &lifted {
            assert_eq!(dest.name, "flag_ZF");
            assert_eq!(*size, Size::Byte);
        } else {
            panic!("expected Assign, got {lifted:?}");
        }
    }

    #[test]
    fn lift_llil_condcall_is_not_nop() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let instr = LlilInstruction::CondCall {
            cond: LlilExpr::Const { value: 1, size: Size::Byte },
            dest: LlilExpr::Const { value: 0x4010_00, size: Size::QWord },
        };
        let lifted = MlilInstruction::lift_llil(instr);
        assert!(!matches!(lifted, MlilInstruction::Nop));
        assert!(matches!(lifted, MlilInstruction::Call { .. }));
    }

    #[test]
    fn lift_llil_jumpto_preserves_all_targets() {
        use rustre_il_llil::{LlilExpr, LlilInstruction};
        let targets = vec![Address::new(0x1000), Address::new(0x2000), Address::new(0x3000)];
        let instr = LlilInstruction::JumpTo {
            dest: LlilExpr::Const { value: 0x1000, size: Size::QWord },
            targets: targets.clone(),
        };
        let lifted = MlilInstruction::lift_llil(instr);
        if let MlilInstruction::JumpTable { targets: got, .. } = &lifted {
            assert_eq!(*got, targets, "jump table must keep every case target");
        } else {
            panic!("expected JumpTable, got {lifted:?}");
        }
    }

    #[test]
    fn lift_llil_cmp_uge_stays_unsigned() {
        use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};
        let cmp = LlilExpr::CmpUge(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
            }),
            Box::new(LlilExpr::Const { value: 0x8000_0000, size: Size::QWord }),
        );
        let lifted = MlilInstruction::lift_llil(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rbx".into()),
            value: cmp,
            size: Size::Byte,
        });
        let MlilInstruction::Assign { src, .. } = &lifted else {
            panic!("expected Assign, got {lifted:?}");
        };
        assert!(
            matches!(src, MlilExpr::CmpUle(..)),
            "CmpUge(l,r) must lower to unsigned CmpUle(r,l), got {src:?}"
        );
    }

    #[test]
    fn lift_llil_mods_uses_signed_division() {
        use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};
        let mods = LlilExpr::ModS(
            Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
            }),
            Box::new(LlilExpr::Const { value: 3, size: Size::QWord }),
            Size::QWord,
        );
        let lifted = MlilInstruction::lift_llil(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rdx".into()),
            value: mods,
            size: Size::QWord,
        });
        let MlilInstruction::Assign { src, .. } = &lifted else {
            panic!("expected Assign, got {lifted:?}");
        };
        let dbg = format!("{src:?}");
        assert!(dbg.contains("DivS"), "ModS must expand via DivS, got {dbg}");
        assert!(!dbg.contains("DivU"), "ModS must not use unsigned division, got {dbg}");
    }

    #[test]
    fn lift_llil_intrinsic_expr_preserves_operation() {
        use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};
        let intrin = LlilExpr::Intrinsic {
            name: "bswap".to_string(),
            args: vec![LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rax".into()),
                size: Size::QWord,
            }],
            result_size: Size::QWord,
        };
        let lifted = MlilInstruction::lift_llil(LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            value: intrin,
            size: Size::QWord,
        });
        let MlilInstruction::Assign { src, .. } = &lifted else {
            panic!("expected Assign, got {lifted:?}");
        };
        // Must NOT collapse to the bare first argument or a constant — the
        // operation itself has to survive as a call-shaped expression.
        assert!(
            matches!(src, MlilExpr::Call { .. }),
            "intrinsic expr must lower to MlilExpr::Call, got {src:?}"
        );
    }

    #[test]
    fn mlil_to_dot_includes_edges() {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1008),
            instrs: vec![],
            predecessors: vec![],
            successors: vec![1],
        });
        func.blocks.push(MlilBasicBlock {
            id: 1,
            start: Address::new(0x1008),
            end: Address::new(0x1010),
            instrs: vec![],
            predecessors: vec![0],
            successors: vec![],
        });
        let dot = func.to_dot();
        assert!(dot.contains("bb0 -> bb1"));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SSA construction — dominance frontier, iterated PHI placement (Cytron et al.),
// variable renaming with version stacks, and common-subexpression elimination.
// ═════════════════════════════════════════════════════════════════════════════

/// Static-Single-Assignment construction and SSA-level optimisations.
///
/// This module implements the classic Cytron-Ferrante-Rosen-Wegman-Zadeck
/// algorithm:
///
/// 1. Compute the dominator tree (delegating to [`crate::compute_dominators`]).
/// 2. Compute the *dominance frontier* `DF(n)` for every node.
/// 3. Place φ-functions for each variable at the iterated dominance frontier of
///    its definition sites (`DF+`).
/// 4. Rename variables top-down over the dominator tree using per-name version
///    stacks so that every definition is unique and uses reference the correct
///    reaching definition.
pub mod ssa {
    use super::{MlilExpr, MlilFunction, MlilInstruction, SsaVar, compute_dominators};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

    /// The dominator tree of a function: maps each block id to its immediate
    /// dominator and (derived) its set of children.
    #[derive(Debug, Clone)]
    pub struct DomTree {
        /// `idom[n]` = immediate dominator of `n` (entry maps to itself).
        pub idom: HashMap<u32, u32>,
        /// `children[n]` = blocks whose immediate dominator is `n`.
        pub children: HashMap<u32, Vec<u32>>,
        /// The entry block id.
        pub entry: u32,
    }

    impl DomTree {
        /// Build the dominator tree for `func`.
        #[must_use]
        pub fn build(func: &MlilFunction) -> Self {
            let idom: HashMap<u32, u32> = compute_dominators(func).into_iter().collect();
            let entry = func.blocks.first().map_or(0, |b| b.id);
            let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
            for (&node, &parent) in &idom {
                if node != parent {
                    children.entry(parent).or_default().push(node);
                }
            }
            for v in children.values_mut() {
                v.sort_unstable();
            }
            Self {
                idom,
                children,
                entry,
            }
        }

        /// Returns `true` if block `a` dominates block `b` (reflexively).
        #[must_use]
        pub fn dominates(&self, a: u32, b: u32) -> bool {
            let mut cur = b;
            loop {
                if cur == a {
                    return true;
                }
                match self.idom.get(&cur) {
                    Some(&p) if p != cur => cur = p,
                    _ => return false,
                }
            }
        }

        /// Returns the immediate dominator of `n`, or `None` for the entry.
        #[must_use]
        pub fn immediate_dominator(&self, n: u32) -> Option<u32> {
            self.idom.get(&n).copied().filter(|&p| p != n)
        }

        /// Children of `n` in the dominator tree.
        #[must_use]
        pub fn children_of(&self, n: u32) -> &[u32] {
            self.children.get(&n).map_or(&[], Vec::as_slice)
        }
    }

    /// The dominance frontier `DF(n)` for every block.
    ///
    /// `DF(n)` is the set of blocks `m` where `n` dominates a predecessor of `m`
    /// but does not strictly dominate `m` itself. φ-functions for a variable
    /// defined in `n` may be required in every block of `DF(n)`.
    #[derive(Debug, Clone, Default)]
    pub struct DominanceFrontier {
        /// Per-block frontier sets.
        pub frontier: HashMap<u32, BTreeSet<u32>>,
    }

    impl DominanceFrontier {
        /// Compute dominance frontiers using the Cytron et al. bottom-up method.
        #[must_use]
        pub fn compute(func: &MlilFunction, dom: &DomTree) -> Self {
            let mut frontier: HashMap<u32, BTreeSet<u32>> = HashMap::new();
            for block in &func.blocks {
                frontier.entry(block.id).or_default();
            }
            // For each join node b (>= 2 predecessors), walk up from each
            // predecessor until we reach idom(b), adding b to each node's DF.
            for block in &func.blocks {
                if block.predecessors.len() < 2 {
                    continue;
                }
                let b = block.id;
                let idom_b = dom.idom.get(&b).copied();
                for &pred in &block.predecessors {
                    let mut runner = pred;
                    while Some(runner) != idom_b {
                        frontier.entry(runner).or_default().insert(b);
                        match dom.idom.get(&runner) {
                            Some(&p) if p != runner => runner = p,
                            _ => break,
                        }
                    }
                }
            }
            Self { frontier }
        }

        /// The dominance frontier set of a single block.
        #[must_use]
        pub fn of(&self, block: u32) -> BTreeSet<u32> {
            self.frontier.get(&block).cloned().unwrap_or_default()
        }

        /// The *iterated* dominance frontier `DF+(S)` of a set of blocks `S`,
        /// computed as the fixed point of `DF` over `S`.
        #[must_use]
        pub fn iterated(&self, seed: &BTreeSet<u32>) -> BTreeSet<u32> {
            let mut result: BTreeSet<u32> = BTreeSet::new();
            let mut worklist: VecDeque<u32> = seed.iter().copied().collect();
            let mut in_work: HashSet<u32> = seed.iter().copied().collect();
            while let Some(n) = worklist.pop_front() {
                in_work.remove(&n);
                for &m in &self.of(n) {
                    if result.insert(m) && in_work.insert(m) {
                        worklist.push_back(m);
                    }
                }
            }
            result
        }
    }

    /// Returns, for each base variable *name*, the set of block ids that contain
    /// a definition of that name. Used as the seed for φ-placement.
    #[must_use]
    fn definition_sites(func: &MlilFunction) -> BTreeMap<String, BTreeSet<u32>> {
        let mut sites: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                if let Some(def) = ai.instr.defined_var() {
                    sites.entry(def.name.clone()).or_default().insert(block.id);
                }
                if let MlilInstruction::Call { ret_vars, .. }
                | MlilInstruction::SysCall { ret_vars, .. } = &ai.instr
                {
                    for rv in ret_vars {
                        sites.entry(rv.name.clone()).or_default().insert(block.id);
                    }
                }
            }
        }
        sites
    }

    /// Result of φ-placement: for every block, the set of variable *names* that
    /// require a φ-function at the head of that block.
    #[derive(Debug, Clone, Default)]
    pub struct PhiPlacement {
        /// `phis[block]` = names needing a φ-node in `block`.
        pub phis: HashMap<u32, BTreeSet<String>>,
    }

    impl PhiPlacement {
        /// Compute φ-placement via iterated dominance frontiers.
        #[must_use]
        pub fn compute(func: &MlilFunction, df: &DominanceFrontier) -> Self {
            let sites = definition_sites(func);
            let mut phis: HashMap<u32, BTreeSet<String>> = HashMap::new();
            for (name, defs) in &sites {
                let idf = df.iterated(defs);
                for block in idf {
                    phis.entry(block).or_default().insert(name.clone());
                }
            }
            Self { phis }
        }

        /// Names that need a φ-node in `block`.
        #[must_use]
        pub fn at(&self, block: u32) -> BTreeSet<String> {
            self.phis.get(&block).cloned().unwrap_or_default()
        }

        /// Total number of φ-functions to insert across the whole function.
        #[must_use]
        pub fn total(&self) -> usize {
            self.phis.values().map(BTreeSet::len).sum()
        }
    }

    // ── variable renaming with version stacks ───────────────────────────────

    /// Drives the full SSA-construction pipeline on a function whose
    /// instructions still reference base variables at version 0.
    #[derive(Debug)]
    pub struct SsaBuilder {
        next_version: HashMap<String, u32>,
        stacks: HashMap<String, Vec<u32>>,
    }

    impl Default for SsaBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SsaBuilder {
        /// Create an empty builder.
        #[must_use]
        pub fn new() -> Self {
            Self {
                next_version: HashMap::new(),
                stacks: HashMap::new(),
            }
        }

        fn fresh(&mut self, name: &str) -> u32 {
            let v = self.next_version.entry(name.to_string()).or_insert(1);
            let version = *v;
            *v += 1;
            self.stacks
                .entry(name.to_string())
                .or_default()
                .push(version);
            version
        }

        fn top(&self, name: &str) -> u32 {
            self.stacks
                .get(name)
                .and_then(|s| s.last().copied())
                .unwrap_or(0)
        }

        /// Construct full SSA form for `func` in place. Returns the placement
        /// that was used (for inspection / testing).
        pub fn build(func: &mut MlilFunction) -> PhiPlacement {
            let dom = DomTree::build(func);
            let df = DominanceFrontier::compute(func, &dom);
            let placement = PhiPlacement::compute(func, &df);

            // 1. Insert φ-stubs (sources filled during renaming).
            Self::insert_phis(func, &placement);

            // 2. Rename via a pre-order walk of the dominator tree. Renaming
            //    uses an explicit work stack to mirror the recursive algorithm
            //    and to correctly pop versions when leaving a subtree.
            let mut builder = Self::new();
            builder.rename(func, &dom);
            placement
        }

        fn insert_phis(func: &mut MlilFunction, placement: &PhiPlacement) {
            for block in &mut func.blocks {
                let names = placement.at(block.id);
                if names.is_empty() {
                    continue;
                }
                let start = block.start;
                let mut phi_instrs: Vec<super::MlilAnnotatedInstr> = Vec::new();
                let pred_count = block.predecessors.len();
                for name in names {
                    let sources = vec![SsaVar::new(name.clone(), 0); pred_count.max(1)];
                    phi_instrs.push(super::MlilAnnotatedInstr {
                        address: start,
                        instr: MlilInstruction::Phi {
                            dest: SsaVar::new(name, 0),
                            sources,
                        },
                    });
                }
                // φ-nodes go at the very top of the block.
                phi_instrs.append(&mut block.instrs);
                block.instrs = phi_instrs;
            }
        }

        fn rename(&mut self, func: &mut MlilFunction, dom: &DomTree) {
            // Iterative dominator-tree traversal with explicit save/restore of
            // version stacks. Each frame records which names were pushed so we
            // can pop them when the subtree is fully processed.
            enum Action {
                Enter(u32),
                Exit(Vec<String>),
            }
            let mut work: Vec<Action> = vec![Action::Enter(dom.entry)];
            while let Some(action) = work.pop() {
                match action {
                    Action::Exit(pushed) => {
                        for name in pushed {
                            if let Some(stack) = self.stacks.get_mut(&name) {
                                stack.pop();
                            }
                        }
                    }
                    Action::Enter(bid) => {
                        let pushed = self.rename_block(func, bid);
                        work.push(Action::Exit(pushed));
                        for &child in dom.children_of(bid).iter().rev() {
                            work.push(Action::Enter(child));
                        }
                    }
                }
            }
        }

        /// Rename a single block; returns the list of variable names that had a
        /// fresh version pushed (so the caller can pop on subtree exit).
        fn rename_block(&mut self, func: &mut MlilFunction, bid: u32) -> Vec<String> {
            let mut pushed: Vec<String> = Vec::new();
            // Snapshot successor ids first (immutable) for φ-source patching.
            let succ_ids: Vec<u32> = func
                .block_by_id(bid)
                .map(|b| b.successors.clone())
                .unwrap_or_default();

            // Rename within the block.
            if let Some(idx) = func.blocks.iter().position(|b| b.id == bid) {
                let mut instrs = std::mem::take(&mut func.blocks[idx].instrs);
                for ai in &mut instrs {
                    // Uses: rewrite to top-of-stack versions (skip φ sources).
                    if !ai.instr.is_phi() {
                        Self::rewrite_uses(&mut ai.instr, self);
                    }
                    // Defs: allocate a fresh version.
                    Self::rewrite_def(&mut ai.instr, self, &mut pushed);
                }
                func.blocks[idx].instrs = instrs;
            }

            // Patch φ-operands in successors corresponding to this predecessor.
            for succ in succ_ids {
                if let Some(sidx) = func.blocks.iter().position(|b| b.id == succ) {
                    let pred_index = func.blocks[sidx]
                        .predecessors
                        .iter()
                        .position(|&p| p == bid)
                        .unwrap_or(0);
                    let mut instrs = std::mem::take(&mut func.blocks[sidx].instrs);
                    for ai in &mut instrs {
                        if let MlilInstruction::Phi { dest, sources } = &mut ai.instr
                            && pred_index < sources.len()
                        {
                            let v = self.top(&dest.name);
                            sources[pred_index] = SsaVar::new(dest.name.clone(), v);
                        }
                    }
                    func.blocks[sidx].instrs = instrs;
                }
            }
            pushed
        }

        fn rewrite_uses(instr: &mut MlilInstruction, b: &Self) {
            match instr {
                MlilInstruction::Assign { src, .. } => Self::rewrite_expr(src, b),
                MlilInstruction::Store { addr, src, .. } => {
                    Self::rewrite_expr(addr, b);
                    Self::rewrite_expr(src, b);
                }
                MlilInstruction::Jump { dest } | MlilInstruction::JumpTable { dest, .. } => {
                    Self::rewrite_expr(dest, b);
                }
                MlilInstruction::CondJump { cond, .. } => Self::rewrite_expr(cond, b),
                MlilInstruction::Call { dest, args, .. }
                | MlilInstruction::TailCall { dest, args } => {
                    Self::rewrite_expr(dest, b);
                    for a in args {
                        Self::rewrite_expr(a, b);
                    }
                }
                MlilInstruction::Ret { values } => {
                    for v in values {
                        Self::rewrite_expr(v, b);
                    }
                }
                MlilInstruction::SysCall { args, .. } => {
                    for a in args {
                        Self::rewrite_expr(a, b);
                    }
                }
                MlilInstruction::Nop
                | MlilInstruction::Trap { .. }
                | MlilInstruction::Undefined
                | MlilInstruction::Phi { .. } => {}
            }
        }

        fn rewrite_def(instr: &mut MlilInstruction, b: &mut Self, pushed: &mut Vec<String>) {
            match instr {
                MlilInstruction::Assign { dest, .. } | MlilInstruction::Phi { dest, .. } => {
                    let v = b.fresh(&dest.name);
                    pushed.push(dest.name.clone());
                    dest.version = v;
                }
                MlilInstruction::Call { ret_vars, .. }
                | MlilInstruction::SysCall { ret_vars, .. } => {
                    for rv in ret_vars {
                        let v = b.fresh(&rv.name);
                        pushed.push(rv.name.clone());
                        rv.version = v;
                    }
                }
                _ => {}
            }
        }

        fn rewrite_expr(expr: &mut MlilExpr, b: &Self) {
            match expr {
                MlilExpr::Var { var, .. } => {
                    var.version = b.top(&var.name);
                }
                MlilExpr::Const { .. }
                | MlilExpr::Undefined(_)
                | MlilExpr::StackPointer(_)
                | MlilExpr::Flag { .. } => {}
                MlilExpr::Load { addr, .. } => Self::rewrite_expr(addr, b),
                MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => Self::rewrite_expr(e, b),
                MlilExpr::ZeroExtend { expr, .. } | MlilExpr::SignExtend { expr, .. } => {
                    Self::rewrite_expr(expr, b);
                }
                MlilExpr::Add(l, r, _)
                | MlilExpr::Sub(l, r, _)
                | MlilExpr::Mul(l, r, _)
                | MlilExpr::DivU(l, r, _)
                | MlilExpr::DivS(l, r, _)
                | MlilExpr::And(l, r, _)
                | MlilExpr::Or(l, r, _)
                | MlilExpr::Xor(l, r, _)
                | MlilExpr::Shl(l, r, _)
                | MlilExpr::Shr(l, r, _)
                | MlilExpr::Sar(l, r, _)
                | MlilExpr::FAdd(l, r, _)
                | MlilExpr::FSub(l, r, _)
                | MlilExpr::FMul(l, r, _)
                | MlilExpr::FDiv(l, r, _)
                | MlilExpr::CmpEq(l, r)
                | MlilExpr::CmpNe(l, r)
                | MlilExpr::CmpSlt(l, r)
                | MlilExpr::CmpUlt(l, r)
                | MlilExpr::CmpSle(l, r)
                | MlilExpr::CmpUle(l, r) => {
                    Self::rewrite_expr(l, b);
                    Self::rewrite_expr(r, b);
                }
                MlilExpr::FNeg(e, _) => Self::rewrite_expr(e, b),
                MlilExpr::IntToFloat { expr, .. } | MlilExpr::FloatToInt { expr, .. } => {
                    Self::rewrite_expr(expr, b);
                }
                MlilExpr::Select { cond, true_val, false_val, .. } => {
                    Self::rewrite_expr(cond, b);
                    Self::rewrite_expr(true_val, b);
                    Self::rewrite_expr(false_val, b);
                }
                MlilExpr::Call { dest, args, .. } => {
                    Self::rewrite_expr(dest, b);
                    for a in args {
                        Self::rewrite_expr(a, b);
                    }
                }
            }
        }
    }

    /// Convenience entry-point: build full SSA form for `func` in place.
    pub fn construct_ssa(func: &mut MlilFunction) -> PhiPlacement {
        SsaBuilder::build(func)
    }

    // ── common-subexpression elimination ────────────────────────────────────

    /// A canonical, hashable key for a side-effect-free MLIL expression. Used to
    /// detect identical computations across a block for CSE.
    fn expr_key(e: &MlilExpr) -> Option<String> {
        // Loads and calls are excluded — they may observe memory side effects.
        match e {
            MlilExpr::Load { .. } | MlilExpr::Call { .. } => None,
            _ => Some(format!("{e:?}")),
        }
    }

    /// Local (per-block) common-subexpression elimination over a function in SSA
    /// form.
    ///
    /// When two assignments compute the same pure expression, later uses of
    /// the second definition are rewritten to reference the first, and the
    /// redundant assignment is turned into a copy. Returns the number of
    /// redundant computations found.
    ///
    /// Because the IR is in SSA form, "the same expression" is sound to share:
    /// the operands are immutable single-assignment variables.
    pub fn common_subexpression_elimination(func: &mut MlilFunction) -> u32 {
        let mut eliminated = 0u32;
        for block in &mut func.blocks {
            // Map expr-key → the SsaVar that first computed it.
            let mut available: HashMap<String, SsaVar> = HashMap::new();
            // Map redundant var → canonical var, for use-rewriting.
            let mut replace: HashMap<SsaVar, SsaVar> = HashMap::new();

            for ai in &mut block.instrs {
                // First, rewrite any uses that reference an already-replaced var.
                if !ai.instr.is_phi() {
                    rewrite_uses_with(&mut ai.instr, &replace);
                }
                if let MlilInstruction::Assign { dest, src, size } = &ai.instr
                    && let Some(key) = expr_key(src)
                {
                    if let Some(canon) = available.get(&key) {
                        // Redundant: turn into a copy of the canonical var.
                        replace.insert(dest.clone(), canon.clone());
                        let new_src = MlilExpr::Var {
                            var: canon.clone(),
                            size: *size,
                        };
                        let dest_c = dest.clone();
                        let size_c = *size;
                        ai.instr = MlilInstruction::Assign {
                            dest: dest_c,
                            size: size_c,
                            src: new_src,
                        };
                        eliminated += 1;
                    } else {
                        available.insert(key, dest.clone());
                    }
                }
            }
        }
        eliminated
    }

    fn rewrite_uses_with(instr: &mut MlilInstruction, map: &HashMap<SsaVar, SsaVar>) {
        match instr {
            MlilInstruction::Assign { src, .. } => replace_in_expr(src, map),
            MlilInstruction::Store { addr, src, .. } => {
                replace_in_expr(addr, map);
                replace_in_expr(src, map);
            }
            MlilInstruction::Jump { dest } | MlilInstruction::JumpTable { dest, .. } => {
                replace_in_expr(dest, map);
            }
            MlilInstruction::CondJump { cond, .. } => replace_in_expr(cond, map),
            MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
                replace_in_expr(dest, map);
                for a in args {
                    replace_in_expr(a, map);
                }
            }
            MlilInstruction::Ret { values } => {
                for v in values {
                    replace_in_expr(v, map);
                }
            }
            MlilInstruction::SysCall { args, .. } => {
                for a in args {
                    replace_in_expr(a, map);
                }
            }
            MlilInstruction::Phi { sources, .. } => {
                for s in sources {
                    if let Some(c) = map.get(s) {
                        *s = c.clone();
                    }
                }
            }
            MlilInstruction::Nop | MlilInstruction::Trap { .. } | MlilInstruction::Undefined => {}
        }
    }

    fn replace_in_expr(expr: &mut MlilExpr, map: &HashMap<SsaVar, SsaVar>) {
        match expr {
            MlilExpr::Var { var, .. } => {
                if let Some(c) = map.get(var) {
                    *var = c.clone();
                }
            }
            MlilExpr::Const { .. }
            | MlilExpr::Undefined(_)
            | MlilExpr::StackPointer(_)
            | MlilExpr::Flag { .. } => {}
            MlilExpr::Load { addr, .. } => replace_in_expr(addr, map),
            MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => replace_in_expr(e, map),
            MlilExpr::ZeroExtend { expr, .. } | MlilExpr::SignExtend { expr, .. } => {
                replace_in_expr(expr, map);
            }
            MlilExpr::Add(l, r, _)
            | MlilExpr::Sub(l, r, _)
            | MlilExpr::Mul(l, r, _)
            | MlilExpr::DivU(l, r, _)
            | MlilExpr::DivS(l, r, _)
            | MlilExpr::And(l, r, _)
            | MlilExpr::Or(l, r, _)
            | MlilExpr::Xor(l, r, _)
            | MlilExpr::Shl(l, r, _)
            | MlilExpr::Shr(l, r, _)
            | MlilExpr::Sar(l, r, _)
            | MlilExpr::FAdd(l, r, _)
            | MlilExpr::FSub(l, r, _)
            | MlilExpr::FMul(l, r, _)
            | MlilExpr::FDiv(l, r, _)
            | MlilExpr::CmpEq(l, r)
            | MlilExpr::CmpNe(l, r)
            | MlilExpr::CmpSlt(l, r)
            | MlilExpr::CmpUlt(l, r)
            | MlilExpr::CmpSle(l, r)
            | MlilExpr::CmpUle(l, r) => {
                replace_in_expr(l, map);
                replace_in_expr(r, map);
            }
            MlilExpr::FNeg(e, _) => replace_in_expr(e, map),
            MlilExpr::IntToFloat { expr, .. } | MlilExpr::FloatToInt { expr, .. } => {
                replace_in_expr(expr, map);
            }
            MlilExpr::Select { cond, true_val, false_val, .. } => {
                replace_in_expr(cond, map);
                replace_in_expr(true_val, map);
                replace_in_expr(false_val, map);
            }
            MlilExpr::Call { dest, args, .. } => {
                replace_in_expr(dest, map);
                for a in args {
                    replace_in_expr(a, map);
                }
            }
        }
    }

    /// Verify SSA invariants: every variable (version >= 1) is defined exactly
    /// once across the whole function. Returns a list of violating variables.
    #[must_use]
    pub fn verify_ssa(func: &MlilFunction) -> Vec<SsaVar> {
        let mut counts: HashMap<SsaVar, u32> = HashMap::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                match &ai.instr {
                    MlilInstruction::Assign { dest, .. } | MlilInstruction::Phi { dest, .. } => {
                        *counts.entry(dest.clone()).or_insert(0) += 1;
                    }
                    MlilInstruction::Call { ret_vars, .. }
                    | MlilInstruction::SysCall { ret_vars, .. } => {
                        for rv in ret_vars {
                            *counts.entry(rv.clone()).or_insert(0) += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        counts
            .into_iter()
            .filter(|(v, c)| v.version >= 1 && *c > 1)
            .map(|(v, _)| v)
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            MlilAnnotatedInstr, MlilBasicBlock, MlilFunction, MlilInstruction, Size, SsaVar,
        };
        use rustre_core::address::Address;

        fn var(name: &str) -> SsaVar {
            SsaVar::new(name, 0)
        }

        fn assign(name: &str, src: MlilExpr) -> MlilInstruction {
            MlilInstruction::Assign {
                dest: var(name),
                size: Size::QWord,
                src,
            }
        }

        fn const_e(v: u64) -> MlilExpr {
            MlilExpr::Const {
                value: v,
                size: Size::QWord,
            }
        }

        fn var_e(name: &str) -> MlilExpr {
            MlilExpr::Var {
                var: var(name),
                size: Size::QWord,
            }
        }

        fn block(
            id: u32,
            addr: u64,
            instrs: Vec<MlilInstruction>,
            preds: Vec<u32>,
            succs: Vec<u32>,
        ) -> MlilBasicBlock {
            MlilBasicBlock {
                id,
                start: Address::new(addr),
                end: Address::new(addr + instrs.len() as u64),
                instrs: instrs
                    .into_iter()
                    .enumerate()
                    .map(|(i, instr)| MlilAnnotatedInstr {
                        address: Address::new(addr + i as u64),
                        instr,
                    })
                    .collect(),
                predecessors: preds,
                successors: succs,
            }
        }

        /// Build a diamond CFG:  0 -> {1,2} -> 3.  `x` is defined in 1 and 2,
        /// and used in 3 — so block 3 needs a φ for `x`.
        fn diamond() -> MlilFunction {
            let mut f = MlilFunction::new(Address::new(0));
            f.blocks.push(block(
                0,
                0,
                vec![MlilInstruction::CondJump {
                    cond: const_e(1),
                    true_dest: Address::new(10),
                    false_dest: Address::new(20),
                }],
                vec![],
                vec![1, 2],
            ));
            f.blocks.push(block(
                1,
                10,
                vec![
                    assign("x", const_e(1)),
                    MlilInstruction::Jump { dest: const_e(30) },
                ],
                vec![0],
                vec![3],
            ));
            f.blocks.push(block(
                2,
                20,
                vec![
                    assign("x", const_e(2)),
                    MlilInstruction::Jump { dest: const_e(30) },
                ],
                vec![0],
                vec![3],
            ));
            f.blocks.push(block(
                3,
                30,
                vec![
                    assign("y", var_e("x")),
                    MlilInstruction::Ret {
                        values: vec![var_e("y")],
                    },
                ],
                vec![1, 2],
                vec![],
            ));
            f
        }

        #[test]
        fn dom_tree_diamond() {
            let f = diamond();
            let dom = DomTree::build(&f);
            // 0 dominates everything.
            assert!(dom.dominates(0, 1));
            assert!(dom.dominates(0, 3));
            // idom(3) == 0 (neither 1 nor 2 dominates the join).
            assert_eq!(dom.immediate_dominator(3), Some(0));
            assert_eq!(dom.immediate_dominator(1), Some(0));
            assert_eq!(dom.immediate_dominator(0), None);
        }

        #[test]
        fn dominance_frontier_diamond() {
            let f = diamond();
            let dom = DomTree::build(&f);
            let df = DominanceFrontier::compute(&f, &dom);
            // The frontier of both arms is the join block 3.
            assert!(df.of(1).contains(&3));
            assert!(df.of(2).contains(&3));
            // The entry's frontier is empty.
            assert!(df.of(0).is_empty());
            // The join's own frontier is empty.
            assert!(df.of(3).is_empty());
        }

        #[test]
        fn phi_placement_diamond() {
            let f = diamond();
            let dom = DomTree::build(&f);
            let df = DominanceFrontier::compute(&f, &dom);
            let placement = PhiPlacement::compute(&f, &df);
            // `x` is defined in 1 and 2 -> needs a φ in block 3.
            assert!(placement.at(3).contains("x"));
            // `y` defined only in 3 -> no φ.
            assert!(!placement.at(3).contains("y"));
            assert_eq!(placement.total(), 1);
        }

        #[test]
        fn construct_ssa_diamond_inserts_phi() {
            let mut f = diamond();
            let placement = construct_ssa(&mut f);
            assert_eq!(placement.total(), 1);
            // Block 3 must now begin with a φ for x.
            let b3 = f.block_by_id(3).unwrap();
            let first = &b3.instrs[0].instr;
            match first {
                MlilInstruction::Phi { dest, sources } => {
                    assert_eq!(dest.name, "x");
                    assert_eq!(sources.len(), 2);
                    // Both sources must be distinct, non-zero versions.
                    assert!(sources[0].version >= 1);
                    assert!(sources[1].version >= 1);
                    assert_ne!(sources[0].version, sources[1].version);
                }
                other => panic!("expected phi, got {other:?}"),
            }
        }

        #[test]
        fn construct_ssa_unique_versions() {
            let mut f = diamond();
            construct_ssa(&mut f);
            // After renaming, x in block1 and x in block2 must have different
            // versions, and SSA must verify clean.
            let violations = verify_ssa(&f);
            assert!(violations.is_empty(), "ssa violations: {violations:?}");
        }

        #[test]
        fn construct_ssa_use_picks_reaching_def() {
            // Straight line: x = 1; y = x; ret y.  After SSA, the use of x in
            // `y = x` must reference x#1.
            let mut f = MlilFunction::new(Address::new(0));
            f.blocks.push(block(
                0,
                0,
                vec![
                    assign("x", const_e(1)),
                    assign("y", var_e("x")),
                    MlilInstruction::Ret {
                        values: vec![var_e("y")],
                    },
                ],
                vec![],
                vec![],
            ));
            construct_ssa(&mut f);
            let b0 = f.block_by_id(0).unwrap();
            // x defined version 1
            if let MlilInstruction::Assign { dest, .. } = &b0.instrs[0].instr {
                assert_eq!(dest.version, 1);
            } else {
                panic!();
            }
            // y = x#1
            if let MlilInstruction::Assign {
                src: MlilExpr::Var { var, .. },
                ..
            } = &b0.instrs[1].instr
            {
                assert_eq!(var.name, "x");
                assert_eq!(var.version, 1);
            } else {
                panic!("expected y = x#1");
            }
        }

        #[test]
        fn iterated_frontier_nested() {
            // Loop CFG: 0 -> 1 -> 2 -> 1 (back edge) and 2 -> 3.
            let mut f = MlilFunction::new(Address::new(0));
            f.blocks.push(block(
                0,
                0,
                vec![MlilInstruction::Jump { dest: const_e(10) }],
                vec![],
                vec![1],
            ));
            f.blocks.push(block(
                1,
                10,
                vec![
                    assign("i", const_e(0)),
                    MlilInstruction::Jump { dest: const_e(20) },
                ],
                vec![0, 2],
                vec![2],
            ));
            f.blocks.push(block(
                2,
                20,
                vec![
                    assign("i", const_e(1)),
                    MlilInstruction::CondJump {
                        cond: const_e(1),
                        true_dest: Address::new(10),
                        false_dest: Address::new(30),
                    },
                ],
                vec![1],
                vec![1, 3],
            ));
            f.blocks.push(block(
                3,
                30,
                vec![MlilInstruction::Ret { values: vec![] }],
                vec![2],
                vec![],
            ));
            let dom = DomTree::build(&f);
            let df = DominanceFrontier::compute(&f, &dom);
            // Block 1 is a loop header (has back-edge predecessor 2), so 1 is on
            // the dominance frontier of 2 and of 1 itself.
            let mut seed = BTreeSet::new();
            seed.insert(1u32);
            seed.insert(2u32);
            let idf = df.iterated(&seed);
            assert!(idf.contains(&1), "loop header must be in iterated DF");
        }

        #[test]
        fn cse_removes_redundant_pure_expr() {
            // a = b + c;  d = b + c;  -> d becomes copy of a.
            let mut f = MlilFunction::new(Address::new(0));
            let bc = MlilExpr::Add(Box::new(var_e("b")), Box::new(var_e("c")), Size::QWord);
            f.blocks.push(block(
                0,
                0,
                vec![
                    assign("a", bc.clone()),
                    assign("d", bc),
                    MlilInstruction::Ret {
                        values: vec![var_e("a"), var_e("d")],
                    },
                ],
                vec![],
                vec![],
            ));
            let n = common_subexpression_elimination(&mut f);
            assert_eq!(n, 1);
            let b0 = f.block_by_id(0).unwrap();
            // Second assignment must now be `d = a`.
            if let MlilInstruction::Assign {
                src: MlilExpr::Var { var, .. },
                ..
            } = &b0.instrs[1].instr
            {
                assert_eq!(var.name, "a");
            } else {
                panic!("expected d = a after CSE");
            }
        }

        #[test]
        fn cse_keeps_loads_distinct() {
            // Two loads from the same address must NOT be merged (memory may change).
            let mut f = MlilFunction::new(Address::new(0));
            let load = MlilExpr::Load {
                addr: Box::new(var_e("p")),
                size: Size::QWord,
            };
            f.blocks.push(block(
                0,
                0,
                vec![
                    assign("a", load.clone()),
                    assign("d", load),
                    MlilInstruction::Ret { values: vec![] },
                ],
                vec![],
                vec![],
            ));
            let n = common_subexpression_elimination(&mut f);
            assert_eq!(n, 0);
        }

        #[test]
        fn verify_ssa_detects_double_def() {
            let mut f = MlilFunction::new(Address::new(0));
            f.blocks.push(block(
                0,
                0,
                vec![
                    MlilInstruction::Assign {
                        dest: SsaVar::new("x", 1),
                        size: Size::QWord,
                        src: const_e(1),
                    },
                    MlilInstruction::Assign {
                        dest: SsaVar::new("x", 1),
                        size: Size::QWord,
                        src: const_e(2),
                    },
                    MlilInstruction::Ret { values: vec![] },
                ],
                vec![],
                vec![],
            ));
            let violations = verify_ssa(&f);
            assert_eq!(violations.len(), 1);
            assert_eq!(violations[0], SsaVar::new("x", 1));
        }

        #[test]
        fn single_block_no_phi() {
            let mut f = MlilFunction::new(Address::new(0));
            f.blocks.push(block(
                0,
                0,
                vec![
                    assign("x", const_e(5)),
                    MlilInstruction::Ret {
                        values: vec![var_e("x")],
                    },
                ],
                vec![],
                vec![],
            ));
            let placement = construct_ssa(&mut f);
            assert_eq!(placement.total(), 0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enterprise battery — `fold_mlil_expr`, copy-propagation, dead-store
// elimination, trivial-phi elimination.
//
// The MLIL passes are the layer between the lifter and structuring; a wrong
// constant fold or a missed side-effect silently rewrites the program. This
// battery enforces the semantic invariants:
//
//   * **Const-fold truncates to size** — every `Const{size, v}` the folder
//     produces satisfies `v < 2^size.bits()`. (Regression target for the
//     pre-fix bug where `Not(0xFF as u8)` yielded the un-masked
//     `0xFFFF_FFFF_FFFF_FF00`.)
//   * **Algebraic identities** — `x + 0`, `0 + x`, `x - x`, `x ^ x`, `x & x`,
//     `x | 0`, `x * 1`, `1 * x`, `~~x`, `--x`, `x == x`, `x != x`, `x << 0`,
//     `x >> 0`, `x & all_ones`. None of them should ever survive a fold.
//   * **Shift saturation** — `x << count` with `count ≥ size.bits()` MUST be
//     `0`. The previous implementation used `wrapping_shl` which returns
//     `x << (count % width) = x` for `count = width`, a silent miscompile.
//   * **Side-effect safety** — `Sub(Load, Load)`, `Mul(Load, 0)`, `Xor(Call,
//     Call)` etc. must NOT be folded to `0` even when both subtrees are
//     structurally equal: the load or call must survive.
//   * **Copy-prop transitive closure** — chains `a = b; c = a; d = c` must
//     resolve all the way to the root in a single `propagate_copies` call.
//   * **Dead-store side-effect preservation** — an assignment whose RHS
//     hides a `Load`/`Call` deep in the expression tree must NOT be removed
//     even when its `dest` is unused.
//   * **Fuzz robustness** — random expressions over 5000 iterations must
//     fold without panicking.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod enterprise_battery {
    use super::*;

    /// Deterministic LCG (Knuth MMIX).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    fn c(v: u64, s: Size) -> MlilExpr {
        MlilExpr::Const { value: v, size: s }
    }
    fn v(name: &str, ver: u32, s: Size) -> MlilExpr {
        MlilExpr::Var {
            var: SsaVar::new(name, ver),
            size: s,
        }
    }
    fn b(e: MlilExpr) -> Box<MlilExpr> {
        Box::new(e)
    }

    // ── Const-fold truncation to size ─────────────────────────────────────

    /// Every folded `Const{size}` must satisfy `value < 2^size.bits()`. This
    /// is the invariant that broke when `Not(0xFF as u8)` returned the
    /// un-masked `0xFFFF_FFFF_FFFF_FF00` — a value too wide for `u8`.
    #[test]
    fn fold_const_is_always_truncated_to_size() {
        let cases: &[(MlilExpr, Size)] = &[
            (
                MlilExpr::Not(b(c(0xFF, Size::Byte)), Size::Byte),
                Size::Byte,
            ),
            (
                MlilExpr::Add(b(c(0xFF, Size::Byte)), b(c(1, Size::Byte)), Size::Byte),
                Size::Byte,
            ),
            (
                MlilExpr::Sub(b(c(0, Size::Byte)), b(c(1, Size::Byte)), Size::Byte),
                Size::Byte,
            ),
            (
                MlilExpr::Mul(b(c(0xFF, Size::Byte)), b(c(0xFF, Size::Byte)), Size::Byte),
                Size::Byte,
            ),
            (MlilExpr::Neg(b(c(1, Size::Word)), Size::Word), Size::Word),
            (
                MlilExpr::Not(b(c(0, Size::DWord)), Size::DWord),
                Size::DWord,
            ),
            (
                MlilExpr::Shl(b(c(0xFFFF, Size::Word)), b(c(8, Size::Byte)), Size::Word),
                Size::Word,
            ),
        ];
        for (e, s) in cases {
            let (folded, _) = fold_mlil_expr(e.clone());
            let val = folded.is_const().expect("must fold to a Const");
            let bits = s.bits();
            let upper = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            assert!(
                val <= upper,
                "value {val:#x} exceeds size {s:?} (max {upper:#x}) — truncation invariant violated"
            );
        }
    }

    /// `Shl` with `count ≥ width` MUST yield 0. The previous `wrapping_shl`
    /// used `count % width`, so `1u64 << 64` came back as 1 (silent miscompile).
    #[test]
    fn fold_shift_saturates_at_width() {
        // 1 << 64 (QWord): width is exactly the bit count → result is 0.
        let e = MlilExpr::Shl(b(c(1, Size::QWord)), b(c(64, Size::Byte)), Size::QWord);
        let (folded, _) = fold_mlil_expr(e);
        assert_eq!(
            folded.is_const(),
            Some(0),
            "Shl by ≥width must saturate to 0"
        );
        // 0xFF << 8 (Byte): saturates to 0 too.
        let e = MlilExpr::Shl(b(c(0xFF, Size::Byte)), b(c(8, Size::Byte)), Size::Byte);
        let (folded, _) = fold_mlil_expr(e);
        assert_eq!(folded.is_const(), Some(0));
        // Shr same property.
        let e = MlilExpr::Shr(b(c(0xFFFF, Size::Word)), b(c(16, Size::Byte)), Size::Word);
        let (folded, _) = fold_mlil_expr(e);
        assert_eq!(folded.is_const(), Some(0));
    }

    /// `Sar` of negative value preserves the sign through truncation.
    #[test]
    fn fold_sar_sign_extends_inside_size() {
        // 0xFF as i8 is -1; -1 >> 1 = -1 (arithmetic shift); back to u8 = 0xFF.
        let e = MlilExpr::Sar(b(c(0xFF, Size::Byte)), b(c(1, Size::Byte)), Size::Byte);
        let (folded, _) = fold_mlil_expr(e);
        assert_eq!(folded.is_const(), Some(0xFF));
        // 0x80 as i8 is -128; -128 >> 7 = -1 → 0xFF.
        let e = MlilExpr::Sar(b(c(0x80, Size::Byte)), b(c(7, Size::Byte)), Size::Byte);
        let (folded, _) = fold_mlil_expr(e);
        assert_eq!(folded.is_const(), Some(0xFF));
    }

    // ── Algebraic identities ──────────────────────────────────────────────

    #[test]
    fn fold_additive_identities() {
        let x = v("x", 0, Size::QWord);
        // x + 0 = x
        let (f, _) = fold_mlil_expr(MlilExpr::Add(
            b(x.clone()),
            b(c(0, Size::QWord)),
            Size::QWord,
        ));
        assert_eq!(f, x);
        // 0 + x = x
        let (f, _) = fold_mlil_expr(MlilExpr::Add(
            b(c(0, Size::QWord)),
            b(x.clone()),
            Size::QWord,
        ));
        assert_eq!(f, x);
        // x - 0 = x
        let (f, _) = fold_mlil_expr(MlilExpr::Sub(
            b(x.clone()),
            b(c(0, Size::QWord)),
            Size::QWord,
        ));
        assert_eq!(f, x);
        // x - x = 0
        let (f, _) = fold_mlil_expr(MlilExpr::Sub(b(x.clone()), b(x), Size::QWord));
        assert_eq!(f.is_const(), Some(0));
    }

    #[test]
    fn fold_logical_identities() {
        let x = v("x", 0, Size::DWord);
        // x ^ x = 0
        let (f, _) = fold_mlil_expr(MlilExpr::Xor(b(x.clone()), b(x.clone()), Size::DWord));
        assert_eq!(f.is_const(), Some(0));
        // x & x = x
        let (f, _) = fold_mlil_expr(MlilExpr::And(b(x.clone()), b(x.clone()), Size::DWord));
        assert_eq!(f, x);
        // x | x = x
        let (f, _) = fold_mlil_expr(MlilExpr::Or(b(x.clone()), b(x.clone()), Size::DWord));
        assert_eq!(f, x);
        // x ^ 0 = x
        let (f, _) = fold_mlil_expr(MlilExpr::Xor(
            b(x.clone()),
            b(c(0, Size::DWord)),
            Size::DWord,
        ));
        assert_eq!(f, x);
        // x & 0xFFFFFFFF = x (Size::DWord all-ones)
        let (f, _) = fold_mlil_expr(MlilExpr::And(
            b(x.clone()),
            b(c(0xFFFFFFFF, Size::DWord)),
            Size::DWord,
        ));
        assert_eq!(f, x);
    }

    #[test]
    fn fold_multiplicative_identities() {
        let x = v("x", 0, Size::QWord);
        // x * 1 = x
        let (f, _) = fold_mlil_expr(MlilExpr::Mul(
            b(x.clone()),
            b(c(1, Size::QWord)),
            Size::QWord,
        ));
        assert_eq!(f, x);
        // 1 * x = x
        let (f, _) = fold_mlil_expr(MlilExpr::Mul(
            b(c(1, Size::QWord)),
            b(x.clone()),
            Size::QWord,
        ));
        assert_eq!(f, x);
        // x * 0 = 0
        let (f, _) = fold_mlil_expr(MlilExpr::Mul(
            b(x),
            b(c(0, Size::QWord)),
            Size::QWord,
        ));
        assert_eq!(f.is_const(), Some(0));
    }

    #[test]
    fn fold_shift_identities() {
        let x = v("x", 0, Size::QWord);
        let (f, _) = fold_mlil_expr(MlilExpr::Shl(
            b(x.clone()),
            b(c(0, Size::Byte)),
            Size::QWord,
        ));
        assert_eq!(f, x);
        let (f, _) = fold_mlil_expr(MlilExpr::Shr(
            b(x.clone()),
            b(c(0, Size::Byte)),
            Size::QWord,
        ));
        assert_eq!(f, x);
    }

    #[test]
    fn fold_unary_double_inverses() {
        let x = v("x", 0, Size::QWord);
        // -(-x) = x
        let (f, _) = fold_mlil_expr(MlilExpr::Neg(
            b(MlilExpr::Neg(b(x.clone()), Size::QWord)),
            Size::QWord,
        ));
        assert_eq!(f, x);
        // ~(~x) = x
        let (f, _) = fold_mlil_expr(MlilExpr::Not(
            b(MlilExpr::Not(b(x.clone()), Size::QWord)),
            Size::QWord,
        ));
        assert_eq!(f, x);
    }

    #[test]
    fn fold_compare_identities() {
        let x = v("x", 0, Size::QWord);
        let (f, _) = fold_mlil_expr(MlilExpr::CmpEq(b(x.clone()), b(x.clone())));
        assert_eq!(f.is_const(), Some(1));
        let (f, _) = fold_mlil_expr(MlilExpr::CmpNe(b(x.clone()), b(x)));
        assert_eq!(f.is_const(), Some(0));
    }

    // ── Side-effect safety ────────────────────────────────────────────────

    /// `Sub(Load(p), Load(p))` is *not* `0` — the loads may fault and must
    /// both be evaluated. This is the soundness guard for every "x - x = 0"
    /// style identity in the folder.
    #[test]
    fn fold_does_not_break_load_side_effects() {
        let load = || MlilExpr::Load {
            addr: b(v("p", 0, Size::QWord)),
            size: Size::QWord,
        };
        // x - x = 0 must NOT trigger when x is a Load.
        let e = MlilExpr::Sub(b(load()), b(load()), Size::QWord);
        let (folded, _) = fold_mlil_expr(e);
        // The folded expression must still contain a Load.
        let mut has_load = false;
        let mut stack = vec![&folded];
        while let Some(node) = stack.pop() {
            if matches!(node, MlilExpr::Load { .. }) {
                has_load = true;
                break;
            }
            match node {
                MlilExpr::Add(l, r, _)
                | MlilExpr::Sub(l, r, _)
                | MlilExpr::Mul(l, r, _)
                | MlilExpr::Xor(l, r, _)
                | MlilExpr::And(l, r, _)
                | MlilExpr::Or(l, r, _) => {
                    stack.push(l);
                    stack.push(r);
                }
                _ => {}
            }
        }
        assert!(
            has_load,
            "Sub of two Loads was folded away, dropping the side effect"
        );
    }

    #[test]
    fn fold_mul_by_zero_preserves_load_side_effect() {
        let load = MlilExpr::Load {
            addr: b(v("p", 0, Size::QWord)),
            size: Size::QWord,
        };
        // Mul(Load, 0) must NOT fold to Const(0) — the load must run.
        let e = MlilExpr::Mul(b(load), b(c(0, Size::QWord)), Size::QWord);
        let (folded, _) = fold_mlil_expr(e);
        assert!(
            !matches!(folded, MlilExpr::Const { value: 0, .. }),
            "Mul(Load, 0) was folded to 0, dropping the load side effect"
        );
    }

    // ── Copy-prop transitive closure ──────────────────────────────────────

    /// `a = b; c = a; d = c` must end with every use rewritten to `b`
    /// after a single `propagate_copies` pass. Previously only one hop
    /// per call was substituted.
    #[test]
    fn copy_prop_resolves_transitive_chain_in_one_pass() {
        use MlilInstruction::*;
        let addr = Address::new(0x1000);
        let ai = |i: MlilInstruction| MlilAnnotatedInstr {
            address: addr,
            instr: i,
        };
        let blk = MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x1100),
            instrs: vec![
                ai(Assign {
                    dest: SsaVar::new("a", 1),
                    size: Size::QWord,
                    src: v("b", 0, Size::QWord),
                }),
                ai(Assign {
                    dest: SsaVar::new("c", 1),
                    size: Size::QWord,
                    src: v("a", 1, Size::QWord),
                }),
                ai(Assign {
                    dest: SsaVar::new("d", 1),
                    size: Size::QWord,
                    src: v("c", 1, Size::QWord),
                }),
                // `out = d` — after copy-prop should read `b`.
                ai(Assign {
                    dest: SsaVar::new("out", 1),
                    size: Size::QWord,
                    src: v("d", 1, Size::QWord),
                }),
            ],
            predecessors: vec![],
            successors: vec![],
        };
        let mut f = MlilFunction::new(addr);
        f.blocks.push(blk);
        let _ = propagate_copies(&mut f);
        // The fourth assignment should now read `b`, not `d`.
        let last = &f.blocks[0].instrs[3].instr;
        if let MlilInstruction::Assign {
            src: MlilExpr::Var { var, .. },
            ..
        } = last
        {
            assert_eq!(
                var.name, "b",
                "expected transitive copy-prop to land on b, got {var}"
            );
        } else {
            panic!("unexpected shape for last instr: {last:?}");
        }
    }

    // ── Dead-store side-effect preservation ───────────────────────────────

    /// An assignment whose `dest` is dead but whose RHS contains a `Load`
    /// deep inside an arithmetic tree must NOT be eliminated.
    #[test]
    fn dead_store_keeps_load_buried_in_expression() {
        use MlilInstruction::*;
        let addr = Address::new(0x2000);
        let ai = |i: MlilInstruction| MlilAnnotatedInstr {
            address: addr,
            instr: i,
        };
        let load = MlilExpr::Load {
            addr: b(v("p", 0, Size::QWord)),
            size: Size::QWord,
        };
        // dead = (load + 1) — `dead` is never used, but the Load is observable.
        let rhs = MlilExpr::Add(b(load), b(c(1, Size::QWord)), Size::QWord);
        let mut f = MlilFunction::new(addr);
        f.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr,
            end: Address::new(0x2100),
            instrs: vec![ai(Assign {
                dest: SsaVar::new("dead", 1),
                size: Size::QWord,
                src: rhs,
            })],
            predecessors: vec![],
            successors: vec![],
        });
        let removed = eliminate_dead_stores(&mut f);
        assert_eq!(removed, 0, "assignment hiding a Load must not be deleted");
        assert_eq!(f.blocks[0].instrs.len(), 1);
    }

    // ── Fuzz robustness ───────────────────────────────────────────────────

    /// Build a random expression of bounded depth and fold it. The folder
    /// must always terminate and never panic, even when sizes are randomly
    /// mixed and shift counts are out of range.
    fn random_expr(rng: &mut Lcg, depth: u32) -> MlilExpr {
        if depth == 0 || rng.next().is_multiple_of(3) {
            // Leaf: const or var.
            if rng.next() & 1 == 0 {
                let sizes = [Size::Byte, Size::Word, Size::DWord, Size::QWord];
                let size = sizes[(rng.next() as usize) & 3];
                // Respect the IR contract on leaves: a `Const{size, v}` must
                // satisfy `v < 2^size.bits()`. Producing malformed input would
                // garbage-in/garbage-out and mask real folder bugs.
                let bits = size.bits();
                let raw = rng.next();
                let value = if bits >= 64 {
                    raw
                } else {
                    raw & ((1u64 << bits) - 1)
                };
                MlilExpr::Const { value, size }
            } else {
                let name = format!("v{}", rng.next() & 0xf);
                let ver = (rng.next() & 0x7) as u32;
                let sizes = [Size::Byte, Size::Word, Size::DWord, Size::QWord];
                MlilExpr::Var {
                    var: SsaVar::new(name, ver),
                    size: sizes[(rng.next() as usize) & 3],
                }
            }
        } else {
            let s = [Size::Byte, Size::Word, Size::DWord, Size::QWord][(rng.next() as usize) & 3];
            let l = b(random_expr(rng, depth - 1));
            let r = b(random_expr(rng, depth - 1));
            match rng.next() % 12 {
                0 => MlilExpr::Add(l, r, s),
                1 => MlilExpr::Sub(l, r, s),
                2 => MlilExpr::Mul(l, r, s),
                3 => MlilExpr::And(l, r, s),
                4 => MlilExpr::Or(l, r, s),
                5 => MlilExpr::Xor(l, r, s),
                6 => MlilExpr::Shl(l, r, s),
                7 => MlilExpr::Shr(l, r, s),
                8 => MlilExpr::Sar(l, r, s),
                9 => MlilExpr::Neg(l, s),
                10 => MlilExpr::Not(l, s),
                _ => MlilExpr::CmpEq(l, r),
            }
        }
    }

    #[test]
    fn fuzz_fold_never_panics_and_truncates_constants() {
        let mut rng = Lcg(0xdead_beef_cafe_babe);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut first_fail: Option<(u64, String)> = None;
        for i in 0..5_000u64 {
            let e = random_expr(&mut rng, 6);
            let e_dbg = format!("{e:?}");
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (folded, _) = fold_mlil_expr(e);
                if let MlilExpr::Const { value, size } = folded {
                    let bits = size.bits();
                    let upper = if bits >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << bits) - 1
                    };
                    assert!(value <= upper, "fuzz: const {value:#x} > size {size:?} max");
                }
            }));
            if let Err(p) = r {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&'static str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "<unknown panic>".to_string());
                first_fail = Some((i, format!("{msg}\n  expr={e_dbg}")));
                break;
            }
        }
        std::panic::set_hook(prev);
        assert!(first_fail.is_none(), "fold panicked: {first_fail:?}");
    }
}
