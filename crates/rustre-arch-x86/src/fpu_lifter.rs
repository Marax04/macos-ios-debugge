//! x87 FPU instruction lifting.
//!
//! Models the x87 FPU as an 8-deep stack of 80-bit extended-precision floats.
//! Every FPU instruction is translated to a set of IL [`Effect`]s that push,
//!
//! # Layer distinction
//!
//! This module is the **x87 IL lifter**: it translates x87 instructions into
//! [`rustre_il_lift::Effect`] sequences that model the 8-deep FPU stack,
//! the `fpu_c0`–`fpu_c3` condition-code virtual registers, and FPU status-word
//! (`fpu_sw`) updates.
//!
//! For **textual decoding** — mapping raw (D8–DF escape byte, `ModRM`) pairs
//! to mnemonic strings, operand text, and semantic categories without any IL
//! dependency — see [`crate::x87`].  The two modules are complementary.
//! pop, or modify stack entries, update the FPU status-word flags, or produce
//! memory reads/writes.
//!
//! # Stack model
//! The stack top is always `ST(0)`.  Stack registers are named `st0`..`st7`
//! in the IL.  Push / pop are modelled as explicit register moves with a
//! stack-pointer update via [`Effect::Intrinsic { name: "fpu_push" }`] and
//! `"fpu_pop"` stubs (keeping the IL linear).
//!
//! # Flag model
//! The x87 condition flags C0/C1/C2/C3 are modelled as virtual registers
//! `fpu_c0`..`fpu_c3`.  The FPU status word is `fpu_sw`.
//!
//! # Dispatch status (NOT wired into `src/lift.rs`)
//!
//! This module is **not** part of the active lifting path. `src/lift.rs`
//! dispatches every mnemonic directly via its own native match arms (added
//! across several hardening passes), and does not call into this module.
//! It is intentionally retained -- not dead code pending removal -- per
//! explicit user instruction, as a possible future cross-validation /
//! second-opinion decode path independent of `lift.rs`.

use rustre_il_lift::{Effect, IrExpr};

// ─────────────────────────────────────────────────────────────────────────────
// FpuFlags
// ─────────────────────────────────────────────────────────────────────────────

/// The four condition-code bits of the x87 FPU status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FpuFlag {
    /// C0 (also CF in integer compare ops).
    C0,
    /// C1 (stack-fault / rounding bit).
    C1,
    /// C2 (indefinite / unordered bit).
    C2,
    /// C3 (also ZF in integer compare ops).
    C3,
}

impl FpuFlag {
    /// The virtual register name used in IL for this flag.
    #[must_use]
    pub fn reg_name(self) -> &'static str {
        match self {
            Self::C0 => "fpu_c0",
            Self::C1 => "fpu_c1",
            Self::C2 => "fpu_c2",
            Self::C3 => "fpu_c3",
        }
    }

    /// `IrExpr::Reg` shorthand.
    #[must_use]
    pub fn expr(self) -> IrExpr {
        IrExpr::Reg(self.reg_name().to_string())
    }
}

/// A set of [`FpuFlag`]s, used to declare which flags an instruction modifies.
#[derive(Debug, Clone, Default)]
pub struct FpuFlags {
    pub c0: bool,
    pub c1: bool,
    pub c2: bool,
    pub c3: bool,
}

impl FpuFlags {
    /// All four flags set.
    #[must_use]
    pub fn all() -> Self {
        Self {
            c0: true,
            c1: true,
            c2: true,
            c3: true,
        }
    }

    /// No flags set.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// C0 and C3 only (used by FCOM/FUCOM).
    #[must_use]
    pub fn compare() -> Self {
        Self {
            c0: true,
            c1: false,
            c2: true,
            c3: true,
        }
    }

    /// Only C1 (stack fault).
    #[must_use]
    pub fn c1_only() -> Self {
        Self {
            c0: false,
            c1: true,
            c2: false,
            c3: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FpuStack
// ─────────────────────────────────────────────────────────────────────────────

/// Models the x87 FPU 8-deep register stack.
///
/// The stack is represented as a fixed-size ring buffer with a top pointer.
/// [`FpuStack::push`] / [`FpuStack::pop`] return [`Effect`]s that encode the
/// operation in the IL.
#[derive(Debug, Clone)]
pub struct FpuStack {
    /// Current stack top index (0–7).
    top: u8,
    /// Whether each slot is in use.
    live: [bool; 8],
}

impl FpuStack {
    /// Create an empty FPU stack (all tags empty, TOP = 0).
    #[must_use]
    pub fn new() -> Self {
        Self {
            top: 0,
            live: [false; 8],
        }
    }

    /// Returns the current stack-top index.
    #[must_use]
    pub fn top(&self) -> u8 {
        self.top
    }

    /// Physical register index for ST(n).
    #[must_use]
    pub fn phys_idx(&self, st_n: u8) -> u8 {
        (self.top + st_n) & 7
    }

    /// Register name for ST(n), e.g. `"st0"`.
    #[must_use]
    pub fn st_name(&self, st_n: u8) -> String {
        format!("st{st_n}")
    }

    /// `IrExpr` for ST(n).
    #[must_use]
    pub fn st_expr(&self, st_n: u8) -> IrExpr {
        IrExpr::Reg(self.st_name(st_n))
    }

    /// Emit effects for a push (FLDXX): decrements TOP, marks new ST(0) live.
    ///
    /// Returns a `[fpu_push]` intrinsic effect.
    #[must_use]
    pub fn push_effects(&mut self, value: IrExpr) -> Vec<Effect> {
        self.top = self.top.wrapping_sub(1) & 7;
        self.live[self.top as usize] = true;
        vec![
            Effect::Intrinsic {
                name: "fpu_push".to_string(),
                args: vec![value.clone()],
            },
            Effect::RegWrite {
                reg: "st0".to_string(),
                value,
            },
        ]
    }

    /// Emit effects for a pop (FSTP): marks current ST(0) empty, increments TOP.
    ///
    /// Returns a `[fpu_pop]` intrinsic effect.
    #[must_use]
    pub fn pop_effects(&mut self) -> Vec<Effect> {
        self.live[self.top as usize] = false;
        self.top = (self.top + 1) & 7;
        vec![Effect::Intrinsic {
            name: "fpu_pop".to_string(),
            args: vec![],
        }]
    }

    /// Returns `true` if ST(n) is live.
    #[must_use]
    pub fn is_live(&self, st_n: u8) -> bool {
        self.live[self.phys_idx(st_n) as usize]
    }
}

impl Default for FpuStack {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FpuOpKind
// ─────────────────────────────────────────────────────────────────────────────

/// High-level kind of an x87 FPU operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FpuOpKind {
    /// ST(0) = ST(0) op src
    BinOp,
    /// ST(dst) = ST(dst) op ST(0)
    BinOpReverse,
    /// ST(0) = src
    Load,
    /// mem/int = ST(0)
    Store,
    /// ST(0) = ST(0) op ST(0) + pop
    BinOpPop,
    /// Compare ST(0) with src, set flags
    Compare,
    /// Unary op on ST(0)
    UnaryOp,
    /// No-op / control
    Control,
    /// Integer load/store
    IntLoad,
    IntStore,
}

// ─────────────────────────────────────────────────────────────────────────────
// FpuInstrDesc
// ─────────────────────────────────────────────────────────────────────────────

/// Describes a decoded x87 FPU instruction.
#[derive(Debug, Clone)]
pub struct FpuInstrDesc {
    /// Mnemonic (e.g. `"fadd"`, `"fld"`, `"fstp"`).
    pub mnemonic: String,
    /// Which ST(n) register is the implicit destination (usually 0).
    pub st_dst: u8,
    /// Which ST(n) register is the source (for register-register forms).
    pub st_src: Option<u8>,
    /// Whether the operation pops the stack.
    pub pops: bool,
    /// Whether the operation pops twice (e.g. FCOMPP).
    pub pops_twice: bool,
    /// Memory operand address, if any.
    pub mem_addr: Option<IrExpr>,
    /// Size of memory operand in bytes (4 = float, 8 = double, 10 = extended,
    /// 2/4/8 = integer, 28/108 = env).
    pub mem_size: Option<u8>,
    /// The operation kind.
    pub kind: FpuOpKind,
    /// Flags modified by this instruction.
    pub flags: FpuFlags,
}

// ─────────────────────────────────────────────────────────────────────────────
// FpuLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Translates x87 FPU instructions to IL effects.
pub struct FpuLifter {
    stack: FpuStack,
}

impl FpuLifter {
    /// Create a new lifter with an empty FPU stack.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack: FpuStack::new(),
        }
    }

    /// Access the current stack state.
    #[must_use]
    pub fn stack(&self) -> &FpuStack {
        &self.stack
    }

    /// Emit IL effects for `desc`.
    #[must_use]
    pub fn lift(&mut self, desc: &FpuInstrDesc) -> Vec<Effect> {
        let mut effects = Vec::new();

        match &desc.mnemonic.to_ascii_lowercase()[..] {
            // ── FLD variants ─────────────────────────────────────────────────
            "fld" | "flds" | "fldl" | "fldt" => {
                let src = if let Some(addr) = &desc.mem_addr {
                    let sz: u8 = desc.mem_size.unwrap_or(4);
                    let dest = "__fpu_tmp".to_string();
                    let addr_e: IrExpr = addr.clone();
                    effects.push(Effect::MemRead {
                        addr: addr_e,
                        dest: dest.clone(),
                        size: sz,
                    });
                    IrExpr::Reg(dest)
                } else if let Some(sn) = desc.st_src {
                    self.stack.st_expr(sn)
                } else {
                    IrExpr::Undef
                };
                effects.extend(self.stack.push_effects(src));
            }
            // ── FILD (integer load) ───────────────────────────────────────────
            "fild" | "filds" | "fildl" | "fildll" => {
                let addr = desc.mem_addr.clone().unwrap_or(IrExpr::Undef);
                let sz: u8 = desc.mem_size.unwrap_or(2);
                let dest = "__fpu_int_tmp".to_string();
                effects.push(Effect::MemRead {
                    addr,
                    dest: dest.clone(),
                    size: sz,
                });
                let cvt = IrExpr::Reg(dest);
                effects.extend(self.stack.push_effects(cvt));
                effects.push(Effect::Intrinsic {
                    name: "fild_cvt_int_to_float".to_string(),
                    args: vec![],
                });
            }
            // ── FST / FSTP (store) ────────────────────────────────────────────
            "fst" | "fsts" | "fstl" | "fstt" => {
                let val = self.stack.st_expr(desc.st_dst);
                if let Some(addr) = &desc.mem_addr {
                    let sz: u8 = desc.mem_size.unwrap_or(4);
                    let addr_e: IrExpr = addr.clone();
                    effects.push(Effect::MemWrite {
                        addr: addr_e,
                        value: val,
                        size: sz,
                    });
                } else if let Some(sn) = desc.st_src {
                    effects.push(Effect::RegWrite {
                        reg: self.stack.st_name(sn),
                        value: val,
                    });
                }
            }
            "fstp" | "fstps" | "fstpl" | "fstpt" => {
                let val = self.stack.st_expr(0);
                if let Some(addr) = &desc.mem_addr {
                    let sz: u8 = desc.mem_size.unwrap_or(4);
                    let addr_e: IrExpr = addr.clone();
                    effects.push(Effect::MemWrite {
                        addr: addr_e,
                        value: val,
                        size: sz,
                    });
                } else if let Some(sn) = desc.st_src {
                    effects.push(Effect::RegWrite {
                        reg: self.stack.st_name(sn),
                        value: val,
                    });
                }
                effects.extend(self.stack.pop_effects());
            }
            // ── FIST / FISTP (integer store) ──────────────────────────────────
            "fist" | "fistp" => {
                let val = self.stack.st_expr(0);
                effects.push(Effect::Intrinsic {
                    name: "fistp_cvt_float_to_int".to_string(),
                    args: vec![val.clone()],
                });
                if let Some(addr) = &desc.mem_addr {
                    let sz: u8 = desc.mem_size.unwrap_or(2);
                    let addr_e: IrExpr = addr.clone();
                    effects.push(Effect::MemWrite {
                        addr: addr_e,
                        value: IrExpr::Reg("__fpu_int_out".to_string()),
                        size: sz,
                    });
                }
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            // ── FADD / FADDP ──────────────────────────────────────────────────
            "fadd" | "faddp" | "fadds" | "faddl" => {
                let (a, b) = self.binop_srcs(desc);
                let result = IrExpr::Add(Box::new(a), Box::new(b));
                effects.push(Effect::RegWrite {
                    reg: self.stack.st_name(desc.st_dst),
                    value: result,
                });
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            // ── FIADD ─────────────────────────────────────────────────────────
            "fiadd" => {
                let a = self.stack.st_expr(0);
                let b = desc
                    .mem_addr
                    .clone()
                    .map_or(IrExpr::Undef, |addr| IrExpr::Deref(Box::new(addr), desc.mem_size.unwrap_or(2)));
                effects.push(Effect::RegWrite {
                    reg: "st0".to_string(),
                    value: IrExpr::Add(Box::new(a), Box::new(b)),
                });
            }
            // ── FSUB / FSUBR ──────────────────────────────────────────────────
            "fsub" | "fsubp" | "fsubs" | "fsubl" => {
                let (a, b) = self.binop_srcs(desc);
                let result = IrExpr::Sub(Box::new(a), Box::new(b));
                effects.push(Effect::RegWrite {
                    reg: self.stack.st_name(desc.st_dst),
                    value: result,
                });
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            "fsubr" | "fsubrp" => {
                let (a, b) = self.binop_srcs(desc);
                let result = IrExpr::Sub(Box::new(b), Box::new(a));
                effects.push(Effect::RegWrite {
                    reg: self.stack.st_name(desc.st_dst),
                    value: result,
                });
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            // ── FMUL / FDIV ────────────────────────────────────────────────────
            "fmul" | "fmulp" | "fmuls" | "fmull" => {
                let (a, b) = self.binop_srcs(desc);
                let result = IrExpr::Mul(Box::new(a), Box::new(b));
                effects.push(Effect::RegWrite {
                    reg: self.stack.st_name(desc.st_dst),
                    value: result,
                });
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            "fdiv" | "fdivp" | "fdivs" | "fdivl" => {
                let (a, b) = self.binop_srcs(desc);
                effects.push(Effect::Intrinsic {
                    name: "fdiv".to_string(),
                    args: vec![self.stack.st_expr(desc.st_dst), a, b],
                });
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            "fdivr" | "fdivrp" => {
                let (a, b) = self.binop_srcs(desc);
                effects.push(Effect::Intrinsic {
                    name: "fdivr".to_string(),
                    args: vec![self.stack.st_expr(desc.st_dst), b, a],
                });
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
            }
            // ── FCOM / FCOMP / FCOMPP ─────────────────────────────────────────
            "fcom" | "fcoml" | "fcoms" | "fcomp" | "fcompl" | "fcomps" | "fcompp" => {
                let a = self.stack.st_expr(0);
                let b = if let Some(sn) = desc.st_src {
                    self.stack.st_expr(sn)
                } else if let Some(addr) = &desc.mem_addr {
                    let ae: IrExpr = addr.clone();
                    IrExpr::Deref(Box::new(ae), desc.mem_size.unwrap_or(4_u8))
                } else {
                    self.stack.st_expr(1)
                };
                effects.push(Effect::Intrinsic {
                    name: "fcom".to_string(),
                    args: vec![a, b],
                });
                emit_flag_set(&mut effects, FpuFlag::C0, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C2, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C3, IrExpr::Undef);
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
                if desc.pops_twice {
                    effects.extend(self.stack.pop_effects());
                }
            }
            // ── FUCOM / FUCOMP ─────────────────────────────────────────────────
            "fucom" | "fucomp" | "fucompp" => {
                let a = self.stack.st_expr(0);
                let b = desc
                    .st_src
                    .map(|s| self.stack.st_expr(s))
                    .unwrap_or(self.stack.st_expr(1));
                effects.push(Effect::Intrinsic {
                    name: "fucom".to_string(),
                    args: vec![a, b],
                });
                emit_flag_set(&mut effects, FpuFlag::C0, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C2, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C3, IrExpr::Undef);
                if desc.pops {
                    effects.extend(self.stack.pop_effects());
                }
                if desc.pops_twice {
                    effects.extend(self.stack.pop_effects());
                }
            }
            // ── FCHS / FABS ────────────────────────────────────────────────────
            "fchs" => {
                let val = self.stack.st_expr(0);
                effects.push(Effect::RegWrite {
                    reg: "st0".to_string(),
                    value: IrExpr::Sub(Box::new(IrExpr::Const(0)), Box::new(val)),
                });
            }
            "fabs" => {
                effects.push(Effect::Intrinsic {
                    name: "fabs".to_string(),
                    args: vec![self.stack.st_expr(0)],
                });
            }
            // ── FSQRT ─────────────────────────────────────────────────────────
            "fsqrt" => {
                effects.push(Effect::Intrinsic {
                    name: "fsqrt".to_string(),
                    args: vec![self.stack.st_expr(0)],
                });
            }
            // ── FSIN / FCOS ────────────────────────────────────────────────────
            "fsin" => {
                effects.push(Effect::Intrinsic {
                    name: "fsin".to_string(),
                    args: vec![self.stack.st_expr(0)],
                });
            }
            "fcos" => {
                effects.push(Effect::Intrinsic {
                    name: "fcos".to_string(),
                    args: vec![self.stack.st_expr(0)],
                });
            }
            // ── FYL2X / FPTAN / FPATAN ─────────────────────────────────────────
            "fyl2x" => {
                effects.push(Effect::Intrinsic {
                    name: "fyl2x".to_string(),
                    args: vec![self.stack.st_expr(0), self.stack.st_expr(1)],
                });
                effects.extend(self.stack.pop_effects());
            }
            "fptan" => {
                effects.push(Effect::Intrinsic {
                    name: "fptan".to_string(),
                    args: vec![self.stack.st_expr(0)],
                });
                // FPTAN pushes 1.0 onto the stack
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Const(0x3ff0_0000_0000_0000)),
                );
            }
            "fpatan" => {
                effects.push(Effect::Intrinsic {
                    name: "fpatan".to_string(),
                    args: vec![self.stack.st_expr(0), self.stack.st_expr(1)],
                });
                effects.extend(self.stack.pop_effects());
            }
            // ── FXAM / FTST ────────────────────────────────────────────────────
            "fxam" => {
                effects.push(Effect::Intrinsic {
                    name: "fxam".to_string(),
                    args: vec![self.stack.st_expr(0)],
                });
                emit_flag_set(&mut effects, FpuFlag::C0, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C1, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C2, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C3, IrExpr::Undef);
            }
            "ftst" => {
                let a = self.stack.st_expr(0);
                effects.push(Effect::Intrinsic {
                    name: "ftst".to_string(),
                    args: vec![a],
                });
                emit_flag_set(&mut effects, FpuFlag::C0, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C2, IrExpr::Undef);
                emit_flag_set(&mut effects, FpuFlag::C3, IrExpr::Undef);
            }
            // ── FLDZ / FLD1 / FLDPI etc. (constant loads) ─────────────────────
            "fldz" => {
                effects.extend(self.stack.push_effects(IrExpr::Const(0)));
            }
            "fld1" => {
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Const(0x3ff0_0000_0000_0000)),
                );
            }
            "fldpi" => {
                effects.push(Effect::Intrinsic {
                    name: "fldpi".to_string(),
                    args: vec![],
                });
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Reg("fpu_const_pi".to_string())),
                );
            }
            "fldl2e" => {
                effects.push(Effect::Intrinsic {
                    name: "fldl2e".to_string(),
                    args: vec![],
                });
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Reg("fpu_const_l2e".to_string())),
                );
            }
            "fldl2t" => {
                effects.push(Effect::Intrinsic {
                    name: "fldl2t".to_string(),
                    args: vec![],
                });
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Reg("fpu_const_l2t".to_string())),
                );
            }
            "fldlg2" => {
                effects.push(Effect::Intrinsic {
                    name: "fldlg2".to_string(),
                    args: vec![],
                });
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Reg("fpu_const_lg2".to_string())),
                );
            }
            "fldln2" => {
                effects.push(Effect::Intrinsic {
                    name: "fldln2".to_string(),
                    args: vec![],
                });
                effects.extend(
                    self.stack
                        .push_effects(IrExpr::Reg("fpu_const_ln2".to_string())),
                );
            }
            // ── FXCH ──────────────────────────────────────────────────────────
            "fxch" => {
                let sn = desc.st_src.unwrap_or(1);
                let a = self.stack.st_expr(0);
                let b = self.stack.st_expr(sn);
                effects.push(Effect::RegWrite {
                    reg: "st0".to_string(),
                    value: b,
                });
                effects.push(Effect::RegWrite {
                    reg: self.stack.st_name(sn),
                    value: a,
                });
            }
            // ── FFREE ─────────────────────────────────────────────────────────
            "ffree" => {
                let sn = desc.st_src.unwrap_or(0);
                effects.push(Effect::Intrinsic {
                    name: "ffree".to_string(),
                    args: vec![self.stack.st_expr(sn)],
                });
            }
            // ── FNINIT / FINIT ─────────────────────────────────────────────────
            "fninit" | "finit" => {
                effects.push(Effect::Intrinsic {
                    name: "finit".to_string(),
                    args: vec![],
                });
            }
            // ── FWAIT / FNOP ──────────────────────────────────────────────────
            "fwait" | "fnop" => {}
            // ── FNSTSW / FSTCW / FLDCW ────────────────────────────────────────
            "fnstsw" | "fstsw" => {
                let dst = desc
                    .mem_addr
                    .clone()
                    .unwrap_or(IrExpr::Reg("ax".to_string()));
                effects.push(Effect::Intrinsic {
                    name: "fnstsw".to_string(),
                    args: vec![dst],
                });
            }
            "fstcw" | "fnstcw" => {
                let addr = desc.mem_addr.clone().unwrap_or(IrExpr::Undef);
                effects.push(Effect::MemWrite {
                    addr,
                    value: IrExpr::Reg("fpu_cw".to_string()),
                    size: 2,
                });
            }
            "fldcw" => {
                let addr = desc.mem_addr.clone().unwrap_or(IrExpr::Undef);
                effects.push(Effect::MemRead {
                    addr,
                    dest: "fpu_cw".to_string(),
                    size: 2,
                });
            }
            // ── FRSTOR / FSAVE ─────────────────────────────────────────────────
            "frstor" => {
                effects.push(Effect::Intrinsic {
                    name: "frstor".to_string(),
                    args: vec![],
                });
            }
            "fsave" | "fnsave" => {
                effects.push(Effect::Intrinsic {
                    name: "fsave".to_string(),
                    args: vec![],
                });
            }
            // ── fallback ──────────────────────────────────────────────────────
            other => {
                effects.push(Effect::Intrinsic {
                    name: format!("__fpu_{other}"),
                    args: vec![],
                });
            }
        }

        effects
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Returns `(a, b)` for a binary FPU op.
    ///
    /// If a memory source is present, returns `(ST(0), deref(mem))`.
    /// Otherwise returns `(ST(dst), ST(src))`.
    fn binop_srcs(&self, desc: &FpuInstrDesc) -> (IrExpr, IrExpr) {
        let a = self.stack.st_expr(desc.st_dst);
        let b = if let Some(addr) = &desc.mem_addr {
            let ae: IrExpr = addr.clone();
            IrExpr::Deref(Box::new(ae), desc.mem_size.unwrap_or(4_u8))
        } else if let Some(sn) = desc.st_src {
            self.stack.st_expr(sn)
        } else {
            self.stack.st_expr(1)
        };
        (a, b)
    }
}

impl Default for FpuLifter {
    fn default() -> Self {
        Self::new()
    }
}

/// Append a `RegWrite` that records the outcome of a flag calculation.
fn emit_flag_set(effects: &mut Vec<Effect>, flag: FpuFlag, value: IrExpr) {
    effects.push(Effect::RegWrite {
        reg: flag.reg_name().to_string(),
        value,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder helpers for tests
// ─────────────────────────────────────────────────────────────────────────────

/// Builder helper: construct an [`FpuInstrDesc`] for a register-only
/// binary FPU operation, picking sensible defaults for the rest of the
/// fields. Mainly intended for test/synthetic construction.
#[must_use]
pub fn reg_desc(mnemonic: &str, st_dst: u8, st_src: Option<u8>, pops: bool) -> FpuInstrDesc {
    FpuInstrDesc {
        mnemonic: mnemonic.to_string(),
        st_dst,
        st_src,
        pops,
        pops_twice: false,
        mem_addr: None,
        mem_size: None,
        kind: FpuOpKind::BinOp,
        flags: FpuFlags::none(),
    }
}

/// Builder helper: construct an [`FpuInstrDesc`] for a memory-load FPU
/// operation with a constant address.
#[must_use]
pub fn mem_desc(mnemonic: &str, addr_val: u64, size: u8, pops: bool) -> FpuInstrDesc {
    FpuInstrDesc {
        mnemonic: mnemonic.to_string(),
        st_dst: 0,
        st_src: None,
        pops,
        pops_twice: false,
        mem_addr: Some(IrExpr::Const(addr_val)),
        mem_size: Some(size),
        kind: FpuOpKind::Load,
        flags: FpuFlags::none(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // FpuStack
    #[test]
    fn stack_push_sets_live() {
        let mut stk = FpuStack::new();
        let _ = stk.push_effects(IrExpr::Const(0));
        assert!(stk.is_live(0));
    }

    #[test]
    fn stack_pop_clears_live() {
        let mut stk = FpuStack::new();
        let _ = stk.push_effects(IrExpr::Const(42));
        let _ = stk.pop_effects();
        // After pop the slot that was ST(0) is now empty
        assert!(!stk.is_live(7)); // top wrapped back
    }

    #[test]
    fn stack_top_advances_on_push_pop() {
        let mut stk = FpuStack::new();
        let initial = stk.top();
        let _ = stk.push_effects(IrExpr::Const(1));
        assert_eq!(stk.top(), initial.wrapping_sub(1) & 7);
        let _ = stk.pop_effects();
        assert_eq!(stk.top(), initial);
    }

    #[test]
    fn stack_st_name() {
        let stk = FpuStack::new();
        assert_eq!(stk.st_name(0), "st0");
        assert_eq!(stk.st_name(7), "st7");
    }

    #[test]
    fn stack_push_effects_contains_intrinsic() {
        let mut stk = FpuStack::new();
        let effs = stk.push_effects(IrExpr::Const(0));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_push"))
        );
    }

    #[test]
    fn stack_pop_effects_contains_intrinsic() {
        let mut stk = FpuStack::new();
        let _ = stk.push_effects(IrExpr::Const(0));
        let effs = stk.pop_effects();
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_pop"))
        );
    }

    // FpuFlag
    #[test]
    fn fpu_flag_reg_names() {
        assert_eq!(FpuFlag::C0.reg_name(), "fpu_c0");
        assert_eq!(FpuFlag::C3.reg_name(), "fpu_c3");
    }

    // FADD
    #[test]
    fn lift_fadd_produces_add() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fadd", 0, Some(1), false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Add(..),
                ..
            }
        )));
    }

    // FADDP
    #[test]
    fn lift_faddp_produces_add_and_pop() {
        let mut lft = FpuLifter::new();
        let _ = lft.stack.push_effects(IrExpr::Const(0)); // ensure stack not empty
        let desc = reg_desc("faddp", 0, Some(1), true);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Add(..),
                ..
            }
        )));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_pop"))
        );
    }

    // FSUB
    #[test]
    fn lift_fsub_produces_sub() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fsub", 0, Some(1), false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Sub(..),
                ..
            }
        )));
    }

    // FMUL
    #[test]
    fn lift_fmul_produces_mul() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fmul", 0, Some(1), false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Mul(..),
                ..
            }
        )));
    }

    // FDIV
    #[test]
    fn lift_fdiv_produces_intrinsic() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fdiv", 0, Some(1), false);
        let effs = lft.lift(&desc);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fdiv"))
        );
    }

    // FSUBR
    #[test]
    fn lift_fsubr_reverses_operands() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fsubr", 0, Some(1), false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Sub(..),
                ..
            }
        )));
    }

    // FLD from memory
    #[test]
    fn lift_fld_mem_reads_then_pushes() {
        let mut lft = FpuLifter::new();
        let desc = mem_desc("fld", 0x1000, 4, false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_push"))
        );
    }

    // FSTP to memory
    #[test]
    fn lift_fstp_mem_writes_and_pops() {
        let mut lft = FpuLifter::new();
        let _ = lft.stack.push_effects(IrExpr::Const(0));
        let desc = mem_desc("fstp", 0x2000, 4, true);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(e, Effect::MemWrite { .. })));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_pop"))
        );
    }

    // FCHS
    #[test]
    fn lift_fchs_produces_sub_from_zero() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fchs", 0, None, false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(
            |e| matches!(e, Effect::RegWrite { value: IrExpr::Sub(..), reg } if reg == "st0")
        ));
    }

    // FABS
    #[test]
    fn lift_fabs_produces_intrinsic() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("fabs", 0, None, false));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fabs"))
        );
    }

    // FSQRT
    #[test]
    fn lift_fsqrt_produces_intrinsic() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("fsqrt", 0, None, false));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fsqrt"))
        );
    }

    // FSIN / FCOS
    #[test]
    fn lift_fsin_fcos() {
        let mut lft = FpuLifter::new();
        assert!(
            lft.lift(&reg_desc("fsin", 0, None, false))
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fsin"))
        );
        assert!(
            lft.lift(&reg_desc("fcos", 0, None, false))
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fcos"))
        );
    }

    // FXAM / FTST
    #[test]
    fn lift_fxam_sets_flags() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("fxam", 0, None, false));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fxam"))
        );
    }

    #[test]
    fn lift_ftst_produces_intrinsic_and_flags() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("ftst", 0, None, false));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "ftst"))
        );
    }

    // FLDZ / FLD1
    #[test]
    fn lift_fldz_pushes_zero() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("fldz", 0, None, false));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_push"))
        );
    }

    #[test]
    fn lift_fld1_pushes_one() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("fld1", 0, None, false));
        assert!(effs.iter().any(|e| matches!(e, Effect::RegWrite { reg, value: IrExpr::Const(v), .. } if reg == "st0" && *v != 0)));
    }

    // FXCH
    #[test]
    fn lift_fxch_swaps_st0_and_st1() {
        let mut lft = FpuLifter::new();
        let effs = lft.lift(&reg_desc("fxch", 0, Some(1), false));
        assert_eq!(
            effs.iter()
                .filter(|e| matches!(e, Effect::RegWrite { .. }))
                .count(),
            2
        );
    }

    // FCOM
    #[test]
    fn lift_fcom_produces_intrinsic_and_flags() {
        let mut lft = FpuLifter::new();
        let desc = reg_desc("fcom", 0, Some(1), false);
        let effs = lft.lift(&desc);
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fcom"))
        );
    }

    // FILD
    #[test]
    fn lift_fild_reads_mem_and_pushes() {
        let mut lft = FpuLifter::new();
        let desc = mem_desc("fild", 0x3000, 4, false);
        let effs = lft.lift(&desc);
        assert!(effs.iter().any(|e| matches!(e, Effect::MemRead { .. })));
    }

    // FYL2X
    #[test]
    fn lift_fyl2x_pops() {
        let mut lft = FpuLifter::new();
        let _ = lft.stack.push_effects(IrExpr::Const(1));
        let _ = lft.stack.push_effects(IrExpr::Const(2));
        let effs = lft.lift(&reg_desc("fyl2x", 0, None, false));
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fyl2x"))
        );
        assert!(
            effs.iter()
                .any(|e| matches!(e, Effect::Intrinsic { name, .. } if name == "fpu_pop"))
        );
    }
}
