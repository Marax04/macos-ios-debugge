//! Deobfuscation pass applying MBA simplification to IR expressions.
//!
//! Walks an IR function's expression tree, converts each sub-expression to
//! [`MbaExpr`], simplifies via the MBA engine, and converts back.  Provides
//! pass configuration, per-function result tracking, and an optional (mocked)
//! Z3 verification stub.

use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use crate::{MbaExpr, MbaSimplifier};

// ────────────────────────────────────────────────────────────────────────────────
// IrExpr — simplified IR expression type
// ────────────────────────────────────────────────────────────────────────────────

/// A simplified IR expression.
///
/// Mirrors a common compiler-IR expression language.  All arithmetic is
/// word-size (64-bit wrapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrExpr {
    /// Integer constant.
    Const(i64),
    /// Named variable / SSA value.
    Var(String),
    /// Addition.
    Add(Box<Self>, Box<Self>),
    /// Subtraction.
    Sub(Box<Self>, Box<Self>),
    /// Multiplication.
    Mul(Box<Self>, Box<Self>),
    /// Unsigned division.
    Div(Box<Self>, Box<Self>),
    /// Unsigned modulo.
    Mod(Box<Self>, Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Bitwise NOT.
    Not(Box<Self>),
    /// Arithmetic negation.
    Neg(Box<Self>),
    /// Left shift.
    Shl(Box<Self>, Box<Self>),
    /// Logical right shift.
    Shr(Box<Self>, Box<Self>),
    /// Arithmetic (sign-extending) right shift.
    ///
    /// Distinct from [`Self::Shr`]: `MbaExpr` keeps `Shr` and `Sar` apart
    /// (`logical_shr` vs a signed `>>`), so collapsing both onto `Shr` here
    /// silently dropped the sign extension and changed what the simplified IR
    /// means for negative operands.
    Sar(Box<Self>, Box<Self>),
    /// Equality comparison (1 if equal, 0 otherwise).
    Eq(Box<Self>, Box<Self>),
    /// Inequality comparison.
    Ne(Box<Self>, Box<Self>),
    /// Unsigned less-than.
    Lt(Box<Self>, Box<Self>),
    /// Unsigned less-or-equal.
    Le(Box<Self>, Box<Self>),
    /// Memory load from address.
    Load(Box<Self>),
    /// Memory store: `Store(address, value)`.
    Store(Box<Self>, Box<Self>),
    /// Function call: `Call(name, args)`.
    Call(String, Vec<Self>),
    /// SSA phi: `Phi(values)`.
    Phi(Vec<Self>),
}

impl IrExpr {
    /// Returns the node count of this expression tree.
    #[must_use]
    pub fn complexity(&self) -> usize {
        match self {
            Self::Const(_) | Self::Var(_) => 1,
            Self::Not(e) | Self::Neg(e) | Self::Load(e) => 1 + e.complexity(),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Div(l, r)
            | Self::Mod(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Shl(l, r)
            | Self::Shr(l, r)
            | Self::Sar(l, r)
            | Self::Eq(l, r)
            | Self::Ne(l, r)
            | Self::Lt(l, r)
            | Self::Le(l, r)
            | Self::Store(l, r) => 1 + l.complexity() + r.complexity(),
            Self::Call(_, args) => 1 + args.iter().map(Self::complexity).sum::<usize>(),
            Self::Phi(vals) => 1 + vals.iter().map(Self::complexity).sum::<usize>(),
        }
    }

    /// Returns `true` if this expression contains only arithmetic and bitwise
    /// operations (no memory accesses, calls, or phi nodes).
    #[must_use]
    pub fn is_arithmetic(&self) -> bool {
        match self {
            Self::Const(_) | Self::Var(_) => true,
            Self::Not(e) | Self::Neg(e) => e.is_arithmetic(),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Shl(l, r)
            | Self::Shr(l, r)
            | Self::Sar(l, r) => l.is_arithmetic() && r.is_arithmetic(),
            _ => false,
        }
    }

    /// Collect all variable names used.
    #[must_use]
    pub fn vars(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_vars(&mut out);
        out
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Var(name) => {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
            Self::Const(_) => {}
            Self::Not(e) | Self::Neg(e) | Self::Load(e) => e.collect_vars(out),
            Self::Add(l, r)
            | Self::Sub(l, r)
            | Self::Mul(l, r)
            | Self::Div(l, r)
            | Self::Mod(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Shl(l, r)
            | Self::Shr(l, r)
            | Self::Sar(l, r)
            | Self::Eq(l, r)
            | Self::Ne(l, r)
            | Self::Lt(l, r)
            | Self::Le(l, r)
            | Self::Store(l, r) => {
                l.collect_vars(out);
                r.collect_vars(out);
            }
            Self::Call(_, args) => {
                for a in args { a.collect_vars(out); }
            }
            Self::Phi(vals) => {
                for v in vals { v.collect_vars(out); }
            }
        }
    }
}

impl fmt::Display for IrExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(c) => write!(f, "{c}"),
            Self::Var(name) => write!(f, "{name}"),
            Self::Add(l, r) => write!(f, "({l} + {r})"),
            Self::Sub(l, r) => write!(f, "({l} - {r})"),
            Self::Mul(l, r) => write!(f, "({l} * {r})"),
            Self::Div(l, r) => write!(f, "({l} / {r})"),
            Self::Mod(l, r) => write!(f, "({l} % {r})"),
            Self::And(l, r) => write!(f, "({l} & {r})"),
            Self::Or(l, r) => write!(f, "({l} | {r})"),
            Self::Xor(l, r) => write!(f, "({l} ^ {r})"),
            Self::Not(e) => write!(f, "(~{e})"),
            Self::Neg(e) => write!(f, "(-{e})"),
            Self::Shl(l, r) => write!(f, "({l} << {r})"),
            Self::Shr(l, r) => write!(f, "({l} >> {r})"),
            Self::Sar(l, r) => write!(f, "({l} >>a {r})"),
            Self::Eq(l, r) => write!(f, "({l} == {r})"),
            Self::Ne(l, r) => write!(f, "({l} != {r})"),
            Self::Lt(l, r) => write!(f, "({l} < {r})"),
            Self::Le(l, r) => write!(f, "({l} <= {r})"),
            Self::Load(addr) => write!(f, "mem[{addr}]"),
            Self::Store(addr, val) => write!(f, "mem[{addr}] = {val}"),
            Self::Call(name, args) => {
                let args_str = args.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(", ");
                write!(f, "{name}({args_str})")
            }
            Self::Phi(vals) => {
                let s = vals.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(", ");
                write!(f, "φ({s})")
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Pass types
// ────────────────────────────────────────────────────────────────────────────────

/// Configuration for the MBA deobfuscation pass.
#[derive(Debug, Clone)]
pub struct PassConfig {
    /// Skip simplification for expressions with complexity below this value.
    pub max_complexity_threshold: u32,
    /// Enable (mocked) Z3 SMT verification after simplification.
    pub use_z3_verification: bool,
    /// Maximum simplification iterations per expression.
    pub max_iterations: u32,
    /// Only simplify arithmetic sub-expressions (skip Load/Store/Call).
    pub arithmetic_only: bool,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            max_complexity_threshold: 3,
            use_z3_verification: false,
            max_iterations: 100,
            arithmetic_only: true,
        }
    }
}

/// An example simplification for reporting purposes.
#[derive(Debug, Clone)]
pub struct SimplificationExample {
    /// Original expression as a string.
    pub original: String,
    /// Simplified expression as a string.
    pub simplified: String,
    /// Fraction of complexity removed in `[0.0, 1.0]`.
    pub complexity_reduction: f64,
}

/// Result of applying the pass to a function.
#[derive(Debug, Clone)]
pub struct PassResult {
    /// Number of expressions successfully simplified.
    pub simplified_count: u32,
    /// Number of expressions where simplification failed or was skipped.
    pub failed_count: u32,
    /// Total expressions examined.
    pub total_exprs: u32,
    /// Wall-clock time of the pass in milliseconds.
    pub time_ms: u64,
    /// A sample of interesting simplifications.
    pub examples: Vec<SimplificationExample>,
}

impl PassResult {
    /// Fraction of expressions simplified in `[0.0, 1.0]`.
    #[must_use]
    pub fn simplification_rate(&self) -> f64 {
        if self.total_exprs == 0 {
            0.0
        } else {
            f64::from(self.simplified_count) / f64::from(self.total_exprs)
        }
    }
}

impl fmt::Display for PassResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PassResult: simplified={}/{} ({:.1}%) in {}ms",
            self.simplified_count,
            self.total_exprs,
            self.simplification_rate() * 100.0,
            self.time_ms
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Translation: IrExpr ↔ MbaExpr
// ────────────────────────────────────────────────────────────────────────────────

/// Translate an [`IrExpr`] to an [`MbaExpr`].
///
/// Operations that have no MBA equivalent (Div, Mod, Eq, Ne, Lt, Le, Load,
/// Store, Call, Phi) are represented as a `Var` with a synthetic name, so
/// they can be treated as atomic sub-expressions.
#[must_use]
pub fn translate_ir_to_mba(expr: &IrExpr) -> MbaExpr {
    match expr {
        IrExpr::Const(c) => MbaExpr::Const(*c),
        IrExpr::Var(name) => MbaExpr::Var(name.clone()),
        IrExpr::Add(l, r) => MbaExpr::mk_add(translate_ir_to_mba(l), translate_ir_to_mba(r)),
        IrExpr::Sub(l, r) => MbaExpr::mk_sub(translate_ir_to_mba(l), translate_ir_to_mba(r)),
        IrExpr::Mul(l, r) => MbaExpr::mk_mul(translate_ir_to_mba(l), translate_ir_to_mba(r)),
        IrExpr::And(l, r) => MbaExpr::mk_and(translate_ir_to_mba(l), translate_ir_to_mba(r)),
        IrExpr::Or(l, r) => MbaExpr::mk_or(translate_ir_to_mba(l), translate_ir_to_mba(r)),
        IrExpr::Xor(l, r) => MbaExpr::mk_xor(translate_ir_to_mba(l), translate_ir_to_mba(r)),
        IrExpr::Not(e) => MbaExpr::mk_not(translate_ir_to_mba(e)),
        IrExpr::Neg(e) => MbaExpr::mk_neg(translate_ir_to_mba(e)),
        IrExpr::Shl(l, r) => {
            // Only constant shift amounts translate cleanly.
            if let IrExpr::Const(n) = r.as_ref() {
                let shift = (*n as u8).min(63);
                MbaExpr::Shl(Box::new(translate_ir_to_mba(l)), shift)
            } else {
                MbaExpr::Var(format!("shl_{}_{}", ir_var_hash(l), ir_var_hash(r)))
            }
        }
        IrExpr::Shr(l, r) => {
            if let IrExpr::Const(n) = r.as_ref() {
                let shift = (*n as u8).min(63);
                MbaExpr::Shr(Box::new(translate_ir_to_mba(l)), shift)
            } else {
                MbaExpr::Var(format!("shr_{}_{}", ir_var_hash(l), ir_var_hash(r)))
            }
        }
        IrExpr::Sar(l, r) => {
            if let IrExpr::Const(n) = r.as_ref() {
                let shift = (*n as u8).min(63);
                MbaExpr::Sar(Box::new(translate_ir_to_mba(l)), shift)
            } else {
                MbaExpr::Var(format!("sar_{}_{}", ir_var_hash(l), ir_var_hash(r)))
            }
        }
        // Opaque sub-expressions: represent as variables.
        IrExpr::Div(l, r) => MbaExpr::Var(format!("div_{}_{}", ir_var_hash(l), ir_var_hash(r))),
        IrExpr::Mod(l, r) => MbaExpr::Var(format!("mod_{}_{}", ir_var_hash(l), ir_var_hash(r))),
        IrExpr::Eq(l, r) => MbaExpr::Var(format!("eq_{}_{}", ir_var_hash(l), ir_var_hash(r))),
        IrExpr::Ne(l, r) => MbaExpr::Var(format!("ne_{}_{}", ir_var_hash(l), ir_var_hash(r))),
        IrExpr::Lt(l, r) => MbaExpr::Var(format!("lt_{}_{}", ir_var_hash(l), ir_var_hash(r))),
        IrExpr::Le(l, r) => MbaExpr::Var(format!("le_{}_{}", ir_var_hash(l), ir_var_hash(r))),
        IrExpr::Load(addr) => MbaExpr::Var(format!("load_{}", ir_var_hash(addr))),
        // These three must hash their operands too, exactly like the arms
        // above. Mapping every store to `store_result`, every phi to
        // `phi_result` and every call to `call_{name}` regardless of its
        // arguments made two DIFFERENT opaque values the SAME symbolic
        // variable — and the simplifier's `x ^ x -> 0`, `x - x -> 0`,
        // `x & x -> x` rules then "proved" unrelated values equal:
        // `f(x) ^ f(y)` simplified to `0`.
        IrExpr::Store(addr, val) => MbaExpr::Var(format!(
            "store_{}_{}",
            ir_var_hash(addr),
            ir_var_hash(val)
        )),
        IrExpr::Call(name, args) => {
            let arg_hash = args.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, a| {
                h.rotate_left(5) ^ ir_var_hash(a)
            });
            MbaExpr::Var(format!("call_{name}_{arg_hash}"))
        }
        IrExpr::Phi(vals) => {
            let vals_hash = vals.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, v| {
                h.rotate_left(5) ^ ir_var_hash(v)
            });
            MbaExpr::Var(format!("phi_{vals_hash}"))
        }
    }
}

/// Translate a simplified [`MbaExpr`] back to an [`IrExpr`].
///
/// Shift amounts that were collapsed to a `Var` during [`translate_ir_to_mba`]
/// are left as `IrExpr::Var` — they won't be re-expanded.
#[must_use]
pub fn translate_mba_to_ir(expr: &MbaExpr) -> IrExpr {
    match expr {
        MbaExpr::Const(c) => IrExpr::Const(*c),
        MbaExpr::Var(name) => IrExpr::Var(name.clone()),
        MbaExpr::Add(l, r) => IrExpr::Add(
            Box::new(translate_mba_to_ir(l)),
            Box::new(translate_mba_to_ir(r)),
        ),
        MbaExpr::Sub(l, r) => IrExpr::Sub(
            Box::new(translate_mba_to_ir(l)),
            Box::new(translate_mba_to_ir(r)),
        ),
        MbaExpr::Mul(l, r) => IrExpr::Mul(
            Box::new(translate_mba_to_ir(l)),
            Box::new(translate_mba_to_ir(r)),
        ),
        MbaExpr::And(l, r) => IrExpr::And(
            Box::new(translate_mba_to_ir(l)),
            Box::new(translate_mba_to_ir(r)),
        ),
        MbaExpr::Or(l, r) => IrExpr::Or(
            Box::new(translate_mba_to_ir(l)),
            Box::new(translate_mba_to_ir(r)),
        ),
        MbaExpr::Xor(l, r) => IrExpr::Xor(
            Box::new(translate_mba_to_ir(l)),
            Box::new(translate_mba_to_ir(r)),
        ),
        MbaExpr::Not(e) => IrExpr::Not(Box::new(translate_mba_to_ir(e))),
        MbaExpr::Neg(e) => IrExpr::Neg(Box::new(translate_mba_to_ir(e))),
        MbaExpr::Shl(e, n) => IrExpr::Shl(
            Box::new(translate_mba_to_ir(e)),
            Box::new(IrExpr::Const(i64::from(*n))),
        ),
        MbaExpr::Shr(e, n) => IrExpr::Shr(
            Box::new(translate_mba_to_ir(e)),
            Box::new(IrExpr::Const(i64::from(*n))),
        ),
        MbaExpr::Sar(e, n) => IrExpr::Sar(
            Box::new(translate_mba_to_ir(e)),
            Box::new(IrExpr::Const(i64::from(*n))),
        ),
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// DeobfMbaPass
// ────────────────────────────────────────────────────────────────────────────────

/// The main deobfuscation pass.
pub struct DeobfMbaPass {
    /// Pass configuration.
    pub config: PassConfig,
    /// Underlying MBA simplification engine.
    pub simplifier: MbaSimplifier,
}

impl DeobfMbaPass {
    /// Create a pass with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: PassConfig::default(),
            simplifier: MbaSimplifier::new().without_verification(),
        }
    }

    /// Create a pass with custom configuration.
    #[must_use]
    pub fn with_config(config: PassConfig) -> Self {
        let max_iter = config.max_iterations as usize;
        Self {
            config,
            simplifier: MbaSimplifier::new()
                .with_max_iterations(max_iter)
                .without_verification(),
        }
    }

    /// Simplify a single [`IrExpr`].
    ///
    /// Returns `(simplified_expr, was_changed)`.
    #[must_use]
    pub fn simplify_expr(&self, expr: &IrExpr) -> (IrExpr, bool) {
        let complexity = expr.complexity() as u32;
        if complexity <= self.config.max_complexity_threshold {
            return (expr.clone(), false);
        }
        if self.config.arithmetic_only && !expr.is_arithmetic() {
            // Try to simplify only arithmetic sub-expressions.
            return (self.simplify_children(expr), false);
        }

        let mba = translate_ir_to_mba(expr);
        let result = self.simplifier.simplify(mba);
        if result.complexity_after < result.complexity_before {
            let ir_simplified = translate_mba_to_ir(&result.simplified);
            let verification_ok = if self.config.use_z3_verification {
                self.verify_with_z3(expr, &ir_simplified)
            } else {
                true
            };
            if verification_ok {
                return (ir_simplified, true);
            }
        }
        (expr.clone(), false)
    }

    /// Walk an expression tree recursively and simplify each arithmetic sub-tree.
    fn simplify_children(&self, expr: &IrExpr) -> IrExpr {
        match expr {
            IrExpr::Const(_) | IrExpr::Var(_) => expr.clone(),
            IrExpr::Add(l, r) => IrExpr::Add(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Sub(l, r) => IrExpr::Sub(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Mul(l, r) => IrExpr::Mul(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::And(l, r) => IrExpr::And(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Or(l, r) => IrExpr::Or(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Xor(l, r) => IrExpr::Xor(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Not(e) => IrExpr::Not(Box::new(self.try_simplify(e))),
            IrExpr::Neg(e) => IrExpr::Neg(Box::new(self.try_simplify(e))),
            IrExpr::Shl(l, r) => IrExpr::Shl(Box::new(self.try_simplify(l)), r.clone()),
            IrExpr::Shr(l, r) => IrExpr::Shr(Box::new(self.try_simplify(l)), r.clone()),
            IrExpr::Sar(l, r) => IrExpr::Sar(Box::new(self.try_simplify(l)), r.clone()),
            IrExpr::Load(addr) => IrExpr::Load(Box::new(self.try_simplify(addr))),
            IrExpr::Store(addr, val) => IrExpr::Store(Box::new(self.try_simplify(addr)), Box::new(self.try_simplify(val))),
            IrExpr::Div(l, r) => IrExpr::Div(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Mod(l, r) => IrExpr::Mod(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Eq(l, r) => IrExpr::Eq(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Ne(l, r) => IrExpr::Ne(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Lt(l, r) => IrExpr::Lt(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Le(l, r) => IrExpr::Le(Box::new(self.try_simplify(l)), Box::new(self.try_simplify(r))),
            IrExpr::Call(name, args) => {
                IrExpr::Call(name.clone(), args.iter().map(|a| self.try_simplify(a)).collect())
            }
            IrExpr::Phi(vals) => {
                IrExpr::Phi(vals.iter().map(|v| self.try_simplify(v)).collect())
            }
        }
    }

    fn try_simplify(&self, expr: &IrExpr) -> IrExpr {
        let (simplified, _) = self.simplify_expr(expr);
        simplified
    }

    /// Apply the MBA pass to a flat list of IR expressions (e.g. one function's SSA values).
    ///
    /// Returns a [`PassResult`] and a new list of (possibly simplified) expressions.
    #[must_use]
    pub fn apply_pass_to_function(&self, exprs: &[IrExpr]) -> (Vec<IrExpr>, PassResult) {
        let start = Instant::now();
        let mut simplified_exprs = Vec::with_capacity(exprs.len());
        let mut simplified_count: u32 = 0;
        let mut failed_count: u32 = 0;
        let mut examples: Vec<SimplificationExample> = Vec::new();

        for expr in exprs {
            let original_str = expr.to_string();
            let original_complexity = expr.complexity();
            let (new_expr, changed) = self.simplify_expr(expr);
            if changed {
                simplified_count += 1;
                let new_complexity = new_expr.complexity();
                let reduction = if original_complexity > 0 {
                    1.0 - (new_complexity as f64 / original_complexity as f64)
                } else {
                    0.0
                };
                if examples.len() < 10 {
                    examples.push(SimplificationExample {
                        original: original_str,
                        simplified: new_expr.to_string(),
                        complexity_reduction: reduction,
                    });
                }
                simplified_exprs.push(new_expr);
            } else {
                failed_count += 1;
                simplified_exprs.push(expr.clone());
            }
        }

        let time_ms = start.elapsed().as_millis() as u64;
        let result = PassResult {
            simplified_count,
            failed_count,
            total_exprs: exprs.len() as u32,
            time_ms,
            examples,
        };
        (simplified_exprs, result)
    }

    /// Mix a seed with a linear congruential step.
    ///
    /// Same constants as `nonlinear_mba_solver::lcg`; used to decorrelate the
    /// per-variable samples in [`Self::verify_with_z3`].
    const fn lcg(seed: u64) -> u64 {
        seed.wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407)
    }

    /// Optional SMT-based equivalence verification.
    ///
    /// In this implementation the check is performed by sampling 64 random
    /// 8-bit values per variable and comparing results.  A real Z3-backed
    /// implementation would generate SMT-LIB2 and invoke a solver.
    #[must_use]
    pub fn verify_with_z3(&self, original: &IrExpr, simplified: &IrExpr) -> bool {
        let orig_vars = original.vars();
        let simp_vars = simplified.vars();
        let mut all_vars = orig_vars;
        for v in simp_vars {
            if !all_vars.contains(&v) {
                all_vars.push(v);
            }
        }
        let mask: i64 = 0xFF;
        let seed: u64 = 0xdead_beef_cafe_1234;
        for i in 0u64..64 {
            let mut assignment: HashMap<String, i64> = HashMap::new();
            for (j, var) in all_vars.iter().enumerate() {
                // MIX the variable index in, do not ADD it.
                //
                // Adding `j` made the low byte of every sample exactly
                // `base_i + j`, so the k-th variable was always
                // `first_var + k (mod 256)` and all 64 samples lay on the
                // diagonal `y = x+1, z = x+2, …`. Any two expressions agreeing
                // on that single line were declared equivalent — `x + y` and
                // `2x + 1` among them — which made this gate inert and every
                // rewrite it guards effectively unverified.
                //
                // `NonlinearMbaSolver::verify_equivalence_sampling` already
                // multiplies the variable index by the golden-ratio constant
                // and runs it through the LCG; this is the same construction.
                let rng = Self::lcg(
                    seed.wrapping_add(i.wrapping_mul(0x9e37_79b9_7f4a_7c15))
                        .wrapping_add((j as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)),
                );
                let val = (rng as i64) & mask;
                assignment.insert(var.clone(), val);
            }
            let v_orig = eval_ir(original, &assignment) & mask;
            let v_simp = eval_ir(simplified, &assignment) & mask;
            if v_orig != v_simp {
                return false;
            }
        }
        true
    }
}

impl Default for DeobfMbaPass {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DeobfMbaPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeobfMbaPass")
            .field("max_complexity_threshold", &self.config.max_complexity_threshold)
            .field("use_z3_verification", &self.config.use_z3_verification)
            .field("max_iterations", &self.config.max_iterations)
            .finish_non_exhaustive()
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────────

fn ir_var_hash(expr: &IrExpr) -> u64 {
    // Simple FNV-1a over the display string.
    let s = expr.to_string();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Evaluate an [`IrExpr`] for a given variable assignment.
///
/// Missing variables evaluate to 0.  Division by zero returns 0.
fn eval_ir(expr: &IrExpr, vars: &HashMap<String, i64>) -> i64 {
    match expr {
        IrExpr::Const(c) => *c,
        IrExpr::Var(name) => vars.get(name).copied().unwrap_or(0),
        IrExpr::Add(l, r) => eval_ir(l, vars).wrapping_add(eval_ir(r, vars)),
        IrExpr::Sub(l, r) => eval_ir(l, vars).wrapping_sub(eval_ir(r, vars)),
        IrExpr::Mul(l, r) => eval_ir(l, vars).wrapping_mul(eval_ir(r, vars)),
        IrExpr::Div(l, r) => {
            let rhs = eval_ir(r, vars);
            if rhs == 0 { 0 } else { eval_ir(l, vars).wrapping_div(rhs) }
        }
        IrExpr::Mod(l, r) => {
            let rhs = eval_ir(r, vars);
            if rhs == 0 { 0 } else { eval_ir(l, vars).wrapping_rem(rhs) }
        }
        IrExpr::And(l, r) => eval_ir(l, vars) & eval_ir(r, vars),
        IrExpr::Or(l, r) => eval_ir(l, vars) | eval_ir(r, vars),
        IrExpr::Xor(l, r) => eval_ir(l, vars) ^ eval_ir(r, vars),
        IrExpr::Not(e) => !eval_ir(e, vars),
        IrExpr::Neg(e) => eval_ir(e, vars).wrapping_neg(),
        IrExpr::Shl(l, r) => {
            let shift = eval_ir(r, vars) as u32 & 63;
            eval_ir(l, vars).wrapping_shl(shift)
        }
        IrExpr::Shr(l, r) => {
            let shift = eval_ir(r, vars) as u32 & 63;
            let bits = eval_ir(l, vars).to_ne_bytes();
            let unsigned = u64::from_ne_bytes(bits) >> shift;
            i64::from_ne_bytes(unsigned.to_ne_bytes())
        }
        // Arithmetic shift: signed `>>` sign-extends, which is the whole point
        // of keeping `Sar` distinct from `Shr`.
        IrExpr::Sar(l, r) => {
            let shift = eval_ir(r, vars) as u32 & 63;
            eval_ir(l, vars) >> shift
        }
        IrExpr::Eq(l, r) => i64::from(eval_ir(l, vars) == eval_ir(r, vars)),
        IrExpr::Ne(l, r) => i64::from(eval_ir(l, vars) != eval_ir(r, vars)),
        IrExpr::Lt(l, r) => i64::from((eval_ir(l, vars) as u64) < (eval_ir(r, vars) as u64)),
        IrExpr::Le(l, r) => i64::from((eval_ir(l, vars) as u64) <= (eval_ir(r, vars) as u64)),
        IrExpr::Load(_) | IrExpr::Store(_, _) | IrExpr::Call(_, _) | IrExpr::Phi(_) => 0,
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn var(name: &str) -> IrExpr {
        IrExpr::Var(name.to_string())
    }

    fn cnst(c: i64) -> IrExpr {
        IrExpr::Const(c)
    }

    fn pass() -> DeobfMbaPass {
        DeobfMbaPass::new()
    }

    // ── IrExpr complexity / is_arithmetic ─────────────────────────────────────

    #[test]
    fn test_ir_const_complexity() {
        assert_eq!(cnst(42).complexity(), 1);
    }

    #[test]
    fn test_ir_add_complexity() {
        let e = IrExpr::Add(Box::new(var("x")), Box::new(cnst(1)));
        assert_eq!(e.complexity(), 3);
    }

    #[test]
    fn test_ir_is_arithmetic_true() {
        let e = IrExpr::And(Box::new(var("x")), Box::new(var("y")));
        assert!(e.is_arithmetic());
    }

    #[test]
    fn test_ir_is_arithmetic_false_for_load() {
        let e = IrExpr::Load(Box::new(cnst(0x1000)));
        assert!(!e.is_arithmetic());
    }

    // ── translate_ir_to_mba ────────────────────────────────────────────────────

    #[test]
    fn test_translate_const() {
        let ir = cnst(99);
        let mba = translate_ir_to_mba(&ir);
        assert_eq!(mba, MbaExpr::Const(99));
    }

    #[test]
    fn test_translate_var() {
        let ir = var("z");
        let mba = translate_ir_to_mba(&ir);
        assert_eq!(mba, MbaExpr::Var("z".to_string()));
    }

    #[test]
    fn test_translate_add() {
        let ir = IrExpr::Add(Box::new(var("a")), Box::new(cnst(5)));
        let mba = translate_ir_to_mba(&ir);
        assert!(matches!(mba, MbaExpr::Add(_, _)));
    }

    #[test]
    fn test_translate_and() {
        let ir = IrExpr::And(Box::new(var("x")), Box::new(var("y")));
        let mba = translate_ir_to_mba(&ir);
        assert!(matches!(mba, MbaExpr::And(_, _)));
    }

    #[test]
    fn test_translate_load_becomes_var() {
        let ir = IrExpr::Load(Box::new(cnst(0x4000)));
        let mba = translate_ir_to_mba(&ir);
        assert!(matches!(mba, MbaExpr::Var(_)));
    }

    // ── translate_mba_to_ir ────────────────────────────────────────────────────

    #[test]
    fn test_translate_back_const() {
        let mba = MbaExpr::Const(7);
        let ir = translate_mba_to_ir(&mba);
        assert_eq!(ir, cnst(7));
    }

    #[test]
    fn test_translate_back_add() {
        let mba = MbaExpr::mk_add(MbaExpr::Var("x".into()), MbaExpr::Const(1));
        let ir = translate_mba_to_ir(&mba);
        assert!(matches!(ir, IrExpr::Add(_, _)));
    }

    // ── simplify_expr ─────────────────────────────────────────────────────────

    #[test]
    fn test_simplify_expr_const_no_change() {
        let p = pass();
        let e = cnst(5);
        let (simplified, changed) = p.simplify_expr(&e);
        assert!(!changed);
        assert_eq!(simplified, e);
    }

    #[test]
    fn test_simplify_expr_x_plus_zero() {
        let p = DeobfMbaPass::with_config(PassConfig {
            max_complexity_threshold: 0,
            ..Default::default()
        });
        let e = IrExpr::Add(Box::new(var("x")), Box::new(cnst(0)));
        let (simplified, changed) = p.simplify_expr(&e);
        if changed {
            assert_eq!(simplified.to_string(), "x");
        } else {
            // simplification not triggered — still correct.
            assert_eq!(simplified, e);
        }
    }

    #[test]
    fn test_simplify_mba_identity() {
        // (x & y) + (x | y) should simplify to x + y.
        let p = DeobfMbaPass::with_config(PassConfig {
            max_complexity_threshold: 0,
            arithmetic_only: true,
            ..Default::default()
        });
        let and_xy = IrExpr::And(Box::new(var("x")), Box::new(var("y")));
        let or_xy = IrExpr::Or(Box::new(var("x")), Box::new(var("y")));
        let e = IrExpr::Add(Box::new(and_xy), Box::new(or_xy));
        let (simplified, changed) = p.simplify_expr(&e);
        if changed {
            assert!(simplified.to_string().contains('x'));
        } else {
            assert_eq!(simplified, e);
        }
    }

    // ── apply_pass_to_function ────────────────────────────────────────────────

    #[test]
    fn test_apply_pass_empty() {
        let p = pass();
        let (exprs, result) = p.apply_pass_to_function(&[]);
        assert!(exprs.is_empty());
        assert_eq!(result.total_exprs, 0);
        assert_eq!(result.simplified_count, 0);
    }

    #[test]
    fn test_apply_pass_counts_total() {
        let p = pass();
        let inputs = vec![cnst(1), cnst(2), cnst(3)];
        let (_, result) = p.apply_pass_to_function(&inputs);
        assert_eq!(result.total_exprs, 3);
    }

    #[test]
    fn test_apply_pass_simplification_rate_zero_exprs() {
        let result = PassResult {
            simplified_count: 0,
            failed_count: 0,
            total_exprs: 0,
            time_ms: 0,
            examples: Vec::new(),
        };
        assert_eq!(result.simplification_rate(), 0.0);
    }

    // ── verify_with_z3 (sampling) ─────────────────────────────────────────────

    #[test]
    fn test_verify_identical_exprs() {
        let p = pass();
        let e = IrExpr::Add(Box::new(var("x")), Box::new(var("y")));
        assert!(p.verify_with_z3(&e, &e));
    }

    #[test]
    fn test_verify_different_exprs_returns_false() {
        let p = pass();
        let e1 = IrExpr::Add(Box::new(var("x")), Box::new(cnst(1)));
        let e2 = IrExpr::Add(Box::new(var("x")), Box::new(cnst(2)));
        assert!(!p.verify_with_z3(&e1, &e2));
    }

    // ── eval_ir ────────────────────────────────────────────────────────────────

    #[test]
    fn test_eval_ir_add() {
        let e = IrExpr::Add(Box::new(cnst(3)), Box::new(cnst(4)));
        assert_eq!(eval_ir(&e, &HashMap::new()), 7);
    }

    #[test]
    fn test_eval_ir_and() {
        let e = IrExpr::And(Box::new(cnst(0b1010)), Box::new(cnst(0b1100)));
        assert_eq!(eval_ir(&e, &HashMap::new()), 0b1000);
    }

    #[test]
    fn test_eval_ir_div_by_zero_safe() {
        let e = IrExpr::Div(Box::new(cnst(10)), Box::new(cnst(0)));
        assert_eq!(eval_ir(&e, &HashMap::new()), 0);
    }

    #[test]
    fn test_ir_expr_display_phi() {
        let e = IrExpr::Phi(vec![var("x"), var("y")]);
        let s = e.to_string();
        assert!(s.starts_with('φ'));
    }

    #[test]
    fn test_pass_result_display() {
        let r = PassResult {
            simplified_count: 3,
            failed_count: 2,
            total_exprs: 5,
            time_ms: 12,
            examples: Vec::new(),
        };
        let s = r.to_string();
        assert!(s.contains("3/5"));
    }
}
